#define _GNU_SOURCE

#include "nfqws.h"
#include "sec.h"
#include "desync.h"
#include "helpers.h"
#include "checksum.h"
#include "params.h"
#include "protocol.h"
#include "hostlist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#define NF_DROP 0
#define NF_ACCEPT 1


struct params_s params;


static bool bHup = false;
static void onhup(int sig)
{
	printf("HUP received !\n");
	if (params.hostlist)
		printf("Will reload hostlist on next request\n");
	bHup = true;
}
// should be called in normal execution
static void dohup()
{
	if (bHup)
	{
		if (params.hostlist)
		{
			if (!LoadHostList(&params.hostlist, params.hostfile))
			{
				// what will we do without hostlist ?? sure, gonna die
				exit(1);
			}
		}
		bHup = false;
	}
}



static bool proto_check_ipv4(uint8_t *data, size_t len)
{
	return 	len >= 20 && (data[0] & 0xF0) == 0x40 &&
		len >= ((data[0] & 0x0F) << 2);
}
// move to transport protocol
static void proto_skip_ipv4(uint8_t **data, size_t *len)
{
	size_t l;

	l = (**data & 0x0F) << 2;
	*data += l;
	*len -= l;
}
static bool proto_check_tcp(uint8_t *data, size_t len)
{
	return	len >= 20 && len >= ((data[12] & 0xF0) >> 2);
}
static void proto_skip_tcp(uint8_t **data, size_t *len)
{
	size_t l;
	l = ((*data)[12] & 0xF0) >> 2;
	*data += l;
	*len -= l;
}

static bool proto_check_ipv6(uint8_t *data, size_t len)
{
	return 	len >= 40 && (data[0] & 0xF0) == 0x60 &&
		(len - 40) >= htons(*(uint16_t*)(data + 4)); // payload length
}
// move to transport protocol
// proto_type = 0 => error
static void proto_skip_ipv6(uint8_t **data, size_t *len, uint8_t *proto_type)
{
	size_t hdrlen;
	uint8_t HeaderType;

	*proto_type = 0; // put error in advance

	HeaderType = (*data)[6]; // NextHeader field
	*data += 40; *len -= 40; // skip ipv6 base header
	while (*len > 0) // need at least one byte for NextHeader field
	{
		switch (HeaderType)
		{
		case 0: // Hop-by-Hop Options
		case 43: // routing
		case 51: // authentication
		case 60: // Destination Options
		case 135: // mobility
		case 139: // Host Identity Protocol Version v2
		case 140: // Shim6
			if (*len < 2) return; // error
			hdrlen = 8 + ((*data)[1] << 3);
			break;
		case 44: // fragment. length fixed to 8, hdrlen field defined as reserved
			hdrlen = 8;
			break;
		case 59: // no next header
			return; // error
		default:
			// we found some meaningful payload. it can be tcp, udp, icmp or some another exotic shit
			*proto_type = HeaderType;
			return;
		}
		if (*len < hdrlen) return; // error
		HeaderType = **data;
		// advance to the next header location
		*len -= hdrlen;
		*data += hdrlen;
	}
	// we have garbage
}

static inline bool tcp_synack_segment(const struct tcphdr *tcphdr)
{
	/* check for set bits in TCP hdr */
	return  tcphdr->urg == 0 &&
		tcphdr->ack == 1 &&
		tcphdr->psh == 0 &&
		tcphdr->rst == 0 &&
		tcphdr->syn == 1 &&
		tcphdr->fin == 0;
}
static void tcp_rewrite_winsize(struct tcphdr *tcp, uint16_t winsize)
{
	uint16_t winsize_old;
	winsize_old = htons(tcp->window); // << scale_factor;
	tcp->window = htons(winsize);
	DLOG("Window size change %u => %u\n", winsize_old, winsize)
}

// data/len points to data payload
static bool modify_tcp_packet(uint8_t *data, size_t len, struct tcphdr *tcphdr)
{
	if (tcp_synack_segment(tcphdr) && params.wsize)
	{
		tcp_rewrite_winsize(tcphdr, (uint16_t)params.wsize);
		return true;
	}
	return false;
}



static packet_process_result processPacketData(uint8_t *data_pkt, size_t len_pkt, uint32_t *mark)
{
	struct iphdr *iphdr = NULL;
	struct ip6_hdr *ip6hdr = NULL;
	struct tcphdr *tcphdr = NULL;
	size_t len = len_pkt, len_tcp;
	uint8_t *data = data_pkt;
	packet_process_result res = pass, res2;
	uint8_t proto;

	if (*mark & params.desync_fwmark) return res;

	if (proto_check_ipv4(data, len))
	{
		iphdr = (struct iphdr *) data;
		proto = iphdr->protocol;
		proto_skip_ipv4(&data, &len);
	}
	else if (proto_check_ipv6(data, len))
	{
		ip6hdr = (struct ip6_hdr *) data;
		proto_skip_ipv6(&data, &len, &proto);
	}
	else
	{
		// not ipv6 and not ipv4
		return res;
	}

	if (proto==IPPROTO_TCP && proto_check_tcp(data, len))
	{
		tcphdr = (struct tcphdr *) data;
		len_tcp = len;
		proto_skip_tcp(&data, &len);
		//DLOG("got TCP packet. payload_len=%d\n",len)

		if (modify_tcp_packet(data, len, tcphdr))
			res = modify;

		res2 = dpi_desync_packet(data_pkt, len_pkt, iphdr, ip6hdr, tcphdr, len_tcp, data, len);
		res = (res2==pass && res==modify) ? modify : res2;
		if (res==modify) tcp_fix_checksum(tcphdr,len_tcp,iphdr,ip6hdr);
	}
	return res;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *cookie)
{
	int id;
	size_t len;
	struct nfqnl_msg_packet_hdr *ph;
	uint8_t *data;

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ph ? ntohl(ph->packet_id) : 0;

	uint32_t mark = nfq_get_nfmark(nfa);
	len = nfq_get_payload(nfa, &data);
	DLOG("packet: id=%d len=%zu\n", id, len)
	if (len >= 0)
	{
		switch (processPacketData(data, len, &mark))
		{
		case modify: return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, len, data);
		case drop: return nfq_set_verdict2(qh, id, NF_DROP, mark, 0, NULL);
		}
	}

	return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);
}



static void exithelp()
{
	printf(
		" --debug=0|1\n"
		" --qnum=<nfqueue_number>\n"
		" --daemon\t\t\t\t; daemonize\n"
		" --pidfile=<filename>\t\t\t; write pid to file\n"
		" --user=<username>\t\t\t; drop root privs\n"
		" --uid=uid[:gid]\t\t\t; drop root privs\n"
		" --wsize=<window_size>\t\t\t; set window size. 0 = do not modify. OBSOLETE !\n"
		" --hostcase\t\t\t\t; change Host: => host:\n"
		" --hostspell\t\t\t\t; exact spelling of \"Host\" header. must be 4 chars. default is \"host\"\n"
		" --hostnospace\t\t\t\t; remove space after Host: and add it to User-Agent: to preserve packet size\n"
		" --dpi-desync[=<mode>]\t\t\t; try to desync dpi state. modes : fake rst rstack disorder disorder2 split split2\n"
		" --dpi-desync-fwmark=<int|0xHEX>\t; override fwmark for desync packet. default = 0x%08X\n"
		" --dpi-desync-ttl=<int>\t\t\t; set ttl for desync packet\n"
		" --dpi-desync-fooling=<mode>[,<mode>]\t; can use multiple comma separated values. modes : none md5sig ts badseq badsum\n"
		" --dpi-desync-retrans=0|1\t\t; 0(default)=reinject original data packet after fake  1=drop original data packet to force its retransmission\n"
		" --dpi-desync-skip-nosni=0|1\t\t; 1(default)=do not act on ClientHello without SNI (ESNI ?)\n"
		" --dpi-desync-split-pos=<1..%u>\t; (for disorder only) split TCP packet at specified position\n"
		" --dpi-desync-any-protocol=0|1\t\t; 0(default)=desync only http and tls  1=desync any nonempty data packet\n"
		" --hostlist=<filename>\t\t\t; apply dpi desync only to the listed hosts (one host per line, subdomains auto apply)\n",
		DPI_DESYNC_FWMARK_DEFAULT,DPI_DESYNC_MAX_FAKE_LEN
	);
	exit(1);
}

static void cleanup_params()
{
	if (params.hostlist)
	{
		StrPoolDestroy(&params.hostlist);
		params.hostlist = NULL;
	}
}
static void exithelp_clean()
{
	cleanup_params();
	exithelp();
}
static void exit_clean(int code)
{
	cleanup_params();
	exit(code);
}



int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));
	int option_index = 0;
	int v;
	bool daemon = false;
	uid_t uid = 0;
	gid_t gid = 0;
	char pidfile[256];

	srandom(time(NULL));

	memset(&params, 0, sizeof(params));
	memcpy(params.hostspell, "host", 4); // default hostspell
	*pidfile = 0;

	params.desync_fwmark = DPI_DESYNC_FWMARK_DEFAULT;
	params.desync_skip_nosni = true;
	params.desync_split_pos = 3;

	const struct option long_options[] = {
		{"debug",optional_argument,0,0},	// optidx=0
		{"qnum",required_argument,0,0},		// optidx=1
		{"daemon",no_argument,0,0},		// optidx=2
		{"pidfile",required_argument,0,0},	// optidx=3
		{"user",required_argument,0,0 },	// optidx=4
		{"uid",required_argument,0,0 },		// optidx=5
		{"wsize",required_argument,0,0},	// optidx=6
		{"hostcase",no_argument,0,0},		// optidx=7
		{"hostspell",required_argument,0,0},	// optidx=8
		{"hostnospace",no_argument,0,0},	// optidx=9
		{"dpi-desync",optional_argument,0,0},		// optidx=10
		{"dpi-desync-fwmark",required_argument,0,0},	// optidx=11
		{"dpi-desync-ttl",required_argument,0,0},	// optidx=12
		{"dpi-desync-fooling",required_argument,0,0},	// optidx=13
		{"dpi-desync-retrans",optional_argument,0,0},	// optidx=14
		{"dpi-desync-skip-nosni",optional_argument,0,0},// optidx=15
		{"dpi-desync-split-pos",required_argument,0,0},// optidx=16
		{"dpi-desync-any-protocol",optional_argument,0,0},// optidx=17
		{"hostlist",required_argument,0,0},		// optidx=18
		{NULL,0,NULL,0}
	};
	if (argc < 2) exithelp();
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp();
		switch (option_index)
		{
		case 0: /* debug */
			params.debug = !optarg || atoi(optarg);
			break;
		case 1: /* qnum */
			params.qnum = atoi(optarg);
			if (params.qnum < 0 || params.qnum>65535)
			{
				fprintf(stderr, "bad qnum\n");
				exit_clean(1);
			}
			break;
		case 2: /* daemon */
			daemon = true;
			break;
		case 3: /* pidfile */
			strncpy(pidfile, optarg, sizeof(pidfile));
			pidfile[sizeof(pidfile) - 1] = '\0';
			break;
		case 4: /* user */
		{
			struct passwd *pwd = getpwnam(optarg);
			if (!pwd)
			{
				fprintf(stderr, "non-existent username supplied\n");
				exit_clean(1);
			}
			uid = pwd->pw_uid;
			gid = pwd->pw_gid;
			break;
		}
		case 5: /* uid */
			gid = 0x7FFFFFFF; // default git. drop gid=0
			if (!sscanf(optarg, "%u:%u", &uid, &gid))
			{
				fprintf(stderr, "--uid should be : uid[:gid]\n");
				exit_clean(1);
			}
			break;
		case 6: /* wsize */
			params.wsize = atoi(optarg);
			if (params.wsize < 0 || params.wsize>65535)
			{
				fprintf(stderr, "bad wsize\n");
				exit_clean(1);
			}
			break;
		case 7: /* hostcase */
			params.hostcase = true;
			break;
		case 8: /* hostspell */
			if (strlen(optarg) != 4)
			{
				fprintf(stderr, "hostspell must be exactly 4 chars long\n");
				exit_clean(1);
			}
			params.hostcase = true;
			memcpy(params.hostspell, optarg, 4);
			break;
		case 9: /* hostnospace */
			params.hostnospace = true;
			break;
		case 10: /* dpi-desync */
			if (!optarg || !strcmp(optarg,"fake"))
				params.desync_mode = DESYNC_FAKE;
			else if (!strcmp(optarg,"rst"))
				params.desync_mode = DESYNC_RST;
			else if (!strcmp(optarg,"rstack"))
				params.desync_mode = DESYNC_RSTACK;
			else if (!strcmp(optarg,"disorder"))
				params.desync_mode = DESYNC_DISORDER;
			else if (!strcmp(optarg,"disorder2"))
				params.desync_mode = DESYNC_DISORDER2;
			else if (!strcmp(optarg,"split"))
				params.desync_mode = DESYNC_SPLIT;
			else if (!strcmp(optarg,"split2"))
				params.desync_mode = DESYNC_SPLIT2;
			else
			{
				fprintf(stderr, "invalid dpi-desync mode\n");
				exit_clean(1);
			}
			break;
		case 11: /* dpi-desync */
			params.desync_fwmark = 0;
			if (!sscanf(optarg, "0x%X", &params.desync_fwmark)) sscanf(optarg, "%u", &params.desync_fwmark);
			if (!params.desync_fwmark)
			{
				fprintf(stderr, "dpi-desync-fwmark should be decimal or 0xHEX and should not be zero\n");
				exit_clean(1);
			}
			break;
		case 12: /* dpi-desync-ttl */
			params.desync_ttl = (uint8_t)atoi(optarg);
			break;
		case 13: /* dpi-desync-fooling */
			{
				char *e,*p = optarg;
				while (p)
				{
					e = strchr(p,',');
					if (e) *e++=0;
					if (!strcmp(p,"md5sig"))
						params.desync_tcp_fooling_mode |= TCP_FOOL_MD5SIG;
					else if (!strcmp(p,"ts"))
						params.desync_tcp_fooling_mode |= TCP_FOOL_TS;
					else if (!strcmp(p,"badsum"))
						params.desync_tcp_fooling_mode |= TCP_FOOL_BADSUM;
					else if (!strcmp(p,"badseq"))
						params.desync_tcp_fooling_mode |= TCP_FOOL_BADSEQ;
					else if (strcmp(p,"none"))
					{
						fprintf(stderr, "dpi-desync-fooling allowed values : none,md5sig,ts,badseq,badsum\n");
						exit_clean(1);
					}
					p = e;
				}
			}
			break;
		case 14: /* dpi-desync-retrans */
			params.desync_retrans = !optarg || atoi(optarg);
			break;
		case 15: /* dpi-desync-skip-nosni */
			params.desync_skip_nosni = !optarg || atoi(optarg);
			break;
		case 16: /* dpi-desync-split-pos */
			params.desync_split_pos = atoi(optarg);
			if (params.desync_split_pos<1 || params.desync_split_pos>DPI_DESYNC_MAX_FAKE_LEN)
			{
				fprintf(stderr, "dpi-desync-split-pos must be within 1..%u range\n",DPI_DESYNC_MAX_FAKE_LEN);
				exit_clean(1);
			}
			break;
		case 17: /* dpi-desync-any-protocol */
			params.desync_any_proto = !optarg || atoi(optarg);
			break;
		case 18: /* hostlist */
			if (!LoadHostList(&params.hostlist, optarg))
				exit_clean(1);
			strncpy(params.hostfile,optarg,sizeof(params.hostfile));
			params.hostfile[sizeof(params.hostfile)-1]='\0';
			break;
		}
	}

	if (daemon) daemonize();

	h = NULL;
	qh = NULL;

	if (*pidfile && !writepid(pidfile))
	{
		fprintf(stderr, "could not write pidfile\n");
		goto exiterr;
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		goto exiterr;
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		goto exiterr;
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		goto exiterr;
	}

	printf("binding this socket to queue '%u'\n", params.qnum);
	qh = nfq_create_queue(h, params.qnum, &cb, &params);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		goto exiterr;
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		goto exiterr;
	}
	if (nfq_set_queue_maxlen(qh, Q_MAXLEN) < 0) {
		fprintf(stderr, "can't set queue maxlen\n");
		goto exiterr;
	}
	// accept packets if they cant be handled
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN , NFQA_CFG_F_FAIL_OPEN))
	{
		fprintf(stderr, "can't set queue flags. errno=%d\n", errno);
		// dot not fail. not supported on old linuxes <3.6 
	}

	if (!droproot(uid, gid)) goto exiterr;
	printf("Running as UID=%u GID=%u\n", getuid(), getgid());

	signal(SIGHUP, onhup);

	desync_init();

	fd = nfq_fd(h);

	// increase socket buffer size. on slow systems reloading hostlist can take a while.
	// if too many unhandled packets are received its possible to get "no buffer space available" error
	rv = Q_RCVBUF/2;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rv, sizeof(int)) <0)
	{
		perror("setsockopt (SO_RCVBUF): ");
		goto exiterr;
	}
	do
	{
		while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
		{
			dohup();
			int r = nfq_handle_packet(h, buf, rv);
			if (r) fprintf(stderr, "nfq_handle_packet error %d\n", r);
		}
		fprintf(stderr, "recv: errno %d\n",errno);
		perror("recv");
		// do not fail on ENOBUFS
	} while(errno==ENOBUFS);

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	rawsend_cleanup();
	cleanup_params();
	return 0;

exiterr:
	if (qh) nfq_destroy_queue(qh);
	if (h) nfq_close(h);
	cleanup_params();
	return 1;
}
