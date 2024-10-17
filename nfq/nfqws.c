#define _GNU_SOURCE

#include "nfqws.h"
#include "sec.h"
#include "desync.h"
#include "helpers.h"
#include "checksum.h"
#include "params.h"
#include "protocol.h"
#include "hostlist.h"
#include "ipset.h"
#include "gzip.h"
#include "pools.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <syslog.h>

#ifdef __CYGWIN__
#include "win.h"
#endif

#ifdef __linux__
#include <libnetfilter_queue/libnetfilter_queue.h>
#define NF_DROP 0
#define NF_ACCEPT 1
#endif

#define CTRACK_T_SYN	60
#define CTRACK_T_FIN	60
#define CTRACK_T_EST	300
#define CTRACK_T_UDP	60

struct params_s params;
#ifdef __CYGWIN__
bool bQuit=false;
#endif

static bool bHup = false;
static void onhup(int sig)
{
	printf("HUP received !\n");
	printf("Will reload hostlists and ipsets on next request (if any)\n");
	bHup = true;
}
// should be called in normal execution
static void dohup(void)
{
	if (bHup)
	{
		if (!LoadIncludeHostLists() || !LoadExcludeHostLists() || !LoadIncludeIpsets() || !LoadExcludeIpsets())
		{
			// what will we do without hostlist ?? sure, gonna die
			exit(1);
		}
		bHup = false;
	}
}

static void onusr1(int sig)
{
	printf("\nCONNTRACK DUMP\n");
	ConntrackPoolDump(&params.conntrack);
	printf("\n");
}
static void onusr2(int sig)
{
	printf("\nHOSTFAIL POOL DUMP\n");
	
	struct desync_profile_list *dpl;
	LIST_FOREACH(dpl, &params.desync_profiles, next)
	{
		printf("\nDESYNC PROFILE %d\n",dpl->dp.n);
		HostFailPoolDump(dpl->dp.hostlist_auto_fail_counters);
	}
	
	printf("\n");
}

static void pre_desync(void)
{
	signal(SIGHUP, onhup);
	signal(SIGUSR1, onusr1);
	signal(SIGUSR2, onusr2);

	desync_init();
}


static uint8_t processPacketData(uint32_t *mark, const char *ifout, uint8_t *data_pkt, size_t *len_pkt)
{
#ifdef __linux__
	if (*mark & params.desync_fwmark)
	{
		DLOG("ignoring generated packet\n");
		return VERDICT_PASS;
	}
#endif
	return dpi_desync_packet(*mark, ifout, data_pkt, len_pkt);
}


#ifdef __linux__
static int nfq_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *cookie)
{
	int id, ilen;
	size_t len;
	struct nfqnl_msg_packet_hdr *ph;
	uint8_t *data;
	uint32_t ifidx;
	char ifout[IFNAMSIZ+1];

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ph ? ntohl(ph->packet_id) : 0;

	uint32_t mark = nfq_get_nfmark(nfa);
	ilen = nfq_get_payload(nfa, &data);

	*ifout=0;
	if (params.bind_fix4 || params.bind_fix6)
	{
		char ifin[IFNAMSIZ+1];
		uint32_t ifidx_in;

		ifidx = nfq_get_outdev(nfa);
		if (ifidx) if_indextoname(ifidx,ifout);
		*ifin=0;
		ifidx_in = nfq_get_indev(nfa);
		if (ifidx_in) if_indextoname(ifidx_in,ifin);

		DLOG("packet: id=%d len=%d mark=%08X ifin=%s(%u) ifout=%s(%u)\n", id, ilen, mark, ifin, ifidx_in, ifout, ifidx);
	}
	else
		// save some syscalls
		DLOG("packet: id=%d len=%d mark=%08X\n", id, ilen, mark);
	if (ilen >= 0)
	{
		len = ilen;
		uint8_t verdict = processPacketData(&mark, ifout, data, &len);
		switch(verdict & VERDICT_MASK)
		{
		case VERDICT_MODIFY:
			DLOG("packet: id=%d pass modified. len=%zu\n", id, len);
			return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, (uint32_t)len, data);
		case VERDICT_DROP:
			DLOG("packet: id=%d drop\n", id);
			return nfq_set_verdict2(qh, id, NF_DROP, mark, 0, NULL);
		}
	}
	DLOG("packet: id=%d pass unmodified\n", id);
	return nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);
}
static int nfq_main(void)
{
	struct nfq_handle *h = NULL;
	struct nfq_q_handle *qh = NULL;
	int fd,rv;
	uint8_t buf[16384] __attribute__((aligned));

	DLOG_CONDUP("opening library handle\n");
	h = nfq_open();
	if (!h) {
		DLOG_PERROR("nfq_open()");
		goto exiterr;
	}

	DLOG_CONDUP("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		DLOG_PERROR("nfq_unbind_pf()");
		goto exiterr;
	}

	DLOG_CONDUP("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		DLOG_PERROR("nfq_bind_pf()");
		goto exiterr;
	}

	DLOG_CONDUP("binding this socket to queue '%u'\n", params.qnum);
	qh = nfq_create_queue(h, params.qnum, &nfq_cb, &params);
	if (!qh) {
		DLOG_PERROR("nfq_create_queue()");
		goto exiterr;
	}

	DLOG_CONDUP("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		DLOG_PERROR("can't set packet_copy mode");
		goto exiterr;
	}
	if (nfq_set_queue_maxlen(qh, Q_MAXLEN) < 0) {
		DLOG_PERROR("can't set queue maxlen");
		goto exiterr;
	}
	// accept packets if they cant be handled
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_FAIL_OPEN , NFQA_CFG_F_FAIL_OPEN))
	{
		DLOG_ERR("can't set queue flags. its OK on linux <3.6\n");
		// dot not fail. not supported on old linuxes <3.6 
	}

	DLOG_CONDUP("initializing raw sockets bind-fix4=%u bind-fix6=%u\n",params.bind_fix4,params.bind_fix6);
	if (!rawsend_preinit(params.bind_fix4,params.bind_fix6))
		goto exiterr;

#ifndef __CYGWIN__
	sec_harden();

	if (params.droproot && !droproot(params.uid, params.gid))
		goto exiterr;

	print_id();
#endif

	pre_desync();

	fd = nfq_fd(h);

	// increase socket buffer size. on slow systems reloading hostlist can take a while.
	// if too many unhandled packets are received its possible to get "no buffer space available" error
	if (!set_socket_buffers(fd,Q_RCVBUF/2,Q_SNDBUF/2))
		goto exiterr;
	do
	{
		while ((rv = recv(fd, buf, sizeof(buf), 0)) > 0)
		{
			dohup();
			int r = nfq_handle_packet(h, (char *)buf, rv);
			if (r) DLOG_ERR("nfq_handle_packet error %d\n", r);
		}
		DLOG_ERR("recv: errno %d\n",errno);
		DLOG_PERROR("recv");
		// do not fail on ENOBUFS
	} while(errno==ENOBUFS);

	DLOG_CONDUP("unbinding from queue %u\n", params.qnum);
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	DLOG_CONDUP("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	DLOG_CONDUP("closing library handle\n");
	nfq_close(h);
	return 0;

exiterr:
	if (qh) nfq_destroy_queue(qh);
	if (h) nfq_close(h);
	return 1;
}

#elif defined(BSD)

static int dvt_main(void)
{
	uint8_t buf[16384] __attribute__((aligned));
	struct sockaddr_storage sa_from;
	int fd[2] = {-1,-1}; // 4,6
	int i,r,res=1,fdct=1,fdmax;
	unsigned int id=0;
	socklen_t socklen;
	ssize_t rd,wr;
	fd_set fdset;

	{
		struct sockaddr_in bp4;
		bp4.sin_family = AF_INET;
		bp4.sin_port = htons(params.port);
		bp4.sin_addr.s_addr = INADDR_ANY;
	
		DLOG_CONDUP("creating divert4 socket\n");
		fd[0] = socket_divert(AF_INET);
		if (fd[0] == -1) {
			DLOG_PERROR("socket (DIVERT4)");
			goto exiterr;
		}
		DLOG_CONDUP("binding divert4 socket\n");
		if (bind(fd[0], (struct sockaddr*)&bp4, sizeof(bp4)) < 0)
		{
			DLOG_PERROR("bind (DIVERT4)");
			goto exiterr;
		}
		if (!set_socket_buffers(fd[0],Q_RCVBUF,Q_SNDBUF))
			goto exiterr;
	}


#ifdef __OpenBSD__
	{
		// in OpenBSD must use separate divert sockets for ipv4 and ipv6
		struct sockaddr_in6 bp6;
		memset(&bp6,0,sizeof(bp6));
		bp6.sin6_family = AF_INET6;
		bp6.sin6_port = htons(params.port);
	
		DLOG_CONDUP("creating divert6 socket\n");
		fd[1] = socket_divert(AF_INET6);
		if (fd[1] == -1) {
			DLOG_PERROR("socket (DIVERT6)");
			goto exiterr;
		}
		DLOG_CONDUP("binding divert6 socket\n");
		if (bind(fd[1], (struct sockaddr*)&bp6, sizeof(bp6)) < 0)
		{
			DLOG_PERROR("bind (DIVERT6)");
			goto exiterr;
		}
		fdct++;
		if (!set_socket_buffers(fd[1],Q_RCVBUF,Q_SNDBUF))
			goto exiterr;
	}
#endif
	fdmax = (fd[0]>fd[1] ? fd[0] : fd[1]) + 1;

	DLOG_CONDUP("initializing raw sockets\n");
	if (!rawsend_preinit(false,false))
		goto exiterr;

	if (params.droproot && !droproot(params.uid, params.gid))
		goto exiterr;
	print_id();

	pre_desync();

	for(;;)
	{
		FD_ZERO(&fdset);
		for(i=0;i<fdct;i++) FD_SET(fd[i], &fdset);
		r = select(fdmax,&fdset,NULL,NULL,NULL);
		if (r==-1)
		{
			if (errno==EINTR)
			{
				// a signal received
				dohup();
				continue;
			}
			DLOG_PERROR("select");
			goto exiterr;
		}
		for(i=0;i<fdct;i++)
		{
			if (FD_ISSET(fd[i], &fdset))
			{
				socklen = sizeof(sa_from);
				rd = recvfrom(fd[i], buf, sizeof(buf), 0, (struct sockaddr*)&sa_from, &socklen);
				if (rd<0)
				{
					DLOG_PERROR("recvfrom");
					goto exiterr;
				}
				else if (rd>0)
				{
					uint32_t mark=0;
					uint8_t verdict;
					size_t len = rd;

					DLOG("packet: id=%u len=%zu\n", id, len);
					verdict = processPacketData(&mark, NULL, buf, &len);
					switch (verdict & VERDICT_MASK)
					{
					case VERDICT_PASS:
					case VERDICT_MODIFY:
						if ((verdict & VERDICT_MASK)==VERDICT_PASS)
							DLOG("packet: id=%u reinject unmodified\n", id);
						else
							DLOG("packet: id=%u reinject modified len=%zu\n", id, len);
						wr = sendto(fd[i], buf, len, 0, (struct sockaddr*)&sa_from, socklen);
						if (wr<0)
							DLOG_PERROR("reinject sendto");
						else if (wr!=len)
							DLOG_ERR("reinject sendto: not all data was reinjected. received %zu, sent %zd\n", len, wr);
						break;
					default:
						DLOG("packet: id=%u drop\n", id);
					}
					id++;
				}
				else
				{
					DLOG("unexpected zero size recvfrom\n");
				}
			}
		}
	}

	res=0;
exiterr:
	if (fd[0]!=-1) close(fd[0]);
	if (fd[1]!=-1) close(fd[1]);
	return res;
}


#elif defined (__CYGWIN__)

static int win_main(const char *windivert_filter)
{
	size_t len;
	unsigned int id;
	uint8_t verdict;
	bool bOutbound;
	uint8_t packet[16384];
	uint32_t mark;
	WINDIVERT_ADDRESS wa;
	char ifout[22];

	pre_desync();

	if (!win_dark_init(&params.ssid_filter, &params.nlm_filter))
	{
		DLOG_ERR("win_dark_init failed. win32 error %u (0x%08X)\n", w_win32_error, w_win32_error);
		return w_win32_error;
	}

	for(;;)
	{
		if (!logical_net_filter_match())
		{
			DLOG_CONDUP("logical network is not present. waiting it to appear.\n");
			fflush(stdout);
			do
			{
				if (bQuit)
				{
					DLOG("QUIT requested\n");
					win_dark_deinit();
					return 0;
				}
				usleep(500000);
			}
			while (!logical_net_filter_match());
			DLOG_CONDUP("logical network now present\n");
			fflush(stdout);
		}

		if (!windivert_init(windivert_filter))
		{
			win_dark_deinit();
			return w_win32_error;
		}

		DLOG_CONDUP("windivert initialized. capture is started.\n");

		// cygwin auto flush fails when piping
		fflush(stdout);
		fflush(stderr);

		for (id=0;;id++)
		{
			len = sizeof(packet);
			if (!windivert_recv(packet, &len, &wa))
			{
				if (errno==ENOBUFS)
				{
					DLOG("windivert: ignoring too large packet\n");
					continue; // too large packet
				}
				else if (errno==ENODEV)
				{
					DLOG_CONDUP("logical network disappeared. deinitializing windivert.\n");
					rawsend_cleanup();
					break;
				}
				else if (errno==EINTR)
				{
					DLOG("QUIT requested\n");
					win_dark_deinit();
					return 0;
				}
				DLOG_ERR("windivert: recv failed. errno %d\n", errno);
				win_dark_deinit();
				return w_win32_error;
			}

			*ifout=0;
			if (wa.Outbound) snprintf(ifout,sizeof(ifout),"%u.%u", wa.Network.IfIdx, wa.Network.SubIfIdx);
			DLOG("packet: id=%u len=%zu %s IPv6=%u IPChecksum=%u TCPChecksum=%u UDPChecksum=%u IfIdx=%u.%u\n", id, len, wa.Outbound ? "outbound" : "inbound", wa.IPv6, wa.IPChecksum, wa.TCPChecksum, wa.UDPChecksum, wa.Network.IfIdx, wa.Network.SubIfIdx);
			if (wa.Impostor)
			{
				DLOG("windivert: passing impostor packet\n");
				verdict = VERDICT_PASS;
			}
			else if (wa.Loopback)
			{
				DLOG("windivert: passing loopback packet\n");
				verdict = VERDICT_PASS;
			}
			else
			{
				dohup();

				mark=0;
				// pseudo interface id IfIdx.SubIfIdx
				verdict = processPacketData(&mark, ifout, packet, &len);
			}
			switch (verdict & VERDICT_MASK)
			{
				case VERDICT_PASS:
				case VERDICT_MODIFY:
					if ((verdict & VERDICT_MASK)==VERDICT_PASS)
						DLOG("packet: id=%u reinject unmodified\n", id);
					else
						DLOG("packet: id=%u reinject modified len=%zu\n", id, len);
					if (!windivert_send(packet, len, &wa))
						DLOG_ERR("windivert: reinject of packet id=%u failed\n", id);
					break;
				default:
					DLOG("packet: id=%u drop\n", id);
			}
	
			// cygwin auto flush fails when piping
			fflush(stdout);
			fflush(stderr);
		}
	}
	win_dark_deinit();
	return 0;
}

#endif // multiple OS divert handlers



static bool parse_ws_scale_factor(char *s, uint16_t *wsize, uint8_t *wscale)
{
	int v;
	char *p;

	if ((p = strchr(s,':'))) *p++=0;
	v = atoi(s);
	if (v < 0 || v>65535)
	{
		DLOG_ERR("bad wsize\n");
		return false;
	}
	*wsize=(uint16_t)v;
	if (p && *p)
	{
		v = atoi(p);
		if (v < 0 || v>255)
		{
			DLOG_ERR("bad wscale\n");
			return false;
		}
		*wscale = (uint8_t)v;
	}
	return true;
}



static void cleanup_params(void)
{
	ConntrackPoolDestroy(&params.conntrack);

	dp_list_destroy(&params.desync_profiles);

#ifdef __CYGWIN__
	strlist_destroy(&params.ssid_filter);
	strlist_destroy(&params.nlm_filter);
#endif
}
static void exit_clean(int code)
{
	cleanup_params();
	exit(code);
}

static bool parse_cutoff(const char *opt, unsigned int *value, char *mode)
{
	*mode = (*opt=='n' || *opt=='d' || *opt=='s') ? *opt++ : 'n';
	return sscanf(opt, "%u", value)>0;
}
static bool parse_badseq_increment(const char *opt, uint32_t *value)
{
	if (((opt[0]=='0' && opt[1]=='x') || (opt[0]=='-' && opt[1]=='0' && opt[2]=='x')) && sscanf(opt+2+(opt[0]=='-'), "%X", (int32_t*)value)>0)
	{
		if (opt[0]=='-') *value = -*value;
		return true;
	}
	else
	{
		return sscanf(opt, "%d", (int32_t*)value)>0;
	}
}
static void load_file_or_exit(const char *filename, void *buf, size_t *size)
{
	if (filename[0]=='0' && filename[1]=='x')
	{
		if (!parse_hex_str(filename+2,buf,size) || !*size)
		{
			DLOG_ERR("invalid hex string: %s\n",filename+2);
			exit_clean(1);
		}
		DLOG("read %zu bytes from hex string\n",*size);
	}
	else
	{
		if (!load_file_nonempty(filename,buf,size))
		{
			DLOG_ERR("could not read %s\n",filename);
			exit_clean(1);
		}
		DLOG("read %zu bytes from %s\n",*size,filename);
	}
}

static bool parse_autottl(const char *s, autottl *t)
{
	unsigned int delta,min,max;
	AUTOTTL_SET_DEFAULT(*t);
	if (s)
	{
		max = t->max;
		switch (sscanf(s,"%u:%u-%u",&delta,&min,&max))
		{
			case 3:
				if ((delta && !max) || max>255) return false;
				t->max=(uint8_t)max;
			case 2:
				if ((delta && !min) || min>255 || min>max) return false;
				t->min=(uint8_t)min;
			case 1:
				if (delta>255) return false;
				t->delta=(uint8_t)delta;
				break;
			default:
				return false;
		}
	}
	return true;
}

static bool parse_l7_list(char *opt, uint32_t *l7)
{
	char *e,*p,c;

	for (p=opt,*l7=0 ; p ; )
	{
		if ((e = strchr(p,',')))
		{
			c=*e;
			*e=0;
		}

		if (!strcmp(p,"http"))
			*l7 |= L7_PROTO_HTTP;
		else if (!strcmp(p,"tls"))
			*l7 |= L7_PROTO_TLS;
		else if (!strcmp(p,"quic"))
			*l7 |= L7_PROTO_QUIC;
		else if (!strcmp(p,"wireguard"))
			*l7 |= L7_PROTO_WIREGUARD;
		else if (!strcmp(p,"dht"))
			*l7 |= L7_PROTO_DHT;
		else if (!strcmp(p,"unknown"))
			*l7 |= L7_PROTO_UNKNOWN;
		else return false;

		if (e)
		{
			*e++=c;
		}
		p = e;
	}
	return true;
}


static bool wf_make_l3(char *opt, bool *ipv4, bool *ipv6)
{
	char *e,*p,c;

	for (p=opt,*ipv4=*ipv6=false ; p ; )
	{
		if ((e = strchr(p,',')))
		{
			c=*e;
			*e=0;
		}

		if (!strcmp(p,"ipv4"))
			*ipv4 = true;
		else if (!strcmp(p,"ipv6"))
			*ipv6 = true;
		else return false;

		if (e)
		{
			*e++=c;
		}
		p = e;
	}
	return true;
}

#ifdef __CYGWIN__
static bool wf_make_pf(char *opt, const char *l4, const char *portname, char *buf, size_t len)
{
	char *e,*p,c,s1[64];
	port_filter pf;
	int n;

	if (len<3) return false;

	for (n=0,p=opt,*buf='(',buf[1]=0 ; p ; n++)
	{
		if ((e = strchr(p,',')))
		{
			c=*e;
			*e=0;
		}
		if (!pf_parse(p,&pf)) return false;

		if (pf.from==pf.to)
			snprintf(s1, sizeof(s1), "(%s.%s %s %u)", l4, portname, pf.neg ? "!=" : "==", pf.from);
		else
			snprintf(s1, sizeof(s1), "(%s.%s %s %u %s %s.%s %s %u)", l4, portname, pf.neg ? "<" : ">=", pf.from, pf.neg ? "or" : "and" , l4, portname, pf.neg ? ">" : "<=", pf.to);
		if (n) strncat(buf," or ",len-strlen(buf)-1);
		strncat(buf, s1, len-strlen(buf)-1);

		if (e)
		{
			*e++=c;
		}
		p = e;
	}
	strncat(buf, ")", len-strlen(buf)-1);
	return true;
}

#define DIVERT_NO_LOCALNETSv4_DST "(" \
                   "(ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and " \
                   "(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and " \
                   "(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and " \
                   "(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and " \
                   "(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255))"
#define DIVERT_NO_LOCALNETSv4_SRC "(" \
                   "(ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255) and " \
                   "(ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and " \
                   "(ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and " \
                   "(ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and " \
                   "(ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255))"

#define DIVERT_NO_LOCALNETSv6_DST "(" \
                   "(ipv6.DstAddr > ::1) and " \
                   "(ipv6.DstAddr < 2001::0 or ipv6.DstAddr >= 2001:1::0) and " \
                   "(ipv6.DstAddr < fc00::0 or ipv6.DstAddr >= fe00::0) and " \
                   "(ipv6.DstAddr < fe80::0 or ipv6.DstAddr >= fec0::0) and " \
                   "(ipv6.DstAddr < ff00::0 or ipv6.DstAddr >= ffff::0))"
#define DIVERT_NO_LOCALNETSv6_SRC "(" \
                   "(ipv6.SrcAddr > ::1) and " \
                   "(ipv6.SrcAddr < 2001::0 or ipv6.SrcAddr >= 2001:1::0) and " \
                   "(ipv6.SrcAddr < fc00::0 or ipv6.SrcAddr >= fe00::0) and " \
                   "(ipv6.SrcAddr < fe80::0 or ipv6.SrcAddr >= fec0::0) and " \
                   "(ipv6.SrcAddr < ff00::0 or ipv6.SrcAddr >= ffff::0))"

#define DIVERT_NO_LOCALNETS_SRC "(" DIVERT_NO_LOCALNETSv4_SRC " or " DIVERT_NO_LOCALNETSv6_SRC ")"
#define DIVERT_NO_LOCALNETS_DST "(" DIVERT_NO_LOCALNETSv4_DST " or " DIVERT_NO_LOCALNETSv6_DST ")"

#define DIVERT_TCP_INBOUNDS "(tcp.Ack and tcp.Syn or tcp.Rst or tcp.Fin)"

// HTTP/1.? 30(2|7)
#define DIVERT_HTTP_REDIRECT "tcp.PayloadLength>=12 and tcp.Payload32[0]==0x48545450 and tcp.Payload16[2]==0x2F31 and tcp.Payload[6]==0x2E and tcp.Payload16[4]==0x2033 and tcp.Payload[10]==0x30 and (tcp.Payload[11]==0x32 or tcp.Payload[11]==0x37)"

#define DIVERT_PROLOG "!impostor and !loopback"

static bool wf_make_filter(
	char *wf, size_t len,
	unsigned int IfIdx,unsigned int SubIfIdx,
	bool ipv4, bool ipv6,
	const char *pf_tcp_src, const char *pf_tcp_dst,
	const char *pf_udp_src, const char *pf_udp_dst)
{
	char pf_dst_buf[512],iface[64];
	const char *pf_dst;
	const char *f_tcpin = *pf_tcp_src ? dp_list_have_autohostlist(&params.desync_profiles) ? "(" DIVERT_TCP_INBOUNDS " or (" DIVERT_HTTP_REDIRECT "))" : DIVERT_TCP_INBOUNDS : "";

	snprintf(iface,sizeof(iface)," ifIdx=%u and subIfIdx=%u and",IfIdx,SubIfIdx);

	if (!*pf_tcp_src && !*pf_udp_src) return false;
	if (*pf_tcp_src && *pf_udp_src)
	{
		snprintf(pf_dst_buf,sizeof(pf_dst_buf),"(%s or %s)",pf_tcp_dst,pf_udp_dst);
		pf_dst = pf_dst_buf;
	}
	else
		pf_dst = *pf_tcp_dst ? pf_tcp_dst : pf_udp_dst;
	snprintf(wf,len,
 	       DIVERT_PROLOG " and%s%s\n ((outbound and %s%s)\n  or\n  (inbound and tcp%s%s%s%s%s%s%s))",
		IfIdx ? iface : "",
		ipv4 ? ipv6 ? "" : " ip and" : " ipv6 and",
		pf_dst,
		ipv4 ? ipv6 ? " and " DIVERT_NO_LOCALNETS_DST : " and " DIVERT_NO_LOCALNETSv4_DST : " and " DIVERT_NO_LOCALNETSv6_DST,
		*pf_tcp_src ? "" : " and false",
		*f_tcpin ? " and " : "",
		*f_tcpin ? f_tcpin : "",
		*pf_tcp_src ? " and " : "",
		*pf_tcp_src ? pf_tcp_src : "",
		*pf_tcp_src ? " and " : "",
		*pf_tcp_src ? ipv4 ? ipv6 ? DIVERT_NO_LOCALNETS_SRC : DIVERT_NO_LOCALNETSv4_SRC : DIVERT_NO_LOCALNETSv6_SRC : ""
		);

	return true;
}

static unsigned int hash_jen(const void *data,unsigned int len)
{
	unsigned int hash;
	HASH_JEN(data,len,hash);
	return hash;
}

#endif


static void exithelp(void)
{
	printf(
		" --debug=0|1|syslog|@<filename>\n"
#ifdef __linux__
		" --qnum=<nfqueue_number>\n"
#elif defined(BSD)
		" --port=<port>\t\t\t\t\t; divert port\n"
#endif
		" --daemon\t\t\t\t\t; daemonize\n"
		" --pidfile=<filename>\t\t\t\t; write pid to file\n"
#ifndef __CYGWIN__
		" --user=<username>\t\t\t\t; drop root privs\n"
		" --uid=uid[:gid]\t\t\t\t; drop root privs\n"
#endif
#ifdef __linux__
		" --bind-fix4\t\t\t\t\t; apply outgoing interface selection fix for generated ipv4 packets\n"
		" --bind-fix6\t\t\t\t\t; apply outgoing interface selection fix for generated ipv6 packets\n"
#endif
		" --ctrack-timeouts=S:E:F[:U]\t\t\t; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u\n"
#ifdef __CYGWIN__
		"\nWINDIVERT FILTER:\n"
		" --wf-iface=<int>[.<int>]\t\t\t; numeric network interface and subinterface indexes\n"
		" --wf-l3=ipv4|ipv6\t\t\t\t; L3 protocol filter. multiple comma separated values allowed.\n"
		" --wf-tcp=[~]port1[-port2]\t\t\t; TCP port filter. ~ means negation. multiple comma separated values allowed.\n"
		" --wf-udp=[~]port1[-port2]\t\t\t; UDP port filter. ~ means negation. multiple comma separated values allowed.\n"
		" --wf-raw=<filter>|@<filename>\t\t\t; raw windivert filter string or filename\n"
		" --wf-save=<filename>\t\t\t\t; save windivert filter string to a file and exit\n"
		"\nLOGICAL NETWORK FILTER:\n"
		" --ssid-filter=ssid1[,ssid2,ssid3,...]\t\t; enable winws only if any of specified wifi SSIDs connected\n"
		" --nlm-filter=net1[,net2,net3,...]\t\t; enable winws only if any of specified NLM network is connected. names and GUIDs are accepted.\n"
		" --nlm-list[=all]\t\t\t\t; list Network List Manager (NLM) networks. connected only or all.\n"
#endif
		"\nMULTI-STRATEGY:\n"
		" --new\t\t\t\t\t\t; begin new strategy\n"
		" --filter-l3=ipv4|ipv6\t\t\t\t; L3 protocol filter. multiple comma separated values allowed.\n"
		" --filter-tcp=[~]port1[-port2]\t\t\t; TCP port filter. ~ means negation. setting tcp and not setting udp filter denies udp.\n"
		" --filter-udp=[~]port1[-port2]\t\t\t; UDP port filter. ~ means negation. setting udp and not setting tcp filter denies tcp.\n"
		" --filter-l7=[http|tls|quic|wireguard|dht|unknown] ; L6-L7 protocol filter. multiple comma separated values allowed.\n"
		" --ipset=<filename>\t\t\t\t; ipset include filter (one ip/CIDR per line, ipv4 and ipv6 accepted, gzip supported, multiple ipsets allowed)\n"
		" --ipset-exclude=<filename>\t\t\t; ipset exclude filter (one ip/CIDR per line, ipv4 and ipv6 accepted, gzip supported, multiple ipsets allowed)\n"
		"\nHOSTLIST FILTER:\n"
		" --hostlist=<filename>\t\t\t\t; apply dpi desync only to the listed hosts (one host per line, subdomains auto apply, gzip supported, multiple hostlists allowed)\n"
		" --hostlist-exclude=<filename>\t\t\t; do not apply dpi desync to the listed hosts (one host per line, subdomains auto apply, gzip supported, multiple hostlists allowed)\n"
		" --hostlist-auto=<filename>\t\t\t; detect DPI blocks and build hostlist automatically\n"
		" --hostlist-auto-fail-threshold=<int>\t\t; how many failed attempts cause hostname to be added to auto hostlist (default : %d)\n"
		" --hostlist-auto-fail-time=<int>\t\t; all failed attemps must be within these seconds (default : %d)\n"
		" --hostlist-auto-retrans-threshold=<int>\t; how many request retransmissions cause attempt to fail (default : %d)\n"
		" --hostlist-auto-debug=<logfile>\t\t; debug auto hostlist positives\n"
		"\nTAMPER:\n"
		" --wsize=<window_size>[:<scale_factor>]\t\t; set window size. 0 = do not modify. OBSOLETE !\n"
		" --wssize=<window_size>[:<scale_factor>]\t; set window size for server. 0 = do not modify. default scale_factor = 0.\n"
		" --wssize-cutoff=[n|d|s]N\t\t\t; apply server wsize only to packet numbers (n, default), data packet numbers (d), relative sequence (s) less than N\n"
		" --hostcase\t\t\t\t\t; change Host: => host:\n"
		" --hostspell\t\t\t\t\t; exact spelling of \"Host\" header. must be 4 chars. default is \"host\"\n"
		" --hostnospace\t\t\t\t\t; remove space after Host: and add it to User-Agent: to preserve packet size\n"
		" --domcase\t\t\t\t\t; mix domain case : Host: TeSt.cOm\n"
		" --dpi-desync=[<mode0>,]<mode>[,<mode2>]\t; try to desync dpi state. modes : synack syndata fake fakeknown rst rstack hopbyhop destopt ipfrag1 disorder disorder2 split split2 ipfrag2 udplen tamper\n"
#ifdef __linux__
		" --dpi-desync-fwmark=<int|0xHEX>\t\t; override fwmark for desync packet. default = 0x%08X (%u)\n"
#elif defined(SO_USER_COOKIE)
		" --dpi-desync-sockarg=<int|0xHEX>\t\t; override sockarg (SO_USER_COOKIE) for desync packet. default = 0x%08X (%u)\n"
#endif
		" --dpi-desync-ttl=<int>\t\t\t\t; set ttl for desync packet\n"
		" --dpi-desync-ttl6=<int>\t\t\t; set ipv6 hop limit for desync packet. by default ttl value is used.\n"
		" --dpi-desync-autottl=[<delta>[:<min>[-<max>]]]\t; auto ttl mode for both ipv4 and ipv6. default: %u:%u-%u\n"
		" --dpi-desync-autottl6=[<delta>[:<min>[-<max>]]] ; overrides --dpi-desync-autottl for ipv6 only\n"
		" --dpi-desync-fooling=<mode>[,<mode>]\t\t; can use multiple comma separated values. modes : none md5sig ts badseq badsum datanoack hopbyhop hopbyhop2\n"
		" --dpi-desync-repeats=<N>\t\t\t; send every desync packet N times\n"
		" --dpi-desync-skip-nosni=0|1\t\t\t; 1(default)=do not act on ClientHello without SNI (ESNI ?)\n"
		" --dpi-desync-split-pos=<1..%u>\t\t; data payload split position\n"
		" --dpi-desync-split-http-req=method|host\t; split at specified logical part of plain http request\n"
		" --dpi-desync-split-tls=sni|sniext\t\t; split at specified logical part of TLS ClientHello\n"
		" --dpi-desync-split-seqovl=<int>\t\t; use sequence overlap before first sent original split segment\n"
		" --dpi-desync-split-seqovl-pattern=<filename>|0xHEX ; pattern for the fake part of overlap\n"
		" --dpi-desync-ipfrag-pos-tcp=<8..%u>\t\t; ip frag position starting from the transport header. multiple of 8, default %u.\n"
		" --dpi-desync-ipfrag-pos-udp=<8..%u>\t\t; ip frag position starting from the transport header. multiple of 8, default %u.\n"
		" --dpi-desync-badseq-increment=<int|0xHEX>\t; badseq fooling seq signed increment. default %d\n"
		" --dpi-desync-badack-increment=<int|0xHEX>\t; badseq fooling ackseq signed increment. default %d\n"
		" --dpi-desync-any-protocol=0|1\t\t\t; 0(default)=desync only http and tls  1=desync any nonempty data packet\n"
		" --dpi-desync-fake-http=<filename>|0xHEX\t; file containing fake http request\n"
		" --dpi-desync-fake-tls=<filename>|0xHEX\t\t; file containing fake TLS ClientHello (for https)\n"
		" --dpi-desync-fake-unknown=<filename>|0xHEX\t; file containing unknown protocol fake payload\n"
		" --dpi-desync-fake-syndata=<filename>|0xHEX\t; file containing SYN data payload\n"
		" --dpi-desync-fake-quic=<filename>|0xHEX\t; file containing fake QUIC Initial\n"
		" --dpi-desync-fake-wireguard=<filename>|0xHEX\t; file containing fake wireguard handshake initiation\n"
		" --dpi-desync-fake-dht=<filename>|0xHEX\t\t; file containing DHT protocol fake payload (d1...e)\n"
		" --dpi-desync-fake-unknown-udp=<filename>|0xHEX\t; file containing unknown udp protocol fake payload\n"
		" --dpi-desync-udplen-increment=<int>\t\t; increase or decrease udp packet length by N bytes (default %u). negative values decrease length.\n"
		" --dpi-desync-udplen-pattern=<filename>|0xHEX\t; udp tail fill pattern\n"
		" --dpi-desync-start=[n|d|s]N\t\t\t; apply dpi desync only to packet numbers (n, default), data packet numbers (d), relative sequence (s) greater or equal than N\n"
		" --dpi-desync-cutoff=[n|d|s]N\t\t\t; apply dpi desync only to packet numbers (n, default), data packet numbers (d), relative sequence (s) less than N\n",
		CTRACK_T_SYN, CTRACK_T_EST, CTRACK_T_FIN, CTRACK_T_UDP,
		HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT, HOSTLIST_AUTO_FAIL_TIME_DEFAULT, HOSTLIST_AUTO_RETRANS_THRESHOLD_DEFAULT,
#if defined(__linux__) || defined(SO_USER_COOKIE)
		DPI_DESYNC_FWMARK_DEFAULT,DPI_DESYNC_FWMARK_DEFAULT,
#endif
		AUTOTTL_DEFAULT_DELTA,AUTOTTL_DEFAULT_MIN,AUTOTTL_DEFAULT_MAX,
		DPI_DESYNC_MAX_FAKE_LEN,
		DPI_DESYNC_MAX_FAKE_LEN, IPFRAG_UDP_DEFAULT,
		DPI_DESYNC_MAX_FAKE_LEN, IPFRAG_TCP_DEFAULT,
		BADSEQ_INCREMENT_DEFAULT, BADSEQ_ACK_INCREMENT_DEFAULT,
		UDPLEN_INCREMENT_DEFAULT
	);
	exit(1);
}
static void exithelp_clean(void)
{
	cleanup_params();
	exithelp();
}

bool parse_httpreqpos(const char *s, enum httpreqpos *pos)
{
	if (!strcmp(s, "method"))
		*pos = httpreqpos_method;
	else if (!strcmp(s, "host"))
		*pos = httpreqpos_host;
	else
		return false;
	return true;
}
bool parse_tlspos(const char *s, enum tlspos *pos)
{
	if (!strcmp(s, "sni"))
		*pos = tlspos_sni;
	else if (!strcmp(s, "sniext"))
		*pos = tlspos_sniext;
	else
		return false;
	return true;
}

int main(int argc, char **argv)
{
#ifdef __CYGWIN__
	if (service_run(argc, argv))
	{
		// we were running as service. now exit.
		return 0;
	}
#endif
	int result, v;
	int option_index = 0;
	bool daemon = false;
	char pidfile[256];
#ifdef __CYGWIN__
	char windivert_filter[8192], wf_pf_tcp_src[256], wf_pf_tcp_dst[256], wf_pf_udp_src[256], wf_pf_udp_dst[256], wf_save_file[256];
	bool wf_ipv4=true, wf_ipv6=true;
	unsigned int IfIdx=0, SubIfIdx=0;
	unsigned int hash_wf_tcp=0,hash_wf_udp=0,hash_wf_raw=0,hash_ssid_filter=0,hash_nlm_filter=0;
	*windivert_filter = *wf_pf_tcp_src = *wf_pf_tcp_dst = *wf_pf_udp_src = *wf_pf_udp_dst = *wf_save_file = 0;
#endif

	srandom(time(NULL));
	mask_from_preflen6_prepare();

	memset(&params, 0, sizeof(params));
	*pidfile = 0;

	struct desync_profile_list *dpl;
	struct desync_profile *dp;
	int desync_profile_count=0;
	if (!(dpl = dp_list_add(&params.desync_profiles)))
	{
		DLOG_ERR("desync_profile_add: out of memory\n");
		exit_clean(1);
	}
	dp = &dpl->dp;
	dp->n = ++desync_profile_count;

#ifdef __linux__
	params.qnum = -1;
#elif defined(BSD)
	params.port = 0;
#endif
	params.desync_fwmark = DPI_DESYNC_FWMARK_DEFAULT;
	params.ctrack_t_syn = CTRACK_T_SYN;
	params.ctrack_t_est = CTRACK_T_EST;
	params.ctrack_t_fin = CTRACK_T_FIN;
	params.ctrack_t_udp = CTRACK_T_UDP;

#ifdef __CYGWIN__
	LIST_INIT(&params.ssid_filter);
	LIST_INIT(&params.nlm_filter);
#else
	if (can_drop_root()) // are we root ?
	{
		params.uid = params.gid = 0x7FFFFFFF; // default uid:gid
		params.droproot = true;
	}
#endif

	const struct option long_options[] = {
		{"debug",optional_argument,0,0},	// optidx=0
#ifdef __linux__
		{"qnum",required_argument,0,0},		// optidx=1
#elif defined(BSD)
		{"port",required_argument,0,0},		// optidx=1
#else
		{"disabled_argument_1",no_argument,0,0},// optidx=1
#endif
		{"daemon",no_argument,0,0},		// optidx=2
		{"pidfile",required_argument,0,0},	// optidx=3
#ifndef __CYGWIN__
		{"user",required_argument,0,0 },	// optidx=4
		{"uid",required_argument,0,0 },		// optidx=5
#else
		{"disabled_argument_2",no_argument,0,0},	// optidx=4
		{"disabled_argument_3",no_argument,0,0},	// optidx=5
#endif
		{"wsize",required_argument,0,0},	// optidx=6
		{"wssize",required_argument,0,0},	// optidx=7
		{"wssize-cutoff",required_argument,0,0},// optidx=8
		{"ctrack-timeouts",required_argument,0,0},// optidx=9
		{"hostcase",no_argument,0,0},		// optidx=10
		{"hostspell",required_argument,0,0},	// optidx=11
		{"hostnospace",no_argument,0,0},	// optidx=12
		{"domcase",no_argument,0,0 },		// optidx=13
		{"dpi-desync",required_argument,0,0},		// optidx=14
#ifdef __linux__
		{"dpi-desync-fwmark",required_argument,0,0},	// optidx=15
#elif defined(SO_USER_COOKIE)
		{"dpi-desync-sockarg",required_argument,0,0},	// optidx=15
#else
		{"disabled_argument_4",no_argument,0,0},	// optidx=15
#endif
		{"dpi-desync-ttl",required_argument,0,0},	// optidx=16
		{"dpi-desync-ttl6",required_argument,0,0},	// optidx=17
		{"dpi-desync-autottl",optional_argument,0,0},	// optidx=18
		{"dpi-desync-autottl6",optional_argument,0,0},	// optidx=19
		{"dpi-desync-fooling",required_argument,0,0},	// optidx=20
		{"dpi-desync-repeats",required_argument,0,0},	// optidx=21
		{"dpi-desync-skip-nosni",optional_argument,0,0},// optidx=22
		{"dpi-desync-split-pos",required_argument,0,0},// optidx=23
		{"dpi-desync-split-http-req",required_argument,0,0 },// optidx=24
		{"dpi-desync-split-tls",required_argument,0,0 },// optidx=25
		{"dpi-desync-split-seqovl",required_argument,0,0 },// optidx=26
		{"dpi-desync-split-seqovl-pattern",required_argument,0,0 },// optidx=27
		{"dpi-desync-ipfrag-pos-tcp",required_argument,0,0},// optidx=28
		{"dpi-desync-ipfrag-pos-udp",required_argument,0,0},// optidx=29
		{"dpi-desync-badseq-increment",required_argument,0,0},// optidx=30
		{"dpi-desync-badack-increment",required_argument,0,0},// optidx=31
		{"dpi-desync-any-protocol",optional_argument,0,0},// optidx=32
		{"dpi-desync-fake-http",required_argument,0,0},// optidx=33
		{"dpi-desync-fake-tls",required_argument,0,0},// optidx=34
		{"dpi-desync-fake-unknown",required_argument,0,0},// optidx=35
		{"dpi-desync-fake-syndata",required_argument,0,0},// optidx=36
		{"dpi-desync-fake-quic",required_argument,0,0},// optidx=37
		{"dpi-desync-fake-wireguard",required_argument,0,0},// optidx=38
		{"dpi-desync-fake-dht",required_argument,0,0},// optidx=39
		{"dpi-desync-fake-unknown-udp",required_argument,0,0},// optidx=40
		{"dpi-desync-udplen-increment",required_argument,0,0},// optidx=41
		{"dpi-desync-udplen-pattern",required_argument,0,0},// optidx=42
		{"dpi-desync-cutoff",required_argument,0,0},// optidx=43
		{"dpi-desync-start",required_argument,0,0},// optidx=43
		{"hostlist",required_argument,0,0},		// optidx=44
		{"hostlist-exclude",required_argument,0,0},	// optidx=45
		{"hostlist-auto",required_argument,0,0},	// optidx=46
		{"hostlist-auto-fail-threshold",required_argument,0,0},	// optidx=48
		{"hostlist-auto-fail-time",required_argument,0,0},	// optidx=49
		{"hostlist-auto-retrans-threshold",required_argument,0,0},	// optidx=50
		{"hostlist-auto-debug",required_argument,0,0},	// optidx=51
		{"new",no_argument,0,0},	// optidx=52
		{"filter-l3",required_argument,0,0},	// optidx=53
		{"filter-tcp",required_argument,0,0},	// optidx=54
		{"filter-udp",required_argument,0,0},	// optidx=55
		{"filter-l7",required_argument,0,0},	// optidx=56
		{"ipset",required_argument,0,0},	// optidx=57
		{"ipset-exclude",required_argument,0,0},// optidx=58
#ifdef __linux__
		{"bind-fix4",no_argument,0,0},		// optidx=59
		{"bind-fix6",no_argument,0,0},		// optidx=60
#elif defined(__CYGWIN__)
		{"wf-iface",required_argument,0,0},	// optidx=59
		{"wf-l3",required_argument,0,0},	// optidx=60
		{"wf-tcp",required_argument,0,0},	// optidx=61
		{"wf-udp",required_argument,0,0},	// optidx=62
		{"wf-raw",required_argument,0,0},	// optidx=63
		{"wf-save",required_argument,0,0},	// optidx=64
		{"ssid-filter",required_argument,0,0},	// optidx=65
		{"nlm-filter",required_argument,0,0},	// optidx=66
		{"nlm-list",optional_argument,0,0},	// optidx=67
#endif
		{NULL,0,NULL,0}
	};
	if (argc < 2) exithelp();
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp();
		switch (option_index)
		{
		case 0: /* debug */
			if (optarg)
			{
				if (*optarg=='@')
				{
					strncpy(params.debug_logfile,optarg+1,sizeof(params.debug_logfile));
					params.debug_logfile[sizeof(params.debug_logfile)-1] = 0;
					FILE *F = fopen(params.debug_logfile,"wt");
					if (!F)
					{
						fprintf(stderr, "cannot create %s\n", params.debug_logfile);
						exit_clean(1);
					}
#ifndef __CYGWIN__
					if (params.droproot && chown(params.debug_logfile, params.uid, -1))
						fprintf(stderr, "could not chown %s. log file may not be writable after privilege drop\n", params.debug_logfile);
#endif
					params.debug = true;
					params.debug_target = LOG_TARGET_FILE;
				}
				else if (!strcmp(optarg,"syslog"))
				{
					params.debug = true;
					params.debug_target = LOG_TARGET_SYSLOG;
					openlog(progname,LOG_PID,LOG_USER);
				}
				else
				{
					params.debug = !!atoi(optarg);
					params.debug_target = LOG_TARGET_CONSOLE;
				}
			}
			else
			{
				params.debug = true;
				params.debug_target = LOG_TARGET_CONSOLE;
			}
			break;
#ifndef __CYGWIN__
		case 1: /* qnum or port */
#ifdef __linux__
			params.qnum = atoi(optarg);
			if (params.qnum < 0 || params.qnum>65535)
			{
				DLOG_ERR("bad qnum\n");
				exit_clean(1);
			}
#elif defined(BSD)
			{
				int i = atoi(optarg);
				if (i <= 0 || i > 65535)
				{
					DLOG_ERR("bad port number\n");
					exit_clean(1);
				}
				params.port = (uint16_t)i;
			}
#endif
			break;
#endif
		case 2: /* daemon */
			daemon = true;
			break;
		case 3: /* pidfile */
			strncpy(pidfile, optarg, sizeof(pidfile));
			pidfile[sizeof(pidfile) - 1] = '\0';
			break;
#ifndef __CYGWIN__
		case 4: /* user */
		{
			struct passwd *pwd = getpwnam(optarg);
			if (!pwd)
			{
				DLOG_ERR("non-existent username supplied\n");
				exit_clean(1);
			}
			params.uid = pwd->pw_uid;
			params.gid = pwd->pw_gid;
			params.droproot = true;
			break;
		}
		case 5: /* uid */
			params.gid = 0x7FFFFFFF; // default gid. drop gid=0
			params.droproot = true;
			if (sscanf(optarg, "%u:%u", &params.uid, &params.gid)<1)
			{
				DLOG_ERR("--uid should be : uid[:gid]\n");
				exit_clean(1);
			}
			break;
#endif
		case 6: /* wsize */
			if (!parse_ws_scale_factor(optarg,&dp->wsize,&dp->wscale))
				exit_clean(1);
			break;
		case 7: /* wssize */
			if (!parse_ws_scale_factor(optarg,&dp->wssize,&dp->wsscale))
				exit_clean(1);
			break;
		case 8: /* wssize-cutoff */
			if (!parse_cutoff(optarg, &dp->wssize_cutoff, &dp->wssize_cutoff_mode))
			{
				DLOG_ERR("invalid wssize-cutoff value\n");
				exit_clean(1);
			}
			break;
		case 9: /* ctrack-timeouts */
			if (sscanf(optarg, "%u:%u:%u:%u", &params.ctrack_t_syn, &params.ctrack_t_est, &params.ctrack_t_fin, &params.ctrack_t_udp)<3)
			{
				DLOG_ERR("invalid ctrack-timeouts value\n");
				exit_clean(1);
			}
			break;
		case 10: /* hostcase */
			dp->hostcase = true;
			break;
		case 11: /* hostspell */
			if (strlen(optarg) != 4)
			{
				DLOG_ERR("hostspell must be exactly 4 chars long\n");
				exit_clean(1);
			}
			dp->hostcase = true;
			memcpy(dp->hostspell, optarg, 4);
			break;
		case 12: /* hostnospace */
			dp->hostnospace = true;
			break;
		case 13: /* domcase */
			dp->domcase = true;
			break;
		case 14: /* dpi-desync */
			{
				char *mode=optarg,*mode2,*mode3;
				mode2 = mode ? strchr(mode,',') : NULL;
				if (mode2) *mode2++=0;
				mode3 = mode2 ? strchr(mode2,',') : NULL;
				if (mode3) *mode3++=0;

				dp->desync_mode0 = desync_mode_from_string(mode);
				if (desync_valid_zero_stage(dp->desync_mode0))
				{
					mode = mode2;
					mode2 = mode3;
					mode3 = NULL;
				}
				else
				{
					dp->desync_mode0 = DESYNC_NONE;
				}
				dp->desync_mode = desync_mode_from_string(mode);
				dp->desync_mode2 = desync_mode_from_string(mode2);
				if (dp->desync_mode0==DESYNC_INVALID || dp->desync_mode==DESYNC_INVALID || dp->desync_mode2==DESYNC_INVALID)
				{
					DLOG_ERR("invalid dpi-desync mode\n");
					exit_clean(1);
				}
				if (mode3)
				{
					DLOG_ERR("invalid desync combo : %s+%s+%s\n",mode,mode2,mode3);
					exit_clean(1);
				}
				if (dp->desync_mode2 && (desync_only_first_stage(dp->desync_mode) || !(desync_valid_first_stage(dp->desync_mode) && desync_valid_second_stage(dp->desync_mode2))))
				{
					DLOG_ERR("invalid desync combo : %s+%s\n", mode,mode2);
					exit_clean(1);
				}
				#if defined(__OpenBSD__)
				if (dp->desync_mode==DESYNC_IPFRAG2 || dp->desync_mode2==DESYNC_IPFRAG2)
				{
					DLOG_ERR("OpenBSD has checksum issues with fragmented packets. ipfrag disabled.\n");
					exit_clean(1);
				}
				#endif
			}
			break;
#ifndef __CYGWIN__
		case 15: /* dpi-desync-fwmark/dpi-desync-sockarg */
#if defined(__linux__) || defined(SO_USER_COOKIE)
			params.desync_fwmark = 0;
			if (sscanf(optarg, "0x%X", &params.desync_fwmark)<=0) sscanf(optarg, "%u", &params.desync_fwmark);
			if (!params.desync_fwmark)
			{
				DLOG_ERR("fwmark/sockarg should be decimal or 0xHEX and should not be zero\n");
				exit_clean(1);
			}
#else
			DLOG_ERR("fmwark/sockarg not supported in this OS\n");
			exit_clean(1);
#endif
			break;
#endif
		case 16: /* dpi-desync-ttl */
			dp->desync_ttl = (uint8_t)atoi(optarg);
			break;
		case 17: /* dpi-desync-ttl6 */
			dp->desync_ttl6 = (uint8_t)atoi(optarg);
			break;
		case 18: /* dpi-desync-autottl */
			if (!parse_autottl(optarg, &dp->desync_autottl))
			{
				DLOG_ERR("dpi-desync-autottl value error\n");
				exit_clean(1);
			}
			break;
		case 19: /* dpi-desync-autottl6 */
			if (!parse_autottl(optarg, &dp->desync_autottl6))
			{
				DLOG_ERR("dpi-desync-autottl6 value error\n");
				exit_clean(1);
			}
			break;
		case 20: /* dpi-desync-fooling */
			{
				char *e,*p = optarg;
				while (p)
				{
					e = strchr(p,',');
					if (e) *e++=0;
					if (!strcmp(p,"md5sig"))
						dp->desync_fooling_mode |= FOOL_MD5SIG;
					else if (!strcmp(p,"ts"))
						dp->desync_fooling_mode |= FOOL_TS;
					else if (!strcmp(p,"badsum"))
					{
						#ifdef __OpenBSD__
						DLOG_CONDUP("\nWARNING !!! OpenBSD may forcibly recompute tcp/udp checksums !!! In this case badsum fooling will not work.\nYou should check tcp checksum correctness in tcpdump manually before using badsum.\n\n");
						#endif
						dp->desync_fooling_mode |= FOOL_BADSUM;
					}
					else if (!strcmp(p,"badseq"))
						dp->desync_fooling_mode |= FOOL_BADSEQ;
					else if (!strcmp(p,"datanoack"))
						dp->desync_fooling_mode |= FOOL_DATANOACK;
					else if (!strcmp(p,"hopbyhop"))
						dp->desync_fooling_mode |= FOOL_HOPBYHOP;
					else if (!strcmp(p,"hopbyhop2"))
						dp->desync_fooling_mode |= FOOL_HOPBYHOP2;
					else if (strcmp(p,"none"))
					{
						DLOG_ERR("dpi-desync-fooling allowed values : none,md5sig,ts,badseq,badsum,datanoack,hopbyhop,hopbyhop2\n");
						exit_clean(1);
					}
					p = e;
				}
			}
			break;
		case 21: /* dpi-desync-repeats */
			if (sscanf(optarg,"%u",&dp->desync_repeats)<1 || !dp->desync_repeats || dp->desync_repeats>20)
			{
				DLOG_ERR("dpi-desync-repeats must be within 1..20\n");
				exit_clean(1);
			}
			break;
		case 22: /* dpi-desync-skip-nosni */
			dp->desync_skip_nosni = !optarg || atoi(optarg);
			break;
		case 23: /* dpi-desync-split-pos */
			if (sscanf(optarg,"%u",&dp->desync_split_pos)<1 || dp->desync_split_pos<1)
			{
				DLOG_ERR("dpi-desync-split-pos is not valid\n");
				exit_clean(1);
			}
			break;
		case 24: /* dpi-desync-split-http-req */
			if (!parse_httpreqpos(optarg, &dp->desync_split_http_req))
			{
				DLOG_ERR("Invalid argument for dpi-desync-split-http-req\n");
				exit_clean(1);
			}
			break;
		case 25: /* dpi-desync-split-tls */
			if (!parse_tlspos(optarg, &dp->desync_split_tls))
			{
				DLOG_ERR("Invalid argument for dpi-desync-split-tls\n");
				exit_clean(1);
			}
			break;
		case 26: /* dpi-desync-split-seqovl */
			if (sscanf(optarg,"%u",&dp->desync_seqovl)<1)
			{
				DLOG_ERR("dpi-desync-split-seqovl is not valid\n");
				exit_clean(1);
			}
			break;
		case 27: /* dpi-desync-split-seqovl-pattern */
			{
				char buf[sizeof(dp->seqovl_pattern)];
				size_t sz=sizeof(buf);
				load_file_or_exit(optarg,buf,&sz);
				fill_pattern(dp->seqovl_pattern,sizeof(dp->seqovl_pattern),buf,sz);
			}
			break;
		case 28: /* dpi-desync-ipfrag-pos-tcp */
			if (sscanf(optarg,"%u",&dp->desync_ipfrag_pos_tcp)<1 || dp->desync_ipfrag_pos_tcp<1 || dp->desync_ipfrag_pos_tcp>DPI_DESYNC_MAX_FAKE_LEN)
			{
				DLOG_ERR("dpi-desync-ipfrag-pos-tcp must be within 1..%u range\n",DPI_DESYNC_MAX_FAKE_LEN);
				exit_clean(1);
			}
			if (dp->desync_ipfrag_pos_tcp & 7)
			{
				DLOG_ERR("dpi-desync-ipfrag-pos-tcp must be multiple of 8\n");
				exit_clean(1);
			}
			break;
		case 29: /* dpi-desync-ipfrag-pos-udp */
			if (sscanf(optarg,"%u",&dp->desync_ipfrag_pos_udp)<1 || dp->desync_ipfrag_pos_udp<1 || dp->desync_ipfrag_pos_udp>DPI_DESYNC_MAX_FAKE_LEN)
			{
				DLOG_ERR("dpi-desync-ipfrag-pos-udp must be within 1..%u range\n",DPI_DESYNC_MAX_FAKE_LEN);
				exit_clean(1);
			}
			if (dp->desync_ipfrag_pos_udp & 7)
			{
				DLOG_ERR("dpi-desync-ipfrag-pos-udp must be multiple of 8\n");
				exit_clean(1);
			}
			break;
		case 30: /* dpi-desync-badseq-increments */
			if (!parse_badseq_increment(optarg,&dp->desync_badseq_increment))
			{
				DLOG_ERR("dpi-desync-badseq-increment should be signed decimal or signed 0xHEX\n");
				exit_clean(1);
			}
			break;
		case 31: /* dpi-desync-badack-increment */
			if (!parse_badseq_increment(optarg,&dp->desync_badseq_ack_increment))
			{
				DLOG_ERR("dpi-desync-badack-increment should be signed decimal or signed 0xHEX\n");
				exit_clean(1);
			}
			break;
		case 32: /* dpi-desync-any-protocol */
			dp->desync_any_proto = !optarg || atoi(optarg);
			break;
		case 33: /* dpi-desync-fake-http */
			dp->fake_http_size = sizeof(dp->fake_http);
			load_file_or_exit(optarg,dp->fake_http,&dp->fake_http_size);
			break;
		case 34: /* dpi-desync-fake-tls */
			dp->fake_tls_size = sizeof(dp->fake_tls);
			load_file_or_exit(optarg,dp->fake_tls,&dp->fake_tls_size);
			break;
		case 35: /* dpi-desync-fake-unknown */
			dp->fake_unknown_size = sizeof(dp->fake_unknown);
			load_file_or_exit(optarg,dp->fake_unknown,&dp->fake_unknown_size);
			break;
		case 36: /* dpi-desync-fake-syndata */
			dp->fake_syndata_size = sizeof(dp->fake_syndata);
			load_file_or_exit(optarg,dp->fake_syndata,&dp->fake_syndata_size);
			break;
		case 37: /* dpi-desync-fake-quic */
			dp->fake_quic_size = sizeof(dp->fake_quic);
			load_file_or_exit(optarg,dp->fake_quic,&dp->fake_quic_size);
			break;
		case 38: /* dpi-desync-fake-wireguard */
			dp->fake_wg_size = sizeof(dp->fake_wg);
			load_file_or_exit(optarg,dp->fake_wg,&dp->fake_wg_size);
			break;
		case 39: /* dpi-desync-fake-dht */
			dp->fake_dht_size = sizeof(dp->fake_dht);
			load_file_or_exit(optarg,dp->fake_dht,&dp->fake_dht_size);
			break;
		case 40: /* dpi-desync-fake-unknown-udp */
			dp->fake_unknown_udp_size = sizeof(dp->fake_unknown_udp);
			load_file_or_exit(optarg,dp->fake_unknown_udp,&dp->fake_unknown_udp_size);
			break;
		case 41: /* dpi-desync-udplen-increment */
			if (sscanf(optarg,"%d",&dp->udplen_increment)<1 || dp->udplen_increment>0x7FFF || dp->udplen_increment<-0x8000)
			{
				DLOG_ERR("dpi-desync-udplen-increment must be integer within -32768..32767 range\n");
				exit_clean(1);
			}
			break;
		case 42: /* dpi-desync-udplen-pattern */
			{
				char buf[sizeof(dp->udplen_pattern)];
				size_t sz=sizeof(buf);
				load_file_or_exit(optarg,buf,&sz);
				fill_pattern(dp->udplen_pattern,sizeof(dp->udplen_pattern),buf,sz);
			}
			break;
		case 43: /* desync-cutoff */
			if (!parse_cutoff(optarg, &dp->desync_cutoff, &dp->desync_cutoff_mode))
			{
				DLOG_ERR("invalid desync-cutoff value\n");
				exit_clean(1);
			}
			break;
		case 44: /* desync-start */
			if (!parse_cutoff(optarg, &dp->desync_start, &dp->desync_start_mode))
			{
				DLOG_ERR("invalid desync-start value\n");
				exit_clean(1);
			}
			break;
		case 45: /* hostlist */
			if (!strlist_add(&dp->hostlist_files, optarg))
			{
				DLOG_ERR("strlist_add failed\n");
				exit_clean(1);
			}
			break;
		case 46: /* hostlist-exclude */
			if (!strlist_add(&dp->hostlist_exclude_files, optarg))
			{
				DLOG_ERR("strlist_add failed\n");
				exit_clean(1);
			}
			break;
		case 47: /* hostlist-auto */
			if (*dp->hostlist_auto_filename)
			{
				DLOG_ERR("only one auto hostlist per profile is supported\n");
				exit_clean(1);
			}
			{
				FILE *F = fopen(optarg,"at");
				if (!F)
				{
					DLOG_ERR("cannot create %s\n", optarg);
					exit_clean(1);
				}
				bool bGzip = is_gzip(F);
				fclose(F);
				if (bGzip)
				{
					DLOG_ERR("gzipped auto hostlists are not supported\n");
					exit_clean(1);
				}
#ifndef __CYGWIN__
				if (params.droproot && chown(optarg, params.uid, -1))
					DLOG_ERR("could not chown %s. auto hostlist file may not be writable after privilege drop\n", optarg);
#endif
			}
			if (!strlist_add(&dp->hostlist_files, optarg))
			{
				DLOG_ERR("strlist_add failed\n");
				exit_clean(1);
			}
			strncpy(dp->hostlist_auto_filename, optarg, sizeof(dp->hostlist_auto_filename));
			dp->hostlist_auto_filename[sizeof(dp->hostlist_auto_filename) - 1] = '\0';
			break;
		case 48: /* hostlist-auto-fail-threshold */
			dp->hostlist_auto_fail_threshold = (uint8_t)atoi(optarg);
			if (dp->hostlist_auto_fail_threshold<1 || dp->hostlist_auto_fail_threshold>20)
			{
				DLOG_ERR("auto hostlist fail threshold must be within 1..20\n");
				exit_clean(1);
			}
			break;
		case 49: /* hostlist-auto-fail-time */
			dp->hostlist_auto_fail_time = (uint8_t)atoi(optarg);
			if (dp->hostlist_auto_fail_time<1)
			{
				DLOG_ERR("auto hostlist fail time is not valid\n");
				exit_clean(1);
			}
			break;
		case 50: /* hostlist-auto-retrans-threshold */
			dp->hostlist_auto_retrans_threshold = (uint8_t)atoi(optarg);
			if (dp->hostlist_auto_retrans_threshold<2 || dp->hostlist_auto_retrans_threshold>10)
			{
				DLOG_ERR("auto hostlist fail threshold must be within 2..10\n");
				exit_clean(1);
			}
			break;
		case 51: /* hostlist-auto-debug */
			{
				FILE *F = fopen(optarg,"a+t");
				if (!F)
				{
					DLOG_ERR("cannot create %s\n", optarg);
					exit_clean(1);
				}
				fclose(F);
#ifndef __CYGWIN__
				if (params.droproot && chown(optarg, params.uid, -1))
					DLOG_ERR("could not chown %s. auto hostlist debug log may not be writable after privilege drop\n", optarg);
#endif
				strncpy(params.hostlist_auto_debuglog, optarg, sizeof(params.hostlist_auto_debuglog));
				params.hostlist_auto_debuglog[sizeof(params.hostlist_auto_debuglog) - 1] = '\0';
			}
			break;

		case 52: /* new */
			if (!(dpl = dp_list_add(&params.desync_profiles)))
			{
				DLOG_ERR("desync_profile_add: out of memory\n");
				exit_clean(1);
			}
			dp = &dpl->dp;
			dp->n = ++desync_profile_count;
			break;
		case 53: /* filter-l3 */
			if (!wf_make_l3(optarg,&dp->filter_ipv4,&dp->filter_ipv6))
			{
				DLOG_ERR("bad value for --filter-l3\n");
				exit_clean(1);
			}
			break;
		case 54: /* filter-tcp */
			if (!pf_parse(optarg,&dp->pf_tcp))
			{
				DLOG_ERR("Invalid port filter : %s\n",optarg);
				exit_clean(1);
			}
			// deny udp if not set
			if (pf_is_empty(&dp->pf_udp)) dp->pf_udp.neg=true;
			break;
		case 55: /* filter-udp */
			if (!pf_parse(optarg,&dp->pf_udp))
			{
				DLOG_ERR("Invalid port filter : %s\n",optarg);
				exit_clean(1);
			}
			// deny tcp if not set
			if (pf_is_empty(&dp->pf_tcp)) dp->pf_tcp.neg=true;
			break;
		case 56: /* filter-l7 */
			if (!parse_l7_list(optarg,&dp->filter_l7))
			{
				DLOG_ERR("Invalid l7 filter : %s\n",optarg);
				exit_clean(1);
			}
			break;
		case 57: /* ipset */
			if (!strlist_add(&dp->ipset_files, optarg))
			{
				DLOG_ERR("strlist_add failed\n");
				exit_clean(1);
			}
			break;
		case 58: /* ipset-exclude */
			if (!strlist_add(&dp->ipset_exclude_files, optarg))
			{
				DLOG_ERR("strlist_add failed\n");
				exit_clean(1);
			}
			break;



#ifdef __linux__
		case 59: /* bind-fix4 */
			params.bind_fix4 = true;
			break;
		case 60: /* bind-fix6 */
			params.bind_fix6 = true;
			break;
#elif defined(__CYGWIN__)
		case 59: /* wf-iface */
			if (!sscanf(optarg,"%u.%u",&IfIdx,&SubIfIdx))
			{
				DLOG_ERR("bad value for --wf-iface\n");
				exit_clean(1);
			}
			break;
		case 60: /* wf-l3 */
			if (!wf_make_l3(optarg,&wf_ipv4,&wf_ipv6))
			{
				DLOG_ERR("bad value for --wf-l3\n");
				exit_clean(1);
			}
			break;
		case 61: /* wf-tcp */
			hash_wf_tcp=hash_jen(optarg,strlen(optarg));
			if (!wf_make_pf(optarg,"tcp","SrcPort",wf_pf_tcp_src,sizeof(wf_pf_tcp_src)) ||
				!wf_make_pf(optarg,"tcp","DstPort",wf_pf_tcp_dst,sizeof(wf_pf_tcp_dst)))
			{
				DLOG_ERR("bad value for --wf-tcp\n");
				exit_clean(1);
			}
			break;
		case 62: /* wf-udp */
			hash_wf_udp=hash_jen(optarg,strlen(optarg));
			if (!wf_make_pf(optarg,"udp","SrcPort",wf_pf_udp_src,sizeof(wf_pf_udp_src)) ||
				!wf_make_pf(optarg,"udp","DstPort",wf_pf_udp_dst,sizeof(wf_pf_udp_dst)))
			{
				DLOG_ERR("bad value for --wf-udp\n");
				exit_clean(1);
			}
			break;
		case 63: /* wf-raw */
			hash_wf_raw=hash_jen(optarg,strlen(optarg));
			if (optarg[0]=='@')
			{
				size_t sz = sizeof(windivert_filter)-1;
				load_file_or_exit(optarg+1,windivert_filter,&sz);
				windivert_filter[sz] = 0;
			}
			else
			{
				strncpy(windivert_filter, optarg, sizeof(windivert_filter));
				windivert_filter[sizeof(windivert_filter) - 1] = '\0';
			}
			break;
		case 64: /* wf-save */
			strncpy(wf_save_file, optarg, sizeof(wf_save_file));
			wf_save_file[sizeof(wf_save_file) - 1] = '\0';
			break;
		case 65: /* ssid-filter */
			hash_ssid_filter=hash_jen(optarg,strlen(optarg));
			{
				char *e,*p = optarg;
				while (p)
				{
					e = strchr(p,',');
					if (e) *e++=0;
					if (*p && !strlist_add(&params.ssid_filter, p))
					{
						DLOG_ERR("strlist_add failed\n");
						exit_clean(1);
					}
					p = e;

				}
			}
			break;
		case 66: /* nlm-filter */
			hash_nlm_filter=hash_jen(optarg,strlen(optarg));
			{
				char *e,*p = optarg;
				while (p)
				{
					e = strchr(p,',');
					if (e) *e++=0;
					if (*p && !strlist_add(&params.nlm_filter, p))
					{
						DLOG_ERR("strlist_add failed\n");
						exit_clean(1);
					}
					p = e;

				}
			}
			break;
		case 67: /* nlm-list */
			if (!nlm_list(optarg && !strcmp(optarg,"all")))
			{
				DLOG_ERR("could not get list of NLM networks\n");
				exit_clean(1);
			}
			exit_clean(0);

#endif
		}
	}
	
#ifdef __linux__
	if (params.qnum<0)
	{
		DLOG_ERR("Need queue number (--qnum)\n");
		exit_clean(1);
	}
#elif defined(BSD)
	if (!params.port)
	{
		DLOG_ERR("Need divert port (--port)\n");
		exit_clean(1);
	}
#elif defined(__CYGWIN__)
	if (!*windivert_filter)
	{
		if (!*wf_pf_tcp_src && !*wf_pf_udp_src)
		{
			DLOG_ERR("windivert filter : must specify port filter\n");
			exit_clean(1);
		}
		if (!wf_make_filter(windivert_filter, sizeof(windivert_filter), IfIdx, SubIfIdx, wf_ipv4, wf_ipv6, wf_pf_tcp_src, wf_pf_tcp_dst, wf_pf_udp_src, wf_pf_udp_dst))
		{
			DLOG_ERR("windivert filter : could not make filter\n");
			exit_clean(1);
		}
	}
	DLOG("windivert filter size: %zu\nwindivert filter:\n%s\n",strlen(windivert_filter),windivert_filter);
	if (*wf_save_file)
	{
		if (save_file(wf_save_file,windivert_filter,strlen(windivert_filter)))
		{
			DLOG_ERR("windivert filter: raw filter saved to %s\n", wf_save_file);
			exit_clean(0);
		}
		else
		{
			DLOG_ERR("windivert filter: could not save raw filter to %s\n", wf_save_file);
			exit_clean(1);
		}
	}
	HANDLE hMutexArg;
	{
		char mutex_name[128];
		snprintf(mutex_name,sizeof(mutex_name),"Global\\winws_arg_%u_%u_%u_%u_%u_%u_%u_%u_%u",hash_wf_tcp,hash_wf_udp,hash_wf_raw,hash_ssid_filter,hash_nlm_filter,IfIdx,SubIfIdx,wf_ipv4,wf_ipv6);

		hMutexArg = CreateMutexA(NULL,TRUE,mutex_name);
		if (hMutexArg && GetLastError()==ERROR_ALREADY_EXISTS)
		{
			CloseHandle(hMutexArg);	hMutexArg = NULL;
			DLOG_ERR("A copy of winws is already running with the same filter\n");
			goto exiterr;
		}
		
	}
#endif

	DLOG("adding low-priority default empty desync profile\n");
	// add default empty profile
	if (!(dpl = dp_list_add(&params.desync_profiles)))
	{
		DLOG_ERR("desync_profile_add: out of memory\n");
		exit_clean(1);
	}

	DLOG_CONDUP("we have %d user defined desync profile(s) and default low priority profile 0\n",desync_profile_count);

	LIST_FOREACH(dpl, &params.desync_profiles, next)
	{
		dp = &dpl->dp;
		// not specified - use desync_ttl value instead
		if (dp->desync_ttl6 == 0xFF) dp->desync_ttl6=dp->desync_ttl;
		if (!AUTOTTL_ENABLED(dp->desync_autottl6)) dp->desync_autottl6 = dp->desync_autottl;
		if (AUTOTTL_ENABLED(dp->desync_autottl))
			DLOG("[profile %d] autottl ipv4 %u:%u-%u\n",dp->n,dp->desync_autottl.delta,dp->desync_autottl.min,dp->desync_autottl.max);
		if (AUTOTTL_ENABLED(dp->desync_autottl6))
			DLOG("[profile %d] autottl ipv6 %u:%u-%u\n",dp->n,dp->desync_autottl6.delta,dp->desync_autottl6.min,dp->desync_autottl6.max);
		if (dp->desync_split_tls==tlspos_none && dp->desync_split_pos) dp->desync_split_tls=tlspos_pos;
		if (dp->desync_split_http_req==httpreqpos_none && dp->desync_split_pos) dp->desync_split_http_req=httpreqpos_pos;
	}

	if (!LoadIncludeHostLists())
	{
		DLOG_ERR("Include hostlists load failed\n");
		exit_clean(1);
	}
	if (!LoadExcludeHostLists())
	{
		DLOG_ERR("Exclude hostlists load failed\n");
		exit_clean(1);
	}
	if (!LoadIncludeIpsets())
	{
		DLOG_ERR("Include ipset load failed\n");
		exit_clean(1);
	}
	if (!LoadExcludeIpsets())
	{
		DLOG_ERR("Exclude ipset load failed\n");
		exit_clean(1);
	}
	
	if (daemon) daemonize();

	if (*pidfile && !writepid(pidfile))
	{
		DLOG_ERR("could not write pidfile\n");
		goto exiterr;
	}

	DLOG("initializing conntrack with timeouts tcp=%u:%u:%u udp=%u\n", params.ctrack_t_syn, params.ctrack_t_est, params.ctrack_t_fin, params.ctrack_t_udp);
	ConntrackPoolInit(&params.conntrack, 10, params.ctrack_t_syn, params.ctrack_t_est, params.ctrack_t_fin, params.ctrack_t_udp);

#ifdef __linux__
	result = nfq_main();
#elif defined(BSD)
	result = dvt_main();
#elif defined(__CYGWIN__)
	result = win_main(windivert_filter);
#else
	#error unsupported OS
#endif
ex:
	rawsend_cleanup();
	cleanup_params();
#ifdef __CYGWIN__
	if (hMutexArg)
	{
		ReleaseMutex(hMutexArg);
		CloseHandle(hMutexArg);
	}
#endif
	return result;
exiterr:
	result = 1;
	goto ex;
}
