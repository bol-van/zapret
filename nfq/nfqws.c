#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
//#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>

bool proto_check_ipv4(unsigned char *data,int len)
{
	return 	len>=20 && (data[0] & 0xF0)==0x40 &&
		len>=((data[0] & 0x0F)<<2);
}
// move to transport protocol
void proto_skip_ipv4(unsigned char **data,int *len)
{
	int l;
	
	l = (**data & 0x0F)<<2;
	*data += l;
	*len -= l;
}
bool proto_check_tcp(unsigned char *data,int len)
{
	return	len>=20 && len>=((data[12] & 0xF0)>>2);
}
void proto_skip_tcp(unsigned char **data,int *len)
{
	int l;
	l = ((*data)[12] & 0xF0)>>2;
	*data += l;
	*len -= l;
}

bool proto_check_ipv6(unsigned char *data,int len)
{
	return 	len>=40 && (data[0] & 0xF0)==0x60 &&
		(len-40)>=htons(*(uint16_t*)(data+4)); // payload length
}
// move to transport protocol
// proto_type = 0 => error
void proto_skip_ipv6(unsigned char **data,int *len,uint8_t *proto_type)
{
	int hdrlen;
	uint8_t HeaderType;
	
	*proto_type = 0; // put error in advance
	
	HeaderType = (*data)[6]; // NextHeader field
	*data += 40; *len -= 40; // skip ipv6 base header
	while(*len>0) // need at least one byte for NextHeader field
	{
		switch(HeaderType)
		{
			case 0: // Hop-by-Hop Options
			case 60: // Destination Options
			case 43: // routing
				if (*len<2) return; // error
				hdrlen = 8+((*data)[1]<<3);
				break;
			case 44: // fragment
				hdrlen = 8;
				break;
			case 59: // no next header
				return; // error
			default:
				// we found some meaningful payload. it can be tcp, udp, icmp or some another exotic shit
				*proto_type = HeaderType;
				return;
		}
		if (*len<hdrlen) return; // error
		HeaderType = **data;
		// advance to the next header location
		*len -= hdrlen;
		*data += hdrlen;
	}
	// we have garbage
}

unsigned char *find_bin(unsigned char *data,int len,const void *blk,int blk_len)
{
	while (len>=blk_len)
	{
		if (!memcmp(data,blk,blk_len))
			return data;
		data++;
		len--;
	}
	return NULL;
}

static inline bool tcp_synack_segment( const struct tcphdr *tcphdr )
{
	/* check for set bits in TCP hdr */
	return  tcphdr->urg == 0 &&
		tcphdr->ack == 1 &&
		tcphdr->psh == 0 &&
		tcphdr->rst == 0 &&
		tcphdr->syn == 1 &&
		tcphdr->fin == 0;
}

uint16_t tcp_checksum(const void *buff, int len, in_addr_t src_addr, in_addr_t dest_addr)
{
	const uint16_t *buf=buff;
	uint16_t *ip_src=(uint16_t *)&src_addr, *ip_dst=(uint16_t *)&dest_addr;
	uint32_t sum;
	int length=len;

	// Calculate the sum
	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	if ( len & 1 )
	{
		// Add the padding if the packet lenght is odd
		uint16_t v=0;
		*(uint8_t *)&v = *((uint8_t *)buf);
		sum += v;
	}
		
	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(IPPROTO_TCP);
	sum += htons(length);
	
	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum
	return (uint16_t)(~sum);
}
void tcp_fix_checksum(struct tcphdr *tcp,int len, in_addr_t src_addr, in_addr_t dest_addr)
{
	tcp->check = 0;
	tcp->check = tcp_checksum(tcp,len,src_addr,dest_addr);
}
uint16_t tcp6_checksum(const void *buff, int len, const struct in6_addr *src_addr, const struct in6_addr *dest_addr)
{
	const uint16_t *buf=buff;
	const uint16_t *ip_src=(uint16_t *)src_addr, *ip_dst=(uint16_t *)dest_addr;
	uint32_t sum;
	int length=len;
	
	// Calculate the sum
	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	if ( len & 1 )
	{
		// Add the padding if the packet lenght is odd
		uint16_t v=0;
		*(uint8_t *)&v = *((uint8_t *)buf);
		sum += v;
	}
	
	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(IPPROTO_TCP);
	sum += htons(length);
	
	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum
	return (uint16_t)(~sum);
}
void tcp6_fix_checksum(struct tcphdr *tcp,int len, const struct in6_addr *src_addr, const struct in6_addr *dest_addr)
{
	tcp->check = 0;
	tcp->check = tcp6_checksum(tcp,len,src_addr,dest_addr);
}

void tcp_rewrite_winsize(struct tcphdr *tcp,uint16_t winsize)
{
    unsigned int winsize_old;
/*
    unsigned char scale_factor=1;
    int optlen = (tcp->doff << 2);
    unsigned char *opt = (unsigned char*)(tcp+1);

    optlen = optlen>sizeof(struct tcphdr) ? optlen-sizeof(struct tcphdr) : 0;
    printf("optslen=%d\n",optlen);
    while (optlen)
    {
	switch(*opt)
	{
	    case 0: break; // end of option list;
	    case 1: opt++; optlen--; break; // noop
	    default:
		if (optlen<2 || optlen<opt[1]) break;
		if (*opt==3 && opt[1]>=3)
		{
		    scale_factor=opt[2];
		    printf("Found scale factor %u\n",opt[2]);
		    //opt[2]=0;
		}
		optlen-=opt[1];
		opt+=opt[1];
	}	
    }
*/
    winsize_old = htons(tcp->window); // << scale_factor;
    tcp->window = htons(winsize);
    printf("Window size change %u => %u\n",winsize_old,winsize);
}

struct cbdata_s
{
	int wsize;
	int qnum;
	bool hostcase,hostnospace;
	char hostspell[4];
};

// ret: false - not modified, true - modified
bool processPacketData(unsigned char *data,int len,const struct cbdata_s *cbdata)
{
	struct iphdr *iphdr = NULL;
	struct ip6_hdr *ip6hdr = NULL;
	struct tcphdr *tcphdr = NULL;
	unsigned char *phost,*pua;
	int len_tcp;
	bool bRet = false;
	uint8_t proto;
	
	if (proto_check_ipv4(data,len))
	{
		iphdr = (struct iphdr *) data;
		proto = iphdr->protocol;
		proto_skip_ipv4(&data,&len);
	}
	else if (proto_check_ipv6(data,len))
	{
		ip6hdr = (struct ip6_hdr *) data;
		proto_skip_ipv6(&data,&len,&proto);
	}
	else
	{
		// not ipv6 and not ipv4
		return false;
	}
	
	if (proto==IPPROTO_TCP && proto_check_tcp(data,len))
	{
		tcphdr = (struct tcphdr *) data;
		len_tcp = len;
		proto_skip_tcp(&data,&len);
		//printf("got TCP packet. payload_len=%d\n",len);
		if (cbdata->wsize && tcp_synack_segment(tcphdr))
		{
			tcp_rewrite_winsize(tcphdr,(uint16_t)cbdata->wsize);
			bRet = true;
		}
		if ((cbdata->hostcase || cbdata->hostnospace) && (phost = find_bin(data,len,"\r\nHost: ",8)))
		{
			if (cbdata->hostcase)
			{
				printf("modifying Host: => %c%c%c%c:\n",cbdata->hostspell[0],cbdata->hostspell[1],cbdata->hostspell[2],cbdata->hostspell[3]);
				memcpy(phost+2,cbdata->hostspell,4);
				bRet = true;
			}
			if (cbdata->hostnospace && (pua = find_bin(data,len,"\r\nUser-Agent: ",14)) && (pua = find_bin(pua+1,len-(pua-data)-1,"\r\n",2)))
			{
				printf("removing space after Host: and adding it to User-Agent:\n");
				if (pua > phost)
				{
					memmove(phost+7,phost+8,pua-phost-8);
					phost[pua-phost-1] = ' ';
				}
				else
				{
					memmove(pua+1,pua,phost-pua+7);
					*pua = ' ';
				}
				bRet = true;
			}
		}
		if (bRet)
		{
			if (iphdr)
				tcp_fix_checksum(tcphdr,len_tcp,iphdr->saddr,iphdr->daddr);
			else
				tcp6_fix_checksum(tcphdr,len_tcp,&ip6hdr->ip6_src,&ip6hdr->ip6_dst);
		}
	}
	return bRet;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *cookie)
{
	int id,len;
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *data;
	const struct cbdata_s *cbdata = (struct cbdata_s*)cookie;

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ph ? ntohl(ph->packet_id) : 0;

	len = nfq_get_payload(nfa, &data);
	printf("packet: id=%d len=%d\n",id,len);
	if (len >= 0)
	{
		if (processPacketData(data, len, cbdata))
			return nfq_set_verdict(qh, id, NF_ACCEPT, len, data);
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

bool droproot(uid_t uid, gid_t gid)
{
    if (uid)
    {
         if (setgid(gid))
         {
		perror("setgid: ");
		return false;
         }
         if (setuid(uid))
         {
		perror("setuid: ");
		return false;
         }
    }
   return true;
}

void exithelp()
{
	printf(
          " --qnum=<nfqueue_number>\n"
          " --wsize=<window_size>\t; set window size. 0 = do not modify\n"
          " --hostcase\t\t; change Host: => host:\n"
          " --hostspell\t\t; exact spelling of \"Host\" header. must be 4 chars. default is \"host\"\n"
          " --hostnospace\t\t; remove space after Host: and add it to User-Agent: to preserve packet size\n"
          " --daemon\t\t; daemonize\n"
        );
	exit(1);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	struct cbdata_s cbdata;
	int option_index=0;
	int v;
	bool daemon=false;
	uid_t uid=0;
	gid_t gid;

	memset(&cbdata,0,sizeof(cbdata));
	memcpy(cbdata.hostspell,"host",4); // default hostspell
	
	const struct option long_options[] = {
    	    {"qnum",required_argument,0,0},	// optidx=0
    	    {"daemon",no_argument,0,0},		// optidx=1
    	    {"wsize",required_argument,0,0},	// optidx=2
    	    {"hostcase",no_argument,0,0},	// optidx=3
    	    {"hostspell",required_argument,0,0}, // optidx=4
    	    {"hostnospace",no_argument,0,0},	// optidx=5
    	    {"user",required_argument,0,0},	// optidx=6
    	    {NULL,0,NULL,0}
	};
	if (argc<2) exithelp();
	while ((v=getopt_long_only(argc,argv,"",long_options,&option_index))!=-1)
	{
	    if (v) exithelp();
	    switch(option_index)
	    {
		case 0: /* qnum */
		    cbdata.qnum=atoi(optarg);
		    if (cbdata.qnum<0 || cbdata.qnum>65535)
		    {
			fprintf(stdout,"bad qnum\n");
			exit(1);
		    }
		    break;
		case 1: /* daemon */
		    daemon = true;
		    break;
		case 2: /* wsize */
		    cbdata.wsize=atoi(optarg);
		    if (cbdata.wsize<0 || cbdata.wsize>65535)
		    {
			fprintf(stdout,"bad wsize\n");
			exit(1);
		    }
		    break;
		case 3: /* hostcase */
		    cbdata.hostcase = true;
		    break;
		case 4: /* hostspell */
		    if (strlen(optarg)!=4)
		    {
			fprintf(stdout,"hostspell must be exactly 4 chars long\n");
			exit(1);
		    }
		    cbdata.hostcase = true;
		    memcpy(cbdata.hostspell,optarg,4);
		    break;
		case 5: /* hostnospace */
		    cbdata.hostnospace = true;
		    break;
		case 6: /* user */
	    	{
	    		struct passwd *pwd = getpwnam(optarg);
			if (!pwd)
			{
				fprintf(stderr,"non-existent username supplied\n");
				exit(1);
			}
			uid = pwd->pw_uid;
			gid = pwd->pw_gid;
			break;
	    	}
	    }
	}

	if (daemon)
	{
	    int pid;
	    
            pid = fork();
            if (pid == -1)
                return -1;
            else if (pid != 0)
        	return 0;
            if (setsid() == -1)
                return -1;  
            if (chdir ("/") == -1)  
                return -1;
	    close(STDIN_FILENO);
	    close(STDOUT_FILENO);
	    close(STDERR_FILENO);                
	    /* redirect fd's 0,1,2 to /dev/null */  
            open ("/dev/null", O_RDWR);  
            /* stdin */
            dup(0);  
            /* stdout */
            dup(0);  
            /* stderror */
	}
	
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%u'\n", cbdata.qnum);
	qh = nfq_create_queue(h, cbdata.qnum, &cb, &cbdata);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	if (droproot(uid,gid))
	{
		while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
		{
		    int r=nfq_handle_packet(h, buf, rv);
		    if (r) fprintf(stderr,"nfq_handle_packet error %d\n",r);
		}
	}

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

	exit(0);
}
