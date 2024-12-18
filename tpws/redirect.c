#include "redirect.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "params.h"
#include "helpers.h"
#include "linux_compat.h"

#ifdef __linux__
 #include <linux/netfilter_ipv4.h>
#endif


#if defined(BSD)

#include <net/if.h>
#include <net/pfvar.h>

static int redirector_fd=-1;

void redir_close(void)
{
	if (redirector_fd!=-1)
	{
		close(redirector_fd);
		redirector_fd = -1;
		DBGPRINT("closed redirector\n");
	}
}
static bool redir_open_private(const char *fname, int flags)
{
	redir_close();
	redirector_fd = open(fname, flags);
	if (redirector_fd < 0)
	{
		DLOG_PERROR("redir_openv_private");
		return false;
	}
	DBGPRINT("opened redirector %s\n",fname);
	return true;
}
bool redir_init(void)
{
	return params.pf_enable ? redir_open_private("/dev/pf", O_RDONLY) : true;
}

static bool destination_from_pf(const struct sockaddr *accept_sa, struct sockaddr_storage *orig_dst)
{
	struct pfioc_natlook nl;
	struct sockaddr_storage asa2;

	if (redirector_fd==-1) return false;

	if (params.debug>=2)
	{
		char s[48],s2[48];
		*s=0; ntop46_port(accept_sa, s, sizeof(s));
		*s2=0; ntop46_port((struct sockaddr *)orig_dst, s2, sizeof(s2));
		DBGPRINT("destination_from_pf %s %s\n",s,s2);
	}

	saconvmapped(orig_dst);
	if (accept_sa->sa_family==AF_INET6 && orig_dst->ss_family==AF_INET)
	{
		memcpy(&asa2,accept_sa,sizeof(struct sockaddr_in6));
		saconvmapped(&asa2);
		accept_sa = (struct sockaddr*)&asa2;
	}

	if (params.debug>=2)
	{
		char s[48],s2[48];
		*s=0; ntop46_port(accept_sa, s, sizeof(s));
		*s2=0; ntop46_port((struct sockaddr *)orig_dst, s2, sizeof(s2));
		DBGPRINT("destination_from_pf (saconvmapped) %s %s\n",s,s2);
	}

	if (accept_sa->sa_family!=orig_dst->ss_family)
	{
		DBGPRINT("accept_sa and orig_dst sa_family mismatch : %d %d\n", accept_sa->sa_family, orig_dst->ss_family);
		return false;
	}

	memset(&nl, 0, sizeof(nl));
	nl.proto           = IPPROTO_TCP;
	nl.direction       = PF_OUT;
	nl.af = orig_dst->ss_family;
	switch(orig_dst->ss_family)
	{
	case AF_INET:
		{
		struct sockaddr_in *sin = (struct sockaddr_in *)orig_dst;
		nl.daddr.v4.s_addr = sin->sin_addr.s_addr;
		nl.saddr.v4.s_addr = ((struct sockaddr_in*)accept_sa)->sin_addr.s_addr;
#ifdef __APPLE__
		nl.sxport.port     = ((struct sockaddr_in*)accept_sa)->sin_port;
		nl.dxport.port     = sin->sin_port;
#else
		nl.sport           = ((struct sockaddr_in*)accept_sa)->sin_port;
		nl.dport           = sin->sin_port;
#endif
		}
		break;
	case AF_INET6:
		{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)orig_dst;
		nl.daddr.v6 = sin6->sin6_addr;
		nl.saddr.v6 = ((struct sockaddr_in6*)accept_sa)->sin6_addr;
#ifdef __APPLE__
		nl.sxport.port = ((struct sockaddr_in6*)accept_sa)->sin6_port;
		nl.dxport.port = sin6->sin6_port;
#else
		nl.sport = ((struct sockaddr_in6*)accept_sa)->sin6_port;
		nl.dport = sin6->sin6_port;
#endif
		}
		break;
	default:
		DBGPRINT("destination_from_pf : unexpected address family %d\n",orig_dst->ss_family);
		return false;
	}

	if (ioctl(redirector_fd, DIOCNATLOOK, &nl) < 0)
	{
		DLOG_PERROR("ioctl(DIOCNATLOOK) failed");
		return false;
	}
	DBGPRINT("destination_from_pf : got orig dest addr from pf\n");

	switch(nl.af)
	{
	case AF_INET:
		orig_dst->ss_family = nl.af;
#ifdef __APPLE__
		((struct sockaddr_in*)orig_dst)->sin_port = nl.rdxport.port;
#else
		((struct sockaddr_in*)orig_dst)->sin_port = nl.rdport;
#endif
		((struct sockaddr_in*)orig_dst)->sin_addr = nl.rdaddr.v4;
		break;
	case AF_INET6:
		orig_dst->ss_family = nl.af;
#ifdef __APPLE__
		((struct sockaddr_in6*)orig_dst)->sin6_port = nl.rdxport.port;
#else
		((struct sockaddr_in6*)orig_dst)->sin6_port = nl.rdport;
#endif
		((struct sockaddr_in6*)orig_dst)->sin6_addr = nl.rdaddr.v6;
		break;
	default:
		DBGPRINT("destination_from_pf : DIOCNATLOOK returned unexpected address family %d\n",nl.af);
		return false;
	}

	return true;
}


#else

bool redir_init(void) {return true;}
void redir_close(void) {};

#endif



//Store the original destination address in orig_dst
bool get_dest_addr(int sockfd, const struct sockaddr *accept_sa, struct sockaddr_storage *orig_dst)
{
	char orig_dst_str[INET6_ADDRSTRLEN];
	socklen_t addrlen = sizeof(*orig_dst);
	int r;

	memset(orig_dst, 0, addrlen);

	//For UDP transparent proxying:
	//Set IP_RECVORIGDSTADDR socket option for getting the original 
	//destination of a datagram

#ifdef __linux__
	// DNAT
	r=getsockopt(sockfd, SOL_IP, SO_ORIGINAL_DST, (struct sockaddr*) orig_dst, &addrlen);
	if (r<0)
		r = getsockopt(sockfd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, (struct sockaddr*) orig_dst, &addrlen);
	if (r<0)
	{
		DBGPRINT("both SO_ORIGINAL_DST and IP6T_SO_ORIGINAL_DST failed !\n");
#endif
		// TPROXY : socket is bound to original destination
		r=getsockname(sockfd, (struct sockaddr*) orig_dst, &addrlen);
		if (r<0)
		{
			DLOG_PERROR("getsockname");
			return false;
		}
		if (orig_dst->ss_family==AF_INET6)
			((struct sockaddr_in6*)orig_dst)->sin6_scope_id=0; // or MacOS will not connect()
#ifdef BSD
		if (params.pf_enable && !destination_from_pf(accept_sa, orig_dst))
			DBGPRINT("pf filter destination_from_pf failed\n");
#endif
#ifdef __linux__
	}
#endif
	if (saconvmapped(orig_dst))
		DBGPRINT("Original destination : converted ipv6 mapped address to ipv4\n");

	if (params.debug)
	{
		if (orig_dst->ss_family == AF_INET)
		{
			inet_ntop(AF_INET, &(((struct sockaddr_in*) orig_dst)->sin_addr), orig_dst_str, INET_ADDRSTRLEN);
			VPRINT("Original destination for socket fd=%d : %s:%d\n", sockfd,orig_dst_str, htons(((struct sockaddr_in*) orig_dst)->sin_port));
		}
		else if (orig_dst->ss_family == AF_INET6)
		{
			inet_ntop(AF_INET6,&(((struct sockaddr_in6*) orig_dst)->sin6_addr), orig_dst_str, INET6_ADDRSTRLEN);
			VPRINT("Original destination for socket fd=%d : [%s]:%d\n", sockfd,orig_dst_str, htons(((struct sockaddr_in6*) orig_dst)->sin6_port));
		}
	}
	return true;
}
