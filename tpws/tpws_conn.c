#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netdb.h>

#include "tpws.h"
#include "tpws_conn.h"
#include "redirect.h"
#include "tamper.h"
#include "socks.h"
#include "helpers.h"
#include "hostlist.h"
#include "linux_compat.h"

// keep separate legs counter. counting every time thousands of legs can consume cpu
static int legs_local, legs_remote;
/*
static void count_legs(struct tailhead *conn_list)
{
	tproxy_conn_t *conn = NULL;

	legs_local = legs_remote = 0;
	TAILQ_FOREACH(conn, conn_list, conn_ptrs)
		conn->remote ? legs_remote++ : legs_local++;
	
}
*/
static void print_legs(void)
{
	VPRINT("Legs : local:%d remote:%d\n", legs_local, legs_remote);
}


static bool socks5_send_rep(int fd,uint8_t rep)
{
	s5_rep s5rep;
	memset(&s5rep,0,sizeof(s5rep));
	s5rep.ver = 5;
	s5rep.rep = rep;
	s5rep.atyp = S5_ATYP_IP4;
	return send(fd,&s5rep,sizeof(s5rep),MSG_DONTWAIT)==sizeof(s5rep);
}
static bool socks5_send_rep_errno(int fd,int errn)
{
	uint8_t rep;
	switch(errn)
	{
		case 0:
			rep=S5_REP_OK; break;
		case ECONNREFUSED:
			rep=S5_REP_CONN_REFUSED; break;
		case ENETUNREACH:
			rep=S5_REP_NETWORK_UNREACHABLE; break;
		case ETIMEDOUT:
		case EHOSTUNREACH:
			rep=S5_REP_HOST_UNREACHABLE; break;
		default:
			rep=S5_REP_GENERAL_FAILURE;
	}
	return socks5_send_rep(fd,rep);
}
static bool socks4_send_rep(int fd, uint8_t rep)
{
	s4_rep s4rep;
	memset(&s4rep, 0, sizeof(s4rep));
	s4rep.rep = rep;
	return send(fd, &s4rep, sizeof(s4rep), MSG_DONTWAIT) == sizeof(s4rep);
}
static bool socks4_send_rep_errno(int fd, int errn)
{
	return socks4_send_rep(fd, errn ? S4_REP_FAILED : S4_REP_OK);
}
static bool socks_send_rep(uint8_t ver, int fd, uint8_t rep5)
{
	return ver==5 ? socks5_send_rep(fd, rep5) : socks4_send_rep(fd, rep5 ? S4_REP_FAILED : S4_REP_OK);
}
static bool socks_send_rep_errno(uint8_t ver, int fd, int errn)
{
	return ver==5 ? socks5_send_rep_errno(fd,errn) : socks4_send_rep_errno(fd, errn);
}


static bool cork(int fd, int enable)
{
#ifdef __linux__
	int e = errno;
	if (setsockopt(fd, SOL_TCP, TCP_CORK, &enable, sizeof(enable))<0)
	{
		DLOG_PERROR("setsockopt (TCP_CORK)");
		errno = e;
		return false;
	}
	errno = e;
#endif
	return true;
}

ssize_t send_with_ttl(int fd, const void *buf, size_t len, int flags, int ttl)
{
	ssize_t wr;

	if (!params.skip_nodelay)
	{
		int ttl_apply = ttl ? ttl : params.ttl_default;
		DBGPRINT("send_with_ttl %d fd=%d\n",ttl,fd);
		if (!set_ttl_hl(fd, ttl_apply))
			//DLOG_ERR("could not set ttl %d to fd=%d\n",ttl,fd);
			DLOG_ERR("could not set ttl %d to fd=%d\n",ttl_apply,fd);
		cork(fd,true);
	}
	wr = send(fd, buf, len, flags);
	if (!params.skip_nodelay)
		cork(fd,false);
	return wr;
}


static bool send_buffer_create(send_buffer_t *sb, const void *data, size_t len, size_t extra_bytes, int flags, int ttl)
{
	if (sb->data)
	{
		DLOG_ERR("FATAL : send_buffer_create but buffer is not empty\n");
		exit(1);
	}
	sb->data = malloc(len + extra_bytes);
	if (!sb->data)
	{
		DBGPRINT("send_buffer_create failed\n");
		return false;
	}
	if (data) memcpy(sb->data,data,len);
	sb->len = len;
	sb->pos = 0;
	sb->ttl = ttl;
	sb->flags = flags;
	return true;
}
static bool send_buffer_realloc(send_buffer_t *sb, size_t extra_bytes)
{
	if (sb->data)
	{
		uint8_t *p = (uint8_t*)realloc(sb->data, sb->len + extra_bytes);
		if (p)
		{
			sb->data = p;
			DBGPRINT("reallocated send_buffer from %zd to %zd\n", sb->len, sb->len + extra_bytes);
			return true;
		}
		else
		{
			DBGPRINT("failed to realloc send_buffer from %zd to %zd\n", sb->len, sb->len + extra_bytes);
		}
	}
	return false;
}

static void send_buffer_free(send_buffer_t *sb)
{
	free(sb->data);
	sb->data = NULL;
}
static void send_buffers_free(send_buffer_t *sb_array, int count)
{
	for (int i=0;i<count;i++)
		send_buffer_free(sb_array+i);
}
static void conn_free_buffers(tproxy_conn_t *conn)
{
	send_buffers_free(conn->wr_buf,sizeof(conn->wr_buf)/sizeof(conn->wr_buf[0]));
}
static bool send_buffer_present(send_buffer_t *sb)
{
	return !!sb->data;
}
static bool send_buffers_present(send_buffer_t *sb_array, int count)
{
	for(int i=0;i<count;i++)
		if (send_buffer_present(sb_array+i))
			return true;
	return false;
}
static ssize_t send_buffer_send(send_buffer_t *sb, int fd)
{
	ssize_t wr;

	wr = send_with_ttl(fd, sb->data + sb->pos, sb->len - sb->pos, sb->flags, sb->ttl);
	DBGPRINT("send_buffer_send len=%zu pos=%zu wr=%zd err=%d\n",sb->len,sb->pos,wr,errno);
	if (wr>0)
	{
		sb->pos += wr;
		if (sb->pos >= sb->len)
		{
			send_buffer_free(sb);
		}
	}
	else if (wr<0 && errno==EAGAIN) wr=0;
	
	return wr;
}
static ssize_t send_buffers_send(send_buffer_t *sb_array, int count, int fd, size_t *real_wr)
{
	ssize_t wr,twr=0;

	for (int i=0;i<count;i++)
	{
		if (send_buffer_present(sb_array+i))
		{
			wr = send_buffer_send(sb_array+i, fd);
			DBGPRINT("send_buffers_send(%d) wr=%zd err=%d\n",i,wr,errno);
			if (wr<0)
			{
				if (real_wr) *real_wr = twr;
				return wr; // send error
			}
			twr+=wr;
			if (send_buffer_present(sb_array+i)) // send next buffer only when current is fully sent
				break;
		}
	}
	if (real_wr) *real_wr = twr;
	return twr;
}

static bool conn_in_tcp_mode(tproxy_conn_t *conn)
{
	return !(conn->conn_type==CONN_TYPE_SOCKS && conn->socks_state!=S_TCP);
}

static bool conn_partner_alive(tproxy_conn_t *conn)
{
	return conn->partner && conn->partner->state!=CONN_CLOSED;
}
static bool conn_buffers_present(tproxy_conn_t *conn)
{
	return send_buffers_present(conn->wr_buf,sizeof(conn->wr_buf)/sizeof(conn->wr_buf[0]));
}
static ssize_t conn_buffers_send(tproxy_conn_t *conn)
{
	size_t wr,real_twr;
	wr = send_buffers_send(conn->wr_buf,sizeof(conn->wr_buf)/sizeof(conn->wr_buf[0]), conn->fd, &real_twr);
	conn->twr += real_twr;
	return wr;
}
static bool conn_has_unsent(tproxy_conn_t *conn)
{
	return conn->wr_unsent || conn_buffers_present(conn);
}
static int conn_bytes_unread(tproxy_conn_t *conn)
{
	int numbytes=-1;
	ioctl(conn->fd, FIONREAD, &numbytes);
	return numbytes;
}
static bool conn_has_unsent_pair(tproxy_conn_t *conn)
{
	return conn_has_unsent(conn) || (conn_partner_alive(conn) && conn_has_unsent(conn->partner));
}

static bool conn_shutdown(tproxy_conn_t *conn)
{
	conn->bShutdown = true;
	if (shutdown(conn->fd,SHUT_WR)<0)
	{
		DLOG_PERROR("shutdown");
		return false;
	}
	return true;
}

static ssize_t send_or_buffer(send_buffer_t *sb, int fd, const void *buf, size_t len, int flags, int ttl)
{
	ssize_t wr=0;
	if (len)
	{
		wr = send_with_ttl(fd, buf, len, flags, ttl);
		if (wr<0 && errno==EAGAIN) wr=0;
		if (wr>=0 && wr<len)
		{
			if (!send_buffer_create(sb, buf+wr, len-wr, 0, flags, ttl))
				wr=-1;
		}
	}
	return wr;
}

static void dbgprint_socket_buffers(int fd)
{
	if (params.debug>=2)
	{
		int v;
		socklen_t sz;
		sz=sizeof(int);
		if (!getsockopt(fd,SOL_SOCKET,SO_RCVBUF,&v,&sz))
			DBGPRINT("fd=%d SO_RCVBUF=%d\n",fd,v);
		sz=sizeof(int);
		if (!getsockopt(fd,SOL_SOCKET,SO_SNDBUF,&v,&sz))
			DBGPRINT("fd=%d SO_SNDBUF=%d\n",fd,v);
	}
}

bool set_socket_buffers(int fd, int rcvbuf, int sndbuf)
{
	DBGPRINT("set_socket_buffers fd=%d rcvbuf=%d sndbuf=%d\n",fd,rcvbuf,sndbuf);
	if (rcvbuf && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int)) <0)
	{
		DLOG_PERROR("setsockopt (SO_RCVBUF)");
		return false;
	}
	if (sndbuf && setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(int)) <0)
	{
		DLOG_PERROR("setsockopt (SO_SNDBUF)");
		return false;
	}
	dbgprint_socket_buffers(fd);
	return true;
}


static bool proxy_remote_conn_ack(tproxy_conn_t *conn, int sock_err)
{
	// if proxy mode acknowledge connection request
	// conn = remote. conn->partner = local
	if (!conn->remote || !conn_partner_alive(conn)) return false;
	bool bres = true;
	switch(conn->partner->conn_type)
	{
		case CONN_TYPE_SOCKS:
			if (conn->partner->socks_state==S_WAIT_CONNECTION)
			{
				conn->partner->socks_state=S_TCP;
				bres = socks_send_rep_errno(conn->partner->socks_ver,conn->partner->fd,sock_err);
				DBGPRINT("socks connection acknowledgement. bres=%d remote_errn=%d remote_fd=%d local_fd=%d\n",bres,sock_err,conn->fd,conn->partner->fd);
			}
			break;
	}
	return bres;
}

#if defined(__linux__) || defined(__APPLE__)

static void set_user_timeout(int fd, int timeout)
{
#ifdef __linux__
	if (timeout>0)
	{
		int msec = 1000*timeout;
		if (setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &msec, sizeof(int)) <0)
			DLOG_PERROR("setsockopt (TCP_USER_TIMEOUT)");
	}
#elif defined(__APPLE__)
	if (timeout>0 && setsockopt(fd, IPPROTO_TCP, TCP_RXT_CONNDROPTIME, &timeout, sizeof(int)) <0)
		DLOG_PERROR("setsockopt (TCP_RXT_CONNDROPTIME)");
#endif
}

#else

#define set_user_timeout(fd,timeout)

#endif


//Createas a socket and initiates the connection to the host specified by 
//remote_addr.
//Returns -1 if something fails, >0 on success (socket fd).
static int connect_remote(const struct sockaddr *remote_addr, int mss)
{
	int remote_fd = 0, yes = 1, no = 0;
    
	
 	if((remote_fd = socket(remote_addr->sa_family, SOCK_STREAM, 0)) < 0)
 	{
		DLOG_PERROR("socket (connect_remote)");
		return -1;
	}
	// Use NONBLOCK to avoid slow connects affecting the performance of other connections
	// separate fcntl call to comply with macos
	if (fcntl(remote_fd, F_SETFL, O_NONBLOCK)<0)
	{
		DLOG_PERROR("socket set O_NONBLOCK (connect_remote)");
		close(remote_fd);
		return -1;
	}
	if (setsockopt(remote_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
	{
		DLOG_PERROR("setsockopt (SO_REUSEADDR, connect_remote)");
		close(remote_fd);
		return -1;
	}
	if (!set_socket_buffers(remote_fd, params.remote_rcvbuf, params.remote_sndbuf))
	{
		close(remote_fd);
		return -1;
	}
	if (!set_keepalive(remote_fd))
	{
		DLOG_PERROR("set_keepalive");
		close(remote_fd);
		return -1;
	}
	if (setsockopt(remote_fd, IPPROTO_TCP, TCP_NODELAY, params.skip_nodelay ? &no : &yes, sizeof(int)) <0)
	{
		DLOG_PERROR("setsockopt (TCP_NODELAY, connect_remote)");
		close(remote_fd);
		return -1;
	}
#ifdef __linux__
	if (mss)
	{
		VPRINT("Setting MSS %d\n", mss);
		if (setsockopt(remote_fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(int)) <0)
		{
			DLOG_PERROR("setsockopt (TCP_MAXSEG, connect_remote)");
			close(remote_fd);
			return -1;
		}
	}
#endif

	// if no bind address specified - address family will be 0 in params_connect_bindX
	if(remote_addr->sa_family == params.connect_bind4.sin_family)
	{
		if (bind(remote_fd, (struct sockaddr *)&params.connect_bind4, sizeof(struct sockaddr_in)) == -1)
		{
			DLOG_PERROR("bind on connect");
			close(remote_fd);
			return -1;
		}
	}
	else if(remote_addr->sa_family == params.connect_bind6.sin6_family)
	{
		if (*params.connect_bind6_ifname && !params.connect_bind6.sin6_scope_id)
		{
			params.connect_bind6.sin6_scope_id=if_nametoindex(params.connect_bind6_ifname);
			if (!params.connect_bind6.sin6_scope_id)
			{
				DLOG_ERR("interface name not found : %s\n", params.connect_bind6_ifname);
				close(remote_fd);
				return -1;
			}
		}

		if (bind(remote_fd, (struct sockaddr *)&params.connect_bind6, sizeof(struct sockaddr_in6)) == -1)
		{
			DLOG_PERROR("bind on connect");
			close(remote_fd);
			return -1;
		}
	}

	set_user_timeout(remote_fd, params.tcp_user_timeout_remote);

	if (connect(remote_fd, remote_addr, remote_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0)
	{
		if(errno != EINPROGRESS)
		{
			DLOG_PERROR("connect (connect_remote)");
			close(remote_fd);
			return -1;
		}
	}
	DBGPRINT("Connecting remote fd=%d\n",remote_fd);

	return remote_fd;
}

static bool connect_remote_conn(tproxy_conn_t *conn)
{
	int mss=0;

	apply_desync_profile(&conn->track, (struct sockaddr *)&conn->dest);

	if (conn->track.dp && conn->track.dp->mss)
	{
		mss = conn->track.dp->mss;
		if (conn->track.dp->hostlist_auto)
		{
			if (conn->track.hostname)
			{
				bool bHostExcluded;
				conn->track.b_host_matches = HostlistCheck(conn->track.dp, conn->track.hostname, &bHostExcluded, false);
				conn->track.b_host_checked = true;
				if (!conn->track.b_host_matches)
				{
					conn->track.b_ah_check = !bHostExcluded;
					mss = 0;
				}
			}
		}
	}

	return (conn->partner->fd = connect_remote((struct sockaddr *)&conn->dest, mss))>=0;
}

//Free resources occupied by this connection
static void free_conn(tproxy_conn_t *conn)
{
	if (!conn) return;
	if (conn->fd) close(conn->fd);
	if (conn->splice_pipe[0])
	{
		close(conn->splice_pipe[0]);
		close(conn->splice_pipe[1]);
	}
	conn_free_buffers(conn);
	if (conn->partner) conn->partner->partner=NULL;
	free(conn->track.hostname);
	if (conn->socks_ri) conn->socks_ri->ptr = NULL; // detach conn
	free(conn);
}
static tproxy_conn_t *new_conn(int fd, bool remote)
{
	tproxy_conn_t *conn;

	//Create connection object and fill in information
	if((conn = (tproxy_conn_t*) calloc(1, sizeof(tproxy_conn_t))) == NULL)
	{
		DLOG_ERR("Could not allocate memory for connection\n");
		return NULL;
	}

	conn->state = CONN_UNAVAILABLE;
	conn->fd = fd;
	conn->remote = remote;

#ifdef SPLICE_PRESENT
	// if dont tamper - both legs are spliced, create 2 pipes
	// otherwise create pipe only in local leg
	if (!params.nosplice && ( !remote || !params.tamper || params.tamper_lim ) && pipe2(conn->splice_pipe, O_NONBLOCK) != 0)
	{
		DLOG_ERR("Could not create the splice pipe\n");
		free_conn(conn);
		return NULL;
	}
#endif
	
	return conn;
}

static bool epoll_set(tproxy_conn_t *conn, uint32_t events)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.ptr = (void*) conn;
	DBGPRINT("epoll_set fd=%d events=%08X\n",conn->fd,events);
	if(epoll_ctl(conn->efd, EPOLL_CTL_MOD, conn->fd, &ev)==-1 &&
	   epoll_ctl(conn->efd, EPOLL_CTL_ADD, conn->fd, &ev)==-1)
	{
		DLOG_PERROR("epoll_ctl (add/mod)");
		return false;
	}
	return true;
}
static bool epoll_del(tproxy_conn_t *conn)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));

	DBGPRINT("epoll_del fd=%d\n",conn->fd);
	if(epoll_ctl(conn->efd, EPOLL_CTL_DEL, conn->fd, &ev)==-1)
	{
		DLOG_PERROR("epoll_ctl (del)");
		return false;
	}
	return true;
}

static bool epoll_update_flow(tproxy_conn_t *conn)
{
	if (conn->bFlowInPrev==conn->bFlowIn && conn->bFlowOutPrev==conn->bFlowOut && conn->bPrevRdhup==(conn->state==CONN_RDHUP))
		return true; // unchanged, no need to syscall
	DBGPRINT("SET FLOW fd=%d to in=%d out=%d state_rdhup=%d\n",conn->fd,conn->bFlowIn,conn->bFlowOut,conn->state==CONN_RDHUP);
	uint32_t evtmask = (conn->state==CONN_RDHUP ? 0 : EPOLLRDHUP)|(conn->bFlowIn?EPOLLIN:0)|(conn->bFlowOut?EPOLLOUT:0);
	if (!epoll_set(conn, evtmask))
		return false;
	conn->bFlowInPrev = conn->bFlowIn;
	conn->bFlowOutPrev = conn->bFlowOut;
	conn->bPrevRdhup = (conn->state==CONN_RDHUP);
	return true;
}
static bool epoll_set_flow(tproxy_conn_t *conn, bool bFlowIn, bool bFlowOut)
{
	conn->bFlowIn = bFlowIn;
	conn->bFlowOut = bFlowOut;
	return epoll_update_flow(conn);
}

//Acquires information, initiates a connect and initialises a new connection
//object. Return NULL if anything fails, pointer to object otherwise
static tproxy_conn_t* add_tcp_connection(int efd, struct tailhead *conn_list,int local_fd, const struct sockaddr *accept_sa, uint16_t listen_port, conn_type_t proxy_type)
{
	struct sockaddr_storage orig_dst;
	tproxy_conn_t *conn;

	if (proxy_type==CONN_TYPE_TRANSPARENT)
	{
		if(!get_dest_addr(local_fd, accept_sa, &orig_dst))
		{
			DLOG_ERR("Could not get destination address\n");
			close(local_fd);
			return NULL;
		}
		if (check_local_ip((struct sockaddr*)&orig_dst) && saport((struct sockaddr*)&orig_dst)==listen_port)
		{
			VPRINT("Dropping connection to local address to the same port to avoid loop\n");
			close(local_fd);
			return NULL;
		}
	}

	// socket buffers inherited from listen_fd
	dbgprint_socket_buffers(local_fd);

	if(!set_keepalive(local_fd))
	{
		DLOG_PERROR("set_keepalive");
		close(local_fd);
		return 0;
	}

	if(!(conn = new_conn(local_fd, false)))
	{
		close(local_fd);
		return NULL;
	}
	conn->conn_type = proxy_type; // only local connection has proxy_type. remote is always in tcp mode
	conn->state = CONN_AVAILABLE; // accepted connection is immediately available
	conn->efd = efd;

	socklen_t salen=sizeof(conn->client);
	getpeername(conn->fd,(struct sockaddr *)&conn->client,&salen);

	if (proxy_type==CONN_TYPE_TRANSPARENT)
	{
		sa46copy(&conn->dest, (struct sockaddr *)&orig_dst);

		if(!(conn->partner = new_conn(0, true)))
		{
			free_conn(conn);
			return NULL;
		}

		conn->partner->partner = conn;
		conn->partner->efd = efd;
		conn->partner->client = conn->client;
		conn->partner->dest = conn->dest;

		if (!connect_remote_conn(conn))
		{
			DLOG_ERR("Failed to connect\n");
			free_conn(conn->partner);
			free_conn(conn);
			return NULL;
		}

		//remote_fd is connecting. Non-blocking connects are signaled as done by
		//socket being marked as ready for writing
		if (!epoll_set(conn->partner, EPOLLOUT))
		{
			free_conn(conn->partner);
			free_conn(conn);
			return NULL;
		}
	}

	//Transparent proxy mode :
	// Local socket can be closed while waiting for connection attempt. I need
	// to detect this when waiting for connect() to complete. However, I dont
	// want to get EPOLLIN-events, as I dont want to receive any data before
	// remote connection is established
	//Proxy mode : I need to service proxy protocol
	// remote connection not started until proxy handshake is complete

	if (!epoll_set(conn, proxy_type==CONN_TYPE_TRANSPARENT ? EPOLLRDHUP : (EPOLLIN|EPOLLRDHUP)))
	{
		free_conn(conn->partner);
		free_conn(conn);
		return NULL;
	}

	TAILQ_INSERT_HEAD(conn_list, conn, conn_ptrs);
	legs_local++;
	if (conn->partner)
	{
		TAILQ_INSERT_HEAD(conn_list, conn->partner, conn_ptrs);
		legs_remote++;
	}

	return conn;
} 

//Checks if a connection attempt was successful or not
//Returns true if successfull, false if not
static bool check_connection_attempt(tproxy_conn_t *conn, int efd)
{
	int errn = 0;
	socklen_t optlen = sizeof(errn);

	if (conn->state!=CONN_UNAVAILABLE || !conn->remote)
	{
		// locals are connected since accept
		// remote need to be checked only once
		return true;
	}

	// check the connection was sucessfull. it means its not in in SO_ERROR state
	if(getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &errn, &optlen) == -1)
	{
		DLOG_PERROR("getsockopt (SO_ERROR)");
		return false;
	}
	if (!errn)
	{
		if (params.debug>=1)
		{
			sockaddr_in46 sa;
			socklen_t salen=sizeof(sa);
			char ip_port[48];

			if (getsockname(conn->fd,(struct sockaddr *)&sa,&salen))
				*ip_port=0;
			else
				ntop46_port((struct sockaddr*)&sa,ip_port,sizeof(ip_port));
			VPRINT("Socket fd=%d (remote) connected from : %s\n", conn->fd, ip_port);
		}
		if (!epoll_set_flow(conn, true, false) || (conn_partner_alive(conn) && !epoll_set_flow(conn->partner, true, false)))
		{
			return false;
		}
		conn->state = CONN_AVAILABLE;
	}
	proxy_remote_conn_ack(conn,get_so_error(conn->fd));
	return !errn;
}




static bool epoll_set_flow_pair(tproxy_conn_t *conn)
{
	bool bHasUnsent = conn_has_unsent(conn);
	bool bHasUnsentPartner = conn_partner_alive(conn) ? conn_has_unsent(conn->partner) : false;

	DBGPRINT("epoll_set_flow_pair fd=%d remote=%d partner_fd=%d bHasUnsent=%d bHasUnsentPartner=%d state_rdhup=%d\n", 
			conn->fd , conn->remote, conn_partner_alive(conn) ? conn->partner->fd : 0, bHasUnsent, bHasUnsentPartner, conn->state==CONN_RDHUP);
	if (!epoll_set_flow(conn, !bHasUnsentPartner && (conn->state != CONN_RDHUP), bHasUnsent))
		return false;
	if (conn_partner_alive(conn))
	{
		if (!epoll_set_flow(conn->partner, !bHasUnsent && (conn->partner->state != CONN_RDHUP), bHasUnsentPartner))
			return false;
	}
	return true;
}

static bool handle_unsent(tproxy_conn_t *conn)
{
	ssize_t wr;

	DBGPRINT("+handle_unsent, fd=%d has_unsent=%d has_unsent_partner=%d\n",conn->fd,conn_has_unsent(conn),conn_partner_alive(conn) ? conn_has_unsent(conn->partner) : false);
	
#ifdef SPLICE_PRESENT
	if (!params.nosplice && conn->wr_unsent)
	{
		wr = splice(conn->splice_pipe[0], NULL, conn->fd, NULL, conn->wr_unsent, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		DBGPRINT("splice unsent=%zd wr=%zd err=%d\n",conn->wr_unsent,wr,errno);
		if (wr<0)
		{
			if (errno==EAGAIN) wr=0;
			else return false;
		}
		conn->twr += wr;
		conn->wr_unsent -= wr;
	}
#endif
	if (!conn->wr_unsent && conn_buffers_present(conn))
	{
		wr=conn_buffers_send(conn);
		DBGPRINT("conn_buffers_send wr=%zd\n",wr);
		if (wr<0) return false;
	}
	if (!conn_has_unsent(conn) && conn_partner_alive(conn) && conn->partner->state==CONN_RDHUP)
	{
		if (!conn->bShutdown)
		{
			DBGPRINT("fd=%d no more has unsent. partner in RDHUP state. executing delayed shutdown.\n", conn->fd);
			if (!conn_shutdown(conn))
			{
				DBGPRINT("emergency connection close due to failed shutdown\n");
				return false;
			}
		}
		if (conn->state==CONN_RDHUP && !conn_has_unsent(conn->partner))
		{
			DBGPRINT("both partners are in RDHUP state and have no unsent. closing.\n");
			return false;
		}
	}

	return epoll_set_flow_pair(conn);
}


static bool proxy_mode_connect_remote(tproxy_conn_t *conn, struct tailhead *conn_list)
{
	int remote_fd;

	if (params.debug>=1)
	{
		char ip_port[48];
		ntop46_port((struct sockaddr *)&conn->dest,ip_port,sizeof(ip_port));
		VPRINT("socks target for fd=%d is : %s\n", conn->fd, ip_port);
	}
	if (check_local_ip((struct sockaddr *)&conn->dest))
	{
		VPRINT("Dropping connection to local address for security reasons\n");
		socks_send_rep(conn->socks_ver, conn->fd, S5_REP_NOT_ALLOWED_BY_RULESET);
		return false;
	}

	if (!(conn->partner = new_conn(remote_fd, true)))
	{
		close(remote_fd);
		DLOG_ERR("socks out-of-memory (1)\n");
		socks_send_rep(conn->socks_ver, conn->fd, S5_REP_GENERAL_FAILURE);
		return false;
	}
	conn->partner->partner = conn;
	conn->partner->efd = conn->efd;
	conn->partner->client = conn->client;
	conn->partner->dest = conn->dest;

	if (!connect_remote_conn(conn))
	{
		free_conn(conn->partner); conn->partner = NULL;
		DLOG_ERR("socks failed to connect (1) errno=%d\n", errno);
		socks_send_rep_errno(conn->socks_ver, conn->fd, errno);
		return false;
	}

	if (!epoll_set(conn->partner, EPOLLOUT))
	{
		DLOG_ERR("socks epoll_set error %d\n", errno);
		free_conn(conn->partner);
		conn->partner = NULL;
		socks_send_rep(conn->socks_ver, conn->fd, S5_REP_GENERAL_FAILURE);
		return false;
	}
	TAILQ_INSERT_HEAD(conn_list, conn->partner, conn_ptrs);
	legs_remote++;
	print_legs();
	DBGPRINT("S_WAIT_CONNECTION\n");
	conn->socks_state = S_WAIT_CONNECTION;
	return true;
}

static bool handle_proxy_mode(tproxy_conn_t *conn, struct tailhead *conn_list)
{
	// To simplify things I dont care about buffering. If message splits, I just hang up
	// in proxy mode messages are short. they can be split only intentionally. all normal programs send them in one packet

	ssize_t rd,wr;
	char buf[sizeof(s5_req)]; // s5_req - the largest possible req

	// receive proxy control message
	rd=recv(conn->fd, buf, sizeof(buf), MSG_DONTWAIT);
	DBGPRINT("handle_proxy_mode rd=%zd\n",rd);
	if (rd<1) return false; // hangup
	switch(conn->conn_type)
	{
		case CONN_TYPE_SOCKS:
			switch(conn->socks_state)
			{
				case S_WAIT_HANDSHAKE:
					DBGPRINT("S_WAIT_HANDSHAKE\n");
					if (buf[0] != 5 && buf[0] != 4) return false; // unknown socks version
					conn->socks_ver = buf[0];
					DBGPRINT("socks version %u\n", conn->socks_ver);
					if (conn->socks_ver==5)
					{
						s5_handshake *m = (s5_handshake*)buf;
						s5_handshake_ack ack;
						uint8_t k;

						ack.ver=5;
						if (!S5_REQ_HANDHSHAKE_VALID(m,rd))
						{
							DBGPRINT("socks5 proxy handshake invalid\n");
							return false;
						}
						for (k=0;k<m->nmethods;k++) if (m->methods[k]==S5_AUTH_NONE) break;
						if (k>=m->nmethods)
						{
							DBGPRINT("socks5 client wants authentication but we dont support\n");
							ack.method=S5_AUTH_UNACCEPTABLE;
							wr=send(conn->fd,&ack,sizeof(ack),MSG_DONTWAIT);
							return false;
						}
						DBGPRINT("socks5 recv valid handshake\n");
						ack.method=S5_AUTH_NONE;
						wr=send(conn->fd,&ack,sizeof(ack),MSG_DONTWAIT);
						if (wr!=sizeof(ack))
						{
							DBGPRINT("socks5 handshake ack send error. wr=%zd errno=%d\n",wr,errno);
							return false;
						}
						DBGPRINT("socks5 send handshake ack OK\n");
						conn->socks_state=S_WAIT_REQUEST;
						return true;
					}
					else
					{
						// socks4 does not have separate handshake phase. it starts with connect request
						// ipv6 and domain resolving are not supported
						s4_req *m = (s4_req*)buf;
						if (!S4_REQ_HEADER_VALID(m, rd))
						{
							DBGPRINT("socks4 request invalid\n");
							return false;
						}
						if (m->cmd!=S4_CMD_CONNECT)
						{
							// BIND is not supported
							DBGPRINT("socks4 unsupported command %02X\n", m->cmd);
							socks4_send_rep(conn->fd, S4_REP_FAILED);
							return false;
						}
						if (!S4_REQ_CONNECT_VALID(m, rd))
						{
							DBGPRINT("socks4 connect request invalid\n");
							socks4_send_rep(conn->fd, S4_REP_FAILED);
							return false;
						}
						if (!m->port)
						{
							DBGPRINT("socks4 zero port\n");
							socks4_send_rep(conn->fd, S4_REP_FAILED);
							return false;
						}
						if (m->ip==htonl(1)) // special ip 0.0.0.1
						{
							VPRINT("socks4a protocol not supported\n");
							socks4_send_rep(conn->fd, S4_REP_FAILED);
							return false;
						}
						((struct sockaddr_in*)&conn->dest)->sin_family = AF_INET;
						((struct sockaddr_in*)&conn->dest)->sin_port = m->port;
						((struct sockaddr_in*)&conn->dest)->sin_addr.s_addr = m->ip;
						return proxy_mode_connect_remote(conn, conn_list);
					}
					break;
				case S_WAIT_REQUEST:
					DBGPRINT("S_WAIT_REQUEST\n");
					{
						s5_req *m = (s5_req*)buf;

						if (!S5_REQ_HEADER_VALID(m,rd))
						{
							DBGPRINT("socks5 request invalid\n");
							return false;
						}
						if (m->cmd!=S5_CMD_CONNECT)
						{
							// BIND and UDP are not supported
							DBGPRINT("socks5 unsupported command %02X\n", m->cmd);
							socks5_send_rep(conn->fd,S5_REP_COMMAND_NOT_SUPPORTED);
							return false;
						}
						if (!S5_REQ_CONNECT_VALID(m,rd))
						{
							DBGPRINT("socks5 connect request invalid\n");
							return false;
						}
						DBGPRINT("socks5 recv valid connect request\n");
						switch(m->atyp)
						{
							case S5_ATYP_IP4:
								((struct sockaddr_in*)&conn->dest)->sin_family = AF_INET;
								((struct sockaddr_in*)&conn->dest)->sin_port = m->d4.port;
								((struct sockaddr_in*)&conn->dest)->sin_addr = m->d4.addr;
								break;
							case S5_ATYP_IP6:
								((struct sockaddr_in6*)&conn->dest)->sin6_family = AF_INET6;
								((struct sockaddr_in6*)&conn->dest)->sin6_port = m->d6.port;
								((struct sockaddr_in6*)&conn->dest)->sin6_addr = m->d6.addr;
								((struct sockaddr_in6*)&conn->dest)->sin6_flowinfo = 0;
								((struct sockaddr_in6*)&conn->dest)->sin6_scope_id = 0;
								break;
							case S5_ATYP_DOM:
								{
									uint16_t port;

									if (params.no_resolve)
									{
										VPRINT("socks5 hostname resolving disabled\n");
										socks5_send_rep(conn->fd,S5_REP_NOT_ALLOWED_BY_RULESET);
										return false;
									}
									port=S5_PORT_FROM_DD(m,rd);
									if (!port)
									{
										VPRINT("socks5 no port is given\n");
										socks5_send_rep(conn->fd,S5_REP_HOST_UNREACHABLE);
										return false;
									}
									m->dd.domport[m->dd.len] = 0;
									DBGPRINT("socks5 queue resolve hostname '%s' port '%u'\n",m->dd.domport,port);
									conn->socks_ri = resolver_queue(m->dd.domport,port,conn);
									if (!conn->socks_ri)
									{
										VPRINT("socks5 could not queue resolve item\n");
										socks5_send_rep(conn->fd,S5_REP_GENERAL_FAILURE);
										return false;
									}
									conn->socks_state=S_WAIT_RESOLVE;
									DBGPRINT("S_WAIT_RESOLVE\n");
									return true;
								}
								break;
							default:
								return false; // should not be here. S5_REQ_CONNECT_VALID checks for valid atyp

						}
						return proxy_mode_connect_remote(conn,conn_list);
					}
					break;
				case S_WAIT_RESOLVE:
					DBGPRINT("socks received message while in S_WAIT_RESOLVE. hanging up\n");
					break;
				case S_WAIT_CONNECTION:
					DBGPRINT("socks received message while in S_WAIT_CONNECTION. hanging up\n");
					break;
				default:
					DBGPRINT("socks received message while in an unexpected connection state\n");
					break;
			}
			break;
	}
	return false;
}

static bool resolve_complete(struct resolve_item *ri, struct tailhead *conn_list)
{
	tproxy_conn_t *conn = (tproxy_conn_t *)ri->ptr;

	if (conn && (conn->state != CONN_CLOSED))
	{
		if (conn->socks_state==S_WAIT_RESOLVE)
		{
			DBGPRINT("resolve_complete %s. getaddrinfo result %d\n", ri->dom, ri->ga_res);
			if (ri->ga_res)
			{
				socks5_send_rep(conn->fd,S5_REP_HOST_UNREACHABLE);
				return false;;
			}
			else
			{
				if (!conn->track.hostname)
				{
					DBGPRINT("resolve_complete put hostname : %s\n", ri->dom);
					conn->track.hostname = strdup(ri->dom);
				}
				sa46copy(&conn->dest, (struct sockaddr *)&ri->ss);
				return proxy_mode_connect_remote(conn,conn_list);
			}
		}
		else
			DLOG_ERR("resolve_complete: conn in wrong socks_state !!! (%s)\n", ri->dom);
	}
	else
		DBGPRINT("resolve_complete: orphaned resolve for %s\n", ri->dom);

	return true;
}


static bool in_tamper_out_range(tproxy_conn_t *conn)
{
	if (!conn->track.dp) return true;
	bool in_range = \
		((conn->track.dp->tamper_start_n ? (conn->tnrd+1) : conn->trd) >= conn->track.dp->tamper_start &&
		 (!conn->track.dp->tamper_cutoff || (conn->track.dp->tamper_cutoff_n ? (conn->tnrd+1) : conn->trd) < conn->track.dp->tamper_cutoff));
	DBGPRINT("tamper_out range check. stream pos %" PRIu64 "(n%" PRIu64 "). tamper range %s%u-%s%u (%s)\n",
		conn->trd, conn->tnrd+1,
		conn->track.dp ? conn->track.dp->tamper_start_n ? "n" : "" : "?" , conn->track.dp ? conn->track.dp->tamper_start : 0,
		conn->track.dp ? conn->track.dp->tamper_cutoff_n ? "n" : "" : "?" , conn->track.dp ? conn->track.dp->tamper_cutoff : 0,
		in_range ? "IN RANGE" : "OUT OF RANGE");
	return in_range;
		 
}

static void tamper(tproxy_conn_t *conn, uint8_t *segment, size_t segment_buffer_size, size_t *segment_size, size_t *multisplit_pos, int *multisplit_count, uint8_t *split_flags)
{
	if (multisplit_count) *multisplit_count=0;
	if (params.tamper)
	{
		if (conn->remote)
		{
			if (conn_partner_alive(conn) && !conn->partner->track.bTamperInCutoff)
				tamper_in(&conn->partner->track,(struct sockaddr*)&conn->partner->client,segment,segment_buffer_size,segment_size);
		}
		else
		{
			if (in_tamper_out_range(conn))
				tamper_out(&conn->track,(struct sockaddr*)&conn->dest,segment,segment_buffer_size,segment_size,multisplit_pos,multisplit_count,split_flags);
		}
	}
}

// buffer must have at least one extra byte for OOB
static ssize_t send_oob(int fd, uint8_t *buf, size_t len, int ttl, bool oob, uint8_t oob_byte)
{
	ssize_t wr;
	if (oob)
	{
		uint8_t oob_save;
		oob_save = buf[len];
		buf[len] = oob_byte;
		wr = send_with_ttl(fd, buf, len+1, MSG_OOB, ttl);
		buf[len] = oob_save;
		if (wr<0 && errno==EAGAIN) wr=0;
	}
	else
		wr = send_with_ttl(fd, buf, len, 0, ttl);
	return wr;
}


static unsigned int segfail_count=0;
static time_t segfail_report_time=0;
static void report_segfail(void)
{
	time_t now = time(NULL);
	segfail_count++;
	if (now==segfail_report_time)
		VPRINT("WARNING ! segmentation failed. total fails : %u\n", segfail_count);
	else
	{
		DLOG_ERR("WARNING ! segmentation failed. total fails : %u\n", segfail_count);
		segfail_report_time = now;
	}
}

#define RD_BLOCK_SIZE 65536
#define MAX_WASTE (1024*1024)

static bool handle_epoll(tproxy_conn_t *conn, struct tailhead *conn_list, uint32_t evt)
{
	int numbytes;
	ssize_t rd = 0, wr = 0;
	size_t bs;


	DBGPRINT("+handle_epoll\n");

	if (!conn_in_tcp_mode(conn))
	{
		if (!(evt & EPOLLIN))
			return true; // nothing to read
		return handle_proxy_mode(conn,conn_list);
	}

	if (!handle_unsent(conn))
		return false; // error
	if (!conn_partner_alive(conn) && !conn_has_unsent(conn))
		return false; // when no partner, we only waste read and send unsent

	if (!(evt & EPOLLIN))
		return true; // nothing to read

	if (!conn_partner_alive(conn))
	{
		// throw it to a black hole
		uint8_t waste[65070];
		uint64_t trd=0;

		while((rd=recv(conn->fd, waste, sizeof(waste), MSG_DONTWAIT))>0 && trd<MAX_WASTE)
		{
			trd+=rd;
			conn->trd+=rd;
		}
		DBGPRINT("wasted recv=%zd all_rd=%" PRIu64 " err=%d\n",rd,trd,errno);
		return true;
	}

	// do not receive new until old is sent
	if (conn_has_unsent(conn->partner))
		return true;
		
	bool oom=false;

	numbytes=conn_bytes_unread(conn);
	DBGPRINT("numbytes=%d\n",numbytes);
	if (numbytes>0)
	{
		DBGPRINT("%s leg fd=%d stream pos : %" PRIu64 "(n%" PRIu64 ")/%" PRIu64 "\n", conn->remote ? "remote" : "local", conn->fd, conn->trd,conn->tnrd+1,conn->twr);
#ifdef SPLICE_PRESENT
		if (!params.nosplice && (!params.tamper || (conn->remote && conn->partner->track.bTamperInCutoff) || (!conn->remote && !in_tamper_out_range(conn))))
		{
			// incoming data from remote leg we splice without touching
			// pipe is in the local leg, so its in conn->partner->splice_pipe
			// if we dont tamper - splice both legs

			rd = splice(conn->fd, NULL, conn->partner->splice_pipe[1], NULL, SPLICE_LEN, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
			DBGPRINT("splice fd=%d remote=%d len=%d rd=%zd err=%d\n",conn->fd,conn->remote,SPLICE_LEN,rd,errno);
			if (rd<0 && errno==EAGAIN) rd=0;
			if (rd>0)
			{
				conn->tnrd++;
				conn->trd += rd;
				conn->partner->wr_unsent += rd;
				wr = splice(conn->partner->splice_pipe[0], NULL, conn->partner->fd, NULL, conn->partner->wr_unsent, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
				DBGPRINT("splice fd=%d remote=%d wr=%zd err=%d\n",conn->partner->fd,conn->partner->remote,wr,errno);
				if (wr<0 && errno==EAGAIN) wr=0;
				if (wr>0)
				{
					conn->partner->wr_unsent -= wr;
					conn->partner->twr += wr;
				}
			}
		}
		else
#endif
		{
			// incoming data from local leg
			uint8_t buf[RD_BLOCK_SIZE + 6];

			rd = recv(conn->fd, buf, RD_BLOCK_SIZE, MSG_DONTWAIT);
			DBGPRINT("recv fd=%d rd=%zd err=%d\n",conn->fd, rd,errno);
			if (rd<0 && errno==EAGAIN) rd=0;
			if (rd>0)
			{
				size_t multisplit_pos[MAX_SPLITS];
				int multisplit_count;

				uint8_t split_flags;

				bs = rd;

				// tamper needs to know stream position of the block start
				tamper(conn, buf, sizeof(buf), &bs, multisplit_pos, &multisplit_count, &split_flags);
				// increase after tamper
				conn->tnrd++;
				conn->trd+=rd;

				if (multisplit_count)
				{
					ssize_t from,to,len;
					int i;
					bool bApplyDisorder, bApplyOOB;
					for (i=0,from=0;i<=multisplit_count;i++)
					{
						to = i==multisplit_count ? bs : multisplit_pos[i];

						bApplyDisorder = !(i & 1) && i<multisplit_count && (split_flags & SPLIT_FLAG_DISORDER);
						bApplyOOB = i==0 && (split_flags & SPLIT_FLAG_OOB);
						len = to-from;
#ifdef __linux__
						if (params.fix_seg_avail)
						{
							if (params.fix_seg)
							{
								unsigned int wasted;
								bool bWaitOK = socket_wait_notsent(conn->partner->fd, params.fix_seg, &wasted);
								if (wasted)
									VPRINT("WARNING ! wasted %u ms to fix segmenation\n", wasted);
								if (!bWaitOK)
									report_segfail();
							}
							else
							{
								if (socket_has_notsent(conn->partner->fd))
									report_segfail();
							}
						}
#endif
						VPRINT("Sending multisplit part %d %zd-%zd (len %zd)%s%s : ", i+1, from, to, len, bApplyDisorder ? " with disorder" : "", bApplyOOB ? " with OOB" : "");
						packet_debug(buf+from,len);
						wr = send_oob(conn->partner->fd, buf+from, len, bApplyDisorder, bApplyOOB, conn->track.dp ? conn->track.dp->oob_byte : 0);
						if (wr<0) break;
						conn->partner->twr += wr;
						if (wr<len)
						{
							from+=wr;
							VPRINT("Cannot send part %d immediately. only %zd bytes were sent (%zd left in segment). cancelling split.\n", i+1, wr, bs-from);
							wr = send_or_buffer(conn->partner->wr_buf, conn->partner->fd, buf+from, bs-from, 0, 0);
							if (wr>0) conn->partner->twr += wr;
							break;
						}
						from = to;
					}
				}
				else
				{
					wr = send_or_buffer(conn->partner->wr_buf, conn->partner->fd, buf, bs, 0, 0);
					DBGPRINT("send_or_buffer(3) fd=%d wr=%zd err=%d\n",conn->partner->fd,wr,errno);
					if (wr>0) conn->partner->twr += wr;
				}
				if (wr<0 && errno==ENOMEM) oom=true;
			}
		}

		if (!epoll_set_flow_pair(conn))
			return false;
	}
	
	DBGPRINT("-handle_epoll rd=%zd wr=%zd\n",rd,wr);
	if (oom) DBGPRINT("handle_epoll: OUT_OF_MEMORY\n");

	// do not fail if partner fails.
	// if partner fails there will be another epoll event with EPOLLHUP or EPOLLERR
	return rd>=0 && !oom;
}

static bool remove_closed_connections(int efd, struct tailhead *close_list)
{
	tproxy_conn_t *conn = NULL;
	bool bRemoved = false;

	while ((conn = TAILQ_FIRST(close_list)))
	{
		TAILQ_REMOVE(close_list, conn, conn_ptrs);

		epoll_del(conn);
		VPRINT("Socket fd=%d (partner_fd=%d, remote=%d) closed, connection removed. total_read=%" PRIu64 " total_write=%" PRIu64 " event_count=%u\n",
			conn->fd, conn->partner ? conn->partner->fd : 0, conn->remote, conn->trd, conn->twr, conn->event_count);
		if (conn->remote) legs_remote--; else legs_local--;
		free_conn(conn);
		bRemoved = true;
	}
	return bRemoved;
}

// move to close list connection and its partner
static void close_tcp_conn(struct tailhead *conn_list, struct tailhead *close_list, tproxy_conn_t *conn)
{
	if (conn->state != CONN_CLOSED)
	{
		conn->state = CONN_CLOSED;
		TAILQ_REMOVE(conn_list, conn, conn_ptrs);
		TAILQ_INSERT_TAIL(close_list, conn, conn_ptrs);
	}
}


static bool read_all_and_buffer(tproxy_conn_t *conn, int buffer_number)
{
	if (conn_partner_alive(conn))
	{
		int numbytes=conn_bytes_unread(conn);
		DBGPRINT("read_all_and_buffer(%d) numbytes=%d\n",buffer_number,numbytes);
		if (numbytes>0)
		{
			if (send_buffer_create(conn->partner->wr_buf+buffer_number, NULL, numbytes, 6, 0, 0))
			{
				ssize_t rd = recv(conn->fd, conn->partner->wr_buf[buffer_number].data, numbytes, MSG_DONTWAIT);
				if (rd>0)
				{
					conn->trd+=rd;
					conn->partner->wr_buf[buffer_number].len = rd;

					conn->partner->bFlowOut = true;

					tamper(conn, conn->partner->wr_buf[buffer_number].data, numbytes+6, &conn->partner->wr_buf[buffer_number].len, NULL, NULL, NULL);

					if (epoll_update_flow(conn->partner))
						return true;
						
				}
				send_buffer_free(conn->partner->wr_buf+buffer_number);
			}
		}
	}
	return false;
}


static bool conn_timed_out(tproxy_conn_t *conn)
{
	if (conn->orphan_since && conn->state==CONN_UNAVAILABLE)
	{
		time_t timediff = time(NULL) - conn->orphan_since;
		return timediff>=params.max_orphan_time;
	}
	else
		return false;
}
static void conn_close_timed_out(struct tailhead *conn_list, struct tailhead *close_list)
{
	tproxy_conn_t *c,*cnext = NULL;

	DBGPRINT("conn_close_timed_out\n");

	c = TAILQ_FIRST(conn_list);
	while(c)
	{
		cnext = TAILQ_NEXT(c,conn_ptrs);
		if (conn_timed_out(c))
		{
			DBGPRINT("closing timed out connection: fd=%d remote=%d\n",c->fd,c->remote);
			close_tcp_conn(conn_list,close_list,c);
		}
		c = cnext;
	}
}

static void conn_close_both(struct tailhead *conn_list, struct tailhead *close_list, tproxy_conn_t *conn)
{
	if (conn_partner_alive(conn)) close_tcp_conn(conn_list,close_list,conn->partner);
	close_tcp_conn(conn_list,close_list,conn);
}
static void conn_close_with_partner_check(struct tailhead *conn_list, struct tailhead *close_list, tproxy_conn_t *conn)
{
	close_tcp_conn(conn_list,close_list,conn);
	if (conn_partner_alive(conn))
	{ 
		if (!conn_has_unsent(conn->partner))
			close_tcp_conn(conn_list,close_list,conn->partner);
		else if (conn->partner->remote && conn->partner->state==CONN_UNAVAILABLE && params.max_orphan_time)
			// time out only remote legs that are not connected yet
			conn->partner->orphan_since = time(NULL);
	}
}


static bool handle_resolve_pipe(tproxy_conn_t **conn, struct tailhead *conn_list, int fd)
{
	ssize_t rd;
	struct resolve_item *ri;
	bool b;

	rd = read(fd,&ri,sizeof(void*));
	if (rd<0)
	{
		DLOG_PERROR("resolve_pipe read");
		return false;
	}
	else if (rd!=sizeof(void*))
	{
		// partial pointer read is FATAL. in any case it will cause pointer corruption and coredump
		DLOG_ERR("resolve_pipe not full read %zd\n",rd);
		exit(1000);
	}
	b = resolve_complete(ri, conn_list);
	*conn = (tproxy_conn_t *)ri->ptr;
	if (*conn) (*conn)->socks_ri = NULL;
	free(ri);
	return b;
}

int event_loop(const int *listen_fd, size_t listen_fd_ct)
{
	int retval = 0, num_events = 0;
	int tmp_fd = 0; //Used to temporarily hold the accepted file descriptor
	tproxy_conn_t *conn = NULL;
	int efd=0, i;
	struct epoll_event ev, events[MAX_EPOLL_EVENTS];
	struct tailhead conn_list, close_list;
	time_t tm,last_timeout_check=0;
	tproxy_conn_t *listen_conn = NULL;
	size_t sct;
	struct sockaddr_storage accept_sa;
	socklen_t accept_salen;
	int resolve_pipe[2];

	if (!listen_fd_ct) return -1;
	                                         	
	resolve_pipe[0]=resolve_pipe[1]=0;

	legs_local = legs_remote = 0;
	//Initialize queue (remember that TAILQ_HEAD just defines the struct)
	TAILQ_INIT(&conn_list);
	TAILQ_INIT(&close_list);

	if ((efd = epoll_create(1)) == -1) {
		DLOG_PERROR("epoll_create");
		return -1;
	}

	if (!(listen_conn=calloc(listen_fd_ct,sizeof(*listen_conn))))
	{
		DLOG_PERROR("calloc listen_conn");
		return -1;
	}
	
	//Start monitoring listen sockets
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	for(sct=0;sct<listen_fd_ct;sct++)
	{
		listen_conn[sct].listener = true;
		listen_conn[sct].fd = listen_fd[sct];
		ev.data.ptr = listen_conn + sct;
		if (epoll_ctl(efd, EPOLL_CTL_ADD, listen_conn[sct].fd, &ev) == -1) {
			DLOG_PERROR("epoll_ctl (listen socket)");
			retval = -1;
			goto ex;
		}
	}
	if ((params.proxy_type==CONN_TYPE_SOCKS) && !params.no_resolve)
	{
		if (pipe(resolve_pipe)==-1)
		{
			DLOG_PERROR("pipe (resolve_pipe)");
			retval = -1;
			goto ex;
		}
		if (fcntl(resolve_pipe[0], F_SETFL, O_NONBLOCK) < 0)
		{
			DLOG_PERROR("resolve_pipe set O_NONBLOCK");
			retval = -1;
			goto ex;
		}
		ev.data.ptr = NULL;
		if (epoll_ctl(efd, EPOLL_CTL_ADD, resolve_pipe[0], &ev) == -1) {
			DLOG_PERROR("epoll_ctl (listen socket)");
			retval = -1;
			goto ex;
		}
		if (!resolver_init(params.resolver_threads,resolve_pipe[1]))
		{
			DLOG_ERR("could not initialize multithreaded resolver\n");
			retval = -1;
			goto ex;
		}
		VPRINT("initialized multi threaded resolver with %d threads\n",resolver_thread_count());
	}

	for(;;)
	{
		ReloadCheck();

		DBGPRINT("epoll_wait\n");

		if ((num_events = epoll_wait(efd, events, MAX_EPOLL_EVENTS, -1)) == -1)
		{
			if (errno == EINTR) continue; // system call was interrupted
			DLOG_PERROR("epoll_wait");
			retval = -1;
			break;
		}

		for (i = 0; i < num_events; i++)
		{
			conn = (tproxy_conn_t*)events[i].data.ptr;
			if (!conn)
			{
				DBGPRINT("\nEVENT mask %08X resolve_pipe\n",events[i].events);
				if (events[i].events & EPOLLIN)
				{
					DBGPRINT("EPOLLIN\n");
					if (!handle_resolve_pipe(&conn, &conn_list, resolve_pipe[0]))
					{
						DBGPRINT("handle_resolve_pipe false\n");
						if (conn) close_tcp_conn(&conn_list,&close_list,conn);
					}
				}
				continue;
			}
			conn->event_count++;
			if (conn->listener)
			{
				DBGPRINT("\nEVENT mask %08X fd=%d accept\n",events[i].events,conn->fd);

				accept_salen = sizeof(accept_sa);
				//Accept new connection
#if defined (__APPLE__)
				// macos does not have accept4()
				tmp_fd = accept(conn->fd, (struct sockaddr*)&accept_sa, &accept_salen);
#else
				tmp_fd = accept4(conn->fd, (struct sockaddr*)&accept_sa, &accept_salen, SOCK_NONBLOCK);
#endif
				if (tmp_fd < 0)
				{
					DLOG_PERROR("Failed to accept connection");
				}
				else if (legs_local >= params.maxconn) // each connection has 2 legs - local and remote
				{
					close(tmp_fd);
					VPRINT("Too many local legs : %d\n", legs_local);
				}
#if defined (__APPLE__)
				// separate fcntl call to comply with macos
				else if (fcntl(tmp_fd, F_SETFL, O_NONBLOCK) < 0)
				{
					DLOG_PERROR("socket set O_NONBLOCK (accept)");
					close(tmp_fd);
				}
#endif
				else if (!(conn=add_tcp_connection(efd, &conn_list, tmp_fd, (struct sockaddr*)&accept_sa, params.port, params.proxy_type)))
				{
					// add_tcp_connection closes fd in case of failure
					VPRINT("Failed to add connection\n");
				}
				else
				{	
					print_legs();

					if (params.debug>=1)
					{
						char ip_port[48];
						ntop46_port((struct sockaddr*)&conn->client,ip_port,sizeof(ip_port));
						VPRINT("Socket fd=%d (local) connected from %s\n", conn->fd, ip_port);
					}
					set_user_timeout(conn->fd, params.tcp_user_timeout_local);
				}
			}
			else
			{
				DBGPRINT("\nEVENT mask %08X fd=%d remote=%d fd_partner=%d\n",events[i].events,conn->fd,conn->remote,conn_partner_alive(conn) ? conn->partner->fd : 0);

				if (conn->state != CONN_CLOSED)
				{
					if (events[i].events & (EPOLLHUP|EPOLLERR))
					{
						int errn = get_so_error(conn->fd);
						const char *se;
						switch (events[i].events & (EPOLLHUP|EPOLLERR))
						{
							case EPOLLERR: se="EPOLLERR"; break;
							case EPOLLHUP: se="EPOLLHUP"; break;
							case EPOLLHUP|EPOLLERR: se="EPOLLERR EPOLLHUP"; break;
							default: se=NULL;
						}
						VPRINT("Socket fd=%d (partner_fd=%d, remote=%d) %s so_error=%d (%s)\n",conn->fd,conn->partner ? conn->partner->fd : 0,conn->remote,se,errn,strerror(errn));
						proxy_remote_conn_ack(conn,errn);
						read_all_and_buffer(conn,3);
						if (errn==ECONNRESET && conn_partner_alive(conn))
						{
							if (conn->remote && params.tamper) rst_in(&conn->partner->track,(struct sockaddr*)&conn->partner->client);

							struct linger lin;
							lin.l_onoff=1;
							lin.l_linger=0;
							DBGPRINT("setting LINGER=0 to partner to force mirrored RST close\n");
							if (setsockopt(conn->partner->fd,SOL_SOCKET,SO_LINGER,&lin,sizeof(lin))<0)
								DLOG_PERROR("setsockopt (SO_LINGER)");
						}
						conn_close_with_partner_check(&conn_list,&close_list,conn);
						continue;
					}
					if (events[i].events & EPOLLOUT)
					{
						if (!check_connection_attempt(conn, efd))
						{
							VPRINT("Connection attempt failed for fd=%d\n", conn->fd);
							conn_close_both(&conn_list,&close_list,conn);
							continue;
						}
					}
					if (events[i].events & EPOLLRDHUP)
					{
						DBGPRINT("EPOLLRDHUP\n");
						read_all_and_buffer(conn,2);
						if (!conn->remote && params.tamper) hup_out(&conn->track,(struct sockaddr*)&conn->client);

						conn->state = CONN_RDHUP; // only writes. do not receive RDHUP anymore
						if (conn_has_unsent(conn))
						{
							DBGPRINT("conn fd=%d has unsent\n", conn->fd);
							epoll_set_flow(conn,false,true);
						}
						else
						{
							DBGPRINT("conn fd=%d has no unsent\n", conn->fd);
							conn->bFlowIn = false;
							epoll_update_flow(conn);
							if (conn_partner_alive(conn))
							{
								if (conn_has_unsent(conn->partner))
									DBGPRINT("partner has unset. partner shutdown delayed.\n");
								else
								{
									DBGPRINT("partner has no unsent. shutting down partner.\n");
									if (!conn_shutdown(conn->partner))
									{
										DBGPRINT("emergency connection close due to failed shutdown\n");
										conn_close_with_partner_check(&conn_list,&close_list,conn);
									}
									if (conn->partner->state==CONN_RDHUP)
									{
										DBGPRINT("both partners are in RDHUP state and have no unsent. closing.\n");
										conn_close_with_partner_check(&conn_list,&close_list,conn);
									}
								}
							}
							else
							{
								DBGPRINT("partner is absent or not alive. closing.\n");
								close_tcp_conn(&conn_list,&close_list,conn);
							}
						}
						continue;
					}

					if (events[i].events & (EPOLLIN|EPOLLOUT))
					{
						const char *se;
						switch (events[i].events & (EPOLLIN|EPOLLOUT))
						{
							case EPOLLIN: se="EPOLLIN"; break;
							case EPOLLOUT: se="EPOLLOUT"; break;
							case EPOLLIN|EPOLLOUT: se="EPOLLIN EPOLLOUT"; break;
							default: se=NULL;
						}
						if (se) DBGPRINT("%s\n",se);
						// will not receive this until successful check_connection_attempt()
						if (!handle_epoll(conn, &conn_list, events[i].events))
						{
							DBGPRINT("handle_epoll false\n");
							conn_close_with_partner_check(&conn_list,&close_list,conn);
							continue;
						}
						if ((conn->state == CONN_RDHUP) && conn_partner_alive(conn) && !conn->partner->bShutdown && !conn_has_unsent(conn))
						{
							DBGPRINT("conn fd=%d has no unsent. shutting down partner.\n", conn->fd);
							if (!conn_shutdown(conn->partner))
							{
								DBGPRINT("emergency connection close due to failed shutdown\n");
								conn_close_with_partner_check(&conn_list,&close_list,conn);
								continue;
							}
						}

					}
				}

			}
		}
		tm = time(NULL);
		if (last_timeout_check!=tm)
		{
			// limit whole list lookups to once per second
			last_timeout_check=tm;
			conn_close_timed_out(&conn_list,&close_list);
		}
		if (remove_closed_connections(efd, &close_list))
		{
			// at least one leg was removed. recount legs
			print_legs();
		}

		fflush(stderr); fflush(stdout); // for console messages
	}

ex:
	if (efd) close(efd);
	free(listen_conn);
	resolver_deinit();
	if (resolve_pipe[0]) close(resolve_pipe[0]);
	if (resolve_pipe[1]) close(resolve_pipe[1]);
	return retval;
}
