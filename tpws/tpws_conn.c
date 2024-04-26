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
	VPRINT("Legs : local:%d remote:%d", legs_local, legs_remote)
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


ssize_t send_with_ttl(int fd, const void *buf, size_t len, int flags, int ttl)
{
 	ssize_t wr;

	if (ttl)
	{
		DBGPRINT("send_with_ttl %d fd=%d",ttl,fd);
		if (!set_ttl_hl(fd, ttl))
			//fprintf(stderr,"could not set ttl %d to fd=%d\n",ttl,fd);
			fprintf(stderr,"could not set ttl %d to fd=%d\n",ttl,fd);
	}
	wr = send(fd, buf, len, flags);
	if (ttl)
	{
		int e=errno;
		if (!set_ttl_hl(fd, params.ttl_default))
			fprintf(stderr,"could not set ttl %d to fd=%d\n",params.ttl_default,fd);
		errno=e;
	}
	return wr;
}


static bool send_buffer_create(send_buffer_t *sb, const void *data, size_t len, size_t extra_bytes, int flags, int ttl)
{
	if (sb->data)
	{
		fprintf(stderr,"FATAL : send_buffer_create but buffer is not empty\n");
		exit(1);
	}
	sb->data = malloc(len + extra_bytes);
	if (!sb->data)
	{
		DBGPRINT("send_buffer_create failed. errno=%d",errno)
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
			DBGPRINT("reallocated send_buffer from %zd to %zd", sb->len, sb->len + extra_bytes)
			return true;
		}
		else
		{
			DBGPRINT("failed to realloc send_buffer from %zd to %zd", sb->len, sb->len + extra_bytes)
		}
	}
	return false;
}

static void send_buffer_free(send_buffer_t *sb)
{
	if (sb->data)
	{
		free(sb->data);
		sb->data = NULL;
	}
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
	DBGPRINT("send_buffer_send len=%zu pos=%zu wr=%zd err=%d",sb->len,sb->pos,wr,errno)
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
			DBGPRINT("send_buffers_send(%d) wr=%zd err=%d",i,wr,errno)
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
			DBGPRINT("fd=%d SO_RCVBUF=%d",fd,v)
		sz=sizeof(int);
		if (!getsockopt(fd,SOL_SOCKET,SO_SNDBUF,&v,&sz))
			DBGPRINT("fd=%d SO_SNDBUF=%d",fd,v)
	}
}

bool set_socket_buffers(int fd, int rcvbuf, int sndbuf)
{
	DBGPRINT("set_socket_buffers fd=%d rcvbuf=%d sndbuf=%d",fd,rcvbuf,sndbuf)
	if (rcvbuf && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int)) <0)
	{
		perror("setsockopt (SO_RCVBUF)");
		close(fd);
		return false;
	}
	if (sndbuf && setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(int)) <0)
	{
		perror("setsockopt (SO_SNDBUF)");
		close(fd);
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
				DBGPRINT("socks connection acknowledgement. bres=%d remote_errn=%d remote_fd=%d local_fd=%d",bres,sock_err,conn->fd,conn->partner->fd)
			}
			break;
	}
	return bres;
}

//Createas a socket and initiates the connection to the host specified by 
//remote_addr.
//Returns -1 if something fails, >0 on success (socket fd).
static int connect_remote(const struct sockaddr *remote_addr, bool bApplyConnectionFooling)
{
	int remote_fd = 0, yes = 1, no = 0, v;
    
	
 	if((remote_fd = socket(remote_addr->sa_family, SOCK_STREAM, 0)) < 0)
 	{
		perror("socket (connect_remote)");
		return -1;
	}
	// Use NONBLOCK to avoid slow connects affecting the performance of other connections
	// separate fcntl call to comply with macos
	if (fcntl(remote_fd, F_SETFL, O_NONBLOCK)<0)
	{
		perror("socket set O_NONBLOCK (connect_remote)");
		close(remote_fd);
		return -1;
	}
	if (setsockopt(remote_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
	{
		perror("setsockopt (SO_REUSEADDR, connect_remote)");
		close(remote_fd);
		return -1;
	}
	if (!set_socket_buffers(remote_fd, params.remote_rcvbuf, params.remote_sndbuf))
		return -1;
	if (!set_keepalive(remote_fd))
	{
		perror("set_keepalive");
		close(remote_fd);
		return -1;
	}
	if (setsockopt(remote_fd, IPPROTO_TCP, TCP_NODELAY, params.skip_nodelay ? &no : &yes, sizeof(int)) <0)
	{
		perror("setsockopt (TCP_NODELAY, connect_remote)");
		close(remote_fd);
		return -1;
	}
	if (bApplyConnectionFooling && params.mss)
	{
		uint16_t port = saport(remote_addr);
		if (pf_in_range(port,&params.mss_pf))
		{
			VPRINT("Setting MSS %d",params.mss)
			if (setsockopt(remote_fd, IPPROTO_TCP, TCP_MAXSEG, &params.mss, sizeof(int)) <0)
			{
				perror("setsockopt (TCP_MAXSEG, connect_remote)");
				close(remote_fd);
				return -1;
			}
		}
		else
		{
			VPRINT("Not setting MSS. Port %u is out of MSS port range.",port)
		}
	}
	if (connect(remote_fd, remote_addr, remote_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0)
	{
		if(errno != EINPROGRESS)
		{
			perror("connect (connect_remote)");
			close(remote_fd);
			return -1;
		}
	}
	DBGPRINT("Connecting remote fd=%d",remote_fd)

	return remote_fd;
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
	if (conn->track.hostname) free(conn->track.hostname);
	if (conn->socks_ri) conn->socks_ri->ptr = NULL; // detach conn
	free(conn);
}
static tproxy_conn_t *new_conn(int fd, bool remote)
{
	tproxy_conn_t *conn;

	//Create connection object and fill in information
	if((conn = (tproxy_conn_t*) malloc(sizeof(tproxy_conn_t))) == NULL)
	{
		fprintf(stderr, "Could not allocate memory for connection\n");
		return NULL;
	}

	memset(conn, 0, sizeof(tproxy_conn_t));
	conn->state = CONN_UNAVAILABLE;
	conn->fd = fd;
	conn->remote = remote;

#ifdef SPLICE_PRESENT
	// if dont tamper - both legs are spliced, create 2 pipes
	// otherwise create pipe only in local leg
	if (!params.nosplice && ( !remote || !params.tamper || params.tamper_start || params.tamper_cutoff ) && pipe2(conn->splice_pipe, O_NONBLOCK) != 0)
	{
		fprintf(stderr, "Could not create the splice pipe\n");
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
	DBGPRINT("epoll_set fd=%d events=%08X",conn->fd,events);
	if(epoll_ctl(conn->efd, EPOLL_CTL_MOD, conn->fd, &ev)==-1 &&
	   epoll_ctl(conn->efd, EPOLL_CTL_ADD, conn->fd, &ev)==-1)
	{
		perror("epoll_ctl (add/mod)");
		return false;
	}
	return true;
}
static bool epoll_del(tproxy_conn_t *conn)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));

	DBGPRINT("epoll_del fd=%d",conn->fd);
	if(epoll_ctl(conn->efd, EPOLL_CTL_DEL, conn->fd, &ev)==-1)
	{
		perror("epoll_ctl (del)");
		return false;
	}
	return true;
}

static bool epoll_update_flow(tproxy_conn_t *conn)
{
	if (conn->bFlowInPrev==conn->bFlowIn && conn->bFlowOutPrev==conn->bFlowOut && conn->bPrevRdhup==(conn->state==CONN_RDHUP))
		return true; // unchanged, no need to syscall
	uint32_t evtmask = (conn->state==CONN_RDHUP ? 0 : EPOLLRDHUP)|(conn->bFlowIn?EPOLLIN:0)|(conn->bFlowOut?EPOLLOUT:0);
	if (!epoll_set(conn, evtmask))
		return false;
	DBGPRINT("SET FLOW fd=%d to in=%d out=%d state_rdhup=%d",conn->fd,conn->bFlowIn,conn->bFlowOut,conn->state==CONN_RDHUP)
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
	int remote_fd=0;

	if (proxy_type==CONN_TYPE_TRANSPARENT)
	{
		if(!get_dest_addr(local_fd, accept_sa, &orig_dst))
		{
			fprintf(stderr, "Could not get destination address\n");
			close(local_fd);
			return NULL;
		}
		if (check_local_ip((struct sockaddr*)&orig_dst) && saport((struct sockaddr*)&orig_dst)==listen_port)
		{
			VPRINT("Dropping connection to local address to the same port to avoid loop")
			close(local_fd);
			return NULL;
		}
	}

	// socket buffers inherited from listen_fd
	dbgprint_socket_buffers(local_fd);

	if(!set_keepalive(local_fd))
	{
		perror("set_keepalive");
		close(local_fd);
		return 0;
	}

	if (proxy_type==CONN_TYPE_TRANSPARENT)
	{
		if ((remote_fd = connect_remote((struct sockaddr *)&orig_dst, true)) < 0)
		{
			fprintf(stderr, "Failed to connect\n");
			close(local_fd);
			return NULL;
		}
	}

	if(!(conn = new_conn(local_fd, false)))
	{
		if (remote_fd) close(remote_fd);
		close(local_fd);
		return NULL;
	}
	conn->conn_type = proxy_type; // only local connection has proxy_type. remote is always in tcp mode
	conn->state = CONN_AVAILABLE; // accepted connection is immediately available
	conn->efd = efd;

	if (proxy_type==CONN_TYPE_TRANSPARENT)
	{
		if(!(conn->partner = new_conn(remote_fd, true)))
		{
			free_conn(conn);
			close(remote_fd);
			return NULL;
		}
		conn->partner->partner = conn;
		conn->partner->efd = efd;

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
		perror("getsockopt (SO_ERROR)");
		return false;
	}
	if (!errn)
	{
		VPRINT("Socket fd=%d (remote) connected", conn->fd)
		if (!epoll_set_flow(conn, true, false) || conn_partner_alive(conn) && !epoll_set_flow(conn->partner, true, false))
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

	DBGPRINT("epoll_set_flow_pair fd=%d remote=%d partner_fd=%d bHasUnsent=%d bHasUnsentPartner=%d state_rdhup=%d", 
			conn->fd , conn->remote, conn_partner_alive(conn) ? conn->partner->fd : 0, bHasUnsent, bHasUnsentPartner, conn->state==CONN_RDHUP)
	if (!epoll_set_flow(conn, !bHasUnsentPartner && (conn->state!=CONN_RDHUP), bHasUnsent || conn->state==CONN_RDHUP))
		return false;
	if (conn_partner_alive(conn))
	{
		if (!epoll_set_flow(conn->partner, !bHasUnsent && (conn->partner->state!=CONN_RDHUP), bHasUnsentPartner || conn->partner->state==CONN_RDHUP))
			return false;
	}
	return true;
}

static bool handle_unsent(tproxy_conn_t *conn)
{
	ssize_t wr;

	DBGPRINT("+handle_unsent, fd=%d has_unsent=%d has_unsent_partner=%d",conn->fd,conn_has_unsent(conn),conn_partner_alive(conn) ? conn_has_unsent(conn->partner) : false)
	
#ifdef SPLICE_PRESENT
	if (!params.nosplice && conn->wr_unsent)
	{
		wr = splice(conn->splice_pipe[0], NULL, conn->fd, NULL, conn->wr_unsent, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		DBGPRINT("splice unsent=%zd wr=%zd err=%d",conn->wr_unsent,wr,errno)
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
		DBGPRINT("conn_buffers_send wr=%zd",wr)
		if (wr<0) return false;
	}
	return epoll_set_flow_pair(conn);
}


bool proxy_mode_connect_remote(const struct sockaddr *sa, tproxy_conn_t *conn, struct tailhead *conn_list)
{
	int remote_fd;

	if (params.debug>=1)
	{
		printf("socks target for fd=%d is : ", conn->fd);
		print_sockaddr(sa);
		printf("\n");
	}
	if (check_local_ip((struct sockaddr *)sa))
	{
		VPRINT("Dropping connection to local address for security reasons")
		socks_send_rep(conn->socks_ver, conn->fd, S5_REP_NOT_ALLOWED_BY_RULESET);
		return false;
	}

	bool bConnFooling=true;
	if (conn->track.hostname && params.mss)
	{
		bConnFooling=HostlistCheck(conn->track.hostname, NULL);
		if (!bConnFooling)
			VPRINT("0-phase desync hostlist check negative. not acting on this connection.")
	}

	if ((remote_fd = connect_remote(sa, bConnFooling)) < 0)
	{
		fprintf(stderr, "socks failed to connect (1) errno=%d\n", errno);
		socks_send_rep_errno(conn->socks_ver, conn->fd, errno);
		return false;
	}
	if (!(conn->partner = new_conn(remote_fd, true)))
	{
		close(remote_fd);
		fprintf(stderr, "socks out-of-memory (1)\n");
		socks_send_rep(conn->socks_ver, conn->fd, S5_REP_GENERAL_FAILURE);
		return false;
	}
	conn->partner->partner = conn;
	conn->partner->efd = conn->efd;
	if (!epoll_set(conn->partner, EPOLLOUT))
	{
		fprintf(stderr, "socks epoll_set error %d\n", errno);
		free_conn(conn->partner);
		conn->partner = NULL;
		socks_send_rep(conn->socks_ver, conn->fd, S5_REP_GENERAL_FAILURE);
		return false;
	}
	TAILQ_INSERT_HEAD(conn_list, conn->partner, conn_ptrs);
	legs_remote++;
	print_legs();
	DBGPRINT("S_WAIT_CONNECTION")
	conn->socks_state = S_WAIT_CONNECTION;
	return true;
}

static bool handle_proxy_mode(tproxy_conn_t *conn, struct tailhead *conn_list)
{
	// To simplify things I dont care about buffering. If message splits, I just hang up
	// in proxy mode messages are short. they can be split only intentionally. all normal programs send them in one packet

	ssize_t rd,wr;
	char buf[sizeof(s5_req)]; // s5_req - the largest possible req
	struct sockaddr_storage ss;

	// receive proxy control message
	rd=recv(conn->fd, buf, sizeof(buf), MSG_DONTWAIT);
	DBGPRINT("handle_proxy_mode rd=%zd",rd)
	if (rd<1) return false; // hangup
	switch(conn->conn_type)
	{
		case CONN_TYPE_SOCKS:
			switch(conn->socks_state)
			{
				case S_WAIT_HANDSHAKE:
					DBGPRINT("S_WAIT_HANDSHAKE")
					if (buf[0] != 5 && buf[0] != 4) return false; // unknown socks version
					conn->socks_ver = buf[0];
					DBGPRINT("socks version %u", conn->socks_ver)
					if (conn->socks_ver==5)
					{
						s5_handshake *m = (s5_handshake*)buf;
						s5_handshake_ack ack;
						uint8_t k;

						ack.ver=5;
						if (!S5_REQ_HANDHSHAKE_VALID(m,rd))
						{
							DBGPRINT("socks5 proxy handshake invalid")
							return false;
						}
						for (k=0;k<m->nmethods;k++) if (m->methods[k]==S5_AUTH_NONE) break;
						if (k>=m->nmethods)
						{
							DBGPRINT("socks5 client wants authentication but we dont support")
							ack.method=S5_AUTH_UNACCEPTABLE;
							wr=send(conn->fd,&ack,sizeof(ack),MSG_DONTWAIT);
							return false;
						}
						DBGPRINT("socks5 recv valid handshake")
						ack.method=S5_AUTH_NONE;
						wr=send(conn->fd,&ack,sizeof(ack),MSG_DONTWAIT);
						if (wr!=sizeof(ack))
						{
							DBGPRINT("socks5 handshake ack send error. wr=%zd errno=%d",wr,errno)
							return false;
						}
						DBGPRINT("socks5 send handshake ack OK")
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
							DBGPRINT("socks4 request invalid")
							return false;
						}
						if (m->cmd!=S4_CMD_CONNECT)
						{
							// BIND is not supported
							DBGPRINT("socks4 unsupported command %02X", m->cmd)
							socks4_send_rep(conn->fd, S4_REP_FAILED);
							return false;
						}
						if (!S4_REQ_CONNECT_VALID(m, rd))
						{
							DBGPRINT("socks4 connect request invalid")
							socks4_send_rep(conn->fd, S4_REP_FAILED);
							return false;
						}
						if (!m->port)
						{
							DBGPRINT("socks4 zero port")
							socks4_send_rep(conn->fd, S4_REP_FAILED);
							return false;
						}
						if (m->ip==htonl(1)) // special ip 0.0.0.1
						{
							VPRINT("socks4a protocol not supported")
							socks4_send_rep(conn->fd, S4_REP_FAILED);
							return false;
						}
						ss.ss_family = AF_INET;
						((struct sockaddr_in*)&ss)->sin_port = m->port;
						((struct sockaddr_in*)&ss)->sin_addr.s_addr = m->ip;
						return proxy_mode_connect_remote((struct sockaddr *)&ss, conn, conn_list);
					}
					break;
				case S_WAIT_REQUEST:
					DBGPRINT("S_WAIT_REQUEST")
					{
						s5_req *m = (s5_req*)buf;

						if (!S5_REQ_HEADER_VALID(m,rd))
						{
							DBGPRINT("socks5 request invalid")
							return false;
						}
						if (m->cmd!=S5_CMD_CONNECT)
						{
							// BIND and UDP are not supported
							DBGPRINT("socks5 unsupported command %02X", m->cmd)
							socks5_send_rep(conn->fd,S5_REP_COMMAND_NOT_SUPPORTED);
							return false;
						}
						if (!S5_REQ_CONNECT_VALID(m,rd))
						{
							DBGPRINT("socks5 connect request invalid")
							return false;
						}
						DBGPRINT("socks5 recv valid connect request")
						switch(m->atyp)
						{
							case S5_ATYP_IP4:
								ss.ss_family = AF_INET;
								((struct sockaddr_in*)&ss)->sin_port = m->d4.port;
								((struct sockaddr_in*)&ss)->sin_addr = m->d4.addr;
								break;
							case S5_ATYP_IP6:
								ss.ss_family = AF_INET6;
								((struct sockaddr_in6*)&ss)->sin6_port = m->d6.port;
								((struct sockaddr_in6*)&ss)->sin6_addr = m->d6.addr;
								((struct sockaddr_in6*)&ss)->sin6_flowinfo = 0;
								((struct sockaddr_in6*)&ss)->sin6_scope_id = 0;
								break;
							case S5_ATYP_DOM:
								{
									struct addrinfo *ai,hints;
									int r;
									uint16_t port;
									char sport[6];

									if (params.no_resolve)
									{
										VPRINT("socks5 hostname resolving disabled")
										socks5_send_rep(conn->fd,S5_REP_NOT_ALLOWED_BY_RULESET);
										return false;
									}
									port=S5_PORT_FROM_DD(m,rd);
									if (!port)
									{
										VPRINT("socks5 no port is given")
										socks5_send_rep(conn->fd,S5_REP_HOST_UNREACHABLE);
										return false;
									}
									m->dd.domport[m->dd.len] = 0;
									DBGPRINT("socks5 queue resolve hostname '%s' port '%u'",m->dd.domport,port)
									conn->socks_ri = resolver_queue(m->dd.domport,port,conn);
									if (!conn->socks_ri)
									{
										VPRINT("socks5 could not queue resolve item")
										socks5_send_rep(conn->fd,S5_REP_GENERAL_FAILURE);
										return false;
									}
									conn->socks_state=S_WAIT_RESOLVE;
									DBGPRINT("S_WAIT_RESOLVE")
									return true;
								}
								break;
							default:
								return false; // should not be here. S5_REQ_CONNECT_VALID checks for valid atyp

						}
						return proxy_mode_connect_remote((struct sockaddr *)&ss,conn,conn_list);
					}
					break;
				case S_WAIT_RESOLVE:
					DBGPRINT("socks received message while in S_WAIT_RESOLVE. hanging up")
					break;
				case S_WAIT_CONNECTION:
					DBGPRINT("socks received message while in S_WAIT_CONNECTION. hanging up")
					break;
				default:
					DBGPRINT("socks received message while in an unexpected connection state")
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
			DBGPRINT("resolve_complete %s. getaddrinfo result %d", ri->dom, ri->ga_res);
			if (ri->ga_res)
			{
				socks5_send_rep(conn->fd,S5_REP_HOST_UNREACHABLE);
				return false;;
			}
			else
			{
				if (!conn->track.hostname)
				{
					DBGPRINT("resolve_complete put hostname : %s", ri->dom)
					conn->track.hostname = strdup(ri->dom);
				}
				return proxy_mode_connect_remote((struct sockaddr *)&ri->ss,conn,conn_list);
			}
		}
		else
			fprintf(stderr, "resolve_complete: conn in wrong socks_state !!! (%s)\n", ri->dom);
	}
	else
		DBGPRINT("resolve_complete: orphaned resolve for %s", ri->dom);

	return true;
}


static bool in_tamper_out_range(tproxy_conn_t *conn)
{
	return (params.tamper_start_n ? (conn->tnrd+1) : conn->trd) >= params.tamper_start &&
		(!params.tamper_cutoff || (params.tamper_cutoff_n ? (conn->tnrd+1) : conn->trd) < params.tamper_cutoff);
}

static void tamper(tproxy_conn_t *conn, uint8_t *segment, size_t segment_buffer_size, size_t *segment_size, size_t *split_pos, uint8_t *split_flags)
{
	*split_pos=0;
	if (params.tamper)
	{
		if (conn->remote)
		{
			if (conn_partner_alive(conn) && !conn->partner->track.bTamperInCutoff)
			{
				tamper_in(&conn->partner->track,segment,segment_buffer_size,segment_size);
			}
		}
		else
		{
			bool in_range = in_tamper_out_range(conn);
			DBGPRINT("tamper_out stream pos %" PRIu64 "(n%" PRIu64 "). tamper range %s%u-%s%u (%s)",
				conn->trd, conn->tnrd+1,
				params.tamper_start_n ? "n" : "" , params.tamper_start,
				params.tamper_cutoff_n ? "n" : "" , params.tamper_cutoff,
				in_range ? "IN RANGE" : "OUT OF RANGE")
			if (in_range) tamper_out(&conn->track,segment,segment_buffer_size,segment_size,split_pos,split_flags);
		}
	}
}

// buffer must have at least one extra byte for OOB
static ssize_t send_or_buffer_oob(send_buffer_t *sb, int fd, uint8_t *buf, size_t len, int ttl, bool oob)
{
	ssize_t wr;
	if (oob)
	{
		VPRINT("Sending OOB byte %02X", params.oob_byte)
		uint8_t oob_save;
		oob_save = buf[len];
		buf[len] = params.oob_byte;
		wr = send_or_buffer(sb, fd, buf, len+1, MSG_OOB, ttl);
		buf[len] = oob_save;
	}
	else
		wr = send_or_buffer(sb, fd, buf, len, 0, ttl);
	return wr;
}


#define RD_BLOCK_SIZE 65536
#define MAX_WASTE (1024*1024)
static bool handle_epoll(tproxy_conn_t *conn, struct tailhead *conn_list, uint32_t evt)
{
	int numbytes;
	ssize_t rd = 0, wr = 0;
	size_t bs;


	DBGPRINT("+handle_epoll")

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
		DBGPRINT("wasted recv=%zd all_rd=%" PRIu64 " err=%d",rd,trd,errno)
		return true;
	}

	// do not receive new until old is sent
	if (conn_has_unsent(conn->partner))
		return true;
		
	bool oom=false;

	numbytes=conn_bytes_unread(conn);
	DBGPRINT("numbytes=%d",numbytes)
	if (numbytes>0)
	{
		DBGPRINT("%s leg fd=%d stream pos : %" PRIu64 "(n%" PRIu64 ")/%" PRIu64, conn->remote ? "remote" : "local", conn->fd, conn->trd,conn->tnrd+1,conn->twr)
#ifdef SPLICE_PRESENT
		if (!params.nosplice && (!params.tamper || conn->remote && conn->partner->track.bTamperInCutoff || !conn->remote && !in_tamper_out_range(conn)))
		{
			// incoming data from remote leg we splice without touching
			// pipe is in the local leg, so its in conn->partner->splice_pipe
			// if we dont tamper - splice both legs

			rd = splice(conn->fd, NULL, conn->partner->splice_pipe[1], NULL, SPLICE_LEN, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
			DBGPRINT("splice fd=%d remote=%d len=%d rd=%zd err=%d",conn->fd,conn->remote,SPLICE_LEN,rd,errno)
			if (rd<0 && errno==EAGAIN) rd=0;
			if (rd>0)
			{
				conn->tnrd++;
				conn->trd += rd;
				conn->partner->wr_unsent += rd;
				wr = splice(conn->partner->splice_pipe[0], NULL, conn->partner->fd, NULL, conn->partner->wr_unsent, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
				DBGPRINT("splice fd=%d remote=%d wr=%zd err=%d",conn->partner->fd,conn->partner->remote,wr,errno)
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
			uint8_t buf[RD_BLOCK_SIZE + 5];

			rd = recv(conn->fd, buf, RD_BLOCK_SIZE, MSG_DONTWAIT);
			DBGPRINT("recv fd=%d rd=%zd err=%d",conn->fd, rd,errno)
			if (rd<0 && errno==EAGAIN) rd=0;
			if (rd>0)
			{
				size_t split_pos;
				uint8_t split_flags;

				bs = rd;

				// tamper needs to know stream position of the block start
				tamper(conn, buf, sizeof(buf), &bs, &split_pos, &split_flags);
				// increase after tamper
				conn->tnrd++;
				conn->trd+=rd;

				if (split_pos && bs<sizeof(buf) && split_pos<sizeof(buf))
				{
					VPRINT("Splitting at pos %zu%s", split_pos, (split_flags & SPLIT_FLAG_DISORDER) ? " with disorder" : "")

					wr = send_or_buffer_oob(conn->partner->wr_buf, conn->partner->fd, buf, split_pos, !!(split_flags & SPLIT_FLAG_DISORDER), !!(split_flags & SPLIT_FLAG_OOB));
					DBGPRINT("send_or_buffer(1) fd=%d wr=%zd err=%d",conn->partner->fd,wr,errno)
					if (wr >= 0)
					{
						conn->partner->twr += wr;
						wr = send_or_buffer(conn->partner->wr_buf + 1, conn->partner->fd, buf + split_pos, bs - split_pos, 0, 0);
						DBGPRINT("send_or_buffer(2) fd=%d wr=%zd err=%d",conn->partner->fd,wr,errno)
						if (wr>0) conn->partner->twr += wr;
					}
				}
				else
				{
					wr = send_or_buffer(conn->partner->wr_buf, conn->partner->fd, buf, bs, 0, 0);
					DBGPRINT("send_or_buffer(3) fd=%d wr=%zd err=%d",conn->partner->fd,wr,errno)
					if (wr>0) conn->partner->twr += wr;
				}
				if (wr<0 && errno==ENOMEM) oom=true;
			}
		}

		if (!epoll_set_flow_pair(conn))
			return false;
	}
	
	DBGPRINT("-handle_epoll rd=%zd wr=%zd",rd,wr)
	if (oom) DBGPRINT("handle_epoll: OUT_OF_MEMORY")

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

		shutdown(conn->fd,SHUT_RDWR);
		epoll_del(conn);
		VPRINT("Socket fd=%d (partner_fd=%d, remote=%d) closed, connection removed. total_read=%" PRIu64 " total_write=%" PRIu64 " event_count=%u",
			conn->fd, conn->partner ? conn->partner->fd : 0, conn->remote, conn->trd, conn->twr, conn->event_count)
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
		DBGPRINT("read_all_and_buffer(%d) numbytes=%d",buffer_number,numbytes)
		if (numbytes>0)
		{
			if (send_buffer_create(conn->partner->wr_buf+buffer_number, NULL, numbytes, 5, 0, 0))
			{
				ssize_t rd = recv(conn->fd, conn->partner->wr_buf[buffer_number].data, numbytes, MSG_DONTWAIT);
				if (rd>0)
				{
					conn->trd+=rd;
					conn->partner->wr_buf[buffer_number].len = rd;

					conn->partner->bFlowOut = true;

					size_t split_pos;
					uint8_t split_flags;

					tamper(conn, conn->partner->wr_buf[buffer_number].data, numbytes+5, &conn->partner->wr_buf[buffer_number].len, &split_pos, &split_flags);

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

	DBGPRINT("conn_close_timed_out")

	c = TAILQ_FIRST(conn_list);
	while(c)
	{
		cnext = TAILQ_NEXT(c,conn_ptrs);
		if (conn_timed_out(c))
		{
			DBGPRINT("closing timed out connection: fd=%d remote=%d",c->fd,c->remote)
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
		perror("resolve_pipe read");
		return false;
	}
	else if (rd!=sizeof(void*))
	{
		// partial pointer read is FATAL. in any case it will cause pointer corruption and coredump
		fprintf(stderr,"resolve_pipe not full read %zu\n",rd);
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
		perror("epoll_create");
		return -1;
	}

	if (!(listen_conn=calloc(listen_fd_ct,sizeof(*listen_conn))))
	{
		perror("calloc listen_conn");
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
			perror("epoll_ctl (listen socket)");
			retval = -1;
			goto ex;
		}
	}
	if ((params.proxy_type==CONN_TYPE_SOCKS) && !params.no_resolve)
	{
		if (pipe(resolve_pipe)==-1)
		{
			perror("pipe (resolve_pipe)");
			retval = -1;
			goto ex;
		}
		if (fcntl(resolve_pipe[0], F_SETFL, O_NONBLOCK) < 0)
		{
			perror("resolve_pipe set O_NONBLOCK");
			retval = -1;
			goto ex;
		}
		ev.data.ptr = NULL;
		if (epoll_ctl(efd, EPOLL_CTL_ADD, resolve_pipe[0], &ev) == -1) {
			perror("epoll_ctl (listen socket)");
			retval = -1;
			goto ex;
		}
		if (!resolver_init(params.resolver_threads,resolve_pipe[1]))
		{
			fprintf(stderr,"could not initialize multithreaded resolver\n");
			retval = -1;
			goto ex;
		}
		VPRINT("initialized multi threaded resolver with %d threads",resolver_thread_count());
	}

	for(;;)
	{
		DBGPRINT("epoll_wait")

		if ((num_events = epoll_wait(efd, events, MAX_EPOLL_EVENTS, -1)) == -1)
		{
			if (errno == EINTR) continue; // system call was interrupted
			perror("epoll_wait");
			retval = -1;
			break;
		}

		dohup();

		for (i = 0; i < num_events; i++)
		{
			conn = (tproxy_conn_t*)events[i].data.ptr;
			if (!conn)
			{
				DBGPRINT("\nEVENT mask %08X resolve_pipe",events[i].events)
				if (events[i].events & EPOLLIN)
				{
					DBGPRINT("EPOLLIN")
					if (!handle_resolve_pipe(&conn, &conn_list, resolve_pipe[0]))
					{
						DBGPRINT("handle_resolve_pipe false")
						if (conn) close_tcp_conn(&conn_list,&close_list,conn);
					}
				}
				continue;
			}
			conn->event_count++;
			if (conn->listener)
			{
				DBGPRINT("\nEVENT mask %08X fd=%d accept",events[i].events,conn->fd)

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
					perror("Failed to accept connection");
				}
				else if (legs_local >= params.maxconn) // each connection has 2 legs - local and remote
				{
					close(tmp_fd);
					VPRINT("Too many local legs : %d", legs_local)
				}
#if defined (__APPLE__)
				// separate fcntl call to comply with macos
				else if (fcntl(tmp_fd, F_SETFL, O_NONBLOCK) < 0)
				{
					perror("socket set O_NONBLOCK (accept)");
					close(tmp_fd);
				}
#endif
				else if (!(conn=add_tcp_connection(efd, &conn_list, tmp_fd, (struct sockaddr*)&accept_sa, params.port, params.proxy_type)))
				{
					// add_tcp_connection closes fd in case of failure
					VPRINT("Failed to add connection");
				}
				else
				{	
					print_legs();
					VPRINT("Socket fd=%d (local) connected", conn->fd)
				}
			}
			else
			{
				DBGPRINT("\nEVENT mask %08X fd=%d remote=%d fd_partner=%d",events[i].events,conn->fd,conn->remote,conn_partner_alive(conn) ? conn->partner->fd : 0)

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
						VPRINT("Socket fd=%d (partner_fd=%d, remote=%d) %s so_error=%d (%s)",conn->fd,conn->partner ? conn->partner->fd : 0,conn->remote,se,errn,strerror(errn));
						proxy_remote_conn_ack(conn,errn);
						read_all_and_buffer(conn,3);
						if (errn==ECONNRESET && conn->remote && params.tamper && conn_partner_alive(conn)) rst_in(&conn->partner->track);

						conn_close_with_partner_check(&conn_list,&close_list,conn);
						continue;
					}
					if (events[i].events & EPOLLOUT)
					{
						if (!check_connection_attempt(conn, efd))
						{
							VPRINT("Connection attempt failed for fd=%d", conn->fd)
							conn_close_both(&conn_list,&close_list,conn);
							continue;
						}
					}
					if (events[i].events & EPOLLRDHUP)
					{
						DBGPRINT("EPOLLRDHUP")
						read_all_and_buffer(conn,2);
						if (!conn->remote && params.tamper) hup_out(&conn->track);

						if (conn_has_unsent(conn))
						{
							DBGPRINT("conn fd=%d has unsent, not closing", conn->fd)
							conn->state = CONN_RDHUP; // only writes
							epoll_set_flow(conn,false,true);
						}
						else
						{
							DBGPRINT("conn fd=%d has no unsent, closing", conn->fd)
							conn_close_with_partner_check(&conn_list,&close_list,conn);
						}
						continue;
					}

					if (events[i].events & (EPOLLIN|EPOLLOUT))
					{
						// will not receive this until successful check_connection_attempt()
						if (!handle_epoll(conn, &conn_list, events[i].events))
						{
							DBGPRINT("handle_epoll false")
							conn_close_with_partner_check(&conn_list,&close_list,conn);
							continue;
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
	if (listen_conn) free(listen_conn);
	resolver_deinit();
	if (resolve_pipe[0]) close(resolve_pipe[0]);
	if (resolve_pipe[1]) close(resolve_pipe[1]);
	return retval;
}
