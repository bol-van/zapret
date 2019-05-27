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
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/netfilter_ipv4.h>
#include <ifaddrs.h>

#include "tpws.h"
#include "tpws_conn.h"
#include "tamper.h"
#include "params.h"

#ifndef IP6T_SO_ORIGINAL_DST
 #define IP6T_SO_ORIGINAL_DST 80
#endif


bool send_buffer_create(send_buffer_t *sb, char *data, size_t len)
{
	if (sb->data)
	{
		fprintf(stderr,"FATAL : send_buffer_create but buffer is not empty\n");
		exit(1);
	}
	sb->data = malloc(len);
	if (!sb->data) return false;
	if (data) memcpy(sb->data,data,len);
	sb->len = len;
	sb->pos = 0;
	return true;
}
bool send_buffer_free(send_buffer_t *sb)
{
	if (sb->data)
	{
		free(sb->data);
		sb->data = NULL;
	}
}
void send_buffers_free(send_buffer_t *sb_array, int count)
{
	for (int i=0;i<count;i++)
		send_buffer_free(sb_array+i);
}
void conn_free_buffers(tproxy_conn_t *conn)
{
	send_buffers_free(conn->wr_buf,sizeof(conn->wr_buf)/sizeof(conn->wr_buf[0]));
}
bool send_buffer_present(send_buffer_t *sb)
{
	return !!sb->data;
}
bool send_buffers_present(send_buffer_t *sb_array, int count)
{
	for(int i=0;i<count;i++)
		if (send_buffer_present(sb_array+i))
			return true;
	return false;
}
ssize_t send_buffer_send(send_buffer_t *sb, int fd)
{
	ssize_t wr;

	wr = send(fd, sb->data + sb->pos, sb->len - sb->pos, 0);
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
ssize_t send_buffers_send(send_buffer_t *sb_array, int count, int fd, size_t *real_wr)
{
	ssize_t wr=0,twr=0;

	for (int i=0;i<count;i++)
	{
		if (send_buffer_present(sb_array+i))
		{
			wr = send_buffer_send(sb_array+i, fd);
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
bool conn_partner_alive(tproxy_conn_t *conn)
{
	return conn->partner && conn->partner->state!=CONN_CLOSED;
}
bool conn_buffers_present(tproxy_conn_t *conn)
{
	return send_buffers_present(conn->wr_buf,sizeof(conn->wr_buf)/sizeof(conn->wr_buf[0]));
}
ssize_t conn_buffers_send(tproxy_conn_t *conn)
{
	size_t wr,real_twr;
	wr = send_buffers_send(conn->wr_buf,sizeof(conn->wr_buf)/sizeof(conn->wr_buf[0]), conn->fd, &real_twr);
	conn->twr += real_twr;
	return wr;
}
bool conn_has_unsent(tproxy_conn_t *conn)
{
	return !conn->remote && conn->wr_unsent || conn_buffers_present(conn);
}
int conn_bytes_unread(tproxy_conn_t *conn)
{
	int numbytes=-1;
	ioctl(conn->fd, FIONREAD, &numbytes)!=-1;
	return numbytes;
}
bool conn_has_unsent_pair(tproxy_conn_t *conn)
{
	return conn_has_unsent(conn) || (conn_partner_alive(conn) && conn_has_unsent(conn->partner));
}


ssize_t send_or_buffer(send_buffer_t *sb, int fd, char *buf, size_t len)
{
	ssize_t wr=0;
	if (len)
	{
		wr = send(fd, buf, len, 0);
		if (wr<0 && errno==EAGAIN) wr=0;
		if (wr>=0 && wr<len)
		{
			if (!send_buffer_create(sb, buf+wr, len-wr))
				wr=-1;
		}
	}
	return wr;
}


bool set_linger(int fd)
{
	struct linger ling={1,5};
	return setsockopt(fd,SOL_SOCKET,SO_LINGER,&ling,sizeof(ling))!=-1;
}
int set_keepalive(int fd)
{
	int yes=1;
	return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int))!=-1;
}

bool ismapped(const struct sockaddr_in6 *sa)
{
	// ::ffff:1.2.3.4
	return !memcmp(sa->sin6_addr.s6_addr,"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff",12);
}
bool mappedcmp(const struct sockaddr_in *sa1,const struct sockaddr_in6 *sa2)
{
	return ismapped(sa2) && !memcmp(sa2->sin6_addr.s6_addr+12,&sa1->sin_addr.s_addr,4);
}
bool sacmp(const struct sockaddr *sa1,const struct sockaddr *sa2)
{
	return sa1->sa_family==AF_INET && sa2->sa_family==AF_INET && !memcmp(&((struct sockaddr_in*)sa1)->sin_addr,&((struct sockaddr_in*)sa2)->sin_addr,sizeof(struct in_addr)) ||
		sa1->sa_family==AF_INET6 && sa2->sa_family==AF_INET6 && !memcmp(&((struct sockaddr_in6*)sa1)->sin6_addr,&((struct sockaddr_in6*)sa2)->sin6_addr,sizeof(struct in6_addr)) ||
		sa1->sa_family==AF_INET && sa2->sa_family==AF_INET6 && mappedcmp((struct sockaddr_in*)sa1,(struct sockaddr_in6*)sa2) ||
		sa1->sa_family==AF_INET6 && sa2->sa_family==AF_INET && mappedcmp((struct sockaddr_in*)sa2,(struct sockaddr_in6*)sa1);
}
uint16_t saport(const struct sockaddr *sa)
{
	return htons(sa->sa_family==AF_INET ? ((struct sockaddr_in*)sa)->sin_port :
		     sa->sa_family==AF_INET6 ? ((struct sockaddr_in6*)sa)->sin6_port : 0);
}
// -1 = error,  0 = not local, 1 = local
bool check_local_ip(const struct sockaddr *saddr)
{
	struct ifaddrs *addrs,*a;
    
	if (getifaddrs(&addrs)<0) return -1;
	a  = addrs;

	while (a)
	{
		if (a->ifa_addr && sacmp(a->ifa_addr,saddr))
		{
			freeifaddrs(addrs);
			return true;
		}
		a = a->ifa_next;
	}

	freeifaddrs(addrs);
	return false;
}

//Createas a socket and initiates the connection to the host specified by 
//remote_addr.
//Returns 0 if something fails, >0 on success (socket fd).
static int connect_remote(struct sockaddr_storage *remote_addr)
{
	int remote_fd = 0, yes = 1;
    
	//Use NONBLOCK to avoid slow connects affecting the performance of other connections
 	if((remote_fd = socket(remote_addr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0){
		perror("socket (connect_remote): ");
		return 0;
	}

	if(setsockopt(remote_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
	{
		perror("setsockopt (SO_REUSEADDR, connect_remote): ");
		close(remote_fd);
		return 0;
	}
	if(!set_keepalive(remote_fd))
	{
		perror("set_keepalive: ");
		close(remote_fd);
		return 0;
	}
	if (setsockopt(remote_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) <0)
	{
		perror("setsockopt (SO_NODELAY, connect_remote): ");
		close(remote_fd);
		return 0;
	}

	if(connect(remote_fd, (struct sockaddr*) remote_addr, 
		remote_addr->ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0)
	{
		if(errno != EINPROGRESS)
		{
			perror("connect (connect_remote): ");
			close(remote_fd);
			return 0;
		}
	}

	return remote_fd;
}

//Store the original destination address in remote_addr
//Return 0 on success, <0 on failure
static bool get_dest_addr(int sockfd, struct sockaddr_storage *orig_dst)
{
	char orig_dst_str[INET6_ADDRSTRLEN];
	socklen_t addrlen = sizeof(*orig_dst);
	int r;

	memset(orig_dst, 0, addrlen);

	//For UDP transparent proxying:
	//Set IP_RECVORIGDSTADDR socket option for getting the original 
	//destination of a datagram

	// DNAT
	r=getsockopt(sockfd, SOL_IP, SO_ORIGINAL_DST, (struct sockaddr*) orig_dst, &addrlen);
	if (r<0)
		r = getsockopt(sockfd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, (struct sockaddr*) orig_dst, &addrlen);
	if (r<0)
	{
		fprintf(stderr,"both SO_ORIGINAL_DST and IP6T_SO_ORIGINAL_DST failed !\n");
		// TPROXY : socket is bound to original destination
		r=getsockname(sockfd, (struct sockaddr*) orig_dst, &addrlen);
		if (r<0)
		{
			perror("getsockname: ");
			return false;
		}
	}
	if (orig_dst->ss_family == AF_INET)
	{
		inet_ntop(AF_INET, &(((struct sockaddr_in*) orig_dst)->sin_addr), orig_dst_str, INET_ADDRSTRLEN);
		printf("Original destination for socket fd=%d : %s:%d\n", sockfd,orig_dst_str, htons(((struct sockaddr_in*) orig_dst)->sin_port));
	}
	else if (orig_dst->ss_family == AF_INET6)
	{
		inet_ntop(AF_INET6,&(((struct sockaddr_in6*) orig_dst)->sin6_addr), orig_dst_str, INET6_ADDRSTRLEN);
		printf("Original destination for socket fd=%d : [%s]:%d\n", sockfd,orig_dst_str, htons(((struct sockaddr_in6*) orig_dst)->sin6_port));
	}
	return true;
}

//Free resources occupied by this connection
void free_conn(tproxy_conn_t *conn)
{
	if (conn->fd) close(conn->fd);
	if (conn->splice_pipe[0])
	{
		close(conn->splice_pipe[0]);
		close(conn->splice_pipe[1]);
	}
	conn_free_buffers(conn);
	if (conn->partner) conn->partner->partner=NULL;
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

	// pipe only needed for one leg. other we process by send/recv
	// lets store pipe in local leg
	if(!remote && pipe2(conn->splice_pipe, O_NONBLOCK) != 0)
	{
		fprintf(stderr, "Could not create the splice pipe\n");
		free_conn(conn);
		return NULL;
	}
	
	return conn;
}

bool epoll_set(tproxy_conn_t *conn, uint32_t events)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.ptr = (void*) conn;

	if(epoll_ctl(conn->efd, EPOLL_CTL_MOD, conn->fd, &ev)==-1 &&
	   epoll_ctl(conn->efd, EPOLL_CTL_ADD, conn->fd, &ev)==-1)
	{
		perror("epoll_ctl (add/mod)");
		return false;
	}
	return true;
}
bool epoll_del(tproxy_conn_t *conn)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));

	if(epoll_ctl(conn->efd, EPOLL_CTL_DEL, conn->fd, &ev)==-1)
	{
		perror("epoll_ctl (del)");
		return false;
	}
	return true;
}

bool epoll_update_flow(tproxy_conn_t *conn)
{
	if (conn->bFlowInPrev==conn->bFlowIn && conn->bFlowOutPrev==conn->bFlowOut && conn->bPrevRdhup==(conn->state==CONN_RDHUP))
		return true; // unchanged, no need to syscall
	uint32_t evtmask = (conn->state==CONN_RDHUP ? 0 : EPOLLRDHUP)|(conn->bFlowIn?EPOLLIN:0)|(conn->bFlowOut?EPOLLOUT:0);
	if (!epoll_set(conn, evtmask))
		return false;
	DBGPRINT("SET FLOW fd=%d to in=%d out=%d state_rdhup=%d",conn->fd,conn->bFlowIn,conn->bFlowOut,conn->state==CONN_RDHUP);
	conn->bFlowInPrev = conn->bFlowIn;
	conn->bFlowOutPrev = conn->bFlowOut;
	conn->bPrevRdhup = (conn->state==CONN_RDHUP);
	return true;
}
bool epoll_set_flow(tproxy_conn_t *conn, bool bFlowIn, bool bFlowOut)
{
	conn->bFlowIn = bFlowIn;
	conn->bFlowOut = bFlowOut;
	return epoll_update_flow(conn);
}

//Acquires information, initiates a connect and initialises a new connection
//object. Return NULL if anything fails, pointer to object otherwise
tproxy_conn_t* add_tcp_connection(int efd, struct tailhead *conn_list,
        int local_fd, uint16_t listen_port)
{
	struct sockaddr_storage orig_dst;
	tproxy_conn_t *conn;
	int remote_fd;
	int yes=1;

	if(!get_dest_addr(local_fd, &orig_dst))
	{
		fprintf(stderr, "Could not get destination address\n");
		close(local_fd);
		return NULL;
	}

	if (check_local_ip((struct sockaddr*)&orig_dst) && saport((struct sockaddr*)&orig_dst)==listen_port)
	{
		fprintf(stderr, "Dropping connection to local address to the same port to avoid loop\n");
		close(local_fd);
		return NULL;
	}

	if(!set_keepalive(local_fd))
	{
		perror("set_keepalive: ");
		close(local_fd);
		return 0;
	}

	if(!(remote_fd = connect_remote(&orig_dst)))
	{
		fprintf(stderr, "Failed to connect\n");
		close(local_fd);
		return NULL;
	}
	
	if(!(conn = new_conn(local_fd, false)))
	{
		close(remote_fd);
		close(local_fd);
		return NULL;
	}
	conn->state = CONN_AVAILABLE; // accepted connection is immediately available
	conn->efd = efd;

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
	if (!epoll_set(conn->partner, EPOLLOUT|EPOLLERR))
	{
		free_conn(conn->partner);
		free_conn(conn);
		return NULL;
	}

	//Local socket can be closed while waiting for connection attempt. I need
	//to detect this when waiting for connect() to complete. However, I dont
	//want to get EPOLLIN-events, as I dont want to receive any data before
	//remote connection is established
	if (!epoll_set(conn, 0))
	{
		free_conn(conn->partner);
		free_conn(conn);
		return NULL;
	}

	TAILQ_INSERT_HEAD(conn_list, conn, conn_ptrs);
	TAILQ_INSERT_HEAD(conn_list, conn->partner, conn_ptrs);
	return conn;
} 

//Checks if a connection attempt was successful or not
//Returns true if successfull, false if not
bool check_connection_attempt(tproxy_conn_t *conn, int efd)
{
	int fd_flags = 0;
	int conn_success = 0;
	socklen_t optlen = sizeof(conn_success);

	if (conn->state!=CONN_UNAVAILABLE || !conn->remote)
	{
		// locals are connected since accept
		// remote need to be checked only once
		return true;
	}

	// check the connection was sucessfull. it means its not in in SO_ERROR state
	if(getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &conn_success, &optlen) == -1)
	{
		perror("getsockopt (SO_ERROR)");
		return false;
	}
	if(conn_success == 0)
	{
		printf("Socket fd=%d (remote) connected\n", conn->fd);

		if (!epoll_set_flow(conn, true, false) || !epoll_set_flow(conn->partner, true, false))
			return false;
		
       		conn->state = CONN_AVAILABLE;
		return true;
	}
        
	return false;
}




bool epoll_set_flow_pair(tproxy_conn_t *conn)
{
	bool bHasUnsent = conn_has_unsent(conn);
	bool bHasUnsentPartner = conn_partner_alive(conn) ? conn_has_unsent(conn->partner) : false;

	DBGPRINT("epoll_set_flow_pair fd=%d partner_fd=%d bHasUnsent=%d bHasUnsentPartner=%d state_rdhup=%d", 
			conn->fd , conn_partner_alive(conn) ? conn->partner->fd : 0, bHasUnsent, bHasUnsentPartner, conn->state==CONN_RDHUP);
	if (!epoll_set_flow(conn, !bHasUnsentPartner && (conn->state!=CONN_RDHUP), bHasUnsent || conn->state==CONN_RDHUP))
		return false;
	if (conn_partner_alive(conn))
	{
		if (!epoll_set_flow(conn->partner, !bHasUnsent && (conn->partner->state!=CONN_RDHUP), conn->partner->bFlowOut = bHasUnsentPartner || conn->partner->state==CONN_RDHUP))
			return false;
	}
	return true;
}

bool handle_unsent(tproxy_conn_t *conn)
{
	ssize_t wr=0,twr=0;

	DBGPRINT("+handle_unsent, fd=%d has_unsent=%d has_unsent_partner=%d",conn->fd,conn_has_unsent(conn),conn_partner_alive(conn) ? conn_has_unsent(conn->partner) : false);
	
	// its possible to have unsent data both in the pipe and in buffers
	// but we initialize pipe only on local leg
	if (!conn->remote)
	{
		if (conn->wr_unsent)
		{
			wr = splice(conn->splice_pipe[0], NULL, conn->fd, NULL, conn->wr_unsent, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
			DBGPRINT("splice unsent=%zd wr=%zd err=%d",conn->wr_unsent,wr,errno);
			if (wr<0)
			{
				if (errno==EAGAIN) wr=0;
				else return false;
			}
			twr += wr;
			conn->twr += wr;
			conn->wr_unsent -= wr;
		}
	}
	if (!conn->wr_unsent && conn_buffers_present(conn))
	{
		wr=conn_buffers_send(conn);
		DBGPRINT("conn_buffers_send wr=%zd",wr);
		if (wr<0) return false;
		twr += wr;
	}
	return epoll_set_flow_pair(conn);
}


#define RD_BLOCK_SIZE 8192

bool handle_epoll(tproxy_conn_t *conn, uint32_t evt)
{
	int numbytes;
	ssize_t rd = 0, wr = 0;
	size_t bs;


	DBGPRINT("+handle_epoll");

	if (!handle_unsent(conn))
		return false; // error
	if (!conn_partner_alive(conn) && !conn_has_unsent(conn))
		return false; // when no partner, we only waste read and send unsent

	if (!(evt & EPOLLIN))
		return true; // nothing to read
		
	if (!conn_partner_alive(conn))
	{
		// throw it to a black hole
		char waste[1448];
		ssize_t rrd;

		while((rrd=recv(conn->fd, waste, sizeof(waste), MSG_DONTWAIT))>0)
		{
			rd+=rrd;
			conn->trd+=rrd;
		}
		DBGPRINT("wasted recv=%zd all_rd=%zd err=%d",rrd,rd,errno);
		return true;
	}

	// do not receive new until old is sent
	if (conn_has_unsent(conn->partner))
		return true;

	numbytes=conn_bytes_unread(conn);
	DBGPRINT("numbytes=%d",numbytes);
	if (numbytes>0)
	{
		if (conn->remote)
		{
			// incoming data from remote leg we splice without touching
			// pipe is in the local leg, so its in conn->partner->splice_pipe

			rd = splice(conn->fd, NULL, conn->partner->splice_pipe[1], NULL, SPLICE_LEN, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
			DBGPRINT("splice len=%d rd=%zd err=%d",SPLICE_LEN,rd,errno);
			if (rd<0 && errno==EAGAIN) rd=0;
			if (rd>0)
			{
				conn->trd += rd;
				conn->partner->wr_unsent += rd;
				wr = splice(conn->partner->splice_pipe[0], NULL, conn->partner->fd, NULL, conn->partner->wr_unsent, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
				DBGPRINT("splice wr=%zd err=%d",wr,errno);
				if (wr<0 && errno==EAGAIN) wr=0;
				if (wr>0) 
				{
					conn->partner->wr_unsent -= wr;
					conn->partner->twr += wr;
				}
			}
		}
		else
		{
			// incoming data from local leg
			char buf[RD_BLOCK_SIZE + 4];

			rd = recv(conn->fd, buf, RD_BLOCK_SIZE, MSG_DONTWAIT);
			if (rd<0 && errno==EAGAIN) rd=0;
			if (rd>0)
			{
				conn->trd+=rd;

				size_t split_pos=0;

				bs = rd;
				modify_tcp_segment(buf,&bs,&split_pos);

				if (split_pos)
				{
					printf("Splitting at pos %zu\n", split_pos);
					wr = send_or_buffer(conn->partner->wr_buf, conn->partner->fd, buf, split_pos);
					if (wr >= 0)
					{
						conn->partner->twr += wr;
						wr = send_or_buffer(conn->partner->wr_buf + 1, conn->partner->fd, buf + split_pos, bs - split_pos);
						if (wr>0) conn->partner->twr += wr;
					}
				}
				else
				{
					wr = send_or_buffer(conn->partner->wr_buf, conn->partner->fd, buf, bs);
					if (wr>0) conn->partner->twr += wr;
				}
			}
		}

		if (!epoll_set_flow_pair(conn))
			return false;
	}
	
	DBGPRINT("-handle_epoll rd=%zd wr=%zd",rd,wr);

	return rd != -1 && wr != -1;
}

bool remove_closed_connections(int efd, struct tailhead *close_list)
{
	tproxy_conn_t *conn = NULL;
	bool bRemoved = false;

	while (conn = TAILQ_FIRST(close_list))
	{
		TAILQ_REMOVE(close_list, conn, conn_ptrs);

		shutdown(conn->fd,SHUT_RDWR);
		epoll_del(conn);
		printf("Socket fd=%d (partner_fd=%d, remote=%d) closed, connection removed. total_read=%zu total_write=%zu event_count=%d\n",
			conn->fd, conn->partner ? conn->partner->fd : 0, conn->remote, conn->trd, conn->twr, conn->event_count);
		free_conn(conn);
		bRemoved = true;
	}
	return bRemoved;
}

// move to close list connection and its partner
void close_tcp_conn(tproxy_conn_t *conn, struct tailhead *conn_list, struct tailhead *close_list)
{
	conn->state = CONN_CLOSED;
	TAILQ_REMOVE(conn_list, conn, conn_ptrs);
	TAILQ_INSERT_TAIL(close_list, conn, conn_ptrs);
}


bool read_all_and_buffer(tproxy_conn_t *conn)
{
	if (conn_partner_alive(conn))
	{
		int numbytes=conn_bytes_unread(conn);
		DBGPRINT("read_all_and_buffer numbytes=%d",numbytes);
		if (numbytes>0)
		{
			if (send_buffer_create(conn->partner->wr_buf+2, NULL, numbytes))
			{
				ssize_t rd = recv(conn->fd, conn->partner->wr_buf[2].data, numbytes, MSG_DONTWAIT);
				if (rd>0)
				{
					conn->trd+=rd;
					conn->partner->wr_buf[2].len = rd;
					
					conn->partner->bFlowOut = true;
					if (epoll_update_flow(conn->partner))
						return true;
				}
				send_buffer_free(conn->partner->wr_buf+2);
			}
		}
	}
	return false;
}

void count_legs(struct tailhead *conn_list, int *ct_local, int *ct_remote)
{
	tproxy_conn_t *conn = NULL;

	if (ct_local) *ct_local = 0;
	if (ct_remote) *ct_remote = 0;
	TAILQ_FOREACH(conn, conn_list, conn_ptrs)
	{
		if (conn->remote)
		{
			if (ct_remote) (*ct_remote)++;
		}
		else
		{
			if (ct_local) (*ct_local)++;
		}
	}
	
}
void print_legs(struct tailhead *conn_list)
{
	int legs_local,legs_remote;
	count_legs(conn_list, &legs_local, &legs_remote);
	printf("Legs : local:%d remote:%d\n", legs_local, legs_remote);
}


#define CONN_CLOSE(conn) { \
 if (conn->state!=CONN_CLOSED) close_tcp_conn(conn, &conn_list, &close_list); \
}
#define CONN_CLOSE_BOTH(conn) { \
 if (conn_partner_alive(conn)) CONN_CLOSE(conn->partner); \
 CONN_CLOSE(conn); \
}

#define CONN_CLOSE_WITH_PARTNER_CHECK(conn) { \
 CONN_CLOSE(conn); \
 if (conn_partner_alive(conn) && !conn_has_unsent(conn->partner)) \
  CONN_CLOSE(conn->partner); \
}

int event_loop(int listen_fd)
{
	int retval = 0, num_events = 0;
	int tmp_fd = 0; //Used to temporarily hold the accepted file descriptor
	tproxy_conn_t *conn = NULL;
	int efd, i;
	struct epoll_event ev, events[MAX_EPOLL_EVENTS];
	struct tailhead conn_list, close_list;

	//Initialize queue (remember that TAILQ_HEAD just defines the struct)
	TAILQ_INIT(&conn_list);
	TAILQ_INIT(&close_list);

	if ((efd = epoll_create(1)) == -1) {
		perror("epoll_create");
		return -1;
	}
	
	//Start monitoring listen socket
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	//There is only one listen socket, and I want to use ptr in order to have 
	//easy access to the connections. So if ptr is NULL that means an event on
	//listen socket.
	ev.data.ptr = NULL;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, listen_fd, &ev) == -1) {
		perror("epoll_ctl (listen socket)");
		close(efd);
		return -1;
	}

	while (1)
	{
		DBGPRINT("epoll_wait");

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
			if (events[i].data.ptr == NULL)
			{
				int legs_local;
				count_legs(&conn_list, &legs_local, NULL);
				//Accept new connection
				tmp_fd = accept4(listen_fd, NULL, 0, SOCK_NONBLOCK);
				if (tmp_fd < 0)
				{
					fprintf(stderr, "Failed to accept connection\n");
				}
				else if (legs_local >= params.maxconn) // each connection has 2 legs - local and remote
				{
					close(tmp_fd);
					fprintf(stderr, "Too many local legs : %d\n", legs_local);
				}
				else if (!(conn=add_tcp_connection(efd, &conn_list, tmp_fd, params.port)))
				{
					// add_tcp_connection closes fd in case of failure
					fprintf(stderr, "Failed to add connection\n");
				}
				else
				{
					printf("Socket fd=%d (local) connected\n", conn->fd);
					print_legs(&conn_list);
				}
			}
			else
			{
				conn = (tproxy_conn_t*)events[i].data.ptr;
				conn->event_count++;

				DBGPRINT("\nEVENT mask %08X fd=%d fd_partner=%d",events[i].events,conn->fd,conn_partner_alive(conn) ? conn->partner->fd : 0);

				if (conn->state != CONN_CLOSED)
				{
					if (events[i].events & (EPOLLERR|EPOLLHUP))
					{
						// immediately shutdown both ends
						CONN_CLOSE_BOTH(conn);
						continue;
					}
					if (events[i].events & EPOLLOUT)
					{
						if (!check_connection_attempt(conn, efd))
						{
							fprintf(stderr, "Connection attempt failed for fd=%d\n", conn->fd);
							CONN_CLOSE_BOTH(conn);
							continue;
						}
					}
					if (events[i].events & EPOLLRDHUP)
					{
						read_all_and_buffer(conn);

						if (conn_has_unsent(conn))
						{
							DBGPRINT("conn fd=%d has unsent, not closing", conn->fd);
							conn->state = CONN_RDHUP; // only writes
							epoll_set_flow(conn,false,true);
						}
						else
						{
							DBGPRINT("conn fd=%d has no unsent, closing", conn->fd);
							CONN_CLOSE_WITH_PARTNER_CHECK(conn);
						}
						continue;
					}

					if (events[i].events & (EPOLLIN|EPOLLOUT))
					{
						// will not receive this until successful check_connection_attempt()
						if (!handle_epoll(conn, events[i].events))
						{
							DBGPRINT("handle_epoll false");
							CONN_CLOSE_WITH_PARTNER_CHECK(conn);
							continue;
						}
					}
				}

			}
		}

		if (remove_closed_connections(efd, &close_list))
			print_legs(&conn_list);

		fflush(stderr); fflush(stdout); // for console messages
	}

	close(efd);

	return retval;
}
