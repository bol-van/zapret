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
#include <sys/epoll.h>
#include <fcntl.h>
#include <linux/netfilter_ipv4.h>
#include <ifaddrs.h>

#include "tpws_conn.h"

#ifndef IP6T_SO_ORIGINAL_DST
 #define IP6T_SO_ORIGINAL_DST 80
#endif

int linger(int sock_fd)
{
    struct linger ling={1,5};
    return setsockopt(sock_fd,SOL_SOCKET,SO_LINGER,&ling,sizeof(ling));
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
int check_local_ip(const struct sockaddr *saddr)
{
    struct ifaddrs *addrs,*a;
    
    if (getifaddrs(&addrs)<0) return -1;
    a  = addrs;

    while (a)
    {
	if (a->ifa_addr && sacmp(a->ifa_addr,saddr))
	{
	    freeifaddrs(addrs);
	    return 1;
	}
	a = a->ifa_next;
    }

    freeifaddrs(addrs);
    return 0;
}

//Createas a socket and initiates the connection to the host specified by 
//remote_addr.
//Returns 0 if something fails, >0 on success (socket fd).
static int connect_remote(struct sockaddr_storage *remote_addr){
    int remote_fd = 0, yes = 1;
    

    //Use NONBLOCK to avoid slow connects affecting the performance of other
    //connections
    if((remote_fd = socket(remote_addr->ss_family, SOCK_STREAM | 
                    SOCK_NONBLOCK, 0)) < 0){
        perror("socket (connect_remote): ");
        return 0;
    }

    if(setsockopt(remote_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0){
        perror("setsockopt (SO_REUSEADDR, connect_remote): ");
        close(remote_fd);
        return 0;
    }
    if(setsockopt(remote_fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) < 0){
        perror("setsockopt (SO_KEEPALIVE, connect_remote): ");
        close(remote_fd);
        return 0;
    }
    
    if(connect(remote_fd, (struct sockaddr*) remote_addr, 
            remote_addr->ss_family == AF_INET ? sizeof(struct sockaddr_in) :
            sizeof(struct sockaddr_in6)) < 0){
        if(errno != EINPROGRESS){
            perror("connect (connect_remote): ");
            close(remote_fd);
            return 0;
        }
    }

    return remote_fd;
}

//Store the original destination address in remote_addr
//Return 0 on success, <0 on failure
static int get_org_dstaddr(int sockfd, struct sockaddr_storage *orig_dst){
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
    	    return -1;
	}
    }
    if(orig_dst->ss_family == AF_INET){
        inet_ntop(AF_INET, 
                &(((struct sockaddr_in*) orig_dst)->sin_addr),
                orig_dst_str, INET_ADDRSTRLEN);
        fprintf(stderr, "Original destination for socket %d : %s:%d\n", sockfd,orig_dst_str, htons(((struct sockaddr_in*) orig_dst)->sin_port));
    } else if(orig_dst->ss_family == AF_INET6){
        inet_ntop(AF_INET6, 
                &(((struct sockaddr_in6*) orig_dst)->sin6_addr),
                orig_dst_str, INET6_ADDRSTRLEN);
        fprintf(stderr, "Original destination for socket %d : [%s]:%d\n", sockfd,orig_dst_str, htons(((struct sockaddr_in6*) orig_dst)->sin6_port));
    }
    return 0;
}

//Acquires information, initiates a connect and initialises a new connection
//object. Return NULL if anything fails, pointer to object otherwise
tproxy_conn_t* add_tcp_connection(int efd, struct tailhead *conn_list,
        int local_fd, uint16_t listen_port)
{
    struct sockaddr_storage orig_dst;
    tproxy_conn_t *conn;
    int remote_fd;
    struct epoll_event ev;
 
    if(get_org_dstaddr(local_fd, &orig_dst)){
        fprintf(stderr, "Could not get local address\n");
        close(local_fd);
        return NULL;
    }

    if (check_local_ip((struct sockaddr*)&orig_dst)==1 && saport((struct sockaddr*)&orig_dst)==listen_port)
    {
        fprintf(stderr, "Dropping connection to local address to the same port to avoid loop\n");
        close(local_fd);
        return NULL;
    }


    if((remote_fd = connect_remote(&orig_dst)) == 0){
        fprintf(stderr, "Failed to connect\n");
        close(remote_fd);
        close(local_fd);
        return NULL;
    }

    //Create connection object and fill in information
    if((conn = (tproxy_conn_t*) malloc(sizeof(tproxy_conn_t))) == NULL){
        fprintf(stderr, "Could not allocate memory for connection\n");
        close(remote_fd);
        close(local_fd);
        return NULL;
    }

    memset(conn, 0, sizeof(tproxy_conn_t));
    conn->state = CONN_AVAILABLE;
    conn->remote_fd = remote_fd;
    conn->local_fd = local_fd;

    if(pipe(conn->splice_pipe) != 0){
        fprintf(stderr, "Could not create the required pipe\n");
        free_conn(conn);
        return NULL;
    }


    //remote_fd is connecting. Non-blocking connects are signaled as done by 
    //socket being marked as ready for writing
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.ptr = (void*) conn;

    if(epoll_ctl(efd, EPOLL_CTL_ADD, remote_fd, &ev) == -1){
        perror("epoll_ctl (remote_fd)");
        free_conn(conn);
        return NULL;
    }

    //Local socket can be closed while waiting for connection attempt. I need
    //to detect this when waiting for connect() to complete. However, I dont
    //want to get EPOLLIN-events, as I dont want to receive any data before
    //remote connection is established
    ev.events = EPOLLRDHUP;

    if(epoll_ctl(efd, EPOLL_CTL_ADD, local_fd, &ev) == -1){
        perror("epoll_ctl (local_fd)");
        free_conn(conn);
        return NULL;
    } else
    {
        TAILQ_INSERT_HEAD(conn_list, conn, conn_ptrs);
        return conn;
    }
} 

//Free resources occupied by this connection
void free_conn(tproxy_conn_t *conn){

    close(conn->remote_fd);
    close(conn->local_fd);

    if(conn->splice_pipe[0] != 0){
        close(conn->splice_pipe[0]);
        close(conn->splice_pipe[1]);
    }

    free(conn);
}

//Checks if a connection attempt was successful or not
//Returns 0 if successfull, -1 if not
int8_t check_connection_attempt(tproxy_conn_t *conn, int efd){
    struct epoll_event ev;
    int conn_success = 0;
    int fd_flags = 0;
    socklen_t optlen = sizeof(conn_success);

    //If the connection was sucessfull or not is contained in SO_ERROR
    if(getsockopt(conn->remote_fd, SOL_SOCKET, SO_ERROR, &conn_success, 
                &optlen) == -1){
        perror("getsockopt (SO_ERROR)");
        return -1;
    }

    if(conn_success == 0){
        fprintf(stderr, "Socket %d connected\n", conn->remote_fd);
       
        //Set socket as blocking now, for ease of processing
        //TODO: Non-blocking
        if((fd_flags = fcntl(conn->remote_fd, F_GETFL)) == -1){
            perror("fcntl (F_GETFL)");
            return -1;
        }

        if(fcntl(conn->remote_fd, F_SETFL, fd_flags & ~O_NONBLOCK) == -1){
            perror("fcntl (F_SETFL)");
            return -1;
        }

        //Update both file descriptors. I am interested in EPOLLIN (if there is
        //any data) and EPOLLRDHUP (remote peer closed socket). As this is just
        //an example, EPOLLOUT is ignored and it is OK for send() to block
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.ptr = (void*) conn;

        if(epoll_ctl(efd, EPOLL_CTL_MOD, conn->remote_fd, &ev) == -1 ||
                epoll_ctl(efd, EPOLL_CTL_MOD, conn->local_fd, &ev) == -1){
            perror("epoll_ctl (check_connection_attempt)");
            return -1;
        } else {
            return 0;
        }
    }
        
    return -1;
}
