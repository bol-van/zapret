#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <pwd.h>
#include <signal.h>
#include <sys/capability.h>
#include <sys/prctl.h>

#include "tpws.h"
#include "tpws_conn.h"
#include "hostlist.h"

enum splithttpreq { split_none = 0, split_method, split_host };

struct params_s
{
	char bindaddr[64],bindiface[IFNAMSIZ];
	bool bind_if6;
	bool bindll,bindll_force;
	int bind_wait_ifup,bind_wait_ip,bind_wait_ip_ll;
	uid_t uid;
	gid_t gid;
	uint16_t port;
	bool daemon;
	bool hostcase, hostdot, hosttab, hostnospace, methodspace, methodeol, unixeol;
	char hostspell[4];
	enum splithttpreq split_http_req;
	int split_pos;
	int maxconn;
	char hostfile[256];
	char pidfile[256];
	strpool *hostlist;
};

struct params_s params;

unsigned char *find_bin(void *data, size_t len, const void *blk, size_t blk_len)
{
	while (len >= blk_len)
	{
		if (!memcmp(data, blk, blk_len))
			return data;
		data = (char*)data + 1;
		len--;
	}
	return NULL;
}

bool bHup = false;
void onhup(int sig)
{
 printf("HUP received !\n");
 if (params.hostlist)
  printf("Will reload hostlist on next request\n");
 bHup = true;
}
// should be called in normal execution
void dohup()
{
 if (bHup)
 {
  if (params.hostlist)
  {
   if (!LoadHostList(&params.hostlist, params.hostfile))
	exit(1);
  }
  bHup = false;
 }
}

size_t send_with_flush(int sockfd, const void *buf, size_t len, int flags)
{
	int flag, err;
	size_t wr;

	flag = 1;
	setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	wr = send(sockfd, buf, len, flags);
	err = errno;
	flag = 0;
	setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	errno = err;
	return wr;
}

#define RD_BLOCK_SIZE 8192

// pHost points to "Host: ..."
bool find_host(char **pHost,char *buf,size_t bs)
{
 if (!*pHost)
 {
  *pHost = find_bin(buf, bs, "\nHost: ", 7);
  if (*pHost) (*pHost)++;
  printf("Found Host: at pos %zu\n",*pHost - buf);
 }
 return !!*pHost;
}

static const char *http_methods[] = { "GET /","POST /","HEAD /","OPTIONS /","PUT /","DELETE /","CONNECT /","TRACE /",NULL };
void modify_tcp_segment(char *segment,size_t *size,size_t *split_pos)
{
	char *p, *pp, *pHost = NULL;
	size_t method_len = 0, pos;
	const char **method;
	bool bIsHttp = false, bBypass = false;
	char bRemovedHostSpace = 0;
	char Host[128];
	
	*split_pos=0;

	for (method = http_methods; *method; method++)
	{
		method_len = strlen(*method);
		if (method_len <= *size && !memcmp(segment, *method, method_len))
		{
			bIsHttp = true;
			method_len -= 2; // "GET /" => "GET"
			break;
		}
	}
	if (bIsHttp)
	{
		printf("Data block looks like http request start : %s\n", *method);
		// cpu saving : we search host only if and when required. we do not research host every time we need its position
		if (params.hostlist && find_host(&pHost,segment,*size))
		{
			bool bInHostList = false;
			p = pHost + 6;
			while (p < (segment + *size) && (*p == ' ' || *p == '\t')) p++;
			pp = p;
			while (pp < (segment + *size) && (pp - p) < (sizeof(Host) - 1) && *pp != '\r' && *pp != '\n') pp++;
			memcpy(Host, p, pp - p);
			Host[pp - p] = '\0';
			printf("Requested Host is : %s\n", Host);
			for(p = Host; *p; p++) *p=tolower(*p);
			p = Host;
			while (p)
			{
				bInHostList = StrPoolCheckStr(params.hostlist, p);
				printf("Hostlist check for %s : %s\n", p, bInHostList ? "positive" : "negative");
				if (bInHostList) break;
				p = strchr(p, '.');
				if (p) p++;
			}
			bBypass = !bInHostList;
		}
		if (!bBypass)
		{
			if (params.unixeol)
			{
				p = pp = segment;
				while (p = find_bin(p, segment + *size - p, "\r\n", 2))
				{
					*p = '\n'; p++;
					memmove(p, p + 1, segment + *size - p - 1);
					(*size)--;
					if (pp == (p - 1))
					{
						// probably end of http headers
						printf("Found double EOL at pos %zu. Stop replacing.\n", pp - segment);
						break;
					}
					pp = p;
				}
				pHost = NULL; // invalidate
			}

			if (params.methodspace)
			{
				// we only work with data blocks looking as HTTP query, so method is at the beginning
				printf("Adding extra space after method\n");
				p = segment + method_len + 1;
				pos = method_len + 1;
				memmove(p + 1, p, *size - pos);
				*p = ' '; // insert extra space
				(*size)++; // block will grow by 1 byte
				if (pHost) pHost++; // Host: position will move by 1 byte
			}
			if ((params.hostdot || params.hosttab) && find_host(&pHost,segment,*size))
			{
				p = pHost + 6;
				while (p < (segment + *size) && *p != '\r' && *p != '\n') p++;
				if (p < (segment + *size))
				{
					pos = p - segment;
					printf("Adding %s to host name at pos %zu\n", params.hostdot ? "dot" : "tab", pos);
					memmove(p + 1, p, *size - pos);
					*p = params.hostdot ? '.' : '\t'; // insert dot or tab
					(*size)++; // block will grow by 1 byte
				}
			}
			if (params.hostnospace && find_host(&pHost,segment,*size) && pHost[5] == ' ')
			{
				p = pHost + 6;
				pos = p - segment;
				printf("Removing space before host name at pos %zu\n", pos);
				memmove(p - 1, p, *size - pos);
				(*size)--; // block will shrink by 1 byte
				bRemovedHostSpace = 1;
			}
			if (!params.split_pos)
			{
				switch (params.split_http_req)
				{
				case split_method:
					*split_pos = method_len - 1;
					break;
				case split_host:
					if (find_host(&pHost,segment,*size))
						*split_pos = pHost + 6 - bRemovedHostSpace - segment;
					break;
				}
			}
			if (params.hostcase && find_host(&pHost,segment,*size))
			{
				printf("Changing 'Host:' => '%c%c%c%c:' at pos %zu\n", params.hostspell[0], params.hostspell[1], params.hostspell[2], params.hostspell[3], pHost - segment);
				memcpy(pHost, params.hostspell, 4);
			}
			if (params.methodeol)
			{
				printf("Adding EOL before method\n");
				if (params.unixeol)
				{
					memmove(segment + 1, segment, *size);
					(*size)++;;
					segment[0] = '\n';
					if (*split_pos) (*split_pos)++;
				}
				else
				{
					memmove(segment + 2, segment, *size);
					*size += 2;
					segment[0] = '\r';
					segment[1] = '\n';
					if (*split_pos) *split_pos += 2;
				}
			}
			if (params.split_pos && params.split_pos < *size) *split_pos = params.split_pos;
		}
		else
		{
			printf("Not acting on this request\n");
		}
	}
	else
	{
		printf("Data block does not look like http request start\n");
		// this is the only parameter applicable to non-http block (may be https ?)
		if (params.split_pos && params.split_pos < *size) *split_pos = params.split_pos;
	}
}


bool handle_epollin(tproxy_conn_t *conn, ssize_t *data_transferred)
{
	int numbytes;
	int fd_in, fd_out;
	bool bOutgoing;
	ssize_t rd = 0, wr = 0;
	size_t bs;

	//Easy way to determin which socket is ready for reading
	//TODO: Optimize. This one allows me quick lookup for conn, but
	//I need to make a system call to determin which socket
	numbytes = 0;
	if (ioctl(conn->local_fd, FIONREAD, &numbytes) != -1
		&& numbytes > 0) {
		fd_in = conn->local_fd;
		fd_out = conn->remote_fd;
		bOutgoing = true;
	}
	else {
		fd_in = conn->remote_fd;
		fd_out = conn->local_fd;
		numbytes = 0;
		ioctl(fd_in, FIONREAD, &numbytes);
		bOutgoing = false;
	}

	if (numbytes)
	{
		if (bOutgoing)
		{
			char buf[RD_BLOCK_SIZE + 4];

			rd = recv(fd_in, buf, RD_BLOCK_SIZE, MSG_DONTWAIT);
			if (rd > 0)
			{
				size_t split_pos;
				
				bs = rd;
				modify_tcp_segment(buf,&bs,&split_pos);

				if (split_pos)
				{
					printf("Splitting at pos %zu\n", split_pos);
					wr = send_with_flush(fd_out, buf, split_pos, 0);
					if (wr >= 0)
						wr = send(fd_out, buf + split_pos, bs - split_pos, 0);
				}
				else
				{
					wr = send(fd_out, buf, bs, 0);
				}
			}
		}
		else
		{
			// *** we are not interested in incoming traffic
			// splice it without processing

			//printf("splicing numbytes=%d\n",numbytes);
			rd = numbytes = splice(fd_in, NULL, conn->splice_pipe[1], NULL,
				SPLICE_LEN, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
			//printf("spliced rd=%d\n",rd);
			if (rd > 0)
			{
				wr = splice(conn->splice_pipe[0], NULL, fd_out, NULL,
					rd, SPLICE_F_MOVE);
			}
			//printf("splice rd=%d wr=%d\n",rd,wr);
		}
	}
	if (data_transferred) *data_transferred = rd < 0 ? 0 : rd;
	return rd != -1 && wr != -1;
}

void remove_closed_connections(struct tailhead *close_list)
{
	tproxy_conn_t *conn = NULL;

	while (close_list->tqh_first != NULL) {
		conn = (tproxy_conn_t*)close_list->tqh_first;
		TAILQ_REMOVE(close_list, close_list->tqh_first, conn_ptrs);

		ssize_t rd = 0;
		while (handle_epollin(conn, &rd) && rd);

		printf("Socket %d and %d closed, connection removed\n",
			conn->local_fd, conn->remote_fd);
		free_conn(conn);
	}
}

void close_tcp_conn(tproxy_conn_t *conn, struct tailhead *conn_list, struct tailhead *close_list)
{
	conn->state = CONN_CLOSED;
	TAILQ_REMOVE(conn_list, conn, conn_ptrs);
	TAILQ_INSERT_TAIL(close_list, conn, conn_ptrs);
}

int event_loop(int listen_fd)
{
	int retval = 0, num_events = 0;
	int tmp_fd = 0; //Used to temporarily hold the accepted file descriptor
	tproxy_conn_t *conn = NULL;
	int efd, i;
	struct epoll_event ev, events[MAX_EPOLL_EVENTS];
	struct tailhead conn_list, close_list;
	uint8_t check_close = 0;
	int conncount = 0;

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
		return -1;
	}

	while (1) {
		if ((num_events = epoll_wait(efd, events, MAX_EPOLL_EVENTS, -1)) == -1) {
			if (errno == EINTR) continue; // system call was interrupted
			perror("epoll_wait");
			retval = -1;
			break;
		}

		dohup();

		for (i = 0; i < num_events; i++) {
			if (events[i].data.ptr == NULL) {
				//Accept new connection
				tmp_fd = accept(listen_fd, NULL, 0);
				if (tmp_fd < 0)
				{
					fprintf(stderr, "Failed to accept connection\n");
				}
				else if (conncount >= params.maxconn)
				{
					close(tmp_fd);
					fprintf(stderr, "Too much connections : %d\n", conncount);
				}
				else if ((conn = add_tcp_connection(efd, &conn_list, tmp_fd, params.port)) == NULL)
				{
					close(tmp_fd);
					fprintf(stderr, "Failed to add connection\n");
				}
				else
				{
					conncount++;
					printf("Connections : %d\n", conncount);
				}
			}
			else {
				conn = (tproxy_conn_t*)events[i].data.ptr;

				//Only applies to remote_fd, connection attempt has
				//succeeded/failed
				if (events[i].events & EPOLLOUT) {
					if (check_connection_attempt(conn, efd) == -1) {
						fprintf(stderr, "Connection attempt failed for %d\n",
							conn->remote_fd);
						check_close = 1;
						close_tcp_conn(conn, &conn_list, &close_list);
						conncount--;
					}
					continue;
				}
				else if (conn->state != CONN_CLOSED &&
					(events[i].events & EPOLLRDHUP ||
						events[i].events & EPOLLHUP ||
						events[i].events & EPOLLERR)) {
					check_close = 1;
					close_tcp_conn(conn, &conn_list, &close_list);
					conncount--;
					continue;
				}

				//Since I use an event cache, earlier events might cause for
				//example this connection to be closed. No need to process fd if
				//that is the case
				if (conn->state == CONN_CLOSED) {
					continue;
				}

				if (!handle_epollin(conn, NULL)) {
					close_tcp_conn(conn, &conn_list, &close_list);
					conncount--;
					check_close = 1;
				}
			}
		}

		//Remove connections
		if (check_close)
			remove_closed_connections(&close_list);

		check_close = 0;
	}

	//Add cleanup
	return retval;
}

int8_t block_sigpipe()
{
	sigset_t sigset;
	memset(&sigset, 0, sizeof(sigset));

	//Get the old sigset, add SIGPIPE and update sigset
	if (sigprocmask(SIG_BLOCK, NULL, &sigset) == -1) {
		perror("sigprocmask (get)");
		return -1;
	}

	if (sigaddset(&sigset, SIGPIPE) == -1) {
		perror("sigaddset");
		return -1;
	}

	if (sigprocmask(SIG_BLOCK, &sigset, NULL) == -1) {
		perror("sigprocmask (set)");
		return -1;
	}

	return 0;
}


bool is_interface_online(const char *ifname)
{
	struct ifreq ifr;
	int sock;
	
	if ((sock=socket(PF_INET, SOCK_DGRAM, IPPROTO_IP))==-1)
		return false;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ] = 0;
	ioctl(sock, SIOCGIFFLAGS, &ifr);
	close(sock);
	return !!(ifr.ifr_flags & IFF_UP);
}


void exithelp()
{
	printf(
		" --bind-addr=<ipv4_addr>|<ipv6_addr>\n"
		" --bind-iface4=<interface_name>\t; bind to the first ipv4 addr of interface\n"
		" --bind-iface6=<interface_name>\t; bind to the first ipv6 addr of interface\n"
		" --bind-linklocal=prefer|force\t; prefer or force ipv6 link local\n"
		" --bind-wait-ifup=<sec>\t\t; wait for interface to appear and up\n"
		" --bind-wait-ip=<sec>\t\t; after ifup wait for ip address to appear up to N seconds\n"
		" --bind-wait-ip-linklocal=<sec>\t; accept only link locals first N seconds then any\n"
		" --port=<port>\n"
		" --maxconn=<max_connections>\n"
		" --hostlist=<filename>\t\t; only act on host in the list (one host per line, subdomains auto apply)\n"
		" --split-http-req=method|host\n"
		" --split-pos=<numeric_offset>\t; split at specified pos. invalidates split-http-req.\n"
		" --hostcase\t\t\t; change Host: => host:\n"
		" --hostspell\t\t\t; exact spelling of \"Host\" header. must be 4 chars. default is \"host\"\n"
		" --hostdot\t\t\t; add \".\" after Host: name\n"
		" --hosttab\t\t\t; add tab after Host: name\n"
		" --hostnospace\t\t\t; remove space after Host:\n"
		" --methodspace\t\t\t; add extra space after method\n"
		" --methodeol\t\t\t; add end-of-line before method\n"
		" --unixeol\t\t\t; replace 0D0A to 0A\n"
		" --daemon\t\t\t; daemonize\n"
		" --pidfile=<filename>\t\t; write pid to file\n"
		" --user=<username>\t\t; drop root privs\n"
		" --uid=uid[:gid]\t\t; drop root privs\n"
	);
	exit(1);
}
void cleanup_params()
{
	if (params.hostlist)
	{
		StrPoolDestroy(&params.hostlist);
		params.hostlist = NULL;
	}
}
void exithelp_clean()
{
	cleanup_params();
	exithelp();
}
void exit_clean(int code)
{
	cleanup_params();
	exit(code);
}
void parse_params(int argc, char *argv[])
{
	int option_index = 0;
	int v, i;

	memset(&params, 0, sizeof(params));
	memcpy(params.hostspell, "host", 4); // default hostspell
	params.maxconn = DEFAULT_MAX_CONN;

	const struct option long_options[] = {
		{ "help",no_argument,0,0 },// optidx=0
		{ "h",no_argument,0,0 },// optidx=1
		{ "bind-addr",required_argument,0,0 },// optidx=2
		{ "bind-iface4",required_argument,0,0 },// optidx=3
		{ "bind-iface6",required_argument,0,0 },// optidx=4
		{ "bind-linklocal",required_argument,0,0 },// optidx=5
		{ "bind-wait-ifup",required_argument,0,0 },// optidx=6
		{ "bind-wait-ip",required_argument,0,0 },// optidx=7
		{ "bind-wait-ip-linklocal",required_argument,0,0 },// optidx=8
		{ "port",required_argument,0,0 },// optidx=9
		{ "daemon",no_argument,0,0 },// optidx=10
		{ "user",required_argument,0,0 },// optidx=11
		{ "uid",required_argument,0,0 },// optidx=12
		{ "maxconn",required_argument,0,0 },// optidx=13
		{ "hostcase",no_argument,0,0 },// optidx=14
		{ "hostspell",required_argument,0,0 },// optidx=15
		{ "hostdot",no_argument,0,0 },// optidx=16
		{ "hostnospace",no_argument,0,0 },// optidx=17
		{ "split-http-req",required_argument,0,0 },// optidx=18
		{ "split-pos",required_argument,0,0 },// optidx=19
		{ "methodspace",no_argument,0,0 },// optidx=20
		{ "methodeol",no_argument,0,0 },// optidx=21
		{ "hosttab",no_argument,0,0 },// optidx=22
		{ "unixeol",no_argument,0,0 },// optidx=23
		{ "hostlist",required_argument,0,0 },// optidx=24
		{ "pidfile",required_argument,0,0 },// optidx=25
		{ NULL,0,NULL,0 }
	};
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp_clean();
		switch (option_index)
		{
		case 0:
		case 1:
			exithelp_clean();
			break;
		case 2: /* bind-addr */
			strncpy(params.bindaddr, optarg, sizeof(params.bindaddr));
			params.bindaddr[sizeof(params.bindaddr) - 1] = 0;
			break;
		case 3: /* bind-iface4 */
			params.bind_if6=false;
			strncpy(params.bindiface, optarg, sizeof(params.bindiface));
			params.bindiface[sizeof(params.bindiface) - 1] = 0;
			break;
		case 4: /* bind-iface6 */
			params.bind_if6=true;
			strncpy(params.bindiface, optarg, sizeof(params.bindiface));
			params.bindiface[sizeof(params.bindiface) - 1] = 0;
			break;
		case 5: /* bind-linklocal */
			params.bindll = true;
			if (!strcmp(optarg, "force"))
				params.bindll_force=true;
			else if (strcmp(optarg, "prefer"))
			{
				fprintf(stderr, "invalid parameter in bind-linklocal : %s\n",optarg);
				exit_clean(1);
			}
			break;
		case 6: /* bind-wait-ifup */
			params.bind_wait_ifup = atoi(optarg);
			break;
		case 7: /* bind-wait-ip */
			params.bind_wait_ip = atoi(optarg);
			break;
		case 8: /* bind-wait-ip-linklocal */
			params.bind_wait_ip_ll = atoi(optarg);
			break;
		case 9: /* port */
			i = atoi(optarg);
			if (i <= 0 || i > 65535)
			{
				fprintf(stderr, "bad port number\n");
				exit_clean(1);
			}
			params.port = (uint16_t)i;
			break;
		case 10: /* daemon */
			params.daemon = true;
			break;
		case 11: /* user */
		{
			struct passwd *pwd = getpwnam(optarg);
			if (!pwd)
			{
				fprintf(stderr, "non-existent username supplied\n");
				exit_clean(1);
			}
			params.uid = pwd->pw_uid;
			params.gid = pwd->pw_gid;
			break;
		}
		case 12: /* uid */
			params.gid=0x7FFFFFFF; // default git. drop gid=0
			if (!sscanf(optarg,"%u:%u",&params.uid,&params.gid))
			{
				fprintf(stderr, "--uid should be : uid[:gid]\n");
				exit_clean(1);
			}
			break;
		case 13: /* maxconn */
			params.maxconn = atoi(optarg);
			if (params.maxconn <= 0)
			{
				fprintf(stderr, "bad maxconn\n");
				exit_clean(1);
			}
			break;
		case 14: /* hostcase */
			params.hostcase = true;
			break;
		case 15: /* hostspell */
			if (strlen(optarg) != 4)
			{
				fprintf(stderr, "hostspell must be exactly 4 chars long\n");
				exit_clean(1);
			}
			params.hostcase = true;
			memcpy(params.hostspell, optarg, 4);
			break;
		case 16: /* hostdot */
			params.hostdot = true;
			break;
		case 17: /* hostnospace */
			params.hostnospace = true;
			break;
		case 18: /* split-http-req */
			if (!strcmp(optarg, "method"))
				params.split_http_req = split_method;
			else if (!strcmp(optarg, "host"))
				params.split_http_req = split_host;
			else
			{
				fprintf(stderr, "Invalid argument for split-http-req\n");
				exit_clean(1);
			}
			break;
		case 19: /* split-pos */
			i = atoi(optarg);
			if (i)
				params.split_pos = i;
			else
			{
				fprintf(stderr, "Invalid argument for split-pos\n");
				exit_clean(1);
			}
			break;
		case 20: /* methodspace */
			params.methodspace = true;
			break;
		case 21: /* methodeol */
			params.methodeol = true;
			break;
		case 22: /* hosttab */
			params.hosttab = true;
			break;
		case 23: /* unixeol */
			params.unixeol = true;
			break;
		case 24: /* hostlist */
			if (!LoadHostList(&params.hostlist, optarg))
				exit_clean(1);
			strncpy(params.hostfile,optarg,sizeof(params.hostfile));
			params.hostfile[sizeof(params.hostfile)-1]='\0';
			break;
		case 25: /* pidfile */
			strncpy(params.pidfile,optarg,sizeof(params.pidfile));
			params.pidfile[sizeof(params.pidfile)-1]='\0';
			break;
		}
	}
	if (!params.port)
	{
		fprintf(stderr, "Need port number\n");
		exit_clean(1);
	}
}

void daemonize()
{
	int pid;

	pid = fork();
	if (pid == -1)
	{
		perror("fork: ");
		exit(2);
	}
	else if (pid != 0)
		exit(0);

	if (setsid() == -1)
		exit(2);
	if (chdir("/") == -1)
		exit(2);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/* redirect fd's 0,1,2 to /dev/null */
	open("/dev/null", O_RDWR);
	/* stdin */
	dup(0);
	/* stdout */
	dup(0);
	/* stderror */
}

bool setpcap(cap_value_t *caps,int ncaps)
{
	cap_t capabilities;
	
	if (!(capabilities = cap_init()))
		return false;
	
	if (ncaps && (cap_set_flag(capabilities, CAP_PERMITTED, ncaps, caps, CAP_SET) ||
		cap_set_flag(capabilities, CAP_EFFECTIVE, ncaps, caps, CAP_SET)))
	{
		cap_free(capabilities);
		return false;
	}
	if (cap_set_proc(capabilities))
	{
		cap_free(capabilities);
		return false;
	}
	cap_free(capabilities);
	return true;
}
int getmaxcap()
{
	int maxcap = CAP_LAST_CAP;
	FILE *F = fopen("/proc/sys/kernel/cap_last_cap","r");
	if (F)
	{
		fscanf(F,"%d",&maxcap);
		fclose(F);
	}
	return maxcap;
	
}
bool dropcaps()
{
	// must have CAP_SETPCAP at the end. its required to clear bounding set
	cap_value_t cap_values[] = {CAP_SETPCAP};
	int capct=sizeof(cap_values)/sizeof(*cap_values);
	int maxcap = getmaxcap();

	if (setpcap(cap_values, capct))
	{
		for(int cap=0;cap<=maxcap;cap++)
		{
			if (cap_drop_bound(cap))
			{
				fprintf(stderr,"could not drop cap %d\n",cap);
				perror("cap_drop_bound");
			}
		}
	}
	// now without CAP_SETPCAP
	if (!setpcap(cap_values, capct - 1))
	{
		perror("setpcap");
		return false;
	}
	return true;
}
bool droproot()
{
	if (params.uid || params.gid)
	{
		if (prctl(PR_SET_KEEPCAPS, 1L))
		{
			perror("prctl(PR_SET_KEEPCAPS): ");
			return false;
		}
		if (setgid(params.gid))
		{
			perror("setgid: ");
			return false;
		}
		if (setuid(params.uid))
		{
			perror("setuid: ");
			return false;
		}
	}
	return dropcaps();
}


bool writepid(const char *filename)
{
	FILE *F;
	if (!(F=fopen(filename,"w")))
		return false;
	fprintf(F,"%d",getpid());
	fclose(F);
	return true;
}



bool find_listen_addr(struct sockaddr_storage *salisten, bool bindll, int *if_index)
{
	struct ifaddrs *addrs,*a;
	bool found=false;
    
	if (getifaddrs(&addrs)<0)
		return false;

	a  = addrs;
	while (a)
	{
		if (a->ifa_addr)
		{
			if (a->ifa_addr->sa_family==AF_INET &&
			    *params.bindiface && !params.bind_if6 && !strcmp(a->ifa_name, params.bindiface))
			{
				salisten->ss_family = AF_INET;
				memcpy(&((struct sockaddr_in*)salisten)->sin_addr, &((struct sockaddr_in*)a->ifa_addr)->sin_addr, sizeof(struct in_addr));
				found=true;
				break;
			}
			// ipv6 links locals are fe80::/10
			else if (a->ifa_addr->sa_family==AF_INET6
			          &&
			         (!*params.bindiface && bindll ||
			          *params.bindiface && params.bind_if6 && !strcmp(a->ifa_name, params.bindiface))
			          &&
				 (!bindll ||
				  ((struct sockaddr_in6*)a->ifa_addr)->sin6_addr.s6_addr[0]==0xFE &&
				  (((struct sockaddr_in6*)a->ifa_addr)->sin6_addr.s6_addr[1] & 0xC0)==0x80))
			{
				salisten->ss_family = AF_INET6;
				memcpy(&((struct sockaddr_in6*)salisten)->sin6_addr, &((struct sockaddr_in6*)a->ifa_addr)->sin6_addr, sizeof(struct in6_addr));
				if (if_index) *if_index = if_nametoindex(a->ifa_name);
				found=true;
				break;
			}
		}
		a = a->ifa_next;
	}
	freeifaddrs(addrs);
	return found;
}


int main(int argc, char *argv[]) {
	int listen_fd = -1;
	int yes = 1, retval = 0;
	int r;
	struct sockaddr_storage salisten;
	socklen_t salisten_len;
	int ipv6_only=0,if_index=0;

	parse_params(argc, argv);

	memset(&salisten, 0, sizeof(salisten));
	if (*params.bindiface)
	{
		if (params.bind_wait_ifup > 0)
		{
			int sec=0;
			if (!is_interface_online(params.bindiface))
			{
				fprintf(stderr,"waiting ifup of %s for up to %d seconds...\n",params.bindiface,params.bind_wait_ifup);
				do
				{
					sleep(1);
					sec++;
				}
				while (!is_interface_online(params.bindiface) && sec<params.bind_wait_ifup);
				if (sec>=params.bind_wait_ifup)
				{
					printf("wait timed out\n");
					goto exiterr;
				}
			}
		}
		if (!(if_index = if_nametoindex(params.bindiface)) && params.bind_wait_ip<=0)
		{
			printf("bad iface %s\n",params.bindiface);
			goto exiterr;
		}
	}
	if (*params.bindaddr)
	{
		if (inet_pton(AF_INET, params.bindaddr, &((struct sockaddr_in*)&salisten)->sin_addr))
		{
			salisten.ss_family = AF_INET;
		}
		else if (inet_pton(AF_INET6, params.bindaddr, &((struct sockaddr_in6*)&salisten)->sin6_addr))
		{
			salisten.ss_family = AF_INET6;
			ipv6_only = 1;
		}
		else
		{
			printf("bad bind addr : %s\n", params.bindaddr);
			goto exiterr;
		}
	}
	else
	{
		if (*params.bindiface || params.bindll)
		{
			bool found;
			int sec=0;
			
			if (params.bind_wait_ip > 0)
			{
				fprintf(stderr,"waiting for ip for %d seconds...\n", params.bind_wait_ip);
				if (params.bindll && !params.bindll_force && params.bind_wait_ip_ll>0)
					fprintf(stderr,"during the first %d seconds accepting only link locals...\n", params.bind_wait_ip_ll);
			}
			
			for(;;)
			{
				found = find_listen_addr(&salisten,params.bindll,&if_index);
				if (found) break;
				
				if (params.bindll && !params.bindll_force && sec>=params.bind_wait_ip_ll)
					if (found = find_listen_addr(&salisten,false,&if_index)) break;
				
				if (sec>=params.bind_wait_ip)
					break;
				
				sleep(1);
				sec++;
			} 

			if (!found)
			{
				printf("suitable ip address not found\n");
				goto exiterr;
			}
			ipv6_only=1;
		}
		else
		{
			salisten.ss_family = AF_INET6;
			// leave sin6_addr zero
		}
	}
	if (salisten.ss_family == AF_INET6)
	{
		salisten_len = sizeof(struct sockaddr_in6);
		((struct sockaddr_in6*)&salisten)->sin6_port = htons(params.port);
		((struct sockaddr_in6*)&salisten)->sin6_scope_id = if_index;
	}
	else
	{
		salisten_len = sizeof(struct sockaddr_in);
		((struct sockaddr_in*)&salisten)->sin_port = htons(params.port);
	}

	if (params.daemon) daemonize();

	if (*params.pidfile && !writepid(params.pidfile))
	{
		fprintf(stderr,"could not write pidfile\n");
		goto exiterr;
	}

	if ((listen_fd = socket(salisten.ss_family, SOCK_STREAM, 0)) == -1) {
		perror("socket: ");
		goto exiterr;
	}

	if ((salisten.ss_family == AF_INET6) && setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, sizeof(ipv6_only)) == -1)
	{
		perror("setsockopt (IPV6_ONLY): ");
		goto exiterr;
	}

	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
	{
		perror("setsockopt (SO_REUSEADDR): ");
		goto exiterr;
	}
	if (setsockopt(listen_fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) == -1)
	{
		perror("setsockopt (SO_KEEPALIVE): ");
		goto exiterr;
	}
	
	//Mark that this socket can be used for transparent proxying
	//This allows the socket to accept connections for non-local IPs
	if (setsockopt(listen_fd, SOL_IP, IP_TRANSPARENT, &yes, sizeof(yes)) == -1)
	{
		perror("setsockopt (IP_TRANSPARENT): ");
		goto exiterr;
	}

	if (bind(listen_fd, (struct sockaddr *)&salisten, salisten_len) == -1) {
		perror("bind: ");
		goto exiterr;
	}

	if (!droproot())
	{
		goto exiterr;
	}
	
	fprintf(stderr,"Running as UID=%u GID=%u\n",getuid(),getgid());

	if (listen(listen_fd, BACKLOG) == -1) {
		perror("listen: ");
		goto exiterr;
	}
	
	//splice() causes the process to receive the SIGPIPE-signal if one part (for
	//example a socket) is closed during splice(). I would rather have splice()
	//fail and return -1, so blocking SIGPIPE.
	if (block_sigpipe() == -1) {
		fprintf(stderr, "Could not block SIGPIPE signal\n");
		goto exiterr;
	}

	fprintf(stderr, "Will listen to port %d\n", params.port);

	signal(SIGHUP, onhup); 

	retval = event_loop(listen_fd);
	
	close(listen_fd);
	cleanup_params();

	fprintf(stderr, "Will exit\n");

	return retval < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
	
exiterr:
	if (listen_fd!=-1) close(listen_fd);
	cleanup_params();
	return EXIT_FAILURE;
}
