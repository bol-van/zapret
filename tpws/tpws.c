#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
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

#include "tpws.h"
#include "tpws_conn.h"

enum splithttpreq { split_none = 0, split_method, split_host };

struct params_s
{
	char bindaddr[64];
	uid_t uid;
	gid_t gid;
	uint16_t port;
	bool daemon;
	bool hostcase, hostdot, hosttab, hostnospace, methodspace, methodeol, unixeol;
	char hostspell[4];
	enum splithttpreq split_http_req;
	int split_pos;
	int maxconn;
};

struct params_s params;

unsigned char *find_bin(void *data, ssize_t len, const void *blk, ssize_t blk_len)
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

ssize_t send_with_flush(int sockfd, const void *buf, size_t len, int flags)
{
	int flag, err;
	ssize_t wr;

	flag = 1;
	setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	wr = send(sockfd, buf, len, flags);
	err = errno;
	flag = 0;
	setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	errno = err;
	return wr;
}

void close_tcp_conn(tproxy_conn_t *conn, struct tailhead *conn_list,
	struct tailhead *close_list) {
	conn->state = CONN_CLOSED;
	TAILQ_REMOVE(conn_list, conn, conn_ptrs);
	TAILQ_INSERT_TAIL(close_list, conn, conn_ptrs);
}

static const char *http_methods[] = { "GET /","POST /","HEAD /","OPTIONS /","PUT /","DELETE /","CONNECT /","TRACE /",NULL };

#define RD_BLOCK_SIZE 8192

bool handle_epollin(tproxy_conn_t *conn, int *data_transferred) {
	int numbytes;
	int fd_in, fd_out;
	bool bOutgoing;
	ssize_t rd = 0, wr = 0, bs;

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
				char *p, *pp, *pHost=NULL;
				ssize_t method_len=0, split_pos=0, pos;
				const char **method;
				bool bIsHttp=false;
				char bRemovedHostSpace=0;

				bs = rd;

				for (method = http_methods; *method; method++)
				{
					method_len = strlen(*method);
					if (method_len <= bs && !memcmp(buf, *method, method_len))
					{
						bIsHttp = true;
						method_len-=2; // "GET /" => "GET"
						break;
					}
				}
				if (bIsHttp)
				{
					printf("Data block looks like http request start : %s\n", *method);

					if (params.unixeol)
					{
						p = pp = buf;
						while (p = find_bin(p, buf + bs - p, "\r\n", 2))
						{
							*p = '\n'; p++;
							memmove(p, p + 1, buf + bs - p - 1);
							bs--;
							if (pp == (p - 1))
							{
								// probably end of http headers
								printf("Found double EOL at pos %zd. Stop replacing.\n", pp - buf);
								break;
							}
							pp = p;
						}
					}

					if (params.methodspace)
					{
						// we only work with data blocks looking as HTTP query, so method is at the beginning
						printf("Adding extra space after method\n");
						p = buf + method_len + 1;
						pos = method_len + 1;
						memmove(p + 1, p, bs - pos);
						*p = ' '; // insert extra space
						bs++; // block will grow by 1 byte
					}

					// search for Host only if required (save some CPU)
					if (params.hostdot || params.hosttab || params.hostcase || params.hostnospace || params.split_http_req==split_host)
					{
						// we need Host: location
						pHost=find_bin(buf, bs, "\nHost: ", 7);
						if (pHost) pHost++;
					}

					if (pHost && params.hostdot || params.hosttab)
					{
						p = pHost + 6;
						while (p < (buf + bs) && *p != '\r' && *p != '\n') p++;
						if (p < (buf + bs))
						{
							pos = p - buf;
							printf("Adding %s to host name at pos %zd\n", params.hostdot ? "dot" : "tab", pos);
							memmove(p + 1, p, bs - pos);
							*p = params.hostdot ? '.' : '\t'; // insert dot or tab
							bs++; // block will grow by 1 byte
						}
					}

					if (pHost && params.hostnospace && pHost[5]==' ')
					{
						p = pHost + 6;
						pos = p - buf;
						printf("Removing space before host name at pos %zd\n", pos);
						memmove(p - 1, p, bs - pos);
                                                bs--; // block will shrink by 1 byte
                                                bRemovedHostSpace=1;
					}

					if (params.split_pos)
					{
						split_pos = params.split_pos < bs ? params.split_pos : 0;
					}
					else
					{
						switch (params.split_http_req)
						{
						case split_method:
							split_pos = method_len - 1;
							break;
						case split_host:
							if (pHost)
								split_pos = pHost + 6 - bRemovedHostSpace - buf;
							break;
						}
					}

					if (params.hostcase)
					{
						if (pHost)
						{
							printf("Changing 'Host:' => '%c%c%c%c:' at pos %zd\n", params.hostspell[0], params.hostspell[1], params.hostspell[2], params.hostspell[3], pHost - buf);
							memcpy(pHost, params.hostspell, 4);
						}
					}

					if (params.methodeol)
					{
						printf("Adding EOL before method\n");
						if (params.unixeol)
						{
							memmove(buf + 1, buf, bs);
							bs++;;
							buf[0] = '\n';
							if (split_pos) split_pos++;
						}
						else
						{
							memmove(buf + 2, buf, bs);
							bs += 2;
							buf[0] = '\r';
							buf[1] = '\n';
							if (split_pos) split_pos += 2;
						}
					}
				}
				else
				{
					printf("Data block does not look like http request start\n");

					// this is the only parameter applicable to non-http block (may be https ?)
					if (params.split_pos<bs) split_pos = params.split_pos;
				}

				if (split_pos)
				{
					printf("Splitting at pos %zd\n", split_pos);
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

void remove_closed_connections(struct tailhead *close_list) {
	tproxy_conn_t *conn = NULL;

	while (close_list->tqh_first != NULL) {
		conn = (tproxy_conn_t*)close_list->tqh_first;
		TAILQ_REMOVE(close_list, close_list->tqh_first, conn_ptrs);

		int rd = 0;
		while (handle_epollin(conn, &rd) && rd);

		printf("Socket %d and %d closed, connection removed\n",
			conn->local_fd, conn->remote_fd);
		free_conn(conn);
	}
}

int event_loop(int listen_fd) {
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
			if (errno==EINTR) continue; // system call was interrupted
			perror("epoll_wait");
			retval = -1;
			break;
		}

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

int8_t block_sigpipe() {
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

void exithelp()
{
	printf(
          " --bind-addr=<ipv4_addr>|<ipv6_addr>\n"
          " --port=<port>\n --maxconn=<max_connections>\n"
          " --split-http-req=method|host\n"
          " --split-pos=<numeric_offset>\t; split at specified pos. invalidates split-http-req.\n"
          " --hostcase\t\t; change Host: => host:\n"
          " --hostspell\t\t; exact spelling of \"Host\" header. must be 4 chars. default is \"host\"\n"
          " --hostdot\t\t; add \".\" after Host: name\n"
          " --hosttab\t\t; add tab after Host: name\n"
          " --hostnospace\t\t; remove space after Host:\n"
          " --methodspace\t\t; add extra space after method\n"
          " --methodeol\t\t; add end-of-line before method\n"
          " --unixeol\t\t; replace 0D0A to 0A\n"
          " --daemon\t\t; daemonize\n"
          " --user=<username>\t; drop root privs\n"
        );
	exit(1);
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
		{ "port",required_argument,0,0 },// optidx=3
		{ "daemon",no_argument,0,0 },// optidx=4
		{ "user",required_argument,0,0 },// optidx=5
		{ "maxconn",required_argument,0,0 },// optidx=6
		{ "hostcase",no_argument,0,0 },// optidx=7
		{ "hostspell",required_argument,0,0 },// optidx=8
		{ "hostdot",no_argument,0,0 },// optidx=9
		{ "hostnospace",no_argument,0,0 },// optidx=10
		{ "split-http-req",required_argument,0,0 },// optidx=11
		{ "split-pos",required_argument,0,0 },// optidx=12
		{ "methodspace",no_argument,0,0 },// optidx=13
		{ "methodeol",no_argument,0,0 },// optidx=14
		{ "hosttab",no_argument,0,0 },// optidx=15
		{ "unixeol",no_argument,0,0 },// optidx=16
		{ NULL,0,NULL,0 }
	};
	while ((v = getopt_long_only(argc, argv, "", long_options, &option_index)) != -1)
	{
		if (v) exithelp();
		switch (option_index)
		{
		case 0:
		case 1:
			exithelp();
			break;
		case 2: /* bind-addr */
			strncpy(params.bindaddr, optarg, sizeof(params.bindaddr));
			params.bindaddr[sizeof(params.bindaddr) - 1] = 0;
			break;
		case 3: /* qnum */
			i = atoi(optarg);
			if (i <= 0 || i > 65535)
			{
				fprintf(stderr, "bad port number\n");
				exit(1);
			}
			params.port = (uint16_t)i;
			break;
		case 4: /* daemon */
			params.daemon = true;
			break;
		case 5: /* user */
		{
			struct passwd *pwd = getpwnam(optarg);
			if (!pwd)
			{
				fprintf(stderr, "non-existent username supplied\n");
				exit(1);
			}
			params.uid = pwd->pw_uid;
			params.gid = pwd->pw_gid;
			break;
		}
		case 6: /* maxconn */
			params.maxconn = atoi(optarg);
			if (params.maxconn <= 0)
			{
				fprintf(stderr, "bad maxconn\n");
				exit(1);
			}
			break;
		case 7: /* hostcase */
			params.hostcase = true;
			break;
		case 8: /* hostspell */
			if (strlen(optarg) != 4)
			{
				fprintf(stdout, "hostspell must be exactly 4 chars long\n");
				exit(1);
			}
			params.hostcase = true;
			memcpy(params.hostspell, optarg, 4);
			break;
		case 9: /* hostdot */
			params.hostdot = true;
			break;
		case 10: /* hostnospace */
			params.hostnospace = true;
			break;
		case 11: /* split-http-req */
			if (!strcmp(optarg, "method"))
				params.split_http_req = split_method;
			else if (!strcmp(optarg, "host"))
				params.split_http_req = split_host;
			else
			{
				fprintf(stderr, "Invalid argument for split-http-req\n");
				exit(1);
			}
			break;
		case 12: /* split-pos */
			i = atoi(optarg);
			if (i)
				params.split_pos = i;
			else
			{
				fprintf(stderr, "Invalid argument for split-pos\n");
				exit(1);
			}
			break;
		case 13: /* methodspace */
			params.methodspace = true;
			break;
		case 14: /* methodeol */
			params.methodeol = true;
			break;
		case 15: /* hosttab */
			params.hosttab = true;
			break;
		case 16: /* unixeol */
			params.unixeol = true;
			break;
		}
	}
	if (!params.port)
	{
		fprintf(stderr, "Need port number\n");
		exit(1);
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

bool droproot()
{
	if (params.uid)
	{
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
	return true;
}

int main(int argc, char *argv[]) {
	int listen_fd = 0;
	int yes = 1, retval = 0;
	int r;
	struct sockaddr_storage salisten;
	socklen_t salisten_len;
	int ipv6_only;

	parse_params(argc, argv);

	memset(&salisten, 0, sizeof(salisten));
	if (*params.bindaddr)
	{
		if (inet_pton(AF_INET, params.bindaddr, &((struct sockaddr_in*)&salisten)->sin_addr))
		{
			salisten.ss_family = AF_INET;
			((struct sockaddr_in*)&salisten)->sin_port = htons(params.port);
			salisten_len = sizeof(struct sockaddr_in);
		}
		else if (inet_pton(AF_INET6, params.bindaddr, &((struct sockaddr_in6*)&salisten)->sin6_addr))
		{
			salisten.ss_family = AF_INET6;
			((struct sockaddr_in6*)&salisten)->sin6_port = htons(params.port);
			salisten_len = sizeof(struct sockaddr_in6);
			ipv6_only = 1;
		}
		else
		{
			printf("bad bind addr\n");
			exit(1);
		}
	}
	else
	{
		salisten.ss_family = AF_INET6;
		((struct sockaddr_in6*)&salisten)->sin6_port = htons(params.port);
		salisten_len = sizeof(struct sockaddr_in6);
		ipv6_only = 0;
		// leave sin6_addr zero
	}

	if (params.daemon) daemonize();

	if ((listen_fd = socket(salisten.ss_family, SOCK_STREAM, 0)) == -1) {
		perror("socket: ");
		exit(EXIT_FAILURE);
	}

	if ((salisten.ss_family == AF_INET6) && setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, sizeof(ipv6_only)) == -1)
	{
		perror("setsockopt (IPV6_ONLY): ");
		close(listen_fd);
		exit(EXIT_FAILURE);
	}

	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
	{
		perror("setsockopt (SO_REUSEADDR): ");
		close(listen_fd);
		exit(EXIT_FAILURE);
	}
	if (setsockopt(listen_fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) == -1)
	{
		perror("setsockopt (SO_KEEPALIVE): ");
		close(listen_fd);
		exit(EXIT_FAILURE);
	}

	//Mark that this socket can be used for transparent proxying
	//This allows the socket to accept connections for non-local IPs
	if (setsockopt(listen_fd, SOL_IP, IP_TRANSPARENT, &yes, sizeof(yes)) == -1)
	{
		perror("setsockopt (IP_TRANSPARENT): ");
		close(listen_fd);
		exit(EXIT_FAILURE);
	}

	if (!droproot())
	{
		close(listen_fd);
		exit(EXIT_FAILURE);
	}

	if (bind(listen_fd, (struct sockaddr *)&salisten, salisten_len) == -1) {
		perror("bind: ");
		close(listen_fd);
		exit(EXIT_FAILURE);
	}

	if (listen(listen_fd, BACKLOG) == -1) {
		perror("listen: ");
		close(listen_fd);
		exit(EXIT_FAILURE);
	}

	//splice() causes the process to receive the SIGPIPE-signal if one part (for
	//example a socket) is closed during splice(). I would rather have splice()
	//fail and return -1, so blocking SIGPIPE.
	if (block_sigpipe() == -1) {
		fprintf(stderr, "Could not block SIGPIPE signal\n");
		close(listen_fd);
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Will listen to port %d\n", params.port);

	retval = event_loop(listen_fd);
	close(listen_fd);

	fprintf(stderr, "Will exit\n");

	if (retval < 0)
		exit(EXIT_FAILURE);
	else
		exit(EXIT_SUCCESS);
}
