#ifndef	SHIM_SYS_EPOLL_H
#define	SHIM_SYS_EPOLL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>

#if defined(__NetBSD__)
#include <sys/sigtypes.h>
#elif defined(__OpenBSD__) || defined(__DragonFly__) || defined(__FreeBSD__) || defined(__APPLE__)
#include <sys/signal.h>
#endif

#define EPOLL_CLOEXEC O_CLOEXEC
#define EPOLL_NONBLOCK O_NONBLOCK

enum EPOLL_EVENTS { __EPOLL_DUMMY };
#define EPOLLIN 0x001
#define EPOLLPRI 0x002
#define EPOLLOUT 0x004
#define EPOLLRDNORM 0x040
#define EPOLLNVAL 0x020
#define EPOLLRDBAND 0x080
#define EPOLLWRNORM 0x100
#define EPOLLWRBAND 0x200
#define EPOLLMSG 0x400
#define EPOLLERR 0x008
#define EPOLLHUP 0x010
#define EPOLLRDHUP 0x2000
#define EPOLLEXCLUSIVE (1U<<28)
#define EPOLLWAKEUP (1U<<29)
#define EPOLLONESHOT (1U<<30)
#define EPOLLET (1U<<31)

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

typedef union epoll_data {
	void *ptr;
	int fd;
	uint32_t u32;
	uint64_t u64;
} epoll_data_t;

struct epoll_event {
	uint32_t events;
	epoll_data_t data;
}
#ifdef __x86_64__
__attribute__ ((__packed__))
#endif
;


int epoll_create(int);
int epoll_create1(int);
int epoll_ctl(int, int, int, struct epoll_event *);
int epoll_wait(int, struct epoll_event *, int, int);
int epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *);


#ifndef SHIM_SYS_SHIM_HELPERS
#define SHIM_SYS_SHIM_HELPERS
#include <unistd.h> /* IWYU pragma: keep */

extern int epoll_shim_close(int);
#define close epoll_shim_close
#endif


#ifdef __cplusplus
}
#endif

#endif /* sys/epoll.h */
