#ifndef EPOLL_SHIM_CTX_H_
#define EPOLL_SHIM_CTX_H_

#include "fix.h"

#include <sys/tree.h>

#include <unistd.h>

#include "epollfd_ctx.h"
#include "eventfd_ctx.h"
#include "signalfd_ctx.h"
#include "timerfd_ctx.h"

struct fd_context_map_node_;
typedef struct fd_context_map_node_ FDContextMapNode;

typedef errno_t (*fd_context_read_fun)(FDContextMapNode *node, /**/
    void *buf, size_t nbytes, size_t *bytes_transferred);
typedef errno_t (*fd_context_write_fun)(FDContextMapNode *node, /**/
    const void *buf, size_t nbytes, size_t *bytes_transferred);
typedef errno_t (*fd_context_close_fun)(FDContextMapNode *node);

typedef struct {
	fd_context_read_fun read_fun;
	fd_context_write_fun write_fun;
	fd_context_close_fun close_fun;
} FDContextVTable;

errno_t fd_context_default_read(FDContextMapNode *node, /**/
    void *buf, size_t nbytes, size_t *bytes_transferred);
errno_t fd_context_default_write(FDContextMapNode *node, /**/
    void const *buf, size_t nbytes, size_t *bytes_transferred);

struct fd_context_map_node_ {
	RB_ENTRY(fd_context_map_node_) entry;
	int fd;
	int flags;
	union {
		EpollFDCtx epollfd;
		EventFDCtx eventfd;
		TimerFDCtx timerfd;
		SignalFDCtx signalfd;
	} ctx;
	FDContextVTable const *vtable;
};

errno_t fd_context_map_node_destroy(FDContextMapNode *node);

/**/

typedef RB_HEAD(fd_context_map_, fd_context_map_node_) FDContextMap;

typedef struct {
	FDContextMap fd_context_map;
	pthread_mutex_t mutex;
} EpollShimCtx;

extern EpollShimCtx epoll_shim_ctx;

FDContextMapNode *epoll_shim_ctx_create_node(EpollShimCtx *epoll_shim_ctx,
    errno_t *ec);
FDContextMapNode *epoll_shim_ctx_find_node(EpollShimCtx *epoll_shim_ctx,
    int fd);
FDContextMapNode *epoll_shim_ctx_remove_node(EpollShimCtx *epoll_shim_ctx,
    int fd);
void epoll_shim_ctx_remove_node_explicit(EpollShimCtx *epoll_shim_ctx,
    FDContextMapNode *node);

/**/

int epoll_shim_close(int fd);
ssize_t epoll_shim_read(int fd, void *buf, size_t nbytes);
ssize_t epoll_shim_write(int fd, void const *buf, size_t nbytes);

#endif
