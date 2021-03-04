#ifndef EVENTFD_CTX_H_
#define EVENTFD_CTX_H_

#include "fix.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <pthread.h>

#define EVENTFD_CTX_FLAG_SEMAPHORE (1 << 0)

typedef struct {
	int kq_; // non owning
	int flags_;
	pthread_mutex_t mutex_;

	bool is_signalled_;
	int self_pipe_[2]; // only used if EVFILT_USER is not available
	uint_least64_t counter_;
} EventFDCtx;

errno_t eventfd_ctx_init(EventFDCtx *eventfd, int kq, unsigned int counter,
    int flags);
errno_t eventfd_ctx_terminate(EventFDCtx *eventfd);

errno_t eventfd_ctx_write(EventFDCtx *eventfd, uint64_t value);
errno_t eventfd_ctx_read(EventFDCtx *eventfd, uint64_t *value);

#endif
