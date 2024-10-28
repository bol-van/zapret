#ifndef TIMERFD_CTX_H_
#define TIMERFD_CTX_H_

#include "fix.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <pthread.h>
#include <time.h>

typedef struct {
	int kq; // non owning
	int flags;
	pthread_mutex_t mutex;

	int clockid;
	/*
	 * Next expiration time, absolute (clock given by clockid).
	 * If it_interval is != 0, it is a periodic timer.
	 * If it_value is == 0, the timer is disarmed.
	 */
	struct itimerspec current_itimerspec;
	uint64_t nr_expirations;
} TimerFDCtx;

errno_t timerfd_ctx_init(TimerFDCtx *timerfd, int kq, int clockid);
errno_t timerfd_ctx_terminate(TimerFDCtx *timerfd);

errno_t timerfd_ctx_settime(TimerFDCtx *timerfd, int flags,
    struct itimerspec const *new, struct itimerspec *old);
errno_t timerfd_ctx_gettime(TimerFDCtx *timerfd, struct itimerspec *cur);

errno_t timerfd_ctx_read(TimerFDCtx *timerfd, uint64_t *value);

#endif
