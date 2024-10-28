#pragma once

#ifndef _ERRNO_T_DEFINED
#define _ERRNO_T_DEFINED
typedef int errno_t;
#endif

#ifdef __APPLE__

#include <time.h>
#include <signal.h>
#include <poll.h>

struct itimerspec {
        struct timespec  it_interval;
        struct timespec  it_value;
};
int ppoll(struct pollfd *fds, nfds_t nfds,const struct timespec *tmo_p, const sigset_t *sigmask);

#endif
