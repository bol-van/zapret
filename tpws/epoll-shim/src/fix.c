#include "fix.h"

#ifdef __APPLE__

#include <errno.h>

int ppoll(struct pollfd *fds, nfds_t nfds,const struct timespec *tmo_p, const sigset_t *sigmask)
{
	// macos does not implement ppoll
	// this is a hacky ppoll shim. only for tpws which does not require sigmask
	if (sigmask)
	{
		errno = EINVAL;
		return -1;
	}
	return poll(fds,nfds,tmo_p ? tmo_p->tv_sec*1000 + tmo_p->tv_nsec/1000000 : -1);
}

#endif
