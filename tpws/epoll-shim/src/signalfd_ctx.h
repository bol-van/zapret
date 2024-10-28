#ifndef SIGNALFD_CTX_H_
#define SIGNALFD_CTX_H_

#include "fix.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	int kq; // non owning
} SignalFDCtx;

errno_t signalfd_ctx_init(SignalFDCtx *signalfd, int kq, const sigset_t *sigs);
errno_t signalfd_ctx_terminate(SignalFDCtx *signalfd);

errno_t signalfd_ctx_read(SignalFDCtx *signalfd, uint32_t *ident);

#endif
