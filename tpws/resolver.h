#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netdb.h>

#include "helpers.h"

struct resolve_item
{
	char dom[256];	// request dom
	sockaddr_in46 ss; // resolve result
	int ga_res;	// getaddrinfo result code
	uint16_t port;	// request port
	void *ptr;
	TAILQ_ENTRY(resolve_item) next;
};

struct resolve_item *resolver_queue(const char *dom, uint16_t port, void *ptr);
void resolver_deinit(void);
bool resolver_init(int threads, int fd_signal_pipe);
int resolver_thread_count(void);
