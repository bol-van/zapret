#define _GNU_SOURCE

#include "resolver.h"
#include "params.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <semaphore.h>
#include <fcntl.h> 
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include <errno.h>
#include <unistd.h>

#define SIG_BREAK SIGUSR1

#ifdef __APPLE__
	static const char *sem_name="/tpws_resolver";
#endif

TAILQ_HEAD(resolve_tailhead, resolve_item);

typedef struct
{
	int fd_signal_pipe;
	sem_t *sem;
#ifndef __APPLE__
	sem_t _sem;
#endif
	struct resolve_tailhead resolve_list;
	pthread_mutex_t resolve_list_lock;
	int threads;
	pthread_t *thread;
	bool bInit, bStop;
} t_resolver;
static t_resolver resolver = { .bInit = false };

#define rlist_lock pthread_mutex_lock(&resolver.resolve_list_lock)
#define rlist_unlock pthread_mutex_unlock(&resolver.resolve_list_lock)

static void resolver_clear_list(void)
{
	struct resolve_item *ri;

	for (;;)
	{
		ri = TAILQ_FIRST(&resolver.resolve_list);
		if (!ri) break;
		TAILQ_REMOVE(&resolver.resolve_list, ri, next);
		free(ri);
	}
}

int resolver_thread_count(void)
{
	return resolver.bInit ? resolver.threads : 0;
}
 
static void *resolver_thread(void *arg)
{
	int r;
	sigset_t signal_mask;

	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIG_BREAK);

	//printf("resolver_thread %d start\n",syscall(SYS_gettid));
	for(;;)
	{
		if (resolver.bStop) break;
		r = sem_wait(resolver.sem);
		if (resolver.bStop) break;
		if (r)
		{
			if (errno!=EINTR)
			{
				DLOG_PERROR("sem_wait (resolver_thread)");
				break; // fatal err
			}
		}
		else
		{
			struct resolve_item *ri;
			ssize_t wr;

			rlist_lock;
			ri = TAILQ_FIRST(&resolver.resolve_list);
			if (ri) TAILQ_REMOVE(&resolver.resolve_list, ri, next);
			rlist_unlock;

			if (ri)
			{
				struct addrinfo *ai,hints;
				char sport[6];

				//printf("THREAD %d GOT JOB %s\n", syscall(SYS_gettid), ri->dom);
				snprintf(sport,sizeof(sport),"%u",ri->port);
				memset(&hints, 0, sizeof(struct addrinfo));
				hints.ai_socktype = SOCK_STREAM;
				// unfortunately getaddrinfo cannot be interrupted with a signal. we cannot cancel a query
				ri->ga_res = getaddrinfo(ri->dom,sport,&hints,&ai);
				if (!ri->ga_res)
				{
					if (ai->ai_addrlen>sizeof(ri->ss))
					{
						DLOG_ERR("getaddrinfo returned too large address\n");
						ri->ga_res = EAI_FAIL;
					}
					else
						memcpy(&ri->ss, ai->ai_addr, ai->ai_addrlen);
					freeaddrinfo(ai);
				}
				//printf("THREAD %d END JOB %s  FIRST=%p\n", syscall(SYS_gettid), ri->dom, TAILQ_FIRST(&resolver.resolve_list));

				// never interrupt this
				pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
				wr = write(resolver.fd_signal_pipe,&ri,sizeof(void*));
				if (wr<0)
				{
					free(ri);
					DLOG_PERROR("write resolve_pipe");
				}
				else if (wr!=sizeof(void*))
				{
					// partial pointer write is FATAL. in any case it will cause pointer corruption and coredump
					free(ri);
					DLOG_ERR("write resolve_pipe : not full write\n");
					exit(1000);
				}
				pthread_sigmask(SIG_UNBLOCK, &signal_mask, NULL);
			}
		}
	}
	//printf("resolver_thread %d exit\n",syscall(SYS_gettid));
	return NULL;
}

static void sigbreak(int sig)
{
}

void resolver_deinit(void)
{
	if (resolver.bInit)
	{
		resolver.bStop = true;

		// wait all threads to terminate
		for (int t = 0; t < resolver.threads; t++)
			pthread_kill(resolver.thread[t], SIGUSR1);
		for (int t = 0; t < resolver.threads; t++)
		{
			pthread_kill(resolver.thread[t], SIGUSR1);
			pthread_join(resolver.thread[t], NULL);
		}
	
		pthread_mutex_destroy(&resolver.resolve_list_lock);
		free(resolver.thread);

		#ifdef __APPLE__
			sem_close(resolver.sem);
		#else
			sem_destroy(resolver.sem);
		#endif

		resolver_clear_list();

		memset(&resolver,0,sizeof(resolver));
	}
}

bool resolver_init(int threads, int fd_signal_pipe)
{
	int t;
	struct sigaction action;

	if (threads<1 || resolver.bInit) return false;

	memset(&resolver,0,sizeof(resolver));
	resolver.bInit = true;

#ifdef __APPLE__
	// MacOS does not support unnamed semaphores

	char sn[64];
	snprintf(sn,sizeof(sn),"%s_%d",sem_name,getpid());
	resolver.sem = sem_open(sn,O_CREAT,0600,0);
	if (resolver.sem==SEM_FAILED)
	{
		DLOG_PERROR("sem_open");
		goto ex;
	}
	// unlink immediately to remove tails
	sem_unlink(sn);
#else
	if (sem_init(&resolver._sem,0,0)==-1)
	{	
		DLOG_PERROR("sem_init");
		goto ex;
	}
	resolver.sem = &resolver._sem;
#endif

	if (pthread_mutex_init(&resolver.resolve_list_lock, NULL)) goto ex;

	resolver.fd_signal_pipe = fd_signal_pipe;
	TAILQ_INIT(&resolver.resolve_list);

	// start as many threads as we can up to specified number
	resolver.thread = malloc(sizeof(pthread_t)*threads);
	if (!resolver.thread) goto ex;

	memset(&action,0,sizeof(action));
	action.sa_handler = sigbreak;
	sigaction(SIG_BREAK, &action, NULL);


	pthread_attr_t attr;
	if (pthread_attr_init(&attr)) goto ex;
	// set minimum thread stack size

	if (pthread_attr_setstacksize(&attr,PTHREAD_STACK_MIN>32768 ? PTHREAD_STACK_MIN : 32768))
	{
		pthread_attr_destroy(&attr);
		goto ex;
	}

	for(t=0, resolver.threads=threads ; t<threads ; t++)
	{
		if (pthread_create(resolver.thread + t, &attr, resolver_thread, NULL))
		{
			resolver.threads=t;
			break;
		}
	}
	pthread_attr_destroy(&attr);
	if (!resolver.threads) goto ex;

	return true;

ex:
	resolver_deinit();
	return false;
}



struct resolve_item *resolver_queue(const char *dom, uint16_t port, void *ptr)
{
	struct resolve_item *ri = calloc(1,sizeof(struct resolve_item));
	if (!ri) return NULL;

	strncpy(ri->dom,dom,sizeof(ri->dom));
	ri->dom[sizeof(ri->dom)-1] = 0;
	ri->port = port;
	ri->ptr = ptr;

	rlist_lock;
	TAILQ_INSERT_TAIL(&resolver.resolve_list, ri, next);
	rlist_unlock;
	if (sem_post(resolver.sem)<0)
	{
		DLOG_PERROR("resolver_queue sem_post");
		free(ri);
		return NULL;
	}
	return ri;
}
