#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include "sec.h"
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>

#ifdef __linux__

#include <sys/prctl.h>

bool checkpcap(uint64_t caps)
{
	if (!caps) return true; // no special caps reqd

	struct __user_cap_header_struct ch = {_LINUX_CAPABILITY_VERSION_3, getpid()};
	struct __user_cap_data_struct cd[2];
	uint32_t c0 = (uint32_t)caps;
	uint32_t c1 = (uint32_t)(caps>>32);

	return !capget(&ch,cd) && (cd[0].effective & c0)==c0 && (cd[1].effective & c1)==c1;
}
bool setpcap(uint64_t caps)
{
	struct __user_cap_header_struct ch = {_LINUX_CAPABILITY_VERSION_3, getpid()};
	struct __user_cap_data_struct cd[2];
	
	cd[0].effective = cd[0].permitted = (uint32_t)caps;
	cd[0].inheritable = 0;
	cd[1].effective = cd[1].permitted = (uint32_t)(caps>>32);
	cd[1].inheritable = 0;

	return !capset(&ch,cd);
}
int getmaxcap()
{
	int maxcap = CAP_LAST_CAP;
	FILE *F = fopen("/proc/sys/kernel/cap_last_cap", "r");
	if (F)
	{
		fscanf(F, "%d", &maxcap);
		fclose(F);
	}
	return maxcap;

}
bool dropcaps()
{
	uint64_t caps = 0;
	int maxcap = getmaxcap();

	if (setpcap(caps|(1<<CAP_SETPCAP)))
	{
		for (int cap = 0; cap <= maxcap; cap++)
		{
			if (prctl(PR_CAPBSET_DROP, cap)<0)
			{
				fprintf(stderr, "could not drop bound cap %d\n", cap);
				perror("cap_drop_bound");
			}
		}
	}
	// now without CAP_SETPCAP
	if (!setpcap(caps))
	{
		perror("setpcap");
		return checkpcap(caps);
	}
	return true;
}
#endif

bool can_drop_root()
{
#ifdef __linux__
	// has some caps
	return checkpcap((1<<CAP_SETUID)|(1<<CAP_SETGID)|(1<<CAP_SETPCAP));
#else
	// effective root
	return !geteuid();
#endif
}

bool droproot(uid_t uid, gid_t gid)
{
#ifdef __linux__
	if (prctl(PR_SET_KEEPCAPS, 1L))
	{
		perror("prctl(PR_SET_KEEPCAPS)");
		return false;
	}
#endif
	// drop all SGIDs
	if (setgroups(0,NULL))
	{
		perror("setgroups");
		return false;
	}
	if (setgid(gid))
	{
		perror("setgid");
		return false;
	}
	if (setuid(uid))
	{
		perror("setuid");
		return false;
	}
#ifdef __linux__
	return dropcaps();
#else
	return true;
#endif
}

void print_id()
{
 int i,N;
 gid_t g[128];
 printf("Running as UID=%u GID=",getuid());
 N=getgroups(sizeof(g)/sizeof(*g),g);
 if (N>0)
 {
	for(i=0;i<N;i++)
		printf(i==(N-1) ? "%u" : "%u,", g[i]);
	printf("\n");
 }
 else
	printf("%u\n",getgid());
}

void daemonize()
{
	int pid;

	pid = fork();
	if (pid == -1)
	{
		perror("fork");
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
	int fd;
	/* stdin */
	fd = dup(0);
	/* stdout */
	fd = dup(0);
	/* stderror */
}

bool writepid(const char *filename)
{
	FILE *F;
	if (!(F = fopen(filename, "w")))
		return false;
	fprintf(F, "%d", getpid());
	fclose(F);
	return true;
}
