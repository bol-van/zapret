#include <stdio.h>
#include <stdlib.h>
#include "sec.h"
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>

bool setpcap(cap_value_t *caps, int ncaps)
{
	cap_t capabilities;

	if (!(capabilities = cap_init()))
		return false;

	if (ncaps && (cap_set_flag(capabilities, CAP_PERMITTED, ncaps, caps, CAP_SET) ||
		cap_set_flag(capabilities, CAP_EFFECTIVE, ncaps, caps, CAP_SET)))
	{
		cap_free(capabilities);
		return false;
	}
	if (cap_set_proc(capabilities))
	{
		cap_free(capabilities);
		return false;
	}
	cap_free(capabilities);
	return true;
}
int getmaxcap()
{
	int maxcap = CAP_LAST_CAP;
	FILE *F = fopen("/proc/sys/kernel/cap_last_cap", "r");
	if (F)
	{
		int n = fscanf(F, "%d", &maxcap);
		fclose(F);
	}
	return maxcap;

}
bool dropcaps()
{
	// must have CAP_SETPCAP at the end. its required to clear bounding set
	cap_value_t cap_values[] = { CAP_NET_ADMIN,CAP_NET_RAW,CAP_SETPCAP };
	int capct = sizeof(cap_values) / sizeof(*cap_values);
	int maxcap = getmaxcap();

	if (setpcap(cap_values, capct))
	{
		for (int cap = 0; cap <= maxcap; cap++)
		{
			if (cap_drop_bound(cap))
			{
				fprintf(stderr, "could not drop cap %d\n", cap);
				perror("cap_drop_bound");
			}
		}
	}
	// now without CAP_SETPCAP
	if (!setpcap(cap_values, capct - 1))
	{
		perror("setpcap");
		return false;
	}
	return true;
}
bool droproot(uid_t uid, gid_t gid)
{
	if (uid || gid)
	{
		if (prctl(PR_SET_KEEPCAPS, 1L))
		{
			perror("prctl(PR_SET_KEEPCAPS): ");
			return false;
		}
		if (setgid(gid))
		{
			perror("setgid: ");
			return false;
		}
		if (setuid(uid))
		{
			perror("setuid: ");
			return false;
		}
	}
	return dropcaps();
}

void daemonize()
{
	int pid;

	pid = fork();
	if (pid == -1)
	{
		perror("fork: ");
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
