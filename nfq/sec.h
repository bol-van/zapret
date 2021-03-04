#pragma once

#include <sys/types.h>
#include <stdbool.h>

#ifdef __linux__

#include <sys/capability.h>

bool checkpcap(uint64_t caps);
bool setpcap(uint64_t caps);
int getmaxcap();
bool dropcaps();
#endif

bool can_drop_root();
bool droproot(uid_t uid, gid_t gid);
void print_id();
void daemonize();
bool writepid(const char *filename);
