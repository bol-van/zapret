#pragma once

#include <sys/capability.h>
#include <sys/types.h>
#include <stdbool.h>

bool setpcap(uint64_t caps);
int getmaxcap();
bool dropcaps();
bool droproot(uid_t uid, gid_t gid);
void daemonize();
bool writepid(const char *filename);
