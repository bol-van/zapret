#pragma once

#include <sys/capability.h>
#include <sys/types.h>
#include <stdbool.h>

bool setpcap(cap_value_t *caps, int ncaps);
int getmaxcap();
bool dropcaps();
bool droproot(uid_t uid, gid_t gid);
void daemonize();
bool writepid(const char *filename);
