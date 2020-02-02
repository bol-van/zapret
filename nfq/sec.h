#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/capability.h>

bool setpcap(uint64_t caps);
bool checkpcap(uint64_t caps);
int getmaxcap();
bool dropcaps();
bool droproot(uid_t uid, gid_t gid);
void daemonize();
bool writepid(const char *filename);
