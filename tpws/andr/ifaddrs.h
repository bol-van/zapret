#pragma once

#include <ifaddrs.h>

#if __ANDROID_API__ < 24
void freeifaddrs(struct ifaddrs *);
int getifaddrs(struct ifaddrs **);
#endif
