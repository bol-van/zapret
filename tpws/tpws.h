#pragma once

#ifdef __linux__
 #define SPLICE_PRESENT
#endif

#include <sys/param.h>

void ReloadCheck();
