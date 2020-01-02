#pragma once

#include <stdbool.h>
#include "strpool.h"

bool LoadHostList(strpool **hostlist, char *filename);
bool SearchHostList(strpool *hostlist, const char *host);
