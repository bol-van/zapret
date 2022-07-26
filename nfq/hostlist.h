#pragma once

#include <stdbool.h>
#include "strpool.h"

bool AppendHostList(strpool **hostlist, char *filename);
bool LoadHostLists(strpool **hostlist, struct str_list_head *file_list);
bool SearchHostList(strpool *hostlist, const char *host);
// return : true = apply fooling, false = do not apply
bool HostlistCheck(strpool *hostlist, strpool *hostlist_exclude, const char *host);
