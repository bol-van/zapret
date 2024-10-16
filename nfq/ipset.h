#pragma once

#include <stdbool.h>
#include <arpa/inet.h>
#include "params.h"
#include "pools.h"

bool LoadIncludeIpsets();
bool LoadExcludeIpsets();
bool SearchIpset(const ipset *ips, const struct in_addr *ipv4, const struct in6_addr *ipv6);
bool IpsetCheck(struct desync_profile *dp, const struct in_addr *ipv4, const struct in6_addr *ipv6);
