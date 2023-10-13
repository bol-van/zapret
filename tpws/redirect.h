#pragma once

#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>

bool get_dest_addr(int sockfd, const struct sockaddr *accept_sa, struct sockaddr_storage *orig_dst);
bool redir_init(void);
void redir_close(void);
