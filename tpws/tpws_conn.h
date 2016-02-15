#ifndef TPROXY_TEST_CONN_H
#define TPROXY_TEST_CONN_H

#include "tpws.h"
#include <stdbool.h>

int check_local_ip(const struct sockaddr *saddr);
uint16_t saport(const struct sockaddr *sa);
tproxy_conn_t* add_tcp_connection(int efd, struct tailhead *conn_list, 
        int local_fd, uint16_t listen_port);
void free_conn(tproxy_conn_t *conn);
int8_t check_connection_attempt(tproxy_conn_t *conn, int efd);
#endif
