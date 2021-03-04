#pragma once

#include <stdint.h>
#include <arpa/inet.h>

#pragma pack(push,1)

#define S4_CMD_CONNECT		1
#define S4_CMD_BIND		2
typedef struct
{
	uint8_t ver,cmd;
	uint16_t port;
	uint32_t ip;
} s4_req;
#define S4_REQ_HEADER_VALID(r,l) (l>=sizeof(s4_req) && r->ver==4)
#define S4_REQ_CONNECT_VALID(r,l) (S4_REQ_HEADER_VALID(r,l) && r->cmd==S4_CMD_CONNECT)

#define S4_REP_OK		90
#define S4_REP_FAILED		91
typedef struct
{
	uint8_t zero,rep;
	uint16_t port;
	uint32_t ip;
} s4_rep;



#define S5_AUTH_NONE		0
#define S5_AUTH_GSSAPI		1
#define S5_AUTH_USERPASS	2
#define S5_AUTH_UNACCEPTABLE	0xFF
typedef struct
{
	uint8_t ver,nmethods,methods[255];
} s5_handshake;
#define S5_REQ_HANDHSHAKE_VALID(r,l) (l>=3 && r->ver==5 && r->nmethods && l>=(2+r->nmethods))
typedef struct
{
	uint8_t ver,method;
} s5_handshake_ack;

#define S5_CMD_CONNECT		1
#define S5_CMD_BIND		2
#define S5_CMD_UDP_ASSOC	3
#define S5_ATYP_IP4		1
#define S5_ATYP_DOM		3
#define S5_ATYP_IP6		4
typedef struct
{
	uint8_t ver,cmd,rsv,atyp;
	union {
		struct {
			struct in_addr addr;
			uint16_t port;
		} d4;
		struct {
			struct in6_addr addr;
			uint16_t port;
		} d6;
		struct {
			uint8_t len;
			char domport[255+2]; // max hostname + binary port
		} dd;
	};
} s5_req;
#define S5_REQ_HEADER_VALID(r,l) (l>=4 && r->ver==5)
#define S5_IP46_VALID(r,l) (r->atyp==S5_ATYP_IP4 && l>=(4+sizeof(r->d4)) || r->atyp==S5_ATYP_IP6 && l>=(4+sizeof(r->d6)))
#define S5_REQ_CONNECT_VALID(r,l) (S5_REQ_HEADER_VALID(r,l) && r->cmd==S5_CMD_CONNECT && (S5_IP46_VALID(r,l) || r->atyp==S5_ATYP_DOM && l>=5 && l>=(5+r->dd.len)))
#define S5_PORT_FROM_DD(r,l) (l>=(4+r->dd.len+2) ? ntohs(*(uint16_t*)(r->dd.domport+r->dd.len)) : 0)

#define S5_REP_OK			0
#define S5_REP_GENERAL_FAILURE		1
#define S5_REP_NOT_ALLOWED_BY_RULESET	2
#define S5_REP_NETWORK_UNREACHABLE	3
#define S5_REP_HOST_UNREACHABLE		4
#define S5_REP_CONN_REFUSED		5
#define S5_REP_TTL_EXPIRED		6
#define S5_REP_COMMAND_NOT_SUPPORTED	7
#define S5_REP_ADDR_TYPE_NOT_SUPPORTED	8
typedef struct
{
	uint8_t ver,rep,rsv,atyp;
	union {
		struct {
			struct in_addr addr;
			uint16_t port;
		} d4;
	};
} s5_rep;

#pragma pack(pop)
