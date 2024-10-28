#pragma once

#include <stdint.h>
#include <netinet/in.h>

// taken from an older apple SDK
// some fields are different from BSDs

#define DIOCNATLOOK	_IOWR('D', 23, struct pfioc_natlook)

enum    { PF_INOUT, PF_IN, PF_OUT, PF_FWD };

struct pf_addr {
	union {
		struct in_addr		v4;
		struct in6_addr		v6;
		u_int8_t		addr8[16];
		u_int16_t		addr16[8];
		u_int32_t		addr32[4];
	} pfa;		    /* 128-bit address */
#define v4	pfa.v4
#define v6	pfa.v6
#define addr8	pfa.addr8
#define addr16	pfa.addr16
#define addr32	pfa.addr32
};

union pf_state_xport {
	u_int16_t	port;
	u_int16_t	call_id;
	u_int32_t	spi;
};

struct pfioc_natlook {
	struct pf_addr	 saddr;
	struct pf_addr	 daddr;
	struct pf_addr	 rsaddr;
	struct pf_addr	 rdaddr;
	union pf_state_xport	sxport;
	union pf_state_xport	dxport;
	union pf_state_xport	rsxport;
	union pf_state_xport	rdxport;
	sa_family_t	 af;
	u_int8_t	 proto;
	u_int8_t	 proto_variant;
	u_int8_t	 direction;
};
