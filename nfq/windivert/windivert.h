/*
 * windivert.h
 * (C) 2019, all rights reserved,
 *
 * This file is part of WinDivert.
 *
 * WinDivert is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * WinDivert is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __WINDIVERT_H
#define __WINDIVERT_H

#ifndef WINDIVERT_KERNEL
#include <windows.h>
#endif      /* WINDIVERT_KERNEL */

#ifndef WINDIVERTEXPORT
#define WINDIVERTEXPORT     extern __declspec(dllimport)
#endif      /* WINDIVERTEXPORT */

#ifdef __MINGW32__
#define __in
#define __in_opt
#define __out
#define __out_opt
#define __inout
#define __inout_opt
#include <stdint.h>
#define INT8    int8_t
#define UINT8   uint8_t
#define INT16   int16_t
#define UINT16  uint16_t
#define INT32   int32_t
#define UINT32  uint32_t
#define INT64   int64_t
#define UINT64  uint64_t
#endif      /* __MINGW32__ */

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************/
/* WINDIVERT API                                                            */
/****************************************************************************/

/*
 * WinDivert layers.
 */
typedef enum
{
    WINDIVERT_LAYER_NETWORK = 0,        /* Network layer. */
    WINDIVERT_LAYER_NETWORK_FORWARD = 1,/* Network layer (forwarded packets) */
    WINDIVERT_LAYER_FLOW = 2,           /* Flow layer. */
    WINDIVERT_LAYER_SOCKET = 3,         /* Socket layer. */
    WINDIVERT_LAYER_REFLECT = 4,        /* Reflect layer. */
} WINDIVERT_LAYER, *PWINDIVERT_LAYER;

/*
 * WinDivert NETWORK and NETWORK_FORWARD layer data.
 */
typedef struct
{
    UINT32 IfIdx;                       /* Packet's interface index. */
    UINT32 SubIfIdx;                    /* Packet's sub-interface index. */
} WINDIVERT_DATA_NETWORK, *PWINDIVERT_DATA_NETWORK;

/*
 * WinDivert FLOW layer data.
 */
typedef struct
{
    UINT64 EndpointId;                  /* Endpoint ID. */
    UINT64 ParentEndpointId;            /* Parent endpoint ID. */
    UINT32 ProcessId;                   /* Process ID. */
    UINT32 LocalAddr[4];                /* Local address. */
    UINT32 RemoteAddr[4];               /* Remote address. */
    UINT16 LocalPort;                   /* Local port. */
    UINT16 RemotePort;                  /* Remote port. */
    UINT8  Protocol;                    /* Protocol. */
} WINDIVERT_DATA_FLOW, *PWINDIVERT_DATA_FLOW;

/*
 * WinDivert SOCKET layer data.
 */
typedef struct
{
    UINT64 EndpointId;                  /* Endpoint ID. */
    UINT64 ParentEndpointId;            /* Parent Endpoint ID. */
    UINT32 ProcessId;                   /* Process ID. */
    UINT32 LocalAddr[4];                /* Local address. */
    UINT32 RemoteAddr[4];               /* Remote address. */
    UINT16 LocalPort;                   /* Local port. */
    UINT16 RemotePort;                  /* Remote port. */
    UINT8  Protocol;                    /* Protocol. */
} WINDIVERT_DATA_SOCKET, *PWINDIVERT_DATA_SOCKET;

/*
 * WinDivert REFLECTION layer data.
 */
typedef struct
{
    INT64  Timestamp;                   /* Handle open time. */
    UINT32 ProcessId;                   /* Handle process ID. */
    WINDIVERT_LAYER Layer;              /* Handle layer. */
    UINT64 Flags;                       /* Handle flags. */
    INT16  Priority;                    /* Handle priority. */
} WINDIVERT_DATA_REFLECT, *PWINDIVERT_DATA_REFLECT;

/*
 * WinDivert address.
 */
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4201)
#endif
typedef struct
{
    INT64  Timestamp;                   /* Packet's timestamp. */
    UINT32 Layer:8;                     /* Packet's layer. */
    UINT32 Event:8;                     /* Packet event. */
    UINT32 Sniffed:1;                   /* Packet was sniffed? */
    UINT32 Outbound:1;                  /* Packet is outound? */
    UINT32 Loopback:1;                  /* Packet is loopback? */
    UINT32 Impostor:1;                  /* Packet is impostor? */
    UINT32 IPv6:1;                      /* Packet is IPv6? */
    UINT32 IPChecksum:1;                /* Packet has valid IPv4 checksum? */
    UINT32 TCPChecksum:1;               /* Packet has valid TCP checksum? */
    UINT32 UDPChecksum:1;               /* Packet has valid UDP checksum? */
    UINT32 Reserved1:8;
    UINT32 Reserved2;
    union
    {
        WINDIVERT_DATA_NETWORK Network; /* Network layer data. */
        WINDIVERT_DATA_FLOW Flow;       /* Flow layer data. */
        WINDIVERT_DATA_SOCKET Socket;   /* Socket layer data. */
        WINDIVERT_DATA_REFLECT Reflect; /* Reflect layer data. */
        UINT8 Reserved3[64];
    };
} WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;
#ifdef _MSC_VER
#pragma warning(pop)
#endif

/*
 * WinDivert events.
 */
typedef enum
{
    WINDIVERT_EVENT_NETWORK_PACKET = 0, /* Network packet. */
    WINDIVERT_EVENT_FLOW_ESTABLISHED = 1,
                                        /* Flow established. */
    WINDIVERT_EVENT_FLOW_DELETED = 2,   /* Flow deleted. */
    WINDIVERT_EVENT_SOCKET_BIND = 3,    /* Socket bind. */
    WINDIVERT_EVENT_SOCKET_CONNECT = 4, /* Socket connect. */
    WINDIVERT_EVENT_SOCKET_LISTEN = 5,  /* Socket listen. */
    WINDIVERT_EVENT_SOCKET_ACCEPT = 6,  /* Socket accept. */
    WINDIVERT_EVENT_SOCKET_CLOSE = 7,   /* Socket close. */
    WINDIVERT_EVENT_REFLECT_OPEN = 8,   /* WinDivert handle opened. */
    WINDIVERT_EVENT_REFLECT_CLOSE = 9,  /* WinDivert handle closed. */
} WINDIVERT_EVENT, *PWINDIVERT_EVENT;

/*
 * WinDivert flags.
 */
#define WINDIVERT_FLAG_SNIFF            0x0001
#define WINDIVERT_FLAG_DROP             0x0002
#define WINDIVERT_FLAG_RECV_ONLY        0x0004
#define WINDIVERT_FLAG_READ_ONLY        WINDIVERT_FLAG_RECV_ONLY
#define WINDIVERT_FLAG_SEND_ONLY        0x0008
#define WINDIVERT_FLAG_WRITE_ONLY       WINDIVERT_FLAG_SEND_ONLY
#define WINDIVERT_FLAG_NO_INSTALL       0x0010
#define WINDIVERT_FLAG_FRAGMENTS        0x0020

/*
 * WinDivert parameters.
 */
typedef enum
{
    WINDIVERT_PARAM_QUEUE_LENGTH = 0,   /* Packet queue length. */
    WINDIVERT_PARAM_QUEUE_TIME = 1,     /* Packet queue time. */
    WINDIVERT_PARAM_QUEUE_SIZE = 2,     /* Packet queue size. */
    WINDIVERT_PARAM_VERSION_MAJOR = 3,  /* Driver version (major). */
    WINDIVERT_PARAM_VERSION_MINOR = 4,  /* Driver version (minor). */
} WINDIVERT_PARAM, *PWINDIVERT_PARAM;
#define WINDIVERT_PARAM_MAX             WINDIVERT_PARAM_VERSION_MINOR

/*
 * WinDivert shutdown parameter.
 */
typedef enum
{
    WINDIVERT_SHUTDOWN_RECV = 0x1,      /* Shutdown recv. */
    WINDIVERT_SHUTDOWN_SEND = 0x2,      /* Shutdown send. */
    WINDIVERT_SHUTDOWN_BOTH = 0x3,      /* Shutdown recv and send. */
} WINDIVERT_SHUTDOWN, *PWINDIVERT_SHUTDOWN;
#define WINDIVERT_SHUTDOWN_MAX          WINDIVERT_SHUTDOWN_BOTH

#ifndef WINDIVERT_KERNEL

/*
 * Open a WinDivert handle.
 */
WINDIVERTEXPORT HANDLE WinDivertOpen(
    __in        const char *filter,
    __in        WINDIVERT_LAYER layer,
    __in        INT16 priority,
    __in        UINT64 flags);

/*
 * Receive (read) a packet from a WinDivert handle.
 */
WINDIVERTEXPORT BOOL WinDivertRecv(
    __in        HANDLE handle,
    __out_opt   VOID *pPacket,
    __in        UINT packetLen,
    __out_opt   UINT *pRecvLen,
    __out_opt   WINDIVERT_ADDRESS *pAddr);

/*
 * Receive (read) a packet from a WinDivert handle.
 */
WINDIVERTEXPORT BOOL WinDivertRecvEx(
    __in        HANDLE handle,
    __out_opt   VOID *pPacket,
    __in        UINT packetLen,
    __out_opt   UINT *pRecvLen,
    __in        UINT64 flags,
    __out       WINDIVERT_ADDRESS *pAddr,
    __inout_opt UINT *pAddrLen,
    __inout_opt LPOVERLAPPED lpOverlapped);

/*
 * Send (write/inject) a packet to a WinDivert handle.
 */
WINDIVERTEXPORT BOOL WinDivertSend(
    __in        HANDLE handle,
    __in        const VOID *pPacket,
    __in        UINT packetLen,
    __out_opt   UINT *pSendLen,
    __in        const WINDIVERT_ADDRESS *pAddr);

/*
 * Send (write/inject) a packet to a WinDivert handle.
 */
WINDIVERTEXPORT BOOL WinDivertSendEx(
    __in        HANDLE handle,
    __in        const VOID *pPacket,
    __in        UINT packetLen,
    __out_opt   UINT *pSendLen,
    __in        UINT64 flags,
    __in        const WINDIVERT_ADDRESS *pAddr,
    __in        UINT addrLen,
    __inout_opt LPOVERLAPPED lpOverlapped);

/*
 * Shutdown a WinDivert handle.
 */
WINDIVERTEXPORT BOOL WinDivertShutdown(
    __in        HANDLE handle,
    __in        WINDIVERT_SHUTDOWN how);

/*
 * Close a WinDivert handle.
 */
WINDIVERTEXPORT BOOL WinDivertClose(
    __in        HANDLE handle);

/*
 * Set a WinDivert handle parameter.
 */
WINDIVERTEXPORT BOOL WinDivertSetParam(
    __in        HANDLE handle,
    __in        WINDIVERT_PARAM param,
    __in        UINT64 value);

/*
 * Get a WinDivert handle parameter.
 */
WINDIVERTEXPORT BOOL WinDivertGetParam(
    __in        HANDLE handle,
    __in        WINDIVERT_PARAM param,
    __out       UINT64 *pValue);

#endif      /* WINDIVERT_KERNEL */

/*
 * WinDivert constants.
 */
#define WINDIVERT_PRIORITY_HIGHEST              30000
#define WINDIVERT_PRIORITY_LOWEST               (-WINDIVERT_PRIORITY_HIGHEST)
#define WINDIVERT_PARAM_QUEUE_LENGTH_DEFAULT    4096
#define WINDIVERT_PARAM_QUEUE_LENGTH_MIN        32
#define WINDIVERT_PARAM_QUEUE_LENGTH_MAX        16384
#define WINDIVERT_PARAM_QUEUE_TIME_DEFAULT      2000        /* 2s */
#define WINDIVERT_PARAM_QUEUE_TIME_MIN          100         /* 100ms */
#define WINDIVERT_PARAM_QUEUE_TIME_MAX          16000       /* 16s */
#define WINDIVERT_PARAM_QUEUE_SIZE_DEFAULT      4194304     /* 4MB */
#define WINDIVERT_PARAM_QUEUE_SIZE_MIN          65535       /* 64KB */
#define WINDIVERT_PARAM_QUEUE_SIZE_MAX          33554432    /* 32MB */
#define WINDIVERT_BATCH_MAX                     0xFF        /* 255 */
#define WINDIVERT_MTU_MAX                       (40 + 0xFFFF)

/****************************************************************************/
/* WINDIVERT HELPER API                                                     */
/****************************************************************************/

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4214)
#endif

/*
 * IPv4/IPv6/ICMP/ICMPv6/TCP/UDP header definitions.
 */
typedef struct
{
    UINT8  HdrLength:4;
    UINT8  Version:4;
    UINT8  TOS;
    UINT16 Length;
    UINT16 Id;
    UINT16 FragOff0;
    UINT8  TTL;
    UINT8  Protocol;
    UINT16 Checksum;
    UINT32 SrcAddr;
    UINT32 DstAddr;
} WINDIVERT_IPHDR, *PWINDIVERT_IPHDR;

#define WINDIVERT_IPHDR_GET_FRAGOFF(hdr)                    \
    (((hdr)->FragOff0) & 0xFF1F)
#define WINDIVERT_IPHDR_GET_MF(hdr)                         \
    ((((hdr)->FragOff0) & 0x0020) != 0)
#define WINDIVERT_IPHDR_GET_DF(hdr)                         \
    ((((hdr)->FragOff0) & 0x0040) != 0)
#define WINDIVERT_IPHDR_GET_RESERVED(hdr)                   \
    ((((hdr)->FragOff0) & 0x0080) != 0)

#define WINDIVERT_IPHDR_SET_FRAGOFF(hdr, val)               \
    do                                                      \
    {                                                       \
        (hdr)->FragOff0 = (((hdr)->FragOff0) & 0x00E0) |    \
            ((val) & 0xFF1F);                               \
    }                                                       \
    while (FALSE)
#define WINDIVERT_IPHDR_SET_MF(hdr, val)                    \
    do                                                      \
    {                                                       \
        (hdr)->FragOff0 = (((hdr)->FragOff0) & 0xFFDF) |    \
            (((val) & 0x0001) << 5);                        \
    }                                                       \
    while (FALSE)
#define WINDIVERT_IPHDR_SET_DF(hdr, val)                    \
    do                                                      \
    {                                                       \
        (hdr)->FragOff0 = (((hdr)->FragOff0) & 0xFFBF) |    \
            (((val) & 0x0001) << 6);                        \
    }                                                       \
    while (FALSE)
#define WINDIVERT_IPHDR_SET_RESERVED(hdr, val)              \
    do                                                      \
    {                                                       \
        (hdr)->FragOff0 = (((hdr)->FragOff0) & 0xFF7F) |    \
            (((val) & 0x0001) << 7);                        \
    }                                                       \
    while (FALSE)

typedef struct
{
    UINT8  TrafficClass0:4;
    UINT8  Version:4;
    UINT8  FlowLabel0:4;
    UINT8  TrafficClass1:4;
    UINT16 FlowLabel1;
    UINT16 Length;
    UINT8  NextHdr;
    UINT8  HopLimit;
    UINT32 SrcAddr[4];
    UINT32 DstAddr[4];
} WINDIVERT_IPV6HDR, *PWINDIVERT_IPV6HDR;

#define WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(hdr)             \
    ((((hdr)->TrafficClass0) << 4) | ((hdr)->TrafficClass1))
#define WINDIVERT_IPV6HDR_GET_FLOWLABEL(hdr)                \
    ((((UINT32)(hdr)->FlowLabel0) << 16) | ((UINT32)(hdr)->FlowLabel1))

#define WINDIVERT_IPV6HDR_SET_TRAFFICCLASS(hdr, val)        \
    do                                                      \
    {                                                       \
        (hdr)->TrafficClass0 = ((UINT8)(val) >> 4);         \
        (hdr)->TrafficClass1 = (UINT8)(val);                \
    }                                                       \
    while (FALSE)
#define WINDIVERT_IPV6HDR_SET_FLOWLABEL(hdr, val)           \
    do                                                      \
    {                                                       \
        (hdr)->FlowLabel0 = (UINT8)((val) >> 16);           \
        (hdr)->FlowLabel1 = (UINT16)(val);                  \
    }                                                       \
    while (FALSE)

typedef struct
{
    UINT8  Type;
    UINT8  Code;
    UINT16 Checksum;
    UINT32 Body;
} WINDIVERT_ICMPHDR, *PWINDIVERT_ICMPHDR;

typedef struct
{
    UINT8  Type;
    UINT8  Code;
    UINT16 Checksum;
    UINT32 Body;
} WINDIVERT_ICMPV6HDR, *PWINDIVERT_ICMPV6HDR;

typedef struct
{
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT32 SeqNum;
    UINT32 AckNum;
    UINT16 Reserved1:4;
    UINT16 HdrLength:4;
    UINT16 Fin:1;
    UINT16 Syn:1;
    UINT16 Rst:1;
    UINT16 Psh:1;
    UINT16 Ack:1;
    UINT16 Urg:1;
    UINT16 Reserved2:2;
    UINT16 Window;
    UINT16 Checksum;
    UINT16 UrgPtr;
} WINDIVERT_TCPHDR, *PWINDIVERT_TCPHDR;

typedef struct
{
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT16 Length;
    UINT16 Checksum;
} WINDIVERT_UDPHDR, *PWINDIVERT_UDPHDR;

#ifdef _MSC_VER
#pragma warning(pop)
#endif

/*
 * Flags for WinDivertHelperCalcChecksums()
 */
#define WINDIVERT_HELPER_NO_IP_CHECKSUM                     1
#define WINDIVERT_HELPER_NO_ICMP_CHECKSUM                   2
#define WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM                 4
#define WINDIVERT_HELPER_NO_TCP_CHECKSUM                    8
#define WINDIVERT_HELPER_NO_UDP_CHECKSUM                    16

#ifndef WINDIVERT_KERNEL

/*
 * Hash a packet.
 */
WINDIVERTEXPORT UINT64 WinDivertHelperHashPacket(
    __in        const VOID *pPacket,
    __in        UINT packetLen,
    __in        UINT64 seed
#ifdef __cplusplus
                = 0
#endif
);

/*
 * Parse IPv4/IPv6/ICMP/ICMPv6/TCP/UDP headers from a raw packet.
 */
WINDIVERTEXPORT BOOL WinDivertHelperParsePacket(
    __in        const VOID *pPacket,
    __in        UINT packetLen,
    __out_opt   PWINDIVERT_IPHDR *ppIpHdr,
    __out_opt   PWINDIVERT_IPV6HDR *ppIpv6Hdr,
    __out_opt   UINT8 *pProtocol,
    __out_opt   PWINDIVERT_ICMPHDR *ppIcmpHdr,
    __out_opt   PWINDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
    __out_opt   PWINDIVERT_TCPHDR *ppTcpHdr,
    __out_opt   PWINDIVERT_UDPHDR *ppUdpHdr,
    __out_opt   PVOID *ppData,
    __out_opt   UINT *pDataLen,
    __out_opt   PVOID *ppNext,
    __out_opt   UINT *pNextLen);

/*
 * Parse an IPv4 address.
 */
WINDIVERTEXPORT BOOL WinDivertHelperParseIPv4Address(
    __in        const char *addrStr,
    __out_opt   UINT32 *pAddr);

/*
 * Parse an IPv6 address.
 */
WINDIVERTEXPORT BOOL WinDivertHelperParseIPv6Address(
    __in        const char *addrStr,
    __out_opt   UINT32 *pAddr);

/*
 * Format an IPv4 address.
 */
WINDIVERTEXPORT BOOL WinDivertHelperFormatIPv4Address(
    __in        UINT32 addr,
    __out       char *buffer,
    __in        UINT bufLen);

/*
 * Format an IPv6 address.
 */
WINDIVERTEXPORT BOOL WinDivertHelperFormatIPv6Address(
    __in        const UINT32 *pAddr,
    __out       char *buffer,
    __in        UINT bufLen);

/*
 * Calculate IPv4/IPv6/ICMP/ICMPv6/TCP/UDP checksums.
 */
WINDIVERTEXPORT BOOL WinDivertHelperCalcChecksums(
    __inout     VOID *pPacket, 
    __in        UINT packetLen,
    __out_opt   WINDIVERT_ADDRESS *pAddr,
    __in        UINT64 flags);

/*
 * Decrement the TTL/HopLimit.
 */
WINDIVERTEXPORT BOOL WinDivertHelperDecrementTTL(
    __inout     VOID *pPacket,
    __in        UINT packetLen);

/*
 * Compile the given filter string.
 */
WINDIVERTEXPORT BOOL WinDivertHelperCompileFilter(
    __in        const char *filter,
    __in        WINDIVERT_LAYER layer,
    __out_opt   char *object,
    __in        UINT objLen,
    __out_opt   const char **errorStr,
    __out_opt   UINT *errorPos);

/*
 * Evaluate the given filter string.
 */
WINDIVERTEXPORT BOOL WinDivertHelperEvalFilter(
    __in        const char *filter,
    __in        const VOID *pPacket,
    __in        UINT packetLen,
    __in        const WINDIVERT_ADDRESS *pAddr);

/*
 * Format the given filter string.
 */
WINDIVERTEXPORT BOOL WinDivertHelperFormatFilter(
    __in        const char *filter,
    __in        WINDIVERT_LAYER layer,
    __out       char *buffer,
    __in        UINT bufLen);

/*
 * Byte ordering.
 */
WINDIVERTEXPORT UINT16 WinDivertHelperNtohs(
    __in        UINT16 x);
WINDIVERTEXPORT UINT16 WinDivertHelperHtons(
    __in        UINT16 x);
WINDIVERTEXPORT UINT32 WinDivertHelperNtohl(
    __in        UINT32 x);
WINDIVERTEXPORT UINT32 WinDivertHelperHtonl(
    __in        UINT32 x);
WINDIVERTEXPORT UINT64 WinDivertHelperNtohll(
    __in        UINT64 x);
WINDIVERTEXPORT UINT64 WinDivertHelperHtonll(
    __in        UINT64 x);
WINDIVERTEXPORT void WinDivertHelperNtohIPv6Address(
    __in        const UINT *inAddr,
    __out       UINT *outAddr);
WINDIVERTEXPORT void WinDivertHelperHtonIPv6Address(
    __in        const UINT *inAddr,
    __out       UINT *outAddr);

/*
 * Old names to be removed in the next version.
 */
WINDIVERTEXPORT void WinDivertHelperNtohIpv6Address(
    __in        const UINT *inAddr,
    __out       UINT *outAddr);
WINDIVERTEXPORT void WinDivertHelperHtonIpv6Address(
    __in        const UINT *inAddr,
    __out       UINT *outAddr);

#endif      /* WINDIVERT_KERNEL */

#ifdef __cplusplus
}
#endif

#endif      /* __WINDIVERT_H */
