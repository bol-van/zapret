#pragma once

#include <sys/types.h>
#include <stdbool.h>

#ifdef __linux__

#include <stddef.h>
#include <sys/capability.h>
#include <linux/audit.h>

bool checkpcap(uint64_t caps);
bool setpcap(uint64_t caps);
int getmaxcap(void);
bool dropcaps(void);

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))
#define syscall_arg(x) (offsetof(struct seccomp_data, args[x]))

#if defined(__aarch64__)

# define ARCH_NR	AUDIT_ARCH_AARCH64

#elif defined(__amd64__)

# define ARCH_NR	AUDIT_ARCH_X86_64

#elif defined(__arm__) && (defined(__ARM_EABI__) || defined(__thumb__))

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define ARCH_NR	AUDIT_ARCH_ARM
# else
#  define ARCH_NR	AUDIT_ARCH_ARMEB
# endif

#elif defined(__i386__)

# define ARCH_NR	AUDIT_ARCH_I386

#elif defined(__mips__)

#if _MIPS_SIM == _MIPS_SIM_ABI32
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define ARCH_NR	AUDIT_ARCH_MIPSEL
# else
#  define ARCH_NR	AUDIT_ARCH_MIPS
# endif
#elif _MIPS_SIM == _MIPS_SIM_ABI64
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define ARCH_NR	AUDIT_ARCH_MIPSEL64
# else
#  define ARCH_NR	AUDIT_ARCH_MIPS64
# endif
#else
# error "Unsupported mips abi"
#endif

#elif defined(__PPC64__)

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define ARCH_NR	AUDIT_ARCH_PPC64LE
# else
#  define ARCH_NR	AUDIT_ARCH_PPC64
# endif

#elif defined(__PPC__)

# define ARCH_NR	AUDIT_ARCH_PPC

#elif __riscv && __riscv_xlen == 64

# define ARCH_NR	AUDIT_ARCH_RISCV64

#else

# error "Platform does not support seccomp filter yet"

#endif

#endif


#ifndef __CYGWIN__
bool sec_harden(void);
bool can_drop_root(void);
bool droproot(uid_t uid, gid_t gid);
void print_id(void);
#endif

void daemonize(void);
bool writepid(const char *filename);
