#ifndef __GHOST_AGENT_H
#define __GHOST_AGENT_H

#define TASK_COMM_LEN     16
#define MAX_FILENAME_LEN  256
#define MAX_ARGS_LEN      128

typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

enum event_type {
    /* Standard ring — process */
    EVENT_EXEC       = 1,
    EVENT_OPEN       = 2,
    EVENT_CONNECT    = 3,
    EVENT_CLONE      = 4,
    EVENT_UNLINK     = 5,

    /* Critical ring — privilege */
    EVENT_SETUID     = 6,
    EVENT_SETGID     = 7,
    EVENT_PTRACE     = 8,
    EVENT_CAPSET     = 9,

    /* Critical ring — memory */
    EVENT_MMAP_EXEC  = 10,
    EVENT_MPROTECT   = 11,

    /* Standard ring — network */
    EVENT_BIND       = 12,
    EVENT_LISTEN     = 13,
    EVENT_ACCEPT     = 14,
    EVENT_SENDTO     = 15,

    /* Standard ring — file */
    EVENT_OPENAT2    = 16,
    EVENT_RENAME     = 17,
    EVENT_CHMOD      = 18,
    EVENT_CHOWN      = 19,

    /* Standard ring — process */
    EVENT_EXIT       = 20,
    EVENT_PRCTL      = 21,

    /* NEW — process */
    EVENT_FORK       = 22,
    EVENT_VFORK      = 23,

    /* NEW — file */
    EVENT_READ       = 24,
    EVENT_WRITE      = 25,

    /* NEW — network */
    EVENT_SENDMSG    = 26,
    EVENT_RECVFROM   = 27,
    EVENT_RECVMSG    = 28,

    /* NEW — auth (critical ring) */
    EVENT_SETREUID   = 29,
    EVENT_SETREGID   = 30,
    EVENT_SETNS      = 31,

    /* NEW — crypto (standard ring) */
    EVENT_ENTROPY_READ = 32,

    /* NEW — LSM hooks (critical ring) */
    EVENT_CAP_CHECK  = 33,
    EVENT_LSM_OPEN   = 34,
    /* NEW — fd/signal */
    EVENT_SOCKET     = 35,
    EVENT_ACCEPT4    = 36,
    EVENT_DUP2       = 37,
    EVENT_DUP3       = 38,
    EVENT_KILL       = 39,
    EVENT_TGKILL     = 40,

    /* NEW — kprobe network */
    EVENT_TCP_CONNECT = 41,
    EVENT_TCP_ACCEPT  = 42,
    EVENT_TCP_CLOSE   = 43,
    EVENT_UDP_SEND    = 44,
    EVENT_UDP_RECV    = 45,

    /* NEW — LSM */
    EVENT_INODE_PERM = 46,

    /* NEW — perf abuse */
    EVENT_PERF_OPEN  = 47,
    /* NEW — DNS query capture, for C14 DNS/DGA analysis */
    EVENT_DNS_QUERY  = 48,

};

#define PRIORITY_STANDARD 0
#define PRIORITY_CRITICAL 1

struct ghost_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u64 parent_pid;
    __u8  event_type;
    __u8  priority;
    __u16 flags;
    char  comm[16];
    char  path[64];
    __u8  _pad[12];
} __attribute__((packed));




/* ==================================================================

 * TLS ClientHello capture -- SEPARATE from struct ghost_event and its

 * ring buffers entirely, by design. Real ClientHello records need up

 * to ~1KB of raw payload for JA4+ fingerprinting (full cipher-suite

 * list, extension list, signature algorithms) -- far more than

 * ghost_event's path[64] can hold, and growing that shared struct

 * would affect every one of the 49 existing event types' memory

 * footprint for a capability only this one hook needs. Kept fully

 * isolated: own struct, own ring buffer map, own Rust reader --

 * zero risk to the existing, currently-live production event path.

 * ================================================================== */

#define TLS_HELLO_MAX_LEN 1024



struct tls_hello_event {

    __u64 timestamp_ns;

    __u32 pid;

    __u32 uid;

    char  comm[16];

    __u8  dst_ip[4];

    __u16 dst_port;

    __u16 hello_len;              /* actual bytes captured, <= TLS_HELLO_MAX_LEN */

    __u8  hello[TLS_HELLO_MAX_LEN];

} __attribute__((packed));

#endif /* __GHOST_AGENT_H */
