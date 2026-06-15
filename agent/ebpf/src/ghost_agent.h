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
    EVENT_EXEC       = 1,
    EVENT_OPEN       = 2,
    EVENT_CONNECT    = 3,
    EVENT_CLONE      = 4,
    EVENT_UNLINK     = 5,
    EVENT_SETUID     = 6,
    EVENT_SETGID     = 7,
    EVENT_PTRACE     = 8,
    EVENT_CAPSET     = 9,
    EVENT_MMAP_EXEC  = 10,
    EVENT_MPROTECT   = 11,
    EVENT_BIND       = 12,
    EVENT_LISTEN     = 13,
    EVENT_ACCEPT     = 14,
    EVENT_SENDTO     = 15,
    EVENT_OPENAT2    = 16,
    EVENT_RENAME     = 17,
    EVENT_CHMOD      = 18,
    EVENT_CHOWN      = 19,
    EVENT_EXIT       = 20,
    EVENT_PRCTL      = 21,
};

#define PRIORITY_STANDARD 0
#define PRIORITY_CRITICAL 1

/*
 * ghost_event — fixed size event struct
 * Layout: 8+4+4+4+4+8+1+1+2+16+64 = 116 bytes + 12 pad = 128
 */
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

#endif /* __GHOST_AGENT_H */
