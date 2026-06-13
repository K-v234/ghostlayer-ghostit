#ifndef __GHOST_AGENT_H
#define __GHOST_AGENT_H

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN     128

typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

/* Syscall event categories tracked by Ghost IT */
enum event_type {
    EVENT_EXEC    = 1,  /* Process execution  — execve  */
    EVENT_OPEN    = 2,  /* File access        — openat  */
    EVENT_CONNECT = 3,  /* Network connection — connect */
    EVENT_CLONE   = 4,  /* Process fork       — clone   */
    EVENT_UNLINK  = 5,  /* File deletion      — unlink  */
};

/*
 * ghost_event — core event struct passed from kernel to userspace
 * via BPF ring buffer. Fixed size, cache-aligned.
 */
struct ghost_event {
    __u64 timestamp;            /* Nanoseconds since boot (bpf_ktime_get_ns) */
    __u32 pid;                  /* Process ID                                 */
    __u32 ppid;                 /* Parent process ID                          */
    __u32 uid;                  /* User ID                                    */
    __u32 gid;                  /* Group ID                                   */
    __u8  event_type;           /* enum event_type                            */
    __u8  pad[3];               /* Explicit padding for alignment             */
    char  comm[TASK_COMM_LEN];  /* Process name (e.g. "nginx", "bash")        */

    union {
        struct {
            char filename[MAX_FILENAME_LEN];
            char args[MAX_ARGS_LEN];
        } exec;

        struct {
            char filename[MAX_FILENAME_LEN];
            int  flags;
        } open;

        struct {
            __u32 daddr;   /* Destination IPv4 address (network byte order) */
            __u16 dport;   /* Destination port (host byte order)            */
            __u16 family;  /* AF_INET = 2                                   */
        } connect;

        struct {
            __u64 clone_flags;
        } clone_info;

        struct {
            char filename[MAX_FILENAME_LEN];
        } unlink;
    };
};

#endif /* __GHOST_AGENT_H */
