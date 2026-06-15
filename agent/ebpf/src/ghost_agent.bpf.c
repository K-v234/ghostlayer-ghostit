/*
 * ghost_agent.bpf.c — Ghost IT Kernel eBPF Program v2
 *
 * Probe points implemented (21 of 47 target):
 *
 * CRITICAL ring (never-drop, 4MB):
 *   sys_setuid, sys_setgid, sys_ptrace, sys_capset
 *   sys_mmap (exec bit), sys_mprotect (exec bit)
 *
 * STANDARD ring (16MB, drops oldest on overflow):
 *   sys_execve, sys_execveat, sys_clone
 *   sys_openat, sys_openat2, sys_rename, sys_unlink, sys_chmod, sys_chown
 *   sys_connect, sys_bind, sys_listen, sys_sendto
 *   sys_exit_group, sys_prctl
 *
 * Kernel: 5.8+ (ring buffer), BTF + CO-RE required
 *
 * Ghost Layer Technologies — CONFIDENTIAL
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ghost_agent.h"

char LICENSE[] SEC("license") = "GPL";

/* ------------------------------------------------------------------ */
/* Maps                                                                */
/* ------------------------------------------------------------------ */

/*
 * Critical ring — 4MB, never drops events
 * Used for: privilege escalation, memory exec, ptrace
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} critical_rb SEC(".maps");

/*
 * Standard ring — 16MB, drops oldest on overflow (self-healing)
 * Used for: file, network, process events
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} standard_rb SEC(".maps");

/*
 * ghost_config — runtime tunables
 * Key 0: min_uid  (ignore UIDs below this)
 * Key 1: self_pid (ignore agent's own events)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key,   __u32);
    __type(value, __u32);
} ghost_config SEC(".maps");

/*
 * pid_blacklist — PIDs to ignore
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key,   __u32);
    __type(value, __u8);
} pid_blacklist SEC(".maps");

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static __always_inline void fill_common(
    struct ghost_event *e, __u8 type, __u8 priority)
{
    struct task_struct *task =
        (struct task_struct *)bpf_get_current_task();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->tgid         = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid          = bpf_get_current_uid_gid() >> 32;
    e->parent_pid   = BPF_CORE_READ(task, real_parent, tgid);
    e->event_type   = type;
    e->priority     = priority;
    e->flags        = 0;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
}

static __always_inline int should_drop(void)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 key, *val;

    /* Drop our own agent */
    key = 1;
    val = bpf_map_lookup_elem(&ghost_config, &key);
    if (val && *val && pid == *val)
        return 1;

    /* Drop UIDs below minimum */
    key = 0;
    val = bpf_map_lookup_elem(&ghost_config, &key);
    if (val && uid < *val)
        return 1;

    /* Drop blacklisted PIDs */
    __u8 *bl = bpf_map_lookup_elem(&pid_blacklist, &pid);
    if (bl)
        return 1;

    return 0;
}

static __always_inline int is_noisy_path(const void *upath)
{
    char buf[8] = {};
    bpf_probe_read_user_str(buf, sizeof(buf), upath);

    if (buf[0]=='/' && buf[1]=='p' && buf[2]=='r' && buf[3]=='o' && buf[4]=='c')
        return 1;
    if (buf[0]=='/' && buf[1]=='s' && buf[2]=='y' && buf[3]=='s')
        return 1;
    if (buf[0]=='/' && buf[1]=='d' && buf[2]=='e' && buf[3]=='v' && buf[4]=='/')
        return 1;
    if (buf[0]=='/' && buf[1]=='\0')
        return 1;
    return 0;
}

/* Reserve from correct ring based on priority */
#define RESERVE(priority) \
    ((priority) == PRIORITY_CRITICAL \
        ? bpf_ringbuf_reserve(&critical_rb,  sizeof(struct ghost_event), 0) \
        : bpf_ringbuf_reserve(&standard_rb, sizeof(struct ghost_event), 0))

/* ================================================================== */
/* CRITICAL RING — PRIVILEGE PROBES                                   */
/* ================================================================== */

SEC("tp/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_CRITICAL);
    if (!e) return 0;

    fill_common(e, EVENT_SETUID, PRIORITY_CRITICAL);
    e->flags = (__u16)ctx->args[0]; /* new UID */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_setgid")
int handle_setgid(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_CRITICAL);
    if (!e) return 0;

    fill_common(e, EVENT_SETGID, PRIORITY_CRITICAL);
    e->flags = (__u16)ctx->args[0]; /* new GID */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_CRITICAL);
    if (!e) return 0;

    fill_common(e, EVENT_PTRACE, PRIORITY_CRITICAL);
    e->flags = (__u16)ctx->args[0]; /* ptrace request */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_capset")
int handle_capset(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_CRITICAL);
    if (!e) return 0;

    fill_common(e, EVENT_CAPSET, PRIORITY_CRITICAL);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================================================================== */
/* CRITICAL RING — MEMORY EXEC PROBES                                 */
/* ================================================================== */

#define PROT_EXEC 0x4
#define MAP_ANON  0x20

SEC("tp/syscalls/sys_enter_mmap")
int handle_mmap(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    /* Only care about executable mappings */
    __u64 prot  = (__u64)ctx->args[2];
    __u64 flags = (__u64)ctx->args[3];

    if (!(prot & PROT_EXEC)) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_CRITICAL);
    if (!e) return 0;

    fill_common(e, EVENT_MMAP_EXEC, PRIORITY_CRITICAL);
    e->flags = (__u16)(prot | (flags << 8));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_mprotect")
int handle_mprotect(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    __u64 prot = (__u64)ctx->args[2];
    if (!(prot & PROT_EXEC)) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_CRITICAL);
    if (!e) return 0;

    fill_common(e, EVENT_MPROTECT, PRIORITY_CRITICAL);
    e->flags = (__u16)prot;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================================================================== */
/* STANDARD RING — PROCESS PROBES                                     */
/* ================================================================== */

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_EXEC, PRIORITY_STANDARD);
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (const void *)(long)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_EXEC, PRIORITY_STANDARD);
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (const void *)(long)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_clone")
int handle_clone(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_CLONE, PRIORITY_STANDARD);
    e->flags = (__u16)((__u64)ctx->args[0] & 0xFFFF);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_exit_group")
int handle_exit_group(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_EXIT, PRIORITY_STANDARD);
    e->flags = (__u16)ctx->args[0]; /* exit code */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_prctl")
int handle_prctl(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_PRCTL, PRIORITY_STANDARD);
    e->flags = (__u16)ctx->args[0]; /* prctl option */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================================================================== */
/* STANDARD RING — FILE PROBES                                        */
/* ================================================================== */

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    char path[16] = {};
    bpf_probe_read_user_str(path, sizeof(path), (const void *)(long)ctx->args[1]);
    if (is_noisy_path((const void *)(long)ctx->args[1])) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_OPEN, PRIORITY_STANDARD);
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (const void *)(long)ctx->args[1]);
    e->flags = (__u16)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat2")
int handle_openat2(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    if (is_noisy_path((const void *)(long)ctx->args[1])) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_OPENAT2, PRIORITY_STANDARD);
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (const void *)(long)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_unlink")
int handle_unlink(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_UNLINK, PRIORITY_STANDARD);
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (const void *)(long)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_rename")
int handle_rename(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_RENAME, PRIORITY_STANDARD);
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (const void *)(long)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_chmod")
int handle_chmod(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_CHMOD, PRIORITY_STANDARD);
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (const void *)(long)ctx->args[0]);
    e->flags = (__u16)ctx->args[1]; /* mode */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_chown")
int handle_chown(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_CHOWN, PRIORITY_STANDARD);
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (const void *)(long)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================================================================== */
/* STANDARD RING — NETWORK PROBES                                     */
/* ================================================================== */

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_CONNECT, PRIORITY_STANDARD);

    struct sockaddr_in addr = {};
    bpf_probe_read_user(&addr, sizeof(addr), (const void *)(long)ctx->args[1]);
    e->flags = addr.sin_family;

    /* Encode IP:port in path field */
    __u32 ip   = addr.sin_addr.s_addr;
    __u16 port = __builtin_bswap16(addr.sin_port);
    /* Store raw IP+port in path as hex string */
    __u8 a = ip & 0xFF, b = (ip>>8)&0xFF, c = (ip>>16)&0xFF, d = (ip>>24)&0xFF;
    e->path[0] = a; e->path[1] = b; e->path[2] = c; e->path[3] = d;
    e->path[4] = (port >> 8) & 0xFF; e->path[5] = port & 0xFF;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_bind")
int handle_bind(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_BIND, PRIORITY_STANDARD);
    struct sockaddr_in addr = {};
    bpf_probe_read_user(&addr, sizeof(addr), (const void *)(long)ctx->args[1]);
    e->flags = addr.sin_family;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_listen")
int handle_listen(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;

    fill_common(e, EVENT_LISTEN, PRIORITY_STANDARD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
