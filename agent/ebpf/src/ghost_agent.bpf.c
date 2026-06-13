/*
 * ghost_agent.bpf.c — Ghost IT Kernel eBPF Program (v2 — filtered)
 *
 * Layer 1 filtering happens here in kernel space:
 *   - Ignore kernel threads (pid == tgid == 0)
 *   - Ignore noisy system daemons via comm blacklist
 *   - Ignore /sys, /proc, /dev path prefixes
 *   - Ignore root-owned daemon file polling
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

/* Ring buffer — zero-copy event stream to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");

/*
 * pid_blacklist — userspace writes PIDs to ignore (e.g. known daemons).
 * Key: pid, Value: 1
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key,   __u32);
    __type(value, __u8);
} pid_blacklist SEC(".maps");

/*
 * config — runtime tunables set by userspace loader.
 * Key 0: min_uid  (ignore events from UIDs below this)
 * Key 1: self_pid (ignore our own agent's events)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key,   __u32);
    __type(value, __u32);
} ghost_config SEC(".maps");

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static __always_inline void fill_common(struct ghost_event *e, __u8 type)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->timestamp  = bpf_ktime_get_ns();
    e->pid        = bpf_get_current_pid_tgid() >> 32;
    e->uid        = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid        = bpf_get_current_uid_gid() >> 32;
    e->ppid       = BPF_CORE_READ(task, real_parent, tgid);
    e->event_type = type;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
}

/*
 * should_drop — returns 1 if this event should be silently discarded.
 * All checks run in kernel space — zero userspace overhead for dropped events.
 */
static __always_inline int should_drop(void)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 key, *val;

    /* Drop our own agent's events */
    key = 1;
    val = bpf_map_lookup_elem(&ghost_config, &key);
    if (val && *val && pid == *val)
        return 1;

    /* Drop UIDs below minimum (kernel threads, root daemons) */
    key = 0;
    val = bpf_map_lookup_elem(&ghost_config, &key);
    if (val && uid < *val)
        return 1;

    /* Drop explicitly blacklisted PIDs */
    __u8 *blacklisted = bpf_map_lookup_elem(&pid_blacklist, &pid);
    if (blacklisted)
        return 1;

    return 0;
}

/*
 * is_noisy_path — returns 1 for /sys, /proc, /dev paths.
 * We check byte-by-byte since BPF can't use strncmp on user pointers.
 */
static __always_inline int is_noisy_path(const char *path)
{
    char buf[8] = {};
    bpf_probe_read_kernel_str(buf, sizeof(buf), path);

    /* /proc/ */
    if (buf[0]=='/' && buf[1]=='p' && buf[2]=='r' && buf[3]=='o' && buf[4]=='c')
        return 1;
    /* /sys/ */
    if (buf[0]=='/' && buf[1]=='s' && buf[2]=='y' && buf[3]=='s')
        return 1;
    /* /dev/ */
    if (buf[0]=='/' && buf[1]=='d' && buf[2]=='e' && buf[3]=='v')
        return 1;
    /* / (root dir polls by systemd) */
    if (buf[0]=='/' && buf[1]=='\0')
        return 1;

    return 0;
}

/* ------------------------------------------------------------------ */
/* Tracepoints                                                         */
/* ------------------------------------------------------------------ */

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVENT_EXEC);
    bpf_probe_read_user_str(e->exec.filename, sizeof(e->exec.filename),
                            (const void *)ctx->args[0]);
    const char **argv = (const char **)(ctx->args[1]);
    const char  *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), &argv[1]);
    if (argp)
        bpf_probe_read_user_str(e->exec.args, sizeof(e->exec.args), argp);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    /* Read path first to apply path filter before reserving ring buf space */
    char path[16] = {};
    bpf_probe_read_user_str(path, sizeof(path), (const void *)ctx->args[1]);
    if (is_noisy_path(path)) return 0;

    struct ghost_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVENT_OPEN);
    bpf_probe_read_user_str(e->open.filename, sizeof(e->open.filename),
                            (const void *)ctx->args[1]);
    e->open.flags = (int)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVENT_CONNECT);
    struct sockaddr_in addr = {};
    bpf_probe_read_user(&addr, sizeof(addr), (const void *)ctx->args[1]);
    e->connect.family = addr.sin_family;
    e->connect.dport  = __builtin_bswap16(addr.sin_port);
    e->connect.daddr  = addr.sin_addr.s_addr;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_clone")
int handle_clone(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVENT_CLONE);
    e->clone_info.clone_flags = (__u64)ctx->args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_unlink")
int handle_unlink(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    struct ghost_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e, EVENT_UNLINK);
    bpf_probe_read_user_str(e->unlink.filename, sizeof(e->unlink.filename),
                            (const void *)ctx->args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
