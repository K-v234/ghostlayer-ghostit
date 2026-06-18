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

/* ================================================================== */
/* PROCESS — fork, vfork                                              */
/* ================================================================== */

SEC("tp/syscalls/sys_enter_fork")
int handle_fork(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_FORK, PRIORITY_STANDARD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_vfork")
int handle_vfork(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_VFORK, PRIORITY_STANDARD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================================================================== */
/* FILE — read, write                                                  */
/* ================================================================== */

SEC("tp/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    /* Only track reads on interesting fds — skip fd 0,1,2 */
    int fd = (int)ctx->args[0];
    if (fd <= 2) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_READ, PRIORITY_STANDARD);
    e->flags = (__u16)fd;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    int fd = (int)ctx->args[0];
    if (fd <= 2) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_WRITE, PRIORITY_STANDARD);
    e->flags = (__u16)fd;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================================================================== */
/* NETWORK — sendto, recvfrom, sendmsg, recvmsg                      */
/* ================================================================== */

SEC("tp/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_SENDTO, PRIORITY_STANDARD);
    e->flags = (__u16)ctx->args[0]; /* fd */

    /* Read destination address if provided */
    const void *addr = (const void *)ctx->args[4];
    if (addr) {
        struct sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), addr);
        e->path[0] = sa.sin_addr.s_addr & 0xFF;
        e->path[1] = (sa.sin_addr.s_addr >> 8) & 0xFF;
        e->path[2] = (sa.sin_addr.s_addr >> 16) & 0xFF;
        e->path[3] = (sa.sin_addr.s_addr >> 24) & 0xFF;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_recvfrom")
int handle_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_RECVFROM, PRIORITY_STANDARD);
    e->flags = (__u16)ctx->args[0]; /* fd */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_sendmsg")
int handle_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_SENDMSG, PRIORITY_STANDARD);
    e->flags = (__u16)ctx->args[0]; /* fd */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_recvmsg")
int handle_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_RECVMSG, PRIORITY_STANDARD);
    e->flags = (__u16)ctx->args[0]; /* fd */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================================================================== */
/* AUTH — setreuid, setregid, setns (critical ring)                   */
/* ================================================================== */

SEC("tp/syscalls/sys_enter_setreuid")
int handle_setreuid(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_CRITICAL);
    if (!e) return 0;
    fill_common(e, EVENT_SETREUID, PRIORITY_CRITICAL);
    e->flags = (__u16)ctx->args[1]; /* effective UID */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_setregid")
int handle_setregid(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_CRITICAL);
    if (!e) return 0;
    fill_common(e, EVENT_SETREGID, PRIORITY_CRITICAL);
    e->flags = (__u16)ctx->args[1]; /* effective GID */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_setns")
int handle_setns(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_CRITICAL);
    if (!e) return 0;
    fill_common(e, EVENT_SETNS, PRIORITY_CRITICAL);
    e->flags = (__u16)ctx->args[1]; /* nstype */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================================================================== */
/* CRYPTO — entropy reads (/dev/urandom watch)                        */
/* ================================================================== */

SEC("tp/syscalls/sys_enter_openat")
int handle_entropy_watch(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;

    char path[16] = {};
    bpf_probe_read_user_str(path, sizeof(path), (const void *)ctx->args[1]);

    /* Only fire for /dev/urandom and /dev/random */
    int is_urandom = (path[0]=='/' && path[1]=='d' && path[2]=='e' &&
                      path[3]=='v' && path[4]=='/' && path[5]=='u');
    int is_random  = (path[0]=='/' && path[1]=='d' && path[2]=='e' &&
                      path[3]=='v' && path[4]=='/' && path[5]=='r');

    if (!is_urandom && !is_random) return 0;

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_ENTROPY_READ, PRIORITY_STANDARD);
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (const void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================================================================== */
/* LSM HOOKS — capability + file open                                 */
/* ================================================================== */

SEC("lsm/capable")
int BPF_PROG(ghost_cap_check, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts)
{
    if (should_drop()) return 0;

    /* Only track sensitive capabilities */
    if (cap != 0  &&  /* CAP_CHOWN */
        cap != 1  &&  /* CAP_DAC_OVERRIDE */
        cap != 6  &&  /* CAP_SETUID */
        cap != 7  &&  /* CAP_SETGID */
        cap != 21 &&  /* CAP_SYS_ADMIN */
        cap != 22)    /* CAP_SYS_BOOT */
        return 0;

    struct ghost_event *e = RESERVE(PRIORITY_CRITICAL);
    if (!e) return 0;
    fill_common(e, EVENT_CAP_CHECK, PRIORITY_CRITICAL);
    e->flags = (__u16)cap;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(ghost_lsm_file_open, struct file *file)
{
    if (should_drop()) return 0;

    /* Only track opens on sensitive paths */
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct dentry *parent = BPF_CORE_READ(dentry, d_parent);

    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_LSM_OPEN, PRIORITY_STANDARD);

    /* Read filename */
    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    if (name)
        bpf_probe_read_kernel_str(e->path, sizeof(e->path), name);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================================================================== */
/* NEW PROBES — fd, signal, network kprobes, LSM, perf               */
/* ================================================================== */

SEC("tp/syscalls/sys_enter_socket")
int handle_socket(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_SOCKET, PRIORITY_STANDARD);
    e->flags = (__u16)ctx->args[0]; /* domain */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_accept4")
int handle_accept4(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_ACCEPT4, PRIORITY_STANDARD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_dup2")
int handle_dup2(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_DUP2, PRIORITY_STANDARD);
    e->flags = (__u16)ctx->args[1]; /* newfd */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_dup3")
int handle_dup3(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_DUP3, PRIORITY_STANDARD);
    e->flags = (__u16)ctx->args[1]; /* newfd */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_kill")
int handle_kill(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_KILL, PRIORITY_STANDARD);
    e->flags = (__u16)ctx->args[1]; /* signal */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_tgkill")
int handle_tgkill(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_TGKILL, PRIORITY_STANDARD);
    e->flags = (__u16)ctx->args[2]; /* signal */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_TCP_CONNECT, PRIORITY_STANDARD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/inet_csk_accept")
int BPF_KPROBE(handle_tcp_accept, struct sock *sk)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_TCP_ACCEPT, PRIORITY_STANDARD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_tcp_close, struct sock *sk)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_TCP_CLOSE, PRIORITY_STANDARD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(handle_udp_send, struct sock *sk)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_UDP_SEND, PRIORITY_STANDARD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(handle_udp_recv, struct sock *sk)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_UDP_RECV, PRIORITY_STANDARD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(handle_inode_perm, struct inode *inode, int mask)
{
    if (should_drop()) return 0;
    /* Only care about write/exec permission checks */
    if (!(mask & 0x2) && !(mask & 0x1)) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_STANDARD);
    if (!e) return 0;
    fill_common(e, EVENT_INODE_PERM, PRIORITY_STANDARD);
    e->flags = (__u16)mask;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_perf_event_open")
int handle_perf_open(struct trace_event_raw_sys_enter *ctx)
{
    if (should_drop()) return 0;
    struct ghost_event *e = RESERVE(PRIORITY_CRITICAL);
    if (!e) return 0;
    fill_common(e, EVENT_PERF_OPEN, PRIORITY_CRITICAL);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
