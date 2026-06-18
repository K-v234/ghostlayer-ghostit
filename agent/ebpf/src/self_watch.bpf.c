/*
 * self_watch.bpf.c — Ghost IT Agent Self-Watch (C6 Layer 2)
 *
 * Monitors agent's own PID via sched_process_exit tracepoint.
 * If agent dies without graceful shutdown → emits CRITICAL alert.
 *
 * Ghost Layer Technologies — CONFIDENTIAL
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ghost_agent.h"

char LICENSE[] SEC("license") = "GPL";

/* Agent PID set by userspace at startup */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key,   __u32);
    __type(value, __u32);
} self_watch_config SEC(".maps");

/* Alert ring — 512KB */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} self_watch_rb SEC(".maps");

/* Graceful shutdown flag — set before exit */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} graceful_flag SEC(".maps");

SEC("tp/sched/sched_process_exit")
int ghost_self_watch(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 exiting_pid = ctx->pid;

    /* Get monitored agent PID */
    __u32 key = 0;
    __u32 *agent_pid = bpf_map_lookup_elem(&self_watch_config, &key);
    if (!agent_pid || *agent_pid == 0)
        return 0;

    if (exiting_pid != *agent_pid)
        return 0;

    /* Check graceful shutdown flag */
    __u32 flag_key = 0;
    __u32 *graceful = bpf_map_lookup_elem(&graceful_flag, &flag_key);
    if (graceful && *graceful == 1)
        return 0; /* Graceful shutdown — OK */

    /* Unexpected death — emit CRITICAL alert */
    struct ghost_event *e = bpf_ringbuf_reserve(&self_watch_rb,
                                                 sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = exiting_pid;
    e->event_type   = 255; /* AGENT_KILLED sentinel */
    e->priority     = PRIORITY_CRITICAL;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
