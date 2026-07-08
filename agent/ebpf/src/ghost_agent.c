/*
 * ghost_agent.c — Ghost IT Userspace Loader v2
 *
 * Polls BOTH ring buffers:
 *   critical_rb → never-drop, high priority events
 *   standard_rb → normal events
 *
 * Streams events as newline-delimited JSON to stdout.
 * Pipe into Rust agent or Python forwarder.
 *
 * Ghost Layer Technologies — CONFIDENTIAL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ghost_agent.h"

#define CFG_MIN_UID  0
#define CFG_SELF_PID 1
#define MIN_UID      1000

static volatile int running = 1;

static void sig_handler(int sig) { (void)sig; running = 0; }

static const char *event_type_str(__u8 type)
{
    switch (type) {
        case EVENT_EXEC:       return "exec";
        case EVENT_OPEN:       return "open";
        case EVENT_CONNECT:    return "connect";
        case EVENT_CLONE:      return "clone";
        case EVENT_UNLINK:     return "unlink";
        case EVENT_SETUID:     return "setuid";
        case EVENT_SETGID:     return "setgid";
        case EVENT_PTRACE:     return "ptrace";
        case EVENT_CAPSET:     return "capset";
        case EVENT_MMAP_EXEC:  return "mmap_exec";
        case EVENT_MPROTECT:   return "mprotect";
        case EVENT_BIND:       return "bind";
        case EVENT_LISTEN:     return "listen";
        case EVENT_ACCEPT:     return "accept";
        case EVENT_SENDTO:     return "sendto";
        case EVENT_OPENAT2:    return "openat2";
        case EVENT_RENAME:     return "rename";
        case EVENT_CHMOD:      return "chmod";
        case EVENT_CHOWN:      return "chown";
        case EVENT_EXIT:       return "exit";
        case EVENT_PRCTL:        return "prctl";
        case EVENT_FORK:         return "fork";
        case EVENT_VFORK:        return "vfork";
        case EVENT_READ:         return "read";
        case EVENT_WRITE:        return "write";
        case EVENT_SENDMSG:      return "sendmsg";
        case EVENT_RECVFROM:     return "recvfrom";
        case EVENT_RECVMSG:      return "recvmsg";
        case EVENT_SETREUID:     return "setreuid";
        case EVENT_SETREGID:     return "setregid";
        case EVENT_SETNS:        return "setns";
        case EVENT_ENTROPY_READ: return "entropy_read";
        case EVENT_CAP_CHECK:    return "cap_check";
        case EVENT_LSM_OPEN:     return "lsm_open";
        default:                 return "unknown";
    }
}

static void json_str(const char *src, char *dst, size_t dst_sz)
{
    size_t di = 0;
    for (size_t si = 0; src[si] && di < dst_sz - 7; si++) {
        unsigned char c = (unsigned char)src[si];
        if (c == '"' || c == '\\') {
            dst[di++] = '\\';
            dst[di++] = (char)c;
        } else if (c == '\n') {
            dst[di++] = '\\'; dst[di++] = 'n';
        } else if (c == '\r') {
            dst[di++] = '\\'; dst[di++] = 'r';
        } else if (c == '\t') {
            dst[di++] = '\\'; dst[di++] = 't';
        } else if (c < 0x20) {
            di += (size_t)snprintf(dst + di, 7, "\\u%04x", c);
        } else {
            dst[di++] = (char)c;
        }
    }
    dst[di] = '\0';
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx; (void)size;
    const struct ghost_event *e = data;
    char esc[MAX_FILENAME_LEN * 2] = {};

    json_str(e->path, esc, sizeof(esc));
    char esc_comm[sizeof(e->comm) * 2] = {};
    json_str(e->comm, esc_comm, sizeof(esc_comm));

    printf("{\"ts\":%llu,\"pid\":%u,\"tgid\":%u,\"ppid\":%llu,"
           "\"uid\":%u,\"gid\":%u,\"comm\":\"%s\","
           "\"type\":\"%s\",\"priority\":%u,\"flags\":%u",
           (unsigned long long)e->timestamp_ns,
           e->pid, e->tgid,
           (unsigned long long)e->parent_pid,
           e->uid, e->gid,
           esc_comm,
           event_type_str(e->event_type),
           e->priority,
           e->flags);

    if (esc[0])
        printf(",\"path\":\"%s\"", esc);

    puts("}");
    fflush(stdout);
    return 0;
}

static int inject_config(struct bpf_object *obj)
{
    int fd = bpf_object__find_map_fd_by_name(obj, "ghost_config");
    if (fd < 0) {
        fprintf(stderr, "[ghost-agent] ERROR: ghost_config map not found\n");
        return -1;
    }

    __u32 key, val;

    key = CFG_MIN_UID;
    val = MIN_UID;
    bpf_map_update_elem(fd, &key, &val, BPF_ANY);

    key = CFG_SELF_PID;
    val = (__u32)getpid();
    bpf_map_update_elem(fd, &key, &val, BPF_ANY);

    fprintf(stderr, "[ghost-agent] Config: min_uid=%u self_pid=%u\n",
            MIN_UID, val);
    return 0;
}

int main(void)
{
    struct bpf_object  *obj = NULL;
    struct bpf_program *prog;
    struct ring_buffer *rb_std  = NULL;
    struct ring_buffer *rb_crit = NULL;
    int map_fd, err;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = bpf_object__open("ghost_agent.bpf.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[ghost-agent] ERROR: cannot open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "[ghost-agent] ERROR: cannot load BPF object\n");
        goto cleanup;
    }

    if (inject_config(obj) < 0)
        goto cleanup;

    /* Attach all programs */
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "[ghost-agent] ERROR: cannot attach %s\n",
                    bpf_program__name(prog));
            goto cleanup;
        }
        fprintf(stderr, "[ghost-agent] Attached: %s\n",
                bpf_program__name(prog));
    }

    /* Setup standard ring buffer */
    map_fd = bpf_object__find_map_fd_by_name(obj, "standard_rb");
    if (map_fd < 0) {
        fprintf(stderr, "[ghost-agent] ERROR: standard_rb not found\n");
        goto cleanup;
    }
    rb_std = ring_buffer__new(map_fd, handle_event, NULL, NULL);

    /* Setup critical ring buffer */
    map_fd = bpf_object__find_map_fd_by_name(obj, "critical_rb");
    if (map_fd < 0) {
        fprintf(stderr, "[ghost-agent] ERROR: critical_rb not found\n");
        goto cleanup;
    }
    rb_crit = ring_buffer__new(map_fd, handle_event, NULL, NULL);

    if (!rb_std || !rb_crit) {
        fprintf(stderr, "[ghost-agent] ERROR: ring buffer init failed\n");
        goto cleanup;
    }

    fprintf(stderr,
            "[ghost-agent] Running — dual ring buffer active "
            "(critical: 4MB never-drop, standard: 16MB)\n");

    while (running) {
        /* Poll critical ring first — higher priority */
        err = ring_buffer__poll(rb_crit, 10);
        if (err == -EINTR) break;

        /* Then standard ring */
        err = ring_buffer__poll(rb_std, 90);
        if (err == -EINTR) break;

        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[ghost-agent] ERROR: poll error %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb_std);
    ring_buffer__free(rb_crit);
    bpf_object__close(obj);
    fprintf(stderr, "[ghost-agent] Stopped.\n");
    return 0;
}
