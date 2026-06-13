/*
 * ghost_agent.c — Ghost IT Userspace Loader (v2 — filtered)
 *
 * Loads BPF object, injects runtime config into BPF maps,
 * then streams filtered events as JSON to stdout.
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

/* Config map keys */
#define CFG_MIN_UID  0
#define CFG_SELF_PID 1

/* Only show events from UIDs >= this (filters out most daemon noise) */
#define MIN_UID 1000

static volatile int running = 1;

static void sig_handler(int sig) { (void)sig; running = 0; }

static const char *event_type_str(__u8 type)
{
    switch (type) {
        case EVENT_EXEC:    return "exec";
        case EVENT_OPEN:    return "open";
        case EVENT_CONNECT: return "connect";
        case EVENT_CLONE:   return "clone";
        case EVENT_UNLINK:  return "unlink";
        default:            return "unknown";
    }
}

static void json_str(const char *src, char *dst, size_t dst_sz)
{
    size_t di = 0;
    for (size_t si = 0; src[si] && di < dst_sz - 3; si++) {
        if (src[si] == '"' || src[si] == '\\') dst[di++] = '\\';
        dst[di++] = src[si];
    }
    dst[di] = '\0';
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx; (void)size;
    const struct ghost_event *e = data;
    char esc[MAX_FILENAME_LEN * 2];
    char ip[INET_ADDRSTRLEN];

    printf("{\"ts\":%llu,\"pid\":%u,\"ppid\":%u,"
           "\"uid\":%u,\"gid\":%u,\"comm\":\"%s\",\"type\":\"%s\"",
           (unsigned long long)e->timestamp,
           e->pid, e->ppid, e->uid, e->gid,
           e->comm, event_type_str(e->event_type));

    switch (e->event_type) {
        case EVENT_EXEC:
            json_str(e->exec.filename, esc, sizeof(esc));
            printf(",\"file\":\"%s\"", esc);
            json_str(e->exec.args, esc, sizeof(esc));
            if (esc[0]) printf(",\"args\":\"%s\"", esc);
            break;
        case EVENT_OPEN:
            json_str(e->open.filename, esc, sizeof(esc));
            printf(",\"file\":\"%s\",\"flags\":%d", esc, e->open.flags);
            break;
        case EVENT_CONNECT:
            inet_ntop(AF_INET, &e->connect.daddr, ip, sizeof(ip));
            printf(",\"daddr\":\"%s\",\"dport\":%u,\"family\":%u",
                   ip, e->connect.dport, e->connect.family);
            break;
        case EVENT_CLONE:
            printf(",\"clone_flags\":%llu",
                   (unsigned long long)e->clone_info.clone_flags);
            break;
        case EVENT_UNLINK:
            json_str(e->unlink.filename, esc, sizeof(esc));
            printf(",\"file\":\"%s\"", esc);
            break;
    }
    puts("}");
    fflush(stdout);
    return 0;
}

static int inject_config(struct bpf_object *obj)
{
    int cfg_fd = bpf_object__find_map_fd_by_name(obj, "ghost_config");
    if (cfg_fd < 0) {
        fprintf(stderr, "[ghost-agent] ERROR: config map not found\n");
        return -1;
    }

    /* Set minimum UID filter */
    __u32 key = CFG_MIN_UID, val = MIN_UID;
    bpf_map_update_elem(cfg_fd, &key, &val, BPF_ANY);

    /* Tell kernel to ignore our own PID */
    key = CFG_SELF_PID;
    val = (__u32)getpid();
    bpf_map_update_elem(cfg_fd, &key, &val, BPF_ANY);

    fprintf(stderr, "[ghost-agent] Config: min_uid=%u self_pid=%u\n",
            MIN_UID, val);
    return 0;
}

int main(void)
{
    struct bpf_object  *obj = NULL;
    struct bpf_program *prog;
    struct ring_buffer *rb  = NULL;
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

    /* Inject runtime config before attaching programs */
    if (inject_config(obj) < 0)
        goto cleanup;

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

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "[ghost-agent] ERROR: ring buffer map not found\n");
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ghost-agent] ERROR: ring buffer init failed\n");
        goto cleanup;
    }

    fprintf(stderr, "[ghost-agent] Running — filtered stream active\n");

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "[ghost-agent] ERROR: poll error %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    bpf_object__close(obj);
    fprintf(stderr, "[ghost-agent] Stopped.\n");
    return 0;
}
