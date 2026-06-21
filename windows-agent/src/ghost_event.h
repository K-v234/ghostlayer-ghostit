/*
 * ghost_event.h — GhostIT Windows Agent
 * Shared 128-byte event struct for C9 Windows Monitoring Layer
 *
 * CRITICAL: This struct must remain binary-compatible with V0 Linux
 * ghost_agent.h. Any change here breaks pipeline deserialization.
 *
 * Owner  : Dakshin
 * STATUS : 100% — production ready
 * Target : Windows 11 22H2+ (Build 22621+) / Windows 10 RS3+ (ETW-only)
 */

#pragma once

#ifdef _WIN32
#include <windows.h>
#include <stdint.h>
#else
#include <stdint.h>
#include <time.h>
#endif

#define GHOST_EVT_PROCESS_CREATE    0x01
#define GHOST_EVT_PROCESS_EXIT      0x02
#define GHOST_EVT_FILE_OPEN         0x03
#define GHOST_EVT_FILE_WRITE        0x04
#define GHOST_EVT_FILE_DELETE       0x05
#define GHOST_EVT_FILE_RENAME       0x06
#define GHOST_EVT_NET_CONNECT       0x07
#define GHOST_EVT_NET_LISTEN        0x08
#define GHOST_EVT_NET_ACCEPT        0x09
#define GHOST_EVT_REGISTRY_SET      0x0A
#define GHOST_EVT_REGISTRY_DELETE   0x0B
#define GHOST_EVT_THREAD_CREATE     0x0C
#define GHOST_EVT_THREAD_INJECT     0x0D
#define GHOST_EVT_TOKEN_ELEVATE     0x0E
#define GHOST_EVT_MODULE_LOAD       0x0F
#define GHOST_EVT_MEMORY_EXEC       0x10
#define GHOST_EVT_PIPE_CREATE       0x11
#define GHOST_EVT_PIPE_CONNECT      0x12
#define GHOST_EVT_CANARY_HIT        0x13
#define GHOST_EVT_LAYER_DIVERGE     0x14
#define GHOST_EVT_SERVICE_INSTALL   0x15
#define GHOST_EVT_SCHEDULED_TASK    0x16

#define GHOST_PRI_CRITICAL    3
#define GHOST_PRI_HIGH        2
#define GHOST_PRI_MEDIUM      1
#define GHOST_PRI_LOW         0

#define GHOST_LAYER_EBPF      0x01
#define GHOST_LAYER_ETW       0x02
#define GHOST_LAYER_BOTH      0x03
#define GHOST_LAYER_LINUX     0x04

#define GHOST_INTEGRITY_SYSTEM      0x04
#define GHOST_INTEGRITY_HIGH        0x03
#define GHOST_INTEGRITY_MEDIUM      0x02
#define GHOST_INTEGRITY_LOW         0x01
#define GHOST_INTEGRITY_UNTRUSTED   0x00

#pragma pack(push, 1)
typedef struct ghost_event {
    uint64_t    timestamp_ns;
    uint32_t    pid;
    uint32_t    ppid;
    uint32_t    tid;
    uint32_t    uid;
    uint8_t     event_type;
    uint8_t     priority;
    uint8_t     layer;
    uint8_t     integrity;
    char        comm[16];
    char        path[56];
    uint32_t    dst_ip;
    uint16_t    dst_port;
    uint16_t    src_port;
    uint8_t     reserved[20];
} ghost_event_t;
#pragma pack(pop)

#ifdef _WIN32
static_assert(sizeof(ghost_event_t) == 128,
    "ghost_event_t must be exactly 128 bytes — V0 pipeline compatibility");
#endif

static inline uint64_t filetime_to_unix_ns(FILETIME ft) {
    uint64_t ticks = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (ticks - 116444736000000000ULL) * 100ULL;
}

static inline uint64_t ghost_timestamp_ns(void) {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    return filetime_to_unix_ns(ft);
}

static inline void ghost_event_init(ghost_event_t *evt,
                                     uint8_t event_type,
                                     uint8_t layer) {
    memset(evt, 0, sizeof(ghost_event_t));
    evt->timestamp_ns = ghost_timestamp_ns();
    evt->event_type   = event_type;
    evt->layer        = layer;
    evt->priority     = GHOST_PRI_MEDIUM;
}
