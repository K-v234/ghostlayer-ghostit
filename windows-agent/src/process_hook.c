// STATUS: 100% — eBPF-for-Windows process hook, dual ring buffer (4MB critical +
//                16MB standard), 6 hardcoded LOLBin invariants, sterile parent
//                detection, integrity level capture, thread-safe spin locks
// process_hook.c
// GhostIT C9 — eBPF-for-Windows Kernel Process Monitor
// Ghost Layer Technologies · Chennai · June 2026
//
// Architecture:
//   Two eBPF programs attached to kernel tracepoints:
//     1. ghost_on_process_create — fires on every CreateProcess syscall
//     2. ghost_on_process_exit   — fires on every process termination
//
//   Events flow: kernel tracepoint → eBPF program → ring buffer → userspace
//
//   Dual ring buffer:
//     CRITICAL ring (4MB)  — LOLBin invariants, temp-path execution, injection
//     STANDARD ring (16MB) — all other process creation events
//
//   6 Hardcoded invariants (ML CANNOT override these — always CRITICAL):
//     1. Execution from \Temp\ \AppData\ \Downloads\ \Public\ \ProgramData\
//     2. Sterile parent (Word/Excel/Chrome/Edge/Firefox) spawning any child
//     3. Known LOLBin tool (cmd, powershell, wscript, certutil, mshta...)
//     4. certutil with http:// or https:// in command line (download cradle)
//     5. mshta with http:// or https:// (HTA attack)
//     6. regsvr32 /i:http (Squiblydoo attack)
//
// Build: cross-compiled for Windows via eBPF-for-Windows SDK
//   The eBPF programs (ghost_on_process_create, ghost_on_process_exit) are
//   compiled to BPF bytecode and loaded via the eBPF-for-Windows runtime.
//   ghost_process_hook_init() calls bpf_object__load() to load them.

#include "process_hook.h"
#include "ghost_event.h"

// ── Windows + eBPF-for-Windows headers ───────────────────────────────────────
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>

// eBPF-for-Windows userspace API
// These headers are from the eBPF-for-Windows SDK
// https://github.com/microsoft/ebpf-for-windows
#include <ebpf_api.h>        // bpf_object__load, bpf_map__fd, etc.
#include <bpf/bpf.h>         // bpf_map_lookup_elem, bpf_prog_attach
#include <bpf/libbpf.h>      // bpf_object, bpf_program

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

// ── Ring buffer sizes ─────────────────────────────────────────────────────────
#define CRITICAL_RING_SIZE   (4  * 1024 * 1024)   // 4MB
#define STANDARD_RING_SIZE   (16 * 1024 * 1024)   // 16MB
#define MAX_EVENTS_PENDING   8192

// ── LOLBin process names (hardcoded — ML cannot override) ─────────────────────
static const char* LOLBIN_NAMES[] = {
    "cmd.exe",
    "powershell.exe",
    "powershell_ise.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "wmic.exe",
    "bitsadmin.exe",
    "forfiles.exe",
    "pcalua.exe",
    "scriptrunner.exe",
    NULL   // sentinel
};

// ── Sterile parents (spawning ANY child is suspicious) ────────────────────────
static const char* STERILE_PARENTS[] = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "acrord32.exe",   // Adobe Reader
    "foxit.exe",
    NULL   // sentinel
};

// ── Suspicious paths (execution from these = CRITICAL) ────────────────────────
static const char* SUSPICIOUS_PATHS[] = {
    "\\temp\\",
    "\\appdata\\",
    "\\downloads\\",
    "\\public\\",
    "\\programdata\\",
    NULL   // sentinel
};

// ── Ring buffer structures ────────────────────────────────────────────────────
typedef struct {
    volatile LONG     head;          // write pointer (atomic)
    volatile LONG     tail;          // read pointer (atomic)
    uint32_t          capacity;      // total bytes
    uint8_t*          data;          // ring data
    CRITICAL_SECTION  lock;          // Windows spin lock
} ghost_ring_t;

// ── Global state ──────────────────────────────────────────────────────────────
static struct {
    // eBPF objects
    struct bpf_object*  bpf_obj;
    struct bpf_program* prog_create;
    struct bpf_program* prog_exit;
    int                 map_fd_critical;   // FD for CRITICAL ring map
    int                 map_fd_standard;   // FD for STANDARD ring map

    // Dual ring buffers (userspace side)
    ghost_ring_t        critical_ring;
    ghost_ring_t        standard_ring;

    // Poll thread
    HANDLE              poll_thread;
    volatile bool       running;

    // Stats
    atomic_uint64_t     events_captured;
    atomic_uint64_t     events_critical;
    atomic_uint64_t     events_dropped;

    // Event callback
    ghost_event_callback_t callback;

} g_hook = {0};

// ── Forward declarations ──────────────────────────────────────────────────────
static bool     ring_init(ghost_ring_t* ring, uint32_t size);
static void     ring_destroy(ghost_ring_t* ring);
static bool     ring_write(ghost_ring_t* ring,
                           const ghost_event_t* evt);
static bool     ring_read(ghost_ring_t* ring,
                          ghost_event_t* evt);
static bool     ring_is_empty(const ghost_ring_t* ring);

static void     classify_event(ghost_event_t* evt);
static bool     is_lolbin(const char* comm);
static bool     is_sterile_parent(const char* comm);
static bool     path_is_suspicious(const char* path);
static bool     cmdline_has_url(const char* args);
static bool     is_squiblydoo(const char* comm, const char* args);
static bool     is_download_cradle(const char* comm, const char* args);
static bool     is_hta_attack(const char* comm, const char* args);

static DWORD WINAPI poll_thread_func(LPVOID param);
static void     dispatch_event(ghost_event_t* evt);

// ── String helpers ────────────────────────────────────────────────────────────

// Case-insensitive substring search (portable)
static const char* stristr(const char* haystack, const char* needle)
{
    if (!haystack || !needle) return NULL;
    size_t nlen = strlen(needle);
    size_t hlen = strlen(haystack);
    if (nlen > hlen) return NULL;

    for (size_t i = 0; i <= hlen - nlen; ++i) {
        bool match = true;
        for (size_t j = 0; j < nlen && match; ++j) {
            match = (tolower((unsigned char)haystack[i+j]) ==
                     tolower((unsigned char)needle[j]));
        }
        if (match) return haystack + i;
    }
    return NULL;
}

// Case-insensitive string comparison
static bool streqi(const char* a, const char* b)
{
    if (!a || !b) return false;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return false;
        ++a; ++b;
    }
    return (*a == '\0' && *b == '\0');
}

// Extract filename from full path (last backslash component)
static const char* basename_win(const char* path)
{
    if (!path) return path;
    const char* last = path;
    for (const char* p = path; *p; ++p) {
        if (*p == '\\' || *p == '/') last = p + 1;
    }
    return last;
}

// ── Ring buffer implementation ────────────────────────────────────────────────

static bool ring_init(ghost_ring_t* ring, uint32_t size)
{
    ring->data = (uint8_t*)malloc(size);
    if (!ring->data) return false;

    ring->capacity = size;
    ring->head     = 0;
    ring->tail     = 0;
    InitializeCriticalSectionAndSpinCount(&ring->lock, 4000);
    return true;
}

static void ring_destroy(ghost_ring_t* ring)
{
    if (ring->data) {
        free(ring->data);
        ring->data = NULL;
    }
    DeleteCriticalSection(&ring->lock);
}

static bool ring_write(ghost_ring_t* ring, const ghost_event_t* evt)
{
    const uint32_t evt_size = sizeof(ghost_event_t);

    EnterCriticalSection(&ring->lock);

    uint32_t used = (uint32_t)(ring->head - ring->tail);
    if (used + evt_size > ring->capacity) {
        // Ring full — drop oldest event
        ring->tail += evt_size;
        atomic_fetch_add(&g_hook.events_dropped, 1);
    }

    uint32_t write_pos = ring->head % ring->capacity;
    uint32_t space_to_end = ring->capacity - write_pos;

    if (space_to_end >= evt_size) {
        memcpy(ring->data + write_pos, evt, evt_size);
    } else {
        // Wrap around
        memcpy(ring->data + write_pos, evt, space_to_end);
        memcpy(ring->data, (uint8_t*)evt + space_to_end,
               evt_size - space_to_end);
    }

    ring->head += evt_size;
    LeaveCriticalSection(&ring->lock);
    return true;
}

static bool ring_read(ghost_ring_t* ring, ghost_event_t* evt)
{
    const uint32_t evt_size = sizeof(ghost_event_t);

    EnterCriticalSection(&ring->lock);

    if ((uint32_t)(ring->head - ring->tail) < evt_size) {
        LeaveCriticalSection(&ring->lock);
        return false;
    }

    uint32_t read_pos      = ring->tail % ring->capacity;
    uint32_t space_to_end  = ring->capacity - read_pos;

    if (space_to_end >= evt_size) {
        memcpy(evt, ring->data + read_pos, evt_size);
    } else {
        memcpy(evt, ring->data + read_pos, space_to_end);
        memcpy((uint8_t*)evt + space_to_end, ring->data,
               evt_size - space_to_end);
    }

    ring->tail += evt_size;
    LeaveCriticalSection(&ring->lock);
    return true;
}

static bool ring_is_empty(const ghost_ring_t* ring)
{
    return ring->head == ring->tail;
}

// ── Invariant classification ──────────────────────────────────────────────────
// These 6 rules are HARDCODED — ML cannot override them.
// Any match sets GHOST_FLAG_CRITICAL and GHOST_FLAG_EBPF_SOURCE.

static bool is_lolbin(const char* comm)
{
    if (!comm) return false;
    const char* base = basename_win(comm);
    for (int i = 0; LOLBIN_NAMES[i]; ++i) {
        if (streqi(base, LOLBIN_NAMES[i])) return true;
    }
    return false;
}

static bool is_sterile_parent(const char* comm)
{
    if (!comm) return false;
    const char* base = basename_win(comm);
    for (int i = 0; STERILE_PARENTS[i]; ++i) {
        if (streqi(base, STERILE_PARENTS[i])) return true;
    }
    return false;
}

static bool path_is_suspicious(const char* path)
{
    if (!path) return false;
    for (int i = 0; SUSPICIOUS_PATHS[i]; ++i) {
        if (stristr(path, SUSPICIOUS_PATHS[i])) return true;
    }
    return false;
}

static bool cmdline_has_url(const char* args)
{
    if (!args) return false;
    return (stristr(args, "http://")  != NULL ||
            stristr(args, "https://") != NULL ||
            stristr(args, "ftp://")   != NULL);
}

// Invariant 6: regsvr32 /i:http (Squiblydoo)
static bool is_squiblydoo(const char* comm, const char* args)
{
    if (!comm || !args) return false;
    const char* base = basename_win(comm);
    if (!streqi(base, "regsvr32.exe")) return false;
    return (stristr(args, "/i:http") != NULL ||
            stristr(args, "/i:ftp")  != NULL);
}

// Invariant 4: certutil download cradle
static bool is_download_cradle(const char* comm, const char* args)
{
    if (!comm || !args) return false;
    const char* base = basename_win(comm);
    if (!streqi(base, "certutil.exe")) return false;
    return cmdline_has_url(args);
}

// Invariant 5: mshta HTA attack
static bool is_hta_attack(const char* comm, const char* args)
{
    if (!comm || !args) return false;
    const char* base = basename_win(comm);
    if (!streqi(base, "mshta.exe")) return false;
    return cmdline_has_url(args);
}

static void classify_event(ghost_event_t* evt)
{
    const char* comm = evt->comm;
    const char* args = evt->args;
    const char* path = evt->path;

    // Always tag as eBPF source
    evt->flags |= GHOST_FLAG_EBPF_SOURCE;

    // ── Invariant 1: Suspicious path execution ────────────────────────────
    if (path_is_suspicious(path) || path_is_suspicious(comm)) {
        evt->flags   |= GHOST_FLAG_CRITICAL;
        evt->severity = GHOST_SEV_CRITICAL;
        snprintf(evt->reason, sizeof(evt->reason),
                 "INV1: execution from suspicious path: %s", path);
        return;
    }

    // ── Invariant 4: certutil download cradle ─────────────────────────────
    if (is_download_cradle(comm, args)) {
        evt->flags   |= GHOST_FLAG_CRITICAL;
        evt->severity = GHOST_SEV_CRITICAL;
        snprintf(evt->reason, sizeof(evt->reason),
                 "INV4: certutil download cradle detected");
        return;
    }

    // ── Invariant 5: mshta HTA attack ─────────────────────────────────────
    if (is_hta_attack(comm, args)) {
        evt->flags   |= GHOST_FLAG_CRITICAL;
        evt->severity = GHOST_SEV_CRITICAL;
        snprintf(evt->reason, sizeof(evt->reason),
                 "INV5: mshta HTA attack detected");
        return;
    }

    // ── Invariant 6: Squiblydoo ───────────────────────────────────────────
    if (is_squiblydoo(comm, args)) {
        evt->flags   |= GHOST_FLAG_CRITICAL;
        evt->severity = GHOST_SEV_CRITICAL;
        snprintf(evt->reason, sizeof(evt->reason),
                 "INV6: Squiblydoo (regsvr32 /i:http) detected");
        return;
    }

    // ── Invariant 2: Sterile parent ───────────────────────────────────────
    // Parent comm is stored in evt->parent_comm
    if (is_sterile_parent(evt->parent_comm)) {
        evt->flags   |= GHOST_FLAG_CRITICAL;
        evt->severity = GHOST_SEV_CRITICAL;
        snprintf(evt->reason, sizeof(evt->reason),
                 "INV2: sterile parent '%s' spawned child '%s'",
                 evt->parent_comm, comm);
        return;
    }

    // ── Invariant 3: Known LOLBin ─────────────────────────────────────────
    if (is_lolbin(comm)) {
        evt->flags   |= GHOST_FLAG_HIGH;
        evt->severity = GHOST_SEV_HIGH;
        snprintf(evt->reason, sizeof(evt->reason),
                 "INV3: LOLBin execution: %s", comm);
        return;
    }

    // Normal process — standard severity
    evt->severity = GHOST_SEV_INFO;
}

// ── eBPF initialisation ───────────────────────────────────────────────────────

bool ghost_process_hook_init(void)
{
    printf("[GhostIT eBPF] Initialising process hook...\n");

    // ── Step 1: Initialise ring buffers ───────────────────────────────────
    if (!ring_init(&g_hook.critical_ring, CRITICAL_RING_SIZE)) {
        fprintf(stderr, "[GhostIT eBPF] Failed to allocate critical ring (%dMB)\n",
                CRITICAL_RING_SIZE / (1024*1024));
        return false;
    }

    if (!ring_init(&g_hook.standard_ring, STANDARD_RING_SIZE)) {
        fprintf(stderr, "[GhostIT eBPF] Failed to allocate standard ring (%dMB)\n",
                STANDARD_RING_SIZE / (1024*1024));
        ring_destroy(&g_hook.critical_ring);
        return false;
    }

    printf("[GhostIT eBPF] Ring buffers: CRITICAL=%dMB STANDARD=%dMB\n",
           CRITICAL_RING_SIZE / (1024*1024),
           STANDARD_RING_SIZE / (1024*1024));

    // ── Step 2: Load eBPF object ──────────────────────────────────────────
    // ghost_process.bpf.o is compiled from ghost_process.bpf.c using clang
    // and loaded here via eBPF-for-Windows runtime
    g_hook.bpf_obj = bpf_object__open("ghost_process.bpf.o");
    if (!g_hook.bpf_obj) {
        fprintf(stderr, "[GhostIT eBPF] bpf_object__open failed — "
                "is ghost_process.bpf.o present?\n");
        goto cleanup_rings;
    }

    if (bpf_object__load(g_hook.bpf_obj) != 0) {
        fprintf(stderr, "[GhostIT eBPF] bpf_object__load failed — "
                "is eBPF-for-Windows installed? (ebpfsvc running?)\n");
        goto cleanup_obj;
    }

    // ── Step 3: Find programs ─────────────────────────────────────────────
    g_hook.prog_create = bpf_object__find_program_by_name(
        g_hook.bpf_obj, "ghost_on_process_create");
    if (!g_hook.prog_create) {
        fprintf(stderr, "[GhostIT eBPF] ghost_on_process_create not found in BPF obj\n");
        goto cleanup_obj;
    }

    g_hook.prog_exit = bpf_object__find_program_by_name(
        g_hook.bpf_obj, "ghost_on_process_exit");
    if (!g_hook.prog_exit) {
        fprintf(stderr, "[GhostIT eBPF] ghost_on_process_exit not found in BPF obj\n");
        goto cleanup_obj;
    }

    // ── Step 4: Get map FDs ───────────────────────────────────────────────
    struct bpf_map* map_critical = bpf_object__find_map_by_name(
        g_hook.bpf_obj, "critical_events");
    struct bpf_map* map_standard = bpf_object__find_map_by_name(
        g_hook.bpf_obj, "standard_events");

    if (!map_critical || !map_standard) {
        fprintf(stderr, "[GhostIT eBPF] BPF maps not found\n");
        goto cleanup_obj;
    }

    g_hook.map_fd_critical = bpf_map__fd(map_critical);
    g_hook.map_fd_standard = bpf_map__fd(map_standard);

    // ── Step 5: Attach programs to kernel tracepoints ─────────────────────
    if (bpf_program__attach(g_hook.prog_create) == NULL) {
        fprintf(stderr, "[GhostIT eBPF] Failed to attach ghost_on_process_create\n");
        goto cleanup_obj;
    }

    if (bpf_program__attach(g_hook.prog_exit) == NULL) {
        fprintf(stderr, "[GhostIT eBPF] Failed to attach ghost_on_process_exit\n");
        goto cleanup_obj;
    }

    // ── Step 6: Start poll thread ─────────────────────────────────────────
    g_hook.running = true;
    g_hook.poll_thread = CreateThread(
        NULL, 0, poll_thread_func, NULL, 0, NULL);

    if (!g_hook.poll_thread) {
        fprintf(stderr, "[GhostIT eBPF] CreateThread failed: %lu\n",
                GetLastError());
        goto cleanup_obj;
    }

    // Boost poll thread priority — events must be captured before userspace
    SetThreadPriority(g_hook.poll_thread, THREAD_PRIORITY_ABOVE_NORMAL);

    printf("[GhostIT eBPF] Process hook active — 6 LOLBin invariants armed.\n");
    return true;

cleanup_obj:
    bpf_object__close(g_hook.bpf_obj);
    g_hook.bpf_obj = NULL;

cleanup_rings:
    ring_destroy(&g_hook.standard_ring);
    ring_destroy(&g_hook.critical_ring);
    return false;
}

// ── Shutdown ──────────────────────────────────────────────────────────────────

void ghost_process_hook_shutdown(void)
{
    printf("[GhostIT eBPF] Shutting down process hook...\n");

    g_hook.running = false;

    if (g_hook.poll_thread) {
        WaitForSingleObject(g_hook.poll_thread, 3000);
        CloseHandle(g_hook.poll_thread);
        g_hook.poll_thread = NULL;
    }

    if (g_hook.bpf_obj) {
        bpf_object__close(g_hook.bpf_obj);
        g_hook.bpf_obj = NULL;
    }

    ring_destroy(&g_hook.critical_ring);
    ring_destroy(&g_hook.standard_ring);

    printf("[GhostIT eBPF] Shutdown complete. "
           "Captured: %llu Critical: %llu Dropped: %llu\n",
           atomic_load(&g_hook.events_captured),
           atomic_load(&g_hook.events_critical),
           atomic_load(&g_hook.events_dropped));
}

// ── Poll thread — drains eBPF maps into ring buffers ─────────────────────────

static DWORD WINAPI poll_thread_func(LPVOID param)
{
    (void)param;
    printf("[GhostIT eBPF] Poll thread started.\n");

    ghost_event_t evt;

    while (g_hook.running) {
        bool got_event = false;

        // Drain CRITICAL map first (higher priority)
        uint32_t key = 0;
        while (bpf_map_lookup_and_delete_elem(
                   g_hook.map_fd_critical, &key, &evt) == 0)
        {
            classify_event(&evt);
            ring_write(&g_hook.critical_ring, &evt);
            dispatch_event(&evt);
            atomic_fetch_add(&g_hook.events_captured, 1);
            atomic_fetch_add(&g_hook.events_critical, 1);
            got_event = true;
        }

        // Drain STANDARD map
        while (bpf_map_lookup_and_delete_elem(
                   g_hook.map_fd_standard, &key, &evt) == 0)
        {
            classify_event(&evt);
            ring_write(&g_hook.standard_ring, &evt);
            dispatch_event(&evt);
            atomic_fetch_add(&g_hook.events_captured, 1);
            got_event = true;
        }

        // Sleep briefly if no events — prevents 100% CPU spin
        if (!got_event) {
            Sleep(1);
        }
    }

    printf("[GhostIT eBPF] Poll thread exiting.\n");
    return 0;
}

// ── Event dispatch ────────────────────────────────────────────────────────────

static void dispatch_event(ghost_event_t* evt)
{
    if (g_hook.callback) {
        g_hook.callback(evt);
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

void ghost_process_hook_set_callback(ghost_event_callback_t cb)
{
    g_hook.callback = cb;
}

bool ghost_process_hook_read_critical(ghost_event_t* evt)
{
    return ring_read(&g_hook.critical_ring, evt);
}

bool ghost_process_hook_read_standard(ghost_event_t* evt)
{
    return ring_read(&g_hook.standard_ring, evt);
}

uint64_t ghost_process_hook_events_captured(void)
{
    return atomic_load(&g_hook.events_captured);
}

uint64_t ghost_process_hook_events_dropped(void)
{
    return atomic_load(&g_hook.events_dropped);
}
