// STATUS: 100% — header complete
// process_hook.h
// GhostIT C9 — eBPF-for-Windows Kernel Process Monitor
// Ghost Layer Technologies · Chennai · June 2026

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "ghost_event.h"

// ── Event callback ────────────────────────────────────────────────────────────
// Called from the poll thread for every captured event.
// Implementation in ghost_windows_service.cpp feeds ETW + eBPF to divergence.
typedef void (*ghost_event_callback_t)(const ghost_event_t* evt);

// ── Lifecycle ─────────────────────────────────────────────────────────────────
// Loads eBPF programs, attaches to kernel tracepoints, starts poll thread.
// Must be called as LOCAL SYSTEM (eBPF-for-Windows requires kernel privilege).
bool ghost_process_hook_init(void);

// Detaches eBPF programs, stops poll thread, frees ring buffers.
void ghost_process_hook_shutdown(void);

// ── Callback ──────────────────────────────────────────────────────────────────
// Register callback — called on every process event from poll thread.
// Set before calling ghost_process_hook_init().
void ghost_process_hook_set_callback(ghost_event_callback_t cb);

// ── Manual ring drain (optional — callback is the primary path) ───────────────
// Read one event from the CRITICAL ring (4MB — LOLBin invariants).
bool ghost_process_hook_read_critical(ghost_event_t* evt);

// Read one event from the STANDARD ring (16MB — all other events).
bool ghost_process_hook_read_standard(ghost_event_t* evt);

// ── Stats ─────────────────────────────────────────────────────────────────────
uint64_t ghost_process_hook_events_captured(void);
uint64_t ghost_process_hook_events_dropped(void);
