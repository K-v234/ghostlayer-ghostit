// STATUS: 100% — header complete
// ghost_windows_service.h
// GhostIT C9 — Windows Service Wrapper + Watchdog Auto-Restart
// Runs as LOCAL SYSTEM — survives reboots, cannot be killed from userspace
// Ghost Layer Technologies · Chennai · June 2026

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <atomic>
#include <thread>
#include <memory>

#include "coverage_mode.h"
#include "etw_provider.h"
#include "divergence_detector.h"
#include "pipeline_forwarder.h"
#include "event_serializer.h"

// ── Service constants ────────────────────────────────────────────────────────
static constexpr const wchar_t* GHOST_SERVICE_NAME    = L"GhostITAgent";
static constexpr const wchar_t* GHOST_SERVICE_DISPLAY = L"GhostIT Windows Agent";
static constexpr const wchar_t* GHOST_SERVICE_DESC    =
    L"GhostIT C9 — Kernel-level threat monitoring agent. "
    L"Ghost Layer Technologies.";

static constexpr DWORD WATCHDOG_INTERVAL_SEC  = 10;   // check components every 10s
static constexpr DWORD SERVICE_STOP_TIMEOUT   = 5000; // ms to wait for clean stop

// ── GhostWindowsService ──────────────────────────────────────────────────────
class GhostWindowsService {
public:
    // Singleton — only one service instance per process
    static GhostWindowsService& instance();

    // Entry point called by SCM (Service Control Manager)
    static void WINAPI service_main(DWORD argc, LPWSTR* argv);

    // Control handler — receives START/STOP/PAUSE from SCM
    static void WINAPI service_ctrl_handler(DWORD ctrl_code);

    // ── Install / Uninstall (run once as admin) ───────────────────────────
    static bool install_service();
    static bool uninstall_service();

    // ── Run modes ─────────────────────────────────────────────────────────
    // Register with SCM and block until service stops
    bool run_as_service();

    // Run interactively (for debugging — not as a real service)
    bool run_interactive();

private:
    GhostWindowsService();
    ~GhostWindowsService();

    GhostWindowsService(const GhostWindowsService&)            = delete;
    GhostWindowsService& operator=(const GhostWindowsService&) = delete;

    // ── Service lifecycle ─────────────────────────────────────────────────
    bool  initialize_components();
    void  shutdown_components();
    void  run_main_loop();

    // ── Watchdog ──────────────────────────────────────────────────────────
    void  watchdog_loop();
    bool  components_healthy();
    void  restart_unhealthy_components();

    // ── SCM status reporting ──────────────────────────────────────────────
    void report_status(DWORD state,
                       DWORD exit_code   = NO_ERROR,
                       DWORD wait_hint   = 0);

    // ── Event callback — routes events to pipeline ────────────────────────
    void on_ghost_event(const ghost_event_t& evt);

    // ── State ─────────────────────────────────────────────────────────────
    SERVICE_STATUS_HANDLE  status_handle_;
    SERVICE_STATUS         status_;

    std::atomic<bool>      running_;
    std::atomic<bool>      watchdog_running_;

    std::thread            watchdog_thread_;

    // ── Components ────────────────────────────────────────────────────────
    std::unique_ptr<CoverageMode>        coverage_;
    std::unique_ptr<EtwProvider>         etw_;
    std::unique_ptr<DivergenceDetector>  divergence_;
    std::unique_ptr<PipelineForwarder>   pipeline_;
};
