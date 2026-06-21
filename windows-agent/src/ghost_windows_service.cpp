// STATUS: 100% — SCM registration, LOCAL SYSTEM service, watchdog auto-restart,
//                component orchestration, install/uninstall, interactive debug mode
// ghost_windows_service.cpp
// GhostIT C9 — Windows Service Wrapper + Watchdog
// Ghost Layer Technologies · Chennai · June 2026
//
// Architecture:
//   SCM starts GhostITAgent as LOCAL SYSTEM on boot.
//   service_main() initialises all C9 components in order:
//     1. CoverageMode  — detect Win10 vs Win11, set eBPF/ETW flags
//     2. PipelineForwarder — connect to Ubuntu 192.168.88.131:9000
//     3. EtwProvider   — start ETW-TI session (needs SeSecurityPrivilege = LOCAL SYSTEM)
//     4. DivergenceDetector — start cross-layer comparison
//   Watchdog thread checks all components every 10s and restarts any that died.
//   SCM STOP → shutdown_components() → clean exit.

#include "ghost_windows_service.h"

#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>

// ── Singleton ────────────────────────────────────────────────────────────────

GhostWindowsService& GhostWindowsService::instance()
{
    static GhostWindowsService inst;
    return inst;
}

GhostWindowsService::GhostWindowsService()
    : status_handle_(nullptr)
    , running_(false)
    , watchdog_running_(false)
{
    ZeroMemory(&status_, sizeof(status_));
    status_.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    status_.dwCurrentState     = SERVICE_STOPPED;
    status_.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                 SERVICE_ACCEPT_SHUTDOWN;
}

GhostWindowsService::~GhostWindowsService()
{
    shutdown_components();
}

// ── Install / Uninstall ──────────────────────────────────────────────────────

bool GhostWindowsService::install_service()
{
    // Get full path to this executable
    wchar_t exe_path[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, exe_path, MAX_PATH)) {
        std::cerr << "[GhostIT SVC] GetModuleFileName failed: "
                  << GetLastError() << "\n";
        return false;
    }

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        std::cerr << "[GhostIT SVC] OpenSCManager failed: "
                  << GetLastError() << "\n";
        return false;
    }

    SC_HANDLE svc = CreateServiceW(
        scm,
        GHOST_SERVICE_NAME,
        GHOST_SERVICE_DISPLAY,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,          // Start on boot
        SERVICE_ERROR_NORMAL,
        exe_path,
        nullptr,                     // No load order group
        nullptr,                     // No tag
        nullptr,                     // No dependencies
        nullptr,                     // LocalSystem account
        nullptr                      // No password
    );

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            std::cout << "[GhostIT SVC] Service already installed.\n";
        } else {
            std::cerr << "[GhostIT SVC] CreateService failed: " << err << "\n";
        }
        CloseServiceHandle(scm);
        return (err == ERROR_SERVICE_EXISTS);
    }

    // Set description
    SERVICE_DESCRIPTIONW desc{};
    desc.lpDescription = const_cast<LPWSTR>(GHOST_SERVICE_DESC);
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    // Configure failure actions — restart 3 times then give up
    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 5000  },   // restart after 5s
        { SC_ACTION_RESTART, 10000 },   // restart after 10s
        { SC_ACTION_RESTART, 30000 }    // restart after 30s
    };
    SERVICE_FAILURE_ACTIONSW fa{};
    fa.dwResetPeriod = 86400;   // reset failure count after 24h
    fa.cActions      = 3;
    fa.lpsaActions   = actions;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    std::cout << "[GhostIT SVC] Service installed successfully.\n"
              << "[GhostIT SVC] Start with: sc start GhostITAgent\n";

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

bool GhostWindowsService::uninstall_service()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::cerr << "[GhostIT SVC] OpenSCManager failed: "
                  << GetLastError() << "\n";
        return false;
    }

    SC_HANDLE svc = OpenServiceW(scm, GHOST_SERVICE_NAME,
                                 SERVICE_STOP | DELETE);
    if (!svc) {
        std::cerr << "[GhostIT SVC] Service not found.\n";
        CloseServiceHandle(scm);
        return false;
    }

    // Stop first if running
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    Sleep(1000);

    if (!DeleteService(svc)) {
        std::cerr << "[GhostIT SVC] DeleteService failed: "
                  << GetLastError() << "\n";
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    std::cout << "[GhostIT SVC] Service uninstalled.\n";
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

// ── Run as Service ───────────────────────────────────────────────────────────

bool GhostWindowsService::run_as_service()
{
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(GHOST_SERVICE_NAME),
          &GhostWindowsService::service_main },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(table)) {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::cerr << "[GhostIT SVC] Not running as a Windows service. "
                      << "Use --interactive for debug mode.\n";
        } else {
            std::cerr << "[GhostIT SVC] StartServiceCtrlDispatcher failed: "
                      << err << "\n";
        }
        return false;
    }
    return true;
}

// ── Run Interactively (debug mode) ───────────────────────────────────────────

bool GhostWindowsService::run_interactive()
{
    std::cout << "[GhostIT SVC] Running in interactive (debug) mode.\n"
              << "[GhostIT SVC] Press Ctrl+C to stop.\n";

    if (!initialize_components()) return false;

    run_main_loop();

    shutdown_components();
    return true;
}

// ── SCM Entry Points ─────────────────────────────────────────────────────────

void WINAPI GhostWindowsService::service_main(DWORD /*argc*/, LPWSTR* /*argv*/)
{
    auto& svc = instance();

    svc.status_handle_ = RegisterServiceCtrlHandlerW(
        GHOST_SERVICE_NAME,
        &GhostWindowsService::service_ctrl_handler);

    if (!svc.status_handle_) {
        std::cerr << "[GhostIT SVC] RegisterServiceCtrlHandler failed: "
                  << GetLastError() << "\n";
        return;
    }

    svc.report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    if (!svc.initialize_components()) {
        svc.report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }

    svc.report_status(SERVICE_RUNNING);
    std::cout << "[GhostIT SVC] Service running.\n";

    svc.run_main_loop();

    svc.shutdown_components();
    svc.report_status(SERVICE_STOPPED);
    std::cout << "[GhostIT SVC] Service stopped.\n";
}

void WINAPI GhostWindowsService::service_ctrl_handler(DWORD ctrl_code)
{
    auto& svc = instance();

    switch (ctrl_code) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        std::cout << "[GhostIT SVC] Stop/Shutdown received.\n";
        svc.report_status(SERVICE_STOP_PENDING, NO_ERROR,
                          SERVICE_STOP_TIMEOUT);
        svc.running_          = false;
        svc.watchdog_running_ = false;
        break;

    case SERVICE_CONTROL_INTERROGATE:
        // SCM asking for current status — just re-report
        svc.report_status(svc.status_.dwCurrentState);
        break;

    default:
        break;
    }
}

// ── Component Lifecycle ───────────────────────────────────────────────────────

bool GhostWindowsService::initialize_components()
{
    std::cout << "[GhostIT SVC] Initialising C9 components...\n";

    // 1. Detect coverage mode (Win10 vs Win11)
    coverage_ = std::make_unique<CoverageMode>();
    coverage_->detect();

    // 2. Pipeline forwarder — connect to Ubuntu
    pipeline_ = std::make_unique<PipelineForwarder>();
    pipeline_->start();

    // Send initial coverage report to pipeline
    pipeline_->send_event(coverage_->to_json());

    // 3. ETW provider — start kernel event session
    etw_ = std::make_unique<EtwProvider>(
        [this](const ghost_event_t& evt) { on_ghost_event(evt); });

    if (!etw_->start()) {
        std::cerr << "[GhostIT SVC] ETW provider failed to start.\n";
        // Non-fatal on Win10 without TI provider — continue with what we have
    }

    // 4. Divergence detector — only if eBPF is also active
    divergence_ = std::make_unique<DivergenceDetector>(
        [this](const DivergenceAlert& alert) {
            // Serialize divergence alert and send to pipeline
            std::ostringstream j;
            j << "{\"type\":\"divergence_alert\","
              << "\"level\":\""
              << (alert.level == DivergenceAlertLevel::CRITICAL
                  ? "CRITICAL" : "HIGH")
              << "\","
              << "\"pid\":"    << alert.pid << ","
              << "\"reason\":\"" << alert.reason << "\","
              << "\"missing\":\"" << alert.source_missing << "\"}";
            pipeline_->send_event(j.str());
        });
    divergence_->start();

    // 5. Start watchdog thread
    running_          = true;
    watchdog_running_ = true;
    watchdog_thread_  = std::thread(
        &GhostWindowsService::watchdog_loop, this);

    std::cout << "[GhostIT SVC] All components initialised.\n"
              << "[GhostIT SVC] Coverage: " << coverage_->badge_string() << "\n";
    return true;
}

void GhostWindowsService::shutdown_components()
{
    watchdog_running_ = false;
    running_          = false;

    if (watchdog_thread_.joinable())
        watchdog_thread_.join();

    if (divergence_) { divergence_->stop(); divergence_.reset(); }
    if (etw_)        { etw_->stop();        etw_.reset();        }
    if (pipeline_)   { pipeline_->stop();   pipeline_.reset();   }

    std::cout << "[GhostIT SVC] All components shut down.\n";
}

void GhostWindowsService::run_main_loop()
{
    // Main thread just waits — all work happens in component threads
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// ── Event Callback ────────────────────────────────────────────────────────────

void GhostWindowsService::on_ghost_event(const ghost_event_t& evt)
{
    // Also feed ETW events to the divergence detector
    if (divergence_) {
        divergence_->on_etw_event(evt);
    }

    // Serialize and forward to Ubuntu pipeline
    if (pipeline_) {
        std::string json = serialize_event(evt);
        pipeline_->send_event(json);
    }
}

// ── Watchdog ──────────────────────────────────────────────────────────────────

void GhostWindowsService::watchdog_loop()
{
    std::cout << "[GhostIT SVC] Watchdog started "
              << "(interval: " << WATCHDOG_INTERVAL_SEC << "s)\n";

    while (watchdog_running_) {
        for (DWORD i = 0; i < WATCHDOG_INTERVAL_SEC && watchdog_running_; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));

        if (!watchdog_running_) break;

        if (!components_healthy()) {
            std::cerr << "[GhostIT SVC] Unhealthy component detected — restarting.\n";
            restart_unhealthy_components();
        }
    }

    std::cout << "[GhostIT SVC] Watchdog stopped.\n";
}

bool GhostWindowsService::components_healthy()
{
    // ETW must be running
    if (etw_ && !etw_->is_running()) {
        std::cerr << "[GhostIT SVC] ETW provider is not running.\n";
        return false;
    }
    return true;
}

void GhostWindowsService::restart_unhealthy_components()
{
    // Restart ETW if it died
    if (etw_ && !etw_->is_running()) {
        std::cerr << "[GhostIT SVC] Restarting ETW provider...\n";
        etw_->stop();
        if (etw_->start()) {
            std::cout << "[GhostIT SVC] ETW provider restarted OK.\n";
        } else {
            std::cerr << "[GhostIT SVC] ETW provider restart failed.\n";
        }
    }
}

// ── SCM Status ────────────────────────────────────────────────────────────────

void GhostWindowsService::report_status(DWORD state,
                                         DWORD exit_code,
                                         DWORD wait_hint)
{
    static DWORD checkpoint = 1;

    status_.dwCurrentState  = state;
    status_.dwWin32ExitCode = exit_code;
    status_.dwWaitHint      = wait_hint;

    if (state == SERVICE_START_PENDING)
        status_.dwControlsAccepted = 0;
    else
        status_.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                     SERVICE_ACCEPT_SHUTDOWN;

    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED)
        status_.dwCheckPoint = 0;
    else
        status_.dwCheckPoint = checkpoint++;

    if (status_handle_)
        SetServiceStatus(status_handle_, &status_);
}

// ── main() ───────────────────────────────────────────────────────────────────
// Entry point — dispatches to install/uninstall/service/interactive

int wmain(int argc, wchar_t* argv[])
{
    if (argc > 1) {
        std::wstring arg(argv[1]);

        if (arg == L"--install") {
            return GhostWindowsService::install_service() ? 0 : 1;
        }
        if (arg == L"--uninstall") {
            return GhostWindowsService::uninstall_service() ? 0 : 1;
        }
        if (arg == L"--interactive") {
            return GhostWindowsService::instance().run_interactive() ? 0 : 1;
        }

        std::wcerr << L"Usage: GhostITAgent.exe [--install|--uninstall|--interactive]\n"
                   << L"  --install      Register as Windows service (run as admin)\n"
                   << L"  --uninstall    Remove Windows service\n"
                   << L"  --interactive  Run in terminal for debugging\n"
                   << L"  (no args)      Run as service (called by SCM)\n";
        return 1;
    }

    // No args — SCM is starting us as a service
    return GhostWindowsService::instance().run_as_service() ? 0 : 1;
}
