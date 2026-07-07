// STATUS: 100% — header complete
// coverage_mode.h
// GhostIT C9 — Windows Version Detection + Coverage Mode
// Win11 22H2+ → Full Coverage (eBPF + ETW)
// Win10        → Standard Coverage (ETW only)
// Ghost Layer Technologies · Chennai · June 2026

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <functional>

// ── Coverage levels ───────────────────────────────────────────────────────────
enum class CoverageLevel {
    FULL,       // Win11 22H2+ — eBPF-for-Windows + ETW-TI both active
    STANDARD,   // Win10 / Server 2019 — ETW only (eBPF not supported)
    UNKNOWN     // Detection failed
};

// ── Version info ──────────────────────────────────────────────────────────────
struct WindowsVersionInfo {
    DWORD         major;          // e.g. 10
    DWORD         minor;          // e.g. 0
    DWORD         build;          // e.g. 22621 (Win11 22H2)
    std::string   display_name;   // e.g. "Windows 11 22H2"
    CoverageLevel coverage;
    bool          ebpf_supported;
    bool          etw_ti_supported;
};

// ── CoverageMode ──────────────────────────────────────────────────────────────
class CoverageMode {
public:
    CoverageMode();

    // Detect Windows version and set coverage level
    bool detect();

    // Returns the detected version info
    const WindowsVersionInfo& version_info() const;

    // Human-readable badge for C13 dashboard
    // "Full Coverage (eBPF + ETW)" or "Standard Coverage (ETW only)"
    std::string badge_string() const;

    // JSON payload for pipeline — sent with every heartbeat
    std::string to_json() const;

    // True if eBPF-for-Windows can be loaded on this host
    bool ebpf_supported() const;

    // True if ETW-TI provider is available (Win10 RS3+)
    bool etw_ti_supported() const;

    // Log coverage level to stdout — call after detect()
    void log_coverage() const;

private:
    // Read true build number via RtlGetVersion (bypasses compatibility shim)
    static bool rtl_get_version(OSVERSIONINFOEXW& out);

    // Map build number → display name + coverage level
    static WindowsVersionInfo classify(DWORD major, DWORD minor, DWORD build);

    WindowsVersionInfo info_;
    bool               detected_;
};
