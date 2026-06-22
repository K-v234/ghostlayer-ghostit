// STATUS: 100% — RtlGetVersion detection, Full/Standard coverage classification,
//                dashboard badge string, JSON heartbeat payload
// coverage_mode.cpp
// GhostIT C9 — Windows Version Detection + Coverage Mode
// Ghost Layer Technologies · Chennai · June 2026
//
// Why RtlGetVersion and not GetVersionEx?
//   GetVersionEx lies — on Win10/11 it returns 6.2 (Win8) for compatibility.
//   RtlGetVersion in ntdll.dll always returns the real version.
//   We load it dynamically so we don't need to link ntdll explicitly.

#include "coverage_mode.h"
#include <winternl.h>
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#include <iostream>
#include <sstream>
#include <iomanip>

// ── Win11 build thresholds ────────────────────────────────────────────────────
// Win11 21H2 = build 22000 (eBPF-for-Windows GA on 22H2+)
// Win11 22H2 = build 22621 — minimum for full eBPF support
static constexpr DWORD WIN11_MIN_BUILD          = 22000;
static constexpr DWORD WIN11_22H2_BUILD         = 22621;
static constexpr DWORD WIN11_23H2_BUILD         = 22631;
static constexpr DWORD WIN11_24H2_BUILD         = 26100;

// Win10 builds
static constexpr DWORD WIN10_RS3_BUILD          = 16299; // ETW-TI available
static constexpr DWORD WIN10_21H2_BUILD         = 19044;
static constexpr DWORD WIN10_22H2_BUILD         = 19045;

// Server builds
static constexpr DWORD SERVER_2022_BUILD        = 20348;
static constexpr DWORD SERVER_2019_BUILD        = 17763;

// ── Constructor ───────────────────────────────────────────────────────────────

CoverageMode::CoverageMode()
    : detected_(false)
{
    info_.major          = 0;
    info_.minor          = 0;
    info_.build          = 0;
    info_.display_name   = "Unknown";
    info_.coverage       = CoverageLevel::UNKNOWN;
    info_.ebpf_supported = false;
    info_.etw_ti_supported = false;
}

// ── Public API ────────────────────────────────────────────────────────────────

bool CoverageMode::detect()
{
    OSVERSIONINFOEXW osvi{};
    if (!rtl_get_version(osvi)) {
        std::cerr << "[GhostIT COVERAGE] RtlGetVersion failed — "
                  << "falling back to Standard Coverage.\n";
        info_.coverage       = CoverageLevel::STANDARD;
        info_.display_name   = "Unknown Windows";
        info_.etw_ti_supported = true;   // safe assumption for Win10+
        info_.ebpf_supported   = false;
        detected_ = true;
        return false;
    }

    info_ = classify(osvi.dwMajorVersion,
                     osvi.dwMinorVersion,
                     osvi.dwBuildNumber);
    detected_ = true;

    log_coverage();
    return true;
}

const WindowsVersionInfo& CoverageMode::version_info() const
{
    return info_;
}

std::string CoverageMode::badge_string() const
{
    switch (info_.coverage) {
    case CoverageLevel::FULL:
        return "Full Coverage (eBPF + ETW)";
    case CoverageLevel::STANDARD:
        return "Standard Coverage (ETW only)";
    default:
        return "Unknown Coverage";
    }
}

std::string CoverageMode::to_json() const
{
    // JSON payload sent in every heartbeat to pipeline
    // C13 dashboard reads this to display the badge
    std::ostringstream j;
    j << "{"
      << "\"type\":\"coverage_report\","
      << "\"agent\":\"windows-c9\","
      << "\"os\":\"" << info_.display_name << "\","
      << "\"build\":" << info_.build << ","
      << "\"coverage\":\""
      << (info_.coverage == CoverageLevel::FULL ? "full" : "standard")
      << "\","
      << "\"badge\":\"" << badge_string() << "\","
      << "\"ebpf_active\":"
      << (info_.ebpf_supported ? "true" : "false")
      << ","
      << "\"etw_ti_active\":"
      << (info_.etw_ti_supported ? "true" : "false")
      << "}";
    return j.str();
}

bool CoverageMode::ebpf_supported()    const { return info_.ebpf_supported;    }
bool CoverageMode::etw_ti_supported()  const { return info_.etw_ti_supported;  }

void CoverageMode::log_coverage() const
{
    std::cout << "[GhostIT COVERAGE] Detected: " << info_.display_name
              << " (build " << info_.build << ")\n"
              << "[GhostIT COVERAGE] Mode: " << badge_string() << "\n"
              << "[GhostIT COVERAGE] eBPF supported:    "
              << (info_.ebpf_supported   ? "YES" : "NO")  << "\n"
              << "[GhostIT COVERAGE] ETW-TI supported:  "
              << (info_.etw_ti_supported ? "YES" : "NO")  << "\n";

    if (info_.coverage == CoverageLevel::STANDARD) {
        std::cout << "[GhostIT COVERAGE] NOTE: This endpoint shows "
                  << "'Standard Coverage' in the dashboard.\n"
                  << "[GhostIT COVERAGE] Upgrade to Windows 11 22H2+ "
                  << "for Full Coverage (eBPF + ETW dual-layer).\n";
    }
}

// ── Private Helpers ───────────────────────────────────────────────────────────

bool CoverageMode::rtl_get_version(OSVERSIONINFOEXW& out)
{
    // Load ntdll dynamically — always present on Windows
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    // RtlGetVersion signature
    using RtlGetVersionFn = NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);
    auto fn = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(ntdll, "RtlGetVersion"));
    if (!fn) return false;

    out.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    NTSTATUS status = fn(reinterpret_cast<PRTL_OSVERSIONINFOW>(&out));

    // STATUS_SUCCESS = 0
    return status == 0;
}

WindowsVersionInfo CoverageMode::classify(DWORD major, DWORD minor, DWORD build)
{
    WindowsVersionInfo v{};
    v.major = major;
    v.minor = minor;
    v.build = build;

    // ── Windows 11 ────────────────────────────────────────────────────────
    if (major == 10 && minor == 0 && build >= WIN11_MIN_BUILD) {

        if (build >= WIN11_24H2_BUILD) {
            v.display_name = "Windows 11 24H2";
        } else if (build >= WIN11_23H2_BUILD) {
            v.display_name = "Windows 11 23H2";
        } else if (build >= WIN11_22H2_BUILD) {
            v.display_name = "Windows 11 22H2";
        } else {
            v.display_name = "Windows 11 21H2";
        }

        // eBPF-for-Windows GA requires Win11 22H2+ (build 22621+)
        v.ebpf_supported   = (build >= WIN11_22H2_BUILD);
        v.etw_ti_supported = true;
        v.coverage = v.ebpf_supported
                     ? CoverageLevel::FULL
                     : CoverageLevel::STANDARD;
        return v;
    }

    // ── Windows Server 2022 ───────────────────────────────────────────────
    if (major == 10 && minor == 0 && build >= SERVER_2022_BUILD) {
        v.display_name     = "Windows Server 2022";
        v.ebpf_supported   = true;
        v.etw_ti_supported = true;
        v.coverage         = CoverageLevel::FULL;
        return v;
    }

    // ── Windows 10 / Server 2019 ──────────────────────────────────────────
    if (major == 10 && minor == 0) {

        if (build >= WIN10_22H2_BUILD) {
            v.display_name = "Windows 10 22H2";
        } else if (build >= WIN10_21H2_BUILD) {
            v.display_name = "Windows 10 21H2";
        } else if (build >= SERVER_2019_BUILD) {
            v.display_name = "Windows Server 2019 / Windows 10 1809";
        } else if (build >= WIN10_RS3_BUILD) {
            v.display_name = "Windows 10 Fall Creators Update+";
        } else {
            v.display_name = "Windows 10 (early build)";
        }

        v.ebpf_supported   = false;
        v.etw_ti_supported = (build >= WIN10_RS3_BUILD);
        v.coverage         = CoverageLevel::STANDARD;
        return v;
    }

    v.display_name     = "Unsupported Windows version";
    v.ebpf_supported   = false;
    v.etw_ti_supported = false;
    v.coverage         = CoverageLevel::UNKNOWN;
    return v;
}
