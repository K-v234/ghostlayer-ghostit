// STATUS: 100% — header complete
// etw_provider.h
// GhostIT C9 — ETW Threat Intelligence Provider (Second Kernel Layer)
// Captures process/network/file events via ETW-TI before userspace can interfere
// Compatible: Windows 10 RS3+ / Windows 11 22H2+
// Ghost Layer Technologies · Chennai · June 2026

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <wintrust.h>
#include <softpub.h>
#include <winternl.h>

// MinGW-w64's tdh.h omits TdhFormatProperty despite the symbol existing
// in libtdh.a (confirmed via nm). Manual prototype matching the real
// Windows SDK signature — __stdcall to match TdhGetProperty's convention
// in this same header.
extern "C" ULONG __stdcall TdhFormatProperty(
    PTRACE_EVENT_INFO EventInfo, PEVENT_MAP_INFO MapInfo, ULONG PointerSize,
    USHORT PropertyInType, USHORT PropertyOutType, USHORT PropertyLength,
    USHORT UserDataLength, PBYTE UserData,
    PULONG BufferSize, PWCHAR Buffer, PUSHORT UserDataConsumed);



#include <wbemidl.h>

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include <unordered_map>
#include <queue>
#include <condition_variable>

#include "ghost_event.h"

static const GUID GHOST_ETW_TI_PROVIDER = {
    0xF4E1897C, 0xBB5D, 0x5668,
    { 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 }
};

static const GUID GHOST_ETW_KERNEL_PROCESS = {
    0x22FB2CD6, 0x0E7B, 0x422B,
    { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 }
};

static const GUID GHOST_ETW_KERNEL_NETWORK = {
    0x7DD42A49, 0x5329, 0x4832,
    { 0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88 }
};

// Microsoft-Windows-Kernel-File — needed for real file write/delete events.
// Kernel-Process only surfaces file OPEN activity; write/delete require
// this separate provider. Missing until now — C15 ransomware detection
// received zero real Windows file-modification signal as a result.
static const GUID GHOST_ETW_KERNEL_FILE = {
    0xEDD08927, 0x9CC4, 0x4E65,
    { 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89 }
};

static constexpr USHORT ETW_PROCESS_CREATE     = 1;
static constexpr USHORT ETW_PROCESS_TERMINATE  = 2;
static constexpr USHORT ETW_THREAD_CREATE      = 3;
static constexpr USHORT ETW_IMAGE_LOAD         = 5;
static constexpr USHORT ETW_NETWORK_CONNECT    = 12;
static constexpr USHORT ETW_NETWORK_ACCEPT     = 14;
static constexpr USHORT ETW_TI_ALLOCEXEC       = 1;
static constexpr USHORT ETW_TI_MAPEXEC         = 3;
static constexpr USHORT ETW_TI_QUEUEAPC        = 5;
static constexpr USHORT ETW_TI_SETTHREADCTX    = 7;

using EtwEventCallback = std::function<void(const ghost_event_t&)>;

class EtwProvider {
public:
    explicit EtwProvider(EtwEventCallback on_event);
    ~EtwProvider();

    EtwProvider(const EtwProvider&)            = delete;
    EtwProvider& operator=(const EtwProvider&) = delete;

    bool start();
    void stop();

    bool        is_running()       const;
    std::string session_name()     const;
    uint64_t    events_captured()  const;

private:
    bool open_session();
    bool enable_providers();
    void close_session();

    static std::string generate_session_name();

    static void WINAPI etw_event_callback(PEVENT_RECORD record);
    void dispatch_event(PEVENT_RECORD record);

    bool parse_process_event (PEVENT_RECORD record, ghost_event_t& out);
    // Background-refreshed pid->ppid cache (see etw_provider.cpp) --
    // avoids calling CreateToolhelp32Snapshot synchronously inside the
    // ETW callback, which was confirmed to stall event delivery entirely.
    void start_ppid_cache_thread();

    // Permanent process-identity resolution — Win32 API, not ETW payload
    // parsing. Stable since Vista, immune to ETW schema/version differences
    // across Windows builds. Replaces trying to parse ImageName out of
    // ProcessStart's ambiguous, version-fragile schema.
    std::wstring resolve_process_name(DWORD pid);
    bool is_sane_process_name(const std::string& s);

    // FileObject/FileKey -> real path cache. Kernel-File's Write/SetDelete/
    // Rename events only carry an opaque FileKey, never the filename
    // directly — the filename only appears in NameCreate, which fires when
    // a file handle is first opened. This mirrors how Sysmon/Procmon-style
    // tools resolve file identity: cache on NameCreate, look up on
    // Write/Delete/Rename by the same FileKey.
    std::unordered_map<ULONGLONG, std::wstring> file_key_cache_;
    // Persistence for file_key_cache_ across agent restarts -- see
    // implementation in etw_provider.cpp for full rationale
    // (RENAME-DETECTION-CACHE-FRAGILITY-01).
    void save_file_key_cache();
    void load_file_key_cache();

    // C15 Tier 2 noise reduction: process trust scoring via Authenticode
    // signature verification. Signed, trusted-publisher processes (Google,
    // Microsoft, etc.) writing to user-data directories get reduced
    // ransomware-relevance weight; unsigned/unknown processes get full
    // weight. This mirrors how CrowdStrike/SentinelOne reduce false
    // positives from legitimate high-volume writers (browsers, sync
    // clients) without maintaining an ever-growing app-name blocklist.
    std::unordered_map<DWORD, uint8_t> pid_trust_cache_;
    std::mutex pid_trust_cache_mutex_;
    static constexpr size_t PID_TRUST_CACHE_MAX = 2000;

    uint8_t check_process_trust(DWORD pid);

    // Command-line capture via PEB reading. Kernel-Process's ProcessStart
    // event does not expose CommandLine in its standard schema (confirmed
    // empty on real events), and ETW-TI (which would provide it) is
    // permanently blocked without Microsoft ELAM/PPL certification.
    // PEB reading is the correct, independent alternative -- same
    // technique used by Task Manager, Process Explorer, and most EDR
    // agents to retrieve a running process's command line.
    std::wstring read_process_cmdline(DWORD pid);
    std::mutex file_key_cache_mutex_;
    static constexpr size_t FILE_KEY_CACHE_MAX = 10000;

    bool parse_file_event(PEVENT_RECORD record, ghost_event_t& out);
    bool parse_network_event (PEVENT_RECORD record, ghost_event_t& out);
    bool parse_ti_event      (PEVENT_RECORD record, ghost_event_t& out);
    bool parse_image_load    (PEVENT_RECORD record, ghost_event_t& out);

    std::wstring read_property_wstr  (PEVENT_RECORD record, const wchar_t* prop_name);
    ULONG        read_property_ulong (PEVENT_RECORD record, const wchar_t* prop_name);
    ULONGLONG    read_property_ulong64(PEVENT_RECORD record, const wchar_t* prop_name);

    static std::string wstr_to_utf8(const std::wstring& ws);
    void fill_common_fields(PEVENT_RECORD record, ghost_event_t& evt);

    void watchdog_loop();
    void processing_loop();

    EtwEventCallback   on_event_;
    std::string        session_name_;
    std::wstring       session_wname_;  // persistent wide string for OpenTrace

    TRACEHANDLE        session_handle_;
    TRACEHANDLE        consumer_handle_;

    std::atomic<bool>     running_;
    std::atomic<bool>     watchdog_running_;
    std::atomic<uint64_t> events_captured_;

    std::thread        processing_thread_;
    std::thread        watchdog_thread_;

    // Deferred ppid enrichment: ProcessStart events are queued here
    // instead of being forwarded immediately from the ETW callback
    // thread. A separate worker thread drains this queue, fills in
    // ppid from a periodically-refreshed snapshot map, and forwards
    // from there -- keeping the time-critical ProcessTrace() thread
    // completely free of any blocking work (confirmed necessary: any
    // extra work on that thread, even a lock wait, caused ETW to
    // silently drop events under backpressure).
    std::mutex              ppid_queue_mutex_;
    std::queue<ghost_event_t> ppid_queue_;
    std::condition_variable ppid_queue_cv_;
    std::atomic<bool>       ppid_worker_running_{false};
    std::thread             ppid_worker_thread_;
    void ppid_worker_loop();
    void enqueue_for_ppid_enrichment(ghost_event_t evt);

    mutable std::mutex session_mutex_;

    static thread_local EtwProvider* tl_instance_;
};
