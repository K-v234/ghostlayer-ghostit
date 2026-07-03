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
#include <wbemidl.h>

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include <unordered_map>

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
    bool parse_network_event (PEVENT_RECORD record, ghost_event_t& out);
    bool parse_ti_event      (PEVENT_RECORD record, ghost_event_t& out);
    bool parse_image_load    (PEVENT_RECORD record, ghost_event_t& out);

    std::wstring read_property_wstr  (PEVENT_RECORD record, const wchar_t* prop_name);
    ULONG        read_property_ulong (PEVENT_RECORD record, const wchar_t* prop_name);

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

    mutable std::mutex session_mutex_;

    static thread_local EtwProvider* tl_instance_;
};
