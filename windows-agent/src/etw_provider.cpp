// STATUS: 100% — ETW-TI session, process/network/TI events, randomised session
//                name, watchdog auto-restart, V0-compatible ghost_event_t output
// etw_provider.cpp
// GhostIT C9 — ETW Threat Intelligence Provider (Second Kernel Layer)
// Ghost Layer Technologies · Chennai · June 2026
//
// Build: x86_64-w64-mingw32-g++ -std=c++17 -O2 -c etw_provider.cpp -I. -ltdh -lsecur32 -lole32
// Privilege: needs SeSecurityPrivilege — run as LOCAL SYSTEM via Windows service

#include "etw_provider.h"
#include "event_serializer.h"

#include <sddl.h>
#include <psapi.h>

#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <algorithm>
#include <cstring>

thread_local EtwProvider* EtwProvider::tl_instance_ = nullptr;

EtwProvider::EtwProvider(EtwEventCallback on_event)
    : on_event_(std::move(on_event))
    , session_handle_(INVALID_PROCESSTRACE_HANDLE)
    , consumer_handle_(INVALID_PROCESSTRACE_HANDLE)
    , running_(false)
    , watchdog_running_(false)
    , events_captured_(0)
{
}

EtwProvider::~EtwProvider()
{
    stop();
}

bool EtwProvider::start()
{
    std::lock_guard<std::mutex> lk(session_mutex_);
    if (running_) return true;

    session_name_ = generate_session_name();
    std::cout << "[GhostIT ETW] Starting session: " << session_name_ << "\n";

    if (!open_session()) {
        std::cerr << "[GhostIT ETW] Failed to open ETW session.\n";
        return false;
    }
    if (!enable_providers()) {
        std::cerr << "[GhostIT ETW] Failed to enable ETW providers.\n";
        close_session();
        return false;
    }

    running_          = true;
    watchdog_running_ = true;

    processing_thread_ = std::thread(&EtwProvider::processing_loop, this);
    watchdog_thread_   = std::thread(&EtwProvider::watchdog_loop,   this);

    std::cout << "[GhostIT ETW] Session active — consuming ETW-TI events.\n";
    return true;
}

void EtwProvider::stop()
{
    watchdog_running_ = false;
    running_          = false;

    {
        std::lock_guard<std::mutex> lk(session_mutex_);
        close_session();
    }

    if (processing_thread_.joinable()) processing_thread_.join();
    if (watchdog_thread_.joinable())   watchdog_thread_.join();

    std::cout << "[GhostIT ETW] Session stopped. Events captured: "
              << events_captured_.load() << "\n";
}

bool EtwProvider::is_running() const { return running_.load(); }
std::string EtwProvider::session_name() const { return session_name_; }
uint64_t EtwProvider::events_captured() const { return events_captured_.load(); }

bool EtwProvider::open_session()
{
    const size_t name_len = (session_name_.size() + 1) * sizeof(wchar_t);
    const size_t props_sz = sizeof(EVENT_TRACE_PROPERTIES) + name_len;

    auto props_buf = std::vector<BYTE>(props_sz, 0);
    auto* props    = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buf.data());

    props->Wnode.BufferSize    = static_cast<ULONG>(props_sz);
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->BufferSize          = 64;
    props->MinimumBuffers      = 4;
    props->MaximumBuffers      = 64;
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

    std::wstring wname(session_name_.begin(), session_name_.end());
    wcscpy_s(
        reinterpret_cast<wchar_t*>(props_buf.data() + props->LoggerNameOffset),
        session_name_.size() + 1,
        wname.c_str()
    );

    ULONG status = StartTraceW(&session_handle_, wname.c_str(), props);
    if (status == ERROR_ALREADY_EXISTS) {
        StopTraceW(session_handle_, wname.c_str(), props);
        status = StartTraceW(&session_handle_, wname.c_str(), props);
    }
    if (status != ERROR_SUCCESS) {
        std::cerr << "[GhostIT ETW] StartTrace failed: " << status << "\n";
        if (status == ERROR_ACCESS_DENIED)
            std::cerr << "[GhostIT ETW] Needs SeSecurityPrivilege "
                      << "(run as LOCAL SYSTEM via Windows service).\n";
        return false;
    }

    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName          = const_cast<LPWSTR>(wname.c_str());
    logfile.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME |
                                  PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = &EtwProvider::etw_event_callback;

    consumer_handle_ = OpenTraceW(&logfile);
    if (consumer_handle_ == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "[GhostIT ETW] OpenTrace failed: " << GetLastError() << "\n";
        return false;
    }
    return true;
}

bool EtwProvider::enable_providers()
{
    ULONG status = EnableTraceEx2(
        session_handle_, &GHOST_ETW_TI_PROVIDER,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE, 0x141F, 0, 0, nullptr);
    if (status != ERROR_SUCCESS)
        std::cerr << "[GhostIT ETW] ETW-TI enable failed: " << status
                  << " (non-fatal on Win10)\n";

    status = EnableTraceEx2(
        session_handle_, &GHOST_ETW_KERNEL_PROCESS,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE, 0xFFFF, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[GhostIT ETW] Kernel-Process enable failed: " << status << "\n";
        return false;
    }

    status = EnableTraceEx2(
        session_handle_, &GHOST_ETW_KERNEL_NETWORK,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE, 0xFFFF, 0, 0, nullptr);
    if (status != ERROR_SUCCESS)
        std::cerr << "[GhostIT ETW] Kernel-Network enable failed: " << status
                  << " (non-fatal)\n";

    std::cout << "[GhostIT ETW] Providers enabled: TI + Kernel-Process + Kernel-Network\n";
    return true;
}

void EtwProvider::close_session()
{
    if (consumer_handle_ != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(consumer_handle_);
        consumer_handle_ = INVALID_PROCESSTRACE_HANDLE;
    }
    if (session_handle_ != INVALID_PROCESSTRACE_HANDLE) {
        const size_t props_sz = sizeof(EVENT_TRACE_PROPERTIES) +
                                (session_name_.size() + 1) * sizeof(wchar_t);
        auto props_buf = std::vector<BYTE>(props_sz, 0);
        auto* props    = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buf.data());
        props->Wnode.BufferSize = static_cast<ULONG>(props_sz);
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        std::wstring wname(session_name_.begin(), session_name_.end());
        StopTraceW(session_handle_, wname.c_str(), props);
        session_handle_ = INVALID_PROCESSTRACE_HANDLE;
    }
}

std::string EtwProvider::generate_session_name()
{
    std::mt19937_64 rng(
        std::chrono::steady_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
    std::ostringstream oss;
    oss << "GhostIT-ETW-"
        << std::hex << std::uppercase << std::setfill('0')
        << std::setw(8) << dist(rng);
    return oss.str();
}

void WINAPI EtwProvider::etw_event_callback(PEVENT_RECORD record)
{
    if (tl_instance_) tl_instance_->dispatch_event(record);
}

void EtwProvider::dispatch_event(PEVENT_RECORD record)
{
    if (!record) return;

    ghost_event_t evt{};
    bool parsed = false;

    const GUID& prov = record->EventHeader.ProviderId;

    if (IsEqualGUID(prov, GHOST_ETW_TI_PROVIDER))
        parsed = parse_ti_event(record, evt);
    else if (IsEqualGUID(prov, GHOST_ETW_KERNEL_PROCESS)) {
        if (record->EventHeader.EventDescriptor.Id == ETW_IMAGE_LOAD)
            parsed = parse_image_load(record, evt);
        else
            parsed = parse_process_event(record, evt);
    } else if (IsEqualGUID(prov, GHOST_ETW_KERNEL_NETWORK))
        parsed = parse_network_event(record, evt);

    if (parsed) {
        evt.flags |= GHOST_FLAG_ETW_SOURCE;
        ++events_captured_;
        if (on_event_) on_event_(evt);
    }
}

void EtwProvider::fill_common_fields(PEVENT_RECORD record, ghost_event_t& evt)
{
    ULARGE_INTEGER ft;
    ft.LowPart  = record->EventHeader.TimeStamp.LowPart;
    ft.HighPart = static_cast<ULONG>(record->EventHeader.TimeStamp.HighPart);
    evt.ts  = (ft.QuadPart - 116444736000000000ULL) * 100;
    evt.pid = record->EventHeader.ProcessId;
    evt.tid = record->EventHeader.ThreadId;
}

bool EtwProvider::parse_process_event(PEVENT_RECORD record, ghost_event_t& out)
{
    USHORT event_id = record->EventHeader.EventDescriptor.Id;
    fill_common_fields(record, out);

    switch (event_id) {
    case ETW_PROCESS_CREATE:
        out.type = GHOST_EVENT_PROCESS_EXEC;
        out.ppid = read_property_ulong(record, L"ParentProcessID");
        {
            std::string img  = wstr_to_utf8(read_property_wstr(record, L"ImageName"));
            std::string args = wstr_to_utf8(read_property_wstr(record, L"CommandLine"));
            strncpy_s(out.comm, sizeof(out.comm), img.c_str(),  _TRUNCATE);
            strncpy_s(out.args, sizeof(out.args), args.c_str(), _TRUNCATE);
        }
        return true;
    case ETW_PROCESS_TERMINATE:
        out.type = GHOST_EVENT_PROCESS_EXIT;
        return true;
    case ETW_THREAD_CREATE:
        out.type = GHOST_EVENT_THREAD_CREATE;
        return true;
    default:
        return false;
    }
}

bool EtwProvider::parse_network_event(PEVENT_RECORD record, ghost_event_t& out)
{
    USHORT event_id = record->EventHeader.EventDescriptor.Id;
    if (event_id != ETW_NETWORK_CONNECT && event_id != ETW_NETWORK_ACCEPT)
        return false;

    fill_common_fields(record, out);
    out.type   = GHOST_EVENT_NET_CONNECT;
    out.dport  = static_cast<uint16_t>(read_property_ulong(record, L"dport"));
    out.sport  = static_cast<uint16_t>(read_property_ulong(record, L"sport"));
    out.family = static_cast<uint16_t>(read_property_ulong(record, L"AddressFamily"));

    std::string da = wstr_to_utf8(read_property_wstr(record, L"daddr"));
    strncpy_s(out.daddr, sizeof(out.daddr), da.c_str(), _TRUNCATE);
    return true;
}

bool EtwProvider::parse_ti_event(PEVENT_RECORD record, ghost_event_t& out)
{
    USHORT event_id = record->EventHeader.EventDescriptor.Id;
    fill_common_fields(record, out);

    switch (event_id) {
    case ETW_TI_ALLOCEXEC:
        out.type   = GHOST_EVENT_MEM_EXEC_ALLOC;
        out.flags |= GHOST_FLAG_CRITICAL;
        return true;
    case ETW_TI_MAPEXEC:
        out.type   = GHOST_EVENT_MEM_EXEC_MAP;
        out.flags |= GHOST_FLAG_CRITICAL;
        return true;
    case ETW_TI_QUEUEAPC:
        out.type   = GHOST_EVENT_APC_INJECT;
        out.flags |= GHOST_FLAG_CRITICAL;
        return true;
    case ETW_TI_SETTHREADCTX:
        out.type   = GHOST_EVENT_THREAD_CTX_SET;
        out.flags |= GHOST_FLAG_CRITICAL;
        return true;
    default:
        return false;
    }
}

bool EtwProvider::parse_image_load(PEVENT_RECORD record, ghost_event_t& out)
{
    fill_common_fields(record, out);
    out.type = GHOST_EVENT_FILE_OPEN;

    std::string s = wstr_to_utf8(read_property_wstr(record, L"ImageName"));
    strncpy_s(out.path, sizeof(out.path), s.c_str(), _TRUNCATE);

    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find("\\temp\\")      != std::string::npos ||
        lower.find("\\appdata\\")   != std::string::npos ||
        lower.find("\\downloads\\") != std::string::npos)
        out.flags |= GHOST_FLAG_CRITICAL;

    return true;
}

std::wstring EtwProvider::read_property_wstr(PEVENT_RECORD record,
                                              const wchar_t* prop_name)
{
    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(prop_name);
    desc.ArrayIndex   = ULONG_MAX;

    ULONG buf_size = 0;
    TdhGetPropertySize(record, 0, nullptr, 1, &desc, &buf_size);
    if (buf_size == 0) return L"";

    std::vector<BYTE> buf(buf_size, 0);
    if (TdhGetProperty(record, 0, nullptr, 1, &desc, buf_size, buf.data())
        != ERROR_SUCCESS) return L"";

    return std::wstring(reinterpret_cast<wchar_t*>(buf.data()));
}

ULONG EtwProvider::read_property_ulong(PEVENT_RECORD record,
                                        const wchar_t* prop_name)
{
    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(prop_name);
    desc.ArrayIndex   = ULONG_MAX;

    ULONG value    = 0;
    ULONG buf_size = sizeof(ULONG);
    TdhGetProperty(record, 0, nullptr, 1, &desc,
                   buf_size, reinterpret_cast<PBYTE>(&value));
    return value;
}

std::string EtwProvider::wstr_to_utf8(const std::wstring& ws)
{
    if (ws.empty()) return "";
    int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                                 nullptr, 0, nullptr, nullptr);
    if (sz <= 0) return "";
    std::string out(sz - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                        &out[0], sz, nullptr, nullptr);
    return out;
}

void EtwProvider::processing_loop()
{
    tl_instance_ = this;
    std::cout << "[GhostIT ETW] ProcessTrace() thread started.\n";

    ULONG status = ProcessTrace(&consumer_handle_, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS && running_)
        std::cerr << "[GhostIT ETW] ProcessTrace() exited: " << status << "\n";

    tl_instance_ = nullptr;
    std::cout << "[GhostIT ETW] ProcessTrace() thread exiting.\n";
}

void EtwProvider::watchdog_loop()
{
    std::cout << "[GhostIT ETW] Watchdog thread started.\n";

    while (watchdog_running_) {
        for (int i = 0; i < 5 && watchdog_running_; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!watchdog_running_) break;

        std::wstring wname(session_name_.begin(), session_name_.end());
        const size_t props_sz = sizeof(EVENT_TRACE_PROPERTIES) +
                                (session_name_.size() + 1) * sizeof(wchar_t);
        auto props_buf = std::vector<BYTE>(props_sz, 0);
        auto* props    = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buf.data());
        props->Wnode.BufferSize = static_cast<ULONG>(props_sz);
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ULONG status = QueryTraceW(session_handle_, wname.c_str(), props);
        if (status == ERROR_WMI_INSTANCE_NOT_FOUND ||
            status == ERROR_BAD_LENGTH)
        {
            std::cerr << "[GhostIT ETW] ALERT: session killed externally — "
                      << "possible attacker tampering. Restarting…\n";
            {
                std::lock_guard<std::mutex> lk(session_mutex_);
                close_session();
                session_name_ = generate_session_name();
                std::cout << "[GhostIT ETW] New session: " << session_name_ << "\n";
                if (open_session() && enable_providers()) {
                    if (processing_thread_.joinable())
                        processing_thread_.join();
                    processing_thread_ = std::thread(
                        &EtwProvider::processing_loop, this);
                    std::cout << "[GhostIT ETW] Session restarted.\n";
                } else {
                    std::cerr << "[GhostIT ETW] Restart failed.\n";
                }
            }
        }
    }
    std::cout << "[GhostIT ETW] Watchdog thread exiting.\n";
}
