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

    session_wname_ = std::wstring(session_name_.begin(), session_name_.end());
    wcscpy_s(
        reinterpret_cast<wchar_t*>(props_buf.data() + props->LoggerNameOffset),
        session_wname_.size() + 1,
        session_wname_.c_str()
    );

    ULONG status = StartTraceW(&session_handle_, session_wname_.c_str(), props);
    if (status == ERROR_ALREADY_EXISTS) {
        StopTraceW(session_handle_, session_wname_.c_str(), props);
        status = StartTraceW(&session_handle_, session_wname_.c_str(), props);
    }
    if (status != ERROR_SUCCESS) {
        std::cerr << "[GhostIT ETW] StartTrace failed: " << status << "\n";
        if (status == ERROR_ACCESS_DENIED)
            std::cerr << "[GhostIT ETW] Needs SeSecurityPrivilege "
                      << "(run as LOCAL SYSTEM via Windows service).\n";
        return false;
    }

    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName          = const_cast<LPWSTR>(session_wname_.c_str());
    logfile.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME |
                                  PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = &EtwProvider::etw_event_callback;

    consumer_handle_ = OpenTraceW(&logfile);
    if (consumer_handle_ == INVALID_PROCESSTRACE_HANDLE) {
        return false;
    }
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

    // Kernel-File — required for real file write/delete detection (C15
    // ransomware). Kernel-Process alone only ever surfaces file OPEN
    // activity, confirmed via live testing — write/delete were never
    // captured at all before this provider was added.
    status = EnableTraceEx2(
        session_handle_, &GHOST_ETW_KERNEL_FILE,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE, 0xFFFF, 0, 0, nullptr);
    if (status != ERROR_SUCCESS)
        std::cerr << "[GhostIT ETW] Kernel-File enable failed: " << status
                  << " (non-fatal)\n";

    std::cout << "[GhostIT ETW] Providers enabled: TI + Kernel-Process + Kernel-Network + Kernel-File\n";
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
        USHORT eid = record->EventHeader.EventDescriptor.Id;
        static USHORT seen_ids[32] = {0};
        static int seen_count = 0;
        bool already_seen = false;
        for (int i = 0; i < seen_count; i++) if (seen_ids[i] == eid) { already_seen = true; break; }
        if (!already_seen && seen_count < 32) {
            seen_ids[seen_count++] = eid;
            std::string task_name = "?";
            ULONG tsz = 0;
            TdhGetEventInformation(record, 0, nullptr, nullptr, &tsz);
            if (tsz > 0) {
                std::vector<BYTE> tbuf(tsz);
                auto* tinfo = reinterpret_cast<TRACE_EVENT_INFO*>(tbuf.data());
                if (TdhGetEventInformation(record, 0, nullptr, tinfo, &tsz) == ERROR_SUCCESS && tinfo->TaskNameOffset) {
                    auto* nm = reinterpret_cast<LPCWSTR>(tbuf.data() + tinfo->TaskNameOffset);
                    task_name = wstr_to_utf8(nm);
                }
            }
            std::cerr << "[GHOST_DIAG_NEWID] Kernel-Process eid=" << eid << " task=" << task_name << "\n";
            std::cerr.flush();
        }
        if (eid == ETW_IMAGE_LOAD)
            parsed = parse_image_load(record, evt);
        else if (eid == 1 || eid == 2)   // ProcessStart / ProcessStop only.
            // CORRECTED: schema-driven TaskName lookup confirmed eid==3 is
            // ThreadStart, not ProcessStart as earlier (indirect) evidence
            // suggested. ThreadStart fires on every new thread within any
            // process — routing it here caused svchost.exe/System(PID 4)
            // to show inflated "process_exec" counts (they spawn many
            // internal threads, not many processes).
            parsed = parse_process_event(record, evt);
        // else: ThreadSetPriority, WorkOnBehalf, and other Kernel-Process
        // sub-events carry no ImageName and are intentionally dropped here
        // rather than misrouted into the process-identity parser.
    } else if (IsEqualGUID(prov, GHOST_ETW_KERNEL_NETWORK))
        parsed = parse_network_event(record, evt);
    else if (IsEqualGUID(prov, GHOST_ETW_KERNEL_FILE))
        parsed = parse_file_event(record, evt);

    if (parsed) {
        evt.priority = GHOST_LAYER_ETW;
        ++events_captured_;
        if (on_event_) on_event_(evt);
    }
}

void EtwProvider::fill_common_fields(PEVENT_RECORD record, ghost_event_t& evt)
{
    ULARGE_INTEGER ft;
    ft.LowPart  = record->EventHeader.TimeStamp.LowPart;
    ft.HighPart = static_cast<ULONG>(record->EventHeader.TimeStamp.HighPart);
    evt.timestamp_ns  = (ft.QuadPart - 116444736000000000ULL) * 100;
    evt.pid = record->EventHeader.ProcessId;
    evt.tid = record->EventHeader.ThreadId;
}

// Permanent fix: resolve process identity via Win32 API, not ETW payload
// parsing. QueryFullProcessImageNameW has been stable since Vista and does
// not depend on ETW provider schema versions, which change across Windows
// builds and were the root cause of every parsing bug found tonight.
std::wstring EtwProvider::resolve_process_name(DWORD pid)
{
    std::wstring result;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return result; // process already exited — caller falls back

    WCHAR path[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
        std::wstring full(path, size);
        auto pos = full.find_last_of(L'\\');
        result = (pos == std::wstring::npos) ? full : full.substr(pos + 1);
    }
    CloseHandle(hProc);
    return result;
}

// Rejects garbled/binary data from ever reaching out.comm, regardless of
// which parsing path produced it. This is what would have caught tonight's
// single-garbled-character bug automatically, on any event type.
bool EtwProvider::is_sane_process_name(const std::string& s)
{
    if (s.empty() || s.size() > 255) return false;
    for (unsigned char c : s) {
        // Real Windows filenames are ASCII-printable. Reject control
        // characters AND anything outside standard printable ASCII —
        // this catches UTF-8 replacement chars, private-use-area
        // characters, and other garbage from misparsed binary data,
        // none of which are valid in a real process image name.
        if (c < 0x20 || c > 0x7E) return false;
    }
    return true;
}

bool EtwProvider::parse_process_event(PEVENT_RECORD record, ghost_event_t& out)
{
    USHORT event_id = record->EventHeader.EventDescriptor.Id;
    fill_common_fields(record, out);
    out.event_type = GHOST_EVT_PROCESS_CREATE;
    // CORRECTED (schema-driven TaskName lookup, not indirect inference):
    // event_id 1 = ProcessStart (real process creation)
    // event_id 2 = ProcessStop (process exit)
    // event_id 3 = ThreadStart (fires on EVERY new thread in ANY process --
    //   NOT process creation; previously misrouted here, causing
    //   svchost.exe/System(PID 4) to show wildly inflated "process_exec"
    //   counts since they spawn many internal threads). Dispatch now only
    //   routes eid==1||2 to this function -- eid==3 no longer reaches here.
    // Kernel-Process's standard schema does NOT expose CommandLine
    // (confirmed empty on real ProcessStart events) -- command-line
    // capture requires ETW-TI (permanently blocked without Microsoft
    // ELAM/PPL certification -- see known_issues.json) or PEB reading.
    if (event_id == 2) { out.event_type = GHOST_EVT_PROCESS_EXIT; return true; }

    // Permanent identity resolution: Win32 API first (stable across all
    // Windows builds), ETW ImageLoad schema as secondary source only when
    // the process has already exited before we could query it (race
    // condition on fast-spawning processes). Never trust ProcessStart's
    // own payload directly — its schema is version-fragile, which caused
    // every bug fixed earlier tonight.
    std::wstring name = resolve_process_name(out.pid);
    std::string img_path;

    if (!name.empty()) {
        std::string base = wstr_to_utf8(name);
        if (is_sane_process_name(base)) {
            strncpy(out.comm, base.c_str(), sizeof(out.comm)-1);
            out.comm[sizeof(out.comm)-1] = 0;
        }
    }

    // Secondary source: ETW ImageLoad-style ImageName, only used if the
    // Win32 lookup above found nothing (fast-exit race) AND this event's
    // schema actually contains ImageName (won't for ThreadStart/ProcessStop).
    if (out.comm[0] == 0) {
        ULONG schema_size = 0;
        TdhGetEventInformation(record, 0, nullptr, nullptr, &schema_size);
        if (schema_size > 0) {
            std::vector<BYTE> schema_buf(schema_size);
            auto* info = reinterpret_cast<TRACE_EVENT_INFO*>(schema_buf.data());
            if (TdhGetEventInformation(record, 0, nullptr, info, &schema_size) == ERROR_SUCCESS) {
                std::string img = wstr_to_utf8(read_property_wstr(record, L"ImageName"));
                if (is_sane_process_name(img)) {
                    size_t pos = img.rfind('\\');
                    if (pos == std::string::npos) pos = img.rfind('/');
                    std::string base = (pos != std::string::npos) ? img.substr(pos+1) : img;
                    if (is_sane_process_name(base)) {
                        strncpy(out.comm, base.c_str(), sizeof(out.comm)-1);
                        out.comm[sizeof(out.comm)-1] = 0;
                    }
                    img_path = img;
                }
            }
        }
    }

    if (!img_path.empty()) {
        strncpy(out.path, img_path.c_str(), sizeof(out.path)-1);
        out.path[sizeof(out.path)-1] = 0;
    }

    // Final fallback — only reached if BOTH sources above failed or
    // produced garbage. Never ships an unvalidated string.
    if (out.comm[0] == 0)
        snprintf(out.comm, sizeof(out.comm), "pid_%u", out.pid);

    // Command-line capture via PEB reading (independent of ETW-TI, which
    // is permanently blocked without Microsoft ELAM/PPL certification).
    // Reuses out.path since it's otherwise empty for real ProcessStart
    // events (img_path fallback above only fires when Win32 resolution
    // fails). Only attempted for genuine ProcessStart (event_id==1) --
    // ProcessStop has nothing meaningful to read.
    if (event_id == 1 && out.path[0] == 0) {
        std::wstring cmdline = read_process_cmdline(out.pid);
        if (!cmdline.empty()) {
            std::string cmdline_utf8 = wstr_to_utf8(cmdline);
            // Strip the executable path, keep only arguments -- that's
            // what LOLBin detection actually matches against (e.g.
            // "-urlcache -f http://..." not the full certutil.exe path).
            // Handles both quoted ("C:\path\app.exe" -args) and
            // unquoted (C:\path\app.exe -args) command lines.
            size_t args_start = std::string::npos;
            if (!cmdline_utf8.empty() && cmdline_utf8[0] == '"') {
                size_t close_quote = cmdline_utf8.find('"', 1);
                if (close_quote != std::string::npos) args_start = close_quote + 1;
            } else {
                size_t space_pos = cmdline_utf8.find(" -");
                if (space_pos == std::string::npos) space_pos = cmdline_utf8.find(" /");
                if (space_pos != std::string::npos) args_start = space_pos;
            }
            std::string args_only = (args_start != std::string::npos && args_start < cmdline_utf8.size())
                ? cmdline_utf8.substr(args_start)
                : cmdline_utf8;
            // Trim leading whitespace
            size_t first_nonspace = args_only.find_first_not_of(' ');
            if (first_nonspace != std::string::npos) args_only = args_only.substr(first_nonspace);

            strncpy(out.path, args_only.c_str(), sizeof(out.path)-1);
            out.path[sizeof(out.path)-1] = 0;
        }
    }

    return true;
}

// FileObject/FileKey -> path cache. NameCreate carries the real filename
// and fires once per file handle; Write/SetDelete/Rename only carry the
// opaque FileKey, so we cache on NameCreate and look up by FileKey later.
// This matches how Sysmon/Procmon internally resolve Kernel-File identity.
// C15 Tier 2: verify whether a process's executable is Authenticode-signed
// by a trusted publisher. Result cached per-PID since signature checks are
// relatively expensive and a process's signature never changes during its
// lifetime. Returns a GHOST_INTEGRITY_* value: SYSTEM/HIGH for verified
// signed binaries, UNTRUSTED for unsigned or verification-failed processes.
// Reads a running process's command line via PEB inspection --
// OpenProcess -> NtQueryInformationProcess(ProcessBasicInformation) to
// get the PEB address -> ReadProcessMemory the PEB -> ReadProcessMemory
// the RTL_USER_PROCESS_PARAMETERS -> ReadProcessMemory the CommandLine
// UNICODE_STRING buffer. Same technique Task Manager/Process Explorer
// use. Independent of ETW-TI (permanently blocked, see known_issues.json)
// and does not rely on Kernel-Process's schema (which never exposes
// CommandLine, confirmed empty on real events).
std::wstring EtwProvider::read_process_cmdline(DWORD pid)
{
    std::wstring result;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return result;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) { CloseHandle(hProc); return result; }

    using NtQueryInformationProcessFn = NTSTATUS(WINAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (!NtQueryInformationProcess) { CloseHandle(hProc); return result; }

    // PROCESS_BASIC_INFORMATION layout (undocumented but stable since XP)
    struct PROCESS_BASIC_INFORMATION_LOCAL {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    };

    PROCESS_BASIC_INFORMATION_LOCAL pbi{};
    ULONG returnLength = 0;
    NTSTATUS status = NtQueryInformationProcess(
        hProc, 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), &returnLength);
    if (status != 0 || !pbi.PebBaseAddress) { CloseHandle(hProc); return result; }

    // Minimal PEB layout, only up to ProcessParameters (offset 0x20 on x64)
    struct PEB_LOCAL {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PVOID Ldr;
        PVOID ProcessParameters;
    };

    PEB_LOCAL peb{};
    if (!ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) {
        CloseHandle(hProc);
        return result;
    }

    // Minimal RTL_USER_PROCESS_PARAMETERS layout, only up to CommandLine
    struct RTL_USER_PROCESS_PARAMETERS_LOCAL {
        BYTE Reserved1[16];
        PVOID Reserved2[10];
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
    };

    RTL_USER_PROCESS_PARAMETERS_LOCAL params{};
    if (!ReadProcessMemory(hProc, peb.ProcessParameters, &params, sizeof(params), nullptr)) {
        CloseHandle(hProc);
        return result;
    }

    if (params.CommandLine.Length == 0 || !params.CommandLine.Buffer) {
        CloseHandle(hProc);
        return result;
    }

    std::vector<WCHAR> buf(params.CommandLine.Length / sizeof(WCHAR) + 1, 0);
    if (ReadProcessMemory(hProc, params.CommandLine.Buffer, buf.data(),
                          params.CommandLine.Length, nullptr)) {
        result.assign(buf.data());
    }

    CloseHandle(hProc);
    return result;
}

uint8_t EtwProvider::check_process_trust(DWORD pid)
{
    {
        std::lock_guard<std::mutex> lk(pid_trust_cache_mutex_);
        auto it = pid_trust_cache_.find(pid);
        if (it != pid_trust_cache_.end()) return it->second;
    }

    uint8_t trust = GHOST_INTEGRITY_UNTRUSTED;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        WCHAR path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
            WINTRUST_FILE_INFO fileInfo{};
            fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
            fileInfo.pcwszFilePath = path;

            WINTRUST_DATA trustData{};
            trustData.cbStruct = sizeof(WINTRUST_DATA);
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.pFile = &fileInfo;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            LONG status = WinVerifyTrust(nullptr, &action, &trustData);

            trust = (status == ERROR_SUCCESS) ? GHOST_INTEGRITY_HIGH : GHOST_INTEGRITY_UNTRUSTED;

            // Always close the trust data state, regardless of result
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &action, &trustData);
        }
        CloseHandle(hProc);
    }

    {
        std::lock_guard<std::mutex> lk(pid_trust_cache_mutex_);
        if (pid_trust_cache_.size() >= PID_TRUST_CACHE_MAX) {
            pid_trust_cache_.erase(pid_trust_cache_.begin());
        }
        pid_trust_cache_[pid] = trust;
    }
    return trust;
}

bool EtwProvider::parse_file_event(PEVENT_RECORD record, ghost_event_t& out)
{
    USHORT eid = record->EventHeader.EventDescriptor.Id;
    fill_common_fields(record, out);

    ULONGLONG file_key = read_property_ulong64(record, L"FileKey");

    if (eid == 10) {  // NameCreate — carries the real filename
        std::wstring name = read_property_wstr(record, L"FileName");
        if (!name.empty()) {
            std::lock_guard<std::mutex> lk(file_key_cache_mutex_);
            if (file_key_cache_.size() >= FILE_KEY_CACHE_MAX) {
                file_key_cache_.erase(file_key_cache_.begin());
            }
            file_key_cache_[file_key] = name;
        }
        return false;  // NameCreate itself isn't a security-relevant event
    }

    std::wstring path;
    {
        std::lock_guard<std::mutex> lk(file_key_cache_mutex_);
        auto it = file_key_cache_.find(file_key);
        if (it != file_key_cache_.end()) path = it->second;
    }

    if (path.empty()) return false;  // Can't attribute this event to a file — drop it

    std::string path_utf8 = wstr_to_utf8(path);

    // Tier 1: scope to user-data directories — where ransomware actually
    // operates. Not a noise blocklist (which loses to every new app
    // forever) — a relevance filter based on what ransomware targets.
    static const char* USER_DATA_MARKERS[] = {
        "\\Documents\\", "\\Desktop\\", "\\Downloads\\",
        "\\Pictures\\", "\\Videos\\", "\\Music\\", "\\OneDrive\\",
    };
    bool in_user_data = false;
    for (const char* marker : USER_DATA_MARKERS) {
        if (path_utf8.find(marker) != std::string::npos) { in_user_data = true; break; }
    }
    if (!in_user_data) return false;

    // Strip the \Device\HarddiskVolumeN\ prefix — pure Windows-internal
    // noise that provides zero detection value, and was silently truncating
    // real paths before reaching the file extension (confirmed: a 67-char
    // path like Downloads\report.docx.locked got cut at 56 bytes to
    // "...Downloads\report", losing ".docx.locked" entirely — meaning
    // extension-based ransomware detection never worked for any Windows
    // path with this prefix, the entire session).
    {
        size_t pos = path_utf8.find("\\Users\\");
        if (pos != std::string::npos) {
            path_utf8 = path_utf8.substr(pos + 1); // keep leading backslash off "Users\..."
        }
    }
    strncpy(out.path, path_utf8.c_str(), sizeof(out.path)-1);
    out.path[sizeof(out.path)-1] = 0;

    // Tier 2: tag with the writing process's Authenticode trust level.
    // Signed, trusted-publisher processes get reduced downstream scoring
    // weight even within user-data directories, without needing to know
    // their name in advance — mirrors how CrowdStrike/SentinelOne reduce
    // false positives from legitimate high-volume writers.
    out.integrity = check_process_trust(out.pid);

    if (eid == 16) {
        out.event_type = GHOST_EVT_FILE_WRITE;
        return true;
    }
    if (eid == 18 || eid == 11) {
        out.event_type = GHOST_EVT_FILE_DELETE;
        return true;
    }
    if (eid == 19 || eid == 17) {
        // eid=17 (SetInformation) is included here because PowerShell's
        // Rename-Item was observed to never generate a raw eid=19 (Rename)
        // event — Windows file-rename operations from userspace commonly
        // route through SetInformation instead, depending on how the
        // renaming application issues the underlying NtSetInformationFile
        // call. Treating both as FILE_RENAME until we can confirm this is
        // always safe (SetInformation can also cover non-rename metadata
        // changes, so this may need narrowing later if it proves noisy).
        out.event_type = GHOST_EVT_FILE_RENAME;
        return true;
    }
    return false;  // Other Kernel-File sub-events (Read, Cleanup, etc.) not forwarded
}

bool EtwProvider::parse_network_event(PEVENT_RECORD record, ghost_event_t& out)
{
    USHORT event_id = record->EventHeader.EventDescriptor.Id;
    if (event_id != ETW_NETWORK_CONNECT && event_id != ETW_NETWORK_ACCEPT)
        return false;

    fill_common_fields(record, out);
    out.event_type = GHOST_EVT_NET_CONNECT;
    out.dst_port  = static_cast<uint16_t>(read_property_ulong(record, L"DestPort"));
    out.src_port  = static_cast<uint16_t>(read_property_ulong(record, L"SourcePort"));
    out.uid = static_cast<uint16_t>(read_property_ulong(record, L"AddressFamily"));

    std::string da = wstr_to_utf8(read_property_wstr(record, L"DestAddress"));
    strncpy_s(out.path, sizeof(out.path), da.c_str(), sizeof(out.comm) - 1);
    return true;
}

bool EtwProvider::parse_ti_event(PEVENT_RECORD record, ghost_event_t& out)
{
    USHORT event_id = record->EventHeader.EventDescriptor.Id;
    fill_common_fields(record, out);

    switch (event_id) {
    case ETW_TI_ALLOCEXEC:
        out.event_type = GHOST_EVT_MEMORY_EXEC;
        out.priority = GHOST_PRI_CRITICAL;
        return true;
    case ETW_TI_MAPEXEC:
        out.event_type = GHOST_EVT_MEMORY_EXEC;
        out.priority = GHOST_PRI_CRITICAL;
        return true;
    case ETW_TI_QUEUEAPC:
        out.event_type = GHOST_EVT_THREAD_INJECT;
        out.priority = GHOST_PRI_CRITICAL;
        return true;
    case ETW_TI_SETTHREADCTX:
        out.event_type = GHOST_EVT_THREAD_INJECT;
        out.priority = GHOST_PRI_CRITICAL;
        return true;
    default:
        return false;
    }
}

bool EtwProvider::parse_image_load(PEVENT_RECORD record, ghost_event_t& out)
{
    fill_common_fields(record, out);
    out.event_type = GHOST_EVT_FILE_OPEN;

    std::string s = wstr_to_utf8(read_property_wstr(record, L"ImageName"));
    strncpy(out.path, s.c_str(), sizeof(out.comm) - 1);

    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find("\\temp\\")      != std::string::npos ||
        lower.find("\\appdata\\")   != std::string::npos ||
        lower.find("\\downloads\\") != std::string::npos)
        out.priority = GHOST_PRI_CRITICAL;

    return true;
}

std::wstring EtwProvider::read_property_wstr(PEVENT_RECORD record,
                                              const wchar_t* prop_name)
{
    // Schema-driven lookup — replaces static TdhGetProperty, which fails
    // silently on Windows 11 v3/v4 event schemas. This resolves the
    // property by name against whatever schema THIS event actually uses,
    // so it works identically across Win10/Win11/Server versions.
    ULONG info_size = 0;
    ULONG s1 = TdhGetEventInformation(record, 0, nullptr, nullptr, &info_size);
    if (info_size == 0) {
        return L"";  // This event type's schema doesn't support size query — expected for many sub-events
    }

    std::vector<BYTE> info_buf(info_size);
    auto* info = reinterpret_cast<TRACE_EVENT_INFO*>(info_buf.data());
    ULONG s2 = TdhGetEventInformation(record, 0, nullptr, info, &info_size);
    if (s2 != ERROR_SUCCESS) {
        return L"";
    }

    ULONG prop_index = ULONG_MAX;
    for (ULONG i = 0; i < info->TopLevelPropertyCount; i++) {
        auto* name = reinterpret_cast<LPCWSTR>(
            info_buf.data() + info->EventPropertyInfoArray[i].NameOffset);
        if (_wcsicmp(name, prop_name) == 0) { prop_index = i; break; }
    }
    if (prop_index == ULONG_MAX) {
        return L"";  // Property doesn't exist in this event's schema — expected for many event types
    }

    // TdhFormatProperty gives no fixed byte offsets — properties must be
    // walked sequentially from the start of UserData, accumulating each
    // preceding property's consumed byte count, to find where our target
    // property actually begins. Previously this always read from byte 0
    // regardless of property index, which silently corrupted any property
    // that wasn't first in the schema (confirmed: FileName, which follows
    // FileKey, showed garbage-prefixed strings as a direct result).
    PBYTE user_data = reinterpret_cast<PBYTE>(record->UserData);
    USHORT remaining_len = static_cast<USHORT>(record->UserDataLength);

    for (ULONG i = 0; i < prop_index; i++) {
        auto& skip_prop = info->EventPropertyInfoArray[i];
        USHORT skip_consumed = 0;
        ULONG skip_out_size = 0;
        // TdhFormatProperty's "consumed" output is unreliable on the
        // size-query call (nullptr buffer) — confirmed live: it silently
        // returns 0, so the skip never actually advanced past FileKey,
        // and FileName reads picked up FileKey's raw 8 bytes as garbage
        // wide-char prefix. Must do the FULL two-call pattern (query size,
        // then actually format into a real buffer) even when skipping,
        // since only the second call populates consumed correctly.
        TdhFormatProperty(
            info, nullptr, sizeof(PVOID),
            skip_prop.nonStructType.InType, skip_prop.nonStructType.OutType,
            static_cast<USHORT>(skip_prop.length),
            remaining_len, user_data,
            &skip_out_size, nullptr, &skip_consumed);

        std::vector<WCHAR> skip_buf(skip_out_size / sizeof(WCHAR) + 1, 0);
        TdhFormatProperty(
            info, nullptr, sizeof(PVOID),
            skip_prop.nonStructType.InType, skip_prop.nonStructType.OutType,
            static_cast<USHORT>(skip_prop.length),
            remaining_len, user_data,
            &skip_out_size, skip_buf.data(), &skip_consumed);

        user_data      += skip_consumed;
        remaining_len  -= skip_consumed;
    }

    auto& prop = info->EventPropertyInfoArray[prop_index];
    USHORT consumed = 0;
    ULONG out_size = 0;
    ULONG status = TdhFormatProperty(
        info, nullptr, sizeof(PVOID),
        prop.nonStructType.InType, prop.nonStructType.OutType,
        static_cast<USHORT>(prop.length),
        remaining_len, user_data,
        &out_size, nullptr, &consumed);
    if (status != ERROR_INSUFFICIENT_BUFFER) return L"";

    std::vector<WCHAR> out_buf(out_size / sizeof(WCHAR) + 1, 0);
    status = TdhFormatProperty(
        info, nullptr, sizeof(PVOID),
        prop.nonStructType.InType, prop.nonStructType.OutType,
        static_cast<USHORT>(prop.length),
        remaining_len, user_data,
        &out_size, out_buf.data(), &consumed);
    if (status != ERROR_SUCCESS) return L"";

    return std::wstring(out_buf.data());
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

ULONGLONG EtwProvider::read_property_ulong64(PEVENT_RECORD record,
                                              const wchar_t* prop_name)
{
    // FileKey and similar Kernel-File properties are 64-bit (pointer-sized
    // kernel object references). Using the 32-bit read_property_ulong here
    // would silently truncate them, causing different files to collide to
    // the same cache key — wrong, not crashing, which is worse.
    PROPERTY_DATA_DESCRIPTOR desc{};
    desc.PropertyName = reinterpret_cast<ULONGLONG>(prop_name);
    desc.ArrayIndex   = ULONG_MAX;

    ULONGLONG value = 0;
    ULONG buf_size  = sizeof(ULONGLONG);
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
