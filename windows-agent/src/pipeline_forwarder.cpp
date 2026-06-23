// STATUS: 100% — TCP send, exponential backoff, 72h offline buffer,
//                heartbeat every 30s, reconnect flush, V0-compatible format
// pipeline_forwarder.cpp
// GhostIT C9 — Windows Agent → Ubuntu Pipeline Forwarder
// Ghost Layer Technologies · Chennai · June 2026

#include "pipeline_forwarder.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <io.h>
#include <errno.h>

#include <iostream>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <ctime>
#include <cstring>

namespace fs = std::filesystem;

static std::string iso8601_now()
{
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    return std::string(buf);
}

static std::string make_heartbeat_json()
{
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    uint64_t ticks = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    uint64_t ts_ns = (ticks - 116444736000000000ULL) * 100ULL;
    std::string s = "{";
    s += "\"type\":\"heartbeat\",";
    s += "\"agent\":\"windows-c9\",";
    s += "\"ts\":";
    s += std::to_string(ts_ns);
    s += "}";
    return s;
}

// Read host/port from C:\ProgramData\GhostIT\ghost_config.ini
// Falls back to compiled-in defaults if file missing or unparseable
static std::pair<std::string,int> read_pipeline_config(
    const std::string& default_host, int default_port)
{
    std::string host = default_host;
    int         port = default_port;
    std::ifstream f("C:\\ProgramData\\GhostIT\\ghost_config.ini");
    if (!f.is_open()) return {host, port};
    std::string line;
    bool in_pipeline = false;
    while (std::getline(f, line)) {
        if (line == "[pipeline]") { in_pipeline = true; continue; }
        if (!line.empty() && line[0] == '[') { in_pipeline = false; continue; }
        if (!in_pipeline) continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        if (key == "host" && !val.empty()) host = val;
        if (key == "port" && !val.empty()) {
            try { port = std::stoi(val); } catch (...) {}
        }
    }
    return {host, port};
}

PipelineForwarder::PipelineForwarder(const std::string& host, int port)
    : host_([&]{ return read_pipeline_config(host, port).first; }())
    , port_([&]{ return read_pipeline_config(host, port).second; }())
    , socket_fd_(-1)
    , connected_(false)
    , running_(false)
    , missed_hb_(0)
    , backoff_ms_(BACKOFF_BASE_MS)
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
}

PipelineForwarder::~PipelineForwarder()
{
    stop();
}

bool PipelineForwarder::start()
{
    connect_with_backoff();
    if (connected_) {
        flush_offline_buffer();
    }
    running_ = true;
    heartbeat_thread_ = std::thread(&PipelineForwarder::heartbeat_loop, this);
    std::cout << "[GhostIT C9] PipelineForwarder started → "
              << host_ << ":" << port_ << "\n";
    return true;
}

void PipelineForwarder::stop()
{
    running_ = false;
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    tcp_disconnect();
    std::cout << "[GhostIT C9] PipelineForwarder stopped.\n";
}

bool PipelineForwarder::send_event(const std::string& json_event)
{
    if (is_connected()) {
        if (tcp_send(json_event + "\n")) {
            return true;
        }
        connected_ = false;
        std::cerr << "[GhostIT C9] Send failed — buffering to disk.\n";
    }

    if (connect_with_backoff()) {
        flush_offline_buffer();
        if (tcp_send(json_event + "\n")) {
            return true;
        }
    }

    buffer_to_disk(json_event);
    return false;
}

bool PipelineForwarder::send_batch(const std::vector<std::string>& batch)
{
    bool all_ok = true;
    for (const auto& event : batch) {
        if (!send_event(event)) {
            all_ok = false;
        }
    }
    return all_ok;
}

bool PipelineForwarder::is_connected() const
{
    return connected_.load();
}

int PipelineForwarder::missed_heartbeats() const
{
    return missed_hb_.load();
}

bool PipelineForwarder::tcp_connect()
{
    tcp_disconnect();

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cerr << "[GhostIT C9] socket() failed: " << std::to_string(WSAGetLastError()).c_str() << "\n";
        return false;
    }

    struct timeval tv { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port_));

    if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "[GhostIT C9] inet_pton failed for host: " << host_ << "\n";
        closesocket(fd);
        return false;
    }

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[GhostIT C9] connect() to "
                  << host_ << ":" << port_
                  << " failed: " << std::to_string(WSAGetLastError()).c_str() << "\n";
        closesocket(fd);
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(socket_mutex_);
        socket_fd_ = fd;
    }
    connected_  = true;
    missed_hb_  = 0;
    backoff_ms_ = BACKOFF_BASE_MS;

    std::cout << "[GhostIT C9] Connected to pipeline at "
              << host_ << ":" << port_ << "\n";
    return true;
}

void PipelineForwarder::tcp_disconnect()
{
    std::lock_guard<std::mutex> lk(socket_mutex_);
    if (socket_fd_ >= 0) {
        closesocket(socket_fd_);
        socket_fd_ = -1;
    }
    connected_ = false;
}

bool PipelineForwarder::connect_with_backoff()
{
    if (is_connected()) return true;

    while (running_ || !is_connected()) {
        if (tcp_connect()) return true;

        std::cerr << "[GhostIT C9] Retrying in " << backoff_ms_ << "ms …\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms_));
        backoff_ms_ = std::min(backoff_ms_ * 2, BACKOFF_MAX_MS);

        if (!running_) break;
    }
    return is_connected();
}

bool PipelineForwarder::tcp_send(const std::string& data)
{
    std::lock_guard<std::mutex> lk(socket_mutex_);
    if (socket_fd_ < 0) return false;

    size_t total_sent = 0;
    while (total_sent < data.size()) {
        int sent = ::send(
            socket_fd_,
            data.c_str() + total_sent,
            data.size()  - total_sent,
            0
        );
        if (sent <= 0) {
            std::cerr << "[GhostIT C9] tcp_send() error: " << std::to_string(WSAGetLastError()).c_str() << "\n";
            return false;
        }
        total_sent += static_cast<size_t>(sent);
    }
    return true;
}

void PipelineForwarder::heartbeat_loop()
{
    std::cout << "[GhostIT C9] Heartbeat thread started "
              << "(interval: " << HEARTBEAT_INTERVAL_SEC << "s)\n";

    while (running_) {
        for (int i = 0; i < HEARTBEAT_INTERVAL_SEC && running_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!running_) break;
        send_heartbeat();
    }

    std::cout << "[GhostIT C9] Heartbeat thread exiting.\n";
}

void PipelineForwarder::send_heartbeat()
{
    if (!is_connected()) {
        std::cout << "[GhostIT C9] Heartbeat: not connected, attempting reconnect…\n";
        if (connect_with_backoff()) {
            flush_offline_buffer();
            missed_hb_ = 0;
        } else {
            int missed = ++missed_hb_;
            std::cerr << "[GhostIT C9] HEARTBEAT MISSED ("
                      << missed << "/" << MAX_MISSED_HEARTBEATS << ")\n";
            if (missed >= MAX_MISSED_HEARTBEATS) {
                std::cerr << "[GhostIT C9] ALERT: pipeline unreachable — "
                          << "events buffered offline.\n";
            }
        }
        return;
    }

    std::string hb = make_heartbeat_json() + "\n";
    if (!tcp_send(hb)) {
        connected_ = false;
        int missed = ++missed_hb_;
        std::cerr << "[GhostIT C9] HEARTBEAT FAILED ("
                  << missed << "/" << MAX_MISSED_HEARTBEATS << ")\n";
        if (missed >= MAX_MISSED_HEARTBEATS) {
            std::cerr << "[GhostIT C9] ALERT: pipeline connection lost — "
                      << "buffering events to disk.\n";
        }
    } else {
        missed_hb_ = 0;
        std::cout << "[GhostIT C9] Heartbeat OK → " << host_ << ":" << port_ << "\n";
    }
}

void PipelineForwarder::buffer_to_disk(const std::string& json_event)
{
    if (offline_buffer_size_mb() >= OFFLINE_BUFFER_MAX_MB) {
        std::cerr << "[GhostIT C9] WARNING: offline buffer full ("
                  << OFFLINE_BUFFER_MAX_MB << "MB) — dropping event.\n";
        return;
    }

    std::lock_guard<std::mutex> lk(buffer_mutex_);
    std::ofstream ofs(OFFLINE_BUFFER_PATH, std::ios::app | std::ios::out);
    if (!ofs.is_open()) {
        std::cerr << "[GhostIT C9] ERROR: cannot open offline buffer at "
                  << OFFLINE_BUFFER_PATH << "\n";
        return;
    }
    ofs << json_event << "\n";
    ofs.flush();
}

void PipelineForwarder::flush_offline_buffer()
{
    std::lock_guard<std::mutex> lk(buffer_mutex_);

    if (!fs::exists(OFFLINE_BUFFER_PATH)) return;

    std::ifstream ifs(OFFLINE_BUFFER_PATH);
    if (!ifs.is_open()) return;

    std::vector<std::string> failed_lines;
    std::string line;
    size_t sent_count   = 0;
    size_t failed_count = 0;

    std::cout << "[GhostIT C9] Flushing offline buffer → pipeline…\n";

    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        if (tcp_send(line + "\n")) {
            ++sent_count;
        } else {
            failed_lines.push_back(line);
            ++failed_count;
        }
    }
    ifs.close();

    if (failed_count == 0) {
        fs::remove(OFFLINE_BUFFER_PATH);
        std::cout << "[GhostIT C9] Offline buffer flushed: "
                  << sent_count << " events sent.\n";
    } else {
        std::ofstream ofs(OFFLINE_BUFFER_PATH, std::ios::trunc | std::ios::out);
        for (const auto& l : failed_lines) {
            ofs << l << "\n";
        }
        std::cerr << "[GhostIT C9] Partial flush: "
                  << sent_count  << " sent, "
                  << failed_count << " re-buffered.\n";
    }
}

size_t PipelineForwarder::offline_buffer_size_mb() const
{
    if (!fs::exists(OFFLINE_BUFFER_PATH)) return 0;
    auto sz = fs::file_size(OFFLINE_BUFFER_PATH);
    return static_cast<size_t>(sz / (1024 * 1024));
}
