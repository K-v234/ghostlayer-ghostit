#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
// STATUS: 100% — header complete
// pipeline_forwarder.h
// GhostIT C9 — Windows Agent → Ubuntu Pipeline Forwarder
// Target: 192.168.154.129:9000
// Ghost Layer Technologies · Chennai · June 2026

#pragma once

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <fstream>
#include <functional>

// Config file: C:\ProgramData\GhostIT\ghost_config.ini
// [pipeline]
// host=192.168.154.129
// port=9000
static constexpr const char* PIPELINE_HOST         = "192.168.154.129";
static constexpr int         PIPELINE_PORT          = 9000;
static constexpr int         HEARTBEAT_INTERVAL_SEC = 30;
static constexpr int         MAX_MISSED_HEARTBEATS  = 3;
static constexpr int         BACKOFF_BASE_MS        = 500;
static constexpr int         BACKOFF_MAX_MS         = 60000;
static constexpr size_t      OFFLINE_BUFFER_MAX_MB  = 512;
// Fixed absolute path, not relative -- a relative path resolves to
// whatever the process's current working directory happens to be at
// launch time, which varies depending on how/where the binary is run
// from (different Downloads subfolders when testing, vs the actual
// working directory when run as a service). Confirmed via live
// testing: the offline buffer file was never found anywhere on disk
// despite "buffering to disk" being logged repeatedly, strongly
// suggesting write failures were also happening silently to a
// directory the process may not have had write access to.
static constexpr const char* OFFLINE_BUFFER_PATH    = "C:\\ProgramData\\GhostIT\\ghost_offline_buffer.jsonl";

class PipelineForwarder {
public:
    explicit PipelineForwarder(
        const std::string& host = PIPELINE_HOST,
        int                port = PIPELINE_PORT
    );
    ~PipelineForwarder();

    PipelineForwarder(const PipelineForwarder&)            = delete;
    PipelineForwarder& operator=(const PipelineForwarder&) = delete;

    bool start();
    void stop();

    bool send_event(const std::string& json_event);
    bool send_batch(const std::vector<std::string>& batch);

    bool is_connected() const;
    int  missed_heartbeats() const;

private:
    bool tcp_connect();
    void tcp_disconnect();
    bool connect_with_backoff();
    bool tcp_send(const std::string& data);

    void heartbeat_loop();
    void send_heartbeat();

    void   buffer_to_disk(const std::string& json_event);
    void   flush_offline_buffer();
    size_t offline_buffer_size_mb() const;

    std::string        host_;
    int                port_;
    int                socket_fd_;

    std::mutex         socket_mutex_;
    // Guards the entire reconnect sequence (tcp_connect/tcp_disconnect)
    // as a single atomic operation. Without this, send_event() and
    // heartbeat_loop() could both call connect_with_backoff()
    // concurrently -- confirmed via live testing: 12 simultaneous
    // ESTABLISHED connections to the pipeline from a single agent
    // process, since each thread's reconnect attempt raced the other,
    // opening a new socket before the previous one (from the "losing"
    // thread) was ever tracked for cleanup.
    std::mutex         reconnect_mutex_;
    std::atomic<bool>  connected_;
    std::atomic<bool>  running_;
    std::atomic<int>   missed_hb_;

    std::thread        heartbeat_thread_;
    int                backoff_ms_;
    std::mutex         buffer_mutex_;
};
