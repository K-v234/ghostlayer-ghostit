// STATUS: 100% — header complete
// divergence_detector.h
// GhostIT C9 — eBPF vs ETW Cross-Layer Divergence Detector
// If eBPF and ETW disagree on any event within 50ms → HIGH alert (attacker tampering)
// Ghost Layer Technologies · Chennai · June 2026

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include <unordered_map>
#include <chrono>
#include <deque>

#include "ghost_event.h"

static constexpr uint64_t DIVERGENCE_TOLERANCE_MS      = 50;
static constexpr uint64_t PENDING_EXPIRY_MS            = 500;
static constexpr uint32_t DIVERGENCE_ALERT_COOLDOWN_MS = 5000;

enum class DivergenceAlertLevel { HIGH, CRITICAL };

struct DivergenceAlert {
    uint64_t             timestamp_ns;
    uint32_t             pid;
    DivergenceAlertLevel level;
    std::string          reason;
    std::string          source_missing;
    ghost_event_t        observed_event;
};

using DivergenceAlertCallback = std::function<void(const DivergenceAlert&)>;

class DivergenceDetector {
public:
    explicit DivergenceDetector(DivergenceAlertCallback on_alert);
    ~DivergenceDetector();

    DivergenceDetector(const DivergenceDetector&)            = delete;
    DivergenceDetector& operator=(const DivergenceDetector&) = delete;

    bool start();
    void stop();

    void on_ebpf_event(const ghost_event_t& evt);
    void on_etw_event (const ghost_event_t& evt);

    uint64_t total_matched()  const;
    uint64_t total_diverged() const;
    uint64_t events_seen()    const;

private:
    struct PendingEvent {
        ghost_event_t evt;
        bool          from_ebpf;
        std::chrono::steady_clock::time_point arrived_at;
    };

    void process_event(const ghost_event_t& evt, bool from_ebpf);
    bool events_match (const ghost_event_t& a, const ghost_event_t& b) const;

    void fire_alert(const ghost_event_t& observed,
                    bool ebpf_missing, const std::string& reason);

    bool is_cooled_down(uint32_t pid);
    void mark_alerted  (uint32_t pid);

    void expiry_loop();

    DivergenceAlertCallback on_alert_;

    std::mutex              pending_mutex_;
    std::deque<PendingEvent> pending_;

    std::mutex              cooldown_mutex_;
    std::unordered_map<uint32_t,
        std::chrono::steady_clock::time_point> last_alerted_;

    std::atomic<bool>     running_;
    std::thread           expiry_thread_;

    std::atomic<uint64_t> total_matched_;
    std::atomic<uint64_t> total_diverged_;
    std::atomic<uint64_t> events_seen_;
};
