// STATUS: 100% — 50ms match window, expiry sweep, alert cooldown,
//                eBPF-silent and ETW-silent detection, content mismatch detection
// divergence_detector.cpp
// GhostIT C9 — eBPF vs ETW Cross-Layer Divergence Detector
// Ghost Layer Technologies · Chennai · June 2026

#include "divergence_detector.h"

#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>

using namespace std::chrono;

DivergenceDetector::DivergenceDetector(DivergenceAlertCallback on_alert)
    : on_alert_(std::move(on_alert))
    , running_(false)
    , total_matched_(0)
    , total_diverged_(0)
    , events_seen_(0)
{
}

DivergenceDetector::~DivergenceDetector() { stop(); }

bool DivergenceDetector::start()
{
    running_       = true;
    expiry_thread_ = std::thread(&DivergenceDetector::expiry_loop, this);
    std::cout << "[GhostIT DIVERGE] Divergence detector started "
              << "(tolerance: " << DIVERGENCE_TOLERANCE_MS << "ms)\n";
    return true;
}

void DivergenceDetector::stop()
{
    running_ = false;
    if (expiry_thread_.joinable()) expiry_thread_.join();
    std::cout << "[GhostIT DIVERGE] Stopped. "
              << "Matched: "   << total_matched_.load()
              << " Diverged: " << total_diverged_.load()
              << " Total: "    << events_seen_.load() << "\n";
}

void DivergenceDetector::on_ebpf_event(const ghost_event_t& evt)
{
    ++events_seen_;
    process_event(evt, true);
}

void DivergenceDetector::on_etw_event(const ghost_event_t& evt)
{
    ++events_seen_;
    process_event(evt, false);
}

uint64_t DivergenceDetector::total_matched()  const { return total_matched_.load();  }
uint64_t DivergenceDetector::total_diverged() const { return total_diverged_.load(); }
uint64_t DivergenceDetector::events_seen()    const { return events_seen_.load();    }

void DivergenceDetector::process_event(const ghost_event_t& evt, bool from_ebpf)
{
    if (evt.type != GHOST_EVENT_PROCESS_EXEC &&
        evt.type != GHOST_EVENT_NET_CONNECT  &&
        evt.type != GHOST_EVENT_FILE_OPEN)
        return;

    auto now = steady_clock::now();
    std::lock_guard<std::mutex> lk(pending_mutex_);

    for (auto it = pending_.begin(); it != pending_.end(); ++it) {
        if (it->from_ebpf == from_ebpf) continue;

        auto age_ms = duration_cast<milliseconds>(now - it->arrived_at).count();
        if (age_ms > static_cast<long long>(DIVERGENCE_TOLERANCE_MS)) continue;

        if (events_match(it->evt, evt)) {
            ++total_matched_;
            pending_.erase(it);
            return;
        }

        if (it->evt.pid == evt.pid && it->evt.type == evt.type) {
            std::ostringstream reason;
            reason << "eBPF/ETW content mismatch for PID " << evt.pid
                   << " event type " << static_cast<int>(evt.type)
                   << " — comm: eBPF='" << it->evt.comm
                   << "' ETW='"         << evt.comm << "'";

            ++total_diverged_;
            pending_.erase(it);

            DivergenceAlert alert{};
            alert.timestamp_ns   = evt.ts;
            alert.pid            = evt.pid;
            alert.level          = DivergenceAlertLevel::CRITICAL;
            alert.reason         = reason.str();
            alert.source_missing = "none (content mismatch)";
            alert.observed_event = evt;

            if (on_alert_ && is_cooled_down(evt.pid)) {
                mark_alerted(evt.pid);
                on_alert_(alert);
            }
            return;
        }
    }

    PendingEvent pending{};
    pending.evt        = evt;
    pending.from_ebpf  = from_ebpf;
    pending.arrived_at = now;
    pending_.push_back(std::move(pending));
}

bool DivergenceDetector::events_match(const ghost_event_t& a,
                                       const ghost_event_t& b) const
{
    if (a.type != b.type || a.pid != b.pid) return false;

    if (a.type == GHOST_EVENT_PROCESS_EXEC)
        if (strncmp(a.comm, b.comm, sizeof(a.comm)) != 0) return false;

    if (a.type == GHOST_EVENT_NET_CONNECT) {
        if (a.dport != b.dport || a.family != b.family) return false;
        if (strncmp(a.daddr, b.daddr, sizeof(a.daddr)) != 0) return false;
    }

    if (a.type == GHOST_EVENT_FILE_OPEN)
        if (strncmp(a.path, b.path, sizeof(a.path)) != 0) return false;

    return true;
}

void DivergenceDetector::fire_alert(const ghost_event_t& observed,
                                     bool  ebpf_missing,
                                     const std::string& reason)
{
    if (!on_alert_)                    return;
    if (!is_cooled_down(observed.pid)) return;

    DivergenceAlert alert{};
    alert.timestamp_ns   = observed.ts;
    alert.pid            = observed.pid;
    alert.level          = DivergenceAlertLevel::HIGH;
    alert.reason         = reason;
    alert.source_missing = ebpf_missing ? "ebpf" : "etw";
    alert.observed_event = observed;

    mark_alerted(observed.pid);

    std::cerr << "[GhostIT DIVERGE] HIGH ALERT — "
              << (ebpf_missing ? "eBPF" : "ETW")
              << " silent for PID " << observed.pid
              << " ('" << observed.comm << "')"
              << " — possible layer tampering.\n";

    on_alert_(alert);
}

bool DivergenceDetector::is_cooled_down(uint32_t pid)
{
    std::lock_guard<std::mutex> lk(cooldown_mutex_);
    auto it = last_alerted_.find(pid);
    if (it == last_alerted_.end()) return true;
    auto elapsed_ms = duration_cast<milliseconds>(
        steady_clock::now() - it->second).count();
    return elapsed_ms >= static_cast<long long>(DIVERGENCE_ALERT_COOLDOWN_MS);
}

void DivergenceDetector::mark_alerted(uint32_t pid)
{
    std::lock_guard<std::mutex> lk(cooldown_mutex_);
    last_alerted_[pid] = steady_clock::now();
}

void DivergenceDetector::expiry_loop()
{
    std::cout << "[GhostIT DIVERGE] Expiry sweep thread started.\n";

    while (running_) {
        for (int i = 0; i < 10 && running_; ++i)
            std::this_thread::sleep_for(milliseconds(10));
        if (!running_) break;

        auto now = steady_clock::now();
        std::vector<PendingEvent> expired;

        {
            std::lock_guard<std::mutex> lk(pending_mutex_);
            auto it = pending_.begin();
            while (it != pending_.end()) {
                auto age_ms = duration_cast<milliseconds>(
                    now - it->arrived_at).count();
                if (age_ms > static_cast<long long>(PENDING_EXPIRY_MS)) {
                    expired.push_back(*it);
                    it = pending_.erase(it);
                } else {
                    ++it;
                }
            }
        }

        for (const auto& p : expired) {
            ++total_diverged_;
            std::ostringstream reason;
            reason << (p.from_ebpf ? "eBPF" : "ETW")
                   << " saw PID " << p.evt.pid
                   << " ('" << p.evt.comm << "') but "
                   << (p.from_ebpf ? "ETW" : "eBPF")
                   << " was silent after " << PENDING_EXPIRY_MS << "ms — "
                   << (p.from_ebpf
                       ? "ETW layer may be suppressed by attacker"
                       : "eBPF layer may be suppressed by attacker");
            fire_alert(p.evt, !p.from_ebpf, reason.str());
        }
    }

    std::cout << "[GhostIT DIVERGE] Expiry sweep thread exiting.\n";
}
