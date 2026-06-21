#pragma once

#include <string>
#include <cstdint>
#include <optional>

struct GhostEvent {
    uint64_t ts;

    uint32_t pid;
    uint32_t ppid;

    uint32_t uid;
    uint32_t gid;

    std::string comm;
    std::string type;

    std::optional<std::string> file;
    std::optional<std::string> args;

    std::optional<uint32_t> flags;

    std::optional<std::string> daddr;
    std::optional<uint16_t> dport;

    std::optional<uint32_t> family;
    std::optional<uint64_t> clone_flags;
};

std::string serialize_event(const GhostEvent& event);
