#include "event_serializer.h"
#include <nlohmann/json.hpp>
#include <cstring>

using json = nlohmann::json;

// Convert dst_ip uint32 to dotted-decimal string
static std::string ip_to_str(uint32_t ip) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
        (ip >>  8) & 0xFF,  ip        & 0xFF);
    return std::string(buf);
}

// Map event_type byte to human-readable string
static const char* event_type_str(uint8_t t) {
    switch (t) {
    case GHOST_EVT_PROCESS_CREATE:  return "process_exec";
    case GHOST_EVT_PROCESS_EXIT:    return "process_exit";
    case GHOST_EVT_FILE_OPEN:       return "file_open";
    case GHOST_EVT_FILE_WRITE:      return "file_write";
    case GHOST_EVT_FILE_DELETE:     return "file_delete";
    case GHOST_EVT_NET_CONNECT:     return "net_connect";
    case GHOST_EVT_NET_LISTEN:      return "net_listen";
    case GHOST_EVT_THREAD_CREATE:   return "thread_create";
    case GHOST_EVT_THREAD_INJECT:   return "thread_inject";
    case GHOST_EVT_MODULE_LOAD:     return "module_load";
    case GHOST_EVT_MEMORY_EXEC:     return "memory_exec";
    case GHOST_EVT_CANARY_HIT:      return "canary_hit";
    case GHOST_EVT_LAYER_DIVERGE:   return "layer_diverge";
    case GHOST_EVT_TOKEN_ELEVATE:   return "token_elevate";
    case GHOST_EVT_SERVICE_INSTALL: return "service_install";
    case GHOST_EVT_SCHEDULED_TASK:  return "scheduled_task";
    default:                        return "unknown";
    }
}

static const char* priority_str(uint8_t p) {
    switch (p) {
    case GHOST_PRI_CRITICAL: return "critical";
    case GHOST_PRI_HIGH:     return "high";
    case GHOST_PRI_MEDIUM:   return "medium";
    default:                 return "low";
    }
}

std::string serialize_event(const ghost_event_t& evt) {
    json j;
    j["ts"]         = evt.timestamp_ns;
    j["pid"]        = evt.pid;
    j["ppid"]       = evt.ppid;
    j["tid"]        = evt.tid;
    j["uid"]        = evt.uid;
    j["type"]       = event_type_str(evt.event_type);
    j["priority"]   = priority_str(evt.priority);
    j["integrity"]  = evt.integrity;
    j["layer"]      = evt.layer;
    j["comm"]       = std::string(evt.comm, strnlen(evt.comm, sizeof(evt.comm)));
    j["path"]       = std::string(evt.path, strnlen(evt.path, sizeof(evt.path)));
    j["agent"]      = "windows-c9";
    if (evt.dst_ip != 0)   j["daddr"]    = ip_to_str(evt.dst_ip);
    if (evt.dst_port != 0) j["dport"]    = evt.dst_port;
    if (evt.src_port != 0) j["sport"]    = evt.src_port;
    return j.dump();
}
