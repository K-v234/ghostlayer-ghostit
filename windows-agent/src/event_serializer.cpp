#include "event_serializer.h"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

std::string serialize_event(const GhostEvent& event)
{
    json j;

    j["ts"]   = event.ts;
    j["pid"]  = event.pid;
    j["ppid"] = event.ppid;

    j["uid"]  = event.uid;
    j["gid"]  = event.gid;

    j["comm"] = event.comm;
    j["type"] = event.type;

    if (event.file.has_value())
        j["file"] = event.file.value();

    if (event.args.has_value())
        j["args"] = event.args.value();

    if (event.flags.has_value())
        j["flags"] = event.flags.value();

    if (event.daddr.has_value())
        j["daddr"] = event.daddr.value();

    if (event.dport.has_value())
        j["dport"] = event.dport.value();

    if (event.family.has_value())
        j["family"] = event.family.value();

    if (event.clone_flags.has_value())
        j["clone_flags"] = event.clone_flags.value();

    return j.dump();
}
