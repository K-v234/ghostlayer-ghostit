#pragma once

#include <string>
#include <vector>

class PipelineForwarder {
public:
    PipelineForwarder(
        const std::string& host,
        int port
    );

    bool connect();

    bool send_event(
        const std::string& json_event
    );

    bool send_batch(
        const std::vector<std::string>& batch
    );

    void disconnect();

private:
    std::string host_;
    int port_;
    int socket_fd_;
};
