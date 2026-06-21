#include "pipeline_forwarder.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

PipelineForwarder::PipelineForwarder(
    const std::string& host,
    int port
)
    : host_(host),
      port_(port),
      socket_fd_(-1)
{
}

PipelineForwarder::~PipelineForwarder()
{
    disconnect();
}

bool PipelineForwarder::connect()
{
    if (socket_fd_ >= 0)
        return true;

    socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_fd_ < 0)
        return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);

    if (inet_pton(AF_INET,
                  host_.c_str(),
                  &addr.sin_addr) <= 0)
    {
        disconnect();
        return false;
    }

    if (::connect(socket_fd_,
                  (sockaddr*)&addr,
                  sizeof(addr)) < 0)
    {
        disconnect();
        return false;
    }

    return true;
}

bool PipelineForwarder::reconnect()
{
    disconnect();
    return connect();
}

bool PipelineForwarder::is_connected() const
{
    return socket_fd_ >= 0;
}

bool PipelineForwarder::send_event(
    const std::string& json_event
)
{
    if (!is_connected())
    {
        if (!reconnect())
            return false;
    }

    std::string payload =
        json_event + "\n";

    ssize_t sent =
        send(socket_fd_,
             payload.c_str(),
             payload.size(),
             0);

    if (sent < 0)
    {
        reconnect();
        return false;
    }

    return true;
}

bool PipelineForwarder::send_batch(
    const std::vector<std::string>& batch
)
{
    for (const auto& event : batch)
    {
        if (!send_event(event))
            return false;
    }

    return true;
}

void PipelineForwarder::disconnect()
{
    if (socket_fd_ >= 0)
    {
        close(socket_fd_);
        socket_fd_ = -1;
    }
}
