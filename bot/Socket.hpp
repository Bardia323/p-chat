// A WebSocket client (RFC 6455) for native p-chat programs - a bot, a test:
// ws:// or wss:// (TLS by OpenSSL, the server's certificate and name
// checked), binary messages only, one connection, blocking with timeouts.
#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace bot {

using Bytes = std::vector<std::uint8_t>;

class Socket {
public:
    // Connects and upgrades, or throws std::runtime_error.
    explicit Socket(const std::string& url, int timeout_ms = 10000);
    ~Socket();
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    void send(const Bytes& message);
    // The next whole binary message, waiting at most `timeout_ms`; nothing
    // if none came. Pings are answered on the way; a close ends it (open()
    // turns false).
    std::optional<Bytes> receive(int timeout_ms);
    bool open() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace bot
