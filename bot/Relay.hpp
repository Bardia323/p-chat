// The relay's frames (docs/protocol.md, "The relay's frames"), from a native
// program: a request, its answer by id; what the relay pushes unasked (a
// signal for a room) is let go - a native program has no live link.
#pragma once
#include "Socket.hpp"
#include "chat/Pairing.hpp"

namespace bot {

struct Fetched {
    chat::Key32 mailbox{};
    std::array<std::uint8_t, 16> handle{};
    Bytes envelope;
};

class Relay {
public:
    explicit Relay(std::string url);
    const std::string& url() const { return url_; }
    // Each answers the relay's status (0 ok) or throws when the relay cannot be reached.
    int put(const Bytes& envelope);
    std::vector<Fetched> fetch(const std::vector<chat::Key32>& mailboxes);
    int del(const chat::Key32& mailbox, const std::vector<std::array<std::uint8_t, 16>>& handles);
    int pair_post(const chat::Token& token, const Bytes& box);
    std::vector<Bytes> pair_fetch(const chat::Token& token);
    int pair_done(const chat::Token& token);

private:
    std::pair<int, Bytes> call(std::uint8_t op, const Bytes& body);
    std::string url_;
    std::unique_ptr<Socket> socket_;
    std::uint32_t next_ = 1;
};

}  // namespace bot
