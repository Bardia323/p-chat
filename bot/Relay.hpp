// The relay's frames (docs/protocol.md, "The relay's frames"), from a native
// program: a request, its answer by id. What the relay pushes unasked - a
// signal for a room this device joined, a hint that mail is waiting - is
// kept for the host to take (a device with live links answers signals).
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
    // Rooms (protocol 3): joined to be signaled in; a signal to a label in one.
    int join(const chat::Key32& room, const chat::Key32& label);
    int signal(const chat::Key32& room, const chat::Key32& label, const Bytes& box);
    // What was pushed: signals (room, box), and whether mail was said to wait.
    // `poll` reads what came, waiting at most `ms`.
    void poll(int ms);
    std::vector<std::pair<chat::Key32, Bytes>> take_signals();
    bool take_mail();
    // Each new connection: rooms are joined again on it.
    std::uint64_t connection() const { return connection_; }
    bool up() const { return socket_ && socket_->open(); }

private:
    std::pair<int, Bytes> call(std::uint8_t op, const Bytes& body);
    std::string url_;
    std::unique_ptr<Socket> socket_;
    std::uint32_t next_ = 1;
    std::uint64_t connection_ = 0;
    std::vector<std::pair<chat::Key32, Bytes>> signals_;
    bool mail_ = false;
    bool pushed(const Bytes& m);
};

}  // namespace bot
