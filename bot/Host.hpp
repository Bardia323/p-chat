// A native device: what a browser's session does, for a program on a server
// (a bot) or a test. Its keys are its own (Ed25519 and X25519 seeds in a
// folder, readable by its user only); conversations, messages and ratchet
// keys are kept beside them; it talks to the relay only - no live link, so
// it takes mail, and what it says to a device that does not take mail
// waits here until that device does.
#pragma once
#include "Relay.hpp"
#include "chat/App.hpp"

#include <functional>
#include <map>

namespace bot {

class Host {
public:
    // Opens (or makes) the device in `dir`, under `name`.
    Host(std::string dir, std::string name, std::string relay_url);

    chat::App& app() { return *app_; }
    Relay& relay() { return relay_; }
    std::string peer() const { return app_->peer(); }

    // Pairing as the invited device: the link (or its part after '#') and
    // the six words. Waits for the answer up to `wait_ms`; "ok" or why not.
    std::string pair(const std::string& link, const std::string& code, const std::string& call, int wait_ms = 60000);
    // Pairing as the one who invites (tests): an invite, then take what comes.
    chat::App::Inviting invite(chat::InviteKind kind, const std::string& conversation = {});
    std::string take_pairing(const chat::App::Inviting& invite, int wait_ms = 60000);

    // One round: the App's asks answered, what goes out sent, what came fetched.
    void step(std::uint64_t now_ms);
    // Told of each notice (after it is kept).
    std::function<void(const chat::Notice&)> on_notice;

private:
    void answer(std::uint64_t now_ms);
    void carry(const chat::Outgoing& o);
    void fetch();
    std::string open(const Bytes& envelope);
    void keep(const chat::Notice& n);
    chat::Key32 ratchet_private(const chat::Key32& pub) const;
    chat::Key32 fresh_ratchet_key();

    std::string dir_, name_;
    chat::Key32 seed_{}, secret_{};
    chat::Device device_;
    Relay relay_;
    std::unique_ptr<chat::App> app_;
    struct Waiting {
        std::string conversation, peer;
        Bytes envelope;
    };
    std::vector<Waiting> waiting_;  // for a device that takes no mail, until it does
};

}  // namespace bot
