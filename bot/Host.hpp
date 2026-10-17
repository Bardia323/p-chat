// A native device: what a browser's session does, for a program on a server
// (a bot), a device left on (sgchat_node) or a test. Its keys are its own
// (Ed25519 and X25519 seeds in a folder, readable by its user only);
// conversations, messages, ratchet keys and what it keeps for others are
// kept beside them. With no live path it talks to the relay only, so it
// takes mail, and what it says to a device that does not take mail waits
// here until that device does. Given a live path (`live`), it links with
// its chats' devices as a browser does, carries for them (bot/Carry) and
// may need no relay at all (an empty relay url).
#pragma once
#include "Carry.hpp"
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
    // Live links (protocol 4 on): the App's live path, and carrying on it.
    void live(chat::App::Live* live);
    // Whether this device relays for its contacts (protocol 11): one left on.
    void set_relaying(bool on) { relaying_ = on; }
    bool has_relay() const { return !relay_.url().empty(); }
    Carry& carrier() { return *carry_; }
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

    // With live links: what was sent and not yet acknowledged (or not yet
    // sent), signals until taken, envelopes said under a generation not
    // reached yet, and the carrying.
    void go(std::uint64_t now);
    void join_rooms();
    void near(const std::vector<std::string>& rooms);
    struct Out {
        std::string conversation, peer;
        std::uint64_t sequence = 0, live_at = 0, made = 0, until = 0;
        Bytes envelope;
        bool mailbox = false, control = false, waiting = false, held = false;
    };
    struct Signal {
        std::string peer;
        chat::Key32 room{}, label{};
        Bytes box;
        std::uint64_t made = 0, carried = 0;
    };
    struct Later {
        Bytes envelope;
        std::uint64_t until = 0;
    };
    std::vector<Out> outbox_;
    std::vector<Signal> signals_;
    std::vector<Later> later_;
    std::unique_ptr<Carry> carry_;
    bool live_ = false, relaying_ = false;
    std::uint64_t now_ = 0, ticked_ = 0, fetched_ = 0, joined_on_ = 0;
    std::string joined_rooms_;
    std::map<std::string, std::uint64_t> relinked_;
};

}  // namespace bot
