// Carrying for contacts, from a native device: web/carry.js, the same frames
// and the same bounds (docs/protocol.md, "Contacts carrying", "A device that
// relays", "Carried within the chat"). A relay's work, done on the live
// links a device has; like a relay it has no world role - it moves sealed
// bytes, opens nothing, and keeps nothing in a state.
#pragma once
#include "chat/Wire.hpp"

#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace bot {

using chat::Bytes;
using chat::Key32;

struct CarryLimits {
    std::size_t rooms = 256, held = 512, held_bytes = 16u << 20, per_giver = 128;
    std::uint64_t ttl = 14ull * 86400000ull;
    std::size_t pass_per_minute = 120, hold_per_minute = 60, ask_ids = 1024, box = 131072, serves = 1024,
                handles = 4096, hops = 4, seen = 1024, share_per_gather = 64;
};
// A phone's share, and a device that relays (one left on).
CarryLimits carry_limits();
CarryLimits relaying_limits();

namespace carry_kind {
constexpr std::uint8_t rooms = 1, pass = 2, signal = 3, hold = 4, ask = 5, given = 6, taken = 7, relays = 8, serves = 9,
                       gather = 10, share = 11, hop = 12;
}

struct Room {
    Key32 room{}, label{};
};
struct Held {
    std::string key;  // hex(mailbox) + hex(handle)
    Key32 mailbox{};
    std::array<std::uint8_t, 16> handle{};
    Bytes envelope;
    std::string from;
    std::uint64_t at = 0;
};

// What carrying needs of its host.
struct CarryIo {
    std::function<bool(const std::string& peer, const Bytes& frame)> send;
    std::function<std::vector<std::string>()> peers;               // linked now
    std::function<std::vector<Room>()> rooms;                      // its own
    std::function<std::vector<Key32>()> mailboxes;                 // its own
    std::function<std::vector<Key32>()> members;                   // its chats' other devices' (protocol 13)
    std::function<void(const Key32& room, const Bytes& box)> signal_in;
    std::function<std::string(const Bytes& envelope)> open;        // the App's status
    std::function<void(const std::string& peer, const std::vector<std::string>& rooms)> near;
    std::function<bool()> helping, relaying;
    std::function<void(const Held&)> put;                          // kept across restarts
    std::function<void(const std::string& key)> drop;
    std::function<std::uint64_t()> now;
};

class Carry {
public:
    Carry(CarryIo io, std::vector<Held> kept);
    // Once a second: rooms said, mail asked for and gathered, the old forgotten.
    void tick();
    // A frame on the carry channel from `peer`: what was done ("ok",
    // "refused", "held", "passed", "nowhere", a count...).
    std::string frame(const std::string& peer, const Bytes& bytes);
    // A signal of this device's for `peer` (in `room`, to `label`): how many took it.
    int signal(const std::string& peer, const Key32& room, const Key32& label, const Bytes& box);
    // An envelope for a device that is away, given to linked contacts to keep.
    int hold(const Bytes& envelope, const std::string& recipient, bool relays_only = false);
    std::vector<std::string> relays() const;  // linked contacts that relay
    std::size_t kept() const { return held_.size(); }
    struct Done {
        std::size_t passed = 0, held = 0, given = 0, shared = 0, hopped = 0;
    } done;

private:
    CarryLimits limits() const;
    bool allowed(const std::string& peer, const std::string& what, std::size_t per);
    std::string keep(const std::string& peer, const Bytes& env, const Key32& mailbox, const std::array<std::uint8_t, 16>& handle);
    void opened(const std::vector<std::array<std::uint8_t, 16>>& handles);
    bool own_room(const std::string& room) const;
    std::vector<Room> serves_for(const std::string& peer, std::vector<bool>& now) const;
    void remember(std::uint64_t now);

    CarryIo io_;
    std::map<std::string, Held> held_;
    std::map<std::string, std::set<std::string>> reach_;  // peer -> hex(room)+hex(label)
    struct Told {
        std::uint64_t at = 0;
        std::string said;
    };
    std::map<std::string, Told> told_, flagged_, serves_told_;
    std::map<std::string, std::uint64_t> asked_, gathered_;
    std::map<std::string, std::set<std::string>> shared_;
    std::map<std::string, std::uint8_t> relaying_;
    std::map<std::string, std::vector<std::pair<Room, bool>>> serving_;
    std::map<std::string, std::pair<std::uint64_t, std::size_t>> rates_;
    std::map<std::string, std::uint64_t> gone_, seen_;     // hex handle / hex id -> when
    std::vector<std::string> gone_order_, seen_order_;
    struct Served {
        Room where;
        std::string peer;
        std::uint64_t at = 0;
    };
    std::map<std::string, Served> served_;  // what a relaying device remembers of where contacts are reached
};

// The frames, made.
namespace carry_frames {
Bytes rooms(const std::vector<Room>& rooms);
Bytes pass(const Key32& room, const Key32& label, const Bytes& box);
Bytes signal(const Key32& room, const Bytes& box);
Bytes hold(const Bytes& env);
Bytes ask(const std::vector<Key32>& ids);
Bytes given(const Key32& mailbox, const std::array<std::uint8_t, 16>& handle, const Bytes& env);
Bytes taken(const Key32& mailbox, const std::vector<std::array<std::uint8_t, 16>>& handles);
Bytes relays(std::uint8_t flags);
Bytes serves(const std::vector<std::pair<Room, bool>>& devices);
Bytes gather(const std::vector<Key32>& mailboxes, const std::vector<std::array<std::uint8_t, 16>>& have,
             const std::vector<std::array<std::uint8_t, 16>>& gone);
Bytes share(const std::array<std::uint8_t, 16>& handle, const Bytes& env);
Bytes hop(std::uint8_t left, const std::array<std::uint8_t, 16>& id, const Key32& room, const Key32& label, const Bytes& box);
}  // namespace carry_frames

// The relay's handle of an envelope: H(envelope) truncated to 16 bytes.
std::array<std::uint8_t, 16> envelope_handle(const Bytes& env);

}  // namespace bot
