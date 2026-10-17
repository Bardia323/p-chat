// Linked devices (protocol 11): one person's devices - a phone and a
// desktop, say - acting as one person, with no account and no server: an
// agreement among the devices themselves.
//
// Two devices of one person pair (a Link invite: the six words, the four
// pictures) and so make a conversation of their own, of kind Self, with
// every one of them on the owner's side. Over it they keep each other's
// chats:
//
// - every chat one of them is in, the others are brought into too, on this
//   person's side, by the conversation's ordinary handoff (the old quorum
//   endorses; the owner's side proposes - for a chat where this person is
//   the friend's side, it is asked to by a signed `device_ask`);
// - the device that brought one in gives it the chat (`linked_chat`: the
//   conversation, its secret, its committee, and the handoff that brought
//   it in, which it checks as a further device checks its accept), then
//   what was said there, each message checked against the chat's agreed
//   epochs (or, said under the generation it is in, by its sender's key) -
//   the same machinery fills in what one missed while it was away;
// - a chat named on one is named so on the others (`link_name`);
// - unlinking is said in an `unlink`: one device leaves every chat it
//   shares with the others (forgetting it, or keeping a copy it cannot
//   write in), or the two agree which chats go with which.
#pragma once
#include "chat/Group.hpp"
#include "chat/Recovery.hpp"

namespace chat {

// A chat given to a linked device (type `linked_chat`, in the self
// conversation): what it needs to take its place in it.
//   u8 11 | conversation(16) | u8 kind | u8 side | secret(32) | u64 secret_generation
//   | short(name) | short(introduced) | short(relay) | u64 generation | u8 n | n x member
//   | long(trust) | u8 m | m x member (before) | u8 no_recovery | u32 disappear_s
// trust: empty at generation 0 (the linked device was in it from its start);
// u8 1 | long(Finalized) | long(Handoff), the handoff that brought it in, as
// a further device's accept; u8 2 | short(sender key) | device id(32), a
// channel to read: its key from now on, and the publisher's device that speaks under it.
struct LinkedChat {
    ConversationId conversation{};
    Kind kind = Kind::Direct;
    Side side = Side::Owner;  // this person's side in it
    Key32 secret{};
    std::uint64_t secret_generation = 0;
    std::string name, introduced, relay;
    std::uint64_t generation = 0;
    std::vector<Member> members;
    Bytes trust;
    std::vector<Member> before;  // with trust 1: the committee the handoff came from
    bool no_recovery = false;
    std::uint32_t disappear_s = 0;
};
Bytes encode(const LinkedChat& l);
LinkedChat decode_linked_chat(const Bytes& b);

// A member asks the owner's side to change its own devices (type
// `device_ask`, in the chat): to add a device linked to it, on its side, or
// to take itself out (it is leaving).  u8 11 | u8 add | sign | agree | u8 flags
struct DeviceAsk {
    bool add = true;
    Member member;
};
Bytes encode(const DeviceAsk& a);
DeviceAsk decode_device_ask(const Bytes& b);

// Unlinking (type `unlink`, in the self conversation).
//   u8 11 | u8 what | u16 n | n x conversation (the sender keeps) | u16 m | m x conversation (the receiver keeps)
enum class UnlinkWhat : std::uint8_t { Forget = 1, Keep = 2, SplitAsk = 3, SplitAgree = 4, SplitRefuse = 5 };
struct Unlink {
    UnlinkWhat what = UnlinkWhat::Keep;
    std::vector<ConversationId> keeps, gives;
};
Bytes encode(const Unlink& u);
Unlink decode_unlink(const Bytes& b);

// A chat named on one device (type `link_name`).  u8 11 | conversation(16) | short(name)
struct LinkName {
    ConversationId conversation{};
    std::string name;
};
Bytes encode(const LinkName& n);
LinkName decode_link_name(const Bytes& b);

// What a device has of its chats (control 13, LinkHave): for each, the
// generation and next history tick it is at, whether it still lacks agreed
// epochs older than the one it started from, and per sender the runs of
// sequences it holds.
//   u8 11 | u8 all | u16 n | n x (conversation(16) | u64 generation | u64 next_tick | u8 older
//                                 | u16 k | k x (device id(32) | u16 r | r x (u64 from | u64 to)))
// all: these are every chat it has (a chat not named is one it lacks), or
// only some (one it was just given).
using Runs = std::vector<std::pair<std::uint64_t, std::uint64_t>>;  // inclusive, ascending, apart
struct LinkHave {
    bool all = true;
    struct Chat {
        ConversationId conversation{};
        std::uint64_t generation = 0, next_tick = 0;
        bool older = false;
        std::map<Key32, Runs> held;
    };
    std::vector<Chat> chats;
};
Bytes encode(const LinkHave& h);
LinkHave decode_link_have(const Bytes& b);
// The runs a log holds, per sender (at most 256 runs each: the newest kept).
std::map<Key32, Runs> runs_of(const std::vector<sg::net::Observation>& log);
bool holds(const std::map<Key32, Runs>& held, const Key32& sender, std::uint64_t sequence);

// A chat's finalized epochs a linked device lacks (control 14, LinkEpochs),
// and the handoff to the generation it is in, when it is one behind.
//   u8 11 | conversation(16) | u16 n | n x long(Finalized) | u8 h | (h = 1: long(HandoffAsk), endorsed)
struct LinkEpochs {
    ConversationId conversation{};
    std::vector<Bytes> epochs;  // encoded Finalized
    std::optional<HandoffAsk> handoff;
};
Bytes encode(const LinkEpochs& e);
LinkEpochs decode_link_epochs(const Bytes& b);

// A chat's messages a linked device lacks (control 15, LinkHistory):
//   u8 11 | conversation(16) | long(history items, as HistoryShare's)
struct LinkHistory {
    ConversationId conversation{};
    std::vector<HistoryItem> items;
};
Bytes encode(const LinkHistory& h);
LinkHistory decode_link_history(const Bytes& b);

// The agreed history going back from a known epoch: the earlier epoch, if it
// is the one `expect` names and its checkpoint is its own; refused otherwise.
bool epoch_before(const Finalized& f, const sg::net::Digest& expect);

}  // namespace chat
