// Groups and channels (protocol 4).
//
// A group is a conversation of many: its committee is every member's
// devices, its ordering the same Agreement, who is in it the same handoffs.
// Each device speaks in it under a sender key of its own - a chain that
// gives one content key per message - handed to every other member over
// the pairwise ratchets, and replaced by a fresh one whenever who is in the
// group changes: a member taken out cannot read what follows.
//
// A channel is a group whose committee is its publisher's devices alone.
// Readers hold its key from their invite; they check every post against the
// publisher's committee, and cannot post. Posts are put once at the relay,
// at the channel's daily mailbox, sealed under a key from its secret.
#pragma once
#include "chat/Message.hpp"

namespace chat {

// Protocol 11 added Self: the conversation of one person's linked devices
// alone (Link.hpp), over which they keep each other's chats.
enum class Kind : std::uint8_t { Direct = 0, Group = 1, Channel = 2, Self = 3 };

// A sender key: an id, a chain key, and how far the chain has gone.
struct SenderKey {
    Key32 id{};
    Key32 chain{};
    std::uint32_t iteration = 0;
};
Bytes encode(const SenderKey& k);
SenderKey decode_sender_key(const Bytes& b);
// The content key for the next message, and the chain moved on.
Key32 sender_step(SenderKey& k);
// A receiver's copy: the key for `iteration`, keeping the ones skipped (at
// most 1000 ahead; `skipped` holds at most 256) - the chain moves only forward.
struct SenderChain {
    SenderKey key;
    std::vector<std::pair<std::uint32_t, Key32>> skipped;
};
Key32 sender_key_at(SenderChain& c, std::uint32_t iteration);

// A message under a sender key (frame kind 3, envelope version 2):
// u8 3 | sender | key id | u32 iteration | long(observation as engine Message).
struct SenderFrame {
    Key32 sender{}, key_id{};
    std::uint32_t iteration = 0;
    sg::net::Observation message;
};
Bytes encode_frame(const SenderFrame& f, const Key32& recipient);
SenderFrame decode_sender_frame(const Bytes& b, const Key32& recipient);

// The group invite (a message of type `group_invite` in a direct
// conversation from its owner's side): what the new member needs.
struct GroupInvite {
    ConversationId group{};
    Kind kind = Kind::Group;
    Key32 secret{};
    std::uint64_t secret_generation = 0;
    std::string name;
    std::uint64_t generation = 0;
    std::vector<Member> members;
    Bytes trust;  // empty at generation 0; else Finalized | Handoff, as a pairing's
    std::vector<Member> before;  // with trust: the committee the handoff came from
};
Bytes encode(const GroupInvite& g);
GroupInvite decode_group_invite(const Bytes& b);

// A channel's posts at the relay (envelope version 18):
// u8 18 | channel mailbox(day) | nonce | AEAD(post key, ad, pad(sender frame)).
Key32 channel_mailbox(const Key32& secret, std::uint32_t day);
Bytes channel_envelope(const Key32& secret, std::uint32_t day, const Bytes& frame, const std::array<std::uint8_t, 24>& nonce);
Bytes open_channel_envelope(const Key32& secret, const Bytes& envelope);

}  // namespace chat
