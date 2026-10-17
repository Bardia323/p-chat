// Pairing: an invite in a link, a code said aloud, a request and a reply.
//
// The link carries the owner device's keys, the relay, a one-time token and
// an invite secret; it never reaches a server (it is the URL's fragment).
// The code stretched by Argon2id with the invite secret as salt is the
// pair key: both the request and the reply carry a MAC under it, so neither
// side accepts a pairing from someone who has only the link, or only the code.
#pragma once
#include "chat/Identity.hpp"
#include "sg/net/Integrity.hpp"

namespace chat {

using Token = std::array<std::uint8_t, 16>;

// Protocol 4 added Channel: a reader of a channel (reusable until cancelled).
// Protocol 5 added Recovery: a new device for one that was lost.
// Protocol 11 added Link: another device of one's own, linked to this one.
enum class InviteKind : std::uint8_t { Contact = 1, ExtraDevice = 2, ReusableDevice = 3, Channel = 4, Recovery = 5, Link = 6 };
struct Invite {
    InviteKind kind = InviteKind::Contact;
    Device owner;
    Token token{};
    Key32 secret{};
    std::string relay;  // wss:// (or ws:// on loopback), at most 512 bytes; empty: given in person (protocol 10)
};
Bytes encode(const Invite& i);
Invite decode_invite(const Bytes& b);
// "v1." + base64url(encode(invite)), the part of the link after '#'.
std::string invite_fragment(const Invite& i);
Invite invite_from_fragment(const std::string& fragment);

// Argon2id(code, salt = invite secret, ad = "sg.chat.v1.pair.code" | token).
Key32 pair_key(const std::string& normalized_code, const Invite& i);

// The new device asks: its keys, a nonce, the name it gives, a MAC under
// the pair key, and its own signature (it holds the key it asks to pin).
struct PairRequest {
    Device device;
    Token nonce{};
    std::string name;  // at most 64 bytes of UTF-8
    bool mail = false; // protocol 2: whether the new device takes mail
    std::uint8_t version = 2;  // a protocol 1 request (no delivery) is still taken
    Key32 mac{};
    sg::net::Signature signature{};
};
Key32 request_mac(const Key32& pair_key, const Invite& i, const PairRequest& r);
Bytes request_statement(const Invite& i, const PairRequest& r);  // what the device signs (includes the MAC)
Bytes encode(const PairRequest& r);
PairRequest decode_request(const Bytes& b);
// The owner's check: the MAC under its own pair key, then the signature.
bool request_holds(const Key32& pair_key, const Invite& i, const PairRequest& r);

// A member of a conversation's committee: a device, and whose side it is on.
enum class Side : std::uint8_t { Owner = 0, Friend = 1 };
struct Member {
    Device device;
    Side side = Side::Friend;
    bool mail = false;  // takes mail: messages may wait for it in its mailbox (protocol 2)
};
// A member's one byte: bit 0 its side, bit 1 whether it takes mail. Protocol
// 1 wrote only the side, which reads the same (no mail).
std::uint8_t member_flags(const Member& m);
Member member_of(const Device& d, std::uint8_t flags);
using ConversationId = std::array<std::uint8_t, 16>;

// The owner answers: the conversation, its secret, its committee as it will
// be, and what the new device needs to take up the conversation's trust
// (empty for a new contact; a verified handoff for a further device).
struct PairAccept {
    ConversationId conversation{};
    Key32 secret{};
    std::uint64_t secret_generation = 0;
    std::string owner_name;
    std::uint64_t generation = 0;
    std::vector<Member> members;
    Bytes trust;
    Key32 mac{};
    sg::net::Signature signature{};
};
Bytes accept_body(const PairAccept& a);
// MAC over the transcript: both devices' keys, the token, the request's
// nonce, and the body.
Key32 accept_mac(const Key32& pair_key, const Invite& i, const PairRequest& r, const PairAccept& a);
Bytes accept_statement(const Invite& i, const PairRequest& r, const PairAccept& a);  // what the owner signs
Bytes encode(const PairAccept& a);
PairAccept decode_accept(const Bytes& b);
// The new device's check: MAC, then the owner device's signature.
bool accept_holds(const Key32& pair_key, const Invite& i, const PairRequest& r, const PairAccept& a);

// Where the reply waits: a mailbox only the two ends can name.
Key32 reply_mailbox(const Invite& i, const Key32& new_device_id);

}  // namespace chat
