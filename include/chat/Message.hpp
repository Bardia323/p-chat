// A chat message is an engine Observation (sg::net): signed by its sender's
// device key, accepted only through sg::net::Integrity.
//
//   peer      = the sender device's id (hex)
//   context   = BLAKE2b("sg.chat.v1.context" | conversation | generation)
//   tick      = the committee generation it was sent under
//   sequence  = the sender device's own count in this conversation, from 1
//   object    = the conversation id (hex)
//   parameter = its type ("text", "ack", ...)
//   discrete  = true, conflict = "<peer>:<sequence>" (unique)
//   payload   = the content, sealed under a key of its own (content key)
//
// One observation goes to every member; each recipient device gets the
// content key wrapped for it alone, under the ratchet between the two, with
// sender, recipient, conversation, sequence and the observation's id as the
// wrap's associated data - so a message can be neither moved to another
// chat nor handed on sealed to someone else.
#pragma once
#include "chat/Pairing.hpp"
#include "chat/Ratchet.hpp"
#include "chat/Seal.hpp"
#include "sg/net/Protocol.hpp"

namespace chat {

// Protocol 2 added `delivery`, 3 `file`, 4 `sender_key` and `group_invite`,
// 5 `options` (and recovery's control frames), 6 `push`, 7 `call` and
// `call_join`, 8 `game` and `stroke`, 9 `release`, 11 `linked_chat`,
// `device_ask`, `unlink` and `link_name` (linked devices, Link.hpp). A
// message's content says the version it was written in; earlier ones are
// still read.
constexpr std::uint8_t protocol_version = 11;
enum class Type { Text, Ack, DeviceRevoked, HistorySync, Rekey, Delivery, File, SenderKey, GroupInvite, Options, Push, Call, CallJoin, Game, Stroke, Release,
                  LinkedChat, DeviceAsk, Unlink, LinkName };
const char* type_name(Type t);
// Unknown names are not refused here: they are acknowledged and ignored.
std::optional<Type> type_of(const std::string& name);

sg::net::Digest conversation_context(const ConversationId& c, std::uint64_t generation);

// What a message says, before it is sealed: when (for display only) and its body.
struct Content {
    std::uint64_t time_ms = 0;
    Bytes body;
};
Bytes encode(const Content& c);
Content decode_content(const Bytes& b);
// nonce (24) | mac | text; AD = "sg.chat.v1.content" | conversation | sender | sequence | type.
Bytes seal_content(const Key32& content_key, const Nonce& nonce, const sg::net::Observation& unsigned_message, const Content& c);
Content open_content(const Key32& content_key, const sg::net::Observation& message);

// An observation as it is kept and carried: the engine's own encoding, a
// protocol message of kind Inputs holding it alone.
Bytes observation_bytes(const sg::net::Observation& o);
sg::net::Observation observation_from(const Bytes& b);

// The observation, unsigned: sign `statement()` with the sender's device key.
sg::net::Observation make_message(const ConversationId& c, std::uint64_t generation, const Key32& sender,
                                  std::uint64_t sequence, const std::string& type);
// Its parts as they must be for a conversation and a generation, or refused.
void check_message(const sg::net::Observation& o, const ConversationId& c, std::uint64_t generation);

// Bodies of the control types.
struct AckBody {
    std::vector<std::pair<Key32, std::uint64_t>> seen;  // (sender device, sequence)
};
Bytes encode(const AckBody& a);
AckBody decode_ack(const Bytes& b);
struct RevokedBody {
    Key32 device{};
    std::uint64_t generation = 0;  // the committee generation it is no longer in
};
Bytes encode(const RevokedBody& r);
RevokedBody decode_revoked(const Bytes& b);
// How a device takes messages: live only (the relay keeps nothing for it)
// or also from its mailbox. Mailbox is an opt-in this device signs.
enum class DeliveryMode : std::uint8_t { Live = 1, Mailbox = 2 };
Bytes encode(DeliveryMode m);
DeliveryMode decode_delivery(const Bytes& b);
struct RekeyBody {
    Key32 secret{};
    std::uint64_t secret_generation = 0;
};
Bytes encode(const RekeyBody& r);
RekeyBody decode_rekey(const Bytes& b);

// The wrap's associated data: everything a wrapped key belongs to.
Bytes wrap_ad(const Key32& sender, const Key32& recipient, const ConversationId& c, std::uint64_t sequence,
              const sg::net::Digest& message_id, const Header& h);

// What a sealed box holds, padded. Kind 1: a message; kind 2: control, an
// engine protocol message (epochs) or a handoff step.
enum class FrameKind : std::uint8_t { Message = 1, Control = 2 };
struct MessageFrame {
    Key32 sender{};
    Header header;      // version 2 only
    Bytes wrapped;      // version 2: the content key under the ratchet (48 bytes)
    Key32 content_key{};// version 1 only: protected by the box alone
    sg::net::Observation message;  // signed
};
// The observation travels in the engine's own encoding: a protocol message
// of kind Inputs from the sender to the recipient, holding it alone.
Bytes encode_frame(const MessageFrame& f, Version v, const Key32& recipient);
struct ControlFrame {
    Key32 sender{};
    std::uint8_t kind = 0;  // see Trust.hpp
    Bytes body;
};
Bytes encode_frame(const ControlFrame& f);
struct Frame {
    FrameKind kind = FrameKind::Message;
    MessageFrame message;
    ControlFrame control;
};
Frame decode_frame(const Bytes& b, Version v, const Key32& recipient);
// A version 1 message is refused from a device a ratchet exists with: once
// there is one, a message without it is a downgrade, never a fallback.
bool accepts(Version v, bool ratchet_exists);

// Daily mailboxes: BLAKE2b-256(key = conversation secret, "sg.chat.v1.mailbox" | device | day).
Key32 mailbox(const Key32& secret, const Key32& device, std::uint32_t day);
// The signaling room both ends of a conversation meet in.
Key32 room(const Key32& secret);

}  // namespace chat
