// Notifications (protocol 6).
//
// A device that wants to be woken makes its own VAPID key pair (P-256),
// subscribes with the push service of its browser, and tells each of its
// conversations - in a signed `push` message, sealed like any other - where
// to push and the VAPID private key to push with. A member whose message
// cannot reach it live then makes the push itself (the relay holds no key):
// a payload sealed to the subscription (RFC 8291) that says only which
// ping it is and in which conversation, under a VAPID token (RFC 8292). The
// woken device shows the symbol it chose for that conversation, if any:
// no sender, no words. Pings of one message carry one id, shown once.
#pragma once
#include "chat/Message.hpp"

namespace chat {

struct PushInfo {
    std::string endpoint;               // https (http on the loopback, for tests), at most 1024 bytes
    std::array<std::uint8_t, 65> p256dh{};  // the subscription's key (uncompressed P-256)
    std::array<std::uint8_t, 16> auth{};
    Key32 vapid_private{};              // P-256 scalar
    std::array<std::uint8_t, 65> vapid_public{};
};
Bytes encode(const PushInfo& p);
PushInfo decode_push_info(const Bytes& b);

// What a push carries, sealed to the woken device, as text:
// "p6." hex(ping) "." hex(conversation) - 68 bytes.
using Ping = std::array<std::uint8_t, 16>;
Ping ping_id(const ConversationId& conversation, const Key32& sender, std::uint64_t sequence);
Bytes push_payload(const Ping& ping, const ConversationId& conversation);

}  // namespace chat
