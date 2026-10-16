// What the engine's WebRtcTransport asks to be carried to a peer (an SDP, a
// candidate, a restart), signed by the sending device and routed by the
// relay only inside the conversation's room. The receiver checks the
// signature against the device it pinned before the transport sees it, and
// takes each sender's counter only forward (a replayed frame is dropped).
#pragma once
#include "chat/Wire.hpp"
#include "sg/net/IceSession.hpp"
#include "sg/net/Integrity.hpp"

namespace chat {

struct SignalFrame {
    Key32 room{}, from{}, to{};
    std::uint64_t counter = 0;
    sg::net::IceSignal signal;
    sg::net::Signature signature{};
};
Bytes signal_statement(const SignalFrame& f);  // "sg.chat.v1.signal" | everything but the signature
Bytes encode(const SignalFrame& f);
SignalFrame decode_signal(const Bytes& b);
bool signal_holds(const SignalFrame& f, const Key32& sender_sign_key);

// What the relay sees of it: who in the room it is for, by a label that
// means nothing outside the conversation, and the frame sealed under a key
// from the conversation's secret - the relay learns no device ids.
//   label = H(secret, "sg.chat.v1.label" | device id)
//   box   = nonce(24) | AEAD(H(secret, "sg.chat.v1.signal.key"), nonce, "sg.chat.v1.signal.ad" | room, frame)
Key32 label(const Key32& secret, const Key32& device);
Bytes signal_box(const Key32& secret, const std::array<std::uint8_t, 24>& nonce, const Bytes& frame);
Bytes signal_unbox(const Key32& secret, const Bytes& box);

}  // namespace chat
