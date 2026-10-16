#include "chat/Signal.hpp"
#include "chat/Crypto.hpp"
#include "chat/Message.hpp"

namespace chat {

namespace {
Writer fields(Writer w, const SignalFrame& f) {
    if (f.signal.value.size() > 65535 || f.signal.type.size() > 128) throw Refused("chat: an oversize signal");
    w.raw(f.room).raw(f.from).raw(f.to).u64(f.counter);
    w.u8(f.signal.lane == sg::net::DeliveryClass::Latest ? 1 : 0).u64(f.signal.session).u8(std::uint8_t(f.signal.kind));
    w.short_text(f.signal.value).short_text(f.signal.type);
    return w;
}
}  // namespace

Bytes signal_statement(const SignalFrame& f) { return fields(Writer("sg.chat.v1.signal"), f).take(); }
Bytes encode(const SignalFrame& f) { return fields(Writer().u8(1), f).raw(f.signature).take(); }
SignalFrame decode_signal(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 1) throw Refused("chat: unknown signal version");
    SignalFrame f;
    f.room = r.key();
    f.from = r.key();
    f.to = r.key();
    f.counter = r.u64();
    const auto lane = r.u8();
    if (lane > 1) throw Refused("chat: unknown lane");
    f.signal.lane = lane ? sg::net::DeliveryClass::Latest : sg::net::DeliveryClass::Reliable;
    f.signal.session = r.u64();
    const auto kind = r.u8();
    if (kind > 2) throw Refused("chat: unknown signal kind");
    f.signal.kind = sg::net::IceSignalKind(kind);
    f.signal.value = r.short_text(65535);
    f.signal.type = r.short_text(128);
    f.signature = r.fixed<64>();
    r.end();
    f.signal.peer = hex(f.from);
    return f;
}
bool signal_holds(const SignalFrame& f, const Key32& key) {
    return sg::net::check_signature(key, signal_statement(f), f.signature);
}

Key32 label(const Key32& secret, const Key32& device) {
    return blake2b256(secret, Writer("sg.chat.v1.label").raw(device).data());
}
namespace {
Key32 signal_key(const Key32& secret) { return blake2b256(secret, Writer("sg.chat.v1.signal.key").data()); }
Bytes signal_ad(const Key32& secret) { return Writer("sg.chat.v1.signal.ad").raw(room(secret)).take(); }
}  // namespace
Bytes signal_box(const Key32& secret, const std::array<std::uint8_t, 24>& nonce, const Bytes& frame) {
    return Writer().raw(nonce).raw(aead_lock(signal_key(secret), nonce, signal_ad(secret), frame)).take();
}
Bytes signal_unbox(const Key32& secret, const Bytes& box) {
    Reader r(box);
    const auto nonce = r.fixed<24>();
    return aead_unlock(signal_key(secret), nonce, signal_ad(secret), r.raw(r.left()));
}

}  // namespace chat
