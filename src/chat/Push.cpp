#include "chat/Push.hpp"
#include "chat/Crypto.hpp"

namespace chat {

namespace {
bool endpoint_ok(const std::string& e) {
    return e.size() <= 1024 && (e.rfind("https://", 0) == 0 || e.rfind("http://127.0.0.1:", 0) == 0 || e.rfind("http://localhost:", 0) == 0);
}
}  // namespace

Bytes encode(const PushInfo& p) {
    if (!endpoint_ok(p.endpoint)) throw Refused("chat: a push endpoint is https, at most 1024 bytes");
    if (p.p256dh[0] != 4 || p.vapid_public[0] != 4) throw Refused("chat: push keys are uncompressed P-256 points");
    return Writer().u8(6).short_text(p.endpoint).raw(p.p256dh).raw(p.auth).raw(p.vapid_private).raw(p.vapid_public).take();
}
PushInfo decode_push_info(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 6) throw Refused("chat: unknown push version");
    PushInfo p;
    p.endpoint = r.short_text(1024);
    p.p256dh = r.fixed<65>();
    p.auth = r.fixed<16>();
    p.vapid_private = r.key();
    p.vapid_public = r.fixed<65>();
    r.end();
    if (!endpoint_ok(p.endpoint) || p.p256dh[0] != 4 || p.vapid_public[0] != 4) throw Refused("chat: not a push subscription");
    return p;
}

Ping ping_id(const ConversationId& c, const Key32& sender, std::uint64_t sequence) {
    const auto h = blake2b(16, Bytes{}, Writer("sg.chat.v6.push.ping").raw(c).raw(sender).u64(sequence).data());
    Ping p{};
    std::copy(h.begin(), h.end(), p.begin());
    return p;
}
Bytes push_payload(const Ping& ping, const ConversationId& c) {
    const auto text = "p6." + hex(Bytes(ping.begin(), ping.end())) + "." + hex(Bytes(c.begin(), c.end()));
    return Bytes(text.begin(), text.end());
}

}  // namespace chat
