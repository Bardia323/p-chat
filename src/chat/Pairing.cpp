#include "chat/Pairing.hpp"
#include "chat/Crypto.hpp"

namespace chat {

namespace {
void device(Writer& w, const Device& d) { w.raw(d.sign).raw(d.agree); }
Device device(Reader& r) {
    Device d;
    d.sign = r.key();
    d.agree = r.key();
    return d;
}
sg::net::Signature signature(Reader& r) { return r.fixed<64>(); }
void utf8_bound(const std::string& s, std::size_t n, const char* what) {
    if (s.size() > n) throw Refused(std::string("chat: ") + what + " is too long");
}
}  // namespace

std::uint8_t member_flags(const Member& m) { return std::uint8_t(std::uint8_t(m.side) | (m.mail ? 2 : 0)); }
Member member_of(const Device& d, std::uint8_t flags) {
    if (flags > 3) throw Refused("chat: unknown member flags");
    return {d, Side(flags & 1), (flags & 2) != 0};
}

Bytes encode(const Invite& i) {
    utf8_bound(i.relay, 512, "a relay address");
    if (std::uint8_t(i.kind) < 1 || std::uint8_t(i.kind) > 5) throw Refused("chat: unknown invite kind");
    Writer w;
    w.u8(1).u8(std::uint8_t(i.kind));
    device(w, i.owner);
    w.raw(i.token).raw(i.secret).short_text(i.relay);
    return w.take();
}
Invite decode_invite(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 1) throw Refused("chat: unknown invite version");
    Invite i;
    const auto kind = r.u8();
    if (kind < 1 || kind > 5) throw Refused("chat: unknown invite kind");
    i.kind = InviteKind(kind);
    i.owner = device(r);
    i.token = r.fixed<16>();
    i.secret = r.key();
    i.relay = r.short_text(512);
    r.end();
    // None (protocol 10): an invite given in person, its pairing carried on a
    // link the two phones made themselves; the chat then has no relay.
    const bool secure = i.relay.empty() || i.relay.rfind("wss://", 0) == 0 || i.relay.rfind("ws://127.0.0.1:", 0) == 0 ||
                        i.relay.rfind("ws://localhost:", 0) == 0;
    if (!secure) throw Refused("chat: a relay is wss://, or ws:// on loopback");
    return i;
}
std::string invite_fragment(const Invite& i) { return "v1." + base64url(encode(i)); }
Invite invite_from_fragment(const std::string& f) {
    if (f.rfind("v1.", 0) != 0) throw Refused("chat: not a v1 invite");
    return decode_invite(from_base64url(f.substr(3)));
}

Key32 pair_key(const std::string& code, const Invite& i) {
    return argon2id(normalize_code(code), Bytes(i.secret.begin(), i.secret.end()),
                    Writer("sg.chat.v1.pair.code").raw(i.token).data());
}

namespace {
Writer request_fields(const std::string& domain, const Invite& i, const PairRequest& r) {
    Writer w(domain);
    w.raw(i.token);
    device(w, i.owner);
    device(w, r.device);
    w.raw(r.nonce).short_text(r.name);
    if (r.version >= 2) w.u8(r.mail ? 1 : 0);
    return w;
}
}  // namespace
Key32 request_mac(const Key32& key, const Invite& i, const PairRequest& r) {
    return blake2b256(key, request_fields("sg.chat.v1.pair.request", i, r).data());
}
Bytes request_statement(const Invite& i, const PairRequest& r) {
    return request_fields("sg.chat.v1.pair.request.sig", i, r).raw(r.mac).take();
}
Bytes encode(const PairRequest& r) {
    utf8_bound(r.name, 64, "a name");
    Writer w;
    if (r.version != 1 && r.version != 2) throw Refused("chat: unknown request version");
    w.u8(r.version);
    device(w, r.device);
    w.raw(r.nonce).short_text(r.name);
    if (r.version >= 2) w.u8(r.mail ? 1 : 0);
    w.raw(r.mac).raw(r.signature);
    return w.take();
}
PairRequest decode_request(const Bytes& b) {
    Reader rd(b);
    PairRequest r;
    r.version = rd.u8();
    if (r.version != 1 && r.version != 2) throw Refused("chat: unknown request version");
    r.device = device(rd);
    r.nonce = rd.fixed<16>();
    r.name = rd.short_text(64);
    if (r.version >= 2) {
        const auto mail = rd.u8();
        if (mail > 1) throw Refused("chat: unknown delivery");
        r.mail = mail == 1;
    }
    r.mac = rd.key();
    r.signature = signature(rd);
    rd.end();
    return r;
}
bool request_holds(const Key32& key, const Invite& i, const PairRequest& r) {
    const auto mac = request_mac(key, i, r);
    if (!same(mac.data(), r.mac.data(), 32)) return false;
    return sg::net::check_signature(r.device.sign, request_statement(i, r), r.signature);
}

Bytes accept_body(const PairAccept& a) {
    utf8_bound(a.owner_name, 64, "a name");
    if (a.members.empty() || a.members.size() > 64) throw Refused("chat: a committee is 1..64 devices");
    Writer w;
    w.u8(1).raw(a.conversation).raw(a.secret).u64(a.secret_generation).short_text(a.owner_name).u64(a.generation);
    w.u8(std::uint8_t(a.members.size()));
    for (const auto& m : a.members) {
        device(w, m.device);
        w.u8(member_flags(m));
    }
    w.long_bytes(a.trust, 200000);
    return w.take();
}
namespace {
Writer accept_transcript(const std::string& domain, const Invite& i, const PairRequest& r, const PairAccept& a) {
    Writer w(domain);
    w.raw(i.token).raw(r.nonce);
    device(w, i.owner);
    device(w, r.device);
    w.raw(blake2b256(Bytes{}, accept_body(a)));
    return w;
}
}  // namespace
Key32 accept_mac(const Key32& key, const Invite& i, const PairRequest& r, const PairAccept& a) {
    return blake2b256(key, accept_transcript("sg.chat.v1.pair.accept", i, r, a).data());
}
Bytes accept_statement(const Invite& i, const PairRequest& r, const PairAccept& a) {
    return accept_transcript("sg.chat.v1.pair.accept.sig", i, r, a).raw(a.mac).take();
}
Bytes encode(const PairAccept& a) { return Writer().raw(accept_body(a)).raw(a.mac).raw(a.signature).take(); }
PairAccept decode_accept(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 1) throw Refused("chat: unknown accept version");
    PairAccept a;
    a.conversation = r.fixed<16>();
    a.secret = r.key();
    a.secret_generation = r.u64();
    a.owner_name = r.short_text(64);
    a.generation = r.u64();
    const auto n = r.u8();
    if (n == 0 || n > 64) throw Refused("chat: a committee is 1..64 devices");
    for (unsigned k = 0; k < n; ++k) {
        const auto d = device(r);
        a.members.push_back(member_of(d, r.u8()));
    }
    a.trust = r.long_bytes(200000);
    a.mac = r.key();
    a.signature = signature(r);
    r.end();
    return a;
}
bool accept_holds(const Key32& key, const Invite& i, const PairRequest& r, const PairAccept& a) {
    const auto mac = accept_mac(key, i, r, a);
    if (!same(mac.data(), a.mac.data(), 32)) return false;
    return sg::net::check_signature(i.owner.sign, accept_statement(i, r, a), a.signature);
}

Key32 reply_mailbox(const Invite& i, const Key32& id) {
    return blake2b256(i.secret, Writer("sg.chat.v1.pair.reply").raw(i.token).raw(id).data());
}

}  // namespace chat
