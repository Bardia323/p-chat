#include "chat/Message.hpp"
#include "chat/Crypto.hpp"

namespace chat {

const char* type_name(Type t) {
    switch (t) {
    case Type::Text: return "text";
    case Type::Ack: return "ack";
    case Type::DeviceRevoked: return "device_revoked";
    case Type::HistorySync: return "history_sync";
    case Type::Rekey: return "rekey";
    case Type::Delivery: return "delivery";
    case Type::File: return "file";
    case Type::SenderKey: return "sender_key";
    case Type::GroupInvite: return "group_invite";
    case Type::Options: return "options";
    case Type::Push: return "push";
    case Type::Call: return "call";
    case Type::CallJoin: return "call_join";
    case Type::Game: return "game";
    case Type::Stroke: return "stroke";
    case Type::Release: return "release";
    case Type::LinkedChat: return "linked_chat";
    case Type::DeviceAsk: return "device_ask";
    case Type::Unlink: return "unlink";
    case Type::LinkName: return "link_name";
    }
    throw Refused("chat: unknown type");
}
std::optional<Type> type_of(const std::string& name) {
    for (auto t : {Type::Text, Type::Ack, Type::DeviceRevoked, Type::HistorySync, Type::Rekey, Type::Delivery, Type::File, Type::SenderKey, Type::GroupInvite, Type::Options, Type::Push, Type::Call, Type::CallJoin, Type::Game, Type::Stroke, Type::Release,
                   Type::LinkedChat, Type::DeviceAsk, Type::Unlink, Type::LinkName})
        if (name == type_name(t)) return t;
    return std::nullopt;
}

sg::net::Digest conversation_context(const ConversationId& c, std::uint64_t generation) {
    return blake2b256(Bytes{}, Writer("sg.chat.v1.context").raw(c).u64(generation).data());
}

Bytes encode(const Content& c) { return Writer().u8(protocol_version).u64(c.time_ms).long_bytes(c.body, 200000).take(); }
Content decode_content(const Bytes& b) {
    Reader r(b);
    const auto v = r.u8();
    if (v < 1 || v > protocol_version) throw Refused("chat: unknown content version");
    Content c;
    c.time_ms = r.u64();
    c.body = r.long_bytes(200000);
    r.end();
    return c;
}
namespace {
Bytes content_ad(const sg::net::Observation& o) {
    return Writer("sg.chat.v1.content").short_text(o.object).short_text(o.peer).u64(o.sequence).short_text(o.parameter).take();
}
}  // namespace
Bytes seal_content(const Key32& key, const Nonce& nonce, const sg::net::Observation& o, const Content& c) {
    return Writer().raw(nonce).raw(aead_lock(key, nonce, content_ad(o), encode(c))).take();
}
Content open_content(const Key32& key, const sg::net::Observation& o) {
    Reader r(o.payload);
    const auto nonce = r.fixed<24>();
    return decode_content(aead_unlock(key, nonce, content_ad(o), r.raw(r.left())));
}

Bytes observation_bytes(const sg::net::Observation& o) {
    sg::net::Message m;
    m.kind = sg::net::MessageKind::Inputs;
    m.from = m.to = "sgchat";
    m.inputs = {o};
    return sg::net::encode(m);
}
sg::net::Observation observation_from(const Bytes& b) {
    const auto m = sg::net::decode_message(b);
    if (m.kind != sg::net::MessageKind::Inputs || m.inputs.size() != 1) throw Refused("chat: not one observation");
    return m.inputs[0];
}

sg::net::Observation make_message(const ConversationId& c, std::uint64_t generation, const Key32& sender,
                                  std::uint64_t sequence, const std::string& type) {
    if (sequence == 0) throw Refused("chat: sequences start at 1");
    sg::net::Observation o;
    o.peer = hex(sender);
    o.context = conversation_context(c, generation);
    o.tick = generation;
    o.sequence = sequence;
    o.object = hex(c);
    o.parameter = type;
    o.discrete = true;
    o.conflict = o.peer + ":" + std::to_string(sequence);
    return o;
}
void check_message(const sg::net::Observation& o, const ConversationId& c, std::uint64_t generation) {
    if (o.object != hex(c) || o.context != conversation_context(c, generation) || o.tick != generation ||
        !o.discrete || o.sequence == 0 || o.conflict != o.peer + ":" + std::to_string(o.sequence) ||
        o.parameter.empty() || o.parameter.size() > 32 || o.payload.size() < 24 + 16)
        throw Refused("chat: not a message of this conversation and generation");
}

Bytes encode(const AckBody& a) {
    if (a.seen.size() > 1024) throw Refused("chat: too many acknowledgements");
    Writer w;
    w.u16(std::uint16_t(a.seen.size()));
    for (const auto& [d, s] : a.seen) w.raw(d).u64(s);
    return w.take();
}
AckBody decode_ack(const Bytes& b) {
    Reader r(b);
    AckBody a;
    const auto n = r.u16();
    if (n > 1024) throw Refused("chat: too many acknowledgements");
    for (unsigned i = 0; i < n; ++i) {
        const auto d = r.key();
        a.seen.emplace_back(d, r.u64());
    }
    r.end();
    return a;
}
Bytes encode(const RevokedBody& v) { return Writer().raw(v.device).u64(v.generation).take(); }
RevokedBody decode_revoked(const Bytes& b) {
    Reader r(b);
    RevokedBody v;
    v.device = r.key();
    v.generation = r.u64();
    r.end();
    return v;
}
Bytes encode(DeliveryMode m) { return Writer().u8(std::uint8_t(m)).take(); }
DeliveryMode decode_delivery(const Bytes& b) {
    Reader r(b);
    const auto m = r.u8();
    r.end();
    if (m != 1 && m != 2) throw Refused("chat: unknown delivery mode");
    return DeliveryMode(m);
}
Bytes encode(const RekeyBody& v) { return Writer().raw(v.secret).u64(v.secret_generation).take(); }
RekeyBody decode_rekey(const Bytes& b) {
    Reader r(b);
    RekeyBody v;
    v.secret = r.key();
    v.secret_generation = r.u64();
    r.end();
    return v;
}

Bytes wrap_ad(const Key32& sender, const Key32& recipient, const ConversationId& c, std::uint64_t sequence,
              const sg::net::Digest& id, const Header& h) {
    return Writer("sg.chat.v2.wrap").raw(sender).raw(recipient).raw(c).u64(sequence).raw(id).raw(encode(h)).take();
}

Bytes encode_frame(const MessageFrame& f, Version v, const Key32& recipient) {
    if (f.message.peer != hex(f.sender)) throw Refused("chat: a frame's sender is its message's peer");
    sg::net::Message m;
    m.kind = sg::net::MessageKind::Inputs;
    m.from = f.message.peer;
    m.to = hex(recipient);
    m.inputs = {f.message};
    Writer w;
    w.u8(std::uint8_t(FrameKind::Message)).raw(f.sender);
    if (v == Version::Ratchet) {
        if (f.wrapped.size() != 48) throw Refused("chat: a wrapped key is 48 bytes");
        w.raw(encode(f.header)).raw(f.wrapped);
    } else if (v == Version::Sealed) {
        w.raw(f.content_key);
    } else throw Refused("chat: a message frame is version 1 or 2");
    w.long_bytes(sg::net::encode(m), 262144);
    return w.take();
}
Bytes encode_frame(const ControlFrame& f) {
    return Writer().u8(std::uint8_t(FrameKind::Control)).raw(f.sender).u8(f.kind).long_bytes(f.body, 262144).take();
}
Frame decode_frame(const Bytes& b, Version v, const Key32& recipient) {
    Reader r(b);
    Frame f;
    const auto kind = r.u8();
    if (kind == std::uint8_t(FrameKind::Control)) {
        if (v != Version::Ratchet) throw Refused("chat: control frames travel under version 2");
        f.kind = FrameKind::Control;
        f.control.sender = r.key();
        f.control.kind = r.u8();
        f.control.body = r.long_bytes(262144);
        r.end();
        return f;
    }
    if (kind != std::uint8_t(FrameKind::Message)) throw Refused("chat: unknown frame kind");
    auto& m = f.message;
    m.sender = r.key();
    if (v == Version::Ratchet) {
        m.header = decode_header(r);
        m.wrapped = r.raw(48);
    } else if (v == Version::Sealed) {
        m.content_key = r.key();
    } else throw Refused("chat: a message frame is version 1 or 2");
    const auto inner = sg::net::decode_message(r.long_bytes(262144));
    r.end();
    if (inner.kind != sg::net::MessageKind::Inputs || inner.inputs.size() != 1 || inner.from != hex(m.sender) ||
        inner.to != hex(recipient) || inner.inputs[0].peer != inner.from)
        throw Refused("chat: a frame carries one message, from its sender, to its recipient");
    m.message = inner.inputs[0];
    return f;
}

bool accepts(Version v, bool ratchet_exists) {
    if (v == Version::Ratchet) return ratchet_exists;
    if (v == Version::Sealed) return !ratchet_exists;
    return false;
}

Key32 mailbox(const Key32& secret, const Key32& device, std::uint32_t day) {
    return blake2b256(secret, Writer("sg.chat.v1.mailbox").raw(device).u32(day).data());
}
Key32 room(const Key32& secret) { return blake2b256(secret, Writer("sg.chat.v1.room").data()); }

}  // namespace chat
