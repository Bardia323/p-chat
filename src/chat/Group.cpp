#include "chat/Group.hpp"
#include "chat/Crypto.hpp"

namespace chat {

Bytes encode(const SenderKey& k) { return Writer().u8(4).raw(k.id).raw(k.chain).u32(k.iteration).take(); }
SenderKey decode_sender_key(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 4) throw Refused("chat: unknown sender key version");
    SenderKey k;
    k.id = r.key();
    k.chain = r.key();
    k.iteration = r.u32();
    r.end();
    return k;
}
namespace {
std::pair<Key32, Key32> step(const Key32& chain) {
    return {blake2b256(chain, Writer("sg.chat.v4.sender.message").data()), blake2b256(chain, Writer("sg.chat.v4.sender.chain").data())};
}
}  // namespace
Key32 sender_step(SenderKey& k) {
    if (k.iteration == 0xffffffffu) throw Refused("chat: a sender key is spent");
    auto [mk, next] = step(k.chain);
    wipe(k.chain);
    k.chain = next;
    wipe(next);
    ++k.iteration;
    return mk;
}
Key32 sender_key_at(SenderChain& c, std::uint32_t it) {
    for (auto i = c.skipped.begin(); i != c.skipped.end(); ++i)
        if (i->first == it) {
            const auto mk = i->second;
            wipe(i->second);
            c.skipped.erase(i);
            return mk;
        }
    if (it < c.key.iteration) throw Refused("chat: a sender key already used");
    if (it - c.key.iteration > 1000) throw Refused("chat: a message too far ahead of its sender key");
    while (c.key.iteration < it) {
        const auto at = c.key.iteration;
        c.skipped.emplace_back(at, sender_step(c.key));
        if (c.skipped.size() > 256) {
            wipe(c.skipped.front().second);
            c.skipped.erase(c.skipped.begin());
        }
    }
    return sender_step(c.key);
}

Bytes encode_frame(const SenderFrame& f, const Key32& recipient) {
    if (f.message.peer != hex(f.sender)) throw Refused("chat: a frame's sender is its message's peer");
    sg::net::Message m;
    m.kind = sg::net::MessageKind::Inputs;
    m.from = f.message.peer;
    m.to = hex(recipient);
    m.inputs = {f.message};
    return Writer().u8(3).raw(f.sender).raw(f.key_id).u32(f.iteration).long_bytes(sg::net::encode(m), 262144).take();
}
SenderFrame decode_sender_frame(const Bytes& b, const Key32& recipient) {
    Reader r(b);
    if (r.u8() != 3) throw Refused("chat: not a sender-key frame");
    SenderFrame f;
    f.sender = r.key();
    f.key_id = r.key();
    f.iteration = r.u32();
    const auto inner = sg::net::decode_message(r.long_bytes(262144));
    r.end();
    if (inner.kind != sg::net::MessageKind::Inputs || inner.inputs.size() != 1 || inner.from != hex(f.sender) ||
        inner.to != hex(recipient) || inner.inputs[0].peer != inner.from)
        throw Refused("chat: a frame carries one message, from its sender, to its recipient");
    f.message = inner.inputs[0];
    return f;
}

Bytes encode(const GroupInvite& g) {
    if (g.name.size() > 64 || g.members.empty() || g.members.size() > 64) throw Refused("chat: a group invite out of bounds");
    Writer w;
    w.u8(4).raw(g.group).u8(std::uint8_t(g.kind)).raw(g.secret).u64(g.secret_generation).short_text(g.name).u64(g.generation);
    w.u8(std::uint8_t(g.members.size()));
    for (const auto& m : g.members) w.raw(m.device.sign).raw(m.device.agree).u8(member_flags(m));
    w.long_bytes(g.trust, 1 << 22);
    w.u8(std::uint8_t(g.before.size()));
    for (const auto& m : g.before) w.raw(m.device.sign).raw(m.device.agree).u8(member_flags(m));
    return w.take();
}
GroupInvite decode_group_invite(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 4) throw Refused("chat: unknown group invite version");
    GroupInvite g;
    g.group = r.fixed<16>();
    const auto kind = r.u8();
    if (kind != 1 && kind != 2) throw Refused("chat: a group invite is for a group or a channel");
    g.kind = Kind(kind);
    g.secret = r.key();
    g.secret_generation = r.u64();
    g.name = r.short_text(64);
    g.generation = r.u64();
    const auto n = r.u8();
    if (n == 0 || n > 64) throw Refused("chat: a group is 1..64 devices");
    for (unsigned i = 0; i < n; ++i) {
        Device d;
        d.sign = r.key();
        d.agree = r.key();
        g.members.push_back(member_of(d, r.u8()));
    }
    g.trust = r.long_bytes(1 << 22);
    const auto nb = r.u8();
    for (unsigned i = 0; i < nb; ++i) {
        Device d;
        d.sign = r.key();
        d.agree = r.key();
        g.before.push_back(member_of(d, r.u8()));
    }
    r.end();
    return g;
}

Key32 channel_mailbox(const Key32& secret, std::uint32_t day) {
    return blake2b256(secret, Writer("sg.chat.v4.channel.mailbox").u32(day).data());
}
namespace {
Key32 post_key(const Key32& secret) { return blake2b256(secret, Writer("sg.chat.v4.channel.post").data()); }
}  // namespace
Bytes channel_envelope(const Key32& secret, std::uint32_t day, const Bytes& frame, const Nonce& nonce) {
    const auto mailbox = channel_mailbox(secret, day);
    const auto ad = Writer("sg.chat.v4.channel.ad").raw(mailbox).take();
    return Writer().u8(18).raw(mailbox).raw(nonce).raw(aead_lock(post_key(secret), nonce, ad, pad(frame))).take();
}
Bytes open_channel_envelope(const Key32& secret, const Bytes& e) {
    Reader r(e);
    if (r.u8() != 18) throw Refused("chat: not a channel post");
    const auto mailbox = r.key();
    const auto nonce = r.fixed<24>();
    const auto ad = Writer("sg.chat.v4.channel.ad").raw(mailbox).take();
    return unpad(aead_unlock(post_key(secret), nonce, ad, r.raw(r.left())));
}

}  // namespace chat
