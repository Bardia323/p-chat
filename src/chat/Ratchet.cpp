#include "chat/Ratchet.hpp"
#include "chat/Crypto.hpp"
#include "chat/Seal.hpp"
#include <algorithm>

namespace chat {

namespace {
// KDF_RK: a new root key and chain key from the root and a turn's X25519.
std::pair<Key32, Key32> root_step(const Key32& root, const Key32& shared) {
    const auto out = blake2b(64, Bytes(root.begin(), root.end()), Writer("sg.chat.v2.ratchet.root").raw(shared).data());
    return {key_from(Bytes(out.begin(), out.begin() + 32)), key_from(Bytes(out.begin() + 32, out.end()))};
}
// KDF_CK: the message key and the next chain key.
std::pair<Key32, Key32> chain_step(const Key32& chain) {
    return {blake2b256(chain, Writer("sg.chat.v2.ratchet.message").data()),
            blake2b256(chain, Writer("sg.chat.v2.ratchet.chain").data())};
}
void keep_skipped(Ratchet& r, std::uint32_t until) {
    if (!r.receiving) return;
    if (until > r.nr && until - r.nr > max_skip) throw Refused("chat: a message too far ahead of its chain");
    while (r.nr < until) {
        auto [mk, next] = chain_step(r.receive);
        r.skipped.push_back({r.theirs, r.nr, mk});
        wipe(r.receive);
        r.receive = next;
        wipe(mk);
        wipe(next);
        ++r.nr;
    }
    // The oldest skipped keys go first when there are too many.
    if (r.skipped.size() > max_kept) {
        const auto drop = r.skipped.size() - max_kept;
        for (std::size_t i = 0; i < drop; ++i) wipe(r.skipped[i].key);
        r.skipped.erase(r.skipped.begin(), r.skipped.begin() + std::ptrdiff_t(drop));
    }
}
}  // namespace

Ratchet::~Ratchet() {
    wipe(root);
    wipe(send);
    wipe(receive);
    for (auto& s : skipped) wipe(s.key);
}

Bytes encode(const Header& h) { return Writer().raw(h.dh).u32(h.pn).u32(h.n).take(); }
Header decode_header(Reader& r) {
    Header h;
    h.dh = r.key();
    h.pn = r.u32();
    h.n = r.u32();
    return h;
}

Bytes encode(const Ratchet& r) {
    Writer w("sg.chat.v2.ratchet.state");
    w.raw(r.root).raw(r.send).raw(r.receive).u8(r.sending).u8(r.receiving).raw(r.own).raw(r.theirs);
    w.u32(r.ns).u32(r.nr).u32(r.pn).u32(std::uint32_t(r.skipped.size()));
    for (const auto& s : r.skipped) w.raw(s.dh).u32(s.n).raw(s.key);
    return w.take();
}
Ratchet decode_ratchet(const Bytes& b) {
    Reader rd(b, "sg.chat.v2.ratchet.state");
    Ratchet r;
    r.root = rd.key();
    r.send = rd.key();
    r.receive = rd.key();
    r.sending = rd.u8() != 0;
    r.receiving = rd.u8() != 0;
    r.own = rd.key();
    r.theirs = rd.key();
    r.ns = rd.u32();
    r.nr = rd.u32();
    r.pn = rd.u32();
    const auto n = rd.u32();
    if (n > max_kept) throw Refused("chat: too many skipped keys");
    for (std::uint32_t i = 0; i < n; ++i) {
        Skipped s;
        s.dh = rd.key();
        s.n = rd.u32();
        s.key = rd.key();
        r.skipped.push_back(s);
    }
    rd.end();
    return r;
}

Key32 ratchet_seed(const Key32& secret, const Key32& shared, const Key32& a, const Key32& b) {
    const bool order = first_of(a, b);
    return blake2b256(secret, Writer("sg.chat.v2.ratchet.seed").raw(shared).raw(order ? a : b).raw(order ? b : a).data());
}
bool first_of(const Key32& own, const Key32& their) {
    if (own == their) throw Refused("chat: a device has no ratchet with itself");
    return std::lexicographical_compare(own.begin(), own.end(), their.begin(), their.end());
}
Ratchet start_first(const Key32& seed, const Key32& own_static, const Key32& their_static, const Key32& shared) {
    Ratchet r;
    std::tie(r.root, r.send) = root_step(seed, shared);
    r.sending = true;
    r.own = own_static;
    r.theirs = their_static;
    return r;
}
Ratchet start_second(const Key32& seed, const Key32& own_static, const Key32& their_static, const Key32& shared,
                     const Key32& fresh, const Key32& fresh_shared) {
    Ratchet r;
    std::tie(r.root, r.receive) = root_step(seed, shared);
    r.receiving = true;
    r.theirs = their_static;
    (void)own_static;
    std::tie(r.root, r.send) = root_step(r.root, fresh_shared);
    r.sending = true;
    r.own = fresh;
    return r;
}

Sent ratchet_send(Ratchet& r) {
    if (!r.sending) throw Refused("chat: no sending chain yet");
    if (r.ns == 0xffffffffu) throw Refused("chat: a sending chain is spent");
    auto [mk, next] = chain_step(r.send);
    Sent out{{r.own, r.pn, r.ns}, mk};
    wipe(r.send);
    r.send = next;
    wipe(mk);
    wipe(next);
    ++r.ns;
    return out;
}

bool needs_turn(const Ratchet& r, const Header& h) {
    for (const auto& s : r.skipped)
        if (s.dh == h.dh && s.n == h.n) return false;
    return !(r.receiving && h.dh == r.theirs);
}

std::pair<Ratchet, Key32> ratchet_receive(const Ratchet& in, const Header& h, const std::optional<Turn>& turn) {
    Ratchet r = in;
    for (auto it = r.skipped.begin(); it != r.skipped.end(); ++it)
        if (it->dh == h.dh && it->n == h.n) {
            const auto key = it->key;
            wipe(it->key);
            r.skipped.erase(it);
            return {r, key};
        }
    if (!(r.receiving && h.dh == r.theirs)) {
        if (!turn) throw Refused("chat: this header needs a ratchet turn");
        // What is left of the old chain is kept for messages still on the way.
        keep_skipped(r, h.pn);
        r.pn = r.ns;
        r.ns = 0;
        r.nr = 0;
        r.theirs = h.dh;
        std::tie(r.root, r.receive) = root_step(r.root, turn->received);
        r.receiving = true;
        r.own = turn->fresh;
        std::tie(r.root, r.send) = root_step(r.root, turn->sent);
        r.sending = true;
    }
    if (h.n < r.nr) throw Refused("chat: a message key already used");
    keep_skipped(r, h.n);
    auto [mk, next] = chain_step(r.receive);
    wipe(r.receive);
    r.receive = next;
    wipe(next);
    ++r.nr;
    return {r, mk};
}

namespace {
std::pair<Key32, Nonce> wrap_keys(const Key32& mk) {
    const auto out = blake2b(64, Bytes(mk.begin(), mk.end()), Writer("sg.chat.v2.ratchet.keys").data());
    Nonce nonce{};
    std::copy(out.begin() + 32, out.begin() + 56, nonce.begin());
    return {key_from(Bytes(out.begin(), out.begin() + 32)), nonce};
}
}  // namespace
Bytes wrap(const Key32& mk, const Bytes& ad, const Key32& content_key) {
    const auto [key, nonce] = wrap_keys(mk);
    return aead_lock(key, nonce, ad, Bytes(content_key.begin(), content_key.end()));
}
Key32 unwrap(const Key32& mk, const Bytes& ad, const Bytes& wrapped) {
    const auto [key, nonce] = wrap_keys(mk);
    return key_from(aead_unlock(key, nonce, ad, wrapped));
}

}  // namespace chat
