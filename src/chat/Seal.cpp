#include "chat/Seal.hpp"
#include "chat/Crypto.hpp"

namespace chat {

Bytes pad(const Bytes& frame) {
    for (const auto size : buckets)
        if (frame.size() + 4 <= size) {
            Bytes out = Writer().u32(std::uint32_t(frame.size())).raw(frame).take();
            out.resize(size, 0);
            return out;
        }
    throw Refused("chat: a message larger than the largest bucket");
}
Bytes unpad(const Bytes& padded) {
    bool bucket = false;
    for (const auto size : buckets) bucket |= padded.size() == size;
    if (!bucket) throw Refused("chat: not a padded bucket");
    Reader r(padded);
    const auto n = r.u32();
    if (n > padded.size() - 4) throw Refused("chat: padding length out of range");
    Bytes frame = r.raw(n);
    std::uint8_t rest = 0;
    for (std::size_t i = 4 + n; i < padded.size(); ++i) rest |= padded[i];
    if (rest) throw Refused("chat: nonzero padding");
    // The smallest bucket that holds it, and no other, is the canonical one.
    for (const auto size : buckets)
        if (frame.size() + 4 <= size) {
            if (size != padded.size()) throw Refused("chat: padded to a larger bucket than needed");
            break;
        }
    return frame;
}

Key32 seal_key(const std::string& purpose, const Key32& shared, const Key32& ephemeral, const Key32& recipient) {
    return blake2b256(Bytes{}, Writer("sg.chat.v1.seal." + purpose).raw(shared).raw(ephemeral).raw(recipient).data());
}
Bytes seal_with(const std::string& purpose, const Key32& shared, const Key32& ephemeral, const Key32& recipient,
                const Nonce& nonce, const Bytes& plain) {
    const auto key = seal_key(purpose, shared, ephemeral, recipient);
    const auto ad = Writer("sg.chat.v1.seal.ad").raw(ephemeral).raw(recipient).data();
    return Writer().raw(ephemeral).raw(nonce).raw(aead_lock(key, nonce, ad, plain)).take();
}
Key32 box_ephemeral(const Bytes& box) {
    if (box.size() < seal_overhead) throw Refused("chat: a box shorter than its overhead");
    return key_from(Bytes(box.begin(), box.begin() + 32));
}
Bytes open_with(const std::string& purpose, const Key32& shared, const Key32& recipient, const Bytes& box) {
    Reader r(box);
    const auto ephemeral = r.key();
    const auto nonce = r.fixed<24>();
    const auto sealed = r.raw(r.left());
    const auto key = seal_key(purpose, shared, ephemeral, recipient);
    return aead_unlock(key, nonce, Writer("sg.chat.v1.seal.ad").raw(ephemeral).raw(recipient).data(), sealed);
}
Bytes seal(const std::string& purpose, const Key32& recipient, const Bytes& plain, const Key32& ephemeral_secret,
           const Nonce& nonce) {
    return seal_with(purpose, x25519(ephemeral_secret, recipient), x25519_public(ephemeral_secret), recipient, nonce, plain);
}
Bytes seal(const std::string& purpose, const Key32& recipient, const Bytes& plain) {
    auto secret = random_key();
    Nonce nonce{};
    const auto r = random_bytes(24);
    std::copy(r.begin(), r.end(), nonce.begin());
    auto out = seal(purpose, recipient, plain, secret, nonce);
    wipe(secret);
    return out;
}
Bytes open(const std::string& purpose, const Key32& secret, const Bytes& box) {
    return open_with(purpose, x25519(secret, box_ephemeral(box)), x25519_public(secret), box);
}

bool envelope_size(std::size_t size) {
    for (const auto b : buckets)
        if (size == 1 + 32 + seal_overhead + b) return true;
    return false;
}
Bytes encode(const Envelope& e) {
    if (!envelope_size(1 + 32 + e.box.size())) throw Refused("chat: an envelope's box is a sealed bucket");
    return Writer().u8(std::uint8_t(e.version)).raw(e.mailbox).raw(e.box).take();
}
Envelope decode_envelope(const Bytes& b) {
    if (!envelope_size(b.size())) throw Refused("chat: not an envelope's size");
    Reader r(b);
    Envelope e;
    const auto v = r.u8();
    if (v != 1 && v != 2 && v != 16) throw Refused("chat: unknown envelope version");
    e.version = Version(v);
    e.mailbox = r.key();
    e.box = r.raw(r.left());
    return e;
}

}  // namespace chat
