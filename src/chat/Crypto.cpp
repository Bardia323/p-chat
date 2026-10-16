#include "chat/Crypto.hpp"
#include "sg/net/Integrity.hpp"
#include <monocypher.h>
#include <memory>

namespace chat {

Bytes blake2b(std::size_t size, const Bytes& key, const Bytes& data) {
    if (size == 0 || size > 64 || key.size() > 64) throw Refused("chat: BLAKE2b is 1..64 bytes with a key of at most 64");
    Bytes out(size);
    crypto_blake2b_keyed(out.data(), size, key.data(), key.size(), data.data(), data.size());
    return out;
}
Key32 blake2b256(const Bytes& key, const Bytes& data) { return key_from(blake2b(32, key, data)); }
Key32 blake2b256(const Key32& key, const Bytes& data) { return blake2b256(Bytes(key.begin(), key.end()), data); }

Key32 x25519(const Key32& secret, const Key32& their_public) {
    Key32 shared{};
    crypto_x25519(shared.data(), secret.data(), their_public.data());
    if (same(shared.data(), Key32{}.data(), 32)) throw Refused("chat: X25519 with a small-order key");
    return shared;
}
Key32 x25519_public(const Key32& secret) {
    Key32 pub{};
    crypto_x25519_public_key(pub.data(), secret.data());
    return pub;
}

Bytes aead_lock(const Key32& key, const std::array<std::uint8_t, 24>& nonce, const Bytes& ad, const Bytes& plain) {
    Bytes out(16 + plain.size());
    crypto_aead_lock(out.data() + 16, out.data(), key.data(), nonce.data(), ad.data(), ad.size(), plain.data(), plain.size());
    return out;
}
Bytes aead_unlock(const Key32& key, const std::array<std::uint8_t, 24>& nonce, const Bytes& ad, const Bytes& sealed) {
    if (sealed.size() < 16) throw Refused("chat: sealed text shorter than its MAC");
    Bytes out(sealed.size() - 16);
    if (crypto_aead_unlock(out.data(), sealed.data(), key.data(), nonce.data(), ad.data(), ad.size(), sealed.data() + 16, out.size()) != 0)
        throw Refused("chat: authentication failed");
    return out;
}

ArgonCost argon_cost() { return {}; }
Key32 argon2id(const std::string& password, const Bytes& salt, const Bytes& ad, const ArgonCost& cost) {
    if (salt.size() < 16 || cost.kib < 8 * cost.lanes || cost.passes < 1) throw Refused("chat: invalid Argon2id input");
    crypto_argon2_config config{CRYPTO_ARGON2_ID, cost.kib, cost.passes, cost.lanes};
    crypto_argon2_inputs inputs{reinterpret_cast<const std::uint8_t*>(password.data()), salt.data(),
                                static_cast<std::uint32_t>(password.size()), static_cast<std::uint32_t>(salt.size())};
    crypto_argon2_extras extras{nullptr, ad.data(), 0, static_cast<std::uint32_t>(ad.size())};
    std::unique_ptr<std::uint64_t[]> work(new std::uint64_t[std::size_t(cost.kib) * 128]);
    Key32 out{};
    crypto_argon2(out.data(), 32, work.get(), config, inputs, extras);
    crypto_wipe(work.get(), std::size_t(cost.kib) * 1024);
    return out;
}

Bytes random_bytes(std::size_t n) {
    Bytes out;
    while (out.size() < n) {
        auto seed = sg::net::random_seed();
        for (std::size_t i = 0; i < seed.size() && out.size() < n; ++i) out.push_back(seed[i]);
        sg::net::wipe(seed);
    }
    return out;
}
Key32 random_key() { return key_from(random_bytes(32)); }

void wipe(Bytes& b) { crypto_wipe(b.data(), b.size()); b.clear(); }
void wipe(Key32& k) { crypto_wipe(k.data(), k.size()); }

}  // namespace chat
