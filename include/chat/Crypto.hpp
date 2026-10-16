// The primitives the protocol is made of, from the engine's pinned
// Monocypher 4.0.3: BLAKE2b (keyed, as hash, KDF and MAC), X25519,
// XChaCha20-Poly1305 and Argon2id. Ed25519 is the engine's (sg::net).
//
// In the browser the device's X25519 and Ed25519 private keys never come
// here: WebCrypto does the agreement (deriveBits) and the signing, and only
// what one message needs - a shared secret, a message key - reaches this code.
#pragma once
#include "chat/Wire.hpp"

namespace chat {

// BLAKE2b of `data`, `size` bytes long (1..64), keyed when `key` is not empty.
Bytes blake2b(std::size_t size, const Bytes& key, const Bytes& data);
Key32 blake2b256(const Bytes& key, const Bytes& data);
Key32 blake2b256(const Key32& key, const Bytes& data);

// X25519. An all-zero result (a small-order public key) is refused, as
// WebCrypto refuses it, so both sides fail alike.
Key32 x25519(const Key32& secret, const Key32& their_public);
Key32 x25519_public(const Key32& secret);

// XChaCha20-Poly1305. Sealed is mac (16) then cipher text.
Bytes aead_lock(const Key32& key, const std::array<std::uint8_t, 24>& nonce, const Bytes& ad, const Bytes& plain);
// Refuses (throws Refused) when the MAC does not hold.
Bytes aead_unlock(const Key32& key, const std::array<std::uint8_t, 24>& nonce, const Bytes& ad, const Bytes& sealed);

// The fixed Argon2id parameters the pairing code is stretched with
// (docs/protocol.md: about half a second on a mid phone, in the browser).
struct ArgonCost {
    std::uint32_t kib = 32768, passes = 2, lanes = 1;
};
ArgonCost argon_cost();
Key32 argon2id(const std::string& password, const Bytes& salt, const Bytes& ad, const ArgonCost& cost = argon_cost());

// Random bytes from the system (the browser's crypto.getRandomValues).
Bytes random_bytes(std::size_t n);
Key32 random_key();

void wipe(Bytes& b);
void wipe(Key32& k);

}  // namespace chat
