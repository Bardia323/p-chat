// A box only one device can open, the padding that makes every box one of
// three sizes, and the envelope the relay sees: version, mailbox id, box.
//
// Seal: an ephemeral X25519 key meets the recipient's; the box key is
// BLAKE2b-256("sg.chat.v1.seal.<purpose>" | shared | ephemeral | recipient),
// the nonce random, and the box ephemeral (32) | nonce (24) | mac (16) | text.
// The split into "with a shared secret" and "with a secret key" is so the
// browser can do the X25519 in WebCrypto and only the shared secret comes here.
#pragma once
#include "chat/Wire.hpp"

namespace chat {

using Nonce = std::array<std::uint8_t, 24>;

constexpr std::size_t seal_overhead = 32 + 24 + 16;
// Plaintexts are padded to one of these before sealing; longer is refused.
constexpr std::size_t buckets[3] = {1024, 16384, 262144};
Bytes pad(const Bytes& frame);    // u32 length | frame | zeros, to the smallest bucket
Bytes unpad(const Bytes& padded); // refuses a size that is not a bucket, or nonzero padding

Key32 seal_key(const std::string& purpose, const Key32& shared, const Key32& ephemeral, const Key32& recipient);
Bytes seal_with(const std::string& purpose, const Key32& shared, const Key32& ephemeral, const Key32& recipient,
                const Nonce& nonce, const Bytes& plain);
Bytes open_with(const std::string& purpose, const Key32& shared, const Key32& recipient, const Bytes& box);
// The ephemeral public key a box starts with.
Key32 box_ephemeral(const Bytes& box);
// Natively, with the keys in hand (tests, tools, vectors).
Bytes seal(const std::string& purpose, const Key32& recipient, const Bytes& plain);
Bytes seal(const std::string& purpose, const Key32& recipient, const Bytes& plain, const Key32& ephemeral_secret,
           const Nonce& nonce);
Bytes open(const std::string& purpose, const Key32& secret, const Bytes& box);

// What the relay holds and routes. Versions: 1 a message sealed without a
// ratchet (refused once one exists), 2 a message or control frame under the
// ratchet, 16 a pairing reply. The box is always a padded bucket.
enum class Version : std::uint8_t { Sealed = 1, Ratchet = 2, PairReply = 16 };
struct Envelope {
    Version version = Version::Ratchet;
    Key32 mailbox{};
    Bytes box;
};
Bytes encode(const Envelope& e);
Envelope decode_envelope(const Bytes& b);
// True when `size` is what an envelope of a known layout can be.
bool envelope_size(std::size_t size);

}  // namespace chat
