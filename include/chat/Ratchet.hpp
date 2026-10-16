// The Double Ratchet between two devices of a conversation: X25519 turns,
// BLAKE2b chains, a message key used once and forgotten.
//
// It is a pure state machine. Every X25519 it needs is handed to it (the
// browser does them in WebCrypto with non-extractable keys); it never holds
// a private key, only public ones, chain keys and the keys of messages
// skipped but not yet arrived - at most `max_skip` per turn and `max_kept`
// in all. A step works on a copy: the caller keeps the result only when the
// message it opened was authentic.
//
// Starting without a first message: the device with the lower id is
// "first". Both derive the seed from the conversation secret and the two
// devices' static X25519 keys; the first sends on the chain from its static
// key; the second turns at once with a fresh key, so either can speak first.
#pragma once
#include "chat/Wire.hpp"
#include <optional>

namespace chat {

struct Header {
    Key32 dh{};
    std::uint32_t pn = 0, n = 0;
    bool operator==(const Header& o) const { return dh == o.dh && pn == o.pn && n == o.n; }
};
Bytes encode(const Header& h);  // 40 bytes
Header decode_header(Reader& r);

struct Skipped {
    Key32 dh{};
    std::uint32_t n = 0;
    Key32 key{};
};
// Its keys are wiped when a ratchet goes: a chain key, once stepped past,
// and a message key, once used, are gone from memory as well as from use.
struct Ratchet {
    Ratchet() = default;
    Ratchet(const Ratchet&) = default;
    Ratchet& operator=(const Ratchet&) = default;
    ~Ratchet();
    Key32 root{}, send{}, receive{};
    bool sending = false, receiving = false;
    Key32 own{};     // our current ratchet public key (its private key is the caller's)
    Key32 theirs{};  // theirs
    std::uint32_t ns = 0, nr = 0, pn = 0;
    std::vector<Skipped> skipped;
};
constexpr std::uint32_t max_skip = 1000;
constexpr std::size_t max_kept = 2000;
Bytes encode(const Ratchet& r);
Ratchet decode_ratchet(const Bytes& b);

// BLAKE2b-256(key = conversation secret, "sg.chat.v2.ratchet.seed" |
// X25519(static, static) | lower id | higher id).
Key32 ratchet_seed(const Key32& conversation_secret, const Key32& static_shared, const Key32& id_a, const Key32& id_b);
bool first_of(const Key32& own_id, const Key32& their_id);
// The first device: sends from its static key.
Ratchet start_first(const Key32& seed, const Key32& own_static, const Key32& their_static, const Key32& static_shared);
// The second: receives on the static chain and turns with a fresh key
// (`fresh` public, `fresh_shared` = X25519(fresh, their static)).
Ratchet start_second(const Key32& seed, const Key32& own_static, const Key32& their_static, const Key32& static_shared,
                     const Key32& fresh, const Key32& fresh_shared);

struct Sent {
    Header header;
    Key32 key{};
};
// The next message key on the sending chain, and its header.
Sent ratchet_send(Ratchet& r);

// Whether a header needs a turn (two X25519s the caller makes) to be opened.
bool needs_turn(const Ratchet& r, const Header& h);
struct Turn {
    Key32 received{};  // X25519(our current ratchet private key, h.dh)
    Key32 fresh{};     // the new ratchet public key
    Key32 sent{};      // X25519(the new private key, h.dh)
};
// The message key for `h`, advancing a copy of the ratchet. Refuses a
// header that is too far ahead, already used, or needs a turn not given.
std::pair<Ratchet, Key32> ratchet_receive(const Ratchet& r, const Header& h, const std::optional<Turn>& turn);

// One message key opens one wrapped content key: the AEAD key and nonce are
// BLAKE2b-512(key = message key, "sg.chat.v2.ratchet.keys").
Bytes wrap(const Key32& message_key, const Bytes& ad, const Key32& content_key);
Key32 unwrap(const Key32& message_key, const Bytes& ad, const Bytes& wrapped);

}  // namespace chat
