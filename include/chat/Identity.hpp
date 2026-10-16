// A device is its two public keys; its id is their hash. A pairing code is
// six words; a pairing's fingerprint is four emoji. None of these is a key.
#pragma once
#include "chat/Wire.hpp"
#include <utility>

namespace chat {

// What a device shows the world: Ed25519 (signs) and X25519 (agrees).
struct Device {
    Key32 sign{}, agree{};
    bool operator==(const Device& o) const { return sign == o.sign && agree == o.agree; }
};
// BLAKE2b-256("sg.chat.v1.device" | sign | agree).
Key32 device_id(const Device& d);
// The id in hex: how a device is named as a committee member and a peer.
std::string peer_of(const Device& d);

// The fixed list (BIP-39 English, data/words.txt) and the emoji list
// (data/emoji.txt: glyph and spoken name), as the program holds them.
const std::vector<std::string>& words();
const std::vector<std::pair<std::string, std::string>>& emoji();

// Six words from the first 66 bits of nine random bytes.
std::string make_code(const Bytes& random9);
// What was typed, as the six full words joined by single spaces: case and
// spacing do not matter, and each word may be cut to its first four
// letters (unique in the list). Anything else is refused.
std::string normalize_code(const std::string& typed);

// Four indexes into emoji(), the same on both devices of a pairing:
// BLAKE2b-256("sg.chat.v1.fingerprint" | lower id | higher id), first bytes.
std::array<int, 4> fingerprint(const Key32& a, const Key32& b);

}  // namespace chat
