// Bytes on the wire: big endian, length-prefixed, bounded, and refused when
// short, long or trailing. Every hash, MAC, KDF and signature input starts
// with its domain string, so no two purposes ever share an input.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace chat {

using Bytes = std::vector<std::uint8_t>;
using Key32 = std::array<std::uint8_t, 32>;

// What a malformed, truncated or oversize input is refused with.
struct Refused : std::invalid_argument {
    using std::invalid_argument::invalid_argument;
};

class Writer {
public:
    Writer() = default;
    // A domain-separated input: the domain's length (one byte) and its text.
    explicit Writer(const std::string& domain);
    Writer& u8(std::uint8_t v);
    Writer& u16(std::uint16_t v);
    Writer& u32(std::uint32_t v);
    Writer& u64(std::uint64_t v);
    Writer& raw(const std::uint8_t* p, std::size_t n);
    Writer& raw(const Bytes& b) { return raw(b.data(), b.size()); }
    template <std::size_t N>
    Writer& raw(const std::array<std::uint8_t, N>& a) { return raw(a.data(), N); }
    // Lengths in two bytes (names, keys) or four (bodies), never more than said.
    Writer& short_bytes(const Bytes& b);
    Writer& short_text(const std::string& s);
    Writer& long_bytes(const Bytes& b, std::size_t maximum);
    const Bytes& data() const { return bytes_; }
    Bytes take() { return std::move(bytes_); }

private:
    Bytes bytes_;
};

class Reader {
public:
    explicit Reader(const Bytes& b) : bytes_(b) {}
    // Reads a domain prefix and refuses any other.
    Reader(const Bytes& b, const std::string& domain);
    std::uint8_t u8();
    std::uint16_t u16();
    std::uint32_t u32();
    std::uint64_t u64();
    Bytes raw(std::size_t n);
    Key32 key();
    template <std::size_t N>
    std::array<std::uint8_t, N> fixed() {
        need(N);
        std::array<std::uint8_t, N> a{};
        for (std::size_t i = 0; i < N; ++i) a[i] = bytes_[at_ + i];
        at_ += N;
        return a;
    }
    Bytes short_bytes(std::size_t maximum = 65535);
    std::string short_text(std::size_t maximum = 4096);
    Bytes long_bytes(std::size_t maximum);
    std::size_t left() const { return bytes_.size() - at_; }
    void end() const;

private:
    const Bytes& bytes_;
    std::size_t at_ = 0;
    void need(std::size_t n) const;
};

std::string hex(const std::uint8_t* p, std::size_t n);
inline std::string hex(const Bytes& b) { return hex(b.data(), b.size()); }
template <std::size_t N>
std::string hex(const std::array<std::uint8_t, N>& a) { return hex(a.data(), N); }
Bytes unhex(const std::string& text);
Key32 key_from_hex(const std::string& text);
Key32 key_from(const Bytes& b);

// base64url without padding: the invite's fragment.
std::string base64url(const Bytes& b);
Bytes from_base64url(const std::string& text);

// Both equal, in time that does not depend on where they differ.
bool same(const std::uint8_t* a, const std::uint8_t* b, std::size_t n);

}  // namespace chat
