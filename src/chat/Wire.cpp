#include "chat/Wire.hpp"

namespace chat {

Writer::Writer(const std::string& domain) {
    if (domain.empty() || domain.size() > 255) throw Refused("chat: a domain is 1..255 bytes");
    u8(static_cast<std::uint8_t>(domain.size()));
    raw(reinterpret_cast<const std::uint8_t*>(domain.data()), domain.size());
}
Writer& Writer::u8(std::uint8_t v) { bytes_.push_back(v); return *this; }
Writer& Writer::u16(std::uint16_t v) { u8(std::uint8_t(v >> 8)); return u8(std::uint8_t(v)); }
Writer& Writer::u32(std::uint32_t v) { u16(std::uint16_t(v >> 16)); return u16(std::uint16_t(v)); }
Writer& Writer::u64(std::uint64_t v) { u32(std::uint32_t(v >> 32)); return u32(std::uint32_t(v)); }
Writer& Writer::raw(const std::uint8_t* p, std::size_t n) {
    bytes_.insert(bytes_.end(), p, p + n);
    return *this;
}
Writer& Writer::short_bytes(const Bytes& b) {
    if (b.size() > 65535) throw Refused("chat: a short field is at most 65535 bytes");
    u16(std::uint16_t(b.size()));
    return raw(b);
}
Writer& Writer::short_text(const std::string& s) { return short_bytes(Bytes(s.begin(), s.end())); }
Writer& Writer::long_bytes(const Bytes& b, std::size_t maximum) {
    if (b.size() > maximum || b.size() > 0xffffffffu) throw Refused("chat: a field is longer than its bound");
    u32(std::uint32_t(b.size()));
    return raw(b);
}

Reader::Reader(const Bytes& b, const std::string& domain) : bytes_(b) {
    const auto n = u8();
    const auto text = raw(n);
    if (std::string(text.begin(), text.end()) != domain) throw Refused("chat: wrong domain");
}
void Reader::need(std::size_t n) const {
    if (n > bytes_.size() - at_) throw Refused("chat: truncated input");
}
std::uint8_t Reader::u8() { need(1); return bytes_[at_++]; }
std::uint16_t Reader::u16() { const auto hi = u8(); return std::uint16_t((hi << 8) | u8()); }
std::uint32_t Reader::u32() { const std::uint32_t hi = u16(); return (hi << 16) | u16(); }
std::uint64_t Reader::u64() { const std::uint64_t hi = u32(); return (hi << 32) | u32(); }
Bytes Reader::raw(std::size_t n) {
    need(n);
    Bytes out(bytes_.begin() + std::ptrdiff_t(at_), bytes_.begin() + std::ptrdiff_t(at_ + n));
    at_ += n;
    return out;
}
Key32 Reader::key() { return fixed<32>(); }
Bytes Reader::short_bytes(std::size_t maximum) {
    const auto n = u16();
    if (n > maximum) throw Refused("chat: oversize field");
    return raw(n);
}
std::string Reader::short_text(std::size_t maximum) {
    const auto b = short_bytes(maximum);
    return std::string(b.begin(), b.end());
}
Bytes Reader::long_bytes(std::size_t maximum) {
    const auto n = u32();
    if (n > maximum) throw Refused("chat: oversize field");
    return raw(n);
}
void Reader::end() const {
    if (at_ != bytes_.size()) throw Refused("chat: trailing bytes");
}

std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out += digits[p[i] >> 4];
        out += digits[p[i] & 15];
    }
    return out;
}
Bytes unhex(const std::string& text) {
    if (text.size() % 2) throw Refused("chat: odd hex");
    const auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return unsigned(c - '0');
        if (c >= 'a' && c <= 'f') return unsigned(c - 'a' + 10);
        throw Refused("chat: noncanonical hex");
    };
    Bytes out(text.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = std::uint8_t((digit(text[2 * i]) << 4) | digit(text[2 * i + 1]));
    return out;
}
Key32 key_from(const Bytes& b) {
    if (b.size() != 32) throw Refused("chat: a key is 32 bytes");
    Key32 k{};
    for (std::size_t i = 0; i < 32; ++i) k[i] = b[i];
    return k;
}
Key32 key_from_hex(const std::string& text) { return key_from(unhex(text)); }

std::string base64url(const Bytes& b) {
    static const char* abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    std::size_t i = 0;
    for (; i + 3 <= b.size(); i += 3) {
        const std::uint32_t v = (std::uint32_t(b[i]) << 16) | (std::uint32_t(b[i + 1]) << 8) | b[i + 2];
        out += abc[v >> 18]; out += abc[(v >> 12) & 63]; out += abc[(v >> 6) & 63]; out += abc[v & 63];
    }
    if (b.size() - i == 1) {
        const std::uint32_t v = std::uint32_t(b[i]) << 16;
        out += abc[v >> 18]; out += abc[(v >> 12) & 63];
    } else if (b.size() - i == 2) {
        const std::uint32_t v = (std::uint32_t(b[i]) << 16) | (std::uint32_t(b[i + 1]) << 8);
        out += abc[v >> 18]; out += abc[(v >> 12) & 63]; out += abc[(v >> 6) & 63];
    }
    return out;
}
Bytes from_base64url(const std::string& text) {
    const auto value = [](char c) -> std::uint32_t {
        if (c >= 'A' && c <= 'Z') return std::uint32_t(c - 'A');
        if (c >= 'a' && c <= 'z') return std::uint32_t(c - 'a' + 26);
        if (c >= '0' && c <= '9') return std::uint32_t(c - '0' + 52);
        if (c == '-') return 62;
        if (c == '_') return 63;
        throw Refused("chat: not base64url");
    };
    if (text.size() % 4 == 1) throw Refused("chat: truncated base64url");
    Bytes out;
    std::size_t i = 0;
    for (; i + 4 <= text.size(); i += 4) {
        const auto v = (value(text[i]) << 18) | (value(text[i + 1]) << 12) | (value(text[i + 2]) << 6) | value(text[i + 3]);
        out.push_back(std::uint8_t(v >> 16)); out.push_back(std::uint8_t(v >> 8)); out.push_back(std::uint8_t(v));
    }
    const auto rest = text.size() - i;
    if (rest >= 2) {
        auto v = (value(text[i]) << 18) | (value(text[i + 1]) << 12);
        if (rest == 3) v |= value(text[i + 2]) << 6;
        out.push_back(std::uint8_t(v >> 16));
        if (rest == 3) out.push_back(std::uint8_t(v >> 8));
        // One spelling per byte string: the unused low bits are zero.
        if ((rest == 2 && (v & 0xffff)) || (rest == 3 && (v & 0xff))) throw Refused("chat: noncanonical base64url");
    }
    return out;
}

bool same(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    std::uint8_t d = 0;
    for (std::size_t i = 0; i < n; ++i) d |= std::uint8_t(a[i] ^ b[i]);
    return d == 0;
}

}  // namespace chat
