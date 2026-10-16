#include "chat/Window.hpp"

namespace chat {

namespace {
std::uint64_t zeros(std::uint64_t bits, std::uint64_t width) {
    std::uint64_t n = 0;
    for (std::uint64_t i = 0; i < width; ++i) n += ((bits >> i) & 1u) ? 0 : 1;
    return n;
}
}  // namespace

Arrival arrive(Window& w, std::uint64_t s) {
    if (s == 0) return Arrival::TooOld;
    if (s > w.high) {
        const auto d = s - w.high;
        if (d >= 64) {
            // Everything in the window leaves it; of the skipped sequences,
            // the newest 63 stay as missing and the rest are lost at once.
            w.lost += zeros(w.seen, window_bits) + (d - 1 - window_bits);
            w.seen = 0;
        } else {
            // Bits that leave: the top d of the old window.
            const auto leaving = w.seen >> (window_bits - d);
            w.lost += zeros(leaving, d);
            w.seen = (w.seen << d) & window_full;
            w.seen |= std::uint64_t(1) << (d - 1);  // the old highest arrived (or is sequence 0)
        }
        w.high = s;
        return Arrival::New;
    }
    if (s == w.high) return Arrival::Duplicate;
    const auto offset = w.high - 1 - s;
    if (offset >= window_bits) return Arrival::TooOld;
    const auto bit = std::uint64_t(1) << offset;
    if (w.seen & bit) return Arrival::Duplicate;
    w.seen |= bit;
    return Arrival::Filled;
}

std::vector<std::uint64_t> missing(const Window& w) {
    std::vector<std::uint64_t> out;
    for (std::uint64_t i = window_bits; i-- > 0;)
        if (!((w.seen >> i) & 1u) && w.high >= i + 2) out.push_back(w.high - 1 - i);
    return out;
}

}  // namespace chat
