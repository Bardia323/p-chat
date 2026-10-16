// Which of a sender's sequences have arrived: the highest, and a window of
// the 63 below it. Pure in its three numbers, so an arrow can keep it in
// params and the laws can re-run it.
//
// A sequence above the highest moves the window and leaves the ones it
// skipped missing; a missing one that arrives later fills its place; one
// seen before is a duplicate (no change); one below the window is too old,
// and a missing one that falls out of the window is counted lost. A missing
// sequence still missing after the mailbox's life is a message that will
// not come: the app says "message missing".
#pragma once
#include <cstdint>
#include <vector>

namespace chat {

constexpr std::uint64_t window_bits = 63;
constexpr std::uint64_t window_full = (std::uint64_t(1) << window_bits) - 1;

struct Window {
    std::uint64_t high = 0;          // the highest sequence arrived (0: none)
    std::uint64_t seen = window_full; // bit i: sequence high - 1 - i arrived
    std::uint64_t lost = 0;          // missing ones that left the window
};
enum class Arrival { New, Filled, Duplicate, TooOld };
Arrival arrive(Window& w, std::uint64_t sequence);
// The sequences in the window still missing, lowest first.
std::vector<std::uint64_t> missing(const Window& w);

}  // namespace chat
