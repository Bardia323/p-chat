// The whiteboard (protocol 8): the inside of world/board.sg's arrows. The
// board counts its strokes and says who leads; where each device looks is a
// participant of its view, and the engine's Reconcile brings every view to
// the one that leads. Nothing here keeps a clock or reaches another state.
#pragma once
#include "sg/dsl/Natives.hpp"

namespace chat {

// One board's natives, with a Reconcile of its own.
sg::dsl::Natives board_natives();
// A device's place in its board's view: "d" and its id.
std::string viewer_element(const std::string& peer);

}  // namespace chat
