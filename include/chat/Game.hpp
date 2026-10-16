// Tape tennis (protocol 8): the inside of world/game.sg's arrows, and the
// court's rules as a forecast. A game of two in a conversation, each device
// running the same court; the controls agreed by the engine's Distributed
// reconciliation, the court moved by its declared arrows, the picture
// smoothed by the engine's Prediction. Nothing here keeps a clock or
// reaches another state: an arrow is handed its own state.
#pragma once
#include "sg/dsl/Natives.hpp"
#include "sg/net/Distributed.hpp"
#include "sg/net/Prediction.hpp"

namespace chat {

// One game's natives, with a Distributed solver of its own.
sg::dsl::Natives game_natives();
// A step of the court: what both devices move it by, whatever their frames.
constexpr double court_step = 1.0 / 60.0;
// How far the picture may run ahead of what both have agreed, in court frames
// (0.4 s): past a phone link's round trip and a step of six, so a player's own
// paddle never waits for the other's answer to move.
constexpr std::size_t court_lead = 24;
// The court's rules: walls, paddles, points.
void bounce(sg::Params& left, sg::Params& right, sg::Params& ball, sg::Params& score);
// The court as numbers (ball x y vx vy, left y vy, right y vy, scores, hits),
// and its forecast: the same declared motion, run on a copy.
sg::net::PredictedValues court_frame(const sg::State& game);
sg::net::Prediction::Step court_forecast(const sg::State& game);

}  // namespace chat
