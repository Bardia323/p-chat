// Table tennis (protocol 8; paddles by place, protocol 12): the inside of world/game.sg's arrows, and the
// court's rules as a forecast. A game of two in a conversation, each device
// running the same court; the controls agreed by the engine's Distributed
// reconciliation, the court moved by its declared arrows, the picture
// smoothed by the engine's Prediction. Nothing here keeps a clock or
// reaches another state: an arrow is handed its own state.
#pragma once
#include "sg/dsl/Natives.hpp"
#include "sg/net/Distributed.hpp"
#include "sg/net/Prediction.hpp"

#include <map>
#include <optional>

namespace chat {

// One game's natives, with a Distributed solver of its own.
sg::dsl::Natives game_natives();
// A step of the court: what both devices move it by, whatever their frames.
constexpr double court_step = 1.0 / 60.0;
// How far the picture may run ahead of what both have agreed, in court frames
// (1 s): a step of ten and its agreement over a slow phone link, twice. A
// player's own paddle never waits on it: it is drawn where the hand is.
constexpr std::size_t court_lead = 60;
// A paddle's speed under a held key, and how far from the middle it goes.
constexpr double court_speed = 0.95;
constexpr double court_reach = 0.65;
// The court's rules: walls, paddles, points.
void bounce(sg::Params& left, sg::Params& right, sg::Params& ball, sg::Params& score);
// The court as numbers (ball x y vx vy, left y vy, right y vy, scores, hits),
// and its forecast: the same declared motion, run on a copy.
sg::net::PredictedValues court_frame(const sg::State& game);
sg::net::Prediction::Step court_forecast(const sg::State& game);

// One player's side of a court, kept by its host: the hand (where its keys
// have put the paddle, frame by frame), the picture ahead of what is agreed,
// and when the next step may be published. Nothing of it is the world: the
// court's state moves only by the published places and its arrows.
class CourtSide {
public:
    CourtSide(const sg::State& game, int player);
    void steer(int move) { move_ = move > 0 ? 1 : move < 0 ? -1 : 0; }
    // Before the world's frame: the hand moved a frame, the picture with it;
    // where this paddle is at the end of the court's next step, once this side
    // has played past it (to be said, then the step published).
    std::optional<double> before(const sg::State& game);
    // After the world's frame: the picture corrected to what was agreed.
    void after(const sg::State& game, double time);
    double hand() const { return hand_; }
    const sg::net::Prediction& picture() const { return prediction_; }

private:
    int player_, move_ = 0;
    double hand_ = 0, theirs_ = 0;
    std::int64_t last_epoch_ = 1;
    sg::net::Prediction prediction_;
    std::map<std::uint64_t, double> hands_;  // by court frame
};

}  // namespace chat
