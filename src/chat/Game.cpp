#include "chat/Game.hpp"
#include "sg/core/Declared.hpp"
#include "sg/net/Exchange.hpp"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace chat {

namespace {
using sg::Element;
using sg::Event;
using sg::Key;
using sg::Params;
using sg::State;

int command(double x) { return x > 0.5 ? 1 : x < -0.5 ? -1 : 0; }
// An event this state says: its own name, then what it is.
Key said(const State& s, const char* what) { return Key(s.id().str() + "." + what); }

void publish_world(State& s) {
    const auto player = static_cast<int>(s.params().num("player"));
    auto& p = s.element(Key{"p" + std::to_string(player)}).params;
    p.set("position_0", s.element("left").params.num("y")).set("position_1", s.element("right").params.num("y"));
    s.emit({said(s, "published"), Params{}.set("epoch", s.params().get("epoch"))});
}
void begin(State& s, std::int64_t epoch) {
    s.params().set("epoch", epoch).set("round", std::int64_t{0});
    for (auto& element : s.elements()) {
        if (element.kind != Key{"participant"} || !element.params.get_or<bool>("computes", false)) continue;
        for (int c = 0; c < 2; ++c) {
            const auto suffix = "_" + std::to_string(c);
            element.params.set(Key{"result" + suffix}, element.params.num(Key{"observation" + suffix}));
        }
    }
}
}  // namespace

void bounce(Params& l, Params& r, Params& b, Params& score) {
    for (auto* p : {&l, &r}) p->set("y", std::clamp(p->num("y"), -0.65, 0.65));
    double x = b.num("x"), y = b.num("y"), vx = b.num("vx"), vy = b.num("vy");
    if (y > 0.749) y = 1.498 - y, vy = -std::fabs(vy);
    if (y < -0.749) y = -1.498 - y, vy = std::fabs(vy);
    const bool left = vx < 0;
    const auto& p = left ? l : r;
    const double face = left ? -0.8565 : 0.8565;
    if ((left ? x <= face && x > -0.93 : x >= face && x < 0.93) && std::fabs(y - p.num("y")) <= 0.121) {
        x = face;
        vx = (left ? 1 : -1) * std::min(1.25, std::fabs(vx) * 1.025);
        vy = std::clamp(4.1 * (y - p.num("y")) + 0.18 * p.num("vy"), -0.65, 0.65);
        if (std::fabs(vy) < 0.1) vy = vy < 0 ? -0.1 : 0.1;
        score.set("hits", std::int64_t{score.get_or<std::int64_t>("hits", 0) + 1});
    }
    if (std::fabs(x) > 1.02) {
        const Key side = x > 0 ? Key{"left_score"} : Key{"right_score"};
        score.set(side, score.get_or<std::int64_t>(side, 0) + 1);
        x = 0, y = 0;
        vx = vx > 0 ? -0.68 : 0.68;
        const auto total = score.get_or<std::int64_t>("left_score", 0) + score.get_or<std::int64_t>("right_score", 0);
        vy = total % 2 == 0 ? 0.27 : -0.27;
    }
    b.set("x", x).set("y", y).set("vx", vx).set("vy", vy);
}

sg::net::PredictedValues court_frame(const State& game) {
    const auto& b = game.element("ball").params;
    const auto& l = game.element("left").params;
    const auto& r = game.element("right").params;
    return {b.num("x"), b.num("y"), b.num("vx"), b.num("vy"), l.num("y"), l.num("vy"), r.num("y"), r.num("vy"),
            game.params().num("left_score"), game.params().num("right_score"), game.params().num("hits")};
}

sg::net::Prediction::Step court_forecast(const State& game) {
    const auto declared = [&](Key name) {
        const auto* arrow = game.morphism(name);
        if (!arrow || !arrow->declared || arrow->declared->size() != 1) throw std::logic_error("the court's forecast needs its declared motion");
        return arrow->declared->front().does;
    };
    const auto ball = declared("move_ball"), left = declared("move_left"), right = declared("move_right");
    return [ball, left, right](const sg::net::PredictedValues& x, const sg::net::DiscreteInputs& input) {
        if (x.size() != 11 || input.size() != 2 || std::abs(input[0]) > 1 || std::abs(input[1]) > 1) throw std::invalid_argument("not a court");
        Element b{Key{"ball"}, Key{}}, l{Key{"left"}, Key{}}, r{Key{"right"}, Key{}};
        b.params.set("x", x[0]).set("y", x[1]).set("vx", x[2]).set("vy", x[3]);
        l.params.set("y", x[4]).set("vy", 0.95 * double(input[0]));
        r.params.set("y", x[6]).set("vy", 0.95 * double(input[1]));
        Params score;
        score.set("left_score", std::int64_t(x[8])).set("right_score", std::int64_t(x[9])).set("hits", std::int64_t(x[10]));
        const auto args = Params{}.set("duration", court_step);
        sg::run(left, l, l, &args);
        sg::run(right, r, r, &args);
        sg::run(ball, b, b, &args);
        bounce(l.params, r.params, b.params, score);
        return sg::net::PredictedValues{b.params.num("x"), b.params.num("y"), b.params.num("vx"), b.params.num("vy"),
                                        l.params.num("y"), l.params.num("vy"), r.params.num("y"), r.params.num("vy"),
                                        score.num("left_score"), score.num("right_score"), score.num("hits")};
    };
}

sg::dsl::Natives game_natives() {
    sg::dsl::Natives n;
    auto solver = std::make_shared<sg::net::Distributed>();
    // ---- the court ----
    n.arrow("game_configure", [](State& s, Element&, Element*, const Event& e) {
        if (!e.args.has("player")) return;
        const auto player = static_cast<int>(e.args.num("player"));
        if (player != 0 && player != 1) return;
        s.params().set("player", std::int64_t{player});
        s.element("p0").params.set("publishes", player == 0).set("coordinate", std::int64_t{0});
        s.element("p1").params.set("publishes", player == 1).set("coordinate", std::int64_t{1});
    });
    n.arrow("game_input", [](State& s, Element&, Element*, const Event& e) {
        if (!e.args.has("move")) return;
        const auto player = static_cast<int>(s.params().num("player"));
        auto& p = s.element(Key{"p" + std::to_string(player)}).params;
        const Key coordinate{"value_" + std::to_string(player)};
        const double move = command(e.args.num("move"));
        if (p.num(coordinate) != move) {
            p.set(coordinate, move);
            s.emit(said(s, "input.changed"));
        }
    });
    n.arrow("game_publish", [](State& s, Element&, Element*, const Event&) { publish_world(s); });
    n.transport("game_publish_to", [](const Element& from, Element& to) {
        if (!from.params.get_or<bool>("publishes", false)) return;
        for (int c = 0; c < 2; ++c) {
            const auto suffix = "_" + std::to_string(c);
            if (from.params.has(Key{"value" + suffix})) to.params.set(Key{"observation" + suffix}, from.params.get(Key{"value" + suffix}));
            if (from.params.has(Key{"position" + suffix})) to.params.set(Key{"position" + suffix}, from.params.get(Key{"position" + suffix}));
        }
    });
    n.transport("game_correct", [](const Element& from, Element& to) {
        if (!from.params.get_or<bool>("computes", false)) return;
        for (int c = 0; c < 2; ++c) {
            const auto suffix = "_" + std::to_string(c);
            if (from.params.has(Key{"result" + suffix})) to.params.set(Key{"command" + suffix}, from.params.get(Key{"result" + suffix}));
        }
    });
    n.arrow("game_corrected", [](State& s, Element& control, Element*, const Event& e) {
        if (!e.args.has("epoch")) return;
        const auto epoch = sg::net::Exchange::step(e.args).epoch;
        if (epoch == s.params().get_or<std::int64_t>("epoch", 0)) control.params.set("ready_epoch", epoch);
    });
    // The court's steps, once both controls of this epoch are agreed: always
    // `steps` of the same length of time on both devices.
    n.arrow("game_step", [](State& s, Element& control, Element*, const Event& e) {
        const auto epoch = s.params().get_or<std::int64_t>("epoch", 0);
        if (e.args.num("dt") <= 0 || control.params.num("ready_epoch", -1) != epoch || control.params.num("issued_epoch", -1) == epoch) return;
        control.params.set("issued_epoch", epoch);
        const auto steps = std::clamp<std::int64_t>(s.params().get_or<std::int64_t>("steps", 1), 1, 30);
        for (std::int64_t i = 0; i < steps; ++i) s.emit({said(s, "ready"), Params{}.set("duration", court_step)});
    });
    n.arrow("game_commands", [](State& s, Element&, Element*, const Event& e) {
        if (e.args.num("duration") <= 0) return;
        const auto player = static_cast<int>(s.params().num("player"));
        const auto& p = s.element(Key{"p" + std::to_string(player)}).params;
        s.element("left").params.set("vy", 0.95 * command(p.num("command_0")));
        s.element("right").params.set("vy", 0.95 * command(p.num("command_1")));
    });
    n.arrow("game_bounce", [](State& s, Element&, Element*, const Event& e) {
        if (e.args.num("duration") <= 0) return;
        bounce(s.element("left").params, s.element("right").params, s.element("ball").params, s.params());
        // The epoch's last step: the next epoch begins, and its controls are published.
        const auto step = s.params().get_or<std::int64_t>("step", 0) + 1;
        if (step < std::clamp<std::int64_t>(s.params().get_or<std::int64_t>("steps", 1), 1, 30)) {
            s.params().set("step", step);
            return;
        }
        s.params().set("step", std::int64_t{0}).set("epoch", s.params().get_or<std::int64_t>("epoch", 0) + 1);
        publish_world(s);
    });
    // ---- its network ----
    n.arrow("rally_configure", [](State& s, Element&, Element*, const Event& e) {
        if (!e.args.has("player")) return;
        const auto player = static_cast<int>(e.args.num("player"));
        if (player != 0 && player != 1) return;
        s.params().set("peer", "p" + std::to_string(player));
        for (int i = 0; i < 2; ++i) {
            auto& p = s.element(Key{"p" + std::to_string(i)}).params;
            p.set("computes", i == player);
            if (i != player) p.erase("observation_0"), p.erase("observation_1");
        }
        begin(s, 0);
    });
    n.arrow("rally_begin", [](State& s, Element&, Element*, const Event& e) {
        if (!e.args.has("epoch")) return;
        const auto epoch = sg::net::Exchange::step(e.args).epoch;
        if (epoch < sg::net::Exchange::step(s).epoch) return;
        begin(s, epoch);
    });
    n.arrow("rally_receive", [solver](State& s, Element&, Element*, const Event& e) {
        if (!e.args.has("packet")) return;
        for (const auto& change : solver->receive(s, sg::net::Exchange::decode(sg::net::Exchange::bytes(e.args))))
            s.element(change.element).params = change.params;
    });
    n.arrow("rally_solve", [solver](State& s, Element&, Element*, const Event& e) {
        const double dt = e.args.num("dt");
        if (dt <= 0) return;  // Temporal's zero interval is the identity
        const auto step = sg::net::Exchange::step(s);
        if (step.tick < s.params().num("settle_rounds", 2)) {
            const auto result = solver->evaluate(s);
            s.params() = result.params;
            for (const auto& change : result.boundaries) s.element(change.element).params = change.params;
            for (const auto& r : result.section.readings)
                s.element(r.element).params.set(sg::net::Cellular::coordinate_key("result", r.dimension, r.coordinate), r.value);
            if (result.advanced) s.params().set("residual", result.section.residual);
            for (const auto& packet : result.outgoing)
                s.emit({said(s, "boundary"), sg::net::Exchange::arguments(sg::net::Exchange::encode(packet))});
        }
        const auto now = sg::net::Exchange::step(s);
        const auto& boundary = s.element("shared").params;
        // Committed once the other has reached the same settled round: the
        // last packets are sent again until it has, so neither waits forever.
        if (now.tick >= s.params().num("settle_rounds", 2) && boundary.num("remote_epoch", -1) == now.epoch &&
            boundary.num("remote_tick", -1) == now.tick && boundary.get_or<bool>("remote_ready", false) &&
            s.params().num("committed_epoch", -1) != now.epoch) {
            s.params().set("committed_epoch", now.epoch);
            s.emit({said(s, "committed"), Params{}.set("epoch", now.epoch)});
        }
    });
    return n;
}

}  // namespace chat
