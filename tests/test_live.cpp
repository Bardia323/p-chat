// v1 §11: live state. Tape tennis, two worlds and nothing between them but
// the network's boundary packets (two frames late, as a link would be): the
// court is a state of each world, embedded in its conversation; the
// controls agree by the engine's Distributed reconciliation; both worlds
// play the very same game, step for step; the engine's Prediction shows it
// ahead of what is agreed, and gives way when it is.
#include "check.hpp"
#include "chat/Game.hpp"
#include "chat/Board.hpp"
#include "vectors.hpp"
#include "chat/World.hpp"
#include "sg/core/Engine.hpp"
#include "sg/core/Laws.hpp"
#include "sg/net/Exchange.hpp"

#include <cmath>
#include <deque>

using namespace chat;

namespace {
struct World {
    sg::StateGraph graph;
    std::unique_ptr<sg::Engine> engine;
    std::deque<std::pair<int, sg::net::Bytes>> out;  // (frames to wait, packet)
    std::string game, net;
};
}  // namespace

int main() {
    sg::set_observers(sg::Observers::Strict);
    ConversationId conv{};
    conv[0] = 0x31;
    CallId id{};
    id[0] = 0x47;
    World a, b;
    for (auto* s : {&a, &b}) {
        build_world(s->graph);
        s->engine = std::make_unique<sg::Engine>(s->graph);
        s->engine->set_strict(true);
        s->engine->start();
        s->engine->send("contacts", {"contact.add", contact_add_args(conv, "Tennis", Side::Owner, 0, {})});
        s->engine->tick(0), s->engine->tick(0);
        s->engine->send("contacts", {"game.start", game_args(conv, id)});
        s->engine->tick(0), s->engine->tick(0);
        s->game = game_state(id);
        s->net = game_net_state(id);
    }
    CHECK_MSG(a.graph.contains(a.game) && a.graph.contains(a.net) && a.graph.contains(game_time_state(id)), "the court, its network and its time are states");
    CHECK_MSG(a.graph.validate().empty() && sg::verify(a.graph).ok(), "the world with a game validates and its laws hold");
    bool embedded = false;
    for (const auto& e : a.graph.embeddings()) embedded |= e.guest.str() == a.game;
    CHECK_MSG(embedded, "the court is embedded in its conversation");
    int player = 0;
    for (auto* s : {&a, &b}) {
        s->graph.state(s->net).bus().subscribe(s->net + ".boundary", [s](const sg::Event& e) {
            s->out.emplace_back(2, sg::net::Exchange::bytes(e.args));
        });
        const auto config = sg::Params{}.set("player", std::int64_t(player++));
        s->engine->send(s->game, {s->game + ".configure", config});
        s->engine->send(s->net, {s->net + ".configure", config});
        s->engine->send(s->game, {s->game + ".publish", {}});
        s->engine->tick(0);
    }
    sg::net::Prediction prediction(court_forecast(a.graph.state(a.game)), 12, 128, {1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0});
    prediction.reset(0, court_frame(a.graph.state(a.game)));
    std::int64_t last = 0;
    std::uint64_t lead = 0;
    double time = 0;
    std::map<std::int64_t, sg::net::PredictedValues> frames_a, frames_b;
    for (int f = 0; f < 1800; ++f) {
        // Each plays: up for a while, then down, each its own way.
        const double ma = (f / 45) % 2 ? 1.0 : -1.0, mb = (f / 70) % 3 == 0 ? -1.0 : 1.0;
        a.engine->send(a.game, {a.game + ".input", sg::Params{}.set("move", ma)});
        b.engine->send(b.game, {b.game + ".input", sg::Params{}.set("move", mb)});
        for (auto* s : {&a, &b}) s->engine->tick(court_step);
        time += court_step;
        // The links: what each said reaches the other two frames later.
        for (auto [from, to] : {std::pair{&a, &b}, std::pair{&b, &a}}) {
            for (auto& [wait, packet] : from->out) --wait;
            while (!from->out.empty() && from->out.front().first <= 0) {
                to->engine->send(to->net, {to->net + ".receive", sg::net::Exchange::arguments(from->out.front().second)});
                from->out.pop_front();
            }
        }
        const auto ea = a.graph.state(a.game).params().get_or<std::int64_t>("epoch", 0);
        const auto eb = b.graph.state(b.game).params().get_or<std::int64_t>("epoch", 0);
        frames_a[ea] = court_frame(a.graph.state(a.game));
        frames_b[eb] = court_frame(b.graph.state(b.game));
        prediction.advance({std::int64_t(ma), 0});
        if (ea != last) {
            prediction.reconcile(std::uint64_t(ea) * 6, court_frame(a.graph.state(a.game)), time);
            last = ea;
        }
        lead = std::max(lead, prediction.predicted_tick() - prediction.finalized_tick());
    }
    const auto epochs = std::min(frames_a.rbegin()->first, frames_b.rbegin()->first);
    bool same = epochs > 100;
    for (std::int64_t e = 0; e <= epochs && same; ++e)
        if (frames_a.count(e) && frames_b.count(e)) same &= frames_a[e] == frames_b[e];
    std::printf("tape tennis: %lld steps agreed in 1800 frames (packets two frames late), %lld court frames - %.0f%% of real time; score %g-%g, %g hits; prediction ahead by at most %llu\n",
                (long long)epochs, (long long)epochs * 6, 100.0 * double(epochs) * 6 / 1800, frames_a[epochs][8], frames_a[epochs][9],
                frames_a[epochs][10], (unsigned long long)lead);
    CHECK_MSG(epochs * 6 >= 1800 * 6 / 10, "the court keeps at least 60% of real time over a link two frames long");
    CHECK_MSG(same, "both worlds play the very same game, step for step");
    CHECK_MSG(frames_a[epochs][10] > 0 || frames_a[epochs][8] + frames_a[epochs][9] > 0, "the ball was hit or a point was scored");
    CHECK_MSG(lead <= 12, "the prediction stays within its lead");
    CHECK_MSG(sg::verify(a.graph).ok() && sg::verify(b.graph).ok(), "the laws still hold after the game");
    a.engine->send("contacts", {"game.end", game_args(conv, id)});
    a.engine->tick(0), a.engine->tick(0);
    CHECK_MSG(!a.graph.contains(a.game) && !a.graph.contains(a.net) && !a.graph.contains(game_time_state(id)), "a game ends by its edit");
    CHECK(a.graph.validate().empty());

    // The whiteboard: three devices look at it, each its own way; one leads,
    // and the engine's Reconcile brings every view to where it looks.
    {
        sg::StateGraph g;
        build_world(g);
        sg::Engine e(g);
        e.set_strict(true);
        e.start();
        ConversationId room{};
        room[0] = 0x52;
        std::vector<Member> devices;
        for (std::uint8_t i = 0; i < 3; ++i) devices.push_back({{vectors::fill(std::uint8_t(0x10 + i)), vectors::fill(std::uint8_t(0x20 + i))}, Side::Owner, true});
        e.send("contacts", {"contact.add", contact_add_args(room, "Room", Side::Owner, 0, devices)});
        e.tick(0), e.tick(0);
        e.send("contacts", {"board.open", board_args(room, devices)});
        e.tick(0), e.tick(0);
        const auto board = board_state(room), view = view_state(room);
        CHECK_MSG(g.contains(board) && g.contains(view) && g.contains(board_time_state(room)), "the board, its view and its time are states");
        CHECK_MSG(g.validate().empty() && sg::verify(g).ok(), "the world with a board validates and its laws hold");
        std::vector<std::string> peers;
        for (const auto& m : devices) peers.push_back(hex(device_id(m.device)));
        const double looks[3][3] = {{0.1, 0.2, 1.0}, {-0.4, 0.3, 2.0}, {0.6, -0.5, 0.5}};
        for (int i = 0; i < 3; ++i)
            e.send(view, {view + ".observe", sg::Params{}.set("peer", peers[std::size_t(i)]).set("x", looks[i][0]).set("y", looks[i][1]).set("zoom", looks[i][2])});
        e.send(board, {board + ".lead", sg::Params{}.set("peer", peers[1])});
        for (int f = 0; f < 10; ++f) e.tick(court_step);
        bool follows = true;
        for (const auto& p : peers) {
            const auto& el = g.state(view).element(sg::Key(viewer_element(p))).params;
            for (int c = 0; c < 3; ++c) follows &= std::fabs(el.num(sg::Key("result_" + std::to_string(c))) - looks[1][c]) < 1e-6;
        }
        CHECK_MSG(follows, "every view is brought to the one that leads");
        CHECK(g.state(board).params().get_or<std::string>("leader", "") == peers[1]);
        e.send(board, {board + ".stroke", {}});
        e.send(board, {board + ".stroke", {}});
        e.tick(0);
        CHECK(g.state(board).params().get_or<std::int64_t>("strokes", 0) == 2);
        e.send(board, {board + ".lead", sg::Params{}.set("peer", "")});
        for (int f = 0; f < 4; ++f) e.tick(court_step);
        CHECK_MSG(g.state(view).params().get_or<std::string>("leader", "x").empty(), "no one leads: each looks its own way");
        CHECK(sg::verify(g).ok());
        e.send("contacts", {"board.close", board_args(room, devices)});
        e.tick(0), e.tick(0);
        CHECK_MSG(!g.contains(board) && !g.contains(view), "a board is put away by its edit");
    }
    return sgchat_test::finish("sgchat_live");
}
