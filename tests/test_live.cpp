// v1 §11: live state. Table tennis, two worlds and nothing between them but
// the network's boundary packets (1 to 6 frames late, as a link would be): the
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

namespace {
struct Played {
    std::int64_t epochs = 0;
    double real = 0;         // court frames agreed per frame played
    double placed = 0;       // the largest gap between a paddle agreed and the hand that put it
    bool same = true, behind = true, hit = false;
    std::uint64_t lead = 0;
};
// Two worlds, each with its host's side of the court; what each network says
// reaches the other `late` frames later. Each player moves its own way.
Played play(int late, World& a, World& b) {
    CourtSide sa(a.graph.state(a.game), 0), sb(b.graph.state(b.game), 1);
    std::map<std::int64_t, sg::net::PredictedValues> frames_a, frames_b;
    std::map<std::uint64_t, double> hand_a;
    Played out;
    double time = 0;
    const int frames = 1800;
    for (auto* s : {&a, &b}) s->out.clear();
    for (int f = 0; f < frames; ++f) {
        sa.steer((f / 45) % 2 ? 1 : -1);
        sb.steer((f / 70) % 3 == 0 ? -1 : 1);
        for (auto [s, side] : {std::pair{&a, &sa}, std::pair{&b, &sb}})
            if (const auto y = side->before(s->graph.state(s->game))) {
                s->engine->send(s->game, {s->game + ".publish", sg::Params{}.set("y", *y)});
            }
        hand_a.emplace(sa.picture().predicted_tick(), sa.hand());  // as the side keeps it: the frame it was played
        for (auto* s : {&a, &b}) s->engine->tick(court_step);
        time += court_step;
        for (auto [s, side] : {std::pair{&a, &sa}, std::pair{&b, &sb}}) side->after(s->graph.state(s->game), time);
        for (auto [from, to] : {std::pair{&a, &b}, std::pair{&b, &a}}) {
            for (auto& [wait, packet] : from->out) --wait;
            while (!from->out.empty() && from->out.front().first <= 0) {
                to->engine->send(to->net, {to->net + ".receive", sg::net::Exchange::arguments(from->out.front().second)});
                from->out.pop_front();
            }
        }
        const auto& ca = a.graph.state(a.game);
        const auto ea = ca.params().get_or<std::int64_t>("epoch", 0);
        const auto eb = b.graph.state(b.game).params().get_or<std::int64_t>("epoch", 0);
        const auto steps = std::uint64_t(ca.params().get_or<std::int64_t>("steps", 1));
        const auto tick = std::uint64_t(ea - 1) * steps;
        if (!frames_a.count(ea) && ea > 1 && hand_a.count(tick)) out.placed = std::max(out.placed, std::fabs(court_frame(ca)[4] - hand_a[tick]));
        frames_a[ea] = court_frame(ca);
        frames_b[eb] = court_frame(b.graph.state(b.game));
        out.behind &= tick <= sa.picture().predicted_tick();
        out.lead = std::max(out.lead, sa.picture().predicted_tick() - sa.picture().finalized_tick());
    }
    out.epochs = std::min(frames_a.rbegin()->first, frames_b.rbegin()->first);
    const auto steps = a.graph.state(a.game).params().get_or<std::int64_t>("steps", 1);
    out.real = double((out.epochs - 1) * steps) / frames;
    for (std::int64_t e = 1; e <= out.epochs && out.same; ++e)
        if (frames_a.count(e) && frames_b.count(e)) out.same &= frames_a[e] == frames_b[e];
    out.hit = frames_a[out.epochs][10] > 0 || frames_a[out.epochs][8] + frames_a[out.epochs][9] > 0;
    std::printf("table tennis, packets %d frames late: %lld steps, %.0f%% of real time; paddles agreed within %.4f of the hands; picture ahead by at most %llu\n",
                late, (long long)out.epochs, 100 * out.real, out.placed, (unsigned long long)out.lead);
    return out;
}
}  // namespace

int main() {
    sg::set_observers(sg::Observers::Strict);
    ConversationId conv{};
    conv[0] = 0x31;
    for (const int late : {1, 2, 4, 6}) {
    CallId id{};
    id[0] = std::uint8_t(0x40 + late);
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
        s->graph.state(s->net).bus().subscribe(s->net + ".boundary", [s, late](const sg::Event& e) {
            s->out.emplace_back(late, sg::net::Exchange::bytes(e.args));
        });
        const auto config = sg::Params{}.set("player", std::int64_t(player++));
        s->engine->send(s->game, {s->game + ".configure", config});
        s->engine->send(s->net, {s->net + ".configure", config});
        s->engine->tick(0);
    }
    const auto r = play(late, a, b);
    CHECK_MSG(r.same, "both worlds play the very same game, step for step");
    CHECK_MSG(r.behind, "the court never runs ahead of the screen");
    CHECK_MSG(r.placed <= 1.0 / 1024 + 1e-9, "each paddle is agreed where its player's hand put it");
    CHECK_MSG(r.lead <= court_lead, "the picture stays within its lead");
    CHECK_MSG(r.hit, "the ball was hit or a point was scored");
    // A round trip up to eight frames (a phone's link): the court keeps real time.
    if (late <= 4) CHECK_MSG(r.real >= 0.95, "the court keeps to real time over a link this long");
    CHECK_MSG(r.real <= 1.0, "and never faster");
    CHECK_MSG(sg::verify(a.graph).ok() && sg::verify(b.graph).ok(), "the laws still hold after the game");
    if (late != 6) continue;
    a.engine->send("contacts", {"game.end", game_args(conv, id)});
    a.engine->tick(0), a.engine->tick(0);
    CHECK_MSG(!a.graph.contains(a.game) && !a.graph.contains(a.net) && !a.graph.contains(game_time_state(id)), "a game ends by its edit");
    CHECK(a.graph.validate().empty());
    }

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
