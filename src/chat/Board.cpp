#include "chat/Board.hpp"
#include "sg/net/Reconcile.hpp"

namespace chat {

namespace {
using sg::Element;
using sg::Event;
using sg::Key;
using sg::Params;
using sg::State;
}  // namespace

std::string viewer_element(const std::string& peer) { return "d" + peer; }

sg::dsl::Natives board_natives() {
    sg::dsl::Natives n;
    auto reconcile = std::make_shared<sg::net::Reconcile>();
    n.arrow("board_stroke", [](State& s, Element&, Element*, const Event&) {
        s.params().set("strokes", s.params().get_or<std::int64_t>("strokes", 0) + 1);
    });
    n.arrow("board_lead", [](State& s, Element&, Element*, const Event& e) {
        const auto* peer = e.args.text("peer");
        const std::string who = peer ? *peer : std::string();
        s.params().set("leader", who);
        s.emit({Key(s.id().str() + ".led"), Params{}.set("peer", who)});
    });
    // Where a device looks, said at the view's port as it moves.
    n.arrow("view_observe", [](State& s, Element&, Element*, const Event& e) {
        const auto* peer = e.args.text("peer");
        if (!peer) return;
        auto* v = s.find(Key(viewer_element(*peer)));
        if (!v) return;
        v->params.set("observation_0", e.args.num("x")).set("observation_1", e.args.num("y")).set("observation_2", e.args.num("zoom", 1.0));
    });
    // One that leads is pinned where it looks; the others are free, and the
    // constraints bring them to it. None leading: each is its own.
    n.arrow("view_lead", [](State& s, Element&, Element*, const Event& e) {
        const auto* peer = e.args.text("peer");
        const std::string leader = peer && !peer->empty() ? viewer_element(*peer) : std::string();
        for (auto& el : s.elements()) {
            if (el.kind != Key{"participant"}) continue;
            const bool leads = el.id.str() == leader;
            for (int c = 0; c < 3; ++c) el.params.set(Key("pinned_" + std::to_string(c)), leads);
            el.params.set("weight", leader.empty() || leads ? 1.0 : 0.0);
        }
        s.params().set("leader", leader);
    });
    n.arrow("view_solve", [reconcile](State& s, Element&, Element*, const Event& e) {
        if (e.args.num("dt") <= 0) return;  // Temporal's zero interval is the identity
        const auto result = reconcile->evaluate(s);
        for (const auto& r : result.readings)
            s.element(r.element).params.set(sg::net::Cellular::coordinate_key("result", r.dimension, r.coordinate), r.value);
        s.params().set("residual", result.residual);
        s.emit({Key(s.id().str() + ".agreed"), Params{}});
    });
    return n;
}

}  // namespace chat
