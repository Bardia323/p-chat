// Phase 3: the world. The book and its conversations validate strictly and
// keep their laws with nothing unchecked; a conversation is made, posts,
// counts what comes in by each sender's window (new, duplicate, filled,
// too old, lost), clears what was read, gains and loses devices only at the
// next generation, opens and closes from the book, and goes.
#include "check.hpp"
#include "chat/Window.hpp"
#include "chat/World.hpp"
#include "sg/core/Engine.hpp"
#include "sg/core/Laws.hpp"
#include "vectors.hpp"

using namespace chat;

namespace {
void laws_hold(sg::StateGraph& g, const std::string& when) {
    const auto problems = g.validate();
    CHECK_MSG(problems.empty(), when + ": validate: " + (problems.empty() ? "" : problems.front()));
    const auto report = sg::verify(g);
    CHECK_MSG(report.ok(), when + ": laws: " + report.str());
    CHECK_MSG(report.all_checked(), when + ": unchecked equations: " + report.str());
}
std::int64_t integer(const sg::State& s, const char* element, const char* key) {
    return s.element(element).params.get_or<std::int64_t>(key, -1);
}
}  // namespace

int main() {
    // The window alone, pure.
    {
        Window w;
        CHECK(arrive(w, 1) == Arrival::New && missing(w).empty());
        CHECK(arrive(w, 1) == Arrival::Duplicate);
        CHECK(arrive(w, 4) == Arrival::New && missing(w) == (std::vector<std::uint64_t>{2, 3}));
        CHECK(arrive(w, 3) == Arrival::Filled && missing(w) == (std::vector<std::uint64_t>{2}));
        CHECK(arrive(w, 3) == Arrival::Duplicate);
        CHECK(arrive(w, 0) == Arrival::TooOld);
        // At 67 the window is 4..66: 2 (still missing) has fallen out, lost;
        // 5..66 are missing.
        CHECK(arrive(w, 4 + 63) == Arrival::New && w.lost == 1 && missing(w).size() == 62);
        CHECK(arrive(w, 4 + 64) == Arrival::New && w.lost == 1 && missing(w).size() == 62);
        CHECK(arrive(w, 2) == Arrival::TooOld);
        Window far;
        arrive(far, 1);
        CHECK(arrive(far, 200) == Arrival::New && far.lost == 200 - 1 - 1 - 63 && missing(far).size() == 63);
    }

    sg::set_observers(sg::Observers::Strict);
    sg::StateGraph g;
    build_world(g);
    laws_hold(g, "the book alone");

    sg::Engine engine(g);
    engine.set_strict(true);
    engine.start();
    std::vector<sg::Params> replies;
    for (const char* e : {"contact.add.edit.done", "contact.remove.edit.done", "device.add.edit.done", "device.revoke.edit.done"})
        g.state("contacts").bus().subscribe(e, [&](const sg::Event& ev) { replies.push_back(ev.args); });
    const auto settle = [&] { for (int i = 0; i < 3; ++i) engine.tick(0); };

    const auto A = vectors::owner(), F = vectors::friend1(), G = vectors::friend2();
    ConversationId c{};
    c[0] = 0xc0;
    const auto state = conversation_state(c);
    engine.send("contacts", {"contact.add", contact_add_args(c, "Ana \"the\" friend", Side::Owner, 0, {{F.device, Side::Friend}})});
    settle();
    CHECK(g.contains(state));
    CHECK(!replies.empty() && replies.back().get_or<bool>("ok", false));
    CHECK(*g.state(state).params().text("name") == "Ana \"the\" friend");
    laws_hold(g, "with a conversation");

    // Twice is refused, and the graph is as it was.
    const auto revision = g.revision();
    engine.send("contacts", {"contact.add", contact_add_args(c, "again", Side::Owner, 0, {})});
    settle();
    CHECK(!replies.back().get_or<bool>("ok", true) && g.revision() == revision);

    // Posting: the thread's sequence moves on, and the conversation says it.
    std::vector<sg::Params> outgoing;
    g.state(state).bus().subscribe(state + ".outgoing", [&](const sg::Event& e) { outgoing.push_back(e.args); });
    engine.send(state, {state + ".post", post_args("text", "t1")});
    engine.send(state, {state + ".post", post_args("ack", "t2")});
    settle();
    CHECK(outgoing.size() == 2 && outgoing[0].num("sequence") == 1 && outgoing[1].num("sequence") == 2);
    CHECK(outgoing.size() == 2 && *outgoing[1].text("kind") == "ack" && *outgoing[1].text("token") == "t2");
    CHECK(integer(g.state(state), "thread", "sent") == 2);

    // Receiving: by the sender's window. Duplicates change nothing; only new
    // text counts as unread; a gap is seen; a late one fills it.
    const auto fid = device_id(F.device);
    const auto dev = device_element(fid);
    const auto receive = [&](std::uint64_t s, const char* kind) {
        engine.send(state, {state + ".receive", receive_args(fid, s, kind)});
        settle();
    };
    receive(1, "text");
    CHECK(integer(g.state(state), "thread", "unread") == 1);
    receive(1, "text");
    CHECK(integer(g.state(state), "thread", "unread") == 1);
    receive(2, "ack");
    CHECK(integer(g.state(state), "thread", "unread") == 1 && integer(g.state(state), dev.c_str(), "high") == 2);
    receive(5, "text");
    {
        Window w{std::uint64_t(integer(g.state(state), dev.c_str(), "high")),
                 std::uint64_t(integer(g.state(state), dev.c_str(), "seen")),
                 std::uint64_t(integer(g.state(state), dev.c_str(), "lost"))};
        CHECK(missing(w) == (std::vector<std::uint64_t>{3, 4}));
    }
    receive(4, "text");
    CHECK(integer(g.state(state), "thread", "unread") == 3);
    receive(4, "text");
    CHECK(integer(g.state(state), "thread", "unread") == 3);
    // An unknown device changes nothing.
    engine.send(state, {state + ".receive", receive_args(device_id(G.device), 1, "text")});
    settle();
    CHECK(integer(g.state(state), "thread", "unread") == 3);
    engine.send(state, {state + ".rename", rename_args("Ana")});
    settle();
    CHECK(*g.state(state).params().text("name") == "Ana");
    engine.send(state, {state + ".read", {}});
    settle();
    CHECK(integer(g.state(state), "thread", "unread") == 0);
    laws_hold(g, "after traffic");

    // Opening from the book and closing back.
    sg::Params open;
    open.set("conversation", hex(c));
    engine.fire({"contacts.open", open});
    settle();
    CHECK(engine.current() && engine.current()->id() == sg::Key(state));
    engine.fire(state + ".close");
    settle();
    CHECK(engine.current() && engine.current()->id() == sg::Key("contacts"));

    // Devices: only at the next generation, one at a time; revoke removes it.
    engine.send("contacts", {"device.add", device_args(c, {G.device, Side::Friend}, 5)});
    settle();
    CHECK(!replies.back().get_or<bool>("ok", true) && !g.state(state).find(device_element(device_id(G.device))));
    engine.send("contacts", {"device.add", device_args(c, {G.device, Side::Friend}, 1)});
    settle();
    CHECK(replies.back().get_or<bool>("ok", false) && g.state(state).find(device_element(device_id(G.device))));
    CHECK(g.state(state).params().get_or<std::int64_t>("generation", -1) == 1);
    laws_hold(g, "after a device joined");
    engine.send("contacts", {"device.revoke", device_args(c, {G.device, Side::Friend}, 1)});
    settle();
    CHECK(!replies.back().get_or<bool>("ok", true) && g.state(state).find(device_element(device_id(G.device))));
    engine.send("contacts", {"device.revoke", device_args(c, {G.device, Side::Friend}, 2)});
    settle();
    CHECK(replies.back().get_or<bool>("ok", false) && !g.state(state).find(device_element(device_id(G.device))));
    CHECK(g.state(state).find(device_element(fid)));
    laws_hold(g, "after a device was revoked");

    // A second conversation beside the first; then the first goes.
    ConversationId c2 = c;
    c2[0] = 0xc2;
    engine.send("contacts", {"contact.add", contact_add_args(c2, "Ben", Side::Friend, 0, {{A.device, Side::Owner}})});
    settle();
    CHECK(g.contains(conversation_state(c2)));
    laws_hold(g, "with two conversations");
    engine.send("contacts", {"contact.remove", contact_remove_args(c)});
    settle();
    CHECK(!g.contains(state) && g.contains(conversation_state(c2)));
    laws_hold(g, "after a conversation went");
    CHECK(engine.problems().empty());
    return sgchat_test::finish("sgchat_world");
}
