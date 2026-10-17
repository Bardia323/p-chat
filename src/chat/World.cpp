#include "chat/World.hpp"
#include "chat/Window.hpp"
#include "chat/Game.hpp"
#include "chat/Board.hpp"
#include "sg/dsl/Apply.hpp"
#include "sg/dsl/Compile.hpp"
#include "sg/dsl/Runtime.hpp"

namespace sgen {
void build_chat(sg::StateGraph&, const sg::dsl::Natives&, sg::dsl::Bindings&);
}

namespace chat {

const char* conversation_template();
const char* device_template();
const char* call_template();
const char* game_template();
const char* board_template();

namespace {
using sg::Element;
using sg::Event;
using sg::Params;
using sg::State;
using sg::StateGraph;

std::string replaced(std::string text, const std::vector<std::pair<std::string, std::string>>& with) {
    for (const auto& [from, to] : with)
        for (std::size_t at = text.find(from); at != std::string::npos; at = text.find(from, at + to.size()))
            text.replace(at, from.size(), to);
    return text;
}
std::string arg_text(const Event& e, const char* key) {
    const auto* t = e.args.text(key);
    if (!t) throw Refused(std::string("chat: an edit needs ") + key);
    return *t;
}
std::int64_t arg_int(const Event& e, const char* key) {
    if (!e.args.has(key)) throw Refused(std::string("chat: an edit needs ") + key);
    return static_cast<std::int64_t>(e.args.num(key));
}
CallId call_arg(const Event& e) {
    const auto b = unhex(arg_text(e, "call"));
    if (b.size() != 16) throw Refused("chat: a call id is 16 bytes");
    CallId c{};
    std::copy(b.begin(), b.end(), c.begin());
    return c;
}
ConversationId conversation_arg(const Event& e) {
    const auto b = unhex(arg_text(e, "conversation"));
    if (b.size() != 16) throw Refused("chat: a conversation id is 16 bytes");
    ConversationId c{};
    std::copy(b.begin(), b.end(), c.begin());
    return c;
}
// Applies a source to the graph, all or nothing; states it names that are
// there already are only referred to.
void apply_source(StateGraph& g, const std::string& text, const sg::dsl::Natives& n) {
    auto compiled = sg::dsl::compile_source(text, "<sgchat edit>");
    if (!compiled.ok()) throw Refused("chat: " + compiled.report());
    for (auto& step : compiled.plan.steps)
        if (const auto* s = std::get_if<sg::dsl::plan::State>(&step); s && g.contains(s->id))
            step = sg::dsl::plan::Extern{s->id, s->kind};
    const auto applied = sg::dsl::apply(compiled.plan, g, n);
    if (!applied.ok) throw Refused("chat: " + applied.why);
}
void add_device(StateGraph& g, const std::string& state, const Member& m, const sg::dsl::Natives& n) {
    const auto id = device_id(m.device);
    if (g.state(state).find(device_element(id))) throw Refused("chat: that device is pinned already");
    apply_source(g,
                 replaced(device_template(), {{"CONV", state},
                                              {"DEV", device_element(id)},
                                              {"\"ID\"", "\"" + hex(id) + "\""},
                                              {"SIGN", hex(m.device.sign)},
                                              {"AGREE", hex(m.device.agree)},
                                              {"SIDE", std::to_string(int(m.side))},
                                              {"MAILBOX", m.mail ? "1" : "0"}}),
                 n);
}
Params done(bool ok, const std::string& why = {}) {
    Params p;
    p.set("ok", ok);
    if (!why.empty()) p.set("why", why);
    return p;
}

Window window_of(const Element& d) {
    Window w;
    w.high = std::uint64_t(d.params.get_or<std::int64_t>("high", 0));
    w.seen = std::uint64_t(d.params.get_or<std::int64_t>("seen", std::int64_t(window_full)));
    w.lost = std::uint64_t(d.params.get_or<std::int64_t>("lost", 0));
    return w;
}
}  // namespace

std::string conversation_state(const ConversationId& c) { return "c_" + hex(c); }
std::string call_state(const CallId& c) { return "k_" + hex(Bytes(c.begin(), c.end())); }
std::string game_state(const CallId& g) { return "g_" + hex(Bytes(g.begin(), g.end())); }
std::string game_net_state(const CallId& g) { return "n_" + hex(Bytes(g.begin(), g.end())); }
std::string game_time_state(const CallId& g) { return "t_" + hex(Bytes(g.begin(), g.end())); }
std::string board_state(const ConversationId& c) { return "b_" + hex(c); }
std::string view_state(const ConversationId& c) { return "v_" + hex(c); }
std::string board_time_state(const ConversationId& c) { return "u_" + hex(c); }
std::string device_element(const Key32& id) { return "d" + hex(id); }

std::string devices_arg(const std::vector<Member>& ms) {
    std::string out;
    for (const auto& m : ms) {
        if (!out.empty()) out += ';';
        out += hex(m.device.sign) + ":" + hex(m.device.agree) + ":" + std::to_string(int(member_flags(m)));
    }
    return out;
}
std::vector<Member> devices_from(const std::string& arg) {
    std::vector<Member> out;
    std::size_t at = 0;
    while (at < arg.size()) {
        const auto end = std::min(arg.find(';', at), arg.size());
        const auto part = arg.substr(at, end - at);
        if (part.size() != 64 + 1 + 64 + 2 || part[64] != ':' || part[129] != ':' || part[130] < '0' || part[130] > '3')
            throw Refused("chat: a device is sign:agree:flags");
        Device d;
        d.sign = key_from_hex(part.substr(0, 64));
        d.agree = key_from_hex(part.substr(65, 64));
        out.push_back(member_of(d, std::uint8_t(part[130] - '0')));
        at = end + 1;
    }
    return out;
}

sg::Params contact_add_args(const ConversationId& c, const std::string& name, Side side, std::uint64_t generation,
                            const std::vector<Member>& pinned, const std::string& introduced, int kind) {
    Params p;
    p.set("kind", std::int64_t(kind));
    p.set("conversation", hex(c)).set("name", name).set("side", std::int64_t(side));
    p.set("generation", std::int64_t(generation)).set("devices", devices_arg(pinned));
    if (!introduced.empty()) p.set("introduced", introduced);
    return p;
}
sg::Params rename_args(const std::string& name) {
    Params p;
    p.set("name", name);
    return p;
}
sg::Params contact_remove_args(const ConversationId& c) {
    Params p;
    p.set("conversation", hex(c));
    return p;
}
sg::Params device_args(const ConversationId& c, const Member& m, std::uint64_t generation) {
    return devices_args(c, {m}, generation);
}
sg::Params devices_args(const ConversationId& c, const std::vector<Member>& ms, std::uint64_t generation) {
    Params p;
    p.set("conversation", hex(c)).set("devices", devices_arg(ms)).set("generation", std::int64_t(generation));
    return p;
}
sg::Params post_args(const std::string& kind, const std::string& token) {
    Params p;
    p.set("kind", kind).set("token", token);
    return p;
}
sg::Params receive_args(const Key32& device, std::uint64_t sequence, const std::string& kind, int mode) {
    Params p;
    p.set("device", hex(device)).set("sequence", std::int64_t(sequence)).set("kind", kind);
    if (mode) p.set("mode", std::int64_t(mode));
    return p;
}
sg::Params options_args(bool recovery, std::uint32_t disappear_s) {
    Params p;
    p.set("recovery", std::int64_t(recovery ? 1 : 0)).set("disappear", std::int64_t(disappear_s));
    return p;
}
sg::Params replace_args(const ConversationId& c, const Key32& lost, const Member& m, std::uint64_t generation) {
    Params p;
    p.set("conversation", hex(c)).set("lost", hex(lost)).set("devices", devices_arg({m})).set("generation", std::int64_t(generation));
    return p;
}
namespace {
Params call_base(const ConversationId& c, const CallId& call) {
    Params p;
    p.set("conversation", hex(c)).set("call", hex(Bytes(call.begin(), call.end())));
    return p;
}
}  // namespace
sg::Params call_start_args(const ConversationId& c, const CallId& call, int mode, int stripes) {
    return call_base(c, call).set("mode", std::int64_t(mode)).set("stripes", std::int64_t(stripes));
}
sg::Params call_end_args(const ConversationId& c, const CallId& call) { return call_base(c, call); }
sg::Params game_args(const ConversationId& c, const CallId& game) { return call_base(c, game); }
sg::Params board_args(const ConversationId& c, const std::vector<Member>& devices) {
    Params p;
    p.set("conversation", hex(c)).set("devices", devices_arg(devices));
    return p;
}
sg::Params call_roster_args(const ConversationId& c, const CallId& call, std::uint64_t generation, std::size_t viewers) {
    return call_base(c, call).set("generation", std::int64_t(generation)).set("viewers", std::int64_t(viewers));
}
sg::Params call_place_args(const ConversationId& c, const CallId& call, std::uint64_t generation, std::uint64_t epoch,
                           const std::vector<std::string>& forwarders) {
    std::string joined;
    for (const auto& f : forwarders) joined += (joined.empty() && &f == &forwarders.front() ? "" : ";") + f;
    return call_base(c, call).set("generation", std::int64_t(generation)).set("epoch", std::int64_t(epoch)).set("forwarders", joined);
}
sg::Params delivery_args(int mode) {
    Params p;
    p.set("mode", std::int64_t(mode));
    return p;
}

sg::dsl::Natives natives() {
    sg::dsl::Natives n;
    // The book asks for an edit of the graph with what it was sent.
    n.arrow("chat_ask", [](State& s, Element&, Element*, const Event& e) {
        if (e.args.text("conversation")) s.emit({sg::Key(e.name.str() + ".edit"), e.args});
    });
    // A message to send: the thread's own sequence moves on by one, and the
    // conversation says what goes out (the token lets the app match it to
    // the content it keeps, which is not the world's).
    n.arrow("chat_post", [](State& s, Element& thread, Element*, const Event& e) {
        const auto* kind = e.args.text("kind");
        if (!kind || kind->empty()) return;
        const auto sent = thread.params.get_or<std::int64_t>("sent", 0) + 1;
        thread.params.set("sent", sent);
        Params out;
        out.set("sequence", sent).set("kind", *kind);
        if (const auto* token = e.args.text("token")) out.set("token", *token);
        s.emit({sg::Key(s.id().str() + ".outgoing"), out});
    });
    // A message that came in, already accepted by Integrity outside the
    // world: its sender's window takes it; a new text is one more unread.
    n.arrow("chat_receive", [](State& s, Element& thread, Element*, const Event& e) {
        const auto* device = e.args.text("device");
        if (!device || !e.args.has("sequence")) return;
        auto* d = s.find(sg::Key("d" + *device));
        if (!d) return;
        auto w = window_of(*d);
        const auto arrival = arrive(w, std::uint64_t(e.args.num("sequence")));
        d->params.set("high", std::int64_t(w.high)).set("seen", std::int64_t(w.seen)).set("lost", std::int64_t(w.lost));
        // A device's signed delivery message says whether it takes mail; only
        // its newest such message counts (a delivery that is not new is old news).
        if (arrival == Arrival::New && e.args.is("kind", "delivery") && e.args.has("mode"))
            d->params.set("mailbox", std::int64_t(e.args.num("mode") == 2 ? 1 : 0));
        if ((arrival == Arrival::New || arrival == Arrival::Filled) && e.args.is("kind", "text"))
            thread.params.set("unread", thread.params.get_or<std::int64_t>("unread", 0) + 1);
    });
    // What this device calls the other side is its own to change.
    n.arrow("chat_rename", [](State& s, Element&, Element*, const Event& e) {
        const auto* name = e.args.text("name");
        if (name && !name->empty() && name->size() <= 64) s.params().set("name", *name);
    });
    // This device's own choice of how it takes messages.
    n.arrow("chat_delivery", [](State& s, Element&, Element*, const Event& e) {
        if (e.args.has("mode")) s.params().set("mailbox", std::int64_t(e.args.num("mode") == 2 ? 1 : 0));
    });
    // A chat's options, as a member said them (Recovery.hpp).
    n.arrow("chat_options", [](State& s, Element&, Element*, const Event& e) {
        if (e.args.has("recovery")) s.params().set("recovery", std::int64_t(e.args.num("recovery") != 0 ? 1 : 0));
        if (e.args.has("disappear")) s.params().set("disappear", std::int64_t(std::max(0.0, e.args.num("disappear"))));
    });
    // A chat this device left but keeps, to read: no longer written in.
    n.arrow("chat_leave", [](State& s, Element&, Element*, const Event&) { s.params().set("left", std::int64_t(1)); });
    n.arrow("chat_clear", [](State&, Element& thread, Element*, const Event&) { thread.params.set("unread", std::int64_t(0)); });

    // The edits. Each refuses what is not as it says, and the graph is as it was.
    n.edit("contact_add", [](StateGraph& g, const Event& e) { return make_conversation(g, e.args); });
    n.edit("contact_remove", [](StateGraph& g, const Event& e) {
        const auto state = conversation_state(conversation_arg(e));
        if (!g.contains(state)) return done(false, "no such conversation");
        const auto r = g.removal(state);
        if (!r.ok()) return done(false, r.refused.front());
        g.remove(r);
        return done(true);
    });
    // A device joins or leaves only after its handoff is verified outside
    // the world (Agreement::resume): the edit holds it to the next generation.
    n.edit("device_add", [](StateGraph& g, const Event& e) {
        const auto state = conversation_state(conversation_arg(e));
        if (!g.contains(state)) return done(false, "no such conversation");
        auto& s = g.state(state);
        const auto generation = arg_int(e, "generation");
        if (generation != s.params().get_or<std::int64_t>("generation", 0) + 1) return done(false, "not the next generation");
        // Every device one handoff brings in, at once (a group's member and
        // all their devices): the generation moves once.
        const auto ms = devices_from(arg_text(e, "devices"));
        if (ms.empty()) return done(false, "no device");
        for (const auto& m : ms)
            if (s.find(device_element(device_id(m.device)))) return done(false, "that device is pinned already");
        for (const auto& m : ms) add_device(g, state, m, natives());
        s.params().set("generation", generation);
        return done(true);
    });
    n.edit("device_revoke", [](StateGraph& g, const Event& e) {
        const auto state = conversation_state(conversation_arg(e));
        if (!g.contains(state)) return done(false, "no such conversation");
        auto& s = g.state(state);
        const auto generation = arg_int(e, "generation");
        if (generation != s.params().get_or<std::int64_t>("generation", 0) + 1) return done(false, "not the next generation");
        const auto ms = devices_from(arg_text(e, "devices"));
        if (ms.empty()) return done(false, "no device");
        for (const auto& m : ms)
            if (!s.find(device_element(device_id(m.device)))) return done(false, "that device is not pinned");
        for (const auto& m : ms) s.remove_element(device_element(device_id(m.device)));
        s.params().set("generation", generation);
        return done(true);
    });
    // A lost device replaced by a new one, in one step: the recovery's
    // generation, endorsed outside the world (Recovery.hpp).
    n.edit("device_replace", [](StateGraph& g, const Event& e) {
        const auto state = conversation_state(conversation_arg(e));
        if (!g.contains(state)) return done(false, "no such conversation");
        auto& s = g.state(state);
        const auto generation = arg_int(e, "generation");
        if (generation != s.params().get_or<std::int64_t>("generation", 0) + 1) return done(false, "not the next generation");
        const auto lost = device_element(key_from_hex(arg_text(e, "lost")));
        const auto ms = devices_from(arg_text(e, "devices"));
        if (ms.size() != 1 || !s.find(lost)) return done(false, "one lost device for one new one");
        s.remove_element(lost);
        add_device(g, state, ms[0], natives());
        s.params().set("generation", generation);
        return done(true);
    });
    // A call: its state made from world/call.sg, its stripes as participants
    // of the engine's Placement (neighbours as constraints).
    n.edit("call_start", [](StateGraph& g, const Event& e) {
        const auto c = conversation_arg(e);
        const auto call = call_arg(e);
        const auto conv = conversation_state(c), state = call_state(call);
        if (!g.contains(conv)) return done(false, "no such conversation");
        if (g.contains(state)) return done(false, "that call is there already");
        const auto stripes = arg_int(e, "stripes");
        if (stripes < 1 || stripes > 64) return done(false, "1..64 stripes");
        std::string body;
        for (std::int64_t i = 0; i < stripes; ++i)
            body += "    element stripe_" + std::to_string(i) + " : participant {\n        observation = 0.0\n        weight = 1.0\n        solver = \"\"\n    }\n";
        for (std::int64_t i = 0; i + 1 < stripes || (stripes > 2 && i + 1 == stripes); ++i)
            body += "    element next_" + std::to_string(i) + " : constraint {\n        left = \"stripe_" + std::to_string(i) +
                    "\"\n        right = \"stripe_" + std::to_string((i + 1) % stripes) + "\"\n    }\n";
        apply_source(g, replaced(call_template(), {{"CALL", state}, {"CONVID", hex(c)}, {"CONV", conv},
                                                   {"\"ID\"", "\"" + hex(Bytes(call.begin(), call.end())) + "\""}, {"@STRIPES@", body}}),
                     natives());
        g.state(state).params().set("mode", arg_int(e, "mode"));
        g.keep_default(state);
        return done(true);
    });
    n.edit("call_end", [](StateGraph& g, const Event& e) {
        const auto state = call_state(call_arg(e));
        if (!g.contains(state)) return done(false, "no such call");
        const auto r = g.removal(state);
        if (!r.ok()) return done(false, r.refused.front());
        g.remove(r);
        return done(true);
    });
    // A game of two: the court, its network and its time, made from
    // world/game.sg, with natives of their own (a solver of their own).
    n.edit("game_start", [](StateGraph& g, const Event& e) {
        const auto c = conversation_arg(e);
        const auto id = call_arg(e);
        const auto conv = conversation_state(c);
        if (!g.contains(conv)) return done(false, "no such conversation");
        if (g.contains(game_state(id))) return done(false, "that game is there already");
        auto n = natives();
        const auto gn = game_natives();
        for (const char* a : {"game_configure", "game_publish", "game_corrected", "game_step", "game_commands",
                              "game_bounce", "rally_configure", "rally_begin", "rally_receive", "rally_solve"})
            n.arrow(a, gn.arrow(a));
        for (const char* t : {"game_publish_to", "game_correct", "game_agreed"}) n.transport(t, gn.transport(t));
        apply_source(g, replaced(game_template(), {{"GAME", game_state(id)}, {"NET", game_net_state(id)}, {"TIME", game_time_state(id)},
                                                   {"CONV", conv}, {"\"ID\"", "\"" + hex(Bytes(id.begin(), id.end())) + "\""}}),
                     n);
        for (const auto& s : {game_state(id), game_net_state(id), game_time_state(id)}) g.keep_default(s);
        return done(true);
    });
    n.edit("game_end", [](StateGraph& g, const Event& e) {
        const auto id = call_arg(e);
        if (!g.contains(game_state(id))) return done(false, "no such game");
        for (const auto& s : {game_state(id), game_net_state(id), game_time_state(id)}) {
            const auto r = g.removal(s);
            if (!r.ok()) return done(false, r.refused.front());
            g.remove(r);
        }
        return done(true);
    });
    // A conversation's whiteboard: the board, its view (a participant for each
    // of the conversation's devices) and its time, made from world/board.sg.
    n.edit("board_lay", [](StateGraph& g, const Event& e) {
        const auto c = conversation_arg(e);
        const auto conv = conversation_state(c);
        if (!g.contains(conv)) return done(false, "no such conversation");
        if (g.contains(board_state(c))) return done(true);
        std::vector<std::string> peers;
        for (const auto& m : devices_from(arg_text(e, "devices"))) peers.push_back(hex(device_id(m.device)));
        std::sort(peers.begin(), peers.end());
        std::string body;
        for (const auto& p : peers)
            body += "    element " + viewer_element(p) + " : participant {\n        dim = int(3)\n        observation_0 = 0.0\n"
                    "        observation_1 = 0.0\n        observation_2 = 1.0\n        weight = 1.0\n        pinned_0 = false\n"
                    "        pinned_1 = false\n        pinned_2 = false\n    }\n";
        for (std::size_t i = 0; i + 1 < peers.size(); ++i)
            body += "    element link_" + std::to_string(i) + " : constraint {\n        left = \"" + viewer_element(peers[i]) +
                    "\"\n        right = \"" + viewer_element(peers[i + 1]) + "\"\n        dim = int(3)\n    }\n";
        auto n = natives();
        const auto bn = board_natives();
        for (const char* a : {"board_stroke", "board_lead", "view_observe", "view_lead", "view_solve"}) n.arrow(a, bn.arrow(a));
        apply_source(g, replaced(board_template(), {{"@VIEWERS@", body}, {"BOARD", board_state(c)}, {"VIEW", view_state(c)},
                                                    {"TIME", board_time_state(c)}, {"CONVID", hex(c)}, {"CONV", conv}}),
                     n);
        for (const auto& s : {board_state(c), view_state(c), board_time_state(c)}) g.keep_default(s);
        return done(true);
    });
    n.edit("board_fold", [](StateGraph& g, const Event& e) {
        const auto c = conversation_arg(e);
        if (!g.contains(board_state(c))) return done(false, "no board");
        for (const auto& s : {board_state(c), view_state(c), board_time_state(c)}) {
            const auto r = g.removal(s);
            if (!r.ok()) return done(false, r.refused.front());
            g.remove(r);
        }
        return done(true);
    });
    // Who is in it: the next generation, after its roster epoch's handoff.
    n.edit("call_roster", [](StateGraph& g, const Event& e) {
        const auto state = call_state(call_arg(e));
        if (!g.contains(state)) return done(false, "no such call");
        auto& p = g.state(state).params();
        // Generations only go forward; one a device missed is passed over.
        const auto generation = arg_int(e, "generation");
        if (generation <= p.get_or<std::int64_t>("generation", 0)) return done(false, "not a later generation");
        p.set("generation", generation).set("viewers", arg_int(e, "viewers"));
        return done(true);
    });
    // Who forwards which stripe: Placement's plan for this generation.
    n.edit("call_place", [](StateGraph& g, const Event& e) {
        const auto state = call_state(call_arg(e));
        if (!g.contains(state)) return done(false, "no such call");
        auto& s = g.state(state);
        if (arg_int(e, "generation") != s.params().get_or<std::int64_t>("generation", 0)) return done(false, "a plan for another generation");
        const auto forwarders = arg_text(e, "forwarders");
        std::vector<std::string> each;
        for (std::size_t at = 0; at <= forwarders.size();) {
            const auto end = std::min(forwarders.find(';', at), forwarders.size());
            each.push_back(forwarders.substr(at, end - at));
            at = end + 1;
        }
        for (std::size_t i = 0; i < each.size(); ++i) {
            auto* stripe = s.find(sg::Key("stripe_" + std::to_string(i)));
            if (!stripe) return done(false, "more forwarders than stripes");
            stripe->params.set("solver", each[i]);
        }
        s.params().set("placed", arg_int(e, "epoch"));
        return done(true);
    });
    return n;
}

sg::Params make_conversation(sg::StateGraph& g, const sg::Params& args) {
    const Event e{"contact.add", args};
    const auto c = conversation_arg(e);
    const auto state = conversation_state(c);
    if (g.contains(state)) return done(false, "that conversation is there already");
    const auto pinned = devices_from(arg_text(e, "devices"));
    apply_source(g, replaced(conversation_template(), {{"CONV", state}, {"\"ID\"", "\"" + hex(c) + "\""}}), natives());
    for (const auto& m : pinned) add_device(g, state, m, natives());
    auto& p = g.state(state).params();
    p.set("name", arg_text(e, "name")).set("side", arg_int(e, "side")).set("generation", arg_int(e, "generation"));
    if (const auto* introduced = args.text("introduced")) p.set("introduced", *introduced);
    if (args.has("kind")) p.set("kind", std::int64_t(args.num("kind")));
    g.keep_default(state);
    return done(true);
}

void build_world(sg::StateGraph& g) {
    sg::dsl::Bindings bindings;
    sgen::build_chat(g, natives(), bindings);
}

}  // namespace chat
