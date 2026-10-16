// v1 §10: calls and streams, over simulated links (each pair of devices a
// fixed delay, 10-60 ms one way).
//
// A swarm: a streamer and nine viewers (two desktops that seed, four phones
// on Wi-Fi that forward, three on mobile data that only take). The roster
// is the call's epoch, sealed by a handoff; the engine's Placement plans
// which viewer forwards which stripe, from the call's state in the world,
// and the plan reaches the world by its edit. Pieces of 250 ms, roots once
// a second. A viewer leaves and another joins half way: a new generation, a
// new key, a new plan; the one that left cannot open what follows. A viewer
// holding the key injects a chunk of its own: no one plays it. Every
// viewer plays what it was there for, and the latency is logged.
//
// Talk: everyone to everyone (four), and speakers through a small fan-out
// tree (three speakers, eight listening, two layers), roots every 100 ms;
// both under 300 ms from capture to being played, verified.
#include "check.hpp"
#include "chat/Swarm.hpp"
#include "chat/World.hpp"
#include "vectors.hpp"
#include "sg/core/Engine.hpp"
#include "sg/core/Laws.hpp"

#include <algorithm>
#include <cstdio>
#include <functional>
#include <random>

using namespace chat;

namespace {
struct Dev {
    std::string name;
    Key32 seed;
    std::unique_ptr<sg::net::SigningKey> key;
    Device device;
    std::string peer;
    Dev(std::string n, std::uint8_t a) : name(std::move(n)), seed(vectors::fill(a)) {
        sg::net::Seed s{};
        std::copy(seed.begin(), seed.end(), s.begin());
        key = std::make_unique<sg::net::SigningKey>(s);
        std::copy(key->public_key().begin(), key->public_key().end(), device.sign.begin());
        device.agree = x25519_public(vectors::fill(std::uint8_t(a + 1)));
        peer = peer_of(device);
    }
};

// Time, in milliseconds, and what happens when.
struct Sim {
    double now = 0;
    std::multimap<double, std::function<void()>> queue;
    void at(double t, std::function<void()> f) { queue.emplace(t, std::move(f)); }
    void after(double ms, std::function<void()> f) { at(now + ms, std::move(f)); }
    void run(double until) {
        while (!queue.empty() && queue.begin()->first <= until) {
            auto it = queue.begin();
            now = it->first;
            auto f = std::move(it->second);
            queue.erase(it);
            f();
        }
        now = until;
    }
};
double delay(const std::string& a, const std::string& b) {
    const auto h = blake2b256(Bytes{}, Writer().short_text(std::min(a, b)).short_text(std::max(a, b)).data());
    return 10 + h[0] % 51;
}
double percentile(std::vector<double> v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return v[std::min(v.size() - 1, std::size_t(p * double(v.size())))];
}

// The call's roster epoch at `tick`, finalized by its holder and sealed by a
// handoff to the next generation; what each viewer checks before believing it.
struct Sealed {
    sg::net::Problem problem;
    sg::net::Handoff handoff;
    sg::net::Committee old;
    sg::net::Digest receipt;
};
Sealed seal_roster(const CallId& call, const Dev& holder, const Roster& roster, std::uint64_t tick, const sg::net::Digest& previous) {
    const auto old = call_committee(call, roster.generation - 1, {holder.device});
    const auto ctx = roster_context(call, old, tick, previous);
    auto statement = roster_statement(call, ctx, holder.peer, roster);
    statement.sign(*holder.key);
    auto problem = roster_problem(ctx, statement);
    const auto verify = roster_verify(call);
    const auto proposal = verify.propose(problem, old, holder.peer, *holder.key, sg::net::CpuBackend{});
    const auto v = verify.proposal(problem, old, proposal);
    sg::net::Agreement agreement(old, previous, tick, {}, ctx.world);
    agreement.attest(*v, holder.peer, *holder.key);
    const auto fin = agreement.finalize(*v, proposal);
    agreement.accept(problem, verify, *fin);
    sg::net::Handoff h{*fin, v->checkpoint(), call_committee(call, roster.generation, {holder.device}), {}};
    h.endorsements.push_back(agreement.endorse(problem, verify, h, holder.peer, *holder.key));
    return {problem, h, old, fin->id()};
}
// A viewer's check: the handoff holds against the call's committee, and the
// roster is what its checkpoint says.
std::optional<Roster> believe(const CallId& call, const Sealed& s) {
    if (!sg::net::verify_handoff(s.problem, s.old, roster_verify(call), s.handoff)) return std::nullopt;
    return checkpoint_roster(s.handoff.checkpoint);
}
}  // namespace

int main() {
    sg::set_observers(sg::Observers::Strict);
    std::mt19937 rng(10);
    const auto bytes = [&](std::size_t n) {
        Bytes b(n);
        for (auto& x : b) x = std::uint8_t(rng());
        return b;
    };

    // ---- a stream's chunks and roots, alone ----
    {
        Dev s("speaker", 0x41), other("other", 0x43);
        CallId c{};
        c[1] = 9;
        const auto k = vectors::fill(0x21);
        sg::net::PublicKey pub{};
        std::copy(s.device.sign.begin(), s.device.sign.end(), pub.begin());
        Playback pb(c, device_id(s.device), pub);
        std::vector<Bytes> chunks;
        Root r;
        r.call = c;
        r.streamer = device_id(s.device);
        for (std::uint64_t i = 0; i < 4; ++i) {
            ChunkHeader h{c, device_id(s.device), 0, i, Layer::Full, i == 0, 1000 * i};
            chunks.push_back(seal_chunk(k, h, Nonce{}, Bytes(100, std::uint8_t(i))));
            r.hashes.push_back(chunk_hash(chunks.back()));
        }
        CHECK(open_chunk(k, chunks[1]) == Bytes(100, 1));
        auto tampered = chunks[1];
        tampered.back() ^= 1;
        CHECK_THROWS(open_chunk(k, tampered));
        CHECK_THROWS(open_chunk(vectors::fill(0x22), chunks[1]));
        for (const auto& ch : chunks) CHECK(pb.chunk(ch) == "kept");
        CHECK_MSG(pb.take().empty(), "nothing is played before a root names it");
        auto by_other = r;
        by_other.signature = other.key->sign(by_other.statement());
        CHECK_MSG(!pb.root(by_other), "a root signed by another is not taken");
        r.signature = s.key->sign(r.statement());
        CHECK(decode_root(encode(r)).statement() == r.statement());
        CHECK(pb.root(r));
        CHECK_MSG(pb.take().size() == 4 && pb.played() == 4, "named, they play in order");
        auto again = r;
        again.hashes = {chunk_hash(tampered)};
        again.first = 2;
        again.signature = s.key->sign(again.statement());
        CHECK_MSG(!pb.root(again), "a root never names a number again");
        ChunkHeader foreign{c, device_id(other.device), 0, 4, Layer::Full, false, 0};
        CHECK_MSG(pb.chunk(seal_chunk(k, foreign, Nonce{}, Bytes(10, 1))) == "refused", "another stream's chunk is not this one's");
        CHECK(pb.chunk(chunks[0]) == "late");
    }

    // ---- the world: a conversation, and its call ----
    sg::StateGraph graph;
    build_world(graph);
    sg::Engine engine(graph);
    engine.set_strict(true);
    engine.start();
    Dev holder("streamer", 0x51);
    ConversationId conv{};
    conv[0] = 0x77;
    CallId call{};
    call[0] = 0x88;
    engine.send("contacts", {"contact.add", contact_add_args(conv, "Stream night", Side::Owner, 0, {{holder.device, Side::Owner, true}})});
    engine.tick(0), engine.tick(0);
    constexpr int stripes = 4;
    engine.send("contacts", {"call.start", call_start_args(conv, call, int(CallMode::Swarm), stripes)});
    engine.tick(0), engine.tick(0);
    CHECK_MSG(graph.contains(call_state(call)), "the call is a state of the world, made by its edit");
    CHECK_MSG(graph.validate().empty() && sg::verify(graph).ok(), "the world with a call validates and its laws hold");
    const auto& callstate = graph.state(call_state(call));

    // ---- who watches: two desktops, four phones on Wi-Fi, three on mobile data, and one who comes later ----
    std::vector<std::unique_ptr<Dev>> devs;
    const Capacity caps[] = {Capacity::Seed, Capacity::Seed, Capacity::Forward, Capacity::Forward, Capacity::Forward,
                             Capacity::Forward, Capacity::Take, Capacity::Take, Capacity::Take, Capacity::Forward};
    for (int i = 0; i < 10; ++i) devs.push_back(std::make_unique<Dev>("viewer" + std::to_string(i), std::uint8_t(0x60 + 2 * i)));
    const auto roster_of = [&](std::uint64_t generation, const std::vector<int>& who) {
        Roster r;
        r.call = call;
        r.generation = generation;
        for (int i : who) r.viewers.push_back({devs[std::size_t(i)]->device, caps[i]});
        std::sort(r.viewers.begin(), r.viewers.end(), [](const Viewer& a, const Viewer& b) { return peer_of(a.device) < peer_of(b.device); });
        return r;
    };
    const auto secret = vectors::fill(0x99);

    // Generation 1: viewers 0..8.
    std::vector<int> first;
    for (int i = 0; i < 9; ++i) first.push_back(i);
    const auto r1 = roster_of(1, first);
    const auto s1 = seal_roster(call, holder, r1, 0, {});
    const auto b1 = believe(call, s1);
    CHECK_MSG(b1 && b1->digest() == r1.digest(), "a viewer believes the roster its handoff seals");
    {
        auto forged = s1;
        forged.handoff.checkpoint.back() ^= 1;
        CHECK_MSG(!believe(call, forged), "a roster changed after it was sealed is not believed");
    }
    engine.send(call_state(call), {call_state(call) + ".roster", call_roster_args(conv, call, 1, r1.viewers.size())});
    engine.tick(0), engine.tick(0);
    CHECK(callstate.params().get_or<std::int64_t>("generation", 0) == 1);
    sg::net::Cellular cellular(callstate);
    CHECK(cellular.stalks().size() == stripes);
    auto plan = plan_stripes(callstate, cellular, r1, s1.receipt, 1, 0);
    CHECK_MSG(plan.feasible, "Placement plans the stripes");
    std::set<std::string> forwarders(plan.forwarders.begin(), plan.forwarders.end());
    bool only_givers = !forwarders.count("");
    for (const auto& v : r1.viewers)
        if (v.capacity == Capacity::Take) only_givers &= !forwarders.count(peer_of(v.device));
    CHECK_MSG(only_givers, "only viewers that can give forward (none on mobile data)");
    engine.send(call_state(call), {call_state(call) + ".place", call_place_args(conv, call, 1, 1, plan.forwarders)});
    engine.tick(0), engine.tick(0);
    bool placed = true;
    for (int i = 0; i < stripes; ++i)
        placed &= *callstate.element(sg::Key("stripe_" + std::to_string(i))).params.text("solver") == plan.forwarders[std::size_t(i)];
    CHECK_MSG(placed, "the plan is in the world, by its edit");

    // ---- the swarm, simulated ----
    Sim sim;
    struct Node {
        Dev* dev = nullptr;
        bool on = false;
        std::uint64_t generation = 0;
        Key32 key{};
        std::unique_ptr<SwarmPeer> swarm;
        std::unique_ptr<Playback> playback;
        std::set<sg::net::Digest> roots;
        std::uint64_t joined_piece = 0;
        std::vector<double> latency;
        std::set<std::uint64_t> played;
        std::map<std::uint64_t, Bytes> pieces;  // what it holds, to give on
    };
    std::map<std::string, Node> nodes;
    const std::string streamer = holder.peer;
    std::map<std::uint64_t, Bytes> originals;  // the streamer's media, by piece
    std::map<std::uint64_t, double> captured;
    std::uint64_t generation = 1;
    Key32 key = call_key(secret, call, 1, r1.digest());
    std::map<std::uint64_t, Key32> keys{{1, key}};  // what the test knows: each generation's key
    std::vector<std::string> current_forwarders = plan.forwarders;
    std::vector<sg::net::Digest> unrooted;
    std::uint64_t root_first = 0, next_piece = 0;
    std::size_t forged_played = 0;

    std::function<void(const std::string&, const std::string&, const Bytes&)> deliver_piece;
    std::function<void(const std::string&, const Root&)> deliver_root;
    const auto send_piece = [&](const std::string& from, const std::string& to, const Bytes& chunk) {
        sim.after(delay(from, to), [&, from, to, chunk] { deliver_piece(from, to, chunk); });
    };
    const auto send_root = [&](const std::string& from, const std::string& to, const Root& r) {
        sim.after(delay(from, to), [&, to, r] { deliver_root(to, r); });
    };
    const auto neighbours_of = [&](const std::string& self) {
        // The stripes' forwarders, and three more on a ring of the roster.
        std::vector<std::string> on;
        for (const auto& [p, n] : nodes)
            if (n.on) on.push_back(p);
        std::set<std::string> out(current_forwarders.begin(), current_forwarders.end());
        const auto at = std::find(on.begin(), on.end(), self);
        if (at != on.end())
            for (int k = 1; k <= 3; ++k) out.insert(on[(std::size_t(at - on.begin()) + std::size_t(k)) % on.size()]);
        out.erase(self);
        out.erase("");
        return std::vector<std::string>(out.begin(), out.end());
    };
    const auto join = [&](Dev* d, std::uint64_t from_piece) {
        auto& n = nodes[d->peer];
        n.dev = d;
        n.on = true;
        n.generation = generation;
        n.key = key;
        n.swarm = std::make_unique<SwarmPeer>(d->peer, stripes);
        sg::net::PublicKey k{};
        std::copy(holder.device.sign.begin(), holder.device.sign.end(), k.begin());
        n.playback = std::make_unique<Playback>(call, device_id(holder.device), k);
        n.joined_piece = from_piece;
    };
    // Neighbours both ways: who lists you is yours too (else a map, or a
    // piece, would go one way only).
    const auto rewire = [&] {
        std::map<std::string, std::set<std::string>> both;
        for (auto& [p, n] : nodes)
            if (n.on)
                for (const auto& q : neighbours_of(p))
                    if (nodes.count(q) && nodes[q].on) both[p].insert(q), both[q].insert(p);
        for (auto& [p, n] : nodes)
            if (n.on) n.swarm->neighbours(std::vector<std::string>(both[p].begin(), both[p].end()));
    };
    for (int i : first) join(devs[std::size_t(i)].get(), 0);
    rewire();

    deliver_piece = [&](const std::string& from, const std::string& to, const Bytes& chunk) {
        auto it = nodes.find(to);
        if (it == nodes.end() || !it->second.on) return;
        auto& n = it->second;
        const auto h = chunk_header(chunk);
        n.swarm->answered(from, h.sequence);
        // Every copy goes to the playback (it keeps a few until a root
        // decides); the first is what this viewer gives on, until a root
        // names another.
        const auto verdict = n.playback->chunk(chunk);
        if (verdict == "refused" || verdict == "late") return;
        const bool had = n.swarm->holds(h.sequence);
        n.swarm->hold(h.sequence);
        if (!had || verdict == "ready") n.pieces[h.sequence] = chunk;
        // A forwarder gives its stripe on at once - the streamer's own copy,
        // whatever came before it - to six of its neighbours (a different six
        // each piece); the rest is pulled.
        const auto stripe = std::size_t(h.sequence % stripes);
        if (current_forwarders[stripe] == to && from == streamer) {
            const auto& ns = n.swarm->neighbours();
            for (std::size_t k = 0; k < std::min<std::size_t>(6, ns.size()); ++k)
                send_piece(to, ns[(std::size_t(h.sequence / stripes) * 6 + k) % ns.size()], chunk);
        }
    };
    deliver_root = [&](const std::string& to, const Root& r) {
        auto it = nodes.find(to);
        if (it == nodes.end() || !it->second.on) return;
        auto& n = it->second;
        const auto id = blake2b256(Bytes{}, encode(r));
        if (!n.roots.insert(id).second) return;
        n.playback->root(r);
        for (const auto& m : n.swarm->neighbours()) send_root(to, m, r);  // roots are small: flooded once
    };

    // The streamer: a piece every 250 ms, a root every four.
    std::function<void()> produce = [&] {
        const auto seq = next_piece++;
        ChunkHeader h;
        h.call = call;
        h.streamer = device_id(holder.device);
        h.generation = generation;
        h.sequence = seq;
        h.key_frame = seq % 8 == 0;
        h.captured_us = std::uint64_t(sim.now * 1000);
        Nonce nonce{};
        const auto nb = bytes(24);
        std::copy(nb.begin(), nb.end(), nonce.begin());
        const auto media = bytes(1500);
        originals[seq] = media;
        captured[seq] = sim.now;
        const auto chunk = seal_chunk(key, h, nonce, media);
        unrooted.push_back(chunk_hash(chunk));
        const auto& f = current_forwarders[std::size_t(seq % stripes)];
        if (!f.empty()) send_piece(streamer, f, chunk);
        if (unrooted.size() == 4) {
            Root r;
            r.call = call;
            r.streamer = device_id(holder.device);
            r.generation = generation;
            r.first = root_first;
            r.hashes = unrooted;
            r.signature = holder.key->sign(r.statement());
            root_first += unrooted.size();
            unrooted.clear();
            for (const auto& fw : std::set<std::string>(current_forwarders.begin(), current_forwarders.end()))
                if (!fw.empty()) send_root(streamer, fw, r);
        }
        if (sim.now < 30000) sim.after(250, produce);
    };
    sim.at(0, produce);

    // Every viewer: says what it holds, asks for what it lacks, plays what is believed.
    std::function<void(std::string)> tick = [&](std::string self) {
        auto it = nodes.find(self);
        if (it == nodes.end() || !it->second.on) return;
        auto& n = it->second;
        for (const auto& m : n.swarm->neighbours()) {
            const auto map = n.swarm->map();
            sim.after(delay(self, m), [&, self, m, map] {
                auto t = nodes.find(m);
                if (t != nodes.end() && t->second.on) t->second.swarm->heard(self, map);
            });
        }
        const auto from = std::max<std::uint64_t>(n.playback->played(), n.joined_piece);
        for (const auto& [peer, piece] : n.swarm->wants(from, from + 16, 4, sim.now)) {
            n.swarm->asked(peer, piece, sim.now);
            sim.after(delay(self, peer), [&, self, peer, piece = piece] {
                auto t = nodes.find(peer);
                if (t == nodes.end() || !t->second.on) return;
                // What it gives on: the copy a root it holds names, else (no
                // root yet) the first that came - never one a root says is not it.
                if (const auto b = t->second.playback->believed(piece)) return send_piece(peer, self, *b);
                const auto c = t->second.pieces.find(piece);
                if (c == t->second.pieces.end()) return;
                const auto named = t->second.playback->named(piece);
                if (named && *named != chunk_hash(c->second)) return;
                send_piece(peer, self, c->second);
            });
        }
        // What a root refused is let go, and asked for again.
        for (auto s : n.playback->take_refused()) {
            n.swarm->drop(s);
            n.pieces.erase(s);
        }
        for (auto& [seq, chunk] : n.playback->take()) {
            n.pieces[seq] = chunk;  // played, so believed: what it gives on from now
            n.latency.push_back(sim.now - captured[seq]);
            n.played.insert(seq);
            try {
                if (open_chunk(keys.at(chunk_header(chunk).generation), chunk) != originals[seq]) ++forged_played;
            } catch (const std::exception&) {
                ++forged_played;  // nothing believed may fail to open
            }
            n.swarm->forget_before(seq > 40 ? seq - 40 : 0);
        }
        // A gap whose time is long over (3 s after capture) is passed over.
        const auto p = n.playback->played();
        if (captured.count(p) && sim.now - captured[p] > 3000) n.playback->skip();
        sim.after(100, [&, self] { tick(self); });
    };
    for (const auto& [p, n] : nodes) sim.at(5, [&, p = p] { tick(p); });

    // A viewer holding the key injects a chunk of its own, under the right number.
    sim.at(15040, [&] {
        const auto liar = devs[2]->peer;
        ChunkHeader h;
        h.call = call;
        h.streamer = device_id(holder.device);
        h.generation = generation;
        h.sequence = next_piece + 1;  // ahead of the real one
        const auto fake = seal_chunk(nodes[liar].key, h, Nonce{}, Bytes(1500, 0xEE));
        for (const auto& m : nodes[liar].swarm->neighbours()) send_piece(liar, m, fake);
    });

    sim.run(10000);
    // Half way: viewer 8 leaves, viewer 9 comes. A new roster, sealed; a new key; a new plan.
    std::vector<int> second;
    for (int i = 0; i < 8; ++i) second.push_back(i);
    second.push_back(9);
    const auto r2 = roster_of(2, second);
    const auto s2 = seal_roster(call, holder, r2, 1, s1.receipt);
    const auto b2 = believe(call, s2);
    CHECK_MSG(b2 && !on(*b2, devs[8]->peer) && on(*b2, devs[9]->peer), "the next roster: one gone, one come");
    engine.send(call_state(call), {call_state(call) + ".roster", call_roster_args(conv, call, 2, r2.viewers.size())});
    engine.tick(0), engine.tick(0);
    sg::net::Cellular cellular2(callstate);
    const auto plan2 = plan_stripes(callstate, cellular2, r2, s2.receipt, 2, 1);
    CHECK(plan2.feasible);
    engine.send(call_state(call), {call_state(call) + ".place", call_place_args(conv, call, 2, 2, plan2.forwarders)});
    engine.tick(0), engine.tick(0);
    CHECK(callstate.params().get_or<std::int64_t>("generation", 0) == 2 && callstate.params().get_or<std::int64_t>("placed", 0) == 2);
    const auto old_key = key;
    generation = 2;
    key = call_key(secret, call, 2, r2.digest());
    keys[2] = key;
    current_forwarders = plan2.forwarders;
    const auto switch_piece = next_piece;
    nodes[devs[8]->peer].on = false;
    const auto left_key = nodes[devs[8]->peer].key;
    for (auto& [p, n] : nodes)
        if (n.on) n.key = key, n.generation = 2;
    join(devs[9].get(), switch_piece);
    rewire();
    sim.at(10000, [&] { tick(devs[9]->peer); });
    sim.run(33000);

    // ---- what was played ----
    CHECK_MSG(forged_played == 0, "nothing played that the streamer did not send");
    std::uint64_t refused = 0;
    for (const auto& [p, n] : nodes) refused += n.playback->refused();
    CHECK_MSG(refused > 0, "the injected chunk was refused (" + std::to_string(refused) + " times)");
    std::vector<double> all;
    bool everyone = true;
    for (const auto& [p, n] : nodes) {
        if (!n.on) continue;
        const auto last = root_first;  // what roots named
        std::uint64_t owed = 0, got = 0;
        for (auto s = n.joined_piece + (n.joined_piece ? 4 : 0); s < last; ++s, ++owed) got += n.played.count(s);
        everyone &= owed > 0 && got == owed;
        if (std::getenv("CALL_TRACE"))
            for (auto s = n.joined_piece; s < last; ++s)
                if (!n.played.count(s)) std::printf("  %s missed %llu\n", n.dev->name.c_str(), (unsigned long long)s);
        all.insert(all.end(), n.latency.begin(), n.latency.end());
        std::printf("  %s %s: played %llu of %llu, latency p50 %.0f ms, p95 %.0f ms\n", n.dev->name.c_str(),
                    n.dev->peer.substr(0, 6).c_str(), (unsigned long long)got, (unsigned long long)owed, percentile(n.latency, .5),
                    percentile(n.latency, .95));
    }
    CHECK_MSG(everyone, "every viewer played every piece streamed while it was there - the injected number too, from its real copy");
    std::printf("swarm: %zu viewers at the end, latency p50 %.0f ms, p95 %.0f ms, max %.0f ms (pieces of 250 ms, a root a second)\n",
                std::size_t(std::count_if(nodes.begin(), nodes.end(), [](const auto& n) { return n.second.on; })), percentile(all, .5),
                percentile(all, .95), percentile(all, 1));
    CHECK_MSG(percentile(all, .95) < 1500, "a swarm plays within 1.5 s of capture (a root a second)");
    // The one that left cannot open what came after.
    bool sealed_out = true;
    for (const auto& [p, n] : nodes)
        if (n.on)
            for (const auto& [s, c] : n.pieces)
                if (s >= switch_piece + 4) try {
                        open_chunk(left_key, c);
                        sealed_out = false;
                    } catch (const std::exception&) {
                    }
    CHECK_MSG(sealed_out && old_key != key, "a viewer that left cannot open what came after (a new key)");

    // ---- talk: everyone to everyone, and speakers through a tree ----
    const auto talk = [&](int speakers, int listeners, bool tree) {
        Sim t;
        std::vector<std::unique_ptr<Dev>> people;
        for (int i = 0; i < speakers + listeners; ++i) people.push_back(std::make_unique<Dev>("p" + std::to_string(i), std::uint8_t(0xA0 + 2 * i)));
        std::vector<double> lat;
        std::size_t wrong = 0;
        const auto tkey = vectors::fill(0x33);
        // Each speaker's stream, each listener's playback of it.
        std::map<std::pair<int, int>, std::unique_ptr<Playback>> pb;
        std::map<std::pair<int, std::uint64_t>, double> when;
        for (int s = 0; s < speakers; ++s)
            for (int l = 0; l < speakers + listeners; ++l)
                if (l != s) {
                    sg::net::PublicKey k{};
                    std::copy(people[std::size_t(s)]->device.sign.begin(), people[std::size_t(s)]->device.sign.end(), k.begin());
                    pb[{s, l}] = std::make_unique<Playback>(call, device_id(people[std::size_t(s)]->device), k, Layer::Small);
                }
        // The tree: a relay for each speaker (the first listeners), giving on to all.
        const auto route = [&](int s, int l) -> std::vector<int> {
            if (!tree || l == speakers + s % listeners) return {s, l};
            return {s, speakers + s % listeners, l};
        };
        const auto carry = [&](const std::vector<int>& path, std::function<void()> f) {
            double d = 0;
            for (std::size_t i = 0; i + 1 < path.size(); ++i) d += delay(people[std::size_t(path[i])]->peer, people[std::size_t(path[i + 1])]->peer);
            t.after(d, std::move(f));
        };
        for (int s = 0; s < speakers; ++s) {
            auto seq = std::make_shared<std::uint64_t>(0);
            auto hashes = std::make_shared<std::vector<sg::net::Digest>>();
            auto first = std::make_shared<std::uint64_t>(0);
            std::shared_ptr<std::function<void()>> frame = std::make_shared<std::function<void()>>();
            *frame = [&, s, seq, hashes, first, frame] {
                ChunkHeader h;
                h.call = call;
                h.streamer = device_id(people[std::size_t(s)]->device);
                h.sequence = (*seq)++;
                h.layer = Layer::Small;
                const auto chunk = seal_chunk(tkey, h, Nonce{}, Bytes(300, std::uint8_t(s)));
                hashes->push_back(chunk_hash(chunk));
                when[{s, h.sequence}] = t.now;
                for (int l = 0; l < speakers + listeners; ++l)
                    if (l != s) carry(route(s, l), [&, s, l, chunk] { pb[{s, l}]->chunk(chunk); });
                if (hashes->size() == 3) {  // 3 frames of 40 ms: a root every 120 ms at most
                    Root r;
                    r.call = call;
                    r.streamer = h.streamer;
                    r.layer = Layer::Small;
                    r.first = *first;
                    r.hashes = *hashes;
                    r.signature = people[std::size_t(s)]->key->sign(r.statement());
                    *first += hashes->size();
                    hashes->clear();
                    for (int l = 0; l < speakers + listeners; ++l)
                        if (l != s) carry(route(s, l), [&, s, l, r] {
                            pb[{s, l}]->root(r);
                            for (auto& [q, c] : pb[{s, l}]->take()) {
                                lat.push_back(t.now - when[{s, q}]);
                                wrong += open_chunk(tkey, c) != Bytes(300, std::uint8_t(s));
                            }
                        });
                }
                if (t.now < 10000) t.after(40, *frame);
            };
            t.at(s * 7.0, *frame);
        }
        t.run(11000);
        std::printf("%s: %d speaking, %d listening, %zu frames played, latency p50 %.0f ms, p95 %.0f ms, max %.0f ms\n",
                    tree ? "speakers through a tree" : "everyone to everyone", speakers, listeners, lat.size(), percentile(lat, .5),
                    percentile(lat, .95), percentile(lat, 1));
        return std::make_tuple(percentile(lat, .95), wrong, lat.size());
    };
    const auto [mesh95, mesh_wrong, mesh_n] = talk(4, 0, false);
    CHECK_MSG(mesh_n > 0 && mesh_wrong == 0 && mesh95 < 300, "everyone to everyone: played under 300 ms, verified");
    const auto [tree95, tree_wrong, tree_n] = talk(3, 8, true);
    CHECK_MSG(tree_n > 0 && tree_wrong == 0 && tree95 < 300, "speakers through a tree: played under 300 ms, verified");

    CHECK_MSG(graph.validate().empty() && sg::verify(graph).ok(), "the world still validates after the call's edits");
    engine.send("contacts", {"call.end", call_end_args(conv, call)});
    engine.tick(0), engine.tick(0);
    CHECK_MSG(!graph.contains(call_state(call)), "a call ends by its edit");
    return sgchat_test::finish("sgchat_call");
}
