#include "chat/Swarm.hpp"
#include "chat/Crypto.hpp"

namespace chat {

double capacity_weight(Capacity c) { return c == Capacity::Seed ? 4.0 : c == Capacity::Forward ? 1.0 : 0.0; }

sg::net::Digest Roster::digest() const { return blake2b256(Bytes{}, Writer("sg.chat.v7.roster").raw(encode(*this)).data()); }
Bytes encode(const Roster& r) {
    if (r.viewers.size() > 4096) throw Refused("chat: a roster is at most 4096 viewers");
    Writer w;
    w.u8(7).raw(r.call).u64(r.generation).u16(std::uint16_t(r.viewers.size()));
    for (const auto& v : r.viewers) w.raw(v.device.sign).raw(v.device.agree).u8(std::uint8_t(v.capacity));
    return w.take();
}
Roster decode_roster(const Bytes& b) {
    Reader rd(b);
    if (rd.u8() != 7) throw Refused("chat: not a roster");
    Roster r;
    r.call = rd.fixed<16>();
    r.generation = rd.u64();
    const auto n = rd.u16();
    if (n > 4096) throw Refused("chat: a roster is at most 4096 viewers");
    std::string last;
    for (unsigned i = 0; i < n; ++i) {
        Viewer v;
        v.device.sign = rd.key();
        v.device.agree = rd.key();
        const auto c = rd.u8();
        if (c > 2) throw Refused("chat: unknown capacity");
        v.capacity = Capacity(c);
        const auto p = peer_of(v.device);
        if (i && p <= last) throw Refused("chat: a roster is sorted and has each viewer once");
        last = p;
        r.viewers.push_back(v);
    }
    rd.end();
    return r;
}
bool on(const Roster& r, const std::string& peer) {
    for (const auto& v : r.viewers)
        if (peer_of(v.device) == peer) return true;
    return false;
}

std::string call_region(const CallId& call) { return "sgchat-call:" + hex(Bytes(call.begin(), call.end())); }
sg::net::Committee call_committee(const CallId& call, std::uint64_t generation, const std::vector<Device>& holders) {
    sg::net::Committee out;
    out.region = call_region(call);
    out.generation = generation;
    for (const auto& d : holders) out.members.push_back({peer_of(d), d.sign});
    std::sort(out.members.begin(), out.members.end(), [](const auto& a, const auto& b) { return a.peer < b.peer; });
    out.quorum = quorum_for(out.members.size());
    out.faults = 0;
    out.validate();
    return out;
}
sg::net::EpochContext roster_context(const CallId& call, const sg::net::Committee& committee, std::uint64_t tick,
                                     const sg::net::Digest& previous) {
    sg::net::EpochContext ctx;
    ctx.world = call_region(call);
    ctx.partition = committee.region;
    ctx.tick = tick;
    ctx.generation = committee.generation;
    const auto s = placeholder_system();
    ctx.topology = sg::net::topology_hash(s.layout);
    ctx.constraints = sg::net::constraint_hash(s, {});
    ctx.solver = history_spec().id();
    ctx.committee = committee.id();
    ctx.previous = previous;
    return ctx;
}
sg::net::Observation roster_statement(const CallId& call, const sg::net::EpochContext& ctx, const std::string& proposer,
                                      const Roster& roster) {
    sg::net::Observation o;
    o.peer = proposer;
    o.context = ctx.id();
    o.tick = ctx.tick;
    o.sequence = ctx.tick + 1;
    o.object = hex(Bytes(call.begin(), call.end()));
    o.parameter = "roster";
    o.discrete = true;
    o.conflict = "roster";
    o.payload = encode(roster);
    return o;
}
sg::net::Problem roster_problem(const sg::net::EpochContext& ctx, const sg::net::Observation& statement) {
    return sg::net::Problem::make(ctx, placeholder_system(), history_spec(), {statement});
}
Bytes roster_checkpoint(const sg::net::Problem& p) {
    if (p.epoch.ordered_inputs.size() != 1) throw Refused("chat: a roster epoch has one statement");
    const auto& o = p.epoch.ordered_inputs[0];
    const auto r = decode_roster(o.payload);
    if (r.generation != p.epoch.context.generation + 1) throw Refused("chat: a roster is for the generation after its epoch's");
    return Writer("sg.chat.v7.roster.checkpoint").short_text(o.object).u64(p.epoch.context.tick).raw(p.epoch.context.previous).raw(o.payload).take();
}
sg::net::Verify roster_verify(const CallId& call) {
    const auto object = hex(Bytes(call.begin(), call.end()));
    return sg::net::Verify(
        [object](const sg::net::Observation& o) {
            if (o.parameter != "roster" || o.object != object || o.conflict != "roster") return false;
            try { decode_roster(o.payload); return true; } catch (const std::exception&) { return false; }
        },
        [](const sg::net::Problem& p, const std::vector<double>&) { return roster_checkpoint(p); });
}
Roster checkpoint_roster(const Bytes& checkpoint) {
    Reader r(checkpoint, "sg.chat.v7.roster.checkpoint");
    r.short_text();
    r.u64();
    r.key();
    return decode_roster(r.raw(r.left()));
}

Bytes encode(const BufferMap& m) { return Writer().u8(7).u64(m.base).u64(m.bits).take(); }
BufferMap decode_buffer_map(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 7) throw Refused("chat: not a buffer map");
    BufferMap m;
    m.base = r.u64();
    m.bits = r.u64();
    r.end();
    return m;
}

SwarmPeer::SwarmPeer(std::string self, std::size_t stripes) : self_(std::move(self)), stripes_(stripes) {}
void SwarmPeer::neighbours(std::vector<std::string> peers) {
    neighbours_ = std::move(peers);
    for (auto it = maps_.begin(); it != maps_.end();)
        it = std::find(neighbours_.begin(), neighbours_.end(), it->first) == neighbours_.end() ? maps_.erase(it) : std::next(it);
}
void SwarmPeer::hold(std::uint64_t piece) {
    held_.insert(piece);
    last_asked_.erase(piece);
    for (auto& [p, w] : waiting_) w.erase(piece);
}
BufferMap SwarmPeer::map() const {
    BufferMap m;
    if (held_.empty()) return m;
    m.base = *held_.rbegin() >= 63 ? *held_.rbegin() - 63 : 0;
    for (auto it = held_.lower_bound(m.base); it != held_.end(); ++it) m.bits |= std::uint64_t(1) << (*it - m.base);
    return m;
}
void SwarmPeer::heard(const std::string& peer, const BufferMap& m) {
    if (std::find(neighbours_.begin(), neighbours_.end(), peer) != neighbours_.end()) maps_[peer] = m;
}
std::vector<std::pair<std::string, std::uint64_t>> SwarmPeer::wants(std::uint64_t from, std::uint64_t until, std::size_t per_peer,
                                                                    double now_ms, double patience_ms) {
    std::vector<std::pair<std::string, std::uint64_t>> out;
    // Questions long unanswered are given up (the one asked is tried last).
    for (auto& [p, w] : waiting_)
        for (auto it = w.begin(); it != w.end();)
            if (now_ms - it->second > patience_ms) last_asked_[it->first] = p, it = w.erase(it);
            else ++it;
    std::map<std::string, std::size_t> load;
    for (const auto& [p, w] : waiting_) load[p] = w.size();
    // Nearest the playing point first (its deadline is soonest); among the
    // ones holding it, the least asked; ties by name - the same each time.
    std::vector<std::uint64_t> missing;
    for (auto piece = from; piece < until; ++piece)
        if (!held_.count(piece)) missing.push_back(piece);
    std::map<std::uint64_t, std::size_t> rarity;
    for (auto piece : missing)
        for (const auto& [p, m] : maps_) rarity[piece] += m.has(piece);
    // The nearest few strictly in order; beyond them, the rarest first.
    const std::size_t urgent = std::min<std::size_t>(missing.size(), 4);
    std::stable_sort(missing.begin() + std::ptrdiff_t(urgent), missing.end(),
                     [&](auto a, auto b) { return rarity[a] < rarity[b]; });
    for (auto piece : missing) {
        bool already = false;
        for (const auto& [p, w] : waiting_) already |= w.count(piece) != 0;
        if (already) continue;
        std::string best;
        const auto tried = last_asked_.find(piece);
        const auto worse = [&](const std::string& a, const std::string& b) {  // is a worse than b?
            const bool ta = tried != last_asked_.end() && tried->second == a, tb = tried != last_asked_.end() && tried->second == b;
            if (ta != tb) return ta;
            return load[a] > load[b];
        };
        for (const auto& [p, m] : maps_)
            if (m.has(piece) && load[p] < per_peer && (best.empty() || worse(best, p))) best = p;
        if (best.empty()) continue;
        ++load[best];
        out.emplace_back(best, piece);
    }
    return out;
}
void SwarmPeer::answered(const std::string& peer, std::uint64_t piece) {
    const auto w = waiting_.find(peer);
    if (w != waiting_.end()) w->second.erase(piece);
}
void SwarmPeer::forget_before(std::uint64_t piece) {
    held_.erase(held_.begin(), held_.lower_bound(piece));
    last_asked_.erase(last_asked_.begin(), last_asked_.lower_bound(piece));
    for (auto& [p, w] : waiting_) w.erase(w.begin(), w.lower_bound(piece));
}

StripePlan plan_stripes(const sg::State& call, const sg::net::Cellular& cellular, const Roster& roster, const sg::net::Digest& receipt,
                        std::uint64_t epoch, std::uint64_t last_placement_epoch) {
    sg::net::FinalizedPlacementView view{call, receipt, epoch, roster.generation, last_placement_epoch};
    sg::net::PlacementMetrics metrics;
    for (const auto& v : roster.viewers)
        metrics.peers.push_back({{peer_of(v.device), {}}, capacity_weight(v.capacity) * double(cellular.stalks().size()),
                                 v.capacity != Capacity::Take});
    metrics.migration_penalty = 0.05;
    metrics.hold_epochs = 0;
    const auto plan = sg::net::Placement::plan(view, cellular, metrics);
    StripePlan out;
    out.generation = plan.generation;
    out.feasible = plan.feasible;
    out.forwarders.assign(cellular.stalks().size(), std::string());
    for (const auto& a : plan.assignments) {
        const auto name = a.stalk.str();
        if (name.rfind("stripe_", 0) != 0) continue;
        const auto i = std::size_t(std::stoul(name.substr(7)));
        if (i < out.forwarders.size()) out.forwarders[i] = a.peer;
    }
    return out;
}

}  // namespace chat
