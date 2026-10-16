#include "chat/Trust.hpp"
#include "chat/Crypto.hpp"
#include "sg/net/Backend.hpp"
#include <algorithm>
#include <set>

namespace chat {

namespace {
// The engine's canonical encoding (sg::net, src/net/Canonical.*): a domain
// as text, integers as eight big-endian bytes, text and bytes with an
// eight-byte length, digests and signatures as they are. Used for the one
// thing it must equal byte for byte: the agreement journal.
class Canonical {
public:
    explicit Canonical(const std::string& domain) { text(domain); }
    void integer(std::uint64_t v) { w_.u64(v); }
    void text(const std::string& s) { w_.u64(s.size()).raw(reinterpret_cast<const std::uint8_t*>(s.data()), s.size()); }
    void digest(const sg::net::Digest& d) { w_.raw(d); }
    void signature(const sg::net::Signature& s) { w_.raw(s); }
    Bytes take() { return w_.take(); }

private:
    Writer w_;
};
sg::net::Digest to_digest(const Key32& k) { return k; }
}  // namespace

std::uint32_t quorum_for(std::size_t n) {
    if (n == 0) throw Refused("chat: a committee has a device");
    return n <= 2 ? std::uint32_t(n) : std::uint32_t(n - 1);
}
std::string region_of(const ConversationId& c) { return "sgchat:" + hex(c); }
std::uint32_t majority_for(std::size_t n) {
    if (n == 0) throw Refused("chat: a committee has a device");
    return std::uint32_t(n / 2 + 1);
}
sg::net::Committee committee_of(const ConversationId& c, std::uint64_t generation, const std::vector<Member>& members,
                               bool majority) {
    sg::net::Committee out;
    out.region = region_of(c);
    out.generation = generation;
    for (const auto& m : members) out.members.push_back({peer_of(m.device), m.device.sign});
    std::sort(out.members.begin(), out.members.end(), [](const auto& a, const auto& b) { return a.peer < b.peer; });
    out.quorum = majority ? majority_for(out.members.size()) : quorum_for(out.members.size());
    out.faults = 0;
    out.validate();
    return out;
}

const sg::net::Layout& placeholder_layout() {
    static const sg::net::Layout layout{{0, 1}, {0}, {0}, {}, {}, {0, 0}, {}, {}};
    return layout;
}
sg::net::LinearSystem placeholder_system() {
    sg::net::LinearSystem s{placeholder_layout()};
    s.observations = {0.0};
    s.confidence = {1.0};
    s.pins = {0.0};
    s.fixed = {0};
    s.lambda = 1;
    s.relaxation = 0.9;
    s.iterations = 0;
    return s;
}
sg::net::SolverSpec history_spec() {
    sg::net::SolverSpec spec;
    spec.rules = "sgchat-history-v1";
    spec.iterations = 0;
    return spec;
}
sg::net::EpochContext history_context(const ConversationId& c, const sg::net::Committee& committee, std::uint64_t tick,
                                      const sg::net::Digest& previous) {
    sg::net::EpochContext ctx;
    ctx.world = region_of(c);
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

Bytes encode(const History& h) {
    if (h.ranges.size() > 1024 || h.ids.size() > 65536) throw Refused("chat: an epoch's history is too long");
    Writer w;
    w.u8(1).u16(std::uint16_t(h.ranges.size()));
    for (const auto& r : h.ranges) w.raw(r.peer).u64(r.from).u64(r.to);
    w.u32(std::uint32_t(h.ids.size()));
    for (const auto& id : h.ids) w.raw(id);
    return w.take();
}
History decode_history(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 1) throw Refused("chat: unknown history version");
    History h;
    const auto n = r.u16();
    if (n > 1024) throw Refused("chat: an epoch's history is too long");
    std::uint64_t named = 0;
    for (unsigned i = 0; i < n; ++i) {
        Range g;
        g.peer = r.key();
        g.from = r.u64();
        g.to = r.u64();
        if (g.from == 0 || g.to + 1 < g.from || (i && !(h.ranges.back().peer < g.peer)))
            throw Refused("chat: a history's ranges are sorted, distinct and start after 0");
        named += g.to + 1 - g.from;
        h.ranges.push_back(g);
    }
    const auto m = r.u32();
    if (m > 65536 || m != named) throw Refused("chat: a history names one id for each sequence it covers");
    for (std::uint32_t i = 0; i < m; ++i) h.ids.push_back(r.key());
    r.end();
    return h;
}

History history_of(const std::vector<sg::net::Observation>& log, const Cutoffs& since) {
    // Per sender, by sequence: the newest generation's statement of it.
    std::map<Key32, std::map<std::uint64_t, const sg::net::Observation*>> by;
    for (const auto& o : log) {
        auto& slot = by[key_from_hex(o.peer)][o.sequence];
        if (!slot || slot->tick < o.tick) slot = &o;
    }
    std::set<Key32> peers;
    for (const auto& [p, c] : since) peers.insert(p), (void)c;
    for (const auto& [p, m] : by) peers.insert(p), (void)m;
    History h;
    for (const auto& p : peers) {
        const auto found = since.find(p);
        const std::uint64_t start = found == since.end() ? 1 : found->second + 1;
        Range g{p, start, start - 1};
        const auto seen = by.find(p);
        if (seen != by.end())
            for (auto s = start;; ++s) {
                const auto it = seen->second.find(s);
                if (it == seen->second.end()) break;
                h.ids.push_back(it->second->id());
                g.to = s;
            }
        h.ranges.push_back(g);
    }
    return h;
}
Cutoffs cutoffs_after(const Cutoffs& since, const History& h) {
    Cutoffs out = since;
    for (const auto& r : h.ranges) out[r.peer] = r.to;
    return out;
}

Agrees compare(const History& proposed, const std::vector<sg::net::Observation>& own_log, const Cutoffs& since) {
    // A proposal must start where the last checkpoint ended, for every
    // sender the conversation has had.
    std::set<Key32> named;
    for (const auto& r : proposed.ranges) {
        named.insert(r.peer);
        const auto found = since.find(r.peer);
        if (r.from != (found == since.end() ? 1 : found->second + 1)) return Agrees::Differs;
    }
    for (const auto& [p, c] : since)
        if (!named.count(p)) return Agrees::Differs;
    // Our own log, cut to the proposal's ends.
    std::map<Key32, std::map<std::uint64_t, sg::net::Digest>> by;
    std::map<Key32, std::map<std::uint64_t, std::uint64_t>> tick;
    for (const auto& o : own_log) {
        const auto p = key_from_hex(o.peer);
        auto& t = tick[p];
        if (!t.count(o.sequence) || t[o.sequence] < o.tick) {
            t[o.sequence] = o.tick;
            by[p][o.sequence] = o.id();
        }
    }
    bool behind = false;
    std::size_t at = 0;
    for (const auto& r : proposed.ranges) {
        for (auto s = r.from; s <= r.to && s != 0; ++s, ++at) {
            const auto mine = by[r.peer].find(s);
            if (mine == by[r.peer].end()) { behind = true; continue; }
            if (mine->second != proposed.ids[at]) return Agrees::Differs;
        }
        // Something of ours after a sender's cut is only later; a gap in the
        // proposal's run where we hold the message cannot be (runs are whole).
    }
    // A message of ours from a sender the proposal does not name is later too.
    return behind ? Agrees::Behind : Agrees::Same;
}

std::string proposer_of(const std::vector<Member>& members) {
    std::string out;
    for (const auto& m : members)
        if (m.side == Side::Owner && (out.empty() || peer_of(m.device) < out)) out = peer_of(m.device);
    if (out.empty()) throw Refused("chat: a conversation has a device on the owner's side");
    return out;
}
sg::net::Observation history_statement(const ConversationId& c, const sg::net::EpochContext& ctx, const std::string& proposer,
                                       const History& h) {
    sg::net::Observation o;
    o.peer = proposer;
    o.context = ctx.id();
    o.tick = ctx.tick;
    o.sequence = ctx.tick + 1;
    o.object = hex(c);
    o.parameter = "history";
    o.discrete = true;
    o.conflict = "history";
    o.payload = encode(h);
    return o;
}
sg::net::Problem history_problem(const sg::net::EpochContext& ctx, const sg::net::Observation& statement) {
    return sg::net::Problem::make(ctx, placeholder_system(), history_spec(), {statement});
}

Bytes history_checkpoint(const sg::net::Problem& p) {
    if (p.epoch.ordered_inputs.size() != 1) throw Refused("chat: a history epoch has one statement");
    const auto& o = p.epoch.ordered_inputs[0];
    const auto h = decode_history(o.payload);
    Writer w("sg.chat.v1.history.checkpoint");
    w.short_text(o.object).u64(p.epoch.context.tick).raw(p.epoch.context.previous);
    w.u16(std::uint16_t(h.ranges.size()));
    for (const auto& r : h.ranges) w.raw(r.peer).u64(r.to);
    Key32 chain = p.epoch.context.previous;
    for (const auto& id : h.ids) chain = blake2b256(Bytes{}, Writer("sg.chat.v1.history.chain").raw(chain).raw(id).data());
    w.raw(chain);
    return w.take();
}
sg::net::Verify history_verify(const ConversationId& c) {
    const auto object = hex(c);
    return sg::net::Verify(
        [object](const sg::net::Observation& o) {
            if (o.parameter != "history" || o.object != object || o.conflict != "history") return false;
            try { decode_history(o.payload); return true; } catch (const std::exception&) { return false; }
        },
        [](const sg::net::Problem& p, const std::vector<double>&) { return history_checkpoint(p); });
}
Cutoffs checkpoint_cutoffs(const Bytes& checkpoint) {
    Reader r(checkpoint, "sg.chat.v1.history.checkpoint");
    r.short_text();
    r.u64();
    r.key();
    Cutoffs out;
    const auto n = r.u16();
    for (unsigned i = 0; i < n; ++i) {
        const auto p = r.key();
        out[p] = r.u64();
    }
    r.key();
    r.end();
    return out;
}

sg::net::ResultCertificate certificate_for(const sg::net::Problem& p, const std::string& signer) {
    return certificate_for(p, signer, history_checkpoint(p));
}
sg::net::ResultCertificate certificate_for(const sg::net::Problem& p, const std::string& signer, const Bytes& checkpoint) {
    p.validate();
    const auto s = p.system();
    const auto executed = sg::net::CpuBackend{}.solve(s);
    const auto values = sg::net::canonical_values(s, executed, p.solver.quantum);
    sg::net::ResultCertificate c;
    c.epoch = p.epoch.id();
    c.inputs = p.epoch.inputs;
    c.topology = p.epoch.context.topology;
    c.constraints = p.epoch.context.constraints;
    c.solver = p.epoch.context.solver;
    c.result = sg::net::hash(sg::net::canonical_result(values, p.solver.quantum));
    c.checkpoint = sg::net::hash(checkpoint);
    c.residual = sg::net::measure(s, values);
    c.signer = signer;
    return c;
}
sg::net::Proposal proposal_for(sg::net::ResultCertificate c) {
    sg::net::Proposal p;
    p.certificate = std::move(c);
    p.values = {0.0};
    return p;
}
sg::net::Attestation attestation_for(const sg::net::VerifiedResult& r, const std::string& peer) {
    return {r.epoch().id(), r.decision(), peer, {}};
}

Bytes journal(const sg::net::Committee& committee, const sg::net::Digest& previous, std::uint64_t next_tick,
              const std::string& world, const sg::net::Digest& handoff, std::vector<sg::net::Attestation> locks) {
    std::sort(locks.begin(), locks.end(), [](const auto& a, const auto& b) { return a.signer < b.signer; });
    Canonical w("sg.net.agreement-journal.v1");
    w.digest(committee.id());
    w.digest(previous);
    w.integer(next_tick);
    w.text(world);
    w.digest(handoff);
    w.integer(locks.size());
    for (const auto& a : locks) {
        w.digest(a.epoch);
        w.digest(a.decision);
        w.text(a.signer);
        w.signature(a.signature);
    }
    return w.take();
}
sg::net::Agreement locked(const sg::net::Committee& committee, const sg::net::Digest& previous, std::uint64_t next_tick,
                          const std::string& world, const Bytes& j, sg::net::Agreement::Persist persist) {
    sg::net::Agreement a(committee, previous, next_tick, std::move(persist), next_tick ? world : std::string{});
    a.restore(j);
    return a;
}

sg::net::Handoff draft_handoff(const sg::net::Finalization& last, const Bytes& checkpoint, const sg::net::Committee& next) {
    sg::net::Handoff h;
    h.finalized = last;
    h.checkpoint = checkpoint;
    h.next = next;
    return h;
}
void check_endorsable(const sg::net::Agreement& a, const sg::net::Committee& current, const sg::net::Problem& p,
                      const sg::net::Verify& v, const sg::net::Handoff& h, const std::string& peer) {
    h.next.validate();
    sg::net::Agreement independent(current, p.epoch.context.previous, p.epoch.context.tick, {}, p.epoch.context.world);
    const auto result = independent.accept(p, v, h.finalized);
    if (!result || result->checkpoint() != h.checkpoint || a.previous() != h.finalized.id() ||
        a.next_tick() != p.epoch.context.tick + 1 || !current.key(peer) || h.next.region != current.region ||
        current.generation == UINT64_MAX || h.next.generation != current.generation + 1)
        throw Refused("chat: handoff does not extend this finalized regional checkpoint");
}
sg::net::Attestation endorsement_for(const sg::net::Problem& p, const sg::net::Handoff& h, const std::string& peer) {
    return {p.epoch.id(), h.decision(), peer, {}};
}

Bytes encode(const sg::net::Attestation& a) { return Writer().raw(a.epoch).raw(a.decision).short_text(a.signer).raw(a.signature).take(); }
sg::net::Attestation decode_attestation(Reader& r) {
    sg::net::Attestation a;
    a.epoch = r.key();
    a.decision = r.key();
    a.signer = r.short_text(128);
    a.signature = r.fixed<64>();
    return a;
}
Bytes encode(const sg::net::Committee& c) {
    Writer w;
    w.short_text(c.region).u64(c.generation).u32(c.quorum).u32(c.faults).u16(std::uint16_t(c.members.size()));
    for (const auto& m : c.members) w.short_text(m.peer).raw(m.key);
    return w.take();
}
sg::net::Committee decode_committee(Reader& r) {
    sg::net::Committee c;
    c.region = r.short_text(128);
    c.generation = r.u64();
    c.quorum = r.u32();
    c.faults = r.u32();
    const auto n = r.u16();
    if (n > 64) throw Refused("chat: a committee is at most 64 devices");
    for (unsigned i = 0; i < n; ++i) {
        sg::net::Member m;
        m.peer = r.short_text(128);
        m.key = r.key();
        c.members.push_back(m);
    }
    c.validate();
    return c;
}
namespace {
Bytes finalization_bytes(const sg::net::Finalization& f) {
    sg::net::Message m;
    m.kind = sg::net::MessageKind::Finalization;
    m.from = m.to = "sgchat";
    m.finalization = f;
    return sg::net::encode(m);
}
sg::net::Finalization finalization_from(const Bytes& b) {
    const auto m = sg::net::decode_message(b);
    if (m.kind != sg::net::MessageKind::Finalization) throw Refused("chat: not a finalization");
    return m.finalization;
}
void members(Writer& w, const std::vector<Member>& ms) {
    w.u8(std::uint8_t(ms.size()));
    for (const auto& m : ms) w.raw(m.device.sign).raw(m.device.agree).u8(member_flags(m));
}
std::vector<Member> members(Reader& r) {
    std::vector<Member> out;
    const auto n = r.u8();
    if (n == 0 || n > 64) throw Refused("chat: a committee is 1..64 devices");
    for (unsigned i = 0; i < n; ++i) {
        Device d;
        d.sign = r.key();
        d.agree = r.key();
        out.push_back(member_of(d, r.u8()));
    }
    return out;
}
}  // namespace
Bytes encode(const sg::net::Handoff& h) {
    Writer w;
    w.u8(1).long_bytes(finalization_bytes(h.finalized), 1 << 20).long_bytes(h.checkpoint, 1 << 20).raw(encode(h.next));
    w.u16(std::uint16_t(h.endorsements.size()));
    for (const auto& a : h.endorsements) w.raw(encode(a));
    return w.take();
}
namespace {
sg::net::Handoff decode_handoff(Reader& r) {
    if (r.u8() != 1) throw Refused("chat: unknown handoff version");
    sg::net::Handoff h;
    h.finalized = finalization_from(r.long_bytes(1 << 20));
    h.checkpoint = r.long_bytes(1 << 20);
    h.next = decode_committee(r);
    const auto n = r.u16();
    if (n > 64) throw Refused("chat: too many endorsements");
    for (unsigned i = 0; i < n; ++i) h.endorsements.push_back(decode_attestation(r));
    return h;
}
}  // namespace
sg::net::Handoff decode_handoff(const Bytes& b) {
    Reader r(b);
    auto h = decode_handoff(r);
    r.end();
    return h;
}

Bytes encode(const Finalized& f) {
    Writer w;
    w.u8(1).short_text(f.context.world).short_text(f.context.partition).u64(f.context.tick).u64(f.context.generation);
    w.raw(f.context.topology).raw(f.context.constraints).raw(f.context.solver).raw(f.context.committee).raw(f.context.previous);
    w.long_bytes(observation_bytes(f.statement), 1 << 20).long_bytes(finalization_bytes(f.finalization), 1 << 20);
    w.long_bytes(f.checkpoint, 1 << 20);
    return w.take();
}
Finalized decode_finalized(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 1) throw Refused("chat: unknown finalized version");
    Finalized f;
    f.context.world = r.short_text(128);
    f.context.partition = r.short_text(128);
    f.context.tick = r.u64();
    f.context.generation = r.u64();
    f.context.topology = r.key();
    f.context.constraints = r.key();
    f.context.solver = r.key();
    f.context.committee = r.key();
    f.context.previous = r.key();
    f.statement = observation_from(r.long_bytes(1 << 20));
    f.finalization = finalization_from(r.long_bytes(1 << 20));
    f.checkpoint = r.long_bytes(1 << 20);
    r.end();
    return f;
}
sg::net::Problem problem_of(const Finalized& f) { return history_problem(f.context, f.statement); }

Bytes encode(const HandoffAsk& a) {
    Writer w;
    w.raw(encode(a.handoff));
    members(w, a.next);
    return w.take();
}
HandoffAsk decode_handoff_ask(const Bytes& b) {
    Reader r(b);
    HandoffAsk a;
    a.handoff = decode_handoff(r);
    a.next = members(r);
    r.end();
    return a;
}

}  // namespace chat
