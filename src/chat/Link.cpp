#include "chat/Link.hpp"
#include "chat/Crypto.hpp"
#include <algorithm>
#include <set>

namespace chat {

namespace {
constexpr std::uint8_t link_version = 11;
void member_out(Writer& w, const Member& m) { w.raw(m.device.sign).raw(m.device.agree).u8(member_flags(m)); }
Member member_in(Reader& r) {
    Device d;
    d.sign = r.key();
    d.agree = r.key();
    return member_of(d, r.u8());
}
void members_out(Writer& w, const std::vector<Member>& ms) {
    if (ms.size() > 255) throw Refused("chat: at most 255 devices");
    w.u8(std::uint8_t(ms.size()));
    for (const auto& m : ms) member_out(w, m);
}
std::vector<Member> members_in(Reader& r) {
    std::vector<Member> out;
    const auto n = r.u8();
    for (unsigned i = 0; i < n; ++i) out.push_back(member_in(r));
    return out;
}
void version_in(Reader& r) {
    if (r.u8() != link_version) throw Refused("chat: unknown link version");
}
void ids_out(Writer& w, const std::vector<ConversationId>& ids) {
    if (ids.size() > 4096) throw Refused("chat: at most 4096 chats");
    w.u16(std::uint16_t(ids.size()));
    for (const auto& id : ids) w.raw(id);
}
std::vector<ConversationId> ids_in(Reader& r) {
    std::vector<ConversationId> out;
    const auto n = r.u16();
    if (n > 4096) throw Refused("chat: at most 4096 chats");
    for (unsigned i = 0; i < n; ++i) out.push_back(r.fixed<16>());
    return out;
}
}  // namespace

Bytes encode(const LinkedChat& l) {
    if (l.name.size() > 64 || l.introduced.size() > 64 || l.relay.size() > 512) throw Refused("chat: a linked chat's names out of bounds");
    if (l.members.empty()) throw Refused("chat: a linked chat has members");
    Writer w;
    w.u8(link_version).raw(l.conversation).u8(std::uint8_t(l.kind)).u8(std::uint8_t(l.side)).raw(l.secret).u64(l.secret_generation);
    w.short_text(l.name).short_text(l.introduced).short_text(l.relay).u64(l.generation);
    members_out(w, l.members);
    w.long_bytes(l.trust, 180000);
    members_out(w, l.before);
    w.u8(l.no_recovery ? 1 : 0).u32(l.disappear_s);
    return w.take();
}
LinkedChat decode_linked_chat(const Bytes& b) {
    Reader r(b);
    version_in(r);
    LinkedChat l;
    l.conversation = r.fixed<16>();
    const auto kind = r.u8();
    if (kind > 2) throw Refused("chat: a linked chat is two-sided, a group or a channel");
    l.kind = Kind(kind);
    const auto side = r.u8();
    if (side > 1) throw Refused("chat: unknown side");
    l.side = Side(side);
    l.secret = r.key();
    l.secret_generation = r.u64();
    l.name = r.short_text(64);
    l.introduced = r.short_text(64);
    l.relay = r.short_text(512);
    l.generation = r.u64();
    l.members = members_in(r);
    if (l.members.empty()) throw Refused("chat: a linked chat has members");
    l.trust = r.long_bytes(180000);
    l.before = members_in(r);
    const auto nr = r.u8();
    if (nr > 1) throw Refused("chat: unknown option");
    l.no_recovery = nr == 1;
    l.disappear_s = r.u32();
    r.end();
    return l;
}

Bytes encode(const DeviceAsk& a) {
    Writer w;
    w.u8(link_version);
    member_out(w, a.member);
    return w.take();
}
DeviceAsk decode_device_ask(const Bytes& b) {
    Reader r(b);
    version_in(r);
    DeviceAsk a;
    a.member = member_in(r);
    r.end();
    return a;
}

Bytes encode(const Leave& l) {
    return Writer().u8(link_version).raw(l.conversation).u64(l.generation).raw(l.leaving).raw(l.previous).u64(l.tick)
        .long_bytes(l.tail, 1 << 20).take();
}
Leave decode_leave(Reader& r) {
    version_in(r);
    Leave l;
    l.conversation = r.fixed<16>();
    l.generation = r.u64();
    l.leaving = r.key();
    l.previous = r.key();
    l.tick = r.u64();
    l.tail = r.long_bytes(1 << 20);
    decode_history(l.tail);  // refused here if it does not read
    return l;
}
sg::net::Digest Leave::decision() const { return blake2b256(Bytes{}, Writer("sg.chat.v11.leave").raw(encode(*this)).data()); }
sg::net::Digest Leave::epoch() const {
    return blake2b256(Bytes{}, Writer("sg.chat.v11.leave.epoch").raw(conversation).u64(generation).data());
}
sg::net::Attestation leave_endorsement(const Leave& l, const std::string& peer) { return {l.epoch(), l.decision(), peer, {}}; }
bool leave_holds(const Leave& l, const sg::net::Committee& committee, const std::vector<sg::net::Attestation>& ends) {
    if (l.generation != committee.generation + 1 || !committee.key(hex(l.leaving))) return false;
    std::set<std::string> signers;
    for (const auto& a : ends) {
        const auto* key = committee.key(a.signer);
        if (!key || a.epoch != l.epoch() || a.decision != l.decision() || !signers.insert(a.signer).second ||
            !sg::net::check_signature(*key, a.statement(), a.signature))
            return false;
    }
    return signers.count(hex(l.leaving)) && signers.size() >= committee.quorum;
}
Bytes encode(const LeaveDone& d) {
    Writer w;
    w.raw(encode(d.leave)).u16(std::uint16_t(d.endorsements.size()));
    for (const auto& a : d.endorsements) w.raw(encode(a));
    members_out(w, d.members);
    member_out(w, d.left);
    return w.take();
}
LeaveDone decode_leave_done(const Bytes& b) {
    Reader r(b);
    LeaveDone d;
    d.leave = decode_leave(r);
    const auto n = r.u16();
    if (n > 256) throw Refused("chat: too many endorsements");
    for (unsigned i = 0; i < n; ++i) d.endorsements.push_back(decode_attestation(r));
    d.members = members_in(r);
    if (d.members.empty()) throw Refused("chat: a committee has members");
    d.left = member_in(r);
    r.end();
    return d;
}

Bytes encode(const Unlink& u) {
    Writer w;
    w.u8(link_version).u8(std::uint8_t(u.what));
    ids_out(w, u.keeps);
    ids_out(w, u.gives);
    return w.take();
}
Unlink decode_unlink(const Bytes& b) {
    Reader r(b);
    version_in(r);
    Unlink u;
    const auto what = r.u8();
    if (what < 1 || what > 5) throw Refused("chat: unknown unlink");
    u.what = UnlinkWhat(what);
    u.keeps = ids_in(r);
    u.gives = ids_in(r);
    r.end();
    return u;
}

Bytes encode(const LinkName& n) {
    if (n.name.empty() || n.name.size() > 64) throw Refused("chat: a name is 1..64 bytes");
    return Writer().u8(link_version).raw(n.conversation).short_text(n.name).take();
}
LinkName decode_link_name(const Bytes& b) {
    Reader r(b);
    version_in(r);
    LinkName n;
    n.conversation = r.fixed<16>();
    n.name = r.short_text(64);
    if (n.name.empty()) throw Refused("chat: a name is 1..64 bytes");
    r.end();
    return n;
}

Bytes encode(const LinkHave& h) {
    if (h.chats.size() > 1024) throw Refused("chat: at most 1024 chats said at once");
    Writer w;
    w.u8(link_version).u8(h.all ? 1 : 0).u16(std::uint16_t(h.chats.size()));
    for (const auto& c : h.chats) {
        if (c.held.size() > 256) throw Refused("chat: at most 256 senders a chat");
        w.raw(c.conversation).u64(c.generation).u64(c.next_tick).u8(c.older ? 1 : 0).u16(std::uint16_t(c.held.size()));
        for (const auto& [peer, runs] : c.held) {
            if (runs.size() > 256) throw Refused("chat: at most 256 runs a sender");
            w.raw(peer).u16(std::uint16_t(runs.size()));
            for (const auto& [from, to] : runs) w.u64(from).u64(to);
        }
    }
    return w.take();
}
LinkHave decode_link_have(const Bytes& b) {
    Reader r(b);
    version_in(r);
    LinkHave h;
    const auto all = r.u8();
    if (all > 1) throw Refused("chat: all is 0 or 1");
    h.all = all == 1;
    const auto n = r.u16();
    if (n > 1024) throw Refused("chat: at most 1024 chats said at once");
    for (unsigned i = 0; i < n; ++i) {
        LinkHave::Chat c;
        c.conversation = r.fixed<16>();
        c.generation = r.u64();
        c.next_tick = r.u64();
        const auto older = r.u8();
        if (older > 1) throw Refused("chat: older is 0 or 1");
        c.older = older == 1;
        const auto k = r.u16();
        if (k > 256) throw Refused("chat: at most 256 senders a chat");
        for (unsigned j = 0; j < k; ++j) {
            const auto peer = r.key();
            const auto nr = r.u16();
            if (nr > 256) throw Refused("chat: at most 256 runs a sender");
            Runs runs;
            for (unsigned x = 0; x < nr; ++x) {
                const auto from = r.u64(), to = r.u64();
                // Ascending and apart: a run that overlaps or goes back is refused.
                if (from < 1 || to < from || (!runs.empty() && from <= runs.back().second + 1)) throw Refused("chat: runs ascend, apart");
                runs.emplace_back(from, to);
            }
            if (!c.held.emplace(peer, std::move(runs)).second) throw Refused("chat: a sender said twice");
        }
        h.chats.push_back(std::move(c));
    }
    r.end();
    return h;
}
std::map<Key32, Runs> runs_of(const std::vector<sg::net::Observation>& log) {
    std::map<Key32, std::vector<std::uint64_t>> seen;
    for (const auto& o : log)
        if (o.sequence > 0) seen[key_from_hex(o.peer)].push_back(o.sequence);
    std::map<Key32, Runs> out;
    for (auto& [peer, seqs] : seen) {
        std::sort(seqs.begin(), seqs.end());
        seqs.erase(std::unique(seqs.begin(), seqs.end()), seqs.end());
        Runs runs;
        for (auto s : seqs) {
            if (!runs.empty() && s == runs.back().second + 1) runs.back().second = s;
            else runs.emplace_back(s, s);
        }
        // A log with more holes than can be said: the newest runs, and the
        // oldest said as one (what is older is not asked for again).
        if (runs.size() > 256) {
            Runs kept{{runs.front().first, runs[runs.size() - 256].second}};
            kept.insert(kept.end(), runs.end() - 255, runs.end());
            runs = std::move(kept);
        }
        out[peer] = std::move(runs);
    }
    return out;
}
bool holds(const std::map<Key32, Runs>& held, const Key32& sender, std::uint64_t sequence) {
    const auto found = held.find(sender);
    if (found == held.end()) return false;
    for (const auto& [from, to] : found->second)
        if (sequence >= from && sequence <= to) return true;
    return false;
}

Bytes encode(const LinkEpochs& e) {
    if (e.epochs.size() > 4096) throw Refused("chat: too many epochs at once");
    Writer w;
    if (e.leaves.size() > 4096 || (e.handoff && e.left)) throw Refused("chat: epochs out of bounds");
    w.u8(link_version).raw(e.conversation).u16(std::uint16_t(e.epochs.size()));
    for (const auto& f : e.epochs) w.long_bytes(f, 1 << 20);
    w.u16(std::uint16_t(e.leaves.size()));
    for (const auto& l : e.leaves) w.long_bytes(l, 1 << 20);
    w.u8(e.handoff ? 1 : e.left ? 2 : 0);
    if (e.handoff) w.long_bytes(encode(*e.handoff), 1 << 20);
    if (e.left) w.long_bytes(encode(*e.left), 1 << 20);
    return w.take();
}
LinkEpochs decode_link_epochs(const Bytes& b) {
    Reader r(b);
    version_in(r);
    LinkEpochs e;
    e.conversation = r.fixed<16>();
    const auto n = r.u16();
    if (n > 4096) throw Refused("chat: too many epochs at once");
    for (unsigned i = 0; i < n; ++i) e.epochs.push_back(r.long_bytes(1 << 20));
    const auto nl = r.u16();
    if (nl > 4096) throw Refused("chat: too many leaves at once");
    for (unsigned i = 0; i < nl; ++i) e.leaves.push_back(r.long_bytes(1 << 20));
    const auto h = r.u8();
    if (h > 2) throw Refused("chat: a handoff, a leave or none");
    if (h == 1) e.handoff = decode_handoff_ask(r.long_bytes(1 << 20));
    if (h == 2) e.left = decode_leave_done(r.long_bytes(1 << 20));
    r.end();
    return e;
}

Bytes encode(const LinkHistory& h) {
    return Writer().u8(link_version).raw(h.conversation).long_bytes(encode(h.items), 262144).take();
}
LinkHistory decode_link_history(const Bytes& b) {
    Reader r(b);
    version_in(r);
    LinkHistory h;
    h.conversation = r.fixed<16>();
    h.items = decode_history_items(r.long_bytes(262144));
    r.end();
    return h;
}

bool epoch_before(const Finalized& f, const sg::net::Digest& expect) {
    return f.finalization.id() == expect && history_checkpoint(problem_of(f)) == f.checkpoint &&
           sg::net::hash(f.checkpoint) == f.finalization.proposal.certificate.checkpoint;
}

}  // namespace chat
