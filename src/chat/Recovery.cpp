#include "chat/Recovery.hpp"
#include "chat/Crypto.hpp"
#include <set>

namespace chat {

namespace {
void member_out(Writer& w, const Member& m) { w.raw(m.device.sign).raw(m.device.agree).u8(member_flags(m)); }
Member member_in(Reader& r) {
    Device d;
    d.sign = r.key();
    d.agree = r.key();
    return member_of(d, r.u8());
}
}  // namespace

Bytes encode(const Recovery& r) {
    Writer w;
    w.u8(5).raw(r.conversation).u64(r.generation).raw(r.lost);
    member_out(w, r.replacement);
    w.u8(std::uint8_t(r.scope)).u64(r.since_ms).u64(r.not_before_ms).raw(r.previous).u64(r.tick).long_bytes(r.tail, 1 << 20);
    return w.take();
}
Recovery decode_recovery(Reader& rd) {
    if (rd.u8() != 5) throw Refused("chat: unknown recovery version");
    Recovery r;
    r.conversation = rd.fixed<16>();
    r.generation = rd.u64();
    r.lost = rd.key();
    r.replacement = member_in(rd);
    const auto scope = rd.u8();
    if (scope > 2) throw Refused("chat: unknown history scope");
    r.scope = Scope(scope);
    r.since_ms = rd.u64();
    r.not_before_ms = rd.u64();
    r.previous = rd.key();
    r.tick = rd.u64();
    r.tail = rd.long_bytes(1 << 20);
    decode_history(r.tail);  // refused here if it does not read
    return r;
}
sg::net::Digest Recovery::decision() const { return blake2b256(Bytes{}, Writer("sg.chat.v5.recovery").raw(encode(*this)).data()); }
sg::net::Digest Recovery::epoch() const {
    return blake2b256(Bytes{}, Writer("sg.chat.v5.recovery.epoch").raw(conversation).u64(generation).data());
}

std::uint32_t recovery_quorum(std::size_t remaining) {
    return std::max<std::uint32_t>(1, std::uint32_t((2 * remaining + 2) / 3));
}
sg::net::Attestation recovery_endorsement(const Recovery& r, const std::string& peer) { return {r.epoch(), r.decision(), peer, {}}; }
sg::net::Attestation recovery_refusal(const Recovery& r, const std::string& peer) {
    const auto refused = blake2b256(Bytes{}, Writer("sg.chat.v5.recovery.refused").raw(r.decision()).data());
    return {r.epoch(), refused, peer, {}};
}
bool recovery_holds(const Recovery& r, const sg::net::Committee& committee, const std::vector<sg::net::Attestation>& ends) {
    const auto lost = hex(r.lost);
    std::set<std::string> signers;
    for (const auto& a : ends) {
        const auto* key = committee.key(a.signer);
        if (!key || a.signer == lost || a.epoch != r.epoch() || a.decision != r.decision() || !signers.insert(a.signer).second ||
            !sg::net::check_signature(*key, a.statement(), a.signature))
            return false;
    }
    const auto remaining = committee.members.size() - (committee.key(lost) ? 1 : 0);
    return remaining > 0 && signers.size() >= recovery_quorum(remaining);
}

Bytes encode(const RecoveryDone& d) {
    Writer w;
    w.raw(encode(d.recovery)).u16(std::uint16_t(d.endorsements.size()));
    for (const auto& a : d.endorsements) w.raw(encode(a));
    w.u8(std::uint8_t(d.members.size()));
    for (const auto& m : d.members) member_out(w, m);
    return w.take();
}
RecoveryDone decode_recovery_done(const Bytes& b) {
    Reader r(b);
    RecoveryDone d;
    d.recovery = decode_recovery(r);
    const auto n = r.u16();
    if (n > 64) throw Refused("chat: too many endorsements");
    for (unsigned i = 0; i < n; ++i) d.endorsements.push_back(decode_attestation(r));
    const auto m = r.u8();
    if (m == 0 || m > 64) throw Refused("chat: a committee is 1..64 devices");
    for (unsigned i = 0; i < m; ++i) d.members.push_back(member_in(r));
    r.end();
    return d;
}

Bytes encode(const std::vector<HistoryItem>& items) {
    if (items.size() > 4096) throw Refused("chat: too many history items at once");
    Writer w;
    w.u8(5).u16(std::uint16_t(items.size()));
    for (const auto& i : items) w.long_bytes(observation_bytes(i.message), 1 << 20).raw(i.key);
    return w.take();
}
std::vector<HistoryItem> decode_history_items(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 5) throw Refused("chat: unknown history version");
    std::vector<HistoryItem> out;
    const auto n = r.u16();
    for (unsigned i = 0; i < n; ++i) {
        HistoryItem h;
        h.message = observation_from(r.long_bytes(1 << 20));
        h.key = r.key();
        out.push_back(std::move(h));
    }
    r.end();
    return out;
}

std::vector<sg::net::Digest> chained_ids(const std::vector<Finalized>& epochs, const sg::net::Digest& head) {
    std::vector<sg::net::Digest> ids;
    sg::net::Digest previous{};
    for (const auto& f : epochs) {
        if (f.context.previous != previous) throw Refused("chat: an epoch that does not follow the one before");
        if (history_checkpoint(problem_of(f)) != f.checkpoint || sg::net::hash(f.checkpoint) != f.finalization.proposal.certificate.checkpoint)
            throw Refused("chat: an epoch whose checkpoint is not its own");
        for (const auto& id : decode_history(f.statement.payload).ids) ids.push_back(id);
        previous = f.finalization.id();
    }
    if (previous != head) throw Refused("chat: the history does not end where the recovery says");
    return ids;
}

Bytes encode(const Options& o) { return Writer().u8(5).u8(o.no_recovery ? 1 : 0).u32(o.disappear_s).take(); }
Options decode_options(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 5) throw Refused("chat: unknown options version");
    Options o;
    const auto nr = r.u8();
    if (nr > 1) throw Refused("chat: unknown option");
    o.no_recovery = nr == 1;
    o.disappear_s = r.u32();
    r.end();
    return o;
}

}  // namespace chat
