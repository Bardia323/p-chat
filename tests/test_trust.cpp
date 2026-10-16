// Phase 3: a conversation's trust is the engine's own (sg::net).
//
// - Messages go through Integrity: accepted, duplicate dropped, replay and
//   forgery refused, equivocation kept as evidence.
// - What the browser signs outside the engine (attestation, endorsement,
//   certificate) and the vote lock it writes are byte for byte what the
//   engine's Agreement::attest / endorse and Verify::propose make.
// - History epochs finalize, chain, and catch a dropped or reordered message.
// - A device joins only with the old quorum's endorsements.
#include "check.hpp"
#include "chat/World.hpp"
#include "vectors.hpp"

using namespace chat;
using sg::net::Delivery;

namespace {
struct Dev {
    vectors::Keys keys;
    sg::net::SigningKey key;
    std::string peer;
    Key32 id;
    explicit Dev(vectors::Keys k) : keys(k), key(k.seed), peer(peer_of(k.device)), id(device_id(k.device)) {}
};
ConversationId conv() {
    ConversationId c{};
    for (std::size_t i = 0; i < 16; ++i) c[i] = std::uint8_t(0x91 + i);
    return c;
}
sg::net::Observation message(const Dev& from, std::uint64_t generation, std::uint64_t seq, const std::string& text) {
    auto o = make_message(conv(), generation, from.id, seq, "text");
    Nonce n{};
    n[0] = std::uint8_t(seq);
    o.payload = seal_content(vectors::fill(std::uint8_t(seq)), n, o, Content{seq, Bytes(text.begin(), text.end())});
    o.sign(from.key);
    return o;
}
// One member's whole view of an epoch: statement, problem, verified result.
struct Epoch {
    sg::net::EpochContext context;
    sg::net::Observation statement;
    sg::net::Problem problem;
    sg::net::Proposal proposal;
};
Epoch propose(const Dev& proposer, const sg::net::Committee& committee, std::uint64_t tick, const sg::net::Digest& previous,
              const std::vector<sg::net::Observation>& log, const Cutoffs& since) {
    Epoch e;
    e.context = history_context(conv(), committee, tick, previous);
    e.statement = history_statement(conv(), e.context, proposer.peer, history_of(log, since));
    e.statement.sign(proposer.key);
    e.problem = history_problem(e.context, e.statement);
    auto cert = certificate_for(e.problem, proposer.peer);
    cert.signature = proposer.key.sign(cert.statement());
    e.proposal = proposal_for(cert);
    return e;
}
}  // namespace

int main() {
    const Dev A(vectors::owner()), F(vectors::friend1()), G(vectors::friend2());
    const std::vector<Member> two = {{A.keys.device, Side::Owner}, {F.keys.device, Side::Friend}};
    const auto committee = committee_of(conv(), 0, two);
    CHECK(committee.quorum == 2 && committee.faults == 0);
    CHECK(quorum_for(1) == 1 && quorum_for(2) == 2 && quorum_for(3) == 2 && quorum_for(5) == 4);

    // 1. Integrity: the only way a message is accepted.
    {
        sg::net::Integrity integrity(committee);
        const auto ctx = conversation_context(conv(), 0);
        const auto m1 = message(F, 0, 1, "hello");
        CHECK(integrity.receive(m1, ctx, 0) == Delivery::Accepted);
        CHECK(integrity.receive(m1, ctx, 0) == Delivery::Duplicate);
        auto twin = message(F, 0, 1, "hello, but other");
        CHECK(integrity.receive(twin, ctx, 0) == Delivery::Equivocation);
        CHECK(integrity.evidence().size() == 1 && integrity.evidence()[0].first.id() == m1.id() &&
              integrity.evidence()[0].second.id() == twin.id());
        auto forged = message(F, 0, 2, "forged");
        forged.payload[30] ^= 1;  // the signature no longer holds
        CHECK(integrity.receive(forged, ctx, 0) == Delivery::Invalid);
        const auto stranger = message(G, 0, 1, "not a member");
        CHECK(integrity.receive(stranger, ctx, 0) == Delivery::Invalid);
        const auto moved = message(F, 1, 3, "wrong generation");
        CHECK(integrity.receive(moved, ctx, 0) == Delivery::Invalid);
        // A new generation retires the old: an old message again is a replay.
        integrity.retire_before(1);
        CHECK(integrity.receive(message(F, 0, 4, "late"), ctx, 0) == Delivery::Replay);
        CHECK(integrity.receive(m1, ctx, 0) == Delivery::Replay);
    }

    // 2. Signed outside the engine = signed by it. The certificate:
    const auto m1 = message(F, 0, 1, "one"), m2 = message(A, 0, 1, "two"), m3 = message(F, 0, 2, "three");
    std::vector<sg::net::Observation> log = {m1, m2, m3};
    const auto proposer = proposer_of(two) == A.peer ? &A : &F;
    CHECK(proposer == &A);  // the owner's side states the history
    const auto other = proposer == &A ? &F : &A;
    auto e0 = propose(*proposer, committee, 0, {}, log, {});
    const auto verify = history_verify(conv());
    const sg::net::CpuBackend cpu;
    const auto engines = verify.propose(e0.problem, committee, proposer->peer, proposer->key, cpu);
    CHECK(engines.certificate.statement() == e0.proposal.certificate.statement());
    CHECK(engines.certificate.signature == e0.proposal.certificate.signature && engines.values == e0.proposal.values);
    const auto v_prop = verify.proposal(e0.problem, committee, e0.proposal);
    CHECK(v_prop.has_value());

    // ... the vote and the journal its lock is persisted as:
    Bytes engine_journal;
    sg::net::Agreement engine_agreement(committee, {}, 0, [&](const Bytes& b) { engine_journal = b; });
    const auto engine_vote = engine_agreement.attest(*v_prop, proposer->peer, proposer->key);
    auto vote = attestation_for(*v_prop, proposer->peer);
    vote.signature = proposer->key.sign(vote.statement());
    CHECK(vote.statement() == engine_vote.statement() && vote.signature == engine_vote.signature);
    const auto j = journal(committee, {}, 0, e0.context.world, {}, {vote});
    CHECK(j == engine_journal);
    // Read back, the lock holds: the member cannot vote for another problem.
    auto restored = locked(committee, {}, 0, e0.context.world, j);
    auto other_log = log;
    other_log.pop_back();
    const auto e_other = propose(*proposer, committee, 0, {}, other_log, {});
    const auto v_other = verify.proposal(e_other.problem, committee, e_other.proposal);
    CHECK(v_other.has_value());
    CHECK_THROWS(restored.attest(*v_other, proposer->peer, proposer->key));
    CHECK(restored.attest(*v_prop, proposer->peer, proposer->key).signature == vote.signature);
    // A journal with a forged lock is refused by the engine.
    auto bad = vote;
    bad.signature[0] ^= 1;
    CHECK_THROWS(locked(committee, {}, 0, e0.context.world, journal(committee, {}, 0, e0.context.world, {}, {bad})));

    // 3. The epoch: the other member's log agrees, it attests, it finalizes.
    CHECK(compare(decode_history(e0.statement.payload), log, {}) == Agrees::Same);
    auto a_prop = locked(committee, {}, 0, e0.context.world, j);
    sg::net::Agreement a_other(committee, {}, 0);
    const auto v_at_other = verify.proposal(e0.problem, committee, e0.proposal);
    auto vote2 = attestation_for(*v_at_other, other->peer);
    vote2.signature = other->key.sign(vote2.statement());
    CHECK(a_prop.receive(*v_prop, vote2));
    const auto fin = a_prop.finalize(*v_prop, e0.proposal);
    CHECK(fin.has_value());
    CHECK(a_other.receive(*v_at_other, vote));
    const auto accepted = a_other.accept(e0.problem, verify, *fin);
    CHECK(accepted.has_value() && a_other.next_tick() == 1 && a_other.previous() == fin->id());
    CHECK(a_prop.accept(e0.problem, verify, *fin).has_value());
    const auto checkpoint0 = history_checkpoint(e0.problem);
    const auto since = checkpoint_cutoffs(checkpoint0);
    CHECK(since.at(F.id) == 2 && since.at(A.id) == 1);

    // 4. The next epoch chains to it, and catches what went wrong.
    const auto m4 = message(A, 0, 2, "four"), m5 = message(F, 0, 3, "five");
    auto log1 = log;
    log1.push_back(m4);
    log1.push_back(m5);
    const auto proposer1 = &A;
    auto e1 = propose(*proposer1, committee, 1, fin->id(), log1, since);
    CHECK(e1.context.previous == fin->id());
    // - a member that has not got m5 yet waits for it (no vote);
    auto lacking = log1;
    lacking.pop_back();
    CHECK(compare(decode_history(e1.statement.payload), lacking, since) == Agrees::Behind);
    // - a member whose m5 is another message sees it differs;
    auto altered = log1;
    altered.back() = message(F, 0, 3, "five, altered");
    CHECK(compare(decode_history(e1.statement.payload), altered, since) == Agrees::Differs);
    // - a proposal that drops a message from its run is not a run: the proposer
    //   cannot leave m4 out and keep a later one of A's;
    auto dropped = decode_history(e1.statement.payload);
    {
        History h = dropped;
        for (auto& r : h.ranges)
            if (r.peer == A.id) r.to = r.from - 1;  // A's m4 left out
        h.ids.erase(std::remove(h.ids.begin(), h.ids.end(), m4.id()), h.ids.end());
        CHECK(compare(h, log1, since) == Agrees::Same);  // an epoch that ends earlier is fine ...
        auto statement = history_statement(conv(), e1.context, proposer1->peer, h);
        statement.sign(proposer1->key);
        const auto chk = history_checkpoint(history_problem(e1.context, statement));
        CHECK(checkpoint_cutoffs(chk).at(A.id) == 1);  // ... and the next one starts at m4.
        History hole = dropped;
        hole.ids.erase(std::remove(hole.ids.begin(), hole.ids.end(), m4.id()), hole.ids.end());
        CHECK_THROWS(decode_history(encode(hole)));  // ids no longer one per sequence
    }
    // - a reordered history differs, and its signature no longer holds;
    {
        auto h = decode_history(e1.statement.payload);
        CHECK(h.ids.size() == 2);
        std::swap(h.ids[0], h.ids[1]);
        CHECK(compare(h, log1, since) == Agrees::Differs);
        auto moved = e1.statement;
        moved.payload = encode(h);
        CHECK(!moved.authentic(committee));
        CHECK(!verify.proposal(history_problem(e1.context, moved), committee, e1.proposal).has_value());
    }
    // - a history that does not start where the last ended differs.
    CHECK(compare(decode_history(e1.statement.payload), log1, {}) == Agrees::Differs);
    // - a statement chained to another predecessor is not this epoch.
    {
        sg::net::Digest wrong = fin->id();
        wrong[0] ^= 1;
        auto e_wrong = propose(*proposer1, committee, 1, wrong, log1, since);
        const auto v = verify.proposal(e_wrong.problem, committee, e_wrong.proposal);
        CHECK(v.has_value());
        CHECK_THROWS(a_other.attest(*v, other->peer, other->key));
    }

    // 5. A device joins only with the old quorum's endorsements.
    const std::vector<Member> three = {two[0], two[1], {G.keys.device, Side::Friend}};
    const auto next = committee_of(conv(), 1, three);
    CHECK(next.quorum == 2);
    auto h = draft_handoff(*fin, checkpoint0, next);
    CHECK(!sg::net::verify_handoff(e0.problem, committee, verify, h));
    CHECK_THROWS(sg::net::Agreement::resume(e0.problem, committee, verify, h));
    // Our endorsement equals the engine's, and so does the journal that seals
    // the old generation.
    check_endorsable(a_prop, committee, e0.problem, verify, h, A.peer);
    auto end_a = endorsement_for(e0.problem, h, A.peer);
    end_a.signature = A.key.sign(end_a.statement());
    Bytes sealed_journal;
    sg::net::Agreement engine_a(committee, fin->id(), 1, [&](const Bytes& b) { sealed_journal = b; }, e0.context.world);
    const auto engine_end = engine_a.endorse(e0.problem, verify, h, A.peer, A.key);
    CHECK(engine_end.statement() == end_a.statement() && engine_end.signature == end_a.signature);
    CHECK(journal(committee, fin->id(), 1, e0.context.world, h.decision(), {}) == sealed_journal);
    h.endorsements = {end_a};
    CHECK(!sg::net::verify_handoff(e0.problem, committee, verify, h));  // one of two
    auto forged_end = endorsement_for(e0.problem, h, F.peer);
    forged_end.signature = A.key.sign(forged_end.statement());  // F's vote, A's key
    h.endorsements = {end_a, forged_end};
    CHECK(!sg::net::verify_handoff(e0.problem, committee, verify, h));
    auto end_g = endorsement_for(e0.problem, h, G.peer);  // not a member yet
    end_g.signature = G.key.sign(end_g.statement());
    h.endorsements = {end_a, end_g};
    CHECK(!sg::net::verify_handoff(e0.problem, committee, verify, h));
    auto end_f = endorsement_for(e0.problem, h, F.peer);
    end_f.signature = F.key.sign(end_f.statement());
    h.endorsements = {end_a, end_f};
    CHECK(sg::net::verify_handoff(e0.problem, committee, verify, h));
    // A handoff that skips a generation, or leaves the region, is refused.
    {
        auto skip = h;
        skip.next = committee_of(conv(), 2, three);
        CHECK(!sg::net::verify_handoff(e0.problem, committee, verify, skip));
        CHECK_THROWS(check_endorsable(a_prop, committee, e0.problem, verify, skip, A.peer));
    }
    // The new committee is taken up by resume, at the next tick, chained.
    auto resumed = sg::net::Agreement::resume(e0.problem, committee, verify, h);
    CHECK(resumed.next_tick() == 1 && resumed.previous() == fin->id());
    // Encoded and read back, the handoff and the finalized epoch are the same.
    const auto again = decode_handoff(encode(h));
    CHECK(again.decision() == h.decision() && sg::net::verify_handoff(e0.problem, committee, verify, again));
    const Finalized f0{e0.context, e0.statement, *fin, checkpoint0};
    const auto f0b = decode_finalized(encode(f0));
    CHECK(problem_of(f0b).epoch.id() == e0.problem.epoch.id() && f0b.finalization.id() == fin->id());
    HandoffAsk ask{draft_handoff(*fin, checkpoint0, next), three};
    CHECK(decode_handoff_ask(encode(ask)).next.size() == 3);

    // 6. Revoking with three devices: two of three endorse; the revoked one
    //    is not needed, and is gone from the next committee.
    {
        const auto c3 = committee_of(conv(), 1, three);
        auto e = propose(A, c3, 1, fin->id(), log1, since);
        const auto v = verify.proposal(e.problem, c3, e.proposal);
        CHECK(v.has_value());
        sg::net::Agreement ag(c3, fin->id(), 1, {}, e.context.world);
        std::vector<sg::net::Attestation> votes;
        for (const Dev* d : {&A, &F}) {
            auto a = attestation_for(*v, d->peer);
            a.signature = d->key.sign(a.statement());
            CHECK(ag.receive(*v, a));
        }
        const auto f1 = ag.finalize(*v, e.proposal);
        CHECK(f1.has_value());
        CHECK(ag.accept(e.problem, verify, *f1).has_value());
        auto revoke = draft_handoff(*f1, history_checkpoint(e.problem), committee_of(conv(), 2, two));
        for (const Dev* d : {&A, &F}) {
            auto a = endorsement_for(e.problem, revoke, d->peer);
            a.signature = d->key.sign(a.statement());
            revoke.endorsements.push_back(a);
        }
        CHECK(sg::net::verify_handoff(e.problem, c3, verify, revoke));
        CHECK(!revoke.next.key(G.peer));

        // 7. The agreed history a recovered device is given: each epoch links
        //    to the one before, and the last is the one the recovery names.
        const Finalized f1full{e.context, e.statement, *f1, history_checkpoint(e.problem)};
        const auto ids = chained_ids({f0, f1full}, f1->id());
        CHECK(ids.size() == decode_history(e0.statement.payload).ids.size() + decode_history(e.statement.payload).ids.size());
        CHECK_THROWS(chained_ids({f1full, f0}, f1->id()));  // reordered
        CHECK_THROWS(chained_ids({f1full}, f1->id()));      // the first dropped
        CHECK_THROWS(chained_ids({f0}, f1->id()));          // the last dropped
        CHECK(chained_ids({}, sg::net::Digest{}).empty());
    }

    // 8. A recovery: two thirds of the devices that remain endorse; the lost
    //    one's word does not count, nor a signature that is not the signer's.
    {
        CHECK(recovery_quorum(1) == 1 && recovery_quorum(2) == 2 && recovery_quorum(3) == 2 && recovery_quorum(4) == 3);
        const auto c3 = committee_of(conv(), 1, three);
        Recovery rec;
        rec.conversation = conv();
        rec.generation = 2;
        rec.lost = G.id;
        rec.replacement = {vectors::friend1().device, Side::Friend};
        rec.not_before_ms = 1700086400000ull;
        const auto by = [&](const Dev& d) {
            auto a = recovery_endorsement(rec, d.peer);
            a.signature = d.key.sign(a.statement());
            return a;
        };
        CHECK(recovery_holds(rec, c3, {by(A), by(F)}));
        CHECK(!recovery_holds(rec, c3, {by(A)}));
        CHECK(!recovery_holds(rec, c3, {by(A), by(G)}));
        CHECK(!recovery_holds(rec, c3, {by(A), by(A)}));
        auto forged = by(F);
        forged.signature = A.key.sign(forged.statement());
        CHECK(!recovery_holds(rec, c3, {by(A), forged}));
        // Endorsed, then changed: the endorsements are for another decision.
        auto moved = rec;
        moved.not_before_ms = 0;
        CHECK(!recovery_holds(moved, c3, {by(A), by(F)}));
        // The old device's refusal is its own statement, not an endorsement.
        auto no = recovery_refusal(rec, G.peer);
        no.signature = G.key.sign(no.statement());
        CHECK(!recovery_holds(rec, c3, {by(A), no}));
        // Two devices: the other side alone.
        const auto c2 = committee_of(conv(), 0, two);
        rec.lost = F.id;
        CHECK(recovery_holds(rec, c2, {by(A)}) && !recovery_holds(rec, c2, {}));
    }
    return sgchat_test::finish("sgchat_trust");
}
