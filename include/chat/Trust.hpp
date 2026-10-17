// A conversation's trust, made of the engine's own machinery (sg::net):
//
// - its devices are a Committee (all of both sides' pinned devices);
// - its messages are Observations accepted only through Integrity;
// - its history is an Agreement: every so often a member states the
//   ordered list of message ids since the last epoch (one discrete
//   Observation), the others attest it when their own logs say the same,
//   and the finalization chains to the one before - tamper-evident history;
// - a device joins or leaves only by a Handoff the old quorum endorses
//   (Agreement::endorse / resume, generation + 1), and only then is the
//   graph edited.
//
// Agreement and Verify finalize numerical epochs. A chat epoch has nothing
// to solve, so it carries the smallest valid system the engine accepts - one
// free coordinate, observed 0 with confidence 1, no overlaps, no iterations
// (it solves to 0 exactly) - and all its meaning is in its one discrete
// input and the checkpoint made from it. docs/protocol.md says why, and
// ENGINE_REQUESTS.md asks for a discrete-only epoch.
//
// The engine signs attestations, endorsements and proposals with a
// SigningKey it holds. A browser device's key is a non-extractable WebCrypto
// key, so here each is made unsigned (its statement is what is signed) and
// a vote's lock is written as the very journal the engine would persist,
// then read back by Agreement::restore, which checks it. Ed25519 is
// deterministic: the bytes are the engine's own (tests/test_trust.cpp).
#pragma once
#include "chat/Message.hpp"
#include "sg/net/Agreement.hpp"
#include <map>

namespace chat {

// q = n for one or two devices; q = n - 1 (f = 0) for more: 2q > n + f,
// and one lost device can still be revoked by the rest.
std::uint32_t quorum_for(std::size_t devices);
// A group's: a majority (2q > n), so a group goes on with members away.
std::uint32_t majority_for(std::size_t devices);
std::string region_of(const ConversationId& c);  // "sgchat:<hex>": committee region, epoch world and partition
sg::net::Committee committee_of(const ConversationId& c, std::uint64_t generation, const std::vector<Member>& members,
                               bool majority = false);

const sg::net::Layout& placeholder_layout();
sg::net::LinearSystem placeholder_system();
sg::net::SolverSpec history_spec();
sg::net::EpochContext history_context(const ConversationId& c, const sg::net::Committee& committee, std::uint64_t tick,
                                      const sg::net::Digest& previous);

// What a history epoch states: for each sender device, the run of sequences
// it covers (from the one after the last epoch's, without a gap), and the
// ids of those messages in canonical order (by sender, then sequence).
struct Range {
    Key32 peer{};
    std::uint64_t from = 1, to = 0;  // inclusive; empty when to < from
};
struct History {
    std::vector<Range> ranges;
    std::vector<sg::net::Digest> ids;
};
Bytes encode(const History& h);
History decode_history(const Bytes& b);
// Where each sender's history has reached: the cutoffs of the last checkpoint.
using Cutoffs = std::map<Key32, std::uint64_t>;
// The history of `log` (accepted messages, any order) after `since`: per
// sender the longest run without a gap. A message missing stops its sender's run.
History history_of(const std::vector<sg::net::Observation>& log, const Cutoffs& since);
Cutoffs cutoffs_after(const Cutoffs& since, const History& h);

enum class Agrees { Same, Behind, Differs };
// A member's verdict on a proposed history, by its own log: Same - attest;
// Behind - it has not yet all the messages named (wait for them); Differs -
// a message dropped, changed, moved or added (show it, never attest).
Agrees compare(const History& proposed, const std::vector<sg::net::Observation>& own_log, const Cutoffs& since);

// The epoch's one input: the history, stated by the owner's side - its
// device with the lowest id - and signed by its device key. One proposer, so
// no two members ever lock on different statements for one tick; the owner's
// side, because it is the side that changes who is in the conversation and
// so must be there when it does (a device being revoked is never relied on).
std::string proposer_of(const std::vector<Member>& members);
sg::net::Observation history_statement(const ConversationId& c, const sg::net::EpochContext& context,
                                       const std::string& proposer, const History& h);
sg::net::Problem history_problem(const sg::net::EpochContext& context, const sg::net::Observation& signed_statement);
// The checkpoint, a function of the statement alone: "sg.chat.v1.history.
// checkpoint" | conversation | tick | predecessor | cutoffs | BLAKE2b chain
// over the ids, starting from the predecessor. A statement names every
// sender the conversation has had, so its cutoffs are the whole history's.
Bytes history_checkpoint(const sg::net::Problem& p);
sg::net::Verify history_verify(const ConversationId& c);
Cutoffs checkpoint_cutoffs(const Bytes& checkpoint);

// A proposal's certificate, unsigned: sign `statement()`, then `proposal_for`.
sg::net::ResultCertificate certificate_for(const sg::net::Problem& p, const std::string& signer);
// The same for an epoch of another kind (a call's roster): its own checkpoint.
sg::net::ResultCertificate certificate_for(const sg::net::Problem& p, const std::string& signer, const Bytes& checkpoint);
sg::net::Proposal proposal_for(sg::net::ResultCertificate signed_certificate);
sg::net::Attestation attestation_for(const sg::net::VerifiedResult& r, const std::string& peer);

// The journal Agreement persists once `locks` are cast (sorted by signer),
// in its own format ("sg.net.agreement-journal.v1"); persist it, then let
// the engine read it back (`locked`).
Bytes journal(const sg::net::Committee& committee, const sg::net::Digest& previous, std::uint64_t next_tick,
              const std::string& world, const sg::net::Digest& handoff, std::vector<sg::net::Attestation> locks);
sg::net::Agreement locked(const sg::net::Committee& committee, const sg::net::Digest& previous, std::uint64_t next_tick,
                          const std::string& world, const Bytes& journal, sg::net::Agreement::Persist persist = {});

// A handoff from the last finalized epoch to the next committee.
sg::net::Handoff draft_handoff(const sg::net::Finalization& last, const Bytes& checkpoint, const sg::net::Committee& next);
// What Agreement::endorse checks, without a SigningKey; refused otherwise.
void check_endorsable(const sg::net::Agreement& a, const sg::net::Committee& current, const sg::net::Problem& last,
                      const sg::net::Verify& v, const sg::net::Handoff& h, const std::string& peer);
sg::net::Attestation endorsement_for(const sg::net::Problem& last, const sg::net::Handoff& h, const std::string& peer);

Bytes encode(const sg::net::Committee& c);
sg::net::Committee decode_committee(Reader& r);
Bytes encode(const sg::net::Handoff& h);
sg::net::Handoff decode_handoff(const Bytes& b);
Bytes encode(const sg::net::Attestation& a);
sg::net::Attestation decode_attestation(Reader& r);

// A finalized epoch, whole: what a device keeps so it can endorse a handoff
// from it, and what a new device is given to resume from.
struct Finalized {
    sg::net::EpochContext context;
    sg::net::Observation statement;  // signed
    sg::net::Finalization finalization;
    Bytes checkpoint;
};
Bytes encode(const Finalized& f);
Finalized decode_finalized(const Bytes& b);
sg::net::Problem problem_of(const Finalized& f);

// Control frames (Message.hpp, kind 2), what each body is.
enum class Control : std::uint8_t {
    Epoch = 1,        // an engine protocol message: Proposal (with the statement) / Attestation / Finalization
    HandoffAsk = 2,   // Handoff without endorsements, and the next members' keys
    HandoffVote = 3,  // an endorsement (Attestation)
    HandoffDone = 4,  // the Handoff, endorsed
    Nudge = 5,        // empty: the member whose turn it is is asked to propose an epoch now
    // Protocol 5: recovery (Recovery.hpp), and history given to a new device.
    RecoveryAsk = 6,    // Recovery | its asker's endorsement
    RecoveryVote = 7,   // an endorsement
    RecoveryRefuse = 8, // the lost device's refusal
    RecoveryDone = 9,   // RecoveryDone
    HistoryShare = 10,  // history items, to the new device alone
    // Protocol 7: a call's next key, to each device still in it (Call.hpp).
    CallKey = 11,
    CallRoster = 12,  // a call's next roster: its finalized epoch and the handoff that seals it
    // Protocol 11: between one person's linked devices, in their self
    // conversation (Link.hpp).
    LinkHave = 13,     // what this device has of each chat
    LinkEpochs = 14,   // a chat's finalized epochs (and its last handoff) a linked device lacks
    LinkHistory = 15,  // a chat's messages a linked device lacks, each with its key
};
struct HandoffAsk {
    sg::net::Handoff handoff;
    std::vector<Member> next;
};
Bytes encode(const HandoffAsk& a);
HandoffAsk decode_handoff_ask(const Bytes& b);

}  // namespace chat
