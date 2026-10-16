// Recovery and a chat's lifetime (protocol 5).
//
// A lost device is a member that is absent. It cannot endorse a handoff, so
// a recovery is a decision of its own: the other members endorse replacing
// it (engine Attestations, by their device keys) - a recovery quorum of two
// thirds of them, and in a conversation of two the other side alone, after a
// check in person or by voice - and it takes effect only a day after it was
// asked, so the old device, if it still exists, can refuse it. Then the old
// generation is sealed and every key turns.
//
// The new device may be given the history (all of it, since a time, or
// none): each message as it was signed, with the key to open it. It takes
// only messages whose ids are in the conversation's agreed history: a chain
// of finalized epochs ending where the endorsed decision says, and the
// messages since, which the decision names (each endorser checked them
// against its own log, as it would an epoch's).
#pragma once
#include "chat/Trust.hpp"

namespace chat {

enum class Scope : std::uint8_t { None = 0, Since = 1, Full = 2 };

struct Recovery {
    ConversationId conversation{};
    std::uint64_t generation = 0;  // the generation it makes
    Key32 lost{};                  // the device it replaces
    Member replacement;            // the new device, on the lost one's side
    Scope scope = Scope::None;
    std::uint64_t since_ms = 0;    // with Since
    std::uint64_t not_before_ms = 0;
    sg::net::Digest previous{};    // the last finalized epoch's id (zero: none)
    std::uint64_t tick = 0;        // the next history tick
    Bytes tail;                    // the history since that epoch (an encoded History), as the asker has it
    sg::net::Digest decision() const;
    sg::net::Digest epoch() const;  // what endorsements name as their epoch
};
Bytes encode(const Recovery& r);
Recovery decode_recovery(Reader& r);

// Two thirds of the devices that remain (at least one): who must endorse.
std::uint32_t recovery_quorum(std::size_t remaining);
sg::net::Attestation recovery_endorsement(const Recovery& r, const std::string& peer);  // unsigned
// The old device's refusal: the same, over the cancelled decision.
sg::net::Attestation recovery_refusal(const Recovery& r, const std::string& peer);
// Endorsed: distinct members of `committee` other than the lost device, by
// their own keys, at least the recovery quorum. Refused (false) otherwise.
bool recovery_holds(const Recovery& r, const sg::net::Committee& committee, const std::vector<sg::net::Attestation>& endorsements);

struct RecoveryDone {
    Recovery recovery;
    std::vector<sg::net::Attestation> endorsements;
    std::vector<Member> members;  // the committee it makes
};
Bytes encode(const RecoveryDone& d);
RecoveryDone decode_recovery_done(const Bytes& b);

// History given to a new device: messages as signed, with their keys.
struct HistoryItem {
    sg::net::Observation message;
    Key32 key{};
};
Bytes encode(const std::vector<HistoryItem>& items);
std::vector<HistoryItem> decode_history_items(const Bytes& b);
// The agreed history, as finalized epochs (oldest first): the ids they name,
// if each links to the one before and the last is `head`; refused otherwise.
std::vector<sg::net::Digest> chained_ids(const std::vector<Finalized>& epochs, const sg::net::Digest& head);

// A chat's options, said by a member: no recovery (the history dies with a
// lost device), and messages that disappear after a while (0: never).
struct Options {
    bool no_recovery = false;
    std::uint32_t disappear_s = 0;
};
Bytes encode(const Options& o);
Options decode_options(const Bytes& b);

}  // namespace chat
