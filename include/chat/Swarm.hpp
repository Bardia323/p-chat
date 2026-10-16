// A stream to many (protocol 7): a swarm, torrent-style.
//
// Who may watch is the call's roster. The call is held by the devices of
// the one who started it - its committee, as a channel's is its
// publisher's - and every change of roster is one of its epochs (the new
// roster its one statement), finalized, then sealed by a Handoff to the
// next generation: a new generation, a new key, and a viewer that left
// never has it. Each viewer says what it can give: a desktop seeds, a phone
// on Wi-Fi forwards, a phone on mobile data only takes.
//
// The stream is cut in pieces of 200-500 ms (a chunk each, Call.hpp), and
// the pieces in stripes (piece number mod stripes). The engine's Placement
// plans which viewer forwards which stripe, by what each can give, from the
// call's state in the world (its stripes are participants there, and
// neighbouring stripes constraints); the plan reaches the world only by an
// edit. The streamer gives each piece to its stripe's forwarder; the rest
// is pulled: viewers tell their neighbours what they hold (a buffer map),
// and ask for what they lack, nearest the playing point first, then the
// rarest.
#pragma once
#include "chat/Call.hpp"
#include "sg/net/Placement.hpp"

#include <set>

namespace chat {

enum class Capacity : std::uint8_t { Take = 0, Forward = 1, Seed = 2 };
double capacity_weight(Capacity c);  // what Placement is told: 0, 1, 4

struct Viewer {
    Device device;
    Capacity capacity = Capacity::Take;
};
struct Roster {
    CallId call{};
    std::uint64_t generation = 0;
    std::vector<Viewer> viewers;  // sorted by peer, distinct
    sg::net::Digest digest() const;
};
Bytes encode(const Roster& r);
Roster decode_roster(const Bytes& b);
bool on(const Roster& r, const std::string& peer);

// The call's committee: its starter's devices (every one must agree with
// one or two, all but one beyond), in its own region.
std::string call_region(const CallId& call);
sg::net::Committee call_committee(const CallId& call, std::uint64_t generation, const std::vector<Device>& holders);
sg::net::EpochContext roster_context(const CallId& call, const sg::net::Committee& committee, std::uint64_t tick,
                                     const sg::net::Digest& previous);
sg::net::Observation roster_statement(const CallId& call, const sg::net::EpochContext& context, const std::string& proposer,
                                      const Roster& roster);
sg::net::Problem roster_problem(const sg::net::EpochContext& context, const sg::net::Observation& signed_statement);
// "sg.chat.v7.roster.checkpoint" | call | tick | predecessor | roster: a function of the statement alone.
Bytes roster_checkpoint(const sg::net::Problem& p);
sg::net::Verify roster_verify(const CallId& call);
Roster checkpoint_roster(const Bytes& checkpoint);

// What a viewer holds: 64 pieces from `base`.
struct BufferMap {
    std::uint64_t base = 0;
    std::uint64_t bits = 0;
    bool has(std::uint64_t piece) const { return piece >= base && piece < base + 64 && (bits >> (piece - base)) & 1; }
};
Bytes encode(const BufferMap& m);
BufferMap decode_buffer_map(const Bytes& b);

// One viewer's part in the swarm: what it holds, what it asks for, whom.
class SwarmPeer {
public:
    SwarmPeer(std::string self, std::size_t stripes);
    void neighbours(std::vector<std::string> peers);
    const std::vector<std::string>& neighbours() const { return neighbours_; }
    // A piece it now holds (verified or not: the playback decides; it holds
    // only what it may give on - pieces named by a root).
    void hold(std::uint64_t piece);
    void drop(std::uint64_t piece) { held_.erase(piece); }  // what it held was refused: to be asked for again
    bool holds(std::uint64_t piece) const { return held_.count(piece) != 0; }
    BufferMap map() const;
    void heard(const std::string& peer, const BufferMap& m);
    // What to ask for now, and from whom: missing pieces from `from` up to
    // `until`, nearest first, then the rarest among neighbours; at most
    // `per_peer` waiting on any one neighbour. A question unanswered for
    // `patience_ms` is asked again, of another if one has it. (Times are
    // the caller's: this keeps no clock.)
    std::vector<std::pair<std::string, std::uint64_t>> wants(std::uint64_t from, std::uint64_t until, std::size_t per_peer,
                                                             double now_ms, double patience_ms = 500);
    void asked(const std::string& peer, std::uint64_t piece, double now_ms) { waiting_[peer][piece] = now_ms; }
    void answered(const std::string& peer, std::uint64_t piece);
    void forget_before(std::uint64_t piece);

private:
    std::string self_;
    std::size_t stripes_;
    std::vector<std::string> neighbours_;
    std::set<std::uint64_t> held_;
    std::map<std::string, BufferMap> maps_;
    std::map<std::string, std::map<std::uint64_t, double>> waiting_;  // peer -> piece -> when asked
    std::map<std::uint64_t, std::string> last_asked_;
};

// The forwarder of each stripe, planned by the engine's Placement over the
// call's state (its `stripe_<i>` participants and their constraints), by
// what each viewer on the roster can give. Viewers that only take are not
// available to it.
struct StripePlan {
    std::vector<std::string> forwarders;  // by stripe
    std::uint64_t generation = 0;
    bool feasible = false;
};
StripePlan plan_stripes(const sg::State& call, const sg::net::Cellular& cellular, const Roster& roster,
                        const sg::net::Digest& receipt, std::uint64_t epoch, std::uint64_t last_placement_epoch);

}  // namespace chat
