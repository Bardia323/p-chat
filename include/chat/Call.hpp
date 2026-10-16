// Calls and streams (protocol 7): what travels and how it is believed.
//
// A call is a conversation's (its members, its committee). Its key is fresh
// for each generation of who is in it: a member that leaves never has the
// next one. Media is encoded by the browser (WebCodecs) into chunks; each
// chunk is sealed under the call key, bound to the call, its stream, its
// generation and its number, and goes on the Latest lane (late is lost, not
// waited for). Every so often - about once a second for a stream, every
// tenth of one for talk - the streamer signs a root: the list of the hashes
// of the chunks it sent since the last, with its device key. A chunk is
// played only once a root its streamer signed names its hash: a chunk
// injected by anyone else, or changed on the way, is never played, however
// well it is sealed (a member holds the key, and could seal one).
#pragma once
#include "chat/Trust.hpp"

#include <deque>

namespace chat {

using CallId = std::array<std::uint8_t, 16>;
enum class CallMode : std::uint8_t { Mesh = 0, Swarm = 1, Hybrid = 2 };
// A stream's layer: what a speaker sends twice (simulcast), full and small.
enum class Layer : std::uint8_t { Full = 0, Small = 1, Audio = 2 };

// The key of a generation of a call: from the call's secret (made by the one
// who started it, sent to members sealed like a message) and the roster
// that generation is (its digest), so two generations never share a key.
Key32 call_key(const Key32& call_secret, const CallId& call, std::uint64_t generation, const sg::net::Digest& roster);

struct ChunkHeader {
    CallId call{};
    Key32 streamer{};  // the device whose stream it is
    std::uint64_t generation = 0, sequence = 0;
    Layer layer = Layer::Full;
    bool key_frame = false;
    std::uint64_t captured_us = 0;  // on the streamer's clock, for latency only
};
// u8 7 | call | streamer | u64 generation | u64 sequence | u8 layer | u8 key frame | u64 captured
// | nonce(24) | AEAD(key, nonce, the header before the nonce, media)
Bytes seal_chunk(const Key32& key, const ChunkHeader& h, const Nonce& nonce, const Bytes& media);
ChunkHeader chunk_header(const Bytes& chunk);  // read, not yet believed
Bytes open_chunk(const Key32& key, const Bytes& chunk);
sg::net::Digest chunk_hash(const Bytes& chunk);

// The streamer's root: the hashes of its chunks of one layer from `first`
// on, in order. Each layer is a stream of its own (its own numbers, its own
// roots): a listener given one layer and not another never waits on it.
struct Root {
    CallId call{};
    Key32 streamer{};
    Layer layer = Layer::Full;
    std::uint64_t generation = 0, first = 0;
    std::vector<sg::net::Digest> hashes;
    sg::net::Signature signature{};
    Bytes statement() const;  // D("sg.chat.v7.call.root") | the fields before the signature
};
Bytes encode(const Root& r);
Root decode_root(const Bytes& b);

// One streamer's chunks, as a receiver holds them: kept until a root names
// them, played in order once it has, never before; refused if a root says
// another hash for their number. Until a root decides, a few different
// chunks for one number are kept (one injected first cannot shut out the
// real one). What waits is bounded (a stream that never sends a root fills
// no memory).
class Playback {
public:
    Playback(CallId call, Key32 streamer, sg::net::PublicKey key, Layer layer = Layer::Full, std::size_t keep = 512);
    // A chunk come in: "kept" (waits for its root), "ready" (named already),
    // "refused" (not this stream's, or a hash no root of it names) or "late".
    std::string chunk(const Bytes& chunk);
    // A root come in: true if its signature is the streamer's and it follows on.
    bool root(const Root& r);
    // The next chunks believed, in order (sequence, bytes), up to the first
    // that has not come or is not yet named.
    std::vector<std::pair<std::uint64_t, Bytes>> take();
    // Past a gap (the caller's jitter deadline is over): to the next believed
    // chunk; how many were lost (0: none ready beyond).
    std::uint64_t skip();
    std::uint64_t refused() const { return refused_; }
    // What a root this playback took says a number's hash is, if one has.
    std::optional<sg::net::Digest> named(std::uint64_t sequence) const;
    // The chunk held for a number that a root names, if it is here (not yet played).
    std::optional<Bytes> believed(std::uint64_t sequence) const;
    // The numbers whose chunks a root refused and that are not here now:
    // to be fetched again.
    std::vector<std::uint64_t> take_refused();
    std::uint64_t played() const { return next_; }

private:
    CallId call_;
    Key32 streamer_;
    sg::net::PublicKey key_;
    Layer layer_;
    std::size_t keep_;
    std::map<std::uint64_t, sg::net::Digest> named_;  // sequence -> hash, from roots
    std::map<std::uint64_t, std::vector<Bytes>> held_;  // sequence -> candidates (one once named), not yet played
    std::vector<std::uint64_t> again_;
    std::uint64_t next_ = 0, rooted_ = 0, refused_ = 0;
};

}  // namespace chat
