#include "chat/Call.hpp"
#include "chat/Crypto.hpp"

namespace chat {

Key32 call_key(const Key32& secret, const CallId& call, std::uint64_t generation, const sg::net::Digest& roster) {
    return blake2b256(secret, Writer("sg.chat.v7.call.key").raw(call).u64(generation).raw(roster).data());
}

namespace {
Writer header_of(const ChunkHeader& h) {
    Writer w;
    w.u8(7).raw(h.call).raw(h.streamer).u64(h.generation).u64(h.sequence).u8(std::uint8_t(h.layer)).u8(h.key_frame ? 1 : 0).u64(h.captured_us);
    return w;
}
constexpr std::size_t header_size = 1 + 16 + 32 + 8 + 8 + 1 + 1 + 8;
}  // namespace

Bytes seal_chunk(const Key32& key, const ChunkHeader& h, const Nonce& nonce, const Bytes& media) {
    if (media.size() > 200000) throw Refused("chat: a chunk is at most 200000 bytes");
    const auto ad = header_of(h).take();
    return Writer().raw(ad).raw(nonce).raw(aead_lock(key, nonce, ad, media)).take();
}
ChunkHeader chunk_header(const Bytes& chunk) {
    Reader r(chunk);
    if (r.u8() != 7) throw Refused("chat: not a chunk");
    ChunkHeader h;
    h.call = r.fixed<16>();
    h.streamer = r.key();
    h.generation = r.u64();
    h.sequence = r.u64();
    const auto layer = r.u8();
    if (layer > 2) throw Refused("chat: unknown layer");
    h.layer = Layer(layer);
    const auto key_frame = r.u8();
    if (key_frame > 1) throw Refused("chat: a key frame is 0 or 1");
    h.key_frame = key_frame == 1;
    h.captured_us = r.u64();
    if (chunk.size() < header_size + 24 + 16) throw Refused("chat: a chunk cut short");
    return h;
}
Bytes open_chunk(const Key32& key, const Bytes& chunk) {
    chunk_header(chunk);
    const Bytes ad(chunk.begin(), chunk.begin() + std::ptrdiff_t(header_size));
    Reader r(chunk);
    r.raw(header_size);
    const auto nonce = r.fixed<24>();
    return aead_unlock(key, nonce, ad, r.raw(r.left()));
}
sg::net::Digest chunk_hash(const Bytes& chunk) { return blake2b256(Bytes{}, Writer("sg.chat.v7.call.chunk").raw(chunk).data()); }

Bytes Root::statement() const {
    if (hashes.size() > 1024) throw Refused("chat: a root names at most 1024 chunks");
    Writer w("sg.chat.v7.call.root");
    w.raw(call).raw(streamer).u8(std::uint8_t(layer)).u64(generation).u64(first).u16(std::uint16_t(hashes.size()));
    for (const auto& h : hashes) w.raw(h);
    return w.take();
}
Bytes encode(const Root& r) {
    Writer w;
    w.u8(7).raw(r.call).raw(r.streamer).u8(std::uint8_t(r.layer)).u64(r.generation).u64(r.first).u16(std::uint16_t(r.hashes.size()));
    for (const auto& h : r.hashes) w.raw(h);
    return w.raw(r.signature).take();
}
Root decode_root(const Bytes& b) {
    Reader rd(b);
    if (rd.u8() != 7) throw Refused("chat: not a root");
    Root r;
    r.call = rd.fixed<16>();
    r.streamer = rd.key();
    const auto layer = rd.u8();
    if (layer > 2) throw Refused("chat: unknown layer");
    r.layer = Layer(layer);
    r.generation = rd.u64();
    r.first = rd.u64();
    const auto n = rd.u16();
    if (n > 1024) throw Refused("chat: a root names at most 1024 chunks");
    for (unsigned i = 0; i < n; ++i) r.hashes.push_back(rd.key());
    r.signature = rd.fixed<64>();
    rd.end();
    return r;
}

Playback::Playback(CallId call, Key32 streamer, sg::net::PublicKey key, Layer layer, std::size_t keep)
    : call_(call), streamer_(streamer), key_(key), layer_(layer), keep_(keep) {}

std::string Playback::chunk(const Bytes& c) {
    ChunkHeader h;
    try {
        h = chunk_header(c);
    } catch (const std::exception&) {
        ++refused_;
        return "refused";
    }
    if (h.call != call_ || h.streamer != streamer_ || h.layer != layer_) {
        ++refused_;
        return "refused";
    }
    if (h.sequence < next_) return "late";
    const auto named = named_.find(h.sequence);
    if (named != named_.end()) {
        if (named->second != chunk_hash(c)) {
            ++refused_;
            return "refused";
        }
        held_[h.sequence] = {c};
        return "ready";
    }
    auto& candidates = held_[h.sequence];
    for (const auto& had : candidates)
        if (had == c) return "kept";
    if (candidates.size() >= 4) return "kept";  // enough to choose from: the root decides
    if (candidates.empty() && held_.size() > keep_) {
        held_.erase(h.sequence);
        held_.erase(std::prev(held_.end()));  // the furthest ahead goes first
        held_[h.sequence].push_back(c);
        return "kept";
    }
    candidates.push_back(c);
    return "kept";
}

bool Playback::root(const Root& r) {
    if (r.call != call_ || r.streamer != streamer_ || r.layer != layer_ || r.hashes.empty()) return false;
    if (!sg::net::check_signature(key_, r.statement(), r.signature)) return false;
    // A root never names again what one has named (a streamer cannot change
    // what it said a number was); one lost leaves a gap. The first a late
    // joiner sees is where its playing starts.
    if (r.first < rooted_) return false;
    if (rooted_ == 0 && named_.empty()) next_ = std::max(next_, r.first);
    for (std::size_t i = 0; i < r.hashes.size(); ++i) named_[r.first + i] = r.hashes[i];
    rooted_ = r.first + r.hashes.size();
    // What was kept and a root now names: the one it names stays, others are refused.
    for (auto it = held_.begin(); it != held_.end();) {
        const auto n = named_.find(it->first);
        if (n == named_.end()) {
            ++it;
            continue;
        }
        std::vector<Bytes> keep;
        for (auto& c : it->second) {
            if (n->second == chunk_hash(c)) keep.push_back(std::move(c));
            else ++refused_;
        }
        if (keep.empty()) {
            again_.push_back(it->first);
            it = held_.erase(it);
        } else {
            keep.resize(1);
            it->second = std::move(keep);
            ++it;
        }
    }
    while (named_.size() > keep_ * 2) named_.erase(named_.begin());
    return true;
}

std::vector<std::pair<std::uint64_t, Bytes>> Playback::take() {
    std::vector<std::pair<std::uint64_t, Bytes>> out;
    for (auto it = held_.begin(); it != held_.end() && it->first < next_;) it = held_.erase(it);
    for (auto it = held_.find(next_); it != held_.end() && named_.count(next_) && it->second.size() == 1 &&
                                      chunk_hash(it->second[0]) == named_.at(next_);
         it = held_.find(next_)) {
        out.emplace_back(next_, std::move(it->second[0]));
        held_.erase(it);
        ++next_;
    }
    return out;
}

std::optional<sg::net::Digest> Playback::named(std::uint64_t sequence) const {
    const auto n = named_.find(sequence);
    if (n == named_.end()) return std::nullopt;
    return n->second;
}

std::optional<Bytes> Playback::believed(std::uint64_t sequence) const {
    const auto n = named_.find(sequence);
    const auto h = held_.find(sequence);
    if (n == named_.end() || h == held_.end()) return std::nullopt;
    for (const auto& c : h->second)
        if (chunk_hash(c) == n->second) return c;
    return std::nullopt;
}

std::vector<std::uint64_t> Playback::take_refused() {
    std::vector<std::uint64_t> out;
    for (auto s : again_)
        if (s >= next_ && !held_.count(s)) out.push_back(s);
    again_.clear();
    return out;
}

std::uint64_t Playback::skip() {
    // The next believed chunk after a gap: what is missing before it is lost.
    for (const auto& [seq, c] : held_)
        if (seq > next_ && named_.count(seq) && c.size() == 1 && chunk_hash(c[0]) == named_.at(seq)) {
            const auto lost = seq - next_;
            next_ = seq;
            return lost;
        }
    return 0;
}

}  // namespace chat
