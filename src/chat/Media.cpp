#include "chat/Media.hpp"
#include "chat/Crypto.hpp"
#include <monocypher.h>

namespace chat {

namespace {
Nonce derived_nonce(const Key32& key, const std::string& purpose, const Key32& blob, std::uint32_t index) {
    const auto h = blake2b(24, Bytes(key.begin(), key.end()), Writer("sg.chat.v3." + purpose).raw(blob).u32(index).data());
    Nonce n{};
    std::copy(h.begin(), h.end(), n.begin());
    return n;
}
Bytes chunk_ad(const Key32& blob, std::uint32_t index, std::uint32_t count) {
    return Writer("sg.chat.v3.chunk").raw(blob).u32(index).u32(count).take();
}
Key32 piece_key(const Key32& key) { return blake2b256(key, Writer("sg.chat.v3.piece.key").data()); }
}  // namespace

Bytes encode(const FileRef& f) {
    if (f.mime.size() > 128 || f.name.size() > 256 || f.thumbnail.size() > max_thumbnail || f.size > max_file)
        throw Refused("chat: a file reference out of bounds");
    Writer w;
    w.u8(3).raw(f.blob).raw(f.key).raw(f.hash).short_text(f.mime).u64(f.size).u8(std::uint8_t(f.kind));
    w.short_text(f.name).u32(f.duration_ms).u16(f.width).u16(f.height).short_bytes(f.thumbnail).raw(f.pack);
    return w.take();
}
FileRef decode_file(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 3) throw Refused("chat: unknown file reference version");
    FileRef f;
    f.blob = r.key();
    f.key = r.key();
    f.hash = r.key();
    f.mime = r.short_text(128);
    f.size = r.u64();
    const auto kind = r.u8();
    if (kind > 4) throw Refused("chat: unknown file kind");
    f.kind = FileKind(kind);
    f.name = r.short_text(256);
    f.duration_ms = r.u32();
    f.width = r.u16();
    f.height = r.u16();
    f.thumbnail = r.short_bytes(max_thumbnail);
    f.pack = r.key();
    r.end();
    if (f.size > max_file) throw Refused("chat: a file over 100 MB");
    return f;
}

std::uint32_t chunk_count(std::uint64_t size) {
    if (size > max_file) throw Refused("chat: a file over 100 MB");
    return size == 0 ? 1 : std::uint32_t((size + chunk_size - 1) / chunk_size);
}
Bytes seal_chunk(const Key32& key, const Key32& blob, std::uint32_t index, std::uint32_t count, const Bytes& plain) {
    if (index >= count || plain.size() > chunk_size || (index + 1 < count && plain.size() != chunk_size))
        throw Refused("chat: a chunk out of place");
    return aead_lock(key, derived_nonce(key, "chunk.nonce", blob, index), chunk_ad(blob, index, count), plain);
}
Bytes open_chunk(const Key32& key, const Key32& blob, std::uint32_t index, std::uint32_t count, const Bytes& sealed) {
    if (index >= count || sealed.size() > chunk_size + chunk_overhead) throw Refused("chat: a chunk out of place");
    auto plain = aead_unlock(key, derived_nonce(key, "chunk.nonce", blob, index), chunk_ad(blob, index, count), sealed);
    if (index + 1 < count && plain.size() != chunk_size) throw Refused("chat: a short chunk before the last");
    return plain;
}

struct Hasher::Impl {
    crypto_blake2b_ctx ctx;
};
Hasher::Hasher() : impl_(new Impl) { crypto_blake2b_init(&impl_->ctx, 32); }
Hasher::~Hasher() {
    crypto_wipe(&impl_->ctx, sizeof impl_->ctx);
    delete impl_;
}
void Hasher::update(const Bytes& b) { crypto_blake2b_update(&impl_->ctx, b.data(), b.size()); }
Key32 Hasher::final() {
    Key32 out{};
    crypto_blake2b_final(&impl_->ctx, out.data());
    crypto_blake2b_init(&impl_->ctx, 32);
    return out;
}

Key32 piece_mailbox(const Key32& secret, const Key32& blob, std::uint32_t piece) {
    return blake2b256(secret, Writer("sg.chat.v3.piece").raw(blob).u32(piece).data());
}
std::uint32_t piece_count(std::uint32_t chunks) { return (chunks + chunks_per_piece - 1) / chunks_per_piece; }
bool piece_size(std::size_t size) {
    for (const auto b : buckets)
        if (size == 1 + 32 + 24 + 16 + b) return true;
    return false;
}
Bytes piece_envelope(const Key32& mailbox, const Key32& key, const Key32& blob, std::uint32_t piece,
                     const std::vector<Bytes>& chunks, const Nonce& nonce) {
    if (chunks.empty() || chunks.size() > chunks_per_piece) throw Refused("chat: a piece is 1..3 chunks");
    Writer w;
    w.u32(piece * chunks_per_piece).u16(std::uint16_t(chunks.size()));
    for (const auto& c : chunks) w.long_bytes(c, chunk_size + chunk_overhead);
    const auto ad = Writer("sg.chat.v3.piece").raw(blob).u32(piece).take();
    return Writer().u8(17).raw(mailbox).raw(nonce).raw(aead_lock(piece_key(key), nonce, ad, pad(w.take()))).take();
}
Piece open_piece(const Key32& key, const Key32& blob, std::uint32_t piece, const Bytes& envelope) {
    if (!piece_size(envelope.size()) || envelope[0] != 17) throw Refused("chat: not a piece");
    Reader r(envelope);
    r.u8();
    r.key();
    const auto nonce = r.fixed<24>();
    const auto ad = Writer("sg.chat.v3.piece").raw(blob).u32(piece).take();
    const auto plain = unpad(aead_unlock(piece_key(key), nonce, ad, r.raw(r.left())));
    Reader p(plain);
    Piece out;
    out.first = p.u32();
    if (out.first != piece * chunks_per_piece) throw Refused("chat: a piece out of place");
    const auto n = p.u16();
    if (n == 0 || n > chunks_per_piece) throw Refused("chat: a piece is 1..3 chunks");
    for (unsigned i = 0; i < n; ++i) out.chunks.push_back(p.long_bytes(chunk_size + chunk_overhead));
    p.end();
    return out;
}

Bytes want_frame(const Key32& blob, std::uint32_t from) {
    return Writer().u8(std::uint8_t(BlobFrame::Want)).raw(blob).u32(from).take();
}
Bytes chunk_frame(const Key32& blob, std::uint32_t index, std::uint32_t count, const Bytes& sealed) {
    return Writer().u8(std::uint8_t(BlobFrame::Chunk)).raw(blob).u32(index).u32(count).long_bytes(sealed, chunk_size + chunk_overhead).take();
}
Frame_ decode_blob_frame(const Bytes& b) {
    Reader r(b);
    Frame_ f;
    const auto k = r.u8();
    if (k != 1 && k != 2) throw Refused("chat: unknown blob frame");
    f.kind = BlobFrame(k);
    f.blob = r.key();
    f.index = r.u32();
    if (f.kind == BlobFrame::Chunk) {
        f.count = r.u32();
        f.sealed = r.long_bytes(chunk_size + chunk_overhead);
        if (f.index >= f.count || f.count > chunk_count(max_file)) throw Refused("chat: a chunk out of place");
    }
    r.end();
    return f;
}

std::vector<Bytes> live_pieces(const Bytes& whole, std::uint32_t id) {
    if (whole.size() <= live_piece) {
        if (!whole.empty() && whole[0] == 0xff) throw Refused("chat: a live message cannot begin with 0xff");
        return {whole};
    }
    const auto count = (whole.size() + live_piece - 1) / live_piece;
    if (count > 64) throw Refused("chat: too large to send live");
    std::vector<Bytes> out;
    for (std::size_t i = 0; i < count; ++i) {
        const auto from = i * live_piece, to = std::min(whole.size(), from + live_piece);
        out.push_back(Writer().u8(0xff).u32(id).u16(std::uint16_t(i)).u16(std::uint16_t(count))
                          .raw(Bytes(whole.begin() + std::ptrdiff_t(from), whole.begin() + std::ptrdiff_t(to))).take());
    }
    return out;
}
std::optional<Bytes> LiveJoin::take(const Bytes& m) {
    if (m.empty() || m[0] != 0xff) return m;
    Reader r(m);
    r.u8();
    const auto pid = r.u32();
    const auto index = r.u16(), n = r.u16();
    auto part = r.raw(r.left());
    if (n < 2 || n > 64 || index >= n || part.size() > live_piece) {
        have.clear(), next = 0;
        return std::nullopt;
    }
    if (index == 0) {
        id = pid, count = n, next = 0;
        have.clear();
    }
    if (pid != id || n != count || index != next) {
        have.clear(), next = 0, count = 0;
        return std::nullopt;
    }
    have.insert(have.end(), part.begin(), part.end());
    if (++next < count) return std::nullopt;
    Bytes whole;
    whole.swap(have);
    next = 0, count = 0;
    return whole;
}

}  // namespace chat
