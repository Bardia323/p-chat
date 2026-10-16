// Files, pictures, voice notes, videos and stickers (protocol 3).
//
// A file is encrypted on the sending device under a key of its own, in
// 64 KiB chunks, each sealed (XChaCha20-Poly1305) with its index and
// whether it is the last in its associated data: a chunk cannot be moved,
// dropped or the file cut short without it showing. The message that
// carries a file holds only its reference - the blob's random id, its key,
// the hash of what it is, its type and size, and a tiny picture - so the
// conversation's history stays small and signed.
//
// The chunks travel apart from the message: pulled from a device that has
// them over the engine's live link (a `blob` channel on the Reliable lane,
// one chunk a frame), or, for a device that takes mail, left at the relay in
// padded pieces of three chunks (envelope version 17), at mailbox ids only
// the conversation can name.
#pragma once
#include "chat/Seal.hpp"
#include <optional>

namespace chat {

constexpr std::size_t chunk_size = 65536;
constexpr std::uint64_t max_file = 100ull * 1024 * 1024;
constexpr std::size_t chunk_overhead = 16;
constexpr std::uint32_t chunks_per_piece = 3;
constexpr std::size_t max_thumbnail = 12 * 1024;

enum class FileKind : std::uint8_t { File = 0, Image = 1, Video = 2, Voice = 3, Sticker = 4 };
struct FileRef {
    Key32 blob{};      // random; for a sticker, the sticker's own hash
    Key32 key{};       // the file key (zero for a sticker of a shared pack)
    Key32 hash{};      // BLAKE2b-256 of the plaintext
    std::string mime;  // at most 128 bytes
    std::uint64_t size = 0;
    FileKind kind = FileKind::File;
    std::string name;  // at most 256 bytes of UTF-8
    std::uint32_t duration_ms = 0;  // voice and video
    std::uint16_t width = 0, height = 0;
    Bytes thumbnail;   // a tiny picture (JPEG/WebP), at most 12 KiB
    Key32 pack{};      // a sticker's pack (content-addressed); zero otherwise
};
Bytes encode(const FileRef& f);
FileRef decode_file(const Bytes& b);

std::uint32_t chunk_count(std::uint64_t size);
// A chunk sealed: mac (16) | text, under the file key, its nonce made from
// the key, the blob and the index (never repeated: one key per file).
Bytes seal_chunk(const Key32& key, const Key32& blob, std::uint32_t index, std::uint32_t count, const Bytes& plain);
Bytes open_chunk(const Key32& key, const Key32& blob, std::uint32_t index, std::uint32_t count, const Bytes& sealed);

// BLAKE2b-256 over a stream, chunk by chunk.
class Hasher {
public:
    Hasher();
    ~Hasher();
    Hasher(const Hasher&) = delete;
    Hasher& operator=(const Hasher&) = delete;
    void update(const Bytes& b);
    Key32 final();

private:
    struct Impl;
    Impl* impl_;
};

// Pieces at the relay: where piece i of a blob waits, and what it is.
Key32 piece_mailbox(const Key32& conversation_secret, const Key32& blob, std::uint32_t piece);
std::uint32_t piece_count(std::uint32_t chunks);
// The envelope (version 17): u8 17 | mailbox | nonce (24) | AEAD(piece key,
// padded(u32 first | u16 n | n x long(sealed chunk))). The piece key is the
// file key's, so the relay holds nothing it can open.
Bytes piece_envelope(const Key32& mailbox, const Key32& key, const Key32& blob, std::uint32_t piece,
                     const std::vector<Bytes>& sealed_chunks, const std::array<std::uint8_t, 24>& nonce);
struct Piece {
    std::uint32_t first = 0;
    std::vector<Bytes> chunks;  // sealed
};
Piece open_piece(const Key32& key, const Key32& blob, std::uint32_t piece, const Bytes& envelope);
bool piece_size(std::size_t size);

// Frames on the live `blob` channel: a want (from a chunk on) and a chunk.
enum class BlobFrame : std::uint8_t { Want = 1, Chunk = 2 };
Bytes want_frame(const Key32& blob, std::uint32_t from);
Bytes chunk_frame(const Key32& blob, std::uint32_t index, std::uint32_t count, const Bytes& sealed);
struct Frame_ {
    BlobFrame kind = BlobFrame::Want;
    Key32 blob{};
    std::uint32_t index = 0, count = 0;
    Bytes sealed;
};
Frame_ decode_blob_frame(const Bytes& b);

// A data channel takes at most 256 KiB in one message. What is larger than
// `live_piece` goes in pieces, in order, on the reliable channel:
// u8 0xff | u32 id | u16 index | u16 count | bytes (at most 64 pieces, 8 MiB).
// What is smaller goes as it is (no envelope or blob frame begins with 0xff).
constexpr std::size_t live_piece = 131072;
std::vector<Bytes> live_pieces(const Bytes& whole, std::uint32_t id);
// One peer's channel, joined again: the whole once its last piece is in;
// a piece out of order drops what was begun.
struct LiveJoin {
    std::uint32_t id = 0;
    std::uint16_t count = 0, next = 0;
    Bytes have;
    std::optional<Bytes> take(const Bytes& message);
};

}  // namespace chat
