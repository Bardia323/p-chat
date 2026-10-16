// v1 §5: files. Chunks open only in their place, under their key, and a file
// cut short, reordered or changed does not open; references and pieces read
// back as they were written; a file over 100 MB is refused.
#include "check.hpp"
#include "chat/Crypto.hpp"
#include "chat/Media.hpp"
#include <random>

using namespace chat;

int main() {
    std::mt19937 rng(5);
    Bytes file(200000);
    for (auto& b : file) b = std::uint8_t(rng());
    const auto key = random_key(), blob = random_key();
    const auto count = chunk_count(file.size());
    CHECK(count == 4 && chunk_count(0) == 1 && chunk_count(65536) == 1 && chunk_count(65537) == 2);
    CHECK_THROWS(chunk_count(max_file + 1));

    // Seal, hash, open: the same bytes.
    std::vector<Bytes> sealed;
    Hasher h;
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto from = std::size_t(i) * chunk_size, to = std::min(file.size(), from + chunk_size);
        const Bytes plain(file.begin() + std::ptrdiff_t(from), file.begin() + std::ptrdiff_t(to));
        h.update(plain);
        sealed.push_back(seal_chunk(key, blob, i, count, plain));
    }
    const auto hash = h.final();
    CHECK(hash == blake2b256(Bytes{}, file));
    Bytes back;
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto p = open_chunk(key, blob, i, count, sealed[i]);
        back.insert(back.end(), p.begin(), p.end());
    }
    CHECK(back == file);

    // Moved, cut short, under another key or blob, changed: refused.
    CHECK_THROWS(open_chunk(key, blob, 1, count, sealed[2]));               // reordered
    CHECK_THROWS(open_chunk(key, blob, 2, 3, sealed[2]));                   // the last made out of a middle one
    CHECK_THROWS(open_chunk(key, blob, 3, 5, sealed[3]));                   // a longer file claimed
    CHECK_THROWS(open_chunk(random_key(), blob, 0, count, sealed[0]));
    CHECK_THROWS(open_chunk(key, random_key(), 0, count, sealed[0]));
    {
        auto bad = sealed[1];
        bad[40] ^= 1;
        CHECK_THROWS(open_chunk(key, blob, 1, count, bad));
    }
    CHECK_THROWS(seal_chunk(key, blob, 0, count, Bytes(100)));              // a short chunk before the last

    // The reference.
    FileRef f;
    f.blob = blob;
    f.key = key;
    f.hash = hash;
    f.mime = "image/jpeg";
    f.size = file.size();
    f.kind = FileKind::Image;
    f.name = "café.jpg";
    f.width = 640;
    f.height = 480;
    f.thumbnail = Bytes(3000, 7);
    const auto ref = decode_file(encode(f));
    CHECK(ref.blob == f.blob && ref.key == f.key && ref.hash == f.hash && ref.mime == f.mime && ref.size == f.size &&
          ref.kind == f.kind && ref.name == f.name && ref.width == 640 && ref.thumbnail == f.thumbnail);
    {
        auto big = f;
        big.size = max_file + 1;
        CHECK_THROWS(encode(big));
        big = f;
        big.thumbnail = Bytes(max_thumbnail + 1);
        CHECK_THROWS(encode(big));
        auto b = encode(f);
        b.push_back(0);
        CHECK_THROWS(decode_file(b));
    }

    // Pieces at the relay: three chunks each, padded, opened only with the file key.
    const auto secret = random_key();
    CHECK(piece_count(count) == 2 && piece_count(1) == 1 && piece_count(3) == 1);
    Nonce n{};
    const auto env0 = piece_envelope(piece_mailbox(secret, blob, 0), key, blob, 0, {sealed[0], sealed[1], sealed[2]}, n);
    const auto env1 = piece_envelope(piece_mailbox(secret, blob, 1), key, blob, 1, {sealed[3]}, n);
    CHECK(piece_size(env0.size()) && piece_size(env1.size()) && env0.size() == 1 + 32 + 40 + 262144 && env1.size() == 1 + 32 + 40 + 16384);
    const auto p0 = open_piece(key, blob, 0, env0);
    CHECK(p0.first == 0 && p0.chunks.size() == 3 && p0.chunks[2] == sealed[2]);
    CHECK(open_piece(key, blob, 1, env1).chunks.at(0) == sealed[3]);
    CHECK_THROWS(open_piece(key, blob, 1, env0));                          // a piece out of place
    CHECK_THROWS(open_piece(random_key(), blob, 0, env0));
    CHECK(piece_mailbox(secret, blob, 0) != piece_mailbox(secret, blob, 1));

    // Frames on the live link.
    const auto w = decode_blob_frame(want_frame(blob, 2));
    CHECK(w.kind == BlobFrame::Want && w.blob == blob && w.index == 2);
    const auto c = decode_blob_frame(chunk_frame(blob, 3, count, sealed[3]));
    CHECK(c.kind == BlobFrame::Chunk && c.index == 3 && c.count == count && c.sealed == sealed[3]);
    CHECK_THROWS(decode_blob_frame(chunk_frame(blob, 4, 4, sealed[3])));
    // Live pieces: what a data channel cannot take whole goes in order, and
    // comes back whole; a piece missing or out of order drops what was begun.
    {
        Bytes big(300000);
        for (auto& b : big) b = std::uint8_t(rng());
        big[0] = 2;
        const auto ps = live_pieces(big, 7);
        CHECK(ps.size() == 3);
        for (const auto& p : ps) CHECK(p.size() <= 262144 - 64);
        LiveJoin j;
        CHECK(!j.take(ps[0]) && !j.take(ps[1]));
        const auto whole = j.take(ps[2]);
        CHECK(whole && *whole == big);
        LiveJoin k;
        CHECK(!k.take(ps[0]) && !k.take(ps[2]) && !k.take(ps[1]));  // out of order: nothing
        CHECK(k.take(Bytes{2, 3}) == Bytes({2, 3}));                 // small: as it is
        CHECK(live_pieces(Bytes{1, 2, 3}, 1).size() == 1);
        CHECK_THROWS(live_pieces(Bytes{0xff, 1}, 1));
        CHECK_THROWS(live_pieces(Bytes(live_piece * 64 + 1, 1), 1));
    }
    return sgchat_test::finish("sgchat_media");
}
