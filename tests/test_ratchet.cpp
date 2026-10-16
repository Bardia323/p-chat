// Phase 3b: the Double Ratchet. Two devices talk both ways from the moment
// they share a conversation; messages out of order open; a message key
// opens once; too far ahead is refused; the state survives being written
// out; and a sealed message without the ratchet is refused once it exists.
#include "check.hpp"
#include "vectors.hpp"
#include <random>

using namespace chat;

namespace {
// One side: the ratchet, and the private key of its current ratchet key
// (the browser keeps that one in WebCrypto).
struct Side_ {
    Ratchet r;
    Key32 secret;
};
struct Packet {
    Header h;
    Bytes wrapped;
    Key32 content;
};
Packet send(Side_& s, std::uint64_t seq, std::mt19937& rng) {
    const auto sent = ratchet_send(s.r);
    Key32 content{};
    for (auto& b : content) b = std::uint8_t(rng());
    Bytes ad = Writer("test").u64(seq).take();
    return {sent.header, wrap(sent.key, ad, content), content};
}
bool receive(Side_& s, const Packet& p, std::uint64_t seq, std::mt19937& rng) {
    std::optional<Turn> turn;
    Key32 fresh{};
    if (needs_turn(s.r, p.h)) {
        for (auto& b : fresh) b = std::uint8_t(rng());
        turn = Turn{x25519(s.secret, p.h.dh), x25519_public(fresh), x25519(fresh, p.h.dh)};
    }
    try {
        auto [next, mk] = ratchet_receive(s.r, p.h, turn);
        const auto got = unwrap(mk, Writer("test").u64(seq).take(), p.wrapped);
        if (got != p.content) return false;
        // Kept only now that the message was authentic.
        s.r = decode_ratchet(encode(next));
        if (turn) s.secret = fresh;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}
}  // namespace

int main() {
    std::mt19937 rng(7);
    const auto A = vectors::owner(), F = vectors::friend1();
    const auto aid = device_id(A.device), fid = device_id(F.device);
    const auto secret = vectors::fill(0xa1);
    const auto ss = x25519(A.secret, F.device.agree);
    CHECK(ss == x25519(F.secret, A.device.agree));
    const auto seed = ratchet_seed(secret, ss, aid, fid);
    CHECK(seed == ratchet_seed(secret, ss, fid, aid));
    const bool a_first = first_of(aid, fid);
    CHECK(a_first != first_of(fid, aid));
    CHECK_THROWS(first_of(aid, aid));

    const auto start = [&](Side_& first, Side_& second, const vectors::Keys& fk, const vectors::Keys& sk) {
        first.r = start_first(seed, fk.device.agree, sk.device.agree, ss);
        first.secret = fk.secret;
        const auto fresh = vectors::fill(0xd1);
        second.r = start_second(seed, sk.device.agree, fk.device.agree, ss, x25519_public(fresh), x25519(fresh, fk.device.agree));
        second.secret = fresh;
    };
    Side_ a, f;
    if (a_first) start(a, f, A, F); else start(f, a, F, A);

    // Either may speak first.
    {
        Side_ a2 = a, f2 = f;
        auto p = send(a2, 1, rng);
        CHECK(receive(f2, p, 1, rng));
        Side_ a3 = a, f3 = f;
        auto q = send(f3, 1, rng);
        CHECK(receive(a3, q, 1, rng));
    }

    // A long exchange, both ways, with turns, out of order within each burst.
    std::uint64_t seq = 0;
    for (int round = 0; round < 40; ++round) {
        auto& from = round % 3 == 2 ? a : (round % 2 ? f : a);
        auto& to = &from == &a ? f : a;
        std::vector<std::pair<Packet, std::uint64_t>> burst;
        const int n = 1 + int(rng() % 6);
        for (int i = 0; i < n; ++i) burst.emplace_back(send(from, ++seq, rng), seq);
        std::shuffle(burst.begin(), burst.end(), rng);
        for (const auto& [p, s] : burst) CHECK_MSG(receive(to, p, s, rng), "round " + std::to_string(round));
    }

    // A message key opens once: the same packet again is refused.
    {
        auto p = send(a, ++seq, rng);
        CHECK(receive(f, p, seq, rng));
        CHECK(!receive(f, p, seq, rng));
    }
    // Skipped keys wait; an old one opens later, once.
    {
        auto p1 = send(f, ++seq, rng);
        const auto s1 = seq;
        auto p2 = send(f, ++seq, rng);
        CHECK(receive(a, p2, seq, rng));
        CHECK(a.r.skipped.size() >= 1);
        CHECK(receive(a, p1, s1, rng));
        CHECK(!receive(a, p1, s1, rng));
    }
    // Late from the chain before a turn still opens.
    {
        auto old = send(a, ++seq, rng);
        const auto s_old = seq;
        auto now = send(a, ++seq, rng);
        CHECK(receive(f, now, seq, rng));
        auto reply = send(f, ++seq, rng);
        CHECK(receive(a, reply, seq, rng));  // a turns
        auto after = send(a, ++seq, rng);
        CHECK(receive(f, after, seq, rng));  // f turns
        CHECK(receive(f, old, s_old, rng));  // the old chain's key was kept
    }
    // Too far ahead of a chain is refused, and the ratchet is as it was.
    {
        Side_ f2 = f;
        for (std::uint32_t i = 0; i < max_skip + 1; ++i) ratchet_send(f2.r);
        auto far = send(f2, ++seq, rng);
        const auto before = encode(a.r);
        CHECK(!receive(a, far, seq, rng));
        CHECK(encode(a.r) == before);
    }
    // A tampered wrap does not open, and does not move the ratchet.
    {
        auto p = send(f, ++seq, rng);
        auto bad = p;
        bad.wrapped[5] ^= 1;
        const auto before = encode(a.r);
        CHECK(!receive(a, bad, seq, rng));
        CHECK(encode(a.r) == before);
        CHECK(receive(a, p, seq, rng));
    }
    // A header that needs a turn is refused without one.
    {
        auto p = send(a, ++seq, rng);
        Side_ f2 = f;
        auto q = send(f2, ++seq, rng);
        (void)p;
        Header made_up = q.h;
        made_up.dh = vectors::fill(0x99);
        CHECK(needs_turn(a.r, made_up));
        CHECK_THROWS(ratchet_receive(a.r, made_up, std::nullopt));
    }
    // The skipped keys are bounded.
    {
        Side_ a2 = a, f2 = f;
        std::vector<Packet> held;
        for (int turn = 0; turn < 4; ++turn) {
            for (std::uint32_t i = 0; i < 900; ++i) held.push_back(send(f2, ++seq, rng));
            auto last = send(f2, ++seq, rng);
            CHECK(receive(a2, last, seq, rng));
            auto back = send(a2, ++seq, rng);
            CHECK(receive(f2, back, seq, rng));
        }
        CHECK(a2.r.skipped.size() <= max_kept);
    }
    // The state is written out and read back whole; a damaged one is refused.
    CHECK(encode(decode_ratchet(encode(a.r))) == encode(a.r));
    {
        auto b = encode(a.r);
        b.push_back(0);
        CHECK_THROWS(decode_ratchet(b));
        b.pop_back();
        b.pop_back();
        CHECK_THROWS(decode_ratchet(b));
    }
    // Version 1 is refused once a ratchet exists.
    CHECK(!accepts(Version::Sealed, true) && accepts(Version::Ratchet, true) && !accepts(Version::Ratchet, false));
    return sgchat_test::finish("sgchat_ratchet");
}
