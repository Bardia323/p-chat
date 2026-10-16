// Phase 1: the protocol's bytes are the vectors' bytes, what is made opens,
// and what is malformed, truncated, oversize or forged is refused.
#include "check.hpp"
#include "vectors.hpp"
#include "chat/Push.hpp"

using namespace chat;

namespace {
template <class F>
bool refused(F f) {
    try { f(); } catch (const std::exception&) { return true; }
    return false;
}
Bytes flip(Bytes b, std::size_t at) {
    b[at] ^= 1;
    return b;
}
}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    // 1. Byte for byte, every vector.
    const auto made = vectors::compute();
    const auto kept = vectors::from_json(std::string(argv[1]) + "/v4.json");
    CHECK_MSG(made.size() == kept.size(), "the vector file has as many entries as are made");
    for (const auto& [k, v] : made) {
        const auto found = kept.find(k);
        CHECK_MSG(found != kept.end() && found->second == v, "vector " + k);
    }

    const auto A = vectors::owner(), F = vectors::friend1();
    const auto get = [&](const std::string& k) { return unhex(kept.at(k)); };

    // 2. The code: any case and spacing, prefixes of four; nothing else.
    CHECK(normalize_code(kept.at("code.words")) == kept.at("code.words"));
    CHECK(refused([] { normalize_code("abandon ability able about above"); }));
    CHECK(refused([] { normalize_code("abandon ability able about above zzzz"); }));
    CHECK(refused([] { normalize_code("abandon ability able about above abs"); }));
    CHECK(refused([] { normalize_code("abandon ability able about above absent!"); }));
    CHECK(words().size() == 2048 && emoji().size() == 256);

    // 3. The invite: round trip, and refusals.
    const auto inv = invite_from_fragment(kept.at("invite.fragment"));
    CHECK(encode(inv) == get("invite.bytes"));
    CHECK(refused([&] { decode_invite(Bytes(get("invite.bytes").begin(), get("invite.bytes").end() - 1)); }));
    CHECK(refused([&] { auto b = get("invite.bytes"); b.push_back(0); decode_invite(b); }));
    CHECK(refused([&] { auto i = inv; i.relay = "https://relay.example"; decode_invite(encode(i)); }));
    CHECK(refused([&] { auto i = inv; i.relay = "ws://relay.example:80"; decode_invite(encode(i)); }));
    CHECK(refused([&] { auto i = inv; i.relay = " "; decode_invite(encode(i)); }));
    {
        // Protocol 10: no relay at all - an invite given in person.
        auto i = inv;
        i.relay.clear();
        CHECK(decode_invite(encode(i)).relay.empty());
    }
    CHECK(refused([&] { invite_from_fragment("v2." + base64url(get("invite.bytes"))); }));
    CHECK(refused([] { from_base64url("AB=C"); }));

    // 4. The request opens for the owner and holds under the right code only.
    const auto pk = key_from(get("pair.key"));
    const auto req = decode_request(unpad(open("request", A.secret, get("request.box"))));
    CHECK(request_holds(pk, inv, req));
    CHECK(!request_holds(pair_key("abandon ability able about above absent", inv), inv, req));
    auto forged = req;
    forged.name = "Eve";
    CHECK(!request_holds(pk, inv, forged));
    CHECK(refused([&] { open("request", F.secret, get("request.box")); }));
    CHECK(refused([&] { open("accept", A.secret, get("request.box")); }));
    CHECK(refused([&] { open("request", A.secret, flip(get("request.box"), 100)); }));

    // 5. The accept: MAC under the pair key over the transcript, then the
    // owner's signature. A wrong code, another nonce, a changed body: refused.
    const auto acc = decode_accept(unpad(open("accept", F.secret, get("accept.box"))));
    CHECK(accept_holds(pk, inv, req, acc));
    CHECK(!accept_holds(pair_key("abandon ability able about above absent", inv), inv, req, acc));
    auto other_nonce = req;
    other_nonce.nonce[0] ^= 1;
    CHECK(!accept_holds(pk, inv, other_nonce, acc));
    auto changed = acc;
    changed.secret[0] ^= 1;
    CHECK(!accept_holds(pk, inv, req, changed));
    auto resigned = acc;  // a MAC still good, but not the owner's signature
    resigned.signature = F.sign(accept_statement(inv, req, acc));
    CHECK(!accept_holds(pk, inv, req, resigned));

    // 6. Padding and envelopes: three sizes only, nothing else.
    CHECK(pad(Bytes(1020)).size() == 1024 && pad(Bytes(1021)).size() == 16384);
    CHECK(refused([] { pad(Bytes(262141)); }));
    CHECK(refused([] { unpad(Bytes(1000)); }));
    CHECK(refused([] { auto p = pad(Bytes(10)); p[500] = 1; unpad(p); }));
    CHECK(refused([] { auto p = pad(Bytes(10)); p.resize(16384); unpad(p); }));
    const auto env = decode_envelope(get("envelope.v2"));
    CHECK(env.version == Version::Ratchet && encode(env) == get("envelope.v2"));
    CHECK(refused([&] { auto e = get("envelope.v2"); e.pop_back(); decode_envelope(e); }));
    CHECK(refused([&] { auto e = get("envelope.v2"); e[0] = 3; decode_envelope(e); }));
    CHECK(envelope_size(1 + 32 + seal_overhead + 1024) && !envelope_size(1 + 32 + seal_overhead + 1025));

    // 7. The message under the ratchet: the owner opens it, unwraps the
    // content key and reads "hello"; its signature is the friend's.
    const auto frame = decode_frame(unpad(open("message", A.secret, env.box)), Version::Ratchet, device_id(A.device));
    CHECK(frame.kind == FrameKind::Message);
    const auto& m = frame.message.message;
    check_message(m, acc.conversation, 0);
    CHECK(sg::net::check_signature(F.device.sign, m.statement(), m.signature));
    const auto owner_first = kept.at("ratchet.owner_first") == "1";
    auto receiver = decode_ratchet(get(owner_first ? "ratchet.first" : "ratchet.second"));
    CHECK(!needs_turn(receiver, frame.message.header) || owner_first);
    std::optional<Turn> turn;
    if (needs_turn(receiver, frame.message.header)) {
        const auto fresh = vectors::fill(0xe1);
        turn = Turn{x25519(A.secret, frame.message.header.dh), x25519_public(fresh), x25519(fresh, frame.message.header.dh)};
    }
    const auto [next, mk] = ratchet_receive(receiver, frame.message.header, turn);
    CHECK(hex(mk) == kept.at("ratchet.key"));
    const auto ck = unwrap(mk, wrap_ad(frame.message.sender, device_id(A.device), acc.conversation, m.sequence, m.id(), frame.message.header),
                           frame.message.wrapped);
    const auto content = open_content(ck, m);
    CHECK(std::string(content.body.begin(), content.body.end()) == "hello" && content.time_ms == 1700000000000ull);
    // The wrap is bound to its recipient: unwrapping as another device fails.
    CHECK(refused([&] {
        unwrap(mk, wrap_ad(frame.message.sender, device_id(vectors::friend2().device), acc.conversation, m.sequence, m.id(), frame.message.header),
               frame.message.wrapped);
    }));
    // ... and to its conversation and its sequence.
    CHECK(refused([&] {
        auto other = acc.conversation;
        other[0] ^= 1;
        unwrap(mk, wrap_ad(frame.message.sender, device_id(A.device), other, m.sequence, m.id(), frame.message.header), frame.message.wrapped);
    }));
    CHECK(refused([&] { decode_frame(unpad(open("message", A.secret, env.box)), Version::Ratchet, device_id(F.device)); }));
    // A message moved to another conversation does not check.
    CHECK(refused([&] { auto other = acc.conversation; other[1] ^= 1; check_message(m, other, 0); }));
    CHECK(refused([&] { check_message(m, acc.conversation, 1); }));

    // 8. Version 1 is a downgrade once a ratchet exists.
    const auto env1 = decode_envelope(get("envelope.v1"));
    CHECK(env1.version == Version::Sealed);
    CHECK(!accepts(Version::Sealed, true) && accepts(Version::Sealed, false) && accepts(Version::Ratchet, true));
    const auto f1 = decode_frame(unpad(open("message", A.secret, env1.box)), Version::Sealed, device_id(A.device));
    CHECK(f1.message.message.id() == m.id());

    // 9. Signaling: signed by its sender, and nothing else holds.
    auto sf = decode_signal(get("signal.bytes"));
    CHECK(signal_holds(sf, A.device.sign) && !signal_holds(sf, F.device.sign));
    sf.counter = 2;
    CHECK(!signal_holds(sf, A.device.sign));
    CHECK(refused([&] { auto b = get("signal.bytes"); b.push_back(0); decode_signal(b); }));
    CHECK(signal_unbox(acc.secret, get("signal.box")) == get("signal.bytes"));
    CHECK(refused([&] { auto other = acc.secret; other[0] ^= 1; signal_unbox(other, get("signal.box")); }));

    // 10. Fingerprints are the same from both ends.
    CHECK(fingerprint(device_id(A.device), device_id(F.device)) == fingerprint(device_id(F.device), device_id(A.device)));

    // 11. X25519 with a small-order key is refused, as WebCrypto refuses it.
    CHECK(refused([&] { x25519(A.secret, Key32{}); }));
    // Every release reads what the release before wrote: content of each
    // earlier protocol is taken; one from a protocol not yet made is not.
    for (std::uint8_t v = 1; v <= protocol_version; ++v) {
        const auto c = decode_content(Writer().u8(v).u64(42).long_bytes(Bytes{'h', 'i'}, 200000).take());
        CHECK_MSG(c.time_ms == 42 && c.body == Bytes({'h', 'i'}), "content of protocol " + std::to_string(v) + " is read");
    }
    CHECK(refused([] { decode_content(Writer().u8(std::uint8_t(protocol_version + 1)).u64(42).long_bytes(Bytes{}, 200000).take()); }));

    // Protocol 6: a push subscription reads back; not https, not a P-256
    // point, or one byte more, and it is refused.
    {
        const auto pi = decode_push_info(get("push.info"));
        CHECK(pi.endpoint == "https://push.example/send/abc" && hex(encode(pi)) == kept.at("push.info"));
        auto bad = pi;
        bad.endpoint = "http://push.example/x";
        CHECK(refused([&] { encode(bad); }));
        auto b2 = get("push.info");
        b2[2 + 1 + pi.endpoint.size()] = 2;  // p256dh's first byte: not uncompressed
        CHECK(refused([&] { decode_push_info(b2); }));
        auto b3 = get("push.info");
        b3.push_back(0);
        CHECK(refused([&] { decode_push_info(b3); }));
        CHECK(get("push.payload").size() == 68 && get("push.payload")[0] == 'p' && get("push.payload")[2] == '.');
    }
    return sgchat_test::finish("sgchat_vectors");
}
