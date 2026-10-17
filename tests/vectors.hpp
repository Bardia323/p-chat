// The protocol's test vectors: fixed keys, fixed ephemerals and nonces,
// and every byte string the protocol makes from them. The native tool
// writes them (tools/make_vectors.cpp -> tests/vectors/v1.json); the native
// test and the browser test make them again and must match byte for byte.
//
// Private keys appear here only because these are test keys.
#pragma once
#include "chat/Crypto.hpp"
#include "chat/Group.hpp"
#include "chat/Media.hpp"
#include "chat/Identity.hpp"
#include "chat/Link.hpp"
#include "chat/Message.hpp"
#include "chat/Pairing.hpp"
#include "chat/Ratchet.hpp"
#include "chat/Recovery.hpp"
#include "chat/Push.hpp"
#include "chat/Swarm.hpp"
#include "chat/Seal.hpp"
#include "chat/Signal.hpp"
#include "chat/Trust.hpp"
#include <fstream>
#include <map>
#include <sstream>

namespace vectors {
using namespace chat;
using Out = std::vector<std::pair<std::string, std::string>>;

inline Key32 fill(std::uint8_t b) {
    Key32 k{};
    for (std::size_t i = 0; i < 32; ++i) k[i] = std::uint8_t(b + i);
    return k;
}
template <std::size_t N>
std::array<std::uint8_t, N> fill_n(std::uint8_t b) {
    std::array<std::uint8_t, N> a{};
    for (std::size_t i = 0; i < N; ++i) a[i] = std::uint8_t(b + i);
    return a;
}
struct Keys {
    Key32 seed, secret;
    Device device;
    Keys(std::uint8_t a, std::uint8_t b) : seed(fill(a)), secret(fill(b)) {
        sg::net::SigningKey k(seed);
        device.sign = k.public_key();
        device.agree = x25519_public(secret);
    }
    sg::net::Signature sign(const Bytes& m) const { return sg::net::SigningKey(seed).sign(m); }
};
inline Keys owner() { return Keys(0x01, 0x02); }
inline Keys friend1() { return Keys(0x03, 0x04); }
inline Keys friend2() { return Keys(0x05, 0x06); }

inline Out compute() {
    Out out;
    const auto put = [&](const std::string& k, const std::string& v) { out.emplace_back(k, v); };
    const auto A = owner(), F = friend1(), G = friend2();
    for (const auto& [name, k] : {std::pair<std::string, Keys>{"owner", A}, {"friend", F}, {"friend2", G}}) {
        put(name + ".seed", hex(k.seed));
        put(name + ".secret", hex(k.secret));
        put(name + ".sign", hex(k.device.sign));
        put(name + ".agree", hex(k.device.agree));
        put(name + ".id", hex(device_id(k.device)));
    }
    // The code.
    const auto random9 = Bytes{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    const auto code = make_code(random9);
    put("code.random", hex(random9));
    put("code.words", code);
    put("code.typed", "  ABAN, abil.  Able-abou above absent ");
    put("code.typed.normal", normalize_code("  ABAN, abil.  Able-abou above absent "));
    // The invite.
    Invite inv;
    inv.kind = InviteKind::Contact;
    inv.owner = A.device;
    inv.token = fill_n<16>(0x41);
    inv.secret = fill(0x51);
    inv.relay = "wss://relay.example/chat";
    put("invite.bytes", hex(encode(inv)));
    put("invite.fragment", invite_fragment(inv));
    const auto pk = pair_key(code, inv);
    put("pair.key", hex(pk));
    // The request.
    PairRequest req;
    req.device = F.device;
    req.nonce = fill_n<16>(0x61);
    req.name = "Ana";
    req.mac = request_mac(pk, inv, req);
    put("request.mac", hex(req.mac));
    put("request.statement", hex(request_statement(inv, req)));
    req.signature = F.sign(request_statement(inv, req));
    put("request.signature", hex(req.signature));
    put("request.bytes", hex(encode(req)));
    const auto req_box = seal("request", A.device.agree, pad(encode(req)), fill(0x71), fill_n<24>(0x81));
    put("request.box", hex(req_box));
    // The accept.
    PairAccept acc;
    acc.conversation = fill_n<16>(0x91);
    acc.secret = fill(0xa1);
    acc.owner_name = "Bardia";
    acc.members = {{A.device, Side::Owner}, {F.device, Side::Friend}};
    acc.mac = accept_mac(pk, inv, req, acc);
    put("accept.body", hex(accept_body(acc)));
    put("accept.mac", hex(acc.mac));
    put("accept.statement", hex(accept_statement(inv, req, acc)));
    acc.signature = A.sign(accept_statement(inv, req, acc));
    put("accept.signature", hex(acc.signature));
    put("accept.bytes", hex(encode(acc)));
    const auto acc_box = seal("accept", F.device.agree, pad(encode(acc)), fill(0x72), fill_n<24>(0x82));
    put("accept.box", hex(acc_box));
    put("accept.mailbox", hex(reply_mailbox(inv, device_id(F.device))));
    put("accept.envelope", hex(encode(Envelope{Version::PairReply, reply_mailbox(inv, device_id(F.device)), acc_box})));
    const auto fp = fingerprint(device_id(A.device), device_id(F.device));
    put("fingerprint", std::to_string(fp[0]) + "," + std::to_string(fp[1]) + "," + std::to_string(fp[2]) + "," +
                           std::to_string(fp[3]));
    // The committee and a message.
    const auto conv = acc.conversation;
    const auto committee = committee_of(conv, 0, acc.members);
    put("committee.id", hex(committee.id()));
    auto msg = make_message(conv, 0, device_id(F.device), 1, "text");
    msg.payload = seal_content(fill(0xb1), fill_n<24>(0xc1), msg, Content{1700000000000ull, Bytes{'h', 'e', 'l', 'l', 'o'}});
    put("message.payload", hex(msg.payload));
    put("message.statement", hex(msg.statement()));
    msg.signature = F.sign(msg.statement());
    put("message.signature", hex(msg.signature));
    put("message.id", hex(msg.id()));
    // The ratchet between the two, and the message under it.
    const auto ss = x25519(A.secret, F.device.agree);
    const auto aid = device_id(A.device), fid = device_id(F.device);
    const auto seed = ratchet_seed(acc.secret, ss, aid, fid);
    put("ratchet.static", hex(ss));
    put("ratchet.seed", hex(seed));
    const bool owner_first = first_of(aid, fid);
    put("ratchet.owner_first", owner_first ? "1" : "0");
    const auto fresh_secret = fill(0xd1);
    const auto first_keys = owner_first ? A : F, second_keys = owner_first ? F : A;
    auto first = start_first(seed, first_keys.device.agree, second_keys.device.agree, ss);
    auto second = start_second(seed, second_keys.device.agree, first_keys.device.agree, ss, x25519_public(fresh_secret),
                               x25519(fresh_secret, first_keys.device.agree));
    put("ratchet.first", hex(encode(first)));
    put("ratchet.second", hex(encode(second)));
    // The friend sends message 1 to the owner.
    auto& sender_state = owner_first ? second : first;
    const auto sent = ratchet_send(sender_state);
    put("ratchet.header", hex(encode(sent.header)));
    put("ratchet.key", hex(sent.key));
    const auto ad = wrap_ad(fid, aid, conv, 1, msg.id(), sent.header);
    const auto wrapped = wrap(sent.key, ad, fill(0xb1));
    put("ratchet.wrapped", hex(wrapped));
    MessageFrame frame;
    frame.sender = fid;
    frame.header = sent.header;
    frame.wrapped = wrapped;
    frame.message = msg;
    const auto frame_bytes = encode_frame(frame, Version::Ratchet, aid);
    put("frame.v2", hex(frame_bytes));
    const auto box2 = seal("message", A.device.agree, pad(frame_bytes), fill(0x73), fill_n<24>(0x83));
    const auto mb = mailbox(acc.secret, aid, 19000);
    put("mailbox.owner.19000", hex(mb));
    put("room", hex(room(acc.secret)));
    put("envelope.v2", hex(encode(Envelope{Version::Ratchet, mb, box2})));
    MessageFrame frame1;
    frame1.sender = fid;
    frame1.content_key = fill(0xb1);
    frame1.message = msg;
    const auto box1 = seal("message", A.device.agree, pad(encode_frame(frame1, Version::Sealed, aid)), fill(0x74), fill_n<24>(0x84));
    put("envelope.v1", hex(encode(Envelope{Version::Sealed, mb, box1})));
    // A history epoch over that message.
    const auto ctx = history_context(conv, committee, 0, {});
    put("history.context", hex(ctx.id()));
    const auto proposer = proposer_of(acc.members);
    put("history.proposer", proposer);
    const auto& pk_proposer = proposer == peer_of(A.device) ? A : F;
    const auto h = history_of({msg}, {});
    auto statement = history_statement(conv, ctx, proposer, h);
    put("history.statement", hex(statement.statement()));
    statement.signature = pk_proposer.sign(statement.statement());
    put("history.signature", hex(statement.signature));
    const auto problem = history_problem(ctx, statement);
    put("history.checkpoint", hex(history_checkpoint(problem)));
    put("history.epoch", hex(problem.epoch.id()));
    auto cert = certificate_for(problem, proposer);
    put("history.certificate", hex(cert.statement()));
    cert.signature = pk_proposer.sign(cert.statement());
    put("history.certificate.signature", hex(cert.signature));
    const auto verify = history_verify(conv);
    const auto verified = verify.proposal(problem, committee, proposal_for(cert));
    if (!verified) throw std::runtime_error("vectors: the proposal does not verify");
    auto vote = attestation_for(*verified, proposer);
    put("history.attestation", hex(vote.statement()));
    vote.signature = pk_proposer.sign(vote.statement());
    put("history.attestation.signature", hex(vote.signature));
    put("history.journal", hex(journal(committee, {}, 0, ctx.world, {}, {vote})));
    // A signaling frame.
    SignalFrame sf;
    sf.room = room(acc.secret);
    sf.from = aid;
    sf.to = fid;
    sf.counter = 1;
    sf.signal.lane = sg::net::DeliveryClass::Reliable;
    sf.signal.session = 0;
    sf.signal.kind = sg::net::IceSignalKind::Candidate;
    sf.signal.value = "candidate:1 1 udp 2122260223 192.0.2.1 54400 typ host";
    sf.signal.type = "0";
    put("signal.statement", hex(signal_statement(sf)));
    sf.signature = A.sign(signal_statement(sf));
    put("signal.bytes", hex(encode(sf)));
    put("signal.label.friend", hex(label(acc.secret, fid)));
    put("signal.box", hex(signal_box(acc.secret, fill_n<24>(0x85), encode(sf))));
    // Protocol 3: a file, a chunk of it, a piece of it at the relay.
    FileRef file;
    file.blob = fill(0xe1);
    file.key = fill(0xe2);
    file.hash = blake2b256(Bytes{}, Bytes(70000, 0x5a));
    file.mime = "application/octet-stream";
    file.size = 70000;
    file.kind = FileKind::File;
    file.name = "tape.bin";
    put("file.ref", hex(encode(file)));
    const auto c0 = seal_chunk(file.key, file.blob, 0, 2, Bytes(65536, 0x5a));
    const auto c1 = seal_chunk(file.key, file.blob, 1, 2, Bytes(70000 - 65536, 0x5a));
    put("file.chunk1", hex(c1));
    put("file.piece0", hex(piece_envelope(piece_mailbox(acc.secret, file.blob, 0), file.key, file.blob, 0, {c0, c1}, fill_n<24>(0x86))));
    // Protocol 4: a sender key, a message under it, a channel post, a group invite.
    SenderKey sk{fill(0xe3), fill(0xe4), 0};
    put("group.sender_key", hex(encode(sk)));
    auto stepped = sk;
    put("group.content_key", hex(sender_step(stepped)));
    const auto sframe = encode_frame(SenderFrame{fid, sk.id, 0, msg}, aid);
    put("group.frame", hex(sframe));
    put("channel.post", hex(channel_envelope(acc.secret, 19000, encode_frame(SenderFrame{fid, sk.id, 0, msg}, Key32{}), fill_n<24>(0x87))));
    GroupInvite gi;
    gi.group = fill_n<16>(0x95);
    gi.secret = fill(0xe5);
    gi.name = "Tapes club";
    gi.members = acc.members;
    put("group.invite", hex(encode(gi)));
    // Protocol 5: a recovery, its decision, an endorsement, a history item, options.
    Recovery rec;
    rec.conversation = gi.group;
    rec.generation = 1;
    rec.lost = fid;
    rec.replacement = acc.members.back();
    rec.scope = Scope::Since;
    rec.since_ms = 1700000000000ull;
    rec.not_before_ms = 1700086400000ull;
    rec.tick = 3;
    put("recovery.bytes", hex(encode(rec)));
    put("recovery.decision", hex(rec.decision()));
    auto end = recovery_endorsement(rec, hex(aid));
    end.signature = A.sign(end.statement());
    put("recovery.endorsement", hex(encode(end)));
    put("history.items", hex(encode(std::vector<HistoryItem>{{msg, fill(0xe6)}})));
    put("options.bytes", hex(encode(Options{true, 86400})));
    // Protocol 6: a subscription said to a conversation, and a push's payload.
    PushInfo pi;
    pi.endpoint = "https://push.example/send/abc";
    pi.p256dh = fill_n<65>(0x04);
    pi.auth = fill_n<16>(0xa1);
    pi.vapid_private = fill(0xa2);
    pi.vapid_public = fill_n<65>(0x04);
    put("push.info", hex(encode(pi)));
    put("push.payload", hex(push_payload(ping_id(gi.group, fid, 7), gi.group)));
    // Protocol 7: a call's chunk, its root, a roster, a buffer map.
    CallId call{};
    for (std::size_t i = 0; i < call.size(); ++i) call[i] = std::uint8_t(0xc0 + i);
    const auto ckey = call_key(fill(0xc1), call, 1, fill(0xc2));
    put("call.key", hex(ckey));
    const ChunkHeader ch{call, fid, 1, 5, Layer::Small, true, 123456};
    const auto chunk = seal_chunk(ckey, ch, fill_n<24>(0x88), Bytes(40, 0x5c));
    put("call.chunk", hex(chunk));
    Root root;
    root.call = call;
    root.streamer = fid;
    root.layer = Layer::Small;
    root.generation = 1;
    root.first = 5;
    root.hashes = {chunk_hash(chunk)};
    root.signature = F.sign(root.statement());
    put("call.root", hex(encode(root)));
    Roster roster;
    roster.call = call;
    roster.generation = 1;
    roster.viewers = {{acc.members.front().device, Capacity::Seed}};
    put("call.roster", hex(encode(roster)));
    put("call.buffer_map", hex(encode(BufferMap{64, 0x8000000000000001ull})));
    // Protocol 8: a stroke on a board (color 3, width 4, three points).
    put("board.stroke", hex(Writer().u8(8).u8(3).u8(4).u16(3).u16(0).u16(0).u16(1000).u16(65036).u16(32767).u16(32767).take()));
    // Protocol 11: linked devices - a Link invite, a chat given, a device
    // asked for, an unlink, a name, what a device has, its history given.
    auto link = inv;
    link.kind = InviteKind::Link;
    put("link.invite", hex(encode(link)));
    LinkedChat lc;
    lc.conversation = acc.conversation;
    lc.kind = Kind::Direct;
    lc.side = Side::Owner;
    lc.secret = acc.secret;
    lc.secret_generation = 0;
    lc.name = "Ana";
    lc.introduced = "Ana";
    lc.relay = "wss://relay.example/chat";
    lc.generation = 0;
    lc.members = acc.members;
    lc.disappear_s = 3600;
    put("link.chat", hex(encode(lc)));
    put("link.device_ask", hex(encode(DeviceAsk{true, {G.device, Side::Friend, true}})));
    put("link.unlink", hex(encode(Unlink{UnlinkWhat::SplitAsk, {acc.conversation}, {gi.group}})));
    put("link.name", hex(encode(LinkName{acc.conversation, "Ana (work)"})));
    LinkHave have;
    LinkHave::Chat hc;
    hc.conversation = acc.conversation;
    hc.generation = 1;
    hc.next_tick = 2;
    hc.older = true;
    hc.held[fid] = {{1, 7}, {9, 12}};
    have.chats.push_back(hc);
    put("link.have", hex(encode(have)));
    put("link.history", hex(encode(LinkHistory{acc.conversation, {{msg, fill(0xe6)}}})));
    return out;
}

// The file: one "name": "value" per line, in the order made.
inline std::string to_json(const Out& v) {
    std::ostringstream o;
    o << "{\n";
    for (std::size_t i = 0; i < v.size(); ++i)
        o << "  \"" << v[i].first << "\": \"" << v[i].second << "\"" << (i + 1 < v.size() ? "," : "") << "\n";
    o << "}\n";
    return o.str();
}
inline std::map<std::string, std::string> from_json(const std::string& path) {
    std::ifstream in(path);
    std::map<std::string, std::string> out;
    for (std::string line; std::getline(in, line);) {
        const auto a = line.find('"');
        if (a == std::string::npos) continue;
        const auto b = line.find('"', a + 1), c = line.find('"', b + 1), d = line.find('"', c + 1);
        out[line.substr(a + 1, b - a - 1)] = line.substr(c + 1, d - c - 1);
    }
    return out;
}
}  // namespace vectors
