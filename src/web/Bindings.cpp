// The browser's way in: the App (chat/App.hpp) and the protocol's pieces,
// as JavaScript sees them. Bytes cross as Uint8Array, copied each way. No
// private key ever crosses: WebCrypto keeps them, and only what one
// operation needs (a shared secret, a signature) comes in.
//
// The live path is the engine's WebRtcTransport (Reliable lane), whose
// signals the App signs and seals before the relay carries them.
#include "chat/App.hpp"
#include "chat/Crypto.hpp"
#include "chat/Media.hpp"
#include "chat/Window.hpp"
#include "sg/web/WebRtc.hpp"
#include <emscripten/bind.h>
#include <map>
#include <emscripten/val.h>

using emscripten::val;
using namespace chat;

namespace {
Bytes bytes(const val& v) {
    Bytes b(v["length"].as<unsigned>());
    if (!b.empty()) val(emscripten::typed_memory_view(b.size(), b.data())).call<void>("set", v);
    return b;
}
val u8(const std::uint8_t* p, std::size_t n) {
    return val::global("Uint8Array").new_(emscripten::typed_memory_view(n, p));
}
val u8(const Bytes& b) { return u8(b.data(), b.size()); }
template <std::size_t N>
val u8(const std::array<std::uint8_t, N>& a) { return u8(a.data(), N); }
Key32 key(const val& v) { return key_from(bytes(v)); }
[[noreturn]] void fail(const std::exception& e) { val::global("Error").new_(std::string(e.what())).throw_(); }
template <class F>
auto guard(F f) -> decltype(f()) {
    try {
        return f();
    } catch (const std::exception& e) {
        fail(e);
    }
}

// The engine's browser transport, as the App's live path.
struct WebLive final : App::Live {
    sg::web::WebRtcTransport transport;
    explicit WebLive(sg::net::IceConfig c) : transport(std::move(c)) {}
    void connect(const std::string& peer) override { transport.connect(peer); }
    bool connected(const std::string& peer) override { return transport.telemetry(peer).connected; }
    // Larger than a data channel takes: in pieces, joined again on arrival.
    std::uint32_t pieces_sent = 0;
    std::map<std::pair<std::string, std::string>, LiveJoin> joining;
    bool send(const std::string& peer, const std::string& channel, const Bytes& bytes) override {
        for (const auto& p : live_pieces(bytes, ++pieces_sent))
            if (transport.send({peer, channel, sg::net::DeliveryClass::Reliable, {}, p}) != sg::net::SendResult::Accepted) return false;
        return true;
    }
    // A call's chunk: on the Latest lane, small enough to go whole.
    bool send_latest(const std::string& peer, const std::string& channel, const std::string& slot, const Bytes& bytes) override {
        if (bytes.size() > live_piece) return false;
        return transport.send({peer, channel, sg::net::DeliveryClass::Latest, slot, bytes}) == sg::net::SendResult::Accepted;
    }
    bool receive(std::string& peer, std::string& channel, Bytes& bytes) override {
        sg::net::Inbound in;
        while (transport.try_receive(in)) {
            auto whole = joining[{in.peer, in.channel}].take(in.bytes);
            if (!whole) continue;
            peer = in.peer;
            channel = in.channel;
            bytes = std::move(*whole);
            return true;
        }
        return false;
    }
    std::vector<sg::net::IceSignal> signals() override { return transport.signals(); }
    void signal(const std::string& peer, const sg::net::IceSignal& s) override { transport.signal(peer, s); }
    void reconnect(const std::string& peer) override { transport.reconnect(peer); }
    void poll() override {
        transport.poll();
        transport.events();  // delivery uncertainty is met by acknowledgements and the mailbox
    }
};

class WebApp {
public:
    WebApp(std::string sign, std::string agree, std::string name) {
        guard([&] {
            Device d{key_from_hex(sign), key_from_hex(agree)};
            app_ = std::make_unique<App>(d, name);
            return 0;
        });
    }
    std::string peer() const { return app_->peer(); }
    void rename(std::string n) { guard([&] { app_->rename(n); return 0; }); }
    void live(val servers, bool relay_only) {
        guard([&] {
            sg::net::IceConfig c;
            c.peer = app_->peer();
            for (unsigned i = 0; i < servers["length"].as<unsigned>(); ++i) c.ice_servers.push_back(servers[i].as<std::string>());
            c.relay_only = relay_only;
            // Room for a burst (signals carried for contacts, a call's roots) taken
            // between two pumps: a Reliable link whose queue overflows is closed by
            // design, and with no relay a closed link may not come back.
            c.receive_messages = 8192;
            c.receive_bytes = 64u << 20;
            live_ = std::make_unique<WebLive>(c);
            app_->set_live(live_.get());
            return 0;
        });
    }

    void load(val record) { guard([&] { app_->load(bytes(record)); return 0; }); }
    void replay(std::string c, val obs, val body, double time) {
        guard([&] { app_->replay(c, bytes(obs), bytes(body), std::uint64_t(time)); return 0; });
    }
    void start() { guard([&] { app_->start(); return 0; }); }
    val conversations() const {
        val out = val::array();
        for (const auto& c : app_->conversations()) out.call<void>("push", c);
        return out;
    }
    val save(std::string c) const { return guard([&] { return u8(app_->save(c)); }); }
    val take_dirty() {
        val out = val::array();
        for (const auto& c : app_->take_dirty()) out.call<void>("push", c);
        return out;
    }
    void pump(double now) { guard([&] { app_->pump(std::uint64_t(now)); return 0; }); }

    val take_starts() {
        val out = val::array();
        for (const auto& s : app_->take_starts()) {
            val o = val::object();
            o.set("conversation", s.conversation);
            o.set("peer", s.peer);
            o.set("agree", u8(s.agree));
            o.set("second", s.second);
            out.call<void>("push", o);
        }
        return out;
    }
    void started(std::string c, std::string peer, val ss, val fresh, val fresh_shared) {
        guard([&] {
            if (fresh.isNull() || fresh.isUndefined()) app_->started(c, peer, key(ss));
            else app_->started(c, peer, key(ss), key(fresh), key(fresh_shared));
            return 0;
        });
    }
    val take_signs() {
        val out = val::array();
        for (const auto& s : app_->take_signs()) {
            val o = val::object();
            o.set("id", double(s.id));
            o.set("statement", u8(s.statement));
            out.call<void>("push", o);
        }
        return out;
    }
    void signed_(double id, val sig) {
        guard([&] {
            const auto b = bytes(sig);
            if (b.size() != 64) throw Refused("chat: a signature is 64 bytes");
            sg::net::Signature s{};
            std::copy(b.begin(), b.end(), s.begin());
            app_->signed_(std::uint64_t(id), s);
            return 0;
        });
    }
    val take_outgoing() {
        val out = val::array();
        for (const auto& g : app_->take_outgoing()) {
            val o = val::object();
            o.set("kind", g.kind);
            o.set("conversation", g.conversation);
            o.set("peer", g.peer);
            o.set("purpose", g.purpose);
            o.set("agree", u8(g.agree));
            o.set("mailbox", u8(g.mailbox));
            o.set("room", u8(g.room));
            o.set("label", u8(g.label));
            o.set("version", int(g.version));
            o.set("plain", u8(g.plain));
            o.set("box", u8(g.box));
            o.set("token", u8(g.token));
            o.set("sequence", double(g.sequence));
            o.set("live", g.live);
            o.set("mailbox_ok", g.mailbox_ok);
            o.set("ping", g.ping);
            out.call<void>("push", o);
        }
        return out;
    }
    val take_notices() {
        val out = val::array();
        for (const auto& n : app_->take_notices()) {
            val o = val::object();
            o.set("kind", n.kind);
            o.set("conversation", n.conversation);
            o.set("peer", n.peer);
            o.set("text", n.text);
            o.set("sequence", double(n.sequence));
            o.set("time", double(n.time));
            o.set("data", u8(n.data));
            o.set("body", u8(n.body));
            o.set("type", n.type);
            o.set("key", u8(n.key));
            out.call<void>("push", o);
        }
        return out;
    }

    void post(std::string c, std::string text, double time) { guard([&] { app_->post(c, text, std::uint64_t(time)); return 0; }); }
    void read(std::string c) { guard([&] { app_->read(c); return 0; }); }
    void rename_contact(std::string c, std::string n) { guard([&] { app_->rename_contact(c, n); return 0; }); }
    void set_delivery(std::string c, int mode) { guard([&] { app_->set_delivery(c, DeliveryMode(mode == 2 ? 2 : 1)); return 0; }); }
    void open_conversation(std::string c) { guard([&] { app_->open_conversation(c); return 0; }); }
    void close_conversation(std::string c) { guard([&] { app_->close_conversation(c); return 0; }); }
    void remove_contact(std::string c) { guard([&] { app_->remove_contact(c); return 0; }); }
    void revoke(std::string c, std::string device) { guard([&] { app_->revoke(c, key_from_hex(device)); return 0; }); }
    std::string create_group(std::string name, val contacts, int kind) {
        return guard([&] {
            std::vector<std::string> cs;
            for (unsigned i = 0; i < contacts["length"].as<unsigned>(); ++i) cs.push_back(contacts[i].as<std::string>());
            return app_->create_group(name, cs, kind == 2 ? Kind::Channel : Kind::Group);
        });
    }
    void add_to_group(std::string g, std::string contact) { guard([&] { app_->add_to_group(g, contact); return 0; }); }
    val open_post(val envelope) {
        return guard([&] {
            const auto r = app_->open_post(bytes(envelope));
            val o = val::object();
            o.set("status", r.status);
            o.set("conversation", r.conversation);
            o.set("why", r.why);
            return o;
        });
    }

    // What the UI draws: the conversation's state, read const from the engine.
    val info(std::string c) const {
        return guard([&] {
            const auto& s = app_->state(c);
            val o = val::object();
            o.set("name", app_->name_of(c));
            o.set("introduced", app_->introduced_as(c));
            o.set("mailbox", app_->delivery(c) == DeliveryMode::Mailbox);
            o.set("kind", int(app_->kind_of(c)));
            o.set("member", app_->member_here(c));
            o.set("unread", double(s.element("thread").params.get_or<std::int64_t>("unread", 0)));
            o.set("side", double(s.params().get_or<std::int64_t>("side", 0)));
            o.set("generation", double(app_->generation_of(c)));
            o.set("removed", app_->removed(c));
            const auto op = app_->options_of(c);
            o.set("recovery", !op.no_recovery);
            o.set("disappear", double(op.disappear_s));
            o.set("recovering", app_->recovery_state(c));
            val members = val::array();
            for (const auto& m : app_->members_of(c)) {
                val d = val::object();
                const auto id = device_id(m.device);
                d.set("peer", hex(id));
                d.set("side", int(m.side));
                d.set("self", hex(id) == app_->peer());
                d.set("mail", hex(id) != app_->peer() && app_->takes_mail(c, hex(id)));
                if (const auto* e = s.find(sg::Key(device_element(id)))) {
                    Window w{std::uint64_t(e->params.get_or<std::int64_t>("high", 0)),
                             std::uint64_t(e->params.get_or<std::int64_t>("seen", std::int64_t(window_full))),
                             std::uint64_t(e->params.get_or<std::int64_t>("lost", 0))};
                    val gaps = val::array();
                    for (auto g : missing(w)) gaps.call<void>("push", double(g));
                    d.set("missing", gaps);
                    d.set("lost", double(w.lost));
                    d.set("high", double(w.high));
                }
                members.call<void>("push", d);
            }
            o.set("members", members);
            return o;
        });
    }
    std::string current() const {
        const auto* s = app_->engine().current();
        return s ? s->id().str() : std::string();
    }
    // A device's own four pictures (a recovery's new device shows them; the
    // approvers compare).
    val fingerprint_of(std::string peer) const { return fingerprint_with_(peer, peer); }
    val fingerprint_with(std::string peer) const { return fingerprint_with_(app_->peer(), peer); }
    val fingerprint_with_(std::string a, std::string peer) const {
        return guard([&] {
            const auto f = fingerprint(key_from_hex(a), key_from_hex(peer));
            val o = val::array();
            for (int i : f) {
                val e = val::object();
                e.set("glyph", emoji()[std::size_t(i)].first);
                e.set("name", emoji()[std::size_t(i)].second);
                o.call<void>("push", e);
            }
            return o;
        });
    }

    // Pairing, the owner.
    val invite(int kind, std::string relay, std::string c) {
        return guard([&] {
            const auto inv = app_->invite(InviteKind(kind), relay, c);
            val o = val::object();
            o.set("fragment", invite_fragment(inv.invite));
            o.set("code", inv.code);
            o.set("token", u8(inv.invite.token));
            o.set("invite", u8(encode(inv.invite)));
            o.set("conversation", inv.conversation);
            o.set("kind", kind);
            return o;
        });
    }
    // A recovery invite: as an invite, with the lost device and the history given.
    val recovery_invite(std::string relay, std::string c, std::string lost, int scope, double since) {
        return guard([&] {
            const auto inv = app_->recovery_invite(relay, c, key_from_hex(lost), Scope(scope < 0 || scope > 2 ? 0 : scope),
                                                   std::uint64_t(since));
            val o = val::object();
            o.set("fragment", invite_fragment(inv.invite));
            o.set("code", inv.code);
            o.set("token", u8(inv.invite.token));
            o.set("invite", u8(encode(inv.invite)));
            o.set("conversation", inv.conversation);
            o.set("kind", int(InviteKind::Recovery));
            o.set("lost", lost);
            o.set("scope", scope);
            o.set("since", since);
            return o;
        });
    }
    void approve_recovery(std::string c) { guard([&] { app_->approve_recovery(c); return 0; }); }
    void refuse_recovery(std::string c) { guard([&] { app_->refuse_recovery(c); return 0; }); }
    std::string recovery_state(std::string c) const { return guard([&] { return app_->recovery_state(c); }); }
    void set_recovery_wait(double ms) { app_->set_recovery_wait(std::uint64_t(ms)); }
    void set_options(std::string c, bool no_recovery, double disappear_s) {
        guard([&] { app_->set_options(c, Options{no_recovery, std::uint32_t(disappear_s)}); return 0; });
    }
    void share_push(std::string c, val info) { guard([&] { app_->share_push(c, bytes(info)); return 0; }); }
    // Calls (protocol 7).
    std::string start_call(std::string c, int mode) { return guard([&] { return app_->start_call(c, CallMode(mode < 0 || mode > 2 ? 0 : mode)); }); }
    void join_call(std::string call, int capacity) {
        guard([&] { app_->join_call(call, Capacity(capacity < 0 || capacity > 2 ? 0 : capacity)); return 0; });
    }
    void leave_call(std::string call) { guard([&] { app_->leave_call(call); return 0; }); }
    void pick_full(std::string call, std::string speaker) { guard([&] { app_->pick_full(call, speaker); return 0; }); }
    // Releases (protocol 9).
    void post_release(std::string c, int what, val json) { guard([&] { app_->post_release(c, what, bytes(json)); return 0; }); }
    std::string release_seen(val keys, int quorum, double version, val hash, std::string signer, val sig) {
        return guard([&] {
            std::vector<std::string> ks;
            for (unsigned i = 0; i < keys["length"].as<unsigned>(); ++i) ks.push_back(keys[i].as<std::string>());
            const auto s = bytes(sig);
            if (s.size() != 64) throw Refused("chat: a signature is 64 bytes");
            sg::net::Signature signature{};
            std::copy(s.begin(), s.end(), signature.begin());
            return app_->release_seen(ks, std::uint32_t(quorum), std::uint64_t(version), key(hash), signer, signature);
        });
    }
    double release_forks() const { return double(app_->release_forks()); }
    bool send_release(std::string peer, val frame) { return guard([&] { return app_->send_release(peer, bytes(frame)); }); }
    bool send_carry(std::string peer, val frame) { return guard([&] { return app_->send_carry(peer, bytes(frame)); }); }
    val take_carry() {
        val out = val::array();
        for (const auto& [p, b] : app_->take_carry()) {
            val o = val::object();
            o.set("peer", p);
            o.set("frame", u8(b));
            out.call<void>("push", o);
        }
        return out;
    }
    val live_peers() const {
        val out = val::array();
        for (const auto& p : app_->live_peers()) out.call<void>("push", p);
        return out;
    }
    val take_release() {
        val out = val::array();
        for (const auto& [p, b] : app_->take_release()) {
            val o = val::object();
            o.set("peer", p);
            o.set("frame", u8(b));
            out.call<void>("push", o);
        }
        return out;
    }
    // Live state (protocol 8): tape tennis and the whiteboard.
    std::string start_game(std::string c) { return guard([&] { return app_->start_game(c); }); }
    void join_game(std::string g) { guard([&] { app_->join_game(g); return 0; }); }
    void leave_game(std::string g) { guard([&] { app_->leave_game(g); return 0; }); }
    void game_input(std::string g, int move) { guard([&] { app_->game_input(g, move); return 0; }); }
    val games() const {
        return guard([&] {
            val out = val::array();
            for (const auto& g : app_->games()) {
                val o = val::object();
                o.set("id", g.id);
                o.set("conversation", g.conversation);
                o.set("opponent", g.opponent);
                o.set("player", g.player);
                o.set("playing", g.playing);
                o.set("epoch", double(g.epoch));
                o.set("left", double(g.left_score));
                o.set("right", double(g.right_score));
                o.set("hits", double(g.hits));
                o.set("ballX", g.ball_x);
                o.set("ballY", g.ball_y);
                o.set("leftY", g.left_y);
                o.set("rightY", g.right_y);
                o.set("lead", double(g.lead));
                o.set("sent", double(g.sent));
                o.set("received", double(g.received));
                out.call<void>("push", o);
            }
            return out;
        });
    }
    void open_board(std::string c) { guard([&] { app_->open_board(c); return 0; }); }
    void close_board(std::string c) { guard([&] { app_->close_board(c); return 0; }); }
    void post_stroke(std::string c, val stroke, double time) { guard([&] { app_->post_stroke(c, bytes(stroke), std::uint64_t(time)); return 0; }); }
    void pen(std::string c, double x, double y, bool down, int color) { guard([&] { app_->pen(c, x, y, down, color); return 0; }); }
    void look(std::string c, double x, double y, double zoom) { guard([&] { app_->look(c, x, y, zoom); return 0; }); }
    void lead(std::string c, bool on) { guard([&] { app_->lead(c, on); return 0; }); }
    val board(std::string c) const {
        return guard([&] {
            const auto b = app_->board(c);
            val o = val::object();
            o.set("open", b.open);
            o.set("strokes", double(b.strokes));
            o.set("leader", b.leader);
            o.set("x", b.x);
            o.set("y", b.y);
            o.set("zoom", b.zoom);
            val pens = val::array();
            for (const auto& p : b.pens) {
                val q = val::object();
                q.set("peer", p.peer);
                q.set("x", p.x);
                q.set("y", p.y);
                q.set("down", p.down);
                q.set("color", p.color);
                pens.call<void>("push", q);
            }
            o.set("pens", pens);
            return o;
        });
    }
    val calls() const {
        return guard([&] {
            val out = val::array();
            for (const auto& k : app_->calls()) {
                val o = val::object();
                o.set("id", k.id);
                o.set("conversation", k.conversation);
                o.set("starter", k.starter);
                o.set("mode", int(k.mode));
                o.set("joined", k.joined);
                o.set("generation", double(k.generation));
                val in = val::array();
                for (const auto& p : k.in) in.call<void>("push", p);
                o.set("in", in);
                val fw = val::array();
                for (const auto& p : k.forwarders) fw.call<void>("push", p);
                o.set("forwarders", fw);
                o.set("sent", double(k.sent));
                o.set("played", double(k.played));
                o.set("refused", double(k.refused));
                o.set("roots", double(k.roots));
                out.call<void>("push", o);
            }
            return out;
        });
    }
    void send_media(std::string call, int layer, bool key_frame, double captured_us, val media) {
        guard([&] {
            app_->send_media(call, Layer(layer < 0 || layer > 2 ? 0 : layer), key_frame, std::uint64_t(captured_us), bytes(media));
            return 0;
        });
    }
    val take_media() {
        val out = val::array();
        for (const auto& m : app_->take_media()) {
            val o = val::object();
            o.set("call", m.call);
            o.set("streamer", m.streamer);
            o.set("sequence", double(m.sequence));
            o.set("captured", double(m.captured_us));
            o.set("layer", int(m.layer));
            o.set("key", m.key_frame);
            o.set("data", u8(m.data));
            out.call<void>("push", o);
        }
        return out;
    }
    void forget_said(std::string c, double seq) { guard([&] { app_->forget_said(c, std::uint64_t(seq)); return 0; }); }
    void share_history(std::string c, std::string peer, val items) {
        guard([&] {
            std::vector<HistoryItem> hs;
            for (unsigned i = 0; i < items["length"].as<unsigned>(); ++i)
                hs.push_back({observation_from(bytes(items[i]["obs"])), key(items[i]["key"])});
            app_->share_history(c, peer, hs);
            return 0;
        });
    }
    std::string take_request(val invite_bytes, std::string code, std::string c, val box, val shared, val extra) {
        return guard([&] {
            App::Inviting inv;
            inv.invite = decode_invite(bytes(invite_bytes));
            inv.code = code;
            inv.conversation = c;
            if (!extra.isNull() && !extra.isUndefined() && extra["lost"].isString()) {
                inv.lost = key_from_hex(extra["lost"].as<std::string>());
                inv.scope = Scope(extra["scope"].as<int>());
                inv.since_ms = std::uint64_t(extra["since"].as<double>());
            }
            return app_->take_request(inv, bytes(box), key(shared));
        });
    }
    // Pairing, the new device. What it asked is kept by the host (encrypted)
    // until the reply comes: the invite, the request and the pair key.
    val ask(std::string fragment, std::string code, std::string name, std::string call, bool mail) {
        return guard([&] {
            const auto a = app_->ask(invite_from_fragment(fragment), code, name, call, mail);
            val o = val::object();
            o.set("asking", u8(Writer().long_bytes(encode(a.invite), 4096).long_bytes(encode(a.request), 4096).raw(a.key).short_text(a.call).take()));
            o.set("mailbox", u8(reply_mailbox(a.invite, device_id(app_->self()))));
            o.set("token", u8(a.invite.token));
            o.set("relay", a.invite.relay);
            return o;
        });
    }
    std::string take_accept(val asking, val envelope, val shared) {
        return guard([&] {
            const auto b = bytes(asking);
            Reader r(b);
            Asking a;
            a.invite = decode_invite(r.long_bytes(4096));
            a.request = decode_request(r.long_bytes(4096));
            a.key = r.key();
            a.call = r.short_text(64);
            r.end();
            return app_->take_accept(a, bytes(envelope), key(shared));
        });
    }

    // What arrives.
    val open(val envelope, val shared, val turn) {
        return guard([&] {
            std::optional<Turn> t;
            if (!turn.isNull() && !turn.isUndefined()) t = Turn{key(turn["received"]), key(turn["fresh"]), key(turn["sent"])};
            const auto r = app_->open(bytes(envelope), key(shared), t);
            val o = val::object();
            o.set("status", r.status);
            o.set("conversation", r.conversation);
            o.set("why", r.why);
            o.set("own", u8(r.own));
            o.set("dh", u8(r.dh));
            return o;
        });
    }
    void signal_in(val room, val box) { guard([&] { app_->signal_in(key(room), bytes(box)); return 0; }); }
    val rooms_of(std::string c) const {
        return guard([&] {
            val out = val::array();
            for (const auto& [r, l] : app_->rooms_of(c)) {
                val o = val::object();
                o.set("room", u8(r));
                o.set("label", u8(l));
                out.call<void>("push", o);
            }
            return out;
        });
    }
    val rooms() const {
        val out = val::array();
        for (const auto& [r, l] : app_->rooms()) {
            val o = val::object();
            o.set("room", u8(r));
            o.set("label", u8(l));
            out.call<void>("push", o);
        }
        return out;
    }
    val mailboxes() const {
        val out = val::array();
        for (const auto& m : app_->mailboxes()) out.call<void>("push", u8(m));
        return out;
    }
    val mailboxes_of(std::string c) const {
        return guard([&] {
            val out = val::array();
            for (const auto& m : app_->mailboxes_of(c)) out.call<void>("push", u8(m));
            return out;
        });
    }
    val mailbox_on(std::string c, double day) const {
        return guard([&] { return u8(app_->mailbox_on(c, std::uint32_t(day))); });
    }
    val room_of(std::string c) const {
        return guard([&] {
            const auto [r, l] = app_->room_of(c);
            val o = val::object();
            o.set("room", u8(r));
            o.set("label", u8(l));
            return o;
        });
    }
    bool live_with(std::string peer) const { return app_->live_with(peer); }
    bool takes_mail(std::string c, std::string peer) const { return guard([&] { return app_->takes_mail(c, peer); }); }
    void post_file(std::string c, val ref, double time) { guard([&] { app_->post_file(c, bytes(ref), std::uint64_t(time)); return 0; }); }
    bool send_blob(std::string peer, val frame) { return guard([&] { return app_->send_blob(peer, bytes(frame)); }); }
    val take_blobs() {
        val out = val::array();
        for (const auto& [p, f] : app_->take_blobs()) {
            val o = val::object();
            o.set("peer", p);
            o.set("frame", u8(f));
            out.call<void>("push", o);
        }
        return out;
    }
    val piece_mailbox(std::string c, val blob, double piece) const {
        return guard([&] { return u8(app_->piece_mailbox_of(c, key(blob), std::uint32_t(piece))); });
    }
    void reconnect_live(std::string peer) { guard([&] { app_->reconnect_live(peer); return 0; }); }
    std::string describe(std::string c) const { return guard([&] { return app_->describe(c); }); }
    bool send_live(std::string peer, val envelope) { return guard([&] { return app_->send_live(peer, bytes(envelope)); }); }
    val take_live() {
        val out = val::array();
        for (const auto& e : app_->take_live()) out.call<void>("push", u8(e));
        return out;
    }

private:
    std::unique_ptr<App> app_;
    std::unique_ptr<WebLive> live_;
};

// The protocol's pieces, for sealing with a WebCrypto shared secret and for
// the vector checks (tests/test_browser.py).
val js_seal(std::string purpose, val agree, val plain, val ephemeral, val shared) {
    return guard([&] {
        const auto r = random_bytes(24);
        Nonce n{};
        std::copy(r.begin(), r.end(), n.begin());
        return u8(seal_with(purpose, key(shared), key(ephemeral), key(agree), n, bytes(plain)));
    });
}
val js_seal_fixed(std::string purpose, val agree, val plain, val ephemeral, val shared, val nonce) {
    return guard([&] {
        Nonce n{};
        const auto b = bytes(nonce);
        if (b.size() != 24) throw Refused("chat: a nonce is 24 bytes");
        std::copy(b.begin(), b.end(), n.begin());
        return u8(seal_with(purpose, key(shared), key(ephemeral), key(agree), n, bytes(plain)));
    });
}
val js_open_box(std::string purpose, val shared, val recipient, val box) {
    return guard([&] { return u8(open_with(purpose, key(shared), key(recipient), bytes(box))); });
}
val js_envelope(int version, val mailbox_id, val box) {
    return guard([&] { return u8(encode(Envelope{Version(version), key(mailbox_id), bytes(box)})); });
}
val js_ephemeral_of(val env) { return guard([&] { return u8(App::ephemeral_of(bytes(env))); }); }
val js_device_id_of(val sign, val agree) { return guard([&] { return u8(device_id(Device{key(sign), key(agree)})); }); }
// Notifications: a subscription said to a conversation, and what a push carries.
val js_push_encode(val o) {
    return guard([&] {
        PushInfo p;
        p.endpoint = o["endpoint"].as<std::string>();
        const auto fill = [](auto& out, const Bytes& in) {
            if (in.size() != out.size()) throw Refused("chat: a push key of the wrong size");
            std::copy(in.begin(), in.end(), out.begin());
        };
        fill(p.p256dh, bytes(o["p256dh"]));
        fill(p.auth, bytes(o["auth"]));
        fill(p.vapid_private, bytes(o["vapidPrivate"]));
        fill(p.vapid_public, bytes(o["vapidPublic"]));
        return u8(encode(p));
    });
}
val js_push_decode(val b) {
    return guard([&] {
        const auto p = decode_push_info(bytes(b));
        val o = val::object();
        o.set("endpoint", p.endpoint);
        o.set("p256dh", u8(Bytes(p.p256dh.begin(), p.p256dh.end())));
        o.set("auth", u8(Bytes(p.auth.begin(), p.auth.end())));
        o.set("vapidPrivate", u8(Bytes(p.vapid_private.begin(), p.vapid_private.end())));
        o.set("vapidPublic", u8(Bytes(p.vapid_public.begin(), p.vapid_public.end())));
        return o;
    });
}
val js_push_payload(std::string conversation, std::string sender, double sequence) {
    return guard([&] {
        const auto raw = unhex(conversation);
        if (raw.size() != 16) throw Refused("chat: a conversation id is 16 bytes");
        ConversationId c{};
        std::copy(raw.begin(), raw.end(), c.begin());
        return u8(push_payload(ping_id(c, key_from_hex(sender), std::uint64_t(sequence)), c));
    });
}

// The engine's own statement for a release signature (web/release.js must
// write the very same bytes; the browser and Node checks hold it to them).
val js_release_statement(std::string signer, double version, val hash) {
    return guard([&] {
        sg::net::Observation o;
        o.peer = signer;
        o.context = key_from_hex("574c43b2f14b8293deb3fa1c3a83e477fd68b4acec22c0ed31785a0f14219ca1");
        o.tick = 0;
        o.sequence = std::uint64_t(version);
        o.object = "p-chat";
        o.parameter = "release";
        o.discrete = true;
        o.conflict = "release";
        o.payload = bytes(hash);
        return u8(o.statement());
    });
}

val js_parse_invite(std::string fragment) {
    return guard([&] {
        const auto i = invite_from_fragment(fragment);
        val o = val::object();
        o.set("kind", int(i.kind));
        o.set("relay", i.relay);
        o.set("owner", hex(device_id(i.owner)));
        o.set("token", u8(i.token));
        o.set("agree", u8(i.owner.agree));
        return o;
    });
}
std::string js_normalize(std::string typed) { return guard([&] { return normalize_code(typed); }); }
val js_blake2b_of(int size, val k, val data) { return guard([&] { return u8(blake2b(std::size_t(size), bytes(k), bytes(data))); }); }
val js_argon(std::string code, val salt, val ad) { return guard([&] { return u8(argon2id(code, bytes(salt), bytes(ad))); }); }
val js_aead_seal(val k, val nonce, val ad, val plain) {
    return guard([&] {
        const auto nb = bytes(nonce);
        Nonce n{};
        if (nb.size() != 24) throw Refused("chat: a nonce is 24 bytes");
        std::copy(nb.begin(), nb.end(), n.begin());
        return u8(aead_lock(key(k), n, bytes(ad), bytes(plain)));
    });
}
val js_aead_open(val k, val nonce, val ad, val sealed) {
    return guard([&] {
        const auto nb = bytes(nonce);
        Nonce n{};
        if (nb.size() != 24) throw Refused("chat: a nonce is 24 bytes");
        std::copy(nb.begin(), nb.end(), n.begin());
        return u8(aead_unlock(key(k), n, bytes(ad), bytes(sealed)));
    });
}
bool js_ed25519_check(val pub, val message, val sig) {
    return guard([&] {
        const auto s = bytes(sig);
        if (s.size() != 64) return false;
        sg::net::Signature sg_sig{};
        std::copy(s.begin(), s.end(), sg_sig.begin());
        return sg::net::check_signature(key(pub), bytes(message), sg_sig);
    });
}
val js_pad_frame(val frame) { return guard([&] { return u8(pad(bytes(frame))); }); }
val js_unpad_frame(val padded) { return guard([&] { return u8(unpad(bytes(padded))); }); }
val js_words_list() {
    val out = val::array();
    for (const auto& w : words()) out.call<void>("push", w);
    return out;
}
std::string js_hex_of(val b) { return hex(bytes(b)); }

// Files: chunks, the stream's hash, references, relay pieces, live frames.
double js_chunk_count(double size) { return guard([&] { return double(chunk_count(std::uint64_t(size))); }); }
val js_seal_chunk(val k, val blob, double index, double count, val plain) {
    return guard([&] { return u8(seal_chunk(key(k), key(blob), std::uint32_t(index), std::uint32_t(count), bytes(plain))); });
}
val js_open_chunk(val k, val blob, double index, double count, val sealed) {
    return guard([&] { return u8(open_chunk(key(k), key(blob), std::uint32_t(index), std::uint32_t(count), bytes(sealed))); });
}
class JsHasher {
public:
    void update(val b) { h_.update(bytes(b)); }
    val final() { return u8(h_.final()); }
private:
    Hasher h_;
};
val js_file_encode(val o) {
    return guard([&] {
        FileRef f;
        f.blob = key(o["blob"]);
        f.key = key(o["key"]);
        f.hash = key(o["hash"]);
        f.mime = o["mime"].as<std::string>();
        f.size = std::uint64_t(o["size"].as<double>());
        f.kind = FileKind(o["kind"].as<int>());
        f.name = o["name"].as<std::string>();
        f.duration_ms = std::uint32_t(o["duration"].as<double>());
        f.width = std::uint16_t(o["width"].as<int>());
        f.height = std::uint16_t(o["height"].as<int>());
        f.thumbnail = bytes(o["thumbnail"]);
        f.pack = key(o["pack"]);
        return u8(encode(f));
    });
}
val js_file_decode(val b) {
    return guard([&] {
        const auto f = decode_file(bytes(b));
        val o = val::object();
        o.set("blob", u8(f.blob));
        o.set("key", u8(f.key));
        o.set("hash", u8(f.hash));
        o.set("mime", f.mime);
        o.set("size", double(f.size));
        o.set("kind", int(f.kind));
        o.set("name", f.name);
        o.set("duration", double(f.duration_ms));
        o.set("width", int(f.width));
        o.set("height", int(f.height));
        o.set("thumbnail", u8(f.thumbnail));
        o.set("pack", u8(f.pack));
        o.set("count", double(chunk_count(f.size)));
        return o;
    });
}
val js_piece_envelope(val mailbox_id, val k, val blob, double piece, val chunks) {
    return guard([&] {
        std::vector<Bytes> cs;
        for (unsigned i = 0; i < chunks["length"].as<unsigned>(); ++i) cs.push_back(bytes(chunks[i]));
        const auto r = random_bytes(24);
        Nonce n{};
        std::copy(r.begin(), r.end(), n.begin());
        return u8(piece_envelope(key(mailbox_id), key(k), key(blob), std::uint32_t(piece), cs, n));
    });
}
val js_open_piece(val k, val blob, double piece, val env) {
    return guard([&] {
        const auto p = open_piece(key(k), key(blob), std::uint32_t(piece), bytes(env));
        val o = val::object();
        o.set("first", double(p.first));
        val cs = val::array();
        for (const auto& c : p.chunks) cs.call<void>("push", u8(c));
        o.set("chunks", cs);
        return o;
    });
}
val js_want_frame(val blob, double from) { return guard([&] { return u8(want_frame(key(blob), std::uint32_t(from))); }); }
val js_chunk_frame(val blob, double index, double count, val sealed) {
    return guard([&] { return u8(chunk_frame(key(blob), std::uint32_t(index), std::uint32_t(count), bytes(sealed))); });
}
val js_decode_blob_frame(val b) {
    return guard([&] {
        const auto f = decode_blob_frame(bytes(b));
        val o = val::object();
        o.set("kind", f.kind == BlobFrame::Want ? std::string("want") : std::string("chunk"));
        o.set("blob", u8(f.blob));
        o.set("index", double(f.index));
        o.set("count", double(f.count));
        o.set("sealed", u8(f.sealed));
        return o;
    });
}
}  // namespace

EMSCRIPTEN_BINDINGS(sgchat) {
    emscripten::class_<WebApp>("App")
        .constructor<std::string, std::string, std::string>()
        .function("peer", &WebApp::peer)
        .function("rename", &WebApp::rename)
        .function("live", &WebApp::live)
        .function("load", &WebApp::load)
        .function("replay", &WebApp::replay)
        .function("start", &WebApp::start)
        .function("conversations", &WebApp::conversations)
        .function("save", &WebApp::save)
        .function("takeDirty", &WebApp::take_dirty)
        .function("pump", &WebApp::pump)
        .function("takeStarts", &WebApp::take_starts)
        .function("started", &WebApp::started)
        .function("takeSigns", &WebApp::take_signs)
        .function("signed", &WebApp::signed_)
        .function("takeOutgoing", &WebApp::take_outgoing)
        .function("takeNotices", &WebApp::take_notices)
        .function("post", &WebApp::post)
        .function("read", &WebApp::read)
        .function("renameContact", &WebApp::rename_contact)
        .function("setDelivery", &WebApp::set_delivery)
        .function("openConversation", &WebApp::open_conversation)
        .function("closeConversation", &WebApp::close_conversation)
        .function("removeContact", &WebApp::remove_contact)
        .function("revoke", &WebApp::revoke)
        .function("createGroup", &WebApp::create_group)
        .function("addToGroup", &WebApp::add_to_group)
        .function("openPost", &WebApp::open_post)
        .function("info", &WebApp::info)
        .function("current", &WebApp::current)
        .function("fingerprintWith", &WebApp::fingerprint_with)
        .function("fingerprintOf", &WebApp::fingerprint_of)
        .function("invite", &WebApp::invite)
        .function("takeRequest", &WebApp::take_request)
        .function("recoveryInvite", &WebApp::recovery_invite)
        .function("approveRecovery", &WebApp::approve_recovery)
        .function("refuseRecovery", &WebApp::refuse_recovery)
        .function("recoveryState", &WebApp::recovery_state)
        .function("setRecoveryWait", &WebApp::set_recovery_wait)
        .function("setOptions", &WebApp::set_options)
        .function("forgetSaid", &WebApp::forget_said)
        .function("sharePush", &WebApp::share_push)
        .function("startCall", &WebApp::start_call)
        .function("joinCall", &WebApp::join_call)
        .function("leaveCall", &WebApp::leave_call)
        .function("pickFull", &WebApp::pick_full)
        .function("postRelease", &WebApp::post_release)
        .function("releaseSeen", &WebApp::release_seen)
        .function("releaseForks", &WebApp::release_forks)
        .function("sendRelease", &WebApp::send_release)
        .function("takeRelease", &WebApp::take_release)
        .function("sendCarry", &WebApp::send_carry)
        .function("takeCarry", &WebApp::take_carry)
        .function("livePeers", &WebApp::live_peers)
        .function("startGame", &WebApp::start_game)
        .function("joinGame", &WebApp::join_game)
        .function("leaveGame", &WebApp::leave_game)
        .function("gameInput", &WebApp::game_input)
        .function("games", &WebApp::games)
        .function("openBoard", &WebApp::open_board)
        .function("closeBoard", &WebApp::close_board)
        .function("postStroke", &WebApp::post_stroke)
        .function("pen", &WebApp::pen)
        .function("look", &WebApp::look)
        .function("lead", &WebApp::lead)
        .function("board", &WebApp::board)
        .function("calls", &WebApp::calls)
        .function("sendMedia", &WebApp::send_media)
        .function("takeMedia", &WebApp::take_media)
        .function("shareHistory", &WebApp::share_history)
        .function("ask", &WebApp::ask)
        .function("takeAccept", &WebApp::take_accept)
        .function("open", &WebApp::open)
        .function("signalIn", &WebApp::signal_in)
        .function("rooms", &WebApp::rooms)
        .function("mailboxes", &WebApp::mailboxes)
        .function("mailboxesOf", &WebApp::mailboxes_of)
        .function("roomOf", &WebApp::room_of)
        .function("roomsOf", &WebApp::rooms_of)
        .function("mailboxOn", &WebApp::mailbox_on)
        .function("sendLive", &WebApp::send_live)
        .function("liveWith", &WebApp::live_with)
        .function("takesMail", &WebApp::takes_mail)
        .function("postFile", &WebApp::post_file)
        .function("sendBlob", &WebApp::send_blob)
        .function("takeBlobs", &WebApp::take_blobs)
        .function("pieceMailbox", &WebApp::piece_mailbox)
        .function("reconnectLive", &WebApp::reconnect_live)
        .function("describe", &WebApp::describe)
        .function("takeLive", &WebApp::take_live);
    emscripten::function("seal", &js_seal);
    emscripten::function("sealFixed", &js_seal_fixed);
    emscripten::function("openBox", &js_open_box);
    emscripten::function("envelope", &js_envelope);
    emscripten::function("ephemeralOf", &js_ephemeral_of);
    emscripten::function("deviceId", &js_device_id_of);
    emscripten::function("parseInvite", &js_parse_invite);
    emscripten::function("releaseStatement", &js_release_statement);
    emscripten::function("pushEncode", &js_push_encode);
    emscripten::function("pushDecode", &js_push_decode);
    emscripten::function("pushPayload", &js_push_payload);
    emscripten::function("normalizeCode", &js_normalize);
    emscripten::function("blake2b", &js_blake2b_of);
    emscripten::function("argon2id", &js_argon);
    emscripten::function("aeadSeal", &js_aead_seal);
    emscripten::function("aeadOpen", &js_aead_open);
    emscripten::function("ed25519Check", &js_ed25519_check);
    emscripten::function("pad", &js_pad_frame);
    emscripten::function("unpad", &js_unpad_frame);
    emscripten::function("words", &js_words_list);
    emscripten::function("hex", &js_hex_of);
    emscripten::class_<JsHasher>("Hasher").constructor<>().function("update", &JsHasher::update).function("final", &JsHasher::final);
    emscripten::function("chunkCount", &js_chunk_count);
    emscripten::function("sealChunk", &js_seal_chunk);
    emscripten::function("openChunk", &js_open_chunk);
    emscripten::function("fileEncode", &js_file_encode);
    emscripten::function("fileDecode", &js_file_decode);
    emscripten::function("pieceEnvelope", &js_piece_envelope);
    emscripten::function("openPiece", &js_open_piece);
    emscripten::function("wantFrame", &js_want_frame);
    emscripten::function("chunkFrame", &js_chunk_frame);
    emscripten::function("decodeBlobFrame", &js_decode_blob_frame);
}
