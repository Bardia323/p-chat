// The messenger end to end, natively: devices whose host loop is played by
// this test (test keys for WebCrypto, a map for the relay), as web/session.js
// plays it in a browser. Pairing, a wrong code, messages both ways, acks,
// history epochs, saving and loading, a further device by handoff, revoking
// it, a message the relay drops, and the live path.
#include "check.hpp"
#include <random>
#include "chat/App.hpp"
#include "chat/Window.hpp"
#include "vectors.hpp"
#include <memory>

using namespace chat;

namespace {
struct Relay {
    std::map<Key32, std::vector<Bytes>> mailboxes;
    std::map<Token, std::vector<Bytes>> posts;
    std::set<Token> burned;
    bool drop_next = false;
    void put(const Bytes& envelope) {
        if (drop_next) { drop_next = false; return; }
        auto& box = mailboxes[key_from(Bytes(envelope.begin() + 1, envelope.begin() + 33))];
        if (std::find(box.begin(), box.end(), envelope) == box.end()) box.push_back(envelope);
    }
};

// One device: its keys (what WebCrypto holds), its App, what it kept.
struct Host {
    Key32 seed, secret;
    Device device;
    std::unique_ptr<App> app;
    std::map<std::string, Key32> ratchet_keys;  // public hex -> private
    std::map<std::string, Bytes> records;
    std::map<std::string, std::vector<std::tuple<Bytes, Bytes, std::uint64_t>>> kept;  // conversation -> messages
    std::vector<Notice> notices;
    std::map<std::string, std::vector<HistoryItem>> keyed;  // what could be given to a recovered device
    std::string name, call;
    bool mail = true;
    std::vector<std::tuple<std::string, std::string, Bytes>> waiting;
    Relay* relay;
    std::uint64_t now = 1700000000000ull;

    Host(std::uint8_t a, std::uint8_t b, std::string n, Relay* r) : seed(vectors::fill(a)), secret(vectors::fill(b)), name(n), relay(r) {
        device.sign = sg::net::SigningKey(seed).public_key();
        device.agree = x25519_public(secret);
        app = std::make_unique<App>(device, name);
        app->start();
    }
    Key32 private_of(const Key32& pub) const {
        if (pub == device.agree) return secret;
        return ratchet_keys.at(hex(pub));
    }
    Bytes seal_box(const std::string& purpose, const Key32& to, const Bytes& plain) const {
        const auto e = random_key();  // a WebCrypto key in a browser
        Nonce n{};
        const auto r = random_bytes(24);
        std::copy(r.begin(), r.end(), n.begin());
        return seal_with(purpose, x25519(e, to), x25519_public(e), to, n, plain);
    }
    // The host's loop: fill what is asked, keep what changed, carry what goes.
    void step() {
        for (int round = 0; round < 8; ++round) {
            app->pump(now);
            bool any = false;
            for (const auto& s : app->take_starts()) {
                any = true;
                const auto ss = x25519(secret, s.agree);
                if (s.second) {
                    const auto f = random_key();
                    ratchet_keys[hex(x25519_public(f))] = f;
                    app->started(s.conversation, s.peer, ss, x25519_public(f), x25519(f, s.agree));
                } else {
                    app->started(s.conversation, s.peer, ss);
                }
            }
            for (const auto& s : app->take_signs()) {
                any = true;
                app->signed_(s.id, sg::net::SigningKey(seed).sign(s.statement));
            }
            for (const auto& id : app->take_dirty()) records[id] = app->save(id);
            for (const auto& o : app->take_outgoing()) {
                any = true;
                if (o.kind == "envelope") {
                    const auto env = encode(Envelope{o.version, o.mailbox, seal_box(o.purpose, o.agree, o.plain)});
                    if (o.live && app->send_live(o.peer, env)) continue;
                    // Live only: the relay gets nothing; it waits here for a link.
                    if (o.purpose == "message" && !o.mailbox_ok) waiting.push_back({o.conversation, o.peer, env});
                    else relay->put(env);
                } else if (o.kind == "pair") {
                    if (!relay->burned.count(o.token)) {
                        relay->posts[o.token].push_back(seal_box(o.purpose, o.agree, o.plain));
                        relay->burned.insert(o.token);
                    }
                } else if (o.kind == "post") {
                    relay->put(o.box);
                } else if (o.kind == "pair_done") {
                    relay->burned.insert(o.token);
                    relay->posts.erase(o.token);
                }
            }
            for (auto& n : app->take_notices()) {
                // A linked device asks for messages it lacks: given with the keys kept here.
                if (n.kind == "link_wants") {
                    std::vector<HistoryItem> items;
                    std::set<std::string> wanted;
                    for (std::size_t at = 0; at < n.text.size();) {
                        const auto end = std::min(n.text.find(',', at), n.text.size());
                        wanted.insert(n.text.substr(at, end - at));
                        at = end + 1;
                    }
                    for (const auto& i : keyed[n.conversation])
                        if (wanted.erase(i.message.peer + ":" + std::to_string(i.message.sequence))) items.push_back(i);
                    if (!items.empty()) {
                        app->give_history(n.conversation, n.peer, items);
                        any = true;
                    }
                }
                if (n.kind == "history_item" && !n.key.empty()) {
                    keyed[n.conversation].push_back({observation_from(n.data), key_from(n.key)});
                    kept[n.conversation].emplace_back(n.data, Bytes{}, n.time);
                }
                if (n.kind == "message" || n.kind == "sent") kept[n.conversation].emplace_back(n.data, n.kind == "sent" ? n.body : Bytes{}, n.time);
                if (n.kind == "retire_key") ratchet_keys.erase(n.text);
                if ((n.kind == "message" || n.kind == "sent") && !n.key.empty())
                    keyed[n.conversation].push_back({observation_from(n.data), key_from(n.key)});
                notices.push_back(n);
            }
            for (const auto& env : app->take_live()) open(env);
            for (auto it = waiting.begin(); it != waiting.end();) {
                const auto& [cid, p, env] = *it;
                const auto ids = app->conversations();
                const bool known = std::find(ids.begin(), ids.end(), cid) != ids.end();
                if (app->send_live(p, env)) { it = waiting.erase(it); any = true; }
                else if (known && app->takes_mail(cid, p)) { relay->put(env); it = waiting.erase(it); any = true; }
                else ++it;
            }
            if (!any) return;
        }
    }
    std::string open(const Bytes& env) {
        const auto shared = x25519(secret, App::ephemeral_of(env));
        auto r = app->open(env, shared);
        if (r.status == "need_turn") {
            const auto f = random_key();
            ratchet_keys[hex(x25519_public(f))] = f;
            r = app->open(env, shared, Turn{x25519(private_of(r.own), r.dh), x25519_public(f), x25519(f, r.dh)});
        }
        return r.status;
    }
    // Fetch every mailbox, open what is there, delete it once kept.
    int fetch() {
        int n = 0;
        for (const auto& m : app->mailboxes()) {
            auto found = relay->mailboxes.find(m);
            if (found == relay->mailboxes.end()) continue;
            // A channel's posts stay for its other readers; the rest is taken.
            const bool posts = !found->second.empty() && found->second.front()[0] == 18;
            auto envelopes = posts ? found->second : std::move(found->second);
            if (!posts) relay->mailboxes.erase(found);
            for (const auto& e : envelopes) {
                const auto s = e[0] == 18 ? app->open_post(e).status : open(e);
                n += s == "accepted" || s == "control";
                step();
            }
        }
        return n;
    }
    std::vector<std::string> said(const std::string& conv) const {
        std::vector<std::string> out;
        for (const auto& n : notices)
            if (n.kind == "message" && n.conversation == conv && n.type == "text") out.emplace_back(n.body.begin(), n.body.end());
        return out;
    }
    bool heard(const std::string& kind, const std::string& conv = {}) const {
        for (const auto& n : notices)
            if (n.kind == kind && (conv.empty() || n.conversation == conv)) return true;
        return false;
    }
    std::size_t count(const std::string& kind, const std::string& conv) const {
        std::size_t k = 0;
        for (const auto& n : notices) k += n.kind == kind && n.conversation == conv;
        return k;
    }
    std::int64_t unread(const std::string& conv) const {
        return app->state(conv).element("thread").params.get_or<std::int64_t>("unread", -1);
    }
    // A reload: a new App from what was kept.
    void reload() {
        app = std::make_unique<App>(device, name);
        for (const auto& [id, rec] : records) app->load(rec);
        for (const auto& [id, ms] : kept)
            for (const auto& [obs, body, time] : ms) app->replay(id, obs, body, time);
        app->start();
    }
};

void everyone(std::vector<Host*> hs, int rounds = 6) {
    for (int i = 0; i < rounds; ++i)
        for (auto* h : hs) {
            h->step();
            h->fetch();
            h->step();
        }
}

// Pairing: the owner invites, the device asks with the code, the owner
// answers, the device takes the answer.
std::string pair(Host& owner, Host& dev, InviteKind kind, const std::string& code_said, const std::string& conv = {},
                 std::vector<Host*> others = {}) {
    auto inv = owner.app->invite(kind, "wss://relay.example/chat", conv);
    const auto parsed = invite_from_fragment(invite_fragment(inv.invite));
    const auto asking = dev.app->ask(parsed, code_said.empty() ? inv.code : code_said, dev.name, dev.call, dev.mail);
    dev.step();
    const auto posts = owner.relay->posts[inv.invite.token];
    if (posts.empty()) return "no post";
    const auto box = posts.front();
    const auto taken = owner.app->take_request(inv, box, x25519(owner.secret, box_ephemeral(box)));
    if (taken != "ok") {
        owner.step();
        return taken;
    }
    std::vector<Host*> all = {&owner, &dev};
    all.insert(all.end(), others.begin(), others.end());
    for (int i = 0; i < 12; ++i) {
        for (auto* h : all)
            if (h != &dev) {
                h->step();
                h->fetch();
                h->step();
            }
        const auto reply = owner.relay->mailboxes.find(reply_mailbox(parsed, device_id(dev.device)));
        if (reply != owner.relay->mailboxes.end() && !reply->second.empty()) {
            const auto env = reply->second.front();
            owner.relay->mailboxes.erase(reply);
            const auto r = dev.app->take_accept(asking, env, x25519(dev.secret, App::ephemeral_of(env)));
            dev.step();
            return r;
        }
    }
    return "no reply";
}
}  // namespace

int main() {
    sg::set_observers(sg::Observers::Strict);
    Relay relay;
    Host A(0x01, 0x02, "Bardia", &relay), F(0x03, 0x04, "Ana", &relay), G(0x05, 0x06, "Ana's phone", &relay),
        E(0x07, 0x08, "Eve", &relay);
    F.call = "My brother";

    // 1. A wrong code: the owner refuses it and burns the token.
    CHECK(pair(A, E, InviteKind::Contact, "abandon ability able about above absent") == "failed");
    CHECK(A.heard("invite_failed") && A.app->conversations().empty());

    // 2. Pairing with the code.
    CHECK(pair(A, F, InviteKind::Contact, "") == "ok");
    CHECK(A.app->conversations().size() == 1 && F.app->conversations().size() == 1);
    const auto c = A.app->conversations()[0];
    CHECK(F.app->conversations()[0] == c);
    // Ana said at pairing that she takes mail; Bardia says so now, signed.
    CHECK(A.app->takes_mail(c, F.app->peer()) && !F.app->takes_mail(c, A.app->peer()));
    A.app->set_delivery(c, DeliveryMode::Mailbox);
    everyone({&A, &F});
    CHECK(F.app->takes_mail(c, A.app->peer()));
    std::string fa, ff;
    for (const auto& n : A.notices) if (n.kind == "paired") fa = n.text;
    for (const auto& n : F.notices) if (n.kind == "paired") ff = n.text;
    CHECK_MSG(!fa.empty() && fa == ff, "both sides show the same four emoji: " + fa + " / " + ff);
    // Ana chose what to call the one who invited her; Bardia sees what Ana
    // calls herself until he renames her.
    CHECK(F.app->name_of(c) == "My brother" && F.app->introduced_as(c) == "Bardia");
    CHECK(A.app->name_of(c) == "Ana" && A.app->introduced_as(c) == "Ana");
    A.app->rename_contact(c, "Ana (work)");
    CHECK(A.app->name_of(c) == "Ana (work)");

    // 3. Messages both ways through the mailbox; unread; acks.
    A.app->post(c, "hello Ana", A.now);
    everyone({&A, &F});
    CHECK(F.said(c) == std::vector<std::string>{"hello Ana"});
    CHECK(F.unread(c) == 1);
    F.app->read(c);
    CHECK(F.unread(c) == 0);
    F.app->post(c, "hi Bardia", F.now);
    F.app->post(c, "how are you", F.now);
    everyone({&A, &F});
    CHECK(A.said(c) == (std::vector<std::string>{"hi Bardia", "how are you"}));
    CHECK(A.heard("acked", c) && F.heard("acked", c));

    // 4. Saved and loaded: both reload, and carry on.
    A.reload();
    F.reload();
    CHECK(A.app->name_of(c) == "Ana (work)" && F.app->name_of(c) == "My brother");
    A.app->post(c, "after a reload", A.now);
    everyone({&A, &F});
    CHECK(F.said(c).back() == "after a reload");
    F.app->post(c, "here too", F.now);
    everyone({&A, &F});
    CHECK(A.said(c).back() == "here too");

    // Each says the release it runs (protocol 9): ordinary messages, kept in
    // the history like any other.
    A.app->post_release(c, 1, Bytes(1400, 'a'));
    F.app->post_release(c, 1, Bytes(1400, 'f'));
    everyone({&A, &F});

    // 5. History epochs: fifty messages, and the conversation's history is finalized.
    for (int i = 0; i < 30; ++i) A.app->post(c, "a" + std::to_string(i), A.now);
    for (int i = 0; i < 25; ++i) F.app->post(c, "f" + std::to_string(i), F.now);
    everyone({&A, &F}, 10);
    CHECK_MSG(A.heard("history", c) && F.heard("history", c), "a history epoch finalized on both");
    CHECK(!A.heard("history_differs") && !F.heard("history_differs"));

    // 6. A further device for Ana: the owner proposes a handoff; Ana's first
    //    device endorses it; the new device takes up the conversation's trust.
    CHECK(pair(A, G, InviteKind::ExtraDevice, "", c, {&F}) == "ok");
    everyone({&A, &F, &G});
    CHECK(G.app->conversations().size() == 1 && G.app->generation_of(c) == 1);
    CHECK(A.app->generation_of(c) == 1 && F.app->generation_of(c) == 1);
    CHECK(A.app->members_of(c).size() == 3 && F.app->members_of(c).size() == 3);
    A.app->post(c, "to both of Ana's devices", A.now);
    everyone({&A, &F, &G});
    CHECK(F.said(c).back() == "to both of Ana's devices" && G.said(c).back() == "to both of Ana's devices");
    G.app->post(c, "from the new phone", G.now);
    everyone({&A, &F, &G});
    CHECK(A.said(c).back() == "from the new phone" && F.said(c).back() == "from the new phone");

    // 7. Only the owner's side changes who is in a conversation: Ana's device
    //    cannot revoke, and says nothing when it tries. (A handoff without
    //    the old quorum's endorsements is refused: tests/test_trust.cpp.)
    {
        const auto outgoing_before = F.notices.size();
        CHECK_THROWS(F.app->revoke(c, device_id(A.device)));
        F.step();
        bool said = false;
        for (std::size_t i = outgoing_before; i < F.notices.size(); ++i) said |= F.notices[i].kind == "sent";
        CHECK(!said && F.app->generation_of(c) == 1);
    }

    // 8. Revoking the new device: everyone is told, the old quorum (A and F)
    //    hands off to a committee without it, and the secret changes.
    A.app->revoke(c, device_id(G.device));
    everyone({&A, &F, &G}, 10);
    CHECK(G.heard("removed", c) && G.app->removed(c));
    CHECK(A.app->generation_of(c) == 2 && F.app->generation_of(c) == 2);
    CHECK(A.app->members_of(c).size() == 2 && F.app->members_of(c).size() == 2);
    CHECK(F.heard("rekeyed", c));
    // The revoked device can no longer be heard.
    G.app->post(c, "still here?", G.now);
    everyone({&A, &F, &G});
    CHECK(A.said(c).back() != "still here?" && F.said(c).back() != "still here?");
    A.app->post(c, "just us again", A.now);
    everyone({&A, &F, &G});
    CHECK(F.said(c).back() == "just us again" && G.said(c).back() != "just us again");

    // 9. The relay drops a message: the gap shows in the sender's window,
    //    and the next history cannot be agreed past it.
    relay.drop_next = true;
    F.app->post(c, "lost on the way", F.now);
    F.app->post(c, "after the lost one", F.now);
    everyone({&A, &F});
    CHECK(A.said(c).back() == "after the lost one");
    {
        const auto& s = A.app->state(c);
        const auto& d = s.element(device_element(device_id(F.device)).c_str());
        Window w{std::uint64_t(d.params.get_or<std::int64_t>("high", 0)), std::uint64_t(d.params.get_or<std::int64_t>("seen", 0)),
                 std::uint64_t(d.params.get_or<std::int64_t>("lost", 0))};
        CHECK(missing(w).size() == 1);
    }

    // 10. Live only (the default): the relay gets nothing for a device that
    //     does not take mail; its messages wait on the sender until a link.
    Relay quiet;
    Host P(0x21, 0x22, "Pia", &quiet), Q(0x23, 0x24, "Quinn", &quiet);
    P.mail = false;
    Q.mail = false;
    CHECK(pair(P, Q, InviteKind::Contact, "") == "ok");
    const auto pq = P.app->conversations()[0];
    CHECK(!P.app->takes_mail(pq, Q.app->peer()) && P.app->delivery(pq) == DeliveryMode::Live);
    std::size_t blobs_before = 0;
    for (const auto& [m, v] : quiet.mailboxes) blobs_before += v.size();
    P.app->post(pq, "only when you are here", P.now);
    everyone({&P, &Q});
    std::size_t blobs_after = 0;
    for (const auto& [m, v] : quiet.mailboxes) blobs_after += v.size();
    CHECK(blobs_after == blobs_before && !P.waiting.empty() && Q.said(pq).empty());

    // 12. A group: an owner and three contacts, one sender key each.
    Relay groupy;
    Host X(0x31, 0x32, "Xia", &groupy), Y(0x33, 0x34, "Yan", &groupy), Z(0x35, 0x36, "Zoe", &groupy), W(0x37, 0x38, "Wim", &groupy);
    for (auto* h : {&Y, &Z, &W}) CHECK(pair(X, *h, InviteKind::Contact, "") == "ok");
    const auto direct = [&](Host& h) {
        for (const auto& id : X.app->conversations())
            if (X.app->kind_of(id) == Kind::Direct)
                for (const auto& m : X.app->members_of(id))
                    if (m.device == h.device) return id;
        return std::string();
    };
    const auto grp = X.app->create_group("Tapes club", {direct(Y), direct(Z)});
    X.app->set_delivery(grp, DeliveryMode::Mailbox);  // no live links in this test
    everyone({&X, &Y, &Z}, 8);
    CHECK(Y.app->kind_of(grp) == Kind::Group && Z.app->kind_of(grp) == Kind::Group);
    CHECK(Y.app->members_of(grp).size() == 3 && Y.app->name_of(grp) == "Tapes club");
    X.app->post(grp, "hello club", X.now);
    Y.app->post(grp, "hi all", Y.now);
    everyone({&X, &Y, &Z}, 8);
    CHECK(Y.said(grp) == std::vector<std::string>{"hello club"} && Z.said(grp) == (std::vector<std::string>{"hello club", "hi all"}));
    CHECK(X.said(grp) == std::vector<std::string>{"hi all"});


    // ... a fourth comes in: a majority endorses (2 of 3), and keys turn.
    X.app->add_to_group(grp, direct(W));
    everyone({&X, &Y, &Z, &W}, 12);
    CHECK_MSG(W.app->conversations().size() == 2 && W.app->members_of(grp).size() == 4, "the fourth member took up the group");
    CHECK(X.app->generation_of(grp) == 1 && Y.app->generation_of(grp) == 1);
    Z.app->post(grp, "welcome Wim", Z.now);
    everyone({&X, &Y, &Z, &W}, 8);
    CHECK(W.said(grp) == std::vector<std::string>{"welcome Wim"} && X.said(grp).back() == "welcome Wim");

    // ... and one goes: what follows, it cannot read.
    std::vector<Key32> zoe{device_id(Z.device)};
    X.app->remove_devices(grp, zoe);
    everyone({&X, &Y, &Z, &W}, 12);
    CHECK(X.app->members_of(grp).size() == 3 && Y.app->generation_of(grp) == 2 && Z.app->removed(grp));
    X.app->post(grp, "after Zoe", X.now);
    everyone({&X, &Y, &Z, &W}, 8);
    CHECK(Y.said(grp).back() == "after Zoe" && W.said(grp).back() == "after Zoe" && Z.said(grp).back() != "after Zoe");

    // ... and Wim's phone is lost: Xia brings in his new one; Yan must
    //     approve too (two of the two that remain), and keys turn.
    Host V(0x3d, 0x3e, "Wim's new phone", &groupy);
    {
        X.app->set_recovery_wait(1000);
        auto inv = X.app->recovery_invite("wss://relay.example/chat", grp, device_id(W.device), Scope::Full);
        const auto parsed = invite_from_fragment(invite_fragment(inv.invite));
        auto asking = V.app->ask(parsed, inv.code, V.name, V.call, V.mail);
        V.step();
        const auto box = groupy.posts[inv.invite.token].front();
        CHECK(X.app->take_request(inv, box, x25519(X.secret, box_ephemeral(box))) == "ok");
        everyone({&X, &Y});
        CHECK(Y.heard("recovery_approve", grp));
        X.now += 5000;
        everyone({&X, &Y});
        CHECK_MSG(X.app->generation_of(grp) == 2, "not without Yan's approval, however long the wait");
        Y.app->approve_recovery(grp);
        everyone({&X, &Y});
        CHECK(X.app->generation_of(grp) == 3 && Y.app->generation_of(grp) == 3);
        const auto reply_at = reply_mailbox(parsed, device_id(V.device));
        CHECK(groupy.mailboxes.count(reply_at) && !groupy.mailboxes[reply_at].empty());
        const auto env = groupy.mailboxes[reply_at].front();
        groupy.mailboxes.erase(reply_at);
        CHECK(V.app->take_accept(asking, env, x25519(V.secret, App::ephemeral_of(env))) == "ok");
        everyone({&X, &Y, &V}, 10);
        CHECK(V.app->kind_of(grp) == Kind::Group && V.app->members_of(grp).size() == 3);
        Y.app->post(grp, "hello Wim's new phone", Y.now);
        everyone({&X, &Y, &V, &W}, 8);
        CHECK(V.said(grp).back() == "hello Wim's new phone" && X.said(grp).back() == "hello Wim's new phone");
        CHECK(W.said(grp).back() != "hello Wim's new phone");
        V.app->post(grp, "back in the club", V.now);
        everyone({&X, &Y, &V}, 8);
        CHECK(Y.said(grp).back() == "back in the club");
    }

    // 13. A channel: its publisher's committee alone; a reader checks every
    //     post and cannot post.
    Host R(0x39, 0x3a, "Rita", &groupy);
    const auto chn = X.app->create_channel_for_test("Tape news");
    CHECK(pair(X, R, InviteKind::Channel, "", chn) == "ok");
    CHECK(R.app->kind_of(chn) == Kind::Channel && !R.app->member_here(chn) && X.app->member_here(chn));
    X.app->post(chn, "issue one", X.now);
    X.app->post(chn, "issue two", X.now);
    everyone({&X, &R}, 6);
    CHECK(R.said(chn) == (std::vector<std::string>{"issue one", "issue two"}));
    CHECK_THROWS(R.app->post(chn, "may I?", R.now));
    // A second reader reads the same posts, left at the relay once.
    Host S(0x3b, 0x3c, "Sam", &groupy);
    CHECK(pair(X, S, InviteKind::Channel, "", chn) == "ok");
    X.app->post(chn, "issue three", X.now);
    everyone({&X, &R, &S}, 6);
    CHECK(S.said(chn) == std::vector<std::string>{"issue three"} && R.said(chn).back() == "issue three");

    // 14. Recovery: Kai's phone is lost, and Lia (the other side) brings in
    //     his new one. First the old phone, still here, refuses; then, lost
    //     for real, it is replaced when the wait is over, and the new phone
    //     takes only history the agreed chain names.
    {
        Relay rr;
        Host K(0x41, 0x42, "Kai", &rr), L(0x43, 0x44, "Lia", &rr), N(0x45, 0x46, "Kai's new phone", &rr);
        CHECK(pair(K, L, InviteKind::Contact, "") == "ok");
        const auto kl = K.app->conversations()[0];
        K.app->set_delivery(kl, DeliveryMode::Mailbox);
        for (int i = 0; i < 30; ++i) K.app->post(kl, "k" + std::to_string(i), K.now);
        for (int i = 0; i < 25; ++i) L.app->post(kl, "l" + std::to_string(i), L.now);
        everyone({&K, &L}, 10);
        CHECK(K.heard("history", kl) && L.heard("history", kl));
        const auto ask = [&](std::uint64_t wait, std::string& asked) {
            L.app->set_recovery_wait(wait);
            auto inv = L.app->recovery_invite("wss://relay.example/chat", kl, device_id(K.device), Scope::Full);
            const auto parsed = invite_from_fragment(invite_fragment(inv.invite));
            auto asking = N.app->ask(parsed, inv.code, N.name, N.call, N.mail);
            N.step();
            const auto box = rr.posts[inv.invite.token].front();
            asked = L.app->take_request(inv, box, x25519(L.secret, box_ephemeral(box)));
            return std::make_pair(parsed, asking);
        };
        // Lost is not refused by the lost one: a device cannot recover itself.
        CHECK_THROWS(L.app->recovery_invite("wss://relay.example/chat", kl, device_id(L.device), Scope::Full));
        std::string asked;
        ask(3600000, asked);
        CHECK(asked == "ok");
        everyone({&L, &K});
        CHECK(K.heard("recovery_of_me", kl) && !L.app->recovery_state(kl).empty() && !K.app->recovery_state(kl).empty());
        K.app->refuse_recovery(kl);
        everyone({&L, &K});
        CHECK(L.heard("recovery_refused", kl) && L.app->recovery_state(kl).empty());
        CHECK(L.app->generation_of(kl) == 0 && K.app->generation_of(kl) == 0);

        // Lost for real: Kai's old phone hears nothing from here on.
        const auto [parsed, asking] = ask(1000, asked);
        CHECK(asked == "ok");
        everyone({&L});
        const auto reply_at = reply_mailbox(parsed, device_id(N.device));
        CHECK_MSG(!rr.mailboxes.count(reply_at) || rr.mailboxes[reply_at].empty(), "nothing before the wait is over");
        CHECK(L.app->generation_of(kl) == 0);
        L.now += 2000;
        everyone({&L});
        CHECK(L.heard("recovered", kl) && L.app->generation_of(kl) == 1);
        CHECK_MSG(rr.mailboxes.count(reply_at) && !rr.mailboxes[reply_at].empty(), "the new phone is answered");
        const auto env = rr.mailboxes[reply_at].front();
        rr.mailboxes.erase(reply_at);
        CHECK(N.app->take_accept(asking, env, x25519(N.secret, App::ephemeral_of(env))) == "ok");
        N.step();
        everyone({&L, &N}, 8);
        CHECK(N.app->generation_of(kl) == 1 && N.app->members_of(kl).size() == 2 && L.app->members_of(kl).size() == 2);
        bool new_in = false, old_out = true;
        for (const auto& m : L.app->members_of(kl)) {
            new_in |= m.device == N.device;
            old_out &= !(m.device == K.device);
        }
        CHECK(new_in && old_out);
        // The new phone is on Kai's side: it turns the secret the old one knew.
        CHECK(L.heard("rekeyed", kl));
        // History: what the chain names opens; a forged key opens nothing.
        std::vector<HistoryItem> items;
        for (const auto& i : L.keyed[kl])
            if (i.message.parameter == "text") items.push_back(i);
        CHECK_MSG(items.size() == 55, "items: " + std::to_string(items.size()));
        auto forged = items.front();
        forged.key[0] ^= 1;
        L.app->share_history(kl, N.app->peer(), {forged});
        everyone({&L, &N});
        CHECK(N.count("history_item", kl) == 0);
        L.app->share_history(kl, N.app->peer(), items);
        everyone({&L, &N});
        const auto got = N.count("history_item", kl);
        // Every one: the agreed epochs, and the messages since that the endorsed recovery names.
        CHECK_MSG(got == items.size(), "history given: " + std::to_string(got) + " of " + std::to_string(items.size()));
        // They talk; the old phone, back again, is told it was replaced and reads nothing.
        L.app->post(kl, "welcome back", L.now);
        everyone({&L, &N});
        CHECK(N.said(kl) == std::vector<std::string>{"welcome back"});
        N.app->post(kl, "new phone, same Kai", N.now);
        everyone({&L, &N});
        CHECK(L.said(kl).back() == "new phone, same Kai");
        everyone({&K, &L, &N}, 8);
        CHECK(K.app->removed(kl));
        L.app->post(kl, "only the new phone", L.now);
        everyone({&K, &L, &N});
        CHECK(N.said(kl).back() == "only the new phone" && K.said(kl).back() != "only the new phone");
        // No recovery: said by a member, and kept by both; nothing can be replaced.
        L.app->set_options(kl, Options{true, 0});
        everyone({&L, &N});
        CHECK(N.app->options_of(kl).no_recovery && L.app->options_of(kl).no_recovery);
        CHECK_THROWS(N.app->recovery_invite("wss://relay.example/chat", kl, device_id(L.device), Scope::None));
        const auto before = L.keyed[kl].size();
        N.app->post(kl, "not kept for anyone", N.now);
        everyone({&L, &N});
        CHECK(L.said(kl).back() == "not kept for anyone" && L.keyed[kl].size() == before);
    }

    // 11. The live path: two devices joined directly, the relay unused.
    struct Link : App::Live {
        Link* other = nullptr;
        std::deque<std::pair<std::string, Bytes>> in;
        std::string name;
        // The Latest lane, as a real link may be: some lost, some out of order.
        bool lossy = false;
        std::mt19937 rng{7};
        void connect(const std::string&) override {}
        bool connected(const std::string&) override { return other != nullptr; }
        bool send(const std::string&, const std::string& channel, const Bytes& e) override {
            other->in.emplace_back(channel, e);
            return true;
        }
        bool send_latest(const std::string&, const std::string& channel, const std::string&, const Bytes& e) override {
            if (lossy && rng() % 5 == 0) return true;  // lost on the way
            if (lossy && rng() % 4 == 0 && !other->in.empty()) other->in.insert(other->in.end() - 1, {channel, e});  // overtakes one
            else other->in.emplace_back(channel, e);
            return true;
        }
        bool receive(std::string& p, std::string& channel, Bytes& e) override {
            if (in.empty()) return false;
            p = other->name;
            channel = in.front().first;
            e = in.front().second;
            in.pop_front();
            return true;
        }
        std::vector<sg::net::IceSignal> signals() override { return {}; }
        void signal(const std::string&, const sg::net::IceSignal&) override {}
        void poll() override {}
    } la, lf;
    la.other = &lf;
    lf.other = &la;
    la.name = A.app->peer();
    lf.name = F.app->peer();
    A.app->set_live(&la);
    F.app->set_live(&lf);
    const auto in_mailboxes = [&] { std::size_t n = 0; for (const auto& [m, v] : relay.mailboxes) n += v.size(); return n; };
    const auto before = in_mailboxes();
    A.app->post(c, "live", A.now);
    for (int i = 0; i < 4; ++i) { A.step(); F.step(); }
    CHECK(F.said(c).back() == "live");
    CHECK(in_mailboxes() == before);
    // Carrying for contacts (protocol 10): a frame on the live link reaches
    // the other's host whole and from whom it came; one larger than any
    // envelope is refused; the devices a link is up with are known.
    {
        const Bytes frame(70000, 0x42);
        CHECK(A.app->send_carry(F.app->peer(), frame));
        for (int i = 0; i < 2; ++i) { A.step(); F.step(); }
        const auto got = F.app->take_carry();
        CHECK(got.size() == 1 && got[0].first == A.app->peer() && got[0].second == frame);
        CHECK_THROWS(A.app->send_carry(F.app->peer(), Bytes(carry_frame_max + 1, 0)));
        const auto peers = A.app->live_peers();
        CHECK(std::find(peers.begin(), peers.end(), F.app->peer()) != peers.end());
    }
    // ... and what waited for a live link goes the moment there is one.
    Link lp, lq;
    lp.other = &lq;
    lq.other = &lp;
    lp.name = P.app->peer();
    lq.name = Q.app->peer();
    P.app->set_live(&lp);
    Q.app->set_live(&lq);
    for (int i = 0; i < 4; ++i) { P.step(); Q.step(); }
    CHECK(P.waiting.empty() && Q.said(pq) == std::vector<std::string>{"only when you are here"});

    // 15. A call over the live link: rung, answered; what is said is played
    //     in order, only once a root its speaker signed names it; a copy
    //     changed on the way is refused, the real one played.
    {
        const auto call = A.app->start_call(c);
        for (int i = 0; i < 4; ++i) { A.step(); F.step(); }
        CHECK(F.heard("call", c));
        F.app->join_call(call);
        for (int i = 0; i < 4; ++i) { A.step(); F.step(); }
        CHECK(A.heard("call_joined", c) && A.app->calls().front().in.size() == 2);
        std::vector<App::Media> got;
        for (int i = 0; i < 12; ++i) {
            A.app->send_media(call, Layer::Full, i == 0, std::uint64_t(i) * 40000, Bytes(200, std::uint8_t(i)));
            if (i == 5) {
                // On the way to Ana, a copy of the sixth frame, changed, goes first.
                auto last = lf.in.end();
                while (last != lf.in.begin() && std::prev(last)->first != "call") --last;
                CHECK(last != lf.in.begin());
                auto forged = *std::prev(last);
                forged.second.back() ^= 1;
                lf.in.insert(std::prev(last), forged);
            }
            A.now += 40;
            F.now += 40;
            A.step();
            F.step();
            for (auto& m : F.app->take_media()) got.push_back(std::move(m));
        }
        for (int i = 0; i < 6; ++i) {
            A.now += 100, F.now += 100;
            A.step(), F.step();
            for (auto& m : F.app->take_media()) got.push_back(std::move(m));
        }
        bool in_order = got.size() == 12;
        for (std::size_t i = 0; i < got.size(); ++i) in_order &= got[i].sequence == i && got[i].data == Bytes(200, std::uint8_t(i));
        CHECK_MSG(in_order, "all twelve frames played, in order, as said: " + std::to_string(got.size()));
        CHECK_MSG(F.app->calls().front().refused >= 1, "the changed copy was refused");
        A.app->leave_call(call);
        for (int i = 0; i < 4; ++i) { A.step(); F.step(); }
        CHECK_MSG(F.heard("call_ended", c) && F.app->calls().empty() && A.app->calls().empty(), "one leaves a call of two: it ends for both");
    }

    // 16. A call of three in a group, over a hub of live links: one leaves,
    //     and the key turns for the two still in - the one that left cannot
    //     open what follows.
    {
        struct Port;
        struct Hub {
            std::map<std::string, Port*> ports;
            std::vector<Bytes> tapped;  // what went by on channel "call", to look at after
        } hub;
        struct Port : App::Live {
            Hub* hub = nullptr;
            std::string name;
            std::deque<std::tuple<std::string, std::string, Bytes>> in;
            void connect(const std::string&) override {}
            bool connected(const std::string& p) override { return hub->ports.count(p) != 0; }
            bool send(const std::string& p, const std::string& channel, const Bytes& e) override {
                const auto it = hub->ports.find(p);
                if (it == hub->ports.end()) return false;
                if (channel == "call") hub->tapped.push_back(e);
                it->second->in.emplace_back(name, channel, e);
                return true;
            }
            bool receive(std::string& p, std::string& channel, Bytes& e) override {
                if (in.empty()) return false;
                std::tie(p, channel, e) = in.front();
                in.pop_front();
                return true;
            }
            std::vector<sg::net::IceSignal> signals() override { return {}; }
            void signal(const std::string&, const sg::net::IceSignal&) override {}
            void poll() override {}
        };
        Port px, py, pv;
        for (auto [port, host] : {std::pair{&px, &X}, std::pair{&py, &Y}, std::pair{&pv, &V}}) {
            port->hub = &hub;
            port->name = host->app->peer();
            hub.ports[port->name] = port;
            host->app->set_live(port);
        }
        const auto all = [&](int rounds) {
            for (int i = 0; i < rounds; ++i)
                for (auto* h : {&X, &Y, &V}) {
                    h->now += 50;
                    h->step();
                    h->fetch();
                    h->step();
                }
        };
        const auto call = X.app->start_call(grp);
        all(6);
        CHECK(Y.heard("call", grp) && V.heard("call", grp));
        Y.app->join_call(call);
        V.app->join_call(call);
        all(6);
        CHECK(X.app->calls().front().in.size() == 3);
        for (int i = 0; i < 4; ++i) X.app->send_media(call, Layer::Full, i == 0, 0, Bytes(64, std::uint8_t(i)));
        all(4);
        const auto said = [](Host& h) {
            std::size_t n = 0;
            for (const auto& m : h.app->take_media()) n += m.data.size() == 64;
            return n;
        };
        CHECK_MSG(said(Y) == 4 && said(V) == 4, "everyone in the call hears the one who speaks");
        V.app->leave_call(call);
        all(8);
        CHECK_MSG(X.app->calls().front().in.size() == 2 && X.app->calls().front().generation == 1, "one left: a new generation");
        CHECK_MSG(Y.app->calls().front().generation == 1, "the one still in has the next key");
        hub.tapped.clear();
        for (int i = 0; i < 4; ++i) X.app->send_media(call, Layer::Full, false, 0, Bytes(64, std::uint8_t(9)));
        all(4);
        CHECK(said(Y) == 4);
        CHECK_MSG(V.app->calls().empty(), "the one that left has no call, and no key to it");
        bool unreadable = !hub.tapped.empty();
        for (const auto& chunk : hub.tapped) unreadable &= chunk_header(chunk).generation == 1;
        CHECK_MSG(unreadable, "what follows is under the next generation's key");
        X.app->leave_call(call);
        all(6);

        // 17. A swarm in the group: Xia streams; Yan (a desktop) forwards,
        //     Wim's phone (mobile data) only takes. The roster is Xia's
        //     sealed epoch; each plans the same forwarders by Placement.
        const auto stream = X.app->start_call(grp, CallMode::Swarm);
        all(6);
        Y.app->join_call(stream, Capacity::Seed);
        V.app->join_call(stream, Capacity::Take);
        all(12);
        const auto view = [&](Host& h) { return h.app->calls().front(); };
        if (std::getenv("CALL_TRACE"))
            for (auto* h : {&X, &Y, &V}) {
                const auto v = view(*h);
                std::printf("  %s gen %llu in %zu fwd %zu joined %d heard roster %d\n", h->name.c_str(), (unsigned long long)v.generation, v.in.size(),
                            v.forwarders.size(), int(v.joined), int(h->heard("call_roster", grp)));
            }
        CHECK_MSG(view(X).generation >= 1 && view(Y).generation == view(X).generation && view(V).generation == view(X).generation,
                  "everyone on the roster has its generation's key");
        CHECK_MSG(view(Y).forwarders == view(X).forwarders && view(V).forwarders == view(X).forwarders, "everyone plans the same forwarders");
        bool no_taker = true;
        for (const auto& f : view(X).forwarders) no_taker &= f != V.app->peer();
        CHECK_MSG(no_taker && !view(X).forwarders.empty(), "a phone on mobile data forwards nothing");
        CHECK_MSG(X.app->engine().current() && true, "");
        std::size_t frames = 0;
        for (int t = 0; t < 60; ++t) {
            X.app->send_media(stream, Layer::Full, t % 15 == 0, std::uint64_t(t) * 66000, Bytes(300, std::uint8_t(t)));
            all(1);
            frames += 1;
        }
        all(30);
        const auto heard = [](Host& h) {
            std::vector<std::uint8_t> got;
            for (const auto& m : h.app->take_media()) got.push_back(m.data.empty() ? 0 : m.data[0]);
            return got;
        };
        const auto hy = heard(Y), hv = heard(V);
        bool ordered = !hy.empty();
        for (std::size_t i = 1; i < hy.size(); ++i) ordered &= hy[i] == std::uint8_t(hy[i - 1] + 1);
        CHECK_MSG(ordered && hy.size() >= 50 && hv.size() >= 50,
                  "the swarm's viewers see the stream, in order: " + std::to_string(hy.size()) + " and " + std::to_string(hv.size()) + " of 60 frames");
        CHECK_MSG(view(Y).refused == 0 && view(V).refused == 0, "nothing refused");
        X.app->leave_call(stream);
        all(6);

        // 18. Speakers through a tree, simulcast: Xia and Yan speak, each a
        //     full and a small picture; Wim's phone asks for Xia's full one.
        //     It gets that, and Yan's small; Yan, who asked for none, Xia's small.
        const auto talk = X.app->start_call(grp, CallMode::Hybrid);
        all(6);
        Y.app->join_call(talk, Capacity::Forward);
        V.app->join_call(talk, Capacity::Take);
        all(12);
        CHECK(view(V).generation == view(X).generation && view(Y).generation == view(X).generation);
        V.app->pick_full(talk, X.app->peer());
        all(4);
        for (int t = 0; t < 20; ++t) {
            for (auto* s : {&X, &Y}) {
                s->app->send_media(talk, Layer::Full, t % 10 == 0, 0, Bytes(400, std::uint8_t(t)));
                s->app->send_media(talk, Layer::Small, t % 10 == 0, 0, Bytes(100, std::uint8_t(t)));
            }
            all(1);
        }
        all(20);
        const auto layers = [](Host& h) {
            std::map<std::pair<std::string, Layer>, int> n;
            for (const auto& m : h.app->take_media()) ++n[{m.streamer, m.layer}];
            return n;
        };
        auto lv = layers(V), ly = layers(Y);
        const auto of = [](auto& n, Host& who, Layer l) { return n[std::make_pair(who.app->peer(), l)]; };
        CHECK_MSG(of(lv, X, Layer::Full) >= 18 && of(lv, X, Layer::Small) >= 18, "the one who asked has Xia's full and small pictures");
        CHECK_MSG(of(lv, Y, Layer::Full) == 0 && of(lv, Y, Layer::Small) >= 18, "and of Yan, whom it did not ask for, the small one only");
        CHECK_MSG(of(ly, X, Layer::Full) == 0 && of(ly, X, Layer::Small) >= 18, "Yan, who asked for no one, has Xia's small picture only");
        CHECK(view(V).refused == 0 && view(Y).refused == 0);
        X.app->leave_call(talk);
        all(6);
        for (auto* h : {&X, &Y, &V}) h->app->set_live(nullptr);
    }
    // 19. Tape tennis over the live link: asked, played; both courts the same,
    //     step for step; then over for both.
    {
        la.lossy = lf.lossy = true;
        const auto game = A.app->start_game(c);
        for (int i = 0; i < 4; ++i) { A.step(); F.step(); }
        CHECK(F.heard("game", c));
        F.app->join_game(game);
        for (int i = 0; i < 4; ++i) { A.step(); F.step(); }
        CHECK_MSG(A.heard("game_on", c) && F.heard("game_on", c), "both play");
        std::map<std::int64_t, std::vector<double>> seen_a, seen_f;
        for (int f = 0; f < 600; ++f) {
            A.app->game_input(game, (f / 40) % 2 ? 1 : -1);
            F.app->game_input(game, (f / 55) % 2 ? -1 : 1);
            A.now += 16, F.now += 16;
            A.step();
            F.step();
            const auto va = A.app->games().front(), vf = F.app->games().front();
            seen_a[va.epoch] = {double(va.left_score), double(va.right_score), double(va.hits)};
            seen_f[vf.epoch] = {double(vf.left_score), double(vf.right_score), double(vf.hits)};
        }
        const auto va = A.app->games().front();
        CHECK_MSG(va.epoch > 40, "the game goes on: " + std::to_string(va.epoch) + " steps agreed");
        bool same = true;
        for (const auto& [e, s] : seen_a)
            if (seen_f.count(e)) same &= seen_f[e] == s;
        CHECK_MSG(same, "both sides see the same score at every step");
        CHECK(va.lead <= court_lead);
        A.app->leave_game(game);
        for (int i = 0; i < 4; ++i) { A.step(); F.step(); }
        CHECK_MSG(F.heard("game_over", c) && A.app->games().empty() && F.app->games().empty(), "over for both");
        la.lossy = lf.lossy = false;
    }
    // 20. The whiteboard over the live link: a stroke said and counted on
    //     both; a pen seen moving on the other side; one leads, and the
    //     other's view is brought to where it looks.
    {
        A.app->open_board(c);
        F.app->open_board(c);
        const auto frames = [&](int n) {
            for (int f = 0; f < n; ++f) {
                A.now += 16, F.now += 16;
                A.step();
                F.step();
            }
        };
        frames(4);
        CHECK(A.app->board(c).open && F.app->board(c).open);
        const auto stroke = Writer().u8(8).u8(3).u8(4).u16(2).u16(0).u16(0).u16(1000).u16(1000).take();
        A.app->post_stroke(c, stroke, A.now);
        frames(6);
        CHECK_MSG(A.app->board(c).strokes == 1 && F.app->board(c).strokes == 1, "a stroke is said, and counted on both boards");
        for (int i = 0; i < 20; ++i) {
            A.app->pen(c, -0.5 + 0.05 * i, 0.25, true, 2);
            frames(1);
        }
        const auto pens = F.app->board(c).pens;
        CHECK_MSG(pens.size() == 1 && pens[0].peer == A.app->peer() && std::fabs(pens[0].x - 0.45) < 0.15 && pens[0].down && pens[0].color == 2,
                  "the other side sees the pen where it is going");
        A.app->look(c, 0.3, -0.2, 1.5);
        F.app->look(c, -0.6, 0.4, 0.8);
        A.app->lead(c, true);
        frames(10);
        const auto fv = F.app->board(c);
        CHECK_MSG(fv.leader == A.app->peer() && std::fabs(fv.x - 0.3) < 1e-4 && std::fabs(fv.y + 0.2) < 1e-4 && std::fabs(fv.zoom - 1.5) < 1e-4,
                  "following: the other's view is brought to the leader's");
        A.app->lead(c, false);
        frames(4);
        CHECK(F.app->board(c).leader.empty());
        A.app->close_board(c);
        F.app->close_board(c);
        CHECK(!A.app->board(c).open);
    }
    // 22. Linked devices (protocol 11): a phone P and a desktop D of one
    //     person. P talks with C (P invited C: P's side owns the chat) and Q
    //     (Q invited P). D links to P: it is brought into both by handoff -
    //     asked of Q's side for Q's chat - given each chat over the self
    //     conversation with what was said there, each message checked
    //     against the agreed epochs. New chats and names follow; one that
    //     was away is filled in; then unlinking, three ways.
    {
        Relay lr;
        Host P(0x81, 0x82, "Pat", &lr), D(0x83, 0x84, "Pat's desktop", &lr), C(0x85, 0x86, "Cy", &lr), Q(0x87, 0x88, "Quin", &lr),
            E(0x89, 0x8a, "Eli", &lr), T(0x8b, 0x8c, "Pat's tablet", &lr), U(0x8d, 0x8e, "Pat's laptop", &lr);
        const auto texts = [](const Host& h, const std::string& conv) {
            std::vector<std::string> out;
            for (const auto& n : h.notices)
                if ((n.kind == "message" || n.kind == "history_item" || n.kind == "sent") && n.conversation == conv && n.type == "text")
                    out.emplace_back(n.body.begin(), n.body.end());
            std::sort(out.begin(), out.end());
            return out;
        };
        const auto has = [](const Host& h, const std::string& conv) {
            const auto ids = h.app->conversations();
            return std::find(ids.begin(), ids.end(), conv) != ids.end() && !h.app->removed(conv);
        };
        const auto in = [](const Host& h, const std::string& conv, const Host& who) {
            for (const auto& m : h.app->members_of(conv))
                if (m.device == who.device) return true;
            return false;
        };
        CHECK(pair(P, C, InviteKind::Contact, "") == "ok");
        const auto pc = P.app->conversations()[0];
        CHECK(pair(Q, P, InviteKind::Contact, "") == "ok");
        std::string qp;
        for (const auto& id : P.app->conversations()) if (id != pc) qp = id;
        P.app->set_delivery(pc, DeliveryMode::Mailbox);
        Q.app->set_delivery(qp, DeliveryMode::Mailbox);
        everyone({&P, &C, &Q});
        for (int i = 0; i < 3; ++i) {
            P.app->post(pc, "p" + std::to_string(i), P.now);
            C.app->post(pc, "c" + std::to_string(i), C.now);
            Q.app->post(qp, "q" + std::to_string(i), Q.now);
        }
        // Enough said for an epoch before the link: the one given checks back to it.
        for (int i = 3; i < 50; ++i) P.app->post(pc, "p" + std::to_string(i), P.now);
        everyone({&P, &C, &Q}, 8);
        CHECK(texts(P, pc).size() == 53 && texts(P, qp).size() == 3 && P.heard("history", pc));

        // Linked: one Link invite, the six words, the same four pictures.
        CHECK(pair(P, D, InviteKind::Link, "") == "ok");
        CHECK(!P.app->self_conversation().empty() && P.app->self_conversation() == D.app->self_conversation());
        CHECK(P.app->linked() == std::vector<std::string>{D.app->peer()} && D.app->linked() == std::vector<std::string>{P.app->peer()});
        CHECK(P.app->kind_of(P.app->self_conversation()) == Kind::Self);
        std::string fp, fd;
        for (const auto& n : P.notices) if (n.kind == "paired" && n.conversation == P.app->self_conversation()) fp = n.text;
        for (const auto& n : D.notices) if (n.kind == "paired") fd = n.text;
        CHECK_MSG(!fp.empty() && fp == fd, "both show the same four pictures: " + fp + " / " + fd);
        everyone({&P, &D, &C, &Q}, 14);
        CHECK_MSG(has(D, pc) && has(D, qp), "the linked device has both chats");
        CHECK(in(C, pc, D) && in(Q, qp, D) && in(P, pc, D) && in(P, qp, D));
        CHECK(C.app->generation_of(pc) == 1 && Q.app->generation_of(qp) == 1 && D.app->generation_of(pc) == 1);
        // On this person's side: the owner's in P's chat, the friend's in Q's.
        for (const auto& m : C.app->members_of(pc)) if (m.device == D.device) CHECK(m.side == Side::Owner);
        for (const auto& m : Q.app->members_of(qp)) if (m.device == D.device) CHECK(m.side == Side::Friend);
        CHECK(D.app->name_of(pc) == P.app->name_of(pc));
        CHECK_MSG(texts(D, pc) == texts(P, pc), "what was said, given: " + std::to_string(texts(D, pc).size()));
        CHECK(texts(D, qp) == texts(P, qp));
        CHECK_MSG(D.count("history_item", pc) == 53 && D.count("history_item", qp) == 3,
                  "history given: " + std::to_string(D.count("history_item", pc)) + " " + std::to_string(D.count("history_item", qp)));

        // The linked device talks in it; what is said reaches both of this person's devices.
        D.app->post(pc, "from the desktop", D.now);
        C.app->post(pc, "to both", C.now);
        Q.app->post(qp, "to Pat", Q.now);
        everyone({&P, &D, &C, &Q});
        CHECK(!C.said(pc).empty() && !P.said(pc).empty() && C.said(pc).back() == "from the desktop" && P.said(pc).back() == "to both");
        CHECK(D.said(pc).back() == "to both" && D.said(qp).back() == "to Pat" && P.said(qp).back() == "to Pat");
        // A forged history item is not taken: only what the agreed epochs name, or a member signed.
        {
            auto forged = P.keyed[pc].front();
            forged.key[0] ^= 1;
            const auto before = D.count("history_item", pc);
            P.app->give_history(pc, D.app->peer(), {forged});
            everyone({&P, &D});
            CHECK(D.count("history_item", pc) == before);
        }

        // A new contact made on P is on D from its start; a name follows.
        CHECK(pair(P, E, InviteKind::Contact, "") == "ok");
        std::string pe;
        for (const auto& id : P.app->conversations()) if (id != pc && id != qp && id != P.app->self_conversation()) pe = id;
        P.app->set_delivery(pe, DeliveryMode::Mailbox);
        everyone({&P, &D, &E});
        CHECK_MSG(has(D, pe) && in(E, pe, D) && E.app->generation_of(pe) == 0, "the new contact's chat is on the desktop");
        E.app->post(pe, "hi Pat", E.now);
        everyone({&P, &D, &E});
        CHECK(P.said(pe).back() == "hi Pat" && D.said(pe).back() == "hi Pat");
        P.app->rename_contact(pe, "Eli from work");
        everyone({&P, &D});
        CHECK(D.app->name_of(pe) == "Eli from work");
        // A group made on P: D in it from its start.
        const auto pg = P.app->create_group("Pat, Cy, Quin", {pc, qp});
        everyone({&P, &D, &C, &Q}, 8);
        CHECK(has(D, pg) && has(C, pg) && has(Q, pg) && in(C, pg, D));
        P.app->set_delivery(pg, DeliveryMode::Mailbox);
        everyone({&P, &D, &C, &Q}, 4);
        C.app->post(pg, "group hello", C.now);
        everyone({&P, &D, &C, &Q}, 8);
        CHECK_MSG(P.said(pg) == std::vector<std::string>{"group hello"} && D.said(pg) == std::vector<std::string>{"group hello"},
                  "a group's message on both: " + std::to_string(P.said(pg).size()) + " " + std::to_string(D.said(pg).size()));
        CHECK(!D.heard("warning") && !P.heard("warning"));

        // Kept and read back: both carry on as they were.
        P.reload();
        D.reload();
        everyone({&P, &D, &C, &Q});
        CHECK(D.app->linked() == std::vector<std::string>{P.app->peer()} && has(D, pc) && texts(D, pc) == texts(P, pc));

        // D away; what it missed is lost on the way to it (the relay dropped
        // its mail), and an epoch is agreed without it. Back, it says what it
        // has; P gives what it lacks, the epoch too.
        for (int i = 0; i < 52; ++i) C.app->post(pc, "while away " + std::to_string(i), C.now);
        everyone({&P, &C}, 8);
        for (const auto& m : D.app->mailboxes()) lr.mailboxes.erase(m);
        D.now += 400000;
        everyone({&P, &D, &C}, 10);
        CHECK_MSG(texts(D, pc) == texts(P, pc), "filled in by the linked device: " + std::to_string(texts(D, pc).size()) + " of " +
                                                    std::to_string(texts(P, pc).size()));
        const auto epoch_of = [](const Host& h, const std::string& conv) {
            const auto d = h.app->describe(conv);
            return d.substr(d.find("last epoch"), d.find(", since") - d.find("last epoch"));
        };
        CHECK_MSG(epoch_of(D, pc) == epoch_of(P, pc), "the epoch caught up: " + epoch_of(D, pc) + " / " + epoch_of(P, pc));

        // Unlink, Keep: D leaves every chat (by handoff; P stays) and keeps a copy to read.
        D.app->unlink(UnlinkWhat::Keep);
        everyone({&P, &D, &C, &Q, &E}, 14);
        CHECK(D.app->self_conversation().empty() && P.app->self_conversation().empty() && P.app->linked().empty());
        CHECK(P.heard("unlinked") && D.heard("unlinked"));
        CHECK_MSG(!in(C, pc, D) && !in(Q, qp, D) && !in(E, pe, D) && !in(C, pg, D), "D was taken out of each");
        CHECK(in(C, pc, P) && C.app->generation_of(pc) == 2);
        CHECK(D.app->removed(pc) && D.app->left(pc) && D.app->left(qp) && texts(D, pc).size() == texts(P, pc).size());
        D.app->post(pc, "after", D.now);  // refused here: nothing goes
        C.app->post(pc, "only Pat now", C.now);
        everyone({&P, &D, &C});
        CHECK(P.said(pc).back() == "only Pat now" && D.said(pc).back() != "only Pat now" && C.said(pc).back() != "after");

        // Unlink, Forget: a tablet linked, filled in, then gone - P keeps going without it.
        CHECK(pair(P, T, InviteKind::Link, "") == "ok");
        everyone({&P, &T, &C, &Q, &E}, 14);
        CHECK(has(T, pc) && has(T, qp) && has(T, pe) && has(T, pg) && in(C, pc, T));
        T.app->unlink(UnlinkWhat::Forget);
        everyone({&P, &T, &C, &Q, &E}, 14);
        CHECK(!in(C, pc, T) && !in(Q, qp, T) && P.app->linked().empty());
        CHECK(T.app->removed(pc) && !T.app->left(pc) && T.heard("left", pc));

        // Split: a laptop linked; the two agree which chats go with which.
        CHECK(pair(P, U, InviteKind::Link, "") == "ok");
        everyone({&P, &U, &C, &Q, &E}, 14);
        CHECK(has(U, pc) && has(U, qp) && has(U, pe));
        P.app->ask_split({pc, qp, pg}, {pe});
        everyone({&P, &U});
        CHECK(U.heard("split_asked") && U.app->split().state == "asking" && U.app->split().mine == std::vector<std::string>{pe});
        U.app->agree_split();
        everyone({&P, &U, &C, &Q, &E}, 14);
        CHECK(P.app->linked().empty() && U.app->linked().empty());
        CHECK_MSG(in(C, pc, P) && !in(C, pc, U) && in(E, pe, U) && !in(E, pe, P) && !in(Q, qp, U), "each kept its own");
        E.app->post(pe, "to the laptop", E.now);
        everyone({&P, &U, &E});
        CHECK(U.said(pe).back() == "to the laptop");
    }
    // 21. Releases: each signature an engine Observation; a member who signs
    //     two different releases as one version is equivocation, kept in
    //     the engine's Integrity.
    {
        std::vector<std::unique_ptr<sg::net::SigningKey>> members;
        std::vector<std::string> keys;
        for (std::uint8_t i = 0; i < 3; ++i) {
            sg::net::Seed s{};
            s.fill(std::uint8_t(0x70 + i));
            members.push_back(std::make_unique<sg::net::SigningKey>(s));
            keys.push_back(hex(Bytes(members.back()->public_key().begin(), members.back()->public_key().end())));
        }
        const auto seen = [&](int who, std::uint64_t version, std::uint8_t body) {
            sg::net::Observation o;
            o.peer = keys[std::size_t(who)];
            o.context = key_from_hex("574c43b2f14b8293deb3fa1c3a83e477fd68b4acec22c0ed31785a0f14219ca1");
            o.sequence = version;
            o.object = "p-chat";
            o.parameter = "release";
            o.discrete = true;
            o.conflict = "release";
            o.payload = Bytes(32, body);
            o.sign(*members[std::size_t(who)]);
            Key32 h{};
            h.fill(body);
            return A.app->release_seen(keys, 2, version, h, keys[std::size_t(who)], o.signature);
        };
        CHECK(seen(0, 2, 0x11) == "accepted" && seen(1, 2, 0x11) == "accepted");
        CHECK_MSG(seen(0, 2, 0x11) == "duplicate", "the same signature again: a duplicate");
        CHECK_MSG(seen(0, 2, 0x22) == "equivocation" && A.app->release_forks() == 1, "one member signs another release 2: equivocation, kept");
        Key32 forged{};
        forged.fill(0x33);
        CHECK_MSG(A.app->release_seen(keys, 2, 3, forged, keys[2], sg::net::Signature{}) == "invalid", "a signature that does not hold is invalid");
    }
    return sgchat_test::finish("sgchat_app");
}
