#include "Host.hpp"
#include "chat/Crypto.hpp"
#include "chat/Seal.hpp"

#include <sys/stat.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>

namespace bot {

namespace fs = std::filesystem;
using namespace chat;

namespace {
Bytes read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(f), {});
}
// Written whole or not at all, readable by this user only.
void write_file(const fs::path& p, const Bytes& b) {
    const auto tmp = p.string() + ".new";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(b.data()), std::streamsize(b.size()));
        if (!f) throw std::runtime_error("host: cannot write " + tmp);
    }
    ::chmod(tmp.c_str(), 0600);
    fs::rename(tmp, p);
}
void append_file(const fs::path& p, const Bytes& b) {
    std::ofstream f(p, std::ios::binary | std::ios::app);
    f.write(reinterpret_cast<const char*>(b.data()), std::streamsize(b.size()));
    ::chmod(p.c_str(), 0600);
}
sg::net::Seed seed_of(const Key32& k) {
    sg::net::Seed s{};
    std::copy(k.begin(), k.end(), s.begin());
    return s;
}
void sleep_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }
std::uint64_t wall_ms() {
    return std::uint64_t(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}
}  // namespace

Host::Host(std::string dir, std::string name, std::string relay_url)
    : dir_(std::move(dir)), name_(std::move(name)), relay_(std::move(relay_url)) {
    fs::create_directories(fs::path(dir_) / "ratchet");
    fs::create_directories(fs::path(dir_) / "records");
    fs::create_directories(fs::path(dir_) / "messages");
    ::chmod(dir_.c_str(), 0700);
    const auto keys = fs::path(dir_) / "device";
    auto k = read_file(keys);
    if (k.empty()) {
        k = random_bytes(64);
        write_file(keys, k);
    }
    if (k.size() != 64) throw std::runtime_error("host: " + keys.string() + " is not a device key");
    std::copy(k.begin(), k.begin() + 32, seed_.begin());
    std::copy(k.begin() + 32, k.end(), secret_.begin());
    const sg::net::SigningKey key(seed_of(seed_));
    std::copy(key.public_key().begin(), key.public_key().end(), device_.sign.begin());
    device_.agree = x25519_public(secret_);
    app_ = std::make_unique<App>(device_, name_);
    // What was kept: the records, then each conversation's messages again.
    for (const auto& e : fs::directory_iterator(fs::path(dir_) / "records")) {
        if (e.path().extension() == ".new") continue;
        app_->load(read_file(e.path()));
    }
    for (const auto& id : app_->conversations()) {
        const auto log = read_file(fs::path(dir_) / "messages" / id);
        Reader r(log);
        while (r.left()) {
            const auto obs = r.long_bytes(1 << 20);
            const auto body = r.long_bytes(1 << 20);
            const auto time = r.u64();
            try {
                app_->replay(id, obs, body, time);
            } catch (const std::exception&) {
            }  // a message of a past committee
        }
    }
    app_->start();
}

namespace {
std::string name_of_key(const Key32& pub) { return hex(Bytes(pub.begin(), pub.end())); }
}  // namespace

Key32 Host::fresh_ratchet_key() {
    const auto f = random_key();
    write_file(fs::path(dir_) / "ratchet" / name_of_key(x25519_public(f)), Bytes(f.begin(), f.end()));
    return f;
}
Key32 Host::ratchet_private(const Key32& pub) const {
    if (pub == device_.agree) return secret_;
    const auto b = read_file(fs::path(dir_) / "ratchet" / name_of_key(pub));
    if (b.size() != 32) throw std::runtime_error("host: a ratchet key this device no longer has");
    return key_from(b);
}

void Host::keep(const Notice& n) {
    if ((n.kind == "message" || n.kind == "sent") && !n.data.empty())
        append_file(fs::path(dir_) / "messages" / n.conversation,
                    Writer().long_bytes(n.data, 1 << 20).long_bytes(n.kind == "sent" ? n.body : Bytes{}, 1 << 20).u64(n.time).take());
    if (n.kind == "retire_key") fs::remove(fs::path(dir_) / "ratchet" / n.text);
    if (n.kind == "removed_contact") {
        fs::remove(fs::path(dir_) / "records" / n.conversation);
        fs::remove(fs::path(dir_) / "messages" / n.conversation);
    }
}

void Host::carry(const Outgoing& o) {
    if (o.kind == "envelope") {
        const auto env = encode(Envelope{o.version, o.mailbox, seal(o.purpose, o.agree, o.plain)});
        if (std::getenv("SGCHAT_HOST_TRACE")) std::fprintf(stderr, "host %s sends %s seq %llu mailbox_ok %d\n", name_.c_str(), o.purpose.c_str(), (unsigned long long)o.sequence, int(o.mailbox_ok));
        if (o.purpose == "message" && !o.mailbox_ok) waiting_.push_back({o.conversation, o.peer, env});
        else relay_.put(env);
    } else if (o.kind == "pair") {
        relay_.pair_post(o.token, seal(o.purpose, o.agree, o.plain));
    } else if (o.kind == "pair_done") {
        relay_.pair_done(o.token);
    } else if (o.kind == "post") {
        relay_.put(o.box);
    }  // "signal": no live link here
}

void Host::answer(std::uint64_t now_ms) {
    for (int round = 0; round < 16; ++round) {
        app_->pump(now_ms);
        bool any = false;
        for (const auto& s : app_->take_starts()) {
            any = true;
            const auto ss = x25519(secret_, s.agree);
            if (s.second) {
                const auto f = fresh_ratchet_key();
                app_->started(s.conversation, s.peer, ss, x25519_public(f), x25519(f, s.agree));
            } else {
                app_->started(s.conversation, s.peer, ss);
            }
        }
        for (const auto& s : app_->take_signs()) {
            any = true;
            app_->signed_(s.id, sg::net::SigningKey(seed_of(seed_)).sign(s.statement));
        }
        for (const auto& id : app_->take_dirty()) write_file(fs::path(dir_) / "records" / id, app_->save(id));
        for (const auto& o : app_->take_outgoing()) {
            any = true;
            carry(o);
        }
        for (const auto& n : app_->take_notices()) {
            any = true;
            keep(n);
            if (on_notice) on_notice(n);
        }
        if (!any) return;
    }
}

std::string Host::open(const Bytes& env) {
    const auto shared = x25519(secret_, App::ephemeral_of(env));
    auto r = app_->open(env, shared);
    if (r.status == "need_turn") {
        try {
            const auto f = fresh_ratchet_key();
            r = app_->open(env, shared, Turn{x25519(ratchet_private(r.own), r.dh), x25519_public(f), x25519(f, r.dh)});
            if (r.status != "accepted" && r.status != "duplicate" && r.status != "equivocation")
                fs::remove(fs::path(dir_) / "ratchet" / name_of_key(x25519_public(f)));
        } catch (const std::exception& e) {
            r.status = "refused";
            r.why = e.what();
        }
    }
    if (std::getenv("SGCHAT_HOST_TRACE") && r.status == "refused") std::fprintf(stderr, "host %s refused: %s\n", name_.c_str(), r.why.c_str());
    return r.status;
}

void Host::fetch() {
    for (const auto& item : relay_.fetch(app_->mailboxes())) {
        if (!item.envelope.empty() && item.envelope[0] == 18) continue;  // a channel's posts: a bot reads none
        const auto status = open(item.envelope);
        if (std::getenv("SGCHAT_HOST_TRACE")) std::fprintf(stderr, "host %s opened %s\n", name_.c_str(), status.c_str());
        if (status != "need_turn") relay_.del(item.mailbox, {item.handle});
        answer(wall_ms());
    }
}

void Host::step(std::uint64_t now_ms) {
    answer(now_ms);
    fetch();
    for (auto it = waiting_.begin(); it != waiting_.end();) {
        const auto ids = app_->conversations();
        const bool known = std::find(ids.begin(), ids.end(), it->conversation) != ids.end();
        if (!known) it = waiting_.erase(it);
        else if (app_->takes_mail(it->conversation, it->peer)) relay_.put(it->envelope), it = waiting_.erase(it);
        else ++it;
    }
    answer(now_ms);
}

std::string Host::pair(const std::string& link, const std::string& code, const std::string& call, int wait_ms) {
    const auto hash = link.find('#');
    const auto invite = invite_from_fragment(hash == std::string::npos ? link : link.substr(hash + 1));
    const auto asking = app_->ask(invite, normalize_code(code), name_, call, true);
    answer(wall_ms());
    const auto box = reply_mailbox(invite, device_id(device_));
    for (int waited = 0; waited < wait_ms; waited += 500) {
        for (const auto& item : relay_.fetch({box})) {
            const auto r = app_->take_accept(asking, item.envelope, x25519(secret_, App::ephemeral_of(item.envelope)));
            relay_.del(item.mailbox, {item.handle});
            answer(wall_ms());
            return r;
        }
        sleep_ms(500);
    }
    return "no answer";
}

App::Inviting Host::invite(InviteKind kind, const std::string& conversation) {
    return app_->invite(kind, relay_.url(), conversation);
}

std::string Host::take_pairing(const App::Inviting& inv, int wait_ms) {
    for (int waited = 0; waited < wait_ms; waited += 500) {
        for (const auto& box : relay_.pair_fetch(inv.invite.token)) {
            const auto r = app_->take_request(inv, box, x25519(secret_, box_ephemeral(box)));
            answer(wall_ms());
            return r;
        }
        sleep_ms(500);
    }
    return "no request";
}

}  // namespace bot
