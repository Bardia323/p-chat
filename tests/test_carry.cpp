// The native carrier (bot/Carry): the same frames and the same answers as
// web/carry.js (tests/direct_checks.mjs), on a network of devices made of
// queues: carrying one link deep, mail kept and given, bounds, and carried
// within the chat (protocol 13) - never through someone not in it.
#include "Carry.hpp"
#include "chat/Crypto.hpp"
#include "check.hpp"

#include <deque>
#include <map>
#include <memory>
#include <set>
#include <tuple>

using namespace bot;
using chat::Bytes;
using chat::Key32;

namespace {
std::uint64_t clock_ms = 1000;
Bytes rnd(std::size_t n, int b) {
    Bytes out(n);
    for (std::size_t i = 0; i < n; ++i) out[i] = std::uint8_t((b * 31 + i * 7) & 255);
    return out;
}
Key32 key(int b) {
    const auto r = rnd(32, b);
    Key32 k{};
    std::copy(r.begin(), r.end(), k.begin());
    return k;
}
Bytes env(int b, Key32 mailbox, std::size_t size = 1 + 32 + 72 + 1024) {
    auto e = rnd(size, b);
    e[0] = 2;
    std::copy(mailbox.begin(), mailbox.end(), e.begin() + 1);
    return e;
}

struct Net;
struct Phone {
    std::string name;
    std::unique_ptr<Carry> carry;
    std::map<std::string, Held> kept;
    std::vector<std::pair<Key32, Bytes>> heard;
    std::vector<Bytes> opened;
};
struct Net {
    std::set<std::string> links;
    std::deque<std::tuple<std::string, std::string, Bytes>> queue;
    std::map<std::string, std::unique_ptr<Phone>> phones;
    std::map<std::string, std::vector<Room>> rooms;
    std::map<std::string, std::vector<Key32>> boxes, members;
    std::set<std::string> selfish;
    bool relaying_r = false;
    Phone& add(const std::string& name) {
        auto p = std::make_unique<Phone>();
        p->name = name;
        auto* me = p.get();
        CarryIo io;
        io.send = [this, name](const std::string& to, const Bytes& f) {
            if (!links.count(name + "|" + to)) return false;
            queue.emplace_back(to, name, f);
            return true;
        };
        io.peers = [this, name] {
            std::vector<std::string> out;
            for (const auto& l : links)
                if (l.rfind(name + "|", 0) == 0) out.push_back(l.substr(name.size() + 1));
            return out;
        };
        io.rooms = [this, name] { return rooms[name]; };
        io.mailboxes = [this, name] { return boxes[name]; };
        io.members = [this, name] { return members[name]; };
        io.signal_in = [me](const Key32& room, const Bytes& box) { me->heard.push_back({room, box}); };
        io.open = [me](const Bytes& e) { me->opened.push_back(e); return std::string("accepted"); };
        io.helping = [this, name] { return !selfish.count(name); };
        io.relaying = [this, name] { return name == "r" && relaying_r; };
        io.put = [me](const Held& h) { me->kept[h.key] = h; };
        io.drop = [me](const std::string& k) { me->kept.erase(k); };
        io.now = [] { return clock_ms; };
        p->carry = std::make_unique<Carry>(io, std::vector<Held>{});
        phones[name] = std::move(p);
        return *me;
    }
    void link(const std::string& a, const std::string& b) { links.insert(a + "|" + b), links.insert(b + "|" + a); }
    void cut(const std::string& a, const std::string& b) { links.erase(a + "|" + b), links.erase(b + "|" + a); }
    std::vector<std::string> flush() {
        std::vector<std::string> out;
        while (!queue.empty()) {
            auto [to, from, f] = queue.front();
            queue.pop_front();
            out.push_back(phones[to]->carry->frame(from, f));
        }
        return out;
    }
    void round() {
        for (auto& [_, p] : phones) p->carry->tick();
        flush(), flush();
    }
};
bool has(const std::vector<std::string>& v, const std::string& s) { return std::find(v.begin(), v.end(), s) != v.end(); }
}  // namespace

int main() {
    // ---- one link deep (protocol 10) ----
    {
        Net net;
        auto &X = net.add("x"), &Y = net.add("y"), &H = net.add("h");
        const Room xy{key(1), key(2)}, y{key(1), key(3)};
        net.rooms["y"] = {y};
        net.link("x", "h"), net.link("y", "h");
        net.round();
        CHECK(X.carry->signal("y", xy.room, y.label, rnd(300, 4)) == 1);
        const auto passed = net.flush();
        CHECK_MSG(has(passed, "passed") && Y.heard.size() == 1 && Y.heard[0].second == rnd(300, 4), "a contact passes a signal on to the phone in that room");
        X.carry->signal("y", xy.room, key(9), rnd(300, 5));
        CHECK_MSG(has(net.flush(), "nowhere") && Y.heard.size() == 1, "a signal for a room no linked phone is in goes nowhere");
        // Held for a phone that is away, given when it asks, dropped when opened.
        const auto mY = key(7);
        const auto e1 = env(11, mY);
        net.cut("y", "h");
        CHECK(X.carry->hold(e1, "y") == 1);
        CHECK_MSG(net.flush()[0] == "held" && H.kept.size() == 1, "a contact keeps an envelope for a phone that is away");
        X.carry->hold(e1, "y");
        net.flush();
        CHECK_MSG(H.kept.size() == 1, "the same envelope twice is kept once");
        CHECK_MSG(H.carry->frame("x", carry_frames::hold(rnd(500, 1))) == "refused", "what is not a relay's envelope is not kept");
        net.boxes["y"] = {mY};
        net.link("y", "h");
        clock_ms += 9000;
        net.round();
        CHECK_MSG(Y.opened.size() == 1 && Y.opened[0] == e1 && H.kept.empty(), "back, the phone is given what was kept, and it is dropped");
        // Bounds.
        int full = 0;
        for (int i = 0; i < 130; ++i) {
            if (i % 50 == 0) clock_ms += 61000;
            if (H.carry->frame("x", carry_frames::hold(env(100 + i, key(50 + i)))) == "full") ++full;
        }
        CHECK_MSG(H.kept.size() == 128 && full == 2, "one giver has at most 128 kept");
        int refused = 0;
        for (int i = 0; i < 70; ++i)
            if (H.carry->frame("y", carry_frames::hold(env(400 + i, key(90)))) == "refused") ++refused;
        CHECK_MSG(refused == 10, "at most 60 a minute from one giver");
        clock_ms += carry_limits().ttl + 1;
        H.carry->tick();
        CHECK_MSG(H.kept.empty(), "kept 14 days at most");
        net.selfish.insert("h");
        const auto before = Y.heard.size();
        X.carry->signal("y", xy.room, y.label, rnd(300, 12));
        CHECK_MSG(has(net.flush(), "refused") && Y.heard.size() == before, "a phone that does not carry passes nothing on");
        CHECK_MSG(H.carry->frame("x", carry_frames::signal(xy.room, rnd(10, 1))) == "ok", "but takes what is for it");
    }
    // ---- a device that relays (protocol 11) ----
    {
        Net net;
        net.relaying_r = true;
        auto &R = net.add("r"), &A = net.add("a");
        net.add("b");
        const auto ab = key(61);
        net.rooms["a"] = {{ab, key(62)}};
        net.rooms["b"] = {{ab, key(63)}};
        net.link("r", "a"), net.link("r", "b");
        net.round(), net.round();
        CHECK_MSG(A.carry->relays() == std::vector<std::string>{"r"}, "a device that relays says so");
        int kept = 0;
        for (int i = 0; i < 200; ++i)
            if (R.carry->frame("a", carry_frames::hold(env(800 + i, key(90 + i)))) == "held") ++kept;
        CHECK_MSG(kept == 200, "a device that relays keeps a relay's share");
    }
    // ---- carried within the chat (protocol 13) ----
    {
        Net net;
        auto &A = net.add("a"), &M1 = net.add("m1"), &M2 = net.add("m2"), &B = net.add("b"), &O = net.add("o");
        const auto g = key(150);
        for (auto [n, b] : std::vector<std::pair<std::string, int>>{{"a", 151}, {"m1", 152}, {"m2", 153}, {"b", 154}}) net.rooms[n] = {{g, key(b)}};
        net.rooms["o"] = {{key(160), key(161)}};
        const auto mB = key(170);
        for (const auto* n : {"a", "m1", "m2"}) net.members[n] = {mB};
        net.boxes["b"] = {mB};
        net.link("a", "o"), net.link("o", "m2"), net.link("m2", "b");
        net.round();
        A.carry->signal("b", g, key(154), rnd(300, 171));
        CHECK_MSG(has(net.flush(), "nowhere") && B.heard.empty(), "a signal goes no further than a contact who is not in the chat");
        net.cut("o", "m2"), net.link("a", "m1"), net.link("m1", "m2");
        net.round();
        A.carry->signal("b", g, key(154), rnd(300, 172));
        std::vector<std::string> out;
        for (int i = 0; i < 4; ++i)
            for (const auto& s : net.flush()) out.push_back(s);
        CHECK_MSG(has(out, "hopped") && has(out, "passed") && B.heard.size() == 1 && B.heard[0].second == rnd(300, 172),
                  "through the chat's members, over more than one link, it reaches its device");
        CHECK_MSG(O.carry->frame("a", carry_frames::hop(4, {}, g, key(154), rnd(9, 1))) == "refused", "a hop not of its chats is refused by a contact");
        CHECK_MSG(M2.carry->frame("m1", carry_frames::hop(1, {9}, g, key(231), rnd(9, 1))) == "nowhere", "a hop with no link left is passed on no more");
        CHECK_MSG(M2.carry->frame("m1", carry_frames::hop(1, {9}, g, key(231), rnd(9, 1))) == "seen", "a hop seen already is passed on no more");
        net.cut("m2", "b");
        const auto eB = env(180, mB);
        CHECK(A.carry->hold(eB, "b") >= 1);
        net.flush();
        CHECK_MSG(M1.kept.size() == 1 && O.kept.size() == 1, "kept by those it was given to");
        clock_ms += 16000;
        net.round();
        CHECK_MSG(M2.kept.size() == 1, "a member gathers it from another for its chat's device");
        CHECK_MSG(O.carry->frame("m1", carry_frames::share(envelope_handle(eB), eB)) == "refused", "a contact not in the chat takes none of its mail");
        const auto big = env(181, mB, 1 + 32 + 72 + 262144);
        M1.carry->frame("a", carry_frames::hold(big));
        clock_ms += 16000;
        net.round();
        CHECK_MSG(M1.kept.size() == 2 && M2.kept.size() == 1, "a file's pieces are not gathered, only messages");
        net.cut("m1", "m2"), net.link("m2", "b");
        clock_ms += 9000;
        net.round();
        CHECK_MSG(B.opened.size() == 1 && B.opened[0] == eB && M2.kept.empty(), "back, the device takes it from the member that gathered it");
        net.cut("m2", "b"), net.link("m1", "m2");
        clock_ms += 16000;
        net.round();
        CHECK_MSG(M1.kept.size() == 1 && !M1.kept.count(chat::hex(mB) + chat::hex(envelope_handle(eB))), "one opened is dropped by the other members who keep it");
        // Frames refused as in JavaScript.
        CHECK(O.carry->frame("a", carry_frames::hop(5, {}, g, key(1), rnd(7, 6))) == "refused");
        CHECK(O.carry->frame("a", carry_frames::hop(0, {}, g, key(1), rnd(7, 6))) == "refused");
        CHECK(O.carry->frame("a", Bytes{99, 0}) == "refused");
        auto cut = carry_frames::gather({mB}, {}, {});
        cut.pop_back();
        CHECK(O.carry->frame("a", cut) == "refused");
    }
    return sgchat_test::finish("sgchat_carry");
}
