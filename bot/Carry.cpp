#include "Carry.hpp"
#include "chat/Crypto.hpp"

#include <algorithm>

namespace bot {

using namespace chat;
namespace k = carry_kind;
using Handle = std::array<std::uint8_t, 16>;

namespace {
constexpr std::uint64_t ROOMS_AGAIN_MS = 60000, ASK_EVERY_MS = 8000, GATHER_EVERY_MS = 15000, SEEN_MS = 5 * 60000,
                        SERVED_WRITE_MS = 3600000;
constexpr std::uint8_t FLAG_RELAYS = 1;

template <class T>
std::string hx(const T& b) { return hex(Bytes(b.begin(), b.end())); }
std::string hx(const Bytes& b) { return hex(b); }
// What a relay would take: a sealed message (version 1 or 2) of one of its sizes.
bool sized(std::size_t n) { return n == 1 + 32 + 72 + 1024 || n == 1 + 32 + 72 + 16384 || n == 1 + 32 + 72 + 262144; }
bool small(std::size_t n) { return n == 1 + 32 + 72 + 1024 || n == 1 + 32 + 72 + 16384; }
bool envelope_ok(const Bytes& e) { return !e.empty() && (e[0] == 1 || e[0] == 2) && sized(e.size()); }
Key32 mailbox_of(const Bytes& e) {
    Key32 m{};
    std::copy(e.begin() + 1, e.begin() + 33, m.begin());
    return m;
}
Key32 key_at(Reader& r) { return r.key(); }
Bytes from_hex(const std::string& s) {
    Bytes out(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = std::uint8_t(std::stoi(s.substr(2 * i, 2), nullptr, 16));
    return out;
}
}  // namespace

CarryLimits carry_limits() { return {}; }
CarryLimits relaying_limits() {
    CarryLimits l;
    l.held = 4096, l.held_bytes = 256u << 20, l.per_giver = 1024, l.pass_per_minute = 600, l.hold_per_minute = 300;
    return l;
}

Handle envelope_handle(const Bytes& env) {
    const auto h = blake2b(16, {}, env);
    Handle out{};
    std::copy(h.begin(), h.end(), out.begin());
    return out;
}

namespace carry_frames {
Bytes rooms(const std::vector<Room>& rs) {
    Writer w;
    w.u8(k::rooms).u16(std::uint16_t(rs.size()));
    for (const auto& r : rs) w.raw(r.room).raw(r.label);
    return w.take();
}
Bytes pass(const Key32& room, const Key32& label, const Bytes& box) {
    return Writer().u8(k::pass).raw(room).raw(label).u32(std::uint32_t(box.size())).raw(box).take();
}
Bytes signal(const Key32& room, const Bytes& box) { return Writer().u8(k::signal).raw(room).u32(std::uint32_t(box.size())).raw(box).take(); }
Bytes hold(const Bytes& env) { return Writer().u8(k::hold).raw(env).take(); }
Bytes ask(const std::vector<Key32>& ids) {
    Writer w;
    w.u8(k::ask).u16(std::uint16_t(ids.size()));
    for (const auto& m : ids) w.raw(m);
    return w.take();
}
Bytes given(const Key32& mailbox, const Handle& handle, const Bytes& env) { return Writer().u8(k::given).raw(mailbox).raw(handle).raw(env).take(); }
Bytes taken(const Key32& mailbox, const std::vector<Handle>& handles) {
    Writer w;
    w.u8(k::taken).raw(mailbox).u16(std::uint16_t(handles.size()));
    for (const auto& h : handles) w.raw(h);
    return w.take();
}
Bytes relays(std::uint8_t flags) { return Writer().u8(k::relays).u8(flags).take(); }
Bytes serves(const std::vector<std::pair<Room, bool>>& ds) {
    Writer w;
    w.u8(k::serves).u16(std::uint16_t(ds.size()));
    for (const auto& [r, now] : ds) w.raw(r.room).raw(r.label).u8(now ? 1 : 0);
    return w.take();
}
Bytes gather(const std::vector<Key32>& mailboxes, const std::vector<Handle>& have, const std::vector<Handle>& gone) {
    Writer w;
    w.u8(k::gather).u16(std::uint16_t(mailboxes.size()));
    for (const auto& m : mailboxes) w.raw(m);
    w.u16(std::uint16_t(have.size()));
    for (const auto& h : have) w.raw(h);
    w.u16(std::uint16_t(gone.size()));
    for (const auto& h : gone) w.raw(h);
    return w.take();
}
Bytes share(const Handle& handle, const Bytes& env) { return Writer().u8(k::share).raw(handle).raw(env).take(); }
Bytes hop(std::uint8_t left, const Handle& id, const Key32& room, const Key32& label, const Bytes& box) {
    return Writer().u8(k::hop).u8(left).raw(id).raw(room).raw(label).u32(std::uint32_t(box.size())).raw(box).take();
}
}  // namespace carry_frames

namespace f = carry_frames;

Carry::Carry(CarryIo io, std::vector<Held> kept) : io_(std::move(io)) {
    for (auto& h : kept) held_[h.key] = std::move(h);
}

CarryLimits Carry::limits() const { return io_.relaying && io_.relaying() ? relaying_limits() : carry_limits(); }

std::vector<std::string> Carry::relays() const {
    std::vector<std::string> out;
    for (const auto& p : io_.peers()) {
        const auto it = relaying_.find(p);
        if (it != relaying_.end() && (it->second & FLAG_RELAYS)) out.push_back(p);
    }
    return out;
}

bool Carry::allowed(const std::string& peer, const std::string& what, std::size_t per) {
    const auto now = io_.now();
    auto& r = rates_[peer + ":" + what];
    if (r.second == 0 || now - r.first > 60000) {
        r = {now, 1};
        return true;
    }
    if (r.second >= per) return false;
    ++r.second;
    return true;
}

bool Carry::own_room(const std::string& room) const {
    for (const auto& r : io_.rooms())
        if (hx(r.room) == room) return true;
    return false;
}

void Carry::remember(std::uint64_t now) {
    for (const auto& [p, m] : reach_)
        for (const auto& key : m) {
            auto it = served_.find(key);
            if (it != served_.end() && it->second.peer == p && now - it->second.at < SERVED_WRITE_MS) continue;
            Served s;
            const auto b = from_hex(key);
            std::copy(b.begin(), b.begin() + 32, s.where.room.begin());
            std::copy(b.begin() + 32, b.end(), s.where.label.begin());
            s.peer = p, s.at = now;
            served_[key] = s;
        }
    for (auto it = served_.begin(); it != served_.end();)
        it = now - it->second.at > carry_limits().ttl ? served_.erase(it) : std::next(it);
}

std::vector<Room> Carry::serves_for(const std::string& peer, std::vector<bool>& now_flags) const {
    std::vector<Room> out;
    const auto mine = reach_.find(peer);
    if (mine == reach_.end()) return out;
    std::set<std::string> rooms, here;
    for (const auto& key : mine->second) rooms.insert(key.substr(0, 64));
    for (const auto& [p, m] : reach_)
        if (p != peer) here.insert(m.begin(), m.end());
    for (const auto& [key, s] : served_) {
        if (out.size() >= carry_limits().serves) break;
        if (rooms.count(key.substr(0, 64)) && !mine->second.count(key) && s.peer != peer) {
            out.push_back(s.where);
            now_flags.push_back(here.count(key) > 0);
        }
    }
    return out;
}

void Carry::opened(const std::vector<Handle>& handles) {
    const auto now = io_.now();
    std::set<std::string> gone;
    for (const auto& h : handles) {
        const auto s = hx(h);
        gone.insert(s);
        if (!gone_.count(s)) gone_order_.push_back(s);
        gone_[s] = now;
    }
    while (gone_order_.size() > carry_limits().handles) gone_.erase(gone_order_.front()), gone_order_.erase(gone_order_.begin());
    for (auto it = held_.begin(); it != held_.end();) {
        if (gone.count(hx(it->second.handle))) {
            io_.drop(it->first);
            it = held_.erase(it);
        } else {
            ++it;
        }
    }
}

void Carry::tick() {
    const auto now = io_.now();
    const auto list = io_.peers();
    const std::set<std::string> peers(list.begin(), list.end());
    const auto forget = [&](auto& m) {
        for (auto it = m.begin(); it != m.end();) it = peers.count(it->first) ? std::next(it) : m.erase(it);
    };
    forget(reach_), forget(told_), forget(relaying_), forget(serving_), forget(flagged_), forget(serves_told_), forget(gathered_),
        forget(shared_), forget(asked_);
    const bool relaying = io_.relaying && io_.relaying();
    if (relaying) remember(now);
    else served_.clear();
    for (auto it = seen_.begin(); it != seen_.end();) it = now - it->second > SEEN_MS ? seen_.erase(it) : std::next(it);
    for (auto it = gone_.begin(); it != gone_.end();) it = now - it->second > carry_limits().ttl ? gone_.erase(it) : std::next(it);
    auto mine = io_.rooms();
    if (mine.size() > carry_limits().rooms) mine.resize(carry_limits().rooms);
    std::string said;
    for (const auto& r : mine) said += hx(r.room) + hx(r.label) + ",";
    const auto ids = io_.mailboxes();
    // The gathers due: the mailboxes of the other devices of this device's
    // chats, what it keeps for them already, and what was opened.
    std::vector<Bytes> gathers;
    const bool helping = io_.helping();
    std::vector<std::string> due;
    for (const auto& p : peers)
        if (helping && io_.members && now - (gathered_.count(p) ? gathered_[p] : 0) > GATHER_EVERY_MS) due.push_back(p);
    if (!due.empty()) {
        const auto want = io_.members();
        if (!want.empty()) {
            std::set<std::string> wanted;
            for (const auto& m : want) wanted.insert(hx(m));
            std::vector<Handle> have, gone;
            for (const auto& [key, h] : held_)
                if (wanted.count(hx(h.mailbox)) && have.size() < carry_limits().handles) have.push_back(h.handle);
            for (const auto& s : gone_order_) {
                if (gone.size() >= carry_limits().handles) break;
                const auto b = from_hex(s);
                Handle h{};
                std::copy(b.begin(), b.end(), h.begin());
                gone.push_back(h);
            }
            for (std::size_t i = 0; i < want.size(); i += carry_limits().ask_ids)
                gathers.push_back(f::gather(std::vector<Key32>(want.begin() + i, want.begin() + std::min(want.size(), i + carry_limits().ask_ids)),
                                            i ? std::vector<Handle>{} : have, i ? std::vector<Handle>{} : gone));
        }
    }
    for (const auto& p : peers) {
        auto& t = told_[p];
        if (t.at == 0 || t.said != said || now - t.at > ROOMS_AGAIN_MS) {
            if (io_.send(p, f::rooms(mine))) t = {now, said};
        }
        if (std::find(due.begin(), due.end(), p) != due.end()) {
            gathered_[p] = now;
            for (const auto& g : gathers) io_.send(p, g);
        }
        if (!ids.empty() && now - asked_[p] > ASK_EVERY_MS) {
            asked_[p] = now;
            for (std::size_t i = 0; i < ids.size(); i += carry_limits().ask_ids)
                io_.send(p, f::ask(std::vector<Key32>(ids.begin() + i, ids.begin() + std::min(ids.size(), i + carry_limits().ask_ids))));
        }
        // That this device relays, said once it does (and once it stops).
        const std::uint8_t flags = relaying ? FLAG_RELAYS : 0;
        auto fl = flagged_.find(p);
        if ((flags || fl != flagged_.end()) &&
            (fl == flagged_.end() || fl->second.said != std::to_string(flags) || now - fl->second.at > ROOMS_AGAIN_MS) && io_.send(p, f::relays(flags)))
            flagged_[p] = {now, std::to_string(flags)};
        if (relaying) {
            std::vector<bool> nows;
            const auto list2 = serves_for(p, nows);
            std::string key;
            std::vector<std::pair<Room, bool>> ds;
            for (std::size_t i = 0; i < list2.size(); ++i) {
                key += hx(list2[i].room) + hx(list2[i].label) + (nows[i] ? "1" : "0");
                ds.push_back({list2[i], nows[i]});
            }
            auto was = serves_told_.find(p);
            if ((!ds.empty() || was != serves_told_.end()) &&
                (was == serves_told_.end() || was->second.said != key || now - was->second.at > ROOMS_AGAIN_MS) && io_.send(p, f::serves(ds)))
                serves_told_[p] = {now, key};
        }
    }
    // Kept too long: gone.
    for (auto it = held_.begin(); it != held_.end();) {
        if (now - it->second.at > carry_limits().ttl) {
            io_.drop(it->first);
            it = held_.erase(it);
        } else {
            ++it;
        }
    }
}

int Carry::signal(const std::string& peer, const Key32& room, const Key32& label, const Bytes& box) {
    int n = 0;
    const auto r = hx(room);
    Handle id{};
    const auto rnd = random_bytes(16);
    std::copy(rnd.begin(), rnd.end(), id.begin());
    seen_[hx(id)] = io_.now();
    seen_order_.push_back(hx(id));
    for (const auto& p : io_.peers()) {
        bool member = false;
        const auto it = reach_.find(p);
        if (it != reach_.end())
            for (const auto& key : it->second) member = member || key.compare(0, 64, r) == 0;
        const auto frame = p == peer ? f::signal(room, box) : member ? f::hop(std::uint8_t(carry_limits().hops), id, room, label, box) : f::pass(room, label, box);
        if (io_.send(p, frame)) ++n;
    }
    return n;
}

int Carry::hold(const Bytes& env, const std::string& recipient, bool relays_only) {
    const auto rs = relays();
    const std::set<std::string> relaying(rs.begin(), rs.end());
    std::vector<std::string> order(rs.begin(), rs.end());
    if (!relays_only)
        for (const auto& p : io_.peers())
            if (!relaying.count(p)) order.push_back(p);
    int n = 0;
    for (const auto& p : order) {
        if (p == recipient || (n >= 3 && !relaying.count(p))) continue;
        if (io_.send(p, f::hold(env))) ++n;
    }
    return n;
}

std::string Carry::keep(const std::string& peer, const Bytes& env, const Key32& mailbox, const Handle& handle) {
    const auto L = limits();
    const auto key = hx(mailbox) + hx(handle);
    if (held_.count(key)) return "ok";
    std::size_t bytes = 0, from = 0;
    for (const auto& [_, h] : held_) bytes += h.envelope.size(), from += h.from == peer;
    if (held_.size() >= L.held || bytes + env.size() > L.held_bytes || from >= L.per_giver) return "full";
    Held h{key, mailbox, handle, env, peer, io_.now()};
    io_.put(h);
    held_[key] = std::move(h);
    ++done.held;
    return "held";
}

std::string Carry::frame(const std::string& peer, const Bytes& bytes) {
    if (bytes.empty()) return "refused";
    const auto kind = bytes[0];
    const Bytes body(bytes.begin() + 1, bytes.end());
    const bool helping = io_.helping();
    try {
        Reader r(body);
        switch (kind) {
        case k::rooms: {
            const unsigned n = r.u16();
            if (n > carry_limits().rooms || body.size() != 2 + n * 64) return "refused";
            const bool fresh = !reach_.count(peer);
            std::set<std::string> m, rooms;
            for (unsigned i = 0; i < n; ++i) {
                const auto room = key_at(r), label = key_at(r);
                m.insert(hx(room) + hx(label));
                if (own_room(hx(room))) rooms.insert(hx(room));
            }
            reach_[peer] = m;
            // A member of a chat of this device's newly linked: the chat's
            // other devices not linked here may be found again through it.
            if (fresh && helping && !rooms.empty() && io_.near) io_.near(peer, std::vector<std::string>(rooms.begin(), rooms.end()));
            return "ok";
        }
        case k::pass: {
            const auto room = key_at(r), label = key_at(r);
            const auto n = r.u32();
            if (body.size() != 68 + n || n > carry_limits().box || !n) return "refused";
            const auto box = r.raw(n);
            if (!helping || !allowed(peer, "pass", limits().pass_per_minute)) return "refused";
            const auto key = hx(room) + hx(label);
            for (const auto& [p, m] : reach_) {
                if (p == peer || !m.count(key)) continue;
                if (!io_.send(p, f::signal(room, box))) return "busy";
                ++done.passed;
                return "passed";
            }
            return "nowhere";
        }
        case k::signal: {
            const auto room = key_at(r);
            const auto n = r.u32();
            if (body.size() != 36 + n || n > carry_limits().box || !n) return "refused";
            io_.signal_in(room, r.raw(n));
            return "ok";
        }
        case k::hold: {
            if (!envelope_ok(body)) return "refused";
            if (!helping || !allowed(peer, "hold", limits().hold_per_minute)) return "refused";
            return keep(peer, body, mailbox_of(body), envelope_handle(body));
        }
        case k::ask: {
            const unsigned n = r.u16();
            if (n > carry_limits().ask_ids || body.size() != 2 + n * 32) return "refused";
            if (!helping || !allowed(peer, "ask", 30)) return "refused";
            std::set<std::string> want;
            for (unsigned i = 0; i < n; ++i) want.insert(hx(key_at(r)));
            std::size_t given = 0;
            for (const auto& [_, h] : held_)
                if (want.count(hx(h.mailbox)) && io_.send(peer, f::given(h.mailbox, h.handle, h.envelope))) ++given;
            done.given += given;
            return std::to_string(given);
        }
        case k::given: {
            const auto mailbox = key_at(r);
            const auto handle = r.fixed<16>();
            const auto env = r.raw(r.left());
            if (!envelope_ok(env) || mailbox_of(env) != mailbox) return "refused";
            // Opened (or not ours to keep): the one who kept it drops it.
            if (envelope_handle(env) != handle) return "refused";
            const auto status = io_.open(env);
            if (status != "need_turn" && status != "later") {
                io_.send(peer, f::taken(mailbox, {handle}));
                opened({handle});
            }
            return status;
        }
        case k::taken: {
            const auto mailbox = key_at(r);
            const unsigned n = r.u16();
            if (n > 256 || body.size() != 34 + n * 16) return "refused";
            std::vector<Handle> hs;
            for (unsigned i = 0; i < n; ++i) {
                const auto h = r.fixed<16>();
                if (held_.count(hx(mailbox) + hx(h))) hs.push_back(h);
            }
            opened(hs);
            return "ok";
        }
        case k::relays: {
            if (body.size() != 1 || (body[0] & ~FLAG_RELAYS)) return "refused";
            relaying_[peer] = body[0];
            return "ok";
        }
        case k::serves: {
            const unsigned n = r.u16();
            if (n > carry_limits().serves || body.size() != 2 + n * 65) return "refused";
            std::vector<std::pair<Room, bool>> ds;
            for (unsigned i = 0; i < n; ++i) {
                Room d{key_at(r), key_at(r)};
                const auto now = r.u8();
                if (now > 1) return "refused";
                ds.push_back({d, now == 1});
            }
            // Believed only of a contact that said it relays.
            if (!(relaying_.count(peer) && (relaying_[peer] & FLAG_RELAYS))) return "refused";
            serving_[peer] = ds;
            std::set<std::string> near;
            for (const auto& [d, now] : ds)
                if (now) near.insert(hx(d.room));
            if (!near.empty() && io_.near) io_.near(peer, std::vector<std::string>(near.begin(), near.end()));
            return "ok";
        }
        case k::gather: {
            std::vector<std::string> want_list;
            std::vector<Handle> have, gone;
            const unsigned n = r.u16();
            if (n > carry_limits().ask_ids) return "refused";
            for (unsigned i = 0; i < n; ++i) want_list.push_back(hx(key_at(r)));
            const unsigned h = r.u16();
            if (h > carry_limits().handles) return "refused";
            for (unsigned i = 0; i < h; ++i) have.push_back(r.fixed<16>());
            const unsigned g = r.u16();
            if (g > carry_limits().handles) return "refused";
            for (unsigned i = 0; i < g; ++i) gone.push_back(r.fixed<16>());
            if (r.left()) return "refused";
            if (!helping || !allowed(peer, "gather", 12)) return "refused";
            opened(gone);
            const std::set<std::string> want(want_list.begin(), want_list.end());
            std::set<std::string> skip;
            for (const auto& x : have) skip.insert(hx(x));
            for (const auto& [s, _] : gone_) skip.insert(s);
            auto& gave = shared_[peer];
            std::size_t sent = 0;
            for (const auto& [_, held] : held_) {
                if (sent >= carry_limits().share_per_gather) break;
                const auto hs = hx(held.handle);
                if (held.from == peer || !want.count(hx(held.mailbox)) || skip.count(hs) || gave.count(hs) || !small(held.envelope.size())) continue;
                if (!io_.send(peer, f::share(held.handle, held.envelope))) break;
                gave.insert(hs);
                ++sent;
            }
            done.shared += sent;
            return std::to_string(sent);
        }
        case k::share: {
            const auto handle = r.fixed<16>();
            const auto env = r.raw(r.left());
            if (!envelope_ok(env) || !small(env.size())) return "refused";
            // Kept only for a device of one of this device's own chats, and
            // only what was not opened already.
            if (!helping || !io_.members || envelope_handle(env) != handle) return "refused";
            const auto mailbox = mailbox_of(env);
            bool ours = false;
            for (const auto& m : io_.members()) ours = ours || m == mailbox;
            if (!ours) return "refused";
            if (gone_.count(hx(handle))) return "gone";
            return keep(peer, env, mailbox, handle);
        }
        case k::hop: {
            const auto left = r.u8();
            const auto id = r.fixed<16>();
            const auto room = key_at(r), label = key_at(r);
            const auto n = r.u32();
            if (left < 1 || left > carry_limits().hops || body.size() != 85 + n || n > carry_limits().box || !n) return "refused";
            const auto box = r.raw(n);
            const auto ids = hx(id), rs = hx(room), ls = hx(label);
            if (seen_.count(ids)) return "seen";
            seen_[ids] = io_.now();
            seen_order_.push_back(ids);
            while (seen_order_.size() > carry_limits().seen) seen_.erase(seen_order_.front()), seen_order_.erase(seen_order_.begin());
            for (const auto& own : io_.rooms())
                if (hx(own.room) == rs && hx(own.label) == ls) {
                    io_.signal_in(room, box);
                    return "ok";
                }
            // Passed on only by a member of the chat, only to its members.
            if (!helping || !own_room(rs) || !allowed(peer, "pass", limits().pass_per_minute)) return "refused";
            for (const auto& [p, m] : reach_) {
                if (p == peer || !m.count(rs + ls)) continue;
                if (!io_.send(p, f::signal(room, box))) return "busy";
                ++done.passed;
                return "passed";
            }
            if (left <= 1) return "nowhere";
            std::size_t sent = 0;
            for (const auto& [p, m] : reach_) {
                if (p == peer) continue;
                bool member = false;
                for (const auto& key : m) member = member || key.compare(0, 64, rs) == 0;
                if (member && io_.send(p, f::hop(std::uint8_t(left - 1), id, room, label, box))) ++sent;
            }
            done.hopped += sent;
            return sent ? "hopped" : "nowhere";
        }
        default: return "refused";
        }
    } catch (const std::exception&) {
        return "refused";  // cut short
    }
}

}  // namespace bot
