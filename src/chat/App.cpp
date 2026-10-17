#include "chat/App.hpp"
#include "chat/World.hpp"
#include "chat/Board.hpp"
#include "sg/net/Exchange.hpp"
#include "chat/Crypto.hpp"
#include "chat/Media.hpp"
#include "chat/Signal.hpp"
#include "chat/Window.hpp"
#include "sg/core/Text.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstring>

namespace chat {

namespace {
constexpr std::uint32_t mailbox_days_back = 15;
constexpr std::uint64_t epoch_every = 50;
constexpr std::size_t early_limit = 64;

ConversationId conversation_of(const std::string& hexid) {
    const auto b = unhex(hexid);
    if (b.size() != 16) throw Refused("chat: a conversation id is 16 bytes");
    ConversationId c{};
    std::copy(b.begin(), b.end(), c.begin());
    return c;
}
Nonce random_nonce() {
    const auto r = random_bytes(24);
    Nonce n{};
    std::copy(r.begin(), r.end(), n.begin());
    return n;
}
std::string emoji_text(const std::array<int, 4>& f) {
    std::string glyphs, names;
    for (int i : f) {
        glyphs += emoji()[std::size_t(i)].first;
        if (!names.empty()) names += ", ";
        names += emoji()[std::size_t(i)].second;
    }
    return glyphs + " (" + names + ")";
}
sg::net::Message protocol(sg::net::MessageKind kind, const std::string& from) {
    sg::net::Message m;
    m.kind = kind;
    m.from = from;
    m.to = "members";
    return m;
}
void members_out(Writer& w, const std::vector<Member>& ms) {
    w.u8(std::uint8_t(ms.size()));
    for (const auto& m : ms) w.raw(m.device.sign).raw(m.device.agree).u8(member_flags(m));
}
std::vector<Member> members_in(Reader& r) {
    std::vector<Member> out;
    const auto n = r.u8();
    for (unsigned i = 0; i < n; ++i) {
        Device d;
        d.sign = r.key();
        d.agree = r.key();
        out.push_back(member_of(d, r.u8()));
    }
    return out;
}
}  // namespace

// One conversation's machinery outside the world.
struct App::Conversation {
    ConversationId id{};
    std::string hexid, state, name;
    Side side = Side::Friend;
    Kind kind = Kind::Direct;
    // Sender keys (groups, channels): this device's, and each member's.
    std::optional<SenderKey> own_key;
    std::map<std::string, SenderChain> their_keys;
    std::vector<Bytes> parked;  // sender-key frames that came before their key
    // The agreed history of this lineage (encoded Finalized, oldest first),
    // and what it starts from (zero, or a recovery's decision).
    std::vector<Bytes> epochs;
    sg::net::Digest chain_root{};
    // A recovery under way.
    struct Pending {
        Recovery rec;
        std::vector<sg::net::Attestation> votes;
        bool mine = false, approved = false, refused = false;
        std::string asker;
        Bytes invite, request;
        Key32 pair_key{};
    };
    std::optional<Pending> pending;
    // A recovered device's: the ids the agreed history names, which history given to it must be.
    std::set<sg::net::Digest> agreed_ids;

    struct Secret {
        std::uint64_t generation = 0;
        Key32 key{};
    };
    std::vector<Secret> secrets;  // oldest first; the last is in use
    std::uint64_t generation = 0;
    std::vector<Member> members;
    sg::net::Committee committee;
    std::unique_ptr<sg::net::Integrity> integrity;
    std::unique_ptr<sg::net::Agreement> agreement;
    Bytes journal;
    std::optional<Finalized> last;
    Cutoffs cutoffs;
    std::uint32_t epoch_day = 0;
    std::map<std::string, Ratchet> ratchets;
    std::set<std::string> starting;
    std::map<std::string, std::vector<std::function<void()>>> held;
    std::map<std::string, std::uint64_t> signal_in;
    std::uint64_t signal_out = 0;
    std::vector<sg::net::Observation> log;
    struct Mine {
        std::string kind;
        Bytes body;
        std::uint64_t time = 0;
        std::set<std::string> acked;
    };
    std::map<std::uint64_t, Mine> mine;
    // The secret each member was last heard signalling under: a device that
    // missed a rekey (live only, away) is answered in the room it is in.
    std::map<std::string, std::uint64_t> heard_in;
    std::vector<std::pair<Key32, std::uint64_t>> to_ack;
    bool removed = false;
    // A history epoch under way.
    struct Run {
        sg::net::EpochContext context;
        sg::net::Observation statement;
        std::optional<sg::net::Problem> problem;
        sg::net::Proposal proposal;
        std::optional<sg::net::VerifiedResult> verified;
        std::vector<sg::net::Attestation> votes;
        bool voted = false, differs = false;
    };
    std::optional<Run> run;
    std::vector<sg::net::Message> early;
    bool proposing = false, nudged = false;
    // A change of members under way (a handoff).
    struct Change {
        bool add = true, mine = false, endorsed = false, asked = false;
        std::vector<Member> members;  // who comes in, or goes
        std::string asker, via;       // via: the direct conversation a group invite goes through
        std::optional<sg::net::Handoff> handoff;
        std::vector<Member> next;
        std::vector<sg::net::Attestation> votes;
        // A further device's pairing, answered once the handoff is done.
        Bytes invite, request;
        Key32 pair_key{};
    };
    std::optional<Change> change;

    // Linked devices (Link.hpp). The handoff that brought in the generation
    // it is at: what a linked device is given to take it up (the last epoch
    // before it, the endorsed handoff with the next members, the members before).
    Bytes join_last, join_ask;
    std::vector<Member> join_before;
    // This device is leaving it (unlinked): asked to be taken out, by handoff.
    bool leaving = false;
    // The agreed history this device still lacks before the epoch it began
    // from: the id of the epoch it waits for, going back.
    sg::net::Digest chain_expect{};
    bool chain_older = false;
    // Asked of the owner's side, and when (a device_ask, said again in a while).
    std::map<std::string, std::uint64_t> asked;
    // The owner's side: devices its members asked to add or take out, in turn.
    std::deque<DeviceAsk> asks;
    // The self conversation's: devices that said they left the link, and a
    // split of the chats under way.
    std::set<std::string> unlinked;
    struct Split {
        bool mine = false;  // asked by this device
        std::string with;
        std::vector<std::string> keeps, gives;  // this device's view
    };
    std::optional<Split> split;

    const Member* member(const std::string& peer) const {
        for (const auto& m : members)
            if (peer_of(m.device) == peer) return &m;
        return nullptr;
    }
    sg::net::Digest context() const { return conversation_context(id, generation); }
    bool group() const { return kind == Kind::Group; }
    bool changes(const Member& m) const {
        if (!change) return false;
        for (const auto& x : change->members)
            if (x.device == m.device) return true;
        return false;
    }
    sg::net::Verify verify() const { return history_verify(id); }
};

App::App(Device self, std::string name) : self_(self), peer_(peer_of(self)), name_(std::move(name)), id_(device_id(self)) {
    build_world(graph_);
    engine_ = std::make_unique<sg::Engine>(graph_);
    engine_->set_strict(true);
}
App::~App() = default;
void App::rename(const std::string& name) {
    if (name.size() > 64) throw Refused("chat: a name is at most 64 bytes");
    name_ = name;
}

App::Conversation& App::conv(const std::string& id) {
    const auto found = conversations_.find(id);
    if (found == conversations_.end()) throw Refused("chat: no such conversation");
    return *found->second;
}
const App::Conversation& App::conv(const std::string& id) const {
    const auto found = conversations_.find(id);
    if (found == conversations_.end()) throw Refused("chat: no such conversation");
    return *found->second;
}

void App::sign(Bytes statement, std::function<void(const sg::net::Signature&)> then) {
    signs_.emplace(next_sign_++, std::make_pair(std::move(statement), std::move(then)));
}
std::vector<SignAsk> App::take_signs() {
    std::vector<SignAsk> out;
    for (const auto& [id, s] : signs_) out.push_back({id, s.first});
    return out;
}
void App::signed_(std::uint64_t id, const sg::net::Signature& signature) {
    const auto found = signs_.find(id);
    if (found == signs_.end()) return;
    auto [statement, then] = std::move(found->second);
    signs_.erase(found);
    // The host's signature is checked before anything is built on it.
    if (!sg::net::check_signature(self_.sign, statement, signature)) {
        notices_.push_back({"warning", "", "", "a signature from this device's key did not check"});
        return;
    }
    then(signature);
}
std::vector<StartAsk> App::take_starts() { return std::exchange(starts_, {}); }
std::vector<Outgoing> App::take_outgoing() { return std::exchange(outgoing_, {}); }
std::vector<Notice> App::take_notices() { return std::exchange(notices_, {}); }
std::vector<std::string> App::take_dirty() {
    std::vector<std::string> out(dirty_.begin(), dirty_.end());
    dirty_.clear();
    return out;
}
std::vector<std::string> App::conversations() const {
    std::vector<std::string> out;
    for (const auto& [id, c] : conversations_) out.push_back(id), (void)c;
    return out;
}
const sg::State& App::state(const std::string& conversation) const { return graph_.state(conv(conversation).state); }
std::string App::name_of(const std::string& c) const {
    const auto* n = graph_.state(conv(c).state).params().text("name");
    return n ? *n : conv(c).name;
}
std::string App::introduced_as(const std::string& c) const {
    const auto* n = graph_.state(conv(c).state).params().text("introduced");
    return n ? *n : std::string();
}
void App::set_delivery(const std::string& id, DeliveryMode mode) {
    auto& c = conv(id);
    engine_->send(c.state, {c.state + ".delivery", delivery_args(int(mode))});
    settle();
    post_kind(c, "delivery", encode(mode));
    dirty_.insert(id);
}
DeliveryMode App::delivery(const std::string& id) const {
    return graph_.state(conv(id).state).params().get_or<std::int64_t>("mailbox", 0) ? DeliveryMode::Mailbox : DeliveryMode::Live;
}
bool App::takes_mail(const std::string& id, const std::string& peer) const {
    const auto* e = graph_.state(conv(id).state).find(sg::Key("d" + peer));
    return e && e->params.get_or<std::int64_t>("mailbox", 0) == 1;
}
void App::rename_contact(const std::string& id, const std::string& name) {
    auto& c = conv(id);
    if (name.empty() || name.size() > 64) throw Refused("chat: a name is 1..64 bytes");
    engine_->send(c.state, {c.state + ".rename", rename_args(name)});
    settle();
    c.name = name;
    dirty_.insert(id);
    // Named so on this person's other devices too.
    if (auto* s = self_conv(); s && c.kind != Kind::Self && !siblings().empty()) post_kind(*s, "link_name", encode(LinkName{c.id, name}));
}
std::vector<Member> App::members_of(const std::string& c) const { return conv(c).members; }
bool App::removed(const std::string& c) const { return conv(c).removed; }
std::uint64_t App::generation_of(const std::string& c) const { return conv(c).generation; }

Key32 App::secret_now(const Conversation& c) const { return c.secrets.back().key; }

void App::settle() {
    if (!started_) return;
    for (int i = 0; i < 4; ++i) engine_->tick(0);
    while (!said_.empty()) {
        const auto said = said_.front();
        said_.pop_front();
        outgoing_said(said);
    }
}

void App::listen(Conversation& c) {
    const auto conversation = c.hexid;
    // The listener only writes down what the conversation said.
    graph_.state(c.state).bus().subscribe(c.state + ".outgoing", [this, conversation](const sg::Event& e) {
        auto p = e.args;
        p.set("conversation", conversation);
        said_.push_back(p);
    });
}

void App::set_members(Conversation& c, std::uint64_t generation, std::vector<Member> members) {
    c.generation = generation;
    c.members = std::move(members);
    c.committee = committee_of(c.id, generation, c.members, c.group());
    c.integrity = std::make_unique<sg::net::Integrity>(c.committee);
    // What was said under an older generation is a replay now.
    if (generation > 0) c.integrity->retire_before(generation);
}

void App::ask_starts(Conversation& c) {
    if (c.kind == Kind::Channel) return;  // posts go through the relay, under the channel's key
    for (const auto& m : c.members) {
        const auto p = peer_of(m.device);
        if (p == peer_ || c.ratchets.count(p) || c.starting.count(p)) continue;
        c.starting.insert(p);
        starts_.push_back({c.hexid, p, m.device.agree, !first_of(id_, device_id(m.device))});
    }
}
void App::started(const std::string& conversation, const std::string& peer, const Key32& ss, const Key32& fresh,
                  const Key32& fresh_shared) {
    auto& c = conv(conversation);
    const auto* m = c.member(peer);
    if (!m || c.ratchets.count(peer)) return;
    const auto their = device_id(m->device);
    const auto seed = ratchet_seed(secret_now(c), ss, id_, their);
    if (first_of(id_, their)) c.ratchets[peer] = start_first(seed, self_.agree, m->device.agree, ss);
    else c.ratchets[peer] = start_second(seed, self_.agree, m->device.agree, ss, fresh, fresh_shared);
    c.starting.erase(peer);
    dirty_.insert(c.hexid);
    flush_held(c, peer);
}
void App::flush_held(Conversation& c, const std::string& peer) {
    auto found = c.held.find(peer);
    if (found == c.held.end()) return;
    auto waiting = std::move(found->second);
    c.held.erase(found);
    for (auto& f : waiting) f();
}

App::Conversation& App::make_conversation(const ConversationId& id, const std::string& name, Side side,
                                          const Key32& secret, std::uint64_t secret_generation,
                                          std::uint64_t generation, const std::vector<Member>& members,
                                          const std::string& introduced, Kind kind) {
    auto c = std::make_unique<Conversation>();
    c->id = id;
    c->hexid = hex(id);
    c->state = conversation_state(id);
    c->name = name;
    c->side = side;
    c->kind = kind;
    c->secrets.push_back({secret_generation, secret});
    c->epoch_day = day_;  // a conversation's first day counts as its last epoch's
    set_members(*c, generation, members);
    std::vector<Member> pinned;
    for (const auto& m : members)
        if (peer_of(m.device) != peer_) pinned.push_back(m);
    const auto args = contact_add_args(id, name, side, generation, pinned, introduced, int(kind));
    if (started_) {
        engine_->send("contacts", {"contact.add", args});
        settle();
        if (!graph_.contains(c->state)) throw Refused("chat: the conversation was not made");
    } else {
        const auto made = chat::make_conversation(graph_, args);
        if (!made.get_or<bool>("ok", false)) throw Refused("chat: " + made.get_or<std::string>("why", "not made"));
    }
    auto& ref = *c;
    const auto persist = [this, cid = c->hexid](const Bytes& b) { persist_agreement(conv(cid), b); };
    if (generation == 0) c->agreement = std::make_unique<sg::net::Agreement>(c->committee, sg::net::Digest{}, 0, persist);
    conversations_[c->hexid] = std::move(c);
    listen(ref);
    ask_starts(ref);
    dirty_.insert(ref.hexid);
    index_mailboxes();
    if (started_) connect_members(ref);
    return ref;
}

// ---- keeping -------------------------------------------------------------

Bytes App::save(const std::string& id) const {
    const auto& c = conv(id);
    Writer w("sgchat.conversation.v1");
    w.raw(c.id).short_text(c.name).u8(std::uint8_t(c.side));
    w.u8(std::uint8_t(c.secrets.size()));
    for (const auto& s : c.secrets) w.u64(s.generation).raw(s.key);
    w.u64(c.generation);
    members_out(w, c.members);
    w.long_bytes(Bytes(), 0);
    const auto text = sg::to_text(graph_.state(c.state));
    w.long_bytes(Bytes(text.begin(), text.end()), 1 << 20);
    w.long_bytes(c.journal, 1 << 20);
    w.raw(c.agreement ? c.agreement->previous() : sg::net::Digest{}).u64(c.agreement ? c.agreement->next_tick() : 0);
    w.u8(c.last ? 1 : 0);
    if (c.last) w.long_bytes(encode(*c.last), 1 << 22);
    w.u32(c.epoch_day);
    w.u16(std::uint16_t(c.ratchets.size()));
    for (const auto& [p, r] : c.ratchets) w.short_text(p).long_bytes(encode(r), 1 << 20);
    w.u64(c.signal_out).u16(std::uint16_t(c.signal_in.size()));
    for (const auto& [p, n] : c.signal_in) w.short_text(p).u64(n);
    w.u8(c.removed ? 1 : 0);
    w.u8(std::uint8_t(c.kind)).u8(c.own_key ? 1 : 0);
    if (c.own_key) w.short_bytes(encode(*c.own_key));
    w.u16(std::uint16_t(c.their_keys.size()));
    for (const auto& [p, k] : c.their_keys) {
        w.short_text(p).short_bytes(encode(k.key)).u16(std::uint16_t(k.skipped.size()));
        for (const auto& [i, mk] : k.skipped) w.u32(i).raw(mk);
    }
    w.u16(std::uint16_t(c.parked.size()));
    for (const auto& f : c.parked) w.long_bytes(f, 1 << 20);
    w.u32(std::uint32_t(c.epochs.size()));
    for (const auto& e : c.epochs) w.long_bytes(e, 1 << 22);
    w.raw(c.chain_root);
    w.u8(c.pending ? 1 : 0);
    if (c.pending) {
        const auto& p = *c.pending;
        w.raw(encode(p.rec)).u16(std::uint16_t(p.votes.size()));
        for (const auto& v : p.votes) w.raw(encode(v));
        w.u8(p.mine).u8(p.approved).u8(p.refused).short_text(p.asker).long_bytes(p.invite, 4096).long_bytes(p.request, 4096).raw(p.pair_key);
    }
    w.u32(std::uint32_t(c.agreed_ids.size()));
    for (const auto& id : c.agreed_ids) w.raw(id);
    // A change under way is kept, so a reload does not strand a sealed generation.
    w.u8(c.change ? 1 : 0);
    if (c.change) {
        const auto& ch = *c.change;
        w.u8(ch.add).u8(ch.mine).u8(ch.endorsed).u8(ch.asked);
        members_out(w, ch.members);
        w.short_text(ch.asker).short_text(ch.via);
        w.u8(ch.handoff ? 1 : 0);
        if (ch.handoff) w.long_bytes(encode(*ch.handoff), 1 << 22);
        members_out(w, ch.next);
        w.u16(std::uint16_t(ch.votes.size()));
        for (const auto& v : ch.votes) w.raw(encode(v));
        w.long_bytes(ch.invite, 4096).long_bytes(ch.request, 4096).raw(ch.pair_key);
    }
    // Protocol 11: linked devices (a record without it is read as before).
    w.u8(11).long_bytes(c.join_last, 1 << 22).long_bytes(c.join_ask, 1 << 22);
    members_out(w, c.join_before);
    w.u8(c.leaving ? 1 : 0).raw(c.chain_expect).u8(c.chain_older ? 1 : 0);
    w.u16(std::uint16_t(c.unlinked.size()));
    for (const auto& p : c.unlinked) w.short_text(p);
    w.u8(c.split ? 1 : 0);
    if (c.split) {
        w.u8(c.split->mine ? 1 : 0).short_text(c.split->with);
        for (const auto* list : {&c.split->keeps, &c.split->gives}) {
            w.u16(std::uint16_t(list->size()));
            for (const auto& id : *list) w.short_text(id);
        }
    }
    return w.take();
}

void App::load(const Bytes& record) {
    if (started_) throw Refused("chat: records are loaded before the start");
    Reader r(record, "sgchat.conversation.v1");
    const auto id = r.fixed<16>();
    const auto name = r.short_text(64);
    const auto side = r.u8();
    if (side > 1) throw Refused("chat: unknown side");
    std::vector<Conversation::Secret> secrets;
    const auto ns = r.u8();
    for (unsigned i = 0; i < ns; ++i) {
        Conversation::Secret s;
        s.generation = r.u64();
        s.key = r.key();
        secrets.push_back(s);
    }
    if (secrets.empty()) throw Refused("chat: a conversation has a secret");
    const auto generation = r.u64();
    const auto members = members_in(r);
    r.long_bytes(0);
    const auto text_bytes = r.long_bytes(1 << 20);
    auto& c = make_conversation(id, name, Side(side), secrets.back().key, secrets.back().generation, generation, members);
    c.secrets = secrets;
    std::string why;
    if (!sg::from_text(graph_.state(c.state), std::string(text_bytes.begin(), text_bytes.end()), &why))
        throw Refused("chat: a kept conversation's state: " + why);
    graph_.keep_default(c.state);
    c.journal = r.long_bytes(1 << 20);
    const auto previous = r.key();
    const auto next_tick = r.u64();
    if (r.u8()) {
        c.last = decode_finalized(r.long_bytes(1 << 22));
        c.cutoffs = checkpoint_cutoffs(c.last->checkpoint);
    }
    c.epoch_day = r.u32();
    const auto nr = r.u16();
    for (unsigned i = 0; i < nr; ++i) {
        const auto p = r.short_text(128);
        c.ratchets[p] = decode_ratchet(r.long_bytes(1 << 20));
        c.starting.erase(p);
    }
    starts_.erase(std::remove_if(starts_.begin(), starts_.end(),
                                 [&](const StartAsk& s) { return s.conversation == c.hexid && c.ratchets.count(s.peer); }),
                  starts_.end());
    c.signal_out = r.u64();
    const auto ni = r.u16();
    for (unsigned i = 0; i < ni; ++i) {
        const auto p = r.short_text(128);
        c.signal_in[p] = r.u64();
    }
    c.removed = r.u8() != 0;
    c.kind = Kind(r.u8());
    if (r.u8()) c.own_key = decode_sender_key(r.short_bytes());
    const auto nk = r.u16();
    for (unsigned i = 0; i < nk; ++i) {
        const auto p = r.short_text(128);
        SenderChain k;
        k.key = decode_sender_key(r.short_bytes());
        const auto ns_ = r.u16();
        for (unsigned j = 0; j < ns_; ++j) {
            const auto it = r.u32();
            k.skipped.emplace_back(it, r.key());
        }
        c.their_keys[p] = k;
    }
    const auto np = r.u16();
    for (unsigned i = 0; i < np; ++i) c.parked.push_back(r.long_bytes(1 << 20));
    const auto ne = r.u32();
    for (std::uint32_t i = 0; i < ne; ++i) c.epochs.push_back(r.long_bytes(1 << 22));
    c.chain_root = r.key();
    if (r.u8()) {
        Conversation::Pending p;
        p.rec = decode_recovery(r);
        const auto nv = r.u16();
        for (unsigned i = 0; i < nv; ++i) p.votes.push_back(decode_attestation(r));
        p.mine = r.u8();
        p.approved = r.u8();
        p.refused = r.u8();
        p.asker = r.short_text(128);
        p.invite = r.long_bytes(4096);
        p.request = r.long_bytes(4096);
        p.pair_key = r.key();
        c.pending = std::move(p);
    }
    const auto na = r.u32();
    for (std::uint32_t i = 0; i < na; ++i) c.agreed_ids.insert(r.key());
    if (c.kind != Kind::Direct) {
        // The committee as the kind counts it (a group's majority).
        set_members(c, c.generation, c.members);
        starts_.erase(std::remove_if(starts_.begin(), starts_.end(),
                                     [&](const StartAsk& s) { return s.conversation == c.hexid && c.kind == Kind::Channel; }),
                      starts_.end());
    }
    if (r.u8()) {
        Conversation::Change ch;
        ch.add = r.u8();
        ch.mine = r.u8();
        ch.endorsed = r.u8();
        ch.asked = r.u8();
        ch.members = members_in(r);
        ch.asker = r.short_text(128);
        ch.via = r.short_text(64);
        if (r.u8()) ch.handoff = decode_handoff(r.long_bytes(1 << 22));
        ch.next = members_in(r);
        const auto nv = r.u16();
        for (unsigned i = 0; i < nv; ++i) ch.votes.push_back(decode_attestation(r));
        ch.invite = r.long_bytes(4096);
        ch.request = r.long_bytes(4096);
        ch.pair_key = r.key();
        c.change = std::move(ch);
    }
    if (r.left()) {
        if (r.u8() != 11) throw Refused("chat: a kept conversation's link part");
        c.join_last = r.long_bytes(1 << 22);
        c.join_ask = r.long_bytes(1 << 22);
        c.join_before = members_in(r);
        c.leaving = r.u8() != 0;
        c.chain_expect = r.key();
        c.chain_older = r.u8() != 0;
        const auto nu = r.u16();
        for (unsigned i = 0; i < nu; ++i) c.unlinked.insert(r.short_text(128));
        if (r.u8()) {
            Conversation::Split sp;
            sp.mine = r.u8() != 0;
            sp.with = r.short_text(128);
            for (auto* list : {&sp.keeps, &sp.gives}) {
                const auto n = r.u16();
                for (unsigned i = 0; i < n; ++i) list->push_back(r.short_text(64));
            }
            c.split = std::move(sp);
        }
    }
    r.end();
    // The agreement as it was left: its predecessor, its next tick and the
    // locks it had cast, read back by the engine (which checks them).
    const auto persist = [this, id = c.hexid](const Bytes& j) { persist_agreement(conv(id), j); };
    const auto world = region_of(c.id);
    if (!c.journal.empty()) c.agreement = std::make_unique<sg::net::Agreement>(locked(c.committee, previous, next_tick, world, c.journal, persist));
    else c.agreement = std::make_unique<sg::net::Agreement>(c.committee, previous, next_tick, persist, next_tick ? world : std::string{});
    dirty_.erase(c.hexid);
}

void App::replay(const std::string& id, const Bytes& observation, const Bytes& body, std::uint64_t time_ms) {
    auto& c = conv(id);
    const auto o = observation_from(observation);
    check_message(o, c.id, o.tick);
    if (!o.authentic(c.committee) && o.tick == c.generation) throw Refused("chat: a kept message does not check");
    c.log.push_back(o);
    // Integrity's memory is rebuilt from what was kept.
    if (o.tick == c.generation) c.integrity->receive(o, c.context(), c.generation);
    if (o.peer == peer_) {
        auto& m = c.mine[o.sequence];
        m.kind = o.parameter;
        m.body = body;
        m.time = time_ms;
    }
}

void App::start() {
    if (started_) return;
    engine_->start();
    started_ = true;
    have_due_ = true;  // what this device has is said to its linked devices at once
    for (auto& [id, c] : conversations_) connect_members(*c), (void)id;
}

void App::persist_agreement(Conversation& c, const Bytes& journal) {
    c.journal = journal;
    dirty_.insert(c.hexid);
}

// ---- time and the pump ----------------------------------------------------

void App::index_mailboxes() {
    mailbox_index_.clear();
    for (const auto& [id, c] : conversations_)
        for (const auto& s : c->secrets)
            for (std::uint32_t d = day_ > mailbox_days_back ? day_ - mailbox_days_back : 0; d <= day_ + 1; ++d) {
                // A channel's reader reads the channel's own mailbox; its publisher has none.
                if (c->kind == Kind::Channel) {
                    if (!c->committee.key(peer_)) mailbox_index_[channel_mailbox(s.key, d)] = id;
                } else {
                    mailbox_index_[mailbox(s.key, id_, d)] = id;
                }
            }
    indexed_day_ = day_;
}
std::vector<Key32> App::mailboxes() const {
    std::vector<Key32> out;
    for (const auto& [m, id] : mailbox_index_) out.push_back(m), (void)id;
    return out;
}
std::vector<Key32> App::mailboxes_of(const std::string& id) const {
    std::vector<Key32> out;
    for (const auto& [m, cid] : mailbox_index_)
        if (cid == id) out.push_back(m);
    return out;
}
Key32 App::mailbox_on(const std::string& id, std::uint32_t day) const { return mailbox(secret_now(conv(id)), id_, day); }
std::pair<Key32, Key32> App::room_of(const std::string& id) const {
    const auto& c = conv(id);
    return {room(secret_now(c)), label(secret_now(c), id_)};
}
std::vector<std::pair<Key32, Key32>> App::rooms_of(const std::string& id) const {
    const auto& c = conv(id);
    std::vector<std::pair<Key32, Key32>> out;
    if (c.removed || c.kind == Kind::Channel) return out;
    for (const auto& s : c.secrets) out.emplace_back(room(s.key), label(s.key, id_));
    return out;
}
std::vector<std::pair<Key32, Key32>> App::rooms() const {
    std::vector<std::pair<Key32, Key32>> out;
    // Every secret still kept: a device that has not had the newest yet is
    // in the room of one before it.
    for (const auto& [id, c] : conversations_)
        if (!c->removed && c->kind != Kind::Channel)
            for (const auto& s : c->secrets) out.emplace_back(room(s.key), label(s.key, id_));
    return out;
}

void App::pump(std::uint64_t now_ms) {
    now_ = now_ms;
    day_ = std::uint32_t(now_ms / 86400000ull);
    if (day_ != indexed_day_ || mailbox_index_.empty()) index_mailboxes();
    settle();
    if (live_) {
        live_->poll();
        receive_live();
        handle_signals();
        // Signals that came before their conversation did: tried again, two minutes at most.
        for (auto it = early_signals_.begin(); it != early_signals_.end();) {
            if (now_ > it->at + 120000 || signal_into(it->room, it->box)) it = early_signals_.erase(it);
            else ++it;
        }
    }
    for (auto& [id, c] : conversations_) {
        if (c->removed) continue;
        if (!c->to_ack.empty() && !(c->change && c->change->endorsed)) {
            AckBody a;
            a.seen = std::exchange(c->to_ack, {});
            if (a.seen.size() > 1024) a.seen.resize(1024);
            post_kind(*c, "ack", encode(a));
        }
        maybe_propose(*c, false);
        continue_change(*c);
        continue_recovery(*c);
        // The owner's side takes its members' asks in turn, one change at a time.
        if (!c->asks.empty() && !c->change && !c->pending && c->side == Side::Owner && proposer_of(c->members) == peer_) {
            const auto a = c->asks.front();
            c->asks.pop_front();
            const auto* there = c->member(peer_of(a.member.device));
            try {
                if (a.add && !there) begin_change(*c, true, {a.member});
                else if (!a.add && there) begin_change(*c, false, {*there});
            } catch (const std::exception& e) {
                notices_.push_back({"warning", id, "", std::string("a device asked for was not changed: ") + e.what()});
            }
        }
        pump_leaving(*c);
    }
    pump_link();
    pump_calls();
    pump_games();
    settle();
}

// ---- the UI -----------------------------------------------------------------

void App::post(const std::string& id, const std::string& text, std::uint64_t time_ms) {
    auto& c = conv(id);
    if (c.removed) {
        notices_.push_back({"warning", id, "", "This device was removed from the conversation."});
        return;
    }
    if (!member_here(id)) throw Refused("chat: only its publisher posts in a channel");
    if (left(id) || c.leaving) throw Refused("chat: this device left this chat");
    if (text.empty() || text.size() > 200000) throw Refused("chat: a message is 1..200000 bytes");
    const auto token = "t" + std::to_string(next_token_++);
    posts_[token] = {id, "text", Bytes(text.begin(), text.end()), time_ms};
    engine_->send(c.state, {c.state + ".post", post_args("text", token)});
    settle();
}
void App::post_kind(Conversation& c, const std::string& kind, const Bytes& body) {
    const auto token = "t" + std::to_string(next_token_++);
    posts_[token] = {c.hexid, kind, body, now_};
    engine_->send(c.state, {c.state + ".post", post_args(kind, token)});
    settle();
}
void App::read(const std::string& id) {
    auto& c = conv(id);
    engine_->send(c.state, {c.state + ".read", {}});
    settle();
    dirty_.insert(id);
}
void App::open_conversation(const std::string& id) {
    sg::Params p;
    p.set("conversation", conv(id).hexid);
    engine_->fire({"contacts.open", p});
    settle();
}
void App::close_conversation(const std::string& id) {
    const auto& c = conv(id);
    if (engine_->current() && engine_->current()->id() == sg::Key(c.state)) engine_->fire(c.state + ".close");
    settle();
}
void App::remove_contact(const std::string& id) {
    auto& c = conv(id);
    close_conversation(id);
    engine_->send("contacts", {"contact.remove", contact_remove_args(c.id)});
    settle();
    if (graph_.contains(c.state)) throw Refused("chat: the conversation was not removed");
    conversations_.erase(id);
    index_mailboxes();
    notices_.push_back({"removed_contact", id, "", ""});
}

// What a conversation said is going out: the message it is, signed, then
// sealed to every other member under the ratchet with each.
void App::outgoing_said(const sg::Params& said) {
    const auto* token = said.text("token");
    const auto* id = said.text("conversation");
    if (!token || !id) return;
    const auto found = posts_.find(*token);
    if (found == posts_.end()) return;
    const std::string cid = std::get<0>(found->second), kind = std::get<1>(found->second);
    const Bytes body = std::get<2>(found->second);
    const std::uint64_t time = std::get<3>(found->second);
    posts_.erase(found);
    auto& c = conv(cid);
    const auto sequence = std::uint64_t(said.num("sequence"));
    auto o = make_message(c.id, c.generation, id_, sequence, kind);
    // In a group or a channel, what is said is said under this device's
    // sender key: one content key from its chain, the same for everyone.
    std::optional<SenderKey> at;
    Key32 content_key{};
    if (c.kind != Kind::Direct && (kind == "text" || kind == "file")) {
        ensure_sender_key(c, false);
        at = *c.own_key;
        content_key = sender_step(*c.own_key);
        dirty_.insert(cid);
    } else {
        content_key = random_key();
    }
    o.payload = seal_content(content_key, random_nonce(), o, Content{time, body});
    sign(o.statement(), [this, cid, o, content_key, body, time, at](const sg::net::Signature& s) mutable {
        if (!conversations_.count(cid)) return;
        auto& c = conv(cid);
        o.signature = s;
        c.log.push_back(o);
        if (o.tick == c.generation) c.integrity->receive(o, c.context(), c.generation);
        auto& m = c.mine[o.sequence];
        m.kind = o.parameter;
        m.body = body;
        m.time = time;
        Notice n{"sent", cid, peer_, ""};
        n.sequence = o.sequence;
        n.time = time;
        n.type = o.parameter;
        n.data = observation_bytes(o);
        n.body = body;
        if (!options_of(cid).no_recovery) n.key = Bytes(content_key.begin(), content_key.end());
        notices_.push_back(n);
        dirty_.insert(cid);
        if (at) {
            if (c.change && c.change->endorsed) return;  // said again under the next generation
            if (c.kind == Kind::Channel) {
                // Put once at the channel's mailbox; every reader fetches it.
                const auto frame = encode_frame(SenderFrame{id_, at->id, at->iteration, o}, Key32{});
                Outgoing out;
                out.kind = "post";
                out.conversation = cid;
                out.box = channel_envelope(secret_now(c), day_, frame, random_nonce());
                outgoing_.push_back(std::move(out));
            } else {
                for (const auto& m : c.members)
                    if (peer_of(m.device) != peer_) seal_group(c, m, o, *at, content_key);
            }
        } else {
            send_message(c, o, content_key);
        }
        wipe(content_key);
        // A new secret is used from the moment its rekey has gone, sealed
        // to mailboxes under the one before.
        if (o.parameter == "rekey" && c.side == Side::Owner) {
            const auto k = decode_rekey(body);
            if (k.secret_generation > c.secrets.back().generation) {
                c.secrets.push_back({k.secret_generation, k.secret});
                if (c.secrets.size() > 3) c.secrets.erase(c.secrets.begin());
                index_mailboxes();
            }
        }
    });
}

void App::send_message(Conversation& c, sg::net::Observation o, const Key32& content_key, const std::string& only) {
    // While a change of members is sealed, nothing goes out: it is said
    // again under the next generation, to the next members.
    if (c.change && c.change->endorsed) return;
    for (const auto& m : c.members) {
        const auto p = peer_of(m.device);
        if (p == peer_ || (!only.empty() && p != only)) continue;
        if (c.ratchets.count(p)) seal_to(c, m, o, content_key);
        else c.held[p].push_back([this, cid = c.hexid, m, o, content_key] {
            if (conversations_.count(cid)) seal_to(conv(cid), m, o, content_key);
        });
    }
}
void App::seal_to(Conversation& c, const Member& m, const sg::net::Observation& o, const Key32& content_key) {
    const auto p = peer_of(m.device);
    const auto mid = device_id(m.device);
    auto& r = c.ratchets.at(p);
    const auto sent = ratchet_send(r);
    MessageFrame f;
    f.sender = id_;
    f.header = sent.header;
    auto mk = sent.key;
    f.wrapped = wrap(mk, wrap_ad(id_, mid, c.id, o.sequence, o.id(), sent.header), content_key);
    wipe(mk);
    f.message = o;
    Outgoing out;
    out.kind = "envelope";
    out.conversation = c.hexid;
    out.peer = p;
    out.purpose = "message";
    out.agree = m.device.agree;
    out.version = Version::Ratchet;
    out.mailbox = mailbox(secret_now(c), mid, day_);
    out.plain = pad(encode_frame(f, Version::Ratchet, mid));
    out.sequence = o.sequence;
    out.live = true;
    out.mailbox_ok = takes_mail(c.hexid, p);
    out.ping = o.parameter == "text" || o.parameter == "file";
    outgoing_.push_back(std::move(out));
    dirty_.insert(c.hexid);
}
void App::seal_group(Conversation& c, const Member& m, const sg::net::Observation& o, const SenderKey& at, const Key32&) {
    const auto mid = device_id(m.device);
    const auto p = peer_of(m.device);
    Outgoing out;
    out.kind = "envelope";
    out.conversation = c.hexid;
    out.peer = p;
    out.purpose = "message";
    out.agree = m.device.agree;
    out.version = Version::Ratchet;
    out.mailbox = mailbox(secret_now(c), mid, day_);
    out.plain = pad(encode_frame(SenderFrame{id_, at.id, at.iteration, o}, mid));
    out.sequence = o.sequence;
    out.live = true;
    out.mailbox_ok = takes_mail(c.hexid, p);
    out.ping = o.parameter == "text" || o.parameter == "file";
    outgoing_.push_back(std::move(out));
}
// This device's sender key: made when it has none (or must have a fresh one,
// after who is in the conversation changed), and handed to every member over
// the pairwise ratchets in a `sender_key` message - for a channel, kept for
// readers' invites.
void App::ensure_sender_key(Conversation& c, bool fresh) {
    if (c.own_key && !fresh) return;
    if (c.kind == Kind::Channel && !member_here(c.hexid)) return;
    SenderKey k;
    k.id = random_key();
    k.chain = random_key();
    k.iteration = 0;
    c.own_key = k;
    dirty_.insert(c.hexid);
    if (c.kind == Kind::Group) post_kind(c, "sender_key", encode(k));
}

void App::send_control(Conversation& c, Control kind, const Bytes& body, const std::string& only,
                       const std::vector<Member>* to) {
    const auto frame = encode_frame(ControlFrame{id_, std::uint8_t(kind), body});
    for (const auto& m : to ? *to : c.members) {
        const auto p = peer_of(m.device);
        if (p == peer_ || (!only.empty() && p != only)) continue;
        Outgoing out;
        out.kind = "envelope";
        out.conversation = c.hexid;
        out.peer = p;
        out.purpose = "message";
        out.agree = m.device.agree;
        out.version = Version::Ratchet;
        out.mailbox = mailbox(secret_now(c), device_id(m.device), day_);
        out.plain = pad(frame);
        out.live = true;
        out.mailbox_ok = takes_mail(c.hexid, p);
        outgoing_.push_back(std::move(out));
    }
}

// ---- what arrives ---------------------------------------------------------------

Key32 App::ephemeral_of(const Bytes& envelope) { return box_ephemeral(decode_envelope(envelope).box); }

Opened App::open(const Bytes& envelope, const Key32& shared, const std::optional<Turn>& turn) {
    Opened out;
    try {
        const auto e = decode_envelope(envelope);
        if (e.version == Version::PairReply) return {"unknown", "", "a pairing reply"};
        const auto at = mailbox_index_.find(e.mailbox);
        if (at == mailbox_index_.end()) return {"unknown", "", "no conversation of this device has that mailbox"};
        auto& c = conv(at->second);
        out.conversation = c.hexid;
        const auto plain = unpad(open_with("message", shared, self_.agree, e.box));
        if (!plain.empty() && plain[0] == 3) {
            if (e.version != Version::Ratchet || c.kind == Kind::Direct) return {"refused", c.hexid, "a sender-key frame out of place"};
            return sender_frame(c, plain);
        }
        const auto frame = decode_frame(plain, e.version, id_);
        const auto sender = frame.kind == FrameKind::Control ? frame.control.sender : frame.message.sender;
        const auto p = hex(sender);
        const auto* m = c.member(p);
        if (!m) return {"refused", c.hexid, "not a device of this conversation"};
        if (frame.kind == FrameKind::Control) {
            if (e.version != Version::Ratchet) return {"refused", c.hexid, "control without version 2"};
            const auto cid = c.hexid;
            control(c, *m, frame.control);
            dirty_.insert(cid);
            Opened done{"control", cid, ""};
            done.peer = p;
            return done;
        }
        const auto& fm = frame.message;
        const auto& o = fm.message;
        const bool ratchet = c.ratchets.count(p) != 0;
        if (!accepts(e.version, ratchet)) return {"refused", c.hexid, ratchet ? "a message without the ratchet" : "no ratchet yet"};
        Key32 content_key{};
        std::optional<Ratchet> next;
        if (e.version == Version::Ratchet) {
            const auto& r = c.ratchets.at(p);
            if (needs_turn(r, fm.header) && !turn) {
                out.status = "need_turn";
                out.own = r.own;
                out.dh = fm.header.dh;
                return out;
            }
            auto stepped = ratchet_receive(r, fm.header, needs_turn(r, fm.header) ? turn : std::nullopt);
            content_key = unwrap(stepped.second, wrap_ad(sender, id_, c.id, o.sequence, o.id(), fm.header), fm.wrapped);
            wipe(stepped.second);
            next = std::move(stepped.first);
        } else {
            content_key = fm.content_key;
        }
        // Integrity says what an older generation's message is (a replay);
        // one of this generation must also be this conversation's in form.
        if (o.tick == c.generation) check_message(o, c.id, c.generation);
        const auto content = open_content(content_key, o);
        if (next) {
            const auto old = c.ratchets.at(p).own;
            c.ratchets[p] = *next;
            if (old != next->own && old != self_.agree) notices_.push_back({"retire_key", c.hexid, p, hex(old)});
        }
        dirty_.insert(c.hexid);
        auto out_ = deliver(c, o, content, p, content_key);
        wipe(content_key);
        out_.peer = p;
        return out_;
    } catch (const std::exception& ex) {
        out.status = "refused";
        out.why = ex.what();
        return out;
    }
}

Opened App::deliver(Conversation& c, const sg::net::Observation& o, const Content& content, const std::string& p, const Key32& key) {
    switch (c.integrity->receive(o, c.context(), c.generation)) {
    case sg::net::Delivery::Accepted:
        accept_message(c, o, content, key);
        return {"accepted", c.hexid, ""};
    case sg::net::Delivery::Duplicate:
        if (type_of(o.parameter) != Type::Ack && member_here(c.hexid)) c.to_ack.emplace_back(key_from_hex(o.peer), o.sequence);
        return {"duplicate", c.hexid, ""};
    case sg::net::Delivery::Equivocation: {
        Notice n{"equivocation", c.hexid, p, "Two different messages were sent as one. Both are kept."};
        n.sequence = o.sequence;
        const auto& ev = c.integrity->evidence().back();
        n.data = observation_bytes(ev.first);
        n.body = observation_bytes(ev.second);
        notices_.push_back(n);
        return {"equivocation", c.hexid, ""};
    }
    case sg::net::Delivery::Replay:
        return {"refused", c.hexid, "replay"};
    case sg::net::Delivery::Invalid:
        return {"refused", c.hexid, "not authentic"};
    }
    return {"refused", c.hexid, ""};
}

Opened App::sender_frame(Conversation& c, const Bytes& plain) {
    const auto f = decode_sender_frame(plain, c.kind == Kind::Channel ? Key32{} : id_);
    const auto p = hex(f.sender);
    if (!c.member(p)) return {"refused", c.hexid, "not a device of this conversation"};
    const auto found = c.their_keys.find(p);
    if (found == c.their_keys.end() || found->second.key.id != f.key_id) {
        // Its sender key may still be on the way: kept, and tried again when it comes.
        if (c.parked.size() < 256 && std::find(c.parked.begin(), c.parked.end(), plain) == c.parked.end()) c.parked.push_back(plain);
        dirty_.insert(c.hexid);
        return {"waiting", c.hexid, "its sender key has not come yet"};
    }
    auto chain = found->second;
    auto mk = sender_key_at(chain, f.iteration);
    const auto& o = f.message;
    if (o.tick == c.generation) check_message(o, c.id, c.generation);
    const auto content = open_content(mk, o);
    found->second = chain;
    dirty_.insert(c.hexid);
    const auto out = deliver(c, o, content, p, mk);
    wipe(mk);
    return out;
}

Opened App::open_post(const Bytes& envelope) {
    try {
        if (envelope.size() < 33 || envelope[0] != 18) return {"refused", "", "not a channel post"};
        const auto at = mailbox_index_.find(key_from(Bytes(envelope.begin() + 1, envelope.begin() + 33)));
        if (at == mailbox_index_.end()) return {"unknown", "", "no channel of this device has that mailbox"};
        auto& c = conv(at->second);
        for (auto s = c.secrets.rbegin(); s != c.secrets.rend(); ++s) {
            Bytes plain;
            try { plain = open_channel_envelope(s->key, envelope); } catch (const std::exception&) { continue; }
            return sender_frame(c, plain);
        }
        return {"refused", c.hexid, "a post that does not open"};
    } catch (const std::exception& ex) {
        return {"refused", "", ex.what()};
    }
}

void App::accept_message(Conversation& c, const sg::net::Observation& o, const Content& content, const Key32& key) {
    c.log.push_back(o);
    const auto sender = key_from_hex(o.peer);
    int mode = 0;
    if (o.parameter == "delivery") try { mode = int(decode_delivery(content.body)); } catch (const std::exception&) {}
    engine_->send(c.state, {c.state + ".receive", receive_args(sender, o.sequence, o.parameter, mode)});
    settle();
    Notice n{"message", c.hexid, o.peer, ""};
    n.sequence = o.sequence;
    n.time = content.time_ms;
    n.type = o.parameter;
    n.data = observation_bytes(o);
    n.body = content.body;
    if (!options_of(c.hexid).no_recovery) n.key = Bytes(key.begin(), key.end());
    notices_.push_back(n);
    const auto* m = c.member(o.peer);
    const auto type = type_of(o.parameter);
    if (type != Type::Ack && member_here(c.hexid) && c.kind != Kind::Channel) c.to_ack.emplace_back(sender, o.sequence);
    try {
        if (type == Type::Ack) {
            for (const auto& [d, s] : decode_ack(content.body).seen)
                if (d == id_ && c.mine.count(s)) {
                    c.mine[s].acked.insert(o.peer);
                    Notice a{"acked", c.hexid, o.peer, ""};
                    a.sequence = s;
                    notices_.push_back(a);
                }
        } else if (type == Type::DeviceRevoked && m && m->side == Side::Owner) {
            const auto v = decode_revoked(content.body);
            if (v.device == id_) {
                c.removed = true;
                notices_.push_back({"removed", c.hexid, o.peer, "This device was removed. Ask " + name_of(c.hexid) + " for a new key."});
            } else {
                notices_.push_back({"revoked", c.hexid, hex(v.device), ""});
            }
        } else if (type == Type::SenderKey && m && c.kind == Kind::Group) {
            // A member's new sender key: what it says from now on opens.
            c.their_keys[o.peer] = SenderChain{decode_sender_key(content.body), {}};
            auto parked = std::exchange(c.parked, {});
            for (const auto& f : parked) sender_frame(c, f);
        } else if (type == Type::Options && m) {
            const auto op = decode_options(content.body);
            engine_->send(c.state, {c.state + ".options", options_args(!op.no_recovery, op.disappear_s)});
            settle();
            notices_.push_back({"options", c.hexid, o.peer, ""});
        } else if ((type == Type::Call || type == Type::CallJoin) && m) {
            call_message(c, o, *type, content.body, content.time_ms);
        } else if (type == Type::Game && m) {
            if (now_ <= content.time_ms + 120000) game_message(c, o, content.body);
        } else if (type == Type::Stroke && m) {
            if (boards_.count(c.hexid) && graph_.contains(board_state(c.id))) {
                engine_->send(board_state(c.id), {board_state(c.id) + ".stroke", {}});
                settle();
            }
        } else if (type == Type::Push && m) {
            // Where and how to wake that device: checked here, kept by the host.
            decode_push_info(content.body);
            Notice n{"push", c.hexid, o.peer, ""};
            n.body = content.body;
            notices_.push_back(n);
        } else if (type == Type::GroupInvite && m && c.kind == Kind::Direct) {
            join_group(c, o, decode_group_invite(content.body));
        } else if (type == Type::LinkedChat && m && c.kind == Kind::Self && !c.removed) {
            take_linked(c, o, content.body);
        } else if (type == Type::DeviceAsk && m && c.kind != Kind::Self) {
            take_device_ask(c, *m, content.body);
        } else if (type == Type::Unlink && m && c.kind == Kind::Self && !c.removed) {
            take_unlink(c, *m, content.body);
        } else if (type == Type::LinkName && m && c.kind == Kind::Self && !c.removed) {
            const auto n = decode_link_name(content.body);
            const auto found = conversations_.find(hex(n.conversation));
            if (found != conversations_.end() && found->second->kind != Kind::Self) {
                auto& x = *found->second;
                engine_->send(x.state, {x.state + ".rename", rename_args(n.name)});
                settle();
                x.name = n.name;
                dirty_.insert(x.hexid);
                notices_.push_back({"renamed", x.hexid, o.peer, n.name});
            }
        } else if (type == Type::Rekey && m && m->side == Side::Owner) {
            const auto k = decode_rekey(content.body);
            if (k.secret_generation > c.secrets.back().generation) {
                c.secrets.push_back({k.secret_generation, k.secret});
                if (c.secrets.size() > 3) c.secrets.erase(c.secrets.begin());
                index_mailboxes();
                notices_.push_back({"rekeyed", c.hexid, "", ""});
            }
        }
    } catch (const std::exception&) {
        notices_.push_back({"warning", c.hexid, o.peer, "a message body did not read"});
    }
    consider(c);
}

// ---- history -----------------------------------------------------------------

std::uint64_t App::since_epoch(const Conversation& c) const {
    std::uint64_t n = 0;
    for (const auto& o : c.log) {
        const auto found = c.cutoffs.find(key_from_hex(o.peer));
        if (found == c.cutoffs.end() || o.sequence > found->second) ++n;
    }
    return n;
}

void App::maybe_propose(Conversation& c, bool nudge) {
    if (!started_ || c.removed || c.run || c.proposing || !c.agreement || c.kind == Kind::Channel) return;
    if (c.change && c.change->endorsed) return;
    if (proposer_of(c.members) != peer_) return;
    const auto since = since_epoch(c);
    // A handoff extends an epoch its own committee finalized: after one
    // handoff, the next waits for an epoch of the new committee, said or not.
    const bool stale = !c.last || c.last->context.committee != c.committee.id();
    const bool due = since >= epoch_every || (since > 0 && day_ > c.epoch_day) || (nudge && (since > 0 || stale)) ||
                     (c.nudged && (since > 0 || stale));
    if (!due) return;
    c.nudged = false;
    const auto history = history_of(c.log, c.cutoffs);
    const auto ctx = history_context(c.id, c.committee, c.agreement->next_tick(), c.agreement->previous());
    auto statement = history_statement(c.id, ctx, peer_, history);
    c.proposing = true;
    sign(statement.statement(), [this, cid = c.hexid, ctx, statement](const sg::net::Signature& s) mutable {
        if (!conversations_.count(cid)) return;
        auto& c = conv(cid);
        statement.signature = s;
        auto problem = history_problem(ctx, statement);
        auto cert = certificate_for(problem, peer_);
        sign(cert.statement(), [this, cid, ctx, statement, problem, cert](const sg::net::Signature& s2) mutable {
            if (!conversations_.count(cid)) return;
            auto& c = conv(cid);
            c.proposing = false;
            cert.signature = s2;
            Conversation::Run run;
            run.context = ctx;
            run.statement = statement;
            run.problem = problem;
            run.proposal = proposal_for(cert);
            run.verified = c.verify().proposal(problem, c.committee, run.proposal);
            if (!run.verified || !c.agreement || c.agreement->next_tick() != ctx.tick) return;
            auto m = protocol(sg::net::MessageKind::Proposal, peer_);
            m.inputs = {statement};
            m.proposal = run.proposal;
            c.run = std::move(run);
            send_control(c, Control::Epoch, sg::net::encode(m));
            consider(c);
        });
    });
}

void App::consider(Conversation& c) {
    if (!c.run || c.run->voted || c.run->differs) return;
    if (c.change && c.change->endorsed) return;  // a sealed generation votes no more
    switch (compare(decode_history(c.run->statement.payload), c.log, c.cutoffs)) {
    case Agrees::Same: attest(c); break;
    case Agrees::Behind: break;  // the messages it names are still on their way
    case Agrees::Differs:
        c.run->differs = true;
        notices_.push_back({"history_differs", c.hexid, c.run->statement.peer,
                            "This conversation's history differs between devices: a message was dropped, changed or moved."});
        break;
    }
}

void App::attest(Conversation& c) {
    auto& run = *c.run;
    run.voted = true;
    auto vote = attestation_for(*run.verified, peer_);
    sign(vote.statement(), [this, cid = c.hexid, vote](const sg::net::Signature& s) mutable {
        if (!conversations_.count(cid)) return;
        auto& c = conv(cid);
        if (!c.run) return;
        vote.signature = s;
        // The lock is persisted (the host saves this record before it sends
        // anything) and read back by the engine, before the vote goes out.
        const auto& ctx = c.run->context;
        const auto j = journal(c.committee, ctx.previous, ctx.tick, ctx.world, {}, {vote});
        persist_agreement(c, j);
        const auto persist = [this, cid](const Bytes& b) { persist_agreement(conv(cid), b); };
        c.agreement = std::make_unique<sg::net::Agreement>(locked(c.committee, ctx.previous, ctx.tick, ctx.world, j, persist));
        for (const auto& v : c.run->votes) c.agreement->receive(*c.run->verified, v);
        auto m = protocol(sg::net::MessageKind::Attestation, peer_);
        m.proposal.certificate = c.run->proposal.certificate;
        m.attestation = vote;
        send_control(c, Control::Epoch, sg::net::encode(m));
        try_finalize(c);
    });
}

void App::try_finalize(Conversation& c) {
    if (!c.run || !c.run->verified || !c.agreement) return;
    const auto f = c.agreement->finalize(*c.run->verified, c.run->proposal);
    if (!f) return;
    auto m = protocol(sg::net::MessageKind::Finalization, peer_);
    m.finalization = *f;
    send_control(c, Control::Epoch, sg::net::encode(m));
    if (c.agreement->accept(*c.run->problem, c.verify(), *f)) finished(c, *f);
}

void App::finished(Conversation& c, const sg::net::Finalization& f) {
    c.last = Finalized{c.run->context, c.run->statement, f, c.run->verified->checkpoint()};
    c.epochs.push_back(encode(*c.last));
    c.cutoffs = checkpoint_cutoffs(c.last->checkpoint);
    c.epoch_day = day_;
    c.run.reset();
    c.early.clear();
    dirty_.insert(c.hexid);
    Notice n{"history", c.hexid, "", ""};
    n.sequence = c.last->context.tick;
    notices_.push_back(n);
    continue_change(c);
}

void App::control(Conversation& c, const Member& from, const ControlFrame& f) {
    const auto p = peer_of(from.device);
    switch (Control(f.kind)) {
    case Control::Epoch: {
        const auto m = sg::net::decode_message(f.body);
        if (m.from != p) throw Refused("chat: an epoch message from someone else");
        if (m.kind == sg::net::MessageKind::Proposal) {
            if (!c.agreement || c.run || m.inputs.size() != 1) return;
            const auto& statement = m.inputs[0];
            if (statement.tick != c.agreement->next_tick() || statement.peer != p ||
                proposer_of(c.members) != p)
                return;
            const auto ctx = history_context(c.id, c.committee, statement.tick, c.agreement->previous());
            if (statement.context != ctx.id()) return;
            Conversation::Run run;
            run.context = ctx;
            run.statement = statement;
            run.problem = history_problem(ctx, statement);
            run.proposal = m.proposal;
            run.verified = c.verify().proposal(*run.problem, c.committee, m.proposal);
            if (!run.verified) return;
            c.run = std::move(run);
            const auto early = std::exchange(c.early, {});
            for (const auto& e : early) {
                if (e.kind == sg::net::MessageKind::Attestation && e.proposal.certificate.epoch == c.run->verified->epoch().id()) {
                    c.run->votes.push_back(e.attestation);
                    c.agreement->receive(*c.run->verified, e.attestation);
                }
            }
            consider(c);
            try_finalize(c);
            for (const auto& e : early)
                if (e.kind == sg::net::MessageKind::Finalization && c.run &&
                    e.finalization.proposal.certificate.epoch == c.run->verified->epoch().id())
                    if (c.agreement->accept(*c.run->problem, c.verify(), e.finalization)) {
                        finished(c, e.finalization);
                        break;
                    }
        } else if (m.kind == sg::net::MessageKind::Attestation) {
            if (m.attestation.signer != p) return;
            if (c.run && c.run->verified && m.proposal.certificate.epoch == c.run->verified->epoch().id()) {
                c.run->votes.push_back(m.attestation);
                c.agreement->receive(*c.run->verified, m.attestation);
                try_finalize(c);
            } else if (c.early.size() < early_limit) {
                c.early.push_back(m);
            }
        } else if (m.kind == sg::net::MessageKind::Finalization) {
            if (c.run && c.run->verified && m.finalization.proposal.certificate.epoch == c.run->verified->epoch().id()) {
                if (c.agreement->accept(*c.run->problem, c.verify(), m.finalization)) finished(c, m.finalization);
            } else if (c.early.size() < early_limit) {
                c.early.push_back(m);
            }
        }
        return;
    }
    case Control::Nudge:
        maybe_propose(c, true);
        if (!c.run && !c.proposing) c.nudged = true;
        return;
    case Control::HandoffAsk: {
        // Only the owner's side may change who is in a conversation, by one
        // device at a time, to the next generation.
        if (from.side != Side::Owner || (c.change && c.change->endorsed)) return;
        const auto ask = decode_handoff_ask(f.body);
        if (ask.handoff.next.generation != c.generation + 1 ||
            ask.handoff.next.id() != committee_of(c.id, c.generation + 1, ask.next, c.group()).id())
            return;
        std::set<std::string> now, next;
        for (const auto& m : c.members) now.insert(peer_of(m.device));
        for (const auto& m : ask.next) next.insert(peer_of(m.device));
        std::vector<std::string> added, gone;
        std::set_difference(next.begin(), next.end(), now.begin(), now.end(), std::back_inserter(added));
        std::set_difference(now.begin(), now.end(), next.begin(), next.end(), std::back_inserter(gone));
        // Two sides: one device at a time. A group: several, all coming in
        // or all going.
        if ((added.empty() == gone.empty()) || (!c.group() && added.size() + gone.size() != 1)) return;
        Conversation::Change ch;
        ch.add = !added.empty();
        const auto& changing = ch.add ? added : gone;
        for (const auto& m : ch.add ? ask.next : c.members)
            if (std::find(changing.begin(), changing.end(), peer_of(m.device)) != changing.end()) ch.members.push_back(m);
        ch.asker = p;
        ch.handoff = ask.handoff;
        ch.next = ask.next;
        c.change = std::move(ch);
        continue_change(c);
        return;
    }
    case Control::HandoffVote: {
        if (!c.change || !c.change->mine || !c.change->handoff) return;
        Reader r(f.body);
        const auto v = decode_attestation(r);
        r.end();
        if (v.signer != p) return;
        for (const auto& had : c.change->votes)
            if (had.signer == v.signer) return;
        c.change->votes.push_back(v);
        dirty_.insert(c.hexid);
        continue_change(c);
        return;
    }
    case Control::RecoveryAsk: {
        // Asked by a member: replace a lost device. The lost device (if it
        // is here at all) is told, and may refuse; the others endorse.
        if (c.pending) return;
        Reader r(f.body);
        Conversation::Pending pend;
        pend.rec = decode_recovery(r);
        pend.votes.push_back(decode_attestation(r));
        r.end();
        const auto& rec = pend.rec;
        if (rec.conversation != c.id || rec.generation != c.generation + 1 || !c.member(hex(rec.lost)) || hex(rec.lost) == p ||
            pend.votes[0].signer != p || !sg::net::check_signature(from.device.sign, pend.votes[0].statement(), pend.votes[0].signature) ||
            pend.votes[0].decision != rec.decision())
            return;
        pend.asker = p;
        const bool me = rec.lost == id_;
        c.pending = std::move(pend);
        Notice n{me ? "recovery_of_me" : "recovery_approve", c.hexid, peer_of(rec.replacement.device),
                 me ? "Someone is replacing this device. If it is not you, refuse."
                    : emoji_text(fingerprint(device_id(rec.replacement.device), device_id(rec.replacement.device)))};
        n.time = rec.not_before_ms;
        notices_.push_back(n);
        return;
    }
    case Control::RecoveryVote: {
        if (!c.pending || !c.pending->mine) return;
        Reader r(f.body);
        const auto v = decode_attestation(r);
        r.end();
        if (v.signer != p || v.decision != c.pending->rec.decision() || hex(c.pending->rec.lost) == p) return;
        for (const auto& had : c.pending->votes)
            if (had.signer == v.signer) return;
        if (!sg::net::check_signature(from.device.sign, v.statement(), v.signature)) return;
        c.pending->votes.push_back(v);
        continue_recovery(c);
        return;
    }
    case Control::RecoveryRefuse: {
        // Only the device that is said to be lost can refuse: it is not.
        if (!c.pending) return;
        Reader r(f.body);
        const auto v = decode_attestation(r);
        r.end();
        const auto expect = recovery_refusal(c.pending->rec, hex(c.pending->rec.lost));
        if (v.signer != hex(c.pending->rec.lost) || p != v.signer || v.decision != expect.decision ||
            !sg::net::check_signature(from.device.sign, v.statement(), v.signature))
            return;
        c.pending->refused = true;
        notices_.push_back({"recovery_refused", c.hexid, p, "The old device refused: it is not lost. Nothing changed."});
        c.pending.reset();
        return;
    }
    case Control::RecoveryDone: {
        const auto d = decode_recovery_done(f.body);
        if (d.recovery.conversation != c.id || d.recovery.generation != c.generation + 1) return;
        if (!recovery_holds(d.recovery, c.committee, d.endorsements)) return;
        if (now_ + 60000 < d.recovery.not_before_ms) return;  // not before its day (a minute's leeway between clocks)
        apply_recovery(c, d);
        return;
    }
    case Control::HistoryShare: {
        // History for this (recovered) device: only messages the agreed
        // history names, each opened by its own key.
        if (c.agreed_ids.empty()) return;
        for (const auto& item : decode_history_items(f.body)) {
            try {
                if (!c.agreed_ids.count(item.message.id())) continue;
                const auto content = open_content(item.key, item.message);
                Notice n{"history", c.hexid, item.message.peer, ""};
                n.kind = "history_item";
                n.sequence = item.message.sequence;
                n.time = content.time_ms;
                n.type = item.message.parameter;
                n.data = observation_bytes(item.message);
                n.body = content.body;
                n.key = Bytes(item.key.begin(), item.key.end());
                notices_.push_back(n);
            } catch (const std::exception&) {
            }
        }
        return;
    }
    case Control::LinkHave:
        if (c.kind == Kind::Self && !c.removed && p != peer_) take_have(c, from, f.body);
        return;
    case Control::LinkEpochs:
        if (c.kind == Kind::Self && !c.removed && p != peer_) take_epochs(c, from, f.body);
        return;
    case Control::LinkHistory:
        if (c.kind == Kind::Self && !c.removed && p != peer_) take_link_history(c, from, f.body);
        return;
    case Control::CallKey:
        call_key_frame(c, from, f.body);
        return;
    case Control::CallRoster:
        call_roster_frame(c, from, f.body);
        return;
    case Control::HandoffDone: {
        if (!c.last) return;
        const auto ask = decode_handoff_ask(f.body);
        if (!sg::net::verify_handoff(problem_of(*c.last), c.committee, c.verify(), ask.handoff) ||
            ask.handoff.next.id() != committee_of(c.id, c.generation + 1, ask.next, c.group()).id())
            return;
        apply_handoff(c, ask.handoff, ask.next);
        return;
    }
    }
}

// ---- who is in the conversation ---------------------------------------------------

void App::begin_change(Conversation& c, bool add, const std::vector<Member>& ms, const std::string& via) {
    if (c.change) throw Refused("chat: one change of devices at a time");
    if (c.side != Side::Owner) throw Refused("chat: only the owner's side changes devices");
    if (ms.empty() || (!c.group() && ms.size() != 1)) throw Refused("chat: two sides change one device at a time");
    Conversation::Change ch;
    ch.add = add;
    ch.mine = true;
    ch.members = ms;
    ch.asker = peer_;
    ch.via = via;
    c.change = std::move(ch);
    dirty_.insert(c.hexid);
    continue_change(c);
}

void App::continue_change(Conversation& c) {
    if (!c.change || !started_) return;
    auto& ch = *c.change;
    if (ch.handoff && ch.endorsed) {
        if (!ch.mine) return;
        // Enough endorsements: the handoff is done, for everyone.
        if (ch.votes.size() < c.committee.quorum) return;
        auto h = *ch.handoff;
        h.endorsements = ch.votes;
        if (!sg::net::verify_handoff(problem_of(*c.last), c.committee, c.verify(), h)) return;
        const auto body = encode(HandoffAsk{h, ch.next});
        const auto old = c.members;
        // Everyone of the old committee is told - a device taken out too, so
        // one that asked to leave knows it has.
        send_control(c, Control::HandoffDone, body, {}, &old);
        const auto change = ch;
        const auto last = *c.last;
        apply_handoff(c, h, ch.next);
        Writer trust;
        trust.u8(1).long_bytes(encode(last), 1 << 22).long_bytes(encode(h), 1 << 22);
        if (change.add && !change.invite.empty())
            send_accept(c, decode_invite(change.invite), decode_request(change.request), change.pair_key, trust.take());
        else if (change.add && !change.via.empty())
            send_group_invite(c, change.via, trust.take(), old);
        return;
    }
    if (ch.handoff) {  // asked: endorse once the epoch it extends is ours too
        if (!c.last || c.last->finalization.id() != ch.handoff->finalized.id()) return;
        endorse(c);
        return;
    }
    if (!ch.mine || c.run || c.proposing) return;
    // The handoff extends the last epoch, which must cover everything said,
    // and be this committee's own.
    if (!c.last || c.last->context.committee != c.committee.id() || since_epoch(c) > 0) {
        if (!c.agreement) return;
        const auto proposer = proposer_of(c.members);
        if (proposer == peer_) maybe_propose(c, true);
        else if (!ch.asked) {
            send_control(c, Control::Nudge, {}, proposer);
            ch.asked = true;
        }
        return;
    }
    ch.asked = false;
    std::vector<Member> next;
    for (auto m : c.members)
        if (ch.add || !c.changes(m)) {
            const auto p = peer_of(m.device);
            m.mail = p == peer_ ? delivery(c.hexid) == DeliveryMode::Mailbox : takes_mail(c.hexid, p);
            next.push_back(m);
        }
    if (ch.add)
        for (const auto& m : ch.members) next.push_back(m);
    ch.next = next;
    ch.handoff = draft_handoff(c.last->finalization, c.last->checkpoint, committee_of(c.id, c.generation + 1, next, c.group()));
    // Every member endorses - one being taken out too: a device that asked
    // to leave may be needed for the quorum.
    send_control(c, Control::HandoffAsk, encode(HandoffAsk{*ch.handoff, next}));
    dirty_.insert(c.hexid);
    endorse(c);
}

void App::endorse(Conversation& c) {
    auto& ch = *c.change;
    if (ch.endorsed) return;
    const auto problem = problem_of(*c.last);
    try {
        check_endorsable(*c.agreement, c.committee, problem, c.verify(), *ch.handoff, peer_);
    } catch (const std::exception& e) {
        notices_.push_back({"warning", c.hexid, "", std::string("a change of devices was refused: ") + e.what()});
        c.change.reset();
        return;
    }
    // Endorsing seals the old generation: it is persisted before the vote goes.
    const auto& ctx = c.last->context;
    const auto j = journal(c.committee, c.last->finalization.id(), ctx.tick + 1, ctx.world, ch.handoff->decision(), {});
    persist_agreement(c, j);
    const auto persist = [this, cid = c.hexid](const Bytes& b) { persist_agreement(conv(cid), b); };
    c.agreement = std::make_unique<sg::net::Agreement>(locked(c.committee, c.last->finalization.id(), ctx.tick + 1, ctx.world, j, persist));
    ch.endorsed = true;
    auto vote = endorsement_for(problem, *ch.handoff, peer_);
    sign(vote.statement(), [this, cid = c.hexid, vote](const sg::net::Signature& s) mutable {
        if (!conversations_.count(cid)) return;
        auto& c = conv(cid);
        if (!c.change) return;
        vote.signature = s;
        if (c.change->mine) {
            c.change->votes.push_back(vote);
            dirty_.insert(cid);
            continue_change(c);
        } else {
            send_control(c, Control::HandoffVote, encode(vote), c.change->asker);
        }
    });
}

void App::apply_handoff(Conversation& c, const sg::net::Handoff& h, std::vector<Member> next) {
    const auto problem = problem_of(*c.last);
    auto resumed = sg::net::Agreement::resume(problem, c.committee, c.verify(), h,
                                              [this, cid = c.hexid](const Bytes& b) { persist_agreement(conv(cid), b); });
    std::set<std::string> before, after;
    for (const auto& m : c.members) before.insert(peer_of(m.device));
    for (const auto& m : next) after.insert(peer_of(m.device));
    std::vector<Member> added, gone;
    for (const auto& m : next)
        if (!before.count(peer_of(m.device))) added.push_back(m);
    for (const auto& m : c.members)
        if (!after.count(peer_of(m.device))) gone.push_back(m);
    const bool mine = c.change && c.change->mine;
    const auto asker = c.change ? c.change->asker : std::string();
    const auto old = c.members;
    // The handoff that brought this generation in, as a device linked to
    // this one is given it to take its place here (Link.hpp).
    c.join_last = encode(*c.last);
    c.join_ask = encode(HandoffAsk{h, next});
    c.join_before = old;
    c.agreement = std::make_unique<sg::net::Agreement>(std::move(resumed));
    c.journal = c.agreement->snapshot();
    const auto generation = c.generation + 1;
    set_members(c, generation, next);
    c.change.reset();
    // The world follows in one edit each way: the generation moves once,
    // however many devices one handoff brings in or takes out.
    std::vector<Member> added_here, gone_here;
    bool me_gone = false;
    for (const auto& m : added)
        if (peer_of(m.device) != peer_) added_here.push_back(m);
    for (const auto& m : gone) {
        if (peer_of(m.device) == peer_) me_gone = true;
        else gone_here.push_back(m);
    }
    if (!added_here.empty()) {
        engine_->send("contacts", {"device.add", devices_args(c.id, added_here, generation)});
        settle();
        for (const auto& m : added_here) notices_.push_back({"device_added", c.hexid, peer_of(m.device), ""});
    }
    if (!gone_here.empty()) {
        engine_->send("contacts", {"device.revoke", devices_args(c.id, gone_here, generation)});
        settle();
        for (const auto& m : gone_here) {
            const auto p = peer_of(m.device);
            c.ratchets.erase(p);
            c.held.erase(p);
            notices_.push_back({"revoked", c.hexid, p, ""});
        }
    }
    dirty_.insert(c.hexid);
    // This device was taken out: the conversation is over here (it asked to
    // leave, or was revoked). Nothing more is said in it.
    if (me_gone) {
        c.removed = true;
        const bool was_leaving = c.leaving;
        c.leaving = false;
        if (was_leaving) notices_.push_back({"left", c.hexid, "", ""});
        return;
    }
    // The world's generation follows; if no device was added or taken here
    // (this device is the one added), the edit was the pairing's.
    ask_starts(c);
    connect_members(c);
    // What this device said after the last epoch is said again, to the next
    // members, under the next generation, with the same sequences.
    for (const auto& [seq, m] : c.mine) {
        const auto found = c.cutoffs.find(id_);
        if (found != c.cutoffs.end() && seq <= found->second) continue;
        auto o = make_message(c.id, c.generation, id_, seq, m.kind);
        const auto ck = random_key();
        o.payload = seal_content(ck, random_nonce(), o, Content{m.time, m.body});
        sign(o.statement(), [this, cid = c.hexid, o, ck](const sg::net::Signature& s) mutable {
            if (!conversations_.count(cid)) return;
            auto& c = conv(cid);
            o.signature = s;
            if (o.tick != c.generation) return;
            c.log.push_back(o);
            c.integrity->receive(o, c.context(), c.generation);
            Notice n{"resent", cid, peer_, ""};
            n.sequence = o.sequence;
            n.data = observation_bytes(o);
            notices_.push_back(n);
            send_message(c, o, ck);
        });
    }
    // Who is in it changed: each device speaks under a fresh sender key the
    // members taken out never get.
    if (c.kind == Kind::Group) {
        for (const auto& m : gone) c.their_keys.erase(peer_of(m.device));
        if (member_here(c.hexid)) ensure_sender_key(c, true);
    }
    // A device taken out takes the conversation's secret with it: a new one,
    // said under the old (sent_rekey takes it up once it is sealed) - by the
    // owner's side that asked for it, or, when the one that asked was the one
    // that left, by the owner's side's lowest device that stays.
    if (!gone.empty() && c.side == Side::Owner) {
        bool asker_stays = false;
        for (const auto& m : next) asker_stays |= peer_of(m.device) == asker && m.side == Side::Owner;
        bool lowest = true;
        for (const auto& m : next)
            if (m.side == Side::Owner && peer_of(m.device) < peer_) lowest = false;
        if (mine || (!asker_stays && lowest)) post_kind(c, "rekey", encode(RekeyBody{random_key(), c.secrets.back().generation + 1}));
    }
    // A device linked to this one, brought in: given the chat by the lowest
    // of this person's devices that were in it before.
    if (c.kind != Kind::Self)
        for (const auto& m : added)
            if (sibling(peer_of(m.device))) {
                bool lowest = true;
                for (const auto& b : old)
                    if (sibling(peer_of(b.device)) && peer_of(b.device) < peer_) lowest = false;
                if (lowest) give_chat(c);
                break;
            }
}

void App::revoke(const std::string& id, const Key32& device) { remove_devices(id, {device}); }
void App::remove_devices(const std::string& id, const std::vector<Key32>& devices) {
    auto& c = conv(id);
    if (c.side != Side::Owner || c.change) throw Refused("chat: only the owner's side revokes, one change at a time");
    std::vector<Member> going;
    for (const auto& d : devices) {
        const auto* m = c.member(hex(d));
        if (!m || hex(d) == peer_) throw Refused("chat: not a device that can be revoked");
        going.push_back(*m);
    }
    if (going.empty() || (!c.group() && going.size() != 1)) throw Refused("chat: two sides change one device at a time");
    // Everyone, the revoked devices too, is told first - under this generation.
    for (const auto& d : devices) post_kind(c, "device_revoked", encode(RevokedBody{d, c.generation}));
    begin_change(c, false, going);
}

// ---- pairing ----------------------------------------------------------------

App::Inviting App::invite(InviteKind kind, const std::string& relay, const std::string& conversation) {
    Inviting out;
    out.invite.kind = kind;
    out.invite.owner = self_;
    const auto t = random_bytes(16);
    std::copy(t.begin(), t.end(), out.invite.token.begin());
    out.invite.secret = random_key();
    out.invite.relay = relay;
    decode_invite(encode(out.invite));  // the relay address is one a device would accept
    out.code = make_code(random_bytes(9));
    if (kind == InviteKind::Link) {
        // Another device of this person's own: into the self conversation
        // (made by the pairing if there is none yet).
        if (const auto* s = self_conv()) out.conversation = s->hexid;
    } else if (kind != InviteKind::Contact) {
        const auto& c = conv(conversation);
        if (c.side != Side::Owner) throw Refused("chat: only the owner's side invites further devices");
        if ((kind == InviteKind::Channel) != (c.kind == Kind::Channel)) throw Refused("chat: a channel invites readers");
        out.conversation = conversation;
    }
    return out;
}

std::string App::take_request(const Inviting& inv, const Bytes& box, const Key32& shared) {
    PairRequest req;
    try {
        req = decode_request(unpad(open_with("request", shared, self_.agree, box)));
    } catch (const std::exception&) {
        return "refused";
    }
    const auto key = pair_key(inv.code, inv.invite);
    if (!request_holds(key, inv.invite, req)) {
        notices_.push_back({"invite_failed", inv.conversation, "", "Invite failed: possible interception"});
        Outgoing done;
        done.kind = "pair_done";
        done.token = inv.invite.token;
        outgoing_.push_back(done);
        return "failed";
    }
    if (inv.invite.kind == InviteKind::Contact) {
        ConversationId id{};
        const auto r = random_bytes(16);
        std::copy(r.begin(), r.end(), id.begin());
        // This person's linked devices are in it from its start, on its side.
        std::vector<Member> members{{self_, Side::Owner, false}, {req.device, Side::Friend, req.mail}};
        for (auto m : siblings()) {
            m.side = Side::Owner;
            members.push_back(m);
        }
        auto& c = make_conversation(id, req.name.empty() ? "New contact" : req.name, Side::Owner, random_key(), 0, 0, members, req.name);
        send_accept(c, inv.invite, req, key, {});
        if (members.size() > 2) give_chat(c);
        return "ok";
    }
    if (inv.invite.kind == InviteKind::Link) {
        // Linked devices are one side: the owner's, every one of them, and they take mail.
        const Member coming{req.device, Side::Owner, true};
        if (req.device == self_) return "refused";
        auto* s = self_conv();
        if (!s) {
            ConversationId id{};
            const auto r = random_bytes(16);
            std::copy(r.begin(), r.end(), id.begin());
            auto& c = make_conversation(id, "", Side::Owner, random_key(), 0, 0, {{self_, Side::Owner, true}, coming}, "", Kind::Self);
            engine_->send(c.state, {c.state + ".delivery", delivery_args(int(DeliveryMode::Mailbox))});
            settle();
            send_accept(c, inv.invite, req, key, {});
            notices_.push_back({"linked", c.hexid, peer_of(req.device), ""});
            have_due_ = true;
            return "ok";
        }
        if (s->member(peer_of(req.device)) || s->change) return "refused";
        begin_change(*s, true, {coming});
        s->change->invite = encode(inv.invite);
        s->change->request = encode(req);
        s->change->pair_key = key;
        dirty_.insert(s->hexid);
        return "ok";
    }
    auto& c = conv(inv.conversation);
    if (inv.invite.kind == InviteKind::Recovery) {
        // The new device for a lost one: asked of the others, and told to the
        // lost one, which has a day to refuse.
        if (c.pending || c.change || options_of(c.hexid).no_recovery || !c.member(hex(inv.lost))) return "refused";
        Conversation::Pending p;
        auto& rec = p.rec;
        rec.conversation = c.id;
        rec.generation = c.generation + 1;
        rec.lost = inv.lost;
        const auto* lost = c.member(hex(inv.lost));
        rec.replacement = {req.device, lost->side, req.mail};
        rec.scope = inv.scope;
        rec.since_ms = inv.since_ms;
        rec.not_before_ms = now_ + recovery_wait_;
        rec.previous = c.last ? c.last->finalization.id() : sg::net::Digest{};
        rec.tick = c.agreement ? c.agreement->next_tick() : 0;
        rec.tail = encode(history_of(c.log, c.cutoffs));
        p.mine = true;
        p.asker = peer_;
        p.invite = encode(inv.invite);
        p.request = encode(req);
        p.pair_key = key;
        c.pending = std::move(p);
        dirty_.insert(c.hexid);
        auto vote = recovery_endorsement(c.pending->rec, peer_);
        sign(vote.statement(), [this, cid = c.hexid, vote](const sg::net::Signature& s) mutable {
            if (!conversations_.count(cid)) return;
            auto& c = conv(cid);
            if (!c.pending) return;
            vote.signature = s;
            c.pending->votes.push_back(vote);
            send_control(c, Control::RecoveryAsk, Writer().raw(encode(c.pending->rec)).raw(encode(vote)).take());
            Notice n{"recovery_started", cid, peer_of(c.pending->rec.replacement.device), ""};
            n.time = c.pending->rec.not_before_ms;
            notices_.push_back(n);
            dirty_.insert(cid);
        });
        return "ok";
    }
    if (inv.invite.kind == InviteKind::Channel) {
        // A reader: not a member, so no handoff; the channel's key from now on.
        if (c.kind != Kind::Channel || !c.own_key) return "refused";
        send_accept(c, inv.invite, req, key, Writer().u8(2).short_bytes(encode(*c.own_key)).take());
        return "ok";
    }
    if (c.member(peer_of(req.device))) return "refused";
    begin_change(c, true, {{req.device, Side::Friend, req.mail}});
    c.change->invite = encode(inv.invite);
    c.change->request = encode(req);
    c.change->pair_key = key;
    dirty_.insert(c.hexid);
    return "ok";
}

void App::send_accept(Conversation& c, const Invite& inv, const PairRequest& req, const Key32& key, const Bytes& trust) {
    PairAccept acc;
    acc.conversation = c.id;
    acc.secret = secret_now(c);
    acc.secret_generation = c.secrets.back().generation;
    acc.owner_name = c.kind == Kind::Channel ? c.name : name_;
    acc.generation = c.generation;
    acc.members = c.members;
    acc.trust = trust;
    acc.mac = accept_mac(key, inv, req, acc);
    sign(accept_statement(inv, req, acc), [this, cid = c.hexid, inv, req, acc](const sg::net::Signature& s) mutable {
        acc.signature = s;
        Outgoing out;
        out.kind = "envelope";
        out.conversation = cid;
        out.purpose = "accept";
        out.agree = req.device.agree;
        out.version = Version::PairReply;
        out.mailbox = reply_mailbox(inv, device_id(req.device));
        out.plain = pad(encode(acc));
        out.live = false;
        outgoing_.push_back(out);
        if (inv.kind != InviteKind::ReusableDevice && inv.kind != InviteKind::Channel) {
            Outgoing done;
            done.kind = "pair_done";
            done.token = inv.token;
            outgoing_.push_back(done);
        }
        Notice n{"paired", cid, peer_of(req.device), emoji_text(fingerprint(id_, device_id(req.device)))};
        n.type = req.name;
        notices_.push_back(n);
    });
}

Asking App::ask(const Invite& invite, const std::string& code, const std::string& name, const std::string& call, bool mail) {
    if (call.size() > 64) throw Refused("chat: a name is at most 64 bytes");
    Asking a;
    a.invite = invite;
    a.call = call;
    a.key = pair_key(code, invite);
    a.request.device = self_;
    const auto n = random_bytes(16);
    std::copy(n.begin(), n.end(), a.request.nonce.begin());
    a.request.name = name;
    a.request.mail = mail;
    a.request.mac = request_mac(a.key, invite, a.request);
    auto req = a.request;
    sign(request_statement(invite, req), [this, invite, req](const sg::net::Signature& s) mutable {
        req.signature = s;
        Outgoing out;
        out.kind = "pair";
        out.purpose = "request";
        out.agree = invite.owner.agree;
        out.token = invite.token;
        out.plain = pad(encode(req));
        outgoing_.push_back(out);
    });
    return a;
}

std::string App::take_accept(const Asking& a, const Bytes& envelope, const Key32& shared) {
    PairAccept acc;
    try {
        const auto e = decode_envelope(envelope);
        if (e.version != Version::PairReply || e.mailbox != reply_mailbox(a.invite, id_)) return "not this pairing's reply";
        acc = decode_accept(unpad(open_with("accept", shared, self_.agree, e.box)));
    } catch (const std::exception&) {
        return "the reply did not open";
    }
    if (!accept_holds(a.key, a.invite, a.request, acc)) {
        notices_.push_back({"invite_failed", "", "", "Invite failed: possible interception"});
        return "Invite failed: possible interception";
    }
    // A device recovered: the endorsed decision, and the agreed history.
    if (!acc.trust.empty() && acc.trust[0] == 3) {
        RecoveryDone d;
        Kind kind = Kind::Direct;
        std::vector<Finalized> epochs;
        try {
            Reader r(acc.trust);
            r.u8();
            d = decode_recovery_done(r.long_bytes(1 << 20));
            kind = Kind(r.u8());
            const auto n = r.u16();
            for (unsigned i = 0; i < n; ++i) epochs.push_back(decode_finalized(r.long_bytes(1 << 22)));
            r.end();
        } catch (const std::exception& ex) {
            return std::string("the recovery did not read: ") + ex.what();
        }
        const auto& rec = d.recovery;
        if (rec.conversation != acc.conversation || !(rec.replacement.device == self_) || rec.generation != acc.generation)
            return "the recovery is not for this device";
        // The endorsers are the members that remain: their keys are in the decision's committee.
        std::vector<Member> remaining;
        for (const auto& m : d.members)
            if (!(m.device == self_)) remaining.push_back(m);
        const auto check = committee_of(acc.conversation, rec.generation - 1, remaining, kind == Kind::Group);
        if (!recovery_holds(rec, check, d.endorsements)) return "the recovery is not endorsed";
        std::vector<sg::net::Digest> ids;
        try {
            ids = chained_ids(epochs, rec.previous);
            for (const auto& id : decode_history(rec.tail).ids) ids.push_back(id);
        } catch (const std::exception& ex) {
            return std::string("the history does not hold: ") + ex.what();
        }
        if (conversations_.count(hex(acc.conversation))) return "that conversation is here already";
        const auto called = !a.call.empty() ? a.call : acc.owner_name.empty() ? "New contact" : acc.owner_name;
        auto& c = make_conversation(acc.conversation, called, rec.replacement.side, acc.secret, acc.secret_generation,
                                    acc.generation, d.members, acc.owner_name, kind);
        const auto persist = [this, cid = c.hexid](const Bytes& b) { persist_agreement(conv(cid), b); };
        c.agreement = std::make_unique<sg::net::Agreement>(c.committee, rec.decision(), std::max<std::uint64_t>(rec.tick, 1), persist,
                                                           region_of(c.id));
        c.journal = c.agreement->snapshot();
        c.chain_root = rec.decision();
        c.agreed_ids.insert(ids.begin(), ids.end());
        if (kind == Kind::Group) ensure_sender_key(c, true);
        rekey_after_recovery(c);
        Notice n{"paired", c.hexid, peer_of(a.invite.owner), emoji_text(fingerprint(id_, device_id(a.invite.owner)))};
        n.type = c.name;
        notices_.push_back(n);
        dirty_.insert(c.hexid);
        return "ok";
    }
    // A channel's reader: not a member; its key is the channel's sender key.
    if (!acc.trust.empty() && acc.trust[0] == 2) {
        bool owner = false;
        for (const auto& m : acc.members) owner |= m.device == a.invite.owner && m.side == Side::Owner;
        if (!owner) return "the reply does not name its publisher";
        if (conversations_.count(hex(acc.conversation))) return "that channel is here already";
        SenderKey key;
        try {
            Reader r(acc.trust);
            r.u8();
            key = decode_sender_key(r.short_bytes());
            r.end();
        } catch (const std::exception&) {
            return "the channel's key did not read";
        }
        const auto called = !a.call.empty() ? a.call : acc.owner_name.empty() ? "Channel" : acc.owner_name;
        auto& c = make_conversation(acc.conversation, called, Side::Friend, acc.secret, acc.secret_generation, acc.generation,
                                    acc.members, acc.owner_name, Kind::Channel);
        c.their_keys[peer_of(a.invite.owner)] = SenderChain{key, {}};
        index_mailboxes();
        Notice n{"paired", c.hexid, peer_of(a.invite.owner), emoji_text(fingerprint(id_, device_id(a.invite.owner)))};
        n.type = c.name;
        notices_.push_back(n);
        dirty_.insert(c.hexid);
        return "ok";
    }
    if (a.invite.kind == InviteKind::Link) {
        // Linked to another device of this person's own: every member on the
        // owner's side, this one and the one it linked to among them.
        bool me = false, owner = false, one_side = true;
        for (const auto& m : acc.members) {
            me |= m.device == self_;
            owner |= m.device == a.invite.owner;
            one_side &= m.side == Side::Owner;
        }
        if (!me || !owner || !one_side) return "the reply does not name this device and the one it is linked to";
        if (self_conv()) return "this device is linked already: unlink it first";
        if (conversations_.count(hex(acc.conversation))) return "that conversation is here already";
        Resumed resumed;
        if (!acc.trust.empty()) {
            std::vector<Member> old;
            for (const auto& m : acc.members)
                if (!(m.device == self_)) old.push_back(m);
            resumed = resume_from(acc.trust, acc.conversation, acc.generation, old, acc.members, false);
            if (!resumed.why.empty()) return resumed.why;
        } else if (acc.generation != 0) {
            return "a first device joins at generation 0";
        }
        auto& c = make_conversation(acc.conversation, "", Side::Owner, acc.secret, acc.secret_generation, acc.generation, acc.members,
                                    "", Kind::Self);
        adopt(c, std::move(resumed));
        c.epoch_day = day_;
        engine_->send(c.state, {c.state + ".delivery", delivery_args(int(DeliveryMode::Mailbox))});
        settle();
        Notice n{"paired", c.hexid, peer_of(a.invite.owner), emoji_text(fingerprint(id_, device_id(a.invite.owner)))};
        notices_.push_back(n);
        notices_.push_back({"linked", c.hexid, peer_of(a.invite.owner), ""});
        have_due_ = true;
        dirty_.insert(c.hexid);
        return "ok";
    }
    bool me = false, owner = false;
    for (const auto& m : acc.members) {
        me |= m.device == self_ && m.side == Side::Friend && m.mail == a.request.mail;
        owner |= m.device == a.invite.owner && m.side == Side::Owner;
    }
    if (!me || !owner) return "the reply does not name this device and its owner";
    if (conversations_.count(hex(acc.conversation))) return "that conversation is here already";
    Resumed resumed;
    if (!acc.trust.empty()) {
        // A further device: take up the conversation's trust from the last
        // finalized epoch and the handoff the old quorum endorsed.
        std::vector<Member> old;
        for (const auto& m : acc.members)
            if (!(m.device == self_)) old.push_back(m);
        resumed = resume_from(acc.trust, acc.conversation, acc.generation, old, acc.members, false);
        if (!resumed.why.empty()) return resumed.why;
    } else if (acc.generation != 0) {
        return "a first device joins at generation 0";
    }
    // The one invited names the one who invited: its own choice, else what
    // they call themselves.
    const auto called = !a.call.empty() ? a.call : acc.owner_name.empty() ? "New contact" : acc.owner_name;
    auto& c = make_conversation(acc.conversation, called, Side::Friend, acc.secret, acc.secret_generation, acc.generation,
                                acc.members, acc.owner_name);
    adopt(c, std::move(resumed));
    c.epoch_day = day_;
    if (a.request.mail) {
        engine_->send(c.state, {c.state + ".delivery", delivery_args(int(DeliveryMode::Mailbox))});
        settle();
    }
    Notice n{"paired", c.hexid, peer_of(a.invite.owner), emoji_text(fingerprint(id_, device_id(a.invite.owner)))};
    n.type = c.name;
    notices_.push_back(n);
    dirty_.insert(c.hexid);
    return "ok";
}

App::Resumed App::resume_from(const Bytes& trust, const ConversationId& id, std::uint64_t generation,
                              const std::vector<Member>& before, const std::vector<Member>& after, bool majority) {
    Resumed out;
    try {
        Reader r(trust);
        if (r.u8() != 1) return {nullptr, std::nullopt, "unknown trust"};
        const auto f = decode_finalized(r.long_bytes(1 << 22));
        const auto h = decode_handoff(r.long_bytes(1 << 22));
        r.end();
        if (generation == 0) return {nullptr, std::nullopt, "a device joins later at a later generation"};
        const auto old_committee = committee_of(id, generation - 1, before, majority);
        if (old_committee.id() != f.context.committee || h.next.id() != committee_of(id, generation, after, majority).id())
            return {nullptr, std::nullopt, "the committee is not the conversation's"};
        const auto verify = history_verify(id);
        if (!sg::net::verify_handoff(problem_of(f), old_committee, verify, h))
            return {nullptr, std::nullopt, "the handoff is not endorsed by the old quorum"};
        out.agreement = std::make_unique<sg::net::Agreement>(sg::net::Agreement::resume(problem_of(f), old_committee, verify, h));
        out.last = f;
    } catch (const std::exception& ex) {
        return {nullptr, std::nullopt, std::string("the trust did not check: ") + ex.what()};
    }
    return out;
}
void App::adopt(Conversation& c, Resumed r) {
    const auto persist = [this, cid = c.hexid](const Bytes& b) { persist_agreement(conv(cid), b); };
    if (r.agreement) {
        c.journal = r.agreement->snapshot();
        c.last = r.last;
        c.cutoffs = checkpoint_cutoffs(r.last->checkpoint);
        // The agreement persists through the conversation from here on.
        c.agreement = std::make_unique<sg::net::Agreement>(locked(c.committee, r.agreement->previous(), r.agreement->next_tick(),
                                                                  region_of(c.id), c.journal, persist));
    } else {
        c.agreement = std::make_unique<sg::net::Agreement>(c.committee, sg::net::Digest{}, 0, persist);
    }
}

// ---- recovery ---------------------------------------------------------------------

Options App::options_of(const std::string& id) const {
    const auto& p = graph_.state(conv(id).state).params();
    Options o;
    o.no_recovery = p.get_or<std::int64_t>("recovery", 1) == 0;
    o.disappear_s = std::uint32_t(p.get_or<std::int64_t>("disappear", 0));
    return o;
}
void App::set_options(const std::string& id, const Options& o) {
    auto& c = conv(id);
    engine_->send(c.state, {c.state + ".options", options_args(!o.no_recovery, o.disappear_s)});
    settle();
    if (member_here(id)) post_kind(c, "options", encode(o));
    dirty_.insert(id);
}

App::Inviting App::recovery_invite(const std::string& relay, const std::string& id, const Key32& lost, Scope scope,
                                   std::uint64_t since_ms) {
    auto& c = conv(id);
    if (options_of(id).no_recovery) throw Refused("chat: this chat has no recovery: its history dies with a lost device");
    if (!c.member(hex(lost)) || lost == id_) throw Refused("chat: not a device of this conversation");
    if (c.kind == Kind::Channel) throw Refused("chat: a channel's publisher replaces its own devices");
    auto inv = invite(InviteKind::Contact, relay);
    inv.invite.kind = InviteKind::Recovery;
    inv.conversation = id;
    inv.lost = lost;
    inv.scope = scope;
    inv.since_ms = since_ms;
    return inv;
}

void App::approve_recovery(const std::string& id) {
    auto& c = conv(id);
    if (!c.pending || c.pending->mine || c.pending->approved || c.pending->rec.lost == id_) return;
    // What it names since the last epoch must be what this device has: it
    // is what the new device will take as agreed.
    const auto prev = c.last ? c.last->finalization.id() : sg::net::Digest{};
    if (c.pending->rec.previous != prev) throw Refused("chat: the recovery names another last epoch than this device's; wait and try again");
    switch (compare(decode_history(c.pending->rec.tail), c.log, c.cutoffs)) {
    case Agrees::Same: break;
    case Agrees::Behind: throw Refused("chat: this device has not had every message the recovery names yet; try again in a moment");
    case Agrees::Differs:
        notices_.push_back({"history_differs", c.hexid, c.pending->asker, ""});
        throw Refused("chat: the history the recovery names differs from this device's: not approved");
    }
    c.pending->approved = true;
    auto vote = recovery_endorsement(c.pending->rec, peer_);
    sign(vote.statement(), [this, id, vote](const sg::net::Signature& s) mutable {
        if (!conversations_.count(id)) return;
        auto& c = conv(id);
        if (!c.pending) return;
        vote.signature = s;
        send_control(c, Control::RecoveryVote, encode(vote), c.pending->asker);
    });
}
void App::refuse_recovery(const std::string& id) {
    auto& c = conv(id);
    if (!c.pending || c.pending->rec.lost != id_) return;
    auto no = recovery_refusal(c.pending->rec, peer_);
    sign(no.statement(), [this, id, no](const sg::net::Signature& s) mutable {
        if (!conversations_.count(id)) return;
        auto& c = conv(id);
        no.signature = s;
        send_control(c, Control::RecoveryRefuse, encode(no));
        c.pending.reset();
        dirty_.insert(id);
    });
}

// The asker's side: when the day is over and enough have said yes, done.
void App::continue_recovery(Conversation& c) {
    if (!c.pending || !c.pending->mine || c.pending->refused) return;
    auto& p = *c.pending;
    if (now_ < p.rec.not_before_ms || !recovery_holds(p.rec, c.committee, p.votes)) return;
    RecoveryDone d;
    d.recovery = p.rec;
    d.endorsements = p.votes;
    for (const auto& m : c.members)
        if (device_id(m.device) != p.rec.lost) d.members.push_back(m);
    d.members.push_back(p.rec.replacement);
    // Everyone of the old committee is told - the lost device too, if it hears.
    send_control(c, Control::RecoveryDone, encode(d));
    const auto pend = p;
    const auto epochs = c.epochs;
    apply_recovery(c, d);
    // The new device: the decision, and the agreed history it can check
    // what it is given against.
    Writer trust;
    trust.u8(3).long_bytes(encode(d), 1 << 20).u8(std::uint8_t(c.kind)).u16(std::uint16_t(epochs.size()));
    for (const auto& e : epochs) trust.long_bytes(e, 1 << 22);
    send_accept(c, decode_invite(pend.invite), decode_request(pend.request), pend.pair_key, trust.take());
    Notice n{"recovered", c.hexid, peer_of(pend.rec.replacement.device), ""};
    n.sequence = std::uint64_t(pend.rec.scope);
    n.time = pend.rec.since_ms;
    notices_.push_back(n);
}

// Everyone's side: the old generation sealed, the lost device out and the
// new one in, every key turned.
void App::apply_recovery(Conversation& c, const RecoveryDone& d) {
    const auto& rec = d.recovery;
    const bool me_lost = rec.lost == id_;
    set_members(c, rec.generation, d.members);
    const auto persist = [this, cid = c.hexid](const Bytes& b) { persist_agreement(conv(cid), b); };
    c.agreement = std::make_unique<sg::net::Agreement>(c.committee, rec.decision(), std::max<std::uint64_t>(rec.tick, 1), persist,
                                                       region_of(c.id));
    c.journal = c.agreement->snapshot();
    c.chain_root = rec.decision();
    c.epochs.clear();
    c.run.reset();
    c.change.reset();
    c.pending.reset();
    engine_->send("contacts", {"device.replace", replace_args(c.id, rec.lost, rec.replacement, rec.generation)});
    settle();
    c.ratchets.erase(hex(rec.lost));
    c.held.erase(hex(rec.lost));
    c.their_keys.erase(hex(rec.lost));
    dirty_.insert(c.hexid);
    if (me_lost) {
        c.removed = true;
        notices_.push_back({"removed", c.hexid, "", "This device was replaced. Ask " + name_of(c.hexid) + " for a new key."});
        return;
    }
    ask_starts(c);
    connect_members(c);
    if (c.kind == Kind::Group) ensure_sender_key(c, true);
    rekey_after_recovery(c);
    notices_.push_back({"device_replaced", c.hexid, peer_of(rec.replacement.device), ""});
}

// The lost device knew the secret its mailboxes come from: the owner's side's
// lowest device turns it (the new one, if it is that).
void App::rekey_after_recovery(Conversation& c) {
    if (c.side != Side::Owner) return;
    for (const auto& m : c.members)
        if (m.side == Side::Owner && peer_of(m.device) < peer_) return;
    post_kind(c, "rekey", encode(RekeyBody{random_key(), c.secrets.back().generation + 1}));
}

void App::share_push(const std::string& id, const Bytes& info) {
    auto& c = conv(id);
    decode_push_info(info);
    if (!member_here(id) || c.kind == Kind::Channel || c.removed) return;
    post_kind(c, "push", info);
}

void App::forget_said(const std::string& id, std::uint64_t sequence) {
    auto& c = conv(id);
    const auto m = c.mine.find(sequence);
    if (m == c.mine.end()) return;
    std::fill(m->second.body.begin(), m->second.body.end(), 0);
    m->second.body.clear();
}

void App::share_history(const std::string& id, const std::string& peer, const std::vector<HistoryItem>& items) {
    auto& c = conv(id);
    if (!c.member(peer)) throw Refused("chat: history goes to a device of the conversation");
    // In parts that fit a frame (the relay's largest bucket); a message too
    // large for one alone is not given.
    constexpr std::size_t most = 200000;
    std::vector<HistoryItem> part;
    std::size_t size = 0;
    for (const auto& i : items) {
        const auto n = observation_bytes(i.message).size() + 40;
        if (n > most) continue;
        if (size + n > most || part.size() == 4096) {
            send_control(c, Control::HistoryShare, encode(part), peer);
            part.clear();
            size = 0;
        }
        part.push_back(i);
        size += n;
    }
    if (!part.empty()) send_control(c, Control::HistoryShare, encode(part), peer);
}

std::string App::recovery_state(const std::string& id) const {
    const auto& c = conv(id);
    if (!c.pending) return {};
    const auto& p = *c.pending;
    return (p.mine ? std::string("mine") : p.rec.lost == id_ ? std::string("me") : std::string("asked")) + " " + hex(p.rec.lost) + " " +
           peer_of(p.rec.replacement.device) + " " + std::to_string(p.rec.not_before_ms) + " " + std::to_string(p.votes.size()) +
           " " + std::to_string(recovery_quorum(c.committee.members.size() - 1)) + " " + (p.approved ? "approved" : "open");
}

// ---- groups and channels ---------------------------------------------------------

Kind App::kind_of(const std::string& id) const { return conv(id).kind; }
bool App::member_here(const std::string& id) const { return conv(id).committee.key(peer_) != nullptr; }

std::string App::create_group(const std::string& name, const std::vector<std::string>& contacts, Kind kind) {
    if (kind == Kind::Direct) throw Refused("chat: a group or a channel");
    if (name.empty() || name.size() > 64) throw Refused("chat: a name is 1..64 bytes");
    std::vector<Member> members{{self_, Side::Owner, false}};
    // A group's maker's linked devices are in it from its start, on its side
    // (a channel is posted to from the device that made it; the others read it).
    if (kind == Kind::Group)
        for (auto m : siblings()) {
            m.side = Side::Owner;
            members.push_back(m);
        }
    if (kind == Kind::Group)
        for (const auto& cid : contacts) {
            const auto& d = conv(cid);
            if (d.kind != Kind::Direct || d.removed) throw Refused("chat: a group is made of contacts");
            for (auto m : d.members)
                if (peer_of(m.device) != peer_ && std::none_of(members.begin(), members.end(), [&](const Member& x) { return x.device == m.device; })) {
                    m.side = Side::Friend;
                    m.mail = takes_mail(cid, peer_of(m.device));
                    members.push_back(m);
                }
        }
    ConversationId id{};
    const auto r = random_bytes(16);
    std::copy(r.begin(), r.end(), id.begin());
    auto& c = make_conversation(id, name, Side::Owner, random_key(), 0, 0, members, name, kind);
    ensure_sender_key(c, true);
    if (kind == Kind::Group)
        for (const auto& cid : contacts) send_group_invite(c, cid, {}, {});
    if (kind == Kind::Group && !siblings().empty()) give_chat(c);
    notices_.push_back({kind == Kind::Group ? "group" : "channel", c.hexid, "", name});
    return c.hexid;
}

void App::send_group_invite(Conversation& g, const std::string& via, const Bytes& trust, const std::vector<Member>& before) {
    GroupInvite gi;
    gi.group = g.id;
    gi.kind = g.kind;
    gi.secret = secret_now(g);
    gi.secret_generation = g.secrets.back().generation;
    gi.name = g.name;
    gi.generation = g.generation;
    gi.members = g.members;
    gi.trust = trust;
    gi.before = trust.empty() ? std::vector<Member>{} : before;
    post_kind(conv(via), "group_invite", encode(gi));
}

void App::add_to_group(const std::string& group, const std::string& contact) {
    auto& g = conv(group);
    if (g.kind != Kind::Group) throw Refused("chat: contacts are added to groups");
    const auto& d = conv(contact);
    std::vector<Member> coming;
    for (auto m : d.members)
        if (peer_of(m.device) != peer_ && !g.member(peer_of(m.device))) {
            m.side = Side::Friend;
            m.mail = takes_mail(contact, peer_of(m.device));
            coming.push_back(m);
        }
    if (coming.empty()) throw Refused("chat: they are in the group already");
    begin_change(g, true, coming, contact);
}

// A group invite, said in a direct conversation by one of its own side:
// the group as it is, and if it is not at its start, the handoff to take up.
void App::join_group(Conversation& direct, const sg::net::Observation& from, const GroupInvite& gi) {
    // One of this person's own devices made it: it comes as a linked chat.
    if (sibling(from.peer)) return;
    bool me = false, owner = false;
    for (const auto& m : gi.members) {
        me |= m.device == self_ && m.side == Side::Friend;
        owner |= peer_of(m.device) == from.peer && m.side == Side::Owner;
    }
    if (!me || !owner || gi.kind != Kind::Group) {
        notices_.push_back({"warning", direct.hexid, from.peer, "A group invite that does not hold was refused."});
        return;
    }
    if (conversations_.count(hex(gi.group))) return;
    Resumed resumed;
    if (!gi.trust.empty()) {
        resumed = resume_from(gi.trust, gi.group, gi.generation, gi.before, gi.members, true);
        if (!resumed.why.empty()) {
            notices_.push_back({"warning", direct.hexid, from.peer, "A group invite was refused: " + resumed.why});
            return;
        }
    } else if (gi.generation != 0) {
        return;
    }
    auto& c = make_conversation(gi.group, gi.name, Side::Friend, gi.secret, gi.secret_generation, gi.generation, gi.members,
                                gi.name, Kind::Group);
    adopt(c, std::move(resumed));
    c.epoch_day = day_;
    ensure_sender_key(c, true);
    notices_.push_back({"group", c.hexid, from.peer, gi.name});
}

// ---- live ---------------------------------------------------------------------

void App::set_live(Live* live) { live_ = live; }
// What came on the live link, each to its own: envelopes, pieces, a call's
// chunks, a game's and a board's packets, releases, carried frames.
void App::receive_live() {
    std::string p, channel;
    Bytes bytes;
    for (int n = 0; n < 4096 && live_->receive(p, channel, bytes); ++n) {
        if (channel == "envelope") live_in_.push_back(std::move(bytes));
        else if (channel == "blob") blobs_in_.emplace_back(p, std::move(bytes));
        else if (channel == "call") call_chunk(p, bytes);
        else if (channel == "callroot") call_root(p, bytes);
        else if (channel == "callmap") call_map(p, bytes);
        else if (channel == "callwant") call_want(p, bytes);
        else if (channel == "callpick") call_pick(p, bytes);
        else if (channel == "game") game_packet(p, bytes);
        else if (channel == "board") board_packet(p, bytes);
        else if (channel == "release" && release_in_.size() < 4096) release_in_.emplace_back(p, std::move(bytes));
        else if (channel == "carry" && carry_in_.size() < 4096 && bytes.size() <= carry_frame_max)
            carry_in_.emplace_back(p, std::move(bytes));
    }
}
// Every frame while a game or a board is open: only what they need - the
// link read, the court stepped, its packets out - so a player's own paddle
// answers at once, never waiting on the session's slower round.
void App::tick_live(std::uint64_t now_ms) {
    now_ = std::max(now_, now_ms);
    if (live_) {
        live_->poll();
        receive_live();
    }
    pump_games();
    settle();
}
void App::connect_members(Conversation& c) {
    if (!live_ || c.removed || c.kind == Kind::Channel) return;
    for (const auto& m : c.members) {
        const auto p = peer_of(m.device);
        if (p == peer_ || connected_.count(p)) continue;
        live_->connect(p);
        connected_.insert(p);
    }
}
bool App::send_live(const std::string& peer, const Bytes& envelope) {
    return live_ && live_->connected(peer) && live_->send(peer, "envelope", envelope);
}
std::string App::describe(const std::string& id) const {
    const auto& c = conv(id);
    std::string s = "generation " + std::to_string(c.generation) + ", members " + std::to_string(c.members.size());
    s += ", next tick " + (c.agreement ? std::to_string(c.agreement->next_tick()) : std::string("-"));
    s += ", last epoch " + (c.last ? std::to_string(c.last->context.tick) : std::string("none"));
    s += ", since epoch " + std::to_string(since_epoch(c)) + ", log " + std::to_string(c.log.size());
    if (c.proposing) s += ", proposing";
    if (c.run) {
        s += ", run tick " + std::to_string(c.run->context.tick) + " by " + c.run->statement.peer.substr(0, 6);
        s += c.run->voted ? " voted" : "";
        s += c.run->differs ? " differs" : "";
        s += ", votes " + std::to_string(c.run->votes.size());
        const auto verdict = compare(decode_history(c.run->statement.payload), c.log, c.cutoffs);
        s += verdict == Agrees::Same ? " (same)" : verdict == Agrees::Behind ? " (behind)" : " (differs)";
    }
    s += ", early " + std::to_string(c.early.size());
    if (c.change) {
        const auto& ch = *c.change;
        s += std::string(", change ") + (ch.add ? "add " : "remove ") + std::to_string(ch.members.size());
        s += ch.mine ? " mine" : " asked by " + ch.asker.substr(0, 6);
        s += ch.handoff ? " drafted" : " waiting for epoch";
        s += ch.endorsed ? " endorsed" : "";
        s += ", endorsements " + std::to_string(ch.votes.size()) + "/" + std::to_string(c.committee.quorum);
    }
    s += ", signs pending " + std::to_string(signs_.size());
    return s;
}
void App::reconnect_live(const std::string& peer) {
    if (live_ && connected_.count(peer)) live_->reconnect(peer);
}
bool App::live_with(const std::string& peer) const { return live_ && live_->connected(peer); }
std::vector<Bytes> App::take_live() { return std::exchange(live_in_, {}); }
bool App::send_blob(const std::string& peer, const Bytes& frame) {
    return live_ && live_->connected(peer) && live_->send(peer, "blob", frame);
}
std::vector<std::pair<std::string, Bytes>> App::take_blobs() { return std::exchange(blobs_in_, {}); }
void App::post_file(const std::string& id, const Bytes& ref, std::uint64_t time_ms) {
    auto& c = conv(id);
    if (c.removed) throw Refused("chat: this device was removed from the conversation");
    if (!member_here(id)) throw Refused("chat: only its publisher posts in a channel");
    decode_file(ref);  // a reference that reads, or nothing is said
    const auto token = "t" + std::to_string(next_token_++);
    posts_[token] = {id, "file", ref, time_ms};
    engine_->send(c.state, {c.state + ".post", post_args("file", token)});
    settle();
}
Key32 App::piece_mailbox_of(const std::string& id, const Key32& blob, std::uint32_t piece) const {
    return piece_mailbox(secret_now(conv(id)), blob, piece);
}

void App::handle_signals() {
    for (const auto& s : live_->signals()) {
        auto& said = said_session_[s.peer][s.lane == sg::net::DeliveryClass::Latest ? 1 : 0];
        said = std::max(said, s.session);
        for (auto& [id, c] : conversations_) {
            const auto* m = c->member(s.peer);
            if (!m || c->removed) continue;
            // In the room the peer was last heard from; not heard yet (a new
            // device, one that may have missed a rekey), in every room kept -
            // under one counter, so the copies after the first are dropped.
            std::vector<Key32> secrets;
            const auto heard = c->heard_in.find(s.peer);
            for (const auto& k : c->secrets)
                if (heard == c->heard_in.end() || k.generation == heard->second) secrets.push_back(k.key);
            if (secrets.empty()) secrets.push_back(secret_now(*c));
            const auto counter = ++c->signal_out;
            dirty_.insert(id);
            for (const auto& secret : secrets) {
                SignalFrame frame;
                frame.room = room(secret);
                frame.from = id_;
                frame.to = device_id(m->device);
                frame.counter = counter;
                frame.signal = s;
                sign(signal_statement(frame), [this, cid = id, frame, secret](const sg::net::Signature& sig) mutable {
                    if (!conversations_.count(cid)) return;
                    frame.signature = sig;
                    Outgoing out;
                    out.kind = "signal";
                    out.conversation = cid;
                    out.peer = hex(frame.to);
                    out.room = frame.room;
                    out.label = label(secret, frame.to);
                    out.box = signal_box(secret, random_nonce(), encode(frame));
                    outgoing_.push_back(out);
                });
            }
            break;
        }
    }
}

void App::signal_in(const Key32& r, const Bytes& box) {
    if (signal_into(r, box)) return;
    // A room no conversation here has (yet): a device that has just paired
    // can be signalled before it has taken the answer. Kept a while, tried
    // again as conversations come.
    if (early_signals_.size() >= 64) early_signals_.pop_front();
    early_signals_.push_back({r, box, now_});
}
bool App::signal_into(const Key32& r, const Bytes& box) {
    for (auto& [id, c] : conversations_) {
        for (const auto& s : c->secrets) {
            if (room(s.key) != r) continue;
            try {
                const auto frame = decode_signal(signal_unbox(s.key, box));
                const auto from = hex(frame.from);
                const auto* m = c->member(from);
                if (!m || frame.to != id_ || frame.room != r) return true;
                if (frame.counter <= c->signal_in[from]) return true;  // replayed
                if (!signal_holds(frame, m->device.sign)) return true;
                c->signal_in[from] = frame.counter;
                c->heard_in[from] = s.generation;
                dirty_.insert(id);
                if (live_) {
                    live_->signal(from, frame.signal);
                    // Heard from a peer whose link is down, under an older session than
                    // this device's newest for it (it went away and came back, starting
                    // again): it would never be answered - the engine takes sessions only
                    // forward. The link is made again, once, so the peer takes up the newer.
                    const auto lane = frame.signal.lane == sg::net::DeliveryClass::Latest ? 1 : 0;
                    const auto said = said_session_.find(from);
                    if (said != said_session_.end() && frame.signal.session < said->second[lane] && !live_->connected(from) &&
                        now_ >= behind_at_[from] + 15000 && connected_.count(from)) {
                        behind_at_[from] = now_;
                        live_->reconnect(from);
                    }
                }
            } catch (const std::exception&) {
            }
            return true;
        }
    }
    return false;
}

// ---- calls (protocol 7): the `call` and `call_join` messages, chunks and roots on the live link ----
//
// Everyone to everyone (Mesh): each says its own to each. A swarm (Swarm):
// the one who started it streams, in pieces of 250 ms, to the forwarder of
// each piece's stripe; the rest is pulled between neighbours. Speakers
// through a tree (Hybrid): each speaks to the relay of its stripe, who
// gives it on to all. In both, who is in it is the starter's roster epoch,
// sealed by a handoff, with a new key for each generation.

namespace {
constexpr std::uint64_t talk_root_ms = 100;     // talk: a root a tenth of a second
constexpr std::uint64_t stream_root_ms = 1000;  // a stream: a root a second
constexpr std::uint64_t piece_ms = 250;         // a stream's piece
constexpr std::uint64_t map_every_ms = 250;     // a viewer says what it holds
constexpr std::uint64_t ring_for_ms = 120000;   // a call older than this when it comes is not rung
constexpr std::size_t stripes_of_a_call = 4;

struct CallInvite {
    CallId call{};
    CallMode mode = CallMode::Mesh;
    std::uint64_t generation = 0;
    Key32 secret{};
};
Bytes encode(const CallInvite& i) { return Writer().u8(7).raw(i.call).u8(std::uint8_t(i.mode)).u64(i.generation).raw(i.secret).take(); }
CallInvite decode_call_invite(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 7) throw Refused("chat: unknown call version");
    CallInvite i;
    i.call = r.fixed<16>();
    const auto mode = r.u8();
    if (mode > 2) throw Refused("chat: unknown call mode");
    i.mode = CallMode(mode);
    i.generation = r.u64();
    i.secret = r.key();
    r.end();
    return i;
}
// u8 7 | call | u8 in | u8 what it can give (a swarm's viewers)
Bytes join_body(const CallId& call, bool in, Capacity capacity) {
    return Writer().u8(7).raw(call).u8(in ? 1 : 0).u8(std::uint8_t(capacity)).take();
}
struct Join {
    CallId call{};
    bool in = false;
    Capacity capacity = Capacity::Take;
};
Join decode_join(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 7) throw Refused("chat: unknown call version");
    Join j;
    j.call = r.fixed<16>();
    const auto in = r.u8();
    const auto cap = r.u8();
    if (in > 1 || cap > 2) throw Refused("chat: a join is in or out, with what it gives");
    r.end();
    j.in = in == 1;
    j.capacity = Capacity(cap);
    return j;
}
// The next key, to one device: signed by its maker, bound to its recipient.
Bytes key_statement(const CallId& call, std::uint64_t generation, const Key32& to, const Key32& secret) {
    return Writer("sg.chat.v7.call.next").raw(call).u64(generation).raw(to).raw(secret).take();
}
std::string id_hex(const CallId& c) { return hex(Bytes(c.begin(), c.end())); }
// A stream's piece: the frames of 250 ms, each as it was encoded.
struct PieceFrame {
    Layer layer = Layer::Full;
    bool key_frame = false;
    std::uint64_t captured_us = 0;
    Bytes data;
};
Bytes encode(const std::vector<PieceFrame>& fs) {
    Writer w;
    w.u8(7).u16(std::uint16_t(fs.size()));
    for (const auto& f : fs) w.u8(std::uint8_t(f.layer)).u8(f.key_frame ? 1 : 0).u64(f.captured_us).long_bytes(f.data, 200000);
    return w.take();
}
std::vector<PieceFrame> decode_frames(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 7) throw Refused("chat: not a piece");
    std::vector<PieceFrame> out;
    for (unsigned n = r.u16(); n > 0; --n) {
        PieceFrame f;
        const auto layer = r.u8();
        if (layer > 2) throw Refused("chat: unknown layer");
        f.layer = Layer(layer);
        f.key_frame = r.u8() != 0;
        f.captured_us = r.u64();
        f.data = r.long_bytes(200000);
        out.push_back(std::move(f));
    }
    r.end();
    return out;
}
}  // namespace

struct App::Call {
    CallId id{};
    std::string hexid, conversation, starter;
    CallMode mode = CallMode::Mesh;
    std::uint64_t generation = 0;
    Key32 secret{};
    std::map<std::uint64_t, Key32> keys;  // by generation, to open what comes
    bool joined = false;
    Capacity capacity = Capacity::Take;   // what this device gives, in a swarm
    std::set<std::string> in;
    // The roster (Swarm, Hybrid): sealed by the starter; who forwards what.
    Roster roster;
    std::map<std::string, Capacity> asked;  // the starter's: who joined, with what they give
    std::uint64_t roster_tick = 0;
    sg::net::Digest roster_previous{};
    bool sealing = false, again = false;  // one roster sealed at a time; a change meanwhile, sealed after
    std::vector<std::string> forwarders, neighbours;
    std::unique_ptr<SwarmPeer> swarm;
    std::map<std::uint64_t, Bytes> pieces;  // what this viewer holds, to give on
    std::set<sg::net::Digest> roots_seen;
    std::uint64_t last_map = 0;
    // Saying, each layer a stream of its own: the next number, and what the
    // next root will name.
    struct Out {
        std::uint64_t sequence = 0, root_first = 0, last_root = 0;
        std::vector<sg::net::Digest> unrooted;
    };
    std::map<Layer, Out> out;
    // Simulcast (a tree): whose full picture this device asked for; a
    // relay's: who asked for whose.
    std::string picked;
    std::map<std::string, std::string> picks;
    std::vector<PieceFrame> bundle;  // a stream's piece being made
    std::uint64_t bundle_since = 0;
    // Hearing: each streamer's playback, and since when it has waited on a gap.
    std::map<std::string, std::unique_ptr<Playback>> playbacks;
    std::map<std::string, std::uint64_t> stuck_since;
    std::uint64_t sent = 0, played = 0, roots = 0;
    Key32 key() const { return keys.at(generation); }
    bool talk() const { return mode != CallMode::Swarm; }
    std::uint64_t root_every() const { return talk() ? talk_root_ms : stream_root_ms; }
    std::uint64_t patience() const { return talk() ? 400 : 3000; }
};

std::string App::start_call(const std::string& id, CallMode mode) {
    auto& c = conv(id);
    if (!member_here(id) || c.removed) throw Refused("chat: only a member calls");
    if (c.kind == Kind::Channel) throw Refused("chat: a channel streams to its readers; it does not call");
    CallInvite inv;
    const auto r = random_bytes(16);
    std::copy(r.begin(), r.end(), inv.call.begin());
    inv.mode = mode;
    inv.secret = random_key();
    auto k = std::make_unique<Call>();
    k->id = inv.call;
    k->hexid = id_hex(inv.call);
    k->conversation = id;
    k->starter = peer_;
    k->mode = mode;
    k->secret = inv.secret;
    k->keys[0] = call_key(inv.secret, inv.call, 0, sg::net::Digest{});
    k->joined = true;
    k->capacity = Capacity::Seed;
    k->in.insert(peer_);
    k->roster.call = inv.call;
    const auto hexid = k->hexid;
    calls_[hexid] = std::move(k);
    open_call(*calls_[hexid]);
    post_kind(c, "call", encode(inv));
    return hexid;
}

void App::open_call(Call& k) {
    // The call's state in the world, made by its edit; a mesh has one stripe.
    const auto& c = conv(k.conversation);
    if (!graph_.contains(call_state(k.id))) {
        engine_->send("contacts", {"call.start", call_start_args(c.id, k.id, int(k.mode),
                                                                 k.mode == CallMode::Mesh ? 1 : int(stripes_of_a_call))});
        settle();
    }
}

void App::join_call(const std::string& call, Capacity capacity) {
    const auto it = calls_.find(call);
    if (it == calls_.end()) throw Refused("chat: no such call");
    auto& k = *it->second;
    if (k.joined) return;
    k.joined = true;
    k.capacity = capacity;
    k.in.insert(peer_);
    open_call(k);
    post_kind(conv(k.conversation), "call_join", join_body(k.id, true, capacity));
    if (live_)
        for (const auto& p : k.in)
            if (p != peer_) live_->connect(p);
}

void App::leave_call(const std::string& call) {
    const auto it = calls_.find(call);
    if (it == calls_.end()) return;
    auto& k = *it->second;
    if (k.joined && conversations_.count(k.conversation)) post_kind(conv(k.conversation), "call_join", join_body(k.id, false, k.capacity));
    if (conversations_.count(k.conversation) && graph_.contains(call_state(k.id))) {
        engine_->send("contacts", {"call.end", call_end_args(conv(k.conversation).id, k.id)});
        settle();
    }
    notices_.push_back({"call_ended", k.conversation, peer_, k.hexid});
    calls_.erase(it);
}

std::vector<App::CallView> App::calls() const {
    std::vector<CallView> out;
    for (const auto& [id, k] : calls_) {
        CallView v;
        v.id = id;
        v.conversation = k->conversation;
        v.starter = k->starter;
        v.mode = k->mode;
        v.joined = k->joined;
        v.generation = k->generation;
        v.in.assign(k->in.begin(), k->in.end());
        v.forwarders = k->forwarders;
        v.sent = k->sent;
        v.played = k->played;
        v.roots = k->roots;
        for (const auto& [p, pb] : k->playbacks) v.refused += pb->refused();
        out.push_back(v);
    }
    return out;
}

void App::call_message(Conversation& c, const sg::net::Observation& o, Type type, const Bytes& body, std::uint64_t said_ms) {
    if (type == Type::Call) {
        const auto inv = decode_call_invite(body);
        const auto hexid = id_hex(inv.call);
        if (calls_.count(hexid) || inv.generation != 0 || now_ > said_ms + ring_for_ms) return;  // known, or over by now
        auto k = std::make_unique<Call>();
        k->id = inv.call;
        k->hexid = hexid;
        k->conversation = c.hexid;
        k->starter = o.peer;
        k->mode = inv.mode;
        k->secret = inv.secret;
        k->keys[0] = call_key(inv.secret, inv.call, 0, sg::net::Digest{});
        k->in.insert(o.peer);
        k->roster.call = inv.call;
        calls_[hexid] = std::move(k);
        Notice n{"call", c.hexid, o.peer, hexid};
        n.type = std::to_string(int(inv.mode));
        n.time = said_ms;
        notices_.push_back(n);
        return;
    }
    const auto j = decode_join(body);
    const auto it = calls_.find(id_hex(j.call));
    if (it == calls_.end() || it->second->conversation != c.hexid) return;
    auto& k = *it->second;
    if (j.in) {
        k.in.insert(o.peer);
        k.asked[o.peer] = j.capacity;
        notices_.push_back({"call_joined", c.hexid, o.peer, k.hexid});
        if (live_ && k.joined) live_->connect(o.peer);
    } else {
        k.in.erase(o.peer);
        k.asked.erase(o.peer);
        k.playbacks.erase(o.peer);
        notices_.push_back({"call_left", c.hexid, o.peer, k.hexid});
    }
    if (!k.joined || k.starter != peer_) {
        if (!j.in && k.joined && k.in.size() <= 1) leave_call(k.hexid);
        return;
    }
    // The starter: a mesh turns its key when one leaves; a swarm or a tree
    // seals its next roster, and everyone on it gets the next key.
    if (k.mode == CallMode::Mesh) {
        if (!j.in) turn_call_key(k);
    } else {
        seal_call_roster(k);
    }
    if (!j.in && k.in.size() <= 1) leave_call(k.hexid);
}

// The next roster: an epoch of the call's committee (the starter's device),
// finalized, sealed by a handoff to the next generation, sent to each on it.
void App::seal_call_roster(Call& k) {
    if (k.sealing) {
        k.again = true;
        return;
    }
    k.sealing = true;
    auto& c = conv(k.conversation);
    Roster r;
    r.call = k.id;
    r.generation = k.generation + 1;
    for (const auto& [p, cap] : k.asked) {
        const auto* m = c.member(p);
        if (m && k.in.count(p)) r.viewers.push_back({m->device, cap});
    }
    r.viewers.push_back({self_, Capacity::Seed});
    std::sort(r.viewers.begin(), r.viewers.end(), [](const Viewer& a, const Viewer& b) { return peer_of(a.device) < peer_of(b.device); });
    const auto old = call_committee(k.id, k.generation, {self_});
    const auto ctx = roster_context(k.id, old, k.roster_tick, k.roster_previous);
    auto statement = roster_statement(k.id, ctx, peer_, r);
    // Three signatures, one after another: the statement, the certificate,
    // the vote; then the handoff's endorsement. The browser holds the key.
    sign(statement.statement(), [this, call = k.hexid, ctx, statement, r, old](const sg::net::Signature& s1) mutable {
        if (!calls_.count(call)) return;
        statement.signature = s1;
        const auto problem = roster_problem(ctx, statement);
        auto cert = certificate_for(problem, peer_, roster_checkpoint(problem));
        sign(cert.statement(), [this, call, ctx, problem, r, old, cert](const sg::net::Signature& s2) mutable {
            if (!calls_.count(call)) return;
            cert.signature = s2;
            const auto proposal = proposal_for(cert);
            const auto verify = roster_verify(r.call);
            const auto v = verify.proposal(problem, old, proposal);
            if (!v) return;
            auto vote = attestation_for(*v, peer_);
            sign(vote.statement(), [this, call, ctx, problem, r, old, proposal, v, vote](const sg::net::Signature& s3) mutable {
                if (!calls_.count(call)) return;
                vote.signature = s3;
                auto& k = *calls_[call];
                sg::net::Agreement agreement(old, k.roster_previous, k.roster_tick, {}, ctx.world);
                const auto verify = roster_verify(r.call);
                if (!agreement.receive(*v, vote)) return;
                const auto fin = agreement.finalize(*v, proposal);
                if (!fin || !agreement.accept(problem, verify, *fin)) return;
                sg::net::Handoff h{*fin, v->checkpoint(), call_committee(r.call, r.generation, {self_}), {}};
                auto e = endorsement_for(problem, h, peer_);
                sign(e.statement(), [this, call, ctx, problem, r, h, fin](const sg::net::Signature& s4) mutable {
                    if (!calls_.count(call)) return;
                    auto e = endorsement_for(problem, h, peer_);
                    e.signature = s4;
                    h.endorsements.push_back(e);
                    auto& k = *calls_[call];
                    const Finalized f{ctx, problem.epoch.ordered_inputs[0], *fin, h.checkpoint};
                    const auto frame = Writer().u8(7).long_bytes(encode(f), 1 << 22).long_bytes(encode(h), 1 << 20).take();
                    take_call_roster(k, r, *fin);
                    auto& c = conv(k.conversation);
                    for (const auto& v : r.viewers) {
                        const auto p = peer_of(v.device);
                        if (p != peer_) send_control(c, Control::CallRoster, frame, p);
                    }
                    turn_call_key(k);
                    k.sealing = false;
                    if (std::exchange(k.again, false)) seal_call_roster(k);
                });
            });
        });
    });
}

// A roster believed: the world told (next generation, and who forwards
// what - each device plans the same, from the same finalized roster).
void App::take_call_roster(Call& k, const Roster& r, const sg::net::Finalization& fin) {
    k.roster = r;
    k.roster_tick = k.roster_tick + 1;
    k.roster_previous = fin.id();
    const auto& c = conv(k.conversation);
    if (!graph_.contains(call_state(k.id))) open_call(k);
    engine_->send(call_state(k.id), {call_state(k.id) + ".roster", call_roster_args(c.id, k.id, r.generation, r.viewers.size())});
    settle();
    const auto& state = graph_.state(call_state(k.id));
    sg::net::Cellular cellular(state);
    const auto plan = plan_stripes(state, cellular, r, fin.id(), k.roster_tick, 0);
    k.forwarders = plan.forwarders;
    engine_->send(call_state(k.id), {call_state(k.id) + ".place", call_place_args(c.id, k.id, r.generation, k.roster_tick, k.forwarders)});
    settle();
    // Neighbours, both ways: the forwarders and three on a ring of the roster.
    std::vector<std::string> on;
    for (const auto& v : r.viewers) on.push_back(peer_of(v.device));
    std::map<std::string, std::set<std::string>> both;
    for (std::size_t i = 0; i < on.size(); ++i) {
        std::set<std::string> mine(k.forwarders.begin(), k.forwarders.end());
        for (std::size_t s = 1; s <= 3 && s < on.size(); ++s) mine.insert(on[(i + s) % on.size()]);
        mine.erase(on[i]);
        mine.erase("");
        for (const auto& q : mine) both[on[i]].insert(q), both[q].insert(on[i]);
    }
    k.neighbours.assign(both[peer_].begin(), both[peer_].end());
    if (!k.swarm) k.swarm = std::make_unique<SwarmPeer>(peer_, stripes_of_a_call);
    k.swarm->neighbours(k.neighbours);
    // A viewer's call is who the roster says; the starter's, who has joined
    // (one who joined meanwhile is in the next roster).
    if (k.starter != peer_) {
        k.in.clear();
        for (const auto& p : on) k.in.insert(p);
    }
    if (live_)
        for (const auto& p : k.neighbours) live_->connect(p);
    notices_.push_back({"call_roster", k.conversation, k.starter, k.hexid});
}

void App::call_roster_frame(Conversation& c, const Member& from, const Bytes& body) {
    Reader rd(body);
    if (rd.u8() != 7) return;
    const auto f = decode_finalized(rd.long_bytes(1 << 22));
    const auto h = decode_handoff(rd.long_bytes(1 << 20));
    rd.end();
    const auto problem = roster_problem(f.context, f.statement);
    const auto r = decode_roster(f.statement.payload);
    const auto it = calls_.find(id_hex(r.call));
    if (it == calls_.end() || it->second->conversation != c.hexid) return;
    auto& k = *it->second;
    // Believed only from the starter, sealed by its committee, and forward.
    if (peer_of(from.device) != k.starter || r.generation <= k.roster.generation) return;
    const auto old = call_committee(r.call, r.generation - 1, {from.device});
    if (!sg::net::verify_handoff(problem, old, roster_verify(r.call), h) || h.finalized.id() != f.finalization.id()) return;
    if (checkpoint_roster(h.checkpoint).digest() != r.digest()) return;
    take_call_roster(k, r, f.finalization);
}

void App::turn_call_key(Call& k) {
    auto& c = conv(k.conversation);
    const auto generation = k.generation + 1;
    const auto secret = random_key();
    const auto roster = k.talk() && k.mode == CallMode::Mesh ? sg::net::Digest{} : k.roster.digest();
    for (const auto& p : k.in) {
        if (p == peer_) continue;
        const auto* m = c.member(p);
        if (!m) continue;
        const auto to = device_id(m->device);
        sign(key_statement(k.id, generation, to, secret), [this, cid = c.hexid, call = k.hexid, generation, secret, p](const sg::net::Signature& s) {
            if (!conversations_.count(cid) || !calls_.count(call)) return;
            send_control(conv(cid), Control::CallKey, Writer().u8(7).raw(calls_[call]->id).u64(generation).raw(secret).raw(s).take(), p);
        });
    }
    k.secret = secret;
    k.generation = generation;
    k.keys[generation] = call_key(secret, k.id, generation, roster);
    while (k.keys.size() > 3) k.keys.erase(k.keys.begin());
}

void App::call_key_frame(Conversation& c, const Member& from, const Bytes& body) {
    Reader r(body);
    if (r.u8() != 7) return;
    const auto call = r.fixed<16>();
    const auto generation = r.u64();
    const auto secret = r.key();
    const auto sig = r.fixed<64>();
    r.end();
    const auto it = calls_.find(id_hex(call));
    if (it == calls_.end() || it->second->conversation != c.hexid) return;
    auto& k = *it->second;
    // Only from the one who started it, for this device, and only forward.
    if (peer_of(from.device) != k.starter || generation <= k.generation) return;
    sg::net::Signature s{};
    std::copy(sig.begin(), sig.end(), s.begin());
    if (!sg::net::check_signature(from.device.sign, key_statement(call, generation, id_, secret), s)) return;
    // A roster generation's key binds its roster: this device must have it.
    const auto roster = k.mode == CallMode::Mesh ? sg::net::Digest{} : k.roster.digest();
    if (k.mode != CallMode::Mesh && k.roster.generation != generation) return;
    k.secret = secret;
    k.generation = generation;
    k.keys[generation] = call_key(secret, call, generation, roster);
    while (k.keys.size() > 3) k.keys.erase(k.keys.begin());
}

void App::send_media(const std::string& call, Layer layer, bool key_frame, std::uint64_t captured_us, const Bytes& media) {
    const auto it = calls_.find(call);
    if (it == calls_.end() || !it->second->joined) throw Refused("chat: not in that call");
    auto& k = *it->second;
    if (k.mode == CallMode::Swarm && k.starter != peer_) throw Refused("chat: a swarm's viewers watch; its starter streams");
    if (k.mode == CallMode::Swarm) {
        // Frames gathered into a piece; sealed when it is 250 ms long.
        if (k.bundle.empty()) k.bundle_since = now_;
        k.bundle.push_back({layer, key_frame, captured_us, media});
        if (now_ >= k.bundle_since + piece_ms) pump_calls();
        return;
    }
    send_chunk(k, layer, key_frame, captured_us, media);
}

// One chunk, sealed under this generation's key, to whoever it goes to first.
void App::send_chunk(Call& k, Layer layer, bool key_frame, std::uint64_t captured_us, const Bytes& media) {
    auto& o = k.out[layer];
    ChunkHeader h{k.id, id_, k.generation, o.sequence++, layer, key_frame, captured_us};
    const auto chunk = seal_chunk(k.key(), h, random_nonce(), media);
    o.unrooted.push_back(chunk_hash(chunk));
    ++k.sent;
    if (!live_) return;
    const auto slot = k.hexid + ":" + std::to_string(int(layer)) + ":" + std::to_string(h.sequence);
    // A mesh: to everyone. A swarm: to its stripe's forwarder. A tree: to this
    // speaker's relay, who gives it on. Without a forwarder: to everyone.
    std::string first;
    if (k.mode == CallMode::Swarm && !k.forwarders.empty()) first = k.forwarders[std::size_t(h.sequence % k.forwarders.size())];
    if (k.mode == CallMode::Hybrid && !k.forwarders.empty()) {
        std::size_t at = 0;
        for (const auto& v : k.roster.viewers) {
            if (peer_of(v.device) == peer_) break;
            ++at;
        }
        first = k.forwarders[at % k.forwarders.size()];
    }
    if (!first.empty() && first != peer_) {
        live_->send_latest(first, "call", slot, chunk);
        return;
    }
    for (const auto& p : k.in)
        if (p != peer_ && wants_layer(k, p, peer_, layer)) live_->send_latest(p, "call", slot, chunk);
}

// In a tree, a speaker's full picture goes only to those who asked for it
// (simulcast); the small one and the sound, to everyone.
bool App::wants_layer(const Call& k, const std::string& listener, const std::string& speaker, Layer layer) const {
    if (k.mode != CallMode::Hybrid || layer != Layer::Full) return true;
    const auto p = k.picks.find(listener);
    return p != k.picks.end() && p->second == speaker;
}

void App::pick_full(const std::string& call, const std::string& speaker) {
    const auto it = calls_.find(call);
    if (it == calls_.end() || !it->second->joined) return;
    auto& k = *it->second;
    k.picked = speaker;
    if (!live_) return;
    // Told to the relays (and to the speaker, who may be its own).
    std::set<std::string> to(k.forwarders.begin(), k.forwarders.end());
    to.insert(speaker);
    const auto frame = Writer().u8(7).raw(k.id).short_text(speaker).take();
    for (const auto& p : to)
        if (!p.empty() && p != peer_) live_->send(p, "callpick", frame);
    if (to.count(peer_)) k.picks[peer_] = speaker;
}
void App::call_pick(const std::string& peer, const Bytes& bytes) {
    try {
        Reader r(bytes);
        if (r.u8() != 7) return;
        const auto call = r.fixed<16>();
        const auto speaker = r.short_text(128);
        r.end();
        const auto it = calls_.find(id_hex(call));
        if (it == calls_.end() || !it->second->in.count(peer)) return;
        it->second->picks[peer] = speaker;
    } catch (const std::exception&) {
    }
}

void App::pump_calls() {
    for (auto& [id, kp] : calls_) {
        auto& k = *kp;
        if (!k.joined) continue;
        if (k.mode == CallMode::Swarm && k.starter == peer_ && !k.bundle.empty() && now_ >= k.bundle_since + piece_ms) {
            bool key = false;
            for (const auto& f : k.bundle) key |= f.key_frame;
            const auto captured = k.bundle.front().captured_us;
            send_chunk(k, Layer::Full, key, captured, encode(k.bundle));
            k.bundle.clear();
        }
        // A root of what each layer said since the last: about every tenth of
        // a second in talk, every second in a stream.
        for (auto& [layer, o] : k.out) {
            if (o.unrooted.empty() || (now_ < o.last_root + k.root_every() && o.unrooted.size() < 1024)) continue;
            Root r;
            r.call = k.id;
            r.streamer = id_;
            r.layer = layer;
            r.generation = k.generation;
            r.first = o.root_first;
            r.hashes = std::exchange(o.unrooted, {});
            o.root_first += r.hashes.size();
            o.last_root = now_;
            std::vector<std::string> to;
            if (k.mode == CallMode::Mesh || k.forwarders.empty()) {
                to.assign(k.in.begin(), k.in.end());
            } else {
                // Roots are small: to the forwarders (or relays) and the neighbours; flooded on from there once.
                std::set<std::string> s(k.forwarders.begin(), k.forwarders.end());
                s.insert(k.neighbours.begin(), k.neighbours.end());
                if (k.mode == CallMode::Hybrid) s.insert(k.in.begin(), k.in.end());
                to.assign(s.begin(), s.end());
            }
            sign(r.statement(), [this, call = id, r, to](const sg::net::Signature& s) mutable {
                r.signature = s;
                const auto bytes = encode(r);
                if (!calls_.count(call)) return;
                auto& k = *calls_[call];
                ++k.roots;
                k.roots_seen.insert(blake2b256(Bytes{}, bytes));
                if (!live_) return;
                for (const auto& p : to)
                    if (p != peer_ && !p.empty() && wants_layer(k, p, peer_, r.layer)) live_->send(p, "callroot", bytes);
            });
        }
        // A swarm's viewer says what it holds, and asks for what it lacks.
        if (k.mode == CallMode::Swarm && k.swarm && k.starter != peer_ && live_ && now_ >= k.last_map + map_every_ms) {
            k.last_map = now_;
            const auto map = Writer().u8(7).raw(k.id).raw(encode(k.swarm->map())).take();
            for (const auto& p : k.neighbours) live_->send(p, "callmap", map);
            const auto* pb = k.playbacks.count(k.starter + ":0") ? k.playbacks[k.starter + ":0"].get() : nullptr;
            const auto from = pb ? pb->played() : 0;
            for (const auto& [peer, piece] : k.swarm->wants(from, from + 16, 4, double(now_))) {
                k.swarm->asked(peer, piece, double(now_));
                live_->send(peer, "callwant", Writer().u8(7).raw(k.id).u64(piece).take());
            }
        }
        // What each stream's playback believes now; a gap waited on long enough is passed over.
        for (auto& [stream, pb] : k.playbacks) {
            const auto streamer = stream.substr(0, stream.find(':'));
            for (auto s : pb->take_refused())
                if (k.swarm) k.swarm->drop(s), k.pieces.erase(s);
            auto ready = pb->take();
            if (ready.empty()) {
                auto& since = k.stuck_since[stream];
                if (!since) since = now_;
                if (now_ - since > k.patience() && pb->skip()) ready = pb->take(), since = 0;
            } else {
                k.stuck_since[stream] = 0;
            }
            for (auto& [seq, chunk] : ready) {
                const auto h = chunk_header(chunk);
                const auto key = k.keys.find(h.generation);
                if (key == k.keys.end()) continue;
                try {
                    const auto media = open_chunk(key->second, chunk);
                    k.pieces[seq] = chunk;  // believed: what it gives on
                    if (k.mode == CallMode::Swarm) {
                        std::uint64_t i = 0;
                        for (auto& f : decode_frames(media))
                            media_.push_back(Media{k.hexid, streamer, seq * 1024 + i++, f.captured_us, f.layer, f.key_frame, std::move(f.data)});
                    } else {
                        media_.push_back(Media{k.hexid, streamer, seq, h.captured_us, h.layer, h.key_frame, media});
                    }
                    ++k.played;
                } catch (const std::exception&) {
                }
            }
            if (k.swarm && !ready.empty()) {
                const auto keep_from = ready.back().first > 64 ? ready.back().first - 64 : 0;
                k.swarm->forget_before(keep_from);
                k.pieces.erase(k.pieces.begin(), k.pieces.lower_bound(keep_from));
            }
        }
    }
}

Playback* App::playback_of(Call& k, const std::string& streamer, const Key32& streamer_id, Layer layer) {
    const auto stream = streamer + ":" + std::to_string(int(layer));
    auto& pb = k.playbacks[stream];
    if (!pb) {
        const auto* m = conv(k.conversation).member(streamer);
        if (!m) {
            k.playbacks.erase(stream);
            return nullptr;
        }
        pb = std::make_unique<Playback>(k.id, streamer_id, m->device.sign, layer);
    }
    return pb.get();
}

void App::call_chunk(const std::string& peer, const Bytes& chunk) {
    try {
        const auto h = chunk_header(chunk);
        const auto it = calls_.find(id_hex(h.call));
        if (it == calls_.end() || !it->second->joined) return;
        auto& k = *it->second;
        const auto streamer = hex(h.streamer);
        if (streamer == peer_) return;
        // A mesh: each streams its own. A swarm: the starter's alone. A tree: any speaker in it.
        if (k.mode == CallMode::Mesh && streamer != peer) return;
        if (k.mode == CallMode::Swarm && streamer != k.starter) return;
        if (!k.in.count(streamer)) return;
        auto* pb = playback_of(k, streamer, h.streamer, h.layer);
        if (!pb) return;
        const auto verdict = pb->chunk(chunk);
        if (verdict == "refused" || verdict == "late") return;
        if (k.mode == CallMode::Swarm && k.swarm) {
            k.swarm->answered(peer, h.sequence);
            const bool had = k.swarm->holds(h.sequence);
            k.swarm->hold(h.sequence);
            if (!had || verdict == "ready") k.pieces[h.sequence] = chunk;
        }
        // The streamer's own copy, to the forwarder of its stripe (a swarm) or
        // the speaker's relay (a tree): given on at once.
        if (!live_ || peer != streamer || k.forwarders.empty()) return;
        if (k.mode == CallMode::Swarm && k.forwarders[std::size_t(h.sequence % k.forwarders.size())] == peer_) {
            for (std::size_t i = 0; i < std::min<std::size_t>(6, k.neighbours.size()); ++i)
                live_->send_latest(k.neighbours[(std::size_t(h.sequence / k.forwarders.size()) * 6 + i) % k.neighbours.size()], "call",
                                   k.hexid + ":" + std::to_string(h.sequence), chunk);
        }
        if (k.mode == CallMode::Hybrid)
            for (const auto& p : k.in)
                if (p != peer_ && p != streamer && wants_layer(k, p, streamer, h.layer))
                    live_->send_latest(p, "call", k.hexid + ":" + streamer + ":" + std::to_string(int(h.layer)) + ":" + std::to_string(h.sequence), chunk);
    } catch (const std::exception&) {
    }
}

void App::call_root(const std::string& peer, const Bytes& bytes) {
    try {
        const auto r = decode_root(bytes);
        const auto it = calls_.find(id_hex(r.call));
        if (it == calls_.end() || !it->second->joined) return;
        auto& k = *it->second;
        const auto streamer = hex(r.streamer);
        if (streamer == peer_) return;
        if (k.mode == CallMode::Mesh && streamer != peer) return;
        if (k.mode == CallMode::Swarm && streamer != k.starter) return;
        auto* pb = playback_of(k, streamer, r.streamer, r.layer);
        if (!pb || !k.roots_seen.insert(blake2b256(Bytes{}, bytes)).second) return;
        pb->root(r);
        // Flooded on once: to neighbours in a swarm, to everyone from a relay in a tree.
        if (!live_ || k.mode == CallMode::Mesh) return;
        if (k.mode == CallMode::Swarm)
            for (const auto& p : k.neighbours)
                if (p != peer) live_->send(p, "callroot", bytes);
        if (k.mode == CallMode::Hybrid && peer == streamer)
            for (const auto& p : k.in)
                if (p != peer_ && p != streamer && wants_layer(k, p, streamer, r.layer)) live_->send(p, "callroot", bytes);
    } catch (const std::exception&) {
    }
}

// A swarm's neighbours: what one holds, and what one asks for.
void App::call_map(const std::string& peer, const Bytes& bytes) {
    try {
        Reader r(bytes);
        if (r.u8() != 7) return;
        const auto call = r.fixed<16>();
        const auto map = decode_buffer_map(r.raw(r.left()));
        const auto it = calls_.find(id_hex(call));
        if (it == calls_.end() || !it->second->swarm) return;
        it->second->swarm->heard(peer, map);
    } catch (const std::exception&) {
    }
}
void App::call_want(const std::string& peer, const Bytes& bytes) {
    try {
        Reader r(bytes);
        if (r.u8() != 7) return;
        const auto call = r.fixed<16>();
        const auto piece = r.u64();
        r.end();
        const auto it = calls_.find(id_hex(call));
        if (it == calls_.end() || !live_) return;
        auto& k = *it->second;
        if (std::find(k.neighbours.begin(), k.neighbours.end(), peer) == k.neighbours.end()) return;
        // What it gives on: the copy a root it holds names, else the first that
        // came - never one a root says is not it.
        auto* pb = k.playbacks.count(k.starter + ":0") ? k.playbacks[k.starter + ":0"].get() : nullptr;
        if (pb)
            if (const auto b = pb->believed(piece)) {
                live_->send_latest(peer, "call", k.hexid + ":" + std::to_string(piece), *b);
                return;
            }
        const auto c = k.pieces.find(piece);
        if (c == k.pieces.end()) return;
        if (pb)
            if (const auto named = pb->named(piece); named && *named != chunk_hash(c->second)) return;
        live_->send_latest(peer, "call", k.hexid + ":" + std::to_string(piece), c->second);
    } catch (const std::exception&) {
    }
}

std::vector<App::Media> App::take_media() { return std::exchange(media_, {}); }

// ---- live state (protocol 8): tape tennis ----

namespace {
// u8 8 | game(16) | u8 what (0 asks, 1 plays, 2 stops)
Bytes game_body(const CallId& id, int what) { return Writer().u8(8).raw(id).u8(std::uint8_t(what)).take(); }
}  // namespace

struct App::Board {
    struct PenState {
        std::unique_ptr<sg::net::Prediction> prediction;
        double last_x = 0, last_y = 0;
        std::uint64_t last_frame = 0;
        bool down = false;
        int color = 0;
    };
    std::map<std::string, PenState> pens;  // others', by device
};

struct App::Game {
    CallId id{};
    std::string hexid, conversation, asker, opponent;
    int player = 0;
    bool playing = false;
    int move = 0, their_move = 0;
    std::unique_ptr<sg::net::Prediction> prediction;
    std::int64_t last_epoch = 0;
    std::vector<Bytes> out;  // the network's boundary packets, to the other
    std::string game, net;
    std::uint64_t sent = 0, received = 0;  // packets, for looking
    std::uint64_t packets = 0;              // a slot of its own for each, on the Latest lane
    std::deque<Bytes> last;                 // the last two packets, said again till the step is agreed
    std::uint64_t said_at = 0;
};

std::string App::start_game(const std::string& id) {
    auto& c = conv(id);
    if (c.kind != Kind::Direct || !member_here(id) || c.removed) throw Refused("chat: a game of two is played in a two-sided conversation");
    auto g = std::make_unique<Game>();
    const auto r = random_bytes(16);
    std::copy(r.begin(), r.end(), g->id.begin());
    g->hexid = hex(r);
    g->conversation = id;
    g->asker = peer_;
    g->player = 0;
    const auto hexid = g->hexid;
    post_kind(c, "game", game_body(g->id, 0));
    games_[hexid] = std::move(g);
    return hexid;
}

void App::join_game(const std::string& id) {
    const auto it = games_.find(id);
    if (it == games_.end()) throw Refused("chat: no such game");
    auto& g = *it->second;
    if (g.playing) return;
    g.player = 1;
    g.opponent = g.asker;
    post_kind(conv(g.conversation), "game", game_body(g.id, 1));
    open_game(g);
}

void App::leave_game(const std::string& id) {
    const auto it = games_.find(id);
    if (it == games_.end()) return;
    auto& g = *it->second;
    if (conversations_.count(g.conversation)) {
        post_kind(conv(g.conversation), "game", game_body(g.id, 2));
        if (graph_.contains(game_state(g.id))) {
            engine_->send("contacts", {"game.end", game_args(conv(g.conversation).id, g.id)});
            settle();
        }
    }
    notices_.push_back({"game_over", g.conversation, peer_, g.hexid});
    games_.erase(it);
}

// The court made in this world, set as this device's player, and listened to:
// what its network says goes to the other player.
void App::open_game(Game& g) {
    const auto& c = conv(g.conversation);
    g.game = game_state(g.id);
    g.net = game_net_state(g.id);
    if (!graph_.contains(g.game)) {
        engine_->send("contacts", {"game.start", game_args(c.id, g.id)});
        settle();
    }
    if (!graph_.contains(g.game)) return;
    g.playing = true;
    const auto id = g.hexid;
    graph_.state(g.net).bus().subscribe(g.net + ".boundary", [this, id](const sg::Event& e) {
        if (games_.count(id)) games_[id]->out.push_back(sg::net::Exchange::bytes(e.args));
    });
    const auto config = sg::Params{}.set("player", std::int64_t(g.player));
    engine_->send(g.game, {g.game + ".configure", config});
    engine_->send(g.net, {g.net + ".configure", config});
    engine_->send(g.game, {g.game + ".publish", {}});
    settle();
    g.prediction = std::make_unique<sg::net::Prediction>(court_forecast(graph_.state(g.game)), court_lead, 128,
                                                         std::vector<std::uint8_t>{1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0});
    g.prediction->reset(0, court_frame(graph_.state(g.game)));
    if (live_) live_->connect(g.opponent);
    notices_.push_back({"game_on", g.conversation, g.opponent, g.hexid});
}

void App::game_message(Conversation& c, const sg::net::Observation& o, const Bytes& body) {
    Reader r(body);
    if (r.u8() != 8) return;
    const auto id = r.fixed<16>();
    const auto what = r.u8();
    r.end();
    const auto hexid = hex(Bytes(id.begin(), id.end()));
    auto it = games_.find(hexid);
    if (what == 0) {
        if (it != games_.end() || o.peer == peer_) return;
        auto g = std::make_unique<Game>();
        g->id = id;
        g->hexid = hexid;
        g->conversation = c.hexid;
        g->asker = o.peer;
        games_[hexid] = std::move(g);
        notices_.push_back({"game", c.hexid, o.peer, hexid});
        return;
    }
    if (it == games_.end() || it->second->conversation != c.hexid) return;
    auto& g = *it->second;
    if (what == 1 && g.asker == peer_ && !g.playing) {
        g.opponent = o.peer;
        open_game(g);
    } else if (what == 2) {
        if (graph_.contains(game_state(g.id))) {
            engine_->send("contacts", {"game.end", game_args(c.id, g.id)});
            settle();
        }
        notices_.push_back({"game_over", c.hexid, o.peer, hexid});
        games_.erase(it);
    }
}

void App::game_input(const std::string& id, int move) {
    const auto it = games_.find(id);
    if (it == games_.end() || !it->second->playing) return;
    auto& g = *it->second;
    g.move = move > 0 ? 1 : move < 0 ? -1 : 0;
    engine_->send(g.game, {g.game + ".input", sg::Params{}.set("move", double(g.move))});
}

// A packet from the other player: the network's own receive arrow takes it.
void App::game_packet(const std::string& peer, const Bytes& bytes) {
    try {
        Reader r(bytes);
        if (r.u8() != 8) return;
        const auto id = r.fixed<16>();
        const auto packet = r.raw(r.left());
        const auto it = games_.find(hex(Bytes(id.begin(), id.end())));
        if (it == games_.end() || !it->second->playing || it->second->opponent != peer) return;
        const auto p = sg::net::Exchange::decode(packet);  // refused here if it does not read
        (void)p;
        engine_->send(it->second->net, {it->second->net + ".receive", sg::net::Exchange::arguments(packet)});
        ++it->second->received;
    } catch (const std::exception&) {
    }
}

// While a game is on, the world steps in frames of 1/60 s (each state on its
// own line of the game's time); what its network said goes to the other.
void App::pump_games() {
    bool any = !boards_.empty();
    for (const auto& [id, g] : games_) any |= g->playing;
    if (!any) {
        last_frame_ = now_;
        return;
    }
    if (!last_frame_) last_frame_ = now_;
    int frames = 0;
    while (now_ >= last_frame_ + 16 && frames < 8) {
        last_frame_ += 16;
        ++frames;
        ++frames_;
        engine_->tick(court_step);
        frame_time_ += court_step;
        for (auto& [cid, b] : boards_)
            for (auto& [peer, p] : b->pens) p.prediction->advance({});
        for (auto& [id, g] : games_) {
            if (!g->playing || !graph_.contains(g->game)) continue;
            const auto& court = graph_.state(g->game);
            const auto epoch = court.params().get_or<std::int64_t>("epoch", 0);
            if (epoch != g->last_epoch) {
                // Agreed: the step before's last packets stay a while yet - the
                // other may not have seen it agreed (they are said again only
                // until the next step's own replace them).
                g->prediction->reconcile(std::uint64_t(epoch) * std::uint64_t(court.params().get_or<std::int64_t>("steps", 6)), court_frame(court), frame_time_);
                g->last_epoch = epoch;
                // What the other did, as agreed: the forecast's guess at its control.
                const auto& mine = court.element(sg::Key("p" + std::to_string(g->player))).params;
                g->their_move = int(mine.num(sg::Key("command_" + std::to_string(1 - g->player)), 0));
            }
            sg::net::DiscreteInputs in{0, 0};
            in[std::size_t(g->player)] = g->move;
            in[std::size_t(1 - g->player)] = g->their_move;
            g->prediction->advance(in);
        }
    }
    if (now_ > last_frame_ + 200) last_frame_ = now_;  // far behind (a tab asleep): not caught up frame by frame
    if (!live_) return;
    for (auto& [id, g] : games_) {
        if (!g->playing) continue;
        // Late is lost on the Latest lane: the last two packets (this round's
        // and the one before, which the other may still be waiting on) are
        // said again, every three frames, till the step is agreed.
        if (!g->out.empty()) {
            for (const auto& p : g->out) g->last.push_back(p);
            while (g->last.size() > 2) g->last.pop_front();
            g->said_at = now_;
        } else if (!g->last.empty() && now_ >= g->said_at + 48) {
            g->out.assign(g->last.begin(), g->last.end());
            g->said_at = now_;
        }
        for (const auto& packet : g->out)
            g->sent += live_->send_latest(g->opponent, "game", "game:" + id + ":" + std::to_string(g->packets++),
                                          Writer().u8(8).raw(g->id).raw(packet).take());
        g->out.clear();
    }
}

std::vector<App::GameView> App::games() const {
    std::vector<GameView> out;
    for (const auto& [id, g] : games_) {
        GameView v;
        v.id = id;
        v.conversation = g->conversation;
        v.opponent = g->playing ? g->opponent : g->asker;
        v.player = g->player;
        v.playing = g->playing;
        if (g->playing && graph_.contains(g->game)) {
            const auto& court = graph_.state(g->game);
            v.epoch = court.params().get_or<std::int64_t>("epoch", 0);
            v.left_score = court.params().get_or<std::int64_t>("left_score", 0);
            v.right_score = court.params().get_or<std::int64_t>("right_score", 0);
            v.hits = court.params().get_or<std::int64_t>("hits", 0);
            const auto shown = g->prediction ? g->prediction->display(frame_time_) : court_frame(court);
            v.ball_x = shown[0], v.ball_y = shown[1], v.left_y = shown[4], v.right_y = shown[6];
            // This player's own paddle as it is now, with every move made so
            // far - never smoothed behind the hand that moves it.
            if (g->prediction) (g->player == 0 ? v.left_y : v.right_y) = g->prediction->predicted()[g->player == 0 ? 4 : 6];
            if (g->prediction) v.lead = g->prediction->predicted_tick() - g->prediction->finalized_tick();
            v.sent = g->sent;
            v.received = g->received;
        }
        out.push_back(v);
    }
    return out;
}

// ---- live state (protocol 8): the whiteboard ----

namespace {
// A stroke: u8 8 | u8 color | u8 width | u16 n | n x (i16 x, i16 y), the
// board's square from -32767 to 32767 on each side.
void check_stroke(const Bytes& b) {
    Reader r(b);
    if (r.u8() != 8) throw Refused("chat: not a stroke");
    if (r.u8() > 15) throw Refused("chat: unknown color");
    const auto width = r.u8();
    if (width == 0 || width > 64) throw Refused("chat: a stroke is 1..64 wide");
    const auto n = r.u16();
    if (n == 0 || n > 4096) throw Refused("chat: a stroke is 1..4096 points");
    r.raw(std::size_t(n) * 4);
    r.end();
}
// What goes live on a board: u8 8 | conversation(16) | u8 what | ...
//   1 a pen:  f32 x | f32 y | u8 down | u8 color
//   2 a look: f32 x | f32 y | f32 zoom
//   3 leads:  u8 on
void put_f32(Writer& w, double v) {
    float f = float(v);
    std::uint32_t u;
    std::memcpy(&u, &f, 4);
    w.u32(u);
}
double get_f32(Reader& r) {
    const auto u = r.u32();
    float f;
    std::memcpy(&f, &u, 4);
    if (!std::isfinite(f) || std::fabs(f) > 1e6f) throw Refused("chat: not a place on a board");
    return double(f);
}
}  // namespace

void App::open_board(const std::string& id) {
    auto& c = conv(id);
    if (!member_here(id) || c.removed) throw Refused("chat: only a member draws on a board");
    if (!graph_.contains(board_state(c.id))) {
        engine_->send("contacts", {"board.open", board_args(c.id, c.members)});
        settle();
    }
    if (!boards_.count(id)) boards_[id] = std::make_unique<Board>();
    if (live_) connect_members(c);
}
void App::close_board(const std::string& id) {
    boards_.erase(id);
    if (!conversations_.count(id)) return;
    const auto& c = conv(id);
    if (graph_.contains(board_state(c.id))) {
        engine_->send("contacts", {"board.close", board_args(c.id, c.members)});
        settle();
    }
}
void App::post_stroke(const std::string& id, const Bytes& stroke, std::uint64_t time_ms) {
    auto& c = conv(id);
    check_stroke(stroke);
    (void)time_ms;
    post_kind(c, "stroke", stroke);
    if (boards_.count(id) && graph_.contains(board_state(c.id))) {
        engine_->send(board_state(c.id), {board_state(c.id) + ".stroke", {}});
        settle();
    }
}
void App::board_send(const std::string& id, const Bytes& body) {
    if (!live_) return;
    const auto& c = conv(id);
    for (const auto& m : c.members) {
        const auto p = peer_of(m.device);
        if (p != peer_) live_->send_latest(p, "board", "board:" + id + ":" + std::to_string(body.size() > 18 ? body[17] : 0), body);
    }
}
void App::pen(const std::string& id, double x, double y, bool down, int color) {
    if (!boards_.count(id)) return;
    const auto& c = conv(id);
    Writer w;
    w.u8(8).raw(c.id).u8(1);
    put_f32(w, x);
    put_f32(w, y);
    w.u8(down ? 1 : 0).u8(std::uint8_t(color & 15));
    board_send(id, w.take());
}
void App::look(const std::string& id, double x, double y, double zoom) {
    if (!boards_.count(id)) return;
    const auto& c = conv(id);
    engine_->send(view_state(c.id), {view_state(c.id) + ".observe", sg::Params{}.set("peer", peer_).set("x", x).set("y", y).set("zoom", zoom)});
    Writer w;
    w.u8(8).raw(c.id).u8(2);
    put_f32(w, x);
    put_f32(w, y);
    put_f32(w, zoom);
    board_send(id, w.take());
}
void App::lead(const std::string& id, bool leading) {
    if (!boards_.count(id)) return;
    const auto& c = conv(id);
    engine_->send(board_state(c.id), {board_state(c.id) + ".lead", sg::Params{}.set("peer", leading ? peer_ : std::string())});
    settle();
    board_send(id, Writer().u8(8).raw(c.id).u8(3).u8(leading ? 1 : 0).take());
}
void App::board_packet(const std::string& peer, const Bytes& bytes) {
    try {
        Reader r(bytes);
        if (r.u8() != 8) return;
        const auto cid = r.fixed<16>();
        const auto id = hex(Bytes(cid.begin(), cid.end()));
        const auto what = r.u8();
        if (!boards_.count(id) || !conversations_.count(id) || !conv(id).member(peer)) return;
        const auto& c = conv(id);
        if (what == 1) {
            const auto x = get_f32(r), y = get_f32(r);
            const bool down = r.u8() != 0;
            const int color = r.u8() & 15;
            r.end();
            auto& p = boards_[id]->pens[peer];
            // A pen moves on between what is heard of it: the engine's
            // Prediction, its velocity from the last two places.
            const double dt = std::max<double>(1, double(frames_ - p.last_frame)) * court_step;
            const sg::net::PredictedValues v{x, y, p.prediction ? (x - p.last_x) / dt : 0, p.prediction ? (y - p.last_y) / dt : 0};
            if (!p.prediction) {
                p.prediction = std::make_unique<sg::net::Prediction>(
                    [](const sg::net::PredictedValues& s, const sg::net::DiscreteInputs&) {
                        return sg::net::PredictedValues{s[0] + s[2] * court_step, s[1] + s[3] * court_step, s[2] * 0.9, s[3] * 0.9};
                    },
                    30, 256, std::vector<std::uint8_t>{1, 1, 1, 1}, 0.08);
                p.prediction->reset(frames_, v);
            } else if (frames_ > p.prediction->finalized_tick()) {
                p.prediction->reconcile(frames_, v, frame_time_);
            }
            p.last_x = x, p.last_y = y, p.last_frame = frames_, p.down = down, p.color = color;
        } else if (what == 2) {
            const auto x = get_f32(r), y = get_f32(r), zoom = get_f32(r);
            r.end();
            engine_->send(view_state(c.id), {view_state(c.id) + ".observe", sg::Params{}.set("peer", peer).set("x", x).set("y", y).set("zoom", zoom)});
        } else if (what == 3) {
            const bool on = r.u8() != 0;
            r.end();
            const auto& b = graph_.state(board_state(c.id));
            const auto now = b.params().get_or<std::string>("leader", "");
            // One leads at a time: a device stops only its own leading.
            if (on || now == peer) engine_->send(board_state(c.id), {board_state(c.id) + ".lead", sg::Params{}.set("peer", on ? peer : std::string())});
        }
    } catch (const std::exception&) {
    }
}

App::BoardView App::board(const std::string& id) const {
    BoardView v;
    const auto it = boards_.find(id);
    if (it == boards_.end() || !conversations_.count(id)) return v;
    const auto& c = conv(id);
    if (!graph_.contains(board_state(c.id))) return v;
    v.open = true;
    const auto& b = graph_.state(board_state(c.id));
    v.strokes = b.params().get_or<std::int64_t>("strokes", 0);
    v.leader = b.params().get_or<std::string>("leader", "");
    if (const auto* me = graph_.state(view_state(c.id)).find(sg::Key(viewer_element(peer_)))) {
        v.x = me->params.num("result_0", 0);
        v.y = me->params.num("result_1", 0);
        v.zoom = me->params.num("result_2", 1);
    }
    for (const auto& [peer, p] : it->second->pens) {
        if (!p.prediction) continue;
        const auto at = p.prediction->display(frame_time_);
        v.pens.push_back({peer, at[0], at[1], p.down, p.color});
    }
    return v;
}

// ---- releases (protocol 9) ----

void App::post_release(const std::string& id, int what, const Bytes& json) {
    auto& c = conv(id);
    if (what != 1 && what != 2) throw Refused("chat: a release is run or a fork");
    if (!member_here(id) || c.removed) return;
    post_kind(c, "release", Writer().u8(9).u8(std::uint8_t(what)).long_bytes(json, 1 << 20).take());
}

namespace {
// What a release signature is, to the engine: an Observation of the signer
// (web/release.js writes the same bytes).
sg::net::Observation release_observation(std::uint64_t version, const Key32& hash, const std::string& signer) {
    sg::net::Observation o;
    o.peer = signer;
    // SHA-256 of "p-chat.release.v1": the chain's own (web/release.js computes it).
    o.context = key_from_hex("574c43b2f14b8293deb3fa1c3a83e477fd68b4acec22c0ed31785a0f14219ca1");
    o.tick = 0;
    o.sequence = version;
    o.object = "p-chat";
    o.parameter = "release";
    o.discrete = true;
    o.conflict = "release";
    o.payload = Bytes(hash.begin(), hash.end());
    return o;
}
}  // namespace

std::string App::release_seen(const std::vector<std::string>& keys, std::uint32_t quorum, std::uint64_t version, const Key32& hash,
                              const std::string& signer, const sg::net::Signature& signature) {
    sg::net::Committee committee;
    committee.region = "p-chat-release";
    for (const auto& k : keys) committee.members.push_back({k, key_from_hex(k)});
    std::sort(committee.members.begin(), committee.members.end(), [](const auto& a, const auto& b) { return a.peer < b.peer; });
    committee.quorum = quorum;
    committee.faults = 0;
    committee.validate();
    auto& integrity = releases_[committee.id()];
    if (!integrity) integrity = std::make_unique<sg::net::Integrity>(committee);
    auto o = release_observation(version, hash, signer);
    o.signature = signature;
    switch (integrity->receive(o, o.context, 0)) {
    case sg::net::Delivery::Accepted: return "accepted";
    case sg::net::Delivery::Duplicate: return "duplicate";
    case sg::net::Delivery::Equivocation: return "equivocation";
    case sg::net::Delivery::Replay: return "replay";
    case sg::net::Delivery::Invalid: return "invalid";
    }
    return "invalid";
}
std::size_t App::release_forks() const {
    std::size_t n = 0;
    for (const auto& [id, integrity] : releases_) n += integrity->evidence().size();
    return n;
}
bool App::send_release(const std::string& peer, const Bytes& frame) { return live_ && live_->send(peer, "release", frame); }
std::vector<std::pair<std::string, Bytes>> App::take_release() { return std::exchange(release_in_, {}); }

// ---- carrying for contacts (protocol 10) ----
bool App::send_carry(const std::string& peer, const Bytes& frame) {
    if (frame.size() > carry_frame_max) throw Refused("chat: a carried frame is too large");
    return live_ && live_->connected(peer) && live_->send(peer, "carry", frame);
}
std::vector<std::pair<std::string, Bytes>> App::take_carry() { return std::exchange(carry_in_, {}); }
std::vector<std::string> App::live_peers() const {
    std::set<std::string> out;
    if (!live_) return {};
    for (const auto& [id, c] : conversations_) {
        if (c->removed) continue;
        for (const auto& m : c->members) {
            const auto p = peer_of(m.device);
            if (p != peer_ && !out.count(p) && live_->connected(p)) out.insert(p);
        }
    }
    return {out.begin(), out.end()};
}

// ---- linked devices (protocol 11, Link.hpp) ------------------------------------

App::Conversation* App::self_conv() {
    for (auto& [id, c] : conversations_)
        if (c->kind == Kind::Self && !c->removed) return c.get();
    return nullptr;
}
const App::Conversation* App::self_conv() const {
    for (const auto& [id, c] : conversations_)
        if (c->kind == Kind::Self && !c->removed) return c.get();
    return nullptr;
}
std::string App::self_conversation() const {
    const auto* s = self_conv();
    return s ? s->hexid : std::string();
}
// This person's other devices: the self conversation's other members, but a
// device that said it left the link (its handoff out may still be under way).
std::vector<Member> App::siblings() const {
    const auto* s = self_conv();
    if (!s || !s->committee.key(peer_)) return {};
    std::vector<Member> out;
    for (const auto& m : s->members) {
        const auto p = peer_of(m.device);
        if (p != peer_ && !s->unlinked.count(p)) out.push_back(m);
    }
    return out;
}
bool App::sibling(const std::string& peer) const {
    for (const auto& m : siblings())
        if (peer_of(m.device) == peer) return true;
    return false;
}
std::vector<std::string> App::linked() const {
    std::vector<std::string> out;
    for (const auto& m : siblings()) out.push_back(peer_of(m.device));
    return out;
}
void App::set_relay(const std::string& id, const std::string& url) {
    if (url.size() > 512) throw Refused("chat: a relay address is at most 512 bytes");
    relays_[id] = url;
}
bool App::left(const std::string& id) const {
    return graph_.state(conv(id).state).params().get_or<std::int64_t>("left", 0) == 1;
}
bool App::leaving(const std::string& id) const { return conv(id).leaving; }

// Every chat a linked device is not in yet, it is brought into, on this
// person's side - by the lowest of this person's devices in it, so one asks.
// What this device has is said to each linked device now and then, so the
// one that has more fills in the other.
void App::pump_link() {
    if (!started_ || !self_conv()) return;
    const auto sibs = siblings();
    if (sibs.empty()) return;
    for (const auto& m : sibs) {
        const auto p = peer_of(m.device);
        const bool live = live_with(p);
        const bool came = live && !sibling_live_.count(p);
        if (live) sibling_live_.insert(p);
        else sibling_live_.erase(p);
        const auto at = have_sent_.find(p);
        if (have_due_ || came || at == have_sent_.end() || now_ >= at->second + 300000) send_have(p);
    }
    have_due_ = false;
    for (auto& [id, cp] : conversations_) {
        auto& c = *cp;
        if (c.kind == Kind::Self || c.kind == Kind::Channel || c.removed || c.leaving || left(id) || !member_here(id)) continue;
        std::vector<Member> missing;
        bool lowest = true;
        for (const auto& m : sibs) {
            const auto p = peer_of(m.device);
            if (!c.member(p)) missing.push_back(m);
            else if (p < peer_) lowest = false;
        }
        if (missing.empty() || !lowest || c.change || c.pending) continue;
        for (auto& m : missing) m.side = c.side;
        if (c.side == Side::Owner) {
            if (!c.group()) missing.resize(1);
            try {
                begin_change(c, true, missing);
            } catch (const std::exception& e) {
                notices_.push_back({"warning", id, "", std::string("a linked device was not brought in: ") + e.what()});
            }
            continue;
        }
        // The other side's: asked to bring it in (said again in ten minutes, if nothing came of it).
        for (const auto& m : missing) {
            auto& at = c.asked[peer_of(m.device)];
            if (at && now_ < at + 600000) continue;
            at = std::max<std::uint64_t>(now_, 1);
            post_kind(c, "device_ask", encode(DeviceAsk{true, m}));
        }
    }
}

// Leaving a chat (unlinked): taken out by handoff - proposed here on the
// owner's side, asked of the owner's side on the other - while a device of
// this person stays in it.
void App::pump_leaving(Conversation& c) {
    if (!c.leaving || c.removed || !member_here(c.hexid)) return;
    const auto* me = c.member(peer_);
    if (c.side == Side::Owner) {
        if (c.change || c.pending) return;
        try {
            begin_change(c, false, {*me});
        } catch (const std::exception& e) {
            notices_.push_back({"warning", c.hexid, "", std::string("this device could not leave: ") + e.what()});
            c.leaving = false;
        }
        return;
    }
    auto& at = c.asked[peer_];
    if (at && now_ < at + 600000) return;
    at = std::max<std::uint64_t>(now_, 1);
    post_kind(c, "device_ask", encode(DeviceAsk{false, *me}));
}

// A chat, given to this person's linked devices over the self conversation.
void App::give_chat(Conversation& c) {
    auto* s = self_conv();
    if (!s || c.kind == Kind::Self) return;
    LinkedChat l;
    l.conversation = c.id;
    l.kind = c.kind;
    l.side = c.side;
    l.secret = secret_now(c);
    l.secret_generation = c.secrets.back().generation;
    l.name = name_of(c.hexid);
    l.introduced = introduced_as(c.hexid);
    if (l.introduced.size() > 64) l.introduced.clear();
    const auto relay = relays_.find(c.hexid);
    if (relay != relays_.end()) l.relay = relay->second;
    const auto o = options_of(c.hexid);
    l.no_recovery = o.no_recovery;
    l.disappear_s = o.disappear_s;
    if (c.kind == Kind::Channel) {
        // A channel is given to read: its key from now on, and whose it is.
        l.side = Side::Friend;
        l.generation = c.generation;
        l.members = c.members;
        std::optional<std::pair<std::string, SenderKey>> key;
        if (member_here(c.hexid) && c.own_key) key = {peer_, *c.own_key};
        for (const auto& [p, k] : c.their_keys)
            if (!key) key = {p, k.key};
        if (!key) return;
        l.trust = Writer().u8(2).short_bytes(encode(key->second)).raw(key_from_hex(key->first)).take();
    } else if (!c.join_ask.empty()) {
        const auto ask = decode_handoff_ask(c.join_ask);
        l.generation = ask.handoff.next.generation;
        l.members = ask.next;
        l.before = c.join_before;
        l.trust = Writer().u8(1).long_bytes(c.join_last, 1 << 22).long_bytes(encode(ask.handoff), 1 << 22).take();
    } else if (c.generation == 0) {
        l.generation = 0;
        l.members = c.members;
    } else {
        return;  // at a generation no handoff here brought in (a recovery's): nothing a linked device could check
    }
    post_kind(*s, "linked_chat", encode(l));
}

// A chat given by a linked device: taken as a further device takes its
// accept - the handoff that brought this device in checked against the old
// committee - or, from its start, as a group's member takes its invite.
void App::take_linked(Conversation& self, const sg::net::Observation& o, const Bytes& body) {
    (void)self;
    const auto l = decode_linked_chat(body);
    const auto id = hex(l.conversation);
    if (const auto found = conversations_.find(id); found != conversations_.end()) {
        if (!found->second->removed || found->second->kind == Kind::Self) return;
        // A copy this device kept when it left (or was taken out): the chat
        // itself, given again, takes its place.
        remove_contact(id);
    }
    bool me = false, giver = false;
    for (const auto& m : l.members) {
        me |= m.device == self_ && m.side == l.side;
        giver |= peer_of(m.device) == o.peer && m.side == l.side;
    }
    if (l.kind == Kind::Channel) {
        if (l.trust.empty() || l.trust[0] != 2) return;
        Reader r(l.trust);
        r.u8();
        const auto key = decode_sender_key(r.short_bytes());
        const auto speaker = r.key();
        r.end();
        bool publisher = false;
        for (const auto& m : l.members) publisher |= device_id(m.device) == speaker && m.side == Side::Owner;
        if (!publisher) return;
        auto& c = make_conversation(l.conversation, l.name.empty() ? "Channel" : l.name, Side::Friend, l.secret, l.secret_generation,
                                    l.generation, l.members, l.introduced, Kind::Channel);
        c.their_keys[hex(speaker)] = SenderChain{key, {}};
        relays_[id] = l.relay;
        index_mailboxes();
        Notice n{"linked_chat", id, o.peer, l.relay};
        n.type = l.name;
        notices_.push_back(n);
        dirty_.insert(id);
        return;
    }
    // Only a chat this device is in, from one of this person's devices in it.
    if (!me) return;
    if (!giver) {
        notices_.push_back({"warning", "", o.peer, "A chat given by a linked device that is not in it was refused."});
        return;
    }
    Resumed resumed;
    if (!l.trust.empty()) {
        if (l.trust[0] != 1) return;
        resumed = resume_from(l.trust, l.conversation, l.generation, l.before, l.members, l.kind == Kind::Group);
        if (!resumed.why.empty()) {
            notices_.push_back({"warning", "", o.peer, "A chat given by a linked device was refused: " + resumed.why});
            return;
        }
    } else if (l.generation != 0) {
        return;
    }
    auto& c = make_conversation(l.conversation, l.name.empty() ? "Chat" : l.name, l.side, l.secret, l.secret_generation, l.generation,
                                l.members, l.introduced, l.kind);
    const std::optional<Finalized> head = resumed.last;
    adopt(c, std::move(resumed));
    c.epoch_day = day_;
    if (head) {
        // The epoch the handoff extends is agreed; those before it are asked
        // for, each checked against the one after it.
        for (const auto& i : decode_history(head->statement.payload).ids) c.agreed_ids.insert(i);
        c.epochs.push_back(encode(*head));
        c.chain_expect = head->context.previous;
        c.chain_older = c.chain_expect != sg::net::Digest{};
    }
    if (l.no_recovery || l.disappear_s) {
        engine_->send(c.state, {c.state + ".options", options_args(!l.no_recovery, l.disappear_s)});
        settle();
    }
    const auto* s = self_conv();
    const auto* mine = s ? s->member(peer_) : nullptr;
    if (mine && mine->mail) {
        engine_->send(c.state, {c.state + ".delivery", delivery_args(int(DeliveryMode::Mailbox))});
        settle();
    }
    if (c.kind == Kind::Group) ensure_sender_key(c, true);
    relays_[id] = l.relay;
    Notice n{"linked_chat", id, o.peer, l.relay};
    n.type = l.name;
    notices_.push_back(n);
    dirty_.insert(id);
    // What was said in it, asked of the one that gave it.
    send_have(o.peer, {id});
}

// A member asks the owner's side to change its own devices: a device linked
// to it, added on its side; or itself, taken out. Taken in turn by the owner's
// side's proposer (pump), by handoff - which the old quorum endorses as ever.
void App::take_device_ask(Conversation& c, const Member& from, const Bytes& body) {
    const auto a = decode_device_ask(body);
    if (c.side != Side::Owner || c.kind == Kind::Channel || c.removed || !member_here(c.hexid)) return;
    auto m = a.member;
    if (a.add) {
        if (c.member(peer_of(m.device))) return;
        m.side = from.side;
    } else {
        // Only itself: a member leaves; it does not take out another.
        if (!(m.device == from.device)) return;
        m = from;
        // A side of two is not left empty: that is the chat ending, not a device leaving it.
        bool other = false;
        for (const auto& x : c.members) other |= x.side == from.side && !(x.device == from.device);
        if (!other) return;
    }
    for (const auto& had : c.asks)
        if (had.add == a.add && had.member.device == m.device) return;
    if (c.asks.size() >= 64) return;
    c.asks.push_back({a.add, m});
    notices_.push_back({a.add ? "device_asked" : "device_leaving", c.hexid, peer_of(from.device), peer_of(m.device)});
}

// What a linked device says of the link: it left it (forgetting or keeping
// what it had), or asks, agrees to or refuses a split of the chats.
void App::take_unlink(Conversation& self, const Member& from, const Bytes& body) {
    const auto u = decode_unlink(body);
    const auto p = peer_of(from.device);
    const auto ids = [](const std::vector<ConversationId>& list) {
        std::vector<std::string> out;
        for (const auto& id : list) out.push_back(hex(id));
        return out;
    };
    switch (u.what) {
    case UnlinkWhat::Forget:
    case UnlinkWhat::Keep: {
        self.unlinked.insert(p);
        self.split.reset();
        dirty_.insert(self.hexid);
        notices_.push_back({"unlinked_peer", self.hexid, p, u.what == UnlinkWhat::Forget ? "forget" : "keep"});
        // The link was the two of them: it is over. More stay linked: it goes
        // out of their self conversation by handoff.
        if (siblings().empty()) end_link("unlinked");
        else if (self.side == Side::Owner && proposer_of(self.members) == peer_ && !self.change) {
            const auto* m = self.member(p);
            if (m) self.asks.push_back({false, *m});
        }
        return;
    }
    case UnlinkWhat::SplitAsk: {
        if (self.members.size() != 2) return;
        self.split = Conversation::Split{false, p, ids(u.gives), ids(u.keeps)};
        dirty_.insert(self.hexid);
        notices_.push_back({"split_asked", self.hexid, p, ""});
        return;
    }
    case UnlinkWhat::SplitAgree: {
        if (!self.split || !self.split->mine || self.split->with != p) return;
        if (ids(u.keeps) != self.split->gives || ids(u.gives) != self.split->keeps) return;
        const auto gives = self.split->gives;
        leave_all(UnlinkWhat::SplitAgree, &gives);
        end_link("split");
        return;
    }
    case UnlinkWhat::SplitRefuse:
        if (self.split && self.split->with == p) {
            self.split.reset();
            dirty_.insert(self.hexid);
            notices_.push_back({"split_refused", self.hexid, p, ""});
        }
        return;
    }
}

void App::unlink(UnlinkWhat what) {
    auto* s = self_conv();
    if (!s) throw Refused("chat: this device is not linked");
    if (what != UnlinkWhat::Forget && what != UnlinkWhat::Keep) throw Refused("chat: unlink forgets or keeps; a split is asked");
    post_kind(*s, "unlink", encode(Unlink{what, {}, {}}));
    leave_all(what);
    end_link(what == UnlinkWhat::Forget ? "forget" : "keep");
}
void App::ask_split(const std::vector<std::string>& mine, const std::vector<std::string>& theirs) {
    auto* s = self_conv();
    if (!s) throw Refused("chat: this device is not linked");
    if (s->members.size() != 2) throw Refused("chat: a split is between two linked devices");
    if (s->split) throw Refused("chat: a split is asked already");
    std::vector<ConversationId> keeps, gives;
    std::set<std::string> seen;
    for (const auto* list : {&mine, &theirs})
        for (const auto& id : *list) {
            const auto& c = conv(id);
            if (c.kind == Kind::Self || !seen.insert(id).second) throw Refused("chat: each chat goes one way");
            (list == &mine ? keeps : gives).push_back(c.id);
        }
    const auto sibs = siblings();
    if (sibs.size() != 1) throw Refused("chat: a split is between two linked devices");
    s->split = Conversation::Split{true, peer_of(sibs[0].device), mine, theirs};
    dirty_.insert(s->hexid);
    post_kind(*s, "unlink", encode(Unlink{UnlinkWhat::SplitAsk, keeps, gives}));
}
void App::agree_split() {
    auto* s = self_conv();
    if (!s || !s->split || s->split->mine) throw Refused("chat: no split asked of this device");
    Unlink u{UnlinkWhat::SplitAgree, {}, {}};
    for (const auto& id : s->split->keeps) u.keeps.push_back(conversation_of(id));
    for (const auto& id : s->split->gives) u.gives.push_back(conversation_of(id));
    post_kind(*s, "unlink", encode(u));
    const auto gives = s->split->gives;
    leave_all(UnlinkWhat::SplitAgree, &gives);
    end_link("split");
}
void App::refuse_split() {
    auto* s = self_conv();
    if (!s || !s->split) return;
    s->split.reset();
    dirty_.insert(s->hexid);
    post_kind(*s, "unlink", encode(Unlink{UnlinkWhat::SplitRefuse, {}, {}}));
}
App::SplitView App::split() const {
    SplitView v;
    const auto* s = self_conv();
    if (!s || !s->split) return v;
    v.state = s->split->mine ? "asked" : "asking";
    v.with = s->split->with;
    v.mine = s->split->keeps;
    v.theirs = s->split->gives;
    return v;
}

// Leaving the chats this device shares with its linked devices (all, or
// those a split gives the other): by handoff, they stay. Keep: what was said
// stays here to read; the world says so (`left`).
void App::leave_all(UnlinkWhat what, const std::vector<std::string>* only) {
    const auto sibs = siblings();
    for (auto& [id, cp] : conversations_) {
        auto& c = *cp;
        if (c.kind == Kind::Self || c.removed) continue;
        if (only && std::find(only->begin(), only->end(), id) == only->end()) continue;
        if (what == UnlinkWhat::Keep) {
            engine_->send(c.state, {c.state + ".leave", {}});
            settle();
        }
        bool shared = false;
        for (const auto& m : sibs) shared |= c.member(peer_of(m.device)) != nullptr;
        if (c.kind == Kind::Channel || !member_here(id) || !shared) {
            // Nothing to leave by handoff (a channel read here; a chat no
            // linked device is in): it ends here.
            c.removed = true;
            notices_.push_back({"left", id, "", ""});
        } else {
            c.leaving = true;
        }
        dirty_.insert(id);
    }
    index_mailboxes();
}
void App::end_link(const std::string& why) {
    auto* s = self_conv();
    if (!s) return;
    s->split.reset();
    s->removed = true;
    engine_->send(s->state, {s->state + ".leave", {}});
    settle();
    dirty_.insert(s->hexid);
    sibling_live_.clear();
    notices_.push_back({"unlinked", s->hexid, "", why});
}

// What this device has of its chats, said to a linked device: the one that
// has more gives it what it lacks.
void App::send_have(const std::string& peer, const std::vector<std::string>& only) {
    auto* s = self_conv();
    if (!s) return;
    have_sent_[peer] = std::max<std::uint64_t>(now_, 1);
    LinkHave h;
    h.all = only.empty();
    std::size_t size = 0;
    const auto flush = [&] {
        send_control(*s, Control::LinkHave, encode(h), peer);
        h.chats.clear();
        size = 0;
    };
    for (const auto& [id, c] : conversations_) {
        if (c->kind == Kind::Self || c->removed || c->leaving) continue;
        if (!only.empty() && std::find(only.begin(), only.end(), id) == only.end()) continue;
        LinkHave::Chat ch;
        ch.conversation = c->id;
        ch.generation = c->generation;
        ch.next_tick = c->agreement ? c->agreement->next_tick() : 0;
        ch.older = c->chain_older;
        for (auto& [sender, runs] : runs_of(c->log))
            if (ch.held.size() < 256) ch.held.emplace(sender, std::move(runs));
        std::size_t n = 16 + 17 + 2;
        for (const auto& [sender, runs] : ch.held) n += 34 + 16 * runs.size();
        if (size + n > 150000 || h.chats.size() == 1024) flush();
        h.chats.push_back(std::move(ch));
        size += n;
    }
    // Said even when it has nothing: a device with no chats lacks them all.
    flush();
}

// A linked device said what it has: what it lacks is given - a chat it is
// not in yet (given again, at most every ten minutes), the epochs that let it
// check what it is given, and, asked of the host (which keeps the keys), the
// messages it misses.
void App::take_have(Conversation& self, const Member& from, const Bytes& body) {
    (void)self;
    const auto p = peer_of(from.device);
    if (!sibling(p)) return;
    // The same said again (a control frame is said again a while) is answered once in five minutes.
    const auto digest = blake2b256(Bytes{}, body);
    auto& heard = have_heard_[p];
    if (heard.first == digest && now_ < heard.second + 300000) return;
    heard = {digest, std::max<std::uint64_t>(now_, 1)};
    const auto h = decode_link_have(body);
    std::map<std::string, const LinkHave::Chat*> listed;
    for (const auto& ch : h.chats) listed[hex(ch.conversation)] = &ch;
    for (auto& [id, cp] : conversations_) {
        auto& c = *cp;
        if (c.kind == Kind::Self || c.removed || c.leaving) continue;
        const auto at = listed.find(id);
        if (at == listed.end()) {
            if (!h.all || (c.kind != Kind::Channel && !c.member(p))) continue;
            auto& given = given_[id + p];
            if (given && now_ < given + 600000) continue;
            given = std::max<std::uint64_t>(now_, 1);
            give_chat(c);
            continue;
        }
        const auto& ch = *at->second;
        if (c.kind == Kind::Channel) continue;
        // The epochs: older than where it began (newest first), when it
        // still lacks them; and those after where it stands, with the
        // handoff to this generation when it is one behind.
        std::vector<Bytes> older, newer;
        for (const auto& e : c.epochs) {
            try {
                const auto f = decode_finalized(e);
                if (f.context.tick < ch.next_tick) {
                    if (ch.older) older.push_back(e);
                } else {
                    newer.push_back(e);
                }
            } catch (const std::exception&) {
            }
        }
        std::reverse(older.begin(), older.end());
        std::optional<HandoffAsk> handoff;
        if (ch.generation + 1 == c.generation && !c.join_ask.empty()) handoff = decode_handoff_ask(c.join_ask);
        const auto send = [&](std::vector<Bytes> list, bool with_handoff) {
            LinkEpochs le;
            le.conversation = c.id;
            std::size_t size = 0;
            for (auto& e : list) {
                if (size + e.size() > 180000 && !le.epochs.empty()) {
                    send_control(self, Control::LinkEpochs, encode(le), p);
                    le.epochs.clear();
                    size = 0;
                }
                size += e.size();
                le.epochs.push_back(std::move(e));
            }
            if (with_handoff) le.handoff = handoff;
            if (!le.epochs.empty() || le.handoff) send_control(self, Control::LinkEpochs, encode(le), p);
        };
        if (!older.empty()) send(older, false);
        if (!newer.empty() || handoff) send(newer, handoff.has_value());
        // The messages it lacks, by sender and sequence.
        std::string wants;
        std::set<std::pair<std::string, std::uint64_t>> seen;
        for (const auto& o : c.log) {
            if (o.parameter != "text" && o.parameter != "file" && o.parameter != "stroke") continue;
            if (holds(ch.held, key_from_hex(o.peer), o.sequence) || !seen.insert({o.peer, o.sequence}).second) continue;
            if (!wants.empty()) wants += ',';
            wants += o.peer + ":" + std::to_string(o.sequence);
        }
        if (!wants.empty()) notices_.push_back({"link_wants", id, p, wants});
    }
}

// Epochs a linked device gave: each taken only as it checks - one going back
// from the epoch this device began from, or one after where it stands (the
// engine's Agreement takes it, with its quorum's attestations); and the
// handoff to the next generation, verified against the old committee.
void App::take_epochs(Conversation& self, const Member& from, const Bytes& body) {
    (void)self;
    if (!sibling(peer_of(from.device))) return;
    const auto e = decode_link_epochs(body);
    const auto found = conversations_.find(hex(e.conversation));
    if (found == conversations_.end() || found->second->removed || found->second->kind == Kind::Channel) return;
    auto& c = *found->second;
    std::vector<Finalized> fs;
    for (const auto& b : e.epochs) try { fs.push_back(decode_finalized(b)); } catch (const std::exception&) {}
    const auto take = [&] {
        for (bool moved = true; moved;) {
            moved = false;
            for (const auto& f : fs) {
                if (c.chain_older && epoch_before(f, c.chain_expect)) {
                    for (const auto& i : decode_history(f.statement.payload).ids) c.agreed_ids.insert(i);
                    c.epochs.insert(c.epochs.begin(), encode(f));
                    c.chain_expect = f.context.previous;
                    c.chain_older = c.chain_expect != sg::net::Digest{} && c.chain_expect != c.chain_root;
                    moved = true;
                } else if (catch_up(c, f)) {
                    moved = true;
                }
            }
        }
    };
    take();
    if (e.handoff && c.last && !(c.change && c.change->endorsed && c.change->mine)) {
        const auto& h = e.handoff->handoff;
        if (h.next.generation == c.generation + 1 && sg::net::verify_handoff(problem_of(*c.last), c.committee, c.verify(), h) &&
            h.next.id() == committee_of(c.id, c.generation + 1, e.handoff->next, c.group()).id()) {
            apply_handoff(c, h, e.handoff->next);
            take();
        }
    }
    dirty_.insert(c.hexid);
}
bool App::catch_up(Conversation& c, const Finalized& f) {
    if (!c.agreement || f.context.tick != c.agreement->next_tick() || f.context.previous != c.agreement->previous() ||
        f.context.committee != c.committee.id())
        return false;
    try {
        if (!c.agreement->accept(problem_of(f), c.verify(), f.finalization)) return false;
    } catch (const std::exception&) {
        return false;
    }
    c.last = f;
    c.epochs.push_back(encode(f));
    c.cutoffs = checkpoint_cutoffs(f.checkpoint);
    c.epoch_day = day_;
    c.run.reset();
    c.early.clear();
    for (const auto& i : decode_history(f.statement.payload).ids) c.agreed_ids.insert(i);
    Notice n{"history", c.hexid, "", ""};
    n.sequence = f.context.tick;
    notices_.push_back(n);
    return true;
}

// Messages a linked device gave: each taken only as it checks. One said
// under the generation this device is in is a message like any other - its
// sender's signature, Integrity, the window. An older one, only if the
// chat's agreed epochs name it (as a recovered device's history).
void App::take_link_history(Conversation& self, const Member& from, const Bytes& body) {
    (void)self;
    if (!sibling(peer_of(from.device))) return;
    const auto h = decode_link_history(body);
    const auto found = conversations_.find(hex(h.conversation));
    if (found == conversations_.end() || found->second->removed || found->second->kind == Kind::Channel) return;
    auto& c = *found->second;
    std::set<sg::net::Digest> logged;
    for (const auto& o : c.log) logged.insert(o.id());
    for (const auto& item : h.items) {
        try {
            const auto& o = item.message;
            if (logged.count(o.id())) continue;
            if (o.tick == c.generation) {
                check_message(o, c.id, c.generation);
                const auto content = open_content(item.key, o);
                deliver(c, o, content, o.peer, item.key);
                continue;
            }
            if (!c.agreed_ids.count(o.id())) continue;
            check_message(o, c.id, o.tick);
            const auto content = open_content(item.key, o);
            c.log.push_back(o);
            logged.insert(o.id());
            Notice n{"history_item", c.hexid, o.peer, ""};
            n.sequence = o.sequence;
            n.time = content.time_ms;
            n.type = o.parameter;
            n.data = observation_bytes(o);
            n.body = content.body;
            n.key = Bytes(item.key.begin(), item.key.end());
            notices_.push_back(n);
        } catch (const std::exception&) {
        }
    }
    dirty_.insert(c.hexid);
}

void App::give_history(const std::string& id, const std::string& peer, const std::vector<HistoryItem>& items) {
    auto* s = self_conv();
    const auto& c = conv(id);
    if (!s || !sibling(peer)) throw Refused("chat: history goes to a linked device");
    constexpr std::size_t most = 200000;
    LinkHistory part{c.id, {}};
    std::size_t size = 0;
    for (const auto& i : items) {
        if (i.message.object != c.hexid) continue;
        const auto n = observation_bytes(i.message).size() + 40;
        if (n > most) continue;
        if (size + n > most || part.items.size() == 4096) {
            send_control(*s, Control::LinkHistory, encode(part), peer);
            part.items.clear();
            size = 0;
        }
        part.items.push_back(i);
        size += n;
    }
    if (!part.items.empty()) send_control(*s, Control::LinkHistory, encode(part), peer);
}

}  // namespace chat
