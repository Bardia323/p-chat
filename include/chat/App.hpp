// One device's messenger: the world (the book and its conversations) and,
// beside it, the external machinery that pairs, seals, opens, accepts,
// acknowledges, keeps history and changes who is in a conversation.
//
// The world is changed only through its ports and edits (world/*.sg); what
// it says (a conversation's `outgoing`) is heard by a listener that only
// records it. Everything else here is outside the world: it holds no clock
// (the host says what day and time it is), no private key (the host signs
// and does every X25519 with its own keys, in a browser non-extractable
// WebCrypto keys), and no socket (the host carries what it is given).
//
// So the host's loop is: hand in what arrived, fill what is asked (starts of
// ratchets, signatures), save what changed, carry what is to go out, show
// what happened - and `pump` the world. tests/test_app.cpp is that loop with
// test keys; web/session.js is it in a browser.
#pragma once
#include "chat/Group.hpp"
#include "chat/Recovery.hpp"
#include "chat/Push.hpp"
#include "chat/Swarm.hpp"
#include "chat/Game.hpp"
#include "chat/Message.hpp"
#include "chat/Trust.hpp"
#include "chat/World.hpp"
#include "sg/net/IceSession.hpp"
#include "sg/core/Engine.hpp"
#include <deque>
#include <functional>
#include <memory>
#include <array>
#include <set>

namespace chat {

// The largest frame carried for a contact (protocol 10): one envelope of the
// largest bucket, with its mailbox and handle, and room to spare.
constexpr std::size_t carry_frame_max = 300 * 1024;

// What the host is asked to do, and what it is told.
struct StartAsk {  // begin a ratchet: X25519(own static, agree); if `second`, also a fresh key
    std::string conversation, peer;
    Key32 agree{};
    bool second = false;
};
struct SignAsk {  // sign `statement` with this device's Ed25519 key, answer with `signed_`
    std::uint64_t id = 0;
    Bytes statement;
};
struct Outgoing {
    // "envelope": seal `plain` to `agree` for `purpose`, make the envelope
    //   (version, mailbox), send it live to `peer` if it can, else to the mailbox.
    // "pair": seal `plain` to `agree` ("request"), post it under `token`.
    // "signal": send `box` to `label` in `room`.
    // "pair_done": tell the relay the token is used.
    // "post": put `box` (a channel's post, envelope 18) at the relay.
    std::string kind, conversation, peer, purpose;
    Key32 agree{}, mailbox{}, room{}, label{};
    Version version = Version::Ratchet;
    Bytes plain, box;
    Token token{};
    std::uint64_t sequence = 0;  // a message's, for acknowledgement; 0 otherwise
    bool live = false;
    // May it wait in the recipient's mailbox? Only if that device said so.
    // Otherwise it waits, sealed, on this device until a live link is up.
    bool mailbox_ok = false;
    // A message a person said (text, a file): worth waking the recipient for
    // when it cannot go live (protocol 6).
    bool ping = false;
};
struct Notice {
    // message, sent, acked, equivocation, removed, revoked, rekeyed, paired,
    // invite_failed, history, history_differs, refused, device_added, warning
    std::string kind, conversation, peer, text;
    std::uint64_t sequence = 0, time = 0;
    Bytes data;   // a message's observation (engine encoding), or evidence
    Bytes body;   // a message's body
    Bytes key;    // its content key - kept only where the chat allows recovery
    std::string type;
};
// An opened envelope's outcome. need_turn: hand in a Turn made with the
// private key of `own` (a ratchet public key, or the device's own agree key)
// and `dh`, and open again.
struct Opened {
    std::string status;  // accepted, duplicate, equivocation, refused, need_turn, control, unknown
    std::string conversation, why;
    Key32 own{}, dh{};
};
// Pairing as the new device: what it holds between asking and the answer.
struct Asking {
    Invite invite;
    PairRequest request;
    Key32 key{};
    std::string call;  // what this device will call the one who invited it
};

class App {
public:
    explicit App(Device self, std::string name);
    ~App();
    App(const App&) = delete;
    App& operator=(const App&) = delete;

    const Device& self() const { return self_; }
    const std::string& peer() const { return peer_; }
    void rename(const std::string& name);

    // ---- keeping: the host saves records encrypted, and loads them back ----
    // A conversation's record, and its messages one by one (their kept
    // observation; for this device's own, also the body and time it said,
    // which it may have to say again), before start().
    void load(const Bytes& record);
    void replay(const std::string& conversation, const Bytes& observation, const Bytes& body = {}, std::uint64_t time_ms = 0);
    void start();
    std::vector<std::string> conversations() const;
    Bytes save(const std::string& conversation) const;
    std::vector<std::string> take_dirty();
    // The engine's state of a conversation, for the UI to draw (const).
    const sg::State& state(const std::string& conversation) const;
    const sg::Engine& engine() const { return *engine_; }
    std::string name_of(const std::string& conversation) const;
    std::vector<Member> members_of(const std::string& conversation) const;
    bool removed(const std::string& conversation) const;
    std::uint64_t generation_of(const std::string& conversation) const;

    // ---- time, from outside: wall time drives only external machinery ----
    void pump(std::uint64_t now_ms);
    // The light round a game's frames need (live link, court, packets), each animation frame.
    void tick_live(std::uint64_t now_ms);

    // ---- what the host is asked, and answers ----
    std::vector<StartAsk> take_starts();
    void started(const std::string& conversation, const std::string& peer, const Key32& static_shared,
                 const Key32& fresh = {}, const Key32& fresh_shared = {});
    std::vector<SignAsk> take_signs();
    void signed_(std::uint64_t id, const sg::net::Signature& signature);
    std::vector<Outgoing> take_outgoing();
    std::vector<Notice> take_notices();

    // ---- the UI fires and sends ----
    void post(const std::string& conversation, const std::string& text, std::uint64_t time_ms);
    void read(const std::string& conversation);
    // What this device calls a contact: its own to change, at any time.
    void rename_contact(const std::string& conversation, const std::string& name);
    // How this device takes a conversation's messages: live only, or also
    // by mailbox. Told to the other devices in a signed message.
    void set_delivery(const std::string& conversation, DeliveryMode mode);
    DeliveryMode delivery(const std::string& conversation) const;
    bool takes_mail(const std::string& conversation, const std::string& peer) const;
    std::string introduced_as(const std::string& conversation) const;
    void open_conversation(const std::string& conversation);
    void close_conversation(const std::string& conversation);
    void remove_contact(const std::string& conversation);
    void revoke(const std::string& conversation, const Key32& device);
    // Several devices at once (a group's member and all their devices).
    void remove_devices(const std::string& conversation, const std::vector<Key32>& devices);

    // ---- groups and channels (protocol 4) ----
    // A group of contacts (their direct conversations' ids), or a channel
    // (no contacts: readers come by invite). The id is the new conversation's.
    std::string create_group(const std::string& name, const std::vector<std::string>& contacts, Kind kind = Kind::Group);
    // A contact (all its devices) into a group this device's side runs.
    void add_to_group(const std::string& group, const std::string& contact);
    Kind kind_of(const std::string& conversation) const;
    std::string create_channel_for_test(const std::string& name) { return create_group(name, {}, Kind::Channel); }
    // Whether this device is in the conversation's committee (a channel's
    // reader is not: it reads, and cannot post).
    bool member_here(const std::string& conversation) const;
    // A channel's post (envelope version 18), fetched from its mailbox.
    Opened open_post(const Bytes& envelope);

    // ---- pairing: the owner ----
    struct Inviting {
        Invite invite;
        std::string code, conversation;  // conversation: for a further device
        // A recovery invite's: the lost device, and what history the new one is given.
        Key32 lost{};
        Scope scope = Scope::None;
        std::uint64_t since_ms = 0;
    };
    Inviting invite(InviteKind kind, const std::string& relay, const std::string& conversation = {});
    // A posted request, opened by the host (the shared secret of its box):
    // "ok", "failed" (the code was wrong: a possible interception) or "refused".
    std::string take_request(const Inviting& inv, const Bytes& box, const Key32& shared);

    // ---- recovery and a chat's lifetime (protocol 5) ----
    // An invite for a device to take the place of one that was lost.
    Inviting recovery_invite(const std::string& relay, const std::string& conversation, const Key32& lost, Scope scope,
                             std::uint64_t since_ms = 0);
    // A member's yes, after checking with the person in person or by voice.
    void approve_recovery(const std::string& conversation);
    // The old device's no (it still exists: it is not lost).
    void refuse_recovery(const std::string& conversation);
    // History for a recovered device, from the asker's kept messages.
    void share_history(const std::string& conversation, const std::string& peer, const std::vector<HistoryItem>& items);
    void set_options(const std::string& conversation, const Options& o);
    Options options_of(const std::string& conversation) const;
    // How long a recovery waits for the old device to say no: a day. Shorter only in tests.
    void set_recovery_wait(std::uint64_t ms) { recovery_wait_ = ms; }
    // Notifications: where and how to wake this device, said in a signed
    // `push` message to the conversation's members (protocol 6).
    void share_push(const std::string& conversation, const Bytes& push_info);
    // Disappearing messages: what this device said and keeps to say again,
    // forgotten once its time is over (the host forgets its own copies).
    void forget_said(const std::string& conversation, std::uint64_t sequence);
    // What a pending recovery is, for the UI: lost and new device, ready time; empty if none.
    std::string recovery_state(const std::string& conversation) const;

    // ---- pairing: the new device ----
    // `name` is this device's own (what it tells the other side it is called);
    // `call` is what it will call the one who invited it - its choice alone.
    Asking ask(const Invite& invite, const std::string& code, const std::string& name, const std::string& call,
               bool mail = false);
    // The reply, opened by the host: "ok" (and the conversation is made) or why not.
    std::string take_accept(const Asking& asking, const Bytes& envelope, const Key32& shared);

    // ---- what arrives ----
    // The ephemeral key of an envelope's box: the host makes the shared secret.
    static Key32 ephemeral_of(const Bytes& envelope);
    Opened open(const Bytes& envelope, const Key32& shared, const std::optional<Turn>& turn = std::nullopt);
    // A signal from the relay's room.
    void signal_in(const Key32& room, const Bytes& box);
    // The rooms to be in, as (room, label).
    // The rooms of every secret the conversation still keeps (the newest last).
    std::vector<std::pair<Key32, Key32>> rooms_of(const std::string& conversation) const;
    std::vector<std::pair<Key32, Key32>> rooms() const;
    // The mailboxes to fetch: every conversation's, for this device, from
    // fifteen days ago to tomorrow, for every secret still in use.
    std::vector<Key32> mailboxes() const;
    // The same, for one conversation (each may live on its own relay).
    std::vector<Key32> mailboxes_of(const std::string& conversation) const;
    std::pair<Key32, Key32> room_of(const std::string& conversation) const;
    // This device's mailbox in a conversation on a day (its current secret).
    Key32 mailbox_on(const std::string& conversation, std::uint32_t day) const;

    // ---- the live path: the engine's WebRtcTransport, or a test's own ----
    struct Live {
        virtual ~Live() = default;
        virtual void connect(const std::string& peer) = 0;
        virtual bool connected(const std::string& peer) = 0;
        // Two channels on the Reliable lane: "envelope" and "blob" (chunks).
        virtual bool send(const std::string& peer, const std::string& channel, const Bytes& bytes) = 0;
        virtual bool receive(std::string& peer, std::string& channel, Bytes& bytes) = 0;
        virtual std::vector<sg::net::IceSignal> signals() = 0;
        virtual void signal(const std::string& peer, const sg::net::IceSignal& s) = 0;
        virtual void poll() = 0;
        // A link that says it is up but delivers nothing is made again.
        virtual void reconnect(const std::string&) {}
        // A call's chunks go on the Latest lane: late is lost, not waited for.
        virtual bool send_latest(const std::string& peer, const std::string& channel, const std::string& slot, const Bytes& bytes) {
            (void)slot;
            return send(peer, channel, bytes);
        }
    };
    void set_live(Live* live);
    // An envelope sealed by the host, sent live if the peer is connected.
    bool send_live(const std::string& peer, const Bytes& envelope);
    bool live_with(const std::string& peer) const;
    void reconnect_live(const std::string& peer);
    // Where a conversation's trust stands, in words: for looking, never for deciding.
    std::string describe(const std::string& conversation) const;
    // Envelopes that came live, for the host to open.
    std::vector<Bytes> take_live();
    // Blob frames: sent to a peer on the live link, and those that came.
    bool send_blob(const std::string& peer, const Bytes& frame);
    std::vector<std::pair<std::string, Bytes>> take_blobs();
    // A file said in a conversation: its reference, as a signed message.
    void post_file(const std::string& conversation, const Bytes& file_ref, std::uint64_t time_ms);
    // Where piece i of a blob waits at the relay, for this conversation.
    Key32 piece_mailbox_of(const std::string& conversation, const Key32& blob, std::uint32_t piece) const;

    // ---- calls (protocol 7, Call.hpp) ----
    // A call in a conversation: a secret made here, sent to its members in a
    // signed `call` message; who is in it said in `call_join` messages; its
    // chunks on the live link's Latest lane, each played only once a root
    // its streamer signed names it. The key turns when someone leaves.
    std::string start_call(const std::string& conversation, CallMode mode = CallMode::Mesh);
    // Joining: what this device can give (a swarm's viewers: a desktop
    // seeds, a phone on Wi-Fi forwards, on mobile data it only takes).
    void join_call(const std::string& call, Capacity capacity = Capacity::Forward);
    void leave_call(const std::string& call);
    struct CallView {
        std::string id, conversation, starter;
        CallMode mode = CallMode::Mesh;
        bool joined = false;
        std::uint64_t generation = 0;
        std::vector<std::string> in;  // devices in it, this one too when joined
        std::vector<std::string> forwarders;  // a swarm's or a tree's, by stripe
        std::uint64_t sent = 0, played = 0, refused = 0, roots = 0;
    };
    std::vector<CallView> calls() const;
    // What the browser's encoder made: sealed, sent to everyone in the call,
    // named in the next root (about every 100 ms).
    void send_media(const std::string& call, Layer layer, bool key_frame, std::uint64_t captured_us, const Bytes& media);
    struct Media {
        std::string call, streamer;
        std::uint64_t sequence = 0, captured_us = 0;
        Layer layer = Layer::Full;
        bool key_frame = false;
        Bytes data;
    };
    // What may be played, believed and opened, in each stream's order.
    std::vector<Media> take_media();
    // Speakers through a tree send a full and a small picture (simulcast):
    // whose full one this device wants. The others' come small.
    void pick_full(const std::string& call, const std::string& speaker);

    // ---- live state (protocol 8, Game.hpp) ----
    // Tape tennis in a two-sided conversation: the one who asks plays left.
    // The court is a state of each device's world, embedded in the
    // conversation; the controls agreed by Distributed over the live link.
    std::string start_game(const std::string& conversation);
    void join_game(const std::string& game);
    void leave_game(const std::string& game);
    void game_input(const std::string& game, int move);  // -1 down, 0 still, 1 up
    struct GameView {
        std::string id, conversation, opponent;
        int player = 0;
        bool playing = false;
        std::int64_t epoch = 0, left_score = 0, right_score = 0, hits = 0;
        // Where things are, as the prediction shows them (ahead of what is agreed).
        double ball_x = 0, ball_y = 0, left_y = 0, right_y = 0;
        std::uint64_t lead = 0;
        std::uint64_t sent = 0, received = 0;  // packets, for looking
    };
    std::vector<GameView> games() const;

    // The whiteboard: a conversation's, laid out by its edit; strokes are
    // signed `stroke` messages; pens move live, smoothed by Prediction; one
    // device may lead where everyone looks (Reconcile over the board's view).
    void open_board(const std::string& conversation);
    void close_board(const std::string& conversation);
    void post_stroke(const std::string& conversation, const Bytes& stroke, std::uint64_t time_ms);
    void pen(const std::string& conversation, double x, double y, bool down, int color);
    void look(const std::string& conversation, double x, double y, double zoom);
    void lead(const std::string& conversation, bool leading);
    struct Pen {
        std::string peer;
        double x = 0, y = 0;
        bool down = false;
        int color = 0;
    };
    struct BoardView {
        bool open = false;
        std::int64_t strokes = 0;
        std::string leader;
        double x = 0, y = 0, zoom = 1;  // where this device is brought to look, when one leads
        std::vector<Pen> pens;
    };
    BoardView board(const std::string& conversation) const;

    // ---- releases (protocol 9, web/release.js) ----
    // A release chain said to a conversation (`release` message: u8 9 | u8
    // what (1 this device runs it, 2 a fork seen) | long(the chain, as JSON));
    // checked by the page, never by the world.
    void post_release(const std::string& conversation, int what, const Bytes& json);
    // A release signature seen: kept in the engine's Integrity over its
    // committee (the keys, hex, and how many must sign). Two different
    // records signed for one version by one member: "equivocation", kept.
    std::string release_seen(const std::vector<std::string>& committee, std::uint32_t quorum, std::uint64_t version,
                             const Key32& record_hash, const std::string& signer, const sg::net::Signature& signature);
    std::size_t release_forks() const;
    // A release's files between peers, on the live link (channel `release`).
    bool send_release(const std::string& peer, const Bytes& frame);
    std::vector<std::pair<std::string, Bytes>> take_release();

    // ---- carrying for contacts (protocol 10, web/carry.js) ----
    // A relay's work done by the phones themselves, on the live links they
    // already have: rooms said, sealed signals passed on, sealed envelopes
    // held for a device that is away. The App only carries the frames; what
    // they mean is the host's, as a relay's frames are.
    bool send_carry(const std::string& peer, const Bytes& frame);
    std::vector<std::pair<std::string, Bytes>> take_carry();
    // The devices a live link is up with now.
    std::vector<std::string> live_peers() const;

private:
    struct Conversation;
    Device self_;
    std::string peer_, name_;
    Key32 id_{};
    std::uint64_t now_ = 0;
    std::uint32_t day_ = 0;
    sg::StateGraph graph_;
    std::unique_ptr<sg::Engine> engine_;
    bool started_ = false;
    std::map<std::string, std::unique_ptr<Conversation>> conversations_;
    std::set<std::string> dirty_;
    std::vector<StartAsk> starts_;
    std::map<std::uint64_t, std::pair<Bytes, std::function<void(const sg::net::Signature&)>>> signs_;
    std::uint64_t next_sign_ = 1;
    std::vector<Outgoing> outgoing_;
    std::vector<Notice> notices_;
    std::deque<sg::Params> said_;
    std::map<std::string, std::tuple<std::string, std::string, Bytes, std::uint64_t>> posts_;  // token -> conv, kind, body, time
    std::uint64_t next_token_ = 1;
    Live* live_ = nullptr;
    std::set<std::string> connected_;
    std::vector<Bytes> live_in_;
    std::vector<std::pair<std::string, Bytes>> blobs_in_;
    struct Call;
    std::map<std::string, std::unique_ptr<Call>> calls_;
    std::vector<Media> media_;
    void call_message(Conversation& c, const sg::net::Observation& o, Type type, const Bytes& body, std::uint64_t said_ms);
    void call_key_frame(Conversation& c, const Member& from, const Bytes& body);
    void pump_calls();
    void call_chunk(const std::string& peer, const Bytes& chunk);
    void call_root(const std::string& peer, const Bytes& root);
    void turn_call_key(Call& k);
    void open_call(Call& k);
    void seal_call_roster(Call& k);
    void take_call_roster(Call& k, const Roster& r, const sg::net::Finalization& fin);
    void call_roster_frame(Conversation& c, const Member& from, const Bytes& body);
    void send_chunk(Call& k, Layer layer, bool key_frame, std::uint64_t captured_us, const Bytes& media);
    Playback* playback_of(Call& k, const std::string& streamer, const Key32& streamer_id, Layer layer);
    bool wants_layer(const Call& k, const std::string& listener, const std::string& speaker, Layer layer) const;
    void call_pick(const std::string& peer, const Bytes& bytes);
    struct Game;
    std::map<std::string, std::unique_ptr<Game>> games_;
    std::uint64_t last_frame_ = 0;
    double frame_time_ = 0;
    void game_message(Conversation& c, const sg::net::Observation& o, const Bytes& body);
    void open_game(Game& g);
    void game_packet(const std::string& peer, const Bytes& bytes);
    void pump_games();
    struct Board;
    std::map<std::string, std::unique_ptr<Board>> boards_;
    std::uint64_t frames_ = 0;
    void board_packet(const std::string& peer, const Bytes& bytes);
    void board_send(const std::string& conversation, const Bytes& body);
    std::map<sg::net::Digest, std::unique_ptr<sg::net::Integrity>> releases_;  // by committee
    std::vector<std::pair<std::string, Bytes>> release_in_;
    std::vector<std::pair<std::string, Bytes>> carry_in_;
    void receive_live();
    struct EarlySignal {
        Key32 room{};
        Bytes box;
        std::uint64_t at = 0;
    };
    std::deque<EarlySignal> early_signals_;
    // The newest session this device has signalled each peer, per lane; and
    // when a link was last made again because the peer was found behind it.
    std::map<std::string, std::array<std::uint64_t, 2>> said_session_;
    std::map<std::string, std::uint64_t> behind_at_;
    bool signal_into(const Key32& room, const Bytes& box);
    void call_map(const std::string& peer, const Bytes& bytes);
    void call_want(const std::string& peer, const Bytes& bytes);

    Conversation& conv(const std::string& id);
    const Conversation& conv(const std::string& id) const;
    void sign(Bytes statement, std::function<void(const sg::net::Signature&)> then);
    void settle();
    void make_world(Conversation& c, const std::string& world_text);
    void listen(Conversation& c);
    void set_members(Conversation& c, std::uint64_t generation, std::vector<Member> members);
    void ask_starts(Conversation& c);
    void post_kind(Conversation& c, const std::string& kind, const Bytes& body);
    void outgoing_said(const sg::Params& said);
    void send_message(Conversation& c, sg::net::Observation o, const Key32& content_key, const std::string& only = {});
    void seal_to(Conversation& c, const Member& m, const sg::net::Observation& o, const Key32& content_key);
    void flush_held(Conversation& c, const std::string& peer);
    void accept_message(Conversation& c, const sg::net::Observation& o, const Content& content, const Key32& key);
    void control(Conversation& c, const Member& from, const ControlFrame& f);
    void send_control(Conversation& c, Control kind, const Bytes& body, const std::string& only = {},
                      const std::vector<Member>* to = nullptr);
    void maybe_propose(Conversation& c, bool nudge);
    void consider(Conversation& c);
    void attest(Conversation& c);
    void try_finalize(Conversation& c);
    void finished(Conversation& c, const sg::net::Finalization& f);
    void continue_change(Conversation& c);
    void endorse(Conversation& c);
    void apply_handoff(Conversation& c, const sg::net::Handoff& h, const std::vector<Member>& next);
    void persist_agreement(Conversation& c, const Bytes& journal);
    std::uint64_t since_epoch(const Conversation& c) const;
    Key32 secret_now(const Conversation& c) const;
    void connect_members(Conversation& c);
    void handle_signals();
    Conversation& make_conversation(const ConversationId& id, const std::string& name, Side side, const Key32& secret,
                                    std::uint64_t secret_generation, std::uint64_t generation,
                                    const std::vector<Member>& members, const std::string& introduced = {},
                                    Kind kind = Kind::Direct);
    void begin_change(Conversation& c, bool add, const std::vector<Member>& ms, const std::string& via = {});
    Opened deliver(Conversation& c, const sg::net::Observation& o, const Content& content, const std::string& p, const Key32& key);
    void continue_recovery(Conversation& c);
    void apply_recovery(Conversation& c, const RecoveryDone& d);
    std::uint64_t recovery_wait_ = 86400000ull;
    void rekey_after_recovery(Conversation& c);
    Opened sender_frame(Conversation& c, const Bytes& plain);
    void ensure_sender_key(Conversation& c, bool fresh);
    void seal_group(Conversation& c, const Member& m, const sg::net::Observation& o, const SenderKey& at, const Key32& mk);
    void join_group(Conversation& direct, const sg::net::Observation& from, const GroupInvite& g);
    struct Resumed {
        std::unique_ptr<sg::net::Agreement> agreement;
        std::optional<Finalized> last;
        std::string why;
    };
    static Resumed resume_from(const Bytes& trust, const ConversationId& c, std::uint64_t generation,
                               const std::vector<Member>& before, const std::vector<Member>& after, bool majority);
    void adopt(Conversation& c, Resumed r);
    void send_group_invite(Conversation& group, const std::string& via, const Bytes& trust, const std::vector<Member>& before);
    void send_accept(Conversation& c, const Invite& inv, const PairRequest& req, const Key32& pair_key, const Bytes& trust);
    void index_mailboxes();
    std::map<Key32, std::string> mailbox_index_;
    std::uint32_t indexed_day_ = 0;
};

}  // namespace chat
