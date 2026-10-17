# Progress

All phases done; every gate passes: native 13 tests, the Wasm suite 10
(Node and headless Chrome for Testing 155). Built against the engine at
`c0e4919` (pinned), on this server.

## Phase 0: skeleton - done

- `CMakeLists.txt` fetches the engine (`FETCHCONTENT_SOURCE_DIR_STATEGINE=../stategine`
  to build against the checkout), `EXCLUDE_FROM_ALL` so only what sgchat's
  targets need is built. CUDA and native ICE off.
- One module, `chat` (headers `include/chat`, bodies `src/chat`), held to the
  engine's shape (`sgchat_modules`). `sgchat_link` links `stategine::net`.

## Phase 1: protocol spec and vectors - done

- `docs/protocol.md`; `src/chat/` codecs over Monocypher; `tests/vectors/v4.json`
  from `sgchat_make_vectors`, checked by `sgchat_vectors`.
- Primitives checked against independent implementations: Ed25519, X25519,
  BLAKE2b (Python `cryptography`), XChaCha20-Poly1305 (libsodium), Argon2id (argon2-cffi).

## Phase 2: relay - done

`relay/relay.py` (websockets 16, asyncio API): rooms by label, RAM mailbox
with TTL and per-mailbox/global quotas, first-post-wins tokens, cancellable
reusable tokens, optional VAPID push (empty), binary frames only, nothing
logged. `sgchat_relay` covers token burn, reusable cancel, TTL expiry,
quotas, room isolation, malformed frames, backpressure, VAPID signature,
and that the relay prints nothing.

## Phase 3: world - done

`world/chat.sg` (the book), `world/conversation.sg` and `world/device.sg`
(templates the `contact.add` and `device.add` edits compile with the
engine's own compiler). Natives in `src/chat/World.cpp`. `sgchat_world`:
strict validation, `sg::verify` ok with **no unchecked equations**,
sequence windows (new, duplicate, filled, too old, lost), edits only at the
next generation, revoke removes the device, rename, open/close transitions.
`sgchat_trust`: Integrity accepts, drops duplicates, refuses replays and
forgeries, keeps equivocation evidence.

**Extra state, justified**: `contacts`, the book. Conversations are made at
run time and must be reachable (opened from the book and closed back to
it), and a structural change is an edit some state asks for; a
conversation cannot ask for its own making. It holds nothing else.

## Phase 3b: forward secrecy - done

Double Ratchet per device pair (`chat/Ratchet.hpp`), pure in its state, with
every X25519 handed in (WebCrypto in the browser). Skipped keys: 1000 per
turn, 2000 kept. No first message needed (the lower device id sends from
its static key; the other turns at once). Version 2 envelopes; version 1
refused once a ratchet exists. `sgchat_ratchet`.

## Phase 4: browser shell - done

Wasm target `sgchat_web` (embind, `-sDYNAMIC_EXECUTION=0` for the CSP)
linking `chat` and `stategine::web`. `web/crypto.js` (non-extractable
Ed25519/X25519/AES-GCM in IndexedDB, `storage.persist()`), `web/session.js`
(the App's host loop, relay client, live-or-mailbox, the engine's
`WebRtcTransport`), `web/store.js` (content sealed at rest, replayed into
the App at start). Gate: `sgchat_vectors_node` and `sgchat_browser_vectors`
- Wasm makes every vector and WebCrypto every signature and shared secret,
byte for byte as natively.

**Argon2id** (32 MiB, 2 passes, 1 lane): 42 ms native, 49 ms Wasm under
Node, 44 ms in headless Chrome on this server. A mid phone is about ten
times slower than this CPU in Wasm: roughly half a second. **Not measured
on a real phone.**

## Phase 5: UI - done

One screen at a time: code entry (the fragment is read once and removed
from the address bar), contact list, chat, invite (QR, six words, kind:
contact / further device / reusable), devices per contact with remove,
fingerprint emoji, About (bundle fingerprint, storage status, the limits),
and errors: invite used, device not recognized, device removed, browser too
old, equivocation, history differs, message missing, invite failed. The look
follows the concept art (a VHS sleeve: cream card, display type, yellow /
amber / orange / red bands, a script on the red, boxed labels); the chat is
mostly conversation, with a round send key that presses in. Fonts and the
QR generator are self-hosted, so the app loads nothing from elsewhere.
Since: plain screen names (Chats, Invite, Devices, Settings); a p-chat
wordmark whose dash is the five stripes; motion (screen entries by depth
with a tracking pass and a title split, band wipes, message pops, the send
key firing, unread bumps, fingerprint drops, staggered words; all off under
prefers-reduced-motion); pressed keys sink, with a chromatic-split shadow
in the dark; Twemoji fingerprint pictures shipped; dir=auto and byte-bounded
names for every language. No Japanese text.
A dark look follows the phone (or Settings → Look): the second concept
(black sleeve, white type and outlined labels, stripes yellow → orange →
red → magenta → violet); fonts and layout the same.

## Phase 6: signed delivery - done

`web/sw.js` serves only a bundle whose `manifest.json` (file SHA-256s) is
signed by the release key written into it, takes a new one only when newer,
signed and whole. `tools/release.py` (keygen, build, verify, fingerprint).
The e2e test changes a file on the host without signing it: the page keeps
the signed one. README and About say plainly that `sw.js` itself can be
replaced by the host.

## Phase 7: end to end - done

`sgchat_e2e` (`tests/e2e.py`): four browser profiles and the local relay,
through the UI. Pair (QR link + words); texts both ways **over WebRTC**
(counted); a tab closed and the mailbox delivering on reopening; a wrong
code and the owner's "Invite failed: possible interception"; a further
device after the friend's first device endorsed the handoff; revoking it
("This device was removed. Ask … for a new key."); keys cleared and a fully
cleared profile ("Device not recognized"); the signed service worker; and a
scan of the relay process's memory finding no message, name or code (with a
positive control proving the scan works).

## Amendments (from the user, during the work)

1. PairAccept carries a MAC under the pair key over the transcript; refused otherwise.
2. The authenticated bytes bind sender, recipient, conversation and sequence
   (the observation, signed, names sender, conversation, sequence; the
   per-recipient wrap names the recipient).
3. Gaps: a 63-sequence window per sender in the world; "message missing"
   once a gap outlives the mailbox's TTL.
4. Deniability - **superseded** by the engine-reuse amendment (messages are signed).
5. Double Ratchet (Phase 3b).
6. The service worker's limit stated in README, About and `sw.js`.
7. History encrypted at rest (AES-GCM, non-extractable key).
8. **Engine reuse**: messages are `sg::net::Observation`s accepted only by
   `Integrity`; a conversation's devices are a `Committee` (q = n for two, n - 1
   beyond); devices join and leave by `Handoff` with old-quorum endorsements
   (`verify_handoff` / `Agreement::resume`), then `graph.edit`; history
   epochs are `Agreement` epochs over the ordered message ids, chained;
   vote locks persisted before a vote is sent.
9. **Names**: each person introduces themselves; the one invited chooses what
   to call the inviter; anyone can rename a contact locally.
10. **p-chat** is the client's name.

## Decisions

- **One observation per message, a content key wrapped per recipient**:
  every member must hold the same observation for history epochs.
- **Message context and tick = the committee generation**, so messages never
  wait for an epoch. A handoff retires the old generation (Replay); what was
  said after the last epoch is said again under the new one, same sequence.
- **History epochs have one input**, the history the owner's side states;
  members attest only when their logs agree. One proposer means no
  conflicting locks; the owner's side, because a revoked device must never
  be the one relied on (found by `sgchat_app`).
- **Placeholder numerical system** (one free coordinate, 0 iterations) so
  `Agreement`/`Verify` finalize a discrete-only epoch: ENGINE_REQUESTS.md #2.
- **Signing outside the engine**: statements made in Wasm, signed in
  WebCrypto; the vote lock written as the engine's own journal and read back
  by `Agreement::restore`; byte-equal to the engine (`sgchat_trust`):
  ENGINE_REQUESTS.md #1.
- **A new secret after a revocation** (rekey), used once its announcement is sealed.
- **Signaling** sealed under the conversation secret, addressed by labels:
  the relay learns no device ids. Signals are retried until the other end is
  in the room.
- **The session is a C++ App** (platform-neutral, natively tested end to end
  in `sgchat_app`), and the browser only its host: WebCrypto, IndexedDB,
  sockets, DOM. No private key reaches Wasm.

## Untested on real phones

- Stock iPhone Safari and stock Android Chrome: pairing in under a minute,
  QR scanning by the camera app, WebRTC across mobile networks (needs a
  STUN/TURN server in `config.json`), Argon2id time, Safari's storage
  eviction message, Android push. All checks so far ran on this server in
  headless Chrome 155 and Node 22.
- A deployed relay behind real TLS, and the service worker on a real HTTPS host.

## Not done (v0 limits, also in README)

- A second **owner** device per conversation (protocol carries it; the app does not link one).
- `history_sync` is reserved: a new device does not receive earlier history.
- Groups, files, native apps, iOS push (non-goals).

# v1

The v1 brief (user, 2026-10-15) continues v0 phase by phase; each section
below has its gate.

## v1 §1 Hardening, §2 Engine trust - done in v0

Already in v0 by the user's amendments: the accept's transcript MAC, the
bindings, gap windows and "message missing", history at rest under
AES-GCM; messages as signed `Observation`s inside the ciphertext, accepted
only by `Integrity`, the `Committee`, handoffs, `Agreement` history with
the placeholder system. On "signed bytes bind the recipient device": the
signature binds sender, conversation and sequence and the generation
(context); the generation fixes the committee, so the set of recipient
devices is bound by the signature; the one recipient of each copy is bound
by the wrap's AEAD under the pairwise ratchet. Gates: `sgchat_vectors`,
`sgchat_trust`, `sgchat_app`, `sgchat_vectors_node`, `sgchat_browser_vectors`.

## v1 §3 Forward secrecy - done

The Double Ratchet was v0 Phase 3b. Added: used keys wiped (a chain key
when stepped past, a message key once used, skipped keys when used or
evicted, a ratchet's keys when it goes; the content key after
wrapping/unwrapping; the browser zeroes its copies of shared secrets).
Gate: `sgchat_ratchet`, `sgchat_app`.

## v1 §4 Delivery modes - done (protocol 2)

Per contact and device: live only (default; the relay keeps nothing,
envelopes wait sealed in the sender's encrypted outbox) or takes mail (an
opt-in, carried at pairing and changed by a signed `delivery` message).
Per-item status (◷ ✉ ✓ ✓✓). Found by the e2e test and fixed on the way:
duplicates are acknowledged again; control frames are kept and replayed
(idempotent) for 5 minutes; a live link that says it is up but delivers
nothing is made again (`WebRtcTransport::reconnect`). Gate: `sgchat_app`
(live only leaves the relay empty and delivers on linking), `sgchat_e2e`
(mailbox opt-in, status "in the mailbox"). Protocol 2; vectors `v4.json`.

## v1 §5 Media - done (protocol 3)

`chat/Media.hpp`: per-file key, chunks of 64 KiB under XChaCha20-Poly1305
bound to blob, index and count; streaming BLAKE2b; the `file` reference
(blob, key, hash, MIME, size, kind, name, duration, size in pixels,
thumbnail, pack); relay pieces (envelope 17, three chunks, padded) at ids
only members can derive; `want`/`chunk` frames on the live `blob` channel.
`web/media.js`: pictures redrawn on a canvas (EXIF gone), thumbnails, video
poster frames, voice notes (MediaRecorder), the built-in content-addressed
sticker pack, chunk serving and pulling, piece upload and fetch, hash check
before showing. IndexedDB schema 2 (stores `blobs`, `chunks`) by migration.
Gate: `sgchat_media` (chunks, truncation, reorder, keys, references,
pieces, frames, the 100 MB cap), `sgchat_relay` (version 17), `sgchat_e2e`
(a photo arrives without its EXIF; a file byte for byte; a sticker; a voice
note from the fake microphone; a file from the relay pieces with its sender
gone).

Found and fixed on the way: the Wasm targets compiled without exception
catching (a refusal aborted the whole module) - now `-fexceptions`, as the
engine's own; the CSP forbade `blob:` media (voice and video would not
play) and style attributes (now set through CSSOM); a dropped signal could
leave two WebRTC sessions that never meet again (signals are now kept until
delivered, 10 minutes at most); a live send into a peer that has just gone
is backed by a mailbox copy when the recipient takes mail.
Not done: a video's own metadata is not stripped (no cheap re-encode in the
browser); custom sticker packs are not yet sent as blobs.

## v1 §6 Groups and channels - done (protocol 4)

`chat/Group.hpp` and the App: a group is a conversation of many (committee
of all members' devices, majority quorum, the same Agreement and handoffs,
several devices changed at once); members come by a signed `group_invite`
in a contact's two-sided conversation (trust through the contact), resuming
the group's Agreement when it is under way. Sender keys per device, handed
over the pairwise ratchets, rotated at every membership change; frames that
come before their key are kept and opened later. A channel: the publisher's
committee alone; readers pair with a channel invite (kind 4), get the
channel's key, verify every post through `Integrity`, cannot post; posts
are put once at the channel's mailbox (envelope 18). Gates: `sgchat_app`
(a group of four with an addition by majority and a removal - the removed
member cannot read what follows; a channel with two readers, a reader's post
refused), `sgchat_e2e` (a group both ways in browsers with who-said-it; a
channel's reader through the UI), vectors `v4.json` (file, chunk, piece,
sender key, sender frame, channel post, group invite), relay (version 18).
Found and fixed: items waiting for a live link now go to the mailbox once
the recipient says it takes mail.

## v1 §7 Recovery and a chat's lifetime - done (protocol 5)

`chat/Recovery.hpp` and the App. A lost device is an absent member; any
other member asks for a new device in its place with a recovery invite
(kind 5). The recovery record names the lost device, the new one, the
history scope (all, since a time, none), the time it may take effect (24 h
later), the last finalized epoch and the messages since (its tail). The
members that remain endorse it with engine `Attestation`s - two thirds of
them, in a conversation of two the other side alone - after comparing the
new device's four pictures in person or by voice, and only if the tail is
what their own log holds. The lost device is told and can refuse until
the wait is over; a refusal cancels it everywhere. Done: the committee
changes by a `device.replace` edit (world port and native), the old
generation is sealed (a fresh `Agreement` chained to the decision), the
lost device's ratchets and keys go, sender keys and the conversation
secret turn. The new device checks the endorsements and the chain of
finalized epochs from the first to the one the decision names, and takes
given history only for agreed ids that open under their own keys. Options,
said by a member in a signed `options` message: no recovery (no content key
is kept; a recovery invite is refused) and disappearing messages (a
message said while it is on is deleted on every device when its time is
over - words, key, outbox copies, relay copies - its sealed observation
kept for the history; messages said before stay). UI: a "This chat"
section (Recovery / No recovery, Messages disappear after), "Replace:
lost" on each other device with the history to give, the approver's banner
with the new device's pictures, the lost device's "Refuse: it is not lost",
the asker's approvals and ready time, and the new device's own pictures
while it waits.

Gates: `sgchat_trust` (quorum arithmetic; the lost device's own
endorsement, a duplicate, a forged signature, a changed decision and a
refusal do not count; an epoch chain reordered or with its first or last
epoch dropped is refused), `sgchat_app` (1:1 where the friend's side
replaces the owner's phone: refused by the old phone, then done after the
wait, history 55 of 55 given and a forged key giving nothing, the old
phone removed and reading nothing, no recovery set and kept by both; a
group where the second remaining member must approve - not without it,
however long the wait - and keys turn), `sgchat_media` (live pieces),
`sgchat_e2e` (disappearing messages gone from both phones and the outbox,
older ones kept; a replacement refused by the old phone, then done in
browsers, the new phone given the history and talking), vectors `v4.json`
(recovery, decision, endorsement, history items, options).

Found and fixed on the way: a device that misses a rekey while it is away
and takes no mail could never be reached again (it is now in the room of
every kept secret, and a peer not yet heard from is signalled in all of
them); a message larger than a data channel takes (a long text, a history
share) never went live (now in pieces); timer rounds that threw were
unnamed page errors (now each is caught, named and logged, and the e2e
test counts it as an error); two pairing polls at once could take a reply
twice. Seen once and not again in the three runs since: a WebCrypto `OperationError`
on the new phone, before the rounds were named; if it comes back, the e2e
test now fails with where it came from. Engine request 3: a handoff under
a recovery quorum.

## v1 §8 Notifications - done (protocol 6)

`chat/Push.hpp`, `web/push.js`, `web/sw.js`. Each device makes its own VAPID
key pair (P-256, WebCrypto), subscribes with its browser's push service and
says where and how to wake it in a signed `push` message to every
conversation it is in (and to new ones as they come). A member whose
message of a person (text, file) cannot go live - it waits on the sender,
sits in the mailbox, or went over a link that was gone (no
acknowledgement in 30 s) - makes the push itself: the payload sealed to the
subscription (RFC 8291, one aes128gcm record) under an ES256 VAPID token
(RFC 8292), at most one in 20 s per conversation and device. It goes
straight to the push service when the browser lets the page (the CSP allows
the four browsers' push services), else through the relay (op 49), which
carries it as it is - only to those push services, at most 60 a minute per
connection - and holds no key. The payload is `p6.<ping>.<conversation>`;
the ping id is the same for every copy of one message, and the woken
service worker shows a ping once and shows only the symbol its own user
chose for that chat (Devices, "Notification symbol"; kept sealed at rest,
read by the worker under the same at-rest key), a dot if none. Settings
has "Allow notifications", or on an iPhone in a tab the Add to Home Screen
steps; a web app manifest and Home Screen icons drawn from the wordmark
(`tools/icons.py`). The v0 relay-held VAPID key is no longer used by the
app.

Gates: `sgchat_vectors` (push subscription and payload; plain http, a
compressed point, a trailing byte refused), `sgchat_relay` (forwarding:
unknown hosts, look-alike hosts, a non-VAPID authorization, a smuggled
header, an oversize body refused; the loopback only when asked; carried as
it is; the rate), `sgchat_e2e` (the friend's phone says how to wake it, its
tab closes, the owner's message makes a push that a test push service
opens as a browser would - RFC 8291 and the VAPID token checked, the
payload a ping and the conversation, no words - delivered to the friend's
service worker through Chrome's push path; the same ping not shown twice;
the chosen symbol shown, a dot for a chat without one).

The browser tests now run on a full Chrome (Chrome for Testing 155): the
headless shell grants no notification permission at all. Headless Chrome
does not always keep a notification shown from a push event dispatched by
the DevTools protocol (a bare worker behaves the same), so what is shown is
also checked through the worker's own handler. Not tested on real phones:
FCM, Mozilla's and Apple's push services themselves, whether they accept a
push posted from a page (CORS), and the iPhone Home Screen path.

## v1 §9 Bots - done

`bot/`: a WebSocket client of its own (RFC 6455, ws and wss through
OpenSSL with the server's name and certificate checked), the relay's
frames, and `bot::Host` - a native device: Ed25519 and X25519 seeds in its
folder (0600, the folder 0700), conversations, messages and ratchet keys
kept beside them and loaded again on start, the App's asks answered, mail
only (what it says to a device that takes no mail waits on it until that
device does). `sgchat_echo` pairs with a link and the six words and says
back what it is told (in a group only after `/echo `). Nothing new on the
wire: a bot is a device. Gates: `sgchat_bot` (the relay and the bot as
their own processes, two people as native hosts: pairing, an answer, a
restart from its folder - the same device, the same chat - a group with a
person, answers only when asked, revoked by the other two without its say
and reading nothing after), `sgchat_e2e` (p-chat pairs with the echo bot
through the UI and hears it answer). Found and fixed on the way: ratchet key
files were named from two different temporaries (a key could not be found
again after a turn).

## v1 §10 Calls and streams - done (protocol 7)

`chat/Call.hpp` (chunks, roots, playback), `chat/Swarm.hpp` (rosters,
buffer maps, the pull scheduler, stripes planned by the engine's
Placement), `world/call.sg` (a call is a state: its stripes participants
of Placement, its roster and plan changed by edits), the App's calls,
`web/call.js` (WebCodecs: VP8 video at 640x360 and 15 fps, Opus audio; the
camera through MediaStreamTrackProcessor where there is one, else drawn
into frames), the call screen (the other side's tiles with the stepped
stripe shadow, you in a corner, Mute, Camera off, a round red hang key,
live counts and latency) and a "Go live" key in groups.

Every chunk is sealed under the call key, bound to call, streamer,
generation and number, sent on the Latest lane; every chunk is played only
once a root its streamer signed (100 ms in talk, 1 s in a stream) names it.
Talk: everyone to everyone up to five devices (the key turns for those
still in when one leaves), speakers through a tree of relays beyond. A
stream: a swarm - the starter's roster epochs, each finalized and sealed by
a Handoff to the next generation with a new key bound to the roster;
viewers say what they give (desktop seeds, phone on Wi-Fi forwards, phone
on mobile data only takes); every device plans the same forwarders from
the same finalized roster with Placement; pieces of 250 ms to the stripe's
forwarder, given on to six at once, the rest pulled by buffer maps.

Gates:
- `sgchat_call` - the gate as the brief asks, over simulated links (10-60
  ms each way, fixed per pair): a swarm of nine viewers with a streamer
  (two seeding, four forwarding, three only taking), Placement's plan in
  the world by its edit; half way one leaves and one joins (a new sealed
  roster, a new key, a new plan; the one that left cannot open what
  follows); a viewer holding the key injects a chunk of its own under the
  right number and it is refused everywhere - its real copy still played;
  every viewer plays every piece it was there for. Latency logged: the
  swarm p50 555 ms, p95 905 ms; everyone to everyone p50 73 ms, p95 135 ms;
  three speakers through a tree to eight, p50 101 ms, p95 164 ms (both
  under 300 ms). Also a root signed by another, a root naming again, a
  changed chunk, another stream's chunk - refused.
- `sgchat_app` - a call over the live link (rung, answered, twelve frames
  in order, a changed copy refused, hung up for both); a call of three in
  a group (one leaves: a new generation, the one still in has the key,
  what follows is under it); a swarm in the group (a seed, a phone that only
  takes and forwards nothing, everyone with the same plan and key, the
  stream in order).
- `sgchat_e2e` - in Chrome, with its fake camera and microphone: a call
  through the UI (frames decoded both ways after their roots named them,
  nothing refused; caller p50 73-91 ms, p95 116-144 ms; the friend p50
  67-99 ms, p95 114-340 ms across runs) and going live in a group (the
  viewer takes the sealed roster and its key, no camera opened on it; p50
  2.1 s, p95 3.2 s from capture to played - pieces of 250 ms and a root a
  second).

Simulcast: through a tree, speakers send a full and a small picture, each
layer its own stream with its own roots; a listener taps a tile to ask for
that speaker's full picture (`callpick`), and relays give the full layer
only to those who asked. Gates: `sgchat_app` (two speakers, one listener
asking for one: it has that one's full and small pictures and the other's
small only; one who asked for none, small only), `sgchat_e2e` (a call
through a tree in Chrome: small pictures before any asking, the full one
after the tile is tapped, nothing refused).

Not done, and said so: a swarm of many browsers was not run (the browser
test has one viewer; the swarm of nine is the simulation); Safari has no
MediaStreamTrackProcessor for audio, so it sends video only. Engine
request 4: messages larger than a data channel takes.

## v1 §11 Live state - done (protocol 8)

Tape tennis and a whiteboard, both states of the world, embedded in their
conversation at its `table` and `board` portals.

Tape tennis (`world/game.sg`, `chat/Game.hpp`): the court, its network and
its own time are made by the `game.start` edit. Each player's control is
its participant's pinned coordinate in the network; the engine's
Distributed reconciliation agrees both (boundary packets on the live link's
Latest lane, the last two said again every three frames); each committed
step moves the court six steps of 1/60 s by its declared arrows; the
picture is the engine's Prediction (at most twelve frames ahead). The
court's rules and its forecast are sgchat's own, following the engine's
Pong; the engine's example code is not compiled in (it reaches an
internal header). The whiteboard (`world/board.sg`, `chat/Board.hpp`):
strokes are signed messages; pens move live, smoothed by Prediction; where
each device looks is a participant of the board's view, and the engine's
Reconcile brings every view to the one that leads ("Follow me"). UI: Board
and Play in the attach tray; the court (W/S, arrows, a finger, or the
keys), the board (colors, Move, +, -, Follow me), both in the sleeve's look.

Gates:
- `sgchat_live` - two worlds with nothing between them but boundary packets
  two frames late: the very same game step for step (257 steps, 86% of
  real time), the laws hold before and after; a board of three devices,
  one leads and every view is brought to it, strokes counted, put away by
  its edit.
- `sgchat_app` - tape tennis over a lossy Latest lane (a fifth lost, a
  quarter overtaking): 71 steps in 600 frames, the same score at every step
  on both, over for both; the whiteboard: a stroke counted on both boards,
  a pen seen where it is going, following brings the other's view to the
  leader's.
- `sgchat_e2e` - in Chrome: asked, accepted and played through the UI, the
  court advancing on both phones (prediction 3 frames ahead); a stroke
  drawn with the mouse reaches the other board and is kept there as a
  signed message; Follow me with zoom brings the other view to it.

Found and fixed on the way: a screen made by an asynchronous render could be
drawn over the next one (renders now check they are still the screen
shown); the DSL takes `net` and `open` in a native's name as IO (renamed).
Seen once: in one e2e run the friend's second device got no live link
(signalling); it did not come back in the runs after, and is watched.

## v1 §12 Release chain and peer updates - done (protocol 9)

`web/release.js` (the chain's checks, shared by the page and `sw.js`, which
has it written in), `tools/release.py` (keygen, build, sign, verify), the
service worker (the release run and one waiting, evidence, forks, a bundle
given by a peer), the page (status, "Update ready", About: version, chain
head, fingerprint, sw.js mismatch, refusals; announcing the release run to
each conversation; taking a newer one from a contact's phone over the live
link; forks kept in the engine's Integrity and told to everyone).

Records are signed by a committee of the owner's devices (any two of three
in the tests); each signature an engine Observation signature, so two
records for one version are equivocation the engine keeps. The first
committee is written into `sw.js` (no cycle: the record names `sw.js`'s
hash, so `sw.js` names a committee, not a record). IndexedDB: each schema
adds the stores it lacks and keeps what is there. Each protocol reads the
content of every earlier one.

Gates:
- `sgchat_release` (Node, `web/release.js`): the first release and its
  quorum; a valid update; a bad signature (forged, or of one outside the
  committee); a broken link; a downgrade, and the same version again; a file,
  a manifest, an sw.js not the one named; versions skipped, link by link
  (and a well-signed later one not carrying a bad skipped one); a chain
  with one missing; a committee handed over (the old cannot sign after);
  a fork; and chains cut by `tools/release.py` (signed by one member, then
  another with `sign`) holding here and in `release.py verify`.
- `sgchat_release_browser` (Chrome, the service worker): an older database
  migrated; release 2 checked, waiting, "Update ready", run from the next
  open; refused, the evidence kept and release 2 run on: one signature of
  two, a broken link, a downgrade, a file changed after signing; from 2
  straight to 4; an sw.js the release does not name shown in About, and
  gone again; a fork shown and kept in the engine's Integrity, the second
  release refused and the first still waiting; a bundle given by a peer
  taken, and one with a file changed refused.
- `sgchat_vectors` (Node and browser): release.js's signature bytes are the
  engine's own; content of every earlier protocol read, of a later one not.
- `sgchat_app`: a member's two releases for one version are equivocation
  in the App's Integrity; a duplicate is a duplicate; a bad signature invalid.
- `sgchat_e2e`: the owner's phone is given release 2 (checked, waiting, run
  from the next open), tells its contact, whose phone takes release 2's
  files from it over the live link, checks them all, says "Update ready",
  and runs release 2 when reopened.

Found and fixed on the way: a `release` message was not kept in the store,
so a reopened app replayed its log with a gap and the history stopped at it
(every message is kept now, whatever it says); a device that had just
paired could be signalled before it knew the conversation, and the signal
was lost - two ends then waited on each other (signals for a room not yet
known are kept two minutes and tried again, and a live link that stays down
with something waiting is made again); a release's files were asked for one
at a time (32 now).

## v1 §13 Docs and the whole suite - done

README: what p-chat does now, the release chain, the threat model (the
first load and `sw.js` trusted as served, what the relay still sees,
recovery as a social attack, a re-shared history weakening forward
secrecy), what has not been tried on real phones, the tests, the layout.
CHANGELOG: v1, dated.

The whole suite run again and again to find what fails only sometimes.
Two did, and both were real:
- A screen drawn late over a newer one: Devices' buttons draw Devices
  again once what they do is done; if the chat had been opened meanwhile,
  Devices was drawn over it and what was being typed was lost (the e2e's
  message to the bot, about one run in three). Devices, Invite and Settings
  are now drawn only while they are the screen shown, as the chat, the
  board and About already were. The e2e presses the kept button after the
  chat is open and something typed, and checks the words stay; without the
  fix it fails as the suite did.
- A question to the service worker lost while it is being replaced (the
  site served a different `sw.js`; Chrome activates the new worker only
  when the old one is next idle): asked once more, of the worker then
  active (`release_browser`'s peer install, about one run in five).

Runs after both fixes: native 12 of 12; the Wasm suite (release, vectors in
Node and Chrome, e2e, release_browser) 5 of 5, four times in a row;
release_browser alone 8 of 8 (one of them asked the worker twice).

## After v1: first things on a phone

From trying p-chat on a phone on the local network (a test CA, the relay
with TLS, a signed release served over HTTPS):
- About showed nothing in a browser whose service worker never started (a
  certificate visited past its warning): it waited on the worker, which
  never came. It is drawn at once now and the release filled in when known;
  asking the worker gives up after 3 s when none is running, and About
  says the background check is not running. e2e opens About with service
  workers blocked.
- About is for people first (how it works, good to know, what it cannot
  hide); the fingerprint, chain head and threat notes fold under "Check
  this version".
- No relay address in sight: none on the Invite screen; one's own under
  Settings → Advanced, tried before it is kept (refused in words when it is
  not an address or does not answer). Everyday wording says "server".
  e2e: no address on Invite; a bad one and a silent one refused; one that
  answers kept and named by the next invite; emptied back to the default.
- p-chat opens on Chats (no welcome form): empty, "Invite someone", Group
  and Channel waiting for a contact; the name is asked on the Invite screen.
Wasm suite 5 of 5 after each change.
- About rewritten for reading at a glance: twelve feature tiles, a drawing
  (you - locked box - relay - locked box - friend), three steps, "No server
  in charge", "Why it's safe", each point a picture (Twemoji 15, the same
  package as the fingerprints; 15 more files in web/emoji) and short
  sentences. "Relay" in everything people read. Tape tennis is table tennis
  on screen (the code keeps game_/rally_). A chat drawn again over itself
  keeps its tray open and its draft, and carries neither into another chat
  (the e2e's whiteboard step met the tray closing under it).

## v1.1 No middleman - done (protocol 10)

The user's goal: no middleman; phone to phone, the relay optional. A page
cannot accept a connection, so two phones need something to pass their
first signals; now that can be the two phones' own codes (in person) or a
contact linked to both - not only a relay.

- `web/direct.js`: a WebRTC description carried compact (the ICE username
  and password, the DTLS fingerprint, the role, UDP candidates; the
  standard description of one data channel made again from it): 90 bytes
  for Chrome's, the inviting phone's whole code about 350 characters, the
  answer 140. `PairLink` (an RTCPeerConnection with one channel) carries the
  pairing request, the accept and the conversation's first signals.
- `web/carry.js`: the relay's work over the live links phones already have,
  on a new channel `carry` (App: `send_carry`, `take_carry`, `live_peers`):
  rooms said (again whenever they change), signals passed on, envelopes
  kept, asked for, given and dropped; bounds and rates as a relay's.
- An invite may name no relay (`decode_invite`); content version 10; the
  vectors made again (every entry whose bytes hold a content version).
- Session: relays switchable (none connected when off); signals with no
  relay to take them given to every linked phone for 2 minutes; a lost link
  made again every 30 s while a contact is linked (only the engine's newest
  session is taken, so a try made while the other was away is never
  heard); a message for a device that takes mail kept here and with up to
  three linked contacts; the joining phone keeps the relay the code names.
- UI: Invite starts with "In person"; the joining phone's own screen; a
  camera reader (the browser's BarcodeDetector, else jsQR, vendored);
  "Scan their code" on Chats; Settings → Relay and Carry for contacts; About
  says the relay is optional and what waits without one.
- Found on the way: a phone said its rooms to a contact once a minute, so a
  chat made since was not reachable through it until then (said whenever
  they change now); a link opened in an open p-chat changed only its
  address's '#' and was not taken (taken now).

Tests: `sgchat_direct` (Node: codes from Chrome's, Firefox's and Safari's
descriptions, refusals, a carrier's rules), `sgchat_meet` (Chrome: in person
with relays off and no relay connection ever opened; a lost link found
again through a contact; a message kept by a contact and given back), the
native App test (a carried frame, its bound, the linked peers). A pairing
link between Chrome and Firefox opened both ways from the codes alone
(Playwright's Firefox); WebKit would not start on this server (system
libraries missing), so Safari is untried until a real iPhone.

## v1.2 A relay always there; nothing sent that cannot arrive

From trying the public site on phones: a call that never rang and texts
that stopped (the site had no relay, so a link lost to a locked screen or a
reload could never be made again); an iPhone that lost its device on a
reload; names chosen for oneself.

- `relay/worker`: the relay on Cloudflare (Worker + one SQLite Durable
  Object, WebSockets that hibernate; BLAKE2b of its own, checked against
  Python's on 36 inputs). `tests/test_relay.py --worker` runs the relay's
  checks against it under `wrangler dev` (`sgchat_relay_worker`); a break
  put in on purpose was caught (5 checks). Deployed; the public release's
  default relay. A chat made with no relay uses the default one.
- Keys: where a browser does not give back an Ed25519/X25519 CryptoKey from
  IndexedDB (tried once with a key of no use), private keys are kept wrapped
  (AES-GCM, pkcs8) under a non-extractable key and unwrapped non-extractable.
  `sgchat_meet` makes one phone such a browser and reloads it. A phone whose
  key is gone says so, names no one, and can start again (the database
  closed, then deleted).
- Nothing sent that cannot arrive: no relay and no live link to every other
  device - the composer is shut and `send` refuses. Calls only with a relay.
- No name of one's own: invites and pairing ask none; the Paired screen
  asks what to call them (both sides); a contact with none is "New contact".
- Links: a phone heard signalling under an older session than this one's
  newest for it, while the link is down, has the link made again (at most
  each 15 s), instead of every 30 s on a timer - which restarted links that
  were half up. A link is restarted for a missing acknowledgement only
  where it can be made again (the chat's relay up, or another linked
  contact): found by recording every RTCPeerConnection in the test - a
  healthy link, the only one a phone had, closed by that rule 32 s after it
  was made. Receive queues 8192 messages / 64 MiB, the App taking up to 4096
  a pump.
- A notice is centred by its margins (its animation's transform had undone
  the centring and pushed it off the screen). The code back can be copied
  and pasted, for pairing with no relay from afar.

Runs: native 13 of 13, the Wasm suite 7 of 7; `sgchat_meet` 9 in a row
after the last change (it had failed every run before it).

## v1.7 Four at once - done (protocol 11)

Four agents in worktrees, merged on `integrate`:
- Lag: measured with `tests/lag_browser.py` (relay 80 ms away). Live p50
  488 -> 5 ms, relay only 3121 -> 168 ms, reopened 3 s -> 162 ms. The host
  pumps on the links' own events; signals batched, none dropped; relay op 4
  `watch` and pushed `0x41` (relay.py and the Worker).
- Desktop: the wide layout fills the window; `tests/desktop_browser.py`,
  `tests/desktop_shots.py`.
- A device that relays: carry frames 8 `relays` and 9 `serves`; the `#l1.`
  code to link again in person; `sgchat_meet` part 3.
- Linked devices: invite kind 6, conversation kind 3 (made by `contact.add`),
  `linked_chat`, `device_ask`, `unlink`, `link_name`, controls 13-18; "read
  only" is the conversation's `left` param set by the `CONV.leave` arrow;
  `device.add`/`device.revoke` take every device of a handoff in one
  generation step. Content version 11. Link timing is App machinery on the
  host's `now`; no clock in the world.

Runs: native 13 of 13; the Wasm suite 10 (lag, desktop and link added): 9 of 10
in the whole run, `sgchat_link_browser` timing out at Forget ("T has both
chats") and Split; alone it then passed 5 runs in a row. Open: why only
after the others.

## v1.8 Table tennis by place - done (protocol 12)

Measured first (tests/test_live.cpp, two worlds, packets 1-6 frames late):
the own paddle jumped up to 0.19 when a step was agreed (the court took a
held key from the moment of publishing, the picture from the moment it was
pressed); the court ran at 150% of real time on a fast link and 46%/31% at
4/6 frames late. Now: each player publishes, once its screen has played
past a step, where its paddle is at the step's end (`publish(y)`, a grid
of 1/1024); the other's number is read from its own packet (`remote_*`,
the `game_agreed` transport), so both courts take the same numbers; one
settle round; steps of ten frames, the court's first step 1 (the network's
step 0 is agreed before anything is published). `CourtSide` (Game.hpp) is
the host's side: hand, picture (Prediction, lead 60), when to publish.
Paddles agreed within 0.0005 of the hand at every delay; 99% of real time
up to 4 frames late (76% at 6, waiting rather than racing).

