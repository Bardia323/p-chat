# The sgchat protocol, 11

What travels between two devices running p-chat, and what the relay sees. Every layout
here is what `src/chat/` makes; `tests/vectors/v4.json` holds the bytes for
fixed keys (made by `sgchat_make_vectors`, checked natively by
`sgchat_vectors` and in a browser by `tests/test_browser.py`). Where this
page and the code disagree, the vectors decide, and one of them is a bug.

## Versions

**Protocol 11** (this page) lets a connection watch its mailboxes at the
relay (op 4) and be told at once that mail is waiting in one (pushed frame
`0x41`): a device fetches when it is told, not at its next round; a device
still talks to a protocol 10 relay, which refuses the op, and fetches each
round as before. It also lets a device relay for its contacts, with no
relay: `carry` frames 8 (`relays`) and 9 (`serves`), and a code to link
again in person (`#l1.`) for two devices already paired that lost every
link. Nothing a message carries changed (content version 10).
**Protocol 10** makes the relay optional: an invite may name
no relay (paired in person, over a link the two phones make from two codes
they show each other), and contacts carry for each other on the live links
they have (the `carry` channel: rooms, signals passed on, envelopes kept);
content version 10. **Protocol 9** added releases (the `release` type and the
`release` channel; content version 9). **Protocol 8** added live state (the `game` and `stroke`
types; the `game` and `board` channels on the live link; content version
8). **Protocol 7** added calls and streams (types `call` and
`call_join`, control kinds 11-12, chunks, roots, rosters and buffer maps on
the live link; content version 7). **Protocol 6** added notifications (the `push` type, push
payloads, the relay's push forwarding; content version 6). **Protocol 5**
added recovery and a chat's lifetime (invite
kind 5, control kinds 6-10, the `options` type, the recovery record and
its endorsements, history given to a recovered device; content version 5;
large live messages in pieces; signals into every kept room until a peer
is heard). **Protocol 4** added groups and channels (types `sender_key`
and `group_invite`, frame kind 3, envelope version 18, invite kind 4,
conversation kinds, a group's majority quorum; content version 4).
**Protocol 3** added files (the `file` type, envelope version
17 for pieces at the relay, the `blob` channel on the live link; content
version 3). **Protocol 2** added delivery modes: the `delivery` message type,
a device's mail flag in member records and in the pairing request
(request version 2), and content version 2. A protocol 2 device still reads
protocol 1: a version 1 request (no delivery byte), member records with
only a side, content version 1. Every wire change bumps this number; the
vectors are `tests/vectors/v4.json`.

## Notation

- Integers are big endian: `u8`, `u16`, `u32`, `u64`.
- `short(x)`: `u16` length, then the bytes; `long(x, max)`: `u32` length.
- `D("name")`: a domain: `u8` length, then the ASCII name. **Every hash,
  MAC, KDF and signature input starts with one**, and no two purposes share one.
- `H(key, x)`: BLAKE2b-256 of `x`, keyed with `key` when one is given.
- `H64`: BLAKE2b-512. `X(a, B)`: X25519. `AEAD(k, n, ad, p)`:
  XChaCha20-Poly1305 (Monocypher `crypto_aead_lock`, libsodium's
  `xchacha20poly1305_ietf`), written `mac(16) | cipher text`.
- Everything is refused when truncated, longer than its bound, or followed
  by trailing bytes. Unknown version bytes are refused.

All primitives come from the engine's pinned Monocypher 4.0.3 (target
`sg_net_crypto`); Ed25519 is `sg::net` (`SigningKey`, `check_signature`).
They were checked against libsodium (XChaCha20-Poly1305), argon2-cffi
(Argon2id) and Python `cryptography` (Ed25519, X25519, BLAKE2b) while
writing this page.

## Devices

A device is two public keys: Ed25519 `sign` and X25519 `agree`. In a
browser both private keys are made by WebCrypto with `extractable: false`
and kept as `CryptoKey`s in IndexedDB; they never reach Wasm.

    device_id = H(D("sg.chat.v1.device") | sign | agree)
    peer      = hex(device_id)        (64 lowercase hex characters)

The app checks at start that WebCrypto has both `Ed25519` and `X25519`; if
either is missing it says "Please update your browser" and stops. There is
no other curve.

## The code

Six words of the BIP-39 English list (`data/words.txt`, 2048 words, from
github.com/bitcoin/bips `bip-0039/english.txt`, SHA-256
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`):
the first 66 bits of 9 random bytes, 11 bits per word, most significant
first. 66 bits. Typed in any case, separated by spaces, commas, dots or
hyphens; each word may be given by its first four letters (unique in the
list). Normalized: the six full words, lower case, one space between.

## The invite

    invite = u8 1 | u8 kind | owner.sign | owner.agree | token(16) | secret(32) | short(relay)
    kind:    1 contact, 2 extra-device, 3 reusable-device
    relay:   wss://..., or ws://127.0.0.1:... / ws://localhost:... (tests), at most 512 bytes;
             empty (protocol 10): no relay - an invite given in person
    link:    https://<static host>/#v1.<base64url(invite), no padding>

The fragment never reaches a server. The app reads it, then removes it from
the address bar (`history.replaceState`). Base64url is canonical (unused
bits zero).

## Pairing

    pair_key = Argon2id(password = normalized code,
                        salt = invite.secret,
                        ad = D("sg.chat.v1.pair.code") | token,
                        m = 32768 KiB, t = 2, p = 1, 32 bytes)

The cost: on this server's CPU natively 42 ms; in Wasm under Node 22
measured as recorded in PROGRESS.md; aimed at about half a second on a mid
phone. It is a constant of v1: changing it is a new version.

**Request** (new device to owner), posted to the relay under `token`:

    request  = u8 2 | sign | agree | nonce(16) | short(name, <= 64) | u8 mail | mac(32) | sig(64)
    mac      = H(pair_key, D("sg.chat.v1.pair.request") | token | owner.sign | owner.agree
                           | sign | agree | nonce | short(name) | u8 mail)
    (version 1: no mail byte, in the request or under the MAC)
    sig      = Ed25519(new device, D("sg.chat.v1.pair.request.sig") | (the same fields) | mac)
    posted   = seal("request", owner.agree, pad(request))

The owner opens it, checks the MAC under its own pair key (constant time),
then the signature (the device holds the key it asks to have pinned). On a
MAC failure it shows "Invite failed: possible interception" and burns the
token (a reusable one is cancelled).

**Accept** (owner to new device):

    body     = u8 1 | conversation(16) | secret(32) | u64 secret_generation | short(owner name)
               | u64 generation | u8 n | n x (sign | agree | u8 flags) | long(trust, 200000)
    mac      = H(pair_key, D("sg.chat.v1.pair.accept") | token | nonce | owner.sign | owner.agree
                           | sign | agree | H(body))
    sig      = Ed25519(owner device, D("sg.chat.v1.pair.accept.sig") | (the same fields) | mac)
    accept   = body | mac | sig
    flags:   bit 0 the side (0 the owner's, 1 the friend's); bit 1 the device takes mail
    trust:   empty for a new contact; for a further device: u8 1 | Finalized | Handoff (below)

The MAC covers the transcript: both devices' keys, the token and the
request's nonce. The new device refuses any accept whose MAC or signature
fails. It is sealed to the new device and left at

    reply mailbox = H(invite.secret, D("sg.chat.v1.pair.reply") | token | new device_id)

as an envelope of version 16. Both sides then show four emoji:

    fingerprint = first 4 bytes of H(D("sg.chat.v1.fingerprint") | lower id | higher id)

each an index into `data/emoji.txt` (256 emoji with spoken names, all
Unicode 10 or older), to be compared aloud if wanted.

## Names

A device introduces itself with a name of its own choosing: the request's
`name`, the accept's `owner name` (at most 64 bytes of UTF-8 each). That is
all the identity there is beyond the keys. **What a device calls the other
side is its own choice and never leaves it**: the device that was invited
chooses, when it pairs, what to call the one who invited it (falling back
to the name that one gave); the inviter starts from the name it was given.
Either may rename a contact at any time (`<conversation>.rename`, a port
and an arrow of the world). The name each side introduced itself with is
kept beside it (`introduced`) and shown.

## Sealing and padding

    seal(purpose, R, p): e = fresh X25519 key; s = X(e, R)
       key = H(D("sg.chat.v1.seal." + purpose) | s | e.pub | R)
       box = e.pub | nonce(24, random) | AEAD(key, nonce, D("sg.chat.v1.seal.ad") | e.pub | R, p)
    purposes: request, accept, message

`p` is always padded: `u32 length | frame | zeros`, to the smallest of
**1 KiB, 16 KiB, 256 KiB**; larger is refused, and so is a padding that is
not zero or a bucket larger than needed. In the browser `e` is a WebCrypto
key and only `s` reaches Wasm; an all-zero `s` (small-order key) is refused
on both sides, as WebCrypto refuses it.

## Envelopes (what the relay sees)

    envelope = u8 version | mailbox(32) | box
    version:  1 a message sealed without a ratchet, 2 under the ratchet, 16 a pairing reply
    size:     1 + 32 + 72 + one of 1024, 16384, 262144 - nothing else

The relay refuses any other size or version. The box hides the sender, the
conversation, the type and the sequence (sealed sender).

    mailbox(device, day) = H(secret, D("sg.chat.v1.mailbox") | device_id | u32 day)
    day   = floor(unix seconds / 86400), UTC
    room  = H(secret, D("sg.chat.v1.room"))           (signaling)

`secret` is the conversation's secret of its current secret generation
(given in the accept, replaced by `rekey` after a revocation). Ids rotate
daily and are unlinkable without the secret. An id is a capability: knowing
it allows fetch and delete. A recipient fetches the days from 15 days ago to
tomorrow, for every secret generation younger than the mailbox's life.
**Mailbox TTL: 14 days.**

## A message is an engine Observation

Each chat message is an `sg::net::Observation`, in the engine's canonical
statement encoding (`sg.net.observation.v1`), signed by the sender's device
key (Ed25519):

    peer      = sender peer (hex device id)
    context   = H(D("sg.chat.v1.context") | conversation | u64 generation)
    tick      = the committee generation it was sent under
    sequence  = the sender device's count in this conversation, from 1
    object    = hex(conversation)
    parameter = type: text, ack, device_revoked, history_sync, rekey
    discrete  = true, conflict = peer + ":" + sequence (unique)
    payload   = nonce(24) | AEAD(content key, nonce,
                  D("sg.chat.v1.content") | short(object) | short(peer) | u64 sequence | short(type),
                  u8 version (2; 1 still read) | u64 time_ms | long(body, 200000))

The content key is fresh for each message. One observation goes to every
other member of the conversation's committee; each gets the content key
wrapped for it alone (below). Messages are not deniable: the sender's
signature is evidence, kept for equivocation and history.

Bodies: `text` UTF-8. `delivery`: `u8 mode` (1 live only, 2 takes mail). `ack`: `u16 n | n x (device_id | u64 sequence)`.
`device_revoked`: `device_id | u64 generation` (the committee generation
it is no longer in). `rekey`: `secret(32) | u64 secret_generation`.
`history_sync`: reserved. Unknown types are acknowledged and ignored.

**Acceptance.** A message is delivered to the world only through
`sg::net::Integrity::receive(message, context, tick)` with the receiver's
committee: `Accepted` delivers to `graph.port(conversation, "receive")`;
`Duplicate` is dropped; `Replay` (a generation retired) and `Invalid`
(unknown device, bad signature, wrong context) are refused; `Equivocation`
(the same peer and sequence, other bytes) keeps both as evidence and shows
a warning. Integrity's memory is rebuilt at start from the kept log.

A recipient also checks: the frame's sender is the observation's peer, the
observation is of this conversation and generation, the wrap opens for this
device.

## Frames

Inside a box, padded:

    message, version 2 = u8 1 | sender id | header(40) | wrapped(48) | long(M, 262144)
    message, version 1 = u8 1 | sender id | content key(32) | long(M, 262144)
    control            = u8 2 | sender id | u8 kind | long(body, 262144)
    M = sg::net::encode(Message{Inputs, from = sender peer, to = recipient peer, [observation]})

Version 1 is the sealed box alone. It is refused from any device a ratchet
exists with - and every pair of members has one from the moment they share
a committee - so it is only ever accepted by a v1-only build. It is kept so
the version byte keeps its meaning.

## The ratchet (version 2)

A Double Ratchet per pair of devices in a conversation: X25519 turns,
BLAKE2b chains, XChaCha20-Poly1305.

    seed  = H(secret, D("sg.chat.v2.ratchet.seed") | X(static, static) | lower id | higher id)
    KDF_RK(rk, s) = H64(rk, D("sg.chat.v2.ratchet.root") | s) -> (new rk, chain key)
    KDF_CK(ck)    = (H(ck, D("sg.chat.v2.ratchet.message")), H(ck, D("sg.chat.v2.ratchet.chain")))
    header        = dh(32) | u32 pn | u32 n

No first message is needed: the device with the lower id is *first*; it
sends on `KDF_RK(seed, X(statics))` from its static key. The *second*
receives on that chain and turns at once with a fresh key, so either side
can speak first. Ratchet private keys are WebCrypto `CryptoKey`s
(non-extractable) in the browser; the ratchet itself is a pure state
machine in Wasm that is handed every X25519 it needs, kept encrypted at
rest. Skipped message keys: at most **1000** per turn, **2000** kept.

A message key wraps the content key once:

    (key, nonce) = H64(mk, D("sg.chat.v2.ratchet.keys")) -> first 32, next 24
    wrapped      = AEAD(key, nonce, D("sg.chat.v2.wrap") | sender id | recipient id
                        | conversation | u64 sequence | observation id | header, content key)

so a message can be neither replayed into another chat nor sealed on to
another person: the observation names its sender, conversation and
sequence under the signature, and the wrap names its recipient.

## Delivery modes

Each device says, per conversation, how it takes messages:

- **live only** (the default): nothing for it is ever left at the relay.
  A sender keeps an envelope for it sealed in its own (encrypted) store and
  sends it the moment a live link is up.
- **takes mail**: envelopes for it may wait in its mailbox, sealed, for
  the mailbox's life (14 days).

A device's first choice is in its pairing request (and in every member
record the owner's side sends: the accept, a handoff); a change is a signed
`delivery` message to the other members. Each device's choice is a
parameter of its element in the world (`mailbox`), set only by its newest
signed message. Pairing replies use the relay (there is no live link
yet) - or, paired in person, the link the two phones made (protocol 10).

Each of a device's own messages shows what became of it, the most hopeful
across its recipients: waiting here (◷), in the mailbox (✉), sent (✓),
delivered (✓✓). A message sent live and not acknowledged within 30 s
makes the link be made again (`WebRtcTransport::reconnect`) and is sent
again; a duplicate is acknowledged again. Control frames (epochs,
handoffs) have no acknowledgement: they are idempotent, so they are kept
for 5 minutes and sent again every 10 s while a link says it is up.

## Files (protocol 3)

A file never travels in a message. Its sender picks a random 32-byte blob
id and a fresh 32-byte file key, and seals the file in chunks of 64 KiB:

    count     = ceil(size / 65536), at least 1; size at most 100 MB
    chunk i   = AEAD(file key, nonce_i, D("sg.chat.v3.chunk") | blob | u32 i | u32 count, plaintext_i)
    nonce_i   = H24(file key, D("sg.chat.v3.chunk.nonce") | blob | u32 i)

Every chunk but the last is exactly 64 KiB of plaintext: a chunk moved,
dropped, or the file cut short or made longer does not open. The whole is
then checked against the reference's hash before it is shown.

The message (type `file`, signed like any other) carries the reference:

    file = u8 3 | blob | key | hash (BLAKE2b-256 of the plaintext) | short(mime, <= 128) | u64 size
           | u8 kind (0 file, 1 image, 2 video, 3 voice, 4 sticker) | short(name, <= 256)
           | u32 duration_ms | u16 width | u16 height | short(thumbnail, <= 12 KiB) | pack(32)

**Live**: on the engine's Reliable lane, channel `blob`, one chunk a frame:

    want  = u8 1 | blob | u32 from
    chunk = u8 2 | blob | u32 index | u32 count | long(sealed chunk)

A device that has the file serves a member of the conversation that wants
it; the one that wants it asks again from its first missing chunk.

**Mailbox**: if any recipient takes mail, the sender leaves the file at the
relay before the message, in pieces of three chunks:

    piece mailbox = H(secret, D("sg.chat.v3.piece") | blob | u32 piece)
    piece key     = H(file key, D("sg.chat.v3.piece.key"))
    envelope 17   = u8 17 | piece mailbox | nonce(24) | AEAD(piece key, nonce,
                      D("sg.chat.v3.piece") | blob | u32 piece, pad(u32 first | u16 n | n x long(sealed chunk)))
    size          = 1 + 32 + 40 + one of the buckets

Pictures are redrawn on a canvas before sealing (at most 2560 px): what is
sent is pixels, without the camera's EXIF. A video's own metadata is not
rewritten (the browser cannot re-encode it cheaply): it is sent as it is.
Voice notes are MediaRecorder recordings. **Stickers** come in content-
addressed packs: a sticker is named by the BLAKE2b-256 of its picture, a
pack by the BLAKE2b-256 of its list (`web/stickers/pack.json`); a sticker
message names both and carries no key. The built-in pack is "Tape deck".

## Groups and channels (protocol 4)

A conversation has a kind: 0 two sides, 1 a group, 2 a channel (a param
of its state in the world, `kind`).

**A group** is made by one device (its owner's side) from contacts it has:
its committee is every device of every member, its quorum a majority
(`n/2 + 1`, 2q > n), so a group goes on with members away. The maker sends
each contact, in their two-sided conversation, a signed `group_invite`:

    group_invite = u8 4 | group(16) | u8 kind | secret(32) | u64 secret_generation | short(name)
                   | u64 generation | u8 n | n x (sign | agree | u8 flags) | long(trust)
                   | u8 m | m x (sign | agree | u8 flags)      (the committee before, with trust)

A device takes it only from a device that is on the group's owner's side,
and only if it names this device; with `trust` (a group already under
way) it resumes the group's Agreement from the handoff the old committee
endorsed, as a further device does. Adding a contact is one handoff of all
its devices (a group may change several devices at once, all coming or all
going); removing works the same way.

**Sender keys.** Each device of a group speaks under its own chain:

    sender_key   = u8 4 | id(32) | chain(32) | u32 iteration
    content key  = H(chain, D("sg.chat.v4.sender.message")), then chain = H(chain, D("sg.chat.v4.sender.chain"))
    frame kind 3 = u8 3 | sender id | key id | u32 iteration | long(observation as engine Message)

A device's sender key goes to every member in a `sender_key` message over
the pairwise ratchets; it is replaced by a fresh one whenever who is in the
group changes (a member taken out never gets it). A frame that comes before
its key is kept (at most 256) and opened when the key comes. A receiver
keeps up to 256 skipped keys and refuses one more than 1000 ahead. Text and
files go under sender keys; acknowledgements, delivery, revocation, rekey
and sender keys themselves go pairwise. Each copy is still sealed to its
recipient device (sealed sender).

**A channel** has a committee of its publisher's devices alone. A reader
pairs with a channel invite (kind 4, reusable until cancelled); the accept
names the publisher's committee and carries, as its trust, `u8 2 |
short(sender_key)` - the channel's key from that moment on. A reader is not
a member: it checks every post against the publisher's committee
(`Integrity`), keeps no ratchet, takes part in no epoch, and cannot post (a
post of its own would not be authentic). Posts are put once at the relay:

    channel mailbox(day) = H(secret, D("sg.chat.v4.channel.mailbox") | u32 day)
    envelope 18          = u8 18 | channel mailbox | nonce(24)
                           | AEAD(H(secret, D("sg.chat.v4.channel.post")), nonce,
                                  D("sg.chat.v4.channel.ad") | channel mailbox, pad(frame kind 3))
    size                 = 1 + 32 + 40 + one of the buckets

Readers fetch the channel's mailboxes and leave the posts for one another.

## Recovery and a chat's lifetime (protocol 5)

A lost device is a member that is absent: it cannot endorse a handoff, so
its replacement is a decision of its own. Any member other than the lost
device may ask for it, by a recovery invite (kind 5; a pairing like a
further device's, the six words and all). The new device's request comes
to the one who invited it, which writes the recovery:

    recovery = u8 5 | conversation(16) | u64 generation (the one it makes) | lost device id
               | sign | agree | u8 flags (the new device, on the lost one's side)
               | u8 scope (0 none, 1 since, 2 full) | u64 since_ms | u64 not_before_ms
               | previous (the last finalized epoch's id, or zeros) | u64 tick (the next)
               | long(tail)                    (the History since that epoch, as the asker has it)
    decision = H(D("sg.chat.v5.recovery") | recovery)
    epoch    = H(D("sg.chat.v5.recovery.epoch") | conversation | u64 generation)

Endorsements are engine `Attestation`s (`epoch`, `decision`, signer,
Ed25519 by the signer's device key, the engine's statement bytes). A
recovery holds when distinct members of the current committee other than
the lost device have endorsed it, at least `max(1, ceil(2r/3))` of the `r`
that remain - in a conversation of two, the other side alone. An approver
endorses only after comparing the new device's own four pictures
(`fingerprint(new, new)`, shown on the new device while it waits) in person
or by voice, and only if the tail is what its own log holds (as it would an
epoch: behind - not yet; differs - shown, never endorsed).

Control frames carry it (kind 1 as before; a control's body):

| Kind | Body | From |
| --- | --- | --- |
| 6 RecoveryAsk | recovery \| attestation (the asker's endorsement) | the asker, to every member, the lost device too |
| 7 RecoveryVote | attestation | an approver, to the asker |
| 8 RecoveryRefuse | attestation over `H(D("sg.chat.v5.recovery.refused") \| decision)` | the lost device itself |
| 9 RecoveryDone | recovery \| u16 n \| n x attestation \| u8 m \| m x member | the asker, when it holds and the wait is over |
| 10 HistoryShare | u8 5 \| u16 n \| n x (long(observation) \| content key) | a member, to the new device |

`not_before_ms` is the asker's clock plus the wait (24 h; tests shorten it).
Until then the lost device, if it still exists, may refuse; a refusal
cancels the recovery on every device. `RecoveryDone` is taken only if it
holds against the receiver's committee, at its generation + 1, and not
more than a minute before `not_before_ms` by the receiver's clock. Then,
on every device: the committee is the one `RecoveryDone` names (the lost
device out, the new one in), the `Agreement` starts again with
`previous = decision` at `tick` (the old generation sealed), the lost
device's ratchets and sender chain go, ratchets to the new one start,
groups turn their sender keys, and the owner's side's lowest device turns
the conversation secret (the lost device knew the old one).

The new device's accept carries, as its trust, `u8 3 | long(RecoveryDone) |
u8 kind | u16 n | n x long(finalized epoch)`: the endorsed decision, and the
conversation's finalized epochs, oldest first. It checks the endorsements
against the committee of the members that remain, that each epoch follows
the one before from zeros and that the last is the decision's `previous`;
the agreed ids are the epochs' ids and the tail's. History it is given is
taken only for an observation whose id is agreed and whose content opens
under the key given with it; anything else is dropped. Members give what
the asker chose: all, since a time, or none - each message with its own
content key, so what was forward-secret at rest is not for these messages
(see the README's threat model).

**Options** (type `options`, a member's signed message):

    options = u8 5 | u8 no_recovery | u32 disappear_s

With `no_recovery` a recovery invite is refused, and no device keeps a
content key beside its message: history dies with a lost device. With
`disappear_s`, a message said while it is set goes, on every device, that
long after it was said: its words and its key are deleted, the copies
still waiting in an outbox are dropped, and the copies left at a relay are
deleted there (the relay deletes by mailbox and `handle = H16(envelope)`,
which the sender knows). The signed, sealed observation stays: history
epochs and `Integrity` still need it, and without its key it opens for no
one. Messages said before the option was set stay.

**On the live link**, a message larger than 131072 bytes goes in pieces on
the reliable channel, in order: `u8 0xff | u32 id | u16 index | u16 count |
bytes` (at most 64 pieces); a piece out of order drops what was begun.
Nothing else on a data channel begins with `0xff`.

## Notifications (protocol 6)

A device that wants to be woken makes its own VAPID key pair (P-256) and
subscribes with its browser's push service under it. It says, in a `push`
message to each conversation it is in (signed and sealed like any other):

    push = u8 6 | short(endpoint) | p256dh(65) | auth(16) | vapid private(32) | vapid public(65)

The endpoint is https (http on the loopback, for tests), at most 1024
bytes; both points are uncompressed P-256. A member keeps the newest it
has from each device. When a message of a person (text, a file) cannot go
to a device live - it waits on the sender, or in the mailbox, or was sent
live and not acknowledged within 30 s - the sender pushes to that device,
at most once in 20 s per conversation and device:

    payload = "p6." hex(ping) "." hex(conversation)        (68 bytes of text)
    ping    = H16(D("sg.chat.v6.push.ping") | conversation | sender id | u64 sequence)

sealed to the subscription as one aes128gcm record (RFC 8291) and posted
with `Authorization: vapid t=<ES256 JWT for the endpoint's origin, 12 h>,
k=<vapid public>` (RFC 8292), `TTL: 86400`, `Urgency: high`. The page posts
it itself when the browser allows; otherwise the relay carries it (op 49,
below) as it is. A `404` or `410` drops that device's subscription. The
woken device's service worker shows a ping once (it keeps the last 256),
and shows nothing but the symbol its own user chose for that conversation
(a dot if none): the push service sees an endpoint and a sealed record of
fixed size; the relay, when it carries one, the same.

## Calls and streams (protocol 7)

A call is a conversation's. Its starter makes a call id and a secret and
says them in a signed `call` message; each member that answers says so in
`call_join` (and, leaving, says so again):

    call      = u8 7 | call(16) | u8 mode (0 everyone to everyone, 1 a swarm, 2 speakers through a tree)
                | u64 generation (0) | secret(32)
    call_join = u8 7 | call(16) | u8 in (1 joins, 0 leaves) | u8 what it gives (0 takes, 1 forwards, 2 seeds)
    key(g)    = H(secret_g, D("sg.chat.v7.call.key") | call | u64 g | roster digest (zeros in a mesh))

The call is a state of the world (`world/call.sg`, `call.start` and
`call.end` edits at the book): its mode, generation, how many are in it and
its stripes, participants of the engine's Placement (`solver` = who
forwards that stripe; neighbouring stripes are constraints). Who is in it
and who forwards change only by its `roster` and `place` edits.

**Chunks** go on the live link's Latest lane (channel `call`, a slot per
chunk; late is lost, not waited for):

    chunk = u8 7 | call | streamer id | u64 generation | u64 sequence | u8 layer (0 full, 1 small, 2 audio)
            | u8 key frame | u64 captured µs | nonce(24) | AEAD(key(generation), nonce, the header before the nonce, media)

**Roots** go on the reliable lane (channel `callroot`), signed by the
streamer's device key, about every tenth of a second in talk and every
second in a stream:

    root  = u8 7 | call | streamer id | u8 layer | u64 generation | u64 first | u16 n
            | n x H(D("sg.chat.v7.call.chunk") | chunk) | Ed25519
    signs D("sg.chat.v7.call.root") | the same fields before the signature

Each layer of a streamer is a stream of its own: its own numbers and its
own roots, so a listener that is not given one layer never waits on it.

A receiver plays a chunk only once a root of its streamer names its hash:
held until then (up to four different chunks for one number - one
injected first cannot shut out the real one), played in order, refused if
a root names another hash. A root never names a number again; a lost root
leaves a gap; a gap waited on 400 ms in talk (3 s in a stream) is passed
over. Every frame played was said by its streamer, whoever carried it.

**Everyone to everyone** (up to five devices): each says its own chunks and
roots to each. When one leaves, the starter turns the key: a new secret to
each device still in, in a signed control frame (kind 11):

    call_key = u8 7 | call | u64 generation | secret(32) | Ed25519(starter,
               D("sg.chat.v7.call.next") | call | u64 generation | recipient id | secret)

**A swarm** (a stream to many): the starter streams. Each join or leave is
an epoch of the call's committee - the starter's device(s), region
`sgchat-call:<call>` - whose one statement is the next roster
(`Swarm.hpp`):

    roster = u8 7 | call | u64 generation | u16 n | n x (sign | agree | u8 what it gives)   (sorted, distinct)
    checkpoint = D("sg.chat.v7.roster.checkpoint") | call | u64 tick | predecessor | roster

finalized, then sealed by a Handoff to the next generation (the same
committee), and sent to each viewer on it in a control frame (kind 12):
`u8 7 | long(finalized epoch) | long(handoff)`. A viewer takes it only from
the starter, with the handoff verified against the call's committee and
the roster its checkpoint names, and only forward; then the starter's
`call_key` for that generation (bound to the roster's digest). Each device
plans the same forwarders from the same finalized roster with the engine's
Placement (capacities 4 for a seed, 1 for a forwarder; one that only takes
is not available) and tells its world by the `place` edit. The stream is
cut in pieces of 250 ms (a chunk each, its media `u8 7 | u16 n | n x (u8
layer | u8 key | u64 captured | long(frame))`); piece i goes to the
forwarder of stripe i mod 4, who gives it to six of its neighbours at once
(a different six each piece). Neighbours are the forwarders and three on
a ring of the roster, both ways; every 250 ms a viewer says what it holds
(`callmap`: `u8 7 | call | u64 base | u64 bits`, 64 pieces) and asks for
what it lacks (`callwant`: `u8 7 | call | u64 piece`), nearest the playing
point first, then the rarest, at most four waiting on one neighbour, a
question unanswered for 500 ms asked again elsewhere. It gives what a root
it holds names - never a copy a root says is not it. Roots are flooded to
neighbours once.

**Speakers through a tree** (more than five, talking): the same roster and
plan; each speaker sends its chunks to the relay of its stripe (its place
in the roster mod 4), who gives them on; roots likewise. Speakers send a
full picture (640x360) and a small one (320x180) - simulcast. A listener
says whose full picture it wants (`callpick`: `u8 7 | call | short(speaker)`,
to the relays and the speaker); a relay gives a speaker's full layer, and
its roots, only to those who asked for it, and the small picture and the
sound to everyone.

## Live state (protocol 8)

**Tape tennis**, a game of two in a two-sided conversation:

    game = u8 8 | game(16) | u8 what (0 asks, 1 plays, 2 stops)

The one who asks plays left (player 0). Each device makes the court in its
world (`world/game.sg`, the `game.start` and `game.end` edits at the book):
the court `g_<game>`, its network `n_<game>` and its time `t_<game>`
(a Temporal of its own); the court is embedded in the conversation at its
`table` portal. Each step, a player's control (-1, 0, 1) is published into
the network, where it is that player's participant's pinned coordinate;
the shared constraint makes both participants agree, and the engine's
Distributed reconciliation carries it - its boundary packets (`sg::net::
Exchange` bytes) go on the live link's Latest lane:

    game packet = u8 8 | game(16) | packet

each in a slot of its own; the last two are said again every three frames
until the step is agreed (one lost, or overtaken, costs a little time,
never the game). When both have settled (two rounds) the step is
committed, and the court moves six steps of 1/60 s with the controls
agreed - the same motion on both devices, by the same declared arrows. The
picture is the engine's Prediction of the court, ahead of what is agreed
by at most twelve frames, corrected when it is.

**The whiteboard** of a conversation:

    stroke = u8 8 | u8 color (0..15) | u8 width (1..64) | u16 n (1..4096) | n x (i16 x | i16 y)

on the board's square, -32767..32767 each way. A stroke is a signed
message like any other (kept, sealed, accepted through Integrity). The
board is a state of the world (`world/board.sg`, the `board.open` and
`board.close` edits): the board `b_<conversation>` (it counts its strokes
and says who leads), its view `v_<conversation>` - each device of the
conversation a participant (x, y, zoom), neighbours constrained to agree -
and its time `u_<conversation>`; the board is embedded at the
conversation's `board` portal. On the live link (channel `board`, the
Latest lane):

    u8 8 | conversation(16) | u8 1 | f32 x | f32 y | u8 down | u8 color   a pen, about 30 times a second while drawing
    u8 8 | conversation(16) | u8 2 | f32 x | f32 y | f32 zoom            where this device looks
    u8 8 | conversation(16) | u8 3 | u8 on                               this device leads (or stops)

A pen is shown where the engine's Prediction says it is going (its
velocity from the last two places). Where each device looks is said at
the view's port; one that leads is pinned there, and the engine's
Reconcile - each device solving the same problem from the same
observations - brings every view to it.

## Releases (protocol 9)

A release is a record of the release chain (`web/release.js`, written into
`sw.js` when a release is cut; `tools/release.py` makes it):

    body  = {"committee":{"keys":[...sorted hex],"quorum":q},"manifest":hex,"previous":hex,"sw":hex,"version":n}
            (canonical JSON: these keys in this order, no spaces)
    hash  = SHA-256(body)
    record = body + "signatures": [{"key": hex, "sig": hex}, ...]

`manifest` is the SHA-256 of `manifest.json` (every file of the bundle and
its SHA-256), `sw` of `sw.js`, `previous` the hash of the record before
(zeros for the first). A signature is Ed25519 over the engine's Observation
statement (`sg.net.observation.v1`): peer the key's hex, context SHA-256 of
"p-chat.release.v1", tick 0, sequence the version, object "p-chat",
parameter and conflict "release", discrete, payload the record's hash. The
first record is signed by its own committee, which `sw.js` carries; each
later one by a quorum (2q > n) of the committee the record before names. A
device takes a record only if it follows its head (`previous`), has a
higher version and enough signatures; versions it skipped are taken link by
link; then the bundle (manifest, files, `sw.js`). Refused: kept as evidence.
Two records signed for one version by one member are a fork.

A device says the chain it runs to each conversation once per release:

    release = u8 9 | u8 what (1 this device runs it, 2 a fork seen) | long(JSON: the chain, or {"a": record, "b": record})

A contact behind takes the newer release's files from that device on the
live link (channel `release`, reliable, in pieces when large):

    u8 9 | u8 1 | u16 n | path(n)                       asks for a file (manifest.json first)
    u8 9 | u8 2 | u16 n | path(n) | u32 m | file(m)     the file, from the bundle the device runs

up to 32 asked at once, each asked again after 5 s unanswered; the whole is
then checked by the service worker as any release, and waits. Every
signature a device sees is kept in the engine's Integrity over its
committee (a fork is its equivocation).

## No middleman (protocol 10)

The relay is optional. Two phones side by side pair with none, and the
phones of a chat's contacts carry for each other what a relay would.

**In person.** The inviting phone makes an invite (with the relay it uses,
or none) and a WebRTC offer of one data channel, `p-chat-pair`, every
candidate gathered (at most 4 s). It shows one code, a link the other
phone's camera opens:

    https://<site>/#d1.<base64url(u8 1 | short(invite) | short(code) | short(offer))>
    code:  the six words, normalized

When the invite names a relay (and the other phone uses relays), that is
all: the other phone asks with the code from the link, through the relay,
as for any invite. With none, the other phone takes the offer, makes its
answer and shows it back:

    p-chat:a1.<base64url(u8 2 | token(16) | short(answer))>

and the first scans it. A description is carried compact - what differs
between two data channels' descriptions - and the standard one made again
from it:

    compact   = u8 1 | u8 setup | short(mid) | short(ufrag) | short(pwd) | fingerprint(32)
                | u8 n (<= 8) | n x (u8 kind | address | u16 port | u8 type)
    setup:      0 actpass, 1 active, 2 passive
    kind:       1 mDNS name (a UUID, 16 bytes, + ".local"), 4 IPv4 (4), 6 IPv6 (16), 0 short(text, 255)
    type:       0 host, 1 srflx, 2 prflx, 3 relay
    UDP candidates only; a description without a SHA-256 fingerprint is not put in a code.

Over the link the two make, each frame is `u8 kind | body`: 1 the pairing
request (the sealed box that would be posted to the relay), 2 the accept
(the version 16 envelope that would wait in the reply mailbox), 3 `room |
box`, a conversation's sealed signal (above), until the conversation's own
live link is up. Nothing is believed for having come over it: the request
holds under the code's key and the device's signature, the accept under the
owner's, a signal under its sender's. The link is closed ten seconds after
the two are linked directly, or after ten minutes.

Who can see the screen can read the code; who has the code can open the
link offered in it, and ask to pair - but the inviting phone takes only the
answer it scans itself, and the request still needs the words in the code.

**Contacts carrying.** On the live link two members of any conversation
have, channel `carry`, each frame `u8 kind | body`:

    1 rooms:  u16 n (<= 256) | n x (room | label)     where to reach me: replaces the last; said
                                                      when it changes and each minute
    2 pass:   room | label | long(box, 131072)        a sealed signal: pass it to the linked phone
                                                      that said this room and label
    3 signal: room | long(box, 131072)                a sealed signal, for you
    4 hold:   envelope                                keep it: version 1 or 2, a relay's size
    5 ask:    u16 n (<= 1024) | n x mailbox           anything for these?
    6 given:  mailbox | handle(16) | envelope         one that was kept (its mailbox its own)
    7 taken:  mailbox | u16 n | n x handle            opened: drop it

`handle` is the relay's, `H(envelope)` truncated to 16 bytes. A phone with
no relay for a chat (relays off, or none) gives its signals to every
linked phone (directly to the one they are for, if linked; to the others
to pass on), again every 5 s for 2 minutes.
An envelope for a device that takes mail is given to up to three linked
phones to keep. A phone asks every linked phone for its mailboxes each 8 s.

A carrier keeps at most 512 envelopes and 16 MiB, 128 from any one giver,
for 14 days; it passes at most 120 signals and keeps at most 60 envelopes a
minute from one giver. One that does not carry (Settings) refuses 2, 4 and
5, and still says its rooms and takes 3 and 6. What a carrier sees is what
a relay sees - rooms, labels, mailbox ids, sealed boxes and their sizes -
and, being a contact of both, that the two it carries between talk.

**A device that relays (protocol 11).** A device its owner leaves open -
a computer on a desk - may relay for its contacts (Settings, "This device
relays"; it carries, so a device that does not carry does not relay). It
does what every carrier does, with a relay's share of room (below), keeps
what it holds across reloads (every carrier keeps it in IndexedDB), keeps
the screen on while shown (where the browser allows a wake lock), and says
so, on `carry`:

    8 relays: u8 flags                                bit 0: this device relays; no other bit.
                                                      Said once it relays (and once it stops), and each minute
    9 serves: u16 n (<= 1024) | n x (room | label | u8 now)
                                                      the devices it keeps mail for that share a
                                                      room with you (not your own); now 1: linked here now

A relaying device remembers, for 14 days, each (room, label) its linked
contacts said in their `rooms` - where each device is reached, the same a
relay's rooms are. To each linked contact it says, in `serves`, those that
share a room with that contact; again when they change and each minute.
`serves` is believed only from a contact that said it relays, and only
for two things - where to keep, and whom to look for; nothing is opened by
it:

- *Sending.* With no relay for a chat, a message for a device that is away
  is sent (not refused) when every other device of the chat is linked or
  takes mail, and the linked contacts that relay, between them, serve as
  many labels of one of the chat's rooms (not this device's own) as the chat
  has other devices. It is given to every linked contact that relays (and
  to others, up to three); kept only by others, it is given again to one
  that relays once one is linked. The chat says it is reached "through
  <the name this device gives that contact>'s device".
- *Finding each other.* A device of one of this device's chats said `now`
  is looked for again through it: the live link with that device is made
  again (at most every 30 s), its signals passed on by the relaying device.

A relaying device's contacts learn what a relay's room would tell them: that
a device of their own chat comes by it, and when it is linked there. It
learns nothing a carrier does not (rooms, labels, mailbox ids, sealed boxes).

**Linking again in person (protocol 11).** A page cannot be reached: a
device with no relay that was closed and opened again is linked with no one,
and no one can link with it. Two devices already paired - a phone and the
device that relays for it, say - link again from two codes, as when they
paired in person, with no invite:

    https://<site>/#l1.<base64url(u8 3 | token(16) | short(offer))>
    p-chat:a1.<base64url(u8 2 | token(16) | short(answer))>      (the answer, as above)

`token` is random, the answer naming it is the only one taken. Over the
link, only frame 3 (`room | box`, a conversation's sealed signal) is taken:
each device sends every signal it keeps and makes again the live link with
every device it is not linked with, whose signals go over it too. Those of
another chat than the two share are dropped unopened by the other. The link
is closed ten seconds after a device not linked before is, or after ten
minutes. Who scans learns the rooms of the other's chats and sealed signals
- what a relay sees; nothing is believed for having come over it. Through
the device it is linked with again (it carries, or relays), a device finds
the rest.

**Relays off** (Settings, a device's own choice): no connection to any
relay. Invites are made in person only; a message for a device that takes
mail waits on this phone and with linked contacts; pushes, which only a
relay can forward from a page, are not sent.

## Gaps

Each pinned device's window in the world (`chat/Window.hpp`): the highest
sequence, a 63-bit window below it, and a count of those that fell out of
it missing. A sequence missing from the window for longer than the mailbox
TTL (14 days, wall time, outside the world) is shown as "message missing":
a relay that drops a message is seen.

## Committees and history

A conversation's devices are an `sg::net::Committee`:

    region = "sgchat:" + hex(conversation); generation; faults = 0
    members = every pinned device of both sides (peer, sign key)
    quorum  = n for one or two devices, n - 1 for more (2q > n + f)

**History epochs.** Every 50 messages, or once a day, the owner's side
(its device with the lowest id) states the history since the last epoch as
one discrete observation, and the members run an `sg::net::Agreement`
epoch on it. One proposer means no two members ever lock on different
statements for a tick; the owner's side, because it changes who is in the
conversation and so is there when it does - a device being revoked is
never the one relied on. Epoch messages travel like any other frame (live
or through the mailbox), so a member who is away votes when it is back.

    statement: peer = proposer, context = EpochContext.id(), tick, sequence = tick + 1,
               object = hex(conversation), parameter = "history", conflict = "history",
               payload = u8 1 | u16 n | n x (peer id | u64 from | u64 to) | u32 m | m x message id
    runs:      per sender, every sender the conversation has had, from the one after the
               last epoch's cut, as far as there is no gap; ids in order of sender, then sequence
    EpochContext: world = partition = region, tick, generation, topology/constraints/solver of
               the placeholder system, committee id, previous = the last finalization's id
    checkpoint = D("sg.chat.v1.history.checkpoint") | short(object) | u64 tick | previous
               | u16 n | n x (peer id | u64 to) | chain
    chain      = fold over ids of H(D("sg.chat.v1.history.chain") | chain | id), from previous

A member attests only when its own log names the same messages for the same
runs; a member that is missing some waits for them; one whose log differs
(a message dropped, changed, moved or added) never attests and shows it.
The finalization chains to the one before it: history is tamper-evident.
Vote locks are persisted before an attestation is sent.

**The placeholder system.** `Agreement` and `Verify` finalize numerical
epochs, and a chat epoch has nothing to solve. It carries the smallest
system the engine accepts: one free coordinate, observed 0, confidence 1,
no overlaps, 0 iterations (it solves to 0 exactly), solver rules
`sgchat-history-v1`. Every meaning is in the one discrete input and the
checkpoint. ENGINE_REQUESTS.md asks for a discrete-only epoch.

**Signing outside the engine.** `Agreement::attest`/`endorse`,
`Verify::propose` and `Protocol` sign with a `SigningKey` in memory; a
browser device's key is a non-extractable WebCrypto key. So the statement
(attestation, endorsement, result certificate) is made in Wasm, signed in
WebCrypto, and a vote's lock is written as the exact journal the engine
persists (`sg.net.agreement-journal.v1`) and read back with
`Agreement::restore`, which checks it. Ed25519 is deterministic, so the
bytes equal the engine's own (`sgchat_trust` holds them equal).

**Handoffs.** A device joins or leaves only by an `sg::net::Handoff` from
the last finalized epoch to the next committee (generation + 1), endorsed
by the old committee's quorum, verified with `verify_handoff` and taken up
with `Agreement::resume`; only then is the graph edited (`device.add` /
`device.revoke`). Pairing a further device proposes the handoff (a new
history epoch first, so nothing said is left out of the history; a friend's
device that wants an epoch sooner sends control 5, a nudge); the existing devices
endorse it; the new device is given the last finalized epoch and the
endorsed handoff in its accept and resumes from them. Endorsing seals the
old generation; messages still on the way under it are refused as `Replay`
and their senders send them again under the new one, with the same
sequence. Control frames:

    1 epoch:        sg::net::encode(Message): Proposal (with the statement), Attestation, Finalization
    2 handoff ask:  Handoff without endorsements | u8 n | n x (sign | agree | u8 side)
    3 handoff vote: an endorsement (Attestation: epoch | decision | short(signer) | sig)
    4 handoff done: the endorsed Handoff

    Handoff   = u8 1 | long(Finalization as encode(Message)) | long(checkpoint)
                | committee | u16 n | n x Attestation
    committee = short(region) | u64 generation | u32 quorum | u32 faults | u16 n | n x (short(peer) | key)
    Finalized = u8 1 | context fields | long(statement as encode(Message{Inputs}))
                | long(Finalization) | long(checkpoint)

A friend's further device needs the owner's device to propose and an
existing device to endorse: if a two-device conversation has lost its other
device, no quorum is possible, and the owner removes the contact and invites
again ("Ask Bardia for a new key").

**Revocation.** The owner proposes a handoff without the device; the old
quorum endorses; the owner sends `device_revoked` (signed, as every message)
to the remaining devices *and* the revoked one, then `rekey` to the
remaining ones only, and stops sealing to it. The revoked device shows
"This device was removed. Ask Bardia for a new key."

## Signaling

The engine's `WebRtcTransport` (Reliable lane for envelopes) asks for
signals to be carried. Each is signed by the sending device and routed by
the relay only within the conversation's room:

    signal = u8 1 | room | from id | to id | u64 counter | u8 lane | u64 session | u8 kind
             | short(value) | short(type) | sig
    sig    = Ed25519(from, D("sg.chat.v1.signal") | (the same fields))

On the way it is sealed, and addressed by a label, so the relay learns no
device id and cannot read or change a signal:

    label = H(secret, D("sg.chat.v1.label") | device id)
    box   = nonce(24) | AEAD(H(secret, D("sg.chat.v1.signal.key")), nonce,
                             D("sg.chat.v1.signal.ad") | room, signal)

The receiver opens it, checks the signature against the pinned device
before the transport sees it, and takes each sender's counter only forward.
A device is in the room of every secret its conversation still keeps (at
most three). A signal goes to the room its peer was last heard from; to a
peer not heard from yet, it goes to every kept room under one counter (the
copies after the first are dropped as replays) - a device that missed a
rekey while away is still met. The engine takes a link's sessions only
forward: a device that heard a peer signal under an older session than its
own newest for that link, while the link is down (the peer went away and
began again), makes the link again - at most every 15 s - so the peer takes
up the newer session. When the
channel is up, envelopes go direct; otherwise to the mailbox. A message sent
live and not acknowledged within 30 s is also left in the mailbox. Both
paths deduplicate by `(sender, sequence)`; the recipient deletes mailbox
blobs once it has opened and kept them.

## The relay's frames

Binary WebSocket frames only:

    request  = u8 1 | u8 op | u32 id | body
    response = u8 1 | u8 (op | 0x80) | u32 id | u8 status | body
    status:  0 ok, 1 refused (malformed), 2 burned/used, 3 busy (backpressure),
             4 quota, 5 not found

| op | name | body | answer |
| --- | --- | --- | --- |
| 1 | put | envelope | - |
| 2 | fetch | u16 n, n x mailbox | u16 n, n x (mailbox, handle(16), long(envelope)) |
| 3 | delete | mailbox, u16 n, n x handle | - |
| 4 | watch (protocol 11) | u16 n (<= 1024), n x mailbox | - (4 past the relay's bound on all watches) |
| 16 | pair post | token(16), box (1 KiB bucket) | - (2 if burned) |
| 17 | pair fetch | token | u16 n, n x long(box) |
| 18 | pair reusable | token, H(cancel key) | - |
| 19 | pair cancel | token, cancel key(32) | - |
| 20 | pair done | token | - (burns, drops posts) |
| 32 | join room | room(32), label(32) | - |
| 33 | signal | room, to label(32), long(box, 131072) | - |
| 34 | leave room | room | - |
| 48 | push subscribe | mailbox, long(subscription JSON, 4096) | - |
| 49 | push forward | long(endpoint, 1024) \| long(authorization, 1024) \| long(sealed push, 4096) | - |

The relay pushes `u8 1 | u8 0x40 | u32 0 | room | long(box)` to the addressed member
of a room.

**Watching** (protocol 11): a connection names the mailboxes it fetches -
the same ids a fetch names, so the relay learns nothing a fetch does not
show it - and each list replaces the last (an empty one ends watching).
When a put stores a new envelope in a watched mailbox, the relay pushes
`u8 1 | u8 0x41 | u32 0 | mailbox` to each connection watching it: no
envelope, no sender, only which mailbox. It is a hint, best effort (a
connection's full queue drops it): the device fetches that mailbox at once,
and still fetches all of its mailboxes now and again (every 20 s while
watching, every 4 s from a relay that refuses op 4). A device names its
mailboxes again when they change (a new day's, a new chat's) and on every
new connection; the relay forgets a connection's list when it closes. `handle = H(envelope)` truncated to 16 bytes (equal envelopes
dedupe). It keeps everything in RAM, expires it after the TTL, bounds bytes
per mailbox and in all, bounds rooms and members, and logs nothing.

## Constants

| Name | Value |
| --- | --- |
| Buckets | 1024, 16384, 262144 bytes |
| Mailbox TTL | 14 days |
| Argon2id | 32768 KiB, 2 passes, 1 lane |
| Skipped keys | 1000 per turn, 2000 kept |
| Window | 63 sequences |
| History epoch | every 50 messages or daily |
| Live acknowledgement wait | 30 s |
| Mailbox fetched, all of it | every 4 s; every 20 s while the relay tells of mail (protocol 11) |
| Control frames kept / resent | 5 min / every 10 s |
| Delivery default | live only |
| File chunk / largest file | 64 KiB / 100 MB |
| Chunks per relay piece | 3 |
| Thumbnail | at most 12 KiB |
| Names | at most 64 bytes UTF-8 |
| Text body | at most 200000 bytes |
| Recovery wait | 24 h |
| Recovery quorum | max(1, ceil(2r/3)) of the r members that remain |
| Live piece | 131072 bytes, at most 64 |
| Kept secrets (and rooms) | 3 |
| Call roots | every 100 ms (talk), every 1 s (a stream) |
| Stream pieces | 250 ms; 4 stripes; a forwarder gives to 6 at once |
| Waited on a gap | 400 ms (talk), 3 s (a stream) |
| In person: candidates gathered / pairing link kept | 4 s / until linked + 10 s, at most 10 min |
| Carried: signals again / for | every 5 s / 2 min |
| A link made again for a peer heard behind it | at most every 15 s |
| Kept for others | 512 envelopes, 16 MiB, 128 a giver, 14 days |
| Carried a minute, per giver | 120 signals, 60 envelopes, 30 asks |
| Kept by a device that relays | 4096 envelopes, 256 MiB, 1024 a giver, 14 days; a minute, per giver: 600 signals, 300 envelopes |
| A relaying device remembers where a contact is reached | 14 days (written again at most hourly) |
| Looked for again, said `now` by a device that relays | at most every 30 s a device |

## Test vectors

`tests/vectors/v4.json`: keys from fixed seeds (`fill(b)`: bytes b, b+1,
...), fixed ephemerals and nonces, and the invite, request, accept,
envelopes, observation, ratchet states, frames, history statement,
certificate, attestation, journal and signal they make.
