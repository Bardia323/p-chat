# p-chat

Live: **https://p-chat-21r.pages.dev** (Cloudflare Pages), with its relay at
`wss://p-chat-relay.bardia-shahrestani.workers.dev` (Cloudflare Workers,
`relay/worker`). Any other relay can be set in Settings → Advanced, or none.

Private phone-to-phone messages in a plain browser tab: no install, no
account. You show a friend a QR code and tell them six words; their browser
makes a key that cannot be copied out of it, and the two devices are paired.
Messages go phone to phone over WebRTC when both are open, otherwise through
a relay's mailbox that only ever holds ciphertext. The relay is optional:
two phones side by side pair by scanning each other's codes, with none, and
contacts' phones carry for each other what a relay would (protocol 10).

`sgchat` is the project (this folder); **p-chat** is the app people use.
It is an ordinary [stategine](../stategine) project: each conversation is a
state, made and changed through the graph's own edits and ports
(`world/*.sg`), and its trust - who is in it, what was said, its history -
is the engine's own network machinery (`sg::net`: `Observation`,
`Integrity`, `Committee`, `Agreement`, `Handoff`). The byte-exact protocol is
[docs/protocol.md](docs/protocol.md).

What it does (v1): two-sided chats, groups and channels; photos, files,
stickers and voice notes; per contact "live only" or "mailbox too";
notifications that show only a symbol you chose; replacing a lost phone by
the others' approval, with its history, or "No recovery"; disappearing
messages; calls (everyone to everyone, speakers through relays with small
and full pictures) and going live to a swarm; table tennis and a shared
whiteboard; bots; and releases signed by a committee of the owner's devices,
taken from the site or from a contact's phone, every one checked. And no
middleman needed: pairing in person with no relay, contacts passing each
other's signals on and keeping each other's sealed messages - within a
chat, over several links, through its own members and no one else - relays off
altogether (Settings), any relay - the one it came with, a friend's, your own,
or a device of yours left open ("This device relays"). Your phone and
computer linked as one you: every chat on both, history given, kept in step,
and unlinked by keeping a copy, forgetting everything, or splitting the chats.

## What it protects, and what it does not

**Protected**: what you write, and who wrote it, against the relay, the
network, TURN, the static host's logs, and anyone holding only the link or
only the six words. A link used after pairing is worthless. Messages are
end-to-end encrypted per device pair under a Double Ratchet (forward
secrecy), signed by the sending device, and accepted only by the devices
pinned in the conversation. History on the phone is encrypted at rest under
a non-extractable AES-GCM key. Every so often both sides agree on the exact
list of messages so far, chained to the last agreement: a dropped, changed
or reordered message shows.

**Not protected**:

- *When and how much* you send: the relay (whoever runs it) sees the timing
  and size class of envelopes and the daily mailbox ids, but not who sends.
- *A compromised phone*: whoever controls the device controls the app.
- *The code you are running.* A service worker takes a release only from
  the release chain - signed by a quorum of the committee, linked to the one
  it runs, every file the one named - and refuses the rest, keeping the
  evidence; a fork (two releases signed as one version) is kept and told to
  every contact. But the web is the root of trust here, twice over:
  **the first load is trust on first use** (the committee the phone will
  believe is the one in the `sw.js` it is first given), and **`sw.js` itself
  is updated outside the chain**: the browser fetches the worker from the
  site and replaces it whenever the site serves a different one, and the
  signed worker cannot veto that. So the static host, its DNS and its TLS
  certificate remain the root of trust **on every load**, not only the
  first. About warns when the `sw.js` served is not the one the running
  release names; compare the bundle fingerprint (About) with the published
  one.
- *What a carrying contact learns*: a contact whose phone carries for others
  (on by default; Settings) sees what a relay would - rooms, labels,
  mailbox ids, sealed boxes, their sizes and times - and, knowing both
  phones, that the two it carries between talk. It reads nothing.
- *A new contact's code or link* carries its six words: whoever has it can
  pair, once (the one it was meant for is then told it was used). Send it
  only to them, and compare the four pictures if it matters; "A new contact,
  with six words" keeps the words apart from the link. With no relay, the
  inviting phone joins only the code it scans back itself.
- *Relay timing*: the relay sees when envelopes are put and fetched, their
  size class, and which connection forwarded a push; a live link's packets
  (calls, games, the board) show their rhythm to the network.
- *Recovery is social*: a lost phone is replaced by the others' approval. A
  person who is talked into approving a stranger's device (no check of its
  four pictures, in person or by voice) lets that device in, with whatever
  history is given; the old phone's day to refuse is the only check left.
  "No recovery" turns it off for a chat.
- *History given is no longer forward-secret*: when a recovered phone is
  given the history, each message goes with its own key; whoever later
  takes that phone (or the one that gave it) can read what was given.
  Disappearing messages are not given (their keys are gone).
- *Keys on a browser that cannot keep them*: where a browser does not keep
  an Ed25519/X25519 CryptoKey in IndexedDB (an iPhone seen losing one on a
  reload), the private key is kept wrapped (AES-GCM) under a non-extractable
  key, and unwrapped non-extractable. Its bytes still never reach the page,
  but a script running in the page could unwrap it extractable - which it
  cannot do where the key is kept as it is.
- *The relay on Cloudflare*: it holds only sealed boxes and logs nothing,
  but Cloudflare carries its connections, so it sees the addresses they come
  from, as any host does. Run your own relay to change who that is.
- *Deniability*: messages are signed by the device key (so equivocation can
  be proven and history agreed). A recipient can show others a signed message.

**Known trade-offs**:

- Without a relay, phones find each other only directly or through a
  contact linked to both: two phones with no link and no contact online in
  common wait until they have one (or meet). A browser on a phone is closed
  more than it is open, so this is the common case; a relay - any relay,
  your own - is what makes "later" work. And with relays off no
  notifications are sent: a page cannot post to the push services itself.

- Safari may clear a site's storage after about seven days unused (when
  the site is not added to the home screen). The device key dies with it
  and cannot be made again: the app says "Device not recognized. Ask … for
  a new key."
- An iPhone gets notifications only once p-chat is on its Home Screen (Settings
  shows the steps); the Home Screen copy has its own storage and pairs again.
  A notification shows only the symbol you chose for that chat.
- A push is made on the sender's phone with the recipient's VAPID key (shared
  with its contacts in a signed message). When the browser does not let a page
  post to the push service, the relay carries the sealed push as it is: it then
  learns that some connection pushes to some endpoint, never what or for whom.
- A lost phone is replaced by the others' approval and a day's wait (Devices,
  "Replace: lost"); a chat set to "No recovery" cannot be, and its history
  dies with the phone.
- Linked devices (your phone and computer as one you) are trusted on your
  word: a contact's chat takes your new linked device as it would a further
  device of yours, by your devices' handoff, without asking the contact.
  Linking is by link and six words only (no in-person code for it yet).
- Between networks (a phone on mobile data, a computer at home) a live link
  needs a path STUN alone cannot always find; with no TURN, messages then go
  by the relay's mailbox (a round trip or two) and calls may not connect.

**Not tried on real phones** (everything below ran in desktop Chrome, in
tests, on one machine): pairing in person with real cameras and screens,
and between two phones on a real network (mDNS candidates on Wi-Fi, a
phone on mobile data); an iPhone's Home Screen web app and its Web Push;
the real push services (FCM, Mozilla's, Apple's) - whether they accept a
push posted from a page (CORS) or only through the relay; Safari's and
Firefox's WebCodecs (Safari has no MediaStreamTrackProcessor for audio:
video only there) and their data channels' message sizes; calls and streams
over mobile networks, TURN, and between continents; a swarm of many real
browsers (the swarm of nine is a simulation; the browser test has one
viewer); battery and thermal cost of a call or a game; storage eviction on
iOS and Android over weeks; the camera's EXIF stripping on real photos from
each phone; a release fetched from a contact's phone on a slow link (2.3 MB
of Wasm).

## Build

On the build server (no install on the phones, ever):

```sh
. ~/.stategine-env                       # cmake, node; on this server
cmake -S . -B build -G Ninja -DFETCHCONTENT_SOURCE_DIR_STATEGINE=../stategine
cmake --build build && ctest --test-dir build --output-on-failure

source ~/emsdk/emsdk_env.sh              # Emscripten 4+ (here 6.0.12)
emcmake cmake -S . -B build/wasm -G Ninja -DFETCHCONTENT_SOURCE_DIR_STATEGINE=../stategine \
  -DSTATEGINE_SGC_EXECUTABLE=$PWD/build/_deps/stategine-build/sgc \
  -DSGCHAT_BROWSER=/path/to/chrome
cmake --build build/wasm && ctest --test-dir build/wasm --output-on-failure
```

The tests need Python 3 with `websockets`, `cryptography` and `playwright`
(`pip install --user websockets cryptography playwright`), and for the
browser tests a full Chrome or Chromium 137+ (Chrome for Testing's
`chrome`; its headless shell grants no notifications). The native build
needs OpenSSL's headers (the bot's TLS). `SGCHAT_PYTHON` chooses another
Python; `SGCHAT_ECHO` where the browser test finds the echo bot.

| Test | What |
| --- | --- |
| `sgchat_link` | the engine's networking is linked |
| `sgchat_vectors` | every protocol byte equals `tests/vectors/v4.json`; refusals |
| `sgchat_world` | the DSL world: strict validation, every law checked, nothing unchecked; windows, edits, rename |
| `sgchat_trust` | Integrity (accept, duplicate, replay, equivocation), externally signed votes = the engine's, history epochs, handoffs |
| `sgchat_ratchet` | the Double Ratchet: both ways, out of order, limits, replays |
| `sgchat_app` | the whole messenger natively: pairing, wrong code, both ways, reload, epochs, extra device, revoke, a dropped message, live |
| `sgchat_relay` | the relay: token burn, reusable cancel, TTL, quotas, room isolation, malformed frames, backpressure, Web Push, push forwarding |
| `sgchat_relay_worker` | the same checks against the Cloudflare Worker relay under `wrangler dev` (no backpressure or relay-held VAPID there) |
| `sgchat_media` | files: chunks, references, relay pieces, size limits; live pieces |
| `sgchat_call` | calls and streams over simulated links: a swarm of nine with churn, Placement's plan in the world, an injected chunk refused, latency logged; talk under 300 ms |
| `sgchat_live` | live state: table tennis in two worlds with late packets, the same game step for step; a whiteboard's views brought to the one that leads |
| `sgchat_release` | the release chain in Node: every refusal, skipped versions, a committee's handover, a fork; chains cut by release.py |
| `sgchat_release_browser` | the same in a service worker: update ready and run, refusals kept, sw.js mismatch, a fork, a peer's bundle, a migration |
| `sgchat_bot` | the echo bot as its own process, two people as native hosts, the real relay: pairing, answers, a restart, a group, revocation |
| `sgchat_modules` | the engine's module shape rules |
| `sgchat_vectors_node` | the vectors made in Wasm and by WebCrypto under Node |
| `sgchat_browser_vectors` | the same in a real headless browser |
| `sgchat_direct` | protocol 10 in Node: in-person codes made and read back (Chrome's, Firefox's, Safari's descriptions), refusals; a carrier's rules - passing on, keeping, giving back, bounds, rates, a phone that does not carry |
| `sgchat_meet` | protocols 10 and 11 in Chrome (part 3: a device that relays, kept mail given across its reload, linking again in person): two phones with relays off pair in person (both codes read off the screen by jsQR) and talk, never opening a relay connection; three phones, one never using a relay: a lost link found again through a contact, a message kept by the contact while its recipient is away and given back |
| `sgchat_lag` | protocol 11 in Chrome: how long a message takes between two browsers, live and by a relay 80 ms away, reopened and woken (live p50 5 ms, relay only 168 ms) |
| `sgchat_desktop` | the wide layout's facts at 1280x800 and larger; the phone's layout unchanged |
| `sgchat_link_browser` | protocol 11 in Chrome: linking a phone and a computer, every chat and its history on both, names, the linked devices screen, Keep, Forget and Split |
| `sgchat_e2e` | p-chat in real browsers end to end: pairing, files, groups, a channel, disappearing messages, notifications, a call, going live, speakers through a tree, table tennis, the whiteboard, an update from a contact's phone, recovery, a bot, cleared storage, the signed bundle, the relay's memory |

p-chat has a light look (the cream VHS sleeve) and a dark one (the black
sleeve: white type, stripes from yellow to violet). It follows the phone;
**This device → Look** chooses Light or Dark for this browser.

## Deploy the relay on a VPS

The relay keeps everything in RAM, logs nothing, and holds only envelopes it
cannot open. One Python process:

```sh
sudo useradd --system --home /opt/p-chat p-chat
sudo mkdir -p /opt/p-chat && sudo cp relay/relay.py /opt/p-chat/
sudo -u p-chat python3 -m pip install --user websockets cryptography
```

Behind a TLS reverse proxy (recommended; the relay binds loopback), e.g. Caddy:

```
relay.example.org {
    reverse_proxy 127.0.0.1:49290
    log { output discard }
}
```

or with its own certificate: `relay.py --host 0.0.0.0 --port 443 --cert fullchain.pem --key privkey.pem`.

A systemd unit:

```ini
[Unit]
Description=p-chat relay
After=network.target
[Service]
User=p-chat
ExecStart=/usr/bin/python3 /opt/p-chat/relay.py --port 49290
Restart=always
StandardOutput=null
StandardError=null
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
MemoryMax=1G
[Install]
WantedBy=multi-user.target
```

Notifications need nothing from the relay: each phone makes its own VAPID
key and its contacts push to it. The relay only carries a sealed push the
browser would not let a page send itself (op 49), and only to the browsers'
push services (`fcm.googleapis.com`, `*.push.services.mozilla.com`,
`web.push.apple.com`, `*.notify.windows.com`; add one with `--push-host`),
at most 60 a minute per connection. (The v0 relay-held VAPID key,
`--vapid-key`, still works for v0 clients; p-chat v1 does not use it.)

Limits are flags (`--ttl`, `--mailbox-bytes`, `--mailbox-blobs`,
`--total-bytes`, `--rooms`, `--members`, `--queue`); the defaults keep 14
days of mail, 8 MiB per mailbox, 512 MiB in all.

## Host the app (on another host than the relay)

Code and relay live apart, so taking over the relay cannot change the code.
Any static host with HTTPS. Serve with these headers:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self'; connect-src 'self' blob: wss: https://fcm.googleapis.com https://*.push.services.mozilla.com https://web.push.apple.com https://*.notify.windows.com; manifest-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
Cache-Control: no-cache                 (at least for sw.js, manifest.json, manifest.sig)
Content-Type: application/wasm          (for .wasm)
Referrer-Policy: no-referrer
```

`config.json` (in the release) says which relay new invites use and which
STUN/TURN servers WebRTC may use:

```json
{ "relay": "wss://relay.example.org", "ice": ["stun:stun.example.org:3478"] }
```

With no ICE servers, phones connect directly only on the same network;
elsewhere messages go through the mailbox (still end to end encrypted). A
TURN URI is `turn:user:password@turn.example.org:3478`.

## Cut a signed release

Releases are a chain, signed by a **committee of the owner's devices** -
say three keys, any two of which must sign:

```sh
# once, on each signing device (keep each key there, offline):
python3 tools/release.py keygen --key ~/offline/release.pem          # prints its public key

# the first release names the committee, and two of its keys sign it:
python3 tools/release.py build --version 1 --committee <pub1>,<pub2>,<pub3> --quorum 2 \
    --key release-1.pem --key release-2.pem --wasm build/wasm --out dist --config config.json

# each later one links to the one before; members sign where their keys are:
python3 tools/release.py build --version 2 --chain old/chain.json --key release-1.pem --wasm build/wasm --out dist
python3 tools/release.py sign --key release-3.pem --site dist        # on the third device
python3 tools/release.py verify --site dist
```

`build` writes the first committee and the chain's checks (`web/release.js`)
into `sw.js`, hashes every file into `manifest.json`, and adds a record to
`chain.json`: the version, the hashes of `manifest.json` and `sw.js`, the
hash of the record before, and the committee that signs the next
(`--committee` hands it over). Each signature is an engine Observation
signature, so two releases signed as one version are evidence the engine
keeps. It prints the **bundle fingerprint**, which About shows with the
version and the chain head. Upload `dist/`; publish the fingerprint
somewhere other than the static host.

A phone keeps the head of the chain it runs. It takes a release only if it
links to that head, has a higher version and enough signatures of the
committee the head names, and every file (and `sw.js`) is the one named;
versions it skipped are checked link by link. Anything else is refused, the
evidence kept, and it stays where it is. A release taken waits: "Update
ready", run from the next time p-chat is opened. Phones tell their
contacts which release they run, and a phone behind takes a newer one from
a contact's phone over the live link - checked all the same. Never commit
a release key (`.gitignore` refuses `*.pem`).

## Make an invite

1. Open p-chat, give your name, **Invite** → **A new contact**.
2. Let your friend scan the QR with their phone's camera (or send the link).
3. Tell them the six words separately: say them, or another channel - never
   with the link.
4. They open the link, type their name, **what they want to call you**, and
   the words, and press **Pair**. Both phones show the same four emoji;
   compare them by voice if you want to be sure.

Names are each person's own: you introduce yourself with a name, but the
person you invite chooses what to call you on their phone (and you can
rename anyone, under **Keys**). Nobody else sees what you call them.

**Another device for the same friend** (a new phone): Invite → **Another
device of…**, pick them. Their existing device must be open to approve it.
**Reusable device key**: the same, valid until you cancel it. **Remove a
device**: open the conversation → **Keys** → **Remove**; it is told, and the
conversation moves on to a new key without it.

## A bot

A bot is a native p-chat device on a server: its own key, paired like a
contact, revoked like any device. `sgchat_echo` is the one shipped: in a
two-sided chat it says back what it is told; in a group, only what follows
`/echo `.

```sh
./build/sgchat_echo ~/echo-bot wss://relay.example.org --pair '<invite link>' '<six words>'
./build/sgchat_echo ~/echo-bot wss://relay.example.org      # afterwards: the same device, from its folder
```

Invite it as **A new contact**. It has no live link, so it takes mail and
answers through the mailbox: set **Devices → Mailbox too** for it, or its
answers wait on the bot until you do. Its folder holds its key and what it
knows, readable by its user only; to revoke it, take it out of a group (the
others' majority, without its say) or forget the contact. `bot/Host.hpp`
is what any other bot is built on: the App, its keys, the relay, over a
WebSocket client of its own.

## Layout

```
world/            the DSL: the book (chat.sg); a conversation, a device, a call, a game, a board (templates the edits compile)
include/chat/     what each part is; src/chat/ what it does
  Wire Crypto Identity Seal Pairing Message Ratchet Trust Signal Window World App
  Media Group Recovery Push Call Swarm Game Board
src/web/          the Wasm bindings (embind) and the engine's WebRTC as the live path
web/              index.html ui.js session.js store.js crypto.js media.js push.js call.js live.js release.js
                  direct.js (pairing in person) carry.js (contacts carrying) sw.js style.css
                  fonts/ emoji/ stickers/ vendor/ app.webmanifest icons
bot/              native devices: WebSocket client, relay frames, a host that keeps its keys; the echo bot
relay/relay.py    the relay; relay/worker/ the same on Cloudflare (Worker + Durable Object)
tools/            make_vectors.cpp, release.py, icons.py
tests/            native checks, vectors, relay, Node, browser, end to end
docs/protocol.md  the protocol, byte for byte
data/             the word list (BIP-39 English) and the 256 fingerprint emoji
```

Third-party, kept as they came: QR Code Generator by Kazuhiko Arase (MIT,
`web/vendor/qrcode.mjs`); jsQR 1.4.0 by Cosmo Wolfe (Apache 2.0,
`web/vendor/jsQR.js`, licence beside it), to read a code where the browser
has no barcode reader of its own (Safari); fonts Jost and Righteous (SIL OFL) and Yellowtail
(Apache 2.0), with their licences in `web/fonts/`; the 256 fingerprint
pictures are Twemoji (CC-BY 4.0, `web/emoji/`), shipped so both phones of a
pairing draw the same four pictures whatever their emoji font.

Messages and names can be in any language and script: text takes its
direction from what is written (right-to-left too), and every script and
emoji falls back to the phone's own fonts. Names are bounded by bytes
(64 of UTF-8), never cut inside a character. The interface itself is in
English. Monocypher 4.0.3 comes
through the engine, hash-checked.
