// The host's loop around the App (the Wasm world and its machinery): it
// fills what the App asks with this device's WebCrypto keys, keeps what
// changed before anything goes out, carries envelopes live (the engine's
// WebRtcTransport) or through the relay's mailbox, opens what arrives, and
// tells the UI. Wall time is used here only: for retries, for how long a
// gap or an acknowledgement is waited for, for which day's mailbox to use.
// None of it is the world's time.
import * as c from './crypto.js';
const forgetAllHere = () => c.forgetAll();
import * as store from './store.js';
import * as push from './push.js';
import { Calls } from './call.js';
import './release.js';  // the release chain's checks (globalThis.pchatRelease)
import { Media } from './media.js';
import { Carry } from './carry.js';
import { PairLink, FRAME, inPersonLink, readInPerson, answerCode, readAnswer, base64url } from './direct.js';

const TTL_MS = 14 * 86400e3;
const ACK_WAIT_MS = 30e3;
const CONTROL_KEEP_MS = 5 * 60e3;
const SIGNAL_KEEP_MS = 10 * 60e3;
const CONTROL_AGAIN_MS = 10e3;
const FETCH_MS = 4000;
const SWEEP_MS = 5000;
// A message's content key, kept with it (unless the chat has no recovery):
// what a recovered device can be given.
const keyOf = (n) => (n.key?.length ? { key: n.key } : {});
const PAIR_POLL_MS = 2000;
// A signal given to contacts to pass on is given again this often, this long.
const CARRY_AGAIN_MS = 5000, CARRY_KEEP_MS = 120e3;
// The link two phones made to pair in person: closed once their own link is
// up (a while after), or after this long.
const PAIR_LINK_MS = 10 * 60e3;

const OP = { put: 1, fetch: 2, del: 3, pairPost: 16, pairFetch: 17, pairReusable: 18, pairCancel: 19, pairDone: 20,
  join: 32, signal: 33, leave: 34, pushForward: 49 };
// One push per conversation and recipient device in this long, at most.
const PING_GAP_MS = 20e3;
export const STATUS = { ok: 0, refused: 1, burned: 2, busy: 3, quota: 4, missing: 5 };

const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const u16 = (n) => new Uint8Array([n >> 8, n & 255]);
const u32 = (n) => new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const read32 = (b, at) => ((b[at] << 24) >>> 0) + (b[at + 1] << 16) + (b[at + 2] << 8) + b[at + 3];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// One relay: binary frames, a request and its answer by id, signals pushed.
export class Relay {
  constructor(url, onSignal, onOpen) {
    if (!/^wss:\/\//.test(url) && !/^ws:\/\/(127\.0\.0\.1|localhost):/.test(url)) throw new Error('A relay address starts with wss://');
    Object.assign(this, { url, onSignal, onOpen, next: 1, waiting: new Map(), backoff: 1000, closed: false });
    this.open();
  }
  open() {
    if (this.closed) return;
    const ws = (this.ws = new WebSocket(this.url));
    ws.binaryType = 'arraybuffer';
    ws.onopen = () => { this.backoff = 1000; this.onOpen?.(); };
    ws.onmessage = (e) => {
      if (!(e.data instanceof ArrayBuffer)) return;
      const d = new Uint8Array(e.data);
      if (d.length < 6 || d[0] !== 1) return;
      if (d[1] === 0x40) {
        if (d.length < 42) return;
        const room = d.slice(6, 38), n = read32(d, 38);
        if (42 + n === d.length) this.onSignal?.(room, d.slice(42));
        return;
      }
      const id = read32(d, 2), w = this.waiting.get(id);
      if (!w) return;
      this.waiting.delete(id);
      clearTimeout(w.timer);
      w.resolve({ status: d[6], body: d.slice(7) });
    };
    ws.onclose = () => {
      for (const w of this.waiting.values()) { clearTimeout(w.timer); w.reject(new Error('Lost the connection to the relay. Trying again…')); }
      this.waiting.clear();
      if (!this.closed) setTimeout(() => this.open(), this.backoff);
      this.backoff = Math.min(this.backoff * 2, 30000);
    };
  }
  get up() { return this.ws?.readyState === WebSocket.OPEN; }
  call(op, body = new Uint8Array(0)) {
    if (!this.up) return Promise.reject(new Error('Can\'t reach the relay right now. Trying again…'));
    const id = this.next++ >>> 0;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.waiting.delete(id); reject(new Error('The relay did not answer in time. Try again.')); }, 20000);
      this.waiting.set(id, { resolve, reject, timer });
      this.ws.send(cat(new Uint8Array([1, op]), u32(id), body));
    });
  }
  put(envelope) { return this.call(OP.put, envelope); }
  async fetch(ids) {
    const out = [];
    for (let i = 0; i < ids.length; i += 1024) {
      const part = ids.slice(i, i + 1024);
      const r = await this.call(OP.fetch, cat(u16(part.length), ...part));
      if (r.status !== STATUS.ok) continue;
      const b = r.body;
      let at = 2;
      for (let n = (b[0] << 8) | b[1]; n > 0; n--) {
        const mailbox = b.slice(at, at + 32), handle = b.slice(at + 32, at + 48), size = read32(b, at + 48);
        out.push({ mailbox, handle, envelope: b.slice(at + 52, at + 52 + size) });
        at += 52 + size;
      }
    }
    return out;
  }
  del(mailbox, handles) { return this.call(OP.del, cat(mailbox, u16(handles.length), ...handles)); }
  pairPost(token, box) { return this.call(OP.pairPost, cat(token, box)); }
  async pairFetch(token) {
    const r = await this.call(OP.pairFetch, token);
    const out = [];
    let at = 2;
    for (let n = (r.body[0] << 8) | r.body[1]; n > 0; n--) {
      const size = read32(r.body, at);
      out.push(r.body.slice(at + 4, at + 4 + size));
      at += 4 + size;
    }
    return out;
  }
  pairReusable(token, cancelHash) { return this.call(OP.pairReusable, cat(token, cancelHash)); }
  pairCancel(token, key) { return this.call(OP.pairCancel, cat(token, key)); }
  pairDone(token) { return this.call(OP.pairDone, token); }
  join(room, label) { return this.call(OP.join, cat(room, label)); }
  signal(room, to, box) { return this.call(OP.signal, cat(room, to, u32(box.length), box)); }
  close() { this.closed = true; this.ws?.close(); }
}

export class Session {
  constructor(chat, ui) {
    Object.assign(this, { chat, ui, app: null, dev: null, relays: new Map(), conv: new Map(), busy: false, again: false,
      media: null, timers: [], seenPosts: new Set(), config: { ice: [] }, sentLive: 0, sentMailbox: 0, queued: 0, signals: [], joined: new Set(), pinged: new Map(), pushes: [], statuses: new Map(), relinked: new Map(), opened: [], posts: new Set() });
  }

  // ---- starting ----
  async boot() {
    if (!(await c.supported())) return this.ui.screen('unsupported');
    this.media = new Media(this);
    this.calls = new Calls(this);
    this.carrier = new Carry({
      send: (peer, frame) => this.app.sendCarry(peer, frame),
      peers: () => (this.app ? this.app.livePeers() : []),
      rooms: () => this.allRooms(),
      mailboxes: () => this.allMailboxes(),
      signalIn: (room, box) => { this.app.signalIn(room, box); this.pump(); },
      open: async (env) => (await this.open(env)).status,
      handle: (env) => this.chat.blake2b(16, new Uint8Array(0), env),
      helping: () => this.helping(),
      keep: { list: () => store.held(), put: (h) => store.saveHeld(h.key, h), drop: (key) => store.dropHeld(key) },
      now: () => Date.now(),
    });
    try { this.config = await (await fetch('config.json')).json(); } catch { /* none: no STUN/TURN */ }
    this.persisted = await c.persist();
    // Chats this device can no longer open - its key gone, or not given back
    // by the browser - mean a device that was paired and is no more.
    try { this.dev = await c.device(false); } catch { this.dev = null; }
    let records = [];
    try {
      this.profile = await store.profile();
      records = await store.records();
    } catch {
      return this.ui.screen('unrecognized', {});
    }
    if (!this.dev && records.length) return this.ui.screen('unrecognized', {});
    if (this.dev) await this.startApp(records);
    // Each round on its own clock; what one of them throws is said, with its
    // name, and the next round tries again.
    const every = (name, ms, f) => this.timers.push(setInterval(() => Promise.resolve().then(f).catch((e) =>
      console.error('p-chat round failed:', name, e?.name, e?.message, e?.stack)), ms));
    every('pump', 1000, () => this.pump());
    every('fetch', FETCH_MS, () => this.fetchAll());
    every('pairing', PAIR_POLL_MS, () => this.pollPairing());
    every('signals', 1500, () => this.signals.length && this.sendSignals());
    every('media', 1200, () => this.media.tick());
    every('carry', 1000, async () => { if (this.app) { await this.carrier.tick(); this.checkPairing(); this.watchReach(); } });
    every('sweep', SWEEP_MS, () => this.sweep());
    // What the service worker says of releases: one waiting, one refused, a fork.
    navigator.serviceWorker?.addEventListener('message', (e) => this.workerSaid(e.data));
    every('release', 60000, () => this.announceRelease());
    every('release-files', 1500, () => this.askReleaseAgain());
    setTimeout(() => this.announceRelease().catch(() => {}), 3000);
    document.addEventListener?.('visibilitychange', () => document.visibilityState === 'visible' && this.fetchAll());
    return true;
  }
  async startApp(records) {
    // A device introduces itself by no name: each side names the other, on its own phone.
    this.app = new this.chat.App(c.hex(this.dev.signPub), c.hex(this.dev.agreePub), '');
    for (const r of records) {
      try {
        this.app.load(r.bytes);
        this.conv.set(r.conv, r.meta || {});
      } catch (e) {
        this.ui.warn('A kept conversation could not be read: ' + e.message);
      }
    }
    for (const id of this.conv.keys())
      for (const m of await store.messages(id))
        try { this.app.replay(id, m.obs, m.mine ? m.body : new Uint8Array(0), m.time); } catch { /* a message of a past committee */ }
    for (const id of this.conv.keys()) this.tellRelay(id);
    this.app.live(this.config.ice || [], false);
    this.app.start();
    for (const id of this.conv.keys()) this.relayOf(id);
    await this.pump();
    this.fetchAll();
  }
  // The device key is made once, however many ask for it at the same moment.
  ensureDevice() {
    if (this.app) return Promise.resolve();
    if (!this.making) this.making = (async () => {
      this.dev = await c.device(true);
      await store.setProfile(this.profile);
      await this.startApp([]);
    })().finally(() => { this.making = null; });
    return this.making;
  }
  // Whether this device uses relays at all (Settings): with none, it reaches
  // its contacts only directly and through contacts that carry for them.
  relayOn() { return !this.profile?.relayOff; }
  helping() { return !this.profile?.carryOff; }
  async setRelay(on) {
    this.profile = { ...(await store.profile()), relayOff: !on };
    await store.setProfile(this.profile);
    if (!on) {
      for (const r of this.relays.values()) r.close();
      this.relays.clear();
      this.joined.clear();
    } else {
      for (const id of this.conv.keys()) this.relayOf(id);
    }
  }
  async setHelping(on) {
    this.profile = { ...(await store.profile()), carryOff: !on };
    await store.setProfile(this.profile);
  }
  relay(url) {
    if (!url || !this.relayOn()) return null;
    if (!this.relays.has(url)) {
      const r = new Relay(url, (room, box) => { this.app?.signalIn(room, box); this.pump(); }, () => {
        for (const k of [...this.joined]) if (this.relayUrlOf(k.split(':')[0]) === url) this.joined.delete(k);
        this.joinRooms(url);
        this.fetchAll();
        this.flushOutbox();
      });
      this.relays.set(url, r);
    }
    return this.relays.get(url);
  }
  // A chat's relay: the one it was made with, or - made with none (paired in
  // person while no relay was used) - this p-chat's own, so its two phones
  // can always find each other again. Both use the same; its rooms and
  // mailboxes come from the chat's secret, whichever relay carries them.
  relayUrlOf(conv) {
    return this.conv.get(conv)?.relay || (this.relayOn() ? this.profile?.relay || this.config.relay || '' : '');
  }
  relayOf(conv) {
    const url = this.relayUrlOf(conv);
    return url ? this.relay(url) : null;
  }
  // A call only where a relay can always bring a dropped link back: one that
  // could not would leave the chat with no way to reach the other phone.
  canCall(conv) { return !!this.relayOf(conv); }
  // A link is made again only where it can be made: through the chat's relay,
  // up now, or a contact linked here to carry the signals. Otherwise a link
  // that seems quiet is left as it is - restarted, it could never come back.
  canRelink(conv, peer) {
    if (conv && this.relayOf(conv)?.up) return true;
    return this.app.livePeers().some((p) => p !== peer);
  }
  // Whether what is said now reaches them: through a relay (it keeps what
  // waits), or over a live link to every other device of the chat. Neither:
  // nothing is sent. Said again to the screen whenever it changes.
  canSend(conv) {
    if (this.relayOf(conv)) return true;
    const info = this.app.info(conv);
    const others = info.members.filter((m) => !m.self);
    return others.length > 0 && others.every((m) => this.app.liveWith(m.peer));
  }
  // How the other devices are reached now, in a word: linked (directly), the
  // relay, or not at all.
  reachedBy(conv) {
    const info = this.app.info(conv);
    const others = info.members.filter((m) => !m.self);
    if (others.length && others.every((m) => this.app.liveWith(m.peer))) return 'linked';
    return this.relayOf(conv)?.up ? 'relay' : 'none';
  }
  watchReach() {
    this.reach ??= new Map();
    for (const id of this.app.conversations()) {
      const now = this.canSend(id) + ':' + this.reachedBy(id);
      if (this.reach.has(id) && this.reach.get(id) !== now) this.ui.changed(id);
      this.reach.set(id, now);
    }
  }
  async joinRooms(url) {
    if (!this.relay(url)) return;
    for (const [id, meta] of this.conv) {
      if (this.relayUrlOf(id) !== url || this.app.info(id).removed) continue;
      // Every room of a secret still kept: a device that missed a rekey is in one before.
      for (const { room, label } of this.app.roomsOf(id)) {
        try {
          const r = await this.relay(url).join(room, label);
          if (r.status === STATUS.ok) this.joined.add(id + ':' + c.hex(room));
        } catch { /* rejoined on the next open */ }
      }
    }
  }
  // Where this device can be reached, and its mailboxes: every conversation's
  // (a channel's posts stay at its relay).
  allRooms() {
    const out = [];
    for (const id of this.app.conversations()) {
      const info = this.app.info(id);
      if (info.removed) continue;
      for (const r of this.app.roomsOf(id)) out.push(r);
    }
    return out;
  }
  allMailboxes() {
    const out = [];
    for (const id of this.app.conversations()) {
      const info = this.app.info(id);
      if (info.removed || info.kind === 2) continue;
      out.push(...this.app.mailboxesOf(id));
    }
    return out;
  }
  async sendSignals() {
    const keep = [], now = Date.now();
    for (const s of this.signals) {
      const relay = this.relayOf(s.conversation);
      let taken = false;
      if (relay?.up) {
        if (!this.joined.has(s.conversation + ':' + c.hex(s.room))) await this.joinRooms(relay.url);
        // Kept until the other end is in the room to take it: a restart said
        // while it was away is what lets the two sessions meet again.
        const r = await relay.signal(s.room, s.label, s.box).catch(() => null);
        taken = r?.status === STATUS.ok;
      }
      // No relay took it: the phones linked here pass it on (and the link
      // made to pair in person, while it is up), now and again for a while.
      if (!taken && now - (s.carried || 0) >= CARRY_AGAIN_MS && now - s.made < CARRY_KEEP_MS) {
        s.carried = now;
        this.carrier.signal(s);
        const p = this.pairing;
        if (p?.link.up && p.conv === s.conversation) p.link.send(FRAME.signal, cat(s.room, s.box));
      }
      if (!taken && now < s.until) keep.push(s);
    }
    this.signals = keep;
  }

  // ---- the pump: ask, keep, carry, tell ----
  async pump() {
    if (!this.app) return;
    if (this.busy) { this.again = true; return; }
    this.busy = true;
    try {
      for (let round = 0; round < 32; round++) {
        this.again = false;
        this.app.pump(Date.now());
        let any = false;
        for (const s of this.app.takeStarts()) {
          any = true;
          const ss = await c.derive(this.dev.agree, s.agree);
          if (s.second) {
            const f = await c.ratchetKey();
            const fs = await c.derive(f.key, s.agree);
            this.app.started(s.conversation, s.peer, ss, f.pub, fs);
            fs.fill(0);
          } else this.app.started(s.conversation, s.peer, ss, null, null);
          ss.fill(0);  // a shared secret is wiped once Wasm has its copy
        }
        for (const s of this.app.takeSigns()) {
          any = true;
          this.app.signed(s.id, await c.sign(this.dev.sign, s.statement));
        }
        // What changed is kept before anything goes out: a vote's lock, a
        // ratchet's step, a sequence used.
        for (const id of this.app.takeDirty()) {
          if (!this.conv.has(id)) continue;
          const meta = { ...this.conv.get(id), name: this.app.info(id).name };
          this.conv.set(id, meta);
          this.tellRelay(id);
          await store.saveRecord(id, this.app.save(id), meta);
        }
        for (const n of this.app.takeNotices()) { any = true; await this.notice(n); }
        for (const o of this.app.takeOutgoing()) { any = true; await this.carry(o); }
        for (const env of this.app.takeLive()) { any = true; await this.open(env); }
        for (const b of this.app.takeBlobs()) { any = true; await this.media.frame(b.peer, b.frame); }
        const heard = this.app.takeMedia();
        if (heard.length) this.calls.media(heard);
        for (const r of this.app.takeRelease()) await this.releaseFrame(r.peer, r.frame);
        for (const f of this.app.takeCarry()) { any = true; await this.carrier.frame(f.peer, f.frame); }
        await this.retryUnacked();
        if (!any && !this.again) break;
      }
      if (this.profile?.forgetting) setTimeout(() => this.maybeForgotten().catch(() => {}), 0);
    } catch (e) {
      this.ui.warn(e?.message || String(e));
      console.error('pump', e);
    } finally {
      this.busy = false;
    }
  }

  // A message said while the chat's messages disappear goes when its time is
  // over; one said before stays.
  expiry(conv, time) {
    const d = this.conv.has(conv) || this.app.conversations().includes(conv) ? this.info(conv).disappear : 0;
    return d ? { expires: time + d * 1000 } : {};
  }
  async notice(n) {
    const conv = n.conversation;
    // The self conversation (linked devices) is not a chat: nothing of it is shown.
    if (conv && conv === this.selfConv() && (n.kind === 'sent' || n.kind === 'message')) {
      if (n.kind === 'message') this.heard(n.peer);
      await store.saveMessage(conv, { peer: n.peer, seq: n.sequence, obs: n.data, body: n.kind === 'sent' ? n.body : new Uint8Array(0),
        time: n.time, type: n.type, mine: n.kind === 'sent', hidden: true });
      return;
    }
    switch (n.kind) {
      case 'sent': case 'resent': case 'message': {
        if (n.kind === 'resent') break;
        // Said by this person's other (linked) device: theirs is this person's own.
        if (n.kind === 'message' && this.isLinked(n.peer)) { this.heard(n.peer); n = { ...n, kind: 'sent', linkedFrom: true }; }
        if (n.type === 'file') {
          await store.saveMessage(conv, { peer: n.peer, seq: n.sequence, obs: n.data, body: n.body, time: n.time, type: 'file',
            mine: n.kind === 'sent', status: n.kind === 'sent' ? 'sent' : 'received', ...keyOf(n), ...this.expiry(conv, n.time) });
          await this.media.received(conv, n.peer, n.body, n.kind === 'sent' && !n.linkedFrom);
          this.ui.changed(conv);
          break;
        }
        if (n.type === 'release') {
          // Kept like every message (its observation is the history's, and a
          // reopened app replays it); what it says is for the release chain.
          await store.saveMessage(conv, { peer: n.peer, seq: n.sequence, obs: n.data, body: n.kind === 'sent' ? n.body : new Uint8Array(0),
            time: n.time, type: 'release', mine: n.kind === 'sent', hidden: true });
          if (n.kind === 'message') await this.releaseSaid(conv, n.peer, n.body);
          break;
        }
        if (n.type === 'stroke') {
          // A board's stroke: kept with its body on every side, drawn on the board, not in the chat.
          await store.saveMessage(conv, { peer: n.peer, seq: n.sequence, obs: n.data, body: n.body, time: n.time, type: 'stroke',
            mine: n.kind === 'sent', hidden: true, ...keyOf(n), ...this.expiry(conv, n.time) });
          this.ui.stroke(conv, n.body);
          break;
        }
        if (n.type !== 'text' && n.type !== 'device_revoked') {
          // Control messages are kept for history and integrity, not shown.
          await store.saveMessage(conv, { peer: n.peer, seq: n.sequence, obs: n.data, body: n.kind === 'sent' ? n.body : new Uint8Array(0),
            time: n.time, type: n.type, mine: n.kind === 'sent', hidden: true });
          break;
        }
        await store.saveMessage(conv, { peer: n.peer, seq: n.sequence, obs: n.data, body: n.body, time: n.time, type: n.type,
          mine: n.kind === 'sent', status: n.kind === 'sent' ? 'sent' : 'received', ...keyOf(n), ...this.expiry(conv, n.time) });
        this.ui.changed(conv);
        break;
      }
      case 'history_item': {
        // Given after a recovery, checked against the agreed history. What
        // the lost device said was said by this side.
        const info = this.info(conv);
        const mine = n.peer === this.app.peer() || this.isLinked(n.peer) ||
          (info.kind === 0 && !info.members.some((m) => m.side !== info.side && m.peer === n.peer));
        const shown = n.type === 'text' || n.type === 'file';
        await store.saveMessage(conv, { peer: n.peer, seq: n.sequence, obs: n.data, body: shown ? n.body : new Uint8Array(0), time: n.time,
          type: n.type, mine, status: mine ? 'delivered' : 'received', hidden: !shown, history: true, ...keyOf(n) });
        if (n.type === 'file') await this.media.received(conv, n.peer, n.body, false);
        this.historyCount = (this.historyCount || 0) + 1;
        this.ui.changed(conv);
        break;
      }
      case 'recovered': await this.shareHistory(conv, n.peer, n.sequence, n.time); this.ui.changed(conv); break;
      case 'recovery_started': this.ui.warn('Asked. The new device takes the old one\'s place in a day, unless the old one refuses.'); this.ui.changed(conv); break;
      case 'recovery_approve': case 'recovery_of_me': this.ui.alert(conv, n.kind); break;
      case 'recovery_refused': this.ui.warn('The old device refused: it is not lost. Nothing changed.'); this.ui.changed(conv); break;
      case 'device_replaced': {
        const url = this.relayUrlOf(conv);
        if (url) this.joinRooms(url);
        this.ui.changed(conv);
        break;
      }
      case 'acked':
        await this.status({ conversation: conv, sequence: n.sequence }, 'delivered');
        for (const o of await store.outbox()) if (o.conv === conv && o.seq === n.sequence && o.peer === n.peer) await store.dropOutbox(o.id);
        this.ui.changed(conv);
        break;
      case 'retire_key': await c.forgetRatchetKey(n.text); break;
      case 'equivocation':
        await store.saveEvidence(conv, { peer: n.peer, seq: n.sequence, first: n.data, second: n.body });
        this.ui.alert(conv, 'equivocation');
        break;
      case 'removed': this.ui.alert(conv, 'removed'); break;
      case 'paired': this.sharePush(conv); this.ui.paired(conv, n); break;
      case 'push': await store.savePushTo(n.peer, n.body); break;
      case 'call': this.ui.ringing(conv, n.text, n.peer); break;
      case 'call_joined': case 'call_left': this.ui.changed(conv); break;
      case 'call_ended': this.calls.ended(n.text); this.ui.callEnded(conv, n.text); break;
      case 'game': this.ui.gameAsked(conv, n.text, n.peer); break;
      case 'game_on': this.ui.gameOn(conv, n.text); break;
      case 'game_over': this.ui.gameOver(conv, n.text); break;
      case 'invite_failed': this.ui.alert(conv, 'invite_failed'); break;
      case 'history_differs': this.ui.alert(conv, 'history_differs'); break;
      case 'group': case 'channel':
        if (!this.conv.has(conv)) {
          // Joined through a contact's conversation, on that contact's relay.
          const via = n.peer ? [...this.conv.entries()].find(([id]) => this.info(id).kind === 0 &&
            this.info(id).members.some((m) => m.peer === n.peer)) : null;
          this.conv.set(conv, { relay: via?.[1].relay || this.profile.relay || this.config.relay, name: n.text });
          await store.saveRecord(conv, this.app.save(conv), this.conv.get(conv));
          await this.joinRooms(this.conv.get(conv).relay);
        }
        this.sharePush(conv);
        this.ui.changed(null);
        break;
      case 'rekeyed': case 'device_added': case 'revoked': {
        const url = this.relayUrlOf(conv);
        if (url) this.joinRooms(url);
        this.ui.changed(conv);
        break;
      }
      case 'removed_contact': this.ui.changed(conv); break;
      // Linked devices (protocol 11).
      case 'linked': this.ui.changed(null); break;
      case 'linked_chat': {
        // A chat given by this person's other device: on its relay.
        this.conv.set(conv, { relay: n.text || this.profile?.relay || this.config.relay || '', name: n.type });
        await store.saveRecord(conv, this.app.save(conv), this.conv.get(conv));
        this.tellRelay(conv);
        const url = this.relayUrlOf(conv);
        if (url) await this.joinRooms(url);
        this.sharePush(conv);
        this.ui.changed(null);
        break;
      }
      case 'link_wants': await this.giveHistory(conv, n.peer, n.text); break;
      case 'renamed': this.ui.changed(conv); break;
      case 'unlinked': {
        if (n.text === 'forget') {
          this.profile = { ...(await store.profile()), forgetting: true };
          await store.setProfile(this.profile);
        }
        this.ui.unlinked?.(n.text);
        await this.maybeForgotten();
        break;
      }
      case 'unlinked_peer': this.ui.warn('Your other device was unlinked. Its chats stay with it; yours stay here.'); this.ui.changed(null); break;
      case 'split_asked': this.ui.splitAsked?.(); break;
      case 'split_refused': this.ui.warn('Your other device did not agree to that split. Nothing changed.'); this.ui.changed(null); break;
      case 'left': {
        // A chat this device left when it was unlinked: kept to read, or gone.
        const info = this.app.conversations().includes(conv) ? this.info(conv) : null;
        if (info && !info.left) {
          try { this.app.removeContact(conv); } catch { /* gone */ }
          this.conv.delete(conv);
          await store.forget(conv);
        }
        this.ui.changed(null);
        await this.maybeForgotten();
        break;
      }
      case 'warning': this.ui.warn(n.text); break;
      default: break;
    }
  }

  async carry(o) {
    if (o.kind === 'envelope') {
      const e = await c.ephemeral(o.agree);
      const env = this.chat.envelope(o.version, o.mailbox, this.chat.seal(o.purpose, o.agree, o.plain, e.pub, e.shared));
      e.shared.fill(0);
      // A pairing's accept, while the two phones are joined to pair in person: over that link.
      if (o.version === 16 && this.pairing?.role === 'owner' && this.pairing.link.send(FRAME.accept, env)) return;
      const relay = o.conversation ? this.relayOf(o.conversation) : null;
      const target = relay || (this.pendingReplyRelay && this.relay(this.pendingReplyRelay));
      // A control frame (an epoch's vote, a handoff's step) has no
      // acknowledgement: it is kept a while and sent again - it is
      // idempotent, and one lost would stall what it belongs to.
      const control = o.purpose === 'message' && o.sequence === 0;
      const expires = o.sequence > 0 && o.conversation ? this.expiry(o.conversation, Date.now()).expires || 0 : 0;
      const item = { conv: o.conversation, peer: o.peer, seq: o.sequence, env, mailbox: o.mailbox_ok, live: 0,
        control, until: control ? Date.now() + CONTROL_KEEP_MS : 0, expires, ping: !!o.ping, made: Date.now() };
      // A chat whose messages disappear: a copy left at the relay is deleted
      // there when the message's time is over.
      if (expires && o.mailbox_ok && target)
        await store.saveCopy(c.hex(c.random(8)), { conv: o.conversation, url: target.url, mailbox: env.slice(1, 33),
          handle: this.chat.blake2b(16, new Uint8Array(0), env), made: Date.now(), expires });
      if (o.live && this.app.sendLive(o.peer, env)) {
        this.sentLive++;
        // Sent live: kept until acknowledged, then dropped; else, after a
        // while, sent live again, or left in the mailbox if the recipient
        // takes mail (it drops the twin).
        // A link can say it is up a moment after the other end has gone: for
        // a device that takes mail, a copy waits in its mailbox too (it
        // keeps the first it opens and drops the twin).
        let relayed = false;
        if (o.mailbox_ok && target) {
          const r = await target.put(env).catch(() => null);
          relayed = r?.status === STATUS.ok;
        }
        if (o.sequence > 0 || control) await store.saveOutbox(c.hex(c.random(8)), { ...item, live: Date.now(), relayed });
        await this.status(o, 'sent');
        return;
      }
      const id = c.hex(c.random(8));
      if (o.purpose === 'message' && !o.mailbox_ok) {
        // Live only: the relay keeps nothing. It waits here, sealed, until
        // the recipient is on a live link - which a push may bring.
        this.queued++;
        await store.saveOutbox(id, { ...item, waiting: true });
        await this.status(o, 'queued');
        await this.ping(o);
        return;
      }
      if (!target) {
        if (o.purpose !== 'message') return;
        // No relay: kept here, and given to the contacts linked now to keep
        // for it (sent live the moment there is a link, as ever).
        const held = this.carrier.hold(env, o.peer);
        await store.saveOutbox(id, { ...item, waiting: true, held: held ? Date.now() : 0 });
        await this.status(o, held ? 'mailbox' : 'queued');
        return;
      }
      this.sentMailbox++;
      await store.saveOutbox(id, { ...item, url: target.url });
      await this.putOut(id, target, env, o.sequence > 0);
      await this.status(o, 'mailbox');
      await this.ping(o);
    } else if (o.kind === 'pair') {
      const e = await c.ephemeral(o.agree);
      const box = this.chat.seal(o.purpose, o.agree, o.plain, e.pub, e.shared);
      e.shared.fill(0);
      if (this.pairing?.role === 'new' && this.pairing.link.up) {
        this.ui.pairing(this.pairing.link.send(FRAME.request, box) ? 'asked' : 'offline');
        return;
      }
      const url = this.askRelay || (await store.asking())?.relay;
      const relay = this.relay(url);
      if (!relay) { this.ui.pairing('offline'); return; }
      for (let i = 0; i < 50 && !relay.up; i++) await sleep(100);
      const r = await relay.pairPost(o.token, box).catch(() => ({ status: -1 }));
      this.ui.pairing(r.status === STATUS.ok ? 'asked' : r.status === STATUS.burned ? 'used' : 'offline');
    } else if (o.kind === 'pair_done') {
      for (const inv of await store.invites())
        if (c.hex(inv.token) === c.hex(o.token)) {
          await this.relay(inv.relay)?.pairDone(o.token).catch(() => {});
          if (inv.kind !== 3) await store.dropInvite(c.hex(o.token));
        }
    } else if (o.kind === 'post') {
      // A channel's post: put once at its mailbox, for every reader.
      const relay = this.relayOf(o.conversation);
      for (let tries = 0; relay && tries < 3; tries++) {
        const r = await relay.put(o.box).catch(() => null);
        if (r?.status === STATUS.ok) break;
        await sleep(500);
      }
    } else if (o.kind === 'signal') {
      // Signals are kept and sent again until the relay has someone to give
      // them to: the other end may not be in the room yet.
      this.signals.push({ ...o, made: Date.now(), until: Date.now() + SIGNAL_KEEP_MS });
      // A peer that is gone (its signals never taken) cannot crowd out the
      // others: each keeps its newest 48.
      const mine = this.signals.filter((s) => s.peer === o.peer);
      if (mine.length > 48) this.signals.splice(this.signals.indexOf(mine[0]), 1);
      if (this.signals.length > 512) this.signals.shift();
      await this.sendSignals();
    }
  }
  // A message's status is its most hopeful state across its recipients.
  async status(o, s) {
    if (!o.sequence || !o.conversation) return;
    const rank = { queued: 0, mailbox: 1, sent: 2, delivered: 3 };
    const key = o.conversation + '/' + o.sequence;
    if ((rank[this.statuses.get(key)] ?? -1) >= rank[s]) return;
    this.statuses.set(key, s);
    await store.setStatus(o.conversation, this.app.peer(), o.sequence, s);
    this.ui.changed(o.conversation);
  }
  async putOut(id, relay, env, keepForAck) {
    try {
      const r = await relay.put(env);
      if (r.status === STATUS.ok && !keepForAck) await store.dropOutbox(id);
      if (r.status === STATUS.ok && keepForAck) await store.saveOutbox(id, { ...(await this.outboxItem(id)), relayed: true });
    } catch { /* kept: sent again when the relay is back */ }
  }
  async outboxItem(id) { return (await store.outbox()).find((o) => o.id === id) || {}; }
  async flushOutbox() {
    for (const o of await store.outbox()) {
      if (o.relayed || o.live) continue;
      const relay = o.url ? this.relay(o.url) : this.relayOf(o.conv);
      if (relay?.up) await this.putOut(o.id, relay, o.env, o.seq > 0);
    }
  }
  async retryUnacked() {
    const now = Date.now();
    if (now - (this.lastRetry || 0) < 1500) return;
    this.lastRetry = now;
    for (const o of await store.outbox()) {
      if (o.control) {
        if (now > o.until) { await store.dropOutbox(o.id); continue; }
        if ((o.live && now - o.live > CONTROL_AGAIN_MS) || o.waiting) {
          if (this.app.sendLive(o.peer, o.env)) await store.saveOutbox(o.id, { ...o, waiting: false, live: now });
          else if (o.mailbox && !o.relayed) {
            const relay = this.relayOf(o.conv);
            const r = relay?.up ? await relay.put(o.env).catch(() => null) : null;
            if (r?.status === STATUS.ok) await store.saveOutbox(o.id, { ...o, relayed: true });
            else if (!relay && !o.held && this.carrier.hold(o.env, o.peer)) await store.saveOutbox(o.id, { ...o, held: now });
          }
        }
        continue;
      }
      // Waiting long for a live link that is not there: the link is made again
      // (once in a while), in case its making stalled on the way.
      // No relay: given to contacts to keep as soon as one is linked.
      if (o.waiting && o.mailbox && !o.held && o.conv && !this.relayOf(o.conv) && this.carrier.hold(o.env, o.peer)) {
        o.held = now;
        await store.saveOutbox(o.id, o);
        await this.status({ conversation: o.conv, sequence: o.seq }, 'mailbox');
      }
      if (o.waiting && (!o.mailbox || !this.relayOf(o.conv)) && o.peer && now - (o.made || now) > 10000 && !this.app.liveWith(o.peer) &&
          now - (this.relinked.get(o.peer) || 0) > 15000 && this.canRelink(o.conv, o.peer)) {
        this.relinked.set(o.peer, now);
        this.app.reconnectLive(o.peer);
      }
      // Waiting for a live link: sent the moment there is one - or left in
      // the mailbox, once the recipient has said it takes mail.
      if (o.waiting && !o.mailbox && o.conv && this.conv.has(o.conv) && this.app.takesMail(o.conv, o.peer)) {
        const relay = this.relayOf(o.conv);
        const r = relay?.up ? await relay.put(o.env).catch(() => null) : null;
        if (r?.status === STATUS.ok) await store.saveOutbox(o.id, { ...o, waiting: false, mailbox: true, relayed: true, live: now });
        continue;
      }
      if (o.waiting && this.app.sendLive(o.peer, o.env)) {
        this.sentLive++;
        await store.saveOutbox(o.id, { ...o, waiting: false, live: now });
        await this.status({ conversation: o.conv, sequence: o.seq }, 'sent');
        continue;
      }
      // Sent live and not acknowledged: the link was gone. A push may bring it back.
      if (o.ping && !o.pinged && o.live && now - o.live > ACK_WAIT_MS) {
        o.pinged = true;  // kept by the saves below too
        await store.saveOutbox(o.id, o);
        await this.ping({ ping: true, conversation: o.conv, peer: o.peer, sequence: o.seq });
      }
      if (o.live && !o.relayed && now - o.live > ACK_WAIT_MS) {
        // Sent live and not acknowledged: the link may say it is up and
        // deliver nothing. It is made again (at most twice a minute).
        if (now - (this.relinked.get(o.peer) || 0) > ACK_WAIT_MS && this.canRelink(o.conv, o.peer)) {
          this.relinked.set(o.peer, now);
          this.app.reconnectLive(o.peer);
        }
        if (!o.mailbox) {
          // No mailbox: sent live again once the link is back.
          await store.saveOutbox(o.id, { ...o, waiting: true, live: 0 });
          continue;
        }
        const relay = this.relayOf(o.conv);
        if (relay?.up) {
          const r = await relay.put(o.env).catch(() => null);
          if (r?.status === STATUS.ok) await store.saveOutbox(o.id, { ...o, relayed: true });
        }
      }
      if (o.relayed && now - (o.live || 0) > TTL_MS) await store.dropOutbox(o.id);
    }
  }

  // ---- what arrives ----
  async open(env) {
    let shared;
    try { shared = await c.derive(this.dev.agree, this.chat.ephemeralOf(env)); } catch { return { status: 'refused' }; }
    let r = this.app.open(env, shared, null);
    if (r.status === 'need_turn') {
      const mine = await c.ratchetPrivate(c.hex(r.own), this.dev).catch(() => null);
      if (!mine) return { status: 'refused' };
      const f = await c.ratchetKey();
      const turn = { received: await c.derive(mine, r.dh), fresh: f.pub, sent: await c.derive(f.key, r.dh) };
      r = this.app.open(env, shared, turn);
      turn.received.fill(0);
      turn.sent.fill(0);
      if (r.status !== 'accepted' && r.status !== 'duplicate' && r.status !== 'equivocation') await c.forgetRatchetKey(c.hex(f.pub));
    }
    shared.fill(0);
    if (r.peer && this.isLinked(r.peer)) this.heard(r.peer);
    // What came and what became of it, the last few (for looking, never for deciding).
    this.opened.push([r.status, r.why || '']);
    if (this.opened.length > 64) this.opened.shift();
    await this.pump();
    return r;
  }
  async fetchAll() {
    if (!this.app || this.fetching) return;
    this.fetching = true;
    try {
      for (const [id, meta] of this.conv) {
        const relay = this.relayOf(id);
        if (!relay?.up) continue;
        for (const item of await relay.fetch(this.app.mailboxesOf(id))) {
          if (item.envelope[0] === 18) {
            // A channel's post stays for its other readers: read once here.
            const k = c.hex(item.handle);
            if (this.posts.has(k)) continue;
            this.posts.add(k);
            this.opened.push([this.app.openPost(item.envelope).status, 'post']);
            await this.pump();
            continue;
          }
          const r = await this.open(item.envelope);
          // Opened and kept (or not ours to keep): the blob goes.
          if (r.status !== 'need_turn') await relay.del(item.mailbox, [item.handle]).catch(() => {});
        }
      }
      await this.trackGaps();
    } catch { /* again on the next round */ } finally {
      this.fetching = false;
    }
  }
  // A sequence still missing after the mailbox's life is a message that will not come.
  async trackGaps() {
    const now = Date.now();
    for (const id of this.conv.keys()) {
      const info = this.app.info(id);
      const seen = await store.gaps(id), next = {};
      for (const m of info.members)
        for (const s of m.missing || []) {
          const k = m.peer + ':' + s;
          next[k] = seen[k] || now;
        }
      await store.saveGaps(id, next);
    }
  }
  async missing(conv) {
    const g = await store.gaps(conv), now = Date.now();
    return Object.entries(g).filter(([, t]) => now - t > TTL_MS).map(([k]) => k);
  }

  // ---- optional Web Push (Android): an empty wake-up per mailbox ----
  // ---- releases (v1 §12): the chain this device runs, told to its
  // conversations; a newer one a peer runs, taken from it; forks told ----
  // A question for the service worker. One that is being replaced (the site
  // served a new sw.js) may not answer: asked once more, of the one after it.
  async worker(msg, tries = 2) {
    for (let i = 0; i < tries; i++) {
      // None may ever start (no HTTPS, a certificate not trusted): not waited for.
      const reg = await Promise.race([navigator.serviceWorker?.ready, new Promise((r) => setTimeout(r, 3000))]);
      if (!reg?.active) return null;
      const answer = await new Promise((resolve) => {
        const ch = new MessageChannel();
        const t = setTimeout(() => resolve(null), 20000);
        ch.port1.onmessage = (e) => { clearTimeout(t); resolve(e.data); };
        reg.active.postMessage(msg, [ch.port2]);
      });
      if (answer) return answer;
    }
    return null;
  }
  async releaseStatus() {
    const s = await this.worker({ type: 'status' });
    if (!s?.name) return s;
    try { s.chain = await (await (await caches.open(s.name)).match('chain.json')).json(); } catch { s.chain = null; }
    return s;
  }
  // Every signature of a chain, kept in the engine's Integrity by the
  // committee that signs it: one member's two releases for one version show.
  async keepSignatures(chain) {
    const R = globalThis.pchatRelease;
    for (let i = 0; i < chain.length; i++) {
      const r = chain[i], by = (i ? chain[i - 1] : r).committee;
      const hash = R.unhex(await R.hashOf(r));
      for (const s of r.signatures || []) {
        if (!by.keys.includes(s.key)) continue;
        try {
          if (this.app.releaseSeen(by.keys, by.quorum, r.version, hash, s.key, R.unhex(s.sig)) === 'equivocation') return r;
        } catch { /* a malformed signature: not kept */ }
      }
    }
    return null;
  }
  async announceRelease() {
    if (!this.app) return;
    const s = await this.releaseStatus();
    if (!s?.chain) return;
    this.release = s;
    await this.keepSignatures(s.chain);
    const json = new TextEncoder().encode(JSON.stringify(s.chain));
    for (const id of this.conversations()) {
      const info = this.info(id);
      if (!info.member || info.kind === 2 || info.removed) continue;
      // Said once to each conversation, for each release.
      if (this.conv.get(id)?.release === s.head) continue;
      try { this.app.postRelease(id, 1, json); } catch { continue; }
      this.conv.set(id, { ...(this.conv.get(id) || {}), release: s.head });
      await store.saveRecord(id, this.app.save(id), this.conv.get(id));
    }
    await this.pump();
  }
  // A peer says what it runs (or a fork it saw).
  async releaseSaid(conv, peer, body) {
    const R = globalThis.pchatRelease;
    if (body.length < 6 || body[0] !== 9) return;
    const what = body[1], n = new DataView(body.buffer, body.byteOffset).getUint32(2);
    let data;
    try { data = JSON.parse(new TextDecoder().decode(body.slice(6, 6 + n))); } catch { return; }
    if (what === 2) {
      if (data?.a && data?.b && (await R.fork(data.a, data.b))) this.ui.releaseFork(data.a.version);
      return;
    }
    const chain = data;
    const mine = this.release || (await this.releaseStatus());
    if (!Array.isArray(chain) || !mine?.chain || !chain.length) return;
    const fork = await this.keepSignatures(chain);
    if (fork) return this.forkSeen(fork.version, mine.chain.find((r) => r.version === fork.version), fork);
    // Ours, from the same first release, and newer than what runs or waits here.
    if ((await R.hashOf(chain[0])) !== (await R.hashOf(mine.chain[0]))) return;
    const last = chain[chain.length - 1];
    if (last.version <= Math.max(mine.version || 0, mine.pending || 0)) return;
    if (this.fetchingRelease && Date.now() < this.fetchingRelease.until) return;
    let head;
    try { head = await R.follow({ version: mine.version, hash: mine.head, committee: mine.chain[mine.chain.length - 1].committee }, chain); } catch (e) {
      this.ui.warn('A release a contact runs did not hold: ' + e.message);
      return;
    }
    // Its files, from the peer that runs it, over the live link.
    this.fetchingRelease = { peer, chain, head, manifest: null, files: new Map(), want: [], until: Date.now() + 300000, asked: new Map() };
    this.wantRelease('manifest.json');
  }
  // Asked of the peer that has it, up to 32 at a time; asked again while
  // unanswered (the live link may be coming up, or a frame lost on the way).
  wantRelease(path) {
    const f = this.fetchingRelease;
    if (!f) return;
    f.asked.set(path, Date.now());
    const p = new TextEncoder().encode(path);
    this.app.sendRelease(f.peer, cat(new Uint8Array([9, 1]), new Uint8Array([p.length >> 8, p.length & 255]), p));
  }
  moreRelease() {
    const f = this.fetchingRelease;
    if (!f) return;
    for (const p of f.want) {
      if (f.asked.size >= 32) break;
      if (!f.files.has(p) && !f.asked.has(p)) this.wantRelease(p);
    }
    this.pump();
  }
  askReleaseAgain() {
    const f = this.fetchingRelease;
    if (!f) return;
    if (Date.now() > f.until) { this.fetchingRelease = null; return; }
    for (const [p, at] of f.asked) if (Date.now() - at > 5000) this.wantRelease(p);
    this.pump();
  }
  async releaseFrame(peer, frame) {
    if (frame.length < 4 || frame[0] !== 9) return;
    const kind = frame[1], plen = (frame[2] << 8) | frame[3], path = new TextDecoder().decode(frame.slice(4, 4 + plen));
    if (kind === 1) {
      // A peer asks for a file of the release this device runs: given from the bundle it runs.
      const s = this.release || (await this.releaseStatus());
      if (!s?.name) return;
      const res = await (await caches.open(s.name)).match(path);
      if (!res) return;
      const body = new Uint8Array(await res.arrayBuffer());
      const p = new TextEncoder().encode(path);
      this.app.sendRelease(peer, cat(new Uint8Array([9, 2]), new Uint8Array([p.length >> 8, p.length & 255]), p, u32(body.length), body));
      return;
    }
    const f = this.fetchingRelease;
    if (kind !== 2 || !f || peer !== f.peer || Date.now() > f.until) return;
    const at = 4 + plen, n = new DataView(frame.buffer, frame.byteOffset).getUint32(at);
    const body = frame.slice(at + 4, at + 4 + n);
    if (!f.asked.has(path)) return;
    f.asked.delete(path);
    if (path === 'manifest.json') {
      f.manifest = body;
      try { f.want = Object.keys(JSON.parse(new TextDecoder().decode(body)).files); } catch { this.fetchingRelease = null; return; }
    } else {
      f.files.set(path, body);
    }
    if (f.want.some((p) => !f.files.has(p))) return this.moreRelease();
    // All of it: the worker checks it all again, and keeps it waiting.
    this.fetchingRelease = null;
    const r = await this.worker({ type: 'install', chain: f.chain, manifest: f.manifest, files: [...f.files] });
    if (r?.type === 'installed' && r.version) this.ui.updateReady(r.version, peer);
    else if (r?.type === 'refused') this.ui.warn('A release from a contact was refused: ' + r.why);
  }
  async workerSaid(m) {
    if (!m || typeof m !== 'object') return;
    if (m.type === 'update-ready') this.ui.updateReady(m.version);
    else if (m.type === 'release-fork') await this.forkSeen(m.version, m.a, m.b);
    else if (m.type === 'release-refused') this.ui.releaseRefused?.(m.why);
  }
  // A fork: kept, shown, and told to every conversation.
  async forkSeen(version, a, b) {
    // Both, kept in the engine's Integrity: one member's two signatures for
    // one version are its equivocation.
    if (a) await this.keepSignatures([a]);
    if (b) await this.keepSignatures([b]);
    this.ui.releaseFork(version);
    if (!a || !b || !this.app) return;
    const json = new TextEncoder().encode(JSON.stringify({ a, b }));
    for (const id of this.conversations()) {
      const info = this.info(id);
      if (info.member && info.kind !== 2 && !info.removed) try { this.app.postRelease(id, 2, json); } catch { /* not here */ }
    }
    await this.pump();
  }

  // ---- notifications (protocol 6) ----
  // This device's own VAPID pair and its browser's subscription, said to
  // every conversation it is in. (`sub` is given only by tests: a push
  // service of their own.)
  async enablePush(sub) {
    if (!sub) {
      if (push.needsHomeScreen()) throw new Error('On iPhone, add p-chat to the Home Screen first, and open it from there.');
      if (!('PushManager' in globalThis) || !navigator.serviceWorker) throw new Error('This browser cannot show notifications.');
      if ((await Notification.requestPermission()) !== 'granted') throw new Error('Notifications were not allowed.');
    }
    await this.ensureDevice();
    let v = await store.vapid();
    if (!v) { v = await push.vapidKeys(); await store.setVapid(v); }
    sub = sub || (await push.subscribe(v.public));
    const info = this.chat.pushEncode({ ...sub, vapidPrivate: v.private, vapidPublic: v.public });
    this.profile = { ...(await store.profile()), pushInfo: info };
    await store.setProfile(this.profile);
    for (const id of this.conversations()) this.sharePush(id);
    await this.pump();
  }
  sharePush(conv) {
    if (!this.profile?.pushInfo) return;
    try { this.app.sharePush(conv, this.profile.pushInfo); } catch { /* not a member here (a channel's reader) */ }
  }
  // A message that could not go live: its recipient is woken, if it asked to
  // be. One ping id per message (retries show once); one push a while.
  async ping(o) {
    if (!o.ping || !o.conversation || !o.sequence) return;
    const info = await store.pushTo(o.peer);
    if (!info) return;
    const key = o.peer + '/' + o.conversation, now = Date.now();
    if (now - (this.pinged.get(key) || 0) < PING_GAP_MS) return;
    this.pinged.set(key, now);
    const relay = this.relayOf(o.conversation);
    const forward = relay ? async (endpoint, authorization, body) => {
      const e = new TextEncoder().encode(endpoint), a = new TextEncoder().encode(authorization);
      return (await relay.call(OP.pushForward, cat(u32(e.length), e, u32(a.length), a, u32(body.length), body))).status === STATUS.ok;
    } : async () => false;
    const r = await push.send(this.chat.pushDecode(info), this.chat.pushPayload(o.conversation, this.app.peer(), o.sequence), forward);
    this.pushes.push(r);
    if (r === 'gone') await store.savePushTo(o.peer, null);
  }
  async setSignal(conv, symbol) { await store.setSignal(conv, symbol); }

  // ---- the UI fires and sends ----
  reachable(conv) { if (!this.canSend(conv)) throw new Error('Not linked to them, and no relay: nothing can be sent now.'); }
  async send(conv, text) { this.reachable(conv); this.app.post(conv, text, Date.now()); await this.pump(); }
  async sendFile(conv, file, kind) { this.reachable(conv); await this.media.send(conv, await this.media.prepare(file, kind)); }
  async sendPrepared(conv, prepared) { this.reachable(conv); await this.media.send(conv, prepared); }
  async read(conv) { this.app.read(conv); await this.pump(); }
  async rename(conv, name) { this.app.renameContact(conv, name); await this.pump(); }
  async setDelivery(conv, mailbox) { this.app.setDelivery(conv, mailbox ? 2 : 1); await this.pump(); }
  async enter(conv) { this.app.openConversation(conv); await this.read(conv); }
  async leave(conv) { this.app.closeConversation(conv); }

  // ---- recovery and a chat's lifetime ----
  // An invite for a device to take the place of a lost one: shown as any
  // invite (link and six words); the others approve, the old one may refuse.
  async recoverInvite(conv, lost, scope, since = 0) {
    const relay = this.conv.get(conv)?.relay || this.profile.relay || this.config.relay;
    if (!this.relayOn()) throw new Error('An invite sent as a link needs a relay, and relays are off. Turn relays on in Settings.');
    if (!relay) throw new Error('This p-chat has no relay to make invites with. Set one in About → Settings → Advanced.');
    const inv = this.app.recoveryInvite(relay, conv, lost, scope, since);
    const record = { token: inv.token, invite: inv.invite, code: inv.code, conv, kind: 5, relay, made: Date.now(),
      recovery: { lost, scope, since } };
    await store.saveInvite(c.hex(inv.token), record);
    this.relay(relay);
    return { link: location.origin + location.pathname + '#' + inv.fragment, code: inv.code, token: c.hex(inv.token) };
  }
  async approveRecovery(conv) { this.app.approveRecovery(conv); await this.pump(); }
  async refuseRecovery(conv) { this.app.refuseRecovery(conv); await this.pump(); }
  async setOptions(conv, noRecovery, disappearS) { this.app.setOptions(conv, !!noRecovery, disappearS); await this.pump(); }
  // The new device is given what the chosen scope covers, each message with its key.
  async shareHistory(conv, peer, scope, since) {
    if (scope === 0) return;
    const items = [];
    for (const m of await store.messages(conv))
      if (m.key && !m.expired && (m.type === 'text' || m.type === 'file') && (scope === 2 || m.time >= since)) items.push({ obs: m.obs, key: m.key });
    this.shared = items.length;
    if (items.length) this.app.shareHistory(conv, peer, items);
    await this.pump();
  }
  // Disappearing messages: their words and keys go here, their copies at
  // the relay and in the outbox go too; files with them.
  async sweep() {
    if (!this.app || this.sweeping) return;
    this.sweeping = true;
    try {
      const now = Date.now();
      for (const id of this.conversations()) {
        let gone = false;
        for (const m of await store.messages(id)) {
          if (m.expired || !m.expires || m.expires > now) continue;
          if (m.type === 'file') try { await store.forgetBlob(c.hex(this.chat.fileDecode(m.body).blob)); } catch { /* not a file it kept */ }
          if (m.mine) this.app.forgetSaid(id, m.seq);
          await store.expireMessage(id, m);
          gone = true;
        }
        if (gone) this.ui.changed(id);
      }
      for (const o of await store.outbox())
        if (o.expires && o.expires <= now) {
          const relay = o.url && o.env ? this.relay(o.url) : null;
          if (relay) await relay.del(o.env.slice(1, 33), [this.chat.blake2b(16, new Uint8Array(0), o.env)]).catch(() => {});
          await store.dropOutbox(o.id);
        }
      for (const k of await store.copies()) {
        if (now - k.made > TTL_MS) { await store.dropCopy(k.id); continue; }
        if (k.expires > now) continue;
        // Relays off for now: the copy is deleted there once they are on again.
        const relay = this.relay(k.url);
        const r = relay ? await relay.del(k.mailbox, [k.handle]).catch(() => null) : null;
        if (r?.status === STATUS.ok) await store.dropCopy(k.id);
      }
      await this.pump();
    } finally {
      this.sweeping = false;
    }
  }
  async revoke(conv, peer) { this.app.revoke(conv, peer); await this.pump(); }
  async createGroup(name, contacts, channel = false) {
    const id = this.app.createGroup(name, contacts, channel ? 2 : 1);
    const relay = this.profile.relay || this.config.relay;
    this.conv.set(id, { relay, name });
    await this.pump();
    await this.joinRooms(relay);
    return id;
  }
  async addToGroup(group, contact) { this.app.addToGroup(group, contact); await this.pump(); }
  async removeContact(conv) {
    this.app.removeContact(conv);
    this.conv.delete(conv);
    await store.forget(conv);
    await this.pump();
  }
  conversations() { return this.app ? this.app.conversations() : []; }
  // The chats a person sees: every conversation but the one of their own linked devices.
  chats() { return this.conversations().filter((id) => this.app.info(id).kind !== 3); }

  // ---- linked devices (protocol 11) ----
  selfConv() { return this.app ? this.app.selfConversation() : ''; }
  isLinked(peer) { return !!peer && !!this.app && this.app.linked().includes(peer); }
  tellRelay(id) { try { this.app.setRelay(id, this.relayUrlOf(id)); } catch { /* not a conversation here */ } }
  // When a linked device was last heard from, by wall time (for showing only).
  heard(peer) {
    this.lastHeard ??= {};
    this.lastHeard[peer] = Date.now();
    if (Date.now() - (this.heardSaved || 0) > 30e3) {
      this.heardSaved = Date.now();
      store.profile().then((p) => store.setProfile({ ...p, linkSeen: { ...(p.linkSeen || {}), ...this.lastHeard } })).catch(() => {});
    }
  }
  linkedDevices() {
    const seen = { ...(this.profile?.linkSeen || {}), ...(this.lastHeard || {}) };
    return this.app ? this.app.linked().map((peer) => ({ peer, live: this.app.liveWith(peer), heard: seen[peer] || 0,
      fingerprint: this.app.fingerprintWith(peer) })) : [];
  }
  // A linked device asks for messages it lacks: given from what is kept here, each with its key.
  async giveHistory(conv, peer, wanted) {
    const want = new Set(String(wanted || '').split(',').filter(Boolean));
    const items = [];
    for (const m of await store.messages(conv))
      if (m.key && m.obs && !m.expired && want.has(m.peer + ':' + m.seq)) items.push({ obs: m.obs, key: m.key });
    if (!items.length) return;
    try { this.app.giveHistory(conv, peer, items); } catch { return; }
    await this.pump();
  }
  async unlink(mode) {
    // Forget: what was said goes from here now; the chats are left (by
    // handoff), and then everything here is erased.
    if (mode === 'forget') {
      this.profile = { ...(await store.profile()), forgetting: true };
      await store.setProfile(this.profile);
      for (const id of this.chats())
        for (const m of await store.messages(id)) if (!m.expired) await store.expireMessage(id, m);
    }
    this.app.unlink(mode === 'forget' ? 1 : 2);
    await this.pump();
  }
  async askSplit(mine, theirs) { this.app.askSplit(mine, theirs); await this.pump(); }
  async agreeSplit() { this.app.agreeSplit(); await this.pump(); }
  async refuseSplit() { this.app.refuseSplit(); await this.pump(); }
  // Unlinked with Forget: once every chat is left - and what says so (a
  // handoff's end, the unlink itself) has gone out, live or to a relay -
  // nothing of it stays here.
  async maybeForgotten() {
    if (!this.profile?.forgetting || !this.app || this.forgetting) return;
    if (this.chats().some((id) => this.info(id).leaving)) return;
    const now = Date.now();
    this.forgetFrom ||= now;
    const going = (await store.outbox()).filter((o) => !o.relayed && !o.live);
    if (now - this.forgetFrom < 20e3 || (going.length && now - this.forgetFrom < 120e3)) return;
    this.forgetting = true;
    for (const t of this.timers) clearInterval(t);
    for (const r of this.relays.values()) r.close();
    await forgetAllHere();
    this.ui.forgotten?.();
  }
  info(conv) { return this.app.info(conv); }

  // ---- pairing: the owner ----
  async invite(kind, conv, name) {
    await this.ensureDevice();
    const relay = this.profile.relay || this.config.relay;
    if (!this.relayOn()) throw new Error('An invite sent as a link needs a relay, and relays are off. Pair in person, or turn relays on in Settings.');
    if (!relay) throw new Error('This p-chat has no relay to make invites with. Set one in About → Settings → Advanced.');
    const inv = this.app.invite(kind, relay, conv || '');
    const record = { token: inv.token, invite: inv.invite, code: inv.code, conv: inv.conversation, kind, relay, made: Date.now() };
    if (kind === 3 || kind === 4) {
      record.cancel = c.random(32);
      await this.relay(relay).pairReusable(inv.token, this.chat.blake2b(32, new Uint8Array(0), record.cancel));
    }
    await store.saveInvite(c.hex(inv.token), record);
    this.relay(relay);
    return { link: location.origin + location.pathname + '#' + inv.fragment, code: inv.code, token: c.hex(inv.token) };
  }
  async cancelInvite(token) {
    const inv = (await store.invites()).find((i) => c.hex(i.token) === token);
    if (!inv) return;
    const relay = this.relay(inv.relay);
    if (relay && inv.cancel) await relay.pairCancel(inv.token, inv.cancel).catch(() => {});
    else if (relay) await relay.pairDone(inv.token).catch(() => {});
    await store.dropInvite(token);
  }
  async pollPairing() {
    if (!this.app || this.polling) return;
    this.polling = true;
    try { await this.pollPairingOnce(); } finally { this.polling = false; }
  }
  async pollPairingOnce() {
    for (const inv of await store.invites()) {
      if (Date.now() - inv.made > TTL_MS) { await store.dropInvite(c.hex(inv.token)); continue; }
      const relay = this.relay(inv.relay);
      if (!relay?.up) continue;
      for (const box of await relay.pairFetch(inv.token).catch(() => [])) await this.takeRequest(inv, box, relay);
    }
    await this.pollReply();
  }
  // A pairing request for one of this device's invites (sealed to it, held
  // under the code's key): from the relay, or from the link made in person.
  async takeRequest(inv, box, relay) {
    const key = c.hex(this.chat.blake2b(16, new Uint8Array(0), box));
    if (this.seenPosts.has(key)) return;
    this.seenPosts.add(key);
    const shared = await c.derive(this.dev.agree, box.slice(0, 32));
    const before = new Set(this.app.conversations());
    const r = this.app.takeRequest(inv.invite, inv.code, inv.conv || '', box, shared, inv.recovery || null);
    const made = this.app.conversations().filter((id) => !before.has(id));
    for (const id of made) this.conv.set(id, { relay: inv.relay });
    if (inv.conv) this.conv.set(inv.conv, { ...(this.conv.get(inv.conv) || {}), relay: inv.relay });
    if (this.pairing?.token && c.hex(this.pairing.token) === c.hex(inv.token)) this.pairing.conv = made[0] || inv.conv || null;
    this.pendingReplyRelay = inv.relay;
    await this.pump();
    if (r === 'failed') {
      if (relay && inv.cancel) await relay.pairCancel(inv.token, inv.cancel).catch(() => {});
      await store.dropInvite(c.hex(inv.token));
    }
    if (relay && (inv.kind === 3 || inv.kind === 4)) await relay.pairDone(inv.token).catch(() => {});
    if (made.length) await this.joinRooms(inv.relay);
    this.ui.changed(inv.conv || null);
  }

  // ---- pairing: the new device ----
  async pair(fragment, code, name, call, mail = false) {
    const invite = this.chat.parseInvite(fragment);
    const inPerson = this.pairing?.role === 'new' && this.pairing.link.up;
    if (!inPerson && (!invite.relay || !this.relayOn()))
      throw new Error(invite.relay ? 'This invite needs a relay, and relays are off. Turn them on in Settings, or pair in person.' : 'This invite is for pairing in person: scan the other phone\'s code.');
    this.askRelay = invite.relay;
    await this.ensureDevice();
    // Linked devices take mail from each other: a device left on fills in one that was away.
    const a = this.app.ask(fragment, code, '', call || '', !!mail || invite.kind === 6);
    // The relay the invite names (none, if the inviting phone uses none) is
    // the chat's, as for an invite sent as a link - used while relays are on.
    await store.saveAsking({ asking: a.asking, mailbox: a.mailbox, relay: a.relay, owner: invite.owner, made: Date.now() });
    const relay = inPerson ? null : this.relay(a.relay);
    for (let i = 0; relay && i < 50 && !relay.up; i++) await sleep(100);
    await this.pump();
  }
  async pollReply() {
    const a = await store.asking();
    if (!a || !this.app) return;
    const relay = this.relay(a.relay);
    if (!relay?.up) return;
    for (const item of await relay.fetch([a.mailbox]).catch(() => [])) {
      await this.takeAccept(a, item.envelope);
      await relay.del(item.mailbox, [item.handle]).catch(() => {});
    }
  }
  // The owner's accept: from the relay's reply mailbox, or from the link made in person.
  async takeAccept(a, envelope) {
    const shared = await c.derive(this.dev.agree, this.chat.ephemeralOf(envelope));
    const before = new Set(this.app.conversations());
    const r = this.app.takeAccept(a.asking, envelope, shared);
    if (r === 'ok') {
      const made = this.app.conversations().filter((id) => !before.has(id));
      for (const id of made) this.conv.set(id, { relay: a.relay });
      if (this.pairing?.role === 'new') this.pairing.conv = made[0] || null;
      await store.dropAsking();
      await this.pump();
      await this.joinRooms(a.relay);
      this.ui.changed(null);
    } else {
      await store.dropAsking();
      this.ui.alert(null, r.startsWith('Invite failed') ? 'invite_failed' : 'pair_refused', r);
    }
  }

  // ---- pairing in person (protocol 10, direct.js) ----
  // The inviting phone: an invite (with this device's relay, if it uses one;
  // the chat works without), and a link offered. Its code is a link the
  // other phone's camera opens.
  async inPerson(name) {
    await this.ensureDevice();
    this.endPairing();
    const relay = this.relayOn() ? this.profile.relay || this.config.relay || '' : '';
    const inv = this.app.invite(1, relay, '');
    const link = new PairLink(this.config.ice);
    const offer = await link.offer();
    const record = { token: inv.token, invite: inv.invite, code: inv.code, conv: '', kind: 1, relay, made: Date.now(), inPerson: true };
    await store.saveInvite(c.hex(inv.token), record);
    this.watchPairing({ role: 'owner', token: inv.token, record, link });
    if (relay) this.relay(relay);
    return { link: inPersonLink(location.origin + location.pathname, inv.invite, inv.code, offer), token: c.hex(inv.token), relayed: !!relay };
  }
  // The other phone's answer, scanned: the two are joined.
  async theirCode(text) {
    const a = readAnswer(text.trim());
    const p = this.pairing;
    if (!p || p.role !== 'owner' || c.hex(a.token) !== c.hex(p.token)) throw new Error('That code answers another invite. Show them this one again.');
    await p.link.accept(a.answer);
  }
  // The phone that was shown the code: what it says, read.
  inPersonInvite(fragment) {
    const d = readInPerson(fragment);
    return { ...d, fragment: 'v1.' + base64url(d.invite), parsed: this.chat.parseInvite('v1.' + base64url(d.invite)) };
  }
  // ... and its answer, to show back. Once the link is up, the pairing
  // request goes over it.
  async answerInPerson(d, name, call, mail) {
    await this.ensureDevice();
    this.endPairing();
    const link = new PairLink(this.config.ice);
    const answer = await link.answer(d.offer);
    this.watchPairing({ role: 'new', token: d.token, link });
    link.onopen = () => this.pair(d.fragment, d.code, name, call, mail).catch((e) => this.ui.warn(e.message));
    return answerCode(d.token, answer);
  }
  watchPairing(p) {
    this.pairing = { ...p, made: Date.now() };
    p.link.onframe = (kind, body) => this.pairFrame(kind, body).catch((e) => console.error('pairing link', e));
    p.link.onclose = () => { if (this.pairing?.link === p.link) this.pairing.closed = true; };
  }
  async pairFrame(kind, body) {
    const p = this.pairing;
    if (!p) return;
    if (kind === FRAME.request && p.role === 'owner') await this.takeRequest(p.record, body, null);
    else if (kind === FRAME.accept && p.role === 'new') {
      const a = await store.asking();
      if (a) await this.takeAccept(a, body);
    } else if (kind === FRAME.signal && body.length > 32) {
      this.app.signalIn(body.slice(0, 32), body.slice(32));
      await this.pump();
    }
  }
  // Done with once the two phones' own link is up (a little after), or
  // after a while whatever happened.
  checkPairing() {
    const p = this.pairing;
    if (!p) return;
    const now = Date.now();
    const peers = p.conv && this.conv.has(p.conv) ? this.info(p.conv).members.filter((m) => !m.self).map((m) => m.peer) : [];
    if (peers.length && peers.every((x) => this.app.liveWith(x))) p.linked ??= now;
    if ((p.linked && now - p.linked > 10e3) || now - p.made > PAIR_LINK_MS || p.closed) this.endPairing();
  }
  endPairing() {
    if (!this.pairing) return;
    this.pairing.link.close();
    this.pairing = null;
  }
}
