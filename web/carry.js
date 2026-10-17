// Contacts carrying for each other (protocol 10; relaying, 11): the relay's work, done by
// the phones themselves on the live links they already have.
//
// A phone says to each contact it is linked with which rooms it is in (the
// room and label it would give a relay). Then a contact linked with two
// phones can pass a sealed signal from one to the other - so two phones that
// lost their own link find each other again with no relay - and can hold a
// sealed envelope for a phone that is away until it asks for it.
//
// What a carrier sees is what a relay sees: rooms, labels, mailbox ids,
// sealed boxes and their sizes - and, being a contact of both, that the two
// it carries between talk. It cannot open anything. A phone that does not
// want to carry says so (`helping` false): it still says its own rooms and
// takes what is for it.
//
//   1 rooms:  u16 n | n x (room(32) | label(32))           where to reach me (replaces the last)
//   2 pass:   room | label | long(box, 131072)            a signal, to be passed on
//   3 signal: room | long(box, 131072)                    a signal, for you
//   4 hold:   envelope                                    keep this for whoever asks
//   5 ask:    u16 n | n x mailbox                         anything for these?
//   6 given:  mailbox | handle(16) | envelope             one that was kept
//   7 taken:  mailbox | u16 n | n x handle                opened: drop it
//
// Envelopes are the relay's (version 1 or 2, one of its sizes). Bounds: 256
// rooms a peer, 512 envelopes and 16 MiB held in all, 128 from any one
// giver, kept 14 days; a giver may pass 120 signals and hold 60 envelopes a
// minute.
//
// A device that relays (protocol 11): one its owner leaves open - a computer
// on a desk - and says so (Settings). It does what every carrier does, with
// room for more (RELAYING), keeps what it holds across reloads (as every
// carrier does, in IndexedDB), and says so to its contacts:
//
//   8 relays: u8 flags (bit 0: this device relays)       said when it changes, and each minute
//   9 serves: u16 n | n x (room | label | u8 now)          the devices of your chats it keeps mail for
//
// A relaying device remembers, for 14 days, the rooms and labels its linked
// contacts said (where each device is reached). To each linked contact it
// says those that share a room with it - so the contact knows that a message
// for a device that is away will be kept here and asked for - with `now` 1
// for a device linked here this moment: the two can find each other again
// through it. The contact learns what a relay's room tells: that a device
// of their own chat comes by this one, and when. Nothing else.

export const KIND = { rooms: 1, pass: 2, signal: 3, hold: 4, ask: 5, given: 6, taken: 7, relays: 8, serves: 9 };
export const LIMITS = { rooms: 256, held: 512, heldBytes: 16 << 20, perGiver: 128, ttl: 14 * 86400e3, passPerMinute: 120,
  holdPerMinute: 60, askIds: 1024, box: 131072, serves: 1024 };
// What a device that relays takes on: a relay's share, for the few it serves.
export const RELAYING = { ...LIMITS, held: 4096, heldBytes: 256 << 20, perGiver: 1024, passPerMinute: 600, holdPerMinute: 300 };
export const FLAG = { relays: 1 };
const SIZES = new Set([1024, 16384, 262144].map((b) => 1 + 32 + 72 + b));
const ROOMS_AGAIN_MS = 60e3, ASK_EVERY_MS = 8e3;
// What a relaying device remembers of where a contact is reached is written
// down again at most this often (it is read on each tick from memory).
const SERVED_WRITE_MS = 3600e3;

const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const u16 = (n) => new Uint8Array([n >> 8, n & 255]);
const u32 = (n) => new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const read16 = (b, at) => (b[at] << 8) | b[at + 1];
const read32 = (b, at) => ((b[at] << 24) >>> 0) + (b[at + 1] << 16) + (b[at + 2] << 8) + b[at + 3];
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const hexBytes = (s) => Uint8Array.from(s.match(/../g), (x) => parseInt(x, 16));

// A frame, read whole or refused (null).
export function read(frame) {
  const k = frame[0], b = frame.subarray(1);
  try {
    if (k === KIND.rooms) {
      const n = read16(b, 0);
      if (n > LIMITS.rooms || b.length !== 2 + n * 64) return null;
      const rooms = [];
      for (let i = 0; i < n; i++) rooms.push({ room: b.slice(2 + i * 64, 34 + i * 64), label: b.slice(34 + i * 64, 66 + i * 64) });
      return { kind: k, rooms };
    }
    if (k === KIND.pass) {
      const n = read32(b, 64);
      if (b.length !== 68 + n || n > LIMITS.box || !n) return null;
      return { kind: k, room: b.slice(0, 32), label: b.slice(32, 64), box: b.slice(68) };
    }
    if (k === KIND.signal) {
      const n = read32(b, 32);
      if (b.length !== 36 + n || n > LIMITS.box || !n) return null;
      return { kind: k, room: b.slice(0, 32), box: b.slice(36) };
    }
    if (k === KIND.hold) return envelope(b) ? { kind: k, envelope: b.slice() } : null;
    if (k === KIND.ask) {
      const n = read16(b, 0);
      if (n > LIMITS.askIds || b.length !== 2 + n * 32) return null;
      const ids = [];
      for (let i = 0; i < n; i++) ids.push(b.slice(2 + i * 32, 34 + i * 32));
      return { kind: k, mailboxes: ids };
    }
    if (k === KIND.given) {
      const e = b.subarray(48);
      if (!envelope(e) || hex(e.subarray(1, 33)) !== hex(b.subarray(0, 32))) return null;
      return { kind: k, mailbox: b.slice(0, 32), handle: b.slice(32, 48), envelope: e.slice() };
    }
    if (k === KIND.taken) {
      const n = read16(b, 32);
      if (b.length !== 34 + n * 16 || n > 256) return null;
      const handles = [];
      for (let i = 0; i < n; i++) handles.push(b.slice(34 + i * 16, 50 + i * 16));
      return { kind: k, mailbox: b.slice(0, 32), handles };
    }
    if (k === KIND.relays) {
      if (b.length !== 1 || (b[0] & ~FLAG.relays)) return null;
      return { kind: k, flags: b[0] };
    }
    if (k === KIND.serves) {
      const n = read16(b, 0);
      if (n > LIMITS.serves || b.length !== 2 + n * 65) return null;
      const devices = [];
      for (let i = 0, at = 2; i < n; i++, at += 65) {
        if (b[at + 64] > 1) return null;
        devices.push({ room: b.slice(at, at + 32), label: b.slice(at + 32, at + 64), now: b[at + 64] === 1 });
      }
      return { kind: k, devices };
    }
  } catch { /* cut short */ }
  return null;
}
// What a relay would take: a sealed message (version 1 or 2) of one of its sizes.
const envelope = (e) => e.length > 0 && (e[0] === 1 || e[0] === 2) && SIZES.has(e.length);

export const frames = {
  rooms: (rooms) => cat(new Uint8Array([KIND.rooms]), u16(rooms.length), ...rooms.flatMap((r) => [r.room, r.label])),
  pass: (room, label, box) => cat(new Uint8Array([KIND.pass]), room, label, u32(box.length), box),
  signal: (room, box) => cat(new Uint8Array([KIND.signal]), room, u32(box.length), box),
  hold: (env) => cat(new Uint8Array([KIND.hold]), env),
  ask: (ids) => cat(new Uint8Array([KIND.ask]), u16(ids.length), ...ids),
  given: (mailbox, handle, env) => cat(new Uint8Array([KIND.given]), mailbox, handle, env),
  taken: (mailbox, handles) => cat(new Uint8Array([KIND.taken]), mailbox, u16(handles.length), ...handles),
  relays: (flags) => new Uint8Array([KIND.relays, flags]),
  serves: (devices) => cat(new Uint8Array([KIND.serves]), u16(devices.length),
    ...devices.flatMap((d) => [d.room, d.label, new Uint8Array([d.now ? 1 : 0])])),
};

// One phone's carrying. `io` is what it needs of the host:
//   send(peer, frame), peers() (linked now), rooms() ([{room, label}], its own),
//   mailboxes() (its own ids), signalIn(room, box), open(envelope) -> status,
//   handle(envelope) (16 bytes), helping(), keep {list(), put(item), drop(key)}, now();
//   and for relaying (protocol 11): relaying() (this device relays),
//   served {list(), put(item), drop(key)} (what it remembers of its contacts'
//   rooms), near(peer, rooms) (a linked relaying contact has, this moment,
//   devices of these rooms linked to it).
export class Carry {
  constructor(io) {
    // What it did for others, counted (for looking, never for deciding).
    Object.assign(this, { io, reach: new Map(), told: new Map(), asked: new Map(), rates: new Map(), done: { passed: 0, held: 0, given: 0 },
      relaying: new Map(), serving: new Map(), flagged: new Map(), servesTold: new Map(), served: null });
  }
  limits() { return this.io.relaying?.() ? RELAYING : LIMITS; }
  // The linked contacts that say they relay.
  relays() { return this.io.peers().filter((p) => this.relaying.get(p) & FLAG.relays); }
  // Labels kept for in `room` (hex) by the linked contacts that relay: the
  // devices a message for which is kept and asked for there.
  servedIn(room) {
    const out = new Set();
    for (const p of this.relays()) for (const d of this.serving.get(p) || []) if (hex(d.room) === room) out.add(hex(d.label));
    return out;
  }
  // A relaying device's memory of where its contacts are reached, read once
  // from the store and written back when it changes (or an hour on).
  async remember(now) {
    if (!this.served) {
      this.served = new Map();
      for (const s of (await this.io.served?.list()) || []) this.served.set(s.key, s);
    }
    const ttl = LIMITS.ttl;
    for (const [p, m] of this.reach)
      for (const k of m.keys()) {
        const was = this.served.get(k);
        if (was && was.peer === p && now - was.at < SERVED_WRITE_MS) continue;
        const s = { key: k, room: hexBytes(k.slice(0, 64)), label: hexBytes(k.slice(64)), peer: p, at: now };
        this.served.set(k, s);
        await this.io.served?.put(s);
      }
    for (const [k, s] of this.served) if (now - s.at > ttl) { this.served.delete(k); await this.io.served?.drop(k); }
  }
  // What a relaying device says to `peer`: the devices it keeps mail for
  // that share a room with it (not the peer's own), linked here now or not.
  servesFor(peer) {
    const mine = this.reach.get(peer);
    if (!mine) return [];
    const rooms = new Set([...mine.keys()].map((k) => k.slice(0, 64)));
    const now = new Set();
    for (const [p, m] of this.reach) if (p !== peer) for (const k of m.keys()) now.add(k);
    const out = [];
    for (const [k, s] of this.served || []) {
      if (out.length >= LIMITS.serves) break;
      if (rooms.has(k.slice(0, 64)) && !mine.has(k) && s.peer !== peer) out.push({ room: s.room, label: s.label, now: now.has(k) });
    }
    return out;
  }
  // A peer that may pass on n more of `what` this minute.
  allowed(peer, what, per) {
    const now = this.io.now(), k = peer + ':' + what;
    const r = this.rates.get(k);
    if (!r || now - r.since > 60e3) { this.rates.set(k, { since: now, n: 1 }); return true; }
    if (r.n >= per) return false;
    r.n++;
    return true;
  }
  // Once a second: rooms said to who is newly linked (and again each
  // minute), what was heard of who is gone forgotten, kept mail asked for.
  async tick() {
    const now = this.io.now(), peers = new Set(this.io.peers());
    for (const p of [...this.reach.keys()]) if (!peers.has(p)) this.reach.delete(p);
    for (const m of [this.told, this.relaying, this.serving, this.flagged, this.servesTold])
      for (const p of [...m.keys()]) if (!peers.has(p)) m.delete(p);
    const relaying = !!this.io.relaying?.();
    if (relaying) await this.remember(now);
    else if (this.served) {
      // No longer relaying: what it remembered of others is forgotten.
      for (const k of this.served.keys()) await this.io.served?.drop(k);
      this.served = null;
    }
    const mine = this.io.rooms().slice(0, LIMITS.rooms);
    const said = mine.map((r) => hex(r.room) + hex(r.label)).join();
    const ids = this.io.mailboxes();
    for (const p of peers) {
      // Said again when they change (a new chat, a rekey), and each minute.
      const last = this.told.get(p);
      if (!last || last.said !== said || now - last.at > ROOMS_AGAIN_MS) {
        if (this.io.send(p, frames.rooms(mine))) this.told.set(p, { at: now, said });
      }
      if (ids.length && now - (this.asked.get(p) || 0) > ASK_EVERY_MS) {
        this.asked.set(p, now);
        for (let i = 0; i < ids.length; i += LIMITS.askIds) this.io.send(p, frames.ask(ids.slice(i, i + LIMITS.askIds)));
      }
      // That this device relays, said once it does (and once it stops).
      const flags = relaying ? FLAG.relays : 0, f = this.flagged.get(p);
      if ((flags || f) && (!f || f.flags !== flags || now - f.at > ROOMS_AGAIN_MS) && this.io.send(p, frames.relays(flags)))
        this.flagged.set(p, { flags, at: now });
      if (relaying) {
        const list = this.servesFor(p), was = this.servesTold.get(p);
        const key = list.map((d) => hex(d.room) + hex(d.label) + (d.now ? 1 : 0)).join();
        if ((list.length || was) && (!was || was.key !== key || now - was.at > ROOMS_AGAIN_MS) && this.io.send(p, frames.serves(list)))
          this.servesTold.set(p, { key, at: now });
      }
    }
    // Kept too long: gone.
    for (const h of await this.io.keep.list()) if (now - h.at > LIMITS.ttl) await this.io.keep.drop(h.key);
  }
  // A signal of this phone's for `to` (a device): to it directly where they
  // are linked, else given to every linked contact to pass on. How many took it.
  signal(s) {
    let n = 0;
    for (const p of this.io.peers()) {
      const f = p === s.peer ? frames.signal(s.room, s.box) : frames.pass(s.room, s.label, s.box);
      if (this.io.send(p, f)) n++;
    }
    return n;
  }
  // An envelope for a device that is away, given to up to three contacts to
  // keep - every contact that relays first, whatever their number. Only
  // those that relay, when `relaysOnly` (given again to one newly linked).
  hold(env, recipient, relaysOnly = false) {
    const relays = new Set(this.relays());
    const order = [...relays, ...(relaysOnly ? [] : this.io.peers().filter((p) => !relays.has(p)))];
    let n = 0;
    for (const p of order) {
      if (p === recipient || (n >= 3 && !relays.has(p))) continue;
      if (this.io.send(p, frames.hold(env))) n++;
    }
    return n;
  }
  async frame(peer, bytes) {
    const f = read(bytes);
    if (!f) return 'refused';
    const helping = this.io.helping();
    switch (f.kind) {
      case KIND.rooms: {
        const m = new Map();
        for (const r of f.rooms) m.set(hex(r.room) + hex(r.label), true);
        this.reach.set(peer, m);
        return 'ok';
      }
      case KIND.pass: {
        if (!helping || !this.allowed(peer, 'pass', this.limits().passPerMinute)) return 'refused';
        const k = hex(f.room) + hex(f.label);
        for (const [p, m] of this.reach) {
          if (p === peer || !m.has(k)) continue;
          if (!this.io.send(p, frames.signal(f.room, f.box))) return 'busy';
          this.done.passed++;
          return 'passed';
        }
        return 'nowhere';
      }
      case KIND.signal: this.io.signalIn(f.room, f.box); return 'ok';
      case KIND.hold: {
        const L = this.limits();
        if (!helping || !this.allowed(peer, 'hold', L.holdPerMinute)) return 'refused';
        const list = await this.io.keep.list();
        const mailbox = f.envelope.slice(1, 33), handle = this.io.handle(f.envelope), key = hex(mailbox) + hex(handle);
        if (list.some((h) => h.key === key)) return 'ok';
        const bytes = list.reduce((s, h) => s + h.envelope.length, 0);
        if (list.length >= L.held || bytes + f.envelope.length > L.heldBytes ||
          list.filter((h) => h.from === peer).length >= L.perGiver) return 'full';
        await this.io.keep.put({ key, mailbox, handle, envelope: f.envelope, from: peer, at: this.io.now() });
        this.done.held++;
        return 'held';
      }
      case KIND.ask: {
        if (!helping || !this.allowed(peer, 'ask', 30)) return 'refused';
        const want = new Set(f.mailboxes.map(hex));
        let n = 0;
        for (const h of await this.io.keep.list())
          if (want.has(hex(h.mailbox)) && this.io.send(peer, frames.given(h.mailbox, h.handle, h.envelope))) n++;
        this.done.given += n;
        return n;
      }
      case KIND.given: {
        // Opened (or not ours to keep): the one who kept it drops it.
        if (hex(this.io.handle(f.envelope)) !== hex(f.handle)) return 'refused';
        const status = await this.io.open(f.envelope);
        if (status !== 'need_turn' && status !== 'later') this.io.send(peer, frames.taken(f.mailbox, [f.handle]));
        return status;
      }
      case KIND.taken: {
        const gone = new Set(f.handles.map((h) => hex(f.mailbox) + hex(h)));
        for (const h of await this.io.keep.list()) if (gone.has(h.key)) await this.io.keep.drop(h.key);
        return 'ok';
      }
      case KIND.relays: this.relaying.set(peer, f.flags); return 'ok';
      case KIND.serves: {
        // Believed only of a contact that said it relays (and only for
        // deciding where to keep and whom to look for: nothing is opened).
        if (!(this.relaying.get(peer) & FLAG.relays)) return 'refused';
        this.serving.set(peer, f.devices);
        const near = [...new Set(f.devices.filter((d) => d.now).map((d) => hex(d.room)))];
        if (near.length) this.io.near?.(peer, near);
        return 'ok';
      }
      default: return 'refused';
    }
  }
}
