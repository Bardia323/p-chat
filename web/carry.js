// Contacts carrying for each other (protocol 10): the relay's work, done by
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

export const KIND = { rooms: 1, pass: 2, signal: 3, hold: 4, ask: 5, given: 6, taken: 7 };
export const LIMITS = { rooms: 256, held: 512, heldBytes: 16 << 20, perGiver: 128, ttl: 14 * 86400e3, passPerMinute: 120,
  holdPerMinute: 60, askIds: 1024, box: 131072 };
const SIZES = new Set([1024, 16384, 262144].map((b) => 1 + 32 + 72 + b));
const ROOMS_AGAIN_MS = 60e3, ASK_EVERY_MS = 8e3;

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
};

// One phone's carrying. `io` is what it needs of the host:
//   send(peer, frame), peers() (linked now), rooms() ([{room, label}], its own),
//   mailboxes() (its own ids), signalIn(room, box), open(envelope) -> status,
//   handle(envelope) (16 bytes), helping(), keep {list(), put(item), drop(key)}, now().
export class Carry {
  constructor(io) {
    // What it did for others, counted (for looking, never for deciding).
    Object.assign(this, { io, reach: new Map(), told: new Map(), asked: new Map(), rates: new Map(), done: { passed: 0, held: 0, given: 0 } });
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
    for (const p of [...this.told.keys()]) if (!peers.has(p)) this.told.delete(p);
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
  // An envelope for a device that is away, given to up to three contacts to keep.
  hold(env, recipient) {
    let n = 0;
    for (const p of this.io.peers()) {
      if (p === recipient || n >= 3) continue;
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
        if (!helping || !this.allowed(peer, 'pass', LIMITS.passPerMinute)) return 'refused';
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
        if (!helping || !this.allowed(peer, 'hold', LIMITS.holdPerMinute)) return 'refused';
        const list = await this.io.keep.list();
        const mailbox = f.envelope.slice(1, 33), handle = this.io.handle(f.envelope), key = hex(mailbox) + hex(handle);
        if (list.some((h) => h.key === key)) return 'ok';
        const bytes = list.reduce((s, h) => s + h.envelope.length, 0);
        if (list.length >= LIMITS.held || bytes + f.envelope.length > LIMITS.heldBytes ||
          list.filter((h) => h.from === peer).length >= LIMITS.perGiver) return 'full';
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
        if (status !== 'need_turn') this.io.send(peer, frames.taken(f.mailbox, [f.handle]));
        return status;
      }
      case KIND.taken: {
        const gone = new Set(f.handles.map((h) => hex(f.mailbox) + hex(h)));
        for (const h of await this.io.keep.list()) if (gone.has(h.key)) await this.io.keep.drop(h.key);
        return 'ok';
      }
      default: return 'refused';
    }
  }
}
