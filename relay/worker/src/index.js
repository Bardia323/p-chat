// The p-chat relay as a Cloudflare Worker: the same frames as relay/relay.py
// (docs/protocol.md, "The relay's frames"), refused alike, bounded alike.
// It holds nothing it can read: sealed envelopes in mailboxes, pairing
// boxes under one-time tokens, rooms that pass sealed signals to one member.
//
// One Durable Object holds it all. Its WebSockets hibernate between frames:
// each connection carries a small id, and the rooms it is in are kept under
// that id, so they are known again when the object wakes. Mailboxes and
// tokens are in its SQLite storage; everything expires after the TTL. It
// logs nothing: no requests, no addresses (Cloudflare itself sees the
// connections, as any host does).
import { blake2b } from './blake2b.js';

const BUCKETS = [1024, 16384, 262144];
const SEAL = 32 + 24 + 16;
const ENVELOPE_SIZES = new Set(BUCKETS.map((b) => 1 + 32 + SEAL + b));
const ENVELOPE_VERSIONS = new Set([1, 2, 16]);
const PIECE_SIZES = new Set(BUCKETS.map((b) => 1 + 32 + 24 + 16 + b));
const PAIR_BOX = SEAL + 1024;
const OK = 0, REFUSED = 1, BURNED = 2, BUSY = 3, QUOTA = 4, NOT_FOUND = 5;
const OP = { put: 1, fetch: 2, del: 3, pairPost: 16, pairFetch: 17, pairReusable: 18, pairCancel: 19, pairDone: 20,
  join: 32, signal: 33, leave: 34, subscribe: 48, forward: 49 };
const PUSH_HOSTS = ['fcm.googleapis.com', 'push.services.mozilla.com', 'web.push.apple.com', 'notify.windows.com'];
const PUSHED_SIGNAL = 0x40;

class Refused extends Error {}
class Reader {
  constructor(b) { this.b = b; this.at = 0; }
  take(n) { if (n < 0 || this.at + n > this.b.length) throw new Refused('truncated'); const v = this.b.slice(this.at, this.at + n); this.at += n; return v; }
  u8() { return this.take(1)[0]; }
  u16() { const v = this.take(2); return (v[0] << 8) | v[1]; }
  u32() { const v = this.take(4); return ((v[0] << 24) >>> 0) + (v[1] << 16) + (v[2] << 8) + v[3]; }
  long(max) { const n = this.u32(); if (n > max) throw new Refused('oversize'); return this.take(n); }
  rest() { return this.take(this.b.length - this.at); }
  end() { if (this.at !== this.b.length) throw new Refused('trailing'); }
}
const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const u16 = (n) => new Uint8Array([n >> 8, n & 255]);
const u32 = (n) => new Uint8Array([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const answer = (op, rid, status, body = new Uint8Array(0)) => cat(new Uint8Array([1, op | 0x80]), u32(rid), new Uint8Array([status]), body);
const bytes = (v) => new Uint8Array(v);

export default {
  async fetch(request, env) {
    if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
      return env.RELAY.get(env.RELAY.idFromName('relay')).fetch(request);
    }
    return new Response('p-chat relay\n', { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } });
  },
};

export class Relay {
  constructor(ctx, env) {
    this.ctx = ctx;
    const n = (k, d) => (env[k] !== undefined && env[k] !== '' ? Number(env[k]) : d);
    this.limits = {
      ttl: n('TTL', 14 * 86400) * 1000, mailboxBytes: n('MAILBOX_BYTES', 8 << 20), mailboxBlobs: n('MAILBOX_BLOBS', 512),
      totalBytes: n('TOTAL_BYTES', 512 << 20), tokens: n('TOKENS', 65536), rooms: n('ROOMS', 65536), members: n('MEMBERS', 16),
      roomsPerConnection: 64, fetchIds: 1024, reusablePosts: 16, forwardsPerMinute: 60, pushLocal: env.PUSH_LOCAL === '1',
    };
    this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS mail (mid BLOB, handle BLOB, exp INTEGER, env BLOB, PRIMARY KEY (mid, handle));
      CREATE INDEX IF NOT EXISTS mail_exp ON mail (exp);
      CREATE TABLE IF NOT EXISTS tokens (token BLOB PRIMARY KEY, reusable INTEGER, burned INTEGER, cancel BLOB, exp INTEGER);
      CREATE TABLE IF NOT EXISTS posts (token BLOB, n INTEGER, box BLOB);
      CREATE TABLE IF NOT EXISTS joined (conn TEXT, room BLOB, label BLOB, PRIMARY KEY (conn, room));`);
    // Rooms, from the connections still open (a connection's id is its attachment).
    this.rooms = new Map();        // room hex -> Map(label hex -> ws)
    this.forwarded = new Map();    // connection id -> times it forwarded a push (last minute)
    this.forwarding = 0;
    const open = new Map();
    for (const ws of ctx.getWebSockets()) { const a = ws.deserializeAttachment(); if (a?.id) open.set(a.id, ws); }
    for (const row of this.sql.exec('SELECT conn, room, label FROM joined').toArray()) {
      const ws = open.get(row.conn);
      if (!ws) { this.sql.exec('DELETE FROM joined WHERE conn = ?', row.conn); continue; }
      this.member(hex(bytes(row.room))).set(hex(bytes(row.label)), ws);
    }
  }
  member(room) {
    if (!this.rooms.has(room)) this.rooms.set(room, new Map());
    return this.rooms.get(room);
  }
  async fetch() {
    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ id: crypto.randomUUID() });
    await this.alarmSoon();
    return new Response(null, { status: 101, webSocket: client });
  }
  // Expiry: where touched, and in a sweep once an hour while anything is kept.
  async alarmSoon() {
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + Math.min(3600e3, this.limits.ttl));
  }
  async alarm() {
    this.sweep();
    const left = this.sql.exec('SELECT (SELECT count(*) FROM mail) + (SELECT count(*) FROM tokens) AS n').one().n;
    if (left) await this.ctx.storage.setAlarm(Date.now() + Math.min(3600e3, this.limits.ttl));
  }
  sweep() {
    const now = Date.now();
    this.sql.exec('DELETE FROM mail WHERE exp <= ?', now);
    this.sql.exec('DELETE FROM posts WHERE token IN (SELECT token FROM tokens WHERE exp <= ?)', now);
    this.sql.exec('DELETE FROM tokens WHERE exp <= ?', now);
  }
  id(ws) { return ws.deserializeAttachment()?.id || ''; }

  async webSocketMessage(ws, data) {
    if (typeof data === 'string') { ws.close(1003, 'binary frames only'); return; }
    const frame = new Uint8Array(data);
    let reply;
    try {
      reply = await this.handle(ws, frame);
    } catch (e) {
      if (!(e instanceof Refused)) throw e;
      const op = frame.length >= 6 ? frame[1] & 0x7f : 0;
      const rid = frame.length >= 6 ? ((frame[2] << 24) >>> 0) + (frame[3] << 16) + (frame[4] << 8) + frame[5] : 0;
      reply = answer(op, rid, REFUSED);
    }
    ws.send(reply);
  }
  async webSocketClose(ws) { this.drop(ws); }
  async webSocketError(ws) { this.drop(ws); }
  drop(ws) {
    const id = this.id(ws);
    for (const row of this.sql.exec('SELECT room, label FROM joined WHERE conn = ?', id).toArray()) {
      const room = hex(bytes(row.room)), members = this.rooms.get(room);
      if (members?.get(hex(bytes(row.label))) === ws) members.delete(hex(bytes(row.label)));
      if (members && !members.size) this.rooms.delete(room);
    }
    this.sql.exec('DELETE FROM joined WHERE conn = ?', id);
    this.forwarded.delete(id);
  }

  async handle(ws, data) {
    const r = new Reader(data);
    if (r.u8() !== 1) throw new Refused('version');
    const op = r.u8(), rid = r.u32();
    switch (op) {
      case OP.put: return answer(op, rid, await this.put(r.rest()));
      case OP.fetch: {
        const n = r.u16();
        if (n === 0 || n > this.limits.fetchIds) throw new Refused('fetch count');
        const ids = [];
        for (let i = 0; i < n; i++) ids.push(r.take(32));
        r.end();
        const parts = [];
        let found = 0;
        const now = Date.now();
        for (const mid of ids)
          for (const row of this.sql.exec('SELECT handle, env FROM mail WHERE mid = ? AND exp > ? ORDER BY rowid', mid, now).toArray()) {
            const env = bytes(row.env);
            parts.push(mid, bytes(row.handle), u32(env.length), env);
            found++;
          }
        return answer(op, rid, OK, cat(u16(found), ...parts));
      }
      case OP.del: {
        const mid = r.take(32), n = r.u16();
        if (n > 1024) throw new Refused('delete count');
        const handles = [];
        for (let i = 0; i < n; i++) handles.push(r.take(16));
        r.end();
        for (const h of handles) this.sql.exec('DELETE FROM mail WHERE mid = ? AND handle = ?', mid, h);
        return answer(op, rid, OK);
      }
      case OP.pairPost: {
        const token = r.take(16), box = r.rest();
        if (box.length !== PAIR_BOX) throw new Refused('pair box size');
        return answer(op, rid, await this.pairPost(token, box));
      }
      case OP.pairFetch: {
        const token = r.take(16);
        r.end();
        const posts = this.token(token) ? this.sql.exec('SELECT box FROM posts WHERE token = ? ORDER BY n', token).toArray().map((x) => bytes(x.box)) : [];
        return answer(op, rid, OK, cat(u16(posts.length), ...posts.flatMap((p) => [u32(p.length), p])));
      }
      case OP.pairReusable: {
        const token = r.take(16), cancel = r.take(32);
        r.end();
        if (this.token(token)) return answer(op, rid, BURNED);
        if (this.tokenCount() >= this.limits.tokens) return answer(op, rid, QUOTA);
        this.sql.exec('INSERT INTO tokens VALUES (?, 1, 0, ?, ?)', token, cancel, Date.now() + this.limits.ttl);
        await this.alarmSoon();
        return answer(op, rid, OK);
      }
      case OP.pairCancel: {
        const token = r.take(16), key = r.take(32);
        r.end();
        const t = this.token(token);
        if (!t || !t.reusable) return answer(op, rid, NOT_FOUND);
        if (hex(blake2b(key, 32)) !== hex(bytes(t.cancel))) return answer(op, rid, REFUSED);
        this.sql.exec('UPDATE tokens SET burned = 1 WHERE token = ?', token);
        this.sql.exec('DELETE FROM posts WHERE token = ?', token);
        return answer(op, rid, OK);
      }
      case OP.pairDone: {
        const token = r.take(16);
        r.end();
        const t = this.token(token);
        if (!t) {
          this.sql.exec('INSERT INTO tokens VALUES (?, 0, 1, NULL, ?)', token, Date.now() + this.limits.ttl);
          await this.alarmSoon();
        } else if (!t.reusable) this.sql.exec('UPDATE tokens SET burned = 1 WHERE token = ?', token);
        this.sql.exec('DELETE FROM posts WHERE token = ?', token);
        return answer(op, rid, OK);
      }
      case OP.join: {
        const room = r.take(32), label = r.take(32);
        r.end();
        return answer(op, rid, this.join(ws, room, label));
      }
      case OP.signal: {
        const room = r.take(32), to = r.take(32), box = r.long(131072);
        r.end();
        const id = this.id(ws);
        if (!this.sql.exec('SELECT 1 FROM joined WHERE conn = ? AND room = ?', id, room).toArray().length) return answer(op, rid, REFUSED);
        const target = this.rooms.get(hex(room))?.get(hex(to));
        if (!target) return answer(op, rid, NOT_FOUND);
        try {
          target.send(cat(new Uint8Array([1, PUSHED_SIGNAL, 0, 0, 0, 0]), room, u32(box.length), box));
        } catch {
          return answer(op, rid, NOT_FOUND);
        }
        return answer(op, rid, OK);
      }
      case OP.leave: {
        const room = r.take(32);
        r.end();
        this.leave(ws, room);
        return answer(op, rid, OK);
      }
      case OP.subscribe: {
        // Relay-held VAPID pushes (protocol 1) are not offered here: p-chat
        // phones push to each other, and a relay only forwards (op 49).
        r.take(32); r.long(4096); r.end();
        return answer(op, rid, REFUSED);
      }
      case OP.forward: return answer(op, rid, this.forward(ws, r));
      default: throw new Refused('unknown op');
    }
  }

  async put(envelope) {
    const v = envelope[0];
    if (!((ENVELOPE_VERSIONS.has(v) && ENVELOPE_SIZES.has(envelope.length)) || ((v === 17 || v === 18) && PIECE_SIZES.has(envelope.length))))
      throw new Refused('not an envelope');
    const mid = envelope.slice(1, 33), handle = blake2b(envelope, 16), now = Date.now();
    this.sql.exec('DELETE FROM mail WHERE mid = ? AND exp <= ?', mid, now);
    if (this.sql.exec('SELECT 1 FROM mail WHERE mid = ? AND handle = ?', mid, handle).toArray().length) return OK;
    const box = this.sql.exec('SELECT count(*) AS n, coalesce(sum(length(env)), 0) AS b FROM mail WHERE mid = ?', mid).one();
    if (box.n >= this.limits.mailboxBlobs || box.b + envelope.length > this.limits.mailboxBytes) return QUOTA;
    const all = this.sql.exec('SELECT coalesce(sum(length(env)), 0) AS b FROM mail WHERE exp > ?', now).one();
    if (all.b + envelope.length > this.limits.totalBytes) return QUOTA;
    this.sql.exec('INSERT INTO mail VALUES (?, ?, ?, ?)', mid, handle, now + this.limits.ttl, envelope);
    await this.alarmSoon();
    return OK;
  }
  token(token) {
    const t = this.sql.exec('SELECT reusable, burned, cancel, exp FROM tokens WHERE token = ?', token).toArray()[0];
    if (t && t.exp <= Date.now()) {
      this.sql.exec('DELETE FROM tokens WHERE token = ?', token);
      this.sql.exec('DELETE FROM posts WHERE token = ?', token);
      return null;
    }
    return t || null;
  }
  tokenCount() { return this.sql.exec('SELECT count(*) AS n FROM tokens WHERE exp > ?', Date.now()).one().n; }
  // The first post wins; a reusable token takes posts until its owner cancels it.
  async pairPost(token, box) {
    const t = this.token(token);
    if (!t) {
      if (this.tokenCount() >= this.limits.tokens) return QUOTA;
      this.sql.exec('INSERT INTO tokens VALUES (?, 0, 1, NULL, ?)', token, Date.now() + this.limits.ttl);
      this.sql.exec('INSERT INTO posts VALUES (?, 0, ?)', token, box);
      await this.alarmSoon();
      return OK;
    }
    if (t.burned || !t.reusable) return BURNED;
    const posts = this.sql.exec('SELECT box FROM posts WHERE token = ?', token).toArray().map((x) => hex(bytes(x.box)));
    if (posts.length >= this.limits.reusablePosts) return QUOTA;
    if (!posts.includes(hex(box))) this.sql.exec('INSERT INTO posts VALUES (?, ?, ?)', token, posts.length, box);
    return OK;
  }
  // A member is a label in a room; signals go only to a member of the same room.
  join(ws, room, label) {
    const id = this.id(ws), rh = hex(room), lh = hex(label);
    const members = this.rooms.get(rh);
    if (!members && this.rooms.size >= this.limits.rooms) return QUOTA;
    if (members && !members.has(lh) && members.size >= this.limits.members) return QUOTA;
    const mine = this.sql.exec('SELECT room FROM joined WHERE conn = ?', id).toArray().map((x) => hex(bytes(x.room)));
    if (!mine.includes(rh) && mine.length >= this.limits.roomsPerConnection) return QUOTA;
    const old = members?.get(lh);
    if (old && old !== ws) this.sql.exec('DELETE FROM joined WHERE conn = ? AND room = ?', this.id(old), room);
    this.member(rh).set(lh, ws);
    this.sql.exec('INSERT OR REPLACE INTO joined VALUES (?, ?, ?)', id, room, label);
    return OK;
  }
  leave(ws, room) {
    const id = this.id(ws), rh = hex(room);
    const row = this.sql.exec('SELECT label FROM joined WHERE conn = ? AND room = ?', id, room).toArray()[0];
    this.sql.exec('DELETE FROM joined WHERE conn = ? AND room = ?', id, room);
    const members = this.rooms.get(rh);
    if (row && members?.get(hex(bytes(row.label))) === ws) members.delete(hex(bytes(row.label)));
    if (members && !members.size) this.rooms.delete(rh);
  }
  // A push made and signed by a member's device, carried as it is, only to
  // the browsers' push services. The relay holds no key for it.
  forward(ws, r) {
    let endpoint, authorization;
    try {
      endpoint = new TextDecoder('ascii', { fatal: true }).decode(r.long(1024));
      authorization = new TextDecoder('ascii', { fatal: true }).decode(r.long(1024));
    } catch (e) { if (e instanceof Refused) throw e; throw new Refused('push'); }
    const body = r.long(4096);
    r.end();
    let url;
    try { url = new URL(endpoint); } catch { throw new Refused('push'); }
    const host = url.hostname;
    const known = url.protocol === 'https:' && PUSH_HOSTS.some((h) => host === h || host.endsWith('.' + h));
    const local = this.limits.pushLocal && url.protocol === 'http:' && (host === '127.0.0.1' || host === 'localhost');
    if (!(known || local) || !authorization.startsWith('vapid t=') || /[\r\n]/.test(authorization) || /[^\x20-\x7e]/.test(endpoint))
      throw new Refused('push');
    const id = this.id(ws), now = Date.now();
    const times = (this.forwarded.get(id) || []).filter((t) => now - t < 60e3);
    if (times.length >= this.limits.forwardsPerMinute) { this.forwarded.set(id, times); return BUSY; }
    times.push(now);
    this.forwarded.set(id, times);
    if (this.forwarding >= 256) return BUSY;
    this.forwarding++;
    const sent = fetch(endpoint, { method: 'POST', body, headers: { TTL: '86400', Urgency: 'high', 'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream', Authorization: authorization } })
      .then((res) => res.body?.cancel()).catch(() => {}).finally(() => { this.forwarding--; });
    this.ctx.waitUntil?.(sent);
    return OK;
  }
}
