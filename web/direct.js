// Pairing in person (protocol 10): two phones side by side make a link of
// their own, with no relay. The inviting phone shows a code - the invite, its
// six words and how to reach it (a WebRTC offer); the other phone's camera
// opens it and that phone shows a code back (its answer); the first phone
// scans it. The two are then joined directly, and the pairing request and
// its accept - the same, signed and checked as ever - go over that link, as
// do the first signals of the conversation's own live link.
//
// What is in a code is seen only by whoever can see the screen. The link it
// makes is the codes' own: its DTLS fingerprint is in them. Nothing that
// goes over it is believed for having come that way - the request holds
// under the code's key and the device's signature, the accept under the
// owner's, every signal under its sender's.
//
// A WebRTC description is mostly boilerplate. A code carries only what
// differs - the ICE username and password, the DTLS fingerprint, the role,
// the candidates - and the standard description of one data channel is
// made again from it (compact(), described()).

const enc = new TextEncoder(), dec = new TextDecoder();
const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};

// ---- bytes ----
class Reader {
  constructor(b) { this.b = b; this.at = 0; }
  need(n) { if (this.at + n > this.b.length) throw new Error('p-chat: a code is cut short'); }
  u8() { this.need(1); return this.b[this.at++]; }
  u16() { this.need(2); const v = (this.b[this.at] << 8) | this.b[this.at + 1]; this.at += 2; return v; }
  bytes(n) { this.need(n); const v = this.b.slice(this.at, this.at + n); this.at += n; return v; }
  short(max) { const n = this.u16(); if (n > max) throw new Error('p-chat: a code says too much'); return this.bytes(n); }
  text(max) { return dec.decode(this.short(max)); }
  end() { if (this.at !== this.b.length) throw new Error('p-chat: a code has more than it should'); }
}
const u16 = (n) => new Uint8Array([n >> 8, n & 255]);
const short = (b, max) => { if (b.length > max) throw new Error('p-chat: too long for a code'); return cat(u16(b.length), b); };
const text = (s, max) => short(enc.encode(s), max);

export function base64url(b) {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unbase64url(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new Error('p-chat: not a code');
  const t = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  const b = Uint8Array.from(t, (ch) => ch.charCodeAt(0));
  if (base64url(b) !== s) throw new Error('p-chat: not a code');  // canonical only
  return b;
}

// ---- a description, compact ----
//   compact = u8 1 | u8 setup | short(mid) | short(ufrag) | short(pwd) | fingerprint(32) | u8 n | n x candidate
//   setup:     0 actpass, 1 active, 2 passive
//   candidate: u8 address kind | address | u16 port | u8 type
//              kind 1 an mDNS name (a UUID, 16 bytes) + ".local"; 4 IPv4 (4); 6 IPv6 (16); 0 short(text, 255)
//              type 0 host, 1 srflx, 2 prflx, 3 relay
// UDP candidates only; a description with no SHA-256 fingerprint is refused.
const SETUP = ['actpass', 'active', 'passive'];
const TYPES = ['host', 'srflx', 'prflx', 'relay'];
const PRIORITY = [2113937151, 1686052607, 1845501695, 41885439];
const UUID = /^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\.local$/i;

function address(a) {
  const m = UUID.exec(a);
  if (m) return cat(new Uint8Array([1]), hexBytes(m.slice(1).join('')));
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) {
    const parts = a.split('.').map(Number);
    if (parts.every((p) => p <= 255)) return new Uint8Array([4, ...parts]);
  }
  if (a.includes(':')) {
    const six = ipv6(a);
    if (six) return cat(new Uint8Array([6]), six);
  }
  return cat(new Uint8Array([0]), text(a, 255));
}
function readAddress(r) {
  const kind = r.u8();
  if (kind === 1) {
    const h = hexOf(r.bytes(16));
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}.local`;
  }
  if (kind === 4) return Array.from(r.bytes(4)).join('.');
  if (kind === 6) {
    const b = r.bytes(16), groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(((b[i] << 8) | b[i + 1]).toString(16));
    return groups.join(':');
  }
  if (kind === 0) {
    const s = r.text(255);
    if (!/^[A-Za-z0-9.:_-]+$/.test(s)) throw new Error('p-chat: not an address');
    return s;
  }
  throw new Error('p-chat: an address of no known kind');
}
function ipv6(a) {
  const halves = a.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [], right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [...left, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...right];
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return null;
  return Uint8Array.from(groups.flatMap((g) => { const v = parseInt(g, 16); return [v >> 8, v & 255]; }));
}
const hexOf = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const hexBytes = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));

export function compact(sdp) {
  const line = (k) => sdp.split(/\r?\n/).find((l) => l.startsWith('a=' + k + ':'))?.slice(k.length + 3).trim();
  const ufrag = line('ice-ufrag'), pwd = line('ice-pwd'), mid = line('mid') ?? '0', setup = SETUP.indexOf(line('setup'));
  const fp = /^sha-256 ((?:[0-9A-F]{2}:){31}[0-9A-F]{2})$/i.exec(line('fingerprint') || '');
  if (!ufrag || !pwd || setup < 0 || !fp) throw new Error('p-chat: this browser\'s connection cannot be put in a code');
  const candidates = [];
  for (const l of sdp.split(/\r?\n/)) {
    if (!l.startsWith('a=candidate:')) continue;
    const f = l.slice(12).split(' ');
    if (f.length < 8 || f[2].toLowerCase() !== 'udp' || f[1] !== '1') continue;
    const type = TYPES.indexOf(f[7]), port = Number(f[5]);
    if (type < 0 || !(port > 0 && port < 65536)) continue;
    candidates.push(cat(address(f[4]), u16(port), new Uint8Array([type])));
    if (candidates.length === 8) break;
  }
  return cat(new Uint8Array([1, setup]), text(mid, 32), text(ufrag, 256), text(pwd, 256),
    hexBytes(fp[1].replace(/:/g, '')), new Uint8Array([candidates.length]), ...candidates);
}
export function described(bytes) {
  const r = new Reader(bytes);
  if (r.u8() !== 1) throw new Error('p-chat: a code of another version');
  const setup = SETUP[r.u8()];
  if (!setup) throw new Error('p-chat: not a connection');
  const mid = r.text(32), ufrag = r.text(256), pwd = r.text(256);
  const safe = (s) => { if (!/^[A-Za-z0-9+/=_.-]+$/.test(s)) throw new Error('p-chat: not a connection'); return s; };
  const fp = r.bytes(32);
  const n = r.u8();
  if (n > 8) throw new Error('p-chat: too many ways to connect');
  const lines = [];
  for (let i = 0; i < n; i++) {
    const a = readAddress(r), port = r.u16(), t = r.u8();
    if (!TYPES[t] || !port) throw new Error('p-chat: not a way to connect');
    lines.push(`a=candidate:${i + 1} 1 udp ${PRIORITY[t] - i} ${a} ${port} typ ${TYPES[t]}` + (t ? ' raddr 0.0.0.0 rport 0' : ''));
  }
  r.end();
  const id = String(1e15 + Math.floor(Math.random() * 1e15));
  return ['v=0', `o=- ${id} 2 IN IP4 127.0.0.1`, 's=-', 't=0 0', `a=group:BUNDLE ${safe(mid)}`, 'a=msid-semantic: WMS',
    'm=application 9 UDP/DTLS/SCTP webrtc-datachannel', 'c=IN IP4 0.0.0.0',
    `a=ice-ufrag:${safe(ufrag)}`, `a=ice-pwd:${safe(pwd)}`, 'a=ice-options:trickle',
    'a=fingerprint:sha-256 ' + hexOf(fp).toUpperCase().match(/../g).join(':'),
    `a=setup:${setup}`, `a=mid:${mid}`, 'a=sctp-port:5000', 'a=max-message-size:262144', ...lines, 'a=end-of-candidates', '']
    .join('\r\n');
}

// ---- the two codes ----
//   the inviting phone's: a link, https://<site>/#d1.<base64url(u8 1 | short(invite) | short(code) | short(offer))>
//   the other's answer:   p-chat:a1.<base64url(u8 2 | token(16) | short(answer))>
// `invite` is the invite's bytes (protocol §The invite; its relay may be
// empty), `code` the six words, normalized.
export function inPersonLink(origin, invite, code, offer) {
  return origin + '#d1.' + base64url(cat(new Uint8Array([1]), short(invite, 1024), text(code, 128), short(offer, 1024)));
}
export function readInPerson(fragment) {
  if (!fragment.startsWith('d1.')) throw new Error('p-chat: not an in-person code');
  const r = new Reader(unbase64url(fragment.slice(3)));
  if (r.u8() !== 1) throw new Error('p-chat: a code of another version');
  const invite = r.short(1024), code = r.text(128), offer = r.short(1024);
  r.end();
  return { invite, code, offer, token: invite.slice(66, 82) };
}
export function answerCode(token, answer) {
  if (token.length !== 16) throw new Error('p-chat: a token is 16 bytes');
  return 'p-chat:a1.' + base64url(cat(new Uint8Array([2]), token, short(answer, 1024)));
}
export function readAnswer(s) {
  if (!s.startsWith('p-chat:a1.')) throw new Error('That is not the other phone\'s p-chat code.');
  const r = new Reader(unbase64url(s.slice(10)));
  if (r.u8() !== 2) throw new Error('p-chat: a code of another version');
  const token = r.bytes(16), answer = r.short(1024);
  r.end();
  return { token, answer };
}

// ---- the link the two phones make ----
// Frames on it: u8 1 | request box (to the owner) ; u8 2 | envelope (the
// accept) ; u8 3 | room(32) | signal box (the conversation's own signals,
// until its live link is up). Nothing else is taken.
export const FRAME = { request: 1, accept: 2, signal: 3 };
const GATHER_MS = 4000;

export class PairLink {
  constructor(iceServers) {
    this.pc = new RTCPeerConnection({ iceServers: (iceServers || []).map(server) });
    this.channel = null;
    this.onframe = null;
    this.onopen = null;
    this.onclose = null;
    this.pc.onconnectionstatechange = () => {
      if (['failed', 'closed'].includes(this.pc.connectionState)) this.onclose?.();
    };
  }
  get up() { return this.channel?.readyState === 'open'; }
  attach(ch) {
    this.channel = ch;
    ch.binaryType = 'arraybuffer';
    ch.onopen = () => this.onopen?.();
    ch.onclose = () => this.onclose?.();
    ch.onmessage = (e) => {
      if (!(e.data instanceof ArrayBuffer)) return;
      const b = new Uint8Array(e.data);
      if (b.length >= 2 && b.length <= 262144 && b[0] >= 1 && b[0] <= 3) this.onframe?.(b[0], b.slice(1));
    };
  }
  async gathered() {
    if (this.pc.iceGatheringState === 'complete') return;
    await new Promise((done) => {
      const t = setTimeout(done, GATHER_MS);
      this.pc.addEventListener('icegatheringstatechange', () => {
        if (this.pc.iceGatheringState === 'complete') { clearTimeout(t); done(); }
      });
    });
  }
  // The inviting phone: its offer, every candidate in it.
  async offer() {
    this.attach(this.pc.createDataChannel('p-chat-pair', { ordered: true }));
    await this.pc.setLocalDescription(await this.pc.createOffer());
    await this.gathered();
    return compact(this.pc.localDescription.sdp);
  }
  // The other phone: the offer taken, its answer made.
  async answer(offer) {
    this.pc.ondatachannel = (e) => { if (e.channel.label === 'p-chat-pair' && !this.channel) this.attach(e.channel); };
    await this.pc.setRemoteDescription({ type: 'offer', sdp: described(offer) });
    await this.pc.setLocalDescription(await this.pc.createAnswer());
    await this.gathered();
    return compact(this.pc.localDescription.sdp);
  }
  async accept(answer) { await this.pc.setRemoteDescription({ type: 'answer', sdp: described(answer) }); }
  send(kind, body) {
    if (!this.up) return false;
    this.channel.send(cat(new Uint8Array([kind]), body));
    return true;
  }
  close() { try { this.channel?.close(); this.pc.close(); } catch { /* closed */ } }
}
// The same STUN/TURN URIs the engine's transport takes (config.json's ice).
function server(uri) {
  const m = /^(turns?):\/\/([^:]+):([^@]+)@(.+)$/.exec(uri);
  if (m) return { urls: m[1] + ':' + m[4], username: decodeURIComponent(m[2]), credential: decodeURIComponent(m[3]) };
  return { urls: uri.replace('://', ':') };
}
