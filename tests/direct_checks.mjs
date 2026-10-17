// Protocols 10 and 11, in Node: the in-person codes (web/direct.js) and contacts
// carrying for each other (web/carry.js) - every frame read back as made,
// what is refused, and a carrier's rules, with its links and store faked.
//
//   node tests/direct_checks.mjs <web dir>
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const web = process.argv[2];
const d = await import(pathToFileURL(join(web, 'direct.js')).href);
const k = await import(pathToFileURL(join(web, 'carry.js')).href);
const fails = [];
const ok = (cond, what) => { console.log((cond ? 'ok   ' : 'FAIL ') + what); if (!cond) fails.push(what); };
const refused = (f) => { try { f(); return false; } catch { return true; } };
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// ---- descriptions, as three browsers write them ----
const FP = 'B3:B0:98:8C:5B:EE:25:73:AC:95:39:E4:64:C0:59:56:15:12:68:48:9E:11:5D:F5:B8:CA:01:57:42:5A:37:41';
const chrome = `v=0\r\no=- 8835791327787690821 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS\r
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r
a=candidate:1717676752 1 udp 2113937151 01b55c97-947a-44f2-809f-5b4881092149.local 58723 typ host generation 0 network-cost 999\r
a=candidate:842163049 1 udp 1677729535 203.0.113.7 58723 typ srflx raddr 0.0.0.0 rport 0 generation 0 network-cost 999\r
a=candidate:3 1 tcp 1518280447 01b55c97-947a-44f2-809f-5b4881092149.local 9 typ host tcptype active generation 0\r
a=ice-ufrag:Cc2x\r\na=ice-pwd:8Ahfb+c89q9ego9B9GuR3X7K\r\na=ice-options:trickle\r\na=fingerprint:sha-256 ${FP}\r
a=setup:actpass\r\na=mid:0\r\na=sctp-port:5000\r\na=max-message-size:262144\r\n`;
const firefox = `v=0\r\no=mozilla...THIS_IS_SDPARTA-99.0 7651419434183424352 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=sendrecv\r
a=fingerprint:sha-256 ${FP}\r\na=group:BUNDLE 0\r\na=ice-options:trickle\r\na=msid-semantic:WMS *\r
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r
a=candidate:0 1 UDP 2122252543 192.168.1.20 54321 typ host\r
a=candidate:1 1 UDP 2122187007 2001:db8::1:2 54322 typ host\r
a=candidate:2 1 TCP 2105524479 192.168.1.20 9 typ host tcptype active\r
a=sendrecv\r\na=end-of-candidates\r\na=ice-pwd:4c5b3b2f3d1e4c6a8e0e2b2f9a7c1d3e\r\na=ice-ufrag:9a1b2c3d\r\na=mid:0\r\na=setup:active\r
a=sctp-port:5000\r\na=max-message-size:1073741823\r\n`;
const safari = chrome.replace('a=setup:actpass', 'a=setup:passive').replace(/a=candidate:842[^\r]*\r\n/, '');

for (const [name, sdp] of [['Chrome', chrome], ['Firefox', firefox], ['Safari', safari]]) {
  const c = d.compact(sdp);
  const again = d.described(c);
  ok(same(d.compact(again), c), name + ': its description, made again from the code, says the same');
  const lines = again.split('\r\n');
  const want = (l) => lines.includes(l);
  ok(want('a=fingerprint:sha-256 ' + FP) && lines.filter((l) => l.startsWith('a=candidate:')).every((l) => / udp /.test(l)),
    name + ': the fingerprint kept, UDP candidates only');
  ok(c.length < 120, name + ': the code is small (' + c.length + ' bytes)');
}
const ff = d.described(d.compact(firefox)).split('\r\n');
ok(ff.includes('a=setup:active') && ff.some((l) => l.includes(' 2001:db8:0:0:0:0:1:2 54322 typ host')) && ff.some((l) => l.includes(' 192.168.1.20 54321 typ host')),
  'IPv4 and IPv6 addresses, ports and the role carried');
const cr = d.described(d.compact(chrome)).split('\r\n');
ok(cr.some((l) => l.includes(' 01b55c97-947a-44f2-809f-5b4881092149.local 58723 typ host')) &&
  cr.some((l) => l.includes(' 203.0.113.7 58723 typ srflx raddr 0.0.0.0 rport 0')), 'an mDNS name and a reflexive address carried');
ok(refused(() => d.compact(chrome.replace('sha-256', 'sha-1'))), 'a description without a SHA-256 fingerprint is refused');
ok(refused(() => d.compact(chrome.replace(/a=ice-pwd[^\r]*\r\n/, ''))), 'a description without its ICE password is refused');
const good = d.compact(chrome);
ok(refused(() => d.described(good.slice(0, -1))), 'a code cut short is refused');
ok(refused(() => d.described(Uint8Array.from([...good, 0]))), 'a code with more than it should is refused');
ok(refused(() => d.described(Uint8Array.from([2, ...good.slice(1)]))), 'a code of another version is refused');
const evil = d.compact(chrome.replace('a=ice-ufrag:Cc2x', 'a=ice-ufrag:Cc2x\r\na=ice-ufrag:x'));
ok(d.described(evil).includes('a=ice-ufrag:Cc2x'), 'only the first of a field is taken');
ok(refused(() => d.described(d.compact(chrome.replace('a=ice-ufrag:Cc2x', 'a=ice-ufrag:C c\nx')))), 'a field that would add a line is refused');

// ---- the two codes ----
const invite = Uint8Array.from({ length: 112 }, (_, i) => i);
const link = d.inPersonLink('https://chat.example/', invite, 'abandon ability able about above absent', good);
const got = d.readInPerson(link.split('#')[1]);
ok(same(got.invite, invite) && got.code === 'abandon ability able about above absent' && same(got.offer, good) && same(got.token, invite.slice(66, 82)),
  'the inviting phone\'s code: invite, words, offer and token read back');
ok(link.length < 420, 'and it is short enough for a code a phone reads off a screen (' + link.length + ' characters)');
ok(refused(() => d.readInPerson('v1.' + link.split('#d1.')[1])), 'a code that is not an in-person one is refused');
ok(refused(() => d.readInPerson('d1.' + link.split('#d1.')[1] + 'A')), 'one changed is refused');
const answer = d.answerCode(got.token, good);
const back = d.readAnswer(answer);
ok(same(back.token, got.token) && same(back.answer, good), 'the answer code: token and answer read back');
ok(refused(() => d.readAnswer('https://chat.example/#d1.AAAA')), 'a code that is not an answer is refused');
const token = rnd16();
const relink = d.relinkLink('https://chat.example/', token, good);
const rl = d.readRelink(relink.split('#')[1]);
ok(same(rl.token, token) && same(rl.offer, good) && relink.length < 260, 'the code to link again in person: token and offer read back (' + relink.length + ' characters)');
ok(refused(() => d.readRelink('d1.' + relink.split('#l1.')[1])) && refused(() => d.readRelink(relink.split('#')[1] + 'A')) &&
  refused(() => d.readInPerson('d1.' + relink.split('#l1.')[1])), 'it is not taken for another code, nor one changed');
function rnd16() { return Uint8Array.from({ length: 16 }, (_, i) => i * 13 + 1); }
ok(refused(() => d.unbase64url('AB=C')) && refused(() => d.unbase64url('AB')) && same(d.unbase64url('AA'), [0]), 'base64url: canonical only');

// ---- carrying ----
const rnd = (n, b) => Uint8Array.from({ length: n }, (_, i) => (b * 31 + i * 7) & 255);
const env = (b, size = 1 + 32 + 72 + 1024) => { const e = rnd(size, b); e[0] = 2; return e; };
const handle = (e) => e.slice(1, 17).map((x) => x ^ e[e.length - 1]);  // a stand-in for BLAKE2b
let clock = 1000;
function phone(name, net) {
  const kept = new Map(), heard = [], opened = [];
  const io = {
    send: (p, f) => { if (!net.links.has(name + '|' + p)) return false; net.queue.push([p, name, f]); return true; },
    peers: () => [...net.links].filter((l) => l.startsWith(name + '|')).map((l) => l.split('|')[1]),
    rooms: () => net.rooms[name] || [],
    mailboxes: () => net.boxes[name] || [],
    signalIn: (room, box) => heard.push([room, box]),
    open: async (e) => { opened.push(e); return 'accepted'; },
    handle, helping: () => !net.selfish.has(name),
    keep: { list: async () => [...kept.values()], put: async (h) => kept.set(h.key, h), drop: async (key) => kept.delete(key) },
    now: () => clock,
  };
  const carry = new k.Carry(io);
  net.phones[name] = carry;
  return { carry, kept, heard, opened };
}
const net = { links: new Set(), queue: [], phones: {}, rooms: {}, boxes: {}, selfish: new Set() };
const link2 = (a, b) => { net.links.add(a + '|' + b); net.links.add(b + '|' + a); };
const flush = async () => { const out = []; while (net.queue.length) { const [to, from, f] = net.queue.shift(); out.push(await net.phones[to].frame(from, f)); } return out; };
const X = phone('x', net), Y = phone('y', net), H = phone('h', net);
const roomXY = { room: rnd(32, 1), label: rnd(32, 2) }, roomY = { room: rnd(32, 1), label: rnd(32, 3) };
net.rooms.y = [roomY];
link2('x', 'h');
link2('y', 'h');
for (const p of ['x', 'y', 'h']) await net.phones[p].tick();
await flush();
ok(H.carry.reach.get('y')?.size === 1, 'a contact hears where to reach a phone it is linked with');
net.rooms.y = [roomY, { room: rnd(32, 20), label: rnd(32, 21) }];
await Y.carry.tick();
await flush();
ok(H.carry.reach.get('y')?.size === 2, 'and hears again at once when its rooms change');
net.rooms.y = [roomY];
await Y.carry.tick();
await flush();
ok(X.carry.signal({ peer: 'y', room: roomXY.room, label: roomY.label, box: rnd(300, 4) }) === 1, 'a signal for a phone not linked here goes to the contacts that are');
const passed = await flush();
ok(passed.includes('passed') && Y.heard.length === 1 && same(Y.heard[0][1], rnd(300, 4)), 'the contact passes it on, and only to the phone in that room');
X.carry.signal({ peer: 'y', room: roomXY.room, label: rnd(32, 9), box: rnd(300, 5) });
ok((await flush()).includes('nowhere') && Y.heard.length === 1, 'a signal for a room no linked phone is in goes nowhere');
link2('x', 'y');
X.carry.signal({ peer: 'y', room: roomXY.room, label: roomY.label, box: rnd(300, 6) });
await flush();
ok(Y.heard.length === 3, 'linked to it: the signal goes to it directly (and through the contact too)');
net.links.delete('x|y'); net.links.delete('y|x');
ok(H.carry.reach.has('x'), 'a contact knows each phone it is linked with');
net.links.delete('x|h'); net.links.delete('h|x');
await H.carry.tick();
ok(!H.carry.reach.has('x'), 'and forgets where to reach one whose link is gone');
link2('x', 'h');
await X.carry.tick(); await H.carry.tick(); await flush();

// Held for a phone that is away.
const mailboxY = rnd(32, 7);
const e1 = env(11); e1.set(mailboxY, 1);
net.links.delete('y|h'); net.links.delete('h|y');
ok(X.carry.hold(e1, 'y') === 1, 'an envelope for a phone that is away is given to a linked contact');
ok((await flush())[0] === 'held' && H.kept.size === 1, 'the contact keeps it');
X.carry.hold(e1, 'y'); await flush();
ok(H.kept.size === 1, 'the same envelope twice is kept once');
ok(await H.carry.frame('x', k.frames.hold(rnd(500, 1))) === 'refused', 'what is not a relay\'s envelope is not kept');
net.boxes.y = [mailboxY, rnd(32, 8)];
link2('y', 'h');
clock += 9000;
await Y.carry.tick();
await flush();
await flush();
ok(Y.opened.length === 1 && same(Y.opened[0], e1), 'back, the phone asks for its mailboxes and is given what was kept');
ok(H.kept.size === 0, 'opened, it is dropped where it was kept');

// Bounds.
let full = 0;
for (let i = 0; i < 130; i++) {
  if (i % 50 === 0) clock += 61e3;
  const e = env(100 + i); e.set(rnd(32, 50 + i), 1);
  if ((await H.carry.frame('x', k.frames.hold(e))) === 'full') full++;
}
ok(H.kept.size === 128 && full === 2, 'one giver has at most 128 kept');
let refusedRate = 0;
for (let i = 0; i < 70; i++) { const e = env(400 + i); if ((await H.carry.frame('y', k.frames.hold(e))) === 'refused') refusedRate++; }
ok(refusedRate === 10, 'at most 60 a minute from one giver');
clock += LIMITS_TTL();
await H.carry.tick();
ok(H.kept.size === 0, 'kept 14 days at most');
function LIMITS_TTL() { return k.LIMITS.ttl + 1; }

// A phone that does not carry.
net.selfish.add('h');
X.carry.signal({ peer: 'y', room: roomXY.room, label: roomY.label, box: rnd(300, 12) });
const before = Y.heard.length;
ok((await flush()).includes('refused') && Y.heard.length === before, 'a phone that does not carry passes nothing on');
ok(await H.carry.frame('x', k.frames.hold(env(900))) === 'refused', 'and keeps nothing');
ok(await H.carry.frame('x', k.frames.signal(roomXY.room, rnd(10, 1))) === 'ok', 'but takes what is for it');

// Frames: each read back as made; the rest refused.
const m = (f) => k.read(f);
ok(m(k.frames.rooms([roomXY])).rooms.length === 1 && m(k.frames.pass(roomXY.room, roomXY.label, rnd(9, 1))).box.length === 9 &&
  m(k.frames.ask([mailboxY])).mailboxes.length === 1 && m(k.frames.taken(mailboxY, [rnd(16, 1)])).handles.length === 1,
  'every frame reads back as made');
ok(!m(new Uint8Array([99, 0])) && !m(k.frames.rooms([roomXY]).slice(0, -1)) && !m(k.frames.pass(roomXY.room, roomXY.label, new Uint8Array(0))) &&
  !m(k.frames.signal(roomXY.room, new Uint8Array(k.LIMITS.box + 1))), 'a frame of no known kind, cut short, empty or too large is refused');
const g = k.frames.given(rnd(32, 1), rnd(16, 1), e1);
ok(!m(g), 'a kept envelope given under another mailbox than its own is refused');

// ---- a device that relays (protocol 11) ----
{
  const net = { links: new Set(), queue: [], phones: {}, rooms: {}, boxes: {}, selfish: new Set() };
  const link2 = (a, b) => { net.links.add(a + '|' + b); net.links.add(b + '|' + a); };
  const cut = (a, b) => { net.links.delete(a + '|' + b); net.links.delete(b + '|' + a); };
  const flush = async () => { const out = []; while (net.queue.length) { const [to, from, f] = net.queue.shift(); out.push(await net.phones[to].frame(from, f)); } return out; };
  const served = new Map(), near = [];
  let relaying = true;
  // R relays (its memory of where contacts are reached in `served`); A, B and O are phones.
  const mk = (name, extra = {}) => {
    const p = phone(name, net);
    Object.assign(p.carry.io, extra);
    return p;
  };
  const R = mk('r', { relaying: () => relaying, served: { list: async () => [...served.values()], put: async (x) => served.set(x.key, x), drop: async (key) => served.delete(key) } });
  const A = mk('a', { near: (peer, rooms) => near.push([peer, rooms]) }), B = mk('b'), O = mk('o');
  const ab = rnd(32, 61), labelA = rnd(32, 62), labelB = rnd(32, 63), ro = rnd(32, 64);
  net.rooms.a = [{ room: ab, label: labelA }];
  net.rooms.b = [{ room: ab, label: labelB }];
  net.rooms.o = [{ room: ro, label: rnd(32, 65) }];
  link2('r', 'a'); link2('r', 'b'); link2('r', 'o'); link2('a', 'o');
  const round = async () => { for (const p of ['r', 'a', 'b', 'o']) await net.phones[p].tick(); await flush(); };
  await round();
  await round();
  ok(same(A.carry.relays(), ['r']) && !O.carry.relaying.get('a'), 'a device that relays says so; a phone that does not says nothing');
  ok(served.size === 3, 'it remembers where each contact\'s device is reached');
  const toA = A.carry.serving.get('r');
  ok(toA?.length === 1 && same(toA[0].label, labelB) && toA[0].now, 'to a contact it says the devices of that contact\'s own chats it keeps mail for, and that one is linked now');
  ok(!(O.carry.serving.get('r') || []).length, 'and nothing of chats the contact is not in');
  ok(near.some(([p, rooms]) => p === 'r' && rooms.includes(Array.from(ab, (x) => x.toString(16).padStart(2, '0')).join(''))),
    'a contact is told a device of its chat is near, to find it again through the relaying device');
  ok(A.carry.servedIn(Array.from(ab, (x) => x.toString(16).padStart(2, '0')).join('')).size === 1, 'so a message for it can be kept there');
  // B away: it is still served (remembered), no longer near.
  cut('r', 'b');
  clock += 61e3;
  await round();
  const later = A.carry.serving.get('r');
  ok(later?.length === 1 && !later[0].now, 'away, a device is still kept for, and no longer said to be near');
  // Holding: relaying contacts first, whatever their number.
  const eR = env(700); eR.set(rnd(32, 66), 1);
  ok(A.carry.hold(eR, 'b') === 2 && (await flush()).filter((x) => x === 'held').length === 2 && R.kept.size === 1, 'an envelope goes to the device that relays (and others)');
  const eR2 = env(701);
  ok(A.carry.hold(eR2, 'b', true) === 1 && (await flush())[0] === 'held' && R.kept.size === 2 && O.kept.size === 1, 'given again: to the device that relays only');
  // It takes a relay's share, not a phone's.
  let kept = 0;
  for (let i = 0; i < 200; i++) { if (i % 250 === 0) clock += 61e3; const e = env(800 + i); e.set(rnd(32, 90 + i), 1); if ((await R.carry.frame('o', k.frames.hold(e))) === 'held') kept++; }
  ok(kept === 200, 'a device that relays keeps more than a phone would from one giver (' + kept + ')');
  // A serves frame from a contact that never said it relays is not believed.
  ok(await O.carry.frame('a', k.frames.serves([{ room: ab, label: labelB, now: true }])) === 'refused', 'what one that does not relay says it serves is refused');
  // Turned off: it says so, and forgets what it remembered of others.
  relaying = false;
  await round();
  ok(!A.carry.relays().length && served.size === 0 && R.carry.served === null, 'turned off, it says so and forgets where its contacts were reached');
  // Frames.
  const sv = k.frames.serves([{ room: ab, label: labelB, now: true }, { room: ro, label: labelA, now: false }]);
  const back = k.read(sv);
  ok(back.devices.length === 2 && back.devices[0].now && !back.devices[1].now && same(back.devices[1].label, labelA) && k.read(k.frames.relays(1)).flags === 1,
    'relays and serves read back as made');
  const bad = sv.slice(); bad[2 + 64 + 1] = 2;
  ok(!k.read(bad) && !k.read(new Uint8Array([8, 2])) && !k.read(new Uint8Array([8, 1, 0])) && !k.read(sv.slice(0, -1)), 'a flag or a now of no meaning, or a frame cut short, is refused');
}

// ---- carried within the chat (protocol 13) ----
{
  const net = { links: new Set(), queue: [], phones: {}, rooms: {}, boxes: {}, selfish: new Set(), members: {} };
  const link2 = (a, b) => { net.links.add(a + '|' + b); net.links.add(b + '|' + a); };
  const cut = (a, b) => { net.links.delete(a + '|' + b); net.links.delete(b + '|' + a); };
  const flush = async () => { const out = []; while (net.queue.length) { const [to, from, f] = net.queue.shift(); out.push(await net.phones[to].frame(from, f)); } return out; };
  let ids = 0;
  const mk = (name) => {
    const p = phone(name, net);
    Object.assign(p.carry.io, { members: () => net.members[name] || [], id: () => rnd(16, 200 + ids++) });
    return p;
  };
  // A group: A, M1, M2 and B are in it; O is a contact of A and of B, not in it.
  const A = mk('a'), M1 = mk('m1'), M2 = mk('m2'), B = mk('b'), O = mk('o');
  const g = rnd(32, 150), lab = (b) => rnd(32, b);
  for (const [n, b] of [['a', 151], ['m1', 152], ['m2', 153], ['b', 154]]) net.rooms[n] = [{ room: g, label: lab(b) }];
  net.rooms.o = [{ room: rnd(32, 160), label: lab(161) }];
  const mB = rnd(32, 170);
  for (const n of ['a', 'm1', 'm2']) net.members[n] = [mB];
  net.boxes.b = [mB];
  const all = ['a', 'm1', 'm2', 'b', 'o'];
  const round = async () => { for (const p of all) await net.phones[p].tick(); await flush(); await flush(); };
  // A stranger's way: A - O - B, O not in the chat.
  link2('a', 'o'); link2('o', 'm2'); link2('m2', 'b');
  await round();
  A.carry.signal({ peer: 'b', room: g, label: lab(154), box: rnd(300, 171) });
  ok((await flush()).includes('nowhere') && B.heard.length === 0, 'a signal goes no further than a contact who is not in the chat');
  // A member's way: A - M1 - M2 - B.
  cut('o', 'm2'); link2('a', 'm1'); link2('m1', 'm2');
  await round();
  A.carry.signal({ peer: 'b', room: g, label: lab(154), box: rnd(300, 172) });
  let out = [];
  for (let i = 0; i < 4; i++) out.push(...(await flush()));
  ok(out.includes('hopped') && out.includes('passed') && B.heard.length === 1 && same(B.heard[0][1], rnd(300, 172)),
    'through the chat\'s members, over more than one link, it reaches its device');
  ok(await M1.carry.frame('a', k.frames.hop(4, rnd(16, 200 + ids - 1), g, lab(154), rnd(9, 1))) === 'seen', 'a hop seen already is passed on no more');
  ok(await O.carry.frame('a', k.frames.hop(4, rnd(16, 300), g, lab(154), rnd(9, 1))) === 'refused', 'and one not of its chats is refused by a contact');
  const end = await M2.carry.frame('m1', k.frames.hop(1, rnd(16, 301), g, lab(999 % 256), rnd(9, 1)));
  ok(end === 'nowhere', 'a hop with no link left is passed on no more');
  // Mail: A gives it to M1; M2 gathers it; B, back, takes it from M2.
  cut('m2', 'b');
  const eB = env(180); eB.set(mB, 1);
  ok(A.carry.hold(eB, 'b') >= 1, 'an envelope for a device that is away is given to the contacts linked');
  await flush();
  ok(M1.kept.size === 1 && O.kept.size === 1, 'kept by those it was given to');
  clock += 16e3;
  await round();
  ok(M2.kept.size === 1, 'a member gathers it from another for its chat\'s device');
  ok(await O.carry.frame('m1', k.frames.share(handle(eB), eB)) === 'refused', 'a contact who is not in the chat takes none of its mail shared');
  const big = env(181, 1 + 32 + 72 + 262144); big.set(mB, 1);
  await M1.carry.frame('a', k.frames.hold(big));
  clock += 16e3;
  await round();
  ok(M1.kept.size === 2 && M2.kept.size === 1, 'a file\'s pieces are not gathered, only messages');
  cut('m1', 'm2'); link2('m2', 'b');
  clock += 9e3;
  await round();
  ok(B.opened.length === 1 && same(B.opened[0], eB) && M2.kept.size === 0, 'back, the device takes it from the member that gathered it');
  // M1 still keeps a copy: told it was opened, it drops it.
  cut('m2', 'b'); link2('m1', 'm2');
  clock += 16e3;
  await round();
  ok(M1.kept.size === 1 && !M1.kept.has(Array.from(mB, (x) => x.toString(16).padStart(2, '0')).join('') +
    Array.from(handle(eB), (x) => x.toString(16).padStart(2, '0')).join('')), 'one opened is dropped by the other members who keep it');
  clock += 16e3;
  await round();
  ok(M2.kept.size === 0, 'and not gathered again');
  // Frames.
  const gf = k.read(k.frames.gather([mB, g], [rnd(16, 1)], [rnd(16, 2), rnd(16, 3)]));
  const hf = k.read(k.frames.hop(3, rnd(16, 4), g, lab(5), rnd(7, 6)));
  ok(gf.mailboxes.length === 2 && gf.have.length === 1 && gf.gone.length === 2 && hf.left === 3 && hf.box.length === 7 &&
    same(k.read(k.frames.share(handle(eB), eB)).envelope, eB), 'gather, share and hop read back as made');
  ok(!k.read(k.frames.hop(5, rnd(16, 4), g, lab(5), rnd(7, 6))) && !k.read(k.frames.hop(0, rnd(16, 4), g, lab(5), rnd(7, 6))) &&
    !k.read(k.frames.share(handle(big), big)) && !k.read(k.frames.gather([mB], [], []).slice(0, -1)),
    'a hop with too many links or none left, a file\'s piece shared, or a gather cut short is refused');
}

if (fails.length) { console.log(`sgchat_direct: ${fails.length} failed`); process.exit(1); }
console.log('sgchat_direct: ok');
