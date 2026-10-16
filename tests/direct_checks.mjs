// Protocol 10, in Node: the in-person codes (web/direct.js) and contacts
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
ok(!m(new Uint8Array([9, 0])) && !m(k.frames.rooms([roomXY]).slice(0, -1)) && !m(k.frames.pass(roomXY.room, roomXY.label, new Uint8Array(0))) &&
  !m(k.frames.signal(roomXY.room, new Uint8Array(k.LIMITS.box + 1))), 'a frame of no known kind, cut short, empty or too large is refused');
const g = k.frames.given(rnd(32, 1), rnd(16, 1), e1);
ok(!m(g), 'a kept envelope given under another mailbox than its own is refused');

if (fails.length) { console.log(`sgchat_direct: ${fails.length} failed`); process.exit(1); }
console.log('sgchat_direct: ok');
