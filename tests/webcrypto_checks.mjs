// What the browser does with its own keys, checked against the vectors: the
// same checks run under Node (tests/node_vectors.mjs) and in a real browser
// (tests/test_browser.py). WebCrypto makes every Ed25519 signature and every
// X25519 shared secret; Wasm makes everything else; the bytes must be the
// native vectors' bytes.
//
// The private keys here are test keys, imported only for the check.

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s) => new Uint8Array(s.match(/../g).map((x) => parseInt(x, 16)));
const fill = (b, n = 32) => new Uint8Array(Array.from({ length: n }, (_, i) => (b + i) & 255));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
const PKCS8 = {
  Ed25519: unhex('302e020100300506032b657004220420'),
  X25519: unhex('302e020100300506032b656e04220420'),
};

async function importPrivate(alg, raw) {
  const usages = alg === 'Ed25519' ? ['sign'] : ['deriveBits'];
  return crypto.subtle.importKey('pkcs8', concat(PKCS8[alg], raw), { name: alg }, true, usages);
}
async function publicOf(key) {
  const jwk = await crypto.subtle.exportKey('jwk', key);
  const b64 = jwk.x.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
}
async function sign(key, statement) {
  return new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, key, statement));
}
async function derive(secret, pub) {
  const theirs = await crypto.subtle.importKey('raw', pub, { name: 'X25519' }, true, []);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: theirs }, secret, 256));
}

export async function check(chat, made, kept) {
  const fails = [];
  const ok = (cond, what) => { if (!cond) fails.push(what); };
  // 1. Wasm made every vector, byte for byte.
  const names = Object.keys(kept);
  ok(Object.keys(made).length === names.length, 'as many vectors as the file');
  for (const k of names) ok(made[k] === kept[k], 'vector ' + k);
  const v = (k) => unhex(kept[k]);

  // 2. WebCrypto's keys are the test keys' keys; device ids from Wasm.
  const keys = {};
  for (const who of ['owner', 'friend', 'friend2']) {
    const sign_ = await importPrivate('Ed25519', v(who + '.seed'));
    const agree = await importPrivate('X25519', v(who + '.secret'));
    keys[who] = { sign: sign_, agree };
    ok(hex(await publicOf(sign_)) === kept[who + '.sign'], who + ' Ed25519 public key');
    ok(hex(await publicOf(agree)) === kept[who + '.agree'], who + ' X25519 public key');
    ok(hex(chat.deviceId(v(who + '.sign'), v(who + '.agree'))) === kept[who + '.id'], who + ' device id');
  }

  // 3. Every signature, made by WebCrypto, is the vector's.
  const signs = [
    ['friend', 'request.statement', 'request.signature'],
    ['owner', 'accept.statement', 'accept.signature'],
    ['friend', 'message.statement', 'message.signature'],
  ];
  const proposer = kept['history.proposer'] === kept['owner.id'] ? 'owner' : 'friend';
  signs.push([proposer, 'history.statement', 'history.signature']);
  signs.push([proposer, 'history.certificate', 'history.certificate.signature']);
  signs.push([proposer, 'history.attestation', 'history.attestation.signature']);
  for (const [who, statement, signature] of signs)
    ok(hex(await sign(keys[who].sign, v(statement))) === kept[signature], 'WebCrypto signature ' + signature);
  const signal = v('signal.bytes');
  ok(hex(await sign(keys.owner.sign, v('signal.statement'))) === hex(signal.slice(signal.length - 64)), 'signal signature');
  // ... and Wasm checks what WebCrypto signed.
  ok(chat.ed25519Check(v('friend.sign'), v('message.statement'), v('message.signature')), 'Wasm checks a WebCrypto signature');
  ok(!chat.ed25519Check(v('owner.sign'), v('message.statement'), v('message.signature')), 'and refuses another key');

  // 4. Every X25519: WebCrypto's shared secrets seal the vectors' boxes.
  ok(hex(await derive(keys.owner.agree, v('friend.agree'))) === kept['ratchet.static'], 'static shared secret');
  ok(hex(await derive(keys.friend.agree, v('owner.agree'))) === kept['ratchet.static'], 'static shared secret, the other way');
  const boxes = [
    ['request', 0x71, 0x81, 'owner', chat.pad(v('request.bytes')), 'request.box'],
    ['accept', 0x72, 0x82, 'friend', chat.pad(v('accept.bytes')), 'accept.box'],
    ['message', 0x73, 0x83, 'owner', chat.pad(v('frame.v2')), null],
  ];
  for (const [purpose, eph, nonce, to, plain, name] of boxes) {
    const e = await importPrivate('X25519', fill(eph));
    const shared = await derive(e, v(to + '.agree'));
    const box = chat.sealFixed(purpose, v(to + '.agree'), plain, await publicOf(e), shared, fill(nonce, 24));
    if (name) ok(hex(box) === kept[name], 'WebCrypto-sealed ' + name);
    else ok(hex(chat.envelope(2, v('mailbox.owner.19000'), box)) === kept['envelope.v2'], 'WebCrypto-sealed envelope.v2');
    // The recipient opens it with its own key, in WebCrypto.
    const back = chat.openBox(purpose, await derive(keys[to].agree, await publicOf(e)), v(to + '.agree'), box);
    ok(hex(chat.unpad(back)) === hex(chat.unpad(plain)), 'opened ' + purpose);
  }
  // A small-order key is refused by WebCrypto as it is by Wasm.
  let refused = false;
  try { await derive(keys.owner.agree, new Uint8Array(32)); } catch { refused = true; }
  ok(refused, 'WebCrypto refuses a small-order X25519 key');

  // 5. The pairing code's Argon2id, and a keyed BLAKE2b, in Wasm.
  const invite = chat.parseInvite(kept['invite.fragment']);
  ok(invite.relay === 'wss://relay.example/chat' && invite.owner === kept['owner.id'], 'invite parsed');
  const t0 = Date.now();
  const domain = new TextEncoder().encode('sg.chat.v1.pair.code');
  const pk = chat.argon2id(chat.normalizeCode(kept['code.words']), fill(0x51),
    concat(new Uint8Array([domain.length]), domain, fill(0x41, 16)));
  const argonMs = Date.now() - t0;
  ok(hex(pk) === kept['pair.key'], 'pair key');
  ok(chat.normalizeCode(kept['code.typed']) === kept['code.typed.normal'], 'code normalized');
  // A release signature's bytes: web/release.js writes the engine's own
  // Observation statement, and its hashes are the release tool's.
  const R = globalThis.pchatRelease;
  ok(!!R, 'release.js is loaded');
  if (R) {
    for (const [k, version] of [['ab'.repeat(32), 1], ['0f'.repeat(32), 7], ['9c'.repeat(32), 4294967297]]) {
      const h = new Uint8Array(32).map((_, i) => (i * 7 + version) & 255);
      ok(hex(await R.statement(k, version, h)) === hex(chat.releaseStatement(k, version, h)), 'release statement ' + version + ' is the engine\'s');
    }
    const r = { version: 3, manifest: '1'.repeat(64), sw: '2'.repeat(64), previous: R.ZERO, committee: { keys: ['b'.repeat(64), 'a'.repeat(64)], quorum: 2 }, signatures: [] };
    ok(R.canonical(r) === '{"committee":{"keys":["' + 'a'.repeat(64) + '","' + 'b'.repeat(64) + '"],"quorum":2},"manifest":"' + '1'.repeat(64) +
      '","previous":"' + R.ZERO + '","sw":"' + '2'.repeat(64) + '","version":3}', 'a release body is canonical JSON, keys sorted');
  }
  return { fails, argonMs };
}
