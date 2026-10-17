// Notifications made on this device (protocol 6). A device that wants to be
// woken has its own VAPID key pair; it tells its conversations where its
// browser's push service reaches it and the key to push with. A member
// whose message cannot go live makes the push itself: the payload sealed
// to the subscription (RFC 8291, aes128gcm, one record) under a VAPID token
// (RFC 8292, ES256). It goes straight to the push service when the browser
// lets it, else the relay carries it as it is - the relay holds no key.

const enc = new TextEncoder();
const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};
export const b64u = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const unb64u = (s) => {
  const t = s.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(t + '='.repeat((4 - (t.length % 4)) % 4)), (x) => x.charCodeAt(0));
};

// This device's VAPID pair. The private half is meant to be shared with the
// conversations' members (sealed, in a signed message): it is made extractable.
export async function vapidKeys() {
  const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', k.privateKey);
  return { private: unb64u(jwk.d), public: new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey)) };
}

async function signer(priv, pub) {
  const jwk = { kty: 'EC', crv: 'P-256', d: b64u(priv), x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)), ext: false };
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

// RFC 8292: a token for the push service's origin, good for 12 hours.
export async function vapidAuthorization(info, now = Date.now()) {
  const aud = new URL(info.endpoint).origin;
  const sub = globalThis.location?.protocol === 'https:' ? location.origin : 'mailto:p-chat@example.invalid';
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(now / 1000) + 12 * 3600, sub })));
  const key = await signer(info.vapidPrivate, info.vapidPublic);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(head + '.' + claims)));
  return 'vapid t=' + head + '.' + claims + '.' + b64u(sig) + ', k=' + b64u(info.vapidPublic);
}

async function hkdf(salt, ikm, info, bytes) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, bytes * 8));
}

// RFC 8291: one aes128gcm record, sealed to the subscription's key and secret.
export async function seal(info, plain) {
  const e = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const ephemeral = new Uint8Array(await crypto.subtle.exportKey('raw', e.publicKey));
  const theirs = await crypto.subtle.importKey('raw', info.p256dh, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: theirs }, e.privateKey, 256));
  const ikm = await hkdf(info.auth, shared, cat(enc.encode('WebPush: info\0'), info.p256dh, ephemeral), 32);
  shared.fill(0);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  ikm.fill(0);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  cek.fill(0);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, cat(plain, new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]);  // record size 4096
  return cat(salt, rs, new Uint8Array([ephemeral.length]), ephemeral, sealed);
}

// Made and sent: "direct", "relayed", "gone" (the subscription has ended)
// or "failed". `forward(endpoint, authorization, body)` is the relay's.
export async function send(info, payload, forward) {
  const body = await seal(info, payload);
  const authorization = await vapidAuthorization(info);
  try {
    const r = await fetch(info.endpoint, {
      method: 'POST', mode: 'cors', credentials: 'omit', referrerPolicy: 'no-referrer', body,
      headers: { Authorization: authorization, TTL: '86400', Urgency: 'high', 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream' },
      // A push service that does not answer is given up on, not waited for.
      signal: AbortSignal.timeout?.(10000),
    });
    if (r.ok) return 'direct';
    if (r.status === 404 || r.status === 410) return 'gone';
  } catch { /* not allowed from a page (CORS, the CSP): the relay carries it */ }
  if (!forward) return 'failed';
  return (await forward(info.endpoint, authorization, body).catch(() => false)) ? 'relayed' : 'failed';
}

// Where this browser's push service reaches this device, for its own VAPID key.
export async function subscribe(vapidPublic) {
  const reg = await navigator.serviceWorker.ready;
  let sub = await reg.pushManager.getSubscription();
  const same = (k) => k && b64u(new Uint8Array(k)) === b64u(vapidPublic);
  if (sub && !same(sub.options?.applicationServerKey)) { await sub.unsubscribe(); sub = null; }
  sub = sub || (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: vapidPublic }));
  const j = sub.toJSON();
  return { endpoint: j.endpoint, p256dh: unb64u(j.keys.p256dh), auth: unb64u(j.keys.auth) };
}

// An iPhone or iPad in a browser tab: Web Push only once p-chat is on the Home Screen.
export function needsHomeScreen() {
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const standalone = navigator.standalone === true || globalThis.matchMedia?.('(display-mode: standalone)').matches;
  return ios && !standalone;
}
