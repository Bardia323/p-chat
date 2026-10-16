// The device's keys, and everything done with them. They are WebCrypto
// CryptoKeys made with `extractable: false` and kept in IndexedDB as
// CryptoKeys: no page script can read their bytes, and none ever reaches
// Wasm. What leaves here is what one operation needs: a signature, or the
// result of one X25519 (a shared secret).
//
// Also the key that keeps this device's history encrypted at rest: AES-GCM,
// 256 bits, non-extractable, made once.

export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export const unhex = (s) => new Uint8Array((s.match(/../g) || []).map((x) => parseInt(x, 16)));

const DB = 'p-chat';
// Schema 2 added files: `blobs` (what each file is, sealed) and `chunks`
// (its sealed chunks, as they travel). Opening an older database adds them.
const SCHEMA = 2;
const STORES = ['keys', 'records', 'messages', 'meta', 'blobs', 'chunks'];

let dbPromise = null;
export function db() {
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      const open = indexedDB.open(DB, SCHEMA);
      open.onupgradeneeded = () => {
        for (const s of STORES) if (!open.result.objectStoreNames.contains(s)) open.result.createObjectStore(s);
      };
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error);
    });
  }
  return dbPromise;
}
export async function idb(store, mode, run) {
  const d = await db();
  return new Promise((resolve, reject) => {
    const tx = d.transaction(store, mode);
    const req = run(tx.objectStore(store));
    tx.oncomplete = () => resolve(req ? req.result : undefined);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}
export const get = (store, key) => idb(store, 'readonly', (s) => s.get(key));
export const put = (store, key, value) => idb(store, 'readwrite', (s) => s.put(value, key));
export const del = (store, key) => idb(store, 'readwrite', (s) => s.delete(key));
export const all = (store) => idb(store, 'readonly', (s) => s.getAll());
export const allKeys = (store) => idb(store, 'readonly', (s) => s.getAllKeys());

// Both curves, or nothing: there is no other curve to fall back to.
export async function supported() {
  try {
    if (!globalThis.crypto?.subtle || !globalThis.indexedDB) return false;
    const e = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    await crypto.subtle.sign({ name: 'Ed25519' }, e.privateKey, new Uint8Array(1));
    const a = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    const b = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    await crypto.subtle.deriveBits({ name: 'X25519', public: b.publicKey }, a.privateKey, 256);
    return true;
  } catch {
    return false;
  }
}

async function raw(publicKey) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
}

// The device: made once, when it first pairs or invites.
export async function device(create = false) {
  let d = await get('keys', 'device');
  if (d || !create) return d || null;
  const sign = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  const agree = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  d = {
    sign: sign.privateKey,
    agree: agree.privateKey,
    signPub: await raw(sign.publicKey),
    agreePub: await raw(agree.publicKey),
    made: Date.now(),
  };
  await put('keys', 'device', d);
  return d;
}

export async function sign(key, statement) {
  return new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, key, statement));
}

export async function derive(privateKey, theirPublic) {
  const theirs = await crypto.subtle.importKey('raw', theirPublic, { name: 'X25519' }, true, []);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: theirs }, privateKey, 256));
}

// A one-box key: made, used for one X25519, forgotten.
export async function ephemeral(theirPublic) {
  const k = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  return { pub: await raw(k.publicKey), shared: await derive(k.privateKey, theirPublic) };
}

// A ratchet key: kept (non-extractable) until the ratchet turns past it.
export async function ratchetKey() {
  const k = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const pub = await raw(k.publicKey);
  await put('keys', 'r:' + hex(pub), k.privateKey);
  return { pub, key: k.privateKey };
}
export async function ratchetPrivate(pubHex, d) {
  if (pubHex === hex(d.agreePub)) return d.agree;
  const k = await get('keys', 'r:' + pubHex);
  if (!k) throw new Error('a ratchet key this device no longer has');
  return k;
}
export const forgetRatchetKey = (pubHex) => del('keys', 'r:' + pubHex);

// History at rest: AES-GCM under a non-extractable key; the record's name
// is its associated data, so a record cannot be moved under another name.
// Made once: two first uses at the same moment on a new device would each
// make one, and what was sealed under the first would never open again.
let restPromise = null;
function restKey() {
  if (!restPromise) {
    restPromise = (async () => {
      const t = await idb('keys', 'readwrite', (s) => s.get('rest'));
      if (t) return t;
      const k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      // Added only if still absent (another tab of the same site may have made one).
      await idb('keys', 'readwrite', (s) => s.add(k, 'rest')).catch(() => {});
      return await get('keys', 'rest');
    })();
    restPromise.catch(() => { restPromise = null; });
  }
  return restPromise;
}
const enc = new TextEncoder();
export async function seal(name, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(name) },
    await restKey(), bytes));
  return { iv, data };
}
export async function unseal(name, box) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: box.iv, additionalData: enc.encode(name) },
    await restKey(), box.data));
}

// Ask the browser to keep this site's storage (it may still say no).
export async function persist() {
  try {
    if (navigator.storage?.persisted && (await navigator.storage.persisted())) return true;
    return navigator.storage?.persist ? await navigator.storage.persist() : false;
  } catch {
    return false;
  }
}

export function random(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}
