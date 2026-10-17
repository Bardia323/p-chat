// What this device keeps: content, never state. The world's conversations
// are kept as the App saves them (their records), the messages beside them -
// each one sealed under the device's at-rest key (crypto.js) with its own
// name as associated data. On start the records are loaded and the messages
// replayed into the App, which rebuilds its Integrity from them: what was
// accepted once is known again, and a second, different message under the
// same sequence is still equivocation.
import * as c from './crypto.js';

const json = (v) => new TextEncoder().encode(JSON.stringify(v, (k, x) => (x instanceof Uint8Array ? { $b: c.hex(x) } : x)));
const unjson = (b) => JSON.parse(new TextDecoder().decode(b), (k, x) => (x && typeof x === 'object' && '$b' in x ? c.unhex(x.$b) : x));

async function putSealed(store, key, value) {
  await c.put(store, key, await c.seal(store + ':' + key, json(value)));
}
async function getSealed(store, key) {
  const box = await c.get(store, key);
  return box ? unjson(await c.unseal(store + ':' + key, box)) : null;
}
// Keys and records read in one transaction: read in two, a record written
// in between would pair a box with another record's name, and not open.
async function rangeSealed(store, prefix) {
  const range = IDBKeyRange.bound(prefix, prefix + '￿');
  const pairs = [];
  await c.idb(store, 'readonly', (s) => {
    const cursor = s.openCursor(range);
    cursor.onsuccess = () => {
      const at = cursor.result;
      if (!at) return;
      pairs.push([at.key, at.value]);
      at.continue();
    };
    return null;
  });
  const out = [];
  for (const [key, box] of pairs) out.push(unjson(await c.unseal(store + ':' + key, box)));
  return out;
}

// The profile: this device's name and the relay its own invites use.
export const profile = async () => (await getSealed('meta', 'profile')) || { name: '', relay: '' };
export const setProfile = (p) => putSealed('meta', 'profile', p);

// A conversation's record (App::save) and what the app knows beside it.
export const saveRecord = (conv, bytes, meta) => putSealed('records', conv, { bytes, meta });
export async function records() {
  const out = [];
  for (const k of await c.allKeys('records')) out.push({ conv: k, ...(await getSealed('records', k)) });
  return out;
}
export async function meta(conv) {
  return (await getSealed('records', conv))?.meta || {};
}
export async function forget(conv) {
  await c.del('records', conv);
  const range = IDBKeyRange.bound(conv + '/', conv + '/￿');
  await c.idb('messages', 'readwrite', (s) => s.delete(range));
}

// Messages: one per sender and sequence (a message said again under a new
// generation takes its place).
const messageKey = (conv, peer, seq) => `${conv}/${peer}/${String(seq).padStart(20, '0')}`;
export async function saveMessage(conv, m) {
  const key = messageKey(conv, m.peer, m.seq);
  const had = await getSealed('messages', key);
  await putSealed('messages', key, { ...(had || {}), ...m, status: had?.status === 'delivered' ? 'delivered' : m.status });
}
export async function messages(conv) {
  const list = await rangeSealed('messages', conv + '/');
  return list.sort((a, b) => a.time - b.time || (a.peer < b.peer ? -1 : 1) || a.seq - b.seq);
}
export async function setStatus(conv, peer, seq, status) {
  const key = messageKey(conv, peer, seq);
  const m = await getSealed('messages', key);
  if (m && m.status !== 'delivered') await putSealed('messages', key, { ...m, status });
}

// Invites this device made and is waiting on; a pairing it asked for.
export const saveInvite = (token, inv) => putSealed('meta', 'invite:' + token, inv);
export const dropInvite = (token) => c.del('meta', 'invite:' + token);
export async function invites() {
  const out = [];
  for (const k of await c.allKeys('meta')) if (String(k).startsWith('invite:')) out.push(await getSealed('meta', k));
  return out.filter(Boolean);
}
export const saveAsking = (a) => putSealed('meta', 'asking', a);
export const asking = () => getSealed('meta', 'asking');
export const dropAsking = () => c.del('meta', 'asking');

// Envelopes not yet known to have arrived: sent live and not acknowledged,
// or waiting for the relay.
// Envelopes this device keeps for its contacts (carry.js): sealed to
// someone else, kept sealed again here, as the outbox is.
export const saveHeld = (key, h) => putSealed('meta', 'held:' + key, h);
export const dropHeld = (key) => c.del('meta', 'held:' + key);
export const held = () => rangeSealed('meta', 'held:');
// What a device that relays remembers of where its contacts' devices are
// reached (rooms and labels, as a relay's rooms are), 14 days at most.
export const saveServed = (key, s) => putSealed('meta', 'served:' + key, s);
export const dropServed = (key) => c.del('meta', 'served:' + key);
export const served = () => rangeSealed('meta', 'served:');
export const saveOutbox = (id, o) => putSealed('meta', 'out:' + id, o);
export const dropOutbox = (id) => c.del('meta', 'out:' + id);
export async function outboxItem(id) {
  const o = await getSealed('meta', 'out:' + id);
  return o ? { id, ...o } : null;
}
export async function outbox() {
  const out = [];
  for (const k of await c.allKeys('meta')) if (String(k).startsWith('out:')) out.push({ id: k.slice(4), ...(await getSealed('meta', k)) });
  return out;
}

// Equivocation: both statements kept as evidence.
export const saveEvidence = (conv, e) => putSealed('meta', `evidence:${conv}:${Date.now()}:${c.hex(c.random(4))}`, e);
export async function evidence(conv) {
  const out = [];
  for (const k of await c.allKeys('meta')) if (String(k).startsWith('evidence:' + conv + ':')) out.push(await getSealed('meta', k));
  return out;
}

// Files: what each is (its reference, sealed at rest) and its chunks, kept
// as they travel - sealed under the file's own key.
export const saveBlob = (id, meta) => putSealed('blobs', id, meta);
export const blob = (id) => getSealed('blobs', id);
export async function blobs() {
  const out = [];
  for (const k of await c.allKeys('blobs')) out.push({ id: k, ...(await getSealed('blobs', k)) });
  return out;
}
const chunkKey = (id, i) => id + '/' + String(i).padStart(8, '0');
export const putChunk = (id, i, sealed) => c.put('chunks', chunkKey(id, i), sealed);
export const chunk = (id, i) => c.get('chunks', chunkKey(id, i));
export async function chunkIndexes(id) {
  const keys = await c.idb('chunks', 'readonly', (s) => s.getAllKeys(IDBKeyRange.bound(id + '/', id + '/\uffff')));
  return new Set(keys.map((k) => Number(String(k).slice(id.length + 1))));
}

// Disappearing messages: a message whose time is over keeps only what the
// history needs (its signed, sealed observation); its words and its key go.
export async function expireMessage(conv, m) {
  await putSealed('messages', messageKey(conv, m.peer, m.seq), { peer: m.peer, seq: m.seq, obs: m.obs, time: m.time, type: m.type,
    mine: m.mine, body: new Uint8Array(0), hidden: true, expired: true });
}
export async function forgetBlob(id) {
  await c.del('blobs', id);
  await c.idb('chunks', 'readwrite', (s) => s.delete(IDBKeyRange.bound(id + '/', id + '/\uffff')));
}
// Copies of messages left at a relay, for a chat whose messages disappear:
// deleted there when their time is over (the relay deletes by mailbox and
// the envelope's hash, which the sender knows).
export const saveCopy = (id, k) => putSealed('meta', 'copy:' + id, k);
export const dropCopy = (id) => c.del('meta', 'copy:' + id);
export async function copies() {
  const out = [];
  for (const k of await c.allKeys('meta')) if (String(k).startsWith('copy:')) out.push({ id: k.slice(5), ...(await getSealed('meta', k)) });
  return out;
}

// Notifications (protocol 6): this device's VAPID pair; where and how to
// wake each device it talks to (from their `push` messages); and the symbol
// this device shows for a conversation when it is woken (read by sw.js).
export const vapid = () => getSealed('meta', 'vapid');
export const setVapid = (v) => putSealed('meta', 'vapid', v);
export const pushTo = (peer) => getSealed('meta', 'push:' + peer);
export const savePushTo = (peer, info) => putSealed('meta', 'push:' + peer, info);
export const signals = async () => (await getSealed('meta', 'signals')) || {};
export async function setSignal(conv, symbol) {
  const s = await signals();
  if (symbol) s[conv] = symbol;
  else delete s[conv];
  await putSealed('meta', 'signals', s);
}

// Gaps first seen, by wall time: a gap older than the mailbox's life is a
// message that will not come.
export const saveGaps = (conv, gaps) => putSealed('meta', 'gaps:' + conv, gaps);
export const gaps = async (conv) => (await getSealed('meta', 'gaps:' + conv)) || {};
