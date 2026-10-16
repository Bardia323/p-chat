// p-chat's service worker: it serves this site's files only from a bundle
// whose release is in the release chain (web/release.js): each release
// signed by a quorum of the committee the one before names, the first by
// the committee written below, every file of the bundle the one its signed
// manifest names. A newer release it takes whole or not at all, link by
// link from the one it runs; it keeps it waiting and runs it from the next
// time p-chat is opened. A release that does not hold is refused, the
// evidence kept, and it stays where it is; two different releases signed
// as one version are a fork, kept and told.
//
// What it cannot do: the browser fetches this file itself and replaces it
// whenever the site serves a different one, without asking it. So a host
// that serves a new sw.js serves whatever it likes from then on (and the
// first load trusts the committee it is given). The static host, its DNS
// and its TLS remain the root of trust on every load; this worker only
// makes a changed bundle without the committee's signatures fail to replace
// a good one quietly while this worker is the one running - and says so
// when the sw.js it was given is not the one its release names.
const GENESIS = '__GENESIS_COMMITTEE__'; // the first committee: {keys, quorum}; written by tools/release.py
/*__RELEASE_JS__*/
const R = self.pchatRelease;
const PREFIX = 'p-chat-bundle-';
const STATE = 'p-chat-chain';
const hex = (b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('');

// What it keeps: the release it runs, one waiting, the records it has seen
// (by version) and what it refused.
const key = (k) => new Request(self.registration.scope + '__chain/' + k);
async function read(k) {
  const r = await (await caches.open(STATE)).match(key(k));
  return r ? r.json() : null;
}
async function write(k, v) { await (await caches.open(STATE)).put(key(k), new Response(JSON.stringify(v))); }
async function tell(msg) { for (const c of await self.clients.matchAll({ includeUncontrolled: true })) c.postMessage(msg); }
async function refuse(why, detail) {
  const list = (await read('evidence')) || [];
  list.push({ at: Date.now(), why, detail: detail || null });
  while (list.length > 32) list.shift();
  await write('evidence', list);
  await tell({ type: 'release-refused', why });
}
const TYPES = { js: 'text/javascript', mjs: 'text/javascript', wasm: 'application/wasm', html: 'text/html', css: 'text/css', json: 'application/json',
  svg: 'image/svg+xml', png: 'image/png', woff2: 'font/woff2', webmanifest: 'application/manifest+json', txt: 'text/plain' };
const type = (path) => TYPES[path.split('.').pop()] || 'application/octet-stream';

// The chain begins with the committee this worker was made with.
function anchored(chain) {
  const c = chain?.[0]?.committee;
  return !!c && JSON.stringify([...c.keys].sort()) === JSON.stringify([...GENESIS.keys].sort()) && c.quorum === GENESIS.quorum;
}
// Records seen, by version: another one for a version seen, signed by one
// who signed the first, is a fork.
async function remember(chain) {
  const known = (await read('records')) || {};
  for (const r of chain) {
    const had = known[String(r.version)];
    if (had && (await R.hashOf(had)) !== (await R.hashOf(r))) {
      if (await R.fork(had, r)) {
        await refuse('fork', { version: r.version, a: had, b: r });
        await tell({ type: 'release-fork', version: r.version, a: had, b: r });
        return false;
      }
      continue;  // not signed by one who signed the first: not believed, not kept
    }
    known[String(r.version)] = r;
  }
  await write('records', known);
  return true;
}
// A bundle given whole - by the host, or by a peer: checked against the chain
// from the release this device runs, then kept waiting.
async function take(chain, manifestBytes, files) {
  if (!anchored(chain)) throw new Error('the chain does not begin with this site\'s first committee');
  if (!(await remember(chain))) throw new Error('two different releases were signed as one version');
  const running = await read('active');
  const waiting = await read('pending');
  const next = await R.follow(running?.head || null, chain, null);
  if (running && next.version <= running.head.version) return null;
  if (waiting && next.version <= waiting.head.version) return null;
  await R.checkBundle(next, manifestBytes, files);
  const name = PREFIX + String(next.version).padStart(12, '0');
  const cache = await caches.open(name);
  for (const [path, body] of files) await cache.put(path, new Response(body, { headers: { 'content-type': type(path) } }));
  await cache.put('manifest.json', new Response(manifestBytes, { headers: { 'content-type': 'application/json' } }));
  await cache.put('chain.json', new Response(JSON.stringify(chain), { headers: { 'content-type': 'application/json' } }));
  await write('pending', { head: next, name });
  if (!running) await promote();  // the first: run at once
  else await tell({ type: 'update-ready', version: next.version });
  return next;
}
// The release waiting becomes the one run; the others go.
async function promote() {
  const waiting = await read('pending');
  if (!waiting) return;
  await write('active', waiting);
  await (await caches.open(STATE)).delete(key('pending'));
  for (const k of await caches.keys()) if (k.startsWith(PREFIX) && k !== waiting.name) await caches.delete(k);
}
// What the host has now.
async function update() {
  const [c, m] = await Promise.all(['chain.json', 'manifest.json'].map((f) => fetch(f, { cache: 'no-store' })));
  if (!c.ok || !m.ok) throw new Error('no release chain');
  const chain = await c.json();
  const manifestBytes = new Uint8Array(await m.arrayBuffer());
  const running = await read('active'), waiting = await read('pending');
  const last = chain[chain.length - 1];
  const have = Math.max(running?.head.version || 0, waiting?.head.version || 0);
  if (running && last.version <= have) {
    await remember(chain);
    if (last.version < running.head.version) await refuse(`the site offers release ${last.version}, older than ${running.head.version} (a downgrade)`);
    return;
  }
  const manifest = JSON.parse(new TextDecoder().decode(manifestBytes));
  const files = new Map();
  for (const path of Object.keys(manifest.files)) {
    const r = await fetch(path, { cache: 'no-store' });
    if (!r.ok) throw new Error('a file is missing: ' + path);
    files.set(path, new Uint8Array(await r.arrayBuffer()));
  }
  await take(chain, manifestBytes, files);
}
let checking = null;
const check = () => (checking ??= update().catch((e) => refuse(e.message)).finally(() => { checking = null; }));

self.addEventListener('install', (e) => e.waitUntil(check().then(() => self.skipWaiting())));
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  e.respondWith((async () => {
    // Opening p-chat: what waits is run from now.
    if (e.request.mode === 'navigate') await promote();
    const running = await read('active');
    if (!running) return fetch(e.request);
    let path = url.pathname.slice(new URL(self.registration.scope).pathname.length) || 'index.html';
    if (e.request.mode === 'navigate') {
      path = 'index.html';
      e.waitUntil(check());
    }
    const cache = await caches.open(running.name);
    return (await cache.match(path)) || fetch(e.request);
  })());
});

// A push (protocol 6) says only which ping it is and in which conversation,
// sealed to this device by the browser's push encryption: "p6.<ping>.<conversation>".
// What shows is the symbol this device chose for that conversation - no
// sender, no words. A ping already shown is not shown again.
self.addEventListener('push', (e) => e.waitUntil(woken(e.data ? e.data.text() : '')));
async function woken(text) {
  {
    const m = /^p6\.([0-9a-f]{32})\.([0-9a-f]{32})$/.exec(text);
    const conv = m ? m[2] : null;
    if (m) {
      const pings = await caches.open('p-chat-pings');
      const key = new Request(self.registration.scope + 'ping/' + m[1]);
      if (await pings.match(key)) return;
      await pings.put(key, new Response(''));
      const all = await pings.keys();
      for (const old of all.slice(0, Math.max(0, all.length - 256))) await pings.delete(old);
    }
    const symbol = conv ? await symbolOf(conv).catch(() => null) : null;
    await self.registration.showNotification('p-chat', { body: symbol || '•', tag: 'p-chat-' + (conv || 'any'), renotify: true, icon: 'icon-180.png', data: { ping: m ? m[1] : null } });
  }
}
// The symbols are kept as the page keeps everything: sealed under this
// device's at-rest key (AES-GCM, the record's name as associated data), in
// the page's database - which this worker never makes or changes.
function request(r) {
  return new Promise((resolve, reject) => { r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
}
async function symbolOf(conv) {
  const open = indexedDB.open('p-chat');
  open.onupgradeneeded = () => open.transaction.abort();  // none yet: leave it to the page
  const d = await request(open);
  try {
    const tx = d.transaction(['keys', 'meta'], 'readonly');
    const [key, box] = await Promise.all([request(tx.objectStore('keys').get('rest')), request(tx.objectStore('meta').get('signals'))]);
    if (!key || !box) return null;
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: box.iv, additionalData: new TextEncoder().encode('meta:signals') }, key, box.data);
    const symbol = JSON.parse(new TextDecoder().decode(plain))[conv];
    return typeof symbol === 'string' && symbol.length <= 16 ? symbol : null;
  } finally {
    d.close();
  }
}
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const open = await self.clients.matchAll({ type: 'window' });
    if (open.length) return open[0].focus();
    return self.clients.openWindow('./');
  })());
});

// The page asks: what runs (and whether this worker is the one its release
// names), what waits, what was refused; or hands a bundle a peer gave it.
self.addEventListener('message', (e) => {
  const reply = (v) => (e.ports[0] ? e.ports[0].postMessage(v) : e.source?.postMessage(v));
  const d = e.data || {};
  e.waitUntil((async () => {
    if (d === 'status' || d.type === 'status') {
      const running = await read('active'), waiting = await read('pending');
      let swMatches = null;
      try {
        const r = await fetch('sw.js', { cache: 'no-store' });
        if (r.ok && running) swMatches = hex(await crypto.subtle.digest('SHA-256', await r.arrayBuffer())) === running.head.sw;
      } catch { /* offline: not known */ }
      const manifest = running ? await (await caches.open(running.name)).match('manifest.json') : null;
      const fp = manifest ? hex(await crypto.subtle.digest('SHA-256', await manifest.arrayBuffer())) : null;
      reply({ type: 'status', version: running?.head.version ?? null, head: running?.head.hash ?? null, fingerprint: fp,
        pending: waiting?.head.version ?? null, swMatches, evidence: (await read('evidence')) || [], name: running?.name ?? null });
    } else if (d.type === 'check') {
      await check();
      reply({ type: 'checked' });
    } else if (d.type === 'install') {
      try {
        const next = await take(d.chain, new Uint8Array(d.manifest), new Map(d.files.map(([p, b]) => [p, new Uint8Array(b)])));
        reply({ type: 'installed', version: next?.version ?? null });
      } catch (err) {
        await refuse(err.message);
        reply({ type: 'refused', why: err.message });
      }
    }
  })());
});
