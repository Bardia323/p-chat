// Files beside messages (protocol 3): what is picked is made ready here
// (a picture redrawn on a canvas, which leaves its EXIF behind; a tiny
// thumbnail), sealed in 64 KiB chunks under a key of its own, its
// reference said as a signed message, and its chunks carried apart: pulled
// over the live link from a device that has them, or left at the relay in
// pieces for a device that takes mail. What arrives is checked chunk by
// chunk, then whole against its hash, before it is shown.
import * as c from './crypto.js';
import * as store from './store.js';

export const KIND = { file: 0, image: 1, video: 2, voice: 3, sticker: 4 };
const MAX = 100 * 1024 * 1024;
const CHUNK = 65536;
const WANT_AGAIN_MS = 4000;
const FRAMES_PER_ROUND = 48;

function canvas(w, h) {
  if (globalThis.OffscreenCanvas) return new OffscreenCanvas(w, h);
  const el = document.createElement('canvas');
  el.width = w;
  el.height = h;
  return el;
}
async function toBlob(cv, type, quality) {
  if (cv.convertToBlob) return cv.convertToBlob({ type, quality });
  return new Promise((r) => cv.toBlob(r, type, quality));
}
async function thumbnail(source, w, h) {
  const scale = Math.min(1, 96 / Math.max(w, h));
  const cv = canvas(Math.max(1, Math.round(w * scale)), Math.max(1, Math.round(h * scale)));
  cv.getContext('2d').drawImage(source, 0, 0, cv.width, cv.height);
  for (const q of [0.6, 0.4, 0.25]) {
    const b = new Uint8Array(await (await toBlob(cv, 'image/jpeg', q)).arrayBuffer());
    if (b.length <= 12 * 1024) return b;
  }
  return new Uint8Array(0);
}

// A picture, redrawn: what reaches the other phone is pixels, not the file
// (no camera, no place, no time in it).
async function picture(file) {
  const bmp = await createImageBitmap(file, { imageOrientation: 'from-image' });
  const scale = Math.min(1, 2560 / Math.max(bmp.width, bmp.height));
  const w = Math.round(bmp.width * scale), h = Math.round(bmp.height * scale);
  const cv = canvas(w, h);
  cv.getContext('2d').drawImage(bmp, 0, 0, w, h);
  const type = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
  const out = await toBlob(cv, type, 0.88);
  return { blob: out, mime: type, width: w, height: h, thumbnail: await thumbnail(bmp, bmp.width, bmp.height) };
}
async function poster(file) {
  // The first frame, if this browser can play it; else no picture.
  try {
    const v = document.createElement('video');
    v.muted = true;
    v.preload = 'auto';
    v.src = URL.createObjectURL(file);
    await new Promise((ok, no) => { v.onloadeddata = ok; v.onerror = no; setTimeout(no, 4000); });
    const out = { width: v.videoWidth, height: v.videoHeight, duration: Math.round((v.duration || 0) * 1000) };
    out.thumbnail = await thumbnail(v, v.videoWidth || 1, v.videoHeight || 1);
    URL.revokeObjectURL(v.src);
    return out;
  } catch {
    return { width: 0, height: 0, duration: 0, thumbnail: new Uint8Array(0) };
  }
}

// A voice note: the microphone while held (or until stopped).
export async function recorder() {
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  const type = ['audio/webm;codecs=opus', 'audio/mp4', 'audio/webm'].find((t) => MediaRecorder.isTypeSupported?.(t)) || '';
  // Speech, not music: Opus at 24 kbit/s (the browser's own choice is several
  // times that); AAC (Safari's mp4) needs more to sound like a voice.
  const rec = new MediaRecorder(stream, { ...(type ? { mimeType: type } : {}), audioBitsPerSecond: type.includes('opus') ? 24_000 : 48_000 });
  const parts = [];
  rec.ondataavailable = (e) => e.data.size && parts.push(e.data);
  const started = performance.now();
  rec.start(250);
  return {
    stop: () => new Promise((done) => {
      rec.onstop = () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(parts, { type: rec.mimeType || type || 'audio/webm' });
        done({ blob, mime: blob.type.split(';')[0], duration: Math.round(performance.now() - started) });
      };
      rec.stop();
    }),
    cancel: () => { rec.stop(); stream.getTracks().forEach((t) => t.stop()); },
  };
}

export class Media {
  constructor(session) {
    Object.assign(this, { s: session, serving: new Map(), urls: new Map(), asked: new Map(), progress: new Map(),
      pack: null, busy: false });
  }
  get chat() { return this.s.chat; }

  // The built-in sticker pack: content-addressed, named by its list's hash.
  async stickers() {
    if (this.pack) return this.pack;
    const bytes = new Uint8Array(await (await fetch('stickers/pack.json')).arrayBuffer());
    const list = JSON.parse(new TextDecoder().decode(bytes));
    this.pack = { id: c.hex(this.chat.blake2b(32, new Uint8Array(0), bytes)), name: list.name, stickers: list.stickers };
    return this.pack;
  }

  // ---- sending ----
  async prepare(file, kind) {
    if (file.size > MAX) throw new Error('A file is at most 100 MB.');
    if (kind === KIND.image || (kind === undefined && file.type.startsWith('image/') && file.type !== 'image/svg+xml'))
      return { kind: KIND.image, name: file.name || '', ...(await picture(file)) };
    if (kind === KIND.video || (kind === undefined && file.type.startsWith('video/')))
      return { kind: KIND.video, blob: file, mime: file.type || 'video/mp4', name: file.name || '', ...(await poster(file)) };
    return { kind: kind ?? KIND.file, blob: file, mime: file.type || 'application/octet-stream', name: file.name || 'file',
      width: 0, height: 0, duration: 0, thumbnail: new Uint8Array(0) };
  }
  async send(conv, p) {
    const size = p.blob.size;
    if (size > MAX) throw new Error('A file is at most 100 MB.');
    const key = c.random(32), blob = c.random(32), id = c.hex(blob);
    const count = this.chat.chunkCount(size);
    const hasher = new this.chat.Hasher();
    const sealed = [];
    for (let i = 0; i < count; i++) {
      const plain = new Uint8Array(await p.blob.slice(i * CHUNK, Math.min(size, (i + 1) * CHUNK)).arrayBuffer());
      hasher.update(plain);
      const s = this.chat.sealChunk(key, blob, i, count, plain);
      await store.putChunk(id, i, s);
      if (count <= 64) sealed.push(s);
      this.progress.set(id, { have: i + 1, count, sending: true });
      if (i % 8 === 7) this.s.ui.changed(conv);
    }
    const hash = hasher.final();
    hasher.delete();
    const ref = { blob, key, hash, mime: p.mime.slice(0, 128), size, kind: p.kind, name: (p.name || '').slice(0, 200),
      duration: p.duration || 0, width: Math.min(p.width || 0, 65535), height: Math.min(p.height || 0, 65535),
      thumbnail: p.thumbnail || new Uint8Array(0), pack: new Uint8Array(32) };
    const bytes = this.chat.fileEncode(ref);
    await store.saveBlob(id, { conv, peer: this.s.app.peer(), ref: bytes, count, complete: true });
    // A device that takes mail finds the pieces at the relay before the
    // message that names them.
    if (this.s.info(conv).members.some((m) => !m.self && m.mail)) await this.upload(conv, ref, count);
    this.s.app.postFile(conv, bytes, Date.now());
    await this.s.pump();
  }
  async sticker(conv, s) {
    this.s.reachable(conv);
    const pack = await this.stickers();
    const bytes = new Uint8Array(await (await fetch('stickers/' + s.file)).arrayBuffer());
    const hash = this.chat.blake2b(32, new Uint8Array(0), bytes);
    const ref = { blob: hash, key: new Uint8Array(32), hash, mime: 'image/svg+xml', size: bytes.length, kind: KIND.sticker,
      name: s.file, duration: 0, width: 0, height: 0, thumbnail: new Uint8Array(0), pack: c.unhex(pack.id) };
    this.s.app.postFile(conv, this.chat.fileEncode(ref), Date.now());
    await this.s.pump();
  }
  async upload(conv, ref, count) {
    const relay = this.s.relayOf(conv);
    if (!relay) return;
    const id = c.hex(ref.blob);
    for (let p = 0; p * 3 < count; p++) {
      const chunks = [];
      for (let i = p * 3; i < Math.min(count, p * 3 + 3); i++) chunks.push(await store.chunk(id, i));
      const env = this.chat.pieceEnvelope(this.s.app.pieceMailbox(conv, ref.blob, p), ref.key, ref.blob, p, chunks);
      for (let tries = 0; tries < 3; tries++) {
        const r = await relay.put(env).catch(() => null);
        if (r?.status === 0) break;
        await new Promise((ok) => setTimeout(ok, 500));
      }
    }
  }

  // ---- receiving ----
  // A file message: what it names is wanted, from its sender.
  async received(conv, peer, refBytes, mine) {
    let ref;
    try { ref = this.chat.fileDecode(refBytes); } catch { return; }
    if (ref.kind === KIND.sticker) return;
    const id = c.hex(ref.blob);
    if (await store.blob(id)) return;
    await store.saveBlob(id, { conv, peer, ref: refBytes, count: ref.count, complete: mine });
    this.tick();
  }
  async frame(peer, bytes) {
    let f;
    try { f = this.chat.decodeBlobFrame(bytes); } catch { return; }
    const id = c.hex(f.blob);
    const meta = await store.blob(id);
    if (!meta) return;
    if (f.kind === 'want') {
      // Served to a device of the same conversation only.
      if (!this.s.info(meta.conv).members.some((m) => m.peer === peer)) return;
      this.serving.set(peer + '/' + id, { peer, id, next: f.index, count: meta.count });
      return;
    }
    if (meta.complete || f.count !== meta.count) return;
    const ref = this.chat.fileDecode(meta.ref);
    try { this.chat.openChunk(ref.key, ref.blob, f.index, f.count, f.sealed); } catch { return; }
    await store.putChunk(id, f.index, f.sealed);
    await this.check(id, meta, ref);
  }
  // Whole, the file must be what its reference says it is.
  async check(id, meta, ref) {
    const have = await store.chunkIndexes(id);
    this.progress.set(id, { have: have.size, count: meta.count });
    if (have.size < meta.count) { this.s.ui.changed(meta.conv); return false; }
    const hasher = new this.chat.Hasher();
    try {
      for (let i = 0; i < meta.count; i++) hasher.update(this.chat.openChunk(ref.key, ref.blob, i, meta.count, await store.chunk(id, i)));
      if (c.hex(hasher.final()) !== c.hex(ref.hash)) throw new Error('hash');
    } catch {
      await c.idb('chunks', 'readwrite', (s) => s.delete(IDBKeyRange.bound(id + '/', id + '/￿')));
      return false;
    } finally { hasher.delete(); }
    await store.saveBlob(id, { ...meta, complete: true });
    this.progress.delete(id);
    this.s.ui.changed(meta.conv);
    return true;
  }
  // Each round: serve what is wanted, ask again for what is missing, look
  // at the relay for pieces.
  async tick() {
    if (this.busy || !this.s.app) return;
    this.busy = true;
    try {
      for (const [k, sv] of this.serving) {
        let sent = 0;
        while (sv.next < sv.count && sent < FRAMES_PER_ROUND) {
          const sealed = await store.chunk(sv.id, sv.next);
          if (!sealed) break;
          if (!this.s.app.sendBlob(sv.peer, this.chat.chunkFrame(c.unhex(sv.id), sv.next, sv.count, sealed))) break;
          sv.next++;
          sent++;
        }
        if (sv.next >= sv.count) this.serving.delete(k);
      }
      for (const meta of await store.blobs()) {
        if (meta.complete) continue;
        const have = await store.chunkIndexes(meta.id);
        let first = 0;
        while (have.has(first)) first++;
        if (first >= meta.count) { await this.check(meta.id, meta, this.chat.fileDecode(meta.ref)); continue; }
        const last = this.asked.get(meta.id) || { at: 0, have: -1 };
        const now = Date.now();
        if (this.s.app.liveWith(meta.peer)) {
          if (now - last.at > WANT_AGAIN_MS || last.have !== have.size) {
            this.s.app.sendBlob(meta.peer, this.chat.wantFrame(c.unhex(meta.id), first));
            this.asked.set(meta.id, { at: now, have: have.size });
          }
        } else if (now - last.at > WANT_AGAIN_MS) {
          this.asked.set(meta.id, { at: now, have: have.size });
          await this.fetchPieces(meta, have);
        }
      }
    } finally {
      this.busy = false;
    }
  }
  async fetchPieces(meta, have) {
    const relay = this.s.relayOf(meta.conv);
    if (!relay?.up) return;
    const ref = this.chat.fileDecode(meta.ref);
    const want = [];
    for (let p = 0; p * 3 < meta.count; p++)
      for (let i = p * 3; i < Math.min(meta.count, p * 3 + 3); i++) if (!have.has(i)) { want.push(p); break; }
    for (let at = 0; at < want.length; at += 32) {
      const ids = want.slice(at, at + 32).map((p) => this.s.app.pieceMailbox(meta.conv, ref.blob, p));
      for (const item of await relay.fetch(ids).catch(() => [])) {
        const p = want[at + ids.findIndex((x) => c.hex(x) === c.hex(item.mailbox))];
        try {
          const piece = this.chat.openPiece(ref.key, ref.blob, p, item.envelope);
          for (let k = 0; k < piece.chunks.length; k++) {
            const i = piece.first + k;
            this.chat.openChunk(ref.key, ref.blob, i, meta.count, piece.chunks[k]);
            await store.putChunk(meta.id, i, piece.chunks[k]);
          }
        } catch { /* not this file's piece */ }
      }
    }
    await this.check(meta.id, meta, ref);
  }

  // ---- showing ----
  async url(refBytes) {
    const ref = this.chat.fileDecode(refBytes);
    if (ref.kind === KIND.sticker) {
      const pack = await this.stickers();
      const s = c.hex(ref.pack) === pack.id && pack.stickers.find((x) => x.hash === c.hex(ref.hash));
      return s ? 'stickers/' + s.file : null;
    }
    const id = c.hex(ref.blob);
    if (this.urls.has(id)) return this.urls.get(id);
    const meta = await store.blob(id);
    if (!meta?.complete) return null;
    const parts = [];
    for (let i = 0; i < ref.count; i++) parts.push(this.chat.openChunk(ref.key, ref.blob, i, ref.count, await store.chunk(id, i)));
    const url = URL.createObjectURL(new Blob(parts, { type: ref.mime }));
    this.urls.set(id, url);
    return url;
  }
  state(refBytes) {
    try {
      const ref = this.chat.fileDecode(refBytes);
      return { ref, id: c.hex(ref.blob), progress: this.progress.get(c.hex(ref.blob)) };
    } catch {
      return null;
    }
  }
}
