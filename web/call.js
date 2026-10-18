// Calls in the browser (protocol 7): the camera and the microphone encoded by
// WebCodecs on this phone, each encoded chunk handed to Wasm - sealed under
// the call's key, sent on the live link's Latest lane, named in a root signed
// by this device about every tenth of a second. What comes back is played
// only once its speaker's root names it (the App holds it till then), then
// decoded here. Nothing of a call is kept.
export const MODE = { mesh: 0, swarm: 1, hybrid: 2 };
const LAYER = { full: 0, small: 1, audio: 2 };
const FPS = 15, LONG = 640, SMALL_LONG = 320;
// Sound is played this far ahead of now: enough to ride the jitter of pieces
// that come in bursts (named by roots a tenth of a second apart), and no more.
// Ahead by more than LATE, a piece is dropped until it is back (speech loses
// nothing a listener hears); behind, it starts again at LEAD.
const LEAD = 0.12, LATE = 0.32;
// A picture's size as the camera gives it, its long side LONG at most, even.
const sized = (w, h, long) => {
  const s = Math.min(1, long / Math.max(w, h));
  return [Math.max(2, Math.round((w * s) / 2) * 2), Math.max(2, Math.round((h * s) / 2) * 2)];
};
// The picture's codec: VP9 where this browser encodes it (about a third
// smaller for the same picture), VP8 elsewhere; bits a second for the full
// and the small picture in each. Nothing on the wire says which: a receiver
// reads it from each key frame (`codecOf`), so a call may mix the two.
const VP8 = 'vp8', VP9 = 'vp09.00.30.08';
const RATE = { [VP8]: [600_000, 150_000], [VP9]: [400_000, 100_000] };
const codecOf = (b) => {
  if (b.length > 5 && !(b[0] & 1) && b[3] === 0x9d && b[4] === 0x01 && b[5] === 0x2a) return VP8;  // a VP8 key frame's start code
  return b.length && (b[0] & 0xc0) === 0x80 ? VP9 : null;  // VP9's frame marker
};
// Speech: Opus at 20 kbit/s, nothing sent while no one speaks (DTX), in
// pieces of 60 ms - each piece sealed, numbered and named in a root costs
// about 150 bytes, more than 20 ms of the sound itself.
const OPUS = { codec: 'opus', sampleRate: 48000, numberOfChannels: 1, bitrate: 20_000,
  opus: { application: 'voip', signal: 'voice', usedtx: true, frameDuration: 60_000 } };

export class Calls {
  constructor(session) {
    Object.assign(this, { s: session, id: null, stream: null, timers: [], video: null, audio: null, remote: new Map(),
      latency: [], layers: {}, ctx: null, playAt: 0, muted: false, camera: true, onchange: null });
  }
  static supported() { return 'VideoEncoder' in globalThis && 'VideoDecoder' in globalThis && !!navigator.mediaDevices?.getUserMedia; }
  // The best picture codec this browser encodes in real time (asked once).
  static async codec() {
    Calls.chosen ??= VideoEncoder.isConfigSupported({ codec: VP9, width: LONG, height: 360, bitrate: RATE[VP9][0], framerate: FPS, latencyMode: 'realtime' })
      .then((r) => (r.supported ? VP9 : VP8), () => VP8);
    return Calls.chosen;
  }
  // Speech as OPUS asks where the browser takes it; elsewhere its Opus alone, lower.
  static async sound() {
    Calls.voice ??= AudioEncoder.isConfigSupported(OPUS).then((r) => (r.supported ? OPUS : null), () => null)
      .then((c) => c ?? { codec: 'opus', sampleRate: 48000, numberOfChannels: 1, bitrate: 20_000 });
    return Calls.voice;
  }

  // Talk: everyone to everyone up to five devices, speakers through a small
  // tree beyond. A stream (`live`): this device to a swarm.
  // The sound, started in the tap itself (before anything is awaited): a phone
  // (Safari) keeps a context made otherwise paused, and sound queued for it plays late.
  wake() {
    this.ctx ??= new AudioContext({ latencyHint: 'interactive' });
    this.ctx.resume().catch(() => {});
  }
  async start(conv, live = false, mode = null) {
    this.wake();
    if (!Calls.supported()) throw new Error('This browser cannot make calls (it has no WebCodecs).');
    const devices = this.s.info(conv).members.length;
    const id = this.s.app.startCall(conv, mode ?? (live ? MODE.swarm : devices <= 5 ? MODE.mesh : MODE.hybrid));
    await this.s.pump();
    await this.open(id, true);
    return id;
  }
  async answer(id) {
    this.wake();
    if (!Calls.supported()) throw new Error('This browser cannot make calls (it has no WebCodecs).');
    const k = this.s.app.calls().find((c) => c.id === id);
    this.s.app.joinCall(id, Calls.capacity());
    await this.s.pump();
    await this.open(id, k?.mode !== MODE.swarm);  // a stream's viewer watches: no camera
  }
  // What this device can give a swarm: a computer seeds, a phone on Wi-Fi
  // forwards, a phone on mobile data (or saving data) only takes.
  static capacity() {
    const phone = /Android|iPhone|iPad|Mobile/.test(navigator.userAgent);
    const c = navigator.connection;
    if (c?.saveData || c?.type === 'cellular') return 0;
    return phone ? 1 : 2;
  }
  decline(id) { this.s.app.leaveCall(id); this.s.pump(); }
  info() { return this.id ? this.s.app.calls().find((k) => k.id === this.id) : null; }

  async open(id, speaking) {
    this.id = id;
    this.wake();
    if (speaking) {
      this.stream = await navigator.mediaDevices.getUserMedia({
        video: { width: { ideal: LONG }, height: { ideal: LONG }, frameRate: FPS, facingMode: 'user' },
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true } });
      this.startVideo(await Calls.codec());
      if ('AudioEncoder' in globalThis) this.startAudio(await Calls.sound());
    }
    // While a call is on, the session goes round often: roots go out, what came is played.
    this.timers.push(setInterval(() => this.s.pump(), 40));
  }

  // ---- saying ----
  startVideo(codec) {
    const track = this.stream.getVideoTracks()[0];
    if (!track) return;
    let frames = 0;
    // Through a tree, a small picture too (simulcast): listeners get it
    // unless they asked for this speaker's full one.
    const k = this.info();
    const small = k?.mode === MODE.hybrid ? this.smallEncoder(codec) : null;
    // Configured by the frames: a phone held upright gives an upright picture,
    // and it is sent upright - never squeezed into a size it is not.
    let shape = '', encoder;
    // An encoder that fails (VP9 too slow, or taken away) closes: a VP8 one
    // takes its place, from the next frame (a key frame).
    const make = () => (encoder = this.video = new VideoEncoder({
      output: (chunk) => {
        const data = new Uint8Array(chunk.byteLength);
        chunk.copyTo(data);
        this.send(LAYER.full, chunk.type === 'key', data);
      },
      error: (e) => {
        console.error('video encoder', e);
        if (codec === VP8 || !this.id) return;
        codec = Calls.chosen = VP8;
        shape = '';
        make();
      },
    }));
    make();
    const keyEvery = FPS * 2;
    const take = (frame) => {
      const [w, hgt] = sized(frame.displayWidth, frame.displayHeight, LONG);
      if (w + 'x' + hgt !== shape && encoder.state !== 'closed') {
        shape = w + 'x' + hgt;
        encoder.configure({ codec, width: w, height: hgt, bitrate: RATE[codec][0], framerate: FPS, latencyMode: 'realtime' });
        if (small) small.shape(frame.displayWidth, frame.displayHeight);
        frames = 0;  // a new shape starts at a key frame
      }
      const key = frames++ % keyEvery === 0;
      if (encoder.state === 'configured' && encoder.encodeQueueSize < 4 && this.camera) encoder.encode(frame, { keyFrame: key });
      if (small && small.encoder.state === 'configured' && small.encoder.encodeQueueSize < 4 && this.camera) {
        small.ctx.drawImage(frame, 0, 0, small.canvas.width, small.canvas.height);
        const f = new VideoFrame(small.canvas, { timestamp: frame.timestamp });
        small.encoder.encode(f, { keyFrame: key });
        f.close();
      }
      frame.close();
    };
    if ('MediaStreamTrackProcessor' in globalThis) {
      // Frames as the camera gives them.
      const reader = new MediaStreamTrackProcessor({ track }).readable.getReader();
      const pull = async () => {
        for (;;) {
          const { value, done } = await reader.read();
          if (done || !this.id) { value?.close(); return; }
          take(value);
        }
      };
      pull();
    } else {
      // Elsewhere: the camera drawn into a picture, FPS times a second.
      const el = Object.assign(document.createElement('video'), { muted: true, playsInline: true, srcObject: this.stream });
      el.play().catch(() => {});
      this.timers.push(setInterval(() => { if (el.readyState >= 2) take(new VideoFrame(el, { timestamp: performance.now() * 1000 })); }, 1000 / FPS));
    }
  }
  smallEncoder(codec) {
    const canvas = new OffscreenCanvas(SMALL_LONG, SMALL_LONG);
    const out = { canvas, ctx: canvas.getContext('2d') };
    const configure = () => out.encoder.configure({ codec, width: canvas.width, height: canvas.height, bitrate: RATE[codec][1], framerate: FPS, latencyMode: 'realtime' });
    // Like the full picture's: failing, it goes on in VP8.
    const make = () => (out.encoder = this.smallVideo = new VideoEncoder({
      output: (chunk) => {
        const data = new Uint8Array(chunk.byteLength);
        chunk.copyTo(data);
        this.send(LAYER.small, chunk.type === 'key', data);
      },
      error: (e) => {
        console.error('small encoder', e);
        if (codec === VP8 || !this.id) return;
        codec = VP8;
        make();
        configure();
      },
    }));
    make();
    out.shape = (w, hgt) => {
      [canvas.width, canvas.height] = sized(w, hgt, SMALL_LONG);
      configure();
    };
    return out;
  }
  // A tree: whose full picture this device wants (one at a time).
  pick(speaker) {
    if (!this.id) return;
    this.picked = speaker;
    try { this.s.app.pickFull(this.id, speaker); } catch { /* over */ }
    this.onchange?.();
  }
  startAudio(config) {
    const track = this.stream.getAudioTracks()[0];
    if (!track) return;
    const encoder = (this.audio = new AudioEncoder({
      output: (chunk) => {
        if (chunk.byteLength <= 2) return;  // silence (DTX): nothing to send, as WebRTC sends nothing
        const data = new Uint8Array(chunk.byteLength);
        chunk.copyTo(data);
        this.send(LAYER.audio, true, data);
      },
      error: (e) => console.error('audio encoder', e),
    }));
    encoder.configure(config);
    if (!('MediaStreamTrackProcessor' in globalThis)) return this.workletAudio(track, encoder);
    const reader = new MediaStreamTrackProcessor({ track }).readable.getReader();
    const pull = async () => {
      for (;;) {
        const { value, done } = await reader.read();
        if (done || !this.id) { value?.close(); return; }
        if (encoder.state === 'configured' && !this.muted) encoder.encode(value);
        value.close();
      }
    };
    pull();
  }
  // The microphone where a track gives no frames of its own (Safari): its
  // samples taken by an audio worklet, 20 ms at a time, and encoded alike.
  async workletAudio(track, encoder) {
    const ctx = new AudioContext({ sampleRate: 48000, latencyHint: 'interactive' });
    this.micCtx = ctx;
    await ctx.audioWorklet.addModule('mic.js');
    const source = ctx.createMediaStreamSource(new MediaStream([track]));
    const node = new AudioWorkletNode(ctx, 'p-chat-mic', { numberOfInputs: 1, numberOfOutputs: 0, channelCount: 1 });
    let at = 0;
    node.port.onmessage = (e) => {
      if (!this.id || encoder.state !== 'configured' || this.muted) return;
      const samples = e.data;
      const data = new AudioData({ format: 'f32-planar', sampleRate: ctx.sampleRate, numberOfFrames: samples.length, numberOfChannels: 1,
        timestamp: Math.round((at / ctx.sampleRate) * 1e6), data: samples });
      at += samples.length;
      encoder.encode(data);
      data.close();
    };
    source.connect(node);
    await ctx.resume().catch(() => {});
  }
  send(layer, key, data) {
    if (!this.id) return;
    try { this.s.app.sendMedia(this.id, layer, key, Date.now() * 1000, data); } catch { /* the call is over */ }
  }

  // ---- hearing: what the App believes, decoded ----
  media(list) {
    for (const m of list) {
      if (m.call !== this.id) continue;
      this.latency.push(Date.now() - m.captured / 1000);
      this.layers[m.layer] = (this.layers[m.layer] || 0) + 1;
      if (this.latency.length > 600) this.latency.shift();
      const r = this.peer(m.streamer);
      if (m.layer === LAYER.audio) {
        if (r.audio?.state === 'configured') r.audio.decode(new EncodedAudioChunk({ type: 'key', timestamp: m.captured, data: m.data }));
        continue;
      }
      // The full picture when it comes; the small one only while no full one does.
      const which = m.layer === LAYER.small ? 'small' : 'video';
      if (r[which].state === 'closed') r[which] = r.decoder(which === 'video');  // one that failed (a codec it lacks) is made again
      const dec = r[which];
      if (m.layer === LAYER.small) r.lastSmall = performance.now();
      else r.lastFull = performance.now();
      // A decoder starts at a key frame, in the codec that frame is in.
      const codec = m.key ? codecOf(m.data) : null;
      if (codec && codec !== dec.codec) {
        try { dec.configure({ codec, optimizeForLatency: true }); dec.codec = codec; } catch { continue; }
      } else if (dec.state !== 'configured') continue;
      try { dec.decode(new EncodedVideoChunk({ type: m.key ? 'key' : 'delta', timestamp: m.captured, data: m.data })); } catch { dec.reset(); dec.codec = null; }
      r.frames++;
    }
  }
  peer(streamer) {
    let r = this.remote.get(streamer);
    if (r) return r;
    const canvas = Object.assign(document.createElement('canvas'), { width: LONG, height: Math.round(LONG * 0.75) });
    r = { canvas, frames: 0, drawn: 0, lastFull: 0, lastSmall: 0, small: null };
    const drawer = (full) => (frame) => {
      // A small picture is drawn only while no full one has come for a while.
      if (full || performance.now() - r.lastFull > 500) {
        // The canvas takes the picture's own shape (upright, or wide).
        const [w, hgt] = sized(frame.displayWidth, frame.displayHeight, LONG);
        if (canvas.width !== w || canvas.height !== hgt) { canvas.width = w; canvas.height = hgt; this.onshape?.(); }
        canvas.getContext('2d').drawImage(frame, 0, 0, canvas.width, canvas.height);
        r.drawn++;
      }
      frame.close();
    };
    r.decoder = (full) => new VideoDecoder({ output: drawer(full), error: () => {} });
    r.video = r.decoder(true);
    r.small = r.decoder(false);
    if ('AudioDecoder' in globalThis) {
      r.audio = new AudioDecoder({ output: (data) => this.play(data), error: () => {} });
      r.audio.configure({ codec: 'opus', sampleRate: 48000, numberOfChannels: 1 });
    }
    this.remote.set(streamer, r);
    this.onchange?.();
    return r;
  }
  play(data) {
    // Each piece of sound after the one before, a little ahead of now.
    const ctx = this.ctx;
    if (!ctx) return data.close();
    const buffer = ctx.createBuffer(data.numberOfChannels, data.numberOfFrames, data.sampleRate);
    for (let ch = 0; ch < data.numberOfChannels; ch++) {
      const plane = new Float32Array(data.numberOfFrames);
      data.copyTo(plane, { planeIndex: ch, format: 'f32-planar' });
      buffer.copyToChannel(plane, ch);
    }
    data.close();
    // Kept LEAD ahead of now: behind (nothing came for a while), it starts
    // again there; more than LATE ahead (a burst, or two clocks apart), this
    // piece is let go so the sound catches up - the delay never grows.
    const now = ctx.currentTime;
    if (this.playAt < now + 0.02) this.playAt = now + LEAD;
    if (this.playAt > now + LATE) { this.dropped = (this.dropped || 0) + 1; return; }
    const src = ctx.createBufferSource();
    src.buffer = buffer;
    src.connect(ctx.destination);
    src.start(this.playAt);
    this.playAt += buffer.duration;
  }
  stats() {
    const k = this.info();
    const l = [...this.latency].sort((a, b) => a - b);
    const at = (p) => (l.length ? Math.round(l[Math.min(l.length - 1, Math.floor(p * l.length))]) : 0);
    let drawn = 0;
    for (const r of this.remote.values()) drawn += r.drawn;
    return { played: k?.played || 0, refused: k?.refused || 0, sent: k?.sent || 0, roots: k?.roots || 0, drawn, p50: at(0.5), p95: at(0.95), in: k?.in.length || 0 };
  }

  async hang() {
    const id = this.id;
    this.id = null;
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    this.stream?.getTracks().forEach((t) => t.stop());
    this.stream = null;
    this.latency = [];
    this.layers = {};
    for (const enc of [this.video, this.smallVideo, this.audio]) try { enc?.close(); } catch { /* closed */ }
    this.smallVideo = null;
    this.picked = null;
    for (const r of this.remote.values())
      for (const d of [r.video, r.small, r.audio]) try { d?.close(); } catch { /* closed */ }
    this.remote.clear();
    try { await this.ctx?.close(); } catch { /* closed */ }
    try { await this.micCtx?.close(); } catch { /* closed */ }
    this.ctx = this.micCtx = null;
    this.playAt = 0;
    if (id) { try { this.s.app.leaveCall(id); } catch { /* over */ } await this.s.pump(); }
  }
  // The other side hung up: what is open here closes too.
  ended(id) { if (id === this.id) this.hang(); }
}
