// Live state on the screen: tape tennis and the whiteboard. Both are states
// of the world (Wasm); this only draws what they are, as the App shows them
// (const), and fires what the hands do at their ports.
export const PALETTE = ['ink', '#d4382a', '#ff8f1f', '#ffc21a', '#5b2bd8', '#d81f8a', '#2a9d8f'];
const STRIPES = ['#ffc21a', '#ff8f1f', '#ff4f2b', '#d81f8a', '#5b2bd8'];

// ---- tape tennis ----
export class Court {
  constructor(session, id, canvas) {
    Object.assign(this, { s: session, id, canvas, move: 0, held: new Set(), raf: 0, timer: 0, onover: null });
    this.ctx = canvas.getContext('2d');
    this.keys = (e) => {
      const up = ['KeyW', 'ArrowUp'].includes(e.code), down = ['KeyS', 'ArrowDown'].includes(e.code);
      if (!up && !down) return;
      e.preventDefault();
      if (e.type === 'keydown') this.held.add(up ? 1 : -1); else this.held.delete(up ? 1 : -1);
      this.steer();
    };
    addEventListener('keydown', this.keys);
    addEventListener('keyup', this.keys);
    // A finger on the court: the paddle goes toward it.
    canvas.addEventListener('pointerdown', (e) => { this.finger = e; canvas.setPointerCapture(e.pointerId); });
    canvas.addEventListener('pointermove', (e) => { if (this.finger) this.finger = e; });
    canvas.addEventListener('pointerup', () => { this.finger = null; this.steer(); });
    this.timer = setInterval(() => this.s.pump(), 16);
    const frame = () => { this.draw(); this.raf = requestAnimationFrame(frame); };
    this.raf = requestAnimationFrame(frame);
  }
  press(dir, on) { if (on) this.held.add(dir); else this.held.delete(dir); this.steer(); }
  steer(target) {
    let m = this.held.has(1) ? 1 : this.held.has(-1) ? -1 : 0;
    if (target !== undefined) m = target;
    if (m !== this.move) { this.move = m; this.s.app.gameInput(this.id, m); }
  }
  view() { return this.s.app.games().find((g) => g.id === this.id); }
  draw() {
    const g = this.view();
    if (!g) { this.stop(); this.onover?.(); return; }
    const c = this.canvas, x = this.ctx, W = c.width, H = c.height;
    const X = (v) => ((v + 1) / 2) * W, Y = (v) => ((0.75 - v) / 1.5) * H;
    if (this.finger) {
      const r = c.getBoundingClientRect();
      const fy = 0.75 - ((this.finger.clientY - r.top) / r.height) * 1.5;
      const mine = g.player === 0 ? g.leftY : g.rightY;
      this.steer(fy > mine + 0.04 ? 1 : fy < mine - 0.04 ? -1 : 0);
    }
    x.fillStyle = '#141414';
    x.fillRect(0, 0, W, H);
    STRIPES.forEach((s, i) => { x.fillStyle = s; x.fillRect(0, i * 3, W, 3); x.fillRect(0, H - 15 + i * 3, W, 3); });
    x.strokeStyle = 'rgba(243,232,207,.25)';
    x.setLineDash([8, 10]);
    x.lineWidth = 3;
    x.beginPath(); x.moveTo(W / 2, 20); x.lineTo(W / 2, H - 20); x.stroke();
    x.setLineDash([]);
    x.fillStyle = '#f3e8cf';
    x.font = `${Math.round(H / 7)}px Righteous, sans-serif`;
    x.textAlign = 'center';
    x.fillText(String(g.left), W * 0.38, H * 0.2);
    x.fillText(String(g.right), W * 0.62, H * 0.2);
    const pad = (px, py, mine) => {
      x.fillStyle = mine ? '#ffc21a' : '#f3e8cf';
      x.fillRect(X(px) - 6, Y(py + 0.121), 12, Y(py - 0.121) - Y(py + 0.121));
    };
    pad(-0.88, g.leftY, g.player === 0);
    pad(0.88, g.rightY, g.player === 1);
    x.shadowColor = '#ff4f2b';
    x.shadowBlur = 16;
    x.fillStyle = '#ff4f2b';
    x.beginPath(); x.arc(X(g.ballX), Y(g.ballY), Math.max(6, W * 0.011), 0, Math.PI * 2); x.fill();
    x.shadowBlur = 0;
    // The tape's own lines, faintly.
    x.fillStyle = 'rgba(0,0,0,.18)';
    for (let yy = 0; yy < H; yy += 4) x.fillRect(0, yy, W, 1);
  }
  stop() {
    cancelAnimationFrame(this.raf);
    clearInterval(this.timer);
    removeEventListener('keydown', this.keys);
    removeEventListener('keyup', this.keys);
  }
}

// ---- the whiteboard ----
// A stroke: u8 8 | u8 color | u8 width | u16 n | n x (i16 x, i16 y); the
// board's square is -1..1 each way, as -32767..32767.
export function encodeStroke(color, width, points) {
  const n = Math.min(points.length, 4096);
  const b = new Uint8Array(5 + n * 4), d = new DataView(b.buffer);
  b[0] = 8; b[1] = color; b[2] = width;
  d.setUint16(3, n);
  for (let i = 0; i < n; i++) {
    d.setInt16(5 + i * 4, Math.round(Math.max(-1, Math.min(1, points[i][0])) * 32767));
    d.setInt16(7 + i * 4, Math.round(Math.max(-1, Math.min(1, points[i][1])) * 32767));
  }
  return b;
}
export function decodeStroke(b) {
  if (b.length < 5 || b[0] !== 8) return null;
  const d = new DataView(b.buffer, b.byteOffset, b.byteLength), n = d.getUint16(3);
  if (b.length !== 5 + n * 4) return null;
  const points = [];
  for (let i = 0; i < n; i++) points.push([d.getInt16(5 + i * 4) / 32767, d.getInt16(7 + i * 4) / 32767]);
  return { color: b[1], width: b[2], points };
}

export class Board {
  constructor(session, conv, canvas, strokes, names) {
    Object.assign(this, { s: session, conv, canvas, strokes, names, color: 0, width: 4, view: { x: 0, y: 0, zoom: 1 }, drawing: null,
      lastPen: 0, lastLook: 0, raf: 0, timer: 0, pan: false, leading: false });
    this.ctx = canvas.getContext('2d');
    this.ink = getComputedStyle(document.documentElement).getPropertyValue('--ink').trim() || '#141414';
    this.paper = getComputedStyle(document.documentElement).getPropertyValue('--cream').trim() || '#f3e8cf';
    canvas.addEventListener('pointerdown', (e) => this.down(e));
    canvas.addEventListener('pointermove', (e) => this.moveTo(e));
    canvas.addEventListener('pointerup', (e) => this.up(e));
    canvas.addEventListener('wheel', (e) => { e.preventDefault(); this.zoomBy(e.deltaY < 0 ? 1.15 : 1 / 1.15); }, { passive: false });
    this.timer = setInterval(() => this.s.pump(), 16);
    const frame = () => { this.draw(); this.raf = requestAnimationFrame(frame); };
    this.raf = requestAnimationFrame(frame);
    this.look(true);
  }
  // Where on the board a point of the screen is, and back.
  toBoard(e) {
    const r = this.canvas.getBoundingClientRect(), v = this.shown();
    return [((e.clientX - r.left) / r.width * 2 - 1) / v.zoom + v.x, -(((e.clientY - r.top) / r.height * 2 - 1) / v.zoom) + v.y];
  }
  shown() {
    const b = this.s.app.board(this.conv);
    // One who is not this device leads: where it looks is where everyone looks.
    if (b.leader && b.leader !== this.s.app.peer()) return { x: b.x, y: b.y, zoom: b.zoom || 1 };
    return this.view;
  }
  down(e) {
    this.canvas.setPointerCapture(e.pointerId);
    if (this.pan) { this.panFrom = { x: e.clientX, y: e.clientY, view: { ...this.view } }; return; }
    this.drawing = [this.toBoard(e)];
  }
  moveTo(e) {
    if (this.panFrom) {
      const r = this.canvas.getBoundingClientRect();
      this.view.x = this.panFrom.view.x - (e.clientX - this.panFrom.x) / r.width * 2 / this.view.zoom;
      this.view.y = this.panFrom.view.y + (e.clientY - this.panFrom.y) / r.height * 2 / this.view.zoom;
      this.look();
      return;
    }
    if (!this.drawing) return;
    const p = this.toBoard(e);
    this.drawing.push(p);
    const now = performance.now();
    if (now - this.lastPen > 33) { this.lastPen = now; this.s.app.pen(this.conv, p[0], p[1], true, this.color); }
  }
  up() {
    this.panFrom = null;
    if (!this.drawing) return;
    const pts = this.drawing;
    this.drawing = null;
    const last = pts[pts.length - 1];
    this.s.app.pen(this.conv, last[0], last[1], false, this.color);
    if (pts.length < 2) pts.push([pts[0][0] + 0.002, pts[0][1]]);
    const bytes = encodeStroke(this.color, this.width, pts);
    this.pending = decodeStroke(bytes);
    try { this.s.app.postStroke(this.conv, bytes, Date.now()); } catch (err) { console.warn(err); }
    this.s.pump();
  }
  zoomBy(f) { this.view.zoom = Math.max(0.25, Math.min(8, this.view.zoom * f)); this.look(); }
  reset() { this.view = { x: 0, y: 0, zoom: 1 }; this.look(); }
  look(now) {
    const t = performance.now();
    if (!now && t - this.lastLook < 80) { clearTimeout(this.lookLater); this.lookLater = setTimeout(() => this.look(true), 90); return; }
    this.lastLook = t;
    this.s.app.look(this.conv, this.view.x, this.view.y, this.view.zoom);
  }
  follow(on) { this.leading = on; this.s.app.lead(this.conv, on); this.look(true); }
  draw() {
    const c = this.canvas, x = this.ctx, W = c.width, H = c.height, v = this.shown();
    const SX = (bx) => ((bx - v.x) * v.zoom + 1) / 2 * W, SY = (by) => ((-(by - v.y)) * v.zoom + 1) / 2 * H;
    x.fillStyle = this.paper;
    x.fillRect(0, 0, W, H);
    // The board's square, and its grid.
    x.strokeStyle = 'rgba(128,128,128,.18)';
    x.lineWidth = 1;
    for (let g = -1; g <= 1.0001; g += 0.25) {
      x.beginPath(); x.moveTo(SX(g), SY(-1)); x.lineTo(SX(g), SY(1)); x.stroke();
      x.beginPath(); x.moveTo(SX(-1), SY(g)); x.lineTo(SX(1), SY(g)); x.stroke();
    }
    const line = (s) => {
      x.strokeStyle = s.color === 0 ? this.ink : PALETTE[s.color] || this.ink;
      x.lineWidth = Math.max(1, s.width * v.zoom * W / 800);
      x.lineCap = 'round'; x.lineJoin = 'round';
      x.beginPath();
      s.points.forEach((p, i) => (i ? x.lineTo(SX(p[0]), SY(p[1])) : x.moveTo(SX(p[0]), SY(p[1]))));
      x.stroke();
    };
    for (const s of this.strokes) line(s);
    if (this.pending) line(this.pending);
    if (this.drawing) line({ color: this.color, width: this.width, points: this.drawing });
    // The others' pens, where they are going.
    for (const p of this.s.app.board(this.conv).pens) {
      x.fillStyle = p.color === 0 ? this.ink : PALETTE[p.color] || this.ink;
      x.globalAlpha = p.down ? 1 : 0.5;
      x.beginPath(); x.arc(SX(p.x), SY(p.y), 7, 0, Math.PI * 2); x.fill();
      x.globalAlpha = 1;
      x.font = '600 12px Jost, sans-serif';
      x.fillText(this.names(p.peer), SX(p.x) + 10, SY(p.y) - 8);
    }
  }
  add(stroke) { this.strokes.push(stroke); this.pending = null; }
  stop() { cancelAnimationFrame(this.raf); clearInterval(this.timer); clearTimeout(this.lookLater); }
}
