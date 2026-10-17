// What the person sees: one screen at a time, drawn from what the world and
// the store say. The UI observes and fires: it reads a conversation's state
// (const, through the App) and the kept messages, and it sends to ports
// (post, read) and fires events (open, close). Every text a person or a
// peer wrote is set as text, never as markup.
import { needsHomeScreen } from './push.js';
import { Session } from './session.js';
import * as store from './store.js';
import { hex, forgetAll } from './crypto.js';
import { qrcode } from './vendor/qrcode.mjs';
import { KIND as FILE, recorder } from './media.js';
import { Calls } from './call.js';
import { Court, Board, decodeStroke, PALETTE } from './live.js';

const root = document.getElementById('app');

// Light, dark, or as the phone says: a choice of this browser's alone.
function theme(choice) {
  try {
    if (choice !== undefined) {
      if (choice === 'auto') localStorage.removeItem('p-chat.theme');
      else localStorage.setItem('p-chat.theme', choice);
    }
    choice = localStorage.getItem('p-chat.theme') || 'auto';
  } catch { choice = choice || 'auto'; }
  if (choice === 'auto') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', choice);
  const dark = choice === 'dark' || (choice === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches);
  document.querySelector('meta[name=theme-color]')?.setAttribute('content', dark ? '#141414' : '#d4382a');
  return choice;
}
theme();
matchMedia('(prefers-color-scheme: dark)').addEventListener?.('change', () => theme());
const KIND = { contact: 1, extra: 2, reusable: 3, channel: 4, recovery: 5, link: 6 };

// The link's fragment is read once and taken out of the address bar.
let invite = null, meeting = null, relinking = null;
if (location.hash.startsWith('#l1.')) {
  // A code shown by a device already paired, to link again in person (protocol 11).
  relinking = location.hash.slice(1);
  history.replaceState(null, '', location.pathname + location.search);
} else if (location.hash.startsWith('#d1.')) {
  // A code shown by a phone side by side (protocol 10): paired in person.
  meeting = location.hash.slice(1);
  history.replaceState(null, '', location.pathname + location.search);
} else if (location.hash.startsWith('#v1.')) {
  invite = location.hash.slice(1);
  history.replaceState(null, '', location.pathname + location.search);
}

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'text') el.textContent = v;
    else if (k === 'style') el.style.cssText = v;  // through CSSOM: the page's CSP allows no style attributes
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return el;
}
const svg = (markup) => { const t = document.createElement('template'); t.innerHTML = markup; return t.content.firstChild; };
// The name, set as the sleeve sets its title: "p", a dash that is the
// tape's stripes, "chat".
function logo() {
  return h('div', { class: 'logo', role: 'img', 'aria-label': 'p-chat' },
    h('span', { class: 'p' }, 'p'), h('span', { class: 'dash', 'aria-hidden': 'true' }, h('i'), h('i'), h('i'), h('i'), h('i')),
    h('span', { class: 'c' }, 'chat'));
}
// How the keyboard is used, said on a computer's screen (hidden on a phone).
const kbd = (k) => h('kbd', {}, k);
const keysHint = () => h('p', { class: 'keys-hint', 'data-test': 'keys-hint' },
  kbd('Enter'), ' sends · ', kbd('Shift'), ' + ', kbd('Enter'), ' a new line · ', kbd('Esc'), ' goes back');
// A fingerprint picture: the same drawing on every phone, whatever its fonts.
function emojiPic(e) {
  const code = Array.from(e.glyph).map((ch) => ch.codePointAt(0)).filter((c) => c !== 0xfe0f).map((c) => c.toString(16)).join('-');
  return h('img', { class: 'g', src: 'emoji/' + code + '.svg', alt: e.name, width: 48, height: 48, draggable: 'false' });
}

function head(title, opts = {}) {
  return h('div', { class: 'head' },
    opts.back ? h('button', { class: 'back', onclick: opts.back, 'data-test': 'back' }, '◀ ', opts.backText || 'Back') : null,
    logo(),
    h('h1', { class: 'display' + (opts.small ? ' small' : '') }, title));
}
function foot(...kids) {
  return h('footer', { class: 'foot' }, h('div', { class: 'row' }, ...kids));
}
function toast(text) {
  const t = h('div', { class: 'toast', role: 'status' }, text);
  document.body.append(t);
  setTimeout(() => t.remove(), 4500);
}
const DEPTH = { meet: 1, relink: 3, contacts: 0, unsupported: 0, unrecognized: 0, pair: 1, chat: 1, invite: 1, about: 1, error: 1, newgroup: 1,
  paired: 2, devices: 2, settings: 2, replace: 3, call: 2, game: 2, board: 2, linked: 3, unlink: 4, split: 5 };
let entering = null;

// A file in the conversation: its little picture at once, the thing itself
// once every chunk has come and the whole matches its hash.
const thumbs = new Map();
function thumbUrl(id, bytes) {
  if (!bytes?.length) return null;
  if (!thumbs.has(id)) thumbs.set(id, URL.createObjectURL(new Blob([bytes], { type: 'image/jpeg' })));
  return thumbs.get(id);
}
const size = (n) => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(0) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
const clock = (ms) => { const s = Math.round(ms / 1000); return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); };
function fileBubble(m, fresh) {
  const st = session.media.state(m.body);
  const meta = h('span', { class: 'meta', 'data-status': m.mine ? m.status || 'sent' : null }, when(m.time), m.mine ? ' ' + STATUS_MARK[m.status || 'sent'] : '');
  const base = 'msg file' + (m.mine ? ' mine' : '') + (fresh ? ' new' : '');
  if (!st) return h('div', { class: base }, 'A file this phone cannot read', meta);
  const { ref, id, progress } = st;
  const bar = progress ? h('span', { class: 'bar' }, h('i', { style: 'width:' + Math.round(100 * progress.have / progress.count) + '%' })) : null;
  if (ref.kind === FILE.sticker) {
    const img = h('img', { class: 'sticker-img', alt: 'sticker', 'data-test': 'sticker' });
    session.media.url(m.body).then((u) => { if (u) img.src = u; });
    return h('div', { class: 'msg sticker' + (m.mine ? ' mine' : '') + (fresh ? ' new' : ''), 'data-test': m.mine ? 'mine' : 'theirs' }, img, meta);
  }
  const wrap = h('div', { class: base, 'data-test': m.mine ? 'mine' : 'theirs', 'data-kind': ref.kind, 'data-blob': id });
  if (ref.kind === FILE.image || ref.kind === FILE.video) {
    const t = thumbUrl(id, ref.thumbnail);
    const pic = h('div', { class: 'pic', style: ref.width && ref.height ? 'aspect-ratio:' + ref.width + '/' + ref.height : '' },
      t ? h('img', { src: t, alt: '', class: 'blur' }) : null, ref.kind === FILE.video ? h('span', { class: 'play' }, '▶') : null, bar);
    wrap.append(pic, meta);
    session.media.url(m.body).then((u) => {
      if (!u) return;
      const full = ref.kind === FILE.image ? h('img', { src: u, alt: ref.name || 'picture', 'data-test': 'picture' })
        : h('video', { src: u, controls: true, playsinline: true, preload: 'metadata', 'data-test': 'video' });
      pic.replaceChildren(full);
    });
    return wrap;
  }
  if (ref.kind === FILE.voice) {
    const slot = h('div', { class: 'voice' }, h('span', { class: 'wave' }, '▮▮▯▮▮▯▮'), clock(ref.duration), bar);
    wrap.append(slot, meta);
    session.media.url(m.body).then((u) => { if (u) slot.replaceChildren(h('audio', { src: u, controls: true, 'data-test': 'voice' })); });
    return wrap;
  }
  const link = h('span', { class: 'doc' }, h('b', { dir: 'auto' }, ref.name || 'file'), h('span', {}, size(ref.size)), bar);
  wrap.append(link, meta);
  session.media.url(m.body).then((u) => {
    if (u) link.replaceChildren(h('a', { href: u, download: ref.name || 'file', 'data-test': 'download' }, '⬇ ', h('b', { dir: 'auto' }, ref.name || 'file')), h('span', {}, size(ref.size)));
  });
  return wrap;
}
// Who said it, in a group: what this device calls that contact (from the
// two-sided conversation the device belongs to), else a short device id.
function speaker(peer) {
  if (peer === session.app.peer()) return 'You';
  for (const id of session.conversations()) {
    const info = session.info(id);
    if (info.kind === 0 && info.members.some((m) => m.peer === peer)) return info.name;
  }
  return 'Device ' + peer.slice(0, 6);
}
function preview(m) {
  if (m.type !== 'file') return text(m.body);
  const st = session.media.state(m.body);
  const k = st?.ref.kind;
  return k === FILE.image ? 'Photo' : k === FILE.video ? 'Video' : k === FILE.voice ? 'Voice note' : k === FILE.sticker ? 'Sticker' : 'File: ' + (st?.ref.name || '');
}
function draw(...nodes) {
  root.replaceChildren(...nodes);
  if (!entering) return;
  // Entered: in from the side it lies on, with a pass of the tape's tracking.
  root.classList.remove('enter', 'from-right', 'from-left');
  void root.offsetWidth;
  root.classList.add('enter', entering);
  entering = null;
}
root.addEventListener('animationend', (e) => { if (e.target === root) root.classList.remove('enter', 'from-right', 'from-left'); });
const shortId = (peer) => peer.slice(0, 4) + '…' + peer.slice(-4);
const when = (t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const day = (t) => new Date(t).toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short' });
const text = (b) => new TextDecoder().decode(b);
// A name is at most 64 bytes of UTF-8 (the protocol's bound): cut by bytes,
// never inside a character, whatever the script.
function clip(name, bytes = 64) {
  let out = '', n = 0;
  for (const ch of name.trim()) {
    const len = new TextEncoder().encode(ch).length;
    if (n + len > bytes) break;
    out += ch;
    n += len;
  }
  return out;
}

const seenMsgs = new Set(), lastUnread = new Map();
// What became of a message: waiting here, in the mailbox, sent, delivered.
const STATUS_MARK = { queued: '◷', mailbox: '✉', sent: '✓', delivered: '✓✓', received: '' };
const state = { screen: 'loading', conv: null, alerts: new Map(), pairing: null, invite: null, ringing: new Map(), gameAsks: new Map(),
  update: null, fork: null };

const ui = {
  screen(name, data) { show(name, data); },
  async changed(conv) {
    renderSide();
    if (state.screen === 'chat' && (!conv || conv === state.conv)) await renderChat(false);
    else if (state.screen === 'contacts') await renderContacts();
    else if (state.screen === 'devices' && conv === state.conv) renderDevices();
    else if (state.screen === 'relink') renderRelinkStatus();
    else if (state.screen === 'invite' && state.invite?.kind !== KIND.contact && conv) renderInviteStatus();
    else if (state.screen === 'linked' || state.screen === 'split') show(state.screen, {});
    else if (state.screen === 'pair' && session.chats().length && !linkInvite()) {
      const c = session.chats()[0];
      show('paired', { conv: c, peer: session.info(c).members.find((m) => !m.self && m.side === 0)?.peer });
    }
  },
  alert(conv, kind, detail) {
    if (kind === 'invite_failed' && !conv) {
      if (state.screen === 'invite' || state.screen === 'pair' || state.screen === 'meet') return show('error', { kind: 'invite_failed' });
    }
    if (kind === 'pair_refused') return show('error', { kind: 'pair_refused', detail });
    if (conv) state.alerts.set(conv + ':' + kind, true);
    if (kind === 'invite_failed') return show('error', { kind: 'invite_failed' });
    if (kind === 'recovery_approve' && !(state.screen === 'chat' && state.conv === conv))
      toast(session.info(conv).name + ': a new device asks to replace a lost one. Open the chat to check it.');
    if (kind === 'recovery_of_me') toast('Someone says this phone is lost. Open ' + session.info(conv).name + ' to refuse.');
    this.changed(conv);
  },
  paired(conv, n) {
    if (state.screen === 'invite' || state.screen === 'pair' || state.screen === 'meet') show('paired', { conv, peer: n.peer, name: n.type });
    else toast('Paired with ' + (n.type || 'a new device'));
  },
  pairing(status) {
    state.pairing = status;
    if (status === 'asked') state.askedAt = Date.now();
    if (status === 'used') show('error', { kind: session.conversations().length ? 'invite_used' : 'unrecognized' });
    else if (state.screen === 'pair') renderPair();
    else if (state.screen === 'meet') renderMeet();
  },
  warn(t) { toast(t); },
  // Linked devices: the link ended here; the other device asks for a split; all forgotten.
  unlinked(why) {
    toast(why === 'split' ? 'Split. Each device keeps its own chats.' : why === 'forget' ? 'Unlinked. Leaving every chat, then erasing this device.'
      : why === 'keep' ? 'Unlinked. Leaving every chat; what was said stays here to read.' : 'Unlinked.');
    if (['linked', 'unlink', 'split'].includes(state.screen)) show('linked', {});
    else this.changed(null);
  },
  splitAsked() {
    if (state.screen === 'linked') show('linked', {});
    else toast('Your other device asks to split your chats. Open Settings → Linked devices.');
  },
  forgotten() { location.reload(); },
  ringing(conv, call, peer) {
    state.ringing.set(conv, { call, peer });
    if (state.screen === 'chat' && state.conv === conv) renderChat(false);
    else toast(speaker(peer) + ' is calling. Open the chat to answer.');
  },
  updateReady(version, from) {
    state.update = { version, from };
    toast('Release ' + version + ' is ready' + (from ? ' (from ' + speaker(from) + ')' : '') + '. It runs the next time you open p-chat.');
    this.releaseShown();
  },
  releaseFork(version) {
    state.fork = version;
    this.releaseShown();
  },
  releaseShown() {
    if (state.screen === 'contacts') renderContacts();
    else if (state.screen === 'chat') renderChat(false);
    else if (state.screen === 'about') renderAbout();
  },
  gameAsked(conv, game, peer) {
    state.gameAsks.set(conv, { game, peer });
    if (state.screen === 'chat' && state.conv === conv) renderChat(false);
    else toast(speaker(peer) + ' asks you to play table tennis.');
  },
  gameOn(conv, game) { show('game', { conv, game }); },
  gameOver(conv) {
    state.gameAsks.delete(conv);
    if (state.screen === 'game') show('chat', { conv });
    else this.changed(conv);
  },
  stroke(conv, body) {
    if (state.screen === 'board' && state.conv === conv && liveBoard) { const s = decodeStroke(body); if (s) liveBoard.add(s); }
  },
  callEnded(conv) {
    state.ringing.delete(conv);
    if (state.screen === 'call') show('chat', { conv });
    else this.changed(conv);
  },
};

const session = new Session(null, ui);

// What can be seen: on a phone the keyboard covers the bottom of the screen
// without making the page smaller (Safari), so a chat is fitted to the
// visual viewport - its top and height - and keeps its newest message in sight.
function fitToView() {
  const vv = globalThis.visualViewport;
  if (!vv) return;
  const s = document.documentElement.style;
  s.setProperty('--view-h', Math.round(vv.height) + 'px');
  s.setProperty('--view-top', Math.round(vv.offsetTop) + 'px');
  const tape = state.screen === 'chat' ? root.querySelector('.tape') : null;
  if (tape?.dataset.end === '1') tape.scrollTop = tape.scrollHeight;
}
globalThis.visualViewport?.addEventListener('resize', fitToView);
globalThis.visualViewport?.addEventListener('scroll', fitToView);
fitToView();

// Going back: each screen deeper than the one before is a step in the
// browser's history, so its back (a swipe on an iPhone, Android's key, the
// edge swipe of the Home Screen app) comes back here; a back key on screen
// that goes to the screen before steps the history back too, so the two
// never disagree. Pairing's screens replace each other (a finished pairing
// is not gone back into), and a call is left only by hanging up.
const PASSING = new Set(['pair', 'meet', 'relink', 'paired', 'error', 'unrecognized', 'unsupported']);
const steps = [];  // what the browser's history holds of p-chat, as it holds it
let fromHistory = false, expectPop = 0;
function stepTo(name) {
  const entry = { screen: name, conv: state.conv ?? null };
  const was = steps[steps.length - 1];
  try {
    if (was && steps.length > 1 && steps[steps.length - 2].screen === name && (steps[steps.length - 2].conv ?? null) === entry.conv) {
      // Back to the screen before: the history steps back with it.
      steps.pop();
      expectPop++;
      history.back();
    } else if (!was || PASSING.has(was.screen) || PASSING.has(name) || (DEPTH[name] ?? 1) <= (DEPTH[was.screen] ?? 0)) {
      if (was && (DEPTH[name] ?? 1) <= (DEPTH[was.screen] ?? 0) && !PASSING.has(was.screen)) { steps.length = 0; }
      steps[Math.max(0, steps.length - 1)] = entry;
      history.replaceState(entry, '');
    } else {
      steps.push(entry);
      history.pushState(entry, '');
    }
  } catch { /* no history here */ }
}
addEventListener('popstate', (e) => {
  if (expectPop) { expectPop--; return; }
  if (state.screen === 'call') { try { history.pushState({ screen: 'call', conv: state.conv }, ''); } catch { /* none */ } return; }
  steps.pop();
  const to = e.state?.screen || 'contacts';
  fromHistory = true;
  try { show(to, e.state?.conv ? { conv: e.state.conv } : {}); } finally { fromHistory = false; }
});
// The Home Screen app has no browser around it: a swipe in from the left edge goes back.
{
  let from = null;
  addEventListener('touchstart', (e) => { const t = e.touches[0]; from = t && t.clientX < 22 ? { x: t.clientX, y: t.clientY } : null; }, { passive: true });
  addEventListener('touchend', (e) => {
    const t = e.changedTouches[0];
    if (from && t && t.clientX - from.x > 80 && Math.abs(t.clientY - from.y) < 60 && steps.length > 1) history.back();
    from = null;
  }, { passive: true });
}

function show(name, data = {}) {
  if (state.screen === 'chat' && name !== 'chat' && state.conv) session.leave(state.conv);
  if (state.screen === 'game' && name !== 'game') { liveCourt?.stop(); liveCourt = null; }
  if (state.screen === 'board' && name !== 'board') { liveBoard?.stop(); liveBoard = null; try { session.app.closeBoard(state.conv); } catch { /* gone */ } }
  const from = DEPTH[state.screen] ?? 0, to = DEPTH[name] ?? 1;
  if (name !== state.screen || data.conv !== undefined) entering = to >= from ? 'from-right' : 'from-left';
  Object.assign(state, { screen: name, ...data });
  if (!fromHistory) stepTo(name);
  // A chat fills what can be seen and no more: its messages scroll inside it.
  const fitted = name === 'chat' || name === 'call' || name === 'game' || name === 'board';
  root.classList.toggle('fitted', fitted);
  // The page itself held still meanwhile: only what is meant to scroll does (iPhone).
  document.documentElement.classList.toggle('still', fitted);
  renderSide();
  const screens = { unsupported, unrecognized, pair: renderPair, contacts: renderContacts, chat: () => renderChat(true),
    invite: renderInvite, meet: renderMeet, relink: renderRelink, devices: renderDevices, paired: renderPaired, about: renderAbout, error: renderError, settings: renderSettings,
    newgroup: renderNewGroup, replace: renderReplace, call: renderCall, game: renderGame, board: renderBoard,
    linked: renderLinked, unlink: renderUnlink, split: renderSplit };
  (screens[name] || renderContacts)();
}

// ---- the screens ----

function unsupported() {
  draw(head('Too old'), h('main', {}, h('div', { class: 'band yellow' }, h('p', { class: 'caps', 'data-test': 'unsupported' }, 'Please update your browser')),
    h('div', { class: 'pad' }, h('p', {}, 'This browser cannot keep keys that cannot be copied out of it (Ed25519 and X25519 in WebCrypto). p-chat uses no other kind of key, so it stops here.'))));
}

// This phone's key is gone: it cannot open its chats, and a key cannot be
// made again. Starting again clears what it can no longer open.
function unrecognized() {
  draw(head('Key lost', { small: true }), h('main', {},
    h('div', { class: 'band red' }, h('p', { class: 'caps', 'data-test': 'unrecognized' }, 'This phone lost its key')),
    h('div', { class: 'pad' },
      h('p', {}, 'Its chats are still here, but it can no longer open them. A key cannot be made again.'),
      h('p', {}, 'Start again, then pair with your contacts once more.'),
      h('button', { class: 'btn wide', 'data-test': 'start-again', onclick: async () => {
        if (!confirm('Clear this phone\'s chats and start again?')) return;
        await forgetAll();
        location.reload();
      } }, 'Start again'))));
}


// The invite being paired with is a Link (another device of one's own): its
// pairing ends on the Linked screen the self conversation's notice shows.
function linkInvite() {
  try { return session.chat.parseInvite(invite).kind === KIND.link; } catch { return false; }
}
function renderPair() {
  const parsed = (() => { try { return session.chat.parseInvite(invite); } catch { return null; } })();
  if (!parsed) return show('error', { kind: 'bad_link' });
  const mail = h('input', { type: 'checkbox', 'data-test': 'mail' });
  const words = h('textarea', { autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', placeholder: 'six words', 'data-test': 'code' });
  const recovering = parsed.kind === KIND.recovery, linking = parsed.kind === KIND.link;
  const status = h('p', { class: 'fine', 'data-test': 'pair-status' },
    state.pairing === 'asked' && recovering ? 'Asked. The others approve; the lost device has a day to object. Show them these four pictures:' :
    state.pairing === 'asked' ? 'Asked. Waiting for the other phone to answer…' :
    state.pairing === 'offline' ? 'Can\'t connect. Trying again…' :
    state.pairing === 'working' ? 'Checking the words…' : '');
  // Asked, and no answer for a while (the request lost on the way, the other
  // phone away): it may be asked again.
  const stale = state.pairing === 'asked' && Date.now() - (state.askedAt || 0) > 30e3;
  if (state.pairing === 'asked' && !stale) setTimeout(() => state.screen === 'pair' && renderPair(), 31e3);
  const go = h('button', { class: 'btn wide', 'data-test': 'pair', disabled: state.pairing === 'working' || (state.pairing === 'asked' && !stale) },
    stale ? 'Ask again' : linking ? 'Link this device' : 'Pair this phone');
  go.onclick = async () => {
    let code;
    try { code = session.chat.normalizeCode(words.value); } catch { toast('That is not six words from the list. Check each word.'); return; }
    state.pairing = 'working';
    renderPair();
    await new Promise((r) => setTimeout(r, 30));
    try { await session.pair(invite, code, '', '', mail.checked); }
    catch (e) { state.pairing = null; toast(e.message); renderPair(); }
  };
  const mine = recovering && state.pairing === 'asked' && session.app ? session.app.fingerprintOf(session.app.peer()) : null;
  draw(head('Pair', { small: true, back: () => { state.pairing = null; show('contacts'); } }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, recovering ? 'In place of a lost device' : linking ? 'Link to your other device' : 'You were invited'),
      h('p', { class: 'caps light' }, (linking ? 'Your device ' : 'By device ') + shortId(parsed.owner))),
    h('div', { class: 'pad' },
      linking ? h('p', {}, 'This device becomes one with your other one: every chat on both, what was said given here, new chats on both. Type the six words your other device shows.')
        : h('p', {}, 'Type the six words you were told separately. Nothing you type leaves this phone: the words only prove this link was meant for you.'),
      h('label', { class: 'field' }, h('span', {}, 'The six words'), words),
      linking ? null : h('label', { class: 'check' }, mail, h('span', {}, 'When this phone is away, let messages wait on the relay, locked so only this phone can read them (up to 14 days). Otherwise they wait on the sender\'s phone until you are both online.')),
      go, status,
      mine ? h('div', { class: 'emoji', 'data-test': 'own-fingerprint' }, mine.map((e) => h('div', { 'data-glyph': e.glyph }, emojiPic(e), h('span', { class: 'n' }, e.name)))) : null)));
}

// The chats as the list shows them: on Chats (a phone), and in the side
// pane of a computer's wide window, the open one marked.
async function chatRows(selected = null) {
  const ids = session.chats();
  const rows = [];
  for (const id of ids) {
    const info = session.info(id);
    const ms = (await store.messages(id)).filter((m) => !m.hidden);
    const last = ms[ms.length - 1];
    rows.push(h('li', {}, h('button', { class: 'spine' + (id === selected ? ' on' : ''), 'data-test': selected === null ? 'contact' : 'side-contact', 'data-conv': id,
      'aria-current': id === selected ? 'true' : null, onclick: () => show('chat', { conv: id }) },
      h('span', { class: 'tag' }),
      h('span', {}, h('span', { class: 'name', dir: 'auto' }, info.name,
        info.kind === 1 ? h('span', { class: 'badge' }, 'group') : info.kind === 2 ? h('span', { class: 'badge' }, 'channel') : null), h('span', { class: 'last' },
        info.left ? 'Read only: this device left' : info.leaving ? 'Leaving…' : info.removed ? 'This device was removed'
          : last ? (last.mine ? 'You: ' : '') + preview(last) : 'No messages yet'),
        // A replacement waiting on this phone: said on the list, not only inside the chat.
        (() => {
          const [role, , , , , , approved] = (info.recovering || '').split(' ');
          if (role === 'me') return h('span', { class: 'flag red', 'data-test': 'flag-replaced' }, 'Says this phone is lost');
          if (role && role !== 'mine' && approved !== 'approved') return h('span', { class: 'flag', 'data-test': 'flag-approve' }, 'Approve a device');
          return null;
        })()),
      info.unread ? h('span', { class: 'count' + (info.unread > (lastUnread.get(id) || 0) ? ' bump' : ''), 'data-test': 'unread' }, String(info.unread)) : h('span', {}))));
    if (selected === null) lastUnread.set(id, info.unread);
  }
  const contacts = ids.some((id) => session.info(id).kind === 0 && !session.info(id).removed);
  return { ids, rows, contacts };
}
const chatsFoot = (contacts) => foot(h('div', { class: 'row' },
    h('button', { class: 'btn light', 'data-test': 'invite', onclick: () => show('invite', { invite: null }) }, 'Invite'),
    h('button', { class: 'btn light', 'data-test': 'new-group', disabled: !contacts, onclick: () => show('newgroup', { channel: false }) }, 'Group'),
    h('button', { class: 'btn light', 'data-test': 'new-channel', disabled: !contacts, onclick: () => show('newgroup', { channel: true }) }, 'Channel')),
  h('button', { class: 'label cream', onclick: () => show('about') }, 'About'));
const noChats = () => h('div', { class: 'empty', 'data-test': 'no-chats' },
  h('p', { class: 'caps' }, 'No chats yet'),
  h('p', {}, 'Invite someone: they scan your code, or open your link.'),
  h('button', { class: 'btn wide', 'data-test': 'start-invite', onclick: () => show('invite', { invite: null }) }, 'Invite someone'),
  h('button', { class: 'btn light wide', 'data-test': 'scan-code', onclick: () => scanned() }, 'Scan their code'),
  h('p', { class: 'fine' }, 'Were you sent a link? Open it on this phone.'));
async function renderContacts() {
  const { ids, rows, contacts } = await chatRows();
  if (state.screen !== 'contacts') return;
  const band = h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'This phone'),
    h('p', { class: 'caps light' }, ids.length ? ids.length + (ids.length === 1 ? ' conversation' : ' conversations') : 'Private messages, phone to phone'));
  if (wide()) {
    // A computer: the list is beside (with its keys); here, room to begin.
    draw(head('Hello'), h('main', {}, releaseBanners(), installBanner(), band, h('div', { class: 'lines' }),
      h('div', { class: ids.length ? 'empty pick' : 'empty welcome', 'data-test': ids.length ? 'pick' : 'no-chats' },
        h('p', { class: 'caps' }, ids.length ? 'Pick a chat on the left' : 'No chats yet'),
        h('p', {}, ids.length ? 'Or begin a new one.' : 'Invite someone: they scan your code, or open your link.'),
        h('div', { class: 'row' }, h('button', { class: 'btn', 'data-test': 'start-invite', onclick: () => show('invite', { invite: null }) }, 'Invite someone'),
          h('button', { class: 'btn light', 'data-test': 'scan-code', onclick: () => scanned() }, 'Scan their code')),
        ids.length ? null : h('p', { class: 'fine' }, 'Were you sent a link? Open it in this browser.'),
        keysHint())));
    return;
  }
  draw(head('Chats'), h('main', {}, releaseBanners(), installBanner(), band, h('div', { class: 'lines' }),
    ids.length ? h('ul', { class: 'shelf' }, rows) : noChats()),
  chatsFoot(contacts));
}

// A computer's wide window: the chats in a pane of their own beside the
// screen, the open chat marked; a phone has one screen at a time.
const wideWindow = globalThis.matchMedia?.('(min-width: 900px)');
const wide = () => !!wideWindow?.matches;
const side = document.getElementById('side');
let sideTimer = 0;
function renderSide() {
  clearTimeout(sideTimer);
  sideTimer = setTimeout(async () => {
    if (!wide() || ['unsupported', 'unrecognized', 'loading'].includes(state.screen)) { side.hidden = true; return; }
    const open = ['chat', 'devices', 'call', 'game', 'board', 'replace'].includes(state.screen) ? state.conv : '';
    const { ids, rows, contacts } = await chatRows(open);
    side.hidden = false;
    side.replaceChildren(head('Chats', { small: true }),
      h('main', {}, ids.length ? h('ul', { class: 'shelf' }, rows) : h('p', { class: 'fine side-empty' }, 'No chats yet.')),
      chatsFoot(contacts));
  }, 60);
}
wideWindow?.addEventListener('change', () => { renderSide(); if (state.screen) show(state.screen, {}); });
// Esc goes back, on a computer as the back key does on a phone.
addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  // The camera reading a code closes first; a call is left only by hanging up.
  const scanner = document.querySelector('[data-test=scanner-cancel]');
  if (scanner) { scanner.click(); return; }
  if (state.screen === 'call') return;
  if (steps.length > 1) history.back();
});

let drawnChat = null;
async function renderChat(first) {
  const id = state.conv;
  if (!session.chats().includes(id)) return show('contacts');
  if (first) await session.enter(id);
  else if (document.visibilityState === 'visible') await session.read(id);
  const info = session.info(id);
  const ms = (await store.messages(id)).filter((m) => !m.hidden);
  const missing = await session.missing(id);
  const tape = h('div', { class: 'tape', 'data-test': 'tape' });
  const firstLook = !seenMsgs.has(id);
  let lastDay = '', lastSpeaker = null;
  for (const m of ms) {
    const d = day(m.time);
    if (d !== lastDay) { tape.append(h('div', { class: 'day' }, d)); lastDay = d; }
    if (m.type === 'device_revoked') { tape.append(h('div', { class: 'day' }, 'A device was removed')); continue; }
    const k = id + '/' + m.peer + '/' + m.seq;
    const fresh = seenMsgs.has(id) && !seenMsgs.has(k);
    seenMsgs.add(k);
    if (info.kind === 1 && !m.mine && m.peer !== lastSpeaker) tape.append(h('div', { class: 'speaker', dir: 'auto' }, speaker(m.peer)));
    lastSpeaker = m.mine ? null : m.peer;
    if (m.type === 'file') { tape.append(fileBubble(m, fresh)); continue; }
    tape.append(h('div', { class: 'msg' + (m.mine ? ' mine' : '') + (fresh ? ' new' : ''), dir: 'auto', 'data-test': m.mine ? 'mine' : 'theirs' }, text(m.body),
      h('span', { class: 'meta', 'data-status': m.mine ? m.status || 'sent' : null }, when(m.time), m.mine ? ' ' + STATUS_MARK[m.status || 'sent'] : '')));
  }
  const banners = [];
  // Left when it was unlinked: a copy to read, said plainly.
  if (info.left || info.leaving) banners.push(h('div', { class: 'banner', 'data-test': 'left' }, h('b', {}, info.leaving && !info.removed ? 'Leaving' : 'Read only'),
    info.leaving && !info.removed ? 'This device is leaving this chat (it was unlinked). Your other device stays in it.'
      : 'This device left this chat when it was unlinked. What was said stays here to read; nothing more comes or goes.'));
  else if (info.removed) banners.push(h('div', { class: 'banner red', 'data-test': 'removed' }, h('b', {}, 'Removed'), 'This device was removed. Ask ' + info.name + ' for a new key.'));
  if (state.alerts.has(id + ':equivocation')) banners.push(h('div', { class: 'banner red', 'data-test': 'equivocation' }, h('b', {}, 'Two versions'),
    'A device sent two different messages under the same number. Both are kept as evidence. Someone may be tampering with this conversation.'));
  if (state.alerts.has(id + ':history_differs')) banners.push(h('div', { class: 'banner red', 'data-test': 'history-differs' }, h('b', {}, 'History differs'),
    'Your devices do not agree on this conversation\'s history: a message was dropped, changed or moved on the way.'));
  banners.push(...releaseBanners());
  const recovering = recoveryBanner(id, info);
  if (recovering) banners.push(recovering);
  const asked = state.gameAsks.get(id);
  if (asked && session.app.games().some((g) => g.id === asked.game && !g.playing)) banners.push(h('div', { class: 'banner ring', 'data-test': 'game-asked' },
    h('b', {}, 'Table tennis'), speaker(asked.peer) + ' asks you to play.',
    h('div', { class: 'row' },
      h('button', { class: 'btn', 'data-test': 'play-accept', onclick: () => {
        state.gameAsks.delete(id);
        try { session.app.joinGame(asked.game); session.pump(); } catch (e) { toast(e.message); }
      } }, 'Play'),
      h('button', { class: 'btn light', 'data-test': 'play-decline', onclick: () => {
        state.gameAsks.delete(id); session.app.leaveGame(asked.game); session.pump(); renderChat(false);
      } }, 'Not now'))));
  const ringing = state.ringing.get(id);
  const ring = ringing && session.app.calls().find((k) => k.id === ringing.call && !k.joined);
  if (ring) banners.push(h('div', { class: 'banner ring', 'data-test': 'ringing' },
    h('b', {}, ring.mode === 1 ? 'Live' : 'Calling'), speaker(ringing.peer) + (ring.mode === 1 ? ' is live.' : ' is calling.'),
    h('div', { class: 'row' },
      h('button', { class: 'btn', 'data-test': 'answer', onclick: async () => {
        state.ringing.delete(id);
        try { await session.calls.answer(ringing.call); show('call', { conv: id }); } catch (e) { toast(e.message); }
      } }, ring?.mode === 1 ? 'Watch' : 'Answer'),
      h('button', { class: 'btn light', 'data-test': 'decline', onclick: () => { state.ringing.delete(id); session.calls.decline(ringing.call); renderChat(false); } }, 'Decline'))));
  if (missing.length) banners.push(h('div', { class: 'banner', 'data-test': 'missing' }, h('b', {}, 'Message missing'),
    missing.length + (missing.length === 1 ? ' message was' : ' messages were') + ' sent but never arrived. ' + (missing.length === 1 ? 'It' : 'They') + ' may have been lost on the way.'));
  // No relay and no link to them: nothing can reach them, so nothing is sent
  // (one side moving on alone is what a chat must never do).
  const cut = !info.removed && !session.canSend(id);
  // Cut off: say why and the two ways back, right here.
  if (cut && !info.left && !info.leaving) banners.push(h('div', { class: 'banner', 'data-test': 'cut' }, h('b', {}, 'Not reachable'),
    session.relayOn() ? 'No link to them, and this chat has no relay. Link again: one of you shows a code, the other scans it.'
      : 'Relays are off and the link between you dropped (a phone asleep is enough). Link again in person, or turn a relay on: it only passes locked messages.',
    h('div', { class: 'row' },
      h('button', { class: 'btn', 'data-test': 'cut-relink', onclick: () => show('relink', { relink: null, relinkCode: null, relinkLink: null, relinkDone: false, relinkFrom: id }) }, 'Link again'),
      session.relayOn() ? null : h('button', { class: 'btn light', 'data-test': 'cut-relay', onclick: async () => { await session.setRelay(true); renderChat(false); } }, 'Turn a relay on'))));
  const shut = info.removed || info.left || info.leaving;
  const input = h('textarea', { rows: 1, placeholder: info.left || info.leaving ? 'Read only' : info.removed ? 'Removed' : cut ? 'Not linked to them, and no relay: can\'t send now' : 'Message',
    disabled: shut || cut, 'data-test': 'message', dir: 'auto', maxlength: 20000, 'aria-label': 'Message' });
  const key = h('button', { class: 'key', 'data-test': 'send', 'aria-label': 'Send', title: 'Send', disabled: shut || cut });
  // The key sends what is written; with nothing written it records a voice
  // note (tap, speak, tap again), and while recording it stops.
  const KEY = {
    send: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 2.5v15L17.5 10z" fill="currentColor" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>',
    voice: '<svg viewBox="0 0 20 20" aria-hidden="true"><rect x="7" y="2" width="6" height="11" rx="3" fill="currentColor"/><path d="M4 9a6 6 0 0 0 12 0M10 15v3" stroke="currentColor" stroke-width="2" fill="none"/></svg>',
    stop: '<svg viewBox="0 0 20 20" aria-hidden="true"><rect x="5" y="5" width="10" height="10" rx="2" fill="currentColor"/></svg>',
  };
  const keyShows = () => {
    const now = rec ? 'stop' : input.value.trim() ? 'send' : 'voice';
    if (key.dataset.shows === now) return;
    key.dataset.shows = now;
    key.setAttribute('aria-label', { send: 'Send', voice: 'Record a voice note', stop: 'Stop and send' }[now]);
    key.classList.toggle('voice', now !== 'send');
    key.classList.toggle('recording', now === 'stop');
    key.replaceChildren(svg(KEY[now]));
  };
  // What was just said, in sight: the list goes to its end.
  const toEnd = () => { const tp = root.querySelector('.tape'); if (tp) { tp.scrollTop = tp.scrollHeight; tp.dataset.end = '1'; } };
  const grow = () => { input.style.height = 'auto'; input.style.height = Math.min(input.scrollHeight + 4, 140) + 'px'; };
  input.addEventListener('input', grow);
  const send = async () => {
    const t = input.value.trim();
    if (!t || !session.canSend(id)) return;
    input.value = '';
    grow();
    key.classList.remove('fire');
    void key.offsetWidth;
    key.classList.add('pressed', 'fire');
    setTimeout(() => key.classList.remove('pressed'), 120);
    keyShows();
    await session.send(id, t);
    await renderChat(false);
    toEnd();
  };
  key.onclick = () => (rec || !input.value.trim() ? voice() : send());
  // Sending from the keyboard keeps it up: the key never takes the focus
  // from what is being written (a phone would drop its keyboard and raise it
  // again). Sent on the finger's lift, so no click (and no blur) follows.
  key.addEventListener('mousedown', (e) => { if (document.activeElement === input) e.preventDefault(); });
  key.addEventListener('touchend', (e) => {
    if (document.activeElement !== input || rec || !input.value.trim() || key.disabled) return;
    e.preventDefault();
    send();
  }, { passive: false });
  input.addEventListener('input', () => keyShows());
  const pick = (accept, kind) => {
    const f = h('input', { type: 'file', accept, class: 'hidden', 'data-test': 'file-' + kind });
    f.onchange = async () => {
      setTray(false);
      for (const file of f.files) {
        try { await session.sendFile(id, file); } catch (e) { toast(e.message); }
      }
      await renderChat(false);
      toEnd();
    };
    return f;
  };
  const photos = pick('image/*,video/*', 'media'), files = pick('', 'any');
  const stickers = h('div', { class: 'stickers hidden', 'data-test': 'sticker-picker' });
  session.media.stickers().then((pack) => stickers.append(...pack.stickers.map((s) =>
    h('button', { class: 'sticker-key', 'data-test': 'sticker-' + s.file, onclick: async () => {
      stickers.classList.add('hidden'); setTray(false);
      await session.media.sticker(id, s).catch((e) => toast(e.message));
      await renderChat(false);
      toEnd();
    } }, h('img', { src: 'stickers/' + s.file, alt: s.file.replace('.svg', '') })))));
  let rec = null;
  async function voice() {
    if (!rec) {
      if (!session.canSend(id)) return;
      try { rec = await recorder(); mic.classList.add('recording'); mic.lastChild.textContent = 'Stop'; } catch (e) { toast('No microphone: ' + e.message); }
      keyShows();
      return;
    }
    const r = rec;
    rec = null;
    mic.classList.remove('recording');
    mic.lastChild.textContent = 'Voice';
    keyShows();
    const v = await r.stop();
    setTray(false);
    try {
      await session.sendPrepared(id, { kind: FILE.voice, blob: v.blob, mime: v.mime, name: 'voice', duration: v.duration, width: 0, height: 0, thumbnail: new Uint8Array(0) });
    } catch (e) { toast(e.message); }
    await renderChat(false);
    toEnd();
  }
  const mic = h('button', { class: 'tray-key', 'data-test': 'voice', onclick: voice }, svg('<svg viewBox="0 0 20 20" aria-hidden="true"><rect x="7" y="2" width="6" height="11" rx="3" fill="currentColor"/><path d="M4 9a6 6 0 0 0 12 0M10 15v3" stroke="currentColor" stroke-width="2" fill="none"/></svg>'), h('span', {}, 'Voice'));
  const tray = h('div', { class: 'tray hidden', 'data-test': 'tray' },
    h('button', { class: 'tray-key', 'data-test': 'pick-media', onclick: () => photos.click() }, svg('<svg viewBox="0 0 20 20" aria-hidden="true"><rect x="2" y="4" width="16" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="7" cy="9" r="1.6" fill="currentColor"/><path d="M3 15l5-5 4 4 2-2 3 3" fill="none" stroke="currentColor" stroke-width="2"/></svg>'), h('span', {}, 'Photo')),
    h('button', { class: 'tray-key', 'data-test': 'pick-file', onclick: () => files.click() }, svg('<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 2h7l4 4v12H5z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M12 2v4h4" fill="none" stroke="currentColor" stroke-width="2"/></svg>'), h('span', {}, 'File')),
    h('button', { class: 'tray-key', 'data-test': 'pick-sticker', onclick: () => stickers.classList.toggle('hidden') }, svg('<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="7" cy="8" r="1.3" fill="currentColor"/><circle cx="13" cy="8" r="1.3" fill="currentColor"/><path d="M6 12a4.5 4.5 0 0 0 8 0" fill="none" stroke="currentColor" stroke-width="2"/></svg>'), h('span', {}, 'Sticker')),
    info.kind !== 2 ? liveKey(id, 'board') : null,
    info.kind === 0 ? liveKey(id, 'play') : null,
    mic, photos, files);
  const attach = h('button', { class: 'key attach', 'data-test': 'attach', 'aria-label': 'Attach', title: 'Attach', disabled: shut || cut,
    onclick: () => setTray(tray.classList.contains('hidden')) });
  // The tray and its key say the same thing, always: open, the + turned to ×.
  function setTray(open) {
    tray.classList.toggle('hidden', !open);
    attach.classList.toggle('open', open);
    if (!open) stickers.classList.add('hidden');
  }
  attach.append(svg('<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 3v14M3 10h14" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/></svg>'));
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } });
  keyShows();
  // Another screen came while this one was being made: it is not drawn over it.
  if (state.screen !== 'chat' || state.conv !== id) return;
  const chathead = h('div', { class: 'chathead' },
    h('button', { class: 'back to-list', 'data-test': 'back', 'aria-label': 'Back', onclick: () => show('contacts') }, '◀'),
    h('div', {}, h('h1', { 'data-test': 'chat-name', dir: 'auto' }, info.name), h('div', { class: 'sub' },
      info.kind === 2 ? (info.member ? 'Your channel' : 'Channel · read only')
        : info.kind === 1 ? info.members.length + ' devices · group' : info.members.length - 1 + (info.members.length === 2 ? ' device' : ' devices') + ' · sealed',
      info.kind === 2 || info.left ? null : h('span', { class: 'reach', 'data-test': 'reach' }, ' · ' + { linked: 'linked', relay: 'through the relay', none: 'not reachable now',
        carried: 'through ' + session.relayingName(id) }[session.reachedBy(id)]))),
    info.member && info.kind !== 2 && Calls.supported() && !info.removed ? callKey(id) : null,
    info.member && info.kind === 1 && Calls.supported() && !info.removed ? callKey(id, true) : null,
    h('button', { class: 'label', 'data-test': 'devices', onclick: () => show('devices') }, 'Devices'));
  const body = h('main', {}, banners, tape);
  // Drawn again over itself (a message came): the heading and the messages
  // are new; the composer is the one already there - never focused, never
  // replaced - so the keyboard, what was typed and an open tray stay as they
  // were. Only what may have changed of it is said again.
  const kept = drawnChat === id ? root.querySelector(`.composer[data-chat="${id}"]`) : null;
  const was = root.querySelector('.tape');
  const atEnd = !was || was.scrollHeight - was.scrollTop - was.clientHeight < 48;
  if (kept && root.querySelector('.chathead') && root.querySelector('#app > main')) {
    root.querySelector('.chathead').replaceWith(chathead);
    root.querySelector('#app > main').replaceWith(body);
    const ki = kept.querySelector('[data-test=message]');
    if (ki) { ki.disabled = input.disabled; ki.placeholder = input.placeholder; }
    for (const test of ['send', 'attach']) {
      const k = kept.querySelector(`[data-test=${test}]`);
      if (k) k.disabled = shut || cut;
    }
  } else {
    draw(chathead, body,
      info.left || info.leaving
        ? h('div', { class: 'composer reader', 'data-test': 'read-only', 'data-chat': id }, h('p', { class: 'caps light' }, 'Read only · this device left'))
        : info.kind === 2 && !info.member
        ? h('div', { class: 'composer reader', 'data-test': 'read-only', 'data-chat': id }, h('p', { class: 'caps light' }, 'Only ' + (info.introduced || 'its publisher') + ' posts here'))
        : h('div', { class: 'composer', 'data-chat': id }, stickers, tray, attach, input, key));
    grow();
  }
  drawnChat = id;
  seenMsgs.add(id);
  void firstLook;
  // The newest in sight, unless one had scrolled up to read.
  tape.scrollTop = atEnd ? tape.scrollHeight : was.scrollTop;
  tape.addEventListener('scroll', () => { tape.dataset.end = tape.scrollHeight - tape.scrollTop - tape.clientHeight < 48 ? '1' : ''; });
  tape.dataset.end = atEnd ? '1' : '';
}

async function pictures(fp, test) {
  return h('div', { class: 'emoji', 'data-test': test }, fp.map((e) => h('div', { 'data-glyph': e.glyph }, emojiPic(e), h('span', { class: 'n' }, e.name))));
}
// A recovery under way, as each one sees it: the one who asked, the ones who
// approve (after comparing the new device's pictures), the device said to be lost.
function recoveryBanner(id, info) {
  if (!info.recovering) return null;
  const [role, lost, fresh, at, votes, quorum, approved] = info.recovering.split(' ');
  const ready = new Date(Number(at)).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' });
  const whose = info.members.find((m) => m.peer === lost)?.side === info.side ? 'your' : info.name + '\'s';
  if (role === 'me') return h('div', { class: 'banner red', 'data-test': 'recovery-of-me' }, h('b', {}, 'Being replaced'),
    'Someone says this device is lost and asks for a new one in its place. If that is not you, refuse now.',
    h('div', { class: 'row' }, h('button', { class: 'btn warn', 'data-test': 'refuse-recovery', onclick: async () => {
      await session.refuseRecovery(id); toast('Refused. This device stays.');
    } }, 'Refuse: it is not lost')));
  if (role === 'mine') return h('div', { class: 'banner', 'data-test': 'recovery-mine' }, h('b', {}, 'Replacing a device'),
    'Approvals ' + votes + ' of ' + quorum + '. The new device takes its place ' + ready + ', unless the old one refuses.');
  return h('div', { class: 'banner', 'data-test': 'recovery-approve' }, h('b', {}, 'A lost device?'),
    'A new device asks to take the place of ' + whose + ' device ' + shortId(lost) + '. Check with ' + info.name +
    ', in person or by voice, that the new device shows these four pictures.',
    pictures(session.app.fingerprintOf(fresh), 'recovery-fingerprint'),
    approved === 'approved' ? h('p', { class: 'fine' }, 'You approved. It takes effect ' + ready + '.')
      : h('div', { class: 'row' }, h('button', { class: 'btn', 'data-test': 'approve-recovery', onclick: async () => {
        try { await session.approveRecovery(id); toast('Approved.'); } catch (e) { toast(e.message); }
      } }, 'They match: approve')));
}

async function renderInvite() {
  if (state.invite?.link) return renderInviteShown();
  const contacts = session.chats().filter((id) => session.info(id).side === 0 && session.info(id).kind === 0);
  const pick = h('select', { 'data-test': 'for' }, contacts.map((id) => h('option', { value: id }, session.info(id).name)));
  if (state.screen !== 'invite') return;
  const meet = async () => {
    try {
      const made = await session.inPerson();
      state.invite = { inPerson: true, link: made.link, token: made.token, kind: KIND.contact, relayed: made.relayed };
      renderInviteShown();
    } catch (e) { toast(e.message); }
  };
  const linked = session.relayOn();
  const make = async (kind) => {
    try {
      const conv = kind === KIND.contact || kind === KIND.link ? '' : pick.value;
      if (kind !== KIND.contact && kind !== KIND.link && !conv) { toast('Pick whose device it is.'); return; }
      const made = await session.invite(kind, conv);
      state.invite = { ...made, kind, conv };
      renderInviteShown();
    } catch (e) { toast(e.message); }
  };
  draw(head('Invite', { back: () => show('contacts') }), h('main', {}, h('div', { class: 'choices' },
    h('button', { class: 'choice yellow', 'data-test': 'kind-code', onclick: meet },
      h('p', { class: 'caps' }, 'A new contact'), h('p', { class: 'caps light' }, 'They scan your code, or open your link')),
    h('button', { class: 'choice amber', 'data-test': 'kind-contact', onclick: () => make(KIND.contact), disabled: !linked },
      h('p', { class: 'caps' }, 'A new contact, with six words'), h('p', { class: 'caps light' }, 'Safer from afar: the link alone is not enough')),
    h('button', { class: 'choice orange', 'data-test': 'kind-extra', onclick: () => make(KIND.extra), disabled: !contacts.length || !linked },
      h('p', { class: 'caps' }, 'Another device of…'), h('p', { class: 'caps light' }, 'One more phone or computer for a contact')),
    h('button', { class: 'choice red', 'data-test': 'kind-reusable', onclick: () => make(KIND.reusable), disabled: !contacts.length || !linked },
      h('p', { class: 'caps' }, 'Reusable device key for…'), h('p', { class: 'caps light' }, 'Works until you cancel it')),
    h('button', { class: 'choice violet', 'data-test': 'kind-link', onclick: () => make(KIND.link), disabled: !linked },
      h('p', { class: 'caps' }, 'My other device'), h('p', { class: 'caps light' }, 'Link your phone and computer: one you, every chat on both'))),
    h('div', { class: 'pad' },
      linked ? null : h('p', { class: 'fine', 'data-test': 'relay-off-note' }, 'Relays are off (Settings), so invites go in person only.'),
      contacts.length ? h('label', { class: 'field' }, h('span', {}, 'Whose device'), pick) : null,
      h('button', { class: 'btn light', 'data-test': 'scan-code', onclick: () => scanned() }, 'They showed you a code? Scan it'))));
}
function renderInviteShown() {
  if (state.screen !== 'invite') return;
  const inv = state.invite;
  if (inv.inPerson) return renderInPerson(inv);
  const qr = qrcode(0, 'M');
  qr.addData(inv.link);
  qr.make();
  const img = h('img', { class: 'qr', alt: 'Invite link as a QR code', src: qr.createDataURL(8, 0), 'data-test': 'qr', 'data-link': inv.link });
  const words = inv.code.split(' ');
  draw(head('Invite', { small: true, back: () => { state.invite = null; show('contacts'); } }), h('main', {}, h('div', { class: 'split' }, h('div', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, inv.kind === KIND.contact ? 'Scan with their phone camera' : inv.kind === KIND.link ? 'Scan with your other device' : 'Scan with the new device')),
    h('div', { class: 'pad center' }, img,
      h('div', { class: 'row' }, h('button', { class: 'btn light', onclick: async () => { await navigator.clipboard?.writeText(inv.link); toast('Link copied. Send it; say the words separately.'); } }, 'Copy link')))),
    h('div', {}, h('div', { class: 'band amber' }, h('p', { class: 'caps' }, 'Then say these six words'), h('p', { class: 'caps light' }, 'Out loud or another way. Never with the link.')),
    h('div', { class: 'pad' }, h('ol', { class: 'words', 'data-test': 'words' }, words.map((w) => h('li', {}, w))),
      h('p', { class: 'fine', 'data-test': 'invite-status' }, inv.kind === KIND.contact ? 'Waiting for them to pair…'
        : inv.kind === KIND.link ? 'Waiting for your other device…'
        : inv.kind === KIND.recovery ? 'Waiting… the others approve, and the lost device has a day to object.' : 'Waiting… their other device must approve.'),
      h('button', { class: 'btn light', onclick: async () => { await session.cancelInvite(inv.token); state.invite = null; show('contacts'); } }, 'Cancel invite'))))));
}
function renderInviteStatus() {
  const s = root.querySelector('[data-test=invite-status]');
  if (s && state.invite?.conv && state.invite.kind === KIND.recovery) {
    const r = session.info(state.invite.conv).recovering.split(' ');
    s.textContent = r[0] === 'mine' ? 'Asked. Approvals ' + r[4] + ' of ' + r[5] + '; it takes effect ' +
      new Date(Number(r[3])).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' }) + '.' : 'Waiting for the new device…';
  } else if (s && state.invite?.conv) {
    const n = session.info(state.invite.conv).members.length - 1;
    s.textContent = 'Now ' + n + (n === 1 ? ' device.' : ' devices.') + ' Waiting for approval…';
  }
}

function renderNewGroup() {
  const channel = state.channel;
  const name = h('input', { dir: 'auto', placeholder: channel ? 'What the channel is called' : 'What the group is called', 'data-test': 'group-name' });
  const contacts = session.conversations().filter((id) => session.info(id).kind === 0 && !session.info(id).removed);
  const picks = contacts.map((id) => h('label', { class: 'check' }, h('input', { type: 'checkbox', value: id, 'data-test': 'pick-contact' }),
    h('span', { dir: 'auto' }, session.info(id).name)));
  const make = async () => {
    const n = clip(name.value);
    if (!n) { toast('Give it a name.'); return; }
    const chosen = picks.map((p) => p.firstChild).filter((x) => x.checked).map((x) => x.value);
    if (!channel && !chosen.length) { toast('Pick who is in it.'); return; }
    try {
      const id = await session.createGroup(n, chosen, channel);
      show('chat', { conv: id });
    } catch (e) { toast(e.message); }
  };
  draw(head(channel ? 'Channel' : 'Group', { small: true, back: () => show('contacts') }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, channel ? 'Only you post' : 'Everyone talks'),
      h('p', { class: 'caps light' }, channel ? 'Readers come by invite, and only read' : 'Each phone has its own key; it turns when people come and go')),
    h('div', { class: 'pad' }, h('label', { class: 'field' }, h('span', {}, 'Name'), name),
      channel ? null : h('div', {}, h('p', { class: 'caps' }, 'Who is in it'), picks.length ? h('div', { class: 'picks' }, picks) : h('p', { class: 'fine' }, 'Pair with someone first.')),
      h('button', { class: 'btn wide', 'data-test': 'make-group', onclick: make }, channel ? 'Make the channel' : 'Make the group'))));
}

// A new contact's code: their camera opens it, or they open it as a link.
// With a relay, that is all - their request comes back through it. With
// none, their phone shows a code back, and this one scans it.
function renderInPerson(inv) {
  const qr = qrcode(0, 'L');
  qr.addData(inv.link);
  qr.make();
  const img = h('img', { class: 'qr', alt: 'Your p-chat code', src: qr.createDataURL(8, 0), 'data-test': 'qr', 'data-link': inv.link });
  const relayed = !!inv.relayed;
  const status = h('p', { class: 'fine', 'data-test': 'invite-status' }, inv.joining ? 'Joining the two phones…' : 'Waiting for them…');
  const take = async (text) => {
    try {
      await session.theirCode(text);
      inv.joining = true;
      status.textContent = 'Joining the two phones…';
    } catch (e) { toast(e.message); }
  };
  const scan = () => scanQR('Scan the code on their phone', take);
  const pasted = h('input', { autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none', placeholder: 'p-chat:a1.…', 'data-test': 'answer-text' });
  draw(head('Invite', { small: true, back: () => { session.endPairing(); state.invite = null; show('contacts'); } }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Let them scan this'), h('p', { class: 'caps light' }, 'Or send them the link')),
    h('div', { class: 'split' }, h('div', { class: 'pad center' }, img,
      h('div', { class: 'row' }, h('button', { class: 'btn light', 'data-test': 'copy-link', onclick: async () => {
        await navigator.clipboard?.writeText(inv.link).catch(() => {});
        toast('Link copied. Anyone with it can pair, once: send it only to them.');
      } }, 'Copy link'))),
    h('div', { class: 'pad' }, status,
      h('p', { class: 'fine' }, relayed ? 'Their phone answers through the relay. If it shows a code instead, scan it:'
        : 'No relay: when their phone shows a code, scan it.'),
      h('button', { class: relayed ? 'btn light' : 'btn wide', 'data-test': 'scan-answer', onclick: scan }, 'Scan their code'),
      h('label', { class: 'field' }, h('span', {}, 'Or paste their code'), pasted),
      h('button', { class: 'btn light', 'data-test': 'use-answer', onclick: () => take(pasted.value) }, 'Use this code')))));
}

// Linking again in person (protocol 11): with no relay, a device that lost
// every link (closed and opened again) is found by none. One scan with a
// contact - or with the device that relays for you - links the two again,
// and through it the rest. This side shows its code and scans the answer;
// the other (state.relink, the code it was shown) shows its answer back.
async function renderRelink() {
  if (state.relinkDone) {
    // Done: the code was used once, and is not shown again.
    draw(head('Link again', { small: true, back: () => show('contacts') }), h('main', {},
      h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Linked again'), h('p', { class: 'caps light' }, 'The rest come back through it')),
      h('div', { class: 'pad' }, h('p', { class: 'fine', 'data-test': 'relink-status' }, 'Linked again.'),
        h('button', { class: 'btn wide', 'data-test': 'relink-done', onclick: () => state.relinkFrom ? show('chat', { conv: state.relinkFrom }) : show('contacts') }, 'Done'))));
    return;
  }
  if (state.relink) {
    if (!state.relinkCode) {
      const go = h('button', { class: 'btn wide', 'data-test': 'relink-answer', onclick: async () => {
        go.disabled = true;
        try { state.relinkCode = await session.answerRelink(state.relink); renderRelink(); } catch (e) { go.disabled = false; toast(e.message); }
      } }, 'Show my code');
      draw(head('Link again', { small: true, back: () => show('contacts') }), h('main', {},
        h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Link again in person'), h('p', { class: 'caps light' }, 'With a device you are already paired with')),
        h('div', { class: 'pad' }, h('p', { class: 'fine' }, 'Your phones join directly. Only locked signals go between them, to find each other again; nothing is paired anew.'), go)));
      return;
    }
    const qr = qrcode(0, 'L');
    qr.addData(state.relinkCode);
    qr.make();
    draw(head('Link again', { small: true, back: () => { session.endPairing(); show('contacts'); } }), h('main', {},
      h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Show them this code'), h('p', { class: 'caps light' }, 'Their device scans it')),
      h('div', { class: 'pad' }, h('img', { class: 'qr', alt: 'Your answer as a code', src: qr.createDataURL(8, 0), 'data-test': 'relink-qr', 'data-code': state.relinkCode }),
        h('div', { class: 'row' }, h('button', { class: 'btn light', 'data-test': 'copy-relink', onclick: async () => {
          await navigator.clipboard?.writeText(state.relinkCode).catch(() => {});
          toast('Copied. Send it to them: they paste it where they would scan it.');
        } }, 'Copy code')),
        h('p', { class: 'fine', 'data-test': 'relink-status' }, relinkSaid()))));
    return;
  }
  if (!state.relinkLink) {
    // One code at a time, however often the screen is drawn meanwhile; an
    // old one is not left on screen while the new one is made.
    draw(head('Link again', { small: true, back: () => { session.endPairing(); show('settings'); } }), h('main', {},
      h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Making your code'), h('p', { class: 'caps light' }, 'A few seconds')),
      h('div', { class: 'pad' }, h('p', { class: 'fine', 'data-test': 'relink-status' }, 'Finding how this device can be reached…'))));
    state.relinkMaking ??= session.relinkOffer().then((l) => { state.relinkLink = l; }).finally(() => { state.relinkMaking = null; });
    try { await state.relinkMaking; } catch (e) { toast(e.message); return show('settings'); }
    if (state.screen !== 'relink' || state.relink) return;
  }
  const qr = qrcode(0, 'L');
  qr.addData(state.relinkLink);
  qr.make();
  const take = async (text) => {
    try { await session.theirCode(text); renderRelinkStatus('Joining…'); } catch (e) { toast(e.message); }
  };
  const pasted = h('input', { autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none', placeholder: 'p-chat:a1.…', 'data-test': 'relink-text' });
  draw(head('Link again', { small: true, back: () => { session.endPairing(); state.relinkLink = null; state.relinkFrom ? show('chat', { conv: state.relinkFrom }) : show('settings'); } }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Let them scan this'), h('p', { class: 'caps light' }, 'A device you are paired with')),
    h('div', { class: 'pad' }, h('img', { class: 'qr', alt: 'Your code to link again', src: qr.createDataURL(8, 0), 'data-test': 'relink-link', 'data-link': state.relinkLink }),
      h('div', { class: 'row' }, h('button', { class: 'btn light', 'data-test': 'copy-relink-link', onclick: async () => {
        await navigator.clipboard?.writeText(state.relinkLink).catch(() => {});
        toast('Link copied. Send it only to them.');
      } }, 'Copy link')),
      h('p', { class: 'fine', 'data-test': 'relink-status' }, relinkSaid()),
      h('button', { class: 'btn wide', 'data-test': 'relink-scan', onclick: () => scanQR('Scan the code on their device', take) }, 'Scan their code'),
      h('label', { class: 'field' }, h('span', {}, 'Or paste their code'), pasted),
      h('button', { class: 'btn light', 'data-test': 'relink-use', onclick: () => take(pasted.value) }, 'Use this code'))));
}
function relinkSaid() {
  const p = session.pairing;
  if (p?.role !== 'relink') return 'Closed. Make a new code to try again.';
  if (p.linked) return 'Linked again.';
  if (p.link.up) return 'Joined. Finding your chats…';
  return state.relink ? 'Waiting for them to scan it…' : 'When their device shows a code, scan it.';
}
function renderRelinkStatus(text) {
  const p = session.pairing;
  if (!state.relinkDone && p?.role === 'relink' && p.linked) { state.relinkDone = true; return renderRelink(); }
  const s = root.querySelector('[data-test=relink-status]');
  if (s) s.textContent = text || relinkSaid();
}

// The phone shown a code in person: its names, then a code of its own back.
function renderMeet() {
  let d;
  try { d = session.inPersonInvite(state.meet); } catch { return show('error', { kind: 'bad_link' }); }
  if (state.meetAsked && !state.meetCode) {
    draw(head('Pair', { small: true, back: () => { state.meetAsked = false; show('contacts'); } }), h('main', {},
      h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Pairing'), h('p', { class: 'caps light' }, 'By device ' + shortId(d.parsed.owner))),
      h('div', { class: 'pad' }, h('p', { class: 'fine', 'data-test': 'pair-status' },
        state.pairing === 'offline' ? 'Can\'t connect. Trying again…' : 'Asked. Waiting for their phone…'))));
    return;
  }
  if (state.meetCode) {
    const qr = qrcode(0, 'L');
    qr.addData(state.meetCode);
    qr.make();
    const status = state.pairing === 'asked' ? 'Asked. Waiting for their phone…' : state.pairing === 'offline' ? 'The phones could not join. Try again side by side.'
      : 'Waiting for them to scan it…';
    draw(head('In person', { small: true, back: () => { session.endPairing(); state.meetCode = null; show('contacts'); } }), h('main', {},
      h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Show them this code'), h('p', { class: 'caps light' }, 'Their phone scans it')),
      h('div', { class: 'split' }, h('div', { class: 'pad center' }, h('img', { class: 'qr', alt: 'Your answer as a code', src: qr.createDataURL(8, 0), 'data-test': 'answer-qr', 'data-code': state.meetCode }),
        h('div', { class: 'row' }, h('button', { class: 'btn light', 'data-test': 'copy-answer', onclick: async () => {
          await navigator.clipboard?.writeText(state.meetCode).catch(() => {});
          toast('Copied. Send it to them: they paste it where they would scan it.');
        } }, 'Copy code'))),
        h('div', { class: 'pad' }, h('p', { class: 'fine', 'data-test': 'pair-status' }, status),
          h('p', { class: 'keys-hint' }, 'Their phone scans it with its camera, and the two are paired. Or copy the code and send it to them.')))));
    return;
  }
  const mail = h('input', { type: 'checkbox', 'data-test': 'mail' });
  const relayed = !!d.parsed.relay && session.relayOn();
  const go = h('button', { class: 'btn wide', 'data-test': 'show-answer', onclick: async () => {
    go.disabled = true;
    try {
      if (relayed) {
        // The code names a relay: the request goes back through it, and that is all.
        state.meetAsked = true;
        await session.pair(d.fragment, d.code, '', '', mail.checked);
        renderMeet();
      } else {
        state.meetCode = await session.answerInPerson(d, '', '', mail.checked);
        renderMeet();
      }
    } catch (e) { go.disabled = false; state.meetAsked = false; toast(e.message); }
  } }, relayed ? 'Pair' : 'Show my code');
  draw(head('In person', { small: true, back: () => show('contacts') }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'You were invited'), h('p', { class: 'caps light' }, 'By device ' + shortId(d.parsed.owner))),
    h('div', { class: 'pad' },
      h('label', { class: 'check' }, mail, h('span', {}, 'When this phone is away, let messages wait for it, locked so only it can read them: at a relay, or with contacts who carry for others.')),
      go)));
}

// A code read by the camera: shown in person (d1), or an invite link (v1).
async function scanned() {
  scanQR('Scan the code on their phone', (text) => {
    const at = text.indexOf('#');
    const frag = at >= 0 ? text.slice(at + 1) : '';
    state.pairing = null;
    if (frag.startsWith('d1.')) return show('meet', { meet: frag, meetCode: null, meetAsked: false });
    if (frag.startsWith('l1.')) return show('relink', { relink: frag, relinkCode: null, relinkDone: false, relinkFrom: null });
    if (frag.startsWith('v1.')) { invite = frag; return show('pair'); }
    toast('That is not a p-chat code.');
  });
}
// The camera, until it reads a QR code: the browser's own reader where it
// has one, else jsQR (web/vendor) on frames drawn to a canvas.
async function scanQR(title, onText) {
  let stream = null, timer = 0, done = false;
  const close = () => { done = true; clearTimeout(timer); stream?.getTracks().forEach((tr) => tr.stop()); box.remove(); };
  const video = h('video', { playsinline: '', muted: '', autoplay: '' });
  const box = h('div', { class: 'scanner', 'data-test': 'scanner' }, h('p', { class: 'caps' }, title), video,
    h('button', { class: 'btn light', 'data-test': 'scanner-cancel', onclick: close }, 'Cancel'));
  document.body.append(box);
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
  } catch (e) { close(); toast('No camera: ' + e.message); return; }
  if (done) { stream.getTracks().forEach((tr) => tr.stop()); return; }
  video.srcObject = stream;
  await video.play().catch(() => {});
  let detector = null;
  try { if ((await globalThis.BarcodeDetector?.getSupportedFormats())?.includes('qr_code')) detector = new globalThis.BarcodeDetector({ formats: ['qr_code'] }); } catch { /* none */ }
  if (!detector) await import('./vendor/jsQR.js');
  const canvas = document.createElement('canvas'), ctx = canvas.getContext('2d', { willReadFrequently: true });
  const look = async () => {
    if (done) return;
    let text = null;
    try {
      if (detector) text = (await detector.detect(video))[0]?.rawValue || null;
      else if (video.videoWidth) {
        const w = Math.min(video.videoWidth, 960), hgt = Math.round(video.videoHeight * (w / video.videoWidth));
        canvas.width = w; canvas.height = hgt;
        ctx.drawImage(video, 0, 0, w, hgt);
        text = globalThis.jsQR(ctx.getImageData(0, 0, w, hgt).data, w, hgt, { inversionAttempts: 'dontInvert' })?.data || null;
      }
    } catch { /* the next frame */ }
    if (text) { close(); onText(text); } else timer = setTimeout(look, 200);
  };
  look();
}

function renderPaired() {
  const { conv, peer } = state;
  const info = session.info(conv);
  if (info.kind === 3) return renderLinkedPaired(conv, peer);
  const other = peer || info.members.find((m) => !m.self)?.peer;
  const fp = session.app.fingerprintWith(other);
  // What you call them is yours: chosen here, on this phone, and never sent.
  const naming = info.kind !== 1;
  const call = h('input', { value: info.name === 'New contact' ? '' : info.name, autocomplete: 'off', dir: 'auto', maxlength: 64,
    placeholder: 'Only you see this name', 'data-test': 'call-them' });
  const go = async () => {
    const n = clip(call.value);
    if (naming && n && n !== info.name) await session.rename(conv, n);
    state.invite = null;
    show('chat', { conv });
  };
  call.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  draw(head('Paired', { small: true, back: go }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Paired')),
    h('div', { class: 'pad paired' },
      naming ? h('label', { class: 'field' }, h('span', {}, 'What do you call them?'), call) : null,
      h('div', { class: 'emoji', 'data-test': 'fingerprint' }, fp.map((e) => h('div', { 'data-glyph': e.glyph }, emojiPic(e), h('span', { class: 'n' }, e.name)))),
      h('p', {}, 'Both phones show these four pictures. To be sure no one stood between you, compare them by voice.'),
      h('button', { class: 'btn wide', 'data-test': 'open-chat', onclick: go }, 'Start talking'))));
}

function addToGroup(id) {
  const inGroup = new Set(session.info(id).members.map((m) => m.peer));
  const others = session.conversations().filter((c) => session.info(c).kind === 0 &&
    session.info(c).members.some((m) => !m.self && !inGroup.has(m.peer)));
  if (!others.length) return null;
  const pick = h('select', { 'data-test': 'add-who' }, others.map((c) => h('option', { value: c }, session.info(c).name)));
  return h('div', { class: 'row' }, pick, h('button', { class: 'btn light', 'data-test': 'add-to-group', onclick: async () => {
    try { await session.addToGroup(id, pick.value); toast('Adding… the others must approve.'); } catch (e) { toast(e.message); }
  } }, 'Add'));
}

function renderDevices() {
  // Drawn again after something was done here: not over a screen opened since.
  if (state.screen !== 'devices') return;
  const id = state.conv;
  const info = session.info(id);
  const owner = info.side === 0;
  const rows = info.members.map((m) => {
    const fp = m.self ? null : session.app.fingerprintWith(m.peer);
    return h('div', { class: 'device', 'data-test': 'device', 'data-peer': m.peer },
      h('div', { class: 'who' }, m.self ? 'This device' : m.linked ? 'Your linked device' : m.side === 0 ? (owner ? 'Your device' : info.name + '\'s device') : (owner ? info.name + '\'s device' : 'Your other device')),
      h('div', { class: 'id' }, m.peer),
      fp ? h('div', { class: 'emoji' }, fp.map((e) => h('div', { 'data-glyph': e.glyph }, emojiPic(e), h('span', { class: 'n' }, e.name)))) : null,
      !m.self && owner && m.side === 1 ? h('button', { class: 'btn warn', 'data-test': 'revoke', onclick: async () => {
        if (!confirm('Remove this device? It will be told, and it will need a new key from you.')) return;
        try { await session.revoke(id, m.peer); toast('Removing… the other devices must approve.'); } catch (e) { toast(e.message); }
      } }, 'Remove') : null,
      !m.self && info.recovery && info.kind !== 2 && !info.recovering ? h('button', { class: 'btn light', 'data-test': 'replace', onclick: () => show('replace', { conv: id, lost: m.peer }) }, 'Replace: lost') : null);
  });
  const rename = h('input', { value: info.name, dir: 'auto', 'data-test': 'rename' });
  const mail = info.mailbox;
  const delivery = h('div', { class: 'pad' },
    h('p', { class: 'caps' }, 'Delivery'),
    h('div', { class: 'theme', role: 'group', 'aria-label': 'Delivery' },
      h('button', { class: 'btn light', 'aria-pressed': String(!mail), 'data-test': 'delivery-live', onclick: async () => { await session.setDelivery(id, false); renderDevices(); } }, 'Live only'),
      h('button', { class: 'btn light', 'aria-pressed': String(mail), 'data-test': 'delivery-mailbox', onclick: async () => { await session.setDelivery(id, true); renderDevices(); } }, 'Mailbox too')),
    h('p', { class: 'fine' }, mail
      ? 'When this phone is away, messages for it wait on the relay, locked so only this phone can read them, for up to 14 days.'
      : 'The relay keeps nothing for this phone: messages wait on the sender\'s phone until both are online.'));
  const DISAPPEAR = [[0, 'Never'], [3600, '1 hour'], [86400, '1 day'], [604800, '1 week']];
  const options = h('div', { class: 'pad' },
    h('p', { class: 'caps' }, 'This chat'),
    h('div', { class: 'theme', role: 'group', 'aria-label': 'Recovery' },
      h('button', { class: 'btn light', 'aria-pressed': String(info.recovery), 'data-test': 'recovery-on', onclick: async () => { await session.setOptions(id, false, info.disappear); renderDevices(); } }, 'Recovery'),
      h('button', { class: 'btn light', 'aria-pressed': String(!info.recovery), 'data-test': 'recovery-off', onclick: async () => {
        if (!confirm('No recovery: if a phone is lost, its history is gone with it. For everyone in this chat.')) return;
        await session.setOptions(id, true, info.disappear); renderDevices();
      } }, 'No recovery')),
    h('p', { class: 'fine' }, info.recovery
      ? 'A lost phone can be replaced: the others approve, the old one has a day to object, and the new one may be given the history.'
      : 'A lost phone cannot be replaced, and its history dies with it.'),
    h('label', { class: 'field' }, h('span', {}, 'Messages disappear after'),
      h('select', { 'data-test': 'disappear', onchange: async (e) => { await session.setOptions(id, !info.recovery, Number(e.target.value)); renderDevices(); } },
        DISAPPEAR.map(([s, t]) => h('option', { value: s, selected: info.disappear === s ? '' : null }, t)))),
    h('p', { class: 'fine' }, info.disappear ? 'Gone from every phone, from what waits to be sent, and from the relay.' : ''),
    signalPicker(id));
  draw(head('Devices', { small: true, back: () => show('chat', { conv: id }) }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, info.name),
      h('p', { class: 'caps light' }, (info.introduced && info.introduced !== info.name ? 'Calls themself ' + info.introduced + ' · ' : '') + 'Generation ' + info.generation)),
    // Two columns on a computer: what this chat is to you, then its devices.
    h('div', { class: 'cols' }, h('div', { class: 'col' },
    h('div', { class: 'pad' }, h('label', { class: 'field' }, h('span', {}, 'What you call them (only you see this)'), rename),
      h('button', { class: 'btn light', 'data-test': 'rename-save', onclick: async () => {
        const n = clip(rename.value);
        if (!n) return;
        await session.rename(id, clip(n));
        renderDevices();
      } }, 'Rename')),
    delivery,
    info.kind !== 2 ? options : null), h('div', { class: 'col' },
    rows,
    h('div', { class: 'pad' },
      owner && info.kind === 0 ? h('button', { class: 'btn light', onclick: () => { state.invite = null; show('invite'); } }, 'Add a device for ' + info.name) : null,
      owner && info.kind === 2 ? h('button', { class: 'btn light', 'data-test': 'invite-readers', onclick: async () => {
        try {
          const made = await session.invite(4, id, '');
          state.invite = { ...made, kind: 4, conv: id };
          show('invite', { invite: state.invite });
        } catch (e) { toast(e.message); }
      } }, 'Invite readers') : null,
      owner && info.kind === 1 ? addToGroup(id) : null,
      h('button', { class: 'btn warn', 'data-test': 'forget', onclick: async () => {
        if (!confirm('Forget ' + info.name + ' on this device? The messages here are deleted.')) return;
        await session.removeContact(id);
        show('contacts');
      } }, 'Forget contact'))))));
}

// The symbol a notification for this chat shows, chosen here and known only here.
const SIGNALS = ['🌙', '🌵', '🍋', '🐟', '🎈', '🔔', '🌊', '🍄', '🎲', '🔥', '🍀', '🦋', '🍒', '🐬', '🌈'];
function signalPicker(id) {
  const row = h('div', { class: 'signals', role: 'radiogroup', 'aria-label': 'Notification symbol', 'data-test': 'signals' });
  const fill = async () => {
    const now = (await store.signals())[id] || '';
    row.replaceChildren(
      h('button', { class: 'sig', role: 'radio', 'aria-checked': String(!now), 'data-test': 'signal-none', onclick: async () => { await session.setSignal(id, ''); fill(); } }, '•'),
      ...SIGNALS.map((s) => h('button', { class: 'sig', role: 'radio', 'aria-checked': String(now === s), 'data-test': 'signal', 'data-symbol': s,
        onclick: async () => { await session.setSignal(id, s); fill(); } }, emojiPic({ glyph: s, name: s }))));
  };
  fill();
  return h('div', {}, h('p', { class: 'caps' }, 'Notification symbol'), row,
    h('p', { class: 'fine' }, 'When this chat wakes your phone, it shows only this. No one else knows which symbol is which chat.'));
}

// A call: the key in the chat's head, and the screen while it is on.
function callKey(id, live = false) {
  const key = h('button', { class: 'label call-key', 'data-test': live ? 'go-live' : 'call', 'aria-label': live ? 'Go live' : 'Call',
    title: live ? 'Go live' : 'Call', onclick: async () => {
      if (!session.canCall(id)) { toast('Calls need a relay, so a dropped call can always find its way back. Turn relays on in Settings.'); return; }
      try { await session.calls.start(id, live); show('call', { conv: id }); } catch (e) { toast(e.message); }
    } });
  if (!session.canCall(id)) key.classList.add('off');
  key.append(svg(live
    ? '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="2.6" fill="currentColor"/><path d="M5.8 5.8a6 6 0 0 0 0 8.4M14.2 5.8a6 6 0 0 1 0 8.4M3.2 3.2a9.6 9.6 0 0 0 0 13.6M16.8 3.2a9.6 9.6 0 0 1 0 13.6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>'
    : '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5.5 2.5l3 3.2-1.6 2a10 10 0 0 0 5.4 5.4l2-1.6 3.2 3-1.6 2.6c-.4.6-1.1.9-1.8.7A15.5 15.5 0 0 1 2.2 6.9c-.2-.7.1-1.4.7-1.8z" fill="currentColor"/></svg>'));
  return key;
}
let callTimer = null;
// A call, in the sleeve's own look: the chat's heading, the other side large
// in the court's frame (ink, the stepped stripes), you in its corner, and
// keys that press in at the foot, as the composer's do.
const ICON = {
  mic: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="3" width="6" height="11" rx="3" fill="currentColor"/><path d="M5.5 11a6.5 6.5 0 0 0 13 0M12 17.5V21" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
  micOff: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="3" width="6" height="11" rx="3" fill="currentColor"/><path d="M5.5 11a6.5 6.5 0 0 0 13 0M12 17.5V21M4 4l16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
  cam: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="6.5" width="12.5" height="11" rx="2.5" fill="currentColor"/><path d="M16.5 10.5l4.5-2.5v8l-4.5-2.5z" fill="currentColor"/></svg>',
  camOff: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="6.5" width="12.5" height="11" rx="2.5" fill="currentColor"/><path d="M16.5 10.5l4.5-2.5v8l-4.5-2.5zM4 4l16 16" fill="currentColor" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
  hang: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 13.5c5.4-4.8 13.6-4.8 19 0l-1.9 3-3.7-1.4v-2.6a9.5 9.5 0 0 0-7.8 0v2.6l-3.7 1.4z" fill="currentColor"/></svg>',
};
function renderCall() {
  const id = state.conv;
  const k = session.calls.info();
  if (!k) return show('chat', { conv: id });
  const info = session.info(id);
  const live = k.mode === 1;
  const screens = h('div', { class: 'screens', 'data-test': 'tiles' });
  const me = session.calls.stream ? h('video', { class: 'me', muted: true, autoplay: true, playsinline: true, 'aria-label': 'You' }) : null;
  if (me) { me.muted = true; me.srcObject = session.calls.stream; }
  // A picture fills its glass when its shape is near the glass's; else it is shown whole.
  const fit = () => {
    for (const c of screens.querySelectorAll('canvas')) {
      const box = c.parentElement.getBoundingClientRect();
      if (!box.width || !box.height || !c.width) continue;
      const a = c.width / c.height, b = box.width / box.height;
      c.style.objectFit = Math.max(a / b, b / a) < 1.45 ? 'cover' : 'contain';
    }
  };
  const fill = () => {
    const remote = [...session.calls.remote.entries()];
    screens.dataset.n = String(Math.min(remote.length, 4));
    // Through a tree: a screen tapped is that speaker's full picture.
    screens.replaceChildren(...remote.map(([peer, r]) =>
      h('figure', { class: 'tile' + (session.calls.picked === peer ? ' picked' : ''), 'data-test': 'tile', 'data-peer': peer,
        onclick: () => k.mode === 2 && session.calls.pick(peer) }, r.canvas, h('figcaption', { dir: 'auto' }, speaker(peer)))));
    if (!remote.length) screens.append(h('div', { class: 'calling' }, h('div', { class: 'rings' }, h('i'), h('i'), h('i'), h('b')),
      h('p', {}, live && k.starter === session.app.peer() ? 'On air' : 'Calling ' + info.name + '…'),
      h('p', { class: 'fine' }, live && k.starter === session.app.peer() ? 'Viewers join from the chat.' : 'Sealed: only they can open it.')));
    requestAnimationFrame(fit);
  };
  session.calls.onchange = fill;
  session.calls.onshape = () => requestAnimationFrame(fit);
  fill();
  const clock = h('span', { 'data-test': 'call-clock' }, '0:00');
  const stats = h('p', { class: 'stats', 'data-test': 'call-stats' });
  const key = (test, label, on, off, pressed, act) => {
    const b = h('button', { class: 'key deck', 'data-test': test, 'aria-label': label, 'aria-pressed': String(pressed()), onclick: () => {
      act(); b.setAttribute('aria-pressed', String(pressed())); b.replaceChildren(svg(pressed() ? off : on));
    } });
    b.append(svg(pressed() ? off : on));
    return b;
  };
  const mute = key('mute', 'Mute', ICON.mic, ICON.micOff, () => session.calls.muted, () => { session.calls.muted = !session.calls.muted; });
  const cam = key('camera', 'Camera off', ICON.cam, ICON.camOff, () => !session.calls.camera, () => { session.calls.camera = !session.calls.camera; });
  const hang = h('button', { class: 'key hang', 'data-test': 'hang', 'aria-label': 'Hang up', onclick: async () => {
    await session.calls.hang(); show('chat', { conv: id });
  } });
  hang.append(svg(ICON.hang));
  draw(h('div', { class: 'chathead callhead' },
      h('div', {}, h('h1', { dir: 'auto' }, info.name),
        h('div', { class: 'sub' }, (live ? (k.starter === session.app.peer() ? 'Live · ' : 'Watching · ') : 'Sealed · '), clock))),
    h('main', { class: 'call' }, screens, me),
    h('div', { class: 'composer decks' }, session.calls.stream ? mute : null, hang, session.calls.stream ? cam : null, stats));
  clearInterval(callTimer);
  const began = Date.now();
  const tick = () => {
    if (state.screen !== 'call') return clearInterval(callTimer);
    const s = session.calls.stats();
    const secs = Math.floor((Date.now() - began) / 1000);
    clock.textContent = Math.floor(secs / 60) + ':' + String(secs % 60).padStart(2, '0');
    const fw = session.calls.info()?.forwarders?.filter(Boolean).length || 0;
    stats.textContent = `${s.in} in the call · ${s.played} played · ${s.refused} refused · ${s.p50} ms` + (k.mode !== 0 ? ` · ${fw} forwarding` : '');
    fit();
  };
  tick();
  callTimer = setInterval(tick, 500);
}

// ---- releases: one waiting, and a fork ----
function forkBanner() {
  return h('div', { class: 'banner red', 'data-test': 'release-fork' }, h('b', {}, 'Two releases'),
    'Two different releases were signed as release ' + state.fork + '. Do not update; tell the people who sign p-chat. The evidence is kept.');
}
function releaseBanners() {
  const out = [];
  if (state.fork) out.push(forkBanner());
  if (state.update && !state.fork) out.push(h('div', { class: 'banner', 'data-test': 'update-ready' }, h('b', {}, 'Update ready'),
    'Release ' + state.update.version + ' is checked: every signature and every file. It runs the next time you open p-chat.',
    h('div', { class: 'row' }, h('button', { class: 'btn', 'data-test': 'restart', onclick: () => location.reload() }, 'Open it now'))));
  return out;
}

// ---- live state: tape tennis and the whiteboard ----
let liveCourt = null, liveBoard = null;
function liveKey(id, what) {
  const play = what === 'play';
  const key = h('button', { class: 'tray-key', 'data-test': what, 'aria-label': play ? 'Play table tennis' : 'Whiteboard', title: play ? 'Play' : 'Board',
    onclick: () => {
      try {
        if (play) { session.app.startGame(id); session.pump(); toast('Asked. The game begins when they say yes.'); }
        else show('board', { conv: id });
      } catch (e) { toast(e.message); }
    } });
  key.append(svg(play
    ? '<svg viewBox="0 0 20 20" aria-hidden="true"><rect x="2" y="5" width="2.6" height="10" rx="1" fill="currentColor"/><rect x="15.4" y="5" width="2.6" height="10" rx="1" fill="currentColor"/><circle cx="10" cy="10" r="2" fill="currentColor"/></svg>'
    : '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 15.5l9.6-9.6 2.5 2.5L5.5 18H3z" fill="currentColor"/><path d="M13.6 4.9l1.6-1.6 2.5 2.5-1.6 1.6z" fill="currentColor"/></svg>'),
    h('span', {}, play ? 'Play' : 'Board'));
  return key;
}
function renderGame() {
  const id = state.conv, game = state.game;
  const info = session.info(id);
  const canvas = h('canvas', { class: 'court', width: 800, height: 600, 'data-test': 'court', 'aria-label': 'The court' });
  // Two wide keys under the court, held to move: the paddle goes while one is held.
  const hold = (dir) => {
    const b = h('button', { class: 'pad-key', 'data-test': dir > 0 ? 'up' : 'down', 'aria-label': dir > 0 ? 'Up' : 'Down' },
      h('span', { 'aria-hidden': 'true' }, kbd(dir > 0 ? 'W' : 'S'), kbd(dir > 0 ? '↑' : '↓')),
      svg(dir > 0 ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 15l7-7 7 7" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg>'
        : '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 9l7 7 7-7" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg>'));
    const on = (v) => (e) => { e.preventDefault(); b.classList.toggle('held', v); liveCourt?.press(dir, v); };
    b.addEventListener('pointerdown', (e) => { try { b.setPointerCapture(e.pointerId); } catch { /* no live pointer */ } on(true)(e); });
    for (const ev of ['pointerup', 'pointercancel', 'lostpointercapture']) b.addEventListener(ev, on(false));
    b.addEventListener('contextmenu', (e) => e.preventDefault());
    return b;
  };
  const stop = () => { session.app.leaveGame(game); session.pump(); show('chat', { conv: id }); };
  draw(h('div', { class: 'chathead' },
      h('button', { class: 'back', 'data-test': 'stop-game', 'aria-label': 'Stop and go back', onclick: stop }, '◀'),
      h('div', {}, h('h1', {}, 'Table tennis'), h('div', { class: 'sub' }, 'With ' + info.name)),
      h('button', { class: 'label', onclick: stop }, 'Stop')),
    h('main', { class: 'game' }, canvas, h('p', { class: 'fine' }, 'Hold a key, or drag on the court.'),
      h('p', { class: 'keys-hint fine', 'data-test': 'game-keys' }, 'On the keyboard: hold ', kbd('W'), ' or ', kbd('↑'), ' for up, ', kbd('S'), ' or ', kbd('↓'), ' for down.')),
    h('div', { class: 'composer pads' }, hold(1), hold(-1)));
  liveCourt?.stop();
  liveCourt = new Court(session, game, canvas);
  liveCourt.onover = () => { if (state.screen === 'game') show('chat', { conv: id }); };
}
async function renderBoard() {
  const id = state.conv;
  const info = session.info(id);
  try { session.app.openBoard(id); } catch (e) { toast(e.message); return show('chat', { conv: id }); }
  const strokes = (await store.messages(id)).filter((m) => m.type === 'stroke' && m.body?.length).map((m) => decodeStroke(m.body)).filter(Boolean);
  if (state.screen !== 'board' || state.conv !== id) return;
  const canvas = h('canvas', { class: 'sheet', width: 900, height: 900, 'data-test': 'sheet', 'aria-label': 'The board' });
  const colors = h('div', { class: 'swatches', role: 'radiogroup', 'aria-label': 'Color' });
  const pick = () => colors.replaceChildren(...PALETTE.map((c, i) => {
    const b = h('button', { class: 'swatch', role: 'radio', 'aria-checked': String((liveBoard?.color ?? 0) === i), 'data-test': 'color', 'aria-label': 'Color ' + i,
      onclick: () => { liveBoard.color = i; pick(); } });
    b.style.background = i === 0 ? 'var(--ink)' : c;
    return b;
  }));
  const pan = h('button', { class: 'tool', 'aria-pressed': 'false', 'data-test': 'pan', onclick: () => {
    liveBoard.pan = !liveBoard.pan; pan.setAttribute('aria-pressed', String(liveBoard.pan));
  } }, 'Move');
  const follow = h('button', { class: 'tool wide', 'aria-pressed': 'false', 'data-test': 'follow', onclick: () => {
    const on = follow.getAttribute('aria-pressed') !== 'true';
    liveBoard.follow(on); follow.setAttribute('aria-pressed', String(on));
  } }, 'Follow me');
  // The chat's heading; the sheet large in the court's frame, the colours under
  // it; at the foot, the composer's bar of tools that press in.
  draw(h('div', { class: 'chathead' }, h('button', { class: 'back', 'data-test': 'back', 'aria-label': 'Back', onclick: () => show('chat', { conv: id }) }, '◀'),
      h('div', {}, h('h1', {}, 'Whiteboard'), h('div', { class: 'sub' }, 'With ' + info.name))),
    h('main', { class: 'board' }, canvas, colors),
    h('div', { class: 'composer tools' }, pan, h('button', { class: 'tool', 'data-test': 'zoom-in', 'aria-label': 'Zoom in', onclick: () => liveBoard.zoomBy(1.25) }, '+'),
      h('button', { class: 'tool', 'data-test': 'zoom-out', 'aria-label': 'Zoom out', onclick: () => liveBoard.zoomBy(0.8) }, '−'), follow));
  liveBoard?.stop();
  liveBoard = new Board(session, id, canvas, strokes, (peer) => speaker(peer));
  pick();
}

// An invite for a new device in place of a lost one: what history it gets.
function renderReplace() {
  const { conv: id, lost } = state;
  const scope = h('select', { 'data-test': 'scope' }, h('option', { value: 2 }, 'All the history'), h('option', { value: 1 }, 'The last 30 days'),
    h('option', { value: 0 }, 'No history'));
  draw(head('Replace', { small: true, back: () => show('devices', { conv: id }) }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'A lost device'), h('p', { class: 'caps light' }, shortId(lost))),
    h('div', { class: 'pad' },
      h('p', {}, 'The new device scans an invite and types six words. The others in this chat approve after checking its pictures in person or by voice; the lost device, if it still exists, has a day to object.'),
      h('label', { class: 'field' }, h('span', {}, 'What the new device is given'), scope),
      h('button', { class: 'btn wide', 'data-test': 'make-replace', onclick: async () => {
        try {
          const s = Number(scope.value);
          const made = await session.recoverInvite(id, lost, s, s === 1 ? Date.now() - 30 * 86400e3 : 0);
          state.invite = { ...made, kind: KIND.recovery, conv: id };
          show('invite', { invite: state.invite });
        } catch (e) { toast(e.message); }
      } }, 'Make the invite'))));
}

// ---- linked devices (protocol 11) ----

// A short line for Settings: who this device is linked to, if anyone.
function linkedLine() {
  const n = session.app ? session.app.linked().length : 0;
  return n ? 'Linked to ' + n + (n === 1 ? ' other device' : ' other devices') + ' of yours. Every chat is on each.'
    : 'Not linked. Link your phone and your computer: one you, every chat on both.';
}
// When a linked device was last heard from, in words.
function lastSeen(d) {
  if (d.live) return 'Online now';
  if (!d.heard) return 'Not heard from yet';
  const ago = Date.now() - d.heard;
  if (ago < 60e3) return 'Last heard just now';
  if (ago < 3600e3) return 'Last heard ' + Math.round(ago / 60e3) + ' min ago';
  if (ago < 86400e3) return 'Last heard ' + when(d.heard);
  return 'Last heard ' + day(d.heard);
}

// Two devices just linked: the same four pictures on both.
function renderLinkedPaired(conv, peer) {
  const other = peer || session.info(conv).members.find((m) => !m.self)?.peer;
  const fp = session.app.fingerprintWith(other);
  draw(head('Linked', { small: true, back: () => show('linked', {}) }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Linked'), h('p', { class: 'caps light' }, 'One you, two devices')),
    h('div', { class: 'pad' },
      h('div', { class: 'emoji', 'data-test': 'fingerprint' }, fp.map((e) => h('div', { 'data-glyph': e.glyph }, emojiPic(e), h('span', { class: 'n' }, e.name)))),
      h('p', {}, 'Both devices show these four pictures. If they match, no one stood between them.'),
      h('p', { class: 'fine' }, 'Your chats come over now, with what was said in them. A new chat on one is on the other.'),
      h('button', { class: 'btn wide', 'data-test': 'linked-done', onclick: () => { state.invite = null; show('linked', {}); } }, 'Done'))));
}

// Settings → Linked devices: each with its four pictures, when it was last
// heard from, and a way to unlink.
function renderLinked() {
  if (state.screen !== 'linked') return;
  const devices = session.linkedDevices();
  const split = session.app ? session.app.split() : { state: '' };
  const leaving = session.chats().filter((id) => session.info(id).leaving).length;
  const banners = [];
  if (split.state === 'asking') {
    const name = (id) => session.info(id).name;
    banners.push(h('div', { class: 'banner', 'data-test': 'split-asked' }, h('b', {}, 'Split your chats?'),
      'Your other device asks to split. Each device then leaves the chats that go with the other.',
      h('p', { class: 'split-list' }, h('span', { class: 'caps' }, 'Stay here: '), split.mine.length ? split.mine.map(name).join(', ') : 'none'),
      h('p', { class: 'split-list' }, h('span', { class: 'caps' }, 'Go with the other: '), split.theirs.length ? split.theirs.map(name).join(', ') : 'none'),
      h('div', { class: 'row' },
        h('button', { class: 'btn', 'data-test': 'agree-split', onclick: async () => {
          if (!confirm('Split: this device leaves the chats that go with the other, and the two are no longer linked.')) return;
          try { await session.agreeSplit(); } catch (e) { toast(e.message); }
        } }, 'Agree'),
        h('button', { class: 'btn light', 'data-test': 'refuse-split', onclick: async () => { await session.refuseSplit(); show('linked', {}); } }, 'Not this'))));
  } else if (split.state === 'asked') {
    banners.push(h('div', { class: 'banner', 'data-test': 'split-waiting' }, h('b', {}, 'Split asked'), 'Waiting for your other device to agree.'));
  }
  if (leaving) banners.push(h('div', { class: 'banner', 'data-test': 'leaving' }, h('b', {}, 'Leaving'),
    'Leaving ' + leaving + (leaving === 1 ? ' chat' : ' chats') + '. Each needs its other phones to agree; it finishes when they are online.'));
  const cards = devices.map((d) => h('div', { class: 'device', 'data-test': 'linked-device', 'data-peer': d.peer },
    h('div', { class: 'who' }, 'Your other device'),
    h('div', { class: 'seen' + (d.live ? ' live' : ''), 'data-test': 'last-seen' }, lastSeen(d)),
    h('div', { class: 'id' }, d.peer),
    h('div', { class: 'emoji' }, d.fingerprint.map((e) => h('div', { 'data-glyph': e.glyph }, emojiPic(e), h('span', { class: 'n' }, e.name)))),
    h('button', { class: 'btn warn', 'data-test': 'unlink', disabled: !!split.state, onclick: () => show('unlink', { unlinkFrom: d.peer }) }, 'Unlink')));
  const link = async () => {
    try {
      const made = await session.invite(KIND.link, '');
      state.invite = { ...made, kind: KIND.link, conv: '' };
      show('invite', { invite: state.invite });
    } catch (e) { toast(e.message); }
  };
  draw(head('Linked devices', { small: true, back: () => show('settings') }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'One you, many devices'),
      h('p', { class: 'caps light', 'data-test': 'linked-count' }, devices.length ? 'This device and ' + devices.length + ' more' : 'This device alone')),
    banners,
    devices.length ? cards : h('div', { class: 'pad' }, h('p', { 'data-test': 'not-linked' }, 'This device is not linked to another.'),
      h('p', { class: 'fine' }, 'Linked devices are one person to everyone you talk to: each chat is on all of them, with what was said, and a device left on fills in one that was away.')),
    h('div', { class: 'pad' },
      h('button', { class: devices.length ? 'btn light' : 'btn wide', 'data-test': 'link-device', disabled: !!split.state, onclick: link }, devices.length ? 'Link another device' : 'Link a device'),
      h('p', { class: 'fine' }, 'On the other device, open p-chat and scan the code, then type the six words.'))));
}

// Unlinking, three ways - each said plainly, and confirmed.
function renderUnlink() {
  const other = state.unlinkFrom;
  const go = async (mode, sure) => {
    if (!confirm(sure)) return;
    try { await session.unlink(mode); } catch (e) { toast(e.message); return; }
    show('linked', {});
  };
  draw(head('Unlink', { small: true, back: () => show('linked', {}) }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Unlink this device'), h('p', { class: 'caps light' }, 'From ' + shortId(other || ''))),
    h('button', { class: 'choice amber', 'data-test': 'unlink-keep', onclick: () => go('keep',
      'Keep: this device leaves every chat, and keeps what was said to read. Your other device stays in them.') },
      h('p', { class: 'caps' }, 'Keep a copy'), h('p', { class: 'caps light' }, 'Leave every chat; what was said stays here, read only')),
    h('button', { class: 'choice red', 'data-test': 'unlink-forget', onclick: () => go('forget',
      'Forget: this device leaves every chat, then erases everything on it. Your other device stays in them.') },
      h('p', { class: 'caps' }, 'Forget'), h('p', { class: 'caps light' }, 'Leave every chat, then erase this device')),
    h('button', { class: 'choice violet', 'data-test': 'unlink-split', disabled: session.app.linked().length !== 1, onclick: () => show('split', { splitPick: null }) },
      h('p', { class: 'caps' }, 'Split'), h('p', { class: 'caps light' }, 'Choose which chats stay here and which go with the other')),
    h('div', { class: 'pad' }, h('p', { class: 'fine' }, 'Your contacts see one of your devices leave a chat, as when a device is removed. Keep and Forget work even while your other device is away; a split waits for both to agree.'))));
}

// A split: each chat both devices have, here or with the other.
function renderSplit() {
  const shared = session.chats().filter((id) => { const i = session.info(id); return !i.removed && !i.left && i.kind !== 2 && i.members.some((m) => m.linked); });
  state.splitPick ??= Object.fromEntries(shared.map((id) => [id, 'here']));
  const rows = shared.map((id) => {
    const at = state.splitPick[id] || 'here';
    return h('div', { class: 'split-row', 'data-test': 'split-row', 'data-conv': id },
      h('span', { class: 'name', dir: 'auto' }, session.info(id).name),
      h('div', { class: 'theme', role: 'group', 'aria-label': 'Where it goes' },
        h('button', { class: 'btn light', 'aria-pressed': String(at === 'here'), 'data-test': 'split-here', onclick: () => { state.splitPick[id] = 'here'; renderSplit(); } }, 'Here'),
        h('button', { class: 'btn light', 'aria-pressed': String(at === 'there'), 'data-test': 'split-there', onclick: () => { state.splitPick[id] = 'there'; renderSplit(); } }, 'Other')));
  });
  const ask = async () => {
    const mine = shared.filter((id) => state.splitPick[id] !== 'there'), theirs = shared.filter((id) => state.splitPick[id] === 'there');
    if (!confirm('Ask your other device to split: ' + mine.length + ' stay here, ' + theirs.length + ' go with it. It must agree.')) return;
    try { await session.askSplit(mine, theirs); } catch (e) { toast(e.message); return; }
    show('linked', {});
  };
  draw(head('Split', { small: true, back: () => show('unlink', {}) }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Which chats go where'), h('p', { class: 'caps light' }, 'Both devices must agree')),
    h('div', { class: 'pad' }, shared.length ? rows : h('p', {}, 'No chats are on both devices.'),
      h('button', { class: 'btn wide', 'data-test': 'ask-split', onclick: ask }, 'Ask the other device'))));
}

function renderError(data = state) {
  const texts = {
    invite_failed: ['Stopped', 'The six words did not match', 'Perhaps a word was mistyped - or someone else tried to use the link. This invite is cancelled: make a new one (or ask for one), and say the words again.'],
    invite_used: ['Used', 'This invite was already used', 'An invite works for one phone, once. Ask for a new one.'],
    unrecognized: ['Already used', 'This invite was already used.', 'Perhaps by this phone, before it lost its key. Ask for a new invite.'],
    pair_refused: ['Stopped', 'Pairing was refused', data.detail || ''],
    bad_link: ['Broken', 'This link is not an invite', 'It may have been cut short. Ask for it again.'],
  };
  const [title, line, more] = texts[data.kind] || ['Stopped', data.kind, ''];
  draw(head(title, { small: true }), h('main', {},
    h('div', { class: 'band red' }, h('p', { class: 'caps', 'data-test': 'error' }, line)),
    h('div', { class: 'pad' }, h('p', {}, more),
      h('button', { class: 'btn', onclick: () => show('contacts') }, 'OK'))));
}

// About is drawn at once. What the release is - asked of the service worker,
// which may be slow, or not running at all - is filled in when it is known.
let aboutSeen = null, aboutAsk = null;
function renderAbout() {
  drawAbout(aboutSeen);
  aboutAsk ??= learnRelease().finally(() => { aboutAsk = null; });
  aboutAsk.then((seen) => { aboutSeen = seen; if (state.screen === 'about') drawAbout(seen); });
}
async function learnRelease() {
  let fingerprint = 'not a signed release (development)', version = '-';
  try {
    const m = new Uint8Array(await (await fetch('manifest.json', { cache: 'no-store' })).arrayBuffer());
    const d = new Uint8Array(await crypto.subtle.digest('SHA-256', m));
    fingerprint = hex(d).match(/..../g).slice(0, 8).join(' ');
    version = JSON.parse(new TextDecoder().decode(m)).version;
  } catch { /* not a release */ }
  // The release chain, as the service worker keeps it.
  const s = await session.releaseStatus().catch(() => null);
  if (s?.version) version = s.version;
  return { fingerprint, version, s };
}
function drawAbout(seen) {
  const { fingerprint, version, s } = seen || { fingerprint: '…', version: '…', s: null };
  const open = !!root.querySelector('details.more[open]');
  const warnings = [];
  if (s?.swMatches === false) warnings.push(h('div', { class: 'banner red', 'data-test': 'sw-mismatch' }, h('b', {}, 'Not the signed worker'),
    'The site serves a service worker (sw.js) that is not the one this release names. The site may have been changed: do not update until the people who sign p-chat say why.'));
  if (state.fork) warnings.push(forkBanner());
  const kept = session.persisted ? 'This browser promised to keep them.' : 'Open p-chat now and then, or add it to your Home Screen, so the browser keeps them.';
  // A picture from the shipped Twemoji, so it looks the same on every phone.
  const pic = (code) => h('img', { class: 'g', src: 'emoji/' + code + '.svg', alt: '', width: 26, height: 26, draggable: 'false' });
  // A section: one picture, a title, short sentences one after another.
  const part = (code, title, ...lines) => h('section', { class: 'part', 'data-test': 'about-part' },
    h('h2', {}, pic(code), title), h('p', {}, lines.join(' ')));
  draw(head('About', { small: true, back: () => show('contacts') }), h('main', {},
    warnings,
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Private messages, phone to phone'),
      h('p', { class: 'caps light' }, 'No account · no phone number · nothing to install')),
    h('div', { class: 'pad about' },
      part('1f4ac', 'What it does', 'Chat one to one, in groups or in channels.', 'Send photos, files and voice notes.',
        'Call with voice or video.', 'Play table tennis. Draw together.', 'Make messages disappear.', 'Write in any language.'),
      part('1f512', 'How it stays private', 'Your phone makes its own keys. They never leave it.',
        'Each message is locked before it is sent. Only the phones in the chat can open it.',
        'Every message has a new key.', 'Four matching pictures in Devices mean nobody is in between.'),
      part('1f91d', 'No middleman', 'Phones talk to each other directly.', 'Pair in person by scanning each other\'s codes.',
        'A relay is optional. It only passes on locked messages, and cannot open them.',
        'Any relay works, even your own. Or turn relays off.'),
      part('1f511', 'Good to know', 'Your chats live only on this phone.', kept, 'Lost your phone? Your contacts can approve a new one.',
        'Without a relay, you can send only while your phones are linked.', 'A hacked phone is not protected.'),
      h('div', { class: 'row' },
        h('button', { class: 'btn', 'data-test': 'settings', onclick: () => show('settings') }, 'Settings')),
      h('details', { class: 'more', open }, h('summary', {}, 'Check this version'),
        h('p', { 'data-test': 'release' }, 'Release ' + version + '. Its fingerprint, to compare with the one it was published with:'),
        h('p', { class: 'mono', 'data-test': 'bundle' }, fingerprint),
        seen && !s ? h('p', { class: 'fine', 'data-test': 'no-worker' }, 'p-chat\'s background check is not running in this browser, so new versions are not checked here and notifications cannot work. '
          + 'Is the site\'s certificate trusted (not only "visited anyway")?') : null,
        s?.head ? h('p', { class: 'fine' }, 'Release chain head ', h('span', { class: 'mono', 'data-test': 'chain-head' }, s.head.slice(0, 16)),
          ' - each release signed by the people the one before names.') : null,
        s?.pending ? h('p', { 'data-test': 'pending' }, 'Release ' + s.pending + ' is checked and waits: it runs the next time p-chat is opened.') : null,
        s?.evidence?.length ? h('p', { class: 'fine', 'data-test': 'release-evidence' }, 'Refused: ' + s.evidence.length + ' (the last: ' + s.evidence[s.evidence.length - 1].why + ').') : null,
        h('p', { class: 'fine' }, 'What is protected: what you write and who wrote it, from the relay, the network and anyone holding only the link or only the words. What is not: when and how much you send, a phone that is itself compromised, and the first load of this page.'),
        h('p', { class: 'fine' }, 'The page is checked by a service worker against a signed list of files. But the browser replaces the service worker itself whenever the site serves a new one, and it cannot refuse that: the host that serves this page, its DNS and its TLS remain what you trust, every time it loads.')))));
}

async function renderSettings() {
  const p = await store.profile();
  if (state.screen !== 'settings') return;
  const relay = h('input', { value: p.relay || '', placeholder: session.config.relay || 'wss://relay.example', 'data-test': 'server', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none' });
  const said = h('p', { class: 'fine', 'data-test': 'server-state' });
  const now = theme();
  const looks = h('div', { class: 'theme', role: 'group', 'aria-label': 'Look' }, ['auto', 'light', 'dark'].map((t) =>
    h('button', { class: 'btn light', 'aria-pressed': String(now === t), 'data-test': 'theme-' + t, onclick: () => { theme(t); renderSettings(); } },
      t === 'auto' ? 'Auto' : t === 'light' ? 'Light' : 'Dark')));
  const relayOn = session.relayOn(), helping = session.helping(), relaying = session.relaying();
  const pair = (test, on, set) => h('div', { class: 'theme', role: 'group' },
    h('button', { class: 'btn light', 'aria-pressed': String(on), 'data-test': test + '-on', onclick: async () => { await set(true); renderSettings(); } }, 'On'),
    h('button', { class: 'btn light', 'aria-pressed': String(!on), 'data-test': test + '-off', onclick: async () => { await set(false); renderSettings(); } }, 'Off'));
  draw(head('Settings', { small: true, back: () => show('about') }), h('main', {}, h('div', { class: 'cols' },
    h('div', { class: 'pad' },
      h('p', { class: 'caps' }, 'Linked devices'),
      h('p', { class: 'fine' }, linkedLine()),
      h('button', { class: 'btn light', 'data-test': 'linked-devices', onclick: () => show('linked', {}) }, 'Linked devices'),
      h('p', { class: 'caps' }, 'Look'), looks,
      h('p', { class: 'caps' }, 'Relay'), pair('relay', relayOn, (on) => session.setRelay(on)),
      h('p', { class: 'fine', 'data-test': 'relay-state' }, relayOn
        ? 'On. A relay helps phones find each other, and holds locked messages for a phone that is away. It cannot read them.'
        : 'Off. Phones reach each other directly, or through contacts who carry for others. New contacts pair in person. A message for a phone that is away waits here, or with a contact.'),
      h('p', { class: 'caps' }, 'Carry for contacts'), pair('carry', helping, (on) => session.setHelping(on)),
      h('p', { class: 'fine' }, helping
        ? 'On. While linked, this phone passes locked signals between your contacts and keeps locked messages for them while they are away. It cannot read them - but it does see which of your contacts talk to each other.'
        : 'Off. This phone carries nothing for others. It still takes what is for it.'),
      h('p', { class: 'caps' }, 'This device relays'), pair('relays', relaying, (on) => session.setRelaying(on)),
      h('p', { class: 'fine', 'data-test': 'relays-state' }, relaying
        ? 'On. Leave it open and plugged in - a computer on a desk is best. Your contacts give it their locked messages first, and it keeps them for 14 days, even if it is closed and opened again. It helps your contacts find each other. It cannot read anything.'
        : 'Off. Turn it on for a device you leave open: it then does a relay\'s work for your contacts, with no relay.'),
      h('div', { class: 'row' }, h('button', { class: 'btn light', 'data-test': 'relink', onclick: () => show('relink', { relink: null, relinkCode: null, relinkLink: null, relinkDone: false, relinkFrom: null }) },
        'Link again in person')),
      h('p', { class: 'fine' }, 'Lost every link, with no relay? Scan a code with a contact, or with your device that relays: the rest come back through it.')),
    h('div', { class: 'pad' },
      notifications(p),
      h('details', { class: 'more', 'data-test': 'advanced' }, h('summary', {}, 'Advanced'),
        h('label', { class: 'field' }, h('span', {}, 'Relay for invites you make'), relay),
        h('p', { class: 'fine' }, 'Any relay works: your own, a friend\'s, or the one p-chat came with (leave it empty). Chats you already have keep theirs.'),
        h('button', { class: 'btn light', 'data-test': 'save-server', onclick: async () => {
          const url = relay.value.trim();
          if (url) {
            said.textContent = 'Checking…';
            const why = await reachable(url);
            if (why) { said.textContent = why; return; }
          }
          await store.setProfile({ ...(await store.profile()), relay: url });
          session.profile = await store.profile();
          said.textContent = url ? 'Connected. New invites use it.' : 'New invites use the relay this p-chat came with.';
        } }, 'Use this relay'),
        said,
        h('p', { class: 'fine' }, session.dev ? 'Device ' + hex(session.chat.deviceId(session.dev.signPub, session.dev.agreePub)) : 'No device key yet.'))))));
}

// A server someone typed: answered within a few seconds, or why not (in words).
function reachable(url) {
  if (!/^wss:\/\/[^\s/]+/.test(url) && !/^ws:\/\/(127\.0\.0\.1|localhost)(:\d+)?(\/|$)/.test(url))
    return Promise.resolve('A relay address starts with wss:// - for example wss://relay.example.org');
  return new Promise((done) => {
    let ws;
    const end = (why) => { clearTimeout(timer); try { ws.close(); } catch { /* closed */ } done(why); };
    const timer = setTimeout(() => end('Can\'t reach it. Check the address, or try again later.'), 6000);
    try { ws = new WebSocket(url); } catch { end('That is not a relay address.'); return; }
    ws.onopen = () => end(null);
    ws.onerror = () => end('Can\'t reach it. Check the address, or try again later.');
  });
}

// Putting p-chat on the Home Screen: Safari offers no prompt, so the two
// steps are shown; where the browser has its own (Chrome), its button. Not
// in the installed app, and gone once dismissed. Done first: the Home Screen
// copy keeps its own chats.
let installPrompt = null;
addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); installPrompt = e; if (state.screen === 'contacts') renderContacts(); });
const remembered = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const remember = (k, v) => { try { localStorage.setItem(k, v); } catch { /* not kept */ } };
function installBanner() {
  if (remembered('p-chat:install-dismissed') || !(needsHomeScreen() || installPrompt)) return null;
  const box = h('div', { class: 'banner install', 'data-test': 'install' },
    h('b', {}, 'Put p-chat on your Home Screen'),
    installPrompt
      ? h('p', {}, 'It opens like an app, and can tell you when something comes.')
      : h('p', {}, 'Tap Share ', svg('<svg class="inline" viewBox="0 0 20 20" aria-label="(the square with an arrow)"><path d="M10 2v10M6 6l4-4 4 4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M5 9H4v9h12V9h-1" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>'),
        ' at the bottom of Safari, then Add to Home Screen. Do it before pairing: the Home Screen copy keeps its own chats.'),
    h('div', { class: 'row' },
      installPrompt ? h('button', { class: 'btn', 'data-test': 'install-now', onclick: async () => {
        installPrompt.prompt();
        await installPrompt.userChoice.catch(() => null);
        installPrompt = null;
        renderContacts();
      } }, 'Install') : null,
      h('button', { class: 'btn light', 'data-test': 'install-later', onclick: () => { remember('p-chat:install-dismissed', '1'); box.remove(); } }, 'Not now')));
  return box;
}

// Notifications: on an iPhone in a tab, the way to the Home Screen first.
function notifications(p) {
  if (needsHomeScreen()) return h('div', { class: 'guide', 'data-test': 'home-screen-guide' },
    h('p', { class: 'caps' }, 'Notifications'),
    h('p', {}, 'On iPhone, p-chat can tell you something arrived only once it is on your Home Screen:'),
    h('ol', {},
      h('li', {}, 'Tap Share (the square with the arrow) at the bottom of Safari.'),
      h('li', {}, 'Tap Add to Home Screen, then Add.'),
      h('li', {}, 'Open p-chat from the Home Screen, not from Safari.'),
      h('li', {}, 'Come back here and allow notifications.')),
    h('p', { class: 'fine' }, 'Your chats stay in Safari\'s copy; the Home Screen one starts fresh and pairs again.'));
  const can = 'PushManager' in globalThis && 'serviceWorker' in navigator;
  return h('div', {},
    h('p', { class: 'caps' }, 'Notifications'),
    h('p', { class: 'fine', 'data-test': 'push-state' }, p.pushInfo ? 'On. A notification shows the symbol you chose for a chat (Devices), never who or what.'
      : can ? 'Off. When on, a message that cannot reach you at once wakes this phone: it shows only the symbol you chose for that chat.'
        : 'This browser cannot show notifications.'),
    can && !p.pushInfo ? h('button', { class: 'btn light', 'data-test': 'enable-push', onclick: async () => {
      try { await session.enablePush(); toast('On.'); renderSettings(); } catch (e) { toast(e.message); }
    } }, 'Allow notifications') : null);
}

// ---- start ----
async function start() {
  const chat = await globalThis.createChat();
  session.chat = chat;
  globalThis.pchat = { session, ui, state, store }; // for tests and for looking
  if ('serviceWorker' in navigator && isSecureContext) navigator.serviceWorker.register('sw.js').catch(() => {});
  const booted = await session.boot();
  if (!booted || state.screen === 'unsupported' || state.screen === 'unrecognized') return;
  if (meeting) return show('meet', { meet: meeting, meetCode: null, meetAsked: false });
  if (relinking) return show('relink', { relink: relinking, relinkCode: null, relinkDone: false, relinkFrom: null });
  if (invite) return show('pair');
  const a = await store.asking();
  if (a) { state.pairing = 'asked'; invite = invite || null; }
  show('contacts');
}
// A code or link opened while p-chat is already open (the address changes
// only after its '#'): taken as at start.
addEventListener('hashchange', () => {
  const h = location.hash.slice(1);
  if (!h.startsWith('d1.') && !h.startsWith('v1.') && !h.startsWith('l1.')) return;
  history.replaceState(null, '', location.pathname + location.search);
  if (!session.chat) return;
  state.pairing = null;
  if (h.startsWith('d1.')) show('meet', { meet: h, meetCode: null, meetAsked: false });
  else if (h.startsWith('l1.')) show('relink', { relink: h, relinkCode: null, relinkDone: false, relinkFrom: null });
  else { invite = h; show('pair'); }
});
start().catch((e) => { draw(h('main', {}, h('div', { class: 'pad' }, h('p', { class: 'caps' }, 'p-chat could not start'), h('p', {}, e.message)))); });
