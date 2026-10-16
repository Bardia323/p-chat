// What the person sees: one screen at a time, drawn from what the world and
// the store say. The UI observes and fires: it reads a conversation's state
// (const, through the App) and the kept messages, and it sends to ports
// (post, read) and fires events (open, close). Every text a person or a
// peer wrote is set as text, never as markup.
import { needsHomeScreen } from './push.js';
import { Session } from './session.js';
import * as store from './store.js';
import { hex } from './crypto.js';
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
const KIND = { contact: 1, extra: 2, reusable: 3, channel: 4, recovery: 5 };

// The link's fragment is read once and taken out of the address bar.
let invite = null, meeting = null;
if (location.hash.startsWith('#d1.')) {
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
const DEPTH = { meet: 1, contacts: 0, unsupported: 0, unrecognized: 0, pair: 1, chat: 1, invite: 1, about: 1, error: 1, newgroup: 1,
  paired: 2, devices: 2, settings: 2, replace: 3, call: 2, game: 2, board: 2 };
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
    if (state.screen === 'chat' && (!conv || conv === state.conv)) await renderChat(false);
    else if (state.screen === 'contacts') await renderContacts();
    else if (state.screen === 'devices' && conv === state.conv) renderDevices();
    else if (state.screen === 'invite' && state.invite?.kind !== KIND.contact && conv) renderInviteStatus();
    else if (state.screen === 'pair' && session.conversations().length) {
      const c = session.conversations()[0];
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
    this.changed(conv);
  },
  paired(conv, n) {
    if (state.screen === 'invite' || state.screen === 'pair' || state.screen === 'meet') show('paired', { conv, peer: n.peer, name: n.type });
    else toast('Paired with ' + (n.type || 'a new device'));
  },
  pairing(status) {
    state.pairing = status;
    if (status === 'used') show('error', { kind: session.conversations().length ? 'invite_used' : 'unrecognized' });
    else if (state.screen === 'pair') renderPair();
    else if (state.screen === 'meet') renderMeet();
  },
  warn(t) { toast(t); },
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

function show(name, data = {}) {
  if (state.screen === 'chat' && name !== 'chat' && state.conv) session.leave(state.conv);
  if (state.screen === 'game' && name !== 'game') { liveCourt?.stop(); liveCourt = null; }
  if (state.screen === 'board' && name !== 'board') { liveBoard?.stop(); liveBoard = null; try { session.app.closeBoard(state.conv); } catch { /* gone */ } }
  const from = DEPTH[state.screen] ?? 0, to = DEPTH[name] ?? 1;
  if (name !== state.screen || data.conv !== undefined) entering = to >= from ? 'from-right' : 'from-left';
  Object.assign(state, { screen: name, ...data });
  const screens = { unsupported, unrecognized, pair: renderPair, contacts: renderContacts, chat: () => renderChat(true),
    invite: renderInvite, meet: renderMeet, devices: renderDevices, paired: renderPaired, about: renderAbout, error: renderError, settings: renderSettings,
    newgroup: renderNewGroup, replace: renderReplace, call: renderCall, game: renderGame, board: renderBoard };
  (screens[name] || renderContacts)();
}

// ---- the screens ----

function unsupported() {
  draw(head('Too old'), h('main', {}, h('div', { class: 'band yellow' }, h('p', { class: 'caps', 'data-test': 'unsupported' }, 'Please update your browser')),
    h('div', { class: 'pad' }, h('p', {}, 'This browser cannot keep keys that cannot be copied out of it (Ed25519 and X25519 in WebCrypto). p-chat uses no other kind of key, so it stops here.'))));
}

function unrecognized(data = state) {
  const who = data.owner || 'the person who invited you';
  draw(head('Not known', { small: true }), h('main', {},
    h('div', { class: 'band red' }, h('p', { class: 'caps', 'data-test': 'unrecognized' }, 'Device not recognized. Ask ' + who + ' for a new key.')),
    h('div', { class: 'pad' }, h('p', {}, 'This browser no longer has the key it was paired with: its storage was cleared (Safari clears a site not opened for about a week). A key cannot be made again. Open a new invite from ' + who + '.'))));
}

async function saveName(n) {
  const p = await store.profile();
  await store.setProfile({ ...p, name: clip(n) || p.name || 'Me' });
  session.profile = await store.profile();
  session.app?.rename(session.profile.name);
}

function renderPair() {
  const parsed = (() => { try { return session.chat.parseInvite(invite); } catch { return null; } })();
  if (!parsed) return show('error', { kind: 'bad_link' });
  const name = h('input', { autocomplete: 'nickname', dir: 'auto', placeholder: 'What they will see you as', 'data-test': 'name' });
  const call = h('input', { autocomplete: 'off', dir: 'auto', placeholder: 'Only you see this name', 'data-test': 'call' });
  const mail = h('input', { type: 'checkbox', 'data-test': 'mail' });
  const words = h('textarea', { autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', placeholder: 'six words', 'data-test': 'code' });
  const recovering = parsed.kind === KIND.recovery;
  const status = h('p', { class: 'fine', 'data-test': 'pair-status' },
    state.pairing === 'asked' && recovering ? 'Asked. The others approve; the lost device has a day to object. Show them these four pictures:' :
    state.pairing === 'asked' ? 'Asked. Waiting for the other phone to answer…' :
    state.pairing === 'offline' ? 'Can\'t connect. Trying again…' :
    state.pairing === 'working' ? 'Checking the words…' : '');
  const go = h('button', { class: 'btn wide', 'data-test': 'pair', disabled: state.pairing === 'working' || state.pairing === 'asked' }, 'Pair this phone');
  go.onclick = async () => {
    let code;
    try { code = session.chat.normalizeCode(words.value); } catch { toast('That is not six words from the list. Check each word.'); return; }
    state.pairing = 'working';
    renderPair();
    await new Promise((r) => setTimeout(r, 30));
    try { await session.pair(invite, code, clip(name.value) || 'Friend', clip(call.value), mail.checked); }
    catch (e) { state.pairing = null; toast(e.message); renderPair(); }
  };
  const mine = recovering && state.pairing === 'asked' && session.app ? session.app.fingerprintOf(session.app.peer()) : null;
  draw(head('Pair', { small: true }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, recovering ? 'In place of a lost device' : 'You were invited'),
      h('p', { class: 'caps light' }, 'By device ' + shortId(parsed.owner))),
    h('div', { class: 'pad' },
      h('p', {}, 'Type the six words you were told separately. Nothing you type leaves this phone: the words only prove this link was meant for you.'),
      h('label', { class: 'field' }, h('span', {}, 'Your name'), name),
      h('label', { class: 'field' }, h('span', {}, 'What do you call them?'), call),
      h('label', { class: 'field' }, h('span', {}, 'The six words'), words),
      h('label', { class: 'check' }, mail, h('span', {}, 'When this phone is away, let messages wait on the relay, locked so only this phone can read them (up to 14 days). Otherwise they wait on the sender\'s phone until you are both online.')),
      go, status,
      mine ? h('div', { class: 'emoji', 'data-test': 'own-fingerprint' }, mine.map((e) => h('div', { 'data-glyph': e.glyph }, emojiPic(e), h('span', { class: 'n' }, e.name)))) : null)));
}

async function renderContacts() {
  const ids = session.conversations();
  const rows = [];
  for (const id of ids) {
    const info = session.info(id);
    const ms = (await store.messages(id)).filter((m) => !m.hidden);
    const last = ms[ms.length - 1];
    rows.push(h('li', {}, h('button', { class: 'spine', 'data-test': 'contact', 'data-conv': id, onclick: () => show('chat', { conv: id }) },
      h('span', { class: 'tag' }),
      h('span', {}, h('span', { class: 'name', dir: 'auto' }, info.name,
        info.kind === 1 ? h('span', { class: 'badge' }, 'group') : info.kind === 2 ? h('span', { class: 'badge' }, 'channel') : null), h('span', { class: 'last' },
        info.removed ? 'This device was removed' : last ? (last.mine ? 'You: ' : '') + preview(last) : 'No messages yet')),
      info.unread ? h('span', { class: 'count' + (info.unread > (lastUnread.get(id) || 0) ? ' bump' : ''), 'data-test': 'unread' }, String(info.unread)) : h('span', {}))));
    lastUnread.set(id, info.unread);
  }
  const p = await store.profile();
  if (state.screen !== 'contacts') return;
  const contacts = ids.some((id) => session.info(id).kind === 0 && !session.info(id).removed);
  draw(head('Chats'), h('main', {}, releaseBanners(),
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, p.name ? 'This phone: ' + p.name : 'This phone'),
      h('p', { class: 'caps light' }, ids.length ? ids.length + (ids.length === 1 ? ' conversation' : ' conversations') : 'Private messages, phone to phone')),
    h('div', { class: 'lines' }),
    ids.length ? h('ul', { class: 'shelf' }, rows) : h('div', { class: 'empty', 'data-test': 'no-chats' },
      h('p', { class: 'caps' }, 'No chats yet'),
      h('p', {}, 'Invite someone: they scan your code, or open your link.'),
      h('button', { class: 'btn wide', 'data-test': 'start-invite', onclick: () => show('invite', { invite: null }) }, 'Invite someone'),
      h('button', { class: 'btn light wide', 'data-test': 'scan-code', onclick: () => scanned() }, 'Scan their code'),
      h('p', { class: 'fine' }, 'Were you sent a link? Open it on this phone.'))),
  foot(h('div', { class: 'row' },
      h('button', { class: 'btn light', 'data-test': 'invite', onclick: () => show('invite', { invite: null }) }, 'Invite'),
      h('button', { class: 'btn light', 'data-test': 'new-group', disabled: !contacts, onclick: () => show('newgroup', { channel: false }) }, 'Group'),
      h('button', { class: 'btn light', 'data-test': 'new-channel', disabled: !contacts, onclick: () => show('newgroup', { channel: true }) }, 'Channel')),
    h('button', { class: 'label cream', onclick: () => show('about') }, 'About')));
}

let drawnChat = null;
async function renderChat(first) {
  const id = state.conv;
  if (!session.conversations().includes(id)) return show('contacts');
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
  if (info.removed) banners.push(h('div', { class: 'banner red', 'data-test': 'removed' }, h('b', {}, 'Removed'), 'This device was removed. Ask ' + info.name + ' for a new key.'));
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
  const input = h('textarea', { rows: 1, placeholder: info.removed ? 'Removed' : 'Message', disabled: info.removed, 'data-test': 'message', dir: 'auto', maxlength: 20000, 'aria-label': 'Message' });
  const key = h('button', { class: 'key', 'data-test': 'send', 'aria-label': 'Send', title: 'Send', disabled: info.removed });
  key.append(svg('<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 2.5v15L17.5 10z" fill="currentColor" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>'));
  const grow = () => { input.style.height = 'auto'; input.style.height = Math.min(input.scrollHeight + 4, 140) + 'px'; };
  input.addEventListener('input', grow);
  const send = async () => {
    const t = input.value.trim();
    if (!t) return;
    input.value = '';
    grow();
    key.classList.remove('fire');
    void key.offsetWidth;
    key.classList.add('pressed', 'fire');
    setTimeout(() => key.classList.remove('pressed'), 120);
    await session.send(id, t);
    await renderChat(false);
    root.querySelector('[data-test=message]')?.focus();
  };
  key.onclick = send;
  const pick = (accept, kind) => {
    const f = h('input', { type: 'file', accept, class: 'hidden', 'data-test': 'file-' + kind });
    f.onchange = async () => {
      tray.classList.add('hidden');
      for (const file of f.files) {
        try { await session.sendFile(id, file); } catch (e) { toast(e.message); }
      }
      await renderChat(false);
    };
    return f;
  };
  const photos = pick('image/*,video/*', 'media'), files = pick('', 'any');
  const stickers = h('div', { class: 'stickers hidden', 'data-test': 'sticker-picker' });
  session.media.stickers().then((pack) => stickers.append(...pack.stickers.map((s) =>
    h('button', { class: 'sticker-key', 'data-test': 'sticker-' + s.file, onclick: async () => {
      stickers.classList.add('hidden'); tray.classList.add('hidden');
      await session.media.sticker(id, s);
      await renderChat(false);
    } }, h('img', { src: 'stickers/' + s.file, alt: s.file.replace('.svg', '') })))));
  let rec = null;
  const mic = h('button', { class: 'tray-key', 'data-test': 'voice', onclick: async () => {
    if (!rec) {
      try { rec = await recorder(); mic.classList.add('recording'); mic.lastChild.textContent = 'Stop'; } catch (e) { toast('No microphone: ' + e.message); }
      return;
    }
    const r = rec;
    rec = null;
    mic.classList.remove('recording');
    const v = await r.stop();
    tray.classList.add('hidden');
    await session.sendPrepared(id, { kind: FILE.voice, blob: v.blob, mime: v.mime, name: 'voice', duration: v.duration, width: 0, height: 0, thumbnail: new Uint8Array(0) });
    await renderChat(false);
  } }, svg('<svg viewBox="0 0 20 20" aria-hidden="true"><rect x="7" y="2" width="6" height="11" rx="3" fill="currentColor"/><path d="M4 9a6 6 0 0 0 12 0M10 15v3" stroke="currentColor" stroke-width="2" fill="none"/></svg>'), h('span', {}, 'Voice'));
  const tray = h('div', { class: 'tray hidden', 'data-test': 'tray' },
    h('button', { class: 'tray-key', 'data-test': 'pick-media', onclick: () => photos.click() }, svg('<svg viewBox="0 0 20 20" aria-hidden="true"><rect x="2" y="4" width="16" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="7" cy="9" r="1.6" fill="currentColor"/><path d="M3 15l5-5 4 4 2-2 3 3" fill="none" stroke="currentColor" stroke-width="2"/></svg>'), h('span', {}, 'Photo')),
    h('button', { class: 'tray-key', 'data-test': 'pick-file', onclick: () => files.click() }, svg('<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 2h7l4 4v12H5z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M12 2v4h4" fill="none" stroke="currentColor" stroke-width="2"/></svg>'), h('span', {}, 'File')),
    h('button', { class: 'tray-key', 'data-test': 'pick-sticker', onclick: () => stickers.classList.toggle('hidden') }, svg('<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="7" cy="8" r="1.3" fill="currentColor"/><circle cx="13" cy="8" r="1.3" fill="currentColor"/><path d="M6 12a4.5 4.5 0 0 0 8 0" fill="none" stroke="currentColor" stroke-width="2"/></svg>'), h('span', {}, 'Sticker')),
    info.kind !== 2 ? liveKey(id, 'board') : null,
    info.kind === 0 ? liveKey(id, 'play') : null,
    mic, photos, files);
  const attach = h('button', { class: 'key attach', 'data-test': 'attach', 'aria-label': 'Attach', title: 'Attach', disabled: info.removed,
    onclick: () => { tray.classList.toggle('hidden'); attach.classList.toggle('open'); } });
  attach.append(svg('<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 3v14M3 10h14" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/></svg>'));
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } });
  // Drawn again over itself (a message came): what was typed, and an open
  // tray, stay. Not carried into another chat.
  const same = drawnChat === id && !!root.querySelector('[data-test=message]');
  const focused = same && document.activeElement?.dataset?.test === 'message';
  const draft = same ? root.querySelector('[data-test=message]').value : '';
  const trayOpen = same && !!root.querySelector('[data-test=tray]:not(.hidden)');
  // Another screen came while this one was being made: it is not drawn over it.
  if (state.screen !== 'chat' || state.conv !== id) return;
  draw(h('div', { class: 'chathead' },
      h('button', { class: 'back', 'data-test': 'back', 'aria-label': 'Back', onclick: () => show('contacts') }, '◀'),
      h('div', {}, h('h1', { 'data-test': 'chat-name', dir: 'auto' }, info.name), h('div', { class: 'sub' },
        info.kind === 2 ? (info.member ? 'Your channel' : 'Channel · read only')
          : info.kind === 1 ? info.members.length + ' devices · group' : info.members.length - 1 + (info.members.length === 2 ? ' device' : ' devices') + ' · sealed')),
      info.member && info.kind !== 2 && Calls.supported() && !info.removed ? callKey(id) : null,
      info.member && info.kind === 1 && Calls.supported() && !info.removed ? callKey(id, true) : null,
      h('button', { class: 'label', 'data-test': 'devices', onclick: () => show('devices') }, 'Devices')),
    h('main', {}, banners, tape),
    info.kind === 2 && !info.member
      ? h('div', { class: 'composer reader', 'data-test': 'read-only' }, h('p', { class: 'caps light' }, 'Only ' + (info.introduced || 'its publisher') + ' posts here'))
      : h('div', { class: 'composer' }, stickers, tray, attach, input, key));
  drawnChat = id;
  input.value = draft;
  grow();
  if (focused) input.focus();
  if (trayOpen) { tray.classList.remove('hidden'); attach.classList.add('open'); }
  seenMsgs.add(id);
  void firstLook;
  tape.scrollTop = tape.scrollHeight;
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
  const contacts = session.conversations().filter((id) => session.info(id).side === 0);
  const pick = h('select', { 'data-test': 'for' }, contacts.map((id) => h('option', { value: id }, session.info(id).name)));
  const p = await store.profile();
  if (state.screen !== 'invite') return;
  const name = h('input', { value: p.name || '', autocomplete: 'nickname', dir: 'auto', maxlength: 64, placeholder: 'What they will see you as', 'data-test': 'name' });
  const named = async () => {
    if (!clip(name.value)) { toast('Write your name first: it is what they will see.'); name.focus(); return false; }
    await saveName(name.value);
    return true;
  };
  const meet = async () => {
    if (!(await named())) return;
    try {
      const made = await session.inPerson(session.profile.name);
      state.invite = { inPerson: true, link: made.link, token: made.token, kind: KIND.contact, relayed: made.relayed };
      renderInviteShown();
    } catch (e) { toast(e.message); }
  };
  const linked = session.relayOn();
  const make = async (kind) => {
    try {
      if (!clip(name.value)) { toast('Write your name first: it is what they will see.'); name.focus(); return; }
      await saveName(name.value);
      const conv = kind === KIND.contact ? '' : pick.value;
      if (kind !== KIND.contact && !conv) { toast('Pick whose device it is.'); return; }
      const made = await session.invite(kind, conv, session.profile.name);
      state.invite = { ...made, kind, conv };
      renderInviteShown();
    } catch (e) { toast(e.message); }
  };
  draw(head('Invite', { back: () => show('contacts') }), h('main', {},
    h('div', { class: 'pad' }, h('label', { class: 'field' }, h('span', {}, 'Your name'), name)),
    h('button', { class: 'choice yellow', 'data-test': 'kind-code', onclick: meet },
      h('p', { class: 'caps' }, 'A new contact'), h('p', { class: 'caps light' }, 'They scan your code, or open your link')),
    h('button', { class: 'choice amber', 'data-test': 'kind-contact', onclick: () => make(KIND.contact), disabled: !linked },
      h('p', { class: 'caps' }, 'A new contact, with six words'), h('p', { class: 'caps light' }, 'Safer from afar: the link alone is not enough')),
    h('button', { class: 'choice orange', 'data-test': 'kind-extra', onclick: () => make(KIND.extra), disabled: !contacts.length || !linked },
      h('p', { class: 'caps' }, 'Another device of…'), h('p', { class: 'caps light' }, 'One more phone or computer for a contact')),
    h('button', { class: 'choice red', 'data-test': 'kind-reusable', onclick: () => make(KIND.reusable), disabled: !contacts.length || !linked },
      h('p', { class: 'caps' }, 'Reusable device key for…'), h('p', { class: 'caps light' }, 'Works until you cancel it')),
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
  draw(head('Invite', { small: true, back: () => { state.invite = null; show('contacts'); } }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, inv.kind === KIND.contact ? 'Scan with their phone camera' : 'Scan with the new device')),
    h('div', { class: 'pad' }, img,
      h('div', { class: 'row' }, h('button', { class: 'btn light', onclick: async () => { await navigator.clipboard?.writeText(inv.link); toast('Link copied. Send it; say the words separately.'); } }, 'Copy link'))),
    h('div', { class: 'band amber' }, h('p', { class: 'caps' }, 'Then say these six words'), h('p', { class: 'caps light' }, 'Out loud or another way. Never with the link.')),
    h('div', { class: 'pad' }, h('ol', { class: 'words', 'data-test': 'words' }, words.map((w) => h('li', {}, w))),
      h('p', { class: 'fine', 'data-test': 'invite-status' }, inv.kind === KIND.contact ? 'Waiting for them to pair…'
        : inv.kind === KIND.recovery ? 'Waiting… the others approve, and the lost device has a day to object.' : 'Waiting… their other device must approve.'),
      h('button', { class: 'btn light', onclick: async () => { await session.cancelInvite(inv.token); state.invite = null; show('contacts'); } }, 'Cancel invite'))));
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
      channel ? null : h('div', {}, h('p', { class: 'caps' }, 'Who is in it'), picks.length ? picks : h('p', { class: 'fine' }, 'Pair with someone first.')),
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
  const scan = () => scanQR('Scan the code on their phone', async (text) => {
    try {
      await session.theirCode(text);
      inv.joining = true;
      status.textContent = 'Joining the two phones…';
    } catch (e) { toast(e.message); }
  });
  draw(head('Invite', { small: true, back: () => { session.endPairing(); state.invite = null; show('contacts'); } }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Let them scan this'), h('p', { class: 'caps light' }, 'Or send them the link')),
    h('div', { class: 'pad' }, img,
      h('div', { class: 'row' }, h('button', { class: 'btn light', 'data-test': 'copy-link', onclick: async () => {
        await navigator.clipboard?.writeText(inv.link).catch(() => {});
        toast('Link copied. Anyone with it can pair, once: send it only to them.');
      } }, 'Copy link')),
      status,
      h('p', { class: 'fine' }, relayed ? 'Their phone answers through the relay. If it shows a code instead, scan it:'
        : 'No relay: when their phone shows a code, scan it.'),
      h('button', { class: relayed ? 'btn light' : 'btn wide', 'data-test': 'scan-answer', onclick: scan }, 'Scan their code'))));
}

// The phone shown a code in person: its names, then a code of its own back.
function renderMeet() {
  let d;
  try { d = session.inPersonInvite(state.meet); } catch { return show('error', { kind: 'bad_link' }); }
  if (state.meetAsked && !state.meetCode) {
    draw(head('Pair', { small: true }), h('main', {},
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
    draw(head('In person', { small: true }), h('main', {},
      h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'Show them this code'), h('p', { class: 'caps light' }, 'Their phone scans it')),
      h('div', { class: 'pad' }, h('img', { class: 'qr', alt: 'Your answer as a code', src: qr.createDataURL(8, 0), 'data-test': 'answer-qr', 'data-code': state.meetCode }),
        h('p', { class: 'fine', 'data-test': 'pair-status' }, status))));
    return;
  }
  const name = h('input', { autocomplete: 'nickname', dir: 'auto', placeholder: 'What they will see you as', 'data-test': 'name' });
  const call = h('input', { autocomplete: 'off', dir: 'auto', placeholder: 'Only you see this name', 'data-test': 'call' });
  const mail = h('input', { type: 'checkbox', 'data-test': 'mail' });
  store.profile().then((p) => { if (!name.value) name.value = p.name || ''; });
  const relayed = !!d.parsed.relay && session.relayOn();
  const go = h('button', { class: 'btn wide', 'data-test': 'show-answer', onclick: async () => {
    if (!clip(name.value)) { toast('Write your name first: it is what they will see.'); name.focus(); return; }
    go.disabled = true;
    try {
      if (relayed) {
        // The code names a relay: the request goes back through it, and that is all.
        state.meetAsked = true;
        await session.pair(d.fragment, d.code, clip(name.value), clip(call.value), mail.checked);
        renderMeet();
      } else {
        state.meetCode = await session.answerInPerson(d, clip(name.value), clip(call.value), mail.checked);
        renderMeet();
      }
    } catch (e) { go.disabled = false; state.meetAsked = false; toast(e.message); }
  } }, relayed ? 'Pair' : 'Show my code');
  draw(head('In person', { small: true, back: () => show('contacts') }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'You were invited'), h('p', { class: 'caps light' }, 'By device ' + shortId(d.parsed.owner))),
    h('div', { class: 'pad' },
      h('label', { class: 'field' }, h('span', {}, 'Your name'), name),
      h('label', { class: 'field' }, h('span', {}, 'What do you call them?'), call),
      h('label', { class: 'check' }, mail, h('span', {}, 'When this phone is away, let messages wait for it, locked so only it can read them: at a relay, or with contacts who carry for others.')),
      go)));
}

// A code read by the camera: shown in person (d1), or an invite link (v1).
async function scanned() {
  scanQR('Scan the code on their phone', (text) => {
    const at = text.indexOf('#');
    const frag = at >= 0 ? text.slice(at + 1) : '';
    if (frag.startsWith('d1.')) return show('meet', { meet: frag, meetCode: null, meetAsked: false });
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
  const other = peer || info.members.find((m) => !m.self)?.peer;
  const fp = session.app.fingerprintWith(other);
  draw(head('Paired', { small: true }), h('main', {},
    h('div', { class: 'band yellow' }, h('p', { class: 'caps' }, 'With ' + info.name)),
    h('div', { class: 'pad' },
      h('div', { class: 'emoji', 'data-test': 'fingerprint' }, fp.map((e) => h('div', { 'data-glyph': e.glyph }, emojiPic(e), h('span', { class: 'n' }, e.name)))),
      h('p', {}, 'Both phones show these four pictures. If you want to be sure no one stood between you, compare them by voice.'),
      h('button', { class: 'btn wide', 'data-test': 'open-chat', onclick: () => { state.invite = null; show('chat', { conv }); } }, 'Start talking'))));
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
      h('div', { class: 'who' }, m.self ? 'This device' : m.side === 0 ? (owner ? 'Your device' : info.name + '\'s device') : (owner ? info.name + '\'s device' : 'Your other device')),
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
    h('div', { class: 'pad' }, h('label', { class: 'field' }, h('span', {}, 'What you call them (only you see this)'), rename),
      h('button', { class: 'btn light', 'data-test': 'rename-save', onclick: async () => {
        const n = clip(rename.value);
        if (!n) return;
        await session.rename(id, clip(n));
        renderDevices();
      } }, 'Rename')),
    delivery,
    info.kind !== 2 ? options : null,
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
      } }, 'Forget contact'))));
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
      try { await session.calls.start(id, live); show('call', { conv: id }); } catch (e) { toast(e.message); }
    } });
  key.append(svg(live
    ? '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="2.6" fill="currentColor"/><path d="M5.8 5.8a6 6 0 0 0 0 8.4M14.2 5.8a6 6 0 0 1 0 8.4M3.2 3.2a9.6 9.6 0 0 0 0 13.6M16.8 3.2a9.6 9.6 0 0 1 0 13.6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>'
    : '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5.5 2.5l3 3.2-1.6 2a10 10 0 0 0 5.4 5.4l2-1.6 3.2 3-1.6 2.6c-.4.6-1.1.9-1.8.7A15.5 15.5 0 0 1 2.2 6.9c-.2-.7.1-1.4.7-1.8z" fill="currentColor"/></svg>'));
  return key;
}
let callTimer = null;
function renderCall() {
  const id = state.conv;
  const k = session.calls.info();
  if (!k) return show('chat', { conv: id });
  const info = session.info(id);
  const tiles = h('div', { class: 'tiles', 'data-test': 'tiles' });
  const me = session.calls.stream ? h('video', { class: 'me', muted: true, autoplay: true, playsinline: true, 'aria-label': 'You' }) : null;
  if (me) { me.muted = true; me.srcObject = session.calls.stream; }
  const fill = () => {
    // Through a tree: a tile tapped is that speaker's full picture.
    tiles.replaceChildren(...[...session.calls.remote.entries()].map(([peer, r]) =>
      h('figure', { class: 'tile' + (session.calls.picked === peer ? ' picked' : ''), 'data-test': 'tile', 'data-peer': peer,
        onclick: () => k.mode === 2 && session.calls.pick(peer) }, r.canvas, h('figcaption', { dir: 'auto' }, speaker(peer)))));
    if (!session.calls.remote.size) tiles.append(h('p', { class: 'caps light waiting' },
      k.mode === 1 && k.starter === session.app.peer() ? 'On air. Viewers join from the chat.' : 'Ringing…'));
  };
  session.calls.onchange = fill;
  fill();
  const stats = h('p', { class: 'mono stats', 'data-test': 'call-stats' });
  const mute = h('button', { class: 'deck', 'aria-pressed': String(session.calls.muted), 'data-test': 'mute', onclick: () => {
    session.calls.muted = !session.calls.muted; mute.setAttribute('aria-pressed', String(session.calls.muted));
  } }, 'Mute');
  const cam = h('button', { class: 'deck', 'aria-pressed': String(!session.calls.camera), 'data-test': 'camera', onclick: () => {
    session.calls.camera = !session.calls.camera; cam.setAttribute('aria-pressed', String(!session.calls.camera));
  } }, 'Camera off');
  const hang = h('button', { class: 'hang', 'data-test': 'hang', 'aria-label': 'Hang up', onclick: async () => {
    await session.calls.hang(); show('chat', { conv: id });
  } });
  hang.append(svg('<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M2 11.5c4.5-4 11.5-4 16 0l-1.6 2.6-3.2-1.2v-2.2a8 8 0 0 0-6.4 0v2.2l-3.2 1.2z" fill="currentColor"/></svg>'));
  const live = k.mode === 1;
  draw(h('div', { class: 'callhead' }, h('h1', { dir: 'auto' }, info.name),
    h('div', { class: 'sub' }, (live ? (k.starter === session.app.peer() ? 'You are live' : 'Watching') + ' · ' : '') + 'Sealed · each frame checked before it plays')),
    h('main', { class: 'call' }, tiles, me, stats),
    h('div', { class: 'decks' }, session.calls.stream ? mute : null, session.calls.stream ? cam : null, hang));
  clearInterval(callTimer);
  const tick = () => {
    if (state.screen !== 'call') return clearInterval(callTimer);
    const s = session.calls.stats();
    const fw = session.calls.info()?.forwarders?.filter(Boolean).length || 0;
    stats.textContent = `${s.in} in the call · ${s.played} played · ${s.refused} refused · latency ${s.p50} ms (p95 ${s.p95})` +
      (k.mode !== 0 ? ` · ${fw} forwarding` : '');
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
  const hold = (dir) => {
    const b = h('button', { class: 'deck', 'data-test': dir > 0 ? 'up' : 'down', 'aria-label': dir > 0 ? 'Up' : 'Down' }, dir > 0 ? '▲' : '▼');
    for (const [ev, on] of [['pointerdown', true], ['pointerup', false], ['pointerleave', false]]) b.addEventListener(ev, () => liveCourt?.press(dir, on));
    return b;
  };
  draw(h('div', { class: 'callhead' }, h('h1', { dir: 'auto' }, 'Table tennis'), h('div', { class: 'sub' }, 'With ' + info.name + ' · W/S or ↑/↓ · the same court on both phones')),
    h('main', { class: 'call game' }, canvas),
    h('div', { class: 'decks' }, hold(1), hold(-1), h('button', { class: 'hang', 'data-test': 'stop-game', 'aria-label': 'Stop', onclick: () => {
      session.app.leaveGame(game); session.pump(); show('chat', { conv: id });
    } }, '■')));
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
  const pan = h('button', { class: 'deck', 'aria-pressed': 'false', 'data-test': 'pan', onclick: () => {
    liveBoard.pan = !liveBoard.pan; pan.setAttribute('aria-pressed', String(liveBoard.pan));
  } }, 'Move');
  const follow = h('button', { class: 'deck', 'aria-pressed': 'false', 'data-test': 'follow', onclick: () => {
    const on = follow.getAttribute('aria-pressed') !== 'true';
    liveBoard.follow(on); follow.setAttribute('aria-pressed', String(on));
  } }, 'Follow me');
  draw(h('div', { class: 'callhead' }, h('button', { class: 'back', 'data-test': 'back', 'aria-label': 'Back', onclick: () => show('chat', { conv: id }) }, '◀'),
    h('h1', { dir: 'auto' }, 'Board'), h('div', { class: 'sub' }, info.name + ' · every stroke is a signed message')),
    h('main', { class: 'call board' }, canvas, colors),
    h('div', { class: 'decks' }, pan, h('button', { class: 'deck', 'data-test': 'zoom-in', onclick: () => liveBoard.zoomBy(1.25) }, '+'),
      h('button', { class: 'deck', 'data-test': 'zoom-out', onclick: () => liveBoard.zoomBy(0.8) }, '−'), follow));
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

function renderError(data = state) {
  const texts = {
    invite_failed: ['Stopped', 'Invite failed: possible interception', 'The six words did not match the link. Someone else may have tried to use it. The invite is cancelled; make a new one and say the words again.'],
    invite_used: ['Used', 'This invite was already used', 'An invite works for one phone, once. Ask for a new one.'],
    unrecognized: ['Not known', 'Device not recognized. Ask for a new key.', 'This invite was already used - perhaps by this phone, before its storage was cleared. Keys cannot be made again: ask the person who invited you for a new invite.'],
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
        'Without a relay, messages wait until you are both online.', 'A hacked phone is not protected.'),
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
  const name = h('input', { value: p.name || '', maxlength: 64 });
  const relay = h('input', { value: p.relay || '', placeholder: session.config.relay || 'wss://relay.example', 'data-test': 'server', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none' });
  const said = h('p', { class: 'fine', 'data-test': 'server-state' });
  const now = theme();
  const looks = h('div', { class: 'theme', role: 'group', 'aria-label': 'Look' }, ['auto', 'light', 'dark'].map((t) =>
    h('button', { class: 'btn light', 'aria-pressed': String(now === t), 'data-test': 'theme-' + t, onclick: () => { theme(t); renderSettings(); } },
      t === 'auto' ? 'Auto' : t === 'light' ? 'Light' : 'Dark')));
  const relayOn = session.relayOn(), helping = session.helping();
  const pair = (test, on, set) => h('div', { class: 'theme', role: 'group' },
    h('button', { class: 'btn light', 'aria-pressed': String(on), 'data-test': test + '-on', onclick: async () => { await set(true); renderSettings(); } }, 'On'),
    h('button', { class: 'btn light', 'aria-pressed': String(!on), 'data-test': test + '-off', onclick: async () => { await set(false); renderSettings(); } }, 'Off'));
  draw(head('Settings', { small: true, back: () => show('about') }), h('main', {},
    h('div', { class: 'pad' },
      h('p', { class: 'caps' }, 'Look'), looks,
      h('p', { class: 'caps' }, 'Relay'), pair('relay', relayOn, (on) => session.setRelay(on)),
      h('p', { class: 'fine', 'data-test': 'relay-state' }, relayOn
        ? 'On. A relay helps phones find each other, and holds locked messages for a phone that is away. It cannot read them.'
        : 'Off. Phones reach each other directly, or through contacts who carry for others. New contacts pair in person. A message for a phone that is away waits here, or with a contact.'),
      h('p', { class: 'caps' }, 'Carry for contacts'), pair('carry', helping, (on) => session.setHelping(on)),
      h('p', { class: 'fine' }, helping
        ? 'On. While linked, this phone passes locked signals between your contacts and keeps locked messages for them while they are away. It cannot read them - but it does see which of your contacts talk to each other.'
        : 'Off. This phone carries nothing for others. It still takes what is for it.'),
      notifications(p),
      h('label', { class: 'field' }, h('span', {}, 'Your name'), name),
      h('button', { class: 'btn', 'data-test': 'save-settings', onclick: async () => { await saveName(name.value); toast('Saved'); } }, 'Save'),
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
        h('p', { class: 'fine' }, session.dev ? 'Device ' + hex(session.chat.deviceId(session.dev.signPub, session.dev.agreePub)) : 'No device key yet.')))));
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
  if (invite) return show('pair');
  const a = await store.asking();
  if (a) { state.pairing = 'asked'; invite = invite || null; }
  show('contacts');
}
// A code or link opened while p-chat is already open (the address changes
// only after its '#'): taken as at start.
addEventListener('hashchange', () => {
  const h = location.hash.slice(1);
  if (!h.startsWith('d1.') && !h.startsWith('v1.')) return;
  history.replaceState(null, '', location.pathname + location.search);
  if (!session.chat) return;
  if (h.startsWith('d1.')) show('meet', { meet: h, meetCode: null, meetAsked: false });
  else { invite = h; show('pair'); }
});
start().catch((e) => { draw(h('main', {}, h('div', { class: 'pad' }, h('p', { class: 'caps' }, 'p-chat could not start'), h('p', {}, e.message)))); });
