"""Protocol 10 in real browsers: no middleman.

  1. Two phones with relays off pair in person: the inviting phone's code
     opened by the other, the other's code scanned back (both codes read by
     jsQR off the pictures shown). They talk, and neither ever opened a
     connection to a relay.
  2. Three phones, each pair met in person. One of them, X, never uses a
     relay. Its link with Y is lost and found again through H, a contact of
     both, passing the signals on. Then Y is away: X's message for it is kept
     by H, sealed, and given to Y when it is back.
"""
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAILS = []

# Every WebSocket a page opens, counted: a relay is the only thing p-chat opens one to.
# Every WebRTC connection's life, for looking when a link is lost: when made,
# each state it passes, and who closed it.
WATCH_RTC = """(() => {
  const P = window.RTCPeerConnection;
  window.__rtc = [];
  window.RTCPeerConnection = class extends P {
    constructor(c) {
      super(c);
      const me = { n: window.__rtc.length, t0: Date.now(), states: [], closed: null };
      window.__rtc.push(me);
      this.addEventListener('connectionstatechange', () => me.states.push([Math.round((Date.now() - me.t0) / 1000), this.connectionState]));
      this.__me = me;
    }
    close() { if (!this.__me.closed) this.__me.closed = [Math.round((Date.now() - this.__me.t0) / 1000), (new Error().stack || '').split('\\n').slice(2, 6).join(' | ')]; return super.close(); }
  };
})();"""

COUNT_SOCKETS = """(() => {
  const W = window.WebSocket;
  window.__sockets = [];
  window.WebSocket = class extends W { constructor(u, p) { super(u, p); window.__sockets.push(String(u)); } };
})();"""


def check(cond, what):
    print(('ok   ' if cond else 'FAIL ') + what, flush=True)
    if not cond:
        FAILS.append(what)


def wait(page, js, timeout, what):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if page.evaluate(js):
                print('ok   ' + what, flush=True)
                return True
        except Exception:
            pass
        time.sleep(0.25)
    check(False, 'timed out: ' + what)
    return False


# A QR code as shown (an <img>), read back by jsQR.
READ_QR = """async (sel) => {
  await import('./vendor/jsQR.js');
  const img = document.querySelector(sel);
  await img.decode();
  const c = document.createElement('canvas');
  c.width = img.naturalWidth + 64; c.height = img.naturalHeight + 64;
  const x = c.getContext('2d');
  x.fillStyle = '#fff'; x.fillRect(0, 0, c.width, c.height);
  x.drawImage(img, 32, 32);
  return globalThis.jsQR(x.getImageData(0, 0, c.width, c.height).data, c.width, c.height)?.data || null;
}"""


def run(args, serve, launch):
    from playwright.sync_api import sync_playwright
    wasm = Path(args.wasm).resolve()
    work = Path(tempfile.mkdtemp(prefix='meet-', dir=wasm))
    relay = subprocess.Popen([sys.executable, str(ROOT / 'relay' / 'relay.py'), '--port', '0'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    port = int(relay.stdout.readline().split()[1])
    config = work / 'config.json'
    config.write_text(json.dumps({'relay': f'ws://127.0.0.1:{port}', 'ice': []}))
    rel = [sys.executable, str(ROOT / 'tools' / 'release.py')]
    keys = [work / f'k{i}.pem' for i in (1, 2)]
    pubs = [subprocess.run(rel + ['keygen', '--key', str(k)], check=True, capture_output=True, text=True).stdout.split()[-1] for k in keys]
    site = work / 'site'
    subprocess.run(rel + ['build', '--version', '1', '--committee', ','.join(pubs), '--quorum', '2', '--key', str(keys[0]),
                          '--key', str(keys[1]), '--wasm', str(wasm), '--out', str(site), '--config', str(config)], check=True, capture_output=True)
    server, url = serve(site)
    try:
        with sync_playwright() as p:
            browser = launch(p, args.browser)

            def phone(name, wrapped=False):
                ctx = browser.new_context(viewport={'width': 390, 'height': 844}, permissions=['camera'])
                ctx.add_init_script(COUNT_SOCKETS)
                ctx.add_init_script(WATCH_RTC)
                if wrapped:
                    # As a browser that cannot keep an Ed25519/X25519 key in IndexedDB (an iPhone's): kept wrapped.
                    ctx.add_init_script('window.__pchatWrapKeys = true;')
                page = ctx.new_page()
                page.errors = []
                page.on('pageerror', lambda e: page.errors.append(f'{e.name}: {e.message}'))
                page.on('console', lambda m: page.errors.append(m.text[:300]) if m.type == 'error' and 'p-chat round failed' in m.text else None)
                page.name = name
                page.goto(url + '/index.html')
                wait(page, "window.pchat && window.pchat.state.screen === 'contacts'", 60, name + ' opens on Chats')
                return page

            def relays_off(page):
                page.evaluate("window.pchat.ui.screen('settings')")
                page.click('[data-test=relay-off]')
                wait(page, "document.querySelector('[data-test=relay-state]')?.textContent.startsWith('Off.')", 10, page.name + ': relays off, said plainly')

            def meet(owner, other, other_name, mail=False, one_side=False):
                """The owner shows its code and the other opens it. With a relay that is all; with none,
                the other shows a code back and the owner scans it."""
                owner.evaluate("window.pchat.ui.screen('invite', {invite: null})")
                owner.click('[data-test=kind-code]')
                owner.wait_for_selector('[data-test=qr]', timeout=20000)
                link = owner.get_attribute('[data-test=qr]', 'data-link')
                read = owner.evaluate(READ_QR, '[data-test=qr]')
                check(read == link and '#d1.' in link, f'{owner.name}\'s code reads back as its link ({len(link)} characters)')
                other.goto(read)
                wait(other, "window.pchat && window.pchat.state.screen === 'meet'", 60, f'{other.name}: the code opens p-chat to pair in person')
                if mail:
                    other.check('[data-test=mail]')
                if one_side:
                    check(other.text_content('[data-test=show-answer]') == 'Pair', f'{other.name}\'s phone only asks to pair: the code names a relay')
                other.click('[data-test=show-answer]')
                if one_side:
                    wait(owner, "window.pchat.state.screen === 'paired'", 60, f'{other.name} only opened the code: the relay carried the rest')
                    check(not other.query_selector('[data-test=answer-qr]'), 'no code was shown back')
                else:
                    other.wait_for_selector('[data-test=answer-qr]', timeout=20000)
                    code = other.get_attribute('[data-test=answer-qr]', 'data-code')
                    check(other.evaluate(READ_QR, '[data-test=answer-qr]') == code, f'{other.name}\'s code back reads as its answer ({len(code)} characters)')
                    check(other.query_selector('[data-test=copy-answer]') is not None, 'the code back can be copied, to send from afar')
                    owner.fill('[data-test=answer-text]', code)  # pasted, as one sent from afar would be
                    owner.click('[data-test=use-answer]')
                wait(owner, "window.pchat.state.screen === 'paired'", 60, f'{owner.name} and {other.name} are paired')
                wait(other, "window.pchat.state.screen === 'paired'", 30, f'{other.name} says so too')
                fo = owner.evaluate("Array.from(document.querySelectorAll('[data-test=fingerprint] [data-glyph]')).map(e => e.dataset.glyph).join('')")
                ff = other.evaluate("Array.from(document.querySelectorAll('[data-test=fingerprint] [data-glyph]')).map(e => e.dataset.glyph).join('')")
                check(len(fo) > 0 and fo == ff, 'both show the same four pictures')
                owner.fill('[data-test=call-them]', other_name)
                other.fill('[data-test=call-them]', owner.name)
                owner.click('[data-test=open-chat]')
                other.click('[data-test=open-chat]')
                wait(owner, f"document.querySelector('[data-test=chat-name]')?.textContent === '{other_name}'", 20, f'{owner.name} calls them {other_name}')
                conv = owner.evaluate("window.pchat.state.conv")
                other_conv = other.evaluate("window.pchat.state.conv")
                return conv, other_conv

            ids = {}

            def peer(page):
                # Asked once: a page that is away has no p-chat to ask.
                if page.name not in ids:
                    ids[page.name] = page.evaluate('window.pchat.session.app.peer()')
                return ids[page.name]

            def linked(a, b):
                return f"window.pchat.session.app.liveWith('{peer(b)}')"

            def said(page, conv):
                return f"window.pchat.store.messages('{conv}').then(ms => ms.filter(m => !m.hidden).map(m => m.body && new TextDecoder().decode(m.body)))"

            # ---- 1. in person, relays off on both ----
            M = phone('Mina')
            N = phone('Noor')
            relays_off(M)
            relays_off(N)
            M.evaluate("window.pchat.ui.screen('invite', {invite: null})")
            check(M.evaluate("document.querySelector('[data-test=kind-contact]').disabled && !!document.querySelector('[data-test=relay-off-note]')"),
                  'relays off: an invite by link cannot be made, and the screen says why')
            mn, nm = meet(M, N, 'Noor')
            check(M.evaluate(f"window.pchat.session.conv.get('{mn}').relay") == '' and N.evaluate(f"window.pchat.session.conv.get('{nm}').relay") == '',
                  'the chat has no relay')
            wait(M, linked(M, N), 60, 'their own link is up, signalled over the link they made')
            M.evaluate(f"window.pchat.session.send('{mn}', 'hello-in-person-IP1')")
            wait(N, f"{said(N, nm)}.then(s => s.includes('hello-in-person-IP1'))", 30, 'a message goes phone to phone')
            N.evaluate(f"window.pchat.session.send('{nm}', 'and-back-IP2')")
            wait(M, f"{said(M, mn)}.then(s => s.includes('and-back-IP2'))", 30, 'and one back')
            # A message coming in: the chat is drawn again, but the composer is the same one,
            # not focused (no keyboard raised); the chat fits the screen and says how they are reached.
            M.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{mn}'}})")
            wait(M, "document.querySelector('[data-test=chat-name]')?.textContent === 'Noor'", 20, 'the chat opens')
            M.evaluate("(() => { const i = document.querySelector('[data-test=message]'); i.__kept = 1; i.value = 'half-typed'; i.blur(); })()")
            N.evaluate(f"window.pchat.session.send('{nm}', 'while-reading-WR1')")
            wait(M, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('while-reading-WR1'))", 30,
                 'a message comes in while the chat is open')
            check(M.evaluate("(() => { const i = document.querySelector('[data-test=message]'); return i.__kept === 1 && i.value === 'half-typed' && document.activeElement !== i; })()"),
                  'the composer is the same, what was typed stays, and nothing raised the keyboard')
            check(M.evaluate("document.getElementById('app').classList.contains('fitted') && Math.abs(document.getElementById('app').getBoundingClientRect().height - innerHeight) < 2"),
                  'the chat fits what can be seen; its messages scroll inside it')
            check('linked' in M.text_content('[data-test=reach]'), 'the chat says the phones are linked')
            M.evaluate("document.querySelector('[data-test=message]').value = ''")
            wait(M, "window.pchat.session.pairing === null", 60, 'the link made to pair is closed once their own is up')
            M.evaluate("window.pchat.ui.screen('invite', {invite: null})")
            M.click('[data-test=scan-code]')
            wait(M, "!!document.querySelector('[data-test=scanner] video')", 10, 'the camera opens to read a code')
            M.click('[data-test=scanner-cancel]')
            wait(M, "!document.querySelector('[data-test=scanner]')", 10, 'and closes')
            for page in (M, N):
                check(page.evaluate('window.__sockets') == [], page.name + ' never opened a connection to a relay')
                check(not page.errors, page.name + ' had no page errors: ' + '; '.join(page.errors))

            # ---- 2. three phones: X never uses a relay; H carries for X and Y ----
            X = phone('Xia')
            Y = phone('Yann', wrapped=True)
            H = phone('Hale')
            relays_off(X)
            hx, xh = meet(H, X, 'Xia', mail=True)
            hy, yh = meet(H, Y, 'Yann', mail=True, one_side=True)
            xy, yx = meet(X, Y, 'Yann', mail=True)
            check(Y.evaluate(f"window.pchat.session.conv.get('{yh}').relay") == H.evaluate(f"window.pchat.session.conv.get('{hy}').relay") != '',
                  'met in person, a chat takes the relay the inviting phone named')
            for page in (X, Y, H):
                peer(page)
            wait(X, linked(X, H) + ' && ' + linked(X, Y), 90, 'X is linked with H and with Y')
            wait(Y, linked(Y, H), 60, 'Y is linked with H')
            wait(X, "window.pchat.session.pairing === null", 60, 'the links made to pair are closed')
            # Their link lost, and made again: with no relay, the signals go through H.
            passed = H.evaluate('window.pchat.session.carrier.done.passed')
            X.evaluate(f"window.pchat.session.app.reconnectLive('{peer(Y)}')")
            wait(X, f"!{linked(X, Y)}", 20, 'X and Y\'s link is lost')
            wait(X, linked(X, Y), 90, 'and found again with no relay')
            check(H.evaluate('window.pchat.session.carrier.done.passed') > passed, 'H passed the signals on')
            X.evaluate(f"window.pchat.session.send('{xy}', 'found-again-FA1')")
            wait(Y, f"{said(Y, yx)}.then(s => s.includes('found-again-FA1'))", 30, 'and they talk again')
            # Y away, and X has no relay: nothing can reach Y, so X cannot send (one side never moves on alone).
            check(Y.evaluate("new Promise(r => { const o = indexedDB.open('p-chat'); o.onsuccess = () => { "
                             "const q = o.result.transaction('keys').objectStore('keys').get('device'); q.onsuccess = () => r(!!q.result.sign.wrapped); }; })"),
                  'Y\'s browser cannot keep its key as it is (an iPhone\'s): kept wrapped')
            Y.goto('about:blank')
            wait(X, f"!{linked(X, Y)}", 60, 'Y is away')
            X.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{xy}'}})")
            wait(X, "document.querySelector('[data-test=message]')?.disabled && document.querySelector('[data-test=send]')?.disabled", 20,
                 'X\'s chat with Y says it cannot send now')
            refused = X.evaluate(f"window.pchat.session.send('{xy}', 'never-sent-NS1').then(() => false, () => true)")
            check(refused and not X.evaluate(f"{said(X, xy)}.then(s => s.includes('never-sent-NS1'))"), 'and nothing is sent: not even on X\'s side')
            Y.goto(url + '/index.html')
            wait(Y, "window.pchat && window.pchat.state.screen !== 'loading'", 60, 'Y is back')
            check(Y.evaluate("window.pchat.state.screen") == 'contacts', 'reloaded, Y is still itself - its chats, not "lost its key"')
            if not wait(X, linked(X, Y), 90, 'X and Y are linked again, through H'):
                for page in (X, Y, H):
                    print('   ', page.name, page.evaluate('''() => { const s = window.pchat.session; return JSON.stringify({
                      live: s.app.livePeers().map(p => p.slice(0, 6)), signals: s.signals.map(x => [x.peer.slice(0, 6), Math.round((Date.now() - x.made) / 1000)]),
                      relinked: [...s.relinked].map(([p, t]) => [p.slice(0, 6), Math.round((Date.now() - t) / 1000)]),
                      reach: [...s.carrier.reach].map(([p, m]) => [p.slice(0, 6), m.size]), done: s.carrier.done }); }'''), flush=True)
                print('    X rtc', X.evaluate("JSON.stringify(window.__rtc.map(r => [r.n, Math.round((Date.now() - r.t0) / 1000), r.states, r.closed]))")[:6000], flush=True)
            X.evaluate(f"window.pchat.session.send('{xy}', 'live-again-L1')")
            wait(Y, f"{said(Y, yx)}.then(s => s.includes('live-again-L1'))", 30, 'and talk directly again')
            check(X.evaluate('window.__sockets') == [], 'X never opened a connection to a relay')
            for page in (X, Y, H):
                check(not page.errors, page.name + ' had no page errors: ' + '; '.join(page.errors))
            browser.close()
    finally:
        server.shutdown()
        relay.terminate()
    if FAILS:
        print(f'sgchat_meet: {len(FAILS)} failed')
        return 1
    print('sgchat_meet: ok')
    return 0
