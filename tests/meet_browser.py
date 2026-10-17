"""Protocol 10 in real browsers: no middleman.

  1. Two phones with relays off pair in person: the inviting phone's code
     opened by the other, the other's code scanned back (both codes read by
     jsQR off the pictures shown). They talk, and neither ever opened a
     connection to a relay.
  2. Three phones, each pair met in person. One of them, X, never uses a
     relay. Its link with Y is lost and found again through H, a contact of
     both, passing the signals on. Then Y is away: X's message for it is kept
     by H, sealed, and given to Y when it is back.
  3. No relay at all (protocol 11): R relays (Settings). A's message for B,
     who is away, is kept by R. R is closed and opened again, and keeps it.
     B, back with no link to anyone, links again with R in person (two
     codes) and is given it; A links again with R, and finds B through R.

SGCHAT_MEET_ONLY=relaying runs only part 3 (for working on it).
"""
import os
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

            only = os.environ.get('SGCHAT_MEET_ONLY', '')
            if only != 'relaying':
                parts_before(browser, url, work, phone, relays_off, meet, peer, linked, said)
            relaying(browser, url, work, phone, relays_off, peer, linked, said, meet, relay)
            browser.close()
    finally:
        server.shutdown()
        relay.terminate()
    if FAILS:
        print(f'sgchat_meet: {len(FAILS)} failed')
        return 1
    print('sgchat_meet: ok')
    return 0


def relaying(browser, url, work, phone, relays_off, peer, linked, said, meet, relay):
    """3. With no relay anywhere, a device that relays carries for its contacts."""
    relay.terminate()  # from here there is no relay at all
    R = phone('Rue')
    A = phone('Ari')
    B = phone('Bea')
    for page in (R, A, B):
        relays_off(page)
    R.click('[data-test=relays-on]')
    wait(R, "window.pchat.session.relaying() && document.querySelector('[data-test=relays-state]').textContent.startsWith('On.')", 10, 'Rue relays, said plainly')
    R.screenshot(path=str(work / 'relays-light.png'), full_page=True)
    R.emulate_media(color_scheme='dark')
    R.screenshot(path=str(work / 'relays-dark.png'), full_page=True)
    R.emulate_media(color_scheme='light')
    ra, ar = meet(R, A, 'Ari', mail=True)
    rb, br = meet(R, B, 'Bea', mail=True)
    ab, ba = meet(A, B, 'Bea', mail=True)
    for page in (R, A, B):
        peer(page)
    wait(R, linked(R, A) + ' && ' + linked(R, B), 90, 'Rue is linked with Ari and Bea')
    wait(A, linked(A, B), 90, 'Ari is linked with Bea')
    wait(A, f"window.pchat.session.carrier.relays().includes('{peer(R)}')", 30, 'Ari knows Rue\'s device relays')
    wait(A, f"window.pchat.session.app.roomsOf('{ab}').some(r => window.pchat.session.carrier.servedIn(window.pchat.session.chat.hex(r.room)).size >= 1)",
         30, 'and that it keeps mail for Bea\'s device')
    # Bea away: with no relay, Ari can still send - Rue keeps it.
    B.goto('about:blank')
    wait(A, f"!{linked(A, B)}", 60, 'Bea is away')
    A.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{ab}'}})")
    wait(A, "!document.querySelector('[data-test=message]')?.disabled", 20, 'Ari\'s chat with Bea can still send')
    if not wait(A, "document.querySelector('[data-test=reach]')?.textContent.includes(\"through Rue's device\")", 20, 'and says through whom'):
        print('    reach:', A.evaluate("document.querySelector('[data-test=reach]')?.textContent"), A.evaluate(f"window.pchat.session.reachedBy('{ab}')"))
    A.fill('[data-test=message]', 'kept-by-rue-KR1')
    A.click('[data-test=send]')
    wait(R, "window.pchat.store.held().then(h => h.length >= 1)", 30, 'Rue keeps it, sealed')
    A.screenshot(path=str(work / 'carried-light.png'))
    A.emulate_media(color_scheme='dark')
    A.screenshot(path=str(work / 'carried-dark.png'))
    A.emulate_media(color_scheme='light')
    # Rue closed and opened again: it keeps what it holds, and has no link to anyone.
    R.reload()
    wait(R, "window.pchat && window.pchat.state.screen === 'contacts'", 60, 'Rue is opened again')
    wait(R, "window.pchat.session.relaying() && window.pchat.store.held().then(h => h.length >= 1)", 10, 'still relaying, still keeping it')
    wait(A, f"!{linked(A, R)}", 60, 'Ari lost Rue\'s link')

    def relink(shower, scanner):
        shower.evaluate("window.pchat.ui.screen('relink', {relink: null, relinkCode: null, relinkLink: null, relinkDone: false})")
        shower.wait_for_selector('[data-test=relink-link]', timeout=20000)
        link = shower.get_attribute('[data-test=relink-link]', 'data-link')
        check(shower.evaluate(READ_QR, '[data-test=relink-link]') == link and '#l1.' in link, f'{shower.name}\'s code to link again reads back ({len(link)} characters)')
        if scanner.name == 'Bea':
            time.sleep(1.2)  # the screen's entrance done
            shower.screenshot(path=str(work / 'relink-code-light.png'))
        scanner.goto(link)
        wait(scanner, "window.pchat.state.screen === 'relink'", 30, f'{scanner.name}: the code opens p-chat to link again')
        scanner.click('[data-test=relink-answer]')
        scanner.wait_for_selector('[data-test=relink-qr]', timeout=20000)
        if scanner.name == 'Bea':
            scanner.emulate_media(color_scheme='dark')
            time.sleep(1.2)  # the screen's entrance done
            scanner.screenshot(path=str(work / 'relink-answer-dark.png'))
            scanner.emulate_media(color_scheme='light')
        code = scanner.get_attribute('[data-test=relink-qr]', 'data-code')
        check(scanner.evaluate(READ_QR, '[data-test=relink-qr]') == code, f'{scanner.name}\'s answer reads back')
        shower.fill('[data-test=relink-text]', code)
        shower.click('[data-test=relink-use]')

    # Bea back: no link to anyone. One scan with Rue, and Rue gives her what it kept.
    B.goto(url + '/index.html')
    wait(B, "window.pchat && window.pchat.state.screen === 'contacts'", 60, 'Bea is back')
    check(B.evaluate("window.pchat.session.app.livePeers().length") == 0, 'with no link to anyone')
    relink(R, B)
    wait(B, linked(B, R), 60, 'Bea and Rue are linked again, in person')
    wait(R, "document.querySelector('[data-test=relink-status]')?.textContent === 'Linked again.'", 30, 'Rue\'s screen says so')
    time.sleep(1.2)  # the screen's entrance done
    R.screenshot(path=str(work / 'relink-light.png'))
    R.emulate_media(color_scheme='dark')
    R.screenshot(path=str(work / 'relink-dark.png'))
    R.emulate_media(color_scheme='light')
    wait(B, f"{said(B, ba)}.then(s => s.includes('kept-by-rue-KR1'))", 60, 'Bea is given what Rue kept')
    wait(R, "window.pchat.store.held().then(h => h.length === 0)", 30, 'opened, Rue drops it')
    # Ari links again with Rue, and through Rue finds Bea.
    relink(R, A)
    if not wait(A, linked(A, R), 60, 'Ari and Rue are linked again'):
        for page in (R, A, B):
            print('   ', page.name, page.evaluate('''() => { const s = window.pchat.session; return JSON.stringify({
              pairing: s.pairing && { role: s.pairing.role, up: s.pairing.link.up, linked: s.pairing.linked, closed: s.pairing.closed },
              live: s.app.livePeers().map(p => p.slice(0, 6)), signals: s.signals.map(x => [x.peer.slice(0, 6), Math.round((Date.now() - x.made) / 1000)]),
              reach: [...s.carrier.reach].map(([p, m]) => [p.slice(0, 6), m.size]), done: s.carrier.done }); }'''), flush=True)
    if not wait(A, linked(A, B), 90, 'and Ari finds Bea through Rue, with no relay'):
        for page in (R, A, B):
            print('   ', page.name, page.evaluate('''() => { const s = window.pchat.session; return JSON.stringify({
              live: s.app.livePeers().map(p => p.slice(0, 6)), signals: s.signals.length, relays: s.carrier.relays().map(p => p.slice(0, 6)),
              serving: [...s.carrier.serving].map(([p, l]) => [p.slice(0, 6), l.map(d => d.now)]),
              relinked: [...s.relinked].map(([p, t]) => [p.slice(0, 6), Math.round((Date.now() - t) / 1000)]),
              reach: [...s.carrier.reach].map(([p, m]) => [p.slice(0, 6), m.size]), done: s.carrier.done }); }'''), flush=True)
            print('    rtc', page.evaluate("JSON.stringify(window.__rtc.slice(-6).map(r => [r.n, Math.round((Date.now() - r.t0) / 1000), r.states, !!r.closed]))")[:1500])
    A.evaluate(f"window.pchat.session.send('{ab}', 'direct-again-DA1')")
    wait(B, f"{said(B, ba)}.then(s => s.includes('direct-again-DA1'))", 30, 'and they talk directly again')
    wait(A, f"{said(A, ab)}.then(s => s.filter(x => x === 'kept-by-rue-KR1').length === 1)", 5, 'what Ari sent is there once')
    for page in (R, A, B):
        check(page.evaluate('window.__sockets') == [], page.name + ' never opened a connection to a relay')
        check(not page.errors, page.name + ' had no page errors: ' + '; '.join(page.errors))


def parts_before(browser, url, work, phone, relays_off, meet, peer, linked, said):
    """0-2: an iPhone's install hint, two phones in person, three that carry."""
    # ---- 0. an iPhone in Safari: the way to the Home Screen, shown on Chats, gone when dismissed ----
    ictx = browser.new_context(viewport={'width': 390, 'height': 844},
                               user_agent='Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1')
    I = ictx.new_page()
    I.goto(url + '/index.html')
    wait(I, "!!document.querySelector('[data-test=install]')", 60, 'an iPhone in Safari is shown how to put p-chat on its Home Screen')
    I.screenshot(path=str(work / 'install.png'))
    I.click('[data-test=install-later]')
    I.reload()
    wait(I, "window.pchat && window.pchat.state.screen === 'contacts'", 60, 'reloaded')
    check(not I.query_selector('[data-test=install]'), 'dismissed, it stays dismissed')
    ictx.close()

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
    # Sent into a link that had died without saying so: not acknowledged, it
    # is sent again once the link carries again (N takes mail; no relay).
    N.evaluate(f"window.pchat.session.setDelivery('{nm}', true)")
    wait(M, f"window.pchat.session.app.takesMail('{mn}', '{peer(N)}')", 30, 'Noor takes mail')
    N.evaluate("(() => { const a = window.pchat.session.app; a.__takeLive = a.takeLive; a.takeLive = () => { a.__takeLive(); return []; }; })()")
    M.evaluate(f"window.pchat.session.send('{mn}', 'into-a-dead-link-DL1')")
    time.sleep(5)
    N.evaluate("(() => { const a = window.pchat.session.app; a.takeLive = a.__takeLive; })()")
    wait(N, f"{said(N, nm)}.then(s => s.includes('into-a-dead-link-DL1'))", 75, 'what went into a dead link is sent again, and arrives')
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
    M.evaluate("(() => { const i = document.querySelector('[data-test=message]'); i.value = ''; i.dispatchEvent(new Event('input')); })()")
    check(M.get_attribute('[data-test=send]', 'data-shows') == 'voice', 'nothing written: the send key records a voice note')
    M.fill('[data-test=message]', 'said-and-seen-SS1')
    check(M.get_attribute('[data-test=send]', 'data-shows') == 'send', 'something written: it sends')
    M.evaluate("document.querySelector('.tape').scrollTop = 0")
    M.click('[data-test=send]')
    wait(M, "(() => { const t = document.querySelector('.tape'); return [...t.querySelectorAll('[data-test=mine]')].some(e => e.textContent.includes('said-and-seen-SS1')) "
            "&& t.scrollHeight - t.scrollTop - t.clientHeight < 4; })()", 20, 'what was sent is in sight: the list goes to its end')
    # Something new while reading further up: said below, and a tap goes to it.
    for i in range(14):
        N.evaluate(f"window.pchat.session.send('{nm}', 'filler-{i}')")
    wait(M, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('filler-13'))", 30, 'many messages come in')
    wait(M, "(() => { const t = document.querySelector('.tape'); return t.scrollHeight - t.scrollTop - t.clientHeight < 4; })()", 10,
         'open at the end, the list stays at the end as they come')
    M.evaluate("document.querySelector('.tape').scrollTop = 0")
    N.evaluate(f"window.pchat.session.send('{nm}', 'while-up-there-NB1')")
    wait(M, "document.querySelector('[data-test=new-below]')?.textContent === '1 new message ↓'", 30, 'scrolled up: a new message is said below')
    check(M.evaluate("document.querySelector('.tape').scrollTop") < 50, 'and the list stays where it was being read')
    M.click('[data-test=new-below]')
    wait(M, "(() => { const t = document.querySelector('.tape'); return t.scrollHeight - t.scrollTop - t.clientHeight < 8 && !document.querySelector('[data-test=new-below]'); })()",
         10, 'a tap goes to the end, and the note is gone')
    # Written right to left: the time at the bubble's other end, not on the words.
    N.evaluate(f"window.pchat.session.send('{nm}', 'سلام دوست من، این یک پیام فارسی است')")
    N.evaluate(f"window.pchat.session.send('{nm}', 'hello my friend, this is written left to right')")
    wait(M, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('left to right'))", 30, 'both come in')
    ends = M.evaluate("""(() => {
      const of = (t) => Array.from(document.querySelectorAll('[data-test=theirs]')).find(e => e.textContent.includes(t));
      const side = (b) => { const r = b.getBoundingClientRect(), m = b.querySelector('.meta').getBoundingClientRect();
        return { left: m.left - r.left, right: r.right - m.right, below: m.top >= b.firstChild.parentNode.getBoundingClientRect().top }; };
      return { rtl: side(of('فارسی')), ltr: side(of('left to right')) }; })()""")
    check(ends['rtl']['left'] < 20 and ends['rtl']['right'] > 40, f'right to left: the time is at the left end ({ends["rtl"]})')
    check(ends['ltr']['right'] < 20 and ends['ltr']['left'] > 40, f'left to right: the time is at the right end ({ends["ltr"]})')
    M.screenshot(path=str(work / 'rtl-time.png'))
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
