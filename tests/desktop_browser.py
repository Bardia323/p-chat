"""p-chat on a computer: the layout's facts, in a real browser.

  - A wide window (900 px and more): the chats' pane on the left and the
    screen beside it, both the window's full height, side by side, filling
    the window's width; the open chat marked in the pane; no sideways scroll;
    every screen of the app drawn without spilling over the window.
  - A phone's width: no pane; the screen alone.
  - A window resized across 900 px, both ways: the pane comes and goes, and
    the open chat stays open.

Two pages pair in person with relays off (as meet_browser does) so there is a
chat to open. The site is web/ itself with the Wasm module beside it.
"""
import json
import tempfile
import time
from pathlib import Path

from meet_browser import READ_QR

ROOT = Path(__file__).resolve().parents[1]
FAILS = []


def check(cond, what):
    print(('ok   ' if cond else 'FAIL ') + what, flush=True)
    if not cond:
        FAILS.append(what)


def wait(page, js, timeout, what):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if page.evaluate(js):
                return True
        except Exception:
            pass
        time.sleep(0.2)
    check(False, 'timed out: ' + what)
    return False


# The layout as it stands: where each pane is, the open chat, any sideways scroll.
LAYOUT = """() => {
  const side = document.getElementById('side'), app = document.getElementById('app');
  const r = (e) => { const b = e.getBoundingClientRect(); return { x: b.x, y: b.y, w: b.width, h: b.height }; };
  const shown = side && !side.hidden && getComputedStyle(side).display !== 'none';
  return { W: innerWidth, H: innerHeight, side: shown ? r(side) : null, app: r(app),
    scrollX: document.documentElement.scrollWidth - innerWidth,
    marked: [...document.querySelectorAll('#side [aria-current=true]')].map((e) => e.dataset.conv),
    screen: window.pchat.state.screen, conv: window.pchat.state.conv };
}"""


def site(wasm):
    d = Path(tempfile.mkdtemp(prefix='desktop-', dir=wasm))
    for f in (ROOT / 'web').iterdir():
        (d / f.name).symlink_to(f)
    for f in ('sgchat.js', 'sgchat.wasm'):
        (d / f).symlink_to(Path(wasm) / f)
    (d / 'config.json').write_text(json.dumps({'relay': '', 'ice': []}))
    return d


def run(args, serve, launch):
    from playwright.sync_api import sync_playwright
    server, url = serve(site(Path(args.wasm).resolve()))
    try:
        with sync_playwright() as p:
            browser = launch(p, args.browser)

            def page(name):
                ctx = browser.new_context(viewport={'width': 1280, 'height': 800}, permissions=['camera'], service_workers='block',
                                          reduced_motion='reduce')  # a screen sliding in is not one spilling over
                pg = ctx.new_page()
                pg.errors = []
                pg.on('pageerror', lambda e: pg.errors.append(f'{e.name}: {e.message}'))
                pg.name = name
                pg.goto(url + '/index.html')
                wait(pg, "window.pchat && window.pchat.state.screen === 'contacts'", 60, name + ' opens')
                pg.evaluate("window.pchat.ui.screen('settings')")
                pg.click('[data-test=relay-off]')
                wait(pg, "document.querySelector('[data-test=relay-state]')?.textContent.startsWith('Off.')", 10, name + ': relays off')
                return pg

            M, N = page('Mina'), page('Noor')
            # Before any chat: the pane is there already, and the screen says how to begin.
            M.evaluate("window.pchat.ui.screen('contacts')")
            wait(M, "!document.getElementById('side').hidden && !!document.querySelector('#app [data-test=no-chats]')", 10,
                 'no chats yet: the pane is there, and the screen says how to begin')
            check(M.query_selector('#app [data-test=keys-hint]').is_visible(), 'a computer is told its keys (Enter, Esc)')

            # Paired in person, relays off.
            M.evaluate("window.pchat.ui.screen('invite', {invite: null})")
            M.click('[data-test=kind-code]')
            M.wait_for_selector('[data-test=qr]', timeout=20000)
            N.goto(M.evaluate(READ_QR, '[data-test=qr]'))
            wait(N, "window.pchat && window.pchat.state.screen === 'meet'", 60, 'the code opens p-chat')
            N.click('[data-test=show-answer]')
            N.wait_for_selector('[data-test=answer-qr]', timeout=20000)
            M.fill('[data-test=answer-text]', N.get_attribute('[data-test=answer-qr]', 'data-code'))
            M.click('[data-test=use-answer]')
            wait(M, "window.pchat.state.screen === 'paired'", 60, 'paired')
            M.fill('[data-test=call-them]', 'Noor')
            M.click('[data-test=open-chat]')
            wait(M, "document.querySelector('[data-test=chat-name]')?.textContent === 'Noor'", 20, 'the chat opens')
            mn = M.evaluate('window.pchat.state.conv')
            M.evaluate(f"window.pchat.session.send('{mn}', 'hello from a computer')")

            def layout(w, hgt):
                M.set_viewport_size({'width': w, 'height': hgt})
                time.sleep(0.35)  # the pane is drawn a moment after the screen
                return M.evaluate(LAYOUT)

            for w, hgt in ((1280, 800), (1920, 1080), (2560, 1440), (900, 700)):
                M.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{mn}'}})")
                L = layout(w, hgt)
                s, a = L['side'], L['app']
                check(s is not None, f'{w}x{hgt}: the chats\' pane is there')
                if not s:
                    continue
                check(abs(s['h'] - hgt) < 2 and abs(a['h'] - hgt) < 2 and s['y'] == 0 and a['y'] == 0,
                      f'{w}x{hgt}: both panes are the window\'s full height ({s["h"]:.0f}, {a["h"]:.0f})')
                check(s['x'] == 0 and abs(s['x'] + s['w'] - a['x']) < 1 and abs(a['x'] + a['w'] - w) < 1,
                      f'{w}x{hgt}: side by side, filling the window\'s width (pane {s["w"]:.0f}, screen {a["w"]:.0f})')
                check(L['marked'] == [mn], f'{w}x{hgt}: the open chat is marked in the pane')
                check(L['scrollX'] <= 0, f'{w}x{hgt}: no sideways scroll')
                # Every screen: nothing wider than the window.
                spill = []
                for name, data in (('contacts', '{}'), ('devices', f"{{conv: '{mn}'}}"), ('settings', '{}'), ('about', '{}'),
                                   ('invite', '{invite: null}'), ('newgroup', '{channel: false}'), ('board', f"{{conv: '{mn}'}}"),
                                   ('error', "{kind: 'bad_link'}"), ('chat', f"{{conv: '{mn}'}}")):
                    M.evaluate(f"window.pchat.ui.screen('{name}', {data})")
                    time.sleep(0.3)
                    if M.evaluate("document.documentElement.scrollWidth - innerWidth") > 0 or \
                            M.evaluate("[...document.querySelectorAll('#app *')].some(e => e.getBoundingClientRect().right > innerWidth + 1 && getComputedStyle(e).position !== 'fixed')"):
                        spill.append(name + ':' + M.evaluate("[...document.querySelectorAll('#app *')].filter(e => e.getBoundingClientRect().right > innerWidth + 1 && getComputedStyle(e).position !== 'fixed').slice(0, 3).map(e => e.tagName + '.' + e.className + ' ' + Math.round(e.getBoundingClientRect().right)).join(' | ')"))
                check(not spill, f'{w}x{hgt}: no screen spills over the window' + (f' ({", ".join(spill)})' if spill else ''))

            # A phone's width: no pane, the screen alone.
            M.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{mn}'}})")
            L = layout(390, 844)
            check(L['side'] is None, '390x844: no pane on a phone\'s width')
            check(abs(L['app']['w'] - 390) < 1 and L['scrollX'] <= 0, '390x844: the screen alone, the width of the window')
            check(L['screen'] == 'chat' and L['conv'] == mn, 'made narrow, the open chat stays open')
            check(M.query_selector('.chathead .back.to-list').is_visible(), 'and on a phone it has its back key')
            # And back across: the pane comes back, the chat marked.
            L = layout(1440, 900)
            check(L['side'] is not None and L['marked'] == [mn] and L['screen'] == 'chat', 'made wide again: the pane is back, the chat marked')
            check(not M.query_selector('.chathead .back.to-list').is_visible(), 'beside the pane, the chat needs no back key')
            for pg in (M, N):
                check(not pg.errors, pg.name + ' had no page errors: ' + '; '.join(pg.errors))
            browser.close()
    finally:
        server.shutdown()
    print('sgchat_desktop_browser: ' + ('ok' if not FAILS else f'{len(FAILS)} failed'))
    return 1 if FAILS else 0
