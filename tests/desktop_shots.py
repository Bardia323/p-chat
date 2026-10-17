"""p-chat on a computer, looked at: every screen photographed at desktop
sizes (1280x800, 1920x1080, 2560x1440) and a phone's (390x844), light and
dark, for a person to look at. Not a pass/fail test (test_browser.py
desktop checks the layout's facts); a camera.

    python tests/desktop_shots.py --wasm <wasm dir> --browser <chrome> --out <dir> [--only chat,about]

Two pages pair in person with relays off (as tests/meet_browser.py does),
talk a little, and then each screen is drawn and photographed at each size.
The site is web/ itself (no release build, no service worker), so a change
to the CSS is seen at once.
"""
import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_browser import serve, launch  # noqa: E402
from meet_browser import READ_QR  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SIZES = [('phone', 390, 844), ('1280', 1280, 800), ('1920', 1920, 1080), ('2560', 2560, 1440)]


def site(wasm):
    d = Path(tempfile.mkdtemp(prefix='desk-', dir=wasm))
    for f in (ROOT / 'web').iterdir():
        (d / f.name).symlink_to(f)
    for f in ('sgchat.js', 'sgchat.wasm'):
        (d / f).symlink_to(Path(wasm) / f)
    (d / 'config.json').write_text(json.dumps({'relay': '', 'ice': []}))
    return d


def wait(page, js, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if page.evaluate(js):
                return True
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError('timed out: ' + js)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--wasm', required=True)
    p.add_argument('--browser', default=os.environ.get('SGCHAT_BROWSER', ''))
    p.add_argument('--out', required=True)
    p.add_argument('--only', default='')
    p.add_argument('--sizes', default='')
    a = p.parse_args()
    only = set(filter(None, a.only.split(',')))
    sizes = [s for s in SIZES if not a.sizes or s[0] in a.sizes.split(',')]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    wasm = Path(a.wasm).resolve()
    d = site(wasm)
    server, url = serve(d)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = launch(pw, a.browser)

        def page(name):
            ctx = browser.new_context(viewport={'width': 1280, 'height': 800}, permissions=['camera', 'microphone'],
                                      service_workers='block', reduced_motion='reduce')
            pg = ctx.new_page()
            pg.errors = []
            pg.on('pageerror', lambda e: pg.errors.append(str(e)))
            pg.name = name
            pg.goto(url + '/index.html')
            wait(pg, "window.pchat && window.pchat.state.screen === 'contacts'", 60)
            pg.evaluate("window.pchat.ui.screen('settings')")
            pg.click('[data-test=relay-off]')
            wait(pg, "document.querySelector('[data-test=relay-state]')?.textContent.startsWith('Off.')")
            return pg

        def shoot(pg, name, prep=None, settle=0.35):
            if only and name not in only:
                return
            for label, w, hgt in sizes:
                for scheme in ('light', 'dark'):
                    pg.set_viewport_size({'width': w, 'height': hgt})
                    pg.emulate_media(color_scheme=scheme, reduced_motion='reduce')
                    if prep:
                        prep()
                    time.sleep(settle)
                    pg.screenshot(path=str(out / f'{name}-{label}-{scheme}.png'))
            pg.set_viewport_size({'width': 1280, 'height': 800})

        M, N = page('Mina'), page('Noor')
        shoot(M, 'empty-chats', lambda: M.evaluate("window.pchat.ui.screen('contacts')"))
        # Pairing in person, each step photographed as it stands.
        M.evaluate("window.pchat.ui.screen('invite', {invite: null})")
        shoot(M, 'invite')
        M.click('[data-test=kind-code]')
        M.wait_for_selector('[data-test=qr]', timeout=20000)
        shoot(M, 'invite-inperson')
        link = M.evaluate(READ_QR, '[data-test=qr]')
        N.goto(link)
        wait(N, "window.pchat && window.pchat.state.screen === 'meet'", 60)
        shoot(N, 'meet')
        N.click('[data-test=show-answer]')
        N.wait_for_selector('[data-test=answer-qr]', timeout=20000)
        shoot(N, 'meet-code')
        M.fill('[data-test=answer-text]', N.get_attribute('[data-test=answer-qr]', 'data-code'))
        M.click('[data-test=use-answer]')
        wait(M, "window.pchat.state.screen === 'paired'", 60)
        wait(N, "window.pchat.state.screen === 'paired'", 30)
        shoot(M, 'paired')
        M.fill('[data-test=call-them]', 'Noor')
        N.fill('[data-test=call-them]', 'Mina')
        M.click('[data-test=open-chat]')
        N.click('[data-test=open-chat]')
        wait(M, "document.querySelector('[data-test=chat-name]')?.textContent === 'Noor'")
        mn, nm = M.evaluate('window.pchat.state.conv'), N.evaluate('window.pchat.state.conv')
        wait(M, f"window.pchat.session.app.liveWith(window.pchat.session.info('{mn}').members.find(m => !m.self).peer)", 60)
        lines = [(M, mn, 'Hello! Are you there?'), (N, nm, 'Yes - just got in. The tape is rolling.'),
                 (M, mn, 'Good. I wanted to show you how p-chat looks on a computer now: the chats on the left, the conversation on the right, '
                         'and long messages kept to a length a person can read without turning their head.'),
                 (N, nm, 'Looks right to me.'), (N, nm, 'Shall we play table tennis later?'), (M, mn, 'Yes 🏓')]
        for pg, conv, t in lines:
            pg.evaluate(f"window.pchat.session.send('{conv}', {json.dumps(t)})")
            time.sleep(0.4)
        wait(M, "document.querySelectorAll('[data-test=theirs]').length >= 2")
        # A second contact on Mina's list, so the list is a list (a group with Noor).
        M.evaluate(f"window.pchat.session.createGroup('Tape club', ['{mn}'], false)")
        time.sleep(1)
        chat = lambda: M.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{mn}'}})")  # noqa: E731
        shoot(M, 'chat', chat)
        shoot(M, 'chat-tray', lambda: (chat(), time.sleep(.6), M.evaluate("(() => { const t = document.querySelector('[data-test=tray]'); if (t.classList.contains('hidden')) document.querySelector('[data-test=attach]').click(); "
                                              "const st = document.querySelector('[data-test=sticker-picker]'); if (st.classList.contains('hidden')) document.querySelector('[data-test=pick-sticker]').click(); })()")))
        shoot(M, 'chats', lambda: M.evaluate("window.pchat.ui.screen('contacts')"))
        shoot(M, 'devices', lambda: M.evaluate(f"window.pchat.ui.screen('devices', {{conv: '{mn}'}})"))
        shoot(M, 'settings', lambda: M.evaluate("window.pchat.ui.screen('settings')"))
        shoot(M, 'about', lambda: M.evaluate("window.pchat.ui.screen('about')"))
        shoot(M, 'newgroup', lambda: M.evaluate("window.pchat.ui.screen('newgroup', {channel: false})"))
        shoot(M, 'replace', lambda: M.evaluate(f"window.pchat.ui.screen('replace', {{conv: '{mn}', lost: window.pchat.session.info('{mn}').members.find(m => !m.self).peer}})"))
        shoot(M, 'error', lambda: M.evaluate("window.pchat.ui.screen('error', {kind: 'invite_failed'})"))
        shoot(M, 'toast', lambda: (M.evaluate("window.pchat.ui.screen('contacts')"), time.sleep(.2), M.evaluate("window.pchat.ui.warn('Link copied. Send it; say the words separately.')")))
        shoot(M, 'banners', lambda: (M.evaluate(f"window.pchat.state.alerts.set('{mn}:equivocation', true); window.pchat.state.update = {{version: 7}}"),
                                     M.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{mn}'}})")))
        M.evaluate(f"window.pchat.state.alerts.clear(); window.pchat.state.update = null")
        # The camera reading a code.
        if not only or 'scanner' in only:
            M.evaluate("window.pchat.ui.screen('invite', {invite: null})")

            def scan():
                if M.query_selector('[data-test=scanner-cancel]'):
                    M.click('[data-test=scanner-cancel]')
                M.click('[data-test=scan-code]')
                M.wait_for_selector('[data-test=scanner] video')
            shoot(M, 'scanner', scan, settle=0.8)
            M.click('[data-test=scanner-cancel]')
        # The whiteboard, with a stroke or two.
        if not only or 'board' in only:
            M.evaluate(f"window.pchat.ui.screen('board', {{conv: '{mn}'}})")
            M.wait_for_selector('[data-test=sheet]')
            box = M.query_selector('[data-test=sheet]').bounding_box()
            M.mouse.move(box['x'] + box['width'] * .2, box['y'] + box['height'] * .3)
            M.mouse.down()
            for i in range(20):
                M.mouse.move(box['x'] + box['width'] * (.2 + i * .03), box['y'] + box['height'] * (.3 + (i % 5) * .04))
            M.mouse.up()
            shoot(M, 'board')
        # Table tennis: asked, taken.
        if not only or 'game' in only:
            M.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{mn}'}})")
            M.evaluate(f"window.pchat.session.app.startGame('{mn}'); window.pchat.session.pump()")
            N.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{nm}'}})")
            N.wait_for_selector('[data-test=play-accept]', timeout=30000)
            shoot(N, 'game-asked')
            N.click('[data-test=play-accept]')
            wait(M, "window.pchat.state.screen === 'game'", 30)
            shoot(M, 'game')
            M.click('[data-test=stop-game]')
        # A call: drawn from a call as the session would say it (relays are off here, and calls need one).
        if not only or 'call' in only:
            M.evaluate("""(() => {
              const s = window.pchat.session, c = document.createElement('canvas');
              c.width = 640; c.height = 480;
              const x = c.getContext('2d'); const g = x.createLinearGradient(0, 0, 640, 480);
              g.addColorStop(0, '#3b1d94'); g.addColorStop(1, '#ff8f1f'); x.fillStyle = g; x.fillRect(0, 0, 640, 480);
              x.fillStyle = '#f3e8cf'; x.beginPath(); x.arc(320, 230, 90, 0, 7); x.fill(); x.fillRect(200, 330, 240, 150);
              s.calls.info = () => ({ mode: 0, starter: 'x', forwarders: [] });
              s.calls.remote = new Map([['ab12cd34', { canvas: c }]]);
              s.calls.stats = () => ({ in: 2, played: 120, refused: 0, p50: 38 });
            })()""")
            shoot(M, 'call', lambda: M.evaluate(f"window.pchat.ui.screen('call', {{conv: '{mn}'}})"))
            M.evaluate("window.pchat.session.calls.remote = new Map()")
            shoot(M, 'call-ringing', lambda: M.evaluate(f"window.pchat.ui.screen('call', {{conv: '{mn}'}})"))
        shoot(M, 'keylost', lambda: M.evaluate("window.pchat.ui.screen('unrecognized')"))
        for pg in (M, N):
            if pg.errors:
                print(pg.name, 'page errors:', pg.errors)
        browser.close()
    server.shutdown()
    print('shots in', out)


if __name__ == '__main__':
    main()
