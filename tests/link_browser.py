"""Protocol 11 in real browsers: linked devices.

A contact C, and one person's phone P and desktop D. P and C talk; D links
to P (a Link invite: the link and six words, the same four pictures on
both) and is brought into the chat - it has what was said there, and talks
in it. A new contact made on P is on D. D, live only, is away while C says
something and goes; back, P (left on) fills it in. The Linked devices
screen on each. Then unlinking, each way once: Keep (D leaves, a copy to
read), Forget (a tablet T, linked and gone), Split (D linked again; the two
agree which chats go with which).
"""
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

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
                print('ok   ' + what, flush=True)
                return True
        except Exception:
            pass
        time.sleep(0.25)
    check(False, 'timed out: ' + what)
    return False


def run(args, serve, launch):
    from playwright.sync_api import sync_playwright
    wasm = Path(args.wasm).resolve()
    work = Path(tempfile.mkdtemp(prefix='link-', dir=wasm))
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
    shots = work / 'shots'
    shots.mkdir()
    try:
        with sync_playwright() as p:
            browser = launch(p, args.browser)
            contexts = {}

            def device(name, wide=False):
                ctx = browser.new_context(viewport={'width': 1280, 'height': 860} if wide else {'width': 390, 'height': 844})
                page = ctx.new_page()
                page.on('dialog', lambda d: d.accept())
                page.errors = []
                page.on('pageerror', lambda e: page.errors.append(f'{e.name}: {e.message}'))
                page.on('console', lambda m: page.errors.append(m.text[:300]) if m.type == 'error' and 'p-chat round failed' in m.text else None)
                page.name = name
                contexts[name] = ctx
                return page

            def start(page):
                page.goto(url + '/index.html')
                wait(page, "window.pchat && window.pchat.state.screen === 'contacts'", 60, page.name + ' opens on Chats')

            def said(page, conv):
                return (f"window.pchat.store.messages('{conv}').then(ms => ms.filter(m => !m.hidden && m.body?.length)"
                        ".map(m => new TextDecoder().decode(m.body)))")

            def has_chat(page, conv):
                return f"window.pchat.session.chats().includes('{conv}')"

            def members(page, conv):
                return page.evaluate(f"window.pchat.session.info('{conv}').members.map(m => m.peer)")

            def diag(conv, *pages):
                # Where each stands, for looking when a wait failed.
                for page in pages:
                    try:
                        print('    ', page.name, page.evaluate(f"""(() => {{ const s = window.pchat.session; return JSON.stringify({{
                          d: s.app.conversations().includes('{conv}') ? s.app.describe('{conv}') : 'none',
                          info: s.app.conversations().includes('{conv}') ? (({{generation, removed, left, leaving}}) => ({{generation, removed, left, leaving}}))(s.info('{conv}')) : null,
                          me: s.app.peer().slice(0, 6), linked: s.app.linked().map(p => p.slice(0, 6)), live: s.app.livePeers().map(p => p.slice(0, 6)),
                          opened: s.opened.slice(-40), mb: s.app.mailboxes().map(m => window.pchat.session.chat.hex(m).slice(0, 8)).slice(0, 80) }}); }})()"""), flush=True)
                        print('      store', page.evaluate(f"window.pchat.store.messages('{conv}').then(ms => JSON.stringify(ms.slice(-8).map(m => [m.peer.slice(0, 6), m.seq, m.type, m.hidden ? 'h' : '', m.body?.length ? new TextDecoder().decode(m.body).slice(0, 20) : '', m.mine ? 'mine' : ''])))"), flush=True)
                        print('      later', page.evaluate("JSON.stringify(window.pchat.session.later.map(l => window.pchat.session.chat.hex(l.env.slice(1, 5))))"), flush=True)
                        print('      outbox', page.evaluate(f"window.pchat.store.outbox().then(os => JSON.stringify(os.filter(o => o.conv === '{conv}').map(o => [o.peer.slice(0, 6), o.seq, o.control ? 'c' : 'm', o.waiting ? 'w' : '', o.live ? 'l' : '', o.relayed ? 'r' : '', window.pchat.session.chat.hex(o.env.slice(1, 5))])))"), flush=True)
                    except Exception as e:
                        print('    ', page.name, 'away', e, flush=True)

            def peer(page):
                return page.evaluate('window.pchat.session.app.peer()')

            def words_of(page):
                return ' '.join(page.evaluate("Array.from(document.querySelectorAll('[data-test=words] li')).map(e => e.textContent)"))

            def contact(owner, other, other_name):
                """The owner invites with a link and six words; the other pairs; each names the other."""
                owner.evaluate("window.pchat.ui.screen('invite', {invite: null})")
                owner.click('[data-test=kind-contact]')
                owner.wait_for_selector('[data-test=qr]')
                link, words = owner.get_attribute('[data-test=qr]', 'data-link'), words_of(owner)
                other.goto(link)
                wait(other, "window.pchat && window.pchat.state.screen === 'pair'", 60, f'{other.name} opens the invite')
                other.fill('[data-test=code]', words)
                other.check('[data-test=mail]')
                other.click('[data-test=pair]')
                wait(owner, "window.pchat.state.screen === 'paired'", 90, f'{owner.name} and {other.name} are paired')
                wait(other, "window.pchat.state.screen === 'paired'", 60, f'{other.name} says so too')
                owner.fill('[data-test=call-them]', other_name)
                other.fill('[data-test=call-them]', owner.name)
                owner.click('[data-test=open-chat]')
                other.click('[data-test=open-chat]')
                wait(owner, f"document.querySelector('[data-test=chat-name]')?.textContent === '{other_name}'", 20, f'{owner.name} opens the chat')
                return owner.evaluate('window.pchat.state.conv')

            def link(owner, other):
                """Settings -> Linked devices -> Link a device: the other opens the link and types the six words."""
                owner.evaluate("window.pchat.ui.screen('linked', {})")
                owner.click('[data-test=link-device]')
                owner.wait_for_selector('[data-test=qr]')
                check('other device' in owner.text_content('main'), 'the invite says it is for your other device')
                lnk, words = owner.get_attribute('[data-test=qr]', 'data-link'), words_of(owner)
                other.goto(lnk)
                wait(other, "window.pchat && window.pchat.state.screen === 'pair'", 60, f'{other.name} opens the link')
                check(other.text_content('[data-test=pair]') == 'Link this device' and not other.query_selector('[data-test=mail]'),
                      f'{other.name} is asked to link, not to pair with a contact')
                other.fill('[data-test=code]', words)
                other.click('[data-test=pair]')
                wait(owner, "window.pchat.state.screen === 'paired'", 90, f'{owner.name} and {other.name} are linked')
                wait(other, "window.pchat.state.screen === 'paired'", 60, f'{other.name} says so too')
                fo = owner.evaluate("Array.from(document.querySelectorAll('[data-test=fingerprint] [data-glyph]')).map(e => e.dataset.glyph).join('')")
                fd = other.evaluate("Array.from(document.querySelectorAll('[data-test=fingerprint] [data-glyph]')).map(e => e.dataset.glyph).join('')")
                check(len(fo) > 0 and fo == fd, 'both show the same four pictures')
                owner.click('[data-test=linked-done]')
                other.click('[data-test=linked-done]')
                wait(owner, f"window.pchat.session.app.linked().includes('{peer(other)}')", 20, f'{owner.name} knows it is linked with {other.name}')
                wait(other, f"window.pchat.session.app.linked().includes('{peer(owner)}')", 20, f'{other.name} knows it too')

            # ---- 1. P and C talk; then D links to P ----
            P = device('Pat')
            C = device('Cy')
            D = device('Desk', wide=True)
            for page in (P, C, D):
                start(page)
            pc = contact(P, C, 'Cy')
            P.evaluate(f"window.pchat.session.send('{pc}', 'before-link-1')")
            C.evaluate(f"window.pchat.session.send('{pc}', 'before-link-2')")
            wait(C, f"{said(C, pc)}.then(s => s.includes('before-link-1'))", 30, 'C hears P')
            wait(P, f"{said(P, pc)}.then(s => s.includes('before-link-2'))", 30, 'P hears C')
            link(P, D)
            wait(D, has_chat(D, pc), 120, 'D is brought into the chat with C (by handoff, C endorsing)')
            wait(D, f"{said(D, pc)}.then(s => s.includes('before-link-1') && s.includes('before-link-2'))", 60,
                 'D has what was said before it was linked')
            check(peer(D) in members(C, pc), 'C\'s chat has D in it')
            check(D.evaluate(f"window.pchat.session.info('{pc}').name") == 'Cy', 'D calls the contact what P calls them')
            check(D.evaluate("!window.pchat.session.chats().includes(window.pchat.session.selfConv())"), 'the self conversation is not shown as a chat')
            D.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{pc}'}})")
            wait(D, "Array.from(document.querySelectorAll('[data-test=mine]')).some(e => e.textContent.includes('before-link-1'))", 20,
                 'on D, what P said shows as its own')
            D.evaluate(f"window.pchat.session.send('{pc}', 'from-the-desktop')")
            wait(C, f"{said(C, pc)}.then(s => s.includes('from-the-desktop'))", 60, 'C hears D')
            wait(P, f"{said(P, pc)}.then(s => s.includes('from-the-desktop'))", 60, 'P hears D (its own other device)')
            C.evaluate(f"window.pchat.session.send('{pc}', 'to-both-of-you')")
            wait(D, f"{said(D, pc)}.then(s => s.includes('to-both-of-you'))", 60, 'D hears C')
            wait(P, f"{said(P, pc)}.then(s => s.includes('to-both-of-you'))", 60, 'and so does P')

            # ---- 2. a new contact made on P is on D ----
            E = device('Eli')
            start(E)
            pe = contact(P, E, 'Eli')
            wait(D, has_chat(D, pe), 60, 'the new contact\'s chat is on D too')
            E.evaluate(f"window.pchat.session.send('{pe}', 'hi-from-eli')")
            wait(D, f"{said(D, pe)}.then(s => s.includes('hi-from-eli'))", 60, 'D hears the new contact')
            P.evaluate(f"window.pchat.session.rename('{pe}', 'Eli at work')")
            wait(D, f"window.pchat.session.info('{pe}').name === 'Eli at work'", 30, 'a name given on P is the name on D')

            # ---- 3. D away; C says something and goes; P, left on, fills D in ----
            D.evaluate(f"window.pchat.session.setDelivery('{pc}', false)")
            wait(C, f"!window.pchat.session.app.takesMail('{pc}', '{peer(D)}')", 30, 'D takes no mail in that chat: only live')
            d_peer = peer(D)
            D.goto('about:blank')
            wait(P, f"!window.pchat.session.app.liveWith('{d_peer}')", 60, 'D is away')
            C.evaluate(f"window.pchat.session.send('{pc}', 'while-away-1')")
            C.evaluate(f"window.pchat.session.send('{pc}', 'while-away-2')")
            wait(P, f"{said(P, pc)}.then(s => s.includes('while-away-2'))", 60, 'P has them')
            # C closes once its own round is done (what it keeps written down), as a person would a moment later.
            wait(C, "!window.pchat.session.busy", 10, 'C is between rounds')
            time.sleep(3)
            print('     C before away:', C.evaluate(f"window.pchat.session.app.describe('{pc}')"), flush=True)
            print('     P then:', P.evaluate(f"window.pchat.session.app.describe('{pc}')"), flush=True)
            C.goto('about:blank')
            start(D)
            wait(D, f"{said(D, pc)}.then(s => s.includes('while-away-1') && s.includes('while-away-2'))", 120,
                 'D is back, and filled in by P - C is gone')

            # ---- 4. the Linked devices screen, on each ----
            for page, other in ((P, D), (D, P)):
                page.evaluate("window.pchat.ui.screen('linked', {})")
                wait(page, f"document.querySelector('[data-test=linked-device]')?.dataset.peer === '{peer(other)}'", 20,
                     f'{page.name} lists {other.name}, with its four pictures')
                check(page.evaluate("document.querySelectorAll('[data-test=linked-device] [data-glyph]').length") == 4, 'four pictures')
                wait(page, "/Online now|Last heard/.test(document.querySelector('[data-test=last-seen]').textContent)", 60,
                     f'{page.name} says when {other.name} was last seen: ' + page.text_content('[data-test=last-seen]'))
            for theme in ('light', 'dark'):
                for page in (D, P):
                    page.evaluate(f"localStorage.setItem('p-chat.theme', '{theme}'); document.documentElement.setAttribute('data-theme', '{theme}')")
                    page.evaluate("window.pchat.ui.screen('linked', {})")
                    time.sleep(2)
                    page.screenshot(path=str(shots / f'linked-{page.name}-{theme}.png'), full_page=True)
                D.evaluate("window.pchat.ui.screen('unlink', {unlinkFrom: window.pchat.session.app.linked()[0]})")
                time.sleep(2)
                D.screenshot(path=str(shots / f'unlink-{theme}.png'), full_page=True)
            for page in (D, P):
                page.evaluate("localStorage.removeItem('p-chat.theme'); document.documentElement.removeAttribute('data-theme')")
            print('     screenshots in', shots, flush=True)

            # ---- 5. Keep: D leaves every chat (C back, to agree), keeping a copy to read ----
            print('     P before C back:', P.evaluate(f"window.pchat.session.app.describe('{pc}')"), flush=True)
            start(C)
            print('     C back:', C.evaluate(f"window.pchat.session.app.describe('{pc}')"), flush=True)
            D.evaluate("window.pchat.ui.screen('unlink', {unlinkFrom: window.pchat.session.app.linked()[0]})")
            D.click('[data-test=unlink-keep]')
            wait(D, "window.pchat.session.app.linked().length === 0", 20, 'D is unlinked')
            wait(P, "window.pchat.session.app.linked().length === 0", 60, 'P knows')
            wait(C, f"!window.pchat.session.info('{pc}').members.some(m => m.peer === '{d_peer}')", 120, 'D has left the chat with C')
            wait(E, f"!window.pchat.session.info('{pe}').members.some(m => m.peer === '{d_peer}')", 120, 'and the chat with E')
            wait(D, f"window.pchat.session.info('{pc}').left && window.pchat.session.info('{pc}').removed", 60, 'D keeps the chat, read only')
            D.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{pc}'}})")
            wait(D, "!!document.querySelector('[data-test=left]') && !!document.querySelector('[data-test=read-only]')", 20,
                 'it says so, and there is nothing to write in')
            check(D.evaluate(f"{said(D, pc)}.then(s => s.includes('to-both-of-you'))"), 'what was said is still there to read')
            time.sleep(1.5)
            D.screenshot(path=str(shots / 'read-only.png'))
            P.evaluate("window.pchat.ui.screen('settings')")
            time.sleep(1.5)
            P.screenshot(path=str(shots / 'settings.png'), full_page=True)
            C.evaluate(f"window.pchat.session.send('{pc}', 'after-keep')")
            if not wait(P, f"{said(P, pc)}.then(s => s.includes('after-keep'))", 60, 'P still talks with C'):
                diag(pc, P, C, D)
            time.sleep(3)
            check(not D.evaluate(f"{said(D, pc)}.then(s => s.includes('after-keep'))"), 'D hears nothing more')

            # ---- 6. Forget: a tablet T is linked, has the chats, and is unlinked by forgetting ----
            T = device('Tab')
            start(T)
            link(P, T)
            if not wait(T, has_chat(T, pc) + ' && ' + has_chat(T, pe), 120, 'T has both chats'):
                diag(pc, P, C, T)
                diag(pe, P, E, T)
            t_peer = peer(T)
            T.evaluate("window.pchat.ui.screen('unlink', {unlinkFrom: window.pchat.session.app.linked()[0]})")
            T.click('[data-test=unlink-forget]')
            wait(C, f"!window.pchat.session.info('{pc}').members.some(m => m.peer === '{t_peer}')", 120, 'T has left the chat with C')
            wait(E, f"!window.pchat.session.info('{pe}').members.some(m => m.peer === '{t_peer}')", 120, 'and the chat with E')
            wait(T, "window.pchat && window.pchat.state.screen === 'contacts' && window.pchat.session.chats().length === 0", 60,
                 'T has forgotten everything: no chats')
            wait(P, "window.pchat.session.app.linked().length === 0", 30, 'P is linked to nothing')

            # ---- 7. Split: D linked again (its kept copy replaced); the two agree ----
            link(P, D)
            wait(D, f"window.pchat.session.chats().includes('{pc}') && !window.pchat.session.info('{pc}').removed && !window.pchat.session.info('{pc}').left",
                 120, 'D, linked again, is back in the chat with C')
            wait(D, has_chat(D, pe) + f" && !window.pchat.session.info('{pe}').removed", 120, 'and with E')
            P.evaluate("window.pchat.ui.screen('unlink', {unlinkFrom: window.pchat.session.app.linked()[0]})")
            P.click('[data-test=unlink-split]')
            P.wait_for_selector('[data-test=split-row]')
            P.click(f"[data-test=split-row][data-conv='{pe}'] [data-test=split-there]")
            P.click('[data-test=ask-split]')
            D.evaluate("window.pchat.ui.screen('linked', {})")
            wait(D, "!!document.querySelector('[data-test=split-asked]')", 60, 'D is asked to agree, and shown which chats go where')
            time.sleep(2)
            D.screenshot(path=str(shots / 'split-asked.png'), full_page=True)
            D.click('[data-test=agree-split]')
            wait(C, f"!window.pchat.session.info('{pc}').members.some(m => m.peer === '{peer(D)}')", 120, 'D left the chat with C (it stays with P)')
            wait(E, f"!window.pchat.session.info('{pe}').members.some(m => m.peer === '{peer(P)}')", 120, 'P left the chat with E (it went with D)')
            wait(P, "window.pchat.session.app.linked().length === 0", 30, 'P is unlinked')
            wait(D, "window.pchat.session.app.linked().length === 0", 30, 'D is unlinked')
            E.evaluate(f"window.pchat.session.send('{pe}', 'to-the-desktop-only')")
            if not wait(D, f"{said(D, pe)}.then(s => s.includes('to-the-desktop-only'))", 60, 'E talks with D'):
                diag(pe, P, E, D)
            C.evaluate(f"window.pchat.session.send('{pc}', 'to-the-phone-only')")
            if not wait(P, f"{said(P, pc)}.then(s => s.includes('to-the-phone-only'))", 60, 'C talks with P'):
                diag(pc, P, C, D)
            check(not P.evaluate(f"window.pchat.session.chats().includes('{pe}')"), 'the chat that went with D is gone from P')

            for page in (P, C, D, E, T):
                check(not page.errors, page.name + ' had no page errors: ' + '; '.join(page.errors[:5]))
            browser.close()
    finally:
        server.shutdown()
        relay.terminate()
    if FAILS:
        print(f'sgchat_link_browser: {len(FAILS)} failed')
        return 1
    print('sgchat_link_browser: ok')
    return 0
