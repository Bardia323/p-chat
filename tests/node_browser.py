"""A device left on, in real browsers: the native sgchat_node.

A phone P and a contact C (browsers) talk. P links the node N (a "My other
device" invite, the link and six words given to sgchat_node --link): N is
brought into the chat, links live with both browsers (the engine's
IceTransport to their WebRtcTransport) and hears what C says. N relays: C
knows it does. Then C turns relays off and P is away: what C says to P is
kept by N, and given to P when it is back. Kept no longer, once opened.
"""
import json
import subprocess
import sys
import tempfile
import threading
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


class Node:
    """sgchat_node as a process: its STATE lines read as they come."""

    def __init__(self, exe, folder, relay, link=None, words=None):
        args = [exe, str(folder), '--relay', relay, '--name', 'Node']
        if link:
            args += ['--link', link, words]
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.state, self.lines, self.errors = {}, [], []
        threading.Thread(target=self.read, daemon=True).start()
        threading.Thread(target=self.read_errors, daemon=True).start()

    def read(self):
        for line in self.proc.stdout:
            self.lines.append(line.strip())
            if line.startswith('STATE '):
                self.state = json.loads(line[6:])

    def read_errors(self):
        for line in self.proc.stderr:
            self.errors.append(line.strip())

    def until(self, test, timeout, what):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                break
            try:
                if test(self.state):
                    print('ok   ' + what, flush=True)
                    return True
            except Exception:
                pass
            time.sleep(0.25)
        check(False, 'timed out: ' + what + f' (node: {self.state}, {self.lines[:3]}, errors {self.errors[-5:]})')
        return False

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def run(args, serve, launch):
    from playwright.sync_api import sync_playwright
    if not args.node:
        print('sgchat_node_browser: --node (an ICE build of sgchat_node) is needed')
        return 1
    wasm = Path(args.wasm).resolve()
    work = Path(tempfile.mkdtemp(prefix='node-', dir=wasm))
    relay = subprocess.Popen([sys.executable, str(ROOT / 'relay' / 'relay.py'), '--port', '0'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    port = int(relay.stdout.readline().split()[1])
    relay_url = f'ws://127.0.0.1:{port}'
    config = work / 'config.json'
    config.write_text(json.dumps({'relay': relay_url, 'ice': []}))
    rel = [sys.executable, str(ROOT / 'tools' / 'release.py')]
    keys = [work / f'k{i}.pem' for i in (1, 2)]
    pubs = [subprocess.run(rel + ['keygen', '--key', str(k)], check=True, capture_output=True, text=True).stdout.split()[-1] for k in keys]
    site = work / 'site'
    subprocess.run(rel + ['build', '--version', '1', '--committee', ','.join(pubs), '--quorum', '2', '--key', str(keys[0]),
                          '--key', str(keys[1]), '--wasm', str(wasm), '--out', str(site), '--config', str(config)], check=True, capture_output=True)
    server, url = serve(site)
    node = None
    try:
        with sync_playwright() as p:
            browser = launch(p, args.browser)

            def device(name):
                ctx = browser.new_context(viewport={'width': 390, 'height': 844})
                page = ctx.new_page()
                page.on('dialog', lambda d: d.accept())
                page.name = name
                return page

            def start(page):
                page.goto(url + '/index.html')
                wait(page, "window.pchat && window.pchat.state.screen === 'contacts'", 60, page.name + ' opens on Chats')
                page.evaluate("window.pchat.ui.screen('contacts', {})")

            def said(conv):
                return (f"window.pchat.store.messages('{conv}').then(ms => ms.filter(m => !m.hidden && m.body?.length)"
                        ".map(m => new TextDecoder().decode(m.body)))")

            def peer(page):
                return page.evaluate('window.pchat.session.app.peer()')

            def words_of(page):
                return ' '.join(page.evaluate("Array.from(document.querySelectorAll('[data-test=words] li')).map(e => e.textContent)"))

            P, C = device('Pat'), device('Cy')
            start(P)
            start(C)
            # ---- 1. P and C talk ----
            P.evaluate("window.pchat.ui.screen('invite', {invite: null})")
            P.click('[data-test=kind-contact]')
            P.wait_for_selector('[data-test=qr]')
            link, words = P.get_attribute('[data-test=qr]', 'data-link'), words_of(P)
            C.goto(link)
            wait(C, "window.pchat && window.pchat.state.screen === 'pair'", 60, 'C opens the invite')
            C.fill('[data-test=code]', words)
            C.check('[data-test=mail]')
            C.click('[data-test=pair]')
            wait(P, "window.pchat.state.screen === 'paired'", 90, 'P and C are paired')
            wait(C, "window.pchat.state.screen === 'paired'", 60, 'C says so too')
            P.fill('[data-test=call-them]', 'Cy')
            C.fill('[data-test=call-them]', 'Pat')
            P.click('[data-test=open-chat]')
            C.click('[data-test=open-chat]')
            wait(P, "document.querySelector('[data-test=chat-name]')?.textContent === 'Cy'", 20, 'P opens the chat')
            pc = P.evaluate('window.pchat.state.conv')
            P.evaluate(f"window.pchat.session.send('{pc}', 'before-the-node')")
            wait(C, f"{said(pc)}.then(s => s.includes('before-the-node'))", 30, 'C hears P')

            # ---- 2. P links the node ----
            P.evaluate("window.pchat.ui.screen('linked', {})")
            P.click('[data-test=link-device]')
            P.wait_for_selector('[data-test=qr]')
            lnk, words = P.get_attribute('[data-test=qr]', 'data-link'), words_of(P)
            node = Node(args.node, work / 'node', relay_url, lnk, words)
            wait(P, "window.pchat.state.screen === 'paired'", 90, 'P and the node are linked')
            P.click('[data-test=linked-done]')
            node.until(lambda s: s.get('chats') is not None, 30, 'the node is up')
            n_peer = next((l.split()[1] for l in node.lines if l.startswith('READY ')), '')
            check(n_peer != '', 'the node says who it is')
            wait(P, f"window.pchat.session.app.linked().includes('{n_peer}')", 30, 'P knows it is linked with the node')
            node.until(lambda s: pc in s['chats'], 120, 'the node is brought into the chat with C')
            wait(C, f"window.pchat.session.info('{pc}').members.some(m => m.peer === '{n_peer}')", 60, 'C\'s chat has the node in it')

            # ---- 3. live, native to browser ----
            wait(C, f"window.pchat.session.app.liveWith('{n_peer}')", 90, 'C is linked live with the node (browser WebRTC to native ICE)')
            wait(P, f"window.pchat.session.app.liveWith('{n_peer}')", 90, 'and so is P')
            C.evaluate(f"window.pchat.session.send('{pc}', 'hello-node')")
            node.until(lambda s: 'hello-node' in s['heard'], 60, 'the node hears C, live')
            wait(C, f"window.pchat.session.carrier.relays().includes('{n_peer}')", 60, 'C knows the node relays')
            wait(C, f"window.pchat.session.app.roomsOf('{pc}').some(r => window.pchat.session.carrier.servedIn(window.pchat.session.chat.hex(r.room)).size >= 1)",
                 60, 'and that it keeps mail for P\'s device')

            # ---- 4. kept by the node while P is away ----
            P.evaluate(f"window.pchat.session.setDelivery('{pc}', true)")
            wait(C, f"window.pchat.session.app.takesMail('{pc}', '{peer(P)}')", 30, 'P takes mail')
            p_peer = peer(P)
            C.evaluate("window.pchat.session.setRelay(false)")
            P.goto('about:blank')
            wait(C, f"!window.pchat.session.app.liveWith('{p_peer}')", 60, 'P is away')
            wait(C, f"window.pchat.session.canSend('{pc}')", 30, 'C can still send to P, through the node')
            C.evaluate(f"window.pchat.session.send('{pc}', 'kept-by-the-node')")
            node.until(lambda s: s['kept'] >= 1, 60, 'the node keeps it for P (C has no relay)')
            start(P)
            wait(P, f"window.pchat.session.app.liveWith('{n_peer}')", 90, 'back, P links with the node again')
            wait(P, f"{said(pc)}.then(s => s.includes('kept-by-the-node'))", 90, 'P is given what the node kept')
            node.until(lambda s: s['kept'] == 0 and s['given'] >= 1, 60, 'opened, the node keeps it no more')
            browser.close()
    finally:
        if node:
            node.stop()
        server.shutdown()
        relay.terminate()
    if FAILS:
        print(f'sgchat_node_browser: {len(FAILS)} failed')
        return 1
    print('sgchat_node_browser: ok')
    return 0
