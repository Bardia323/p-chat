"""sgchat in real headless browsers (Chromium, through Playwright).

    python test_browser.py vectors --wasm build/wasm --browser <chrome>
    python test_browser.py e2e --wasm build/wasm --browser <chrome>

vectors: the protocol's vectors made by Wasm in the browser, and every
Ed25519 signature and X25519 secret made by the browser's own WebCrypto,
byte for byte against the native file.

desktop: p-chat in a computer's wide window: both panes the full height,
the chats' pane there from 900 px and gone below, the open chat marked, no
sideways scroll, a resize across the breakpoint (tests/desktop_browser.py).

e2e: two (and three) browser contexts and the local relay: pairing, live
and mailbox messages, a wrong code, a further device, revoking, a cleared
device, and no plaintext anywhere in the relay's memory.

Browser profiles and served files are disposable, under the build folder.
"""
import argparse
import functools
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Quiet(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map,
                      '.mjs': 'text/javascript', '.js': 'text/javascript', '.wasm': 'application/wasm'}

    def log_message(self, *a):
        pass


def serve(directory):
    handler = functools.partial(Quiet, directory=str(directory))
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f'http://127.0.0.1:{server.server_port}'


def launch(playwright, browser_path):
    return playwright.chromium.launch(executable_path=browser_path or None, headless=True,
                                      args=['--disable-features=WebRtcHideLocalIpsWithMdns',
                                            '--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream'])


def vectors(args):
    from playwright.sync_api import sync_playwright
    wasm = Path(args.wasm).resolve()
    with tempfile.TemporaryDirectory(dir=wasm) as d:
        d = Path(d)
        for f in ['sgchat.js', 'sgchat.wasm', 'sgchat_vectors_wasm.js', 'sgchat_vectors_wasm.wasm']:
            shutil.copy(wasm / f, d / f)
        shutil.copy(ROOT / 'tests' / 'webcrypto_checks.mjs', d / 'webcrypto_checks.mjs')
        shutil.copy(ROOT / 'web' / 'release.js', d / 'release.js')
        shutil.copy(ROOT / 'tests' / 'vectors' / 'v4.json', d / 'v4.json')
        (d / 'index.html').write_text('''<!doctype html><meta charset="utf-8">
<script src="sgchat.js"></script><script src="sgchat_vectors_wasm.js"></script><script src="release.js"></script>
<script type="module">
import { check } from './webcrypto_checks.mjs';
const chat = await createChat(), vec = await createVectors();
const kept = await (await fetch('v4.json')).json();
window.result = await check(chat, JSON.parse(vec.vectors()), kept);
</script>''')
        server, url = serve(d)
        try:
            with sync_playwright() as p:
                browser = launch(p, args.browser)
                page = browser.new_page()
                errors = []
                page.on('pageerror', lambda e: errors.append(str(e)))
                page.goto(url + '/index.html')
                page.wait_for_function('window.result !== undefined', timeout=60000)
                result = page.evaluate('window.result')
                version = browser.version
                browser.close()
        finally:
            server.shutdown()
    for f in result['fails'] + errors:
        print('FAIL', f)
    print(f'browser {version}: argon2id (32 MiB, 2 passes) in Wasm: {result["argonMs"]} ms')
    if result['fails'] or errors:
        print(f'sgchat_browser_vectors: {len(result["fails"]) + len(errors)} failed')
        return 1
    print('sgchat_browser_vectors: ok')
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('mode', choices=['vectors', 'e2e', 'release', 'meet', 'lag', 'desktop'])
    p.add_argument('--wasm', required=True)
    p.add_argument('--browser', default=os.environ.get('SGCHAT_BROWSER', ''))
    p.add_argument('--echo', default='', help='the native echo bot (sgchat_echo)')
    p.add_argument('--rtt', type=int, default=80, help='lag: the relay\'s round trip, made by a proxy (ms)')
    p.add_argument('--cases', default='', help='lag: which of live,reopen,relay (all by default)')
    p.add_argument('--trace', action='store_true', help='lag: print what the relay was asked')
    p.add_argument('--count', type=int, default=12, help='lag: messages per series')
    a = p.parse_args()
    if a.mode == 'vectors':
        sys.exit(vectors(a))
    if a.mode == 'release':
        import release_browser
        sys.exit(release_browser.run(a, serve, launch))
    if a.mode == 'lag':
        import lag_browser
        sys.exit(lag_browser.run(a, serve, launch))
    if a.mode == 'desktop':
        import desktop_browser
        sys.exit(desktop_browser.run(a, serve, launch))
    if a.mode == 'meet':
        import meet_browser
        sys.exit(meet_browser.run(a, serve, launch))
    import e2e
    sys.exit(e2e.run(a, serve, launch))


if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    main()
