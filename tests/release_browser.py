"""v1 §12 in a real browser: the release chain, as p-chat's service worker
keeps it. One page, and a host whose release changes under it:

  a valid update (checked, waiting, "Update ready", run from the next open);
  a bad signature, a broken link, a downgrade, a file not the manifest's -
  each refused, the evidence kept, the release run unchanged;
  versions skipped, checked link by link; an sw.js the release does not
  name, shown in About; a fork - two releases signed as one version - kept
  in the engine's Integrity and shown; a bundle given by a peer, checked
  alike and waiting.
"""
import base64
import json
import shutil
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


def wait(page, js, timeout=60, what=''):
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
    work = Path(tempfile.mkdtemp(prefix='release-', dir=wasm))
    rel = [sys.executable, str(ROOT / 'tools' / 'release.py')]
    keys = [work / f'k{i}.pem' for i in (1, 2, 3)]
    pubs = [subprocess.run(rel + ['keygen', '--key', str(k)], check=True, capture_output=True, text=True).stdout.split()[-1] for k in keys]
    config = work / 'config.json'
    config.write_text(json.dumps({'relay': '', 'ice': []}))

    def cut(version, chain, signers, out=None, committee=None):
        out = out or work / f'v{version}'
        cmd = rel + ['build', '--version', str(version), '--wasm', str(wasm), '--out', str(out), '--config', str(config)]
        if chain:
            cmd += ['--chain', str(chain / 'chain.json')]
        if committee or not chain:
            cmd += ['--committee', ','.join(committee or pubs), '--quorum', '2']
        for s in signers:
            cmd += ['--key', str(keys[s])]
        subprocess.run(cmd, check=True, capture_output=True)
        return out

    www = work / 'www'

    def publish(site):
        if www.exists():
            shutil.rmtree(www)
        shutil.copytree(site, www)

    v1 = cut(1, None, [0, 1])
    publish(v1)
    server, url = serve(www)
    status = "window.pchat.session.releaseStatus()"
    try:
        with sync_playwright() as p:
            browser = launch(p, args.browser)
            page = browser.new_page()
            errors = []
            page.on('pageerror', lambda e: errors.append(str(e)))
            # A database of the first schema, as an older p-chat left it (no
            # stores for files yet), with something in it.
            page.goto(url + '/manifest.json')
            page.evaluate('''() => new Promise((ok, no) => {
                const o = indexedDB.open('p-chat', 1);
                o.onupgradeneeded = () => { for (const s of ['keys', 'records', 'messages', 'meta']) o.result.createObjectStore(s); };
                o.onsuccess = () => { const t = o.result.transaction('meta', 'readwrite'); t.objectStore('meta').put('kept', 'older'); t.oncomplete = () => { o.result.close(); ok(); }; };
                o.onerror = () => no(o.error);
            })''')
            page.goto(url + '/index.html')
            wait(page, "window.pchat && window.pchat.state.screen !== 'loading'", 60, 'p-chat starts')
            migrated = page.evaluate('''() => new Promise((ok) => {
                const o = indexedDB.open('p-chat');
                o.onsuccess = () => {
                    const d = o.result, stores = [...d.objectStoreNames];
                    const r = d.transaction('meta').objectStore('meta').get('older');
                    r.onsuccess = () => ok({ version: d.version, stores, kept: r.result });
                };
            })''')
            check(migrated['version'] >= 2 and 'blobs' in migrated['stores'] and 'chunks' in migrated['stores'] and migrated['kept'] == 'kept',
                  'an older database is migrated: the new stores added, what was in it kept: ' + repr(migrated))
            wait(page, f"{status}.then(s => s && s.version === 1)", 60, 'release 1 runs: its first committee is the one sw.js was made with')
            page.evaluate("window.pchat.session.ensureDevice('Tester')")  # a device (fork evidence is kept by its App)

            def offered():
                page.evaluate("window.pchat.session.worker({ type: 'check' })")
                return page.evaluate(f"{status}.then(s => JSON.stringify(s))")

            def last_refused():
                s = json.loads(page.evaluate(f"{status}.then(s => JSON.stringify(s))"))
                return s['version'], s['pending'], (s['evidence'][-1]['why'] if s['evidence'] else '')

            # 1. A valid update.
            v2 = cut(2, v1, [0, 2])
            publish(v2)
            offered()
            wait(page, f"{status}.then(s => s.pending === 2)", 60, 'release 2 is checked and waits')
            check(page.evaluate(f"{status}.then(s => s.version)") == 1, 'release 1 still runs until p-chat is opened again')
            wait(page, "!!document.querySelector('[data-test=update-ready]')", 20, 'the page says: Update ready')
            page.click('[data-test=restart]')
            wait(page, "window.pchat && window.pchat.state.screen !== 'loading'", 60, 'reopened')
            wait(page, f"{status}.then(s => s.version === 2 && !s.pending)", 30, 'release 2 runs')
            page.evaluate("window.pchat.ui.screen('about')")
            wait(page, "document.querySelector('[data-test=release]')?.textContent.startsWith('Release 2')", 20, 'About says release 2')
            check(len(page.text_content('[data-test=chain-head]') or '') == 16, 'and the chain head')

            # 2. What is refused: each time, release 2 runs on and the why is kept.
            v3one = cut(3, v2, [0], work / 'v3one')
            publish(v3one)
            offered()
            version, pending, why = last_refused()
            check(version == 2 and not pending and '1 of the 2' in why, 'a release with one of the two signatures it needs is refused: ' + why)

            v3broken = cut(3, v2, [0, 1], work / 'v3broken')
            chain = json.loads((v3broken / 'chain.json').read_text())
            chain[-1]['previous'] = '1' * 64
            (v3broken / 'chain.json').write_text(json.dumps(chain))
            publish(v3broken)
            offered()
            version, pending, why = last_refused()
            check(version == 2 and not pending and 'broken link' in why, 'a broken link is refused: ' + why)

            publish(v1)
            offered()
            version, pending, why = last_refused()
            check(version == 2 and not pending and 'downgrade' in why, 'a downgrade is refused: ' + why)

            v3changed = cut(3, v2, [0, 1], work / 'v3changed')
            (v3changed / 'ui.js').write_text((v3changed / 'ui.js').read_text() + '\n// changed after it was signed\n')
            publish(v3changed)
            offered()
            version, pending, why = last_refused()
            check(version == 2 and not pending and 'does not match the manifest' in why, 'a file changed after signing is refused: ' + why)

            # 3. Versions skipped: from 2 straight to 4, release 3 checked on the way.
            v3 = cut(3, v2, [1, 2])
            v4 = cut(4, v3, [0, 2])
            publish(v4)
            offered()
            wait(page, f"{status}.then(s => s.pending === 4)", 60, 'from release 2 straight to 4: 3 checked on the way')
            page.reload()
            wait(page, f"{status}.then(s => s && s.version === 4)", 60, 'release 4 runs')

            # 4. An sw.js the release does not name: the browser takes it (it
            #    cannot refuse), and About says so.
            swapped = work / 'v4swapped'
            shutil.copytree(v4, swapped)
            (swapped / 'sw.js').write_text((swapped / 'sw.js').read_text() + '\n// served by a host that changed it\n')
            publish(swapped)
            page.evaluate("navigator.serviceWorker.getRegistration().then(r => r && r.update())")
            wait(page, f"{status}.then(s => s && s.swMatches === false)", 60, 'the worker this site serves is not the one release 4 names')
            page.evaluate("window.pchat.ui.screen('about')")
            wait(page, "!!document.querySelector('[data-test=sw-mismatch]')", 20, 'About shows it')
            publish(v4)
            page.evaluate("navigator.serviceWorker.getRegistration().then(r => r && r.update())")
            wait(page, f"{status}.then(s => s && s.swMatches === true)", 60, 'the signed worker again: no warning')

            # 5. A fork: two different releases 5, both signed by the first key.
            v5a = cut(5, v4, [0, 1], work / 'v5a')
            other = work / 'config-b.json'
            other.write_text(json.dumps({'relay': 'wss://elsewhere.example', 'ice': []}))
            v5b = work / 'v5b'
            subprocess.run(rel + ['build', '--version', '5', '--chain', str(v4 / 'chain.json'), '--key', str(keys[0]), '--key', str(keys[2]),
                                  '--wasm', str(wasm), '--out', str(v5b), '--config', str(other)], check=True, capture_output=True)
            publish(v5a)
            offered()
            wait(page, f"{status}.then(s => s.pending === 5)", 60, 'one release 5 is checked and waits')
            publish(v5b)
            offered()
            wait(page, "!!document.querySelector('[data-test=release-fork]')", 30, 'another release 5, signed by one who signed the first: a fork, shown')
            wait(page, "window.pchat.session.app.releaseForks() >= 1", 20, 'the fork is kept as evidence in the engine\'s Integrity')
            version, pending, why = last_refused()
            check(why == 'fork' and pending == 5, 'the second is refused; the first still waits')

            # 6. A bundle given by a peer: the same checks, then it waits.
            v6 = cut(6, v5a, [1, 2])
            given = {'chain': json.loads((v6 / 'chain.json').read_text()),
                     'manifest': base64.b64encode((v6 / 'manifest.json').read_bytes()).decode(),
                     'files': {q.relative_to(v6).as_posix(): base64.b64encode(q.read_bytes()).decode()
                               for q in v6.rglob('*') if q.is_file() and q.name not in ('manifest.json', 'chain.json')}}
            got = page.evaluate('''async (g) => {
                const b = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
                return window.pchat.session.worker({ type: 'install', chain: g.chain, manifest: b(g.manifest), files: Object.entries(g.files).map(([p, s]) => [p, b(s)]) });
            }''', given)
            check(got and got.get('type') == 'installed' and got.get('version') == 6, 'release 6, given by a peer, is checked and waits: ' + repr(got))
            v7 = cut(7, v6, [0, 1])
            given = {'chain': json.loads((v7 / 'chain.json').read_text()),
                     'manifest': base64.b64encode((v7 / 'manifest.json').read_bytes()).decode(),
                     'files': {q.relative_to(v7).as_posix(): base64.b64encode(q.read_bytes()).decode()
                               for q in v7.rglob('*') if q.is_file() and q.name not in ('manifest.json', 'chain.json')}}
            given['files']['ui.js'] = base64.b64encode(b'// not the signed one').decode()
            bad = page.evaluate('''async (g) => {
                const b = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
                return window.pchat.session.worker({ type: 'install', chain: g.chain, manifest: b(g.manifest), files: Object.entries(g.files).map(([p, s]) => [p, b(s)]) });
            }''', given)
            check(bad and bad.get('type') == 'refused' and 'does not match the manifest' in bad.get('why', ''),
                  'release 7 from a peer, with a file changed, is refused: ' + repr(bad))
            check(not errors, 'no page errors: ' + '; '.join(errors))
            browser.close()
    finally:
        server.shutdown()
    if FAILS:
        print(f'sgchat_release_browser: {len(FAILS)} failed')
        return 1
    print('sgchat_release_browser: ok')
    return 0
