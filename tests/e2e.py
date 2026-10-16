"""p-chat end to end: separate browser profiles (each its own storage, keys
and service worker), the local relay, and a signed release built with a
throwaway key. Driven through the UI as a person would, and read through
`window.pchat` only to check what the UI cannot show (which path a message
took, the generation).

Covers: pair (QR link + six words), texts both ways live; a tab closed and
delivery through the mailbox on reopening; a wrong code and the owner's
alert; files; a further device (handoff endorsed by the friend's first
device) and revoking it; a group and a channel; disappearing messages;
notifications (a push made by the sender's phone, opened as a push service
would, shown by the friend's worker as the chosen symbol alone); a call, a
stream to a group, speakers through a tree with small and full pictures;
tape tennis and the whiteboard; an update from a contact's phone over the
live link; a lost phone refused and then replaced, given the history; the
echo bot; a device whose keys were cleared ("Device not recognized"); the
signed service worker refusing an unsigned change; and no plaintext, name
or code anywhere in the relay process's memory.
"""
import json
import os
import re
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
                return True
        except Exception:
            pass
        time.sleep(0.25)
    check(False, 'timed out: ' + (what or js))
    return False


def scan_memory(pid, needles):
    """Which of `needles` (bytes) are anywhere in the process's memory."""
    found = set()
    with open(f'/proc/{pid}/maps') as maps, open(f'/proc/{pid}/mem', 'rb', 0) as mem:
        for line in maps:
            m = re.match(r'([0-9a-f]+)-([0-9a-f]+) (r)', line)
            if not m:
                continue
            start, end = int(m.group(1), 16), int(m.group(2), 16)
            if end - start > 1 << 30:
                continue
            try:
                mem.seek(start)
                chunk = mem.read(end - start)
            except (OSError, ValueError, OverflowError):
                continue
            for n in needles:
                if n in chunk:
                    found.add(n)
    return found


class _PushHook:
    seen = []


def push_service():
    """A push service of the test's own, on the loopback."""
    import http.server
    import threading

    class Hook(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            _PushHook.seen.append((dict(self.headers), self.rfile.read(int(self.headers.get('Content-Length', 0)))))
            self.send_response(201)
            self.end_headers()

        def log_message(self, *a):
            pass

    _PushHook.seen = []
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Hook)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    class Service:
        origin = f'http://127.0.0.1:{server.server_port}'
        endpoint = origin + '/push/friend'

        def wait(self, seconds):
            for _ in range(int(seconds * 10)):
                if _PushHook.seen:
                    return _PushHook.seen[0]
                time.sleep(0.1)
            return None

        def close(self):
            server.shutdown()
    return Service()


def push_keys():
    """A subscription's keys, as a browser's push service would hold them."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    ua = ec.generate_private_key(ec.SECP256R1())
    pub = ua.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return ua, pub, os.urandom(16)


def open_push(ua, ua_pub, auth_secret, headers, body):
    """RFC 8291 opened as a browser would, and the RFC 8292 token checked."""
    import base64
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    pad = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    plain = None
    try:
        salt, idlen = body[:16], body[20]
        as_pub = body[21:21 + idlen]
        sealed = body[21 + idlen:]
        shared = ua.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_pub))
        ikm = HKDF(hashes.SHA256(), 32, auth_secret, b'WebPush: info\0' + ua_pub + as_pub).derive(shared)
        cek = HKDF(hashes.SHA256(), 16, salt, b'Content-Encoding: aes128gcm\0').derive(ikm)
        nonce = HKDF(hashes.SHA256(), 12, salt, b'Content-Encoding: nonce\0').derive(ikm)
        record = AESGCM(cek).decrypt(nonce, sealed, None).rstrip(b'\0')
        if headers.get('Content-Encoding') == 'aes128gcm' and record.endswith(b'\2'):
            plain = record[:-1].decode()
    except Exception as e:
        print('   push did not open:', e)
    vapid_ok, audience = False, None
    try:
        auth = headers.get('Authorization', '')
        token, key = auth[len('vapid t='):].split(', k=')
        head, claims, sig = token.split('.')
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pad(key))
        raw = pad(sig)
        public.verify(utils.encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big')),
                      (head + '.' + claims).encode(), ec.ECDSA(hashes.SHA256()))
        audience = json.loads(pad(claims))['aud']
        vapid_ok = auth.startswith('vapid t=')
    except Exception as e:
        print('   VAPID did not hold:', e)
    return plain, vapid_ok, audience


def deliver_push(ctx, page, origin, data):
    """What a push service does on the phone: the browser hands the opened
    payload to the service worker. Returns the pings it has recorded."""
    cdp = ctx.new_cdp_session(page)
    regs = []
    cdp.on('ServiceWorker.workerRegistrationUpdated', lambda e: regs.extend(e['registrations']))
    cdp.send('ServiceWorker.enable')
    for _ in range(50):
        if regs:
            break
        page.wait_for_timeout(100)
    rid = next((r['registrationId'] for r in regs if not r.get('isDeleted')), None)
    if rid is None:
        print('   no service worker registration')
        return None
    cdp.send('ServiceWorker.deliverPushMessage', {'origin': origin, 'registrationId': rid, 'data': data})
    for _ in range(50):
        pinged = page.evaluate("caches.open('p-chat-pings').then(c => c.keys()).then(k => k.map(r => r.url))")
        if pinged:
            return pinged
        page.wait_for_timeout(100)
    return []


def text_in(page, sel):
    return page.evaluate(f"Array.from(document.querySelectorAll('{sel}')).map(e => e.textContent)")


def run(args, serve, launch):
    from playwright.sync_api import sync_playwright
    wasm = Path(args.wasm).resolve()
    work = Path(tempfile.mkdtemp(prefix='e2e-', dir=wasm))
    relay = subprocess.Popen([sys.executable, str(ROOT / 'relay' / 'relay.py'), '--port', '0', '--push-local'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    port = int(relay.stdout.readline().split()[1])
    keys = [work / f'release-{i}.pem' for i in (1, 2, 3)]
    site = work / 'site'
    config = work / 'config.json'
    config.write_text(json.dumps({'relay': f'ws://127.0.0.1:{port}', 'ice': []}))
    rel = [sys.executable, str(ROOT / 'tools' / 'release.py')]
    # A committee of three release keys, two of which sign (v1 §12).
    pubs = [subprocess.run(rel + ['keygen', '--key', str(k)], check=True, capture_output=True, text=True).stdout.split()[-1] for k in keys]
    subprocess.run(rel + ['build', '--version', '1', '--committee', ','.join(pubs), '--quorum', '2', '--key', str(keys[0]), '--key', str(keys[1]),
                          '--wasm', str(wasm), '--out', str(site), '--config', str(config)], check=True, capture_output=True)
    server, url = serve(site)
    running_site = site
    secrets = []
    try:
        with sync_playwright() as p:
            browser = launch(p, args.browser)

            def device(name, **kw):
                ctx = browser.new_context(viewport={'width': 390, 'height': 844}, **kw)
                page = ctx.new_page()
                page.on('dialog', lambda d: d.accept())
                errors = []
                page.on('pageerror', lambda e: errors.append(f'{e.name}: {e.message} | {(e.stack or "")[:600]}'))
                # A round that failed is said on the console; it counts as an error here.
                page.on('console', lambda m: errors.append(m.text[:300]) if m.type == 'error' and m.text.startswith('p-chat round failed') else None)
                page.errors = errors
                page.name = name
                return ctx, page

            def open_app(page, link=None):
                page.goto(link or url + '/index.html')
                wait(page, "window.pchat && window.pchat.state.screen !== 'loading'", 60, page.name + ' starts')

            # ---- 0. a browser whose service worker never starts (a certificate
            #      only "visited anyway"): About still shows, at once, and says so ----
            w_ctx, W = device('no-worker', service_workers='block')
            open_app(W)
            W.click('text=About')
            wait(W, "!!document.querySelector('[data-test=settings]')", 3, 'About shows at once, with no service worker')
            wait(W, "!!document.querySelector('[data-test=no-worker]') && document.querySelector('[data-test=release]').textContent.startsWith('Release 1')", 15,
                 'and says the background check is not running')
            check(not W.errors, 'no-worker had no page errors: ' + '; '.join(W.errors))
            w_ctx.close()

            # ---- 1. pair: the owner shows an invite; the friend types the words ----
            a_ctx, A = device('owner')
            open_app(A)
            # p-chat opens on its chats, empty and ready for the first contact.
            wait(A, "window.pchat.state.screen === 'contacts' && !!document.querySelector('[data-test=no-chats]')", 20, 'it opens on Chats: none yet, an invite one press away')
            check(A.evaluate("document.querySelector('[data-test=new-group]').disabled && !document.querySelector('[data-test=invite]').disabled"),
                  'Group waits for a contact; Invite does not')
            A.click('[data-test=start-invite]')
            check(not A.query_selector('[data-test=name]'), 'an invite asks for no name of one\'s own: they choose what to call you')
            A.click('[data-test=kind-contact]')
            A.wait_for_selector('[data-test=qr]')
            link = A.get_attribute('[data-test=qr]', 'data-link')
            words = ' '.join(text_in(A, '[data-test=words] li'))
            secrets += [words.encode(), b'Bardia Zelkova']
            check(link.startswith(url + '/index.html#v1.') and len(words.split()) == 6, 'an invite: a link and six words')
            f_ctx, F = device('friend')
            open_app(F, link)
            check(F.evaluate('location.hash') == '', 'the fragment is taken out of the address bar')
            check(not F.query_selector('[data-test=name]') and not F.query_selector('[data-test=call]'), 'pairing asks for no names')
            F.fill('[data-test=code]', words.upper().replace(' ', '  '))
            F.check('[data-test=mail]')  # Ana lets mail wait for her phone
            F.click('[data-test=pair]')
            secrets += [b'Ana Qvistberg', b'Big Brother Pellow']
            wait(F, "window.pchat.state.screen === 'paired'", 60, 'the friend is paired')
            wait(A, "window.pchat.state.screen === 'paired'", 60, 'the owner is paired')
            pics = "Array.from(document.querySelectorAll('[data-test=fingerprint] [data-glyph]')).map(e => e.dataset.glyph)"
            fa, ff = A.evaluate(pics), F.evaluate(pics)
            check(A.evaluate("Array.from(document.querySelectorAll('[data-test=fingerprint] img')).every(i => i.complete && i.naturalWidth > 0)"),
                  'the fingerprint pictures load (shipped with the app, not from a font)')
            check(len(fa) == 4 and fa == ff, 'both show the same four emoji: ' + ''.join(fa))
            # Paired: each names the other, on their own phone; nothing chosen was sent.
            c1 = A.evaluate('window.pchat.state.conv')
            check(A.evaluate(f"window.pchat.session.info('{c1}').introduced") == '' and F.evaluate(f"window.pchat.session.info('{c1}').introduced") == '',
                  'neither side introduced itself by a name')
            A.fill('[data-test=call-them]', 'Ana Qvistberg')
            F.fill('[data-test=call-them]', 'Big Brother Pellow')
            A.click('[data-test=open-chat]')
            F.click('[data-test=open-chat]')
            for page in (A, F):
                page.wait_for_selector('[data-test=chat-name]')
            check(text_in(F, '[data-test=chat-name]') == ['Big Brother Pellow'], 'the friend calls him what she chose')
            check(text_in(A, '[data-test=chat-name]') == ['Ana Qvistberg'], 'and he calls her what he chose')

            # ---- texts both ways, live ----
            wait(A, "window.pchat.session.app.sendLive && (() => { const s = window.pchat.session; const c = s.conversations()[0]; "
                    "return s.info(c).members.length === 2; })()", 20)
            # Let the WebRTC session come up (signals through the relay's room).
            time.sleep(4)
            for i in range(3):
                A.fill('[data-test=message]', f'hello-live-{i}-QX7')
                A.click('[data-test=send]')
            secrets += [b'hello-live-0-QX7', b'hello-live-1-QX7']
            wait(F, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('hello-live-2-QX7'))",
                 60, 'the friend receives')
            F.fill('[data-test=message]', 'reply-from-ana-ZK2')
            F.click('[data-test=send]')
            secrets.append(b'reply-from-ana-ZK2')
            wait(A, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('reply-from-ana-ZK2'))",
                 60, 'the owner receives')
            live_a, live_f = A.evaluate('window.pchat.session.sentLive'), F.evaluate('window.pchat.session.sentLive')
            check(live_a > 0 and live_f > 0, f'messages went live, phone to phone (owner {live_a}, friend {live_f})')
            wait(A, "Array.from(document.querySelectorAll('[data-test=mine] .meta')).some(e => e.textContent.includes('✓✓'))",
                 40, 'delivered ticks')
            A.screenshot(path=str(work / 'chat-owner.png'))
            F.screenshot(path=str(work / 'chat-friend.png'))

            # ---- 2. a tab closed: the mailbox holds it until the friend is back ----
            F.close()
            time.sleep(1)
            A.fill('[data-test=message]', 'while-you-were-away-MB9')
            A.click('[data-test=send]')
            secrets.append(b'while-you-were-away-MB9')
            wait(A, 'window.pchat.session.sentMailbox > 0', 40, 'sent through the mailbox (she lets mail wait)')
            wait(A, "Array.from(document.querySelectorAll('[data-test=mine] .meta')).some(e => e.dataset.status === 'mailbox')",
                 20, 'its status says: in the mailbox')
            F = f_ctx.new_page()
            F.name = 'friend'
            F.errors = []
            F.on('pageerror', lambda e: F.errors.append(str(e)))
            F.on('dialog', lambda d: d.accept())
            open_app(F)
            F.click('[data-test=contact]')
            wait(F, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('while-you-were-away-MB9'))",
                 60, 'delivered from the mailbox on reopening')
            check(text_in(F, '[data-test=chat-name]') == ['Big Brother Pellow'], 'her name for him survives a reload')

            # ---- media: a photo (its EXIF left behind), a file, a sticker, a voice note ----
            from PIL import Image
            import io, hashlib
            img = Image.new('RGB', (640, 480), (230, 90, 40))
            exif = Image.Exif()
            exif[0x010F] = 'SecretCam'           # camera make
            exif[0x0110] = 'SecretModel 9'       # camera model
            photo = work / 'photo.jpg'
            img.save(photo, 'JPEG', exif=exif.tobytes())
            check(b'Exif' in photo.read_bytes() and b'SecretCam' in photo.read_bytes(), 'the test photo carries EXIF')
            A.set_input_files('[data-test=file-media]', str(photo))
            wait(F, "!!document.querySelector('[data-test=picture]')", 60, 'the photo arrives and is shown')
            got = F.evaluate("fetch(document.querySelector('[data-test=picture]').src).then(r => r.arrayBuffer()).then(b => Array.from(new Uint8Array(b)))")
            got = bytes(got)
            check(got[:2] == b'\xff\xd8' and b'Exif' not in got and b'SecretCam' not in got, 'the photo that arrives has no EXIF (redrawn)')
            doc = work / 'notes.bin'
            doc.write_bytes(os.urandom(150000))
            F.set_input_files('[data-test=file-any]', str(doc))
            wait(A, "!!document.querySelector('[data-test=download]')", 60, 'the file arrives')
            got = bytes(A.evaluate("fetch(document.querySelector('[data-test=download]').href).then(r => r.arrayBuffer()).then(b => Array.from(new Uint8Array(b)))"))
            check(hashlib.sha256(got).digest() == hashlib.sha256(doc.read_bytes()).digest(), 'the file is the same, byte for byte')
            A.click('[data-test=attach]')
            A.click('[data-test=pick-sticker]')
            A.click('[data-test="sticker-heart.svg"]')
            wait(F, "!!document.querySelector('[data-test=sticker]')?.src?.includes('stickers/heart.svg')", 30, 'the sticker arrives')
            F.click('[data-test=attach]')
            F.click('[data-test=voice]')
            time.sleep(1.5)
            F.click('[data-test=voice]')
            wait(A, "!!document.querySelector('[data-test=voice]')?.src", 60, 'the voice note arrives and plays')
            # A file while Ana is away, and Bardia gone too: it comes from the relay's pieces.
            F.close()
            time.sleep(1)
            big = work / 'away.bin'
            big.write_bytes(os.urandom(300000))
            A.set_input_files('[data-test=file-any]', str(big))
            wait(A, "Array.from(document.querySelectorAll('[data-test=mine][data-kind]')).length >= 2", 30, 'sent while away')
            # Bardia leaves once the file's message is at the relay (its pieces went first).
            wait(A, "(() => { const m = Array.from(document.querySelectorAll('[data-test=mine][data-kind] .meta')).pop(); "
                    "return m && ['mailbox', 'sent', 'delivered'].includes(m.dataset.status); })()", 60, "the file's message is at the relay")
            time.sleep(1)
            A.close()
            F = f_ctx.new_page()
            F.name = 'friend'
            F.errors = []
            F.on('pageerror', lambda e: F.errors.append(str(e)))
            F.on('console', lambda m: F.errors.append('console ' + m.type + ': ' + m.text) if m.type in ('error', 'warning') else None)
            F.on('dialog', lambda d: d.accept())
            open_app(F)
            F.evaluate("void (window.pchat.ui.warn = (t) => console.warn('WARN ' + t))")
            F.click('[data-test=contact]')
            if not wait(F, "Array.from(document.querySelectorAll('[data-test=download]')).length >= 2", 90, 'the file comes from the relay pieces, its sender gone'):
                print('   friend errors', F.errors[-10:])
                print('   friend opened', F.evaluate("JSON.stringify(window.pchat.session.opened)"), 'fetching', F.evaluate('window.pchat.session.fetching'), 'busy', F.evaluate('window.pchat.session.busy'), 'media busy', F.evaluate('window.pchat.session.media.busy'))
                print('   friend blobs', F.evaluate("window.pchat.store.blobs().then(b => b.map(x => [x.id.slice(0,6), x.count, x.complete]))"))
            got = bytes(F.evaluate("fetch(Array.from(document.querySelectorAll('[data-test=download]')).pop().href).then(r => r.arrayBuffer()).then(b => Array.from(new Uint8Array(b)))"))
            check(hashlib.sha256(got).digest() == hashlib.sha256(big.read_bytes()).digest(), 'and it is the same, byte for byte')
            A = a_ctx.new_page()
            A.name = 'owner'
            A.errors = []
            A.on('pageerror', lambda e: A.errors.append(str(e)))
            A.on('dialog', lambda d: d.accept())
            open_app(A)
            A.click('[data-test=contact]')

            # ---- 3. a wrong code: the owner is told of a possible interception ----
            A.click('[data-test=back]')
            A.click('[data-test=invite]')
            A.click('[data-test=kind-contact]')
            A.wait_for_selector('[data-test=qr]')
            link2 = A.get_attribute('[data-test=qr]', 'data-link')
            e_ctx, E = device('eve')
            open_app(E, link2)
            E.fill('[data-test=code]', 'abandon ability able about above absent')
            E.click('[data-test=pair]')
            wait(A, "document.querySelector('[data-test=error]')?.textContent === 'The six words did not match'", 60,
                 'the owner shows: The six words did not match (the invite is cancelled)')
            check(A.evaluate('window.pchat.session.conversations().length') == 1, 'nothing was paired')
            e_ctx.close()

            # ---- 4. a further device for Ana, endorsed by her first device ----
            A.click('text=OK')
            A.click('[data-test=invite]')
            A.click('[data-test=kind-extra]')
            A.wait_for_selector('[data-test=qr]')
            link3 = A.get_attribute('[data-test=qr]', 'data-link')
            words3 = ' '.join(text_in(A, '[data-test=words] li'))
            g_ctx, G = device('friend2')
            open_app(G, link3)
            G.fill('[data-test=code]', words3)
            G.click('[data-test=pair]')
            if not wait(G, "window.pchat.state.screen === 'paired'", 120, 'the further device is paired after the handoff'):
                c0 = A.evaluate('window.pchat.session.conversations()[0]')
                for page in (A, F):
                    print('  ', page.name, page.evaluate(f"window.pchat.session.app.describe('{c0}')"))
                    print('  ', page.name, 'opened', page.evaluate("JSON.stringify(window.pchat.session.opened.slice(-12))"))
                    print('  ', page.name, 'outbox', page.evaluate("window.pchat.store.outbox().then(o => o.map(x => [x.seq, !!x.waiting, !!x.relayed, x.mailbox]))"))
                print('   live A-F', A.evaluate(f"window.pchat.session.app.liveWith(window.pchat.session.info('{c0}').members.find(m => !m.self).peer)"))
            conv = A.evaluate('window.pchat.session.conversations()[0]')
            wait(A, f"window.pchat.session.info('{conv}').members.length === 3", 30, 'three devices on the owner')
            wait(F, f"window.pchat.session.info('{conv}').members.length === 3", 30, 'three devices on the first friend device')
            check(A.evaluate(f"window.pchat.session.info('{conv}').generation") == 1, 'a new committee generation')
            G.fill('[data-test=call-them]', 'Bro Tablet Name')
            G.click('[data-test=open-chat]')
            A.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{conv}'}})")
            A.fill('[data-test=message]', 'to-both-devices-TB3')
            A.click('[data-test=send]')
            for page in (F, G):
                wait(page, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('to-both-devices-TB3'))",
                     60, page.name + ' receives on both devices')
            secrets += [b'to-both-devices-TB3', b'Bro Tablet Name', words3.encode()]

            # ---- 5. revoke it ----
            g_peer = G.evaluate('window.pchat.session.app.peer()')
            A.click('[data-test=devices]')
            A.click(f'[data-peer="{g_peer}"] [data-test=revoke]')
            wait(G, "!!document.querySelector('[data-test=removed]') || window.pchat.state.alerts.size > 0", 90,
                 'the revoked device shows it was removed')
            if not wait(A, f"window.pchat.session.info('{conv}').members.length === 2", 90, 'two devices again on the owner'):
                for page in (A, F, G):
                    print('  ', page.name, page.evaluate(f"window.pchat.session.app.describe('{conv}')"))
                    print('  ', page.name, 'outbox', page.evaluate("window.pchat.store.outbox().then(o => o.map(x => [x.peer.slice(0,6), x.seq, x.control, !!x.waiting, !!x.relayed, x.mailbox]))"))
            wait(F, f"window.pchat.session.info('{conv}').generation === 2", 90, 'the friend at generation 2')
            G.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{conv}'}})")
            G.wait_for_selector('[data-test=removed]', timeout=60000)
            check('This device was removed. Ask Bro Tablet Name for a new key.' in G.text_content('[data-test=removed]'),
                  'the revoked device says: This device was removed. Ask Bro Tablet Name for a new key.')
            A.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{conv}'}})")
            A.fill('[data-test=message]', 'after-revoke-AR4')
            A.click('[data-test=send]')
            F.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{conv}'}})")
            wait(F, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('after-revoke-AR4'))",
                 60, 'the friend still receives after the revocation')
            time.sleep(6)
            check(not G.evaluate("Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('after-revoke-AR4'))"),
                  'the revoked device does not')
            secrets.append(b'after-revoke-AR4')

            # ---- groups and channels ----
            A.evaluate("window.pchat.ui.screen('contacts')")
            A.click('[data-test=new-group]')
            A.fill('[data-test=group-name]', 'Tapes club GC1')
            A.check('[data-test=pick-contact]')
            A.click('[data-test=make-group]')
            A.wait_for_selector('[data-test=message]')
            A.fill('[data-test=message]', 'group-hello-GH1')
            A.click('[data-test=send]')
            secrets.append(b'group-hello-GH1')
            F.evaluate("window.pchat.ui.screen('contacts')")
            wait(F, "Array.from(document.querySelectorAll('[data-test=contact] .name')).some(e => e.textContent.startsWith('Tapes club GC1'))",
                 60, 'the group reaches Ana')
            gid = F.evaluate("window.pchat.session.conversations().find(id => window.pchat.session.info(id).kind === 1)")
            F.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{gid}'}})")
            wait(F, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('group-hello-GH1'))",
                 60, 'a group message, under the owner\'s sender key')
            F.fill('[data-test=message]', 'group-reply-GR2')
            F.click('[data-test=send]')
            wait(A, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('group-reply-GR2'))",
                 60, 'and a reply, under hers')
            check('Ana Qvistberg' in ' '.join(text_in(A, '.speaker')), 'the reply says who said it')
            secrets.append(b'group-reply-GR2')
            A.evaluate("window.pchat.ui.screen('contacts')")
            A.click('[data-test=new-channel]')
            A.fill('[data-test=group-name]', 'Tape news TN1')
            A.click('[data-test=make-group]')
            A.wait_for_selector('[data-test=devices]')
            A.click('[data-test=devices]')
            A.click('[data-test=invite-readers]')
            A.wait_for_selector('[data-test=qr]')
            link4 = A.get_attribute('[data-test=qr]', 'data-link')
            words4 = ' '.join(text_in(A, '[data-test=words] li'))
            r_ctx, Rd = device('reader')
            open_app(Rd, link4)
            Rd.fill('[data-test=code]', words4)
            Rd.click('[data-test=pair]')
            wait(Rd, "window.pchat.state.screen === 'paired'", 60, 'a reader pairs with the channel')
            Rd.fill('[data-test=call-them]', 'The news')
            Rd.click('[data-test=open-chat]')
            wait(Rd, "!!document.querySelector('[data-test=read-only]') && !document.querySelector('[data-test=message]')", 20,
                 'a reader has no composer: only the publisher posts')
            chid = A.evaluate("window.pchat.session.conversations().find(id => window.pchat.session.info(id).kind === 2)")
            A.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{chid}'}})")
            A.fill('[data-test=message]', 'news-one-NW1')
            A.click('[data-test=send]')
            secrets.append(b'news-one-NW1')
            wait(Rd, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('news-one-NW1'))",
                 60, 'the reader reads the post, checked against the publisher')
            r_ctx.close()

            def open_chat(page, cid):
                page.evaluate(f"window.pchat.ui.screen('chat', {{conv: '{cid}'}})")
                wait(page, f"document.querySelector('[data-test=chat-name]')?.textContent === window.pchat.session.info('{cid}').name", 20,
                     page.name + ' shows the chat')

            # ---- disappearing messages: gone from both phones when their time is over ----
            A.evaluate(f"window.pchat.session.setOptions('{conv}', false, 20)")
            wait(F, f"window.pchat.session.info('{conv}').disappear === 20", 60, 'the friend takes up the disappearing option')
            open_chat(A, conv)
            A.fill('[data-test=message]', 'gone-soon-DS1')
            A.click('[data-test=send]')
            ds_seq = None
            for _ in range(50):
                ds_seq = A.evaluate(f"window.pchat.store.messages('{conv}').then(ms => ms.find(m => m.mine && new TextDecoder().decode(m.body) === 'gone-soon-DS1')?.seq ?? null)")
                if ds_seq is not None:
                    break
                time.sleep(0.2)
            open_chat(F, conv)
            if not wait(F, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('gone-soon-DS1'))",
                        60, 'a disappearing message arrives'):
                tail = f"window.pchat.store.messages('{conv}').then(ms => JSON.stringify(ms.slice(-4).map(m => [m.type, m.mine, new TextDecoder().decode(m.body).slice(0, 16), m.time, m.expires, !!m.expired])))"
                for page in (A, F):
                    print('  ', page.name, page.evaluate(tail), page.evaluate(f"window.pchat.session.app.describe('{conv}')"), 'now', page.evaluate('Date.now()'))
                    print('  ', page.name, 'screen', page.evaluate('window.pchat.state.screen'), 'warned', page.evaluate("document.querySelector('.toast')?.textContent || ''"))
            for page in (A, F):
                wait(page, "!Array.from(document.querySelectorAll('.msg')).some(e => e.textContent.includes('gone-soon-DS1'))", 60,
                     page.name + ': it is gone from the screen')
                gone = page.evaluate(f"window.pchat.store.messages('{conv}').then(ms => ms.filter(m => new TextDecoder().decode(m.body).includes('gone-soon-DS1') || (m.expired && m.key)).length)")
                check(gone == 0, page.name + ': its words and its key are gone from storage')
            check(ds_seq is not None and A.evaluate(f"window.pchat.store.outbox().then(o => o.filter(x => x.conv === '{conv}' && x.seq === {ds_seq or -1}).length)") == 0,
                  'nothing of it waits in the outbox')
            check(A.evaluate(f"window.pchat.store.messages('{conv}').then(ms => ms.some(m => new TextDecoder().decode(m.body) === 'after-revoke-AR4'))"),
                  'what was said before messages disappeared stays')
            A.evaluate(f"window.pchat.session.setOptions('{conv}', false, 0)")
            wait(F, f"window.pchat.session.info('{conv}').disappear === 0", 60, 'and back to keeping messages')

            # ---- notifications: the sender makes the push; only the chosen symbol shows ----
            pushed = push_service()
            ua, ua_pub, ua_auth = push_keys()
            f_ctx.grant_permissions(['notifications'], origin=url)
            open_chat(F, conv)
            F.click('[data-test=devices]')
            F.click('[data-test=signal][data-symbol="🐬"]')
            wait(F, "document.querySelector('[data-test=signal][data-symbol=\"🐬\"]')?.getAttribute('aria-checked') === 'true'", 10,
                 'the friend picks a symbol for this chat')
            F.evaluate(f"window.pchat.session.enablePush({{endpoint: '{pushed.endpoint}', p256dh: new Uint8Array({list(ua_pub)}), "
                       f"auth: new Uint8Array({list(ua_auth)})}})")
            f_peer = F.evaluate('window.pchat.session.app.peer()')
            wait(A, f"window.pchat.store.pushTo('{f_peer}').then(x => !!x)", 60, 'the owner learns, in a signed message, how to wake the friend')
            F.close()  # the friend's tab is gone: what follows cannot go live
            open_chat(A, conv)
            A.fill('[data-test=message]', 'wake-up-WU1')
            A.click('[data-test=send]')
            secrets.append(b'wake-up-WU1')
            got = pushed.wait(90)
            check(got is not None, 'a push reaches the friend\'s push service (made by the owner\'s phone, carried by the relay)')
            if got:
                headers, body = got
                plain, vapid_ok, audience = open_push(ua, ua_pub, ua_auth, headers, body)
                check(vapid_ok and audience == pushed.origin, 'its VAPID token holds, for the push service\'s origin')
                check(re.fullmatch(rf'p6\.[0-9a-f]{{32}}\.{conv}', plain or '') is not None,
                      'what it says, sealed to the friend: a ping id and the conversation - no sender, no words: ' + repr(plain))
                check(b'wake-up' not in body, 'the push service sees no words')
            # The friend's phone, woken by its push service: what shows is the symbol.
            F = f_ctx.new_page()
            F.on('dialog', lambda d: d.accept())
            F.name, F.errors = 'friend', []
            F.on('pageerror', lambda e: F.errors.append(str(e)))
            open_app(F)
            if got:
                # Delivered as the push service would, through the browser's
                # push path: the worker takes it (its ping is recorded).
                ping = plain.split('.')[1] if plain else ''
                pinged = deliver_push(f_ctx, F, url, plain)
                check(any(u.endswith('/ping/' + ping) for u in pinged), 'the friend\'s service worker is woken by the push')
                # Headless Chrome does not always keep a notification shown from a
                # push event the DevTools protocol dispatched (a bare worker does
                # the same): what shows is checked through the worker's handler.
                sw = f_ctx.service_workers[0] if f_ctx.service_workers else None
                notes = "self.registration.getNotifications().then(ns => ns.map(n => [n.title, n.body, n.timestamp]))"
                if sw:
                    for _ in range(30):  # the push's own showing, if this Chrome keeps it, lands a moment after its ping
                        before = sw.evaluate(notes)
                        if before:
                            break
                        time.sleep(0.1)
                    check(before in ([], [['p-chat', '🐬', before[0][2] if before else 0]]),
                          'what the push showed, if this Chrome kept it, is the symbol alone: ' + repr(before))
                    time.sleep(0.05)
                    sw.evaluate(f"woken('{plain}')")
                    check(sw.evaluate(notes) == before, 'the same ping is not shown twice')
                    sw.evaluate(f"woken('p6.' + '5'.repeat(32) + '.{conv}')")
                    shown = [n[:2] for n in sw.evaluate(notes)]
                    check(shown == [['p-chat', '🐬']], 'a notification shows only the symbol chosen for the chat: ' + repr(shown))
                    sw.evaluate("woken('p6.' + '6'.repeat(32) + '.' + 'ab'.repeat(16))")
                    check(['p-chat', '•'] in [n[:2] for n in sw.evaluate(notes)], 'a chat without a symbol shows a dot')
                else:
                    check(False, 'the friend has a service worker')
                wait(F, f"window.pchat.store.messages('{conv}').then(ms => ms.some(m => new TextDecoder().decode(m.body) === 'wake-up-WU1'))", 90,
                     'and the message itself arrives once the phone is open')
            pushed.close()

            # ---- a call: camera and microphone (the browser's fake ones), each frame checked before it plays ----
            open_chat(A, conv)
            open_chat(F, conv)
            A.click('[data-test=call]')
            wait(A, "window.pchat.state.screen === 'call'", 30, 'the caller is in the call')
            wait(F, "!!document.querySelector('[data-test=answer]')", 60, 'the friend\'s phone rings')
            F.click('[data-test=answer]')
            wait(F, "window.pchat.state.screen === 'call'", 30, 'the friend answers')
            stats = "window.pchat.session.calls.stats()"
            if not wait(F, f"{stats}.drawn > 30", 90, 'the friend sees the caller: frames decoded after their roots named them'):
                print('   caller', A.evaluate(stats), 'friend', F.evaluate(stats))
            wait(A, f"{stats}.drawn > 30", 60, 'and the caller sees the friend')
            sa, sf = A.evaluate(stats), F.evaluate(stats)
            print(f"   call latency, capture to played (verified): caller p50 {sa['p50']} ms p95 {sa['p95']} ms; friend p50 {sf['p50']} ms p95 {sf['p95']} ms; "
                  f"roots {sa['roots']}/{sf['roots']}, played {sa['played']}/{sf['played']}")
            check(sa['refused'] == 0 and sf['refused'] == 0, 'nothing refused on a clean link')
            check(0 < sf['p95'] < 1500, f"played within 1.5 s of capture (p95 {sf['p95']} ms)")
            check(A.evaluate("document.querySelectorAll('[data-test=tile] canvas').length") == 1, 'one tile: the other side')
            A.screenshot(path=str(work / 'call-caller.png'))
            F.screenshot(path=str(work / 'call-friend.png'))
            A.click('[data-test=hang]')
            wait(A, "window.pchat.state.screen === 'chat'", 30, 'hung up')
            wait(F, "window.pchat.state.screen === 'chat' && !window.pchat.session.calls.id", 60, 'the call ends for the friend too')

            # ---- going live in the group: a swarm of its viewers, the roster sealed, frames checked ----
            open_chat(A, gid)
            open_chat(F, gid)
            A.click('[data-test=go-live]')
            wait(A, "window.pchat.state.screen === 'call'", 30, 'the owner is live')
            wait(F, "!!document.querySelector('[data-test=answer]')", 60, 'the friend sees it is live')
            F.click('[data-test=answer]')
            wait(F, "window.pchat.state.screen === 'call'", 30, 'the friend watches')
            if not wait(F, f"{stats}.drawn > 10", 90, 'the viewer sees the stream: pieces of 250 ms, named by a root a second'):
                print('   streamer', A.evaluate(stats), A.evaluate("JSON.stringify(window.pchat.session.app.calls())"))
                print('   viewer', F.evaluate(stats), F.evaluate("JSON.stringify(window.pchat.session.app.calls())"))
            sf = F.evaluate(stats)
            print(f"   stream latency, capture to played (verified): p50 {sf['p50']} ms p95 {sf['p95']} ms, refused {sf['refused']}")
            check(sf['refused'] == 0 and 0 < sf['p95'] < 4000, 'the stream plays within 4 s of capture, nothing refused')
            check(F.evaluate("window.pchat.session.app.calls()[0].generation") >= 1, 'the viewer took the sealed roster and its key')
            check(not F.query_selector('[data-test=mute]'), 'a viewer has no camera or microphone open')
            A.click('[data-test=hang]')
            wait(F, "window.pchat.state.screen === 'chat' && !window.pchat.session.calls.id", 60, 'the stream ends for the viewer too')

            # ---- speakers through a tree (simulcast): small pictures for all, the full one when asked ----
            A.evaluate(f"window.pchat.session.calls.start('{gid}', false, 2).then(() => window.pchat.ui.screen('call', {{conv: '{gid}'}}))")
            wait(A, "window.pchat.state.screen === 'call'", 30, 'a call through a tree')
            wait(F, "!!document.querySelector('[data-test=answer]')", 60, 'it rings')
            F.click('[data-test=answer]')
            wait(F, "window.pchat.session.calls.layers[1] > 10", 60, 'the small picture comes to everyone')
            check(not F.evaluate("window.pchat.session.calls.layers[0]"), 'and no full picture before one is asked for')
            F.click('[data-test=tile]')
            wait(F, "window.pchat.session.calls.layers[0] > 10", 60, 'asked for, the full picture comes too')
            check(F.evaluate(f"{stats}.refused") == 0, 'nothing refused in the tree')
            A.click('[data-test=hang]')
            wait(F, "window.pchat.state.screen === 'chat' && !window.pchat.session.calls.id", 60, 'the tree call ends for both')

            # ---- tape tennis: asked and played; the same court on both ----
            open_chat(A, conv)
            open_chat(F, conv)
            A.click('[data-test=attach]')
            A.click('[data-test=play]')
            wait(F, "!!document.querySelector('[data-test=play-accept]')", 60, 'the friend is asked to play')
            F.click('[data-test=play-accept]')
            wait(A, "window.pchat.state.screen === 'game'", 30, 'the game begins for the one who asked')
            wait(F, "window.pchat.state.screen === 'game'", 30, 'and for the friend')
            A.dispatch_event('[data-test=up]', 'pointerdown')
            if not wait(F, "(window.pchat.session.app.games()[0]?.epoch || 0) > 40", 60, 'the court moves on agreed steps'):
                print('   games', A.evaluate("JSON.stringify(window.pchat.session.app.games())"), F.evaluate("JSON.stringify(window.pchat.session.app.games())"))
            wait(A, "(window.pchat.session.app.games()[0]?.epoch || 0) > 40", 30, 'on both phones')
            A.dispatch_event('[data-test=up]', 'pointerup')
            ga, gf = A.evaluate("window.pchat.session.app.games()[0]"), F.evaluate("window.pchat.session.app.games()[0]")
            print(f"   tape tennis: steps {ga['epoch']}/{gf['epoch']}, score {ga['left']}-{ga['right']} / {gf['left']}-{gf['right']}, prediction ahead {ga['lead']}/{gf['lead']}")
            check(ga['lead'] <= 24 and gf['lead'] <= 24, 'the picture runs ahead of what is agreed, within its bound (court_lead, 24 frames)')
            A.screenshot(path=str(work / 'game.png'))
            A.click('[data-test=stop-game]')
            wait(F, "window.pchat.state.screen === 'chat'", 30, 'stopped: back to the chat for both')
            # After a game, the chat open on both: what each says appears on the other's screen there and then.
            wait(A, "window.pchat.state.screen === 'chat'", 30, 'the one who stopped is back in the chat')
            F.evaluate(f"window.pchat.session.send('{conv}', 'after-game-AG1')")
            wait(A, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('after-game-AG1'))", 30,
                 'after the game, a message shows in the open chat, without leaving it')
            A.evaluate(f"window.pchat.session.send('{conv}', 'after-game-AG2')")
            wait(F, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('after-game-AG2'))", 30,
                 'and the other way')

            # ---- the whiteboard: a stroke drawn reaches the other; one leads where both look ----
            for page in (A, F):
                if not wait(page, "!!document.querySelector('[data-test=attach]')", 20, page.name + ' has its composer'):
                    print('  ', page.name, page.evaluate("JSON.stringify({screen: window.pchat.state.screen, conv: window.pchat.state.conv, len: history.length, st: history.state, html: document.getElementById('app').className})"))
                page.click('[data-test=attach]')
                page.click('[data-test=board]')
            wait(A, "window.pchat.state.screen === 'board'", 20, 'the board opens')
            box = A.locator('[data-test=sheet]').bounding_box()
            A.mouse.move(box['x'] + box['width'] * 0.3, box['y'] + box['height'] * 0.3)
            A.mouse.down()
            for k in range(1, 12):
                A.mouse.move(box['x'] + box['width'] * (0.3 + 0.04 * k), box['y'] + box['height'] * (0.3 + 0.02 * k), steps=2)
                A.wait_for_timeout(20)
            A.mouse.up()
            wait(F, f"window.pchat.session.app.board('{conv}').strokes >= 1", 60, 'the stroke reaches the other board')
            wait(F, f"window.pchat.store.messages('{conv}').then(ms => ms.some(m => m.type === 'stroke' && m.body.length > 5))", 30,
                 'kept as a signed message on the other phone')
            A.click('[data-test=follow]')
            A.click('[data-test=zoom-in]')
            A.click('[data-test=zoom-in]')
            wait(F, f"Math.abs(window.pchat.session.app.board('{conv}').zoom - 1.5625) < 0.01 && window.pchat.session.app.board('{conv}').leader !== ''", 30,
                 'following: the other view is brought to the leader\'s (Reconcile over where each looks)')
            F.screenshot(path=str(work / 'board-follower.png'))
            A.click('[data-test=back]')
            F.click('[data-test=back]')

            # ---- an update from a peer: release 2, from the owner's phone over the live link ----
            site2 = work / 'site2'
            subprocess.run(rel + ['build', '--version', '2', '--chain', str(site / 'chain.json'), '--key', str(keys[0]), '--key', str(keys[2]),
                                  '--wasm', str(wasm), '--out', str(site2), '--config', str(config)], check=True, capture_output=True)
            import base64
            given = {'chain': json.loads((site2 / 'chain.json').read_text()),
                     'manifest': base64.b64encode((site2 / 'manifest.json').read_bytes()).decode(),
                     'files': {p.relative_to(site2).as_posix(): base64.b64encode(p.read_bytes()).decode()
                               for p in site2.rglob('*') if p.is_file() and p.name not in ('manifest.json', 'chain.json')}}
            # The owner's phone is given release 2 (as another of its peers would give it): its worker checks it all.
            got = A.evaluate('''async (g) => {
                const b = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
                return window.pchat.session.worker({ type: 'install', chain: g.chain, manifest: b(g.manifest), files: Object.entries(g.files).map(([p, s]) => [p, b(s)]) });
            }''', given)
            check(got and got.get('type') == 'installed' and got.get('version') == 2, 'release 2, given whole, is checked and waits: ' + repr(got))
            A.reload()
            wait(A, "window.pchat && window.pchat.state.screen !== 'loading'", 60, 'reopened')
            wait(A, "window.pchat.session.releaseStatus().then(s => s && s.version === 2)", 30, 'the owner\'s phone runs release 2 from the next open')
            # It says so to its contacts; the friend's phone takes release 2 from it, file by file over the live link.
            open_chat(F, conv)
            if not wait(F, "!!document.querySelector('[data-test=update-ready]')", 120, 'the friend\'s phone has release 2 from the owner\'s, checked: Update ready'):
                print('   friend release', F.evaluate("window.pchat.session.releaseStatus().then(s => JSON.stringify({v: s && s.version, p: s && s.pending, e: s && s.evidence}))"))
                print('   friend fetching', F.evaluate("JSON.stringify(window.pchat.session.fetchingRelease ? {asked: window.pchat.session.fetchingRelease.asked, files: window.pchat.session.fetchingRelease.files.size, want: window.pchat.session.fetchingRelease.want.length} : null)"))
                print('   friend heard', F.evaluate(f"window.pchat.store.messages('{conv}').then(ms => JSON.stringify(ms.filter(m => m.type === 'release').map(m => [m.mine, m.seq])))"))
                print('   owner said', A.evaluate(f"window.pchat.store.messages('{conv}').then(ms => JSON.stringify(ms.filter(m => m.type === 'release').map(m => [m.mine, m.seq])))"),
                      A.evaluate(f"JSON.stringify(window.pchat.session.conv.get('{conv}'))"), A.evaluate("JSON.stringify(window.pchat.session.release && window.pchat.session.release.version)"))
            F.click('[data-test=restart]')
            wait(F, "window.pchat && window.pchat.state.screen !== 'loading'", 60, 'the friend reopens')
            wait(F, "window.pchat.session.releaseStatus().then(s => s && s.version === 2)", 30, 'and runs release 2')
            running_site = site2  # what runs now (the host still serves release 1)

            # ---- recovery: Ana's phone is lost; Bardia brings in her new one ----
            f_peer = F.evaluate('window.pchat.session.app.peer()')
            def replace_invite(wait_ms):
                A.evaluate(f"window.pchat.session.app.setRecoveryWait({wait_ms})")
                A.evaluate(f"window.pchat.ui.screen('devices', {{conv: '{conv}'}})")
                A.click(f'[data-peer="{f_peer}"] [data-test=replace]')
                A.select_option('[data-test=scope]', '2')
                A.click('[data-test=make-replace]')
                A.wait_for_selector('[data-test=qr]')
                return A.get_attribute('[data-test=qr]', 'data-link'), ' '.join(text_in(A, '[data-test=words] li'))
            def new_phone(name, link, words):
                ctx, page = device(name)
                page.on('console', lambda m: print('  [' + name + ']', m.type, m.text[:300]) if m.type in ('error', 'warning') else None)
                open_app(page, link)
                page.fill('[data-test=code]', words)
                page.click('[data-test=pair]')
                wait(page, "!!document.querySelector('[data-test=own-fingerprint]')", 60, name + ' shows its own four pictures')
                return ctx, page
            # First the old phone is still there, and refuses.
            link5, words5 = replace_invite(600000)
            n1_ctx, N1 = new_phone('new-refused', link5, words5)
            open_chat(F, conv)
            F.wait_for_selector('[data-test=refuse-recovery]', timeout=60000)
            F.click('[data-test=refuse-recovery]')
            wait(A, f"window.pchat.session.info('{conv}').recovering === ''", 60, 'the old phone refused: nothing changes')
            check(A.evaluate(f"window.pchat.session.info('{conv}').generation") == 2, 'the committee is as it was')
            n1_ctx.close()
            # Then it is lost for real.
            f_ctx.close()
            link6, words6 = replace_invite(3000)
            n_ctx, N = new_phone('new-phone', link6, words6)
            secrets += [words5.encode(), words6.encode()]
            open_chat(A, conv)
            wait(A, "!!document.querySelector('[data-test=recovery-mine]')", 30, 'the owner shows the recovery under way')
            wait(N, "window.pchat.state.screen === 'paired'", 90, 'the new phone takes the lost one\'s place after the wait')
            n_peer = N.evaluate('window.pchat.session.app.peer()')
            wait(A, f"window.pchat.session.info('{conv}').members.some(m => m.peer === '{n_peer}') && !window.pchat.session.info('{conv}').members.some(m => m.peer === '{f_peer}')",
                 30, 'the owner has the new phone in place of the lost one')
            check(A.evaluate(f"window.pchat.session.info('{conv}').generation") == 3, 'a new generation')
            N.click('[data-test=open-chat]')
            if not wait(N, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('after-revoke-AR4'))",
                        90, 'the new phone is given the history, checked against the agreed chain'):
                for page in (A, N):
                    print('  ', page.name, page.evaluate(f"window.pchat.session.app.describe('{conv}')"))
                    print('  ', page.name, 'opened', page.evaluate("JSON.stringify(window.pchat.session.opened.slice(-12))"))
                    print('  ', page.name, 'outbox', page.evaluate("window.pchat.store.outbox().then(o => o.map(x => [x.peer.slice(0,6), x.seq, x.control, !!x.waiting, !!x.relayed, x.mailbox]))"))
                    print('  ', page.name, 'stored', page.evaluate(f"window.pchat.store.messages('{conv}').then(m => m.length)"), 'history', page.evaluate('window.pchat.session.historyCount'))
                print('   live A-N', A.evaluate(f"window.pchat.session.app.liveWith('{n_peer}')"), 'shared', A.evaluate('window.pchat.session.shared'),
                      'n', n_peer[:6], 'f', f_peer[:6])
                print('   new-phone opened all', N.evaluate("JSON.stringify(window.pchat.session.opened)"))
            check(not N.evaluate("Array.from(document.querySelectorAll('.msg')).some(e => e.textContent.includes('gone-soon-DS1'))"),
                  'what disappeared is not given')
            A.fill('[data-test=message]', 'after-recovery-RC1')
            A.click('[data-test=send]')
            wait(N, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('after-recovery-RC1'))",
                 60, 'and talks with the owner')
            secrets.append(b'after-recovery-RC1')
            for page in (F, N1, N):
                check(not page.errors, page.name + ' had no page errors: ' + '; '.join(page.errors))
            n_ctx.close()

            # ---- the server, out of sight: no address to type to invite; one's own under Advanced ----
            A.evaluate("window.pchat.ui.screen('invite', {invite: null})")
            A.wait_for_selector('[data-test=kind-contact]')
            check(A.evaluate("!document.querySelector('[data-test=relay], [data-test=server]') && !/wss?:\\/\\//.test(document.body.innerText)"),
                  'an invite asks for no server address')
            A.evaluate("window.pchat.ui.screen('about')")
            A.wait_for_selector('[data-test=settings]')
            check(len(A.query_selector_all('[data-test=about-part]')) == 4 and len(A.query_selector_all('main img.g')) == 4
                  and 'cannot open them' in A.inner_text('main') and 'server' not in A.inner_text('main').lower(),
                  'About: four short sections, one picture each; the relay only passes on what it cannot open')
            A.click('[data-test=settings]')
            A.click('[data-test=advanced] summary')
            A.fill('[data-test=server]', 'relay.example.org')
            A.click('[data-test=save-server]')
            wait(A, "document.querySelector('[data-test=server-state]').textContent.startsWith('A relay address starts with wss://')", 10, 'an address that is not one is refused, in words')
            A.fill('[data-test=server]', 'ws://127.0.0.1:9')
            A.click('[data-test=save-server]')
            wait(A, "document.querySelector('[data-test=server-state]').textContent.startsWith('Can\\'t reach it')", 15, 'a server that does not answer is not kept')
            check(A.evaluate("window.pchat.store.profile().then(p => p.relay || '')") == '', 'and the one this p-chat came with stays')
            A.fill('[data-test=server]', f'ws://localhost:{port}')
            A.click('[data-test=save-server]')
            wait(A, "document.querySelector('[data-test=server-state]').textContent === 'Connected. New invites use it.'", 15, 'one that answers is kept')
            made = A.evaluate("window.pchat.session.invite(1, '', 'Owner').then(i => window.pchat.session.chat.parseInvite(i.link.split('#')[1]).relay)")
            check(made == f'ws://localhost:{port}', 'a new invite names it: ' + repr(made))
            A.fill('[data-test=server]', '')
            A.click('[data-test=save-server]')
            wait(A, "document.querySelector('[data-test=server-state]').textContent.startsWith('New invites use the relay this p-chat came with')", 10, 'emptied: the one it came with again')

            # ---- a bot: the native echo bot pairs like a contact and answers ----
            A.evaluate("window.pchat.ui.screen('contacts')")
            A.click('[data-test=invite]')
            A.click('[data-test=kind-contact]')
            A.wait_for_selector('[data-test=qr]')
            link7 = A.get_attribute('[data-test=qr]', 'data-link')
            words7 = ' '.join(text_in(A, '[data-test=words] li'))
            before = set(A.evaluate('window.pchat.session.conversations()'))
            bot = subprocess.Popen([args.echo, str(work / 'echo'), f'ws://127.0.0.1:{port}', '--pair', link7, words7],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env={**os.environ, 'SGCHAT_ECHO_TRACE': '1'}) if args.echo and os.path.exists(args.echo) else None
            check(bot is not None, 'the echo bot is built: ' + str(args.echo))
            if bot:
                check(bot.stdout.readline().strip() == 'PAIRED ok', 'the bot pairs with the six words')
                wait(A, "window.pchat.state.screen === 'paired'", 60, 'the owner shows the bot paired')
                echo_conv = next(iter(set(A.evaluate('window.pchat.session.conversations()')) - before), None)
                check(echo_conv and A.evaluate(f"window.pchat.session.info('{echo_conv}').name") == 'Echo', 'it calls itself Echo')
                A.click('[data-test=open-chat]')
                # A bot has no live link: its answers wait in the mailbox.
                A.click('[data-test=devices]')
                # Pressed, and the chat opened before what it does is done: the
                # devices screen is not drawn again over the chat (it was, and
                # what was being typed went with it). The button, kept, is
                # pressed once the chat is open and something typed.
                A.evaluate("window.__late = document.querySelector('[data-test=delivery-mailbox]')")
                open_chat(A, echo_conv)
                A.fill('[data-test=message]', 'hello-echo-HE1')
                A.evaluate("window.__late.click()")
                wait(A, f"window.pchat.session.info('{echo_conv}').mailbox === true", 20, 'mailbox too, for the bot')
                time.sleep(1)
                check(A.evaluate("document.querySelector('[data-test=message]')?.value") == 'hello-echo-HE1',
                      'a screen drawn late is not drawn over the one opened since: what was typed stays')
                A.click('[data-test=send]')
                if not wait(A, "Array.from(document.querySelectorAll('[data-test=theirs]')).some(e => e.textContent.includes('echo: hello-echo-HE1'))",
                            90, 'the bot answers in the chat'):
                    print('   echo conv', A.evaluate(f"JSON.stringify(window.pchat.session.info('{echo_conv}'))")[:600])
                    print('   echo said', A.evaluate(f"window.pchat.store.messages('{echo_conv}').then(ms => JSON.stringify(ms.map(m => [m.type, m.mine, m.seq, m.status])))"))
                    bot.terminate()
                    print('   bot', bot.communicate(timeout=10))
                    bot = None
                if bot:
                    bot.terminate()
                    bot.wait(10)
                secrets.append(b'hello-echo-HE1')

            # ---- 6. cleared storage: device not recognized ----
            # (a) the keys are gone but the records are not
            G.evaluate("new Promise(r => { const o = indexedDB.open('p-chat'); o.onsuccess = () => { "
                       "const t = o.result.transaction('keys', 'readwrite'); t.objectStore('keys').clear(); t.oncomplete = r; }; })")
            open_app(G)
            check(G.evaluate("window.pchat.state.screen") == 'unrecognized' and
                  'lost its key' in G.text_content('[data-test=unrecognized]'), 'keys gone: this phone lost its key, said plainly')
            G.click('[data-test=start-again]')
            wait(G, "window.pchat && window.pchat.state.screen === 'contacts' && window.pchat.session.conversations().length === 0", 60,
                 'Start again: a fresh phone, ready to pair')
            # (b) everything cleared, the old link opened again: the invite is used
            g_ctx.close()
            h_ctx, H = device('cleared')
            open_app(H, link3)
            H.fill('[data-test=code]', words3)
            H.click('[data-test=pair]')
            wait(H, "window.pchat.state.screen === 'error' && document.querySelector('[data-test=error]').textContent.startsWith('This invite was already used')",
                 60, 'storage cleared, old link: This invite was already used.')
            h_ctx.close()

            # ---- 7. the signed service worker keeps a signed bundle ----
            sw = A.evaluate("navigator.serviceWorker.controller ? 'controlled' : 'not'")
            if sw != 'controlled':
                A.reload()
                wait(A, 'window.pchat && !!navigator.serviceWorker.controller', 30, 'the service worker controls the page')
            index = site / 'index.html'
            original = index.read_text()
            index.write_text(original.replace('<title>p-chat</title>', '<title>p-chat TAMPERED</title>'))
            A.reload()
            wait(A, "window.pchat", 30)
            check(A.title() == 'p-chat', 'an unsigned change to the site is not served (the signed bundle is)')
            index.write_text(original)
            wait(A, "window.pchat.state.screen !== 'loading'", 30, 'the page has started')  # else its start draws over About
            fp = subprocess.run(rel + ['fingerprint', '--site', str(running_site)], capture_output=True, text=True).stdout.split('fingerprint ')[1].strip()
            A.evaluate("window.pchat.ui.screen('about')")
            wait(A, f"document.querySelector('[data-test=bundle]')?.textContent === '{fp}'", 30, 'About shows the bundle fingerprint: ' + fp)

            for page in (A, F):
                check(not page.errors, page.name + ' had no page errors: ' + '; '.join(page.errors))
            browser.close()

        # ---- 8. nothing readable in the relay's memory ----
        envelope_sample = None
        check(relay.poll() is None, 'the relay is still running')
        found = scan_memory(relay.pid, secrets)
        check(not found, 'no plaintext, name or code in the relay process memory' + (': found ' + repr(found) if found else ''))
        # The scan sees what is there: a frame sent now is found.
        import asyncio
        from websockets.asyncio.client import connect

        async def put_marker():
            async with connect(f'ws://127.0.0.1:{port}') as ws:
                env = bytes([2]) + b'\x07' * 32 + b'CONTROL-MARKER-' * 70 + b'X' * (1024 + 72 - 15 * 70)
                await ws.send(bytes([1, 1, 0, 0, 0, 1]) + env)
                await ws.recv()
        asyncio.run(put_marker())
        check(b'CONTROL-MARKER-' in scan_memory(relay.pid, [b'CONTROL-MARKER-']), 'the scan finds what the relay does hold')
        del envelope_sample
    finally:
        server.shutdown()
        relay.terminate()
        relay.communicate(timeout=10)
        print('pictures and the throwaway release in', work)
    print(f'p-chat e2e: {len(FAILS)} failed' if FAILS else 'p-chat e2e: ok')
    return 1 if FAILS else 0
