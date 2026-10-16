"""Phase 2: the relay, run as its own process and spoken to over WebSockets.

Token burn, reusable token cancel, TTL expiry, quotas, room isolation,
malformed-frame refusal, backpressure, Web Push, and that it says nothing.

    python tests/test_relay.py                      relay/relay.py
    python tests/test_relay.py --worker relay/worker   the Cloudflare Worker, under `wrangler dev`
                                                    (no backpressure or relay-held VAPID there: skipped)
"""
import asyncio
import base64
import hashlib
import http.server
import json
import os
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from websockets.asyncio.client import connect

RELAY = Path(__file__).resolve().parents[1] / 'relay' / 'relay.py'
OK, REFUSED, BURNED, BUSY, QUOTA, NOT_FOUND = 0, 1, 2, 3, 4, 5
FAILS = []


def check(cond, what):
    if not cond:
        FAILS.append(what)
        print('FAIL', what, flush=True)


WORKER = None  # the Cloudflare Worker's folder, when it is the one tested


class Dev:
    """`wrangler dev` with a store of its own: started as relay.py would be, its flags as vars."""

    VARS = {'--ttl': 'TTL', '--mailbox-blobs': 'MAILBOX_BLOBS', '--mailbox-bytes': 'MAILBOX_BYTES', '--total-bytes': 'TOTAL_BYTES'}

    def __init__(self, extra):
        import socket
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]
        self.store = tempfile.mkdtemp(prefix='relay-worker-')
        cmd = [os.path.expanduser('~/.local/bin/wrangler'), 'dev', '--local', '--ip', '127.0.0.1', '--port', str(self.port),
               '--persist-to', self.store, '--log-level', 'error']
        args = list(extra)
        while args:
            flag = args.pop(0)
            if flag == '--push-local':
                cmd += ['--var', 'PUSH_LOCAL:1']
            elif flag in self.VARS:
                cmd += ['--var', f'{self.VARS[flag]}:{args.pop(0)}']
            else:
                raise SystemExit('not for the worker: ' + flag)
        self.p = subprocess.Popen(cmd, cwd=WORKER, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        import urllib.request
        for _ in range(240):
            try:
                urllib.request.urlopen(f'http://127.0.0.1:{self.port}/', timeout=1).read()
                return
            except Exception:
                time.sleep(0.25)
        raise SystemExit('wrangler dev did not start')

    def terminate(self):
        import signal
        os.killpg(self.p.pid, signal.SIGTERM)

    def communicate(self, timeout=None):
        self.p.wait(timeout)
        return '', ''


def start(*extra):
    if WORKER:
        d = Dev(extra)
        return d, d.port, f'READY {d.port}'
    p = subprocess.Popen([sys.executable, str(RELAY), '--port', '0', *extra],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = p.stdout.readline()
    assert line.startswith('READY '), (line, p.stderr.read())
    return p, int(line.split()[1]), line


class Client:
    def __init__(self, ws):
        self.ws, self.rid, self.pushed = ws, 0, []

    async def call(self, op, body=b''):
        self.rid += 1
        await self.ws.send(bytes([1, op]) + struct.pack('>I', self.rid) + body)
        while True:
            data = await self.ws.recv()
            if data[1] == 0x40:
                self.pushed.append(data)
                continue
            assert data[1] == op | 0x80 and struct.unpack('>I', data[2:6])[0] == self.rid, data[:8]
            return data[6], data[7:]

    async def raw(self, frame):
        await self.ws.send(frame)
        return await self.ws.recv()


def envelope(mailbox, fill, version=2, bucket=1024):
    return bytes([version]) + mailbox + bytes([fill]) * (72 + bucket)


def fetched(body):
    n = struct.unpack('>H', body[:2])[0]
    at, out = 2, []
    for _ in range(n):
        mid, handle = body[at:at + 32], body[at + 32:at + 48]
        size = struct.unpack('>I', body[at + 48:at + 52])[0]
        out.append((mid, handle, body[at + 52:at + 52 + size]))
        at += 52 + size
    assert at == len(body)
    return out


async def main_checks(port):
    url = f'ws://127.0.0.1:{port}'
    async with connect(url, max_size=None) as a_ws, connect(url, max_size=None) as b_ws, \
            connect(url, max_size=None) as c_ws:
        a, b, c = Client(a_ws), Client(b_ws), Client(c_ws)
        m1, m2 = b'\x01' * 32, b'\x02' * 32

        # Mailbox: put, fetch, the same envelope twice is one, delete.
        e1 = envelope(m1, 7)
        check(await a.call(1, e1) == (OK, b''), 'put')
        check(await a.call(1, e1) == (OK, b''), 'put again is idempotent')
        status, body = await b.call(2, struct.pack('>H', 2) + m1 + m2)
        got = fetched(body)
        check(status == OK and len(got) == 1 and got[0][2] == e1, 'fetch one')
        check(got[0][1] == hashlib.blake2b(e1, digest_size=16).digest(), 'handle is the envelope hash')
        check((await b.call(3, m1 + struct.pack('>H', 1) + got[0][1]))[0] == OK, 'delete')
        check(fetched((await b.call(2, struct.pack('>H', 1) + m1))[1]) == [], 'deleted')

        # Malformed frames are refused, each by its reason.
        check((await a.call(1, envelope(m1, 1)[:-1]))[0] == REFUSED, 'envelope one byte short')
        check((await a.call(1, envelope(m1, 1, version=3)))[0] == REFUSED, 'unknown envelope version')
        check((await a.call(1, envelope(m1, 1, bucket=2048)))[0] == REFUSED, 'not a bucket size')
        piece = bytes([17]) + m2 + b'\x05' * (40 + 1024)
        check((await a.call(1, piece))[0] == OK, "a file's piece (version 17, its own size)")
        check((await a.call(1, bytes([17]) + m2 + b'\x05' * (72 + 1024)))[0] == REFUSED, 'a piece of an envelope size')
        check((await a.call(1, bytes([2]) + m2 + b'\x05' * (40 + 1024)))[0] == REFUSED, 'an envelope of a piece size')
        check((await a.call(2, struct.pack('>H', 2) + m1))[0] == REFUSED, 'fetch truncated')
        check((await a.call(2, struct.pack('>H', 0)))[0] == REFUSED, 'empty fetch')
        check((await a.call(2, struct.pack('>H', 1) + m1 + b'x'))[0] == REFUSED, 'fetch trailing byte')
        check((await a.call(99, b''))[0] == REFUSED, 'unknown op')
        check((await a.call(16, b'\0' * 16 + b'\1' * 100))[0] == REFUSED, 'pair box of the wrong size')
        reply = await a.raw(bytes([2, 1]) + struct.pack('>I', 9) + e1)
        check(reply[6] == REFUSED, 'unknown frame version')

        # Pairing: the first post wins, the token is burned.
        token, box1, box2 = b'\x10' * 16, b'\x21' * 1096, b'\x22' * 1096
        check((await b.call(16, token + box1))[0] == OK, 'first post')
        check((await c.call(16, token + box2))[0] == BURNED, 'second post refused')
        status, body = await a.call(17, token)
        check(status == OK and body == struct.pack('>HI', 1, 1096) + box1, 'only the first is kept')
        check((await a.call(20, token))[0] == OK, 'done')
        check((await a.call(17, token))[1] == struct.pack('>H', 0), 'done drops the post')
        check((await b.call(16, token + box1))[0] == BURNED, 'a done token stays burned')

        # Reusable: many posts until the owner cancels with the right key.
        reuse, cancel = b'\x30' * 16, b'\x31' * 32
        check((await a.call(18, reuse + hashlib.blake2b(cancel, digest_size=32).digest()))[0] == OK, 'reusable')
        check((await a.call(18, reuse + b'\0' * 32))[0] == BURNED, 'a token is registered once')
        check((await b.call(16, reuse + box1))[0] == OK and (await c.call(16, reuse + box2))[0] == OK, 'two posts')
        check(struct.unpack('>H', (await a.call(17, reuse))[1][:2])[0] == 2, 'both kept')
        check((await b.call(19, reuse + b'\x32' * 32))[0] == REFUSED, 'cancel with the wrong key')
        check((await a.call(19, reuse + cancel))[0] == OK, 'cancel')
        check((await b.call(16, reuse + box1))[0] == BURNED, 'cancelled')
        check((await a.call(17, reuse))[1] == struct.pack('>H', 0), 'cancel drops the posts')
        check((await a.call(18, token + b'\0' * 32))[0] == BURNED, 'a burned token cannot become reusable')

        # Rooms: signals reach only the addressed member of the same room.
        r1, r2 = b'\x41' * 32, b'\x42' * 32
        la, lb, lc = b'\x51' * 32, b'\x52' * 32, b'\x53' * 32
        check((await a.call(32, r1 + la))[0] == OK and (await b.call(32, r1 + lb))[0] == OK, 'join r1')
        check((await c.call(32, r2 + lc))[0] == OK, 'join r2')
        frame = b'sealed signal'
        check((await a.call(33, r1 + lb + struct.pack('>I', len(frame)) + frame))[0] == OK, 'signal in room')
        pushed = await asyncio.wait_for(b.ws.recv(), 5)
        check(pushed == bytes([1, 0x40, 0, 0, 0, 0]) + r1 + struct.pack('>I', len(frame)) + frame, 'pushed to b')
        check((await a.call(33, r1 + lc + struct.pack('>I', 1) + b'x'))[0] == NOT_FOUND, 'c is not in r1')
        check((await c.call(33, r1 + lb + struct.pack('>I', 1) + b'x'))[0] == REFUSED, 'c cannot speak in r1')
        check((await a.call(33, r2 + lc + struct.pack('>I', 1) + b'x'))[0] == REFUSED, 'a cannot speak in r2')
        await asyncio.sleep(0.3)
        check(c.pushed == [], 'c heard nothing')
        check((await a.call(34, r1))[0] == OK, 'leave')
        check((await b.call(33, r1 + la + struct.pack('>I', 1) + b'x'))[0] == NOT_FOUND, 'a left')

        # Push is off unless configured.
        sub = json.dumps({'endpoint': 'https://push.example/x'}).encode()
        check((await a.call(48, m1 + struct.pack('>I', len(sub)) + sub))[0] == REFUSED, 'push is off')

        # A text frame closes the connection.
        await c.ws.send('text')
        try:
            await asyncio.wait_for(c.ws.recv(), 5)
            check(False, 'text frame closes')
        except Exception:
            check(c.ws.close_code == 1003, 'closed 1003 for a text frame')


async def quota_checks(port):
    async with connect(f'ws://127.0.0.1:{port}') as ws:
        a = Client(ws)
        m = b'\x09' * 32
        check((await a.call(1, envelope(m, 1)))[0] == OK, 'quota put 1')
        check((await a.call(1, envelope(m, 2)))[0] == OK, 'quota put 2')
        check((await a.call(1, envelope(m, 3)))[0] == QUOTA, 'per-mailbox blob quota')
        # The total: 3 blobs of 1129 bytes fit in 3500, a fourth does not.
        check((await a.call(1, envelope(b'\x0a' * 32, 4)))[0] == OK, 'total 3')
        check((await a.call(1, envelope(b'\x0b' * 32, 5)))[0] == QUOTA, 'total quota')
        check((await a.call(1, envelope(b'\x0c' * 32, 6, bucket=16384)))[0] == QUOTA, 'per-mailbox byte quota')
        # Expiry: after the TTL, blobs and tokens are gone, and room again.
        check((await a.call(16, b'\x60' * 16 + b'\1' * 1096))[0] == OK, 'post before expiry')
        await asyncio.sleep(2.5)
        check(fetched((await a.call(2, struct.pack('>H', 1) + m))[1]) == [], 'expired blobs are gone')
        check((await a.call(1, envelope(b'\x0b' * 32, 5)))[0] == OK, 'room after expiry')
        check((await a.call(17, b'\x60' * 16))[1] == struct.pack('>H', 0), 'expired token is gone')


async def backpressure_checks(port):
    url = f'ws://127.0.0.1:{port}'
    async with connect(url, max_size=None) as a_ws, connect(url, max_size=None, max_queue=1) as b_ws:
        a, b = Client(a_ws), Client(b_ws)
        room, la, lb = b'\x71' * 32, b'\x72' * 32, b'\x73' * 32
        await a.call(32, room + la)
        await b.call(32, room + lb)
        big = b'\x74' * 120000
        statuses = []
        for _ in range(400):
            statuses.append((await a.call(33, room + lb + struct.pack('>I', len(big)) + big))[0])
            if statuses[-1] == BUSY:
                break
        check(BUSY in statuses, 'a member that does not read is backpressure, not unbounded memory')


class Hook(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        Hook.seen.append((self.path, dict(self.headers), self.rfile.read(int(self.headers.get('Content-Length', 0)))))
        self.send_response(201)
        self.end_headers()

    def log_message(self, *a):
        pass


async def push_checks(port, public, endpoint):
    async with connect(f'ws://127.0.0.1:{port}') as ws:
        a = Client(ws)
        m = b'\x0d' * 32
        sub = json.dumps({'endpoint': endpoint, 'keys': {}}).encode()
        check((await a.call(48, m + struct.pack('>I', len(sub)) + sub))[0] == OK, 'subscribe')
        bad = json.dumps({'endpoint': 'http://push.example/x'}).encode()
        check((await a.call(48, m + struct.pack('>I', len(bad)) + bad))[0] == REFUSED, 'plain http refused')
        check((await a.call(1, envelope(m, 9)))[0] == OK, 'put to a subscribed mailbox')
        for _ in range(50):
            if Hook.seen:
                break
            await asyncio.sleep(0.1)
    check(len(Hook.seen) == 1, 'one push')
    if Hook.seen:
        path, headers, body = Hook.seen[0]
        check(body == b'', 'the push is empty')
        auth = headers.get('Authorization', '')
        check(auth.startswith('vapid t=') and (', k=' + public) in auth, 'VAPID header')
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        jwt = auth[len('vapid t='):].split(',')[0]
        head, claims, sig = jwt.split('.')
        pad = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pad(public))
        raw = pad(sig)
        der = utils.encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big'))
        key.verify(der, (head + '.' + claims).encode(), ec.ECDSA(hashes.SHA256()))
        check(json.loads(pad(claims))['aud'].startswith('http://127.0.0.1:'), 'audience is the push origin')


def forward(endpoint, authorization, body):
    e, a = endpoint.encode(), authorization.encode()
    return struct.pack('>I', len(e)) + e + struct.pack('>I', len(a)) + a + struct.pack('>I', len(body)) + body


async def forward_checks(port, endpoint, local):
    async with connect(f'ws://127.0.0.1:{port}') as ws:
        a = Client(ws)
        auth = 'vapid t=aaa.bbb.ccc, k=ddd'
        check((await a.call(49, forward('https://evil.example/x', auth, b'x')))[0] == REFUSED, 'a push to an unknown host is refused')
        check((await a.call(49, forward('https://fcm.googleapis.com.evil.example/x', auth, b'x')))[0] == REFUSED,
              'a host that only begins like a push service is refused')
        check((await a.call(49, forward(endpoint, 'Bearer x', b'x')))[0] == REFUSED, 'only a VAPID authorization is carried')
        check((await a.call(49, forward(endpoint, auth + '\r\nX-Evil: 1', b'x')))[0] == REFUSED, 'no header can be smuggled')
        check((await a.call(49, forward(endpoint, auth, b'x' * 4097)))[0] == REFUSED, 'a push body is at most 4096 bytes')
        status = (await a.call(49, forward(endpoint, auth, b'sealed-payload')))[0]
        if not local:
            check(status == REFUSED, 'the loopback is refused unless asked for (tests)')
            return
        check(status == OK, 'a push forwarded')
        for _ in range(50):
            if Hook.seen:
                break
            await asyncio.sleep(0.1)
        check(len(Hook.seen) == 1, 'it reaches the push service')
        if Hook.seen:
            path, headers, body = Hook.seen[0]
            check(body == b'sealed-payload' and headers.get('Authorization') == auth and headers.get('Content-Encoding') == 'aes128gcm',
                  'carried as it is: body, VAPID authorization, aes128gcm')
        statuses = [(await a.call(49, forward(endpoint, auth, b'p')))[0] for _ in range(70)]
        check(BUSY in statuses and statuses.count(OK) <= 59, 'at most 60 forwarded pushes a minute from one connection')
    Hook.seen.clear()


def main():
    global WORKER
    if '--worker' in sys.argv:
        WORKER = str(Path(sys.argv[sys.argv.index('--worker') + 1]).resolve())
        source = (Path(WORKER) / 'src' / 'index.js').read_text() + (Path(WORKER) / 'src' / 'blake2b.js').read_text()
        check('console.' not in source, 'the worker logs nothing')
    relay, port, _ = start('--ttl', '600')
    try:
        asyncio.run(main_checks(port))
    finally:
        relay.terminate()
        out, err = relay.communicate(timeout=10)
        check(out == '' and err == '', 'the relay says nothing beyond READY: ' + repr((out, err)))

    relay, port, _ = start('--ttl', '2', '--mailbox-blobs', '2', '--mailbox-bytes', '4000', '--total-bytes', '3500')
    try:
        asyncio.run(quota_checks(port))
    finally:
        relay.terminate()
        relay.communicate(timeout=10)

    if not WORKER:
        relay, port, _ = start('--queue', '4')
        try:
            asyncio.run(backpressure_checks(port))
        finally:
            relay.terminate()
            relay.communicate(timeout=10)

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    hook = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Hook)
    threading.Thread(target=hook.serve_forever, daemon=True).start()
    for local in (False, True):
        relay, port, _ = start(*(['--push-local'] if local else []))
        try:
            asyncio.run(forward_checks(port, f'http://127.0.0.1:{hook.server_port}/push/2', local))
        finally:
            relay.terminate()
            relay.communicate(timeout=10)
    if WORKER:
        hook.shutdown()
    else:
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / 'vapid.pem'
            key.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            relay, port, line = start('--vapid-key', str(key))
            try:
                asyncio.run(push_checks(port, line.split()[3], f'http://127.0.0.1:{hook.server_port}/push/1'))
            finally:
                relay.terminate()
                relay.communicate(timeout=10)
                hook.shutdown()

    if FAILS:
        print(f'sgchat_relay: {len(FAILS)} failed')
        sys.exit(1)
    print('sgchat_relay: ok')


if __name__ == '__main__':
    main()
