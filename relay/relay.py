"""sgchat relay: signaling rooms, a ciphertext mailbox, pairing tokens, and
optional Web Push. It has no world role and holds nothing it can read.

Everything is in RAM and expires after the mailbox's life (14 days by
default). Nothing is logged: no requests, no addresses. Frames are binary
and must match docs/protocol.md exactly, or they are refused.

    python relay.py                          # loopback, ws://127.0.0.1:49290
    python relay.py --host 0.0.0.0 --cert tls.pem --key tls.key
    python relay.py --vapid-key vapid.pem --vapid-subject mailto:you@example.org

Requires `websockets` >= 13; Web Push also `cryptography`.
"""
import argparse
import asyncio
import base64
import collections
import hashlib
import json
import logging
import ssl
import struct
import sys
import time
import urllib.parse
import urllib.request

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

BUCKETS = (1024, 16384, 262144)
SEAL = 32 + 24 + 16
ENVELOPE_SIZES = {1 + 32 + SEAL + b for b in BUCKETS}
ENVELOPE_VERSIONS = {1, 2, 16}
# Protocol 3: a file's piece (version 17) is sealed by the file's own key;
# protocol 4: a channel's post (version 18) by a key from the channel's secret.
PIECE_SIZES = {1 + 32 + 24 + 16 + b for b in BUCKETS}
PAIR_BOX = SEAL + 1024

OK, REFUSED, BURNED, BUSY, QUOTA, NOT_FOUND = 0, 1, 2, 3, 4, 5
PUT, FETCH, DELETE, WATCH = 1, 2, 3, 4
PAIR_POST, PAIR_FETCH, PAIR_REUSABLE, PAIR_CANCEL, PAIR_DONE = 16, 17, 18, 19, 20
JOIN, SIGNAL, LEAVE = 32, 33, 34
PUSH_SUBSCRIBE, PUSH_FORWARD = 48, 49
# Push services a forwarded push may go to (protocol 6): the browsers' own.
PUSH_HOSTS = ('fcm.googleapis.com', 'push.services.mozilla.com', 'web.push.apple.com', 'notify.windows.com')
PUSHED_SIGNAL = 0x40
# Protocol 11: a connection watching a mailbox is told at once that mail is waiting there.
PUSHED_MAIL = 0x41


class Refused(Exception):
    """A frame that does not match its layout."""


class Reader:
    def __init__(self, data):
        self.data, self.at = data, 0

    def take(self, n):
        if n < 0 or self.at + n > len(self.data):
            raise Refused('truncated')
        out = self.data[self.at:self.at + n]
        self.at += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack('>H', self.take(2))[0]

    def u32(self):
        return struct.unpack('>I', self.take(4))[0]

    def long(self, maximum):
        n = self.u32()
        if n > maximum:
            raise Refused('oversize')
        return self.take(n)

    def end(self):
        if self.at != len(self.data):
            raise Refused('trailing')


class Limits:
    def __init__(self, a):
        self.ttl = a.ttl
        self.mailbox_bytes = a.mailbox_bytes
        self.mailbox_blobs = a.mailbox_blobs
        self.total_bytes = a.total_bytes
        self.tokens = a.tokens
        self.rooms = a.rooms
        self.members = a.members
        self.rooms_per_connection = 64
        self.queue = a.queue
        self.fetch_ids = 1024
        self.watches = a.watches
        self.reusable_posts = 16
        self.push_hosts = PUSH_HOSTS + tuple(a.push_host or ())
        self.push_local = a.push_local
        self.forwards_per_minute = 60


class Relay:
    """The relay's memory. Wall time is used only to expire things."""

    def __init__(self, limits, push=None, clock=time.monotonic):
        self.limits, self.push, self.clock = limits, push, clock
        self.forwarding = set()
        self.mailboxes = {}                      # id -> OrderedDict(handle -> (expires, envelope))
        self.stored = 0
        self.tokens = {}                         # token -> dict
        self.rooms = {}                          # room -> {label: connection}
        self.subscriptions = {}                  # mailbox -> (expires, subscription)
        self.watchers = {}                       # mailbox -> {connection}: told when mail comes
        self.watched = 0

    # Expiry: lazily where touched, and in a sweep.
    def sweep(self):
        now = self.clock()
        for mid in list(self.mailboxes):
            box = self.mailboxes[mid]
            for handle in [h for h, (exp, _) in box.items() if exp <= now]:
                self.stored -= len(box.pop(handle)[1])
            if not box:
                del self.mailboxes[mid]
        for token in [t for t, s in self.tokens.items() if s['expires'] <= now]:
            del self.tokens[token]
        for mid in [m for m, (exp, _) in self.subscriptions.items() if exp <= now]:
            del self.subscriptions[mid]

    # Mailbox.
    def put(self, envelope):
        if not ((envelope[:1] and envelope[0] in ENVELOPE_VERSIONS and len(envelope) in ENVELOPE_SIZES) or
                (envelope[:1] in (b'\x11', b'\x12') and len(envelope) in PIECE_SIZES)):
            raise Refused('not an envelope')
        mid = envelope[1:33]
        handle = hashlib.blake2b(envelope, digest_size=16).digest()
        self.sweep_one(mid)
        box = self.mailboxes.setdefault(mid, collections.OrderedDict())
        if handle in box:
            return OK
        used = sum(len(e) for _, e in box.values())
        if len(box) >= self.limits.mailbox_blobs or used + len(envelope) > self.limits.mailbox_bytes:
            if not box:
                del self.mailboxes[mid]
            return QUOTA
        if self.stored + len(envelope) > self.limits.total_bytes:
            if not box:
                del self.mailboxes[mid]
            return QUOTA
        box[handle] = (self.clock() + self.limits.ttl, envelope)
        self.stored += len(envelope)
        # Whoever watches this mailbox is told, now: no envelope, only its
        # mailbox (best effort - a full queue drops the notice; it fetches anyway).
        for conn in self.watchers.get(mid, ()):
            conn.offer(bytes([1, PUSHED_MAIL]) + b'\0\0\0\0' + mid)
        if self.push and mid in self.subscriptions:
            self.push.notify(self.subscriptions[mid][1])
        return OK

    def sweep_one(self, mid):
        box = self.mailboxes.get(mid)
        if not box:
            return
        now = self.clock()
        for handle in [h for h, (exp, _) in box.items() if exp <= now]:
            self.stored -= len(box.pop(handle)[1])
        if not box:
            del self.mailboxes[mid]

    def fetch(self, ids):
        out = []
        for mid in ids:
            self.sweep_one(mid)
            for handle, (_, envelope) in self.mailboxes.get(mid, {}).items():
                out.append((mid, handle, envelope))
        return out

    # Watching: a connection names the mailboxes it fetches (the same ids a
    # fetch names), and is told when one gets mail. The list replaces the last.
    def watch(self, ids, conn):
        ids = set(ids)
        if self.watched - len(conn.watching) + len(ids) > self.limits.watches:
            return QUOTA
        self.unwatch(conn)
        for mid in ids:
            self.watchers.setdefault(mid, set()).add(conn)
        conn.watching = ids
        self.watched += len(ids)
        return OK

    def unwatch(self, conn):
        for mid in conn.watching:
            w = self.watchers.get(mid)
            if w is not None:
                w.discard(conn)
                if not w:
                    del self.watchers[mid]
        self.watched -= len(conn.watching)
        conn.watching = set()

    def delete(self, mid, handles):
        box = self.mailboxes.get(mid)
        if not box:
            return OK
        for h in handles:
            if h in box:
                self.stored -= len(box.pop(h)[1])
        if not box:
            del self.mailboxes[mid]
        return OK

    # Pairing tokens: the first post wins; a reusable token takes posts until
    # its owner cancels it. A burned token is remembered until it expires.
    def token(self, token):
        state = self.tokens.get(token)
        if state and state['expires'] <= self.clock():
            del self.tokens[token]
            state = None
        return state

    def pair_post(self, token, box):
        state = self.token(token)
        if state is None:
            if len(self.tokens) >= self.limits.tokens:
                return QUOTA
            self.tokens[token] = {'reusable': False, 'burned': True, 'posts': [box],
                                  'cancel': None, 'expires': self.clock() + self.limits.ttl}
            return OK
        if state['burned'] or not state['reusable']:
            return BURNED
        if len(state['posts']) >= self.limits.reusable_posts:
            return QUOTA
        if box not in state['posts']:
            state['posts'].append(box)
        return OK

    def pair_fetch(self, token):
        state = self.token(token)
        return [] if state is None else list(state['posts'])

    def pair_reusable(self, token, cancel_hash):
        if self.token(token) is not None:
            return BURNED
        if len(self.tokens) >= self.limits.tokens:
            return QUOTA
        self.tokens[token] = {'reusable': True, 'burned': False, 'posts': [],
                              'cancel': cancel_hash, 'expires': self.clock() + self.limits.ttl}
        return OK

    def pair_cancel(self, token, cancel_key):
        state = self.token(token)
        if state is None or not state['reusable']:
            return NOT_FOUND
        if hashlib.blake2b(cancel_key, digest_size=32).digest() != state['cancel']:
            return REFUSED
        state['burned'], state['posts'] = True, []
        return OK

    def pair_done(self, token):
        state = self.token(token)
        if state is None:
            self.tokens[token] = {'reusable': False, 'burned': True, 'posts': [],
                                  'cancel': None, 'expires': self.clock() + self.limits.ttl}
            return OK
        if state['reusable']:
            state['posts'] = []
            return OK
        state['burned'], state['posts'] = True, []
        return OK

    # Rooms: a member is a label in a room; signals go only to a member of
    # the same room, never to everyone.
    def join(self, room, label, conn):
        members = self.rooms.get(room)
        if members is None:
            if len(self.rooms) >= self.limits.rooms:
                return QUOTA
            members = self.rooms[room] = {}
        if label not in members and len(members) >= self.limits.members:
            return QUOTA
        if room not in conn.rooms and len(conn.rooms) >= self.limits.rooms_per_connection:
            return QUOTA
        old = members.get(label)
        if old is not None and old is not conn:
            old.rooms.pop(room, None)
        members[label] = conn
        conn.rooms[room] = label
        return OK

    def leave(self, room, conn):
        label = conn.rooms.pop(room, None)
        members = self.rooms.get(room)
        if members is not None and label is not None and members.get(label) is conn:
            del members[label]
            if not members:
                del self.rooms[room]
        return OK

    def signal(self, room, to, box, conn):
        if room not in conn.rooms:
            return REFUSED
        target = self.rooms.get(room, {}).get(to)
        if target is None:
            return NOT_FOUND
        frame = bytes([1, PUSHED_SIGNAL]) + b'\0\0\0\0' + room + struct.pack('>I', len(box)) + box
        return OK if target.offer(frame) else BUSY

    def subscribe(self, mid, subscription):
        if self.push is None:
            return REFUSED
        if len(self.subscriptions) >= self.limits.tokens and mid not in self.subscriptions:
            return QUOTA
        self.subscriptions[mid] = (self.clock() + self.limits.ttl, subscription)
        return OK

    def forward(self, endpoint, authorization, body):
        if len(self.forwarding) >= 256:
            return BUSY
        task = asyncio.get_running_loop().create_task(asyncio.to_thread(post_push, endpoint, authorization, body))
        self.forwarding.add(task)
        task.add_done_callback(self.forwarding.discard)
        return OK

    def drop(self, conn):
        for room in list(conn.rooms):
            self.leave(room, conn)
        self.unwatch(conn)


class Connection:
    """One client's bounded outgoing queue. A full queue is backpressure."""

    def __init__(self, ws, limit):
        self.ws, self.rooms, self.watching = ws, {}, set()
        self.queue = asyncio.Queue(limit)
        self.forwarded = []  # when this connection last forwarded pushes (for the rate)

    def offer(self, frame):
        try:
            self.queue.put_nowait(frame)
            return True
        except asyncio.QueueFull:
            return False

    async def writer(self):
        while True:
            await self.ws.send(await self.queue.get())


def answer(op, rid, status, body=b''):
    return bytes([1, op | 0x80]) + struct.pack('>I', rid) + bytes([status]) + body


def handle(relay, conn, data):
    """One request frame: its answer, or Refused."""
    r = Reader(data)
    if r.u8() != 1:
        raise Refused('version')
    op, rid = r.u8(), r.u32()
    if op == PUT:
        envelope = r.take(len(data) - r.at)
        return answer(op, rid, relay.put(envelope))
    if op == FETCH:
        n = r.u16()
        if n == 0 or n > relay.limits.fetch_ids:
            raise Refused('fetch count')
        ids = [r.take(32) for _ in range(n)]
        r.end()
        found = relay.fetch(ids)
        body = bytearray(struct.pack('>H', len(found)))
        for mid, h, envelope in found:
            body += mid + h + struct.pack('>I', len(envelope)) + envelope
        return answer(op, rid, OK, bytes(body))
    if op == DELETE:
        mid = r.take(32)
        n = r.u16()
        if n > 1024:
            raise Refused('delete count')
        handles = [r.take(16) for _ in range(n)]
        r.end()
        return answer(op, rid, relay.delete(mid, handles))
    if op == WATCH:
        n = r.u16()
        if n > relay.limits.fetch_ids:
            raise Refused('watch count')
        ids = [r.take(32) for _ in range(n)]
        r.end()
        return answer(op, rid, relay.watch(ids, conn))
    if op == PAIR_POST:
        token, box = r.take(16), r.take(len(data) - r.at)
        if len(box) != PAIR_BOX:
            raise Refused('pair box size')
        return answer(op, rid, relay.pair_post(token, box))
    if op == PAIR_FETCH:
        token = r.take(16)
        r.end()
        posts = relay.pair_fetch(token)
        body = bytearray(struct.pack('>H', len(posts)))
        for p in posts:
            body += struct.pack('>I', len(p)) + p
        return answer(op, rid, OK, bytes(body))
    if op == PAIR_REUSABLE:
        token, cancel_hash = r.take(16), r.take(32)
        r.end()
        return answer(op, rid, relay.pair_reusable(token, cancel_hash))
    if op == PAIR_CANCEL:
        token, key = r.take(16), r.take(32)
        r.end()
        return answer(op, rid, relay.pair_cancel(token, key))
    if op == PAIR_DONE:
        token = r.take(16)
        r.end()
        return answer(op, rid, relay.pair_done(token))
    if op == JOIN:
        room, label = r.take(32), r.take(32)
        r.end()
        return answer(op, rid, relay.join(room, label, conn))
    if op == SIGNAL:
        room, to = r.take(32), r.take(32)
        box = r.long(131072)
        r.end()
        return answer(op, rid, relay.signal(room, to, box, conn))
    if op == LEAVE:
        room = r.take(32)
        r.end()
        return answer(op, rid, relay.leave(room, conn))
    if op == PUSH_SUBSCRIBE:
        mid = r.take(32)
        raw = r.long(4096)
        r.end()
        try:
            sub = json.loads(raw.decode('utf-8'))
            endpoint = sub['endpoint']
            parsed = urllib.parse.urlsplit(endpoint)
            local = parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost')
            if not isinstance(endpoint, str) or not (parsed.scheme == 'https' or local):
                raise ValueError
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            raise Refused('subscription')
        return answer(op, rid, relay.subscribe(mid, endpoint))
    if op == PUSH_FORWARD:
        # A push made and signed by a member's device: carried as it is. The
        # relay holds no key; it learns only that a push goes to an endpoint.
        try:
            endpoint = r.long(1024).decode('ascii')
            authorization = r.long(1024).decode('ascii')
        except UnicodeDecodeError:
            raise Refused('push')
        body = r.long(4096)
        r.end()
        parsed = urllib.parse.urlsplit(endpoint)
        host = parsed.hostname or ''
        known = parsed.scheme == 'https' and any(host == h or host.endswith('.' + h) for h in relay.limits.push_hosts)
        local = relay.limits.push_local and parsed.scheme == 'http' and host in ('127.0.0.1', 'localhost')
        if not (known or local) or not authorization.startswith('vapid t=') or any(ch in authorization for ch in '\r\n'):
            raise Refused('push')
        now = relay.clock()
        conn.forwarded = [t for t in conn.forwarded if now - t < 60]
        if len(conn.forwarded) >= relay.limits.forwards_per_minute:
            return answer(op, rid, BUSY)
        conn.forwarded.append(now)
        return answer(op, rid, relay.forward(endpoint, authorization, body))
    raise Refused('unknown op')


def post_push(endpoint, authorization, body):
    request = urllib.request.Request(endpoint, data=body, method='POST', headers={
        'TTL': '86400', 'Urgency': 'high', 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream',
        'Content-Length': str(len(body)), 'Authorization': authorization})
    try:
        urllib.request.urlopen(request, timeout=10).close()
    except Exception:
        pass  # best effort, and nothing is recorded


class Push:
    """Empty Web Push messages with VAPID (RFC 8292). An empty push carries
    nothing to encrypt: it only wakes the device to fetch its mailbox."""

    def __init__(self, key_path, subject):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        with open(key_path, 'rb') as f:
            self.key = serialization.load_pem_private_key(f.read(), None)
        if not isinstance(self.key, ec.EllipticCurvePrivateKey) or self.key.curve.name != 'secp256r1':
            raise SystemExit('VAPID key must be a P-256 private key (PEM)')
        self.subject, self._ec, self._hashes, self._utils = subject, ec, hashes, utils
        pub = self.key.public_key().public_bytes(serialization.Encoding.X962,
                                                 serialization.PublicFormat.UncompressedPoint)
        self.public = b64(pub)
        self.pending = set()

    def token(self, audience):
        header = b64(json.dumps({'typ': 'JWT', 'alg': 'ES256'}, separators=(',', ':')).encode())
        claims = b64(json.dumps({'aud': audience, 'exp': int(time.time()) + 12 * 3600, 'sub': self.subject},
                                separators=(',', ':')).encode())
        signed = (header + '.' + claims).encode()
        der = self.key.sign(signed, self._ec.ECDSA(self._hashes.SHA256()))
        r, s = self._utils.decode_dss_signature(der)
        return header + '.' + claims + '.' + b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))

    def notify(self, endpoint):
        if len(self.pending) >= 256:
            return
        task = asyncio.get_running_loop().create_task(asyncio.to_thread(self.send, endpoint))
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)

    def send(self, endpoint):
        parts = urllib.parse.urlsplit(endpoint)
        audience = parts.scheme + '://' + parts.netloc
        request = urllib.request.Request(endpoint, data=b'', method='POST', headers={
            'TTL': '86400', 'Urgency': 'high', 'Content-Length': '0',
            'Authorization': 'vapid t=' + self.token(audience) + ', k=' + self.public})
        try:
            urllib.request.urlopen(request, timeout=10).close()
        except Exception:
            pass  # best effort, and nothing is recorded


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


async def run(args, ready=None):
    logging.getLogger('websockets').setLevel(logging.CRITICAL)
    push = Push(args.vapid_key, args.vapid_subject) if args.vapid_key else None
    relay = Relay(Limits(args), push)
    tls = None
    if args.cert and args.key:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(args.cert, args.key)

    async def client(ws):
        conn = Connection(ws, args.queue)
        writer = asyncio.create_task(conn.writer())
        try:
            async for data in ws:
                if not isinstance(data, bytes):
                    await ws.close(1003, 'binary frames only')
                    return
                try:
                    reply = handle(relay, conn, data)
                except Refused:
                    op, rid = (data[1], struct.unpack('>I', data[2:6])[0]) if len(data) >= 6 else (0, 0)
                    reply = answer(op & 0x7f, rid, REFUSED)
                if not conn.offer(reply):
                    await ws.close(1013, 'backpressure')
                    return
        except ConnectionClosed:
            pass
        finally:
            relay.drop(conn)
            writer.cancel()
            await asyncio.gather(writer, return_exceptions=True)

    async def sweeper():
        while True:
            await asyncio.sleep(min(60.0, max(0.2, args.ttl / 4)))
            relay.sweep()

    async with serve(client, args.host, args.port, ssl=tls, max_size=300 * 1024, max_queue=16,
                     write_limit=256 * 1024, compression=None, server_header=None, logger=None) as server:
        sweep = asyncio.create_task(sweeper())
        port = next(iter(server.sockets)).getsockname()[1]
        print(f'READY {port}' + (f' VAPID {push.public}' if push else ''), flush=True)
        if ready:
            ready(port)
        try:
            await asyncio.Future()
        finally:
            sweep.cancel()


def arguments(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=49290)
    p.add_argument('--cert')
    p.add_argument('--key')
    p.add_argument('--ttl', type=float, default=14 * 86400, help='seconds a blob, token or subscription lives')
    p.add_argument('--mailbox-bytes', type=int, default=8 * 1024 * 1024)
    p.add_argument('--mailbox-blobs', type=int, default=512)
    p.add_argument('--total-bytes', type=int, default=512 * 1024 * 1024)
    p.add_argument('--tokens', type=int, default=65536)
    p.add_argument('--rooms', type=int, default=65536)
    p.add_argument('--members', type=int, default=16)
    p.add_argument('--watches', type=int, default=1 << 20, help='mailboxes watched, over all connections')
    p.add_argument('--queue', type=int, default=256, help='frames waiting for one client')
    p.add_argument('--vapid-key', help='P-256 private key (PEM) for Web Push; off when absent')
    p.add_argument('--push-host', action='append', help='a further push service host forwarded pushes may go to')
    p.add_argument('--push-local', action='store_true', help='tests only: forwarded pushes may go to http on the loopback')
    p.add_argument('--vapid-subject', default='mailto:admin@localhost')
    return p.parse_args(argv)


def main():
    p_args = arguments()
    if p_args.host not in ('127.0.0.1', 'localhost', '::1') and not (p_args.cert and p_args.key):
        sys.exit('a relay on a public address needs --cert and --key (or bind loopback behind a TLS proxy)')
    try:
        asyncio.run(run(p_args))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
