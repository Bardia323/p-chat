"""How long a message takes, phone to phone, in real browsers: from the
moment one side sends to the moment the other has it kept and shown.

  a. live: the two linked directly (WebRTC), both taking mail.
  b. relay only: no direct link can be made (every ICE candidate dropped,
     as between two networks with no TURN): the relay's mailbox carries it.
  c. one side away, then back: sent while it is gone, it has it how long
     after it opens p-chat again - taking mail, and live only (where the
     direct link must be made again first).
  d. a phone that slept (hidden, its relay connection dead while the
     browser still calls it open): how long after it is shown again.

The relay is the local one behind a small proxy that delays each frame by
half of --rtt (a relay is some way off on the internet). Prints p50/p90/max
per case and fails past the targets (live p50 150 ms; relay p50 500 ms, for
a relay up to 100 ms away). --cases picks some of live,reopen,relay;
--trace prints the relay frames and link states it saw.

    python tests/test_browser.py lag --wasm build/wasm --browser <chrome> [--rtt 80]
"""
import asyncio
import json
import random
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAILS = []

# Every remote ICE candidate dropped while window.__noIce is set: no path is
# ever tried, so the link never comes up (as with no TURN across two NATs).
NO_ICE = """(() => {
  const P = window.RTCPeerConnection;
  window.RTCPeerConnection = class extends P {
    addIceCandidate(c) { return window.__noIce ? Promise.resolve() : super.addIceCandidate(c); }
    setRemoteDescription(d) {
      if (window.__noIce && d?.sdp) d = { type: d.type, sdp: d.sdp.split('\\r\\n').filter((l) => !l.startsWith('a=candidate')).join('\\r\\n') };
      return super.setRemoteDescription(d);
    }
  };
})();"""

# What the relay was asked, and when (for looking at where the time goes).
TRACE = """() => {
  window.__trace = [];
  for (const r of window.pchat.session.relays.values())
    for (const k of ['put', 'fetch', 'del', 'signal']) {
      const f = r[k].bind(r);
      r[k] = async (...a) => { const t = Date.now(); const v = await f(...a); window.__trace.push([k, t % 100000, Date.now() - t, Array.isArray(v) ? v.length : v?.status]); return v; };
    }
  const s = window.pchat.session;
  for (const k of ['open', 'carry', 'pump']) {
    const f = s[k].bind(s);
    s[k] = async (...a) => { const t = Date.now(); const v = await f(...a); window.__trace.push([k, t % 100000, Date.now() - t, a[0]?.kind || '']); return v; };
  }
}"""

# A page's own timeline (ms since it started): its relay connection, each
# WebRTC connection's states. For --trace.
EVENTS = """(() => {
  const t0 = Date.now(), ev = (window.__ev = []), at = () => Date.now() - t0;
  const W = window.WebSocket;
  window.WebSocket = class extends W {
    constructor(u, p) {
      super(u, p); ev.push(['ws', at()]); this.addEventListener('open', () => ev.push(['ws open', at()]));
      this.addEventListener('message', (e) => { const d = new Uint8Array(e.data); ev.push(['<' + d[1].toString(16) + (d[1] & 0x80 ? '/' + d[6] : ''), at()]); });
    }
    send(d) { ev.push(['>' + d[1], at()]); return super.send(d); }
  };
  const P = window.RTCPeerConnection;
  window.RTCPeerConnection = class extends P {
    constructor(c) {
      super(c);
      const n = ev.filter((e) => e[0] === 'pc').length;
      ev.push(['pc', at(), n]);
      this.addEventListener('connectionstatechange', () => ev.push(['pc ' + n + ' ' + this.connectionState, at()]));
      this.addEventListener('signalingstatechange', () => ev.push(['pc ' + n + ' sig ' + this.signalingState, at()]));
    }
  };
})();"""

# Asleep: hidden, and its relay connections dead on the way while the browser
# still calls them open (a phone's, after the screen was off a while).
SLEEP = """() => {
  Object.defineProperty(document, 'visibilityState', { get: () => 'hidden', configurable: true });
  document.dispatchEvent(new Event('visibilitychange'));
  for (const r of window.pchat.session.relays.values()) { r.ws.send = () => {}; r.ws.onmessage = null; }
}"""
WAKE = """() => {
  Object.defineProperty(document, 'visibilityState', { get: () => 'visible', configurable: true });
  document.dispatchEvent(new Event('visibilitychange'));
  return Date.now();
}"""

# When each text message was kept and shown here, by its words.
WATCH = """() => {
  const s = window.pchat.session;
  if (s.__got) return;
  s.__got = {};
  const notice = s.notice.bind(s);
  s.notice = async (n) => {
    const r = await notice(n);
    if (n.kind === 'message' && n.type === 'text') { s.__got[new TextDecoder().decode(n.body)] = Date.now(); window.__trace?.push(['got', Date.now() % 100000]); }
    return r;
  };
}"""


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
        time.sleep(0.05)
    check(False, 'timed out: ' + what)
    return False


def proxy(target_port, rtt_ms):
    """A WebSocket proxy that holds each frame rtt/2 each way, in order."""
    from websockets.asyncio.server import serve
    from websockets.asyncio.client import connect
    half = rtt_ms / 2000
    ready = threading.Event()
    port = [0]

    async def pipe(src, dst):
        q = asyncio.Queue()

        async def later():
            while True:
                at, m = await q.get()
                if m is None:
                    await dst.close()
                    return
                await asyncio.sleep(max(0, at - time.monotonic()))
                await dst.send(m)

        t = asyncio.create_task(later())
        try:
            async for m in src:
                q.put_nowait((time.monotonic() + half, m))
        except Exception:
            pass
        q.put_nowait((time.monotonic() + half, None))
        try:
            await t
        except Exception:
            pass

    async def handler(ws):
        async with connect(f'ws://127.0.0.1:{target_port}', max_size=None) as up:
            await asyncio.gather(pipe(ws, up), pipe(up, ws))

    async def main():
        async with serve(handler, '127.0.0.1', 0, max_size=None) as s:
            port[0] = s.sockets[0].getsockname()[1]
            ready.set()
            await asyncio.Future()

    threading.Thread(target=lambda: asyncio.run(main()), daemon=True).start()
    ready.wait(10)
    return port[0]


def summary(name, xs):
    xs = sorted(xs)
    if not xs:
        print(f'{name}: no samples', flush=True)
        return None
    p50 = statistics.median(xs)
    p90 = xs[min(len(xs) - 1, int(len(xs) * 0.9))]
    print(f'{name}: n={len(xs)} p50={p50:.0f} ms p90={p90:.0f} ms max={xs[-1]:.0f} ms', flush=True)
    return p50


def run(args, serve, launch):
    from playwright.sync_api import sync_playwright
    wasm = Path(args.wasm).resolve()
    work = Path(tempfile.mkdtemp(prefix='lag-', dir=wasm))
    relay = subprocess.Popen([sys.executable, str(ROOT / 'relay' / 'relay.py'), '--port', '0'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    port = int(relay.stdout.readline().split()[1])
    rtt = int(getattr(args, 'rtt', 80) or 0)
    far = proxy(port, rtt) if rtt else port
    config = work / 'config.json'
    config.write_text(json.dumps({'relay': f'ws://127.0.0.1:{far}', 'ice': []}))
    rel = [sys.executable, str(ROOT / 'tools' / 'release.py')]
    keys = [work / f'k{i}.pem' for i in (1, 2)]
    pubs = [subprocess.run(rel + ['keygen', '--key', str(k)], check=True, capture_output=True, text=True).stdout.split()[-1] for k in keys]
    site = work / 'site'
    subprocess.run(rel + ['build', '--version', '1', '--committee', ','.join(pubs), '--quorum', '2', '--key', str(keys[0]),
                          '--key', str(keys[1]), '--wasm', str(wasm), '--out', str(site), '--config', str(config)], check=True, capture_output=True)
    server, url = serve(site)
    results = {}
    n = int(getattr(args, 'count', 0) or 12)
    try:
        with sync_playwright() as p:
            browser = launch(p, args.browser)

            def device(name, no_ice):
                ctx = browser.new_context(viewport={'width': 390, 'height': 844})
                ctx.add_init_script(NO_ICE)
                ctx.add_init_script(EVENTS)
                if no_ice:
                    ctx.add_init_script('window.__noIce = true;')
                page = ctx.new_page()
                page.on('dialog', lambda d: d.accept())
                page.errors = []
                page.on('pageerror', lambda e: page.errors.append(f'{e.name}: {e.message}'))
                page.on('console', lambda m: page.errors.append(m.text[:300]) if m.type == 'error' and 'p-chat round failed' in m.text else None)
                page.name, page.ctx = name, ctx
                page.goto(url + '/index.html')
                wait(page, "window.pchat && window.pchat.state.screen !== 'loading'", 60, name + ' starts')
                return page

            def pair(no_ice, tag):
                A, F = device('A' + tag, no_ice), device('F' + tag, no_ice)
                A.click('[data-test=start-invite]')
                A.click('[data-test=kind-contact]')
                A.wait_for_selector('[data-test=qr]')
                link = A.get_attribute('[data-test=qr]', 'data-link')
                words = ' '.join(A.evaluate("Array.from(document.querySelectorAll('[data-test=words] li')).map(e => e.textContent)"))
                F.goto(link)
                wait(F, "window.pchat && window.pchat.state.screen === 'pair'", 60, 'the invite opens')
                F.fill('[data-test=code]', words)
                F.check('[data-test=mail]')
                F.click('[data-test=pair]')
                wait(F, "window.pchat.state.screen === 'paired'", 60, 'paired')
                wait(A, "window.pchat.state.screen === 'paired'", 60, 'paired, both')
                for page, them in ((A, 'F'), (F, 'A')):
                    page.fill('[data-test=call-them]', them)
                    page.click('[data-test=open-chat]')
                conv = A.evaluate('window.pchat.state.conv')
                A.evaluate(f"window.pchat.session.setDelivery('{conv}', true)")
                for page in (A, F):
                    page.peer = page.evaluate('window.pchat.session.app.peer()')
                    page.evaluate(WATCH)
                for page in (A, F):
                    wait(page, f"window.pchat.session.info('{conv}').members.filter(m => !m.self).every(m => m.mail)", 30, 'both take mail')
                return A, F, conv

            def once(src, dst, conv, text):
                src.evaluate("([c, t]) => { window.__sentAt = Date.now(); window.__trace?.push(['send', window.__sentAt % 100000]); window.pchat.session.send(c, t); }", [conv, text])
                sent = src.evaluate('window.__sentAt')
                if not wait(dst, f"!!window.pchat.session.__got[{json.dumps(text)}]", 60, f'{text} arrives'):
                    return None
                return dst.evaluate(f"window.pchat.session.__got[{json.dumps(text)}]") - sent

            def series(A, F, conv, name, linked_must):
                out = []
                for i in range(n):
                    src, dst = (A, F) if i % 2 == 0 else (F, A)
                    if linked_must is not None:
                        live = src.evaluate(f"window.pchat.session.app.liveWith('{dst.peer}')")
                        if live != linked_must:
                            check(False, f'{name}: the link is {"up" if live else "down"} before message {i}')
                    ms = once(src, dst, conv, f'{name}-{i}-{random.randrange(1 << 30)}')
                    if ms is not None:
                        out.append(ms)
                    time.sleep(random.uniform(0.2, 1.5))
                return out

            def reopen(A, F, conv, name):
                """F away; A says something; F back. How long after F opens until it has it."""
                F.goto('about:blank')
                time.sleep(2.5)
                text = f'{name}-{random.randrange(1 << 30)}'
                A.evaluate("([c, t]) => window.pchat.session.send(c, t)", [conv, text])
                time.sleep(2)
                t0 = time.time() * 1000
                F.goto(url + '/index.html')
                wait(F, "!!(window.pchat && window.pchat.session && window.pchat.session.app)", 60, 'back')
                F.evaluate(WATCH)
                ready = time.time() * 1000
                kept = f"window.pchat.store.messages('{conv}').then(ms => ms.some(m => m.body && new TextDecoder().decode(m.body) === {json.dumps(text)}))"
                if not wait(F, kept, 90, f'{name}: had on reopening'):
                    return None
                if getattr(args, 'trace', False):
                    print(name, 'F', F.evaluate('JSON.stringify(window.__ev)'), flush=True)
                return time.time() * 1000 - ready, ready - t0

            cases = (getattr(args, 'cases', '') or 'live,reopen,relay').split(',')
            if 'live' in cases or 'reopen' in cases:
                # ---- a. live ----
                A, F, conv = pair(False, '1')
                wait(A, f"window.pchat.session.app.liveWith('{F.peer}')", 60, 'linked')
                if 'live' in cases:
                    for page in (A, F):
                        page.evaluate(TRACE)
                    results['live'] = series(A, F, conv, 'live', True)
                    if getattr(args, 'trace', False):
                        for page in (A, F):
                            print(page.name, page.evaluate('JSON.stringify(window.__trace.slice(-60))'), flush=True)
                    sent_live = A.evaluate('window.pchat.session.sentLive') + F.evaluate('window.pchat.session.sentLive')
                    check(sent_live >= n, f'went live ({sent_live})')
                # ---- c. away and back, taking mail, then live only ----
                if 'reopen' in cases:
                    got = [x for x in (reopen(A, F, conv, 'reopen-mail') for _ in range(3)) if x]
                    results['reopen (mail)'] = [g[0] for g in got]
                    F.evaluate(f"window.pchat.session.setDelivery('{conv}', false)")
                    wait(A, f"!window.pchat.session.info('{conv}').members.find(m => m.peer === '{F.peer}').mail", 30, 'F live only')
                    wait(A, f"window.pchat.session.app.liveWith('{F.peer}')", 60, 'linked again')
                    got = [x for x in (reopen(A, F, conv, 'reopen-live') for _ in range(3)) if x]
                    results['reopen (live only)'] = [g[0] for g in got]
                for page in (A, F):
                    check(not page.errors, page.name + ' had no page errors: ' + '; '.join(page.errors))
                    page.ctx.close()
            if 'relay' in cases:
                # ---- b. relay only ----
                A, F, conv = pair(True, '2')
                time.sleep(3)
                for page in (A, F):
                    page.evaluate(TRACE)
                results['relay only'] = series(A, F, conv, 'relay', False)
                if getattr(args, 'trace', False):
                    for page in (A, F):
                        print(page.name, page.evaluate('JSON.stringify(window.__trace.slice(-40))'), flush=True)
                check(A.evaluate('window.pchat.session.sentLive') == 0, 'nothing went live: the relay carried it all')
                # ---- d. a phone that slept: its relay connection still says open, and carries nothing ----
                for away in (2, 11):
                    F.evaluate(SLEEP)
                    time.sleep(away)
                    text = f'resume-{away}-{random.randrange(1 << 30)}'
                    A.evaluate("([c, t]) => window.pchat.session.send(c, t)", [conv, text])
                    time.sleep(0.5)
                    t0 = F.evaluate(WAKE)
                    if wait(F, f"!!window.pchat.session.__got[{json.dumps(text)}]", 60, f'had on waking after {away} s'):
                        results[f'woken after {away} s'] = [F.evaluate(f"window.pchat.session.__got[{json.dumps(text)}]") - t0]
                for page in (A, F):
                    check(not page.errors, page.name + ' had no page errors: ' + '; '.join(page.errors))
            browser.close()
    finally:
        server.shutdown()
        relay.terminate()
    print(f'---- send to shown, relay {rtt} ms away ----')
    p = {k: summary(k, v) for k, v in results.items()}
    # The targets, for a relay up to 100 ms away (the relay path is two of its round trips).
    if 'live' in p:
        check(p['live'] is not None and p['live'] < 150, 'live p50 under 150 ms')
    if 'relay only' in p and rtt <= 100:
        check(p['relay only'] is not None and p['relay only'] < 500, 'relay only p50 under 500 ms')
    if FAILS:
        print(f'sgchat_lag: {len(FAILS)} failed')
        return 1
    print('sgchat_lag: ok')
    return 0
