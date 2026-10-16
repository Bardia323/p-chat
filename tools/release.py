"""Cut a signed p-chat release, one link of the release chain (v1 §12).

    python tools/release.py keygen --key ~/offline/release-1.pem
    python tools/release.py build --version 1 --committee <pub1>,<pub2>,<pub3> --quorum 2 \\
        --key ~/offline/release-1.pem --key ~/offline/release-2.pem --wasm build/wasm --out dist [--config config.json]
    python tools/release.py build --version 2 --chain old-dist/chain.json --key ... --wasm build/wasm --out dist
    python tools/release.py sign --key ~/offline/release-3.pem --site dist
    python tools/release.py verify --site dist
    python tools/release.py fingerprint --site dist

keygen makes one member's release key (Ed25519, PEM, readable only by you)
and prints its public half. Each member keeps theirs offline, on their own
device, and none is ever committed: a quorum of them can sign a release
every installed service worker will take.

build copies the app (web/), the Wasm module and the deployment's
config.json into --out, writes the chain's first committee and the chain's
own checks (web/release.js) into sw.js, lists every file with its SHA-256 in
manifest.json, and adds a record to the chain (chain.json): the version,
the SHA-256 of manifest.json and of sw.js, the hash of the record before,
and the committee that signs the next (--committee/--quorum; the same as
before if not given). It signs the record with the --key members given;
others add theirs with `sign` before it is published. The first release's
committee signs itself; each later one is signed by the one before names.

A signature is an engine Observation signature (sg::net): peer the key,
sequence the version, payload the record's hash - so two records signed for
one version are equivocation the engine keeps (web/release.js says the bytes).
"""
import argparse
import hashlib
import json
import os
import shutil
import stat
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZERO = '0' * 64


def load_key(path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = serialization.load_pem_private_key(Path(path).read_bytes(), None)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit('a release key is an Ed25519 private key')
    return key


def public_hex(key):
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def fingerprint(manifest_bytes):
    d = hashlib.sha256(manifest_bytes).hexdigest()
    return ' '.join(d[i:i + 4] for i in range(0, 32, 4))


# ---- the chain's bytes, as web/release.js has them ----

def canonical(r):
    body = {'committee': {'keys': sorted(r['committee']['keys']), 'quorum': r['committee']['quorum']},
            'manifest': r['manifest'], 'previous': r['previous'], 'sw': r['sw'], 'version': r['version']}
    return json.dumps(body, separators=(',', ':'))


def record_hash(r):
    return hashlib.sha256(canonical(r).encode()).hexdigest()


def text(s):
    b = s.encode()
    return struct.pack('>Q', len(b)) + b


def statement(key_hex, version, hash_hex):
    """The engine's Observation statement (sg::net::detail::Writer)."""
    context = hashlib.sha256(b'p-chat.release.v1').digest()
    payload = bytes.fromhex(hash_hex)
    return (text('sg.net.observation.v1') + text(key_hex) + context + struct.pack('>Q', 0) + struct.pack('>Q', version)
            + text('p-chat') + text('release') + struct.pack('>Q', 1) + text('release') + struct.pack('>Q', len(payload)) + payload)


def sign_record(r, key):
    pub = public_hex(key)
    sig = key.sign(statement(pub, r['version'], record_hash(r))).hex()
    r['signatures'] = [s for s in r['signatures'] if s['key'] != pub] + [{'key': pub, 'sig': sig}]


def signed_by(r, committee):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    seen = set()
    for s in r['signatures']:
        if s['key'] in seen or s['key'] not in committee['keys']:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(s['key'])).verify(bytes.fromhex(s['sig']),
                                                                               statement(s['key'], r['version'], record_hash(r)))
            seen.add(s['key'])
        except Exception:
            pass
    return len(seen)


def check_committee(c):
    keys = c['keys']
    if not keys or len(set(keys)) != len(keys) or not all(len(k) == 64 for k in keys):
        sys.exit('a committee is distinct keys')
    if not (1 <= c['quorum'] <= len(keys)) or 2 * c['quorum'] <= len(keys):
        sys.exit('a quorum is more than half the committee')


def follow(chain):
    """Every link, from the first: the head, or exit with why."""
    first = chain[0]
    if first['previous'] != ZERO or signed_by(first, first['committee']) < first['committee']['quorum']:
        sys.exit('the first release is not signed by its own committee')
    head = first
    for r in chain[1:]:
        if r['version'] <= head['version']:
            sys.exit(f"release {r['version']} is not newer than {head['version']}")
        if r['previous'] != record_hash(head):
            sys.exit(f"release {r['version']} does not follow release {head['version']}")
        n = signed_by(r, head['committee'])
        if n < head['committee']['quorum']:
            sys.exit(f"release {r['version']} has {n} of the {head['committee']['quorum']} signatures it needs")
        head = r
    return head


# ---- commands ----

def keygen(a):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    path = Path(a.key)
    if path.exists():
        sys.exit(f'{path} exists; refusing to replace a release key')
    key = Ed25519PrivateKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    print('release public key', public_hex(key))


def build(a):
    keys = [load_key(k) for k in a.key]
    chain = json.loads(Path(a.chain).read_text()) if a.chain else []
    if chain:
        follow(chain)
    if a.committee:
        committee = {'keys': sorted(a.committee.split(',')), 'quorum': a.quorum}
    elif chain:
        committee = chain[-1]['committee']
    else:
        sys.exit('the first release names its committee (--committee, --quorum)')
    check_committee(committee)
    first = chain[0]['committee'] if chain else committee
    out, wasm, web = Path(a.out), Path(a.wasm), ROOT / 'web'
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(web, out)
    for f in ('sgchat.js', 'sgchat.wasm'):
        shutil.copy(wasm / f, out / f)
    if a.config:
        json.loads(Path(a.config).read_text())
        shutil.copy(a.config, out / 'config.json')
    elif not (out / 'config.json').exists():
        (out / 'config.json').write_text('{"relay": "", "ice": []}\n')
    sw = (out / 'sw.js').read_text()
    if '__GENESIS_COMMITTEE__' not in sw or '/*__RELEASE_JS__*/' not in sw:
        sys.exit('sw.js has no place for the chain')
    sw = sw.replace("'__GENESIS_COMMITTEE__'", json.dumps({'keys': sorted(first['keys']), 'quorum': first['quorum']}))
    sw = sw.replace('/*__RELEASE_JS__*/', (web / 'release.js').read_text())
    (out / 'sw.js').write_text(sw)
    files = {}
    for p in sorted(out.rglob('*')):
        if p.is_file() and p.name not in ('manifest.json', 'chain.json'):
            files[p.relative_to(out).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    manifest = json.dumps({'version': a.version, 'files': files}, sort_keys=True, separators=(',', ':')).encode()
    (out / 'manifest.json').write_bytes(manifest)
    record = {'version': a.version, 'manifest': hashlib.sha256(manifest).hexdigest(), 'sw': files['sw.js'],
              'previous': record_hash(chain[-1]) if chain else ZERO, 'committee': committee, 'signatures': []}
    signer = chain[-1]['committee'] if chain else committee
    for k in keys:
        if public_hex(k) not in signer['keys']:
            sys.exit(f'{public_hex(k)} is not of the committee that signs release {a.version}')
        sign_record(record, k)
    chain.append(record)
    (out / 'chain.json').write_text(json.dumps(chain, indent=1))
    have = signed_by(record, signer)
    print(f"release {a.version}: {len(files)} files, signed by {have} of {len(signer['keys'])} (needs {signer['quorum']})")
    print('record', record_hash(record))
    print('bundle fingerprint', fingerprint(manifest))


def sign(a):
    site = Path(a.site)
    chain = json.loads((site / 'chain.json').read_text())
    key = load_key(a.key)
    r = chain[-1]
    signer = chain[-2]['committee'] if len(chain) > 1 else r['committee']
    if public_hex(key) not in signer['keys']:
        sys.exit('this key is not of the committee that signs this release')
    sign_record(r, key)
    (site / 'chain.json').write_text(json.dumps(chain, indent=1))
    print(f"release {r['version']} signed by {signed_by(r, signer)} of {len(signer['keys'])} (needs {signer['quorum']})")


def verify(a):
    site = Path(a.site)
    chain = json.loads((site / 'chain.json').read_text())
    head = follow(chain)
    manifest = (site / 'manifest.json').read_bytes()
    if hashlib.sha256(manifest).hexdigest() != head['manifest']:
        sys.exit('manifest.json is not the one the release names')
    for path, want in json.loads(manifest)['files'].items():
        if hashlib.sha256((site / path).read_bytes()).hexdigest() != want:
            sys.exit(f'{path} does not match the manifest')
    if hashlib.sha256((site / 'sw.js').read_bytes()).hexdigest() != head['sw']:
        sys.exit('sw.js is not the one the release names')
    print(f"release {head['version']}: every link, signature and file holds; head {record_hash(head)}; bundle fingerprint {fingerprint(manifest)}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    k = sub.add_parser('keygen')
    k.add_argument('--key', required=True)
    b = sub.add_parser('build')
    b.add_argument('--key', action='append', default=[], help='a member key that signs now (any number)')
    b.add_argument('--version', type=int, required=True)
    b.add_argument('--chain', help='the chain so far (the last release\'s chain.json)')
    b.add_argument('--committee', help='the keys (hex, comma separated) that sign the next release')
    b.add_argument('--quorum', type=int, default=0)
    b.add_argument('--wasm', required=True)
    b.add_argument('--out', required=True)
    b.add_argument('--config')
    s = sub.add_parser('sign')
    s.add_argument('--key', required=True)
    s.add_argument('--site', required=True)
    f = sub.add_parser('fingerprint')
    f.add_argument('--site', required=True)
    v = sub.add_parser('verify')
    v.add_argument('--site', required=True)
    a = p.parse_args()
    if a.cmd == 'keygen':
        keygen(a)
    elif a.cmd == 'build':
        build(a)
    elif a.cmd == 'sign':
        sign(a)
    elif a.cmd == 'fingerprint':
        print('bundle fingerprint', fingerprint((Path(a.site) / 'manifest.json').read_bytes()))
    else:
        verify(a)


if __name__ == '__main__':
    main()
