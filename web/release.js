// The release chain (v1 §12): what makes a bundle of p-chat one this device
// may run. Used by the page, and written into sw.js when a release is cut
// (the worker has no modules), so both check alike.
//
// A record says a release: its version, the SHA-256 of its manifest.json
// (which lists every file's SHA-256) and of its sw.js, the record before
// it (its hash; zeros for the first), and the committee that signs the
// next (the owner's devices' keys and how many must sign). It is signed by
// the committee the record before names (the first, by its own): each
// signature an engine Observation signature (sg::net), so two different
// records signed for one version are equivocation the engine keeps.
//
//   body  = {"committee":{"keys":[...sorted hex],"quorum":q},"manifest":hex,"previous":hex,"sw":hex,"version":n}
//           (keys sorted, no spaces: canonical JSON)
//   hash  = SHA-256(body)
//   signs = Observation{peer: key hex, context: SHA-256("p-chat.release.v1"), tick 0, sequence: version,
//           object "p-chat", parameter "release", discrete, conflict "release", payload: hash}.statement()
//
// A device keeps its head. It takes a record only if it follows its head
// (previous = head's hash), has a higher version, and enough signatures of
// the head's committee; versions it skipped are taken link by link. Then
// the bundle: its manifest's hash, every file's, and sw.js's.
(function (g) {
  const enc = new TextEncoder();
  const hex = (b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('');
  const unhex = (s) => new Uint8Array((s.match(/../g) || []).map((x) => parseInt(x, 16)));
  const sha = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
  const ZERO = '0'.repeat(64);
  const isHex = (s, n) => typeof s === 'string' && s.length === n && /^[0-9a-f]+$/.test(s);

  // The engine's canonical bytes (sg::net::detail::Writer): a text is a u64
  // length and its bytes, an integer a u64, big-endian; a digest its 32 bytes.
  function writer(domain) {
    const parts = [];
    const w = {
      integer(v) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v)); parts.push(b); return w; },
      bytes(v) { w.integer(v.length); parts.push(v); return w; },
      text(s) { return w.bytes(enc.encode(s)); },
      digest(d) { if (d.length !== 32) throw new Error('a digest is 32 bytes'); parts.push(d); return w; },
      data() { const n = parts.reduce((a, p) => a + p.length, 0), out = new Uint8Array(n); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out; },
    };
    return w.text(domain);
  }
  let contextPromise = null;
  const context = () => (contextPromise ??= sha(enc.encode('p-chat.release.v1')));
  async function statement(key, version, hash) {
    return writer('sg.net.observation.v1').text(key).digest(await context()).integer(0).integer(version)
      .text('p-chat').text('release').integer(1).text('release').bytes(hash).data();
  }

  function canonical(r) {
    const keys = [...r.committee.keys].sort();
    return JSON.stringify({ committee: { keys, quorum: r.committee.quorum }, manifest: r.manifest, previous: r.previous, sw: r.sw, version: r.version });
  }
  function wellFormed(r) {
    const c = r && r.committee;
    if (!r || !Number.isSafeInteger(r.version) || r.version < 1) throw new Error('a release has a version');
    if (!isHex(r.manifest, 64) || !isHex(r.sw, 64) || !isHex(r.previous, 64)) throw new Error('a release names its manifest, sw.js and the release before');
    if (!c || !Array.isArray(c.keys) || !c.keys.length || c.keys.length > 16 || !c.keys.every((k) => isHex(k, 64)) || new Set(c.keys).size !== c.keys.length)
      throw new Error('a committee is 1..16 distinct keys');
    if (!Number.isInteger(c.quorum) || c.quorum < 1 || c.quorum > c.keys.length || 2 * c.quorum <= c.keys.length) throw new Error('a quorum is more than half');
    if (!Array.isArray(r.signatures)) throw new Error('a release is signed');
  }
  async function hashOf(r) { return hex(await sha(enc.encode(canonical(r)))); }

  // Signatures of `by` (a committee) on record r: how many distinct members signed it, rightly.
  async function signedBy(r, by) {
    const hash = unhex(await hashOf(r));
    const seen = new Set();
    for (const s of r.signatures) {
      if (!s || !isHex(s.key, 64) || !isHex(s.sig, 128) || seen.has(s.key) || !by.keys.includes(s.key)) continue;
      const key = await crypto.subtle.importKey('raw', unhex(s.key), { name: 'Ed25519' }, false, ['verify']);
      if (await crypto.subtle.verify({ name: 'Ed25519' }, key, unhex(s.sig), await statement(s.key, r.version, hash))) seen.add(s.key);
    }
    return seen.size;
  }

  // A head this device keeps: {version, hash, committee}. The first record of
  // a chain is checked against its own committee and the hash sw.js names.
  async function genesis(r, expect) {
    wellFormed(r);
    if (r.previous !== ZERO) throw new Error('the first release names none before it');
    const hash = await hashOf(r);
    if (expect && hash !== expect) throw new Error('not the first release this site was made with');
    if ((await signedBy(r, r.committee)) < r.committee.quorum) throw new Error('the first release is not signed by its committee');
    return { version: r.version, hash, committee: r.committee, manifest: r.manifest, sw: r.sw };
  }
  // One step: r follows head. Refused otherwise, with why.
  async function step(head, r) {
    wellFormed(r);
    if (r.version <= head.version) throw new Error(`release ${r.version} is not newer than ${head.version} (a downgrade)`);
    if (r.previous !== head.hash) throw new Error(`release ${r.version} does not follow release ${head.version} (a broken link)`);
    const n = await signedBy(r, head.committee);
    if (n < head.committee.quorum) throw new Error(`release ${r.version} has ${n} of the ${head.committee.quorum} signatures it needs`);
    return { version: r.version, hash: await hashOf(r), committee: r.committee, manifest: r.manifest, sw: r.sw };
  }
  // A chain from the device's head (or the first record) to its end, link by
  // link: every version it skipped is checked on the way.
  async function follow(head, chain, expectGenesis) {
    if (!Array.isArray(chain) || !chain.length) throw new Error('no release chain');
    let at = head;
    let i = 0;
    if (!at) {
      at = await genesis(chain[0], expectGenesis);
      i = 1;
    } else {
      // Where this device is in it: its head's own record.
      const hashes = await Promise.all(chain.map(hashOf));
      const k = hashes.indexOf(at.hash);
      if (k < 0) throw new Error('the chain does not pass through this device\'s release');
      i = k + 1;
    }
    for (; i < chain.length; i++) at = await step(at, chain[i]);
    return at;
  }
  // The bundle a record names: manifest.json's bytes, and each file's.
  async function checkBundle(head, manifestBytes, files) {
    if (hex(await sha(manifestBytes)) !== head.manifest) throw new Error('manifest.json is not the one the release names');
    const m = JSON.parse(new TextDecoder().decode(manifestBytes));
    if (m.version !== head.version) throw new Error('manifest.json is for another version');
    for (const [path, want] of Object.entries(m.files)) {
      const body = files.get(path);
      if (!body) throw new Error('a file is missing: ' + path);
      if (hex(await sha(body)) !== want) throw new Error('a file does not match the manifest: ' + path);
    }
    if (!files.get('sw.js') || hex(await sha(files.get('sw.js'))) !== head.sw) throw new Error('sw.js is not the one the release names');
    return m;
  }
  // Two records for one version, both signed: a fork. Evidence, never taken.
  async function fork(a, b) {
    if (a.version !== b.version || (await hashOf(a)) === (await hashOf(b))) return false;
    for (const s of a.signatures) {
      const other = b.signatures.find((t) => t.key === s.key);
      if (!other) continue;
      // The same member signed both: an equivocation of its own.
      const key = await crypto.subtle.importKey('raw', unhex(s.key), { name: 'Ed25519' }, false, ['verify']);
      const okA = await crypto.subtle.verify({ name: 'Ed25519' }, key, unhex(s.sig), await statement(s.key, a.version, unhex(await hashOf(a))));
      const okB = await crypto.subtle.verify({ name: 'Ed25519' }, key, unhex(other.sig), await statement(s.key, b.version, unhex(await hashOf(b))));
      if (okA && okB) return true;
    }
    return false;
  }
  g.pchatRelease = { canonical, hashOf, statement, genesis, step, follow, checkBundle, fork, signedBy, ZERO, hex, unhex };
})(globalThis);
