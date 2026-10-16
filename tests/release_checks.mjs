// v1 §12: the release chain, as web/release.js checks it (the page, and
// sw.js, which has it written in). A committee of three, two of whom must
// sign; then the same chain cut by tools/release.py, checked here alike.
//
//   node tests/release_checks.mjs <web/release.js> <python> <tools/release.py> <wasm build>
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';

const [releaseJs, python, releasePy, wasm] = process.argv.slice(2);
await import(pathToFileURL(releaseJs).href);
const R = globalThis.pchatRelease;
const fails = [];
const ok = (cond, what) => { console.log((cond ? 'ok   ' : 'FAIL ') + what); if (!cond) fails.push(what); };
const refused = async (f, why) => { try { await f(); return false; } catch (e) { return !why || e.message.includes(why); } };
const enc = new TextEncoder();
const sha = async (b) => R.hex(await crypto.subtle.digest('SHA-256', b));

// ---- the members' keys, and records signed by some of them ----
const member = async () => {
  const k = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  return { key: k.privateKey, pub: R.hex(await crypto.subtle.exportKey('raw', k.publicKey)) };
};
const [a, b, c, d, e, f] = await Promise.all([member(), member(), member(), member(), member(), member()]);
const committee = (ms, quorum) => ({ keys: ms.map((m) => m.pub).sort(), quorum });
async function sign(r, ms) {
  const h = R.unhex(await R.hashOf(r));
  for (const m of ms) r.signatures.push({ key: m.pub, sig: R.hex(await crypto.subtle.sign({ name: 'Ed25519' }, m.key, await R.statement(m.pub, r.version, h))) });
  return r;
}
// A bundle: its files, its manifest, the record that names them.
async function bundle(version, text) {
  const files = new Map([['index.html', enc.encode('<p>' + text)], ['sw.js', enc.encode('// worker ' + text)], ['app.js', enc.encode('app ' + text)]]);
  const listed = {};
  for (const [p, body] of files) listed[p] = await sha(body);
  const manifest = enc.encode(JSON.stringify({ files: listed, version }));
  return { files, manifest, manifestHash: await sha(manifest), swHash: listed['sw.js'] };
}
async function record(version, previous, signers, next, made) {
  const bnd = made || (await bundle(version, 'v' + version));
  const r = { version, manifest: bnd.manifestHash, sw: bnd.swHash, previous, committee: next, signatures: [] };
  await sign(r, signers);
  return { r, bnd };
}

const abc = committee([a, b, c], 2);
const v1 = await record(1, R.ZERO, [a, b], abc);
const h1 = await R.genesis(v1.r);
ok(h1.version === 1, 'the first release, signed by two of its three');
ok(await refused(async () => R.genesis((await record(1, R.ZERO, [a], abc)).r), 'not signed'), 'the first release with one of the two signatures it needs is refused');
const v2 = await record(2, h1.hash, [a, c], abc);
const h2 = await R.follow(h1, [v1.r, v2.r]);
ok(h2.version === 2 && h2.hash === (await R.hashOf(v2.r)), 'a valid update: release 2 follows release 1, signed by two of three');
ok((await R.checkBundle(h2, v2.bnd.manifest, v2.bnd.files)).version === 2, 'its bundle: the manifest and every file are the ones named');

// ---- what is refused ----
const forged = await record(2, h1.hash, [a], abc);
forged.r.signatures.push({ key: b.pub, sig: forged.r.signatures[0].sig });  // a's signature passed off as b's
ok(await refused(() => R.step(h1, forged.r), '1 of the 2'), 'a bad signature: one forged, the release has 1 of the 2 it needs');
const outsider = await record(2, h1.hash, [a, d], abc);
ok(await refused(() => R.step(h1, outsider.r), '1 of the 2'), 'a signature of one outside the committee does not count');
const broken = await record(2, '1'.repeat(64), [a, b], abc);
ok(await refused(() => R.step(h1, broken.r), 'broken link'), 'a broken link: release 2 not following release 1');
ok(await refused(async () => R.step(h2, (await record(1, h2.hash, [a, b], abc)).r), 'downgrade'), 'a downgrade: release 1 after release 2');
ok(await refused(async () => R.step(h2, (await record(2, h2.hash, [a, b], abc)).r), 'downgrade'), 'the same version again: not newer');
const bad = new Map(v2.bnd.files);
bad.set('app.js', enc.encode('app v2, changed'));
ok(await refused(() => R.checkBundle(h2, v2.bnd.manifest, bad), 'does not match the manifest'), 'a file whose hash is not the manifest\'s');
ok(await refused(() => R.checkBundle(h2, enc.encode('{"version":2,"files":{}}'), v2.bnd.files), 'manifest.json is not the one'), 'a manifest that is not the one the release names');
const otherSw = await bundle(2, 'v2');
const swRecord = await record(2, h1.hash, [a, b], abc, { ...otherSw, swHash: '3'.repeat(64) });
const hsw = await R.step(h1, swRecord.r);
ok(await refused(() => R.checkBundle(hsw, otherSw.manifest, otherSw.files), 'sw.js is not the one'), 'an sw.js that is not the one the release names');

// ---- versions skipped are checked link by link ----
const v3 = await record(3, h2.hash, [b, c], abc);
const v4 = await record(4, await R.hashOf(v3.r), [a, b], abc);
const h4 = await R.follow(h1, [v1.r, v2.r, v3.r, v4.r]);
ok(h4.version === 4, 'from release 1 straight to 4: 2 and 3 checked on the way');
const v3bad = await record(3, h2.hash, [c], abc);
const v4after = await record(4, await R.hashOf(v3bad.r), [a, b], abc);
ok(await refused(() => R.follow(h1, [v1.r, v2.r, v3bad.r, v4after.r]), 'release 3 has 1 of the 2'),
  'a later release well signed does not carry one skipped that is not');
ok(await refused(() => R.follow(h1, [v1.r, v3.r, v4.r]), 'broken link'), 'a chain with a release missing is a broken link');

// ---- the committee hands over ----
const def = committee([d, e, f], 2);
const v5 = await record(5, h4.hash, [a, c], def);  // signed by the old, names the new
const h5 = await R.step(h4, v5.r);
const v6old = await record(6, h5.hash, [a, b], def);
ok(await refused(() => R.step(h5, v6old.r), '0 of the 2'), 'after a handover, the old committee cannot sign');
ok((await R.step(h5, (await record(6, h5.hash, [d, f], def)).r)).version === 6, 'the new one can');

// ---- a fork: two records signed as one version ----
const v2b = await record(2, h1.hash, [a, b], abc, await bundle(2, 'v2, another'));
ok(await R.fork(v2.r, v2b.r), 'two different releases 2, both signed by a: a fork, evidence');
ok(!(await R.fork(v2.r, v2.r)), 'the same release twice is not a fork');

// ---- the release tool: the same chain, cut by tools/release.py ----
const dir = mkdtempSync(join(tmpdir(), 'sgchat-release-'));
const keys = [1, 2, 3].map((i) => join(dir, `k${i}.pem`));
const pubs = keys.map((k) => execFileSync(python, [releasePy, 'keygen', '--key', k]).toString().trim().split(' ').pop());
const site = (v) => join(dir, 'site' + v);
execFileSync(python, [releasePy, 'build', '--version', '1', '--committee', pubs.join(','), '--quorum', '2', '--key', keys[0], '--key', keys[1],
  '--wasm', wasm, '--out', site(1)]);
execFileSync(python, [releasePy, 'build', '--version', '2', '--chain', join(site(1), 'chain.json'), '--key', keys[2], '--wasm', wasm, '--out', site(2)]);
ok(await refused(() => R.follow(null, JSON.parse(readFileSync(join(site(2), 'chain.json'))))), 'a release with one signature of two is not taken');
execFileSync(python, [releasePy, 'sign', '--key', keys[0], '--site', site(2)]);
const chain = JSON.parse(readFileSync(join(site(2), 'chain.json')));
const head = await R.follow(null, chain);
ok(head.version === 2, 'the release tool\'s chain holds here: release 1, then 2 signed by two (one after the other)');
const files = new Map();
const walk = (p) => { for (const n of readdirSync(p)) { const q = join(p, n); if (statSync(q).isDirectory()) walk(q); else files.set(relative(site(2), q).split('\\\\').join('/'), new Uint8Array(readFileSync(q))); } };
walk(site(2));
await R.checkBundle(head, files.get('manifest.json'), files);
ok(true, 'and its bundle: every file, sw.js with the first committee written in');
ok(readFileSync(join(site(2), 'sw.js'), 'utf8').includes(pubs.sort()[0]) && !readFileSync(join(site(2), 'sw.js'), 'utf8').includes('__RELEASE_JS__'),
  'sw.js carries the first committee and the chain\'s checks');
execFileSync(python, [releasePy, 'verify', '--site', site(2)]);
ok(true, 'and tools/release.py verify agrees');
writeFileSync(join(site(2), 'app.js'), 'changed');

if (fails.length) { console.log(`sgchat_release: ${fails.length} failed`); process.exit(1); }
console.log('sgchat_release: ok');
