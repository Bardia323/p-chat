// Phase 4 under Node: the vectors made in Wasm, and WebCrypto's part of
// them, byte for byte against the native file.
//   node node_vectors.mjs <build>/sgchat_vectors_wasm.js tests/vectors/v4.json
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { check } from './webcrypto_checks.mjs';
import '../web/release.js';  // the release chain's checks (sets globalThis.pchatRelease)

const require = createRequire(import.meta.url);
const [vectorsJs, file] = process.argv.slice(2).map((p) => resolve(p));
const createVectors = require(vectorsJs);
const createChat = require(join(dirname(vectorsJs), 'sgchat.js'));
const vectorsModule = await createVectors();
const chat = await createChat();
const made = JSON.parse(vectorsModule.vectors());
const kept = JSON.parse(readFileSync(file, 'utf8'));
const { fails, argonMs } = await check(chat, made, kept);
for (const f of fails) console.error('FAIL', f);
console.log(`argon2id (32 MiB, 2 passes) in Wasm under Node: ${argonMs} ms`);
if (fails.length) {
  console.error(`sgchat_vectors_node: ${fails.length} failed`);
  process.exit(1);
}
console.log('sgchat_vectors_node: ok');
