// Shared test vectors against the web client's implementation (the protocol helpers in app.js).
//
//   node tests/vectors.mjs
//
// tests/vectors/jcs.json: canonical JSON. tests/vectors/protocol.json: signed objects and their exact
// fields, timestamps, padding, WebAuthn assertions, key statement chains (see tests/make_vectors.py).
// The Python implementations are checked against the same files by tests/vectors.py. Prints one JSON
// object; exit 0 only if every vector is judged as the file says.
import { readFileSync } from 'node:fs';

const root = new URL('..', import.meta.url);
const source = readFileSync(new URL('server/public/assets/app.js', root), 'utf8');
// app.js is a page script, not a module: take the helper block's own text, so the test runs the shipped code.
const found = source.match(/\/\/ ---- begin: protocol helpers[^\n]*\n([\s\S]*?)\/\/ ---- end: protocol helpers/);
if (!found) throw new Error('protocol helper block not found in app.js');
const h = new Function(found[1] + 'return { b64u, unb64u, sha256, jcs, parseTs, shaped, pad, unpad, assertionProblem, replayFromAnchor, shapeAnswer, SHAPES, enc };')();

const read = (name) => JSON.parse(readFileSync(new URL('tests/vectors/' + name, root), 'utf8'));
const P = read('protocol.json');
const failed = [];
let count = 0;
const expect = (group, vector, got, want) => {
  count++;
  if (JSON.stringify(got) !== JSON.stringify(want)) failed.push({ group, vector, implementation: 'client', got, want });
};
const attempt = (fn) => { try { return fn(); } catch (e) { return null; } };

for (const v of read('jcs.json').vectors) expect('jcs', v.name, h.jcs(v.value), v.canonical);
for (const v of P.hashes) {
  expect('hashes', v.name, h.jcs(v.object), v.canonical);
  expect('hashes', v.name, h.b64u(await h.sha256(h.enc.encode(h.jcs(v.object)))), v.sha256);
}
for (const v of P.shapes) if (v.type in h.SHAPES) expect('shapes', v.name, h.shaped(v.object, v.type, v.extra), v.ok);
for (const v of P.timestamps) expect('timestamps', JSON.stringify(v.value), h.parseTs(v.value), v.seconds);
for (const v of P.padding) {
  expect('padding', v.name, h.b64u(h.pad(h.unb64u(v.plain), 4096)), v.padded);
  expect('padding', v.name, attempt(() => h.b64u(h.unpad(h.unb64u(v.padded), 4096))), v.plain);
}
for (const v of P.bad_padding) expect('bad_padding', v.name, attempt(() => h.b64u(h.unpad(h.unb64u(v.padded), 4096))), null);
const challenge = h.unb64u(P.challenge);
for (const v of P.assertions) {
  expect('assertions', v.name, await h.assertionProblem(v.assertion, challenge, v.credential, P.origin, P.rp_id), v.problem);
}
for (const v of P.chains) {
  expect('chains', v.name, await h.replayFromAnchor(P.recipient_id, P.enc_pubkey, v.anchor, v.items, P.origin, P.rp_id), v.result);
}
for (const v of P.answers) expect('answers', v.name, h.jcs(h.shapeAnswer(v.schema, v.choice, v.fields, v.comment)), h.jcs(v.answer));

console.log(JSON.stringify({ status: failed.length ? 'failed' : 'ok', checks: count, failed }, null, 4));
process.exit(failed.length ? 1 : 0);
