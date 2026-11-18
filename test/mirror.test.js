import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sealRoot, openRoot, rootFrom, makeHandle, handleKind, MirrorError, ORIGINAL, MIRROR } from '../js/mirror.js';
import { fromPrf, childKey, pubkeyOf } from '../js/derive.js';
import { answerFor, checkAnswer } from '../js/flow.js';
import { bytesToHex, hexToBytes } from '../js/bytes.js';

const root = hexToBytes('11'.repeat(32));        // an original passkey's PRF output
const mirrorPrf = hexToBytes('a5'.repeat(32));   // a backup passkey's own PRF output
const rnd = (b) => new Uint8Array(16).fill(b);
const rejects = (p) => assert.rejects(p, MirrorError);

test('seal and open give the root back; the blob is 61 bytes with version 1 first', async () => {
  const blob = await sealRoot(mirrorPrf, root);
  assert.equal(blob.length, 61);
  assert.equal(blob[0], 1);
  assert.equal(bytesToHex(await openRoot(mirrorPrf, blob)), bytesToHex(root));
  assert.equal(bytesToHex(await openRoot(mirrorPrf, blob.buffer.slice(0))), bytesToHex(root), 'an ArrayBuffer works too');
  assert.notEqual(bytesToHex(await sealRoot(mirrorPrf, root)), bytesToHex(blob), 'a new nonce each time');
});

test('a wrong key, wrong version, truncated or tampered blob is refused', async () => {
  const blob = await sealRoot(mirrorPrf, root);
  await rejects(openRoot(hexToBytes('a6'.repeat(32)), blob));
  await rejects(openRoot(mirrorPrf, Uint8Array.of(2, ...blob.subarray(1))));
  await rejects(openRoot(mirrorPrf, blob.subarray(0, 60)));
  await rejects(openRoot(mirrorPrf, Uint8Array.of(...blob, 0)));
  for (const i of [1, 13, 30, 60]) { const t = Uint8Array.from(blob); t[i] ^= 1; await rejects(openRoot(mirrorPrf, t)); }
  await rejects(openRoot(mirrorPrf, undefined));
  await rejects(openRoot(mirrorPrf, new Uint8Array(0)));
});

test('the version byte and label are bound as additional data', async () => {
  // Same key and nonce, ciphertext made with different additional data: must not open.
  const { hkdf, sha256, utf8ToBytes } = await import('../vendor/noble.js');
  const raw = hkdf(sha256, mirrorPrf, utf8ToBytes('passkey-portal mirror v1'), utf8ToBytes('passkey-portal mirror wrap v1'), 32);
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  const iv = new Uint8Array(12);
  const noAad = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, root));
  await rejects(openRoot(mirrorPrf, Uint8Array.of(1, ...iv, ...noAad)));
  const good = await sealRoot(mirrorPrf, root, iv);
  assert.equal(bytesToHex(await openRoot(mirrorPrf, good)), bytesToHex(root));
});

test('user handle types, including the old 16-byte form', () => {
  assert.equal(handleKind(rnd(7)), 'original', 'old passkeys: 16 random bytes');
  assert.equal(handleKind(rnd(2)), 'original', 'old passkeys whose first random byte happens to be 2');
  assert.equal(handleKind(makeHandle(ORIGINAL, rnd(9))), 'original');
  assert.equal(handleKind(makeHandle(MIRROR, rnd(9))), 'mirror');
  assert.equal(makeHandle(MIRROR, rnd(9)).length, 17);
  assert.equal(handleKind(makeHandle(MIRROR, rnd(9)).buffer), 'mirror');
  for (const bad of [undefined, null, new Uint8Array(0), new Uint8Array(15), new Uint8Array(18), Uint8Array.of(3, ...rnd(0)), Uint8Array.of(0, ...rnd(0))])
    assert.throws(() => handleKind(bad), MirrorError);
  assert.throws(() => makeHandle(3));
});

test('an original and a mirror of it give the same keys, children and sign-in answers', async () => {
  const orig = await rootFrom({ handle: makeHandle(ORIGINAL), prf: root });
  const old = await rootFrom({ handle: rnd(4), prf: root });
  const mir = await rootFrom({ handle: makeHandle(MIRROR), prf: mirrorPrf, blob: await sealRoot(mirrorPrf, root) });
  assert.deepEqual([orig.kind, old.kind, mir.kind], ['original', 'original', 'mirror']);
  const k = [orig, old, mir].map((r) => fromPrf(r.root));
  for (const x of k.slice(1)) {
    assert.equal(pubkeyOf(x.masterKey), pubkeyOf(k[0].masterKey));
    assert.equal(bytesToHex(x.childSeed), bytesToHex(k[0].childSeed));
    assert.equal(bytesToHex(childKey(x.childSeed, 'https://site.example')), bytesToHex(childKey(k[0].childSeed, 'https://site.example')));
  }
  // The root of the pinned test vector in derive.test.js, so a mirror keeps existing identities.
  assert.equal(pubkeyOf(k[2].masterKey), '553da2c5fe55f47e1087f19abfe0f1f6f42adee30f780b5d82b9186eb85ba8d6');
  const T = 1790000000, a = answerFor(orig.root, 'https://site.example', { createdAt: T }), b = answerFor(mir.root, 'https://site.example', { createdAt: T });
  assert.equal(a.childNsec, b.childNsec);
  assert.equal(checkAnswer(b, 'https://site.example', T).ok, true);
});

test('a mirror with a missing or bad blob is an error, never its own PRF identity', async () => {
  const h = makeHandle(MIRROR);
  const blob = await sealRoot(mirrorPrf, root);
  const bad = Uint8Array.from(blob); bad[40] ^= 1;
  for (const b of [undefined, new Uint8Array(0), bad, blob.subarray(0, 30), await sealRoot(hexToBytes('01'.repeat(32)), root)]) {
    await assert.rejects(rootFrom({ handle: h, prf: mirrorPrf, blob: b }), (e) => e instanceof MirrorError && /backup passkey can't open your identity/.test(e.message));
  }
});

test('an original never reads a blob as its root', async () => {
  const other = hexToBytes('22'.repeat(32));
  const r = await rootFrom({ handle: makeHandle(ORIGINAL), prf: root, blob: await sealRoot(root, other) });
  assert.equal(bytesToHex(r.root), bytesToHex(root));
  await assert.rejects(rootFrom({ handle: undefined, prf: root }), MirrorError, 'no handle: refused, not guessed');
  await assert.rejects(rootFrom({ handle: makeHandle(ORIGINAL), prf: undefined }), MirrorError);
});
