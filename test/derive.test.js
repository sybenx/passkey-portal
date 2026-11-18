import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fromPrf, childKey, pubkeyOf, PRF_SALT } from '../js/derive.js';
import { toScalar, bytesToHex, hexToBytes, N } from '../js/bytes.js';
import { siteOrigin, isSiteOrigin } from '../js/origin.js';
import { hkdfSync, createHmac, createHash } from 'node:crypto';

const prf = hexToBytes('11'.repeat(32));

test('derivation is deterministic', () => {
  const a = fromPrf(prf), b = fromPrf(Uint8Array.from(prf));
  assert.equal(bytesToHex(a.masterKey), bytesToHex(b.masterKey));
  assert.equal(bytesToHex(a.childSeed), bytesToHex(b.childSeed));
  assert.equal(bytesToHex(childKey(a.childSeed, 'https://a.example')), bytesToHex(childKey(b.childSeed, 'https://a.example')));
});

test('master key and child seed differ, and another PRF output gives other keys', () => {
  const a = fromPrf(prf), b = fromPrf(hexToBytes('12'.repeat(32)));
  assert.notEqual(bytesToHex(a.masterKey), bytesToHex(a.childSeed));
  assert.notEqual(bytesToHex(a.masterKey), bytesToHex(b.masterKey));
  assert.notEqual(bytesToHex(a.childSeed), bytesToHex(b.childSeed));
});

test('the same origin gives the same child; different origins give different children', () => {
  const { masterKey, childSeed } = fromPrf(prf);
  const a = childKey(childSeed, 'https://a.example'), a2 = childKey(childSeed, 'https://a.example');
  const b = childKey(childSeed, 'https://b.example'), aPort = childKey(childSeed, 'https://a.example:8443');
  const aHttp = childKey(childSeed, 'http://localhost:8000');
  assert.equal(bytesToHex(a), bytesToHex(a2));
  const all = [a, b, aPort, aHttp, masterKey].map(bytesToHex);
  assert.equal(new Set(all).size, all.length);
  assert.notEqual(pubkeyOf(a), pubkeyOf(masterKey));
});

test('fixed outputs, so a change to the derivation is noticed (these are this code\'s own values)', () => {
  const { masterKey, childSeed } = fromPrf(prf);
  assert.equal(bytesToHex(PRF_SALT).length, 64);
  assert.match(bytesToHex(masterKey), /^[0-9a-f]{64}$/);
  // Pinned on first run; see README "Keys". If these change, every person's keys change.
  assert.equal(pubkeyOf(masterKey), PINNED.master);
  assert.equal(pubkeyOf(childKey(childSeed, 'https://a.example')), PINNED.childA);
});

test('the derivation matches Node\'s own HKDF, HMAC and SHA-256 (a second implementation)', () => {
  const { masterKey, childSeed } = fromPrf(prf);
  const h = (info) => Buffer.from(hkdfSync('sha256', prf, 'passkey-portal v1', info, 32)).toString('hex');
  assert.equal(bytesToHex(masterKey), h('passkey-portal master key v1'));
  assert.equal(bytesToHex(childSeed), h('passkey-portal child seed v1'));
  const c = createHmac('sha256', childSeed).update('passkey-portal child v1' + 'https://a.example').digest('hex');
  assert.equal(bytesToHex(childKey(childSeed, 'https://a.example')), c);
  assert.equal(bytesToHex(PRF_SALT), createHash('sha256').update('passkey-portal prf salt v1').digest('hex'));
});

test('toScalar keeps a key in range, and moves 0 and N or more to the next valid one', () => {
  const ok = hexToBytes('01'.repeat(32));
  assert.equal(toScalar(ok), ok);
  for (const bad of ['00'.repeat(32), 'ff'.repeat(32), N.toString(16)]) {
    const x = BigInt('0x' + bytesToHex(toScalar(hexToBytes(bad))));
    assert.ok(x > 0n && x < N);
  }
  assert.throws(() => toScalar(new Uint8Array(31)));
});

test('the PRF output must be 32 bytes', () => {
  assert.throws(() => fromPrf(new Uint8Array(31)));
  assert.throws(() => fromPrf('11'.repeat(32)));
});

test('origins: https, or http on localhost; nothing else', () => {
  for (const o of ['https://a.example', 'https://a.example:8443', 'http://localhost:8000', 'http://127.0.0.1:5173', 'http://localhost'])
    assert.equal(siteOrigin(o), o);
  for (const o of ['http://a.example', 'https://a.example/', 'https://a.example/path', 'https://A.example', 'https://a.example:443',
    'null', '', 'file:///x', 'javascript:alert(1)', undefined, 'https://user@a.example', 'http://localhost.evil.example'])
    assert.equal(isSiteOrigin(o), false, String(o));
  const { childSeed } = fromPrf(prf);
  assert.throws(() => childKey(childSeed, 'https://a.example/'));
});

const PINNED = {
  master: '553da2c5fe55f47e1087f19abfe0f1f6f42adee30f780b5d82b9186eb85ba8d6',
  childA: '6c5b7d537a76ddf3566223df64ac6d3a391137b870de456c524b9e6a85a27d69',
};
