import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAttestation, verifyAttestation, KIND } from '../js/attest.js';
import { fromPrf, childKey, pubkeyOf } from '../js/derive.js';
import { signEvent } from '../js/event.js';
import { hexToBytes } from '../js/bytes.js';

const site = 'https://site.example', T = 1790000000;
const keys = (b) => { const { masterKey, childSeed } = fromPrf(hexToBytes(b.repeat(32))); return { masterKey, childKey: childKey(childSeed, site) }; };
const A = keys('22'), B = keys('33');
const pair = (k = A, more = {}) => buildAttestation({ ...k, origin: site, createdAt: T, ...more });

/** Re-sign an event after changing it, so only the change itself can make it fail. */
const resign = (e, key, change) => signEvent({ ...e, ...change(e) }, key);

test('a valid pair verifies and names both keys', () => {
  const { master, child } = pair();
  const v = verifyAttestation(master, child, { origin: site, now: T });
  assert.deepEqual(v, { ok: true, masterPubkey: pubkeyOf(A.masterKey), childPubkey: pubkeyOf(A.childKey), origin: site });
  assert.equal(master.kind, KIND);
  assert.ok(KIND >= 30000 && KIND < 40000);
});

test('tampered content is refused', () => {
  const { master, child } = pair();
  assert.equal(verifyAttestation({ ...master, content: 'not mine' }, child).ok, false);
  assert.equal(verifyAttestation(master, { ...child, content: 'not mine' }).ok, false);
});

test('swapped keys are refused', () => {
  const a = pair(), b = pair(B);
  assert.equal(verifyAttestation(a.child, a.master).ok, false, 'master and child swapped');
  assert.equal(verifyAttestation(a.master, b.child).ok, false, 'child from another master');
  assert.equal(verifyAttestation(b.master, a.child).ok, false, 'master from another pair');
  // A master that claims someone else's child, properly signed by the master: the child never agreed.
  const claim = resign(a.master, A.masterKey, () => ({ tags: [['d', pubkeyOf(B.childKey)], ['p', pubkeyOf(B.childKey)], ['rel', 'child'], ['origin', site]] }));
  assert.equal(verifyAttestation(claim, b.child).ok, false);
  assert.equal(verifyAttestation(claim, a.child).ok, false);
});

test('the wrong origin is refused', () => {
  const { master, child } = pair();
  assert.equal(verifyAttestation(master, child, { origin: 'https://other.example' }).ok, false);
  const moved = resign(child, A.childKey, (e) => ({ tags: e.tags.map((t) => (t[0] === 'origin' ? ['origin', 'https://other.example'] : t)) }));
  assert.equal(verifyAttestation(master, moved).ok, false, 'events name different origins');
  const plainHttp = resign(master, A.masterKey, (e) => ({ tags: e.tags.map((t) => (t[0] === 'origin' ? ['origin', 'http://site.example'] : t)) }));
  assert.equal(verifyAttestation(plainHttp, child).ok, false);
});

test('the wrong kind is refused, even when properly signed', () => {
  const { master, child } = pair();
  assert.equal(verifyAttestation(resign(master, A.masterKey, () => ({ kind: 30438 })), child).ok, false);
  assert.equal(verifyAttestation(master, resign(child, A.childKey, () => ({ kind: 1 }))).ok, false);
});

test('a bad signature is refused', () => {
  const { master, child } = pair();
  const flip = (s) => (s[0] === '0' ? '1' : '0') + s.slice(1);
  assert.equal(verifyAttestation({ ...master, sig: flip(master.sig) }, child).ok, false);
  assert.equal(verifyAttestation(master, { ...child, sig: master.sig }).ok, false);
  // A child event signed by the master key instead of the child key.
  assert.equal(verifyAttestation(master, signEvent({ ...child }, A.masterKey)).ok, false);
});

test('roles and duplicate tags are checked', () => {
  const { master, child } = pair();
  assert.equal(verifyAttestation(resign(master, A.masterKey, (e) => ({ tags: e.tags.map((t) => (t[0] === 'rel' ? ['rel', 'master'] : t)) })), child).ok, false);
  assert.equal(verifyAttestation(resign(master, A.masterKey, (e) => ({ tags: [...e.tags, ['p', pubkeyOf(B.childKey)]] })), child).ok, false);
});

test('expiration: refused once passed, and must be well formed', () => {
  const { master, child } = pair(A, { expiration: T + 60 });
  assert.equal(verifyAttestation(master, child, { now: T + 59 }).ok, true);
  assert.deepEqual(verifyAttestation(master, child, { now: T + 60 }), { ok: false, reason: 'expired' });
  const odd = resign(master, A.masterKey, (e) => ({ tags: e.tags.map((t) => (t[0] === 'expiration' ? ['expiration', 'soon'] : t)) }));
  assert.equal(verifyAttestation(odd, child, { now: T }).ok, false);
  assert.throws(() => pair(A, { expiration: T }));
});
