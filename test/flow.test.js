// The sign-in flow end to end, with a made-up PRF output in place of the passkey tap.
// The WebAuthn part (js/passkey.js) cannot run in Node; it has to be tried in a browser.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { answerFor, checkAnswer, ANSWER } from '../js/flow.js';
import { fromPrf, childKey, pubkeyOf } from '../js/derive.js';
import { npubEncode, nsecDecode } from '../js/nip19.js';
import { bytesToHex } from '../js/bytes.js';

const fakePrf = () => Uint8Array.from({ length: 32 }, (_, i) => i * 7 + 1);
const site = 'https://demo.example', T = 1790000000;

test('end to end: passkey secret -> answer -> the site checks it', () => {
  const a = answerFor(fakePrf(), site, { createdAt: T });
  // What crosses postMessage is plain data: JSON round trip, as structured clone would.
  const got = JSON.parse(JSON.stringify(a));
  assert.equal(got.type, ANSWER);
  const r = checkAnswer(got, site, T);
  assert.equal(r.ok, true, r.reason);

  const { masterKey, childSeed } = fromPrf(fakePrf());
  assert.equal(r.masterNpub, npubEncode(pubkeyOf(masterKey)));
  assert.equal(r.childNpub, npubEncode(pubkeyOf(childKey(childSeed, site))));
  assert.notEqual(r.childNpub, r.masterNpub);
  // The site gets its own child nsec, never the master's.
  assert.notEqual(bytesToHex(nsecDecode(got.childNsec)), bytesToHex(masterKey));
  assert.ok(!JSON.stringify(got).includes(bytesToHex(masterKey)));
  assert.ok(!JSON.stringify(got).includes(bytesToHex(childSeed)));
});

test('the same passkey gives the same keys next time', () => {
  const a = answerFor(fakePrf(), site, { createdAt: T }), b = answerFor(fakePrf(), site, { createdAt: T + 500 });
  assert.equal(a.childNsec, b.childNsec);
  assert.equal(a.masterPubkey, b.masterPubkey);
});

test('an answer made for one site does not work on another', () => {
  const a = answerFor(fakePrf(), site, { createdAt: T });
  assert.equal(checkAnswer(a, 'https://evil.example', T).ok, false);
  const other = answerFor(fakePrf(), 'https://evil.example', { createdAt: T });
  assert.notEqual(other.childNsec, a.childNsec);
  assert.equal(other.masterPubkey, a.masterPubkey);
});

test('an answer whose nsec does not match the attestation is refused', () => {
  const a = answerFor(fakePrf(), site, { createdAt: T });
  const b = answerFor(fakePrf(), 'https://other.example', { createdAt: T });
  assert.equal(checkAnswer({ ...a, childNsec: b.childNsec }, site, T).ok, false);
  assert.equal(checkAnswer({ ...a, masterPubkey: a.childPubkey }, site, T).ok, false);
  assert.equal(checkAnswer({ ...a, type: 'x' }, site, T).ok, false);
});

test('a site that is not https gets nothing', () => {
  assert.throws(() => answerFor(fakePrf(), 'http://demo.example'));
  assert.ok(answerFor(fakePrf(), 'http://localhost:8001'));
});
