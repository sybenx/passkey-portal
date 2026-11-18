import { test } from 'node:test';
import assert from 'node:assert/strict';
import { eventId, signEvent, verifyEvent } from '../js/event.js';
import { schnorr } from '../vendor/noble.js';
import { bytesToHex, hexToBytes } from '../js/bytes.js';

// Real kind-1 events by fiatjaf, as they came from a relay. Copied from nostr-tools' fakejson.test.ts
// (github.com/nbd-wtf/nostr-tools). Their ids and signatures were made by other software.
const real = [
  { tags: [], content: "so did we cut all corners and p2p stuff in order to make a decentralized social network that was fast and worked, but in the end what we got was a lot of very slow clients that can't handle the traffic of one jack dorsey tweet?", sig: 'ca62629d189edebb8f0811cfa0ac53015013df5f305dcba3f411ba15cfc4074d8c2d517ee7d9e81c9eb72a7328bfbe31c9122156397565ac55e740404e2b1fe7', id: 'fef2a50f7d9d3d5a5f38ee761bc087ec16198d3f0140df6d1e8193abf7c2b146', kind: 1, pubkey: '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d', created_at: 1671150419 },
  { content: 'a bunch of mfs interacted with my post using what I assume were "likes": https://nostr.build/i/964.png', created_at: 1672506879, id: 'f40bdd0905137ad60482537e260890ab50b0863bf16e67cf9383f203bd26c96f', kind: 1, pubkey: '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d', sig: '8b825d2d4096f0643b18ca39da59ec07a682cd8a3e717f119c845037573d98099f5bea94ec7ddedd5600c8020144a255ed52882a911f7f7ada6d6abb3c0a1eb4', tags: [] },
];

test('real NIP-01 events: our id matches and the signature checks', () => {
  for (const e of real) {
    assert.equal(eventId(e), e.id);
    assert.equal(verifyEvent(e), true);
  }
});

test('a changed real event fails', () => {
  assert.equal(verifyEvent({ ...real[0], content: real[0].content + '!' }), false);
  assert.equal(verifyEvent({ ...real[0], created_at: real[0].created_at + 1 }), false);
  assert.equal(verifyEvent({ ...real[0], sig: real[1].sig }), false);
});

// BIP-340 test vectors 0, 1 and 5 (github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv).
test('BIP-340 vectors', () => {
  const v0 = { sk: '0000000000000000000000000000000000000000000000000000000000000003', pk: 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9', aux: '00'.repeat(32), msg: '00'.repeat(32),
    sig: 'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0' };
  const v1 = { sk: 'b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef', pk: 'dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659', aux: '00'.repeat(31) + '01', msg: '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89',
    sig: '6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a' };
  for (const v of [v0, v1]) {
    assert.equal(bytesToHex(schnorr.getPublicKey(hexToBytes(v.sk))), v.pk);
    assert.equal(bytesToHex(schnorr.sign(hexToBytes(v.msg), hexToBytes(v.sk), hexToBytes(v.aux))), v.sig);
    assert.equal(schnorr.verify(hexToBytes(v.sig), hexToBytes(v.msg), hexToBytes(v.pk)), true);
  }
  // Vector 5: a public key that is not on the curve must fail.
  assert.equal(schnorr.verify(hexToBytes(v0.sig), hexToBytes(v0.msg), hexToBytes('eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34')), false);
});

test('signEvent makes an event verifyEvent accepts, and the id covers every field', () => {
  const sk = hexToBytes('01'.repeat(32));
  const e = signEvent({ created_at: 1700000000, kind: 1, tags: [['t', 'x']], content: 'hi' }, sk);
  assert.equal(verifyEvent(e), true);
  for (const change of [{ kind: 2 }, { tags: [] }, { content: 'ho' }, { pubkey: real[0].pubkey }, { id: real[0].id }])
    assert.equal(verifyEvent({ ...e, ...change }), false, JSON.stringify(change));
  assert.throws(() => eventId({ ...e, pubkey: 'AB' }));
  assert.throws(() => eventId({ ...e, tags: [[1]] }));
});
