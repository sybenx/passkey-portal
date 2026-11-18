// Test vectors from NIP-19 itself (github.com/nostr-protocol/nips/blob/master/19.md).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { npubEncode, npubDecode, nsecEncode, nsecDecode } from '../js/nip19.js';
import { bytesToHex, hexToBytes } from '../js/bytes.js';

const vectors = [
  ['npub', '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e', 'npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg'],
  ['npub', '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d', 'npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6'],
  ['nsec', '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa', 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5'],
];

test('NIP-19 vectors encode and decode both ways', () => {
  for (const [kind, hex, b32] of vectors) {
    if (kind === 'npub') { assert.equal(npubEncode(hex), b32); assert.equal(npubDecode(b32), hex); }
    else { assert.equal(nsecEncode(hexToBytes(hex)), b32); assert.equal(bytesToHex(nsecDecode(b32)), hex); }
  }
});

test('a wrong prefix, a bad checksum and a wrong length are refused', () => {
  assert.throws(() => npubDecode(vectors[2][2]));
  assert.throws(() => nsecDecode(vectors[0][2]));
  const typo = vectors[0][2].slice(0, -1) + (vectors[0][2].endsWith('g') ? 'h' : 'g');
  assert.throws(() => npubDecode(typo));
  assert.throws(() => npubEncode('ab'));
  assert.throws(() => nsecEncode(new Uint8Array(33)));
});
