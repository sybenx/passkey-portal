// Byte helpers every module shares. Pure: no page, no storage, no network.

import { sha256, bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '../vendor/noble.js';

export { bytesToHex, hexToBytes, utf8ToBytes, concatBytes };

/** The order of the secp256k1 group. A secret key is a number from 1 to N - 1. */
export const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const isHex32 = (h) => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h);
export { isHex32 };

/**
 * 32 bytes of hash output as a valid secret key. If the number is 0 or not below N (odds about
 * 1 in 2^128), the next try is SHA-256 of the bytes that failed, until one fits. The usual path is
 * the bytes as they are, so this never changes a key anyone already has.
 */
export function toScalar(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error('toScalar: need 32 bytes');
  let b = bytes;
  for (;;) {
    const x = BigInt('0x' + bytesToHex(b));
    if (x > 0n && x < N) return b;
    b = sha256(b);
  }
}

/** Overwrite a secret once it is no longer needed. Best effort: JavaScript may hold copies. */
export const wipe = (...bs) => { for (const b of bs) if (b instanceof Uint8Array) b.fill(0); };
