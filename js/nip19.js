// npub and nsec (NIP-19): 32 bytes in bech32. Pure.

import { bech32 } from '../vendor/noble.js';
import { bytesToHex, hexToBytes, isHex32 } from './bytes.js';

const encode = (prefix, bytes) => bech32.encode(prefix, bech32.toWords(bytes));

function decode(prefix, s) {
  if (typeof s !== 'string') throw new Error(`${prefix}: not text`);
  const { prefix: p, words } = bech32.decode(s.trim().toLowerCase());
  if (p !== prefix) throw new Error(`${prefix}: this is a ${p}`);
  const b = bech32.fromWords(words);
  if (b.length !== 32) throw new Error(`${prefix}: wrong length`);
  return Uint8Array.from(b);
}

/** Public key, hex, to npub. */
export function npubEncode(hex) {
  if (!isHex32(hex)) throw new Error('npub: need 64 hex characters');
  return encode('npub', hexToBytes(hex));
}
/** npub to public key, hex. */
export const npubDecode = (s) => bytesToHex(decode('npub', s));

/** Secret key, 32 bytes, to nsec. */
export function nsecEncode(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error('nsec: need 32 bytes');
  return encode('nsec', bytes);
}
/** nsec to secret key, 32 bytes. */
export const nsecDecode = (s) => decode('nsec', s);
