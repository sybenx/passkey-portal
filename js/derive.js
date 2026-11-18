// Keys from the passkey's secret. Pure.
//
// The passkey gives 32 bytes (its PRF output for PRF_SALT). Two secrets come from them, each by
// HKDF-SHA256 with its own label, so neither tells you anything about the other:
//   the master key   the person's own nostr key
//   the child seed   makes a separate key for each site
// They are kept apart on purpose. One day the master key may move into a FROST setup where its nsec
// is never whole in one place; the child keys must still come back from the seed alone.

import { sha256, hkdf, hmac, schnorr } from '../vendor/noble.js';
import { utf8ToBytes, concatBytes, bytesToHex, toScalar } from './bytes.js';
import { siteOrigin } from './origin.js';

/** What the page asks the passkey's PRF for: SHA-256 of a fixed text. Changing it changes every key. */
export const PRF_SALT = sha256(utf8ToBytes('passkey-portal prf salt v1'));

const HKDF_SALT = utf8ToBytes('passkey-portal v1');
const MASTER_INFO = utf8ToBytes('passkey-portal master key v1');
const SEED_INFO = utf8ToBytes('passkey-portal child seed v1');
const CHILD_PREFIX = utf8ToBytes('passkey-portal child v1');

/** The two secrets from a PRF output. Both are 32 bytes; `masterKey` is a valid secret key. */
export function fromPrf(prf) {
  if (!(prf instanceof Uint8Array) || prf.length !== 32) throw new Error('fromPrf: need 32 bytes');
  return {
    masterKey: toScalar(hkdf(sha256, prf, HKDF_SALT, MASTER_INFO, 32)),
    childSeed: hkdf(sha256, prf, HKDF_SALT, SEED_INFO, 32),
  };
}

/**
 * The child key for one site: HMAC-SHA256(child seed, "passkey-portal child v1" ‖ origin), as a
 * valid secret key. The prefix has a fixed length, so prefix ‖ origin cannot be read two ways.
 *
 * This is NOT Keykin's child (account key + tweak). There, a child nsec with its tweak gives the
 * account key, so a child nsec is never formed. Here the child nsec is handed to the other site, so
 * it has to be a key of its own, with no path back to the master key or the seed.
 */
export function childKey(childSeed, origin) {
  if (!(childSeed instanceof Uint8Array) || childSeed.length !== 32) throw new Error('childKey: need a 32-byte seed');
  const o = siteOrigin(origin);
  return toScalar(hmac(sha256, childSeed, concatBytes(CHILD_PREFIX, utf8ToBytes(o))));
}

/** The x-only public key, hex, as nostr uses it. */
export const pubkeyOf = (secretKey) => bytesToHex(schnorr.getPublicKey(secretKey));
