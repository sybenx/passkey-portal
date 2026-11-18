// Backup ("mirror") passkeys. Pure: WebCrypto only, no page, no storage, no network.
//
// The ROOT is the 32-byte PRF output of a person's first (original) passkey. All their keys come
// from it: fromPrf(root). A mirror is a passkey on another portal that carries a sealed copy of the
// root in its own largeBlob, locked with a key from the mirror passkey's own PRF output.
//
// A passkey says which kind it is in its user handle (user.id), which the browser returns on
// every sign-in:
//   16 bytes             made before mirrors existed: an original (fully random)
//   17 bytes, 0x01 | 16  an original: keys come straight from its PRF output
//   17 bytes, 0x02 | 16  a mirror: keys come only from the root in its blob
// Anything else is refused. A mirror never falls back to its own PRF output (that would be a
// different identity), and an original never reads a blob.

import { sha256, hkdf, randomBytes } from '../vendor/noble.js';
import { utf8ToBytes, concatBytes } from './bytes.js';

export class MirrorError extends Error {}

export const ORIGINAL = 0x01;
export const MIRROR = 0x02;
const HANDLE_LEN = 17, OLD_HANDLE_LEN = 16;

/** A new user handle for a passkey of this type. */
export function makeHandle(type, random = randomBytes(16)) {
  if (type !== ORIGINAL && type !== MIRROR) throw new Error('handle: unknown type');
  if (!(random instanceof Uint8Array) || random.length !== 16) throw new Error('handle: need 16 random bytes');
  return concatBytes(Uint8Array.of(type), random);
}

/** 'original' or 'mirror' from a user handle; an error for anything this code did not make. */
export function handleKind(handle) {
  const h = handle instanceof ArrayBuffer ? new Uint8Array(handle) : handle;
  if (!(h instanceof Uint8Array)) throw new MirrorError('This passkey did not say what kind it is.');
  if (h.length === OLD_HANDLE_LEN) return 'original';
  if (h.length === HANDLE_LEN && h[0] === ORIGINAL) return 'original';
  if (h.length === HANDLE_LEN && h[0] === MIRROR) return 'mirror';
  throw new MirrorError('This passkey was not made by this portal in a way it understands.');
}

// The blob: version (1 byte) | nonce (12) | AES-256-GCM of the root (32 + 16 tag) = 61 bytes.
const VERSION = 0x01, NONCE = 12, BLOB_LEN = 1 + NONCE + 32 + 16;
const WRAP_SALT = utf8ToBytes('passkey-portal mirror v1');
const WRAP_INFO = utf8ToBytes('passkey-portal mirror wrap v1');
const AAD_LABEL = utf8ToBytes('passkey-portal mirror blob');
const aad = (version) => concatBytes(Uint8Array.of(version), AAD_LABEL);

async function wrapKey(wrapPrf) {
  if (!(wrapPrf instanceof Uint8Array) || wrapPrf.length !== 32) throw new MirrorError('mirror: need the passkey\'s 32-byte secret');
  const raw = hkdf(sha256, wrapPrf, WRAP_SALT, WRAP_INFO, 32);
  try { return await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']); } finally { raw.fill(0); }
}

/** Seal the root for a mirror passkey whose PRF output is `wrapPrf`. */
export async function sealRoot(wrapPrf, root, nonce = randomBytes(NONCE)) {
  if (!(root instanceof Uint8Array) || root.length !== 32) throw new MirrorError('mirror: the root must be 32 bytes');
  const key = await wrapKey(wrapPrf);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(VERSION) }, key, root));
  return concatBytes(Uint8Array.of(VERSION), nonce, ct);
}

/** The root from a blob, or a MirrorError if it is missing, the wrong shape, or does not open. */
export async function openRoot(wrapPrf, blob) {
  const b = blob instanceof ArrayBuffer ? new Uint8Array(blob) : blob;
  if (!(b instanceof Uint8Array) || b.length === 0) throw new MirrorError('The backup copy is missing from this passkey.');
  if (b[0] !== VERSION) throw new MirrorError('The backup copy is in a format this portal does not know.');
  if (b.length !== BLOB_LEN) throw new MirrorError('The backup copy is damaged.');
  const key = await wrapKey(wrapPrf);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.subarray(1, 1 + NONCE), additionalData: aad(b[0]) }, key, b.subarray(1 + NONCE)));
  } catch { throw new MirrorError('The backup copy does not open with this passkey.'); }
}

/**
 * The root from what a sign-in returned: { handle, prf, blob }.
 * Returns { root, kind }. An original's root is its PRF output, and its blob is never looked at.
 * A mirror's root is only ever its opened blob.
 */
export async function rootFrom({ handle, prf, blob }) {
  const kind = handleKind(handle);
  if (!(prf instanceof Uint8Array) || prf.length !== 32) throw new MirrorError('This passkey gave no secret.');
  if (kind === 'original') return { root: Uint8Array.from(prf), kind };
  try { return { root: await openRoot(prf, blob), kind }; }
  catch (e) { throw new MirrorError(`This backup passkey can't open your identity right now. ${e.message} Nothing else was tried, so no different identity was made. Use your original portal, or another backup.`); }
}

/** Messages between a portal offering a copy (A) and the portal making the backup (B). */
export const HELLO = 'passkey-portal/mirror-hello'; // A -> B, repeated until B answers
export const READY = 'passkey-portal/mirror-ready'; // B -> A: B lists A, the person is looking
export const WANT = 'passkey-portal/mirror-want';   // B -> A: the backup passkey exists, send the root
export const ROOT = 'passkey-portal/mirror-root';   // A -> B: { root }
export const DONE = 'passkey-portal/mirror-done';   // B -> A: { masterPubkey } after B read it back
export const FAILED = 'passkey-portal/mirror-failed'; // B -> A: { reason }
