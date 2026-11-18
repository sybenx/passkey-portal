// The passkey, used only as a locked box that gives back the same 32 bytes each time: its PRF
// output for PRF_SALT. There is no server, so the challenge is random and nothing checks the
// signature; the passkey is never a login here, only the source of the secret.
//
// A backup ("mirror") passkey also carries a sealed copy of the person's root in its largeBlob;
// see js/mirror.js. Browser only (WebAuthn). This is the one part the Node tests cannot reach.

import { randomBytes } from '../vendor/noble.js';
import { PRF_SALT } from './derive.js';
import { makeHandle, rootFrom, ORIGINAL, MIRROR, MirrorError } from './mirror.js';

/** kind: 'unsupported' (this device or browser cannot do it), 'cancelled', 'failed' or 'mirror' (a backup that won't open). */
export class PasskeyError extends Error {
  constructor(kind, message) { super(message); this.kind = kind; }
}

const TIMEOUT = 120000;
const prfAsk = () => ({ prf: { eval: { first: PRF_SALT } } });
const unsupported = (why) => new PasskeyError('unsupported', why);
const bytes = (b) => (b ? new Uint8Array(b instanceof ArrayBuffer ? b : b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength)) : undefined);

/** Whether to even try. Returns a reason it cannot work, or null if it might. */
export async function cannotTry() {
  if (!window.isSecureContext) return 'This page is not on a secure (https) connection.';
  if (!window.PublicKeyCredential || !navigator.credentials) return 'This browser does not support passkeys.';
  try {
    const caps = await PublicKeyCredential.getClientCapabilities?.();
    if (caps && caps['extension:prf'] === false) return 'This browser has passkeys, but not the part this page needs (called PRF).';
  } catch { /* older browsers: just try */ }
  return null;
}

/** The 32-byte PRF output from an extension result, or undefined. */
const prfOut = (cred) => {
  const b = bytes(cred.getClientExtensionResults?.().prf?.results?.first);
  if (b && b.length !== 32) throw unsupported('The passkey gave back a secret of the wrong size.');
  return b;
};

/** Byte 32 of authenticator data holds the flags; 0x04 means the person was verified (fingerprint, face or PIN). */
const verified = (authData) => authData && new Uint8Array(authData)[32] & 0x04;

const call = async (fn, cancelled = 'The passkey request was cancelled or timed out.') => {
  try { return await fn(); } catch (e) {
    if (e?.name === 'NotAllowedError' || e?.name === 'AbortError') throw new PasskeyError('cancelled', cancelled);
    if (e?.name === 'NotSupportedError') throw unsupported('This device cannot make this kind of passkey.');
    if (e?.name === 'SecurityError') throw unsupported('The browser refused passkeys for this address.');
    throw new PasskeyError('failed', e?.message || String(e));
  }
};

const ask = (id, extensions) => navigator.credentials.get({
  publicKey: {
    challenge: randomBytes(32), rpId: location.hostname, userVerification: 'required', timeout: TIMEOUT,
    ...(id ? { allowCredentials: [{ type: 'public-key', id }] } : {}), extensions,
  },
});

/** One passkey use: { handle, prf, blob }. Asks for the PRF and the largeBlob together. */
async function assertion(id) {
  let cred;
  try { cred = await ask(id, { ...prfAsk(), largeBlob: { read: true } }); } catch (e) {
    // A browser that rejects the largeBlob request outright: ask again without it. An original
    // still works; a mirror then has no blob and stops with its own message.
    if (e?.name !== 'NotSupportedError' && e?.name !== 'TypeError') throw e;
    cred = await ask(id, prfAsk());
  }
  if (!verified(cred.response.authenticatorData)) throw unsupported('The passkey did not check it was you (fingerprint, face or PIN).');
  const prf = prfOut(cred);
  if (!prf) throw unsupported('This passkey cannot give the secret this page needs (no PRF result).');
  return { handle: bytes(cred.response.userHandle), prf, blob: bytes(cred.getClientExtensionResults?.().largeBlob?.blob) };
}

/**
 * Sign in with a passkey already saved for this site (`id` asks for that one only).
 * Returns { root, kind }: kind is 'original' or 'mirror'. The caller wipes the root when done.
 */
export async function usePasskey(id) {
  const a = await call(() => assertion(id));
  try { return await rootFrom(a); }
  catch (e) { throw e instanceof MirrorError ? new PasskeyError('mirror', e.message) : e; }
  finally { a.prf.fill(0); }
}

const today = () => new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });

function newCredential(type, name, extensions) {
  return navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      rp: { id: location.hostname, name: 'Passkey Portal' },
      user: { id: makeHandle(type), name, displayName: name },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
      attestation: 'none', timeout: TIMEOUT, extensions: { ...prfAsk(), ...extensions },
    },
  });
}

function checkMade(cred) {
  const prf = cred.getClientExtensionResults?.().prf;
  if (!prf || prf.enabled === false) throw unsupported('A passkey was saved, but it cannot give the secret this page needs (no PRF). You can delete it in your passkey settings.');
  const authData = cred.response.getAuthenticatorData?.();
  if (authData && !verified(authData)) throw unsupported('The passkey did not check it was you (fingerprint, face or PIN).');
}

/** Just the PRF output of one known passkey (no blob, no handle check: the caller knows what it made). */
export async function prfOf(id) {
  const cred = await call(() => ask(id, prfAsk()));
  const out = prfOut(cred);
  if (!out) throw unsupported('This passkey cannot give the secret this page needs (no PRF result).');
  return out;
}

/**
 * Make a new original passkey: a new, different identity. Returns { root, kind: 'original' }.
 * The handle is random after its type byte, so a new passkey never replaces an old one.
 */
export async function createPasskey() {
  const cred = await call(() => newCredential(ORIGINAL, `Nostr key ${today()}`, {}));
  checkMade(cred);
  // Some platforms say "enabled" when making the passkey but only give the secret when using it.
  return { root: prfOut(cred) ?? await prfOf(cred.rawId), kind: 'original' };
}

/**
 * Make a backup passkey here. It must support largeBlob, or nothing is made.
 * Returns { id, prf }: prf is undefined if the platform gives it only on use (then call prfOf).
 */
export async function createMirrorPasskey() {
  const cred = await call(() => newCredential(MIRROR, `Nostr key backup ${today()}`, { largeBlob: { support: 'required' } }),
    'Cancelled, or this device can\'t hold a backup on this portal (it needs a passkey feature called largeBlob).');
  checkMade(cred);
  if (cred.getClientExtensionResults?.().largeBlob?.supported !== true) {
    throw unsupported('This device can\'t hold a backup on this portal (no largeBlob). A passkey was saved but it can\'t open anything; you can delete it in your passkey settings.');
  }
  return { id: cred.rawId, prf: prfOut(cred) };
}

/** Write the sealed root into a backup passkey. */
export async function writeBlob(id, blob) {
  const cred = await call(() => ask(id, { largeBlob: { write: blob } }));
  if (cred.getClientExtensionResults?.().largeBlob?.written !== true) throw unsupported('This device would not save the backup copy into the passkey.');
}

/** The words for platforms known not to work (late 2026). Shown when it fails as unsupported. */
export const KNOWN_GAPS = [
  'Firefox on Android',
  'Samsung Pass as the passkey manager',
  'iPhone and iPad before iOS 18.4',
  'Using a passkey on another phone by scanning a QR code',
];
