// The passkey, used only as a locked box that gives back the same 32 bytes each time: its PRF
// output for PRF_SALT. There is no server, so the challenge is random and nothing checks the
// signature; the passkey is never a login here, only the source of the secret.
//
// Browser only (WebAuthn). This is the one part the Node tests cannot reach.

import { randomBytes } from '../vendor/noble.js';
import { PRF_SALT } from './derive.js';

/** kind: 'unsupported' (this device or browser cannot do it), 'cancelled', or 'failed'. */
export class PasskeyError extends Error {
  constructor(kind, message) { super(message); this.kind = kind; }
}

const TIMEOUT = 120000;
const prfAsk = () => ({ prf: { eval: { first: PRF_SALT } } });
const unsupported = (why) => new PasskeyError('unsupported', why);

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
  const r = cred.getClientExtensionResults?.().prf?.results?.first;
  if (!r) return undefined;
  const b = new Uint8Array(r instanceof ArrayBuffer ? r : r.buffer.slice(r.byteOffset, r.byteOffset + r.byteLength));
  if (b.length !== 32) throw unsupported('The passkey gave back a secret of the wrong size.');
  return b;
};

/** Byte 32 of authenticator data holds the flags; 0x04 means the person was verified (fingerprint, face or PIN). */
const verified = (authData) => authData && new Uint8Array(authData)[32] & 0x04;

const call = async (fn) => {
  try { return await fn(); } catch (e) {
    if (e?.name === 'NotAllowedError' || e?.name === 'AbortError') throw new PasskeyError('cancelled', 'The passkey request was cancelled or timed out.');
    if (e?.name === 'NotSupportedError') throw unsupported('This device cannot make this kind of passkey.');
    if (e?.name === 'SecurityError') throw unsupported('The browser refused passkeys for this address.');
    throw new PasskeyError('failed', e?.message || String(e));
  }
};

/** Use a passkey already saved for this site. `id`, if given, asks for that one only. */
export async function usePasskey(id) {
  const cred = await call(() => navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32), rpId: location.hostname, userVerification: 'required', timeout: TIMEOUT,
      ...(id ? { allowCredentials: [{ type: 'public-key', id }] } : {}),
      extensions: prfAsk(),
    },
  }));
  if (!verified(cred.response.authenticatorData)) throw unsupported('The passkey did not check it was you (fingerprint, face or PIN).');
  const out = prfOut(cred);
  if (!out) throw unsupported('This passkey cannot give the secret this page needs (no PRF result).');
  return out;
}

/**
 * Make a new passkey and return its secret. Each one is a different identity. The user id is
 * random, so a new passkey never replaces an old one on the same device.
 */
export async function createPasskey() {
  const made = new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  const cred = await call(() => navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      rp: { id: location.hostname, name: 'Passkey Portal' },
      user: { id: randomBytes(16), name: `Nostr key ${made}`, displayName: `Nostr key ${made}` },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
      attestation: 'none', timeout: TIMEOUT, extensions: prfAsk(),
    },
  }));
  const prf = cred.getClientExtensionResults?.().prf;
  if (!prf || prf.enabled === false) throw unsupported('A passkey was saved, but it cannot give the secret this page needs (no PRF). You can delete it in your passkey settings.');
  const authData = cred.response.getAuthenticatorData?.();
  if (authData && !verified(authData)) throw unsupported('The passkey did not check it was you (fingerprint, face or PIN).');
  // Some platforms say "enabled" when making the passkey but only give the secret when using it.
  return prfOut(cred) ?? usePasskey(cred.rawId);
}

/** The words for platforms known not to work (late 2026). Shown when it fails as unsupported. */
export const KNOWN_GAPS = [
  'Firefox on Android',
  'Samsung Pass as the passkey manager',
  'iPhone and iPad before iOS 18.4',
  'Using a passkey on another phone by scanning a QR code',
];
