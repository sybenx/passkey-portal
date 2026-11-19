// A test page, not part of the portal. It answers one question on a real device: does this passkey
// manager keep a 33-byte value in the passkey's user handle (user.id) and hand it back unchanged?
// That is what a portal without PRF would rely on. The value here is random and opens nothing.
//
// Browser only (WebAuthn).

import { randomBytes, sha256 } from '../vendor/noble.js';
import { bytesToHex } from './bytes.js';
import { PRF_SALT } from './derive.js';
import { $, say, listOf, refuseFrames } from './ui.js';

const TIMEOUT = 120000;
const HANDLE_KIND = 0x03;   // marks "the secret is in the handle"; 0x01 and 0x02 are taken on the mirrors branch
const HANDLE_LENGTH = 33;   // the kind byte, then 32 bytes

let expected = null;        // the fingerprint from step 1, while this page stays open

/** A short code for a value, so two values can be compared without showing either. */
const fingerprint = (bytes) => bytesToHex(sha256(bytes)).slice(0, 12);

/** Bit 2 of the flags byte in authenticator data: the passkey checked it was you. */
const verified = (authData) => (new Uint8Array(authData)[32] & 0x04) !== 0;

const yesNo = (v) => (v === true ? 'yes' : v === false ? 'no' : 'not reported');

function why(e) {
  if (e?.name === 'NotAllowedError') return 'Cancelled, timed out, or not allowed by the browser or passkey manager.';
  return `${e?.name || 'Error'}: ${e?.message || e}`;
}

async function make() {
  say('verdict', '');
  listOf('made', ['Waiting for your passkey manager…']);
  const handle = new Uint8Array(HANDLE_LENGTH);
  handle[0] = HANDLE_KIND;
  handle.set(randomBytes(32), 1);
  const made = new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: randomBytes(32),
        rp: { id: location.hostname, name: 'Passkey Portal' },
        user: { id: handle, name: `Handle test ${made}`, displayName: `Handle test ${made}` },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
        attestation: 'none', timeout: TIMEOUT,
        extensions: {
          credProps: true,
          // Asks a hardware key to demand its PIN or fingerprint before giving anything about this passkey.
          credentialProtectionPolicy: 'userVerificationRequired',
          enforceCredentialProtectionPolicy: false,
          prf: {},
        },
      },
    });
    const ext = cred.getClientExtensionResults?.() ?? {};
    const authData = cred.response.getAuthenticatorData?.();
    expected = fingerprint(handle);
    listOf('made', [
      'Saved.',
      `Fingerprint of the value stored: ${expected}`,
      `Stored length: ${HANDLE_LENGTH} bytes`,
      `Checked it was you: ${authData ? yesNo(verified(authData)) : 'not reported'}`,
      `Saved so it can be found without a username: ${yesNo(ext.credProps?.rk)}`,
      `Says it supports PRF: ${yesNo(ext.prf?.enabled)}`,
    ]);
  } catch (e) {
    listOf('made', ['Could not make the passkey.', why(e)]);
  } finally {
    handle.fill(0);
  }
}

async function use() {
  say('verdict', '');
  listOf('used', ['Waiting for your passkey manager…']);
  try {
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32), rpId: location.hostname, userVerification: 'required', timeout: TIMEOUT,
        extensions: { prf: { eval: { first: PRF_SALT } } },
      },
    });
    const raw = cred.response.userHandle;
    const got = raw ? new Uint8Array(raw) : null;
    const prf = cred.getClientExtensionResults?.().prf?.results?.first;
    const lines = [];
    let ok = false;
    if (!got || got.length === 0) {
      lines.push('The passkey manager gave back no value at all.');
    } else {
      const fp = fingerprint(got);
      const shape = got.length === HANDLE_LENGTH && got[0] === HANDLE_KIND;
      lines.push(`Fingerprint of the value given back: ${fp}`);
      lines.push(`Length given back: ${got.length} bytes${shape ? '' : ' (not the test shape: is this a different passkey?)'}`);
      if (expected) lines.push(fp === expected ? 'Same as step 1.' : 'DIFFERENT from step 1.');
      else lines.push('Step 1 was not done on this page load, so compare the fingerprints by eye.');
      ok = shape && (!expected || fp === expected);
      got.fill(0);
    }
    lines.push(`Checked it was you: ${yesNo(verified(cred.response.authenticatorData))}`);
    lines.push(`Gave a PRF secret: ${yesNo(!!prf)}`);
    listOf('used', lines);
    say('verdict', ok
      ? (expected ? 'It works here: the value came back unchanged.' : 'A test value came back. Check the fingerprints match.')
      : 'It did not work here.');
  } catch (e) {
    listOf('used', ['Could not use the passkey.', why(e)]);
  }
}

function start() {
  if (refuseFrames()) return;
  if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials) {
    say('verdict', 'This browser cannot use passkeys on this page.');
    return;
  }
  $('make').addEventListener('click', make);
  $('use').addEventListener('click', use);
}

start();
