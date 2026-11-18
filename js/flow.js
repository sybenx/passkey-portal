// What the sign-in popup sends back to a site, and how the site checks it. Pure, so the whole
// flow except the passkey tap can be tested in Node.

import { fromPrf, childKey, pubkeyOf } from './derive.js';
import { nsecEncode, nsecDecode, npubEncode } from './nip19.js';
import { buildAttestation, verifyAttestation } from './attest.js';
import { siteOrigin } from './origin.js';
import { wipe } from './bytes.js';

/** Message types sent by postMessage between a site and the popup. */
export const REQUEST = 'passkey-portal/request';
export const READY = 'passkey-portal/ready';
export const ANSWER = 'passkey-portal/answer';
export const REFUSED = 'passkey-portal/refused';

/** The answer for one site from the person's root (an original passkey's PRF output). The master key is wiped before returning. */
export function answerFor(root, origin, { createdAt, expiration } = {}) {
  const o = siteOrigin(origin);
  const { masterKey, childSeed } = fromPrf(root);
  const child = childKey(childSeed, o);
  try {
    const attestation = buildAttestation({ masterKey, childKey: child, origin: o, createdAt, expiration });
    return { type: ANSWER, origin: o, childNsec: nsecEncode(child), childPubkey: pubkeyOf(child), masterPubkey: pubkeyOf(masterKey), attestation };
  } finally { wipe(masterKey, childSeed, child); }
}

/**
 * What a site does with an answer: check the attestation was made for its own origin, and that the
 * nsec it was given is the child key the attestation names.
 * Returns { ok: true, childNsec, childNpub, masterNpub } or { ok: false, reason }.
 */
export function checkAnswer(a, ownOrigin, now) {
  if (a?.type !== ANSWER) return { ok: false, reason: 'not an answer' };
  const v = verifyAttestation(a.attestation?.master, a.attestation?.child, { origin: ownOrigin, now });
  if (!v.ok) return v;
  if (a.masterPubkey !== v.masterPubkey || a.childPubkey !== v.childPubkey) return { ok: false, reason: 'keys do not match the attestation' };
  let sk;
  try { sk = nsecDecode(a.childNsec); } catch { return { ok: false, reason: 'bad nsec' }; }
  const pk = pubkeyOf(sk);
  wipe(sk);
  if (pk !== v.childPubkey) return { ok: false, reason: 'the nsec is not the attested child' };
  return { ok: true, childNsec: a.childNsec, childNpub: npubEncode(v.childPubkey), masterNpub: npubEncode(v.masterPubkey) };
}
