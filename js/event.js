// Nostr events (NIP-01): the id, signing and checking. Pure.

import { schnorr, sha256 } from '../vendor/noble.js';
import { bytesToHex, hexToBytes, utf8ToBytes, isHex32 } from './bytes.js';

const isTags = (t) => Array.isArray(t) && t.every((x) => Array.isArray(x) && x.every((v) => typeof v === 'string'));

/** The event id: SHA-256 of [0, pubkey, created_at, kind, tags, content] as JSON. */
export function eventId(e) {
  if (!isHex32(e?.pubkey)) throw new Error('event: bad pubkey');
  if (!Number.isSafeInteger(e.created_at) || e.created_at < 0) throw new Error('event: bad created_at');
  if (!Number.isSafeInteger(e.kind) || e.kind < 0 || e.kind > 65535) throw new Error('event: bad kind');
  if (!isTags(e.tags)) throw new Error('event: bad tags');
  if (typeof e.content !== 'string') throw new Error('event: bad content');
  return bytesToHex(sha256(utf8ToBytes(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content]))));
}

/** Sign an event template ({ created_at, kind, tags, content }) with a secret key. */
export function signEvent(t, secretKey) {
  const e = { pubkey: bytesToHex(schnorr.getPublicKey(secretKey)), created_at: t.created_at, kind: t.kind, tags: t.tags, content: t.content };
  const id = eventId(e);
  return { id, ...e, sig: bytesToHex(schnorr.sign(hexToBytes(id), secretKey)) };
}

/** True only if the id matches the event and the signature is the pubkey's, over that id. */
export function verifyEvent(e) {
  try {
    if (typeof e?.id !== 'string' || eventId(e) !== e.id) return false;
    if (typeof e.sig !== 'string' || !/^[0-9a-f]{128}$/.test(e.sig)) return false;
    return schnorr.verify(hexToBytes(e.sig), hexToBytes(e.id), hexToBytes(e.pubkey));
  } catch { return false; }
}
