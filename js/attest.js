// The attestation: two signed events that tie a site's child key to the master key. Pure.
//
// DRAFT. Not a registered NIP; the kind and tags are expected to change.
// The master signs "this child key is mine, for this site". The child signs "this is my master".
// One alone proves nothing: anyone can name any key. Both together mean each key's holder agreed.

import { signEvent, verifyEvent } from './event.js';
import { pubkeyOf } from './derive.js';
import { siteOrigin, isSiteOrigin } from './origin.js';

/** An addressable kind (30000-39999), so each pair replaces the last one for the same keys. DRAFT. */
export const KIND = 30437;

/** The value of the one tag called `name`, or undefined if there is none or more than one. */
const one = (tags, name) => {
  const found = tags.filter((t) => t[0] === name);
  return found.length === 1 && found[0].length >= 2 ? found[0][1] : undefined;
};

function template(rel, other, origin, createdAt, expiration, content) {
  const tags = [['d', other], ['p', other], ['rel', rel], ['origin', origin]];
  if (expiration !== undefined) tags.push(['expiration', String(expiration)]);
  return { kind: KIND, created_at: createdAt, tags, content };
}

/**
 * Both events for one site. `expiration` (unix seconds) is optional.
 * Returns { master, child }: master is signed by the master key, child by the child key.
 */
export function buildAttestation({ masterKey, childKey, origin, createdAt = Math.floor(Date.now() / 1000), expiration }) {
  const o = siteOrigin(origin);
  if (expiration !== undefined && (!Number.isSafeInteger(expiration) || expiration <= createdAt)) throw new Error('attest: expiration must be after created_at');
  const m = pubkeyOf(masterKey), c = pubkeyOf(childKey);
  if (m === c) throw new Error('attest: the two keys are the same');
  return {
    master: signEvent(template('child', c, o, createdAt, expiration, `This key is mine, made for ${o}.`), masterKey),
    child: signEvent(template('master', m, o, createdAt, expiration, `My master key made me for ${o}.`), childKey),
  };
}

/**
 * Check a pair. `origin`, if given, must be the origin both events name (a site checks its own).
 * `now` is unix seconds, for the expiration check.
 * Returns { ok: true, masterPubkey, childPubkey, origin } or { ok: false, reason }.
 */
export function verifyAttestation(master, child, { origin, now = Math.floor(Date.now() / 1000) } = {}) {
  const no = (reason) => ({ ok: false, reason });
  if (!master || !child) return no('missing event');
  if (master.kind !== KIND || child.kind !== KIND) return no('wrong kind');
  if (!verifyEvent(master)) return no('master event: bad id or signature');
  if (!verifyEvent(child)) return no('child event: bad id or signature');
  const m = master.pubkey, c = child.pubkey;
  if (m === c) return no('the two keys are the same');
  if (one(master.tags, 'd') !== c || one(master.tags, 'p') !== c) return no('master event does not name this child');
  if (one(child.tags, 'd') !== m || one(child.tags, 'p') !== m) return no('child event does not name this master');
  if (one(master.tags, 'rel') !== 'child' || one(child.tags, 'rel') !== 'master') return no('roles are not master and child');
  const o = one(master.tags, 'origin');
  if (!isSiteOrigin(o) || one(child.tags, 'origin') !== o) return no('origins missing or different');
  if (origin !== undefined && o !== origin) return no('made for a different site');
  for (const e of [master, child]) {
    const has = e.tags.some((t) => t[0] === 'expiration');
    if (!has) continue;
    const x = one(e.tags, 'expiration');
    if (x === undefined || !/^[0-9]{1,15}$/.test(x)) return no('bad expiration');
    if (Number(x) <= now) return no('expired');
  }
  return { ok: true, masterPubkey: m, childPubkey: c, origin: o };
}
