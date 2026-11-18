// Which site origins the portal will make a key for. Pure.

const LOCAL = new Set(['localhost', '127.0.0.1']);

/**
 * The origin back if it is one the portal serves, otherwise an error. It must be exactly a
 * browser's origin string (scheme, host, port if not the default; no path, no slash at the end),
 * https, or http only for localhost and 127.0.0.1 while testing.
 */
export function siteOrigin(o) {
  if (typeof o !== 'string' || o === 'null') throw new Error('origin: missing');
  let u;
  try { u = new URL(o); } catch { throw new Error('origin: not a web address'); }
  if (u.origin !== o) throw new Error('origin: not in the plain form a browser sends');
  if (u.protocol === 'https:') return o;
  if (u.protocol === 'http:' && LOCAL.has(u.hostname)) return o;
  throw new Error('origin: only https sites (or localhost for testing)');
}

/** True if `o` is fine for siteOrigin. */
export const isSiteOrigin = (o) => { try { siteOrigin(o); return true; } catch { return false; } };
