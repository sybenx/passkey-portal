// Lists of portal origins: the operator's mirror list, and the list a site tries in order. Pure.

import { isSiteOrigin } from './origin.js';

/** Valid portal origins from a list, in order, without repeats and without `self`. Junk is dropped. */
export function originList(list, self) {
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const o of list) if (isSiteOrigin(o) && o !== self && !out.includes(o)) out.push(o);
  return out;
}

/** True if this portal's own list names `origin`. Both portals must list each other. */
export const lists = (list, origin) => originList(list).includes(origin);

/** The portals a site was told to try: ?portal=a&portal=b or ?portal=a,b. Otherwise `fallback`. */
export function portalsFrom(search, fallback) {
  const asked = new URLSearchParams(search).getAll('portal').flatMap((p) => p.split(',')).map((p) => p.trim());
  const list = originList(asked);
  return list.length ? list : [fallback];
}

/**
 * Trying portals in turn, in one popup window. Call tick(now) often; it says what to do:
 *   'ask'     post the request to portals[i] again
 *   'next'    point the popup at portals[i] (just moved on: the last one did not answer in time)
 *   'give-up' none answered
 *   'wait'    heard back, nothing to do
 */
export function tryPortals(portals, now, wait = 5000) {
  let i = 0, since = now, heard = false, over = false;
  return {
    get current() { return portals[i]; },
    ready() { heard = true; },
    tick(t) {
      if (over) return 'give-up';
      if (heard) return 'wait';
      if (t - since < wait) return 'ask';
      if (i + 1 >= portals.length) { over = true; return 'give-up'; }
      i += 1; since = t;
      return 'next';
    },
  };
}
