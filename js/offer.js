// Portal A's side of making a backup on portal B. Started only by the person, while signed in,
// picking B from A's own list. The root goes only to B's exact origin, only to the window A opened
// itself, and only after B says it lists A and has made the backup passkey.

import { HELLO, READY, WANT, ROOT, DONE, FAILED } from './mirror.js';
import { bytesToHex } from './bytes.js';
import { randomBytes } from '../vendor/noble.js';

/**
 * Open `<target>/mirror.html` and hand it the root when it asks. Resolves when B has read the backup
 * back and named the same master key; rejects with a plain message otherwise.
 * `status(text)` is told what is happening.
 */
export function offerCopy(target, root, masterPubkey, status) {
  return new Promise((resolve, reject) => {
    const nonce = bytesToHex(randomBytes(16));
    const popup = window.open(`${target}/mirror.html`, '_blank', 'popup,width=440,height=720');
    if (!popup) return reject(new Error('The window was blocked. Allow pop-ups for this page and try again.'));
    let heard = false, sent = false;
    const started = Date.now();
    const end = (fn, v) => { clearInterval(poll); window.removeEventListener('message', onMessage); fn(v); };
    const poll = setInterval(() => {
      if (popup.closed) return end(reject, new Error('The backup window was closed before it finished.'));
      if (heard) return;
      if (Date.now() - started > 15000) { popup.close(); return end(reject, new Error(`${target} did not answer. It may be down, or not set up to take backups from here.`)); }
      popup.postMessage({ type: HELLO, nonce }, target);
    }, 250);
    function onMessage(e) {
      if (e.origin !== target || e.source !== popup || e.data?.nonce !== nonce) return;
      const t = e.data.type;
      if (t === READY) { heard = true; status(`Continue in the ${target} window.`); }
      else if (t === WANT && heard && !sent) {
        sent = true;
        popup.postMessage({ type: ROOT, nonce, root }, target); // the browser sends a copy, never to '*'
        status('Copy sent. Waiting for the backup to be checked…');
      } else if (t === DONE) {
        if (e.data.masterPubkey === masterPubkey) end(resolve, target);
        else end(reject, new Error('The backup opened a different identity. Do not rely on it.'));
      } else if (t === FAILED) end(reject, new Error(`No backup was saved: ${String(e.data.reason || 'it did not finish').replace(/\.$/, '')}.`));
    }
    window.addEventListener('message', onMessage);
  });
}
