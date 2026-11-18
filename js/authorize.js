// The sign-in popup. Another site opens it and asks by postMessage. The site is known only by the
// message's origin, as the browser reports it, never by anything the site says about itself. The
// answer is posted to that exact origin and to the window that opened this one, then the popup closes.

import { answerFor, REQUEST, READY, REFUSED } from './flow.js';
import { isSiteOrigin } from './origin.js';
import { wipe } from './bytes.js';
import { cannotTry, usePasskey, createPasskey, PasskeyError, KNOWN_GAPS } from './passkey.js';
import { $, show, say, listOf, refuseFrames } from './ui.js';

let site = null;   // the origin that asked, once accepted
let nonce = '';    // echoed back so the site can match the answer to its request
let busy = false;
let stopped = false; // after a refusal, this popup answers nobody

function fail(title, text, { gaps = false, retry = false } = {}) {
  say('error-title', title); say('error-text', text);
  $('gaps').hidden = !gaps;
  if (gaps) listOf('gap-list', KNOWN_GAPS);
  $('again').hidden = !retry;
  show('error');
}

function send(msg) {
  if (!window.opener || window.opener.closed) throw new Error('The site that asked is gone.');
  window.opener.postMessage({ ...msg, nonce }, site); // exact origin, never '*'
}

function onMessage(e) {
  if (stopped || e.source !== window.opener || e.data?.type !== REQUEST) return;
  if (site) { if (e.origin === site) send({ type: READY }); return; } // the site asks again until it hears back
  if (!isSiteOrigin(e.origin)) {
    stopped = true;
    return fail('Not signed in', `${e.origin} is not using a secure (https) connection, so it can't get a key.`);
  }
  site = e.origin;
  nonce = typeof e.data.nonce === 'string' && e.data.nonce.length <= 128 ? e.data.nonce : '';
  say('origin', site);
  send({ type: READY });
  show('ask');
}

async function signIn(how) {
  if (busy || !site) return;
  busy = true;
  const why = await cannotTry();
  if (why) { busy = false; return fail('This device or browser can\'t do this', why, { gaps: true }); }
  say('busy-text', how === 'create' ? 'Making your passkey… you may be asked twice.' : 'Waiting for your passkey…');
  show('busy');
  try {
    const prf = how === 'create' ? await createPasskey() : await usePasskey();
    const answer = answerFor(prf, site);
    wipe(prf);
    send(answer);
    show('done');
    setTimeout(() => window.close(), 600);
  } catch (e) {
    const unsupported = e instanceof PasskeyError && e.kind === 'unsupported';
    fail(unsupported ? 'This device or browser can\'t do this' : 'Not signed in', e?.message || String(e), { gaps: unsupported, retry: !unsupported });
  } finally { busy = false; }
}

function start() {
  if (refuseFrames()) return;
  if (!window.opener) {
    return fail('Nothing to sign in to', 'Open this page from a site\'s "Sign in with portal" button.');
  }
  window.addEventListener('message', onMessage);
  $('use').addEventListener('click', () => signIn('use'));
  $('create').addEventListener('click', () => signIn('create'));
  $('again').addEventListener('click', () => show('ask'));
  $('no').addEventListener('click', () => { try { send({ type: REFUSED }); } catch { /* gone already */ } window.close(); });
  setTimeout(() => { if (!site && !stopped) { stopped = true; fail('Nothing to sign in to', 'No site asked for a sign-in.'); } }, 15000);
}

start();
