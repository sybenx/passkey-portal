// A stand-in for another site using "Sign in with portal". It opens the portal's authorize page,
// asks it by postMessage (to the portal's exact origin), and checks the answer it gets back.

import { checkAnswer, REQUEST, READY, ANSWER, REFUSED } from './flow.js';
import { isSiteOrigin } from './origin.js';
import { bytesToHex } from './bytes.js';
import { randomBytes } from '../vendor/noble.js';
import { $, say } from './ui.js';

// ?portal=https://portal.example picks the portal; without it, the one next to this page.
const asked = new URLSearchParams(location.search).get('portal');
const portalUrl = asked && isSiteOrigin(asked) ? `${asked}/authorize.html` : new URL('authorize.html', location.href).href;
const portalOrigin = new URL(portalUrl).origin;

let popup = null, nonce = '', poll = 0;

function stop() { clearInterval(poll); poll = 0; }

function onMessage(e) {
  if (e.origin !== portalOrigin || e.source !== popup || e.data?.nonce !== nonce) return;
  if (e.data.type === READY) { stop(); say('status', 'Waiting for you in the portal window…'); return; }
  if (e.data.type === REFUSED) { stop(); say('status', 'You chose not to sign in.'); return; }
  if (e.data.type !== ANSWER) return;
  stop();
  const r = checkAnswer(e.data, location.origin);
  if (!r.ok) { say('status', `The answer did not check out: ${r.reason}. Not signed in.`); return; }
  say('status', '');
  say('child-npub', r.childNpub);
  say('master-npub', r.masterNpub);
  say('events', JSON.stringify(e.data.attestation, null, 2));
  $('result').hidden = false;
}

function signIn() {
  $('result').hidden = true;
  nonce = bytesToHex(randomBytes(16));
  popup = window.open(portalUrl, 'passkey-portal', 'popup,width=440,height=720');
  if (!popup) { say('status', 'The portal window was blocked. Allow pop-ups for this page and try again.'); return; }
  say('status', 'Opening the portal…');
  stop();
  // The portal cannot hear us until it has loaded, so ask until it answers or the window closes.
  poll = setInterval(() => {
    if (popup.closed) { stop(); say('status', 'The portal window was closed.'); return; }
    popup.postMessage({ type: REQUEST, v: 1, nonce }, portalOrigin);
  }, 250);
}

say('portal', portalOrigin);
$('same-origin').hidden = portalOrigin !== location.origin;
window.addEventListener('message', onMessage);
$('signin').addEventListener('click', signIn);
