// A stand-in for another site using "Sign in with portal". It opens a portal's authorize page,
// asks it by postMessage (to the portal's exact origin), and checks the answer it gets back.
// It can be given several portals (a person's original and backups): if one does not answer in a
// few seconds, the same window is pointed at the next. Each gives the same identity.

import { checkAnswer, REQUEST, READY, ANSWER, REFUSED } from './flow.js';
import { portalsFrom, tryPortals } from './portals.js';
import { bytesToHex } from './bytes.js';
import { randomBytes } from '../vendor/noble.js';
import { $, say } from './ui.js';

// ?portal=https://a.example&portal=https://b.example (or comma-separated); without it, the one next to this page.
const portals = portalsFrom(location.search, location.origin);
const page = (origin) => `${origin}/authorize.html`;

let popup = null, nonce = '', poll = 0, run = null;

function stop() { clearInterval(poll); poll = 0; }

function onMessage(e) {
  if (!run || e.origin !== run.current || e.source !== popup || e.data?.nonce !== nonce) return;
  if (e.data.type === READY) { run.ready(); say('status', `Waiting for you in the ${run.current} window…`); return; }
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
  stop();
  run = tryPortals(portals, Date.now());
  popup = window.open(page(run.current), 'passkey-portal', 'popup,width=440,height=720');
  if (!popup) { say('status', 'The portal window was blocked. Allow pop-ups for this page and try again.'); return; }
  say('status', `Opening ${run.current}…`);
  // A portal cannot hear us until it has loaded, so ask until it answers or the window closes.
  poll = setInterval(() => {
    if (popup.closed) { stop(); say('status', 'The portal window was closed.'); return; }
    const act = run.tick(Date.now());
    if (act === 'ask') { try { popup.postMessage({ type: REQUEST, v: 1, nonce }, run.current); } catch { /* still loading */ } }
    else if (act === 'next') { say('status', `No answer, trying ${run.current}…`); popup.location.href = page(run.current); }
    else if (act === 'give-up') { stop(); say('status', 'None of the portals answered.'); }
  }, 250);
}

say('portal', portals.join(', '));
$('same-origin').hidden = !portals.includes(location.origin);
window.addEventListener('message', onMessage);
$('signin').addEventListener('click', signIn);
