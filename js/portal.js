// The portal's home page: unlock the passkey, show the npub, let the person take their nsec.
// The keys are held in this module only while the page is open. Nothing is stored or sent.

import { fromPrf, pubkeyOf } from './derive.js';
import { npubEncode, nsecEncode } from './nip19.js';
import { wipe } from './bytes.js';
import { cannotTry, usePasskey, createPasskey, PasskeyError, KNOWN_GAPS } from './passkey.js';
import { $, show, say, copyButton, listOf, refuseFrames } from './ui.js';

let keys = null; // { masterKey, childSeed } while unlocked

function forget() {
  if (keys) wipe(keys.masterKey, keys.childSeed);
  keys = null;
  say('npub', ''); say('nsec', '');
}

function fail(e) {
  const unsupported = e instanceof PasskeyError && e.kind === 'unsupported';
  say('error-title', unsupported ? 'This device or browser can\'t do this' : e?.kind === 'cancelled' ? 'Cancelled' : 'That didn\'t work');
  say('error-text', e?.message || String(e));
  $('gaps').hidden = !unsupported;
  if (unsupported) listOf('gap-list', KNOWN_GAPS);
  show('error');
}

async function unlock(how) {
  const why = await cannotTry();
  if (why) return fail(new PasskeyError('unsupported', why));
  say('busy-text', how === 'create' ? 'Making your passkey… you may be asked twice.' : 'Waiting for your passkey…');
  show('busy');
  try {
    const prf = how === 'create' ? await createPasskey() : await usePasskey();
    forget();
    keys = fromPrf(prf);
    wipe(prf);
    say('npub', npubEncode(pubkeyOf(keys.masterKey)));
    closeSecret();
    show('home');
  } catch (e) { fail(e); }
}

function closeSecret() {
  say('nsec', '');
  $('secret-closed').hidden = false; $('secret-confirm').hidden = true; $('secret-open').hidden = true;
}

function start() {
  if (refuseFrames()) return;
  $('use').addEventListener('click', () => unlock('use'));
  $('create').addEventListener('click', () => unlock('create'));
  $('again').addEventListener('click', () => show('start'));
  copyButton($('copy-npub'), () => $('npub').textContent);
  $('reveal').addEventListener('click', () => { $('secret-closed').hidden = true; $('secret-confirm').hidden = false; });
  $('reveal-no').addEventListener('click', closeSecret);
  $('reveal-yes').addEventListener('click', () => {
    if (!keys) return show('start');
    say('nsec', nsecEncode(keys.masterKey));
    $('secret-confirm').hidden = true; $('secret-open').hidden = false;
  });
  copyButton($('copy-nsec'), () => $('nsec').textContent);
  $('hide').addEventListener('click', closeSecret);
  $('lock').addEventListener('click', () => { forget(); show('start'); });
  window.addEventListener('pagehide', forget);
  show('start');
}

start();
