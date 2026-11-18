// The portal's home page: unlock the passkey, show the npub, let the person take their nsec, and
// add a backup portal. The root and keys are held in this module only while the page is open.
// Nothing is stored or sent, except the root to a backup portal the person picked (js/offer.js).

import { fromPrf, pubkeyOf } from './derive.js';
import { npubEncode, nsecEncode } from './nip19.js';
import { wipe } from './bytes.js';
import { originList } from './portals.js';
import { offerCopy } from './offer.js';
import { cannotTry, usePasskey, createPasskey, PasskeyError, KNOWN_GAPS } from './passkey.js';
import { $, show, say, copyButton, listOf, refuseFrames } from './ui.js';
import mirrors from '../mirrors.js';

let root = null;  // the person's root, while unlocked
let keys = null;  // { masterKey, childSeed } from it

function forget() {
  if (keys) wipe(keys.masterKey, keys.childSeed);
  wipe(root);
  keys = null; root = null;
  say('npub', ''); say('nsec', ''); say('backup-status', '');
}

function fail(e) {
  const unsupported = e instanceof PasskeyError && e.kind === 'unsupported';
  say('error-title', unsupported ? 'This device or browser can\'t do this'
    : e?.kind === 'mirror' ? 'This backup can\'t open your identity right now'
      : e?.kind === 'cancelled' ? 'Cancelled' : 'That didn\'t work');
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
    const got = how === 'create' ? await createPasskey() : await usePasskey();
    forget();
    root = got.root;
    keys = fromPrf(root);
    say('npub', npubEncode(pubkeyOf(keys.masterKey)));
    say('kind', got.kind === 'mirror'
      ? 'You opened this with a backup passkey. It is the same identity as your original.'
      : 'You opened this with your original passkey.');
    closeSecret();
    show('home');
  } catch (e) { fail(e); }
}

function closeSecret() {
  say('nsec', '');
  $('secret-closed').hidden = false; $('secret-confirm').hidden = true; $('secret-open').hidden = true;
}

/** One button per backup portal this portal lists. None listed: the card stays hidden. */
function backupButtons() {
  const list = originList(mirrors, location.origin);
  $('backup').hidden = list.length === 0;
  $('backup-list').replaceChildren(...list.map((target) => {
    const b = Object.assign(document.createElement('button'), { className: 'secondary', textContent: `Back up to ${target}` });
    b.addEventListener('click', async () => {
      if (!root) return show('start');
      say('backup-status', 'Opening the backup portal…');
      try { await offerCopy(target, root, pubkeyOf(keys.masterKey), (t) => say('backup-status', t)); say('backup-status', `Backup saved on ${target}. It opens this same identity.`); }
      catch (e) { say('backup-status', e.message); }
    });
    return b;
  }));
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
  backupButtons();
  show('start');
}

start();
