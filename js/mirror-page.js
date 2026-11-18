// Portal B's side of making a backup. Portal A opens this page and offers the root by postMessage.
// B accepts only from the window that opened it, only the first portal that asks, and only if that
// portal is in B's own list (and A only offers to portals in its list). Each passkey use is behind
// its own button, so every one starts from a fresh tap (some browsers require that).

import { HELLO, READY, WANT, ROOT, DONE, FAILED, sealRoot } from './mirror.js';
import { lists } from './portals.js';
import { fromPrf, pubkeyOf } from './derive.js';
import { npubEncode } from './nip19.js';
import { wipe } from './bytes.js';
import { cannotTry, createMirrorPasskey, prfOf, writeBlob, usePasskey, PasskeyError } from './passkey.js';
import { $, show, say, refuseFrames } from './ui.js';
import mirrors from '../mirrors.js';

let from = null, nonce = '', stopped = false;
let cred = null;      // { id, prf } of the backup passkey being made
let root = null, expect = '';
let onRoot = null;    // waiting for A to send the root

function send(msg) { if (window.opener && !window.opener.closed) window.opener.postMessage({ ...msg, nonce }, from); }

function cleanup() { wipe(root, cred?.prf); root = null; cred = null; }

function fail(text, title = 'No backup was made') {
  stopped = true;
  if (from) send({ type: FAILED, reason: text });
  cleanup();
  say('error-title', title); say('error-text', text); show('error');
}

function onMessage(e) {
  if (stopped || e.source !== window.opener) return;
  if (e.data?.type === HELLO) {
    if (from) { if (e.origin === from) send({ type: READY }); return; }
    if (!lists(mirrors, e.origin) || e.origin === location.origin) {
      stopped = true;
      say('error-title', 'Not accepted'); say('error-text', `${e.origin} is not a portal this one takes backups from. Nothing was made.`);
      return show('error');
    }
    from = e.origin;
    nonce = typeof e.data.nonce === 'string' && e.data.nonce.length <= 128 ? e.data.nonce : '';
    say('from', from); say('here', location.origin);
    send({ type: READY });
    show('ask');
  } else if (e.data?.type === ROOT && e.origin === from && e.data.nonce === nonce && onRoot) {
    const r = e.data.root;
    if (!(r instanceof Uint8Array) || r.length !== 32) return fail('The portal sent something that is not a copy.');
    onRoot(r); onRoot = null;
  }
}

/** Show a button for the next passkey use, and run `fn` when it is tapped. */
function step(text, fn) {
  say('step-text', text);
  $('step-go').onclick = async () => {
    say('busy-text', 'Waiting for your passkey…'); show('busy');
    try { await fn(); } catch (e) {
      fail(e?.message || String(e), e instanceof PasskeyError && e.kind === 'unsupported' ? 'This device can\'t hold a backup here' : undefined);
    }
  };
  show('step');
}

async function make() {
  $('go').disabled = true;
  const why = await cannotTry();
  if (why) return fail(why, 'This device can\'t hold a backup here');
  say('busy-text', 'Making your backup passkey (1 of 3)…'); show('busy');
  try { cred = await createMirrorPasskey(); } catch (e) {
    return fail(e?.message || String(e), e instanceof PasskeyError && e.kind === 'unsupported' ? 'This device can\'t hold a backup here' : undefined);
  }
  say('busy-text', 'Getting the copy from your portal…');
  root = await new Promise((resolve) => {
    onRoot = resolve; send({ type: WANT });
    setTimeout(() => { if (onRoot) { onRoot = null; resolve(null); } }, 15000);
  });
  if (!root) return fail('Your portal did not send the copy. Its window may have closed.');
  const k = fromPrf(root);
  expect = pubkeyOf(k.masterKey);
  wipe(k.masterKey, k.childSeed);
  const n = cred.prf ? 3 : 4;
  if (!cred.prf) step('This device needs one more passkey use to lock the copy (2 of 4).', async () => { cred.prf = await prfOf(cred.id); save(n); });
  else save(n);
}

function save(n) {
  step(`Save the copy into your new passkey (${n - 1} of ${n}).`, async () => {
    const blob = await sealRoot(cred.prf, root);
    await writeBlob(cred.id, blob);
    step(`Check the backup opens your identity (${n} of ${n}).`, check);
  });
}

async function check() {
  const got = await usePasskey(cred.id); // the same path as a real sign-in
  const keys = fromPrf(got.root);
  const pk = pubkeyOf(keys.masterKey);
  wipe(got.root, keys.masterKey, keys.childSeed);
  if (got.kind !== 'mirror' || pk !== expect) return fail('The backup did not open the same identity. Do not rely on it; you can delete it in your passkey settings.');
  send({ type: DONE, masterPubkey: pk });
  cleanup();
  stopped = true;
  say('npub', npubEncode(pk));
  show('done');
}

function start() {
  if (refuseFrames()) return;
  if (!window.opener) { say('error-title', 'Nothing to back up'); say('error-text', 'Open this page from your portal\'s "Add a backup portal".'); return show('error'); }
  window.addEventListener('message', onMessage);
  $('go').addEventListener('click', make);
  $('no').addEventListener('click', () => { fail('You chose not to.', 'No backup was made'); window.close(); });
  window.addEventListener('pagehide', cleanup);
  setTimeout(() => { if (!from && !stopped) { stopped = true; say('error-text', 'No portal asked to make a backup.'); show('error'); } }, 15000);
}

start();
