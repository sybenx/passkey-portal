# Passkey Portal

A proof of concept. A static web page that gives a person a nostr identity from a passkey: no
server, no email, no app to install. Tap your passkey, get an npub. Tap it again on another day,
on any device where that passkey is synced, and get the same npub.

It can also sign a person in to another site, like an OAuth popup: the site gets a key made just
for it, plus two signed events that show the key belongs to the person.

And a person can add **backup portals** ("mirrors"): the same code on other domains, each holding a
passkey that opens the same identity. If one portal's domain dies, the others still work.

> **Passkeys are tied to the domain.** A passkey made on `portal.example.com` only ever works on
> `portal.example.com`. If the portal moves to another address, everyone's passkeys stop working
> there and their keys are out of reach. So put the portal on **your own domain from day one**
> (for example `portal.syb.lol`), not on `sybenx.github.io` or `*.pages.dev`. Then hosting can move
> from GitHub Pages to Cloudflare Pages or anywhere else without breaking anyone's account.
> The page uses `location.hostname` as the passkey's relying party id.

## The trust model, plainly

- The secret comes from your passkey, and the key is made in your browser. Nothing is stored by the
  page (no localStorage, no cookies) and nothing is sent anywhere; the pages' Content-Security-Policy
  has `connect-src 'none'`, so their scripts cannot fetch or open connections (fetch, XHR,
  WebSocket) and load nothing from other sites. (A page can still navigate or open a window; the
  code simply doesn't, and you can check.)
- **But whoever controls the domain and the hosting can serve different code.** Changed code could
  take your master key at the moment you tap your passkey. Nothing in a web page can prevent that.
- What this project does about it: the code is public and small enough to read in one sitting, and
  the deploy runs from the public repo by a public GitHub Actions workflow that logs each file's
  SHA-256. That makes a swap **detectable**, not impossible. Nobody is watching for it yet (see "Not built").
- So treat it as a starting point. **Once the identity matters to you, move it off this page:**
  copy the nsec into a real signer app, and stop using the portal for it.
- Each site you sign in to gets a key of its own (its nsec), your master npub, and the two signed
  events tying them together. So every such site can see it is you. That is the point of the
  attestation, but it means these sites can link you to each other.
- The passkey's signature is never checked by anyone; there is no server to check it. The passkey
  is used only as a hardware-locked source of a secret (the WebAuthn PRF extension).

## How the keys are made

Everything here is fixed. Changing any of it changes every person's keys.

1. The passkey's PRF is asked for one value, `first = SHA-256("passkey-portal prf salt v1")`.
   The browser gives back 32 bytes, the same every time for the same passkey. For the person's
   first (original) passkey, these 32 bytes are the **root**. A backup passkey gives the same root
   another way (see "Backup portals"); everything below starts from the root.
2. From the root, with HKDF-SHA256 and salt `"passkey-portal v1"`:
   - **master key** = HKDF(info `"passkey-portal master key v1"`, 32 bytes), as a secret key (step 4)
   - **child seed** = HKDF(info `"passkey-portal child seed v1"`, 32 bytes)
3. **Child key for a site** = HMAC-SHA256(key = child seed, message = `"passkey-portal child v1"` ‖ site origin),
   as a secret key (step 4). The origin is exactly as the browser reports it, such as
   `https://example.com` or `https://example.com:8443`, with no slash at the end.
4. **As a secret key:** read the 32 bytes as a number. If it is 0 or not below the curve order n
   (about 1 chance in 2^128), take SHA-256 of those bytes and try again.

Why the child seed is separate from the master key: later the master key may move into a FROST
setup where its nsec never exists in one place. Child keys must still come back from the seed alone.

Why a child is its own key and not the master key plus a tweak (as in Keykin's child keys): here the
child's nsec is handed to the other site. With a tweak, the child nsec and the tweak together would
give the master key. A hash-made child gives nothing back.

**Every new passkey is a new identity.** "First time? Create a passkey" always makes a new one, with a
random user id, so it never replaces an old passkey; it also never finds the old key. People who
already have one should use "Continue with passkey".

## Sign in with portal

The other site opens `https://<portal>/authorize.html` in a popup and they talk by `postMessage`:

1. The site sends `{ type: "passkey-portal/request", v: 1, nonce }` to the popup, with the portal's
   origin as the target, every 250 ms until it hears back (the popup can't hear anything until it
   has loaded).
2. The popup takes the site's origin **from the message event's `origin`**, never from the message.
   It accepts only messages from the window that opened it, only `https://` origins (or
   `http://localhost`, `http://*.localhost` and `http://127.0.0.1` for testing), and only the first site that asks. It
   answers `{ type: "passkey-portal/ready", nonce }` and shows the person the origin.
3. The person taps their passkey. The popup makes the child key for that exact origin and the
   attestation, and posts this to the opener, with that origin as the target (never `"*"`):

   ```json
   { "type": "passkey-portal/answer", "nonce": "…", "origin": "https://site.example",
     "childNsec": "nsec1…", "childPubkey": "<hex>", "masterPubkey": "<hex>",
     "attestation": { "master": { …event… }, "child": { …event… } } }
   ```

   or `{ "type": "passkey-portal/refused", "nonce": "…" }` if the person says no. Then it closes.
4. The site checks the attestation was made for its own origin, that both signatures are good, and
   that the nsec it got is the child the attestation names (`checkAnswer` in `js/flow.js`).

If the popup was not opened by a site (no `window.opener`), it refuses. It also refuses to run inside
a frame. A site that sends `Cross-Origin-Opener-Policy: same-origin` loses its link to the popup and
cannot use this.

## Backup portals (mirrors)

A passkey belongs to one domain. So a person whose portal's domain dies loses the passkey's secret,
and with it their keys. A backup portal fixes that: another domain running this same code, holding a
second passkey that opens **the same root**, so the same master key and the same child key for every
site.

### How it works

- **The copy lives inside the backup passkey**, in its WebAuthn `largeBlob` (a small storage area
  the passkey keeps for its site). No relay, no server, no network: the CSP stays `connect-src 'none'`.
- **The blob** is 61 bytes: `version (0x01) | nonce (12 random bytes) | AES-256-GCM(root)` (32 bytes
  plus a 16-byte tag). The AES key is HKDF-SHA256 of the backup passkey's own PRF output, salt
  `"passkey-portal mirror v1"`, info `"passkey-portal mirror wrap v1"`. The additional data is the
  version byte followed by `"passkey-portal mirror blob"`. WebCrypto does the AES (`js/mirror.js`).
- **A passkey says what kind it is in its user handle** (`user.id`, which the browser returns on
  every sign-in):

  | user.id | Kind | Where the root comes from |
  |---|---|---|
  | 16 bytes | original, made by the first version of this code (fully random) | its PRF output |
  | 17 bytes, first byte `0x01` | original | its PRF output |
  | 17 bytes, first byte `0x02` | backup | its blob, opened with its PRF output |
  | anything else, or none | refused | nothing |

  The new handles are 17 bytes so they can never be mistaken for the old 16-byte ones, whatever
  their first byte.
- **Signing in is one tap for both kinds:** one `get()` asks for the PRF and `largeBlob: { read: true }`
  together, then the handle decides. If a browser rejects the largeBlob request outright, the page
  asks again without it (an original still works; a backup then has no blob and stops).
- **The hard rule:** a backup whose blob is missing, damaged or won't open stops with "This backup
  passkey can't open your identity right now". It **never** falls back to its own PRF output, which
  would be a different identity. And an original never reads a blob.
- The signed-in page says which kind opened it.

### Adding one

Only from a signed-in portal, and only when the person asks:

1. Portal A's signed-in page shows "Add a backup portal" with one button per origin in A's own
   `mirrors.js` (nothing listed: no card). The person picks portal B.
2. A opens `<B>/mirror.html` in a popup and says hello by `postMessage` to B's exact origin until B
   answers (15 seconds at most).
3. B takes the asker's origin from the message event, never from the message. It accepts only the
   window that opened it, only the first portal that asks, and **only if A is in B's own
   `mirrors.js`**. B shows the person which portal is offering the copy.
4. The person taps "Make a backup passkey here". B makes a passkey with a backup handle, the PRF,
   and `largeBlob: { support: 'required' }`. If this device can't do largeBlob, nothing is made.
5. Only now does B ask A for the root, and A sends it to B's exact origin, to the window A opened.
6. B seals the root with its new passkey's PRF output and writes the blob. Then it signs in with the
   new passkey **the same way a real sign-in does** and checks it opens the same master key.
7. Only then does B tell A, and A shows success only if B names A's own master public key.
8. B wipes the root; A keeps it only while signed in (as before, until Lock or leaving the page).

A backup portal can add further backups the same way: once signed in, it has the root too.

**Taps at B:** 3 in the headless Chrome check (make the passkey, save the copy, check it). Each
is behind its own button, because some browsers (notably Safari) let a page use a passkey only
right after a tap. A device that gives the PRF result only when a passkey is used, not when it is
made, needs a 4th. Plus the one tap that signed in at A.

### Why sending the root to another site is acceptable here, and where it is not

The root is everything: whoever gets it has the master key forever. So the code sends it only when
all of these hold:

- **A sends only to origins in A's own shipped list.** The list is part of A's public code. No
  incoming message, link or query string can add to it, so a phishing page can't get itself chosen.
- **Only after the person, signed in, picked that portal.** Nothing starts the offer except a tap on
  A's own page. No message from another site can start it.
- **Only to a window A itself opened,** at the origin A put in that window's address, using that
  exact origin as the `postMessage` target. If that window is navigated somewhere else, the browser
  drops the message.
- **B must list A too,** so B only takes copies from portals its operator trusts.

What this does not protect against: whoever runs A (or can change A's code or list) can send the root
anywhere, but they could already take it at the moment of a tap, as said under "The trust model".
Whoever runs B can read every root copied to it. **Adding a backup portal means trusting its operator
as much as your original's.** So `mirrors.js` should list only portals run by people the operator of
this portal would trust with their own keys, ideally on different hosting and different domain
registrars so they don't die together.

### For sites: several portals, no typing

A site can be given an ordered list of portals: `demo-client.html?portal=https://a.example&portal=https://b.example`
(or comma-separated). "Sign in" opens the first. If it doesn't answer within 5 seconds, the same
popup window is pointed at the next one (one window, so no pop-up blocker trouble). Whichever answers,
the site gets the same master key and the same child key, because every portal of a person gives the
same root. (`js/portals.js` has the logic; the demo shows it.)

A portal that is up but where this person has no passkey still answers, so the site does not move on
by itself; the person would have to close the window and use another portal. Not handled yet.

## The attestation (DRAFT)

**Draft, not a registered NIP. Expect the kind and the tags to change.** Nothing is published to
relays; the events are only made and handed to the site.

Two events of kind **30437** (addressable, so a newer pair replaces an older one). 30437 is not in
the NIPs kind list as of 2026-11-18; it was not checked against unlisted uses.

Signed by the master key:

```json
{ "kind": 30437, "pubkey": "<master hex>", "created_at": 1790000000,
  "tags": [["d", "<child hex>"], ["p", "<child hex>"], ["rel", "child"], ["origin", "https://site.example"]],
  "content": "This key is mine, made for https://site.example." }
```

Signed by the child key:

```json
{ "kind": 30437, "pubkey": "<child hex>", "created_at": 1790000000,
  "tags": [["d", "<master hex>"], ["p", "<master hex>"], ["rel", "master"], ["origin", "https://site.example"]],
  "content": "My master key made me for https://site.example." }
```

Either may also have `["expiration", "<unix seconds>"]` (NIP-40). The portal does not set one yet.

`verifyAttestation(master, child, { origin, now })` in `js/attest.js` accepts the pair only if: both
are kind 30437; both ids and BIP-340 signatures are right; the keys differ; the master's `d` and `p`
are the child's pubkey and the child's `d` and `p` are the master's (exactly one of each); `rel` is
`child` on the master's event and `master` on the child's; both name the same valid `origin`, and it
is the expected one if one is given; and no `expiration` has passed. One event alone proves nothing,
since anyone can name any key; the pair means both key holders agreed. The `content` is for people
and is covered by the signature, but not otherwise checked.

## Try it

### In Node (the logic)

```sh
node --test
```

No install is needed: the tests use only the vendored crypto. They cover the key derivation (also
checked against Node's own HKDF and HMAC), NIP-19 test vectors, BIP-340 test vectors, two real
relay events, the attestation (and each way of breaking it), the whole sign-in flow with a
made-up PRF output, the backup blob (and each way of breaking it), user handle kinds including the
old format, original and backup giving identical keys, the mirror lists and the portal fallthrough. **The passkey part (`js/passkey.js`) cannot run in Node.** It was tried in
headless Chrome with Chrome's virtual authenticator, which is not a real phone.

### On your computer

Passkeys work on `http://localhost` (and `*.localhost`) without https. An IP address such as
`127.0.0.1` can't hold a passkey, so it can only be a demo site, not a portal. Serve the folder twice,
on two ports, so the demo site and the portal have different origins:

```sh
python3 -m http.server 8000 &   # the portal
python3 -m http.server 8001 &   # the "other site"
```

Open `http://localhost:8000/` for the portal, and
`http://127.0.0.1:8001/demo-client.html?portal=http://localhost:8000` for the demo site.

To try backups locally, put both test portals in `mirrors.js`
(`export default ['http://localhost:8000', 'http://b.localhost:8001'];`), serve the folder on port
8001 too, and use `http://b.localhost:8001` as the second portal (browsers send `*.localhost` to
your own machine). Then demo: `http://127.0.0.1:8002/demo-client.html?portal=http://localhost:8000&portal=http://b.localhost:8001`.

### On a phone

A phone needs https and a real domain. Deploy (below), then open `https://<your portal>/` on the
phone and tap "First time? Create a passkey". For the sign-in popup, the demo page should be served
from **a different origin** than the portal (a second Pages project, or another subdomain), opened
as `https://<demo site>/demo-client.html?portal=https://<your portal>`. Served from the portal's own
address it still works, but it is not a real test of the cross-site path, and it says so.

A real test of backups needs **two real https hosts** (two domains, each with this code and a
`mirrors.js` naming the other), and a phone whose passkey manager supports largeBlob.

## Deploy

No build step; the site is the files as they are: `index.html`, `authorize.html`, `mirror.html`,
`demo-client.html`, `mirrors.js`, `favicon.svg`, `css/`, `js/`, `vendor/`. Edit `mirrors.js` to list
backup portals (it ships empty, which hides the feature). It is a JavaScript module and not a JSON
file because the pages' `connect-src 'none'` blocks loading JSON.

- **GitHub Pages:** push the repo (public) to GitHub, then in Settings > Pages choose "GitHub
  Actions" as the source. `.github/workflows/pages.yml` runs the tests, checks the vendored file's
  hash, copies the files and deploys them, and prints each deployed file's SHA-256 in the log. Set
  your own domain in Settings > Pages before anyone makes a passkey.
- **Cloudflare Pages:** connect the repo, no build command, output directory `/`. Add your own
  domain before anyone makes a passkey. (This serves the tests and tools folders too; they are harmless.)

## Known gaps (late 2026)

The page needs the WebAuthn PRF extension. If it's missing, the page says this device or browser
can't do it and stops. It never falls back to a weaker secret. Known not to work:

- Firefox on Android
- Samsung Pass as the passkey manager
- iPhone and iPad before iOS 18.4
- Using a passkey from another phone by scanning a QR code (the cross-device flow)

Backups also need the passkey manager to support **largeBlob**. Where it doesn't, the page says
this device can't hold a backup here and makes nothing (Chrome reports this the same way as a
cancelled request, so the message says "Cancelled, or this device can't hold a backup"). Which
phones and passkey managers support largeBlob together with PRF has **not been checked** on real
devices.

Some platforms say PRF is "enabled" when making the passkey but give the secret only when using it.
The page handles that by asking for the new passkey once more right after making it, so a first-time
person may be asked twice.

## Not built

- Publishing anything to relays (the attestation, a profile, anything).
- Recovery beyond backup portals. Lose every passkey and the key is gone unless you saved the nsec.
- A backup for devices without largeBlob (for example a copy kept on a relay). Not built.
- Revoking or listing backups. A backup portal's operator could keep a copy of the root; nothing undoes that.
- Finding a person's portals by typing a handle. Sites must be told the list.
- Moving on from a portal that is up but has no passkey for this person.
- An upgrade path into FROST or Keykin, and a way to move the child seed along with it.
- Revoking a child key, or the attestation for it. A leaked child nsec stays "yours" by the
  attestation until expirations are used and checked.
- A watcher that checks the live site's files against the public repo's hashes, or any signed
  attestation of the deployed code.
- Any check of the passkey's signature (there is no server).
- Choosing which passkey to use when several exist is left to the browser's own picker.

## Vendored crypto

`vendor/noble.js` is one ES module bundled from these npm packages (exact versions in
`package.json`): `@noble/curves` 2.4.0, `@noble/hashes` 2.4.0, `@scure/base` 2.0.0, by esbuild 0.28.2.
These are the same noble versions Keykin uses. To rebuild and compare:

```sh
npm ci
node tools/build-vendor.mjs   # writes vendor/noble.js and vendor/SHA256SUMS
git diff --stat vendor/       # nothing should change
```

Only `schnorr`, `sha256`, `hmac`, `hkdf`, `bech32` and a few byte helpers are exported.

## Files

| File | What it is |
|---|---|
| `index.html`, `js/portal.js` | The portal: unlock, show the npub, reveal the nsec |
| `authorize.html`, `js/authorize.js` | The sign-in popup for other sites |
| `demo-client.html`, `js/demo-client.js` | A stand-in "other site", trying portals in order |
| `mirror.html`, `js/mirror-page.js` | Making a backup passkey here (portal B's side) |
| `js/offer.js` | Offering a backup to another portal (portal A's side) |
| `js/mirror.js` | User handle kinds, the sealed root blob, root from a sign-in |
| `js/portals.js` | Mirror lists, mutual listing, the site's portal list and fallthrough |
| `mirrors.js` | The operator's list of backup portals |
| `js/passkey.js` | WebAuthn, PRF and largeBlob (browser only) |
| `js/derive.js` | Master key, child seed, child keys |
| `js/origin.js` | Which origins get a key |
| `js/nip19.js` | npub and nsec |
| `js/event.js` | Event id, signing and checking (NIP-01, BIP-340) |
| `js/attest.js` | Draft attestation: build and verify |
| `js/flow.js` | The popup's answer, and how a site checks it |
| `js/bytes.js`, `js/ui.js` | Small helpers |
| `test/` | Node tests |
| `vendor/`, `tools/build-vendor.mjs` | The bundled crypto and how it was made |
