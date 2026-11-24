# Passkey Portal

A proof of concept. A static web page that derives a Nostr key from a passkey, using the
WebAuthn PRF extension. There is no server. The same passkey gives the same npub on any device
where it is synced.

It can also sign a person in to another site, like an OAuth popup: the site gets a key made just
for it, plus two signed events that show the key belongs to the person.

> **Passkeys are tied to the domain.** A passkey made on `portal.example.com` only ever works on
> `portal.example.com`. If the portal moves to another address, everyone's passkeys stop working
> there and their keys are out of reach. So put the portal on **your own domain from day one**
> (for example `portal.syb.lol`), not on `sybenx.github.io` or `*.pages.dev`. Then hosting can move
> from GitHub Pages to Cloudflare Pages or anywhere else without breaking anyone's account.
> The page uses `location.hostname` as the passkey's relying party id.

## Trust model

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
   The browser gives back 32 bytes, the same every time for the same passkey.
2. From those 32 bytes, with HKDF-SHA256 and salt `"passkey-portal v1"`:
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
   `http://localhost` and `http://127.0.0.1` for testing), and only the first site that asks. It
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
relay events, the attestation (and each way of breaking it), and the whole sign-in flow with a
made-up PRF output. **The passkey part (`js/passkey.js`) cannot run in Node.** It was tried in
headless Chrome with Chrome's virtual authenticator, which is not a real phone.

### On your computer

Passkeys work on `http://localhost` without https. Serve the folder twice, on two ports, so the
demo site and the portal have different origins:

```sh
python3 -m http.server 8000 &   # the portal
python3 -m http.server 8001 &   # the "other site"
```

Open `http://localhost:8000/` for the portal, and
`http://127.0.0.1:8001/demo-client.html?portal=http://localhost:8000` for the demo site.

### On a phone

A phone needs https and a real domain. Deploy (below), then open `https://<your portal>/` on the
phone and tap "First time? Create a passkey". For the sign-in popup, the demo page should be served
from **a different origin** than the portal (a second Pages project, or another subdomain), opened
as `https://<demo site>/demo-client.html?portal=https://<your portal>`. Served from the portal's own
address it still works, but it is not a real test of the cross-site path, and it says so.

## Deploy

No build step; the site is the files as they are: `index.html`, `authorize.html`,
`demo-client.html`, `favicon.svg`, `css/`, `js/`, `vendor/`.

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

Some platforms say PRF is "enabled" when making the passkey but give the secret only when using it.
The page handles that by asking for the new passkey once more right after making it, so a first-time
person may be asked twice.

## Not built

- Publishing anything to relays (the attestation, a profile, anything).
- Recovery. Lose the passkey and the key is gone unless you saved the nsec.
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
| `demo-client.html`, `js/demo-client.js` | A stand-in "other site" |
| `js/passkey.js` | WebAuthn and PRF (browser only) |
| `js/derive.js` | Master key, child seed, child keys |
| `js/origin.js` | Which origins get a key |
| `js/nip19.js` | npub and nsec |
| `js/event.js` | Event id, signing and checking (NIP-01, BIP-340) |
| `js/attest.js` | Draft attestation: build and verify |
| `js/flow.js` | The popup's answer, and how a site checks it |
| `js/bytes.js`, `js/ui.js` | Small helpers |
| `test/` | Node tests |
| `vendor/`, `tools/build-vendor.mjs` | The bundled crypto and how it was made |
