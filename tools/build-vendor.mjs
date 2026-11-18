// Bundles the few noble and scure functions the portal uses into vendor/noble.js, one ES module with
// no imports, so the site needs no build step and makes no network requests.
//   npm ci && node tools/build-vendor.mjs
// Then compare: sha256sum vendor/noble.js  (against vendor/SHA256SUMS).
import { build } from 'esbuild';
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const here = import.meta.dirname, root = join(here, '..');
const v = (p) => JSON.parse(readFileSync(join(root, 'node_modules', p, 'package.json'), 'utf8')).version;
const versions = `@noble/curves ${v('@noble/curves')}, @noble/hashes ${v('@noble/hashes')}, @scure/base ${v('@scure/base')}, esbuild ${v('esbuild')}`;
const entry = join(here, '.vendor-entry.js');
writeFileSync(entry, [
  "export { schnorr } from '@noble/curves/secp256k1.js';",
  "export { sha256 } from '@noble/hashes/sha2.js';",
  "export { hmac } from '@noble/hashes/hmac.js';",
  "export { hkdf } from '@noble/hashes/hkdf.js';",
  "export { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';",
  "export { bech32 } from '@scure/base';",
  '',
].join('\n'));
const out = join(root, 'vendor/noble.js');
await build({ entryPoints: [entry], bundle: true, format: 'esm', platform: 'neutral', target: 'es2022',
  mainFields: ['module', 'main'], conditions: ['import', 'default'], outfile: out, legalComments: 'inline',
  banner: { js: `// ${versions}. Built by tools/build-vendor.mjs. Do not edit.` }, logLevel: 'warning' });
rmSync(entry);
const sum = createHash('sha256').update(readFileSync(out)).digest('hex');
writeFileSync(join(root, 'vendor/SHA256SUMS'), `${sum}  noble.js\n`);
console.log('vendor/noble.js', sum, '\n', versions);
