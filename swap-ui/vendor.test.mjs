import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';

const dir = new URL('./vendor/', import.meta.url);
const read = name => readFileSync(new URL(name, dir));

test('vendored bundles match the recorded checksums', () => {
  const lines = read('SHA256SUMS').toString().trim().split('\n');
  assert.ok(lines.length >= 3);
  for (const line of lines) {
    const [sum, name] = line.split('  ');
    assert.equal(createHash('sha256').update(read(name)).digest('hex'), sum, name);
  }
});

test('manifest pins exactly the dependencies in package.json and the lock file', () => {
  const manifest = JSON.parse(read('MANIFEST.json'));
  const pkg = JSON.parse(readFileSync(new URL('../swap-service/vendor-src/package.json', import.meta.url)));
  const lock = JSON.parse(readFileSync(new URL('../swap-service/vendor-src/package-lock.json', import.meta.url)));
  assert.deepEqual(manifest.direct_dependencies, pkg.dependencies);
  for (const [name, version] of Object.entries(pkg.dependencies)) {
    assert.match(version, /^\d+\.\d+\.\d+$/, name + ' must be pinned exactly');
    assert.equal(manifest.packages[name].version, version);
    assert.equal(lock.packages['node_modules/' + name].integrity, manifest.packages[name].integrity);
  }
});

test('the bundles load without a bundler and expose what the page uses', async () => {
  const hash = await import('./vendor/hash.mjs');
  const btc = await import('./vendor/btc-signer.mjs');
  for (const name of ['blake2b', 'sha256', 'ed25519', 'bech32']) assert.ok(hash[name], name);
  for (const name of ['Transaction', 'Address', 'OutScript', 'Script', 'SigHash', 'TEST_NETWORK', 'p2wsh', 'p2wpkh', 'secp256k1']) assert.ok(btc[name], name);
  assert.equal(Buffer.from(hash.blake2b(new Uint8Array(0), {dkLen: 32})).toString('hex'), '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8');
});
