// Reproducible vendor build. `node build.mjs` writes ../../swap-ui/vendor; `node build.mjs --check` fails if the committed
// files differ from a fresh build. Run `npm ci --ignore-scripts` first so versions and integrity hashes match package-lock.json.
import {build} from 'esbuild';
import {createHash} from 'node:crypto';
import {mkdirSync, readFileSync, writeFileSync, existsSync} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', '..', 'swap-ui', 'vendor');
const check = process.argv.includes('--check');
const lock = JSON.parse(readFileSync(join(here, 'package-lock.json'), 'utf8'));
const pinned = Object.fromEntries(Object.entries(JSON.parse(readFileSync(join(here, 'package.json'), 'utf8')).dependencies));
const bundles = {'btc-signer.mjs': 'entry-btc.mjs', 'hash.mjs': 'entry-hash.mjs'};
const files = {};
for (const [name, entry] of Object.entries(bundles)) {
  const result = await build({entryPoints: [join(here, entry)], bundle: true, format: 'esm', platform: 'browser', target: 'es2022', write: false, legalComments: 'inline', minify: false, charset: 'utf8', logLevel: 'error'});
  files[name] = result.outputFiles[0].text;
}
const packages = {};
for (const [path, info] of Object.entries(lock.packages)) {
  if (path.startsWith('node_modules/') && !path.includes('esbuild')) packages[path.slice('node_modules/'.length)] = {version: info.version, integrity: info.integrity};
}
files['MANIFEST.json'] = JSON.stringify({generated_by: 'swap-../../swap-service/vendor-src/build.mjs', direct_dependencies: pinned, bundles, packages}, null, 2) + '\n';
files['SHA256SUMS'] = Object.keys(files).sort().map(name => createHash('sha256').update(files[name]).digest('hex') + '  ' + name).join('\n') + '\n';
if (check) {
  const bad = Object.keys(files).filter(name => !existsSync(join(out, name)) || readFileSync(join(out, name), 'utf8') !== files[name]);
  if (bad.length) { console.error('vendor files differ from a fresh build: ' + bad.join(', ')); process.exit(1); }
  console.log('vendor files match a fresh build');
} else {
  mkdirSync(out, {recursive: true});
  for (const [name, text] of Object.entries(files)) writeFileSync(join(out, name), text);
  console.log('wrote ' + Object.keys(files).join(', '));
}
