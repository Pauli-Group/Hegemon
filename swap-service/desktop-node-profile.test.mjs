import { test } from 'node:test';
import assert from 'node:assert/strict';
import { _electron } from 'playwright-core';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

test('desktop selects v0.11 and launches a fake node without network access', { timeout: 60000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'hegemon-desktop-node-'));
  const bin = join(dir, 'bin');
  const log = join(dir, 'launch-args.json');
  await mkdir(bin);
  // The fake executable records only the selected command-line arguments and never opens a socket.
  const fake = `#!/usr/bin/env node\nconst fs = require('node:fs');\n` +
    `if (process.argv.includes('pre-mainnet')) { fs.writeFileSync(${JSON.stringify(log)}, JSON.stringify(process.argv.slice(2))); setInterval(() => {}, 1000); }\n`;
  await writeFile(join(bin, 'hegemon-node'), fake);
  await writeFile(join(bin, 'walletd'), '#!/bin/sh\nexit 0\n');
  await chmod(join(bin, 'hegemon-node'), 0o700);
  await chmod(join(bin, 'walletd'), 0o700);
  let application;
  try {
    const env = { ...process.env, HEGEMON_BIN_DIR: bin, XDG_CONFIG_HOME: join(dir, 'config') };
    delete env.GH_TOKEN;
    delete env.GITHUB_TOKEN;
    const displayArgs = process.env.DISPLAY ? [] : ['--headless', '--ozone-platform=headless'];
    application = await _electron.launch({
      executablePath: resolve('hegemon-app/node_modules/electron/dist/electron'),
      args: ['--no-sandbox', '--disable-gpu', '--disable-background-networking', ...displayArgs,
        `--user-data-dir=${join(dir, 'user-data')}`, resolve('hegemon-app/out/main/main.cjs')],
      env, timeout: 30000
    });
    const main = await application.firstWindow();
    await main.getByRole('link', { name: /^Node/ }).click();
    await main.getByText('Configuration', { exact: true }).click();
    await main.getByRole('button', { name: 'Add v0.11 testnet node' }).click();
    await main.getByText('This relay uses the v0.11 pre-mainnet release manifest', { exact: false }).waitFor();
    await main.getByRole('button', { name: 'Start node', exact: true }).first().click();
    let args;
    for (let attempt = 0; attempt < 100; attempt++) {
      try { args = JSON.parse(await readFile(log, 'utf8')); break; }
      catch { await new Promise((done) => setTimeout(done, 100)); }
    }
    assert.ok(args, 'fake public node was not launched');
    assert.equal(args[args.indexOf('--network') + 1], 'pre-mainnet');
    assert.match(args[args.indexOf('--network-manifest') + 1], /config[/\\]testnet[/\\]0\.11[/\\]network-manifest\.json$/);
    assert.match(args[args.indexOf('--base-path') + 1], /\.hegemon-node-v0\.11$/);
    assert.ok(!args.includes('--dev'));
    assert.ok(!args.includes('--rpc-external'));
  } finally {
    if (application) await application.close();
    await rm(dir, { recursive: true, force: true });
  }
});
