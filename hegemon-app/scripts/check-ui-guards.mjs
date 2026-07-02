#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import ts from 'typescript';

const here = dirname(fileURLToPath(import.meta.url));
const modulePath = resolve(here, '../src/appGuards.ts');
const source = readFileSync(modulePath, 'utf8');
const appPath = resolve(here, '../src/App.tsx');
const appSource = readFileSync(appPath, 'utf8');
const nodeManagerPath = resolve(here, '../electron/nodeManager.ts');
const nodeManagerSource = readFileSync(nodeManagerPath, 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2022,
    strict: true
  },
  fileName: modulePath
}).outputText;

const module = { exports: {} };
vm.runInNewContext(compiled, {
  exports: module.exports,
  module
}, { filename: modulePath });

const { computeNodeDisplayState, legacyContactWarning } = module.exports;

const legacyContact = {
  id: 'legacy-main',
  name: 'Main wallet',
  address: 'shca1...',
  verified: false,
  notes: 'Main wallet 0.9.1'
};
const ovhContact = {
  id: 'legacy-ovh',
  name: 'old hegemon-ovh wallet',
  address: 'shca1...',
  verified: true
};
const currentContact = {
  id: 'current',
  name: 'Current test wallet',
  address: 'shca1...',
  verified: true,
  notes: 'Verified on 0.10 devnet',
  protocolVersion: '0.10'
};

assert.match(legacyContactWarning(legacyContact), /Legacy contact/);
assert.match(legacyContactWarning(ovhContact), /Legacy contact/);
assert.equal(legacyContactWarning(currentContact), null);

const startupRace = computeNodeDisplayState({
  reachable: true,
  peers: 1,
  isSyncing: true,
  bestNumber: 1370,
  syncTargetHeight: 0,
  mining: true,
  miningSyncGateOpen: false
});
assert.equal(startupRace.startupSummarySettling, true);
assert.equal(startupRace.syncTargetHeight, 1370);
assert.equal(startupRace.isSyncing, false);
assert.equal(startupRace.heightDelta, 0);
assert.equal(startupRace.heightRelation, 'aligned');
assert.equal(startupRace.miningGateBlocked, false);
assert.equal(startupRace.healthLabel, 'Healthy');
assert.equal(startupRace.healthTone, 'ok');

const genuineMiningGate = computeNodeDisplayState({
  reachable: true,
  peers: 1,
  isSyncing: true,
  bestNumber: 1360,
  syncTargetHeight: 1370,
  mining: true,
  miningSyncGateOpen: false
});
assert.equal(genuineMiningGate.startupSummarySettling, false);
assert.equal(genuineMiningGate.syncTargetHeight, 1370);
assert.equal(genuineMiningGate.isSyncing, true);
assert.equal(genuineMiningGate.heightDelta, -10);
assert.equal(genuineMiningGate.heightRelation, 'syncing');
assert.equal(genuineMiningGate.miningGateBlocked, true);
assert.equal(genuineMiningGate.healthLabel, 'Mining gated');
assert.equal(genuineMiningGate.healthTone, 'warn');

const localMinerAhead = computeNodeDisplayState({
  reachable: true,
  peers: 1,
  isSyncing: false,
  bestNumber: 1488,
  syncTargetHeight: 1487,
  mining: true,
  miningSyncGateOpen: true
});
assert.equal(localMinerAhead.heightDelta, 1);
assert.equal(localMinerAhead.heightRelation, 'local_ahead');
assert.equal(localMinerAhead.miningGateBlocked, false);
assert.equal(localMinerAhead.healthLabel, 'Healthy');
assert.equal(localMinerAhead.healthTone, 'ok');

const offline = computeNodeDisplayState({
  reachable: false,
  peers: null,
  isSyncing: null,
  bestNumber: null,
  syncTargetHeight: null,
  mining: null,
  miningSyncGateOpen: null
});
assert.equal(offline.heightDelta, null);
assert.equal(offline.heightRelation, 'unknown');
assert.equal(offline.healthLabel, 'Offline');
assert.equal(offline.healthTone, 'error');

assert.equal(
  appSource.includes('navigator.clipboard.writeText'),
  false,
  'Renderer clipboard writes must go through the Electron native clipboard bridge.'
);
assert.match(appSource, /window\.hegemon\.clipboard\.writeText/);
assert.equal(
  appSource.includes("setWalletError('Failed to copy address."),
  false,
  'Copy-address failures must not mark the wallet itself unhealthy.'
);
assert.match(appSource, /Mining rewards/);
assert.match(appSource, /miningPayoutMismatch/);
assert.match(
  appSource,
  /statusLabel: walletNavLabel/,
  'Wallet navigation must use the payout-aware status label.'
);
assert.equal(
  nodeManagerSource.includes('process.env.HEGEMON_MINER_ADDRESS'),
  false,
  'Managed desktop mining must not inherit a hidden parent HEGEMON_MINER_ADDRESS.'
);

console.log('app UI guard checks passed');
