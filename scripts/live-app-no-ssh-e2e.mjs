#!/usr/bin/env node
import { spawn } from 'node:child_process';
import {
  createWriteStream,
  existsSync,
  mkdtempSync,
  rmSync
} from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';

const ROOT_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const NODE_BIN = process.env.HEGEMON_NODE_BIN ?? path.join(ROOT_DIR, 'target/release/hegemon-node');
const WALLETD_BIN = process.env.HEGEMON_WALLETD_BIN ?? path.join(ROOT_DIR, 'target/release/walletd');
const PASSPHRASE = process.env.HEGEMON_E2E_WALLET_PASSPHRASE ?? 'testwallet123';
const KEEP_TMP = process.env.HEGEMON_E2E_KEEP === '1';
const SMALL_TX_COUNT = Number.parseInt(process.env.HEGEMON_E2E_SMALL_TX_COUNT ?? '3', 10);
const REQUEST_TIMEOUT_MS = Number.parseInt(
  process.env.HEGEMON_E2E_WALLET_REQUEST_TIMEOUT_MS ?? '900000',
  10
);
const WAIT_TIMEOUT_MS = Number.parseInt(process.env.HEGEMON_E2E_WAIT_TIMEOUT_MS ?? '240000', 10);
const UNIT = 100_000_000;
const SMALL_AMOUNT = Number.parseInt(process.env.HEGEMON_E2E_SMALL_AMOUNT ?? `${UNIT / 10}`, 10);
const MULTISIG_FINAL_AMOUNT = Number.parseInt(
  process.env.HEGEMON_E2E_MULTISIG_FINAL_AMOUNT ?? `${UNIT / 20}`,
  10
);
const FEE = Number.parseInt(process.env.HEGEMON_E2E_FEE ?? '1', 10);

const runDir = mkdtempSync(path.join(tmpdir(), 'hegemon-no-ssh-e2e-'));
const children = [];
const startedAt = Date.now();

function log(message) {
  console.log(`[no-ssh-e2e] ${message}`);
}

function fail(message) {
  throw new Error(message);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}

function ensureExecutable(file, label) {
  if (!existsSync(file)) {
    fail(`${label} not found: ${file}`);
  }
}

function spawnLogged(label, command, args, options = {}) {
  const stdoutLog = path.join(runDir, `${label}.stdout.log`);
  const stderrLog = path.join(runDir, `${label}.stderr.log`);
  const stdout = createWriteStream(stdoutLog, { flags: 'a' });
  const stderr = createWriteStream(stderrLog, { flags: 'a' });
  const child = spawn(command, args, {
    cwd: ROOT_DIR,
    env: options.env ?? process.env,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.pipe(stdout);
  child.stderr.pipe(stderr);
  child.on('exit', (code, signal) => {
    stdout.end();
    stderr.end();
    log(`${label} exited code=${code ?? 'null'} signal=${signal ?? 'null'}`);
  });
  const entry = { child, label };
  children.push(entry);
  return entry;
}

function childExited(child) {
  return child.exitCode !== null || child.signalCode !== null;
}

function waitChildExit(child, timeoutMs) {
  if (childExited(child)) {
    return Promise.resolve(true);
  }
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.off('exit', onExit);
      resolve(false);
    }, timeoutMs);
    const onExit = () => {
      clearTimeout(timer);
      resolve(true);
    };
    child.once('exit', onExit);
  });
}

async function stopLogged(entry, timeoutMs = 15000) {
  const { child, label } = entry;
  if (childExited(child)) {
    return;
  }
  log(`stopping ${label}`);
  child.kill('SIGTERM');
  if (await waitChildExit(child, timeoutMs)) {
    return;
  }
  log(`killing ${label}`);
  child.kill('SIGKILL');
  await waitChildExit(child, 5000);
}

function rpc(port, method, params = []) {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: '/',
        timeout: 5000,
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body)
        }
      },
      (response) => {
        let text = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => {
          text += chunk;
        });
        response.on('end', () => {
          try {
            const parsed = JSON.parse(text);
            if (parsed.error) {
              reject(new Error(`${method}: ${JSON.stringify(parsed.error)}`));
              return;
            }
            resolve(parsed.result);
          } catch (error) {
            reject(new Error(`${method}: invalid JSON response: ${text.slice(0, 200)} (${error})`));
          }
        });
      }
    );
    request.on('timeout', () => {
      request.destroy(new Error(`${method}: RPC timeout`));
    });
    request.on('error', reject);
    request.write(body);
    request.end();
  });
}

function parseHeight(header) {
  const value = header?.number ?? header?.height;
  if (typeof value === 'number') {
    return value;
  }
  if (typeof value === 'string') {
    return value.startsWith('0x') ? Number.parseInt(value, 16) : Number.parseInt(value, 10);
  }
  return 0;
}

async function height(port) {
  const header = await rpc(port, 'chain_getHeader');
  return parseHeight(header);
}

async function blockHash(port, number) {
  return await rpc(port, 'chain_getBlockHash', [number]);
}

async function pendingCount(port) {
  const pending = await rpc(port, 'author_pendingExtrinsics');
  return Array.isArray(pending) ? pending.length : 0;
}

async function retry(label, timeoutMs, intervalMs, fn) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const value = await fn();
      if (value) {
        return value;
      }
    } catch (error) {
      lastError = error;
    }
    await sleep(intervalMs);
  }
  const suffix = lastError ? `; last error: ${lastError.message}` : '';
  fail(`${label} timed out after ${timeoutMs}ms${suffix}`);
}

async function waitRpc(port, label) {
  await retry(`wait ${label} RPC`, WAIT_TIMEOUT_MS, 1000, async () => {
    await rpc(port, 'system_health');
    return true;
  });
}

async function waitPeer(port, label) {
  await retry(`wait ${label} peer`, WAIT_TIMEOUT_MS, 1000, async () => {
    const health = await rpc(port, 'system_health');
    return Number(health?.peers ?? 0) >= 1;
  });
}

async function waitHeightAtLeast(port, target, label) {
  return await retry(`wait ${label} height >= ${target}`, WAIT_TIMEOUT_MS, 1000, async () => {
    const current = await height(port);
    return current >= target ? current : null;
  });
}

async function waitSameBlock(seedRpcPort, relayRpcPort, minHeight) {
  return await retry(`wait relay synchronized at height >= ${minHeight}`, WAIT_TIMEOUT_MS, 1000, async () => {
    const seedHeight = await height(seedRpcPort);
    const relayHeight = await height(relayRpcPort);
    const common = Math.min(seedHeight, relayHeight);
    if (common < minHeight) {
      return null;
    }
    const seedHash = await blockHash(seedRpcPort, common);
    const relayHash = await blockHash(relayRpcPort, common);
    return seedHash === relayHash ? common : null;
  });
}

function walletRpcUrl(relayRpcPort) {
  return `http://127.0.0.1:${relayRpcPort}`;
}

class Walletd {
  constructor(label, storePath) {
    this.label = label;
    this.storePath = storePath;
    this.pending = new Map();
    this.nextId = 1;
    this.stderr = '';
  }

  start(mode) {
    const stdoutLog = path.join(runDir, `${this.label}.walletd.stdout.log`);
    const stderrLog = path.join(runDir, `${this.label}.walletd.stderr.log`);
    const stdout = createWriteStream(stdoutLog, { flags: 'a' });
    const stderr = createWriteStream(stderrLog, { flags: 'a' });
    const env = {
      ...process.env,
      HEGEMON_WALLET_DA_SIDECAR: '0',
      HEGEMON_WALLET_PROOF_SIDECAR: '0',
      HEGEMON_WALLET_TRY_SIGNED_SUBMIT: '0'
    };
    this.child = spawn(WALLETD_BIN, ['--store', this.storePath, '--mode', mode], {
      cwd: ROOT_DIR,
      env,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    children.push({ child: this.child, label: `${this.label}-walletd` });
    this.child.stdout.pipe(stdout);
    this.child.stderr.pipe(stderr);
    this.child.stdin.write(`${PASSPHRASE}\n`);
    const reader = createInterface({ input: this.child.stdout });
    reader.on('line', (line) => this.handleLine(line));
    this.child.stderr.on('data', (data) => {
      this.stderr += data.toString();
    });
    this.child.on('exit', (code, signal) => {
      stdout.end();
      stderr.end();
      const error = new Error(`${this.label} walletd exited code=${code ?? 'null'} signal=${signal ?? 'null'}`);
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(error);
      }
      this.pending.clear();
      log(`${this.label} walletd exited code=${code ?? 'null'} signal=${signal ?? 'null'}`);
    });
  }

  handleLine(line) {
    let response;
    try {
      response = JSON.parse(line);
    } catch {
      return;
    }
    const pending = this.pending.get(response.id);
    if (!pending) {
      return;
    }
    this.pending.delete(response.id);
    clearTimeout(pending.timer);
    if (response.ok) {
      pending.resolve(response.result);
    } else {
      const error = new Error(
        `${this.label} ${pending.method} failed (${response.error_code ?? 'unknown'}): ${response.error}`
      );
      error.response = response;
      pending.reject(error);
    }
  }

  request(method, params = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
    if (!this.child || this.child.exitCode !== null) {
      fail(`${this.label} walletd is not running`);
    }
    const id = this.nextId++;
    const payload = JSON.stringify({ id, method, params });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${this.label} ${method} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer, method });
      this.child.stdin.write(`${payload}\n`);
    });
  }
}

function balanceOf(status) {
  const entry = (status.balances ?? []).find((item) => Number(item.assetId) === 0);
  return Number(entry?.spendable ?? entry?.total ?? 0);
}

async function syncWallet(wallet, relayRpcPort, forceRescan = false) {
  await wallet.request('sync.once', {
    ws_url: walletRpcUrl(relayRpcPort),
    force_rescan: forceRescan
  });
  return await wallet.request('status.get');
}

async function waitWalletBalanceAtLeast(wallet, relayRpcPort, target, label) {
  return await retry(`wait ${label} balance >= ${target}`, WAIT_TIMEOUT_MS, 3000, async () => {
    const status = await syncWallet(wallet, relayRpcPort);
    const balance = balanceOf(status);
    return balance >= target ? status : null;
  });
}

async function walletNotes(wallet, relayRpcPort) {
  await syncWallet(wallet, relayRpcPort);
  const response = await wallet.request('multisig.noteList', { asset_id: 0 });
  return response.notes ?? [];
}

async function waitSpendableCommitment(wallet, relayRpcPort, commitment, label) {
  return await retry(`wait ${label} spendable`, WAIT_TIMEOUT_MS, 3000, async () => {
    const notes = await walletNotes(wallet, relayRpcPort);
    return notes.find((note) => note.commitment === commitment) ?? null;
  });
}

async function sendAndConfirm(sender, recipient, relayRpcPort, recipientAddress, amount, memo) {
  const beforeStatus = await syncWallet(recipient, relayRpcPort);
  const before = balanceOf(beforeStatus);
  const beforeRelayPending = await pendingCount(relayRpcPort);
  const result = await sender.request('tx.send', {
    ws_url: walletRpcUrl(relayRpcPort),
    recipients: [{ address: recipientAddress, value: amount, asset_id: 0, memo }],
    fee: FEE,
    auto_consolidate: true
  });
  const afterRelayPending = await pendingCount(relayRpcPort);
  log(
    `submitted ${memo}: ${result.txHash}; relay pending ${beforeRelayPending} -> ${afterRelayPending}`
  );
  await waitWalletBalanceAtLeast(recipient, relayRpcPort, before + amount, memo);
  return result;
}

async function runDisclosureFlow(sender, relayRpcPort, txHash, recipientAddress, amount, memo) {
  const record = await retry(`wait disclosure record for ${txHash}`, WAIT_TIMEOUT_MS, 3000, async () => {
    const records = await sender.request('disclosure.list');
    return (records ?? []).find((entry) => String(entry.txId).toLowerCase() === txHash.toLowerCase()) ?? null;
  });
  if (record.recipientAddress !== recipientAddress) {
    fail(`disclosure recipient mismatch: ${record.recipientAddress} != ${recipientAddress}`);
  }
  if (Number(record.value) !== amount) {
    fail(`disclosure value mismatch: ${record.value} != ${amount}`);
  }
  if (Number(record.assetId) !== 0) {
    fail(`disclosure asset mismatch: ${record.assetId} != 0`);
  }
  if (record.memo !== memo) {
    fail(`disclosure memo mismatch: ${record.memo} != ${memo}`);
  }

  const disclosurePackage = await sender.request('disclosure.create', {
    ws_url: walletRpcUrl(relayRpcPort),
    tx_id: txHash,
    output: Number(record.outputIndex)
  });
  if (disclosurePackage.disclosed_memo !== memo) {
    fail(`disclosure package memo mismatch: ${disclosurePackage.disclosed_memo} != ${memo}`);
  }
  const verified = await sender.request('disclosure.verify', {
    ws_url: walletRpcUrl(relayRpcPort),
    package: disclosurePackage
  });
  if (!verified.verified) {
    fail(`disclosure package did not verify for ${txHash}`);
  }
  if (verified.recipient_address !== recipientAddress) {
    fail(`verified disclosure recipient mismatch: ${verified.recipient_address} != ${recipientAddress}`);
  }
  if (Number(verified.value) !== amount) {
    fail(`verified disclosure value mismatch: ${verified.value} != ${amount}`);
  }
  if (Number(verified.asset_id) !== 0) {
    fail(`verified disclosure asset mismatch: ${verified.asset_id} != 0`);
  }
  if (String(verified.commitment).toLowerCase() !== String(record.commitment).toLowerCase()) {
    fail(`verified disclosure commitment mismatch: ${verified.commitment} != ${record.commitment}`);
  }
  log(`disclosure verified for ${txHash} output ${record.outputIndex}`);
  return {
    txHash,
    outputIndex: Number(record.outputIndex),
    commitment: record.commitment,
    value: Number(record.value),
    verified: true
  };
}

function pickNote(notes, excluded, label, minValue = 1) {
  const note = notes
    .filter((candidate) => !excluded.has(candidate.commitment))
    .filter((candidate) => Number(candidate.value) >= minValue)
    .sort((a, b) => Number(b.value) - Number(a.value))[0];
  if (!note) {
    fail(`missing spendable note for ${label}`);
  }
  excluded.add(note.commitment);
  return note;
}

async function runMultisigFlow(miner, recipient, relayRpcPort, recipientAddress) {
  const signer = await miner.request('multisig.localSignerTag');
  const account = await miner.request('multisig.accountCreate', {
    threshold: 1,
    policySignerTags: [signer.signerTag]
  });
  log(`created private multisig account ${account.accountId}`);

  const notes = await walletNotes(miner, relayRpcPort);
  const excluded = new Set();
  const valueNote = pickNote(notes, excluded, 'multisig value lock', MULTISIG_FINAL_AMOUNT + FEE * 2);
  const setupNote = pickNote(notes, excluded, 'multisig setup', FEE + 1);
  const signerNote = pickNote(notes, excluded, 'multisig approval', FEE + 1);

  const valueLock = await miner.request('multisig.valueLockSubmit', {
    wsUrl: walletRpcUrl(relayRpcPort),
    accountId: account.accountId,
    sourceNoteCommitment: valueNote.commitment,
    recipients: [
      {
        address: recipientAddress,
        value: MULTISIG_FINAL_AMOUNT,
        asset_id: 0,
        memo: 'no-ssh-e2e-multisig-final'
      }
    ],
    finalFee: FEE,
    lockFee: FEE
  });
  log(`multisig value-lock submitted ${valueLock.txHash}`);
  await waitSpendableCommitment(
    miner,
    relayRpcPort,
    valueLock.lockedValueNoteCommitment,
    'multisig locked value note'
  );

  const setup = await miner.request('multisig.setupSubmit', {
    wsUrl: walletRpcUrl(relayRpcPort),
    accountId: account.accountId,
    intentDigest: valueLock.intentDigest,
    fundingNoteCommitment: setupNote.commitment,
    fee: FEE
  });
  const initialAccumulator = setup.outputCommitments[0];
  log(`multisig setup submitted ${setup.txHash}`);
  await waitSpendableCommitment(miner, relayRpcPort, initialAccumulator, 'initial accumulator');

  const approval = await miner.request('multisig.approvalSubmit', {
    wsUrl: walletRpcUrl(relayRpcPort),
    accountId: account.accountId,
    accumulatorCommitment: initialAccumulator,
    signerNoteCommitment: signerNote.commitment,
    fee: FEE
  });
  const thresholdAccumulator = approval.outputCommitments[0];
  log(`multisig approval submitted ${approval.txHash}`);
  await waitSpendableCommitment(miner, relayRpcPort, thresholdAccumulator, 'threshold accumulator');

  const recipientBefore = balanceOf(await syncWallet(recipient, relayRpcPort));
  const finalPlan = await miner.request('multisig.finalPlan', {
    accountId: account.accountId,
    valueNoteCommitment: valueLock.lockedValueNoteCommitment,
    recipients: [
      {
        address: recipientAddress,
        value: MULTISIG_FINAL_AMOUNT,
        asset_id: 0,
        memo: 'no-ssh-e2e-multisig-final'
      }
    ],
    fee: FEE
  });
  if (finalPlan.intentDigest !== valueLock.intentDigest) {
    fail(`multisig final plan digest mismatch: ${finalPlan.intentDigest} != ${valueLock.intentDigest}`);
  }
  const finalTx = await miner.request('multisig.finalSubmit', {
    wsUrl: walletRpcUrl(relayRpcPort),
    accountId: account.accountId,
    intentDigest: valueLock.intentDigest,
    accumulatorCommitment: thresholdAccumulator
  });
  log(`multisig final submitted ${finalTx.txHash}`);
  await waitWalletBalanceAtLeast(
    recipient,
    relayRpcPort,
    recipientBefore + MULTISIG_FINAL_AMOUNT,
    'multisig recipient'
  );
  return {
    accountId: account.accountId,
    valueLockTx: valueLock.txHash,
    setupTx: setup.txHash,
    approvalTx: approval.txHash,
    finalTx: finalTx.txHash
  };
}

async function runConsolidationFlow(recipient, miner, relayRpcPort, minerAddress) {
  let notes = await walletNotes(recipient, relayRpcPort);
  if (notes.length <= 2) {
    fail(`consolidation precondition failed: recipient only has ${notes.length} notes`);
  }
  notes = notes.sort((a, b) => Number(b.value) - Number(a.value));
  const twoLargest = Number(notes[0].value) + Number(notes[1].value);
  const total = notes.reduce((sum, note) => sum + Number(note.value), 0);
  if (total <= twoLargest + FEE) {
    fail(`consolidation precondition failed: notes do not require more than two inputs`);
  }
  const target = Math.min(total - FEE, twoLargest + 1);
  const plan = await recipient.request('tx.plan', {
    recipients: [{ address: minerAddress, value: target, asset_id: 0, memo: 'no-ssh-e2e-consolidated' }],
    fee: FEE
  });
  if (!plan.needsConsolidation) {
    fail(`expected tx.plan to require consolidation; plan=${JSON.stringify(plan)}`);
  }
  log(
    `consolidation plan requires ${plan.plan?.txsNeeded ?? '?'} tx(s) over ${notes.length} notes`
  );
  const beforeRecipient = balanceOf(await syncWallet(recipient, relayRpcPort));
  const result = await recipient.request('tx.send', {
    ws_url: walletRpcUrl(relayRpcPort),
    recipients: [{ address: minerAddress, value: target, asset_id: 0, memo: 'no-ssh-e2e-consolidated' }],
    fee: FEE,
    auto_consolidate: true
  });
  log(`consolidating send submitted ${result.txHash}`);
  await retry('wait recipient consolidation spend confirmed', WAIT_TIMEOUT_MS, 3000, async () => {
    const status = await syncWallet(recipient, relayRpcPort);
    return balanceOf(status) < beforeRecipient ? status : null;
  });
  await syncWallet(miner, relayRpcPort);
  return { txHash: result.txHash, target };
}

function startAppRelay(commonEnv, relayBasePath, relayRpcPort, relayP2pPort, seedP2pPort, restartIndex = 0) {
  const label = restartIndex === 0 ? 'app-relay' : `app-relay-restart-${restartIndex}`;
  return spawnLogged(
    label,
    NODE_BIN,
    [
      '--dev',
      '--base-path',
      relayBasePath,
      '--rpc-port',
      `${relayRpcPort}`,
      '--port',
      `${relayP2pPort}`,
      '--rpc-methods',
      'unsafe',
      '--name',
      'no-ssh-e2e-app-relay'
    ],
    {
      env: {
        ...commonEnv,
        HEGEMON_MINE: '0',
        HEGEMON_SEEDS: `127.0.0.1:${seedP2pPort}`
      }
    }
  );
}

async function restartRelayAndResync({
  appRelay,
  commonEnv,
  relayBasePath,
  relayRpcPort,
  relayP2pPort,
  seedRpcPort,
  seedP2pPort,
  miner,
  recipient,
  expectedCommonHeight,
  expectedMinerSpendable,
  expectedRecipientSpendable
}) {
  await stopLogged(appRelay);
  const restarted = startAppRelay(commonEnv, relayBasePath, relayRpcPort, relayP2pPort, seedP2pPort, 1);
  await waitRpc(relayRpcPort, 'restarted relay');
  await waitPeer(relayRpcPort, 'restarted relay');
  const restartCommonHeight = await waitSameBlock(seedRpcPort, relayRpcPort, expectedCommonHeight);
  const seedPendingAfterRestart = await pendingCount(seedRpcPort);
  const relayPendingAfterRestart = await pendingCount(relayRpcPort);
  const minerRestarted = await syncWallet(miner, relayRpcPort, true);
  const recipientRestarted = await syncWallet(recipient, relayRpcPort, true);
  const minerSpendableAfterRestart = balanceOf(minerRestarted);
  const recipientSpendableAfterRestart = balanceOf(recipientRestarted);
  if (minerSpendableAfterRestart < expectedMinerSpendable) {
    fail(
      `miner balance regressed after relay restart: ${minerSpendableAfterRestart} < ${expectedMinerSpendable}`
    );
  }
  if (recipientSpendableAfterRestart < expectedRecipientSpendable) {
    fail(
      `recipient balance regressed after relay restart: ${recipientSpendableAfterRestart} < ${expectedRecipientSpendable}`
    );
  }
  if (seedPendingAfterRestart !== 0 || relayPendingAfterRestart !== 0) {
    fail(
      `pending actions remained after relay restart: seed=${seedPendingAfterRestart} relay=${relayPendingAfterRestart}`
    );
  }
  log(
    `restarted relay rejoined at height ${restartCommonHeight}; miner=${minerSpendableAfterRestart} recipient=${recipientSpendableAfterRestart}`
  );
  return {
    restarted,
    restartCommonHeight,
    seedPendingAfterRestart,
    relayPendingAfterRestart,
    minerSpendableAfterRestart,
    recipientSpendableAfterRestart
  };
}

async function main() {
  ensureExecutable(NODE_BIN, 'hegemon-node');
  ensureExecutable(WALLETD_BIN, 'walletd');
  log('using native --dev profile; no legacy JSON chain spec or --chain flag');

  const seedRpcPort = await freePort();
  const seedP2pPort = await freePort();
  const relayRpcPort = await freePort();
  const relayP2pPort = await freePort();
  log(`run dir ${runDir}`);
  log(`ports seed rpc=${seedRpcPort} p2p=${seedP2pPort}; relay rpc=${relayRpcPort} p2p=${relayP2pPort}`);

  const miner = new Walletd('miner', path.join(runDir, 'miner.wallet'));
  const recipient = new Walletd('recipient', path.join(runDir, 'recipient.wallet'));
  miner.start('create');
  recipient.start('create');
  const minerStatus = await miner.request('status.get');
  const recipientStatus = await recipient.request('status.get');
  const minerAddress = minerStatus.primaryAddress;
  const recipientAddress = recipientStatus.primaryAddress;
  log(`miner wallet ${minerAddress.slice(0, 24)}...`);
  log(`recipient wallet ${recipientAddress.slice(0, 24)}...`);

  const commonEnv = {
    ...process.env,
    HEGEMON_PQ_STRICT_COMPATIBILITY: '1',
    HEGEMON_MAX_BLOCK_TXS: process.env.HEGEMON_MAX_BLOCK_TXS ?? '64',
    HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK:
      process.env.HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK ?? '64'
  };
  const seedBasePath = path.join(runDir, 'seed-node');
  const relayBasePath = path.join(runDir, 'relay-node');
  spawnLogged(
    'seed-miner',
    NODE_BIN,
    [
      '--dev',
      '--base-path',
      seedBasePath,
      '--rpc-port',
      `${seedRpcPort}`,
      '--port',
      `${seedP2pPort}`,
      '--rpc-methods',
      'unsafe',
      '--name',
      'no-ssh-e2e-seed'
    ],
    {
      env: {
        ...commonEnv,
        HEGEMON_BOOTSTRAP_AUTHORING: '1',
        HEGEMON_MINE: '1',
        HEGEMON_MINE_THREADS: process.env.HEGEMON_E2E_MINE_THREADS ?? '4',
        HEGEMON_MINER_ADDRESS: minerAddress
      }
    }
  );
  const appRelay = startAppRelay(commonEnv, relayBasePath, relayRpcPort, relayP2pPort, seedP2pPort);

  await waitRpc(seedRpcPort, 'seed');
  await waitRpc(relayRpcPort, 'relay');
  await waitPeer(relayRpcPort, 'relay');
  const startHeight = await waitHeightAtLeast(seedRpcPort, 1, 'seed');
  await waitSameBlock(seedRpcPort, relayRpcPort, startHeight);
  log(`relay joined seed and synced at height ${startHeight}`);

  const fundedStatus = await waitWalletBalanceAtLeast(miner, relayRpcPort, 1, 'miner coinbase');
  log(`miner recovered spendable balance ${balanceOf(fundedStatus)} units through relay RPC`);

  const smallTxs = [];
  for (let index = 0; index < SMALL_TX_COUNT; index += 1) {
    smallTxs.push(
      await sendAndConfirm(
        miner,
        recipient,
        relayRpcPort,
        recipientAddress,
        SMALL_AMOUNT,
        `no-ssh-e2e-small-${index + 1}`
      )
    );
  }
  const disclosure = await runDisclosureFlow(
    miner,
    relayRpcPort,
    smallTxs[0].txHash,
    recipientAddress,
    SMALL_AMOUNT,
    'no-ssh-e2e-small-1'
  );

  const consolidation = await runConsolidationFlow(recipient, miner, relayRpcPort, minerAddress);
  const multisig = await runMultisigFlow(miner, recipient, relayRpcPort, recipientAddress);
  const finalCommonHeight = await waitSameBlock(seedRpcPort, relayRpcPort, await height(seedRpcPort));
  const seedPending = await pendingCount(seedRpcPort);
  const relayPending = await pendingCount(relayRpcPort);
  const recipientFinal = await syncWallet(recipient, relayRpcPort);
  const minerFinal = await syncWallet(miner, relayRpcPort);
  const restart = await restartRelayAndResync({
    appRelay,
    commonEnv,
    relayBasePath,
    relayRpcPort,
    relayP2pPort,
    seedRpcPort,
    seedP2pPort,
    miner,
    recipient,
    expectedCommonHeight: finalCommonHeight,
    expectedMinerSpendable: balanceOf(minerFinal),
    expectedRecipientSpendable: balanceOf(recipientFinal)
  });

  const summary = {
    ok: true,
    durationSeconds: Math.round((Date.now() - startedAt) / 1000),
    runDir,
    seedRpcPort,
    relayRpcPort,
    finalCommonHeight,
    seedPending,
    relayPending,
    minerSpendable: balanceOf(minerFinal),
    recipientSpendable: balanceOf(recipientFinal),
    restart: {
      commonHeight: restart.restartCommonHeight,
      seedPending: restart.seedPendingAfterRestart,
      relayPending: restart.relayPendingAfterRestart,
      minerSpendable: restart.minerSpendableAfterRestart,
      recipientSpendable: restart.recipientSpendableAfterRestart
    },
    smallTxs: smallTxs.map((tx) => tx.txHash),
    disclosure,
    consolidation,
    multisig
  };
  console.log(JSON.stringify(summary, null, 2));
}

async function cleanup() {
  for (const { child, label } of children.reverse()) {
    if (!childExited(child)) {
      log(`stopping ${label}`);
      child.kill('SIGTERM');
    }
  }
  await sleep(1500);
  for (const { child, label } of children) {
    if (!childExited(child)) {
      log(`killing ${label}`);
      child.kill('SIGKILL');
    }
  }
  if (!KEEP_TMP) {
    rmSync(runDir, { recursive: true, force: true });
  } else {
    log(`kept run dir ${runDir}`);
  }
}

process.on('SIGINT', async () => {
  await cleanup();
  process.exit(130);
});
process.on('SIGTERM', async () => {
  await cleanup();
  process.exit(143);
});

try {
  await main();
  await cleanup();
} catch (error) {
  console.error(`[no-ssh-e2e] ERROR: ${error.stack ?? error.message}`);
  log(`failure logs kept at ${runDir}`);
  await cleanup();
  process.exit(1);
}
