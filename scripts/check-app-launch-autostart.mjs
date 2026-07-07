#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const APP_PATH =
  process.env.HEGEMON_APP_BUNDLE ?? path.join(ROOT_DIR, 'hegemon-app/dist/mac-arm64/Hegemon.app');
const BUNDLE_ID = process.env.HEGEMON_APP_BUNDLE_ID ?? 'com.hegemon.desktop';
const RPC_URL = process.env.HEGEMON_APP_AUTOSTART_RPC_URL ?? 'http://127.0.0.1:9955';
const APPROVED_SEED = process.env.HEGEMON_APP_EXPECTED_SEED ?? 'hegemon.pauli.group:30333';
const RPC_DOWN_TIMEOUT_MS = Number.parseInt(
  process.env.HEGEMON_APP_AUTOSTART_RPC_DOWN_TIMEOUT_MS ?? '45000',
  10
);
const RPC_UP_TIMEOUT_MS = Number.parseInt(process.env.HEGEMON_APP_AUTOSTART_RPC_UP_TIMEOUT_MS ?? '90000', 10);
const LIVE_TIMEOUT_MS = Number.parseInt(process.env.HEGEMON_APP_AUTOSTART_LIVE_TIMEOUT_MS ?? '180000', 10);
const POLL_MS = Number.parseInt(process.env.HEGEMON_APP_AUTOSTART_POLL_MS ?? '1500', 10);
const MIN_PEERS = Number.parseInt(process.env.HEGEMON_APP_AUTOSTART_MIN_PEERS ?? '1', 10);
const MIN_HEIGHT = Number.parseInt(process.env.HEGEMON_APP_AUTOSTART_MIN_HEIGHT ?? '1', 10);
const MAX_SYNC_LAG = Number.parseInt(process.env.HEGEMON_APP_AUTOSTART_MAX_SYNC_LAG ?? '2', 10);

function log(message) {
  console.log(`[app-autostart] ${message}`);
}

function fail(message) {
  throw new Error(message);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function command(commandName, args, options = {}) {
  const result = spawnSync(commandName, args, {
    encoding: 'utf8',
    stdio: options.stdio ?? 'pipe'
  });
  if (result.status !== 0 && !options.allowFailure) {
    const stderr = result.stderr?.trim();
    const stdout = result.stdout?.trim();
    fail(
      `${commandName} ${args.join(' ')} failed with status ${result.status}${
        stderr ? `: ${stderr}` : stdout ? `: ${stdout}` : ''
      }`
    );
  }
  return result.stdout ?? '';
}

function rpc(method, params = []) {
  const endpoint = new URL(RPC_URL);
  if (endpoint.protocol !== 'http:') {
    fail(`Only http:// loopback RPC URLs are supported by this gate: ${RPC_URL}`);
  }

  const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: endpoint.hostname,
        port: endpoint.port || '80',
        method: 'POST',
        path: endpoint.pathname || '/',
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
            const payload = JSON.parse(text);
            if (payload.error) {
              reject(new Error(`${method}: ${JSON.stringify(payload.error)}`));
              return;
            }
            resolve(payload.result);
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

async function maybeRpc(method, params = []) {
  try {
    return await rpc(method, params);
  } catch {
    return null;
  }
}

async function waitFor(label, timeoutMs, fn) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const value = await fn();
      if (value) {
        return value;
      }
    } catch (error) {
      lastError = error;
    }
    await sleep(POLL_MS);
  }
  const suffix = lastError instanceof Error ? `; last error: ${lastError.message}` : '';
  fail(`${label} timed out after ${timeoutMs}ms${suffix}`);
}

async function rpcReachable() {
  try {
    await rpc('system_health');
    return true;
  } catch {
    return false;
  }
}

function toNumber(value) {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string') {
    const parsed = value.startsWith('0x') ? Number.parseInt(value, 16) : Number.parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function field(object, camelName, snakeName = camelName) {
  if (!object || typeof object !== 'object') {
    return undefined;
  }
  return object[camelName] ?? object[snakeName];
}

async function readSnapshot() {
  const [health, consensus, mining, config, peerList, pending, version, genesis] = await Promise.all([
    maybeRpc('system_health'),
    maybeRpc('hegemon_consensusStatus'),
    maybeRpc('hegemon_miningStatus'),
    maybeRpc('hegemon_nodeConfig'),
    maybeRpc('hegemon_peerList'),
    maybeRpc('author_pendingExtrinsics'),
    maybeRpc('system_version'),
    maybeRpc('chain_getBlockHash', [0])
  ]);
  const peers = Math.max(
    toNumber(health?.peers) ?? 0,
    toNumber(consensus?.peers) ?? 0,
    Array.isArray(peerList) ? peerList.length : 0
  );
  const height =
    toNumber(consensus?.height) ??
    toNumber(mining?.block_height) ??
    toNumber(mining?.blockHeight) ??
    0;
  const target =
    toNumber(consensus?.sync_target_height) ??
    toNumber(consensus?.syncTargetHeight) ??
    toNumber(mining?.sync_target_height) ??
    toNumber(mining?.syncTargetHeight) ??
    height;
  const syncing = Boolean(consensus?.syncing ?? health?.isSyncing ?? false);
  return {
    health,
    consensus,
    mining,
    config,
    peerList,
    pending,
    version,
    genesis,
    peers,
    height,
    target,
    syncing
  };
}

function configFacts(config) {
  const rpcExternal = field(config, 'rpcExternal', 'rpc_external');
  const rpcMethods = field(config, 'rpcMethods', 'rpc_methods');
  const rpcListenAddr = String(field(config, 'rpcListenAddr', 'rpc_listen_addr') ?? '');
  const bootstrapNodes = field(config, 'bootstrapNodes', 'bootstrap_nodes');
  const bootstrapText = Array.isArray(bootstrapNodes)
    ? bootstrapNodes.join(',')
    : bootstrapNodes
      ? String(bootstrapNodes)
      : '';
  return { rpcExternal, rpcMethods, rpcListenAddr, bootstrapText };
}

function isLoopbackRpc(config) {
  const { rpcExternal, rpcListenAddr } = configFacts(config);
  if (rpcExternal === true) {
    return false;
  }
  const text = rpcListenAddr.toLowerCase();
  return !text || text.includes('127.0.0.1') || text.includes('localhost') || text.includes('::1');
}

function usesApprovedSeed(config) {
  const { bootstrapText } = configFacts(config);
  const [expectedHost, expectedPort] = APPROVED_SEED.split(':');
  return bootstrapText.includes(expectedHost) && bootstrapText.includes(expectedPort);
}

function summarizeSnapshot(snapshot) {
  const { rpcExternal, rpcMethods, rpcListenAddr, bootstrapText } = configFacts(snapshot.config);
  return {
    version: snapshot.version,
    genesis: snapshot.genesis,
    height: snapshot.height,
    target: snapshot.target,
    peers: snapshot.peers,
    syncing: snapshot.syncing,
    pending: Array.isArray(snapshot.pending) ? snapshot.pending.length : null,
    mining: snapshot.mining?.is_mining ?? snapshot.mining?.isMining ?? null,
    mining_threads: snapshot.mining?.threads ?? null,
    hash_rate: snapshot.mining?.hash_rate ?? snapshot.mining?.hashRate ?? null,
    rpc_external: rpcExternal ?? null,
    rpc_methods: rpcMethods ?? null,
    rpc_listen_addr: rpcListenAddr || null,
    bootstrap_nodes: bootstrapText || null
  };
}

function quitApp() {
  if (process.platform !== 'darwin') {
    fail('This packaged-app launch gate currently supports macOS only.');
  }
  command('osascript', ['-e', `tell application id "${BUNDLE_ID}" to quit`], { allowFailure: true });
}

function processSnapshot() {
  const appProcesses = command('pgrep', ['-fl', 'Hegemon.app'], { allowFailure: true }).trim();
  const nodeProcesses = command('pgrep', ['-fl', 'hegemon-node'], { allowFailure: true }).trim();
  return [appProcesses ? `Hegemon.app:\n${appProcesses}` : null, nodeProcesses ? `hegemon-node:\n${nodeProcesses}` : null]
    .filter(Boolean)
    .join('\n');
}

async function main() {
  if (!existsSync(APP_PATH)) {
    fail(`Packaged app bundle not found: ${APP_PATH}. Run npm --prefix hegemon-app run package first.`);
  }

  log(`quitting existing ${BUNDLE_ID} instance`);
  quitApp();

  await waitFor('managed RPC to stop after app quit', RPC_DOWN_TIMEOUT_MS, async () => {
    return !(await rpcReachable());
  }).catch((error) => {
    const processes = processSnapshot();
    fail(
      `${error.message}. RPC ${RPC_URL} is still serving before launch, so the autostart baseline is dirty.${
        processes ? `\n${processes}` : ''
      }`
    );
  });

  log(`opening packaged app: ${APP_PATH}`);
  command('open', ['-n', APP_PATH]);

  await waitFor('packaged app to expose managed loopback RPC', RPC_UP_TIMEOUT_MS, async () => {
    return await rpcReachable();
  });

  const liveSnapshot = await waitFor('packaged app to reach live Hegemon testnet P2P state', LIVE_TIMEOUT_MS, async () => {
    const snapshot = await readSnapshot();
    const lag = Math.max(0, snapshot.target - snapshot.height);
    const healthy =
      snapshot.peers >= MIN_PEERS &&
      snapshot.height >= MIN_HEIGHT &&
      !snapshot.syncing &&
      lag <= MAX_SYNC_LAG &&
      isLoopbackRpc(snapshot.config) &&
      usesApprovedSeed(snapshot.config);
    return healthy ? snapshot : null;
  });

  const summary = summarizeSnapshot(liveSnapshot);
  log('PASS packaged app autostarted a local loopback node and reached live Hegemon testnet P2P');
  console.log(JSON.stringify(summary, null, 2));
}

main().catch((error) => {
  console.error(`[app-autostart] FAIL ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
