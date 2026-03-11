import { EventEmitter } from 'node:events';
import { createRequire } from 'node:module';
import { Worker } from 'node:worker_threads';
import type { PoolMinerStartRequest, PoolMinerStatus, PoolStatus, PoolWorkerSnapshot } from '../src/types';

type RpcRequest = {
  jsonrpc: '2.0';
  id: number;
  method: string;
  params?: unknown[];
};

type PoolWorkWire = {
  available?: boolean;
  height?: number | null;
  pre_hash?: string | null;
  parent_hash?: string | null;
  network_difficulty?: number | null;
  share_difficulty?: number | null;
  reason?: string | null;
};

type PoolStatusWire = {
  available?: boolean;
  network_difficulty?: number | null;
  share_difficulty?: number | null;
  accepted_shares?: number | null;
  rejected_shares?: number | null;
  worker_count?: number | null;
  workers?: Array<{
    worker_name?: string;
    accepted_shares?: number;
    rejected_shares?: number;
    block_candidates?: number;
    payout_fraction_ppm?: number;
    last_share_at_ms?: number | null;
  }>;
};

type WorkerMessage =
  | {
      type: 'share';
      nonce: number;
      height: number;
      preHash: string;
      parentHash: string;
    }
  | { type: 'hashes'; count: number }
  | { type: 'log'; message: string }
  | { type: 'error'; error: string };

type WorkerCommand =
  | {
      type: 'setWork';
      work: {
        height: number;
        preHash: string;
        parentHash: string;
        networkDifficulty: number;
        shareDifficulty: number;
      };
    }
  | { type: 'clearWork' }
  | { type: 'stop' };

const WORKER_SCRIPT = `
const { parentPort, workerData } = require('node:worker_threads');
const { createBLAKE3 } = require(workerData.hashWasmModulePath);

let running = true;
let currentWork = null;
let currentPreHashBytes = null;
let currentWorkerNonce = Number(workerData.workerIndex || 0);
const stride = Math.max(1, Number(workerData.totalThreads || 1));
const HASH_REPORT_INTERVAL_MS = 250;
const SHARE_REPORT_INTERVAL_MS = 250;
let pendingHashCount = 0;
let lastHashReportAt = Date.now();
let lastShareReportAt = 0;

function compactToTarget(bits) {
  const exponent = bits >>> 24;
  const mantissa = bits & 0x00ffffff;
  if (mantissa === 0) {
    return null;
  }
  let target = BigInt(mantissa);
  if (exponent > 3) {
    target <<= BigInt(8 * (exponent - 3));
  } else {
    target >>= BigInt(8 * (3 - exponent));
  }
  return target;
}

function encodeNonceLE(nonce) {
  const out = Buffer.alloc(8);
  let remaining = BigInt(nonce);
  for (let i = 0; i < 8; i += 1) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

function nextNonce() {
  const nonce = currentWorkerNonce;
  currentWorkerNonce += stride;
  if (!Number.isSafeInteger(currentWorkerNonce) || currentWorkerNonce > Number.MAX_SAFE_INTEGER - stride) {
    currentWorkerNonce = Number(workerData.workerIndex || 0);
  }
  return nonce;
}

parentPort.on('message', (message) => {
  if (!message || typeof message !== 'object') {
    return;
  }
  if (message.type === 'setWork') {
    currentWork = {
      ...message.work,
      shareTarget: compactToTarget(message.work.shareDifficulty),
      preHashHex: String(message.work.preHash || '').replace(/^0x/i, '').toLowerCase(),
      parentHashHex: String(message.work.parentHash || '')
    };
    currentPreHashBytes = Buffer.from(currentWork.preHashHex, 'hex');
    currentWorkerNonce = Number(workerData.workerIndex || 0);
    pendingHashCount = 0;
    lastHashReportAt = Date.now();
    lastShareReportAt = 0;
    return;
  }
  if (message.type === 'clearWork') {
    currentWork = null;
    currentPreHashBytes = null;
    return;
  }
  if (message.type === 'stop') {
    running = false;
  }
});

async function main() {
  const hasher = await createBLAKE3();
  while (running) {
    if (!currentWork || !currentPreHashBytes || currentWork.shareTarget === null) {
      if (pendingHashCount > 0) {
        parentPort.postMessage({ type: 'hashes', count: pendingHashCount });
        pendingHashCount = 0;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
      continue;
    }

    let processed = 0;
    while (running && currentWork && currentPreHashBytes && processed < 512) {
      const nonce = nextNonce();
      hasher.init();
      hasher.update(currentPreHashBytes);
      hasher.update(encodeNonceLE(nonce));
      const workHex = hasher.digest();
      const workValue = BigInt('0x' + workHex);
      if (workValue <= currentWork.shareTarget) {
        const now = Date.now();
        if (now - lastShareReportAt >= SHARE_REPORT_INTERVAL_MS) {
          lastShareReportAt = now;
          parentPort.postMessage({
            type: 'share',
            nonce,
            height: currentWork.height,
            preHash: '0x' + currentWork.preHashHex,
            parentHash: currentWork.parentHashHex
          });
        }
      }
      processed += 1;
    }

    if (processed > 0) {
      pendingHashCount += processed;
      const now = Date.now();
      if (now - lastHashReportAt >= HASH_REPORT_INTERVAL_MS) {
        parentPort.postMessage({ type: 'hashes', count: pendingHashCount });
        pendingHashCount = 0;
        lastHashReportAt = now;
      }
    }
    await new Promise((resolve) => setImmediate(resolve));
  }

  if (pendingHashCount > 0) {
    parentPort.postMessage({ type: 'hashes', count: pendingHashCount });
  }
}

main().catch((error) => {
  parentPort.postMessage({
    type: 'error',
    error: error instanceof Error ? error.message : String(error)
  });
});
`;

const clampThreadCount = (threads: number | undefined) => {
  if (!Number.isFinite(threads) || !threads || threads < 1) {
    return 1;
  }
  return Math.max(1, Math.min(32, Math.floor(threads)));
};

const nodeRequire = createRequire(import.meta.url);
const hashWasmModulePath = nodeRequire.resolve('hash-wasm');
const RPC_TIMEOUT_MS = 5_000;

const normalizeEndpoint = (endpoint: string) => {
  const trimmed = endpoint.trim();
  if (trimmed.startsWith('ws://')) {
    return `http://${trimmed.slice(5)}`;
  }
  if (trimmed.startsWith('wss://')) {
    return `https://${trimmed.slice(6)}`;
  }
  return trimmed;
};

const mapPoolStatus = (payload: PoolStatusWire | null): PoolStatus | null => {
  if (!payload) {
    return null;
  }
  const workers: PoolWorkerSnapshot[] = Array.isArray(payload.workers)
    ? payload.workers.map((worker) => ({
        workerName: String(worker.worker_name ?? ''),
        acceptedShares: Number(worker.accepted_shares ?? 0),
        rejectedShares: Number(worker.rejected_shares ?? 0),
        blockCandidates: Number(worker.block_candidates ?? 0),
        payoutFractionPpm: Number(worker.payout_fraction_ppm ?? 0),
        lastShareAtMs:
          worker.last_share_at_ms === null || worker.last_share_at_ms === undefined
            ? null
            : Number(worker.last_share_at_ms)
      }))
    : [];
  return {
    available: Boolean(payload.available),
    networkDifficulty:
      payload.network_difficulty === null || payload.network_difficulty === undefined
        ? null
        : Number(payload.network_difficulty),
    shareDifficulty:
      payload.share_difficulty === null || payload.share_difficulty === undefined
        ? null
        : Number(payload.share_difficulty),
    acceptedShares: Number(payload.accepted_shares ?? 0),
    rejectedShares: Number(payload.rejected_shares ?? 0),
    workerCount: Number(payload.worker_count ?? workers.length),
    workers
  };
};

export class PoolMinerManager extends EventEmitter {
  private workers: Worker[] = [];
  private logs: string[] = [];
  private requestId = 0;
  private running = false;
  private endpoint: string | null = null;
  private workerName: string | null = null;
  private authToken: string | undefined;
  private threads = 0;
  private acceptedShares = 0;
  private rejectedShares = 0;
  private blockCandidates = 0;
  private hashesComputed = 0;
  private startedAtMs = 0;
  private currentHeight: number | null = null;
  private lastShareAtMs: number | null = null;
  private error: string | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private pool: PoolStatus | null = null;
  private currentTemplateKey: string | null = null;

  async start(request: PoolMinerStartRequest): Promise<void> {
    const endpoint = normalizeEndpoint(request.endpoint);
    if (!endpoint) {
      throw new Error('Pool endpoint is required.');
    }
    if (!request.workerName.trim()) {
      throw new Error('Worker name is required.');
    }
    const threads = clampThreadCount(request.threads);

    await this.stop();

    this.running = true;
    this.endpoint = endpoint;
    this.workerName = request.workerName.trim();
    this.authToken = request.authToken?.trim() || undefined;
    this.threads = threads;
    this.acceptedShares = 0;
    this.rejectedShares = 0;
    this.blockCandidates = 0;
    this.hashesComputed = 0;
    this.startedAtMs = Date.now();
    this.currentHeight = null;
    this.lastShareAtMs = null;
    this.error = null;
    this.pool = null;
    this.currentTemplateKey = null;
    this.appendLog(`Starting pooled hash worker ${this.workerName} against ${endpoint} with ${threads} thread(s).`);

    for (let workerIndex = 0; workerIndex < threads; workerIndex += 1) {
      const worker = new Worker(WORKER_SCRIPT, {
        eval: true,
        workerData: { workerIndex, totalThreads: threads, hashWasmModulePath }
      });
      worker.on('message', (message: WorkerMessage) => {
        void this.handleWorkerMessage(message);
      });
      worker.on('error', (error) => {
        this.error = error.message;
        this.appendLog(`Worker ${workerIndex} failed: ${error.message}`);
      });
      worker.on('exit', (code) => {
        if (this.running && code !== 0) {
          this.appendLog(`Worker ${workerIndex} exited with code ${code}.`);
        }
      });
      this.workers.push(worker);
    }

    void this.pollPool();
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
    for (const worker of this.workers) {
      worker.postMessage({ type: 'stop' } satisfies WorkerCommand);
      await worker.terminate().catch(() => undefined);
    }
    this.workers = [];
    this.currentTemplateKey = null;
    if (this.endpoint || this.workerName) {
      this.appendLog('Stopped pooled hash worker.');
    }
    this.endpoint = null;
    this.workerName = null;
    this.authToken = undefined;
    this.threads = 0;
    this.currentHeight = null;
    this.pool = null;
  }

  getStatus(): PoolMinerStatus {
    const elapsedMs = this.startedAtMs > 0 ? Date.now() - this.startedAtMs : 0;
    const hashRate = elapsedMs > 0 ? this.hashesComputed / (elapsedMs / 1000) : 0;
    return {
      running: this.running,
      endpoint: this.endpoint,
      workerName: this.workerName,
      threads: this.threads,
      currentHeight: this.currentHeight,
      acceptedShares: this.acceptedShares,
      rejectedShares: this.rejectedShares,
      blockCandidates: this.blockCandidates,
      hashesComputed: this.hashesComputed,
      hashRate,
      lastShareAtMs: this.lastShareAtMs,
      pool: this.pool,
      error: this.error
    };
  }

  getLogs(): string[] {
    return [...this.logs];
  }

  private async handleWorkerMessage(message: WorkerMessage): Promise<void> {
    if (!this.running || !this.endpoint || !this.workerName) {
      return;
    }
    if (message.type === 'hashes') {
      this.hashesComputed += Number(message.count || 0);
      return;
    }
    if (message.type === 'log') {
      this.appendLog(message.message);
      return;
    }
    if (message.type === 'error') {
      this.error = message.error;
      this.appendLog(`Worker error: ${message.error}`);
      return;
    }

    try {
      const response = await this.rpcCall('hegemon_submitPoolShare', [
        {
          worker_name: this.workerName,
          nonce: message.nonce,
          pre_hash: message.preHash,
          parent_hash: message.parentHash,
          height: message.height,
          auth_token: this.authToken
        }
      ]);
      if (response?.accepted) {
        this.acceptedShares += 1;
        if (response.block_candidate) {
          this.blockCandidates += 1;
        }
        this.lastShareAtMs = Date.now();
        this.appendLog(
          response.block_candidate
            ? `Accepted full-target share at height ${message.height} (nonce ${message.nonce}).`
            : `Accepted pool share at height ${message.height} (nonce ${message.nonce}).`
        );
      } else {
        this.rejectedShares += 1;
        this.appendLog(`Rejected pool share at height ${message.height}: ${String(response?.error ?? 'unknown error')}`);
      }
    } catch (error) {
      this.rejectedShares += 1;
      this.error = error instanceof Error ? error.message : String(error);
      this.appendLog(`Pool submission failed: ${this.error}`);
    }
  }

  private schedulePoll(delayMs: number) {
    if (!this.running) {
      return;
    }
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
    }
    this.pollTimer = setTimeout(() => {
      void this.pollPool();
    }, delayMs);
  }

  private async pollPool(): Promise<void> {
    if (!this.running || !this.endpoint) {
      return;
    }
    try {
      const [workPayload, poolPayload] = await Promise.all([
        this.rpcCall('hegemon_poolWork', [this.authToken ? { auth_token: this.authToken } : {}]),
        this.rpcCall('hegemon_poolStatus', [this.authToken ? { auth_token: this.authToken } : {}]).catch(() => null)
      ]);
      this.pool = mapPoolStatus(poolPayload as PoolStatusWire | null);

      const work = workPayload as PoolWorkWire | null;
      if (!work?.available || work.height === null || !work.pre_hash || !work.parent_hash) {
        this.currentHeight = null;
        this.currentTemplateKey = null;
        this.broadcast({ type: 'clearWork' });
        if (work?.reason) {
          this.appendLog(`Pool idle: ${work.reason}`);
        }
      } else {
        const networkDifficulty = Number(work.network_difficulty ?? 0);
        const shareDifficulty = Number(work.share_difficulty ?? networkDifficulty);
        const templateKey = `${work.height}:${work.pre_hash}:${work.parent_hash}:${shareDifficulty}`;
        this.currentHeight = Number(work.height);
        if (templateKey !== this.currentTemplateKey) {
          this.currentTemplateKey = templateKey;
          this.broadcast({
            type: 'setWork',
            work: {
              height: Number(work.height),
              preHash: String(work.pre_hash),
              parentHash: String(work.parent_hash),
              networkDifficulty,
              shareDifficulty
            }
          });
          this.appendLog(
            `Received pool work height=${work.height} share_bits=0x${shareDifficulty.toString(16)} network_bits=0x${networkDifficulty.toString(16)}`
          );
        }
      }
      this.error = null;
      this.schedulePoll(1500);
    } catch (error) {
      this.error = error instanceof Error ? error.message : String(error);
      this.appendLog(`Pool polling failed: ${this.error}`);
      this.broadcast({ type: 'clearWork' });
      this.schedulePoll(3000);
    }
  }

  private broadcast(command: WorkerCommand) {
    for (const worker of this.workers) {
      worker.postMessage(command);
    }
  }

  private async rpcCall(method: string, params: unknown[] = []) {
    const body: RpcRequest = {
      jsonrpc: '2.0',
      id: ++this.requestId,
      method,
      params
    };
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), RPC_TIMEOUT_MS);
    let response: Response;
    try {
      response = await fetch(this.endpoint!, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal
      });
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`RPC ${method} timed out after ${RPC_TIMEOUT_MS}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      throw new Error(`RPC ${method} failed with ${response.status}`);
    }
    const payload = await response.json();
    if (payload.error) {
      throw new Error(payload.error.message || `RPC ${method} error`);
    }
    return payload.result;
  }

  private appendLog(line: string) {
    const stamped = `${new Date().toISOString()} ${line}`;
    this.logs.push(stamped);
    if (this.logs.length > 200) {
      this.logs = this.logs.slice(-200);
    }
    this.emit('logs', this.getLogs());
  }
}
