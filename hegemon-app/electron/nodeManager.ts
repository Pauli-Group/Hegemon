import { app } from 'electron';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, isAbsolute, join, resolve } from 'node:path';
import type { NodeStartOptions, NodeSummary, NodeSummaryRequest } from '../src/types';
import { resolveBinaryPath } from './binPaths';

const DEFAULT_RPC_PORT = 9944;
const CANONICAL_TESTNET_P2P_PORT = 30333;
const LEGACY_TESTNET_P2P_PORT = 31333;
const APPROVED_SEEDS = 'hegemon.pauli.group:30333';
const LEGACY_SEED_ALIASES: Record<string, string> = {
  'hegemon.pauli.group:31333': 'hegemon.pauli.group:30333',
  '158.69.222.121:31333': 'hegemon.pauli.group:30333',
  '158.69.222.121:30333': 'hegemon.pauli.group:30333'
};
const DEFAULT_LOCAL_BASE_PATH = '~/.hegemon-node';
const DEFAULT_TESTNET_BASE_PATH = '~/.hegemon-node-testnet';
const DESKTOP_LIVENESS_ENV_DEFAULTS: Record<string, string> = {
  // Desktop operators prioritize confirmation liveness over throughput.
  HEGEMON_BATCH_TARGET_TXS: '1',
  HEGEMON_BATCH_INCREMENTAL_UPSIZE: '1',
  HEGEMON_PROVER_LIVENESS_LANE: '1',
  // Keep proving jobs alive on commodity hardware instead of timing out.
  HEGEMON_BATCH_JOB_TIMEOUT_MS: '900000',
  HEGEMON_PENDING_PROVEN_BATCH_WAIT_MS: '900000',
  HEGEMON_PROVER_WORK_PACKAGE_TTL_MS: '900000'
};

type RpcRequest = {
  jsonrpc: '2.0';
  id: number;
  method: string;
  params?: unknown[];
};

const normalizeSeedList = (value?: string | null) => {
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const entry of (value ?? '').split(',')) {
    const candidate = LEGACY_SEED_ALIASES[entry.trim().toLowerCase()] ?? entry.trim().toLowerCase();
    if (!candidate || seen.has(candidate)) {
      continue;
    }
    seen.add(candidate);
    normalized.push(candidate);
  }
  return normalized.join(',');
};

const normalizeListenAddr = (listenAddr?: string) => {
  if (!listenAddr) {
    return undefined;
  }
  if (listenAddr.includes(`/tcp/${LEGACY_TESTNET_P2P_PORT}`)) {
    return listenAddr.replace(
      `/tcp/${LEGACY_TESTNET_P2P_PORT}`,
      `/tcp/${CANONICAL_TESTNET_P2P_PORT}`
    );
  }
  return listenAddr;
};

const normalizeManagedStartOptions = (options: NodeStartOptions): NodeStartOptions => {
  const isDefaultLocal =
    options.dev &&
    (!options.basePath || options.basePath === DEFAULT_LOCAL_BASE_PATH);
  const isDefaultTestnet =
    !options.dev &&
    (!options.basePath || options.basePath === DEFAULT_TESTNET_BASE_PATH);

  if (!isDefaultLocal && !isDefaultTestnet) {
    return options;
  }

  const next: NodeStartOptions = { ...options };

  if (normalizeSeedList(next.seeds) !== APPROVED_SEEDS) {
    next.seeds = APPROVED_SEEDS;
  }

  if (!next.listenAddr && (!next.p2pPort || next.p2pPort === LEGACY_TESTNET_P2P_PORT)) {
    next.p2pPort = CANONICAL_TESTNET_P2P_PORT;
  } else if (next.p2pPort === LEGACY_TESTNET_P2P_PORT) {
    next.p2pPort = CANONICAL_TESTNET_P2P_PORT;
  }

  const normalizedListenAddr = normalizeListenAddr(next.listenAddr);
  if (normalizedListenAddr && normalizedListenAddr !== next.listenAddr) {
    next.listenAddr = normalizedListenAddr;
  }

  return next;
};

export class NodeManager extends EventEmitter {
  private process: ChildProcessWithoutNullStreams | null = null;
  private rpcPort = DEFAULT_RPC_PORT;
  private logs: string[] = [];
  private requestId = 0;
  private managedConnectionId: string | null = null;
  private stopping = false;

  getLogs(): string[] {
    return [...this.logs];
  }

  getManagedStatus(): { managed: boolean; connectionId: string | null; pid: number | null; rpcPort: number | null } {
    return {
      managed: Boolean(this.process),
      connectionId: this.managedConnectionId,
      pid: this.process?.pid ?? null,
      rpcPort: this.rpcPort ?? null
    };
  }

  async startNode(options: NodeStartOptions): Promise<void> {
    if (this.process) {
      return;
    }

    const normalizedOptions = normalizeManagedStartOptions(options);
    const nodePath = resolveBinaryPath('hegemon-node');
    const args: string[] = [];
    const chainSpecPath = resolveChainSpecPath(normalizedOptions.chainSpecPath);
    const basePath = expandHomePath(normalizedOptions.basePath);

    if (chainSpecPath) {
      args.push('--chain', chainSpecPath);
    }
    if (normalizedOptions.dev) {
      args.push('--dev');
    }

    if (normalizedOptions.tmp) {
      args.push('--tmp');
    }

    if (basePath) {
      args.push('--base-path', basePath);
    }

    if (normalizedOptions.rpcPort) {
      args.push('--rpc-port', String(normalizedOptions.rpcPort));
      this.rpcPort = normalizedOptions.rpcPort;
    } else {
      this.rpcPort = DEFAULT_RPC_PORT;
    }

    // Guard rail: if something is already answering JSON-RPC on this port, starting a node will
    // either fail to bind (and the UI will misleadingly keep showing the existing node), or worse,
    // connect to a forwarded/remote node that the app cannot stop.
    const preflightUrl = `http://127.0.0.1:${this.rpcPort}`;
    const alreadyServing = await this.ping(preflightUrl);
    if (alreadyServing) {
      const version = await this.safeRpcCall('system_version', [], preflightUrl);
      const genesisHash = await this.safeRpcCall('chain_getBlockHash', [0], preflightUrl);
      const identity = [
        version ? `version=${String(version)}` : null,
        genesisHash ? `genesis=${String(genesisHash)}` : null
      ]
        .filter(Boolean)
        .join(' ');
      this.appendLogs(
        `Refusing to start node: RPC port ${this.rpcPort} is already serving JSON-RPC${identity ? ` (${identity})` : ''}`
      );
      throw new Error(
        `RPC port ${this.rpcPort} is already in use by a node. Pick another RPC port (e.g. 9955) or stop the existing process.`
      );
    }

    if (normalizedOptions.listenAddr) {
      args.push('--listen-addr', normalizedOptions.listenAddr);
    } else if (normalizedOptions.p2pPort) {
      args.push('--port', String(normalizedOptions.p2pPort));
    }

    if (normalizedOptions.rpcExternal) {
      args.push('--rpc-external');
    }

    const rpcMethods =
      normalizedOptions.rpcMethods ?? (normalizedOptions.rpcExternal ? 'safe' : undefined);
    if (rpcMethods) {
      args.push('--rpc-methods', rpcMethods);
    }

    if (normalizedOptions.rpcCorsAll) {
      args.push('--rpc-cors=all');
    }

    if (normalizedOptions.nodeName) {
      args.push('--name', normalizedOptions.nodeName);
    }

    const mineFlag = normalizedOptions.mineOnStart ? '1' : '0';
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      HEGEMON_MINER_ADDRESS: normalizedOptions.minerAddress ?? process.env.HEGEMON_MINER_ADDRESS,
      HEGEMON_SEEDS: normalizedOptions.seeds ?? process.env.HEGEMON_SEEDS,
      HEGEMON_MAX_PEERS:
        normalizedOptions.maxPeers !== undefined
          ? String(normalizedOptions.maxPeers)
          : process.env.HEGEMON_MAX_PEERS,
      HEGEMON_CIPHERTEXT_DA_RETENTION_BLOCKS:
        normalizedOptions.ciphertextDaRetentionBlocks !== undefined
          ? String(normalizedOptions.ciphertextDaRetentionBlocks)
          : process.env.HEGEMON_CIPHERTEXT_DA_RETENTION_BLOCKS,
      HEGEMON_PROOF_DA_RETENTION_BLOCKS:
        normalizedOptions.proofDaRetentionBlocks !== undefined
          ? String(normalizedOptions.proofDaRetentionBlocks)
          : process.env.HEGEMON_PROOF_DA_RETENTION_BLOCKS,
      HEGEMON_DA_STORE_CAPACITY:
        normalizedOptions.daStoreCapacity !== undefined
          ? String(normalizedOptions.daStoreCapacity)
          : process.env.HEGEMON_DA_STORE_CAPACITY,
      HEGEMON_MINE: mineFlag,
      HEGEMON_MINE_THREADS: normalizedOptions.mineThreads
        ? String(normalizedOptions.mineThreads)
        : process.env.HEGEMON_MINE_THREADS
    };
    for (const [key, value] of Object.entries(DESKTOP_LIVENESS_ENV_DEFAULTS)) {
      const current = env[key];
      if (current === undefined || current.trim() === '') {
        env[key] = value;
      }
    }

    this.process = spawn(nodePath, args, { env });
    this.managedConnectionId = normalizedOptions.connectionId ?? null;

    this.process.stdout.on('data', (data) => this.appendLogs(data.toString()));
    this.process.stderr.on('data', (data) => this.appendLogs(data.toString()));
    this.process.on('error', (error) => {
      const message =
        (error as NodeJS.ErrnoException).code === 'ENOENT'
          ? `Node binary not found at ${nodePath}`
          : `Node failed to start: ${error.message}`;
      this.appendLogs(message);
      this.process = null;
      this.managedConnectionId = null;
    });
    this.process.on('exit', (code) => {
      this.appendLogs(`Node exited with code ${code ?? 'unknown'}`);
      this.process = null;
      this.managedConnectionId = null;
    });
  }

  async stopNode(): Promise<void> {
    const proc = this.process;
    if (!proc) {
      return;
    }
    if (this.stopping) {
      return;
    }
    this.stopping = true;

    const waitForExit = async (timeoutMs: number) => {
      if (proc.exitCode !== null) {
        return true;
      }
      return await new Promise<boolean>((resolve) => {
        const timeout = setTimeout(() => resolve(false), timeoutMs);
        proc.once('exit', () => {
          clearTimeout(timeout);
          resolve(true);
        });
      });
    };

    const tryKill = async (signal: NodeJS.Signals, timeoutMs: number) => {
      try {
        proc.kill(signal);
      } catch (error) {
        this.appendLogs(`Failed to send ${signal} to node: ${(error as Error).message}`);
      }
      return await waitForExit(timeoutMs);
    };

    // Best-effort graceful shutdown, then escalate.
    const exited =
      (await tryKill('SIGINT', 5_000)) ||
      (await tryKill('SIGTERM', 2_000)) ||
      (await tryKill('SIGKILL', 2_000));

    if (!exited) {
      this.appendLogs('Node did not exit after SIGKILL; leaving process running.');
    }
    this.process = null;
    this.managedConnectionId = null;
    this.stopping = false;
  }

  async getSummary(request: NodeSummaryRequest): Promise<NodeSummary> {
    const isLocal = request.isLocal;
    const reachable = await this.ping(request.httpUrl);

    if (!reachable) {
      return {
        connectionId: request.connectionId,
        label: request.label,
        reachable: false,
        isLocal,
        nodeVersion: null,
        peers: null,
        isSyncing: null,
        bestBlock: null,
        bestNumber: null,
        genesisHash: null,
        mining: null,
        miningThreads: null,
        hashRate: null,
        blocksFound: null,
        difficulty: null,
        blockHeight: null,
        supplyDigest: null,
        storage: null,
        telemetry: null,
        config: null,
        updatedAt: new Date().toISOString(),
        error: 'RPC unreachable'
      };
    }

    const consensus = await this.safeRpcCall('hegemon_consensusStatus', [], request.httpUrl);
    const mining = await this.safeRpcCall('hegemon_miningStatus', [], request.httpUrl);
    const health = await this.safeRpcCall('system_health', [], request.httpUrl);
    const nodeVersion = await this.safeRpcCall('system_version', [], request.httpUrl);
    const storage = await this.safeRpcCall('hegemon_storageFootprint', [], request.httpUrl);
    const telemetry = await this.safeRpcCall('hegemon_telemetry', [], request.httpUrl);
    const nodeConfig = await this.safeRpcCall('hegemon_nodeConfig', [], request.httpUrl);
    const genesisHash = await this.safeRpcCall('chain_getBlockHash', [0], request.httpUrl);

    return {
      connectionId: request.connectionId,
      label: request.label,
      reachable: true,
      isLocal,
      nodeVersion: nodeVersion ? String(nodeVersion) : null,
      peers: Math.max(Number(consensus?.peers ?? 0), Number(health?.peers ?? 0)),
      isSyncing: Boolean(consensus?.syncing ?? health?.isSyncing ?? false),
      bestBlock: consensus?.best_hash ?? null,
      bestNumber: consensus?.height ?? null,
      genesisHash: genesisHash ?? null,
      mining: mining ? Boolean(mining.is_mining) : null,
      miningThreads: mining?.threads ?? null,
      hashRate: mining?.hash_rate ?? null,
      blocksFound: mining?.blocks_found ?? null,
      difficulty: mining?.difficulty ?? null,
      blockHeight: mining?.block_height ?? null,
      supplyDigest: consensus?.supply_digest ? String(consensus.supply_digest) : null,
      storage: storage
        ? {
            totalBytes: Number(storage.total_bytes ?? 0),
            blocksBytes: Number(storage.blocks_bytes ?? 0),
            stateBytes: Number(storage.state_bytes ?? 0),
            transactionsBytes: Number(storage.transactions_bytes ?? 0),
            nullifiersBytes: Number(storage.nullifiers_bytes ?? 0)
          }
        : null,
      telemetry: telemetry
        ? {
            uptimeSecs: Number(telemetry.uptime_secs ?? 0),
            txCount: Number(telemetry.tx_count ?? 0),
            blocksImported: Number(telemetry.blocks_imported ?? 0),
            blocksMined: Number(telemetry.blocks_mined ?? 0),
            memoryBytes: Number(telemetry.memory_bytes ?? 0),
            networkRxBytes: Number(telemetry.network_rx_bytes ?? 0),
            networkTxBytes: Number(telemetry.network_tx_bytes ?? 0)
          }
        : null,
      config: nodeConfig
        ? {
            nodeName: String(nodeConfig.nodeName ?? ''),
            chainSpecId: String(nodeConfig.chainSpecId ?? ''),
            chainSpecName: String(nodeConfig.chainSpecName ?? ''),
            chainType: String(nodeConfig.chainType ?? ''),
            basePath: String(nodeConfig.basePath ?? ''),
            p2pListenAddr: String(nodeConfig.p2pListenAddr ?? ''),
            rpcListenAddr: String(nodeConfig.rpcListenAddr ?? ''),
            rpcMethods: String(nodeConfig.rpcMethods ?? ''),
            rpcExternal: Boolean(nodeConfig.rpcExternal ?? false),
            bootstrapNodes: Array.isArray(nodeConfig.bootstrapNodes) ? nodeConfig.bootstrapNodes : [],
            pqVerbose: Boolean(nodeConfig.pqVerbose ?? false),
            maxPeers: Number(nodeConfig.maxPeers ?? 0)
          }
        : null,
      updatedAt: new Date().toISOString()
    };
  }

  async setMiningEnabled(enabled: boolean, threads: number | undefined, httpUrl?: string): Promise<void> {
    const authToken = process.env.HEGEMON_MINING_RPC_TOKEN?.trim();
    if (enabled) {
      const params: Record<string, unknown> = threads ? { threads } : {};
      if (authToken) {
        params.auth_token = authToken;
      }
      await this.rpcCall('hegemon_startMining', [params], httpUrl);
    } else {
      const params = authToken ? [{ auth_token: authToken }] : [];
      await this.rpcCall('hegemon_stopMining', params, httpUrl);
    }
  }

  private async safeRpcCall(method: string, params: unknown[], httpUrl: string): Promise<any | null> {
    try {
      return await this.rpcCall(method, params, httpUrl);
    } catch {
      return null;
    }
  }

  private async ping(httpUrl: string): Promise<boolean> {
    try {
      await this.rpcCall('system_health', [], httpUrl);
      return true;
    } catch {
      return false;
    }
  }

  private async rpcCall(method: string, params: unknown[] = [], httpUrl?: string): Promise<any> {
    const body: RpcRequest = {
      jsonrpc: '2.0',
      id: ++this.requestId,
      method,
      params
    };

    const endpoint = httpUrl ?? `http://127.0.0.1:${this.rpcPort}`;
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      throw new Error(`RPC ${method} failed with ${response.status}`);
    }

    const payload = await response.json();
    if (payload.error) {
      throw new Error(payload.error.message || `RPC ${method} error`);
    }

    return payload.result;
  }

  private appendLogs(chunk: string) {
    const lines = chunk.split('\n').filter(Boolean);
    for (const line of lines) {
      this.logs.push(line);
    }
    if (this.logs.length > 200) {
      this.logs = this.logs.slice(-200);
    }
    this.emit('logs', this.getLogs());
  }
}

const expandHomePath = (value?: string) => {
  if (!value) {
    return undefined;
  }
  if (value === '~') {
    return homedir();
  }
  if (value.startsWith('~/')) {
    return join(homedir(), value.slice(2));
  }
  return value;
};

const resolveChainSpecPath = (value?: string) => {
  const expanded = expandHomePath(value);
  if (!expanded) {
    return undefined;
  }
  if (isAbsolute(expanded)) {
    return expanded;
  }

  const candidates = [
    resolve(process.cwd(), expanded),
    resolve(process.cwd(), '..', expanded),
    resolve(process.cwd(), '..', '..', expanded),
    resolve(app.getAppPath(), expanded),
    resolve(app.getAppPath(), '..', expanded),
    resolve(app.getAppPath(), '..', '..', expanded),
    resolve(process.resourcesPath, expanded)
  ];

  const leafName = basename(expanded);
  candidates.push(resolve(process.resourcesPath, 'config', leafName), resolve(process.resourcesPath, leafName));

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  return expanded;
};
