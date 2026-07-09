import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type {
  CanonicalCheckpointStatus,
  NodePeerSnapshot,
  NodeStartOptions,
  NodeSummary,
  NodeSummaryRequest
} from '../src/types';
import { resolveBinaryPath } from './binPaths';
import { applyEnvDefaults, copyParentEnv, createBaseChildEnv, setEnvValue } from './childProcessEnv';

const DEFAULT_RPC_PORT = 9955;
const CANONICAL_TESTNET_P2P_PORT = 30333;
const LEGACY_TESTNET_P2P_PORT = 31333;
const APPROVED_SEED_ENTRIES = ['hegemon.pauli.group:30333', 'devnet.hegemonprotocol.com:30333'] as const;
const APPROVED_SEEDS = APPROVED_SEED_ENTRIES.join(',');
const PUBLIC_TESTNET_NAME = 'Hegemon';
const CANONICAL_TESTNET_CHECKPOINTS = [
  {
    height: 2048,
    hash: '0x00000000e930672262cba74a26750c0540a1e2aa54e7ad27ffc1e6fbd055bc4e'
  },
  {
    height: 4096,
    hash: '0x0000001891cd8a0b45add76b6b0ebe6bc50f6f1dc60879f9f000a71cf22ad5de'
  }
] as const;
const LEGACY_SEED_ALIASES: Record<string, string> = {
  'hegemon.pauli.group:31333': APPROVED_SEEDS,
  'hegemon.pauli.group:30333': APPROVED_SEEDS,
  '158.69.222.121:31333': APPROVED_SEEDS,
  '158.69.222.121:30333': APPROVED_SEEDS,
  'devnet.hegemonprotocol.com:30333': APPROVED_SEEDS,
  '51.222.86.107:30333': APPROVED_SEEDS
};
const DEFAULT_LOCAL_BASE_PATH = '~/.hegemon-node';
const DEFAULT_DEV_010_BASE_PATH = '~/.hegemon-node-native-010-dev';
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
const NODE_ENV_PASSTHROUGH = [
  'HEGEMON_BOOTSTRAP_AUTHORING',
  'HEGEMON_PQ_VERBOSE',
  'HEGEMON_PQ_STRICT_COMPATIBILITY'
] as const;

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
    const expanded = LEGACY_SEED_ALIASES[entry.trim().toLowerCase()] ?? entry.trim().toLowerCase();
    for (const candidate of expanded.split(',')) {
      if (!candidate || seen.has(candidate)) {
        continue;
      }
      seen.add(candidate);
      normalized.push(candidate);
    }
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
    (!options.basePath ||
      options.basePath === DEFAULT_LOCAL_BASE_PATH ||
      options.basePath === DEFAULT_DEV_010_BASE_PATH);
  const isDefaultTestnet =
    !options.dev &&
    (!options.basePath || options.basePath === DEFAULT_TESTNET_BASE_PATH);

  const next: NodeStartOptions = { ...options };
  const currentSeeds = next.seeds?.trim();
  const normalizedSeeds = normalizeSeedList(next.seeds);

  if (currentSeeds && normalizedSeeds !== currentSeeds.toLowerCase()) {
    next.seeds = normalizedSeeds;
  }

  if ((isDefaultLocal || isDefaultTestnet) && normalizedSeeds !== APPROVED_SEEDS) {
    next.seeds = APPROVED_SEEDS;
  }

  if (isDefaultLocal || isDefaultTestnet) {
    if (!next.listenAddr && (!next.p2pPort || next.p2pPort === LEGACY_TESTNET_P2P_PORT)) {
      next.p2pPort = CANONICAL_TESTNET_P2P_PORT;
    } else if (next.p2pPort === LEGACY_TESTNET_P2P_PORT) {
      next.p2pPort = CANONICAL_TESTNET_P2P_PORT;
    }
  }

  const normalizedListenAddr = normalizeListenAddr(next.listenAddr);
  if (normalizedListenAddr && normalizedListenAddr !== next.listenAddr) {
    next.listenAddr = normalizedListenAddr;
  }

  return next;
};

const normalizePeerList = (value: unknown): NodeSummary['peerList'] => {
  if (!Array.isArray(value)) {
    return null;
  }
  return value
    .map((entry): NodePeerSnapshot | null => {
      if (!entry || typeof entry !== 'object') {
        return null;
      }
      const row = entry as Record<string, unknown>;
      const peerId = typeof row.peer_id === 'string' ? row.peer_id : typeof row.peerId === 'string' ? row.peerId : '';
      const addr = typeof row.addr === 'string' ? row.addr : typeof row.endpoint === 'string' ? row.endpoint : '';
      if (!peerId || !addr) {
        return null;
      }
      const protocols = Array.isArray(row.protocols)
        ? row.protocols
            .map((protocol) => Number(protocol))
            .filter((protocol) => Number.isFinite(protocol))
        : undefined;
      return {
        peerId,
        addr,
        connected: row.connected === undefined ? true : Boolean(row.connected),
        protocols
      };
    })
    .filter((entry): entry is NodePeerSnapshot => entry !== null);
};

const finiteNumberOrNull = (value: unknown): number | null => {
  if (value === null || value === undefined || value === '') {
    return null;
  }
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
};

export class NodeManager extends EventEmitter {
  private process: ChildProcessWithoutNullStreams | null = null;
  private rpcPort = DEFAULT_RPC_PORT;
  private logs: string[] = [];
  private requestId = 0;
  private managedConnectionId: string | null = null;
  private managedMinerAddress: string | null = null;
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

  private managedRpcEndpoint(): string {
    return `http://127.0.0.1:${this.rpcPort}`;
  }

  async startNode(options: NodeStartOptions): Promise<void> {
    if (this.process) {
      return;
    }

    const normalizedOptions = normalizeManagedStartOptions(options);
    const nodePath = resolveBinaryPath('hegemon-node');
    const args: string[] = [];
    const basePath = expandHomePath(normalizedOptions.basePath);

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
    const preflightUrl = this.managedRpcEndpoint();
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

    if (normalizedOptions.rpcExternal && normalizedOptions.rpcMethods === 'unsafe') {
      throw new Error('Unsafe RPC methods are only allowed on the managed loopback control plane.');
    }
    const rpcMethods = normalizedOptions.rpcExternal ? 'safe' : 'unsafe';
    args.push('--rpc-methods', rpcMethods);

    if (normalizedOptions.rpcCorsAll) {
      args.push('--rpc-cors=all');
    }

    if (normalizedOptions.nodeName) {
      args.push('--name', normalizedOptions.nodeName);
    }

    const mineFlag = normalizedOptions.mineOnStart ? '1' : '0';
    const env = createBaseChildEnv();
    copyParentEnv(env, NODE_ENV_PASSTHROUGH);
    const effectiveMinerAddress = normalizedOptions.minerAddress ?? null;
    setEnvValue(env, 'HEGEMON_MINER_ADDRESS', effectiveMinerAddress);
    setEnvValue(env, 'HEGEMON_SEEDS', normalizedOptions.seeds ?? process.env.HEGEMON_SEEDS);
    setEnvValue(
      env,
      'HEGEMON_MAX_PEERS',
      normalizedOptions.maxPeers !== undefined ? normalizedOptions.maxPeers : process.env.HEGEMON_MAX_PEERS
    );
    setEnvValue(
      env,
      'HEGEMON_CIPHERTEXT_DA_RETENTION_BLOCKS',
      normalizedOptions.ciphertextDaRetentionBlocks !== undefined
        ? normalizedOptions.ciphertextDaRetentionBlocks
        : process.env.HEGEMON_CIPHERTEXT_DA_RETENTION_BLOCKS
    );
    setEnvValue(
      env,
      'HEGEMON_PROOF_DA_RETENTION_BLOCKS',
      normalizedOptions.proofDaRetentionBlocks !== undefined
        ? normalizedOptions.proofDaRetentionBlocks
        : process.env.HEGEMON_PROOF_DA_RETENTION_BLOCKS
    );
    setEnvValue(
      env,
      'HEGEMON_DA_STORE_CAPACITY',
      normalizedOptions.daStoreCapacity !== undefined
        ? normalizedOptions.daStoreCapacity
        : process.env.HEGEMON_DA_STORE_CAPACITY
    );
    setEnvValue(env, 'HEGEMON_MINE', mineFlag);
    setEnvValue(
      env,
      'HEGEMON_MINE_THREADS',
      normalizedOptions.mineThreads ? normalizedOptions.mineThreads : process.env.HEGEMON_MINE_THREADS
    );
    applyEnvDefaults(env, DESKTOP_LIVENESS_ENV_DEFAULTS);

    this.process = spawn(nodePath, args, { env });
    this.managedConnectionId = normalizedOptions.connectionId ?? null;
    this.managedMinerAddress = effectiveMinerAddress;

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
      this.managedMinerAddress = null;
    });
    this.process.on('exit', (code) => {
      this.appendLogs(`Node exited with code ${code ?? 'unknown'}`);
      this.process = null;
      this.managedConnectionId = null;
      this.managedMinerAddress = null;
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
    let httpUrl: string;
    try {
      httpUrl = normalizeRendererRpcEndpoint(request.httpUrl);
    } catch (error) {
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
        minerAddress: null,
        miningThreads: null,
        miningSyncGateOpen: null,
        bootstrapAuthoring: null,
        hashRate: null,
        blocksFound: null,
        difficulty: null,
        nextDifficulty: null,
        blockHeight: null,
        syncTargetHeight: null,
        pendingExtrinsics: null,
        peerList: null,
        canonicalCheckpoint: null,
        supplyDigest: null,
        storage: null,
        telemetry: null,
        config: null,
        updatedAt: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'RPC endpoint rejected'
      };
    }
    const reachable = await this.ping(httpUrl);

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
        minerAddress: null,
        miningThreads: null,
        miningSyncGateOpen: null,
        bootstrapAuthoring: null,
        hashRate: null,
        blocksFound: null,
        difficulty: null,
        nextDifficulty: null,
        blockHeight: null,
        syncTargetHeight: null,
        pendingExtrinsics: null,
        peerList: null,
        canonicalCheckpoint: null,
        supplyDigest: null,
        storage: null,
        telemetry: null,
        config: null,
        updatedAt: new Date().toISOString(),
        error: 'RPC unreachable'
      };
    }

    const consensus = await this.safeRpcCall('hegemon_consensusStatus', [], httpUrl);
    const mining = await this.safeRpcCall('hegemon_miningStatus', [], httpUrl);
    const health = await this.safeRpcCall('system_health', [], httpUrl);
    const nodeVersion = await this.safeRpcCall('system_version', [], httpUrl);
    const storage = await this.safeRpcCall('hegemon_storageFootprint', [], httpUrl);
    const telemetry = await this.safeRpcCall('hegemon_telemetry', [], httpUrl);
    const nodeConfig = await this.safeRpcCall('hegemon_nodeConfig', [], httpUrl);
    const genesisHash = await this.safeRpcCall('chain_getBlockHash', [0], httpUrl);
    const pendingExtrinsics = await this.safeRpcCall('author_pendingExtrinsics', [], httpUrl);
    const peerList = await this.safeRpcCall('hegemon_peerList', [], httpUrl);
    const bestNumber = finiteNumberOrNull(consensus?.height);
    const canonicalCheckpoint = await this.readCanonicalCheckpoint(httpUrl, bestNumber);
    const consensusSyncTarget = finiteNumberOrNull(consensus?.sync_target_height ?? consensus?.syncTargetHeight);
    const miningSyncTarget = finiteNumberOrNull(mining?.sync_target_height ?? mining?.syncTargetHeight);
    const syncTargetHeight =
      miningSyncTarget !== null && miningSyncTarget > 0
        ? miningSyncTarget
        : consensusSyncTarget !== null && consensusSyncTarget > 0
          ? consensusSyncTarget
          : miningSyncTarget ?? consensusSyncTarget;
    const isSyncing = Boolean(consensus?.syncing ?? health?.isSyncing ?? false);
    const rawMiningSyncGateOpen = mining?.mining_sync_gate_open ?? mining?.miningSyncGateOpen;
    let miningSyncGateOpen =
      rawMiningSyncGateOpen === undefined ? null : Boolean(rawMiningSyncGateOpen);
    if (
      miningSyncGateOpen === false &&
      !isSyncing &&
      bestNumber !== null &&
      syncTargetHeight !== null &&
      syncTargetHeight > 0 &&
      bestNumber >= syncTargetHeight
    ) {
      miningSyncGateOpen = true;
    }

    return {
      connectionId: request.connectionId,
      label: request.label,
      reachable: true,
      isLocal,
      nodeVersion: nodeVersion ? String(nodeVersion) : null,
      peers: Math.max(Number(consensus?.peers ?? 0), Number(health?.peers ?? 0)),
      isSyncing,
      bestBlock: consensus?.best_hash ?? null,
      bestNumber,
      genesisHash: genesisHash ?? null,
      mining: mining ? Boolean(mining.is_mining) : null,
      minerAddress: this.managedConnectionId === request.connectionId ? this.managedMinerAddress : null,
      miningThreads: mining?.threads ?? null,
      miningSyncGateOpen,
      bootstrapAuthoring:
        mining?.bootstrap_authoring === undefined ? null : Boolean(mining.bootstrap_authoring),
      hashRate: mining?.hash_rate ?? null,
      blocksFound: mining?.blocks_found ?? null,
      difficulty: mining?.difficulty ?? null,
      nextDifficulty: mining?.next_difficulty ?? null,
      blockHeight: mining?.block_height ?? null,
      syncTargetHeight,
      pendingExtrinsics: Array.isArray(pendingExtrinsics) ? pendingExtrinsics.length : null,
      peerList: normalizePeerList(peerList),
      canonicalCheckpoint,
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

  private async readCanonicalCheckpoint(
    httpUrl: string,
    bestNumber: number | null
  ): Promise<CanonicalCheckpointStatus> {
    if (bestNumber === null) {
      return {
        network: PUBLIC_TESTNET_NAME,
        seed: APPROVED_SEEDS,
        status: 'unavailable',
        height: null,
        expectedHash: null,
        actualHash: null,
        detail: 'No local height is available yet.'
      };
    }

    const checkpoint = [...CANONICAL_TESTNET_CHECKPOINTS]
      .reverse()
      .find((candidate) => bestNumber >= candidate.height);
    if (!checkpoint) {
      return {
        network: PUBLIC_TESTNET_NAME,
        seed: APPROVED_SEEDS,
        status: 'pending',
        height: CANONICAL_TESTNET_CHECKPOINTS[0].height,
        expectedHash: CANONICAL_TESTNET_CHECKPOINTS[0].hash,
        actualHash: null,
        detail: `Waiting to reach checkpoint height ${CANONICAL_TESTNET_CHECKPOINTS[0].height}.`
      };
    }

    const actualHash = await this.safeRpcCall('chain_getBlockHash', [checkpoint.height], httpUrl);
    const actualHashString = typeof actualHash === 'string' ? actualHash.toLowerCase() : null;
    const expectedHashString = checkpoint.hash.toLowerCase();
    if (!actualHashString) {
      return {
        network: PUBLIC_TESTNET_NAME,
        seed: APPROVED_SEEDS,
        status: 'unavailable',
        height: checkpoint.height,
        expectedHash: checkpoint.hash,
        actualHash: null,
        detail: `Could not read block hash at checkpoint height ${checkpoint.height}.`
      };
    }

    if (actualHashString !== expectedHashString) {
      return {
        network: PUBLIC_TESTNET_NAME,
        seed: APPROVED_SEEDS,
        status: 'mismatch',
        height: checkpoint.height,
        expectedHash: checkpoint.hash,
        actualHash: String(actualHash),
        detail: `Local chain does not match the Hegemon testnet checkpoint at height ${checkpoint.height}.`
      };
    }

    return {
      network: PUBLIC_TESTNET_NAME,
      seed: APPROVED_SEEDS,
      status: 'verified',
      height: checkpoint.height,
      expectedHash: checkpoint.hash,
      actualHash: String(actualHash),
      detail: `Matched the Hegemon testnet checkpoint at height ${checkpoint.height}.`
    };
  }

  async setMiningEnabled(enabled: boolean, threads: number | undefined, httpUrl?: string): Promise<void> {
    const authToken = process.env.HEGEMON_MINING_RPC_TOKEN?.trim();
    const endpoint = this.resolveMiningRpcEndpoint(httpUrl, Boolean(authToken));
    if (enabled) {
      const params: Record<string, unknown> = threads ? { threads } : {};
      if (authToken) {
        params.auth_token = authToken;
      }
      await this.rpcCall('hegemon_startMining', [params], endpoint);
    } else {
      const params = authToken ? [{ auth_token: authToken }] : [];
      await this.rpcCall('hegemon_stopMining', params, endpoint);
    }
  }

  private resolveMiningRpcEndpoint(httpUrl: string | undefined, hasAuthToken: boolean): string | undefined {
    if (!hasAuthToken) {
      return httpUrl ? normalizeRendererRpcEndpoint(httpUrl) : undefined;
    }
    if (!this.process) {
      throw new Error('Mining RPC token can only be used with the managed local node.');
    }
    const trustedEndpoint = this.managedRpcEndpoint();
    if (httpUrl && normalizeRpcEndpoint(httpUrl) !== normalizeRpcEndpoint(trustedEndpoint)) {
      throw new Error('Refusing to send mining RPC token to a renderer-selected RPC URL.');
    }
    return trustedEndpoint;
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

const normalizeRpcEndpoint = (value: string) => {
  const parsed = new URL(value);
  const hostname = parsed.hostname === 'localhost' ? '127.0.0.1' : parsed.hostname;
  const port =
    parsed.port ||
    (parsed.protocol === 'https:' ? '443' : parsed.protocol === 'http:' ? '80' : '');
  return `${parsed.protocol}//${hostname}${port ? `:${port}` : ''}`;
};

const normalizeRendererRpcEndpoint = (value: string) => {
  const parsed = new URL(value);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('RPC endpoint must use HTTP or HTTPS.');
  }
  if (parsed.username || parsed.password || parsed.hash) {
    throw new Error('RPC endpoint must not include credentials or fragments.');
  }
  const rawHostname = parsed.hostname.toLowerCase().replace(/^\[/, '').replace(/\]$/, '');
  const hostname = rawHostname === 'localhost' ? '127.0.0.1' : rawHostname;
  if (hostname !== '127.0.0.1' && hostname !== '::1') {
    throw new Error('Desktop RPC endpoints must be loopback-only. Run a local Hegemon P2P relay node for remote network access.');
  }
  const port =
    parsed.port ||
    (parsed.protocol === 'https:' ? '443' : parsed.protocol === 'http:' ? '80' : '');
  return `${parsed.protocol}//${hostname === '::1' ? '[::1]' : hostname}${port ? `:${port}` : ''}`;
};
