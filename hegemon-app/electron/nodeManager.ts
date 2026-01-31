import { app } from 'electron';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, isAbsolute, join, resolve } from 'node:path';
import type { NodeStartOptions, NodeSummary, NodeSummaryRequest } from '../src/types';
import { resolveBinaryPath } from './binPaths';

const DEFAULT_RPC_PORT = 9944;

type RpcRequest = {
  jsonrpc: '2.0';
  id: number;
  method: string;
  params?: unknown[];
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

    const nodePath = resolveBinaryPath('hegemon-node');
    const args: string[] = [];
    const chainSpecPath = resolveChainSpecPath(options.chainSpecPath);
    const basePath = expandHomePath(options.basePath);

    if (chainSpecPath) {
      args.push('--chain', chainSpecPath);
    }
    if (options.dev) {
      args.push('--dev');
    }

    if (options.tmp) {
      args.push('--tmp');
    }

    if (basePath) {
      args.push('--base-path', basePath);
    }

    if (options.rpcPort) {
      args.push('--rpc-port', String(options.rpcPort));
      this.rpcPort = options.rpcPort;
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

    if (options.listenAddr) {
      args.push('--listen-addr', options.listenAddr);
    } else if (options.p2pPort) {
      args.push('--port', String(options.p2pPort));
    }

    if (options.rpcExternal) {
      args.push('--rpc-external');
    }

    const rpcMethods = options.rpcMethods ?? (options.rpcExternal ? 'safe' : undefined);
    if (rpcMethods) {
      args.push('--rpc-methods', rpcMethods);
    }

    if (options.nodeName) {
      args.push('--name', options.nodeName);
    }

    const mineFlag = options.mineOnStart ? '1' : '0';
    const env = {
      ...process.env,
      HEGEMON_MINER_ADDRESS: options.minerAddress ?? process.env.HEGEMON_MINER_ADDRESS,
      HEGEMON_SEEDS: options.seeds ?? process.env.HEGEMON_SEEDS,
      HEGEMON_CIPHERTEXT_DA_RETENTION_BLOCKS:
        options.ciphertextDaRetentionBlocks !== undefined
          ? String(options.ciphertextDaRetentionBlocks)
          : process.env.HEGEMON_CIPHERTEXT_DA_RETENTION_BLOCKS,
      HEGEMON_PROOF_DA_RETENTION_BLOCKS:
        options.proofDaRetentionBlocks !== undefined
          ? String(options.proofDaRetentionBlocks)
          : process.env.HEGEMON_PROOF_DA_RETENTION_BLOCKS,
      HEGEMON_DA_STORE_CAPACITY:
        options.daStoreCapacity !== undefined
          ? String(options.daStoreCapacity)
          : process.env.HEGEMON_DA_STORE_CAPACITY,
      HEGEMON_MINE: mineFlag,
      HEGEMON_MINE_THREADS: options.mineThreads
        ? String(options.mineThreads)
        : process.env.HEGEMON_MINE_THREADS
    };

    this.process = spawn(nodePath, args, { env });
    this.managedConnectionId = options.connectionId ?? null;

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
    if (enabled) {
      await this.rpcCall('hegemon_startMining', [threads ? { threads } : {}], httpUrl);
    } else {
      await this.rpcCall('hegemon_stopMining', [], httpUrl);
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
