import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { resolve } from 'node:path';
import type { NodeStartOptions, NodeSummary } from '../src/types';

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

  getLogs(): string[] {
    return [...this.logs];
  }

  async startNode(options: NodeStartOptions): Promise<void> {
    if (this.process) {
      return;
    }

    const nodePath = resolve(process.cwd(), 'target/release/hegemon-node');
    const args: string[] = [];

    if (options.chainSpecPath) {
      args.push('--chain', options.chainSpecPath);
    } else if (options.dev) {
      args.push('--dev');
    }

    if (options.tmp) {
      args.push('--tmp');
    }

    if (options.basePath) {
      args.push('--base-path', options.basePath);
    }

    if (options.rpcPort) {
      args.push('--rpc-port', String(options.rpcPort));
      this.rpcPort = options.rpcPort;
    } else {
      this.rpcPort = DEFAULT_RPC_PORT;
    }

    if (options.p2pPort) {
      args.push('--port', String(options.p2pPort));
    }

    const env = {
      ...process.env,
      HEGEMON_MINER_ADDRESS: options.minerAddress ?? process.env.HEGEMON_MINER_ADDRESS,
      HEGEMON_SEEDS: options.seeds ?? process.env.HEGEMON_SEEDS
    };

    this.process = spawn(nodePath, args, { env });

    this.process.stdout.on('data', (data) => this.appendLogs(data.toString()));
    this.process.stderr.on('data', (data) => this.appendLogs(data.toString()));
    this.process.on('exit', (code) => {
      this.appendLogs(`Node exited with code ${code ?? 'unknown'}`);
      this.process = null;
    });
  }

  async stopNode(): Promise<void> {
    if (!this.process) {
      return;
    }
    this.process.kill('SIGINT');
    this.process = null;
  }

  async getSummary(): Promise<NodeSummary> {
    const consensus = await this.rpcCall('hegemon_consensusStatus', []);
    const mining = await this.rpcCall('hegemon_miningStatus', []);

    return {
      peers: Number(consensus.peers ?? 0),
      isSyncing: Boolean(consensus.syncing),
      bestBlock: consensus.best_hash ?? null,
      bestNumber: consensus.height ? Number(consensus.height) : null,
      mining: Boolean(mining.is_mining),
      miningThreads: mining.threads ? Number(mining.threads) : null
    };
  }

  async setMiningEnabled(enabled: boolean, threads?: number): Promise<void> {
    if (enabled) {
      await this.rpcCall('hegemon_startMining', [threads ? { threads } : {}]);
    } else {
      await this.rpcCall('hegemon_stopMining', []);
    }
  }

  private async rpcCall(method: string, params: unknown[] = []): Promise<any> {
    const body: RpcRequest = {
      jsonrpc: '2.0',
      id: ++this.requestId,
      method,
      params
    };

    const response = await fetch(`http://127.0.0.1:${this.rpcPort}`, {
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
