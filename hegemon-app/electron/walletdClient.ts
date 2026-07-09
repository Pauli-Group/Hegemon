import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import type {
  WalletDisclosureCreateResult,
  WalletDisclosureRecord,
  WalletDisclosureVerifyResult,
  WalletSendPlanRequest,
  WalletSendPlanResult,
  WalletSendRequest,
  WalletSendResult,
  WalletStatus,
  WalletSyncResult
} from '../src/types';
import { resolveBinaryPath } from './binPaths';
import { applyEnvDefaults, copyParentEnv, createBaseChildEnv } from './childProcessEnv';
import {
  parseWalletdResponseLine,
  rejectLineDelimitedPassphrase,
  resolveWalletdRequestTimeoutMs,
  walletdExitError,
  walletdResponseError
} from './walletdProtocol';

type PendingRequest = {
  resolve: (value: any) => void;
  reject: (reason: Error) => void;
  timer: NodeJS.Timeout;
};

type WalletdMode = 'open' | 'create';

const WALLETD_ENV_DEFAULTS: Record<string, string> = {
  // Default to inline ciphertext/proof transport for cross-miner portability.
  // Operators can opt into sidecar transport explicitly.
  HEGEMON_WALLET_DA_SIDECAR: '0',
  HEGEMON_WALLET_PROOF_SIDECAR: '0',
  HEGEMON_WALLET_TRY_SIGNED_SUBMIT: '0'
};
const WALLETD_ENV_PASSTHROUGH = [
  'HEGEMON_WALLET_DA_SIDECAR',
  'HEGEMON_WALLET_PROOF_SIDECAR',
  'HEGEMON_WALLET_TRY_SIGNED_SUBMIT',
  'HEGEMON_WALLET_CONSOLIDATION_DA_SIDECAR',
  'HEGEMON_WALLET_CONSOLIDATION_PROOF_SIDECAR',
  'HEGEMON_WALLET_CONSOLIDATION_MAX_TXS_PER_BATCH',
  'HEGEMON_WALLET_CONSOLIDATION_MAX_BATCH_BYTES',
  'HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK',
  'HEGEMON_MAX_BLOCK_TXS',
  'HEGEMON_WALLET_MAX_NULLIFIERS',
  'HEGEMON_WALLET_RPC_CONNECT_TIMEOUT_SECS',
  'HEGEMON_WALLET_RPC_REQUEST_TIMEOUT_SECS',
  'HEGEMON_WALLET_RPC_RECONNECT_ATTEMPTS',
  'HEGEMON_WALLET_RPC_RECONNECT_DELAY_SECS',
  'WALLET_PENDING_TIMEOUT_SECS',
  'WALLET_CONSOLIDATION_PENDING_TIMEOUT_SECS'
] as const;

function walletdSpawnEnv(): NodeJS.ProcessEnv {
  const env = createBaseChildEnv();
  copyParentEnv(env, WALLETD_ENV_PASSTHROUGH);
  applyEnvDefaults(env, WALLETD_ENV_DEFAULTS);
  return env;
}

export class WalletdClient {
  private process: ChildProcessWithoutNullStreams | null = null;
  private pending = new Map<number, PendingRequest>();
  private requestId = 0;
  private storePath: string | null = null;
  private mode: WalletdMode | null = null;
  private stderrBuffer: string[] = [];

  async status(): Promise<WalletStatus> {
    return this.request('status.get', {});
  }

  async init(storePath: string, passphrase: string): Promise<WalletStatus> {
    return this.request('status.get', {}, { storePath, passphrase, mode: 'create' });
  }

  async restore(storePath: string, passphrase: string): Promise<WalletStatus> {
    return this.request('status.get', {}, { storePath, passphrase, mode: 'open' });
  }

  async sync(wsUrl: string, forceRescan: boolean): Promise<WalletSyncResult> {
    return this.request('sync.once', { ws_url: wsUrl, force_rescan: forceRescan });
  }

  async send(request: WalletSendRequest): Promise<WalletSendResult> {
    return this.request('tx.send', {
      ws_url: request.wsUrl,
      recipients: request.recipients,
      fee: request.fee,
      auto_consolidate: request.autoConsolidate
    });
  }

  async sendPlan(request: WalletSendPlanRequest): Promise<WalletSendPlanResult> {
    return this.request('tx.plan', { recipients: request.recipients, fee: request.fee });
  }

  async disclosureCreate(
    wsUrl: string,
    txId: string,
    output: number
  ): Promise<WalletDisclosureCreateResult> {
    return this.request('disclosure.create', { ws_url: wsUrl, tx_id: txId, output });
  }

  async disclosureVerify(
    wsUrl: string,
    packageJson: object
  ): Promise<WalletDisclosureVerifyResult> {
    return this.request('disclosure.verify', { ws_url: wsUrl, package: packageJson });
  }

  async disclosureList(): Promise<WalletDisclosureRecord[]> {
    return this.request('disclosure.list', {});
  }

  private async request(
    method: string,
    params: object,
    unlock:
      | {
          storePath: string;
          passphrase: string;
          mode: WalletdMode;
        }
      | undefined = undefined
  ): Promise<any> {
    if (unlock) {
      await this.ensureProcess(unlock.storePath, unlock.passphrase, unlock.mode);
    } else if (!this.process) {
      throw new Error('walletd process not running');
    }

    if (!this.process || !this.process.stdin.writable) {
      throw new Error('walletd stdin not available');
    }

    const id = ++this.requestId;
    const payload = JSON.stringify({ id, method, params });
    this.process.stdin.write(`${payload}\n`);

    const timeoutMs = resolveWalletdRequestTimeoutMs(
      process.env.HEGEMON_WALLETD_REQUEST_TIMEOUT_MS
    );
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const pending = this.pending.get(id);
        if (!pending) {
          return;
        }
        this.pending.delete(id);
        pending.reject(
          new Error(
            `walletd request '${method}' timed out after ${timeoutMs} ms; the walletd process may be wedged. Stop and reopen the wallet to recover.`
          )
        );
      }, timeoutMs);
      timer.unref?.();
      this.pending.set(id, { resolve, reject, timer });
    });
  }

  private async ensureProcess(storePath: string, passphrase: string, mode: WalletdMode): Promise<void> {
    rejectLineDelimitedPassphrase(passphrase);
    const resolvedPath = expandHomePath(storePath);
    if (this.process && this.storePath === resolvedPath && this.mode === mode) {
      return;
    }

    if (mode === 'open' && !existsSync(resolvedPath)) {
      throw new Error('Wallet store not found.');
    }
    if (mode === 'create' && existsSync(resolvedPath)) {
      throw new Error('Wallet store already exists.');
    }

    await this.stop();

    const walletdPath = resolveBinaryPath('walletd');
    const process = spawn(walletdPath, ['--store', resolvedPath, '--mode', mode], {
      env: walletdSpawnEnv()
    });
    this.process = process;
    this.storePath = resolvedPath;
    this.mode = mode;
    this.stderrBuffer = [];

    process.stdin.write(`${passphrase}\n`);

    const reader = createInterface({ input: process.stdout });
    reader.on('line', (line) => {
      if (this.process !== process) {
        return;
      }
      this.handleResponseLine(line);
    });

    process.on('error', (error) => {
      if (this.process !== process) {
        return;
      }
      const message =
        (error as NodeJS.ErrnoException).code === 'ENOENT'
          ? `walletd binary not found at ${walletdPath}`
          : `walletd failed to start: ${error.message}`;
      this.rejectPending(new Error(message));
      this.clearProcessState();
    });

    process.stderr.on('data', (data) => {
      if (this.process !== process) {
        return;
      }
      this.appendStderr(data);
      console.error(`walletd: ${data.toString()}`);
    });

    process.on('exit', (code, signal) => {
      if (this.process !== process) {
        return;
      }
      const error = this.buildExitError(code, signal);
      this.rejectPending(error);
      this.clearProcessState();
    });
  }

  private handleResponseLine(line: string) {
    const parsed = parseWalletdResponseLine(line);
    if (parsed.kind === 'empty') {
      return;
    }
    if (parsed.kind === 'noise') {
      console.warn(`walletd stdout: ${parsed.text}`);
      return;
    }
    if (parsed.kind === 'invalid') {
      console.error(`walletd invalid JSON response: ${parsed.text}`);
      return;
    }
    const response = parsed.response;
    const pending = this.pending.get(response.id);
    if (!pending) {
      return;
    }
    this.pending.delete(response.id);
    clearTimeout(pending.timer);
    if (response.ok) {
      pending.resolve(response.result ?? null);
    } else {
      pending.reject(walletdResponseError(response));
    }
  }

  async stop(): Promise<void> {
    const process = this.process;
    if (!process) {
      this.rejectPending(new Error('walletd stopped'));
      this.clearProcessState();
      return;
    }

    this.rejectPending(new Error('walletd stopped'));
    this.clearProcessState();

    let exited = false;
    const exitPromise = new Promise<void>((resolve) => {
      const settle = () => {
        exited = true;
        resolve();
      };
      process.once('exit', settle);
      process.once('error', settle);
    });

    process.kill('SIGINT');

    await Promise.race([
      exitPromise,
      new Promise<void>((resolve) => {
        setTimeout(() => resolve(), 1500);
      })
    ]);

    if (!exited) {
      // walletd ignored or could not service SIGINT within the grace period;
      // escalate so a wedged process cannot outlive the app session.
      try {
        process.kill('SIGKILL');
      } catch {
        // Process may have exited between the check and the kill.
      }
      await exitPromise;
    }
  }

  private rejectPending(error: Error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  private clearProcessState() {
    this.process = null;
    this.storePath = null;
    this.mode = null;
    this.stderrBuffer = [];
  }

  private appendStderr(data: Buffer) {
    const lines = data
      .toString()
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (!lines.length) {
      return;
    }
    this.stderrBuffer.push(...lines);
    if (this.stderrBuffer.length > 8) {
      this.stderrBuffer = this.stderrBuffer.slice(-8);
    }
  }

  private buildExitError(code: number | null, signal: NodeJS.Signals | null) {
    return walletdExitError(code, signal, this.stderrBuffer);
  }
}

const expandHomePath = (value: string) => {
  if (value === '~') {
    return homedir();
  }
  if (value.startsWith('~/')) {
    return join(homedir(), value.slice(2));
  }
  return value;
};
