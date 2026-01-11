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

type PendingRequest = {
  resolve: (value: any) => void;
  reject: (reason: Error) => void;
};

type WalletdResponse = {
  id: number;
  ok: boolean;
  result?: any;
  error?: string;
  error_code?: string;
};

type WalletdMode = 'open' | 'create';

export class WalletdClient {
  private process: ChildProcessWithoutNullStreams | null = null;
  private pending = new Map<number, PendingRequest>();
  private requestId = 0;
  private storePath: string | null = null;
  private passphrase: string | null = null;
  private mode: WalletdMode | null = null;
  private stderrBuffer: string[] = [];

  async status(storePath: string, passphrase: string): Promise<WalletStatus> {
    return this.request('status.get', {}, storePath, passphrase, 'open');
  }

  async init(storePath: string, passphrase: string): Promise<WalletStatus> {
    return this.request('status.get', {}, storePath, passphrase, 'create');
  }

  async restore(storePath: string, passphrase: string): Promise<WalletStatus> {
    return this.request('status.get', {}, storePath, passphrase, 'open');
  }

  async sync(
    storePath: string,
    passphrase: string,
    wsUrl: string,
    forceRescan: boolean
  ): Promise<WalletSyncResult> {
    return this.request(
      'sync.once',
      { ws_url: wsUrl, force_rescan: forceRescan },
      storePath,
      passphrase,
      'open'
    );
  }

  async send(request: WalletSendRequest): Promise<WalletSendResult> {
    return this.request(
      'tx.send',
      {
        ws_url: request.wsUrl,
        recipients: request.recipients,
        fee: request.fee,
        auto_consolidate: request.autoConsolidate
      },
      request.storePath,
      request.passphrase,
      'open'
    );
  }

  async sendPlan(request: WalletSendPlanRequest): Promise<WalletSendPlanResult> {
    return this.request(
      'tx.plan',
      { recipients: request.recipients, fee: request.fee },
      request.storePath,
      request.passphrase,
      'open'
    );
  }

  async disclosureCreate(
    storePath: string,
    passphrase: string,
    wsUrl: string,
    txId: string,
    output: number
  ): Promise<WalletDisclosureCreateResult> {
    return this.request(
      'disclosure.create',
      { ws_url: wsUrl, tx_id: txId, output },
      storePath,
      passphrase,
      'open'
    );
  }

  async disclosureVerify(
    storePath: string,
    passphrase: string,
    wsUrl: string,
    packageJson: object
  ): Promise<WalletDisclosureVerifyResult> {
    return this.request(
      'disclosure.verify',
      { ws_url: wsUrl, package: packageJson },
      storePath,
      passphrase,
      'open'
    );
  }

  async disclosureList(storePath: string, passphrase: string): Promise<WalletDisclosureRecord[]> {
    return this.request('disclosure.list', {}, storePath, passphrase, 'open');
  }

  private async request(
    method: string,
    params: object,
    storePath: string | null,
    passphrase: string | null,
    mode: WalletdMode
  ): Promise<any> {
    if (storePath && passphrase) {
      await this.ensureProcess(storePath, passphrase, mode);
    } else if (!this.process) {
      throw new Error('walletd process not running');
    }

    if (!this.process || !this.process.stdin.writable) {
      throw new Error('walletd stdin not available');
    }

    const id = ++this.requestId;
    const payload = JSON.stringify({ id, method, params });
    this.process.stdin.write(`${payload}\n`);

    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
    });
  }

  private async ensureProcess(storePath: string, passphrase: string, mode: WalletdMode): Promise<void> {
    const resolvedPath = expandHomePath(storePath);
    if (
      this.process &&
      this.storePath === resolvedPath &&
      this.passphrase === passphrase &&
      this.mode === mode
    ) {
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
    const process = spawn(walletdPath, ['--store', resolvedPath, '--mode', mode]);
    this.process = process;
    this.storePath = resolvedPath;
    this.passphrase = passphrase;
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
    const trimmed = line.trim();
    if (!trimmed) {
      return;
    }
    let response: WalletdResponse;
    try {
      response = JSON.parse(trimmed) as WalletdResponse;
    } catch {
      if (!trimmed.startsWith('{')) {
        console.warn(`walletd stdout: ${trimmed}`);
        return;
      }
      console.error(`walletd invalid JSON response: ${trimmed}`);
      return;
    }
    const pending = this.pending.get(response.id);
    if (!pending) {
      return;
    }
    this.pending.delete(response.id);
    if (response.ok) {
      pending.resolve(response.result ?? null);
    } else {
      const message = response.error || 'walletd error';
      const error = new Error(
        response.error_code ? `${message} (${response.error_code})` : message
      );
      if (response.error_code) {
        (error as { code?: string }).code = response.error_code;
      }
      pending.reject(error);
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

    const exitPromise = new Promise<void>((resolve) => {
      process.once('exit', () => resolve());
      process.once('error', () => resolve());
    });

    process.kill('SIGINT');

    const timeout = new Promise<void>((resolve) => {
      setTimeout(() => resolve(), 1500);
    });

    await Promise.race([exitPromise, timeout]);
  }

  private rejectPending(error: Error) {
    for (const pending of this.pending.values()) {
      pending.reject(error);
    }
    this.pending.clear();
  }

  private clearProcessState() {
    this.process = null;
    this.storePath = null;
    this.passphrase = null;
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
    const summary = this.formatStderrSummary();
    if (summary) {
      const cleaned = summary.replace(/^Error:\s*/, '').trim();
      if (cleaned) {
        return new Error(cleaned);
      }
    }
    const suffix = signal ? ` (signal ${signal})` : '';
    return new Error(`walletd exited with code ${code ?? 'unknown'}${suffix}`);
  }

  private formatStderrSummary() {
    if (!this.stderrBuffer.length) {
      return '';
    }
    const lines = this.stderrBuffer.filter(Boolean);
    if (!lines.length) {
      return '';
    }
    const first = lines[0];
    const last = lines[lines.length - 1].replace(/^\d+:\s*/, '');
    if (lines.length > 1 && last && last !== first) {
      return `${first} (${last})`;
    }
    return first;
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
