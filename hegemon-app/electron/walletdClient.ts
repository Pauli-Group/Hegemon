import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createInterface } from 'node:readline';
import type {
  WalletDisclosureCreateResult,
  WalletDisclosureVerifyResult,
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
};

type WalletdMode = 'open' | 'create';

export class WalletdClient {
  private process: ChildProcessWithoutNullStreams | null = null;
  private pending = new Map<number, PendingRequest>();
  private requestId = 0;
  private storePath: string | null = null;
  private passphrase: string | null = null;
  private mode: WalletdMode | null = null;

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
    if (
      this.process &&
      this.storePath === storePath &&
      this.passphrase === passphrase &&
      this.mode === mode
    ) {
      return;
    }

    if (mode === 'open' && !existsSync(storePath)) {
      throw new Error('Wallet store not found.');
    }
    if (mode === 'create' && existsSync(storePath)) {
      throw new Error('Wallet store already exists.');
    }

    await this.stop();

    const walletdPath = resolveBinaryPath('walletd');
    this.process = spawn(walletdPath, ['--store', storePath, '--mode', mode]);
    this.storePath = storePath;
    this.passphrase = passphrase;
    this.mode = mode;

    this.process.stdin.write(`${passphrase}\n`);

    const reader = createInterface({ input: this.process.stdout });
    reader.on('line', (line) => this.handleResponseLine(line));

    this.process.stderr.on('data', (data) => {
      console.error(`walletd: ${data.toString()}`);
    });

    this.process.on('exit', (code) => {
      const error = new Error(`walletd exited with code ${code ?? 'unknown'}`);
      for (const pending of this.pending.values()) {
        pending.reject(error);
      }
      this.pending.clear();
      this.process = null;
      this.storePath = null;
      this.passphrase = null;
      this.mode = null;
    });
  }

  private handleResponseLine(line: string) {
    if (!line.trim()) {
      return;
    }
    let response: WalletdResponse;
    try {
      response = JSON.parse(line) as WalletdResponse;
    } catch (error) {
      console.error('walletd invalid response', error);
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
      pending.reject(new Error(response.error || 'walletd error'));
    }
  }

  async stop(): Promise<void> {
    if (this.process) {
      this.process.kill('SIGINT');
      this.process = null;
    }
    this.pending.clear();
    this.storePath = null;
    this.passphrase = null;
    this.mode = null;
  }
}
