import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createInterface } from 'node:readline';
import { resolve } from 'node:path';
import type {
  WalletDisclosureCreateResult,
  WalletDisclosureVerifyResult,
  WalletSendRequest,
  WalletSendResult,
  WalletStatus,
  WalletSyncResult
} from '../src/types';

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

export class WalletdClient {
  private process: ChildProcessWithoutNullStreams | null = null;
  private pending = new Map<number, PendingRequest>();
  private requestId = 0;
  private storePath: string | null = null;
  private passphrase: string | null = null;

  async status(storePath: string, passphrase: string): Promise<WalletStatus> {
    return this.request('status.get', {}, storePath, passphrase);
  }

  async sync(
    storePath: string,
    passphrase: string,
    wsUrl: string,
    forceRescan: boolean
  ): Promise<WalletSyncResult> {
    return this.request('sync.once', { ws_url: wsUrl, force_rescan: forceRescan }, storePath, passphrase);
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
      request.passphrase
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
      passphrase
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
      passphrase
    );
  }

  private async request(
    method: string,
    params: object,
    storePath: string | null,
    passphrase: string | null
  ): Promise<any> {
    if (storePath && passphrase) {
      await this.ensureProcess(storePath, passphrase);
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

  private async ensureProcess(storePath: string, passphrase: string): Promise<void> {
    if (this.process && this.storePath === storePath && this.passphrase === passphrase) {
      return;
    }

    await this.stop();

    const walletdPath = resolve(process.cwd(), 'target/release/walletd');
    this.process = spawn(walletdPath, ['--store', storePath]);
    this.storePath = storePath;
    this.passphrase = passphrase;

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
  }
}
