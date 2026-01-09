import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { WalletSendRequest, WalletSendResult, WalletStatus, WalletSyncResult } from '../src/types';

const walletBin = resolve(process.cwd(), 'target/release/wallet');

const runWalletCommand = (args: string[]): Promise<{ stdout: string; stderr: string }> =>
  new Promise((resolvePromise, reject) => {
    execFile(walletBin, args, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(stderr || error.message));
        return;
      }
      resolvePromise({ stdout, stderr });
    });
  });

const parseStatus = (output: string): WalletStatus => {
  const lines = output.split('\n');
  const status: WalletStatus = { rawOutput: output };

  const addressLine = lines.find((line) => line.includes('Shielded Address:'));
  if (addressLine) {
    status.address = addressLine.split('Shielded Address:')[1]?.trim();
  }

  const balances: WalletStatus['balances'] = [];
  for (const line of lines) {
    const match = line.match(/^\s+(.+?):\s+([0-9.]+)$/);
    if (match) {
      balances.push({
        assetId: match[1].includes('asset') ? Number.parseInt(match[1].split(' ')[1], 10) : 0,
        label: match[1],
        total: match[2]
      });
    }
  }

  if (balances.length) {
    status.balances = balances;
  }

  return status;
};

export const walletInit = async (storePath: string, passphrase: string): Promise<WalletStatus> => {
  await runWalletCommand(['init', '--store', storePath, '--passphrase', passphrase]);
  return walletStatus(storePath, passphrase, true);
};

export const walletRestore = async (storePath: string, passphrase: string): Promise<WalletStatus> => {
  await runWalletCommand(['restore', '--store', storePath, '--passphrase', passphrase]);
  return walletStatus(storePath, passphrase, true);
};

export const walletStatus = async (
  storePath: string,
  passphrase: string,
  noSync = false
): Promise<WalletStatus> => {
  const args = ['status', '--store', storePath, '--passphrase', passphrase];
  if (noSync) {
    args.push('--no-sync');
  }
  const result = await runWalletCommand(args);
  return parseStatus(result.stdout);
};

export const walletSync = async (
  storePath: string,
  passphrase: string,
  wsUrl: string,
  forceRescan: boolean
): Promise<WalletSyncResult> => {
  const args = [
    'substrate-sync',
    '--store',
    storePath,
    '--passphrase',
    passphrase,
    '--ws-url',
    wsUrl
  ];
  if (forceRescan) {
    args.push('--force-rescan');
  }
  const result = await runWalletCommand(args);
  return { rawOutput: result.stdout };
};

export const walletSend = async (request: WalletSendRequest): Promise<WalletSendResult> => {
  const tempDir = await fs.mkdtemp(join(tmpdir(), 'hegemon-wallet-'));
  const recipientsPath = join(tempDir, 'recipients.json');
  await fs.writeFile(recipientsPath, JSON.stringify(request.recipients, null, 2));

  const args = [
    'substrate-send',
    '--store',
    request.storePath,
    '--passphrase',
    request.passphrase,
    '--ws-url',
    request.wsUrl,
    '--recipients',
    recipientsPath,
    '--fee',
    String(request.fee)
  ];

  if (request.autoConsolidate) {
    args.push('--auto-consolidate');
  }

  const result = await runWalletCommand(args);
  return { rawOutput: result.stdout };
};
