import { app, BrowserWindow, ipcMain } from 'electron';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NodeManager } from './nodeManager';
import { WalletdClient } from './walletdClient';
import type {
  NodeStartOptions,
  WalletDisclosureCreateResult,
  WalletDisclosureVerifyResult,
  WalletSendRequest,
  WalletSendResult,
  WalletStatus,
  WalletSyncResult
} from '../src/types';

const __dirname = dirname(fileURLToPath(import.meta.url));
const nodeManager = new NodeManager();
const walletdClient = new WalletdClient();

const createWindow = () => {
  const win = new BrowserWindow({
    width: 1280,
    height: 820,
    backgroundColor: '#0E1C36',
    webPreferences: {
      preload: join(__dirname, 'preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  if (process.env.VITE_DEV_SERVER_URL) {
    win.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    win.loadFile(join(__dirname, '../renderer/index.html'));
  }
};

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

ipcMain.handle('node:start', async (_event, options: NodeStartOptions) => {
  await nodeManager.startNode(options);
});

ipcMain.handle('node:stop', async () => {
  await nodeManager.stopNode();
});

ipcMain.handle('node:summary', async () => {
  return nodeManager.getSummary();
});

ipcMain.handle('node:setMining', async (_event, enabled: boolean, threads?: number) => {
  await nodeManager.setMiningEnabled(enabled, threads);
});

ipcMain.handle('node:logs', async () => nodeManager.getLogs());

ipcMain.handle('wallet:init', async (_event, storePath: string, passphrase: string) => {
  return walletdClient.status(storePath, passphrase) as Promise<WalletStatus>;
});

ipcMain.handle('wallet:restore', async (_event, storePath: string, passphrase: string) => {
  return walletdClient.status(storePath, passphrase) as Promise<WalletStatus>;
});

ipcMain.handle('wallet:status', async (_event, storePath: string, passphrase: string, noSync = false) => {
  return walletdClient.status(storePath, passphrase) as Promise<WalletStatus>;
});

ipcMain.handle('wallet:sync', async (
  _event,
  storePath: string,
  passphrase: string,
  wsUrl: string,
  forceRescan = false
) => {
  return walletdClient.sync(storePath, passphrase, wsUrl, forceRescan) as Promise<WalletSyncResult>;
});

ipcMain.handle('wallet:send', async (_event, request: WalletSendRequest) => {
  return walletdClient.send(request) as Promise<WalletSendResult>;
});

ipcMain.handle(
  'wallet:disclosureCreate',
  async (
    _event,
    storePath: string,
    passphrase: string,
    wsUrl: string,
    txId: string,
    output: number
  ) => {
    return walletdClient.disclosureCreate(
      storePath,
      passphrase,
      wsUrl,
      txId,
      output
    ) as Promise<WalletDisclosureCreateResult>;
  }
);

ipcMain.handle(
  'wallet:disclosureVerify',
  async (
    _event,
    storePath: string,
    passphrase: string,
    wsUrl: string,
    packageJson: object
  ) => {
    return walletdClient.disclosureVerify(
      storePath,
      passphrase,
      wsUrl,
      packageJson
    ) as Promise<WalletDisclosureVerifyResult>;
  }
);
