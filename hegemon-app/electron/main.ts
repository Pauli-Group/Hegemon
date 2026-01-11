import { app, BrowserWindow, ipcMain, nativeImage, session } from 'electron';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NodeManager } from './nodeManager';
import { WalletdClient } from './walletdClient';
import type {
  NodeMiningRequest,
  NodeStartOptions,
  NodeSummaryRequest,
  WalletDisclosureRecord,
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
const devServerUrl = process.env.ELECTRON_RENDERER_URL ?? process.env.VITE_DEV_SERVER_URL;

const buildContentSecurityPolicy = (devUrl?: string) => {
  const defaultSrc = ["'self'"];
  const scriptSrc = ["'self'"];
  const styleSrc = ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'];
  const fontSrc = ["'self'", 'https://fonts.gstatic.com', 'data:'];
  const imgSrc = ["'self'", 'data:', 'blob:'];
  const connectSrc = ["'self'"];

  if (devUrl) {
    scriptSrc.push("'unsafe-inline'");
    try {
      const origin = new URL(devUrl).origin;
      defaultSrc.push(origin);
      scriptSrc.push(origin);
      styleSrc.push(origin);
      connectSrc.push(origin);
      connectSrc.push(origin.replace(/^http/, 'ws'));
    } catch {
      // Ignore malformed dev URL.
    }
  }

  return [
    `default-src ${defaultSrc.join(' ')}`,
    `script-src ${scriptSrc.join(' ')}`,
    `style-src ${styleSrc.join(' ')}`,
    `font-src ${fontSrc.join(' ')}`,
    `img-src ${imgSrc.join(' ')}`,
    `connect-src ${connectSrc.join(' ')}`,
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'"
  ].join('; ');
};

const resolveIconPath = () => {
  const iconFile = process.platform === 'win32' ? 'icon.ico' : 'icon.png';
  const packagedIcon = join(process.resourcesPath, iconFile);
  const devIcon = join(process.cwd(), 'build', iconFile);
  const iconPath = app.isPackaged ? packagedIcon : devIcon;
  return existsSync(iconPath) ? iconPath : null;
};

const createWindow = () => {
  const iconPath = resolveIconPath();
  const windowIcon = iconPath ? nativeImage.createFromPath(iconPath) : undefined;
  const win = new BrowserWindow({
    width: 1280,
    height: 820,
    backgroundColor: '#0E1C36',
    icon: windowIcon,
    webPreferences: {
      preload: join(__dirname, '../preload/preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  if (process.platform === 'darwin' && windowIcon) {
    app.dock.setIcon(windowIcon);
  }

  if (process.env.VITE_DEV_SERVER_URL) {
    win.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else if (process.env.ELECTRON_RENDERER_URL) {
    win.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    win.loadFile(join(__dirname, '../renderer/index.html'));
  }
};

app.whenReady().then(() => {
  const csp = buildContentSecurityPolicy(devServerUrl);
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [csp]
      }
    });
  });
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

ipcMain.handle('node:summary', async (_event, request: NodeSummaryRequest) => {
  return nodeManager.getSummary(request);
});

ipcMain.handle('node:setMining', async (_event, request: NodeMiningRequest) => {
  await nodeManager.setMiningEnabled(request.enabled, request.threads, request.httpUrl);
});

ipcMain.handle('node:logs', async () => nodeManager.getLogs());

ipcMain.handle('wallet:init', async (_event, storePath: string, passphrase: string) => {
  return walletdClient.init(storePath, passphrase) as Promise<WalletStatus>;
});

ipcMain.handle('wallet:restore', async (_event, storePath: string, passphrase: string) => {
  return walletdClient.restore(storePath, passphrase) as Promise<WalletStatus>;
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

ipcMain.handle('wallet:disclosureList', async (_event, storePath: string, passphrase: string) => {
  return walletdClient.disclosureList(storePath, passphrase) as Promise<WalletDisclosureRecord[]>;
});
