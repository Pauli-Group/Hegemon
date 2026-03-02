import { app, BrowserWindow, dialog, ipcMain, Menu, nativeImage, session } from 'electron';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NodeManager } from './nodeManager';
import { WalletdClient } from './walletdClient';
import type {
  NodeMiningRequest,
  NodeStartOptions,
  NodeSummaryRequest,
  Contact,
  DialogOpenOptions,
  WalletDisclosureRecord,
  WalletDisclosureCreateResult,
  WalletDisclosureVerifyResult,
  WalletSendPlanRequest,
  WalletSendPlanResult,
  WalletSendRequest,
  WalletSendResult,
  WalletStatus,
  WalletSyncResult,
  WalletUnlockSession
} from '../src/types';

const __dirname = dirname(fileURLToPath(import.meta.url));
const nodeManager = new NodeManager();
const walletdClient = new WalletdClient();
const devServerUrl = process.env.ELECTRON_RENDERER_URL ?? process.env.VITE_DEV_SERVER_URL;
const contactsFileName = 'contacts.json';
let contactsWriteQueue: Promise<void> = Promise.resolve();
let shutdownInProgress = false;
const DEFAULT_UNLOCK_TTL_MS = 5 * 60 * 1000;
const MIN_UNLOCK_TTL_MS = 30 * 1000;
const walletUnlockTtlMs = (() => {
  const raw = process.env.HEGEMON_WALLET_UNLOCK_TTL_MS;
  const parsed = raw ? Number.parseInt(raw, 10) : NaN;
  if (!Number.isFinite(parsed) || Number.isNaN(parsed) || parsed < MIN_UNLOCK_TTL_MS) {
    return DEFAULT_UNLOCK_TTL_MS;
  }
  return parsed;
})();
type WalletUnlockState = {
  token: string;
  storePath: string;
  expiresAt: number;
};
let walletUnlockState: WalletUnlockState | null = null;

if (process.platform === 'win32') {
  app.setAppUserModelId('com.hegemon.desktop');
}

app.setName('Hegemon');

const resolveContactsPath = () => join(app.getPath('appData'), 'Hegemon', contactsFileName);

const configureAppMenu = () => {
  if (process.platform !== 'darwin') {
    return;
  }
  // Electron’s default macOS menu can emit noisy logs like:
  // "representedObject is not a WeakPtrToElectronMenuModelAsNSObject"
  // when Cocoa validates menu items. We ship an explicit minimal app menu to avoid
  // the default template (and we intentionally omit recent-documents items).
  const template: Electron.MenuItemConstructorOptions[] = [
    { role: 'appMenu' },
    { role: 'editMenu' },
    { role: 'viewMenu' },
    { role: 'windowMenu' }
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
};

const resolveLegacyContactsPaths = () => {
  const appData = app.getPath('appData');
  const stable = resolveContactsPath();
  const candidates = [
    join(app.getPath('userData'), contactsFileName),
    join(appData, 'hegemon-app', contactsFileName),
    join(appData, 'Hegemon Core', contactsFileName),
    join(appData, 'Electron', contactsFileName)
  ];
  return candidates.filter((candidate) => candidate !== stable);
};

const migrateContactsIfNeeded = async (destinationPath: string) => {
  if (existsSync(destinationPath)) {
    return;
  }
  for (const legacyPath of resolveLegacyContactsPaths()) {
    if (!existsSync(legacyPath)) {
      continue;
    }
    try {
      const raw = await readFile(legacyPath, 'utf-8');
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) {
        continue;
      }
      await mkdir(dirname(destinationPath), { recursive: true });
      try {
        await rename(legacyPath, destinationPath);
      } catch (error) {
        console.warn('Failed to move legacy contacts file, falling back to copy.', error);
        await writeFile(destinationPath, JSON.stringify(parsed, null, 2), 'utf-8');
      }
      console.info(`Migrated contacts from ${legacyPath} to ${destinationPath}.`);
      return;
    } catch (error) {
      console.warn(`Failed to migrate contacts from ${legacyPath}.`, error);
    }
  }
};

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

const resolveIconCandidates = () => {
  const iconFiles =
    process.platform === 'darwin'
      ? ['icon.icns', 'icon.png']
      : process.platform === 'win32'
        ? ['icon.ico', 'icon.png']
        : ['icon.png'];
  const basePaths = app.isPackaged
    ? [process.resourcesPath]
    : [join(app.getAppPath(), 'build'), join(process.cwd(), 'build'), join(__dirname, '..', '..', 'build')];
  return basePaths.flatMap((basePath) => iconFiles.map((iconFile) => join(basePath, iconFile)));
};

const loadAppIcon = () => {
  const candidates = resolveIconCandidates();
  for (const candidate of candidates) {
    if (!existsSync(candidate)) {
      continue;
    }
    const image = nativeImage.createFromPath(candidate);
    if (!image.isEmpty()) {
      return image;
    }
  }
  console.warn('Hegemon icon not found. Using default Electron icon.');
  return null;
};

const loadContacts = async (): Promise<Contact[] | null> => {
  const filePath = resolveContactsPath();
  await migrateContactsIfNeeded(filePath);
  try {
    const raw = await readFile(filePath, 'utf-8');
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
      const stamped = new Date().toISOString().replace(/[:.]/g, '-');
      const backupPath = join(app.getPath('userData'), `${contactsFileName}.corrupt-${stamped}`);
      try {
        await rename(filePath, backupPath);
      } catch (renameError) {
        console.warn('Failed to backup corrupt contacts file.', renameError);
      }
      console.warn(`Contacts file was corrupt. Backed up to ${backupPath}.`, error);
      return [];
    }
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error) {
      const err = error as NodeJS.ErrnoException;
      if (err.code === 'ENOENT') {
        return null;
      }
    }
    console.error('Failed to load contacts.', error);
    return [];
  }
};

const saveContacts = async (contacts: Contact[]) => {
  const filePath = resolveContactsPath();
  const payload = JSON.stringify(contacts, null, 2);

  const nextWrite = contactsWriteQueue.then(async () => {
    await mkdir(dirname(filePath), { recursive: true });
    const tmpPath = `${filePath}.tmp-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    await writeFile(tmpPath, payload, 'utf-8');
    await rename(tmpPath, filePath);
  });

  contactsWriteQueue = nextWrite.catch((error) => {
    console.error('Failed to save contacts.', error);
  });

  return nextWrite;
};

const createWindow = () => {
  const windowIcon = loadAppIcon() ?? undefined;
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
    app.dock?.setIcon(windowIcon);
  }

  if (process.env.VITE_DEV_SERVER_URL) {
    win.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else if (process.env.ELECTRON_RENDERER_URL) {
    win.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    win.loadFile(join(__dirname, '../renderer/index.html'));
  }
};

const stopManagedServices = async () => {
  walletUnlockState = null;
  await Promise.allSettled([nodeManager.stopNode(), walletdClient.stop()]);
};

const resolveStorePathForSession = (storePath: string) =>
  storePath === '~'
    ? app.getPath('home')
    : storePath.startsWith('~/')
      ? join(app.getPath('home'), storePath.slice(2))
      : storePath;

const issueWalletUnlockSession = (storePath: string, status: WalletStatus): WalletUnlockSession => {
  const token = randomBytes(32).toString('hex');
  const expiresAt = Date.now() + walletUnlockTtlMs;
  walletUnlockState = {
    token,
    storePath: resolveStorePathForSession(storePath),
    expiresAt
  };
  return { status, unlockToken: token, expiresAt };
};

const requireWalletUnlock = (storePath: string, unlockToken: string) => {
  const state = walletUnlockState;
  if (!state) {
    throw new Error('Wallet is locked. Open or init the store first.');
  }
  if (!unlockToken || unlockToken !== state.token) {
    throw new Error('Wallet unlock token is invalid.');
  }
  if (resolveStorePathForSession(storePath) !== state.storePath) {
    throw new Error('Wallet unlock token does not match the selected store path.');
  }
  if (Date.now() > state.expiresAt) {
    walletUnlockState = null;
    void walletdClient.stop();
    throw new Error('Wallet unlock token expired. Re-open the wallet.');
  }
  state.expiresAt = Date.now() + walletUnlockTtlMs;
};

app.whenReady().then(() => {
  app.setAboutPanelOptions({
    applicationName: 'Hegemon',
    applicationVersion: app.getVersion()
  });

  configureAppMenu();

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
  void stopManagedServices();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', (event) => {
  if (shutdownInProgress) {
    return;
  }
  shutdownInProgress = true;
  event.preventDefault();
  void stopManagedServices().finally(() => app.quit());
});

ipcMain.handle('node:start', async (_event, options: NodeStartOptions) => {
  await nodeManager.startNode(options);
});

ipcMain.handle('node:stop', async () => {
  await nodeManager.stopNode();
});

ipcMain.handle('node:managedStatus', async () => {
  return nodeManager.getManagedStatus();
});

ipcMain.handle('node:summary', async (_event, request: NodeSummaryRequest) => {
  return nodeManager.getSummary(request);
});

ipcMain.handle('node:setMining', async (_event, request: NodeMiningRequest) => {
  await nodeManager.setMiningEnabled(request.enabled, request.threads, request.httpUrl);
});

ipcMain.handle('node:logs', async () => nodeManager.getLogs());

ipcMain.handle('wallet:init', async (_event, storePath: string, passphrase: string) => {
  const status = (await walletdClient.init(storePath, passphrase)) as WalletStatus;
  return issueWalletUnlockSession(storePath, status);
});

ipcMain.handle('wallet:restore', async (_event, storePath: string, passphrase: string) => {
  const status = (await walletdClient.restore(storePath, passphrase)) as WalletStatus;
  return issueWalletUnlockSession(storePath, status);
});

ipcMain.handle('wallet:status', async (_event, storePath: string, unlockToken: string, noSync = false) => {
  if (noSync) {
    // `status.get` is local; flag retained for renderer compatibility.
  }
  requireWalletUnlock(storePath, unlockToken);
  return walletdClient.status() as Promise<WalletStatus>;
});

ipcMain.handle('wallet:sync', async (
  _event,
  storePath: string,
  unlockToken: string,
  wsUrl: string,
  forceRescan = false
) => {
  requireWalletUnlock(storePath, unlockToken);
  return walletdClient.sync(wsUrl, forceRescan) as Promise<WalletSyncResult>;
});

ipcMain.handle('wallet:send', async (_event, request: WalletSendRequest) => {
  requireWalletUnlock(request.storePath, request.unlockToken);
  try {
    return (await walletdClient.send(request)) as WalletSendResult;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const normalized = message.toLowerCase();
    const staleAnchor =
      (normalized.includes('invalid transaction') && normalized.includes("custom error: '3'")) ||
      normalized.includes('invalid anchor');
    if (!staleAnchor) {
      throw error;
    }

    // Recover from stale anchor state (e.g. after fork recovery/reorg) by forcing a
    // wallet rescan against the current chain and retrying submission once.
    await walletdClient.sync(request.wsUrl, true);
    return (await walletdClient.send(request)) as WalletSendResult;
  }
});

ipcMain.handle('wallet:sendPlan', async (_event, request: WalletSendPlanRequest) => {
  requireWalletUnlock(request.storePath, request.unlockToken);
  return walletdClient.sendPlan(request) as Promise<WalletSendPlanResult>;
});

ipcMain.handle('wallet:lock', async () => {
  walletUnlockState = null;
  await walletdClient.stop();
});

ipcMain.handle(
  'wallet:disclosureCreate',
  async (
    _event,
    storePath: string,
    unlockToken: string,
    wsUrl: string,
    txId: string,
    output: number
  ) => {
    requireWalletUnlock(storePath, unlockToken);
    return walletdClient.disclosureCreate(wsUrl, txId, output) as Promise<WalletDisclosureCreateResult>;
  }
);

ipcMain.handle(
  'wallet:disclosureVerify',
  async (
    _event,
    storePath: string,
    unlockToken: string,
    wsUrl: string,
    packageJson: object
  ) => {
    requireWalletUnlock(storePath, unlockToken);
    return walletdClient.disclosureVerify(wsUrl, packageJson) as Promise<WalletDisclosureVerifyResult>;
  }
);

ipcMain.handle('wallet:disclosureList', async (_event, storePath: string, unlockToken: string) => {
  requireWalletUnlock(storePath, unlockToken);
  return walletdClient.disclosureList() as Promise<WalletDisclosureRecord[]>;
});

ipcMain.handle('contacts:list', async () => {
  return loadContacts();
});

ipcMain.handle('contacts:save', async (_event, contacts: Contact[]) => {
  if (!Array.isArray(contacts)) {
    throw new Error('Contacts payload must be an array.');
  }
  await saveContacts(contacts);
});

ipcMain.handle('dialog:openPath', async (_event, options: DialogOpenOptions) => {
  const browserWindow = BrowserWindow.getFocusedWindow() ?? BrowserWindow.getAllWindows()[0];
  const resolvedDefaultPath =
    options.defaultPath === '~'
      ? app.getPath('home')
      : options.defaultPath?.startsWith('~/')
        ? join(app.getPath('home'), options.defaultPath.slice(2))
        : options.defaultPath;
  const dialogOptions: Electron.OpenDialogOptions = {
    title: options.title,
    defaultPath: resolvedDefaultPath,
    buttonLabel: options.buttonLabel,
    filters: options.filters,
    properties: options.properties && options.properties.length > 0 ? options.properties : ['openFile']
  };
  const result = await dialog.showOpenDialog(browserWindow ?? undefined, dialogOptions);
  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }
  return result.filePaths[0];
});
