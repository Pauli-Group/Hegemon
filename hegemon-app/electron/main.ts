import { app, BrowserWindow, clipboard, dialog, ipcMain, Menu, nativeImage, session } from 'electron';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NodeManager } from './nodeManager';
import { WalletdClient } from './walletdClient';
import { normalizeLoopbackWalletOneShotRpcEndpoint } from './rpcEndpoint';
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
const rendererUrlOverride = app.isPackaged
  ? undefined
  : process.env.ELECTRON_RENDERER_URL ?? process.env.VITE_DEV_SERVER_URL;
const contactsFileName = 'contacts.json';
const privateDirectoryMode = 0o700;
const privateFileMode = 0o600;
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

const chmodPrivate = async (path: string, mode: number) => {
  if (process.platform === 'win32') {
    return;
  }
  await chmod(path, mode);
};

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
    await mkdir(dirname(filePath), { recursive: true, mode: privateDirectoryMode });
    await chmodPrivate(dirname(filePath), privateDirectoryMode);
    const tmpPath = `${filePath}.tmp-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    await writeFile(tmpPath, payload, { encoding: 'utf-8', mode: privateFileMode });
    await chmodPrivate(tmpPath, privateFileMode);
    await rename(tmpPath, filePath);
    await chmodPrivate(filePath, privateFileMode);
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
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false
    }
  });

  if (process.platform === 'darwin' && windowIcon) {
    app.dock?.setIcon(windowIcon);
  }

  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event) => {
    event.preventDefault();
  });
  win.webContents.on('will-redirect', (event) => {
    event.preventDefault();
  });
  win.webContents.on('will-attach-webview', (event) => {
    event.preventDefault();
  });

  if (!app.isPackaged && process.env.VITE_DEV_SERVER_URL) {
    win.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else if (!app.isPackaged && process.env.ELECTRON_RENDERER_URL) {
    win.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    win.loadFile(join(__dirname, '../renderer/index.html'));
  }
};

const stopManagedServices = async () => {
  walletUnlockState = null;
  await Promise.allSettled([nodeManager.stopNode(), walletdClient.stop()]);
};

const walletStoreRoot = () => resolve(app.getPath('userData'), 'wallets');

const isPathWithin = (root: string, candidate: string) => {
  const rel = relative(root, candidate);
  return rel === '' || (!!rel && !rel.startsWith('..') && !isAbsolute(rel));
};

const resolveStorePathForSession = (storePath: string) => {
  if (typeof storePath !== 'string') {
    throw new Error('Wallet store path is required.');
  }
  const trimmed = storePath.trim();
  if (!trimmed) {
    throw new Error('Wallet store path is required.');
  }
  if (trimmed.includes('\0')) {
    throw new Error('Wallet store path contains an invalid character.');
  }

  const root = walletStoreRoot();
  const relativeInput =
    trimmed === '~'
      ? 'default.wallet'
      : trimmed.startsWith('~/')
        ? trimmed.slice(2)
        : trimmed;
  if (isAbsolute(relativeInput)) {
    const candidate = resolve(relativeInput);
    if (!isPathWithin(root, candidate)) {
      throw new Error('Wallet stores must be selected from the Hegemon wallet directory.');
    }
    if (candidate === root || candidate.endsWith(sep)) {
      throw new Error('Wallet store path must name a wallet file.');
    }
    return candidate;
  }
  const candidate = resolve(root, relativeInput);
  if (!isPathWithin(root, candidate)) {
    throw new Error('Wallet store path escapes the Hegemon wallet directory.');
  }
  if (candidate === root || candidate.endsWith(sep)) {
    throw new Error('Wallet store path must name a wallet file.');
  }
  return candidate;
};

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

  const csp = buildContentSecurityPolicy(rendererUrlOverride);
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [csp]
      }
    });
  });
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
    callback(false);
  });
  session.defaultSession.setPermissionCheckHandler(() => false);
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

ipcMain.handle('clipboard:writeText', async (_event, text: string) => {
  if (typeof text !== 'string' || text.length === 0) {
    throw new Error('Clipboard text is required.');
  }
  clipboard.writeText(text);
});

ipcMain.handle('wallet:init', async (_event, storePath: string, passphrase: string) => {
  const resolvedStorePath = resolveStorePathForSession(storePath);
  await mkdir(dirname(resolvedStorePath), { recursive: true });
  const status = (await walletdClient.init(resolvedStorePath, passphrase)) as WalletStatus;
  return issueWalletUnlockSession(storePath, status);
});

ipcMain.handle('wallet:restore', async (_event, storePath: string, passphrase: string) => {
  const resolvedStorePath = resolveStorePathForSession(storePath);
  const status = (await walletdClient.restore(resolvedStorePath, passphrase)) as WalletStatus;
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
  return walletdClient.sync(
    normalizeLoopbackWalletOneShotRpcEndpoint(wsUrl),
    forceRescan
  ) as Promise<WalletSyncResult>;
});

ipcMain.handle('wallet:send', async (_event, request: WalletSendRequest) => {
  requireWalletUnlock(request.storePath, request.unlockToken);
  const admittedRequest = {
    ...request,
    wsUrl: normalizeLoopbackWalletOneShotRpcEndpoint(request.wsUrl)
  };
  try {
    return (await walletdClient.send(admittedRequest)) as WalletSendResult;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const normalized = message.toLowerCase();
    const hasCustomError3 = /custom error:\s*['"]?3['"]?/.test(normalized);
    const staleAnchor =
      (normalized.includes('invalid transaction') && hasCustomError3) ||
      normalized.includes('invalid anchor');
    if (!staleAnchor) {
      throw error;
    }

    // Recover from stale anchor state (e.g. after fork recovery/reorg) by forcing a
    // wallet rescan against the current chain and retrying submission once.
    await walletdClient.sync(admittedRequest.wsUrl, true);
    return (await walletdClient.send(admittedRequest)) as WalletSendResult;
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
    return walletdClient.disclosureCreate(
      normalizeLoopbackWalletOneShotRpcEndpoint(wsUrl),
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
    unlockToken: string,
    wsUrl: string,
    packageJson: object
  ) => {
    requireWalletUnlock(storePath, unlockToken);
    return walletdClient.disclosureVerify(
      normalizeLoopbackWalletOneShotRpcEndpoint(wsUrl),
      packageJson
    ) as Promise<WalletDisclosureVerifyResult>;
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
  const dialogBase = options.baseDirectory === 'walletStore' ? walletStoreRoot() : app.getPath('home');
  const trimmedDefaultPath = options.defaultPath?.trim();
  const resolvedDefaultPath =
    options.baseDirectory === 'walletStore'
      ? !trimmedDefaultPath || trimmedDefaultPath === '~'
        ? dialogBase
        : trimmedDefaultPath.startsWith('~/')
          ? resolve(dialogBase, trimmedDefaultPath.slice(2))
          : isAbsolute(trimmedDefaultPath)
            ? resolve(trimmedDefaultPath)
            : resolve(dialogBase, trimmedDefaultPath)
      : options.defaultPath === '~'
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
  const selectedPath = resolve(result.filePaths[0]);
  if (options.baseDirectory === 'walletStore') {
    const root = walletStoreRoot();
    if (!isPathWithin(root, selectedPath) || selectedPath === root || selectedPath.endsWith(sep)) {
      throw new Error('Wallet stores must be selected from the Hegemon wallet directory.');
    }
    return `~/${relative(root, selectedPath).split(sep).join('/')}`;
  }
  return selectedPath;
});
