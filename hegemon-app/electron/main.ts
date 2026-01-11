import { app, BrowserWindow, ipcMain, nativeImage, session } from 'electron';
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
  WalletDisclosureRecord,
  WalletDisclosureCreateResult,
  WalletDisclosureVerifyResult,
  WalletSendPlanRequest,
  WalletSendPlanResult,
  WalletSendRequest,
  WalletSendResult,
  WalletStatus,
  WalletSyncResult
} from '../src/types';

const __dirname = dirname(fileURLToPath(import.meta.url));
const nodeManager = new NodeManager();
const walletdClient = new WalletdClient();
const devServerUrl = process.env.ELECTRON_RENDERER_URL ?? process.env.VITE_DEV_SERVER_URL;
const contactsFileName = 'contacts.json';
let contactsWriteQueue: Promise<void> = Promise.resolve();

if (process.platform === 'win32') {
  app.setAppUserModelId('com.hegemon.desktop');
}

app.setName('Hegemon');

const resolveContactsPath = () => join(app.getPath('appData'), 'Hegemon', contactsFileName);

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

app.whenReady().then(() => {
  app.setAboutPanelOptions({
    applicationName: 'Hegemon',
    applicationVersion: app.getVersion()
  });

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

ipcMain.handle('wallet:sendPlan', async (_event, request: WalletSendPlanRequest) => {
  return walletdClient.sendPlan(request) as Promise<WalletSendPlanResult>;
});

ipcMain.handle('wallet:lock', async () => {
  await walletdClient.stop();
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

ipcMain.handle('contacts:list', async () => {
  return loadContacts();
});

ipcMain.handle('contacts:save', async (_event, contacts: Contact[]) => {
  if (!Array.isArray(contacts)) {
    throw new Error('Contacts payload must be an array.');
  }
  await saveContacts(contacts);
});
