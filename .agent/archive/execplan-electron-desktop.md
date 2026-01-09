# Hegemon Electron Desktop App Execution Plan

**Status**: Optional  
**Last Updated**: 2025-11-25  
**Owner**: Core Team  
**Priority**: Low (post-mainnet)

---

## Overview

Bundle the Hegemon node, wallet, and dashboard into a single desktop application for easy distribution to end users.

## Prerequisites

- [ ] Substrate migration complete (full block production working)
- [ ] Testnet validated for stability
- [ ] All Phase 4 RPC endpoints implemented (`hegemon_startMining`, `hegemon_stopMining`, `hegemon_walletBalance`, etc.)

---

## Decision Log

| ID | Decision | Rationale | Date |
|----|----------|-----------|------|
| E1 | Use Electron for cross-platform | Single codebase for macOS/Windows/Linux; reuse dashboard-ui | 2025-11-25 |
| E2 | Spawn node as child process | Better isolation; easier updates; reuse existing binary | 2025-11-25 |
| E3 | System tray integration | Allow background mining; quick status access | 2025-11-25 |
| E4 | Context isolation enabled | Security best practice for Electron apps | 2025-11-25 |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Hegemon Desktop App                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   Electron Main Process                     ││
│  │  ┌─────────────────┐  ┌──────────────────────────────────┐ ││
│  │  │ Node Manager    │  │ IPC Bridge                       │ ││
│  │  │ - spawn binary  │  │ - renderer ↔ node RPC            │ ││
│  │  │ - health checks │  │ - native file dialogs            │ ││
│  │  │ - log capture   │  │ - system tray integration        │ ││
│  │  └─────────────────┘  └──────────────────────────────────┘ ││
│  └─────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                  Electron Renderer Process                  ││
│  │  ┌─────────────────────────────────────────────────────────┐││
│  │  │              dashboard-ui (React/TypeScript)            │││
│  │  │  - Block Explorer    - Wallet UI    - Mining Controls  │││
│  │  └─────────────────────────────────────────────────────────┘││
│  └─────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                  Bundled Resources                          ││
│  │  hegemon-node (platform binary)  │  chain-spec.json        ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

---

## Progress Checkpoints

- [ ] Phase E1: Project scaffold with Electron + electron-builder
- [ ] Phase E2: Node manager (spawn/stop hegemon-node binary)
- [ ] Phase E3: IPC handlers for RPC bridge
- [ ] Phase E4: Dashboard integration with Electron detection
- [ ] Phase E5: System tray with mining controls
- [ ] Phase E6: Platform builds (macOS, Windows, Linux)
- [ ] Phase E7: Code signing and notarization
- [ ] Phase E8: Auto-update mechanism

---

## Phase E1: Project Scaffold (Week 1)

**Goal**: Create Electron project structure with build configuration.

**Files to Create**:
```
electron/
├── package.json
├── electron-builder.yml
├── tsconfig.json
├── src/
│   ├── main.ts              # Electron main process
│   ├── preload.ts           # Secure bridge to renderer
│   ├── node-manager.ts      # Spawns/manages hegemon-node
│   ├── ipc-handlers.ts      # IPC channel definitions
│   └── tray.ts              # System tray integration
├── resources/
│   ├── icon.icns            # macOS icon
│   ├── icon.ico             # Windows icon
│   └── icon.png             # Linux icon
└── scripts/
    ├── fetch-binaries.sh    # Download platform binaries
    └── notarize.js          # macOS notarization
```

**Step-by-Step Commands**:
```bash
# Step E1.1: Create Electron scaffold
mkdir -p electron/src electron/resources electron/scripts
cd electron
npm init -y
npm install electron electron-builder --save-dev
npm install @electron/remote electron-store --save

# Step E1.2: Configure build
cat > electron-builder.yml << 'EOF'
appId: network.hegemon.desktop
productName: Hegemon
directories:
  output: dist
  buildResources: resources
files:
  - "dist/**/*"
  - "resources/**/*"
extraResources:
  - from: "../target/release/hegemon-node"
    to: "bin/hegemon-node"
    filter: ["**/*"]
mac:
  category: public.app-category.finance
  target:
    - target: dmg
      arch: [x64, arm64]
  hardenedRuntime: true
  entitlements: resources/entitlements.mac.plist
  notarize: false  # Set true for release
win:
  target:
    - target: nsis
      arch: [x64]
linux:
  target:
    - target: AppImage
      arch: [x64]
    - target: deb
      arch: [x64]
  category: Finance
EOF
```

**Verification**:
- [ ] Run: `cd electron && npm install` → installs without errors
- [ ] Run: `npm run dev` → Electron window opens

---

## Phase E2: Node Manager (Week 1)

**Goal**: Implement NodeManager class to spawn and manage hegemon-node binary.

**File: `electron/src/node-manager.ts`**:
```typescript
import { spawn, ChildProcess } from 'child_process';
import { EventEmitter } from 'events';
import WebSocket from 'ws';

interface NodeConfig {
  binaryPath: string;
  dataDir: string;
  rpcPort: number;
  p2pPort: number;
  chain: 'mainnet' | 'testnet' | 'dev';
  bootnodes?: string[];
  miningThreads?: number;
}

export class NodeManager extends EventEmitter {
  private process: ChildProcess | null = null;
  private ws: WebSocket | null = null;
  private config: NodeConfig;
  private isRunning = false;

  constructor(config: NodeConfig) {
    super();
    this.config = config;
  }

  async start(): Promise<void> {
    if (this.isRunning) return;

    const args = [
      `--chain=${this.config.chain}`,
      `--base-path=${this.config.dataDir}`,
      `--rpc-port=${this.config.rpcPort}`,
      `--port=${this.config.p2pPort}`,
      '--rpc-cors=all',
      '--rpc-methods=unsafe', // For local use only
    ];

    if (this.config.bootnodes?.length) {
      args.push(`--bootnodes=${this.config.bootnodes.join(',')}`);
    }

    this.process = spawn(this.config.binaryPath, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    this.process.stdout?.on('data', (data) => {
      const lines = data.toString().split('\n');
      lines.forEach((line: string) => {
        if (line.trim()) {
          this.emit('log', line);
          this.parseLogLine(line);
        }
      });
    });

    this.process.stderr?.on('data', (data) => {
      this.emit('log', `[ERR] ${data.toString()}`);
    });

    this.process.on('exit', (code) => {
      this.isRunning = false;
      this.emit('exit', code);
    });

    // Wait for RPC to be ready
    await this.waitForRpc();
    this.isRunning = true;

    // Connect WebSocket for subscriptions
    await this.connectWebSocket();
  }

  async stop(): Promise<void> {
    if (!this.process) return;

    this.ws?.close();
    
    return new Promise((resolve) => {
      this.process!.once('exit', () => {
        this.process = null;
        this.isRunning = false;
        resolve();
      });
      
      this.process!.kill('SIGTERM');
      
      // Force kill after 10s
      setTimeout(() => {
        if (this.process) {
          this.process.kill('SIGKILL');
        }
      }, 10000);
    });
  }

  async startMining(threads = 1): Promise<void> {
    await this.rpcCall('hegemon_startMining', { threads });
  }

  async stopMining(): Promise<void> {
    await this.rpcCall('hegemon_stopMining', {});
  }

  async rpcCall(method: string, params: unknown): Promise<unknown> {
    const response = await fetch(`http://127.0.0.1:${this.config.rpcPort}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: Date.now(),
        method,
        params,
      }),
    });
    const json = await response.json();
    if (json.error) throw new Error(json.error.message);
    return json.result;
  }

  private async waitForRpc(maxAttempts = 30): Promise<void> {
    for (let i = 0; i < maxAttempts; i++) {
      try {
        await this.rpcCall('system_health', []);
        return;
      } catch {
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    throw new Error('Node RPC did not become available');
  }

  private async connectWebSocket(): Promise<void> {
    this.ws = new WebSocket(`ws://127.0.0.1:${this.config.rpcPort}`);
    
    this.ws.on('open', () => {
      // Subscribe to new blocks
      this.ws!.send(JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'chain_subscribeNewHeads',
        params: [],
      }));
    });

    this.ws.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      if (msg.params?.result?.number) {
        const blockNum = parseInt(msg.params.result.number, 16);
        this.emit('block', blockNum);
      }
    });
  }

  private parseLogLine(line: string): void {
    // Parse Substrate log format for key events
    if (line.includes('Imported #')) {
      const match = line.match(/Imported #(\d+)/);
      if (match) {
        this.emit('block', parseInt(match[1], 10));
      }
    }
  }
}
```

**Verification**:
- [ ] Node starts when app launches
- [ ] Node stops gracefully on app quit
- [ ] Logs are captured and forwarded

---

## Phase E3: IPC Handlers (Week 1-2)

**Goal**: Implement secure IPC bridge between main and renderer processes.

**File: `electron/src/preload.ts`**:
```typescript
import { contextBridge, ipcRenderer } from 'electron';

// Expose safe APIs to renderer
contextBridge.exposeInMainWorld('hegemon', {
  // Node control
  node: {
    startMining: (threads: number) => ipcRenderer.invoke('node:startMining', threads),
    stopMining: () => ipcRenderer.invoke('node:stopMining'),
    getStatus: () => ipcRenderer.invoke('node:getStatus'),
    onLog: (callback: (log: string) => void) => {
      ipcRenderer.on('node:log', (_, log) => callback(log));
    },
    onBlock: (callback: (blockNum: number) => void) => {
      ipcRenderer.on('node:block', (_, blockNum) => callback(blockNum));
    },
  },
  
  // Wallet operations  
  wallet: {
    create: (password: string) => ipcRenderer.invoke('wallet:create', password),
    unlock: (password: string) => ipcRenderer.invoke('wallet:unlock', password),
    getBalance: () => ipcRenderer.invoke('wallet:getBalance'),
    send: (to: string, amount: string) => ipcRenderer.invoke('wallet:send', to, amount),
    getAddress: () => ipcRenderer.invoke('wallet:getAddress'),
  },
  
  // App info
  app: {
    getVersion: () => ipcRenderer.invoke('app:getVersion'),
    getDataDir: () => ipcRenderer.invoke('app:getDataDir'),
    openDataDir: () => ipcRenderer.invoke('app:openDataDir'),
  },
});
```

**File: `electron/src/ipc-handlers.ts`**:
```typescript
import { IpcMain, app, shell } from 'electron';
import { NodeManager } from './node-manager';
import path from 'path';

export function setupIpcHandlers(ipcMain: IpcMain, nodeManager: NodeManager): void {
  // Node control
  ipcMain.handle('node:startMining', async (_, threads: number) => {
    await nodeManager.startMining(threads);
    return { success: true };
  });

  ipcMain.handle('node:stopMining', async () => {
    await nodeManager.stopMining();
    return { success: true };
  });

  ipcMain.handle('node:getStatus', async () => {
    const health = await nodeManager.rpcCall('system_health', []);
    const peers = await nodeManager.rpcCall('system_peers', []);
    return { health, peerCount: (peers as unknown[]).length };
  });

  // Wallet (delegates to node RPC)
  ipcMain.handle('wallet:getBalance', async () => {
    return nodeManager.rpcCall('hegemon_walletBalance', []);
  });

  ipcMain.handle('wallet:send', async (_, to: string, amount: string) => {
    return nodeManager.rpcCall('hegemon_sendTransaction', { to, amount });
  });

  ipcMain.handle('wallet:getAddress', async () => {
    return nodeManager.rpcCall('hegemon_walletAddress', []);
  });

  // App info
  ipcMain.handle('app:getVersion', () => app.getVersion());
  
  ipcMain.handle('app:getDataDir', () => {
    return path.join(app.getPath('userData'), 'chain-data');
  });

  ipcMain.handle('app:openDataDir', () => {
    const dataDir = path.join(app.getPath('userData'), 'chain-data');
    shell.openPath(dataDir);
  });
}
```

**Verification**:
- [ ] IPC calls work from renderer to main
- [ ] Mining can be started/stopped via IPC
- [ ] Wallet balance can be queried

---

## Phase E4: Dashboard Integration (Week 2)

**Goal**: Update dashboard-ui to detect and use Electron IPC when available.

**File: `dashboard-ui/src/types/electron.d.ts`**:
```typescript
interface HegemonElectronAPI {
  node: {
    startMining: (threads: number) => Promise<{ success: boolean }>;
    stopMining: () => Promise<{ success: boolean }>;
    getStatus: () => Promise<{ health: SystemHealth; peerCount: number }>;
    onLog: (callback: (log: string) => void) => void;
    onBlock: (callback: (blockNum: number) => void) => void;
  };
  wallet: {
    create: (password: string) => Promise<{ address: string }>;
    unlock: (password: string) => Promise<{ success: boolean }>;
    getBalance: () => Promise<string>;
    send: (to: string, amount: string) => Promise<{ txHash: string }>;
    getAddress: () => Promise<string>;
  };
  app: {
    getVersion: () => Promise<string>;
    getDataDir: () => Promise<string>;
    openDataDir: () => Promise<void>;
  };
}

declare global {
  interface Window {
    hegemon?: HegemonElectronAPI;
  }
}
```

**Update: `dashboard-ui/src/stores/useNodeStore.ts`**:
```typescript
// Detect Electron environment
const isElectron = typeof window !== 'undefined' && window.hegemon !== undefined;

export const useNodeStore = create<NodeState>((set, get) => ({
  blockNumber: 0,
  syncing: true,
  peerCount: 0,
  mining: false,

  initialize: async () => {
    if (isElectron) {
      // Use Electron IPC
      window.hegemon.node.onBlock((blockNum) => {
        set({ blockNumber: blockNum });
      });
      
      const status = await window.hegemon.node.getStatus();
      set({ syncing: status.health.isSyncing, peerCount: status.peerCount });
    } else {
      // Use WebSocket (existing code)
      const api = await createApi(import.meta.env.VITE_WS_ENDPOINT);
      // ...
    }
  },

  startMining: async (threads = 1) => {
    if (isElectron) {
      await window.hegemon.node.startMining(threads);
      set({ mining: true });
    }
  },

  stopMining: async () => {
    if (isElectron) {
      await window.hegemon.node.stopMining();
      set({ mining: false });
    }
  },
}));
```

**Verification**:
- [ ] Dashboard works in browser (WebSocket mode)
- [ ] Dashboard works in Electron (IPC mode)
- [ ] Block updates work in both modes

---

## Phase E5: Main Process & Tray (Week 2)

**Goal**: Implement main process with system tray integration.

**File: `electron/src/main.ts`**:
```typescript
import { app, BrowserWindow, ipcMain, Tray, Menu } from 'electron';
import path from 'path';
import { NodeManager } from './node-manager';
import { setupIpcHandlers } from './ipc-handlers';

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let nodeManager: NodeManager | null = null;

const isDev = process.env.NODE_ENV === 'development';

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 800,
    minHeight: 600,
    titleBarStyle: 'hiddenInset',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
  }

  mainWindow.on('close', (event) => {
    // Minimize to tray instead of closing
    if (process.platform === 'darwin') {
      event.preventDefault();
      mainWindow?.hide();
    }
  });
}

async function startNode() {
  const nodePath = isDev
    ? path.join(__dirname, '../../target/release/hegemon-node')
    : path.join(process.resourcesPath, 'bin/hegemon-node');

  const dataDir = path.join(app.getPath('userData'), 'chain-data');
  
  nodeManager = new NodeManager({
    binaryPath: nodePath,
    dataDir,
    rpcPort: 9944,
    p2pPort: 30333,
    chain: 'mainnet', // or 'testnet'
  });

  await nodeManager.start();
  
  // Forward node logs to renderer
  nodeManager.on('log', (line) => {
    mainWindow?.webContents.send('node:log', line);
  });

  nodeManager.on('block', (blockNum) => {
    mainWindow?.webContents.send('node:block', blockNum);
  });
}

app.whenReady().then(async () => {
  await startNode();
  await createWindow();
  setupIpcHandlers(ipcMain, nodeManager!);
  setupTray();
});

app.on('before-quit', async () => {
  if (nodeManager) {
    await nodeManager.stop();
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

function setupTray() {
  const iconPath = path.join(__dirname, '../resources/tray-icon.png');
  tray = new Tray(iconPath);
  
  const contextMenu = Menu.buildFromTemplate([
    { label: 'Open Hegemon', click: () => mainWindow?.show() },
    { type: 'separator' },
    { label: 'Start Mining', click: () => nodeManager?.startMining() },
    { label: 'Stop Mining', click: () => nodeManager?.stopMining() },
    { type: 'separator' },
    { label: 'Quit', click: () => app.quit() },
  ]);
  
  tray.setContextMenu(contextMenu);
  tray.setToolTip('Hegemon Node Running');
}
```

**Verification**:
- [ ] App starts with tray icon
- [ ] Tray menu works for mining control
- [ ] Window hides to tray on macOS

---

## Phase E6: Platform Builds (Week 2-3)

**Goal**: Build and test installers for all platforms.

**Commands**:
```bash
# Build dashboard for Electron
cd dashboard-ui
npm run build
cp -r dist ../electron/renderer

# Build Electron app
cd ../electron
npm run build

# Package for current platform
npm run package

# Package for all platforms (requires CI)
npm run package:all
```

**Distribution Sizes (Estimated)**:
| Platform | Size |
|----------|------|
| macOS (universal) | ~120 MB |
| Windows | ~90 MB |
| Linux AppImage | ~100 MB |

**Verification**:
- [ ] macOS: .dmg installs and runs
- [ ] Windows: .exe installer works
- [ ] Linux: AppImage runs without issues
- [ ] All platforms: Node syncs and mines

---

## Phase E7: Code Signing (Week 3)

**Goal**: Sign and notarize builds for distribution.

**macOS Notarization** (`electron/scripts/notarize.js`):
```javascript
const { notarize } = require('@electron/notarize');

exports.default = async function notarizing(context) {
  const { electronPlatformName, appOutDir } = context;
  if (electronPlatformName !== 'darwin') return;

  const appName = context.packager.appInfo.productFilename;
  
  return await notarize({
    appBundleId: 'network.hegemon.desktop',
    appPath: `${appOutDir}/${appName}.app`,
    appleId: process.env.APPLE_ID,
    appleIdPassword: process.env.APPLE_PASSWORD,
    teamId: process.env.APPLE_TEAM_ID,
  });
};
```

**Verification**:
- [ ] macOS: App passes Gatekeeper
- [ ] Windows: SmartScreen doesn't warn
- [ ] All: No security warnings on install

---

## Phase E8: Auto-Update (Week 3)

**Goal**: Implement automatic updates for desktop app.

**Dependencies**:
- electron-updater
- GitHub Releases or custom update server

**Verification**:
- [ ] App checks for updates on launch
- [ ] Update notification shown to user
- [ ] Update installs successfully

---

## Success Criteria

1. **Installation**: One-click install on all platforms
2. **User Experience**: No command-line required for basic usage
3. **Performance**: App launches in < 5 seconds
4. **Stability**: No crashes during normal operation
5. **Security**: Proper code signing, no security warnings

---

## Dependencies on Substrate Migration

| Substrate Phase | Electron Requirement |
|-----------------|---------------------|
| Phase 4 (RPC) | `hegemon_startMining`, `hegemon_stopMining` RPC methods |
| Phase 4 (RPC) | `hegemon_walletBalance`, `hegemon_sendTransaction` for embedded wallet |
| Phase 5 (Wallet) | Wallet must work headlessly when controlled via RPC |
| Phase 6 (Dashboard) | Build with `isElectron` detection; dual API support |
| Phase 8 (Testnet) | Provide testnet chain-spec bundled in Electron resources |

---

## Timeline

| Week | Phase | Deliverable |
|------|-------|-------------|
| 1 | E1-E2 | Project scaffold, Node manager |
| 1-2 | E3 | IPC handlers |
| 2 | E4-E5 | Dashboard integration, System tray |
| 2-3 | E6 | Platform builds |
| 3 | E7-E8 | Code signing, Auto-update |

**Total Duration**: 3 weeks (after Substrate migration complete)
