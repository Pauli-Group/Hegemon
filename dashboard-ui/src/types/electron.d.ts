/**
 * TypeScript declarations for Electron IPC bridge.
 * Used when dashboard-ui is running inside an Electron app.
 */

interface SystemHealth {
  peers: number;
  isSyncing: boolean;
  shouldHavePeers: boolean;
}

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

export {};
