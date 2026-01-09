import { contextBridge, ipcRenderer } from 'electron';
import type { NodeStartOptions, WalletSendRequest } from '../src/types';

contextBridge.exposeInMainWorld('hegemon', {
  node: {
    start: (options: NodeStartOptions) => ipcRenderer.invoke('node:start', options),
    stop: () => ipcRenderer.invoke('node:stop'),
    summary: () => ipcRenderer.invoke('node:summary'),
    setMining: (enabled: boolean, threads?: number) => ipcRenderer.invoke('node:setMining', enabled, threads),
    logs: () => ipcRenderer.invoke('node:logs')
  },
  wallet: {
    init: (storePath: string, passphrase: string) => ipcRenderer.invoke('wallet:init', storePath, passphrase),
    restore: (storePath: string, passphrase: string) => ipcRenderer.invoke('wallet:restore', storePath, passphrase),
    status: (storePath: string, passphrase: string, noSync?: boolean) =>
      ipcRenderer.invoke('wallet:status', storePath, passphrase, noSync),
    sync: (storePath: string, passphrase: string, wsUrl: string, forceRescan?: boolean) =>
      ipcRenderer.invoke('wallet:sync', storePath, passphrase, wsUrl, forceRescan),
    send: (request: WalletSendRequest) => ipcRenderer.invoke('wallet:send', request),
    disclosureCreate: (
      storePath: string,
      passphrase: string,
      wsUrl: string,
      txId: string,
      output: number
    ) => ipcRenderer.invoke('wallet:disclosureCreate', storePath, passphrase, wsUrl, txId, output),
    disclosureVerify: (
      storePath: string,
      passphrase: string,
      wsUrl: string,
      packageJson: object
    ) => ipcRenderer.invoke('wallet:disclosureVerify', storePath, passphrase, wsUrl, packageJson)
  }
});
