import { contextBridge, ipcRenderer } from 'electron';
import type {
  Contact,
  NodeMiningRequest,
  NodeManagedStatus,
  NodeStartOptions,
  NodeSummaryRequest,
  WalletSendPlanRequest,
  WalletSendRequest
} from '../src/types';

contextBridge.exposeInMainWorld('hegemon', {
  node: {
    start: (options: NodeStartOptions) => ipcRenderer.invoke('node:start', options),
    stop: () => ipcRenderer.invoke('node:stop'),
    summary: (request: NodeSummaryRequest) => ipcRenderer.invoke('node:summary', request),
    setMining: (request: NodeMiningRequest) => ipcRenderer.invoke('node:setMining', request),
    logs: () => ipcRenderer.invoke('node:logs'),
    managedStatus: () => ipcRenderer.invoke('node:managedStatus') as Promise<NodeManagedStatus>
  },
  wallet: {
    init: (storePath: string, passphrase: string) => ipcRenderer.invoke('wallet:init', storePath, passphrase),
    restore: (storePath: string, passphrase: string) => ipcRenderer.invoke('wallet:restore', storePath, passphrase),
    status: (storePath: string, passphrase: string, noSync?: boolean) =>
      ipcRenderer.invoke('wallet:status', storePath, passphrase, noSync),
    sync: (storePath: string, passphrase: string, wsUrl: string, forceRescan?: boolean) =>
      ipcRenderer.invoke('wallet:sync', storePath, passphrase, wsUrl, forceRescan),
    send: (request: WalletSendRequest) => ipcRenderer.invoke('wallet:send', request),
    sendPlan: (request: WalletSendPlanRequest) => ipcRenderer.invoke('wallet:sendPlan', request),
    lock: () => ipcRenderer.invoke('wallet:lock'),
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
    ) => ipcRenderer.invoke('wallet:disclosureVerify', storePath, passphrase, wsUrl, packageJson),
    disclosureList: (storePath: string, passphrase: string) =>
      ipcRenderer.invoke('wallet:disclosureList', storePath, passphrase)
  },
  contacts: {
    list: () => ipcRenderer.invoke('contacts:list'),
    save: (contacts: Contact[]) => ipcRenderer.invoke('contacts:save', contacts)
  }
});
