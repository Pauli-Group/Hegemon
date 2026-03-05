import type {
  DialogOpenOptions,
  NodeMiningRequest,
  NodeManagedStatus,
  NodeStartOptions,
  NodeSummary,
  NodeSummaryRequest,
  Contact,
  WalletDisclosureCreateResult,
  WalletDisclosureRecord,
  WalletDisclosureVerifyResult,
  WalletSendRequest,
  WalletSendResult,
  WalletSendPlanRequest,
  WalletSendPlanResult,
  WalletStatus,
  WalletSyncResult,
  WalletUnlockSession
} from './types';

export type HegemonApi = {
  node: {
    start: (options: NodeStartOptions) => Promise<void>;
    stop: () => Promise<void>;
    summary: (request: NodeSummaryRequest) => Promise<NodeSummary>;
    setMining: (request: NodeMiningRequest) => Promise<void>;
    logs: () => Promise<string[]>;
    managedStatus: () => Promise<NodeManagedStatus>;
  };
  wallet: {
    init: (storePath: string, passphrase: string) => Promise<WalletUnlockSession>;
    restore: (storePath: string, passphrase: string) => Promise<WalletUnlockSession>;
    status: (storePath: string, unlockToken: string, noSync?: boolean) => Promise<WalletStatus>;
    sync: (
      storePath: string,
      unlockToken: string,
      wsUrl: string,
      forceRescan?: boolean
    ) => Promise<WalletSyncResult>;
    send: (request: WalletSendRequest) => Promise<WalletSendResult>;
    sendPlan: (request: WalletSendPlanRequest) => Promise<WalletSendPlanResult>;
    lock: () => Promise<void>;
    disclosureCreate: (
      storePath: string,
      unlockToken: string,
      wsUrl: string,
      txId: string,
      output: number
    ) => Promise<WalletDisclosureCreateResult>;
    disclosureVerify: (
      storePath: string,
      unlockToken: string,
      wsUrl: string,
      packageJson: object
    ) => Promise<WalletDisclosureVerifyResult>;
    disclosureList: (storePath: string, unlockToken: string) => Promise<WalletDisclosureRecord[]>;
  };
  contacts: {
    list: () => Promise<Contact[] | null>;
    save: (contacts: Contact[]) => Promise<void>;
  };
  dialog: {
    openPath: (options: DialogOpenOptions) => Promise<string | null>;
  };
};

declare global {
  interface Window {
    hegemon: HegemonApi;
  }
}

declare module '*.wav';
