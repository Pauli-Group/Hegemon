import type {
  NodeMiningRequest,
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
  WalletSyncResult
} from './types';

export type HegemonApi = {
  node: {
    start: (options: NodeStartOptions) => Promise<void>;
    stop: () => Promise<void>;
    summary: (request: NodeSummaryRequest) => Promise<NodeSummary>;
    setMining: (request: NodeMiningRequest) => Promise<void>;
    logs: () => Promise<string[]>;
  };
  wallet: {
    init: (storePath: string, passphrase: string) => Promise<WalletStatus>;
    restore: (storePath: string, passphrase: string) => Promise<WalletStatus>;
    status: (storePath: string, passphrase: string, noSync?: boolean) => Promise<WalletStatus>;
    sync: (storePath: string, passphrase: string, wsUrl: string, forceRescan?: boolean) => Promise<WalletSyncResult>;
    send: (request: WalletSendRequest) => Promise<WalletSendResult>;
    sendPlan: (request: WalletSendPlanRequest) => Promise<WalletSendPlanResult>;
    lock: () => Promise<void>;
    disclosureCreate: (
      storePath: string,
      passphrase: string,
      wsUrl: string,
      txId: string,
      output: number
    ) => Promise<WalletDisclosureCreateResult>;
    disclosureVerify: (
      storePath: string,
      passphrase: string,
      wsUrl: string,
      packageJson: object
    ) => Promise<WalletDisclosureVerifyResult>;
    disclosureList: (storePath: string, passphrase: string) => Promise<WalletDisclosureRecord[]>;
  };
  contacts: {
    list: () => Promise<Contact[] | null>;
    save: (contacts: Contact[]) => Promise<void>;
  };
};

declare global {
  interface Window {
    hegemon: HegemonApi;
  }
}
