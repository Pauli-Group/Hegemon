import type {
  NodeStartOptions,
  NodeSummary,
  WalletDisclosureCreateResult,
  WalletDisclosureVerifyResult,
  WalletSendRequest,
  WalletSendResult,
  WalletStatus,
  WalletSyncResult
} from './types';

export type HegemonApi = {
  node: {
    start: (options: NodeStartOptions) => Promise<void>;
    stop: () => Promise<void>;
    summary: () => Promise<NodeSummary>;
    setMining: (enabled: boolean, threads?: number) => Promise<void>;
    logs: () => Promise<string[]>;
  };
  wallet: {
    init: (storePath: string, passphrase: string) => Promise<WalletStatus>;
    restore: (storePath: string, passphrase: string) => Promise<WalletStatus>;
    status: (storePath: string, passphrase: string, noSync?: boolean) => Promise<WalletStatus>;
    sync: (storePath: string, passphrase: string, wsUrl: string, forceRescan?: boolean) => Promise<WalletSyncResult>;
    send: (request: WalletSendRequest) => Promise<WalletSendResult>;
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
  };
};

declare global {
  interface Window {
    hegemon: HegemonApi;
  }
}
