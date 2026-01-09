export type NodeSummary = {
  peers: number;
  isSyncing: boolean;
  bestBlock: string | null;
  bestNumber: number | null;
  mining: boolean;
  miningThreads?: number | null;
};

export type WalletBalance = {
  assetId: number;
  label: string;
  spendable: number;
  locked: number;
  total: number;
};

export type WalletPending = {
  id: string;
  txId: string;
  direction: string;
  address: string;
  memo?: string | null;
  amount: number;
  fee: number;
  status: string;
  confirmations: number;
  createdAt: string;
};

export type WalletNotes = {
  assetId: number;
  spendableCount: number;
  maxInputs: number;
  needsConsolidation: boolean;
  plan?: { txsNeeded: number; blocksNeeded: number } | null;
};

export type WalletStatus = {
  primaryAddress: string;
  lastSyncedHeight: number;
  balances: WalletBalance[];
  pending: WalletPending[];
  notes?: WalletNotes | null;
};

export type WalletSyncResult = {
  newHeight: number;
  commitments: number;
  ciphertexts: number;
  recovered: number;
  spent: number;
};

export type WalletSendResult = {
  txHash: string;
  recipients: Array<{ address: string; value: number; asset_id: number; memo?: string | null }>;
};

export type WalletDisclosureCreateResult = {
  version: number;
  chain: { genesis_hash: string } | { genesisHash?: string };
  claim: Record<string, unknown>;
  confirmation: Record<string, unknown>;
  proof: Record<string, unknown>;
  disclosed_memo?: string | null;
};

export type WalletDisclosureVerifyResult = {
  verified: boolean;
  recipient_address: string;
  value: number;
  asset_id: number;
  commitment: string;
  anchor: string;
  chain: string;
};

export type NodeStartOptions = {
  chainSpecPath?: string;
  dev?: boolean;
  tmp?: boolean;
  basePath?: string;
  rpcPort?: number;
  p2pPort?: number;
  minerAddress?: string;
  mineThreads?: number;
  seeds?: string;
};

export type WalletSendRequest = {
  storePath: string;
  passphrase: string;
  wsUrl: string;
  recipients: Array<{ address: string; value: number; asset_id: number; memo?: string | null }>;
  fee: number;
  autoConsolidate: boolean;
};
