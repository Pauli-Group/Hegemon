export type NodeConnectionMode = 'local' | 'remote';

export type NodeConnection = {
  id: string;
  label: string;
  mode: NodeConnectionMode;
  wsUrl: string;
  httpUrl?: string;
  chainSpecPath?: string;
  dev?: boolean;
  tmp?: boolean;
  basePath?: string;
  rpcPort?: number;
  p2pPort?: number;
  listenAddr?: string;
  seeds?: string;
  minerAddress?: string;
  mineThreads?: number;
  miningIntent?: boolean;
  allowRemoteMining?: boolean;
  rpcExternal?: boolean;
  rpcMethods?: 'safe' | 'unsafe';
  nodeName?: string;
};

export type NodeStorageFootprint = {
  totalBytes: number;
  blocksBytes: number;
  stateBytes: number;
  transactionsBytes: number;
  nullifiersBytes: number;
};

export type NodeTelemetry = {
  uptimeSecs: number;
  txCount: number;
  blocksImported: number;
  blocksMined: number;
  memoryBytes: number;
  networkRxBytes: number;
  networkTxBytes: number;
};

export type NodeSummary = {
  connectionId: string;
  label: string;
  reachable: boolean;
  isLocal: boolean;
  peers: number | null;
  isSyncing: boolean | null;
  bestBlock: string | null;
  bestNumber: number | null;
  genesisHash: string | null;
  mining: boolean | null;
  miningThreads: number | null;
  hashRate: number | null;
  blocksFound: number | null;
  difficulty: number | null;
  blockHeight: number | null;
  supplyDigest: string | null;
  storage: NodeStorageFootprint | null;
  telemetry: NodeTelemetry | null;
  updatedAt: string;
  error?: string | null;
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
  protocolVersion?: number;
  capabilities?: {
    disclosure: boolean;
    autoConsolidate: boolean;
    notesSummary: boolean;
    errorCodes: boolean;
  };
  walletMode?: 'full' | 'watch_only';
  storePath?: string;
  primaryAddress: string;
  lastSyncedHeight: number;
  balances: WalletBalance[];
  pending: WalletPending[];
  notes?: WalletNotes | null;
  genesisHash?: string | null;
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
  connectionId?: string;
  chainSpecPath?: string;
  dev?: boolean;
  tmp?: boolean;
  basePath?: string;
  rpcPort?: number;
  p2pPort?: number;
  listenAddr?: string;
  minerAddress?: string;
  mineThreads?: number;
  mineOnStart?: boolean;
  seeds?: string;
  rpcExternal?: boolean;
  rpcMethods?: 'safe' | 'unsafe';
  nodeName?: string;
};

export type NodeSummaryRequest = {
  connectionId: string;
  label: string;
  isLocal: boolean;
  httpUrl: string;
};

export type NodeMiningRequest = {
  enabled: boolean;
  threads?: number;
  httpUrl?: string;
};

export type WalletSendRequest = {
  storePath: string;
  passphrase: string;
  wsUrl: string;
  recipients: Array<{ address: string; value: number; asset_id: number; memo?: string | null }>;
  fee: number;
  autoConsolidate: boolean;
};
