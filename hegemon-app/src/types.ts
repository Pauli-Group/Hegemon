export type NodeConnectionMode = 'local' | 'remote';
export type NodeParticipationRole = 'full_node' | 'pooled_hasher' | 'authoring_pool' | 'private_prover';

export type NodeConnection = {
  id: string;
  label: string;
  mode: NodeConnectionMode;
  participationRole?: NodeParticipationRole;
  wsUrl: string;
  httpUrl?: string;
  operatorEndpoint?: string;
  workerName?: string;
  payoutAddress?: string;
  poolAuthToken?: string;
  poolShareBits?: number;
  chainSpecPath?: string;
  dev?: boolean;
  tmp?: boolean;
  basePath?: string;
  rpcPort?: number;
  p2pPort?: number;
  listenAddr?: string;
  seeds?: string;
  maxPeers?: number;
  minerAddress?: string;
  mineThreads?: number;
  miningIntent?: boolean;
  allowRemoteMining?: boolean;
  rpcExternal?: boolean;
  rpcMethods?: 'safe' | 'unsafe';
  rpcCorsAll?: boolean;
  nodeName?: string;
  ciphertextDaRetentionBlocks?: number;
  proofDaRetentionBlocks?: number;
  daStoreCapacity?: number;
};

export type DialogOpenOptions = {
  title?: string;
  defaultPath?: string;
  buttonLabel?: string;
  filters?: Array<{ name: string; extensions: string[] }>;
  properties?: Array<
    | 'openFile'
    | 'openDirectory'
    | 'multiSelections'
    | 'showHiddenFiles'
    | 'createDirectory'
    | 'promptToCreate'
  >;
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

export type NodeConfigSnapshot = {
  nodeName: string;
  chainSpecId: string;
  chainSpecName: string;
  chainType: string;
  basePath: string;
  p2pListenAddr: string;
  rpcListenAddr: string;
  rpcMethods: string;
  rpcExternal: boolean;
  bootstrapNodes: string[];
  pqVerbose: boolean;
  maxPeers: number;
};

export type NodeSummary = {
  connectionId: string;
  label: string;
  reachable: boolean;
  isLocal: boolean;
  nodeVersion: string | null;
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
  aggregationProofFormat: string | null;
  proverStageType: string | null;
  proverStageLevel: number | null;
  proverStageArity: number | null;
  proverReadyBundleAgeMs: number | null;
  blockHeight: number | null;
  supplyDigest: string | null;
  storage: NodeStorageFootprint | null;
  telemetry: NodeTelemetry | null;
  config: NodeConfigSnapshot | null;
  updatedAt: string;
  error?: string | null;
};

export type NodeManagedStatus = {
  managed: boolean;
  connectionId: string | null;
  pid: number | null;
  rpcPort: number | null;
};

export type PoolWorkerSnapshot = {
  workerName: string;
  acceptedShares: number;
  rejectedShares: number;
  blockCandidates: number;
  payoutFractionPpm: number;
  lastShareAtMs: number | null;
};

export type PoolStatus = {
  available: boolean;
  networkDifficulty: number | null;
  shareDifficulty: number | null;
  acceptedShares: number;
  rejectedShares: number;
  workerCount: number;
  workers: PoolWorkerSnapshot[];
};

export type PoolWork = {
  available: boolean;
  height: number | null;
  preHash: string | null;
  parentHash: string | null;
  networkDifficulty: number | null;
  shareDifficulty: number | null;
  reason: string | null;
};

export type PoolMinerStartRequest = {
  endpoint: string;
  workerName: string;
  authToken?: string;
  threads: number;
};

export type PoolMinerStatus = {
  running: boolean;
  endpoint: string | null;
  workerName: string | null;
  threads: number;
  currentHeight: number | null;
  acceptedShares: number;
  rejectedShares: number;
  blockCandidates: number;
  hashesComputed: number;
  hashRate: number;
  lastShareAtMs: number | null;
  pool: PoolStatus | null;
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

export type WalletNoteDetail = {
  assetId: number;
  value: number;
  memo?: string | null;
  address: string;
  diversifierIndex: number;
  position: number;
  ciphertextIndex: number;
  status: string;
  nullifier?: string | null;
  commitment: string;
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
  noteDetails?: WalletNoteDetail[] | null;
  genesisHash?: string | null;
};

export type WalletUnlockSession = {
  status: WalletStatus;
  unlockToken: string;
  expiresAt: number;
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

export type WalletDisclosureRecord = {
  txId: string;
  outputIndex: number;
  recipientAddress: string;
  value: number;
  assetId: number;
  memo?: string | null;
  commitment: string;
  createdAt: string;
};

export type Contact = {
  id: string;
  name: string;
  address: string;
  verified: boolean;
  notes?: string;
  lastUsed?: string;
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
  maxPeers?: number;
  rpcExternal?: boolean;
  rpcMethods?: 'safe' | 'unsafe';
  rpcCorsAll?: boolean;
  nodeName?: string;
  ciphertextDaRetentionBlocks?: number;
  proofDaRetentionBlocks?: number;
  daStoreCapacity?: number;
  poolShareBits?: number;
  poolAuthToken?: string;
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
  unlockToken: string;
  wsUrl: string;
  recipients: Array<{ address: string; value: number; asset_id: number; memo?: string | null }>;
  fee: number;
  autoConsolidate: boolean;
};

export type WalletSendPlanRequest = {
  storePath: string;
  unlockToken: string;
  recipients: Array<{ address: string; value: number; asset_id: number; memo?: string | null }>;
  fee: number;
};

export type WalletSendPlanResult = {
  assetId: number;
  totalNeeded: number;
  availableValue: number;
  walletNoteCount: number;
  selectedNoteCount: number;
  selectedValue: number;
  maxInputs: number;
  sufficientFunds: boolean;
  needsConsolidation: boolean;
  plan?: { txsNeeded: number; blocksNeeded: number } | null;
};
