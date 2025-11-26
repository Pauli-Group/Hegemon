/**
 * Custom type definitions for Hegemon Substrate runtime.
 * These types extend @polkadot/api for our custom pallets.
 */

import type { RegistryTypes } from '@polkadot/types/types';

/**
 * Hegemon custom SCALE types for Polkadot.js
 */
export const hegemonTypes: RegistryTypes = {
  // STARK Verifier parameters
  StarkHashFunction: {
    _enum: ['Blake3', 'Sha3'],
  },
  StarkVerifierParams: {
    hash: 'StarkHashFunction',
    fri_queries: 'u16',
    blowup_factor: 'u8',
    security_bits: 'u16',
  },

  // Settlement types
  NettingKind: {
    _enum: ['Bilateral', 'Multilateral'],
  },
  Leg: {
    from: 'AccountId',
    to: 'AccountId',
    asset: 'u32',
    amount: 'u128',
  },
  Instruction: {
    id: 'u64',
    legs: 'Vec<Leg>',
    netting: 'NettingKind',
    memo: 'Bytes',
    submitted_at: 'u64',
  },
  BatchCommitment: {
    id: 'u64',
    instructions: 'Vec<u64>',
    commitment: 'H256',
    nullifiers: 'Vec<H256>',
    proof: 'Bytes',
    submitted_by: 'AccountId',
    disputed: 'bool',
  },

  // Oracle types
  SubmissionRules: {
    min_interval: 'u64',
    max_size: 'u32',
  },
  CommitmentRecord: {
    commitment: 'Bytes',
    attestation: 'Option<u32>',
    submitted_by: 'AccountId',
    submitted_at: 'u64',
  },
  FeedDetails: {
    owner: 'AccountId',
    name: 'Bytes',
    endpoint: 'Bytes',
    rules: 'SubmissionRules',
    latest_commitment: 'Option<CommitmentRecord>',
    last_ingestion: 'u64',
  },

  // PoW Consensus types
  PowSeal: {
    nonce: 'u64',
    difficulty: 'U256',
    work: 'H256',
  },

  // Identity types (PQ keys)
  PqPublicKey: {
    ml_dsa: 'Bytes', // ML-DSA-65 public key (1952 bytes)
    slh_dsa: 'Option<Bytes>', // SLH-DSA public key (optional)
  },
  IdentityInfo: {
    public_key: 'PqPublicKey',
    registered_at: 'u64',
    attestations: 'Vec<u32>',
  },

  // Mining status for RPC
  MiningStatus: {
    is_active: 'bool',
    threads: 'u32',
    hashrate: 'u64',
    blocks_found: 'u64',
    last_block_time: 'Option<u64>',
  },

  // Consensus status for RPC
  ConsensusStatus: {
    block_height: 'u64',
    best_hash: 'H256',
    finalized_height: 'u64',
    finalized_hash: 'H256',
    syncing: 'bool',
    peer_count: 'u32',
  },

  // Telemetry for RPC
  TelemetryInfo: {
    uptime_seconds: 'u64',
    tx_count: 'u64',
    memory_mb: 'u64',
    network_in_bytes: 'u64',
    network_out_bytes: 'u64',
  },

  // Wallet types for RPC
  WalletNotes: {
    tree_root: 'H256',
    leaf_count: 'u64',
    depth: 'u32',
  },
  WalletCommitment: {
    index: 'u64',
    commitment: 'H256',
    block_height: 'u64',
  },
};

/**
 * Polkadot.js types bundle configuration
 */
export const hegemonTypesBundle = {
  spec: {
    'synthetic-hegemonic': {
      types: [
        {
          minmax: [0, undefined] as [number, number | undefined],
          types: hegemonTypes,
        },
      ],
    },
  },
};

/**
 * RPC method definitions for custom hegemon_* endpoints
 */
export const hegemonRpcMethods = {
  hegemon: {
    miningStatus: {
      description: 'Get current mining status',
      params: [],
      type: 'MiningStatus',
    },
    startMining: {
      description: 'Start mining with specified thread count',
      params: [{ name: 'threads', type: 'u32' }],
      type: 'bool',
    },
    stopMining: {
      description: 'Stop mining',
      params: [],
      type: 'bool',
    },
    consensusStatus: {
      description: 'Get consensus/sync status',
      params: [],
      type: 'ConsensusStatus',
    },
    telemetry: {
      description: 'Get node telemetry',
      params: [],
      type: 'TelemetryInfo',
    },
    walletNotes: {
      description: 'Get wallet commitment tree status',
      params: [],
      type: 'WalletNotes',
    },
    walletCommitments: {
      description: 'Get paginated wallet commitments',
      params: [
        { name: 'offset', type: 'u64' },
        { name: 'limit', type: 'u32' },
      ],
      type: 'Vec<WalletCommitment>',
    },
    walletNullifiers: {
      description: 'Get spent nullifiers',
      params: [],
      type: 'Vec<H256>',
    },
    generateProof: {
      description: 'Generate a ZK transaction proof',
      params: [
        { name: 'inputs', type: 'Vec<H256>' },
        { name: 'outputs', type: 'Vec<H256>' },
        { name: 'amount', type: 'u128' },
      ],
      type: 'Bytes',
    },
    submitTransaction: {
      description: 'Submit a shielded transaction',
      params: [
        { name: 'proof', type: 'Bytes' },
        { name: 'nullifiers', type: 'Vec<H256>' },
        { name: 'commitments', type: 'Vec<H256>' },
        { name: 'ciphertexts', type: 'Vec<Bytes>' },
      ],
      type: 'H256',
    },
    latestBlock: {
      description: 'Get latest block info',
      params: [],
      type: 'Header',
    },
  },
};
