/**
 * Hegemon Custom Types Bundle
 * 
 * These types are required for @polkadot/api to decode Hegemon-specific
 * SCALE-encoded data. See docs/POLKADOTJS_BINDINGS.md for full documentation.
 */

export const typesBundle = {
  spec: {
    'synthetic-hegemonic': {
      types: [
        {
          minmax: [0, undefined] as [number, undefined],
          types: {
            StarkHashFunction: { _enum: ['Blake3', 'Sha3'] },
            StarkVerifierParams: {
              hash: 'StarkHashFunction',
              fri_queries: 'u16',
              blowup_factor: 'u8',
              security_bits: 'u16'
            },
            NettingKind: { _enum: ['Bilateral', 'Multilateral'] },
            Leg: { 
              from: 'AccountId', 
              to: 'AccountId', 
              asset: 'u32', 
              amount: 'u128' 
            },
            Instruction: {
              id: 'u64',
              legs: 'Vec<Leg>',
              netting: 'NettingKind',
              memo: 'Bytes',
              submitted_at: 'u64'
            },
            BatchCommitment: {
              id: 'u64',
              instructions: 'Vec<u64>',
              commitment: 'H256',
              nullifiers: 'Vec<H256>',
              proof: 'Bytes',
              submitted_by: 'AccountId',
              disputed: 'bool'
            },
            SubmissionRules: { 
              min_interval: 'u64', 
              max_size: 'u32' 
            },
            CommitmentRecord: {
              commitment: 'Bytes',
              attestation: 'Option<u32>',
              submitted_by: 'AccountId',
              submitted_at: 'u64'
            },
            FeedDetails: {
              owner: 'AccountId',
              name: 'Bytes',
              endpoint: 'Bytes',
              rules: 'SubmissionRules',
              latest_commitment: 'Option<CommitmentRecord>',
              last_ingestion: 'u64'
            }
          }
        }
      ]
    }
  }
};

/**
 * Block information for display
 */
export interface BlockInfo {
  number: number;
  hash: string;
  parentHash: string;
  timestamp: number;
  extrinsicCount: number;
}

/**
 * Shielded pool event
 */
export interface ShieldedEvent {
  block: number;
  eventIndex: number;
  method: 'CoinbaseMinted' | 'MerkleRootUpdated' | string;
  data: Record<string, unknown>;
}

/**
 * Mining statistics
 */
export interface MiningStats {
  difficulty: bigint;
  difficultyBits: number;
  avgBlockTime: number;
  lastRetargetBlock: number;
}

/**
 * Shielded pool status
 */
export interface ShieldedPoolStatus {
  merkleRoot: string;
  treeSize: number;
  nullifierCount: number;
  poolBalance: bigint;
}

/**
 * Post-quantum cryptography status
 */
export interface PQStatus {
  signatureScheme: 'ML-DSA-65' | 'ML-DSA-87' | 'SLH-DSA';
  kemScheme: 'ML-KEM-768' | 'ML-KEM-1024';
  starkParams: {
    hash: 'Blake3' | 'Sha3';
    friQueries: number;
    blowupFactor: number;
    securityBits: number;
  } | null;
}
