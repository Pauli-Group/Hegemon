use consensus::header::{BlockHeader, PowSeal};
use consensus::types::{CoinbaseData, CoinbaseSource, ConsensusBlock, DaParams, Transaction};
use protocol_versioning::VersionBinding;
use serde::{Deserialize, Serialize};

use crate::error::{NodeError, NodeResult};

#[derive(Serialize, Deserialize)]
struct StoredBlock {
    header: StoredHeader,
    transactions: Vec<StoredTransaction>,
    coinbase: Option<StoredCoinbase>,
}

#[derive(Serialize, Deserialize)]
struct StoredHeader {
    version: u32,
    height: u64,
    view: u64,
    timestamp_ms: u64,
    parent_hash: [u8; 32],
    state_root: [u8; 48],
    nullifier_root: [u8; 48],
    proof_commitment: Vec<u8>,
    da_root: [u8; 48],
    da_chunk_size: u32,
    da_sample_count: u32,
    version_commitment: [u8; 48],
    tx_count: u32,
    fee_commitment: [u8; 48],
    supply_digest: u128,
    validator_set_commitment: [u8; 48],
    signature_aggregate: Vec<u8>,
    signature_bitmap: Option<Vec<u8>>,
    pow: Option<StoredPowSeal>,
}

#[derive(Serialize, Deserialize)]
struct StoredPowSeal {
    nonce: [u8; 32],
    pow_bits: u32,
}

#[derive(Serialize, Deserialize)]
struct StoredTransaction {
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    balance_tag: [u8; 48],
    version_circuit: u16,
    version_crypto: u16,
    ciphertexts: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct StoredCoinbase {
    minted: u64,
    fees: i64,
    burns: u64,
    source: StoredCoinbaseSource,
}

#[derive(Serialize, Deserialize)]
enum StoredCoinbaseSource {
    TransactionIndex(usize),
    BalanceTag([u8; 48]),
}

pub fn serialize_block(block: &ConsensusBlock) -> NodeResult<Vec<u8>> {
    let stored = StoredBlock::from(block);
    Ok(bincode::serialize(&stored)?)
}

pub fn deserialize_block(bytes: &[u8]) -> NodeResult<ConsensusBlock> {
    let stored: StoredBlock = bincode::deserialize(bytes)?;
    stored.into_block()
}

pub fn serialize_header(header: &BlockHeader) -> NodeResult<Vec<u8>> {
    let stored = StoredHeader::from(header);
    Ok(bincode::serialize(&stored)?)
}

pub fn deserialize_header(bytes: &[u8]) -> NodeResult<BlockHeader> {
    let stored: StoredHeader = bincode::deserialize(bytes)?;
    stored.into_header()
}

pub fn serialize_transaction(tx: &Transaction) -> NodeResult<Vec<u8>> {
    let stored = StoredTransaction::from(tx);
    Ok(bincode::serialize(&stored)?)
}

impl From<&ConsensusBlock> for StoredBlock {
    fn from(block: &ConsensusBlock) -> Self {
        let header = StoredHeader {
            version: block.header.version,
            height: block.header.height,
            view: block.header.view,
            timestamp_ms: block.header.timestamp_ms,
            parent_hash: block.header.parent_hash,
            state_root: block.header.state_root,
            nullifier_root: block.header.nullifier_root,
            proof_commitment: block.header.proof_commitment.to_vec(),
            da_root: block.header.da_root,
            da_chunk_size: block.header.da_params.chunk_size,
            da_sample_count: block.header.da_params.sample_count,
            version_commitment: block.header.version_commitment,
            tx_count: block.header.tx_count,
            fee_commitment: block.header.fee_commitment,
            supply_digest: block.header.supply_digest,
            validator_set_commitment: block.header.validator_set_commitment,
            signature_aggregate: block.header.signature_aggregate.clone(),
            signature_bitmap: block.header.signature_bitmap.clone(),
            pow: block.header.pow.as_ref().map(|seal| StoredPowSeal {
                nonce: seal.nonce,
                pow_bits: seal.pow_bits,
            }),
        };
        let transactions = block
            .transactions
            .iter()
            .map(|tx| StoredTransaction {
                nullifiers: tx.nullifiers.clone(),
                commitments: tx.commitments.clone(),
                balance_tag: tx.balance_tag,
                version_circuit: tx.version.circuit,
                version_crypto: tx.version.crypto,
                ciphertexts: tx.ciphertexts.clone(),
            })
            .collect();
        let coinbase = block.coinbase.as_ref().map(|cb| StoredCoinbase {
            minted: cb.minted,
            fees: cb.fees,
            burns: cb.burns,
            source: match cb.source {
                CoinbaseSource::TransactionIndex(idx) => {
                    StoredCoinbaseSource::TransactionIndex(idx)
                }
                CoinbaseSource::BalanceTag(tag) => StoredCoinbaseSource::BalanceTag(tag),
            },
        });
        Self {
            header,
            transactions,
            coinbase,
        }
    }
}

impl StoredBlock {
    fn into_block(self) -> NodeResult<ConsensusBlock> {
        let proof_commitment: [u8; 48] = self
            .header
            .proof_commitment
            .clone()
            .try_into()
            .map_err(|_| NodeError::Invalid("invalid proof commitment"))?;
        let header = BlockHeader {
            version: self.header.version,
            height: self.header.height,
            view: self.header.view,
            timestamp_ms: self.header.timestamp_ms,
            parent_hash: self.header.parent_hash,
            state_root: self.header.state_root,
            nullifier_root: self.header.nullifier_root,
            proof_commitment,
            da_root: self.header.da_root,
            da_params: DaParams {
                chunk_size: self.header.da_chunk_size,
                sample_count: self.header.da_sample_count,
            },
            version_commitment: self.header.version_commitment,
            tx_count: self.header.tx_count,
            fee_commitment: self.header.fee_commitment,
            supply_digest: self.header.supply_digest,
            validator_set_commitment: self.header.validator_set_commitment,
            signature_aggregate: self.header.signature_aggregate,
            signature_bitmap: self.header.signature_bitmap,
            pow: self.header.pow.map(|seal| PowSeal {
                nonce: seal.nonce,
                pow_bits: seal.pow_bits,
            }),
        };
        let transactions = self
            .transactions
            .into_iter()
            .map(|stored| {
                let version = VersionBinding::new(stored.version_circuit, stored.version_crypto);
                Transaction::new(
                    stored.nullifiers,
                    stored.commitments,
                    stored.balance_tag,
                    version,
                    stored.ciphertexts,
                )
            })
            .collect();
        let coinbase = self.coinbase.map(|cb| CoinbaseData {
            minted: cb.minted,
            fees: cb.fees,
            burns: cb.burns,
            source: match cb.source {
                StoredCoinbaseSource::TransactionIndex(idx) => {
                    CoinbaseSource::TransactionIndex(idx)
                }
                StoredCoinbaseSource::BalanceTag(tag) => CoinbaseSource::BalanceTag(tag),
            },
        });
        Ok(ConsensusBlock {
            header,
            transactions,
            coinbase,
            commitment_proof: None,
            transaction_proofs: None,
        })
    }
}

impl From<&BlockHeader> for StoredHeader {
    fn from(header: &BlockHeader) -> Self {
        Self {
            version: header.version,
            height: header.height,
            view: header.view,
            timestamp_ms: header.timestamp_ms,
            parent_hash: header.parent_hash,
            state_root: header.state_root,
            nullifier_root: header.nullifier_root,
            proof_commitment: header.proof_commitment.to_vec(),
            da_root: header.da_root,
            da_chunk_size: header.da_params.chunk_size,
            da_sample_count: header.da_params.sample_count,
            version_commitment: header.version_commitment,
            tx_count: header.tx_count,
            fee_commitment: header.fee_commitment,
            supply_digest: header.supply_digest,
            validator_set_commitment: header.validator_set_commitment,
            signature_aggregate: header.signature_aggregate.clone(),
            signature_bitmap: header.signature_bitmap.clone(),
            pow: header.pow.as_ref().map(|seal| StoredPowSeal {
                nonce: seal.nonce,
                pow_bits: seal.pow_bits,
            }),
        }
    }
}

impl StoredHeader {
    fn into_header(self) -> NodeResult<BlockHeader> {
        let proof_commitment: [u8; 48] = self
            .proof_commitment
            .clone()
            .try_into()
            .map_err(|_| NodeError::Invalid("invalid proof commitment"))?;
        Ok(BlockHeader {
            version: self.version,
            height: self.height,
            view: self.view,
            timestamp_ms: self.timestamp_ms,
            parent_hash: self.parent_hash,
            state_root: self.state_root,
            nullifier_root: self.nullifier_root,
            proof_commitment,
            da_root: self.da_root,
            da_params: DaParams {
                chunk_size: self.da_chunk_size,
                sample_count: self.da_sample_count,
            },
            version_commitment: self.version_commitment,
            tx_count: self.tx_count,
            fee_commitment: self.fee_commitment,
            supply_digest: self.supply_digest,
            validator_set_commitment: self.validator_set_commitment,
            signature_aggregate: self.signature_aggregate,
            signature_bitmap: self.signature_bitmap,
            pow: self.pow.map(|seal| PowSeal {
                nonce: seal.nonce,
                pow_bits: seal.pow_bits,
            }),
        })
    }
}

impl From<&Transaction> for StoredTransaction {
    fn from(tx: &Transaction) -> Self {
        Self {
            nullifiers: tx.nullifiers.clone(),
            commitments: tx.commitments.clone(),
            balance_tag: tx.balance_tag,
            version_circuit: tx.version.circuit,
            version_crypto: tx.version.crypto,
            ciphertexts: tx.ciphertexts.clone(),
        }
    }
}
