use std::path::Path;

use consensus::types::ConsensusBlock;
use serde::{Deserialize, Serialize};
use sled::IVec;
use transaction_circuit::hashing::Felt;

use crate::codec::{deserialize_block, serialize_block};
use crate::error::NodeResult;

const META_KEY: &[u8] = b"meta";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChainMeta {
    pub best_hash: [u8; 32],
    pub height: u64,
    pub state_root: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub supply_digest: u128,
    pub pow_bits: u32,
}

#[derive(Debug)]
pub struct Storage {
    db: sled::Db,
    blocks: sled::Tree,
    meta: sled::Tree,
    notes: sled::Tree,
    nullifiers: sled::Tree,
    ciphertexts: sled::Tree,
}

#[derive(Debug, Clone, Copy)]
pub struct StorageStats {
    pub blocks: usize,
    pub notes: usize,
    pub nullifiers: usize,
    pub ciphertexts: usize,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> NodeResult<Self> {
        let db = sled::open(path)?;
        let blocks = db.open_tree("blocks")?;
        let meta = db.open_tree("meta")?;
        let notes = db.open_tree("notes")?;
        let nullifiers = db.open_tree("nullifiers")?;
        let ciphertexts = db.open_tree("ciphertexts")?;
        Ok(Self {
            db,
            blocks,
            meta,
            notes,
            nullifiers,
            ciphertexts,
        })
    }

    pub fn stats(&self) -> StorageStats {
        StorageStats {
            blocks: self.blocks.len(),
            notes: self.notes.len(),
            nullifiers: self.nullifiers.len(),
            ciphertexts: self.ciphertexts.len(),
        }
    }

    pub fn flush(&self) -> NodeResult<()> {
        self.db.flush()?;
        Ok(())
    }

    pub fn store_meta(&self, meta: &ChainMeta) -> NodeResult<()> {
        let bytes = bincode::serialize(meta)?;
        self.meta.insert(META_KEY, bytes)?;
        Ok(())
    }

    pub fn load_meta(&self) -> NodeResult<Option<ChainMeta>> {
        Ok(self
            .meta
            .get(META_KEY)?
            .map(|value| bincode::deserialize(&value))
            .transpose()?)
    }

    pub fn append_commitment(&self, index: u64, value: Felt) -> NodeResult<()> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&value.as_int().to_be_bytes());
        self.notes.insert(index_key(index), &bytes)?;
        Ok(())
    }

    pub fn append_ciphertext(&self, index: u64, bytes: &[u8]) -> NodeResult<()> {
        self.ciphertexts.insert(index_key(index), bytes)?;
        Ok(())
    }

    pub fn load_commitments(&self) -> NodeResult<Vec<Felt>> {
        let mut values = Vec::new();
        for entry in self.notes.iter() {
            let (_, bytes) = entry?;
            values.push(bytes_to_felt(&bytes));
        }
        Ok(values)
    }

    pub fn load_commitments_range(&self, start: u64, limit: usize) -> NodeResult<Vec<(u64, Felt)>> {
        let mut out = Vec::new();
        for entry in self.notes.range(index_key(start)..) {
            let (key, bytes) = entry?;
            let mut idx_bytes = [0u8; 8];
            idx_bytes.copy_from_slice(&key);
            let index = u64::from_be_bytes(idx_bytes);
            out.push((index, bytes_to_felt(&bytes)));
            if out.len() == limit {
                break;
            }
        }
        Ok(out)
    }

    pub fn load_ciphertexts(&self, start: u64, limit: usize) -> NodeResult<Vec<(u64, Vec<u8>)>> {
        let mut out = Vec::new();
        for entry in self.ciphertexts.range(index_key(start)..) {
            let (key, value) = entry?;
            let mut idx_bytes = [0u8; 8];
            idx_bytes.copy_from_slice(&key);
            let index = u64::from_be_bytes(idx_bytes);
            out.push((index, value.to_vec()));
            if out.len() == limit {
                break;
            }
        }
        Ok(out)
    }

    pub fn insert_block(&self, hash: [u8; 32], block: &ConsensusBlock) -> NodeResult<()> {
        let bytes = serialize_block(block)?;
        self.blocks.insert(hash, bytes)?;
        Ok(())
    }

    pub fn load_blocks(&self) -> NodeResult<Vec<ConsensusBlock>> {
        let mut blocks = Vec::new();
        for entry in self.blocks.iter() {
            let (_, bytes) = entry?;
            blocks.push(deserialize_block(&bytes)?);
        }
        Ok(blocks)
    }

    pub fn load_block(&self, hash: [u8; 32]) -> NodeResult<Option<ConsensusBlock>> {
        self
            .blocks
            .get(hash)?
            .map(|bytes| deserialize_block(&bytes))
            .transpose()
    }

    pub fn reset(&self) -> NodeResult<()> {
        self.blocks.clear()?;
        self.meta.clear()?;
        self.notes.clear()?;
        self.nullifiers.clear()?;
        self.ciphertexts.clear()?;
        self.flush()?;
        Ok(())
    }

    pub fn record_nullifiers(&self, nullifiers: &[[u8; 32]]) -> NodeResult<()> {
        for nf in nullifiers {
            self.nullifiers.insert(nf, IVec::from(&[1u8]))?;
        }
        Ok(())
    }

    pub fn load_nullifiers(&self) -> NodeResult<Vec<[u8; 32]>> {
        let mut out = Vec::new();
        for entry in self.nullifiers.iter() {
            let (key, _) = entry?;
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&key);
            out.push(buf);
        }
        Ok(out)
    }
}

fn bytes_to_felt(bytes: &IVec) -> Felt {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    Felt::new(u64::from_be_bytes(buf))
}

fn index_key(index: u64) -> [u8; 8] {
    index.to_be_bytes()
}
