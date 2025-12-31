use crate::error::ConsensusError;
use crate::types::{
    BlockHash, DaParams, DaRoot, FeeCommitment, RecursiveProofHash, StarkCommitment, SupplyDigest,
    ValidatorSetCommitment, VersionCommitment,
};
use crypto::hashes::sha256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub view: u64,
    pub timestamp_ms: u64,
    pub parent_hash: BlockHash,
    pub state_root: BlockHash,
    pub nullifier_root: BlockHash,
    pub proof_commitment: StarkCommitment,
    pub recursive_proof_hash: RecursiveProofHash,
    pub da_root: DaRoot,
    pub da_params: DaParams,
    pub version_commitment: VersionCommitment,
    pub tx_count: u32,
    pub fee_commitment: FeeCommitment,
    pub supply_digest: SupplyDigest,
    pub validator_set_commitment: ValidatorSetCommitment,
    pub signature_aggregate: Vec<u8>,
    pub signature_bitmap: Option<Vec<u8>>,
    pub pow: Option<PowSeal>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowSeal {
    pub nonce: [u8; 32],
    pub pow_bits: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsensusMode {
    Bft,
    Pow,
}

impl BlockHeader {
    pub fn mode(&self) -> ConsensusMode {
        if self.pow.is_some() {
            ConsensusMode::Pow
        } else {
            ConsensusMode::Bft
        }
    }

    pub fn signing_hash(&self) -> Result<BlockHash, ConsensusError> {
        let mut data = Vec::new();
        data.extend_from_slice(b"block");
        data.extend(encode_signing_fields(self));
        Ok(sha256(&data))
    }

    pub fn hash(&self) -> Result<BlockHash, ConsensusError> {
        Ok(sha256(&encode_full_header(self)))
    }

    pub fn ensure_structure(&self) -> Result<(), ConsensusError> {
        match self.mode() {
            ConsensusMode::Bft => {
                if self
                    .signature_bitmap
                    .as_ref()
                    .is_none_or(|bm| bm.is_empty())
                {
                    return Err(ConsensusError::InvalidHeader("missing signature bitmap"));
                }
            }
            ConsensusMode::Pow => {
                if let Some(seal) = &self.pow {
                    if seal.pow_bits == 0 {
                        return Err(ConsensusError::InvalidHeader("pow bits missing"));
                    }
                } else {
                    return Err(ConsensusError::InvalidHeader("pow seal missing"));
                }
            }
        }
        Ok(())
    }
}

fn encode_signing_fields(header: &BlockHeader) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 8 * 3 + 32 * 8);
    data.extend_from_slice(&header.version.to_le_bytes());
    data.extend_from_slice(&header.height.to_le_bytes());
    data.extend_from_slice(&header.view.to_le_bytes());
    data.extend_from_slice(&header.timestamp_ms.to_le_bytes());
    data.extend_from_slice(&header.parent_hash);
    data.extend_from_slice(&header.state_root);
    data.extend_from_slice(&header.nullifier_root);
    data.extend_from_slice(&header.proof_commitment);
    data.extend_from_slice(&header.recursive_proof_hash);
    data.extend_from_slice(&header.da_root);
    data.extend_from_slice(&header.da_params.chunk_size.to_le_bytes());
    data.extend_from_slice(&header.da_params.sample_count.to_le_bytes());
    data.extend_from_slice(&header.version_commitment);
    data.extend_from_slice(&header.tx_count.to_le_bytes());
    data.extend_from_slice(&header.fee_commitment);
    data.extend_from_slice(&header.supply_digest.to_le_bytes());
    data.extend_from_slice(&header.validator_set_commitment);
    data
}

fn encode_full_header(header: &BlockHeader) -> Vec<u8> {
    let mut data = encode_signing_fields(header);
    data.extend_from_slice(&(header.signature_aggregate.len() as u32).to_le_bytes());
    data.extend_from_slice(&header.signature_aggregate);
    match &header.signature_bitmap {
        Some(bitmap) => {
            data.push(1);
            data.extend_from_slice(&(bitmap.len() as u32).to_le_bytes());
            data.extend_from_slice(bitmap);
        }
        None => data.push(0),
    }
    match &header.pow {
        Some(seal) => {
            data.push(1);
            data.extend_from_slice(&seal.nonce);
            data.extend_from_slice(&seal.pow_bits.to_le_bytes());
        }
        None => data.push(0),
    }
    data
}
