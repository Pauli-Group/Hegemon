use crate::bft::ConsensusUpdate;
use crate::error::ConsensusError;
use crate::pow::PowConsensus;
use crate::proof_interface::ProofVerifier;
use crate::types::{
    ConsensusBlock, StarkCommitment, VersionCommitment, compute_proof_commitment,
    compute_version_commitment,
};

/// Describes the source of a block as it travels through the native import pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockOrigin {
    /// A block pulled from peers during initial sync.
    NetworkInitialSync,
    /// A block broadcast after sync.
    NetworkBroadcast,
    /// A block read from a local file or database snapshot.
    File,
    /// A block produced locally by the embedded miner.
    Own,
}

/// Receipt produced once the consensus rules admit a block into the local ledger.
#[derive(Clone, Debug)]
pub struct ImportReceipt {
    pub origin: BlockOrigin,
    pub update: ConsensusUpdate,
    pub proof_commitment: StarkCommitment,
    pub version_commitment: VersionCommitment,
}

/// Execute the full PoW ledger validation flow before a block is recorded.
pub fn import_pow_block<V: ProofVerifier>(
    consensus: &mut PowConsensus<V>,
    origin: BlockOrigin,
    block: ConsensusBlock,
) -> Result<ImportReceipt, ConsensusError> {
    let proof_commitment = compute_proof_commitment(&block.transactions);
    let version_commitment = compute_version_commitment(&block.transactions);
    let update = consensus.apply_block(block)?;
    Ok(ImportReceipt {
        origin,
        update,
        proof_commitment,
        version_commitment,
    })
}
