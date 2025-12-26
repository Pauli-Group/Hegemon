use std::time::Instant;

use consensus::types::{BalanceTag, Commitment, Transaction as ConsensusTransaction};
use protocol_versioning::VersionBinding;
use transaction_circuit::{
    hashing::{felt_to_bytes32, Felt},
    proof::TransactionProof,
};

#[derive(Clone, Debug)]
pub struct ValidatedTransaction {
    pub id: [u8; 32],
    pub proof: TransactionProof,
    pub transaction: ConsensusTransaction,
    pub fee: u64,
    pub timestamp: Instant,
    pub commitments: Vec<Commitment>,
    pub nullifiers: Vec<[u8; 32]>,
    pub ciphertexts: Vec<Vec<u8>>,
}

impl ValidatedTransaction {
    /// Estimate the transaction weight based on proof/ciphertext sizes and
    /// spent/created record counts. This aligns the mempool with the
    /// fee-per-weight model enforced at admission time.
    pub fn weight(&self) -> u64 {
        let proof_size = bincode::serialized_size(&self.proof).unwrap_or(0) as u64;
        let ciphertext_bytes: u64 = self.ciphertexts.iter().map(|ct| ct.len() as u64).sum();
        // Weight each nullifier/commitment slot so privacy-preserving spends
        // and outputs still pay for the state growth they cause.
        let record_weight = 64 * (self.nullifiers.len() as u64 + self.commitments.len() as u64);
        // A small base cost keeps zero-output transactions from being free.
        256 + proof_size + ciphertext_bytes + record_weight
    }
}

pub fn balance_tag_bytes(tag: Felt) -> BalanceTag {
    felt_to_bytes32(tag)
}

pub fn proof_to_transaction(
    proof: &TransactionProof,
    version: VersionBinding,
    ciphertexts: Vec<Vec<u8>>,
) -> ConsensusTransaction {
    let commitments: Vec<Commitment> = proof
        .public_inputs
        .commitments
        .iter()
        .copied()
        .filter(|value| *value != [0u8; 32])
        .collect();
    let nullifiers: Vec<[u8; 32]> = proof
        .public_inputs
        .nullifiers
        .iter()
        .copied()
        .filter(|value| *value != [0u8; 32])
        .collect();
    let balance_tag = balance_tag_bytes(proof.public_inputs.balance_tag);
    ConsensusTransaction::new(nullifiers, commitments, balance_tag, version, ciphertexts)
}
