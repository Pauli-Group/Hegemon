use std::time::Instant;

use consensus::types::{BalanceTag, Commitment, Transaction as ConsensusTransaction};
use protocol_versioning::VersionBinding;
use transaction_circuit::{hashing::Felt, proof::TransactionProof};

#[derive(Clone, Debug)]
pub struct ValidatedTransaction {
    pub id: [u8; 32],
    pub proof: TransactionProof,
    pub transaction: ConsensusTransaction,
    pub fee: u64,
    pub timestamp: Instant,
    pub commitments: Vec<Felt>,
    pub nullifiers: Vec<[u8; 32]>,
    pub ciphertexts: Vec<Vec<u8>>,
}

pub fn felt_to_bytes(value: Felt) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.as_int().to_be_bytes());
    out
}

pub fn balance_tag_bytes(tag: Felt) -> BalanceTag {
    felt_to_bytes(tag)
}

pub fn felt_vec_to_commitments(values: &[Felt]) -> Vec<Commitment> {
    values
        .iter()
        .filter(|value| value.as_int() != 0)
        .map(|value| felt_to_bytes(*value))
        .collect()
}

pub fn felt_vec_to_nullifiers(values: &[Felt]) -> Vec<[u8; 32]> {
    values
        .iter()
        .filter(|value| value.as_int() != 0)
        .map(|value| felt_to_bytes(*value))
        .collect()
}

pub fn proof_to_transaction(
    proof: &TransactionProof,
    version: VersionBinding,
    ciphertexts: Vec<Vec<u8>>,
) -> ConsensusTransaction {
    let commitments = felt_vec_to_commitments(&proof.public_inputs.commitments);
    let nullifiers = felt_vec_to_nullifiers(&proof.public_inputs.nullifiers);
    let balance_tag = balance_tag_bytes(proof.public_inputs.balance_tag);
    ConsensusTransaction::new(nullifiers, commitments, balance_tag, version, ciphertexts)
}
