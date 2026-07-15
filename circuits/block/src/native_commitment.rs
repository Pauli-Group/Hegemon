use hegemon_field::Goldilocks;
use state_merkle::CommitmentTree;
use transaction_circuit::hashing_pq::{felts_to_bytes48, Commitment};
use transaction_circuit::TransactionProof;
use transaction_core::constants::{POSEIDON2_RATE, POSEIDON2_STEPS, POSEIDON2_WIDTH};
use transaction_core::poseidon2::poseidon2_step;

use crate::commitment_constants::BLOCK_COMMITMENT_DOMAIN_TAG;
use crate::error::BlockError;

const RETIRED_CYCLE_LENGTH: usize = 32;

/// Retired commitment-proof public inputs retained for wire compatibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentBlockPublicInputs {
    pub tx_statements_commitment: [Goldilocks; 6],
    pub starting_state_root: [Goldilocks; 6],
    pub ending_state_root: [Goldilocks; 6],
    pub starting_kernel_root: [Goldilocks; 6],
    pub ending_kernel_root: [Goldilocks; 6],
    pub nullifier_root: [Goldilocks; 6],
    pub da_root: [Goldilocks; 6],
    pub tx_count: u32,
    pub perm_alpha: Goldilocks,
    pub perm_beta: Goldilocks,
    pub nullifiers: Vec<[Goldilocks; 6]>,
    pub sorted_nullifiers: Vec<[Goldilocks; 6]>,
}

/// Retired wrapper retained so recursive blocks keep the exact empty-field
/// encoding used by existing storage and network messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentBlockProof {
    pub proof_bytes: Vec<u8>,
    pub proof_hash: Commitment,
    pub public_inputs: CommitmentBlockPublicInputs,
}

pub struct CommitmentBlockProver;

impl Default for CommitmentBlockProver {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentBlockProver {
    pub const fn new() -> Self {
        Self
    }

    pub fn prove_block_commitment(
        &self,
        _transactions: &[TransactionProof],
    ) -> Result<CommitmentBlockProof, BlockError> {
        retired()
    }

    pub fn prove_block_commitment_with_tree(
        &self,
        _tree: &mut CommitmentTree,
        _transactions: &[TransactionProof],
        _da_root: Commitment,
    ) -> Result<CommitmentBlockProof, BlockError> {
        retired()
    }

    pub fn prove_from_statement_hashes(
        &self,
        _statement_hashes: &[Commitment],
    ) -> Result<CommitmentBlockProof, BlockError> {
        retired()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove_from_statement_hashes_with_inputs(
        &self,
        _statement_hashes: &[Commitment],
        _starting_state_root: Commitment,
        _ending_state_root: Commitment,
        _starting_kernel_root: Commitment,
        _ending_kernel_root: Commitment,
        _nullifier_root: Commitment,
        _da_root: Commitment,
        _nullifiers: Vec<Commitment>,
        _sorted_nullifiers: Vec<Commitment>,
    ) -> Result<CommitmentBlockProof, BlockError> {
        retired()
    }

    /// Preserve the exact statement-commitment function used by the active
    /// recursive-block identity relation without retaining the retired proof.
    pub fn commitment_from_statement_hashes(
        statement_hashes: &[Commitment],
    ) -> Result<Commitment, BlockError> {
        if statement_hashes.is_empty() {
            return Err(BlockError::CommitmentProofEmptyBlock);
        }

        let mut inputs = hashes_to_fields(statement_hashes);
        let input_cycles = statement_hashes.len().max(1);
        let target_len = input_cycles * POSEIDON2_RATE;
        if inputs.len() < target_len {
            inputs.resize(target_len, Goldilocks::ZERO);
        }

        let trace_len = (input_cycles + 1).next_power_of_two() * RETIRED_CYCLE_LENGTH;
        let total_cycles = trace_len / RETIRED_CYCLE_LENGTH;
        let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
        state[0] = Goldilocks::new(BLOCK_COMMITMENT_DOMAIN_TAG) + inputs[0];
        state[1..POSEIDON2_RATE].copy_from_slice(&inputs[1..POSEIDON2_RATE]);
        state[POSEIDON2_WIDTH - 1] = Goldilocks::ONE;

        let mut output = [Goldilocks::ZERO; POSEIDON2_RATE];
        for cycle in 0..total_cycles {
            let next = if cycle + 1 < input_cycles {
                let start = (cycle + 1) * POSEIDON2_RATE;
                Some(&inputs[start..start + POSEIDON2_RATE])
            } else {
                None
            };

            for step in 0..RETIRED_CYCLE_LENGTH {
                if step + 1 == RETIRED_CYCLE_LENGTH && cycle + 1 == total_cycles {
                    output.copy_from_slice(&state[..POSEIDON2_RATE]);
                }
                if step < POSEIDON2_STEPS {
                    poseidon2_step(&mut state, step);
                } else if step + 1 == RETIRED_CYCLE_LENGTH {
                    for index in 0..POSEIDON2_RATE {
                        state[index] += next.map_or(Goldilocks::ZERO, |values| values[index]);
                    }
                }
            }
        }

        Ok(felts_to_bytes48(&output))
    }
}

pub fn verify_block_commitment(_proof: &CommitmentBlockProof) -> Result<(), BlockError> {
    retired()
}

fn retired<T>() -> Result<T, BlockError> {
    Err(BlockError::CommitmentProofVerification(
        "retired commitment proof backend is not executable".to_string(),
    ))
}

fn hashes_to_fields(hashes: &[Commitment]) -> Vec<Goldilocks> {
    let mut fields = Vec::with_capacity(hashes.len() * 6);
    for hash in hashes {
        for chunk in hash.chunks_exact(8) {
            fields.push(Goldilocks::new(u64::from_be_bytes(
                chunk.try_into().expect("8-byte commitment limb"),
            )));
        }
    }
    fields
}
