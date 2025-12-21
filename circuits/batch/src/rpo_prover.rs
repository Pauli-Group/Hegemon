//! RPO‑Fiat‑Shamir batch transaction prover (recursion‑friendly).
//!
//! Keeps the same batch AIR and trace construction, but swaps Blake3
//! Fiat‑Shamir for RPO so that batch proofs can be verified in‑circuit.

use miden_crypto::hash::rpo::Rpo256;
use miden_crypto::rand::RpoRandomCoin;
use winter_crypto::MerkleTree;
use winterfell::{
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions,
    Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

use crate::{
    air::BatchTransactionAir,
    error::BatchCircuitError,
    prover::{default_batch_options, fast_batch_options, BatchTransactionProver},
    public_inputs::BatchPublicInputs,
};
use transaction_circuit::TransactionWitness;

type RpoMerkleTree = MerkleTree<Rpo256>;

/// Batch prover using RPO Fiat‑Shamir.
pub struct BatchTransactionProverRpo {
    options: ProofOptions,
    pub_inputs: Option<BatchPublicInputs>,
}

impl BatchTransactionProverRpo {
    pub fn new(options: ProofOptions) -> Self {
        Self {
            options,
            pub_inputs: None,
        }
    }

    pub fn with_default_options() -> Self {
        Self::new(default_batch_options())
    }

    pub fn with_fast_options() -> Self {
        Self::new(fast_batch_options())
    }

    pub fn build_trace(
        &self,
        witnesses: &[TransactionWitness],
    ) -> Result<TraceTable<BaseElement>, BatchCircuitError> {
        BatchTransactionProver::new(self.options.clone()).build_trace(witnesses)
    }

    pub fn extract_public_inputs(
        &self,
        witnesses: &[TransactionWitness],
    ) -> Result<BatchPublicInputs, BatchCircuitError> {
        BatchTransactionProver::new(self.options.clone()).extract_public_inputs(witnesses)
    }

    pub fn prove_batch(
        &mut self,
        witnesses: &[TransactionWitness],
    ) -> Result<(Proof, BatchPublicInputs), BatchCircuitError> {
        let trace = self.build_trace(witnesses)?;
        let pub_inputs = self.extract_public_inputs(witnesses)?;

        self.pub_inputs = Some(pub_inputs.clone());
        let proof = self
            .prove(trace)
            .map_err(|e| BatchCircuitError::ProofGenerationError(format!("{:?}", e)))?;
        self.pub_inputs = None;

        Ok((proof, pub_inputs))
    }
}

impl Prover for BatchTransactionProverRpo {
    type BaseField = BaseElement;
    type Air = BatchTransactionAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Rpo256;
    type VC = RpoMerkleTree;
    type RandomCoin = RpoRandomCoin;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> BatchPublicInputs {
        self.pub_inputs.clone().unwrap_or_default()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_trace_poly_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_trace_poly_columns,
            domain,
            partition_options,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpo_verifier::verify_batch_proof_rpo;
    use transaction_circuit::hashing::{felts_to_bytes32, merkle_node, HashFelt};
    use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};

    fn compute_merkle_root_from_path(leaf: HashFelt, position: u64, path: &MerklePath) -> HashFelt {
        let mut current = leaf;
        let mut pos = position;
        for sibling in &path.siblings {
            current = if pos & 1 == 0 {
                merkle_node(current, *sibling)
            } else {
                merkle_node(*sibling, current)
            };
            pos >>= 1;
        }
        current
    }

    fn make_test_witness(
        tag: u8,
        merkle_root: [u8; 32],
        input_note: &NoteData,
    ) -> TransactionWitness {
        let input_note = input_note.clone();

        let output_note = NoteData {
            value: 900,
            asset_id: 0,
            pk_recipient: [tag.wrapping_add(3); 32],
            rho: [tag.wrapping_add(4); 32],
            r: [tag.wrapping_add(5); 32],
        };

        let merkle_path = MerklePath::default();

        TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position: 0,
                rho_seed: [tag.wrapping_add(9); 32],
                merkle_path,
            }],
            outputs: vec![OutputNoteWitness { note: output_note }],
            sk_spend: [tag.wrapping_add(7); 32],
            merkle_root,
            fee: 0,
            value_balance: 0,
            version: TransactionWitness::default_version_binding(),
        }
    }

    #[test]
    fn test_rpo_proofs_roundtrip() {
        // Shared anchor for all witnesses.
        let base_input = NoteData {
            value: 1000,
            asset_id: 0,
            pk_recipient: [0u8; 32],
            rho: [1u8; 32],
            r: [2u8; 32],
        };
        let leaf = base_input.commitment();
        let merkle_root = felts_to_bytes32(&compute_merkle_root_from_path(
            leaf,
            0,
            &MerklePath::default(),
        ));

        let witnesses = vec![
            make_test_witness(1, merkle_root, &base_input),
            make_test_witness(2, merkle_root, &base_input),
        ];

        let mut prover = BatchTransactionProverRpo::with_fast_options();
        let (proof, pub_inputs) = prover.prove_batch(&witnesses).unwrap();

        assert!(verify_batch_proof_rpo(&proof, &pub_inputs).is_ok());
    }

    #[test]
    fn test_rpo_proofs_reject_tampering() {
        let base_input = NoteData {
            value: 1000,
            asset_id: 0,
            pk_recipient: [0u8; 32],
            rho: [1u8; 32],
            r: [2u8; 32],
        };
        let leaf = base_input.commitment();
        let merkle_root = felts_to_bytes32(&compute_merkle_root_from_path(
            leaf,
            0,
            &MerklePath::default(),
        ));

        let witnesses = vec![
            make_test_witness(1, merkle_root, &base_input),
            make_test_witness(2, merkle_root, &base_input),
        ];

        let mut prover = BatchTransactionProverRpo::with_fast_options();
        let (proof, pub_inputs) = prover.prove_batch(&witnesses).unwrap();
        let mut bytes = proof.to_bytes();
        bytes[5] ^= 0x01;
        let tampered = Proof::from_bytes(&bytes);
        assert!(
            tampered
                .map(|p| verify_batch_proof_rpo(&p, &pub_inputs).is_err())
                .unwrap_or(true),
            "tampering should fail deserialization or verification"
        );
    }
}
