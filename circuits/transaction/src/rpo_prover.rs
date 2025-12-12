//! RPO‑Fiat‑Shamir transaction prover (recursion‑friendly).
//!
//! This is a drop‑in variant of `TransactionProverStark` that keeps the
//! same AIR and trace layout, but swaps Blake3 Fiat‑Shamir for RPO.
//! Proofs produced by this prover are meant to be verified inside
//! `StarkVerifierAir` for true recursion.

use miden_crypto::hash::rpo::Rpo256;
use miden_crypto::rand::RpoRandomCoin;
use winter_crypto::MerkleTree;
use winterfell::{
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo,
    TracePolyTable, TraceTable,
};

use crate::{
    constants::{MAX_INPUTS, MAX_OUTPUTS},
    stark_air::{
        commitment_output_row, merkle_root_output_row, nullifier_output_row, TransactionAirStark,
        TransactionPublicInputsStark, COL_S0, COL_VALUE,
    },
    stark_prover::{default_proof_options, fast_proof_options, TransactionProverStark},
    witness::TransactionWitness,
    TransactionCircuitError,
};

type RpoMerkleTree = MerkleTree<Rpo256>;

/// Transaction prover using RPO Fiat‑Shamir.
pub struct TransactionProverStarkRpo {
    options: ProofOptions,
}

impl TransactionProverStarkRpo {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn with_default_options() -> Self {
        Self::new(default_proof_options())
    }

    pub fn with_fast_options() -> Self {
        Self::new(fast_proof_options())
    }

    /// Build execution trace (identical to Blake3 prover).
    pub fn build_trace(
        &self,
        witness: &TransactionWitness,
    ) -> Result<TraceTable<BaseElement>, TransactionCircuitError> {
        TransactionProverStark::new(self.options.clone()).build_trace(witness)
    }

    /// Generate an RPO‑Fiat‑Shamir transaction proof.
    pub fn prove_transaction(
        &self,
        witness: &TransactionWitness,
    ) -> Result<Proof, TransactionCircuitError> {
        witness.validate()?;
        let trace = self.build_trace(witness)?;
        self.prove(trace)
            .map_err(|_| TransactionCircuitError::ConstraintViolation("STARK proving failed"))
    }
}

impl Prover for TransactionProverStarkRpo {
    type BaseField = BaseElement;
    type Air = TransactionAirStark;
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

    fn get_pub_inputs(&self, trace: &Self::Trace) -> TransactionPublicInputsStark {
        // Same deterministic read‑back as the Blake3 prover.
        let mut nullifiers = Vec::with_capacity(MAX_INPUTS);
        for i in 0..MAX_INPUTS {
            let row = nullifier_output_row(i);
            let nf = if row < trace.length() {
                let val = trace.get(COL_S0, row);
                let marker = trace.get(COL_VALUE, row);
                if marker == BaseElement::ZERO {
                    BaseElement::ZERO
                } else {
                    val
                }
            } else {
                BaseElement::ZERO
            };
            nullifiers.push(nf);
        }

        let mut commitments = Vec::with_capacity(MAX_OUTPUTS);
        for i in 0..MAX_OUTPUTS {
            let row = commitment_output_row(i);
            let cm = if row < trace.length() {
                let val = trace.get(COL_S0, row);
                let marker = trace.get(COL_VALUE, row);
                if marker == BaseElement::ZERO {
                    BaseElement::ZERO
                } else {
                    val
                }
            } else {
                BaseElement::ZERO
            };
            commitments.push(cm);
        }

        let merkle_root = if trace.length() > 0 {
            let row = merkle_root_output_row(0);
            if row < trace.length() {
                trace.get(COL_S0, row)
            } else {
                BaseElement::ZERO
            }
        } else {
            BaseElement::ZERO
        };

        TransactionPublicInputsStark {
            nullifiers,
            commitments,
            total_input: BaseElement::ZERO,
            total_output: BaseElement::ZERO,
            fee: BaseElement::ZERO,
            merkle_root,
        }
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
    use crate::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
    use crate::hashing::merkle_node;
    use crate::rpo_verifier::verify_transaction_proof_rpo;

    fn compute_merkle_root_from_path(
        leaf: BaseElement,
        position: u64,
        path: &MerklePath,
    ) -> BaseElement {
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

    fn make_test_witness() -> TransactionWitness {
        let input_note = NoteData {
            value: 1000,
            asset_id: 0,
            pk_recipient: [0u8; 32],
            rho: [1u8; 32],
            r: [2u8; 32],
        };

        let output_note = NoteData {
            value: 900,
            asset_id: 0,
            pk_recipient: [3u8; 32],
            rho: [4u8; 32],
            r: [5u8; 32],
        };

        let merkle_path = MerklePath::default();
        let leaf = input_note.commitment();
        let merkle_root = compute_merkle_root_from_path(leaf, 0, &merkle_path);

        TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position: 0,
                rho_seed: [9u8; 32],
                merkle_path,
            }],
            outputs: vec![OutputNoteWitness { note: output_note }],
            sk_spend: [7u8; 32],
            merkle_root,
            fee: 0,
            version: TransactionWitness::default_version_binding(),
        }
    }

    #[test]
    fn test_rpo_proofs_roundtrip() {
        let witness = make_test_witness();
        let prover = TransactionProverStarkRpo::with_fast_options();

        let trace = prover.build_trace(&witness).unwrap();
        let pub_inputs = <TransactionProverStarkRpo as Prover>::get_pub_inputs(&prover, &trace);
        let proof = prover.prove(trace).unwrap();

        assert!(verify_transaction_proof_rpo(&proof, &pub_inputs).is_ok());
    }

    #[test]
    fn test_rpo_proofs_reject_tampering() {
        let witness = make_test_witness();
        let prover = TransactionProverStarkRpo::with_fast_options();

        let trace = prover.build_trace(&witness).unwrap();
        let pub_inputs = <TransactionProverStarkRpo as Prover>::get_pub_inputs(&prover, &trace);
        let mut proof_bytes = prover.prove(trace).unwrap().to_bytes();

        // Flip one byte
        proof_bytes[10] ^= 0x01;
        let tampered = Proof::from_bytes(&proof_bytes).unwrap();

        assert!(verify_transaction_proof_rpo(&tampered, &pub_inputs).is_err());
    }
}
