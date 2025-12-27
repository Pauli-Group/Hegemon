//! Recursive epoch prover using RPO-based STARK verification.
//!
//! This module provides a recursive prover that can:
//! 1. Generate epoch proofs using RPO hash for Fiat-Shamir
//! 2. Verify an inner STARK proof within the AIR circuit (proof-of-proof)
//!
//! ## Why RPO?
//!
//! Standard STARK provers use Blake3 or SHA256 for Fiat-Shamir challenges.
//! These hash functions are expensive in AIR (~100+ columns for bitwise ops).
//! RPO is algebraic: only ~13 columns (x^7 S-box + MDS mixing).
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │              RecursiveEpochProver                               │
//! │                                                                 │
//! │  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐    │
//! │  │ RPO Hash     │──▶│ Merkle Root  │──▶│ Epoch Commitment │    │
//! │  │ (in-circuit) │   │ Verification │   │                  │    │
//! │  └──────────────┘   └──────────────┘   └──────────────────┘    │
//! │                                                                 │
//! │  ┌──────────────────────────────────────────────────────────┐  │
//! │  │ Inner Proof Verification (StarkVerifierAir)               │  │
//! │  │  • Commit phase: hash trace/constraint commitments        │  │
//! │  │  • Query phase: verify Merkle paths with RPO              │  │
//! │  │  • FRI folding: verify polynomial decomposition           │  │
//! │  │  • Deep composition: combine evaluations algebraically    │  │
//! │  └──────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quantum Resistance
//!
//! This is pure STARKs - no elliptic curves. Security derives from:
//! - RPO collision resistance (algebraic hash, post-quantum)
//! - FRI soundness over Goldilocks field
//! - No reliance on discrete log or factoring

use miden_crypto::hash::rpo::Rpo256;
use miden_crypto::rand::RpoRandomCoin;
use miden_crypto::Word;
use winter_air::proof::{merge_ood_evaluations, Proof};
use winter_air::{Air, ConstraintCompositionCoefficients, DeepCompositionCoefficients};
use winter_crypto::{hashers::Blake3_256, Hasher, MerkleTree, RandomCoin};
use winter_fri::folding::fold_positions;
use winter_fri::utils::map_positions_to_indexes;
use winter_math::{fields::f64::BaseElement, FieldElement, ToElements};
use winterfell::{
    crypto::DefaultRandomCoin, verify, AcceptableOptions, BatchingMethod, FieldExtension,
    ProofOptions, Prover,
};

use super::rpo_air::STATE_WIDTH;
use super::rpo_proof::{rpo_hash_elements, rpo_merge, RpoProofOptions};
use super::rpo_stark_prover::{verify_epoch_with_rpo, RpoStarkProver};
use super::rpo_stark_verifier_prover::RpoStarkVerifierProver;
use super::stark_verifier_air::StarkVerifierAir;
use super::stark_verifier_air::StarkVerifierPublicInputs;
use super::stark_verifier_prover::StarkVerifierProver;
use crate::prover::EpochProverError;
use crate::types::Epoch;

const EPOCH_BATCH_TAG: u64 = u64::from_le_bytes(*b"EPOCHBAT");

/// Recursive epoch proof containing the STARK proof and verification metadata.
#[derive(Clone, Debug)]
pub struct RecursiveEpochProof {
    /// Serialized STARK proof bytes.
    ///
    /// - If `is_recursive == false`, this is the *inner* RPO-based proof (RpoAir).
    /// - If `is_recursive == true`, this is the *outer* recursive proof (StarkVerifierAir),
    ///   which verifies `inner_proof_bytes` in-circuit.
    pub proof_bytes: Vec<u8>,
    /// Serialized inner proof bytes (RPO-based), used as the recursion target when
    /// `is_recursive == true`.
    pub inner_proof_bytes: Vec<u8>,
    /// Epoch commitment (hash of epoch metadata).
    pub epoch_commitment: [u8; 32],
    /// Proof accumulator (RPO hash of all proof hashes).
    pub proof_accumulator: [BaseElement; 4],
    /// Number of proofs aggregated in this epoch.
    pub num_proofs: u32,
    /// Whether this proof is recursive (contains inner proof verification).
    pub is_recursive: bool,
}

impl RecursiveEpochProof {
    /// Check if this is a recursive proof (verifies inner proofs).
    pub fn is_recursive(&self) -> bool {
        self.is_recursive
    }

    /// Get the proof accumulator as bytes.
    pub fn accumulator_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, elem) in self.proof_accumulator.iter().enumerate() {
            let val = elem.inner();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
        }
        bytes
    }
}

/// A batched proof which commits to multiple epoch accumulators.
///
/// This is the "epochs → batched inner" stage for single-proof sync: we take `K` epoch
/// accumulators (each a 4-element RPO digest, serialized as 32 bytes) and merge them into a
/// single 4-element digest, then prove a small `RpoAir` STARK over that digest.
#[derive(Clone, Debug)]
pub struct EpochBatchProof {
    /// Serialized STARK proof bytes for an `RpoAir` proof.
    pub proof_bytes: Vec<u8>,
    /// The merged accumulator digest committed to by this proof.
    pub batch_accumulator: [BaseElement; 4],
    /// Inclusive epoch range covered by this batch (bound into the inner proof’s public inputs).
    pub epoch_start: u64,
    /// Inclusive epoch range covered by this batch (bound into the inner proof’s public inputs).
    pub epoch_end: u64,
    /// Number of epochs committed to by this batch.
    pub num_epochs: u32,
}

impl EpochBatchProof {
    pub fn epoch_range(&self) -> (u64, u64) {
        (self.epoch_start, self.epoch_end)
    }
}

/// Recursive epoch prover using RPO-based STARK verification.
///
/// This prover generates proofs where Fiat-Shamir challenges are derived
/// using RPO hash, enabling efficient in-circuit verification for recursion.
pub struct RecursiveEpochProver {
    options: RpoProofOptions,
}

impl Default for RecursiveEpochProver {
    fn default() -> Self {
        Self::new()
    }
}

impl RecursiveEpochProver {
    /// Create a new recursive epoch prover with default options.
    pub fn new() -> Self {
        Self {
            options: RpoProofOptions::default(),
        }
    }

    /// Create prover with fast (test) options.
    pub fn fast() -> Self {
        Self {
            options: RpoProofOptions::fast(),
        }
    }

    /// Create prover with production options.
    pub fn production() -> Self {
        Self {
            options: RpoProofOptions::production(),
        }
    }

    /// Generate a recursive epoch proof using real RPO-based STARK.
    ///
    /// This method:
    /// 1. Converts proof hashes to field elements
    /// 2. Computes the proof accumulator using RPO hash
    /// 3. Builds an RPO execution trace (the accumulator as input state)
    /// 4. Generates a STARK proof with RPO-based Fiat-Shamir
    ///
    /// # Arguments
    ///
    /// * `epoch` - Epoch metadata
    /// * `proof_hashes` - All transaction proof hashes in this epoch
    ///
    /// # Returns
    ///
    /// Recursive epoch proof on success.
    pub fn prove_epoch(
        &self,
        epoch: &Epoch,
        proof_hashes: &[[u8; 32]],
    ) -> Result<RecursiveEpochProof, EpochProverError> {
        if proof_hashes.is_empty() {
            return Err(EpochProverError::EmptyEpoch);
        }

        // Convert proof hashes to field elements and compute accumulator
        let proof_accumulator = self.compute_proof_accumulator(proof_hashes);

        // Generate real STARK proof using RpoStarkProver
        let proof_bytes = self.generate_real_stark_proof(&proof_accumulator)?;

        Ok(RecursiveEpochProof {
            inner_proof_bytes: proof_bytes.clone(),
            proof_bytes,
            epoch_commitment: epoch.commitment(),
            proof_accumulator,
            num_proofs: proof_hashes.len() as u32,
            is_recursive: false,
        })
    }

    /// Generate a batched inner proof which commits to `K` epoch accumulators.
    ///
    /// This is a depth-0 batch: it does **not** verify each epoch proof; it commits to the
    /// provided epoch accumulators by hashing them into a single digest and proving an `RpoAir`
    /// permutation over that digest.
    ///
    /// The intent is to feed these batched-inner proofs into an outer batch verifier proof
    /// (Phase 3b) so a light client can verify a constant number of proofs.
    pub fn prove_epoch_batch(
        &self,
        epoch_start: u64,
        epoch_end: u64,
        epoch_accumulators: &[[u8; 32]],
    ) -> Result<EpochBatchProof, EpochProverError> {
        if epoch_accumulators.is_empty() {
            return Err(EpochProverError::EmptyEpoch);
        }
        if epoch_end < epoch_start {
            return Err(EpochProverError::TraceBuildError(
                "epoch_end must be >= epoch_start".to_string(),
            ));
        }
        let expected = (epoch_end - epoch_start + 1) as usize;
        if epoch_accumulators.len() != expected {
            return Err(EpochProverError::TraceBuildError(format!(
                "epoch accumulator count mismatch: expected {expected}, got {}",
                epoch_accumulators.len()
            )));
        }

        let batch_accumulator = self.compute_proof_accumulator(epoch_accumulators);
        let input_state = build_epoch_batch_input_state(
            &batch_accumulator,
            epoch_start,
            epoch_end,
            epoch_accumulators.len() as u32,
        );
        let proof_bytes = self.generate_real_stark_proof_for_state(input_state)?;

        Ok(EpochBatchProof {
            proof_bytes,
            batch_accumulator,
            epoch_start,
            epoch_end,
            num_epochs: epoch_accumulators.len() as u32,
        })
    }

    /// Verify a batched inner proof (native verification of the contained `RpoAir` proof).
    pub fn verify_epoch_batch_proof(&self, proof: &EpochBatchProof) -> bool {
        if proof.proof_bytes.is_empty() {
            return false;
        }
        let input_state = build_epoch_batch_input_state(
            &proof.batch_accumulator,
            proof.epoch_start,
            proof.epoch_end,
            proof.num_epochs,
        );
        let inner_pub_inputs = self.build_rpo_pub_inputs_for_state(input_state);
        let stark_proof = match winterfell::Proof::from_bytes(&proof.proof_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        verify_epoch_with_rpo(&stark_proof, &inner_pub_inputs).is_ok()
    }

    /// Generate a recursive epoch proof (proof-of-proof) using StarkVerifierAir.
    ///
    /// This produces:
    /// 1) an inner RPO-based STARK proof (RpoAir) over the epoch accumulator
    /// 2) an outer STARK proof (StarkVerifierAir) which verifies the inner proof in-circuit
    ///
    /// Note: The outer proof currently uses Blake3 Fiat–Shamir (Winterfell default). This is
    /// sufficient for one-level recursion demonstrations and node-side recursive attestations,
    /// but not yet self-recursive.
    pub fn prove_epoch_recursive(
        &self,
        epoch: &Epoch,
        proof_hashes: &[[u8; 32]],
    ) -> Result<RecursiveEpochProof, EpochProverError> {
        let mut proof = self.prove_epoch(epoch, proof_hashes)?;

        // Reconstruct the inner public inputs from the accumulator (matches inner prover).
        let inner_pub_inputs = self.build_inner_pub_inputs(&proof.proof_accumulator);

        // Extract recursion witness data from the inner proof.
        let inner_data = InnerProofData::from_proof::<super::rpo_air::RpoAir>(
            &proof.inner_proof_bytes,
            inner_pub_inputs,
        )?;

        // Build outer public inputs for StarkVerifierAir.
        let outer_pub_inputs = inner_data.to_stark_verifier_inputs();

        // Generate outer proof verifying the inner proof in-circuit.
        let outer_options = self.options.to_winter_options();
        let outer_prover = StarkVerifierProver::new(outer_options, outer_pub_inputs);
        let outer_trace = outer_prover.build_trace_from_inner(&inner_data);
        let outer_proof = outer_prover
            .prove(outer_trace)
            .map_err(|e| EpochProverError::ProofGenerationError(format!("{e:?}")))?;

        proof.proof_bytes = outer_proof.to_bytes();
        proof.is_recursive = true;
        Ok(proof)
    }

    /// Generate a recursive epoch proof (proof-of-proof) with an **RPO-backed outer proof**.
    ///
    /// This matches `prove_epoch_recursive()` but switches the outer proof’s Fiat–Shamir and
    /// vector commitments to RPO so the resulting outer proof can itself be verified in-circuit.
    ///
    /// This is the Phase 3b.1 prerequisite for recursion depth 2+.
    pub fn prove_epoch_recursive_rpo_outer(
        &self,
        epoch: &Epoch,
        proof_hashes: &[[u8; 32]],
    ) -> Result<RecursiveEpochProof, EpochProverError> {
        let mut proof = self.prove_epoch(epoch, proof_hashes)?;

        let inner_pub_inputs = self.build_inner_pub_inputs(&proof.proof_accumulator);
        let inner_data = InnerProofData::from_proof::<super::rpo_air::RpoAir>(
            &proof.inner_proof_bytes,
            inner_pub_inputs,
        )?;
        let outer_pub_inputs = inner_data.to_stark_verifier_inputs();

        let outer_options = self.options.to_winter_options();
        let outer_prover = RpoStarkVerifierProver::new(outer_options, outer_pub_inputs);
        let outer_trace = outer_prover.build_trace_from_inner(&inner_data);
        let outer_proof = outer_prover
            .prove(outer_trace)
            .map_err(|e| EpochProverError::ProofGenerationError(format!("{e:?}")))?;

        proof.proof_bytes = outer_proof.to_bytes();
        proof.is_recursive = true;
        Ok(proof)
    }

    /// Compute proof accumulator using RPO hash.
    ///
    /// Hashes all proof hashes together into a 4-element digest.
    fn compute_proof_accumulator(&self, proof_hashes: &[[u8; 32]]) -> [BaseElement; 4] {
        let mut accumulator = [BaseElement::ZERO; 4];

        for hash in proof_hashes {
            // Convert hash to field elements
            let elements = hash_to_elements(hash);

            // Merge into accumulator using RPO
            accumulator = rpo_merge(&accumulator, &elements);
        }

        accumulator
    }

    /// Generate a real STARK proof for the accumulator.
    ///
    /// Uses RpoStarkProver to generate a proof of an RPO permutation
    /// over the accumulator (padded to STATE_WIDTH=12 elements).
    fn generate_real_stark_proof(
        &self,
        accumulator: &[BaseElement; 4],
    ) -> Result<Vec<u8>, EpochProverError> {
        // Pad accumulator to full RPO state width (12 elements).
        let mut input_state = [BaseElement::ZERO; STATE_WIDTH];
        input_state[..4].copy_from_slice(accumulator);
        self.generate_real_stark_proof_for_state(input_state)
    }

    fn generate_real_stark_proof_for_state(
        &self,
        input_state: [BaseElement; STATE_WIDTH],
    ) -> Result<Vec<u8>, EpochProverError> {
        // Create prover with our options
        let prover = RpoStarkProver::from_rpo_options(&self.options);

        // Generate proof
        let (proof, _pub_inputs) = prover
            .prove_rpo_permutation(input_state)
            .map_err(|e| EpochProverError::ProofGenerationError(e))?;

        // Serialize proof
        Ok(proof.to_bytes())
    }

    fn build_inner_pub_inputs(
        &self,
        accumulator: &[BaseElement; 4],
    ) -> super::rpo_air::RpoPublicInputs {
        let mut input_state = [BaseElement::ZERO; STATE_WIDTH];
        input_state[..4].copy_from_slice(accumulator);
        self.build_rpo_pub_inputs_for_state(input_state)
    }

    fn build_rpo_pub_inputs_for_state(
        &self,
        input_state: [BaseElement; STATE_WIDTH],
    ) -> super::rpo_air::RpoPublicInputs {
        let prover = RpoStarkProver::from_rpo_options(&self.options);
        let trace = prover.build_trace(input_state);
        prover.get_pub_inputs(&trace)
    }

    /// Generate mock recursive proof (for backward compatibility/testing).
    #[allow(dead_code)]
    fn generate_mock_recursive_proof(
        &self,
        epoch: &Epoch,
        accumulator: &[BaseElement; 4],
    ) -> Result<Vec<u8>, EpochProverError> {
        // Encode proof metadata
        let mut proof = Vec::with_capacity(128);

        // Magic bytes for recursive proof identification
        proof.extend_from_slice(b"RPROOF01");

        // Epoch commitment
        proof.extend_from_slice(&epoch.commitment());

        // Accumulator (32 bytes)
        for elem in accumulator {
            proof.extend_from_slice(&elem.inner().to_le_bytes());
        }

        // Epoch number
        proof.extend_from_slice(&epoch.epoch_number.to_le_bytes());

        // Padding to fixed size
        proof.resize(128, 0);

        Ok(proof)
    }

    /// Verify a recursive epoch proof using real STARK verification.
    ///
    /// Uses the winterfell verifier with RPO-based Fiat-Shamir.
    pub fn verify_epoch_proof(&self, proof: &RecursiveEpochProof, epoch: &Epoch) -> bool {
        // Basic sanity checks
        if proof.epoch_commitment != epoch.commitment() {
            return false;
        }

        // Check we have proof bytes
        if proof.proof_bytes.is_empty() {
            return false;
        }

        if !proof.is_recursive {
            // Verify the inner RPO proof directly.
            let inner_pub_inputs = self.build_inner_pub_inputs(&proof.proof_accumulator);
            let stark_proof = match winterfell::Proof::from_bytes(&proof.proof_bytes) {
                Ok(p) => p,
                Err(_) => return false,
            };
            return verify_epoch_with_rpo(&stark_proof, &inner_pub_inputs).is_ok();
        }

        // Recursive mode: verify the outer proof, which in-circuit verifies the inner proof.
        if proof.inner_proof_bytes.is_empty() {
            return false;
        }

        let inner_pub_inputs = self.build_inner_pub_inputs(&proof.proof_accumulator);
        let inner_data = match InnerProofData::from_proof::<super::rpo_air::RpoAir>(
            &proof.inner_proof_bytes,
            inner_pub_inputs,
        ) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let outer_pub_inputs = inner_data.to_stark_verifier_inputs();

        let outer_proof = match winterfell::Proof::from_bytes(&proof.proof_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Prefer verifying the outer proof with RPO (self-recursive-friendly), and fall back to
        // the legacy Blake3 outer-proof path for backwards compatibility.
        type RpoMerkleTree = MerkleTree<Rpo256>;
        let acceptable = AcceptableOptions::OptionSet(vec![
            RpoProofOptions::fast().to_winter_options(),
            RpoProofOptions::production().to_winter_options(),
        ]);
        if verify::<StarkVerifierAir, Rpo256, RpoRandomCoin, RpoMerkleTree>(
            outer_proof.clone(),
            outer_pub_inputs.clone(),
            &acceptable,
        )
        .is_ok()
        {
            return true;
        }

        type Blake3 = Blake3_256<BaseElement>;
        type Blake3MerkleTree = MerkleTree<Blake3>;
        verify::<StarkVerifierAir, Blake3, DefaultRandomCoin<Blake3>, Blake3MerkleTree>(
            outer_proof,
            outer_pub_inputs,
            &acceptable,
        )
        .is_ok()
    }

    /// Verify a recursive epoch proof (mock version for testing).
    #[allow(dead_code)]
    pub fn verify_epoch_proof_mock(&self, proof: &RecursiveEpochProof, epoch: &Epoch) -> bool {
        // Basic sanity checks
        if proof.epoch_commitment != epoch.commitment() {
            return false;
        }

        // Check proof format
        if proof.proof_bytes.len() < 8 {
            return false;
        }

        // Check magic bytes
        if &proof.proof_bytes[0..8] != b"RPROOF01" {
            return false;
        }

        // Verify epoch commitment in proof matches
        let commitment_in_proof = &proof.proof_bytes[8..40];
        if commitment_in_proof != epoch.commitment() {
            return false;
        }

        true
    }
}

/// Convert a 32-byte hash to 4 field elements.
fn hash_to_elements(hash: &[u8; 32]) -> [BaseElement; 4] {
    let mut elements = [BaseElement::ZERO; 4];
    for (i, chunk) in hash.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        elements[i] = BaseElement::new(u64::from_le_bytes(buf));
    }
    elements
}

fn build_epoch_batch_input_state(
    batch_accumulator: &[BaseElement; 4],
    epoch_start: u64,
    epoch_end: u64,
    num_epochs: u32,
) -> [BaseElement; STATE_WIDTH] {
    let start_lo = epoch_start as u32;
    let start_hi = (epoch_start >> 32) as u32;
    let end_lo = epoch_end as u32;
    let end_hi = (epoch_end >> 32) as u32;

    let mut input_state = [BaseElement::ZERO; STATE_WIDTH];
    input_state[..4].copy_from_slice(batch_accumulator);
    input_state[4] = BaseElement::new(start_lo as u64);
    input_state[5] = BaseElement::new(start_hi as u64);
    input_state[6] = BaseElement::new(end_lo as u64);
    input_state[7] = BaseElement::new(end_hi as u64);
    input_state[8] = BaseElement::new(EPOCH_BATCH_TAG);
    input_state[9] = BaseElement::new(num_epochs as u64);
    input_state
}

// ============================================================================
// Proof Options for Recursive Verification
// ============================================================================

/// Get default recursive proof options.
///
/// Uses higher blowup factor for recursive verification soundness.
pub fn recursive_proof_options() -> ProofOptions {
    ProofOptions::new(
        16, // num_queries (higher for recursion)
        32, // blowup_factor (32 for degree-8 constraints with cycle 16)
        4,  // grinding_factor
        FieldExtension::None,
        2, // fri_folding_factor
        7, // fri_remainder_max_degree (must be 2^k - 1)
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Get fast recursive proof options for testing.
pub fn fast_recursive_proof_options() -> ProofOptions {
    ProofOptions::new(
        8,
        32, // Must be at least 32 for RPO constraints
        0,
        FieldExtension::None,
        2,
        7,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

// ============================================================================
// Integration Types
// ============================================================================

/// Inner proof representation for recursive verification.
///
/// This encapsulates the data needed to verify a STARK proof within
/// another STARK circuit.
#[derive(Clone, Debug)]
pub struct InnerProofData {
    /// Commitment to the proof trace.
    pub trace_commitment: [BaseElement; 4],
    /// Commitment to constraint evaluations.
    pub constraint_commitment: [BaseElement; 4],
    /// Public inputs of the inner proof.
    pub public_inputs: Vec<BaseElement>,
    /// Proof-of-work nonce used for query seed grinding.
    pub pow_nonce: u64,
    /// Trace length of the inner proof.
    pub trace_length: usize,
    /// Trace width (main trace segment) of the inner proof.
    pub trace_width: usize,
    /// Blowup factor used by the inner proof.
    pub blowup_factor: usize,
    /// Partition size used for main-trace Merkle leaves.
    pub trace_partition_size: usize,
    /// Partition size used for constraint-evaluation Merkle leaves.
    pub constraint_partition_size: usize,
    /// Number of partitions used by the inner FRI proof.
    pub fri_num_partitions: usize,
    /// Constraint composition frame width (number of quotient columns).
    pub constraint_frame_width: usize,
    /// Number of transition constraints in the inner AIR.
    pub num_transition_constraints: usize,
    /// Number of boundary assertions in the inner AIR.
    pub num_assertions: usize,
    /// Number of query draws requested by the inner proof options (before dedup).
    pub num_draws: usize,
    /// Query positions drawn from the transcript (per draw; may contain duplicates).
    pub query_positions: Vec<usize>,
    /// Unique query positions used by the inner proof (sorted + deduped).
    pub unique_query_positions: Vec<usize>,
    /// Trace evaluations at query positions (main trace segment).
    pub trace_evaluations: Vec<Vec<BaseElement>>,
    /// Merkle authentication paths for trace queries (one path per query).
    pub trace_auth_paths: Vec<Vec<[BaseElement; 4]>>,
    /// Constraint composition polynomial evaluations at query positions.
    pub constraint_evaluations: Vec<Vec<BaseElement>>,
    /// Merkle authentication paths for constraint queries.
    pub constraint_auth_paths: Vec<Vec<[BaseElement; 4]>>,
    /// FRI layers for polynomial commitment verification.
    pub fri_layers: Vec<FriLayerData>,
    /// Remainder polynomial coefficients for the last FRI layer.
    pub fri_remainder: Vec<BaseElement>,
    /// Commitment to the remainder polynomial (last FRI commitment).
    pub fri_remainder_commitment: [BaseElement; 4],
    /// Out-of-domain trace evaluations at z (current row; main+aux concatenated).
    pub ood_trace_current: Vec<BaseElement>,
    /// Out-of-domain trace evaluations at z*g (next row; main+aux concatenated).
    pub ood_trace_next: Vec<BaseElement>,
    /// Out-of-domain quotient (constraint composition) evaluations at z (current row).
    pub ood_quotient_current: Vec<BaseElement>,
    /// Out-of-domain quotient (constraint composition) evaluations at z*g (next row).
    pub ood_quotient_next: Vec<BaseElement>,
    /// Digest of the merged OOD frame evaluations (used to reseed the transcript before DEEP).
    pub ood_digest: [BaseElement; 4],
    /// Out-of-domain point z drawn from the public coin.
    pub z: BaseElement,
    /// Constraint composition coefficients drawn from the public coin.
    pub constraint_coeffs: ConstraintCompositionCoefficients<BaseElement>,
    /// DEEP composition coefficients drawn from the public coin.
    pub deep_coeffs: DeepCompositionCoefficients<BaseElement>,
    /// FRI folding factors (alphas) drawn during the commit phase.
    pub fri_alphas: Vec<BaseElement>,
}

/// FRI layer data for recursive verification.
#[derive(Clone, Debug)]
pub struct FriLayerData {
    /// Layer commitment (RPO hash of layer polynomial).
    pub commitment: [BaseElement; 4],
    /// Evaluations at query positions.
    pub evaluations: Vec<BaseElement>,
    /// Merkle authentication paths for evaluations.
    pub auth_paths: Vec<Vec<[BaseElement; 4]>>,
}

impl InnerProofData {
    /// Create placeholder inner proof data for testing.
    pub fn mock() -> Self {
        Self {
            trace_commitment: [BaseElement::ZERO; 4],
            constraint_commitment: [BaseElement::ZERO; 4],
            public_inputs: vec![],
            pow_nonce: 0,
            trace_length: 0,
            trace_width: 0,
            blowup_factor: 0,
            trace_partition_size: 0,
            constraint_partition_size: 0,
            fri_num_partitions: 0,
            constraint_frame_width: 0,
            num_transition_constraints: 0,
            num_assertions: 0,
            num_draws: 0,
            query_positions: vec![],
            unique_query_positions: vec![],
            trace_evaluations: vec![],
            trace_auth_paths: vec![],
            constraint_evaluations: vec![],
            constraint_auth_paths: vec![],
            fri_layers: vec![],
            fri_remainder: vec![],
            fri_remainder_commitment: [BaseElement::ZERO; 4],
            ood_trace_current: vec![],
            ood_trace_next: vec![],
            ood_quotient_current: vec![],
            ood_quotient_next: vec![],
            ood_digest: [BaseElement::ZERO; 4],
            z: BaseElement::ZERO,
            constraint_coeffs: ConstraintCompositionCoefficients {
                transition: vec![],
                boundary: vec![],
            },
            deep_coeffs: DeepCompositionCoefficients {
                trace: vec![],
                constraints: vec![],
            },
            fri_alphas: vec![],
        }
    }

    /// Parse an inner RPO‑Fiat‑Shamir STARK proof into data usable by the recursive verifier.
    ///
    /// This reconstructs the Winterfell verifier transcript using `RpoRandomCoin`
    /// and extracts commitments, queries, Merkle openings, and FRI layer data.
    pub fn from_proof<A>(
        proof_bytes: &[u8],
        pub_inputs: A::PublicInputs,
    ) -> Result<Self, EpochProverError>
    where
        A: Air<BaseField = BaseElement>,
    {
        type RpoMerkleTree = MerkleTree<Rpo256>;

        let proof = Proof::from_bytes(proof_bytes)
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;

        // Only base field recursion is supported for now.
        if proof.options().field_extension() != FieldExtension::None {
            return Err(EpochProverError::TraceBuildError(
                "inner proof uses unsupported field extension".to_string(),
            ));
        }

        // Extract trace/options info from the proof context.
        let trace_info = proof.trace_info().clone();
        let options = proof.options().clone();

        // Capture public inputs as elements before moving into AIR.
        let public_inputs = pub_inputs.to_elements();

        // Instantiate inner AIR to compute protocol parameters.
        let air = A::new(trace_info.clone(), pub_inputs, options.clone());
        let num_draws = air.options().num_queries();

        let lde_domain_size = air.lde_domain_size();
        let fri_options = air.options().to_fri_options();
        let num_fri_layers = fri_options.num_fri_layers(lde_domain_size);
        let folding_factor = fri_options.folding_factor();
        let num_trace_segments = air.trace_info().num_segments();
        let main_trace_width = air.trace_info().main_trace_width();
        let aux_trace_width = air.trace_info().aux_segment_width();
        let constraint_frame_width = air.context().num_constraint_composition_columns();
        let num_transition_constraints = air.context().num_transition_constraints();
        let num_assertions = air.get_assertions().len();

        let partition_options = air.options().partition_options();
        let partition_size_main = partition_options.partition_size::<BaseElement>(main_trace_width);
        let partition_size_aux = partition_options.partition_size::<BaseElement>(aux_trace_width);
        let partition_size_constraint =
            partition_options.partition_size::<BaseElement>(constraint_frame_width);

        // --- parse commitments ----------------------------------------------------------------
        let (trace_roots, constraint_root, fri_roots) = proof
            .commitments
            .clone()
            .parse::<Rpo256>(num_trace_segments, num_fri_layers)
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;

        let trace_commitment = word_to_digest(trace_roots[0]);
        let constraint_commitment = word_to_digest(constraint_root);

        // --- parse trace queries ---------------------------------------------------------------
        let num_unique_queries = proof.num_unique_queries as usize;
        let mut trace_segment_data = Vec::with_capacity(num_trace_segments);
        for (seg_idx, queries) in proof.trace_queries.clone().into_iter().enumerate() {
            let seg_width = if seg_idx == 0 {
                main_trace_width
            } else {
                aux_trace_width
            };
            let seg_partition = if seg_idx == 0 {
                partition_size_main
            } else {
                partition_size_aux
            };
            let (mp, table) = queries
                .parse::<BaseElement, Rpo256, RpoMerkleTree>(
                    lde_domain_size,
                    num_unique_queries,
                    seg_width,
                )
                .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;
            trace_segment_data.push((mp, table, seg_partition));
        }

        // --- parse constraint queries ----------------------------------------------------------
        let (constraint_mp, constraint_table) = proof
            .constraint_queries
            .clone()
            .parse::<BaseElement, Rpo256, RpoMerkleTree>(
                lde_domain_size,
                num_unique_queries,
                constraint_frame_width,
            )
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;

        // --- parse OOD frame -------------------------------------------------------------------
        let (ood_trace_frame, ood_constraint_frame) = proof
            .ood_frame
            .clone()
            .parse::<BaseElement>(main_trace_width, aux_trace_width, constraint_frame_width)
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;
        let ood_trace_current = ood_trace_frame.current_row().to_vec();
        let ood_trace_next = ood_trace_frame.next_row().to_vec();
        let ood_quotient_current = ood_constraint_frame.current_row().to_vec();
        let ood_quotient_next = ood_constraint_frame.next_row().to_vec();

        // --- parse FRI proof -------------------------------------------------------------------
        let fri_num_partitions = proof.fri_proof.num_partitions();
        let fri_remainder_commitment = word_to_digest(*fri_roots.last().unwrap());
        let fri_remainder = proof
            .fri_proof
            .parse_remainder::<BaseElement>()
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;

        let (fri_layer_queries, fri_layer_proofs) = proof
            .fri_proof
            .clone()
            .parse_layers::<BaseElement, Rpo256, RpoMerkleTree>(lde_domain_size, folding_factor)
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;

        // --- reconstruct Fiat‑Shamir transcript -----------------------------------------------
        let mut seed = proof.context.to_elements();
        let mut pub_input_seed = public_inputs.clone();
        seed.append(&mut pub_input_seed);
        let mut coin = <RpoRandomCoin as RandomCoin>::new(&seed);

        // reseed with trace commitments
        coin.reseed(trace_roots[0]);

        // handle auxiliary trace (advance coin state if needed)
        if air.trace_info().is_multi_segment() {
            air.get_aux_rand_elements::<BaseElement, RpoRandomCoin>(&mut coin)
                .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;
            coin.reseed(trace_roots[1]);
        }

        let constraint_coeffs: ConstraintCompositionCoefficients<BaseElement> = air
            .get_constraint_composition_coefficients::<BaseElement, RpoRandomCoin>(&mut coin)
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;

        coin.reseed(constraint_root);
        let z: BaseElement = coin
            .draw()
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;

        // reseed with OOD evaluations digest (trace frame + quotient frame)
        let ood_evals = merge_ood_evaluations(&ood_trace_frame, &ood_constraint_frame);
        let ood_digest_word = Rpo256::hash_elements(&ood_evals);
        let ood_digest = word_to_digest(ood_digest_word);
        coin.reseed(ood_digest_word);

        let deep_coeffs: DeepCompositionCoefficients<BaseElement> = air
            .get_deep_composition_coefficients::<BaseElement, RpoRandomCoin>(&mut coin)
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;

        // FRI commit phase: reseed with each layer commitment and draw alpha.
        // The final FRI commitment is the remainder commitment; it is reseeded
        // but does not have an associated alpha draw.
        let num_fri_layers = fri_roots.len().saturating_sub(1);
        let mut fri_alphas = Vec::with_capacity(num_fri_layers);
        for commitment in fri_roots.iter().take(num_fri_layers) {
            coin.reseed(*commitment);
            let alpha: BaseElement = coin
                .draw()
                .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;
            fri_alphas.push(alpha);
        }

        // Reseed with remainder commitment before drawing query positions.
        if let Some(remainder_commitment) = fri_roots.last() {
            coin.reseed(*remainder_commitment);
        }

        // Draw query positions. Winterfell draws `num_draws` positions, then sorts+dedups them
        // before building Merkle queries.
        let pow_nonce = proof.pow_nonce;
        let query_positions = coin
            .draw_integers(num_draws, lde_domain_size, pow_nonce)
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;
        let mut unique_query_positions = query_positions.clone();
        unique_query_positions.sort_unstable();
        unique_query_positions.dedup();

        if unique_query_positions.len() != num_unique_queries {
            return Err(EpochProverError::TraceBuildError(format!(
                "derived {} unique query positions but proof expects {}",
                unique_query_positions.len(),
                num_unique_queries
            )));
        }

        // --- decompress trace Merkle proofs ---------------------------------------------------
        let mut trace_evaluations: Vec<Vec<BaseElement>> = Vec::new();
        let mut trace_auth_paths: Vec<Vec<[BaseElement; 4]>> = Vec::new();
        for (seg_idx, (mp, table, seg_partition)) in trace_segment_data.into_iter().enumerate() {
            if seg_idx > 0 {
                // Auxiliary trace segments are not yet supported in recursion data model.
                continue;
            }
            trace_evaluations = table.rows().map(|r| r.to_vec()).collect();
            let leaves: Vec<Word> = trace_evaluations
                .iter()
                .map(|row| hash_row_rpo(row, seg_partition))
                .collect();
            let openings = mp
                .into_openings(&leaves, &unique_query_positions)
                .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;
            trace_auth_paths = openings
                .into_iter()
                .map(|(_, path)| path.into_iter().map(word_to_digest).collect())
                .collect();
        }

        // --- decompress constraint Merkle proofs -----------------------------------------------
        let constraint_evaluations: Vec<Vec<BaseElement>> =
            constraint_table.rows().map(|r| r.to_vec()).collect();
        let constraint_leaves: Vec<Word> = constraint_evaluations
            .iter()
            .map(|row| hash_row_rpo(row, partition_size_constraint))
            .collect();
        let constraint_openings = constraint_mp
            .into_openings(&constraint_leaves, &unique_query_positions)
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;
        let constraint_auth_paths: Vec<Vec<[BaseElement; 4]>> = constraint_openings
            .into_iter()
            .map(|(_, path)| path.into_iter().map(word_to_digest).collect())
            .collect();

        // --- build FRI layer data --------------------------------------------------------------
        //
        // The Winterfell verifier de-duplicates query positions at every fold step. In-circuit,
        // we keep a fixed per-draw query schedule, and expand the proof's unique openings by
        // replicating them for duplicate positions.
        let mut fri_layers = Vec::with_capacity(fri_layer_queries.len());
        let mut unique_positions = unique_query_positions.clone();
        let mut draw_positions = query_positions.clone();
        let mut domain_size = lde_domain_size;

        for (layer_idx, (layer_values, layer_mp)) in fri_layer_queries
            .into_iter()
            .zip(fri_layer_proofs.into_iter())
            .enumerate()
        {
            let target_domain_size = domain_size / folding_factor;

            let folded_unique_positions =
                fold_positions(&unique_positions, domain_size, folding_factor);
            let unique_indexes = map_positions_to_indexes(
                &folded_unique_positions,
                domain_size,
                folding_factor,
                fri_num_partitions,
            );

            let leaves: Vec<Word> = layer_values
                .chunks(folding_factor)
                .map(|chunk| Rpo256::hash_elements(chunk))
                .collect();
            let openings = layer_mp
                .into_openings(&leaves, &unique_indexes)
                .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;
            let auth_paths_unique: Vec<Vec<[BaseElement; 4]>> = openings
                .into_iter()
                .map(|(_, path)| path.into_iter().map(word_to_digest).collect())
                .collect();

            // Expand unique openings to per-draw openings.
            let draw_folded_positions: Vec<usize> = draw_positions
                .iter()
                .map(|p| p % target_domain_size)
                .collect();

            let mut evaluations = Vec::with_capacity(query_positions.len() * folding_factor);
            let mut auth_paths = Vec::with_capacity(query_positions.len());
            for pos in &draw_folded_positions {
                let unique_idx = folded_unique_positions
                    .iter()
                    .position(|p| p == pos)
                    .ok_or_else(|| {
                        EpochProverError::TraceBuildError(format!(
                            "FRI layer {layer_idx}: folded position {pos} not found in unique set"
                        ))
                    })?;

                let start = unique_idx * folding_factor;
                let end = start + folding_factor;
                evaluations.extend_from_slice(&layer_values[start..end]);
                auth_paths.push(auth_paths_unique[unique_idx].clone());
            }

            let commitment = word_to_digest(fri_roots[layer_idx]);
            fri_layers.push(FriLayerData {
                commitment,
                evaluations,
                auth_paths,
            });

            unique_positions = folded_unique_positions;
            draw_positions = draw_folded_positions;
            domain_size = target_domain_size;
        }

        // Expand trace/constraint openings from unique positions to per-draw positions.
        let mut trace_evaluations_expanded = Vec::with_capacity(query_positions.len());
        let mut trace_auth_paths_expanded = Vec::with_capacity(query_positions.len());
        let mut constraint_evaluations_expanded = Vec::with_capacity(query_positions.len());
        let mut constraint_auth_paths_expanded = Vec::with_capacity(query_positions.len());
        for &pos in &query_positions {
            let unique_idx = unique_query_positions.binary_search(&pos).map_err(|_| {
                EpochProverError::TraceBuildError(format!(
                    "draw position {pos} not present in unique query positions"
                ))
            })?;
            trace_evaluations_expanded.push(trace_evaluations[unique_idx].clone());
            trace_auth_paths_expanded.push(trace_auth_paths[unique_idx].clone());
            constraint_evaluations_expanded.push(constraint_evaluations[unique_idx].clone());
            constraint_auth_paths_expanded.push(constraint_auth_paths[unique_idx].clone());
        }

        Ok(Self {
            trace_commitment,
            constraint_commitment,
            public_inputs,
            pow_nonce,
            trace_length: trace_info.length(),
            trace_width: main_trace_width,
            blowup_factor: options.blowup_factor(),
            trace_partition_size: partition_size_main,
            constraint_partition_size: partition_size_constraint,
            fri_num_partitions,
            constraint_frame_width,
            num_transition_constraints,
            num_assertions,
            num_draws,
            query_positions,
            unique_query_positions,
            trace_evaluations: trace_evaluations_expanded,
            trace_auth_paths: trace_auth_paths_expanded,
            constraint_evaluations: constraint_evaluations_expanded,
            constraint_auth_paths: constraint_auth_paths_expanded,
            fri_layers,
            fri_remainder,
            fri_remainder_commitment,
            ood_trace_current,
            ood_trace_next,
            ood_quotient_current,
            ood_quotient_next,
            ood_digest,
            z,
            constraint_coeffs,
            deep_coeffs,
            fri_alphas,
        })
    }

    /// Convert to public inputs for StarkVerifierAir.
    pub fn to_stark_verifier_inputs(&self) -> StarkVerifierPublicInputs {
        // Hash the public inputs to get inner_pub_inputs_hash.
        let inner_pub_inputs_hash = if self.public_inputs.is_empty() {
            [BaseElement::ZERO; 4]
        } else {
            rpo_hash_elements(&self.public_inputs)
        };

        // Collect FRI commitments
        let mut fri_commitments: Vec<[BaseElement; 4]> = self
            .fri_layers
            .iter()
            .map(|layer| layer.commitment)
            .collect();
        fri_commitments.push(self.fri_remainder_commitment);

        StarkVerifierPublicInputs::new(
            self.public_inputs.clone(),
            inner_pub_inputs_hash,
            self.trace_commitment,
            self.constraint_commitment,
            fri_commitments,
            self.query_positions.len(),
            self.num_draws,
            self.trace_partition_size,
            self.constraint_partition_size,
            self.blowup_factor,
            self.trace_length,
            self.trace_width,
            self.constraint_frame_width,
            self.num_transition_constraints,
            self.num_assertions,
        )
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn word_to_digest(word: Word) -> [BaseElement; 4] {
    [word[0], word[1], word[2], word[3]]
}

fn hash_row_rpo(row: &[BaseElement], partition_size: usize) -> Word {
    if partition_size == row.len() {
        Rpo256::hash_elements(row)
    } else {
        let num_partitions = row.len().div_ceil(partition_size);
        let mut buffer = vec![Word::default(); num_partitions];
        for (chunk, buf) in row.chunks(partition_size).zip(buffer.iter_mut()) {
            *buf = Rpo256::hash_elements(chunk);
        }
        Rpo256::merge_many(&buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::rpo_air::{RpoAir, STATE_WIDTH};
    use crate::recursion::rpo_stark_prover::RpoStarkProver;
    use crate::recursion::stark_verifier_air::StarkVerifierAir;
    use crate::recursion::stark_verifier_batch_prover::{prove_batch, verify_batch};
    use crate::types::Epoch;
    use std::time::Instant;
    use winter_math::FieldElement;
    use winterfell::AcceptableOptions;

    fn test_epoch() -> Epoch {
        let mut epoch = Epoch::new(0);
        epoch.proof_root = [1u8; 32];
        epoch.state_root = [2u8; 32];
        epoch.nullifier_set_root = [3u8; 32];
        epoch.commitment_tree_root = [4u8; 32];
        epoch
    }

    #[test]
    fn test_recursive_prover_creation() {
        let prover = RecursiveEpochProver::new();
        // Default blowup factor is 16 from RpoProofOptions::default()
        assert_eq!(prover.options.blowup_factor, 16);
    }

    #[test]
    fn test_recursive_prover_fast() {
        let prover = RecursiveEpochProver::fast();
        // Fast options use blowup 32 for RPO constraints
        assert_eq!(prover.options.blowup_factor, 32);
    }

    #[test]
    fn test_compute_proof_accumulator() {
        let prover = RecursiveEpochProver::new();
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let acc = prover.compute_proof_accumulator(&hashes);

        // Accumulator should be non-zero
        assert!(acc.iter().any(|e| *e != BaseElement::ZERO));
    }

    #[test]
    fn test_accumulator_deterministic() {
        let prover = RecursiveEpochProver::new();
        let hashes = vec![[42u8; 32], [99u8; 32]];

        let acc1 = prover.compute_proof_accumulator(&hashes);
        let acc2 = prover.compute_proof_accumulator(&hashes);

        assert_eq!(acc1, acc2);
    }

    #[test]
    fn test_prove_epoch() {
        let prover = RecursiveEpochProver::fast();
        let epoch = test_epoch();
        let hashes = vec![[1u8; 32], [2u8; 32]];

        let proof = prover.prove_epoch(&epoch, &hashes).unwrap();

        assert_eq!(proof.epoch_commitment, epoch.commitment());
        assert_eq!(proof.num_proofs, 2);
        assert!(!proof.proof_bytes.is_empty());
    }

    #[test]
    fn test_prove_epoch_empty_fails() {
        let prover = RecursiveEpochProver::fast();
        let epoch = test_epoch();

        let result = prover.prove_epoch(&epoch, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_prove_epoch_batch_roundtrip_and_tamper_reject() {
        let prover = RecursiveEpochProver::fast();

        // Generate a handful of per-epoch accumulators.
        let mut epoch_accumulators = Vec::new();
        for i in 0..4u64 {
            let mut epoch = test_epoch();
            epoch.epoch_number = i;
            let proof_hashes = vec![[i as u8; 32], [(i as u8).wrapping_add(1); 32]];
            let epoch_proof = prover.prove_epoch(&epoch, &proof_hashes).unwrap();
            epoch_accumulators.push(epoch_proof.accumulator_bytes());
        }

        let batch = prover
            .prove_epoch_batch(10, 13, &epoch_accumulators)
            .expect("batch proof generation should succeed");
        assert_eq!(batch.epoch_range(), (10, 13));
        assert_eq!(batch.num_epochs, 4);
        assert!(prover.verify_epoch_batch_proof(&batch));

        // Tamper with proof bytes.
        let mut tampered = batch.clone();
        tampered.proof_bytes[0] ^= 1;
        assert!(!prover.verify_epoch_batch_proof(&tampered));

        // Tamper with metadata that is bound into the inner proof's public inputs.
        let mut tampered_meta = batch;
        tampered_meta.epoch_end ^= 1;
        assert!(!prover.verify_epoch_batch_proof(&tampered_meta));
    }

    fn epoch_batch_as_inner(
        prover: &RecursiveEpochProver,
        batch: &EpochBatchProof,
    ) -> Result<(InnerProofData, StarkVerifierPublicInputs), EpochProverError> {
        let input_state = build_epoch_batch_input_state(
            &batch.batch_accumulator,
            batch.epoch_start,
            batch.epoch_end,
            batch.num_epochs,
        );
        let inner_pub_inputs = prover.build_rpo_pub_inputs_for_state(input_state);
        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&batch.proof_bytes, inner_pub_inputs)?;
        let verifier_pub_inputs = inner_data.to_stark_verifier_inputs();
        Ok((inner_data, verifier_pub_inputs))
    }

    #[test]
    #[ignore = "heavy: proves an outer batch verifier over epoch batches"]
    fn test_two_stage_epoch_batch_pipeline_roundtrip_and_tamper_reject() {
        let prover = RecursiveEpochProver::fast();

        // K=4 epochs per batch, N=2 batched inners.
        let mut epoch_accumulators = Vec::new();
        for i in 0..8u64 {
            let mut epoch = test_epoch();
            epoch.epoch_number = i;
            let proof_hashes = vec![[i as u8; 32], [(i as u8).wrapping_add(1); 32]];
            let epoch_proof = prover.prove_epoch(&epoch, &proof_hashes).unwrap();
            epoch_accumulators.push(epoch_proof.accumulator_bytes());
        }

        let batch1 = prover
            .prove_epoch_batch(10, 13, &epoch_accumulators[0..4])
            .expect("batch1");
        let batch2 = prover
            .prove_epoch_batch(14, 17, &epoch_accumulators[4..8])
            .expect("batch2");
        assert!(prover.verify_epoch_batch_proof(&batch1));
        assert!(prover.verify_epoch_batch_proof(&batch2));

        // Convert batched-inner proofs into recursion witness data + public inputs.
        let (inner1, pub_inputs1) = epoch_batch_as_inner(&prover, &batch1).expect("inner1");
        let (inner2, pub_inputs2) = epoch_batch_as_inner(&prover, &batch2).expect("inner2");

        // Outer batch proof: verify the two batched-inner proofs in-circuit.
        let outer_options = prover.options.to_winter_options();
        let outer = prove_batch(
            &[inner1, inner2],
            vec![pub_inputs1.clone(), pub_inputs2.clone()],
            outer_options.clone(),
        )
        .expect("outer batch proof");

        let acceptable = || AcceptableOptions::OptionSet(vec![outer_options.clone()]);
        verify_batch(
            &outer,
            vec![pub_inputs1.clone(), pub_inputs2.clone()],
            acceptable(),
        )
        .expect("outer batch verification");

        // Tamper reject: swapping per-inner public inputs must fail.
        assert!(verify_batch(
            &outer,
            vec![pub_inputs2.clone(), pub_inputs1.clone()],
            acceptable()
        )
        .is_err());

        // Tamper reject: mutating an inner batch proof must change its derived verifier public inputs.
        let mut tampered_bytes = batch2.clone();
        tampered_bytes.proof_bytes[0] ^= 1;
        match epoch_batch_as_inner(&prover, &tampered_bytes) {
            Ok((_inner2_t, pub_inputs2_t)) => {
                assert!(verify_batch(
                    &outer,
                    vec![pub_inputs1.clone(), pub_inputs2_t],
                    acceptable()
                )
                .is_err());
            }
            Err(_) => {
                // If the tampered bytes can't even be parsed as a proof, treat as rejection.
            }
        }

        // Tamper reject: metadata bound into the inner proof's public inputs must be consistent.
        let mut tampered_meta = batch2;
        tampered_meta.epoch_end ^= 1;
        if let Ok((_inner2_t, pub_inputs2_t)) = epoch_batch_as_inner(&prover, &tampered_meta) {
            assert!(verify_batch(&outer, vec![pub_inputs1, pub_inputs2_t], acceptable()).is_err());
        }
    }

    #[test]
    fn test_two_stage_epoch_batch_pipeline_small_options() {
        let prover = RecursiveEpochProver {
            options: RpoProofOptions {
                num_queries: 1,
                blowup_factor: 16,
                grinding_factor: 0,
            },
        };

        // K=4 epochs per batch, N=2 batched inners.
        let mut epoch_accumulators = Vec::new();
        for i in 0..8u8 {
            let mut acc = [0u8; 32];
            acc[0] = i;
            epoch_accumulators.push(acc);
        }

        let batch1 = prover
            .prove_epoch_batch(10, 13, &epoch_accumulators[0..4])
            .expect("batch1");
        let batch2 = prover
            .prove_epoch_batch(14, 17, &epoch_accumulators[4..8])
            .expect("batch2");
        let acceptable_inner =
            AcceptableOptions::OptionSet(vec![prover.options.to_winter_options()]);
        for batch in [&batch1, &batch2] {
            let input_state = build_epoch_batch_input_state(
                &batch.batch_accumulator,
                batch.epoch_start,
                batch.epoch_end,
                batch.num_epochs,
            );
            let inner_pub_inputs = prover.build_rpo_pub_inputs_for_state(input_state);
            let inner_proof = Proof::from_bytes(&batch.proof_bytes).expect("inner proof parse");
            crate::recursion::rpo_stark_prover::verify_rpo_proof(
                &inner_proof,
                &inner_pub_inputs,
                &acceptable_inner,
            )
            .expect("inner batch proof verify");
        }

        let (inner1, pub_inputs1) = epoch_batch_as_inner(&prover, &batch1).expect("inner1");
        let (inner2, pub_inputs2) = epoch_batch_as_inner(&prover, &batch2).expect("inner2");

        let outer_options = prover.options.to_winter_options();
        let outer = prove_batch(
            &[inner1, inner2],
            vec![pub_inputs1.clone(), pub_inputs2.clone()],
            outer_options.clone(),
        )
        .expect("outer batch proof");

        let acceptable = || AcceptableOptions::OptionSet(vec![outer_options.clone()]);
        verify_batch(
            &outer,
            vec![pub_inputs1.clone(), pub_inputs2.clone()],
            acceptable(),
        )
        .expect("outer batch verification");

        // Tamper reject: swapping per-inner public inputs must fail.
        assert!(verify_batch(
            &outer,
            vec![pub_inputs2.clone(), pub_inputs1.clone()],
            acceptable()
        )
        .is_err());

        // Tamper reject: mutating an inner batch proof must change its derived verifier public inputs.
        let mut tampered_bytes = batch2.clone();
        tampered_bytes.proof_bytes[0] ^= 1;
        if let Ok((_inner2_t, pub_inputs2_t)) = epoch_batch_as_inner(&prover, &tampered_bytes) {
            assert!(verify_batch(
                &outer,
                vec![pub_inputs1.clone(), pub_inputs2_t],
                acceptable()
            )
            .is_err());
        }

        // Tamper reject: metadata bound into the inner proof's public inputs must be consistent.
        let mut tampered_meta = batch2;
        tampered_meta.epoch_end ^= 1;
        if let Ok((_inner2_t, pub_inputs2_t)) = epoch_batch_as_inner(&prover, &tampered_meta) {
            assert!(verify_batch(&outer, vec![pub_inputs1, pub_inputs2_t], acceptable()).is_err());
        }
    }

    #[test]
    #[ignore = "heavy: measures recursive proof overhead"]
    fn test_recursive_proof_overhead_budget() {
        let prover = RecursiveEpochProver::fast();

        let proof_hashes: Vec<[u8; 32]> = (0..1000)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                h
            })
            .collect();

        let mut epoch = test_epoch();
        epoch.proof_root = crate::compute_proof_root(&proof_hashes);

        let start = Instant::now();
        let _inner = prover.prove_epoch(&epoch, &proof_hashes).unwrap();
        let inner_time = start.elapsed();

        let start = Instant::now();
        let recursive = prover.prove_epoch_recursive(&epoch, &proof_hashes).unwrap();
        let recursive_time = start.elapsed();

        let inner_size = recursive.inner_proof_bytes.len().max(1) as f64;
        let outer_size = recursive.proof_bytes.len() as f64;
        let size_ratio = outer_size / inner_size;

        let inner_secs = inner_time.as_secs_f64().max(1e-9);
        let time_ratio = recursive_time.as_secs_f64() / inner_secs;

        println!(
            "recursive overhead: inner_bytes={} outer_bytes={} size_ratio={:.2} inner_time_ms={:.2} recursive_time_ms={:.2} time_ratio={:.2}",
            recursive.inner_proof_bytes.len(),
            recursive.proof_bytes.len(),
            size_ratio,
            inner_time.as_secs_f64() * 1000.0,
            recursive_time.as_secs_f64() * 1000.0,
            time_ratio
        );

        assert!(
            size_ratio < 9.0,
            "outer/inner proof size ratio too high: {size_ratio:.2} (target < 9.0)"
        );
        assert!(
            time_ratio < 250.0,
            "recursive/inner prover time ratio too high: {time_ratio:.2} (target < 250.0)"
        );
    }

    #[test]
    #[ignore = "heavy: generates proof-of-proof (outer StarkVerifierAir proof)"]
    fn test_prove_epoch_recursive_roundtrip_and_tamper_reject() {
        let prover = RecursiveEpochProver::fast();
        let epoch = test_epoch();
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let proof = prover.prove_epoch_recursive(&epoch, &hashes).unwrap();
        assert!(proof.is_recursive());
        assert!(!proof.proof_bytes.is_empty());
        assert!(!proof.inner_proof_bytes.is_empty());

        assert!(prover.verify_epoch_proof(&proof, &epoch));

        // Tamper with the packaged inner proof bytes after outer proof generation: verification
        // should fail because the verifier reconstructs outer public inputs from the inner proof.
        let mut tampered_inner = proof.clone();
        tampered_inner.inner_proof_bytes[0] ^= 1;
        assert!(!prover.verify_epoch_proof(&tampered_inner, &epoch));

        // Tamper with the outer proof itself: verification should fail.
        let mut tampered_outer = proof;
        tampered_outer.proof_bytes[0] ^= 1;
        assert!(!prover.verify_epoch_proof(&tampered_outer, &epoch));
    }

    #[test]
    fn test_verify_epoch_proof() {
        let prover = RecursiveEpochProver::fast();
        let epoch = test_epoch();
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let proof = prover.prove_epoch(&epoch, &hashes).unwrap();

        assert!(prover.verify_epoch_proof(&proof, &epoch));
    }

    #[test]
    fn test_verify_wrong_epoch_fails() {
        let prover = RecursiveEpochProver::fast();
        let epoch1 = test_epoch();
        let mut epoch2 = test_epoch();
        epoch2.epoch_number = 999;

        let hashes = vec![[1u8; 32]];
        let proof = prover.prove_epoch(&epoch1, &hashes).unwrap();

        // Verification with wrong epoch should fail
        assert!(!prover.verify_epoch_proof(&proof, &epoch2));
    }

    #[test]
    fn test_accumulator_bytes() {
        let prover = RecursiveEpochProver::new();
        let epoch = test_epoch();
        let hashes = vec![[1u8; 32]];

        let proof = prover.prove_epoch(&epoch, &hashes).unwrap();
        let bytes = proof.accumulator_bytes();

        // Should be 32 bytes
        assert_eq!(bytes.len(), 32);
        // Should be non-zero
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hash_to_elements() {
        let hash = [0x42u8; 32];
        let elements = hash_to_elements(&hash);

        assert_eq!(elements.len(), 4);

        // Verify all elements are identical (each 8-byte chunk is the same)
        for i in 1..elements.len() {
            assert_eq!(elements[i], elements[0], "Elements should all be equal");
        }

        // Verify elements are non-zero
        assert_ne!(elements[0], BaseElement::ZERO);
    }

    #[test]
    fn test_inner_proof_data_mock() {
        let data = InnerProofData::mock();
        let inputs = data.to_stark_verifier_inputs();

        assert_eq!(inputs.trace_commitment, [BaseElement::ZERO; 4]);
        assert_eq!(inputs.inner_pub_inputs_hash, [BaseElement::ZERO; 4]);
    }

    #[test]
    fn test_inner_proof_data_from_rpo_proof() {
        // Generate an inner RPO proof and ensure we can extract recursion data.
        let prover = RpoStarkProver::fast();
        let input_state = [BaseElement::new(7); STATE_WIDTH];
        let (proof, pub_inputs) = prover
            .prove_rpo_permutation(input_state)
            .expect("inner proof generation should succeed");

        let data =
            InnerProofData::from_proof::<RpoAir>(&proof.to_bytes(), pub_inputs.clone()).unwrap();

        assert_eq!(data.public_inputs, pub_inputs.to_elements());
        assert_eq!(data.blowup_factor, proof.options().blowup_factor());
        assert_eq!(data.trace_length, proof.trace_info().length());
        assert_eq!(
            data.unique_query_positions.len(),
            proof.num_unique_queries as usize
        );
        assert_eq!(data.query_positions.len(), data.num_draws);
        assert_eq!(data.fri_alphas.len(), data.fri_layers.len());
    }

    #[test]
    fn test_recursive_proof_options() {
        let opts = recursive_proof_options();

        assert!(opts.blowup_factor() >= 32);
        assert!(opts.num_queries() >= 16);
    }

    #[test]
    fn test_fast_recursive_proof_options() {
        let opts = fast_recursive_proof_options();

        assert!(opts.blowup_factor() >= 32);
    }

    #[test]
    #[ignore = "heavy: generates an outer RPO verifier proof and parses it as an inner proof (depth-2 feasibility)"]
    fn test_outer_rpo_verifier_proof_parses_as_inner_stark_verifier_proof() {
        // Keep queries minimal so this test remains usable when run manually.
        let prover = RecursiveEpochProver {
            options: RpoProofOptions {
                num_queries: 1,
                blowup_factor: 32,
                grinding_factor: 0,
            },
        };
        let epoch = test_epoch();
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let proof = prover
            .prove_epoch_recursive_rpo_outer(&epoch, &hashes)
            .expect("outer RPO verifier proof generation should succeed");

        let inner_pub_inputs = prover.build_inner_pub_inputs(&proof.proof_accumulator);
        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&proof.inner_proof_bytes, inner_pub_inputs)
                .expect("inner proof parsing should succeed");
        let outer_pub_inputs = inner_data.to_stark_verifier_inputs();

        let outer_as_inner = InnerProofData::from_proof::<StarkVerifierAir>(
            &proof.proof_bytes,
            outer_pub_inputs.clone(),
        )
        .expect("outer proof should parse as an RPO-friendly StarkVerifierAir proof");

        assert_eq!(
            outer_as_inner.public_inputs,
            outer_pub_inputs.to_elements(),
            "parsed public inputs must match supplied StarkVerifierPublicInputs"
        );

        let outer_proof = winterfell::Proof::from_bytes(&proof.proof_bytes)
            .expect("outer proof should deserialize");
        let inner_air = StarkVerifierAir::new(
            outer_proof.trace_info().clone(),
            outer_pub_inputs,
            outer_proof.options().clone(),
        );

        let num_transition = inner_air.context().num_transition_constraints();
        let num_assertions = inner_air.get_assertions().len();
        let num_constraint_cols = inner_air.context().num_constraint_composition_columns();
        let trace_width = inner_air.trace_info().main_trace_width();

        println!(
            "depth-2 inner StarkVerifierAir params: trace_width={} constraint_cols={} transition_constraints={} assertions={} coeffs_total={} deep_coeffs={} ood_evals={} trace_len={} blowup={} trace_part={} constraint_part={} num_queries={} num_draws={}",
            trace_width,
            num_constraint_cols,
            num_transition,
            num_assertions,
            outer_as_inner.constraint_coeffs.transition.len()
                + outer_as_inner.constraint_coeffs.boundary.len(),
            outer_as_inner.deep_coeffs.trace.len() + outer_as_inner.deep_coeffs.constraints.len(),
            outer_as_inner.ood_trace_current.len()
                + outer_as_inner.ood_quotient_current.len()
                + outer_as_inner.ood_trace_next.len()
                + outer_as_inner.ood_quotient_next.len(),
            outer_as_inner.trace_length,
            outer_as_inner.blowup_factor,
            outer_as_inner.trace_partition_size,
            outer_as_inner.constraint_partition_size,
            outer_as_inner.unique_query_positions.len(),
            outer_as_inner.num_draws
        );

        assert_eq!(
            outer_as_inner.constraint_coeffs.transition.len(),
            num_transition,
            "transition coefficient count must match inner AIR"
        );
        assert_eq!(
            outer_as_inner.constraint_coeffs.boundary.len(),
            num_assertions,
            "boundary coefficient count must match inner AIR assertions"
        );
        assert_eq!(
            outer_as_inner.deep_coeffs.trace.len(),
            trace_width,
            "deep trace coefficient count must match inner trace width"
        );
        assert_eq!(
            outer_as_inner.deep_coeffs.constraints.len(),
            num_constraint_cols,
            "deep constraint coefficient count must match inner constraint composition width"
        );

        // Context-prefix seeding for verifier proofs must reproduce the same z.
        let verifier_pub_inputs = outer_as_inner.to_stark_verifier_inputs();
        let recomputed_z =
            crate::recursion::stark_verifier_air::compute_expected_z(&verifier_pub_inputs);
        assert_eq!(
            recomputed_z, outer_as_inner.z,
            "expected_z must match transcript-derived z for StarkVerifierAir proofs"
        );
    }

    #[test]
    #[ignore = "heavy: validates Winterfell verifier step-3 (OOD constraint consistency) for a StarkVerifierAir proof"]
    fn test_outer_verifier_proof_ood_constraint_consistency_holds() {
        use winter_air::EvaluationFrame;
        use winter_math::{polynom, FieldElement};

        // Keep queries minimal so this test remains usable when run manually.
        let prover = RecursiveEpochProver {
            options: RpoProofOptions {
                num_queries: 1,
                blowup_factor: 32,
                grinding_factor: 0,
            },
        };
        let epoch = test_epoch();
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        // Build: inner (RpoAir epoch proof) -> outer (StarkVerifierAir proof with RPO transcript).
        let proof = prover
            .prove_epoch_recursive_rpo_outer(&epoch, &hashes)
            .expect("outer RPO verifier proof generation should succeed");

        // Parse outer proof as an inner proof of StarkVerifierAir (depth-2).
        let inner_pub_inputs = prover.build_inner_pub_inputs(&proof.proof_accumulator);
        let inner_data =
            InnerProofData::from_proof::<RpoAir>(&proof.inner_proof_bytes, inner_pub_inputs)
                .expect("inner proof parsing should succeed");
        let outer_pub_inputs = inner_data.to_stark_verifier_inputs();
        let outer_as_inner = InnerProofData::from_proof::<StarkVerifierAir>(
            &proof.proof_bytes,
            outer_pub_inputs.clone(),
        )
        .expect("outer proof should parse as an RPO-friendly StarkVerifierAir proof");

        // Instantiate the AIR for the inner proof (StarkVerifierAir) so we can evaluate its
        // transition constraints at z.
        let outer_proof = winterfell::Proof::from_bytes(&proof.proof_bytes)
            .expect("outer proof should deserialize");
        let inner_air = StarkVerifierAir::new(
            outer_proof.trace_info().clone(),
            outer_pub_inputs,
            outer_proof.options().clone(),
        );

        // Evaluate periodic columns at the OOD point z using Winterfell’s periodic-column
        // polynomial semantics (cycle-length aware).
        let z = outer_as_inner.z;
        let periodic_at_z = inner_air
            .get_periodic_column_polys()
            .iter()
            .map(|poly| {
                let num_cycles = inner_air.trace_length() / poly.len();
                let x = z.exp_vartime((num_cycles as u32).into());
                polynom::eval(poly, x)
            })
            .collect::<Vec<_>>();

        let t_constraints =
            inner_air.get_transition_constraints(&outer_as_inner.constraint_coeffs.transition);
        let b_constraints = inner_air.get_boundary_constraints::<BaseElement>(
            None,
            &outer_as_inner.constraint_coeffs.boundary,
        );

        // Evaluate constraints at z over the out-of-domain trace frame and merge them exactly as
        // Winterfell’s verifier does.
        let frame = EvaluationFrame::from_rows(
            outer_as_inner.ood_trace_current.clone(),
            outer_as_inner.ood_trace_next.clone(),
        );
        let mut t_evals = vec![BaseElement::ZERO; t_constraints.num_main_constraints()];
        inner_air.evaluate_transition(&frame, &periodic_at_z, &mut t_evals);
        let mut expected_h_at_z =
            t_constraints.combine_evaluations::<BaseElement>(&t_evals, &[], z);
        for group in b_constraints.main_constraints().iter() {
            expected_h_at_z += group.evaluate_at(frame.current(), z);
        }

        // Reduce the inner proof’s constraint-composition columns at z to a single value:
        // H(z) = Σ_{i=0}^{m-1} z^{i * n} * H_i(z), where m = constraint composition width.
        let mut h_from_quotients = BaseElement::ZERO;
        for (i, value) in outer_as_inner.ood_quotient_current.iter().enumerate() {
            h_from_quotients +=
                z.exp_vartime(((i * outer_as_inner.trace_length) as u32).into()) * *value;
        }

        assert_eq!(
            expected_h_at_z, h_from_quotients,
            "OOD constraint consistency check must hold for valid StarkVerifierAir proofs"
        );
    }
}
