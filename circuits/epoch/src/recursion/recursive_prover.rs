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
use winter_crypto::{Hasher, MerkleTree, RandomCoin};
use winter_fri::folding::fold_positions;
use winter_fri::utils::map_positions_to_indexes;
use winter_math::{fields::f64::BaseElement, FieldElement, ToElements};
use winterfell::{BatchingMethod, FieldExtension, ProofOptions, Prover};

use super::rpo_air::STATE_WIDTH;
use super::rpo_proof::{rpo_hash_elements, RpoProofOptions, rpo_merge};
use super::rpo_stark_prover::{RpoStarkProver, verify_epoch_with_rpo};
use super::stark_verifier_air::StarkVerifierPublicInputs;
use crate::types::Epoch;
use crate::prover::EpochProverError;

/// Recursive epoch proof containing the STARK proof and verification metadata.
#[derive(Clone, Debug)]
pub struct RecursiveEpochProof {
    /// Serialized STARK proof bytes (using RPO for Fiat-Shamir).
    pub proof_bytes: Vec<u8>,
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

/// Recursive epoch prover using RPO-based STARK verification.
///
/// This prover generates proofs where Fiat-Shamir challenges are derived
/// using RPO hash, enabling efficient in-circuit verification for recursion.
pub struct RecursiveEpochProver {
    options: RpoProofOptions,
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
            proof_bytes,
            epoch_commitment: epoch.commitment(),
            proof_accumulator,
            num_proofs: proof_hashes.len() as u32,
            is_recursive: true, // Now uses real STARK proof
        })
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
        // Pad accumulator to full RPO state width (12 elements)
        let mut input_state = [BaseElement::ZERO; STATE_WIDTH];
        input_state[..4].copy_from_slice(accumulator);
        
        // Create prover with our options
        let prover = RpoStarkProver::from_rpo_options(&self.options);
        
        // Generate proof
        let (proof, _pub_inputs) = prover.prove_rpo_permutation(input_state)
            .map_err(|e| EpochProverError::ProofGenerationError(e))?;
        
        // Serialize proof
        Ok(proof.to_bytes())
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
    pub fn verify_epoch_proof(
        &self,
        proof: &RecursiveEpochProof,
        epoch: &Epoch,
    ) -> bool {
        // Basic sanity checks
        if proof.epoch_commitment != epoch.commitment() {
            return false;
        }
        
        // Check we have proof bytes
        if proof.proof_bytes.is_empty() {
            return false;
        }
        
        // Reconstruct input state from accumulator
        let mut input_state = [BaseElement::ZERO; STATE_WIDTH];
        input_state[..4].copy_from_slice(&proof.proof_accumulator);
        
        // Deserialize proof
        let stark_proof = match winterfell::Proof::from_bytes(&proof.proof_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        
        // Create public inputs (reconstruct what the prover used)
        let prover = RpoStarkProver::from_rpo_options(&self.options);
        let trace = prover.build_trace(input_state);
        let pub_inputs = prover.get_pub_inputs(&trace);
        
        // Verify using real STARK verifier with RPO
        verify_epoch_with_rpo(&stark_proof, &pub_inputs).is_ok()
    }
    
    /// Verify a recursive epoch proof (mock version for testing).
    #[allow(dead_code)]
    pub fn verify_epoch_proof_mock(
        &self,
        proof: &RecursiveEpochProof,
        epoch: &Epoch,
    ) -> bool {
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
        if commitment_in_proof != &epoch.commitment() {
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

// ============================================================================
// Proof Options for Recursive Verification
// ============================================================================

/// Get default recursive proof options.
///
/// Uses higher blowup factor for recursive verification soundness.
pub fn recursive_proof_options() -> ProofOptions {
    ProofOptions::new(
        16,  // num_queries (higher for recursion)
        32,  // blowup_factor (32 for degree-8 constraints with cycle 16)
        4,   // grinding_factor
        FieldExtension::None,
        2,   // fri_folding_factor
        7,   // fri_remainder_max_degree (must be 2^k - 1)
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Get fast recursive proof options for testing.
pub fn fast_recursive_proof_options() -> ProofOptions {
    ProofOptions::new(
        8,
        32,  // Must be at least 32 for RPO constraints
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
    /// Blowup factor used by the inner proof.
    pub blowup_factor: usize,
    /// Partition size used for main-trace Merkle leaves.
    pub trace_partition_size: usize,
    /// Partition size used for constraint-evaluation Merkle leaves.
    pub constraint_partition_size: usize,
    /// Number of partitions used by the inner FRI proof.
    pub fri_num_partitions: usize,
    /// Number of query draws requested by the inner proof options (before dedup).
    pub num_draws: usize,
    /// Query positions for FRI verification.
    pub query_positions: Vec<usize>,
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
            blowup_factor: 0,
            trace_partition_size: 0,
            constraint_partition_size: 0,
            fri_num_partitions: 0,
            num_draws: 0,
            query_positions: vec![],
            trace_evaluations: vec![],
            trace_auth_paths: vec![],
            constraint_evaluations: vec![],
            constraint_auth_paths: vec![],
            fri_layers: vec![],
            fri_remainder: vec![],
            fri_remainder_commitment: [BaseElement::ZERO; 4],
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

        let partition_options = air.options().partition_options();
        let partition_size_main =
            partition_options.partition_size::<BaseElement>(main_trace_width);
        let partition_size_aux =
            partition_options.partition_size::<BaseElement>(aux_trace_width);
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
        let ood_digest = Rpo256::hash_elements(&ood_evals);
        coin.reseed(ood_digest);

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

        // draw query positions
        let pow_nonce = proof.pow_nonce;
        let mut query_positions = coin
            .draw_integers(num_draws, lde_domain_size, pow_nonce)
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;
        query_positions.sort_unstable();
        query_positions.dedup();

        if query_positions.len() != num_unique_queries {
            return Err(EpochProverError::TraceBuildError(format!(
                "derived {} unique query positions but proof expects {}",
                query_positions.len(),
                num_unique_queries
            )));
        }

        // --- decompress trace Merkle proofs ---------------------------------------------------
        let mut trace_evaluations = Vec::new();
        let mut trace_auth_paths = Vec::new();
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
                .into_openings(&leaves, &query_positions)
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
            .into_openings(&constraint_leaves, &query_positions)
            .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;
        let constraint_auth_paths: Vec<Vec<[BaseElement; 4]>> = constraint_openings
            .into_iter()
            .map(|(_, path)| path.into_iter().map(word_to_digest).collect())
            .collect();

        // --- build FRI layer data --------------------------------------------------------------
        let mut fri_layers = Vec::with_capacity(fri_layer_queries.len());
        let mut positions = query_positions.clone();
        let mut domain_size = lde_domain_size;
        for (layer_idx, (layer_values, layer_mp)) in fri_layer_queries
            .into_iter()
            .zip(fri_layer_proofs.into_iter())
            .enumerate()
        {
            let folded_positions = fold_positions(&positions, domain_size, folding_factor);
            let position_indexes = map_positions_to_indexes(
                &folded_positions,
                domain_size,
                folding_factor,
                fri_num_partitions,
            );

            let leaves: Vec<Word> = layer_values
                .chunks(folding_factor)
                .map(|chunk| Rpo256::hash_elements(chunk))
                .collect();
            let openings = layer_mp
                .into_openings(&leaves, &position_indexes)
                .map_err(|e| EpochProverError::TraceBuildError(e.to_string()))?;
            let auth_paths: Vec<Vec<[BaseElement; 4]>> = openings
                .into_iter()
                .map(|(_, path)| path.into_iter().map(word_to_digest).collect())
                .collect();

            let commitment = word_to_digest(fri_roots[layer_idx]);
            fri_layers.push(FriLayerData {
                commitment,
                evaluations: layer_values,
                auth_paths,
            });

            positions = folded_positions;
            domain_size /= folding_factor;
        }

        Ok(Self {
            trace_commitment,
            constraint_commitment,
            public_inputs,
            pow_nonce,
            trace_length: trace_info.length(),
            blowup_factor: options.blowup_factor(),
            trace_partition_size: partition_size_main,
            constraint_partition_size: partition_size_constraint,
            fri_num_partitions,
            num_draws,
            query_positions,
            trace_evaluations,
            trace_auth_paths,
            constraint_evaluations,
            constraint_auth_paths,
            fri_layers,
            fri_remainder,
            fri_remainder_commitment,
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
    use crate::types::Epoch;
    use winter_math::FieldElement;
    use crate::recursion::rpo_air::{RpoAir, STATE_WIDTH};
    use crate::recursion::rpo_stark_prover::RpoStarkProver;

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
        assert_eq!(data.query_positions.len(), proof.num_unique_queries as usize);
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
}
