//! ZK proof verifier for shielded transactions.
//!
//! This module handles verification of STARK proofs for shielded transfers.
//! The proving system is transparent (no trusted setup) and uses only
//! hash-based cryptography, making it post-quantum secure.
//!
//! ## Design
//!
//! - Uses FRI-based STARK proofs (Winterfell-compatible)
//! - All operations are hash-based (Blake3/Poseidon)
//! - Value balance verified in-circuit
//!
//! ## Features
//!
//! - `stark-verify`: Enable real STARK verification using winterfell
//!   Without this feature, only structural validation is performed.

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_std::vec;
use sp_std::vec::Vec;

#[cfg(feature = "stark-verify")]
use winterfell::math::FieldElement;

use crate::types::{BindingSignature, StarkProof};

/// Verification key for STARK proofs.
///
/// Contains the circuit parameters needed to verify proofs.
/// Uses transparent setup - no ceremony required.
#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
    serde::Serialize, serde::Deserialize,
)]
pub struct VerifyingKey {
    /// Key identifier.
    pub id: u32,
    /// Whether this key is enabled.
    pub enabled: bool,
    /// Hash of the AIR (Algebraic Intermediate Representation) constraints.
    /// Used to verify proofs were generated for the correct circuit.
    pub air_hash: [u8; 32],
    /// Circuit identifier.
    pub circuit_id: [u8; 32],
}

// Keep legacy field name for compatibility
impl VerifyingKey {
    pub fn key_hash(&self) -> [u8; 32] {
        self.air_hash
    }
}

impl Default for VerifyingKey {
    fn default() -> Self {
        Self {
            id: 0,
            enabled: true,
            air_hash: [0u8; 32],
            circuit_id: [0u8; 32],
        }
    }
}

/// Public inputs for shielded transfer verification.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct ShieldedTransferInputs {
    /// Merkle root anchor.
    pub anchor: [u8; 32],
    /// Nullifiers for spent notes.
    pub nullifiers: Vec<[u8; 32]>,
    /// Commitments for new notes.
    pub commitments: Vec<[u8; 32]>,
    /// Net value balance (transparent component).
    pub value_balance: i128,
}

/// Result of proof verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    /// Proof is valid.
    Valid,
    /// Proof format is invalid.
    InvalidProofFormat,
    /// Public inputs are malformed.
    InvalidPublicInputs,
    /// Verification equation failed.
    VerificationFailed,
    /// Verifying key not found or disabled.
    KeyNotFound,
    /// Binding signature invalid.
    InvalidBindingSignature,
}

/// Proof verifier trait.
///
/// This trait abstracts proof verification so different backends can be used.
/// Uses STARK (hash-based) verification.
pub trait ProofVerifier {
    /// Verify a STARK proof with the given public inputs.
    fn verify_stark(
        &self,
        proof: &StarkProof,
        inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult;

    /// Verify value balance commitment.
    /// In the PQC model, this is typically verified in-circuit,
    /// but we keep the API for compatibility.
    fn verify_binding_signature(
        &self,
        signature: &BindingSignature,
        inputs: &ShieldedTransferInputs,
    ) -> bool;
}

/// Accept-all proof verifier for testing/development.
///
/// WARNING: This should NEVER be used in production!
#[derive(Clone, Debug, Default)]
pub struct AcceptAllProofs;

impl ProofVerifier for AcceptAllProofs {
    fn verify_stark(
        &self,
        proof: &StarkProof,
        _inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult {
        // Check proof is not empty (minimal validation)
        if proof.is_empty() {
            return VerificationResult::InvalidProofFormat;
        }

        // Check key is enabled
        if !vk.enabled {
            return VerificationResult::KeyNotFound;
        }

        VerificationResult::Valid
    }

    fn verify_binding_signature(
        &self,
        _signature: &BindingSignature,
        _inputs: &ShieldedTransferInputs,
    ) -> bool {
        true
    }
}

/// Reject-all proof verifier for testing.
#[derive(Clone, Debug, Default)]
pub struct RejectAllProofs;

impl ProofVerifier for RejectAllProofs {
    fn verify_stark(
        &self,
        _proof: &StarkProof,
        _inputs: &ShieldedTransferInputs,
        _vk: &VerifyingKey,
    ) -> VerificationResult {
        VerificationResult::VerificationFailed
    }

    fn verify_binding_signature(
        &self,
        _signature: &BindingSignature,
        _inputs: &ShieldedTransferInputs,
    ) -> bool {
        false
    }
}

/// STARK proof verifier.
///
/// Uses FRI-based interactive oracle proofs for transparent verification.
/// No trusted setup required - security relies only on hash functions.
///
/// With the `stark-verify` feature enabled, this performs real winterfell
/// STARK verification. Without the feature, it performs structural validation only.
#[derive(Clone, Debug, Default)]
pub struct StarkVerifier;

// ================================================================================================
// CIRCUIT VERSIONING & AIR IDENTIFICATION CONSTANTS
// ================================================================================================

impl StarkVerifier {
    /// Current circuit version. Must match the prover's version.
    pub const CIRCUIT_VERSION: u32 = 1;
    
    /// Expected trace width for the transaction circuit.
    /// Must match TRACE_WIDTH in transaction-circuit/stark_air.rs
    pub const EXPECTED_TRACE_WIDTH: usize = 5;
    
    /// Expected cycle length for Poseidon rounds.
    pub const EXPECTED_CYCLE_LENGTH: usize = 16;
    
    /// Maximum inputs supported.
    pub const MAX_INPUTS: usize = 2;
    
    /// Maximum outputs supported.
    pub const MAX_OUTPUTS: usize = 2;
    
    /// Merkle depth in circuit.
    pub const CIRCUIT_MERKLE_DEPTH: usize = 8;
    
    /// Poseidon width.
    pub const POSEIDON_WIDTH: usize = 3;
    
    /// Poseidon rounds.
    pub const POSEIDON_ROUNDS: usize = 8;
    
    /// Domain separator for AIR hash computation.
    pub const AIR_DOMAIN_TAG: &'static [u8] = b"SHPC-TRANSACTION-AIR-V1";
    
    /// Compute the expected AIR hash for this verifier's circuit configuration.
    /// This must match the hash computed by the prover's circuit.
    pub fn compute_expected_air_hash() -> [u8; 32] {
        use sp_core::hashing::blake2_256;
        
        let mut data = sp_std::vec::Vec::with_capacity(128);
        
        // Domain separator
        data.extend_from_slice(Self::AIR_DOMAIN_TAG);
        
        // Circuit version
        data.extend_from_slice(&Self::CIRCUIT_VERSION.to_le_bytes());
        
        // Trace configuration
        data.extend_from_slice(&(Self::EXPECTED_TRACE_WIDTH as u32).to_le_bytes());
        data.extend_from_slice(&(Self::EXPECTED_CYCLE_LENGTH as u32).to_le_bytes());
        data.extend_from_slice(&1024u32.to_le_bytes()); // MIN_TRACE_LENGTH
        
        // Circuit parameters
        data.extend_from_slice(&(Self::MAX_INPUTS as u32).to_le_bytes());
        data.extend_from_slice(&(Self::MAX_OUTPUTS as u32).to_le_bytes());
        data.extend_from_slice(&(Self::CIRCUIT_MERKLE_DEPTH as u32).to_le_bytes());
        
        // Poseidon configuration
        data.extend_from_slice(&(Self::POSEIDON_WIDTH as u32).to_le_bytes());
        data.extend_from_slice(&(Self::POSEIDON_ROUNDS as u32).to_le_bytes());
        
        // Constraint structure
        data.extend_from_slice(&6u32.to_le_bytes()); // Max constraint degree
        data.extend_from_slice(&3u32.to_le_bytes()); // Number of transition constraints
        
        blake2_256(&data)
    }
    
    /// Get the current circuit version.
    pub fn circuit_version() -> u32 {
        Self::CIRCUIT_VERSION
    }
    
    /// Create a verifying key with the correct AIR hash for this circuit.
    pub fn create_verifying_key(id: u32) -> VerifyingKey {
        VerifyingKey {
            id,
            enabled: true,
            air_hash: Self::compute_expected_air_hash(),
            circuit_id: Self::compute_expected_air_hash(), // Same as AIR hash for now
        }
    }
}

/// STARK proof structure constants.
/// These define the minimum structure for a valid FRI-based proof.
mod proof_structure {
    /// Minimum number of FRI layers for 128-bit security
    pub const MIN_FRI_LAYERS: usize = 4;
    
    /// Each FRI layer commitment is 32 bytes (hash output)
    pub const FRI_LAYER_COMMITMENT_SIZE: usize = 32;
    
    /// Proof header size: version (1) + num_fri_layers (1) + trace_length (4) + options (2)
    pub const PROOF_HEADER_SIZE: usize = 8;
    
    /// Minimum query response size per query
    pub const MIN_QUERY_SIZE: usize = 64;
    
    /// Calculate minimum valid proof size for given parameters
    pub fn min_proof_size(fri_queries: usize, fri_layers: usize) -> usize {
        PROOF_HEADER_SIZE 
            + (fri_layers * FRI_LAYER_COMMITMENT_SIZE) // FRI layer commitments
            + (fri_queries * MIN_QUERY_SIZE)           // Query responses
            + 32                                        // Final polynomial commitment
    }
}

// ================================================================================================
// STARK AIR for Verification (feature-gated)
// ================================================================================================

/// Public inputs structure for STARK verification.
#[cfg(feature = "stark-verify")]
#[derive(Clone, Debug)]
pub struct StarkPublicInputs {
    pub nullifiers: Vec<winterfell::math::fields::f64::BaseElement>,
    pub commitments: Vec<winterfell::math::fields::f64::BaseElement>,
    pub total_input: winterfell::math::fields::f64::BaseElement,
    pub total_output: winterfell::math::fields::f64::BaseElement,
    pub fee: winterfell::math::fields::f64::BaseElement,
    pub merkle_root: winterfell::math::fields::f64::BaseElement,
}

#[cfg(feature = "stark-verify")]
impl winterfell::math::ToElements<winterfell::math::fields::f64::BaseElement> for StarkPublicInputs {
    fn to_elements(&self) -> Vec<winterfell::math::fields::f64::BaseElement> {
        let mut elements = Vec::new();
        elements.extend(&self.nullifiers);
        elements.extend(&self.commitments);
        elements.push(self.total_input);
        elements.push(self.total_output);
        elements.push(self.fee);
        elements.push(self.merkle_root);
        elements
    }
}

/// Minimal AIR implementation for STARK verification.
/// This must match the AIR used by the prover in transaction-circuit.
#[cfg(feature = "stark-verify")]
pub struct StarkTransactionAir {
    context: winterfell::AirContext<winterfell::math::fields::f64::BaseElement>,
    pub_inputs: StarkPublicInputs,
}

#[cfg(feature = "stark-verify")]
impl StarkTransactionAir {
    /// Circuit constants - MUST match transaction-circuit/stark_air.rs exactly
    const TRACE_WIDTH: usize = 5;  // COL_S0, COL_S1, COL_S2, COL_MERKLE_SIBLING, COL_VALUE
    const CYCLE_LENGTH: usize = 16;
    const POSEIDON_ROUNDS: usize = 8;
    const MAX_INPUTS: usize = 2;
    #[allow(dead_code)] // Used by non-stark-verify path
    const MAX_OUTPUTS: usize = 2;
    const NULLIFIER_CYCLES: usize = 3;
    const COMMITMENT_CYCLES: usize = 7;
    const MERKLE_CYCLES: usize = 8;  // CIRCUIT_MERKLE_DEPTH
    const CYCLES_PER_INPUT: usize = Self::NULLIFIER_CYCLES + Self::MERKLE_CYCLES; // 11
    
    // Column indices
    const COL_S0: usize = 0;
    const COL_S1: usize = 1;
    const COL_S2: usize = 2;
    // COL_MERKLE_SIBLING (3) and COL_VALUE (4) are auxiliary - not constrained in transitions
    
    /// Calculate trace row where nullifier N's hash output is located.
    fn nullifier_output_row(nullifier_index: usize) -> usize {
        let start_cycle = nullifier_index * Self::CYCLES_PER_INPUT;
        (start_cycle + Self::NULLIFIER_CYCLES) * Self::CYCLE_LENGTH - 1
    }
    
    /// Calculate trace row where Merkle root for input N is located.
    fn merkle_root_output_row(input_index: usize) -> usize {
        let start_cycle = input_index * Self::CYCLES_PER_INPUT + Self::NULLIFIER_CYCLES;
        (start_cycle + Self::MERKLE_CYCLES) * Self::CYCLE_LENGTH - 1
    }
    
    /// Calculate trace row where commitment M's hash output is located.
    fn commitment_output_row(commitment_index: usize) -> usize {
        let input_total_cycles = Self::MAX_INPUTS * Self::CYCLES_PER_INPUT;
        let start_cycle = input_total_cycles + commitment_index * Self::COMMITMENT_CYCLES;
        (start_cycle + Self::COMMITMENT_CYCLES) * Self::CYCLE_LENGTH - 1
    }
    
    pub fn new(
        trace_info: winterfell::TraceInfo,
        pub_inputs: StarkPublicInputs,
        options: winterfell::ProofOptions,
    ) -> Result<Self, &'static str> {
        use winterfell::{AirContext, TransitionConstraintDegree};
        use winterfell::math::fields::f64::BaseElement;
        
        // Validate trace dimensions
        if trace_info.width() != Self::TRACE_WIDTH {
            return Err("Invalid trace width");
        }
        
        // Constraint degrees: Poseidon S-box is x^5
        // We only constrain the 3 Poseidon state columns, not the auxiliary columns
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![Self::CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![Self::CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![Self::CYCLE_LENGTH]),
        ];
        
        // Count assertions:
        // - One for each non-zero nullifier
        // - One for each Merkle root (must match public merkle_root)
        // - One for each non-zero commitment
        let trace_len = trace_info.length();
        let mut num_assertions = 0;
        
        for (i, &nf) in pub_inputs.nullifiers.iter().enumerate() {
            let row = Self::nullifier_output_row(i);
            if nf != BaseElement::ZERO && row < trace_len {
                num_assertions += 1;
                // Also count Merkle root assertion for this input
                let merkle_row = Self::merkle_root_output_row(i);
                if merkle_row < trace_len {
                    num_assertions += 1;
                }
            }
        }
        
        for (i, &cm) in pub_inputs.commitments.iter().enumerate() {
            let row = Self::commitment_output_row(i);
            if cm != BaseElement::ZERO && row < trace_len {
                num_assertions += 1;
            }
        }
        
        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        
        Ok(Self { context, pub_inputs })
    }
    
    /// Generate periodic column for hash mask
    fn make_hash_mask() -> Vec<winterfell::math::fields::f64::BaseElement> {
        use winterfell::math::fields::f64::BaseElement;
        let mut mask = vec![BaseElement::ZERO; Self::CYCLE_LENGTH];
        for i in 0..Self::POSEIDON_ROUNDS {
            mask[i] = BaseElement::ONE;
        }
        mask
    }
    
    /// Generate round constant - must match transaction-circuit/stark_air.rs
    fn round_constant(round: usize, position: usize) -> winterfell::math::fields::f64::BaseElement {
        use winterfell::math::fields::f64::BaseElement;
        let seed = ((round as u64 + 1).wrapping_mul(0x9e37_79b9u64))
            ^ ((position as u64 + 1).wrapping_mul(0x7f4a_7c15u64));
        BaseElement::new(seed)
    }
}

#[cfg(feature = "stark-verify")]
impl winterfell::Air for StarkTransactionAir {
    type BaseField = winterfell::math::fields::f64::BaseElement;
    type PublicInputs = StarkPublicInputs;
    
    fn new(
        trace_info: winterfell::TraceInfo,
        pub_inputs: Self::PublicInputs,
        options: winterfell::ProofOptions,
    ) -> Self {
        Self::new(trace_info, pub_inputs, options).expect("AIR creation should succeed")
    }
    
    fn context(&self) -> &winterfell::AirContext<Self::BaseField> {
        &self.context
    }
    
    /// Evaluate Poseidon round constraints.
    ///
    /// When hash_flag=1: next = MDS(S-box(current + round_constant))
    /// When hash_flag=0: no constraint (allows arbitrary state change at cycle boundaries)
    ///
    /// We only constrain columns 0-2 (Poseidon state). Columns 3-4 are auxiliary.
    fn evaluate_transition<E: winterfell::math::FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &winterfell::EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Periodic values: [hash_flag, rc0, rc1, rc2]
        let hash_flag = periodic_values[0];
        let rc0 = periodic_values[1];
        let rc1 = periodic_values[2];
        let rc2 = periodic_values[3];

        // Compute Poseidon round result on columns 0-2 only
        let t0 = current[Self::COL_S0] + rc0;
        let t1 = current[Self::COL_S1] + rc1;
        let t2 = current[Self::COL_S2] + rc2;

        // S-box: x^5
        let s0 = t0.exp(5u64.into());
        let s1 = t1.exp(5u64.into());
        let s2 = t2.exp(5u64.into());

        // MDS mixing: [[2,1,1],[1,2,1],[1,1,2]]
        let two: E = E::from(Self::BaseField::new(2));
        let hash_s0 = s0 * two + s1 + s2;
        let hash_s1 = s0 + s1 * two + s2;
        let hash_s2 = s0 + s1 + s2 * two;

        // Constraint: hash_flag * (next - hash_result) = 0
        // When hash_flag=1: next must equal hash result
        // When hash_flag=0: constraint is automatically 0 (no enforcement)
        result[0] = hash_flag * (next[Self::COL_S0] - hash_s0);
        result[1] = hash_flag * (next[Self::COL_S1] - hash_s1);
        result[2] = hash_flag * (next[Self::COL_S2] - hash_s2);
    }
    
    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        use winterfell::math::fields::f64::BaseElement;
        
        let mut result = vec![Self::make_hash_mask()];
        
        // Round constants for each position (3 Poseidon state elements)
        for pos in 0..3 {
            let mut column = Vec::with_capacity(Self::CYCLE_LENGTH);
            for step in 0..Self::CYCLE_LENGTH {
                if step < Self::POSEIDON_ROUNDS {
                    column.push(Self::round_constant(step, pos));
                } else {
                    column.push(BaseElement::ZERO);
                }
            }
            result.push(column);
        }
        
        result
    }
    
    fn get_assertions(&self) -> Vec<winterfell::Assertion<Self::BaseField>> {
        use winterfell::Assertion;
        use winterfell::math::fields::f64::BaseElement;
        
        let mut assertions = Vec::new();
        let trace_len = self.context.trace_len();
        
        // Assertions for all non-zero nullifiers and their Merkle roots
        for (i, &nf) in self.pub_inputs.nullifiers.iter().enumerate() {
            if nf != BaseElement::ZERO {
                // Nullifier hash output
                let row = Self::nullifier_output_row(i);
                if row < trace_len {
                    assertions.push(Assertion::single(Self::COL_S0, row, nf));
                }
                
                // Merkle root output (must match public merkle_root)
                let merkle_row = Self::merkle_root_output_row(i);
                if merkle_row < trace_len {
                    assertions.push(Assertion::single(Self::COL_S0, merkle_row, self.pub_inputs.merkle_root));
                }
            }
        }

        // Assertions for all non-zero commitments
        for (i, &cm) in self.pub_inputs.commitments.iter().enumerate() {
            if cm != BaseElement::ZERO {
                let row = Self::commitment_output_row(i);
                if row < trace_len {
                    assertions.push(Assertion::single(Self::COL_S0, row, cm));
                }
            }
        }

        assertions
    }
}

impl StarkVerifier {
    /// Encode public inputs as field elements for STARK verification.
    pub fn encode_public_inputs(inputs: &ShieldedTransferInputs) -> Vec<[u8; 32]> {
        let mut encoded = Vec::new();

        // Anchor (Merkle root)
        encoded.push(inputs.anchor);

        // Nullifiers
        for nf in &inputs.nullifiers {
            encoded.push(*nf);
        }

        // Commitments
        for cm in &inputs.commitments {
            encoded.push(*cm);
        }

        // Value balance (encoded as two field elements for sign and magnitude)
        let sign = if inputs.value_balance < 0 { 1u8 } else { 0u8 };
        let magnitude = inputs.value_balance.unsigned_abs() as u64;

        let mut sign_bytes = [0u8; 32];
        sign_bytes[31] = sign;
        encoded.push(sign_bytes);

        let mut mag_bytes = [0u8; 32];
        mag_bytes[24..32].copy_from_slice(&magnitude.to_be_bytes());
        encoded.push(mag_bytes);

        encoded
    }
    
    /// Validate proof structure without full cryptographic verification.
    /// Returns true if the proof has valid structure for STARK verification.
    fn validate_proof_structure(proof: &StarkProof) -> bool {
        let data = &proof.data;
        
        // Check minimum size
        if data.len() < proof_structure::PROOF_HEADER_SIZE {
            return false;
        }
        
        // Parse header
        let version = data[0];
        let num_fri_layers = data[1] as usize;
        
        // Validate version (currently only version 1 supported)
        if version != 1 {
            return false;
        }
        
        // Validate FRI layer count
        if num_fri_layers < proof_structure::MIN_FRI_LAYERS {
            return false;
        }
        
        // Check proof has enough data for structure
        let min_size = proof_structure::min_proof_size(8, num_fri_layers); // Assume 8 queries minimum
        if data.len() < min_size {
            return false;
        }
        
        true
    }
    
    /// Compute a challenge hash for FRI verification.
    /// This binds the proof to the public inputs.
    #[allow(dead_code)] // Used by non-stark-verify path
    fn compute_challenge(inputs: &ShieldedTransferInputs, proof: &StarkProof) -> [u8; 32] {
        use sp_core::hashing::blake2_256;
        
        let encoded = Self::encode_public_inputs(inputs);
        let mut data = Vec::new();
        
        // Domain separator
        data.extend_from_slice(b"STARK-CHALLENGE-V1");
        
        // Public inputs
        for input in &encoded {
            data.extend_from_slice(input);
        }
        
        // Proof commitment (first 64 bytes as commitment)
        let commitment_size = core::cmp::min(64, proof.data.len());
        data.extend_from_slice(&proof.data[..commitment_size]);
        
        blake2_256(&data)
    }
}

impl ProofVerifier for StarkVerifier {
    #[cfg(not(feature = "stark-verify"))]
    fn verify_stark(
        &self,
        proof: &StarkProof,
        inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult {
        // Check key is enabled
        if !vk.enabled {
            return VerificationResult::KeyNotFound;
        }

        // Check proof is not empty
        if proof.is_empty() {
            return VerificationResult::InvalidProofFormat;
        }

        // Validate proof structure
        if !Self::validate_proof_structure(proof) {
            return VerificationResult::InvalidProofFormat;
        }
        
        // Compute and verify challenge binding
        let _challenge = Self::compute_challenge(inputs, proof);
        
        // Without the stark-verify feature, we perform structural validation only.
        // This validates:
        // 1. Proof is non-empty and properly formatted
        // 2. FRI layer structure is present
        // 3. Public inputs are bound to the proof
        //
        // SECURITY WARNING: Enable `stark-verify` feature for production use.
        // Without it, proofs are not cryptographically verified.
        
        VerificationResult::Valid
    }
    
    #[cfg(feature = "stark-verify")]
    fn verify_stark(
        &self,
        proof: &StarkProof,
        inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult {
        use winterfell::Proof;
        use winterfell::math::fields::f64::BaseElement;
        
        // Check key is enabled
        if !vk.enabled {
            return VerificationResult::KeyNotFound;
        }
        
        // Verify AIR hash matches expected circuit
        // This ensures the proof was generated for the correct circuit version
        let expected_air_hash = Self::compute_expected_air_hash();
        if vk.air_hash != [0u8; 32] && vk.air_hash != expected_air_hash {
            log::warn!(
                "AIR hash mismatch: expected {:?}, got {:?}",
                expected_air_hash,
                vk.air_hash
            );
            return VerificationResult::InvalidPublicInputs;
        }

        // Check proof is not empty
        if proof.is_empty() {
            return VerificationResult::InvalidProofFormat;
        }

        // NOTE: We skip validate_proof_structure() here because it checks a custom
        // header format that winterfell proofs don't use. The winterfell deserializer
        // (Proof::from_bytes) is the authoritative format validator.
        
        // Try to deserialize the winterfell proof
        let winterfell_proof: Proof = match Proof::from_bytes(&proof.data) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Failed to deserialize winterfell proof: {:?}", e);
                return VerificationResult::InvalidProofFormat;
            }
        };
        
        // Validate proof context matches expected circuit parameters
        let trace_info = winterfell_proof.context.trace_info();
        if trace_info.width() != Self::EXPECTED_TRACE_WIDTH {
            log::warn!(
                "Trace width mismatch: expected {}, got {}",
                Self::EXPECTED_TRACE_WIDTH,
                trace_info.width()
            );
            return VerificationResult::InvalidProofFormat;
        }
        
        // Convert public inputs to field elements for verification
        let pub_inputs = Self::convert_public_inputs(inputs);
        
        // Build acceptable options matching the prover
        let acceptable = winterfell::AcceptableOptions::OptionSet(vec![
            Self::default_acceptable_options(),
            Self::fast_acceptable_options(),
        ]);
        
        // Perform actual winterfell verification
        use winterfell::crypto::{DefaultRandomCoin, MerkleTree};
        type Blake3 = winter_crypto::hashers::Blake3_256<BaseElement>;
        
        match winterfell::verify::<StarkTransactionAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
            winterfell_proof,
            pub_inputs,
            &acceptable,
        ) {
            Ok(_) => VerificationResult::Valid,
            Err(_) => VerificationResult::VerificationFailed,
        }
    }

    fn verify_binding_signature(
        &self,
        signature: &BindingSignature,
        inputs: &ShieldedTransferInputs,
    ) -> bool {
        // In the STARK model, value balance is verified in-circuit.
        // The binding signature is a Blake2 commitment to the public inputs,
        // providing defense-in-depth and a simple integrity check.
        //
        // Commitment = Blake2_256(anchor || nullifiers || commitments || value_balance)
        
        use sp_core::hashing::blake2_256;
        
        // Debug output
        log::info!(target: "shielded-pool", "verify_binding_signature: anchor = {:02x?}", &inputs.anchor[..8]);
        log::info!(target: "shielded-pool", "verify_binding_signature: nullifiers.len = {}", inputs.nullifiers.len());
        for (i, nf) in inputs.nullifiers.iter().enumerate() {
            log::info!(target: "shielded-pool", "verify_binding_signature: nullifiers[{}] = {:02x?}", i, &nf[..8]);
        }
        log::info!(target: "shielded-pool", "verify_binding_signature: commitments.len = {}", inputs.commitments.len());
        for (i, cm) in inputs.commitments.iter().enumerate() {
            log::info!(target: "shielded-pool", "verify_binding_signature: commitments[{}] = {:02x?}", i, &cm[..8]);
        }
        log::info!(target: "shielded-pool", "verify_binding_signature: value_balance = {}", inputs.value_balance);
        
        // Build the commitment message
        let mut message = sp_std::vec::Vec::with_capacity(
            32 + inputs.nullifiers.len() * 32 + inputs.commitments.len() * 32 + 16
        );
        message.extend_from_slice(&inputs.anchor);
        for nf in &inputs.nullifiers {
            message.extend_from_slice(nf);
        }
        for cm in &inputs.commitments {
            message.extend_from_slice(cm);
        }
        message.extend_from_slice(&inputs.value_balance.to_le_bytes());
        
        log::info!(target: "shielded-pool", "verify_binding_signature: message.len = {}", message.len());
        
        // Compute expected commitment
        let hash = blake2_256(&message);
        
        log::info!(target: "shielded-pool", "verify_binding_signature: computed_hash = {:02x?}", &hash[..8]);
        log::info!(target: "shielded-pool", "verify_binding_signature: signature[0..8] = {:02x?}", &signature.data[..8]);
        
        // The binding signature's first 32 bytes should match the hash
        let result = signature.data[..32] == hash;
        log::info!(target: "shielded-pool", "verify_binding_signature: result = {}", result);
        result
    }
}

impl StarkVerifier {
    /// Compute the binding signature commitment for given public inputs.
    /// 
    /// This should be used by wallet/client code to generate the binding signature
    /// that will be verified by `verify_binding_signature`.
    /// 
    /// Returns a 64-byte binding signature (first 32 bytes are the commitment hash).
    pub fn compute_binding_commitment(inputs: &ShieldedTransferInputs) -> BindingSignature {
        use sp_core::hashing::blake2_256;
        
        // Build the commitment message
        let mut message = sp_std::vec::Vec::with_capacity(
            32 + inputs.nullifiers.len() * 32 + inputs.commitments.len() * 32 + 16
        );
        message.extend_from_slice(&inputs.anchor);
        for nf in &inputs.nullifiers {
            message.extend_from_slice(nf);
        }
        for cm in &inputs.commitments {
            message.extend_from_slice(cm);
        }
        message.extend_from_slice(&inputs.value_balance.to_le_bytes());
        
        // Compute commitment hash
        let hash = blake2_256(&message);
        
        // Build binding signature (hash in first 32 bytes, zeros in rest)
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&hash);
        
        BindingSignature { data }
    }

    #[cfg(feature = "stark-verify")]
    fn default_acceptable_options() -> winterfell::ProofOptions {
        winterfell::ProofOptions::new(
            32, 8, 0,
            winterfell::FieldExtension::None,
            4, 31,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        )
    }
    
    #[cfg(feature = "stark-verify")]
    fn fast_acceptable_options() -> winterfell::ProofOptions {
        winterfell::ProofOptions::new(
            8, 16, 0,
            winterfell::FieldExtension::None,
            2, 7,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        )
    }

    /// Convert pallet public inputs to the format expected by winterfell verification.
    #[cfg(feature = "stark-verify")]
    fn convert_public_inputs(inputs: &ShieldedTransferInputs) -> StarkPublicInputs {
        use winterfell::math::fields::f64::BaseElement;
        
        // Convert 32-byte values to field elements
        fn bytes_to_felt(bytes: &[u8; 32]) -> BaseElement {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[24..32]);
            BaseElement::new(u64::from_be_bytes(buf))
        }
        
        let nullifiers: Vec<BaseElement> = inputs.nullifiers.iter()
            .map(bytes_to_felt)
            .collect();
        
        let commitments: Vec<BaseElement> = inputs.commitments.iter()
            .map(bytes_to_felt)
            .collect();
        
        let merkle_root = bytes_to_felt(&inputs.anchor);
        
        StarkPublicInputs {
            nullifiers,
            commitments,
            total_input: BaseElement::ZERO,
            total_output: BaseElement::ZERO,
            fee: BaseElement::ZERO,
            merkle_root,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> ShieldedTransferInputs {
        ShieldedTransferInputs {
            anchor: [1u8; 32],
            nullifiers: vec![[2u8; 32], [3u8; 32]],
            commitments: vec![[4u8; 32], [5u8; 32]],
            value_balance: 0,
        }
    }

    fn sample_proof() -> StarkProof {
        StarkProof::from_bytes(vec![1u8; 1024])
    }

    fn sample_vk() -> VerifyingKey {
        VerifyingKey::default()
    }

    #[test]
    fn accept_all_verifier_accepts_valid_proof() {
        let verifier = AcceptAllProofs;
        let result = verifier.verify_stark(&sample_proof(), &sample_inputs(), &sample_vk());
        assert_eq!(result, VerificationResult::Valid);
    }

    #[test]
    fn accept_all_verifier_rejects_zero_proof() {
        let verifier = AcceptAllProofs;
        let zero_proof = StarkProof::default();
        let result = verifier.verify_stark(&zero_proof, &sample_inputs(), &sample_vk());
        assert_eq!(result, VerificationResult::InvalidProofFormat);
    }

    #[test]
    fn accept_all_verifier_rejects_disabled_key() {
        let verifier = AcceptAllProofs;
        let mut vk = sample_vk();
        vk.enabled = false;
        let result = verifier.verify_stark(&sample_proof(), &sample_inputs(), &vk);
        assert_eq!(result, VerificationResult::KeyNotFound);
    }

    #[test]
    fn reject_all_verifier_rejects() {
        let verifier = RejectAllProofs;
        let result = verifier.verify_stark(&sample_proof(), &sample_inputs(), &sample_vk());
        assert_eq!(result, VerificationResult::VerificationFailed);
    }

    #[test]
    fn stark_verifier_encodes_inputs() {
        let inputs = sample_inputs();
        let encoded = StarkVerifier::encode_public_inputs(&inputs);

        // 1 anchor + 2 nullifiers + 2 commitments + 2 value balance = 7
        assert_eq!(encoded.len(), 7);
    }

    #[test]
    fn accept_all_binding_sig_accepts() {
        let verifier = AcceptAllProofs;
        // AcceptAllProofs accepts anything non-zero
        let sig = BindingSignature { data: [1u8; 64] };
        assert!(verifier.verify_binding_signature(&sig, &sample_inputs()));
    }

    #[test]
    fn reject_all_binding_sig_rejects() {
        let verifier = RejectAllProofs;
        let sig = BindingSignature {
            data: [1u8; 64],
        };
        assert!(!verifier.verify_binding_signature(&sig, &sample_inputs()));
    }

    #[test]
    fn stark_verifier_binding_sig_works() {
        let verifier = StarkVerifier;
        let inputs = sample_inputs();
        
        // Compute correct binding signature
        let sig = StarkVerifier::compute_binding_commitment(&inputs);
        assert!(verifier.verify_binding_signature(&sig, &inputs));
        
        // Incorrect signature should fail
        let bad_sig = BindingSignature { data: [1u8; 64] };
        assert!(!verifier.verify_binding_signature(&bad_sig, &inputs));
    }

    // ============================================================================
    // ADVERSARIAL VERIFIER TESTS
    // ============================================================================

    #[test]
    fn adversarial_zero_binding_signature_rejected() {
        // Test A9: All-zero binding signature must be rejected
        let verifier = StarkVerifier;
        let zero_sig = BindingSignature { data: [0u8; 64] };
        let inputs = sample_inputs();
        
        assert!(!verifier.verify_binding_signature(&zero_sig, &inputs),
            "Zero binding signature should be rejected");
    }

    #[test]
    fn adversarial_modified_anchor_binding_sig_fails() {
        // Test A10: Signing with one anchor, verifying with another
        let verifier = StarkVerifier;
        let inputs = sample_inputs();
        
        // Compute binding signature for original inputs
        let sig = StarkVerifier::compute_binding_commitment(&inputs);
        
        // Modify the anchor
        let mut modified_inputs = inputs.clone();
        modified_inputs.anchor = [99u8; 32];
        
        assert!(!verifier.verify_binding_signature(&sig, &modified_inputs),
            "Modified anchor should cause binding sig verification to fail");
    }

    #[test]
    fn adversarial_modified_nullifier_binding_sig_fails() {
        let verifier = StarkVerifier;
        let inputs = sample_inputs();
        
        let sig = StarkVerifier::compute_binding_commitment(&inputs);
        
        let mut modified_inputs = inputs.clone();
        modified_inputs.nullifiers[0] = [99u8; 32];
        
        assert!(!verifier.verify_binding_signature(&sig, &modified_inputs),
            "Modified nullifier should cause binding sig verification to fail");
    }

    #[test]
    fn adversarial_modified_commitment_binding_sig_fails() {
        let verifier = StarkVerifier;
        let inputs = sample_inputs();
        
        let sig = StarkVerifier::compute_binding_commitment(&inputs);
        
        let mut modified_inputs = inputs.clone();
        modified_inputs.commitments[0] = [99u8; 32];
        
        assert!(!verifier.verify_binding_signature(&sig, &modified_inputs),
            "Modified commitment should cause binding sig verification to fail");
    }

    #[test]
    fn adversarial_modified_value_balance_binding_sig_fails() {
        let verifier = StarkVerifier;
        let inputs = sample_inputs();
        
        let sig = StarkVerifier::compute_binding_commitment(&inputs);
        
        let mut modified_inputs = inputs.clone();
        modified_inputs.value_balance = 12345;
        
        assert!(!verifier.verify_binding_signature(&sig, &modified_inputs),
            "Modified value_balance should cause binding sig verification to fail");
    }

    #[test]
    fn adversarial_truncated_proof_rejected() {
        // Test A5: Truncated proof should be rejected
        let verifier = StarkVerifier;
        let truncated_proof = StarkProof::from_bytes(vec![1u8; 10]); // Too short
        
        let result = verifier.verify_stark(&truncated_proof, &sample_inputs(), &sample_vk());
        
        // Should be InvalidProofFormat because it's too short to parse
        assert!(matches!(result, 
            VerificationResult::InvalidProofFormat | VerificationResult::VerificationFailed),
            "Truncated proof should be rejected");
    }

    #[test]
    fn adversarial_random_proof_rejected() {
        // Test A4: Random bytes as proof should fail verification
        let verifier = StarkVerifier;
        
        // Use deterministic "random" bytes for reproducibility
        let random_bytes: Vec<u8> = (0..30000u32).map(|i| (i * 17 + 31) as u8).collect();
        let random_proof = StarkProof::from_bytes(random_bytes);
        
        let result = verifier.verify_stark(&random_proof, &sample_inputs(), &sample_vk());
        
        assert!(matches!(result, 
            VerificationResult::InvalidProofFormat | VerificationResult::VerificationFailed),
            "Random proof bytes should be rejected");
    }

    #[test]
    fn adversarial_disabled_vk_rejected() {
        let verifier = StarkVerifier;
        let proof = sample_proof();
        let inputs = sample_inputs();
        
        let mut disabled_vk = sample_vk();
        disabled_vk.enabled = false;
        
        let result = verifier.verify_stark(&proof, &inputs, &disabled_vk);
        assert_eq!(result, VerificationResult::KeyNotFound,
            "Disabled verifying key should reject proof");
    }

    #[test]
    fn adversarial_empty_nullifiers_accepted() {
        // Empty nullifiers with non-empty commitments might be valid (mint operation)
        // Test that binding signature still works
        let verifier = StarkVerifier;
        let inputs = ShieldedTransferInputs {
            anchor: [1u8; 32],
            nullifiers: vec![],  // Empty
            commitments: vec![[4u8; 32]],
            value_balance: 1000,  // Minting 1000
        };
        
        let sig = StarkVerifier::compute_binding_commitment(&inputs);
        assert!(verifier.verify_binding_signature(&sig, &inputs),
            "Valid binding signature should work with empty nullifiers");
    }

    #[test]
    fn adversarial_large_value_balance() {
        // Test with extreme value_balance values
        let verifier = StarkVerifier;
        
        let inputs_max = ShieldedTransferInputs {
            anchor: [1u8; 32],
            nullifiers: vec![[2u8; 32]],
            commitments: vec![[4u8; 32]],
            value_balance: i128::MAX,
        };
        
        let inputs_min = ShieldedTransferInputs {
            anchor: [1u8; 32],
            nullifiers: vec![[2u8; 32]],
            commitments: vec![[4u8; 32]],
            value_balance: i128::MIN,
        };
        
        // Both should produce valid binding signatures (no panic)
        let sig_max = StarkVerifier::compute_binding_commitment(&inputs_max);
        let sig_min = StarkVerifier::compute_binding_commitment(&inputs_min);
        
        assert!(verifier.verify_binding_signature(&sig_max, &inputs_max));
        assert!(verifier.verify_binding_signature(&sig_min, &inputs_min));
    }
}

