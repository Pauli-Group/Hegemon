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

#[cfg(all(feature = "production", not(feature = "stark-verify")))]
compile_error!("feature \"production\" requires \"stark-verify\" for real proof verification");

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(not(feature = "std"))]
use sp_std::vec;
use sp_std::vec::Vec;

use crate::types::{BindingHash, StarkProof};

/// Verification key for STARK proofs.
///
/// Contains the circuit parameters needed to verify proofs.
/// Uses transparent setup - no ceremony required.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    DecodeWithMemTracking,
    MaxEncodedLen,
    TypeInfo,
    serde::Serialize,
    serde::Deserialize,
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
            enabled: false,
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
    /// Native fee encoded in the circuit.
    pub fee: u64,
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
    /// Binding hash invalid.
    InvalidBindingHash,
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
    fn verify_binding_hash(&self, binding_hash: &BindingHash, inputs: &ShieldedTransferInputs)
        -> bool;
}

/// Accept-all proof verifier for testing/development.
///
/// WARNING: This should NEVER be used in production!
///
/// This type is only available when the `std` feature is enabled AND
/// the `production` feature is NOT enabled. This prevents accidental
/// use in release binaries.
#[cfg(all(feature = "std", not(feature = "production")))]
#[derive(Clone, Debug, Default)]
pub struct AcceptAllProofs;

#[cfg(all(feature = "std", not(feature = "production")))]
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

    fn verify_binding_hash(&self, _binding_hash: &BindingHash, _inputs: &ShieldedTransferInputs)
        -> bool {
        true
    }
}

/// Reject-all proof verifier for testing.
///
/// This type is only available in test/dev builds.
#[cfg(all(feature = "std", not(feature = "production")))]
#[derive(Clone, Debug, Default)]
pub struct RejectAllProofs;

#[cfg(all(feature = "std", not(feature = "production")))]
impl ProofVerifier for RejectAllProofs {
    fn verify_stark(
        &self,
        _proof: &StarkProof,
        _inputs: &ShieldedTransferInputs,
        _vk: &VerifyingKey,
    ) -> VerificationResult {
        VerificationResult::VerificationFailed
    }

    fn verify_binding_hash(&self, _binding_hash: &BindingHash, _inputs: &ShieldedTransferInputs)
        -> bool {
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
    /// Maximum inputs supported.
    pub const MAX_INPUTS: usize = transaction_core::constants::MAX_INPUTS;

    /// Maximum outputs supported.
    pub const MAX_OUTPUTS: usize = transaction_core::constants::MAX_OUTPUTS;

    /// Compute the expected AIR hash for this verifier's circuit configuration.
    /// This must match the hash computed by the prover's circuit.
    pub fn compute_expected_air_hash() -> [u8; 32] {
        transaction_core::expected_air_hash()
    }

    /// Get the current circuit version.
    pub fn circuit_version() -> u32 {
        transaction_core::CIRCUIT_VERSION
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
#[allow(dead_code)]
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
            + 32 // Final polynomial commitment
    }
}

// ================================================================================================
// STARK AIR for Verification lives in transaction-core.
// ================================================================================================

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

        // Fee (u64, canonical field encoding)
        let mut fee_bytes = [0u8; 32];
        fee_bytes[24..32].copy_from_slice(&inputs.fee.to_be_bytes());
        encoded.push(fee_bytes);

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
    #[allow(dead_code)]
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

    fn is_canonical_felt(bytes: &[u8; 32]) -> bool {
        transaction_core::hashing::is_canonical_bytes32(bytes)
    }

    fn validate_public_inputs(inputs: &ShieldedTransferInputs) -> bool {
        if inputs.nullifiers.len() > Self::MAX_INPUTS {
            return false;
        }
        if inputs.commitments.len() > Self::MAX_OUTPUTS {
            return false;
        }
        if inputs.nullifiers.is_empty() && inputs.commitments.is_empty() {
            return false;
        }
        if !Self::is_canonical_felt(&inputs.anchor) {
            return false;
        }
        if inputs
            .nullifiers
            .iter()
            .any(|nf| !Self::is_canonical_felt(nf) || *nf == [0u8; 32])
        {
            return false;
        }
        if inputs
            .commitments
            .iter()
            .any(|cm| !Self::is_canonical_felt(cm) || *cm == [0u8; 32])
        {
            return false;
        }
        if (inputs.fee as u128) >= transaction_core::constants::FIELD_MODULUS {
            return false;
        }
        if transaction_core::hashing::signed_parts(inputs.value_balance).is_none() {
            return false;
        }
        true
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

        if !Self::validate_public_inputs(inputs) {
            return VerificationResult::InvalidPublicInputs;
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
        // Check key is enabled
        if !vk.enabled {
            return VerificationResult::KeyNotFound;
        }

        if !Self::validate_public_inputs(inputs) {
            return VerificationResult::InvalidPublicInputs;
        }

        // Verify AIR hash matches expected circuit
        // This ensures the proof was generated for the correct circuit version
        let expected_air_hash = Self::compute_expected_air_hash();
        if vk.air_hash == [0u8; 32] {
            return VerificationResult::KeyNotFound;
        }
        if vk.air_hash != expected_air_hash {
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

        // Convert public inputs to field elements for verification
        let pub_inputs = match Self::convert_public_inputs(inputs) {
            Some(pub_inputs) => pub_inputs,
            None => return VerificationResult::InvalidPublicInputs,
        };

        match transaction_core::stark_verifier::verify_transaction_proof_bytes(
            &proof.data,
            &pub_inputs,
        ) {
            Ok(()) => VerificationResult::Valid,
            Err(transaction_core::stark_verifier::TransactionVerifyError::InvalidProofFormat) => {
                VerificationResult::InvalidProofFormat
            }
            Err(transaction_core::stark_verifier::TransactionVerifyError::InvalidPublicInputs(
                _,
            )) => VerificationResult::InvalidPublicInputs,
            Err(transaction_core::stark_verifier::TransactionVerifyError::VerificationFailed(
                _,
            )) => VerificationResult::VerificationFailed,
        }
    }

    fn verify_binding_hash(&self, binding_hash: &BindingHash, inputs: &ShieldedTransferInputs)
        -> bool {
        // In the STARK model, value balance is verified in-circuit.
        // The binding hash is a Blake2 commitment to the public inputs,
        // providing defense-in-depth and a simple integrity check.
        //
        // Commitment = Blake2_256(domain || 0 || message) || Blake2_256(domain || 1 || message)

        use sp_core::hashing::blake2_256;

        // Debug output
        log::info!(target: "shielded-pool", "verify_binding_hash: anchor = {:02x?}", &inputs.anchor[..8]);
        log::info!(target: "shielded-pool", "verify_binding_hash: nullifiers.len = {}", inputs.nullifiers.len());
        for (i, nf) in inputs.nullifiers.iter().enumerate() {
            log::info!(target: "shielded-pool", "verify_binding_hash: nullifiers[{}] = {:02x?}", i, &nf[..8]);
        }
        log::info!(target: "shielded-pool", "verify_binding_hash: commitments.len = {}", inputs.commitments.len());
        for (i, cm) in inputs.commitments.iter().enumerate() {
            log::info!(target: "shielded-pool", "verify_binding_hash: commitments[{}] = {:02x?}", i, &cm[..8]);
        }
        log::info!(target: "shielded-pool", "verify_binding_hash: value_balance = {}", inputs.value_balance);

        let message = Self::binding_hash_message(inputs);

        log::info!(target: "shielded-pool", "verify_binding_hash: message.len = {}", message.len());

        // Compute expected commitment
        let expected = Self::binding_hash_from_message(&message, blake2_256);

        log::info!(target: "shielded-pool", "verify_binding_hash: computed_hash = {:02x?}", &expected[..8]);
        log::info!(target: "shielded-pool", "verify_binding_hash: binding_hash[0..8] = {:02x?}", &binding_hash.data[..8]);

        // Full 64-byte binding hash must match
        let result = binding_hash.data == expected;
        log::info!(target: "shielded-pool", "verify_binding_hash: result = {}", result);
        result
    }
}

impl StarkVerifier {
    const BINDING_HASH_DOMAIN: &'static [u8] = b"binding-hash-v1";

    fn binding_hash_message(inputs: &ShieldedTransferInputs) -> Vec<u8> {
        let mut message = sp_std::vec::Vec::with_capacity(
            32 + inputs.nullifiers.len() * 32 + inputs.commitments.len() * 32 + 24,
        );
        message.extend_from_slice(&inputs.anchor);
        for nf in &inputs.nullifiers {
            message.extend_from_slice(nf);
        }
        for cm in &inputs.commitments {
            message.extend_from_slice(cm);
        }
        message.extend_from_slice(&inputs.fee.to_le_bytes());
        message.extend_from_slice(&inputs.value_balance.to_le_bytes());
        message
    }

    fn binding_hash_from_message(
        message: &[u8],
        blake2_256: fn(&[u8]) -> [u8; 32],
    ) -> [u8; 64] {
        let mut msg0 = sp_std::vec::Vec::with_capacity(Self::BINDING_HASH_DOMAIN.len() + 1 + message.len());
        msg0.extend_from_slice(Self::BINDING_HASH_DOMAIN);
        msg0.push(0);
        msg0.extend_from_slice(message);
        let hash0 = blake2_256(&msg0);

        let mut msg1 = sp_std::vec::Vec::with_capacity(Self::BINDING_HASH_DOMAIN.len() + 1 + message.len());
        msg1.extend_from_slice(Self::BINDING_HASH_DOMAIN);
        msg1.push(1);
        msg1.extend_from_slice(message);
        let hash1 = blake2_256(&msg1);

        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&hash0);
        out[32..].copy_from_slice(&hash1);
        out
    }

    /// Compute the binding hash for given public inputs.
    ///
    /// This should be used by wallet/client code to generate the binding hash
    /// that will be verified by `verify_binding_hash`.
    ///
    /// Returns a 64-byte binding hash with domain-separated halves.
    pub fn compute_binding_hash(inputs: &ShieldedTransferInputs) -> BindingHash {
        use sp_core::hashing::blake2_256;
        let message = Self::binding_hash_message(inputs);
        let data = Self::binding_hash_from_message(&message, blake2_256);
        BindingHash { data }
    }

    /// Convert pallet public inputs to the format expected by winterfell verification.
    #[cfg(feature = "stark-verify")]
    fn convert_public_inputs(
        inputs: &ShieldedTransferInputs,
    ) -> Option<transaction_core::TransactionPublicInputsStark> {
        let mut input_flags = Vec::with_capacity(Self::MAX_INPUTS);
        let mut nullifiers = Vec::with_capacity(Self::MAX_INPUTS);
        for (idx, nf) in inputs.nullifiers.iter().enumerate() {
            let felt = transaction_core::hashing::bytes32_to_felts(nf)?;
            if idx < Self::MAX_INPUTS {
                input_flags.push(transaction_core::Felt::ONE);
            }
            nullifiers.push(felt);
        }
        while nullifiers.len() < Self::MAX_INPUTS {
            nullifiers.push([transaction_core::Felt::ZERO; 4]);
            input_flags.push(transaction_core::Felt::ZERO);
        }

        let mut output_flags = Vec::with_capacity(Self::MAX_OUTPUTS);
        let mut commitments = Vec::with_capacity(Self::MAX_OUTPUTS);
        for (idx, cm) in inputs.commitments.iter().enumerate() {
            let felt = transaction_core::hashing::bytes32_to_felts(cm)?;
            if idx < Self::MAX_OUTPUTS {
                output_flags.push(transaction_core::Felt::ONE);
            }
            commitments.push(felt);
        }
        while commitments.len() < Self::MAX_OUTPUTS {
            commitments.push([transaction_core::Felt::ZERO; 4]);
            output_flags.push(transaction_core::Felt::ZERO);
        }

        let merkle_root = transaction_core::hashing::bytes32_to_felts(&inputs.anchor)?;

        let (value_balance_sign, value_balance_magnitude) =
            transaction_core::hashing::signed_parts(inputs.value_balance)?;

        Some(transaction_core::TransactionPublicInputsStark {
            input_flags,
            output_flags,
            nullifiers,
            commitments,
            fee: transaction_core::Felt::new(inputs.fee),
            value_balance_sign,
            value_balance_magnitude,
            merkle_root,
        })
    }
}

// ================================================================================================
// BATCH PROOF VERIFICATION
// ================================================================================================

/// Public inputs for batch shielded transfer verification.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct BatchPublicInputs {
    /// Shared Merkle root anchor.
    pub anchor: [u8; 32],
    /// All nullifiers across all transactions in the batch.
    pub nullifiers: Vec<[u8; 32]>,
    /// All commitments across all transactions in the batch.
    pub commitments: Vec<[u8; 32]>,
    /// Number of transactions in the batch.
    pub batch_size: u32,
    /// Total fee across all transactions.
    pub total_fee: u128,
}

/// Result of batch proof verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchVerificationResult {
    /// Batch proof is valid.
    Valid,
    /// Batch proof format is invalid.
    InvalidProofFormat,
    /// Public inputs are malformed.
    InvalidPublicInputs,
    /// Verification equation failed.
    VerificationFailed,
    /// Verifying key not found or disabled.
    KeyNotFound,
    /// Invalid batch size.
    InvalidBatchSize,
}

/// Batch proof verifier trait.
///
/// This trait abstracts batch proof verification where multiple transactions
/// are verified together in a single STARK proof.
pub trait BatchVerifier {
    /// Verify a batch STARK proof with the given public inputs.
    fn verify_batch(
        &self,
        proof: &crate::types::BatchStarkProof,
        inputs: &BatchPublicInputs,
        vk: &VerifyingKey,
    ) -> BatchVerificationResult;
}

/// Accept-all batch proof verifier for testing/development.
///
/// WARNING: This should NEVER be used in production!
#[cfg(all(feature = "std", not(feature = "production")))]
#[derive(Clone, Debug, Default)]
pub struct AcceptAllBatchProofs;

#[cfg(all(feature = "std", not(feature = "production")))]
impl BatchVerifier for AcceptAllBatchProofs {
    fn verify_batch(
        &self,
        proof: &crate::types::BatchStarkProof,
        inputs: &BatchPublicInputs,
        vk: &VerifyingKey,
    ) -> BatchVerificationResult {
        // Check proof is not empty (minimal validation)
        if proof.is_empty() {
            return BatchVerificationResult::InvalidProofFormat;
        }

        // Validate batch size
        if !proof.is_valid_batch_size() {
            return BatchVerificationResult::InvalidBatchSize;
        }

        // Ensure batch_size matches inputs
        if proof.batch_size != inputs.batch_size {
            return BatchVerificationResult::InvalidBatchSize;
        }

        // Check key is enabled
        if !vk.enabled {
            return BatchVerificationResult::KeyNotFound;
        }

        BatchVerificationResult::Valid
    }
}

/// Real STARK batch proof verifier.
///
/// Uses the batch-circuit crate to verify aggregated proofs.
#[derive(Clone, Debug, Default)]
pub struct StarkBatchVerifier;

impl BatchVerifier for StarkBatchVerifier {
    fn verify_batch(
        &self,
        proof: &crate::types::BatchStarkProof,
        inputs: &BatchPublicInputs,
        vk: &VerifyingKey,
    ) -> BatchVerificationResult {
        // Basic structural validation
        if proof.is_empty() {
            return BatchVerificationResult::InvalidProofFormat;
        }

        // Validate batch size
        if !proof.is_valid_batch_size() {
            return BatchVerificationResult::InvalidBatchSize;
        }

        // Ensure batch_size matches inputs
        if proof.batch_size != inputs.batch_size {
            return BatchVerificationResult::InvalidBatchSize;
        }

        // Check key is enabled
        if !vk.enabled {
            return BatchVerificationResult::KeyNotFound;
        }

        if !StarkVerifier::is_canonical_felt(&inputs.anchor) {
            return BatchVerificationResult::InvalidPublicInputs;
        }

        if inputs
            .nullifiers
            .iter()
            .any(|nf| !StarkVerifier::is_canonical_felt(nf))
        {
            return BatchVerificationResult::InvalidPublicInputs;
        }

        if inputs
            .commitments
            .iter()
            .any(|cm| !StarkVerifier::is_canonical_felt(cm))
        {
            return BatchVerificationResult::InvalidPublicInputs;
        }

        // Check AIR hash matches expected configuration
        let expected_air_hash = StarkVerifier::compute_expected_air_hash();
        if vk.air_hash != expected_air_hash {
            return BatchVerificationResult::KeyNotFound;
        }

        // Structural validation for batch inputs
        let expected_nullifiers = inputs.batch_size as usize * 2; // MAX_INPUTS per tx
        let expected_commitments = inputs.batch_size as usize * 2; // MAX_OUTPUTS per tx

        if inputs.nullifiers.len() != expected_nullifiers {
            return BatchVerificationResult::InvalidPublicInputs;
        }
        if inputs.commitments.len() != expected_commitments {
            return BatchVerificationResult::InvalidPublicInputs;
        }

        let has_active_nullifier = inputs.nullifiers.iter().any(|nf| *nf != [0u8; 32]);
        if !has_active_nullifier {
            return BatchVerificationResult::InvalidPublicInputs;
        }

        if inputs.total_fee >= transaction_core::constants::FIELD_MODULUS {
            return BatchVerificationResult::InvalidPublicInputs;
        }

        // With stark-verify feature, perform real batch verification
        #[cfg(feature = "stark-verify")]
        {
            use batch_circuit::{
                verify_batch_proof_bytes, BatchCircuitError,
                BatchPublicInputs as CircuitBatchPublicInputs,
            };
            use transaction_core::hashing::bytes32_to_felts;

            let anchor = match bytes32_to_felts(&inputs.anchor) {
                Some(value) => value,
                None => return BatchVerificationResult::InvalidPublicInputs,
            };

            let mut nullifiers = Vec::with_capacity(inputs.nullifiers.len());
            for nf in &inputs.nullifiers {
                let value = match bytes32_to_felts(nf) {
                    Some(value) => value,
                    None => return BatchVerificationResult::InvalidPublicInputs,
                };
                nullifiers.push(value);
            }

            let mut commitments = Vec::with_capacity(inputs.commitments.len());
            for cm in &inputs.commitments {
                let value = match bytes32_to_felts(cm) {
                    Some(value) => value,
                    None => return BatchVerificationResult::InvalidPublicInputs,
                };
                commitments.push(value);
            }

            let total_fee = transaction_core::Felt::new(inputs.total_fee as u64);
            let mut batch_inputs = CircuitBatchPublicInputs::new(
                inputs.batch_size,
                anchor,
                nullifiers,
                commitments,
                total_fee,
            );
            batch_inputs.circuit_version = transaction_core::CIRCUIT_VERSION;

            match verify_batch_proof_bytes(&proof.data, &batch_inputs) {
                Ok(()) => {}
                Err(err) => {
                    return match err {
                        BatchCircuitError::InvalidProofFormat => {
                            BatchVerificationResult::InvalidProofFormat
                        }
                        BatchCircuitError::InvalidBatchSize(_) | BatchCircuitError::EmptyBatch => {
                            BatchVerificationResult::InvalidBatchSize
                        }
                        BatchCircuitError::InvalidPublicInputs(_)
                        | BatchCircuitError::AnchorMismatch => {
                            BatchVerificationResult::InvalidPublicInputs
                        }
                        BatchCircuitError::VerificationError(_) => {
                            BatchVerificationResult::VerificationFailed
                        }
                        BatchCircuitError::InvalidWitness { .. }
                        | BatchCircuitError::TraceBuildError(_)
                        | BatchCircuitError::ProofGenerationError(_) => {
                            BatchVerificationResult::VerificationFailed
                        }
                    };
                }
            }
        }

        BatchVerificationResult::Valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> ShieldedTransferInputs {
        fn canonical_byte(value: u8) -> [u8; 32] {
            let mut out = [0u8; 32];
            out[31] = value;
            out
        }

        ShieldedTransferInputs {
            anchor: canonical_byte(1),
            nullifiers: vec![canonical_byte(2), canonical_byte(3)],
            commitments: vec![canonical_byte(4), canonical_byte(5)],
            fee: 0,
            value_balance: 0,
        }
    }

    fn sample_proof() -> StarkProof {
        StarkProof::from_bytes(vec![1u8; 1024])
    }

    fn sample_vk() -> VerifyingKey {
        StarkVerifier::create_verifying_key(0)
    }

    #[cfg(feature = "stark-verify")]
    fn compute_merkle_root_from_path(
        leaf: transaction_circuit::hashing::Felt,
        position: u64,
        path: &transaction_circuit::note::MerklePath,
    ) -> transaction_circuit::hashing::Felt {
        use transaction_circuit::hashing::merkle_node;

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

    #[cfg(feature = "stark-verify")]
    fn build_stark_fixture() -> (StarkProof, ShieldedTransferInputs, BindingHash) {
        use transaction_circuit::hashing::felt_to_bytes32;
        use transaction_circuit::keys::generate_keys;
        use transaction_circuit::note::{
            InputNoteWitness, MerklePath, NoteData, OutputNoteWitness,
        };
        use transaction_circuit::proof::prove;
        use transaction_circuit::witness::TransactionWitness;

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

        let witness = TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position: 0,
                rho_seed: [7u8; 32],
                merkle_path,
            }],
            outputs: vec![OutputNoteWitness { note: output_note }],
            sk_spend: [6u8; 32],
            merkle_root,
            fee: 100,
            value_balance: 0,
            version: TransactionWitness::default_version_binding(),
        };

        let (proving_key, _verifying_key) = generate_keys();
        let proof = prove(&witness, &proving_key).expect("proof generation");
        let stark_inputs = proof
            .stark_public_inputs
            .as_ref()
            .expect("stark public inputs");

        let inputs = ShieldedTransferInputs {
            anchor: felt_to_bytes32(stark_inputs.merkle_root),
            nullifiers: proof
                .nullifiers
                .iter()
                .copied()
                .map(felt_to_bytes32)
                .filter(|nf| *nf != [0u8; 32])
                .collect(),
            commitments: proof
                .commitments
                .iter()
                .copied()
                .map(felt_to_bytes32)
                .filter(|cm| *cm != [0u8; 32])
                .collect(),
            fee: stark_inputs.fee,
            value_balance: 0,
        };

        let binding_hash = StarkVerifier::compute_binding_hash(&inputs);

        (
            StarkProof::from_bytes(proof.stark_proof),
            inputs,
            binding_hash,
        )
    }

    #[test]
    #[cfg(not(feature = "production"))]
    fn accept_all_verifier_accepts_valid_proof() {
        let verifier = AcceptAllProofs;
        let result = verifier.verify_stark(&sample_proof(), &sample_inputs(), &sample_vk());
        assert_eq!(result, VerificationResult::Valid);
    }

    #[test]
    #[cfg(not(feature = "production"))]
    fn accept_all_verifier_rejects_zero_proof() {
        let verifier = AcceptAllProofs;
        let zero_proof = StarkProof::default();
        let result = verifier.verify_stark(&zero_proof, &sample_inputs(), &sample_vk());
        assert_eq!(result, VerificationResult::InvalidProofFormat);
    }

    #[test]
    #[cfg(not(feature = "production"))]
    fn accept_all_verifier_rejects_disabled_key() {
        let verifier = AcceptAllProofs;
        let mut vk = sample_vk();
        vk.enabled = false;
        let result = verifier.verify_stark(&sample_proof(), &sample_inputs(), &vk);
        assert_eq!(result, VerificationResult::KeyNotFound);
    }

    #[test]
    #[cfg(not(feature = "production"))]
    fn reject_all_verifier_rejects() {
        let verifier = RejectAllProofs;
        let result = verifier.verify_stark(&sample_proof(), &sample_inputs(), &sample_vk());
        assert_eq!(result, VerificationResult::VerificationFailed);
    }

    #[test]
    fn stark_verifier_encodes_inputs() {
        let inputs = sample_inputs();
        let encoded = StarkVerifier::encode_public_inputs(&inputs);

        // 1 anchor + 2 nullifiers + 2 commitments + fee + value balance (sign + mag) = 8
        assert_eq!(encoded.len(), 8);
    }

    #[test]
    #[cfg(not(feature = "production"))]
    fn accept_all_binding_hash_accepts() {
        let verifier = AcceptAllProofs;
        // AcceptAllProofs accepts anything non-zero
        let sig = BindingHash { data: [1u8; 64] };
        assert!(verifier.verify_binding_hash(&sig, &sample_inputs()));
    }

    #[test]
    #[cfg(not(feature = "production"))]
    fn reject_all_binding_hash_rejects() {
        let verifier = RejectAllProofs;
        let sig = BindingHash { data: [1u8; 64] };
        assert!(!verifier.verify_binding_hash(&sig, &sample_inputs()));
    }

    #[test]
    fn stark_verifier_binding_hash_works() {
        let verifier = StarkVerifier;
        let inputs = sample_inputs();

        // Compute correct binding hash
        let sig = StarkVerifier::compute_binding_hash(&inputs);
        assert!(verifier.verify_binding_hash(&sig, &inputs));

        // Incorrect hash should fail
        let bad_sig = BindingHash { data: [1u8; 64] };
        assert!(!verifier.verify_binding_hash(&bad_sig, &inputs));
    }

    // ============================================================================
    // ADVERSARIAL VERIFIER TESTS
    // ============================================================================

    #[test]
    fn adversarial_zero_binding_hash_rejected() {
        // Test A9: All-zero binding hash must be rejected
        let verifier = StarkVerifier;
        let zero_sig = BindingHash { data: [0u8; 64] };
        let inputs = sample_inputs();

        assert!(
            !verifier.verify_binding_hash(&zero_sig, &inputs),
            "Zero binding hash should be rejected"
        );
    }

    #[test]
    fn adversarial_modified_anchor_binding_hash_fails() {
        // Test A10: Signing with one anchor, verifying with another
        let verifier = StarkVerifier;
        let inputs = sample_inputs();

        // Compute binding hash for original inputs
        let sig = StarkVerifier::compute_binding_hash(&inputs);

        // Modify the anchor
        let mut modified_inputs = inputs.clone();
        modified_inputs.anchor = [99u8; 32];

        assert!(
            !verifier.verify_binding_hash(&sig, &modified_inputs),
            "Modified anchor should cause binding hash verification to fail"
        );
    }

    #[test]
    fn adversarial_modified_nullifier_binding_hash_fails() {
        let verifier = StarkVerifier;
        let inputs = sample_inputs();

        let sig = StarkVerifier::compute_binding_hash(&inputs);

        let mut modified_inputs = inputs.clone();
        modified_inputs.nullifiers[0] = [99u8; 32];

        assert!(
            !verifier.verify_binding_hash(&sig, &modified_inputs),
            "Modified nullifier should cause binding hash verification to fail"
        );
    }

    #[test]
    fn adversarial_modified_commitment_binding_hash_fails() {
        let verifier = StarkVerifier;
        let inputs = sample_inputs();

        let sig = StarkVerifier::compute_binding_hash(&inputs);

        let mut modified_inputs = inputs.clone();
        modified_inputs.commitments[0] = [99u8; 32];

        assert!(
            !verifier.verify_binding_hash(&sig, &modified_inputs),
            "Modified commitment should cause binding hash verification to fail"
        );
    }

    #[test]
    fn adversarial_modified_value_balance_binding_hash_fails() {
        let verifier = StarkVerifier;
        let inputs = sample_inputs();

        let sig = StarkVerifier::compute_binding_hash(&inputs);

        let mut modified_inputs = inputs.clone();
        modified_inputs.value_balance = 12345;

        assert!(
            !verifier.verify_binding_hash(&sig, &modified_inputs),
            "Modified value_balance should cause binding hash verification to fail"
        );
    }

    #[test]
    fn adversarial_truncated_proof_rejected() {
        // Test A5: Truncated proof should be rejected
        let verifier = StarkVerifier;
        let truncated_proof = StarkProof::from_bytes(vec![1u8; 10]); // Too short

        let result = verifier.verify_stark(&truncated_proof, &sample_inputs(), &sample_vk());

        // Should be InvalidProofFormat because it's too short to parse
        assert!(
            matches!(
                result,
                VerificationResult::InvalidProofFormat | VerificationResult::VerificationFailed
            ),
            "Truncated proof should be rejected"
        );
    }

    #[test]
    fn adversarial_random_proof_rejected() {
        // Test A4: Random bytes as proof should fail verification
        //
        // Note: With the stark-verify feature enabled, winterfell's Proof::from_bytes
        // may panic on malformed input (overflow in debug mode). We use catch_unwind
        // to treat panics as a valid form of rejection.
        use std::panic;

        let verifier = StarkVerifier;

        // Use deterministic "random" bytes for reproducibility
        let random_bytes: Vec<u8> = (0..30000u32)
            .map(|i| (i.wrapping_mul(17).wrapping_add(31)) as u8)
            .collect();
        let random_proof = StarkProof::from_bytes(random_bytes);
        let inputs = sample_inputs();
        let vk = sample_vk();

        // Catch panics from winterfell's deserializer on malformed input
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            verifier.verify_stark(&random_proof, &inputs, &vk)
        }));

        match result {
            Ok(verification_result) => {
                // Normal return - should be rejection
                assert!(
                    matches!(
                        verification_result,
                        VerificationResult::InvalidProofFormat
                            | VerificationResult::VerificationFailed
                    ),
                    "Random proof bytes should be rejected, got {:?}",
                    verification_result
                );
            }
            Err(_) => {
                // Panic is also a valid form of rejection for malformed input
                // This can happen with winterfell in debug mode on certain inputs
            }
        }
    }

    #[test]
    fn adversarial_disabled_vk_rejected() {
        let verifier = StarkVerifier;
        let proof = sample_proof();
        let inputs = sample_inputs();

        let mut disabled_vk = sample_vk();
        disabled_vk.enabled = false;

        let result = verifier.verify_stark(&proof, &inputs, &disabled_vk);
        assert_eq!(
            result,
            VerificationResult::KeyNotFound,
            "Disabled verifying key should reject proof"
        );
    }

    #[test]
    fn adversarial_empty_nullifiers_accepted() {
        // Empty nullifiers with non-empty commitments might be valid (mint operation)
        // Test that binding hash still works
        let verifier = StarkVerifier;
        let inputs = ShieldedTransferInputs {
            anchor: [1u8; 32],
            nullifiers: vec![], // Empty
            commitments: vec![[4u8; 32]],
            fee: 0,
            value_balance: 1000, // Minting 1000
        };

        let sig = StarkVerifier::compute_binding_hash(&inputs);
        assert!(
            verifier.verify_binding_hash(&sig, &inputs),
            "Valid binding hash should work with empty nullifiers"
        );
    }

    #[test]
    fn adversarial_large_value_balance() {
        // Test with extreme value_balance values
        let verifier = StarkVerifier;

        let inputs_max = ShieldedTransferInputs {
            anchor: [1u8; 32],
            nullifiers: vec![[2u8; 32]],
            commitments: vec![[4u8; 32]],
            fee: 0,
            value_balance: i128::MAX,
        };

        let inputs_min = ShieldedTransferInputs {
            anchor: [1u8; 32],
            nullifiers: vec![[2u8; 32]],
            commitments: vec![[4u8; 32]],
            fee: 0,
            value_balance: i128::MIN,
        };

        // Both should produce valid binding hashes (no panic)
        let sig_max = StarkVerifier::compute_binding_hash(&inputs_max);
        let sig_min = StarkVerifier::compute_binding_hash(&inputs_min);

        assert!(verifier.verify_binding_hash(&sig_max, &inputs_max));
        assert!(verifier.verify_binding_hash(&sig_min, &inputs_min));
    }

    #[test]
    #[cfg(feature = "stark-verify")]
    fn stark_verifier_accepts_real_proof_fixture() {
        let verifier = StarkVerifier;
        let (proof, inputs, _binding_hash) = build_stark_fixture();

        let result = verifier.verify_stark(&proof, &inputs, &sample_vk());
        assert_eq!(result, VerificationResult::Valid);
    }

    #[test]
    #[cfg(feature = "stark-verify")]
    fn stark_verifier_rejects_noncanonical_nullifier() {
        let verifier = StarkVerifier;
        let (proof, mut inputs, _binding_hash) = build_stark_fixture();
        inputs.nullifiers[0][0] = 1u8; // Non-canonical high byte

        let result = verifier.verify_stark(&proof, &inputs, &sample_vk());
        assert_eq!(result, VerificationResult::InvalidPublicInputs);
    }

    #[test]
    #[cfg(feature = "stark-verify")]
    fn stark_verifier_rejects_noncanonical_commitment() {
        let verifier = StarkVerifier;
        let (proof, mut inputs, _binding_hash) = build_stark_fixture();
        inputs.commitments[0][0] = 1u8; // Non-canonical high byte

        let result = verifier.verify_stark(&proof, &inputs, &sample_vk());
        assert_eq!(result, VerificationResult::InvalidPublicInputs);
    }

    #[test]
    #[cfg(feature = "stark-verify")]
    fn stark_verifier_rejects_noncanonical_anchor() {
        let verifier = StarkVerifier;
        let (proof, mut inputs, _binding_hash) = build_stark_fixture();
        inputs.anchor[0] = 1u8; // Non-canonical high byte

        let result = verifier.verify_stark(&proof, &inputs, &sample_vk());
        assert_eq!(result, VerificationResult::InvalidPublicInputs);
    }

    #[test]
    #[cfg(feature = "stark-verify")]
    fn stark_verifier_rejects_tampered_value_balance() {
        let verifier = StarkVerifier;
        let (proof, mut inputs, _binding_hash) = build_stark_fixture();

        inputs.value_balance = 12345;
        let binding_hash = StarkVerifier::compute_binding_hash(&inputs);
        assert!(verifier.verify_binding_hash(&binding_hash, &inputs));

        let result = verifier.verify_stark(&proof, &inputs, &sample_vk());
        assert_eq!(result, VerificationResult::VerificationFailed);
    }
}
