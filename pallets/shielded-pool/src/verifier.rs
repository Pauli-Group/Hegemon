//! ZK proof verifier for shielded transactions.
//!
//! This module handles verification of STARK proofs for shielded transfers.
//! The proving system is transparent (no trusted setup) and uses only
//! hash-based cryptography, making it post-quantum secure.
//!
//! ## Design
//!
//! - Uses Plonky3-based STARK proofs (FRI IOP, transparent)
//! - All operations are hash-based (Blake3/Poseidon)
//! - Value balance verified in-circuit
//!
//! ## Features
//!
//! - Real verification is always enabled (Plonky3 backend).

use p3_field::PrimeCharacteristicRing;
use transaction_core::p3_config::FRI_NUM_QUERIES;

use crate::types::{BindingHash, StablecoinPolicyBinding, StarkProof};
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

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
    pub anchor: [u8; 48],
    /// Nullifiers for spent notes.
    pub nullifiers: Vec<[u8; 48]>,
    /// Commitments for new notes.
    pub commitments: Vec<[u8; 48]>,
    /// Ciphertext hashes for new notes.
    pub ciphertext_hashes: Vec<[u8; 48]>,
    /// Native fee encoded in the circuit.
    pub fee: u64,
    /// Net value balance (transparent component).
    pub value_balance: i128,
    /// Optional stablecoin policy binding (required for issuance/burn).
    pub stablecoin: Option<StablecoinPolicyBinding>,
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
    fn verify_binding_hash(
        &self,
        binding_hash: &BindingHash,
        inputs: &ShieldedTransferInputs,
    ) -> bool;
}

/// Accept-all proof verifier for testing/development.
///
/// WARNING: This should NEVER be used in production!
///
/// This type is only available when the `std` feature is enabled AND
/// the `production` feature is NOT enabled. This prevents accidental
/// use in release binaries.
#[cfg(all(feature = "std", any(test, not(feature = "production"))))]
#[derive(Clone, Debug, Default)]
pub struct AcceptAllProofs;

#[cfg(all(feature = "std", any(test, not(feature = "production"))))]
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

    fn verify_binding_hash(
        &self,
        _binding_hash: &BindingHash,
        _inputs: &ShieldedTransferInputs,
    ) -> bool {
        true
    }
}

/// Reject-all proof verifier for testing.
///
/// This type is only available in test/dev builds.
#[cfg(all(feature = "std", any(test, not(feature = "production"))))]
#[derive(Clone, Debug, Default)]
pub struct RejectAllProofs;

#[cfg(all(feature = "std", any(test, not(feature = "production"))))]
impl ProofVerifier for RejectAllProofs {
    fn verify_stark(
        &self,
        _proof: &StarkProof,
        _inputs: &ShieldedTransferInputs,
        _vk: &VerifyingKey,
    ) -> VerificationResult {
        VerificationResult::VerificationFailed
    }

    fn verify_binding_hash(
        &self,
        _binding_hash: &BindingHash,
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
/// Performs Plonky3 STARK verification over the transaction AIR.
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
    pub fn encode_public_inputs(inputs: &ShieldedTransferInputs) -> Vec<[u8; 48]> {
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

        // Ciphertext hashes
        for ct in &inputs.ciphertext_hashes {
            encoded.push(*ct);
        }

        // Fee (u64, canonical field encoding)
        encoded.push(Self::encode_u64(inputs.fee));

        // Value balance (encoded as two field elements for sign and magnitude)
        let (sign, magnitude) = Self::signed_parts(inputs.value_balance).unwrap_or((0u8, 0u64));
        encoded.push(Self::encode_u8(sign));
        encoded.push(Self::encode_u64(magnitude));

        let (
            stablecoin_enabled,
            stablecoin_asset,
            stablecoin_policy_version,
            issuance_sign,
            issuance_mag,
            policy_hash,
            oracle_commitment,
            attestation_commitment,
        ) = match inputs.stablecoin.as_ref() {
            Some(binding) => {
                let (sign, mag) = Self::signed_parts(binding.issuance_delta).unwrap_or((0u8, 0u64));
                (
                    1u8,
                    binding.asset_id,
                    u64::from(binding.policy_version),
                    sign,
                    mag,
                    binding.policy_hash,
                    binding.oracle_commitment,
                    binding.attestation_commitment,
                )
            }
            None => (0u8, 0u64, 0u64, 0u8, 0u64, [0u8; 48], [0u8; 48], [0u8; 48]),
        };

        encoded.push(Self::encode_u8(stablecoin_enabled));
        encoded.push(Self::encode_u64(stablecoin_asset));
        encoded.push(Self::encode_u64(stablecoin_policy_version));
        encoded.push(Self::encode_u8(issuance_sign));
        encoded.push(Self::encode_u64(issuance_mag));

        encoded.push(policy_hash);
        encoded.push(oracle_commitment);
        encoded.push(attestation_commitment);

        encoded
    }

    fn encode_u64(value: u64) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[40..48].copy_from_slice(&value.to_be_bytes());
        out
    }

    fn encode_u8(value: u8) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[47] = value;
        out
    }

    fn signed_parts(value: i128) -> Option<(u8, u64)> {
        let sign = if value < 0 { 1u8 } else { 0u8 };
        let magnitude = value.unsigned_abs();
        if magnitude > u128::from(u64::MAX) {
            return None;
        }
        Some((sign, magnitude as u64))
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
        let min_size = proof_structure::min_proof_size(FRI_NUM_QUERIES, num_fri_layers);
        if data.len() < min_size {
            return false;
        }

        true
    }

    /// Compute a challenge hash for FRI verification.
    /// This binds the proof to the public inputs.
    #[allow(dead_code)] // Debug-only helper.
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

    fn is_canonical_felt(bytes: &[u8; 48]) -> bool {
        transaction_core::hashing_pq::is_canonical_bytes48(bytes)
    }

    fn validate_public_inputs(inputs: &ShieldedTransferInputs) -> bool {
        if inputs.nullifiers.len() > Self::MAX_INPUTS {
            return false;
        }
        if inputs.commitments.len() > Self::MAX_OUTPUTS {
            return false;
        }
        if inputs.ciphertext_hashes.len() > Self::MAX_OUTPUTS {
            return false;
        }
        if inputs.ciphertext_hashes.len() != inputs.commitments.len() {
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
            .any(|nf| !Self::is_canonical_felt(nf) || *nf == [0u8; 48])
        {
            return false;
        }
        if inputs
            .commitments
            .iter()
            .any(|cm| !Self::is_canonical_felt(cm) || *cm == [0u8; 48])
        {
            return false;
        }
        if inputs
            .ciphertext_hashes
            .iter()
            .any(|ct| !Self::is_canonical_felt(ct))
        {
            return false;
        }
        if (inputs.fee as u128) >= transaction_core::constants::FIELD_MODULUS {
            return false;
        }
        if Self::signed_parts(inputs.value_balance).is_none() {
            return false;
        }
        if let Some(binding) = inputs.stablecoin.as_ref() {
            if binding.asset_id == transaction_core::constants::NATIVE_ASSET_ID
                || binding.asset_id == u64::MAX
            {
                return false;
            }
            if !Self::is_canonical_felt(&binding.policy_hash)
                || !Self::is_canonical_felt(&binding.oracle_commitment)
                || !Self::is_canonical_felt(&binding.attestation_commitment)
            {
                return false;
            }
            if Self::signed_parts(binding.issuance_delta).is_none() {
                return false;
            }
        }
        true
    }
}

impl ProofVerifier for StarkVerifier {
    fn verify_stark(
        &self,
        proof: &StarkProof,
        inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult {
        if !vk.enabled {
            return VerificationResult::KeyNotFound;
        }

        if !Self::validate_public_inputs(inputs) {
            return VerificationResult::InvalidPublicInputs;
        }

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

        if proof.is_empty() {
            return VerificationResult::InvalidProofFormat;
        }

        let pub_inputs = match Self::convert_public_inputs_p3(inputs) {
            Some(pub_inputs) => pub_inputs,
            None => return VerificationResult::InvalidPublicInputs,
        };

        match transaction_core::p3_verifier::verify_transaction_proof_bytes_p3(
            &proof.data,
            &pub_inputs,
        ) {
            Ok(()) => VerificationResult::Valid,
            Err(transaction_core::p3_verifier::TransactionVerifyErrorP3::InvalidProofFormat) => {
                VerificationResult::InvalidProofFormat
            }
            Err(transaction_core::p3_verifier::TransactionVerifyErrorP3::InvalidPublicInputs(
                _,
            )) => VerificationResult::InvalidPublicInputs,
            Err(transaction_core::p3_verifier::TransactionVerifyErrorP3::VerificationFailed(
                err,
            )) => {
                log::info!(target: "shielded-pool", "  STARK verifier error: {:?}", err);
                VerificationResult::VerificationFailed
            }
        }
    }

    fn verify_binding_hash(
        &self,
        binding_hash: &BindingHash,
        inputs: &ShieldedTransferInputs,
    ) -> bool {
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
            48
                + inputs.nullifiers.len() * 48
                + inputs.commitments.len() * 48
                + inputs.ciphertext_hashes.len() * 48
                + 24,
        );
        message.extend_from_slice(&inputs.anchor);
        for nf in &inputs.nullifiers {
            message.extend_from_slice(nf);
        }
        for cm in &inputs.commitments {
            message.extend_from_slice(cm);
        }
        for ct in &inputs.ciphertext_hashes {
            message.extend_from_slice(ct);
        }
        message.extend_from_slice(&inputs.fee.to_le_bytes());
        message.extend_from_slice(&inputs.value_balance.to_le_bytes());
        message
    }

    fn binding_hash_from_message(message: &[u8], blake2_256: fn(&[u8]) -> [u8; 32]) -> [u8; 64] {
        let mut msg0 =
            sp_std::vec::Vec::with_capacity(Self::BINDING_HASH_DOMAIN.len() + 1 + message.len());
        msg0.extend_from_slice(Self::BINDING_HASH_DOMAIN);
        msg0.push(0);
        msg0.extend_from_slice(message);
        let hash0 = blake2_256(&msg0);

        let mut msg1 =
            sp_std::vec::Vec::with_capacity(Self::BINDING_HASH_DOMAIN.len() + 1 + message.len());
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

    fn convert_public_inputs_p3(
        inputs: &ShieldedTransferInputs,
    ) -> Option<transaction_core::TransactionPublicInputsP3> {
        let mut input_flags = Vec::with_capacity(Self::MAX_INPUTS);
        let mut nullifiers = Vec::with_capacity(Self::MAX_INPUTS);
        for nf in inputs.nullifiers.iter().take(Self::MAX_INPUTS) {
            let felt = transaction_core::hashing_pq::bytes48_to_felts(nf)?;
            input_flags.push(transaction_core::Felt::ONE);
            nullifiers.push(felt);
        }
        while nullifiers.len() < Self::MAX_INPUTS {
            nullifiers.push([transaction_core::Felt::ZERO; 6]);
            input_flags.push(transaction_core::Felt::ZERO);
        }

        let mut output_flags = Vec::with_capacity(Self::MAX_OUTPUTS);
        let mut commitments = Vec::with_capacity(Self::MAX_OUTPUTS);
        for cm in inputs.commitments.iter().take(Self::MAX_OUTPUTS) {
            let felt = transaction_core::hashing_pq::bytes48_to_felts(cm)?;
            output_flags.push(transaction_core::Felt::ONE);
            commitments.push(felt);
        }
        while commitments.len() < Self::MAX_OUTPUTS {
            commitments.push([transaction_core::Felt::ZERO; 6]);
            output_flags.push(transaction_core::Felt::ZERO);
        }

        let mut ciphertext_hashes = Vec::with_capacity(Self::MAX_OUTPUTS);
        for ct in inputs.ciphertext_hashes.iter().take(Self::MAX_OUTPUTS) {
            let felt = transaction_core::hashing_pq::bytes48_to_felts(ct)?;
            ciphertext_hashes.push(felt);
        }
        while ciphertext_hashes.len() < Self::MAX_OUTPUTS {
            ciphertext_hashes.push([transaction_core::Felt::ZERO; 6]);
        }

        let merkle_root = transaction_core::hashing_pq::bytes48_to_felts(&inputs.anchor)?;

        let (value_balance_sign, value_balance_magnitude) =
            transaction_core::hashing_pq::signed_parts(inputs.value_balance)?;

        let (
            stablecoin_enabled,
            stablecoin_asset,
            stablecoin_policy_version,
            stablecoin_issuance_sign,
            stablecoin_issuance_magnitude,
            stablecoin_policy_hash,
            stablecoin_oracle_commitment,
            stablecoin_attestation_commitment,
        ) = match inputs.stablecoin.as_ref() {
            Some(binding) => {
                let (issuance_sign, issuance_mag) =
                    transaction_core::hashing_pq::signed_parts(binding.issuance_delta)?;
                let policy_hash =
                    transaction_core::hashing_pq::bytes48_to_felts(&binding.policy_hash)?;
                let oracle_commitment =
                    transaction_core::hashing_pq::bytes48_to_felts(&binding.oracle_commitment)?;
                let attestation_commitment = transaction_core::hashing_pq::bytes48_to_felts(
                    &binding.attestation_commitment,
                )?;
                (
                    transaction_core::Felt::ONE,
                    transaction_core::Felt::from_u64(binding.asset_id),
                    transaction_core::Felt::from_u64(u64::from(binding.policy_version)),
                    issuance_sign,
                    issuance_mag,
                    policy_hash,
                    oracle_commitment,
                    attestation_commitment,
                )
            }
            None => (
                transaction_core::Felt::ZERO,
                transaction_core::Felt::ZERO,
                transaction_core::Felt::ZERO,
                transaction_core::Felt::ZERO,
                transaction_core::Felt::ZERO,
                [transaction_core::Felt::ZERO; 6],
                [transaction_core::Felt::ZERO; 6],
                [transaction_core::Felt::ZERO; 6],
            ),
        };

        Some(transaction_core::TransactionPublicInputsP3 {
            input_flags,
            output_flags,
            nullifiers,
            commitments,
            ciphertext_hashes,
            fee: transaction_core::Felt::from_u64(inputs.fee),
            value_balance_sign,
            value_balance_magnitude,
            merkle_root,
            stablecoin_enabled,
            stablecoin_asset,
            stablecoin_policy_version,
            stablecoin_issuance_sign,
            stablecoin_issuance_magnitude,
            stablecoin_policy_hash,
            stablecoin_oracle_commitment,
            stablecoin_attestation_commitment,
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
    pub anchor: [u8; 48],
    /// All nullifiers across all transactions in the batch.
    pub nullifiers: Vec<[u8; 48]>,
    /// All commitments across all transactions in the batch.
    pub commitments: Vec<[u8; 48]>,
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
#[cfg(all(feature = "std", any(test, not(feature = "production"))))]
#[derive(Clone, Debug, Default)]
pub struct AcceptAllBatchProofs;

#[cfg(all(feature = "std", any(test, not(feature = "production"))))]
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

        let has_active_nullifier = inputs.nullifiers.iter().any(|nf| *nf != [0u8; 48]);
        if !has_active_nullifier {
            return BatchVerificationResult::InvalidPublicInputs;
        }

        if inputs.total_fee >= transaction_core::constants::FIELD_MODULUS {
            return BatchVerificationResult::InvalidPublicInputs;
        }

        #[cfg(feature = "batch-proofs")]
        {
            use batch_circuit::{
                verify_batch_proof_bytes, BatchCircuitError,
                BatchPublicInputs as CircuitBatchPublicInputs, MAX_BATCH_SIZE,
            };
            use transaction_core::hashing_pq::bytes48_to_felts;

            let anchor = match bytes48_to_felts(&inputs.anchor) {
                Some(value) => value,
                None => return BatchVerificationResult::InvalidPublicInputs,
            };

            let mut nullifiers = Vec::with_capacity(inputs.nullifiers.len());
            for nf in &inputs.nullifiers {
                let value = match bytes48_to_felts(nf) {
                    Some(value) => value,
                    None => return BatchVerificationResult::InvalidPublicInputs,
                };
                nullifiers.push(value);
            }

            let mut commitments = Vec::with_capacity(inputs.commitments.len());
            for cm in &inputs.commitments {
                let value = match bytes48_to_felts(cm) {
                    Some(value) => value,
                    None => return BatchVerificationResult::InvalidPublicInputs,
                };
                commitments.push(value);
            }

            let mut tx_active = Vec::with_capacity(MAX_BATCH_SIZE);
            for idx in 0..MAX_BATCH_SIZE {
                let active = idx < inputs.batch_size as usize;
                tx_active.push(if active {
                    transaction_core::Felt::ONE
                } else {
                    transaction_core::Felt::ZERO
                });
            }

            let total_fee = transaction_core::Felt::from_u64(inputs.total_fee as u64);
            let batch_inputs = CircuitBatchPublicInputs {
                batch_size: inputs.batch_size,
                anchor,
                tx_active,
                nullifiers,
                commitments,
                total_fee,
                circuit_version: transaction_core::CIRCUIT_VERSION,
            };

            match verify_batch_proof_bytes(&proof.data, &batch_inputs) {
                Ok(()) => BatchVerificationResult::Valid,
                Err(err) => match err {
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
                },
            }
        }

        #[cfg(not(feature = "batch-proofs"))]
        {
            BatchVerificationResult::InvalidProofFormat
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> ShieldedTransferInputs {
        fn canonical_byte(value: u8) -> [u8; 48] {
            let mut out = [0u8; 48];
            out[47] = value;
            out
        }

        ShieldedTransferInputs {
            anchor: canonical_byte(1),
            nullifiers: vec![canonical_byte(2), canonical_byte(3)],
            commitments: vec![canonical_byte(4), canonical_byte(5)],
            ciphertext_hashes: vec![canonical_byte(6), canonical_byte(7)],
            fee: 0,
            value_balance: 0,
            stablecoin: None,
        }
    }

    fn sample_proof() -> StarkProof {
        StarkProof::from_bytes(vec![1u8; 1024])
    }

    fn sample_vk() -> VerifyingKey {
        StarkVerifier::create_verifying_key(0)
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
        assert_eq!(encoded.len(), 16);
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
        modified_inputs.anchor = [99u8; 48];

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
        modified_inputs.nullifiers[0] = [99u8; 48];

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
        modified_inputs.commitments[0] = [99u8; 48];

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

        let verifier = StarkVerifier;

        // Use deterministic "random" bytes for reproducibility
        let random_bytes: Vec<u8> = (0..30000u32)
            .map(|i| (i.wrapping_mul(17).wrapping_add(31)) as u8)
            .collect();
        let random_proof = StarkProof::from_bytes(random_bytes);
        let inputs = sample_inputs();
        let vk = sample_vk();

        let verification_result = verifier.verify_stark(&random_proof, &inputs, &vk);
        assert!(
            matches!(
                verification_result,
                VerificationResult::InvalidProofFormat | VerificationResult::VerificationFailed
            ),
            "Random proof bytes should be rejected, got {:?}",
            verification_result
        );
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
            anchor: [1u8; 48],
            nullifiers: vec![], // Empty
            commitments: vec![[4u8; 48]],
            ciphertext_hashes: vec![[5u8; 48]],
            fee: 0,
            value_balance: 1000, // Minting 1000
            stablecoin: None,
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
            anchor: [1u8; 48],
            nullifiers: vec![[2u8; 48]],
            commitments: vec![[4u8; 48]],
            ciphertext_hashes: vec![[5u8; 48]],
            fee: 0,
            value_balance: i128::MAX,
            stablecoin: None,
        };

        let inputs_min = ShieldedTransferInputs {
            anchor: [1u8; 48],
            nullifiers: vec![[2u8; 48]],
            commitments: vec![[4u8; 48]],
            ciphertext_hashes: vec![[5u8; 48]],
            fee: 0,
            value_balance: i128::MIN,
            stablecoin: None,
        };

        // Both should produce valid binding hashes (no panic)
        let sig_max = StarkVerifier::compute_binding_hash(&inputs_max);
        let sig_min = StarkVerifier::compute_binding_hash(&inputs_min);

        assert!(verifier.verify_binding_hash(&sig_max, &inputs_max));
        assert!(verifier.verify_binding_hash(&sig_min, &inputs_min));
    }
}
