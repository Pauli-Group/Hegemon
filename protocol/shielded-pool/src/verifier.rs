use alloc::vec::Vec;

use blake2::digest::{Update as BlakeUpdate, VariableOutput};
use blake2::Blake2bVar;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

use crate::types::{BindingHash, StablecoinPolicyBinding, StarkProof};

#[derive(
    Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, MaxEncodedLen, TypeInfo,
)]
pub struct VerifyingKey {
    pub id: u32,
    pub enabled: bool,
    pub air_hash: [u8; 32],
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

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct ShieldedTransferInputs {
    pub anchor: [u8; 48],
    pub nullifiers: Vec<[u8; 48]>,
    pub commitments: Vec<[u8; 48]>,
    pub ciphertext_hashes: Vec<[u8; 48]>,
    pub balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
    pub fee: u64,
    pub value_balance: i128,
    pub stablecoin: Option<StablecoinPolicyBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    Valid,
    InvalidProofFormat,
    InvalidPublicInputs,
    VerificationFailed,
    KeyNotFound,
    InvalidBindingHash,
}

pub trait ProofVerifier {
    fn verify_stark(
        &self,
        proof: &StarkProof,
        inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult;

    fn verify_binding_hash(
        &self,
        binding_hash: &BindingHash,
        inputs: &ShieldedTransferInputs,
    ) -> bool;
}

#[derive(Clone, Debug, Default)]
pub struct StarkVerifier;

impl StarkVerifier {
    pub const MAX_INPUTS: usize = transaction_core::constants::MAX_INPUTS;
    pub const MAX_OUTPUTS: usize = transaction_core::constants::MAX_OUTPUTS;
    const BINDING_HASH_DOMAIN: &'static [u8] = b"binding-hash-v1";

    pub fn compute_expected_air_hash() -> [u8; 32] {
        transaction_core::expected_air_hash()
    }

    pub fn circuit_version() -> u32 {
        transaction_core::CIRCUIT_VERSION
    }

    pub fn create_verifying_key(id: u32) -> VerifyingKey {
        VerifyingKey {
            id,
            enabled: true,
            air_hash: Self::compute_expected_air_hash(),
            circuit_id: Self::compute_expected_air_hash(),
        }
    }

    pub fn encode_public_inputs(inputs: &ShieldedTransferInputs) -> Vec<[u8; 48]> {
        let mut encoded = Vec::new();
        encoded.push(inputs.anchor);
        encoded.extend(inputs.nullifiers.iter().copied());
        encoded.extend(inputs.commitments.iter().copied());
        encoded.extend(inputs.ciphertext_hashes.iter().copied());
        encoded.push(Self::encode_u64(inputs.fee));

        let (sign, magnitude) = Self::signed_parts(inputs.value_balance).unwrap_or((0u8, 0u64));
        encoded.push(Self::encode_u8(sign));
        encoded.push(Self::encode_u64(magnitude));

        for asset_id in inputs.balance_slot_asset_ids {
            encoded.push(Self::encode_u64(asset_id));
        }

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

    pub fn compute_binding_hash(inputs: &ShieldedTransferInputs) -> BindingHash {
        let message = Self::binding_hash_message(inputs);
        let data = Self::binding_hash_from_message(&message, blake2_256);
        BindingHash { data }
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

    fn binding_hash_message(inputs: &ShieldedTransferInputs) -> Vec<u8> {
        let mut message = Vec::with_capacity(
            48 + inputs.nullifiers.len() * 48
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
        for asset_id in inputs.balance_slot_asset_ids {
            message.extend_from_slice(&asset_id.to_le_bytes());
        }
        message
    }

    fn binding_hash_from_message(message: &[u8], blake2_256: fn(&[u8]) -> [u8; 32]) -> [u8; 64] {
        let mut msg0 = Vec::with_capacity(Self::BINDING_HASH_DOMAIN.len() + 1 + message.len());
        msg0.extend_from_slice(Self::BINDING_HASH_DOMAIN);
        msg0.push(0);
        msg0.extend_from_slice(message);
        let hash0 = blake2_256(&msg0);

        let mut msg1 = Vec::with_capacity(Self::BINDING_HASH_DOMAIN.len() + 1 + message.len());
        msg1.extend_from_slice(Self::BINDING_HASH_DOMAIN);
        msg1.push(1);
        msg1.extend_from_slice(message);
        let hash1 = blake2_256(&msg1);

        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&hash0);
        out[32..].copy_from_slice(&hash1);
        out
    }
}

impl ProofVerifier for StarkVerifier {
    fn verify_stark(
        &self,
        proof: &StarkProof,
        _inputs: &ShieldedTransferInputs,
        vk: &VerifyingKey,
    ) -> VerificationResult {
        if !vk.enabled {
            return VerificationResult::KeyNotFound;
        }
        if proof.is_empty() {
            return VerificationResult::InvalidProofFormat;
        }
        VerificationResult::VerificationFailed
    }

    fn verify_binding_hash(
        &self,
        binding_hash: &BindingHash,
        inputs: &ShieldedTransferInputs,
    ) -> bool {
        binding_hash.data == Self::compute_binding_hash(inputs).data
    }
}

fn blake2_256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("fixed output buffer has requested length");
    out
}
