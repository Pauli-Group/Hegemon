//! Transaction proof structures and proving/verification functions.
//!
//! This module provides the main interface for creating and verifying
//! transaction proofs. It uses real STARK proofs via Plonky3.

use protocol_versioning::VersionBinding;
use serde::{Deserialize, Serialize};
use synthetic_crypto::hashes::blake3_384;

use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS},
    error::TransactionCircuitError,
    hashing_pq::{bytes48_to_felts, Commitment},
    keys::{ProvingKey, VerifyingKey},
    public_inputs::{BalanceSlot, TransactionPublicInputs},
    trace::TransactionTrace,
    witness::TransactionWitness,
};

use crate::p3_prover::TransactionProofParams;
use crate::p3_prover::TransactionProverP3;
use crate::p3_verifier::verify_transaction_proof_bytes_p3;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use postcard::to_allocvec;
use transaction_core::p3_air::TransactionPublicInputsP3;
use transaction_core::p3_config::{FRI_LOG_BLOWUP, FRI_NUM_QUERIES, FRI_POW_BITS};

/// A transaction proof containing public inputs and the STARK proof bytes.
///
/// The `stark_proof` field contains the actual cryptographic proof.
/// The other fields are public inputs that can be verified against the proof.
///
/// For full STARK verification, use:
/// - `p3_verifier::verify_transaction_proof_bytes_p3()` with proper `TransactionPublicInputsP3`
/// - Or use `TransactionProverP3::prove()` and verify directly
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionProof {
    pub public_inputs: TransactionPublicInputs,
    #[serde(with = "crate::public_inputs::serde_vec_bytes48")]
    pub nullifiers: Vec<Commitment>,
    #[serde(with = "crate::public_inputs::serde_vec_bytes48")]
    pub commitments: Vec<Commitment>,
    pub balance_slots: Vec<BalanceSlot>,
    /// The actual STARK proof bytes (backend-specific format).
    /// This is the cryptographic proof that the transaction is valid.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stark_proof: Vec<u8>,
    /// STARK public inputs in serialized form for verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stark_public_inputs: Option<SerializedStarkInputs>,
}

/// Serialized STARK public inputs for verification.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerializedStarkInputs {
    pub input_flags: Vec<u8>,
    pub output_flags: Vec<u8>,
    pub fee: u64,
    pub value_balance_sign: u8,
    pub value_balance_magnitude: u64,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub merkle_root: Commitment,
    #[serde(default)]
    pub balance_slot_asset_ids: Vec<u64>,
    #[serde(default)]
    pub stablecoin_enabled: u8,
    #[serde(default)]
    pub stablecoin_asset_id: u64,
    #[serde(default)]
    pub stablecoin_policy_version: u32,
    #[serde(default)]
    pub stablecoin_issuance_sign: u8,
    #[serde(default)]
    pub stablecoin_issuance_magnitude: u64,
    #[serde(
        default = "default_bytes48",
        with = "crate::public_inputs::serde_bytes48"
    )]
    pub stablecoin_policy_hash: Commitment,
    #[serde(
        default = "default_bytes48",
        with = "crate::public_inputs::serde_bytes48"
    )]
    pub stablecoin_oracle_commitment: Commitment,
    #[serde(
        default = "default_bytes48",
        with = "crate::public_inputs::serde_bytes48"
    )]
    pub stablecoin_attestation_commitment: Commitment,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationReport {
    pub verified: bool,
}

impl TransactionProof {
    pub fn version_binding(&self) -> VersionBinding {
        self.public_inputs.version_binding()
    }

    /// Check if this proof has a real STARK proof attached.
    pub fn has_stark_proof(&self) -> bool {
        !self.stark_proof.is_empty()
    }
}

pub const TX_STATEMENT_HASH_DOMAIN: &[u8] = b"tx-statement-v1";
pub const TX_PROOF_DIGEST_DOMAIN: &[u8] = b"tx-proof-digest-v1";
pub const TX_PUBLIC_INPUTS_DIGEST_DOMAIN: &[u8] = b"tx-public-inputs-digest-v1";
pub const TX_VERIFIER_PROFILE_DOMAIN: &[u8] = b"hegemon.inline-tx-p3-profile.v1";

/// Reconstruct the Plonky3 public inputs from a transaction proof.
///
/// This is useful when callers need the STARK public inputs without re-verifying the proof.
pub fn stark_public_inputs_p3(
    proof: &TransactionProof,
) -> Result<TransactionPublicInputsP3, TransactionCircuitError> {
    let stark_inputs =
        proof
            .stark_public_inputs
            .as_ref()
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "missing STARK public inputs",
            ))?;

    let input_flags = stark_inputs
        .input_flags
        .iter()
        .map(|flag| Goldilocks::from_u64(*flag as u64))
        .collect();
    let output_flags = stark_inputs
        .output_flags
        .iter()
        .map(|flag| Goldilocks::from_u64(*flag as u64))
        .collect();

    let nullifiers = proof
        .nullifiers
        .iter()
        .map(|nf| {
            bytes48_to_felts(nf).ok_or(TransactionCircuitError::ConstraintViolation(
                "invalid PQ nullifier encoding",
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let commitments = proof
        .commitments
        .iter()
        .map(|cm| {
            bytes48_to_felts(cm).ok_or(TransactionCircuitError::ConstraintViolation(
                "invalid PQ commitment encoding",
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ciphertext_hashes = proof
        .public_inputs
        .ciphertext_hashes
        .iter()
        .map(|ct| {
            bytes48_to_felts(ct).ok_or(TransactionCircuitError::ConstraintViolation(
                "invalid ciphertext hash encoding",
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let merkle_root = bytes48_to_felts(&stark_inputs.merkle_root).ok_or(
        TransactionCircuitError::ConstraintViolation("invalid PQ merkle root encoding"),
    )?;
    let stablecoin_policy_hash = bytes48_to_felts(&stark_inputs.stablecoin_policy_hash).ok_or(
        TransactionCircuitError::ConstraintViolation("invalid stablecoin policy hash encoding"),
    )?;
    let stablecoin_oracle_commitment = bytes48_to_felts(&stark_inputs.stablecoin_oracle_commitment)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "invalid stablecoin oracle commitment encoding",
        ))?;
    let stablecoin_attestation_commitment = bytes48_to_felts(
        &stark_inputs.stablecoin_attestation_commitment,
    )
    .ok_or(TransactionCircuitError::ConstraintViolation(
        "invalid stablecoin attestation commitment encoding",
    ))?;
    let balance_slot_asset_ids = if stark_inputs.balance_slot_asset_ids.is_empty() {
        proof
            .balance_slots
            .iter()
            .map(|slot| slot.asset_id)
            .collect()
    } else {
        stark_inputs.balance_slot_asset_ids.clone()
    };
    if balance_slot_asset_ids.len() != BALANCE_SLOTS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "invalid balance slot asset count",
        ));
    }
    let balance_slot_assets = [
        Goldilocks::from_u64(balance_slot_asset_ids[0]),
        Goldilocks::from_u64(balance_slot_asset_ids[1]),
        Goldilocks::from_u64(balance_slot_asset_ids[2]),
        Goldilocks::from_u64(balance_slot_asset_ids[3]),
    ];

    Ok(TransactionPublicInputsP3 {
        input_flags,
        output_flags,
        nullifiers,
        commitments,
        ciphertext_hashes,
        fee: Goldilocks::from_u64(stark_inputs.fee),
        value_balance_sign: Goldilocks::from_u64(stark_inputs.value_balance_sign as u64),
        value_balance_magnitude: Goldilocks::from_u64(stark_inputs.value_balance_magnitude),
        merkle_root,
        balance_slot_assets,
        stablecoin_enabled: Goldilocks::from_u64(stark_inputs.stablecoin_enabled as u64),
        stablecoin_asset: Goldilocks::from_u64(stark_inputs.stablecoin_asset_id),
        stablecoin_policy_version: Goldilocks::from_u64(
            stark_inputs.stablecoin_policy_version as u64,
        ),
        stablecoin_issuance_sign: Goldilocks::from_u64(
            stark_inputs.stablecoin_issuance_sign as u64,
        ),
        stablecoin_issuance_magnitude: Goldilocks::from_u64(
            stark_inputs.stablecoin_issuance_magnitude,
        ),
        stablecoin_policy_hash,
        stablecoin_oracle_commitment,
        stablecoin_attestation_commitment,
    })
}

pub fn transaction_statement_hash(proof: &TransactionProof) -> [u8; 48] {
    let public = &proof.public_inputs;
    let mut message = Vec::new();
    message.extend_from_slice(TX_STATEMENT_HASH_DOMAIN);
    message.extend_from_slice(&public.merkle_root);
    for nf in &public.nullifiers {
        message.extend_from_slice(nf);
    }
    for cm in &public.commitments {
        message.extend_from_slice(cm);
    }
    for ct in &public.ciphertext_hashes {
        message.extend_from_slice(ct);
    }
    message.extend_from_slice(&public.native_fee.to_le_bytes());
    message.extend_from_slice(&public.value_balance.to_le_bytes());
    message.extend_from_slice(&public.balance_tag);
    message.extend_from_slice(&public.circuit_version.to_le_bytes());
    message.extend_from_slice(&public.crypto_suite.to_le_bytes());
    message.push(public.stablecoin.enabled as u8);
    message.extend_from_slice(&public.stablecoin.asset_id.to_le_bytes());
    message.extend_from_slice(&public.stablecoin.policy_hash);
    message.extend_from_slice(&public.stablecoin.oracle_commitment);
    message.extend_from_slice(&public.stablecoin.attestation_commitment);
    message.extend_from_slice(&public.stablecoin.issuance_delta.to_le_bytes());
    message.extend_from_slice(&public.stablecoin.policy_version.to_le_bytes());
    blake3_384(&message)
}

pub fn transaction_proof_digest(proof: &TransactionProof) -> [u8; 48] {
    let mut message = Vec::with_capacity(TX_PROOF_DIGEST_DOMAIN.len() + proof.stark_proof.len());
    message.extend_from_slice(TX_PROOF_DIGEST_DOMAIN);
    message.extend_from_slice(&proof.stark_proof);
    blake3_384(&message)
}

pub fn transaction_public_inputs_digest(
    proof: &TransactionProof,
) -> Result<[u8; 48], TransactionCircuitError> {
    let stark_inputs =
        proof
            .stark_public_inputs
            .as_ref()
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "missing STARK public inputs",
            ))?;
    let encoded = to_allocvec(stark_inputs).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to serialize STARK public inputs: {err}"
        ))
    })?;
    let mut message = Vec::with_capacity(TX_PUBLIC_INPUTS_DIGEST_DOMAIN.len() + encoded.len());
    message.extend_from_slice(TX_PUBLIC_INPUTS_DIGEST_DOMAIN);
    message.extend_from_slice(&encoded);
    Ok(blake3_384(&message))
}

pub fn transaction_verifier_profile_digest_for_version(version: VersionBinding) -> [u8; 48] {
    let mut message = Vec::new();
    message.extend_from_slice(TX_VERIFIER_PROFILE_DOMAIN);
    message.extend_from_slice(b"plonky3-transaction-proof");
    message.extend_from_slice(&version.circuit.to_le_bytes());
    message.extend_from_slice(&version.crypto.to_le_bytes());
    message.extend_from_slice(&(FRI_LOG_BLOWUP as u64).to_le_bytes());
    message.extend_from_slice(&(FRI_NUM_QUERIES as u64).to_le_bytes());
    message.extend_from_slice(&(FRI_POW_BITS as u64).to_le_bytes());
    blake3_384(&message)
}

pub fn transaction_verifier_profile_digest(proof: &TransactionProof) -> [u8; 48] {
    transaction_verifier_profile_digest_for_version(proof.version_binding())
}

/// Generate a real STARK proof for a transaction (Plonky3 backend).
pub fn prove(
    witness: &TransactionWitness,
    _proving_key: &ProvingKey,
) -> Result<TransactionProof, TransactionCircuitError> {
    prove_with_params(witness, _proving_key, TransactionProofParams::production())
}

pub fn prove_with_params(
    witness: &TransactionWitness,
    _proving_key: &ProvingKey,
    params: TransactionProofParams,
) -> Result<TransactionProof, TransactionCircuitError> {
    witness.validate()?;

    let trace = TransactionTrace::from_witness(witness)?;
    let public_inputs = witness.public_inputs()?;

    let prover = TransactionProverP3::new();
    let stark_trace = prover.build_trace(witness).map_err(|e| {
        TransactionCircuitError::ConstraintViolationOwned(format!("Trace building failed: {}", e))
    })?;
    let stark_pub_inputs = prover.public_inputs(witness)?;
    let stark_proof = prover.prove_bytes_with_params(stark_trace, &stark_pub_inputs, params)?;

    let serialized_inputs = serialize_p3_inputs(&stark_pub_inputs);
    let nullifiers = public_inputs.nullifiers.clone();
    let commitments = public_inputs.commitments.clone();

    Ok(TransactionProof {
        nullifiers,
        commitments,
        balance_slots: trace.padded_balance_slots(),
        public_inputs,
        stark_proof,
        stark_public_inputs: Some(serialized_inputs),
    })
}

/// Verify a transaction proof.
///
/// This performs real STARK proof verification and requires proof bytes plus public inputs.
pub fn verify(
    proof: &TransactionProof,
    _verifying_key: &VerifyingKey,
) -> Result<VerificationReport, TransactionCircuitError> {
    verify_with_p3(proof)
}
fn verify_with_p3(proof: &TransactionProof) -> Result<VerificationReport, TransactionCircuitError> {
    // Validate public input structure
    if proof.nullifiers.len() != MAX_INPUTS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "invalid PQ nullifier length",
        ));
    }
    if proof.commitments.len() != MAX_OUTPUTS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "invalid PQ commitment length",
        ));
    }
    if proof.public_inputs.ciphertext_hashes.len() != MAX_OUTPUTS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "invalid ciphertext hash length",
        ));
    }
    if proof.balance_slots.len() != BALANCE_SLOTS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "invalid balance slot length",
        ));
    }

    // Always validate balance slots against public_inputs
    // (STARK proofs don't cover balance_slots - they're verified separately)
    verify_balance_slots(proof)?;

    if proof.stark_proof.is_empty() || proof.stark_public_inputs.is_none() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "missing STARK proof bytes or public inputs",
        ));
    }

    let stark_pub_inputs = stark_public_inputs_p3(proof)?;

    match verify_transaction_proof_bytes_p3(&proof.stark_proof, &stark_pub_inputs) {
        Ok(()) => Ok(VerificationReport { verified: true }),
        Err(e) => Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "STARK verification failed: {}",
            e
        ))),
    }
}

fn serialize_p3_inputs(pub_inputs: &TransactionPublicInputsP3) -> SerializedStarkInputs {
    let input_flags = pub_inputs
        .input_flags
        .iter()
        .map(|flag| flag.as_canonical_u64() as u8)
        .collect();
    let output_flags = pub_inputs
        .output_flags
        .iter()
        .map(|flag| flag.as_canonical_u64() as u8)
        .collect();

    SerializedStarkInputs {
        input_flags,
        output_flags,
        fee: pub_inputs.fee.as_canonical_u64(),
        value_balance_sign: pub_inputs.value_balance_sign.as_canonical_u64() as u8,
        value_balance_magnitude: pub_inputs.value_balance_magnitude.as_canonical_u64(),
        merkle_root: hash_to_bytes48(&pub_inputs.merkle_root),
        balance_slot_asset_ids: pub_inputs
            .balance_slot_assets
            .iter()
            .map(|asset| asset.as_canonical_u64())
            .collect(),
        stablecoin_enabled: pub_inputs.stablecoin_enabled.as_canonical_u64() as u8,
        stablecoin_asset_id: pub_inputs.stablecoin_asset.as_canonical_u64(),
        stablecoin_policy_version: pub_inputs.stablecoin_policy_version.as_canonical_u64() as u32,
        stablecoin_issuance_sign: pub_inputs.stablecoin_issuance_sign.as_canonical_u64() as u8,
        stablecoin_issuance_magnitude: pub_inputs.stablecoin_issuance_magnitude.as_canonical_u64(),
        stablecoin_policy_hash: hash_to_bytes48(&pub_inputs.stablecoin_policy_hash),
        stablecoin_oracle_commitment: hash_to_bytes48(&pub_inputs.stablecoin_oracle_commitment),
        stablecoin_attestation_commitment: hash_to_bytes48(
            &pub_inputs.stablecoin_attestation_commitment,
        ),
    }
}

fn hash_to_bytes48(hash: &[Goldilocks; 6]) -> [u8; 48] {
    let mut out = [0u8; 48];
    for (idx, limb) in hash.iter().enumerate() {
        let start = idx * 8;
        out[start..start + 8].copy_from_slice(&limb.as_canonical_u64().to_be_bytes());
    }
    out
}

fn default_bytes48() -> Commitment {
    [0u8; 48]
}

/// Verify that balance_slots match public_inputs.balance_slots
fn verify_balance_slots(proof: &TransactionProof) -> Result<(), TransactionCircuitError> {
    use crate::constants::NATIVE_ASSET_ID;
    use crate::public_inputs::BalanceSlot;

    if proof.public_inputs.balance_slots.len() != proof.balance_slots.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "balance slot count mismatch",
        ));
    }

    let mut stablecoin_slot_seen = false;
    for (idx, expected) in proof.public_inputs.balance_slots.iter().enumerate() {
        let actual = proof
            .balance_slots
            .get(idx)
            .cloned()
            .unwrap_or(BalanceSlot {
                asset_id: u64::MAX,
                delta: 0,
            });

        if actual.asset_id != expected.asset_id || actual.delta != expected.delta {
            return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
        }

        // For native asset, verify delta equals fee
        if expected.asset_id == NATIVE_ASSET_ID {
            let expected_native =
                proof.public_inputs.native_fee as i128 - proof.public_inputs.value_balance;
            if expected.delta != expected_native {
                return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
            }
        } else if proof.public_inputs.stablecoin.enabled
            && expected.asset_id == proof.public_inputs.stablecoin.asset_id
        {
            stablecoin_slot_seen = true;
            if expected.delta != proof.public_inputs.stablecoin.issuance_delta {
                return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
            }
        } else if expected.delta != 0 {
            // Non-native assets must balance to zero
            return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
        }
    }

    if proof.public_inputs.stablecoin.enabled && !stablecoin_slot_seen {
        return Err(TransactionCircuitError::BalanceMismatch(
            proof.public_inputs.stablecoin.asset_id,
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_inputs::TransactionPublicInputs;

    fn dummy_serialized_inputs() -> SerializedStarkInputs {
        SerializedStarkInputs {
            input_flags: vec![0; MAX_INPUTS],
            output_flags: vec![0; MAX_OUTPUTS],
            fee: 0,
            value_balance_sign: 0,
            value_balance_magnitude: 0,
            merkle_root: [0u8; 48],
            balance_slot_asset_ids: vec![0, u64::MAX, u64::MAX, u64::MAX],
            stablecoin_enabled: 0,
            stablecoin_asset_id: 0,
            stablecoin_policy_version: 0,
            stablecoin_issuance_sign: 0,
            stablecoin_issuance_magnitude: 0,
            stablecoin_policy_hash: [0u8; 48],
            stablecoin_oracle_commitment: [0u8; 48],
            stablecoin_attestation_commitment: [0u8; 48],
        }
    }

    fn dummy_proof() -> TransactionProof {
        let public_inputs = TransactionPublicInputs::default();
        TransactionProof {
            nullifiers: public_inputs.nullifiers.clone(),
            commitments: public_inputs.commitments.clone(),
            balance_slots: public_inputs.balance_slots.clone(),
            public_inputs,
            stark_proof: vec![1, 2, 3, 4],
            stark_public_inputs: Some(dummy_serialized_inputs()),
        }
    }

    #[test]
    fn verifier_profile_digest_matches_version_helper() {
        let proof = dummy_proof();
        assert_eq!(
            transaction_verifier_profile_digest(&proof),
            transaction_verifier_profile_digest_for_version(proof.version_binding())
        );
    }

    #[test]
    fn statement_hash_changes_when_fee_changes() {
        let proof = dummy_proof();
        let mut changed = proof.clone();
        changed.public_inputs.native_fee = 9;
        assert_ne!(
            transaction_statement_hash(&proof),
            transaction_statement_hash(&changed)
        );
    }

    #[test]
    fn public_inputs_digest_requires_serialized_inputs() {
        let mut proof = dummy_proof();
        proof.stark_public_inputs = None;
        let error = transaction_public_inputs_digest(&proof).expect_err("missing inputs fail");
        assert!(error.to_string().contains("missing STARK public inputs"));
    }
}
