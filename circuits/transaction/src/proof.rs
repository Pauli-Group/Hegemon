//! Transaction proof structures and proving/verification functions.
//!
//! This module provides the main interface for creating and verifying
//! transaction proofs. It uses real STARK proofs via Plonky3.

use protocol_versioning::VersionBinding;
use serde::{Deserialize, Serialize};

use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS},
    error::TransactionCircuitError,
    hashing_pq::{bytes48_to_felts, Commitment},
    keys::{ProvingKey, VerifyingKey},
    public_inputs::{BalanceSlot, TransactionPublicInputs},
    trace::TransactionTrace,
    witness::TransactionWitness,
};

use crate::p3_prover::TransactionProverP3;
use crate::p3_verifier::verify_transaction_proof_bytes_p3;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use transaction_core::p3_air::TransactionPublicInputsP3;

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

/// Generate a real STARK proof for a transaction (Plonky3 backend).
pub fn prove(
    witness: &TransactionWitness,
    _proving_key: &ProvingKey,
) -> Result<TransactionProof, TransactionCircuitError> {
    witness.validate()?;

    let legacy_trace = TransactionTrace::from_witness(witness)?;
    let public_inputs = witness.public_inputs()?;

    let prover = TransactionProverP3::new();
    let stark_trace = prover.build_trace(witness).map_err(|e| {
        TransactionCircuitError::ConstraintViolation(Box::leak(
            format!("Trace building failed: {}", e).into_boxed_str(),
        ))
    })?;
    let stark_pub_inputs = prover.public_inputs(witness)?;
    let stark_proof = prover.prove_bytes(stark_trace, &stark_pub_inputs)?;

    let serialized_inputs = serialize_p3_inputs(&stark_pub_inputs);
    let nullifiers = public_inputs.nullifiers.clone();
    let commitments = public_inputs.commitments.clone();

    Ok(TransactionProof {
        nullifiers,
        commitments,
        balance_slots: legacy_trace.padded_balance_slots(),
        public_inputs,
        stark_proof,
        stark_public_inputs: Some(serialized_inputs),
    })
}

/// Verify a transaction proof.
///
/// If the proof has STARK proof bytes and public inputs, this performs real cryptographic verification.
/// Otherwise, it falls back to checking public input consistency (for legacy proofs).
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

    let stark_inputs = proof.stark_public_inputs.as_ref().expect("checked above");
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

    let stark_pub_inputs = TransactionPublicInputsP3 {
        input_flags,
        output_flags,
        nullifiers,
        commitments,
        fee: Goldilocks::from_u64(stark_inputs.fee),
        value_balance_sign: Goldilocks::from_u64(stark_inputs.value_balance_sign as u64),
        value_balance_magnitude: Goldilocks::from_u64(stark_inputs.value_balance_magnitude),
        merkle_root,
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
    };

    match verify_transaction_proof_bytes_p3(&proof.stark_proof, &stark_pub_inputs) {
        Ok(()) => Ok(VerificationReport { verified: true }),
        Err(e) => Err(TransactionCircuitError::ConstraintViolation(Box::leak(
            format!("STARK verification failed: {}", e).into_boxed_str(),
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
