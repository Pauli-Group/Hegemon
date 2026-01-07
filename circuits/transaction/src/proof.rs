//! Transaction proof structures and proving/verification functions.
//!
//! This module provides the main interface for creating and verifying
//! transaction proofs. It uses real STARK proofs via winterfell or Plonky3.

use protocol_versioning::VersionBinding;
use serde::{Deserialize, Serialize};

use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS},
    error::TransactionCircuitError,
    hashing::{bytes32_to_felts, Commitment, Felt},
    keys::{ProvingKey, VerifyingKey},
    public_inputs::{BalanceSlot, TransactionPublicInputs},
    trace::TransactionTrace,
    witness::TransactionWitness,
};

#[cfg(all(feature = "winterfell-legacy", not(feature = "plonky3")))]
use crate::hashing::felts_to_bytes32;
#[cfg(all(feature = "winterfell-legacy", not(feature = "plonky3")))]
use crate::stark_prover::TransactionProverStark;
#[cfg(all(feature = "winterfell-legacy", not(feature = "plonky3")))]
use crate::stark_verifier::verify_transaction_proof_bytes;
#[cfg(all(
    feature = "winterfell-legacy",
    feature = "rpo-fiat-shamir",
    not(feature = "plonky3")
))]
use crate::stark_verifier::verify_transaction_proof_bytes_rpo;
#[cfg(all(feature = "winterfell-legacy", not(feature = "plonky3")))]
use crate::stark_verifier::TransactionVerifyError;
#[cfg(all(
    feature = "winterfell-legacy",
    not(feature = "stark-fast"),
    not(feature = "plonky3")
))]
use crate::stark_prover::default_proof_options;
#[cfg(all(feature = "winterfell-legacy", feature = "stark-fast", not(feature = "plonky3")))]
use crate::stark_prover::fast_proof_options;

#[cfg(feature = "plonky3")]
use crate::p3_prover::TransactionProverP3;
#[cfg(feature = "plonky3")]
use crate::p3_verifier::verify_transaction_proof_bytes_p3;
#[cfg(feature = "plonky3")]
use p3_field::{PrimeCharacteristicRing, PrimeField64};
#[cfg(feature = "plonky3")]
use p3_goldilocks::Goldilocks;
#[cfg(feature = "plonky3")]
use transaction_core::p3_air::TransactionPublicInputsP3;

/// A transaction proof containing public inputs and the STARK proof bytes.
///
/// The `stark_proof` field contains the actual cryptographic proof.
/// The other fields are public inputs that can be verified against the proof.
///
/// For full STARK verification, use:
/// - `stark_verifier::verify_transaction_proof_bytes()` with proper `TransactionPublicInputsStark`
/// - Or use `StarkProver::prove_transaction()` and verify directly
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionProof {
    pub public_inputs: TransactionPublicInputs,
    #[serde(with = "crate::public_inputs::serde_vec_bytes32")]
    pub nullifiers: Vec<Commitment>,
    #[serde(with = "crate::public_inputs::serde_vec_bytes32")]
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
    #[serde(with = "crate::public_inputs::serde_bytes32")]
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
    #[serde(default, with = "crate::public_inputs::serde_bytes32")]
    pub stablecoin_policy_hash: Commitment,
    #[serde(default, with = "crate::public_inputs::serde_bytes32")]
    pub stablecoin_oracle_commitment: Commitment,
    #[serde(default, with = "crate::public_inputs::serde_bytes32")]
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
#[cfg(feature = "plonky3")]
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
    let nullifiers = stark_pub_inputs
        .nullifiers
        .iter()
        .map(hash_to_bytes32)
        .collect();
    let commitments = stark_pub_inputs
        .commitments
        .iter()
        .map(hash_to_bytes32)
        .collect();

    Ok(TransactionProof {
        nullifiers,
        commitments,
        balance_slots: legacy_trace.padded_balance_slots(),
        public_inputs,
        stark_proof,
        stark_public_inputs: Some(serialized_inputs),
    })
}

/// Generate a real STARK proof for a transaction (Winterfell backend).
#[cfg(all(not(feature = "plonky3"), feature = "winterfell-legacy"))]
pub fn prove(
    witness: &TransactionWitness,
    _proving_key: &ProvingKey,
) -> Result<TransactionProof, TransactionCircuitError> {
    use winterfell::Prover;

    // Validate witness first
    witness.validate()?;

    // Build trace for public inputs extraction (legacy format)
    let legacy_trace = TransactionTrace::from_witness(witness)?;
    let public_inputs = witness.public_inputs()?;

    // Build the STARK execution trace
    let options = {
        #[cfg(feature = "stark-fast")]
        {
            fast_proof_options()
        }
        #[cfg(not(feature = "stark-fast"))]
        {
            default_proof_options()
        }
    };
    let prover = TransactionProverStark::new(options);
    let stark_trace = prover.build_trace(witness).map_err(|e| {
        TransactionCircuitError::ConstraintViolation(Box::leak(
            format!("Trace building failed: {}", e).into_boxed_str(),
        ))
    })?;

    // Extract STARK public inputs from the trace - this MUST match what the AIR expects
    let stark_pub_inputs = prover.get_pub_inputs(&stark_trace);

    // Generate proof using the trace
    let stark_proof = prover.prove(stark_trace).map_err(|e| {
        TransactionCircuitError::ConstraintViolation(Box::leak(
            format!("STARK proving failed: {:?}", e).into_boxed_str(),
        ))
    })?;

    // Serialize the STARK public inputs
    let input_flags = stark_pub_inputs
        .input_flags
        .iter()
        .map(|f| f.as_int() as u8)
        .collect();
    let output_flags = stark_pub_inputs
        .output_flags
        .iter()
        .map(|f| f.as_int() as u8)
        .collect();
    let fee = stark_pub_inputs.fee.as_int();
    let value_balance_sign = stark_pub_inputs.value_balance_sign.as_int() as u8;
    let value_balance_magnitude = stark_pub_inputs.value_balance_magnitude.as_int();
    let stablecoin_enabled = stark_pub_inputs.stablecoin_enabled.as_int() as u8;
    let stablecoin_asset_id = stark_pub_inputs.stablecoin_asset.as_int();
    let stablecoin_policy_version = stark_pub_inputs.stablecoin_policy_version.as_int() as u32;
    let stablecoin_issuance_sign = stark_pub_inputs.stablecoin_issuance_sign.as_int() as u8;
    let stablecoin_issuance_magnitude = stark_pub_inputs.stablecoin_issuance_magnitude.as_int();

    let nullifiers = stark_pub_inputs
        .nullifiers
        .iter()
        .map(felts_to_bytes32)
        .collect();
    let commitments = stark_pub_inputs
        .commitments
        .iter()
        .map(felts_to_bytes32)
        .collect();
    let merkle_root = felts_to_bytes32(&stark_pub_inputs.merkle_root);
    let stablecoin_policy_hash = felts_to_bytes32(&stark_pub_inputs.stablecoin_policy_hash);
    let stablecoin_oracle_commitment =
        felts_to_bytes32(&stark_pub_inputs.stablecoin_oracle_commitment);
    let stablecoin_attestation_commitment =
        felts_to_bytes32(&stark_pub_inputs.stablecoin_attestation_commitment);

    Ok(TransactionProof {
        // Use nullifiers/commitments from STARK public inputs to ensure consistency
        nullifiers,
        commitments,
        balance_slots: legacy_trace.padded_balance_slots(),
        public_inputs,
        stark_proof: stark_proof.to_bytes(),
        stark_public_inputs: Some(SerializedStarkInputs {
            input_flags,
            output_flags,
            fee,
            value_balance_sign,
            value_balance_magnitude,
            merkle_root,
            stablecoin_enabled,
            stablecoin_asset_id,
            stablecoin_policy_version,
            stablecoin_issuance_sign,
            stablecoin_issuance_magnitude,
            stablecoin_policy_hash,
            stablecoin_oracle_commitment,
            stablecoin_attestation_commitment,
        }),
    })
}

/// Verify a transaction proof.
///
/// If the proof has STARK proof bytes and public inputs, this performs real cryptographic verification.
/// Otherwise, it falls back to checking public input consistency (for legacy proofs).
#[cfg(feature = "plonky3")]
pub fn verify(
    proof: &TransactionProof,
    _verifying_key: &VerifyingKey,
) -> Result<VerificationReport, TransactionCircuitError> {
    verify_with_p3(proof)
}

/// Verify a transaction proof (Winterfell backend).
#[cfg(all(not(feature = "plonky3"), feature = "winterfell-legacy"))]
pub fn verify(
    proof: &TransactionProof,
    _verifying_key: &VerifyingKey,
) -> Result<VerificationReport, TransactionCircuitError> {
    verify_with_stark(proof, verify_transaction_proof_bytes)
}

/// Verify a transaction proof which used RPO Fiat‑Shamir.
#[cfg(all(
    feature = "winterfell-legacy",
    feature = "rpo-fiat-shamir",
    not(feature = "plonky3")
))]
pub fn verify_rpo(
    proof: &TransactionProof,
    _verifying_key: &VerifyingKey,
) -> Result<VerificationReport, TransactionCircuitError> {
    verify_with_stark(proof, verify_transaction_proof_bytes_rpo)
}

#[cfg(feature = "plonky3")]
fn verify_with_p3(
    proof: &TransactionProof,
) -> Result<VerificationReport, TransactionCircuitError> {
    // Validate public input structure
    if proof.nullifiers.len() != MAX_INPUTS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "invalid nullifier length",
        ));
    }
    if proof.commitments.len() != MAX_OUTPUTS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "invalid commitment length",
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
        #[cfg(feature = "legacy-proof")]
        {
            #[allow(deprecated)] // Intentional use of legacy TransactionAir for test fixtures
            let trace = TransactionTrace {
                merkle_root: proof.public_inputs.merkle_root,
                nullifiers: proof.nullifiers.clone(),
                commitments: proof.commitments.clone(),
                balance_slots: proof.balance_slots.clone(),
                native_delta: proof
                    .balance_slots
                    .iter()
                    .find(|slot| slot.asset_id == crate::constants::NATIVE_ASSET_ID)
                    .map(|slot| slot.delta)
                    .unwrap_or(0),
                fee: proof.public_inputs.native_fee,
            };
            #[allow(deprecated)]
            let air = crate::air::TransactionAir::new(trace);
            #[allow(deprecated)]
            air.check(&proof.public_inputs)?;
            return Ok(VerificationReport { verified: true });
        }
        #[cfg(not(feature = "legacy-proof"))]
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "missing STARK proof bytes or public inputs",
            ));
        }
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
            bytes32_to_felts(nf)
                .map(hash_felt_to_gl)
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "invalid nullifier encoding",
                ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let commitments = proof
        .commitments
        .iter()
        .map(|cm| {
            bytes32_to_felts(cm)
                .map(hash_felt_to_gl)
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "invalid commitment encoding",
                ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let merkle_root = bytes32_to_felts(&stark_inputs.merkle_root)
        .map(hash_felt_to_gl)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "invalid merkle root encoding",
        ))?;
    let stablecoin_policy_hash = bytes32_to_felts(&stark_inputs.stablecoin_policy_hash)
        .map(hash_felt_to_gl)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "invalid stablecoin policy hash encoding",
        ))?;
    let stablecoin_oracle_commitment =
        bytes32_to_felts(&stark_inputs.stablecoin_oracle_commitment)
            .map(hash_felt_to_gl)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "invalid stablecoin oracle commitment encoding",
            ))?;
    let stablecoin_attestation_commitment =
        bytes32_to_felts(&stark_inputs.stablecoin_attestation_commitment)
            .map(hash_felt_to_gl)
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

#[cfg(all(feature = "winterfell-legacy", not(feature = "plonky3")))]
fn verify_with_stark(
    proof: &TransactionProof,
    verify_bytes: fn(
        &[u8],
        &crate::stark_air::TransactionPublicInputsStark,
    ) -> Result<(), TransactionVerifyError>,
) -> Result<VerificationReport, TransactionCircuitError> {
    // Validate public input structure
    if proof.nullifiers.len() != MAX_INPUTS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "invalid nullifier length",
        ));
    }
    if proof.commitments.len() != MAX_OUTPUTS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "invalid commitment length",
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
        #[cfg(feature = "legacy-proof")]
        {
            #[allow(deprecated)] // Intentional use of legacy TransactionAir for test fixtures
            let trace = TransactionTrace {
                merkle_root: proof.public_inputs.merkle_root,
                nullifiers: proof.nullifiers.clone(),
                commitments: proof.commitments.clone(),
                balance_slots: proof.balance_slots.clone(),
                native_delta: proof
                    .balance_slots
                    .iter()
                    .find(|slot| slot.asset_id == crate::constants::NATIVE_ASSET_ID)
                    .map(|slot| slot.delta)
                    .unwrap_or(0),
                fee: proof.public_inputs.native_fee,
            };
            #[allow(deprecated)]
            let air = crate::air::TransactionAir::new(trace);
            #[allow(deprecated)]
            air.check(&proof.public_inputs)?;
            return Ok(VerificationReport { verified: true });
        }
        #[cfg(not(feature = "legacy-proof"))]
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "missing STARK proof bytes or public inputs",
            ));
        }
    }

    let stark_inputs = proof.stark_public_inputs.as_ref().expect("checked above");
    let input_flags = stark_inputs
        .input_flags
        .iter()
        .map(|flag| Felt::new(*flag as u64))
        .collect();
    let output_flags = stark_inputs
        .output_flags
        .iter()
        .map(|flag| Felt::new(*flag as u64))
        .collect();

    let nullifiers = proof
        .nullifiers
        .iter()
        .map(|nf| {
            bytes32_to_felts(nf).ok_or(TransactionCircuitError::ConstraintViolation(
                "invalid nullifier encoding",
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let commitments = proof
        .commitments
        .iter()
        .map(|cm| {
            bytes32_to_felts(cm).ok_or(TransactionCircuitError::ConstraintViolation(
                "invalid commitment encoding",
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let merkle_root = bytes32_to_felts(&stark_inputs.merkle_root).ok_or(
        TransactionCircuitError::ConstraintViolation("invalid merkle root encoding"),
    )?;
    let stablecoin_policy_hash = bytes32_to_felts(&stark_inputs.stablecoin_policy_hash).ok_or(
        TransactionCircuitError::ConstraintViolation("invalid stablecoin policy hash encoding"),
    )?;
    let stablecoin_oracle_commitment = bytes32_to_felts(&stark_inputs.stablecoin_oracle_commitment)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "invalid stablecoin oracle commitment encoding",
        ))?;
    let stablecoin_attestation_commitment = bytes32_to_felts(
        &stark_inputs.stablecoin_attestation_commitment,
    )
    .ok_or(TransactionCircuitError::ConstraintViolation(
        "invalid stablecoin attestation commitment encoding",
    ))?;

    let stark_pub_inputs = crate::stark_air::TransactionPublicInputsStark {
        input_flags,
        output_flags,
        nullifiers,
        commitments,
        fee: Felt::new(stark_inputs.fee),
        value_balance_sign: Felt::new(stark_inputs.value_balance_sign as u64),
        value_balance_magnitude: Felt::new(stark_inputs.value_balance_magnitude),
        merkle_root,
        stablecoin_enabled: Felt::new(stark_inputs.stablecoin_enabled as u64),
        stablecoin_asset: Felt::new(stark_inputs.stablecoin_asset_id),
        stablecoin_policy_version: Felt::new(stark_inputs.stablecoin_policy_version as u64),
        stablecoin_issuance_sign: Felt::new(stark_inputs.stablecoin_issuance_sign as u64),
        stablecoin_issuance_magnitude: Felt::new(stark_inputs.stablecoin_issuance_magnitude),
        stablecoin_policy_hash,
        stablecoin_oracle_commitment,
        stablecoin_attestation_commitment,
    };

    match verify_bytes(&proof.stark_proof, &stark_pub_inputs) {
        Ok(()) => Ok(VerificationReport { verified: true }),
        Err(e) => Err(TransactionCircuitError::ConstraintViolation(Box::leak(
            format!("STARK verification failed: {}", e).into_boxed_str(),
        ))),
    }
}

#[cfg(feature = "plonky3")]
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
        merkle_root: hash_to_bytes32(&pub_inputs.merkle_root),
        stablecoin_enabled: pub_inputs.stablecoin_enabled.as_canonical_u64() as u8,
        stablecoin_asset_id: pub_inputs.stablecoin_asset.as_canonical_u64(),
        stablecoin_policy_version: pub_inputs.stablecoin_policy_version.as_canonical_u64() as u32,
        stablecoin_issuance_sign: pub_inputs.stablecoin_issuance_sign.as_canonical_u64() as u8,
        stablecoin_issuance_magnitude: pub_inputs.stablecoin_issuance_magnitude.as_canonical_u64(),
        stablecoin_policy_hash: hash_to_bytes32(&pub_inputs.stablecoin_policy_hash),
        stablecoin_oracle_commitment: hash_to_bytes32(&pub_inputs.stablecoin_oracle_commitment),
        stablecoin_attestation_commitment: hash_to_bytes32(
            &pub_inputs.stablecoin_attestation_commitment,
        ),
    }
}

#[cfg(feature = "plonky3")]
fn hash_to_bytes32(hash: &[Goldilocks; 4]) -> Commitment {
    let mut out = [0u8; 32];
    for (idx, limb) in hash.iter().enumerate() {
        let start = idx * 8;
        out[start..start + 8].copy_from_slice(&limb.as_canonical_u64().to_be_bytes());
    }
    out
}

#[cfg(feature = "plonky3")]
fn hash_felt_to_gl(hash: [Felt; 4]) -> [Goldilocks; 4] {
    [
        Goldilocks::from_u64(hash[0].as_int()),
        Goldilocks::from_u64(hash[1].as_int()),
        Goldilocks::from_u64(hash[2].as_int()),
        Goldilocks::from_u64(hash[3].as_int()),
    ]
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
