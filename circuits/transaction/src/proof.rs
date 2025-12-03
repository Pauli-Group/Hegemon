//! Transaction proof structures and proving/verification functions.
//!
//! This module provides the main interface for creating and verifying
//! transaction proofs. It uses real STARK proofs via winterfell.

use protocol_versioning::VersionBinding;
use serde::{Deserialize, Serialize};

use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS},
    error::TransactionCircuitError,
    hashing::Felt,
    keys::{ProvingKey, VerifyingKey},
    public_inputs::{BalanceSlot, TransactionPublicInputs},
    stark_prover::{TransactionProverStark, fast_proof_options},
    stark_verifier::verify_transaction_proof_bytes,
    trace::TransactionTrace,
    witness::TransactionWitness,
};

/// A transaction proof containing public inputs and the STARK proof bytes.
///
/// The `stark_proof` field contains the actual cryptographic proof.
/// The other fields are public inputs that can be verified against the proof.
///
/// For full STARK verification, use:
/// - `stark_verifier::verify_transaction_proof_bytes()` with proper `TransactionPublicInputsStark`
/// - Or use `StarkProver::prove_transaction()` and verify directly
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionProof {
    pub public_inputs: TransactionPublicInputs,
    #[serde(with = "crate::public_inputs::serde_vec_felt")]
    pub nullifiers: Vec<Felt>,
    #[serde(with = "crate::public_inputs::serde_vec_felt")]
    pub commitments: Vec<Felt>,
    pub balance_slots: Vec<BalanceSlot>,
    /// The actual STARK proof bytes (winterfell format).
    /// This is the cryptographic proof that the transaction is valid.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stark_proof: Vec<u8>,
    /// STARK public inputs in serialized form for verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stark_public_inputs: Option<SerializedStarkInputs>,
}

/// Serialized STARK public inputs for verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedStarkInputs {
    pub total_input: u64,
    pub total_output: u64,
    pub fee: u64,
    #[serde(with = "crate::public_inputs::serde_felt")]
    pub merkle_root: Felt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Generate a real STARK proof for a transaction.
///
/// This function:
/// 1. Validates the witness
/// 2. Builds the execution trace
/// 3. Generates a real STARK proof using winterfell
/// 4. Returns the proof with public inputs
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
    let prover = TransactionProverStark::new(fast_proof_options());
    let stark_trace = prover.build_trace(witness)
        .map_err(|e| TransactionCircuitError::ConstraintViolation(
            Box::leak(format!("Trace building failed: {}", e).into_boxed_str())
        ))?;
    
    // Extract STARK public inputs from the trace - this MUST match what the AIR expects
    let stark_pub_inputs = prover.get_pub_inputs(&stark_trace);
    
    // Generate proof using the trace
    let stark_proof = prover.prove(stark_trace)
        .map_err(|e| TransactionCircuitError::ConstraintViolation(
            Box::leak(format!("STARK proving failed: {:?}", e).into_boxed_str())
        ))?;
    
    // Serialize the STARK public inputs
    // Use as_int() to convert BaseElement to u64
    let total_input = stark_pub_inputs.total_input.as_int();
    let total_output = stark_pub_inputs.total_output.as_int();
    let fee = stark_pub_inputs.fee.as_int();
    
    Ok(TransactionProof {
        // Use nullifiers/commitments from STARK public inputs to ensure consistency
        nullifiers: stark_pub_inputs.nullifiers.clone(),
        commitments: stark_pub_inputs.commitments.clone(),
        balance_slots: legacy_trace.padded_balance_slots(),
        public_inputs,
        stark_proof: stark_proof.to_bytes(),
        stark_public_inputs: Some(SerializedStarkInputs {
            total_input,
            total_output,
            fee,
            merkle_root: stark_pub_inputs.merkle_root,
        }),
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

    // If we have a real STARK proof with serialized public inputs, verify cryptographically
    if proof.has_stark_proof() {
        if let Some(ref stark_inputs) = proof.stark_public_inputs {
            let stark_pub_inputs = crate::stark_air::TransactionPublicInputsStark {
                nullifiers: proof.nullifiers.clone(),
                commitments: proof.commitments.clone(),
                total_input: Felt::new(stark_inputs.total_input),
                total_output: Felt::new(stark_inputs.total_output),
                fee: Felt::new(stark_inputs.fee),
                merkle_root: stark_inputs.merkle_root,
            };
            
            match verify_transaction_proof_bytes(&proof.stark_proof, &stark_pub_inputs) {
                Ok(()) => return Ok(VerificationReport { verified: true }),
                Err(e) => {
                    // STARK verification failure - public inputs don't match what was proven
                    return Err(TransactionCircuitError::ConstraintViolation(
                        Box::leak(format!("STARK verification failed: {}", e).into_boxed_str())
                    ));
                },
            }
        }
    }
    
    // Legacy fallback: check public input consistency only
    // WARNING: This does NOT provide cryptographic security!
    // It's only here for backwards compatibility with old test fixtures.
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
    
    Ok(VerificationReport { verified: true })
}

/// Verify that balance_slots match public_inputs.balance_slots
fn verify_balance_slots(proof: &TransactionProof) -> Result<(), TransactionCircuitError> {
    use crate::constants::NATIVE_ASSET_ID;
    use crate::public_inputs::BalanceSlot;
    
    if proof.public_inputs.balance_slots.len() != proof.balance_slots.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "balance slot count mismatch"
        ));
    }
    
    for (idx, expected) in proof.public_inputs.balance_slots.iter().enumerate() {
        let actual = proof.balance_slots
            .get(idx)
            .cloned()
            .unwrap_or(BalanceSlot { asset_id: u64::MAX, delta: 0 });
            
        if actual.asset_id != expected.asset_id || actual.delta != expected.delta {
            return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
        }
        
        // For native asset, verify delta equals fee
        if expected.asset_id == NATIVE_ASSET_ID {
            if expected.delta != proof.public_inputs.native_fee as i128 {
                return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
            }
        } else if expected.delta != 0 {
            // Non-native assets must balance to zero
            return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
        }
    }
    
    Ok(())
}
