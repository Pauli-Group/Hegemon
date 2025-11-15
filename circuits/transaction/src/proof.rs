use serde::{Deserialize, Serialize};

use crate::{
    air::{check_constraints, TransactionAir},
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS},
    error::TransactionCircuitError,
    hashing::Felt,
    keys::{ProvingKey, VerifyingKey},
    public_inputs::{BalanceSlot, TransactionPublicInputs},
    trace::TransactionTrace,
    witness::TransactionWitness,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionProof {
    pub public_inputs: TransactionPublicInputs,
    #[serde(with = "crate::public_inputs::serde_vec_felt")]
    pub nullifiers: Vec<Felt>,
    #[serde(with = "crate::public_inputs::serde_vec_felt")]
    pub commitments: Vec<Felt>,
    pub balance_slots: Vec<BalanceSlot>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationReport {
    pub verified: bool,
}

pub fn prove(
    witness: &TransactionWitness,
    _proving_key: &ProvingKey,
) -> Result<TransactionProof, TransactionCircuitError> {
    let (trace, public_inputs) = check_constraints(witness)?;
    Ok(TransactionProof {
        nullifiers: trace.padded_nullifiers(MAX_INPUTS),
        commitments: trace.padded_commitments(MAX_OUTPUTS),
        balance_slots: trace.padded_balance_slots(),
        public_inputs,
    })
}

pub fn verify(
    proof: &TransactionProof,
    _verifying_key: &VerifyingKey,
) -> Result<VerificationReport, TransactionCircuitError> {
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
    let air = TransactionAir::new(trace);
    air.check(&proof.public_inputs)?;
    Ok(VerificationReport { verified: true })
}
