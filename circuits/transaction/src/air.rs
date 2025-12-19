//! Legacy AIR for public input consistency checking.
//!
//! **WARNING**: This module does NOT provide cryptographic security.
//! It only performs equality checks on public inputs.
//!
//! For real STARK proving/verification, use the `stark_air`, `stark_prover`,
//! and `stark_verifier` modules instead.
//!
//! This module is retained only for:
//! - Backwards compatibility with old test fixtures
//! - Quick sanity checks during development
//!
//! Production code should always use real STARK proofs.

use crate::{
    constants::{BALANCE_SLOTS, NATIVE_ASSET_ID},
    error::TransactionCircuitError,
    hashing::balance_commitment,
    public_inputs::TransactionPublicInputs,
    trace::TransactionTrace,
};

/// Legacy AIR that only checks public input consistency.
///
/// **WARNING**: This does NOT verify cryptographic proofs!
/// Use `stark_verifier::verify_transaction_proof` for real verification.
#[deprecated(
    since = "0.2.0",
    note = "Use stark_air::TransactionAirStark for real STARK proofs"
)]
pub struct TransactionAir {
    trace: TransactionTrace,
}

#[allow(deprecated)]
impl TransactionAir {
    pub fn new(trace: TransactionTrace) -> Self {
        Self { trace }
    }

    pub fn check(
        &self,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<(), TransactionCircuitError> {
        self.check_nullifiers(public_inputs)?;
        self.check_commitments(public_inputs)?;
        self.check_balances(public_inputs)?;
        self.check_balance_tag(public_inputs)
    }

    fn check_nullifiers(
        &self,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<(), TransactionCircuitError> {
        for (idx, expected) in public_inputs.nullifiers.iter().enumerate() {
            let actual = self.trace.nullifiers.get(idx).copied().unwrap_or_default();
            if actual != *expected {
                return Err(TransactionCircuitError::NullifierMismatch(idx));
            }
        }
        Ok(())
    }

    fn check_commitments(
        &self,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<(), TransactionCircuitError> {
        for (idx, expected) in public_inputs.commitments.iter().enumerate() {
            let actual = self.trace.commitments.get(idx).copied().unwrap_or_default();
            if actual != *expected {
                return Err(TransactionCircuitError::CommitmentMismatch(idx));
            }
        }
        Ok(())
    }

    fn check_balances(
        &self,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<(), TransactionCircuitError> {
        if public_inputs.balance_slots.len() != BALANCE_SLOTS {
            return Err(TransactionCircuitError::ConstraintViolation(
                "balance slot length mismatch",
            ));
        }
        for (idx, expected) in public_inputs.balance_slots.iter().enumerate() {
            let actual = self
                .trace
                .balance_slots
                .get(idx)
                .cloned()
                .unwrap_or(BalanceSlot::zero());
            if actual.asset_id != expected.asset_id || actual.delta != expected.delta {
                return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
            }
            if expected.asset_id == NATIVE_ASSET_ID {
                let expected_native = public_inputs.native_fee as i128 - public_inputs.value_balance;
                if expected.delta != expected_native {
                    return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
                }
            } else if expected.delta != 0 {
                return Err(TransactionCircuitError::BalanceMismatch(expected.asset_id));
            }
        }
        Ok(())
    }

    fn check_balance_tag(
        &self,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<(), TransactionCircuitError> {
        let native_delta = public_inputs
            .balance_slots
            .iter()
            .find(|slot| slot.asset_id == NATIVE_ASSET_ID)
            .map(|slot| slot.delta)
            .unwrap_or(0);
        let expected = balance_commitment(native_delta, &public_inputs.balance_slots);
        if expected != public_inputs.balance_tag {
            return Err(TransactionCircuitError::ConstraintViolation(
                "balance tag mismatch",
            ));
        }
        Ok(())
    }
}

use crate::public_inputs::BalanceSlot;

impl BalanceSlot {
    fn zero() -> Self {
        Self {
            asset_id: 0,
            delta: 0,
        }
    }
}

/// Legacy constraint checking function.
///
/// **WARNING**: This only validates consistency, NOT cryptographic proofs!
#[deprecated(
    since = "0.2.0",
    note = "Use stark_prover::TransactionProverStark::prove_transaction for real STARK proofs"
)]
#[allow(deprecated)]
pub fn check_constraints(
    witness: &crate::witness::TransactionWitness,
) -> Result<(TransactionTrace, TransactionPublicInputs), TransactionCircuitError> {
    witness.validate()?;
    let trace = TransactionTrace::from_witness(witness)?;
    let public_inputs = witness.public_inputs()?;
    let air = TransactionAir::new(trace.clone());
    air.check(&public_inputs)?;
    Ok((trace, public_inputs))
}
