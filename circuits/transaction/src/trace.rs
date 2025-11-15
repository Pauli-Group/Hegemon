use winterfell::math::FieldElement;

use crate::{
    constants::{BALANCE_SLOTS, NATIVE_ASSET_ID},
    hashing::Felt,
    public_inputs::BalanceSlot,
    witness::TransactionWitness,
};

#[derive(Clone, Debug)]
pub struct TransactionTrace {
    pub merkle_root: Felt,
    pub nullifiers: Vec<Felt>,
    pub commitments: Vec<Felt>,
    pub balance_slots: Vec<BalanceSlot>,
    pub native_delta: i128,
    pub fee: u64,
}

impl TransactionTrace {
    pub fn from_witness(
        witness: &TransactionWitness,
    ) -> Result<Self, crate::TransactionCircuitError> {
        let mut balance_slots = witness.balance_slots()?;
        if !balance_slots
            .iter()
            .any(|slot| slot.asset_id == NATIVE_ASSET_ID)
        {
            balance_slots[0] = BalanceSlot {
                asset_id: NATIVE_ASSET_ID,
                delta: 0,
            };
        }
        let native_delta = balance_slots
            .iter()
            .find(|slot| slot.asset_id == NATIVE_ASSET_ID)
            .map(|slot| slot.delta)
            .unwrap_or(0);
        Ok(Self {
            merkle_root: witness.merkle_root,
            nullifiers: witness.nullifiers(),
            commitments: witness.commitments(),
            balance_slots,
            native_delta,
            fee: witness.fee,
        })
    }

    pub fn padded_nullifiers(&self, target: usize) -> Vec<Felt> {
        let mut list = self.nullifiers.clone();
        list.resize(target, Felt::ZERO);
        list
    }

    pub fn padded_commitments(&self, target: usize) -> Vec<Felt> {
        let mut list = self.commitments.clone();
        list.resize(target, Felt::ZERO);
        list
    }

    pub fn padded_balance_slots(&self) -> Vec<BalanceSlot> {
        let mut slots = self.balance_slots.clone();
        slots.resize(
            BALANCE_SLOTS,
            BalanceSlot {
                asset_id: u64::MAX,
                delta: 0,
            },
        );
        slots
    }
}
