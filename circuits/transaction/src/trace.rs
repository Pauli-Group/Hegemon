use crate::{
    constants::{BALANCE_SLOTS, NATIVE_ASSET_ID},
    hashing_pq::{felts_to_bytes48, Commitment},
    public_inputs::BalanceSlot,
    witness::TransactionWitness,
};

#[derive(Clone, Debug)]
pub struct TransactionTrace {
    pub merkle_root: Commitment,
    pub nullifiers: Vec<Commitment>,
    pub commitments: Vec<Commitment>,
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
            nullifiers: witness.nullifiers().iter().map(felts_to_bytes48).collect(),
            commitments: witness.commitments().iter().map(felts_to_bytes48).collect(),
            balance_slots,
            native_delta,
            fee: witness.fee,
        })
    }

    pub fn padded_nullifiers(&self, target: usize) -> Vec<Commitment> {
        let mut list = self.nullifiers.clone();
        list.resize(target, [0u8; 48]);
        list
    }

    pub fn padded_commitments(&self, target: usize) -> Vec<Commitment> {
        let mut list = self.commitments.clone();
        list.resize(target, [0u8; 48]);
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
