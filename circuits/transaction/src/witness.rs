use std::collections::BTreeMap;

use protocol_versioning::{VersionBinding, DEFAULT_VERSION_BINDING};
use serde::{Deserialize, Serialize};
use winterfell::math::FieldElement;

use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS},
    error::TransactionCircuitError,
    hashing::{nullifier, prf_key, Felt},
    note::{InputNoteWitness, OutputNoteWitness},
    public_inputs::{BalanceSlot, TransactionPublicInputs},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionWitness {
    #[serde(with = "crate::witness::serde_vec_inputs")]
    pub inputs: Vec<InputNoteWitness>,
    #[serde(with = "crate::witness::serde_vec_outputs")]
    pub outputs: Vec<OutputNoteWitness>,
    #[serde(with = "crate::witness::serde_bytes32")]
    pub sk_spend: [u8; 32],
    #[serde(with = "crate::witness::serde_felt")]
    pub merkle_root: Felt,
    pub fee: u64,
    #[serde(default)]
    pub value_balance: i128,
    #[serde(default = "TransactionWitness::default_version_binding")]
    pub version: VersionBinding,
}

impl TransactionWitness {
    pub fn validate(&self) -> Result<(), TransactionCircuitError> {
        if self.inputs.len() > MAX_INPUTS {
            return Err(TransactionCircuitError::TooManyInputs(self.inputs.len()));
        }
        if self.outputs.len() > MAX_OUTPUTS {
            return Err(TransactionCircuitError::TooManyOutputs(self.outputs.len()));
        }
        for note in &self.inputs {
            note.validate()?;
        }
        for note in &self.outputs {
            note.validate()?;
        }

        // SECURITY: Validate that no nullifier is zero.
        // Zero nullifiers are used as padding and skipped during double-spend checks.
        // A malicious witness could attempt to produce a zero nullifier for a real note,
        // which would allow that note to be spent multiple times.
        let nullifiers = self.nullifiers();
        for (i, nf) in nullifiers.iter().enumerate() {
            if *nf == Felt::ZERO {
                return Err(TransactionCircuitError::ZeroNullifier(i));
            }
        }

        if self.value_balance.unsigned_abs() > u64::MAX as u128 {
            return Err(TransactionCircuitError::ValueBalanceOutOfRange(
                self.value_balance.unsigned_abs(),
            ));
        }

        let slots = self.balance_slots()?;
        let native_delta = slots
            .iter()
            .find(|slot| slot.asset_id == crate::constants::NATIVE_ASSET_ID)
            .map(|slot| slot.delta)
            .unwrap_or(0);
        let expected_native = self.fee as i128 - self.value_balance;
        if native_delta != expected_native {
            return Err(TransactionCircuitError::BalanceMismatch(
                crate::constants::NATIVE_ASSET_ID,
            ));
        }

        Ok(())
    }

    pub fn prf_key(&self) -> Felt {
        prf_key(&self.sk_spend)
    }

    pub fn nullifiers(&self) -> Vec<Felt> {
        let prf = self.prf_key();
        self.inputs
            .iter()
            .map(|note| nullifier(prf, &note.note.rho, note.position))
            .collect()
    }

    pub fn commitments(&self) -> Vec<Felt> {
        self.outputs
            .iter()
            .map(|note| note.note.commitment())
            .collect()
    }

    pub fn balance_slots(&self) -> Result<Vec<BalanceSlot>, TransactionCircuitError> {
        let mut map: BTreeMap<u64, i128> = BTreeMap::new();
        for input in &self.inputs {
            *map.entry(input.note.asset_id).or_default() += input.note.value as i128;
        }
        for output in &self.outputs {
            *map.entry(output.note.asset_id).or_default() -= output.note.value as i128;
        }

        if !map.contains_key(&crate::constants::NATIVE_ASSET_ID) {
            map.insert(crate::constants::NATIVE_ASSET_ID, 0);
        }

        if map.len() > BALANCE_SLOTS {
            return Err(TransactionCircuitError::BalanceSlotOverflow(
                map.iter().next_back().map(|(asset, _)| *asset).unwrap_or(0),
            ));
        }

        let mut slots: Vec<BalanceSlot> = map
            .into_iter()
            .map(|(asset_id, delta)| BalanceSlot { asset_id, delta })
            .collect();

        while slots.len() < BALANCE_SLOTS {
            slots.push(BalanceSlot {
                asset_id: u64::MAX,
                delta: 0,
            });
        }

        Ok(slots)
    }

    pub fn public_inputs(&self) -> Result<TransactionPublicInputs, TransactionCircuitError> {
        let nullifiers = {
            let mut list = self.nullifiers();
            list.resize(MAX_INPUTS, Felt::ZERO);
            list
        };
        let commitments = {
            let mut list = self.commitments();
            list.resize(MAX_OUTPUTS, Felt::ZERO);
            list
        };
        let balance_slots = self.balance_slots()?;
        TransactionPublicInputs::new(
            self.merkle_root,
            nullifiers,
            commitments,
            balance_slots,
            self.fee,
            self.value_balance,
            self.version,
        )
    }

    pub fn default_version_binding() -> VersionBinding {
        DEFAULT_VERSION_BINDING
    }
}

pub(crate) mod serde_vec_inputs {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(values: &[InputNoteWitness], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        values.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<InputNoteWitness>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<InputNoteWitness>::deserialize(deserializer)
    }
}

pub(crate) mod serde_vec_outputs {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(values: &[OutputNoteWitness], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        values.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<OutputNoteWitness>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<OutputNoteWitness>::deserialize(deserializer)
    }
}

pub(crate) mod serde_bytes32 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    use serde::Deserialize;
}
pub(crate) mod serde_felt {
    use serde::{Deserializer, Serializer};
    use winterfell::math::fields::f64::BaseElement;

    pub fn serialize<S>(value: &BaseElement, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(value.as_int())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BaseElement, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Ok(BaseElement::new(value))
    }

    use serde::Deserialize;
}
