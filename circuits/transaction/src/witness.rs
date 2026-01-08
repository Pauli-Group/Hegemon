use std::collections::BTreeMap;

use protocol_versioning::{VersionBinding, DEFAULT_VERSION_BINDING};
use serde::{Deserialize, Serialize};
use p3_field::PrimeCharacteristicRing;
use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS},
    error::TransactionCircuitError,
    hashing_pq::{felts_to_bytes48, nullifier, prf_key, HashFelt},
    note::{InputNoteWitness, OutputNoteWitness},
    public_inputs::{BalanceSlot, StablecoinPolicyBinding, TransactionPublicInputs},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionWitness {
    #[serde(with = "crate::witness::serde_vec_inputs")]
    pub inputs: Vec<InputNoteWitness>,
    #[serde(with = "crate::witness::serde_vec_outputs")]
    pub outputs: Vec<OutputNoteWitness>,
    #[serde(with = "crate::witness::serde_bytes32")]
    pub sk_spend: [u8; 32],
    #[serde(with = "crate::witness::serde_bytes48")]
    pub merkle_root: [u8; 48],
    pub fee: u64,
    #[serde(default)]
    pub value_balance: i128,
    #[serde(default)]
    pub stablecoin: StablecoinPolicyBinding,
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
            if nf.iter().all(|elem| *elem == crate::hashing_pq::Felt::ZERO) {
                return Err(TransactionCircuitError::ZeroNullifier(i));
            }
        }

        if self.value_balance.unsigned_abs() > u64::MAX as u128 {
            return Err(TransactionCircuitError::ValueBalanceOutOfRange(
                self.value_balance.unsigned_abs(),
            ));
        }

        let slots = self.balance_slots()?;
        if self.stablecoin.enabled {
            if self.stablecoin.asset_id == crate::constants::NATIVE_ASSET_ID {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "stablecoin asset id cannot be native",
                ));
            }
            if self.stablecoin.asset_id == u64::MAX {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "stablecoin asset id cannot be padding",
                ));
            }
            let issuance_mag = self.stablecoin.issuance_delta.unsigned_abs();
            if issuance_mag > u64::MAX as u128 {
                return Err(TransactionCircuitError::ValueBalanceOutOfRange(
                    issuance_mag,
                ));
            }
        } else if !stablecoin_binding_is_zero(&self.stablecoin) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "stablecoin binding must be zeroed when disabled",
            ));
        }

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
        if self.stablecoin.enabled {
            let mut stablecoin_slot_seen = false;
            for slot in slots.iter() {
                if slot.asset_id == self.stablecoin.asset_id {
                    stablecoin_slot_seen = true;
                    if slot.delta != self.stablecoin.issuance_delta {
                        return Err(TransactionCircuitError::BalanceMismatch(slot.asset_id));
                    }
                } else if slot.asset_id != crate::constants::NATIVE_ASSET_ID && slot.delta != 0 {
                    return Err(TransactionCircuitError::BalanceMismatch(slot.asset_id));
                }
            }
            if !stablecoin_slot_seen {
                return Err(TransactionCircuitError::BalanceMismatch(
                    self.stablecoin.asset_id,
                ));
            }
        } else {
            for slot in slots.iter() {
                if slot.asset_id != crate::constants::NATIVE_ASSET_ID && slot.delta != 0 {
                    return Err(TransactionCircuitError::BalanceMismatch(slot.asset_id));
                }
            }
        }

        Ok(())
    }

    pub fn prf_key(&self) -> crate::hashing_pq::Felt {
        prf_key(&self.sk_spend)
    }

    pub fn nullifiers(&self) -> Vec<HashFelt> {
        let prf = self.prf_key();
        self.inputs
            .iter()
            .map(|note| nullifier(prf, &note.note.rho, note.position))
            .collect()
    }

    pub fn commitments(&self) -> Vec<HashFelt> {
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

        map.entry(crate::constants::NATIVE_ASSET_ID).or_insert(0);
        if self.stablecoin.enabled {
            map.entry(self.stablecoin.asset_id).or_insert(0);
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
            let mut list: Vec<[u8; 48]> = self.nullifiers().iter().map(felts_to_bytes48).collect();
            list.resize(MAX_INPUTS, [0u8; 48]);
            list
        };
        let commitments = {
            let mut list: Vec<[u8; 48]> = self.commitments().iter().map(felts_to_bytes48).collect();
            list.resize(MAX_OUTPUTS, [0u8; 48]);
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
            self.stablecoin.clone(),
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

pub(crate) mod serde_bytes48 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 48 {
            return Err(serde::de::Error::custom("expected 48 bytes"));
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    use serde::Deserialize;
}

fn stablecoin_binding_is_zero(binding: &StablecoinPolicyBinding) -> bool {
    !binding.enabled
        && binding.asset_id == 0
        && binding.policy_hash == [0u8; 48]
        && binding.oracle_commitment == [0u8; 48]
        && binding.attestation_commitment == [0u8; 48]
        && binding.issuance_delta == 0
        && binding.policy_version == 0
}
