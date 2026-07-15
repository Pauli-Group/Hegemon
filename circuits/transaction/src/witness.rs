use std::collections::BTreeMap;

use crate::{
    constants::{is_canonical_asset_id, BALANCE_SLOTS, MAX_INPUTS, MAX_NOTE_VALUE, MAX_OUTPUTS},
    error::TransactionCircuitError,
    hashing_pq::{felts_to_bytes48, nullifier, prf_key, HashFelt},
    note::{InputNoteWitness, OutputNoteWitness},
    public_inputs::{BalanceSlot, StablecoinPolicyBinding, TransactionPublicInputs},
};
use protocol_versioning::{VersionBinding, DEFAULT_VERSION_BINDING};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionWitness {
    #[serde(with = "crate::witness::serde_vec_inputs")]
    pub inputs: Vec<InputNoteWitness>,
    #[serde(with = "crate::witness::serde_vec_outputs")]
    pub outputs: Vec<OutputNoteWitness>,
    #[serde(default, with = "crate::public_inputs::serde_vec_bytes48")]
    pub ciphertext_hashes: Vec<[u8; 48]>,
    #[serde(
        default = "TransactionWitness::default_sk_spend",
        deserialize_with = "crate::witness::serde_bytes32::deserialize",
        skip_serializing
    )]
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
        if self.ciphertext_hashes.len() != self.outputs.len() {
            return Err(TransactionCircuitError::CiphertextHashMismatch(
                self.ciphertext_hashes.len(),
            ));
        }

        if self.fee as u128 > MAX_NOTE_VALUE {
            return Err(TransactionCircuitError::FeeOutOfRange(self.fee as u128));
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

        if self.value_balance.unsigned_abs() > MAX_NOTE_VALUE {
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
            if !is_canonical_asset_id(self.stablecoin.asset_id) {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "stablecoin asset id must be canonical",
                ));
            }
            let issuance_mag = self.stablecoin.issuance_delta.unsigned_abs();
            if issuance_mag > MAX_NOTE_VALUE {
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
        let ciphertext_hashes = {
            let mut list = self.ciphertext_hashes.clone();
            list.resize(MAX_OUTPUTS, [0u8; 48]);
            list
        };
        let balance_slots = self.balance_slots()?;
        TransactionPublicInputs::new(
            self.merkle_root,
            nullifiers,
            commitments,
            ciphertext_hashes,
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

    fn default_sk_spend() -> [u8; 32] {
        [0u8; 32]
    }
}

pub(crate) mod serde_vec_inputs {
    use super::*;
    use serde::{ser::SerializeSeq, Deserializer, Serializer};

    pub fn serialize<S>(values: &[InputNoteWitness], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(values.len()))?;
        for value in values {
            seq.serialize_element(value)?;
        }
        seq.end()
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
    use serde::{ser::SerializeSeq, Deserializer, Serializer};

    pub fn serialize<S>(values: &[OutputNoteWitness], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(values.len()))?;
        for value in values {
            seq.serialize_element(value)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<OutputNoteWitness>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<OutputNoteWitness>::deserialize(deserializer)
    }
}

pub(crate) mod serde_bytes32 {
    use serde::Deserializer;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
    use crate::public_inputs::BalanceSlot;
    use std::collections::BTreeSet;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanTransactionVectorFile {
        schema_version: u32,
        balance_cases: Vec<LeanBalanceCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBalanceCase {
        name: String,
        inputs: Vec<LeanNote>,
        outputs: Vec<LeanNote>,
        fee: u64,
        value_balance: String,
        stablecoin_enabled: bool,
        stablecoin_asset_id: u64,
        stablecoin_issuance_delta: String,
        stablecoin_policy_version: u32,
        expected_slots: Option<Vec<LeanBalanceSlot>>,
        expected_valid: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNote {
        asset_id: u64,
        value: u64,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBalanceSlot {
        asset_id: u64,
        delta: String,
    }

    #[test]
    fn lean_generated_balance_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_TRANSACTION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_TRANSACTION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean transaction vectors");
        let vectors: LeanTransactionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean transaction vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.balance_cases.is_empty(),
            "Lean transaction balance cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.balance_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_balance_case(case);
        }
    }

    fn verify_lean_balance_case(case: &LeanBalanceCase) {
        let witness = witness_from_lean_case(case);
        match (witness.balance_slots(), &case.expected_slots) {
            (Ok(actual), Some(expected)) => {
                let expected = expected
                    .iter()
                    .map(|slot| BalanceSlot {
                        asset_id: slot.asset_id,
                        delta: parse_i128(&slot.delta),
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    actual, expected,
                    "{} production balance slots drifted from Lean spec",
                    case.name
                );
            }
            (Err(_), None) => {}
            (Ok(actual), None) => {
                panic!(
                    "{} produced balance slots {actual:?}, but Lean expected overflow",
                    case.name
                );
            }
            (Err(err), Some(expected)) => {
                panic!(
                    "{} failed to produce balance slots ({err}), but Lean expected {expected:?}",
                    case.name
                );
            }
        }

        assert_eq!(
            witness.validate().is_ok(),
            case.expected_valid,
            "{} production balance validation drifted from Lean spec",
            case.name
        );
    }

    fn witness_from_lean_case(case: &LeanBalanceCase) -> TransactionWitness {
        TransactionWitness {
            inputs: case
                .inputs
                .iter()
                .enumerate()
                .map(|(idx, note)| InputNoteWitness {
                    note: note_data(note, idx, true),
                    position: idx as u64,
                    rho_seed: patterned_bytes32(0x70, idx),
                    merkle_path: MerklePath::default(),
                })
                .collect(),
            outputs: case
                .outputs
                .iter()
                .enumerate()
                .map(|(idx, note)| OutputNoteWitness {
                    note: note_data(note, idx, false),
                })
                .collect(),
            ciphertext_hashes: vec![[0u8; 48]; case.outputs.len()],
            sk_spend: patterned_bytes32(0x90, 0),
            merkle_root: [0u8; 48],
            fee: case.fee,
            value_balance: parse_i128(&case.value_balance),
            stablecoin: StablecoinPolicyBinding {
                enabled: case.stablecoin_enabled,
                asset_id: case.stablecoin_asset_id,
                policy_hash: [0u8; 48],
                oracle_commitment: [0u8; 48],
                attestation_commitment: [0u8; 48],
                issuance_delta: parse_i128(&case.stablecoin_issuance_delta),
                policy_version: case.stablecoin_policy_version,
            },
            version: TransactionWitness::default_version_binding(),
        }
    }

    fn note_data(note: &LeanNote, idx: usize, input: bool) -> NoteData {
        let base = if input { 0x10 } else { 0x40 };
        NoteData {
            value: note.value,
            asset_id: note.asset_id,
            pk_recipient: patterned_bytes32(base, idx),
            pk_auth: patterned_bytes32(base + 1, idx),
            rho: patterned_bytes32(base + 2, idx),
            r: patterned_bytes32(base + 3, idx),
        }
    }

    fn patterned_bytes32(seed: u8, idx: usize) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (offset, byte) in out.iter_mut().enumerate() {
            *byte = seed
                .wrapping_add(idx as u8)
                .wrapping_add((offset as u8).wrapping_mul(17));
        }
        out
    }

    fn parse_i128(raw: &str) -> i128 {
        raw.parse::<i128>().expect("Lean signed integer")
    }
}
