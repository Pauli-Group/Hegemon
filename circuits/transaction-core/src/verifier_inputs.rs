use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use hegemon_field::Goldilocks;

use crate::constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID, POSEIDON2_RATE};

pub type Felt = Goldilocks;

/// Verifier-facing transaction fields shared by SmallWood and consensus.
#[derive(Clone, Debug)]
pub struct TransactionVerifierInputs {
    pub input_flags: Vec<Felt>,
    pub output_flags: Vec<Felt>,
    pub nullifiers: Vec<[Felt; 6]>,
    pub commitments: Vec<[Felt; 6]>,
    pub ciphertext_hashes: Vec<[Felt; 6]>,
    pub fee: Felt,
    pub value_balance_sign: Felt,
    pub value_balance_magnitude: Felt,
    pub merkle_root: [Felt; 6],
    pub balance_slot_assets: [Felt; BALANCE_SLOTS],
    pub stablecoin_enabled: Felt,
    pub stablecoin_asset: Felt,
    pub stablecoin_policy_version: Felt,
    pub stablecoin_issuance_sign: Felt,
    pub stablecoin_issuance_magnitude: Felt,
    pub stablecoin_policy_hash: [Felt; 6],
    pub stablecoin_oracle_commitment: [Felt; 6],
    pub stablecoin_attestation_commitment: [Felt; 6],
}

impl Default for TransactionVerifierInputs {
    fn default() -> Self {
        let zero6 = [Felt::ZERO; 6];
        Self {
            input_flags: vec![Felt::ZERO; MAX_INPUTS],
            output_flags: vec![Felt::ZERO; MAX_OUTPUTS],
            nullifiers: vec![zero6; MAX_INPUTS],
            commitments: vec![zero6; MAX_OUTPUTS],
            ciphertext_hashes: vec![zero6; MAX_OUTPUTS],
            fee: Felt::ZERO,
            value_balance_sign: Felt::ZERO,
            value_balance_magnitude: Felt::ZERO,
            merkle_root: zero6,
            balance_slot_assets: [
                Felt::from_u64(NATIVE_ASSET_ID),
                Felt::from_u64(u64::MAX),
                Felt::from_u64(u64::MAX),
                Felt::from_u64(u64::MAX),
            ],
            stablecoin_enabled: Felt::ZERO,
            stablecoin_asset: Felt::ZERO,
            stablecoin_policy_version: Felt::ZERO,
            stablecoin_issuance_sign: Felt::ZERO,
            stablecoin_issuance_magnitude: Felt::ZERO,
            stablecoin_policy_hash: zero6,
            stablecoin_oracle_commitment: zero6,
            stablecoin_attestation_commitment: zero6,
        }
    }
}

impl TransactionVerifierInputs {
    pub const fn expected_len() -> usize {
        MAX_INPUTS
            + MAX_OUTPUTS
            + (MAX_INPUTS * POSEIDON2_RATE)
            + (MAX_OUTPUTS * POSEIDON2_RATE * 2)
            + 32
            + BALANCE_SLOTS
    }

    pub fn to_vec(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(Self::expected_len());
        elements.extend(&self.input_flags);
        elements.extend(&self.output_flags);
        for nullifier in &self.nullifiers {
            elements.extend_from_slice(nullifier);
        }
        for commitment in &self.commitments {
            elements.extend_from_slice(commitment);
        }
        for ciphertext_hash in &self.ciphertext_hashes {
            elements.extend_from_slice(ciphertext_hash);
        }
        elements.push(self.fee);
        elements.push(self.value_balance_sign);
        elements.push(self.value_balance_magnitude);
        elements.extend_from_slice(&self.merkle_root);
        elements.extend_from_slice(&self.balance_slot_assets);
        elements.push(self.stablecoin_enabled);
        elements.push(self.stablecoin_asset);
        elements.push(self.stablecoin_policy_version);
        elements.push(self.stablecoin_issuance_sign);
        elements.push(self.stablecoin_issuance_magnitude);
        elements.extend_from_slice(&self.stablecoin_policy_hash);
        elements.extend_from_slice(&self.stablecoin_oracle_commitment);
        elements.extend_from_slice(&self.stablecoin_attestation_commitment);
        elements
    }

    pub fn try_from_slice(elements: &[Felt]) -> Result<Self, String> {
        let expected_len = Self::expected_len();
        if elements.len() != expected_len {
            return Err(format!(
                "transaction public inputs length mismatch: expected {expected_len}, got {}",
                elements.len()
            ));
        }

        let mut index = 0usize;
        fn take<'a>(slice: &'a [Felt], index: &mut usize, len: usize) -> &'a [Felt] {
            let start = *index;
            let end = start + len;
            *index = end;
            &slice[start..end]
        }

        let input_flags = take(elements, &mut index, MAX_INPUTS).to_vec();
        let output_flags = take(elements, &mut index, MAX_OUTPUTS).to_vec();

        let mut nullifiers = Vec::with_capacity(MAX_INPUTS);
        for _ in 0..MAX_INPUTS {
            let value = take(elements, &mut index, 6);
            nullifiers.push([value[0], value[1], value[2], value[3], value[4], value[5]]);
        }

        let mut commitments = Vec::with_capacity(MAX_OUTPUTS);
        for _ in 0..MAX_OUTPUTS {
            let value = take(elements, &mut index, 6);
            commitments.push([value[0], value[1], value[2], value[3], value[4], value[5]]);
        }

        let mut ciphertext_hashes = Vec::with_capacity(MAX_OUTPUTS);
        for _ in 0..MAX_OUTPUTS {
            let value = take(elements, &mut index, 6);
            ciphertext_hashes.push([value[0], value[1], value[2], value[3], value[4], value[5]]);
        }

        let fee = elements[index];
        index += 1;
        let value_balance_sign = elements[index];
        index += 1;
        let value_balance_magnitude = elements[index];
        index += 1;

        let merkle_root = array6(take(elements, &mut index, 6));
        let assets = take(elements, &mut index, BALANCE_SLOTS);
        let balance_slot_assets = [assets[0], assets[1], assets[2], assets[3]];

        let stablecoin_enabled = elements[index];
        index += 1;
        let stablecoin_asset = elements[index];
        index += 1;
        let stablecoin_policy_version = elements[index];
        index += 1;
        let stablecoin_issuance_sign = elements[index];
        index += 1;
        let stablecoin_issuance_magnitude = elements[index];
        index += 1;

        let stablecoin_policy_hash = array6(take(elements, &mut index, 6));
        let stablecoin_oracle_commitment = array6(take(elements, &mut index, 6));
        let stablecoin_attestation_commitment = array6(take(elements, &mut index, 6));

        Ok(Self {
            input_flags,
            output_flags,
            nullifiers,
            commitments,
            ciphertext_hashes,
            fee,
            value_balance_sign,
            value_balance_magnitude,
            merkle_root,
            balance_slot_assets,
            stablecoin_enabled,
            stablecoin_asset,
            stablecoin_policy_version,
            stablecoin_issuance_sign,
            stablecoin_issuance_magnitude,
            stablecoin_policy_hash,
            stablecoin_oracle_commitment,
            stablecoin_attestation_commitment,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.input_flags.len() != MAX_INPUTS {
            return Err("input_flags length mismatch".into());
        }
        if self.output_flags.len() != MAX_OUTPUTS {
            return Err("output_flags length mismatch".into());
        }
        if self.nullifiers.len() != MAX_INPUTS {
            return Err("nullifiers length mismatch".into());
        }
        if self.commitments.len() != MAX_OUTPUTS {
            return Err("commitments length mismatch".into());
        }
        if self.ciphertext_hashes.len() != MAX_OUTPUTS {
            return Err("ciphertext hash length mismatch".into());
        }
        if self.balance_slot_assets[0] != Felt::from_u64(NATIVE_ASSET_ID) {
            return Err("slot 0 asset must be native asset".into());
        }

        let padding = Felt::from_u64(u64::MAX);
        let native = Felt::from_u64(NATIVE_ASSET_ID);
        let mut saw_padding = false;
        let mut previous_asset = NATIVE_ASSET_ID;
        for asset in self.balance_slot_assets.iter().skip(1) {
            if *asset == padding {
                saw_padding = true;
                continue;
            }
            if saw_padding {
                return Err("balance slot padding must be a suffix".into());
            }
            let asset_id = asset.as_canonical_u64();
            if *asset == native || asset_id <= previous_asset {
                return Err("balance slot assets must be strictly increasing after slot 0".into());
            }
            previous_asset = asset_id;
        }

        let zero = Felt::ZERO;
        let one = Felt::ONE;
        let is_zero_hash = |value: &[Felt; 6]| value.iter().all(|element| *element == zero);

        for (index, flag) in self.input_flags.iter().enumerate() {
            if *flag != zero && *flag != one {
                return Err("input flag must be 0 or 1".into());
            }
            let nullifier = &self.nullifiers[index];
            if *flag == zero && !is_zero_hash(nullifier) {
                return Err("inactive input has non-zero nullifier".into());
            }
            if *flag == one && is_zero_hash(nullifier) {
                return Err("active input has zero nullifier".into());
            }
        }

        for (index, flag) in self.output_flags.iter().enumerate() {
            if *flag != zero && *flag != one {
                return Err("output flag must be 0 or 1".into());
            }
            let commitment = &self.commitments[index];
            if *flag == zero && !is_zero_hash(commitment) {
                return Err("inactive output has non-zero commitment".into());
            }
            if *flag == one && is_zero_hash(commitment) {
                return Err("active output has zero commitment".into());
            }
            if *flag == zero && !is_zero_hash(&self.ciphertext_hashes[index]) {
                return Err("inactive output has non-zero ciphertext hash".into());
            }
        }

        if !self.nullifiers.iter().any(|value| !is_zero_hash(value))
            && !self.commitments.iter().any(|value| !is_zero_hash(value))
        {
            return Err("Transaction has no inputs or outputs".into());
        }
        if self.value_balance_sign != zero && self.value_balance_sign != one {
            return Err("Value balance sign must be 0 or 1".into());
        }
        if self.stablecoin_enabled != zero && self.stablecoin_enabled != one {
            return Err("Stablecoin enabled flag must be 0 or 1".into());
        }
        if self.stablecoin_issuance_sign != zero && self.stablecoin_issuance_sign != one {
            return Err("Stablecoin issuance sign must be 0 or 1".into());
        }
        if self.stablecoin_enabled == one
            && !self
                .balance_slot_assets
                .iter()
                .skip(1)
                .any(|asset| *asset == self.stablecoin_asset)
        {
            return Err("stablecoin asset must appear in a non-native balance slot".into());
        }
        Ok(())
    }
}

fn array6(value: &[Felt]) -> [Felt; 6] {
    [value[0], value[1], value[2], value[3], value[4], value[5]]
}
