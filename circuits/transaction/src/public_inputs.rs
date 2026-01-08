use protocol_versioning::{CircuitVersion, CryptoSuiteId, VersionBinding, DEFAULT_VERSION_BINDING};
use serde::{Deserialize, Serialize};
pub use transaction_core::BalanceSlot;

use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID},
    error::TransactionCircuitError,
    hashing_pq::{balance_commitment_bytes, Commitment},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StablecoinPolicyBinding {
    #[serde(default)]
    pub enabled: bool,
    pub asset_id: u64,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub policy_hash: Commitment,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub oracle_commitment: Commitment,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub attestation_commitment: Commitment,
    #[serde(default)]
    pub issuance_delta: i128,
    pub policy_version: u32,
}

impl Default for StablecoinPolicyBinding {
    fn default() -> Self {
        Self {
            enabled: false,
            asset_id: 0,
            policy_hash: [0u8; 48],
            oracle_commitment: [0u8; 48],
            attestation_commitment: [0u8; 48],
            issuance_delta: 0,
            policy_version: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionPublicInputs {
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub merkle_root: Commitment,
    #[serde(with = "crate::public_inputs::serde_vec_bytes48")]
    pub nullifiers: Vec<Commitment>,
    #[serde(with = "crate::public_inputs::serde_vec_bytes48")]
    pub commitments: Vec<Commitment>,
    pub balance_slots: Vec<BalanceSlot>,
    pub native_fee: u64,
    #[serde(default)]
    pub value_balance: i128,
    #[serde(default)]
    pub stablecoin: StablecoinPolicyBinding,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub balance_tag: Commitment,
    pub circuit_version: CircuitVersion,
    pub crypto_suite: CryptoSuiteId,
}

impl Default for TransactionPublicInputs {
    fn default() -> Self {
        let nullifiers = vec![[0u8; 48]; MAX_INPUTS];
        let commitments = vec![[0u8; 48]; MAX_OUTPUTS];
        let balance_slots = (0..BALANCE_SLOTS)
            .map(|_| BalanceSlot {
                asset_id: u64::MAX,
                delta: 0,
            })
            .collect();

        Self {
            merkle_root: [0u8; 48],
            nullifiers,
            commitments,
            balance_slots,
            native_fee: 0,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            balance_tag: [0u8; 48],
            circuit_version: DEFAULT_VERSION_BINDING.circuit,
            crypto_suite: DEFAULT_VERSION_BINDING.crypto,
        }
    }
}

impl TransactionPublicInputs {
    pub fn new(
        merkle_root: Commitment,
        nullifiers: Vec<Commitment>,
        commitments: Vec<Commitment>,
        balance_slots: Vec<BalanceSlot>,
        native_fee: u64,
        value_balance: i128,
        stablecoin: StablecoinPolicyBinding,
        version: VersionBinding,
    ) -> Result<Self, TransactionCircuitError> {
        if nullifiers.len() != MAX_INPUTS {
            return Err(TransactionCircuitError::NullifierMismatch(nullifiers.len()));
        }
        if commitments.len() != MAX_OUTPUTS {
            return Err(TransactionCircuitError::CommitmentMismatch(
                commitments.len(),
            ));
        }
        if balance_slots.len() != BALANCE_SLOTS {
            return Err(TransactionCircuitError::ConstraintViolation(
                "balance slot vector must match BALANCE_SLOTS",
            ));
        }

        if !transaction_core::hashing_pq::is_canonical_bytes48(&merkle_root) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "merkle root encoding is non-canonical",
            ));
        }
        if nullifiers
            .iter()
            .any(|nf| !transaction_core::hashing_pq::is_canonical_bytes48(nf))
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "nullifier encoding is non-canonical",
            ));
        }
        if commitments
            .iter()
            .any(|cm| !transaction_core::hashing_pq::is_canonical_bytes48(cm))
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "commitment encoding is non-canonical",
            ));
        }
        if stablecoin.enabled {
            if stablecoin.asset_id == NATIVE_ASSET_ID || stablecoin.asset_id == u64::MAX {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "stablecoin asset id invalid",
                ));
            }
            if !transaction_core::hashing_pq::is_canonical_bytes48(&stablecoin.policy_hash)
                || !transaction_core::hashing_pq::is_canonical_bytes48(
                    &stablecoin.oracle_commitment,
                )
                || !transaction_core::hashing_pq::is_canonical_bytes48(
                    &stablecoin.attestation_commitment,
                )
            {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "stablecoin binding encoding is non-canonical",
                ));
            }
            if transaction_core::hashing::signed_parts(stablecoin.issuance_delta).is_none() {
                return Err(TransactionCircuitError::ValueBalanceOutOfRange(
                    stablecoin.issuance_delta.unsigned_abs(),
                ));
            }
        } else if !stablecoin_binding_is_zero(&stablecoin) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "stablecoin binding must be zeroed when disabled",
            ));
        }

        let native_delta = balance_slots
            .iter()
            .find(|slot| slot.asset_id == NATIVE_ASSET_ID)
            .map(|slot| slot.delta)
            .unwrap_or(0);
        let balance_tag =
            balance_commitment_bytes(native_delta, &balance_slots).map_err(|err| {
                TransactionCircuitError::BalanceDeltaOutOfRange(err.asset_id, err.magnitude)
            })?;

        if stablecoin.enabled
            && !balance_slots
                .iter()
                .any(|slot| slot.asset_id == stablecoin.asset_id)
        {
            return Err(TransactionCircuitError::BalanceMismatch(
                stablecoin.asset_id,
            ));
        }

        Ok(Self {
            merkle_root,
            nullifiers,
            commitments,
            balance_slots,
            native_fee,
            value_balance,
            stablecoin,
            balance_tag,
            circuit_version: version.circuit,
            crypto_suite: version.crypto,
        })
    }

    pub fn version_binding(&self) -> VersionBinding {
        VersionBinding::new(self.circuit_version, self.crypto_suite)
    }
}

pub(crate) mod serde_vec_bytes32 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(values: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::with_capacity(values.len() * 32);
        for value in values {
            bytes.extend_from_slice(value);
        }
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if !bytes.len().is_multiple_of(32) {
            return Err(serde::de::Error::custom("invalid 32-byte encoding"));
        }
        Ok(bytes
            .chunks(32)
            .map(|chunk| <[u8; 32]>::try_from(chunk).expect("32-byte chunk"))
            .collect())
    }

    use serde::Deserialize;
}

pub(crate) mod serde_vec_bytes48 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(values: &[[u8; 48]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::with_capacity(values.len() * 48);
        for value in values {
            bytes.extend_from_slice(value);
        }
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 48]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if !bytes.len().is_multiple_of(48) {
            return Err(serde::de::Error::custom("invalid 48-byte encoding"));
        }
        Ok(bytes
            .chunks(48)
            .map(|chunk| <[u8; 48]>::try_from(chunk).expect("48-byte chunk"))
            .collect())
    }

    use serde::Deserialize;
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
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
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
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    use serde::Deserialize;
}

pub(crate) fn default_bytes48() -> [u8; 48] {
    [0u8; 48]
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
