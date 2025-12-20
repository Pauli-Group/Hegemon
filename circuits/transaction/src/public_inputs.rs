use protocol_versioning::{CircuitVersion, CryptoSuiteId, VersionBinding, DEFAULT_VERSION_BINDING};
use serde::{Deserialize, Serialize};
pub use transaction_core::BalanceSlot;
use winterfell::math::FieldElement;

use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID},
    error::TransactionCircuitError,
    hashing::{balance_commitment, Commitment, Felt},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionPublicInputs {
    #[serde(with = "crate::public_inputs::serde_bytes32")]
    pub merkle_root: Commitment,
    #[serde(with = "crate::public_inputs::serde_vec_bytes32")]
    pub nullifiers: Vec<Commitment>,
    #[serde(with = "crate::public_inputs::serde_vec_bytes32")]
    pub commitments: Vec<Commitment>,
    pub balance_slots: Vec<BalanceSlot>,
    pub native_fee: u64,
    pub value_balance: i128,
    #[serde(with = "crate::public_inputs::serde_felt")]
    pub balance_tag: Felt,
    pub circuit_version: CircuitVersion,
    pub crypto_suite: CryptoSuiteId,
}

impl Default for TransactionPublicInputs {
    fn default() -> Self {
        let nullifiers = vec![[0u8; 32]; MAX_INPUTS];
        let commitments = vec![[0u8; 32]; MAX_OUTPUTS];
        let balance_slots = (0..BALANCE_SLOTS)
            .map(|_| BalanceSlot {
                asset_id: u64::MAX,
                delta: 0,
            })
            .collect();

        Self {
            merkle_root: [0u8; 32],
            nullifiers,
            commitments,
            balance_slots,
            native_fee: 0,
            value_balance: 0,
            balance_tag: Felt::ZERO,
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

        if !transaction_core::hashing::is_canonical_bytes32(&merkle_root) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "merkle root encoding is non-canonical",
            ));
        }
        if nullifiers
            .iter()
            .any(|nf| !transaction_core::hashing::is_canonical_bytes32(nf))
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "nullifier encoding is non-canonical",
            ));
        }
        if commitments
            .iter()
            .any(|cm| !transaction_core::hashing::is_canonical_bytes32(cm))
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "commitment encoding is non-canonical",
            ));
        }

        let native_delta = balance_slots
            .iter()
            .find(|slot| slot.asset_id == NATIVE_ASSET_ID)
            .map(|slot| slot.delta)
            .unwrap_or(0);
        let expected_balance_tag = balance_commitment(native_delta, &balance_slots).map_err(
            |err| TransactionCircuitError::BalanceDeltaOutOfRange(err.asset_id, err.magnitude),
        )?;
        let balance_tag = expected_balance_tag;

        Ok(Self {
            merkle_root,
            nullifiers,
            commitments,
            balance_slots,
            native_fee,
            value_balance,
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
