use protocol_versioning::{CircuitVersion, CryptoSuiteId, VersionBinding, DEFAULT_VERSION_BINDING};
use serde::{Deserialize, Serialize};
pub use transaction_core::BalanceSlot;
use winterfell::math::FieldElement;

use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID},
    error::TransactionCircuitError,
    hashing::{balance_commitment, Felt},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionPublicInputs {
    #[serde(with = "crate::public_inputs::serde_felt")]
    pub merkle_root: Felt,
    #[serde(with = "crate::public_inputs::serde_vec_felt")]
    pub nullifiers: Vec<Felt>,
    #[serde(with = "crate::public_inputs::serde_vec_felt")]
    pub commitments: Vec<Felt>,
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
        let nullifiers = vec![Felt::ZERO; MAX_INPUTS];
        let commitments = vec![Felt::ZERO; MAX_OUTPUTS];
        let balance_slots = (0..BALANCE_SLOTS)
            .map(|_| BalanceSlot {
                asset_id: u64::MAX,
                delta: 0,
            })
            .collect();

        Self {
            merkle_root: Felt::ZERO,
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
        merkle_root: Felt,
        nullifiers: Vec<Felt>,
        commitments: Vec<Felt>,
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

        let native_delta = balance_slots
            .iter()
            .find(|slot| slot.asset_id == NATIVE_ASSET_ID)
            .map(|slot| slot.delta)
            .unwrap_or(0);
        let expected_balance_tag = balance_commitment(native_delta, &balance_slots);
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

pub(crate) mod serde_vec_felt {
    use serde::{Deserializer, Serializer};
    use std::convert::TryInto;
    use winterfell::math::fields::f64::BaseElement;

    pub fn serialize<S>(values: &[BaseElement], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<[u8; 8]> = values.iter().map(|v| v.as_int().to_be_bytes()).collect();
        serializer.serialize_bytes(&bytes.concat())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<BaseElement>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if !bytes.len().is_multiple_of(8) {
            return Err(serde::de::Error::custom("invalid field encoding"));
        }
        Ok(bytes
            .chunks(8)
            .map(|chunk| BaseElement::new(u64::from_be_bytes(chunk.try_into().unwrap())))
            .collect())
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
