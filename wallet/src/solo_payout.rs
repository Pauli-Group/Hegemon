//! Public list of solo payout addresses, selected by absolute block height.
//! The spending wallet can recreate every entry from its existing root backup.

use crate::{address::POSEIDON2_V8_ADDRESS_VERSION, DerivedKeys, ShieldedAddress, WalletError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const FORMAT: &str = "hegemon-solo-payout-v1";
pub const MAX_SOLO_PAYOUT_HEIGHTS: usize = 4096;
pub const MAX_SOLO_PAYOUT_SCHEDULE_BYTES: usize = 12 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduleFile {
    format: String,
    chain_id: String,
    first_height: u64,
    addresses: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SoloPayoutSchedule {
    chain_id: [u8; 32],
    first_height: u64,
    addresses: Vec<ShieldedAddress>,
}

fn checked_last_height(first: u64, count: usize) -> Result<u64, WalletError> {
    if first == 0 || !(1..=MAX_SOLO_PAYOUT_HEIGHTS).contains(&count) {
        return Err(WalletError::InvalidArgument(
            "solo payout range must start after genesis and contain 1 to 4096 addresses",
        ));
    }
    first
        .checked_add((count - 1) as u64)
        .ok_or(WalletError::InvalidArgument("solo payout range overflows"))
}

impl SoloPayoutSchedule {
    pub fn derive(
        keys: &DerivedKeys,
        chain_id: [u8; 32],
        first_height: u64,
        count: usize,
    ) -> Result<Self, WalletError> {
        let end = checked_last_height(first_height, count)?;
        let mut addresses = Vec::with_capacity(count);
        for height in first_height..=end {
            let child = keys.solo_payout_keys(chain_id, height);
            addresses.push(child.poseidon2_v8_address(0)?.shielded_address());
        }
        Ok(Self {
            chain_id,
            first_height,
            addresses,
        })
    }

    pub fn from_json(bytes: &[u8], expected_chain_id: [u8; 32]) -> Result<Self, WalletError> {
        if bytes.len() > MAX_SOLO_PAYOUT_SCHEDULE_BYTES {
            return Err(WalletError::InvalidArgument(
                "solo payout schedule exceeds 12 MiB",
            ));
        }
        let file: ScheduleFile = serde_json::from_slice(bytes).map_err(|err| {
            WalletError::Serialization(format!("invalid solo payout schedule: {err}"))
        })?;
        if file.format != FORMAT {
            return Err(WalletError::InvalidArgument(
                "unknown solo payout schedule format",
            ));
        }
        if file.chain_id != hex::encode(expected_chain_id) {
            return Err(WalletError::InvalidArgument(
                "solo payout schedule has the wrong chain ID",
            ));
        }
        checked_last_height(file.first_height, file.addresses.len())?;
        let mut addresses = Vec::with_capacity(file.addresses.len());
        let mut recipients = BTreeSet::new();
        let mut authorities = BTreeSet::new();
        for encoded in file.addresses {
            let address = ShieldedAddress::decode(&encoded)?;
            if address.version != POSEIDON2_V8_ADDRESS_VERSION
                || address.diversifier_index != 0
                || address.encode()? != encoded
            {
                return Err(WalletError::InvalidArgument(
                    "solo payout schedule requires canonical V8 addresses at index zero",
                ));
            }
            if !recipients.insert(address.pk_recipient)
                || !authorities.insert((address.pk_auth, address.pk_auth_extension))
            {
                return Err(WalletError::InvalidArgument(
                    "solo payout schedule reuses a recipient or spending authority",
                ));
            }
            addresses.push(address);
        }
        Ok(Self {
            chain_id: expected_chain_id,
            first_height: file.first_height,
            addresses,
        })
    }

    pub fn to_json(&self) -> Result<Vec<u8>, WalletError> {
        let file = ScheduleFile {
            format: FORMAT.into(),
            chain_id: hex::encode(self.chain_id),
            first_height: self.first_height,
            addresses: self
                .addresses
                .iter()
                .map(ShieldedAddress::encode)
                .collect::<Result<_, _>>()?,
        };
        serde_json::to_vec_pretty(&file).map_err(|err| WalletError::Serialization(err.to_string()))
    }

    pub fn first_height(&self) -> u64 {
        self.first_height
    }

    pub fn last_height(&self) -> u64 {
        self.first_height + (self.addresses.len() - 1) as u64
    }

    pub fn address_at(&self, height: u64) -> Result<&ShieldedAddress, WalletError> {
        height
            .checked_sub(self.first_height)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.addresses.get(index))
            .ok_or(WalletError::InvalidArgument(
                "height outside the supplied solo payout schedule",
            ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RootSecret;

    #[test]
    fn solo_payout_schedule_roundtrips_and_rejects_reused_authority() {
        let keys = RootSecret::from_bytes([1; 32]).derive();
        let chain = [2; 32];
        let schedule = SoloPayoutSchedule::derive(&keys, chain, 101, 2).unwrap();
        let json = schedule.to_json().unwrap();
        let read = SoloPayoutSchedule::from_json(&json, chain).unwrap();
        assert_eq!(read.first_height(), 101);
        assert_eq!(read.last_height(), 102);
        assert!(read.address_at(100).is_err());
        assert!(read.address_at(103).is_err());
        let first = read.address_at(101).unwrap();
        let second = read.address_at(102).unwrap();
        assert_eq!(first, schedule.address_at(101).unwrap());
        assert_eq!(second, schedule.address_at(102).unwrap());
        assert_eq!((first.diversifier_index, second.diversifier_index), (0, 0));
        assert_ne!(first.pk_recipient, second.pk_recipient);
        assert_ne!(first.pk_auth, second.pk_auth);
        assert_ne!(first.pk_enc, second.pk_enc);
        assert!(SoloPayoutSchedule::from_json(&json, [3; 32]).is_err());

        let mut reused = second.clone();
        reused.pk_auth = first.pk_auth;
        reused.pk_auth_extension = first.pk_auth_extension;
        let mut wire: ScheduleFile = serde_json::from_slice(&json).unwrap();
        wire.addresses[1] = reused.encode().unwrap();
        assert!(SoloPayoutSchedule::from_json(&serde_json::to_vec(&wire).unwrap(), chain).is_err());
    }

    #[test]
    fn solo_payout_schedule_validates_boundaries_before_derivation() {
        assert!(checked_last_height(0, 1).is_err());
        assert!(checked_last_height(1, 0).is_err());
        assert!(checked_last_height(1, MAX_SOLO_PAYOUT_HEIGHTS + 1).is_err());
        assert!(checked_last_height(u64::MAX, 2).is_err());
        assert_eq!(checked_last_height(u64::MAX, 1).unwrap(), u64::MAX);
    }
}
