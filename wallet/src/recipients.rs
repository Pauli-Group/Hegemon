use serde::{Deserialize, Serialize};

use crate::address::ShieldedAddress;
use crate::notes::MemoPlaintext;
use crate::store::TransferRecipient;
use crate::tx_builder::Recipient;
use crate::WalletError;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RecipientSpec {
    pub address: String,
    pub value: u64,
    pub asset_id: u64,
    pub memo: Option<String>,
}

pub fn parse_recipients(specs: &[RecipientSpec]) -> Result<Vec<Recipient>, WalletError> {
    specs
        .iter()
        .map(|spec| {
            let address = ShieldedAddress::decode(&spec.address)?;
            let memo = MemoPlaintext::new(spec.memo.clone().unwrap_or_default().into_bytes());
            Ok(Recipient {
                address,
                value: spec.value,
                asset_id: spec.asset_id,
                memo,
            })
        })
        .collect()
}

pub fn transfer_recipients_from_specs(specs: &[RecipientSpec]) -> Vec<TransferRecipient> {
    specs
        .iter()
        .map(|spec| TransferRecipient {
            address: spec.address.clone(),
            value: spec.value,
            asset_id: spec.asset_id,
            memo: spec.memo.clone(),
        })
        .collect()
}
