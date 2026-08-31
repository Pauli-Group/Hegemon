use crate::{rpc::TransactionBundle, WalletError};
use hegemon_hash384::blake2b_384_domain_hash;

const PROVISIONAL_ACTION_ID_DOMAIN: &[u8] = b"hegemon.wallet.provisional-action-id.v2";

/// Local identifier for an ambiguous submission whose canonical node-assigned
/// action id is not known yet.
///
/// Equal width does not make this an [`hegemon_hash384::ActionId48`].  There is
/// deliberately no conversion between the two types: a provisional id may be
/// used only by wallet-local pending/disclosure APIs and can never be sent to a
/// canonical node, RPC, or consensus lookup by type accident.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProvisionalActionId48([u8; 48]);

impl ProvisionalActionId48 {
    pub const fn new(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 48] {
        self.0
    }
}

/// Returns true when a submission failure may still mean the extrinsic was accepted.
///
/// In this case callers should preserve pending note locks instead of immediately
/// unlocking and risking a duplicate spend submission.
pub fn is_ambiguous_submission_error(err: &WalletError) -> bool {
    let WalletError::Rpc(msg) = err else {
        return false;
    };
    let lower = msg.to_ascii_lowercase();
    lower.contains("request timeout")
        || lower.contains("timeout")
        || lower.contains("deadline")
        || lower.contains("connection closed")
        || lower.contains("connection reset")
        || lower.contains("transport error")
}

/// Build a deterministic local 48-byte id for "submission status unknown" records.
///
/// This keeps spent notes locked until the wallet can reconcile on-chain
/// nullifiers (or timeout), preventing accidental nullifier reuse.
pub fn provisional_pending_tx_id(bundle: &TransactionBundle) -> ProvisionalActionId48 {
    let mut preimage =
        Vec::with_capacity(32 + bundle.binding_hash.len() + bundle.nullifiers.len() * 48);
    preimage.extend_from_slice(b"hegemon:wallet:pending-submission:v1");
    preimage.extend_from_slice(&bundle.binding_hash);
    for nf in &bundle.nullifiers {
        preimage.extend_from_slice(nf);
    }
    ProvisionalActionId48::new(blake2b_384_domain_hash(
        PROVISIONAL_ACTION_ID_DOMAIN,
        [preimage.as_slice()],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisional_identifier_is_deterministic_and_tail_sensitive() {
        let mut bundle = TransactionBundle {
            proof_bytes: vec![1, 2, 3],
            nullifiers: vec![[3; 48]],
            commitments: Vec::new(),
            ciphertexts: Vec::new(),
            anchor: [1; 48],
            binding_hash: [2; 64],
            balance_slot_asset_ids: [0, 1, 2, 3],
            fee: 4,
            value_balance: 0,
            stablecoin: Default::default(),
        };
        let original = provisional_pending_tx_id(&bundle);
        assert_eq!(provisional_pending_tx_id(&bundle), original);
        bundle.binding_hash[47] ^= 1;
        assert_ne!(provisional_pending_tx_id(&bundle), original);
    }
}
