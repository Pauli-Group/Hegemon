use crate::{rpc::TransactionBundle, WalletError};

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

/// Build a deterministic local tx id for "submission status unknown" records.
///
/// This keeps spent notes locked until the wallet can reconcile on-chain
/// nullifiers (or timeout), preventing accidental nullifier reuse.
pub fn provisional_pending_tx_id(bundle: &TransactionBundle) -> [u8; 32] {
    let mut preimage =
        Vec::with_capacity(32 + bundle.binding_hash.len() + bundle.nullifiers.len() * 48);
    preimage.extend_from_slice(b"hegemon:wallet:pending-submission:v1");
    preimage.extend_from_slice(&bundle.binding_hash);
    for nf in &bundle.nullifiers {
        preimage.extend_from_slice(nf);
    }
    sp_crypto_hashing::blake2_256(&preimage)
}
