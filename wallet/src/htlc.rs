//! HTLC offer and preparation API for the explicitly unqualified successor.
//! Spending credentials and unrevealed preimages have no public serialization.
#![forbid(unsafe_code)]
use crate::WalletError;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use transaction_circuit::{
    smallwood_htlc::{self, HtlcAction, HtlcPolicy, HtlcStatement, HtlcWitness, SecretRelease},
    smallwood_htlc_transport,
};

pub use crate::store::htlc_store::{
    HtlcAttemptExport, HtlcAttemptReadiness, HtlcAttemptReview, HtlcAttemptStatus,
    HtlcConfirmation, HtlcStatementMetadata, HtlcSwapView,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HtlcOffer {
    pub version: u32,
    pub nonce: [u8; 32],
    pub network_id: [u8; 32],
    pub hashlock: [u8; 32],
    pub value: u64,
    pub maximum_fee: u64,
    pub timeout_height: u64,
    pub claim_authority: [u64; 7],
    pub refund_authority: [u64; 7],
    pub claim_recipient: [u64; 4],
    pub refund_recipient: [u64; 4],
    pub secret_release: SecretRelease,
    pub bitcoin: BitcoinRegtestTerms,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitcoinRegtestTerms {
    pub amount_sat: u64,
    /// Compressed 33-byte SEC public keys. Actual script acceptance is checked by Bitcoin Core.
    pub claim_public_key: Vec<u8>,
    pub refund_public_key: Vec<u8>,
    pub refund_height: u32,
    pub required_confirmations: u32,
}

impl HtlcOffer {
    /// Construct a public offer from the exact owned V8 party addresses. The
    /// caller must establish ownership before invoking this constructor.
    pub fn create_for_addresses(
        network_id: [u8; 32],
        hashlock: [u8; 32],
        value: u64,
        maximum_fee: u64,
        timeout_height: u64,
        claim_address: &crate::ShieldedAddress,
        refund_address: &crate::ShieldedAddress,
        bitcoin: BitcoinRegtestTerms,
    ) -> Result<Self, WalletError> {
        let (claim_recipient, claim_authority) = address_fields(claim_address)?;
        let (refund_recipient, refund_authority) = address_fields(refund_address)?;
        let mut nonce = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);
        let offer = Self {
            version: 1,
            nonce,
            network_id,
            hashlock,
            value,
            maximum_fee,
            timeout_height,
            claim_authority,
            refund_authority,
            claim_recipient,
            refund_recipient,
            secret_release: SecretRelease::HiddenOnHegemon,
            bitcoin,
        };
        offer.validate()?;
        Ok(offer)
    }

    pub fn policy(&self) -> HtlcPolicy {
        HtlcPolicy {
            version: smallwood_htlc::HTLC_POLICY_VERSION,
            network_id: self.network_id,
            hashlock: self.hashlock,
            claim_authority: self.claim_authority,
            refund_authority: self.refund_authority,
            claim_recipient: self.claim_recipient,
            refund_recipient: self.refund_recipient,
            timeout_height: self.timeout_height,
            secret_release: self.secret_release,
        }
    }
    pub fn validate(&self) -> Result<(), WalletError> {
        if self.version != 1
            || self.nonce == [0; 32]
            || self.network_id == [0; 32]
            || self.hashlock == [0; 32]
            || self.value == 0
            || self.value > smallwood_htlc::MAX_VALUE
            || self.maximum_fee >= self.value
            || self.claim_authority == [0; 7]
            || self.refund_authority == [0; 7]
        {
            return Err(WalletError::InvalidArgument("invalid HTLC offer"));
        }
        smallwood_htlc::htlc_policy_digest(self.policy()).map_err(surface_error)?;
        self.bitcoin.validate()?;
        Ok(())
    }
    pub fn id(&self) -> Result<[u8; 32], WalletError> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(b"hegemon.htlc.regtest.offer.v1");
        hasher.update(serde_json::to_vec(self).map_err(surface_error)?);
        Ok(hasher.finalize().into())
    }
    /// Check the Hegemon-first, Bitcoin-reveals sequence against both current
    /// heights. Height units must never be compared directly across chains.
    pub fn check_timeout_margin(
        &self,
        hegemon_height: u64,
        bitcoin_height: u32,
        hegemon_block_seconds: u64,
        bitcoin_block_seconds: u64,
        safety_seconds: u64,
    ) -> Result<(), WalletError> {
        self.validate()?;
        if self.secret_release != SecretRelease::HiddenOnHegemon
            || hegemon_block_seconds == 0
            || bitcoin_block_seconds == 0
            || safety_seconds == 0
        {
            return Err(WalletError::InvalidArgument(
                "unsupported HTLC reveal direction or timing assumptions",
            ));
        }
        let hgn = self
            .timeout_height
            .checked_sub(hegemon_height)
            .ok_or(WalletError::InvalidArgument("Hegemon HTLC already expired"))?;
        let btc = self
            .bitcoin
            .refund_height
            .checked_sub(bitcoin_height)
            .ok_or(WalletError::InvalidArgument("Bitcoin HTLC already expired"))?;
        if btc == 0
            || (hgn as u128) * (hegemon_block_seconds as u128)
                <= (btc as u128) * (bitcoin_block_seconds as u128) + safety_seconds as u128
        {
            return Err(WalletError::InvalidArgument(
                "HTLC refund margin insufficient",
            ));
        }
        Ok(())
    }
    pub fn bitcoin_witness_script(&self) -> Result<Vec<u8>, WalletError> {
        self.validate()?;
        let mut script = vec![0x63, 0x82, 1, 32, 0x88, 0xa8, 32]; // IF SIZE 32 EQUALVERIFY SHA256
        script.extend(self.hashlock);
        script.extend([0x88, 33]);
        script.extend(&self.bitcoin.claim_public_key);
        script.extend([0xac, 0x67]); // CHECKSIG ELSE
        push_script_number(&mut script, self.bitcoin.refund_height);
        script.extend([0xb1, 0x69, 33]); // CLTV VERIFY
        script.extend(&self.bitcoin.refund_public_key);
        script.extend([0xac, 0x68]); // CHECKSIG ENDIF
        Ok(script)
    }
    pub fn bitcoin_script_pubkey(&self) -> Result<Vec<u8>, WalletError> {
        let hash = Sha256::digest(self.bitcoin_witness_script()?);
        let mut script = vec![0, 32];
        script.extend_from_slice(&hash);
        Ok(script)
    }
}

fn address_fields(address: &crate::ShieldedAddress) -> Result<([u64; 4], [u64; 7]), WalletError> {
    use transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes;

    let checked = crate::ShieldedAddress::from_bytes(&address.to_bytes())?;
    if checked.version != crate::address::POSEIDON2_V8_ADDRESS_VERSION
        || checked.crypto_suite != protocol_versioning::CRYPTO_SUITE_ETA
    {
        return Err(WalletError::InvalidArgument(
            "HTLC requires a full V8 address",
        ));
    }
    let recipient = poseidon2_v8_words_from_canonical_bytes(checked.pk_recipient)
        .map_err(|error| WalletError::Serialization(format!("HTLC recipient: {error:?}")))?;
    let auth = poseidon2_v8_words_from_canonical_bytes(checked.pk_auth)
        .map_err(|error| WalletError::Serialization(format!("HTLC authority: {error:?}")))?;
    let mut authority = [0u64; 7];
    authority[..4].copy_from_slice(&auth);
    for (word, bytes) in authority[4..]
        .iter_mut()
        .zip(checked.pk_auth_extension.chunks_exact(8))
    {
        *word = u64::from_le_bytes(bytes.try_into().expect("fixed address limb"));
    }
    Ok((recipient, authority))
}
impl BitcoinRegtestTerms {
    fn validate(&self) -> Result<(), WalletError> {
        let key_valid = |key: &[u8]| key.len() == 33 && matches!(key[0], 2 | 3);
        if self.amount_sat == 0
            || self.amount_sat > 21_000_000 * 100_000_000
            || self.refund_height == 0
            || self.refund_height >= 500_000_000
            || self.required_confirmations == 0
            || !key_valid(&self.claim_public_key)
            || !key_valid(&self.refund_public_key)
        {
            return Err(WalletError::InvalidArgument(
                "invalid Bitcoin regtest HTLC terms",
            ));
        }
        Ok(())
    }
}
fn push_script_number(script: &mut Vec<u8>, mut number: u32) {
    if number <= 16 {
        script.push(0x50 + number as u8);
        return;
    }
    let mut bytes = Vec::new();
    while number != 0 {
        bytes.push(number as u8);
        number >>= 8;
    }
    if bytes.last().is_some_and(|last| last & 0x80 != 0) {
        bytes.push(0);
    }
    script.push(bytes.len() as u8);
    script.extend(bytes);
}

pub(crate) fn surface_error(error: impl std::fmt::Debug) -> WalletError {
    WalletError::Serialization(format!("HTLC: {error:?}"))
}

/// This produces a full proof and locally verifies it; it grants no production
/// submission authority. The exact resulting bytes are the only wire payload.
pub fn prepare_development_carrier(
    statement: &HtlcStatement,
    witness: &HtlcWitness,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WalletError> {
    let proof = smallwood_htlc::prove_development(statement, witness).map_err(surface_error)?;
    smallwood_htlc::verify_development(statement, &proof).map_err(surface_error)?;
    smallwood_htlc_transport::encode(statement, ciphertext, &proof).map_err(surface_error)
}

/// Complete strict SMZC candidate proof. The runtime still requires independent
/// source-registry authorization for this exact chain and relation.
pub fn prepare_candidate_carrier(
    statement: &HtlcStatement,
    witness: &HtlcWitness,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WalletError> {
    let proof = smallwood_htlc::prove_candidate(statement, witness).map_err(surface_error)?;
    smallwood_htlc::verify_candidate(statement, &proof).map_err(surface_error)?;
    smallwood_htlc_transport::encode_candidate(statement, ciphertext, &proof).map_err(surface_error)
}

/// Validate a public secret recovered from a confirmed Bitcoin witness or
/// an explicitly revealing Hegemon claim before using it for the other leg.
pub fn validate_revealed_secret(offer: &HtlcOffer, secret: &[u8; 32]) -> Result<(), WalletError> {
    offer.validate()?;
    let hash: [u8; 32] = Sha256::digest(secret).into();
    if hash != offer.hashlock {
        return Err(WalletError::InvalidArgument(
            "HTLC revealed secret does not match offer",
        ));
    }
    Ok(())
}

pub(crate) fn validate_offer_statement(
    offer: &HtlcOffer,
    statement: &HtlcStatement,
) -> Result<(), WalletError> {
    offer.validate()?;
    statement.validate_structure().map_err(surface_error)?;
    if statement.network_id != offer.network_id || statement.fee > offer.maximum_fee {
        return Err(WalletError::InvalidArgument(
            "HTLC statement differs from accepted offer",
        ));
    }
    if statement.action == HtlcAction::Refund && statement.parent_height < offer.timeout_height {
        return Err(WalletError::InvalidArgument("HTLC refund has not matured"));
    }
    if statement.action == HtlcAction::Lock && statement.parent_height >= offer.timeout_height {
        return Err(WalletError::InvalidArgument("HTLC lock timeout has passed"));
    }
    match (
        statement.action,
        offer.secret_release,
        statement.revealed_secret,
    ) {
        (HtlcAction::Claim, SecretRelease::PublicOnHegemon, Some(secret)) => {
            validate_revealed_secret(offer, &secret)?
        }
        (HtlcAction::Claim, SecretRelease::PublicOnHegemon, None)
        | (_, SecretRelease::HiddenOnHegemon, Some(_)) => {
            return Err(WalletError::InvalidArgument(
                "HTLC public secret release mismatch",
            ))
        }
        _ => (),
    }
    Ok(())
}

/// Retain uncertain input ownership through the last admissible inclusion
/// parent. A reorg back into this range restores abandoned tombstone holds.
pub(crate) fn last_admissible_parent(statement: &HtlcStatement) -> u64 {
    statement
        .parent_height
        .saturating_add(if statement.action == HtlcAction::Lock {
            0
        } else {
            protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW
        })
}

/// Test-only projection for the native lifecycle harness. Ordinary clients
/// must obtain source-owned launch authority before producing a request.
#[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
pub fn prepare_htlc_submit_request_for_retained_test(
    exact_carrier: &[u8],
    network_id: [u8; 32],
    parent_hash: [u8; 32],
    parent_height: u64,
    note_root: [u64; 7],
) -> Result<serde_json::Value, WalletError> {
    use base64::Engine;
    use protocol_versioning::launch_candidate;
    let carrier =
        smallwood_htlc_transport::decode_wallet_exact(exact_carrier).map_err(surface_error)?;
    carrier
        .statement
        .validate_context(network_id, parent_hash, parent_height, note_root)
        .map_err(surface_error)?;
    Ok(serde_json::json!({
        "binding_circuit": launch_candidate::HTLC_VERSION_BINDING.circuit,
        "binding_crypto": launch_candidate::HTLC_VERSION_BINDING.crypto,
        "family_id": launch_candidate::LAUNCH_SHIELDED_FAMILY_ID,
        "action_id": launch_candidate::HTLC_ACTION_ID,
        "object_refs": [], "new_nullifiers": [],
        "public_args": base64::engine::general_purpose::STANDARD.encode(exact_carrier),
        "authorization_proof": null, "authorization_signatures": [], "aux_data": null
    }))
}

impl crate::WalletStore {
    /// Checks exact source authority at the current inclusion height before the
    /// closure is invoked after uncertainty is durable, so cancellation or
    /// ambiguous I/O cannot accidentally release inputs. It receives the exact
    /// retained carrier; no proof reconstruction or witness crosses this boundary.
    pub async fn submit_prepared_htlc_with<F, Fut>(
        &self,
        attempt_id: [u8; 32],
        submit: F,
    ) -> Result<crate::ActionId48, WalletError>
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: std::future::Future<Output = Result<crate::ActionId48, WalletError>>,
    {
        let bytes = self.begin_htlc_submission(attempt_id)?;
        let action_id = submit(bytes).await?;
        self.mark_htlc_submitted(attempt_id, action_id)?;
        Ok(action_id)
    }

    /// Explicit development rehearsal path. The caller must first bind the
    /// wallet context to the current Development node manifest and exact RPC.
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub async fn submit_prepared_htlc_for_retained_test_with<F, Fut>(
        &self,
        attempt_id: [u8; 32],
        submit: F,
    ) -> Result<crate::ActionId48, WalletError>
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: std::future::Future<Output = Result<crate::ActionId48, WalletError>>,
    {
        let bytes = self.begin_htlc_submission_for_retained_test(attempt_id)?;
        let action_id = submit(bytes).await?;
        self.mark_htlc_submitted(attempt_id, action_id)?;
        Ok(action_id)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn offer() -> HtlcOffer {
        HtlcOffer {
            version: 1,
            nonce: [1; 32],
            network_id: [2; 32],
            hashlock: Sha256::digest([19; 32]).into(),
            value: 10_000,
            maximum_fee: 10,
            timeout_height: 1_000,
            claim_authority: [1; 7],
            refund_authority: [2; 7],
            claim_recipient: [3; 4],
            refund_recipient: [4; 4],
            secret_release: SecretRelease::HiddenOnHegemon,
            bitcoin: BitcoinRegtestTerms {
                amount_sat: 100_000,
                claim_public_key: [&[2u8][..], &[3u8; 32]].concat(),
                refund_public_key: [&[3u8][..], &[5u8; 32]].concat(),
                refund_height: 120,
                required_confirmations: 2,
            },
        }
    }
    #[test]
    fn regtest_contract_uses_height_lock_exact_secret_length_and_p2wsh_commitment() {
        let offer = offer();
        let script = offer.bitcoin_witness_script().unwrap();
        assert_eq!(&script[..7], &[0x63, 0x82, 1, 32, 0x88, 0xa8, 32]);
        assert_eq!(&script[7..39], &offer.hashlock);
        assert!(script
            .windows(5)
            .any(|window| window == [1, 120, 0xb1, 0x69, 33]));
        let address_script = offer.bitcoin_script_pubkey().unwrap();
        assert_eq!(&address_script[..2], &[0, 32]);
        assert_eq!(&address_script[2..], &Sha256::digest(script)[..]);
        assert!(validate_revealed_secret(&offer, &[19; 32]).is_ok());
        assert!(validate_revealed_secret(&offer, &[20; 32]).is_err());
    }
    #[test]
    fn timeout_comparison_uses_chain_units_and_direction() {
        let mut offer = offer();
        assert!(offer.check_timeout_margin(1, 119, 10, 600, 600).is_ok());
        assert!(offer.check_timeout_margin(999, 119, 10, 600, 600).is_err());
        assert!(offer.check_timeout_margin(1, 120, 10, 600, 600).is_err());
        offer.secret_release = SecretRelease::PublicOnHegemon;
        assert!(offer.check_timeout_margin(1, 119, 10, 600, 600).is_err());
        offer.bitcoin.refund_height = 500_000_000;
        assert!(offer.validate().is_err());
    }

    #[test]
    fn accepted_offer_and_secret_survive_encrypted_wallet_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("swap-wallet.dat");
        let store = crate::WalletStore::create_full(&path, "disposable test passphrase").unwrap();
        let offer = offer();
        let id = store.accept_htlc_offer(offer.clone()).unwrap();
        store.save_htlc_secret(id, [19; 32]).unwrap();
        let encrypted = std::fs::read(&path).unwrap();
        assert!(!encrypted.windows(32).any(|bytes| bytes == [19; 32]));
        assert!(store.save_htlc_secret(id, [20; 32]).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), encrypted);
        let snapshot =
            crate::WalletStore::open_read_only(&path, "disposable test passphrase").unwrap();
        assert!(snapshot.save_htlc_secret(id, [19; 32]).is_err());
        drop(snapshot);
        drop(store);
        let reopened = crate::WalletStore::open(&path, "disposable test passphrase").unwrap();
        let swaps = reopened.htlc_swaps().unwrap();
        assert_eq!(swaps.len(), 1);
        assert_eq!(swaps[0].id, id);
        assert_eq!(swaps[0].offer, offer);
        assert!(swaps[0].has_secret);
        assert_eq!(reopened.accept_htlc_offer(offer).unwrap(), id);
        assert_eq!(reopened.htlc_swaps().unwrap().len(), 1);
    }
}
