//! Owned, review-bound HTLC preparation. Private agreement exchange is encrypted.
#![forbid(unsafe_code)]

use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use transaction_circuit::{
    constants::FIELD_MODULUS_U64,
    hashing_pq::ciphertext_hash_bytes,
    smallwood_htlc::{self, HtlcAction, HtlcStatement, HtlcWitness, SecretRelease},
    smallwood_htlc_transport,
    smallwood_poseidon2_v8_coinbase::{
        poseidon2_v8_note_commitment, poseidon2_v8_single_key_authorization_digest,
        poseidon2_v8_words_from_canonical_bytes, poseidon2_v8_words_to_bytes,
    },
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    htlc::{self, HtlcOffer},
    poseidon2_v8_coinbase::{
        build_poseidon2_v8_coinbase_args, build_poseidon2_v8_owned_spend_input,
        protocol_opening_to_relation,
    },
    poseidon2_v8_sync::{opening_to_words, words_to_opening, LaunchWalletContext},
    MemoPlaintext, NoteCiphertext, NotePlaintext, Poseidon2V8CanonicalTip, ShieldedAddress,
    WalletError, WalletStore,
};

fn invalid(message: &'static str) -> WalletError {
    WalletError::InvalidArgument(message)
}

fn offer(
    store: &WalletStore,
    context: LaunchWalletContext,
    id: [u8; 32],
) -> Result<HtlcOffer, WalletError> {
    store.require_launch_context(context)?;
    let offer = store
        .htlc_swaps()?
        .into_iter()
        .find(|swap| swap.id == id)
        .ok_or(invalid("unknown accepted HTLC offer"))?
        .offer;
    offer.validate()?;
    if offer.network_id != context.chain_id() {
        return Err(invalid("HTLC offer differs from pinned launch chain"));
    }
    Ok(offer)
}

fn address_fields(address: &ShieldedAddress) -> Result<([u64; 4], [u64; 7]), WalletError> {
    // Reparse the complete public address, including ML-KEM and authorization extension.
    let checked = ShieldedAddress::from_bytes(&address.to_bytes())?;
    if checked.version != crate::address::POSEIDON2_V8_ADDRESS_VERSION
        || checked.crypto_suite != protocol_versioning::CRYPTO_SUITE_ETA
    {
        return Err(invalid("HTLC requires a full V8 address"));
    }
    let recipient = poseidon2_v8_words_from_canonical_bytes(checked.pk_recipient)
        .map_err(htlc::surface_error)?;
    let mut authority = [0; 7];
    authority[..4].copy_from_slice(
        &poseidon2_v8_words_from_canonical_bytes(checked.pk_auth).map_err(htlc::surface_error)?,
    );
    for (word, bytes) in authority[4..]
        .iter_mut()
        .zip(checked.pk_auth_extension.chunks_exact(8))
    {
        *word = u64::from_le_bytes(bytes.try_into().expect("fixed address limb"));
    }
    Ok((recipient, authority))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicHtlcAgreementInfo {
    pub swap_id: [u8; 32],
    pub locked_commitment: [u64; 7],
    pub policy_digest: [u64; 7],
}

/// Generate one policy-owned opening and shared nullifier key inside encrypted wallet state.
pub fn create_htlc_agreement(
    store: &WalletStore,
    context: &LaunchWalletContext,
    swap_id: [u8; 32],
    locked_recipient: &ShieldedAddress,
) -> Result<PublicHtlcAgreementInfo, WalletError> {
    let offer = offer(store, *context, swap_id)?;
    store.derived_keys()?.ok_or(WalletError::WatchOnly)?;
    let (recipient, authority) = address_fields(locked_recipient)?;
    if ![
        (offer.claim_recipient, offer.claim_authority),
        (offer.refund_recipient, offer.refund_authority),
    ]
    .contains(&(recipient, authority))
    {
        return Err(invalid(
            "locked encryption recipient differs from agreed authorities",
        ));
    }
    if let Ok(existing) = store.htlc_private_material(swap_id, *context) {
        if existing.locked_note.recipient_key != recipient {
            return Err(invalid("existing HTLC agreement has another recipient"));
        }
        return agreement_info(swap_id, &offer, existing.locked_note);
    }
    let mut rng = OsRng;
    let base = protocol_opening_to_relation(
        build_poseidon2_v8_coinbase_args(locked_recipient, offer.value, &mut rng)?
            .miner_note
            .opening,
    );
    let mut key = Zeroizing::new([0; 5]);
    for (index, word) in key.iter_mut().enumerate() {
        loop {
            let candidate = rng.next_u64();
            if candidate < FIELD_MODULUS_U64 && (index != 0 || candidate != 0) {
                *word = candidate;
                break;
            }
        }
    }
    let note = smallwood_htlc::bind_locked_note(base, offer.policy(), *key)
        .map_err(htlc::surface_error)?;
    store.save_htlc_locked_opening(swap_id, note, *key)?;
    agreement_info(swap_id, &offer, note)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Encode;
    use protocol_shielded_pool::{
        poseidon2_v8_coinbase::MintPoseidon2V8RewardsArgs, types::CandidateArtifact,
    };
    use rand::{rngs::StdRng, SeedableRng};

    struct Fixture {
        directory: tempfile::TempDir,
        alice: WalletStore,
        bob: WalletStore,
        context: LaunchWalletContext,
        refund: ShieldedAddress,
        claim: ShieldedAddress,
        id: [u8; 32],
    }
    fn wire(
        action: u16,
        binding: protocol_versioning::VersionBinding,
        args: Vec<u8>,
        raw: &[u8],
        fee: u64,
    ) -> Vec<u8> {
        let body = (
            (binding.circuit, binding.crypto),
            1u16,
            action,
            [0u8; 48],
            Vec::<[u8; 48]>::new(),
            Vec::<[u8; 48]>::new(),
            vec![ciphertext_hash_bytes(raw)],
            vec![raw.len() as u32],
            args,
            fee,
            None::<CandidateArtifact>,
        );
        let hash = hegemon_hash384::blake2b_384_domain_hash(
            hegemon_hash384::domains::ACTION_ID_V3,
            [body.encode().as_slice()],
        );
        (hash, body).encode()
    }
    fn apply(
        store: &WalletStore,
        context: LaunchWalletContext,
        actions: Vec<Vec<u8>>,
        marker: u8,
    ) -> crate::Poseidon2V8CanonicalBlock {
        let parent = store.poseidon2_v8_tip().unwrap();
        let block = crate::Poseidon2V8CanonicalBlock {
            height: parent.height + 1,
            hash: [marker; 32],
            parent_hash: parent.block_hash,
            action_bytes: actions,
        };
        store
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&block, context)
            .unwrap();
        block
    }
    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let alice = WalletStore::create_from_root(
            directory.path().join("alice.wallet"),
            "owned",
            crate::RootSecret::from_bytes([71; 32]),
        )
        .unwrap();
        let bob = WalletStore::create_from_root(
            directory.path().join("bob.wallet"),
            "owned",
            crate::RootSecret::from_bytes([72; 32]),
        )
        .unwrap();
        let context = LaunchWalletContext::new(
            [82; 32],
            [81; 32],
            [83; 64],
            1,
            protocol_versioning::COINBASE_MATURITY + 100,
        )
        .unwrap();
        for store in [&alice, &bob] {
            store
                .ensure_poseidon2_v8_launch_genesis_for_retained_test(context, [0; 7])
                .unwrap();
            assert_eq!(store.genesis_hash().unwrap(), None);
            store.require_launch_context(context).unwrap();
        }
        // A real nonzero owned diversifier, canonical reward opening, and actual encrypted ciphertext.
        let refund = alice
            .derived_keys()
            .unwrap()
            .unwrap()
            .poseidon2_v8_address(7)
            .unwrap()
            .shielded_address();
        let claim = bob
            .derived_keys()
            .unwrap()
            .unwrap()
            .poseidon2_v8_address(0)
            .unwrap()
            .shielded_address();
        let reward = MintPoseidon2V8RewardsArgs {
            miner_note: build_poseidon2_v8_coinbase_args(
                &refund,
                103,
                &mut StdRng::seed_from_u64(11),
            )
            .unwrap()
            .miner_note,
            funding_note: None,
        };
        let raw = NoteCiphertext::from_chain_bytes(&reward.miner_note.encrypted_note.encode())
            .unwrap()
            .to_da_bytes()
            .unwrap();
        let funding = apply(
            &alice,
            context,
            vec![wire(
                12,
                protocol_versioning::VersionBinding {
                    circuit: 9,
                    crypto: 7,
                },
                reward.encode(),
                &raw,
                0,
            )],
            91,
        );
        bob.apply_poseidon2_v8_launch_canonical_block_for_retained_test(&funding, context)
            .unwrap();
        assert!(alice.poseidon2_v8_owned_notes().unwrap().is_empty());
        // Reward outputs enter the note tree only at the real maturity boundary.
        for height in 2..=protocol_versioning::COINBASE_MATURITY {
            let mut hash = [0xa5; 32];
            hash[..8].copy_from_slice(&height.to_le_bytes());
            let block = crate::Poseidon2V8CanonicalBlock {
                height,
                hash,
                parent_hash: alice.poseidon2_v8_tip().unwrap().block_hash,
                action_bytes: Vec::new(),
            };
            for store in [&alice, &bob] {
                store
                    .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&block, context)
                    .unwrap();
            }
            if height == protocol_versioning::COINBASE_MATURITY - 1 {
                assert!(alice.poseidon2_v8_owned_notes().unwrap().is_empty());
            }
        }
        assert_eq!(alice.poseidon2_v8_owned_notes().unwrap().len(), 1);
        let offer = HtlcOffer {
            version: 1,
            nonce: [84; 32],
            network_id: context.chain_id(),
            hashlock: Sha256::digest([85; 32]).into(),
            value: 100,
            maximum_fee: 5,
            timeout_height: protocol_versioning::COINBASE_MATURITY + 5,
            claim_authority: address_fields(&claim).unwrap().1,
            refund_authority: address_fields(&refund).unwrap().1,
            claim_recipient: address_fields(&claim).unwrap().0,
            refund_recipient: address_fields(&refund).unwrap().0,
            secret_release: SecretRelease::HiddenOnHegemon,
            bitcoin: htlc::BitcoinRegtestTerms {
                amount_sat: 1000,
                claim_public_key: vec![2; 33],
                refund_public_key: vec![3; 33],
                refund_height: 20,
                required_confirmations: 1,
            },
        };
        let id = alice.accept_htlc_offer(offer.clone()).unwrap();
        assert_eq!(bob.accept_htlc_offer(offer).unwrap(), id);
        create_htlc_agreement(&alice, &context, id, &claim).unwrap();
        let encrypted = export_htlc_agreement(&alice, &context, id, &claim).unwrap();
        import_htlc_agreement(&bob, &context, id, &encrypted, 0).unwrap();
        bob.save_htlc_secret(id, [85; 32]).unwrap();
        Fixture {
            directory,
            alice,
            bob,
            context,
            refund,
            claim,
            id,
        }
    }

    #[test]
    fn encrypted_agreement_is_exact_context_bound_and_private() {
        let f = fixture();
        let envelope = export_htlc_agreement(&f.alice, &f.context, f.id, &f.claim).unwrap();
        assert_eq!(envelope.len(), ENCRYPTED_AGREEMENT_BYTES);
        assert!(!envelope.windows(8).any(|bytes| bytes == AGREEMENT_MAGIC));
        let alice = f.alice.htlc_private_material(f.id, f.context).unwrap();
        let imported = import_htlc_agreement(&f.bob, &f.context, f.id, &envelope, 0).unwrap();
        assert_eq!(
            imported.locked_commitment,
            poseidon2_v8_note_commitment(alice.locked_note).unwrap()
        );
        assert!(import_htlc_agreement(&f.bob, &f.context, f.id, &envelope, 1).is_err());
        let wrong = LaunchWalletContext::new(
            f.context.chain_id(),
            f.context.genesis_hash(),
            [86; 64],
            1,
            protocol_versioning::COINBASE_MATURITY + 100,
        )
        .unwrap();
        assert!(import_htlc_agreement(&f.bob, &wrong, f.id, &envelope, 0).is_err());
        let mut tampered = envelope.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(import_htlc_agreement(&f.bob, &f.context, f.id, &tampered, 0).is_err());
        assert!(import_htlc_agreement(
            &f.bob,
            &f.context,
            f.id,
            &envelope[..envelope.len() - 1],
            0
        )
        .is_err());
        assert!(
            export_htlc_agreement(&f.alice, &f.context, f.id, &ShieldedAddress::default()).is_err()
        );
    }

    #[test]
    fn owned_lock_review_checks_diversifier_value_destination_and_exact_approval() {
        let f = fixture();
        let notes = f.alice.poseidon2_v8_owned_notes().unwrap();
        assert_eq!(notes[0].diversifier_index, 7);
        assert_eq!(notes[0].opening.value, 103);
        assert!(
            HtlcPreparation::new(&f.alice, f.context, f.id, HtlcAction::Lock, 0, 3, &f.claim)
                .is_err()
        );
        assert!(HtlcPreparation::new_for_retained_test(
            &f.alice,
            f.context,
            f.id,
            HtlcAction::Lock,
            0,
            2,
            &f.claim
        )
        .is_err());
        assert!(HtlcPreparation::new_for_retained_test(
            &f.alice,
            f.context,
            f.id,
            HtlcAction::Lock,
            1,
            3,
            &f.claim
        )
        .is_err());
        assert!(HtlcPreparation::new_for_retained_test(
            &f.alice,
            f.context,
            f.id,
            HtlcAction::Lock,
            0,
            3,
            &f.refund
        )
        .is_err());
        let plan = HtlcPreparation::new_for_retained_test(
            &f.alice,
            f.context,
            f.id,
            HtlcAction::Lock,
            0,
            3,
            &f.claim,
        )
        .unwrap();
        assert_eq!(plan.public_review().output_value, 100);
        assert_eq!(plan.public_review().destination, f.claim.encode().unwrap());
        let ct = NoteCiphertext::from_da_bytes(&plan.ciphertext).unwrap();
        let decrypted = ct
            .decrypt(
                &f.bob
                    .derived_keys()
                    .unwrap()
                    .unwrap()
                    .poseidon2_v8_address(0)
                    .unwrap(),
            )
            .unwrap();
        assert!(decrypted.r == poseidon2_v8_words_to_bytes(plan.witness.output_note.randomness));
        assert!(decrypted.rho == poseidon2_v8_words_to_bytes(plan.witness.output_note.rho));
        assert!(plan.prove_for_retained_test([0; 32]).is_err());
        assert!(f.alice.htlc_swaps().unwrap()[0].attempts.is_empty());
        let plan = HtlcPreparation::new_for_retained_test(
            &f.alice,
            f.context,
            f.id,
            HtlcAction::Lock,
            0,
            3,
            &f.claim,
        )
        .unwrap();
        assert!(HtlcPreparation::new_for_retained_test(
            &f.alice,
            f.context,
            f.id,
            HtlcAction::Lock,
            0,
            3,
            &f.claim
        )
        .is_err());
        drop(plan);
        assert!(f.alice.htlc_swaps().unwrap()[0].attempts.is_empty());
    }

    fn action_from_carrier(carrier: &[u8]) -> Vec<u8> {
        let decoded = smallwood_htlc_transport::decode_candidate_exact(carrier).unwrap();
        smallwood_htlc::verify_candidate(&decoded.statement, decoded.proof).unwrap();
        wire(
            protocol_versioning::launch_candidate::HTLC_ACTION_ID,
            protocol_versioning::launch_candidate::HTLC_VERSION_BINDING,
            carrier.to_vec(),
            decoded.ciphertext,
            decoded.statement.fee,
        )
    }
    fn retain_public(directory: &Option<std::path::PathBuf>, label: &str, carrier: &[u8]) {
        use std::io::Write;
        let Some(directory) = directory else { return };
        let decoded = smallwood_htlc_transport::decode_candidate_exact(carrier).unwrap();
        assert_eq!(decoded.statement.revealed_secret, None);
        let preamble = decoded.statement.candidate_binding_bytes().unwrap();
        let receipt = serde_json::to_vec_pretty(&serde_json::json!({
            "schema":"hegemon-owned-htlc-public-proof-v1", "production_authorized":false,
            "action":decoded.statement.action,"statement":decoded.statement,
            "carrier_bytes":carrier.len(),"carrier_sha512":hex::encode(sha2::Sha512::digest(carrier)),
            "proof_bytes":decoded.proof.len(),"proof_sha512":hex::encode(sha2::Sha512::digest(decoded.proof)),
            "relation_digest":hex::encode(smallwood_htlc::relation_digest())
        })).unwrap();
        for (suffix, bytes) in [
            ("carrier.bin", carrier),
            ("preamble.bin", preamble.as_slice()),
            ("proof.smzc", decoded.proof),
            ("receipt.json", receipt.as_slice()),
        ] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join(format!("{label}.{suffix}")))
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
    }

    #[test]
    #[ignore = "full owned-wallet SMZC Lock/Claim/Refund proving; requires dedicated two-CPU lane"]
    fn genuine_owned_wallet_lock_claim_refund_and_exact_recovery() {
        let f = fixture();
        let retained =
            std::env::var_os("HEGEMON_HTLC_OWNED_ARTIFACT_DIR").map(std::path::PathBuf::from);
        if let Some(path) = &retained {
            std::fs::create_dir(path).unwrap();
        }
        let lock = HtlcPreparation::new_for_retained_test(
            &f.alice,
            f.context,
            f.id,
            HtlcAction::Lock,
            0,
            3,
            &f.claim,
        )
        .unwrap();
        let approval = lock.review_digest();
        let prepared = lock.prove_for_retained_test(approval).unwrap();
        let id = prepared.attempt_id();
        let exported = prepared.export_for_retained_test().unwrap();
        let lock_bytes = exported.exact_carrier().to_vec();
        drop(prepared);
        assert_eq!(
            f.alice.recover_htlc_attempt(id).unwrap().exact_carrier(),
            lock_bytes
        );
        assert_eq!(
            f.alice.htlc_swaps().unwrap()[0].attempts[0].status,
            htlc::HtlcAttemptStatus::SubmissionUncertain
        );
        retain_public(&retained, "lock", &lock_bytes);
        let block = apply(
            &f.alice,
            f.context,
            vec![action_from_carrier(&lock_bytes)],
            92,
        );
        f.bob
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&block, f.context)
            .unwrap();
        let locked_tip = f.alice.poseidon2_v8_tip().unwrap();
        let position = f.bob.htlc_swaps().unwrap()[0].locked_note_positions[0];
        assert_eq!(position, 1);
        let mut wrong_kem = f.claim.clone();
        wrong_kem.pk_enc = f.refund.pk_enc.clone();
        assert!(HtlcPreparation::new_for_retained_test(
            &f.bob,
            f.context,
            f.id,
            HtlcAction::Claim,
            position,
            2,
            &wrong_kem
        )
        .is_err());
        let mut wrong_diversifier = f.claim.clone();
        wrong_diversifier.diversifier_index += 1;
        assert!(HtlcPreparation::new_for_retained_test(
            &f.bob,
            f.context,
            f.id,
            HtlcAction::Claim,
            position,
            2,
            &wrong_diversifier
        )
        .is_err());
        assert!(HtlcPreparation::new_for_retained_test(
            &f.alice,
            f.context,
            f.id,
            HtlcAction::Claim,
            position,
            2,
            &f.claim
        )
        .is_err());
        assert!(HtlcPreparation::new_for_retained_test(
            &f.alice,
            f.context,
            f.id,
            HtlcAction::Refund,
            position,
            2,
            &f.refund
        )
        .is_err());
        let claim = HtlcPreparation::new_for_retained_test(
            &f.bob,
            f.context,
            f.id,
            HtlcAction::Claim,
            position,
            2,
            &f.claim,
        )
        .unwrap();
        let approval = claim.review_digest();
        let prepared = claim.prove_for_retained_test(approval).unwrap();
        let claim_id = prepared.attempt_id();
        let claim_bytes = prepared
            .export_for_retained_test()
            .unwrap()
            .exact_carrier()
            .to_vec();
        drop(prepared);
        assert_eq!(
            f.bob
                .recover_htlc_attempt(claim_id)
                .unwrap()
                .exact_carrier(),
            claim_bytes
        );
        retain_public(&retained, "claim", &claim_bytes);
        let block = apply(
            &f.bob,
            f.context,
            vec![action_from_carrier(&claim_bytes)],
            93,
        );
        f.alice
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&block, f.context)
            .unwrap();
        assert!(f
            .bob
            .poseidon2_v8_owned_notes()
            .unwrap()
            .iter()
            .any(|note| note.opening.value == 98 && !note.spent));
        f.alice
            .rollback_poseidon2_v8_to(locked_tip.height, locked_tip.block_hash)
            .unwrap();
        f.bob
            .rollback_poseidon2_v8_to(locked_tip.height, locked_tip.block_hash)
            .unwrap();
        let timeout_height = f.alice.htlc_swaps().unwrap()[0].offer.timeout_height;
        while f.alice.poseidon2_v8_tip().unwrap().height < timeout_height {
            let marker = 100 + f.alice.poseidon2_v8_tip().unwrap().height as u8;
            let block = apply(&f.alice, f.context, vec![], marker);
            f.bob
                .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&block, f.context)
                .unwrap();
        }
        let refund = HtlcPreparation::new_for_retained_test(
            &f.alice,
            f.context,
            f.id,
            HtlcAction::Refund,
            position,
            1,
            &f.refund,
        )
        .unwrap();
        let approval = refund.review_digest();
        let prepared = refund.prove_for_retained_test(approval).unwrap();
        let refund_id = prepared.attempt_id();
        let refund_bytes = prepared
            .export_for_retained_test()
            .unwrap()
            .exact_carrier()
            .to_vec();
        drop(prepared);
        retain_public(&retained, "refund", &refund_bytes);
        let claim_statement = smallwood_htlc_transport::decode_candidate_exact(&claim_bytes)
            .unwrap()
            .statement;
        let refund_statement = smallwood_htlc_transport::decode_candidate_exact(&refund_bytes)
            .unwrap()
            .statement;
        assert_eq!(claim_statement.nullifier, refund_statement.nullifier);
        let block = apply(
            &f.alice,
            f.context,
            vec![action_from_carrier(&refund_bytes)],
            109,
        );
        f.bob
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&block, f.context)
            .unwrap();
        assert!(f
            .alice
            .poseidon2_v8_owned_notes()
            .unwrap()
            .iter()
            .any(|note| note.opening.value == 99 && !note.spent));
        let alice_path = f.directory.path().join("alice.wallet");
        drop(f.alice);
        let reopened = WalletStore::open(alice_path, "owned").unwrap();
        assert_eq!(
            reopened
                .recover_htlc_attempt(refund_id)
                .unwrap()
                .exact_carrier(),
            refund_bytes
        );
        assert_eq!(
            reopened.recover_htlc_attempt(id).unwrap().exact_carrier(),
            lock_bytes
        );
    }
}

fn agreement_info(
    id: [u8; 32],
    offer: &HtlcOffer,
    note: transaction_circuit::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8NoteOpening,
) -> Result<PublicHtlcAgreementInfo, WalletError> {
    Ok(PublicHtlcAgreementInfo {
        swap_id: id,
        locked_commitment: poseidon2_v8_note_commitment(note).map_err(htlc::surface_error)?,
        policy_digest: smallwood_htlc::htlc_policy_digest(offer.policy())
            .map_err(htlc::surface_error)?,
    })
}

const AGREEMENT_MAGIC: &[u8; 8] = b"HGHAG001";
const AGREEMENT_BYTES: usize = 8 + 32 + 32 + 64 + 32 + 18 * 8 + 5 * 8;
const ENCRYPTED_AGREEMENT_BYTES: usize = 7 + 12 + 1568 + 128 + AGREEMENT_BYTES + 16;

/// Encrypted ML-KEM agreement only. The fixed private payload has no public serde/Debug API.
pub fn export_htlc_agreement(
    store: &WalletStore,
    context: &LaunchWalletContext,
    swap_id: [u8; 32],
    recipient: &ShieldedAddress,
) -> Result<Vec<u8>, WalletError> {
    let material = store.htlc_private_material(swap_id, *context)?;
    let (recipient_key, authority) = address_fields(recipient)?;
    if ![
        (
            material.offer.claim_recipient,
            material.offer.claim_authority,
        ),
        (
            material.offer.refund_recipient,
            material.offer.refund_authority,
        ),
    ]
    .contains(&(recipient_key, authority))
    {
        return Err(invalid(
            "private agreement encryption recipient is not an agreed party",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(AGREEMENT_BYTES));
    bytes.extend_from_slice(AGREEMENT_MAGIC);
    bytes.extend_from_slice(&context.chain_id());
    bytes.extend_from_slice(&context.genesis_hash());
    bytes.extend_from_slice(&context.manifest_digest());
    bytes.extend_from_slice(&swap_id);
    for word in opening_to_words(material.locked_note)
        .into_iter()
        .chain(material.policy_nullifier_key)
    {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let mut plaintext = NotePlaintext::random(0, 0, MemoPlaintext::new(bytes.to_vec()), &mut OsRng);
    let encrypted = NoteCiphertext::encrypt(recipient, &plaintext, &mut OsRng);
    plaintext.memo.0.zeroize();
    plaintext.rho.zeroize();
    plaintext.r.zeroize();
    let envelope = encrypted?.to_bytes();
    if envelope.len() != ENCRYPTED_AGREEMENT_BYTES {
        return Err(invalid("unexpected encrypted HTLC agreement framing"));
    }
    Ok(envelope)
}

/// Decrypt privately with the encrypted store's selected diversifier, then validate the exact offer.
/// Confidentiality does not authenticate a sender: the counterparty must compare the public commitment.
pub fn import_htlc_agreement(
    store: &WalletStore,
    context: &LaunchWalletContext,
    swap_id: [u8; 32],
    envelope: &[u8],
    diversifier_index: u32,
) -> Result<PublicHtlcAgreementInfo, WalletError> {
    let offer = offer(store, *context, swap_id)?;
    if envelope.len() != ENCRYPTED_AGREEMENT_BYTES {
        return Err(invalid("encrypted HTLC agreement length"));
    }
    let keys = store.derived_keys()?.ok_or(WalletError::WatchOnly)?;
    let recipient = keys.poseidon2_v8_address(diversifier_index)?;
    let fields = address_fields(&recipient.shielded_address())?;
    if ![
        (offer.claim_recipient, offer.claim_authority),
        (offer.refund_recipient, offer.refund_authority),
    ]
    .contains(&fields)
    {
        return Err(invalid(
            "agreement decryption address is not an agreed party",
        ));
    }
    let mut plaintext = NoteCiphertext::from_bytes(envelope)?.decrypt(&recipient)?;
    let private = Zeroizing::new(std::mem::take(&mut plaintext.memo.0));
    plaintext.rho.zeroize();
    plaintext.r.zeroize();
    if private.len() != AGREEMENT_BYTES
        || plaintext.value != 0
        || plaintext.asset_id != 0
        || &private[..8] != AGREEMENT_MAGIC
        || private[8..40] != context.chain_id()
        || private[40..72] != context.genesis_hash()
        || private[72..136] != context.manifest_digest()
        || private[136..168] != swap_id
    {
        return Err(invalid("private HTLC agreement identity mismatch"));
    }
    let mut words = Zeroizing::new([0u64; 23]);
    for (word, bytes) in words.iter_mut().zip(private[168..].chunks_exact(8)) {
        *word = u64::from_le_bytes(bytes.try_into().expect("fixed agreement limb"));
    }
    let note = words_to_opening(words[..18].try_into().expect("fixed opening"))?;
    let key = words[18..].try_into().expect("fixed nullifier key");
    if note.recipient_key != offer.claim_recipient && note.recipient_key != offer.refund_recipient {
        return Err(invalid(
            "agreed locked opening recipient differs from offer",
        ));
    }
    store.save_htlc_locked_opening(swap_id, note, key)?;
    agreement_info(swap_id, &offer, note)
}

/// Public approval surface only; no opening, credential, nullifier key or preimage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HtlcPreparationReview {
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub manifest_digest: String,
    pub swap_id: [u8; 32],
    pub action: HtlcAction,
    pub amount: u64,
    pub output_value: u64,
    pub fee: u64,
    pub input_position: u64,
    pub input_commitment: [u64; 7],
    pub nullifier: [u64; 7],
    pub output_commitment: [u64; 7],
    pub ciphertext_commitment: Vec<u8>,
    pub reference_height: u64,
    pub reference_hash: [u8; 32],
    pub note_root: [u64; 7],
    pub stablecoin_root: Option<[u64; 7]>,
    pub policy_digest: [u64; 7],
    pub secret_release: SecretRelease,
    pub destination: String,
}

/// Opaque non-Clone plan. Drop cancels only its still-Proving reservation.
pub struct HtlcPreparation<'a> {
    store: &'a WalletStore,
    context: LaunchWalletContext,
    tip: Poseidon2V8CanonicalTip,
    review: HtlcPreparationReview,
    digest: [u8; 32],
    statement: HtlcStatement,
    witness: HtlcWitness,
    ciphertext: Vec<u8>,
    attempt_id: Option<[u8; 32]>,
    require_authority: bool,
}

impl<'a> HtlcPreparation<'a> {
    pub fn new(
        store: &'a WalletStore,
        context: LaunchWalletContext,
        swap_id: [u8; 32],
        action: HtlcAction,
        input_position: u64,
        fee: u64,
        destination: &ShieldedAddress,
    ) -> Result<Self, WalletError> {
        Self::construct(
            store,
            context,
            swap_id,
            action,
            input_position,
            fee,
            destination,
            true,
        )
    }
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn new_for_retained_test(
        store: &'a WalletStore,
        context: LaunchWalletContext,
        swap_id: [u8; 32],
        action: HtlcAction,
        input_position: u64,
        fee: u64,
        destination: &ShieldedAddress,
    ) -> Result<Self, WalletError> {
        Self::construct(
            store,
            context,
            swap_id,
            action,
            input_position,
            fee,
            destination,
            false,
        )
    }
    fn construct(
        store: &'a WalletStore,
        context: LaunchWalletContext,
        swap_id: [u8; 32],
        action: HtlcAction,
        input_position: u64,
        fee: u64,
        destination: &ShieldedAddress,
        require_authority: bool,
    ) -> Result<Self, WalletError> {
        let offer = offer(store, context, swap_id)?;
        // Launch identity lives in the native V8 mirror, not the legacy sync
        // genesis field. This getter also checks the exact pinned context.
        let private = store.htlc_private_material(swap_id, context)?;
        let tip = store.poseidon2_v8_tip()?;
        let inclusion = context.require_canonical_parent(context.genesis_hash(), tip.height)?;
        if require_authority {
            context.require_source_authority()?;
            require_authority_at(context, inclusion, 1)?;
        }
        if fee > offer.maximum_fee || fee >= offer.value || input_position > u32::MAX as u64 {
            return Err(invalid("HTLC exact amount, fee or input position invalid"));
        }
        let (recipient, authority) = address_fields(destination)?;
        let keys = store.derived_keys()?.ok_or(WalletError::WatchOnly)?;
        let spend_key = Zeroizing::new(keys.spend.poseidon2_v8_words()?);
        let owned_authority = poseidon2_v8_single_key_authorization_digest(*spend_key)
            .map_err(htlc::surface_error)?;
        let (input_commitment, nullifier, output) = if action == HtlcAction::Lock {
            if recipient != private.locked_note.recipient_key
                || ![
                    (offer.claim_recipient, offer.claim_authority),
                    (offer.refund_recipient, offer.refund_authority),
                ]
                .contains(&(recipient, authority))
            {
                return Err(invalid(
                    "HTLC lock ciphertext destination differs from private agreement",
                ));
            }
            let owned = store
                .poseidon2_v8_owned_notes()?
                .into_iter()
                .find(|note| !note.spent && note.position == input_position)
                .ok_or(invalid(
                    "selected HTLC Lock input is not an unspent owned note",
                ))?;
            if owned.opening.value
                != offer
                    .value
                    .checked_add(fee)
                    .ok_or(invalid("HTLC input value overflow"))?
            {
                return Err(invalid(
                    "HTLC Lock needs exactly one owned note worth offer value plus fee",
                ));
            }
            let material = keys.poseidon2_v8_address(owned.diversifier_index)?;
            build_poseidon2_v8_owned_spend_input(
                &material,
                &keys.spend,
                owned.opening,
                owned.position,
                owned.path,
            )?;
            (owned.commitment, owned.nullifier, private.locked_note)
        } else {
            let expected = if action == HtlcAction::Claim {
                (offer.claim_recipient, offer.claim_authority)
            } else {
                (offer.refund_recipient, offer.refund_authority)
            };
            if (recipient, authority) != expected || owned_authority != expected.1 {
                return Err(invalid(
                    "HTLC branch destination or wallet authority differs from offer",
                ));
            }
            if *destination
                != keys
                    .poseidon2_v8_address(destination.diversifier_index)?
                    .shielded_address()
            {
                return Err(invalid(
                    "HTLC branch ciphertext address is not the wallet's exact derived address",
                ));
            }
            if action == HtlcAction::Claim && private.secret.is_none() {
                return Err(invalid(
                    "HTLC Claim preimage is not saved in encrypted wallet",
                ));
            }
            let output = protocol_opening_to_relation(
                build_poseidon2_v8_coinbase_args(destination, offer.value - fee, &mut OsRng)?
                    .miner_note
                    .opening,
            );
            (
                poseidon2_v8_note_commitment(private.locked_note).map_err(htlc::surface_error)?,
                smallwood_htlc::htlc_nullifier(
                    private.policy_nullifier_key,
                    input_position as u32,
                    private.locked_note,
                )
                .map_err(htlc::surface_error)?,
                output,
            )
        };
        // The locked owner differs from a SingleKey owner: encrypt this exact opening directly.
        let mut plaintext = NotePlaintext {
            value: output.value,
            asset_id: output.asset_id,
            rho: poseidon2_v8_words_to_bytes(output.rho),
            r: poseidon2_v8_words_to_bytes(output.randomness),
            memo: MemoPlaintext::default(),
        };
        let encrypted = NoteCiphertext::encrypt(destination, &plaintext, &mut OsRng);
        plaintext.rho.zeroize();
        plaintext.r.zeroize();
        let ciphertext = encrypted?.to_da_bytes()?;
        let statement = HtlcStatement {
            version: smallwood_htlc::HTLC_STATEMENT_VERSION,
            action,
            network_id: context.chain_id(),
            parent_hash: tip.block_hash,
            parent_height: tip.height,
            merkle_root: tip.anchor,
            nullifier,
            output_commitment: poseidon2_v8_note_commitment(output).map_err(htlc::surface_error)?,
            ciphertext_commitment: ciphertext_hash_bytes(&ciphertext),
            fee,
            revealed_secret: if action == HtlcAction::Claim
                && offer.secret_release == SecretRelease::PublicOnHegemon
            {
                private.secret
            } else {
                None
            },
        };
        htlc::validate_offer_statement(&offer, &statement)?;
        let witness =
            store.build_htlc_witness(swap_id, &statement, input_position, *spend_key, output)?;
        smallwood_htlc::compile(&statement, &witness).map_err(htlc::surface_error)?;
        let review = HtlcPreparationReview {
            chain_id: context.chain_id(),
            genesis_hash: context.genesis_hash(),
            manifest_digest: hex::encode(context.manifest_digest()),
            swap_id,
            action,
            amount: offer.value,
            output_value: output.value,
            fee,
            input_position,
            input_commitment,
            nullifier,
            output_commitment: statement.output_commitment,
            ciphertext_commitment: statement.ciphertext_commitment.to_vec(),
            reference_height: tip.height,
            reference_hash: tip.block_hash,
            note_root: tip.anchor,
            stablecoin_root: tip.stablecoin_root,
            policy_digest: smallwood_htlc::htlc_policy_digest(offer.policy())
                .map_err(htlc::surface_error)?,
            secret_release: offer.secret_release,
            destination: destination.encode()?,
        };
        let mut hasher = Sha256::new();
        hasher.update(b"hegemon.htlc.owned-review.v1");
        hasher.update(serde_json::to_vec(&review).map_err(htlc::surface_error)?);
        let digest = hasher.finalize().into();
        let attempt_id = store.reserve_htlc_attempt(
            swap_id,
            statement.clone(),
            input_commitment,
            input_position,
        )?;
        Ok(Self {
            store,
            context,
            tip,
            review,
            digest,
            statement,
            witness,
            ciphertext,
            attempt_id: Some(attempt_id),
            require_authority,
        })
    }
    pub fn public_review(&self) -> &HtlcPreparationReview {
        &self.review
    }
    pub fn review_digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn prove(
        self,
        approved_digest: [u8; 32],
    ) -> Result<PreparedHtlcCandidate<'a>, WalletError> {
        if !self.require_authority {
            return Err(invalid(
                "retained plan requires explicit retained proof method",
            ));
        }
        self.prove_inner(approved_digest)
    }
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn prove_for_retained_test(
        self,
        approved_digest: [u8; 32],
    ) -> Result<PreparedHtlcCandidate<'a>, WalletError> {
        if self.require_authority {
            return Err(invalid("production plan requires production proof method"));
        }
        self.prove_inner(approved_digest)
    }
    fn prove_inner(
        mut self,
        approved_digest: [u8; 32],
    ) -> Result<PreparedHtlcCandidate<'a>, WalletError> {
        if approved_digest != self.digest {
            return Err(invalid("HTLC approval differs from exact public review"));
        }
        let id = self.attempt_id.ok_or(invalid("HTLC reservation absent"))?;
        let height = self
            .store
            .check_htlc_preparation(id, self.context, &self.statement)?;
        if self.require_authority {
            self.context.require_source_authority()?;
            require_authority_at(
                self.context,
                height,
                smallwood_htlc::candidate_proof_size_hint(&self.statement)
                    .map_err(htlc::surface_error)?,
            )?;
        }
        let carrier =
            htlc::prepare_candidate_carrier(&self.statement, &self.witness, &self.ciphertext)?;
        let decoded = smallwood_htlc_transport::decode_candidate_exact(&carrier)
            .map_err(htlc::surface_error)?;
        let height = self
            .store
            .check_htlc_preparation(id, self.context, &self.statement)?;
        if self.require_authority {
            require_authority_at(self.context, height, decoded.proof.len())?;
        }
        if self.require_authority {
            self.store.prepare_htlc_submission(id, carrier)?;
        } else {
            #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
            self.store
                .prepare_htlc_submission_for_retained_test(id, carrier)?;
            #[cfg(not(any(test, feature = "poseidon2-v8-retained-test-support")))]
            return Err(invalid(
                "retained HTLC preparation is absent from this build",
            ));
        }
        self.attempt_id = None;
        Ok(PreparedHtlcCandidate {
            store: self.store,
            context: self.context,
            tip: self.tip,
            attempt_id: id,
            review: self.review.clone(),
            digest: self.digest,
            require_authority: self.require_authority,
        })
    }
}

impl Drop for HtlcPreparation<'_> {
    fn drop(&mut self) {
        self.witness.spend_key.zeroize();
        self.witness.policy_nullifier_key.zeroize();
        self.witness.secret.zeroize();
        self.witness.input_note.rho.zeroize();
        self.witness.input_note.randomness.zeroize();
        self.witness.output_note.rho.zeroize();
        self.witness.output_note.randomness.zeroize();
        if let Some(id) = self.attempt_id {
            // Atomic cancellation cannot delete a concurrently sealed Ready candidate.
            let _ = self.store.cancel_htlc_proving_attempt(id);
        }
    }
}

fn require_authority_at(
    context: LaunchWalletContext,
    height: u64,
    bytes: usize,
) -> Result<(), WalletError> {
    if protocol_versioning::launch_candidate::launch_proof_authority(context.request(
        protocol_versioning::launch_candidate::LaunchProofKind::Htlc,
        height,
        bytes,
    ))
    .is_none()
    {
        return Err(invalid(
            "HTLC has no exact source-owned launch proof authority",
        ));
    }
    Ok(())
}

/// Ready is durable and deliberately survives Drop. Exact public bytes cross only the journal's ambiguity barrier.
pub struct PreparedHtlcCandidate<'a> {
    store: &'a WalletStore,
    context: LaunchWalletContext,
    tip: Poseidon2V8CanonicalTip,
    attempt_id: [u8; 32],
    review: HtlcPreparationReview,
    digest: [u8; 32],
    require_authority: bool,
}
impl PreparedHtlcCandidate<'_> {
    pub fn attempt_id(&self) -> [u8; 32] {
        self.attempt_id
    }
    pub fn captured_tip(&self) -> Poseidon2V8CanonicalTip {
        self.tip
    }
    pub fn public_review(&self) -> &HtlcPreparationReview {
        &self.review
    }
    pub fn review_digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn store(&self) -> &WalletStore {
        self.store
    }
    pub fn export(&self) -> Result<crate::htlc::HtlcAttemptExport, WalletError> {
        if !self.require_authority {
            return Err(invalid(
                "retained candidate requires explicit retained export",
            ));
        }
        self.store.require_launch_context(self.context)?;
        self.store.export_htlc_attempt(self.attempt_id)
    }
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn export_for_retained_test(&self) -> Result<crate::htlc::HtlcAttemptExport, WalletError> {
        if self.require_authority {
            return Err(invalid("production candidate requires production export"));
        }
        self.store.require_launch_context(self.context)?;
        self.store
            .export_htlc_attempt_for_retained_test(self.attempt_id)
    }
}
