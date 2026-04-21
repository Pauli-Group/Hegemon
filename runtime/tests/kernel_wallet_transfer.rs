use codec::{Decode, Encode};
use frame_support::assert_ok;
use frame_support::sp_runtime::BuildStorage;
use rand::{rngs::StdRng, SeedableRng};
use runtime::{Kernel, Runtime, RuntimeOrigin, ShieldedPool, System, Timestamp};
use sp_io::TestExternalities;
use sp_runtime::traits::ValidateUnsigned;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidityError,
};
use superneo_hegemon::decode_native_tx_leaf_artifact_bytes;
use tempfile::tempdir;
use transaction_circuit::constants::NATIVE_ASSET_ID;
use transaction_circuit::hashing_pq::{
    balance_commitment_bytes, ciphertext_hash_bytes, felts_to_bytes48,
};
use transaction_circuit::public_inputs::BalanceSlot;
use wallet::{
    build_transaction, MemoPlaintext, NoteCiphertext, NotePlaintext, Recipient, WalletStore,
};

fn new_ext() -> TestExternalities {
    let spec = runtime::chain_spec::development_config();
    spec.genesis.build_storage().unwrap().into()
}

fn sync_kernel_roots() {
    let family_root = pallet_shielded_pool::pallet::MerkleTree::<Runtime>::get().root();
    pallet_kernel::pallet::FamilyRoots::<Runtime>::insert(
        pallet_shielded_pool::family::FAMILY_SHIELDED_POOL,
        family_root,
    );
    let global_root = protocol_kernel::compute_kernel_global_root(
        pallet_kernel::pallet::FamilyRoots::<Runtime>::iter(),
    );
    pallet_kernel::pallet::KernelGlobalRoot::<Runtime>::put(global_root);
}

fn seed_wallet_note_with_plaintext(store: &WalletStore, note: NotePlaintext) {
    let mut rng = StdRng::seed_from_u64(7);
    let address = store.primary_address().expect("primary address");
    let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).expect("encrypt note");
    let recovered = store
        .full_viewing_key()
        .expect("full viewing key")
        .expect("wallet is full")
        .decrypt_note(&ciphertext)
        .expect("recover note");
    let commitment = felts_to_bytes48(&recovered.note_data.commitment());
    let encrypted_note = pallet_shielded_pool::types::EncryptedNote::decode(
        &mut ciphertext
            .to_pallet_bytes()
            .expect("pallet bytes")
            .as_slice(),
    )
    .expect("decode pallet encrypted note");

    store
        .append_commitments(&[(0, commitment)])
        .expect("append commitment");
    store
        .register_ciphertext_index(0)
        .expect("ciphertext index");
    store
        .record_recovered_note(recovered, 0, 0)
        .expect("record recovered note");

    pallet_shielded_pool::pallet::Commitments::<Runtime>::insert(0, commitment);
    pallet_shielded_pool::pallet::EncryptedNotes::<Runtime>::insert(0, encrypted_note);
    pallet_shielded_pool::pallet::CommitmentIndex::<Runtime>::put(1);
    pallet_shielded_pool::pallet::PoolBalance::<Runtime>::put(note.value as u128);

    let mut tree = pallet_shielded_pool::pallet::MerkleTree::<Runtime>::get();
    tree.append(commitment).expect("append merkle leaf");
    let root = tree.root();
    pallet_shielded_pool::pallet::MerkleTree::<Runtime>::put(tree);
    pallet_shielded_pool::pallet::MerkleRoots::<Runtime>::insert(root, System::block_number());

    let mut history = pallet_shielded_pool::pallet::MerkleRootHistory::<Runtime>::get();
    if history.last().copied() != Some(root) {
        history.try_push(root).expect("root history capacity");
        pallet_shielded_pool::pallet::MerkleRootHistory::<Runtime>::put(history);
    }

    sync_kernel_roots();
}

fn seed_wallet_note(store: &WalletStore, value: u64) {
    let mut rng = StdRng::seed_from_u64(7);
    seed_wallet_note_with_plaintext(
        store,
        NotePlaintext::random(value, NATIVE_ASSET_ID, MemoPlaintext::default(), &mut rng),
    );
}

fn wallet_sidecar_args(
    bundle: &wallet::rpc::TransactionBundle,
) -> pallet_shielded_pool::family::ShieldedTransferSidecarArgs {
    let decoded_notes = bundle.decode_notes().expect("decode built notes");
    let mut ciphertext_hashes = Vec::with_capacity(decoded_notes.len());
    let mut ciphertext_sizes = Vec::with_capacity(decoded_notes.len());
    for note in &decoded_notes {
        let bytes = note.to_da_bytes().expect("note to da bytes");
        ciphertext_hashes.push(ciphertext_hash_bytes(&bytes));
        ciphertext_sizes.push(u32::try_from(bytes.len()).expect("ciphertext size fits in u32"));
    }

    pallet_shielded_pool::family::ShieldedTransferSidecarArgs {
        proof: bundle.proof_bytes.clone(),
        commitments: bundle.commitments.clone(),
        ciphertext_hashes,
        ciphertext_sizes,
        anchor: bundle.anchor,
        balance_slot_asset_ids: bundle.balance_slot_asset_ids,
        binding_hash: bundle.binding_hash,
        stablecoin: None,
        fee: bundle.fee,
    }
}

#[test]
fn kernel_wallet_unsigned_transfer_survives_kernel_validate_and_apply() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(1_000);

        let dir = tempdir().expect("tempdir");
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "sender-pass").expect("sender wallet");
        let recipient =
            WalletStore::create_full(&recipient_path, "recipient-pass").expect("recipient wallet");

        seed_wallet_note(&sender, 250_000_000);

        let built = build_transaction(
            &sender,
            &[Recipient {
                address: recipient.primary_address().expect("recipient address"),
                value: 100_000_000,
                asset_id: NATIVE_ASSET_ID,
                memo: MemoPlaintext::new(b"kernel envelope regression".to_vec()),
            }],
            0,
        )
        .expect("wallet build_transaction");

        let ciphertexts = built
            .bundle
            .decode_notes()
            .expect("decode built notes")
            .into_iter()
            .map(|note| {
                let bytes = note.to_pallet_bytes().expect("note to pallet bytes");
                pallet_shielded_pool::types::EncryptedNote::decode(&mut bytes.as_slice())
                    .expect("decode note")
            })
            .collect::<Vec<_>>();
        let ciphertext_hashes = ciphertexts
            .iter()
            .map(|ciphertext| {
                let mut bytes = Vec::with_capacity(
                    ciphertext.ciphertext.len() + ciphertext.kem_ciphertext.len(),
                );
                bytes.extend_from_slice(&ciphertext.ciphertext);
                bytes.extend_from_slice(&ciphertext.kem_ciphertext);
                ciphertext_hash_bytes(&bytes)
            })
            .collect::<Vec<_>>();

        let args = pallet_shielded_pool::family::ShieldedTransferInlineArgs {
            proof: built.bundle.proof_bytes.clone(),
            commitments: built.bundle.commitments.clone(),
            ciphertexts,
            anchor: built.bundle.anchor,
            balance_slot_asset_ids: built.bundle.balance_slot_asset_ids,
            binding_hash: built.bundle.binding_hash,
            stablecoin: None,
            fee: built.bundle.fee,
        };
        let decoded = decode_native_tx_leaf_artifact_bytes(&built.bundle.proof_bytes)
            .expect("decode tx leaf");
        let balance_slots = args
            .balance_slot_asset_ids
            .into_iter()
            .map(|asset_id| BalanceSlot {
                asset_id: if asset_id == u64::MAX {
                    4_294_967_294
                } else {
                    asset_id
                },
                delta: 0,
            })
            .collect::<Vec<_>>();
        let canonical_balance_slot_asset_ids = args
            .balance_slot_asset_ids
            .into_iter()
            .map(|asset_id| {
                if asset_id == u64::MAX {
                    4_294_967_294
                } else {
                    asset_id
                }
            })
            .collect::<Vec<_>>();
        let expected_balance_tag =
            balance_commitment_bytes(i128::from(args.fee), &balance_slots).expect("balance tag");
        assert_eq!(decoded.tx.nullifiers, built.bundle.nullifiers);
        assert_eq!(decoded.tx.commitments, built.bundle.commitments);
        assert_eq!(decoded.tx.ciphertext_hashes, ciphertext_hashes);
        assert_eq!(decoded.tx.balance_tag, expected_balance_tag);
        assert_eq!(
            decoded.stark_public_inputs.merkle_root, built.bundle.anchor,
            "artifact anchor mismatch"
        );
        assert_eq!(
            decoded.stark_public_inputs.balance_slot_asset_ids, canonical_balance_slot_asset_ids,
            "artifact balance slots mismatch"
        );
        assert_eq!(decoded.stark_public_inputs.fee, args.fee);
        let envelope = pallet_shielded_pool::family::build_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
            built.bundle.nullifiers.clone(),
            args.encode(),
        );

        let call = pallet_kernel::Call::<Runtime>::submit_action {
            envelope: envelope.clone(),
        };
        let validity =
            pallet_kernel::Pallet::<Runtime>::validate_unsigned(TransactionSource::External, &call);
        assert!(
            validity.is_ok(),
            "wallet-built kernel action should validate: {validity:?}"
        );

        let prior_commitment_index = ShieldedPool::commitment_index();
        assert_ok!(Kernel::submit_action(RuntimeOrigin::none(), envelope));

        assert_eq!(
            ShieldedPool::commitment_index(),
            prior_commitment_index + built.bundle.commitments.len() as u64
        );
        for nullifier in &built.bundle.nullifiers {
            assert!(
                pallet_shielded_pool::pallet::Nullifiers::<Runtime>::contains_key(nullifier),
                "runtime should record submitted nullifier"
            );
        }
    });
}

#[test]
fn kernel_wallet_unsigned_transfer_missing_anchor_is_future() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(1_000);
        let ciphertexts = vec![pallet_shielded_pool::types::EncryptedNote::default()];
        let anchor = [9u8; 48];
        let balance_slot_asset_ids = [0, u64::MAX, u64::MAX, u64::MAX];
        let nullifiers = vec![[1u8; 48]];
        let commitments = vec![[2u8; 48]];
        let ciphertext_hashes = ciphertexts
            .iter()
            .map(|note| {
                let mut bytes =
                    Vec::with_capacity(note.ciphertext.len() + note.kem_ciphertext.len());
                bytes.extend_from_slice(&note.ciphertext);
                bytes.extend_from_slice(&note.kem_ciphertext);
                ciphertext_hash_bytes(&bytes)
            })
            .collect::<Vec<_>>();
        let binding_hash = pallet_shielded_pool::verifier::StarkVerifier::compute_binding_hash(
            &pallet_shielded_pool::verifier::ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone(),
                commitments: commitments.clone(),
                ciphertext_hashes,
                balance_slot_asset_ids,
                fee: 0,
                value_balance: 0,
                stablecoin: None,
            },
        );
        let args = pallet_shielded_pool::family::ShieldedTransferInlineArgs {
            proof: vec![1u8; 32],
            commitments,
            ciphertexts,
            anchor,
            balance_slot_asset_ids,
            binding_hash: binding_hash.data,
            stablecoin: None,
            fee: 0,
        };
        let envelope = pallet_shielded_pool::family::build_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
            nullifiers,
            args.encode(),
        );
        let call = pallet_kernel::Call::<Runtime>::submit_action { envelope };

        let validity =
            pallet_kernel::Pallet::<Runtime>::validate_unsigned(TransactionSource::External, &call);
        assert!(
            matches!(
                validity,
                Err(TransactionValidityError::Invalid(
                    InvalidTransaction::Future
                ))
            ),
            "kernel wrapper should preserve future-anchor deferral: {validity:?}"
        );
    });
}

#[test]
fn kernel_wallet_unsigned_sidecar_missing_anchor_is_future() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(1_000);

        let dir = tempdir().expect("tempdir");
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "sender-pass").expect("sender wallet");
        let recipient =
            WalletStore::create_full(&recipient_path, "recipient-pass").expect("recipient wallet");

        seed_wallet_note(&sender, 250_000_000);

        let built = build_transaction(
            &sender,
            &[Recipient {
                address: recipient.primary_address().expect("recipient address"),
                value: 100_000_000,
                asset_id: NATIVE_ASSET_ID,
                memo: MemoPlaintext::new(b"sidecar missing anchor".to_vec()),
            }],
            0,
        )
        .expect("wallet build_transaction");

        let mut args = wallet_sidecar_args(&built.bundle);
        args.anchor = [9u8; 48];
        let binding_hash = pallet_shielded_pool::verifier::StarkVerifier::compute_binding_hash(
            &pallet_shielded_pool::verifier::ShieldedTransferInputs {
                anchor: args.anchor,
                nullifiers: built.bundle.nullifiers.clone(),
                commitments: built.bundle.commitments.clone(),
                ciphertext_hashes: args.ciphertext_hashes.clone(),
                balance_slot_asset_ids: built.bundle.balance_slot_asset_ids,
                fee: built.bundle.fee,
                value_balance: 0,
                stablecoin: None,
            },
        );
        args.binding_hash = binding_hash.data;

        let envelope = pallet_shielded_pool::family::build_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_SIDECAR,
            built.bundle.nullifiers.clone(),
            args.encode(),
        );
        let call = pallet_kernel::Call::<Runtime>::submit_action { envelope };

        let validity =
            pallet_kernel::Pallet::<Runtime>::validate_unsigned(TransactionSource::External, &call);
        assert!(
            matches!(
                validity,
                Err(TransactionValidityError::Invalid(
                    InvalidTransaction::Future
                ))
            ),
            "kernel wrapper should preserve future-anchor deferral for sidecar transfers: {validity:?}"
        );
    });
}

#[test]
fn kernel_wallet_unsigned_transfer_replay_is_stale() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(1_000);

        let dir = tempdir().expect("tempdir");
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "sender-pass").expect("sender wallet");
        let recipient =
            WalletStore::create_full(&recipient_path, "recipient-pass").expect("recipient wallet");

        seed_wallet_note(&sender, 250_000_000);

        let built = build_transaction(
            &sender,
            &[Recipient {
                address: recipient.primary_address().expect("recipient address"),
                value: 100_000_000,
                asset_id: NATIVE_ASSET_ID,
                memo: MemoPlaintext::new(b"stale replay regression".to_vec()),
            }],
            0,
        )
        .expect("wallet build_transaction");

        let ciphertexts = built
            .bundle
            .decode_notes()
            .expect("decode built notes")
            .into_iter()
            .map(|note| {
                let bytes = note.to_pallet_bytes().expect("note to pallet bytes");
                pallet_shielded_pool::types::EncryptedNote::decode(&mut bytes.as_slice())
                    .expect("decode note")
            })
            .collect::<Vec<_>>();

        let args = pallet_shielded_pool::family::ShieldedTransferInlineArgs {
            proof: built.bundle.proof_bytes.clone(),
            commitments: built.bundle.commitments.clone(),
            ciphertexts,
            anchor: built.bundle.anchor,
            balance_slot_asset_ids: built.bundle.balance_slot_asset_ids,
            binding_hash: built.bundle.binding_hash,
            stablecoin: None,
            fee: built.bundle.fee,
        };
        let envelope = pallet_shielded_pool::family::build_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
            built.bundle.nullifiers.clone(),
            args.encode(),
        );
        let call = pallet_kernel::Call::<Runtime>::submit_action {
            envelope: envelope.clone(),
        };

        assert!(
            pallet_kernel::Pallet::<Runtime>::validate_unsigned(TransactionSource::External, &call)
                .is_ok()
        );
        assert_ok!(Kernel::submit_action(RuntimeOrigin::none(), envelope));

        let replay_validity =
            pallet_kernel::Pallet::<Runtime>::validate_unsigned(TransactionSource::External, &call);
        assert!(
            matches!(
                replay_validity,
                Err(TransactionValidityError::Invalid(
                    InvalidTransaction::Stale
                ))
            ),
            "replayed spent nullifier should be classified as stale, not bad proof: {replay_validity:?}"
        );
    });
}

#[test]
fn kernel_wallet_preserves_shielded_custom_validity_codes() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(1_000);

        let anchor = ShieldedPool::merkle_tree().root();
        pallet_shielded_pool::pallet::MerkleRoots::<Runtime>::insert(
            anchor,
            System::block_number(),
        );
        sync_kernel_roots();

        let args = pallet_shielded_pool::family::ShieldedTransferInlineArgs {
            proof: vec![1u8; 32],
            commitments: vec![[2u8; 48]],
            ciphertexts: Vec::new(),
            anchor,
            balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
            binding_hash: [0u8; 64],
            stablecoin: None,
            fee: 0,
        };
        let envelope = pallet_shielded_pool::family::build_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
            vec![[1u8; 48]],
            args.encode(),
        );
        let call = pallet_kernel::Call::<Runtime>::submit_action { envelope };

        let validity =
            pallet_kernel::Pallet::<Runtime>::validate_unsigned(TransactionSource::External, &call);
        assert!(
            matches!(
                validity,
                Err(TransactionValidityError::Invalid(
                    InvalidTransaction::Custom(2)
                ))
            ),
            "kernel wrapper should preserve shielded custom validity codes: {validity:?}"
        );
    });
}

#[test]
fn kernel_wallet_rejects_non_native_transfer_payload() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(1_000);

        let dir = tempdir().expect("tempdir");
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "sender-pass").expect("sender wallet");
        let recipient =
            WalletStore::create_full(&recipient_path, "recipient-pass").expect("recipient wallet");

        seed_wallet_note(&sender, 250_000_000);

        let mut built = build_transaction(
            &sender,
            &[Recipient {
                address: recipient.primary_address().expect("recipient address"),
                value: 100_000_000,
                asset_id: NATIVE_ASSET_ID,
                memo: MemoPlaintext::new(b"native tx leaf kernel regression".to_vec()),
            }],
            0,
        )
        .expect("wallet build_transaction");
        built.bundle.proof_bytes = vec![0xde, 0xad, 0xbe, 0xef];

        let ciphertexts = built
            .bundle
            .decode_notes()
            .expect("decode built notes")
            .into_iter()
            .map(|note| {
                let bytes = note.to_pallet_bytes().expect("note to pallet bytes");
                pallet_shielded_pool::types::EncryptedNote::decode(&mut bytes.as_slice())
                    .expect("decode note")
            })
            .collect::<Vec<_>>();

        let args = pallet_shielded_pool::family::ShieldedTransferInlineArgs {
            proof: built.bundle.proof_bytes.clone(),
            commitments: built.bundle.commitments.clone(),
            ciphertexts,
            anchor: built.bundle.anchor,
            balance_slot_asset_ids: built.bundle.balance_slot_asset_ids,
            binding_hash: built.bundle.binding_hash,
            stablecoin: None,
            fee: built.bundle.fee,
        };
        let envelope = pallet_shielded_pool::family::build_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
            built.bundle.nullifiers.clone(),
            args.encode(),
        );

        let call = pallet_kernel::Call::<Runtime>::submit_action {
            envelope: envelope.clone(),
        };
        let validity =
            pallet_kernel::Pallet::<Runtime>::validate_unsigned(TransactionSource::External, &call);
        assert!(
            validity.is_err(),
            "runtime must reject non-native transfer payloads"
        );
    });
}

#[test]
fn kernel_enable_aggregation_mode_revalidation_stays_valid_in_block() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(1_000);

        let envelope = pallet_shielded_pool::family::build_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            pallet_shielded_pool::family::ACTION_ENABLE_AGGREGATION_MODE,
            Vec::new(),
            pallet_shielded_pool::family::EnableAggregationModeArgs.encode(),
        );
        let call = pallet_kernel::Call::<Runtime>::submit_action {
            envelope: envelope.clone(),
        };

        let validity_before =
            pallet_kernel::Pallet::<Runtime>::validate_unsigned(TransactionSource::InBlock, &call);
        assert!(
            validity_before.is_ok(),
            "aggregation-mode control action should validate before execution: {validity_before:?}"
        );

        assert_ok!(Kernel::submit_action(RuntimeOrigin::none(), envelope.clone()));

        let validity_after =
            pallet_kernel::Pallet::<Runtime>::validate_unsigned(TransactionSource::InBlock, &call);
        assert!(
            validity_after.is_ok(),
            "aggregation-mode control action should remain valid on in-block revalidation: {validity_after:?}"
        );
    });
}

#[test]
fn kernel_wallet_unsigned_sidecar_transfer_survives_kernel_validate_and_apply() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(1_000);

        let dir = tempdir().expect("tempdir");
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "sender-pass").expect("sender wallet");
        let recipient =
            WalletStore::create_full(&recipient_path, "recipient-pass").expect("recipient wallet");

        seed_wallet_note(&sender, 250_000_000);

        let built = build_transaction(
            &sender,
            &[Recipient {
                address: recipient.primary_address().expect("recipient address"),
                value: 100_000_000,
                asset_id: NATIVE_ASSET_ID,
                memo: MemoPlaintext::new(b"kernel sidecar envelope regression".to_vec()),
            }],
            0,
        )
        .expect("wallet build_transaction");

        let args = wallet_sidecar_args(&built.bundle);
        let decoded = decode_native_tx_leaf_artifact_bytes(&built.bundle.proof_bytes)
            .expect("decode tx leaf");
        assert_eq!(decoded.tx.nullifiers, built.bundle.nullifiers);
        assert_eq!(decoded.tx.commitments, built.bundle.commitments);
        assert_eq!(decoded.tx.ciphertext_hashes, args.ciphertext_hashes);

        let envelope = pallet_shielded_pool::family::build_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_SIDECAR,
            built.bundle.nullifiers.clone(),
            args.encode(),
        );

        let call = pallet_kernel::Call::<Runtime>::submit_action {
            envelope: envelope.clone(),
        };
        let validity =
            pallet_kernel::Pallet::<Runtime>::validate_unsigned(TransactionSource::External, &call);
        assert!(
            validity.is_ok(),
            "wallet-built sidecar kernel action should validate: {validity:?}"
        );

        let prior_commitment_index = ShieldedPool::commitment_index();
        assert_ok!(Kernel::submit_action(RuntimeOrigin::none(), envelope));

        assert_eq!(
            ShieldedPool::commitment_index(),
            prior_commitment_index + built.bundle.commitments.len() as u64
        );
        for nullifier in &built.bundle.nullifiers {
            assert!(
                pallet_shielded_pool::pallet::Nullifiers::<Runtime>::contains_key(nullifier),
                "nullifier should be consumed after sidecar apply"
            );
        }
    });
}

#[test]
fn kernel_wallet_unsigned_transfer_spends_coinbase_note() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(1_000);

        let dir = tempdir().expect("tempdir");
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "sender-pass").expect("sender wallet");
        let recipient =
            WalletStore::create_full(&recipient_path, "recipient-pass").expect("recipient wallet");

        seed_wallet_note_with_plaintext(&sender, NotePlaintext::coinbase(250_000_000, &[7u8; 32]));

        let built = build_transaction(
            &sender,
            &[Recipient {
                address: recipient.primary_address().expect("recipient address"),
                value: 100_000_000,
                asset_id: NATIVE_ASSET_ID,
                memo: MemoPlaintext::new(b"coinbase spend regression".to_vec()),
            }],
            0,
        )
        .expect("wallet build_transaction");

        let ciphertexts = built
            .bundle
            .decode_notes()
            .expect("decode built notes")
            .into_iter()
            .map(|note| {
                let bytes = note.to_pallet_bytes().expect("note to pallet bytes");
                pallet_shielded_pool::types::EncryptedNote::decode(&mut bytes.as_slice())
                    .expect("decode note")
            })
            .collect::<Vec<_>>();

        let args = pallet_shielded_pool::family::ShieldedTransferInlineArgs {
            proof: built.bundle.proof_bytes.clone(),
            commitments: built.bundle.commitments.clone(),
            ciphertexts,
            anchor: built.bundle.anchor,
            balance_slot_asset_ids: built.bundle.balance_slot_asset_ids,
            binding_hash: built.bundle.binding_hash,
            stablecoin: None,
            fee: built.bundle.fee,
        };
        let envelope = pallet_shielded_pool::family::build_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
            built.bundle.nullifiers.clone(),
            args.encode(),
        );

        let call = pallet_kernel::Call::<Runtime>::submit_action {
            envelope: envelope.clone(),
        };
        let validity =
            pallet_kernel::Pallet::<Runtime>::validate_unsigned(TransactionSource::External, &call);
        assert!(
            validity.is_ok(),
            "wallet-built kernel action should validate for coinbase notes"
        );

        assert_ok!(Kernel::submit_action(RuntimeOrigin::none(), envelope));
    });
}

#[test]
fn kernel_wallet_unsigned_transfer_with_nonzero_fee_survives_kernel_validate_and_apply() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        System::set_block_number(1);
        Timestamp::set_timestamp(1_000);

        let dir = tempdir().expect("tempdir");
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "sender-pass").expect("sender wallet");
        let recipient =
            WalletStore::create_full(&recipient_path, "recipient-pass").expect("recipient wallet");

        seed_wallet_note(&sender, 500_000_000);

        let fee = 10_000_000;
        let built = build_transaction(
            &sender,
            &[Recipient {
                address: recipient.primary_address().expect("recipient address"),
                value: 100_000_000,
                asset_id: NATIVE_ASSET_ID,
                memo: MemoPlaintext::new(b"nonzero fee regression".to_vec()),
            }],
            fee,
        )
        .expect("wallet build_transaction");

        let ciphertexts = built
            .bundle
            .decode_notes()
            .expect("decode built notes")
            .into_iter()
            .map(|note| {
                let bytes = note.to_pallet_bytes().expect("note to pallet bytes");
                pallet_shielded_pool::types::EncryptedNote::decode(&mut bytes.as_slice())
                    .expect("decode note")
            })
            .collect::<Vec<_>>();

        let args = pallet_shielded_pool::family::ShieldedTransferInlineArgs {
            proof: built.bundle.proof_bytes.clone(),
            commitments: built.bundle.commitments.clone(),
            ciphertexts,
            anchor: built.bundle.anchor,
            balance_slot_asset_ids: built.bundle.balance_slot_asset_ids,
            binding_hash: built.bundle.binding_hash,
            stablecoin: None,
            fee: built.bundle.fee,
        };
        let envelope = pallet_shielded_pool::family::build_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
            built.bundle.nullifiers.clone(),
            args.encode(),
        );

        let call = pallet_kernel::Call::<Runtime>::submit_action {
            envelope: envelope.clone(),
        };
        let validity =
            pallet_kernel::Pallet::<Runtime>::validate_unsigned(TransactionSource::External, &call);
        assert!(
            validity.is_ok(),
            "wallet-built kernel action should validate with nonzero fee"
        );

        assert_ok!(Kernel::submit_action(RuntimeOrigin::none(), envelope));
    });
}
