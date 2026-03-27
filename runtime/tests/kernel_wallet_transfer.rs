use codec::{Decode, Encode};
use frame_support::assert_ok;
use frame_support::sp_runtime::BuildStorage;
use rand::{rngs::StdRng, SeedableRng};
use runtime::{Kernel, Runtime, RuntimeOrigin, ShieldedPool, System, Timestamp};
use sp_io::TestExternalities;
use sp_runtime::traits::ValidateUnsigned;
use sp_runtime::transaction_validity::TransactionSource;
use std::sync::{Mutex, OnceLock};
use tempfile::tempdir;
use transaction_circuit::constants::NATIVE_ASSET_ID;
use transaction_circuit::hashing_pq::felts_to_bytes48;
use wallet::{
    build_transaction, MemoPlaintext, NoteCiphertext, NotePlaintext, Recipient, WalletStore,
};

fn wallet_artifact_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

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
            "wallet-built kernel action should validate"
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
fn kernel_wallet_native_tx_leaf_payload_survives_kernel_validate_and_apply() {
    let _env_guard = wallet_artifact_env_lock();
    let previous_mode = std::env::var("HEGEMON_WALLET_TX_ARTIFACT_MODE").ok();
    unsafe {
        std::env::set_var("HEGEMON_WALLET_TX_ARTIFACT_MODE", "native_tx_leaf");
    }

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
                memo: MemoPlaintext::new(b"native tx leaf kernel regression".to_vec()),
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
            "wallet-built native tx-leaf kernel action should validate"
        );

        let prior_commitment_index = ShieldedPool::commitment_index();
        assert_ok!(Kernel::submit_action(RuntimeOrigin::none(), envelope));
        assert_eq!(
            ShieldedPool::commitment_index(),
            prior_commitment_index + built.bundle.commitments.len() as u64
        );
    });

    match previous_mode {
        Some(value) => unsafe {
            std::env::set_var("HEGEMON_WALLET_TX_ARTIFACT_MODE", value);
        },
        None => unsafe {
            std::env::remove_var("HEGEMON_WALLET_TX_ARTIFACT_MODE");
        },
    }
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
