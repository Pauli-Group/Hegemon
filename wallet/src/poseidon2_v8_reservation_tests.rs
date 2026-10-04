// Included in the canonical mirror test module to reuse exact block/ciphertext
// fixtures. These bounded tests exercise wallet ownership, never a prover.

#[test]
fn v8_reservation_concurrent_builders_select_disjoint_durable_inputs() {
    use std::sync::Barrier;
    let directory = tempdir().unwrap();
    let path = directory.path().join("wallet.dat");
    let root = RootSecret::from_bytes([0x51; 32]);
    let store = WalletStore::create_from_root(&path, PASSPHRASE, root.clone()).unwrap();
    seed_two_owned_coinbases(&store, &root);
    for (height, hash, parent) in [(3, BLOCK_3, BLOCK_2), (4, [0x14; 32], BLOCK_3)] {
        store
            .apply_poseidon2_v8_canonical_block(&canonical_block(
                height,
                hash,
                parent,
                vec![coinbase_action(&coinbase_args(
                    &root,
                    17 + height,
                    300 + height,
                ))],
            ))
            .unwrap();
    }
    let barrier = Barrier::new(2);
    let selected = std::thread::scope(|scope| {
        let handles = [501, 502].map(|seed| {
            let store = &store;
            let barrier = &barrier;
            let path = &path;
            scope.spawn(move || {
                barrier.wait();
                let spend = build_poseidon2_v8_wallet_self_spend(
                    store,
                    [4, 7],
                    &mut StdRng::seed_from_u64(seed),
                )
                .unwrap();
                let inputs = spend.material.statement.nullifiers;
                let snapshot = WalletStore::open_read_only(path, PASSPHRASE).unwrap();
                assert!(snapshot
                    .poseidon2_v8_reservations()
                    .unwrap()
                    .iter()
                    .any(|entry| entry.reservation_id == spend.reservation.id()));
                barrier.wait();
                inputs
            })
        });
        handles.map(|handle| handle.join().unwrap())
    });
    assert!(selected[0].iter().all(|input| !selected[1].contains(input)));
    assert!(store.poseidon2_v8_reservations().unwrap().is_empty());
}

#[test]
fn v8_reservation_proving_restart_recovers_only_never_submitted_inputs() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("wallet.dat");
    let root = RootSecret::from_bytes([0x51; 32]);
    let store = WalletStore::create_from_root(&path, PASSPHRASE, root.clone()).unwrap();
    seed_two_owned_coinbases(&store, &root);
    let reservation = store.reserve_poseidon2_v8_spend().unwrap();
    assert!(matches!(
        store.reserve_poseidon2_v8_spend(),
        Err(WalletError::InsufficientFunds { available: 0, .. })
    ));
    std::mem::forget(reservation); // Model process exit without a guard drop.
    drop(store);
    let reopened = WalletStore::open(&path, PASSPHRASE).unwrap();
    assert!(reopened.poseidon2_v8_reservations().unwrap().is_empty());
    let reservation = reopened.reserve_poseidon2_v8_spend().unwrap();
    reservation.begin_submission().unwrap();
    let id = reservation.id();
    drop(reservation); // Transport failure/cancellation cannot release it.
    drop(reopened);
    let uncertain = WalletStore::open(&path, PASSPHRASE).unwrap();
    let entries = uncertain.poseidon2_v8_reservations().unwrap();
    assert_eq!(entries[0].reservation_id, id);
    assert_eq!(
        entries[0].status,
        crate::store::Poseidon2V8ReservationStatus::SubmissionUncertain
    );
    assert!(entries[0].inputs_reserved);
    assert!(uncertain.reserve_poseidon2_v8_spend().is_err());
}

#[test]
fn v8_reservation_success_confirmation_and_reorg_remain_locked_after_restart() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("wallet.dat");
    let root = RootSecret::from_bytes([0x51; 32]);
    let store = WalletStore::create_from_root(&path, PASSPHRASE, root.clone()).unwrap();
    seed_two_owned_coinbases(&store, &root);
    let spend =
        build_poseidon2_v8_wallet_self_spend(&store, [4, 7], &mut StdRng::seed_from_u64(503))
            .unwrap();
    let transfer = transfer_action(&spend.material, WalletProofRoute::Smza);
    spend.reservation.begin_submission().unwrap();
    let tx_id = hegemon_hash384::ActionId48::new([0x39; 48]);
    spend.reservation.mark_submitted(tx_id).unwrap();
    drop(spend);
    store
        .apply_poseidon2_v8_canonical_block_for_retained_test(
            &canonical_block(3, BLOCK_3, BLOCK_2, vec![transfer]),
            retained_test_context(WalletProofRoute::Smza),
        )
        .unwrap();
    assert!(store.poseidon2_v8_reservations().unwrap()[0].inputs_consumed);
    drop(store);
    let reopened = WalletStore::open(&path, PASSPHRASE).unwrap();
    assert_eq!(
        reopened.poseidon2_v8_reservations().unwrap()[0].status,
        crate::store::Poseidon2V8ReservationStatus::Submitted(tx_id)
    );
    reopened.rollback_poseidon2_v8_to(2, BLOCK_2).unwrap();
    assert!(!reopened.poseidon2_v8_reservations().unwrap()[0].inputs_consumed);
    assert!(reopened.reserve_poseidon2_v8_spend().is_err());
    // Detaching the blocks that created the inputs must also retain the hold.
    reopened.rollback_poseidon2_v8_to(0, GENESIS).unwrap();
    drop(reopened);
    let restarted = WalletStore::open(&path, PASSPHRASE).unwrap();
    seed_two_owned_coinbases(&restarted, &root);
    assert!(restarted.reserve_poseidon2_v8_spend().is_err());
}

#[test]
fn v8_reservation_explicit_abandonment_reactivates_on_parent_reorg() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("wallet.dat");
    let root = RootSecret::from_bytes([0x51; 32]);
    let store = WalletStore::create_from_root(&path, PASSPHRASE, root.clone()).unwrap();
    let parent = seed_two_owned_coinbases(&store, &root);
    let reservation = store.reserve_poseidon2_v8_spend().unwrap();
    reservation.begin_submission().unwrap();
    let id = reservation.id();
    drop(reservation);
    assert!(store.abandon_poseidon2_v8_reservation(id, parent).is_err());
    store
        .apply_poseidon2_v8_canonical_block(&canonical_block(3, BLOCK_3, BLOCK_2, vec![]))
        .unwrap();
    let tip = store.poseidon2_v8_tip().unwrap();
    assert!(store.abandon_poseidon2_v8_reservation(id, parent).is_err());
    store.abandon_poseidon2_v8_reservation(id, tip).unwrap();
    assert!(!store.poseidon2_v8_reservations().unwrap()[0].inputs_reserved);
    let replacement = store.reserve_poseidon2_v8_spend().unwrap();
    assert!(store
        .poseidon2_v8_reservations()
        .unwrap()
        .iter()
        .any(|entry| entry.reservation_id == replacement.id()));
    drop(replacement);
    drop(store);
    let reopened = WalletStore::open(&path, PASSPHRASE).unwrap();
    reopened.rollback_poseidon2_v8_to(2, BLOCK_2).unwrap();
    assert!(reopened.poseidon2_v8_reservations().unwrap()[0].inputs_reserved);
    assert!(reopened.reserve_poseidon2_v8_spend().is_err());
}

#[test]
fn v8_reservation_preflight_error_and_build_panic_release_inputs() {
    let directory = tempdir().unwrap();
    let root = RootSecret::from_bytes([0x51; 32]);
    let store = WalletStore::create_from_root(
        directory.path().join("wallet.dat"),
        PASSPHRASE,
        root.clone(),
    )
    .unwrap();
    seed_two_owned_coinbases(&store, &root);
    let reservation = store.reserve_poseidon2_v8_spend().unwrap();
    store
        .apply_poseidon2_v8_canonical_block(&canonical_block(3, BLOCK_3, BLOCK_2, vec![]))
        .unwrap();
    assert!(reservation.begin_submission().is_err());
    drop(reservation);
    assert!(store.poseidon2_v8_reservations().unwrap().is_empty());
    struct PanicRng;
    impl rand::RngCore for PanicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("injected builder RNG failure")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("injected builder RNG failure")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("injected builder RNG failure")
        }
        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(bytes);
            Ok(())
        }
    }
    impl rand::CryptoRng for PanicRng {}
    assert!(std::panic::catch_unwind(|| {
        let _ = build_poseidon2_v8_wallet_self_spend(&store, [4, 7], &mut PanicRng);
    })
    .is_err());
    assert!(store.poseidon2_v8_reservations().unwrap().is_empty());
    assert!(store.reserve_poseidon2_v8_spend().is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v8_reservation_cancellation_before_and_after_submission_marker() {
    use std::sync::Arc;
    let directory = tempdir().unwrap();
    let root = RootSecret::from_bytes([0x51; 32]);
    let store = Arc::new(
        WalletStore::create_from_root(
            directory.path().join("wallet.dat"),
            PASSPHRASE,
            root.clone(),
        )
        .unwrap(),
    );
    seed_two_owned_coinbases(&store, &root);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    let task_store = Arc::clone(&store);
    let task = tokio::spawn(async move {
        let _reservation = task_store.reserve_poseidon2_v8_spend().unwrap();
        tokio::task::spawn_blocking(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            finished_tx.send(()).unwrap();
        })
        .await
        .unwrap();
    });
    entered_rx.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    // The detached blocking worker still runs but cannot submit the proof.
    assert!(store.poseidon2_v8_reservations().unwrap().is_empty());
    let next = store.reserve_poseidon2_v8_spend().unwrap();
    drop(next);
    release_tx.send(()).unwrap();
    finished_rx.await.unwrap();

    let (marked_tx, marked_rx) = tokio::sync::oneshot::channel();
    let task_store = Arc::clone(&store);
    let task = tokio::spawn(async move {
        let reservation = task_store.reserve_poseidon2_v8_spend().unwrap();
        reservation.begin_submission().unwrap();
        marked_tx.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    marked_rx.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        store.poseidon2_v8_reservations().unwrap()[0].status,
        crate::store::Poseidon2V8ReservationStatus::SubmissionUncertain
    );
    assert!(store.reserve_poseidon2_v8_spend().is_err());
}

#[test]
fn v8_reservation_failed_disk_commit_cannot_allocate_or_start_submission() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("wallet.dat");
    let backup = directory.path().join("wallet.retained");
    let root = RootSecret::from_bytes([0x51; 32]);
    let store = WalletStore::create_from_root(&path, PASSPHRASE, root.clone()).unwrap();
    seed_two_owned_coinbases(&store, &root);
    std::fs::rename(&path, &backup).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(store.reserve_poseidon2_v8_spend().is_err());
    assert!(store.poseidon2_v8_reservations().unwrap().is_empty());
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    let reservation = store.reserve_poseidon2_v8_spend().unwrap();
    std::fs::rename(&path, &backup).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(reservation.begin_submission().is_err());
    assert_eq!(
        store.poseidon2_v8_reservations().unwrap()[0].status,
        crate::store::Poseidon2V8ReservationStatus::Proving
    );
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    drop(reservation);
    assert!(store.poseidon2_v8_reservations().unwrap().is_empty());
}
