use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use consensus::reward::INITIAL_SUBSIDY;
use network::GossipRouter;
use node::{api, config::NodeConfig, NodeHandle, NodeService};
use rand::{rngs::StdRng, SeedableRng};
use tempfile::tempdir;
use tokio::task::spawn_blocking;
use tokio::time::{sleep, timeout};
use transaction_circuit::constants::NATIVE_ASSET_ID;
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{InputNoteWitness, NoteData, OutputNoteWitness};
use transaction_circuit::proof::prove;
use transaction_circuit::witness::TransactionWitness;
use url::Url;
use wallet::address::ShieldedAddress;
use wallet::notes::{MemoPlaintext, NoteCiphertext, NotePlaintext};
use wallet::rpc::{TransactionBundle, WalletRpcClient};
use wallet::tx_builder::{build_transaction, Recipient};
use wallet::TransferRecipient;
use wallet::WalletStore;
use wallet::WalletSyncEngine;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn node_wallet_daemons_execute_transfer() {
    let router = GossipRouter::new(1024);
    let dir_a = tempdir().expect("node a dir");
    let dir_b = tempdir().expect("node b dir");

    let mut config_a = NodeConfig::with_db_path(dir_a.path().join("a.db"));
    config_a.api_addr = socket_addr(free_port());
    config_a.api_token = "itest-token".into();
    config_a.note_tree_depth = 12;
    config_a.pow_bits = 0x3f00ffff;
    config_a.miner_workers = 0;
    config_a.miner_seed = [1u8; 32];

    let mut config_b = NodeConfig::with_db_path(dir_b.path().join("b.db"));
    config_b.api_addr = socket_addr(free_port());
    config_b.api_token = "itest-token".into();
    config_b.note_tree_depth = 12;
    config_b.pow_bits = 0x3f00ffff;
    config_b.miner_workers = 0;
    config_b.miner_seed = [1u8; 32];

    let handle_a = NodeService::start(config_a.clone(), router.clone()).expect("start node a");
    let handle_b = NodeService::start(config_b.clone(), router).expect("start node b");

    let api_task_a = tokio::spawn(api::serve(handle_a.service.clone()));
    let api_task_b = tokio::spawn(api::serve(handle_b.service.clone()));

    let base_url_a = Url::parse(&format!("http://{}", handle_a.service.api_addr())).unwrap();
    let base_url_b = Url::parse(&format!("http://{}", handle_b.service.api_addr())).unwrap();

    let wallet_dir = tempdir().expect("wallet dir");
    let alice_path = wallet_dir.path().join("alice.wallet");
    let bob_path = wallet_dir.path().join("bob.wallet");
    let alice_store = Arc::new(WalletStore::create_full(&alice_path, "pass").expect("alice store"));
    let bob_store = Arc::new(WalletStore::create_full(&bob_path, "word").expect("bob store"));
    let alice_address_primary = alice_store.next_address().expect("alice addr");
    let alice_change_address = alice_store.next_address().expect("alice change addr");

    let alice_client = new_wallet_client(base_url_a.clone(), "itest-token").await;
    let bob_client = new_wallet_client(base_url_b.clone(), "itest-token").await;

    post_funding_transaction(&handle_a, &alice_address_primary, &alice_change_address).await;
    handle_a
        .service
        .seal_pending_block()
        .await
        .expect("seal funding block")
        .expect("funding block missing");

    wait_for_height(&handle_a, 1).await;
    wait_for_height(&handle_b, 1).await;

    let supply = handle_a.service.latest_meta().supply_digest;
    assert!(supply >= INITIAL_SUBSIDY as u128);

    sync_wallet(alice_store.clone(), alice_client.clone()).await;
    wait_for_balance(alice_store.as_ref(), 90).await;

    let alice_before = current_balance(alice_store.as_ref());
    assert!(alice_before >= 90);

    let bob_recipient = bob_store.next_address().expect("bob receiving addr");
    let transfer_recipient = Recipient {
        address: bob_recipient.clone(),
        value: 25,
        asset_id: NATIVE_ASSET_ID,
        memo: MemoPlaintext::new(b"integration transfer".to_vec()),
    };

    sync_wallet(alice_store.clone(), alice_client.clone()).await;

    let built =
        build_transaction(alice_store.as_ref(), &[transfer_recipient], 1).expect("build tx");
    alice_store
        .mark_notes_pending(&built.spent_note_indexes, true)
        .expect("mark pending");
    let tx_id = submit_transaction(alice_client.clone(), built.bundle.clone())
        .await
        .expect("submit bundle");
    let bob_address_encoded = bob_recipient
        .encode()
        .expect("encode recipient address for metadata");
    alice_store
        .record_pending_submission(
            tx_id,
            built.nullifiers.clone(),
            built.spent_note_indexes.clone(),
            vec![TransferRecipient {
                address: bob_address_encoded,
                value: 25,
                asset_id: NATIVE_ASSET_ID,
                memo: Some("integration transfer".into()),
            }],
            1,
        )
        .expect("record pending");

    handle_a
        .service
        .seal_pending_block()
        .await
        .expect("seal transfer block")
        .expect("transfer block missing");

    wait_for_height(&handle_a, 2).await;
    wait_for_height(&handle_b, 2).await;
    sync_wallet(alice_store.clone(), alice_client.clone()).await;
    sync_wallet(bob_store.clone(), bob_client.clone()).await;
    wait_for_balance(bob_store.as_ref(), 25).await;

    let alice_after = current_balance(alice_store.as_ref());
    let bob_after = current_balance(bob_store.as_ref());
    assert_ne!(alice_after, alice_before);
    assert!(bob_after >= 25);

    handle_a.shutdown().await;
    handle_b.shutdown().await;
    api_task_a.abort();
    api_task_b.abort();
    drop_rpc_client(alice_client).await;
    drop_rpc_client(bob_client).await;
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind temp port")
        .local_addr()
        .unwrap()
        .port()
}

fn socket_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

async fn new_wallet_client(base: Url, token: &str) -> WalletRpcClient {
    let token = token.to_owned();
    spawn_blocking(move || WalletRpcClient::new(base, token))
        .await
        .expect("spawn wallet client")
        .expect("wallet client")
}

async fn drop_rpc_client(client: WalletRpcClient) {
    let _ = spawn_blocking(move || drop(client)).await;
}

async fn sync_wallet(store: Arc<WalletStore>, client: WalletRpcClient) {
    spawn_blocking(move || {
        let engine = WalletSyncEngine::new(&client, store.as_ref());
        engine.sync_once()
    })
    .await
    .expect("spawn wallet sync")
    .expect("wallet sync");
}

async fn submit_transaction(
    client: WalletRpcClient,
    bundle: TransactionBundle,
) -> Result<[u8; 32], wallet::error::WalletError> {
    spawn_blocking(move || client.submit_transaction(&bundle))
        .await
        .expect("spawn submit transaction")
}

async fn wait_for_height(handle: &NodeHandle, target: u64) {
    let fut = async {
        loop {
            if handle.service.latest_meta().height >= target {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
    };
    timeout(Duration::from_secs(45), fut)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "height wait timed out at target {target}, current {}",
                handle.service.latest_meta().height
            )
        });
}

async fn post_funding_transaction(
    handle: &NodeHandle,
    alice: &ShieldedAddress,
    change: &ShieldedAddress,
) {
    let root = handle.service.merkle_root();
    let (proving_key, _) = generate_keys();
    let input = InputNoteWitness {
        note: NoteData {
            value: 120,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [9u8; 32],
            rho: [10u8; 32],
            r: [11u8; 32],
        },
        position: 1,
        rho_seed: [12u8; 32],
    };
    let mut rng = StdRng::seed_from_u64(42);
    let alice_note = NotePlaintext::random(90, NATIVE_ASSET_ID, MemoPlaintext::default(), &mut rng);
    let change_note =
        NotePlaintext::random(29, NATIVE_ASSET_ID, MemoPlaintext::default(), &mut rng);
    let alice_ct = NoteCiphertext::encrypt(alice, &alice_note, &mut rng).expect("alice ciphertext");
    let change_ct =
        NoteCiphertext::encrypt(change, &change_note, &mut rng).expect("change ciphertext");
    let outputs = vec![
        OutputNoteWitness {
            note: alice_note.to_note_data(alice.pk_recipient),
        },
        OutputNoteWitness {
            note: change_note.to_note_data(change.pk_recipient),
        },
    ];
    let witness = TransactionWitness {
        inputs: vec![input],
        outputs,
        sk_spend: [33u8; 32],
        merkle_root: root,
        fee: 1,
        version: TransactionWitness::default_version_binding(),
    };
    let proof = prove(&witness, &proving_key).expect("prove funding");
    let bundle = TransactionBundle::from_notes(proof, &[alice_ct, change_ct]).expect("bundle");
    handle
        .service
        .submit_transaction(bundle)
        .await
        .expect("submit funding");
}

async fn wait_for_balance(store: &WalletStore, min_balance: u64) {
    let fut = async {
        loop {
            if current_balance(store) >= min_balance {
                break;
            }
            sleep(Duration::from_millis(200)).await;
        }
    };
    timeout(Duration::from_secs(30), fut)
        .await
        .expect("balance wait timed out");
}

fn current_balance(store: &WalletStore) -> u64 {
    store
        .balances()
        .expect("balances")
        .get(&NATIVE_ASSET_ID)
        .copied()
        .unwrap_or(0)
}
