use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use network::GossipRouter;
use node::api;
use node::config::NodeConfig;
use node::{NodeHandle, NodeService};
use serde_json::Value;
use tempfile::tempdir;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, connect_async};
use transaction_circuit::constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing::Felt;
use transaction_circuit::proof::TransactionProof;
use transaction_circuit::public_inputs::{BalanceSlot, TransactionPublicInputs};
use wallet::TransactionBundle;

const EASY_POW_BITS: u32 = 0x3f00ffff;

struct ApiHarness {
    handle: NodeHandle,
    server: JoinHandle<()>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    base_url: String,
    token: String,
}

impl ApiHarness {
    async fn start(token: &str) -> Self {
        let dir = tempdir().unwrap();
        let mut config = NodeConfig::with_db_path(dir.path().join("api-auth.db"));
        config.api_addr = "127.0.0.1:0".parse().unwrap();
        config.api_token = token.to_string();
        config.note_tree_depth = 8;
        config.pow_bits = EASY_POW_BITS;
        config.miner_workers = 0;
        config.min_tx_fee_per_weight = 0;

        let router = GossipRouter::new(8);
        let handle = NodeService::start(config, router).expect("start node");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let app = api::node_router(handle.service.clone(), None);
        let listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind api listener");
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("api server");
        });

        ApiHarness {
            handle,
            server,
            shutdown_tx: Some(shutdown_tx),
            base_url: format!("http://{}", addr),
            token: token.to_string(),
        }
    }

    async fn shutdown(self) {
        // Stop the API server first so its router drops the cloned NodeService
        // before we attempt to unwrap the Arc during shutdown.
        let ApiHarness {
            handle,
            server,
            shutdown_tx,
            ..
        } = self;

        if let Some(tx) = shutdown_tx {
            let _ = tx.send(());
        }

        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;

        // Allow any in-flight handlers to drop their Arc<NodeService> clones.
        for _ in 0..10 {
            if Arc::strong_count(&handle.service) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        handle.shutdown().await.expect("shutdown api harness node");
    }
}

fn dummy_bundle() -> TransactionBundle {
    let nullifier = Felt::new(0);
    let commitment = Felt::new(0);
    let slot = BalanceSlot {
        asset_id: 0,
        delta: 0,
    };

    let public_inputs = TransactionPublicInputs {
        merkle_root: Felt::new(0),
        nullifiers: vec![nullifier; MAX_INPUTS],
        commitments: vec![commitment; MAX_OUTPUTS],
        balance_slots: vec![slot.clone(); BALANCE_SLOTS],
        native_fee: 0,
        balance_tag: Felt::new(0),
        circuit_version: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
        crypto_suite: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
    };

    let proof = TransactionProof {
        public_inputs,
        nullifiers: vec![nullifier; MAX_INPUTS],
        commitments: vec![commitment; MAX_OUTPUTS],
        balance_slots: vec![slot; BALANCE_SLOTS],
    };

    TransactionBundle {
        proof,
        ciphertexts: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthorized_requests_are_rejected() {
    let harness = ApiHarness::start("super-secret-token").await;
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();

    let latest = client
        .get(format!("{}/blocks/latest", harness.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(latest.status(), reqwest::StatusCode::UNAUTHORIZED);

    let metrics = client
        .get(format!("{}/metrics", harness.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), reqwest::StatusCode::UNAUTHORIZED);

    let tx = client
        .post(format!("{}/transactions", harness.base_url))
        .json(&dummy_bundle())
        .send()
        .await
        .unwrap();
    assert_eq!(tx.status(), reqwest::StatusCode::UNAUTHORIZED);

    let url = format!("ws://{}/ws", harness.base_url.trim_start_matches("http://"));
    let ws_result = connect_without_token(&url).await;
    assert!(matches!(ws_result, Err(WsError::Http(_))));

    drop(client);
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorized_endpoints_return_data() {
    let harness = ApiHarness::start("super-secret-token").await;
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();

    let latest = client
        .get(format!("{}/blocks/latest", harness.base_url))
        .header("x-auth-token", &harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(latest.status(), reqwest::StatusCode::OK);
    let block_json: Value = latest.json().await.unwrap();
    assert!(block_json.get("height").is_some());
    assert!(block_json.get("hash").is_some());
    assert!(block_json.get("state_root").is_some());
    assert!(block_json.get("nullifier_root").is_some());
    assert!(block_json.get("supply_digest").is_some());

    let metrics = client
        .get(format!("{}/metrics", harness.base_url))
        .header("x-auth-token", &harness.token)
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), reqwest::StatusCode::OK);
    let metrics_json: Value = metrics.json().await.unwrap();
    assert!(metrics_json.get("hash_rate").is_some());
    assert!(metrics_json.get("best_height").is_some());

    let tx = client
        .post(format!("{}/transactions", harness.base_url))
        .header("x-auth-token", &harness.token)
        .json(&dummy_bundle())
        .send()
        .await
        .unwrap();
    assert_ne!(tx.status(), reqwest::StatusCode::UNAUTHORIZED);

    drop(client);
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_requires_token_and_streams_events() {
    let harness = ApiHarness::start("super-secret-token").await;
    let ws_url = format!("ws://{}/ws", harness.base_url.trim_start_matches("http://"));

    let ws_result = connect_without_token(&ws_url).await;
    assert!(matches!(ws_result, Err(WsError::Http(_))));

    let mut ws_stream = connect_with_token(&ws_url, &harness.token).await;

    let event = timeout(Duration::from_secs(10), ws_stream.next())
        .await
        .expect("telemetry event")
        .expect("websocket message")
        .expect("websocket text");

    let payload = match event {
        tokio_tungstenite::tungstenite::Message::Text(body) => body,
        other => panic!("expected text message, got {other:?}"),
    };
    let json: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(json.get("type"), Some(&Value::String("telemetry".into())));
    assert!(json.get("best_height").is_some());

    ws_stream.close(None).await.unwrap();
    harness.shutdown().await;
}

async fn connect_without_token(url: &str) -> Result<(), WsError> {
    let request = url.into_client_request().unwrap();
    connect_async(request).await.map(|_| ())
}

async fn connect_with_token(
    url: &str,
    token: &str,
) -> WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>> {
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("x-auth-token", token.parse().unwrap());
    let (stream, _) = connect_async(request).await.expect("connect websocket");
    stream
}
