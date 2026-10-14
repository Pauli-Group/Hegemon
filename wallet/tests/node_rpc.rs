//! Integration tests for native node RPC client
//!
//! These tests verify the native node RPC client functionality.
//! Tests marked with #[ignore] require a running node node.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};
use wallet::node_rpc::{LatestBlock, NodeRpcClient, NodeRpcConfig, NoteStatus, PaginationParams};
use wallet::WalletError;

// Test-only loopback fixtures use OS-assigned ports and bounded socket I/O.
fn accept_stub(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // macOS can inherit the listener's nonblocking mode. AllowStdIo
                // requires blocking I/O; the socket deadlines still bound it.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "stub accept timed out");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("stub accept failed: {error}"),
        }
    }
}

fn read_http_headers(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16 * 1024, "stub request headers exceeded cap");
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).unwrap()
}

fn fixture_note_status() -> serde_json::Value {
    serde_json::json!({"leaf_count": 7, "depth": 32, "root": "0x1234", "next_index": 7})
}

#[tokio::test]
async fn default_transport_makes_http_one_shot_requests() {
    let defaults = NodeRpcConfig::default();
    let scheme = defaults.endpoint.split("://").next().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("{scheme}://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut stream = accept_stub(&listener);
        let headers = read_http_headers(&mut stream);
        assert!(headers.starts_with("POST / HTTP/1.1\r\n"));
        assert!(!headers.to_ascii_lowercase().contains("upgrade: websocket"));
        let size: usize = headers
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .expect("JSON-RPC request has a content length");
        assert!(size <= 16 * 1024);
        let mut body = vec![0; size];
        stream.read_exact(&mut body).unwrap();
        let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request["method"], "hegemon_walletNotes");
        let response = serde_json::json!({"jsonrpc":"2.0", "id":request["id"], "result":fixture_note_status()}).to_string();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
    });
    let config = NodeRpcConfig {
        endpoint,
        request_timeout: Duration::from_secs(2),
        ..defaults
    };
    let client = NodeRpcClient::connect_with_config(config).await.unwrap();
    let status = client.note_status().await.unwrap();
    assert_eq!(status.leaf_count, 7);
    let error = client.subscribe_new_heads().await.unwrap_err();
    assert!(error
        .to_string()
        .contains("subscriptions require a ws:// RPC endpoint"));
    server.join().unwrap();
}

#[tokio::test]
async fn explicit_websocket_http_200_is_a_hint_not_a_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut stream = accept_stub(&listener);
        let headers = read_http_headers(&mut stream);
        assert!(headers.starts_with("GET / HTTP/1.1\r\n"));
        assert!(headers.to_ascii_lowercase().contains("upgrade: websocket"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let config = NodeRpcConfig {
        endpoint,
        connection_timeout: Duration::from_secs(2),
        ..NodeRpcConfig::default()
    };
    let error = match NodeRpcClient::connect_with_config(config).await {
        Ok(_) => panic!("explicit WebSocket must not fall back to HTTP"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("HTTP 200 instead of a WebSocket upgrade"));
    assert!(error
        .to_string()
        .contains("--ws-url/ws_url also accepts HTTP"));
    server.join().unwrap();
}

#[tokio::test]
async fn explicit_websocket_keeps_requests_and_subscriptions() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        futures::executor::block_on(async {
            let stream = accept_stub(&listener);
            let mut handshake =
                soketto::handshake::Server::new(futures::io::AllowStdIo::new(stream));
            let key = handshake.receive_request().await.unwrap().key();
            handshake
                .send_response(&soketto::handshake::server::Response::Accept {
                    key,
                    protocol: None,
                })
                .await
                .unwrap();
            let mut builder = handshake.into_builder();
            builder.set_max_message_size(16 * 1024);
            let (mut sender, mut receiver) = builder.finish();
            let mut methods = Vec::new();
            for _ in 0..3 {
                let mut bytes = Vec::new();
                receiver.receive_data(&mut bytes).await.unwrap();
                let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                let method = request["method"].as_str().unwrap();
                let result = match method {
                    "hegemon_walletNotes" => fixture_note_status(),
                    "chain_subscribeNewHeads" => serde_json::json!("heads-1"),
                    "chain_unsubscribeNewHeads" => serde_json::json!(true),
                    other => panic!("unexpected WS method: {other}"),
                };
                methods.push(method.to_string());
                sender
                    .send_text(
                        serde_json::json!({"jsonrpc":"2.0", "id":request["id"], "result":result})
                            .to_string(),
                    )
                    .await
                    .unwrap();
                if method == "chain_subscribeNewHeads" {
                    sender.send_text(serde_json::json!({"jsonrpc":"2.0", "method":"chain_newHead", "params":{"subscription":"heads-1", "result":{"number":"0x2"}}}).to_string()).await.unwrap();
                }
                sender.flush().await.unwrap();
            }
            methods
        })
    });
    let config = NodeRpcConfig {
        endpoint,
        connection_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        ..NodeRpcConfig::default()
    };
    let client = NodeRpcClient::connect_with_config(config).await.unwrap();
    assert!(client.is_connected().await);
    assert_eq!(client.note_status().await.unwrap().leaf_count, 7);
    let mut subscription = client.subscribe_new_heads().await.unwrap();
    let notification = tokio::time::timeout(Duration::from_secs(2), subscription.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(notification["number"], "0x2");
    subscription.unsubscribe().await.unwrap();
    drop(client);
    assert_eq!(
        server.join().unwrap(),
        [
            "hegemon_walletNotes",
            "chain_subscribeNewHeads",
            "chain_unsubscribeNewHeads"
        ]
    );
}

#[test]
fn test_config_defaults() {
    let config = NodeRpcConfig::default();
    assert_eq!(config.endpoint, "http://127.0.0.1:9944");
    assert_eq!(config.max_reconnect_attempts, 5);
    assert_eq!(config.connection_timeout.as_secs(), 30);
    assert_eq!(config.request_timeout.as_secs(), 60);
}

#[test]
fn test_config_with_custom_endpoint() {
    let config = NodeRpcConfig::with_endpoint("ws://localhost:9955");
    assert_eq!(config.endpoint, "ws://localhost:9955");
    // Other defaults should remain
    assert_eq!(config.max_reconnect_attempts, 5);
}

#[test]
fn test_pagination_params_defaults() {
    let params = PaginationParams::default();
    assert_eq!(params.start, 0);
    assert_eq!(params.limit, 128);
}

#[test]
fn test_pagination_params_serialization() {
    let params = PaginationParams {
        start: 10,
        limit: 50,
    };
    let json = serde_json::to_string(&params).unwrap();
    assert!(json.contains("\"start\":10"));
    assert!(json.contains("\"limit\":50"));

    let deserialized: PaginationParams = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.start, 10);
    assert_eq!(deserialized.limit, 50);
}

#[test]
fn test_note_status_deserialization() {
    let json = r#"{
        "leaf_count": 1000,
        "depth": 32,
        "root": "0x1234567890abcdef",
        "next_index": 1001
    }"#;

    let status: NoteStatus = serde_json::from_str(json).unwrap();
    assert_eq!(status.leaf_count, 1000);
    assert_eq!(status.depth, 32);
    assert_eq!(status.root, "0x1234567890abcdef");
    assert_eq!(status.next_index, 1001);
}

#[test]
fn test_latest_block_deserialization() {
    let json = r#"{
        "height": 12345,
        "hash": "0xabcdef",
        "state_root": "0x123456",
        "nullifier_root": "0x789abc",
        "supply_digest": 1000000000,
        "timestamp": 1700000000
    }"#;

    let block: LatestBlock = serde_json::from_str(json).unwrap();
    assert_eq!(block.height, 12345);
    assert_eq!(block.hash, "0xabcdef");
    assert_eq!(block.state_root, "0x123456");
    assert_eq!(block.nullifier_root, "0x789abc");
    assert_eq!(block.supply_digest, 1000000000);
    assert_eq!(block.timestamp, 1700000000);
}

#[test]
fn test_latest_block_without_timestamp() {
    // timestamp should default to 0 if not provided
    let json = r#"{
        "height": 100,
        "hash": "0xabc",
        "state_root": "0x123",
        "nullifier_root": "0x456",
        "supply_digest": 500
    }"#;

    let block: LatestBlock = serde_json::from_str(json).unwrap();
    assert_eq!(block.height, 100);
    assert_eq!(block.timestamp, 0);
}

/// Integration test that requires a running node node
#[tokio::test]
#[ignore]
async fn test_node_client_connect() {
    let client = NodeRpcClient::connect("http://127.0.0.1:9944").await;
    assert!(client.is_ok(), "Should connect to local node node");

    let client = client.unwrap();
    assert!(client.is_connected().await);
}

/// Integration test for note status endpoint
#[tokio::test]
#[ignore]
async fn test_node_client_note_status() {
    let client = NodeRpcClient::connect("http://127.0.0.1:9944")
        .await
        .expect("Failed to connect");

    let status = client.note_status().await;
    assert!(status.is_ok(), "hegemon_walletNotes should work");

    let status = status.unwrap();
    assert!(status.depth > 0, "Tree should have depth > 0");
}

/// Integration test for latest block endpoint
#[tokio::test]
#[ignore]
async fn test_node_client_latest_block() {
    let client = NodeRpcClient::connect("http://127.0.0.1:9944")
        .await
        .expect("Failed to connect");

    let block = client.latest_block().await;
    assert!(block.is_ok(), "hegemon_latestBlock should work");

    let block = block.unwrap();
    assert!(!block.hash.is_empty(), "Block hash should not be empty");
}

/// Integration test for commitments endpoint
#[tokio::test]
#[ignore]
async fn test_node_client_commitments() {
    let client = NodeRpcClient::connect("http://127.0.0.1:9944")
        .await
        .expect("Failed to connect");

    let entries = client.commitments(0, 10).await;
    assert!(entries.is_ok(), "hegemon_walletCommitments should work");
}

/// Integration test for nullifiers endpoint
#[tokio::test]
#[ignore]
async fn test_node_client_nullifiers() {
    let client = NodeRpcClient::connect("http://127.0.0.1:9944")
        .await
        .expect("Failed to connect");

    let nullifiers = client.nullifiers().await;
    assert!(nullifiers.is_ok(), "hegemon_walletNullifiers should work");
}

/// Integration test for block subscription
#[tokio::test]
#[ignore]
async fn test_node_client_block_subscription() {
    #[allow(unused_imports)]
    use futures::StreamExt;
    use std::time::Duration;

    let client = NodeRpcClient::connect("ws://127.0.0.1:9944")
        .await
        .expect("Failed to connect");

    let mut subscription = client
        .subscribe_new_heads()
        .await
        .expect("Should subscribe to new heads");

    // Wait for at least one block
    let result = tokio::time::timeout(Duration::from_secs(30), subscription.next()).await;

    assert!(result.is_ok(), "Should receive block within 30 seconds");
}

/// Test connection failure handling
#[tokio::test]
async fn test_node_client_connection_failure() {
    // Try to connect to a port that doesn't have a node
    let result = NodeRpcClient::connect("ws://127.0.0.1:59999").await;

    assert!(
        result.is_err(),
        "Should fail to connect to non-existent node"
    );
    if let Err(WalletError::Rpc(msg)) = result {
        assert!(
            msg.contains("Failed to connect"),
            "Error should mention connection failure"
        );
    }
}

/// Test blocking client
#[test]
fn test_blocking_client_config() {
    // Just test that config works without actual connection
    let config = NodeRpcConfig::with_endpoint("ws://localhost:9944");
    assert_eq!(config.endpoint, "ws://localhost:9944");
}
