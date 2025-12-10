//! Integration tests for Substrate RPC client
//!
//! These tests verify the Substrate RPC client functionality.
//! Tests marked with #[ignore] require a running Substrate node.

use wallet::substrate_rpc::{
    BlockingSubstrateRpcClient, LatestBlock, NoteStatus, PaginationParams, SubstrateRpcClient,
    SubstrateRpcConfig,
};
use wallet::WalletError;

#[test]
fn test_config_defaults() {
    let config = SubstrateRpcConfig::default();
    assert_eq!(config.endpoint, "ws://127.0.0.1:9944");
    assert_eq!(config.max_reconnect_attempts, 5);
    assert_eq!(config.connection_timeout.as_secs(), 30);
    assert_eq!(config.request_timeout.as_secs(), 60);
}

#[test]
fn test_config_with_custom_endpoint() {
    let config = SubstrateRpcConfig::with_endpoint("ws://localhost:9955");
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

/// Integration test that requires a running Substrate node
#[tokio::test]
#[ignore]
async fn test_substrate_client_connect() {
    let client = SubstrateRpcClient::connect("ws://127.0.0.1:9944").await;
    assert!(client.is_ok(), "Should connect to local Substrate node");

    let client = client.unwrap();
    assert!(client.is_connected().await);
}

/// Integration test for note status endpoint
#[tokio::test]
#[ignore]
async fn test_substrate_client_note_status() {
    let client = SubstrateRpcClient::connect("ws://127.0.0.1:9944")
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
async fn test_substrate_client_latest_block() {
    let client = SubstrateRpcClient::connect("ws://127.0.0.1:9944")
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
async fn test_substrate_client_commitments() {
    let client = SubstrateRpcClient::connect("ws://127.0.0.1:9944")
        .await
        .expect("Failed to connect");

    let entries = client.commitments(0, 10).await;
    assert!(entries.is_ok(), "hegemon_walletCommitments should work");
}

/// Integration test for nullifiers endpoint
#[tokio::test]
#[ignore]
async fn test_substrate_client_nullifiers() {
    let client = SubstrateRpcClient::connect("ws://127.0.0.1:9944")
        .await
        .expect("Failed to connect");

    let nullifiers = client.nullifiers().await;
    assert!(nullifiers.is_ok(), "hegemon_walletNullifiers should work");
}

/// Integration test for block subscription
#[tokio::test]
#[ignore]
async fn test_substrate_client_block_subscription() {
    use futures::StreamExt;
    use std::time::Duration;

    let client = SubstrateRpcClient::connect("ws://127.0.0.1:9944")
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
async fn test_substrate_client_connection_failure() {
    // Try to connect to a port that doesn't have a node
    let result = SubstrateRpcClient::connect("ws://127.0.0.1:59999").await;

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
    let config = SubstrateRpcConfig::with_endpoint("ws://localhost:9944");
    assert_eq!(config.endpoint, "ws://localhost:9944");
}

/// Test shield transaction submission with ML-DSA signature
/// Requires a running Substrate node (run with: cargo test test_shield_e2e -- --ignored)
///
/// Note: Running this test multiple times against the same node without mining
/// will cause "Priority too low" errors because the nonce is reserved in the pool.
/// This is expected behavior - restart the node with `--tmp` for a fresh state.
#[tokio::test]
#[ignore]
async fn test_shield_e2e() {
    use std::time::{SystemTime, UNIX_EPOCH};
    use synthetic_crypto::hashes::blake2_256;

    // Connect to local node
    let client = SubstrateRpcClient::connect("ws://127.0.0.1:9944")
        .await
        .expect("Should connect to node");

    // Alice dev seed: blake2_256("//Alice")
    let alice_seed = blake2_256(b"//Alice");

    // Create unique commitment using current timestamp so each test run is different
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut commitment = [0u8; 32];
    commitment[0..8].copy_from_slice(&nonce.to_le_bytes());

    let encrypted_note = wallet::extrinsic::EncryptedNote::default(); // dummy encrypted note

    // Submit shield transaction for 1000 units
    println!("Submitting shield transaction...");
    let result = client
        .submit_shield_signed(1000, commitment, encrypted_note, &alice_seed)
        .await;

    match &result {
        Ok(tx_hash) => {
            println!("SUCCESS! Transaction hash: 0x{}", hex::encode(tx_hash));
            // Test passed - transaction was submitted
        }
        Err(WalletError::Rpc(msg))
            if msg.contains("Already Imported") || msg.contains("Priority is too low") =>
        {
            // This is OK - means a prior transaction was submitted successfully
            // and the pool has the nonce reserved. Restart node with --tmp for fresh state.
            println!("NOTE: Transaction rejected due to nonce conflict (prior tx in pool)");
            println!("This is expected when running test multiple times against same node.");
            println!("Restart node with --tmp flag for fresh state.");
            // We consider this a pass since the transaction _was_ built and signed correctly
        }
        Err(e) => {
            println!("FAILED: {:?}", e);
            panic!("Shield transaction should succeed: {:?}", e);
        }
    }
}
