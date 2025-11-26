//! Multi-Node Substrate Mining Integration Tests (Task 10.5)
//!
//! These tests verify that multiple Substrate-based Hegemon nodes can:
//! - Form a PQ-secure P2P network
//! - Mine blocks using Blake3 PoW
//! - Propagate blocks via PQ channels
//! - Maintain consensus across nodes
//!
//! # Test Scenarios
//!
//! 1. Single node mining in production mode
//! 2. Multi-node network with mining
//! 3. Chain synchronization after partition
//! 4. Production provider with client callbacks
//!
//! # Prerequisites
//!
//! These tests require the `substrate` feature to be enabled:
//! ```bash
//! cargo test -p security-tests --test multi_node_substrate --features substrate
//! ```

#![cfg(feature = "substrate")]
#![allow(dead_code)] // Allow unused test helpers

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sp_core::H256;
use tokio::sync::mpsc;

// Re-exports from hegemon-node when substrate feature is enabled
#[cfg(feature = "substrate")]
mod substrate_tests {
    use super::*;

    /// Test configuration for easy mining
    const TEST_DIFFICULTY_BITS: u32 = 0x2100ffff;

    /// Helper to create a mock PQ network event receiver
    fn mock_pq_event_receiver() -> mpsc::Receiver<()> {
        let (_, rx) = mpsc::channel(1);
        rx
    }

    /// Test: Production chain state provider with callbacks works correctly
    #[tokio::test]
    async fn test_production_provider_callbacks() {
        use hegemon_node::substrate::client::{
            ProductionChainStateProvider, ProductionConfig, DEFAULT_DIFFICULTY_BITS,
        };
        use hegemon_node::substrate::mining_worker::ChainStateProvider;

        let config = ProductionConfig::default();
        let provider = ProductionChainStateProvider::new(config);

        // Initially uses fallback
        assert_eq!(provider.best_hash(), H256::zero());
        assert_eq!(provider.best_number(), 0);
        assert_eq!(provider.difficulty_bits(), DEFAULT_DIFFICULTY_BITS);

        // Set up callbacks
        let test_hash = H256::repeat_byte(0x42);
        let hash_for_callback = test_hash;
        provider.set_best_block_fn(move || (hash_for_callback, 100));
        provider.set_difficulty_fn(|| TEST_DIFFICULTY_BITS);
        provider.set_pending_txs_fn(|| vec![vec![1, 2, 3], vec![4, 5, 6]]);

        // Now queries via callbacks
        assert_eq!(provider.best_hash(), test_hash);
        assert_eq!(provider.best_number(), 100);
        assert_eq!(provider.difficulty_bits(), TEST_DIFFICULTY_BITS);
        assert_eq!(provider.pending_transactions().len(), 2);
    }

    /// Test: Production provider import callback is invoked
    #[tokio::test]
    async fn test_production_provider_import_callback() {
        use consensus::Blake3Seal;
        use hegemon_node::substrate::client::{ProductionChainStateProvider, ProductionConfig};
        use hegemon_node::substrate::mining_worker::{BlockTemplate, ChainStateProvider};

        let config = ProductionConfig::default();
        let provider = ProductionChainStateProvider::new(config);

        let import_count = Arc::new(AtomicU64::new(0));
        let count_clone = Arc::clone(&import_count);

        provider.set_import_fn(move |template, seal| {
            count_clone.fetch_add(1, Ordering::SeqCst);
            assert_eq!(template.number, 1);
            Ok(H256::from_slice(seal.work.as_bytes()))
        });

        let template = BlockTemplate::new(H256::zero(), 1, TEST_DIFFICULTY_BITS);
        let seal = Blake3Seal {
            nonce: 12345,
            difficulty: TEST_DIFFICULTY_BITS,
            work: H256::repeat_byte(0xaa),
        };

        let result = provider.import_block(&template, &seal);
        assert!(result.is_ok());
        assert_eq!(import_count.load(Ordering::SeqCst), 1);
    }

    /// Test: Mining worker builder creates valid production worker
    #[tokio::test]
    async fn test_production_mining_worker_builder() {
        use hegemon_node::pow::{PowConfig, PowHandle};
        use hegemon_node::substrate::mining_worker::{
            MiningWorkerConfig, ProductionMiningWorkerBuilder,
        };

        let pow_config = PowConfig::mining(1);
        let (pow_handle, _rx) = PowHandle::new(pow_config);

        let worker_config = MiningWorkerConfig {
            threads: 2,
            round_duration_ms: 100,
            work_check_interval_ms: 50,
            verbose: true,
            test_mode: true,
        };

        let builder = ProductionMiningWorkerBuilder::new()
            .with_pow_handle(pow_handle)
            .with_config(worker_config);

        let result = builder.build_mock();
        assert!(result.is_ok());

        let (_worker, chain_state) = result.unwrap();
        assert!(!chain_state.is_fully_configured());

        // Configure the chain state
        chain_state.set_best_block_fn(|| (H256::zero(), 0));
        chain_state.set_difficulty_fn(|| TEST_DIFFICULTY_BITS);
        chain_state.set_pending_txs_fn(|| vec![]);
        chain_state.set_import_fn(|_, seal| Ok(H256::from_slice(seal.work.as_bytes())));

        assert!(chain_state.is_fully_configured());
    }

    /// Test: Block template creation with extrinsics
    #[tokio::test]
    async fn test_block_template_with_transactions() {
        use hegemon_node::substrate::mining_worker::BlockTemplate;

        let parent_hash = H256::repeat_byte(0x11);
        let extrinsics = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        let template = BlockTemplate::new(parent_hash, 42, TEST_DIFFICULTY_BITS)
            .with_extrinsics(extrinsics.clone());

        assert_eq!(template.parent_hash, parent_hash);
        assert_eq!(template.number, 42);
        assert_eq!(template.difficulty_bits, TEST_DIFFICULTY_BITS);
        assert_eq!(template.extrinsics.len(), 3);
        assert_ne!(template.extrinsics_root, H256::zero());
        assert_ne!(template.pre_hash, H256::zero());

        // Mining work should include template data
        let work = template.to_mining_work();
        assert_eq!(work.height, 42);
        assert_eq!(work.pow_bits, TEST_DIFFICULTY_BITS);
        assert_eq!(work.parent_hash, parent_hash);
    }

    /// Test: Mining worker stats tracking
    #[tokio::test]
    async fn test_mining_worker_stats() {
        use hegemon_node::substrate::mining_worker::MiningWorkerStats;

        let mut stats = MiningWorkerStats::new();

        // Simulate mining activity
        for _ in 0..100 {
            stats.rounds_attempted += 1;
            stats.hashes_computed += 10_000;
        }
        stats.blocks_mined += 5;
        stats.blocks_imported += 5;
        stats.blocks_broadcast += 5;

        assert_eq!(stats.blocks_mined, 5);
        assert_eq!(stats.rounds_attempted, 100);
        assert_eq!(stats.hashes_computed, 1_000_000);
        assert_eq!(stats.success_rate(), 0.05); // 5 blocks / 100 rounds
    }

    /// Test: Production provider handles new block notification
    #[tokio::test]
    async fn test_production_provider_on_new_block() {
        use hegemon_node::substrate::client::{ProductionChainStateProvider, ProductionConfig};
        use hegemon_node::substrate::mining_worker::ChainStateProvider;

        let config = ProductionConfig::default();
        let provider = ProductionChainStateProvider::new(config);

        // Notify of new block
        let block_hash = H256::repeat_byte(0xcc);
        provider.on_new_block(&block_hash, 50);

        // Fallback state should be updated
        assert_eq!(provider.fallback_state.best_hash(), block_hash);
        assert_eq!(provider.fallback_state.best_number(), 50);
    }

    /// Test: Production config from environment
    #[tokio::test]
    async fn test_production_config_from_env() {
        use hegemon_node::substrate::client::ProductionConfig;

        // Should not panic and use defaults
        let config = ProductionConfig::from_env();
        assert!(config.poll_interval_ms > 0);
        assert!(config.max_block_transactions > 0);
    }

    /// Test: Multiple concurrent imports to production provider
    #[tokio::test]
    async fn test_concurrent_imports() {
        use consensus::Blake3Seal;
        use hegemon_node::substrate::client::{ProductionChainStateProvider, ProductionConfig};
        use hegemon_node::substrate::mining_worker::{BlockTemplate, ChainStateProvider};
        use std::sync::atomic::AtomicU64;

        let config = ProductionConfig::default();
        let provider = Arc::new(ProductionChainStateProvider::new(config));

        let import_count = Arc::new(AtomicU64::new(0));
        let count_clone = Arc::clone(&import_count);

        provider.set_import_fn(move |_, seal| {
            count_clone.fetch_add(1, Ordering::SeqCst);
            Ok(H256::from_slice(seal.work.as_bytes()))
        });

        let provider_arc = provider.clone();

        // Spawn multiple concurrent import tasks
        let mut handles = vec![];
        for i in 0..10 {
            let provider = Arc::clone(&provider_arc);
            handles.push(tokio::spawn(async move {
                let template = BlockTemplate::new(H256::zero(), i as u64, TEST_DIFFICULTY_BITS);
                let seal = Blake3Seal {
                    nonce: i as u64,
                    difficulty: TEST_DIFFICULTY_BITS,
                    work: H256::repeat_byte(i as u8),
                };
                provider.import_block(&template, &seal)
            }));
        }

        // Wait for all imports
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }

        assert_eq!(import_count.load(Ordering::SeqCst), 10);
    }

    /// Test: Transaction limit is enforced
    #[tokio::test]
    async fn test_transaction_limit_enforcement() {
        use hegemon_node::substrate::client::{ProductionChainStateProvider, ProductionConfig};
        use hegemon_node::substrate::mining_worker::ChainStateProvider;

        let config = ProductionConfig {
            max_block_transactions: 3,
            ..Default::default()
        };
        let provider = ProductionChainStateProvider::new(config);

        // Return 10 transactions
        provider.set_pending_txs_fn(|| {
            (0..10).map(|i| vec![i as u8]).collect()
        });

        let txs = provider.pending_transactions();
        assert_eq!(txs.len(), 3); // Limited by config
    }
}

/// Integration tests that require full Substrate node infrastructure
/// These are marked #[ignore] as they need a running node
#[cfg(feature = "substrate")]
mod node_integration_tests {
    /// Test: Full node boots and accepts mining control
    #[tokio::test]
    #[ignore = "Requires full Substrate infrastructure"]
    async fn test_node_boot_and_mine() {
        // This test would:
        // 1. Start a dev node
        // 2. Enable mining via RPC
        // 3. Wait for block production
        // 4. Verify block was mined
        todo!("Implement when full sc-service integration is complete")
    }

    /// Test: Two nodes sync over PQ network
    #[tokio::test]
    #[ignore = "Requires full Substrate infrastructure"]
    async fn test_two_node_sync() {
        // This test would:
        // 1. Start two nodes
        // 2. Connect via PQ network
        // 3. Mine on node 1
        // 4. Verify node 2 receives block
        todo!("Implement when full sc-service integration is complete")
    }

    /// Test: Three nodes maintain consensus
    #[tokio::test]
    #[ignore = "Requires full Substrate infrastructure"]
    async fn test_three_node_consensus() {
        // This test would:
        // 1. Start three nodes
        // 2. Connect in a triangle
        // 3. Mine on all three
        // 4. Verify all converge to same chain
        todo!("Implement when full sc-service integration is complete")
    }

    /// Test: Network partition and recovery
    #[tokio::test]
    #[ignore = "Requires full Substrate infrastructure"]
    async fn test_partition_recovery() {
        // This test would:
        // 1. Start three nodes
        // 2. Partition into two groups
        // 3. Mine independently
        // 4. Heal partition
        // 5. Verify reorganization to longest chain
        todo!("Implement when full sc-service integration is complete")
    }
}

#[cfg(not(feature = "substrate"))]
mod substrate_tests {
    #[test]
    fn substrate_feature_not_enabled() {
        // This test always passes - just a marker that substrate feature is needed
        println!("Run with: cargo test -p security-tests --test multi_node_substrate --features substrate");
    }
}
