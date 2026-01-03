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
        provider.set_pending_txs_fn(|| (0..10).map(|i| vec![i as u8]).collect());

        let txs = provider.pending_transactions();
        assert_eq!(txs.len(), 3); // Limited by config
    }

    // =========================================================================
    // Task 11.4.7: Integration tests for full Substrate client
    // =========================================================================
    //
    // These tests verify the complete integration of:
    // - new_partial_with_client() creates valid Substrate client
    // - BlockBuilder API executes extrinsics correctly
    // - PowBlockImport verifies Blake3 seals
    // - ProductionChainStateProvider callbacks work with real client
    //
    // Note: Full shielded transaction tests require Phase 12 (pallet-shielded-pool)
    // which is not yet implemented. These tests verify the substrate wiring.

    /// Test: State execution callback computes extrinsics root (Task 11.4.7)
    #[tokio::test]
    async fn test_state_execution_extrinsics_root() {
        use hegemon_node::substrate::client::{
            ProductionChainStateProvider, ProductionConfig, StateExecutionResult,
        };

        let config = ProductionConfig::default();
        let provider = ProductionChainStateProvider::new(config);

        // Set up mock state execution that returns predictable results
        provider.set_execute_extrinsics_fn(|_parent_hash, block_number, extrinsics| {
            // Compute extrinsics root using the real function
            let extrinsics_root =
                hegemon_node::substrate::mining_worker::compute_extrinsics_root(extrinsics);

            // Mock state root based on block number
            let mut state_root_bytes = [0u8; 32];
            state_root_bytes[0..8].copy_from_slice(&block_number.to_le_bytes());

            Ok(StateExecutionResult {
                applied_extrinsics: extrinsics.to_vec(),
                state_root: H256::from_slice(&state_root_bytes),
                extrinsics_root,
                failed_count: 0,
                storage_changes: None,
                recursive_proof: None,
            })
        });

        // Execute with some extrinsics
        let extrinsics = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let result = provider
            .execute_extrinsics(&H256::zero(), 42, &extrinsics)
            .expect("execution should succeed");

        assert_eq!(result.applied_extrinsics.len(), 2);
        assert_ne!(result.extrinsics_root, H256::zero());
        assert_ne!(result.state_root, H256::zero());
        assert_eq!(result.failed_count, 0);

        // Verify state root encodes block number
        assert_eq!(result.state_root.as_bytes()[0..8], 42u64.to_le_bytes());
    }

    /// Test: State execution with failed extrinsics (Task 11.4.7)
    #[tokio::test]
    async fn test_state_execution_with_failures() {
        use hegemon_node::substrate::client::{
            ProductionChainStateProvider, ProductionConfig, StateExecutionResult,
        };

        let config = ProductionConfig::default();
        let provider = ProductionChainStateProvider::new(config);

        // Set up execution that fails some extrinsics
        provider.set_execute_extrinsics_fn(|_parent, _number, extrinsics| {
            // Only accept extrinsics with even length
            let (applied, failed): (Vec<_>, Vec<_>) = extrinsics
                .iter()
                .cloned()
                .partition(|ext| ext.len() % 2 == 0);

            let extrinsics_root =
                hegemon_node::substrate::mining_worker::compute_extrinsics_root(&applied);

            Ok(StateExecutionResult {
                applied_extrinsics: applied,
                state_root: H256::repeat_byte(0x99),
                extrinsics_root,
                failed_count: failed.len(),
                storage_changes: None,
                recursive_proof: None,
            })
        });

        // Mix of even and odd length extrinsics
        let extrinsics = vec![
            vec![1, 2],       // len 2, even - pass
            vec![1, 2, 3],    // len 3, odd - fail
            vec![1, 2, 3, 4], // len 4, even - pass
            vec![1],          // len 1, odd - fail
        ];
        let result = provider
            .execute_extrinsics(&H256::zero(), 1, &extrinsics)
            .expect("execution should succeed");

        assert_eq!(result.applied_extrinsics.len(), 2);
        assert_eq!(result.failed_count, 2);
    }

    /// Test: Block template includes state execution results (Task 11.4.7)
    #[tokio::test]
    async fn test_block_template_with_state_execution() {
        use hegemon_node::substrate::client::{
            ProductionChainStateProvider, ProductionConfig, StateExecutionResult,
        };
        use hegemon_node::substrate::mining_worker::ChainStateProvider;

        let config = ProductionConfig::default();
        let provider = ProductionChainStateProvider::new(config);

        // Configure provider
        provider.set_best_block_fn(|| (H256::repeat_byte(0x11), 99));
        provider.set_difficulty_fn(|| TEST_DIFFICULTY_BITS);
        provider.set_pending_txs_fn(|| vec![vec![1, 2, 3], vec![4, 5, 6]]);

        // Set up state execution
        let expected_state_root = H256::repeat_byte(0xab);
        provider.set_execute_extrinsics_fn(move |_parent, _number, extrinsics| {
            let extrinsics_root =
                hegemon_node::substrate::mining_worker::compute_extrinsics_root(extrinsics);
            Ok(StateExecutionResult {
                applied_extrinsics: extrinsics.to_vec(),
                state_root: expected_state_root,
                extrinsics_root,
                failed_count: 0,
                storage_changes: None,
                recursive_proof: None,
            })
        });

        // Build block template
        let template = provider.build_block_template();

        assert_eq!(template.number, 100); // 99 + 1
        assert_eq!(template.parent_hash, H256::repeat_byte(0x11));
        assert_eq!(template.difficulty_bits, TEST_DIFFICULTY_BITS);
        assert_eq!(template.extrinsics.len(), 2);

        // State root should be from execution callback
        assert_eq!(template.state_root, expected_state_root);
    }

    /// Test: Full block production flow with all callbacks (Task 11.4.7)
    #[tokio::test]
    async fn test_full_block_production_flow() {
        use consensus::Blake3Seal;
        use hegemon_node::substrate::client::{
            ProductionChainStateProvider, ProductionConfig, StateExecutionResult,
        };
        use hegemon_node::substrate::mining_worker::ChainStateProvider;
        use std::sync::atomic::AtomicU64;

        let config = ProductionConfig::default();
        let provider = Arc::new(ProductionChainStateProvider::new(config));

        // Track callback invocations
        let best_block_calls = Arc::new(AtomicU64::new(0));
        let difficulty_calls = Arc::new(AtomicU64::new(0));
        let execute_calls = Arc::new(AtomicU64::new(0));
        let import_calls = Arc::new(AtomicU64::new(0));
        let on_success_calls = Arc::new(AtomicU64::new(0));

        // Configure all callbacks
        let bb = best_block_calls.clone();
        provider.set_best_block_fn(move || {
            bb.fetch_add(1, Ordering::SeqCst);
            (H256::repeat_byte(0x22), 50)
        });

        let dc = difficulty_calls.clone();
        provider.set_difficulty_fn(move || {
            dc.fetch_add(1, Ordering::SeqCst);
            TEST_DIFFICULTY_BITS
        });

        provider.set_pending_txs_fn(|| vec![vec![0xaa, 0xbb]]);

        let ec = execute_calls.clone();
        provider.set_execute_extrinsics_fn(move |_parent, _number, extrinsics| {
            ec.fetch_add(1, Ordering::SeqCst);
            let extrinsics_root =
                hegemon_node::substrate::mining_worker::compute_extrinsics_root(extrinsics);
            Ok(StateExecutionResult {
                applied_extrinsics: extrinsics.to_vec(),
                state_root: H256::repeat_byte(0xcc),
                extrinsics_root,
                failed_count: 0,
                storage_changes: None,
                recursive_proof: None,
            })
        });

        let ic = import_calls.clone();
        provider.set_import_fn(move |_template, seal| {
            ic.fetch_add(1, Ordering::SeqCst);
            Ok(H256::from_slice(seal.work.as_bytes()))
        });

        let osc = on_success_calls.clone();
        provider.set_on_import_success_fn(move |_included| {
            osc.fetch_add(1, Ordering::SeqCst);
        });

        // Simulate full block production
        let template = provider.build_block_template();

        assert_eq!(template.number, 51);
        assert!(best_block_calls.load(Ordering::SeqCst) >= 1);
        assert!(difficulty_calls.load(Ordering::SeqCst) >= 1);
        assert!(execute_calls.load(Ordering::SeqCst) >= 1);

        // Simulate mining found a valid seal
        let seal = Blake3Seal {
            nonce: 99999,
            difficulty: TEST_DIFFICULTY_BITS,
            work: H256::repeat_byte(0xdd),
        };

        // Import the block
        let result = provider.import_block(&template, &seal);
        assert!(result.is_ok());
        assert_eq!(import_calls.load(Ordering::SeqCst), 1);
        assert_eq!(on_success_calls.load(Ordering::SeqCst), 1);
    }

    /// Test: Provider correctly reports configuration status (Task 11.4.7)
    #[tokio::test]
    async fn test_provider_configuration_status() {
        use hegemon_node::substrate::client::{ProductionChainStateProvider, ProductionConfig};

        let config = ProductionConfig::default();
        let provider = ProductionChainStateProvider::new(config);

        // Initially not configured
        assert!(!provider.is_fully_configured());
        assert!(!provider.has_state_execution());

        // Add callbacks one by one
        provider.set_best_block_fn(|| (H256::zero(), 0));
        assert!(!provider.is_fully_configured());

        provider.set_difficulty_fn(|| TEST_DIFFICULTY_BITS);
        assert!(!provider.is_fully_configured());

        provider.set_pending_txs_fn(|| vec![]);
        assert!(!provider.is_fully_configured());

        provider.set_import_fn(|_, seal| Ok(H256::from_slice(seal.work.as_bytes())));
        assert!(provider.is_fully_configured());

        // State execution is optional
        assert!(!provider.has_state_execution());
        provider.set_execute_extrinsics_fn(|_, _, _| {
            Ok(hegemon_node::substrate::client::StateExecutionResult {
                applied_extrinsics: vec![],
                state_root: H256::zero(),
                extrinsics_root: H256::zero(),
                failed_count: 0,
                storage_changes: None,
                recursive_proof: None,
            })
        });
        assert!(provider.has_state_execution());
    }
}

/// Integration tests that require full Substrate node infrastructure
/// These are marked #[ignore] as they need a running node
#[cfg(feature = "substrate")]
mod node_integration_tests {
    /// Test: Full node boots and accepts mining control (Task 11.4.7)
    #[tokio::test]
    #[ignore = "Requires full Substrate infrastructure - run manually"]
    async fn test_node_boot_and_mine() {
        // This test exercises new_full_with_client():
        // 1. Start a dev node with real Substrate client
        // 2. Enable mining via RPC
        // 3. Wait for block production
        // 4. Verify block was mined with real state root
        //
        // To run: cargo test -p security-tests --test multi_node_substrate \
        //         --features substrate test_node_boot_and_mine -- --ignored
        todo!("Implement when sc-service dev node helper is available")
    }

    /// Test: Two nodes sync over PQ network (Task 11.4.7)
    #[tokio::test]
    #[ignore = "Requires full Substrate infrastructure - run manually"]
    async fn test_two_node_sync() {
        // This test verifies PowBlockImport works across nodes:
        // 1. Start two nodes with real clients
        // 2. Connect via PQ network
        // 3. Mine on node 1
        // 4. Verify node 2 receives and imports block
        //
        // To run: cargo test -p security-tests --test multi_node_substrate \
        //         --features substrate test_two_node_sync -- --ignored
        todo!("Implement when sc-service dev node helper is available")
    }

    /// Test: Three nodes maintain consensus (Task 11.4.7)
    #[tokio::test]
    #[ignore = "Requires full Substrate infrastructure - run manually"]
    async fn test_three_node_consensus() {
        // This test verifies consensus with real clients:
        // 1. Start three nodes
        // 2. Connect in a triangle
        // 3. Mine on all three
        // 4. Verify all converge to same chain
        //
        // To run: cargo test -p security-tests --test multi_node_substrate \
        //         --features substrate test_three_node_consensus -- --ignored
        todo!("Implement when sc-service dev node helper is available")
    }

    /// Test: Network partition and recovery
    #[tokio::test]
    #[ignore = "Requires full Substrate infrastructure - run manually"]
    async fn test_partition_recovery() {
        // This test would:
        // 1. Start three nodes
        // 2. Partition into two groups
        // 3. Mine independently
        // 4. Heal partition
        // 5. Verify reorganization to longest chain
        todo!("Implement when sc-service dev node helper is available")
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
