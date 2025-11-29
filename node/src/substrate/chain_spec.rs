//! Hegemon Substrate Chain Specification
//!
//! This module defines the chain specifications for different network
//! configurations: development, local testnet, and public testnet.
//!
//! # Phase 11 Status
//!
//! Now using real WASM binary and genesis configuration.

use runtime::WASM_BINARY;
use sc_service::ChainType;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Specialized `ChainSpec` for the Hegemon runtime.
pub type ChainSpec = sc_service::GenericChainSpec;

/// Chain spec extensions for Hegemon (placeholder).
///
/// In full implementation, this derives ChainSpecGroup and ChainSpecExtension.
/// These extensions configure PoW-specific parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Extensions {
    /// The PoW difficulty bits for this chain.
    pub pow_bits: u32,
    /// Whether this chain requires PQ-secure connections.
    pub require_pq: bool,
}

/// Development chain configuration.
///
/// This configuration is intended for local development with a single node.
/// Uses easy PoW difficulty and pre-funded development accounts.
pub fn development_config() -> Result<ChainSpec, String> {
    let wasm_binary = WASM_BINARY.ok_or("Development WASM binary not available")?;

    let mut properties = sc_chain_spec::Properties::new();
    properties.insert("tokenSymbol".into(), "HGM".into());
    properties.insert("tokenDecimals".into(), 12.into());
    properties.insert("ss58Format".into(), 42.into());

    // Development genesis with pre-funded accounts
    // Uses very easy difficulty for fast mining during development
    // Only includes pallets that have genesis config
    let genesis_config = json!({
        "system": {},
        "balances": {
            "balances": [
                // Alice (development key)
                ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", 1_000_000_000_000_000_000_000_u128],
                // Bob (development key)
                ["5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty", 500_000_000_000_000_000_000_u128]
            ],
            "devAccounts": null
        },
        "sudo": {
            "key": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        },
        "session": {
            "keys": [],
            "nonAuthorityKeys": []
        },
        "difficulty": {
            // Low difficulty for development (fast but not instant mining)
            // initial_bits=0x2000ffff corresponds to difficulty=256 (2^8)
            "initialDifficulty": "0x100",
            "initialBits": 0x2000ffff_u32
        },
        "shieldedPool": {
            "verifyingKey": null
        }
    });

    Ok(ChainSpec::builder(wasm_binary, None)
        .with_name("Hegemon Development")
        .with_id("hegemon_dev")
        .with_chain_type(ChainType::Development)
        .with_properties(properties)
        .with_genesis_config(genesis_config)
        .build())
}

/// Local testnet chain configuration.
///
/// This configuration is intended for multi-node local testing.
pub fn local_testnet_config() -> Result<ChainSpec, String> {
    let wasm_binary = WASM_BINARY.ok_or("Local testnet WASM binary not available")?;

    let mut properties = sc_chain_spec::Properties::new();
    properties.insert("tokenSymbol".into(), "HGM".into());
    properties.insert("tokenDecimals".into(), 12.into());
    properties.insert("ss58Format".into(), 42.into());

    let genesis_config = json!({
        "system": {},
        "balances": {
            "balances": [
                ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", 1_000_000_000_000_000_000_000_u128],
                ["5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty", 500_000_000_000_000_000_000_u128]
            ],
            "devAccounts": null
        },
        "sudo": {
            "key": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        },
        "session": {
            "keys": [],
            "nonAuthorityKeys": []
        },
        "difficulty": {
            // Low difficulty for local testing (easy mining)
            // initial_bits=0x207fffff corresponds to difficulty=2 (easiest)
            "initialDifficulty": "0x2",
            "initialBits": 0x207fffff_u32
        },
        "shieldedPool": {
            "verifyingKey": null
        }
    });

    Ok(ChainSpec::builder(wasm_binary, None)
        .with_name("Hegemon Local Testnet")
        .with_id("hegemon_local")
        .with_chain_type(ChainType::Local)
        .with_properties(properties)
        .with_genesis_config(genesis_config)
        .build())
}

/// Public testnet chain configuration.
///
/// This configuration is for the public testnet deployment.
pub fn testnet_config() -> Result<ChainSpec, String> {
    let wasm_binary = WASM_BINARY.ok_or("Testnet WASM binary not available")?;

    let mut properties = sc_chain_spec::Properties::new();
    properties.insert("tokenSymbol".into(), "HGM".into());
    properties.insert("tokenDecimals".into(), 12.into());
    properties.insert("ss58Format".into(), 42.into());

    let genesis_config = json!({
        "system": {},
        "balances": {
            "balances": [
                // Sudo account for testnet
                ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", 5_000_000_000_000_000_000_000_u128]
            ],
            "devAccounts": null
        },
        "sudo": {
            "key": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        },
        "session": {
            "keys": [],
            "nonAuthorityKeys": []
        },
        "difficulty": {
            // Medium difficulty for public testnet
            // initial_bits=0x1e00ffff corresponds to difficulty=0x1000100
            "initialDifficulty": "0x1000100",
            "initialBits": 0x1e00ffff_u32
        },
        "shieldedPool": {
            "verifyingKey": null
        }
    });

    Ok(ChainSpec::builder(wasm_binary, None)
        .with_name("Hegemon Testnet")
        .with_id("hegemon_testnet")
        .with_chain_type(ChainType::Live)
        .with_properties(properties)
        .with_genesis_config(genesis_config)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_config_works() {
        assert!(development_config().is_ok());
    }

    #[test]
    fn local_testnet_config_works() {
        assert!(local_testnet_config().is_ok());
    }

    #[test]
    fn testnet_config_works() {
        assert!(testnet_config().is_ok());
    }
}
