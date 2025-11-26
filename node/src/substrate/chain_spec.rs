//! Hegemon Substrate Chain Specification
//!
//! This module defines the chain specifications for different network
//! configurations: development, local testnet, and public testnet.
//!
//! # Phase 1 Status
//!
//! This is a scaffold. Full chain spec configuration requires:
//! - WASM binary from substrate-wasm-builder
//! - Aligned runtime types with sc-chain-spec
//! - Full genesis state configuration

use sc_service::ChainType;
use serde::{Deserialize, Serialize};

/// Specialized `ChainSpec` for the Hegemon runtime.
///
/// In full implementation, this will use:
/// ```ignore
/// sc_service::GenericChainSpec<Extensions>
/// ```
/// For now, we use a simple JSON-based chain spec.
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
    // Phase 1: Create minimal chain spec without WASM binary
    // In Phase 2+, this will use runtime::WASM_BINARY

    let mut properties = sc_chain_spec::Properties::new();
    properties.insert("tokenSymbol".into(), "HGM".into());
    properties.insert("tokenDecimals".into(), 12.into());
    properties.insert("ss58Format".into(), 42.into());

    Ok(ChainSpec::builder(&[], None)
        .with_name("Hegemon Development")
        .with_id("hegemon_dev")
        .with_chain_type(ChainType::Development)
        .with_properties(properties)
        .build())
}

/// Local testnet chain configuration.
///
/// This configuration is intended for multi-node local testing.
pub fn local_testnet_config() -> Result<ChainSpec, String> {
    let mut properties = sc_chain_spec::Properties::new();
    properties.insert("tokenSymbol".into(), "HGM".into());
    properties.insert("tokenDecimals".into(), 12.into());
    properties.insert("ss58Format".into(), 42.into());

    Ok(ChainSpec::builder(&[], None)
        .with_name("Hegemon Local Testnet")
        .with_id("hegemon_local")
        .with_chain_type(ChainType::Local)
        .with_properties(properties)
        .build())
}

/// Public testnet chain configuration.
///
/// This configuration is for the public testnet deployment.
pub fn testnet_config() -> Result<ChainSpec, String> {
    let mut properties = sc_chain_spec::Properties::new();
    properties.insert("tokenSymbol".into(), "HGM".into());
    properties.insert("tokenDecimals".into(), 12.into());
    properties.insert("ss58Format".into(), 42.into());

    Ok(ChainSpec::builder(&[], None)
        .with_name("Hegemon Testnet")
        .with_id("hegemon_testnet")
        .with_chain_type(ChainType::Live)
        .with_properties(properties)
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
