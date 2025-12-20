//! Hegemon Chain Specification
//!
//! ONE chain spec. Difficulty retargeting handles hashrate differences.

use runtime::WASM_BINARY;
use sc_service::ChainType;

/// Specialized `ChainSpec` for the Hegemon runtime.
pub type ChainSpec = sc_service::GenericChainSpec;

/// The ONE chain configuration.
///
/// GENESIS_DIFFICULTY = 500,000 for 5-second blocks at ~100 kH/s
/// Retargeting adjusts automatically based on actual hashrate.
pub fn chain_spec() -> Result<ChainSpec, String> {
    let wasm_binary = WASM_BINARY.ok_or("WASM binary not available")?;

    let mut properties = sc_chain_spec::Properties::new();
    properties.insert("tokenSymbol".into(), "HGM".into());
    properties.insert("tokenDecimals".into(), 12.into());
    properties.insert("ss58Format".into(), 42.into());

    let genesis_config = serde_json::json!({
        "system": {},
        "balances": {
            // No pre-mine. All issuance from mining rewards only.
            "balances": [],
            "devAccounts": null
        },
        "sudo": {
            "key": null
        },
        "session": {
            "keys": [],
            "nonAuthorityKeys": []
        },
        "difficulty": {
            // GENESIS_BITS = 0x1d1ad7f2 encodes target = MAX_U256 / 160,000,000
            // For 5-second blocks at ~32 MH/s (4 threads on M-series MacBook)
            "initialDifficulty": "0x9896800",
            "initialBits": 0x1d1a_d7f2_u32
        },
        "shieldedPool": {
            "verifyingKey": null
        }
    });

    Ok(ChainSpec::builder(wasm_binary, None)
        .with_name("Hegemon")
        .with_id("hegemon")
        .with_chain_type(ChainType::Live)
        .with_properties(properties)
        .with_genesis_config(genesis_config)
        .build())
}

// Keep old names as aliases for compatibility
pub fn development_config() -> Result<ChainSpec, String> {
    chain_spec()
}
pub fn local_testnet_config() -> Result<ChainSpec, String> {
    chain_spec()
}
pub fn testnet_config() -> Result<ChainSpec, String> {
    chain_spec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_spec_works() {
        assert!(chain_spec().is_ok());
    }
}
