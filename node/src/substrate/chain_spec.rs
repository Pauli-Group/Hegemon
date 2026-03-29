//! Hegemon Chain Specification
//!
//! ONE chain spec. Difficulty retargeting handles hashrate differences.

use runtime::manifest;
use runtime::WASM_BINARY;
use sc_service::ChainType;

const DEFAULT_DA_CHUNK_SIZE: u32 = 65536;
const DEFAULT_DA_SAMPLE_COUNT: u32 = 80;

/// Specialized `ChainSpec` for the Hegemon runtime.
pub type ChainSpec = sc_service::GenericChainSpec;

/// The ONE chain configuration.
///
/// GENESIS_DIFFICULTY = 500,000 for 5-second blocks at ~100 kH/s
/// Retargeting adjusts automatically based on actual hashrate.
pub fn chain_spec() -> Result<ChainSpec, String> {
    let wasm_binary = WASM_BINARY.ok_or("WASM binary not available")?;
    let protocol_manifest = manifest::protocol_manifest();

    let mut properties = sc_chain_spec::Properties::new();
    properties.insert("tokenSymbol".into(), "HGM".into());
    properties.insert("tokenDecimals".into(), 12.into());
    properties.insert("ss58Format".into(), 42.into());
    properties.insert("daChunkSize".into(), DEFAULT_DA_CHUNK_SIZE.into());
    properties.insert("daSampleCount".into(), DEFAULT_DA_SAMPLE_COUNT.into());

    let verifying_key = manifest::shielded_verifying_key();
    let verifying_key_value = serde_json::to_value(&verifying_key)
        .map_err(|e| format!("Failed to serialize shielded verifying key: {e}"))?;

    let genesis_config = serde_json::json!({
        "system": {},
        "difficulty": {
            // GENESIS_BITS = 0x1d1ad7f2 encodes target = MAX_U256 / 160,000,000
            // For 5-second blocks at ~32 MH/s (4 threads on M-series MacBook)
            "initialDifficulty": "0x9896800",
            "initialBits": 0x1d1a_d7f2_u32
        },
        "kernel": {
            "familyRoots": manifest::kernel_family_roots()
        },
        "shieldedPool": {
            "verifyingKey": verifying_key_value,
            "daPolicy": protocol_manifest.da_policy,
            "ciphertextPolicy": protocol_manifest.ciphertext_policy,
            "proofAvailabilityPolicy": protocol_manifest.proof_availability_policy
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

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Decode;
    use pallet_shielded_pool::verifier::VerifyingKey;
    use sp_core::twox_128;
    use std::collections::BTreeMap;
    use std::fs;

    fn shielded_vk_storage_key() -> String {
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(&twox_128(b"ShieldedPool"));
        key.extend_from_slice(&twox_128(b"VerifyingKeyStorage"));
        format!("0x{}", hex::encode(key))
    }

    #[test]
    fn chain_spec_works() {
        if WASM_BINARY.is_some() {
            assert!(chain_spec().is_ok());
        } else {
            assert!(chain_spec().is_err());
        }
    }

    #[test]
    fn dev_chainspec_json_shielded_vk_matches_runtime_manifest() {
        let chainspec_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/dev-chainspec.json");
        let json = fs::read_to_string(&chainspec_path).expect("read config/dev-chainspec.json");
        let spec: serde_json::Value =
            serde_json::from_str(&json).expect("parse config/dev-chainspec.json");

        let top: BTreeMap<String, String> = serde_json::from_value(
            spec.get("genesis")
                .and_then(|genesis| genesis.get("raw"))
                .and_then(|raw| raw.get("top"))
                .cloned()
                .expect("chainspec raw top map"),
        )
        .expect("decode raw top map");

        let encoded = top
            .get(&shielded_vk_storage_key())
            .expect("shielded verifying key storage entry present");
        let encoded = hex::decode(encoded.trim_start_matches("0x"))
            .expect("decode verifying key storage value");
        let json_vk =
            VerifyingKey::decode(&mut encoded.as_slice()).expect("decode verifying key storage");
        let runtime_vk = runtime::manifest::shielded_verifying_key();

        assert_eq!(
            json_vk, runtime_vk,
            "config/dev-chainspec.json carries a stale shielded verifying key"
        );
    }
}
