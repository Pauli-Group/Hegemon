use sp_core::H256;

use crate::{
    AccountId, Balance, BalancesConfig, DifficultyConfig, PowDifficulty, RuntimeGenesisConfig,
    ShieldedPoolConfig, SystemConfig,
};
use pallet_shielded_pool::verifier::StarkVerifier;

/// Structured chain spec describing PoW parameters, telemetry defaults, and genesis state.
pub struct ChainSpec {
    pub name: &'static str,
    pub id: &'static str,
    pub bootnodes: Vec<String>,
    pub telemetry_endpoints: Vec<String>,
    pub pow_bits: u32,
    pub da_chunk_size: u32,
    pub da_sample_count: u32,
    pub genesis: RuntimeGenesisConfig,
}

const DEFAULT_DA_CHUNK_SIZE: u32 = 65536;
const DEFAULT_DA_SAMPLE_COUNT: u32 = 80;

fn base_genesis(endowed: &[(AccountId, Balance)]) -> RuntimeGenesisConfig {
    RuntimeGenesisConfig {
        system: SystemConfig::default(),
        balances: BalancesConfig {
            balances: endowed.to_vec(),
            dev_accounts: None,
        },
        difficulty: DifficultyConfig::default(),
        shielded_pool: ShieldedPoolConfig {
            verifying_key: Some(StarkVerifier::create_verifying_key(0)),
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn development_config() -> ChainSpec {
    // No pre-mine. All issuance from mining rewards only.
    let endowed: Vec<(AccountId, Balance)> = vec![];
    ChainSpec {
        name: "hegemon-devnet-pow",
        id: "hegemon-devnet-pow",
        bootnodes: Vec::new(),
        telemetry_endpoints: vec!["wss://telemetry.dev.hegemon.invalid/submit".into()],
        pow_bits: PowDifficulty::get(),
        da_chunk_size: DEFAULT_DA_CHUNK_SIZE,
        da_sample_count: DEFAULT_DA_SAMPLE_COUNT,
        genesis: base_genesis(&endowed),
    }
}

pub fn testnet_config() -> ChainSpec {
    // No pre-mine. All issuance from mining rewards only.
    let endowed: Vec<(AccountId, Balance)> = vec![];
    ChainSpec {
        name: "hegemon-testnet-pow",
        id: "hegemon-testnet-pow",
        bootnodes: vec![
            "/dns4/seed1.testnet.hegemon.invalid/tcp/30333/p2p/12D3KooWTestnetSeed1".into(),
            "/dns4/seed2.testnet.hegemon.invalid/tcp/30333/p2p/12D3KooWTestnetSeed2".into(),
        ],
        telemetry_endpoints: vec!["wss://telemetry.testnet.hegemon.invalid/submit".into()],
        pow_bits: PowDifficulty::get(),
        da_chunk_size: DEFAULT_DA_CHUNK_SIZE,
        da_sample_count: DEFAULT_DA_SAMPLE_COUNT,
        genesis: base_genesis(&endowed),
    }
}

/// Utility for tests to produce repeatable PoW pre-hashes.
pub fn genesis_pre_hash() -> H256 {
    H256::repeat_byte(7)
}
