use sp_core::H256;

use crate::{
    AccountId, Balance, BalancesConfig, DifficultyConfig, DummySessionKeys, PowDifficulty,
    RuntimeGenesisConfig, SessionConfig, SudoConfig, SystemConfig,
};

/// Structured chain spec describing PoW parameters, telemetry defaults, and genesis state.
pub struct ChainSpec {
    pub name: &'static str,
    pub id: &'static str,
    pub bootnodes: Vec<String>,
    pub telemetry_endpoints: Vec<String>,
    pub pow_bits: u32,
    pub genesis: RuntimeGenesisConfig,
}

fn account(seed: u8) -> AccountId {
    AccountId::new([seed; 32])
}

fn base_genesis(endowed: &[(AccountId, Balance)], sudo: AccountId) -> RuntimeGenesisConfig {
    let validators: Vec<AccountId> = endowed.iter().map(|(account, _)| account.clone()).collect();
    RuntimeGenesisConfig {
        system: SystemConfig::default(),
        balances: BalancesConfig {
            balances: endowed.to_vec(),
            dev_accounts: None,
        },
        sudo: SudoConfig { key: Some(sudo) },
        session: SessionConfig {
            non_authority_keys: Vec::new(),
            keys: validators
                .iter()
                .map(|validator| (validator.clone(), validator.clone(), DummySessionKeys))
                .collect(),
        },
        difficulty: DifficultyConfig::default(),
    }
}

pub fn development_config() -> ChainSpec {
    let sudo = account(1);
    let endowed = vec![
        (sudo.clone(), 1_000_000_000_000),
        (account(2), 500_000_000_000),
    ];
    ChainSpec {
        name: "hegemon-devnet-pow",
        id: "hegemon-devnet-pow",
        bootnodes: Vec::new(),
        telemetry_endpoints: vec!["wss://telemetry.dev.hegemon.invalid/submit".into()],
        pow_bits: PowDifficulty::get(),
        genesis: base_genesis(&endowed, sudo),
    }
}

pub fn testnet_config() -> ChainSpec {
    let sudo = account(42);
    let endowed = vec![
        (sudo.clone(), 5_000_000_000_000),
        (account(43), 2_000_000_000_000),
        (account(44), 2_000_000_000_000),
    ];
    ChainSpec {
        name: "hegemon-testnet-pow",
        id: "hegemon-testnet-pow",
        bootnodes: vec![
            "/dns4/seed1.testnet.hegemon.invalid/tcp/30333/p2p/12D3KooWTestnetSeed1".into(),
            "/dns4/seed2.testnet.hegemon.invalid/tcp/30333/p2p/12D3KooWTestnetSeed2".into(),
        ],
        telemetry_endpoints: vec!["wss://telemetry.testnet.hegemon.invalid/submit".into()],
        pow_bits: PowDifficulty::get(),
        genesis: base_genesis(&endowed, sudo),
    }
}

/// Utility for tests to produce repeatable PoW pre-hashes.
pub fn genesis_pre_hash() -> H256 {
    H256::repeat_byte(7)
}
