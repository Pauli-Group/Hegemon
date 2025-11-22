use clap::ValueEnum;
use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use serde::{Deserialize, Serialize};

use crate::config::NodeConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ChainProfile {
    Dev,
    Testnet,
}

#[derive(Clone, Debug)]
pub struct ChainSpec {
    pub name: &'static str,
    pub consensus: &'static str,
    pub pow_bits: u32,
    pub bootnodes: Vec<String>,
    pub min_fee_per_weight: u64,
    pub max_block_weight: u64,
    pub mempool_max_weight: u64,
    pub template_tx_limit: usize,
}

pub fn chain_spec(profile: ChainProfile) -> ChainSpec {
    match profile {
        ChainProfile::Dev => ChainSpec {
            name: "hegemon-devnet",
            consensus: "pow-equihash-like",
            pow_bits: DEFAULT_GENESIS_POW_BITS.saturating_sub(4),
            bootnodes: Vec::new(),
            min_fee_per_weight: 5,
            max_block_weight: 750_000,
            mempool_max_weight: 3_000_000,
            template_tx_limit: 256,
        },
        ChainProfile::Testnet => ChainSpec {
            name: "hegemon-testnet",
            consensus: "pow-equihash-like",
            pow_bits: DEFAULT_GENESIS_POW_BITS,
            bootnodes: vec![
                "seed1.testnet.hegemon.invalid:9000".into(),
                "seed2.testnet.hegemon.invalid:9000".into(),
            ],
            min_fee_per_weight: 25,
            max_block_weight: 1_000_000,
            mempool_max_weight: 4_000_000,
            template_tx_limit: 512,
        },
    }
}

impl ChainSpec {
    pub fn apply_to_config(&self, config: &mut NodeConfig) {
        config.pow_bits = self.pow_bits;
        if config.seeds.is_empty() {
            config.seeds = self.bootnodes.clone();
        }
        config.min_tx_fee_per_weight = self.min_fee_per_weight;
        config.max_block_weight = self.max_block_weight;
        config.mempool_max_weight = self.mempool_max_weight;
        config.template_tx_limit = self.template_tx_limit;
    }
}
