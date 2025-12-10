use clap::ValueEnum;
use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use serde::{Deserialize, Serialize};

use crate::config::NodeConfig;
use crate::telemetry::TelemetryPosture;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ChainProfile {
    Dev,
    Testnet,
}

/// Network profile tuned for PQ signing defaults (ML-DSA pk = 1,952 B, sig = 3,293 B)
/// and the SS58 prefix used by the runtime's AccountId32 derivation from PQ public keys.
///
/// NOTE: This chain uses PQ-Noise networking exclusively. There is NO libp2p.
/// Seed nodes are specified as IP:port (e.g., "127.0.0.1:30333") NOT multiaddrs.
/// Use HEGEMON_SEEDS environment variable for runtime seed configuration.
#[derive(Clone, Debug)]
pub struct ChainSpec {
    pub name: &'static str,
    pub consensus: &'static str,
    pub pow_bits: u32,
    /// PQ network seed nodes in IP:PORT format (NOT libp2p multiaddr!)
    pub pq_seeds: Vec<String>,
    pub min_fee_per_weight: u64,
    pub max_block_weight: u64,
    pub mempool_max_weight: u64,
    pub template_tx_limit: usize,
    pub telemetry: TelemetryPosture,
}

pub fn chain_spec(profile: ChainProfile) -> ChainSpec {
    match profile {
        ChainProfile::Dev => ChainSpec {
            name: "hegemon-devnet",
            consensus: "pow-equihash-like",
            pow_bits: DEFAULT_GENESIS_POW_BITS.saturating_sub(4),
            pq_seeds: Vec::new(), // Dev mode: no seeds, use HEGEMON_SEEDS env var
            min_fee_per_weight: 5,
            max_block_weight: 750_000,
            mempool_max_weight: 3_000_000,
            template_tx_limit: 256,
            telemetry: TelemetryPosture {
                tls_enabled: Some(false),
                exposure_scope: Some("devnet".into()),
                ..Default::default()
            },
        },
        ChainProfile::Testnet => ChainSpec {
            name: "hegemon-testnet",
            consensus: "pow-equihash-like",
            pow_bits: DEFAULT_GENESIS_POW_BITS,
            // PQ seed format: IP:PORT (NOT libp2p multiaddr!)
            pq_seeds: vec![
                "seed1.testnet.hegemon.invalid:30333".into(),
                "seed2.testnet.hegemon.invalid:30333".into(),
            ],
            min_fee_per_weight: 25,
            max_block_weight: 1_000_000,
            mempool_max_weight: 4_000_000,
            template_tx_limit: 512,
            telemetry: TelemetryPosture {
                tls_enabled: Some(true),
                exposure_scope: Some("testnet".into()),
                ..Default::default()
            },
        },
    }
}

impl ChainSpec {
    pub fn apply_to_config(&self, config: &mut NodeConfig) {
        config.pow_bits = self.pow_bits;
        if config.seeds.is_empty() {
            config.seeds = self.pq_seeds.clone();
        }
        config.min_tx_fee_per_weight = self.min_fee_per_weight;
        config.max_block_weight = self.max_block_weight;
        config.mempool_max_weight = self.mempool_max_weight;
        config.template_tx_limit = self.template_tx_limit;
        config.telemetry = self.telemetry.clone();
    }
}
