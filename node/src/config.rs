use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use crypto::ml_dsa::MlDsaSecretKey;
use crypto::traits::SigningKey;
use network::{GossipRouter, NatTraversalConfig, RelayConfig};
use protocol_versioning::{VersionBinding, DEFAULT_VERSION_BINDING};
use serde::{Deserialize, Serialize};
use wallet::address::ShieldedAddress;
use wallet::keys::RootSecret;

use crate::chain_spec::ChainProfile;
use crate::error::NodeError;
use crate::telemetry::TelemetryPosture;

const DEFAULT_API_TOKEN: &str = "devnet-token";
const DEFAULT_MINER_SEED: [u8; 32] = [7u8; 32];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub db_path: PathBuf,
    pub peer_store_path: PathBuf,
    pub api_addr: SocketAddr,
    pub api_token: String,
    pub note_tree_depth: usize,
    pub mempool_max_txs: usize,
    pub template_tx_limit: usize,
    pub miner_workers: usize,
    pub miner_seed: [u8; 32],
    pub miner_payout_address: ShieldedAddress,
    pub pow_bits: u32,
    pub chain_profile: ChainProfile,
    pub gossip_buffer: usize,
    pub min_tx_fee_per_weight: u64,
    pub max_block_weight: u64,
    pub mempool_max_weight: u64,
    pub supported_versions: Vec<VersionBinding>,
    pub p2p_addr: SocketAddr,
    pub seeds: Vec<String>,
    pub imported_peers: Vec<String>,
    pub max_peers: usize,
    pub nat_traversal: bool,
    pub relay: RelayConfig,
    pub telemetry: TelemetryPosture,
}

impl NodeConfig {
    pub fn with_db_path(path: impl AsRef<Path>) -> Self {
        let mut config = Self::default();
        config.apply_db_path(path);
        config
    }

    pub fn apply_db_path(&mut self, path: impl AsRef<Path>) {
        let db_path = path.as_ref().to_path_buf();
        self.db_path = db_path.clone();
        self.peer_store_path = db_path.with_extension("peers");
    }

    pub fn miner_secret(&self) -> MlDsaSecretKey {
        MlDsaSecretKey::generate_deterministic(&self.miner_seed)
    }

    pub fn gossip_router(&self) -> GossipRouter {
        GossipRouter::new(self.gossip_buffer)
    }

    pub fn nat_config(&self) -> NatTraversalConfig {
        if self.nat_traversal {
            NatTraversalConfig::for_listener(self.p2p_addr)
        } else {
            NatTraversalConfig::disabled(self.p2p_addr)
        }
    }

    pub fn validate(&self) -> Result<(), NodeError> {
        if self.chain_profile != ChainProfile::Dev {
            if self.api_token == DEFAULT_API_TOKEN {
                return Err(NodeError::InvalidInput(
                    "api_token must be set to a non-default value for non-dev profiles".into(),
                ));
            }
            if self.miner_seed == DEFAULT_MINER_SEED {
                return Err(NodeError::InvalidInput(
                    "miner_seed must be set to a non-default value for non-dev profiles".into(),
                ));
            }
        }
        Ok(())
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("node.db"),
            peer_store_path: PathBuf::from("node.db.peers"),
            api_addr: "127.0.0.1:8080".parse().expect("loopback socket"),
            api_token: DEFAULT_API_TOKEN.to_string(),
            note_tree_depth: 32,
            mempool_max_txs: 1024,
            template_tx_limit: 512,
            miner_workers: 2,
            miner_seed: DEFAULT_MINER_SEED,
            miner_payout_address: default_payout_address(DEFAULT_MINER_SEED),
            pow_bits: DEFAULT_GENESIS_POW_BITS,
            chain_profile: ChainProfile::Dev,
            gossip_buffer: 1024,
            min_tx_fee_per_weight: 25,
            max_block_weight: 1_000_000,
            mempool_max_weight: 4_000_000,
            supported_versions: vec![DEFAULT_VERSION_BINDING],
            p2p_addr: "0.0.0.0:9000".parse().expect("p2p socket"),
            seeds: vec![],
            imported_peers: vec![],
            max_peers: 64,
            nat_traversal: true,
            relay: RelayConfig::default(),
            telemetry: TelemetryPosture::default(),
        }
    }
}

pub fn default_payout_address(seed: [u8; 32]) -> ShieldedAddress {
    let keys = RootSecret::from_bytes(seed).derive();
    keys.address(0)
        .expect("address derivation should succeed")
        .shielded_address()
}
