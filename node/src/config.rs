use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use crypto::ml_dsa::MlDsaSecretKey;
use crypto::traits::SigningKey;
use network::GossipRouter;
use protocol_versioning::{DEFAULT_VERSION_BINDING, VersionBinding};
use serde::{Deserialize, Serialize};
use wallet::address::ShieldedAddress;
use wallet::keys::RootSecret;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub db_path: PathBuf,
    pub api_addr: SocketAddr,
    pub api_token: String,
    pub note_tree_depth: usize,
    pub mempool_max_txs: usize,
    pub template_tx_limit: usize,
    pub miner_workers: usize,
    pub miner_seed: [u8; 32],
    pub miner_payout_address: ShieldedAddress,
    pub pow_bits: u32,
    pub gossip_buffer: usize,
    pub supported_versions: Vec<VersionBinding>,
    pub p2p_addr: SocketAddr,
    pub seeds: Vec<String>,
}

impl NodeConfig {
    pub fn with_db_path(path: impl AsRef<Path>) -> Self {
        let db_path = path.as_ref().to_path_buf();
        Self {
            db_path,
            ..Self::default()
        }
    }

    pub fn miner_secret(&self) -> MlDsaSecretKey {
        MlDsaSecretKey::generate_deterministic(&self.miner_seed)
    }

    pub fn gossip_router(&self) -> GossipRouter {
        GossipRouter::new(self.gossip_buffer)
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("node.db"),
            api_addr: "127.0.0.1:8080".parse().expect("loopback socket"),
            api_token: "devnet-token".to_string(),
            note_tree_depth: 32,
            mempool_max_txs: 1024,
            template_tx_limit: 512,
            miner_workers: 2,
            miner_seed: [7u8; 32],
            miner_payout_address: default_payout_address([7u8; 32]),
            pow_bits: DEFAULT_GENESIS_POW_BITS,
            gossip_buffer: 1024,
            supported_versions: vec![DEFAULT_VERSION_BINDING],
            p2p_addr: "0.0.0.0:9000".parse().expect("p2p socket"),
            seeds: vec![],
        }
    }
}

pub fn default_payout_address(seed: [u8; 32]) -> ShieldedAddress {
    let keys = RootSecret::from_bytes(seed).derive();
    keys.address(0)
        .expect("address derivation should succeed")
        .shielded_address()
}
