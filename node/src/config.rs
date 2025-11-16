use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crypto::ml_dsa::MlDsaSecretKey;
use crypto::traits::SigningKey;
use network::GossipRouter;
use protocol_versioning::{DEFAULT_VERSION_BINDING, VersionBinding};
use serde::{Deserialize, Serialize};

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
    pub pow_bits: u32,
    pub gossip_buffer: usize,
    pub supported_versions: Vec<VersionBinding>,
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
            api_token: "local-dev-token".to_string(),
            note_tree_depth: 32,
            mempool_max_txs: 1024,
            template_tx_limit: 512,
            miner_workers: 2,
            miner_seed: [7u8; 32],
            pow_bits: 0x2100ffff,
            gossip_buffer: 1024,
            supported_versions: vec![DEFAULT_VERSION_BINDING],
        }
    }
}
