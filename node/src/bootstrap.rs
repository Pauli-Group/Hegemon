use std::fs::File;
use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::chain_spec::ChainProfile;
use crate::codec::{deserialize_block, serialize_block};
use crate::config::NodeConfig;
use crate::error::{NodeError, NodeResult};
use crate::storage::Storage;
use network::{PeerStore, PeerStoreConfig};

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerBundle {
    pub chain: ChainProfile,
    pub pow_bits: u32,
    #[serde(with = "serde_bytes")]
    pub genesis_block: Option<ByteBuf>,
    pub peers: Vec<String>,
}

impl PeerBundle {
    pub fn capture(config: &NodeConfig) -> NodeResult<Self> {
        let storage = Storage::open(&config.db_path)?;
        let genesis_block = load_genesis_block(&storage)?;

        let mut peer_store = PeerStore::new(PeerStoreConfig::with_path(&config.peer_store_path));
        peer_store.load()?;
        let peers = peer_store
            .addresses()
            .into_iter()
            .map(|addr| addr.to_string())
            .collect();

        Ok(Self {
            chain: config.chain_profile,
            pow_bits: config.pow_bits,
            genesis_block: genesis_block.map(ByteBuf::from),
            peers,
        })
    }

    pub fn save(&self, path: impl AsRef<Path>) -> NodeResult<()> {
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> NodeResult<Self> {
        let file = File::open(path)?;
        Ok(serde_json::from_reader(file)?)
    }

    pub fn peer_addresses(&self) -> NodeResult<Vec<SocketAddr>> {
        let mut addrs = Vec::new();
        for peer in &self.peers {
            let addr = peer
                .parse()
                .map_err(|err| NodeError::InvalidInput(format!("invalid peer '{peer}': {err}")))?;
            addrs.push(addr);
        }
        Ok(addrs)
    }

    pub fn genesis_block(&self) -> NodeResult<Option<consensus::types::ConsensusBlock>> {
        match &self.genesis_block {
            Some(bytes) => Ok(Some(deserialize_block(bytes)?)),
            None => Ok(None),
        }
    }
}

fn load_genesis_block(storage: &Storage) -> NodeResult<Option<Vec<u8>>> {
    let mut blocks = storage.load_blocks()?;
    blocks.sort_by_key(|block| block.header.height);
    let maybe_genesis = blocks.into_iter().find(|block| block.header.height == 0);

    Ok(match maybe_genesis {
        Some(block) => Some(serialize_block(&block)?),
        None => None,
    })
}

pub fn persist_imported_peers(
    bundle: &PeerBundle,
    config: &NodeConfig,
) -> NodeResult<Vec<SocketAddr>> {
    if bundle.chain != config.chain_profile {
        return Err(NodeError::InvalidInput(format!(
            "bundle chain {:?} does not match configured chain {:?}",
            bundle.chain, config.chain_profile
        )));
    }

    if bundle.pow_bits != config.pow_bits {
        return Err(NodeError::InvalidInput(format!(
            "bundle pow bits {} do not match configured pow bits {}",
            bundle.pow_bits, config.pow_bits
        )));
    }

    let peers = bundle.peer_addresses()?;
    let mut peer_store = PeerStore::new(PeerStoreConfig::with_path(&config.peer_store_path));
    peer_store.load()?;
    peer_store.record_learned(peers.clone())?;

    Ok(peers)
}
