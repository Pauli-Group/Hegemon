use std::collections::HashMap;
use std::path::{Path, PathBuf};

use consensus::types::ConsensusBlock;
use once_cell::sync::Lazy;
use parking_lot::Mutex;

use crate::error::NodeResult;

#[derive(Clone, Debug, Default)]
pub struct StorageMeta {
    pub height: u64,
    pub best_hash: [u8; 32],
    pub supply_digest: u128,
}

#[derive(Clone, Default)]
pub(crate) struct StorageState {
    pub blocks: Vec<ConsensusBlock>,
    pub meta: Option<StorageMeta>,
}

static STORAGE_STATE: Lazy<Mutex<HashMap<PathBuf, StorageState>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub struct Storage {
    path: PathBuf,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> NodeResult<Self> {
        Ok(Self {
            path: path.as_ref().to_path_buf(),
        })
    }

    pub fn load_blocks(&self) -> NodeResult<Vec<ConsensusBlock>> {
        Ok(STORAGE_STATE
            .lock()
            .get(&self.path)
            .map(|state| state.blocks.clone())
            .unwrap_or_default())
    }

    pub fn load_meta(&self) -> NodeResult<Option<StorageMeta>> {
        Ok(STORAGE_STATE
            .lock()
            .get(&self.path)
            .and_then(|state| state.meta.clone()))
    }

    pub fn close(&self) -> NodeResult<()> {
        Ok(())
    }
}

pub(crate) fn load_state(path: &Path) -> StorageState {
    STORAGE_STATE.lock().get(path).cloned().unwrap_or_default()
}

pub(crate) fn store_state(path: &Path, state: StorageState) {
    STORAGE_STATE.lock().insert(path.to_path_buf(), state);
}
