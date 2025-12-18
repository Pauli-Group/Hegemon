use crate::substrate::network_bridge::RecursiveEpochProofMessage;
use codec::{Decode, Encode};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const EPOCH_PROOF_FILE_PREFIX: &str = "epoch-";
const EPOCH_PROOF_FILE_EXTENSION: &str = "scale";

#[derive(Debug)]
pub struct RecursiveEpochProofStore {
    dir: PathBuf,
    proofs: BTreeMap<u64, RecursiveEpochProofMessage>,
}

impl RecursiveEpochProofStore {
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        let mut store = Self {
            dir,
            proofs: BTreeMap::new(),
        };
        store.load_from_dir()?;
        Ok(store)
    }

    pub fn empty(dir: PathBuf) -> Self {
        Self {
            dir,
            proofs: BTreeMap::new(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    pub fn latest(&self) -> Option<&RecursiveEpochProofMessage> {
        self.proofs.last_key_value().map(|(_, msg)| msg)
    }

    pub fn epochs(&self) -> Vec<u64> {
        self.proofs.keys().copied().collect()
    }

    pub fn get(&self, epoch_number: u64) -> Option<&RecursiveEpochProofMessage> {
        self.proofs.get(&epoch_number)
    }

    pub fn insert(&mut self, msg: RecursiveEpochProofMessage) -> InsertOutcome {
        match self.proofs.get(&msg.epoch_number) {
            None => {
                self.proofs.insert(msg.epoch_number, msg);
                InsertOutcome::Inserted
            }
            Some(existing) => {
                if existing.epoch_commitment != msg.epoch_commitment {
                    return InsertOutcome::Conflict;
                }
                if existing.proof_accumulator != msg.proof_accumulator {
                    return InsertOutcome::Conflict;
                }
                if existing.is_recursive != msg.is_recursive {
                    return InsertOutcome::Conflict;
                }

                let same = existing.proof_bytes == msg.proof_bytes
                    && existing.inner_proof_bytes == msg.inner_proof_bytes
                    && existing.start_block == msg.start_block
                    && existing.end_block == msg.end_block
                    && existing.proof_root == msg.proof_root
                    && existing.state_root == msg.state_root
                    && existing.nullifier_set_root == msg.nullifier_set_root
                    && existing.commitment_tree_root == msg.commitment_tree_root
                    && existing.num_proofs == msg.num_proofs;

                if same {
                    InsertOutcome::AlreadyPresent
                } else {
                    InsertOutcome::Conflict
                }
            }
        }
    }

    pub fn persist(&self, msg: &RecursiveEpochProofMessage) -> io::Result<()> {
        let path = self.file_path(msg.epoch_number);
        let tmp_path = path.with_extension(format!("{EPOCH_PROOF_FILE_EXTENSION}.tmp"));
        fs::write(&tmp_path, msg.encode())?;
        fs::rename(tmp_path, path)?;
        Ok(())
    }

    fn load_from_dir(&mut self) -> io::Result<()> {
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some(EPOCH_PROOF_FILE_EXTENSION) {
                continue;
            }

            let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(epoch_number) = parse_epoch_file_name(file_name) else {
                continue;
            };

            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to read recursive epoch proof from disk"
                    );
                    continue;
                }
            };
            let msg = match RecursiveEpochProofMessage::decode(&mut &bytes[..]) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to decode recursive epoch proof from disk"
                    );
                    continue;
                }
            };

            if msg.epoch_number != epoch_number {
                tracing::warn!(
                    path = %path.display(),
                    expected_epoch_number = epoch_number,
                    decoded_epoch_number = msg.epoch_number,
                    "Epoch number mismatch in stored recursive epoch proof; skipping"
                );
                continue;
            }

            match self.insert(msg) {
                InsertOutcome::Inserted | InsertOutcome::AlreadyPresent => {}
                InsertOutcome::Conflict => {
                    tracing::warn!(
                        path = %path.display(),
                        epoch_number,
                        "Conflicting recursive epoch proof for epoch; skipping"
                    );
                }
            }
        }

        Ok(())
    }

    fn file_path(&self, epoch_number: u64) -> PathBuf {
        self.dir.join(format!(
            "{EPOCH_PROOF_FILE_PREFIX}{epoch_number}.{EPOCH_PROOF_FILE_EXTENSION}"
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted,
    AlreadyPresent,
    Conflict,
}

fn parse_epoch_file_name(file_name: &str) -> Option<u64> {
    if !file_name.starts_with(EPOCH_PROOF_FILE_PREFIX) {
        return None;
    }
    let file_name = file_name.strip_prefix(EPOCH_PROOF_FILE_PREFIX)?;
    let file_name = file_name.strip_suffix(&format!(".{EPOCH_PROOF_FILE_EXTENSION}"))?;
    file_name.parse().ok()
}
