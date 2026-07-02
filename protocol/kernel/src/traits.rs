use alloc::vec::Vec;

use crate::manifest::KernelManifest;
use crate::types::{ActionEnvelope, FamilyId, FamilyRoot, GlobalRoot, Nullifier, StatementHash};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelError {
    Other(&'static str),
}

impl KernelError {
    pub const fn other(reason: &'static str) -> Self {
        Self::Other(reason)
    }

    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Other(reason) => reason,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionSourceClass {
    External,
    LocalOnly,
    InBlockOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidActionMeta {
    pub priority: u64,
    pub longevity: u64,
    pub provides: Vec<Vec<u8>>,
    pub requires: Vec<Vec<u8>>,
    pub propagate: bool,
    pub source_class: ActionSourceClass,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub family_id: FamilyId,
    pub new_family_root: FamilyRoot,
    pub emitted_nullifiers: Vec<Nullifier>,
    pub statement_hash: StatementHash,
}

pub trait KernelStateView {
    fn current_height(&self) -> u64;
    fn family_root(&self, family_id: FamilyId) -> FamilyRoot;
    fn global_root(&self) -> GlobalRoot;
}

pub trait KernelStateWrite: KernelStateView {
    fn set_family_root(&mut self, family_id: FamilyId, new_root: FamilyRoot);
    fn set_global_root(&mut self, new_root: GlobalRoot);
}

pub trait ManifestProvider {
    fn manifest_at(height: u64) -> KernelManifest;
}

pub trait KernelFamily {
    fn family_id() -> FamilyId;

    fn validate(
        manifest: &KernelManifest,
        state: &dyn KernelStateView,
        envelope: &ActionEnvelope,
    ) -> Result<ValidActionMeta, KernelError>;

    fn apply(
        manifest: &KernelManifest,
        state: &mut dyn KernelStateWrite,
        envelope: &ActionEnvelope,
    ) -> Result<ApplyOutcome, KernelError>;
}
