use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use codec::{Decode, Encode};
use scale_info::TypeInfo;

use crate::types::{ActionId, FamilyId, FamilyRoot, KernelVersionBinding};

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct FamilySpec {
    pub family_id: FamilyId,
    pub enabled_at: u64,
    pub retired_at: Option<u64>,
    pub supported_actions: Vec<ActionId>,
    pub verifier_key_hashes: Vec<[u8; 32]>,
    pub params_commitment: [u8; 48],
    pub empty_root: FamilyRoot,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct KernelManifest {
    pub manifest_version: u32,
    pub allowed_bindings: Vec<KernelVersionBinding>,
    pub families: BTreeMap<FamilyId, FamilySpec>,
    pub policy_commitments: BTreeMap<[u8; 32], [u8; 48]>,
}

impl KernelManifest {
    pub fn family(&self, family_id: FamilyId, height: u64) -> Option<&FamilySpec> {
        let spec = self.families.get(&family_id)?;
        if height < spec.enabled_at {
            return None;
        }
        if spec.retired_at.is_some_and(|retired| height >= retired) {
            return None;
        }
        Some(spec)
    }

    pub fn binding_allowed(&self, binding: KernelVersionBinding, height: u64) -> bool {
        let _ = height;
        self.allowed_bindings.contains(&binding)
    }
}
