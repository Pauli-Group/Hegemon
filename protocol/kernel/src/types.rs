use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use hegemon_hash384::{domains, Blake2b384DomainHasher};
use scale_info::TypeInfo;

pub type FamilyId = u16;
pub type ActionId = u16;
pub type ObjectId = [u8; 32];
pub type Nullifier = [u8; 48];
pub type Commitment = [u8; 48];
pub type FamilyRoot = [u8; 48];
pub type GlobalRoot = [u8; 48];
pub type StatementHash = [u8; 48];
pub type NativeActionId48 = [u8; 48];
pub type NativeActionRoot32 = [u8; 32];

/// Canonical active-native header commitment to the ordered action ids.
///
/// Keeping this transcript in the already shared kernel crate lets nodes and
/// light clients recompute the 32-byte header field without independently
/// copying the BLAKE3 domain/count framing.
pub fn compute_native_action_root_v1(action_ids: &[NativeActionId48]) -> NativeActionRoot32 {
    let action_count = u32::try_from(action_ids.len())
        .expect("native action count exceeds the canonical u32 wire");
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon-native-extrinsics-v1");
    hasher.update(&action_count.to_le_bytes());
    for action_id in action_ids {
        hasher.update(action_id);
    }
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct KernelVersionBinding {
    pub circuit: u16,
    pub crypto: u16,
}

impl From<protocol_versioning::VersionBinding> for KernelVersionBinding {
    fn from(value: protocol_versioning::VersionBinding) -> Self {
        Self {
            circuit: value.circuit,
            crypto: value.crypto,
        }
    }
}

impl From<KernelVersionBinding> for protocol_versioning::VersionBinding {
    fn from(value: KernelVersionBinding) -> Self {
        Self::new(value.circuit, value.crypto)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct ObjectRef {
    pub family_id: FamilyId,
    pub object_id: ObjectId,
    pub expected_root: FamilyRoot,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct SignatureEnvelope {
    pub key_id: [u8; 32],
    pub signature_scheme: u16,
    pub signature_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct AuthorizationBundle {
    pub proof_bytes: Vec<u8>,
    pub signatures: Vec<SignatureEnvelope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct ActionEnvelope {
    pub binding: KernelVersionBinding,
    pub family_id: FamilyId,
    pub action_id: ActionId,
    pub object_refs: Vec<ObjectRef>,
    pub new_nullifiers: Vec<Nullifier>,
    pub public_args: Vec<u8>,
    pub authorization: AuthorizationBundle,
    pub aux_data: Vec<u8>,
}

impl DecodeWithMemTracking for KernelVersionBinding {}
impl DecodeWithMemTracking for ObjectRef {}
impl DecodeWithMemTracking for SignatureEnvelope {}
impl DecodeWithMemTracking for AuthorizationBundle {}
impl DecodeWithMemTracking for ActionEnvelope {}

impl ActionEnvelope {
    pub fn statement_hash(&self) -> StatementHash {
        let mut hasher = Blake2b384DomainHasher::new(domains::KERNEL_ACTION_STATEMENT_V2);
        let circuit = self.binding.circuit.to_le_bytes();
        let crypto = self.binding.crypto.to_le_bytes();
        let family_id = self.family_id.to_le_bytes();
        let action_id = self.action_id.to_le_bytes();
        let object_count = u32::try_from(self.object_refs.len())
            .expect("kernel object-ref count fits the canonical u32 wire")
            .to_le_bytes();
        hasher
            .update_part(&circuit)
            .update_part(&crypto)
            .update_part(&family_id)
            .update_part(&action_id)
            .update_part(&object_count);
        for object_ref in &self.object_refs {
            hasher
                .update_part(&object_ref.family_id.to_le_bytes())
                .update_part(&object_ref.object_id)
                .update_part(&object_ref.expected_root);
        }
        let nullifier_count = u32::try_from(self.new_nullifiers.len())
            .expect("kernel nullifier count fits the canonical u32 wire")
            .to_le_bytes();
        hasher.update_part(&nullifier_count);
        for nf in &self.new_nullifiers {
            hasher.update_part(nf);
        }
        let signature_count = u32::try_from(self.authorization.signatures.len())
            .expect("kernel signature count fits the canonical u32 wire")
            .to_le_bytes();
        hasher
            .update_part(&self.public_args)
            .update_part(&self.authorization.proof_bytes)
            .update_part(&signature_count);
        for sig in &self.authorization.signatures {
            hasher
                .update_part(&sig.key_id)
                .update_part(&sig.signature_scheme.to_le_bytes())
                .update_part(&sig.signature_bytes);
        }
        hasher.update_part(&self.aux_data);
        hasher.finalize()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DuplicateFamilyId(pub FamilyId);

pub fn compute_kernel_global_root(
    roots: impl IntoIterator<Item = (FamilyId, FamilyRoot)>,
) -> Result<GlobalRoot, DuplicateFamilyId> {
    let mut ordered = BTreeMap::new();
    for (family_id, root) in roots {
        if ordered.insert(family_id, root).is_some() {
            return Err(DuplicateFamilyId(family_id));
        }
    }

    let mut hasher = Blake2b384DomainHasher::new(domains::KERNEL_GLOBAL_ROOT_V2);
    let root_count = u32::try_from(ordered.len())
        .expect("kernel family-root count fits the canonical u32 wire")
        .to_le_bytes();
    hasher.update_part(&root_count);
    for (family_id, root) in ordered {
        hasher
            .update_part(&family_id.to_le_bytes())
            .update_part(&root);
    }
    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> ActionEnvelope {
        ActionEnvelope {
            binding: KernelVersionBinding {
                circuit: 4,
                crypto: 3,
            },
            family_id: 5,
            action_id: 0x0201,
            object_refs: vec![ObjectRef {
                family_id: 1,
                object_id: [0x11; 32],
                expected_root: [0x22; 48],
            }],
            new_nullifiers: vec![[0x33; 48]],
            public_args: vec![1, 2],
            authorization: AuthorizationBundle {
                proof_bytes: vec![3, 4],
                signatures: vec![SignatureEnvelope {
                    key_id: [0x44; 32],
                    signature_scheme: 9,
                    signature_bytes: vec![5, 6],
                }],
            },
            aux_data: vec![7],
        }
    }

    #[test]
    fn kernel_action_statement_v2_kat_binds_every_dynamic_class() {
        let canonical = envelope();
        assert_eq!(
            hex::encode(canonical.statement_hash()),
            "3b7d711150e43b309e7cd04ec9f3385bfa8abce6cc59bb76e739e0fe0160ccd5f6ac6c1ffcba7e5bed9a7aa5e8feffc6"
        );

        let mut changed = canonical.clone();
        changed.authorization.proof_bytes.push(8);
        assert_ne!(canonical.statement_hash(), changed.statement_hash());
        changed = canonical.clone();
        changed.object_refs.push(changed.object_refs[0].clone());
        assert_ne!(canonical.statement_hash(), changed.statement_hash());
        changed = canonical.clone();
        changed.new_nullifiers.push([0x34; 48]);
        assert_ne!(canonical.statement_hash(), changed.statement_hash());
    }

    #[test]
    fn kernel_global_root_v2_kat_orders_and_rejects_duplicates() {
        let first = [0x11; 48];
        let second = [0x22; 48];
        let expected = "dd1ce34f5852026ea0f77e13837c1e61ec5b6b54b9c65c0b318a4b558b8f5fa48557227f18a31c98bc7dfe6e253472cd";
        assert_eq!(
            hex::encode(compute_kernel_global_root([(2, second), (1, first)]).unwrap()),
            expected
        );
        assert_eq!(
            hex::encode(compute_kernel_global_root([(1, first), (2, second)]).unwrap()),
            expected
        );
        assert_eq!(
            compute_kernel_global_root([(1, first), (1, second)]),
            Err(DuplicateFamilyId(1))
        );
    }

    #[test]
    fn native_action_root_v1_binds_order_count_and_every_id_byte() {
        let ids = [[0x11; 48], [0x22; 48]];
        let root = compute_native_action_root_v1(&ids);
        assert_ne!(root, compute_native_action_root_v1(&ids[..1]));
        assert_ne!(root, compute_native_action_root_v1(&[ids[1], ids[0]]));
        let mut mutated = ids;
        mutated[1][47] ^= 1;
        assert_ne!(root, compute_native_action_root_v1(&mutated));
    }
}
