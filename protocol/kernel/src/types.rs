use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

pub type FamilyId = u16;
pub type ActionId = u16;
pub type ObjectId = [u8; 32];
pub type Nullifier = [u8; 48];
pub type Commitment = [u8; 48];
pub type FamilyRoot = [u8; 48];
pub type GlobalRoot = [u8; 48];
pub type StatementHash = [u8; 48];

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
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hegemon-kernel-action-v1");
        hasher.update(&self.binding.circuit.to_le_bytes());
        hasher.update(&self.binding.crypto.to_le_bytes());
        hasher.update(&self.family_id.to_le_bytes());
        hasher.update(&self.action_id.to_le_bytes());
        for object_ref in &self.object_refs {
            hasher.update(&object_ref.family_id.to_le_bytes());
            hasher.update(&object_ref.object_id);
            hasher.update(&object_ref.expected_root);
        }
        for nf in &self.new_nullifiers {
            hasher.update(nf);
        }
        hasher.update(&(self.public_args.len() as u32).to_le_bytes());
        hasher.update(&self.public_args);
        hasher.update(&(self.authorization.proof_bytes.len() as u32).to_le_bytes());
        hasher.update(&self.authorization.proof_bytes);
        hasher.update(&(self.authorization.signatures.len() as u32).to_le_bytes());
        for sig in &self.authorization.signatures {
            hasher.update(&sig.key_id);
            hasher.update(&sig.signature_scheme.to_le_bytes());
            hasher.update(&(sig.signature_bytes.len() as u32).to_le_bytes());
            hasher.update(&sig.signature_bytes);
        }
        hasher.update(&(self.aux_data.len() as u32).to_le_bytes());
        hasher.update(&self.aux_data);

        let mut out = [0u8; 48];
        hasher.finalize_xof().fill(&mut out);
        out
    }
}

pub fn compute_kernel_global_root(
    roots: impl IntoIterator<Item = (FamilyId, FamilyRoot)>,
) -> GlobalRoot {
    let mut ordered = BTreeMap::new();
    for (family_id, root) in roots {
        ordered.insert(family_id, root);
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon-kernel-root-v1");
    for (family_id, root) in ordered {
        hasher.update(&family_id.to_le_bytes());
        hasher.update(&root);
    }
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}
