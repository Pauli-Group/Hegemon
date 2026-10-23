//! Proof-aware, inactive controlled-asset candidate ledger.
//!
//! This bounded in-memory ledger demonstrates the state transition seam. It
//! creates no accepted node route, registration power, funded note or genesis
//! allocation. Importing a snapshot requires external authentication of every
//! row, existing note, spent nullifier and parent context. Native monetary
//! policy, native spend routes and production authorization are untouched.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use crate::asset_spend_v1::{self, AssetSpendPublic, Digest};
use crate::asset_spend_v1_wire::{decode_asset_spend_action_v1, AssetSpendWireErrorV1};
use crate::smallwood_poseidon2_v8_coinbase::{
    poseidon2_v8_default_note_nodes, poseidon2_v8_note_tree_compress,
};
use transaction_core::asset_registry_v1::{
    AssetOperationV1, AssetRegistryContextV1, AssetRegistryErrorV1, AssetRegistryV1,
    PreparedAssetAccountingV1,
};
use transaction_core::poseidon2_width16::Felt;

pub const ASSET_LEDGER_V1_NOTE_DEPTH: usize = 32;
/// Resource bounds for disposable qualification state, not a network limit.
pub const ASSET_LEDGER_V1_MAX_NOTES: usize = 65_536;
pub const ASSET_LEDGER_V1_MAX_NULLIFIERS: usize = 2 * ASSET_LEDGER_V1_MAX_NOTES;
pub const ASSET_LEDGER_V1_MAX_ADMIN_ACTIONS: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetLedgerContextV1 {
    pub chain_id: [u8; 32],
    pub reference_parent_hash: [u8; 32],
    pub parent_height: u64,
    pub note_root: Digest,
    pub registry_root: Digest,
}

#[derive(Debug)]
pub enum AssetLedgerErrorV1 {
    Wire(AssetSpendWireErrorV1),
    Registry(AssetRegistryErrorV1),
    Proof(crate::TransactionCircuitError),
    ParentContext,
    NoteRoot,
    RegistryRoot,
    PolicyFields,
    NonCanonicalDigest,
    ZeroDigest,
    RepeatedNullifier,
    SpentNullifier,
    AdminReplay,
    ResourceLimit,
    NotePosition,
    FeeOverflow,
}
impl From<AssetSpendWireErrorV1> for AssetLedgerErrorV1 {
    fn from(error: AssetSpendWireErrorV1) -> Self {
        Self::Wire(error)
    }
}
impl From<AssetRegistryErrorV1> for AssetLedgerErrorV1 {
    fn from(error: AssetRegistryErrorV1) -> Self {
        Self::Registry(error)
    }
}
impl core::fmt::Display for AssetLedgerErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "candidate asset ledger: {self:?}")
    }
}
impl std::error::Error for AssetLedgerErrorV1 {}

fn check_digest(digest: Digest, nonzero: bool) -> Result<(), AssetLedgerErrorV1> {
    if digest
        .iter()
        .any(|word| *word >= hegemon_field::GOLDILOCKS_MODULUS)
    {
        return Err(AssetLedgerErrorV1::NonCanonicalDigest);
    }
    if nonzero && digest == [0; 7] {
        return Err(AssetLedgerErrorV1::ZeroDigest);
    }
    Ok(())
}
fn to_felts(digest: Digest) -> [Felt; 7] {
    // Every caller first checks canonicality. Never use reduction to accept an
    // alias of a public field word at the state/proof boundary.
    digest.map(Felt::from_u64)
}
fn to_words(digest: [Felt; 7]) -> Digest {
    digest.map(|word| word.as_canonical_u64())
}

/// Exact note witness against the current depth-32 tree. A path is useful to a
/// prover, but possession of a path confers neither note ownership nor value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetNoteMembershipV1 {
    pub position: u32,
    pub commitment: Digest,
    pub siblings: [Digest; ASSET_LEDGER_V1_NOTE_DEPTH],
    pub root: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetSpendReceiptV1 {
    pub before_note_root: Digest,
    pub after_note_root: Digest,
    pub before_registry_root: Digest,
    pub after_registry_root: Digest,
    pub output_positions: [u32; 3],
    pub consumed_nullifiers: [Digest; 2],
    pub native_fee: u64,
    pub operation: u8,
    pub policy_mode: u8,
    /// Published only after the exact release statement's real proof verifies.
    /// Absence is enforced by the statement grammar when release is disabled.
    pub released_secret: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetControlsReceiptV1 {
    pub before_registry_root: Digest,
    pub after_registry_root: Digest,
    pub asset_id: u32,
    pub admin_action_id: [u8; 32],
}

/// Complete resumable candidate state. Checkpoint storage, authentication,
/// durability and canonical-chain/reorg selection remain the caller's duties.
/// In particular, omitting historical admin IDs when restoring a checkpoint
/// would discard replay protection across freeze/unfreeze root cycles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetLedgerSnapshotV1 {
    pub context: AssetLedgerContextV1,
    pub registry: AssetRegistryV1,
    pub commitments: Vec<Digest>,
    pub spent_nullifiers: Vec<Digest>,
    pub admin_action_ids: Vec<[u8; 32]>,
    pub accepted_native_fees_since_snapshot: u128,
}

/// A small qualification ledger. Fields are private so no external caller can
/// skip proof verification by mutating its registry, tree or nullifier set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetLedgerV1 {
    chain_id: [u8; 32],
    reference_parent_hash: [u8; 32],
    parent_height: u64,
    registry: AssetRegistryV1,
    commitments: Vec<Digest>,
    spent_nullifiers: BTreeSet<Digest>,
    admin_action_ids: BTreeSet<[u8; 32]>,
    accepted_native_fees_since_snapshot: u128,
}

impl AssetLedgerV1 {
    /// Import an externally authenticated candidate snapshot. Recomputes both
    /// roots and rejects malformed or duplicate spent-nullifier entries. This
    /// is not an on-chain constructor, asset registration or mint operation.
    pub fn from_authenticated_snapshot(
        context: AssetLedgerContextV1,
        registry: AssetRegistryV1,
        commitments: &[Digest],
        spent_nullifiers: &[Digest],
        admin_action_ids: &[[u8; 32]],
    ) -> Result<Self, AssetLedgerErrorV1> {
        if context.chain_id == [0; 32]
            || context.reference_parent_hash == [0; 32]
            || context.parent_height >= 1 << 48
        {
            return Err(AssetLedgerErrorV1::ParentContext);
        }
        if commitments.len() > ASSET_LEDGER_V1_MAX_NOTES
            || spent_nullifiers.len() > ASSET_LEDGER_V1_MAX_NULLIFIERS
            || admin_action_ids.len() > ASSET_LEDGER_V1_MAX_ADMIN_ACTIONS
        {
            return Err(AssetLedgerErrorV1::ResourceLimit);
        }
        check_digest(context.note_root, false)?;
        check_digest(context.registry_root, false)?;
        let registry_context = registry.context();
        if context.chain_id != registry_context.chain_id
            || context.parent_height != registry_context.parent_height
        {
            return Err(AssetLedgerErrorV1::ParentContext);
        }
        if context.registry_root != to_words(registry_context.registry_root) {
            return Err(AssetLedgerErrorV1::RegistryRoot);
        }
        for commitment in commitments {
            check_digest(*commitment, true)?;
        }
        let mut consumed = BTreeSet::new();
        for nullifier in spent_nullifiers {
            check_digest(*nullifier, true)?;
            if !consumed.insert(*nullifier) {
                return Err(AssetLedgerErrorV1::RepeatedNullifier);
            }
        }
        let mut consumed_admin = BTreeSet::new();
        for action_id in admin_action_ids {
            if !consumed_admin.insert(*action_id) {
                return Err(AssetLedgerErrorV1::AdminReplay);
            }
        }
        let ledger = Self {
            chain_id: context.chain_id,
            reference_parent_hash: context.reference_parent_hash,
            parent_height: context.parent_height,
            registry,
            commitments: commitments.to_vec(),
            spent_nullifiers: consumed,
            admin_action_ids: consumed_admin,
            accepted_native_fees_since_snapshot: 0,
        };
        if ledger.note_root() != context.note_root {
            return Err(AssetLedgerErrorV1::NoteRoot);
        }
        Ok(ledger)
    }

    pub fn registry(&self) -> &AssetRegistryV1 {
        &self.registry
    }
    pub fn commitments(&self) -> &[Digest] {
        &self.commitments
    }
    pub fn nullifier_is_spent(&self, nullifier: &Digest) -> bool {
        self.spent_nullifiers.contains(nullifier)
    }
    pub fn spent_nullifier_count(&self) -> usize {
        self.spent_nullifiers.len()
    }
    pub fn admin_action_is_consumed(&self, action_id: &[u8; 32]) -> bool {
        self.admin_action_ids.contains(action_id)
    }
    pub fn snapshot(&self) -> AssetLedgerSnapshotV1 {
        AssetLedgerSnapshotV1 {
            context: self.context(),
            registry: self.registry.clone(),
            commitments: self.commitments.clone(),
            spent_nullifiers: self.spent_nullifiers.iter().copied().collect(),
            admin_action_ids: self.admin_action_ids.iter().copied().collect(),
            accepted_native_fees_since_snapshot: self.accepted_native_fees_since_snapshot,
        }
    }
    pub fn restore_authenticated_snapshot(
        snapshot: AssetLedgerSnapshotV1,
    ) -> Result<Self, AssetLedgerErrorV1> {
        let mut ledger = Self::from_authenticated_snapshot(
            snapshot.context,
            snapshot.registry,
            &snapshot.commitments,
            &snapshot.spent_nullifiers,
            &snapshot.admin_action_ids,
        )?;
        ledger.accepted_native_fees_since_snapshot = snapshot.accepted_native_fees_since_snapshot;
        Ok(ledger)
    }
    /// Candidate fees observed after snapshot import. Distribution to miners
    /// remains outside this inactive ledger and grants no issuance authority.
    pub fn accepted_native_fees_since_snapshot(&self) -> u128 {
        self.accepted_native_fees_since_snapshot
    }
    pub fn context(&self) -> AssetLedgerContextV1 {
        AssetLedgerContextV1 {
            chain_id: self.chain_id,
            reference_parent_hash: self.reference_parent_hash,
            parent_height: self.parent_height,
            note_root: self.note_root(),
            registry_root: to_words(self.registry.root()),
        }
    }

    /// Compute a root from already-authenticated canonical note commitments.
    /// Used by disposable fixture construction and snapshot readback; no notes
    /// or balances are created by this deterministic calculation.
    pub fn root_for_authenticated_commitments(
        commitments: &[Digest],
    ) -> Result<Digest, AssetLedgerErrorV1> {
        if commitments.len() > ASSET_LEDGER_V1_MAX_NOTES {
            return Err(AssetLedgerErrorV1::ResourceLimit);
        }
        for commitment in commitments {
            check_digest(*commitment, true)?;
        }
        Ok(note_tree_root_and_path(commitments, None).0)
    }
    pub fn note_root(&self) -> Digest {
        note_tree_root_and_path(&self.commitments, None).0
    }
    pub fn note_membership(
        &self,
        position: u32,
    ) -> Result<AssetNoteMembershipV1, AssetLedgerErrorV1> {
        let index = position as usize;
        let commitment = *self
            .commitments
            .get(index)
            .ok_or(AssetLedgerErrorV1::NotePosition)?;
        let (root, siblings) = note_tree_root_and_path(&self.commitments, Some(index));
        Ok(AssetNoteMembershipV1 {
            position,
            commitment,
            siblings,
            root,
        })
    }

    fn prepare_action(
        &self,
        public: &AssetSpendPublic,
    ) -> Result<PreparedAssetAccountingV1, AssetLedgerErrorV1> {
        public
            .validate_structure()
            .map_err(AssetLedgerErrorV1::Proof)?;
        if public.chain_id != self.chain_id
            || public.reference_parent_hash != self.reference_parent_hash
            || public.parent_height != self.parent_height
        {
            return Err(AssetLedgerErrorV1::ParentContext);
        }
        if public.note_root != self.note_root() {
            return Err(AssetLedgerErrorV1::NoteRoot);
        }
        if public.registry_root != to_words(self.registry.root()) {
            return Err(AssetLedgerErrorV1::RegistryRoot);
        }
        let row = self.registry.row(public.asset_id)?;
        if public.asset_id != row.config.asset_id
            || public.policy_version != row.config.policy_version
            || public.credential_root != to_words(row.credential_root)
            || public.credential_depth != row.credential_depth
            || public.frozen != row.frozen
            || public.mint_enabled != row.mint_enabled
            || public.issuer_commitment != to_words(row.config.issuer_commitment)
        {
            return Err(AssetLedgerErrorV1::PolicyFields);
        }
        for nullifier in public.nullifiers {
            check_digest(nullifier, true)?;
            if self.spent_nullifiers.contains(&nullifier) {
                return Err(AssetLedgerErrorV1::SpentNullifier);
            }
        }
        if public.nullifiers[0] == public.nullifiers[1] {
            return Err(AssetLedgerErrorV1::RepeatedNullifier);
        }
        for commitment in public.commitments {
            check_digest(commitment, true)?;
        }
        if self
            .commitments
            .len()
            .checked_add(3)
            .is_none_or(|count| count > ASSET_LEDGER_V1_MAX_NOTES)
            || self
                .spent_nullifiers
                .len()
                .checked_add(2)
                .is_none_or(|count| count > ASSET_LEDGER_V1_MAX_NULLIFIERS)
        {
            return Err(AssetLedgerErrorV1::ResourceLimit);
        }
        let operation = match public.operation {
            asset_spend_v1::TRANSFER => AssetOperationV1::Transfer,
            asset_spend_v1::MINT => AssetOperationV1::Mint,
            asset_spend_v1::BURN => AssetOperationV1::Burn,
            _ => return Err(AssetLedgerErrorV1::PolicyFields),
        };
        self.registry
            .prepare_accounting(
                AssetRegistryContextV1 {
                    chain_id: public.chain_id,
                    parent_height: public.parent_height,
                    registry_root: to_felts(public.registry_root),
                },
                public.asset_id,
                public.policy_version,
                to_felts(public.credential_root),
                operation,
                public.magnitude,
            )
            .map_err(Into::into)
    }

    /// Decode, authenticate current state, verify the real candidate proof,
    /// then atomically replace the staged ledger. A failure leaves every
    /// registry row, note, nullifier and fee counter unchanged.
    pub fn apply_action(
        &mut self,
        bytes: &[u8],
    ) -> Result<AssetSpendReceiptV1, AssetLedgerErrorV1> {
        let action = decode_asset_spend_action_v1(bytes)?;
        let prepared = self.prepare_action(&action.public)?;
        asset_spend_v1::verify_candidate(&action.public, action.proof)
            .map_err(AssetLedgerErrorV1::Proof)?;
        let mut staged = self.clone();
        staged.registry.apply_accounting_after_proof(prepared)?;
        for nullifier in action.public.nullifiers {
            if !staged.spent_nullifiers.insert(nullifier) {
                return Err(AssetLedgerErrorV1::SpentNullifier);
            }
        }
        let first = staged.commitments.len() as u32;
        staged.commitments.extend(action.public.commitments);
        staged.accepted_native_fees_since_snapshot = staged
            .accepted_native_fees_since_snapshot
            .checked_add(u128::from(action.public.fee))
            .ok_or(AssetLedgerErrorV1::FeeOverflow)?;
        let receipt = AssetSpendReceiptV1 {
            before_note_root: action.public.note_root,
            after_note_root: staged.note_root(),
            before_registry_root: action.public.registry_root,
            after_registry_root: to_words(staged.registry.root()),
            output_positions: [first, first + 1, first + 2],
            consumed_nullifiers: action.public.nullifiers,
            native_fee: action.public.fee,
            operation: action.public.operation,
            policy_mode: action.public.policy_mode,
            released_secret: (action.public.secret_release == 1)
                .then_some(action.public.released_secret),
        };
        *self = staged;
        Ok(receipt)
    }

    /// Apply a credential/freeze/mint-control change only after its exact old
    /// policy-admin secret proof verifies. Full config, issuance counters and
    /// native HGN are excluded by the core prepared-controls type.
    pub fn apply_controls_update(
        &mut self,
        public: &crate::asset_policy_admin_v1::PolicyAdminPublicV1,
        proof: &[u8],
    ) -> Result<AssetControlsReceiptV1, AssetLedgerErrorV1> {
        public
            .validate_structure()
            .map_err(AssetLedgerErrorV1::Proof)?;
        if public.chain_id != self.chain_id
            || public.reference_parent_hash != self.reference_parent_hash
            || public.parent_height != self.parent_height
        {
            return Err(AssetLedgerErrorV1::ParentContext);
        }
        let action_id = public.action_id();
        if self.admin_action_ids.contains(&action_id) {
            return Err(AssetLedgerErrorV1::AdminReplay);
        }
        if self.admin_action_ids.len() >= ASSET_LEDGER_V1_MAX_ADMIN_ACTIONS {
            return Err(AssetLedgerErrorV1::ResourceLimit);
        }
        let prepared = self.registry.prepare_controls_update(
            self.registry.context(),
            public.asset_id,
            public.controls,
        )?;
        public
            .verify_prepared(&prepared, self.reference_parent_hash)
            .map_err(AssetLedgerErrorV1::Proof)?;
        crate::asset_policy_admin_v1::verify_candidate(public, proof)
            .map_err(AssetLedgerErrorV1::Proof)?;
        let receipt = AssetControlsReceiptV1 {
            before_registry_root: to_words(prepared.context().registry_root),
            after_registry_root: to_words(prepared.after_root()),
            asset_id: public.asset_id,
            admin_action_id: action_id,
        };
        let mut staged = self.clone();
        staged
            .registry
            .apply_controls_update_after_authorization(prepared)?;
        if !staged.admin_action_ids.insert(action_id) {
            return Err(AssetLedgerErrorV1::AdminReplay);
        }
        *self = staged;
        Ok(receipt)
    }

    /// Change only the externally authenticated canonical parent. No registry
    /// controls, supply, note or nullifier is changed. Reorg support requires
    /// restoring an independently authenticated snapshot rather than rollback.
    pub fn advance_parent_after_chain_verification(
        &mut self,
        expected: AssetLedgerContextV1,
        reference_parent_hash: [u8; 32],
        parent_height: u64,
    ) -> Result<(), AssetLedgerErrorV1> {
        if self.context() != expected
            || reference_parent_hash == [0; 32]
            || parent_height < self.parent_height
            || parent_height >= 1 << 48
            || (parent_height == self.parent_height
                && reference_parent_hash != self.reference_parent_hash)
        {
            return Err(AssetLedgerErrorV1::ParentContext);
        }
        let mut staged = self.clone();
        staged
            .registry
            .advance_parent_after_chain_verification(staged.registry.context(), parent_height)?;
        staged.reference_parent_hash = reference_parent_hash;
        staged.parent_height = parent_height;
        *self = staged;
        Ok(())
    }
}

// A bounded vector is sufficient for disposable lifecycle evidence. At each
// level absent siblings use the *existing V8 default subtree*, including its
// known zero-value native note at level zero. Raw-zero leaves are not defaults.
fn note_tree_root_and_path(
    commitments: &[Digest],
    position: Option<usize>,
) -> (Digest, [Digest; ASSET_LEDGER_V1_NOTE_DEPTH]) {
    let defaults = poseidon2_v8_default_note_nodes();
    let mut nodes = commitments.to_vec();
    let mut siblings = [[0; 7]; ASSET_LEDGER_V1_NOTE_DEPTH];
    let mut cursor = position.unwrap_or(0);
    for level in 0..ASSET_LEDGER_V1_NOTE_DEPTH {
        if position.is_some() {
            siblings[level] = nodes.get(cursor ^ 1).copied().unwrap_or(defaults[level]);
        }
        if nodes.is_empty() {
            nodes.push(defaults[level + 1]);
        } else {
            let mut parents = Vec::with_capacity(nodes.len().div_ceil(2));
            for pair in nodes.chunks(2) {
                parents.push(poseidon2_v8_note_tree_compress(
                    pair[0],
                    pair.get(1).copied().unwrap_or(defaults[level]),
                ));
            }
            nodes = parents;
        }
        cursor >>= 1;
    }
    (nodes[0], siblings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset_policy_admin_v1::{self as admin, PolicyAdminPublicV1, PolicyAdminWitnessV1};
    use crate::asset_spend_v1::{AssetSpendWitness, BURN, MINT, TRANSFER};
    use crate::asset_spend_v1_wire::encode_asset_spend_action_v1;
    use crate::private_spend::{note_commitment, real_nullifier, CIPHERTEXT_BYTES};
    use std::time::Instant;
    use transaction_core::asset_registry_v1::AssetPolicyV1;
    use transaction_core::stablecoin_poseidon2_v8::{
        StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Counters,
    };

    fn empty_registry() -> AssetRegistryV1 {
        AssetRegistryV1::from_rows([1; 32], 100, &[]).unwrap()
    }
    fn fixture(
        commitments: &[Digest],
        spent: &[Digest],
    ) -> Result<AssetLedgerV1, AssetLedgerErrorV1> {
        let registry = empty_registry();
        let context = AssetLedgerContextV1 {
            chain_id: [1; 32],
            reference_parent_hash: [2; 32],
            parent_height: 100,
            note_root: AssetLedgerV1::root_for_authenticated_commitments(commitments)?,
            registry_root: to_words(registry.root()),
        };
        AssetLedgerV1::from_authenticated_snapshot(context, registry, commitments, spent, &[])
    }

    #[test]
    fn empty_and_two_note_roots_match_existing_v8_defaults() {
        let empty = fixture(&[], &[]).unwrap();
        assert_eq!(empty.note_root(), poseidon2_v8_default_note_nodes()[32]);
        let notes = [[7; 7], [8; 7]];
        let ledger = fixture(&notes, &[]).unwrap();
        let existing =
            crate::smallwood_poseidon2_v8_coinbase::poseidon2_v8_two_note_frontier(notes).unwrap();
        assert_eq!(ledger.note_root(), existing.root);
        for index in 0..2 {
            assert_eq!(
                ledger.note_membership(index as u32).unwrap().siblings,
                existing.paths[index]
            );
        }
    }

    #[test]
    fn odd_width_membership_paths_recompute_current_root() {
        let notes = [[1; 7], [2; 7], [3; 7], [4; 7], [5; 7]];
        let ledger = fixture(&notes, &[[20; 7]]).unwrap();
        for (index, leaf) in notes.into_iter().enumerate() {
            let witness = ledger.note_membership(index as u32).unwrap();
            let mut root = leaf;
            for (level, sibling) in witness.siblings.into_iter().enumerate() {
                root = if index >> level & 1 == 0 {
                    poseidon2_v8_note_tree_compress(root, sibling)
                } else {
                    poseidon2_v8_note_tree_compress(sibling, root)
                };
            }
            assert_eq!(root, ledger.note_root());
        }
        assert!(ledger.nullifier_is_spent(&[20; 7]));
        assert!(ledger.note_membership(5).is_err());
    }

    #[test]
    fn snapshot_rejects_root_aliases_and_duplicate_spent_nullifiers() {
        assert!(matches!(
            fixture(&[[0; 7]], &[]),
            Err(AssetLedgerErrorV1::ZeroDigest)
        ));
        assert!(matches!(
            fixture(&[[hegemon_field::GOLDILOCKS_MODULUS; 7]], &[]),
            Err(AssetLedgerErrorV1::NonCanonicalDigest)
        ));
        assert!(matches!(
            fixture(&[[1; 7]], &[[20; 7], [20; 7]]),
            Err(AssetLedgerErrorV1::RepeatedNullifier)
        ));
        let registry = empty_registry();
        let context = AssetLedgerContextV1 {
            chain_id: [1; 32],
            reference_parent_hash: [2; 32],
            parent_height: 100,
            note_root: [99; 7],
            registry_root: to_words(registry.root()),
        };
        assert!(matches!(
            AssetLedgerV1::from_authenticated_snapshot(context, registry, &[[1; 7]], &[], &[]),
            Err(AssetLedgerErrorV1::NoteRoot)
        ));
    }

    #[test]
    fn malformed_action_and_stale_parent_leave_entire_ledger_unchanged() {
        let mut ledger = fixture(&[[1; 7]], &[[20; 7]]).unwrap();
        let before = ledger.clone();
        assert!(ledger.apply_action(b"HGASLC02").is_err());
        assert_eq!(ledger, before);
        let mut stale = ledger.context();
        stale.reference_parent_hash = [5; 32];
        assert!(ledger
            .advance_parent_after_chain_verification(stale, [3; 32], 101)
            .is_err());
        assert_eq!(ledger, before);
        ledger
            .advance_parent_after_chain_verification(ledger.context(), [3; 32], 101)
            .unwrap();
        assert_eq!(ledger.registry().context().parent_height, 101);
        assert_eq!(ledger.note_root(), before.note_root());
        assert_eq!(ledger.spent_nullifiers, before.spent_nullifiers);
    }

    #[test]
    fn snapshot_preserves_historical_admin_replay_ids_and_all_state() {
        let mut snapshot = fixture(&[[1; 7], [2; 7]], &[[20; 7]]).unwrap().snapshot();
        snapshot.admin_action_ids = vec![[33; 32], [34; 32]];
        snapshot.accepted_native_fees_since_snapshot = 91;
        let ledger = AssetLedgerV1::restore_authenticated_snapshot(snapshot.clone()).unwrap();
        assert!(ledger.admin_action_is_consumed(&[33; 32]));
        assert!(ledger.admin_action_is_consumed(&[34; 32]));
        assert_eq!(ledger.accepted_native_fees_since_snapshot(), 91);
        assert_eq!(ledger.snapshot(), snapshot);
        let mut duplicate = snapshot;
        duplicate.admin_action_ids.push([33; 32]);
        assert!(matches!(
            AssetLedgerV1::restore_authenticated_snapshot(duplicate),
            Err(AssetLedgerErrorV1::AdminReplay)
        ));
    }

    const ADMIN_SECRET: Digest = [0, 2, 3, 4, 5, 6, 7];
    const TEST_CIPHERTEXTS: [[u8; CIPHERTEXT_BYTES]; 3] = [
        [1; CIPHERTEXT_BYTES],
        [2; CIPHERTEXT_BYTES],
        [3; CIPHERTEXT_BYTES],
    ];

    fn spend_fixture() -> (AssetLedgerV1, AssetSpendPublic, AssetSpendWitness) {
        let (mut public, mut witness) = asset_spend_v1::fixtures::fixture(MINT, 4).unwrap();
        let tagged = |tag: u64| core::array::from_fn(|index| Felt::from_u64(tag + index as u64));
        // Published, disposable fixture credentials only. The administrative
        // commitment is actually derived from the witness used by the proof.
        let row = AssetPolicyV1 {
            config: StablecoinPoseidon2V8Config {
                asset_id: public.asset_id,
                policy_version: public.policy_version,
                active: true,
                enabled_at: 1,
                retired_at: None,
                issuer_commitment: to_felts(public.issuer_commitment),
                min_collateral_ratio_ppm: 1_500_000,
                max_mint_per_epoch: 1_000_000,
                oracle_submitted_at: 90,
                oracle_max_age: 500,
                oracle_price_numerator: 2,
                oracle_price_denominator: 1,
                collateral_amount: 10_000,
                attestation_created_at: 90,
                attestation_disputed: false,
                attestation_present: true,
                attestation_max_age: 500,
                policy_admin_commitment: to_felts(
                    admin::policy_admin_commitment(public.asset_id, ADMIN_SECRET).unwrap(),
                ),
                oracle_authority_commitment: tagged(201),
                attestation_authority_commitment: tagged(301),
                collateral_asset_id: 0,
                collateral_decimals: 6,
                collateral_scale: 1_000_000,
                locked_collateral_commitment: tagged(401),
            },
            counters: StablecoinPoseidon2V8Counters {
                epoch_id: 0,
                minted_in_epoch: 0,
                total_debt: 0,
                sequence: 0,
            },
            credential_root: to_felts(public.credential_root),
            credential_depth: public.credential_depth,
            frozen: false,
            mint_enabled: true,
        };
        let registry =
            AssetRegistryV1::from_rows(public.chain_id, public.parent_height, &[row]).unwrap();
        let notes = [
            poseidon2_v8_default_note_nodes()[0],
            note_commitment(witness.inputs[1].note).unwrap(),
        ];
        let context = AssetLedgerContextV1 {
            chain_id: public.chain_id,
            reference_parent_hash: public.reference_parent_hash,
            parent_height: public.parent_height,
            note_root: AssetLedgerV1::root_for_authenticated_commitments(&notes).unwrap(),
            registry_root: to_words(registry.root()),
        };
        let ledger =
            AssetLedgerV1::from_authenticated_snapshot(context, registry, &notes, &[], &[])
                .unwrap();
        bind_spend(&ledger, &mut public, &mut witness, [None, Some(1)]);
        (ledger, public, witness)
    }

    fn bind_spend(
        ledger: &AssetLedgerV1,
        public: &mut AssetSpendPublic,
        witness: &mut AssetSpendWitness,
        positions: [Option<u32>; 2],
    ) {
        let context = ledger.context();
        let row = ledger.registry.row(public.asset_id).unwrap();
        public.chain_id = context.chain_id;
        public.reference_parent_hash = context.reference_parent_hash;
        public.parent_height = context.parent_height;
        public.note_root = context.note_root;
        public.registry_root = context.registry_root;
        public.policy_version = row.config.policy_version;
        public.credential_root = to_words(row.credential_root);
        public.credential_depth = row.credential_depth;
        public.frozen = row.frozen;
        public.mint_enabled = row.mint_enabled;
        public.issuer_commitment = to_words(row.config.issuer_commitment);
        for (slot, position) in positions.into_iter().enumerate() {
            if let Some(position) = position {
                let membership = ledger.note_membership(position).unwrap();
                assert_eq!(
                    membership.commitment,
                    note_commitment(witness.inputs[slot].note).unwrap()
                );
                witness.inputs[slot].position = position;
                witness.inputs[slot].siblings = membership.siblings;
                public.nullifiers[slot] = real_nullifier(
                    witness.inputs[slot].spend_key,
                    position,
                    witness.inputs[slot].note,
                )
                .unwrap();
            }
        }
        public.commitments = witness.outputs.map(|note| note_commitment(note).unwrap());
        public.ciphertext_commitments = TEST_CIPHERTEXTS
            .map(|bytes| transaction_core::hashing_pq::ciphertext_hash_bytes(&bytes));
    }

    fn controls_statement(
        ledger: &AssetLedgerV1,
        asset: u32,
        frozen: bool,
        tag: u64,
    ) -> PolicyAdminPublicV1 {
        let mut controls = ledger.registry.row(asset).unwrap().controls();
        controls.frozen = frozen;
        let prepared = ledger
            .registry
            .prepare_controls_update(ledger.registry.context(), asset, controls)
            .unwrap();
        PolicyAdminPublicV1::from_prepared(
            &prepared,
            ledger.reference_parent_hash,
            ledger.parent_height + 100,
            [tag; 7],
        )
        .unwrap()
    }

    // Expensive qualification is opt-in. Fixed ciphertext bytes exercise the
    // exact state/codec seam, not wallet encryption/decryption. Every accepted
    // transition below runs the genuine SMZE verifier; no test verifier or
    // boolean replaces it. The wallet artifact runner covers encryption.
    #[test]
    #[ignore = "real five-proof lifecycle; run only with the sole coordinator builder and usage headroom"]
    fn candidate_real_mint_transfer_burn_freeze_and_persisted_replay_lifecycle() {
        use sha2::{Digest as _, Sha256};
        use std::{
            fs,
            io::Write,
            path::{Path, PathBuf},
        };
        let evidence = std::env::var_os("HEGEMON_ASSET_LEDGER_EVIDENCE_DIR").map(PathBuf::from);
        if let Some(path) = &evidence {
            fs::create_dir(path)
                .expect("evidence directory must be absent and its parent must exist");
        }
        fn retain(path: Option<&Path>, name: &str, bytes: &[u8]) {
            if let Some(directory) = path {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(directory.join(name))
                    .unwrap();
                file.write_all(bytes).unwrap();
                file.sync_all().unwrap();
            }
        }
        fn hash(bytes: &[u8]) -> String {
            hex::encode(Sha256::digest(bytes))
        }
        let mut measurements = Vec::new();
        let mut prove_spend = |name: &str,
                               public: &AssetSpendPublic,
                               witness: &AssetSpendWitness| {
            let start = Instant::now();
            let proof = asset_spend_v1::prove_candidate(public, witness).unwrap();
            let elapsed = start.elapsed().as_secs_f64();
            let action = encode_asset_spend_action_v1(public, &TEST_CIPHERTEXTS, &proof).unwrap();
            retain(evidence.as_deref(), &format!("{name}.smze"), &proof);
            retain(evidence.as_deref(), &format!("{name}.action"), &action);
            measurements.push(serde_json::json!({"name": name, "proof_bytes": proof.len(), "action_bytes": action.len(), "proof_sha256": hash(&proof), "action_sha256": hash(&action), "proving_seconds": elapsed}));
            (proof, action)
        };
        let (mut ledger, mint_public, mint_witness) = spend_fixture();
        let initial = ledger.clone();
        let (mint_proof, mint_action) = prove_spend("mint", &mint_public, &mint_witness);
        // A framed, truncated inner proof reaches the real verifier and fails
        // without changing any state, including supply and replay histories.
        let truncated = encode_asset_spend_action_v1(
            &mint_public,
            &TEST_CIPHERTEXTS,
            &mint_proof[..mint_proof.len() / 2],
        )
        .unwrap();
        assert!(matches!(
            ledger.apply_action(&truncated),
            Err(AssetLedgerErrorV1::Proof(_))
        ));
        assert_eq!(ledger, initial);
        let mint_receipt = ledger.apply_action(&mint_action).unwrap();
        assert_eq!(
            ledger
                .registry
                .row(mint_public.asset_id)
                .unwrap()
                .counters
                .total_debt,
            10
        );
        assert_eq!(ledger.accepted_native_fees_since_snapshot(), 2);
        assert_eq!(ledger.commitments.len(), 5);
        let after_mint = ledger.clone();
        assert!(ledger.apply_action(&mint_action).is_err());
        assert_eq!(ledger, after_mint);
        // Rebinding stale roots cannot revive an already consumed nullifier.
        let mut replay = mint_public.clone();
        replay.note_root = ledger.note_root();
        replay.registry_root = to_words(ledger.registry.root());
        let replay = encode_asset_spend_action_v1(&replay, &TEST_CIPHERTEXTS, &mint_proof).unwrap();
        assert!(matches!(
            ledger.apply_action(&replay),
            Err(AssetLedgerErrorV1::SpentNullifier)
        ));
        assert_eq!(ledger, after_mint);

        let (mut transfer_public, mut transfer_witness) =
            asset_spend_v1::fixtures::fixture(TRANSFER, 4).unwrap();
        transfer_witness.inputs[0].note = mint_witness.outputs[1];
        transfer_witness.inputs[1].note = mint_witness.outputs[2];
        transfer_witness.outputs[0].value = 2;
        transfer_witness.outputs[1].value = 2;
        transfer_witness.outputs[2].value = 1;
        bind_spend(
            &ledger,
            &mut transfer_public,
            &mut transfer_witness,
            [
                Some(mint_receipt.output_positions[1]),
                Some(mint_receipt.output_positions[2]),
            ],
        );
        let (_, transfer_action) = prove_spend("transfer", &transfer_public, &transfer_witness);

        let freeze_public = controls_statement(&ledger, mint_public.asset_id, true, 77);
        let freeze_start = Instant::now();
        let freeze_proof = admin::prove_candidate(
            &freeze_public,
            &PolicyAdminWitnessV1 {
                secret: ADMIN_SECRET,
            },
        )
        .unwrap();
        let freeze_seconds = freeze_start.elapsed().as_secs_f64();
        retain(evidence.as_deref(), "freeze.smze", &freeze_proof);
        retain(
            evidence.as_deref(),
            "freeze.public",
            &freeze_public.binding_bytes(),
        );
        let before_freeze = ledger.clone();
        assert!(matches!(
            ledger.apply_controls_update(&freeze_public, &freeze_proof[..freeze_proof.len() / 2]),
            Err(AssetLedgerErrorV1::Proof(_))
        ));
        assert_eq!(ledger, before_freeze);
        ledger
            .apply_controls_update(&freeze_public, &freeze_proof)
            .unwrap();
        let frozen = ledger.clone();
        assert!(ledger.apply_action(&transfer_action).is_err());
        assert_eq!(ledger, frozen);
        for operation in [TRANSFER, MINT, BURN] {
            for policy_mode in [0, 1] {
                let mut public = transfer_public.clone();
                public.registry_root = to_words(ledger.registry.root());
                public.frozen = true;
                public.operation = operation;
                public.magnitude = if operation == TRANSFER { 0 } else { 1 };
                public.policy_mode = policy_mode;
                public.secret_release = u64::from(policy_mode == 1);
                public.released_secret = if policy_mode == 1 { [37; 32] } else { [0; 32] };
                let action =
                    encode_asset_spend_action_v1(&public, &TEST_CIPHERTEXTS, &mint_proof).unwrap();
                assert!(matches!(
                    ledger.apply_action(&action),
                    Err(AssetLedgerErrorV1::Registry(AssetRegistryErrorV1::Frozen))
                ));
                assert_eq!(ledger, frozen);
            }
        }
        let unfreeze_public = controls_statement(&ledger, mint_public.asset_id, false, 78);
        let unfreeze_start = Instant::now();
        let unfreeze_proof = admin::prove_candidate(
            &unfreeze_public,
            &PolicyAdminWitnessV1 {
                secret: ADMIN_SECRET,
            },
        )
        .unwrap();
        let unfreeze_seconds = unfreeze_start.elapsed().as_secs_f64();
        retain(evidence.as_deref(), "unfreeze.smze", &unfreeze_proof);
        retain(
            evidence.as_deref(),
            "unfreeze.public",
            &unfreeze_public.binding_bytes(),
        );
        ledger
            .apply_controls_update(&unfreeze_public, &unfreeze_proof)
            .unwrap();
        assert_eq!(
            to_words(ledger.registry.root()),
            transfer_public.registry_root,
            "freeze/unfreeze restored exactly the earlier registry root"
        );
        let before_replay = ledger.clone();
        assert!(matches!(
            ledger.apply_controls_update(&freeze_public, &freeze_proof),
            Err(AssetLedgerErrorV1::AdminReplay)
        ));
        assert_eq!(ledger, before_replay);
        ledger = AssetLedgerV1::restore_authenticated_snapshot(ledger.snapshot()).unwrap();
        assert!(matches!(
            ledger.apply_controls_update(&freeze_public, &freeze_proof),
            Err(AssetLedgerErrorV1::AdminReplay)
        ));
        assert_eq!(ledger, before_replay);
        let transfer_receipt = ledger.apply_action(&transfer_action).unwrap();
        assert_eq!(
            ledger
                .registry
                .row(mint_public.asset_id)
                .unwrap()
                .counters
                .total_debt,
            10
        );
        assert_eq!(ledger.accepted_native_fees_since_snapshot(), 4);

        let (mut burn_public, mut burn_witness) =
            asset_spend_v1::fixtures::fixture(BURN, 4).unwrap();
        burn_witness.inputs[0].note = transfer_witness.outputs[1];
        burn_witness.inputs[1].note = transfer_witness.outputs[2];
        for output in &mut burn_witness.outputs {
            output.value = 0;
        }
        burn_public.magnitude = 2;
        burn_public.fee = 1;
        bind_spend(
            &ledger,
            &mut burn_public,
            &mut burn_witness,
            [
                Some(transfer_receipt.output_positions[1]),
                Some(transfer_receipt.output_positions[2]),
            ],
        );
        let (_, burn_action) = prove_spend("burn", &burn_public, &burn_witness);
        ledger.apply_action(&burn_action).unwrap();
        assert_eq!(
            ledger
                .registry
                .row(mint_public.asset_id)
                .unwrap()
                .counters
                .total_debt,
            8
        );
        assert_eq!(ledger.accepted_native_fees_since_snapshot(), 5);
        assert_eq!(ledger.commitments.len(), 11);
        assert_eq!(ledger.spent_nullifiers.len(), 6);
        assert_eq!(ledger.admin_action_ids.len(), 2);
        assert_eq!(
            AssetLedgerV1::restore_authenticated_snapshot(ledger.snapshot()).unwrap(),
            ledger
        );
        measurements.push(serde_json::json!({"name":"freeze", "proof_bytes": freeze_proof.len(), "proof_sha256": hash(&freeze_proof), "proving_seconds": freeze_seconds}));
        measurements.push(serde_json::json!({"name":"unfreeze", "proof_bytes": unfreeze_proof.len(), "proof_sha256": hash(&unfreeze_proof), "proving_seconds": unfreeze_seconds}));
        let report = serde_json::json!({
            "schema":"Hegemon.AssetLedger.RealCandidateLifecycle.v1",
            "asset_relation_id": asset_spend_v1::RELATION_ID,
            "asset_relation_source_sha512": hex::encode(asset_spend_v1::relation_digest()),
            "admin_relation_id": admin::RELATION_ID,
            "admin_relation_source_sha512": hex::encode(admin::relation_digest()),
            "proofs": measurements,
            "final_asset_debt":8, "accepted_native_fees":5,
            "note_count":11, "consumed_nullifiers":6, "consumed_admin_actions":2,
            "real_verifiers_used":true, "production_authorized":false,
        });
        let bytes = serde_json::to_vec_pretty(&report).unwrap();
        retain(evidence.as_deref(), "receipt.json", &bytes);
        eprintln!("{}", String::from_utf8(bytes).unwrap());
    }
}
