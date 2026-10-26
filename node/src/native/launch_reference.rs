//! Finite historical references for the separately authorized launch routes.
//!
//! This module neither verifies a proof nor authenticates arbitrary checkpoints.
//! Storage supplies checkpoints from the selected canonical chain, or from its
//! already validated staged reorg prefix. A hash-indexed orphan lookup is not a
//! valid source. Exact proof verification, source authority at actual inclusion,
//! current/batch nullifier exclusion and lifetime proof budgets remain mandatory.
//! No method changes a carrier or any public field covered by its proof.

use super::launch_v8_verifier::LaunchStartup;
use super::poseidon2_v8_state::{Poseidon2V8BlockContext, Poseidon2V8NoteRoot, Poseidon2V8Root};
use transaction_circuit::{
    private_spend::PrivateSpendPublic,
    smallwood_htlc::{HtlcAction, HtlcStatement},
    smallwood_poseidon2_v8_rp06::Rp06PublicStatement,
};

/// Distance is measured between the proof's reference and the inclusion parent.
/// A reference at H is therefore usable in blocks H+1 through H+13 inclusive.
pub(crate) use protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW;
const MAX_REFERENCE_HEIGHT: u64 = (1_u64 << 48) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaunchReferenceRoute {
    Rp06,
    HtlcLock,
    HtlcClaim,
    HtlcRefund,
    PrivateSpend,
    AssetSpend,
    AssetAdmin,
}
impl LaunchReferenceRoute {
    const fn window(self) -> u64 {
        match self {
            // Lock proves reference_height < the private timeout. Accepting an
            // older Lock could cross that timeout at inclusion.
            Self::HtlcLock => 0,
            // Refund's lower bound remains true at later heights. Claim has no
            // upper timeout predicate in this relation; do not invent one here.
            Self::Rp06 | Self::HtlcClaim | Self::HtlcRefund | Self::PrivateSpend
                | Self::AssetSpend | Self::AssetAdmin => LAUNCH_REFERENCE_WINDOW,
        }
    }
}

/// Pinned source-selected identity; this value does not itself confer authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LaunchReferenceContext {
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    manifest_digest: [u8; 64],
    activation: u64,
    end: Option<u64>,
    static_stable_root: Poseidon2V8Root,
}
impl LaunchReferenceContext {
    pub(crate) fn from_startup(startup: LaunchStartup) -> Result<Self, String> {
        if startup.deactivation_height_exclusive().is_none() && !startup.has_ongoing_hgn_authority() {
            return Err("reference context lacks explicit ongoing HGN authority".into());
        }
        let context = Self {
            chain_id: startup.chain_id(),
            genesis_hash: startup.activation_genesis_hash(),
            manifest_digest: startup.manifest_digest(),
            activation: startup.activation_height(),
            end: startup.deactivation_height_exclusive(),
            static_stable_root: startup.stablecoin_genesis_root(),
        };
        context.validate()?;
        Ok(context)
    }

    fn validate(self) -> Result<(), String> {
        if self.chain_id == [0; 32]
            || self.genesis_hash == [0; 32]
            || self.manifest_digest == [0; 64]
            || self.activation == 0
            || self.activation > MAX_REFERENCE_HEIGHT
            || self.end.is_some_and(|end| self.activation >= end || end > MAX_REFERENCE_HEIGHT + 1)
        {
            return Err("invalid launch reference chain identity or finite lifetime".into());
        }
        Ok(())
    }

    pub(crate) fn require_genesis(
        self,
        hash: [u8; 32],
        stable_root: Poseidon2V8Root,
    ) -> Result<(), String> {
        if hash != self.genesis_hash || stable_root != self.static_stable_root {
            return Err("launch reference storage genesis differs from source context".into());
        }
        Ok(())
    }
    /// A local lifetime predicate for deciding whether a parent snapshot can
    /// serve any future launch proof. This does not authorize an empty block.
    pub(crate) fn permits_launch_after_parent(self, parent: u64) -> bool {
        parent.checked_add(1).is_some_and(|height| {
            height >= self.activation && self.end.is_none_or(|end| height < end) && height <= MAX_REFERENCE_HEIGHT
        })
    }
    pub(crate) fn first_reference_parent(self, parent: u64) -> Result<u64, String> {
        self.validate()?;
        self.require_inclusion_height(
            parent
                .checked_add(1)
                .ok_or("launch reference parent overflow")?,
        )?;
        Ok(parent
            .saturating_sub(LAUNCH_REFERENCE_WINDOW)
            .max(self.activation - 1))
    }

    fn require_inclusion_height(self, height: u64) -> Result<(), String> {
        if height < self.activation || self.end.is_some_and(|end| height >= end) || height > MAX_REFERENCE_HEIGHT {
            return Err("launch reference inclusion outside source lifetime".into());
        }
        Ok(())
    }
}

/// Distinct authenticated registry commitment: never a native stablecoin root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalAssetRegistryRoot([u64; 7]);
impl CanonicalAssetRegistryRoot {
    pub(crate) fn new(limbs: [u64; 7]) -> Result<Self, String> {
        if limbs.iter().any(|word| *word >= 0xffff_ffff_0000_0001) {
            return Err("noncanonical asset registry root".into());
        }
        Ok(Self(limbs))
    }
    pub(crate) const fn limbs(self) -> [u64; 7] { self.0 }
}

/// One authenticated block-end snapshot, including all reward/funding appends.
/// Construction only checks local shape. The caller must authenticate the block
/// and its state against the selected canonical/staged chain before using it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalLaunchCheckpoint {
    hash: [u8; 32],
    parent_hash: [u8; 32],
    height: u64,
    note_anchor: Poseidon2V8NoteRoot,
    static_stable_root: Poseidon2V8Root,
    asset_registry_root: Option<CanonicalAssetRegistryRoot>,
}
impl CanonicalLaunchCheckpoint {
    pub(crate) fn with_asset_registry_root(mut self, root: Option<CanonicalAssetRegistryRoot>) -> Self {
        self.asset_registry_root = root;
        self
    }
    pub(crate) const fn asset_registry_root(self) -> Option<CanonicalAssetRegistryRoot> {
        self.asset_registry_root
    }
    pub(crate) const fn height(self) -> u64 {
        self.height
    }
    pub(crate) const fn hash(self) -> [u8; 32] {
        self.hash
    }
    pub(crate) const fn note_anchor(self) -> Poseidon2V8NoteRoot {
        self.note_anchor
    }
    pub(crate) const fn static_stable_root(self) -> Poseidon2V8Root {
        self.static_stable_root
    }

    pub(crate) fn new(
        hash: [u8; 32],
        parent_hash: [u8; 32],
        height: u64,
        note_anchor: Poseidon2V8NoteRoot,
        static_stable_root: Poseidon2V8Root,
    ) -> Result<Self, String> {
        if height > MAX_REFERENCE_HEIGHT
            || hash == [0; 32]
            || hash == parent_hash
            || (height == 0 && parent_hash != [0; 32])
            || (height != 0 && parent_hash == [0; 32])
        {
            return Err("invalid launch canonical checkpoint height/hash shape".into());
        }
        Ok(Self {
            hash,
            parent_hash,
            height,
            note_anchor,
            static_stable_root,
            asset_registry_root: None,
        })
    }
}

/// Finite, linked snapshots ending at the exact parent selected for application.
/// Keep this immutable during a validation batch. Rebuild it after a tip/reorg
/// change; never extend it with an unverified block from a proposed payload.
#[derive(Clone, Debug)]
pub(crate) struct CanonicalLaunchReferences {
    context: LaunchReferenceContext,
    parent_hash: [u8; 32],
    parent_height: u64,
    checkpoints: Vec<CanonicalLaunchCheckpoint>,
}
impl CanonicalLaunchReferences {
    pub(crate) fn parent_note_anchor(&self) -> Poseidon2V8NoteRoot {
        self.checkpoints.last().expect("validated nonempty checkpoint window").note_anchor
    }
    pub(crate) const fn context(&self) -> LaunchReferenceContext {
        self.context
    }

    /// Trusted integration seam: callers provide authenticated storage/staged
    /// ancestry, never arbitrary peer data. The linked shape checks below detect
    /// accidental branch stitching but are not proof-of-work/consensus checks.
    pub(crate) fn from_validated_chain(
        context: LaunchReferenceContext,
        current_parent_hash: [u8; 32],
        current_parent_height: u64,
        checkpoints: Vec<CanonicalLaunchCheckpoint>,
    ) -> Result<Self, String> {
        context.validate()?;
        let inclusion = current_parent_height
            .checked_add(1)
            .ok_or("launch reference parent height overflow")?;
        context.require_inclusion_height(inclusion)?;
        let first_height = context.first_reference_parent(current_parent_height)?;
        let expected_len = (current_parent_height - first_height + 1) as usize;
        if checkpoints.len() != expected_len {
            return Err("launch reference checkpoint window is incomplete or oversized".into());
        }
        for (index, checkpoint) in checkpoints.iter().enumerate() {
            if checkpoint.height != first_height + index as u64
                || checkpoint.static_stable_root != context.static_stable_root
                || (checkpoint.height == 0 && checkpoint.hash != context.genesis_hash)
                || checkpoints[..index]
                    .iter()
                    .any(|previous| previous.hash == checkpoint.hash)
                || (index > 0 && checkpoint.parent_hash != checkpoints[index - 1].hash)
            {
                return Err(
                    "launch reference checkpoints disagree with canonical ancestry/state".into(),
                );
            }
        }
        let last = checkpoints
            .last()
            .ok_or("launch reference checkpoint window is empty")?;
        if last.hash != current_parent_hash || last.height != current_parent_height {
            return Err("launch reference checkpoint window ends at a different parent".into());
        }
        Ok(Self {
            context,
            parent_hash: current_parent_hash,
            parent_height: current_parent_height,
            checkpoints,
        })
    }

    pub(crate) fn validate_rp06(
        &self,
        statement: &Rp06PublicStatement,
        block: Poseidon2V8BlockContext,
    ) -> Result<CheckedLaunchReference, String> {
        statement.validate().map_err(|e| format!("{e:?}"))?;
        let before = statement
            .base
            .stablecoin
            .before_root
            .map(|v| v.as_canonical_u64());
        let after = statement
            .base
            .stablecoin
            .after_root
            .map(|v| v.as_canonical_u64());
        if before != self.context.static_stable_root.limbs()
            || after != self.context.static_stable_root.limbs()
        {
            return Err("RP06 reference changes the pinned static stablecoin root".into());
        }
        self.validate_reference(
            LaunchReferenceRoute::Rp06,
            statement.chain_id,
            statement.base.stablecoin.parent_height,
            None, // RP06 binds height and note root, not a block hash.
            Poseidon2V8NoteRoot::new(statement.base.merkle_root).map_err(|e| e.to_string())?,
            block,
        )
    }

    pub(crate) fn validate_htlc(
        &self,
        statement: &HtlcStatement,
        block: Poseidon2V8BlockContext,
    ) -> Result<CheckedLaunchReference, String> {
        statement.validate_structure().map_err(|e| e.to_string())?;
        let route = match statement.action {
            HtlcAction::Lock => LaunchReferenceRoute::HtlcLock,
            HtlcAction::Claim => LaunchReferenceRoute::HtlcClaim,
            HtlcAction::Refund => LaunchReferenceRoute::HtlcRefund,
        };
        self.validate_reference(
            route,
            statement.network_id,
            statement.parent_height,
            Some(statement.parent_hash),
            Poseidon2V8NoteRoot::new(statement.merkle_root).map_err(|e| e.to_string())?,
            block,
        )
    }

    pub(crate) fn validate_private_spend(
        &self, statement: &PrivateSpendPublic, block: Poseidon2V8BlockContext,
    ) -> Result<CheckedLaunchReference, String> {
        self.validate_reference(
            LaunchReferenceRoute::PrivateSpend, statement.chain_id,
            statement.reference_parent_height, Some(statement.reference_parent_hash),
            Poseidon2V8NoteRoot::new(statement.merkle_root).map_err(|e| e.to_string())?, block,
        )
    }

    pub(crate) fn validate_asset_spend(
        &self, public: &transaction_circuit::asset_spend_v1::AssetSpendPublic,
        block: Poseidon2V8BlockContext,
    ) -> Result<CheckedLaunchReference, String> {
        self.validate_asset_reference(LaunchReferenceRoute::AssetSpend, public.chain_id,
            public.parent_height, public.reference_parent_hash, Some(public.note_root),
            public.registry_root, block)
    }

    pub(crate) fn validate_asset_admin(
        &self, public: &transaction_circuit::asset_policy_admin_v1::PolicyAdminPublicV1,
        block: Poseidon2V8BlockContext,
    ) -> Result<CheckedLaunchReference, String> {
        self.validate_asset_reference(LaunchReferenceRoute::AssetAdmin, public.chain_id,
            public.parent_height, public.reference_parent_hash, None, public.registry_root, block)
    }

    /// Recovery administration authenticates the actual current parent only.
    pub(crate) fn validate_recovery_admin_current(
        &self, chain_id: [u8; 32], block: Poseidon2V8BlockContext, registry: [u64; 7],
    ) -> Result<CheckedLaunchReference, String> {
        self.validate_asset_reference(LaunchReferenceRoute::AssetAdmin, chain_id,
            block.parent_height(), block.parent_hash(), None, registry, block)
    }

    fn validate_asset_reference(
        &self, route: LaunchReferenceRoute, chain_id: [u8; 32], height: u64,
        hash: [u8; 32], note: Option<[u64; 7]>, registry: [u64; 7],
        block: Poseidon2V8BlockContext,
    ) -> Result<CheckedLaunchReference, String> {
        let distance = self.parent_height.checked_sub(height)
            .ok_or("asset proof reference is in the future")?;
        if distance > route.window() {
            return Err("asset proof reference exceeds its route window".into());
        }
        let checkpoint = self.checkpoints.iter().find(|row| row.height == height)
            .ok_or("asset proof reference has no canonical registry checkpoint")?;
        let root = checkpoint.asset_registry_root
            .ok_or("asset proof reference has no authenticated registry")?;
        if root.limbs() != registry {
            return Err("asset proof registry root differs from reference checkpoint".into());
        }
        let anchor = match note {
            Some(words) => Poseidon2V8NoteRoot::new(words).map_err(|error| error.to_string())?,
            None => checkpoint.note_anchor,
        };
        let mut checked = self.validate_reference(route, chain_id, height, Some(hash), anchor, block)?;
        checked.asset_registry_root = Some(root);
        Ok(checked)
    }

    fn validate_reference(
        &self,
        route: LaunchReferenceRoute,
        chain_id: [u8; 32],
        reference_height: u64,
        reference_hash: Option<[u8; 32]>,
        note_anchor: Poseidon2V8NoteRoot,
        block: Poseidon2V8BlockContext,
    ) -> Result<CheckedLaunchReference, String> {
        if chain_id != self.context.chain_id {
            return Err("launch proof reference is for another chain".into());
        }
        if block.parent_height() != self.parent_height || block.parent_hash() != self.parent_hash {
            return Err(
                "launch reference snapshots are stale for the selected application parent".into(),
            );
        }
        self.context.require_inclusion_height(block.height())?;
        let distance = self
            .parent_height
            .checked_sub(reference_height)
            .ok_or("launch proof reference is in the future")?;
        if distance > route.window() {
            return Err("launch proof reference exceeds its route window".into());
        }
        self.context.require_inclusion_height(
            reference_height
                .checked_add(1)
                .ok_or("launch proof reference height overflow")?,
        )?;
        let checkpoint = self
            .checkpoints
            .iter()
            .find(|checkpoint| checkpoint.height == reference_height)
            .ok_or("launch proof reference has no canonical checkpoint")?;
        if reference_hash.is_some_and(|hash| hash != checkpoint.hash)
            || note_anchor != checkpoint.note_anchor
        {
            return Err(
                "launch proof reference hash/note root is not canonical at its height".into(),
            );
        }
        Ok(CheckedLaunchReference {
            route,
            reference_height,
            reference_hash: checkpoint.hash,
            note_anchor,
            static_stable_root: checkpoint.static_stable_root,
            application_parent_height: block.parent_height(),
            application_parent_hash: block.parent_hash(),
            application_height: block.height(),
            asset_registry_root: None,
        })
    }
}

/// Checked reference metadata, not proof or production-authority evidence.
/// The original reference is retained separately from actual application height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CheckedLaunchReference {
    route: LaunchReferenceRoute,
    reference_height: u64,
    reference_hash: [u8; 32],
    note_anchor: Poseidon2V8NoteRoot,
    static_stable_root: Poseidon2V8Root,
    application_parent_height: u64,
    application_parent_hash: [u8; 32],
    application_height: u64,
    asset_registry_root: Option<CanonicalAssetRegistryRoot>,
}
impl CheckedLaunchReference {
    pub(crate) const fn asset_registry_root(self) -> Option<CanonicalAssetRegistryRoot> {
        self.asset_registry_root
    }
    pub(crate) const fn route(self) -> LaunchReferenceRoute {
        self.route
    }
    pub(crate) const fn reference_height(self) -> u64 {
        self.reference_height
    }
    pub(crate) const fn reference_hash(self) -> [u8; 32] {
        self.reference_hash
    }
    pub(crate) const fn note_anchor(self) -> Poseidon2V8NoteRoot {
        self.note_anchor
    }
    pub(crate) const fn static_stable_root(self) -> Poseidon2V8Root {
        self.static_stable_root
    }
    pub(crate) const fn application_parent_height(self) -> u64 {
        self.application_parent_height
    }
    pub(crate) const fn application_parent_hash(self) -> [u8; 32] {
        self.application_parent_hash
    }
    pub(crate) const fn application_height(self) -> u64 {
        self.application_height
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transaction_circuit::smallwood_htlc::HTLC_STATEMENT_VERSION;
    use transaction_circuit::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8PublicStatement;

    fn hash(height: u64) -> [u8; 32] {
        let mut hash = [1; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        hash
    }
    fn root(height: u64) -> Poseidon2V8NoteRoot {
        Poseidon2V8NoteRoot::new([height + 1; 7]).unwrap()
    }
    fn context() -> LaunchReferenceContext {
        LaunchReferenceContext {
            chain_id: [2; 32],
            genesis_hash: hash(0),
            manifest_digest: [3; 64],
            activation: 1,
            end: Some(100),
            static_stable_root: Poseidon2V8Root::new([0; 7]).unwrap(),
        }
    }
    #[test]
    fn ongoing_reference_keeps_codec_freshness_and_canonical_chain_bounds() {
        let mut context = context();
        context.end = None;
        context.validate().unwrap();
        for height in [100_001, 621_730_875, MAX_REFERENCE_HEIGHT] {
            assert!(context.require_inclusion_height(height).is_ok());
            assert!(context.permits_launch_after_parent(height - 1));
        }
        assert!(context.require_inclusion_height(0).is_err());
        assert!(context.require_inclusion_height(MAX_REFERENCE_HEIGHT + 1).is_err());
        assert!(!context.permits_launch_after_parent(MAX_REFERENCE_HEIGHT));
        assert!(context.require_genesis([99; 32], context.static_stable_root).is_err());
        assert!(!protocol_versioning::launch_reference_policy::launch_reference_distance_allowed(0, 100_001, false));
    }

    fn checkpoints(tip: u64, context: LaunchReferenceContext) -> Vec<CanonicalLaunchCheckpoint> {
        (tip.saturating_sub(12).max(context.activation - 1)..=tip)
            .map(|height| {
                CanonicalLaunchCheckpoint::new(
                    hash(height),
                    if height == 0 {
                        [0; 32]
                    } else {
                        hash(height - 1)
                    },
                    height,
                    root(height),
                    context.static_stable_root,
                )
                .unwrap()
            })
            .collect()
    }
    fn fixture(tip: u64) -> (CanonicalLaunchReferences, Poseidon2V8BlockContext) {
        let refs = CanonicalLaunchReferences::from_validated_chain(
            context(),
            hash(tip),
            tip,
            checkpoints(tip, context()),
        )
        .unwrap();
        let block = Poseidon2V8BlockContext::new(tip, hash(tip), tip + 1, hash(tip + 1)).unwrap();
        (refs, block)
    }
    fn htlc(action: HtlcAction, height: u64) -> HtlcStatement {
        HtlcStatement {
            version: HTLC_STATEMENT_VERSION,
            action,
            network_id: context().chain_id,
            parent_hash: hash(height),
            parent_height: height,
            merkle_root: root(height).limbs(),
            nullifier: [7; 7],
            output_commitment: [8; 7],
            ciphertext_commitment: [9; 48],
            fee: 0,
            revealed_secret: None,
        }
    }
    fn rp06(height: u64) -> Rp06PublicStatement {
        let mut base = SmallwoodPoseidon2V8PublicStatement::default();
        base.stablecoin.parent_height = height;
        base.merkle_root = root(height).limbs();
        Rp06PublicStatement {
            base,
            chain_id: context().chain_id,
        }
    }

    #[test]
    fn reference_window_accepts_twelve_rejects_thirteen_and_future() {
        let (refs, block) = fixture(20);
        for height in [20, 8] {
            let statement = rp06(height);
            let original = statement;
            let checked = refs.validate_rp06(&statement, block).unwrap();
            assert_eq!(statement, original);
            assert_eq!(checked.reference_height(), height);
            assert_eq!(checked.reference_hash(), hash(height));
            assert_eq!(checked.application_parent_height(), 20);
            assert_eq!(checked.application_height(), 21);
            assert_eq!(checked.route(), LaunchReferenceRoute::Rp06);
        }
        for height in [7, 21] {
            assert!(refs.validate_rp06(&rp06(height), block).is_err());
        }
        let mut overflow = rp06(8);
        overflow.base.stablecoin.parent_height = u64::MAX;
        assert!(refs.validate_rp06(&overflow, block).is_err());
        for action in [HtlcAction::Claim, HtlcAction::Refund] {
            let statement = htlc(action, 8);
            let original = statement.clone();
            assert!(refs.validate_htlc(&statement, block).is_ok());
            assert_eq!(statement, original);
            for height in [7, 21] {
                assert!(refs.validate_htlc(&htlc(action, height), block).is_err());
            }
        }
    }

    #[test]
    fn lock_requires_current_parent_and_genesis_reference_is_allowed() {
        let (refs, block) = fixture(20);
        assert!(refs
            .validate_htlc(&htlc(HtlcAction::Lock, 20), block)
            .is_ok());
        assert!(refs
            .validate_htlc(&htlc(HtlcAction::Lock, 19), block)
            .is_err());
        let (refs, block) = fixture(0);
        assert!(refs
            .validate_htlc(&htlc(HtlcAction::Lock, 0), block)
            .is_ok());
        assert!(refs.validate_rp06(&rp06(0), block).is_ok());
    }

    #[test]
    fn proof_chain_hash_anchor_and_actual_parent_are_bound() {
        let (refs, block) = fixture(20);
        let statement = htlc(HtlcAction::Claim, 8);
        let mut changed = statement.clone();
        changed.network_id[0] ^= 1;
        assert!(refs.validate_htlc(&changed, block).is_err());
        let mut changed = statement.clone();
        changed.parent_hash[0] ^= 1;
        assert!(refs.validate_htlc(&changed, block).is_err());
        let mut changed = statement.clone();
        changed.merkle_root = root(9).limbs();
        assert!(refs.validate_htlc(&changed, block).is_err());
        let wrong_parent = Poseidon2V8BlockContext::new(20, [4; 32], 21, hash(21)).unwrap();
        assert!(refs.validate_htlc(&statement, wrong_parent).is_err());
        let later = Poseidon2V8BlockContext::new(21, hash(21), 22, hash(22)).unwrap();
        assert!(refs.validate_htlc(&statement, later).is_err());
        let mut changed = rp06(8);
        changed.chain_id[0] ^= 1;
        assert!(refs.validate_rp06(&changed, block).is_err());
        let mut changed = rp06(8);
        changed.base.merkle_root = root(9).limbs();
        assert!(refs.validate_rp06(&changed, block).is_err());
        let mut changed = rp06(8);
        changed.base.stablecoin.before_root[0] =
            transaction_core::poseidon2_width16::Felt::from_u64(1);
        assert!(refs.validate_rp06(&changed, block).is_err());
        let mut changed = rp06(8);
        changed.base.stablecoin.after_root[0] =
            transaction_core::poseidon2_width16::Felt::from_u64(1);
        assert!(refs.validate_rp06(&changed, block).is_err());
    }

    #[test]
    fn snapshots_reject_stitching_missing_rows_duplicates_orphan_tip_and_state_changes() {
        let ctx = context();
        let good = checkpoints(20, ctx);
        let rejected = |rows| {
            assert!(
                CanonicalLaunchReferences::from_validated_chain(ctx, hash(20), 20, rows).is_err()
            )
        };
        let mut rows = good.clone();
        rows[3].parent_hash = [6; 32];
        rejected(rows);
        let mut rows = good.clone();
        rows[3].hash = rows[2].hash;
        rejected(rows);
        let mut rows = good.clone();
        rows[3].height += 1;
        rejected(rows);
        let mut rows = good.clone();
        rows.remove(3);
        rejected(rows);
        let mut rows = good.clone();
        rows[3].static_stable_root = Poseidon2V8Root::new([1; 7]).unwrap();
        rejected(rows);
        let mut rows = good;
        rows.last_mut().unwrap().hash = [6; 32];
        rejected(rows);
        let mut rows = checkpoints(0, ctx);
        rows[0].hash = [6; 32];
        assert!(CanonicalLaunchReferences::from_validated_chain(ctx, [6; 32], 0, rows).is_err());
        assert!(CanonicalLaunchCheckpoint::new(
            [0; 32],
            hash(1),
            2,
            root(2),
            ctx.static_stable_root
        )
        .is_err());
        assert!(CanonicalLaunchCheckpoint::new(
            hash(2),
            [0; 32],
            2,
            root(2),
            ctx.static_stable_root
        )
        .is_err());
        assert!(CanonicalLaunchCheckpoint::new(
            hash(0),
            hash(1),
            0,
            root(0),
            ctx.static_stable_root
        )
        .is_err());
    }

    #[test]
    fn source_lifetime_uses_inclusion_height_and_references_cannot_precede_activation() {
        let mut ctx = context();
        ctx.activation = 10;
        ctx.end = Some(22);
        let rows = checkpoints(20, ctx);
        let refs =
            CanonicalLaunchReferences::from_validated_chain(ctx, hash(20), 20, rows).unwrap();
        let block = Poseidon2V8BlockContext::new(20, hash(20), 21, hash(21)).unwrap();
        assert!(refs.validate_rp06(&rp06(9), block).is_ok());
        assert!(refs.validate_rp06(&rp06(8), block).is_err());
        assert!(CanonicalLaunchReferences::from_validated_chain(ctx, hash(8), 8, vec![]).is_err());
        assert!(CanonicalLaunchReferences::from_validated_chain(
            ctx,
            hash(21),
            21,
            checkpoints(21, ctx)
        )
        .is_err());
        ctx.chain_id = [0; 32];
        assert!(ctx.validate().is_err());
        ctx = context();
        ctx.genesis_hash = [0; 32];
        assert!(ctx.validate().is_err());
        ctx = context();
        ctx.manifest_digest = [0; 64];
        assert!(ctx.validate().is_err());
    }

    #[test]
    fn complete_historical_root_is_independent_of_current_append_history() {
        let (refs, block) = fixture(20);
        let checked = refs
            .validate_htlc(&htlc(HtlcAction::Refund, 8), block)
            .unwrap();
        assert_eq!(checked.note_anchor(), root(8));
        assert_eq!(checked.static_stable_root(), context().static_stable_root);
        // The module deliberately has no current 100-append-root list to evict
        // this authenticated block-end root when intervening blocks are busy.
        assert_ne!(checked.note_anchor(), root(20));
    }
    #[test]
    fn asset_reference_binds_canonical_registry_note_and_application_parent() {
        let ctx = context();
        let registry = CanonicalAssetRegistryRoot::new([77; 7]).unwrap();
        let rows = checkpoints(20, ctx).into_iter()
            .map(|row| row.with_asset_registry_root(Some(registry))).collect();
        let refs = CanonicalLaunchReferences::from_validated_chain(ctx, hash(20), 20, rows).unwrap();
        let block = Poseidon2V8BlockContext::new(20, hash(20), 21, hash(21)).unwrap();
        for height in [8, 20] {
            let checked = refs.validate_asset_reference(LaunchReferenceRoute::AssetSpend,
                ctx.chain_id, height, hash(height), Some(root(height).limbs()), registry.limbs(), block).unwrap();
            assert_eq!(checked.asset_registry_root(), Some(registry));
            assert_eq!(checked.reference_height(), height);
            assert_eq!(checked.application_parent_height(), 20);
            assert_eq!(checked.application_height(), 21);
        }
        for height in [7, 21] {
            assert!(refs.validate_asset_reference(LaunchReferenceRoute::AssetSpend,
                ctx.chain_id, height, hash(height), Some(root(height).limbs()), registry.limbs(), block).is_err());
        }
        assert!(refs.validate_asset_reference(LaunchReferenceRoute::AssetSpend,
            ctx.chain_id, 8, hash(9), Some(root(8).limbs()), registry.limbs(), block).is_err());
        assert!(refs.validate_asset_reference(LaunchReferenceRoute::AssetSpend,
            ctx.chain_id, 8, hash(8), Some(root(9).limbs()), registry.limbs(), block).is_err());
        assert!(refs.validate_asset_reference(LaunchReferenceRoute::AssetAdmin,
            ctx.chain_id, 8, hash(8), None, [78; 7], block).is_err());
        let stale = Poseidon2V8BlockContext::new(21, hash(21), 22, hash(22)).unwrap();
        assert!(refs.validate_asset_reference(LaunchReferenceRoute::AssetAdmin,
            ctx.chain_id, 8, hash(8), None, registry.limbs(), stale).is_err());
        let missing = CanonicalLaunchReferences::from_validated_chain(ctx, hash(20), 20, checkpoints(20, ctx)).unwrap();
        assert!(missing.validate_asset_reference(LaunchReferenceRoute::AssetAdmin,
            ctx.chain_id, 8, hash(8), None, registry.limbs(), block).is_err());
    }

    #[test]
    fn recovery_admin_receipt_requires_current_canonical_registry_and_parent() {
        let ctx = context();
        let registry = CanonicalAssetRegistryRoot::new([77; 7]).unwrap();
        let rows = checkpoints(20, ctx).into_iter()
            .map(|row| row.with_asset_registry_root(Some(registry))).collect();
        let refs = CanonicalLaunchReferences::from_validated_chain(ctx, hash(20), 20, rows).unwrap();
        let block = Poseidon2V8BlockContext::new(20, hash(20), 21, hash(21)).unwrap();
        let receipt = refs.validate_recovery_admin_current(ctx.chain_id, block, registry.limbs()).unwrap();
        assert_eq!(receipt.reference_height(), 20);
        assert_eq!(receipt.reference_hash(), hash(20));
        assert_eq!(receipt.note_anchor(), root(20));
        assert_eq!(receipt.asset_registry_root(), Some(registry));
        assert!(refs.validate_recovery_admin_current(ctx.chain_id, block, [78; 7]).is_err());
        assert!(refs.validate_recovery_admin_current([99; 32], block, registry.limbs()).is_err());
        let stale = Poseidon2V8BlockContext::new(21, hash(21), 22, hash(22)).unwrap();
        assert!(refs.validate_recovery_admin_current(ctx.chain_id, stale, registry.limbs()).is_err());
    }

}
