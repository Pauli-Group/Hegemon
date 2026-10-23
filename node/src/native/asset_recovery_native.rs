//! Separate recovery leaf verification. Returned plans do not publish state.
//! Caller obtains ALL snapshots/references from one canonical block plan and
//! commits policy accounting, recovery state, notes/NFs/fees atomically.
use super::{
    asset_native,
    asset_recovery_profile::DevelopmentRecoveryV1,
    asset_recovery_state::{
        RecoveryAdminPlanV1, RecoveryCanonicalContextV1, RecoveryLedgerStateV1,
    },
    asset_state::AssetRegistryStateV1,
    launch_reference::{CanonicalAssetRegistryRoot, CanonicalLaunchReferences},
    launch_v8_verifier::LaunchStartup,
    network_profile::NativeNetworkIdentity,
    poseidon2_v8_state::{
        Poseidon2V8BlockContext, Poseidon2V8Commitment, Poseidon2V8NoteRoot, Poseidon2V8Nullifier,
        Poseidon2V8PublicTransition, Poseidon2V8Root,
    },
    KernelVersionBinding, PendingAction, FAMILY_SHIELDED_POOL,
};
use transaction_circuit::{
    asset_recovery_capsule_v1 as capsule, asset_recovery_spend_v1 as spend,
    asset_recovery_wire_v1 as wire, asset_spend_v1_wire as old_wire,
};
use transaction_core::{
    asset_recovery_v1::{RecoveryDescriptorV1, RecoveryPowersV1, RecoveryRowV1},
    asset_registry_v1::{AssetOperationV1, PreparedAssetAccountingV1},
};
pub(crate) const RECOVERY_SPEND_ACTION_ID: u16 = 18;
pub(crate) const RECOVERY_ADMIN_ACTION_ID: u16 = 19;
type Digest = [u64; 7];
type Result<T> = core::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn words(d: [transaction_core::poseidon2_width16::Felt; 7]) -> Digest {
    d.map(|x| x.as_canonical_u64())
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RecoveryDevelopmentAuthorityV1 {
    legacy: asset_native::AssetDevelopmentAuthorityV1,
    descriptors: [Option<RecoveryDescriptorV1>; 16],
    descriptor_len: usize,
    spend_relation: [u8; 64],
    admin_relation: [u8; 64],
    capsule_relation: [u8; 64],
    max_proof_bytes: usize,
    chain: [u8; 32],
    genesis: [u8; 32],
    static_root: Poseidon2V8Root,
    note_genesis_root: Poseidon2V8NoteRoot,
}
impl RecoveryDevelopmentAuthorityV1 {
    /// selected MUST be read from the manifest whose digest Startup authenticates;
    /// root wiring must never call this with a JSON/RPC-supplied replacement.
    pub(crate) fn from_selected_manifest(
        network: &NativeNetworkIdentity,
        genesis: [u8; 32],
        startup: LaunchStartup,
        selected: &DevelopmentRecoveryV1,
    ) -> Result<Self> {
        let legacy =
            asset_native::AssetDevelopmentAuthorityV1::from_source(network, genesis, startup)?
                .ok_or("recovery requires asset-enabled Development")?;
        // Match the actual authenticated selection, not merely another manifest
        // with current source digests. No runtime caller can install opt-ins.
        if network.development_recovery() != Some(selected) {
            return Err("recovery descriptor differs from authenticated network selection".into());
        }
        selected.validate().map_err(err)?;
        selected.require_qualified_geometry().map_err(err)?;
        let mut descriptors = [None; 16];
        for (slot, config) in descriptors.iter_mut().zip(&selected.initial_rows) {
            *slot = Some(RecoveryDescriptorV1 {
                asset_id: config.asset_id,
                stable_policy_id: config.stable_policy_id,
                policy_admin_commitment: config.policy_admin_commitment,
                archive_key_commitment: config.archive_key_commitment,
                maximum_powers: RecoveryPowersV1 {
                    transfer: config.maximum_powers_bits & 1 != 0,
                    burn: config.maximum_powers_bits & 2 != 0,
                },
            });
        }
        Ok(Self {
            legacy,
            descriptors,
            descriptor_len: selected.initial_rows.len(),
            spend_relation: spend::relation_digest(),
            admin_relation: transaction_circuit::asset_recovery_admin_v1::relation_digest(),
            capsule_relation: capsule::relation_digest(),
            max_proof_bytes: selected.max_proof_bytes.min(startup.max_proof_bytes()),
            chain: network.chain_id(),
            genesis,
            static_root: startup.stablecoin_genesis_root(),
            note_genesis_root: startup.note_genesis_root(),
        })
    }
    fn require_source(self) -> Result<()> {
        if self.spend_relation != spend::relation_digest()
            || self.admin_relation
                != transaction_circuit::asset_recovery_admin_v1::relation_digest()
            || self.capsule_relation != capsule::relation_digest()
        {
            return Err("recovery relation differs from its source authority".into());
        }
        Ok(())
    }
    pub(crate) fn require_route(
        self,
        height: u64,
        binding: KernelVersionBinding,
        family_id: u16,
        action_id: u16,
        proof_bytes: usize,
    ) -> Result<()> {
        self.legacy.require_height(height)?;
        self.require_source()?;
        if binding != native_binding()
            || family_id != FAMILY_SHIELDED_POOL
            || !matches!(
                action_id,
                RECOVERY_SPEND_ACTION_ID | RECOVERY_ADMIN_ACTION_ID
            )
            || proof_bytes == 0
            || proof_bytes > self.max_proof_bytes
            || proof_bytes > wire::MAX_PROOF_BYTES
        {
            return Err("recovery action differs from its exact finite source authority".into());
        }
        Ok(())
    }
    pub(crate) fn authorizes_route(
        self,
        height: u64,
        binding: KernelVersionBinding,
        family_id: u16,
        action_id: u16,
    ) -> bool {
        self.require_route(height, binding, family_id, action_id, 1)
            .is_ok()
    }
    fn require_block(&self, block: Poseidon2V8BlockContext) -> Result<()> {
        self.legacy.require_height(block.height())?;
        if block.parent_height() == 0 && block.parent_hash() != self.genesis {
            return Err("recovery genesis mismatch".into());
        }
        // Geometry and descriptor qualification were required before this
        // immutable, source-owned token could be constructed.
        self.require_source()
    }
    fn current<'a>(
        &self,
        block: Poseidon2V8BlockContext,
        assets: &'a AssetRegistryStateV1,
        recovery: &RecoveryLedgerStateV1,
    ) -> Result<()> {
        if assets.registry().context().chain_id != self.chain
            || assets.registry().context().parent_height != block.parent_height()
            || recovery.chain_id() != self.chain
            || recovery.parent_height() != block.parent_height()
        {
            return Err("recovery CURRENT snapshot context mismatch".into());
        }
        Ok(())
    }
    fn row(&self, recovery: &RecoveryLedgerStateV1, asset: u32) -> Result<RecoveryRowV1> {
        let row = *recovery.row(asset).map_err(err)?;
        let descriptor = self.descriptors[..self.descriptor_len]
            .iter()
            .flatten()
            .find(|r| r.asset_id == asset)
            .ok_or("recovery asset not in selected genesis")?;
        if row.descriptor != *descriptor {
            return Err("recovery immutable descriptor differs from genesis".into());
        }
        Ok(row)
    }
    pub(crate) fn preflight(
        &self,
        block: Poseidon2V8BlockContext,
        action: &PendingAction,
    ) -> Result<()> {
        self.require_block(block)?;
        NativeRecoveryActionViewV1::from_pending(*self, block.height(), action)?;
        Ok(())
    }
    /// The NF callback MUST read the canonical shared pool + prior same-block
    /// spends, not a wallet lock list or independently opened recovery database.
    pub(crate) fn prepare_spend<F>(
        &self,
        block: Poseidon2V8BlockContext,
        exact: &[u8],
        assets: &AssetRegistryStateV1,
        recovery: &RecoveryLedgerStateV1,
        parent_note: Poseidon2V8NoteRoot,
        references: &CanonicalLaunchReferences,
        mut is_spent: F,
    ) -> Result<RecoverySpendPlanV1>
    where
        F: FnMut(Digest) -> Result<bool>,
    {
        self.require_block(block)?;
        self.current(block, assets, recovery)?;
        let a = wire::decode_spend_ref(exact).map_err(err)?;
        let p = &a.public.base;
        if p.chain_id != self.chain || references.parent_note_anchor() != parent_note {
            return Err("recovery reference chain/note parent mismatch".into());
        }
        let checked = references.validate_asset_spend(p, block)?;
        let current_registry = CanonicalAssetRegistryRoot::new(words(assets.registry().root()))?;
        if checked.asset_registry_root() != Some(current_registry)
            || p.registry_root != current_registry.limbs()
        {
            return Err("recovery reference registry differs from CURRENT".into());
        }
        let row = self.row(recovery, p.asset_id)?;
        if row != a.public.row {
            return Err("recovery stale CURRENT control row/epoch".into());
        }
        let old = assets.registry().row(p.asset_id).map_err(err)?;
        if p.policy_version != old.config.policy_version
            || p.credential_root != words(old.credential_root)
            || p.credential_depth != old.credential_depth
            || p.frozen != old.frozen
            || p.mint_enabled != old.mint_enabled
            || p.issuer_commitment != words(old.config.issuer_commitment)
            || row.descriptor.policy_admin_commitment != words(old.config.policy_admin_commitment)
        {
            return Err("recovery CURRENT asset controls mismatch".into());
        }
        if p.frozen || p.nullifiers[0] == p.nullifiers[1] {
            return Err("recovery frozen asset or duplicate NF".into());
        }
        for nf in p.nullifiers {
            if nf == [0; 7] || is_spent(nf)? {
                return Err("recovery shared global NF already spent/zero".into());
            }
        }
        let operation = match p.operation {
            transaction_circuit::asset_spend_v1::TRANSFER => AssetOperationV1::Transfer,
            transaction_circuit::asset_spend_v1::MINT => AssetOperationV1::Mint,
            transaction_circuit::asset_spend_v1::BURN => AssetOperationV1::Burn,
            _ => return Err("recovery operation".into()),
        };
        let accounting = assets
            .registry()
            .prepare_accounting(
                assets.registry().context(),
                p.asset_id,
                p.policy_version,
                old.credential_root,
                operation,
                p.magnitude,
            )
            .map_err(err)?;
        // wire verifies exact output0/1 CM+policy+archive/context binding first.
        // Neither structural framing nor successful archive decryption is authority.
        spend::verify_candidate(&a.public, a.proof).map_err(err)?;
        for c in &a.capsules {
            capsule::verify(&c.public, c.proof).map_err(err)?
        }
        let nf = [
            Some(Poseidon2V8Nullifier::new(p.nullifiers[0]).map_err(err)?),
            Some(Poseidon2V8Nullifier::new(p.nullifiers[1]).map_err(err)?),
        ];
        let cm = [
            Some(Poseidon2V8Commitment::new(p.commitments[0]).map_err(err)?),
            Some(Poseidon2V8Commitment::new(p.commitments[1]).map_err(err)?),
            Some(Poseidon2V8Commitment::new(p.commitments[2]).map_err(err)?),
        ];
        let transition = Poseidon2V8PublicTransition::new_with_asset_shielded_state(
            p.parent_height,
            self.static_root,
            checked.note_anchor(),
            nf,
            cm,
        )
        .with_checked_launch_reference(checked)?;
        Ok(RecoverySpendPlanV1 {
            asset_before: assets.encode_exact().map_err(err)?,
            recovery_before: recovery.encode_exact().map_err(err)?,
            accounting,
            transition,
            asset: p.asset_id,
            commitments: p.commitments,
            ciphertexts: a.ciphertexts.map(|c| *c),
            native_fee: p.fee,
        })
    }
    pub(crate) fn prepare_legacy_admin(
        &self,
        block: Poseidon2V8BlockContext,
        exact: &[u8],
        assets: &AssetRegistryStateV1,
        recovery: &RecoveryLedgerStateV1,
        parent_note: Poseidon2V8NoteRoot,
        references: &CanonicalLaunchReferences,
    ) -> Result<super::asset_state::AssetStatePlanV1> {
        self.require_block(block)?;
        self.current(block, assets, recovery)?;
        let a = old_wire::decode_native_asset_admin_action_v1(exact).map_err(err)?;
        if a.public.expires_at < block.parent_height()
            || references.parent_note_anchor() != parent_note
        {
            return Err("legacy recovery policy admin expired/reference mismatch".into());
        }
        let checked = references.validate_asset_admin(&a.public, block)?;
        let root = CanonicalAssetRegistryRoot::new(words(assets.registry().root()))?;
        if checked.asset_registry_root() != Some(root) {
            return Err("legacy recovery policy admin registry differs from CURRENT".into());
        }
        assets
            .plan_verified_actions_at_reference(
                super::asset_state::AssetCanonicalContextV1 {
                    chain_id: self.chain,
                    reference_parent_hash: block.parent_hash(),
                    parent_height: block.parent_height(),
                    note_root: parent_note.limbs(),
                },
                super::asset_state::AssetCanonicalContextV1 {
                    chain_id: self.chain,
                    reference_parent_hash: checked.reference_hash(),
                    parent_height: checked.reference_height(),
                    note_root: checked.note_anchor().limbs(),
                },
                root.limbs(),
                &[super::asset_state::AssetReplayActionV1::Controls(exact)],
                |_| Ok(false),
            )
            .map_err(err)
    }
    pub(crate) fn prepare_admin(
        &self,
        block: Poseidon2V8BlockContext,
        exact: &[u8],
        assets: &AssetRegistryStateV1,
        recovery: &RecoveryLedgerStateV1,
    ) -> Result<RecoveryAdminPlanV1> {
        self.require_block(block)?;
        self.current(block, assets, recovery)?;
        let a = wire::decode_admin_ref(exact).map_err(err)?;
        let row = self.row(recovery, a.public.before.descriptor.asset_id)?;
        if row != a.public.before {
            return Err("recovery admin stale CURRENT row".into());
        }
        let old = assets
            .registry()
            .row(row.descriptor.asset_id)
            .map_err(err)?;
        // apply_verified_admin resolves position->exact note CM/asset, compares current
        // freeze map/root, expiry/epoch/replay and verifies REAL admin proof.
        recovery
            .apply_verified_admin(
                &a.public,
                a.proof,
                RecoveryCanonicalContextV1 {
                    chain_id: self.chain,
                    parent_hash: block.parent_hash(),
                    parent_height: block.parent_height(),
                },
                words(old.config.policy_admin_commitment),
            )
            .map_err(err)
    }
}
/// Only the verifier above constructs a plan. A caller must CAS exact before
/// bytes inside its SAME canonical transaction, then apply accounting and pool.
pub(crate) struct RecoverySpendPlanV1 {
    asset_before: Vec<u8>,
    recovery_before: Vec<u8>,
    accounting: PreparedAssetAccountingV1,
    transition: Poseidon2V8PublicTransition,
    asset: u32,
    commitments: [Digest; 3],
    ciphertexts: [[u8; 2608]; 3],
    native_fee: u64,
}
impl RecoverySpendPlanV1 {
    pub(crate) fn asset_before(&self) -> &[u8] {
        &self.asset_before
    }
    pub(crate) fn recovery_before(&self) -> &[u8] {
        &self.recovery_before
    }
    pub(crate) fn accounting(&self) -> &PreparedAssetAccountingV1 {
        &self.accounting
    }
    pub(crate) fn transition(&self) -> Poseidon2V8PublicTransition {
        self.transition
    }
    pub(crate) fn ciphertexts(&self) -> &[[u8; 2608]; 3] {
        &self.ciphertexts
    }
    pub(crate) fn native_fee(&self) -> u64 {
        self.native_fee
    }
    /// canonical positions supplied by the shared pool plan, never caller hints.
    /// Only asset outputs0/1 are indexed; output2 is ordinary native fee change.
    pub(crate) fn asset_after_outputs(
        &self,
        current: &AssetRegistryStateV1,
        positions: [u32; 3],
    ) -> Result<AssetRegistryStateV1> {
        if current.encode_exact().map_err(err)? != self.asset_before {
            return Err("recovery asset before-state changed".into());
        }
        let recovery = current
            .recovery()
            .ok_or("missing composite recovery state")?;
        let recovery_after = self.recovery_after_outputs(recovery, positions)?;
        let mut after = current
            .apply_recovery_accounting_after_proof(self.accounting.clone())
            .map_err(err)?;
        *after
            .recovery_mut()
            .ok_or("missing projected recovery state")? = recovery_after;
        after.encode_exact().map_err(err)?;
        Ok(after)
    }
    pub(crate) fn recovery_after_outputs(
        &self,
        current: &RecoveryLedgerStateV1,
        positions: [u32; 3],
    ) -> Result<RecoveryLedgerStateV1> {
        if current.encode_exact().map_err(err)? != self.recovery_before {
            return Err("recovery plan before-state changed".into());
        }
        if positions[0].checked_add(1) != Some(positions[1])
            || positions[1].checked_add(1) != Some(positions[2])
        {
            return Err("recovery append positions not canonical consecutive".into());
        }
        let mut after = current.clone();
        for slot in 0..2 {
            after
                .register_verified_output(positions[slot], self.asset, self.commitments[slot])
                .map_err(err)?
        }
        Ok(after)
    }
}
/// Legacy ADMIN remains authorized for credential/full-freeze/mint controls.
/// It cannot change recovery epoch because it never touches recovery snapshots.
/// Legacy SPEND can never consume/create an opted-in recovery asset.
pub(crate) fn reject_legacy_spend_for_opted(
    exact: &[u8],
    recovery: &RecoveryLedgerStateV1,
) -> Result<()> {
    if exact.starts_with(&old_wire::NATIVE_ASSET_SPEND_ACTION_MAGIC_V1) {
        let a = old_wire::decode_native_asset_spend_action_v1(exact).map_err(err)?;
        if recovery.is_opted(a.public.asset_id) {
            return Err("opted asset requires recovery spend route".into());
        }
    }
    Ok(())
}
pub(crate) fn native_binding() -> KernelVersionBinding {
    asset_native::native_binding()
}
pub(crate) fn is_recovery_action(action: &PendingAction) -> bool {
    action.family_id == FAMILY_SHIELDED_POOL
        && matches!(
            action.action_id,
            RECOVERY_SPEND_ACTION_ID | RECOVERY_ADMIN_ACTION_ID
        )
}

/// Framing and metadata only; this never verifies proofs or grants state.
pub(crate) fn preflight_pending(action: &PendingAction) -> Result<()> {
    if action.family_id != FAMILY_SHIELDED_POOL
        || action.binding != asset_native::native_binding()
        || action.anchor != [0; 48]
        || !action.nullifiers.is_empty()
        || !action.commitments.is_empty()
        || action.candidate_artifact.is_some()
    {
        return Err("recovery forbidden outer binding/legacy fields".into());
    }
    match action.action_id {
        RECOVERY_SPEND_ACTION_ID => {
            let a = wire::decode_spend_ref(&action.public_args).map_err(err)?;
            if action.fee != a.public.base.fee
                || action.ciphertext_hashes != a.public.base.ciphertext_commitments
                || action.ciphertext_sizes != [2608u32; 3]
            {
                return Err("recovery outer fee/ciphertext mismatch".into());
            }
        }
        RECOVERY_ADMIN_ACTION_ID => {
            wire::decode_admin_ref(&action.public_args).map_err(err)?;
            if action.fee != 0
                || !action.ciphertext_hashes.is_empty()
                || !action.ciphertext_sizes.is_empty()
            {
                return Err("recovery admin cannot carry value/ciphertexts".into());
            }
        }
        _ => return Err("unknown recovery action route".into()),
    }
    Ok(())
}

/// Construct the exact same pending envelope used by RPC and peer admission.
/// The returned view is structural only: prepare_spend/prepare_admin still own
/// the proof, canonical-reference, current-state and shared-NF checks.
pub(crate) fn pending_recovery_action_from_inline_args(
    authority: RecoveryDevelopmentAuthorityV1,
    height: u64,
    binding: KernelVersionBinding,
    action_id: u16,
    public_args: Vec<u8>,
) -> Result<PendingAction> {
    let (fee, hashes, sizes) = match action_id {
        RECOVERY_SPEND_ACTION_ID => {
            let decoded = wire::decode_spend_ref(&public_args).map_err(err)?;
            (
                decoded.public.base.fee,
                decoded.public.base.ciphertext_commitments.to_vec(),
                vec![wire::CIPHERTEXT_BYTES as u32; 3],
            )
        }
        RECOVERY_ADMIN_ACTION_ID => {
            wire::decode_admin_ref(&public_args).map_err(err)?;
            (0, Vec::new(), Vec::new())
        }
        _ => return Err("unknown recovery pending builder action".into()),
    };
    let pending = PendingAction {
        tx_hash: super::ActionId48::ZERO,
        binding,
        family_id: FAMILY_SHIELDED_POOL,
        action_id,
        anchor: [0; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: hashes,
        ciphertext_sizes: sizes,
        public_args,
        fee,
        candidate_artifact: None,
    };
    NativeRecoveryActionViewV1::from_pending(authority, height, &pending)?;
    Ok(pending)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeRecoveryActionViewV1<'a> {
    exact: &'a [u8],
    transition: Poseidon2V8PublicTransition,
}
impl<'a> NativeRecoveryActionViewV1<'a> {
    pub(crate) fn from_pending(
        authority: RecoveryDevelopmentAuthorityV1,
        height: u64,
        action: &'a PendingAction,
    ) -> Result<Self> {
        preflight_pending(action)?;
        let application_parent = height
            .checked_sub(1)
            .ok_or("recovery inclusion height underflow")?;
        let (chain, parent, proof_bytes, transition) =
            match action.action_id {
                RECOVERY_SPEND_ACTION_ID => {
                    let decoded = wire::decode_spend_ref(&action.public_args).map_err(err)?;
                    let p = &decoded.public.base;
                    if !application_parent.checked_sub(p.parent_height).is_some_and(|age|
                    age <= protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW)
                {
                    return Err("recovery pending reference outside finite window".into());
                }
                    let [nf0, nf1] = p
                        .nullifiers
                        .map(|d| Poseidon2V8Nullifier::new(d).map(Some).map_err(err));
                    let [cm0, cm1, cm2] = p
                        .commitments
                        .map(|d| Poseidon2V8Commitment::new(d).map(Some).map_err(err));
                    let transition = Poseidon2V8PublicTransition::new_with_asset_shielded_state(
                        p.parent_height,
                        authority.static_root,
                        Poseidon2V8NoteRoot::new(p.note_root).map_err(err)?,
                        [nf0?, nf1?],
                        [cm0?, cm1?, cm2?],
                    );
                    (p.chain_id, p.parent_height, decoded.proof.len(), transition)
                }
                RECOVERY_ADMIN_ACTION_ID => {
                    let decoded = wire::decode_admin_ref(&action.public_args).map_err(err)?;
                    let p = &decoded.public;
                    if p.context.parent_height != application_parent
                        || p.expires_at < application_parent
                    {
                        return Err("recovery admin pending context/expiry is not current".into());
                    }
                    let transition = Poseidon2V8PublicTransition::new_with_asset_shielded_state(
                        p.context.parent_height,
                        authority.static_root,
                        authority.note_genesis_root,
                        [None; 2],
                        [None; 3],
                    );
                    (
                        p.context.chain_id,
                        p.context.parent_height,
                        decoded.proof.len(),
                        transition,
                    )
                }
                _ => return Err("unknown recovery view action".into()),
            };
        authority.require_route(
            height,
            action.binding,
            action.family_id,
            action.action_id,
            proof_bytes,
        )?;
        if chain != authority.chain {
            return Err("recovery pending chain differs from source authority".into());
        }
        authority.legacy.require_height(
            parent
                .checked_add(1)
                .ok_or("recovery reference height overflow")?,
        )?;
        Ok(Self {
            exact: &action.public_args,
            transition: transition.with_launch_application_hint(application_parent),
        })
    }
    pub(crate) fn exact_native_leaf(self) -> &'a [u8] {
        self.exact
    }
    pub(crate) fn transition(self) -> Poseidon2V8PublicTransition {
        self.transition
    }
}
