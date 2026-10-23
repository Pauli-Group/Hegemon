//! Source-owned, finite Development authority for the separate asset namespace.
//! Asset actions never borrow a native PrivateSpend proof kind or production
//! capability. Their registry snapshots accompany the existing shared V8 pool.

use super::{
    asset_state::{AssetCanonicalContextV1, AssetRegistryStateV1, AssetReplayActionV1},
    launch_reference::{CanonicalAssetRegistryRoot, CanonicalLaunchReferences},
    launch_v8_verifier::LaunchStartup,
    network_profile::{NativeNetworkIdentity, NativeNetworkProfile},
    poseidon2_v8_state::{
        Poseidon2V8BlockContext, Poseidon2V8Commitment, Poseidon2V8NoteRoot, Poseidon2V8Nullifier,
        Poseidon2V8PublicTransition, Poseidon2V8Root,
    },
    KernelVersionBinding, PendingAction, FAMILY_SHIELDED_POOL,
};
use transaction_circuit::{asset_spend_v1_admission as admission, asset_spend_v1_wire as wire};

#[derive(Clone, Copy, Debug)]
pub(crate) struct AssetDevelopmentAuthorityV1 {
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    manifest_digest: [u8; 64],
    spend_relation: [u8; 64],
    admin_relation: [u8; 64],
    activation: u64,
    end: u64,
    max_proof_bytes: usize,
    static_root: Poseidon2V8Root,
    note_genesis_root: Poseidon2V8NoteRoot,
}

impl AssetDevelopmentAuthorityV1 {
    pub(crate) fn require_height(self, height: u64) -> Result<(), String> {
        if height < self.activation || height >= self.end {
            return Err("asset action outside the finite source lifetime".into());
        }
        Ok(())
    }
    pub(crate) fn from_source(
        network: &NativeNetworkIdentity,
        genesis_hash: [u8; 32],
        startup: LaunchStartup,
    ) -> Result<Option<Self>, String> {
        let Some(descriptor) = network.development_assets() else {
            return Ok(None);
        };
        let end = startup
            .deactivation_height_exclusive()
            .ok_or("asset authority requires finite Development expiry")?;
        let total = startup
            .max_total_proofs()
            .ok_or("asset authority requires finite Development proof budget")?;
        if !cfg!(feature = "development-candidate")
            || network.profile() != NativeNetworkProfile::Development
            || !startup.is_development_candidate()
            || !startup.is_private_spend_only()
            || genesis_hash == [0; 32]
            || startup.chain_id() != network.chain_id()
            || startup.activation_genesis_hash() != genesis_hash
            || Some(startup.manifest_digest()) != network.manifest_digest()
            || startup.activation_height() == 0
            || startup.activation_height() >= end
            || end == u64::MAX
            || total == 0
            || startup.max_proof_actions_per_block() == 0
            || transaction_circuit::asset_spend_v1::ASSET_REFERENCE_WINDOW
                != super::launch_reference::LAUNCH_REFERENCE_WINDOW
        {
            return Err(
                "asset authority requires the exact finite Development source identity".into(),
            );
        }
        descriptor.validate().map_err(|error| error.to_string())?;
        // Retained source-qualified byte bounds must remain valid for these
        // exact graphs. Merely supplying current digests in a manifest cannot
        // qualify a changed proof relation or enlarge its parser resources.
        for [mode, depth] in descriptor.allowed_profiles {
            admission::spend_profile_upper_bound_v1(mode, depth)
                .map_err(|error| error.to_string())?;
        }
        admission::admin_profile_upper_bound_v1().map_err(|error| error.to_string())?;
        Ok(Some(Self {
            chain_id: network.chain_id(),
            genesis_hash,
            manifest_digest: startup.manifest_digest(),
            spend_relation: transaction_circuit::asset_spend_v1::relation_digest(),
            admin_relation: transaction_circuit::asset_policy_admin_v1::relation_digest(),
            activation: startup.activation_height(),
            end,
            max_proof_bytes: descriptor.max_proof_bytes.min(startup.max_proof_bytes()),
            static_root: startup.stablecoin_genesis_root(),
            note_genesis_root: startup.note_genesis_root(),
        }))
    }

    pub(crate) fn require_route(
        self,
        height: u64,
        binding: KernelVersionBinding,
        family_id: u16,
        action_id: u16,
        proof_bytes: usize,
    ) -> Result<(), String> {
        let version = admission::NATIVE_VERSION_BINDING;
        if height < self.activation
            || height >= self.end
            || family_id != FAMILY_SHIELDED_POOL
            || binding.circuit != version.circuit
            || binding.crypto != version.crypto
            || !matches!(
                action_id,
                admission::ASSET_SPEND_ACTION_ID | admission::ASSET_ADMIN_ACTION_ID
            )
            || proof_bytes == 0
            || proof_bytes > self.max_proof_bytes
            || version.profile != 13
            || version.transcript_domain != 9
            || version.backend != 2
            || self.spend_relation != transaction_circuit::asset_spend_v1::relation_digest()
            || self.admin_relation != transaction_circuit::asset_policy_admin_v1::relation_digest()
        {
            return Err("asset action differs from its exact finite source authority".into());
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
    fn require_block(self, block: Poseidon2V8BlockContext) -> Result<(), String> {
        if block.height() < self.activation
            || block.height() >= self.end
            || (block.parent_height() == 0 && block.parent_hash() != self.genesis_hash)
        {
            return Err("asset block differs from its finite source lifetime/genesis".into());
        }
        Ok(())
    }

    /// Metadata eligibility only; inclusion still verifies the original proof,
    /// current accounting and all global/batch nullifiers in the shared store.
    pub(crate) fn checked_reference(
        self,
        block: Poseidon2V8BlockContext,
        exact: &[u8],
        current_asset: &[u8],
        parent_note_root: Poseidon2V8NoteRoot,
        references: &CanonicalLaunchReferences,
    ) -> Result<super::launch_reference::CheckedLaunchReference, String> {
        self.require_block(block)?;
        let state =
            AssetRegistryStateV1::decode_exact(current_asset).map_err(|error| error.to_string())?;
        if state.registry().context().chain_id != self.chain_id
            || state.registry().context().parent_height != block.parent_height()
        {
            return Err("asset CURRENT registry context mismatch".into());
        }
        if references.parent_note_anchor() != parent_note_root {
            return Err(
                "asset references differ from authenticated inclusion-parent note root".into(),
            );
        }
        let checked = if exact.starts_with(&wire::NATIVE_ASSET_SPEND_ACTION_MAGIC_V1) {
            let decoded = wire::decode_native_asset_spend_action_v1(exact)
                .map_err(|error| error.to_string())?;
            self.require_route(
                block.height(),
                native_binding(),
                FAMILY_SHIELDED_POOL,
                admission::ASSET_SPEND_ACTION_ID,
                decoded.proof.len(),
            )?;
            references.validate_asset_spend(&decoded.public, block)?
        } else if exact.starts_with(&wire::NATIVE_ASSET_ADMIN_ACTION_MAGIC_V1) {
            let decoded = wire::decode_native_asset_admin_action_v1(exact)
                .map_err(|error| error.to_string())?;
            self.require_route(
                block.height(),
                native_binding(),
                FAMILY_SHIELDED_POOL,
                admission::ASSET_ADMIN_ACTION_ID,
                decoded.proof.len(),
            )?;
            {
                if decoded.public.expires_at < block.parent_height() {
                    return Err("asset admin expired at CURRENT parent".into());
                }
                references.validate_asset_admin(&decoded.public, block)?
            }
        } else {
            return Err("unknown asset native leaf identity".into());
        };
        let current_root = CanonicalAssetRegistryRoot::new(
            state.registry().root().map(|word| word.as_canonical_u64()),
        )?;
        if checked.asset_registry_root() != Some(current_root) {
            return Err(
                "asset proof reference registry differs from CURRENT canonical registry".into(),
            );
        }
        Ok(checked)
    }

    pub(crate) fn verify_leaf(
        self,
        block: Poseidon2V8BlockContext,
        exact: &[u8],
        current_asset: &[u8],
        parent_note_root: Poseidon2V8NoteRoot,
        references: &CanonicalLaunchReferences,
    ) -> Result<(Poseidon2V8PublicTransition, Vec<u8>), String> {
        let checked =
            self.checked_reference(block, exact, current_asset, parent_note_root, references)?;
        let state =
            AssetRegistryStateV1::decode_exact(current_asset).map_err(|error| error.to_string())?;
        let current_root = CanonicalAssetRegistryRoot::new(
            state.registry().root().map(|word| word.as_canonical_u64()),
        )?;
        let action = if exact.starts_with(&wire::NATIVE_ASSET_SPEND_ACTION_MAGIC_V1) {
            AssetReplayActionV1::Spend(exact)
        } else {
            AssetReplayActionV1::Controls(exact)
        };
        let plan = state
            .plan_verified_actions_at_reference(
                AssetCanonicalContextV1 {
                    chain_id: self.chain_id,
                    reference_parent_hash: block.parent_hash(),
                    parent_height: block.parent_height(),
                    note_root: parent_note_root.limbs(),
                },
                AssetCanonicalContextV1 {
                    chain_id: self.chain_id,
                    reference_parent_hash: checked.reference_hash(),
                    parent_height: checked.reference_height(),
                    note_root: checked.note_anchor().limbs(),
                },
                current_root.limbs(),
                &[action],
                |_| Ok(false),
            )
            .map_err(|error| error.to_string())?;
        // The canonical shared store checks every returned nullifier against
        // persisted and earlier same-block spends before atomic publication.
        // This helper owns no second note/nullifier set.
        let transition = transition_from_exact(self, exact, checked.note_anchor())?
            .with_checked_launch_reference(checked)?;
        let snapshot = plan
            .projected_state()
            .encode_exact()
            .map_err(|error| error.to_string())?;
        Ok((transition, snapshot))
    }
    pub(crate) fn advance(
        self,
        block: Poseidon2V8BlockContext,
        current_asset: &[u8],
    ) -> Result<Vec<u8>, String> {
        // Empty blocks after the finite proof interval must still preserve and
        // advance already authenticated registry state. This grants no route.
        let state =
            AssetRegistryStateV1::decode_exact(current_asset).map_err(|error| error.to_string())?;
        if state.registry().context().chain_id != self.chain_id
            || state.registry().context().parent_height != block.parent_height()
            || (block.parent_height() == 0 && block.parent_hash() != self.genesis_hash)
        {
            return Err("asset advancement context mismatch".into());
        }
        state
            .advance_parent(block.height())
            .and_then(|state| state.encode_exact())
            .map_err(|error| error.to_string())
    }
}

pub(crate) fn native_binding() -> KernelVersionBinding {
    KernelVersionBinding {
        circuit: admission::NATIVE_VERSION_BINDING.circuit,
        crypto: admission::NATIVE_VERSION_BINDING.crypto,
    }
}
pub(crate) fn is_asset_leaf(exact: &[u8]) -> bool {
    exact.starts_with(&wire::NATIVE_ASSET_SPEND_ACTION_MAGIC_V1)
        || exact.starts_with(&wire::NATIVE_ASSET_ADMIN_ACTION_MAGIC_V1)
}
pub(crate) fn is_asset_action(action: &PendingAction) -> bool {
    action.family_id == FAMILY_SHIELDED_POOL
        && matches!(
            action.action_id,
            admission::ASSET_SPEND_ACTION_ID | admission::ASSET_ADMIN_ACTION_ID
        )
}

pub(crate) fn pending_reference_eligible(action: &PendingAction, parent: u64) -> bool {
    if preflight_pending(action).is_err() {
        return false;
    }
    let reference = if action.action_id == admission::ASSET_SPEND_ACTION_ID {
        match wire::decode_native_asset_spend_action_v1(&action.public_args) {
            Ok(value) => value.public.parent_height,
            Err(_) => return false,
        }
    } else {
        match wire::decode_native_asset_admin_action_v1(&action.public_args) {
            Ok(value) if value.public.expires_at >= parent => value.public.parent_height,
            _ => return false,
        }
    };
    parent
        .checked_sub(reference)
        .is_some_and(|age| age <= super::launch_reference::LAUNCH_REFERENCE_WINDOW)
}

pub(crate) fn preflight_pending(action: &PendingAction) -> Result<(), String> {
    if action.family_id != FAMILY_SHIELDED_POOL
        || action.binding != native_binding()
        || action.anchor != [0; 48]
        || !action.nullifiers.is_empty()
        || !action.commitments.is_empty()
        || action.candidate_artifact.is_some()
    {
        return Err("asset outer binding or forbidden legacy fields".into());
    }
    match action.action_id {
        admission::ASSET_SPEND_ACTION_ID => {
            let decoded = wire::decode_native_asset_spend_action_v1(&action.public_args)
                .map_err(|error| error.to_string())?;
            if action.fee != decoded.public.fee
                || action.ciphertext_hashes != decoded.public.ciphertext_commitments
                || action.ciphertext_sizes != [2608u32; 3]
            {
                return Err("asset outer fee/ciphertext metadata mismatch".into());
            }
        }
        admission::ASSET_ADMIN_ACTION_ID => {
            wire::decode_native_asset_admin_action_v1(&action.public_args)
                .map_err(|error| error.to_string())?;
            if action.fee != 0
                || !action.ciphertext_hashes.is_empty()
                || !action.ciphertext_sizes.is_empty()
            {
                return Err("asset admin cannot carry value or ciphertext metadata".into());
            }
        }
        _ => return Err("unknown asset outer action id".into()),
    }
    Ok(())
}

pub(crate) fn pending_asset_action_from_inline_args(
    authority: AssetDevelopmentAuthorityV1,
    height: u64,
    binding: KernelVersionBinding,
    action_id: u16,
    public_args: Vec<u8>,
) -> Result<PendingAction, String> {
    let (fee, hashes, sizes) = match action_id {
        admission::ASSET_SPEND_ACTION_ID => {
            let decoded = wire::decode_native_asset_spend_action_v1(&public_args)
                .map_err(|error| error.to_string())?;
            (
                decoded.public.fee,
                decoded.public.ciphertext_commitments.to_vec(),
                vec![2608u32; 3],
            )
        }
        admission::ASSET_ADMIN_ACTION_ID => {
            wire::decode_native_asset_admin_action_v1(&public_args)
                .map_err(|error| error.to_string())?;
            (0, Vec::new(), Vec::new())
        }
        _ => return Err("unknown native asset pending builder action".into()),
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
    NativeAssetActionViewV1::from_pending(authority, height, &pending)?;
    Ok(pending)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeAssetActionViewV1<'a> {
    exact: &'a [u8],
    transition: Poseidon2V8PublicTransition,
}
impl<'a> NativeAssetActionViewV1<'a> {
    pub(crate) fn from_pending(
        authority: AssetDevelopmentAuthorityV1,
        height: u64,
        action: &'a PendingAction,
    ) -> Result<Self, String> {
        preflight_pending(action)?;
        let (chain, parent, proof_bytes, anchor) =
            if action.action_id == admission::ASSET_SPEND_ACTION_ID {
                let decoded = wire::decode_native_asset_spend_action_v1(&action.public_args)
                    .map_err(|error| error.to_string())?;
                (
                    decoded.public.chain_id,
                    decoded.public.parent_height,
                    decoded.proof.len(),
                    Poseidon2V8NoteRoot::new(decoded.public.note_root)
                        .map_err(|error| error.to_string())?,
                )
            } else {
                let decoded = wire::decode_native_asset_admin_action_v1(&action.public_args)
                    .map_err(|error| error.to_string())?;
                (
                    decoded.public.chain_id,
                    decoded.public.parent_height,
                    decoded.proof.len(),
                    authority.note_genesis_root,
                )
            };
        authority.require_route(
            height,
            action.binding,
            action.family_id,
            action.action_id,
            proof_bytes,
        )?;
        let application_parent = height
            .checked_sub(1)
            .ok_or("asset inclusion height underflow")?;
        if chain != authority.chain_id
            || !application_parent.checked_sub(parent).is_some_and(|age| {
                age <= protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW
            })
        {
            return Err("asset pending proof reference age is outside the finite window".into());
        }
        authority.require_height(
            parent
                .checked_add(1)
                .ok_or("asset reference height overflow")?,
        )?;
        // Hints are scheduling metadata only. Admin has no pool effect, and its
        // real transition obtains the authenticated reference root during replay.
        let transition = transition_from_exact(authority, &action.public_args, anchor)?
            .with_launch_application_hint(application_parent);
        Ok(Self {
            exact: &action.public_args,
            transition,
        })
    }
    pub(crate) fn exact_native_leaf(self) -> &'a [u8] {
        self.exact
    }
    pub(crate) fn transition(self) -> Poseidon2V8PublicTransition {
        self.transition
    }
}

fn transition_from_exact(
    authority: AssetDevelopmentAuthorityV1,
    exact: &[u8],
    admin_anchor: Poseidon2V8NoteRoot,
) -> Result<Poseidon2V8PublicTransition, String> {
    if exact.starts_with(&wire::NATIVE_ASSET_SPEND_ACTION_MAGIC_V1) {
        let decoded =
            wire::decode_native_asset_spend_action_v1(exact).map_err(|error| error.to_string())?;
        let nullifiers = decoded.public.nullifiers.map(|digest| {
            Poseidon2V8Nullifier::new(digest)
                .map(Some)
                .map_err(|error| error.to_string())
        });
        let commitments = decoded.public.commitments.map(|digest| {
            Poseidon2V8Commitment::new(digest)
                .map(Some)
                .map_err(|error| error.to_string())
        });
        let [nf0, nf1] = nullifiers;
        let [cm0, cm1, cm2] = commitments;
        Ok(Poseidon2V8PublicTransition::new_with_asset_shielded_state(
            decoded.public.parent_height,
            authority.static_root,
            Poseidon2V8NoteRoot::new(decoded.public.note_root)
                .map_err(|error| error.to_string())?,
            [nf0?, nf1?],
            [cm0?, cm1?, cm2?],
        ))
    } else {
        let decoded =
            wire::decode_native_asset_admin_action_v1(exact).map_err(|error| error.to_string())?;
        Ok(Poseidon2V8PublicTransition::new_with_asset_shielded_state(
            decoded.public.parent_height,
            authority.static_root,
            admin_anchor,
            [None; 2],
            [None; 3],
        ))
    }
}

pub(crate) fn asset_genesis_bytes(
    network: &NativeNetworkIdentity,
    genesis_hash: [u8; 32],
) -> Result<Option<Vec<u8>>, String> {
    if network.development_assets().is_none() {
        return Ok(None);
    }
    let startup = LaunchStartup::from_source(network, genesis_hash)?
        .ok_or("asset genesis requires source-owned launch startup")?;
    startup
        .asset_authority()
        .ok_or("asset genesis has no typed source authority")?;
    let state = network
        .development_assets()
        .expect("checked descriptor")
        .initial_state(network.chain_id())
        .map_err(|error| error.to_string())?;
    state
        .encode_exact()
        .map(Some)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "development-candidate")]
    use super::super::network_profile::{self, DevelopmentAssetsV1};
    #[cfg(feature = "development-candidate")]
    use super::*;
    #[cfg(feature = "development-candidate")]
    use transaction_core::{
        asset_registry_v1::AssetPolicyV1,
        poseidon2_width16::Felt,
        stablecoin_poseidon2_v8::{StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Counters},
    };

    #[cfg(feature = "development-candidate")]
    fn network() -> NativeNetworkIdentity {
        let address = wallet::RootSecret::from_bytes([97; 32])
            .derive()
            .poseidon2_v8_address(0)
            .unwrap()
            .shielded_address()
            .encode()
            .unwrap();
        let mut manifest =
            network_profile::private_spend_only_development_candidate_manifest(&address).unwrap();
        let row = AssetPolicyV1 {
            config: StablecoinPoseidon2V8Config {
                asset_id: 1001,
                collateral_scale: 1,
                issuer_commitment: [Felt::from_u64(1); 7],
                policy_admin_commitment: [Felt::from_u64(2); 7],
                oracle_authority_commitment: [Felt::from_u64(3); 7],
                attestation_authority_commitment: [Felt::from_u64(4); 7],
                locked_collateral_commitment: [Felt::from_u64(5); 7],
                ..Default::default()
            },
            counters: StablecoinPoseidon2V8Counters::default(),
            credential_root: [Felt::from_u64(6); 7],
            credential_depth: 4,
            frozen: false,
            mint_enabled: false,
        };
        let row = hex::encode(admission::encode_asset_policy_row(&row).unwrap());
        manifest.development_candidate.as_mut().unwrap().assets =
            Some(DevelopmentAssetsV1::compiled(vec![row]).unwrap());
        NativeNetworkIdentity::from_manifest(manifest).unwrap()
    }

    #[cfg(feature = "development-candidate")]
    #[test]
    fn moving_asset_pending_survives_empty_parent_advance_until_age_thirteen() {
        use super::super::{
            genesis_meta, pending_action_hash, revalidate_pending_actions_after_state_advance,
            revalidate_reorg_pending_actions, CommitmentTreeState, NativeState,
            NullifierAccumulator, PersistentKeySet48,
        };
        let network = network();
        let startup = LaunchStartup::from_source(&network, [11; 32])
            .unwrap()
            .unwrap();
        let assets = AssetRegistryStateV1::decode_exact(
            &asset_genesis_bytes(&network, [11; 32]).unwrap().unwrap(),
        )
        .unwrap();
        let controls = transaction_circuit::asset_policy_admin_v1::AssetControlsV1 {
            frozen: true,
            ..assets.registry().row(1001).unwrap().controls()
        };
        let prepared = assets
            .registry()
            .prepare_controls_update(assets.registry().context(), 1001, controls)
            .unwrap();
        let public =
            transaction_circuit::asset_policy_admin_v1::PolicyAdminPublicV1::from_prepared(
                &prepared, [11; 32], 100, [23; 7],
            )
            .unwrap();
        let bytes = wire::encode_native_asset_admin_action_v1(&public, b"SMZE").unwrap();
        // This framed invalid proof is a retention-only fixture. Neither
        // metadata retention nor this test can authorize its inclusion.
        let mut action = pending_asset_action_from_inline_args(
            startup.asset_authority().unwrap(),
            1,
            native_binding(),
            admission::ASSET_ADMIN_ACTION_ID,
            bytes,
        )
        .unwrap();
        action.tx_hash = pending_action_hash(&action);
        let mut state = NativeState {
            best: genesis_meta(0x207f_ffff).unwrap(),
            header_mmr_peaks: Vec::new(),
            pending_actions: std::collections::BTreeMap::new(),
            pending_action_semantic_index: std::collections::BTreeMap::new(),
            pending_action_order_index: std::collections::BTreeSet::new(),
            pending_nullifiers: std::collections::BTreeSet::new(),
            pending_bridge_replay_keys: PersistentKeySet48::new(),
            pending_mempool_bytes: 0,
            commitment_tree: CommitmentTreeState::default(),
            nullifiers: PersistentKeySet48::new(),
            nullifier_accumulator: NullifierAccumulator::new(),
            consumed_bridge_messages: PersistentKeySet48::new(),
            stablecoin_policy_authorizations: std::collections::BTreeSet::new(),
            staged_ciphertexts: std::collections::BTreeMap::new(),
            staged_proofs: std::collections::BTreeMap::new(),
        };
        for parent in [1, 12, 13] {
            state.best.height = parent;
            let retained = revalidate_pending_actions_after_state_advance(
                &state,
                std::collections::BTreeMap::from([(action.tx_hash, action.clone())]),
            );
            assert_eq!(retained.contains_key(&action.tx_hash), parent <= 12);
            let reorged = revalidate_reorg_pending_actions(
                &state,
                std::collections::BTreeMap::new(),
                vec![action.clone()],
            );
            assert_eq!(reorged.contains_key(&action.tx_hash), parent <= 12);
        }
        let original_root = CanonicalAssetRegistryRoot::new(
            assets.registry().root().map(|word| word.as_canonical_u64()),
        )
        .unwrap();
        let context =
            super::super::launch_reference::LaunchReferenceContext::from_startup(startup).unwrap();
        let anchor = startup.note_genesis_root();
        let checkpoint = |hash, parent_hash, height, root| {
            super::super::launch_reference::CanonicalLaunchCheckpoint::new(
                hash,
                parent_hash,
                height,
                anchor,
                startup.stablecoin_genesis_root(),
            )
            .unwrap()
            .with_asset_registry_root(Some(root))
        };
        let block = Poseidon2V8BlockContext::new(1, [31; 32], 2, [32; 32]).unwrap();
        let refs = |root| {
            CanonicalLaunchReferences::from_validated_chain(
                context,
                [31; 32],
                1,
                vec![
                    checkpoint([11; 32], [0; 32], 0, original_root),
                    checkpoint([31; 32], [11; 32], 1, root),
                ],
            )
            .unwrap()
        };
        let current = assets.advance_parent(1).unwrap().encode_exact().unwrap();
        let authority = startup.asset_authority().unwrap();
        assert!(authority
            .checked_reference(
                block,
                &action.public_args,
                &current,
                anchor,
                &refs(original_root)
            )
            .is_ok());
        // A valid reference at an earlier inclusion must never grant source
        // authority at the actual retirement height. Check the precise early
        // lifetime rejection before any stale-reference/current-state check.
        let end = startup.deactivation_height_exclusive().unwrap();
        let retired_block = Poseidon2V8BlockContext::new(end - 1, [31; 32], end, [32; 32]).unwrap();
        assert_eq!(
            authority
                .checked_reference(
                    retired_block,
                    &action.public_args,
                    &current,
                    anchor,
                    &refs(original_root)
                )
                .unwrap_err(),
            "asset block differs from its finite source lifetime/genesis"
        );
        let mut orphan = public.clone();
        orphan.reference_parent_hash = [12; 32];
        let orphan = wire::encode_native_asset_admin_action_v1(&orphan, b"SMZE").unwrap();
        assert!(authority
            .checked_reference(block, &orphan, &current, anchor, &refs(original_root))
            .is_err());
        let mut changed = *assets.registry().row(1001).unwrap();
        changed.frozen = true;
        let changed = AssetRegistryStateV1::from_genesis_rows(network.chain_id(), &[changed])
            .unwrap()
            .advance_parent(1)
            .unwrap();
        let changed_root = CanonicalAssetRegistryRoot::new(
            changed
                .registry()
                .root()
                .map(|word| word.as_canonical_u64()),
        )
        .unwrap();
        assert!(authority
            .checked_reference(
                block,
                &action.public_args,
                &changed.encode_exact().unwrap(),
                anchor,
                &refs(changed_root)
            )
            .is_err());
    }

    #[cfg(feature = "development-candidate")]
    #[test]
    fn separate_asset_authority_binds_network_source_lifetime_and_shared_genesis() {
        let network = network();
        let startup = LaunchStartup::from_source(&network, [11; 32])
            .unwrap()
            .unwrap();
        let authority = startup.asset_authority().unwrap();
        assert!(authority.authorizes_route(
            1,
            native_binding(),
            FAMILY_SHIELDED_POOL,
            admission::ASSET_SPEND_ACTION_ID
        ));
        assert!(authority.authorizes_route(
            1,
            native_binding(),
            FAMILY_SHIELDED_POOL,
            admission::ASSET_ADMIN_ACTION_ID
        ));
        assert!(authority.require_height(0).is_err());
        assert!(authority
            .require_height(startup.deactivation_height_exclusive().unwrap())
            .is_err());
        assert!(authority
            .require_route(
                1,
                native_binding(),
                FAMILY_SHIELDED_POOL,
                admission::ASSET_SPEND_ACTION_ID,
                admission::NATIVE_INNER_PROOF_CAP_BYTES + 1
            )
            .is_err());
        assert!(!authority.authorizes_route(
            1,
            protocol_versioning::launch_candidate::PRIVATE_SPEND_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            admission::ASSET_SPEND_ACTION_ID
        ));
        assert!(AssetDevelopmentAuthorityV1::from_source(&network, [12; 32], startup).is_err());
        let bytes = asset_genesis_bytes(&network, [11; 32]).unwrap().unwrap();
        let state = AssetRegistryStateV1::decode_exact(&bytes).unwrap();
        assert_eq!(state.registry().context().chain_id, network.chain_id());
        assert_eq!(
            state.registry().row(1001).unwrap().counters,
            StablecoinPoseidon2V8Counters::default()
        );
        let block = Poseidon2V8BlockContext::new(0, [11; 32], 1, [13; 32]).unwrap();
        assert!(is_asset_leaf(b"HGANSP01"));
        let references = CanonicalLaunchReferences::from_validated_chain(
            super::super::launch_reference::LaunchReferenceContext::from_startup(startup).unwrap(),
            [11; 32],
            0,
            vec![
                super::super::launch_reference::CanonicalLaunchCheckpoint::new(
                    [11; 32],
                    [0; 32],
                    0,
                    startup.note_genesis_root(),
                    startup.stablecoin_genesis_root(),
                )
                .unwrap()
                .with_asset_registry_root(Some(
                    CanonicalAssetRegistryRoot::new(
                        state.registry().root().map(|word| word.as_canonical_u64()),
                    )
                    .unwrap(),
                )),
            ],
        )
        .unwrap();
        assert!(authority
            .verify_leaf(
                block,
                b"HGANSP01",
                &bytes,
                startup.note_genesis_root(),
                &references
            )
            .is_err());
        let advanced = authority.advance(block, &bytes).unwrap();
        assert_eq!(
            AssetRegistryStateV1::decode_exact(&advanced)
                .unwrap()
                .registry()
                .context()
                .parent_height,
            1
        );
        assert!(
            asset_genesis_bytes(&NativeNetworkIdentity::development(), [11; 32])
                .unwrap()
                .is_none()
        );
        assert!(
            LaunchStartup::from_source(&NativeNetworkIdentity::development(), [11; 32])
                .unwrap()
                .is_none()
        );
    }
}
