//! Closed network-specific dispatch for historical V8 and launch successors.
//! A public network manifest never grants proof authority.
use super::{
    launch_reference::{CanonicalLaunchReferences, LaunchReferenceContext},
    launch_v8_verifier::{LaunchStartup, NativeLaunchActionView, NativeLaunchVerifier},
    network_profile::{NativeNetworkIdentity, NativeNetworkProfile},
    poseidon2_v8_state::{
        Poseidon2V8BlockContext, Poseidon2V8Commitment, Poseidon2V8ExactLeafVerifier,
        Poseidon2V8NativeLeafProfile, Poseidon2V8NoteRoot, Poseidon2V8Nullifier,
        Poseidon2V8PublicTransition, Poseidon2V8Root,
    },
    poseidon2_v8_verifier::{
        Poseidon2V8ActionView, Poseidon2V8NativeVerifierConnector, Poseidon2V8ProductionBinding,
    },
    KernelVersionBinding, PendingAction,
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum NativeProofBinding {
    Historical(Poseidon2V8ProductionBinding),
    Launch(LaunchStartup),
}
impl From<Poseidon2V8ProductionBinding> for NativeProofBinding {
    fn from(binding: Poseidon2V8ProductionBinding) -> Self {
        Self::Historical(binding)
    }
}
impl NativeProofBinding {
    pub(crate) fn asset_authority(
        self,
    ) -> Option<super::asset_native::AssetDevelopmentAuthorityV1> {
        match self {
            Self::Historical(_) => None,
            Self::Launch(startup) => startup.asset_authority(),
        }
    }
    pub(crate) fn recovery_authority(
        self,
    ) -> Option<super::asset_recovery_native::RecoveryDevelopmentAuthorityV1> {
        match self {
            Self::Historical(_) => None,
            Self::Launch(startup) => startup.recovery_authority(),
        }
    }
    pub(crate) fn from_source_for_replay(
        network: &NativeNetworkIdentity,
        genesis_hash: [u8; 32],
    ) -> Result<Option<Self>, String> {
        if network.profile() == NativeNetworkProfile::Legacy {
            Poseidon2V8ProductionBinding::from_source_for_replay()
                .map(|binding| binding.map(Self::Historical))
        } else {
            LaunchStartup::from_source(network, genesis_hash)
                .map(|binding| binding.map(Self::Launch))
        }
    }
    pub(crate) fn from_source_at(
        network: &NativeNetworkIdentity,
        genesis_hash: [u8; 32],
        height: u64,
    ) -> Result<Option<Self>, String> {
        if network.profile() == NativeNetworkProfile::Legacy {
            Poseidon2V8ProductionBinding::from_source_at(height)
                .map(|binding| binding.map(Self::Historical))
        } else {
            Ok(Self::from_source_for_replay(network, genesis_hash)?
                .filter(|binding| binding.active_at(height)))
        }
    }
    pub(crate) fn require_source_at(
        network: &NativeNetworkIdentity,
        genesis_hash: [u8; 32],
        height: u64,
    ) -> Result<Self, String> {
        Self::from_source_at(network, genesis_hash, height)?
            .ok_or_else(|| "exact network has no active source-owned proof capability".into())
    }
    pub(crate) fn active_at(self, height: u64) -> bool {
        match self {
            Self::Historical(value) => value.active_at(height),
            Self::Launch(value) => value.active_at(height),
        }
    }
    pub(crate) fn activation_height(self) -> u64 {
        match self {
            Self::Historical(value) => value.activation_height(),
            Self::Launch(value) => value.activation_height(),
        }
    }
    pub(crate) fn activation_genesis_hash(self) -> [u8; 32] {
        match self {
            Self::Historical(value) => value.activation_genesis_hash(),
            Self::Launch(value) => value.activation_genesis_hash(),
        }
    }
    pub(crate) fn stablecoin_genesis_root(self) -> Poseidon2V8Root {
        match self {
            Self::Historical(value) => value.stablecoin_genesis_root(),
            Self::Launch(value) => value.stablecoin_genesis_root(),
        }
    }
    pub(crate) fn note_genesis_root(self) -> Poseidon2V8NoteRoot {
        match self {
            Self::Historical(value) => value.note_genesis_root(),
            Self::Launch(value) => value.note_genesis_root(),
        }
    }
    pub(crate) fn max_proof_actions_per_block(self) -> usize {
        match self {
            Self::Historical(value) => value.max_proof_actions_per_block(),
            Self::Launch(value) => value.max_proof_actions_per_block(),
        }
    }
    pub(crate) fn coinbase_action_id(self) -> u16 {
        match self {
            Self::Historical(value) => value.coinbase_action_id(),
            Self::Launch(_) => protocol_versioning::launch_candidate::ALLOCATED_REWARD_ACTION_ID,
        }
    }
    pub(crate) fn connector(self) -> NativeExactLeafVerifier {
        match self {
            Self::Historical(value) => NativeExactLeafVerifier::Historical(value.connector()),
            Self::Launch(value) => NativeExactLeafVerifier::Launch(value.connector()),
        }
    }
    pub(crate) fn authorizes_launch_route(
        self,
        height: u64,
        binding: KernelVersionBinding,
        family_id: u16,
        action_id: u16,
    ) -> bool {
        match self {
            Self::Historical(_) => false,
            Self::Launch(value) => value.authorizes_route(height, binding, family_id, action_id),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum NativeProofActionView<'a> {
    Historical(Poseidon2V8ActionView<'a>),
    Launch(NativeLaunchActionView<'a>),
    Asset(super::asset_native::NativeAssetActionViewV1<'a>),
    Recovery(super::asset_recovery_native::NativeRecoveryActionViewV1<'a>),
}
impl<'a> NativeProofActionView<'a> {
    pub(crate) fn from_pending(
        production: NativeProofBinding,
        height: u64,
        action: &'a PendingAction,
    ) -> Result<Self, String> {
        match production {
            NativeProofBinding::Historical(value) => {
                Poseidon2V8ActionView::from_pending(value, height, action).map(Self::Historical)
            }
            NativeProofBinding::Launch(value) => {
                if matches!(
                    action.action_id,
                    super::asset_recovery_native::RECOVERY_SPEND_ACTION_ID
                        | super::asset_recovery_native::RECOVERY_ADMIN_ACTION_ID
                ) {
                    return super::asset_recovery_native::NativeRecoveryActionViewV1::from_pending(
                        value
                            .recovery_authority()
                            .ok_or("network has no recovery Development authority")?,
                        height,
                        action,
                    )
                    .map(Self::Recovery);
                }
                if matches!(
                    action.action_id,
                    transaction_circuit::asset_spend_v1_admission::ASSET_SPEND_ACTION_ID
                        | transaction_circuit::asset_spend_v1_admission::ASSET_ADMIN_ACTION_ID
                ) {
                    return super::asset_native::NativeAssetActionViewV1::from_pending(
                        value
                            .asset_authority()
                            .ok_or("network has no asset Development authority")?,
                        height,
                        action,
                    )
                    .map(Self::Asset);
                }
                NativeLaunchActionView::from_pending(value, height, action).map(Self::Launch)
            }
        }
    }
    pub(crate) fn exact_native_leaf(self) -> &'a [u8] {
        match self {
            Self::Historical(value) => value.exact_native_leaf(),
            Self::Launch(value) => value.exact_native_leaf(),
            Self::Asset(value) => value.exact_native_leaf(),
            Self::Recovery(value) => value.exact_native_leaf(),
        }
    }
    pub(crate) fn nullifiers(self) -> [Option<Poseidon2V8Nullifier>; 2] {
        match self {
            Self::Historical(value) => value.nullifiers(),
            Self::Launch(value) => value.nullifiers(),
            Self::Asset(value) => value.transition().nullifiers(),
            Self::Recovery(value) => value.transition().nullifiers(),
        }
    }
    pub(crate) fn commitments(self) -> [Option<Poseidon2V8Commitment>; 2] {
        match self {
            Self::Historical(value) => value.commitments(),
            Self::Launch(value) => value.commitments(),
            Self::Asset(value) => value.transition().commitments(),
            Self::Recovery(value) => value.transition().commitments(),
        }
    }
    pub(crate) fn note_anchor(self) -> Poseidon2V8NoteRoot {
        match self {
            Self::Historical(value) => value.note_anchor(),
            Self::Launch(value) => value.note_anchor(),
            Self::Asset(value) => value.transition().note_anchor(),
            Self::Recovery(value) => value.transition().note_anchor(),
        }
    }
    pub(crate) fn ordering_transition_hint(self) -> Result<Poseidon2V8PublicTransition, String> {
        match self {
            Self::Historical(value) => value.ordering_transition_hint(),
            Self::Launch(value) => value.ordering_transition_hint(),
            Self::Asset(value) => Ok(value.transition()),
            Self::Recovery(value) => Ok(value.transition()),
        }
    }
    pub(crate) fn all_commitments(self) -> [Option<Poseidon2V8Commitment>; 3] {
        match self {
            Self::Asset(value) => value.transition().all_commitments(),
            Self::Recovery(value) => value.transition().all_commitments(),
            other => {
                let [left, right] = other.commitments();
                [left, right, None]
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum NativeExactLeafVerifier {
    Historical(Poseidon2V8NativeVerifierConnector),
    Launch(NativeLaunchVerifier),
}
impl Poseidon2V8ExactLeafVerifier for NativeExactLeafVerifier {
    fn is_asset_native_leaf(&self, leaf: &[u8]) -> bool {
        match self {
            Self::Historical(value) => value.is_asset_native_leaf(leaf),
            Self::Launch(value) => value.is_asset_native_leaf(leaf),
        }
    }
    fn verify_exact_asset_leaf(
        &mut self,
        block: Poseidon2V8BlockContext,
        index: usize,
        leaf: &[u8],
        current_asset: &[u8],
        parent_note_root: Poseidon2V8NoteRoot,
        next_position: u32,
        is_spent: &mut dyn FnMut([u64; 7]) -> Result<bool, String>,
    ) -> Result<(Poseidon2V8PublicTransition, Vec<u8>), String> {
        match self {
            Self::Historical(value) => value.verify_exact_asset_leaf(
                block,
                index,
                leaf,
                current_asset,
                parent_note_root,
                next_position,
                is_spent,
            ),
            Self::Launch(value) => value.verify_exact_asset_leaf(
                block,
                index,
                leaf,
                current_asset,
                parent_note_root,
                next_position,
                is_spent,
            ),
        }
    }
    fn advance_asset_state(
        &mut self,
        block: Poseidon2V8BlockContext,
        current_asset: &[u8],
    ) -> Result<Vec<u8>, String> {
        match self {
            Self::Historical(value) => value.advance_asset_state(block, current_asset),
            Self::Launch(value) => value.advance_asset_state(block, current_asset),
        }
    }
    fn native_leaf_profile(&self) -> Poseidon2V8NativeLeafProfile {
        match self {
            Self::Historical(value) => value.native_leaf_profile(),
            Self::Launch(value) => value.native_leaf_profile(),
        }
    }
    fn exact_leaf_proof_units(&self, leaf: &[u8]) -> Result<usize, String> {
        match self {
            Self::Historical(value) => value.exact_leaf_proof_units(leaf),
            Self::Launch(value) => value.exact_leaf_proof_units(leaf),
        }
    }
    fn launch_proof_lifetime_limit(&self) -> Option<u64> {
        match self {
            Self::Historical(value) => value.launch_proof_lifetime_limit(),
            Self::Launch(value) => value.launch_proof_lifetime_limit(),
        }
    }
    fn launch_has_ongoing_hgn_authority(&self) -> bool {
        match self {
            Self::Historical(value) => value.launch_has_ongoing_hgn_authority(),
            Self::Launch(value) => value.launch_has_ongoing_hgn_authority(),
        }
    }
    fn launch_proof_action_limit(&self) -> Option<usize> {
        match self {
            Self::Historical(value) => value.launch_proof_action_limit(),
            Self::Launch(value) => value.launch_proof_action_limit(),
        }
    }
    fn launch_reference_context(&self) -> Option<LaunchReferenceContext> {
        match self {
            Self::Historical(value) => value.launch_reference_context(),
            Self::Launch(value) => value.launch_reference_context(),
        }
    }
    fn set_launch_references(
        &mut self,
        references: CanonicalLaunchReferences,
    ) -> Result<(), String> {
        match self {
            Self::Historical(value) => value.set_launch_references(references),
            Self::Launch(value) => value.set_launch_references(references),
        }
    }
    fn verify_exact_v8_leaf(
        &mut self,
        block: Poseidon2V8BlockContext,
        index: usize,
        leaf: &[u8],
    ) -> Result<Poseidon2V8PublicTransition, String> {
        match self {
            Self::Historical(value) => value.verify_exact_v8_leaf(block, index, leaf),
            Self::Launch(value) => value.verify_exact_v8_leaf(block, index, leaf),
        }
    }
    fn verify_exact_v8_leaf_window(
        &mut self,
        block: Poseidon2V8BlockContext,
        index: usize,
        leaves: &[&[u8]],
    ) -> Option<Vec<Result<Poseidon2V8PublicTransition, String>>> {
        match self {
            Self::Historical(value) => value.verify_exact_v8_leaf_window(block, index, leaves),
            Self::Launch(value) => value.verify_exact_v8_leaf_window(block, index, leaves),
        }
    }
    fn record_window_verified_transition(&mut self, transition: Poseidon2V8PublicTransition) {
        match self {
            Self::Historical(value) => value.record_window_verified_transition(transition),
            Self::Launch(value) => value.record_window_verified_transition(transition),
        }
    }
}

/// Syntax preflight pins the compiled relation while borrowing the advertised
/// chain solely for framing. This does not authenticate that chain: contextual
/// decoding under LaunchStartup checks the actual immutable network later.
pub(crate) fn preflight_private_spend_args(bytes: &[u8]) -> Result<(), String> {
    use protocol_shielded_pool::private_spend_transport::{self, ExpectedContext};
    let chain: [u8; 32] = bytes
        .get(72..104)
        .ok_or("private spend preamble is truncated")?
        .try_into()
        .map_err(|_| "private spend chain width")?;
    let relation = transaction_circuit::private_spend::relation_digest();
    let expected = ExpectedContext::new(chain, relation[..48].try_into().expect("digest prefix"))
        .map_err(|e| e.to_string())?;
    let decoded =
        private_spend_transport::decode_exact(expected, bytes).map_err(|e| e.to_string())?;
    for ciphertext in decoded.ciphertexts {
        crypto::private_note_encryption::PrivateNoteCiphertextRef::from_bytes_exact(ciphertext)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Allocation-bounded syntax only; no release or cryptographic authority.
pub(crate) fn preflight_native_proof_action_args(action: &PendingAction) -> Result<(), String> {
    match action.action_id {
        super::asset_recovery_native::RECOVERY_SPEND_ACTION_ID
        | super::asset_recovery_native::RECOVERY_ADMIN_ACTION_ID => {
            if super::admission::native_recovery_action_scope_valid(action) {
                Ok(())
            } else {
                Err("recovery outer fields or exact framing differ".into())
            }
        }
        transaction_circuit::asset_spend_v1_admission::ASSET_SPEND_ACTION_ID
        | transaction_circuit::asset_spend_v1_admission::ASSET_ADMIN_ACTION_ID => {
            super::asset_native::preflight_pending(action)
        }
        protocol_versioning::launch_candidate::PRIVATE_SPEND_ACTION_ID => {
            preflight_private_spend_args(&action.public_args)
        }
        super::ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE => {
            super::poseidon2_v8_verifier::preflight_poseidon2_v8_selected_action_args(
                &action.public_args,
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
        }
        protocol_versioning::launch_candidate::RP06_ACTION_ID => {
            protocol_shielded_pool::rp06_transport::preflight_rp06_inline_args_exact(
                &action.public_args,
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
        }
        protocol_versioning::launch_candidate::HTLC_ACTION_ID => {
            transaction_circuit::smallwood_htlc_transport::decode_candidate_exact(
                &action.public_args,
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
        }
        _ => Err("unsupported exact proof route".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::launch_reference::CanonicalLaunchCheckpoint;

    #[test]
    fn exact_dispatch_forwards_launch_snapshots_and_historical_dispatch_rejects_them() {
        let startup = LaunchStartup::qualification_for_test(
            &NativeNetworkIdentity::development(),
            [2; 32],
            Poseidon2V8Root::new([0; 7]).unwrap(),
            1,
            100,
            10,
        )
        .unwrap();
        let context = LaunchReferenceContext::from_startup(startup).unwrap();
        let references = CanonicalLaunchReferences::from_validated_chain(
            context,
            [2; 32],
            0,
            vec![CanonicalLaunchCheckpoint::new(
                [2; 32],
                [0; 32],
                0,
                startup.note_genesis_root(),
                startup.stablecoin_genesis_root(),
            )
            .unwrap()],
        )
        .unwrap();
        let mut launch = NativeProofBinding::Launch(startup).connector();
        assert_eq!(launch.launch_reference_context(), Some(context));
        assert!(launch.set_launch_references(references.clone()).is_ok());
        let historical = Poseidon2V8ProductionBinding::for_test(
            protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID,
            1,
            Poseidon2V8Root::new([0; 7]).unwrap(),
            Poseidon2V8NoteRoot::new(
                protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NOTE_GENESIS_ROOT,
            )
            .unwrap(),
        )
        .unwrap();
        let mut historical = NativeProofBinding::Historical(historical).connector();
        assert!(historical.launch_reference_context().is_none());
        assert!(historical.set_launch_references(references).is_err());
    }
}

#[cfg(test)]
mod private_spend_routing_tests {
    use super::*;
    use crate::native::*;
    use protocol_shielded_pool::private_spend_transport as transport;
    #[test]
    fn common_route_uses_private_ciphertext_shape_and_shared_proof_classifiers() {
        let ciphertexts = [
            [3; transport::CIPHERTEXT_BYTES],
            [4; transport::CIPHERTEXT_BYTES],
        ];
        let digest = transaction_circuit::private_spend::relation_digest();
        let public = transport::PublicStatement {
            relation_digest: digest[..48].try_into().unwrap(),
            chain_id: [1; 32],
            reference_parent_hash: [2; 32],
            reference_parent_height: 0,
            merkle_root: [0; 7],
            fee: 0,
            nullifiers: [[1; 7], [2; 7]],
            commitments: [[3; 7], [4; 7]],
            secret_release: 0,
            released_secret: [0; 32],
            ciphertext_commitments: ciphertexts
                .each_ref()
                .map(|c| transaction_core::hashing_pq::ciphertext_hash_bytes(c)),
        };
        // Shape-only proof marker: no cryptographic acceptance is asserted.
        let body = transport::encode(&public, [&ciphertexts[0], &ciphertexts[1]], b"SMZL").unwrap();
        preflight_private_spend_args(&body).unwrap();
        let mut action = PendingAction {
            tx_hash: ActionId48::ZERO,
            binding: protocol_versioning::launch_candidate::PRIVATE_SPEND_VERSION_BINDING.into(),
            family_id: FAMILY_SHIELDED_POOL,
            action_id: PRIVATE_SPEND_ACTION_ID,
            anchor: [0; 48],
            nullifiers: vec![],
            commitments: vec![],
            ciphertext_hashes: public.ciphertext_commitments.to_vec(),
            ciphertext_sizes: vec![transport::CIPHERTEXT_BYTES as u32; 2],
            public_args: body.clone(),
            fee: 0,
            candidate_artifact: None,
        };
        assert!(native_submit_action_is_transfer_route(
            action.family_id,
            action.action_id
        ));
        assert!(native_submit_action_route_supported(
            action.family_id,
            action.action_id
        ));
        assert!(is_shielded_transfer_action(&action));
        assert!(is_poseidon2_v8_action(&action));
        assert!(transfer_action_scope_valid(&action));
        assert!(!owns_legacy_ciphertext_da_rows(&action));
        assert!(ensure_native_v3_active_action_route_ids(
            action.family_id,
            action.action_id,
            false
        )
        .is_ok());
        assert_eq!(
            native_action_request_public_args_cap(action.family_id, action.action_id),
            transport::MAX_CARRIER_BYTES
        );
        validate_transfer_action_payload(&action).unwrap();
        action.ciphertext_sizes[0] = 2147;
        assert!(!transfer_action_scope_valid(&action));
        action.ciphertext_sizes = vec![transport::CIPHERTEXT_BYTES as u32];
        action.ciphertext_hashes.pop();
        assert!(!transfer_action_scope_valid(&action));
        let mut changed = body;
        changed[transport::PREAMBLE_BYTES] ^= 1;
        assert!(preflight_private_spend_args(&changed).is_err());
    }
}

#[cfg(test)]
mod ongoing_hgn_accounting_forwarding_tests {
    use super::*;

    #[test]
    fn exact_dispatch_preserves_ongoing_and_bounded_lifetime_authority() {
        let network = crate::native::network_profile::NativeNetworkIdentity::development();
        let stable_root = crate::native::poseidon2_v8_state::Poseidon2V8Root::new([0; 7]).unwrap();
        let ongoing =
            LaunchStartup::qualification_ongoing_hgn_for_test(&network, [2; 32], stable_root)
                .unwrap();
        let ongoing = NativeProofBinding::Launch(ongoing).connector();
        assert!(ongoing.launch_has_ongoing_hgn_authority());
        assert_eq!(ongoing.launch_proof_lifetime_limit(), None);
        let bounded =
            LaunchStartup::qualification_for_test(&network, [2; 32], stable_root, 1, 10, 100)
                .unwrap();
        let bounded = NativeProofBinding::Launch(bounded).connector();
        assert!(!bounded.launch_has_ongoing_hgn_authority());
        assert_eq!(bounded.launch_proof_lifetime_limit(), Some(100));
    }
}
