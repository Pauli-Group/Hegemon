//! Closed source dispatch for the common private spend candidate and historical
//! network-bound RP06/HTLC identities. Old bytes retain their exact decoders.
//! Shape views are ordering hints only. The exact source verifier and canonical
//! StateStore jointly own proof validity, anchor history, roots and nullifiers.
#![allow(dead_code)]

use super::launch_reference::{
    CanonicalLaunchReferences, CheckedLaunchReference, LaunchReferenceContext,
};
use super::network_profile::NativeNetworkIdentity;
use super::poseidon2_v8_state::{
    Poseidon2V8BlockContext, Poseidon2V8Commitment, Poseidon2V8ExactLeafVerifier,
    Poseidon2V8NativeLeafProfile, Poseidon2V8NoteRoot, Poseidon2V8NoteTreeState,
    Poseidon2V8Nullifier, Poseidon2V8PublicTransition, Poseidon2V8Root,
    Poseidon2V8StablecoinEffect,
};
use super::{ActionId48, PendingAction, FAMILY_SHIELDED_POOL};
use codec::Encode;
use protocol_kernel::types::KernelVersionBinding;
use protocol_shielded_pool::private_spend_transport;
use protocol_shielded_pool::rp06_transport::{self, Rp06ExpectedContext};
use protocol_versioning::launch_candidate::{self, LaunchProofKind, LaunchProofRequest};
use protocol_versioning::{ProofAuthorityClass, TxProofBackend};
use transaction_circuit::{
    private_spend, smallwood_htlc, smallwood_htlc_transport,
    smallwood_poseidon2_v8_rp06::{
        rp06_program_identity_sha512, validate_rp06_transcript_bytes, verify_rp06_candidate_bytes,
        Rp06PublicStatement,
    },
};
use transaction_core::hashing_pq::ciphertext_hash_bytes;

/// Startup data derives from the exact validated network and source registry.
/// No caller interval, historical capability, or manifest enables this value.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LaunchStartup {
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    manifest_digest: [u8; 64],
    rp06_relation: [u8; 64],
    htlc_relation: [u8; 64],
    private_spend_relation: [u8; 64],
    activation: u64,
    end: Option<u64>,
    stable_root: Poseidon2V8Root,
    note_root: Poseidon2V8NoteRoot,
    max_actions: usize,
    max_total_proofs: Option<u64>,
    max_proof_bytes: usize,
    development_candidate: bool,
    // Immutable profile selection, derived from the validated manifest.
    private_spend_only: bool,
    assets: Option<super::asset_native::AssetDevelopmentAuthorityV1>,
    recovery: Option<super::asset_recovery_native::RecoveryDevelopmentAuthorityV1>,
    #[cfg(test)]
    qualification_only: bool,
}
impl LaunchStartup {
    pub(crate) fn from_source(
        network: &NativeNetworkIdentity,
        actual_genesis_hash: [u8; 32],
    ) -> Result<Option<Self>, String> {
        #[cfg(feature = "development-candidate")]
        if network.profile() == super::network_profile::NativeNetworkProfile::Development {
            if let Some(source) = network.development_candidate() {
                return Self::from_development_candidate(network, actual_genesis_hash, source)
                    .map(Some);
            }
        }
        let Some(manifest_digest) = network.manifest_digest() else {
            return Ok(None);
        };
        Self::from_source_identity(network.chain_id(), actual_genesis_hash, manifest_digest)
    }
    pub(crate) fn from_source_identity(
        chain_id: [u8; 32],
        genesis_hash: [u8; 32],
        manifest_digest: [u8; 64],
    ) -> Result<Option<Self>, String> {
        if chain_id == [0; 32] || genesis_hash == [0; 32] || manifest_digest == [0; 64] {
            return Err("launch startup has a zero network/genesis/manifest identity".into());
        }
        let rp06_relation = rp06_program_identity_sha512();
        let htlc_relation = smallwood_htlc::relation_digest();
        let private_spend_relation = private_spend::relation_digest();
        // The common spend source is independently authorized. Its startup
        // lifetime, roots and budgets must not depend on historical split-route
        // capabilities, even when those also exist for this exact network.
        if let Some(source) = launch_candidate::launch_source_capability(
            LaunchProofKind::PrivateSpend,
            chain_id,
            genesis_hash,
            manifest_digest,
            private_spend_relation,
        ) {
            let startup = Self {
                chain_id,
                genesis_hash,
                manifest_digest,
                rp06_relation,
                htlc_relation,
                private_spend_relation,
                activation: source.activation_height(),
                end: source.deactivation_height_exclusive(),
                stable_root: Poseidon2V8Root::new(source.stablecoin_genesis_root())
                    .map_err(|e| e.to_string())?,
                note_root: Poseidon2V8NoteRoot::new(source.note_genesis_root())
                    .map_err(|e| e.to_string())?,
                max_actions: source.max_proof_actions_per_block(),
                max_total_proofs: source.max_total_proofs(),
                max_proof_bytes: source.max_proof_bytes(),
                development_candidate: false,
                private_spend_only: true,
                assets: None,
                recovery: None,
                #[cfg(test)]
                qualification_only: false,
            };
            startup.validate()?;
            return Ok(Some(startup));
        }
        // Only networks without a common spend capability use the historical
        // paired-source startup contract below.
        let rp06 = launch_candidate::launch_source_capability(
            LaunchProofKind::Rp06,
            chain_id,
            genesis_hash,
            manifest_digest,
            rp06_relation,
        );
        let htlc = launch_candidate::launch_source_capability(
            LaunchProofKind::Htlc,
            chain_id,
            genesis_hash,
            manifest_digest,
            htlc_relation,
        );
        let (Some(rp06), Some(htlc)) = (rp06, htlc) else {
            return Ok(None);
        };
        if rp06.activation_height() != htlc.activation_height()
            || rp06.deactivation_height_exclusive() != htlc.deactivation_height_exclusive()
            || rp06.stablecoin_genesis_root() != htlc.stablecoin_genesis_root()
            || rp06.note_genesis_root() != htlc.note_genesis_root()
        {
            return Err("launch source capabilities disagree on lifetime or genesis roots".into());
        }
        if rp06.deactivation_height_exclusive().is_none() || htlc.deactivation_height_exclusive().is_none() {
            return Err("historical paired routes require finite source expiry".into());
        }
        let startup = Self {
            chain_id,
            genesis_hash,
            manifest_digest,
            rp06_relation,
            htlc_relation,
            private_spend_relation,
            activation: rp06.activation_height(),
            end: rp06.deactivation_height_exclusive(),
            stable_root: Poseidon2V8Root::new(rp06.stablecoin_genesis_root())
                .map_err(|e| e.to_string())?,
            note_root: Poseidon2V8NoteRoot::new(rp06.note_genesis_root())
                .map_err(|e| e.to_string())?,
            max_actions: rp06
                .max_proof_actions_per_block()
                .min(htlc.max_proof_actions_per_block()),
            // Charge every accepted launch proof against both budgets, conservatively.
            max_total_proofs: Some(rp06.max_total_proofs().ok_or("historical RP06 proof limit absent")?.min(htlc.max_total_proofs().ok_or("historical HTLC proof limit absent")?)),
            max_proof_bytes: rp06.max_proof_bytes().min(htlc.max_proof_bytes()),
            development_candidate: false,
            private_spend_only: false,
            assets: None,
            recovery: None,
            #[cfg(test)]
            qualification_only: false,
        };
        startup.validate()?;
        Ok(Some(startup))
    }

    #[cfg(feature = "development-candidate")]
    fn from_development_candidate(
        network: &NativeNetworkIdentity,
        actual_genesis_hash: [u8; 32],
        source: &super::network_profile::DevelopmentCandidateManifest,
    ) -> Result<Self, String> {
        use super::network_profile::NativeNetworkProfile;
        if network.profile() != NativeNetworkProfile::Development {
            return Err("development candidate authority requires the Development profile".into());
        }
        let manifest_digest = network
            .manifest_digest()
            .ok_or("development candidate requires an explicit manifest")?;
        source
            .validate_private_spend_source()
            .map_err(|e| e.to_string())?;
        let mut startup = Self {
            chain_id: network.chain_id(),
            genesis_hash: actual_genesis_hash,
            manifest_digest,
            rp06_relation: rp06_program_identity_sha512(),
            htlc_relation: smallwood_htlc::relation_digest(),
            private_spend_relation: private_spend::relation_digest(),
            activation: source.activation_height,
            end: Some(source.deactivation_height_exclusive),
            stable_root: Poseidon2V8Root::new(source.stablecoin_genesis_root)
                .map_err(|e| e.to_string())?,
            note_root: Poseidon2V8NoteRoot::new(source.note_genesis_root)
                .map_err(|e| e.to_string())?,
            max_actions: source.max_proof_actions_per_block,
            max_total_proofs: Some(source.max_total_proofs),
            max_proof_bytes: source.max_proof_bytes,
            development_candidate: true,
            private_spend_only: source.private_spend_only,
            assets: None,
            recovery: None,
            #[cfg(test)]
            qualification_only: false,
        };
        startup.validate()?;
        startup.assets = super::asset_native::AssetDevelopmentAuthorityV1::from_source(
            network,
            actual_genesis_hash,
            startup,
        )?;
        startup.recovery = network.development_recovery().map(|selected| {
            super::asset_recovery_native::RecoveryDevelopmentAuthorityV1::from_selected_manifest(
                network, actual_genesis_hash, startup, selected,
            )
        }).transpose()?;
        Ok(startup)
    }
    fn validate(self) -> Result<(), String> {
        let limits_valid = match (self.end, self.max_total_proofs) {
            (Some(end), Some(total)) => self.activation < end && end != u64::MAX && total > 0,
            (None, None) => self.has_ongoing_hgn_authority(),
            _ => false,
        };
        if self.chain_id == [0; 32]
            || self.genesis_hash == [0; 32]
            || self.manifest_digest == [0; 64]
            || self.activation == 0
            || !limits_valid
            || self.max_actions == 0
            || self.max_actions > 512
            || self.max_proof_bytes == 0
            || self.max_proof_bytes
                > smallwood_htlc_transport::MAX_CANDIDATE_CARRIER_BYTES
                    .max(private_spend_transport::MAX_CARRIER_BYTES)
            || self.note_root
                != Poseidon2V8NoteTreeState::new_empty()
                    .map_err(|e| e.to_string())?
                    .root()
        {
            return Err("launch source lifetime/budget/canonical empty note root rejected".into());
        }
        Ok(())
    }
    pub(crate) const fn active_at(self, height: u64) -> bool {
        height >= self.activation && match self.end {
            Some(end) => height < end,
            None => self.has_ongoing_hgn_authority(),
        }
    }
    pub(crate) const fn activation_height(self) -> u64 {
        self.activation
    }
    pub(crate) const fn deactivation_height_exclusive(self) -> Option<u64> {
        self.end
    }
    pub(crate) const fn activation_genesis_hash(self) -> [u8; 32] {
        self.genesis_hash
    }
    pub(crate) const fn stablecoin_genesis_root(self) -> Poseidon2V8Root {
        self.stable_root
    }
    pub(crate) const fn note_genesis_root(self) -> Poseidon2V8NoteRoot {
        self.note_root
    }
    pub(crate) const fn max_proof_actions_per_block(self) -> usize {
        self.max_actions
    }
    pub(crate) const fn max_total_proofs(self) -> Option<u64> {
        self.max_total_proofs
    }
    pub(crate) const fn max_proof_bytes(self) -> usize {
        self.max_proof_bytes
    }
    pub(crate) const fn has_ongoing_hgn_authority(self) -> bool {
        self.private_spend_only && !self.development_candidate
            && self.end.is_none() && self.max_total_proofs.is_none()
    }
    pub(crate) const fn is_development_candidate(self) -> bool {
        self.development_candidate
    }
    pub(crate) const fn is_private_spend_only(self) -> bool {
        self.private_spend_only
    }
    pub(crate) const fn asset_authority(
        self,
    ) -> Option<super::asset_native::AssetDevelopmentAuthorityV1> {
        self.assets
    }
    pub(crate) const fn recovery_authority(
        self,
    ) -> Option<super::asset_recovery_native::RecoveryDevelopmentAuthorityV1> {
        self.recovery
    }
    pub(crate) const fn chain_id(self) -> [u8; 32] {
        self.chain_id
    }
    pub(crate) const fn manifest_digest(self) -> [u8; 64] {
        self.manifest_digest
    }
    pub(crate) const fn connector(self) -> NativeLaunchVerifier {
        NativeLaunchVerifier {
            startup: self,
            references: None,
        }
    }
    fn rp06_context(self) -> Result<Rp06ExpectedContext, String> {
        Rp06ExpectedContext::new(
            self.chain_id,
            self.rp06_relation[..48].try_into().expect("digest prefix"),
        )
        .map_err(|e| e.to_string())
    }
    fn private_spend_context(self) -> Result<private_spend_transport::ExpectedContext, String> {
        private_spend_transport::ExpectedContext::new(
            self.chain_id,
            self.private_spend_relation[..48]
                .try_into()
                .expect("digest prefix"),
        )
        .map_err(|e| e.to_string())
    }
    fn require_profile_action(self, action_id: u16) -> Result<(), String> {
        if self.private_spend_only
            && !matches!(
                action_id,
                launch_candidate::PRIVATE_SPEND_ACTION_ID
                    | launch_candidate::ALLOCATED_REWARD_ACTION_ID
            )
        {
            return Err("private-spend-only profile rejects historical split spend routes".into());
        }
        Ok(())
    }

    pub(crate) fn require_route_authority(
        self,
        height: u64,
        action_id: u16,
        proof_class: ProofAuthorityClass,
        proof_bytes: usize,
    ) -> Result<(), String> {
        if !self.active_at(height) {
            return Err("launch action outside source lifetime".into());
        }
        if matches!(
            action_id,
            super::asset_recovery_native::RECOVERY_SPEND_ACTION_ID
                | super::asset_recovery_native::RECOVERY_ADMIN_ACTION_ID
        ) {
            if proof_class != ProofAuthorityClass::Transaction {
                return Err("recovery requires transaction proof authority".into());
            }
            return self
                .recovery
                .ok_or("network has no recovery Development authority")?
                .require_route(
                    height,
                    super::asset_recovery_native::native_binding(),
                    FAMILY_SHIELDED_POOL,
                    action_id,
                    proof_bytes,
                );
        }
        if matches!(
            action_id,
            transaction_circuit::asset_spend_v1_admission::ASSET_SPEND_ACTION_ID
                | transaction_circuit::asset_spend_v1_admission::ASSET_ADMIN_ACTION_ID
        ) {
            if proof_class != ProofAuthorityClass::Transaction {
                return Err(
                    "asset routes require their separate transaction proof authority".into(),
                );
            }
            return self
                .assets
                .ok_or("network has no asset Development authority")?
                .require_route(
                    height,
                    super::asset_native::native_binding(),
                    FAMILY_SHIELDED_POOL,
                    action_id,
                    proof_bytes,
                );
        }
        self.require_profile_action(action_id)?;
        let (kind, binding, relation_digest, profile_id, domain_set) = match action_id {
            launch_candidate::PRIVATE_SPEND_ACTION_ID => (
                LaunchProofKind::PrivateSpend,
                launch_candidate::PRIVATE_SPEND_VERSION_BINDING,
                self.private_spend_relation,
                launch_candidate::PRIVATE_SPEND_PROFILE_ID,
                launch_candidate::PRIVATE_SPEND_DOMAIN_SET,
            ),
            launch_candidate::RP06_ACTION_ID => (
                LaunchProofKind::Rp06,
                launch_candidate::RP06_VERSION_BINDING,
                self.rp06_relation,
                launch_candidate::RP06_PROFILE_ID,
                launch_candidate::RP06_DOMAIN_SET,
            ),
            launch_candidate::HTLC_ACTION_ID => (
                LaunchProofKind::Htlc,
                launch_candidate::HTLC_VERSION_BINDING,
                self.htlc_relation,
                launch_candidate::HTLC_PROFILE_ID,
                launch_candidate::HTLC_DOMAIN_SET,
            ),
            launch_candidate::ALLOCATED_REWARD_ACTION_ID
                if self.private_spend_only && proof_class == ProofAuthorityClass::MintSource =>
            {
                (
                    LaunchProofKind::PrivateSpend,
                    launch_candidate::PRIVATE_SPEND_VERSION_BINDING,
                    self.private_spend_relation,
                    launch_candidate::PRIVATE_SPEND_PROFILE_ID,
                    launch_candidate::PRIVATE_SPEND_DOMAIN_SET,
                )
            }
            launch_candidate::ALLOCATED_REWARD_ACTION_ID
                if proof_class == ProofAuthorityClass::MintSource =>
            {
                (
                    LaunchProofKind::Rp06,
                    launch_candidate::RP06_VERSION_BINDING,
                    self.rp06_relation,
                    launch_candidate::RP06_PROFILE_ID,
                    launch_candidate::RP06_DOMAIN_SET,
                )
            }
            _ => return Err("unknown launch source route".into()),
        };
        let correct_class = match action_id {
            launch_candidate::RP06_ACTION_ID
            | launch_candidate::HTLC_ACTION_ID
            | launch_candidate::PRIVATE_SPEND_ACTION_ID => {
                proof_class == ProofAuthorityClass::Transaction && proof_bytes > 0
            }
            launch_candidate::ALLOCATED_REWARD_ACTION_ID => {
                proof_class == ProofAuthorityClass::MintSource && proof_bytes == 0
            }
            _ => false,
        };
        if !correct_class {
            return Err("launch source route/class/proof length mismatch".into());
        }
        let request = LaunchProofRequest {
            kind,
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            manifest_digest: self.manifest_digest,
            relation_digest,
            height,
            binding,
            family_id: FAMILY_SHIELDED_POOL,
            action_id,
            proof_class,
            backend_id: TxProofBackend::SmallwoodCandidate.wire_id(),
            profile_id,
            domain_set,
            proof_bytes,
        };
        if self.development_candidate {
            return self.require_development_candidate_request(request);
        }
        #[cfg(test)]
        if self.qualification_only {
            return Ok(());
        }
        let capability = launch_candidate::launch_proof_authority(request)
            .ok_or("launch source registry has no exact action authority")?;
        if !capability.allows(request) {
            return Err("launch source capability rejected exact action".into());
        }
        Ok(())
    }

    fn require_development_candidate_request(
        self,
        request: LaunchProofRequest,
    ) -> Result<(), String> {
        if request.chain_id != self.chain_id
            || request.genesis_hash != self.genesis_hash
            || request.manifest_digest != self.manifest_digest
            || request.height < self.activation
            || self.end.is_none_or(|end| request.height >= end)
            || request.family_id != FAMILY_SHIELDED_POOL
            || request.backend_id != TxProofBackend::SmallwoodCandidate.wire_id()
        {
            return Err(
                "development candidate request differs from its finite source identity".into(),
            );
        }
        self.require_profile_action(request.action_id)?;
        let expected = match request.action_id {
            launch_candidate::PRIVATE_SPEND_ACTION_ID
                if request.proof_class == ProofAuthorityClass::Transaction =>
            {
                (
                    LaunchProofKind::PrivateSpend,
                    launch_candidate::PRIVATE_SPEND_VERSION_BINDING,
                    self.private_spend_relation,
                    launch_candidate::PRIVATE_SPEND_PROFILE_ID,
                    launch_candidate::PRIVATE_SPEND_DOMAIN_SET,
                    true,
                )
            }
            launch_candidate::RP06_ACTION_ID
                if request.proof_class == ProofAuthorityClass::Transaction =>
            {
                (
                    LaunchProofKind::Rp06,
                    launch_candidate::RP06_VERSION_BINDING,
                    self.rp06_relation,
                    launch_candidate::RP06_PROFILE_ID,
                    launch_candidate::RP06_DOMAIN_SET,
                    true,
                )
            }
            launch_candidate::HTLC_ACTION_ID
                if request.proof_class == ProofAuthorityClass::Transaction =>
            {
                (
                    LaunchProofKind::Htlc,
                    launch_candidate::HTLC_VERSION_BINDING,
                    self.htlc_relation,
                    launch_candidate::HTLC_PROFILE_ID,
                    launch_candidate::HTLC_DOMAIN_SET,
                    true,
                )
            }
            launch_candidate::ALLOCATED_REWARD_ACTION_ID
                if self.private_spend_only
                    && request.proof_class == ProofAuthorityClass::MintSource =>
            {
                (
                    LaunchProofKind::PrivateSpend,
                    launch_candidate::PRIVATE_SPEND_VERSION_BINDING,
                    self.private_spend_relation,
                    launch_candidate::PRIVATE_SPEND_PROFILE_ID,
                    launch_candidate::PRIVATE_SPEND_DOMAIN_SET,
                    false,
                )
            }
            launch_candidate::ALLOCATED_REWARD_ACTION_ID
                if request.proof_class == ProofAuthorityClass::MintSource =>
            {
                (
                    LaunchProofKind::Rp06,
                    launch_candidate::RP06_VERSION_BINDING,
                    self.rp06_relation,
                    launch_candidate::RP06_PROFILE_ID,
                    launch_candidate::RP06_DOMAIN_SET,
                    false,
                )
            }
            _ => return Err("development candidate action/class rejected".into()),
        };
        let (kind, binding, relation, profile, domain, proof_required) = expected;
        let route_proof_cap = match kind {
            LaunchProofKind::PrivateSpend => private_spend_transport::MAX_PROOF_BYTES,
            LaunchProofKind::Rp06 => rp06_transport::RP06_CANDIDATE_MAX_PROOF_BYTES,
            LaunchProofKind::Htlc => smallwood_htlc_transport::MAX_CANDIDATE_CARRIER_BYTES,
        };
        if request.kind != kind
            || request.binding != binding
            || request.relation_digest != relation
            || request.profile_id != profile
            || request.domain_set != domain
            || (proof_required
                && (request.proof_bytes == 0
                    || request.proof_bytes > self.max_proof_bytes
                    || request.proof_bytes > route_proof_cap))
            || (!proof_required && request.proof_bytes != 0)
        {
            return Err(
                "development candidate relation, binding, or proof byte cap rejected".into(),
            );
        }
        Ok(())
    }
    /// Fixed public route gate. Exact proof bytes are checked again after decoding.
    pub(crate) fn authorizes_route(
        self,
        height: u64,
        binding: KernelVersionBinding,
        family_id: u16,
        action_id: u16,
    ) -> bool {
        if family_id != FAMILY_SHIELDED_POOL {
            return false;
        }
        if matches!(
            action_id,
            super::asset_recovery_native::RECOVERY_SPEND_ACTION_ID
                | super::asset_recovery_native::RECOVERY_ADMIN_ACTION_ID
        ) {
            return self.recovery.is_some_and(|authority| {
                authority.authorizes_route(height, binding, family_id, action_id)
            });
        }
        if matches!(
            action_id,
            transaction_circuit::asset_spend_v1_admission::ASSET_SPEND_ACTION_ID
                | transaction_circuit::asset_spend_v1_admission::ASSET_ADMIN_ACTION_ID
        ) {
            return self.assets.is_some_and(|authority| {
                authority.authorizes_route(height, binding, family_id, action_id)
            });
        }
        let (expected, class, bytes) = match action_id {
            launch_candidate::PRIVATE_SPEND_ACTION_ID => (
                launch_candidate::PRIVATE_SPEND_VERSION_BINDING,
                ProofAuthorityClass::Transaction,
                1,
            ),
            launch_candidate::RP06_ACTION_ID => (
                launch_candidate::RP06_VERSION_BINDING,
                ProofAuthorityClass::Transaction,
                1,
            ),
            launch_candidate::HTLC_ACTION_ID => (
                launch_candidate::HTLC_VERSION_BINDING,
                ProofAuthorityClass::Transaction,
                1,
            ),
            // Public reward bytes retain their existing binding. The source
            // request inside require_route_authority uses the selected spend
            // capability's identity independently of this wire-format gate.
            launch_candidate::ALLOCATED_REWARD_ACTION_ID => (
                launch_candidate::RP06_VERSION_BINDING,
                ProofAuthorityClass::MintSource,
                0,
            ),
            _ => return false,
        };
        binding == expected.into()
            && self
                .require_route_authority(height, action_id, class, bytes)
                .is_ok()
    }
    /// Explicit ongoing common-HGN fixture, only for local qualification tests.
    /// This never installs source authority or bypasses proof verification.
    #[cfg(test)]
    pub(crate) fn qualification_ongoing_hgn_for_test(
        network: &NativeNetworkIdentity,
        genesis_hash: [u8; 32],
        stable_root: Poseidon2V8Root,
    ) -> Result<Self, String> {
        let mut startup = Self::qualification_for_test(network, genesis_hash, stable_root, 1, 2, 1)?;
        startup.private_spend_only = true;
        startup.end = None;
        startup.max_total_proofs = None;
        startup.validate()?;
        Ok(startup)
    }

    /// Explicit fixture qualification. This does not install registry authority,
    /// bypass cryptographic verification, or appear in a production binary.
    #[cfg(test)]
    pub(crate) fn qualification_for_test(
        network: &NativeNetworkIdentity,
        genesis_hash: [u8; 32],
        stable_root: Poseidon2V8Root,
        activation: u64,
        end: u64,
        max_total_proofs: u64,
    ) -> Result<Self, String> {
        let startup = Self {
            chain_id: network.chain_id(),
            genesis_hash,
            manifest_digest: network
                .manifest_digest()
                .ok_or("qualification requires an explicit manifest")?,
            rp06_relation: rp06_program_identity_sha512(),
            htlc_relation: smallwood_htlc::relation_digest(),
            private_spend_relation: private_spend::relation_digest(),
            activation,
            end: Some(end),
            stable_root,
            note_root: Poseidon2V8NoteTreeState::new_empty()
                .map_err(|e| e.to_string())?
                .root(),
            max_actions: 512,
            max_total_proofs: Some(max_total_proofs),
            max_proof_bytes: smallwood_htlc_transport::MAX_CANDIDATE_CARRIER_BYTES,
            development_candidate: false,
            private_spend_only: false,
            assets: None,
            recovery: None,
            qualification_only: true,
        };
        if genesis_hash == [0; 32] {
            return Err("qualification genesis is zero".into());
        }
        startup.validate()?;
        Ok(startup)
    }
}

/// All fields derive from exact public source grammar; hints never authorize state.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeLaunchActionView<'a> {
    exact_leaf: &'a [u8],
    transition: Poseidon2V8PublicTransition,
    fee: u64,
}
impl<'a> NativeLaunchActionView<'a> {
    pub(crate) fn from_pending(
        startup: LaunchStartup,
        height: u64,
        action: &'a PendingAction,
    ) -> Result<Self, String> {
        if !startup.active_at(height)
            || height == 0
            || action.family_id != FAMILY_SHIELDED_POOL
            || action.anchor != [0; 48]
            || !action.nullifiers.is_empty()
            || !action.commitments.is_empty()
            || action.candidate_artifact.is_some()
        {
            return Err("launch outer route/lifetime or forbidden legacy fields".into());
        }
        startup.require_profile_action(action.action_id)?;
        let (view, hashes, sizes) = match action.action_id {
            launch_candidate::PRIVATE_SPEND_ACTION_ID => {
                if action.binding != launch_candidate::PRIVATE_SPEND_VERSION_BINDING.into()
                    || action.encoded_size() > private_spend_transport::MAX_CARRIER_BYTES + 225
                {
                    return Err("private spend outer binding/byte cap mismatch".into());
                }
                let carrier = private_spend_transport::decode_exact(
                    startup.private_spend_context()?,
                    &action.public_args,
                )
                .map_err(|e| e.to_string())?;
                let statement = private_spend_statement(&carrier.public);
                // Every hidden mode uses R+1..R+13. No mode-dependent metadata
                // or public branch is consulted to set the reference window.
                require_unchecked_reference_age(
                    startup,
                    height,
                    statement.reference_parent_height,
                    false,
                )?;
                for bytes in carrier.ciphertexts {
                    canonical_private_ciphertext(bytes)?;
                }
                let transition = private_spend_transition(startup, &statement)?
                    .with_launch_application_hint(height - 1);
                (
                    Self {
                        exact_leaf: carrier.raw,
                        transition,
                        fee: statement.fee,
                    },
                    statement.ciphertext_commitments.to_vec(),
                    vec![private_spend_transport::CIPHERTEXT_BYTES as u32; 2],
                )
            }
            launch_candidate::RP06_ACTION_ID => {
                if action.binding != launch_candidate::RP06_VERSION_BINDING.into()
                    || action.encoded_size() > rp06_transport::RP06_CANDIDATE_MAX_INLINE_BYTES + 225
                {
                    return Err("RP06 outer binding/byte cap mismatch".into());
                }
                let leaf = rp06_transport::decode_rp06_inline_args_exact(
                    startup.rp06_context()?,
                    &action.public_args,
                )
                .map_err(|e| e.to_string())?
                .native_leaf();
                let statement = parse_rp06_statement(leaf.preamble())?;
                require_unchecked_reference_age(
                    startup,
                    height,
                    statement.base.stablecoin.parent_height,
                    false,
                )?;
                let transition =
                    rp06_transition(startup, statement)?.with_launch_application_hint(height - 1);
                let mut hashes = Vec::with_capacity(2);
                let mut sizes = Vec::with_capacity(2);
                for slot in 0..2 {
                    if let Some(bytes) = leaf.ciphertext(slot) {
                        canonical_ciphertext(bytes)?;
                        hashes.push(ciphertext_hash_bytes(bytes));
                        sizes.push(bytes.len() as u32);
                    }
                }
                (
                    Self {
                        exact_leaf: leaf.raw(),
                        transition,
                        fee: statement.base.fee,
                    },
                    hashes,
                    sizes,
                )
            }
            launch_candidate::HTLC_ACTION_ID => {
                if action.binding != launch_candidate::HTLC_VERSION_BINDING.into()
                    || action.encoded_size()
                        > smallwood_htlc_transport::MAX_CANDIDATE_CARRIER_BYTES + 225
                {
                    return Err("HTLC outer binding/byte cap mismatch".into());
                }
                let carrier = smallwood_htlc_transport::decode_candidate_exact(&action.public_args)
                    .map_err(|e| e.to_string())?;
                if carrier.statement.network_id != startup.chain_id {
                    return Err("HTLC network mismatch".into());
                }
                require_unchecked_reference_age(
                    startup,
                    height,
                    carrier.statement.parent_height,
                    carrier.statement.action == smallwood_htlc::HtlcAction::Lock,
                )?;
                canonical_ciphertext(carrier.ciphertext)?;
                let transition = htlc_transition(startup, &carrier.statement)?
                    .with_launch_application_hint(height - 1);
                (
                    Self {
                        exact_leaf: carrier.exact_bytes,
                        transition,
                        fee: carrier.statement.fee,
                    },
                    vec![carrier.statement.ciphertext_commitment],
                    vec![carrier.ciphertext.len() as u32],
                )
            }
            _ => return Err("unknown launch transaction route".into()),
        };
        if view.fee != action.fee
            || hashes != action.ciphertext_hashes
            || sizes != action.ciphertext_sizes
        {
            return Err("launch exact public fee/ciphertext metadata mismatch".into());
        }
        Ok(view)
    }
    pub(crate) const fn exact_native_leaf(self) -> &'a [u8] {
        self.exact_leaf
    }
    pub(crate) const fn note_anchor(self) -> Poseidon2V8NoteRoot {
        self.transition.note_anchor()
    }
    pub(crate) const fn nullifiers(self) -> [Option<Poseidon2V8Nullifier>; 2] {
        self.transition.nullifiers()
    }
    pub(crate) const fn commitments(self) -> [Option<Poseidon2V8Commitment>; 2] {
        self.transition.commitments()
    }
    pub(crate) const fn fee(self) -> u64 {
        self.fee
    }
    pub(crate) fn ordering_transition_hint(self) -> Result<Poseidon2V8PublicTransition, String> {
        Ok(self.transition)
    }
}

pub(crate) fn pending_launch_action_from_inline_args(
    startup: LaunchStartup,
    height: u64,
    binding: KernelVersionBinding,
    action_id: u16,
    public_args: Vec<u8>,
) -> Result<PendingAction, String> {
    if matches!(
        action_id,
        super::asset_recovery_native::RECOVERY_SPEND_ACTION_ID
            | super::asset_recovery_native::RECOVERY_ADMIN_ACTION_ID
    ) {
        return super::asset_recovery_native::pending_recovery_action_from_inline_args(
            startup
                .recovery_authority()
                .ok_or("network has no recovery Development authority")?,
            height,
            binding,
            action_id,
            public_args,
        );
    }
    if matches!(
        action_id,
        transaction_circuit::asset_spend_v1_admission::ASSET_SPEND_ACTION_ID
            | transaction_circuit::asset_spend_v1_admission::ASSET_ADMIN_ACTION_ID
    ) {
        return super::asset_native::pending_asset_action_from_inline_args(
            startup
                .asset_authority()
                .ok_or("network has no asset Development authority")?,
            height,
            binding,
            action_id,
            public_args,
        );
    }
    let (fee, hashes, sizes) = match action_id {
        launch_candidate::PRIVATE_SPEND_ACTION_ID => {
            let carrier = private_spend_transport::decode_exact(
                startup.private_spend_context()?,
                &public_args,
            )
            .map_err(|e| e.to_string())?;
            (
                carrier.public.fee,
                carrier.public.ciphertext_commitments.to_vec(),
                vec![private_spend_transport::CIPHERTEXT_BYTES as u32; 2],
            )
        }
        launch_candidate::RP06_ACTION_ID => {
            let leaf = rp06_transport::decode_rp06_inline_args_exact(
                startup.rp06_context()?,
                &public_args,
            )
            .map_err(|e| e.to_string())?
            .native_leaf();
            let statement = parse_rp06_statement(leaf.preamble())?;
            let ciphertexts = (0..2)
                .filter_map(|i| leaf.ciphertext(i))
                .collect::<Vec<_>>();
            (
                statement.base.fee,
                ciphertexts
                    .iter()
                    .map(|bytes| ciphertext_hash_bytes(*bytes))
                    .collect(),
                ciphertexts.iter().map(|bytes| bytes.len() as u32).collect(),
            )
        }
        launch_candidate::HTLC_ACTION_ID => {
            let carrier = smallwood_htlc_transport::decode_candidate_exact(&public_args)
                .map_err(|e| e.to_string())?;
            (
                carrier.statement.fee,
                vec![carrier.statement.ciphertext_commitment],
                vec![carrier.ciphertext.len() as u32],
            )
        }
        _ => return Err("unknown launch transaction builder route".into()),
    };
    let pending = PendingAction {
        tx_hash: ActionId48::ZERO,
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
    NativeLaunchActionView::from_pending(startup, height, &pending)?;
    Ok(pending)
}
/// Syntax/ordering only: this never authenticates a checkpoint or creates a
/// checked receipt. Exact verification still requires storage-supplied ancestry.
fn require_unchecked_reference_age(
    startup: LaunchStartup,
    application_height: u64,
    reference_parent_height: u64,
    is_lock: bool,
) -> Result<(), String> {
    let application_parent = application_height
        .checked_sub(1)
        .ok_or("launch application height is zero")?;
    let reference_inclusion = reference_parent_height
        .checked_add(1)
        .ok_or("launch reference height overflow")?;
    if !startup.active_at(application_height)
        || !startup.active_at(reference_inclusion)
        || !protocol_versioning::launch_reference_policy::launch_reference_distance_allowed(
            reference_parent_height,
            application_parent,
            is_lock,
        )
    {
        return Err("launch reference age or finite source lifetime rejected".into());
    }
    Ok(())
}
// Framing only: every2608-byte opaque value is a candidate ciphertext.
// Recipient AEAD/payload validation belongs to the receiving wallet.
fn canonical_private_ciphertext(bytes: &[u8]) -> Result<(), String> {
    crypto::private_note_encryption::PrivateNoteCiphertextRef::from_bytes_exact(bytes)
        .map(|_| ())
        .map_err(|e| e.to_string())
}
fn canonical_ciphertext(bytes: &[u8]) -> Result<(), String> {
    let parsed = wallet::NoteCiphertext::from_da_bytes(bytes).map_err(|e| e.to_string())?;
    if parsed.to_da_bytes().map_err(|e| e.to_string())?.as_slice() != bytes {
        return Err("launch ciphertext canonical readback mismatch".into());
    }
    Ok(())
}
fn parse_rp06_statement(preamble: &[u8]) -> Result<Rp06PublicStatement, String> {
    validate_rp06_transcript_bytes(preamble).map_err(|e| e.to_string())?;
    let words = preamble[112..1136]
        .chunks_exact(8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("checked preamble")))
        .collect::<Vec<_>>();
    Rp06PublicStatement::try_from_public_words(&words).map_err(|e| format!("{e:?}"))
}
fn rp06_transition(
    startup: LaunchStartup,
    statement: Rp06PublicStatement,
) -> Result<Poseidon2V8PublicTransition, String> {
    if statement.chain_id != startup.chain_id
        || statement
            .base
            .stablecoin
            .before_root
            .map(|word| word.as_canonical_u64())
            != startup.stable_root.limbs()
        || statement
            .base
            .stablecoin
            .after_root
            .map(|word| word.as_canonical_u64())
            != startup.stable_root.limbs()
    {
        return Err("RP06 network/static stablecoin root mismatch".into());
    }
    let mut nullifiers = [None; 2];
    let mut commitments = [None; 2];
    for slot in 0..2 {
        if statement.base.input_flags[slot] {
            nullifiers[slot] = Some(
                Poseidon2V8Nullifier::new(statement.base.nullifiers[slot])
                    .map_err(|e| e.to_string())?,
            );
        }
        if statement.base.output_flags[slot] {
            commitments[slot] = Some(
                Poseidon2V8Commitment::new(statement.base.commitments[slot])
                    .map_err(|e| e.to_string())?,
            );
        }
    }
    Ok(
        Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
            statement.base.stablecoin.parent_height,
            startup.stable_root,
            startup.stable_root,
            Poseidon2V8StablecoinEffect::DisabledNoWrite,
            Poseidon2V8NoteRoot::new(statement.base.merkle_root).map_err(|e| e.to_string())?,
            nullifiers,
            commitments,
        ),
    )
}
/// Exact public-schema conversion; selectors, occupancy and policy never enter
/// the runtime interface. Ciphertext commitments and explicit public secret
/// release fields are passed into the same proof-verifier statement.
fn private_spend_statement(
    public: &private_spend_transport::PublicStatement,
) -> private_spend::PrivateSpendPublic {
    private_spend::PrivateSpendPublic {
        chain_id: public.chain_id,
        reference_parent_hash: public.reference_parent_hash,
        reference_parent_height: public.reference_parent_height,
        merkle_root: public.merkle_root,
        fee: public.fee,
        nullifiers: public.nullifiers,
        commitments: public.commitments,
        ciphertext_commitments: public.ciphertext_commitments,
        secret_release: public.secret_release,
        released_secret: public.released_secret,
    }
}

fn private_spend_transition(
    startup: LaunchStartup,
    statement: &private_spend::PrivateSpendPublic,
) -> Result<Poseidon2V8PublicTransition, String> {
    if statement.chain_id != startup.chain_id || statement.nullifiers[0] == statement.nullifiers[1]
    {
        return Err("private spend network or distinct-nullifier check failed".into());
    }
    // Both slots always have public effects: dummy nullifiers are spent and
    // zero-value output commitments are appended just like other notes.
    let nullifiers = [
        Some(Poseidon2V8Nullifier::new(statement.nullifiers[0]).map_err(|e| e.to_string())?),
        Some(Poseidon2V8Nullifier::new(statement.nullifiers[1]).map_err(|e| e.to_string())?),
    ];
    let commitments = [
        Some(Poseidon2V8Commitment::new(statement.commitments[0]).map_err(|e| e.to_string())?),
        Some(Poseidon2V8Commitment::new(statement.commitments[1]).map_err(|e| e.to_string())?),
    ];
    Ok(
        Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
            statement.reference_parent_height,
            startup.stable_root,
            startup.stable_root,
            Poseidon2V8StablecoinEffect::DisabledNoWrite,
            Poseidon2V8NoteRoot::new(statement.merkle_root).map_err(|e| e.to_string())?,
            nullifiers,
            commitments,
        ),
    )
}

fn htlc_transition(
    startup: LaunchStartup,
    statement: &smallwood_htlc::HtlcStatement,
) -> Result<Poseidon2V8PublicTransition, String> {
    Ok(
        Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
            statement.parent_height,
            startup.stable_root,
            startup.stable_root,
            Poseidon2V8StablecoinEffect::DisabledNoWrite,
            Poseidon2V8NoteRoot::new(statement.merkle_root).map_err(|e| e.to_string())?,
            [
                Some(Poseidon2V8Nullifier::new(statement.nullifier).map_err(|e| e.to_string())?),
                None,
            ],
            [
                Some(
                    Poseidon2V8Commitment::new(statement.output_commitment)
                        .map_err(|e| e.to_string())?,
                ),
                None,
            ],
        ),
    )
}

/// Reconstruct genesis solely from the authenticated immutable manifest.
/// Omission delegates byte-for-byte to the historical asset genesis helper.
pub(crate) fn asset_genesis_bytes(
    network: &NativeNetworkIdentity,
    genesis: [u8; 32],
) -> Result<Option<Vec<u8>>, String> {
    let Some(selected) = network.development_recovery() else {
        return super::asset_native::asset_genesis_bytes(network, genesis);
    };
    let startup = LaunchStartup::from_source(network, genesis)?
        .ok_or("recovery genesis has no source startup")?;
    startup
        .recovery_authority()
        .ok_or("recovery genesis has no typed authority")?;
    let rows = network
        .development_assets()
        .ok_or("recovery genesis requires asset descriptor")?
        .genesis_rows()
        .map_err(|e| e.to_string())?;
    let recovery = selected
        .initial_state(network.chain_id(), &rows)
        .map_err(|e| e.to_string())?;
    let initial = recovery.rows().copied().collect::<Vec<_>>();
    let state = super::asset_state::AssetRegistryStateV1::from_genesis_rows_with_recovery(
        network.chain_id(),
        &rows,
        &initial,
    )
    .map_err(|e| e.to_string())?;
    state.encode_exact().map(Some).map_err(|e| e.to_string())
}

#[derive(Clone, Debug)]
pub(crate) struct NativeLaunchVerifier {
    startup: LaunchStartup,
    references: Option<CanonicalLaunchReferences>,
}
impl Poseidon2V8ExactLeafVerifier for NativeLaunchVerifier {
    fn exact_leaf_proof_units(&self, exact: &[u8]) -> Result<usize,String> {
        use transaction_circuit::asset_recovery_wire_v1 as wire;
        if exact.starts_with(&wire::MAGIC) {
            if wire::decode_spend_ref(exact).is_ok() { return Ok(wire::PROOF_UNITS); }
            wire::decode_admin_ref(exact).map_err(|e|e.to_string())?;
        }
        Ok(1)
    }
    fn is_asset_native_leaf(&self, exact: &[u8]) -> bool {
        super::asset_native::is_asset_leaf(exact)
            || exact.starts_with(&transaction_circuit::asset_recovery_wire_v1::MAGIC)
    }
    fn verify_exact_asset_leaf(
        &mut self,
        block: Poseidon2V8BlockContext,
        _leaf_index: usize,
        exact: &[u8],
        current_asset: &[u8],
        parent_note_root: Poseidon2V8NoteRoot,
        next_position: u32,
        is_spent: &mut dyn FnMut([u64; 7]) -> Result<bool, String>,
    ) -> Result<(Poseidon2V8PublicTransition, Vec<u8>), String> {
        use super::asset_state::AssetRegistryStateV1;
        use transaction_circuit::asset_recovery_wire_v1 as wire;
        let references = self
            .references
            .as_ref()
            .ok_or("asset verification requires canonical references")?;
        if exact.starts_with(&wire::MAGIC) {
            let authority = self
                .startup
                .recovery
                .ok_or("network has no recovery Development authority")?;
            let mut current =
                AssetRegistryStateV1::decode_exact(current_asset).map_err(|e| e.to_string())?;
            let recovery = current
                .recovery()
                .ok_or("missing authenticated composite recovery state")?;
            if let Ok(_decoded) = wire::decode_spend_ref(exact) {
                let plan = authority.prepare_spend(
                    block,
                    exact,
                    &current,
                    recovery,
                    parent_note_root,
                    references,
                    is_spent,
                )?;
                let positions = [
                    next_position,
                    next_position
                        .checked_add(1)
                        .ok_or("recovery position overflow")?,
                    next_position
                        .checked_add(2)
                        .ok_or("recovery position overflow")?,
                ];
                let after = plan.asset_after_outputs(&current, positions)?;
                return Ok((
                    plan.transition(),
                    after.encode_exact().map_err(|e| e.to_string())?,
                ));
            }
            wire::decode_admin_ref(exact).map_err(|e| e.to_string())?;
            let plan = authority.prepare_admin(block, exact, &current, recovery)?;
            let root = current
                .registry()
                .root()
                .map(|word| word.as_canonical_u64());
            let checked =
                references.validate_recovery_admin_current(self.startup.chain_id, block, root)?;
            let transition = Poseidon2V8PublicTransition::new_with_asset_shielded_state(
                block.parent_height(),
                self.startup.stable_root,
                parent_note_root,
                [None; 2],
                [None; 3],
            )
            .with_checked_launch_reference(checked)?;
            *current
                .recovery_mut()
                .ok_or("missing authenticated recovery state")? = plan.projected_state().clone();
            return Ok((
                transition,
                current.encode_exact().map_err(|e| e.to_string())?,
            ));
        }
        // The legacy planner itself rejects opted-in spends and preserves the
        // composite recovery snapshot for permitted old administrator controls.
        self.startup
            .assets
            .ok_or("network has no asset Development authority")?
            .verify_leaf(block, exact, current_asset, parent_note_root, references)
    }
    fn advance_asset_state(
        &mut self,
        block: Poseidon2V8BlockContext,
        current_asset: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.startup
            .assets
            .ok_or("network has no asset Development authority")?
            .advance(block, current_asset)
    }
    fn native_leaf_profile(&self) -> Poseidon2V8NativeLeafProfile {
        Poseidon2V8NativeLeafProfile::LaunchMixed
    }
    fn launch_proof_lifetime_limit(&self) -> Option<u64> {
        self.startup.max_total_proofs
    }
    fn launch_has_ongoing_hgn_authority(&self) -> bool {
        self.startup.has_ongoing_hgn_authority()
    }
    fn launch_proof_action_limit(&self) -> Option<usize> {
        Some(self.startup.max_actions)
    }
    fn launch_reference_context(&self) -> Option<LaunchReferenceContext> {
        LaunchReferenceContext::from_startup(self.startup).ok()
    }
    fn set_launch_references(
        &mut self,
        references: CanonicalLaunchReferences,
    ) -> Result<(), String> {
        // A failed replacement invalidates the old set; it must not become a
        // fallback if a caller mishandles an error during a tip/reorg change.
        self.references = None;
        let expected = LaunchReferenceContext::from_startup(self.startup)?;
        if references.context() != expected {
            return Err(
                "launch reference context differs from full source startup identity".into(),
            );
        }
        self.references = Some(references);
        Ok(())
    }
    fn verify_exact_v8_leaf(
        &mut self,
        block: Poseidon2V8BlockContext,
        _leaf_index: usize,
        exact: &[u8],
    ) -> Result<Poseidon2V8PublicTransition, String> {
        if !self.startup.active_at(block.height()) {
            return Err("launch verifier outside source lifetime".into());
        }
        if block.parent_height() == 0 && block.parent_hash() != self.startup.genesis_hash {
            return Err("launch verifier canonical genesis mismatch".into());
        }
        let references = self
            .references
            .as_ref()
            .ok_or("launch exact verification requires canonical reference checkpoints")?;
        if exact.get(..8) == Some(private_spend_transport::MAGIC.as_slice()) {
            let carrier =
                private_spend_transport::decode_exact(self.startup.private_spend_context()?, exact)
                    .map_err(|e| e.to_string())?;
            self.startup.require_route_authority(
                block.height(),
                launch_candidate::PRIVATE_SPEND_ACTION_ID,
                ProofAuthorityClass::Transaction,
                carrier.proof.len(),
            )?;
            let statement = private_spend_statement(&carrier.public);
            let checked = references.validate_private_spend(&statement, block)?;
            for bytes in carrier.ciphertexts {
                canonical_private_ciphertext(bytes)?;
            }
            // Proof acceptance precedes construction of the checked effects.
            // The verifier consumes the unchanged complete SMZD proof.
            private_spend::verify_candidate(&statement, carrier.proof)
                .map_err(|e| e.to_string())?;
            attach_checked_reference(
                private_spend_transition(self.startup, &statement)?,
                checked,
                block,
            )
        } else if exact.get(..8) == Some(rp06_transport::RP06_NATIVE_LEAF_MAGIC.as_slice()) {
            let leaf =
                rp06_transport::decode_rp06_native_leaf_exact(self.startup.rp06_context()?, exact)
                    .map_err(|e| e.to_string())?;
            let statement = parse_rp06_statement(leaf.preamble())?;
            self.startup.require_route_authority(
                block.height(),
                launch_candidate::RP06_ACTION_ID,
                ProofAuthorityClass::Transaction,
                leaf.proof().len(),
            )?;
            // This authenticates only the public reference; no receipt leaves
            // the verifier until the unchanged proof bytes pass below.
            let checked = references.validate_rp06(&statement, block)?;
            for slot in 0..2 {
                if let Some(bytes) = leaf.ciphertext(slot) {
                    canonical_ciphertext(bytes)?;
                }
            }
            verify_rp06_candidate_bytes(
                &leaf.public_words(),
                leaf.relation_digest(),
                leaf.proof(),
                self.startup.chain_id,
            )
            .map_err(|e| e.to_string())?;
            attach_checked_reference(rp06_transition(self.startup, statement)?, checked, block)
        } else if exact.get(..8) == Some(smallwood_htlc_transport::CANDIDATE_MAGIC.as_slice()) {
            let carrier = smallwood_htlc_transport::decode_candidate_exact(exact)
                .map_err(|e| e.to_string())?;
            self.startup.require_route_authority(
                block.height(),
                launch_candidate::HTLC_ACTION_ID,
                ProofAuthorityClass::Transaction,
                carrier.proof.len(),
            )?;
            let checked = references.validate_htlc(&carrier.statement, block)?;
            canonical_ciphertext(carrier.ciphertext)?;
            smallwood_htlc::verify_candidate(&carrier.statement, carrier.proof)
                .map_err(|e| e.to_string())?;
            attach_checked_reference(
                htlc_transition(self.startup, &carrier.statement)?,
                checked,
                block,
            )
        } else {
            Err("launch verifier rejects unknown or historical native leaf".into())
        }
    }
}

/// Keep the selected application fork in the receipt as well as its height.
/// StateStore must check the same parent hash when consuming this transition.
fn attach_checked_reference(
    transition: Poseidon2V8PublicTransition,
    checked: CheckedLaunchReference,
    block: Poseidon2V8BlockContext,
) -> Result<Poseidon2V8PublicTransition, String> {
    if checked.application_parent_height() != block.parent_height()
        || checked.application_parent_hash() != block.parent_hash()
        || checked.application_height() != block.height()
    {
        return Err("checked launch reference is for a different application parent".into());
    }
    transition.with_checked_launch_reference(checked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::launch_reference::CanonicalLaunchCheckpoint;
    use transaction_circuit::smallwood_poseidon2_v8_rp06::rp06_transcript_bytes;
    use transaction_circuit::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8PublicStatement;

    #[cfg(feature = "development-candidate")]
    #[test]
    fn development_candidate_authority_enforces_action_specific_caps_and_finite_window() {
        use super::super::network_profile::{
            DevelopmentCandidateManifest, NativeNetworkManifest, NativeNetworkProfile,
        };
        let recipient = wallet::RootSecret::from_bytes([0x41; 32])
            .derive()
            .poseidon2_v8_address(0)
            .unwrap()
            .shielded_address()
            .encode()
            .unwrap();
        let note_root = Poseidon2V8NoteTreeState::new_empty()
            .unwrap()
            .root()
            .limbs();
        let network = NativeNetworkIdentity::from_manifest(NativeNetworkManifest {
            schema: "hegemon.native.network-manifest.v1".into(),
            profile: NativeNetworkProfile::Development,
            genesis_timestamp_ms: super::super::NATIVE_GENESIS_TIMESTAMP_MS,
            pow_bits: super::super::NATIVE_DEV_POW_BITS,
            rules_hash: super::super::util::hex32(
                &super::super::HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
            ),
            launch_reference_rules_hash: super::super::util::hex32(
                &super::super::network_profile::compiled_launch_reference_rules_hash(),
            ),
            funding_address: Some(recipient),
            funding_subsidy_numerator: 1,
            funding_subsidy_denominator: 5,
            development_candidate: Some(DevelopmentCandidateManifest {
                assets: None,
                recovery: None,
                private_spend_only: false,
                private_spend_source: None,
                activation_height: 1,
                deactivation_height_exclusive: 100,
                max_proof_actions_per_block: 8,
                max_total_proofs: 1_000,
                max_proof_bytes: smallwood_htlc_transport::MAX_CANDIDATE_CARRIER_BYTES,
                stablecoin_genesis_root: [0; 7],
                note_genesis_root: note_root,
            }),
        })
        .unwrap();
        let startup = LaunchStartup::from_source(&network, [0x42; 32])
            .unwrap()
            .unwrap();

        assert!(startup
            .require_route_authority(
                2,
                launch_candidate::RP06_ACTION_ID,
                ProofAuthorityClass::Transaction,
                rp06_transport::RP06_CANDIDATE_MAX_PROOF_BYTES,
            )
            .is_ok());
        assert!(startup
            .require_route_authority(
                2,
                launch_candidate::RP06_ACTION_ID,
                ProofAuthorityClass::Transaction,
                rp06_transport::RP06_CANDIDATE_MAX_PROOF_BYTES + 1,
            )
            .is_err());
        assert!(startup
            .require_route_authority(
                2,
                launch_candidate::HTLC_ACTION_ID,
                ProofAuthorityClass::Transaction,
                smallwood_htlc_transport::MAX_CANDIDATE_CARRIER_BYTES,
            )
            .is_ok());
        assert!(startup
            .require_route_authority(
                2,
                launch_candidate::HTLC_ACTION_ID,
                ProofAuthorityClass::Transaction,
                smallwood_htlc_transport::MAX_CANDIDATE_CARRIER_BYTES + 1,
            )
            .is_err());
        assert!(startup
            .require_route_authority(
                100,
                launch_candidate::HTLC_ACTION_ID,
                ProofAuthorityClass::Transaction,
                1,
            )
            .is_err());
    }

    fn fixture() -> (LaunchStartup, PendingAction) {
        let network = NativeNetworkIdentity::development();
        let startup = LaunchStartup::qualification_for_test(
            &network,
            [2; 32],
            Poseidon2V8Root::new([0; 7]).unwrap(),
            1,
            10,
            2,
        )
        .unwrap();
        let mut base = SmallwoodPoseidon2V8PublicStatement::default();
        base.merkle_root = startup.note_genesis_root().limbs();
        let public = Rp06PublicStatement {
            base,
            chain_id: startup.chain_id(),
        };
        let preamble: [u8; rp06_transport::RP06_PREAMBLE_BYTES] =
            rp06_transcript_bytes(&public).unwrap().try_into().unwrap();
        // Shape-only bytes deliberately cannot establish cryptographic validity.
        let leaf = rp06_transport::encode_rp06_candidate_native_leaf(
            startup.rp06_context().unwrap(),
            &preamble,
            [None, None],
            b"SMZB\0",
        )
        .unwrap();
        let envelope =
            rp06_transport::encode_rp06_candidate_envelope(startup.rp06_context().unwrap(), &leaf)
                .unwrap();
        let args = rp06_transport::encode_rp06_candidate_inline_args(
            startup.rp06_context().unwrap(),
            &envelope,
        )
        .unwrap();
        let pending = pending_launch_action_from_inline_args(
            startup,
            1,
            launch_candidate::RP06_VERSION_BINDING.into(),
            launch_candidate::RP06_ACTION_ID,
            args,
        )
        .unwrap();
        (startup, pending)
    }
    fn reference_hash(startup: LaunchStartup, height: u64) -> [u8; 32] {
        if height == 0 {
            return startup.activation_genesis_hash();
        }
        let mut hash = [3; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        hash
    }
    fn reference_fixture(startup: LaunchStartup, parent_height: u64) -> CanonicalLaunchReferences {
        let checkpoints = (parent_height
            .saturating_sub(12)
            .max(startup.activation_height() - 1)..=parent_height)
            .map(|height| {
                CanonicalLaunchCheckpoint::new(
                    reference_hash(startup, height),
                    if height == 0 {
                        [0; 32]
                    } else {
                        reference_hash(startup, height - 1)
                    },
                    height,
                    startup.note_genesis_root(),
                    startup.stablecoin_genesis_root(),
                )
                .unwrap()
            })
            .collect();
        CanonicalLaunchReferences::from_validated_chain(
            LaunchReferenceContext::from_startup(startup).unwrap(),
            reference_hash(startup, parent_height),
            parent_height,
            checkpoints,
        )
        .unwrap()
    }

    fn private_statement(
        startup: LaunchStartup,
        reference: u64,
    ) -> private_spend::PrivateSpendPublic {
        private_spend::PrivateSpendPublic {
            chain_id: startup.chain_id(),
            reference_parent_hash: reference_hash(startup, reference),
            reference_parent_height: reference,
            merkle_root: startup.note_genesis_root().limbs(),
            fee: 0,
            nullifiers: [[7; 7], [8; 7]],
            commitments: [[9; 7], [10; 7]],
            ciphertext_commitments: [[11; 48], [12; 48]],
            secret_release: 0,
            released_secret: [0; 32],
        }
    }

    #[test]
    fn private_spend_release_statement_is_forwarded_to_proof_verification() {
        let public = private_spend_transport::PublicStatement {
            relation_digest: [1; 48],
            chain_id: [2; 32],
            reference_parent_hash: [3; 32],
            reference_parent_height: 4,
            merkle_root: [5; 7],
            fee: 6,
            nullifiers: [[7; 7], [8; 7]],
            commitments: [[9; 7], [10; 7]],
            ciphertext_commitments: [[11; 48], [12; 48]],
            secret_release: 1,
            released_secret: [0xff; 32],
        };
        let statement = private_spend_statement(&public);
        assert_eq!(statement.secret_release, 1);
        assert_eq!(statement.released_secret, [0xff; 32]);
        assert_eq!(statement.chain_id, public.chain_id);
        assert_eq!(
            statement.ciphertext_commitments,
            public.ciphertext_commitments
        );
        for i in 0..32 {
            let mut changed = public.clone();
            changed.released_secret[i] ^= 1;
            let changed_statement = private_spend_statement(&changed);
            assert_ne!(changed_statement.released_secret, statement.released_secret);
            assert_eq!(changed_statement.released_secret[i], 0xfe);
        }
        let mut no_release = public;
        no_release.secret_release = 0;
        no_release.released_secret = [0; 32];
        let no_release = private_spend_statement(&no_release);
        assert_eq!(no_release.secret_release, 0);
        assert_eq!(no_release.released_secret, [0; 32]);
    }

    #[test]
    fn private_spend_common_reference_window_and_both_effect_slots() {
        let (mut startup, _) = fixture();
        startup.end = Some(100);
        let statement = private_statement(startup, 8);
        for inclusion in 9..=21 {
            require_unchecked_reference_age(startup, inclusion, 8, false).unwrap();
            let block = Poseidon2V8BlockContext::new(
                inclusion - 1,
                reference_hash(startup, inclusion - 1),
                inclusion,
                reference_hash(startup, inclusion),
            )
            .unwrap();
            let references = reference_fixture(startup, inclusion - 1);
            let checked = references
                .validate_private_spend(&statement, block)
                .unwrap();
            assert_eq!(checked.reference_height(), 8);
            assert_eq!(checked.reference_hash(), statement.reference_parent_hash);
        }
        for inclusion in [8, 22] {
            assert!(require_unchecked_reference_age(startup, inclusion, 8, false).is_err());
            let block = Poseidon2V8BlockContext::new(
                inclusion - 1,
                reference_hash(startup, inclusion - 1),
                inclusion,
                reference_hash(startup, inclusion),
            )
            .unwrap();
            assert!(reference_fixture(startup, inclusion - 1)
                .validate_private_spend(&statement, block)
                .is_err());
        }
        let transition = private_spend_transition(startup, &statement).unwrap();
        assert_eq!(
            transition
                .nullifiers()
                .iter()
                .filter(|x| x.is_some())
                .count(),
            2
        );
        assert_eq!(
            transition
                .commitments()
                .iter()
                .filter(|x| x.is_some())
                .count(),
            2
        );
        let mut duplicate = statement.clone();
        duplicate.nullifiers[1] = duplicate.nullifiers[0];
        assert!(private_spend_transition(startup, &duplicate).is_err());
        let block = Poseidon2V8BlockContext::new(
            20,
            reference_hash(startup, 20),
            21,
            reference_hash(startup, 21),
        )
        .unwrap();
        let references = reference_fixture(startup, 20);
        let mut wrong = statement.clone();
        wrong.reference_parent_hash[0] ^= 1;
        assert!(references.validate_private_spend(&wrong, block).is_err());
        wrong = statement.clone();
        wrong.merkle_root[0] += 1;
        assert!(references.validate_private_spend(&wrong, block).is_err());
        wrong = statement;
        wrong.chain_id[0] ^= 1;
        assert!(references.validate_private_spend(&wrong, block).is_err());
    }

    #[test]
    fn private_only_profile_rejects_old_shape_hints_before_proof_processing() {
        let (mut startup, old_action) = fixture();
        assert!(NativeLaunchActionView::from_pending(startup, 1, &old_action).is_ok());
        startup.private_spend_only = true;
        assert!(
            NativeLaunchActionView::from_pending(startup, 1, &old_action)
                .unwrap_err()
                .contains("private-spend-only")
        );
        for action_id in [
            11,
            launch_candidate::HTLC_ACTION_ID,
            launch_candidate::RP06_ACTION_ID,
        ] {
            assert!(startup.require_profile_action(action_id).is_err());
        }
        startup.qualification_only = false;
        assert!(startup
            .require_route_authority(
                1,
                launch_candidate::PRIVATE_SPEND_ACTION_ID,
                ProofAuthorityClass::Transaction,
                64
            )
            .is_err());
    }

    #[test]
    fn ongoing_hgn_startup_preserves_identity_and_rejects_partial_limits() {
        let (mut startup, _) = fixture();
        startup.private_spend_only = true;
        startup.end = None;
        startup.max_total_proofs = None;
        startup.validate().unwrap();
        assert!(startup.connector().launch_has_ongoing_hgn_authority());
        assert_eq!(startup.connector().launch_proof_lifetime_limit(), None);
        for height in [100, 100_001, 621_730_875, (1_u64 << 48) - 1] {
            assert!(startup.active_at(height));
            assert!(startup.require_route_authority(height,
                launch_candidate::PRIVATE_SPEND_ACTION_ID,
                ProofAuthorityClass::Transaction, 1).is_ok());
        }
        let mut bad = startup;
        bad.development_candidate = true;
        assert!(bad.validate().is_err());
        bad = startup;
        bad.private_spend_only = false;
        assert!(bad.validate().is_err());
        bad = startup;
        bad.end = Some(100);
        assert!(bad.validate().is_err());
        bad = startup;
        bad.max_total_proofs = Some(1_000);
        assert!(bad.validate().is_err());
        bad = startup;
        bad.genesis_hash = [0; 32];
        assert!(bad.validate().is_err());
        // Qualification permits route checks only, never invalid proof bytes.
        let block = Poseidon2V8BlockContext::new(100_000, [7; 32], 100_001, [8; 32]).unwrap();
        assert!(startup.connector().verify_exact_v8_leaf(block, 0, b"invalid proof").is_err());
    }

    #[test]
    fn hgn_only_shared_verifier_rejects_asset_and_recovery_without_authority() {
        use transaction_circuit::{
            asset_recovery_wire_v1 as recovery_wire, asset_spend_v1_wire as asset_wire,
        };
        let (mut startup, _) = fixture();
        assert!(startup.assets.is_none());
        assert!(startup.recovery.is_none());
        // The qualification fixture may bypass native proof registry lookup;
        // neither native spend profile may lend that authority to IDs 16-19.
        for private_only in [false, true] {
            startup.private_spend_only = private_only;
            for height in [
                0,
                startup.activation_height(),
                startup.deactivation_height_exclusive().unwrap() - 1,
                startup.deactivation_height_exclusive().unwrap(),
                u64::MAX,
            ] {
                for (action_id, binding) in [
                    (
                        transaction_circuit::asset_spend_v1_admission::ASSET_SPEND_ACTION_ID,
                        super::super::asset_native::native_binding(),
                    ),
                    (
                        transaction_circuit::asset_spend_v1_admission::ASSET_ADMIN_ACTION_ID,
                        super::super::asset_native::native_binding(),
                    ),
                    (
                        super::super::asset_recovery_native::RECOVERY_SPEND_ACTION_ID,
                        super::super::asset_recovery_native::native_binding(),
                    ),
                    (
                        super::super::asset_recovery_native::RECOVERY_ADMIN_ACTION_ID,
                        super::super::asset_recovery_native::native_binding(),
                    ),
                ] {
                    assert!(
                        !startup.authorizes_route(height, binding, FAMILY_SHIELDED_POOL, action_id),
                        "action {action_id} at height {height}, private-only {private_only}"
                    );
                }
            }
        }

        // Import and replay share this exact-leaf verifier. Recognizable but
        // truncated carriers and invalid state must reach authority rejection,
        // before decoding either one or evaluating nullifiers/proofs.
        let mut verifier = startup.connector();
        verifier
            .set_launch_references(reference_fixture(startup, 0))
            .unwrap();
        let block =
            Poseidon2V8BlockContext::new(0, startup.activation_genesis_hash(), 1, [3; 32]).unwrap();
        for (exact, expected) in [
            (
                &asset_wire::NATIVE_ASSET_SPEND_ACTION_MAGIC_V1[..],
                "network has no asset Development authority",
            ),
            (
                &asset_wire::NATIVE_ASSET_ADMIN_ACTION_MAGIC_V1[..],
                "network has no asset Development authority",
            ),
            (
                &recovery_wire::MAGIC[..],
                "network has no recovery Development authority",
            ),
        ] {
            assert!(verifier.is_asset_native_leaf(exact));
            let mut is_spent = |_| -> Result<bool, String> {
                panic!("an unauthorized asset/recovery leaf must not inspect nullifiers")
            };
            let result = verifier.verify_exact_asset_leaf(
                block,
                0,
                exact,
                b"deliberately invalid asset state",
                startup.note_genesis_root(),
                u32::MAX,
                &mut is_spent,
            );
            assert_eq!(result.err().as_deref(), Some(expected));
        }
        assert_eq!(
            verifier
                .advance_asset_state(block, b"deliberately invalid asset state")
                .err()
                .as_deref(),
            Some("network has no asset Development authority"),
        );
    }

    #[test]
    fn private_spend_route_does_not_grant_production_authority() {
        let (mut startup, _) = fixture();
        assert!(startup.authorizes_route(
            1,
            launch_candidate::PRIVATE_SPEND_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            launch_candidate::PRIVATE_SPEND_ACTION_ID,
        ));
        assert!(!startup.authorizes_route(
            1,
            launch_candidate::RP06_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            launch_candidate::PRIVATE_SPEND_ACTION_ID,
        ));
        startup.qualification_only = false;
        assert!(startup
            .require_route_authority(
                1,
                launch_candidate::PRIVATE_SPEND_ACTION_ID,
                ProofAuthorityClass::Transaction,
                64,
            )
            .is_err());
    }

    #[test]
    fn production_startup_selector_fails_closed_for_empty_exact_registry() {
        // Exercise the production selector directly, independent of the
        // optional Development manifest/feature path.
        let identity = ([0x31; 32], [0x32; 32], [0x33; 64]);
        assert!(
            LaunchStartup::from_source_identity(identity.0, identity.1, identity.2)
                .unwrap()
                .is_none()
        );
        for (chain_id, genesis_hash, manifest_digest) in [
            ([0; 32], identity.1, identity.2),
            (identity.0, [0; 32], identity.2),
            (identity.0, identity.1, [0; 64]),
        ] {
            assert!(
                LaunchStartup::from_source_identity(chain_id, genesis_hash, manifest_digest)
                    .is_err()
            );
        }
    }

    #[test]
    fn common_reward_uses_fresh_source_identity_and_existing_wire_binding() {
        let (mut startup, _) = fixture();
        startup.private_spend_only = true;
        startup.qualification_only = false;
        startup.development_candidate = true;
        assert!(startup.authorizes_route(
            1,
            launch_candidate::RP06_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            launch_candidate::ALLOCATED_REWARD_ACTION_ID,
        ));
        assert!(!startup.authorizes_route(
            1,
            launch_candidate::PRIVATE_SPEND_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            launch_candidate::ALLOCATED_REWARD_ACTION_ID,
        ));
        let request = LaunchProofRequest {
            kind: LaunchProofKind::PrivateSpend,
            chain_id: startup.chain_id,
            genesis_hash: startup.genesis_hash,
            manifest_digest: startup.manifest_digest,
            relation_digest: startup.private_spend_relation,
            height: 1,
            binding: launch_candidate::PRIVATE_SPEND_VERSION_BINDING,
            family_id: FAMILY_SHIELDED_POOL,
            action_id: launch_candidate::ALLOCATED_REWARD_ACTION_ID,
            proof_class: ProofAuthorityClass::MintSource,
            backend_id: TxProofBackend::SmallwoodCandidate.wire_id(),
            profile_id: launch_candidate::PRIVATE_SPEND_PROFILE_ID,
            domain_set: launch_candidate::PRIVATE_SPEND_DOMAIN_SET,
            proof_bytes: 0,
        };
        assert!(startup
            .require_development_candidate_request(request)
            .is_ok());
        let mut historical = request;
        historical.kind = LaunchProofKind::Rp06;
        historical.binding = launch_candidate::RP06_VERSION_BINDING;
        historical.relation_digest = startup.rp06_relation;
        historical.profile_id = launch_candidate::RP06_PROFILE_ID;
        historical.domain_set = launch_candidate::RP06_DOMAIN_SET;
        assert!(startup
            .require_development_candidate_request(historical)
            .is_err());
        startup.private_spend_only = false;
        assert!(startup
            .require_development_candidate_request(historical)
            .is_ok());
        assert!(startup
            .require_development_candidate_request(request)
            .is_err());
    }

    #[test]
    fn common_startup_profile_rejects_split_routes_before_authority_lookup() {
        let (mut startup, _) = fixture();
        startup.private_spend_only = true;
        // Qualification may stand in for registry lookup in this fixture, but
        // must never bypass the immutable common-profile route restriction.
        for action_id in [
            launch_candidate::RP06_ACTION_ID,
            launch_candidate::HTLC_ACTION_ID,
        ] {
            assert!(startup
                .require_route_authority(1, action_id, ProofAuthorityClass::Transaction, 64)
                .unwrap_err()
                .contains("private-spend-only"));
        }
        startup.qualification_only = false;
        assert!(startup
            .require_route_authority(
                1,
                launch_candidate::PRIVATE_SPEND_ACTION_ID,
                ProofAuthorityClass::Transaction,
                64,
            )
            .unwrap_err()
            .contains("no exact action authority"));
        assert!(startup
            .require_route_authority(
                1,
                launch_candidate::ALLOCATED_REWARD_ACTION_ID,
                ProofAuthorityClass::MintSource,
                0,
            )
            .unwrap_err()
            .contains("no exact action authority"));
    }

    #[test]
    fn launch_startup_and_fixed_routes_never_gain_registry_authority() {
        let network = NativeNetworkIdentity::development();
        assert!(LaunchStartup::from_source(&network, [2; 32])
            .unwrap()
            .is_none());
        assert!(
            LaunchStartup::from_source(&NativeNetworkIdentity::legacy(), [2; 32])
                .unwrap()
                .is_none()
        );
        assert!(LaunchStartup::from_source(&network, [0; 32]).is_err());
        let (mut startup, _) = fixture();
        assert!(startup.authorizes_route(
            1,
            launch_candidate::RP06_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            14
        ));
        assert!(!startup.authorizes_route(
            0,
            launch_candidate::RP06_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            14
        ));
        assert!(!startup.authorizes_route(
            10,
            launch_candidate::RP06_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            14
        ));
        assert!(!startup.authorizes_route(
            1,
            launch_candidate::HTLC_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            14
        ));
        assert!(!startup.authorizes_route(
            1,
            launch_candidate::RP06_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            10
        ));
        startup.qualification_only = false;
        assert!(!startup.authorizes_route(
            1,
            launch_candidate::RP06_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            14
        ));
        assert!(!startup.authorizes_route(
            1,
            launch_candidate::RP06_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            12
        ));
    }
    #[test]
    fn launch_shape_borrows_original_bytes_and_rejects_outer_mismatches() {
        let (startup, action) = fixture();
        let view = NativeLaunchActionView::from_pending(startup, 1, &action).unwrap();
        let leaf = rp06_transport::decode_rp06_inline_args_exact(
            startup.rp06_context().unwrap(),
            &action.public_args,
        )
        .unwrap()
        .native_leaf();
        assert!(core::ptr::eq(
            view.exact_native_leaf().as_ptr(),
            leaf.raw().as_ptr()
        ));
        assert_eq!(
            view.ordering_transition_hint().unwrap().before_root(),
            startup.stablecoin_genesis_root()
        );
        let mut mutated = action.clone();
        mutated.fee = 1;
        assert!(NativeLaunchActionView::from_pending(startup, 1, &mutated).is_err());
        let mut mutated = action.clone();
        mutated.nullifiers.push([1; 48]);
        assert!(NativeLaunchActionView::from_pending(startup, 1, &mutated).is_err());
        let later = NativeLaunchActionView::from_pending(startup, 2, &action).unwrap();
        assert_eq!(later.ordering_transition_hint().unwrap().parent_height(), 0);
        assert_eq!(
            later
                .ordering_transition_hint()
                .unwrap()
                .application_parent_height(),
            1
        );
        let mut wrong = startup;
        wrong.chain_id[31] ^= 1;
        assert!(NativeLaunchActionView::from_pending(wrong, 1, &action).is_err());
    }
    #[test]
    fn launch_view_keeps_original_reference_and_only_hints_application_height() {
        let (mut startup, action) = fixture();
        startup.end = Some(100);
        let original = action.public_args.clone();
        for application in [1, 13] {
            let view = NativeLaunchActionView::from_pending(startup, application, &action).unwrap();
            let transition = view.ordering_transition_hint().unwrap();
            assert_eq!(transition.parent_height(), 0);
            assert_eq!(transition.application_parent_height(), application - 1);
            assert_eq!(action.public_args, original);
        }
        assert!(NativeLaunchActionView::from_pending(startup, 14, &action).is_err());
        assert!(require_unchecked_reference_age(startup, 10, 10, false).is_err());
        for action in [
            smallwood_htlc::HtlcAction::Lock,
            smallwood_htlc::HtlcAction::Claim,
            smallwood_htlc::HtlcAction::Refund,
        ] {
            let is_lock = action == smallwood_htlc::HtlcAction::Lock;
            assert!(require_unchecked_reference_age(startup, 21, 20, is_lock).is_ok());
            assert_eq!(
                require_unchecked_reference_age(startup, 21, 8, is_lock).is_ok(),
                !is_lock
            );
            assert!(require_unchecked_reference_age(startup, 21, 7, is_lock).is_err());
        }
    }
    #[test]
    fn launch_reference_setter_binds_full_context_and_clears_failed_replacements() {
        let (startup, _) = fixture();
        let mut verifier = startup.connector();
        assert_eq!(
            verifier.launch_reference_context(),
            Some(LaunchReferenceContext::from_startup(startup).unwrap())
        );
        verifier
            .set_launch_references(reference_fixture(startup, 0))
            .unwrap();
        assert!(verifier.references.is_some());
        for field in 0..6 {
            let mut wrong = startup;
            match field {
                0 => wrong.chain_id[31] ^= 1,
                1 => wrong.genesis_hash[31] ^= 1,
                2 => wrong.manifest_digest[63] ^= 1,
                3 => wrong.end = wrong.end.map(|end| end + 1),
                4 => wrong.stable_root = Poseidon2V8Root::new([1; 7]).unwrap(),
                5 => wrong.activation += 1,
                _ => unreachable!(),
            }
            assert!(verifier
                .set_launch_references(reference_fixture(wrong, wrong.activation_height() - 1))
                .is_err());
            assert!(verifier.references.is_none());
            verifier
                .set_launch_references(reference_fixture(startup, 0))
                .unwrap();
        }
    }

    #[test]
    fn checked_reference_cannot_move_to_another_application_fork() {
        let (startup, action) = fixture();
        let view = NativeLaunchActionView::from_pending(startup, 1, &action).unwrap();
        let leaf = rp06_transport::decode_rp06_inline_args_exact(
            startup.rp06_context().unwrap(),
            &action.public_args,
        )
        .unwrap()
        .native_leaf();
        let statement = parse_rp06_statement(leaf.preamble()).unwrap();
        let block =
            Poseidon2V8BlockContext::new(0, startup.activation_genesis_hash(), 1, [3; 32]).unwrap();
        // The host receipt proves checkpoint matching only, not fake proof validity.
        let checked = reference_fixture(startup, 0)
            .validate_rp06(&statement, block)
            .unwrap();
        let wrong_fork = Poseidon2V8BlockContext::new(0, [9; 32], 1, [3; 32]).unwrap();
        assert!(attach_checked_reference(
            rp06_transition(startup, statement).unwrap(),
            checked,
            wrong_fork
        )
        .is_err());
        let mut verifier = startup.connector();
        verifier
            .set_launch_references(reference_fixture(startup, 0))
            .unwrap();
        let stale = Poseidon2V8BlockContext::new(
            1,
            reference_hash(startup, 1),
            2,
            reference_hash(startup, 2),
        )
        .unwrap();
        let error = verifier
            .verify_exact_v8_leaf(stale, 0, view.exact_native_leaf())
            .unwrap_err();
        assert!(error.contains("stale for the selected application parent"));
    }

    #[test]
    fn launch_exact_dispatch_cannot_promote_shape_bytes_to_a_proof() {
        let (startup, action) = fixture();
        let view = NativeLaunchActionView::from_pending(startup, 1, &action).unwrap();
        let block = Poseidon2V8BlockContext::new(0, [2; 32], 1, [3; 32]).unwrap();
        let mut verifier = startup.connector();
        let missing = verifier
            .verify_exact_v8_leaf(block, 0, view.exact_native_leaf())
            .unwrap_err();
        assert!(missing.contains("canonical reference checkpoints"));
        verifier
            .set_launch_references(reference_fixture(startup, 0))
            .unwrap();
        // Correct canonical shape cannot make these fake bytes a proof.
        assert!(verifier
            .verify_exact_v8_leaf(block, 0, view.exact_native_leaf())
            .is_err());
        assert!(startup
            .connector()
            .verify_exact_v8_leaf(block, 0, b"HGV8historical")
            .is_err());
        assert_eq!(startup.connector().launch_proof_lifetime_limit(), Some(2));
        assert_eq!(startup.connector().launch_proof_action_limit(), Some(512));
    }
    #[test]
    #[ignore = "offline retained carrier qualification; set HEGEMON_PRIVATE_SPEND_CARRIER_DIR explicitly"]
    fn private_spend_retained_six_exact_carriers() {
        use sha2::Digest;
        use std::{env, fs};

        // Canonical-reference UNIT evidence only: constructed checkpoints bind
        // each retained public tuple but are not authenticated chain history.
        let root = env::var_os("HEGEMON_PRIVATE_SPEND_CARRIER_DIR")
            .map(std::path::PathBuf::from)
            .expect("HEGEMON_PRIVATE_SPEND_CARRIER_DIR must point at the retained fixture");
        let compiled_relation = private_spend::relation_digest();
        let compiled_relation_hex = hex::encode(compiled_relation);
        let network = NativeNetworkIdentity::development();
        let mut startup = LaunchStartup::qualification_for_test(
            &network,
            [0x42; 32],
            Poseidon2V8Root::new([0; 7]).unwrap(),
            1,
            1_000_000,
            64,
        )
        .expect("test-only qualification startup");
        assert!(startup.qualification_only);

        let branches = ["ordinary", "approval", "final", "lock", "claim", "refund"];
        let mut qualification_source = None;
        let mut carrier_hashes = Vec::new();
        for branch in branches {
            let branch_dir = root.join(format!("proof-{branch}"));
            let config: serde_json::Value = serde_json::from_slice(
                &fs::read(branch_dir.join("source-config.json"))
                    .expect("read branch source configuration"),
            )
            .expect("parse branch source configuration");
            let result: serde_json::Value = serde_json::from_slice(
                &fs::read(branch_dir.join("result.json")).expect("read branch proof result"),
            )
            .expect("parse branch proof result");
            assert_eq!(
                config["relation_digest_sha512"].as_str(),
                Some(compiled_relation_hex.as_str())
            );
            let source_digest = config["qualification_source_sha512"]
                .as_str()
                .expect("branch full-source qualification digest");
            if let Some(first) = qualification_source.as_deref() {
                assert_eq!(source_digest, first, "{branch} full-source digest");
            } else {
                qualification_source = Some(source_digest.to_owned());
            }
            assert_eq!(
                result["status"], "candidate_proof_verified",
                "{branch} status"
            );
            assert_eq!(result["error"], serde_json::Value::Null, "{branch} error");
            assert_eq!(
                result["production_authorized"], false,
                "{branch} is not release authority"
            );
            assert_eq!(result["unchanged_inner_proof_checked"], true);
            assert_eq!(result["complete_carrier_exact_decode_checked"], true);

            let carrier_path = branch_dir.join("carrier.hgps");
            let exact = fs::read(&carrier_path).expect("read retained carrier");
            assert_eq!(
                exact.len() as u64,
                result["carrier_bytes"].as_u64().unwrap()
            );
            let original_sha512 = sha2::Sha512::digest(&exact).to_vec();
            let preamble_chain: [u8; 32] = exact[72..104].try_into().unwrap();
            let expected = private_spend_transport::ExpectedContext::new(
                preamble_chain,
                compiled_relation[..48].try_into().unwrap(),
            )
            .unwrap();
            let decoded = private_spend_transport::decode_exact(expected, &exact)
                .unwrap_or_else(|e| panic!("{branch} exact carrier framing: {e}"));
            assert_eq!(
                &decoded.public.relation_digest[..],
                &compiled_relation[..48]
            );
            assert_eq!(
                decoded.proof.len() as u64,
                result["proof_bytes"].as_u64().unwrap()
            );
            assert_eq!(
                result["carrier_bytes"].as_u64().unwrap(),
                result["proof_bytes"].as_u64().unwrap()
                    + (private_spend_transport::PREAMBLE_BYTES
                        + 2 * private_spend_transport::CIPHERTEXT_BYTES)
                        as u64
            );
            assert_eq!(
                decoded.proof.get(..4),
                Some(private_spend_transport::INNER_PROOF_MAGIC.as_slice())
            );

            // Adopt this branch's actual tuple. The preamble supplies its chain;
            // its root and reference can differ by branch (including refund).
            startup.chain_id = decoded.public.chain_id;
            startup.note_root = Poseidon2V8NoteRoot::new(decoded.public.merkle_root).unwrap();
            startup.activation = decoded
                .public
                .reference_parent_height
                .saturating_sub(12)
                .max(1);
            startup.end = Some(decoded.public.reference_parent_height + 3);
            startup.qualification_only = true;
            let public = decoded.public.clone();
            let parent_height = public.reference_parent_height;
            let parent_hash = public.reference_parent_hash;
            let reference_hash = |height: u64| {
                if height == parent_height {
                    parent_hash
                } else {
                    let mut hash = [0x53; 32];
                    hash[..8].copy_from_slice(&height.to_le_bytes());
                    hash
                }
            };
            let checkpoints = (parent_height.saturating_sub(12).max(startup.activation - 1)
                ..=parent_height)
                .map(|height| {
                    CanonicalLaunchCheckpoint::new(
                        reference_hash(height),
                        if height == 0 {
                            [0; 32]
                        } else {
                            reference_hash(height - 1)
                        },
                        height,
                        startup.note_root,
                        startup.stablecoin_genesis_root(),
                    )
                    .unwrap()
                })
                .collect();
            let references = CanonicalLaunchReferences::from_validated_chain(
                LaunchReferenceContext::from_startup(startup).unwrap(),
                parent_hash,
                parent_height,
                checkpoints,
            )
            .unwrap();
            let block = Poseidon2V8BlockContext::new(
                parent_height,
                parent_hash,
                parent_height + 1,
                reference_hash(parent_height + 1),
            )
            .unwrap();
            let mut verifier = startup.connector();
            verifier.set_launch_references(references.clone()).unwrap();
            // This invokes the exact source verifier; the SMZD magic alone is
            // never treated as proof validity.
            let transition = verifier
                .verify_exact_v8_leaf(block, 0, &exact)
                .unwrap_or_else(|e| panic!("{branch} actual native exact verifier: {e}"));
            let expected_nullifiers = public
                .nullifiers
                .map(|n| Some(Poseidon2V8Nullifier::new(n).unwrap()));
            let expected_commitments = public
                .commitments
                .map(|c| Some(Poseidon2V8Commitment::new(c).unwrap()));
            assert_eq!(
                transition.nullifiers(),
                expected_nullifiers,
                "{branch} nullifiers"
            );
            assert_eq!(
                transition.commitments(),
                expected_commitments,
                "{branch} commitments"
            );
            assert_eq!(transition.note_anchor(), startup.note_root);
            let checked = transition
                .checked_launch_reference()
                .expect("checked reference receipt");
            assert_eq!(checked.reference_hash(), public.reference_parent_hash);
            assert_eq!(checked.reference_height(), public.reference_parent_height);

            let action = pending_launch_action_from_inline_args(
                startup,
                parent_height + 2,
                launch_candidate::PRIVATE_SPEND_VERSION_BINDING.into(),
                launch_candidate::PRIVATE_SPEND_ACTION_ID,
                exact.clone(),
            )
            .unwrap();
            let view =
                NativeLaunchActionView::from_pending(startup, parent_height + 2, &action).unwrap();
            assert_eq!(view.exact_native_leaf(), exact.as_slice());
            assert_eq!(view.fee(), public.fee, "{branch} exact fee");
            assert_eq!(view.nullifiers(), expected_nullifiers);
            assert_eq!(view.commitments(), expected_commitments);

            let reject = |candidate: &[u8]| {
                let mut verifier = startup.connector();
                verifier.set_launch_references(references.clone()).unwrap();
                assert!(verifier.verify_exact_v8_leaf(block, 0, candidate).is_err());
            };
            let mut reserved_identity = exact.clone();
            reserved_identity[23] = 1;
            reject(&reserved_identity);
            reject(&exact[..exact.len() - 1]);
            let mut extra = exact.clone();
            extra.push(0);
            reject(&extra);
            let mut changed_ciphertext = exact.clone();
            changed_ciphertext[private_spend_transport::PREAMBLE_BYTES] ^= 1;
            reject(&changed_ciphertext);
            let mut wrong_chain = exact.clone();
            wrong_chain[72] ^= 1;
            reject(&wrong_chain);
            let mut wrong_relation = exact.clone();
            wrong_relation[24] ^= 1;
            reject(&wrong_relation);
            let mut wrong_fee = exact.clone();
            let fee = u64::from_le_bytes(wrong_fee[200..208].try_into().unwrap());
            wrong_fee[200..208].copy_from_slice(&fee.wrapping_add(1).to_le_bytes());
            reject(&wrong_fee);
            let mut wrong_nullifier = exact.clone();
            wrong_nullifier[208] ^= 1;
            reject(&wrong_nullifier);
            let mut duplicate_nullifier = exact.clone();
            let first_nullifier = duplicate_nullifier[208..264].to_vec();
            duplicate_nullifier[264..320].copy_from_slice(&first_nullifier);
            reject(&duplicate_nullifier);
            let mut wrong_reference = exact.clone();
            wrong_reference[104] ^= 1;
            reject(&wrong_reference);
            let mut inner_reserved_suffix = exact.clone();
            *inner_reserved_suffix.last_mut().unwrap() = 1;
            reject(&inner_reserved_suffix);

            let expired_block = Poseidon2V8BlockContext::new(
                startup.end.unwrap() - 1,
                reference_hash(startup.end.unwrap() - 1),
                startup.end.unwrap(),
                reference_hash(startup.end.unwrap()),
            )
            .unwrap();
            let mut expired = startup.connector();
            expired.set_launch_references(references).unwrap();
            assert!(expired
                .verify_exact_v8_leaf(expired_block, 0, &exact)
                .is_err());
            assert_eq!(sha2::Sha512::digest(&exact).to_vec(), original_sha512);
            let retained_after = fs::read(&carrier_path).expect("reread retained carrier");
            assert_eq!(
                sha2::Sha512::digest(&retained_after).to_vec(),
                original_sha512
            );
            carrier_hashes.push(original_sha512);
        }
        assert_eq!(carrier_hashes.len(), 6);
        assert!(
            startup.qualification_only,
            "fixture must not export launch authority"
        );
    }
}
