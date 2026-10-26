//! Source-owned RP06 verification connector. Carrier recognition is not authority.
#![allow(dead_code)]

use super::poseidon2_v8_state::{
    Poseidon2V8Commitment, Poseidon2V8NoteRoot, Poseidon2V8Nullifier, Poseidon2V8PublicTransition,
    Poseidon2V8Root, Poseidon2V8StablecoinEffect,
};
use super::{PendingAction, FAMILY_SHIELDED_POOL};
use codec::Encode;
use protocol_shielded_pool::rp06_transport::{
    decode_rp06_inline_args_exact, DecodedRp06NativeLeaf, Rp06ExpectedContext,
    RP06_CANDIDATE_MAX_INLINE_BYTES, RP06_CIPHERTEXT_BYTES,
};
use protocol_versioning::launch_candidate::{
    launch_proof_authority, LaunchProofKind, LaunchProofRequest, RP06_ACTION_ID, RP06_DOMAIN_SET,
    RP06_PROFILE_ID, RP06_VERSION_BINDING,
};
use protocol_versioning::{ProofAuthorityClass, TxProofBackend};
use transaction_circuit::smallwood_poseidon2_v8_rp06::{
    rp06_program_identity_sha512, validate_rp06_transcript_bytes, verify_rp06_candidate_bytes,
    Rp06PublicStatement,
};
use transaction_core::hashing_pq::ciphertext_hash_bytes;

/// Constructed from validated startup/release data. This value cannot authorize a proof.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rp06StartupContext {
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    manifest_digest: [u8; 64],
    program_sha512: [u8; 64],
    activation_height: u64,
    deactivation_height_exclusive: u64,
}
impl Rp06StartupContext {
    pub(crate) fn from_validated_startup(
        chain_id: [u8; 32],
        genesis_hash: [u8; 32],
        manifest_digest: [u8; 64],
        program_sha512: [u8; 64],
        activation_height: u64,
        deactivation_height_exclusive: u64,
    ) -> Result<Self, String> {
        if chain_id == [0; 32]
            || genesis_hash == [0; 32]
            || manifest_digest == [0; 64]
            || program_sha512 != rp06_program_identity_sha512()
            || activation_height == 0
            || activation_height >= deactivation_height_exclusive
            || deactivation_height_exclusive == u64::MAX
        {
            return Err("RP06 startup identity or finite lifetime rejected".into());
        }
        Ok(Self {
            chain_id,
            genesis_hash,
            manifest_digest,
            program_sha512,
            activation_height,
            deactivation_height_exclusive,
        })
    }
    fn active_at(self, height: u64) -> bool {
        height >= self.activation_height && height < self.deactivation_height_exclusive
    }
    fn transport(self) -> Result<Rp06ExpectedContext, String> {
        Rp06ExpectedContext::new(
            self.chain_id,
            self.program_sha512[..48].try_into().expect("digest prefix"),
        )
        .map_err(|error| format!("RP06 source context: {error}"))
    }
    fn request(self, height: u64, proof_bytes: usize) -> LaunchProofRequest {
        LaunchProofRequest {
            kind: LaunchProofKind::Rp06,
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            manifest_digest: self.manifest_digest,
            relation_digest: self.program_sha512,
            height,
            binding: RP06_VERSION_BINDING,
            family_id: FAMILY_SHIELDED_POOL,
            action_id: RP06_ACTION_ID,
            proof_class: ProofAuthorityClass::Transaction,
            backend_id: TxProofBackend::SmallwoodCandidate.wire_id(),
            profile_id: RP06_PROFILE_ID,
            domain_set: RP06_DOMAIN_SET,
            proof_bytes,
        }
    }
}

/// The root coordinator obtains these roots from an authenticated canonical parent.
/// `note_anchor` is the exact accepted anchor, not one supplied by a remote action.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rp06ParentContext {
    parent_height: u64,
    parent_hash: [u8; 32],
    note_anchor: Poseidon2V8NoteRoot,
    stable_root: Poseidon2V8Root,
}
impl Rp06ParentContext {
    pub(crate) fn new(
        parent_height: u64,
        parent_hash: [u8; 32],
        note_anchor: Poseidon2V8NoteRoot,
        stable_root: Poseidon2V8Root,
    ) -> Result<Self, String> {
        if parent_height >= (1u64 << 48) - 1 || parent_hash == [0; 32] {
            return Err("RP06 canonical parent height/hash rejected".into());
        }
        Ok(Self {
            parent_height,
            parent_hash,
            note_anchor,
            stable_root,
        })
    }
    pub(crate) const fn parent_hash(self) -> [u8; 32] {
        self.parent_hash
    }
    fn height(self) -> u64 {
        self.parent_height + 1
    }
}

/// Exact public-only shape projection. Its existence does not establish proof validity.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rp06ActionView<'a> {
    leaf: DecodedRp06NativeLeaf<'a>,
    statement: Rp06PublicStatement,
}
impl<'a> Rp06ActionView<'a> {
    pub(crate) fn decode(
        startup: Rp06StartupContext,
        parent: Rp06ParentContext,
        action: &'a PendingAction,
    ) -> Result<Self, String> {
        if !startup.active_at(parent.height()) {
            return Err("RP06 candidate height is outside finite lifetime".into());
        }
        if action.binding != RP06_VERSION_BINDING.into()
            || action.family_id != FAMILY_SHIELDED_POOL
            || action.action_id != RP06_ACTION_ID
        {
            return Err("RP06 outer kernel binding/route mismatch".into());
        }
        if action.encoded_size() > RP06_CANDIDATE_MAX_INLINE_BYTES + 225
            || action.anchor != [0; 48]
            || !action.nullifiers.is_empty()
            || !action.commitments.is_empty()
            || action.candidate_artifact.is_some()
        {
            return Err("RP06 forbidden legacy carrier/state fields or oversized action".into());
        }
        let leaf = decode_rp06_inline_args_exact(startup.transport()?, &action.public_args)
            .map_err(|error| format!("RP06 carrier rejected: {error}"))?
            .native_leaf();
        validate_rp06_transcript_bytes(leaf.preamble())
            .map_err(|error| format!("RP06 source preamble rejected: {error}"))?;
        let statement = Rp06PublicStatement::try_from_public_words(&leaf.public_words())
            .map_err(|error| format!("RP06 public statement rejected: {error:?}"))?;
        if statement.chain_id != startup.chain_id
            || statement.base.stablecoin.parent_height != parent.parent_height
            || statement.base.merkle_root != parent.note_anchor.limbs()
            || statement
                .base
                .stablecoin
                .before_root
                .map(|word| word.as_canonical_u64())
                != parent.stable_root.limbs()
            || statement
                .base
                .stablecoin
                .after_root
                .map(|word| word.as_canonical_u64())
                != parent.stable_root.limbs()
            || statement.base.fee != action.fee
        {
            return Err("RP06 authenticated parent/network/roots or fee mismatch".into());
        }
        let intent = statement
            .expected_action_intent()
            .map_err(|error| format!("RP06 operation intent rejected: {error:?}"))?;
        if intent
            .into_iter()
            .enumerate()
            .any(|(i, word)| leaf.intent_limb(i) != Some(word))
        {
            return Err("RP06 exact operation binding mismatch".into());
        }
        let mut hashes = Vec::with_capacity(2);
        let mut sizes = Vec::with_capacity(2);
        for slot in 0..2 {
            if let Some(raw) = leaf.ciphertext(slot) {
                let parsed = wallet::NoteCiphertext::from_da_bytes(raw)
                    .map_err(|error| format!("RP06 output {slot} ciphertext rejected: {error}"))?;
                if parsed
                    .to_da_bytes()
                    .map_err(|error| error.to_string())?
                    .as_slice()
                    != raw
                {
                    return Err("RP06 ciphertext canonical readback mismatch".into());
                }
                hashes.push(ciphertext_hash_bytes(raw));
                sizes.push(RP06_CIPHERTEXT_BYTES as u32);
            }
        }
        if hashes != action.ciphertext_hashes || sizes != action.ciphertext_sizes {
            return Err("RP06 outer ciphertext hash/size projection mismatch".into());
        }
        Ok(Self { leaf, statement })
    }
    pub(crate) const fn native_leaf(self) -> DecodedRp06NativeLeaf<'a> {
        self.leaf
    }
    pub(crate) const fn statement(self) -> Rp06PublicStatement {
        self.statement
    }
    fn verify_candidate(
        self,
        startup: Rp06StartupContext,
    ) -> Result<Rp06VerifiedAction<'a>, String> {
        verify_rp06_candidate_bytes(
            &self.leaf.public_words(),
            self.leaf.relation_digest(),
            self.leaf.proof(),
            startup.chain_id,
        )
        .map_err(|error| format!("RP06 SMZB proof rejected: {error}"))?;
        let base = self.statement.base;
        let parse_nullifier = |slot: usize| -> Result<Option<Poseidon2V8Nullifier>, String> {
            if !base.input_flags[slot] {
                return Ok(None);
            }
            Poseidon2V8Nullifier::new(base.nullifiers[slot])
                .map(Some)
                .map_err(|error| error.to_string())
        };
        let parse_commitment = |slot: usize| -> Result<Option<Poseidon2V8Commitment>, String> {
            if !base.output_flags[slot] {
                return Ok(None);
            }
            Poseidon2V8Commitment::new(base.commitments[slot])
                .map(Some)
                .map_err(|error| error.to_string())
        };
        let transition = Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
            base.stablecoin.parent_height,
            Poseidon2V8Root::new(
                base.stablecoin
                    .before_root
                    .map(|word| word.as_canonical_u64()),
            )
            .map_err(|error| error.to_string())?,
            Poseidon2V8Root::new(
                base.stablecoin
                    .after_root
                    .map(|word| word.as_canonical_u64()),
            )
            .map_err(|error| error.to_string())?,
            Poseidon2V8StablecoinEffect::DisabledNoWrite,
            Poseidon2V8NoteRoot::new(base.merkle_root).map_err(|error| error.to_string())?,
            [parse_nullifier(0)?, parse_nullifier(1)?],
            [parse_commitment(0)?, parse_commitment(1)?],
        );
        Ok(Rp06VerifiedAction {
            transition,
            fee: base.fee,
            leaf: self.leaf,
        })
    }
}

/// Verified full transition and unchanged carrier. State admission still checks roots/history/nullifiers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rp06VerifiedAction<'a> {
    transition: Poseidon2V8PublicTransition,
    fee: u64,
    leaf: DecodedRp06NativeLeaf<'a>,
}
impl<'a> Rp06VerifiedAction<'a> {
    pub(crate) const fn transition(self) -> Poseidon2V8PublicTransition {
        self.transition
    }
    pub(crate) const fn fee(self) -> u64 {
        self.fee
    }
    pub(crate) const fn native_leaf(self) -> DecodedRp06NativeLeaf<'a> {
        self.leaf
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Rp06NativeVerifierConnector {
    startup: Rp06StartupContext,
}
impl Rp06NativeVerifierConnector {
    pub(crate) const fn from_startup(startup: Rp06StartupContext) -> Self {
        Self { startup }
    }
    pub(crate) fn verify_authorized_action<'a>(
        self,
        parent: Rp06ParentContext,
        action: &'a PendingAction,
    ) -> Result<Rp06VerifiedAction<'a>, String> {
        let view = Rp06ActionView::decode(self.startup, parent, action)?;
        let request = self
            .startup
            .request(parent.height(), view.leaf.proof().len());
        let capability = launch_proof_authority(request)
            .ok_or_else(|| "RP06 has no source-owned launch proof authority".to_string())?;
        if !capability.allows(request) {
            return Err("RP06 source authority rejects exact startup/route/lifetime".into());
        }
        view.verify_candidate(self.startup)
    }
    /// Qualification-only path. Never installs a capability or enables runtime admission.
    #[cfg(test)]
    pub(crate) fn verify_candidate_action_for_test<'a>(
        self,
        parent: Rp06ParentContext,
        action: &'a PendingAction,
    ) -> Result<Rp06VerifiedAction<'a>, String> {
        Rp06ActionView::decode(self.startup, parent, action)?.verify_candidate(self.startup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rp06_context_requires_exact_source_and_finite_lifetime_without_runtime_authority() {
        let program = rp06_program_identity_sha512();
        let context =
            Rp06StartupContext::from_validated_startup([1; 32], [2; 32], [3; 64], program, 1, 10)
                .unwrap();
        assert!(context.active_at(1));
        assert!(!context.active_at(0));
        assert!(!context.active_at(10));
        assert!(launch_proof_authority(context.request(1, 100)).is_none());
        assert!(Rp06StartupContext::from_validated_startup(
            [1; 32],
            [2; 32],
            [3; 64],
            program,
            1,
            u64::MAX
        )
        .is_err());
        let mut wrong = program;
        wrong[63] ^= 1;
        assert!(Rp06StartupContext::from_validated_startup(
            [1; 32], [2; 32], [3; 64], wrong, 1, 10
        )
        .is_err());
        assert!(Rp06StartupContext::from_validated_startup(
            [0; 32], [2; 32], [3; 64], program, 1, 10
        )
        .is_err());
    }
}
