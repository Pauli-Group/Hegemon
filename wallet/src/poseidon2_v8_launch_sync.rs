//! Canonical launch-route projections for the trusted-node wallet mirror.
//! Parsing is not proof verification; normal use also requires source authority.
use super::*;
use protocol_shielded_pool::rp06_transport::{decode_rp06_inline_args_exact, Rp06ExpectedContext};
use protocol_versioning::{
    launch_candidate::{self, LaunchProofKind, LaunchProofRequest},
    ProofAuthorityClass, TxProofBackend,
};
use transaction_circuit::{
    smallwood_htlc::{self, HtlcAction},
    smallwood_htlc_transport,
    smallwood_poseidon2_v8_rp06::{
        rp06_program_identity_sha512, validate_rp06_transcript_bytes, Rp06PublicStatement,
    },
};

/// Exact chain/release configuration supplied by the caller. It confers no
/// authority; every production action is checked against the private registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchWalletContext {
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    manifest_digest: [u8; 64],
    activation_height: u64,
    deactivation_height_exclusive: Option<u64>,
}
impl LaunchWalletContext {
    pub fn chain_id(self) -> [u8; 32] {
        self.chain_id
    }
    pub fn genesis_hash(self) -> [u8; 32] {
        self.genesis_hash
    }
    pub fn manifest_digest(self) -> [u8; 64] {
        self.manifest_digest
    }
    pub(crate) fn require_source_authority(self) -> Result<(), WalletError> {
        self.source_genesis_roots().map(|_| ())
    }
    pub(crate) fn source_genesis_roots(
        self,
    ) -> Result<(Poseidon2V8Digest, Poseidon2V8Digest), WalletError> {
        let request = self.request(LaunchProofKind::PrivateSpend, self.activation_height, 1);
        if let Some(capability) = launch_candidate::launch_source_capability(
            LaunchProofKind::PrivateSpend,
            self.chain_id,
            self.genesis_hash,
            self.manifest_digest,
            request.relation_digest,
        ) {
            if !capability.allows(request)
                || capability.activation_height() != self.activation_height
                || capability.deactivation_height_exclusive() != self.deactivation_height_exclusive
            {
                return Err(invalid(
                    "private source context differs from exact lifetime",
                ));
            }
            return Ok((
                capability.stablecoin_genesis_root(),
                capability.note_genesis_root(),
            ));
        }
        if self.deactivation_height_exclusive.is_none() {
            return Err(invalid("ongoing wallet context lacks exact common HGN source authority"));
        }
        let mut roots = None;
        for kind in [LaunchProofKind::Rp06, LaunchProofKind::Htlc] {
            let request = self.request(kind, self.activation_height, 1);
            let capability = launch_candidate::launch_source_capability(
                kind,
                self.chain_id,
                self.genesis_hash,
                self.manifest_digest,
                request.relation_digest,
            )
            .ok_or(invalid("launch context has no source-owned authority"))?;
            if !capability.allows(request)
                || capability.activation_height() != self.activation_height
                || capability.deactivation_height_exclusive() != self.deactivation_height_exclusive
            {
                return Err(invalid("launch context differs from exact source lifetime"));
            }
            let candidate = (
                capability.stablecoin_genesis_root(),
                capability.note_genesis_root(),
            );
            if roots.is_some_and(|previous| previous != candidate) {
                return Err(invalid(
                    "launch source capabilities disagree on genesis roots",
                ));
            }
            roots = Some(candidate);
        }
        roots.ok_or(invalid("launch source genesis roots absent"))
    }
    pub fn new(
        chain_id: [u8; 32],
        genesis_hash: [u8; 32],
        manifest_digest: [u8; 64],
        activation_height: u64,
        deactivation_height_exclusive: impl Into<Option<u64>>,
    ) -> Result<Self, WalletError> {
        let deactivation_height_exclusive = deactivation_height_exclusive.into();
        if chain_id == [0; 32]
            || genesis_hash == [0; 32]
            || manifest_digest == [0; 64]
            || activation_height == 0
            || deactivation_height_exclusive.is_some_and(|end| activation_height >= end || end == u64::MAX)
        {
            return Err(invalid("invalid launch wallet identity or finite lifetime"));
        }
        Ok(Self {
            chain_id,
            genesis_hash,
            manifest_digest,
            activation_height,
            deactivation_height_exclusive,
        })
    }
    pub(crate) fn request(
        self,
        kind: LaunchProofKind,
        height: u64,
        proof_bytes: usize,
    ) -> LaunchProofRequest {
        let (binding, action_id, profile_id, domain_set, relation_digest) = match kind {
            LaunchProofKind::Htlc => (
                launch_candidate::HTLC_VERSION_BINDING,
                launch_candidate::HTLC_ACTION_ID,
                launch_candidate::HTLC_PROFILE_ID,
                launch_candidate::HTLC_DOMAIN_SET,
                smallwood_htlc::relation_digest(),
            ),
            LaunchProofKind::PrivateSpend => (
                launch_candidate::PRIVATE_SPEND_VERSION_BINDING,
                launch_candidate::PRIVATE_SPEND_ACTION_ID,
                launch_candidate::PRIVATE_SPEND_PROFILE_ID,
                launch_candidate::PRIVATE_SPEND_DOMAIN_SET,
                transaction_circuit::private_spend::relation_digest(),
            ),
            LaunchProofKind::Rp06 => (
                launch_candidate::RP06_VERSION_BINDING,
                launch_candidate::RP06_ACTION_ID,
                launch_candidate::RP06_PROFILE_ID,
                launch_candidate::RP06_DOMAIN_SET,
                rp06_program_identity_sha512(),
            ),
        };
        LaunchProofRequest {
            kind,
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            manifest_digest: self.manifest_digest,
            relation_digest,
            height,
            binding,
            family_id: launch_candidate::LAUNCH_SHIELDED_FAMILY_ID,
            action_id,
            proof_class: ProofAuthorityClass::Transaction,
            backend_id: TxProofBackend::SmallwoodCandidate.wire_id(),
            profile_id,
            domain_set,
            proof_bytes,
        }
    }
    pub fn require_canonical_parent(
        self,
        genesis_hash: [u8; 32],
        parent_height: u64,
    ) -> Result<u64, WalletError> {
        let height = parent_height
            .checked_add(1)
            .ok_or(invalid("launch parent height overflow"))?;
        if genesis_hash != self.genesis_hash
            || height < self.activation_height
            || self.deactivation_height_exclusive.is_some_and(|end| height >= end)
        {
            return Err(invalid(
                "launch parent differs from pinned chain or finite lifetime",
            ));
        }
        Ok(height)
    }
    pub(crate) fn require_canonical_reference(
        self,
        mirror: &Poseidon2V8WalletState,
        reference: Poseidon2V8CanonicalTip,
        strict_current: bool,
    ) -> Result<u64, WalletError> {
        let actual = mirror.tip()?;
        if mirror.canonical_tip_at_height(reference.height) != Some(reference) {
            return Err(invalid(
                "launch reference checkpoint is no longer canonical",
            ));
        }
        self.require_reference_tip(
            mirror
                .canonical_hash(0)
                .ok_or(invalid("launch reference mirror has no genesis"))?,
            actual,
            reference,
            strict_current,
        )
    }

    // The supplied reference must first be selected from this mirror's immutable
    // canonical block-end snapshot, never from proof-provided root/hash hints.
    pub(crate) fn require_reference_tip(
        self,
        genesis: [u8; 32],
        actual: Poseidon2V8CanonicalTip,
        reference: Poseidon2V8CanonicalTip,
        strict_current: bool,
    ) -> Result<u64, WalletError> {
        let inclusion_height = self.require_canonical_parent(genesis, actual.height)?;
        self.require_canonical_parent(genesis, reference.height)?;
        if !protocol_versioning::launch_reference_policy::launch_reference_distance_allowed(
            reference.height,
            actual.height,
            strict_current,
        ) || reference.stablecoin_root.is_none()
            || reference.stablecoin_root != actual.stablecoin_root
        {
            return Err(invalid(
                "launch reference is not attached within its canonical window",
            ));
        }
        Ok(inclusion_height)
    }

    fn check_height(self, mirror: &Poseidon2V8WalletState, height: u64) -> Result<(), WalletError> {
        if mirror.canonical_hash(0) != Some(self.genesis_hash)
            || height < self.activation_height
            || self.deactivation_height_exclusive.is_some_and(|end| height >= end)
        {
            return Err(invalid("launch block outside exact wallet chain/lifetime"));
        }
        Ok(())
    }
}

/// Encrypted V13 binding. Byte vectors are checked to be exactly 64 bytes;
/// this avoids adding an alternate serde encoding to the frozen legacy state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredNativeLaunchContext {
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    manifest_digest: Vec<u8>,
    rp06_relation_digest: Vec<u8>,
    htlc_relation_digest: Vec<u8>,
    activation_height: u64,
    deactivation_height_exclusive: u64,
}
impl StoredNativeLaunchContext {
    pub(crate) fn from_context(context: LaunchWalletContext) -> Self {
        Self {
            chain_id: context.chain_id,
            genesis_hash: context.genesis_hash,
            manifest_digest: context.manifest_digest.to_vec(),
            rp06_relation_digest: rp06_program_identity_sha512().to_vec(),
            htlc_relation_digest: smallwood_htlc::relation_digest().to_vec(),
            activation_height: context.activation_height,
            // Keep the frozen positional u64 encoding. Zero was never a valid
            // finite end and now denotes explicit ongoing mode in storage only.
            deactivation_height_exclusive: context.deactivation_height_exclusive.unwrap_or(0),
        }
    }
    pub(crate) fn current_context(&self) -> Result<LaunchWalletContext, WalletError> {
        if self.rp06_relation_digest.as_slice() != rp06_program_identity_sha512()
            || self.htlc_relation_digest.as_slice() != smallwood_htlc::relation_digest()
        {
            return Err(invalid(
                "stored launch source identity differs from this wallet program",
            ));
        }
        LaunchWalletContext::new(
            self.chain_id,
            self.genesis_hash,
            self.manifest_digest
                .as_slice()
                .try_into()
                .map_err(|_| invalid("stored launch manifest length"))?,
            self.activation_height,
            if self.deactivation_height_exclusive == 0 { None } else { Some(self.deactivation_height_exclusive) },
        )
    }
    pub(crate) fn require_match(&self, context: LaunchWalletContext) -> Result<(), WalletError> {
        if self.current_context()? != context {
            return Err(invalid("wallet launch identity is immutable; use a separate wallet for another chain or program"));
        }
        Ok(())
    }
}

pub(super) struct LaunchProjection {
    nullifiers: Vec<Poseidon2V8Digest>,
    outputs: Vec<(
        Poseidon2V8Digest,
        [u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES],
    )>,
    recover_ordinary_outputs: bool,
    private_commitments: Vec<Poseidon2V8Digest>,
}
fn invalid(message: &'static str) -> WalletError {
    WalletError::InvalidState(message)
}
fn surface(error: impl std::fmt::Display) -> WalletError {
    WalletError::Serialization(format!("launch wallet: {error}"))
}

impl Poseidon2V8WalletState {
    pub(crate) fn apply_launch_block(
        &mut self,
        block: &Poseidon2V8CanonicalBlock,
        keys: Option<&DerivedKeys>,
        context: LaunchWalletContext,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        self.apply_launch_block_inner(block, keys, context, true, false, false)
    }
    /// The test node must have verified these exact bytes. This never installs
    /// production authority and is absent from ordinary wallet builds.
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub(crate) fn apply_launch_block_for_retained_test(
        &mut self,
        block: &Poseidon2V8CanonicalBlock,
        keys: Option<&DerivedKeys>,
        context: LaunchWalletContext,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        self.apply_launch_block_inner(block, keys, context, false, false, false)
    }
    fn apply_launch_block_inner(
        &mut self,
        block: &Poseidon2V8CanonicalBlock,
        keys: Option<&DerivedKeys>,
        context: LaunchWalletContext,
        require_authority: bool,
        allow_assets: bool,
        allow_recovery: bool,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        context.check_height(self, block.height)?;
        let parent = self.tip()?;
        // Capture before applying any action/reward: same-block output roots are
        // never historical references, and later appends cannot evict these roots.
        let references = (parent
            .height
            .saturating_sub(protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW)
            ..=parent.height)
            .filter_map(|height| self.canonical_tip_at_height(height))
            .collect::<Vec<_>>();
        self.apply_block_with_transfer_decoder(block, keys, |wire| match wire.action_id {
            launch_candidate::HTLC_ACTION_ID
            | launch_candidate::RP06_ACTION_ID
            | launch_candidate::PRIVATE_SPEND_ACTION_ID => {
                decode_launch(wire, context, parent, &references, require_authority)
            }
            transaction_circuit::asset_spend_v1_admission::ASSET_SPEND_ACTION_ID
            | transaction_circuit::asset_spend_v1_admission::ASSET_ADMIN_ACTION_ID
                if allow_assets && !require_authority =>
            {
                decode_native_asset_launch(wire, context, parent, &references)
            }
            RECOVERY_SPEND_ACTION_ID | RECOVERY_ADMIN_ACTION_ID
                if allow_recovery && !require_authority =>
            {
                decode_native_recovery_launch(wire, context, parent, &references)
            }
            _ => Err(invalid(
                "ordinary V8 transfer cannot be relabelled as a launch action",
            )),
        })
    }
    pub(super) fn apply_launch_projection(
        &mut self,
        projection: LaunchProjection,
        block: &Poseidon2V8CanonicalBlock,
        keys: Option<&DerivedKeys>,
        delta: &mut Poseidon2V8SyncDelta,
        introduced: &mut Vec<Poseidon2V8Digest>,
    ) -> Result<(), WalletError> {
        for nullifier in projection.nullifiers {
            if self.has_canonical_nullifier(nullifier) {
                return Err(invalid("duplicate launch nullifier in canonical mirror"));
            }
            if let Some(note) = self
                .owned_notes
                .iter_mut()
                .find(|note| note.nullifier == nullifier)
            {
                if note.spent_by.is_some() {
                    return Err(invalid("launch input already spent"));
                }
                note.spent_by = Some(block.hash);
                delta.spent += 1;
            }
            self.nullifiers.push(StoredPoseidon2V8Nullifier {
                value: nullifier,
                block_hash: block.hash,
            });
            introduced.push(nullifier);
        }
        for commitment in projection.private_commitments {
            self.append_commitment(commitment)?;
            delta.commitments += 1;
            delta.ciphertexts += 1;
        }
        for (commitment, raw) in projection.outputs {
            let position = self.append_commitment(commitment)?;
            delta.commitments += 1;
            delta.ciphertexts += 1;
            if projection.recover_ordinary_outputs {
                if let Some(keys) = keys {
                    // This recovery accepts only an exact ordinary key opening.
                    // Policy custody is tracked separately from encrypted descriptors.
                    if let Some((opening, diversifier)) =
                        recover_transfer_note(&raw, commitment, keys)?
                    {
                        self.insert_owned_note_at(
                            opening,
                            commitment,
                            diversifier,
                            position,
                            block,
                            keys,
                        )?;
                        delta.recovered += 1;
                    }
                }
            }
        }
        Ok(())
    }
    pub(crate) fn canonical_note_positions(
        &self,
        commitment: Poseidon2V8Digest,
    ) -> Result<Vec<u64>, WalletError> {
        if self.genesis_hash.is_none() {
            return Ok(Vec::new());
        }
        self.validate_default_root()?;
        Ok(self
            .tree_levels
            .first()
            .into_iter()
            .flatten()
            .enumerate()
            .filter(|(_, value)| **value == commitment)
            .map(|(position, _)| position as u64)
            .collect())
    }
}

fn decode_launch(
    wire: PendingActionWire,
    context: LaunchWalletContext,
    parent: Poseidon2V8CanonicalTip,
    canonical_references: &[Poseidon2V8CanonicalTip],
    require_authority: bool,
) -> Result<DecodedPoseidon2V8Action, WalletError> {
    if wire.anchor != [0; 48]
        || !wire.nullifiers.is_empty()
        || !wire.commitments.is_empty()
        || wire.candidate_artifact.is_some()
    {
        return Err(invalid(
            "launch action contains forbidden legacy state fields",
        ));
    }
    if wire.action_id == protocol_shielded_pool::private_spend_transport::ACTION_ID {
        return decode_private_spend_launch(
            wire,
            context,
            parent,
            canonical_references,
            require_authority,
        );
    }
    let height = parent
        .height
        .checked_add(1)
        .ok_or(invalid("launch wallet height overflow"))?;
    let (kind, proof_len, projection) = if wire.action_id == launch_candidate::HTLC_ACTION_ID {
        if wire.binding != launch_candidate::HTLC_VERSION_BINDING.into() {
            return Err(invalid("HTLC outer binding mismatch"));
        }
        let carrier =
            smallwood_htlc_transport::decode_candidate_exact(&wire.public_args).map_err(surface)?;
        let reference = canonical_references
            .iter()
            .copied()
            .find(|tip| tip.height == carrier.statement.parent_height)
            .ok_or(invalid("HTLC canonical reference checkpoint unavailable"))?;
        context.require_reference_tip(
            context.genesis_hash,
            parent,
            reference,
            carrier.statement.action == HtlcAction::Lock,
        )?;
        carrier
            .statement
            .validate_context(
                context.chain_id,
                reference.block_hash,
                reference.height,
                reference.anchor,
            )
            .map_err(surface)?;
        if wire.fee != carrier.statement.fee
            || wire.ciphertext_hashes != [carrier.statement.ciphertext_commitment]
            || wire.ciphertext_sizes != [carrier.ciphertext.len() as u32]
        {
            return Err(invalid("HTLC outer fee/ciphertext projection mismatch"));
        }
        let parsed = NoteCiphertext::from_da_bytes(carrier.ciphertext)?;
        if parsed.to_da_bytes()?.as_slice() != carrier.ciphertext {
            return Err(invalid("HTLC ciphertext is not canonical"));
        }
        (
            LaunchProofKind::Htlc,
            carrier.proof.len(),
            LaunchProjection {
                nullifiers: vec![carrier.statement.nullifier],
                outputs: vec![(
                    carrier.statement.output_commitment,
                    carrier
                        .ciphertext
                        .try_into()
                        .map_err(|_| invalid("HTLC ciphertext length"))?,
                )],
                recover_ordinary_outputs: carrier.statement.action != HtlcAction::Lock,
                private_commitments: Vec::new(),
            },
        )
    } else {
        if wire.action_id != launch_candidate::RP06_ACTION_ID
            || wire.binding != launch_candidate::RP06_VERSION_BINDING.into()
        {
            return Err(invalid("RP06 outer binding mismatch"));
        }
        let digest = rp06_program_identity_sha512();
        let expected = Rp06ExpectedContext::new(context.chain_id, digest[..48].try_into().unwrap())
            .map_err(surface)?;
        let decoded =
            decode_rp06_inline_args_exact(expected, &wire.public_args).map_err(surface)?;
        let leaf = decoded.native_leaf();
        validate_rp06_transcript_bytes(leaf.preamble()).map_err(surface)?;
        let statement = Rp06PublicStatement::try_from_public_words(&leaf.public_words())
            .map_err(|error| surface(format!("{error:?}")))?;
        let reference = canonical_references
            .iter()
            .copied()
            .find(|tip| tip.height == statement.base.stablecoin.parent_height)
            .ok_or(invalid("RP06 canonical reference checkpoint unavailable"))?;
        context.require_reference_tip(context.genesis_hash, parent, reference, false)?;
        let stable = reference
            .stablecoin_root
            .ok_or(invalid("RP06 stablecoin parent root unavailable"))?;
        if statement.chain_id != context.chain_id
            || statement.base.merkle_root != reference.anchor
            || felt_digest_to_words(statement.base.stablecoin.before_root) != stable
            || felt_digest_to_words(statement.base.stablecoin.after_root) != stable
            || wire.fee != statement.base.fee
        {
            return Err(invalid("RP06 canonical chain/parent/roots/fee mismatch"));
        }
        let intent = statement
            .expected_action_intent()
            .map_err(|error| surface(format!("{error:?}")))?;
        if intent
            .into_iter()
            .enumerate()
            .any(|(index, word)| leaf.intent_limb(index) != Some(word))
        {
            return Err(invalid("RP06 exact operation intent mismatch"));
        }
        let mut outputs = Vec::new();
        let mut hashes = Vec::new();
        let mut sizes = Vec::new();
        for index in 0..2 {
            if let Some(raw) = leaf.ciphertext(index) {
                let parsed = NoteCiphertext::from_da_bytes(raw)?;
                if parsed.to_da_bytes()?.as_slice() != raw {
                    return Err(invalid("RP06 ciphertext is not canonical"));
                }
                outputs.push((statement.base.commitments[index], *raw));
                hashes.push(ciphertext_hash_bytes(raw));
                sizes.push(raw.len() as u32);
            }
        }
        if wire.ciphertext_hashes != hashes || wire.ciphertext_sizes != sizes {
            return Err(invalid("RP06 outer ciphertext projection mismatch"));
        }
        (
            LaunchProofKind::Rp06,
            leaf.proof().len(),
            LaunchProjection {
                nullifiers: (0..2)
                    .filter(|&i| statement.base.input_flags[i])
                    .map(|i| statement.base.nullifiers[i])
                    .collect(),
                outputs,
                recover_ordinary_outputs: true,
                private_commitments: Vec::new(),
            },
        )
    };
    if require_authority
        && launch_candidate::launch_proof_authority(context.request(kind, height, proof_len))
            .is_none()
    {
        return Err(invalid("launch wallet route has no source-owned authority"));
    }
    Ok(DecodedPoseidon2V8Action::Launch(projection))
}

/// Called only after the same block has been projected successfully. The
/// returned metadata has no independent proof or chain-authorization meaning.
pub(crate) fn canonical_launch_observations(
    block: &Poseidon2V8CanonicalBlock,
) -> Result<
    (
        Vec<([u8; 48], u64, [u8; 32])>,
        Vec<([u8; 48], Vec<u8>)>,
        Vec<SmallwoodPoseidon2V8NoteOpening>,
    ),
    WalletError,
> {
    let mut actions = Vec::new();
    let mut htlc = Vec::new();
    let mut rewards = Vec::new();
    for encoded in &block.action_bytes {
        let wire = decode_canonical_action_exact(encoded)?;
        if wire.family_id != FAMILY_SHIELDED_POOL {
            continue;
        }
        actions.push((wire.tx_hash, block.height, block.hash));
        match wire.action_id {
            launch_candidate::HTLC_ACTION_ID => htlc.push((wire.tx_hash, wire.public_args)),
            ACTION_MINT_POSEIDON2_V8_COINBASE | launch_candidate::ALLOCATED_REWARD_ACTION_ID => {
                if let DecodedPoseidon2V8Action::Coinbase(notes) = decode_v8_coinbase(wire)? {
                    rewards.extend(
                        notes
                            .into_iter()
                            .map(|note| protocol_opening_to_relation(note.opening)),
                    );
                }
            }
            _ => (),
        }
    }
    Ok((actions, htlc, rewards))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        keys::RootSecret, poseidon2_v8_coinbase::build_poseidon2_v8_coinbase_args, WalletStore,
    };
    use hegemon_field::{Goldilocks, PrimeCharacteristicRing};
    use protocol_shielded_pool::rp06_transport::{
        encode_rp06_candidate_envelope, encode_rp06_candidate_inline_args,
        encode_rp06_candidate_native_leaf,
    };
    use rand::{rngs::StdRng, SeedableRng};
    const GENESIS: [u8; 32] = [61; 32];
    const CHAIN: [u8; 32] = [62; 32];
    const STABLE: [u64; 7] = [1, 2, 3, 4, 5, 6, 7];
    pub(crate) fn htlc_journal_test_block(
        parent: Poseidon2V8CanonicalTip,
        root: &RootSecret,
    ) -> (Poseidon2V8CanonicalBlock, LaunchWalletContext) {
        (
            block(
                parent,
                72,
                vec![htlc_action(
                    parent,
                    HtlcAction::Claim,
                    [12; 7],
                    output(root, 9, 2),
                )],
            ),
            context(),
        )
    }
    fn context() -> LaunchWalletContext {
        LaunchWalletContext::new(CHAIN, GENESIS, [63; 64], 1, 100).unwrap()
    }
    fn output(
        root: &RootSecret,
        value: u64,
        seed: u64,
    ) -> (
        Poseidon2V8Digest,
        [u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES],
    ) {
        let address = root
            .derive()
            .poseidon2_v8_address(0)
            .unwrap()
            .shielded_address();
        let note =
            build_poseidon2_v8_coinbase_args(&address, value, &mut StdRng::seed_from_u64(seed))
                .unwrap()
                .miner_note;
        let raw = NoteCiphertext::from_chain_bytes(&note.encrypted_note.encode())
            .unwrap()
            .to_da_bytes()
            .unwrap()
            .try_into()
            .unwrap();
        (note.commitment, raw)
    }
    fn wire(
        action_id: u16,
        binding: protocol_versioning::VersionBinding,
        args: Vec<u8>,
        raw: &[u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES],
    ) -> Vec<u8> {
        let mut wire = PendingActionWire {
            tx_hash: [0; 48],
            binding: binding.into(),
            family_id: FAMILY_SHIELDED_POOL,
            action_id,
            anchor: [0; 48],
            nullifiers: vec![],
            commitments: vec![],
            ciphertext_hashes: vec![ciphertext_hash_bytes(raw)],
            ciphertext_sizes: vec![raw.len() as u32],
            public_args: args,
            fee: 0,
            candidate_artifact: None,
        };
        wire.tx_hash = pending_action_hash(&wire);
        wire.encode()
    }
    fn block(
        parent: Poseidon2V8CanonicalTip,
        marker: u8,
        action_bytes: Vec<Vec<u8>>,
    ) -> Poseidon2V8CanonicalBlock {
        Poseidon2V8CanonicalBlock {
            height: parent.height + 1,
            hash: [marker; 32],
            parent_hash: parent.block_hash,
            action_bytes,
        }
    }
    fn htlc_action(
        parent: Poseidon2V8CanonicalTip,
        action: HtlcAction,
        nf: Poseidon2V8Digest,
        output: (
            Poseidon2V8Digest,
            [u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES],
        ),
    ) -> Vec<u8> {
        let statement = smallwood_htlc::HtlcStatement {
            version: 1,
            action,
            network_id: CHAIN,
            parent_hash: parent.block_hash,
            parent_height: parent.height,
            merkle_root: parent.anchor,
            nullifier: nf,
            output_commitment: output.0,
            ciphertext_commitment: ciphertext_hash_bytes(&output.1),
            fee: 0,
            revealed_secret: None,
        };
        // Deliberately invalid proof bytes: these test only trusted-node mirror
        // projection and encrypted recovery, never proof or release acceptance.
        let args =
            smallwood_htlc_transport::encode_candidate(&statement, &output.1, b"SMZC-framing-only")
                .unwrap();
        wire(
            launch_candidate::HTLC_ACTION_ID,
            launch_candidate::HTLC_VERSION_BINDING,
            args,
            &output.1,
        )
    }
    fn rp06_action(
        parent: Poseidon2V8CanonicalTip,
        nf: Poseidon2V8Digest,
        output: (
            Poseidon2V8Digest,
            [u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES],
        ),
    ) -> Vec<u8> {
        let mut base = SmallwoodPoseidon2V8PublicStatement::default();
        base.input_flags = [true, false];
        base.output_flags = [true, false];
        base.nullifiers[0] = nf;
        base.commitments[0] = output.0;
        base.merkle_root = parent.anchor;
        base.ciphertext_commitments[0]=transaction_circuit::smallwood_poseidon2_v8_types::smallwood_poseidon2_v8_ciphertext_commitment(&output.1);
        base.stablecoin.parent_height = parent.height;
        base.stablecoin.before_root = STABLE.map(Goldilocks::from_u64);
        base.stablecoin.after_root = base.stablecoin.before_root;
        let statement = Rp06PublicStatement {
            base,
            chain_id: CHAIN,
        };
        let preamble =
            transaction_circuit::smallwood_poseidon2_v8_rp06::rp06_transcript_bytes(&statement)
                .unwrap()
                .try_into()
                .unwrap();
        let digest = rp06_program_identity_sha512();
        let expected = Rp06ExpectedContext::new(CHAIN, digest[..48].try_into().unwrap()).unwrap();
        let leaf = encode_rp06_candidate_native_leaf(
            expected,
            &preamble,
            [Some(&output.1), None],
            b"SMZB-framing-only",
        )
        .unwrap();
        let envelope = encode_rp06_candidate_envelope(expected, &leaf).unwrap();
        let args = encode_rp06_candidate_inline_args(expected, &envelope).unwrap();
        wire(
            launch_candidate::RP06_ACTION_ID,
            launch_candidate::RP06_VERSION_BINDING,
            args,
            &output.1,
        )
    }
    #[test]
    fn launch_genesis_initialization_is_atomic_exact_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("genesis-wallet");
        let store = WalletStore::create_full(&path, "genesis").unwrap();
        let pristine = std::fs::read(&path).unwrap();
        assert!(store.ensure_poseidon2_v8_launch_genesis(context()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), pristine);
        assert!(store.launch_context().is_err());
        store
            .ensure_poseidon2_v8_launch_genesis_for_retained_test(context(), STABLE)
            .unwrap();
        assert_eq!(store.launch_context().unwrap(), context());
        assert_eq!(store.poseidon2_v8_canonical_hash(0).unwrap(), Some(GENESIS));
        let expected_tip = store.poseidon2_v8_tip().unwrap();
        store
            .ensure_poseidon2_v8_launch_genesis_for_retained_test(context(), STABLE)
            .unwrap();
        assert_eq!(store.poseidon2_v8_tip().unwrap(), expected_tip);
        let initialized = std::fs::read(&path).unwrap();
        let mut wrong_root = STABLE;
        wrong_root[6] ^= 1;
        assert!(store
            .ensure_poseidon2_v8_launch_genesis_for_retained_test(context(), wrong_root)
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), initialized);
        let mut wrong_network = context();
        wrong_network.genesis_hash[31] ^= 1;
        assert!(store
            .ensure_poseidon2_v8_launch_genesis_for_retained_test(wrong_network, STABLE)
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), initialized);
        drop(store);
        let reopened = WalletStore::open(&path, "genesis").unwrap();
        assert_eq!(reopened.poseidon2_v8_tip().unwrap(), expected_tip);
    }

    #[test]
    fn launch_reference_window_projects_unchanged_delayed_actions_and_rejects_orphans() {
        let root = RootSecret::from_bytes([71; 32]);
        let mut mirror = Poseidon2V8WalletState::default();
        mirror.ensure_genesis_for_test(GENESIS, STABLE).unwrap();
        let reference = mirror.tip().unwrap();
        for marker in 1..=12 {
            let next = block(mirror.tip().unwrap(), marker, vec![]);
            mirror
                .apply_launch_block_for_retained_test(&next, None, context())
                .unwrap();
        }
        assert_eq!(
            context()
                .require_canonical_reference(&mirror, reference, false)
                .unwrap(),
            13
        );
        assert!(context()
            .require_canonical_reference(&mirror, reference, true)
            .is_err());
        let lock = block(
            mirror.tip().unwrap(),
            13,
            vec![htlc_action(
                reference,
                HtlcAction::Lock,
                [31; 7],
                output(&root, 9, 20),
            )],
        );
        assert!(mirror
            .apply_launch_block_for_retained_test(&lock, None, context())
            .is_err());
        let actions = vec![
            htlc_action(reference, HtlcAction::Claim, [32; 7], output(&root, 9, 21)),
            htlc_action(reference, HtlcAction::Refund, [33; 7], output(&root, 8, 22)),
            rp06_action(reference, [34; 7], output(&root, 7, 23)),
        ];
        let delayed = block(mirror.tip().unwrap(), 13, actions.clone());
        assert!(mirror
            .apply_launch_block(&delayed, None, context())
            .is_err());
        mirror
            .apply_launch_block_for_retained_test(&delayed, None, context())
            .unwrap();
        assert_eq!(delayed.action_bytes, actions);
        assert!(mirror.has_canonical_nullifier([32; 7]));
        assert!(mirror.has_canonical_nullifier([33; 7]));
        assert!(mirror.has_canonical_nullifier([34; 7]));
        assert!(context()
            .require_canonical_reference(&mirror, reference, false)
            .is_err());
        let expired = block(
            mirror.tip().unwrap(),
            14,
            vec![htlc_action(
                reference,
                HtlcAction::Claim,
                [35; 7],
                output(&root, 6, 24),
            )],
        );
        assert!(mirror
            .apply_launch_block_for_retained_test(&expired, None, context())
            .is_err());
        let future = Poseidon2V8CanonicalTip {
            height: 14,
            ..mirror.tip().unwrap()
        };
        assert!(context()
            .require_canonical_reference(&mirror, future, false)
            .is_err());

        // Replace a height whose old block had outputs. Neither its HTLC hash nor
        // its old RP06 root remains a canonical checkpoint on the selected fork.
        mirror.rollback_to(0, GENESIS).unwrap();
        let first = block(
            mirror.tip().unwrap(),
            40,
            vec![htlc_action(
                reference,
                HtlcAction::Claim,
                [40; 7],
                output(&root, 5, 25),
            )],
        );
        mirror
            .apply_launch_block_for_retained_test(&first, None, context())
            .unwrap();
        let detached = mirror.tip().unwrap();
        let orphan_htlc = htlc_action(detached, HtlcAction::Claim, [41; 7], output(&root, 4, 26));
        let orphan_rp06 = rp06_action(detached, [42; 7], output(&root, 3, 27));
        mirror.rollback_to(0, GENESIS).unwrap();
        let replacement = block(mirror.tip().unwrap(), 41, vec![]);
        mirror
            .apply_launch_block_for_retained_test(&replacement, None, context())
            .unwrap();
        assert!(context()
            .require_canonical_reference(&mirror, detached, false)
            .is_err());
        for action in [orphan_htlc, orphan_rp06] {
            let next = block(mirror.tip().unwrap(), 42, vec![action]);
            assert!(mirror
                .apply_launch_block_for_retained_test(&next, None, context())
                .is_err());
        }
    }
    #[test]
    fn launch_context_is_durable_immutable_and_source_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let store = WalletStore::create_full(&path, "context").unwrap();
        assert!(store.launch_chain_id().is_err());
        assert!(store.initialize_pinned_launch_context(context()).is_err());
        store
            .initialize_pinned_launch_context_for_retained_test(context())
            .unwrap();
        assert_eq!(store.launch_chain_id().unwrap(), CHAIN);
        assert_eq!(context().require_canonical_parent(GENESIS, 0).unwrap(), 1);
        assert!(context().require_canonical_parent([99; 32], 0).is_err());
        assert!(context().require_canonical_parent(GENESIS, 99).is_err());
        assert!(context()
            .require_canonical_parent(GENESIS, u64::MAX)
            .is_err());
        let before = std::fs::read(&path).unwrap();
        let mut changed = context();
        changed.chain_id[31] ^= 1;
        assert!(store
            .initialize_pinned_launch_context_for_retained_test(changed)
            .is_err());
        assert!(store.require_launch_context(changed).is_err());
        changed = context();
        changed.manifest_digest[63] ^= 1;
        assert!(store.require_launch_context(changed).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(store.ensure_poseidon2_v8_genesis([99; 32]).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(store);
        let reopened = WalletStore::open(&path, "context").unwrap();
        assert_eq!(reopened.launch_context().unwrap(), context());
        let mut stored = StoredNativeLaunchContext::from_context(context());
        stored.htlc_relation_digest[63] ^= 1;
        assert!(stored.current_context().is_err());
    }
    #[test]
    fn ongoing_launch_context_preserves_finite_storage_and_canonical_bounds() {
        #[derive(Serialize)]
        struct FrozenFiniteContext {
            chain_id: [u8; 32], genesis_hash: [u8; 32], manifest_digest: Vec<u8>,
            rp06_relation_digest: Vec<u8>, htlc_relation_digest: Vec<u8>,
            activation_height: u64, deactivation_height_exclusive: u64,
        }
        let finite = StoredNativeLaunchContext::from_context(context());
        let old = FrozenFiniteContext {
            chain_id: finite.chain_id, genesis_hash: finite.genesis_hash,
            manifest_digest: finite.manifest_digest.clone(),
            rp06_relation_digest: finite.rp06_relation_digest.clone(),
            htlc_relation_digest: finite.htlc_relation_digest.clone(),
            activation_height: finite.activation_height,
            deactivation_height_exclusive: 100,
        };
        assert_eq!(bincode::serialize(&finite).unwrap(), bincode::serialize(&old).unwrap());
        let ongoing = LaunchWalletContext::new(CHAIN, GENESIS, [63; 64], 1, None).unwrap();
        let stored = StoredNativeLaunchContext::from_context(ongoing);
        assert_eq!(stored.deactivation_height_exclusive, 0);
        let decoded: StoredNativeLaunchContext = bincode::deserialize(&bincode::serialize(&stored).unwrap()).unwrap();
        assert_eq!(decoded.current_context().unwrap(), ongoing);
        assert!(ongoing.require_canonical_parent(GENESIS, 100_000).is_ok());
        assert!(ongoing.require_canonical_parent(GENESIS, 621_730_874).is_ok());
        assert!(ongoing.require_canonical_parent([99; 32], 100_000).is_err());
        assert!(ongoing.require_canonical_parent(GENESIS, u64::MAX).is_err());
        // Data absence cannot create source authority; the registry stays empty.
        assert!(ongoing.require_source_authority().is_err());
        assert!(context().require_canonical_parent(GENESIS, 100).is_err());
    }

    #[test]
    fn launch_mirror_exact_routes_ordinary_recovery_restart_and_reorg() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        let root = RootSecret::from_bytes([71; 32]);
        let store = WalletStore::create_from_root(&path, "mirror", root.clone()).unwrap();
        store
            .ensure_poseidon2_v8_genesis_for_test(GENESIS, STABLE)
            .unwrap();
        let lock = block(
            store.poseidon2_v8_tip().unwrap(),
            72,
            vec![htlc_action(
                store.poseidon2_v8_tip().unwrap(),
                HtlcAction::Lock,
                [11; 7],
                output(&root, 10, 1),
            )],
        );
        let before = std::fs::read(&path).unwrap();
        assert!(store
            .apply_poseidon2_v8_launch_canonical_block(&lock, context())
            .is_err());
        assert!(store.apply_poseidon2_v8_canonical_block(&lock).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        store
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&lock, context())
            .unwrap();
        assert!(
            store.poseidon2_v8_owned_notes().unwrap().is_empty(),
            "HTLC locks must not enter ordinary custody"
        );
        let claim = block(
            store.poseidon2_v8_tip().unwrap(),
            73,
            vec![htlc_action(
                store.poseidon2_v8_tip().unwrap(),
                HtlcAction::Claim,
                [12; 7],
                output(&root, 9, 2),
            )],
        );
        store
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&claim, context())
            .unwrap();
        assert_eq!(store.poseidon2_v8_owned_notes().unwrap()[0].position, 1);
        let payment = rp06_action(
            store.poseidon2_v8_tip().unwrap(),
            [13; 7],
            output(&root, 8, 3),
        );
        let duplicate = block(
            store.poseidon2_v8_tip().unwrap(),
            74,
            vec![payment.clone(), payment.clone()],
        );
        let before = std::fs::read(&path).unwrap();
        assert!(store
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&duplicate, context())
            .is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "failed block projection must be atomic"
        );
        let third = block(store.poseidon2_v8_tip().unwrap(), 74, vec![payment]);
        store
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&third, context())
            .unwrap();
        let notes = store.poseidon2_v8_owned_notes().unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[1].position, 2);
        drop(store);
        let reopened = WalletStore::open(&path, "mirror").unwrap();
        assert_eq!(reopened.poseidon2_v8_owned_notes().unwrap(), notes);
        reopened.rollback_poseidon2_v8_to(1, lock.hash).unwrap();
        assert!(reopened.poseidon2_v8_owned_notes().unwrap().is_empty());
        let replay = block(
            reopened.poseidon2_v8_tip().unwrap(),
            75,
            vec![htlc_action(
                reopened.poseidon2_v8_tip().unwrap(),
                HtlcAction::Lock,
                [11; 7],
                output(&root, 7, 4),
            )],
        );
        assert!(reopened
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&replay, context())
            .is_err());
        reopened
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&claim, context())
            .unwrap();
        assert_eq!(reopened.poseidon2_v8_owned_notes().unwrap()[0].position, 1);
    }
}

fn private_spend_expected(
    context: LaunchWalletContext,
) -> Result<protocol_shielded_pool::private_spend_transport::ExpectedContext, WalletError> {
    let digest = transaction_circuit::private_spend::relation_digest();
    protocol_shielded_pool::private_spend_transport::ExpectedContext::new(
        context.chain_id(),
        digest[..48].try_into().expect("source digest prefix"),
    )
    .map_err(surface)
}
fn decode_private_spend_launch(
    wire: PendingActionWire,
    context: LaunchWalletContext,
    parent: Poseidon2V8CanonicalTip,
    references: &[Poseidon2V8CanonicalTip],
    require_authority: bool,
) -> Result<DecodedPoseidon2V8Action, WalletError> {
    use protocol_shielded_pool::private_spend_transport as transport;
    if wire.binding
        != (PendingVersionBinding {
            circuit: transport::CIRCUIT_VERSION,
            crypto: transport::CRYPTO_SUITE,
        })
    {
        return Err(invalid("private-spend outer version mismatch"));
    }
    let decoded = transport::decode_exact(private_spend_expected(context)?, &wire.public_args)
        .map_err(surface)?;
    let public = &decoded.public;
    let inclusion_height = parent
        .height
        .checked_add(1)
        .ok_or(invalid("private spend inclusion overflow"))?;
    if require_authority
        && launch_candidate::launch_proof_authority(context.request(
            LaunchProofKind::PrivateSpend,
            inclusion_height,
            decoded.proof.len(),
        ))
        .is_none()
    {
        return Err(invalid(
            "private spend wallet route has no source-owned authority",
        ));
    }
    let reference = references
        .iter()
        .copied()
        .find(|tip| tip.height == public.reference_parent_height)
        .ok_or(invalid(
            "private-spend reference absent from canonical window",
        ))?;
    context.require_reference_tip(context.genesis_hash(), parent, reference, false)?;
    if public.reference_parent_hash != reference.block_hash
        || public.merkle_root != reference.anchor
        || wire.fee != public.fee
        || wire.ciphertext_hashes != public.ciphertext_commitments
        || wire.ciphertext_sizes != [transport::CIPHERTEXT_BYTES as u32; 2]
    {
        return Err(invalid(
            "private-spend canonical context or outer projection mismatch",
        ));
    }
    Ok(DecodedPoseidon2V8Action::Launch(LaunchProjection {
        nullifiers: public.nullifiers.to_vec(),
        outputs: Vec::new(),
        recover_ordinary_outputs: false,
        private_commitments: public.commitments.to_vec(),
    }))
}

impl Poseidon2V8WalletState {
    /// Called inside WalletStore's mirror transaction after successful projection.
    /// Recovery does not verify proofs; it consumes the same trusted-node body.
    pub(crate) fn recover_private_spend_block(
        &self,
        block: &Poseidon2V8CanonicalBlock,
        keys: &DerivedKeys,
        issued: &crate::private_spend::IssuedPrivateSpendAddresses,
        context: LaunchWalletContext,
    ) -> Result<Vec<crate::private_spend::StoredPrivateSpendNote>, WalletError> {
        use protocol_shielded_pool::private_spend_transport as transport;
        let stored = self
            .blocks
            .last()
            .filter(|b| b.block_hash == block.hash && b.height == block.height)
            .ok_or(invalid("private-spend recovery block was not projected"))?;
        let mut position = stored.leaf_count_before;
        let mut recovered = Vec::new();
        for encoded in &block.action_bytes {
            let wire = decode_canonical_action_exact(encoded)?;
            if wire.family_id != FAMILY_SHIELDED_POOL {
                continue;
            }
            match wire.action_id {
                transport::ACTION_ID => {
                    let decoded = transport::decode_exact(
                        private_spend_expected(context)?,
                        &wire.public_args,
                    )
                    .map_err(surface)?;
                    for slot in 0..2 {
                        let commitment = decoded.public.commitments[slot];
                        if self
                            .tree_levels
                            .first()
                            .and_then(|leaves| leaves.get(position as usize))
                            != Some(&commitment)
                        {
                            return Err(invalid(
                                "private-spend recovery occurrence differs from mirror",
                            ));
                        }
                        if let Some(note) = crate::private_spend::recover_private_spend_note(
                            keys,
                            issued,
                            decoded.public.relation_digest,
                            decoded.public.chain_id,
                            slot as u8,
                            commitment,
                            decoded.ciphertexts[slot],
                        )? {
                            recovered.push(crate::private_spend::StoredPrivateSpendNote::new(
                                note,
                                keys,
                                context.chain_id(),
                                commitment,
                                position,
                                block.height,
                                block.hash,
                            )?);
                        }
                        position = position
                            .checked_add(1)
                            .ok_or(invalid("private-spend position overflow"))?;
                    }
                }
                transaction_circuit::asset_spend_v1_admission::ASSET_SPEND_ACTION_ID => {
                    // Asset recovery below owns plaintext discovery. This pass must
                    // still cover the same three shared-tree occurrences, including
                    // outputs addressed to another wallet, before mature rewards.
                    let (_, body) = canonical_asset_action_body(encoded)?
                        .ok_or(invalid("asset-spend recovery body absent"))?;
                    let decoded = transaction_circuit::asset_spend_v1_wire::
                        decode_native_asset_spend_action_v1(&body).map_err(surface)?;
                    for commitment in decoded.public.commitments {
                        if self
                            .tree_levels
                            .first()
                            .and_then(|leaves| leaves.get(position as usize))
                            != Some(&commitment)
                        {
                            return Err(invalid(
                                "asset-spend recovery occurrence differs from mirror",
                            ));
                        }
                        position = position
                            .checked_add(1)
                            .ok_or(invalid("asset-spend position overflow"))?;
                    }
                }
                transaction_circuit::asset_spend_v1_admission::ASSET_ADMIN_ACTION_ID => {
                    // Exact framing authenticates the zero-note admin projection.
                    canonical_asset_action_body(encoded)?;
                }
                RECOVERY_SPEND_ACTION_ID => {
                    let (_, _, body) = canonical_recovery_action_body(encoded)?
                        .ok_or(invalid("recovery body absent"))?;
                    let d = transaction_circuit::asset_recovery_wire_v1::decode_spend_ref(&body)
                        .map_err(surface)?;
                    for cm in d.public.base.commitments {
                        if self
                            .tree_levels
                            .first()
                            .and_then(|l| l.get(position as usize))
                            != Some(&cm)
                        {
                            return Err(invalid("recovery occurrence differs from mirror"));
                        }
                        position = position
                            .checked_add(1)
                            .ok_or(invalid("recovery position overflow"))?;
                    }
                }
                RECOVERY_ADMIN_ACTION_ID => {
                    canonical_recovery_action_body(encoded)?;
                }

                launch_candidate::HTLC_ACTION_ID => {
                    position += 1;
                }
                launch_candidate::RP06_ACTION_ID => {
                    let digest = rp06_program_identity_sha512();
                    let expected = Rp06ExpectedContext::new(
                        context.chain_id(),
                        digest[..48].try_into().unwrap(),
                    )
                    .map_err(surface)?;
                    let decoded = decode_rp06_inline_args_exact(expected, &wire.public_args)
                        .map_err(surface)?;
                    let statement = Rp06PublicStatement::try_from_public_words(
                        &decoded.native_leaf().public_words(),
                    )
                    .map_err(|e| {
                        WalletError::Serialization(format!("private launch RP06 shape: {e:?}"))
                    })?;
                    position += statement
                        .base
                        .output_flags
                        .iter()
                        .filter(|active| **active)
                        .count() as u64;
                }
                ACTION_MINT_POSEIDON2_V8_COINBASE
                | launch_candidate::ALLOCATED_REWARD_ACTION_ID => {
                    if let DecodedPoseidon2V8Action::Coinbase(notes) = decode_v8_coinbase(wire)? {
                        let _ = notes; // Queued rewards are not action-time leaves.
                    }
                }
                _ => (),
            }
        }
        for reward in &stored.released_rewards {
            for note in &reward.notes {
                if self
                    .tree_levels
                    .first()
                    .and_then(|leaves| leaves.get(position as usize))
                    != Some(&note.commitment)
                {
                    return Err(invalid(
                        "mature reward recovery occurrence differs from mirror",
                    ));
                }
                position += 1;
            }
        }
        if position != self.tree_levels.first().map_or(0, Vec::len) as u64 {
            return Err(invalid(
                "private-spend recovery did not cover projected leaves",
            ));
        }
        Ok(recovered)
    }
}

#[cfg(test)]
#[path = "private_spend_tests.rs"]
mod private_spend_tests;

/// Exact outer action projection for the encrypted submission journal. Proof and
/// current source authority are checked separately by its caller.
pub(crate) fn private_spend_journal_projection(
    encoded: &[u8],
) -> Result<([u8; 48], Vec<u8>), WalletError> {
    use protocol_shielded_pool::private_spend_transport as t;
    let wire = decode_canonical_action_exact(encoded)?;
    if wire.family_id != FAMILY_SHIELDED_POOL
        || wire.action_id != t::ACTION_ID
        || wire.binding
            != (PendingVersionBinding {
                circuit: t::CIRCUIT_VERSION,
                crypto: t::CRYPTO_SUITE,
            })
        || wire.anchor != [0; 48]
        || !wire.nullifiers.is_empty()
        || !wire.commitments.is_empty()
        || wire.candidate_artifact.is_some()
    {
        return Err(invalid("private journal outer action identity"));
    }
    // Chain and source checks are repeated against the pinned context by caller.
    if wire.public_args.len() < t::PREAMBLE_BYTES {
        return Err(invalid("private journal preamble missing"));
    }
    let chain = wire.public_args[72..104]
        .try_into()
        .map_err(|_| invalid("private journal chain width"))?;
    let expected = t::ExpectedContext::new(
        chain,
        transaction_circuit::private_spend::relation_digest()[..48]
            .try_into()
            .unwrap(),
    )
    .map_err(surface)?;
    let decoded = t::decode_exact(expected, &wire.public_args).map_err(surface)?;
    if wire.fee != decoded.public.fee
        || wire.ciphertext_hashes != decoded.public.ciphertext_commitments
        || wire.ciphertext_sizes != [t::CIPHERTEXT_BYTES as u32; 2]
    {
        return Err(invalid("private journal outer projection differs"));
    }
    Ok((wire.tx_hash, wire.public_args))
}

#[cfg(test)]
pub(crate) fn private_spend_journal_framing_fixture(
    public: &protocol_shielded_pool::private_spend_transport::PublicStatement,
) -> Vec<u8> {
    use codec::Encode;
    use protocol_shielded_pool::private_spend_transport as t;
    let ct = [0u8; t::CIPHERTEXT_BYTES];
    let mut wire = PendingActionWire {
        tx_hash: [0; 48],
        binding: PendingVersionBinding {
            circuit: t::CIRCUIT_VERSION,
            crypto: t::CRYPTO_SUITE,
        },
        family_id: FAMILY_SHIELDED_POOL,
        action_id: t::ACTION_ID,
        anchor: [0; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: public.ciphertext_commitments.to_vec(),
        ciphertext_sizes: vec![t::CIPHERTEXT_BYTES as u32; 2],
        fee: public.fee,
        public_args: t::encode(public, [&ct, &ct], b"SMZL").unwrap(),
        candidate_artifact: None,
    };
    wire.tx_hash = pending_action_hash(&wire);
    wire.encode()
}

/// Construct the canonical native action around unchanged private-spend carrier
/// bytes. This pure framing helper confers no proof or submission authority.
pub fn encode_private_spend_candidate_action(
    context: LaunchWalletContext,
    carrier: &[u8],
) -> Result<Vec<u8>, WalletError> {
    use protocol_shielded_pool::private_spend_transport as t;
    let decoded = t::decode_exact(private_spend_expected(context)?, carrier).map_err(surface)?;
    let mut wire = PendingActionWire {
        tx_hash: [0; 48],
        binding: PendingVersionBinding {
            circuit: t::CIRCUIT_VERSION,
            crypto: t::CRYPTO_SUITE,
        },
        family_id: FAMILY_SHIELDED_POOL,
        action_id: t::ACTION_ID,
        anchor: [0; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: decoded.public.ciphertext_commitments.to_vec(),
        ciphertext_sizes: vec![t::CIPHERTEXT_BYTES as u32; 2],
        public_args: carrier.to_vec(),
        fee: decoded.public.fee,
        candidate_artifact: None,
    };
    wire.tx_hash = pending_action_hash(&wire);
    let encoded = wire.encode();
    private_spend_journal_projection(&encoded)?;
    Ok(encoded)
}
/// Exact framing projection only. The journal independently verifies the proof
/// and validates its production capability or explicit development token.
pub fn project_private_spend_candidate_action(
    encoded: &[u8],
) -> Result<([u8; 48], Vec<u8>), WalletError> {
    private_spend_journal_projection(encoded)
}

impl Poseidon2V8WalletState {
    pub(crate) fn apply_private_spend_source_block(
        &mut self,
        block: &Poseidon2V8CanonicalBlock,
        keys: Option<&DerivedKeys>,
        context: LaunchWalletContext,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        use protocol_shielded_pool::private_spend_transport as t;
        // A capability/lifetime probe, not a claim that an empty block has proof.
        crate::private_spend_rpc::require_private_spend_source(context, block.height, 1)?;
        for encoded in &block.action_bytes {
            let wire = decode_canonical_action_exact(encoded)?;
            if wire.family_id != FAMILY_SHIELDED_POOL {
                return Err(invalid("private source block contains another family"));
            }
            match wire.action_id {
                launch_candidate::ALLOCATED_REWARD_ACTION_ID => {
                    // The canonical node verifies allocated-reward issuance;
                    // the mirror still parses its exact normal reward route.
                    decode_v8_coinbase(wire)?;
                }
                t::ACTION_ID => {
                    let (_, args) = private_spend_journal_projection(encoded)?;
                    let decoded = t::decode_exact(private_spend_expected(context)?, &args)
                        .map_err(surface)?;
                    crate::private_spend_rpc::require_private_spend_source(
                        context,
                        block.height,
                        decoded.proof.len(),
                    )?;
                    let p = &decoded.public;
                    let public = transaction_circuit::private_spend::PrivateSpendPublic {
                        chain_id: p.chain_id,
                        reference_parent_hash: p.reference_parent_hash,
                        reference_parent_height: p.reference_parent_height,
                        merkle_root: p.merkle_root,
                        fee: p.fee,
                        nullifiers: p.nullifiers,
                        commitments: p.commitments,
                        ciphertext_commitments: p.ciphertext_commitments,
                        secret_release: p.secret_release,
                        released_secret: p.released_secret,
                    };
                    transaction_circuit::private_spend::verify_candidate(&public, decoded.proof)
                        .map_err(surface)?;
                }
                _ => {
                    return Err(invalid(
                        "private source block permits only actions 12 and 15",
                    ))
                }
            }
        }
        // Keep independent proof verification and all canonical projections;
        // the normal decoder also rechecks source authority at inclusion height.
        self.apply_launch_block_inner(block, keys, context, true, false, false)
    }
}

#[cfg(feature = "private-spend-dev-artifacts")]
impl Poseidon2V8WalletState {
    pub(crate) fn apply_private_spend_development_block(
        &mut self,
        block: &Poseidon2V8CanonicalBlock,
        keys: Option<&DerivedKeys>,
        token: &crate::private_spend_rpc::DevelopmentPrivateSpendAuthority,
    ) -> Result<Poseidon2V8SyncDelta, WalletError> {
        use protocol_shielded_pool::private_spend_transport as t;
        let context = token.context();
        // A capability/lifetime probe, not a claim that an empty block has proof.
        token.authorize(context, block.height, 1)?;
        for encoded in &block.action_bytes {
            let wire = decode_canonical_action_exact(encoded)?;
            if wire.family_id != FAMILY_SHIELDED_POOL {
                return Err(invalid("private development block contains another family"));
            }
            match wire.action_id {
                launch_candidate::ALLOCATED_REWARD_ACTION_ID => {
                    // The canonical node verifies allocated-reward issuance;
                    // the mirror still parses its exact normal reward route.
                    decode_v8_coinbase(wire)?;
                }
                t::ACTION_ID => {
                    let (_, args) = private_spend_journal_projection(encoded)?;
                    let decoded = t::decode_exact(private_spend_expected(context)?, &args)
                        .map_err(surface)?;
                    token.authorize(context, block.height, decoded.proof.len())?;
                    let p = &decoded.public;
                    let public = transaction_circuit::private_spend::PrivateSpendPublic {
                        chain_id: p.chain_id,
                        reference_parent_hash: p.reference_parent_hash,
                        reference_parent_height: p.reference_parent_height,
                        merkle_root: p.merkle_root,
                        fee: p.fee,
                        nullifiers: p.nullifiers,
                        commitments: p.commitments,
                        ciphertext_commitments: p.ciphertext_commitments,
                        secret_release: p.secret_release,
                        released_secret: p.released_secret,
                    };
                    transaction_circuit::private_spend::verify_candidate(&public, decoded.proof)
                        .map_err(surface)?;
                }
                transaction_circuit::asset_spend_v1_admission::ASSET_SPEND_ACTION_ID
                    if token.assets_enabled() =>
                {
                    validate_native_asset_outer(&wire)?;
                    let d=transaction_circuit::asset_spend_v1_wire::decode_native_asset_spend_action_v1(&wire.public_args).map_err(surface)?;
                    token.authorize(context, block.height, d.proof.len())?;
                    transaction_circuit::asset_spend_v1::verify_candidate(&d.public, d.proof)
                        .map_err(surface)?;
                }
                transaction_circuit::asset_spend_v1_admission::ASSET_ADMIN_ACTION_ID
                    if token.assets_enabled() =>
                {
                    validate_native_asset_outer(&wire)?;
                    let d=transaction_circuit::asset_spend_v1_wire::decode_native_asset_admin_action_v1(&wire.public_args).map_err(surface)?;
                    token.authorize(context, block.height, d.proof.len())?;
                    transaction_circuit::asset_policy_admin_v1::verify_candidate(
                        &d.public, d.proof,
                    )
                    .map_err(surface)?;
                }
                RECOVERY_SPEND_ACTION_ID if token.recovery_enabled() => {
                    validate_native_recovery_outer(&wire)?;
                    let d = transaction_circuit::asset_recovery_wire_v1::decode_spend_ref(
                        &wire.public_args,
                    )
                    .map_err(surface)?;
                    token.authorize_recovery_public(&d.public)?;
                    token.authorize(context, block.height, d.proof.len())?;
                    transaction_circuit::asset_recovery_spend_v1::verify_candidate(
                        &d.public, d.proof,
                    )
                    .map_err(surface)?;
                    // One spend plus two fixed SMZR components for each of two
                    // mandatory capsules: five proof units, each capped alone.
                    const _: [(); 5] =
                        [(); transaction_circuit::asset_recovery_wire_v1::PROOF_UNITS];
                    for cap in d.capsules {
                        for component in
                            transaction_circuit::asset_recovery_capsule_v1::bundle_components(
                                cap.proof,
                            )
                            .map_err(surface)?
                        {
                            token.authorize(context, block.height, component.len())?;
                        }
                        transaction_circuit::asset_recovery_capsule_v1::verify(
                            &cap.public,
                            cap.proof,
                        )
                        .map_err(surface)?;
                    }
                }
                RECOVERY_ADMIN_ACTION_ID if token.recovery_enabled() => {
                    validate_native_recovery_outer(&wire)?;
                    let d = transaction_circuit::asset_recovery_wire_v1::decode_admin_ref(
                        &wire.public_args,
                    )
                    .map_err(surface)?;
                    token.authorize_recovery_admin_public(&d.public)?;
                    token.authorize(context, block.height, d.proof.len())?;
                    transaction_circuit::asset_recovery_admin_v1::verify_candidate(
                        &d.public, d.proof,
                    )
                    .map_err(surface)?;
                }
                _ => {
                    return Err(invalid(
                        "private development block action is outside its source descriptor",
                    ))
                }
            }
        }
        // Explicit token checks above replace only production release authority;
        // canonical history, common reference window and projections remain shared.
        self.apply_launch_block_inner(
            block,
            keys,
            context,
            false,
            token.assets_enabled(),
            token.recovery_enabled(),
        )
    }
}

#[cfg(all(test, feature = "private-spend-dev-artifacts"))]
mod private_spend_development_codec_tests {
    use super::*;
    #[test]
    fn private_spend_development_codec_preserves_complete_carrier_and_rejects_outer_drift() {
        use protocol_shielded_pool::private_spend_transport as t;
        let context = LaunchWalletContext::new([1; 32], [2; 32], [3; 64], 1, 1_000).unwrap();
        let ct = [0; t::CIPHERTEXT_BYTES];
        let p = t::PublicStatement {
            relation_digest: transaction_circuit::private_spend::relation_digest()[..48]
                .try_into()
                .unwrap(),
            chain_id: context.chain_id(),
            reference_parent_hash: [4; 32],
            reference_parent_height: 5,
            merkle_root: [6; 7],
            fee: 7,
            nullifiers: [[8; 7], [9; 7]],
            commitments: [[10; 7], [11; 7]],
            ciphertext_commitments: [transaction_circuit::hashing_pq::ciphertext_hash_bytes(&ct);
                2],
            secret_release: 0,
            released_secret: [0; 32],
        };
        // Framing-only proof marker. Production/dev journal retention must still
        // reject it through the actual verifier; this codec grants no authority.
        let carrier = t::encode(&p, [&ct, &ct], b"SMZL").unwrap();
        let action = encode_private_spend_candidate_action(context, &carrier).unwrap();
        assert_eq!(action, private_spend_journal_framing_fixture(&p));
        assert_eq!(
            project_private_spend_candidate_action(&action).unwrap().1,
            carrier
        );
        let mut changed = decode_canonical_action_exact(&action).unwrap();
        changed.fee += 1;
        changed.tx_hash = pending_action_hash(&changed);
        assert!(project_private_spend_candidate_action(&changed.encode()).is_err());
        let mut trailing = action;
        trailing.push(0);
        assert!(project_private_spend_candidate_action(&trailing).is_err());
    }
}

#[cfg(test)]
mod asset_private_recovery_tests {
    use super::*;

    // Replay only the public occurrence-recovery phase after mirror projection.
    // This does not grant source authority or verify an asset proof.
    fn assert_three_asset_leaves_before_mature_reward(action: Vec<u8>) {
        let (_, body) = canonical_asset_action_body(&action).unwrap().unwrap();
        let decoded =
            transaction_circuit::asset_spend_v1_wire::decode_native_asset_spend_action_v1(&body)
                .unwrap();
        assert_eq!(decoded.public.operation, 1, "regression requires mint");
        let public = decoded.public;
        let genesis = [82; 32];
        let block = Poseidon2V8CanonicalBlock {
            height: public.parent_height + 1,
            hash: [83; 32],
            parent_hash: public.reference_parent_hash,
            action_bytes: vec![action],
        };
        let context =
            LaunchWalletContext::new(public.chain_id, genesis, [84; 64], 1, block.height + 100)
                .unwrap();
        let mut mirror = Poseidon2V8WalletState {
            genesis_hash: Some(genesis),
            tree_levels: empty_tree_levels(),
            root_log: vec![empty_note_root()],
            ..Default::default()
        };
        for commitment in public.commitments {
            mirror.append_commitment(commitment).unwrap();
        }
        let reward = [901; 7];
        mirror.append_commitment(reward).unwrap();
        for value in public.nullifiers {
            mirror.nullifiers.push(StoredPoseidon2V8Nullifier {
                value,
                block_hash: block.hash,
            });
        }
        mirror.blocks.push(StoredPoseidon2V8Block {
            height: block.height,
            block_hash: block.hash,
            parent_hash: block.parent_hash,
            leaf_count_before: 0,
            root_log_len_before: 1,
            root_after: current_note_root(&mirror.tree_levels).unwrap(),
            stablecoin_root_before: None,
            stablecoin_root_after: None,
            introduced_nullifiers: public.nullifiers.to_vec(),
            released_rewards: vec![StoredPoseidon2V8PendingReward {
                created_height: 1,
                created_block_hash: [85; 32],
                notes: vec![StoredPoseidon2V8PendingRewardNote {
                    commitment: reward,
                    owned_opening: None,
                }],
            }],
        });
        // No recipient key or wallet passphrase from the retained mint is used.
        // Every asset occurrence must advance the cursor even without ownership.
        let keys = crate::RootSecret::from_bytes([86; 32]).derive();
        let issued = crate::private_spend::IssuedPrivateSpendAddresses::default();
        assert!(mirror
            .recover_private_spend_block(&block, &keys, &issued, context)
            .unwrap()
            .is_empty());
        // Recovery leaves shared nullifiers available to the store's ordinary
        // private-note spent reconciliation, including the real native fee input.
        assert!(mirror.has_canonical_nullifier(public.nullifiers[1]));
        mirror.tree_levels[0][2][0] ^= 1;
        assert!(matches!(
            mirror.recover_private_spend_block(&block, &keys, &issued, context),
            Err(WalletError::InvalidState(
                "asset-spend recovery occurrence differs from mirror"
            ))
        ));
    }

    #[cfg(feature = "private-spend-dev-artifacts")]
    #[test]
    fn asset_mint_recovery_covers_three_unowned_outputs_then_mature_reward() {
        use transaction_circuit::{
            asset_spend_v1_admission as admission, asset_spend_v1_wire as transport,
        };
        let fixture = crate::asset_spend_v1_fixture::DisposableAssetFixtureV1::build(1, 4).unwrap();
        let mut public = fixture.public.clone();
        let ciphertexts = [[7; 2608], [8; 2608], [9; 2608]];
        public.ciphertext_commitments = ciphertexts.map(|c| ciphertext_hash_bytes(&c));
        // A framing marker is sufficient for cursor recovery, never verification.
        let body =
            transport::encode_native_asset_spend_action_v1(&public, &ciphertexts, b"SMZE").unwrap();
        let binding = admission::NATIVE_VERSION_BINDING;
        let mut wire = PendingActionWire {
            tx_hash: [0; 48],
            binding: PendingVersionBinding {
                circuit: binding.circuit,
                crypto: binding.crypto,
            },
            family_id: FAMILY_SHIELDED_POOL,
            action_id: admission::ASSET_SPEND_ACTION_ID,
            anchor: [0; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: public.ciphertext_commitments.to_vec(),
            ciphertext_sizes: vec![2608; 3],
            public_args: body,
            fee: public.fee,
            candidate_artifact: None,
        };
        wire.tx_hash = pending_action_hash(&wire);
        assert_three_asset_leaves_before_mature_reward(wire.encode());
    }

    #[test]
    #[ignore = "requires HEGEMON_RETAINED_ASSET_MINT_ACTION public canonical action file"]
    fn retained_public_mint_recovery_needs_no_wallet_keys() {
        let path = std::env::var_os("HEGEMON_RETAINED_ASSET_MINT_ACTION")
            .expect("set HEGEMON_RETAINED_ASSET_MINT_ACTION to the retained mint.action");
        assert_three_asset_leaves_before_mature_reward(std::fs::read(path).unwrap());
    }
}
