//! Dormant exact verifier connector for the SmallWood/Poseidon2 V8 lane.
//!
//! The native node does not construct a relation, accept a verifier callback,
//! or trust a caller-supplied digest. It contextual-decodes the exact HGV8 leaf
//! with the digest owned by the transaction relation module, reconstructs the
//! complete verifier input, calls the source-owned SMZ9 verifier, and exposes
//! stablecoin roots only after that call succeeds. Production action authority
//! remains the single fail-closed protocol-versioning gate.

#![allow(dead_code)]

use codec::Encode;
use protocol_shielded_pool::poseidon2_production_transport::{
    decode_poseidon2_production_smz9_inline_args_exact,
    decode_poseidon2_production_smz9_native_leaf_exact, Poseidon2ProductionExpectedContext,
    POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS,
    POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS,
    POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID, POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID,
    POSEIDON2_PRODUCTION_TRANSPORT_BACKEND_ID, POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET,
    POSEIDON2_PRODUCTION_TRANSPORT_FAMILY_ID,
};
use transaction_circuit::smallwood_poseidon2_v8_frontend::{
    V8_PUBLIC_AFTER_ROOT, V8_PUBLIC_BEFORE_ROOT, V8_PUBLIC_PARENT_HEIGHT,
};
use transaction_circuit::{
    smallwood_poseidon2_v8_types::{
        SmallwoodPoseidon2V8PublicStatement, SMALLWOOD_POSEIDON2_V8_PUBLIC_VALUE_BALANCE_MAGNITUDE,
        SMALLWOOD_POSEIDON2_V8_PUBLIC_VALUE_BALANCE_SIGN,
    },
    verify_smallwood_poseidon2_v8_candidate, SmallwoodPoseidon2V8SourceRelationFactory,
    SmallwoodPoseidon2V8VerifierInput, SmallwoodPoseidon2V8VerifierRelationFactory,
    SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS, SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS,
};
use transaction_core::hashing_pq::ciphertext_hash_bytes;

use super::poseidon2_v8_state::{
    Poseidon2V8BlockContext, Poseidon2V8Commitment, Poseidon2V8ExactLeafVerifier,
    Poseidon2V8NoteRoot, Poseidon2V8Nullifier, Poseidon2V8PublicTransition, Poseidon2V8Root,
    Poseidon2V8StablecoinEffect, POSEIDON2_V8_MAX_SCALAR,
};
use super::{
    ActionId48, KernelVersionBinding, PendingAction, ACTION_MINT_POSEIDON2_V8_COINBASE,
    ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE, FAMILY_SHIELDED_POOL,
    MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK, POSEIDON2_V8_MAX_PENDING_ACTION_BYTES,
};

fn ensure_poseidon2_v8_no_transparent_value_balance(
    statement: &SmallwoodPoseidon2V8PublicStatement,
) -> Result<(), String> {
    if statement.value_balance_sign || statement.value_balance_magnitude != 0 {
        return Err(
            "V8 value balance must be canonical zero because no transparent value pool is implemented"
                .to_owned(),
        );
    }
    Ok(())
}

fn ensure_poseidon2_v8_public_words_no_transparent_value_balance(
    public_values: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
) -> Result<(), String> {
    if public_values[SMALLWOOD_POSEIDON2_V8_PUBLIC_VALUE_BALANCE_SIGN] != 0
        || public_values[SMALLWOOD_POSEIDON2_V8_PUBLIC_VALUE_BALANCE_MAGNITUDE] != 0
    {
        return Err(
            "V8 value balance must be canonical zero because no transparent value pool is implemented"
                .to_owned(),
        );
    }
    Ok(())
}

fn ensure_poseidon2_v8_supported_note_genesis_root(
    note_genesis_root: Poseidon2V8NoteRoot,
) -> Result<(), String> {
    if note_genesis_root.limbs()
        != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NOTE_GENESIS_ROOT
    {
        return Err(
            "production V8 note genesis root is not the source-owned canonical empty tree root"
                .to_owned(),
        );
    }
    Ok(())
}

fn poseidon2_v8_stablecoin_effect(
    statement: &SmallwoodPoseidon2V8PublicStatement,
) -> Poseidon2V8StablecoinEffect {
    match statement.stablecoin.direction {
        transaction_core::stablecoin_poseidon2_v8::StablecoinPoseidon2V8Direction::Disabled => {
            Poseidon2V8StablecoinEffect::DisabledNoWrite
        }
        transaction_core::stablecoin_poseidon2_v8::StablecoinPoseidon2V8Direction::Mint => {
            Poseidon2V8StablecoinEffect::Mint
        }
        transaction_core::stablecoin_poseidon2_v8::StablecoinPoseidon2V8Direction::Burn => {
            Poseidon2V8StablecoinEffect::Burn
        }
    }
}

/// Borrowed, exact projection of one canonical V8 `PendingAction`.  The raw
/// native leaf remains a slice of `PendingAction::public_args`; no proof or
/// ciphertext bytes are re-encoded between RPC, relay, mempool, mining, and
/// block verification.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Poseidon2V8ActionView<'a> {
    exact_native_leaf: &'a [u8],
    statement: SmallwoodPoseidon2V8PublicStatement,
    note_anchor: Poseidon2V8NoteRoot,
    nullifiers: [Option<Poseidon2V8Nullifier>; 2],
    commitments: [Option<Poseidon2V8Commitment>; 2],
}

impl<'a> Poseidon2V8ActionView<'a> {
    pub(crate) fn from_pending(
        production: Poseidon2V8ProductionBinding,
        height: u64,
        action: &'a PendingAction,
    ) -> Result<Self, String> {
        if !production.active_at(height) {
            return Err("V8 production binding is not active at the candidate height".to_owned());
        }
        if action.binding
            != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into()
            || action.family_id != FAMILY_SHIELDED_POOL
            || action.action_id != ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE
        {
            return Err("V8 pending action route/binding mismatch".to_owned());
        }
        if action.encoded_size() > POSEIDON2_V8_MAX_PENDING_ACTION_BYTES {
            return Err(format!(
                "V8 full pending action exceeds the route-specific {}-byte cap",
                POSEIDON2_V8_MAX_PENDING_ACTION_BYTES
            ));
        }
        if action.anchor != [0u8; 48]
            || !action.nullifiers.is_empty()
            || !action.commitments.is_empty()
            || action.candidate_artifact.is_some()
        {
            return Err(
                "V8 pending action carries forbidden legacy 48-byte state or artifact fields"
                    .to_owned(),
            );
        }

        let decoded = decode_poseidon2_production_smz9_inline_args_exact(
            production.expected_context(),
            &action.public_args,
        )
        .map_err(|error| format!("V8 pending action contextual decode rejected: {error}"))?;
        let leaf = decoded.envelope().decoded_native_leaf();
        let mut public_values = [0u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS];
        for (index, value) in public_values.iter_mut().enumerate() {
            *value = leaf.statement_word(index).ok_or_else(|| {
                format!("V8 pending action omitted public statement word {index}")
            })?;
        }
        ensure_poseidon2_v8_public_words_no_transparent_value_balance(&public_values)?;
        let statement = SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&public_values)
            .map_err(|error| format!("V8 pending public statement rejected: {error:?}"))?;
        ensure_poseidon2_v8_no_transparent_value_balance(&statement)?;
        let expected_parent_height = height
            .checked_sub(1)
            .ok_or_else(|| "V8 action cannot target native height zero".to_owned())?;
        if statement.stablecoin.parent_height != expected_parent_height {
            return Err(format!(
                "V8 pending statement parent height mismatch: candidate={expected_parent_height} statement={}",
                statement.stablecoin.parent_height
            ));
        }
        let note_anchor = Poseidon2V8NoteRoot::new(statement.merkle_root)
            .map_err(|error| format!("V8 pending note anchor rejected: {error}"))?;
        let parse_nullifier = |slot: usize| -> Result<Option<Poseidon2V8Nullifier>, String> {
            if !statement.input_flags[slot] {
                return Ok(None);
            }
            Poseidon2V8Nullifier::new(statement.nullifiers[slot])
                .map(Some)
                .map_err(|error| format!("V8 pending nullifier {slot} rejected: {error}"))
        };
        let nullifiers = [parse_nullifier(0)?, parse_nullifier(1)?];
        let parse_commitment = |slot: usize| -> Result<Option<Poseidon2V8Commitment>, String> {
            if !statement.output_flags[slot] {
                return Ok(None);
            }
            Poseidon2V8Commitment::new(statement.commitments[slot])
                .map(Some)
                .map_err(|error| format!("V8 pending commitment {slot} rejected: {error}"))
        };
        let commitments = [parse_commitment(0)?, parse_commitment(1)?];
        let expected_binding = statement
            .expected_action_intent()
            .map_err(|error| format!("V8 pending action intent rejected: {error:?}"))?;
        for (index, expected) in expected_binding.iter().copied().enumerate() {
            if leaf.relation_balance_binding_limb(index) != Some(expected) {
                return Err(format!(
                    "V8 pending relation/balance binding mismatch at limb {index}"
                ));
            }
        }

        let mut ciphertext_hashes = Vec::with_capacity(2);
        let mut ciphertext_sizes = Vec::with_capacity(2);
        for slot in 0..2 {
            match (statement.output_flags[slot], leaf.ciphertext(slot)) {
                (true, Some(ciphertext)) => {
                    ciphertext_hashes.push(ciphertext_hash_bytes(ciphertext));
                    ciphertext_sizes.push(u32::try_from(ciphertext.len()).map_err(|_| {
                        "V8 ciphertext length exceeds the pending metadata type".to_owned()
                    })?);
                }
                (false, None) => {}
                _ => return Err(format!("V8 ciphertext activity mismatch at slot {slot}")),
            }
        }
        if action.fee != statement.fee
            || action.ciphertext_hashes != ciphertext_hashes
            || action.ciphertext_sizes != ciphertext_sizes
        {
            return Err(
                "V8 pending fee/ciphertext metadata differs from the exact HGV8 statement"
                    .to_owned(),
            );
        }
        Ok(Self {
            exact_native_leaf: decoded.envelope().native_leaf(),
            statement,
            note_anchor,
            nullifiers,
            commitments,
        })
    }

    pub(crate) const fn exact_native_leaf(self) -> &'a [u8] {
        self.exact_native_leaf
    }

    pub(crate) const fn statement(self) -> SmallwoodPoseidon2V8PublicStatement {
        self.statement
    }

    pub(crate) const fn note_anchor(self) -> Poseidon2V8NoteRoot {
        self.note_anchor
    }

    pub(crate) const fn nullifiers(self) -> [Option<Poseidon2V8Nullifier>; 2] {
        self.nullifiers
    }

    pub(crate) const fn commitments(self) -> [Option<Poseidon2V8Commitment>; 2] {
        self.commitments
    }

    /// Return a parser-owned transition used only to choose deterministic
    /// proof-verification order. It is not validity authority: callers must
    /// discard it after the source verifier returns the proof-bound transition
    /// and must rerun the typed planner on those verified values.
    pub(crate) fn ordering_transition_hint(self) -> Result<Poseidon2V8PublicTransition, String> {
        let before_root = Poseidon2V8Root::new(
            self.statement
                .stablecoin
                .before_root
                .map(|value| value.as_canonical_u64()),
        )
        .map_err(|error| format!("V8 ordering before root rejected: {error}"))?;
        let after_root = Poseidon2V8Root::new(
            self.statement
                .stablecoin
                .after_root
                .map(|value| value.as_canonical_u64()),
        )
        .map_err(|error| format!("V8 ordering after root rejected: {error}"))?;
        Ok(
            Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
                self.statement.stablecoin.parent_height,
                before_root,
                after_root,
                poseidon2_v8_stablecoin_effect(&self.statement),
                self.note_anchor,
                self.nullifiers,
                self.commitments,
            ),
        )
    }
}

/// Build the sole canonical in-memory carrier from exact routed bytes.  Fresh
/// seven-limb nullifiers and commitments remain exclusively inside the HGV8
/// statement; only conventional 48-byte ciphertext hashes are projected into
/// legacy-width metadata fields.
pub(crate) fn pending_poseidon2_v8_action_from_inline_args(
    production: Poseidon2V8ProductionBinding,
    height: u64,
    binding: KernelVersionBinding,
    public_args: Vec<u8>,
) -> Result<PendingAction, String> {
    let decoded = decode_poseidon2_production_smz9_inline_args_exact(
        production.expected_context(),
        &public_args,
    )
    .map_err(|error| format!("V8 action contextual decode rejected: {error}"))?;
    let leaf = decoded.envelope().decoded_native_leaf();
    let mut public_values = [0u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS];
    for (index, value) in public_values.iter_mut().enumerate() {
        *value = leaf
            .statement_word(index)
            .ok_or_else(|| format!("V8 action omitted public statement word {index}"))?;
    }
    ensure_poseidon2_v8_public_words_no_transparent_value_balance(&public_values)?;
    let statement = SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&public_values)
        .map_err(|error| format!("V8 public statement rejected: {error:?}"))?;
    ensure_poseidon2_v8_no_transparent_value_balance(&statement)?;
    let mut ciphertext_hashes = Vec::with_capacity(2);
    let mut ciphertext_sizes = Vec::with_capacity(2);
    for slot in 0..2 {
        if let Some(ciphertext) = leaf.ciphertext(slot) {
            ciphertext_hashes.push(ciphertext_hash_bytes(ciphertext));
            ciphertext_sizes.push(
                u32::try_from(ciphertext.len())
                    .map_err(|_| "V8 ciphertext length exceeds u32".to_owned())?,
            );
        }
    }
    let action = PendingAction {
        tx_hash: ActionId48::ZERO,
        binding,
        family_id: FAMILY_SHIELDED_POOL,
        action_id: ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
        anchor: [0u8; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes,
        ciphertext_sizes,
        public_args,
        fee: statement.fee,
        candidate_artifact: None,
    };
    Poseidon2V8ActionView::from_pending(production, height, &action)?;
    Ok(action)
}

/// The complete release-owned V8 runtime authority after all source identity,
/// route, activation, and genesis fields have been checked together. Production
/// code can obtain this value only from the single protocol-versioning
/// capability; a transport context or boolean alone can never authorize V8.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Poseidon2V8ProductionBinding {
    connector: Poseidon2V8NativeVerifierConnector,
    activation_height: u64,
    deactivation_height_exclusive: u64,
    activation_genesis_hash: [u8; 32],
    stablecoin_genesis_root: Poseidon2V8Root,
    note_genesis_root: Poseidon2V8NoteRoot,
    coinbase_action_id: u16,
    max_proof_actions_per_block: usize,
}

// Retained lifecycle tests must exercise the production routing and verifier
// code while the release capability remains deliberately absent. Keep that
// authority local to the current test thread: parallel tests cannot observe
// it, a thread hop loses it and therefore fails closed, and none of this code
// is present in a production binary.
#[cfg(test)]
std::thread_local! {
    static POSEIDON2_V8_TEST_BINDING: std::cell::Cell<Option<Poseidon2V8ProductionBinding>> =
        const { std::cell::Cell::new(None) };
    static POSEIDON2_V8_TEST_COINBASE: std::cell::RefCell<Option<PendingAction>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct Poseidon2V8TestBindingGuard {
    previous: Option<Poseidon2V8ProductionBinding>,
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(test)]
impl Drop for Poseidon2V8TestBindingGuard {
    fn drop(&mut self) {
        POSEIDON2_V8_TEST_BINDING.with(|slot| slot.set(self.previous));
    }
}

#[cfg(test)]
pub(crate) fn install_poseidon2_v8_test_binding(
    binding: Poseidon2V8ProductionBinding,
) -> Poseidon2V8TestBindingGuard {
    let previous = POSEIDON2_V8_TEST_BINDING.with(|slot| {
        let previous = slot.get();
        slot.set(Some(binding));
        previous
    });
    Poseidon2V8TestBindingGuard {
        previous,
        _not_send: std::marker::PhantomData,
    }
}

#[cfg(test)]
pub(crate) struct Poseidon2V8TestCoinbaseGuard {
    previous: Option<PendingAction>,
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(test)]
impl Drop for Poseidon2V8TestCoinbaseGuard {
    fn drop(&mut self) {
        POSEIDON2_V8_TEST_COINBASE.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

#[cfg(test)]
pub(crate) fn install_poseidon2_v8_test_coinbase(
    action: PendingAction,
) -> Poseidon2V8TestCoinbaseGuard {
    assert_eq!(action.family_id, FAMILY_SHIELDED_POOL);
    assert_eq!(action.action_id, ACTION_MINT_POSEIDON2_V8_COINBASE);
    assert_eq!(
        action.binding,
        protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into()
    );
    let previous = POSEIDON2_V8_TEST_COINBASE.with(|slot| slot.borrow_mut().replace(action));
    Poseidon2V8TestCoinbaseGuard {
        previous,
        _not_send: std::marker::PhantomData,
    }
}

#[cfg(test)]
pub(crate) fn poseidon2_v8_test_coinbase() -> Option<PendingAction> {
    POSEIDON2_V8_TEST_COINBASE.with(|slot| slot.borrow().clone())
}

#[cfg(test)]
pub(crate) fn poseidon2_v8_test_binding_at(
    height: u64,
) -> Option<Poseidon2V8ProductionBinding> {
    POSEIDON2_V8_TEST_BINDING
        .with(|slot| slot.get())
        .filter(|binding| binding.active_at(height))
}

#[cfg(test)]
pub(crate) fn poseidon2_v8_test_binding_authorizes_route(
    height: u64,
    binding: protocol_kernel::types::KernelVersionBinding,
    family_id: u16,
    action_id: u16,
) -> bool {
    poseidon2_v8_test_binding_at(height).is_some_and(|production| {
        binding == protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into()
            && family_id == FAMILY_SHIELDED_POOL
            && matches!(
                action_id,
                ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE
                    | ACTION_MINT_POSEIDON2_V8_COINBASE
            )
            && action_id
                == if action_id == ACTION_MINT_POSEIDON2_V8_COINBASE {
                    production.coinbase_action_id()
                } else {
                    POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID
                }
    })
}

impl Poseidon2V8ProductionBinding {
    /// Load the release tuple for exact historical re-verification without
    /// requiring the current tip to remain inside its authoring window. Every
    /// proof-bearing block must still pass [`Self::active_at`] at its own
    /// height; this constructor is never an authoring or fresh-import gate.
    pub(crate) fn from_source_for_replay() -> Result<Option<Self>, String> {
        #[cfg(test)]
        if let Some(binding) = POSEIDON2_V8_TEST_BINDING.with(|slot| slot.get()) {
            return Ok(Some(binding));
        }
        let Some(capability) = protocol_versioning::smallwood_poseidon2_production_capability()
        else {
            return Ok(None);
        };
        Self::from_capability(capability).map(Some)
    }

    pub(crate) fn from_source_at(height: u64) -> Result<Option<Self>, String> {
        #[cfg(test)]
        if let Some(binding) = poseidon2_v8_test_binding_at(height) {
            return Ok(Some(binding));
        }
        let Some(capability) = protocol_versioning::smallwood_poseidon2_production_capability()
        else {
            return Ok(None);
        };
        let active = capability.active_at(height);
        let binding = Self::from_capability(capability)?;
        Ok(active.then_some(binding))
    }

    pub(crate) fn require_source_at(height: u64) -> Result<Self, String> {
        Self::from_source_at(height)?.ok_or_else(|| {
            "SmallWood Poseidon2 V8 production capability is absent or not active at this height"
                .to_owned()
        })
    }

    fn from_capability(
        capability: protocol_versioning::SmallwoodPoseidon2ProductionCapability,
    ) -> Result<Self, String> {
        if !capability.has_finite_lifetime() {
            return Err("production V8 capability lifetime must be finite and nonempty".to_owned());
        }
        if capability.binding()
            != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING
            || capability.network_id()
                != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID
            || capability.family_id() != POSEIDON2_PRODUCTION_TRANSPORT_FAMILY_ID
            || capability.action_id() != POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID
            || capability.coinbase_action_id() != ACTION_MINT_POSEIDON2_V8_COINBASE
            || usize::try_from(capability.max_proof_actions_per_block()).ok()
                != Some(MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK)
            || capability.backend_id() != POSEIDON2_PRODUCTION_TRANSPORT_BACKEND_ID
            || capability.proof_profile_id() != POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID
            || capability.domain_set() != POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET
        {
            return Err("production V8 capability identity/route tuple mismatch".to_owned());
        }
        if capability.activation_height() > POSEIDON2_V8_MAX_SCALAR {
            return Err("production V8 activation height exceeds relation scalar range".to_owned());
        }
        if capability.activation_height() != 1 {
            return Err(
                "production V8 root-only activation requires a fresh chain at height 1".to_owned(),
            );
        }
        if capability.activation_genesis_hash() == [0; 32] {
            return Err("production V8 activation genesis hash must be nonzero".to_owned());
        }
        let stablecoin_genesis_root = Poseidon2V8Root::new(capability.stablecoin_genesis_root())
            .map_err(|error| format!("production V8 genesis root rejected: {error}"))?;
        let note_genesis_root = Poseidon2V8NoteRoot::new(capability.note_genesis_root())
            .map_err(|error| format!("production V8 note genesis root rejected: {error}"))?;
        ensure_poseidon2_v8_supported_note_genesis_root(note_genesis_root)?;
        let connector = Poseidon2V8NativeVerifierConnector::from_production_capability(capability)?;
        Ok(Self {
            connector,
            activation_height: capability.activation_height(),
            deactivation_height_exclusive: capability.deactivation_height_exclusive(),
            activation_genesis_hash: capability.activation_genesis_hash(),
            stablecoin_genesis_root,
            note_genesis_root,
            coinbase_action_id: capability.coinbase_action_id(),
            max_proof_actions_per_block: usize::try_from(capability.max_proof_actions_per_block())
                .map_err(|_| "production V8 action budget exceeds usize".to_owned())?,
        })
    }

    pub(crate) const fn active_at(self, height: u64) -> bool {
        height >= self.activation_height && height < self.deactivation_height_exclusive
    }

    pub(crate) const fn activation_height(self) -> u64 {
        self.activation_height
    }

    pub(crate) const fn activation_genesis_hash(self) -> [u8; 32] {
        self.activation_genesis_hash
    }

    pub(crate) const fn stablecoin_genesis_root(self) -> Poseidon2V8Root {
        self.stablecoin_genesis_root
    }

    pub(crate) const fn note_genesis_root(self) -> Poseidon2V8NoteRoot {
        self.note_genesis_root
    }

    pub(crate) const fn coinbase_action_id(self) -> u16 {
        self.coinbase_action_id
    }

    pub(crate) const fn max_proof_actions_per_block(self) -> usize {
        self.max_proof_actions_per_block
    }

    pub(crate) const fn connector(self) -> Poseidon2V8NativeVerifierConnector {
        self.connector
    }

    pub(crate) const fn expected_context(self) -> Poseidon2ProductionExpectedContext {
        self.connector.expected_context()
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        network_id: u32,
        activation_height: u64,
        stablecoin_genesis_root: Poseidon2V8Root,
        note_genesis_root: Poseidon2V8NoteRoot,
    ) -> Result<Self, String> {
        ensure_poseidon2_v8_supported_note_genesis_root(note_genesis_root)?;
        Ok(Self {
            connector: Poseidon2V8NativeVerifierConnector::for_test_network(network_id)?,
            activation_height,
            deactivation_height_exclusive: u64::MAX,
            activation_genesis_hash: [0; 32],
            stablecoin_genesis_root,
            note_genesis_root,
            coinbase_action_id: ACTION_MINT_POSEIDON2_V8_COINBASE,
            max_proof_actions_per_block: MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_test_deactivation_height(mut self, height: u64) -> Self {
        self.deactivation_height_exclusive = height;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_activation_genesis_hash(mut self, hash: [u8; 32]) -> Self {
        self.activation_genesis_hash = hash;
        self
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Poseidon2V8NativeVerifierConnector {
    expected: Poseidon2ProductionExpectedContext,
}

impl Poseidon2V8NativeVerifierConnector {
    /// Construct only from the reviewed release capability and the
    /// source-owned relation digest. There is deliberately no production
    /// constructor accepting either value from a caller.
    pub(crate) fn from_production_capability(
        capability: protocol_versioning::SmallwoodPoseidon2ProductionCapability,
    ) -> Result<Self, String> {
        if capability.binding()
            != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING
        {
            return Err("production V8 capability carries the wrong binding".to_owned());
        }
        let source_factory = SmallwoodPoseidon2V8SourceRelationFactory;
        if capability.relation_digest() != *source_factory.expected_relation_digest() {
            return Err(
                "production V8 capability does not match the source-owned relation digest"
                    .to_owned(),
            );
        }
        let expected = Poseidon2ProductionExpectedContext::new(
            capability.network_id(),
            capability.relation_digest(),
        )
        .map_err(|error| format!("invalid release-owned V8 verifier context: {error}"))?;
        Ok(Self { expected })
    }

    fn for_expected_network(network_id: u32) -> Result<Self, String> {
        let source_factory = SmallwoodPoseidon2V8SourceRelationFactory;
        let relation_digest = *source_factory.expected_relation_digest();
        let expected = Poseidon2ProductionExpectedContext::new(network_id, relation_digest)
            .map_err(|error| format!("invalid source-owned V8 verifier context: {error}"))?;
        Ok(Self { expected })
    }

    pub(crate) const fn expected_context(self) -> Poseidon2ProductionExpectedContext {
        self.expected
    }

    #[cfg(test)]
    fn for_test_network(network_id: u32) -> Result<Self, String> {
        Self::for_expected_network(network_id)
    }
}

impl Poseidon2V8ExactLeafVerifier for Poseidon2V8NativeVerifierConnector {
    fn verify_exact_v8_leaf(
        &mut self,
        block: Poseidon2V8BlockContext,
        leaf_index: usize,
        exact_native_leaf: &[u8],
    ) -> Result<Poseidon2V8PublicTransition, String> {
        // Exact transport/context/ciphertext-hash checks all complete before
        // the relation is reconstructed or the proof engine is entered.
        let decoded =
            decode_poseidon2_production_smz9_native_leaf_exact(self.expected, exact_native_leaf)
                .map_err(|error| {
                    format!("V8 leaf {leaf_index} contextual decode rejected: {error}")
                })?;

        let mut public_values = [0u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS];
        for (index, value) in public_values.iter_mut().enumerate() {
            *value = decoded.statement_word(index).ok_or_else(|| {
                format!("V8 leaf {leaf_index} omitted public statement word {index}")
            })?;
        }
        let mut relation_balance_binding = [0u64; SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS];
        for (index, value) in relation_balance_binding.iter_mut().enumerate() {
            *value = decoded
                .relation_balance_binding_limb(index)
                .ok_or_else(|| {
                    format!("V8 leaf {leaf_index} omitted relation binding limb {index}")
                })?;
        }

        let public_parent_height = public_values[V8_PUBLIC_PARENT_HEIGHT];
        if public_parent_height != block.parent_height() {
            return Err(format!(
                "V8 leaf {leaf_index} parent height mismatch: block={} proof={public_parent_height}",
                block.parent_height()
            ));
        }

        let verifier_input = SmallwoodPoseidon2V8VerifierInput {
            network_id: decoded.network_id(),
            relation_digest: decoded.relation_digest(),
            public_values,
            relation_balance_binding,
        };
        ensure_poseidon2_v8_public_words_no_transparent_value_balance(
            &verifier_input.public_values,
        )
        .map_err(|error| format!("V8 leaf {leaf_index} {error}"))?;
        verify_smallwood_poseidon2_v8_candidate(&verifier_input, decoded.proof())
            .map_err(|error| format!("V8 leaf {leaf_index} SMZ9 proof rejected: {error}"))?;

        let before_root = Poseidon2V8Root::new(core::array::from_fn(|index| {
            verifier_input.public_values[V8_PUBLIC_BEFORE_ROOT.start + index]
        }))
        .map_err(|error| format!("V8 leaf {leaf_index} before root rejected: {error}"))?;
        let after_root = Poseidon2V8Root::new(core::array::from_fn(|index| {
            verifier_input.public_values[V8_PUBLIC_AFTER_ROOT.start + index]
        }))
        .map_err(|error| format!("V8 leaf {leaf_index} after root rejected: {error}"))?;

        // Do not project fresh seven-limb values through any historical 48-byte
        // type. The transaction relation owns the typed V8 statement grammar;
        // native state consumes its exact seven canonical Goldilocks limbs.
        let statement = SmallwoodPoseidon2V8PublicStatement::try_from_public_words(
            &verifier_input.public_values,
        )
        .map_err(|error| format!("V8 leaf {leaf_index} public statement rejected: {error:?}"))?;
        ensure_poseidon2_v8_no_transparent_value_balance(&statement)
            .map_err(|error| format!("V8 leaf {leaf_index} {error}"))?;
        let note_anchor = Poseidon2V8NoteRoot::new(statement.merkle_root)
            .map_err(|error| format!("V8 leaf {leaf_index} note anchor rejected: {error}"))?;
        let parse_nullifier = |slot: usize| -> Result<Option<Poseidon2V8Nullifier>, String> {
            if !statement.input_flags[slot] {
                return Ok(None);
            }
            Poseidon2V8Nullifier::new(statement.nullifiers[slot])
                .map(Some)
                .map_err(|error| format!("V8 leaf {leaf_index} nullifier {slot} rejected: {error}"))
        };
        let nullifiers = [parse_nullifier(0)?, parse_nullifier(1)?];
        let parse_commitment = |slot: usize| -> Result<Option<Poseidon2V8Commitment>, String> {
            if !statement.output_flags[slot] {
                return Ok(None);
            }
            Poseidon2V8Commitment::new(statement.commitments[slot])
                .map(Some)
                .map_err(|error| {
                    format!("V8 leaf {leaf_index} commitment {slot} rejected: {error}")
                })
        };
        let commitments = [parse_commitment(0)?, parse_commitment(1)?];

        let stablecoin_effect = poseidon2_v8_stablecoin_effect(&statement);

        Ok(
            Poseidon2V8PublicTransition::new_with_shielded_state_and_stablecoin_effect(
                public_parent_height,
                before_root,
                after_root,
                stablecoin_effect,
                note_anchor,
                nullifiers,
                commitments,
            ),
        )
    }
}

const _: [(); POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS] =
    [(); SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS];
const _: [(); POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS] =
    [(); SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::poseidon2_v8_pending::{
        plan_poseidon2_v8_pending_chain, verify_poseidon2_v8_block_order, Poseidon2V8PendingAction,
        Poseidon2V8PendingCaps,
    };
    use crate::native::poseidon2_v8_state::{
        Poseidon2V8Checkpoint, Poseidon2V8NoteTreeState, Poseidon2V8StateStore,
        Poseidon2V8UnverifiedBlock,
    };
    use codec::Decode;
    use protocol_shielded_pool::poseidon2_production_transport::{
        decode_poseidon2_production_smz9_inline_args_exact,
        encode_historical_poseidon2_v8_smz8_envelope,
        encode_historical_poseidon2_v8_smz8_inline_args,
        encode_historical_poseidon2_v8_smz8_native_leaf, encode_poseidon2_production_smz9_envelope,
        encode_poseidon2_production_smz9_inline_args, encode_poseidon2_production_smz9_native_leaf,
        ensure_poseidon2_production_smz9_stage_bytes, Poseidon2ProductionTransportError,
        Poseidon2ProductionTransportStage, POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES,
    };
    use protocol_shielded_pool::poseidon2_v8_coinbase::MintPoseidon2V8CoinbaseArgs;
    use protocol_shielded_pool::poseidon2_v8_retained_vectors::{
        RETAINED_V8_COINBASE_0_SCALE, RETAINED_V8_COINBASE_0_SHA512, RETAINED_V8_COINBASE_1_SCALE,
        RETAINED_V8_COINBASE_1_SHA512, RETAINED_V8_STATEMENT_SHA512, RETAINED_V8_WITNESS_SHA512,
    };
    use sha2::{Digest, Sha512};
    use std::path::{Component, Path, PathBuf};
    use transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_two_note_frontier;
    use transaction_circuit::smallwood_poseidon2_v8_program::{
        SMALLWOOD_POSEIDON2_V8_ACTION_ID, SMALLWOOD_POSEIDON2_V8_BACKEND_ID,
        SMALLWOOD_POSEIDON2_V8_CIRCUIT_VERSION, SMALLWOOD_POSEIDON2_V8_CRYPTO_SUITE,
        SMALLWOOD_POSEIDON2_V8_DOMAIN_SET, SMALLWOOD_POSEIDON2_V8_FAMILY_ID,
        SMALLWOOD_POSEIDON2_V8_INNER_MAGIC, SMALLWOOD_POSEIDON2_V8_PROFILE_ID,
        SMALLWOOD_POSEIDON2_V8_PROGRAM_MAGIC, SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512,
        SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES,
    };
    use transaction_circuit::smallwood_poseidon2_v8_types::{
        smallwood_poseidon2_v8_ciphertext_commitment, SmallwoodPoseidon2V8PublicStatement,
    };

    const TEST_HEIGHT: u64 = 1;
    const TRANSPORT_PROFILE_OFFSET: usize = 19;
    const RETAINED_SMZ9_MANIFEST_PATH: &str =
        ".agent/artifacts/smallwood-poseidon2-v8/retained-artifact-manifest.json";
    const RETAINED_SMZ9_ARTIFACT_PARENT: &str = ".agent/artifacts/smallwood-poseidon2-v8";
    const RETAINED_SMZ9_CANDIDATE_MANIFEST_PREFIX: &str = "retained-artifact-manifest.candidate";
    const RETAINED_SMZ9_TEST_MANIFEST_ENV: &str = "HEGEMON_TEST_RETAINED_SMZ9_MANIFEST_PATH";
    const RETAINED_SMZ9_MANIFEST_SCHEMA: &str =
        "hegemon-smallwood-poseidon2-v8-retained-manifest-v2";
    const RETAINED_SMZ9_ARTIFACT_SCHEMA: &str =
        "hegemon-smallwood-poseidon2-v8-retained-artifact-v5";
    const RETAINED_SMZ9_SOURCE_INVENTORY_SCHEMA: &str =
        "hegemon-smallwood-poseidon2-v8-release-source-inventory-v2";
    const RETAINED_SMZ9_PRIMARY_ROLE: &str = "retained_proof_primary";
    const RETAINED_SMZ9_INDEPENDENT_ROLE: &str = "retained_proof_independent";

    #[derive(Clone, Debug)]
    struct RetainedFilePin {
        bytes: usize,
        sha512: String,
    }

    #[derive(Clone, Debug)]
    struct RetainedSmz9Pin {
        role: String,
        directory: PathBuf,
        artifact_report: RetainedFilePin,
        proof: RetainedFilePin,
        native_leaf: RetainedFilePin,
        envelope: RetainedFilePin,
        inline_args: RetainedFilePin,
        pending_action: RetainedFilePin,
        public_statement: RetainedFilePin,
        wire_salt_hex: String,
        decs_transcript_root_hex: String,
    }

    struct RetainedSmz9Manifest {
        source_inventory: RetainedSourceInventoryPin,
        primary: RetainedSmz9Pin,
        independent: RetainedSmz9Pin,
    }

    fn block(parent_height: u64) -> Poseidon2V8BlockContext {
        Poseidon2V8BlockContext::new(parent_height, [0x11; 32], parent_height + 1, [0x22; 32])
            .unwrap()
    }

    fn exact_leaf(
        connector: Poseidon2V8NativeVerifierConnector,
    ) -> Result<Vec<u8>, Poseidon2ProductionTransportError> {
        let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
        statement.stablecoin.parent_height = 0;
        let public_values = statement.to_public_words();
        let relation_balance_binding = statement.expected_action_intent().unwrap();
        let mut proof = vec![0xa5; 64];
        proof[..4].copy_from_slice(b"SMZ9");
        encode_poseidon2_production_smz9_native_leaf(
            connector.expected_context(),
            &public_values,
            &relation_balance_binding,
            [None, None],
            &proof,
        )
    }

    fn test_production(network_id: u32) -> Poseidon2V8ProductionBinding {
        Poseidon2V8ProductionBinding::for_test(
            network_id,
            TEST_HEIGHT,
            Poseidon2V8Root::new([0; 7]).unwrap(),
            Poseidon2V8NoteRoot::new(
                protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NOTE_GENESIS_ROOT,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn retained_production_binding_obeys_exclusive_deactivation_height() {
        let mut production =
            test_production(protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID);
        production.activation_height = 10;
        production.deactivation_height_exclusive = 13;

        for height in [10, 11, 12] {
            assert!(production.active_at(height));
        }
        for height in [0, 9, 13, u64::MAX] {
            assert!(!production.active_at(height));
        }
    }

    #[test]
    fn test_binding_rejects_an_unsupported_note_genesis_root() {
        let unsupported = Poseidon2V8NoteRoot::new([1, 2, 3, 4, 5, 6, 7]).unwrap();
        let error = Poseidon2V8ProductionBinding::for_test(
            protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID,
            TEST_HEIGHT,
            Poseidon2V8Root::new([0; 7]).unwrap(),
            unsupported,
        )
        .expect_err("root-only activation must not synthesize a nonempty note frontier");
        assert!(error.contains("canonical empty tree root"));
    }

    struct RetainedSmz9Artifact {
        proof: Vec<u8>,
        native_leaf: Vec<u8>,
        envelope: Vec<u8>,
        inline_args: Vec<u8>,
        pending_action_bytes: Vec<u8>,
        pending_action: PendingAction,
        statement: SmallwoodPoseidon2V8PublicStatement,
        witness_definition_sha512: String,
        input_merkle_path_sha512: Vec<String>,
        wire_salt_hex: String,
        decs_transcript_root_hex: String,
    }

    #[derive(Clone, Debug)]
    struct RetainedSourceInventoryPin {
        root_sha512: String,
        file_count: u64,
        total_bytes: u64,
    }

    fn sha512_hex(bytes: &[u8]) -> String {
        hex::encode(Sha512::digest(bytes))
    }

    fn assert_lower_hex(value: &str, bytes: usize, label: &str) {
        assert_eq!(value.len(), bytes * 2, "{label} has the wrong length");
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{label} is not canonical lower-case hexadecimal"
        );
    }

    fn safe_relative_path(value: &str, label: &str) -> PathBuf {
        assert!(!value.is_empty(), "{label} must not be empty");
        assert!(!value.contains('\\'), "{label} must use forward slashes");
        let path = Path::new(value);
        assert!(!path.is_absolute(), "{label} must be workspace-relative");
        let parts = path
            .components()
            .map(|component| {
                let Component::Normal(part) = component else {
                    panic!("{label} contains a non-canonical or traversing component");
                };
                part.to_str()
                    .unwrap_or_else(|| panic!("{label} is not UTF-8"))
            })
            .collect::<Vec<_>>();
        assert_eq!(parts.join("/"), value, "{label} is not canonical");
        path.to_path_buf()
    }

    fn read_regular_file(path: &Path, label: &str) -> Vec<u8> {
        let metadata = std::fs::symlink_metadata(path).unwrap_or_else(|error| {
            panic!("read metadata for {label} at {}: {error}", path.display())
        });
        assert!(metadata.is_file(), "{label} is not a regular file");
        assert!(
            !metadata.file_type().is_symlink(),
            "{label} must not be a symlink"
        );
        std::fs::read(path)
            .unwrap_or_else(|error| panic!("read {label} from {}: {error}", path.display()))
    }

    fn ensure_no_symlink_path(base: &Path, relative: &Path, label: &str) {
        let mut cursor = base.to_path_buf();
        for component in relative.components() {
            let Component::Normal(component) = component else {
                panic!("{label} contains a non-canonical path component");
            };
            cursor.push(component);
            let metadata = std::fs::symlink_metadata(&cursor).unwrap_or_else(|error| {
                panic!(
                    "read {label} path metadata at {}: {error}",
                    cursor.display()
                )
            });
            assert!(
                !metadata.file_type().is_symlink(),
                "{label} path contains symlink {}",
                cursor.display()
            );
        }
    }

    fn retained_smz9_manifest_relative_path(candidate_override: Option<&str>) -> PathBuf {
        let Some(candidate) = candidate_override else {
            return safe_relative_path(
                RETAINED_SMZ9_MANIFEST_PATH,
                "canonical retained SMZ9 manifest path",
            );
        };
        assert!(
            protocol_versioning::smallwood_poseidon2_production_capability().is_none(),
            "test-only retained candidate selection cannot bypass production capability"
        );
        let relative = safe_relative_path(candidate, "test-only retained candidate manifest path");
        assert_ne!(
            relative,
            Path::new(RETAINED_SMZ9_MANIFEST_PATH),
            "test-only retained candidate override must not alias the fixed production pointer"
        );
        assert_eq!(
            relative.parent(),
            Some(Path::new(RETAINED_SMZ9_ARTIFACT_PARENT)),
            "test-only retained candidate manifest must be a direct child of the retained artifact parent"
        );
        let file_name = relative
            .file_name()
            .and_then(|name| name.to_str())
            .expect("test-only retained candidate manifest has a UTF-8 file name");
        assert!(
            file_name.starts_with(RETAINED_SMZ9_CANDIDATE_MANIFEST_PREFIX)
                && file_name.ends_with(".json"),
            "test-only retained candidate manifest must have an explicit candidate JSON name"
        );
        relative
    }

    fn resolve_retained_smz9_manifest_path(
        workspace_root: &Path,
        candidate_override: Option<&str>,
    ) -> PathBuf {
        let relative = retained_smz9_manifest_relative_path(candidate_override);
        ensure_no_symlink_path(
            workspace_root,
            &relative,
            if candidate_override.is_some() {
                "test-only retained candidate manifest"
            } else {
                "canonical retained SMZ9 manifest"
            },
        );
        let manifest_path = workspace_root.join(&relative);
        let workspace_canonical = std::fs::canonicalize(workspace_root)
            .expect("canonicalize retained artifact workspace root");
        assert_eq!(
            std::fs::canonicalize(&manifest_path).expect("canonicalize retained SMZ9 manifest"),
            workspace_canonical.join(&relative),
            "retained SMZ9 manifest path escaped or aliased the canonical workspace path"
        );
        manifest_path
    }

    fn retained_smz9_test_manifest_override() -> Option<String> {
        match std::env::var(RETAINED_SMZ9_TEST_MANIFEST_ENV) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("{RETAINED_SMZ9_TEST_MANIFEST_ENV} must be canonical UTF-8")
            }
        }
    }

    #[test]
    fn retained_smz9_manifest_selector_defaults_to_exact_old_pointer() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("node crate has a workspace parent");
        assert_eq!(
            retained_smz9_manifest_relative_path(None),
            Path::new(RETAINED_SMZ9_MANIFEST_PATH)
        );
        assert_eq!(
            resolve_retained_smz9_manifest_path(workspace_root, None),
            workspace_root.join(RETAINED_SMZ9_MANIFEST_PATH)
        );
    }

    #[test]
    fn retained_smz9_manifest_selector_accepts_explicit_candidate_file() {
        let workspace = tempfile::tempdir().expect("candidate manifest workspace");
        let parent = workspace.path().join(RETAINED_SMZ9_ARTIFACT_PARENT);
        std::fs::create_dir_all(&parent).expect("candidate manifest parent");
        let candidate_relative = format!(
            "{RETAINED_SMZ9_ARTIFACT_PARENT}/{RETAINED_SMZ9_CANDIDATE_MANIFEST_PREFIX}-test.json"
        );
        let candidate = workspace.path().join(&candidate_relative);
        std::fs::write(&candidate, b"{}\n").expect("candidate manifest fixture");
        assert_eq!(
            resolve_retained_smz9_manifest_path(
                workspace.path(),
                Some(candidate_relative.as_str()),
            ),
            candidate
        );
    }

    #[test]
    #[should_panic(expected = "must be workspace-relative")]
    fn retained_smz9_manifest_selector_rejects_absolute_candidate() {
        let _ = retained_smz9_manifest_relative_path(Some(
            "/tmp/retained-artifact-manifest.candidate.json",
        ));
    }

    #[test]
    #[should_panic(expected = "traversing component")]
    fn retained_smz9_manifest_selector_rejects_candidate_traversal() {
        let _ = retained_smz9_manifest_relative_path(Some(
            ".agent/artifacts/smallwood-poseidon2-v8/../retained-artifact-manifest.candidate.json",
        ));
    }

    #[test]
    #[should_panic(expected = "is not canonical")]
    fn retained_smz9_manifest_selector_rejects_noncanonical_candidate_spelling() {
        let _ = retained_smz9_manifest_relative_path(Some(
            ".agent/artifacts//smallwood-poseidon2-v8/retained-artifact-manifest.candidate.json",
        ));
    }

    #[test]
    #[should_panic(expected = "must not alias the fixed production pointer")]
    fn retained_smz9_manifest_selector_rejects_fixed_pointer_override() {
        let _ = retained_smz9_manifest_relative_path(Some(RETAINED_SMZ9_MANIFEST_PATH));
    }

    #[test]
    #[should_panic(expected = "must be a direct child of the retained artifact parent")]
    fn retained_smz9_manifest_selector_rejects_candidate_outside_artifact_parent() {
        let _ = retained_smz9_manifest_relative_path(Some(
            ".agent/retained-artifact-manifest.candidate.json",
        ));
    }

    #[test]
    #[should_panic(expected = "must have an explicit candidate JSON name")]
    fn retained_smz9_manifest_selector_rejects_non_candidate_name() {
        let _ = retained_smz9_manifest_relative_path(Some(
            ".agent/artifacts/smallwood-poseidon2-v8/not-a-candidate.json",
        ));
    }

    #[cfg(unix)]
    #[test]
    #[should_panic(expected = "path contains symlink")]
    fn retained_smz9_manifest_selector_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().expect("candidate manifest workspace");
        let parent = workspace.path().join(RETAINED_SMZ9_ARTIFACT_PARENT);
        std::fs::create_dir_all(&parent).expect("candidate manifest parent");
        let outside = workspace.path().join("outside-candidate.json");
        std::fs::write(&outside, b"{}\n").expect("outside candidate fixture");
        let candidate_relative = format!(
            "{RETAINED_SMZ9_ARTIFACT_PARENT}/{RETAINED_SMZ9_CANDIDATE_MANIFEST_PREFIX}-symlink.json"
        );
        symlink(&outside, workspace.path().join(&candidate_relative))
            .expect("candidate manifest symlink fixture");
        let _ = resolve_retained_smz9_manifest_path(
            workspace.path(),
            Some(candidate_relative.as_str()),
        );
    }

    fn read_retained_file(directory: &Path, name: &str) -> Vec<u8> {
        read_regular_file(&directory.join(name), &format!("retained SMZ9 {name}"))
    }

    fn retained_file_pin(
        manifest: &serde_json::Value,
        directory: &str,
        name: &str,
    ) -> RetainedFilePin {
        let expected_path = format!("{directory}/{name}");
        let files = manifest["files"]
            .as_array()
            .expect("retained manifest files is an array");
        let mut matches = files.iter().filter(|entry| {
            entry["path"]
                .as_str()
                .is_some_and(|path| path == expected_path)
        });
        let entry = matches
            .next()
            .unwrap_or_else(|| panic!("retained manifest omits {expected_path}"));
        assert!(
            matches.next().is_none(),
            "retained manifest duplicates {expected_path}"
        );
        let bytes = usize::try_from(
            entry["bytes"]
                .as_u64()
                .unwrap_or_else(|| panic!("retained manifest {expected_path} bytes is not u64")),
        )
        .expect("retained file size fits usize");
        let sha512 = entry["sha512"]
            .as_str()
            .unwrap_or_else(|| panic!("retained manifest {expected_path} SHA-512 is not a string"))
            .to_owned();
        assert_lower_hex(&sha512, 64, &format!("retained {expected_path} SHA-512"));
        RetainedFilePin { bytes, sha512 }
    }

    fn retained_smz9_pin(
        manifest: &serde_json::Value,
        artifact_root: &Path,
        role: &str,
    ) -> RetainedSmz9Pin {
        let proofs = manifest["proofs"]
            .as_array()
            .expect("retained manifest proofs is an array");
        let mut matches = proofs.iter().filter(|proof| {
            proof["artifact_role"]
                .as_str()
                .is_some_and(|candidate| candidate == role)
        });
        let proof_entry = matches
            .next()
            .unwrap_or_else(|| panic!("retained manifest omits role {role}"));
        assert!(
            matches.next().is_none(),
            "retained manifest duplicates role {role}"
        );
        let directory_string = proof_entry["directory"]
            .as_str()
            .expect("retained proof directory is a string");
        let directory_relative = safe_relative_path(directory_string, "retained proof directory");
        assert_eq!(
            directory_relative.parent(),
            Some(Path::new(role)),
            "retained proof directory is not a direct child of its role"
        );
        let proof = retained_file_pin(manifest, directory_string, "proof.bin");
        assert_eq!(
            proof_entry["proof"]["bytes"].as_u64(),
            Some(u64::try_from(proof.bytes).expect("retained proof length fits u64"))
        );
        assert_eq!(
            proof_entry["proof"]["sha512"].as_str(),
            Some(proof.sha512.as_str())
        );
        let proof_directory_name = directory_relative
            .file_name()
            .and_then(|name| name.to_str())
            .expect("retained proof directory has a UTF-8 final component");
        let proof_prefix = proof
            .sha512
            .get(..24)
            .expect("retained proof SHA-512 has a 24-character prefix");
        assert_eq!(proof_directory_name, format!("smz9-{proof_prefix}"));
        let wire_salt_hex = proof_entry["wire_salt_hex"]
            .as_str()
            .expect("retained proof wire salt is a string")
            .to_owned();
        let decs_transcript_root_hex = proof_entry["decs_transcript_root_hex"]
            .as_str()
            .expect("retained proof transcript root is a string")
            .to_owned();
        assert_lower_hex(&wire_salt_hex, 32, "retained proof wire salt");
        assert_lower_hex(
            &decs_transcript_root_hex,
            64,
            "retained proof transcript root",
        );
        RetainedSmz9Pin {
            role: role.to_owned(),
            directory: artifact_root.join(&directory_relative),
            artifact_report: retained_file_pin(manifest, directory_string, "artifact-report.json"),
            proof,
            native_leaf: retained_file_pin(manifest, directory_string, "native-leaf.bin"),
            envelope: retained_file_pin(manifest, directory_string, "rpc-envelope.bin"),
            inline_args: retained_file_pin(manifest, directory_string, "scale-inline-args.bin"),
            pending_action: retained_file_pin(manifest, directory_string, "pending-action.bin"),
            public_statement: retained_file_pin(manifest, directory_string, "public-statement.bin"),
            wire_salt_hex,
            decs_transcript_root_hex,
        }
    }

    fn load_retained_smz9_manifest(
        expected: Poseidon2ProductionExpectedContext,
        candidate_override: Option<&str>,
    ) -> RetainedSmz9Manifest {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("node crate has a workspace parent");
        let manifest_path = resolve_retained_smz9_manifest_path(workspace_root, candidate_override);
        let manifest_relative = manifest_path
            .strip_prefix(workspace_root)
            .expect("retained manifest remains workspace-relative")
            .to_path_buf();
        let workspace_canonical = std::fs::canonicalize(workspace_root)
            .expect("canonicalize retained artifact workspace root");
        assert_eq!(
            std::fs::canonicalize(&manifest_path)
                .expect("canonicalize canonical retained SMZ9 manifest"),
            workspace_canonical.join(&manifest_relative),
            "canonical retained SMZ9 manifest path mismatch"
        );
        let manifest_bytes = read_regular_file(&manifest_path, "canonical retained SMZ9 manifest");
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
            .expect("canonical retained SMZ9 manifest is exact JSON");
        assert_eq!(
            manifest["schema"].as_str(),
            Some(RETAINED_SMZ9_MANIFEST_SCHEMA)
        );
        assert_eq!(
            manifest["identity"]["relation_magic"].as_str(),
            Some(std::str::from_utf8(&SMALLWOOD_POSEIDON2_V8_PROGRAM_MAGIC).unwrap())
        );
        assert_eq!(
            manifest["identity"]["semantic_relation"].as_str(),
            Some(transaction_circuit::smallwood_poseidon2_v8_relation::SMALLWOOD_POSEIDON2_V8_RELATION_ID)
        );
        assert_eq!(
            manifest["identity"]["inner_magic"].as_str(),
            Some(std::str::from_utf8(&SMALLWOOD_POSEIDON2_V8_INNER_MAGIC).unwrap())
        );
        assert_eq!(
            manifest["identity"]["network_id"].as_u64(),
            Some(u64::from(expected.network_id()))
        );
        assert_eq!(
            manifest["identity"]["relation_digest_hex"].as_str(),
            Some(hex::encode(expected.relation_digest()).as_str())
        );
        assert_eq!(
            manifest["identity"]["relation_program_bytes"].as_u64(),
            Some(
                u64::try_from(SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES)
                    .expect("relation program length fits u64")
            )
        );
        assert_eq!(
            manifest["identity"]["relation_program_sha512"].as_str(),
            Some(hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512).as_str())
        );
        for (field, value) in [
            (
                "circuit_version",
                u64::from(SMALLWOOD_POSEIDON2_V8_CIRCUIT_VERSION),
            ),
            (
                "crypto_suite",
                u64::from(SMALLWOOD_POSEIDON2_V8_CRYPTO_SUITE),
            ),
            ("family_id", u64::from(SMALLWOOD_POSEIDON2_V8_FAMILY_ID)),
            ("action_id", u64::from(SMALLWOOD_POSEIDON2_V8_ACTION_ID)),
            ("backend_id", u64::from(SMALLWOOD_POSEIDON2_V8_BACKEND_ID)),
            ("profile_id", u64::from(SMALLWOOD_POSEIDON2_V8_PROFILE_ID)),
            ("domain_set", u64::from(SMALLWOOD_POSEIDON2_V8_DOMAIN_SET)),
        ] {
            assert_eq!(manifest["identity"]["route"][field].as_u64(), Some(value));
        }

        let source_inventory = &manifest["source_inventory"];
        assert_eq!(
            source_inventory["schema"].as_str(),
            Some(RETAINED_SMZ9_SOURCE_INVENTORY_SCHEMA)
        );
        let source_inventory_root = source_inventory["root_sha512"]
            .as_str()
            .expect("retained source inventory root is a string")
            .to_owned();
        assert_lower_hex(&source_inventory_root, 64, "retained source inventory root");
        assert!(
            source_inventory_root.bytes().any(|byte| byte != b'0'),
            "retained source inventory root must be nonzero"
        );
        let source_inventory_pin = RetainedSourceInventoryPin {
            root_sha512: source_inventory_root.clone(),
            file_count: source_inventory["file_count"]
                .as_u64()
                .expect("retained source inventory file count is u64"),
            total_bytes: source_inventory["total_bytes"]
                .as_u64()
                .expect("retained source inventory total bytes is u64"),
        };
        assert!(source_inventory_pin.file_count > 0);
        assert!(source_inventory_pin.total_bytes > 0);

        let authority = &manifest["authority"];
        assert_eq!(
            authority["artifact_is_release_authority"].as_bool(),
            Some(false)
        );
        assert_eq!(
            authority["production_capability_enabled"].as_bool(),
            Some(false)
        );
        for field in [
            "authenticated_review_roots",
            "hermetic_release_authority_roots",
            "successor_registry_ids",
        ] {
            assert!(
                authority[field]
                    .as_array()
                    .expect("retained authority field is an array")
                    .is_empty(),
                "retained authority field {field} must remain empty"
            );
        }

        let artifact_root_string = manifest["artifact_root"]
            .as_str()
            .expect("retained artifact root is a string");
        let artifact_root_relative =
            safe_relative_path(artifact_root_string, "retained artifact root");
        assert_eq!(
            artifact_root_relative.parent(),
            Some(Path::new(".agent/artifacts/smallwood-poseidon2-v8"))
        );
        let expected_root_name = format!("hgv8rp03-{}", &source_inventory_root[..16]);
        assert_eq!(
            artifact_root_relative
                .file_name()
                .and_then(|name| name.to_str()),
            Some(expected_root_name.as_str())
        );
        ensure_no_symlink_path(
            workspace_root,
            &artifact_root_relative,
            "retained artifact root",
        );
        let artifact_root = workspace_root.join(&artifact_root_relative);
        assert_eq!(
            std::fs::canonicalize(&artifact_root).expect("canonicalize retained artifact root"),
            workspace_canonical.join(&artifact_root_relative),
            "retained artifact root canonical path mismatch"
        );

        let files = manifest["files"]
            .as_array()
            .expect("retained manifest files is an array");
        assert_eq!(
            manifest["payload_file_count"].as_u64(),
            Some(u64::try_from(files.len()).expect("payload file count fits u64"))
        );
        let mut seen_paths = std::collections::BTreeSet::new();
        let mut total_bytes = 0u64;
        for entry in files {
            let path = entry["path"]
                .as_str()
                .expect("retained file path is a string");
            let relative = safe_relative_path(path, "retained payload file");
            assert!(
                seen_paths.insert(relative.clone()),
                "duplicate retained file path"
            );
            ensure_no_symlink_path(&artifact_root, &relative, "retained payload file");
            let bytes = entry["bytes"]
                .as_u64()
                .expect("retained payload file size is u64");
            total_bytes = total_bytes
                .checked_add(bytes)
                .expect("retained payload total fits u64");
            let expected_sha512 = entry["sha512"]
                .as_str()
                .expect("retained payload SHA-512 is a string");
            assert_lower_hex(expected_sha512, 64, "retained payload SHA-512");
            assert!(entry["executable"].as_bool().is_some());
            let payload = read_regular_file(
                &artifact_root.join(&relative),
                &format!("retained payload {path}"),
            );
            assert_eq!(
                u64::try_from(payload.len()).expect("payload length fits u64"),
                bytes,
                "retained payload {path} length"
            );
            assert_eq!(
                sha512_hex(&payload),
                expected_sha512,
                "retained payload {path} SHA-512"
            );
        }
        assert_eq!(manifest["payload_total_bytes"].as_u64(), Some(total_bytes));
        assert_lower_hex(
            manifest["payload_inventory_sha512"]
                .as_str()
                .expect("retained payload inventory SHA-512 is a string"),
            64,
            "retained payload inventory SHA-512",
        );
        let proofs = manifest["proofs"]
            .as_array()
            .expect("retained manifest proofs is an array");
        assert_eq!(proofs.len(), 2);
        let primary = retained_smz9_pin(&manifest, &artifact_root, RETAINED_SMZ9_PRIMARY_ROLE);
        let independent =
            retained_smz9_pin(&manifest, &artifact_root, RETAINED_SMZ9_INDEPENDENT_ROLE);
        RetainedSmz9Manifest {
            source_inventory: source_inventory_pin,
            primary,
            independent,
        }
    }

    fn load_retained_smz9_artifact(
        pin: &RetainedSmz9Pin,
        source_inventory: &RetainedSourceInventoryPin,
        expected: Poseidon2ProductionExpectedContext,
    ) -> RetainedSmz9Artifact {
        let directory = pin.directory.as_path();
        let report_bytes = read_retained_file(directory, "artifact-report.json");
        assert_eq!(report_bytes.len(), pin.artifact_report.bytes);
        assert_eq!(sha512_hex(&report_bytes), pin.artifact_report.sha512);
        let manifest: serde_json::Value = serde_json::from_slice(&report_bytes)
            .expect("retained RP03 artifact report is exact JSON");
        assert_eq!(
            manifest["schema"].as_str(),
            Some(RETAINED_SMZ9_ARTIFACT_SCHEMA)
        );
        assert_eq!(manifest["artifact_role"].as_str(), Some(pin.role.as_str()));
        assert_eq!(
            manifest["identity"]["relation_program"]["magic"].as_str(),
            Some(std::str::from_utf8(&SMALLWOOD_POSEIDON2_V8_PROGRAM_MAGIC).unwrap())
        );
        assert_eq!(
            manifest["identity"]["semantic_relation"].as_str(),
            Some(transaction_circuit::smallwood_poseidon2_v8_relation::SMALLWOOD_POSEIDON2_V8_RELATION_ID)
        );
        assert_eq!(
            manifest["identity"]["relation_digest_hex"].as_str(),
            Some(hex::encode(expected.relation_digest()).as_str())
        );
        assert_eq!(
            manifest["identity"]["relation_program"]["bytes"].as_u64(),
            Some(
                u64::try_from(SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES)
                    .expect("relation program length fits u64")
            )
        );
        assert_eq!(
            manifest["identity"]["relation_program"]["sha512"].as_str(),
            Some(hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512).as_str())
        );
        assert_eq!(
            manifest["proof_source_inventory"]["schema"].as_str(),
            Some(RETAINED_SMZ9_SOURCE_INVENTORY_SCHEMA)
        );
        assert_eq!(
            manifest["proof_source_inventory"]["root_sha512"].as_str(),
            Some(source_inventory.root_sha512.as_str())
        );
        assert_eq!(
            manifest["proof_source_inventory"]["file_count"].as_u64(),
            Some(source_inventory.file_count)
        );
        assert_eq!(
            manifest["proof_source_inventory"]["total_bytes"].as_u64(),
            Some(source_inventory.total_bytes)
        );

        let proof = read_retained_file(directory, "proof.bin");
        let native_leaf = read_retained_file(directory, "native-leaf.bin");
        let envelope = read_retained_file(directory, "rpc-envelope.bin");
        let inline_args = read_retained_file(directory, "scale-inline-args.bin");
        let pending_action_bytes = read_retained_file(directory, "pending-action.bin");
        let statement_bytes = read_retained_file(directory, "public-statement.bin");
        for (label, bytes, file_pin) in [
            ("proof", proof.as_slice(), &pin.proof),
            ("native leaf", native_leaf.as_slice(), &pin.native_leaf),
            ("RPC envelope", envelope.as_slice(), &pin.envelope),
            ("inline arguments", inline_args.as_slice(), &pin.inline_args),
            (
                "pending action",
                pending_action_bytes.as_slice(),
                &pin.pending_action,
            ),
            (
                "public statement",
                statement_bytes.as_slice(),
                &pin.public_statement,
            ),
        ] {
            assert_eq!(bytes.len(), file_pin.bytes, "retained {label} length");
            assert_eq!(
                sha512_hex(bytes),
                file_pin.sha512,
                "retained {label} SHA-512"
            );
        }
        for (field, file_pin) in [
            ("proof", &pin.proof),
            ("native_leaf", &pin.native_leaf),
            ("rpc_envelope", &pin.envelope),
            ("scale_inline_action", &pin.inline_args),
            ("pending_action", &pin.pending_action),
            ("public_statement", &pin.public_statement),
        ] {
            assert_eq!(
                manifest["sha512"][field].as_str(),
                Some(file_pin.sha512.as_str())
            );
        }

        let decoded = decode_poseidon2_production_smz9_inline_args_exact(expected, &inline_args)
            .expect("retained RP03 inline arguments decode exactly");
        assert_eq!(decoded.raw(), inline_args);
        assert_eq!(decoded.envelope().raw(), envelope);
        assert_eq!(decoded.envelope().native_leaf(), native_leaf);
        assert_eq!(decoded.envelope().decoded_native_leaf().proof(), proof);
        let statement =
            SmallwoodPoseidon2V8PublicStatement::try_from_public_bytes(&statement_bytes)
                .expect("retained RP03 public statement decodes exactly");
        assert_eq!(
            statement.to_public_words(),
            core::array::from_fn(|index| {
                decoded
                    .envelope()
                    .decoded_native_leaf()
                    .statement_word(index)
                    .expect("retained RP03 leaf has all 120 public words")
            })
        );
        let pending_action = crate::native::decode_pending_action_v3_exact(
            &pending_action_bytes,
            "retained RP03 pending action",
        )
        .expect("retained RP03 PendingAction decodes exactly");
        assert_eq!(pending_action.encode(), pending_action_bytes);
        assert_eq!(pending_action.public_args, inline_args);
        assert_eq!(sha512_hex(&statement_bytes), RETAINED_V8_STATEMENT_SHA512);
        let witness_definition_sha512 = manifest["fixture"]
            ["synthetic_fixture_witness_definition_sha512"]
            .as_str()
            .expect("retained RP03 report has a witness-definition digest")
            .to_owned();
        assert_lower_hex(
            &witness_definition_sha512,
            64,
            "retained witness-definition SHA-512",
        );
        let input_merkle_path_sha512 = manifest["fixture"]["input_merkle_path_sha512"]
            .as_array()
            .expect("retained RP03 report has two input Merkle path digests")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("retained RP03 Merkle path digest is a string")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(input_merkle_path_sha512.len(), 2);
        for digest in &input_merkle_path_sha512 {
            assert_lower_hex(digest, 64, "retained Merkle path SHA-512");
        }
        let wire_salt_hex = manifest["proof_randomness_binding"]["wire_salt_hex"]
            .as_str()
            .expect("retained RP03 report has a wire salt")
            .to_owned();
        let decs_transcript_root_hex = manifest["proof_randomness_binding"]
            ["decs_transcript_root_hex"]
            .as_str()
            .expect("retained RP03 report has a DECS transcript root")
            .to_owned();
        assert_eq!(wire_salt_hex, pin.wire_salt_hex);
        assert_eq!(decs_transcript_root_hex, pin.decs_transcript_root_hex);
        RetainedSmz9Artifact {
            proof,
            native_leaf,
            envelope,
            inline_args,
            pending_action_bytes,
            pending_action,
            statement,
            witness_definition_sha512,
            input_merkle_path_sha512,
            wire_salt_hex,
            decs_transcript_root_hex,
        }
    }

    #[cfg(feature = "poseidon2-v8-retained-test-support")]
    fn retained_wallet_rpc_request(
        expected: Poseidon2ProductionExpectedContext,
        envelope: &[u8],
    ) -> serde_json::Value {
        wallet::node_rpc::prepare_poseidon2_smz9_submit_request_json_for_retained_test(
            expected, envelope,
        )
        .expect("actual wallet retained RPC request helper succeeds")
    }

    #[cfg(feature = "poseidon2-v8-retained-test-support")]
    fn retained_rpc_projection(
        expected: Poseidon2ProductionExpectedContext,
        envelope: &[u8],
    ) -> Vec<u8> {
        let request = crate::native::decode_submit_action_rpc_request(
            retained_wallet_rpc_request(expected, envelope),
        )
        .expect("retained wallet RPC request JSON decodes");
        crate::native::admit_native_action_request_projection(&request)
            .expect("retained wallet RPC byte projection is canonical")
    }

    fn retained_coinbase_action(
        height: u64,
        bytes: &[u8],
        expected_sha512: &str,
    ) -> (PendingAction, Poseidon2V8Commitment) {
        assert_eq!(sha512_hex(bytes), expected_sha512);
        let mut cursor = bytes;
        let args = MintPoseidon2V8CoinbaseArgs::decode(&mut cursor)
            .expect("retained V8 coinbase SCALE decodes");
        assert!(cursor.is_empty());
        assert_eq!(args.encode(), bytes);
        assert_eq!(
            args.miner_note.opening.value,
            consensus::reward::block_subsidy(height)
        );
        let (_, metadata) =
            crate::native::coinbase_ciphertext_metadata(&args.miner_note.encrypted_note);
        let (ciphertext_hash, ciphertext_size) =
            metadata.expect("retained V8 coinbase has canonical ciphertext metadata");
        let mut action = PendingAction {
            tx_hash: ActionId48::ZERO,
            binding: protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
            family_id: FAMILY_SHIELDED_POOL,
            action_id: ACTION_MINT_POSEIDON2_V8_COINBASE,
            anchor: [0; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: vec![ciphertext_hash],
            ciphertext_sizes: vec![ciphertext_size],
            public_args: bytes.to_vec(),
            fee: 0,
            candidate_artifact: None,
        };
        action.tx_hash = crate::native::pending_action_hash(&action);
        crate::native::validate_coinbase_action_payload(&action)
            .expect("retained action 11 payload is exact");
        assert_eq!(
            crate::native::coinbase_action_amount(&action).unwrap(),
            consensus::reward::block_subsidy(height)
        );
        let commitment = crate::native::admitted_poseidon2_v8_coinbase_commitment(&action)
            .expect("retained action 11 commitment is source-derived");
        (action, commitment)
    }

    #[cfg(feature = "poseidon2-v8-retained-test-support")]
    fn retained_native_config(path: &Path, name: &str) -> crate::native::NativeConfig {
        crate::native::NativeConfig {
            dev: true,
            tmp: false,
            base_path: path.to_path_buf(),
            db_path: path.join("native-chain.sled"),
            rpc_addr: "127.0.0.1:0".parse().expect("retained RPC address"),
            p2p_listen_addr: "127.0.0.1:0".to_owned(),
            node_name: name.to_owned(),
            rpc_methods: "unsafe".to_owned(),
            rpc_external: false,
            rpc_cors: None,
            seeds: Vec::new(),
            max_peers: 0,
            mine: false,
            mine_threads: 1,
            bootstrap_mining_authoring: false,
            miner_address: None,
            pow_bits: 0x207f_ffff,
        }
    }

    #[cfg(feature = "poseidon2-v8-retained-test-support")]
    fn mine_exact_pending_fixture(
        node: &crate::native::NativeNode,
        action: &PendingAction,
    ) -> crate::native::NativeBlockMeta {
        let _coinbase = install_poseidon2_v8_test_coinbase(action.clone());
        mine_current_retained_template(node, &[action.encode()])
    }

    #[cfg(feature = "poseidon2-v8-retained-test-support")]
    fn mine_current_retained_template(
        node: &crate::native::NativeNode,
        expected_action_bytes: &[Vec<u8>],
    ) -> crate::native::NativeBlockMeta {
        let work = node.prepare_work().expect("prepare retained native work");
        let prepared = work
            .prepared_actions
            .as_deref()
            .expect("retained work carries exact prepared actions");
        assert_eq!(
            prepared.iter().map(Encode::encode).collect::<Vec<_>>(),
            expected_action_bytes
        );
        let seal = crate::native::mine_native_round(work.clone(), 0)
            .expect("mine retained native work");
        let block = node
            .import_mined_block(&work, seal)
            .expect("import retained mined block")
            .expect("retained mined work advances the tip");
        assert_eq!(block.action_bytes, expected_action_bytes);
        block
    }

    #[cfg(feature = "poseidon2-v8-retained-test-support")]
    fn import_exact_retained_blocks(
        node: &crate::native::NativeNode,
        blocks: &[crate::native::NativeBlockMeta],
    ) {
        for block in blocks {
            node.import_announced_block(block.clone())
                .unwrap_or_else(|error| {
                    panic!(
                        "import retained announced block {} at height {}: {error}",
                        hex::encode(block.hash),
                        block.height,
                    )
                });
            let stored = node
                .header_by_hash(&block.hash)
                .expect("load retained imported header")
                .expect("retained imported block remains addressable");
            assert_eq!(stored.action_bytes, block.action_bytes);
        }
    }

    fn retained_block_context(
        parent: Poseidon2V8Checkpoint,
        block_hash: [u8; 32],
    ) -> Poseidon2V8BlockContext {
        Poseidon2V8BlockContext::new(
            parent.height(),
            parent.block_hash(),
            parent.height() + 1,
            block_hash,
        )
        .expect("retained V8 block context is contiguous")
    }

    fn assert_retained_transport_stages(
        production: Poseidon2V8ProductionBinding,
        artifact: &RetainedSmz9Artifact,
    ) {
        for stage in [
            Poseidon2ProductionTransportStage::Wallet,
            Poseidon2ProductionTransportStage::Rpc,
            Poseidon2ProductionTransportStage::Relay,
            Poseidon2ProductionTransportStage::Mempool,
            Poseidon2ProductionTransportStage::Mining,
            Poseidon2ProductionTransportStage::Block,
            Poseidon2ProductionTransportStage::Restart,
            Poseidon2ProductionTransportStage::Sync,
            Poseidon2ProductionTransportStage::Reorg,
            Poseidon2ProductionTransportStage::FreshNodeVerify,
        ] {
            ensure_poseidon2_production_smz9_stage_bytes(
                production.expected_context(),
                &artifact.envelope,
                &artifact.inline_args,
                stage,
            )
            .unwrap_or_else(|error| {
                panic!("retained RP03 {} bytes changed: {error}", stage.label())
            });
        }
    }

    struct ExactRetainedLeafVerifier {
        connector: Poseidon2V8NativeVerifierConnector,
        expected_native_leaf: Vec<u8>,
        verified_calls: usize,
    }

    impl ExactRetainedLeafVerifier {
        fn new(production: Poseidon2V8ProductionBinding, expected_native_leaf: &[u8]) -> Self {
            Self {
                connector: production.connector(),
                expected_native_leaf: expected_native_leaf.to_vec(),
                verified_calls: 0,
            }
        }
    }

    impl Poseidon2V8ExactLeafVerifier for ExactRetainedLeafVerifier {
        fn verify_exact_v8_leaf(
            &mut self,
            block: Poseidon2V8BlockContext,
            leaf_index: usize,
            exact_native_leaf: &[u8],
        ) -> Result<Poseidon2V8PublicTransition, String> {
            if exact_native_leaf != self.expected_native_leaf.as_slice() {
                return Err(format!(
                    "retained native leaf changed before source verification at height {} index {leaf_index}",
                    block.height()
                ));
            }
            self.verified_calls = self
                .verified_calls
                .checked_add(1)
                .ok_or_else(|| "retained verifier call count overflow".to_owned())?;
            self.connector
                .verify_exact_v8_leaf(block, leaf_index, exact_native_leaf)
        }
    }

    #[test]
    #[cfg(feature = "poseidon2-v8-retained-test-support")]
    #[ignore = "verifies both retained RP03 proofs and their exact positive-value native lifecycle; optional test-only manifest is selected by HEGEMON_TEST_RETAINED_SMZ9_MANIFEST_PATH"]
    fn retained_rp03_two_coinbase_chain_survives_rpc_relay_mining_restart_reorg_and_fresh_sync() {
        assert!(protocol_versioning::smallwood_poseidon2_production_capability().is_none());
        let production =
            test_production(protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID)
                .with_test_activation_genesis_hash(
                    crate::native::genesis_meta(0x207f_ffff)
                        .expect("retained native genesis")
                        .hash,
                );
        let _test_binding = install_poseidon2_v8_test_binding(production);
        let manifest_override = retained_smz9_test_manifest_override();
        let retained_manifest = load_retained_smz9_manifest(
            production.expected_context(),
            manifest_override.as_deref(),
        );
        let primary = load_retained_smz9_artifact(
            &retained_manifest.primary,
            &retained_manifest.source_inventory,
            production.expected_context(),
        );
        let independent = load_retained_smz9_artifact(
            &retained_manifest.independent,
            &retained_manifest.source_inventory,
            production.expected_context(),
        );
        assert_ne!(primary.proof, independent.proof);
        assert_ne!(primary.native_leaf, independent.native_leaf);
        assert_ne!(
            primary.pending_action_bytes,
            independent.pending_action_bytes
        );
        assert_eq!(primary.statement, independent.statement);
        assert_eq!(
            primary.witness_definition_sha512,
            independent.witness_definition_sha512
        );
        assert_eq!(
            primary.witness_definition_sha512,
            RETAINED_V8_WITNESS_SHA512
        );
        assert_ne!(primary.wire_salt_hex, independent.wire_salt_hex);
        assert_ne!(
            primary.decs_transcript_root_hex,
            independent.decs_transcript_root_hex
        );
        assert_eq!(primary.statement.activity_mask(), 0b1111);
        assert_eq!(primary.statement.stablecoin.parent_height, 2);
        assert!(!primary.statement.value_balance_sign);
        assert_eq!(primary.statement.value_balance_magnitude, 0);
        assert_retained_transport_stages(production, &primary);
        assert_retained_transport_stages(production, &independent);

        // The actual wallet request helper exact-projects JSON into the one
        // SCALE carrier. This is an in-process RPC boundary test, not an HTTP
        // socket test.
        assert_eq!(
            retained_rpc_projection(production.expected_context(), &primary.envelope),
            primary.inline_args
        );
        assert_eq!(
            retained_rpc_projection(production.expected_context(), &independent.envelope),
            independent.inline_args
        );
        for artifact in [&primary, &independent] {
            let mut rebuilt = pending_poseidon2_v8_action_from_inline_args(
                production,
                3,
                protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
                artifact.inline_args.clone(),
            )
            .expect("test-scoped RPC binding reconstructs the retained action");
            rebuilt.tx_hash = crate::native::pending_action_hash(&rebuilt);
            assert_eq!(rebuilt.encode(), artifact.pending_action_bytes);
            assert_eq!(
                artifact.pending_action.encode(),
                artifact.pending_action_bytes
            );
            let relayed = crate::native::decode_native_peer_pending_action_v3(
                &artifact.pending_action_bytes,
                3,
            )
            .expect("test-scoped peer route exact-decodes the retained pending action");
            assert_eq!(relayed.encode(), artifact.pending_action_bytes);
            assert_eq!(relayed.public_args, artifact.inline_args);

            let mut mutated_peer_bytes = artifact.pending_action_bytes.clone();
            let mutation_index = mutated_peer_bytes
                .len()
                .checked_sub(1)
                .expect("retained pending action is nonempty");
            mutated_peer_bytes[mutation_index] ^= 1;
            assert!(crate::native::decode_native_peer_pending_action_v3(
                &mutated_peer_bytes,
                3,
            )
            .is_err());
        }

        let primary_view =
            Poseidon2V8ActionView::from_pending(production, 3, &primary.pending_action)
                .expect("primary retained action parses under the test-scoped source binding");
        let independent_view =
            Poseidon2V8ActionView::from_pending(production, 3, &independent.pending_action)
                .expect("independent retained action parses under the test-scoped source binding");
        assert_eq!(primary_view.exact_native_leaf(), primary.native_leaf);
        assert_eq!(
            independent_view.exact_native_leaf(),
            independent.native_leaf
        );
        assert_eq!(primary_view.statement(), independent_view.statement());

        let genesis =
            Poseidon2V8Checkpoint::new(0, [0x10; 32], production.stablecoin_genesis_root());
        let primary_context = Poseidon2V8BlockContext::new(2, [0x12; 32], 3, [0x13; 32])
            .expect("primary retained height-three context");
        let independent_context = Poseidon2V8BlockContext::new(2, [0x12; 32], 3, [0x23; 32])
            .expect("independent retained height-three context");
        let mut primary_connector = production.connector();
        let primary_transition = primary_connector
            .verify_exact_v8_leaf(primary_context, 0, &primary.native_leaf)
            .expect("primary retained proof passes the real source verifier");
        let mut independent_connector = production.connector();
        let independent_transition = independent_connector
            .verify_exact_v8_leaf(independent_context, 0, &independent.native_leaf)
            .expect("independent retained proof passes the real source verifier");
        assert_eq!(primary_transition, independent_transition);
        assert_eq!(primary_transition.parent_height(), 2);
        assert_eq!(
            primary_transition.stablecoin_effect(),
            Poseidon2V8StablecoinEffect::DisabledNoWrite
        );

        let (coinbase_0_action, coinbase_0) = retained_coinbase_action(
            1,
            RETAINED_V8_COINBASE_0_SCALE,
            RETAINED_V8_COINBASE_0_SHA512,
        );
        let (coinbase_1_action, coinbase_1) = retained_coinbase_action(
            2,
            RETAINED_V8_COINBASE_1_SCALE,
            RETAINED_V8_COINBASE_1_SHA512,
        );
        assert_ne!(coinbase_0_action.tx_hash, coinbase_1_action.tx_hash);
        let mut expected_two_coinbase_notes = Poseidon2V8NoteTreeState::new_empty().unwrap();
        expected_two_coinbase_notes.append(coinbase_0).unwrap();
        expected_two_coinbase_notes.append(coinbase_1).unwrap();
        let exact_frontier =
            poseidon2_v8_two_note_frontier([coinbase_0.limbs(), coinbase_1.limbs()]).unwrap();
        let exact_path_sha512 = exact_frontier.paths.map(|path| {
            let mut bytes = Vec::with_capacity(path.len() * 7 * 8);
            for sibling in path {
                for limb in sibling {
                    bytes.extend_from_slice(&limb.to_le_bytes());
                }
            }
            sha512_hex(&bytes)
        });
        assert_eq!(primary.input_merkle_path_sha512, exact_path_sha512.to_vec());
        assert_eq!(
            independent.input_merkle_path_sha512,
            exact_path_sha512.to_vec()
        );
        assert_eq!(expected_two_coinbase_notes.leaf_count(), 2);
        assert_eq!(exact_frontier.root, primary_view.note_anchor().limbs());
        assert_eq!(
            expected_two_coinbase_notes.root(),
            primary_view.note_anchor()
        );

        // Drive the retained bytes through the real native-node RPC,
        // peer/mempool, mining, block-store, restart, reorg, and fresh-import
        // paths. Only fixture insertion for the miner-local action-11 notes is
        // test-specific; user action 10 enters through the actual wallet JSON
        // request or peer PendingAction decoder.
        let live_primary_directory = tempfile::tempdir().unwrap();
        let live_primary_config = retained_native_config(
            live_primary_directory.path(),
            "retained-v8-primary",
        );
        let live_primary = crate::native::NativeNode::open(live_primary_config.clone())
            .expect("open retained primary native node");
        let coinbase_block_1 = mine_exact_pending_fixture(&live_primary, &coinbase_0_action);
        let coinbase_block_2 = mine_exact_pending_fixture(&live_primary, &coinbase_1_action);
        assert_eq!(coinbase_block_1.height, 1);
        assert_eq!(coinbase_block_2.height, 2);
        assert_eq!(coinbase_block_1.action_bytes, vec![coinbase_0_action.encode()]);
        assert_eq!(coinbase_block_2.action_bytes, vec![coinbase_1_action.encode()]);

        // A proof-body mutation is intentionally carried unchanged by the
        // wallet packager and rejected only at the source verifier boundary.
        let mut mutated_envelope = primary.envelope.clone();
        let mutated_proof_index = mutated_envelope
            .len()
            .checked_sub(1)
            .expect("retained envelope is nonempty");
        mutated_envelope[mutated_proof_index] ^= 1;
        let mutated_request = retained_wallet_rpc_request(
            production.expected_context(),
            &mutated_envelope,
        );
        let mutated_request_projection = crate::native::decode_submit_action_rpc_request(
            mutated_request.clone(),
        )
        .and_then(|request| crate::native::admit_native_action_request_projection(&request))
        .expect("wallet and RPC projections preserve an opaque proof-body mutation");
        let decoded_mutated_projection = decode_poseidon2_production_smz9_inline_args_exact(
            production.expected_context(),
            &mutated_request_projection,
        )
        .expect("mutated wallet/RPC projection remains an exact SMZ9 inline carrier");
        assert_eq!(
            decoded_mutated_projection.envelope().raw(),
            mutated_envelope.as_slice(),
            "wallet and RPC decoding must preserve every mutated envelope byte",
        );
        let mutated_rpc_error = live_primary
            .validate_and_stage_action(mutated_request)
            .expect_err("source verifier rejects the wallet-carried proof mutation");
        assert!(
            mutated_rpc_error.to_string().contains("SMZ9 proof rejected"),
            "unexpected mutated retained proof error: {mutated_rpc_error}"
        );
        assert!(live_primary.state.read().pending_actions.is_empty());

        let staged_primary = live_primary
            .validate_and_stage_action(retained_wallet_rpc_request(
                production.expected_context(),
                &primary.envelope,
            ))
            .expect("actual native RPC path stages the retained primary action");
        assert_eq!(staged_primary.encode(), primary.pending_action_bytes);
        assert_eq!(
            live_primary
                .action_tree
                .get(staged_primary.tx_hash.as_ref())
                .expect("read retained primary mempool row")
                .expect("retained primary mempool row exists")
                .as_ref(),
            primary.pending_action_bytes.as_slice(),
        );
        let primary_block_3 = mine_current_retained_template(
            &live_primary,
            std::slice::from_ref(&primary.pending_action_bytes),
        );
        assert_eq!(primary_block_3.height, 3);

        // A second node receives the exact action through the production peer
        // decoder and stages it through the relayed mempool path before mining
        // the independently randomized sibling proof.
        let independent_directory = tempfile::tempdir().unwrap();
        let independent_node = crate::native::NativeNode::open(retained_native_config(
            independent_directory.path(),
            "retained-v8-independent",
        ))
        .expect("open retained independent native node");
        import_exact_retained_blocks(
            &independent_node,
            &[coinbase_block_1.clone(), coinbase_block_2.clone()],
        );
        let independent_peer_action = crate::native::decode_native_peer_pending_action_v3(
            &independent.pending_action_bytes,
            3,
        )
        .expect("peer decoder accepts exact independent retained action");
        let relayed_independent = independent_node
            .stage_relayed_pending_action(independent_peer_action)
            .expect("relayed retained action passes proof and state preflight")
            .expect("relayed retained action is newly inserted");
        assert_eq!(
            relayed_independent.encode(),
            independent.pending_action_bytes
        );
        let independent_block_3 = mine_current_retained_template(
            &independent_node,
            std::slice::from_ref(&independent.pending_action_bytes),
        );
        let independent_block_4 = mine_current_retained_template(&independent_node, &[]);

        // Extend the stored primary branch independently so the original
        // proof can win back after the independent sibling first becomes the
        // canonical branch.
        let primary_branch_directory = tempfile::tempdir().unwrap();
        let primary_branch_node = crate::native::NativeNode::open(retained_native_config(
            primary_branch_directory.path(),
            "retained-v8-primary-branch",
        ))
        .expect("open retained primary branch node");
        import_exact_retained_blocks(
            &primary_branch_node,
            &[
                coinbase_block_1.clone(),
                coinbase_block_2.clone(),
                primary_block_3.clone(),
            ],
        );
        let primary_block_4 = mine_current_retained_template(&primary_branch_node, &[]);
        let primary_block_5 = mine_current_retained_template(&primary_branch_node, &[]);

        live_primary
            .import_announced_block(independent_block_3.clone())
            .expect("store independent retained sibling");
        live_primary
            .import_announced_block(independent_block_4.clone())
            .expect("independent retained branch wins");
        assert_eq!(live_primary.best_meta().hash, independent_block_4.hash);
        assert_eq!(
            live_primary
                .load_canonical_block_at_height_unverified(3)
                .expect("load independent canonical height three")
                .action_bytes,
            vec![independent.pending_action_bytes.clone()],
        );
        live_primary
            .import_announced_block(primary_block_4.clone())
            .expect("store extended primary sibling");
        live_primary
            .import_announced_block(primary_block_5.clone())
            .expect("longer primary branch wins back");
        assert_eq!(live_primary.best_meta().hash, primary_block_5.hash);
        assert_eq!(
            live_primary
                .load_canonical_block_at_height_unverified(3)
                .expect("load restored primary canonical height three")
                .action_bytes,
            vec![primary.pending_action_bytes.clone()],
        );

        drop(live_primary);
        let restarted_live_primary =
            crate::native::NativeNode::reopen_after_sled_release_for_test(live_primary_config)
                .expect("restart source-reverifies the retained primary branch");
        assert_eq!(restarted_live_primary.best_meta().hash, primary_block_5.hash);
        let restarted_primary_block = restarted_live_primary
            .load_canonical_block_at_height_unverified(3)
            .expect("restart reloads exact retained action body");
        assert_eq!(
            restarted_primary_block.action_bytes,
            vec![primary.pending_action_bytes.clone()]
        );
        let restarted_actions =
            crate::native::decode_block_actions(&restarted_primary_block)
                .expect("restart exact-decodes retained action body");
        let restarted_view = Poseidon2V8ActionView::from_pending(
            production,
            3,
            &restarted_actions[0],
        )
        .expect("restart reconstructs retained V8 action view");
        assert_eq!(restarted_view.exact_native_leaf(), primary.native_leaf);

        // Fresh import uses the exact persisted block bodies. A body mutation
        // is rejected against the unchanged action root before the valid block
        // is accepted and replayed.
        let fresh_live_directory = tempfile::tempdir().unwrap();
        let fresh_live = crate::native::NativeNode::open(retained_native_config(
            fresh_live_directory.path(),
            "retained-v8-fresh",
        ))
        .expect("open retained fresh native node");
        import_exact_retained_blocks(
            &fresh_live,
            &[coinbase_block_1.clone(), coinbase_block_2.clone()],
        );
        let mut mutated_primary_block = primary_block_3.clone();
        let mutated_block_byte = mutated_primary_block.action_bytes[0]
            .len()
            .checked_sub(1)
            .expect("retained block action is nonempty");
        mutated_primary_block.action_bytes[0][mutated_block_byte] ^= 1;
        let mutated_block_error = fresh_live
            .import_announced_block(mutated_primary_block)
            .expect_err("fresh import rejects retained action-body mutation");
        assert!(
            mutated_block_error.to_string().contains("action root")
                || mutated_block_error.to_string().contains("identity")
                || mutated_block_error
                    .to_string()
                    .contains("decode native block action failed"),
            "unexpected mutated block-body error: {mutated_block_error}"
        );
        import_exact_retained_blocks(
            &fresh_live,
            &[
                primary_block_3.clone(),
                primary_block_4.clone(),
                primary_block_5.clone(),
            ],
        );
        assert_eq!(fresh_live.best_meta().hash, primary_block_5.hash);
        let fresh_primary_block = fresh_live
            .load_canonical_block_at_height_unverified(3)
            .expect("fresh node reloads retained primary action body");
        assert_eq!(
            fresh_primary_block.action_bytes,
            vec![primary.pending_action_bytes.clone()]
        );

        let canonical_directory = tempfile::tempdir().unwrap();
        let database = sled::open(canonical_directory.path()).unwrap();
        let store = Poseidon2V8StateStore::open(&database, genesis, production.note_genesis_root())
            .unwrap();
        let no_leaves: [&[u8]; 0] = [];
        let block_1 = Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            retained_block_context(genesis, [0x11; 32]),
            &no_leaves,
            Some(coinbase_0),
        )
        .unwrap();
        let mut connector = production.connector();
        let tip_1 = store.apply_verified_block(block_1, &mut connector).unwrap();
        let block_2 = Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            retained_block_context(tip_1, [0x12; 32]),
            &no_leaves,
            Some(coinbase_1),
        )
        .unwrap();
        let tip_2 = store.apply_verified_block(block_2, &mut connector).unwrap();
        assert_eq!(tip_2.height(), 2);
        assert_eq!(store.note_tip().unwrap(), expected_two_coinbase_notes);
        assert_eq!(store.proof_lifetime_count().unwrap().get(), 0);

        // Exact source verification yields the sole mempool/mining transition.
        let pending = Poseidon2V8PendingAction::new(
            primary.pending_action.tx_hash,
            primary.pending_action_bytes.len(),
            primary_view.exact_native_leaf(),
            primary_transition,
        );
        let pending_plan = plan_poseidon2_v8_pending_chain(
            tip_2,
            &[pending],
            Poseidon2V8PendingCaps::native_block(),
        )
        .expect("retained RP03 action is selectable for the height-three template");
        assert_eq!(
            pending_plan.selected_action_ids(),
            &[primary.pending_action.tx_hash]
        );
        assert_eq!(
            pending_plan.selected_action_bytes(),
            primary.pending_action_bytes.len()
        );
        assert_eq!(
            verify_poseidon2_v8_block_order(tip_2, &[pending]).unwrap(),
            primary_transition.after_root()
        );

        let primary_leaves = [primary_view.exact_native_leaf()];
        let primary_block = Poseidon2V8UnverifiedBlock::new(primary_context, &primary_leaves)
            .expect("primary retained mined block is exact");
        let mut preflight_connector =
            ExactRetainedLeafVerifier::new(production, &primary.native_leaf);
        assert_eq!(
            store
                .verify_uncommitted_block(primary_block, &mut preflight_connector)
                .unwrap()
                .height(),
            3
        );
        assert_eq!(preflight_connector.verified_calls, 1);
        assert_eq!(store.tip().unwrap(), tip_2);
        let mut block_connector = ExactRetainedLeafVerifier::new(production, &primary.native_leaf);
        let primary_tip = store
            .apply_verified_block(primary_block, &mut block_connector)
            .expect("primary retained proof commits as the height-three block");
        assert_eq!(block_connector.verified_calls, 1);
        assert_eq!(primary_tip.height(), 3);
        assert_eq!(store.proof_lifetime_count().unwrap().get(), 1);
        let mut expected_spend_notes = expected_two_coinbase_notes.clone();
        for commitment in primary_view.commitments().into_iter().flatten() {
            expected_spend_notes.append(commitment).unwrap();
        }
        assert_eq!(expected_spend_notes.leaf_count(), 4);
        assert_eq!(store.note_tip().unwrap(), expected_spend_notes);
        for nullifier in primary_view.nullifiers().into_iter().flatten() {
            assert!(store.is_nullifier_spent(nullifier).unwrap());
        }
        drop(store);
        drop(database);

        // Restart reads the exact committed rows; no cached proof-validity bit
        // is used for the independent replacement or fresh-node replay below.
        let database = sled::open(canonical_directory.path()).unwrap();
        let restarted =
            Poseidon2V8StateStore::open(&database, genesis, production.note_genesis_root())
                .unwrap();
        assert_eq!(restarted.tip().unwrap(), primary_tip);
        assert_eq!(restarted.note_tip().unwrap(), expected_spend_notes);

        let independent_leaves = [independent_view.exact_native_leaf()];
        let independent_block =
            Poseidon2V8UnverifiedBlock::new(independent_context, &independent_leaves)
                .expect("independent retained replacement block is exact");
        let mut reorg_connector =
            ExactRetainedLeafVerifier::new(production, &independent.native_leaf);
        let independent_tip = restarted
            .reorganize_verified(
                &[primary_tip.block_hash()],
                &[independent_block],
                &mut reorg_connector,
            )
            .expect(
                "independent retained proof replaces the primary proof after full verification",
            );
        assert_eq!(reorg_connector.verified_calls, 1);
        assert_eq!(independent_tip.height(), 3);
        assert_ne!(independent_tip.block_hash(), primary_tip.block_hash());
        assert_eq!(restarted.proof_lifetime_count().unwrap().get(), 1);
        assert_eq!(restarted.note_tip().unwrap(), expected_spend_notes);
        for nullifier in independent_view.nullifiers().into_iter().flatten() {
            assert!(restarted.is_nullifier_spent(nullifier).unwrap());
        }

        // Extend the stored primary sibling and reorg back to it. The source
        // verifier sees the original primary native-leaf bytes again; the
        // empty child changes chain weight without changing proof lifetime.
        let no_extension_leaves: [&[u8]; 0] = [];
        let primary_extension = Poseidon2V8UnverifiedBlock::new(
            retained_block_context(primary_tip, [0x14; 32]),
            &no_extension_leaves,
        )
        .unwrap();
        let mut restore_primary_connector =
            ExactRetainedLeafVerifier::new(production, &primary.native_leaf);
        let restored_primary_tip = restarted
            .reorganize_verified(
                &[independent_tip.block_hash()],
                &[primary_block, primary_extension],
                &mut restore_primary_connector,
            )
            .expect("the extended primary branch wins after re-verifying the original bytes");
        assert_eq!(restore_primary_connector.verified_calls, 1);
        assert_eq!(restored_primary_tip.height(), 4);
        assert_eq!(restored_primary_tip.block_hash(), [0x14; 32]);
        assert_eq!(restarted.proof_lifetime_count().unwrap().get(), 1);
        assert_eq!(restarted.note_tip().unwrap(), expected_spend_notes);
        for nullifier in primary_view.nullifiers().into_iter().flatten() {
            assert!(restarted.is_nullifier_spent(nullifier).unwrap());
        }

        // Restart only after the final primary branch is canonical.
        drop(restarted);
        drop(database);
        let database = sled::open(canonical_directory.path()).unwrap();
        let restarted =
            Poseidon2V8StateStore::open(&database, genesis, production.note_genesis_root())
                .unwrap();
        assert_eq!(restarted.tip().unwrap(), restored_primary_tip);
        assert_eq!(restarted.proof_lifetime_count().unwrap().get(), 1);
        assert_eq!(restarted.note_tip().unwrap(), expected_spend_notes);

        let fresh_directory = tempfile::tempdir().unwrap();
        let fresh_database = sled::open(fresh_directory.path()).unwrap();
        let fresh =
            Poseidon2V8StateStore::open(&fresh_database, genesis, production.note_genesis_root())
                .unwrap();
        let fresh_block_1 = Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            retained_block_context(genesis, [0x11; 32]),
            &no_leaves,
            Some(coinbase_0),
        )
        .unwrap();
        let fresh_tip_1 = Poseidon2V8Checkpoint::new(1, [0x11; 32], genesis.root());
        let fresh_block_2 = Poseidon2V8UnverifiedBlock::new_with_trailing_coinbase(
            retained_block_context(fresh_tip_1, [0x12; 32]),
            &no_leaves,
            Some(coinbase_1),
        )
        .unwrap();
        let mut fresh_connector = ExactRetainedLeafVerifier::new(production, &primary.native_leaf);
        let fresh_tip = fresh
            .replay_verified_suffix(
                &[
                    fresh_block_1,
                    fresh_block_2,
                    primary_block,
                    primary_extension,
                ],
                &mut fresh_connector,
            )
            .expect("fresh node source-verifies the original primary proof bytes");
        assert_eq!(fresh_connector.verified_calls, 1);
        assert_eq!(fresh_tip, restored_primary_tip);
        assert_eq!(fresh.proof_lifetime_count().unwrap().get(), 1);
        assert_eq!(fresh.note_tip().unwrap(), restarted.note_tip().unwrap());
        assert!(restarted.exact_rows_equal(&fresh).unwrap());

        // Lifecycle evidence can only make the wire routes recognizable. The
        // shared authority decision remains fail-closed while the source
        // capability is absent.
        drop(_test_binding);
        assert!(Poseidon2V8ProductionBinding::from_source_for_replay()
            .expect("test-scoped binding teardown leaves the release source readable")
            .is_none());
        assert!(protocol_versioning::smallwood_poseidon2_production_capability().is_none());
        assert!(crate::native::ensure_native_v3_active_action_route_ids(
            FAMILY_SHIELDED_POOL,
            ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
            false,
        )
        .is_ok());
        assert!(crate::native::ensure_native_v3_active_action_route_ids(
            FAMILY_SHIELDED_POOL,
            ACTION_MINT_POSEIDON2_V8_COINBASE,
            true,
        )
        .is_ok());
        for (action_id, proof_class) in [
            (
                ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
                protocol_versioning::ProofAuthorityClass::Transaction,
            ),
            (
                ACTION_MINT_POSEIDON2_V8_COINBASE,
                protocol_versioning::ProofAuthorityClass::MintSource,
            ),
        ] {
            assert_eq!(
                protocol_kernel::manifest::kernel_manifest().proof_authority_decision(
                    protocol_versioning::ProofAuthorityOperation::Authoring,
                    protocol_versioning::HEGEMON_PROOF_NETWORK_ID,
                    1,
                    protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
                    FAMILY_SHIELDED_POOL,
                    action_id,
                    proof_class,
                    None,
                ),
                protocol_versioning::ProofAuthorityDecision::Denied,
            );
        }
    }

    fn action_fixture(
        production: Poseidon2V8ProductionBinding,
    ) -> (
        PendingAction,
        SmallwoodPoseidon2V8PublicStatement,
        [u8; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES],
    ) {
        let ciphertext = [0x41; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES];
        let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
        statement.input_flags[0] = true;
        statement.nullifiers[0] = [11, 12, 13, 14, 15, 16, 17];
        statement.output_flags[0] = true;
        statement.commitments[0] = [21, 22, 23, 24, 25, 26, 27];
        statement.ciphertext_commitments[0] =
            smallwood_poseidon2_v8_ciphertext_commitment(&ciphertext);
        statement.merkle_root = [31, 32, 33, 34, 35, 36, 37];
        statement.stablecoin.parent_height = TEST_HEIGHT - 1;
        let public_values = statement.to_public_words();
        let relation_balance_binding = statement.expected_action_intent().unwrap();
        let mut proof = vec![0xa5; 64];
        proof[..4].copy_from_slice(b"SMZ9");
        let native_leaf = encode_poseidon2_production_smz9_native_leaf(
            production.expected_context(),
            &public_values,
            &relation_balance_binding,
            [Some(&ciphertext), None],
            &proof,
        )
        .unwrap();
        let envelope =
            encode_poseidon2_production_smz9_envelope(production.expected_context(), &native_leaf)
                .unwrap();
        let inline_args =
            encode_poseidon2_production_smz9_inline_args(production.expected_context(), &envelope)
                .unwrap();
        let action = pending_poseidon2_v8_action_from_inline_args(
            production,
            TEST_HEIGHT,
            protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
            inline_args,
        )
        .unwrap();
        (action, statement, ciphertext)
    }

    #[test]
    fn connector_pins_source_digest_and_reaches_real_fail_closed_verifier() {
        let mut connector = Poseidon2V8NativeVerifierConnector::for_test_network(17).unwrap();
        let source_factory = SmallwoodPoseidon2V8SourceRelationFactory;
        assert_eq!(
            connector.expected_context().relation_digest(),
            *source_factory.expected_relation_digest()
        );
        let leaf = exact_leaf(connector).unwrap();
        let error = connector
            .verify_exact_v8_leaf(block(0), 0, &leaf)
            .expect_err("dummy SMZ9 proof must fail closed in the real verifier");
        assert!(
            error.contains("SMZ9 proof rejected"),
            "unexpected verifier error: {error}"
        );
    }

    #[test]
    fn connector_rejects_context_and_parent_before_proof_verification() {
        let connector = Poseidon2V8NativeVerifierConnector::for_test_network(17).unwrap();
        let leaf = exact_leaf(connector).unwrap();

        let mut wrong_network = Poseidon2V8NativeVerifierConnector::for_test_network(18).unwrap();
        let error = wrong_network
            .verify_exact_v8_leaf(block(0), 0, &leaf)
            .expect_err("network mismatch must reject");
        assert!(error.contains("NetworkMismatch"));

        let mut connector = connector;
        let error = connector
            .verify_exact_v8_leaf(block(1), 0, &leaf)
            .expect_err("parent mismatch must reject");
        assert!(error.contains("parent height mismatch"));
        assert!(!error.contains("proof rejected"));
    }

    #[test]
    fn action_view_preserves_exact_typed_limbs_and_rejects_legacy_state() {
        let production = test_production(17);
        let (action, statement, _) = action_fixture(production);
        let view = Poseidon2V8ActionView::from_pending(production, TEST_HEIGHT, &action).unwrap();

        assert_eq!(view.statement(), statement);
        assert_eq!(view.note_anchor().limbs(), statement.merkle_root);
        assert_eq!(
            view.nullifiers()[0].unwrap().limbs(),
            statement.nullifiers[0]
        );
        assert_eq!(view.nullifiers()[1], None);
        assert_eq!(
            view.commitments()[0].unwrap().limbs(),
            statement.commitments[0]
        );
        assert_eq!(view.commitments()[1], None);
        assert_eq!(
            view.exact_native_leaf(),
            decode_poseidon2_production_smz9_inline_args_exact(
                production.expected_context(),
                &action.public_args,
            )
            .unwrap()
            .envelope()
            .native_leaf()
        );

        let mut legacy_anchor = action.clone();
        legacy_anchor.anchor = [1; 48];
        let mut legacy_nullifier = action.clone();
        legacy_nullifier.nullifiers.push([2; 48]);
        let mut legacy_commitment = action.clone();
        legacy_commitment.commitments.push([3; 48]);
        for corrupted in [legacy_anchor, legacy_nullifier, legacy_commitment] {
            let error = Poseidon2V8ActionView::from_pending(production, TEST_HEIGHT, &corrupted)
                .expect_err("legacy 48-byte state must reject");
            assert!(error.contains("forbidden legacy 48-byte state"));
        }
    }

    #[test]
    fn value_balance_sign_and_magnitude_reject_before_pending_admission() {
        let production = test_production(17);
        for (sign, magnitude) in [(false, 1), (true, 1)] {
            let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
            statement.value_balance_sign = sign;
            statement.value_balance_magnitude = magnitude;
            let public_values = statement.to_public_words();
            let relation_balance_binding = statement.expected_action_intent().unwrap();
            let mut proof = vec![0xa5; 64];
            proof[..4].copy_from_slice(b"SMZ9");
            let native_leaf = encode_poseidon2_production_smz9_native_leaf(
                production.expected_context(),
                &public_values,
                &relation_balance_binding,
                [None, None],
                &proof,
            )
            .unwrap();
            let envelope = encode_poseidon2_production_smz9_envelope(
                production.expected_context(),
                &native_leaf,
            )
            .unwrap();
            let inline_args = encode_poseidon2_production_smz9_inline_args(
                production.expected_context(),
                &envelope,
            )
            .unwrap();
            let action = PendingAction {
                tx_hash: ActionId48::ZERO,
                binding: protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
                family_id: FAMILY_SHIELDED_POOL,
                action_id: ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
                anchor: [0; 48],
                nullifiers: Vec::new(),
                commitments: Vec::new(),
                ciphertext_hashes: Vec::new(),
                ciphertext_sizes: Vec::new(),
                public_args: inline_args.clone(),
                fee: 0,
                candidate_artifact: None,
            };

            let view_error = Poseidon2V8ActionView::from_pending(production, TEST_HEIGHT, &action)
                .expect_err("nonzero V8 value balance must reject at action projection");
            assert!(view_error.contains("value balance must be canonical zero"));
            let construction_error = pending_poseidon2_v8_action_from_inline_args(
                production,
                TEST_HEIGHT,
                protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
                inline_args,
            )
            .expect_err("nonzero V8 value balance must reject before PendingAction admission");
            assert!(
                construction_error.contains("value balance must be canonical zero")
                    || construction_error.contains("ValueOutOfRange"),
                "unexpected value-balance rejection: {construction_error}"
            );
        }
    }

    #[test]
    fn action_view_rejects_profile_magic_context_and_historical_smz8() {
        let production = test_production(17);
        let (action, statement, ciphertext) = action_fixture(production);
        let decoded = decode_poseidon2_production_smz9_inline_args_exact(
            production.expected_context(),
            &action.public_args,
        )
        .unwrap();
        let payload_offset = action.public_args.len() - decoded.envelope().raw().len();

        let mut wrong_profile = action.clone();
        wrong_profile.public_args[payload_offset + TRANSPORT_PROFILE_OFFSET] ^= 1;
        let error = Poseidon2V8ActionView::from_pending(production, TEST_HEIGHT, &wrong_profile)
            .expect_err("wrong profile must reject");
        assert!(error.contains("UnsupportedProfile"), "{error}");

        let mut wrong_magic = action.clone();
        wrong_magic.public_args[payload_offset] ^= 1;
        let error = Poseidon2V8ActionView::from_pending(production, TEST_HEIGHT, &wrong_magic)
            .expect_err("wrong magic must reject");
        assert!(error.contains("InvalidTransportMagic"));

        let other_production = test_production(18);
        let (other_action, _, _) = action_fixture(other_production);
        let error = Poseidon2V8ActionView::from_pending(production, TEST_HEIGHT, &other_action)
            .expect_err("wrong network context must reject");
        assert!(error.contains("NetworkMismatch"));

        let public_values = statement.to_public_words();
        let relation_balance_binding = statement.expected_action_intent().unwrap();
        let mut old_proof = vec![0xa5; 64];
        old_proof[..4].copy_from_slice(b"SMZ8");
        let old_leaf = encode_historical_poseidon2_v8_smz8_native_leaf(
            production.expected_context(),
            &public_values,
            &relation_balance_binding,
            [Some(&ciphertext), None],
            &old_proof,
        )
        .unwrap();
        let old_envelope =
            encode_historical_poseidon2_v8_smz8_envelope(production.expected_context(), &old_leaf)
                .unwrap();
        let mut old_action = action;
        old_action.public_args = encode_historical_poseidon2_v8_smz8_inline_args(
            production.expected_context(),
            &old_envelope,
        )
        .unwrap();
        let error = Poseidon2V8ActionView::from_pending(production, TEST_HEIGHT, &old_action)
            .expect_err("historical SMZ8 transport must reject");
        assert!(error.contains("InvalidTransportMagic"));
    }
}
