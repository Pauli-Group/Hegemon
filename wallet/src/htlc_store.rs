//! Encrypted swap records live in WalletState and share its exclusive writer lock.
use super::*;
use crate::htlc::{self, HtlcOffer};
use crate::poseidon2_v8_sync::LaunchWalletContext;
use sha2::{Digest, Sha512};
use transaction_circuit::{
    smallwood_htlc::{self, HtlcAction, HtlcStatement},
    smallwood_htlc_transport,
    smallwood_poseidon2_v8_coinbase::poseidon2_v8_note_commitment,
    smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8NoteOpening,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HtlcAttemptStatus {
    Proving,
    Ready,
    SubmissionUncertain,
    Submitted(#[serde(with = "super::serde_action_id48")] ActionId48),
    /// Kept forever: reorg into the reference window restores its reservation.
    Abandoned,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredHtlcSwap {
    pub(crate) id: [u8; 32],
    offer: HtlcOffer,
    /// Encrypted together with the wallet. Never included in the public view.
    secret: Option<[u8; 32]>,
    locked_opening: Option<[u64; 18]>,
    policy_nullifier_key: Option<[u64; 5]>,
    attempts: Vec<StoredHtlcAttempt>,
}
impl std::fmt::Debug for StoredHtlcSwap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredHtlcSwap")
            .field("attempts", &self.attempts.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct StoredHtlcAttempt {
    id: [u8; 32],
    genesis: [u8; 32],
    statement: HtlcStatement,
    input_commitment: [u64; 7],
    input_position: u64,
    status: HtlcAttemptStatus,
    exact_carrier: Vec<u8>,
    confirmed_in: Option<HtlcConfirmation>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtlcConfirmation {
    #[serde(with = "super::serde_action_id48")]
    pub action_id: ActionId48,
    pub height: u64,
    pub block_hash: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcSwapView {
    pub id: [u8; 32],
    pub offer: HtlcOffer,
    pub has_secret: bool,
    /// Exact canonical occurrences; the caller must select a position explicitly.
    pub locked_note_positions: Vec<u64>,
    pub attempts: Vec<HtlcAttemptView>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcAttemptView {
    pub id: [u8; 32],
    pub action: HtlcAction,
    pub status: HtlcAttemptStatus,
    /// Canonical consumption does not identify which competing action won.
    pub input_consumed: bool,
    pub input_reserved: bool,
    pub confirmation: Option<HtlcConfirmation>,
}

/// Private preparation snapshot available only to the wallet's source adapter.
/// No Debug, serde, or public raw-field surface may expose this material.
pub(crate) struct HtlcPrivateMaterial {
    pub(crate) offer: HtlcOffer,
    pub(crate) locked_note: SmallwoodPoseidon2V8NoteOpening,
    pub(crate) policy_nullifier_key: [u64; 5],
    pub(crate) secret: Option<[u8; 32]>,
}
impl Drop for HtlcPrivateMaterial {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.policy_nullifier_key.zeroize();
        self.secret.zeroize();
        self.locked_note.value.zeroize();
        self.locked_note.asset_id.zeroize();
        self.locked_note.recipient_key.zeroize();
        self.locked_note.authorization_key.zeroize();
        self.locked_note.rho.zeroize();
        self.locked_note.randomness.zeroize();
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtlcAttemptReadiness {
    Ready {
        actual_inclusion_height: u64,
    },
    /// Exact bytes are recoverable, but submission eligibility is unestablished.
    Unknown,
}
/// Exact public binding metadata omits any yet-unpublished claim preimage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcStatementMetadata {
    pub version: u32,
    pub action: HtlcAction,
    pub network_id: [u8; 32],
    pub parent_hash: [u8; 32],
    pub parent_height: u64,
    pub merkle_root: [u64; 7],
    pub nullifier: [u64; 7],
    pub output_commitment: [u64; 7],
    pub ciphertext_commitment: [u8; 48],
    pub fee: u64,
    pub revealed_secret_present: bool,
    pub revealed_secret_sha256: Option<[u8; 32]>,
    pub binding_sha512: [u8; 64],
}
impl HtlcStatementMetadata {
    fn from_statement(statement: &HtlcStatement) -> Result<Self, WalletError> {
        Ok(Self {
            version: statement.version,
            action: statement.action,
            network_id: statement.network_id,
            parent_hash: statement.parent_hash,
            parent_height: statement.parent_height,
            merkle_root: statement.merkle_root,
            nullifier: statement.nullifier,
            output_commitment: statement.output_commitment,
            ciphertext_commitment: statement.ciphertext_commitment,
            fee: statement.fee,
            revealed_secret_present: statement.revealed_secret.is_some(),
            revealed_secret_sha256: statement
                .revealed_secret
                .map(|secret| sha2::Sha256::digest(secret).into()),
            binding_sha512: Sha512::digest(
                statement
                    .candidate_binding_bytes()
                    .map_err(htlc::surface_error)?,
            )
            .into(),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcAttemptReview {
    pub attempt_id: [u8; 32],
    pub swap_id: [u8; 32],
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub manifest_digest: Option<[u8; 64]>,
    pub action: HtlcAction,
    pub amount: u64,
    pub fee: u64,
    pub input_nullifier: [u64; 7],
    pub input_commitment: [u64; 7],
    pub input_position: u64,
    pub output_commitment: [u64; 7],
    pub statement: HtlcStatementMetadata,
    pub carrier_sha512: [u8; 64],
    pub carrier_bytes: usize,
    pub status: HtlcAttemptStatus,
    pub confirmation: Option<HtlcConfirmation>,
    pub reference_tip: Option<Poseidon2V8CanonicalTip>,
    pub current_tip: Option<Poseidon2V8CanonicalTip>,
    pub readiness: HtlcAttemptReadiness,
}
/// A complete immutable public carrier. Private note openings and signing
/// credentials never cross this boundary; Ready ambiguity is durable first.
pub struct HtlcAttemptExport {
    review: HtlcAttemptReview,
    exact_carrier: Vec<u8>,
}
impl HtlcAttemptExport {
    pub fn review(&self) -> &HtlcAttemptReview {
        &self.review
    }
    pub fn exact_carrier(&self) -> &[u8] {
        &self.exact_carrier
    }
}

fn pinned_htlc_context(
    state: &WalletState,
    expected: Option<LaunchWalletContext>,
) -> Result<LaunchWalletContext, WalletError> {
    let pinned = state
        .native_launch_context
        .as_ref()
        .ok_or(WalletError::InvalidState(
            "HTLC launch context is not pinned",
        ))?;
    if let Some(expected) = expected {
        pinned.require_match(expected)?;
    }
    pinned.current_context()
}
fn canonical_htlc_attempt(
    state: &WalletState,
    attempt: &StoredHtlcAttempt,
    expected: Option<LaunchWalletContext>,
) -> Result<u64, WalletError> {
    let context = pinned_htlc_context(state, expected)?;
    if state.poseidon2_v8.canonical_hash(0) != Some(attempt.genesis)
        || attempt.genesis != context.genesis_hash()
        || state
            .poseidon2_v8
            .has_canonical_nullifier(attempt.statement.nullifier)
    {
        return Err(WalletError::InvalidState(
            "HTLC input is consumed or belongs to another genesis",
        ));
    }
    let reference = state
        .poseidon2_v8
        .canonical_tip_at_height(attempt.statement.parent_height)
        .ok_or(WalletError::InvalidState(
            "HTLC canonical reference unavailable",
        ))?;
    let inclusion = context.require_canonical_reference(
        &state.poseidon2_v8,
        reference,
        attempt.statement.action == HtlcAction::Lock,
    )?;
    attempt
        .statement
        .validate_context(
            context.chain_id(),
            reference.block_hash,
            reference.height,
            reference.anchor,
        )
        .map_err(htlc::surface_error)?;
    state
        .poseidon2_v8
        .canonical_note_path(attempt.input_commitment, attempt.input_position)?;
    Ok(inclusion)
}
fn ready_htlc_attempt(
    state: &WalletState,
    attempt: &StoredHtlcAttempt,
    require_authority: bool,
) -> Result<u64, WalletError> {
    let inclusion = canonical_htlc_attempt(state, attempt, None)?;
    let context = pinned_htlc_context(state, None)?;
    let carrier = smallwood_htlc_transport::decode_candidate_exact(&attempt.exact_carrier)
        .map_err(htlc::surface_error)?;
    if carrier.statement != attempt.statement {
        return Err(WalletError::InvalidState("HTLC retained carrier changed"));
    }
    if require_authority
        && protocol_versioning::launch_candidate::launch_proof_authority(context.request(
            protocol_versioning::launch_candidate::LaunchProofKind::Htlc,
            inclusion,
            carrier.proof.len(),
        ))
        .is_none()
    {
        return Err(WalletError::InvalidState(
            "HTLC has no source authority at actual inclusion",
        ));
    }
    Ok(inclusion)
}
fn htlc_review(
    state: &WalletState,
    swap: &StoredHtlcSwap,
    attempt: &StoredHtlcAttempt,
    readiness: HtlcAttemptReadiness,
) -> Result<HtlcAttemptReview, WalletError> {
    Ok(HtlcAttemptReview {
        attempt_id: attempt.id,
        swap_id: swap.id,
        chain_id: attempt.statement.network_id,
        genesis_hash: attempt.genesis,
        manifest_digest: pinned_htlc_context(state, None)
            .ok()
            .map(|context| context.manifest_digest()),
        action: attempt.statement.action,
        amount: swap.offer.value,
        fee: attempt.statement.fee,
        input_nullifier: attempt.statement.nullifier,
        input_commitment: attempt.input_commitment,
        input_position: attempt.input_position,
        output_commitment: attempt.statement.output_commitment,
        statement: HtlcStatementMetadata::from_statement(&attempt.statement)?,
        carrier_sha512: Sha512::digest(&attempt.exact_carrier).into(),
        carrier_bytes: attempt.exact_carrier.len(),
        status: attempt.status,
        confirmation: attempt.confirmed_in.filter(|receipt| {
            state.poseidon2_v8.canonical_hash(0) == Some(attempt.genesis)
                && state.poseidon2_v8.canonical_hash(receipt.height) == Some(receipt.block_hash)
                && state
                    .poseidon2_v8
                    .has_canonical_nullifier(attempt.statement.nullifier)
        }),
        reference_tip: state
            .poseidon2_v8
            .canonical_tip_at_height(attempt.statement.parent_height),
        current_tip: state.poseidon2_v8.tip().ok(),
        readiness,
    })
}
impl WalletState {
    pub(super) fn observe_htlc_actions(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        observations: &[([u8; 48], Vec<u8>)],
    ) -> Result<(), WalletError> {
        for swap in &mut self.htlc_swaps {
            for attempt in &mut swap.attempts {
                for (action_id, carrier) in observations {
                    if !attempt.exact_carrier.is_empty() && attempt.exact_carrier == *carrier {
                        if !self
                            .poseidon2_v8
                            .has_canonical_nullifier(attempt.statement.nullifier)
                        {
                            return Err(WalletError::InvalidState(
                                "HTLC confirmation has no canonical input consumption",
                            ));
                        }
                        attempt.confirmed_in = Some(HtlcConfirmation {
                            action_id: ActionId48::try_from(action_id.as_slice())
                                .map_err(htlc::surface_error)?,
                            height,
                            block_hash,
                        });
                    }
                }
            }
        }
        Ok(())
    }
    fn htlc_attempt_active(&self, attempt: &StoredHtlcAttempt) -> bool {
        // An exported old branch may reattach after a deep rollback while a
        // competing newer proof is still valid. Missing/future/orphan reference
        // metadata cannot justify clearing this replacement exclusion.
        attempt.status != HtlcAttemptStatus::Abandoned
            || self.poseidon2_v8.tip().map_or(true, |tip| {
                tip.height <= htlc::last_admissible_parent(&attempt.statement)
            })
    }
    pub(super) fn htlc_reserved_nullifiers(&self) -> HashSet<[u64; 7]> {
        self.htlc_swaps
            .iter()
            .flat_map(|swap| &swap.attempts)
            .filter(|attempt| self.htlc_attempt_active(attempt))
            .map(|attempt| attempt.statement.nullifier)
            .collect()
    }
    pub(super) fn validate_htlc_swaps(&self) -> Result<(), WalletError> {
        let mut ids = HashSet::new();
        let mut attempt_ids = HashSet::new();
        for swap in &self.htlc_swaps {
            if swap.offer.id()? != swap.id || !ids.insert(swap.id) {
                return Err(WalletError::InvalidState("invalid or duplicate HTLC offer"));
            }
            if let Some(secret) = swap.secret {
                htlc::validate_revealed_secret(&swap.offer, &secret)?;
            }
            if swap.locked_opening.is_some() != swap.policy_nullifier_key.is_some() {
                return Err(WalletError::InvalidState("incomplete HTLC private opening"));
            }
            if let (Some(words), Some(key)) = (swap.locked_opening, swap.policy_nullifier_key) {
                let note = crate::poseidon2_v8_sync::words_to_opening(words)?;
                if note.value != swap.offer.value
                    || note.asset_id != 0
                    || smallwood_htlc::bind_locked_note(note, swap.offer.policy(), key)
                        .map_err(htlc::surface_error)?
                        != note
                {
                    return Err(WalletError::InvalidState(
                        "HTLC opening differs from policy",
                    ));
                }
            }
            for attempt in &swap.attempts {
                if attempt.id == [0; 32]
                    || attempt.genesis == [0; 32]
                    || !attempt_ids.insert(attempt.id)
                {
                    return Err(WalletError::InvalidState("invalid HTLC attempt identity"));
                }
                htlc::validate_offer_statement(&swap.offer, &attempt.statement)?;
                if attempt.status != HtlcAttemptStatus::Proving {
                    let carrier =
                        smallwood_htlc_transport::decode_wallet_exact(&attempt.exact_carrier)
                            .map_err(htlc::surface_error)?;
                    if carrier.statement != attempt.statement {
                        return Err(WalletError::InvalidState("stored HTLC carrier mismatch"));
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) fn recover_htlc_proving(&mut self) -> bool {
        let mut changed = false;
        for swap in &mut self.htlc_swaps {
            swap.attempts.retain(|attempt| {
                let retain = attempt.status != HtlcAttemptStatus::Proving;
                changed |= !retain;
                retain
            });
        }
        changed
    }
}

impl WalletStore {
    pub(crate) fn htlc_private_material(
        &self,
        swap_id: [u8; 32],
        context: LaunchWalletContext,
    ) -> Result<HtlcPrivateMaterial, WalletError> {
        self.with_state(|state| {
            if state.mode != WalletMode::Full {
                return Err(WalletError::WatchOnly);
            }
            let pinned = pinned_htlc_context(state, Some(context))?;
            let tip = state.poseidon2_v8.tip()?;
            pinned.require_canonical_parent(
                state
                    .poseidon2_v8
                    .canonical_hash(0)
                    .ok_or(WalletError::InvalidState("HTLC wallet genesis missing"))?,
                tip.height,
            )?;
            let swap = state
                .htlc_swaps
                .iter()
                .find(|swap| swap.id == swap_id)
                .ok_or(WalletError::InvalidState("unknown HTLC offer"))?;
            if swap.offer.network_id != context.chain_id() {
                return Err(WalletError::InvalidState(
                    "HTLC offer belongs to another launch chain",
                ));
            }
            let locked_note = crate::poseidon2_v8_sync::words_to_opening(
                swap.locked_opening
                    .ok_or(WalletError::InvalidState("HTLC locked opening missing"))?,
            )?;
            let policy_nullifier_key = swap
                .policy_nullifier_key
                .ok_or(WalletError::InvalidState("HTLC nullifier key missing"))?;
            if locked_note.value != swap.offer.value
                || smallwood_htlc::bind_locked_note(
                    locked_note,
                    swap.offer.policy(),
                    policy_nullifier_key,
                )
                .map_err(htlc::surface_error)?
                    != locked_note
            {
                return Err(WalletError::InvalidState("HTLC private opening changed"));
            }
            Ok(HtlcPrivateMaterial {
                offer: swap.offer.clone(),
                locked_note,
                policy_nullifier_key,
                secret: swap.secret,
            })
        })
    }
    pub(crate) fn check_htlc_preparation(
        &self,
        attempt_id: [u8; 32],
        context: LaunchWalletContext,
        expected: &HtlcStatement,
    ) -> Result<u64, WalletError> {
        self.with_state(|state| {
            if state.mode != WalletMode::Full {
                return Err(WalletError::WatchOnly);
            }
            let attempt = state
                .htlc_swaps
                .iter()
                .flat_map(|swap| &swap.attempts)
                .find(|attempt| attempt.id == attempt_id)
                .ok_or(WalletError::InvalidState("unknown HTLC attempt"))?;
            if !matches!(
                attempt.status,
                HtlcAttemptStatus::Proving | HtlcAttemptStatus::Ready
            ) || &attempt.statement != expected
            {
                return Err(WalletError::InvalidState(
                    "HTLC exact preparation changed or already exported",
                ));
            }
            canonical_htlc_attempt(state, attempt, Some(context))
        })
    }
    /// Construct private source-relation material from the encrypted agreed
    /// opening and the current canonical mirror. The returned witness has no
    /// Debug/serde surface. No network request is performed by this method.
    pub fn build_htlc_witness(
        &self,
        swap_id: [u8; 32],
        statement: &HtlcStatement,
        input_position: u64,
        spend_key: [u64; 5],
        output_note: SmallwoodPoseidon2V8NoteOpening,
    ) -> Result<smallwood_htlc::HtlcWitness, WalletError> {
        self.with_state(|state| {
            if state.mode != WalletMode::Full {
                return Err(WalletError::WatchOnly);
            }
            let swap = state
                .htlc_swaps
                .iter()
                .find(|swap| swap.id == swap_id)
                .ok_or(WalletError::InvalidState("unknown HTLC offer"))?;
            htlc::validate_offer_statement(&swap.offer, statement)?;
            let tip = state.poseidon2_v8.tip()?;
            statement
                .validate_context(
                    swap.offer.network_id,
                    tip.block_hash,
                    tip.height,
                    tip.anchor,
                )
                .map_err(htlc::surface_error)?;
            let locked_note = crate::poseidon2_v8_sync::words_to_opening(
                swap.locked_opening
                    .ok_or(WalletError::InvalidState("HTLC locked opening missing"))?,
            )?;
            let key = swap
                .policy_nullifier_key
                .ok_or(WalletError::InvalidState("HTLC nullifier key missing"))?;
            let input_note = if statement.action == HtlcAction::Lock {
                if output_note != locked_note {
                    return Err(WalletError::InvalidArgument(
                        "HTLC lock output differs from agreed opening",
                    ));
                }
                state
                    .poseidon2_v8
                    .owned_notes()?
                    .into_iter()
                    .find(|note| {
                        !note.spent
                            && note.position == input_position
                            && note.nullifier == statement.nullifier
                    })
                    .ok_or(WalletError::InvalidState("HTLC lock input not owned"))?
                    .opening
            } else {
                locked_note
            };
            let commitment =
                poseidon2_v8_note_commitment(input_note).map_err(htlc::surface_error)?;
            let siblings = state
                .poseidon2_v8
                .canonical_note_path(commitment, input_position)?;
            if state
                .poseidon2_v8
                .has_canonical_nullifier(statement.nullifier)
            {
                return Err(WalletError::InvalidState("HTLC input already consumed"));
            }
            let secret = if statement.action == HtlcAction::Claim {
                swap.secret
                    .ok_or(WalletError::InvalidState("HTLC claim secret not yet known"))?
            } else {
                [0; 32]
            };
            Ok(smallwood_htlc::HtlcWitness {
                policy: swap.offer.policy(),
                policy_nullifier_key: key,
                input_note,
                input_position: u32::try_from(input_position).map_err(htlc::surface_error)?,
                input_siblings: siblings,
                spend_key,
                secret,
                output_note,
            })
        })
    }

    pub fn accept_htlc_offer(&self, offer: HtlcOffer) -> Result<[u8; 32], WalletError> {
        let id = offer.id()?;
        self.with_htlc_mut(|state| {
            if state.mode != WalletMode::Full {
                return Err(WalletError::WatchOnly);
            }
            if let Some(existing) = state.htlc_swaps.iter().find(|swap| swap.id == id) {
                if existing.offer != offer {
                    return Err(WalletError::InvalidState("HTLC offer identity collision"));
                }
                return Ok(id);
            }
            state.htlc_swaps.push(StoredHtlcSwap {
                id,
                offer,
                secret: None,
                locked_opening: None,
                policy_nullifier_key: None,
                attempts: Vec::new(),
            });
            Ok(id)
        })
    }
    pub fn save_htlc_secret(&self, id: [u8; 32], secret: [u8; 32]) -> Result<(), WalletError> {
        self.with_htlc_mut(|state| {
            let swap = find_swap_mut(state, id)?;
            htlc::validate_revealed_secret(&swap.offer, &secret)?;
            if swap.secret.is_some_and(|known| known != secret) {
                return Err(WalletError::InvalidState("HTLC secret changed"));
            }
            swap.secret = Some(secret);
            Ok(())
        })
    }
    /// Import the counterparty-agreed private note opening before locking funds.
    /// The caller exchanges this privately; it never belongs in an offer/receipt.
    pub fn save_htlc_locked_opening(
        &self,
        id: [u8; 32],
        note: SmallwoodPoseidon2V8NoteOpening,
        nullifier_key: [u64; 5],
    ) -> Result<(), WalletError> {
        self.with_htlc_mut(|state| {
            let swap = find_swap_mut(state, id)?;
            if note.value != swap.offer.value
                || note.asset_id != 0
                || smallwood_htlc::bind_locked_note(note, swap.offer.policy(), nullifier_key)
                    .map_err(htlc::surface_error)?
                    != note
            {
                return Err(WalletError::InvalidArgument(
                    "HTLC opening differs from accepted policy",
                ));
            }
            let words = crate::poseidon2_v8_sync::opening_to_words(note);
            if swap.locked_opening.is_some_and(|old| old != words)
                || swap
                    .policy_nullifier_key
                    .is_some_and(|old| old != nullifier_key)
            {
                return Err(WalletError::InvalidState("HTLC opening already fixed"));
            }
            swap.locked_opening = Some(words);
            swap.policy_nullifier_key = Some(nullifier_key);
            Ok(())
        })
    }
    pub fn htlc_swaps(&self) -> Result<Vec<HtlcSwapView>, WalletError> {
        self.with_state(|state| {
            Ok(state
                .htlc_swaps
                .iter()
                .map(|swap| {
                    Ok(HtlcSwapView {
                        id: swap.id,
                        offer: swap.offer.clone(),
                        has_secret: swap.secret.is_some(),
                        locked_note_positions: match swap.locked_opening {
                            Some(words) => state.poseidon2_v8.canonical_note_positions(
                                poseidon2_v8_note_commitment(
                                    crate::poseidon2_v8_sync::words_to_opening(words)?,
                                )
                                .map_err(htlc::surface_error)?,
                            )?,
                            None => Vec::new(),
                        },
                        attempts: swap
                            .attempts
                            .iter()
                            .map(|attempt| HtlcAttemptView {
                                id: attempt.id,
                                action: attempt.statement.action,
                                status: attempt.status,
                                input_consumed: state.poseidon2_v8.canonical_hash(0)
                                    == Some(attempt.genesis)
                                    && state
                                        .poseidon2_v8
                                        .has_canonical_nullifier(attempt.statement.nullifier),
                                input_reserved: state.htlc_attempt_active(attempt),
                                confirmation: attempt.confirmed_in.filter(|confirmation| {
                                    state.poseidon2_v8.canonical_hash(0) == Some(attempt.genesis)
                                        && state.poseidon2_v8.canonical_hash(confirmation.height)
                                            == Some(confirmation.block_hash)
                                        && state
                                            .poseidon2_v8
                                            .has_canonical_nullifier(attempt.statement.nullifier)
                                }),
                            })
                            .collect(),
                    })
                })
                .collect::<Result<Vec<_>, WalletError>>()?)
        })
    }
    /// Atomically excludes both ordinary RP05 spends and competing HTLC branches.
    /// For Lock the selected input must be a wallet-owned ordinary note. For
    /// Claim/Refund it must match the durable policy-bound locked note opening.
    pub fn reserve_htlc_attempt(
        &self,
        swap_id: [u8; 32],
        statement: HtlcStatement,
        input_commitment: [u64; 7],
        input_position: u64,
    ) -> Result<[u8; 32], WalletError> {
        self.with_htlc_mut(|state| {
            if state.mode != WalletMode::Full {
                return Err(WalletError::WatchOnly);
            }
            let swap = state
                .htlc_swaps
                .iter()
                .find(|swap| swap.id == swap_id)
                .ok_or(WalletError::InvalidState("unknown HTLC offer"))?;
            htlc::validate_offer_statement(&swap.offer, &statement)?;
            let tip = state.poseidon2_v8.tip()?;
            statement
                .validate_context(
                    swap.offer.network_id,
                    tip.block_hash,
                    tip.height,
                    tip.anchor,
                )
                .map_err(htlc::surface_error)?;
            let genesis = state
                .poseidon2_v8
                .canonical_hash(0)
                .ok_or(WalletError::InvalidState("HTLC wallet genesis missing"))?;
            state
                .poseidon2_v8
                .canonical_note_path(input_commitment, input_position)?;
            if state
                .reserved_poseidon2_v8_nullifiers()
                .contains(&statement.nullifier)
                || state
                    .poseidon2_v8
                    .has_canonical_nullifier(statement.nullifier)
            {
                return Err(WalletError::InvalidState("HTLC input reserved or consumed"));
            }
            if statement.action == HtlcAction::Lock {
                if !state.poseidon2_v8.owned_notes()?.iter().any(|note| {
                    !note.spent
                        && note.commitment == input_commitment
                        && note.position == input_position
                        && note.nullifier == statement.nullifier
                }) {
                    return Err(WalletError::InvalidState("HTLC lock input not owned"));
                }
                let opening = crate::poseidon2_v8_sync::words_to_opening(
                    swap.locked_opening
                        .ok_or(WalletError::InvalidState("HTLC locked opening missing"))?,
                )?;
                if poseidon2_v8_note_commitment(opening).map_err(htlc::surface_error)?
                    != statement.output_commitment
                {
                    return Err(WalletError::InvalidArgument(
                        "HTLC lock output differs from agreed opening",
                    ));
                }
            } else {
                let note = crate::poseidon2_v8_sync::words_to_opening(
                    swap.locked_opening
                        .ok_or(WalletError::InvalidState("HTLC locked opening missing"))?,
                )?;
                let key = swap
                    .policy_nullifier_key
                    .ok_or(WalletError::InvalidState("HTLC nullifier key missing"))?;
                if poseidon2_v8_note_commitment(note).map_err(htlc::surface_error)?
                    != input_commitment
                    || smallwood_htlc::htlc_nullifier(
                        key,
                        u32::try_from(input_position).map_err(htlc::surface_error)?,
                        note,
                    )
                    .map_err(htlc::surface_error)?
                        != statement.nullifier
                {
                    return Err(WalletError::InvalidArgument(
                        "HTLC input differs from agreed opening",
                    ));
                }
            }
            let mut id = [0; 32];
            loop {
                OsRng.fill_bytes(&mut id);
                if id != [0; 32]
                    && !state
                        .htlc_swaps
                        .iter()
                        .flat_map(|swap| &swap.attempts)
                        .any(|attempt| attempt.id == id)
                {
                    break;
                }
            }
            find_swap_mut(state, swap_id)?
                .attempts
                .push(StoredHtlcAttempt {
                    id,
                    genesis,
                    statement,
                    input_commitment,
                    input_position,
                    status: HtlcAttemptStatus::Proving,
                    exact_carrier: Vec::new(),
                    confirmed_in: None,
                });
            Ok(id)
        })
    }
    pub fn prepare_htlc_submission(
        &self,
        attempt_id: [u8; 32],
        exact_carrier: Vec<u8>,
    ) -> Result<(), WalletError> {
        self.prepare_htlc_submission_inner(attempt_id, exact_carrier, true)
    }
    /// Rehearsal sealing remains genuine source proof verification. Only
    /// production source activation is skipped under this explicit compile gate.
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn prepare_htlc_submission_for_retained_test(
        &self,
        attempt_id: [u8; 32],
        exact_carrier: Vec<u8>,
    ) -> Result<(), WalletError> {
        self.prepare_htlc_submission_inner(attempt_id, exact_carrier, false)
    }
    fn prepare_htlc_submission_inner(
        &self,
        attempt_id: [u8; 32],
        exact_carrier: Vec<u8>,
        require_authority: bool,
    ) -> Result<(), WalletError> {
        let carrier = smallwood_htlc_transport::decode_candidate_exact(&exact_carrier)
            .map_err(htlc::surface_error)?;
        smallwood_htlc::verify_candidate(&carrier.statement, carrier.proof)
            .map_err(htlc::surface_error)?;
        let statement = carrier.statement.clone();
        let proof_len = carrier.proof.len();
        self.with_htlc_mut(|state| {
            let attempt = state
                .htlc_swaps
                .iter()
                .flat_map(|swap| &swap.attempts)
                .find(|attempt| attempt.id == attempt_id)
                .ok_or(WalletError::InvalidState("unknown HTLC attempt"))?;
            if attempt.status != HtlcAttemptStatus::Proving || attempt.statement != statement {
                return Err(WalletError::InvalidState(
                    "HTLC prepared statement mismatch",
                ));
            }
            let inclusion = canonical_htlc_attempt(state, attempt, None)?;
            let context = pinned_htlc_context(state, None)?;
            if require_authority
                && protocol_versioning::launch_candidate::launch_proof_authority(context.request(
                    protocol_versioning::launch_candidate::LaunchProofKind::Htlc,
                    inclusion,
                    proof_len,
                ))
                .is_none()
            {
                return Err(WalletError::InvalidState(
                    "HTLC has no source authority at actual inclusion",
                ));
            }
            let attempt = find_attempt_mut(state, attempt_id)?;
            attempt.exact_carrier = exact_carrier;
            attempt.status = HtlcAttemptStatus::Ready;
            Ok(())
        })
    }
    /// Atomic adapter cleanup cannot race proof sealing into a Ready deletion.
    /// An already absent proving lease is idempotent; every sealed record stays.
    pub(crate) fn cancel_htlc_proving_attempt(
        &self,
        attempt_id: [u8; 32],
    ) -> Result<(), WalletError> {
        self.with_htlc_mut(|state| {
            let attempt = state
                .htlc_swaps
                .iter()
                .flat_map(|swap| &swap.attempts)
                .find(|attempt| attempt.id == attempt_id);
            match attempt {
                None => return Ok(()),
                Some(attempt) if attempt.status == HtlcAttemptStatus::Proving => (),
                Some(_) => {
                    return Err(WalletError::InvalidState(
                        "sealed HTLC attempt cannot be cancelled",
                    ))
                }
            }
            for swap in &mut state.htlc_swaps {
                swap.attempts.retain(|attempt| attempt.id != attempt_id);
            }
            Ok(())
        })
    }
    /// Persist uncertainty synchronously before creating/polling any mutating
    /// RPC. A timeout, cancellation or rejection response never releases input.
    pub fn begin_htlc_submission(&self, attempt_id: [u8; 32]) -> Result<Vec<u8>, WalletError> {
        self.begin_htlc_submission_inner(attempt_id, true)
    }
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn begin_htlc_submission_for_retained_test(
        &self,
        attempt_id: [u8; 32],
    ) -> Result<Vec<u8>, WalletError> {
        self.begin_htlc_submission_inner(attempt_id, false)
    }
    fn begin_htlc_submission_inner(
        &self,
        attempt_id: [u8; 32],
        require_authority: bool,
    ) -> Result<Vec<u8>, WalletError> {
        self.export_htlc_attempt_inner(attempt_id, false, require_authority, require_authority)
            .map(|export| export.exact_carrier)
    }
    /// Checked submission export; repeated Uncertain/Submitted exports preserve
    /// the identical carrier and status. Bytes follow a synchronous store write.
    pub fn export_htlc_attempt(
        &self,
        attempt_id: [u8; 32],
    ) -> Result<HtlcAttemptExport, WalletError> {
        self.export_htlc_attempt_inner(attempt_id, false, true, true)
    }
    /// Explicit rehearsal export skips source activation only. It still verifies
    /// the complete genuine SMZC proof and the pinned canonical checkpoint.
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn export_htlc_attempt_for_retained_test(
        &self,
        attempt_id: [u8; 32],
    ) -> Result<HtlcAttemptExport, WalletError> {
        self.export_htlc_attempt_inner(attempt_id, false, false, true)
    }
    /// Recover exact public bytes even when offline, expired, orphaned or lacking
    /// source authority. Unknown readiness never grants submission authority.
    pub fn recover_htlc_attempt(
        &self,
        attempt_id: [u8; 32],
    ) -> Result<HtlcAttemptExport, WalletError> {
        self.export_htlc_attempt_inner(attempt_id, true, true, true)
    }
    fn export_htlc_attempt_inner(
        &self,
        attempt_id: [u8; 32],
        offline: bool,
        require_authority: bool,
        verify_proof: bool,
    ) -> Result<HtlcAttemptExport, WalletError> {
        self.with_htlc_mut(|state| {
            let attempt = state
                .htlc_swaps
                .iter()
                .flat_map(|swap| &swap.attempts)
                .find(|attempt| attempt.id == attempt_id)
                .ok_or(WalletError::InvalidState("unknown HTLC attempt"))?;
            if attempt.status == HtlcAttemptStatus::Proving
                || (!offline && attempt.status == HtlcAttemptStatus::Abandoned)
            {
                return Err(WalletError::InvalidState(
                    "HTLC attempt has no exportable prepared candidate",
                ));
            }
            let carrier = smallwood_htlc_transport::decode_candidate_exact(&attempt.exact_carrier)
                .map_err(htlc::surface_error)?;
            if carrier.statement != attempt.statement {
                return Err(WalletError::InvalidState("HTLC retained carrier changed"));
            }
            if verify_proof {
                smallwood_htlc::verify_candidate(&carrier.statement, carrier.proof)
                    .map_err(htlc::surface_error)?;
            }
            let readiness = if attempt.status != HtlcAttemptStatus::Abandoned {
                match ready_htlc_attempt(state, attempt, require_authority) {
                    Ok(actual_inclusion_height) => HtlcAttemptReadiness::Ready {
                        actual_inclusion_height,
                    },
                    Err(_) if offline => HtlcAttemptReadiness::Unknown,
                    Err(error) => return Err(error),
                }
            } else {
                HtlcAttemptReadiness::Unknown
            };
            // Rollback on failed disk write returns no bytes and preserves the hold.
            let attempt = find_attempt_mut(state, attempt_id)?;
            if attempt.status == HtlcAttemptStatus::Ready {
                attempt.status = HtlcAttemptStatus::SubmissionUncertain;
            }
            let swap = state
                .htlc_swaps
                .iter()
                .find(|swap| swap.attempts.iter().any(|attempt| attempt.id == attempt_id))
                .ok_or(WalletError::InvalidState("unknown HTLC offer"))?;
            let attempt = swap
                .attempts
                .iter()
                .find(|attempt| attempt.id == attempt_id)
                .ok_or(WalletError::InvalidState("unknown HTLC attempt"))?;
            Ok(HtlcAttemptExport {
                review: htlc_review(state, swap, attempt, readiness)?,
                exact_carrier: attempt.exact_carrier.clone(),
            })
        })
    }
    /// Read public metadata without exposing bytes or mutating submission state.
    pub fn review_htlc_attempt(
        &self,
        attempt_id: [u8; 32],
    ) -> Result<HtlcAttemptReview, WalletError> {
        self.with_state(|state| {
            let swap = state
                .htlc_swaps
                .iter()
                .find(|swap| swap.attempts.iter().any(|attempt| attempt.id == attempt_id))
                .ok_or(WalletError::InvalidState("unknown HTLC attempt"))?;
            let attempt = swap
                .attempts
                .iter()
                .find(|attempt| attempt.id == attempt_id)
                .ok_or(WalletError::InvalidState("unknown HTLC attempt"))?;
            let readiness = if matches!(
                attempt.status,
                HtlcAttemptStatus::Ready
                    | HtlcAttemptStatus::SubmissionUncertain
                    | HtlcAttemptStatus::Submitted(_)
            ) {
                ready_htlc_attempt(state, attempt, true)
                    .map(|actual_inclusion_height| HtlcAttemptReadiness::Ready {
                        actual_inclusion_height,
                    })
                    .unwrap_or(HtlcAttemptReadiness::Unknown)
            } else {
                HtlcAttemptReadiness::Unknown
            };
            htlc_review(state, swap, attempt, readiness)
        })
    }
    pub fn mark_htlc_submitted(
        &self,
        attempt_id: [u8; 32],
        action_id: ActionId48,
    ) -> Result<(), WalletError> {
        self.with_htlc_mut(|state| {
            let attempt = find_attempt_mut(state, attempt_id)?;
            if attempt.status == HtlcAttemptStatus::Submitted(action_id) {
                return Ok(());
            }
            if attempt.status != HtlcAttemptStatus::SubmissionUncertain {
                return Err(WalletError::InvalidState(
                    "HTLC submission receipt differs or was not prepared",
                ));
            }
            attempt.status = HtlcAttemptStatus::Submitted(action_id);
            Ok(())
        })
    }
    pub fn release_unsubmitted_htlc_attempt(
        &self,
        attempt_id: [u8; 32],
    ) -> Result<(), WalletError> {
        self.with_htlc_mut(|state| {
            let attempt = find_attempt_mut(state, attempt_id)?;
            if !matches!(
                attempt.status,
                HtlcAttemptStatus::Proving | HtlcAttemptStatus::Ready
            ) {
                return Err(WalletError::InvalidState(
                    "possibly submitted HTLC cannot be released",
                ));
            }
            for swap in &mut state.htlc_swaps {
                swap.attempts.retain(|attempt| attempt.id != attempt_id);
            }
            Ok(())
        })
    }
    pub fn abandon_stale_htlc_attempt(
        &self,
        attempt_id: [u8; 32],
        expected_tip: Poseidon2V8CanonicalTip,
    ) -> Result<(), WalletError> {
        self.with_htlc_mut(|state| {
            if state.poseidon2_v8.tip()? != expected_tip {
                return Err(WalletError::InvalidState(
                    "HTLC reconciliation requires current canonical tip",
                ));
            }
            let attempt = state
                .htlc_swaps
                .iter()
                .flat_map(|swap| &swap.attempts)
                .find(|attempt| attempt.id == attempt_id)
                .ok_or(WalletError::InvalidState("unknown HTLC attempt"))?;
            if !matches!(
                attempt.status,
                HtlcAttemptStatus::SubmissionUncertain | HtlcAttemptStatus::Submitted(_)
            ) || state.poseidon2_v8.canonical_hash(0) != Some(attempt.genesis)
                || expected_tip.height <= htlc::last_admissible_parent(&attempt.statement)
                || state
                    .poseidon2_v8
                    .has_canonical_nullifier(attempt.statement.nullifier)
            {
                return Err(WalletError::InvalidState(
                    "HTLC attempt cannot yet be safely abandoned",
                ));
            }
            state
                .poseidon2_v8
                .canonical_note_path(attempt.input_commitment, attempt.input_position)?;
            find_attempt_mut(state, attempt_id)?.status = HtlcAttemptStatus::Abandoned;
            Ok(())
        })
    }
    fn with_htlc_mut<T>(
        &self,
        update: impl FnOnce(&mut WalletState) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        self.ensure_writable()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet poisoned"))?;
        let previous = state.htlc_swaps.clone();
        let result = update(&mut state).and_then(|value| {
            state.validate_htlc_swaps()?;
            self.write_state(&state)?;
            Ok(value)
        });
        if result.is_err() {
            state.htlc_swaps = previous;
        }
        result
    }
}
fn find_swap_mut(
    state: &mut WalletState,
    id: [u8; 32],
) -> Result<&mut StoredHtlcSwap, WalletError> {
    state
        .htlc_swaps
        .iter_mut()
        .find(|swap| swap.id == id)
        .ok_or(WalletError::InvalidState("unknown HTLC offer"))
}
fn find_attempt_mut(
    state: &mut WalletState,
    id: [u8; 32],
) -> Result<&mut StoredHtlcAttempt, WalletError> {
    state
        .htlc_swaps
        .iter_mut()
        .flat_map(|swap| &mut swap.attempts)
        .find(|attempt| attempt.id == id)
        .ok_or(WalletError::InvalidState("unknown HTLC attempt"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn ready_journal_fixture() -> (tempfile::TempDir, WalletStore, Vec<u8>) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet");
        let root = RootSecret::from_bytes([71; 32]);
        let store = WalletStore::create_from_root(&path, "recovery", root.clone()).unwrap();
        store
            .ensure_poseidon2_v8_genesis_for_test([61; 32], [1, 2, 3, 4, 5, 6, 7])
            .unwrap();
        let (funding, context) =
            crate::poseidon2_v8_sync::launch_sync::tests::htlc_journal_test_block(
                store.poseidon2_v8_tip().unwrap(),
                &root,
            );
        store
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&funding, context)
            .unwrap();
        let note = store.poseidon2_v8_owned_notes().unwrap()[0].clone();
        let (block, _) = crate::poseidon2_v8_sync::launch_sync::tests::htlc_journal_test_block(
            store.poseidon2_v8_tip().unwrap(),
            &root,
        );
        let (_, observations, _) =
            crate::poseidon2_v8_sync::launch_sync::canonical_launch_observations(&block).unwrap();
        let decoded = smallwood_htlc_transport::decode_candidate_exact(&observations[0].1).unwrap();
        let mut statement = decoded.statement;
        statement.nullifier = [91; 7];
        let carrier = smallwood_htlc_transport::encode_candidate(
            &statement,
            decoded.ciphertext,
            decoded.proof,
        )
        .unwrap();
        let mut offer = crate::htlc::tests::offer();
        offer.network_id = [62; 32];
        let swap = store.accept_htlc_offer(offer).unwrap();
        // Canonical framing fixture only; it is not a genuine proof and cannot
        // pass the public export/recovery API's complete verification.
        store
            .with_htlc_mut(|state| {
                find_swap_mut(state, swap)?
                    .attempts
                    .push(StoredHtlcAttempt {
                        id: [81; 32],
                        genesis: [61; 32],
                        statement,
                        input_commitment: note.commitment,
                        input_position: note.position,
                        status: HtlcAttemptStatus::Ready,
                        exact_carrier: carrier.clone(),
                        confirmed_in: None,
                    });
                Ok(())
            })
            .unwrap();
        (directory, store, carrier)
    }
    #[test]
    fn htlc_durable_recovery_preserves_exact_uncertain_and_submitted_bytes() {
        let (directory, store, carrier) = ready_journal_fixture();
        assert!(store.export_htlc_attempt([81; 32]).is_err());
        assert!(store.recover_htlc_attempt([81; 32]).is_err());
        let export = store
            .export_htlc_attempt_inner([81; 32], false, false, false)
            .unwrap();
        assert_eq!(export.exact_carrier(), carrier);
        assert_eq!(
            export.review().status,
            HtlcAttemptStatus::SubmissionUncertain
        );
        assert!(matches!(
            export.review().readiness,
            HtlcAttemptReadiness::Ready { .. }
        ));
        let hash = export.review().carrier_sha512;
        drop(store);
        let store = WalletStore::open(directory.path().join("wallet"), "recovery").unwrap();
        let repeated = store
            .export_htlc_attempt_inner([81; 32], false, false, false)
            .unwrap();
        assert_eq!(repeated.exact_carrier(), carrier);
        assert_eq!(repeated.review().carrier_sha512, hash);
        assert_eq!(
            repeated.review().status,
            HtlcAttemptStatus::SubmissionUncertain
        );
        let id = ActionId48::try_from([17u8; 48].as_slice()).unwrap();
        store.mark_htlc_submitted([81; 32], id).unwrap();
        store.mark_htlc_submitted([81; 32], id).unwrap();
        assert!(store
            .mark_htlc_submitted(
                [81; 32],
                ActionId48::try_from([18u8; 48].as_slice()).unwrap()
            )
            .is_err());
        let repeated = store
            .export_htlc_attempt_inner([81; 32], false, false, false)
            .unwrap();
        assert_eq!(repeated.exact_carrier(), carrier);
        assert_eq!(repeated.review().status, HtlcAttemptStatus::Submitted(id));
        assert!(store.release_unsubmitted_htlc_attempt([81; 32]).is_err());
        assert!(store.htlc_swaps().unwrap()[0].attempts[0].input_reserved);
        let unknown = store
            .export_htlc_attempt_inner([81; 32], true, true, false)
            .unwrap();
        assert_eq!(unknown.exact_carrier(), carrier);
        assert_eq!(unknown.review().readiness, HtlcAttemptReadiness::Unknown);
        assert_eq!(unknown.review().status, HtlcAttemptStatus::Submitted(id));
    }
    #[test]
    fn htlc_export_failed_write_returns_no_bytes_and_preserves_ready_hold() {
        let (directory, store, carrier) = ready_journal_fixture();
        let path = directory.path().join("wallet");
        let backup = directory.path().join("preserved-wallet");
        let before = std::fs::read(&path).unwrap();
        std::fs::rename(&path, &backup).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(store
            .export_htlc_attempt_inner([81; 32], false, false, false)
            .is_err());
        assert_eq!(
            store.htlc_swaps().unwrap()[0].attempts[0].status,
            HtlcAttemptStatus::Ready
        );
        assert!(store.htlc_swaps().unwrap()[0].attempts[0].input_reserved);
        assert_eq!(std::fs::read(&backup).unwrap(), before);
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&backup, &path).unwrap();
        drop(store);
        let store = WalletStore::open(&path, "recovery").unwrap();
        assert_eq!(
            store.htlc_swaps().unwrap()[0].attempts[0].status,
            HtlcAttemptStatus::Ready
        );
        let recovered = store
            .export_htlc_attempt_inner([81; 32], true, true, false)
            .unwrap();
        assert_eq!(recovered.exact_carrier(), carrier);
        assert_eq!(recovered.review().readiness, HtlcAttemptReadiness::Unknown);
        assert_eq!(
            recovered.review().status,
            HtlcAttemptStatus::SubmissionUncertain
        );
    }
    #[test]
    fn htlc_atomic_cancel_only_removes_proving_lease() {
        let (_directory, store, carrier) = ready_journal_fixture();
        assert!(store.cancel_htlc_proving_attempt([81; 32]).is_err());
        assert_eq!(
            store.htlc_swaps().unwrap()[0].attempts[0].status,
            HtlcAttemptStatus::Ready
        );
        store
            .with_htlc_mut(|state| {
                let attempt = find_attempt_mut(state, [81; 32])?;
                attempt.status = HtlcAttemptStatus::Proving;
                attempt.exact_carrier.clear();
                Ok(())
            })
            .unwrap();
        store.cancel_htlc_proving_attempt([81; 32]).unwrap();
        store.cancel_htlc_proving_attempt([81; 32]).unwrap();
        assert!(store.htlc_swaps().unwrap()[0].attempts.is_empty());
        assert!(!carrier.is_empty());
    }
    #[test]
    fn htlc_ready_public_claim_review_does_not_reveal_preimage() {
        let (_directory, store, carrier) = ready_journal_fixture();
        let secret = [219u8; 32];
        store
            .with_htlc_mut(|state| {
                let swap = state.htlc_swaps.first_mut().unwrap();
                swap.offer.secret_release = smallwood_htlc::SecretRelease::PublicOnHegemon;
                swap.offer.hashlock = Sha256::digest(secret).into();
                swap.id = swap.offer.id()?;
                let attempt = swap.attempts.first_mut().unwrap();
                attempt.statement.revealed_secret = Some(secret);
                let decoded = smallwood_htlc_transport::decode_candidate_exact(&carrier)
                    .map_err(htlc::surface_error)?;
                attempt.exact_carrier = smallwood_htlc_transport::encode_candidate(
                    &attempt.statement,
                    decoded.ciphertext,
                    decoded.proof,
                )
                .map_err(htlc::surface_error)?;
                Ok(())
            })
            .unwrap();
        let review = store.review_htlc_attempt([81; 32]).unwrap();
        assert_eq!(review.status, HtlcAttemptStatus::Ready);
        assert!(review.statement.revealed_secret_present);
        assert_eq!(
            review.statement.revealed_secret_sha256,
            Some(Sha256::digest(secret).into())
        );
        let debug = format!("{review:?}");
        assert!(!debug.contains(&format!("{:?}", secret)));
        assert!(!debug.contains(&hex::encode(secret)));
        assert_eq!(
            store.htlc_swaps().unwrap()[0].attempts[0].status,
            HtlcAttemptStatus::Ready
        );
        let exported = store
            .export_htlc_attempt_inner([81; 32], true, true, false)
            .unwrap();
        assert_eq!(
            exported.review().status,
            HtlcAttemptStatus::SubmissionUncertain
        );
        assert_eq!(
            smallwood_htlc_transport::decode_candidate_exact(exported.exact_carrier())
                .unwrap()
                .statement
                .revealed_secret,
            Some(secret)
        );
    }
    #[test]
    fn htlc_abandoned_future_orphan_reference_keeps_input_hold_until_reattachment() {
        let (_directory, store, carrier) = ready_journal_fixture();
        let context = store.launch_context().unwrap();
        for height in 2..=5 {
            let tip = store.poseidon2_v8_tip().unwrap();
            store
                .apply_poseidon2_v8_launch_canonical_block_for_retained_test(
                    &crate::Poseidon2V8CanonicalBlock {
                        height,
                        hash: [height as u8; 32],
                        parent_hash: tip.block_hash,
                        action_bytes: Vec::new(),
                    },
                    context,
                )
                .unwrap();
        }
        let reference = store.poseidon2_v8_tip().unwrap();
        store
            .with_htlc_mut(|state| {
                let attempt = find_attempt_mut(state, [81; 32])?;
                attempt.statement.parent_height = reference.height;
                attempt.statement.parent_hash = reference.block_hash;
                let decoded = smallwood_htlc_transport::decode_candidate_exact(&carrier)
                    .map_err(htlc::surface_error)?;
                attempt.exact_carrier = smallwood_htlc_transport::encode_candidate(
                    &attempt.statement,
                    decoded.ciphertext,
                    decoded.proof,
                )
                .map_err(htlc::surface_error)?;
                Ok(())
            })
            .unwrap();
        let exact = store
            .export_htlc_attempt_inner([81; 32], false, false, false)
            .unwrap()
            .exact_carrier;
        for height in 6..=18 {
            let tip = store.poseidon2_v8_tip().unwrap();
            store
                .apply_poseidon2_v8_launch_canonical_block_for_retained_test(
                    &crate::Poseidon2V8CanonicalBlock {
                        height,
                        hash: [height as u8; 32],
                        parent_hash: tip.block_hash,
                        action_bytes: Vec::new(),
                    },
                    context,
                )
                .unwrap();
        }
        store
            .abandon_stale_htlc_attempt([81; 32], store.poseidon2_v8_tip().unwrap())
            .unwrap();
        assert!(!store.htlc_swaps().unwrap()[0].attempts[0].input_reserved);
        store.rollback_poseidon2_v8_to(2, [2; 32]).unwrap();
        assert!(store.htlc_swaps().unwrap()[0].attempts[0].input_reserved);
        assert!(!store.htlc_swaps().unwrap()[0].attempts[0].input_consumed);
        assert!(store
            .export_htlc_attempt_inner([81; 32], false, false, false)
            .is_err());
        let recovered = store
            .export_htlc_attempt_inner([81; 32], true, true, false)
            .unwrap();
        assert_eq!(recovered.exact_carrier(), exact);
        assert_eq!(recovered.review().readiness, HtlcAttemptReadiness::Unknown);
        for height in 3..=5 {
            let tip = store.poseidon2_v8_tip().unwrap();
            store
                .apply_poseidon2_v8_launch_canonical_block_for_retained_test(
                    &crate::Poseidon2V8CanonicalBlock {
                        height,
                        hash: [height as u8; 32],
                        parent_hash: tip.block_hash,
                        action_bytes: Vec::new(),
                    },
                    context,
                )
                .unwrap();
        }
        assert!(store.htlc_swaps().unwrap()[0].attempts[0].input_reserved);
    }
    #[test]
    fn htlc_delayed_submission_holds_through_window_and_reactivates_after_reorg() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet");
        let root = RootSecret::from_bytes([71; 32]);
        let store = WalletStore::create_from_root(&path, "window", root.clone()).unwrap();
        store
            .ensure_poseidon2_v8_genesis_for_test([61; 32], [1, 2, 3, 4, 5, 6, 7])
            .unwrap();
        let (funding, context) =
            crate::poseidon2_v8_sync::launch_sync::tests::htlc_journal_test_block(
                store.poseidon2_v8_tip().unwrap(),
                &root,
            );
        store
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&funding, context)
            .unwrap();
        let note = store.poseidon2_v8_owned_notes().unwrap()[0].clone();
        let reference = store.poseidon2_v8_tip().unwrap();
        let (candidate, _) =
            crate::poseidon2_v8_sync::launch_sync::tests::htlc_journal_test_block(reference, &root);
        let (_, observations, _) =
            crate::poseidon2_v8_sync::launch_sync::canonical_launch_observations(&candidate)
                .unwrap();
        let carrier = smallwood_htlc_transport::decode_candidate_exact(&observations[0].1).unwrap();
        let mut statement = carrier.statement;
        statement.nullifier = [91; 7];
        let exact_carrier = smallwood_htlc_transport::encode_candidate(
            &statement,
            carrier.ciphertext,
            carrier.proof,
        )
        .unwrap();
        let mut offer = crate::htlc::tests::offer();
        offer.network_id = [62; 32];
        let swap = store.accept_htlc_offer(offer).unwrap();
        // Framing-only journal fixture; genuine proofs are required by the
        // public preparation API. This fixture cannot authorize production.
        store
            .with_htlc_mut(|state| {
                find_swap_mut(state, swap)?
                    .attempts
                    .push(StoredHtlcAttempt {
                        id: [81; 32],
                        genesis: [61; 32],
                        statement,
                        input_commitment: note.commitment,
                        input_position: note.position,
                        status: HtlcAttemptStatus::Ready,
                        exact_carrier: exact_carrier.clone(),
                        confirmed_in: None,
                    });
                Ok(())
            })
            .unwrap();
        for height in 2..=13 {
            let tip = store.poseidon2_v8_tip().unwrap();
            let block = crate::poseidon2_v8_sync::Poseidon2V8CanonicalBlock {
                height,
                hash: [height as u8; 32],
                parent_hash: tip.block_hash,
                action_bytes: vec![],
            };
            store
                .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&block, context)
                .unwrap();
        }
        assert!(store.begin_htlc_submission([81; 32]).is_err());
        assert_eq!(
            store.htlc_swaps().unwrap()[0].attempts[0].status,
            HtlcAttemptStatus::Ready
        );
        assert_eq!(
            store
                .begin_htlc_submission_for_retained_test([81; 32])
                .unwrap(),
            exact_carrier
        );
        let final_parent = store.poseidon2_v8_tip().unwrap();
        assert_eq!(final_parent.height, reference.height + 12);
        assert!(store
            .abandon_stale_htlc_attempt([81; 32], final_parent)
            .is_err());
        let expired = crate::poseidon2_v8_sync::Poseidon2V8CanonicalBlock {
            height: 14,
            hash: [14; 32],
            parent_hash: final_parent.block_hash,
            action_bytes: vec![],
        };
        store
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&expired, context)
            .unwrap();
        store
            .abandon_stale_htlc_attempt([81; 32], store.poseidon2_v8_tip().unwrap())
            .unwrap();
        assert!(!store.htlc_swaps().unwrap()[0].attempts[0].input_reserved);
        drop(store);
        let reopened = WalletStore::open(&path, "window").unwrap();
        assert!(!reopened.htlc_swaps().unwrap()[0].attempts[0].input_reserved);
        reopened
            .rollback_poseidon2_v8_to(final_parent.height, final_parent.block_hash)
            .unwrap();
        let view = reopened.htlc_swaps().unwrap();
        assert_eq!(view[0].attempts[0].status, HtlcAttemptStatus::Abandoned);
        assert!(view[0].attempts[0].input_reserved);
        assert!(!view[0].attempts[0].input_consumed);
        let recovered = reopened
            .export_htlc_attempt_inner([81; 32], true, true, false)
            .unwrap();
        assert_eq!(recovered.exact_carrier(), exact_carrier);
        assert_eq!(recovered.review().status, HtlcAttemptStatus::Abandoned);
        assert_eq!(recovered.review().readiness, HtlcAttemptReadiness::Unknown);
        reopened.rollback_poseidon2_v8_to(0, [61; 32]).unwrap();
        assert!(reopened.htlc_swaps().unwrap()[0].attempts[0].input_reserved);
        reopened
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&funding, context)
            .unwrap();
        assert!(reopened.htlc_swaps().unwrap()[0].attempts[0].input_reserved);
    }
    #[test]
    fn htlc_uncertain_receipt_survives_restart_and_detaches_on_reorg() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet");
        let root = RootSecret::from_bytes([71; 32]);
        let store = WalletStore::create_from_root(&path, "journal", root.clone()).unwrap();
        store
            .ensure_poseidon2_v8_genesis_for_test([61; 32], [1, 2, 3, 4, 5, 6, 7])
            .unwrap();
        let offer = HtlcOffer {
            version: 1,
            nonce: [2; 32],
            network_id: [62; 32],
            hashlock: Sha256::digest([19; 32]).into(),
            value: 10,
            maximum_fee: 1,
            timeout_height: 100,
            claim_authority: [1; 7],
            refund_authority: [2; 7],
            claim_recipient: [3; 4],
            refund_recipient: [4; 4],
            secret_release: smallwood_htlc::SecretRelease::HiddenOnHegemon,
            bitcoin: crate::htlc::BitcoinRegtestTerms {
                amount_sat: 10_000,
                claim_public_key: [vec![2], vec![3; 32]].concat(),
                refund_public_key: [vec![3], vec![4; 32]].concat(),
                refund_height: 30,
                required_confirmations: 1,
            },
        };
        let id = store.accept_htlc_offer(offer).unwrap();
        let (block, context) =
            crate::poseidon2_v8_sync::launch_sync::tests::htlc_journal_test_block(
                store.poseidon2_v8_tip().unwrap(),
                &root,
            );
        let (_, observed, _) =
            crate::poseidon2_v8_sync::launch_sync::canonical_launch_observations(&block).unwrap();
        let carrier = observed[0].1.clone();
        let statement = smallwood_htlc_transport::decode_candidate_exact(&carrier)
            .unwrap()
            .statement;
        // Direct journal fixture only. These framing bytes are not valid proofs
        // and cannot pass prepare_htlc_submission or production admission.
        store
            .with_htlc_mut(|state| {
                find_swap_mut(state, id)?.attempts.push(StoredHtlcAttempt {
                    id: [81; 32],
                    genesis: [61; 32],
                    statement,
                    input_commitment: [3; 7],
                    input_position: 0,
                    status: HtlcAttemptStatus::SubmissionUncertain,
                    exact_carrier: carrier,
                    confirmed_in: None,
                });
                Ok(())
            })
            .unwrap();
        assert!(store.release_unsubmitted_htlc_attempt([81; 32]).is_err());
        store
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&block, context)
            .unwrap();
        let view = store.htlc_swaps().unwrap();
        assert!(view[0].attempts[0].input_consumed);
        assert_eq!(
            view[0].attempts[0].confirmation.unwrap().block_hash,
            block.hash
        );
        assert_eq!(
            view[0].attempts[0].status,
            HtlcAttemptStatus::SubmissionUncertain
        );
        drop(store);
        let reopened = WalletStore::open(&path, "journal").unwrap();
        assert_eq!(reopened.htlc_swaps().unwrap(), view);
        reopened.rollback_poseidon2_v8_to(0, [61; 32]).unwrap();
        let detached = reopened.htlc_swaps().unwrap();
        assert!(!detached[0].attempts[0].input_consumed);
        assert!(detached[0].attempts[0].confirmation.is_none());
        assert!(detached[0].attempts[0].input_reserved);
        assert!(reopened.release_unsubmitted_htlc_attempt([81; 32]).is_err());
        reopened
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&block, context)
            .unwrap();
        assert_eq!(reopened.htlc_swaps().unwrap(), view);
    }
}
