//! Durable, wallet-local V8 input ownership. No proof or consensus bytes change.

use super::*;
use crate::poseidon2_v8_sync::Poseidon2V8Digest;

/// Submission uncertainty is persisted before the first mutating RPC poll.
/// A timeout, cancellation or missing response cannot prove non-submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Poseidon2V8ReservationStatus {
    Proving,
    SubmissionUncertain,
    Submitted(#[serde(with = "super::serde_action_id48")] ActionId48),
    /// A stale-parent abandonment tombstone. A reorg to/below the original
    /// parent automatically reserves its inputs again.
    Abandoned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon2V8ReservationView {
    pub reservation_id: [u8; 32],
    pub status: Poseidon2V8ReservationStatus,
    /// Both exact input nullifiers are consumed canonically; this does not
    /// identify which competing action consumed them. Reorgs undo the result.
    pub inputs_consumed: bool,
    pub inputs_reserved: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReservedInput {
    commitment: Poseidon2V8Digest,
    nullifier: Poseidon2V8Digest,
    position: u64,
    created_block_hash: [u8; 32],
}

impl ReservedInput {
    fn from_note(note: &Poseidon2V8OwnedNoteView) -> Self {
        Self {
            commitment: note.commitment,
            nullifier: note.nullifier,
            position: note.position,
            created_block_hash: note.created_block_hash,
        }
    }

    fn matches(&self, note: &Poseidon2V8OwnedNoteView) -> bool {
        self.commitment == note.commitment
            && self.nullifier == note.nullifier
            && self.position == note.position
            && self.created_block_hash == note.created_block_hash
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct StoredPoseidon2V8Reservation {
    id: [u8; 32],
    genesis_hash: [u8; 32],
    parent_height: u64,
    parent_hash: [u8; 32],
    inputs: [ReservedInput; 2],
    pub(super) status: Poseidon2V8ReservationStatus,
}

/// Non-cloneable ownership of one atomically selected, durably locked pair.
/// Dropping a pre-submission builder releases its inputs. The blocking prover
/// can finish after cancellation, but owns no submission capability or guard.
pub struct Poseidon2V8SpendReservation<'a> {
    store: &'a WalletStore,
    id: [u8; 32],
    context: Poseidon2V8SpendContext,
}

impl std::fmt::Debug for Poseidon2V8SpendReservation<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Poseidon2V8SpendReservation { inputs: 2 }")
    }
}

impl Poseidon2V8SpendReservation<'_> {
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    pub(crate) fn context(&self) -> &Poseidon2V8SpendContext {
        &self.context
    }

    /// Called synchronously after all transport preflight/awaits and before
    /// polling the actual mutating request. An error prevents that request.
    pub(crate) fn begin_submission(&self) -> Result<(), WalletError> {
        self.store.with_poseidon2_v8_reservations_mut(|state| {
            if state.poseidon2_v8.tip()? != self.context.tip {
                return Err(WalletError::InvalidState(
                    "V8 reservation canonical tip changed before submission",
                ));
            }
            let notes = state.poseidon2_v8.owned_notes()?;
            let record = state
                .poseidon2_v8_reservations
                .iter_mut()
                .find(|record| record.id == self.id)
                .ok_or(WalletError::InvalidState(
                    "V8 reservation missing before submission",
                ))?;
            if record.status != Poseidon2V8ReservationStatus::Proving
                || record
                    .inputs
                    .iter()
                    .any(|input| !notes.iter().any(|note| input.matches(note) && !note.spent))
            {
                return Err(WalletError::InvalidState(
                    "V8 reservation inputs are no longer spendable",
                ));
            }
            record.status = Poseidon2V8ReservationStatus::SubmissionUncertain;
            Ok(())
        })
    }

    pub(crate) fn mark_submitted(&self, tx_id: ActionId48) -> Result<(), WalletError> {
        self.store.with_poseidon2_v8_reservations_mut(|state| {
            let record = state
                .poseidon2_v8_reservations
                .iter_mut()
                .find(|record| record.id == self.id)
                .ok_or(WalletError::InvalidState(
                    "V8 submitted reservation missing",
                ))?;
            if record.status != Poseidon2V8ReservationStatus::SubmissionUncertain {
                return Err(WalletError::InvalidState(
                    "V8 reservation was not prepared for submission",
                ));
            }
            record.status = Poseidon2V8ReservationStatus::Submitted(tx_id);
            Ok(())
        })
    }

    pub fn release(self) -> Result<(), WalletError> {
        self.store.release_poseidon2_v8_proving_reservation(self.id)
    }
}

impl Drop for Poseidon2V8SpendReservation<'_> {
    fn drop(&mut self) {
        // Failure conservatively leaves the durable Proving row in place;
        // the next exclusive open can recover it without a submission risk.
        let _ = self.store.release_poseidon2_v8_proving_reservation(self.id);
    }
}

impl WalletState {
    fn poseidon2_v8_reservation_is_active(&self, record: &StoredPoseidon2V8Reservation) -> bool {
        record.status != Poseidon2V8ReservationStatus::Abandoned
            || self
                .poseidon2_v8
                .tip()
                .map_or(true, |tip| tip.height <= record.parent_height)
    }

    pub(super) fn reserved_poseidon2_v8_nullifiers(&self) -> HashSet<Poseidon2V8Digest> {
        self.poseidon2_v8_reservations
            .iter()
            .filter(|record| self.poseidon2_v8_reservation_is_active(record))
            .flat_map(|record| record.inputs.iter().map(|input| input.nullifier))
            .collect()
    }

    pub(super) fn validate_poseidon2_v8_reservations(&self) -> Result<(), WalletError> {
        let mut ids = HashSet::new();
        let mut inputs = HashSet::new();
        for record in &self.poseidon2_v8_reservations {
            if record.id == [0; 32]
                || record.genesis_hash == [0; 32]
                || !ids.insert(record.id)
                || record.inputs[0].position == record.inputs[1].position
                || record.inputs.iter().any(|input| {
                    input.nullifier == [0; 7]
                        || input
                            .nullifier
                            .iter()
                            .chain(input.commitment.iter())
                            .any(|limb| *limb >= transaction_circuit::constants::FIELD_MODULUS_U64)
                        || (record.status != Poseidon2V8ReservationStatus::Abandoned
                            && !inputs.insert(input.nullifier))
                })
            {
                return Err(WalletError::InvalidState(
                    "invalid or overlapping V8 input reservations",
                ));
            }
        }
        Ok(())
    }
}

impl WalletStore {
    pub fn reserve_poseidon2_v8_spend(
        &self,
    ) -> Result<Poseidon2V8SpendReservation<'_>, WalletError> {
        let (id, context) = self.with_poseidon2_v8_reservations_mut(|state| {
            if state.mode != WalletMode::Full {
                return Err(WalletError::WatchOnly);
            }
            let context = state
                .poseidon2_v8
                .spend_context(&state.reserved_poseidon2_v8_nullifiers())?;
            let genesis_hash = state
                .poseidon2_v8
                .canonical_hash(0)
                .ok_or(WalletError::InvalidState("V8 reservation genesis missing"))?;
            let mut id = [0; 32];
            loop {
                OsRng.fill_bytes(&mut id);
                if id != [0; 32]
                    && !state
                        .poseidon2_v8_reservations
                        .iter()
                        .any(|record| record.id == id)
                {
                    break;
                }
            }
            state
                .poseidon2_v8_reservations
                .push(StoredPoseidon2V8Reservation {
                    id,
                    genesis_hash,
                    parent_height: context.tip.height,
                    parent_hash: context.tip.block_hash,
                    inputs: [
                        ReservedInput::from_note(&context.notes[0]),
                        ReservedInput::from_note(&context.notes[1]),
                    ],
                    status: Poseidon2V8ReservationStatus::Proving,
                });
            Ok((id, context))
        })?;
        Ok(Poseidon2V8SpendReservation {
            store: self,
            id,
            context,
        })
    }

    pub fn poseidon2_v8_reservations(
        &self,
    ) -> Result<Vec<Poseidon2V8ReservationView>, WalletError> {
        self.with_state(|state| {
            Ok(state
                .poseidon2_v8_reservations
                .iter()
                .map(|record| Poseidon2V8ReservationView {
                    reservation_id: record.id,
                    status: record.status,
                    inputs_reserved: state.poseidon2_v8_reservation_is_active(record),
                    inputs_consumed: state.poseidon2_v8.canonical_hash(0)
                        == Some(record.genesis_hash)
                        && record.inputs.iter().all(|input| {
                            state.poseidon2_v8.has_canonical_nullifier(input.nullifier)
                        }),
                })
                .collect())
        })
    }

    /// Explicit reconciliation after authoritative sync to `expected_tip`.
    /// The original exact-parent statement must already be stale, and both
    /// exact inputs must still be canonically owned and unspent. This never
    /// runs on a timeout/timer. A retained tombstone restores the input hold
    /// if a future reorg makes the old exact-parent action eligible again.
    pub fn abandon_poseidon2_v8_reservation(
        &self,
        id: [u8; 32],
        expected_tip: Poseidon2V8CanonicalTip,
    ) -> Result<(), WalletError> {
        self.with_poseidon2_v8_reservations_mut(|state| {
            if state.poseidon2_v8.tip()? != expected_tip {
                return Err(WalletError::InvalidState(
                    "V8 abandonment requires the current canonical tip",
                ));
            }
            let notes = state.poseidon2_v8.owned_notes()?;
            let record = state
                .poseidon2_v8_reservations
                .iter()
                .find(|record| record.id == id)
                .ok_or(WalletError::InvalidState(
                    "V8 reservation missing for abandonment",
                ))?;
            if record.status == Poseidon2V8ReservationStatus::Proving
                || state.poseidon2_v8.canonical_hash(0) != Some(record.genesis_hash)
                || expected_tip.height <= record.parent_height
                || record
                    .inputs
                    .iter()
                    .any(|input| !notes.iter().any(|note| input.matches(note) && !note.spent))
            {
                return Err(WalletError::InvalidState(
                    "V8 submission cannot yet be safely abandoned",
                ));
            }
            let record = state
                .poseidon2_v8_reservations
                .iter_mut()
                .find(|record| record.id == id)
                .ok_or(WalletError::InvalidState(
                    "V8 reservation missing for abandonment",
                ))?;
            record.status = Poseidon2V8ReservationStatus::Abandoned;
            Ok(())
        })
    }

    fn release_poseidon2_v8_proving_reservation(&self, id: [u8; 32]) -> Result<(), WalletError> {
        // Skip a disk rewrite when Drop follows explicit release or submission.
        if !self.with_state(|state| {
            Ok(state.poseidon2_v8_reservations.iter().any(|record| {
                record.id == id && record.status == Poseidon2V8ReservationStatus::Proving
            }))
        })? {
            return Ok(());
        }
        self.with_poseidon2_v8_reservations_mut(|state| {
            state.poseidon2_v8_reservations.retain(|record| {
                record.id != id || record.status != Poseidon2V8ReservationStatus::Proving
            });
            Ok(())
        })
    }

    fn with_poseidon2_v8_reservations_mut<T>(
        &self,
        func: impl FnOnce(&mut WalletState) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        self.ensure_writable()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| WalletError::InvalidState("wallet poisoned"))?;
        let previous = state.poseidon2_v8_reservations.clone();
        let result = match func(&mut state) {
            Ok(value) => value,
            Err(error) => {
                state.poseidon2_v8_reservations = previous;
                return Err(error);
            }
        };
        if let Err(error) = self.write_state(&state) {
            state.poseidon2_v8_reservations = previous;
            return Err(error);
        }
        Ok(result)
    }
}
