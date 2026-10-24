//! Bounded public-only retention of exact RP06 transfer candidates.
#![forbid(unsafe_code)]
use crate::{
    poseidon2_v8_sync::{LaunchWalletContext, Poseidon2V8CanonicalTip},
    ActionId48, WalletError, WalletStore,
};
use protocol_shielded_pool::rp06_transport::{
    decode_rp06_inline_args_exact, Rp06ExpectedContext, RP06_CANDIDATE_MAX_INLINE_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use transaction_circuit::smallwood_poseidon2_v8_rp06::{
    rp06_program_digest, rp06_program_identity_sha512, validate_rp06_transcript_bytes,
    verify_rp06_candidate_bytes, Rp06PublicStatement,
};

fn invalid(message: &'static str) -> WalletError {
    WalletError::InvalidState(message)
}
fn surface(error: impl std::fmt::Debug) -> WalletError {
    WalletError::Serialization(format!("retained RP06 candidate: {error:?}"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rp06TransferCandidateStatus {
    ExternalAmbiguity,
    Submitted(Vec<u8>),
    Abandoned,
}
/// No input opening, spend credential, random tape or private witness is stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredRp06TransferCandidate {
    pub(crate) reservation_id: [u8; 32],
    pub(crate) chain_id: [u8; 32],
    pub(crate) genesis_hash: [u8; 32],
    pub(crate) manifest_digest: Vec<u8>,
    pub(crate) relation_digest: Vec<u8>,
    pub(crate) parent_height: u64,
    pub(crate) parent_hash: [u8; 32],
    pub(crate) anchor: [u64; 7],
    pub(crate) stablecoin_root: Option<[u64; 7]>,
    pub(crate) inline_args: Vec<u8>,
    pub(crate) status: Rp06TransferCandidateStatus,
}
impl StoredRp06TransferCandidate {
    pub(crate) fn new(
        reservation_id: [u8; 32],
        context: LaunchWalletContext,
        tip: Poseidon2V8CanonicalTip,
        inline_args: Vec<u8>,
    ) -> Result<Self, WalletError> {
        let record = Self {
            reservation_id,
            chain_id: context.chain_id(),
            genesis_hash: context.genesis_hash(),
            manifest_digest: context.manifest_digest().to_vec(),
            relation_digest: rp06_program_identity_sha512().to_vec(),
            parent_height: tip.height,
            parent_hash: tip.block_hash,
            anchor: tip.anchor,
            stablecoin_root: tip.stablecoin_root,
            inline_args,
            status: Rp06TransferCandidateStatus::ExternalAmbiguity,
        };
        record.validate(context)?;
        Ok(record)
    }
    /// Pure bounded validation, suitable for encrypted-state validation under its lock.
    pub(crate) fn validate(&self, context: LaunchWalletContext) -> Result<(), WalletError> {
        if self.reservation_id == [0; 32]
            || self.parent_hash == [0; 32]
            || self.chain_id != context.chain_id()
            || self.genesis_hash != context.genesis_hash()
            || self.manifest_digest.as_slice() != context.manifest_digest()
            || self.relation_digest.as_slice() != rp06_program_identity_sha512()
            || self.inline_args.len() > RP06_CANDIDATE_MAX_INLINE_BYTES
        {
            return Err(invalid(
                "retained RP06 candidate identity/size differs from pinned wallet",
            ));
        }
        context.require_canonical_parent(self.genesis_hash, self.parent_height)?;
        if let Rp06TransferCandidateStatus::Submitted(action) = &self.status {
            if action.len() != 48 {
                return Err(invalid("retained RP06 submitted action length"));
            }
        }
        let expected =
            Rp06ExpectedContext::new(self.chain_id, rp06_program_digest()).map_err(surface)?;
        let decoded =
            decode_rp06_inline_args_exact(expected, &self.inline_args).map_err(surface)?;
        validate_rp06_transcript_bytes(decoded.native_leaf().preamble()).map_err(surface)?;
        let statement =
            Rp06PublicStatement::try_from_public_words(&decoded.native_leaf().public_words())
                .map_err(surface)?;
        if statement.base.stablecoin.parent_height != self.parent_height
            || statement.base.merkle_root != self.anchor
            || statement
                .base
                .stablecoin
                .before_root
                .map(|word| word.as_canonical_u64())
                != self.stablecoin_root.unwrap_or([0; 7])
        {
            return Err(invalid(
                "retained RP06 parent differs from exact candidate statement",
            ));
        }
        Ok(())
    }
    fn verify(&self, context: LaunchWalletContext) -> Result<(), WalletError> {
        self.validate(context)?;
        let decoded = decode_rp06_inline_args_exact(
            Rp06ExpectedContext::new(self.chain_id, rp06_program_digest()).map_err(surface)?,
            &self.inline_args,
        )
        .map_err(surface)?;
        let leaf = decoded.native_leaf();
        verify_rp06_candidate_bytes(
            &leaf.public_words(),
            leaf.relation_digest(),
            leaf.proof(),
            self.chain_id,
        )
        .map_err(surface)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rp06TransferCandidateExport {
    pub reservation_id: [u8; 32],
    pub parent_height: u64,
    pub parent_hash: [u8; 32],
    pub inline_args: Vec<u8>,
    pub carrier_sha512: [u8; 64],
    pub status: Rp06TransferCandidateStatus,
    pub current_parent: bool,
    tip: Poseidon2V8CanonicalTip,
}
impl Rp06TransferCandidateExport {
    pub fn reservation_id(&self) -> [u8; 32] {
        self.reservation_id
    }
    pub fn inline_args(&self) -> &[u8] {
        &self.inline_args
    }
    pub fn tip(&self) -> Poseidon2V8CanonicalTip {
        self.tip
    }
    pub fn carrier_sha512(&self) -> [u8; 64] {
        self.carrier_sha512
    }
    /// The captured canonical reference is at most 12 parents old and every
    /// exact input remains held and unspent in the current wallet mirror.
    pub fn current_parent_eligible(&self) -> bool {
        self.current_parent
    }
}

impl WalletStore {
    pub(crate) fn retain_rp06_transfer_candidate(
        &self,
        context: LaunchWalletContext,
        record: StoredRp06TransferCandidate,
    ) -> Result<(), WalletError> {
        record.validate(context)?;
        let locked = self
            .poseidon2_v8_reservations()?
            .into_iter()
            .find(|entry| entry.reservation_id == record.reservation_id)
            .ok_or(invalid(
                "retained RP06 candidate has no durable input reservation",
            ))?;
        if !matches!(
            locked.status,
            crate::store::Poseidon2V8ReservationStatus::SubmissionUncertain
                | crate::store::Poseidon2V8ReservationStatus::Submitted(_)
        ) {
            return Err(invalid(
                "retained RP06 export requires durable external ambiguity",
            ));
        }
        self.with_rp06_transfers_mut(context, |records| {
            if let Some(existing) = records
                .iter()
                .find(|entry| entry.reservation_id == record.reservation_id)
            {
                if existing.inline_args == record.inline_args
                    && existing.chain_id == record.chain_id
                    && existing.parent_hash == record.parent_hash
                    && existing.parent_height == record.parent_height
                {
                    return Ok(());
                }
                return Err(invalid(
                    "RP06 reservation cannot retain different candidate bytes",
                ));
            }
            records.push(record);
            Ok(())
        })
    }
    pub fn rp06_transfer_candidate_ids(&self) -> Result<Vec<[u8; 32]>, WalletError> {
        let context = self.launch_context()?;
        self.with_rp06_transfers(context, |records| {
            Ok(records.iter().map(|record| record.reservation_id).collect())
        })
    }
    pub fn export_rp06_transfer_candidate(
        &self,
        id: [u8; 32],
    ) -> Result<Rp06TransferCandidateExport, WalletError> {
        self.export_rp06_transfer_candidate_inner(id, true)
    }
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn export_rp06_transfer_candidate_for_retained_test(
        &self,
        id: [u8; 32],
    ) -> Result<Rp06TransferCandidateExport, WalletError> {
        self.export_rp06_transfer_candidate_inner(id, false)
    }
    fn export_rp06_transfer_candidate_inner(
        &self,
        id: [u8; 32],
        authority: bool,
    ) -> Result<Rp06TransferCandidateExport, WalletError> {
        let context = self.launch_context()?;
        let record = self.with_rp06_transfers(context, |records| {
            records
                .iter()
                .find(|record| record.reservation_id == id)
                .cloned()
                .ok_or(invalid("unknown retained RP06 candidate"))
        })?;
        if record.status == Rp06TransferCandidateStatus::Abandoned {
            return Err(invalid("abandoned RP06 candidate cannot be exported again"));
        }
        let captured_tip = Poseidon2V8CanonicalTip {
            height: record.parent_height,
            block_hash: record.parent_hash,
            anchor: record.anchor,
            stablecoin_root: record.stablecoin_root,
        };
        self.require_rp06_canonical_reference(context, captured_tip)?;
        record.verify(context)?;
        let decoded = decode_rp06_inline_args_exact(
            Rp06ExpectedContext::new(record.chain_id, rp06_program_digest()).map_err(surface)?,
            &record.inline_args,
        )
        .map_err(surface)?;
        let reservation = self
            .poseidon2_v8_reservations()?
            .into_iter()
            .find(|entry| entry.reservation_id == id)
            .ok_or(invalid("RP06 retained input reservation is missing"))?;
        if matches!(
            reservation.status,
            crate::store::Poseidon2V8ReservationStatus::Proving
                | crate::store::Poseidon2V8ReservationStatus::Abandoned
        ) {
            return Err(invalid("RP06 retained candidate is not durably exportable"));
        }
        // Recheck after proof verification against one fresh pinned snapshot.
        let inclusion_height = self.require_rp06_canonical_reference(context, captured_tip)?;
        if authority {
            crate::rp06_transfer::require_rp06_authority(
                context,
                inclusion_height,
                decoded.native_leaf().proof().len(),
            )?;
        }
        let carrier_sha512 = Sha512::digest(&record.inline_args).into();
        Ok(Rp06TransferCandidateExport {
            reservation_id: id,
            parent_height: record.parent_height,
            parent_hash: record.parent_hash,
            inline_args: record.inline_args,
            carrier_sha512,
            status: record.status,
            current_parent: reservation.inputs_reserved && !reservation.inputs_consumed,
            tip: captured_tip,
        })
    }
    pub fn mark_rp06_transfer_candidate_submitted(
        &self,
        id: [u8; 32],
        action_id: ActionId48,
    ) -> Result<(), WalletError> {
        let context = self.launch_context()?;
        let bytes = action_id.as_bytes().to_vec();
        self.with_rp06_transfers(context, |records| {
            let record = records
                .iter()
                .find(|record| record.reservation_id == id)
                .ok_or(invalid("unknown retained RP06 candidate"))?;
            record.validate(context)?;
            match &record.status {
                Rp06TransferCandidateStatus::ExternalAmbiguity => Ok(()),
                Rp06TransferCandidateStatus::Submitted(previous) if previous == &bytes => Ok(()),
                _ => Err(invalid(
                    "RP06 acknowledgement differs from retained candidate",
                )),
            }
        })?;
        self.mark_poseidon2_v8_reserved_submitted(id, action_id)?;
        self.with_rp06_transfers_mut(context, |records| {
            let record = records
                .iter_mut()
                .find(|record| record.reservation_id == id)
                .ok_or(invalid("unknown retained RP06 candidate"))?;
            match &record.status {
                Rp06TransferCandidateStatus::ExternalAmbiguity => {
                    record.status = Rp06TransferCandidateStatus::Submitted(bytes)
                }
                Rp06TransferCandidateStatus::Submitted(previous) if previous == &bytes => {}
                _ => return Err(invalid("RP06 submitted candidate status cannot change")),
            }
            Ok(())
        })
    }
    /// Abandon only after the last eligible inclusion parent and authoritative
    /// reconciliation of every exact unspent input. Retain both tombstones so a
    /// reorg into the reference window restores the input hold.
    pub fn abandon_rp06_transfer_candidate(&self, id: [u8; 32]) -> Result<(), WalletError> {
        let context = self.launch_context()?;
        let last_parent = self.with_rp06_transfers(context, |records| {
            let record = records
                .iter()
                .find(|record| record.reservation_id == id)
                .ok_or(invalid("unknown retained RP06 candidate"))?;
            record.validate(context)?;
            record
                .parent_height
                .checked_add(protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW)
                .ok_or(invalid("RP06 abandonment reference height overflow"))
        })?;
        let current_tip = self.poseidon2_v8_tip()?;
        if current_tip.height <= last_parent {
            return Err(invalid(
                "RP06 candidate remains inside its inclusion window",
            ));
        }
        self.abandon_poseidon2_v8_reservation(id, current_tip)?;
        self.with_rp06_transfers_mut(context, |records| {
            records
                .iter_mut()
                .find(|record| record.reservation_id == id)
                .ok_or(invalid("unknown retained RP06 candidate"))?
                .status = Rp06TransferCandidateStatus::Abandoned;
            Ok(())
        })
    }
}
