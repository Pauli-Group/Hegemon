//! Prospective Kernel V5/Delta action projection for the HGS2 statement.
//!
//! These types are not the active `PendingAction` or shielded-pool wire. They
//! deliberately use a new action id and have no production registration.

use super::*;

pub const PROSPECTIVE_KERNEL_CIRCUIT_V5: u16 = 5;
pub const PROSPECTIVE_CRYPTO_SUITE_DELTA: u16 = 4;
pub const PROSPECTIVE_SHIELDED_FAMILY_ID: u16 = 1;
/// Deliberately distinct from the active shielded-inline action id `1`.
pub const PROSPECTIVE_PAY1X2_INLINE_ACTION_ID: u16 = 7;
pub const PROSPECTIVE_NATIVE_BALANCE_SLOT_COUNT: usize = 4;
pub const PROSPECTIVE_NATIVE_BALANCE_SLOTS: [u64; PROSPECTIVE_NATIVE_BALANCE_SLOT_COUNT] =
    [NATIVE_ASSET_ID, u64::MAX, u64::MAX, u64::MAX];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProspectiveKernelBinding {
    pub circuit: u16,
    pub crypto: u16,
}

pub const PROSPECTIVE_KERNEL_V5_DELTA: ProspectiveKernelBinding = ProspectiveKernelBinding {
    circuit: PROSPECTIVE_KERNEL_CIRCUIT_V5,
    crypto: PROSPECTIVE_CRYPTO_SUITE_DELTA,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ProspectiveFamilyId(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ProspectiveActionId(pub u16);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProspectiveStablecoinBinding {
    pub opaque_marker: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProspectiveCandidateArtifact {
    pub opaque_bytes: Vec<u8>,
}

/// Exact-decoded prospective inline action projection.
///
/// `CanonicalCiphertextBytes` means the caller has already exact-decoded and
/// canonically re-encoded each ciphertext under the selected wallet grammar.
/// Vectors are retained intentionally: verifier code must reject malformed
/// counts instead of obtaining correctness from Rust array types alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProspectivePay1x2InlineAction<'a> {
    pub kernel_binding: ProspectiveKernelBinding,
    pub family_id: ProspectiveFamilyId,
    pub action_id: ProspectiveActionId,
    pub ciphertexts: Vec<CanonicalCiphertextBytes<'a>>,
    pub ciphertext_sizes: Vec<u32>,
    pub nullifiers: Vec<Nullifier>,
    pub commitments: Vec<NoteCommitment>,
    pub anchor: MerkleRoot,
    pub fee: u64,
    pub balance_slot_asset_ids: Vec<u64>,
    pub value_balance: i128,
    pub stablecoin: Option<ProspectiveStablecoinBinding>,
    pub candidate_artifact: Option<ProspectiveCandidateArtifact>,
    pub network_binding: NetworkBinding56,
    pub binding_digest: [u8; STATEMENT_BINDING_BYTES],
}

impl<'a> ProspectivePay1x2InlineAction<'a> {
    /// Construct the one canonical prospective action projection from already
    /// typed relation fields and exact-decoded ciphertexts.
    pub fn from_relation(
        relation: &Pay1x2Statement,
        ciphertexts: [CanonicalCiphertextBytes<'a>; OUTPUT_COUNT as usize],
        network: NetworkIdentity,
    ) -> Result<Self, ActionProjectionError> {
        let statement = adapt_action(relation, ciphertexts, network)?;
        let sizes = [
            u32::try_from(ciphertexts[0].as_bytes().len())
                .map_err(|_| ActionProjectionError::CiphertextSizeOverflow(0))?,
            u32::try_from(ciphertexts[1].as_bytes().len())
                .map_err(|_| ActionProjectionError::CiphertextSizeOverflow(1))?,
        ];
        Ok(Self {
            kernel_binding: PROSPECTIVE_KERNEL_V5_DELTA,
            family_id: ProspectiveFamilyId(PROSPECTIVE_SHIELDED_FAMILY_ID),
            action_id: ProspectiveActionId(PROSPECTIVE_PAY1X2_INLINE_ACTION_ID),
            ciphertexts: ciphertexts.to_vec(),
            ciphertext_sizes: sizes.to_vec(),
            nullifiers: vec![relation.nullifier],
            commitments: relation.output_commitments.to_vec(),
            anchor: relation.anchor,
            fee: relation.fee,
            balance_slot_asset_ids: PROSPECTIVE_NATIVE_BALANCE_SLOTS.to_vec(),
            value_balance: 0,
            stablecoin: None,
            candidate_artifact: None,
            network_binding: statement.network_binding,
            binding_digest: statement.binding_digest(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionProjectionError {
    Statement(AdapterError),
    KernelBindingMismatch,
    FamilyIdMismatch(u16),
    ActionIdMismatch(u16),
    CiphertextCount(usize),
    CiphertextSizeCount(usize),
    CiphertextSizeOverflow(usize),
    CiphertextSizeMismatch {
        slot: usize,
        declared: u32,
        actual: usize,
    },
    NullifierCount(usize),
    CommitmentCount(usize),
    BalanceSlotCount(usize),
    BalanceSlotAssetMismatch {
        slot: usize,
        expected: u64,
        actual: u64,
    },
    NonzeroValueBalance(i128),
    StablecoinPresent,
    CandidateArtifactPresent,
    RelationMismatch(&'static str),
    NetworkBindingMismatch,
    BindingDigestMismatch,
    CanonicalStatementMismatch,
}

impl From<AdapterError> for ActionProjectionError {
    fn from(value: AdapterError) -> Self {
        Self::Statement(value)
    }
}

impl core::fmt::Display for ActionProjectionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Statement(error) => write!(formatter, "statement adapter rejected: {error}"),
            Self::KernelBindingMismatch => {
                formatter.write_str("action is not bound to prospective Kernel V5/Delta")
            }
            Self::FamilyIdMismatch(value) => write!(
                formatter,
                "action family {value} is not the prospective shielded family"
            ),
            Self::ActionIdMismatch(value) => write!(
                formatter,
                "action id {value:#06x} is not the prospective Pay1x2 inline route"
            ),
            Self::CiphertextCount(actual) => {
                write!(formatter, "action has {actual} ciphertexts; expected 2")
            }
            Self::CiphertextSizeCount(actual) => {
                write!(
                    formatter,
                    "action has {actual} ciphertext sizes; expected 2"
                )
            }
            Self::CiphertextSizeOverflow(slot) => {
                write!(formatter, "ciphertext {slot} size does not fit u32")
            }
            Self::CiphertextSizeMismatch {
                slot,
                declared,
                actual,
            } => write!(
                formatter,
                "ciphertext {slot} declares {declared} bytes but carries {actual}"
            ),
            Self::NullifierCount(actual) => {
                write!(formatter, "action has {actual} nullifiers; expected 1")
            }
            Self::CommitmentCount(actual) => {
                write!(formatter, "action has {actual} commitments; expected 2")
            }
            Self::BalanceSlotCount(actual) => {
                write!(formatter, "action has {actual} balance slots; expected 4")
            }
            Self::BalanceSlotAssetMismatch {
                slot,
                expected,
                actual,
            } => write!(
                formatter,
                "balance slot {slot} is {actual}; expected canonical asset id {expected}"
            ),
            Self::NonzeroValueBalance(value) => {
                write!(formatter, "Pay1x2 value_balance must be zero, got {value}")
            }
            Self::StablecoinPresent => {
                formatter.write_str("stablecoin binding is forbidden in Pay1x2")
            }
            Self::CandidateArtifactPresent => {
                formatter.write_str("candidate artifact is forbidden in direct Pay1x2")
            }
            Self::RelationMismatch(field) => {
                write!(formatter, "action and HGS2 relation disagree on {field}")
            }
            Self::NetworkBindingMismatch => {
                formatter.write_str("action network binding does not match expected network")
            }
            Self::BindingDigestMismatch => {
                formatter.write_str("action binding digest does not equal the HGS2 digest")
            }
            Self::CanonicalStatementMismatch => {
                formatter.write_str("action-derived statement differs from supplied HGS2 bytes")
            }
        }
    }
}

impl std::error::Error for ActionProjectionError {}

/// Validate the prospective route and reconstruct its unique HGS2 statement.
pub fn adapt_canonical_action(
    action: &ProspectivePay1x2InlineAction<'_>,
    expected_network: NetworkIdentity,
) -> Result<CanonicalPay1x2Statement, ActionProjectionError> {
    validate_action_shape(action)?;
    let relation = relation_from_action(action);
    let ciphertexts = [action.ciphertexts[0], action.ciphertexts[1]];
    let statement = adapt_action(&relation, ciphertexts, expected_network)?;
    if action.network_binding != statement.network_binding {
        return Err(ActionProjectionError::NetworkBindingMismatch);
    }
    if action.binding_digest != statement.binding_digest() {
        return Err(ActionProjectionError::BindingDigestMismatch);
    }
    Ok(statement)
}

/// Verify an exact prospective action projection against exact HGS2 bytes.
pub fn verify_canonical_action_statement(
    action: &ProspectivePay1x2InlineAction<'_>,
    canonical_statement: &[u8],
    expected_network: NetworkIdentity,
) -> Result<CanonicalPay1x2Statement, ActionProjectionError> {
    let action_statement = adapt_canonical_action(action, expected_network)?;
    let decoded = decode_exact(canonical_statement)?;
    if decoded != action_statement {
        return Err(ActionProjectionError::CanonicalStatementMismatch);
    }

    let relation = relation_from_action(action);
    let verified = verify_action_statement(
        canonical_statement,
        &relation,
        [action.ciphertexts[0], action.ciphertexts[1]],
        expected_network,
    )?;
    if action.anchor != verified.anchor {
        return Err(ActionProjectionError::RelationMismatch("anchor"));
    }
    if action.nullifiers[0] != verified.nullifier {
        return Err(ActionProjectionError::RelationMismatch("nullifier"));
    }
    if action.commitments[0] != verified.output_commitments[0]
        || action.commitments[1] != verified.output_commitments[1]
    {
        return Err(ActionProjectionError::RelationMismatch(
            "ordered output commitments",
        ));
    }
    if action.fee != verified.monetary.fee.get() {
        return Err(ActionProjectionError::RelationMismatch("fee"));
    }
    Ok(verified)
}

fn validate_action_shape(
    action: &ProspectivePay1x2InlineAction<'_>,
) -> Result<(), ActionProjectionError> {
    if action.kernel_binding != PROSPECTIVE_KERNEL_V5_DELTA {
        return Err(ActionProjectionError::KernelBindingMismatch);
    }
    if action.family_id.0 != PROSPECTIVE_SHIELDED_FAMILY_ID {
        return Err(ActionProjectionError::FamilyIdMismatch(action.family_id.0));
    }
    if action.action_id.0 != PROSPECTIVE_PAY1X2_INLINE_ACTION_ID {
        return Err(ActionProjectionError::ActionIdMismatch(action.action_id.0));
    }
    if action.ciphertexts.len() != OUTPUT_COUNT as usize {
        return Err(ActionProjectionError::CiphertextCount(
            action.ciphertexts.len(),
        ));
    }
    if action.ciphertext_sizes.len() != OUTPUT_COUNT as usize {
        return Err(ActionProjectionError::CiphertextSizeCount(
            action.ciphertext_sizes.len(),
        ));
    }
    for slot in 0..OUTPUT_COUNT as usize {
        let actual = action.ciphertexts[slot].as_bytes().len();
        if usize::try_from(action.ciphertext_sizes[slot]).ok() != Some(actual) {
            return Err(ActionProjectionError::CiphertextSizeMismatch {
                slot,
                declared: action.ciphertext_sizes[slot],
                actual,
            });
        }
    }
    if action.nullifiers.len() != INPUT_COUNT as usize {
        return Err(ActionProjectionError::NullifierCount(
            action.nullifiers.len(),
        ));
    }
    if action.commitments.len() != OUTPUT_COUNT as usize {
        return Err(ActionProjectionError::CommitmentCount(
            action.commitments.len(),
        ));
    }
    if action.balance_slot_asset_ids.len() != PROSPECTIVE_NATIVE_BALANCE_SLOT_COUNT {
        return Err(ActionProjectionError::BalanceSlotCount(
            action.balance_slot_asset_ids.len(),
        ));
    }
    for (slot, (actual, expected)) in action
        .balance_slot_asset_ids
        .iter()
        .zip(PROSPECTIVE_NATIVE_BALANCE_SLOTS)
        .enumerate()
    {
        if *actual != expected {
            return Err(ActionProjectionError::BalanceSlotAssetMismatch {
                slot,
                expected,
                actual: *actual,
            });
        }
    }
    if action.value_balance != 0 {
        return Err(ActionProjectionError::NonzeroValueBalance(
            action.value_balance,
        ));
    }
    if action.stablecoin.is_some() {
        return Err(ActionProjectionError::StablecoinPresent);
    }
    if action.candidate_artifact.is_some() {
        return Err(ActionProjectionError::CandidateArtifactPresent);
    }
    NativeFee::new(action.fee)?;
    Ok(())
}

fn relation_from_action(action: &ProspectivePay1x2InlineAction<'_>) -> Pay1x2Statement {
    Pay1x2Statement {
        anchor: action.anchor,
        nullifier: action.nullifiers[0],
        output_commitments: [action.commitments[0], action.commitments[1]],
        fee: action.fee,
    }
}
