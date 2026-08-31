//! Canonical 125-call Poseidon2 V8 transaction hash schedule.
//!
//! This module materializes prover trace inputs and exports verifier-shape
//! source descriptors.  It does not validate transaction semantics and does
//! not authorize a proof route.  The executable relation compiler must turn
//! every exported source and final binding into constraints.

#![forbid(unsafe_code)]

use hegemon_field::GOLDILOCKS_MODULUS;
use thiserror::Error;
use transaction_core::{
    constants::{MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG},
    poseidon2_width16::{
        poseidon2_width16_compress14, poseidon2_width16_permutation, Felt,
        POSEIDON2_WIDTH16_DIGEST, POSEIDON2_WIDTH16_RATE, POSEIDON2_WIDTH16_SPONGE_MODE_MARKER,
        POSEIDON2_WIDTH16_SUITE_MARKER, POSEIDON2_WIDTH16_WIDTH,
    },
    stablecoin_poseidon2_v8::{
        StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Counters,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_0,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_1,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_2,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_3,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_0, STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_1,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_ROOT,
        STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_AUTHORIZATION,
        STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_COMMITMENT,
        STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_LEAF, STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_NODE_0,
    },
};

use crate::{
    smallwood_frontend::SmallwoodPrivateAuthMode,
    smallwood_poseidon2_v8_hash_constraints::{
        build_smallwood_poseidon2_v8_hash_rows, SmallwoodPoseidon2V8HashConstraintError,
        SmallwoodPoseidon2V8HashRows, SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT,
        SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALL_COUNT,
    },
    smallwood_poseidon2_v8_types::{
        SmallwoodPoseidon2V8AccumulatorOpening, SmallwoodPoseidon2V8Digest,
        SmallwoodPoseidon2V8NoteOpening, SmallwoodPoseidon2V8PublicStatement,
        SmallwoodPoseidon2V8Witness, SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_DOMAIN,
        SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH,
    },
};

pub const SMALLWOOD_POSEIDON2_V8_SCHEDULE_LIVE_CALLS: usize = 125;
pub const SMALLWOOD_POSEIDON2_V8_SCHEDULE_PADDED_CALLS: usize = 128;
pub const SMALLWOOD_POSEIDON2_V8_AUTH_POLICY_DOMAIN: u64 = 7;
pub const SMALLWOOD_POSEIDON2_V8_AUTH_ACCUMULATOR_DOMAIN: u64 = 6;
pub const SMALLWOOD_POSEIDON2_V8_AUTH_VALUE_LOCK_DOMAIN: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8HashRoleRange {
    pub name: &'static str,
    pub start: usize,
    pub end: usize,
}

/// Gap-free canonical live-call order.  The three padding calls are outside
/// these ranges at `[125,128)`.
pub const SMALLWOOD_POSEIDON2_V8_HASH_ROLE_RANGES: [SmallwoodPoseidon2V8HashRoleRange; 20] = [
    SmallwoodPoseidon2V8HashRoleRange {
        name: "transaction_prf",
        start: 0,
        end: 1,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "input_0_note",
        start: 1,
        end: 4,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "input_0_merkle",
        start: 4,
        end: 36,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "input_0_nullifier",
        start: 36,
        end: 37,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "input_1_note",
        start: 37,
        end: 40,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "input_1_merkle",
        start: 40,
        end: 72,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "input_1_nullifier",
        start: 72,
        end: 73,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "output_0_note",
        start: 73,
        end: 76,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "output_1_note",
        start: 76,
        end: 79,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "action_intent",
        start: 79,
        end: 94,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "authorization_policy",
        start: 94,
        end: 98,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "authorization_current",
        start: 98,
        end: 101,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "authorization_next",
        start: 101,
        end: 104,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "authorization_value_lock",
        start: 104,
        end: 106,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "stable_config_chunks",
        start: 106,
        end: 110,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "stable_config_tree",
        start: 110,
        end: 113,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "stable_state_leaves",
        start: 113,
        end: 115,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "stable_paths",
        start: 115,
        end: 123,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "stable_issuer_commitment",
        start: 123,
        end: 124,
    },
    SmallwoodPoseidon2V8HashRoleRange {
        name: "stable_issuer_authorization",
        start: 124,
        end: 125,
    },
];

const _: () =
    assert!(SMALLWOOD_POSEIDON2_V8_SCHEDULE_LIVE_CALLS == SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT);
const _: () = assert!(
    SMALLWOOD_POSEIDON2_V8_SCHEDULE_PADDED_CALLS == SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALL_COUNT
);
const _: () = assert!(POSEIDON2_WIDTH16_DIGEST == 7);
const _: () = assert!(POSEIDON2_WIDTH16_RATE == 8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8NoteWordRef {
    Value,
    AssetId,
    RecipientKey { limb: usize },
    Rho { limb: usize },
    Randomness { limb: usize },
    AuthorizationKey { limb: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8AccumulatorWordRef {
    PolicyRoot { limb: usize },
    IntentDigest { limb: usize },
    Threshold,
    SignerCount,
    ApprovalCount,
    ApprovedSlot { slot: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8StableConfigWordRef {
    AssetId,
    PolicyVersion,
    Active,
    EnabledAt,
    RetiredPresent,
    RetiredAt,
    IssuerCommitment { limb: usize },
    MinCollateralRatioPpm,
    MaxMintPerEpoch,
    OracleSubmittedAt,
    OracleMaxAge,
    OraclePriceNumerator,
    OraclePriceDenominator,
    CollateralAmount,
    AttestationCreatedAt,
    AttestationDisputed,
    AttestationPresent,
    AttestationMaxAge,
    PolicyAdminCommitment { limb: usize },
    OracleAuthorityCommitment { limb: usize },
    AttestationAuthorityCommitment { limb: usize },
    CollateralAssetId,
    CollateralDecimals,
    CollateralScale,
    LockedCollateralCommitment { limb: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8CounterWordRef {
    EpochId,
    MintedInEpoch,
    TotalDebt,
    Sequence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8SemanticWordRef {
    TransactionSpendKey {
        limb: usize,
    },
    InputAuthorizationPrf {
        input: usize,
    },
    InputNote {
        input: usize,
        word: SmallwoodPoseidon2V8NoteWordRef,
    },
    InputPosition {
        input: usize,
    },
    InputSibling {
        input: usize,
        level: usize,
        limb: usize,
    },
    OutputNote {
        output: usize,
        word: SmallwoodPoseidon2V8NoteWordRef,
    },
    ActionIntentProjectionWord {
        word: usize,
    },
    AuthorizationPolicyThreshold,
    AuthorizationPolicySignerCount,
    AuthorizationPolicySignerTag {
        slot: usize,
        limb: usize,
    },
    AuthorizationCurrent {
        word: SmallwoodPoseidon2V8AccumulatorWordRef,
    },
    AuthorizationNext {
        word: SmallwoodPoseidon2V8AccumulatorWordRef,
    },
    StableConfig {
        word: SmallwoodPoseidon2V8StableConfigWordRef,
    },
    StableBeforeCounter {
        word: SmallwoodPoseidon2V8CounterWordRef,
    },
    StableAfterCounter {
        word: SmallwoodPoseidon2V8CounterWordRef,
    },
    StableAssetIndex,
    StableSibling {
        level: usize,
        limb: usize,
    },
    StableIssuerSecret {
        limb: usize,
    },
    StablePublicAssetId,
    StablePublicPolicyVersion,
    StablePublicActionIntent {
        limb: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8MerklePathRef {
    TransactionInput { input: usize },
    StableBefore,
    StableAfter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8MerkleSide {
    Left,
    Right,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8HashLaneTerm {
    Semantic(SmallwoodPoseidon2V8SemanticWordRef),
    CallFinal {
        call: usize,
        lane: usize,
    },
    OrientedMerkleOperand {
        path: SmallwoodPoseidon2V8MerklePathRef,
        level: usize,
        side: SmallwoodPoseidon2V8MerkleSide,
        limb: usize,
    },
}

/// One initial-state lane as a verifier-shape field expression.  At most one
/// prior-call lane and one semantic source are added, plus a canonical
/// constant.  Merkle orientation is represented as one derived term whose
/// selector constraints are owned by the relation compiler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8HashLaneBinding {
    pub terms: [Option<SmallwoodPoseidon2V8HashLaneTerm>; 2],
    pub constant: u64,
}

impl SmallwoodPoseidon2V8HashLaneBinding {
    pub const ZERO: Self = Self {
        terms: [None, None],
        constant: 0,
    };

    const fn constant(value: u64) -> Self {
        Self {
            terms: [None, None],
            constant: value,
        }
    }

    const fn term(term: SmallwoodPoseidon2V8HashLaneTerm) -> Self {
        Self {
            terms: [Some(term), None],
            constant: 0,
        }
    }

    const fn call_plus_source(
        call: usize,
        lane: usize,
        source: Option<SmallwoodPoseidon2V8SemanticWordRef>,
        constant: u64,
    ) -> Self {
        Self {
            terms: [
                Some(SmallwoodPoseidon2V8HashLaneTerm::CallFinal { call, lane }),
                match source {
                    Some(source) => Some(SmallwoodPoseidon2V8HashLaneTerm::Semantic(source)),
                    None => None,
                },
            ],
            constant,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8HashCallMode {
    Sponge,
    Compress14,
    Padding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8HashCallRole {
    TransactionPrf,
    InputNote { input: usize, block: usize },
    InputMerkle { input: usize, level: usize },
    InputNullifier { input: usize },
    OutputNote { output: usize, block: usize },
    ActionIntent { block: usize },
    AuthorizationPolicy { block: usize },
    AuthorizationCurrent { block: usize },
    AuthorizationNext { block: usize },
    AuthorizationValueLock { block: usize },
    StableConfigChunk { chunk: usize },
    StableConfigNode { node: usize },
    StableStateLeaf { after: bool },
    StablePath { after: bool, level: usize },
    StableIssuerCommitment,
    StableIssuerAuthorization,
    Padding { lane: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8HashDigestRef {
    TransactionPrf,
    InputNote { input: usize },
    InputMerkleNode { input: usize, level: usize },
    InputNullifier { input: usize },
    OutputNote { output: usize },
    ActionIntent,
    AuthorizationPolicy,
    AuthorizationCurrent,
    AuthorizationNext,
    AuthorizationValueLock,
    StableConfigChunk { chunk: usize },
    StableConfigNode { node: usize },
    StableStateLeaf { after: bool },
    StablePathNode { after: bool, level: usize },
    StableIssuerCommitment,
    StableIssuerAuthorization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8HashFinalBinding {
    NextSpongeCall { call: usize },
    Digest(SmallwoodPoseidon2V8HashDigestRef),
    Padding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8HashCall {
    pub index: usize,
    pub mode: SmallwoodPoseidon2V8HashCallMode,
    pub role: SmallwoodPoseidon2V8HashCallRole,
    pub initial_bindings: [SmallwoodPoseidon2V8HashLaneBinding; POSEIDON2_WIDTH16_WIDTH],
    pub initial_state: [u64; POSEIDON2_WIDTH16_WIDTH],
    pub final_state: [u64; POSEIDON2_WIDTH16_WIDTH],
    pub final_binding: SmallwoodPoseidon2V8HashFinalBinding,
}

impl SmallwoodPoseidon2V8HashCall {
    pub fn final_digest(self) -> SmallwoodPoseidon2V8Digest {
        self.final_state[..POSEIDON2_WIDTH16_DIGEST]
            .try_into()
            .expect("the V8 digest occupies seven final-state lanes")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8HashScheduleMaterial {
    pub calls: Box<[SmallwoodPoseidon2V8HashCall; SMALLWOOD_POSEIDON2_V8_SCHEDULE_PADDED_CALLS]>,
    pub packed_rows: SmallwoodPoseidon2V8HashRows,
}

impl SmallwoodPoseidon2V8HashScheduleMaterial {
    pub fn live_calls(
        &self,
    ) -> &[SmallwoodPoseidon2V8HashCall; SMALLWOOD_POSEIDON2_V8_SCHEDULE_LIVE_CALLS] {
        self.calls[..SMALLWOOD_POSEIDON2_V8_SCHEDULE_LIVE_CALLS]
            .try_into()
            .expect("the schedule has exactly 125 live calls")
    }

    pub fn initial_states(
        &self,
    ) -> [[u64; POSEIDON2_WIDTH16_WIDTH]; SMALLWOOD_POSEIDON2_V8_SCHEDULE_LIVE_CALLS] {
        core::array::from_fn(|call| self.calls[call].initial_state)
    }

    pub fn final_digests(
        &self,
    ) -> [SmallwoodPoseidon2V8Digest; SMALLWOOD_POSEIDON2_V8_SCHEDULE_LIVE_CALLS] {
        core::array::from_fn(|call| self.calls[call].final_digest())
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8HashScheduleError {
    #[error("public word {index} is not canonical")]
    NonCanonicalPublicWord { index: usize },
    #[error("witness word {index} is not canonical")]
    NonCanonicalWitnessWord { index: usize },
    #[error("internal V8 hash schedule has {actual} calls, expected {expected}")]
    WrongCallCount { expected: usize, actual: usize },
    #[error("internal V8 sponge role count is {actual}, expected {expected}")]
    WrongSpongeRoleCount { expected: usize, actual: usize },
    #[error("canonical compress14 trace disagrees with its final digest")]
    CompressTraceMismatch,
    #[error("V8 packed hash trace material failed: {0}")]
    HashRows(SmallwoodPoseidon2V8HashConstraintError),
}

impl From<SmallwoodPoseidon2V8HashConstraintError> for SmallwoodPoseidon2V8HashScheduleError {
    fn from(value: SmallwoodPoseidon2V8HashConstraintError) -> Self {
        Self::HashRows(value)
    }
}

#[derive(Clone, Copy)]
struct BoundWord {
    value: u64,
    term: Option<SmallwoodPoseidon2V8HashLaneTerm>,
}

impl BoundWord {
    const ZERO: Self = Self {
        value: 0,
        term: None,
    };

    const fn semantic(value: u64, source: SmallwoodPoseidon2V8SemanticWordRef) -> Self {
        Self {
            value,
            term: Some(SmallwoodPoseidon2V8HashLaneTerm::Semantic(source)),
        }
    }

    const fn call(value: u64, call: usize, lane: usize) -> Self {
        Self {
            value,
            term: Some(SmallwoodPoseidon2V8HashLaneTerm::CallFinal { call, lane }),
        }
    }

    const fn oriented(
        value: u64,
        path: SmallwoodPoseidon2V8MerklePathRef,
        level: usize,
        side: SmallwoodPoseidon2V8MerkleSide,
        limb: usize,
    ) -> Self {
        Self {
            value,
            term: Some(SmallwoodPoseidon2V8HashLaneTerm::OrientedMerkleOperand {
                path,
                level,
                side,
                limb,
            }),
        }
    }
}

struct ScheduleBuilder {
    calls: Vec<SmallwoodPoseidon2V8HashCall>,
}

impl ScheduleBuilder {
    fn new() -> Self {
        Self {
            calls: Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_SCHEDULE_PADDED_CALLS),
        }
    }

    fn call_digest_words(&self, call: usize) -> [BoundWord; POSEIDON2_WIDTH16_DIGEST] {
        core::array::from_fn(|lane| BoundWord::call(self.calls[call].final_state[lane], call, lane))
    }

    fn push_sponge(
        &mut self,
        roles: &[SmallwoodPoseidon2V8HashCallRole],
        domain: u64,
        input: &[BoundWord],
        output: SmallwoodPoseidon2V8HashDigestRef,
    ) -> Result<usize, SmallwoodPoseidon2V8HashScheduleError> {
        let blocks = core::cmp::max(1, input.len().div_ceil(POSEIDON2_WIDTH16_RATE));
        if roles.len() != blocks {
            return Err(
                SmallwoodPoseidon2V8HashScheduleError::WrongSpongeRoleCount {
                    expected: blocks,
                    actual: roles.len(),
                },
            );
        }
        let first_call = self.calls.len();
        let mut previous = [0u64; POSEIDON2_WIDTH16_WIDTH];
        for block in 0..blocks {
            let call = self.calls.len();
            let mut state = if block == 0 {
                [Felt::ZERO; POSEIDON2_WIDTH16_WIDTH]
            } else {
                previous.map(Felt::from_u64)
            };
            let mut bindings = if block == 0 {
                [SmallwoodPoseidon2V8HashLaneBinding::ZERO; POSEIDON2_WIDTH16_WIDTH]
            } else {
                core::array::from_fn(|lane| {
                    SmallwoodPoseidon2V8HashLaneBinding::call_plus_source(call - 1, lane, None, 0)
                })
            };
            if block == 0 {
                state[POSEIDON2_WIDTH16_RATE] = Felt::from_u64(domain);
                state[POSEIDON2_WIDTH16_RATE + 1] = Felt::from_u64(input.len() as u64);
                state[POSEIDON2_WIDTH16_RATE + 2] =
                    Felt::from_u64(POSEIDON2_WIDTH16_SPONGE_MODE_MARKER);
                state[POSEIDON2_WIDTH16_WIDTH - 1] = Felt::from_u64(POSEIDON2_WIDTH16_SUITE_MARKER);
                bindings[POSEIDON2_WIDTH16_RATE] =
                    SmallwoodPoseidon2V8HashLaneBinding::constant(domain);
                bindings[POSEIDON2_WIDTH16_RATE + 1] =
                    SmallwoodPoseidon2V8HashLaneBinding::constant(input.len() as u64);
                bindings[POSEIDON2_WIDTH16_RATE + 2] =
                    SmallwoodPoseidon2V8HashLaneBinding::constant(
                        POSEIDON2_WIDTH16_SPONGE_MODE_MARKER,
                    );
                bindings[POSEIDON2_WIDTH16_WIDTH - 1] =
                    SmallwoodPoseidon2V8HashLaneBinding::constant(POSEIDON2_WIDTH16_SUITE_MARKER);
            }
            let start = block * POSEIDON2_WIDTH16_RATE;
            let take = core::cmp::min(POSEIDON2_WIDTH16_RATE, input.len().saturating_sub(start));
            for lane in 0..take {
                let word = input[start + lane];
                state[lane] += Felt::from_u64(word.value);
                bindings[lane] = if block == 0 {
                    match word.term {
                        Some(term) => SmallwoodPoseidon2V8HashLaneBinding::term(term),
                        None => SmallwoodPoseidon2V8HashLaneBinding::ZERO,
                    }
                } else {
                    let source = match word.term {
                        Some(SmallwoodPoseidon2V8HashLaneTerm::Semantic(source)) => Some(source),
                        _ => None,
                    };
                    SmallwoodPoseidon2V8HashLaneBinding::call_plus_source(call - 1, lane, source, 0)
                };
            }
            if block + 1 == blocks {
                state[POSEIDON2_WIDTH16_RATE + 3] += Felt::ONE;
                if block == 0 {
                    bindings[POSEIDON2_WIDTH16_RATE + 3] =
                        SmallwoodPoseidon2V8HashLaneBinding::constant(1);
                } else {
                    bindings[POSEIDON2_WIDTH16_RATE + 3].constant = 1;
                }
            }
            let initial_state = state.map(|value| value.as_canonical_u64());
            poseidon2_width16_permutation(&mut state);
            let final_state = state.map(|value| value.as_canonical_u64());
            previous = final_state;
            let final_binding = if block + 1 == blocks {
                SmallwoodPoseidon2V8HashFinalBinding::Digest(output)
            } else {
                SmallwoodPoseidon2V8HashFinalBinding::NextSpongeCall { call: call + 1 }
            };
            self.calls.push(SmallwoodPoseidon2V8HashCall {
                index: call,
                mode: SmallwoodPoseidon2V8HashCallMode::Sponge,
                role: roles[block],
                initial_bindings: bindings,
                initial_state,
                final_state,
                final_binding,
            });
        }
        Ok(first_call + blocks - 1)
    }

    fn push_compress14(
        &mut self,
        role: SmallwoodPoseidon2V8HashCallRole,
        domain: u64,
        left: [BoundWord; POSEIDON2_WIDTH16_DIGEST],
        right: [BoundWord; POSEIDON2_WIDTH16_DIGEST],
        output: SmallwoodPoseidon2V8HashDigestRef,
    ) -> Result<usize, SmallwoodPoseidon2V8HashScheduleError> {
        let call = self.calls.len();
        let mut initial_state = [0u64; POSEIDON2_WIDTH16_WIDTH];
        let mut bindings = [SmallwoodPoseidon2V8HashLaneBinding::ZERO; POSEIDON2_WIDTH16_WIDTH];
        for lane in 0..POSEIDON2_WIDTH16_DIGEST {
            initial_state[lane] = left[lane].value;
            initial_state[POSEIDON2_WIDTH16_DIGEST + lane] = right[lane].value;
            bindings[lane] = match left[lane].term {
                Some(term) => SmallwoodPoseidon2V8HashLaneBinding::term(term),
                None => SmallwoodPoseidon2V8HashLaneBinding::ZERO,
            };
            bindings[POSEIDON2_WIDTH16_DIGEST + lane] = match right[lane].term {
                Some(term) => SmallwoodPoseidon2V8HashLaneBinding::term(term),
                None => SmallwoodPoseidon2V8HashLaneBinding::ZERO,
            };
        }
        initial_state[14] = domain;
        initial_state[15] = POSEIDON2_WIDTH16_SUITE_MARKER;
        bindings[14] = SmallwoodPoseidon2V8HashLaneBinding::constant(domain);
        bindings[15] =
            SmallwoodPoseidon2V8HashLaneBinding::constant(POSEIDON2_WIDTH16_SUITE_MARKER);

        let left_felts = left.map(|word| Felt::from_u64(word.value));
        let right_felts = right.map(|word| Felt::from_u64(word.value));
        let expected = poseidon2_width16_compress14(domain, &left_felts, &right_felts)
            .map(|value| value.as_canonical_u64());
        let mut state = initial_state.map(Felt::from_u64);
        poseidon2_width16_permutation(&mut state);
        let final_state = state.map(|value| value.as_canonical_u64());
        if final_state[..POSEIDON2_WIDTH16_DIGEST] != expected {
            return Err(SmallwoodPoseidon2V8HashScheduleError::CompressTraceMismatch);
        }
        self.calls.push(SmallwoodPoseidon2V8HashCall {
            index: call,
            mode: SmallwoodPoseidon2V8HashCallMode::Compress14,
            role,
            initial_bindings: bindings,
            initial_state,
            final_state,
            final_binding: SmallwoodPoseidon2V8HashFinalBinding::Digest(output),
        });
        Ok(call)
    }

    fn finish(
        mut self,
    ) -> Result<SmallwoodPoseidon2V8HashScheduleMaterial, SmallwoodPoseidon2V8HashScheduleError>
    {
        if self.calls.len() != SMALLWOOD_POSEIDON2_V8_SCHEDULE_LIVE_CALLS {
            return Err(SmallwoodPoseidon2V8HashScheduleError::WrongCallCount {
                expected: SMALLWOOD_POSEIDON2_V8_SCHEDULE_LIVE_CALLS,
                actual: self.calls.len(),
            });
        }
        let initial_states: [[u64; POSEIDON2_WIDTH16_WIDTH];
            SMALLWOOD_POSEIDON2_V8_SCHEDULE_LIVE_CALLS] =
            core::array::from_fn(|call| self.calls[call].initial_state);
        let packed_rows = build_smallwood_poseidon2_v8_hash_rows(&initial_states)?;
        while self.calls.len() < SMALLWOOD_POSEIDON2_V8_SCHEDULE_PADDED_CALLS {
            let index = self.calls.len();
            let initial_state = [0u64; POSEIDON2_WIDTH16_WIDTH];
            let mut state = [Felt::ZERO; POSEIDON2_WIDTH16_WIDTH];
            poseidon2_width16_permutation(&mut state);
            self.calls.push(SmallwoodPoseidon2V8HashCall {
                index,
                mode: SmallwoodPoseidon2V8HashCallMode::Padding,
                role: SmallwoodPoseidon2V8HashCallRole::Padding { lane: index - 125 },
                initial_bindings: [SmallwoodPoseidon2V8HashLaneBinding::ZERO;
                    POSEIDON2_WIDTH16_WIDTH],
                initial_state,
                final_state: state.map(|value| value.as_canonical_u64()),
                final_binding: SmallwoodPoseidon2V8HashFinalBinding::Padding,
            });
        }
        let calls = self.calls.into_boxed_slice();
        let calls = calls.try_into().map_err(|calls: Box<[_]>| {
            SmallwoodPoseidon2V8HashScheduleError::WrongCallCount {
                expected: SMALLWOOD_POSEIDON2_V8_SCHEDULE_PADDED_CALLS,
                actual: calls.len(),
            }
        })?;
        Ok(SmallwoodPoseidon2V8HashScheduleMaterial { calls, packed_rows })
    }
}

fn note_words(note: SmallwoodPoseidon2V8NoteOpening, slot: usize, input: bool) -> Vec<BoundWord> {
    let source = |word| {
        if input {
            SmallwoodPoseidon2V8SemanticWordRef::InputNote { input: slot, word }
        } else {
            SmallwoodPoseidon2V8SemanticWordRef::OutputNote { output: slot, word }
        }
    };
    let mut words = Vec::with_capacity(18);
    words.push(BoundWord::semantic(
        note.value,
        source(SmallwoodPoseidon2V8NoteWordRef::Value),
    ));
    words.push(BoundWord::semantic(
        note.asset_id,
        source(SmallwoodPoseidon2V8NoteWordRef::AssetId),
    ));
    for limb in 0..4 {
        words.push(BoundWord::semantic(
            note.recipient_key[limb],
            source(SmallwoodPoseidon2V8NoteWordRef::RecipientKey { limb }),
        ));
    }
    for limb in 0..4 {
        words.push(BoundWord::semantic(
            note.rho[limb],
            source(SmallwoodPoseidon2V8NoteWordRef::Rho { limb }),
        ));
    }
    for limb in 0..4 {
        words.push(BoundWord::semantic(
            note.randomness[limb],
            source(SmallwoodPoseidon2V8NoteWordRef::Randomness { limb }),
        ));
    }
    for limb in 0..4 {
        words.push(BoundWord::semantic(
            note.authorization_key[limb],
            source(SmallwoodPoseidon2V8NoteWordRef::AuthorizationKey { limb }),
        ));
    }
    words
}

fn accumulator_words(
    opening: SmallwoodPoseidon2V8AccumulatorOpening,
    current: bool,
) -> Vec<BoundWord> {
    let source = |word: SmallwoodPoseidon2V8AccumulatorWordRef| {
        // The next accumulator always preserves the current policy, intent,
        // threshold, and signer set.  Only its approval count and slot bitmap
        // come from the typed next opening.  In FinalThresholdSpend the typed
        // next opening remains canonically ZERO, while the hash call commits
        // to the effective cleared accumulator used by the relation.
        let next_dynamic = matches!(
            word,
            SmallwoodPoseidon2V8AccumulatorWordRef::ApprovalCount
                | SmallwoodPoseidon2V8AccumulatorWordRef::ApprovedSlot { .. }
        );
        if current || !next_dynamic {
            SmallwoodPoseidon2V8SemanticWordRef::AuthorizationCurrent { word }
        } else {
            SmallwoodPoseidon2V8SemanticWordRef::AuthorizationNext { word }
        }
    };
    let mut words = Vec::with_capacity(23);
    for limb in 0..7 {
        words.push(BoundWord::semantic(
            opening.policy_root[limb],
            source(SmallwoodPoseidon2V8AccumulatorWordRef::PolicyRoot { limb }),
        ));
    }
    for limb in 0..7 {
        words.push(BoundWord::semantic(
            opening.intent_digest[limb],
            source(SmallwoodPoseidon2V8AccumulatorWordRef::IntentDigest { limb }),
        ));
    }
    words.extend([
        BoundWord::semantic(
            opening.threshold,
            source(SmallwoodPoseidon2V8AccumulatorWordRef::Threshold),
        ),
        BoundWord::semantic(
            opening.signer_count,
            source(SmallwoodPoseidon2V8AccumulatorWordRef::SignerCount),
        ),
        BoundWord::semantic(
            opening.approval_count,
            source(SmallwoodPoseidon2V8AccumulatorWordRef::ApprovalCount),
        ),
    ]);
    for slot in 0..6 {
        words.push(BoundWord::semantic(
            u64::from(opening.approved_slots[slot]),
            source(SmallwoodPoseidon2V8AccumulatorWordRef::ApprovedSlot { slot }),
        ));
    }
    words
}

fn materialize_sponge_digest(domain: u64, input: &[u64]) -> SmallwoodPoseidon2V8Digest {
    let blocks = core::cmp::max(1, input.len().div_ceil(POSEIDON2_WIDTH16_RATE));
    let mut state = [Felt::ZERO; POSEIDON2_WIDTH16_WIDTH];
    for block in 0..blocks {
        if block == 0 {
            state[POSEIDON2_WIDTH16_RATE] = Felt::from_u64(domain);
            state[POSEIDON2_WIDTH16_RATE + 1] = Felt::from_u64(input.len() as u64);
            state[POSEIDON2_WIDTH16_RATE + 2] =
                Felt::from_u64(POSEIDON2_WIDTH16_SPONGE_MODE_MARKER);
            state[POSEIDON2_WIDTH16_WIDTH - 1] = Felt::from_u64(POSEIDON2_WIDTH16_SUITE_MARKER);
        }
        let start = block * POSEIDON2_WIDTH16_RATE;
        let end = core::cmp::min(start + POSEIDON2_WIDTH16_RATE, input.len());
        for (lane, value) in input[start..end].iter().copied().enumerate() {
            state[lane] += Felt::from_u64(value);
        }
        if block + 1 == blocks {
            state[POSEIDON2_WIDTH16_RATE + 3] += Felt::ONE;
        }
        poseidon2_width16_permutation(&mut state);
    }
    core::array::from_fn(|lane| state[lane].as_canonical_u64())
}

fn stable_config_ref(index: usize) -> SmallwoodPoseidon2V8StableConfigWordRef {
    match index {
        0 => SmallwoodPoseidon2V8StableConfigWordRef::AssetId,
        1 => SmallwoodPoseidon2V8StableConfigWordRef::PolicyVersion,
        2 => SmallwoodPoseidon2V8StableConfigWordRef::Active,
        3 => SmallwoodPoseidon2V8StableConfigWordRef::EnabledAt,
        4 => SmallwoodPoseidon2V8StableConfigWordRef::RetiredPresent,
        5 => SmallwoodPoseidon2V8StableConfigWordRef::RetiredAt,
        6..=12 => SmallwoodPoseidon2V8StableConfigWordRef::IssuerCommitment { limb: index - 6 },
        13 => SmallwoodPoseidon2V8StableConfigWordRef::MinCollateralRatioPpm,
        14 => SmallwoodPoseidon2V8StableConfigWordRef::MaxMintPerEpoch,
        15 => SmallwoodPoseidon2V8StableConfigWordRef::OracleSubmittedAt,
        16 => SmallwoodPoseidon2V8StableConfigWordRef::OracleMaxAge,
        17 => SmallwoodPoseidon2V8StableConfigWordRef::OraclePriceNumerator,
        18 => SmallwoodPoseidon2V8StableConfigWordRef::OraclePriceDenominator,
        19 => SmallwoodPoseidon2V8StableConfigWordRef::CollateralAmount,
        20 => SmallwoodPoseidon2V8StableConfigWordRef::AttestationCreatedAt,
        21 => SmallwoodPoseidon2V8StableConfigWordRef::AttestationDisputed,
        22 => SmallwoodPoseidon2V8StableConfigWordRef::AttestationPresent,
        23 => SmallwoodPoseidon2V8StableConfigWordRef::AttestationMaxAge,
        24..=30 => {
            SmallwoodPoseidon2V8StableConfigWordRef::PolicyAdminCommitment { limb: index - 24 }
        }
        31..=37 => {
            SmallwoodPoseidon2V8StableConfigWordRef::OracleAuthorityCommitment { limb: index - 31 }
        }
        38..=44 => SmallwoodPoseidon2V8StableConfigWordRef::AttestationAuthorityCommitment {
            limb: index - 38,
        },
        45 => SmallwoodPoseidon2V8StableConfigWordRef::CollateralAssetId,
        46 => SmallwoodPoseidon2V8StableConfigWordRef::CollateralDecimals,
        47 => SmallwoodPoseidon2V8StableConfigWordRef::CollateralScale,
        48..=54 => {
            SmallwoodPoseidon2V8StableConfigWordRef::LockedCollateralCommitment { limb: index - 48 }
        }
        _ => unreachable!("the stable configuration has exactly 55 words"),
    }
}

fn counter_words(counters: StablecoinPoseidon2V8Counters, after: bool) -> [BoundWord; 4] {
    let source = |word| {
        if after {
            SmallwoodPoseidon2V8SemanticWordRef::StableAfterCounter { word }
        } else {
            SmallwoodPoseidon2V8SemanticWordRef::StableBeforeCounter { word }
        }
    };
    [
        BoundWord::semantic(
            counters.epoch_id,
            source(SmallwoodPoseidon2V8CounterWordRef::EpochId),
        ),
        BoundWord::semantic(
            counters.minted_in_epoch,
            source(SmallwoodPoseidon2V8CounterWordRef::MintedInEpoch),
        ),
        BoundWord::semantic(
            counters.total_debt,
            source(SmallwoodPoseidon2V8CounterWordRef::TotalDebt),
        ),
        BoundWord::semantic(
            counters.sequence,
            source(SmallwoodPoseidon2V8CounterWordRef::Sequence),
        ),
    ]
}

fn scan_canonical_sources(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
) -> Result<(), SmallwoodPoseidon2V8HashScheduleError> {
    for (index, word) in statement.to_public_words().into_iter().enumerate() {
        if word >= GOLDILOCKS_MODULUS {
            return Err(SmallwoodPoseidon2V8HashScheduleError::NonCanonicalPublicWord { index });
        }
    }
    for (index, word) in witness.to_witness_words().into_iter().enumerate() {
        if word >= GOLDILOCKS_MODULUS {
            return Err(SmallwoodPoseidon2V8HashScheduleError::NonCanonicalWitnessWord { index });
        }
    }
    Ok(())
}

/// Build the exact fixed-topology schedule.  This function performs only
/// canonical source checks and trace materialization; semantic equality,
/// activity, balance, authorization, and stablecoin transition rules remain
/// relation constraints.
pub fn build_smallwood_poseidon2_v8_hash_schedule(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
) -> Result<SmallwoodPoseidon2V8HashScheduleMaterial, SmallwoodPoseidon2V8HashScheduleError> {
    scan_canonical_sources(statement, witness)?;
    let mut builder = ScheduleBuilder::new();

    let global_spend_key = if statement.input_flags[0] {
        witness.inputs[0].spend_key
    } else if statement.input_flags[1] {
        witness.inputs[1].spend_key
    } else {
        [0; 4]
    };
    let prf_words = (0..4)
        .map(|limb| {
            BoundWord::semantic(
                global_spend_key[limb],
                SmallwoodPoseidon2V8SemanticWordRef::TransactionSpendKey { limb },
            )
        })
        .collect::<Vec<_>>();
    builder.push_sponge(
        &[SmallwoodPoseidon2V8HashCallRole::TransactionPrf],
        NULLIFIER_DOMAIN_TAG,
        &prf_words,
        SmallwoodPoseidon2V8HashDigestRef::TransactionPrf,
    )?;

    let legacy_prf = builder.calls[0].final_state[0];
    let current_accumulator_values = accumulator_words(witness.auth.current, true)
        .into_iter()
        .map(|word| word.value)
        .collect::<Vec<_>>();
    let current_digest = materialize_sponge_digest(
        SMALLWOOD_POSEIDON2_V8_AUTH_ACCUMULATOR_DOMAIN,
        &current_accumulator_values,
    );
    let value_lock_values = witness
        .auth
        .current
        .policy_root
        .into_iter()
        .chain(witness.auth.current.intent_digest)
        .collect::<Vec<_>>();
    let value_lock_digest = materialize_sponge_digest(
        SMALLWOOD_POSEIDON2_V8_AUTH_VALUE_LOCK_DOMAIN,
        &value_lock_values,
    );
    let effective_input_prfs = core::array::from_fn::<_, 2, _>(|input| {
        if !statement.input_flags[input] {
            return 0;
        }
        match (witness.auth.mode, input) {
            (SmallwoodPrivateAuthMode::SingleKey, _) => legacy_prf,
            (SmallwoodPrivateAuthMode::ApprovalStep, 0) => current_digest[4],
            (SmallwoodPrivateAuthMode::ApprovalStep, _) => legacy_prf,
            (SmallwoodPrivateAuthMode::FinalThresholdSpend, 0) => value_lock_digest[4],
            (SmallwoodPrivateAuthMode::FinalThresholdSpend, _) => current_digest[4],
        }
    });

    for input in 0..2 {
        let note_roles = core::array::from_fn::<_, 3, _>(|block| {
            SmallwoodPoseidon2V8HashCallRole::InputNote { input, block }
        });
        let note_call = builder.push_sponge(
            &note_roles,
            NOTE_DOMAIN_TAG,
            &note_words(witness.inputs[input].note, input, true),
            SmallwoodPoseidon2V8HashDigestRef::InputNote { input },
        )?;
        let mut current_call = note_call;
        let mut position = witness.inputs[input].position;
        for level in 0..SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH {
            let current = builder.call_digest_words(current_call);
            let sibling: [BoundWord; 7] = core::array::from_fn(|limb| {
                BoundWord::semantic(
                    witness.inputs[input].siblings[level][limb],
                    SmallwoodPoseidon2V8SemanticWordRef::InputSibling { input, level, limb },
                )
            });
            let (left_values, right_values) = if position & 1 == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            let path = SmallwoodPoseidon2V8MerklePathRef::TransactionInput { input };
            let left = core::array::from_fn(|limb| {
                BoundWord::oriented(
                    left_values[limb].value,
                    path,
                    level,
                    SmallwoodPoseidon2V8MerkleSide::Left,
                    limb,
                )
            });
            let right = core::array::from_fn(|limb| {
                BoundWord::oriented(
                    right_values[limb].value,
                    path,
                    level,
                    SmallwoodPoseidon2V8MerkleSide::Right,
                    limb,
                )
            });
            current_call = builder.push_compress14(
                SmallwoodPoseidon2V8HashCallRole::InputMerkle { input, level },
                MERKLE_DOMAIN_TAG,
                left,
                right,
                SmallwoodPoseidon2V8HashDigestRef::InputMerkleNode { input, level },
            )?;
            position >>= 1;
        }
        let mut nullifier_words = Vec::with_capacity(6);
        nullifier_words.push(BoundWord::semantic(
            effective_input_prfs[input],
            SmallwoodPoseidon2V8SemanticWordRef::InputAuthorizationPrf { input },
        ));
        let active = statement.input_flags[input];
        nullifier_words.push(BoundWord::semantic(
            if active {
                witness.inputs[input].position
            } else {
                0
            },
            SmallwoodPoseidon2V8SemanticWordRef::InputPosition { input },
        ));
        for limb in 0..4 {
            nullifier_words.push(BoundWord::semantic(
                if active {
                    witness.inputs[input].note.rho[limb]
                } else {
                    0
                },
                SmallwoodPoseidon2V8SemanticWordRef::InputNote {
                    input,
                    word: SmallwoodPoseidon2V8NoteWordRef::Rho { limb },
                },
            ));
        }
        builder.push_sponge(
            &[SmallwoodPoseidon2V8HashCallRole::InputNullifier { input }],
            NULLIFIER_DOMAIN_TAG,
            &nullifier_words,
            SmallwoodPoseidon2V8HashDigestRef::InputNullifier { input },
        )?;
    }

    for output in 0..2 {
        let roles = core::array::from_fn::<_, 3, _>(|block| {
            SmallwoodPoseidon2V8HashCallRole::OutputNote { output, block }
        });
        builder.push_sponge(
            &roles,
            NOTE_DOMAIN_TAG,
            &note_words(witness.outputs[output].note, output, false),
            SmallwoodPoseidon2V8HashDigestRef::OutputNote { output },
        )?;
    }

    let projection = statement.action_intent_projection_words();
    let intent_words = projection
        .into_iter()
        .enumerate()
        .map(|(word, value)| {
            BoundWord::semantic(
                value,
                SmallwoodPoseidon2V8SemanticWordRef::ActionIntentProjectionWord { word },
            )
        })
        .collect::<Vec<_>>();
    let intent_roles = (0..15)
        .map(|block| SmallwoodPoseidon2V8HashCallRole::ActionIntent { block })
        .collect::<Vec<_>>();
    builder.push_sponge(
        &intent_roles,
        SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_DOMAIN,
        &intent_words,
        SmallwoodPoseidon2V8HashDigestRef::ActionIntent,
    )?;

    let mut policy_words = Vec::with_capacity(32);
    policy_words.extend([
        BoundWord::semantic(
            witness.auth.current.threshold,
            SmallwoodPoseidon2V8SemanticWordRef::AuthorizationPolicyThreshold,
        ),
        BoundWord::semantic(
            witness.auth.current.signer_count,
            SmallwoodPoseidon2V8SemanticWordRef::AuthorizationPolicySignerCount,
        ),
    ]);
    for slot in 0..6 {
        for limb in 0..5 {
            policy_words.push(BoundWord::semantic(
                witness.auth.policy_signer_tags[slot][limb],
                SmallwoodPoseidon2V8SemanticWordRef::AuthorizationPolicySignerTag { slot, limb },
            ));
        }
    }
    let policy_roles = core::array::from_fn::<_, 4, _>(|block| {
        SmallwoodPoseidon2V8HashCallRole::AuthorizationPolicy { block }
    });
    builder.push_sponge(
        &policy_roles,
        SMALLWOOD_POSEIDON2_V8_AUTH_POLICY_DOMAIN,
        &policy_words,
        SmallwoodPoseidon2V8HashDigestRef::AuthorizationPolicy,
    )?;

    for current in [true, false] {
        let roles = core::array::from_fn::<_, 3, _>(|block| {
            if current {
                SmallwoodPoseidon2V8HashCallRole::AuthorizationCurrent { block }
            } else {
                SmallwoodPoseidon2V8HashCallRole::AuthorizationNext { block }
            }
        });
        let opening = if current {
            witness.auth.current
        } else {
            SmallwoodPoseidon2V8AccumulatorOpening {
                policy_root: witness.auth.current.policy_root,
                intent_digest: witness.auth.current.intent_digest,
                threshold: witness.auth.current.threshold,
                signer_count: witness.auth.current.signer_count,
                approval_count: witness.auth.next.approval_count,
                approved_slots: witness.auth.next.approved_slots,
            }
        };
        builder.push_sponge(
            &roles,
            SMALLWOOD_POSEIDON2_V8_AUTH_ACCUMULATOR_DOMAIN,
            &accumulator_words(opening, current),
            if current {
                SmallwoodPoseidon2V8HashDigestRef::AuthorizationCurrent
            } else {
                SmallwoodPoseidon2V8HashDigestRef::AuthorizationNext
            },
        )?;
    }

    let mut value_lock_words = Vec::with_capacity(14);
    for limb in 0..7 {
        value_lock_words.push(BoundWord::semantic(
            witness.auth.current.policy_root[limb],
            SmallwoodPoseidon2V8SemanticWordRef::AuthorizationCurrent {
                word: SmallwoodPoseidon2V8AccumulatorWordRef::PolicyRoot { limb },
            },
        ));
    }
    for limb in 0..7 {
        value_lock_words.push(BoundWord::semantic(
            witness.auth.current.intent_digest[limb],
            SmallwoodPoseidon2V8SemanticWordRef::AuthorizationCurrent {
                word: SmallwoodPoseidon2V8AccumulatorWordRef::IntentDigest { limb },
            },
        ));
    }
    builder.push_sponge(
        &[
            SmallwoodPoseidon2V8HashCallRole::AuthorizationValueLock { block: 0 },
            SmallwoodPoseidon2V8HashCallRole::AuthorizationValueLock { block: 1 },
        ],
        SMALLWOOD_POSEIDON2_V8_AUTH_VALUE_LOCK_DOMAIN,
        &value_lock_words,
        SmallwoodPoseidon2V8HashDigestRef::AuthorizationValueLock,
    )?;

    append_stable_schedule(&mut builder, statement, witness)?;
    builder.finish()
}

fn append_stable_schedule(
    builder: &mut ScheduleBuilder,
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
) -> Result<(), SmallwoodPoseidon2V8HashScheduleError> {
    let config: StablecoinPoseidon2V8Config = witness.stablecoin.config;
    let config_values = config.to_fields().map(|value| value.as_canonical_u64());
    let config_words: [BoundWord; 55] = core::array::from_fn(|index| {
        BoundWord::semantic(
            config_values[index],
            SmallwoodPoseidon2V8SemanticWordRef::StableConfig {
                word: stable_config_ref(index),
            },
        )
    });
    let chunk_domains = [
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_0,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_1,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_2,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_3,
    ];
    let mut chunk_calls = [0usize; 4];
    for chunk in 0..4 {
        let left = core::array::from_fn(|lane| config_words[chunk * 14 + lane]);
        let right = core::array::from_fn(|lane| {
            config_words
                .get(chunk * 14 + 7 + lane)
                .copied()
                .unwrap_or(BoundWord::ZERO)
        });
        chunk_calls[chunk] = builder.push_compress14(
            SmallwoodPoseidon2V8HashCallRole::StableConfigChunk { chunk },
            chunk_domains[chunk],
            left,
            right,
            SmallwoodPoseidon2V8HashDigestRef::StableConfigChunk { chunk },
        )?;
    }
    let left_config = builder.push_compress14(
        SmallwoodPoseidon2V8HashCallRole::StableConfigNode { node: 0 },
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_0,
        builder.call_digest_words(chunk_calls[0]),
        builder.call_digest_words(chunk_calls[1]),
        SmallwoodPoseidon2V8HashDigestRef::StableConfigNode { node: 0 },
    )?;
    let right_config = builder.push_compress14(
        SmallwoodPoseidon2V8HashCallRole::StableConfigNode { node: 1 },
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_1,
        builder.call_digest_words(chunk_calls[2]),
        builder.call_digest_words(chunk_calls[3]),
        SmallwoodPoseidon2V8HashDigestRef::StableConfigNode { node: 1 },
    )?;
    let config_root = builder.push_compress14(
        SmallwoodPoseidon2V8HashCallRole::StableConfigNode { node: 2 },
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_ROOT,
        builder.call_digest_words(left_config),
        builder.call_digest_words(right_config),
        SmallwoodPoseidon2V8HashDigestRef::StableConfigNode { node: 2 },
    )?;

    let index = u64::from(statement.stablecoin.asset_id & 15);
    let before_counters = counter_words(witness.stablecoin.before, false);
    let after_counters = counter_words(statement.stablecoin.after, true);
    let leaf_right = |counters: [BoundWord; 4]| {
        [
            counters[0],
            counters[1],
            counters[2],
            counters[3],
            BoundWord::semantic(index, SmallwoodPoseidon2V8SemanticWordRef::StableAssetIndex),
            BoundWord::ZERO,
            BoundWord::ZERO,
        ]
    };
    let before_leaf = builder.push_compress14(
        SmallwoodPoseidon2V8HashCallRole::StableStateLeaf { after: false },
        STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_LEAF,
        builder.call_digest_words(config_root),
        leaf_right(before_counters),
        SmallwoodPoseidon2V8HashDigestRef::StableStateLeaf { after: false },
    )?;
    let after_leaf = builder.push_compress14(
        SmallwoodPoseidon2V8HashCallRole::StableStateLeaf { after: true },
        STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_LEAF,
        builder.call_digest_words(config_root),
        leaf_right(after_counters),
        SmallwoodPoseidon2V8HashDigestRef::StableStateLeaf { after: true },
    )?;

    let mut before = before_leaf;
    let mut after = after_leaf;
    let mut cursor = index;
    for level in 0..4 {
        let sibling: [BoundWord; 7] = core::array::from_fn(|limb| {
            BoundWord::semantic(
                witness.stablecoin.siblings[level][limb].as_canonical_u64(),
                SmallwoodPoseidon2V8SemanticWordRef::StableSibling { level, limb },
            )
        });
        for after_path in [false, true] {
            let current_call = if after_path { after } else { before };
            let current = builder.call_digest_words(current_call);
            let (left_values, right_values) = if cursor & 1 == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            let path = if after_path {
                SmallwoodPoseidon2V8MerklePathRef::StableAfter
            } else {
                SmallwoodPoseidon2V8MerklePathRef::StableBefore
            };
            let left = core::array::from_fn(|limb| {
                BoundWord::oriented(
                    left_values[limb].value,
                    path,
                    level,
                    SmallwoodPoseidon2V8MerkleSide::Left,
                    limb,
                )
            });
            let right = core::array::from_fn(|limb| {
                BoundWord::oriented(
                    right_values[limb].value,
                    path,
                    level,
                    SmallwoodPoseidon2V8MerkleSide::Right,
                    limb,
                )
            });
            let call = builder.push_compress14(
                SmallwoodPoseidon2V8HashCallRole::StablePath {
                    after: after_path,
                    level,
                },
                STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_NODE_0 + level as u64,
                left,
                right,
                SmallwoodPoseidon2V8HashDigestRef::StablePathNode {
                    after: after_path,
                    level,
                },
            )?;
            if after_path {
                after = call;
            } else {
                before = call;
            }
        }
        cursor >>= 1;
    }

    let issuer_secret: [BoundWord; 7] = core::array::from_fn(|limb| {
        BoundWord::semantic(
            witness.stablecoin.issuer_secret[limb].as_canonical_u64(),
            SmallwoodPoseidon2V8SemanticWordRef::StableIssuerSecret { limb },
        )
    });
    let issuer_right = [
        BoundWord::semantic(
            u64::from(statement.stablecoin.asset_id),
            SmallwoodPoseidon2V8SemanticWordRef::StablePublicAssetId,
        ),
        BoundWord::semantic(
            u64::from(statement.stablecoin.policy_version),
            SmallwoodPoseidon2V8SemanticWordRef::StablePublicPolicyVersion,
        ),
        BoundWord::ZERO,
        BoundWord::ZERO,
        BoundWord::ZERO,
        BoundWord::ZERO,
        BoundWord::ZERO,
    ];
    builder.push_compress14(
        SmallwoodPoseidon2V8HashCallRole::StableIssuerCommitment,
        STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_COMMITMENT,
        issuer_secret,
        issuer_right,
        SmallwoodPoseidon2V8HashDigestRef::StableIssuerCommitment,
    )?;
    let action_intent: [BoundWord; 7] = core::array::from_fn(|limb| {
        BoundWord::semantic(
            statement.stablecoin.action_intent[limb].as_canonical_u64(),
            SmallwoodPoseidon2V8SemanticWordRef::StablePublicActionIntent { limb },
        )
    });
    builder.push_compress14(
        SmallwoodPoseidon2V8HashCallRole::StableIssuerAuthorization,
        STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_AUTHORIZATION,
        issuer_secret,
        action_intent,
        SmallwoodPoseidon2V8HashDigestRef::StableIssuerAuthorization,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smallwood_poseidon2_v8_hash_constraints::verify_smallwood_poseidon2_v8_hash_rows;
    use transaction_core::stablecoin_poseidon2_v8::{
        stablecoin_poseidon2_v8_config_digest, stablecoin_poseidon2_v8_issuer_authorization,
        stablecoin_poseidon2_v8_issuer_commitment, stablecoin_poseidon2_v8_root,
    };

    fn fixture() -> (
        SmallwoodPoseidon2V8PublicStatement,
        SmallwoodPoseidon2V8Witness,
    ) {
        let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
        statement.input_flags = [true, true];
        statement.output_flags = [true, true];
        statement.fee = 17;
        let mut witness = SmallwoodPoseidon2V8Witness::default();
        for input in 0..2 {
            witness.inputs[input].active = true;
            witness.inputs[input].spend_key = [101, 102, 103, 104];
            witness.inputs[input].note = SmallwoodPoseidon2V8NoteOpening {
                value: 10 + input as u64,
                asset_id: 0,
                recipient_key: [20 + input as u64; 4],
                authorization_key: [30 + input as u64; 4],
                rho: [40 + input as u64; 4],
                randomness: [50 + input as u64; 4],
            };
            witness.inputs[input].position = input as u64;
            witness.inputs[input].siblings = core::array::from_fn(|level| {
                core::array::from_fn(|limb| {
                    1_000 + input as u64 * 500 + level as u64 * 7 + limb as u64
                })
            });
        }
        for output in 0..2 {
            witness.outputs[output].active = true;
            witness.outputs[output].note = SmallwoodPoseidon2V8NoteOpening {
                value: 5 + output as u64,
                asset_id: 0,
                recipient_key: [60 + output as u64; 4],
                authorization_key: [70 + output as u64; 4],
                rho: [80 + output as u64; 4],
                randomness: [90 + output as u64; 4],
            };
        }
        witness.auth.current.threshold = 2;
        witness.auth.current.signer_count = 2;
        witness.auth.policy_signer_tags[0] = [1, 2, 3, 4, 5];
        witness.auth.policy_signer_tags[1] = [6, 7, 8, 9, 10];
        (statement, witness)
    }

    fn live_final_states(
        material: &SmallwoodPoseidon2V8HashScheduleMaterial,
    ) -> Vec<[u64; POSEIDON2_WIDTH16_WIDTH]> {
        material
            .live_calls()
            .iter()
            .map(|call| call.final_state)
            .collect()
    }

    fn build_live_final_states(
        statement: &SmallwoodPoseidon2V8PublicStatement,
        witness: &SmallwoodPoseidon2V8Witness,
    ) -> Vec<[u64; POSEIDON2_WIDTH16_WIDTH]> {
        let material = build_smallwood_poseidon2_v8_hash_schedule(statement, witness).unwrap();
        live_final_states(&material)
    }

    fn changed_calls(
        left: &[[u64; POSEIDON2_WIDTH16_WIDTH]],
        right: &SmallwoodPoseidon2V8HashScheduleMaterial,
    ) -> Vec<usize> {
        (0..SMALLWOOD_POSEIDON2_V8_SCHEDULE_LIVE_CALLS)
            .filter(|call| left[*call] != right.calls[*call].final_state)
            .collect()
    }

    fn assert_changed_calls(
        statement: &SmallwoodPoseidon2V8PublicStatement,
        witness: &SmallwoodPoseidon2V8Witness,
        base: &[[u64; POSEIDON2_WIDTH16_WIDTH]],
        expected: Vec<usize>,
    ) {
        let changed = build_smallwood_poseidon2_v8_hash_schedule(statement, witness).unwrap();
        assert_eq!(changed_calls(base, &changed), expected);
    }

    fn reference_sponge_digest(domain: u64, input: &[u64]) -> SmallwoodPoseidon2V8Digest {
        let blocks = core::cmp::max(1, input.len().div_ceil(POSEIDON2_WIDTH16_RATE));
        let mut state = [Felt::ZERO; POSEIDON2_WIDTH16_WIDTH];
        for block in 0..blocks {
            if block == 0 {
                state[POSEIDON2_WIDTH16_RATE] = Felt::from_u64(domain);
                state[POSEIDON2_WIDTH16_RATE + 1] = Felt::from_u64(input.len() as u64);
                state[POSEIDON2_WIDTH16_RATE + 2] =
                    Felt::from_u64(POSEIDON2_WIDTH16_SPONGE_MODE_MARKER);
                state[POSEIDON2_WIDTH16_WIDTH - 1] = Felt::from_u64(POSEIDON2_WIDTH16_SUITE_MARKER);
            }
            let start = block * POSEIDON2_WIDTH16_RATE;
            for (lane, word) in input[start..core::cmp::min(start + 8, input.len())]
                .iter()
                .copied()
                .enumerate()
            {
                state[lane] += Felt::from_u64(word);
            }
            if block + 1 == blocks {
                state[POSEIDON2_WIDTH16_RATE + 3] += Felt::ONE;
            }
            poseidon2_width16_permutation(&mut state);
        }
        core::array::from_fn(|lane| state[lane].as_canonical_u64())
    }

    #[test]
    fn exact_125_call_schedule_pads_to_128_and_rows_verify() {
        let (statement, witness) = fixture();
        let material = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness).unwrap();
        assert_eq!(material.live_calls().len(), 125);
        assert_eq!(material.initial_states().len(), 125);
        assert_eq!(material.final_digests().len(), 125);
        verify_smallwood_poseidon2_v8_hash_rows(material.packed_rows.as_rows()).unwrap();
        let mut range_cursor = 0;
        for range in SMALLWOOD_POSEIDON2_V8_HASH_ROLE_RANGES {
            assert_eq!(range.start, range_cursor, "gap before {}", range.name);
            range_cursor = range.end;
        }
        assert_eq!(range_cursor, 125);
        for call in 125..128 {
            assert_eq!(
                material.calls[call].mode,
                SmallwoodPoseidon2V8HashCallMode::Padding
            );
            assert_eq!(material.calls[call].initial_state, [0; 16]);
            assert_eq!(
                material.calls[call].initial_bindings,
                [SmallwoodPoseidon2V8HashLaneBinding::ZERO; 16]
            );
        }
        assert_eq!(
            material.calls[0].role,
            SmallwoodPoseidon2V8HashCallRole::TransactionPrf
        );
        assert_eq!(
            material.calls[36].role,
            SmallwoodPoseidon2V8HashCallRole::InputNullifier { input: 0 }
        );
        assert_eq!(
            material.calls[79].role,
            SmallwoodPoseidon2V8HashCallRole::ActionIntent { block: 0 }
        );
        assert_eq!(
            material.calls[124].role,
            SmallwoodPoseidon2V8HashCallRole::StableIssuerAuthorization
        );
        assert_eq!(
            material.calls[93].final_digest(),
            statement.expected_action_intent().unwrap()
        );
        let config_digest = stablecoin_poseidon2_v8_config_digest(witness.stablecoin.config);
        assert_eq!(
            material.calls[112].final_digest(),
            config_digest.map(|word| word.as_canonical_u64())
        );
        assert_eq!(
            material.calls[121].final_digest(),
            stablecoin_poseidon2_v8_root(
                statement.stablecoin.asset_id,
                config_digest,
                witness.stablecoin.before,
                &witness.stablecoin.siblings,
            )
            .unwrap()
            .map(|word| word.as_canonical_u64())
        );
        assert_eq!(
            material.calls[122].final_digest(),
            stablecoin_poseidon2_v8_root(
                statement.stablecoin.asset_id,
                config_digest,
                statement.stablecoin.after,
                &witness.stablecoin.siblings,
            )
            .unwrap()
            .map(|word| word.as_canonical_u64())
        );
        assert_eq!(
            material.calls[123].final_digest(),
            stablecoin_poseidon2_v8_issuer_commitment(
                statement.stablecoin.asset_id,
                statement.stablecoin.policy_version,
                &witness.stablecoin.issuer_secret,
            )
            .map(|word| word.as_canonical_u64())
        );
        assert_eq!(
            material.calls[124].final_digest(),
            stablecoin_poseidon2_v8_issuer_authorization(
                &statement.stablecoin.action_intent,
                &witness.stablecoin.issuer_secret,
            )
            .map(|word| word.as_canonical_u64())
        );
    }

    #[test]
    fn every_merkle_and_stable_compress_call_is_exactly_one_compress14() {
        let (statement, witness) = fixture();
        let material = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness).unwrap();
        let compress_calls = material
            .live_calls()
            .iter()
            .filter(|call| call.mode == SmallwoodPoseidon2V8HashCallMode::Compress14)
            .count();
        assert_eq!(compress_calls, 64 + 19);
        for call in material
            .live_calls()
            .iter()
            .filter(|call| call.mode == SmallwoodPoseidon2V8HashCallMode::Compress14)
        {
            let left = core::array::from_fn(|lane| Felt::from_u64(call.initial_state[lane]));
            let right = core::array::from_fn(|lane| Felt::from_u64(call.initial_state[7 + lane]));
            let expected = poseidon2_width16_compress14(call.initial_state[14], &left, &right)
                .map(|value| value.as_canonical_u64());
            assert_eq!(&call.final_state[..7], &expected);
        }
    }

    #[test]
    fn targeted_mutations_change_only_the_expected_hash_suffixes() {
        let (statement, witness) = fixture();
        let base = build_live_final_states(&statement, &witness);

        let mut changed_witness = witness;
        changed_witness.inputs[0].spend_key[0] += 1;
        assert_changed_calls(&statement, &changed_witness, &base, vec![0, 36, 72]);

        let mut changed_witness = witness;
        changed_witness.inputs[0].note.randomness[0] += 1;
        assert_changed_calls(
            &statement,
            &changed_witness,
            &base,
            (2..36).collect::<Vec<_>>(),
        );

        let mut changed_statement = statement;
        changed_statement.fee += 1;
        assert_changed_calls(
            &changed_statement,
            &witness,
            &base,
            (84..94).collect::<Vec<_>>(),
        );

        let mut changed_statement = statement;
        changed_statement.merkle_root[0] += 1;
        assert_changed_calls(&changed_statement, &witness, &base, Vec::new());

        let mut changed_witness = witness;
        changed_witness.stablecoin.config.max_mint_per_epoch = 1;
        assert_changed_calls(
            &statement,
            &changed_witness,
            &base,
            [107, 110, 112]
                .into_iter()
                .chain(113..123)
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn merkle_orientation_is_explicit_and_position_mutation_is_local_then_chained() {
        let (statement, witness) = fixture();
        let base = build_live_final_states(&statement, &witness);
        let mut changed_witness = witness;
        changed_witness.inputs[0].position ^= 1 << 5;
        let changed =
            build_smallwood_poseidon2_v8_hash_schedule(&statement, &changed_witness).unwrap();
        assert_eq!(changed_calls(&base, &changed), (9..37).collect::<Vec<_>>());
        assert!(matches!(
            changed.calls[9].initial_bindings[0].terms[0],
            Some(SmallwoodPoseidon2V8HashLaneTerm::OrientedMerkleOperand {
                path: SmallwoodPoseidon2V8MerklePathRef::TransactionInput { input: 0 },
                level: 5,
                side: SmallwoodPoseidon2V8MerkleSide::Left,
                limb: 0,
            })
        ));
    }

    #[test]
    fn authorization_prf_selection_and_final_effective_next_are_exact() {
        let (statement, mut witness) = fixture();
        witness.auth.mode = SmallwoodPrivateAuthMode::FinalThresholdSpend;
        witness.auth.current = SmallwoodPoseidon2V8AccumulatorOpening {
            policy_root: [11, 12, 13, 14, 15, 16, 17],
            intent_digest: [21, 22, 23, 24, 25, 26, 27],
            threshold: 2,
            signer_count: 2,
            approval_count: 2,
            approved_slots: [true, true, false, false, false, false],
        };
        witness.auth.next = SmallwoodPoseidon2V8AccumulatorOpening::ZERO;
        let material = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness).unwrap();
        let mut effective_words = Vec::with_capacity(23);
        effective_words.extend(witness.auth.current.policy_root);
        effective_words.extend(witness.auth.current.intent_digest);
        effective_words.extend([
            witness.auth.current.threshold,
            witness.auth.current.signer_count,
            0,
        ]);
        effective_words.extend([0; 6]);
        assert_eq!(
            material.calls[103].final_digest(),
            reference_sponge_digest(
                SMALLWOOD_POSEIDON2_V8_AUTH_ACCUMULATOR_DOMAIN,
                &effective_words,
            )
        );
        assert!(matches!(
            material.calls[101].initial_bindings[0].terms[0],
            Some(SmallwoodPoseidon2V8HashLaneTerm::Semantic(
                SmallwoodPoseidon2V8SemanticWordRef::AuthorizationCurrent {
                    word: SmallwoodPoseidon2V8AccumulatorWordRef::PolicyRoot { limb: 0 }
                }
            ))
        ));
        assert!(matches!(
            material.calls[103].initial_bindings[0].terms[1],
            Some(SmallwoodPoseidon2V8HashLaneTerm::Semantic(
                SmallwoodPoseidon2V8SemanticWordRef::AuthorizationNext {
                    word: SmallwoodPoseidon2V8AccumulatorWordRef::ApprovalCount
                }
            ))
        ));

        let legacy_prf = material.calls[0].final_state[0];
        let current_prf = material.calls[100].final_state[4];
        let value_lock_prf = material.calls[105].final_state[4];
        assert_eq!(material.calls[36].initial_state[0], value_lock_prf);
        assert_eq!(material.calls[72].initial_state[0], current_prf);
        for input in 0..2 {
            let call = if input == 0 { 36 } else { 72 };
            assert!(matches!(
                material.calls[call].initial_bindings[0].terms[0],
                Some(SmallwoodPoseidon2V8HashLaneTerm::Semantic(
                    SmallwoodPoseidon2V8SemanticWordRef::InputAuthorizationPrf {
                        input: bound_input
                    }
                )) if bound_input == input
            ));
        }

        let (statement, mut approval_witness) = fixture();
        approval_witness.auth.mode = SmallwoodPrivateAuthMode::ApprovalStep;
        let approval =
            build_smallwood_poseidon2_v8_hash_schedule(&statement, &approval_witness).unwrap();
        assert_eq!(
            approval.calls[36].initial_state[0],
            approval.calls[100].final_state[4]
        );
        assert_eq!(approval.calls[72].initial_state[0], legacy_prf);

        let (mut statement, mut single_witness) = fixture();
        single_witness.auth.mode = SmallwoodPrivateAuthMode::SingleKey;
        statement.input_flags[1] = false;
        let single =
            build_smallwood_poseidon2_v8_hash_schedule(&statement, &single_witness).unwrap();
        assert_eq!(
            single.calls[36].initial_state[0],
            single.calls[0].final_state[0]
        );
        assert_eq!(&single.calls[72].initial_state[..6], &[0; 6]);
    }
}
