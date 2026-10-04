//! Secret-independent radix-4 topology compiler for prospective HX512 relations.
//!
//! This module deliberately stops before transaction semantics and before a
//! production proof profile.  It accepts an exact, typed registry of RFC 7693
//! BLAKE2b-512 calls and deterministically lays out the hash operations in
//! SmallWood rows with `K = 1024`.  The registry owns message provenance,
//! personalizations, hash dependencies, and public digest targets.  The
//! compiler independently derives compression counts, counters, final flags,
//! RFC zero tails, and the reusable BLAKE2b operation topology.
//!
//! The inherited `83 core + 7 authority = 90` call / `213` compression
//! schedule is retained below as an explicitly rejected historical fixture.
//! The replacement relation grammar now freezes 95 typed hash slots and 226
//! maximum compression slots, including the complete stablecoin V3 registry.
//! A production proof identity is still unallocated, and the non-hash
//! transaction compiler and proof-profile gates remain incomplete.
//! Consequently this module exports no final complete-relation row count, no
//! identity-independent topology digest, and no production authorization.
//!
//! This descriptor is intentionally independent of the SmallWood PCS/PIOP
//! profile.  Witness-polynomial degree, PIOP opening count, high-randomizer
//! count, transcript sampling, and serialized proof geometry are not topology
//! fields and are not covered by `shape_digest_sha512`.  In particular, a
//! hash-topology digest cannot freeze or authorize an `s5`/five-opening proof
//! profile; those values require a separately bound profile descriptor.

#[cfg(test)]
use crate::hx512_production_relation::HX512_HASH_REGISTRY_FROZEN;
use crate::hx512_production_relation::{
    hx512_exact_hash_message_recipe, hx512_typed_hash_call_registry,
    Hx512AuthorizationMode as RelationAuthorizationMode, Hx512ByteRange, Hx512HashAtomSource,
    Hx512HashMessageAtom, Hx512HashRole, Hx512HashTargetCondition, Hx512UnallocatedIdentity,
    Hx512WireSurface,
};
use sha2::{Digest, Sha512};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub const HX512_RADIX4_PACKING_FACTOR: u32 = 1_024;
pub const HX512_RADIX_BITS: u32 = 2;
pub const HX512_RADIX_DIGITS_PER_WORD: u32 = 32;
pub const HX512_BLAKE2B_ROUNDS: u32 = 12;
pub const HX512_G_PER_ROUND: u32 = 8;
pub const HX512_ADDITIONS_PER_COMPRESSION: u32 = 384;
pub const HX512_EVEN_XORS_PER_COMPRESSION: u32 = 288;
pub const HX512_ODD_XORS_PER_COMPRESSION: u32 = 96;
pub const HX512_FEEDFORWARD_WORDS_PER_STAGE: u32 = 8;
pub const HX512_MESSAGE_WORDS_PER_COMPRESSION: u32 = 16;
pub const HX512_COMPRESSION_BLOCK_BYTES: u32 = 128;
pub const HX512_WORD_OPERATIONS_PER_COMPRESSION: u32 =
    HX512_BLAKE2B_ROUNDS * HX512_G_PER_ROUND * 13 + 2 * HX512_FEEDFORWARD_WORDS_PER_STAGE;

pub const HX512_TOPOLOGY_COMPILER_IMPLEMENTED: bool = true;
pub const HX512_TRANSACTION_NONHASH_COMPILER_COMPLETE: bool = false;
/// Frozen hash-registry slots.  This is not a complete-relation or production claim.
pub const HX512_FINAL_CALL_COUNT: Option<u32> = Some(95);
/// Frozen maximum hash-compression slots across every mode and stable direction.
pub const HX512_FINAL_COMPRESSION_COUNT: Option<u32> = Some(226);
/// Exact rows occupied by the frozen hash topology, excluding non-hash semantics.
pub const HX512_FROZEN_HASH_TOPOLOGY_ROW_COUNT: u32 = 11_892;
pub const HX512_FROZEN_HASH_TOPOLOGY_CELL_COUNT: u32 = 12_177_408;
pub const HX512_FROZEN_HASH_TOPOLOGY_EXPLICIT_PADDING_CELLS: u32 = 2_500;
pub const HX512_FROZEN_HASH_TOPOLOGY_OPERATION_COUNT: u32 = 285_744;
pub const HX512_FROZEN_HASH_TOPOLOGY_RFC_ZERO_BYTES_BY_MODE: [u32; 5] =
    [8_748, 8_494, 8_240, 8_570, 8_316];
/// The complete relation includes a separate non-hash compiler and is not frozen.
pub const HX512_FINAL_RELATION_ROW_COUNT: Option<u32> = None;
/// Identity-dependent: no production proof identity has been allocated.
pub const HX512_FINAL_TOPOLOGY_DIGEST_SHA512: Option<[u8; 64]> = None;
pub const HX512_TOPOLOGY_PRODUCTION_AUTHORIZED: bool = false;

const SHAPE_DIGEST_DOMAIN: &[u8] = b"HEGEMON-HX512-RADIX4-TOPOLOGY-V1\0";
const MAX_ROWS: u32 = u16::MAX as u32 + 1;

const BLAKE2B_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RowId(u16);

impl RowId {
    pub fn checked(value: u32) -> Result<Self, Hx512TopologyError> {
        let value = u16::try_from(value).map_err(|_| Hx512TopologyError::RowIdOverflow(value))?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneId(u16);

impl LaneId {
    pub fn checked(value: u32) -> Result<Self, Hx512TopologyError> {
        if value >= HX512_RADIX4_PACKING_FACTOR {
            return Err(Hx512TopologyError::LaneIdOutOfRange(value));
        }
        Ok(Self(value as u16))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellId {
    row: RowId,
    lane: LaneId,
}

impl CellId {
    pub fn checked(row: u32, lane: u32) -> Result<Self, Hx512TopologyError> {
        Ok(Self {
            row: RowId::checked(row)?,
            lane: LaneId::checked(lane)?,
        })
    }

    pub const fn row(self) -> RowId {
        self.row
    }

    pub const fn lane(self) -> LaneId {
        self.lane
    }

    pub fn linear_index(self) -> u32 {
        u32::from(self.row.0) * HX512_RADIX4_PACKING_FACTOR + u32::from(self.lane.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallId(u16);

impl CallId {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompressionId(u16);

impl CompressionId {
    pub fn checked(value: u32) -> Result<Self, Hx512TopologyError> {
        let value =
            u16::try_from(value).map_err(|_| Hx512TopologyError::CompressionIdOverflow(value))?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationId(u32);

impl OperationId {
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorizationMode {
    SingleKey,
    AccumulatorInit,
    ApprovalStep,
    ValueLockCreation,
    FinalThresholdSpend,
}

impl AuthorizationMode {
    pub const ALL: [Self; 5] = [
        Self::SingleKey,
        Self::AccumulatorInit,
        Self::ApprovalStep,
        Self::ValueLockCreation,
        Self::FinalThresholdSpend,
    ];

    const fn tag(self) -> u8 {
        match self {
            Self::SingleKey => 0,
            Self::AccumulatorInit => 1,
            Self::ApprovalStep => 2,
            Self::ValueLockCreation => 3,
            Self::FinalThresholdSpend => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryPosture {
    /// Historical geometry may be tested but can never become authority.
    RejectedHistoricalFixture,
    /// A live design input whose identity and final schedule are not frozen.
    UnfrozenCandidate,
    /// The relation grammar is frozen, but wider production gates remain.
    FrozenCandidate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceSurface {
    Statement,
    VerifierContext,
    PrivateWitness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageWireRange {
    pub surface: SourceSurface,
    pub offset: u32,
    pub len: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectableMessageSource {
    FixedBytes(Vec<u8>),
    Wire(MessageWireRange),
    HashDigest { call: CallId, digest_offset: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageBitSource {
    pub surface: SourceSurface,
    pub byte_offset: u32,
    pub bit_in_byte: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageProvenance {
    FixedBytes(Vec<u8>),
    PublicStatement {
        offset: u32,
    },
    VerifierContext {
        offset: u32,
    },
    PrivateWitness {
        offset: u32,
    },
    HashDigest {
        call: CallId,
        digest_offset: u16,
    },
    LowByte {
        source: MessageWireRange,
    },
    BitSelect {
        selector: MessageBitSource,
        when_zero: SelectableMessageSource,
        when_one: SelectableMessageSource,
    },
    /// This source is intentionally not lowered by the hash topology compiler.
    NonHashDerived {
        recipe: &'static str,
        hash_dependencies: Vec<CallId>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageSpan {
    pub start: u32,
    pub len: u32,
    pub provenance: MessageProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallVariant {
    /// `None` means the recipe is identical under every authorization mode.
    pub mode: Option<AuthorizationMode>,
    pub message_len: u32,
    /// Spans must partition `0..message_len` exactly and in order.
    pub spans: Vec<MessageSpan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicSurface {
    Statement,
    VerifierContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetCondition {
    Always,
    InputActive(u8),
    OutputActive(u8),
    StablecoinEnabled,
    StablecoinMint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicDigestTarget {
    pub surface: PublicSurface,
    pub offset: u32,
    pub condition: TargetCondition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedBlake2bCall {
    pub id: CallId,
    pub family: &'static str,
    pub role: [u8; 8],
    /// RFC 7693 unkeyed BLAKE2b-512 personalization.  Core framed calls use
    /// all zeroes; the stablecoin authority uses its frozen 16-byte values.
    pub personalization: [u8; 16],
    /// The topology reserves this many compression slots for every variant.
    pub fixed_compressions: u8,
    pub variants: Vec<CallVariant>,
    pub public_targets: Vec<PublicDigestTarget>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateSelectorSource {
    pub offset: u32,
    pub len: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedCallRegistry {
    pub name: &'static str,
    pub posture: RegistryPosture,
    pub statement_bytes: u32,
    pub verifier_context_bytes: u32,
    pub private_witness_bytes: u32,
    /// Required exactly when any call has five authorization-mode variants.
    pub authorization_mode_source: Option<PrivateSelectorSource>,
    pub calls: Vec<TypedBlake2bCall>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BatchKind {
    Source,
    Message,
    AdditionSum,
    AdditionCarry,
    AdditionFinalCarry,
    EvenXor,
    EvenRotate,
    OddXor,
    OddShift,
    OddRotate,
    FeedforwardFirst,
    FeedforwardSecond,
    SelectedControl,
    DigestMux,
    DigestBroadcast,
}

impl BatchKind {
    const ALL: [Self; 15] = [
        Self::Source,
        Self::Message,
        Self::AdditionSum,
        Self::AdditionCarry,
        Self::AdditionFinalCarry,
        Self::EvenXor,
        Self::EvenRotate,
        Self::OddXor,
        Self::OddShift,
        Self::OddRotate,
        Self::FeedforwardFirst,
        Self::FeedforwardSecond,
        Self::SelectedControl,
        Self::DigestMux,
        Self::DigestBroadcast,
    ];

    const fn tag(self) -> u8 {
        match self {
            Self::Source => 0,
            Self::Message => 1,
            Self::AdditionSum => 2,
            Self::AdditionCarry => 3,
            Self::AdditionFinalCarry => 4,
            Self::EvenXor => 5,
            Self::EvenRotate => 6,
            Self::OddXor => 7,
            Self::OddShift => 8,
            Self::OddRotate => 9,
            Self::FeedforwardFirst => 10,
            Self::FeedforwardSecond => 11,
            Self::SelectedControl => 12,
            Self::DigestMux => 13,
            Self::DigestBroadcast => 14,
        }
    }

    fn is_word_batch(self) -> bool {
        !matches!(self, Self::Source | Self::AdditionFinalCarry)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchLayout {
    pub kind: BatchKind,
    pub start_row: RowId,
    pub row_count: u16,
    pub logical_cells: u32,
    pub padding_cells: u32,
}

impl BatchLayout {
    pub fn cell(&self, offset: u32) -> Result<CellId, Hx512TopologyError> {
        if offset >= self.logical_cells {
            return Err(Hx512TopologyError::BatchCellOutOfRange {
                batch: self.kind,
                offset,
                logical_cells: self.logical_cells,
            });
        }
        let row = u32::from(self.start_row.get()) + offset / HX512_RADIX4_PACKING_FACTOR;
        let lane = offset % HX512_RADIX4_PACKING_FACTOR;
        CellId::checked(row, lane)
    }

    pub fn word_cell(&self, word: u32) -> Result<CellId, Hx512TopologyError> {
        if !self.kind.is_word_batch() {
            return Err(Hx512TopologyError::NotAWordBatch(self.kind));
        }
        let offset = word
            .checked_mul(HX512_RADIX_DIGITS_PER_WORD)
            .ok_or(Hx512TopologyError::ArithmeticOverflow("word cell offset"))?;
        let cell = self.cell(offset)?;
        if u32::from(cell.lane().get()) % HX512_RADIX_DIGITS_PER_WORD != 0 {
            return Err(Hx512TopologyError::WordLaneMisaligned {
                batch: self.kind,
                word,
                lane: cell.lane().get(),
            });
        }
        Ok(cell)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressionControl {
    pub active: bool,
    pub counter_low: u64,
    pub counter_high: u64,
    pub final_block: bool,
    pub last_node: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledCompression {
    pub id: CompressionId,
    pub call: CallId,
    pub slot: u8,
    pub controls: [CompressionControl; 5],
    pub message_bytes_by_mode: [u8; 5],
    pub rfc_zero_padding_bytes_by_mode: [u8; 5],
    pub mode_selected_control: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    SelectedCounter,
    SelectedFinalFlag,
    AddTernary,
    AddBinary,
    EvenXor,
    EvenRotate(u8),
    OddXor,
    OddShift,
    OddRotate63,
    FeedforwardFirst,
    FeedforwardSecond,
    DigestMux,
    DigestBroadcast,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MixHalfRound {
    Column,
    Diagonal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MixOperationStep {
    AddAx,
    XorDa,
    RotateD32,
    AddCd,
    XorBc,
    RotateB24,
    AddAy,
    XorDaSecond,
    RotateD16,
    AddCdSecond,
    XorBcSecond,
    ShiftB63,
    RotateB63,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FeedforwardStage {
    First,
    Second,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SelectedControlWord {
    CounterLow,
    FinalFlag,
}

/// Stable key for one word operation in the secret-independent schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperationCoordinate {
    SelectedControl {
        call: CallId,
        compression: CompressionId,
        word: SelectedControlWord,
    },
    Mix {
        call: CallId,
        compression: CompressionId,
        round: u8,
        half: MixHalfRound,
        g: u8,
        step: MixOperationStep,
    },
    Feedforward {
        call: CallId,
        compression: CompressionId,
        stage: FeedforwardStage,
        word: u8,
    },
    DigestMux {
        call: CallId,
        word: u8,
    },
    DigestBroadcast {
        call: CallId,
        word: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopologyValueRef {
    Constant(u64),
    SourceRange {
        first: CellId,
        cells: u16,
    },
    Message {
        compression: CompressionId,
        word: u8,
    },
    Operation(OperationId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Dependencies {
    len: u8,
    values: [TopologyValueRef; 3],
}

impl Dependencies {
    fn one(a: TopologyValueRef) -> Self {
        Self {
            len: 1,
            values: [
                a,
                TopologyValueRef::Constant(0),
                TopologyValueRef::Constant(0),
            ],
        }
    }

    fn two(a: TopologyValueRef, b: TopologyValueRef) -> Self {
        Self {
            len: 2,
            values: [a, b, TopologyValueRef::Constant(0)],
        }
    }

    fn three(a: TopologyValueRef, b: TopologyValueRef, c: TopologyValueRef) -> Self {
        Self {
            len: 3,
            values: [a, b, c],
        }
    }

    fn iter(self) -> impl Iterator<Item = TopologyValueRef> {
        self.values.into_iter().take(usize::from(self.len))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationRecord {
    pub id: OperationId,
    pub event: u32,
    pub kind: OperationKind,
    pub coordinate: OperationCoordinate,
    pub output: CellId,
    dependencies: Dependencies,
    /// Addition producers also own 32 carry digits and one final carry cell.
    addition_carry_output: Option<CellId>,
    addition_final_carry_output: Option<CellId>,
}

impl OperationRecord {
    pub fn dependencies(&self) -> impl Iterator<Item = TopologyValueRef> {
        self.dependencies.iter()
    }

    pub const fn addition_carry_output(&self) -> Option<CellId> {
        self.addition_carry_output
    }

    pub const fn addition_final_carry_output(&self) -> Option<CellId> {
        self.addition_final_carry_output
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompiledCallSummary {
    pub id: CallId,
    pub first_compression: CompressionId,
    pub fixed_compressions: u8,
    pub actual_compressions_by_mode: [u8; 5],
    pub selected_digest_state_by_mode: [u8; 5],
    pub parameter_block: [u8; 64],
    pub parameter_words: [u64; 8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompiledDigestManifest {
    pub call: CallId,
    /// Last active compression output before mode selection.
    pub terminal_operations_by_mode: [[OperationId; 8]; 5],
    /// Canonical output after any required mode mux and broadcast.
    pub exported_operations: [OperationId; 8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompiledMessageDigitSource {
    Fixed(u8),
    Source(CellId),
    Digest(CellId),
    Selected {
        selector_cell: CellId,
        selector_bit_in_digit: u8,
        when_zero: CompiledSelectableDigitSource,
        when_one: CompiledSelectableDigitSource,
    },
    NonHashDerived {
        call: CallId,
        span_index: u16,
        byte_in_span: u32,
        digit: u8,
    },
    RfcZero,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompiledSelectableDigitSource {
    Fixed(u8),
    Source(CellId),
    Digest(CellId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompiledMessageDigitBinding {
    pub call: CallId,
    pub mode: AuthorizationMode,
    pub slot: u8,
    pub byte: u8,
    pub digit: u8,
    pub compression: CompressionId,
    pub message_cell: CellId,
    pub source: CompiledMessageDigitSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicTargetCellBinding {
    pub call: CallId,
    pub target_index: u16,
    pub target: PublicDigestTarget,
    pub digest_byte: u8,
    pub digit: u8,
    pub digest_cell: CellId,
    pub public_cell: CellId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512TopologyGeometry {
    pub call_count: u32,
    pub compression_count: u32,
    pub source_bits: u32,
    pub source_rows: u32,
    pub message_rows: u32,
    pub core_rows: u32,
    pub direct_base_rows: u32,
    pub direct_base_cells: u32,
    pub explicit_padding_cells: u32,
    pub rfc_zero_padding_bytes_by_mode: [u32; 5],
    pub mode_selected_control_positions: u32,
    pub mode_selected_digest_calls: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledHx512Topology {
    pub registry_name: &'static str,
    pub posture: RegistryPosture,
    pub geometry: Hx512TopologyGeometry,
    pub batches: Vec<BatchLayout>,
    pub calls: Vec<CompiledCallSummary>,
    pub compressions: Vec<CompiledCompression>,
    pub digest_manifests: Vec<CompiledDigestManifest>,
    pub operations: Vec<OperationRecord>,
    pub shape_digest_sha512: [u8; 64],
    compression_events: Vec<u32>,
    compression_message_dependencies: Vec<Vec<OperationId>>,
}

impl CompiledHx512Topology {
    pub fn batch(&self, kind: BatchKind) -> Option<&BatchLayout> {
        self.batches.iter().find(|batch| batch.kind == kind)
    }

    pub fn ensure_production_authorized(&self) -> Result<(), Hx512TopologyError> {
        Err(Hx512TopologyError::ProductionAuthorizationUnavailable)
    }

    pub fn compression_message_event(&self, compression: CompressionId) -> Option<u32> {
        self.compression_events
            .get(usize::from(compression.get()))
            .copied()
    }

    pub fn compression_message_dependencies(
        &self,
        compression: CompressionId,
    ) -> Option<&[OperationId]> {
        self.compression_message_dependencies
            .get(usize::from(compression.get()))
            .map(Vec::as_slice)
    }

    pub fn call_compression_id(
        &self,
        call: CallId,
        slot: u8,
    ) -> Result<CompressionId, Hx512TopologyError> {
        let summary = self.calls.iter().find(|summary| summary.id == call).ok_or(
            Hx512TopologyError::ScheduleMismatch("call compression manifest"),
        )?;
        if slot >= summary.fixed_compressions {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "call compression slot",
            ));
        }
        CompressionId::checked(u32::from(summary.first_compression.get()) + u32::from(slot))
    }

    pub fn message_word_cell(
        &self,
        compression: CompressionId,
        word: u8,
    ) -> Result<CellId, Hx512TopologyError> {
        if word >= HX512_MESSAGE_WORDS_PER_COMPRESSION as u8
            || usize::from(compression.get()) >= self.compressions.len()
        {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "message manifest coordinate",
            ));
        }
        let index =
            u32::from(compression.get()) * HX512_MESSAGE_WORDS_PER_COMPRESSION + u32::from(word);
        self.batch(BatchKind::Message)
            .expect("message batch")
            .word_cell(index)
    }

    pub fn message_digit_cell(
        &self,
        compression: CompressionId,
        byte: u8,
        digit: u8,
    ) -> Result<CellId, Hx512TopologyError> {
        if byte >= HX512_COMPRESSION_BLOCK_BYTES as u8 || digit >= 4 {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "message byte/digit coordinate",
            ));
        }
        let offset = u32::from(compression.get()) * HX512_COMPRESSION_BLOCK_BYTES * 4
            + u32::from(byte) * 4
            + u32::from(digit);
        self.batch(BatchKind::Message)
            .expect("message batch")
            .cell(offset)
    }

    pub fn source_byte_digit_cell(
        &self,
        registry: &TypedCallRegistry,
        surface: SourceSurface,
        byte: u32,
        digit: u8,
    ) -> Result<CellId, Hx512TopologyError> {
        if digit >= 4 {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "source digit coordinate",
            ));
        }
        let (base, width) = match surface {
            SourceSurface::Statement => (0, registry.statement_bytes),
            SourceSurface::VerifierContext => {
                (registry.statement_bytes, registry.verifier_context_bytes)
            }
            SourceSurface::PrivateWitness => (
                registry
                    .statement_bytes
                    .checked_add(registry.verifier_context_bytes)
                    .ok_or(Hx512TopologyError::ArithmeticOverflow(
                        "source surface base",
                    ))?,
                registry.private_witness_bytes,
            ),
        };
        if byte >= width {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "source byte coordinate",
            ));
        }
        let absolute = base
            .checked_add(byte)
            .and_then(|value| value.checked_mul(4))
            .and_then(|value| value.checked_add(u32::from(digit)))
            .ok_or(Hx512TopologyError::ArithmeticOverflow("source digit cell"))?;
        self.batch(BatchKind::Source)
            .expect("source batch")
            .cell(absolute)
    }

    fn operation_word_digit_cell(
        &self,
        operation: OperationId,
        byte_in_word: u8,
        digit: u8,
    ) -> Result<CellId, Hx512TopologyError> {
        if byte_in_word >= 8 || digit >= 4 {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "operation byte/digit coordinate",
            ));
        }
        let first = self
            .operations
            .get(operation.get() as usize)
            .ok_or(Hx512TopologyError::ScheduleMismatch(
                "missing digest operation",
            ))?
            .output;
        CellId::checked(
            u32::from(first.row().get()),
            u32::from(first.lane().get()) + u32::from(byte_in_word) * 4 + u32::from(digit),
        )
    }

    pub fn exported_digest_digit_cell(
        &self,
        call: CallId,
        byte: u8,
        digit: u8,
    ) -> Result<CellId, Hx512TopologyError> {
        if byte >= 64 {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "digest byte coordinate",
            ));
        }
        let manifest = self
            .digest_manifests
            .iter()
            .find(|manifest| manifest.call == call)
            .ok_or(Hx512TopologyError::ScheduleMismatch(
                "missing digest manifest",
            ))?;
        self.operation_word_digit_cell(
            manifest.exported_operations[usize::from(byte / 8)],
            byte % 8,
            digit,
        )
    }

    pub fn terminal_digest_digit_cell(
        &self,
        call: CallId,
        mode: AuthorizationMode,
        byte: u8,
        digit: u8,
    ) -> Result<CellId, Hx512TopologyError> {
        if byte >= 64 {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "terminal digest byte coordinate",
            ));
        }
        let manifest = self
            .digest_manifests
            .iter()
            .find(|manifest| manifest.call == call)
            .ok_or(Hx512TopologyError::ScheduleMismatch(
                "missing digest manifest",
            ))?;
        self.operation_word_digit_cell(
            manifest.terminal_operations_by_mode[usize::from(mode.tag())][usize::from(byte / 8)],
            byte % 8,
            digit,
        )
    }

    fn selectable_digit_source(
        &self,
        registry: &TypedCallRegistry,
        source: &SelectableMessageSource,
        byte: u32,
        digit: u8,
    ) -> Result<CompiledSelectableDigitSource, Hx512TopologyError> {
        match source {
            SelectableMessageSource::FixedBytes(bytes) => {
                let value =
                    *bytes
                        .get(byte as usize)
                        .ok_or(Hx512TopologyError::ScheduleMismatch(
                            "selectable literal byte",
                        ))?;
                Ok(CompiledSelectableDigitSource::Fixed(
                    (value >> (digit * 2)) & 3,
                ))
            }
            SelectableMessageSource::Wire(range) => {
                if byte >= range.len {
                    return Err(Hx512TopologyError::ScheduleMismatch("selectable wire byte"));
                }
                Ok(CompiledSelectableDigitSource::Source(
                    self.source_byte_digit_cell(
                        registry,
                        range.surface,
                        range.offset + byte,
                        digit,
                    )?,
                ))
            }
            SelectableMessageSource::HashDigest {
                call,
                digest_offset,
            } => Ok(CompiledSelectableDigitSource::Digest(
                self.exported_digest_digit_cell(
                    *call,
                    (u32::from(*digest_offset) + byte) as u8,
                    digit,
                )?,
            )),
        }
    }

    pub fn compiled_message_digit_source(
        &self,
        registry: &TypedCallRegistry,
        call_id: CallId,
        mode: AuthorizationMode,
        slot: u8,
        byte: u8,
        digit: u8,
    ) -> Result<CompiledMessageDigitSource, Hx512TopologyError> {
        if byte >= 128 || digit >= 4 {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "compiled message coordinate",
            ));
        }
        let call = registry
            .calls
            .iter()
            .find(|call| call.id == call_id)
            .ok_or(Hx512TopologyError::ScheduleMismatch(
                "compiled message call",
            ))?;
        if slot >= call.fixed_compressions {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "compiled message compression slot",
            ));
        }
        let variant = call_variant_for_mode(call, mode)?;
        let message_byte = u32::from(slot) * HX512_COMPRESSION_BLOCK_BYTES + u32::from(byte);
        if message_byte >= variant.message_len {
            return Ok(CompiledMessageDigitSource::RfcZero);
        }
        let (span_index, span) = variant
            .spans
            .iter()
            .enumerate()
            .find(|(_, span)| message_byte >= span.start && message_byte < span.start + span.len)
            .ok_or(Hx512TopologyError::InvalidMessagePartition {
                call: call_id,
                mode: variant.mode,
            })?;
        let byte_in_span = message_byte - span.start;
        match &span.provenance {
            MessageProvenance::FixedBytes(bytes) => {
                let value = bytes[byte_in_span as usize];
                Ok(CompiledMessageDigitSource::Fixed(
                    (value >> (digit * 2)) & 3,
                ))
            }
            MessageProvenance::PublicStatement { offset } => Ok(
                CompiledMessageDigitSource::Source(self.source_byte_digit_cell(
                    registry,
                    SourceSurface::Statement,
                    offset + byte_in_span,
                    digit,
                )?),
            ),
            MessageProvenance::VerifierContext { offset } => Ok(
                CompiledMessageDigitSource::Source(self.source_byte_digit_cell(
                    registry,
                    SourceSurface::VerifierContext,
                    offset + byte_in_span,
                    digit,
                )?),
            ),
            MessageProvenance::PrivateWitness { offset } => Ok(CompiledMessageDigitSource::Source(
                self.source_byte_digit_cell(
                    registry,
                    SourceSurface::PrivateWitness,
                    offset + byte_in_span,
                    digit,
                )?,
            )),
            MessageProvenance::HashDigest {
                call,
                digest_offset,
            } => Ok(CompiledMessageDigitSource::Digest(
                self.exported_digest_digit_cell(
                    *call,
                    (u32::from(*digest_offset) + byte_in_span) as u8,
                    digit,
                )?,
            )),
            MessageProvenance::LowByte { source } => {
                let low_byte = source.offset.checked_add(source.len - 1).ok_or(
                    Hx512TopologyError::ArithmeticOverflow("low-byte source offset"),
                )?;
                Ok(CompiledMessageDigitSource::Source(
                    self.source_byte_digit_cell(registry, source.surface, low_byte, digit)?,
                ))
            }
            MessageProvenance::BitSelect {
                selector,
                when_zero,
                when_one,
            } => {
                let selector_digit = selector.bit_in_byte / 2;
                Ok(CompiledMessageDigitSource::Selected {
                    selector_cell: self.source_byte_digit_cell(
                        registry,
                        selector.surface,
                        selector.byte_offset,
                        selector_digit,
                    )?,
                    selector_bit_in_digit: selector.bit_in_byte % 2,
                    when_zero: self.selectable_digit_source(
                        registry,
                        when_zero,
                        byte_in_span,
                        digit,
                    )?,
                    when_one: self.selectable_digit_source(
                        registry,
                        when_one,
                        byte_in_span,
                        digit,
                    )?,
                })
            }
            MessageProvenance::NonHashDerived { .. } => {
                Ok(CompiledMessageDigitSource::NonHashDerived {
                    call: call_id,
                    span_index: u16::try_from(span_index).map_err(|_| {
                        Hx512TopologyError::ArithmeticOverflow("message span index")
                    })?,
                    byte_in_span,
                    digit,
                })
            }
        }
    }

    pub fn compiled_message_digit_binding(
        &self,
        registry: &TypedCallRegistry,
        call: CallId,
        mode: AuthorizationMode,
        slot: u8,
        byte: u8,
        digit: u8,
    ) -> Result<CompiledMessageDigitBinding, Hx512TopologyError> {
        let compression = self.call_compression_id(call, slot)?;
        Ok(CompiledMessageDigitBinding {
            call,
            mode,
            slot,
            byte,
            digit,
            compression,
            message_cell: self.message_digit_cell(compression, byte, digit)?,
            source: self.compiled_message_digit_source(registry, call, mode, slot, byte, digit)?,
        })
    }

    pub fn public_target_cell_binding(
        &self,
        registry: &TypedCallRegistry,
        call: CallId,
        target_index: u16,
        digest_byte: u8,
        digit: u8,
    ) -> Result<PublicTargetCellBinding, Hx512TopologyError> {
        if digest_byte >= 64 || digit >= 4 {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "public target digest coordinate",
            ));
        }
        let call_recipe = registry
            .calls
            .iter()
            .find(|recipe| recipe.id == call)
            .ok_or(Hx512TopologyError::ScheduleMismatch("public target call"))?;
        let target = *call_recipe
            .public_targets
            .get(usize::from(target_index))
            .ok_or(Hx512TopologyError::ScheduleMismatch("public target index"))?;
        let surface = match target.surface {
            PublicSurface::Statement => SourceSurface::Statement,
            PublicSurface::VerifierContext => SourceSurface::VerifierContext,
        };
        Ok(PublicTargetCellBinding {
            call,
            target_index,
            target,
            digest_byte,
            digit,
            digest_cell: self.exported_digest_digit_cell(call, digest_byte, digit)?,
            public_cell: self.source_byte_digit_cell(
                registry,
                surface,
                target.offset + u32::from(digest_byte),
                digit,
            )?,
        })
    }

    pub fn row_zero_padding_cells(&self) -> Result<Vec<(BatchKind, CellId)>, Hx512TopologyError> {
        let mut cells = Vec::with_capacity(self.geometry.explicit_padding_cells as usize);
        for batch in &self.batches {
            let physical = u32::from(batch.row_count) * HX512_RADIX4_PACKING_FACTOR;
            for offset in batch.logical_cells..physical {
                let row = u32::from(batch.start_row.get()) + offset / HX512_RADIX4_PACKING_FACTOR;
                let lane = offset % HX512_RADIX4_PACKING_FACTOR;
                cells.push((batch.kind, CellId::checked(row, lane)?));
            }
        }
        Ok(cells)
    }

    pub fn audit(&self, registry: &TypedCallRegistry) -> Result<(), Hx512TopologyError> {
        audit_registry(registry)?;
        audit_batch_partition(self)?;
        audit_operation_producers(self)?;
        audit_operation_coordinates(self)?;
        audit_digest_manifests(self)?;
        audit_earlier_consumers(self)?;
        audit_call_schedule(self, registry)?;
        let observed = shape_digest(self, registry);
        if observed != self.shape_digest_sha512 {
            return Err(Hx512TopologyError::ShapeDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hx512TopologyError {
    RowIdOverflow(u32),
    LaneIdOutOfRange(u32),
    CompressionIdOverflow(u32),
    ArithmeticOverflow(&'static str),
    TooManyRows(u32),
    EmptyRegistry,
    DuplicateCallId(CallId),
    MissingCallDependency {
        consumer: CallId,
        producer: CallId,
    },
    CyclicCallDependencies,
    EmptyCallVariants(CallId),
    InvalidVariantSet(CallId),
    MissingAuthorizationModeSource,
    InvalidAuthorizationModeSource,
    InvalidMessageLength {
        call: CallId,
        len: u32,
    },
    InvalidMessagePartition {
        call: CallId,
        mode: Option<AuthorizationMode>,
    },
    ProvenanceOutOfBounds {
        call: CallId,
        surface: PublicSurface,
        end: u32,
    },
    PrivateProvenanceOutOfBounds {
        call: CallId,
        end: u32,
    },
    DigestProvenanceOutOfBounds {
        call: CallId,
        producer: CallId,
        end: u32,
    },
    CompressionSlotsTooSmall {
        call: CallId,
        required: u32,
        fixed: u8,
    },
    NonCanonicalCompressionSlots {
        call: CallId,
        required: u32,
        fixed: u8,
    },
    InvalidPublicTarget {
        call: CallId,
        surface: PublicSurface,
        end: u32,
    },
    BatchCellOutOfRange {
        batch: BatchKind,
        offset: u32,
        logical_cells: u32,
    },
    NotAWordBatch(BatchKind),
    WordLaneMisaligned {
        batch: BatchKind,
        word: u32,
        lane: u16,
    },
    BatchPartition,
    DuplicateCellProducer(CellId),
    UnproducedCell(CellId),
    InvalidPaddingCell(CellId),
    ForwardOperationDependency {
        consumer: OperationId,
        producer: OperationId,
    },
    MessageConsumedBeforeMaterialization {
        operation: OperationId,
        compression: CompressionId,
    },
    HashMessageDependencyNotEarlier {
        compression: CompressionId,
        producer: OperationId,
    },
    RelationRegistryConversion(&'static str),
    ScheduleMismatch(&'static str),
    ShapeDigestMismatch,
    ProductionAuthorizationUnavailable,
}

impl std::fmt::Display for Hx512TopologyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "HX512 topology error: {self:?}")
    }
}

impl std::error::Error for Hx512TopologyError {}

fn ceil_div(value: u32, divisor: u32) -> Result<u32, Hx512TopologyError> {
    if divisor == 0 {
        return Err(Hx512TopologyError::ArithmeticOverflow("zero divisor"));
    }
    value
        .checked_add(divisor - 1)
        .ok_or(Hx512TopologyError::ArithmeticOverflow("ceil-div"))
        .map(|sum| sum / divisor)
}

fn checked_mul(left: u32, right: u32, label: &'static str) -> Result<u32, Hx512TopologyError> {
    left.checked_mul(right)
        .ok_or(Hx512TopologyError::ArithmeticOverflow(label))
}

fn parameter_block(personalization: [u8; 16]) -> [u8; 64] {
    let mut block = [0u8; 64];
    block[0] = 64;
    block[2] = 1;
    block[3] = 1;
    block[48..64].copy_from_slice(&personalization);
    block
}

fn parameter_words(block: [u8; 64]) -> [u64; 8] {
    std::array::from_fn(|index| {
        u64::from_le_bytes(
            block[index * 8..index * 8 + 8]
                .try_into()
                .expect("fixed parameter word width"),
        )
    })
}

fn call_variant_for_mode<'a>(
    call: &'a TypedBlake2bCall,
    mode: AuthorizationMode,
) -> Result<&'a CallVariant, Hx512TopologyError> {
    if call.variants.len() == 1 && call.variants[0].mode.is_none() {
        return Ok(&call.variants[0]);
    }
    call.variants
        .iter()
        .find(|variant| variant.mode == Some(mode))
        .ok_or(Hx512TopologyError::InvalidVariantSet(call.id))
}

fn actual_compressions(message_len: u32) -> u32 {
    std::cmp::max(1, message_len.div_ceil(HX512_COMPRESSION_BLOCK_BYTES))
}

fn compression_control(message_len: u32, slot: u32) -> CompressionControl {
    let actual = actual_compressions(message_len);
    let active = slot < actual;
    let bounded_block_end = (slot + 1)
        .saturating_mul(HX512_COMPRESSION_BLOCK_BYTES)
        .min(message_len);
    CompressionControl {
        active,
        counter_low: u64::from(bounded_block_end),
        counter_high: 0,
        final_block: slot + 1 == actual,
        last_node: false,
    }
}

fn selectable_dependency(source: &SelectableMessageSource) -> Option<CallId> {
    match source {
        SelectableMessageSource::HashDigest { call, .. } => Some(*call),
        _ => None,
    }
}

fn provenance_dependencies(provenance: &MessageProvenance) -> Vec<CallId> {
    match provenance {
        MessageProvenance::HashDigest { call, .. } => vec![*call],
        MessageProvenance::BitSelect {
            when_zero,
            when_one,
            ..
        } => [
            selectable_dependency(when_zero),
            selectable_dependency(when_one),
        ]
        .into_iter()
        .flatten()
        .collect(),
        MessageProvenance::NonHashDerived {
            hash_dependencies, ..
        } => hash_dependencies.clone(),
        _ => Vec::new(),
    }
}

fn wire_range_width(registry: &TypedCallRegistry, surface: SourceSurface) -> u32 {
    match surface {
        SourceSurface::Statement => registry.statement_bytes,
        SourceSurface::VerifierContext => registry.verifier_context_bytes,
        SourceSurface::PrivateWitness => registry.private_witness_bytes,
    }
}

fn selectable_source_len(source: &SelectableMessageSource) -> Result<u32, Hx512TopologyError> {
    match source {
        SelectableMessageSource::FixedBytes(bytes) => u32::try_from(bytes.len())
            .map_err(|_| Hx512TopologyError::ArithmeticOverflow("selectable literal")),
        SelectableMessageSource::Wire(range) => Ok(range.len),
        SelectableMessageSource::HashDigest { digest_offset, .. } => {
            Ok(64 - u32::from(*digest_offset))
        }
    }
}

fn selectable_source_valid(
    registry: &TypedCallRegistry,
    source: &SelectableMessageSource,
    expected_len: u32,
) -> bool {
    match source {
        SelectableMessageSource::FixedBytes(bytes) => bytes.len() == expected_len as usize,
        SelectableMessageSource::Wire(range) => {
            range.len == expected_len
                && range.len > 0
                && range
                    .offset
                    .checked_add(range.len)
                    .is_some_and(|end| end <= wire_range_width(registry, range.surface))
        }
        SelectableMessageSource::HashDigest { digest_offset, .. } => {
            64 - u32::from(*digest_offset) == expected_len
        }
    }
}

fn audit_registry(registry: &TypedCallRegistry) -> Result<(), Hx512TopologyError> {
    if registry.calls.is_empty() {
        return Err(Hx512TopologyError::EmptyRegistry);
    }
    let mut ids = BTreeSet::new();
    let has_mode_variants = registry.calls.iter().any(|call| {
        call.variants.len() == AuthorizationMode::ALL.len()
            && call.variants.iter().all(|variant| variant.mode.is_some())
    });
    match registry.authorization_mode_source {
        Some(source) => {
            let end = source.offset.checked_add(source.len).ok_or(
                Hx512TopologyError::ArithmeticOverflow("authorization mode source"),
            )?;
            if source.len == 0 || end > registry.private_witness_bytes {
                return Err(Hx512TopologyError::InvalidAuthorizationModeSource);
            }
        }
        None if has_mode_variants => {
            return Err(Hx512TopologyError::MissingAuthorizationModeSource);
        }
        None => {}
    }
    for call in &registry.calls {
        if !ids.insert(call.id) {
            return Err(Hx512TopologyError::DuplicateCallId(call.id));
        }
    }
    for call in &registry.calls {
        if call.variants.is_empty() {
            return Err(Hx512TopologyError::EmptyCallVariants(call.id));
        }
        let fixed = call.variants.len() == 1 && call.variants[0].mode.is_none();
        let modes: BTreeSet<_> = call
            .variants
            .iter()
            .filter_map(|variant| variant.mode)
            .collect();
        if !fixed
            && (call.variants.len() != AuthorizationMode::ALL.len()
                || modes.len() != AuthorizationMode::ALL.len()
                || call.variants.iter().any(|variant| variant.mode.is_none()))
        {
            return Err(Hx512TopologyError::InvalidVariantSet(call.id));
        }
        let maximum_required = call
            .variants
            .iter()
            .map(|variant| actual_compressions(variant.message_len))
            .max()
            .expect("nonempty variants");
        if maximum_required != u32::from(call.fixed_compressions) {
            return Err(Hx512TopologyError::NonCanonicalCompressionSlots {
                call: call.id,
                required: maximum_required,
                fixed: call.fixed_compressions,
            });
        }
        let selected_states: BTreeSet<_> = call
            .variants
            .iter()
            .map(|variant| actual_compressions(variant.message_len))
            .collect();
        if selected_states.len() > 2 {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "digest mux supports exactly two terminal states",
            ));
        }
        for variant in &call.variants {
            if variant.message_len
                > u32::from(call.fixed_compressions) * HX512_COMPRESSION_BLOCK_BYTES
            {
                return Err(Hx512TopologyError::InvalidMessageLength {
                    call: call.id,
                    len: variant.message_len,
                });
            }
            let required = actual_compressions(variant.message_len);
            if required > u32::from(call.fixed_compressions) {
                return Err(Hx512TopologyError::CompressionSlotsTooSmall {
                    call: call.id,
                    required,
                    fixed: call.fixed_compressions,
                });
            }
            let mut cursor = 0u32;
            for span in &variant.spans {
                if span.start != cursor || span.len == 0 {
                    return Err(Hx512TopologyError::InvalidMessagePartition {
                        call: call.id,
                        mode: variant.mode,
                    });
                }
                cursor = cursor
                    .checked_add(span.len)
                    .ok_or(Hx512TopologyError::ArithmeticOverflow("message span"))?;
                match &span.provenance {
                    MessageProvenance::FixedBytes(bytes) if bytes.len() != span.len as usize => {
                        return Err(Hx512TopologyError::InvalidMessagePartition {
                            call: call.id,
                            mode: variant.mode,
                        });
                    }
                    MessageProvenance::PublicStatement { offset } => {
                        let end = offset
                            .checked_add(span.len)
                            .ok_or(Hx512TopologyError::ArithmeticOverflow("public provenance"))?;
                        if end > registry.statement_bytes {
                            return Err(Hx512TopologyError::ProvenanceOutOfBounds {
                                call: call.id,
                                surface: PublicSurface::Statement,
                                end,
                            });
                        }
                    }
                    MessageProvenance::VerifierContext { offset } => {
                        let end = offset
                            .checked_add(span.len)
                            .ok_or(Hx512TopologyError::ArithmeticOverflow("context provenance"))?;
                        if end > registry.verifier_context_bytes {
                            return Err(Hx512TopologyError::ProvenanceOutOfBounds {
                                call: call.id,
                                surface: PublicSurface::VerifierContext,
                                end,
                            });
                        }
                    }
                    MessageProvenance::PrivateWitness { offset } => {
                        let end = offset
                            .checked_add(span.len)
                            .ok_or(Hx512TopologyError::ArithmeticOverflow("private provenance"))?;
                        if end > registry.private_witness_bytes {
                            return Err(Hx512TopologyError::PrivateProvenanceOutOfBounds {
                                call: call.id,
                                end,
                            });
                        }
                    }
                    MessageProvenance::HashDigest {
                        call: producer,
                        digest_offset,
                    } => {
                        let end = u32::from(*digest_offset)
                            .checked_add(span.len)
                            .ok_or(Hx512TopologyError::ArithmeticOverflow("digest provenance"))?;
                        if end > 64 {
                            return Err(Hx512TopologyError::DigestProvenanceOutOfBounds {
                                call: call.id,
                                producer: *producer,
                                end,
                            });
                        }
                    }
                    MessageProvenance::LowByte { source } => {
                        if span.len != 1
                            || source.len == 0
                            || source
                                .offset
                                .checked_add(source.len)
                                .is_none_or(|end| end > wire_range_width(registry, source.surface))
                        {
                            return Err(Hx512TopologyError::InvalidMessagePartition {
                                call: call.id,
                                mode: variant.mode,
                            });
                        }
                    }
                    MessageProvenance::BitSelect {
                        selector,
                        when_zero,
                        when_one,
                    } => {
                        if selector.bit_in_byte >= 8
                            || selector.byte_offset >= wire_range_width(registry, selector.surface)
                            || !selectable_source_valid(registry, when_zero, span.len)
                            || !selectable_source_valid(registry, when_one, span.len)
                            || selectable_source_len(when_zero)? != selectable_source_len(when_one)?
                        {
                            return Err(Hx512TopologyError::InvalidMessagePartition {
                                call: call.id,
                                mode: variant.mode,
                            });
                        }
                    }
                    _ => {}
                }
            }
            if cursor != variant.message_len {
                return Err(Hx512TopologyError::InvalidMessagePartition {
                    call: call.id,
                    mode: variant.mode,
                });
            }
        }
        for target in &call.public_targets {
            if matches!(target.condition, TargetCondition::InputActive(index) if index >= 2)
                || matches!(target.condition, TargetCondition::OutputActive(index) if index >= 2)
            {
                return Err(Hx512TopologyError::InvalidPublicTarget {
                    call: call.id,
                    surface: target.surface,
                    end: target.offset,
                });
            }
            let width = match target.surface {
                PublicSurface::Statement => registry.statement_bytes,
                PublicSurface::VerifierContext => registry.verifier_context_bytes,
            };
            let end = target
                .offset
                .checked_add(64)
                .ok_or(Hx512TopologyError::ArithmeticOverflow("public target"))?;
            if end > width {
                return Err(Hx512TopologyError::InvalidPublicTarget {
                    call: call.id,
                    surface: target.surface,
                    end,
                });
            }
        }
    }

    let mut indegree: BTreeMap<CallId, u32> =
        registry.calls.iter().map(|call| (call.id, 0)).collect();
    let mut edges: BTreeMap<CallId, BTreeSet<CallId>> = BTreeMap::new();
    for call in &registry.calls {
        let dependencies: BTreeSet<_> = call
            .variants
            .iter()
            .flat_map(|variant| variant.spans.iter())
            .flat_map(|span| provenance_dependencies(&span.provenance))
            .collect();
        for producer in dependencies {
            if !ids.contains(&producer) {
                return Err(Hx512TopologyError::MissingCallDependency {
                    consumer: call.id,
                    producer,
                });
            }
            if edges.entry(producer).or_default().insert(call.id) {
                *indegree.get_mut(&call.id).expect("registered call") += 1;
            }
        }
    }
    let mut ready: BTreeSet<_> = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
        .collect();
    let mut visited = 0usize;
    while let Some(id) = ready.pop_first() {
        visited += 1;
        for consumer in edges.get(&id).into_iter().flatten() {
            let degree = indegree.get_mut(consumer).expect("registered consumer");
            *degree -= 1;
            if *degree == 0 {
                ready.insert(*consumer);
            }
        }
    }
    if visited != registry.calls.len() {
        return Err(Hx512TopologyError::CyclicCallDependencies);
    }
    Ok(())
}

fn topological_call_order(registry: &TypedCallRegistry) -> Result<Vec<CallId>, Hx512TopologyError> {
    let ids: BTreeSet<_> = registry.calls.iter().map(|call| call.id).collect();
    let mut indegree: BTreeMap<CallId, u32> =
        registry.calls.iter().map(|call| (call.id, 0)).collect();
    let mut edges: BTreeMap<CallId, BTreeSet<CallId>> = BTreeMap::new();
    for call in &registry.calls {
        let dependencies: BTreeSet<_> = call
            .variants
            .iter()
            .flat_map(|variant| variant.spans.iter())
            .flat_map(|span| provenance_dependencies(&span.provenance))
            .collect();
        for producer in dependencies {
            if !ids.contains(&producer) {
                return Err(Hx512TopologyError::MissingCallDependency {
                    consumer: call.id,
                    producer,
                });
            }
            if edges.entry(producer).or_default().insert(call.id) {
                *indegree.get_mut(&call.id).expect("registered call") += 1;
            }
        }
    }
    let mut ready: BTreeSet<_> = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
        .collect();
    let mut order = Vec::with_capacity(registry.calls.len());
    while let Some(id) = ready.pop_first() {
        order.push(id);
        for consumer in edges.get(&id).into_iter().flatten() {
            let degree = indegree.get_mut(consumer).expect("registered consumer");
            *degree -= 1;
            if *degree == 0 {
                ready.insert(*consumer);
            }
        }
    }
    if order.len() != registry.calls.len() {
        return Err(Hx512TopologyError::CyclicCallDependencies);
    }
    Ok(order)
}

fn batch_layouts(
    source_bits: u32,
    compression_count: u32,
    selected_controls: u32,
    digest_mux_calls: u32,
) -> Result<Vec<BatchLayout>, Hx512TopologyError> {
    let source_digits = ceil_div(source_bits, HX512_RADIX_BITS)?;
    let message_words = checked_mul(
        compression_count,
        HX512_MESSAGE_WORDS_PER_COMPRESSION,
        "message words",
    )?;
    let addition_words = checked_mul(
        compression_count,
        HX512_ADDITIONS_PER_COMPRESSION,
        "addition words",
    )?;
    let even_words = checked_mul(
        compression_count,
        HX512_EVEN_XORS_PER_COMPRESSION,
        "even XOR words",
    )?;
    let odd_words = checked_mul(
        compression_count,
        HX512_ODD_XORS_PER_COMPRESSION,
        "odd XOR words",
    )?;
    let feed_words = checked_mul(
        compression_count,
        HX512_FEEDFORWARD_WORDS_PER_STAGE,
        "feedforward words",
    )?;
    let control_words = checked_mul(selected_controls, 2, "selected control words")?;
    let mux_words = checked_mul(digest_mux_calls, 8, "digest mux words")?;
    let logical = [
        (BatchKind::Source, source_digits),
        (
            BatchKind::Message,
            checked_mul(message_words, HX512_RADIX_DIGITS_PER_WORD, "message cells")?,
        ),
        (
            BatchKind::AdditionSum,
            checked_mul(
                addition_words,
                HX512_RADIX_DIGITS_PER_WORD,
                "addition sum cells",
            )?,
        ),
        (
            BatchKind::AdditionCarry,
            checked_mul(
                addition_words,
                HX512_RADIX_DIGITS_PER_WORD,
                "addition carry cells",
            )?,
        ),
        (BatchKind::AdditionFinalCarry, addition_words),
        (
            BatchKind::EvenXor,
            checked_mul(even_words, HX512_RADIX_DIGITS_PER_WORD, "even XOR cells")?,
        ),
        (
            BatchKind::EvenRotate,
            checked_mul(even_words, HX512_RADIX_DIGITS_PER_WORD, "even rotate cells")?,
        ),
        (
            BatchKind::OddXor,
            checked_mul(odd_words, HX512_RADIX_DIGITS_PER_WORD, "odd XOR cells")?,
        ),
        (
            BatchKind::OddShift,
            checked_mul(odd_words, HX512_RADIX_DIGITS_PER_WORD, "odd shift cells")?,
        ),
        (
            BatchKind::OddRotate,
            checked_mul(odd_words, HX512_RADIX_DIGITS_PER_WORD, "odd rotate cells")?,
        ),
        (
            BatchKind::FeedforwardFirst,
            checked_mul(
                feed_words,
                HX512_RADIX_DIGITS_PER_WORD,
                "feedforward first cells",
            )?,
        ),
        (
            BatchKind::FeedforwardSecond,
            checked_mul(
                feed_words,
                HX512_RADIX_DIGITS_PER_WORD,
                "feedforward second cells",
            )?,
        ),
        (
            BatchKind::SelectedControl,
            checked_mul(
                control_words,
                HX512_RADIX_DIGITS_PER_WORD,
                "selected control cells",
            )?,
        ),
        (
            BatchKind::DigestMux,
            checked_mul(mux_words, HX512_RADIX_DIGITS_PER_WORD, "digest mux cells")?,
        ),
        (
            BatchKind::DigestBroadcast,
            checked_mul(
                mux_words,
                HX512_RADIX_DIGITS_PER_WORD,
                "digest broadcast cells",
            )?,
        ),
    ];
    let mut next_row = 0u32;
    let mut layouts = Vec::with_capacity(logical.len());
    for (kind, logical_cells) in logical {
        let rows = ceil_div(logical_cells, HX512_RADIX4_PACKING_FACTOR)?;
        let padded = checked_mul(rows, HX512_RADIX4_PACKING_FACTOR, "batch cells")?;
        let row_count = u16::try_from(rows).map_err(|_| Hx512TopologyError::TooManyRows(rows))?;
        layouts.push(BatchLayout {
            kind,
            start_row: RowId::checked(next_row)?,
            row_count,
            logical_cells,
            padding_cells: padded - logical_cells,
        });
        next_row = next_row
            .checked_add(rows)
            .ok_or(Hx512TopologyError::ArithmeticOverflow("row total"))?;
    }
    if next_row > MAX_ROWS {
        return Err(Hx512TopologyError::TooManyRows(next_row));
    }
    Ok(layouts)
}

struct OperationBuilder<'a> {
    batches: &'a [BatchLayout],
    operations: Vec<OperationRecord>,
    next_event: u32,
}

impl<'a> OperationBuilder<'a> {
    fn batch(&self, kind: BatchKind) -> &BatchLayout {
        self.batches
            .iter()
            .find(|batch| batch.kind == kind)
            .expect("all topology batches exist")
    }

    fn push_word(
        &mut self,
        kind: OperationKind,
        coordinate: OperationCoordinate,
        batch: BatchKind,
        word_index: u32,
        dependencies: Dependencies,
    ) -> Result<TopologyValueRef, Hx512TopologyError> {
        let id = OperationId(self.operations.len() as u32);
        let output = self.batch(batch).word_cell(word_index)?;
        let event = self.next_event;
        self.next_event = self
            .next_event
            .checked_add(1)
            .ok_or(Hx512TopologyError::ArithmeticOverflow("operation event"))?;
        self.operations.push(OperationRecord {
            id,
            event,
            kind,
            coordinate,
            output,
            dependencies,
            addition_carry_output: None,
            addition_final_carry_output: None,
        });
        Ok(TopologyValueRef::Operation(id))
    }

    fn push_add(
        &mut self,
        kind: OperationKind,
        coordinate: OperationCoordinate,
        word_index: u32,
        dependencies: Dependencies,
    ) -> Result<TopologyValueRef, Hx512TopologyError> {
        let id = OperationId(self.operations.len() as u32);
        let output = self.batch(BatchKind::AdditionSum).word_cell(word_index)?;
        let carry = self.batch(BatchKind::AdditionCarry).word_cell(word_index)?;
        let final_carry = self.batch(BatchKind::AdditionFinalCarry).cell(word_index)?;
        let event = self.next_event;
        self.next_event = self
            .next_event
            .checked_add(1)
            .ok_or(Hx512TopologyError::ArithmeticOverflow("addition event"))?;
        self.operations.push(OperationRecord {
            id,
            event,
            kind,
            coordinate,
            output,
            dependencies,
            addition_carry_output: Some(carry),
            addition_final_carry_output: Some(final_carry),
        });
        Ok(TopologyValueRef::Operation(id))
    }
}

fn call_map(registry: &TypedCallRegistry) -> BTreeMap<CallId, &TypedBlake2bCall> {
    registry.calls.iter().map(|call| (call.id, call)).collect()
}

fn build_compression_schedule(
    registry: &TypedCallRegistry,
) -> Result<(Vec<CompiledCallSummary>, Vec<CompiledCompression>), Hx512TopologyError> {
    let mut calls = registry.calls.iter().collect::<Vec<_>>();
    calls.sort_by_key(|call| call.id);
    let mut summaries = Vec::with_capacity(calls.len());
    let mut compressions = Vec::new();
    for call in calls {
        let first = CompressionId::checked(compressions.len() as u32)?;
        let actual_by_mode = std::array::from_fn(|index| {
            let variant = call_variant_for_mode(call, AuthorizationMode::ALL[index])
                .expect("registry audited before schedule");
            actual_compressions(variant.message_len) as u8
        });
        let parameter_block = parameter_block(call.personalization);
        summaries.push(CompiledCallSummary {
            id: call.id,
            first_compression: first,
            fixed_compressions: call.fixed_compressions,
            actual_compressions_by_mode: actual_by_mode,
            selected_digest_state_by_mode: actual_by_mode,
            parameter_block,
            parameter_words: parameter_words(parameter_block),
        });
        for slot in 0..u32::from(call.fixed_compressions) {
            let controls = std::array::from_fn(|index| {
                let variant = call_variant_for_mode(call, AuthorizationMode::ALL[index])
                    .expect("registry audited before schedule");
                compression_control(variant.message_len, slot)
            });
            let message_bytes_by_mode = std::array::from_fn(|index| {
                let variant = call_variant_for_mode(call, AuthorizationMode::ALL[index])
                    .expect("registry audited before schedule");
                let start = slot * HX512_COMPRESSION_BLOCK_BYTES;
                if start >= variant.message_len {
                    0
                } else {
                    (variant.message_len - start).min(HX512_COMPRESSION_BLOCK_BYTES) as u8
                }
            });
            let rfc_zero_padding_bytes_by_mode =
                message_bytes_by_mode.map(|used| HX512_COMPRESSION_BLOCK_BYTES as u8 - used);
            compressions.push(CompiledCompression {
                id: CompressionId::checked(compressions.len() as u32)?,
                call: call.id,
                slot: slot as u8,
                message_bytes_by_mode,
                rfc_zero_padding_bytes_by_mode,
                mode_selected_control: controls.iter().any(|control| *control != controls[0]),
                controls,
            });
        }
    }
    Ok((summaries, compressions))
}

fn add_g(
    builder: &mut OperationBuilder<'_>,
    call: CallId,
    compression: CompressionId,
    round: u8,
    half: MixHalfRound,
    g: u8,
    local_add: &mut u32,
    local_even: &mut u32,
    local_odd: &mut u32,
    work: &mut [TopologyValueRef; 16],
    indices: [usize; 4],
    message_x: TopologyValueRef,
    message_y: TopologyValueRef,
) -> Result<(), Hx512TopologyError> {
    let compression_index = u32::from(compression.get());
    let coordinate = |step| OperationCoordinate::Mix {
        call,
        compression,
        round,
        half,
        g,
        step,
    };
    let [a, b, c, d] = indices;
    let add_index = compression_index * HX512_ADDITIONS_PER_COMPRESSION + *local_add;
    work[a] = builder.push_add(
        OperationKind::AddTernary,
        coordinate(MixOperationStep::AddAx),
        add_index,
        Dependencies::three(work[a], work[b], message_x),
    )?;
    *local_add += 1;

    let even_index = compression_index * HX512_EVEN_XORS_PER_COMPRESSION + *local_even;
    let raw = builder.push_word(
        OperationKind::EvenXor,
        coordinate(MixOperationStep::XorDa),
        BatchKind::EvenXor,
        even_index,
        Dependencies::two(work[d], work[a]),
    )?;
    work[d] = builder.push_word(
        OperationKind::EvenRotate(32),
        coordinate(MixOperationStep::RotateD32),
        BatchKind::EvenRotate,
        even_index,
        Dependencies::one(raw),
    )?;
    *local_even += 1;

    let add_index = compression_index * HX512_ADDITIONS_PER_COMPRESSION + *local_add;
    work[c] = builder.push_add(
        OperationKind::AddBinary,
        coordinate(MixOperationStep::AddCd),
        add_index,
        Dependencies::two(work[c], work[d]),
    )?;
    *local_add += 1;

    let even_index = compression_index * HX512_EVEN_XORS_PER_COMPRESSION + *local_even;
    let raw = builder.push_word(
        OperationKind::EvenXor,
        coordinate(MixOperationStep::XorBc),
        BatchKind::EvenXor,
        even_index,
        Dependencies::two(work[b], work[c]),
    )?;
    work[b] = builder.push_word(
        OperationKind::EvenRotate(24),
        coordinate(MixOperationStep::RotateB24),
        BatchKind::EvenRotate,
        even_index,
        Dependencies::one(raw),
    )?;
    *local_even += 1;

    let add_index = compression_index * HX512_ADDITIONS_PER_COMPRESSION + *local_add;
    work[a] = builder.push_add(
        OperationKind::AddTernary,
        coordinate(MixOperationStep::AddAy),
        add_index,
        Dependencies::three(work[a], work[b], message_y),
    )?;
    *local_add += 1;

    let even_index = compression_index * HX512_EVEN_XORS_PER_COMPRESSION + *local_even;
    let raw = builder.push_word(
        OperationKind::EvenXor,
        coordinate(MixOperationStep::XorDaSecond),
        BatchKind::EvenXor,
        even_index,
        Dependencies::two(work[d], work[a]),
    )?;
    work[d] = builder.push_word(
        OperationKind::EvenRotate(16),
        coordinate(MixOperationStep::RotateD16),
        BatchKind::EvenRotate,
        even_index,
        Dependencies::one(raw),
    )?;
    *local_even += 1;

    let add_index = compression_index * HX512_ADDITIONS_PER_COMPRESSION + *local_add;
    work[c] = builder.push_add(
        OperationKind::AddBinary,
        coordinate(MixOperationStep::AddCdSecond),
        add_index,
        Dependencies::two(work[c], work[d]),
    )?;
    *local_add += 1;

    let odd_index = compression_index * HX512_ODD_XORS_PER_COMPRESSION + *local_odd;
    let raw = builder.push_word(
        OperationKind::OddXor,
        coordinate(MixOperationStep::XorBcSecond),
        BatchKind::OddXor,
        odd_index,
        Dependencies::two(work[b], work[c]),
    )?;
    let shifted = builder.push_word(
        OperationKind::OddShift,
        coordinate(MixOperationStep::ShiftB63),
        BatchKind::OddShift,
        odd_index,
        Dependencies::one(raw),
    )?;
    work[b] = builder.push_word(
        OperationKind::OddRotate63,
        coordinate(MixOperationStep::RotateB63),
        BatchKind::OddRotate,
        odd_index,
        Dependencies::two(raw, shifted),
    )?;
    *local_odd += 1;
    Ok(())
}

fn authorization_mode_source_ref(
    registry: &TypedCallRegistry,
    batches: &[BatchLayout],
) -> Result<Option<TopologyValueRef>, Hx512TopologyError> {
    let Some(source) = registry.authorization_mode_source else {
        return Ok(None);
    };
    let absolute_byte = registry
        .statement_bytes
        .checked_add(registry.verifier_context_bytes)
        .and_then(|value| value.checked_add(source.offset))
        .ok_or(Hx512TopologyError::ArithmeticOverflow(
            "authorization source absolute byte",
        ))?;
    let first_digit = checked_mul(absolute_byte, 4, "authorization source first digit")?;
    let cells = checked_mul(source.len, 4, "authorization source cells")?;
    let cells =
        u16::try_from(cells).map_err(|_| Hx512TopologyError::InvalidAuthorizationModeSource)?;
    let source_batch = batches
        .iter()
        .find(|batch| batch.kind == BatchKind::Source)
        .expect("source batch exists");
    Ok(Some(TopologyValueRef::SourceRange {
        first: source_batch.cell(first_digit)?,
        cells,
    }))
}

fn compression_dependency_calls(call: &TypedBlake2bCall, slot: u32) -> BTreeSet<CallId> {
    let block_start = slot * HX512_COMPRESSION_BLOCK_BYTES;
    let block_end = block_start + HX512_COMPRESSION_BLOCK_BYTES;
    call.variants
        .iter()
        .flat_map(|variant| variant.spans.iter())
        .filter(|span| {
            let span_end = span.start + span.len;
            span.start < block_end && block_start < span_end
        })
        .flat_map(|span| provenance_dependencies(&span.provenance))
        .collect()
}

fn operation_ids(values: [TopologyValueRef; 8]) -> Result<[OperationId; 8], Hx512TopologyError> {
    let mut ids = [OperationId(0); 8];
    for (index, value) in values.into_iter().enumerate() {
        ids[index] = match value {
            TopologyValueRef::Operation(id) => id,
            _ => {
                return Err(Hx512TopologyError::ScheduleMismatch(
                    "digest word is not an operation",
                ));
            }
        };
    }
    Ok(ids)
}

fn build_operations(
    registry: &TypedCallRegistry,
    batches: &[BatchLayout],
    call_summaries: &[CompiledCallSummary],
    compressions: &[CompiledCompression],
) -> Result<
    (
        Vec<OperationRecord>,
        Vec<u32>,
        Vec<Vec<OperationId>>,
        Vec<CompiledDigestManifest>,
    ),
    Hx512TopologyError,
> {
    let calls = call_map(registry);
    let summaries: BTreeMap<_, _> = call_summaries
        .iter()
        .map(|summary| (summary.id, summary))
        .collect();
    let compression_map: BTreeMap<_, _> = compressions
        .iter()
        .map(|compression| (compression.id, compression))
        .collect();
    let selected_control_ordinals: BTreeMap<_, _> = compressions
        .iter()
        .filter(|compression| compression.mode_selected_control)
        .enumerate()
        .map(|(ordinal, compression)| (compression.id, ordinal as u32))
        .collect();
    let digest_mux_ordinals: BTreeMap<_, _> = call_summaries
        .iter()
        .filter(|summary| {
            summary
                .selected_digest_state_by_mode
                .iter()
                .any(|state| *state != summary.selected_digest_state_by_mode[0])
        })
        .enumerate()
        .map(|(ordinal, summary)| (summary.id, ordinal as u32))
        .collect();
    let mut builder = OperationBuilder {
        batches,
        operations: Vec::new(),
        next_event: 1,
    };
    let mut compression_events = vec![0u32; compressions.len()];
    let mut compression_message_dependencies = vec![Vec::new(); compressions.len()];
    let mut outputs: BTreeMap<CallId, [TopologyValueRef; 8]> = BTreeMap::new();
    let mut digest_manifests = Vec::with_capacity(registry.calls.len());
    let mode_source = authorization_mode_source_ref(registry, batches)?;

    for call_id in topological_call_order(registry)? {
        let call = calls[&call_id];
        let summary = summaries[&call_id];
        let mut h: [TopologyValueRef; 8] = std::array::from_fn(|index| {
            TopologyValueRef::Constant(BLAKE2B_IV[index] ^ summary.parameter_words[index])
        });
        let mut states = Vec::with_capacity(usize::from(call.fixed_compressions));
        for slot in 0..u32::from(call.fixed_compressions) {
            let compression_id =
                CompressionId::checked(u32::from(summary.first_compression.get()) + slot)?;
            let compression = compression_map[&compression_id];
            let mut message_dependencies = Vec::new();
            for producer_call in compression_dependency_calls(call, slot) {
                let producer_outputs = outputs.get(&producer_call).ok_or(
                    Hx512TopologyError::MissingCallDependency {
                        consumer: call_id,
                        producer: producer_call,
                    },
                )?;
                for output in producer_outputs {
                    match output {
                        TopologyValueRef::Operation(operation) => {
                            message_dependencies.push(*operation)
                        }
                        _ => {
                            return Err(Hx512TopologyError::ScheduleMismatch(
                                "hash dependency output is not an operation",
                            ));
                        }
                    }
                }
            }
            compression_message_dependencies[usize::from(compression_id.get())] =
                message_dependencies;
            // Materialized message rows are produced at this event.  Their
            // exact span provenance and zero tails live in the typed registry.
            compression_events[usize::from(compression_id.get())] = builder.next_event;
            builder.next_event = builder
                .next_event
                .checked_add(1)
                .ok_or(Hx512TopologyError::ArithmeticOverflow("message event"))?;

            let mut work = [TopologyValueRef::Constant(0); 16];
            work[..8].copy_from_slice(&h);
            for index in 0..8 {
                work[8 + index] = TopologyValueRef::Constant(BLAKE2B_IV[index]);
            }
            if compression.mode_selected_control {
                let ordinal = selected_control_ordinals[&compression_id];
                let selector =
                    mode_source.ok_or(Hx512TopologyError::MissingAuthorizationModeSource)?;
                work[12] = builder.push_word(
                    OperationKind::SelectedCounter,
                    OperationCoordinate::SelectedControl {
                        call: call_id,
                        compression: compression_id,
                        word: SelectedControlWord::CounterLow,
                    },
                    BatchKind::SelectedControl,
                    ordinal * 2,
                    Dependencies::one(selector),
                )?;
                work[14] = builder.push_word(
                    OperationKind::SelectedFinalFlag,
                    OperationCoordinate::SelectedControl {
                        call: call_id,
                        compression: compression_id,
                        word: SelectedControlWord::FinalFlag,
                    },
                    BatchKind::SelectedControl,
                    ordinal * 2 + 1,
                    Dependencies::one(selector),
                )?;
            } else {
                let control = compression.controls[0];
                work[12] = TopologyValueRef::Constant(BLAKE2B_IV[4] ^ control.counter_low);
                work[13] = TopologyValueRef::Constant(BLAKE2B_IV[5] ^ control.counter_high);
                work[14] = TopologyValueRef::Constant(
                    BLAKE2B_IV[6] ^ if control.final_block { u64::MAX } else { 0 },
                );
            }
            let message: [TopologyValueRef; 16] =
                std::array::from_fn(|word| TopologyValueRef::Message {
                    compression: compression_id,
                    word: word as u8,
                });
            let mut local_add = 0u32;
            let mut local_even = 0u32;
            let mut local_odd = 0u32;
            for round in 0..HX512_BLAKE2B_ROUNDS as usize {
                let sigma = BLAKE2B_SIGMA[round];
                for column in 0..4 {
                    add_g(
                        &mut builder,
                        call_id,
                        compression_id,
                        round as u8,
                        MixHalfRound::Column,
                        column as u8,
                        &mut local_add,
                        &mut local_even,
                        &mut local_odd,
                        &mut work,
                        [column, column + 4, column + 8, column + 12],
                        message[sigma[column * 2]],
                        message[sigma[column * 2 + 1]],
                    )?;
                }
                for diagonal in 0..4 {
                    add_g(
                        &mut builder,
                        call_id,
                        compression_id,
                        round as u8,
                        MixHalfRound::Diagonal,
                        diagonal as u8,
                        &mut local_add,
                        &mut local_even,
                        &mut local_odd,
                        &mut work,
                        [
                            diagonal,
                            4 + (diagonal + 1) % 4,
                            8 + (diagonal + 2) % 4,
                            12 + (diagonal + 3) % 4,
                        ],
                        message[sigma[8 + diagonal * 2]],
                        message[sigma[9 + diagonal * 2]],
                    )?;
                }
            }
            if local_add != HX512_ADDITIONS_PER_COMPRESSION
                || local_even != HX512_EVEN_XORS_PER_COMPRESSION
                || local_odd != HX512_ODD_XORS_PER_COMPRESSION
            {
                return Err(Hx512TopologyError::ScheduleMismatch("BLAKE2b G inventory"));
            }
            let mut next_h = [TopologyValueRef::Constant(0); 8];
            for index in 0..8 {
                let word_index = u32::from(compression_id.get()) * 8 + index as u32;
                let first = builder.push_word(
                    OperationKind::FeedforwardFirst,
                    OperationCoordinate::Feedforward {
                        call: call_id,
                        compression: compression_id,
                        stage: FeedforwardStage::First,
                        word: index as u8,
                    },
                    BatchKind::FeedforwardFirst,
                    word_index,
                    Dependencies::two(h[index], work[index]),
                )?;
                next_h[index] = builder.push_word(
                    OperationKind::FeedforwardSecond,
                    OperationCoordinate::Feedforward {
                        call: call_id,
                        compression: compression_id,
                        stage: FeedforwardStage::Second,
                        word: index as u8,
                    },
                    BatchKind::FeedforwardSecond,
                    word_index,
                    Dependencies::two(first, work[index + 8]),
                )?;
            }
            h = next_h;
            states.push(h);
        }
        let selected_states = summary.selected_digest_state_by_mode;
        let output = if selected_states
            .iter()
            .all(|state| *state == selected_states[0])
        {
            states[usize::from(selected_states[0] - 1)]
        } else {
            let ordinal = digest_mux_ordinals[&call_id];
            let selector = mode_source.ok_or(Hx512TopologyError::MissingAuthorizationModeSource)?;
            std::array::from_fn(|word| {
                let left =
                    states[usize::from(selected_states.iter().copied().min().unwrap() - 1)][word];
                let right =
                    states[usize::from(selected_states.iter().copied().max().unwrap() - 1)][word];
                let selected = builder
                    .push_word(
                        OperationKind::DigestMux,
                        OperationCoordinate::DigestMux {
                            call: call_id,
                            word: word as u8,
                        },
                        BatchKind::DigestMux,
                        ordinal * 8 + word as u32,
                        Dependencies::three(left, right, selector),
                    )
                    .expect("validated digest mux cell");
                builder
                    .push_word(
                        OperationKind::DigestBroadcast,
                        OperationCoordinate::DigestBroadcast {
                            call: call_id,
                            word: word as u8,
                        },
                        BatchKind::DigestBroadcast,
                        ordinal * 8 + word as u32,
                        Dependencies::one(selected),
                    )
                    .expect("validated digest broadcast cell")
            })
        };
        let mut terminal_operations_by_mode = [[OperationId(0); 8]; 5];
        for (mode, state) in selected_states.into_iter().enumerate() {
            terminal_operations_by_mode[mode] = operation_ids(states[usize::from(state - 1)])?;
        }
        digest_manifests.push(CompiledDigestManifest {
            call: call_id,
            terminal_operations_by_mode,
            exported_operations: operation_ids(output)?,
        });
        outputs.insert(call_id, output);
    }
    digest_manifests.sort_by_key(|manifest| manifest.call);
    Ok((
        builder.operations,
        compression_events,
        compression_message_dependencies,
        digest_manifests,
    ))
}

pub fn compile_hx512_radix4_topology(
    registry: &TypedCallRegistry,
) -> Result<CompiledHx512Topology, Hx512TopologyError> {
    audit_registry(registry)?;
    let (calls, compressions) = build_compression_schedule(registry)?;
    let compression_count = compressions.len() as u32;
    let selected_controls = compressions
        .iter()
        .filter(|compression| compression.mode_selected_control)
        .count() as u32;
    let digest_mux_calls = calls
        .iter()
        .filter(|call| {
            call.selected_digest_state_by_mode
                .iter()
                .any(|state| *state != call.selected_digest_state_by_mode[0])
        })
        .count() as u32;
    let source_bytes = registry
        .statement_bytes
        .checked_add(registry.verifier_context_bytes)
        .and_then(|value| value.checked_add(registry.private_witness_bytes))
        .ok_or(Hx512TopologyError::ArithmeticOverflow("source bytes"))?;
    let source_bits = checked_mul(source_bytes, 8, "source bits")?;
    let batches = batch_layouts(
        source_bits,
        compression_count,
        selected_controls,
        digest_mux_calls,
    )?;
    let (operations, compression_events, compression_message_dependencies, digest_manifests) =
        build_operations(registry, &batches, &calls, &compressions)?;
    let source_rows = u32::from(
        batches
            .iter()
            .find(|batch| batch.kind == BatchKind::Source)
            .expect("source batch")
            .row_count,
    );
    let message_rows = u32::from(
        batches
            .iter()
            .find(|batch| batch.kind == BatchKind::Message)
            .expect("message batch")
            .row_count,
    );
    let direct_base_rows = batches.iter().map(|batch| u32::from(batch.row_count)).sum();
    let core_rows = direct_base_rows - source_rows - message_rows;
    let direct_base_cells = checked_mul(
        direct_base_rows,
        HX512_RADIX4_PACKING_FACTOR,
        "direct base cells",
    )?;
    let explicit_padding_cells = batches.iter().map(|batch| batch.padding_cells).sum();
    let mut rfc_zero_padding_bytes_by_mode = [0u32; 5];
    for compression in &compressions {
        for (mode, bytes) in compression
            .rfc_zero_padding_bytes_by_mode
            .iter()
            .enumerate()
        {
            rfc_zero_padding_bytes_by_mode[mode] = rfc_zero_padding_bytes_by_mode[mode]
                .checked_add(u32::from(*bytes))
                .ok_or(Hx512TopologyError::ArithmeticOverflow(
                    "RFC zero padding bytes",
                ))?;
        }
    }
    let geometry = Hx512TopologyGeometry {
        call_count: registry.calls.len() as u32,
        compression_count,
        source_bits,
        source_rows,
        message_rows,
        core_rows,
        direct_base_rows,
        direct_base_cells,
        explicit_padding_cells,
        rfc_zero_padding_bytes_by_mode,
        mode_selected_control_positions: selected_controls,
        mode_selected_digest_calls: digest_mux_calls,
    };
    let mut topology = CompiledHx512Topology {
        registry_name: registry.name,
        posture: registry.posture,
        geometry,
        batches,
        calls,
        compressions,
        digest_manifests,
        operations,
        shape_digest_sha512: [0; 64],
        compression_events,
        compression_message_dependencies,
    };
    topology.shape_digest_sha512 = shape_digest(&topology, registry);
    topology.audit(registry)?;
    Ok(topology)
}

fn audit_batch_partition(topology: &CompiledHx512Topology) -> Result<(), Hx512TopologyError> {
    if topology.batches.len() != BatchKind::ALL.len() {
        return Err(Hx512TopologyError::BatchPartition);
    }
    let mut next = 0u32;
    for (expected_kind, batch) in BatchKind::ALL.into_iter().zip(&topology.batches) {
        if batch.kind != expected_kind || u32::from(batch.start_row.get()) != next {
            return Err(Hx512TopologyError::BatchPartition);
        }
        let physical = u32::from(batch.row_count) * HX512_RADIX4_PACKING_FACTOR;
        if physical != batch.logical_cells + batch.padding_cells {
            return Err(Hx512TopologyError::BatchPartition);
        }
        if batch.kind.is_word_batch() && batch.logical_cells % HX512_RADIX_DIGITS_PER_WORD != 0 {
            return Err(Hx512TopologyError::BatchPartition);
        }
        next += u32::from(batch.row_count);
    }
    if next != topology.geometry.direct_base_rows {
        return Err(Hx512TopologyError::BatchPartition);
    }
    Ok(())
}

fn mark_cell(owners: &mut [u8], cell: CellId, marker: u8) -> Result<(), Hx512TopologyError> {
    let index = cell.linear_index() as usize;
    let observed = owners
        .get_mut(index)
        .ok_or(Hx512TopologyError::UnproducedCell(cell))?;
    if *observed != 0 {
        return Err(Hx512TopologyError::DuplicateCellProducer(cell));
    }
    *observed = marker;
    Ok(())
}

fn mark_word(owners: &mut [u8], first: CellId) -> Result<(), Hx512TopologyError> {
    for digit in 0..HX512_RADIX_DIGITS_PER_WORD {
        let cell = CellId::checked(
            u32::from(first.row().get()),
            u32::from(first.lane().get()) + digit,
        )?;
        mark_cell(owners, cell, 1)?;
    }
    Ok(())
}

fn audit_operation_producers(topology: &CompiledHx512Topology) -> Result<(), Hx512TopologyError> {
    let mut owners = vec![0u8; topology.geometry.direct_base_cells as usize];
    for kind in [BatchKind::Source, BatchKind::Message] {
        let batch = topology.batch(kind).expect("input batch");
        for offset in 0..batch.logical_cells {
            mark_cell(&mut owners, batch.cell(offset)?, 1)?;
        }
    }
    for operation in &topology.operations {
        mark_word(&mut owners, operation.output)?;
        if let Some(carry) = operation.addition_carry_output {
            mark_word(&mut owners, carry)?;
        }
        if let Some(final_carry) = operation.addition_final_carry_output {
            mark_cell(&mut owners, final_carry, 1)?;
        }
    }
    for batch in &topology.batches {
        let physical = u32::from(batch.row_count) * HX512_RADIX4_PACKING_FACTOR;
        for offset in batch.logical_cells..physical {
            let row = u32::from(batch.start_row.get()) + offset / HX512_RADIX4_PACKING_FACTOR;
            let lane = offset % HX512_RADIX4_PACKING_FACTOR;
            let cell = CellId::checked(row, lane)?;
            mark_cell(&mut owners, cell, 2)?;
        }
    }
    for (index, owner) in owners.into_iter().enumerate() {
        if owner == 0 {
            let row = index as u32 / HX512_RADIX4_PACKING_FACTOR;
            let lane = index as u32 % HX512_RADIX4_PACKING_FACTOR;
            return Err(Hx512TopologyError::UnproducedCell(CellId::checked(
                row, lane,
            )?));
        }
    }
    Ok(())
}

fn audit_operation_coordinates(topology: &CompiledHx512Topology) -> Result<(), Hx512TopologyError> {
    let expected_operations = topology
        .geometry
        .compression_count
        .checked_mul(HX512_WORD_OPERATIONS_PER_COMPRESSION)
        .and_then(|count| count.checked_add(topology.geometry.mode_selected_control_positions * 2))
        .and_then(|count| count.checked_add(topology.geometry.mode_selected_digest_calls * 16))
        .ok_or(Hx512TopologyError::ArithmeticOverflow(
            "operation inventory",
        ))?;
    if topology.operations.len() as u32 != expected_operations {
        return Err(Hx512TopologyError::ScheduleMismatch("operation inventory"));
    }
    let compression_calls: BTreeMap<_, _> = topology
        .compressions
        .iter()
        .map(|compression| (compression.id, compression.call))
        .collect();
    let mut coordinates = HashSet::with_capacity(topology.operations.len());
    for operation in &topology.operations {
        if !coordinates.insert(operation.coordinate) {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "duplicate operation coordinate",
            ));
        }
        let (call, compression) = match operation.coordinate {
            OperationCoordinate::SelectedControl {
                call,
                compression,
                word,
            } => {
                let expected = match word {
                    SelectedControlWord::CounterLow => OperationKind::SelectedCounter,
                    SelectedControlWord::FinalFlag => OperationKind::SelectedFinalFlag,
                };
                if operation.kind != expected {
                    return Err(Hx512TopologyError::ScheduleMismatch(
                        "selected-control coordinate",
                    ));
                }
                (call, Some(compression))
            }
            OperationCoordinate::Mix {
                call,
                compression,
                round,
                g,
                step,
                ..
            } => {
                if round >= HX512_BLAKE2B_ROUNDS as u8 || g >= 4 {
                    return Err(Hx512TopologyError::ScheduleMismatch("mix coordinate range"));
                }
                let expected = match step {
                    MixOperationStep::AddAx | MixOperationStep::AddAy => OperationKind::AddTernary,
                    MixOperationStep::AddCd | MixOperationStep::AddCdSecond => {
                        OperationKind::AddBinary
                    }
                    MixOperationStep::XorDa
                    | MixOperationStep::XorBc
                    | MixOperationStep::XorDaSecond => OperationKind::EvenXor,
                    MixOperationStep::RotateD32 => OperationKind::EvenRotate(32),
                    MixOperationStep::RotateB24 => OperationKind::EvenRotate(24),
                    MixOperationStep::RotateD16 => OperationKind::EvenRotate(16),
                    MixOperationStep::XorBcSecond => OperationKind::OddXor,
                    MixOperationStep::ShiftB63 => OperationKind::OddShift,
                    MixOperationStep::RotateB63 => OperationKind::OddRotate63,
                };
                if operation.kind != expected {
                    return Err(Hx512TopologyError::ScheduleMismatch(
                        "mix operation coordinate",
                    ));
                }
                (call, Some(compression))
            }
            OperationCoordinate::Feedforward {
                call,
                compression,
                stage,
                word,
            } => {
                if word >= 8
                    || operation.kind
                        != match stage {
                            FeedforwardStage::First => OperationKind::FeedforwardFirst,
                            FeedforwardStage::Second => OperationKind::FeedforwardSecond,
                        }
                {
                    return Err(Hx512TopologyError::ScheduleMismatch(
                        "feedforward coordinate",
                    ));
                }
                (call, Some(compression))
            }
            OperationCoordinate::DigestMux { call, word } => {
                if word >= 8 || operation.kind != OperationKind::DigestMux {
                    return Err(Hx512TopologyError::ScheduleMismatch(
                        "digest-mux coordinate",
                    ));
                }
                (call, None)
            }
            OperationCoordinate::DigestBroadcast { call, word } => {
                if word >= 8 || operation.kind != OperationKind::DigestBroadcast {
                    return Err(Hx512TopologyError::ScheduleMismatch(
                        "digest-broadcast coordinate",
                    ));
                }
                (call, None)
            }
        };
        if let Some(compression) = compression {
            if compression_calls.get(&compression) != Some(&call) {
                return Err(Hx512TopologyError::ScheduleMismatch(
                    "operation call/compression coordinate",
                ));
            }
        }
        let (expected_arity, expected_batch) = match operation.kind {
            OperationKind::SelectedCounter | OperationKind::SelectedFinalFlag => {
                (1, BatchKind::SelectedControl)
            }
            OperationKind::AddTernary => (3, BatchKind::AdditionSum),
            OperationKind::AddBinary => (2, BatchKind::AdditionSum),
            OperationKind::EvenXor => (2, BatchKind::EvenXor),
            OperationKind::EvenRotate(_) => (1, BatchKind::EvenRotate),
            OperationKind::OddXor => (2, BatchKind::OddXor),
            OperationKind::OddShift => (1, BatchKind::OddShift),
            OperationKind::OddRotate63 => (2, BatchKind::OddRotate),
            OperationKind::FeedforwardFirst => (2, BatchKind::FeedforwardFirst),
            OperationKind::FeedforwardSecond => (2, BatchKind::FeedforwardSecond),
            OperationKind::DigestMux => (3, BatchKind::DigestMux),
            OperationKind::DigestBroadcast => (1, BatchKind::DigestBroadcast),
        };
        if operation.dependencies.len != expected_arity {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "operation dependency arity",
            ));
        }
        let batch = topology.batch(expected_batch).expect("operation batch");
        let start = u32::from(batch.start_row.get()) * HX512_RADIX4_PACKING_FACTOR;
        let end = start + batch.logical_cells;
        let output = operation.output.linear_index();
        if output < start || output + HX512_RADIX_DIGITS_PER_WORD > end {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "operation output batch",
            ));
        }
        if matches!(
            operation.kind,
            OperationKind::AddTernary | OperationKind::AddBinary
        ) {
            let carry =
                operation
                    .addition_carry_output
                    .ok_or(Hx512TopologyError::ScheduleMismatch(
                        "missing addition carry output",
                    ))?;
            let final_carry = operation.addition_final_carry_output.ok_or(
                Hx512TopologyError::ScheduleMismatch("missing final carry output"),
            )?;
            let carry_batch = topology.batch(BatchKind::AdditionCarry).unwrap();
            let final_batch = topology.batch(BatchKind::AdditionFinalCarry).unwrap();
            let carry_start = u32::from(carry_batch.start_row.get()) * HX512_RADIX4_PACKING_FACTOR;
            let final_start = u32::from(final_batch.start_row.get()) * HX512_RADIX4_PACKING_FACTOR;
            if carry.linear_index() < carry_start
                || carry.linear_index() + HX512_RADIX_DIGITS_PER_WORD
                    > carry_start + carry_batch.logical_cells
                || final_carry.linear_index() < final_start
                || final_carry.linear_index() >= final_start + final_batch.logical_cells
            {
                return Err(Hx512TopologyError::ScheduleMismatch(
                    "addition auxiliary output batch",
                ));
            }
        } else if operation.addition_carry_output.is_some()
            || operation.addition_final_carry_output.is_some()
        {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "unexpected addition auxiliary output",
            ));
        }
    }
    Ok(())
}

fn audit_digest_manifests(topology: &CompiledHx512Topology) -> Result<(), Hx512TopologyError> {
    if topology.digest_manifests.len() != topology.calls.len() {
        return Err(Hx512TopologyError::ScheduleMismatch(
            "digest manifest count",
        ));
    }
    let mut ids = BTreeSet::new();
    for manifest in &topology.digest_manifests {
        if !ids.insert(manifest.call) {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "duplicate digest manifest",
            ));
        }
        let summary = topology
            .calls
            .iter()
            .find(|summary| summary.id == manifest.call)
            .ok_or(Hx512TopologyError::ScheduleMismatch("digest manifest call"))?;
        for mode in 0..AuthorizationMode::ALL.len() {
            let expected_compression = CompressionId::checked(
                u32::from(summary.first_compression.get())
                    + u32::from(summary.selected_digest_state_by_mode[mode] - 1),
            )?;
            for (word, operation) in manifest.terminal_operations_by_mode[mode]
                .iter()
                .enumerate()
            {
                let coordinate = topology
                    .operations
                    .get(operation.get() as usize)
                    .map(|record| record.coordinate)
                    .ok_or(Hx512TopologyError::ScheduleMismatch(
                        "terminal digest operation",
                    ))?;
                if coordinate
                    != (OperationCoordinate::Feedforward {
                        call: manifest.call,
                        compression: expected_compression,
                        stage: FeedforwardStage::Second,
                        word: word as u8,
                    })
                {
                    return Err(Hx512TopologyError::ScheduleMismatch(
                        "terminal digest coordinate",
                    ));
                }
            }
        }
        let muxed = summary
            .selected_digest_state_by_mode
            .iter()
            .any(|state| *state != summary.selected_digest_state_by_mode[0]);
        for (word, operation) in manifest.exported_operations.iter().enumerate() {
            let coordinate = topology
                .operations
                .get(operation.get() as usize)
                .map(|record| record.coordinate)
                .ok_or(Hx512TopologyError::ScheduleMismatch(
                    "exported digest operation",
                ))?;
            let expected = if muxed {
                OperationCoordinate::DigestBroadcast {
                    call: manifest.call,
                    word: word as u8,
                }
            } else {
                OperationCoordinate::Feedforward {
                    call: manifest.call,
                    compression: CompressionId::checked(
                        u32::from(summary.first_compression.get())
                            + u32::from(summary.selected_digest_state_by_mode[0] - 1),
                    )?,
                    stage: FeedforwardStage::Second,
                    word: word as u8,
                }
            };
            if coordinate != expected {
                return Err(Hx512TopologyError::ScheduleMismatch(
                    "exported digest coordinate",
                ));
            }
        }
    }
    Ok(())
}

fn audit_earlier_consumers(topology: &CompiledHx512Topology) -> Result<(), Hx512TopologyError> {
    let source = topology.batch(BatchKind::Source).expect("source batch");
    let source_start = u32::from(source.start_row.get()) * HX512_RADIX4_PACKING_FACTOR;
    let source_end = source_start
        .checked_add(source.logical_cells)
        .ok_or(Hx512TopologyError::ArithmeticOverflow("source range end"))?;
    for (index, operation) in topology.operations.iter().enumerate() {
        if operation.id.get() as usize != index {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "operation ID sequence",
            ));
        }
        for dependency in operation.dependencies.iter() {
            match dependency {
                TopologyValueRef::Constant(_) => {}
                TopologyValueRef::SourceRange { first, cells } => {
                    let first = first.linear_index();
                    let end = first.checked_add(u32::from(cells)).ok_or(
                        Hx512TopologyError::ArithmeticOverflow("source dependency end"),
                    )?;
                    if cells == 0 || first < source_start || end > source_end {
                        return Err(Hx512TopologyError::InvalidAuthorizationModeSource);
                    }
                }
                TopologyValueRef::Message { compression, word } => {
                    if word >= HX512_MESSAGE_WORDS_PER_COMPRESSION as u8 {
                        return Err(Hx512TopologyError::ScheduleMismatch("message word index"));
                    }
                    let event = *topology
                        .compression_events
                        .get(usize::from(compression.get()))
                        .ok_or(Hx512TopologyError::MessageConsumedBeforeMaterialization {
                            operation: operation.id,
                            compression,
                        })?;
                    if event == 0 || event >= operation.event {
                        return Err(Hx512TopologyError::MessageConsumedBeforeMaterialization {
                            operation: operation.id,
                            compression,
                        });
                    }
                }
                TopologyValueRef::Operation(producer) => {
                    let producer_event = topology
                        .operations
                        .get(producer.get() as usize)
                        .map(|record| record.event)
                        .ok_or(Hx512TopologyError::ForwardOperationDependency {
                            consumer: operation.id,
                            producer,
                        })?;
                    if producer_event >= operation.event {
                        return Err(Hx512TopologyError::ForwardOperationDependency {
                            consumer: operation.id,
                            producer,
                        });
                    }
                }
            }
        }
    }
    if topology.compression_message_dependencies.len() != topology.compressions.len() {
        return Err(Hx512TopologyError::ScheduleMismatch(
            "compression message dependency count",
        ));
    }
    for compression in &topology.compressions {
        let message_event = topology.compression_events[usize::from(compression.id.get())];
        for producer in
            &topology.compression_message_dependencies[usize::from(compression.id.get())]
        {
            let producer_event = topology
                .operations
                .get(producer.get() as usize)
                .map(|record| record.event)
                .ok_or(Hx512TopologyError::HashMessageDependencyNotEarlier {
                    compression: compression.id,
                    producer: *producer,
                })?;
            if producer_event >= message_event {
                return Err(Hx512TopologyError::HashMessageDependencyNotEarlier {
                    compression: compression.id,
                    producer: *producer,
                });
            }
        }
    }
    Ok(())
}

fn audit_call_schedule(
    topology: &CompiledHx512Topology,
    registry: &TypedCallRegistry,
) -> Result<(), Hx512TopologyError> {
    if topology.calls.len() != registry.calls.len()
        || topology.compressions.len() != topology.geometry.compression_count as usize
    {
        return Err(Hx512TopologyError::ScheduleMismatch(
            "call/compression count",
        ));
    }
    let selected_controls = topology
        .compressions
        .iter()
        .filter(|compression| compression.mode_selected_control)
        .count() as u32;
    if selected_controls != topology.geometry.mode_selected_control_positions {
        return Err(Hx512TopologyError::ScheduleMismatch(
            "selected control count",
        ));
    }
    let mut expected_first = 0u32;
    let mut expected_rfc_padding = [0u32; 5];
    for summary in &topology.calls {
        let call = registry
            .calls
            .iter()
            .find(|call| call.id == summary.id)
            .ok_or(Hx512TopologyError::ScheduleMismatch(
                "missing compiled call",
            ))?;
        if u32::from(summary.first_compression.get()) != expected_first
            || summary.fixed_compressions != call.fixed_compressions
        {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "call compression partition",
            ));
        }
        let expected_actual = std::array::from_fn(|index| {
            actual_compressions(
                call_variant_for_mode(call, AuthorizationMode::ALL[index])
                    .expect("registry audited")
                    .message_len,
            ) as u8
        });
        if summary.actual_compressions_by_mode != expected_actual
            || summary.selected_digest_state_by_mode != expected_actual
        {
            return Err(Hx512TopologyError::ScheduleMismatch(
                "mode-selected digest state",
            ));
        }
        if summary.parameter_block != parameter_block(call.personalization)
            || summary.parameter_words != parameter_words(summary.parameter_block)
        {
            return Err(Hx512TopologyError::ScheduleMismatch("RFC parameter block"));
        }
        for slot in 0..u32::from(call.fixed_compressions) {
            let compression_index = expected_first + slot;
            let compression = topology
                .compressions
                .get(compression_index as usize)
                .ok_or(Hx512TopologyError::ScheduleMismatch(
                    "missing compression slot",
                ))?;
            if u32::from(compression.id.get()) != compression_index
                || compression.call != call.id
                || u32::from(compression.slot) != slot
            {
                return Err(Hx512TopologyError::ScheduleMismatch(
                    "compression slot identity",
                ));
            }
            let expected_controls = std::array::from_fn(|index| {
                let variant = call_variant_for_mode(call, AuthorizationMode::ALL[index])
                    .expect("registry audited");
                compression_control(variant.message_len, slot)
            });
            let expected_bytes = std::array::from_fn(|index| {
                let variant = call_variant_for_mode(call, AuthorizationMode::ALL[index])
                    .expect("registry audited");
                let start = slot * HX512_COMPRESSION_BLOCK_BYTES;
                if start >= variant.message_len {
                    0
                } else {
                    (variant.message_len - start).min(HX512_COMPRESSION_BLOCK_BYTES) as u8
                }
            });
            let expected_padding =
                expected_bytes.map(|used| HX512_COMPRESSION_BLOCK_BYTES as u8 - used);
            if compression.controls != expected_controls
                || compression.message_bytes_by_mode != expected_bytes
                || compression.rfc_zero_padding_bytes_by_mode != expected_padding
                || compression.mode_selected_control
                    != expected_controls
                        .iter()
                        .any(|control| *control != expected_controls[0])
            {
                return Err(Hx512TopologyError::ScheduleMismatch(
                    "RFC compression schedule",
                ));
            }
            for (mode, padding) in expected_padding.into_iter().enumerate() {
                expected_rfc_padding[mode] = expected_rfc_padding[mode]
                    .checked_add(u32::from(padding))
                    .ok_or(Hx512TopologyError::ArithmeticOverflow("RFC padding audit"))?;
            }
        }
        expected_first = expected_first
            .checked_add(u32::from(call.fixed_compressions))
            .ok_or(Hx512TopologyError::ArithmeticOverflow(
                "compression partition",
            ))?;
    }
    if expected_first != topology.geometry.compression_count
        || expected_rfc_padding != topology.geometry.rfc_zero_padding_bytes_by_mode
    {
        return Err(Hx512TopologyError::ScheduleMismatch(
            "compression geometry totals",
        ));
    }
    Ok(())
}

fn digest_u32(hasher: &mut Sha512, value: u32) {
    hasher.update(value.to_be_bytes());
}

fn digest_u64(hasher: &mut Sha512, value: u64) {
    hasher.update(value.to_be_bytes());
}

fn digest_bytes(hasher: &mut Sha512, bytes: &[u8]) {
    digest_u32(hasher, bytes.len() as u32);
    hasher.update(bytes);
}

fn source_surface_tag(surface: SourceSurface) -> u8 {
    match surface {
        SourceSurface::Statement => 0,
        SourceSurface::VerifierContext => 1,
        SourceSurface::PrivateWitness => 2,
    }
}

fn digest_selectable_source(hasher: &mut Sha512, source: &SelectableMessageSource) {
    match source {
        SelectableMessageSource::FixedBytes(bytes) => {
            hasher.update([0]);
            digest_bytes(hasher, bytes);
        }
        SelectableMessageSource::Wire(range) => {
            hasher.update([1, source_surface_tag(range.surface)]);
            digest_u32(hasher, range.offset);
            digest_u32(hasher, range.len);
        }
        SelectableMessageSource::HashDigest {
            call,
            digest_offset,
        } => {
            hasher.update([2]);
            hasher.update(call.get().to_be_bytes());
            hasher.update(digest_offset.to_be_bytes());
        }
    }
}

fn digest_provenance(hasher: &mut Sha512, provenance: &MessageProvenance) {
    match provenance {
        MessageProvenance::FixedBytes(bytes) => {
            hasher.update([0]);
            digest_bytes(hasher, bytes);
        }
        MessageProvenance::PublicStatement { offset } => {
            hasher.update([1]);
            digest_u32(hasher, *offset);
        }
        MessageProvenance::VerifierContext { offset } => {
            hasher.update([2]);
            digest_u32(hasher, *offset);
        }
        MessageProvenance::PrivateWitness { offset } => {
            hasher.update([3]);
            digest_u32(hasher, *offset);
        }
        MessageProvenance::HashDigest {
            call,
            digest_offset,
        } => {
            hasher.update([4]);
            hasher.update(call.get().to_be_bytes());
            hasher.update(digest_offset.to_be_bytes());
        }
        MessageProvenance::LowByte { source } => {
            hasher.update([7, source_surface_tag(source.surface)]);
            digest_u32(hasher, source.offset);
            digest_u32(hasher, source.len);
        }
        MessageProvenance::BitSelect {
            selector,
            when_zero,
            when_one,
        } => {
            hasher.update([5, source_surface_tag(selector.surface)]);
            digest_u32(hasher, selector.byte_offset);
            hasher.update([selector.bit_in_byte]);
            digest_selectable_source(hasher, when_zero);
            digest_selectable_source(hasher, when_one);
        }
        MessageProvenance::NonHashDerived {
            recipe,
            hash_dependencies,
        } => {
            hasher.update([6]);
            digest_bytes(hasher, recipe.as_bytes());
            digest_u32(hasher, hash_dependencies.len() as u32);
            for call in hash_dependencies {
                hasher.update(call.get().to_be_bytes());
            }
        }
    }
}

fn digest_operation_coordinate(hasher: &mut Sha512, coordinate: OperationCoordinate) {
    match coordinate {
        OperationCoordinate::SelectedControl {
            call,
            compression,
            word,
        } => {
            hasher.update([0]);
            hasher.update(call.get().to_be_bytes());
            hasher.update(compression.get().to_be_bytes());
            hasher.update([match word {
                SelectedControlWord::CounterLow => 0,
                SelectedControlWord::FinalFlag => 1,
            }]);
        }
        OperationCoordinate::Mix {
            call,
            compression,
            round,
            half,
            g,
            step,
        } => {
            hasher.update([1]);
            hasher.update(call.get().to_be_bytes());
            hasher.update(compression.get().to_be_bytes());
            hasher.update([
                round,
                match half {
                    MixHalfRound::Column => 0,
                    MixHalfRound::Diagonal => 1,
                },
                g,
                match step {
                    MixOperationStep::AddAx => 0,
                    MixOperationStep::XorDa => 1,
                    MixOperationStep::RotateD32 => 2,
                    MixOperationStep::AddCd => 3,
                    MixOperationStep::XorBc => 4,
                    MixOperationStep::RotateB24 => 5,
                    MixOperationStep::AddAy => 6,
                    MixOperationStep::XorDaSecond => 7,
                    MixOperationStep::RotateD16 => 8,
                    MixOperationStep::AddCdSecond => 9,
                    MixOperationStep::XorBcSecond => 10,
                    MixOperationStep::ShiftB63 => 11,
                    MixOperationStep::RotateB63 => 12,
                },
            ]);
        }
        OperationCoordinate::Feedforward {
            call,
            compression,
            stage,
            word,
        } => {
            hasher.update([2]);
            hasher.update(call.get().to_be_bytes());
            hasher.update(compression.get().to_be_bytes());
            hasher.update([
                match stage {
                    FeedforwardStage::First => 0,
                    FeedforwardStage::Second => 1,
                },
                word,
            ]);
        }
        OperationCoordinate::DigestMux { call, word } => {
            hasher.update([3]);
            hasher.update(call.get().to_be_bytes());
            hasher.update([word]);
        }
        OperationCoordinate::DigestBroadcast { call, word } => {
            hasher.update([4]);
            hasher.update(call.get().to_be_bytes());
            hasher.update([word]);
        }
    }
}

fn shape_digest(topology: &CompiledHx512Topology, registry: &TypedCallRegistry) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(SHAPE_DIGEST_DOMAIN);
    digest_bytes(&mut hasher, registry.name.as_bytes());
    hasher.update([match registry.posture {
        RegistryPosture::RejectedHistoricalFixture => 0,
        RegistryPosture::UnfrozenCandidate => 1,
        RegistryPosture::FrozenCandidate => 2,
    }]);
    digest_u32(&mut hasher, HX512_RADIX4_PACKING_FACTOR);
    digest_u32(&mut hasher, registry.statement_bytes);
    digest_u32(&mut hasher, registry.verifier_context_bytes);
    digest_u32(&mut hasher, registry.private_witness_bytes);
    match registry.authorization_mode_source {
        Some(source) => {
            hasher.update([1]);
            digest_u32(&mut hasher, source.offset);
            digest_u32(&mut hasher, source.len);
        }
        None => hasher.update([0]),
    }
    digest_u32(&mut hasher, topology.geometry.call_count);
    digest_u32(&mut hasher, topology.geometry.compression_count);
    for bytes in topology.geometry.rfc_zero_padding_bytes_by_mode {
        digest_u32(&mut hasher, bytes);
    }
    for batch in &topology.batches {
        hasher.update([batch.kind.tag()]);
        hasher.update(batch.start_row.get().to_be_bytes());
        hasher.update(batch.row_count.to_be_bytes());
        digest_u32(&mut hasher, batch.logical_cells);
        digest_u32(&mut hasher, batch.padding_cells);
    }
    let mut calls = registry.calls.iter().collect::<Vec<_>>();
    calls.sort_by_key(|call| call.id);
    for call in calls {
        hasher.update(call.id.get().to_be_bytes());
        digest_bytes(&mut hasher, call.family.as_bytes());
        hasher.update(call.role);
        hasher.update(call.personalization);
        hasher.update([call.fixed_compressions]);
        digest_u32(&mut hasher, call.variants.len() as u32);
        for variant in &call.variants {
            hasher.update([variant.mode.map_or(255, AuthorizationMode::tag)]);
            digest_u32(&mut hasher, variant.message_len);
            digest_u32(&mut hasher, variant.spans.len() as u32);
            for span in &variant.spans {
                digest_u32(&mut hasher, span.start);
                digest_u32(&mut hasher, span.len);
                digest_provenance(&mut hasher, &span.provenance);
            }
        }
        digest_u32(&mut hasher, call.public_targets.len() as u32);
        for target in &call.public_targets {
            hasher.update([match target.surface {
                PublicSurface::Statement => 0,
                PublicSurface::VerifierContext => 1,
            }]);
            digest_u32(&mut hasher, target.offset);
            match target.condition {
                TargetCondition::Always => hasher.update([0, 0]),
                TargetCondition::InputActive(index) => hasher.update([1, index]),
                TargetCondition::OutputActive(index) => hasher.update([2, index]),
                TargetCondition::StablecoinEnabled => hasher.update([3, 0]),
                TargetCondition::StablecoinMint => hasher.update([4, 0]),
            }
        }
    }
    for compression in &topology.compressions {
        hasher.update(compression.id.get().to_be_bytes());
        hasher.update(compression.call.get().to_be_bytes());
        hasher.update([
            compression.slot,
            u8::from(compression.mode_selected_control),
        ]);
        hasher.update(compression.message_bytes_by_mode);
        hasher.update(compression.rfc_zero_padding_bytes_by_mode);
        for control in compression.controls {
            hasher.update([u8::from(control.active)]);
            digest_u64(&mut hasher, control.counter_low);
            digest_u64(&mut hasher, control.counter_high);
            hasher.update([u8::from(control.final_block), u8::from(control.last_node)]);
        }
    }
    digest_u32(
        &mut hasher,
        topology.compression_message_dependencies.len() as u32,
    );
    for dependencies in &topology.compression_message_dependencies {
        digest_u32(&mut hasher, dependencies.len() as u32);
        for dependency in dependencies {
            digest_u32(&mut hasher, dependency.get());
        }
    }
    digest_u32(&mut hasher, topology.digest_manifests.len() as u32);
    for manifest in &topology.digest_manifests {
        hasher.update(manifest.call.get().to_be_bytes());
        for mode in manifest.terminal_operations_by_mode {
            for operation in mode {
                digest_u32(&mut hasher, operation.get());
            }
        }
        for operation in manifest.exported_operations {
            digest_u32(&mut hasher, operation.get());
        }
    }
    for operation in &topology.operations {
        digest_u32(&mut hasher, operation.id.get());
        digest_u32(&mut hasher, operation.event);
        let (tag, argument) = match operation.kind {
            OperationKind::SelectedCounter => (0, 0),
            OperationKind::SelectedFinalFlag => (1, 0),
            OperationKind::AddTernary => (2, 0),
            OperationKind::AddBinary => (3, 0),
            OperationKind::EvenXor => (4, 0),
            OperationKind::EvenRotate(rotation) => (5, rotation),
            OperationKind::OddXor => (6, 0),
            OperationKind::OddShift => (7, 0),
            OperationKind::OddRotate63 => (8, 63),
            OperationKind::FeedforwardFirst => (9, 0),
            OperationKind::FeedforwardSecond => (10, 0),
            OperationKind::DigestMux => (11, 0),
            OperationKind::DigestBroadcast => (12, 0),
        };
        hasher.update([tag, argument]);
        digest_operation_coordinate(&mut hasher, operation.coordinate);
        digest_u32(&mut hasher, operation.output.linear_index());
        hasher.update([operation.dependencies.len]);
        for dependency in operation.dependencies.iter() {
            match dependency {
                TopologyValueRef::Constant(value) => {
                    hasher.update([0]);
                    digest_u64(&mut hasher, value);
                }
                TopologyValueRef::SourceRange { first, cells } => {
                    hasher.update([1]);
                    digest_u32(&mut hasher, first.linear_index());
                    hasher.update(cells.to_be_bytes());
                }
                TopologyValueRef::Message { compression, word } => {
                    hasher.update([2]);
                    hasher.update(compression.get().to_be_bytes());
                    hasher.update([word]);
                }
                TopologyValueRef::Operation(id) => {
                    hasher.update([3]);
                    digest_u32(&mut hasher, id.get());
                }
            }
        }
    }
    hasher.finalize().into()
}

fn one_span(len: u32, provenance: MessageProvenance) -> Vec<MessageSpan> {
    vec![MessageSpan {
        start: 0,
        len,
        provenance,
    }]
}

fn fixed_variant(len: u32, provenance: MessageProvenance) -> Vec<CallVariant> {
    vec![CallVariant {
        mode: None,
        message_len: len,
        spans: one_span(len, provenance),
    }]
}

fn target(offset: u32, condition: TargetCondition) -> PublicDigestTarget {
    PublicDigestTarget {
        surface: PublicSurface::Statement,
        offset,
        condition,
    }
}

fn relation_mode(mode: AuthorizationMode) -> RelationAuthorizationMode {
    match mode {
        AuthorizationMode::SingleKey => RelationAuthorizationMode::SingleKey,
        AuthorizationMode::AccumulatorInit => RelationAuthorizationMode::AccumulatorInit,
        AuthorizationMode::ApprovalStep => RelationAuthorizationMode::ApprovalStep,
        AuthorizationMode::ValueLockCreation => RelationAuthorizationMode::ValueLockCreation,
        AuthorizationMode::FinalThresholdSpend => RelationAuthorizationMode::FinalThresholdSpend,
    }
}

fn relation_surface(surface: Hx512WireSurface) -> SourceSurface {
    match surface {
        Hx512WireSurface::Statement => SourceSurface::Statement,
        Hx512WireSurface::VerifierContext => SourceSurface::VerifierContext,
        Hx512WireSurface::Witness => SourceSurface::PrivateWitness,
    }
}

fn relation_wire_range(range: Hx512ByteRange) -> Result<MessageWireRange, Hx512TopologyError> {
    Ok(MessageWireRange {
        surface: relation_surface(range.surface),
        offset: u32::try_from(range.offset)
            .map_err(|_| Hx512TopologyError::RelationRegistryConversion("wire offset"))?,
        len: u32::try_from(range.bytes)
            .map_err(|_| Hx512TopologyError::RelationRegistryConversion("wire length"))?,
    })
}

fn selectable_from_relation(
    source: &Hx512HashAtomSource,
) -> Result<SelectableMessageSource, Hx512TopologyError> {
    match source {
        Hx512HashAtomSource::Literal(bytes) => {
            Ok(SelectableMessageSource::FixedBytes(bytes.clone()))
        }
        Hx512HashAtomSource::Surface(range) => {
            Ok(SelectableMessageSource::Wire(relation_wire_range(*range)?))
        }
        Hx512HashAtomSource::PriorDigest { call_index } => {
            Ok(SelectableMessageSource::HashDigest {
                call: CallId::new(u16::try_from(*call_index).map_err(|_| {
                    Hx512TopologyError::RelationRegistryConversion("prior digest call")
                })?),
                digest_offset: 0,
            })
        }
    }
}

fn direct_provenance_from_relation(
    source: &Hx512HashAtomSource,
) -> Result<MessageProvenance, Hx512TopologyError> {
    match source {
        Hx512HashAtomSource::Literal(bytes) => Ok(MessageProvenance::FixedBytes(bytes.clone())),
        Hx512HashAtomSource::Surface(range) => {
            let offset = u32::try_from(range.offset)
                .map_err(|_| Hx512TopologyError::RelationRegistryConversion("surface offset"))?;
            Ok(match range.surface {
                Hx512WireSurface::Statement => MessageProvenance::PublicStatement { offset },
                Hx512WireSurface::VerifierContext => MessageProvenance::VerifierContext { offset },
                Hx512WireSurface::Witness => MessageProvenance::PrivateWitness { offset },
            })
        }
        Hx512HashAtomSource::PriorDigest { call_index } => Ok(MessageProvenance::HashDigest {
            call: CallId::new(u16::try_from(*call_index).map_err(|_| {
                Hx512TopologyError::RelationRegistryConversion("digest call index")
            })?),
            digest_offset: 0,
        }),
    }
}

fn relation_atom_span(
    start: u32,
    atom: &Hx512HashMessageAtom,
) -> Result<MessageSpan, Hx512TopologyError> {
    let (len, provenance) = match atom {
        Hx512HashMessageAtom::Copy(source) => (
            u32::try_from(source.byte_len())
                .map_err(|_| Hx512TopologyError::RelationRegistryConversion("atom length"))?,
            direct_provenance_from_relation(source)?,
        ),
        Hx512HashMessageAtom::LowByte(range) => {
            if range.bytes == 0 {
                return Err(Hx512TopologyError::RelationRegistryConversion(
                    "empty low-byte source",
                ));
            }
            (
                1,
                MessageProvenance::LowByte {
                    source: relation_wire_range(*range)?,
                },
            )
        }
        Hx512HashMessageAtom::Select {
            selector,
            when_zero,
            when_one,
        } => {
            if selector.byte.bytes != 1 || selector.bit_in_byte >= 8 {
                return Err(Hx512TopologyError::RelationRegistryConversion(
                    "select bit source",
                ));
            }
            let zero_len = when_zero.byte_len();
            if zero_len == 0 || zero_len != when_one.byte_len() {
                return Err(Hx512TopologyError::RelationRegistryConversion(
                    "select source lengths",
                ));
            }
            (
                u32::try_from(zero_len)
                    .map_err(|_| Hx512TopologyError::RelationRegistryConversion("select length"))?,
                MessageProvenance::BitSelect {
                    selector: MessageBitSource {
                        surface: relation_surface(selector.byte.surface),
                        byte_offset: u32::try_from(selector.byte.offset).map_err(|_| {
                            Hx512TopologyError::RelationRegistryConversion("selector offset")
                        })?,
                        bit_in_byte: selector.bit_in_byte,
                    },
                    when_zero: selectable_from_relation(when_zero)?,
                    when_one: selectable_from_relation(when_one)?,
                },
            )
        }
    };
    Ok(MessageSpan {
        start,
        len,
        provenance,
    })
}

fn relation_role_metadata(role: Hx512HashRole) -> (&'static str, [u8; 8]) {
    match role {
        Hx512HashRole::NoteCommitment { .. } => ("note_commitment", *b"nt.b5121"),
        Hx512HashRole::Nullifier { .. } => ("nullifier", *b"nf.b5121"),
        Hx512HashRole::MerkleNode { .. } => ("merkle_node", *b"mk.b5121"),
        Hx512HashRole::SpendKey { lane: 0, .. } => ("spend_key_lane_a", *b"sk.b51a1"),
        Hx512HashRole::SpendKey { .. } => ("spend_key_lane_b", *b"sk.b51b1"),
        Hx512HashRole::AuthorizationPolicy => ("authorization_policy", *b"pl.b5121"),
        Hx512HashRole::AuthorizationState { lane: 0, .. } => {
            ("authorization_state_lane_a", *b"au.b51a1")
        }
        Hx512HashRole::AuthorizationState { .. } => ("authorization_state_lane_b", *b"au.b51b1"),
        Hx512HashRole::ActionIntent => ("action_intent", *b"act.int1"),
        Hx512HashRole::SpendPlan => ("spend_plan", *b"sp.plan1"),
        Hx512HashRole::Ciphertext { .. } => ("ciphertext", *b"ct.b5121"),
        Hx512HashRole::StableBeforeLeaf => ("stable_before_leaf", *b"sb.leaf1"),
        Hx512HashRole::StableBeforeNode { .. } => ("stable_before_node", *b"sb.node1"),
        Hx512HashRole::StableAfterLeaf => ("stable_after_leaf", *b"sa.leaf1"),
        Hx512HashRole::StableAfterNode { .. } => ("stable_after_node", *b"sa.node1"),
        Hx512HashRole::StableIssuerCommitment => ("stable_issuer_commitment", *b"st.icmt1"),
        Hx512HashRole::StableIssuerAuthorization => ("stable_issuer_authorization", *b"st.iaut1"),
    }
}

fn relation_target_condition(condition: Hx512HashTargetCondition) -> TargetCondition {
    match condition {
        Hx512HashTargetCondition::Always => TargetCondition::Always,
        Hx512HashTargetCondition::InputActive(index) => TargetCondition::InputActive(index),
        Hx512HashTargetCondition::OutputActive(index) => TargetCondition::OutputActive(index),
        Hx512HashTargetCondition::StableEnabled => TargetCondition::StablecoinEnabled,
        Hx512HashTargetCondition::StableMint => TargetCondition::StablecoinMint,
    }
}

/// Losslessly convert the relation grammar's single source of truth into the
/// generic topology registry.  The returned posture follows the grammar's
/// explicit freeze bit; neither posture authorizes production.
pub fn typed_call_registry_from_relation(
    identity: Hx512UnallocatedIdentity,
) -> Result<TypedCallRegistry, Hx512TopologyError> {
    let source = hx512_typed_hash_call_registry(identity);
    if source.authorization_mode_source.surface != Hx512WireSurface::Witness {
        return Err(Hx512TopologyError::RelationRegistryConversion(
            "authorization mode surface",
        ));
    }
    let mut calls = Vec::with_capacity(source.calls.len());
    for call in &source.calls {
        let id = CallId::new(
            u16::try_from(call.index)
                .map_err(|_| Hx512TopologyError::RelationRegistryConversion("call index"))?,
        );
        let mut variants = Vec::with_capacity(AuthorizationMode::ALL.len());
        for mode in AuthorizationMode::ALL {
            let recipe = hx512_exact_hash_message_recipe(identity, call.index, relation_mode(mode))
                .map_err(|_| {
                    Hx512TopologyError::RelationRegistryConversion("exact message recipe")
                })?;
            let schedule = call
                .schedules
                .iter()
                .find(|schedule| schedule.message_bytes == recipe.message_bytes)
                .ok_or(Hx512TopologyError::RelationRegistryConversion(
                    "missing compression schedule",
                ))?;
            let expected_compressions =
                actual_compressions(u32::try_from(recipe.message_bytes).map_err(|_| {
                    Hx512TopologyError::RelationRegistryConversion("scheduled message length")
                })?) as usize;
            if schedule.counters.len() != expected_compressions
                || schedule.final_flags.len() != expected_compressions
                || schedule.counters.iter().enumerate().any(|(slot, counter)| {
                    *counter
                        != ((slot as u64 + 1) * u64::from(HX512_COMPRESSION_BLOCK_BYTES))
                            .min(recipe.message_bytes as u64)
                })
                || schedule
                    .final_flags
                    .iter()
                    .enumerate()
                    .any(|(slot, flag)| *flag != (slot + 1 == expected_compressions))
            {
                return Err(Hx512TopologyError::RelationRegistryConversion(
                    "noncanonical compression schedule",
                ));
            }
            let mut cursor = 0u32;
            let mut spans = Vec::with_capacity(recipe.atoms.len());
            for atom in &recipe.atoms {
                let span = relation_atom_span(cursor, atom)?;
                cursor = cursor
                    .checked_add(span.len)
                    .ok_or(Hx512TopologyError::ArithmeticOverflow("relation message"))?;
                spans.push(span);
            }
            let message_len = u32::try_from(recipe.message_bytes)
                .map_err(|_| Hx512TopologyError::RelationRegistryConversion("message length"))?;
            if cursor != message_len {
                return Err(Hx512TopologyError::RelationRegistryConversion(
                    "expanded message length",
                ));
            }
            variants.push(CallVariant {
                mode: Some(mode),
                message_len,
                spans,
            });
        }
        let identical = variants[1..].iter().all(|variant| {
            variant.message_len == variants[0].message_len && variant.spans == variants[0].spans
        });
        if identical {
            variants.truncate(1);
            variants[0].mode = None;
        }
        let (family, role) = relation_role_metadata(call.role);
        let mut public_targets = Vec::with_capacity(call.public_digest_targets.len());
        for target in &call.public_digest_targets {
            if target.range.bytes != 64 {
                return Err(Hx512TopologyError::RelationRegistryConversion(
                    "public digest width",
                ));
            }
            let surface = match target.range.surface {
                Hx512WireSurface::Statement => PublicSurface::Statement,
                Hx512WireSurface::VerifierContext => PublicSurface::VerifierContext,
                Hx512WireSurface::Witness => {
                    return Err(Hx512TopologyError::RelationRegistryConversion(
                        "private digest target",
                    ));
                }
            };
            public_targets.push(PublicDigestTarget {
                surface,
                offset: u32::try_from(target.range.offset)
                    .map_err(|_| Hx512TopologyError::RelationRegistryConversion("target offset"))?,
                condition: relation_target_condition(target.condition),
            });
        }
        calls.push(TypedBlake2bCall {
            id,
            family,
            role,
            personalization: call.personalization,
            fixed_compressions: u8::try_from(call.max_compressions)
                .map_err(|_| Hx512TopologyError::RelationRegistryConversion("compression count"))?,
            variants,
            public_targets,
        });
    }
    let selector_end = source
        .authorization_mode_source
        .offset
        .checked_add(source.authorization_mode_source.bytes)
        .ok_or(Hx512TopologyError::RelationRegistryConversion(
            "authorization selector range",
        ))?;
    if selector_end > source.witness_bytes {
        return Err(Hx512TopologyError::RelationRegistryConversion(
            "authorization selector bounds",
        ));
    }
    let registry = TypedCallRegistry {
        name: "HX512-TYPED-RELATION-REGISTRY",
        posture: if source.frozen {
            RegistryPosture::FrozenCandidate
        } else {
            RegistryPosture::UnfrozenCandidate
        },
        statement_bytes: u32::try_from(source.statement_bytes)
            .map_err(|_| Hx512TopologyError::RelationRegistryConversion("statement width"))?,
        verifier_context_bytes: u32::try_from(source.verifier_context_bytes)
            .map_err(|_| Hx512TopologyError::RelationRegistryConversion("context width"))?,
        private_witness_bytes: u32::try_from(source.witness_bytes)
            .map_err(|_| Hx512TopologyError::RelationRegistryConversion("witness width"))?,
        authorization_mode_source: Some(PrivateSelectorSource {
            offset: u32::try_from(source.authorization_mode_source.offset)
                .map_err(|_| Hx512TopologyError::RelationRegistryConversion("selector offset"))?,
            len: u32::try_from(source.authorization_mode_source.bytes)
                .map_err(|_| Hx512TopologyError::RelationRegistryConversion("selector length"))?,
        }),
        calls,
    };
    audit_registry(&registry)?;
    Ok(registry)
}

/// Reconstruct the rejected HX512B01 registry used by the old 1.37 MB static
/// screen.  It is retained only to regression-test the generic compiler.
/// Its stablecoin authority and 33/47 authorization language are obsolete.
pub fn rejected_legacy_hx512_90x213_registry() -> TypedCallRegistry {
    const ZERO_PERSON: [u8; 16] = [0; 16];
    const POLICY_PERSON: [u8; 16] = *b"HGMAIDV2\x01\x02\x40\0\0\0\0\0";
    const LEAF_PERSON: [u8; 16] = *b"HGMAROOT\x02\x02\x40\x04\0\0\0\0";
    const SNAPSHOT_PERSON: [u8; 16] = *b"HGMAROOT\x04\x02\x40\x04\0\0\0\0";

    let mut calls = Vec::with_capacity(90);
    for index in 0..4u16 {
        calls.push(TypedBlake2bCall {
            id: CallId::new(index),
            family: "note_commitment",
            role: *b"nt.b5121",
            personalization: ZERO_PERSON,
            fixed_compressions: 2,
            variants: fixed_variant(
                256,
                MessageProvenance::PrivateWitness {
                    offset: [64, 2_448, 4_768, 5_032][usize::from(index)],
                },
            ),
            public_targets: match index {
                2 => vec![target(206, TargetCondition::OutputActive(0))],
                3 => vec![target(270, TargetCondition::OutputActive(1))],
                _ => Vec::new(),
            },
        });
    }
    for input in 0..2u16 {
        let dependencies = vec![
            CallId::new(70 + input),
            CallId::new(72 + input),
            CallId::new(75),
            CallId::new(76),
            CallId::new(77),
            CallId::new(78),
        ];
        calls.push(TypedBlake2bCall {
            id: CallId::new(4 + input),
            family: "nullifier",
            role: *b"nf.b5121",
            personalization: ZERO_PERSON,
            fixed_compressions: 2,
            variants: fixed_variant(
                143,
                MessageProvenance::NonHashDerived {
                    recipe: "resolved-nullifier-key || position || rho",
                    hash_dependencies: dependencies,
                },
            ),
            public_targets: vec![target(
                78 + u32::from(input) * 64,
                TargetCondition::InputActive(input as u8),
            )],
        });
    }
    for input in 0..2u16 {
        for level in 0..32u16 {
            let id = CallId::new(6 + input * 32 + level);
            let current = if level == 0 {
                CallId::new(input)
            } else {
                CallId::new(id.get() - 1)
            };
            calls.push(TypedBlake2bCall {
                id,
                family: "merkle_node",
                role: *b"mk.b5121",
                personalization: ZERO_PERSON,
                fixed_compressions: 2,
                variants: fixed_variant(
                    149,
                    MessageProvenance::NonHashDerived {
                        recipe: "direction-selected current digest and private sibling",
                        hash_dependencies: vec![current],
                    },
                ),
                public_targets: (level == 31)
                    .then(|| target(14, TargetCondition::InputActive(input as u8)))
                    .into_iter()
                    .collect(),
            });
        }
    }
    for lane in 0..2u16 {
        for input in 0..2u16 {
            let id = CallId::new(if lane == 0 { 70 + input } else { 72 + input });
            calls.push(TypedBlake2bCall {
                id,
                family: if lane == 0 {
                    "spend_key_lane_a"
                } else {
                    "spend_key_lane_b"
                },
                role: if lane == 0 {
                    *b"sk.b51a1"
                } else {
                    *b"sk.b51b1"
                },
                personalization: ZERO_PERSON,
                fixed_compressions: 1,
                variants: fixed_variant(
                    93,
                    MessageProvenance::PrivateWitness {
                        offset: u32::from(input) * 2_384,
                    },
                ),
                public_targets: Vec::new(),
            });
        }
    }
    calls.push(TypedBlake2bCall {
        id: CallId::new(74),
        family: "authorization_policy",
        role: *b"pl.b5121",
        personalization: ZERO_PERSON,
        fixed_compressions: 4,
        variants: fixed_variant(
            499,
            MessageProvenance::NonHashDerived {
                recipe: "mode-selected policy master/opening and signer tags",
                hash_dependencies: Vec::new(),
            },
        ),
        public_targets: Vec::new(),
    });
    for lane in 0..2u16 {
        for slot in 0..2u16 {
            let id = CallId::new(if lane == 0 { 75 + slot } else { 77 + slot });
            let lengths = if slot == 0 {
                [136, 263, 263, 225, 263]
            } else {
                [136, 136, 263, 136, 225]
            };
            let variants = AuthorizationMode::ALL
                .into_iter()
                .enumerate()
                .map(|(mode_index, mode)| CallVariant {
                    mode: Some(mode),
                    message_len: lengths[mode_index],
                    spans: one_span(
                        lengths[mode_index],
                        MessageProvenance::NonHashDerived {
                            recipe: "mode-selected authorization frame",
                            hash_dependencies: Vec::new(),
                        },
                    ),
                })
                .collect();
            calls.push(TypedBlake2bCall {
                id,
                family: "authorization_lane",
                role: if lane == 0 {
                    *b"au.b51a1"
                } else {
                    *b"au.b51b1"
                },
                personalization: ZERO_PERSON,
                fixed_compressions: 3,
                variants,
                public_targets: Vec::new(),
            });
        }
    }
    calls.push(TypedBlake2bCall {
        id: CallId::new(79),
        family: "intent",
        role: *b"in.b5121",
        personalization: ZERO_PERSON,
        fixed_compressions: 8,
        variants: fixed_variant(
            968,
            MessageProvenance::NonHashDerived {
                recipe: "HX512B01 frame(statement[0..14] || statement[206..1141])",
                hash_dependencies: Vec::new(),
            },
        ),
        public_targets: Vec::new(),
    });
    calls.push(TypedBlake2bCall {
        id: CallId::new(80),
        family: "balance_tag",
        role: *b"bl.b5121",
        personalization: ZERO_PERSON,
        fixed_compressions: 1,
        variants: fixed_variant(
            100,
            MessageProvenance::NonHashDerived {
                recipe: "canonical public balance frame",
                hash_dependencies: Vec::new(),
            },
        ),
        public_targets: vec![target(869, TargetCondition::Always)],
    });
    for output in 0..2u16 {
        calls.push(TypedBlake2bCall {
            id: CallId::new(81 + output),
            family: "ciphertext_hash",
            role: *b"ct.b5121",
            personalization: ZERO_PERSON,
            fixed_compressions: 18,
            variants: fixed_variant(
                2_182,
                MessageProvenance::NonHashDerived {
                    recipe: "fixed ciphertext frame and exact 2147-byte private ciphertext",
                    hash_dependencies: Vec::new(),
                },
            ),
            public_targets: vec![target(
                334 + u32::from(output) * 64,
                TargetCondition::OutputActive(output as u8),
            )],
        });
    }
    calls.push(TypedBlake2bCall {
        id: CallId::new(83),
        family: "obsolete_stablecoin_policy_constructor",
        role: *b"HGMAIDV2",
        personalization: POLICY_PERSON,
        fixed_compressions: 1,
        variants: fixed_variant(
            61,
            MessageProvenance::NonHashDerived {
                recipe: "obsolete selected manifest row policy tuple",
                hash_dependencies: Vec::new(),
            },
        ),
        public_targets: vec![target(541, TargetCondition::StablecoinEnabled)],
    });
    calls.push(TypedBlake2bCall {
        id: CallId::new(84),
        family: "obsolete_manifest_leaf",
        role: *b"HGMAROOT",
        personalization: LEAF_PERSON,
        fixed_compressions: 2,
        variants: fixed_variant(216, MessageProvenance::PrivateWitness { offset: 10_523 }),
        public_targets: Vec::new(),
    });
    for level in 0..4u16 {
        let mut person = *b"HGMAROOT\x03\x02\x40\x04\0\0\0\0";
        person[12] = level as u8;
        calls.push(TypedBlake2bCall {
            id: CallId::new(85 + level),
            family: "obsolete_manifest_node",
            role: *b"HGMAROOT",
            personalization: person,
            fixed_compressions: 1,
            variants: fixed_variant(
                128,
                MessageProvenance::NonHashDerived {
                    recipe: "direction-selected manifest digest and sibling",
                    hash_dependencies: vec![CallId::new(84 + level)],
                },
            ),
            public_targets: if level == 3 {
                vec![
                    target(733, TargetCondition::StablecoinEnabled),
                    PublicDigestTarget {
                        surface: PublicSurface::VerifierContext,
                        offset: 0,
                        condition: TargetCondition::StablecoinEnabled,
                    },
                ]
            } else {
                Vec::new()
            },
        });
    }
    calls.push(TypedBlake2bCall {
        id: CallId::new(89),
        family: "obsolete_state_snapshot",
        role: *b"HGMAROOT",
        personalization: SNAPSHOT_PERSON,
        fixed_compressions: 1,
        variants: fixed_variant(
            72,
            MessageProvenance::NonHashDerived {
                recipe: "u64le parent height || obsolete manifest root",
                hash_dependencies: vec![CallId::new(88)],
            },
        ),
        public_targets: vec![target(797, TargetCondition::StablecoinEnabled)],
    });
    calls.sort_by_key(|call| call.id);
    TypedCallRegistry {
        name: "REJECTED-HX512B01-90x213",
        posture: RegistryPosture::RejectedHistoricalFixture,
        statement_bytes: 1_141,
        verifier_context_bytes: 72,
        private_witness_bytes: 11_000,
        authorization_mode_source: Some(PrivateSelectorSource {
            offset: 5_296,
            len: 8,
        }),
        calls,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ONLY_IDENTITY: Hx512UnallocatedIdentity = Hx512UnallocatedIdentity {
        magic: *b"HX5TST01",
        statement_grammar: 1,
        circuit_version: 1,
        crypto_suite: 1,
        family_id: 1,
        action_id: 1,
        backend_id: 1,
        proof_profile: 1,
        domain_set: 1,
        network_id: 1,
    };

    fn legacy() -> (TypedCallRegistry, CompiledHx512Topology) {
        let registry = rejected_legacy_hx512_90x213_registry();
        let topology = compile_hx512_radix4_topology(&registry).expect("legacy fixture compiles");
        (registry, topology)
    }

    #[test]
    fn checked_identifiers_reject_out_of_range_values() {
        assert!(matches!(
            RowId::checked(u16::MAX as u32 + 1),
            Err(Hx512TopologyError::RowIdOverflow(_))
        ));
        assert!(matches!(
            LaneId::checked(HX512_RADIX4_PACKING_FACTOR),
            Err(Hx512TopologyError::LaneIdOutOfRange(_))
        ));
        let cell = CellId::checked(17, 992).expect("checked cell");
        assert_eq!(cell.row().get(), 17);
        assert_eq!(cell.lane().get(), 992);
        assert_eq!(cell.linear_index(), 17 * 1_024 + 992);
    }

    #[test]
    fn rejected_legacy_schedule_is_exact_but_never_authorized() {
        let (registry, topology) = legacy();
        assert_eq!(registry.posture, RegistryPosture::RejectedHistoricalFixture);
        assert_eq!(topology.geometry.call_count, 90);
        assert_eq!(topology.geometry.compression_count, 213);
        assert_eq!(topology.geometry.mode_selected_control_positions, 8);
        assert_eq!(topology.geometry.mode_selected_digest_calls, 4);
        assert_eq!(HX512_FINAL_CALL_COUNT, Some(95));
        assert_eq!(HX512_FINAL_COMPRESSION_COUNT, Some(226));
        assert_eq!(HX512_FINAL_RELATION_ROW_COUNT, None);
        assert!(!HX512_TOPOLOGY_PRODUCTION_AUTHORIZED);
        assert!(matches!(
            topology.ensure_production_authorized(),
            Err(Hx512TopologyError::ProductionAuthorizationUnavailable)
        ));
    }

    #[test]
    fn rejected_legacy_geometry_matches_the_corrected_static_screen() {
        let (_, topology) = legacy();
        assert_eq!(topology.geometry.source_bits, 97_704);
        assert_eq!(topology.geometry.source_rows, 48);
        assert_eq!(topology.geometry.message_rows, 107);
        assert_eq!(topology.geometry.core_rows, 11_054);
        assert_eq!(topology.geometry.direct_base_rows, 11_209);
        assert_eq!(topology.geometry.direct_base_cells, 11_478_016);
        assert_eq!(topology.geometry.explicit_padding_cells, 2_988);
        assert_eq!(
            topology.geometry.rfc_zero_padding_bytes_by_mode,
            [8_710, 8_456, 8_202, 8_532, 8_278]
        );
        assert_eq!(
            topology.batch(BatchKind::AdditionSum).unwrap().row_count,
            2_556
        );
        assert_eq!(
            topology.batch(BatchKind::AdditionCarry).unwrap().row_count,
            2_556
        );
        assert_eq!(
            topology
                .batch(BatchKind::AdditionFinalCarry)
                .unwrap()
                .row_count,
            80
        );
        assert_eq!(topology.batch(BatchKind::EvenXor).unwrap().row_count, 1_917);
        assert_eq!(
            topology.batch(BatchKind::EvenRotate).unwrap().row_count,
            1_917
        );
        assert_eq!(topology.batch(BatchKind::OddXor).unwrap().row_count, 639);
        assert_eq!(topology.batch(BatchKind::OddShift).unwrap().row_count, 639);
        assert_eq!(topology.batch(BatchKind::OddRotate).unwrap().row_count, 639);
        assert_eq!(
            topology
                .batch(BatchKind::FeedforwardFirst)
                .unwrap()
                .row_count,
            54
        );
        assert_eq!(
            topology
                .batch(BatchKind::FeedforwardSecond)
                .unwrap()
                .row_count,
            54
        );
        assert_eq!(
            topology
                .batch(BatchKind::SelectedControl)
                .unwrap()
                .row_count,
            1
        );
        assert_eq!(topology.batch(BatchKind::DigestMux).unwrap().row_count, 1);
        assert_eq!(
            topology
                .batch(BatchKind::DigestBroadcast)
                .unwrap()
                .row_count,
            1
        );
    }

    #[test]
    fn every_rfc_counter_final_flag_and_parameter_block_is_explicit() {
        let (registry, topology) = legacy();
        topology.audit(&registry).expect("complete topology audit");
        let first = &topology.compressions[0];
        assert_eq!(first.controls[0].counter_low, 128);
        assert!(!first.controls[0].final_block);
        let second = &topology.compressions[1];
        assert_eq!(second.controls[0].counter_low, 256);
        assert!(second.controls[0].final_block);

        let auth = &topology.calls[75];
        assert_eq!(auth.id, CallId::new(75));
        assert_eq!(auth.actual_compressions_by_mode, [2, 3, 3, 2, 3]);
        let third_auth_compression =
            &topology.compressions[usize::from(auth.first_compression.get()) + 2];
        assert_eq!(third_auth_compression.controls[0].counter_low, 136);
        assert!(!third_auth_compression.controls[0].active);
        assert!(!third_auth_compression.controls[0].final_block);
        assert_eq!(third_auth_compression.controls[1].counter_low, 263);
        assert!(third_auth_compression.controls[1].active);
        assert!(third_auth_compression.controls[1].final_block);
        assert_eq!(
            third_auth_compression.message_bytes_by_mode,
            [0, 7, 7, 0, 7]
        );
        assert_eq!(
            third_auth_compression.rfc_zero_padding_bytes_by_mode,
            [128, 121, 121, 128, 121]
        );
        for compression in &topology.compressions {
            for mode in 0..AuthorizationMode::ALL.len() {
                assert_eq!(
                    u16::from(compression.message_bytes_by_mode[mode])
                        + u16::from(compression.rfc_zero_padding_bytes_by_mode[mode]),
                    128
                );
            }
        }
        assert!(matches!(
            topology
                .compiled_message_digit_source(
                    &registry,
                    CallId::new(0),
                    AuthorizationMode::SingleKey,
                    0,
                    0,
                    0,
                )
                .unwrap(),
            CompiledMessageDigitSource::Source(_)
        ));
        assert_eq!(
            topology
                .compiled_message_digit_source(
                    &registry,
                    CallId::new(75),
                    AuthorizationMode::SingleKey,
                    2,
                    0,
                    0,
                )
                .unwrap(),
            CompiledMessageDigitSource::RfcZero
        );
        assert!(matches!(
            topology
                .compiled_message_digit_source(
                    &registry,
                    CallId::new(75),
                    AuthorizationMode::AccumulatorInit,
                    2,
                    0,
                    0,
                )
                .unwrap(),
            CompiledMessageDigitSource::NonHashDerived { .. }
        ));

        assert_eq!(auth.parameter_words[0], 0x0000_0000_0101_0040);
        assert!(auth.parameter_words[1..].iter().all(|word| *word == 0));
        let authority = topology
            .calls
            .iter()
            .find(|call| call.id == CallId::new(83))
            .unwrap();
        assert_eq!(
            &authority.parameter_block[48..64],
            b"HGMAIDV2\x01\x02\x40\0\0\0\0\0"
        );
    }

    #[test]
    fn all_cells_have_one_producer_and_all_padding_is_explicit() {
        let (registry, topology) = legacy();
        audit_operation_producers(&topology).expect("unique exhaustive producer audit");
        topology.audit(&registry).expect("full audit");
        let zero_cells = topology
            .row_zero_padding_cells()
            .expect("explicit row-zero manifest");
        assert_eq!(zero_cells.len(), 2_988);
        assert_eq!(
            zero_cells
                .iter()
                .map(|(_, cell)| *cell)
                .collect::<HashSet<_>>()
                .len(),
            zero_cells.len()
        );
        for batch in &topology.batches {
            if batch.kind.is_word_batch() {
                let words = batch.logical_cells / HX512_RADIX_DIGITS_PER_WORD;
                for word in 0..words {
                    assert_eq!(
                        u32::from(batch.word_cell(word).unwrap().lane().get())
                            % HX512_RADIX_DIGITS_PER_WORD,
                        0
                    );
                }
            }
        }
    }

    #[test]
    fn dependencies_are_acyclic_and_every_consumer_is_later() {
        let (_, topology) = legacy();
        audit_earlier_consumers(&topology).expect("earlier-consumer audit");
        let nullifier = topology
            .compressions
            .iter()
            .find(|compression| compression.call == CallId::new(4))
            .expect("nullifier compression");
        assert_eq!(
            topology.compression_message_dependencies[usize::from(nullifier.id.get())].len(),
            6 * 8
        );
        assert_eq!(
            topology
                .operations
                .iter()
                .filter(|operation| matches!(
                    operation.kind,
                    OperationKind::AddTernary | OperationKind::AddBinary
                ))
                .count(),
            213 * 384
        );
        assert_eq!(
            topology
                .operations
                .iter()
                .filter(|operation| operation.kind == OperationKind::OddRotate63)
                .count(),
            213 * 96
        );
        assert_eq!(topology.operations.len(), 269_312);
        assert_eq!(
            topology
                .operations
                .iter()
                .map(|operation| operation.coordinate)
                .collect::<HashSet<_>>()
                .len(),
            topology.operations.len()
        );
        let auth_single = topology
            .terminal_digest_digit_cell(CallId::new(75), AuthorizationMode::SingleKey, 0, 0)
            .unwrap();
        let auth_init = topology
            .terminal_digest_digit_cell(CallId::new(75), AuthorizationMode::AccumulatorInit, 0, 0)
            .unwrap();
        assert_ne!(auth_single, auth_init);
    }

    #[test]
    fn public_digest_targets_are_fixed_and_in_bounds() {
        let (registry, topology) = legacy();
        topology.audit(&registry).expect("target provenance audit");
        let targets = |id| {
            registry
                .calls
                .iter()
                .find(|call| call.id == CallId::new(id))
                .unwrap()
                .public_targets
                .clone()
        };
        assert_eq!(
            targets(2),
            vec![target(206, TargetCondition::OutputActive(0))]
        );
        assert_eq!(
            targets(4),
            vec![target(78, TargetCondition::InputActive(0))]
        );
        assert_eq!(
            targets(37),
            vec![target(14, TargetCondition::InputActive(0))]
        );
        assert_eq!(targets(80), vec![target(869, TargetCondition::Always)]);
        assert_eq!(
            targets(81),
            vec![target(334, TargetCondition::OutputActive(0))]
        );
        assert_eq!(
            targets(83),
            vec![target(541, TargetCondition::StablecoinEnabled)]
        );
        assert_eq!(targets(88).len(), 2);
        assert_eq!(
            targets(89),
            vec![target(797, TargetCondition::StablecoinEnabled)]
        );
        let binding = topology
            .public_target_cell_binding(&registry, CallId::new(2), 0, 0, 0)
            .expect("public digest target cell binding");
        assert_eq!(
            binding.target,
            target(206, TargetCondition::OutputActive(0))
        );
        assert_eq!(
            binding.digest_cell,
            topology
                .exported_digest_digit_cell(CallId::new(2), 0, 0)
                .unwrap()
        );
        assert_eq!(
            binding.public_cell,
            topology
                .source_byte_digit_cell(&registry, SourceSurface::Statement, 206, 0)
                .unwrap()
        );
    }

    #[test]
    fn topology_shape_is_mask_mode_and_stable_direction_independent() {
        let (registry, topology) = legacy();
        topology.audit(&registry).expect("shape is valid once");
        let frozen_geometry = topology.geometry.clone();
        let frozen_digest = topology.shape_digest_sha512;
        for mask in 0u8..16 {
            for mode in AuthorizationMode::ALL {
                for stable_direction in 0u8..3 {
                    // Mask, mode, and stable direction may select witness values
                    // and public equalities, but none is a topology input.
                    let selected_view = (
                        mask,
                        mode.tag(),
                        stable_direction,
                        &frozen_geometry,
                        frozen_digest,
                    );
                    assert_eq!(selected_view.3.direct_base_rows, 11_209);
                    assert_eq!(selected_view.3.compression_count, 213);
                    assert_eq!(selected_view.4, frozen_digest);
                }
            }
        }

        let candidate_registry =
            typed_call_registry_from_relation(TEST_ONLY_IDENTITY).expect("lossless converter");
        assert!(HX512_HASH_REGISTRY_FROZEN);
        assert_eq!(candidate_registry.posture, RegistryPosture::FrozenCandidate);
        assert_eq!(candidate_registry.calls.len(), 95);
        assert!(candidate_registry.calls.iter().any(|call| {
            call.variants.iter().any(|variant| {
                variant
                    .spans
                    .iter()
                    .any(|span| matches!(span.provenance, MessageProvenance::LowByte { .. }))
            })
        }));
        assert!(candidate_registry.calls.iter().any(|call| {
            call.variants.iter().any(|variant| {
                variant
                    .spans
                    .iter()
                    .any(|span| matches!(span.provenance, MessageProvenance::BitSelect { .. }))
            })
        }));
        let candidate = compile_hx512_radix4_topology(&candidate_registry)
            .expect("frozen typed relation topology");
        candidate
            .audit(&candidate_registry)
            .expect("typed candidate audit");
        assert_eq!(
            candidate.geometry.call_count,
            HX512_FINAL_CALL_COUNT.unwrap()
        );
        assert_eq!(
            candidate.geometry.compression_count,
            HX512_FINAL_COMPRESSION_COUNT.unwrap()
        );
        assert_eq!(
            candidate.geometry.direct_base_rows,
            HX512_FROZEN_HASH_TOPOLOGY_ROW_COUNT
        );
        assert_eq!(
            candidate.geometry.direct_base_cells,
            HX512_FROZEN_HASH_TOPOLOGY_CELL_COUNT
        );
        assert_eq!(
            candidate.geometry.explicit_padding_cells,
            HX512_FROZEN_HASH_TOPOLOGY_EXPLICIT_PADDING_CELLS
        );
        assert_eq!(
            candidate.geometry.rfc_zero_padding_bytes_by_mode,
            HX512_FROZEN_HASH_TOPOLOGY_RFC_ZERO_BYTES_BY_MODE
        );
        assert_eq!(
            candidate.operations.len() as u32,
            HX512_FROZEN_HASH_TOPOLOGY_OPERATION_COUNT
        );
        assert_eq!(
            candidate
                .shape_digest_sha512
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            concat!(
                "9f86ae65cfc4ad7208597595fac33adbf089ef0be5c42180f8f7c9dc0d16c25",
                "fae59a5a4ddd0d37bc20d0a59848a2e19392914a65b7fb51d69fdf39c8dba3a95"
            )
        );
        assert_eq!(
            candidate.geometry.compression_count,
            candidate_registry
                .calls
                .iter()
                .map(|call| u32::from(call.fixed_compressions))
                .sum::<u32>()
        );
        for mask in 0u8..16 {
            for mode in AuthorizationMode::ALL {
                for stable_direction in 0u8..3 {
                    let selected_view = (
                        mask,
                        mode.tag(),
                        stable_direction,
                        candidate.geometry.direct_base_rows,
                        candidate.shape_digest_sha512,
                    );
                    assert_eq!(selected_view.3, candidate.geometry.direct_base_rows);
                    assert_eq!(selected_view.4, candidate.shape_digest_sha512);
                }
            }
        }
        assert_eq!(HX512_FINAL_CALL_COUNT, Some(95));
        assert_eq!(HX512_FINAL_TOPOLOGY_DIGEST_SHA512, None);
    }

    #[test]
    fn shape_digest_is_stable_and_binds_registry_mutations() {
        let (registry, topology) = legacy();
        let digest = topology.shape_digest_sha512;
        let digest_hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            digest_hex,
            "c5cccebef8bcc47e0235d0cb22defe4e9da57fc349adab7ac5178d2832e913ab\
             5e8ebb8ed104a910ace914cf2b6373f9c699b0eb976baa0f7e84390ab10c9089"
        );
        assert_eq!(digest, shape_digest(&topology, &registry));
        let mut mutated = registry.clone();
        mutated.calls[0]
            .public_targets
            .push(target(14, TargetCondition::Always));
        let mutated_topology =
            compile_hx512_radix4_topology(&mutated).expect("valid mutated registry");
        assert_ne!(digest, mutated_topology.shape_digest_sha512);

        let mut selector_mutation = registry.clone();
        selector_mutation
            .authorization_mode_source
            .as_mut()
            .unwrap()
            .offset += 8;
        let selector_topology = compile_hx512_radix4_topology(&selector_mutation)
            .expect("valid selector source mutation");
        assert_ne!(digest, selector_topology.shape_digest_sha512);
    }

    #[test]
    fn malformed_registries_fail_closed() {
        let mut registry = rejected_legacy_hx512_90x213_registry();
        registry.calls[0].variants[0].spans[0].len -= 1;
        assert!(matches!(
            compile_hx512_radix4_topology(&registry),
            Err(Hx512TopologyError::InvalidMessagePartition { .. })
        ));

        let mut registry = rejected_legacy_hx512_90x213_registry();
        registry.calls[0]
            .public_targets
            .push(target(1_100, TargetCondition::Always));
        assert!(matches!(
            compile_hx512_radix4_topology(&registry),
            Err(Hx512TopologyError::InvalidPublicTarget { .. })
        ));

        let mut registry = rejected_legacy_hx512_90x213_registry();
        registry.calls[0].id = registry.calls[1].id;
        assert!(matches!(
            compile_hx512_radix4_topology(&registry),
            Err(Hx512TopologyError::DuplicateCallId(_))
        ));

        let mut registry = rejected_legacy_hx512_90x213_registry();
        registry.authorization_mode_source = None;
        assert!(matches!(
            compile_hx512_radix4_topology(&registry),
            Err(Hx512TopologyError::MissingAuthorizationModeSource)
        ));

        let mut registry = rejected_legacy_hx512_90x213_registry();
        registry.authorization_mode_source = Some(PrivateSelectorSource {
            offset: registry.private_witness_bytes,
            len: 8,
        });
        assert!(matches!(
            compile_hx512_radix4_topology(&registry),
            Err(Hx512TopologyError::InvalidAuthorizationModeSource)
        ));

        let mut registry = rejected_legacy_hx512_90x213_registry();
        registry.calls[0].fixed_compressions += 1;
        assert!(matches!(
            compile_hx512_radix4_topology(&registry),
            Err(Hx512TopologyError::NonCanonicalCompressionSlots { .. })
        ));
    }
}
