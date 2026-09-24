//! Mixed B128/E384 BaseFold low-degree commitment and opening prototype.
//!
//! Unlike [`crate::authenticated_basefold`], this module does not commit an
//! arbitrary table and merely fold it.  It first applies the same scalar
//! Gao--Mateer additive-NTT Reed--Solomon encoding used by the pinned BaseFold
//! source, commits the encoded B128 codeword, performs the DP24 inverse-
//! butterfly fold in E384, and verifies that the final rate-sized codeword is
//! constant.  Every later E384 layer is authenticated as three ordered B128
//! coefficient lanes.  The verifier receives an expected relation claim whose
//! initial root and geometry must match; a proof cannot select its own root.
//!
//! This is a real executable low-degree commitment/opening kernel, but it is
//! still research-only.  It has no hiding mask generator inside the relation,
//! no complete-ZK simulator, no composed PQ/QROM proof, and no production
//! integration. Queries are sampled canonically without replacement and the
//! exact fixed-bad-set miss product is exposed, but no composed adaptive FRI,
//! PCS, or QROM theorem is claimed. The executable scalar kernel requires
//! equal-dimension groups and is not the pinned M4 mixed-depth prover path.

use std::collections::BTreeMap;

use crate::{authenticated_basefold::sha512, B128, E384};

/// Canonical proof magic.
pub const MIXED_BASEFOLD_PCS_MAGIC: [u8; 8] = *b"HGMBF101";
/// Canonical wire version.
pub const MIXED_BASEFOLD_PCS_VERSION: u16 = 1;
/// Full SHA-512 digest/tape width.
pub const SHA512_BYTES: usize = 64;
/// Exact fixed header bytes.
pub const MIXED_BASEFOLD_PCS_HEADER_BYTES: usize = 160;
/// Exactly three B128 coefficients represent one E384 value.
pub const COEFFICIENT_LANE_COUNT: u8 = 3;
/// Bounds keep exact decoding allocation-safe.
pub const MAX_LOG_DIMENSION: usize = 20;
pub const MAX_LOG_INV_RATE: usize = 6;
pub const MAX_LOG_CODEWORD: usize = 26;
pub const MAX_GROUP_COUNT: usize = 64;
pub const MAX_QUERY_COUNT: usize = 512;

/// The complete-ZK audit requires two full-E384 multiplication dummy rows at
/// the outer endpoint.  This PCS does not create them; the constant prevents a
/// caller from silently substituting two one-lane B128 dummies.
pub const REQUIRED_FULL_E384_DUMMY_MULTIPLICATION_ROWS: usize = 2;

pub const COMPLETE_ZERO_KNOWLEDGE: bool = false;
pub const COMPOSED_PQ128_QROM: bool = false;
pub const PRODUCTION_AUTHORIZED: bool = false;

const ZERO_FLAGS: u16 = 0;
const HASH_SUITE_SHA512: u16 = 1;
const ZERO_RESERVED: [u8; 10] = [0; 10];
const GHASH_TRACE_ONE: B128 = B128::new(1u128 << 121);

const PROFILE: &[u8] = b"hegemon.strict-mixed-field.mixed-basefold-pcs.b128-e384.sha512.v1\0";
const CONTEXT_DOMAIN: &[u8] = b"hegemon.mixed-basefold.context.sha512.v1\0";
const LEAF_DOMAIN: &[u8] = b"hegemon.mixed-basefold.grouped-leaf.sha512.v1\0";
const NODE_DOMAIN: &[u8] = b"hegemon.mixed-basefold.node.sha512.v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"hegemon.mixed-basefold.transcript.sha512.v1\0";
const FOLD_DOMAIN: &[u8] = b"hegemon.mixed-basefold.fold-challenge.e384.sha512.v1\0";
const QUERY_DOMAIN: &[u8] = b"hegemon.mixed-basefold.query.sha512.v1\0";

pub type Digest = [u8; SHA512_BYTES];
pub type IndexTape = [u8; SHA512_BYTES];

/// Fail-closed wire and verifier failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MixedBasefoldPcsError {
    EmptyGroups,
    TooManyGroups {
        actual: usize,
        maximum: usize,
    },
    GroupLengthMismatch,
    InvalidDimension,
    InvalidRate,
    InvalidQueryCount {
        actual: usize,
        maximum: usize,
    },
    TooManyDistinctQueries {
        actual: usize,
        available: usize,
    },
    QuerySamplingExhausted,
    InvalidBadPairCount,
    RandomnessGeometryMismatch,
    LengthOverflow,
    ProofTruncated,
    ProofTrailingBytes {
        remaining: usize,
    },
    InvalidMagic,
    UnsupportedVersion {
        actual: u16,
    },
    NonzeroFlags {
        actual: u16,
    },
    InvalidLaneCount {
        actual: u8,
    },
    InvalidHashSuite {
        actual: u16,
    },
    NonzeroReserved,
    ProfileMismatch,
    ContextMismatch,
    RelationClaimMismatch,
    TranscriptSchedule,
    TerminalAuthentication,
    TerminalNotConstant {
        group: usize,
        index: usize,
    },
    OpeningAuthentication {
        round: usize,
    },
    FoldMismatch {
        query: usize,
        round: usize,
        group: usize,
    },
}

/// Caller-owned statement for the low-degree commitment relation.
///
/// The root is not taken from the proof as authority.  A surrounding protocol
/// must bind this object to its public statement before invoking the verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixedBasefoldRelationClaim {
    pub initial_root: Digest,
    pub log_dimension: u8,
    pub log_inv_rate: u8,
    pub group_count: u16,
}

/// Exact serializer counters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MixedBasefoldPcsSizeReport {
    pub fixed_bytes: usize,
    pub b128_symbols: usize,
    pub merkle_roots: usize,
    pub merkle_auth_nodes: usize,
    pub index_tapes: usize,
    pub log_dimension: usize,
    pub log_inv_rate: usize,
    pub group_count: usize,
    pub query_count: usize,
    /// Transcript-derived, sorted/deduplicated opened leaf count by layer.
    pub layer_opened_leaves: Vec<usize>,
    /// Canonical compact-frontier digest count by layer.
    pub layer_frontier_nodes: Vec<usize>,
}

impl MixedBasefoldPcsSizeReport {
    pub fn serialized_bytes(&self) -> usize {
        self.fixed_bytes
            + self.b128_symbols * B128::BYTE_SIZE
            + (self.merkle_roots + self.merkle_auth_nodes + self.index_tapes) * SHA512_BYTES
    }

    /// Exact grammar formula, where `d=log_dimension`, `r=log_inv_rate`,
    /// `g=group_count`, and `q=query_count`:
    ///
    /// `160 + 64(d+1) + 2^r(48g+64)
    ///      + u_0(16g+64) + 64f_0
    ///      + sum_(l=1..d-1) [u_l(48g+64) + 64f_l]`,
    ///
    /// where `u_l` is the sorted/deduplicated opened-leaf union and `f_l` is
    /// its canonical compact Merkle frontier.  Both schedules are transcript-
    /// derived and are returned by the serializer report.
    pub fn formula_bytes(
        log_dimension: usize,
        log_inv_rate: usize,
        group_count: usize,
        query_count: usize,
        layer_opened_leaves: &[usize],
        layer_frontier_nodes: &[usize],
    ) -> Result<usize, MixedBasefoldPcsError> {
        validate_geometry(log_dimension, log_inv_rate, group_count, query_count)?;
        if layer_opened_leaves.len() != log_dimension || layer_frontier_nodes.len() != log_dimension
        {
            return Err(MixedBasefoldPcsError::TranscriptSchedule);
        }
        let terminal_width = 1usize << log_inv_rate;
        let roots = (log_dimension + 1)
            .checked_mul(SHA512_BYTES)
            .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
        let terminal = terminal_width
            .checked_mul(
                group_count
                    .checked_mul(E384::BYTE_SIZE)
                    .and_then(|bytes| bytes.checked_add(SHA512_BYTES))
                    .ok_or(MixedBasefoldPcsError::LengthOverflow)?,
            )
            .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
        let mut total = MIXED_BASEFOLD_PCS_HEADER_BYTES
            .checked_add(roots)
            .and_then(|total| total.checked_add(terminal))
            .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
        for (layer, (&opened, &frontier)) in layer_opened_leaves
            .iter()
            .zip(layer_frontier_nodes)
            .enumerate()
        {
            let layer_bytes = opened
                .checked_mul(
                    group_count
                        .checked_mul(if layer == 0 {
                            B128::BYTE_SIZE
                        } else {
                            E384::BYTE_SIZE
                        })
                        .and_then(|bytes| bytes.checked_add(SHA512_BYTES))
                        .ok_or(MixedBasefoldPcsError::LengthOverflow)?,
                )
                .and_then(|bytes| {
                    frontier
                        .checked_mul(SHA512_BYTES)
                        .and_then(|frontier_bytes| bytes.checked_add(frontier_bytes))
                })
                .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
            total = total
                .checked_add(layer_bytes)
                .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
        }
        Ok(total)
    }
}

/// Project the exact canonical scalar-kernel wire from its transcript-bound
/// roots without allocating any codeword.  This is serializer-derived static
/// accounting, not a proof measurement and not evidence that the roots commit
/// a valid relation.
pub fn project_compact_size_from_roots(
    log_dimension: usize,
    log_inv_rate: usize,
    group_count: usize,
    query_count: usize,
    context: Digest,
    layer_roots: &[Digest],
) -> Result<MixedBasefoldPcsSizeReport, MixedBasefoldPcsError> {
    let schedule = derive_schedule(
        context,
        log_dimension,
        log_inv_rate,
        group_count,
        query_count,
        layer_roots,
    )?;
    let mut layer_opened_leaves = Vec::with_capacity(log_dimension);
    let mut layer_frontier_nodes = Vec::with_capacity(log_dimension);
    for round in 0..log_dimension {
        let selected = selected_leaf_indices(&schedule.query_indices, round);
        layer_opened_leaves.push(selected.len());
        layer_frontier_nodes.push(compact_frontier_count(
            log_dimension + log_inv_rate - round,
            &selected,
        )?);
    }
    let terminal_width = 1usize << log_inv_rate;
    let opened = layer_opened_leaves
        .iter()
        .try_fold(terminal_width, |total, &count| {
            total
                .checked_add(count)
                .ok_or(MixedBasefoldPcsError::LengthOverflow)
        })?;
    let merkle_auth_nodes = layer_frontier_nodes
        .iter()
        .try_fold(0usize, |total, &count| {
            total
                .checked_add(count)
                .ok_or(MixedBasefoldPcsError::LengthOverflow)
        })?;
    let terminal_symbols = terminal_width
        .checked_mul(group_count)
        .and_then(|count| count.checked_mul(COEFFICIENT_LANE_COUNT as usize))
        .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
    let initial_symbols = layer_opened_leaves[0]
        .checked_mul(group_count)
        .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
    let later_symbols = layer_opened_leaves[1..]
        .iter()
        .try_fold(0usize, |total, &count| {
            count
                .checked_mul(group_count)
                .and_then(|count| count.checked_mul(COEFFICIENT_LANE_COUNT as usize))
                .and_then(|count| total.checked_add(count))
                .ok_or(MixedBasefoldPcsError::LengthOverflow)
        })?;
    let b128_symbols = terminal_symbols
        .checked_add(initial_symbols)
        .and_then(|count| count.checked_add(later_symbols))
        .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
    let report = MixedBasefoldPcsSizeReport {
        fixed_bytes: MIXED_BASEFOLD_PCS_HEADER_BYTES,
        b128_symbols,
        merkle_roots: log_dimension + 1,
        merkle_auth_nodes,
        index_tapes: opened,
        log_dimension,
        log_inv_rate,
        group_count,
        query_count,
        layer_opened_leaves,
        layer_frontier_nodes,
    };
    let formula = MixedBasefoldPcsSizeReport::formula_bytes(
        log_dimension,
        log_inv_rate,
        group_count,
        query_count,
        &report.layer_opened_leaves,
        &report.layer_frontier_nodes,
    )?;
    if report.serialized_bytes() != formula {
        return Err(MixedBasefoldPcsError::LengthOverflow);
    }
    Ok(report)
}

/// Retained one-copy M4 geometry from the checked-in 448,224-byte SHAKE400
/// artifact.  These are seven distinct Merkle trees: four input oracles and
/// three committed FRI rounds.  The terminal commitment root is counted
/// separately in the eight total roots.
pub const RETAINED_M4_TREE_DEPTHS: [usize; 7] = [13, 18, 20, 11, 16, 12, 9];
pub const RETAINED_M4_LEAF_B128_VALUES: [usize; 7] = [2, 2, 2, 2, 16, 16, 8];
pub const RETAINED_M4_FOLD_ARITIES: [usize; 3] = [4, 4, 3];
pub const RETAINED_M4_TERMINAL_VALUES: usize = 512;
pub const RETAINED_M4_EXPLICIT_FIELD_MESSAGES: usize = 984;
pub const STRICT_SCREEN_QUERY_COUNT: usize = 319;
pub const CONSENSUS_PROOF_CAP_BYTES: usize = 512 * 1024;

const M4_PROJECTION_DOMAIN: &[u8] =
    b"hegemon.strict-mixed-field.retained-m4-mixed-depth-projection.sha512.v1\0";
const M4_PROJECTION_ROOT_DOMAIN: &[u8] =
    b"hegemon.strict-mixed-field.retained-m4-synthetic-root.sha512.v1\0";

/// Exact byte lower bound for the retained 4+3-tree layout after substituting
/// E384 fold/message values, one independent 64-byte tape per opened grouped
/// leaf, full SHA-512 roots/frontiers, and canonical compact frontiers for the
/// transcript-derived distinct query union.  Framing, relation masks, and all
/// complete-ZK repair bytes are deliberately zero, so exceeding the cap here
/// is a decisive size disqualification but fitting would prove nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedM4MixedDepthProjection {
    pub claim_label: &'static str,
    pub query_count: usize,
    pub tree_depths: [usize; 7],
    pub opened_leaves: [usize; 7],
    pub frontier_nodes: [usize; 7],
    pub input_b128_values: usize,
    pub fold_e384_values: usize,
    pub terminal_e384_values: usize,
    pub explicit_e384_messages: usize,
    pub roots: usize,
    pub index_tapes: usize,
    pub e384_lower_bound_bytes: usize,
    /// Same mixed channel with degree-four E512 challenges/round values.
    pub e512_mixed_lower_bound_bytes: usize,
    /// E512 everywhere, the only route that avoids separating the current
    /// prover channel's committed scalar from its challenge element.
    pub e512_stock_scalar_lower_bound_bytes: usize,
}

pub fn project_retained_m4_mixed_depth(
    query_count: usize,
) -> Result<RetainedM4MixedDepthProjection, MixedBasefoldPcsError> {
    if query_count == 0 || query_count > MAX_QUERY_COUNT {
        return Err(MixedBasefoldPcsError::InvalidQueryCount {
            actual: query_count,
            maximum: MAX_QUERY_COUNT,
        });
    }
    let global_depth = *RETAINED_M4_TREE_DEPTHS
        .iter()
        .max()
        .expect("nonempty geometry");
    let global_width = 1usize << global_depth;
    if query_count > global_width {
        return Err(MixedBasefoldPcsError::TooManyDistinctQueries {
            actual: query_count,
            available: global_width,
        });
    }
    let context = domain_hash(M4_PROJECTION_DOMAIN, M4_PROJECTION_DOMAIN);
    let mut transcript = Transcript::new(context, global_depth, 1, 7, query_count);
    for tree in 0..8usize {
        let depth = RETAINED_M4_TREE_DEPTHS.get(tree).copied().unwrap_or(9);
        let mut payload = Vec::with_capacity(24);
        payload.extend_from_slice(&(tree as u64).to_le_bytes());
        payload.extend_from_slice(&(depth as u64).to_le_bytes());
        payload.extend_from_slice(&(query_count as u64).to_le_bytes());
        let root = domain_hash(M4_PROJECTION_ROOT_DOMAIN, &payload);
        transcript.observe_root(tree, 1usize << depth, &root);
    }
    let mut available = SparsePermutation::identity(global_width);
    let mut global_queries = Vec::with_capacity(query_count);
    for ordinal in 0..query_count {
        global_queries.push(transcript.sample_distinct_query(&mut available, ordinal)?);
    }

    let mut opened_leaves = [0usize; 7];
    let mut frontier_nodes = [0usize; 7];
    for tree in 0..7 {
        let depth = RETAINED_M4_TREE_DEPTHS[tree];
        let shift = global_depth - depth;
        let mut selected = global_queries
            .iter()
            .map(|&index| index >> shift)
            .collect::<Vec<_>>();
        selected.sort_unstable();
        selected.dedup();
        opened_leaves[tree] = selected.len();
        frontier_nodes[tree] = compact_frontier_count(depth, &selected)?;
    }
    let input_b128_values = (0..4).try_fold(0usize, |total, tree| {
        opened_leaves[tree]
            .checked_mul(RETAINED_M4_LEAF_B128_VALUES[tree])
            .and_then(|count| total.checked_add(count))
            .ok_or(MixedBasefoldPcsError::LengthOverflow)
    })?;
    let fold_e384_values = (4..7).try_fold(0usize, |total, tree| {
        opened_leaves[tree]
            .checked_mul(RETAINED_M4_LEAF_B128_VALUES[tree])
            .and_then(|count| total.checked_add(count))
            .ok_or(MixedBasefoldPcsError::LengthOverflow)
    })?;
    let roots = 8usize;
    let index_tapes = opened_leaves.iter().sum::<usize>();
    let authentication_nodes = frontier_nodes.iter().sum::<usize>();
    let digest_units = roots
        .checked_add(index_tapes)
        .and_then(|count| count.checked_add(authentication_nodes))
        .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
    let e384_values = fold_e384_values
        .checked_add(RETAINED_M4_TERMINAL_VALUES)
        .and_then(|count| count.checked_add(RETAINED_M4_EXPLICIT_FIELD_MESSAGES))
        .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
    let e384_lower_bound_bytes = input_b128_values
        .checked_mul(B128::BYTE_SIZE)
        .and_then(|bytes| {
            e384_values
                .checked_mul(E384::BYTE_SIZE)
                .and_then(|wide| bytes.checked_add(wide))
        })
        .and_then(|bytes| {
            digest_units
                .checked_mul(SHA512_BYTES)
                .and_then(|digests| bytes.checked_add(digests))
        })
        .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
    let e512_mixed_lower_bound_bytes = e384_lower_bound_bytes
        .checked_add(
            e384_values
                .checked_mul(64 - E384::BYTE_SIZE)
                .ok_or(MixedBasefoldPcsError::LengthOverflow)?,
        )
        .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
    let e512_stock_scalar_lower_bound_bytes = e512_mixed_lower_bound_bytes
        .checked_add(
            input_b128_values
                .checked_mul(64 - B128::BYTE_SIZE)
                .ok_or(MixedBasefoldPcsError::LengthOverflow)?,
        )
        .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
    Ok(RetainedM4MixedDepthProjection {
        claim_label: "source-static serializer-term lower bound; not a proof measurement",
        query_count,
        tree_depths: RETAINED_M4_TREE_DEPTHS,
        opened_leaves,
        frontier_nodes,
        input_b128_values,
        fold_e384_values,
        terminal_e384_values: RETAINED_M4_TERMINAL_VALUES,
        explicit_e384_messages: RETAINED_M4_EXPLICIT_FIELD_MESSAGES,
        roots,
        index_tapes,
        e384_lower_bound_bytes,
        e512_mixed_lower_bound_bytes,
        e512_stock_scalar_lower_bound_bytes,
    })
}

/// Caller-supplied independent randomness for every committed grouped leaf.
///
/// Layer `l` must contain `2^(d+r-l)` independent 64-byte tapes.  The backend
/// never derives these tapes from the statement, transcript, witness, or one
/// master seed.  Test fixtures may use deterministic tapes but earn no hiding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixedBasefoldCommitmentRandomness {
    layer_tapes: Vec<Vec<IndexTape>>,
}

impl MixedBasefoldCommitmentRandomness {
    pub fn from_independent_layer_tapes(
        log_dimension: usize,
        log_inv_rate: usize,
        layer_tapes: Vec<Vec<IndexTape>>,
    ) -> Result<Self, MixedBasefoldPcsError> {
        if layer_tapes.len() != log_dimension + 1 {
            return Err(MixedBasefoldPcsError::RandomnessGeometryMismatch);
        }
        let log_codeword = log_dimension
            .checked_add(log_inv_rate)
            .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
        for (layer, tapes) in layer_tapes.iter().enumerate() {
            if tapes.len() != 1usize << (log_codeword - layer) {
                return Err(MixedBasefoldPcsError::RandomnessGeometryMismatch);
            }
        }
        Ok(Self { layer_tapes })
    }

    pub fn layer(&self, layer: usize) -> Option<&[IndexTape]> {
        self.layer_tapes.get(layer).map(Vec::as_slice)
    }

    pub fn required_tape_count(
        log_dimension: usize,
        log_inv_rate: usize,
    ) -> Result<usize, MixedBasefoldPcsError> {
        let log_codeword = log_dimension
            .checked_add(log_inv_rate)
            .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
        (0..=log_dimension).try_fold(0usize, |total, layer| {
            total
                .checked_add(1usize << (log_codeword - layer))
                .ok_or(MixedBasefoldPcsError::LengthOverflow)
        })
    }
}

/// Exact without-replacement query-miss product for a fixed set of bad pairs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistinctQuerySoundness {
    pub pair_count: usize,
    pub bad_pair_count: usize,
    pub query_count: usize,
    /// `P[miss] = product_i numerators[i] / denominators[i]`.
    pub numerators: Vec<usize>,
    pub denominators: Vec<usize>,
}

pub fn distinct_query_soundness(
    pair_count: usize,
    bad_pair_count: usize,
    query_count: usize,
) -> Result<DistinctQuerySoundness, MixedBasefoldPcsError> {
    if pair_count == 0 || bad_pair_count > pair_count {
        return Err(MixedBasefoldPcsError::InvalidBadPairCount);
    }
    if query_count > pair_count {
        return Err(MixedBasefoldPcsError::TooManyDistinctQueries {
            actual: query_count,
            available: pair_count,
        });
    }
    let good = pair_count - bad_pair_count;
    let mut numerators = Vec::with_capacity(query_count);
    let mut denominators = Vec::with_capacity(query_count);
    for draw in 0..query_count {
        numerators.push(good.saturating_sub(draw));
        denominators.push(pair_count - draw);
    }
    Ok(DistinctQuerySoundness {
        pair_count,
        bad_pair_count,
        query_count,
        numerators,
        denominators,
    })
}

/// Exact raw-opening inventory exported to the complete-ZK rank checker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawOpeningKind {
    PairLeft,
    PairRight,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawOpeningObservation {
    pub kind: RawOpeningKind,
    pub round: Option<usize>,
    pub leaf_index: usize,
    pub group: usize,
    pub coefficient_lane: usize,
    pub has_bound_index_tape: bool,
}

/// Enumerate every B128 coefficient exposed by the canonical proof view.  A ZK
/// compiler must build its actual mask observation matrix from this list and
/// prove `rank(R) = rank([R|W])`; counts alone are never sufficient.
pub fn raw_opening_observations_for_queries(
    log_dimension: usize,
    log_inv_rate: usize,
    group_count: usize,
    query_indices: &[usize],
) -> Result<Vec<RawOpeningObservation>, MixedBasefoldPcsError> {
    validate_geometry(
        log_dimension,
        log_inv_rate,
        group_count,
        query_indices.len(),
    )?;
    let mut observations = Vec::new();
    for terminal_index in 0..1usize << log_inv_rate {
        for group in 0..group_count {
            for coefficient_lane in 0..3 {
                observations.push(RawOpeningObservation {
                    kind: RawOpeningKind::Terminal,
                    round: None,
                    leaf_index: terminal_index,
                    group,
                    coefficient_lane,
                    has_bound_index_tape: true,
                });
            }
        }
    }
    for round in 0..log_dimension {
        for leaf_index in selected_leaf_indices(query_indices, round) {
            let kind = if leaf_index & 1 == 0 {
                RawOpeningKind::PairLeft
            } else {
                RawOpeningKind::PairRight
            };
            for group in 0..group_count {
                let lane_count = if round == 0 { 1 } else { 3 };
                for coefficient_lane in 0..lane_count {
                    observations.push(RawOpeningObservation {
                        kind,
                        round: Some(round),
                        leaf_index,
                        group,
                        coefficient_lane,
                        has_bound_index_tape: true,
                    });
                }
            }
        }
    }
    Ok(observations)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupedOpenedLeaf {
    pub values: Vec<E384>,
    pub index_tape: IndexTape,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactLayerOpening {
    /// Leaves in the exact sorted/deduplicated transcript-derived index order.
    pub opened_leaves: Vec<GroupedOpenedLeaf>,
    /// Minimal missing-subtree roots in canonical depth-first left-to-right
    /// order.  No prover-supplied indexes or padding nodes are accepted.
    pub frontier: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalLeaf {
    pub values: Vec<E384>,
    pub index_tape: IndexTape,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixedBasefoldPcsProof {
    log_dimension: u8,
    log_inv_rate: u8,
    group_count: u16,
    query_count: u16,
    profile_digest: Digest,
    context_digest: Digest,
    layer_roots: Vec<Digest>,
    terminal_leaves: Vec<TerminalLeaf>,
    layer_openings: Vec<CompactLayerOpening>,
}

impl MixedBasefoldPcsProof {
    pub const fn log_dimension(&self) -> usize {
        self.log_dimension as usize
    }
    pub const fn log_inv_rate(&self) -> usize {
        self.log_inv_rate as usize
    }
    pub const fn log_codeword(&self) -> usize {
        self.log_dimension() + self.log_inv_rate()
    }
    pub const fn group_count(&self) -> usize {
        self.group_count as usize
    }
    pub const fn query_count(&self) -> usize {
        self.query_count as usize
    }
    pub fn layer_roots(&self) -> &[Digest] {
        &self.layer_roots
    }
    pub fn terminal_leaves(&self) -> &[TerminalLeaf] {
        &self.terminal_leaves
    }
    pub fn layer_openings(&self) -> &[CompactLayerOpening] {
        &self.layer_openings
    }

    pub fn relation_claim(&self) -> MixedBasefoldRelationClaim {
        MixedBasefoldRelationClaim {
            initial_root: self.layer_roots[0],
            log_dimension: self.log_dimension,
            log_inv_rate: self.log_inv_rate,
            group_count: self.group_count,
        }
    }

    fn validate_shape(&self) -> Result<(), MixedBasefoldPcsError> {
        let d = self.log_dimension();
        let r = self.log_inv_rate();
        let g = self.group_count();
        let q = self.query_count();
        validate_geometry(d, r, g, q)?;
        if self.profile_digest != profile_digest() {
            return Err(MixedBasefoldPcsError::ProfileMismatch);
        }
        if self.layer_roots.len() != d + 1
            || self.terminal_leaves.len() != 1usize << r
            || self.layer_openings.len() != d
        {
            return Err(MixedBasefoldPcsError::TranscriptSchedule);
        }
        for terminal in &self.terminal_leaves {
            if terminal.values.len() != g {
                return Err(MixedBasefoldPcsError::TranscriptSchedule);
            }
        }
        let schedule = derive_schedule(self.context_digest, d, r, g, q, &self.layer_roots)?;
        for (round, opening) in self.layer_openings.iter().enumerate() {
            let selected = selected_leaf_indices(&schedule.query_indices, round);
            let frontier_count = compact_frontier_count(self.log_codeword() - round, &selected)?;
            if opening.opened_leaves.len() != selected.len()
                || opening.frontier.len() != frontier_count
            {
                return Err(MixedBasefoldPcsError::TranscriptSchedule);
            }
            if opening
                .opened_leaves
                .iter()
                .any(|leaf| leaf.values.len() != g)
            {
                return Err(MixedBasefoldPcsError::TranscriptSchedule);
            }
            if round == 0
                && opening.opened_leaves.iter().any(|leaf| {
                    leaf.values.iter().any(|value| {
                        let coefficients = value.coefficients();
                        coefficients[1] != B128::ZERO || coefficients[2] != B128::ZERO
                    })
                })
            {
                return Err(MixedBasefoldPcsError::TranscriptSchedule);
            }
        }
        Ok(())
    }

    pub fn encode_counted(
        &self,
    ) -> Result<(Vec<u8>, MixedBasefoldPcsSizeReport), MixedBasefoldPcsError> {
        self.validate_shape()?;
        let schedule = derive_schedule(
            self.context_digest,
            self.log_dimension(),
            self.log_inv_rate(),
            self.group_count(),
            self.query_count(),
            &self.layer_roots,
        )?;
        let mut opened_counts = Vec::with_capacity(self.log_dimension());
        let mut frontier_counts = Vec::with_capacity(self.log_dimension());
        for round in 0..self.log_dimension() {
            let selected = selected_leaf_indices(&schedule.query_indices, round);
            opened_counts.push(selected.len());
            frontier_counts.push(compact_frontier_count(
                self.log_codeword() - round,
                &selected,
            )?);
        }
        let mut writer = Writer::new(
            self.log_dimension(),
            self.log_inv_rate(),
            self.group_count(),
            self.query_count(),
            opened_counts,
            frontier_counts,
        );
        writer.write_fixed(&MIXED_BASEFOLD_PCS_MAGIC);
        writer.write_fixed(&MIXED_BASEFOLD_PCS_VERSION.to_le_bytes());
        writer.write_fixed(&ZERO_FLAGS.to_le_bytes());
        writer.write_fixed(&[self.log_dimension]);
        writer.write_fixed(&[self.log_inv_rate]);
        writer.write_fixed(&[COEFFICIENT_LANE_COUNT]);
        writer.write_fixed(&[0]);
        writer.write_fixed(&self.group_count.to_le_bytes());
        writer.write_fixed(&self.query_count.to_le_bytes());
        writer.write_fixed(&HASH_SUITE_SHA512.to_le_bytes());
        writer.write_fixed(&self.profile_digest);
        writer.write_fixed(&self.context_digest);
        writer.write_fixed(&ZERO_RESERVED);
        debug_assert_eq!(writer.report.fixed_bytes, MIXED_BASEFOLD_PCS_HEADER_BYTES);
        for root in &self.layer_roots {
            writer.write_root(root);
        }
        for leaf in &self.terminal_leaves {
            for &value in &leaf.values {
                writer.write_lane_value(value);
            }
            writer.write_tape(&leaf.index_tape);
        }
        for (layer, opening) in self.layer_openings.iter().enumerate() {
            for leaf in &opening.opened_leaves {
                for &value in &leaf.values {
                    if layer == 0 {
                        writer.write_base_value(value.coefficients()[0]);
                    } else {
                        writer.write_lane_value(value);
                    }
                }
                writer.write_tape(&leaf.index_tape);
            }
            for node in &opening.frontier {
                writer.write_auth_node(node);
            }
        }
        writer.finish()
    }

    pub fn decode_exact(encoded: &[u8]) -> Result<Self, MixedBasefoldPcsError> {
        let mut reader = Reader::new(encoded);
        if reader.read_array::<8>()? != MIXED_BASEFOLD_PCS_MAGIC {
            return Err(MixedBasefoldPcsError::InvalidMagic);
        }
        let version = u16::from_le_bytes(reader.read_array::<2>()?);
        if version != MIXED_BASEFOLD_PCS_VERSION {
            return Err(MixedBasefoldPcsError::UnsupportedVersion { actual: version });
        }
        let flags = u16::from_le_bytes(reader.read_array::<2>()?);
        if flags != ZERO_FLAGS {
            return Err(MixedBasefoldPcsError::NonzeroFlags { actual: flags });
        }
        let d = reader.read_array::<1>()?[0] as usize;
        let r = reader.read_array::<1>()?[0] as usize;
        let lanes = reader.read_array::<1>()?[0];
        if lanes != COEFFICIENT_LANE_COUNT {
            return Err(MixedBasefoldPcsError::InvalidLaneCount { actual: lanes });
        }
        if reader.read_array::<1>()?[0] != 0 {
            return Err(MixedBasefoldPcsError::NonzeroReserved);
        }
        let g = u16::from_le_bytes(reader.read_array::<2>()?) as usize;
        let q = u16::from_le_bytes(reader.read_array::<2>()?) as usize;
        let hash_suite = u16::from_le_bytes(reader.read_array::<2>()?);
        if hash_suite != HASH_SUITE_SHA512 {
            return Err(MixedBasefoldPcsError::InvalidHashSuite { actual: hash_suite });
        }
        validate_geometry(d, r, g, q)?;
        let carried_profile = reader.read_array::<SHA512_BYTES>()?;
        if carried_profile != profile_digest() {
            return Err(MixedBasefoldPcsError::ProfileMismatch);
        }
        let context_digest = reader.read_array::<SHA512_BYTES>()?;
        if reader.read_array::<10>()? != ZERO_RESERVED {
            return Err(MixedBasefoldPcsError::NonzeroReserved);
        }
        let mut layer_roots = Vec::with_capacity(d + 1);
        for _ in 0..=d {
            layer_roots.push(reader.read_array::<SHA512_BYTES>()?);
        }
        let schedule = derive_schedule(context_digest, d, r, g, q, &layer_roots)?;
        let mut selected_by_layer = Vec::with_capacity(d);
        let mut opened_counts = Vec::with_capacity(d);
        let mut frontier_counts = Vec::with_capacity(d);
        for round in 0..d {
            let selected = selected_leaf_indices(&schedule.query_indices, round);
            let frontier = compact_frontier_count(d + r - round, &selected)?;
            opened_counts.push(selected.len());
            frontier_counts.push(frontier);
            selected_by_layer.push(selected);
        }
        let expected = MixedBasefoldPcsSizeReport::formula_bytes(
            d,
            r,
            g,
            q,
            &opened_counts,
            &frontier_counts,
        )?;
        if encoded.len() < expected {
            return Err(MixedBasefoldPcsError::ProofTruncated);
        }
        if encoded.len() > expected {
            return Err(MixedBasefoldPcsError::ProofTrailingBytes {
                remaining: encoded.len() - expected,
            });
        }
        let mut terminal_leaves = Vec::with_capacity(1usize << r);
        for _ in 0..1usize << r {
            let mut values = Vec::with_capacity(g);
            for _ in 0..g {
                values.push(reader.read_lane_value()?);
            }
            terminal_leaves.push(TerminalLeaf {
                values,
                index_tape: reader.read_array::<SHA512_BYTES>()?,
            });
        }
        let mut layer_openings = Vec::with_capacity(d);
        for round in 0..d {
            let mut opened_leaves = Vec::with_capacity(selected_by_layer[round].len());
            for _ in &selected_by_layer[round] {
                let mut values = Vec::with_capacity(g);
                for _ in 0..g {
                    values.push(if round == 0 {
                        E384::from_b128(reader.read_base_value()?)
                    } else {
                        reader.read_lane_value()?
                    });
                }
                opened_leaves.push(GroupedOpenedLeaf {
                    values,
                    index_tape: reader.read_array::<SHA512_BYTES>()?,
                });
            }
            let mut frontier = Vec::with_capacity(frontier_counts[round]);
            for _ in 0..frontier_counts[round] {
                frontier.push(reader.read_array::<SHA512_BYTES>()?);
            }
            layer_openings.push(CompactLayerOpening {
                opened_leaves,
                frontier,
            });
        }
        reader.finish()?;
        let proof = Self {
            log_dimension: d as u8,
            log_inv_rate: r as u8,
            group_count: g as u16,
            query_count: q as u16,
            profile_digest: carried_profile,
            context_digest,
            layer_roots,
            terminal_leaves,
            layer_openings,
        };
        proof.validate_shape()?;
        Ok(proof)
    }
}

fn validate_geometry(d: usize, r: usize, g: usize, q: usize) -> Result<(), MixedBasefoldPcsError> {
    if d == 0 || d > MAX_LOG_DIMENSION {
        return Err(MixedBasefoldPcsError::InvalidDimension);
    }
    if r == 0 || r > MAX_LOG_INV_RATE || d + r > MAX_LOG_CODEWORD {
        return Err(MixedBasefoldPcsError::InvalidRate);
    }
    if g == 0 {
        return Err(MixedBasefoldPcsError::EmptyGroups);
    }
    if g > MAX_GROUP_COUNT {
        return Err(MixedBasefoldPcsError::TooManyGroups {
            actual: g,
            maximum: MAX_GROUP_COUNT,
        });
    }
    if q == 0 || q > MAX_QUERY_COUNT {
        return Err(MixedBasefoldPcsError::InvalidQueryCount {
            actual: q,
            maximum: MAX_QUERY_COUNT,
        });
    }
    let pair_count = 1usize << (d + r - 1);
    if q > pair_count {
        return Err(MixedBasefoldPcsError::TooManyDistinctQueries {
            actual: q,
            available: pair_count,
        });
    }
    Ok(())
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + 8 + payload.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    preimage.extend_from_slice(payload);
    sha512(&preimage)
}

pub fn profile_digest() -> Digest {
    domain_hash(PROFILE, PROFILE)
}
pub fn context_digest(context: &[u8]) -> Digest {
    domain_hash(CONTEXT_DOMAIN, context)
}

fn append_frame(buffer: &mut Vec<u8>, tag: u8, payload: &[u8]) {
    buffer.push(tag);
    buffer.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    buffer.extend_from_slice(payload);
}

#[derive(Clone, Debug)]
struct Transcript {
    state: Vec<u8>,
    fold_count: u64,
    query_count: u64,
}

impl Transcript {
    fn new(context: Digest, d: usize, r: usize, g: usize, q: usize) -> Self {
        let mut state = TRANSCRIPT_DOMAIN.to_vec();
        append_frame(&mut state, 1, &profile_digest());
        append_frame(&mut state, 2, &context);
        let mut geometry = Vec::with_capacity(32);
        for value in [d, r, g, q] {
            geometry.extend_from_slice(&(value as u64).to_le_bytes());
        }
        append_frame(&mut state, 3, &geometry);
        Self {
            state,
            fold_count: 0,
            query_count: 0,
        }
    }

    fn observe_root(&mut self, layer: usize, width: usize, root: &Digest) {
        let mut payload = Vec::with_capacity(16 + SHA512_BYTES);
        payload.extend_from_slice(&(layer as u64).to_le_bytes());
        payload.extend_from_slice(&(width as u64).to_le_bytes());
        payload.extend_from_slice(root);
        append_frame(&mut self.state, 4, &payload);
    }

    fn sample_fold(&mut self, round: usize) -> Result<E384, MixedBasefoldPcsError> {
        if self.fold_count != round as u64 {
            return Err(MixedBasefoldPcsError::TranscriptSchedule);
        }
        let mut preimage = self.state.clone();
        preimage.extend_from_slice(FOLD_DOMAIN);
        append_frame(&mut preimage, 5, &self.fold_count.to_le_bytes());
        let digest = sha512(&preimage);
        let mut raw = [0u8; E384::BYTE_SIZE];
        raw.copy_from_slice(&digest[..E384::BYTE_SIZE]);
        append_frame(&mut self.state, 6, &digest);
        self.fold_count += 1;
        Ok(E384::from_le_bytes(raw))
    }

    fn sample_distinct_query(
        &mut self,
        available: &mut SparsePermutation,
        ordinal: usize,
    ) -> Result<usize, MixedBasefoldPcsError> {
        if available.len() == 0
            || !available.len().is_power_of_two()
            || ordinal >= available.len()
            || self.query_count != ordinal as u64
        {
            return Err(MixedBasefoldPcsError::TranscriptSchedule);
        }
        let remaining = available.len() - ordinal;
        let range = remaining as u64;
        // Rejection sampling is exact.  `zone` is the largest multiple of the
        // range below 2^64 representable without a u128-to-u64 truncation.
        let zone = u64::MAX - (u64::MAX % range);
        for nonce in 0u64..65_536 {
            let mut payload = Vec::with_capacity(32);
            payload.extend_from_slice(&self.query_count.to_le_bytes());
            payload.extend_from_slice(&(available.len() as u64).to_le_bytes());
            payload.extend_from_slice(&range.to_le_bytes());
            payload.extend_from_slice(&nonce.to_le_bytes());
            let mut preimage = self.state.clone();
            preimage.extend_from_slice(QUERY_DOMAIN);
            append_frame(&mut preimage, 7, &payload);
            let digest = sha512(&preimage);
            let raw = u64::from_le_bytes(digest[..8].try_into().expect("eight digest bytes"));
            if raw >= zone {
                continue;
            }
            let chosen_position = ordinal + (raw % range) as usize;
            available.swap(ordinal, chosen_position);
            let index = available.get(ordinal);
            let mut response = Vec::with_capacity(88);
            response.extend_from_slice(&digest);
            response.extend_from_slice(&(chosen_position as u64).to_le_bytes());
            response.extend_from_slice(&(index as u64).to_le_bytes());
            response.extend_from_slice(&nonce.to_le_bytes());
            append_frame(&mut self.state, 8, &response);
            self.query_count += 1;
            return Ok(index);
        }
        Err(MixedBasefoldPcsError::QuerySamplingExhausted)
    }

    fn digest(&self) -> Digest {
        domain_hash(TRANSCRIPT_DOMAIN, &self.state)
    }
}

/// Sparse prefix of a Fisher--Yates permutation. Query derivation touches at
/// most `2q` positions, so exact decoding never allocates the entire domain
/// merely to derive at most 512 distinct indices.
#[derive(Clone, Debug)]
struct SparsePermutation {
    len: usize,
    moved: BTreeMap<usize, usize>,
}

impl SparsePermutation {
    fn identity(len: usize) -> Self {
        Self {
            len,
            moved: BTreeMap::new(),
        }
    }

    const fn len(&self) -> usize {
        self.len
    }

    fn get(&self, position: usize) -> usize {
        self.moved.get(&position).copied().unwrap_or(position)
    }

    fn set(&mut self, position: usize, value: usize) {
        if position == value {
            self.moved.remove(&position);
        } else {
            self.moved.insert(position, value);
        }
    }

    fn swap(&mut self, left: usize, right: usize) {
        let left_value = self.get(left);
        let right_value = self.get(right);
        self.set(left, right_value);
        self.set(right, left_value);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DerivedSchedule {
    fold_challenges: Vec<E384>,
    query_indices: Vec<usize>,
    transcript_digest: Digest,
}

fn derive_schedule(
    context: Digest,
    d: usize,
    r: usize,
    g: usize,
    q: usize,
    layer_roots: &[Digest],
) -> Result<DerivedSchedule, MixedBasefoldPcsError> {
    validate_geometry(d, r, g, q)?;
    if layer_roots.len() != d + 1 {
        return Err(MixedBasefoldPcsError::TranscriptSchedule);
    }
    let codeword_len = 1usize << (d + r);
    let mut transcript = Transcript::new(context, d, r, g, q);
    let mut fold_challenges = Vec::with_capacity(d);
    for (layer, root) in layer_roots.iter().enumerate() {
        transcript.observe_root(layer, codeword_len >> layer, root);
        if layer < d {
            fold_challenges.push(transcript.sample_fold(layer)?);
        }
    }
    let pair_count = codeword_len / 2;
    let mut available = SparsePermutation::identity(pair_count);
    let mut query_indices = Vec::with_capacity(q);
    for ordinal in 0..q {
        query_indices.push(transcript.sample_distinct_query(&mut available, ordinal)?);
    }
    Ok(DerivedSchedule {
        fold_challenges,
        query_indices,
        transcript_digest: transcript.digest(),
    })
}

fn selected_leaf_indices(query_indices: &[usize], round: usize) -> Vec<usize> {
    let mut selected = Vec::with_capacity(query_indices.len().saturating_mul(2));
    for &initial_pair in query_indices {
        let pair = initial_pair >> round;
        selected.push(pair * 2);
        selected.push(pair * 2 + 1);
    }
    selected.sort_unstable();
    selected.dedup();
    selected
}

fn compact_frontier_count(
    log_width: usize,
    selected: &[usize],
) -> Result<usize, MixedBasefoldPcsError> {
    if log_width > MAX_LOG_CODEWORD {
        return Err(MixedBasefoldPcsError::InvalidDimension);
    }
    let width = 1usize << log_width;
    if selected.is_empty()
        || selected.iter().any(|&index| index >= width)
        || selected.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(MixedBasefoldPcsError::TranscriptSchedule);
    }
    fn recurse(start: usize, width: usize, selected: &[usize]) -> usize {
        if selected.is_empty() {
            return 1;
        }
        if width == 1 {
            return 0;
        }
        let midpoint = start + width / 2;
        let split = selected.partition_point(|&index| index < midpoint);
        recurse(start, width / 2, &selected[..split])
            + recurse(midpoint, width / 2, &selected[split..])
    }
    Ok(recurse(0, width, selected))
}

/// Exact scalar Gao--Mateer basis used by the pinned B128 additive NTT.
pub fn gao_mateer_basis(log_domain: usize) -> Result<Vec<B128>, MixedBasefoldPcsError> {
    if log_domain == 0 || log_domain > MAX_LOG_CODEWORD {
        return Err(MixedBasefoldPcsError::InvalidDimension);
    }
    let mut beta = GHASH_TRACE_ONE;
    for _ in 0..(128 - log_domain) {
        beta = beta * beta + beta;
    }
    let mut basis = vec![B128::ZERO; log_domain];
    basis[log_domain - 1] = beta;
    for index in (1..log_domain).rev() {
        basis[index - 1] = basis[index] * basis[index] + basis[index];
    }
    if basis[0] != B128::ONE {
        return Err(MixedBasefoldPcsError::InvalidDimension);
    }
    Ok(basis)
}

fn gao_mateer_twiddle(basis: &[B128], layer: usize, block: usize) -> B128 {
    debug_assert!(layer < basis.len());
    debug_assert!(block < 1usize << layer);
    let mut value = B128::ZERO;
    for bit in 0..layer {
        if (block >> bit) & 1 != 0 {
            value += basis[bit + 1];
        }
    }
    value
}

fn bit_reverse(value: usize, bits: usize) -> usize {
    value.reverse_bits() >> (usize::BITS as usize - bits)
}

/// Scalar reference implementation of pinned `ReedSolomonCode::encode_batch`
/// for one B128 message and batch size zero.
pub fn encode_b128_reed_solomon(
    message: &[B128],
    log_inv_rate: usize,
) -> Result<Vec<B128>, MixedBasefoldPcsError> {
    if message.len() < 2 || !message.len().is_power_of_two() {
        return Err(MixedBasefoldPcsError::InvalidDimension);
    }
    let d = message.len().trailing_zeros() as usize;
    validate_geometry(d, log_inv_rate, 1, 1)?;
    let log_codeword = d + log_inv_rate;
    let basis = gao_mateer_basis(log_codeword)?;
    let codeword_len = 1usize << log_codeword;
    let mut data = Vec::with_capacity(codeword_len);
    for index in 0..codeword_len {
        data.push(message[bit_reverse(index & (message.len() - 1), d)]);
    }
    // Exact neighbors-last reference transform, skipping the early rate
    // layers whose zero-padding butterflies were replaced by repetition.
    for layer in log_inv_rate..log_codeword {
        let block_count = 1usize << layer;
        let half = 1usize << (log_codeword - layer - 1);
        for block in 0..block_count {
            let twiddle = gao_mateer_twiddle(&basis, layer, block);
            let start = block << (log_codeword - layer);
            for low in start..start + half {
                let high = low | half;
                let mut u = data[low];
                let mut v = data[high];
                u += v * twiddle;
                v += u;
                data[low] = u;
                data[high] = v;
            }
        }
    }
    Ok(data)
}

fn basefold_pair(
    basis: &[B128],
    log_len: usize,
    index: usize,
    left: E384,
    right: E384,
    challenge: E384,
) -> E384 {
    let twiddle = E384::from_b128(gao_mateer_twiddle(basis, log_len - 1, index));
    let mut u = left;
    let mut v = right;
    v += u;
    u += v * twiddle;
    u + (v - u) * challenge
}

fn fold_groups(
    groups: &[Vec<E384>],
    basis: &[B128],
    log_len: usize,
    challenge: E384,
) -> Vec<Vec<E384>> {
    groups
        .iter()
        .map(|group| {
            group
                .chunks_exact(2)
                .enumerate()
                .map(|(index, pair)| {
                    basefold_pair(basis, log_len, index, pair[0], pair[1], challenge)
                })
                .collect()
        })
        .collect()
}

fn leaf_hash(
    layer: usize,
    width: usize,
    index: usize,
    values: &[E384],
    tape: &IndexTape,
) -> Digest {
    let lane_count = if layer == 0 { 1usize } else { 3usize };
    let mut payload =
        Vec::with_capacity(27 + values.len() * lane_count * B128::BYTE_SIZE + SHA512_BYTES);
    payload.extend_from_slice(&(layer as u64).to_le_bytes());
    payload.extend_from_slice(&(width as u64).to_le_bytes());
    payload.extend_from_slice(&(index as u64).to_le_bytes());
    payload.extend_from_slice(&(values.len() as u16).to_le_bytes());
    payload.push(lane_count as u8);
    payload.extend_from_slice(tape);
    for value in values {
        let coefficients = value.coefficients();
        debug_assert!(
            layer != 0 || (coefficients[1] == B128::ZERO && coefficients[2] == B128::ZERO)
        );
        for coefficient in &coefficients[..lane_count] {
            payload.extend_from_slice(&coefficient.to_le_bytes());
        }
    }
    domain_hash(LEAF_DOMAIN, &payload)
}

fn node_hash(
    layer: usize,
    tree_level: usize,
    node_index: usize,
    left: &Digest,
    right: &Digest,
) -> Digest {
    let mut payload = Vec::with_capacity(24 + 2 * SHA512_BYTES);
    payload.extend_from_slice(&(layer as u64).to_le_bytes());
    payload.extend_from_slice(&(tree_level as u64).to_le_bytes());
    payload.extend_from_slice(&(node_index as u64).to_le_bytes());
    payload.extend_from_slice(left);
    payload.extend_from_slice(right);
    domain_hash(NODE_DOMAIN, &payload)
}

fn group_values_at(groups: &[Vec<E384>], index: usize) -> Vec<E384> {
    groups.iter().map(|group| group[index]).collect()
}

#[derive(Clone, Debug)]
struct MerkleTree {
    width: usize,
    levels: Vec<Vec<Digest>>,
}

impl MerkleTree {
    fn build(
        layer: usize,
        groups: &[Vec<E384>],
        tapes: &[IndexTape],
    ) -> Result<Self, MixedBasefoldPcsError> {
        if groups.is_empty() {
            return Err(MixedBasefoldPcsError::EmptyGroups);
        }
        let width = groups[0].len();
        if width == 0
            || !width.is_power_of_two()
            || groups.iter().any(|group| group.len() != width)
            || tapes.len() != width
        {
            return Err(MixedBasefoldPcsError::GroupLengthMismatch);
        }
        let mut leaves = Vec::with_capacity(width);
        for index in 0..width {
            leaves.push(leaf_hash(
                layer,
                width,
                index,
                &group_values_at(groups, index),
                &tapes[index],
            ));
        }
        Ok(Self {
            width,
            levels: merkle_levels(layer, leaves),
        })
    }

    fn root(&self) -> Digest {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("validated Merkle tree has a root")
    }

    fn compact_frontier(&self, selected: &[usize]) -> Result<Vec<Digest>, MixedBasefoldPcsError> {
        let log_width = self.width.trailing_zeros() as usize;
        let expected = compact_frontier_count(log_width, selected)?;
        if selected.last().copied().unwrap_or(self.width) >= self.width {
            return Err(MixedBasefoldPcsError::TranscriptSchedule);
        }
        fn recurse(
            tree: &MerkleTree,
            start: usize,
            width: usize,
            selected: &[usize],
            output: &mut Vec<Digest>,
        ) {
            if selected.is_empty() {
                let height = width.trailing_zeros() as usize;
                output.push(tree.levels[height][start >> height]);
                return;
            }
            if width == 1 {
                return;
            }
            let midpoint = start + width / 2;
            let split = selected.partition_point(|&index| index < midpoint);
            recurse(tree, start, width / 2, &selected[..split], output);
            recurse(tree, midpoint, width / 2, &selected[split..], output);
        }
        let mut frontier = Vec::with_capacity(expected);
        recurse(self, 0, self.width, selected, &mut frontier);
        debug_assert_eq!(frontier.len(), expected);
        Ok(frontier)
    }
}

fn merkle_levels(layer: usize, leaves: Vec<Digest>) -> Vec<Vec<Digest>> {
    debug_assert!(!leaves.is_empty() && leaves.len().is_power_of_two());
    let mut levels = vec![leaves];
    let mut tree_level = 1usize;
    while levels.last().expect("leaf level exists").len() > 1 {
        let previous = levels.last().expect("previous level exists");
        let mut next = Vec::with_capacity(previous.len() / 2);
        for (index, pair) in previous.chunks_exact(2).enumerate() {
            next.push(node_hash(layer, tree_level, index, &pair[0], &pair[1]));
        }
        levels.push(next);
        tree_level += 1;
    }
    levels
}

fn reconstruct_compact_root(
    layer: usize,
    width: usize,
    selected: &[usize],
    opening: &CompactLayerOpening,
) -> Result<Digest, MixedBasefoldPcsError> {
    if width == 0 || !width.is_power_of_two() {
        return Err(MixedBasefoldPcsError::TranscriptSchedule);
    }
    let mut leaf_cursor = 0usize;
    let mut frontier_cursor = 0usize;
    fn recurse(
        layer: usize,
        full_width: usize,
        start: usize,
        width: usize,
        selected: &[usize],
        opening: &CompactLayerOpening,
        leaf_cursor: &mut usize,
        frontier_cursor: &mut usize,
    ) -> Result<Digest, MixedBasefoldPcsError> {
        if selected.is_empty() {
            let digest = opening
                .frontier
                .get(*frontier_cursor)
                .copied()
                .ok_or(MixedBasefoldPcsError::TranscriptSchedule)?;
            *frontier_cursor += 1;
            return Ok(digest);
        }
        if width == 1 {
            if selected != [start] {
                return Err(MixedBasefoldPcsError::TranscriptSchedule);
            }
            let leaf = opening
                .opened_leaves
                .get(*leaf_cursor)
                .ok_or(MixedBasefoldPcsError::TranscriptSchedule)?;
            *leaf_cursor += 1;
            return Ok(leaf_hash(
                layer,
                full_width,
                start,
                &leaf.values,
                &leaf.index_tape,
            ));
        }
        let midpoint = start + width / 2;
        let split = selected.partition_point(|&index| index < midpoint);
        let left = recurse(
            layer,
            full_width,
            start,
            width / 2,
            &selected[..split],
            opening,
            leaf_cursor,
            frontier_cursor,
        )?;
        let right = recurse(
            layer,
            full_width,
            midpoint,
            width / 2,
            &selected[split..],
            opening,
            leaf_cursor,
            frontier_cursor,
        )?;
        let height = width.trailing_zeros() as usize;
        Ok(node_hash(layer, height, start >> height, &left, &right))
    }
    let root = recurse(
        layer,
        width,
        0,
        width,
        selected,
        opening,
        &mut leaf_cursor,
        &mut frontier_cursor,
    )?;
    if leaf_cursor != opening.opened_leaves.len() || frontier_cursor != opening.frontier.len() {
        return Err(MixedBasefoldPcsError::TranscriptSchedule);
    }
    Ok(root)
}

fn opened_leaf_at<'a>(
    selected: &[usize],
    opening: &'a CompactLayerOpening,
    index: usize,
) -> Result<&'a GroupedOpenedLeaf, MixedBasefoldPcsError> {
    let position = selected
        .binary_search(&index)
        .map_err(|_| MixedBasefoldPcsError::TranscriptSchedule)?;
    opening
        .opened_leaves
        .get(position)
        .ok_or(MixedBasefoldPcsError::TranscriptSchedule)
}

fn terminal_root(
    layer: usize,
    terminal_leaves: &[TerminalLeaf],
) -> Result<Digest, MixedBasefoldPcsError> {
    if terminal_leaves.is_empty() || !terminal_leaves.len().is_power_of_two() {
        return Err(MixedBasefoldPcsError::TranscriptSchedule);
    }
    let width = terminal_leaves.len();
    let leaves = terminal_leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| leaf_hash(layer, width, index, &leaf.values, &leaf.index_tape))
        .collect();
    Ok(merkle_levels(layer, leaves)
        .last()
        .expect("root level exists")[0])
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixedBasefoldPcsProverOutput {
    pub proof: MixedBasefoldPcsProof,
    pub relation_claim: MixedBasefoldRelationClaim,
    pub fold_challenges: Vec<E384>,
    pub query_indices: Vec<usize>,
    pub transcript_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixedBasefoldPcsVerification {
    pub fold_challenges: Vec<E384>,
    pub query_indices: Vec<usize>,
    pub terminal_constants: Vec<E384>,
    pub transcript_digest: Digest,
}

/// Encode equal-dimension B128 groups, commit every E384 fold layer, and open
/// the transcript-derived distinct-query union with one compact Merkle
/// frontier per layer.  Every committed leaf consumes an explicit independent
/// 64-byte tape supplied by `randomness`; the backend has no master-seed API.
pub fn prove_mixed_basefold_pcs(
    messages: &[Vec<B128>],
    log_inv_rate: usize,
    query_count: usize,
    context: &[u8],
    randomness: &MixedBasefoldCommitmentRandomness,
) -> Result<MixedBasefoldPcsProverOutput, MixedBasefoldPcsError> {
    if messages.is_empty() {
        return Err(MixedBasefoldPcsError::EmptyGroups);
    }
    if messages.len() > MAX_GROUP_COUNT {
        return Err(MixedBasefoldPcsError::TooManyGroups {
            actual: messages.len(),
            maximum: MAX_GROUP_COUNT,
        });
    }
    let dimension = messages[0].len();
    if messages.iter().any(|message| message.len() != dimension) {
        return Err(MixedBasefoldPcsError::GroupLengthMismatch);
    }
    if dimension < 2 || !dimension.is_power_of_two() {
        return Err(MixedBasefoldPcsError::InvalidDimension);
    }
    let d = dimension.trailing_zeros() as usize;
    validate_geometry(d, log_inv_rate, messages.len(), query_count)?;
    if randomness.layer_tapes.len() != d + 1 {
        return Err(MixedBasefoldPcsError::RandomnessGeometryMismatch);
    }
    let log_codeword = d + log_inv_rate;
    let codeword_len = 1usize << log_codeword;
    let basis = gao_mateer_basis(log_codeword)?;

    let mut tables = Vec::with_capacity(d + 1);
    tables.push(
        messages
            .iter()
            .map(|message| {
                encode_b128_reed_solomon(message, log_inv_rate).map(|codeword| {
                    codeword
                        .into_iter()
                        .map(E384::from_b128)
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    );
    let context_digest = context_digest(context);
    let mut transcript =
        Transcript::new(context_digest, d, log_inv_rate, messages.len(), query_count);
    let mut trees = Vec::with_capacity(d + 1);
    let mut layer_tapes = Vec::with_capacity(d + 1);
    let mut roots = Vec::with_capacity(d + 1);
    let mut challenges = Vec::with_capacity(d);
    for layer in 0..=d {
        let width = codeword_len >> layer;
        let tapes = randomness
            .layer(layer)
            .ok_or(MixedBasefoldPcsError::RandomnessGeometryMismatch)?;
        if tapes.len() != width {
            return Err(MixedBasefoldPcsError::RandomnessGeometryMismatch);
        }
        let tree = MerkleTree::build(layer, &tables[layer], &tapes)?;
        let root = tree.root();
        transcript.observe_root(layer, width, &root);
        roots.push(root);
        trees.push(tree);
        layer_tapes.push(tapes.to_vec());
        if layer < d {
            let challenge = transcript.sample_fold(layer)?;
            challenges.push(challenge);
            tables.push(fold_groups(
                &tables[layer],
                &basis,
                log_codeword - layer,
                challenge,
            ));
        }
    }

    let terminal_width = 1usize << log_inv_rate;
    debug_assert_eq!(tables[d][0].len(), terminal_width);
    let terminal_leaves = (0..terminal_width)
        .map(|index| TerminalLeaf {
            values: group_values_at(&tables[d], index),
            index_tape: layer_tapes[d][index],
        })
        .collect::<Vec<_>>();

    let schedule = derive_schedule(
        context_digest,
        d,
        log_inv_rate,
        messages.len(),
        query_count,
        &roots,
    )?;
    if schedule.fold_challenges != challenges {
        return Err(MixedBasefoldPcsError::TranscriptSchedule);
    }
    let mut layer_openings = Vec::with_capacity(d);
    for round in 0..d {
        let selected = selected_leaf_indices(&schedule.query_indices, round);
        let opened_leaves = selected
            .iter()
            .map(|&index| GroupedOpenedLeaf {
                values: group_values_at(&tables[round], index),
                index_tape: layer_tapes[round][index],
            })
            .collect();
        let frontier = trees[round].compact_frontier(&selected)?;
        layer_openings.push(CompactLayerOpening {
            opened_leaves,
            frontier,
        });
    }

    let proof = MixedBasefoldPcsProof {
        log_dimension: d as u8,
        log_inv_rate: log_inv_rate as u8,
        group_count: messages.len() as u16,
        query_count: query_count as u16,
        profile_digest: profile_digest(),
        context_digest,
        layer_roots: roots,
        terminal_leaves,
        layer_openings,
    };
    proof.validate_shape()?;
    let relation_claim = proof.relation_claim();
    Ok(MixedBasefoldPcsProverOutput {
        proof,
        relation_claim,
        fold_challenges: challenges,
        query_indices: schedule.query_indices,
        transcript_digest: schedule.transcript_digest,
    })
}

pub fn verify_mixed_basefold_pcs(
    proof: &MixedBasefoldPcsProof,
    expected_claim: &MixedBasefoldRelationClaim,
    context: &[u8],
) -> Result<MixedBasefoldPcsVerification, MixedBasefoldPcsError> {
    proof.validate_shape()?;
    if proof.context_digest != context_digest(context) {
        return Err(MixedBasefoldPcsError::ContextMismatch);
    }
    if &proof.relation_claim() != expected_claim {
        return Err(MixedBasefoldPcsError::RelationClaimMismatch);
    }
    let d = proof.log_dimension();
    let r = proof.log_inv_rate();
    let g = proof.group_count();
    let q = proof.query_count();
    let log_codeword = d + r;
    let codeword_len = 1usize << log_codeword;
    let basis = gao_mateer_basis(log_codeword)?;

    if terminal_root(d, &proof.terminal_leaves)? != proof.layer_roots[d] {
        return Err(MixedBasefoldPcsError::TerminalAuthentication);
    }
    let mut terminal_constants = Vec::with_capacity(g);
    for group in 0..g {
        let constant = proof.terminal_leaves[0].values[group];
        for (index, leaf) in proof.terminal_leaves.iter().enumerate().skip(1) {
            if leaf.values[group] != constant {
                return Err(MixedBasefoldPcsError::TerminalNotConstant { group, index });
            }
        }
        terminal_constants.push(constant);
    }

    let schedule = derive_schedule(proof.context_digest, d, r, g, q, &proof.layer_roots)?;
    let selected_by_layer = (0..d)
        .map(|round| selected_leaf_indices(&schedule.query_indices, round))
        .collect::<Vec<_>>();
    for round in 0..d {
        let width = codeword_len >> round;
        if reconstruct_compact_root(
            round,
            width,
            &selected_by_layer[round],
            &proof.layer_openings[round],
        )? != proof.layer_roots[round]
        {
            return Err(MixedBasefoldPcsError::OpeningAuthentication { round });
        }
    }
    for (query, &initial_pair) in schedule.query_indices.iter().enumerate() {
        let mut pair_index = initial_pair;
        for round in 0..d {
            let opening = &proof.layer_openings[round];
            let left = opened_leaf_at(&selected_by_layer[round], opening, pair_index * 2)?;
            let right = opened_leaf_at(&selected_by_layer[round], opening, pair_index * 2 + 1)?;
            for group in 0..g {
                let folded = basefold_pair(
                    &basis,
                    log_codeword - round,
                    pair_index,
                    left.values[group],
                    right.values[group],
                    schedule.fold_challenges[round],
                );
                let expected = if round + 1 == d {
                    proof.terminal_leaves[pair_index].values[group]
                } else {
                    opened_leaf_at(
                        &selected_by_layer[round + 1],
                        &proof.layer_openings[round + 1],
                        pair_index,
                    )?
                    .values[group]
                };
                if folded != expected {
                    return Err(MixedBasefoldPcsError::FoldMismatch {
                        query,
                        round,
                        group,
                    });
                }
            }
            pair_index >>= 1;
        }
    }
    Ok(MixedBasefoldPcsVerification {
        fold_challenges: schedule.fold_challenges,
        query_indices: schedule.query_indices,
        terminal_constants,
        transcript_digest: schedule.transcript_digest,
    })
}

pub fn verify_mixed_basefold_pcs_exact(
    encoded: &[u8],
    expected_claim: &MixedBasefoldRelationClaim,
    context: &[u8],
) -> Result<MixedBasefoldPcsVerification, MixedBasefoldPcsError> {
    let proof = MixedBasefoldPcsProof::decode_exact(encoded)?;
    let (canonical, _) = proof.encode_counted()?;
    if canonical != encoded {
        return Err(MixedBasefoldPcsError::TranscriptSchedule);
    }
    verify_mixed_basefold_pcs(&proof, expected_claim, context)
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
    report: MixedBasefoldPcsSizeReport,
}

impl Writer {
    fn new(
        d: usize,
        r: usize,
        g: usize,
        q: usize,
        layer_opened_leaves: Vec<usize>,
        layer_frontier_nodes: Vec<usize>,
    ) -> Self {
        Self {
            bytes: Vec::new(),
            report: MixedBasefoldPcsSizeReport {
                log_dimension: d,
                log_inv_rate: r,
                group_count: g,
                query_count: q,
                layer_opened_leaves,
                layer_frontier_nodes,
                ..MixedBasefoldPcsSizeReport::default()
            },
        }
    }
    fn write_fixed(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
        self.report.fixed_bytes += bytes.len();
    }
    fn write_root(&mut self, root: &Digest) {
        self.bytes.extend_from_slice(root);
        self.report.merkle_roots += 1;
    }
    fn write_lane_value(&mut self, value: E384) {
        for coefficient in value.coefficients() {
            self.bytes.extend_from_slice(&coefficient.to_le_bytes());
            self.report.b128_symbols += 1;
        }
    }
    fn write_base_value(&mut self, value: B128) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self.report.b128_symbols += 1;
    }
    fn write_tape(&mut self, tape: &IndexTape) {
        self.bytes.extend_from_slice(tape);
        self.report.index_tapes += 1;
    }
    fn write_auth_node(&mut self, node: &Digest) {
        self.bytes.extend_from_slice(node);
        self.report.merkle_auth_nodes += 1;
    }
    fn finish(self) -> Result<(Vec<u8>, MixedBasefoldPcsSizeReport), MixedBasefoldPcsError> {
        let formula = MixedBasefoldPcsSizeReport::formula_bytes(
            self.report.log_dimension,
            self.report.log_inv_rate,
            self.report.group_count,
            self.report.query_count,
            &self.report.layer_opened_leaves,
            &self.report.layer_frontier_nodes,
        )?;
        if self.bytes.len() != self.report.serialized_bytes() || self.bytes.len() != formula {
            return Err(MixedBasefoldPcsError::LengthOverflow);
        }
        Ok((self.bytes, self.report))
    }
}

struct Reader<'a> {
    encoded: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, cursor: 0 }
    }
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], MixedBasefoldPcsError> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(MixedBasefoldPcsError::LengthOverflow)?;
        let bytes = self
            .encoded
            .get(self.cursor..end)
            .ok_or(MixedBasefoldPcsError::ProofTruncated)?;
        self.cursor = end;
        Ok(bytes.try_into().expect("exact reader requested N bytes"))
    }
    fn read_lane_value(&mut self) -> Result<E384, MixedBasefoldPcsError> {
        let mut coefficients = [B128::ZERO; 3];
        for coefficient in &mut coefficients {
            *coefficient = B128::from_le_bytes(self.read_array::<{ B128::BYTE_SIZE }>()?);
        }
        Ok(E384::from_coefficients(coefficients))
    }
    fn read_base_value(&mut self) -> Result<B128, MixedBasefoldPcsError> {
        Ok(B128::from_le_bytes(
            self.read_array::<{ B128::BYTE_SIZE }>()?,
        ))
    }
    fn finish(self) -> Result<(), MixedBasefoldPcsError> {
        if self.cursor != self.encoded.len() {
            return Err(MixedBasefoldPcsError::ProofTrailingBytes {
                remaining: self.encoded.len() - self.cursor,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: &[u8] = b"hegemon.mixed-basefold-pcs.kat.statement-network-action-v1";
    fn messages() -> [Vec<B128>; 2] {
        [
            vec![B128::new(1), B128::new(2), B128::new(3), B128::new(4)],
            vec![
                B128::new(0x100),
                B128::new(0x200),
                B128::new(0x300),
                B128::new(0x400),
            ],
        ]
    }

    fn fixture_randomness() -> MixedBasefoldCommitmentRandomness {
        let d = 2usize;
        let r = 2usize;
        let mut layers = Vec::with_capacity(d + 1);
        for layer in 0..=d {
            let width = 1usize << (d + r - layer);
            let tapes = (0..width)
                .map(|index| {
                    let mut payload = Vec::new();
                    payload.extend_from_slice(b"TEST-ONLY independent tape fixture");
                    payload.extend_from_slice(&(layer as u64).to_le_bytes());
                    payload.extend_from_slice(&(index as u64).to_le_bytes());
                    sha512(&payload)
                })
                .collect();
            layers.push(tapes);
        }
        MixedBasefoldCommitmentRandomness::from_independent_layer_tapes(d, r, layers).unwrap()
    }

    fn fixture() -> (
        MixedBasefoldPcsProverOutput,
        Vec<u8>,
        MixedBasefoldPcsSizeReport,
    ) {
        let randomness = fixture_randomness();
        let proved = prove_mixed_basefold_pcs(&messages(), 2, 3, CONTEXT, &randomness).unwrap();
        let (encoded, report) = proved.proof.encode_counted().unwrap();
        (proved, encoded, report)
    }

    fn swap_ranges(bytes: &mut [u8], first: usize, second: usize, len: usize) {
        for offset in 0..len {
            bytes.swap(first + offset, second + offset);
        }
    }

    #[test]
    fn scalar_gao_mateer_rs_encoding_is_nontrivial_and_rate_sized() {
        let message = &messages()[0];
        let encoded = encode_b128_reed_solomon(message, 2).unwrap();
        assert_eq!(encoded.len(), 16);
        assert_ne!(&encoded[..message.len()], message);
        let basis = gao_mateer_basis(4).unwrap();
        assert_eq!(basis[0], B128::ONE);
        assert_eq!(basis.len(), 4);
    }

    #[test]
    fn mixed_rs_basefold_roundtrips_and_terminal_is_low_degree_constant() {
        let (proved, encoded, report) = fixture();
        let verified =
            verify_mixed_basefold_pcs_exact(&encoded, &proved.relation_claim, CONTEXT).unwrap();
        assert_eq!(verified.fold_challenges, proved.fold_challenges);
        assert_eq!(verified.query_indices, proved.query_indices);
        assert_eq!(verified.transcript_digest, proved.transcript_digest);
        assert_eq!(verified.terminal_constants.len(), 2);
        assert!(!COMPLETE_ZERO_KNOWLEDGE);
        assert!(!COMPOSED_PQ128_QROM);
        assert!(!PRODUCTION_AUTHORIZED);
        assert_eq!(report.serialized_bytes(), encoded.len());
        assert_eq!(
            MixedBasefoldPcsProof::decode_exact(&encoded).unwrap(),
            proved.proof
        );
    }

    #[test]
    fn serializer_report_is_derived_and_exact() {
        let (_, encoded, report) = fixture();
        assert_eq!(report.fixed_bytes, 160);
        let expected_symbols =
            4 * 2 * 3 + report.layer_opened_leaves[0] * 2 + report.layer_opened_leaves[1] * 2 * 3;
        assert_eq!(report.b128_symbols, expected_symbols);
        assert_eq!(report.merkle_roots, 3);
        assert_eq!(report.layer_opened_leaves.len(), 2);
        assert_eq!(report.layer_frontier_nodes.len(), 2);
        assert_eq!(report.serialized_bytes(), encoded.len());
        assert_eq!(
            MixedBasefoldPcsSizeReport::formula_bytes(
                2,
                2,
                2,
                3,
                &report.layer_opened_leaves,
                &report.layer_frontier_nodes,
            ),
            Ok(encoded.len()),
        );
        let proved = fixture().0;
        let observations =
            raw_opening_observations_for_queries(2, 2, 2, &proved.query_indices).unwrap();
        assert_eq!(observations.len(), report.b128_symbols);
        assert!(observations.iter().all(|row| row.has_bound_index_tape));
        assert_eq!(REQUIRED_FULL_E384_DUMMY_MULTIPLICATION_ROWS, 2);
    }

    #[test]
    fn relation_claim_context_profile_and_root_order_reject() {
        let (proved, encoded, _) = fixture();
        let mut wrong_claim = proved.relation_claim.clone();
        wrong_claim.initial_root[0] ^= 1;
        assert_eq!(
            verify_mixed_basefold_pcs_exact(&encoded, &wrong_claim, CONTEXT),
            Err(MixedBasefoldPcsError::RelationClaimMismatch)
        );
        assert_eq!(
            verify_mixed_basefold_pcs_exact(&encoded, &proved.relation_claim, b"wrong domain"),
            Err(MixedBasefoldPcsError::ContextMismatch)
        );
        let mut profile = encoded.clone();
        profile[22] ^= 1;
        assert_eq!(
            MixedBasefoldPcsProof::decode_exact(&profile),
            Err(MixedBasefoldPcsError::ProfileMismatch)
        );
        let mut root_order = encoded;
        swap_ranges(&mut root_order, 160, 224, 64);
        assert!(
            verify_mixed_basefold_pcs_exact(&root_order, &proved.relation_claim, CONTEXT,).is_err()
        );
    }

    #[test]
    fn coefficient_lane_group_and_tape_mutations_reject() {
        let (proved, encoded, report) = fixture();
        // header + 3 roots + 4 terminal leaves * (2 E384 values + tape)
        let initial_opening = 160 + 3 * 64 + 4 * (2 * 48 + 64);
        let wide_opening = initial_opening
            + report.layer_opened_leaves[0] * (2 * 16 + 64)
            + report.layer_frontier_nodes[0] * 64;
        let mut coefficient = encoded.clone();
        coefficient[wide_opening] ^= 1;
        assert!(matches!(
            verify_mixed_basefold_pcs_exact(&coefficient, &proved.relation_claim, CONTEXT),
            Err(MixedBasefoldPcsError::OpeningAuthentication { .. })
        ));
        let mut lane_order = encoded.clone();
        swap_ranges(&mut lane_order, wide_opening, wide_opening + 16, 16);
        assert!(
            verify_mixed_basefold_pcs_exact(&lane_order, &proved.relation_claim, CONTEXT,).is_err()
        );
        let mut group_order = encoded.clone();
        swap_ranges(&mut group_order, wide_opening, wide_opening + 48, 48);
        assert!(
            verify_mixed_basefold_pcs_exact(&group_order, &proved.relation_claim, CONTEXT,)
                .is_err()
        );
        let mut tape = encoded;
        tape[wide_opening + 2 * 48] ^= 1;
        assert!(matches!(
            verify_mixed_basefold_pcs_exact(&tape, &proved.relation_claim, CONTEXT),
            Err(MixedBasefoldPcsError::OpeningAuthentication { .. })
        ));
    }

    #[test]
    fn exact_parser_rejects_lane_order_truncation_and_suffix() {
        let (_, encoded, _) = fixture();
        let mut lane_count = encoded.clone();
        lane_count[14] = 2;
        assert_eq!(
            MixedBasefoldPcsProof::decode_exact(&lane_count),
            Err(MixedBasefoldPcsError::InvalidLaneCount { actual: 2 })
        );
        assert_eq!(
            MixedBasefoldPcsProof::decode_exact(&encoded[..encoded.len() - 1]),
            Err(MixedBasefoldPcsError::ProofTruncated)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            MixedBasefoldPcsProof::decode_exact(&trailing),
            Err(MixedBasefoldPcsError::ProofTrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn low_degree_terminal_check_rejects_reauthenticated_nonconstant_codeword() {
        let (proved, _, _) = fixture();
        let mut proof = proved.proof;
        proof.terminal_leaves[1].values[0] += E384::ONE;
        let terminal_layer = proof.log_dimension();
        proof.layer_roots[terminal_layer] =
            terminal_root(terminal_layer, &proof.terminal_leaves).unwrap();
        assert!(matches!(
            verify_mixed_basefold_pcs(&proof, &proved.relation_claim, CONTEXT),
            Err(MixedBasefoldPcsError::TerminalNotConstant { .. })
        ));
    }

    #[test]
    fn queries_are_canonical_distinct_and_miss_product_is_exact() {
        let (proved, _, _) = fixture();
        let mut sorted = proved.query_indices.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), proved.query_indices.len());
        let bound = distinct_query_soundness(8, 2, 3).unwrap();
        assert_eq!(bound.numerators, vec![6, 5, 4]);
        assert_eq!(bound.denominators, vec![8, 7, 6]);
    }

    #[test]
    fn retained_m4_mixed_depth_projection_is_exact_and_over_cap() {
        let report = project_retained_m4_mixed_depth(STRICT_SCREEN_QUERY_COUNT).unwrap();
        assert_eq!(report.tree_depths, [13, 18, 20, 11, 16, 12, 9]);
        assert_eq!(report.opened_leaves, [315, 319, 319, 296, 318, 310, 233]);
        assert_eq!(
            report.frontier_nodes,
            [1224, 2807, 3445, 637, 2171, 919, 197]
        );
        assert_eq!(report.e384_lower_bound_bytes, 1_548_704);
        assert_eq!(report.e512_mixed_lower_bound_bytes, 1_763_232);
        assert_eq!(report.e512_stock_scalar_lower_bound_bytes, 1_883_136);
        assert!(report.e384_lower_bound_bytes > CONSENSUS_PROOF_CAP_BYTES);
    }
}
