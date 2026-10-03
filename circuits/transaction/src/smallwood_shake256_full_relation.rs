//! Exact SHAKE256/SHAKE512 Boolean constraints for the prospective full SmallWood relation.
//!
//! This module is deliberately disconnected from production dispatch.  It provides the
//! conventional-hash primitive and byte-to-field binding needed by the full two-input,
//! two-output relation without treating a host-computed digest as proof authority.  Every
//! message bit is a Boolean witness, SHAKE domain/padding bits are constrained constants, and
//! every Keccak-f[1600] round is represented by polynomial identities over Goldilocks.
//!
//! The optimized round relation uses a degree-five five-input parity identity for theta and a
//! degree-three fused chi identity
//!
//! `out = a XOR ((NOT b) AND c)`.
//!
//! Both fit below SmallWood's active degree-eight ceiling.  Rho and pi are wire permutations.
//! Iota is an affine NOT on the round-constant bits.  The canonical 893-byte statement and its
//! lossless 56-bit Goldilocks projection are owned by [`crate::full_shake448_statement`]; this
//! module consumes that authority and never performs modular reduction.
//! A rejected architecture screen also instantiated a rate-72/capacity-1024 sponge with the
//! SHAKE suffix.  FIPS 202 defines no such `SHAKE512`, so that private helper and `HGF6HR02` cannot
//! be conventional-hash authority.  Production-facing code must not consume it.
//!
//! This is not yet the complete transaction compiler: non-hash balance, stablecoin, Merkle,
//! activity-mask, and five-mode authorization constraints must be joined to these hash traces
//! before the candidate can authorize proofs.  [`ensure_full_relation_production_authorized`]
//! therefore always fails closed.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use crate::full_shake448_statement::{
    encode_v6_ciphertext_hash_frame, encode_v6_semantic_frame, encode_v6_statement,
    project_v6_statement, FullShake448Statement, FullShake448StatementError, SignedMagnitude,
    StablecoinStatementBinding, V6ActivationBinding, V6HashAlgorithm, V6HashPurpose,
    V6HashRoleSpec, V6StatementProjection, GOLDILOCKS_MODULUS, ROLE_ACCUMULATOR, ROLE_AUTH_MUX,
    ROLE_BALANCE_TAG, ROLE_CIPHERTEXT_HASH, ROLE_INTENT, ROLE_MERKLE_NODE, ROLE_NOTE_COMMITMENT,
    ROLE_NULLIFIER, ROLE_POLICY, ROLE_SPEND_KEYS, ROLE_VALUE_LOCK, V6_ACTION_ID, V6_BACKEND_ID,
    V6_CIRCUIT_VERSION, V6_CRYPTO_SUITE, V6_DOMAIN_SET, V6_FAMILY_ID,
    V6_FULL_RELATION_KECCAK_PERMUTATIONS, V6_FULL_RELATION_SHAKE_INVOCATIONS,
    V6_HASH_ROLE_REGISTRY, V6_HASH_ROLE_REGISTRY_MAGIC, V6_PROFILE_TAG, V6_PROOF_PROFILE,
    V6_PUBLIC_VALUES, V6_STATEMENT_BYTES, V6_STATEMENT_GRAMMAR_VERSION, V6_STATEMENT_LIMBS,
    V6_STATEMENT_LIMB_BYTES, V6_STATEMENT_MAGIC,
};

/// SHAKE256's byte absorption and squeeze rate.
pub const SHAKE256_RATE_BYTES: usize = 136;
/// Rejected nonstandard rate-72 XOF geometry.  FIPS 202 defines no SHAKE512 algorithm.
const SHAKE512_RATE_BYTES: usize = 72;
/// Keccak-f[1600] state width.
pub const KECCAK_STATE_BITS: usize = 1_600;
/// Number of lanes in Keccak-f[1600].
pub const KECCAK_LANES: usize = 25;
/// Width of each Keccak lane.
pub const KECCAK_LANE_BITS: usize = 64;
/// Number of Keccak-f[1600] rounds.
pub const KECCAK_ROUNDS: usize = 24;
/// SHAKE256 domain-separation suffix from FIPS 202.
pub const SHAKE_DOMAIN_SUFFIX: u8 = 0x1f;
/// Relation digest width selected for composed PQ/QROM margin.
pub const SHAKE256_448_OUTPUT_BYTES: usize = 56;
/// Rejected nonstandard rate-72 screen output width.
const SHAKE512_448_OUTPUT_BYTES: usize = 56;
/// Rejected nonstandard rate-72 screen's paired output width.
const SHAKE512_896_OUTPUT_BYTES: usize = 112;
/// Active SmallWood Boolean packing factor.
pub const SMALLWOOD_BOOLEAN_PACKING_FACTOR: usize = 64;

/// The retained M4 circuit constrains this many Keccak calls while externalizing two hashes.
pub const LEGACY_M4_PRIVATE_SHAKE_INVOCATIONS: usize = 75;
/// Stable alias consumed by source-bound security accounting.
pub const LEGACY_M4_SHAKE256_INVOCATIONS: usize = LEGACY_M4_PRIVATE_SHAKE_INVOCATIONS;
/// The retained M4 circuit constrains this many permutations for those 75 invocations.
pub const LEGACY_M4_CONSTRAINED_KECCAK_PERMUTATIONS: usize = 83;
/// Exact `intent.1` payload length after omitting anchor and two nullifiers from 893 bytes.
pub const INTENT_STATEMENT_PAYLOAD_BYTES: usize = 725;
/// Exact framed length: 17-byte semantic header, one 2-byte length, and 725-byte payload.
pub const INTENT_FRAME_BYTES: usize = 744;
/// `intent.1` needs six absorption permutations.
pub const INTENT_KECCAK_PERMUTATIONS: usize = 6;
/// Exact `bal.tag1` framed length for its eight fixed fields.
pub const BALANCE_TAG_FRAME_BYTES: usize = 100;
/// `bal.tag1` needs one absorption permutation.
pub const BALANCE_TAG_KECCAK_PERMUTATIONS: usize = 1;
/// Exact active `ct.hash1` frame: header plus five length-delimited fields and 2,147 bytes.
pub const CIPHERTEXT_HASH_FRAME_BYTES: usize = 2_182;
/// One fixed-shape ciphertext trace needs seventeen absorption permutations.
pub const CIPHERTEXT_HASH_KECCAK_PERMUTATIONS: usize = 17;
/// Two fixed-shape ciphertext traces are present for every activity mask.
pub const CIPHERTEXT_HASH_INVOCATIONS: usize = 2;
/// Pre-ciphertext base after moving intent and balance inside the relation.
pub const PRE_CIPHERTEXT_BASE_KECCAK_PERMUTATIONS: usize = LEGACY_M4_CONSTRAINED_KECCAK_PERMUTATIONS
    + INTENT_KECCAK_PERMUTATIONS
    + BALANCE_TAG_KECCAK_PERMUTATIONS;
/// Pre-ciphertext base: 75 private-dependent hashes plus intent and balance.
pub const PRE_CIPHERTEXT_BASE_SHAKE_INVOCATIONS: usize = LEGACY_M4_PRIVATE_SHAKE_INVOCATIONS + 2;
/// Qualifying fixed-shape schedule with both ciphertext hashes constrained in proof.
pub const FULL_RELATION_AUTHORITY_KECCAK_PERMUTATIONS: usize =
    PRE_CIPHERTEXT_BASE_KECCAK_PERMUTATIONS
        + CIPHERTEXT_HASH_INVOCATIONS * CIPHERTEXT_HASH_KECCAK_PERMUTATIONS;
/// Exact complete schedule: the 77-call base plus two ciphertext hashes.
pub const FULL_RELATION_AUTHORITY_SHAKE_INVOCATIONS: usize =
    PRE_CIPHERTEXT_BASE_SHAKE_INVOCATIONS + CIPHERTEXT_HASH_INVOCATIONS;
/// Stable alias consumed by source-bound security accounting.
pub const FULL_RELATION_SHAKE256_INVOCATIONS: usize = FULL_RELATION_AUTHORITY_SHAKE_INVOCATIONS;

/// Rejected uniform-SHAKE256 degree-five/fused-chi source projection for 124 Keccak cores.
/// This excludes absorption, iota affine operations, output bindings, non-hash constraints, and
/// LPPC lowering.  It is not a measured or production row count; emitted QIR is authoritative.
pub const TOURNAMENT_PARITY5_FUSED_CHI_CORE_ROW_PROJECTION: usize =
    1_440 * FULL_RELATION_AUTHORITY_KECCAK_PERMUTATIONS;

/// Successor mixed-algorithm projection for the registry-authoritative 145 Keccak cores.
/// This is a static core projection, not emitted-QIR authority or a proof-size measurement.
const MIXED_V2_PARITY5_FUSED_CHI_CORE_ROW_PROJECTION: usize =
    1_440 * V6_FULL_RELATION_KECCAK_PERMUTATIONS;

/// One fixed hash family in the qualifying full relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullRelationHashGeometry {
    pub name: &'static str,
    pub invocations: usize,
    pub maximum_frame_bytes: usize,
    pub output_bytes: usize,
    pub permutations_per_invocation: usize,
}

/// Rejected profile-2 uniform-SHAKE256 79-invocation/124-permutation snapshot.  It must never be
/// interpreted as the fresh profile-3/domain-set-2 successor schedule in `V6_HASH_ROLE_REGISTRY`.
pub const FULL_RELATION_HASH_GEOMETRY: [FullRelationHashGeometry; 9] = [
    FullRelationHashGeometry {
        name: "note.cm3",
        invocations: 4,
        maximum_frame_bytes: 232,
        output_bytes: 56,
        permutations_per_invocation: 2,
    },
    FullRelationHashGeometry {
        name: "nullif.2",
        invocations: 2,
        maximum_frame_bytes: 135,
        output_bytes: 56,
        permutations_per_invocation: 1,
    },
    FullRelationHashGeometry {
        name: "merk.nd2",
        invocations: 64,
        maximum_frame_bytes: 133,
        output_bytes: 56,
        permutations_per_invocation: 1,
    },
    FullRelationHashGeometry {
        name: "sp.keys2",
        invocations: 2,
        maximum_frame_bytes: 77,
        output_bytes: 112,
        permutations_per_invocation: 1,
    },
    FullRelationHashGeometry {
        name: "policy.1",
        invocations: 1,
        maximum_frame_bytes: 385,
        output_bytes: 56,
        permutations_per_invocation: 3,
    },
    FullRelationHashGeometry {
        name: "authorization_mux",
        invocations: 2,
        maximum_frame_bytes: 181,
        output_bytes: 112,
        permutations_per_invocation: 2,
    },
    FullRelationHashGeometry {
        name: "intent.1",
        invocations: 1,
        maximum_frame_bytes: INTENT_FRAME_BYTES,
        output_bytes: 56,
        permutations_per_invocation: INTENT_KECCAK_PERMUTATIONS,
    },
    FullRelationHashGeometry {
        name: "bal.tag1",
        invocations: 1,
        maximum_frame_bytes: BALANCE_TAG_FRAME_BYTES,
        output_bytes: 56,
        permutations_per_invocation: BALANCE_TAG_KECCAK_PERMUTATIONS,
    },
    FullRelationHashGeometry {
        name: "ct.hash1",
        invocations: CIPHERTEXT_HASH_INVOCATIONS,
        maximum_frame_bytes: CIPHERTEXT_HASH_FRAME_BYTES,
        output_bytes: 56,
        permutations_per_invocation: CIPHERTEXT_HASH_KECCAK_PERMUTATIONS,
    },
];

pub const AUTHORIZATION_MODE_COUNT: usize = 5;
pub const AUTHORIZATION_ABSORB_BLOCKS: usize = 2;
pub const AUTHORIZATION_PADDED_BYTES: usize = AUTHORIZATION_ABSORB_BLOCKS * SHAKE256_RATE_BYTES;
pub const AUTHORIZATION_DUMMY_FRAME_BYTES: usize = SHAKE256_RATE_BYTES;
pub const AUTHORIZATION_ACCUMULATOR_FRAME_BYTES: usize = 181;
pub const AUTHORIZATION_VALUE_LOCK_FRAME_BYTES: usize = 143;

/// Fresh profile-3 SHAKE512 authorization geometry.  A 144-byte zero dummy receives a third
/// FIPS-202 absorption block; the 181-byte accumulator does likewise.  The 143-byte value-lock
/// arm finishes after two absorption blocks, so the common third permutation is its first
/// squeeze.  A fourth common permutation supplies the accumulator/dummy second squeeze.
const SHAKE512_AUTHORIZATION_ABSORB_OR_SQUEEZE_PERMUTATIONS: usize = 4;
const SHAKE512_AUTHORIZATION_MAX_ABSORB_BLOCKS: usize = 3;
const SHAKE512_AUTHORIZATION_PADDED_BYTES: usize =
    SHAKE512_AUTHORIZATION_MAX_ABSORB_BLOCKS * SHAKE512_RATE_BYTES;
const SHAKE512_AUTHORIZATION_DUMMY_FRAME_BYTES: usize = 2 * SHAKE512_RATE_BYTES;

/// Fixed authorization pipeline.  Mode order is Single, Init, Approval, Lock, Final.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FixedAuthorizationMuxSlot {
    A,
    B,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixedAuthorizationArmKind {
    Dummy,
    Accumulator,
    ValueLock,
}

impl FixedAuthorizationMuxSlot {
    const fn arm_kinds(self) -> [FixedAuthorizationArmKind; AUTHORIZATION_MODE_COUNT] {
        match self {
            Self::A => [
                FixedAuthorizationArmKind::Dummy,
                FixedAuthorizationArmKind::Accumulator,
                FixedAuthorizationArmKind::Accumulator,
                FixedAuthorizationArmKind::ValueLock,
                FixedAuthorizationArmKind::Accumulator,
            ],
            Self::B => [
                FixedAuthorizationArmKind::Dummy,
                FixedAuthorizationArmKind::Dummy,
                FixedAuthorizationArmKind::Accumulator,
                FixedAuthorizationArmKind::Dummy,
                FixedAuthorizationArmKind::ValueLock,
            ],
        }
    }
}

const KECCAK_RHO_OFFSETS: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

const KECCAK_ROUND_CONSTANTS: [u64; KECCAK_ROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Index of one scalar bit witness in a SHAKE constraint trace.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Shake256Wire(usize);

impl Shake256Wire {
    /// Construct a wire for an existing aggregate witness slot.
    pub const fn from_index(index: usize) -> Self {
        Self(index)
    }

    /// Zero-based index into [`Shake256ConstraintTrace::witness_values`].
    pub const fn index(self) -> usize {
        self.0
    }

    fn rebased(self, offset: usize) -> Result<Self, Shake256RelationError> {
        self.0
            .checked_add(offset)
            .map(Self)
            .ok_or(Shake256RelationError::WireIndexOverflow)
    }
}

/// Stable family for one Goldilocks polynomial constraint.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Shake256ConstraintKind {
    Constant,
    Boolean,
    PublicBoolean,
    Equality,
    GatedEquality,
    OneHot5,
    OneHotMux5,
    Xor,
    Not,
    Parity5,
    FusedChi,
}

/// Exact Boolean identities used by the SHAKE relation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Shake256Constraint {
    /// `output - value = 0`.
    Constant { output: Shake256Wire, value: bool },
    /// `wire * (wire - 1) = 0`.
    Boolean { wire: Shake256Wire },
    /// Public-input form of `wire * (wire - 1) = 0`.
    PublicBoolean { wire: Shake256Wire },
    /// `left - right = 0`.
    Equality {
        left: Shake256Wire,
        right: Shake256Wire,
    },
    /// `selector * (left - right) = 0`; the selector must have its own Boolean constraint.
    GatedEquality {
        selector: Shake256Wire,
        left: Shake256Wire,
        right: Shake256Wire,
    },
    /// Five Boolean mode selectors sum to exactly one.
    OneHot5 { selectors: [Shake256Wire; 5] },
    /// `output = sum(selectors[i] * inputs[i])` under [`Self::OneHot5`].
    OneHotMux5 {
        selectors: [Shake256Wire; 5],
        inputs: [Shake256Wire; 5],
        output: Shake256Wire,
    },
    /// `output - (left + right - 2*left*right) = 0`.
    Xor {
        left: Shake256Wire,
        right: Shake256Wire,
        output: Shake256Wire,
    },
    /// `output + input - 1 = 0`.
    Not {
        input: Shake256Wire,
        output: Shake256Wire,
    },
    /// Exact five-bit parity.  Its multilinear expansion has degree five.
    Parity5 {
        inputs: [Shake256Wire; 5],
        output: Shake256Wire,
    },
    /// `output = a XOR ((NOT b) AND c)`, with a degree-three expansion.
    FusedChi {
        a: Shake256Wire,
        b: Shake256Wire,
        c: Shake256Wire,
        output: Shake256Wire,
    },
}

impl Shake256Constraint {
    pub const fn kind(self) -> Shake256ConstraintKind {
        match self {
            Self::Constant { .. } => Shake256ConstraintKind::Constant,
            Self::Boolean { .. } => Shake256ConstraintKind::Boolean,
            Self::PublicBoolean { .. } => Shake256ConstraintKind::PublicBoolean,
            Self::Equality { .. } => Shake256ConstraintKind::Equality,
            Self::GatedEquality { .. } => Shake256ConstraintKind::GatedEquality,
            Self::OneHot5 { .. } => Shake256ConstraintKind::OneHot5,
            Self::OneHotMux5 { .. } => Shake256ConstraintKind::OneHotMux5,
            Self::Xor { .. } => Shake256ConstraintKind::Xor,
            Self::Not { .. } => Shake256ConstraintKind::Not,
            Self::Parity5 { .. } => Shake256ConstraintKind::Parity5,
            Self::FusedChi { .. } => Shake256ConstraintKind::FusedChi,
        }
    }

    /// Total degree after expansion over Goldilocks.
    pub const fn degree(self) -> usize {
        match self {
            Self::Constant { .. }
            | Self::Equality { .. }
            | Self::OneHot5 { .. }
            | Self::Not { .. } => 1,
            Self::Boolean { .. }
            | Self::PublicBoolean { .. }
            | Self::GatedEquality { .. }
            | Self::OneHotMux5 { .. }
            | Self::Xor { .. } => 2,
            Self::FusedChi { .. } => 3,
            Self::Parity5 { .. } => 5,
        }
    }

    /// Evaluate the represented polynomial identity in Goldilocks.
    pub fn residual(self, witness: &[u64]) -> Result<u64, Shake256RelationError> {
        let value = |wire: Shake256Wire| {
            witness
                .get(wire.index())
                .copied()
                .ok_or(Shake256RelationError::WireOutOfBounds {
                    wire: wire.index(),
                    witness_len: witness.len(),
                })
        };
        match self {
            Self::Constant { output, value: bit } => Ok(field_sub(value(output)?, u64::from(bit))),
            Self::Boolean { wire } => {
                let bit = value(wire)?;
                Ok(field_mul(bit, field_sub(bit, 1)))
            }
            Self::PublicBoolean { wire } => {
                let bit = value(wire)?;
                Ok(field_mul(bit, field_sub(bit, 1)))
            }
            Self::Equality { left, right } => Ok(field_sub(value(left)?, value(right)?)),
            Self::GatedEquality {
                selector,
                left,
                right,
            } => Ok(field_mul(
                value(selector)?,
                field_sub(value(left)?, value(right)?),
            )),
            Self::OneHot5 { selectors } => {
                let sum = selectors.into_iter().try_fold(0, |sum, selector| {
                    value(selector).map(|selector| field_add(sum, selector))
                })?;
                Ok(field_sub(sum, 1))
            }
            Self::OneHotMux5 {
                selectors,
                inputs,
                output,
            } => {
                let mut selected = 0;
                for (selector, input) in selectors.into_iter().zip(inputs) {
                    selected = field_add(selected, field_mul(value(selector)?, value(input)?));
                }
                Ok(field_sub(value(output)?, selected))
            }
            Self::Xor {
                left,
                right,
                output,
            } => Ok(field_sub(
                value(output)?,
                field_xor(value(left)?, value(right)?),
            )),
            Self::Not { input, output } => {
                Ok(field_sub(field_add(value(output)?, value(input)?), 1))
            }
            Self::Parity5 { inputs, output } => {
                let mut parity = 0;
                for input in inputs {
                    parity = field_xor(parity, value(input)?);
                }
                Ok(field_sub(value(output)?, parity))
            }
            Self::FusedChi { a, b, c, output } => {
                let a = value(a)?;
                let b = value(b)?;
                let c = value(c)?;
                // a XOR ((1-b)c) = a + c - bc - 2ac + 2abc.
                let bc = field_mul(b, c);
                let ac = field_mul(a, c);
                let abc = field_mul(ac, b);
                let expected = field_add(
                    field_sub(field_sub(field_add(a, c), bc), field_mul_small(ac, 2)),
                    field_mul_small(abc, 2),
                );
                Ok(field_sub(value(output)?, expected))
            }
        }
    }

    /// Shift every local wire index into a shared aggregate witness.
    pub fn rebased(self, offset: usize) -> Result<Self, Shake256RelationError> {
        let wire = |value: Shake256Wire| value.rebased(offset);
        Ok(match self {
            Self::Constant { output, value } => Self::Constant {
                output: wire(output)?,
                value,
            },
            Self::Boolean { wire: input } => Self::Boolean { wire: wire(input)? },
            Self::PublicBoolean { wire: input } => Self::PublicBoolean { wire: wire(input)? },
            Self::Equality { left, right } => Self::Equality {
                left: wire(left)?,
                right: wire(right)?,
            },
            Self::GatedEquality {
                selector,
                left,
                right,
            } => Self::GatedEquality {
                selector: wire(selector)?,
                left: wire(left)?,
                right: wire(right)?,
            },
            Self::OneHot5 { selectors } => {
                let [a, b, c, d, e] = selectors;
                Self::OneHot5 {
                    selectors: [wire(a)?, wire(b)?, wire(c)?, wire(d)?, wire(e)?],
                }
            }
            Self::OneHotMux5 {
                selectors,
                inputs,
                output,
            } => {
                let [sa, sb, sc, sd, se] = selectors;
                let [a, b, c, d, e] = inputs;
                Self::OneHotMux5 {
                    selectors: [wire(sa)?, wire(sb)?, wire(sc)?, wire(sd)?, wire(se)?],
                    inputs: [wire(a)?, wire(b)?, wire(c)?, wire(d)?, wire(e)?],
                    output: wire(output)?,
                }
            }
            Self::Xor {
                left,
                right,
                output,
            } => Self::Xor {
                left: wire(left)?,
                right: wire(right)?,
                output: wire(output)?,
            },
            Self::Not { input, output } => Self::Not {
                input: wire(input)?,
                output: wire(output)?,
            },
            Self::Parity5 { inputs, output } => {
                let [a, b, c, d, e] = inputs;
                Self::Parity5 {
                    inputs: [wire(a)?, wire(b)?, wire(c)?, wire(d)?, wire(e)?],
                    output: wire(output)?,
                }
            }
            Self::FusedChi { a, b, c, output } => Self::FusedChi {
                a: wire(a)?,
                b: wire(b)?,
                c: wire(c)?,
                output: wire(output)?,
            },
        })
    }
}

/// Whether a constrained Keccak permutation follows absorption or advances the XOF squeeze.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum KeccakPermutationPhase {
    Absorb,
    /// One-hot authorization multiplexing makes this an absorption for the 181/144-byte arms and
    /// a squeeze for the 143-byte value-lock arm.  The output mux selects the matching state.
    AbsorbOrSqueezeMux,
    Squeeze,
}

/// Input/output boundary for one constrained Keccak permutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeccakPermutationBoundary {
    pub permutation_index: usize,
    pub phase: KeccakPermutationPhase,
    /// State immediately before the twenty-four rounds.  For absorption this is after the exact
    /// padded block was XORed into the rate lanes.  For squeezing it is the prior output state.
    pub absorbed_state_bit_wires: Vec<Shake256Wire>,
    /// State after all twenty-four constrained rounds.
    pub output_state_bit_wires: Vec<Shake256Wire>,
}

/// Algorithm and typed-role provenance carried with every executable trace.
///
/// The parent adapter must compare this value to `V6_HASH_ROLE_REGISTRY`; it must never infer an
/// algorithm from a role name, frame length, or permutation count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeccakXofTraceMetadata {
    pub algorithm: V6HashAlgorithm,
    pub role: Option<V6HashRoleSpec>,
    pub rate_bytes: usize,
    pub message_bytes: usize,
    pub output_bytes: usize,
    pub absorption_permutations: usize,
    pub squeeze_permutations: usize,
    pub total_permutations: usize,
}

/// Exact gate inventory for one SHAKE trace.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Shake256GateCounts {
    pub message_bytes: usize,
    pub output_bytes: usize,
    pub permutation_count: usize,
    pub wire_count: usize,
    pub constant_constraints: usize,
    pub input_boolean_constraints: usize,
    pub public_output_boolean_constraints: usize,
    pub included_output_binding_constraints: usize,
    pub gated_equality_constraints: usize,
    pub one_hot_constraints: usize,
    pub one_hot_mux_constraints: usize,
    pub xor_constraints: usize,
    pub not_constraints: usize,
    pub parity5_constraints: usize,
    pub fused_chi_constraints: usize,
    pub scalar_constraint_count: usize,
    pub external_output_binding_constraints: usize,
    pub maximum_degree: usize,
}

/// Deterministic flat-packing projection for SmallWood.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Shake256RowAccounting {
    pub packing_factor: usize,
    pub scalar_witness_values: usize,
    pub witness_rows: usize,
    pub witness_padding_values: usize,
    pub scalar_constraints: usize,
    pub constraint_rows: usize,
    pub constraint_padding_values: usize,
    pub external_output_binding_constraints: usize,
    pub external_output_binding_rows: usize,
}

/// Global-wire view returned after one SHAKE trace is appended to a shared constraint system.
/// The parent compiler must equality-bind `message_bit_wires` to its frame wires and bind
/// `digest_bit_wires` either to downstream internal wires or canonical public-statement wires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shake256TraceEmbedding {
    pub wire_offset: usize,
    pub wire_count: usize,
    pub message_len: usize,
    pub output_bytes: usize,
    pub metadata: KeccakXofTraceMetadata,
    pub message_bit_wires: Vec<Shake256Wire>,
    pub padding_bit_wires: Vec<Shake256Wire>,
    pub digest_bit_wires: Vec<Shake256Wire>,
    pub public_digest_bit_wires: Vec<Shake256Wire>,
    pub permutations: Vec<KeccakPermutationBoundary>,
    message_source_binding_count: usize,
    digest_target_binding_count: usize,
}

/// Private aliases retained only for the rejected rate-72 architecture screen.
type RejectedRate72ConstraintTrace = Shake256ConstraintTrace;

/// Auditable source/target coverage for one rebased trace.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Shake256TraceBindingCoverage {
    pub expected_message_source_bits: usize,
    pub bound_message_source_bits: usize,
    pub expected_digest_target_bits: usize,
    pub bound_digest_target_bits: usize,
}

/// Fixed two-block authorization mux trace before aggregate rebasing.
#[derive(Clone)]
pub struct FixedAuthorizationMuxTrace {
    slot: FixedAuthorizationMuxSlot,
    inner: Shake256ConstraintTrace,
    selector_wires: [Shake256Wire; AUTHORIZATION_MODE_COUNT],
    /// Only non-dummy raw-frame bits require typed upstream sources.  FIPS padding and dummy
    /// absorption bits are constant-constrained inside `inner`.
    arm_source_bit_wires: [Vec<Shake256Wire>; AUTHORIZATION_MODE_COUNT],
    selected_absorption_bit_wires: Vec<Shake256Wire>,
}

/// Global-wire view of one fixed authorization mux.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedAuthorizationMuxEmbedding {
    pub slot: FixedAuthorizationMuxSlot,
    pub inner: Shake256TraceEmbedding,
    pub selector_wires: [Shake256Wire; AUTHORIZATION_MODE_COUNT],
    pub arm_source_bit_wires: [Vec<Shake256Wire>; AUTHORIZATION_MODE_COUNT],
    pub selected_absorption_bit_wires: Vec<Shake256Wire>,
    selector_source_binding_count: usize,
    arm_source_binding_counts: [usize; AUTHORIZATION_MODE_COUNT],
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixedAuthorizationMuxBindingCoverage {
    pub expected_selector_source_bits: usize,
    pub bound_selector_source_bits: usize,
    pub expected_arm_source_bits: usize,
    pub bound_arm_source_bits: usize,
    pub hash_boundary: Shake256TraceBindingCoverage,
}

impl FixedAuthorizationMuxBindingCoverage {
    pub const fn is_complete(self) -> bool {
        self.expected_selector_source_bits == self.bound_selector_source_bits
            && self.expected_arm_source_bits == self.bound_arm_source_bits
            && self.hash_boundary.is_complete()
    }
}

impl Shake256TraceBindingCoverage {
    pub const fn is_complete(self) -> bool {
        self.expected_message_source_bits == self.bound_message_source_bits
            && self.expected_digest_target_bits == self.bound_digest_target_bits
    }
}

impl Shake256TraceEmbedding {
    /// Require exact algorithm/rate/output/permutation provenance for one registry entry.
    pub fn ensure_typed_role(&self, expected: V6HashRoleSpec) -> Result<(), Shake256RelationError> {
        let metadata = self.metadata;
        if metadata.role != Some(expected)
            || metadata.algorithm != expected.algorithm
            || metadata.rate_bytes != expected.rate_bytes as usize
            || metadata.message_bytes != expected.max_frame_bytes as usize
            || metadata.output_bytes != expected.output_bytes as usize
            || metadata.total_permutations != expected.permutations_per_call as usize
        {
            return Err(Shake256RelationError::HashRoleGeometry {
                role: expected.role,
            });
        }
        Ok(())
    }

    /// Equality-bind every SHAKE message bit to a typed source bit in the aggregate relation.
    /// Constants such as profile, role, field count, lengths, padding bytes, and inactive
    /// ciphertext bytes must be represented by constant-constrained aggregate source wires.
    pub fn bind_message_sources(
        &mut self,
        source_wires: &[Shake256Wire],
        aggregate_constraints: &mut Vec<Shake256Constraint>,
    ) -> Result<usize, Shake256RelationError> {
        if source_wires.len() != self.message_bit_wires.len() {
            return Err(Shake256RelationError::TraceBindingLength {
                boundary: "message-source",
                expected: self.message_bit_wires.len(),
                actual: source_wires.len(),
            });
        }
        if self.message_source_binding_count != 0 {
            return Err(Shake256RelationError::TraceBoundaryAlreadyBound(
                "message-source",
            ));
        }
        for (message, source) in self
            .message_bit_wires
            .iter()
            .copied()
            .zip(source_wires.iter().copied())
        {
            aggregate_constraints.push(Shake256Constraint::Equality {
                left: message,
                right: source,
            });
        }
        self.message_source_binding_count = source_wires.len();
        Ok(source_wires.len())
    }

    /// Equality-bind every digest bit to internal or public target wires.
    pub fn bind_digest_targets(
        &mut self,
        target_wires: &[Shake256Wire],
        aggregate_constraints: &mut Vec<Shake256Constraint>,
    ) -> Result<usize, Shake256RelationError> {
        self.bind_digest_targets_inner(target_wires, None, aggregate_constraints)
    }

    /// Selector-gated equality-bind every digest bit.  This supports fixed-shape inactive
    /// ciphertext traces: the caller must separately Boolean-constrain `selector`, require the
    /// public digest to be zero when it is false, and constrain every inactive ciphertext byte
    /// source to zero.
    pub fn bind_digest_targets_gated(
        &mut self,
        selector: Shake256Wire,
        target_wires: &[Shake256Wire],
        aggregate_constraints: &mut Vec<Shake256Constraint>,
    ) -> Result<usize, Shake256RelationError> {
        self.bind_digest_targets_inner(target_wires, Some(selector), aggregate_constraints)
    }

    fn bind_digest_targets_inner(
        &mut self,
        target_wires: &[Shake256Wire],
        selector: Option<Shake256Wire>,
        aggregate_constraints: &mut Vec<Shake256Constraint>,
    ) -> Result<usize, Shake256RelationError> {
        if target_wires.len() != self.digest_bit_wires.len() {
            return Err(Shake256RelationError::TraceBindingLength {
                boundary: "digest-target",
                expected: self.digest_bit_wires.len(),
                actual: target_wires.len(),
            });
        }
        if self.digest_target_binding_count != 0 {
            return Err(Shake256RelationError::TraceBoundaryAlreadyBound(
                "digest-target",
            ));
        }
        for (digest, target) in self
            .digest_bit_wires
            .iter()
            .copied()
            .zip(target_wires.iter().copied())
        {
            aggregate_constraints.push(match selector {
                Some(selector) => Shake256Constraint::GatedEquality {
                    selector,
                    left: digest,
                    right: target,
                },
                None => Shake256Constraint::Equality {
                    left: digest,
                    right: target,
                },
            });
        }
        self.digest_target_binding_count = target_wires.len();
        Ok(target_wires.len())
    }

    pub const fn binding_coverage(&self) -> Shake256TraceBindingCoverage {
        Shake256TraceBindingCoverage {
            expected_message_source_bits: self.message_bit_wires.len(),
            bound_message_source_bits: self.message_source_binding_count,
            expected_digest_target_bits: self.digest_bit_wires.len(),
            bound_digest_target_bits: self.digest_target_binding_count,
        }
    }

    /// Fail closed unless every message and digest bit has an aggregate-relation binding.
    pub fn ensure_fully_bound(&self) -> Result<(), Shake256RelationError> {
        let coverage = self.binding_coverage();
        if coverage.bound_message_source_bits != coverage.expected_message_source_bits {
            return Err(Shake256RelationError::IncompleteTraceBinding {
                boundary: "message-source",
                expected: coverage.expected_message_source_bits,
                actual: coverage.bound_message_source_bits,
            });
        }
        if coverage.bound_digest_target_bits != coverage.expected_digest_target_bits {
            return Err(Shake256RelationError::IncompleteTraceBinding {
                boundary: "digest-target",
                expected: coverage.expected_digest_target_bits,
                actual: coverage.bound_digest_target_bits,
            });
        }
        Ok(())
    }
}

impl FixedAuthorizationMuxEmbedding {
    /// Bind the five local one-hot selectors to the parent relation's five mode bits.
    pub fn bind_selector_sources(
        &mut self,
        source_wires: &[Shake256Wire],
        aggregate_constraints: &mut Vec<Shake256Constraint>,
    ) -> Result<usize, Shake256RelationError> {
        if source_wires.len() != AUTHORIZATION_MODE_COUNT {
            return Err(Shake256RelationError::TraceBindingLength {
                boundary: "authorization-selector-source",
                expected: AUTHORIZATION_MODE_COUNT,
                actual: source_wires.len(),
            });
        }
        if self.selector_source_binding_count != 0 {
            return Err(Shake256RelationError::TraceBoundaryAlreadyBound(
                "authorization-selector-source",
            ));
        }
        for (selector, source) in self
            .selector_wires
            .iter()
            .copied()
            .zip(source_wires.iter().copied())
        {
            aggregate_constraints.push(Shake256Constraint::Equality {
                left: selector,
                right: source,
            });
        }
        self.selector_source_binding_count = AUTHORIZATION_MODE_COUNT;
        Ok(AUTHORIZATION_MODE_COUNT)
    }

    /// Bind every non-dummy raw-frame bit in one mode arm to typed parent wires.  Dummy bytes and
    /// all FIPS-202 padding bits are constants inside the fixed trace and require no source list.
    pub fn bind_arm_sources(
        &mut self,
        mode: usize,
        source_wires: &[Shake256Wire],
        aggregate_constraints: &mut Vec<Shake256Constraint>,
    ) -> Result<usize, Shake256RelationError> {
        let expected = self
            .arm_source_bit_wires
            .get(mode)
            .ok_or(Shake256RelationError::AuthorizationArmIndex(mode))?;
        if source_wires.len() != expected.len() {
            return Err(Shake256RelationError::TraceBindingLength {
                boundary: "authorization-arm-source",
                expected: expected.len(),
                actual: source_wires.len(),
            });
        }
        if expected.is_empty() {
            return Ok(0);
        }
        if self.arm_source_binding_counts[mode] != 0 {
            return Err(Shake256RelationError::TraceBoundaryAlreadyBound(
                "authorization-arm-source",
            ));
        }
        for (frame, source) in expected.iter().copied().zip(source_wires.iter().copied()) {
            aggregate_constraints.push(Shake256Constraint::Equality {
                left: frame,
                right: source,
            });
        }
        self.arm_source_binding_counts[mode] = expected.len();
        Ok(expected.len())
    }

    pub fn bind_digest_targets(
        &mut self,
        target_wires: &[Shake256Wire],
        aggregate_constraints: &mut Vec<Shake256Constraint>,
    ) -> Result<usize, Shake256RelationError> {
        self.inner
            .bind_digest_targets(target_wires, aggregate_constraints)
    }

    pub const fn binding_coverage(&self) -> FixedAuthorizationMuxBindingCoverage {
        let mut expected_arm_source_bits = 0;
        let mut bound_arm_source_bits = 0;
        let mut mode = 0;
        while mode < AUTHORIZATION_MODE_COUNT {
            expected_arm_source_bits += self.arm_source_bit_wires[mode].len();
            bound_arm_source_bits += self.arm_source_binding_counts[mode];
            mode += 1;
        }
        FixedAuthorizationMuxBindingCoverage {
            expected_selector_source_bits: AUTHORIZATION_MODE_COUNT,
            bound_selector_source_bits: self.selector_source_binding_count,
            expected_arm_source_bits,
            bound_arm_source_bits,
            hash_boundary: self.inner.binding_coverage(),
        }
    }

    pub fn ensure_fully_bound(&self) -> Result<(), Shake256RelationError> {
        let coverage = self.binding_coverage();
        if coverage.bound_selector_source_bits != coverage.expected_selector_source_bits {
            return Err(Shake256RelationError::IncompleteTraceBinding {
                boundary: "authorization-selector-source",
                expected: coverage.expected_selector_source_bits,
                actual: coverage.bound_selector_source_bits,
            });
        }
        if coverage.bound_arm_source_bits != coverage.expected_arm_source_bits {
            return Err(Shake256RelationError::IncompleteTraceBinding {
                boundary: "authorization-arm-source",
                expected: coverage.expected_arm_source_bits,
                actual: coverage.bound_arm_source_bits,
            });
        }
        self.inner.ensure_fully_bound()
    }
}

/// Failure while constructing or verifying the SHAKE/full-relation adapter.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Shake256RelationError {
    #[error("SHAKE256 relation output must be in 1..=136 bytes, got {0}")]
    InvalidOutputLength(usize),
    #[error("SHAKE512 relation output must be in 1..=144 bytes, got {0}")]
    InvalidShake512OutputLength(usize),
    #[error("SHAKE256 message length overflow")]
    MessageLengthOverflow,
    #[error("SHAKE256 aggregate wire index overflow")]
    WireIndexOverflow,
    #[error(
        "fixed authorization {slot:?} mode {mode} frame must have {expected} bytes, got {actual}"
    )]
    AuthorizationFrameLength {
        slot: FixedAuthorizationMuxSlot,
        mode: usize,
        expected: usize,
        actual: usize,
    },
    #[error("fixed authorization {slot:?} mode {mode} frame has a noncanonical domain/layout")]
    AuthorizationFrameDomain {
        slot: FixedAuthorizationMuxSlot,
        mode: usize,
    },
    #[error("fixed authorization {slot:?} mode {mode} dummy frame is not 136 zero bytes")]
    AuthorizationDummyNonZero {
        slot: FixedAuthorizationMuxSlot,
        mode: usize,
    },
    #[error("typed V6 hash role {role:?} requires a {expected}-byte frame, got {actual}")]
    HashRoleFrameLength {
        role: [u8; 8],
        expected: usize,
        actual: usize,
    },
    #[error("typed V6 hash role {role:?} has an inconsistent registry geometry")]
    HashRoleGeometry { role: [u8; 8] },
    #[error("typed V6 hash role {0:?} is not present in HGF6HR02")]
    HashRoleUnregistered([u8; 8]),
    #[error("fixed authorization arm {0} is outside the five-mode relation")]
    AuthorizationArmIndex(usize),
    #[error("SmallWood packing factor must be non-zero")]
    ZeroPackingFactor,
    #[error("SHAKE256 wire {wire} is outside witness length {witness_len}")]
    WireOutOfBounds { wire: usize, witness_len: usize },
    #[error("SHAKE256 witness value at wire {wire} is not a canonical Goldilocks element")]
    NonCanonicalWitness { wire: usize },
    #[error("SHAKE256 constraint {constraint} ({kind:?}) failed with residual {residual}")]
    ConstraintViolation {
        constraint: usize,
        kind: Shake256ConstraintKind,
        residual: u64,
    },
    #[error("SHAKE256 digest does not equal the bound digest")]
    DigestMismatch,
    #[error("SHAKE256 public digest binding must have {expected} bytes, got {actual}")]
    DigestBindingLength { expected: usize, actual: usize },
    #[error("SHAKE256 {boundary} binding requires {expected} bits, got {actual}")]
    TraceBindingLength {
        boundary: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("SHAKE256 {0} boundary is already fully bound")]
    TraceBoundaryAlreadyBound(&'static str),
    #[error("SHAKE256 {boundary} boundary has only {actual} of {expected} required bit bindings")]
    IncompleteTraceBinding {
        boundary: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("the complete SHAKE/full-relation compiler is not production-authorized")]
    ProductionAuthorizationUnavailable,
}

/// Verify an aggregate witness against SHAKE and inter-trace equality constraints.
pub fn verify_constraint_system(
    witness: &[u64],
    constraints: &[Shake256Constraint],
) -> Result<(), Shake256RelationError> {
    for (wire, value) in witness.iter().copied().enumerate() {
        if value >= GOLDILOCKS_MODULUS {
            return Err(Shake256RelationError::NonCanonicalWitness { wire });
        }
    }
    for (index, constraint) in constraints.iter().copied().enumerate() {
        let residual = constraint.residual(witness)?;
        if residual != 0 {
            return Err(Shake256RelationError::ConstraintViolation {
                constraint: index,
                kind: constraint.kind(),
                residual,
            });
        }
    }
    Ok(())
}

/// Fully materialized SHAKE256-448 Boolean trace.
#[derive(Clone)]
pub struct Shake256ConstraintTrace {
    metadata: KeccakXofTraceMetadata,
    message_len: usize,
    output_bytes: usize,
    witness: Vec<u64>,
    constraints: Vec<Shake256Constraint>,
    message_bit_wires: Vec<Shake256Wire>,
    padding_bit_wires: Vec<Shake256Wire>,
    digest_bit_wires: Vec<Shake256Wire>,
    public_digest_bit_wires: Vec<Shake256Wire>,
    permutations: Vec<KeccakPermutationBoundary>,
}

impl Shake256ConstraintTrace {
    pub const fn metadata(&self) -> KeccakXofTraceMetadata {
        self.metadata
    }

    pub const fn algorithm(&self) -> V6HashAlgorithm {
        self.metadata.algorithm
    }

    pub const fn role_spec(&self) -> Option<V6HashRoleSpec> {
        self.metadata.role
    }

    pub const fn absorption_permutations(&self) -> usize {
        self.metadata.absorption_permutations
    }

    pub const fn squeeze_permutations(&self) -> usize {
        self.metadata.squeeze_permutations
    }

    pub fn ensure_typed_role(&self, expected: V6HashRoleSpec) -> Result<(), Shake256RelationError> {
        let metadata = self.metadata;
        if metadata.role != Some(expected)
            || metadata.algorithm != expected.algorithm
            || metadata.rate_bytes != expected.rate_bytes as usize
            || metadata.message_bytes != expected.max_frame_bytes as usize
            || metadata.output_bytes != expected.output_bytes as usize
            || metadata.total_permutations != expected.permutations_per_call as usize
        {
            return Err(Shake256RelationError::HashRoleGeometry {
                role: expected.role,
            });
        }
        Ok(())
    }

    pub const fn message_len(&self) -> usize {
        self.message_len
    }

    pub const fn output_bytes(&self) -> usize {
        self.output_bytes
    }

    pub fn witness_values(&self) -> &[u64] {
        &self.witness
    }

    pub fn constraints(&self) -> &[Shake256Constraint] {
        &self.constraints
    }

    /// Message wires in byte order, least-significant bit first per byte.
    pub fn message_bit_wires(&self) -> &[Shake256Wire] {
        &self.message_bit_wires
    }

    /// SHAKE suffix, zero-fill, and final pad-bit wires in absorption order.
    pub fn padding_bit_wires(&self) -> &[Shake256Wire] {
        &self.padding_bit_wires
    }

    /// Output wires in byte order, least-significant bit first per byte.
    pub fn digest_bit_wires(&self) -> &[Shake256Wire] {
        &self.digest_bit_wires
    }

    /// Public input wires added by [`Self::bind_public_digest`].  An empty slice means the parent
    /// relation still owes all output equality constraints.
    pub fn public_digest_bit_wires(&self) -> &[Shake256Wire] {
        &self.public_digest_bit_wires
    }

    pub fn permutations(&self) -> &[KeccakPermutationBoundary] {
        &self.permutations
    }

    /// Append this trace into one aggregate witness/constraint system and rebase every wire.
    /// This is the composition seam used to add polynomial equalities between SHAKE inputs,
    /// outputs, canonical statement bits, and the non-hash transaction relation.
    pub fn append_to(
        self,
        aggregate_witness: &mut Vec<u64>,
        aggregate_constraints: &mut Vec<Shake256Constraint>,
    ) -> Result<Shake256TraceEmbedding, Shake256RelationError> {
        let Shake256ConstraintTrace {
            metadata,
            message_len,
            output_bytes,
            witness,
            constraints,
            message_bit_wires,
            padding_bit_wires,
            digest_bit_wires,
            public_digest_bit_wires,
            permutations,
        } = self;
        let wire_offset = aggregate_witness.len();
        let wire_count = witness.len();
        wire_offset
            .checked_add(wire_count)
            .ok_or(Shake256RelationError::WireIndexOverflow)?;
        let rebase_wires = |wires: Vec<Shake256Wire>| {
            wires
                .into_iter()
                .map(|wire| wire.rebased(wire_offset))
                .collect::<Result<Vec<_>, Shake256RelationError>>()
        };
        let constraints = constraints
            .into_iter()
            .map(|constraint| constraint.rebased(wire_offset))
            .collect::<Result<Vec<_>, Shake256RelationError>>()?;
        let message_bit_wires = rebase_wires(message_bit_wires)?;
        let padding_bit_wires = rebase_wires(padding_bit_wires)?;
        let digest_bit_wires = rebase_wires(digest_bit_wires)?;
        let public_digest_bit_wires = rebase_wires(public_digest_bit_wires)?;
        let digest_target_binding_count = public_digest_bit_wires.len();
        let permutations = permutations
            .into_iter()
            .map(|boundary| {
                Ok(KeccakPermutationBoundary {
                    permutation_index: boundary.permutation_index,
                    phase: boundary.phase,
                    absorbed_state_bit_wires: rebase_wires(boundary.absorbed_state_bit_wires)?,
                    output_state_bit_wires: rebase_wires(boundary.output_state_bit_wires)?,
                })
            })
            .collect::<Result<Vec<_>, Shake256RelationError>>()?;

        aggregate_witness.extend(witness);
        aggregate_constraints.extend(constraints);
        Ok(Shake256TraceEmbedding {
            wire_offset,
            wire_count,
            message_len,
            output_bytes,
            metadata,
            message_bit_wires,
            padding_bit_wires,
            digest_bit_wires,
            public_digest_bit_wires,
            permutations,
            message_source_binding_count: 0,
            digest_target_binding_count,
        })
    }

    pub fn digest(&self) -> Vec<u8> {
        (0..self.output_bytes)
            .map(|byte| {
                let mut value = 0u8;
                for bit in 0..8 {
                    let wire = self.digest_bit_wires[byte * 8 + bit];
                    value |= (self.witness[wire.index()] as u8) << bit;
                }
                value
            })
            .collect()
    }

    pub fn verify_constraints(&self) -> Result<(), Shake256RelationError> {
        verify_constraint_system(&self.witness, &self.constraints)
    }

    /// Host equality here is a test helper.  Production lowering must add all `output_bytes * 8`
    /// explicit equality constraints reported by [`Self::gate_counts`].
    pub fn verify_digest(&self, expected: &[u8]) -> Result<(), Shake256RelationError> {
        self.verify_constraints()?;
        if self.digest().as_slice() != expected {
            return Err(Shake256RelationError::DigestMismatch);
        }
        Ok(())
    }

    /// Add explicit Boolean public-input wires and equality-bind every output bit to them.
    /// SmallWood lowering must place these returned wires in the public statement, not a private
    /// witness column.  This method makes the polynomial binding concrete and testable; it does
    /// not itself choose the parent relation's public/private column layout.
    pub fn bind_public_digest(mut self, expected: &[u8]) -> Result<Self, Shake256RelationError> {
        if expected.len() != self.output_bytes {
            return Err(Shake256RelationError::DigestBindingLength {
                expected: self.output_bytes,
                actual: expected.len(),
            });
        }
        if !self.public_digest_bit_wires.is_empty() {
            for (bit_index, wire) in self.public_digest_bit_wires.iter().copied().enumerate() {
                let expected_bit = u64::from((expected[bit_index / 8] >> (bit_index % 8)) & 1);
                if self.witness[wire.index()] != expected_bit {
                    return Err(Shake256RelationError::DigestMismatch);
                }
            }
            return Ok(self);
        }
        self.public_digest_bit_wires.reserve(self.output_bytes * 8);
        for (bit_index, digest_wire) in self.digest_bit_wires.iter().copied().enumerate() {
            let value = (expected[bit_index / 8] >> (bit_index % 8)) & 1;
            let public_wire = Shake256Wire(self.witness.len());
            self.witness.push(u64::from(value));
            self.constraints
                .push(Shake256Constraint::PublicBoolean { wire: public_wire });
            self.constraints.push(Shake256Constraint::Equality {
                left: digest_wire,
                right: public_wire,
            });
            self.public_digest_bit_wires.push(public_wire);
        }
        Ok(self)
    }

    pub fn gate_counts(&self) -> Shake256GateCounts {
        let mut constant_constraints = 0;
        let mut input_boolean_constraints = 0;
        let mut public_output_boolean_constraints = 0;
        let mut included_output_binding_constraints = 0;
        let mut gated_equality_constraints = 0;
        let mut one_hot_constraints = 0;
        let mut one_hot_mux_constraints = 0;
        let mut xor_constraints = 0;
        let mut not_constraints = 0;
        let mut parity5_constraints = 0;
        let mut fused_chi_constraints = 0;
        for constraint in &self.constraints {
            match constraint {
                Shake256Constraint::Constant { .. } => constant_constraints += 1,
                Shake256Constraint::Boolean { .. } => input_boolean_constraints += 1,
                Shake256Constraint::PublicBoolean { .. } => public_output_boolean_constraints += 1,
                Shake256Constraint::Equality { .. } => included_output_binding_constraints += 1,
                Shake256Constraint::GatedEquality { .. } => gated_equality_constraints += 1,
                Shake256Constraint::OneHot5 { .. } => one_hot_constraints += 1,
                Shake256Constraint::OneHotMux5 { .. } => one_hot_mux_constraints += 1,
                Shake256Constraint::Xor { .. } => xor_constraints += 1,
                Shake256Constraint::Not { .. } => not_constraints += 1,
                Shake256Constraint::Parity5 { .. } => parity5_constraints += 1,
                Shake256Constraint::FusedChi { .. } => fused_chi_constraints += 1,
            }
        }
        Shake256GateCounts {
            message_bytes: self.message_len,
            output_bytes: self.output_bytes,
            permutation_count: self.permutations.len(),
            wire_count: self.witness.len(),
            constant_constraints,
            input_boolean_constraints,
            public_output_boolean_constraints,
            included_output_binding_constraints,
            gated_equality_constraints,
            one_hot_constraints,
            one_hot_mux_constraints,
            xor_constraints,
            not_constraints,
            parity5_constraints,
            fused_chi_constraints,
            scalar_constraint_count: self.constraints.len(),
            external_output_binding_constraints: if self.public_digest_bit_wires.is_empty() {
                self.output_bytes * 8
            } else {
                0
            },
            maximum_degree: self
                .constraints
                .iter()
                .copied()
                .map(Shake256Constraint::degree)
                .max()
                .unwrap_or(0),
        }
    }

    pub fn row_accounting(
        &self,
        packing_factor: usize,
    ) -> Result<Shake256RowAccounting, Shake256RelationError> {
        if packing_factor == 0 {
            return Err(Shake256RelationError::ZeroPackingFactor);
        }
        let witness_rows = self.witness.len().div_ceil(packing_factor);
        let constraint_rows = self.constraints.len().div_ceil(packing_factor);
        let output_bindings = if self.public_digest_bit_wires.is_empty() {
            self.output_bytes * 8
        } else {
            0
        };
        let output_binding_rows = output_bindings.div_ceil(packing_factor);
        Ok(Shake256RowAccounting {
            packing_factor,
            scalar_witness_values: self.witness.len(),
            witness_rows,
            witness_padding_values: witness_rows * packing_factor - self.witness.len(),
            scalar_constraints: self.constraints.len(),
            constraint_rows,
            constraint_padding_values: constraint_rows * packing_factor - self.constraints.len(),
            external_output_binding_constraints: output_bindings,
            external_output_binding_rows: output_binding_rows,
        })
    }

    pub fn smallwood_row_accounting(&self) -> Shake256RowAccounting {
        self.row_accounting(SMALLWOOD_BOOLEAN_PACKING_FACTOR)
            .expect("the SmallWood Boolean packing factor is non-zero")
    }
}

impl FixedAuthorizationMuxTrace {
    pub const fn slot(&self) -> FixedAuthorizationMuxSlot {
        self.slot
    }

    pub fn selector_wires(&self) -> &[Shake256Wire; AUTHORIZATION_MODE_COUNT] {
        &self.selector_wires
    }

    pub fn arm_source_bit_wires(&self) -> &[Vec<Shake256Wire>; AUTHORIZATION_MODE_COUNT] {
        &self.arm_source_bit_wires
    }

    pub fn selected_absorption_bit_wires(&self) -> &[Shake256Wire] {
        &self.selected_absorption_bit_wires
    }

    pub fn digest(&self) -> Vec<u8> {
        self.inner.digest()
    }

    pub fn verify_constraints(&self) -> Result<(), Shake256RelationError> {
        self.inner.verify_constraints()
    }

    pub fn gate_counts(&self) -> Shake256GateCounts {
        self.inner.gate_counts()
    }

    pub fn permutations(&self) -> &[KeccakPermutationBoundary] {
        self.inner.permutations()
    }

    pub fn append_to(
        self,
        aggregate_witness: &mut Vec<u64>,
        aggregate_constraints: &mut Vec<Shake256Constraint>,
    ) -> Result<FixedAuthorizationMuxEmbedding, Shake256RelationError> {
        let Self {
            slot,
            inner,
            selector_wires,
            arm_source_bit_wires,
            selected_absorption_bit_wires,
        } = self;
        let inner = inner.append_to(aggregate_witness, aggregate_constraints)?;
        let offset = inner.wire_offset;
        let selector_wires = [
            selector_wires[0].rebased(offset)?,
            selector_wires[1].rebased(offset)?,
            selector_wires[2].rebased(offset)?,
            selector_wires[3].rebased(offset)?,
            selector_wires[4].rebased(offset)?,
        ];
        let mut rebased_arms = Vec::with_capacity(AUTHORIZATION_MODE_COUNT);
        for wires in arm_source_bit_wires {
            rebased_arms.push(
                wires
                    .into_iter()
                    .map(|wire| wire.rebased(offset))
                    .collect::<Result<Vec<_>, Shake256RelationError>>()?,
            );
        }
        let arm_source_bit_wires = rebased_arms
            .try_into()
            .map_err(|_| Shake256RelationError::AuthorizationArmIndex(AUTHORIZATION_MODE_COUNT))?;
        let selected_absorption_bit_wires = selected_absorption_bit_wires
            .into_iter()
            .map(|wire| wire.rebased(offset))
            .collect::<Result<Vec<_>, Shake256RelationError>>()?;
        Ok(FixedAuthorizationMuxEmbedding {
            slot,
            inner,
            selector_wires,
            arm_source_bit_wires,
            selected_absorption_bit_wires,
            selector_source_binding_count: 0,
            arm_source_binding_counts: [0; AUTHORIZATION_MODE_COUNT],
        })
    }
}

/// Build one fixed two-permutation authorization pipeline.  The five raw frame arms are ordered
/// Single/Init/Approval/Lock/Final and are all present regardless of the selected private mode.
/// Dummy arms are exactly 136 zero bytes.  Accumulator/value-lock arms must use the canonical V6
/// semantic frame layout.  FIPS-202 suffix, zero-fill, and final-bit placement are constructed as
/// constrained constants here; callers cannot supply arbitrary padded blocks.
pub fn fixed_authorization_mux_relation(
    slot: FixedAuthorizationMuxSlot,
    mode_selectors: [bool; AUTHORIZATION_MODE_COUNT],
    frames: [&[u8]; AUTHORIZATION_MODE_COUNT],
) -> Result<FixedAuthorizationMuxTrace, Shake256RelationError> {
    let kinds = slot.arm_kinds();
    for mode in 0..AUTHORIZATION_MODE_COUNT {
        validate_fixed_authorization_frame(slot, mode, kinds[mode], frames[mode])?;
    }

    let mut builder = ConstraintBuilder::new();
    let selectors = [
        builder.input_bit(mode_selectors[0]),
        builder.input_bit(mode_selectors[1]),
        builder.input_bit(mode_selectors[2]),
        builder.input_bit(mode_selectors[3]),
        builder.input_bit(mode_selectors[4]),
    ];
    builder.constrain_one_hot5(selectors);
    let selector_wires = selectors.map(|selector| selector.wire);

    let mut arm_blocks = Vec::with_capacity(AUTHORIZATION_MODE_COUNT);
    let mut arm_sources = Vec::with_capacity(AUTHORIZATION_MODE_COUNT);
    let mut padding_bit_wires = Vec::new();
    for mode in 0..AUTHORIZATION_MODE_COUNT {
        let (block, sources) = fixed_authorization_padded_arm(
            &mut builder,
            kinds[mode],
            frames[mode],
            &mut padding_bit_wires,
        );
        arm_blocks.push(block);
        arm_sources.push(sources);
    }
    let arm_blocks: [Vec<Bit>; AUTHORIZATION_MODE_COUNT] = arm_blocks
        .try_into()
        .map_err(|_| Shake256RelationError::AuthorizationArmIndex(AUTHORIZATION_MODE_COUNT))?;
    let arm_source_bit_wires = arm_sources
        .try_into()
        .map_err(|_| Shake256RelationError::AuthorizationArmIndex(AUTHORIZATION_MODE_COUNT))?;

    let mut selected = Vec::with_capacity(AUTHORIZATION_PADDED_BYTES * 8);
    for bit in 0..AUTHORIZATION_PADDED_BYTES * 8 {
        selected.push(builder.one_hot_mux5(
            selectors,
            [
                arm_blocks[0][bit],
                arm_blocks[1][bit],
                arm_blocks[2][bit],
                arm_blocks[3][bit],
                arm_blocks[4][bit],
            ],
        ));
    }
    let selected_absorption_bit_wires = selected.iter().map(|bit| bit.wire).collect();

    let mut state = [builder.zero(); KECCAK_STATE_BITS];
    let mut permutations = Vec::with_capacity(AUTHORIZATION_ABSORB_BLOCKS);
    for block in 0..AUTHORIZATION_ABSORB_BLOCKS {
        for bit in 0..SHAKE256_RATE_BYTES * 8 {
            state[bit] = builder.xor(state[bit], selected[block * SHAKE256_RATE_BYTES * 8 + bit]);
        }
        let absorbed_state_bit_wires = state.iter().map(|bit| bit.wire).collect();
        state = keccak_f1600(&mut builder, state);
        let output_state_bit_wires = state.iter().map(|bit| bit.wire).collect();
        permutations.push(KeccakPermutationBoundary {
            permutation_index: block,
            phase: KeccakPermutationPhase::Absorb,
            absorbed_state_bit_wires,
            output_state_bit_wires,
        });
    }
    let output_bytes = SHAKE256_448_OUTPUT_BYTES * 2;
    let digest_bit_wires = state[..output_bytes * 8]
        .iter()
        .map(|bit| bit.wire)
        .collect();
    Ok(FixedAuthorizationMuxTrace {
        slot,
        inner: Shake256ConstraintTrace {
            metadata: KeccakXofTraceMetadata {
                algorithm: V6HashAlgorithm::Shake256Output448,
                role: None,
                rate_bytes: SHAKE256_RATE_BYTES,
                message_bytes: 0,
                output_bytes,
                absorption_permutations: AUTHORIZATION_ABSORB_BLOCKS,
                squeeze_permutations: 0,
                total_permutations: AUTHORIZATION_ABSORB_BLOCKS,
            },
            message_len: 0,
            output_bytes,
            witness: builder.witness,
            constraints: builder.constraints,
            message_bit_wires: Vec::new(),
            padding_bit_wires,
            digest_bit_wires,
            public_digest_bit_wires: Vec::new(),
            permutations,
        },
        selector_wires,
        arm_source_bit_wires,
        selected_absorption_bit_wires,
    })
}

/// Build the fresh profile-3 four-permutation SHAKE512 authorization pipeline.
///
/// Mode order is Single/Init/Approval/Lock/Final.  Every arm is present and one-hot selected.
/// Accumulator and canonical 144-byte zero-dummy arms absorb three blocks and squeeze once.
/// Value-lock arms absorb two blocks and squeeze once; the common fourth permutation is retained
/// as an unused second squeeze so every private mode has identical committed geometry.  The 896
/// digest bits are selected from the exact per-arm FIPS phase, preventing a short arm from being
/// silently reinterpreted as a 216-byte zero-extended message.
fn rejected_rate72_authorization_mux_relation(
    slot: FixedAuthorizationMuxSlot,
    mode_selectors: [bool; AUTHORIZATION_MODE_COUNT],
    frames: [&[u8]; AUTHORIZATION_MODE_COUNT],
) -> Result<FixedAuthorizationMuxTrace, Shake256RelationError> {
    let kinds = slot.arm_kinds();
    for mode in 0..AUTHORIZATION_MODE_COUNT {
        validate_fixed_authorization_frame_for_dummy_len(
            slot,
            mode,
            kinds[mode],
            frames[mode],
            SHAKE512_AUTHORIZATION_DUMMY_FRAME_BYTES,
        )?;
    }

    let mut builder = ConstraintBuilder::new();
    let selectors = [
        builder.input_bit(mode_selectors[0]),
        builder.input_bit(mode_selectors[1]),
        builder.input_bit(mode_selectors[2]),
        builder.input_bit(mode_selectors[3]),
        builder.input_bit(mode_selectors[4]),
    ];
    builder.constrain_one_hot5(selectors);
    let selector_wires = selectors.map(|selector| selector.wire);

    let mut arm_blocks = Vec::with_capacity(AUTHORIZATION_MODE_COUNT);
    let mut arm_sources = Vec::with_capacity(AUTHORIZATION_MODE_COUNT);
    let mut arm_absorption_blocks = [0usize; AUTHORIZATION_MODE_COUNT];
    let mut padding_bit_wires = Vec::new();
    for mode in 0..AUTHORIZATION_MODE_COUNT {
        let (block, sources, absorption_blocks) = fixed_authorization_padded_arm_with_rate(
            &mut builder,
            kinds[mode],
            frames[mode],
            SHAKE512_RATE_BYTES,
            SHAKE512_AUTHORIZATION_MAX_ABSORB_BLOCKS,
            &mut padding_bit_wires,
        )?;
        arm_blocks.push(block);
        arm_sources.push(sources);
        arm_absorption_blocks[mode] = absorption_blocks;
    }
    let arm_blocks: [Vec<Bit>; AUTHORIZATION_MODE_COUNT] = arm_blocks
        .try_into()
        .map_err(|_| Shake256RelationError::AuthorizationArmIndex(AUTHORIZATION_MODE_COUNT))?;
    let arm_source_bit_wires = arm_sources
        .try_into()
        .map_err(|_| Shake256RelationError::AuthorizationArmIndex(AUTHORIZATION_MODE_COUNT))?;

    let mut selected = Vec::with_capacity(SHAKE512_AUTHORIZATION_PADDED_BYTES * 8);
    for bit in 0..SHAKE512_AUTHORIZATION_PADDED_BYTES * 8 {
        selected.push(builder.one_hot_mux5(
            selectors,
            [
                arm_blocks[0][bit],
                arm_blocks[1][bit],
                arm_blocks[2][bit],
                arm_blocks[3][bit],
                arm_blocks[4][bit],
            ],
        ));
    }
    let selected_absorption_bit_wires = selected.iter().map(|bit| bit.wire).collect();

    let mut state = [builder.zero(); KECCAK_STATE_BITS];
    let mut states_after =
        Vec::with_capacity(SHAKE512_AUTHORIZATION_ABSORB_OR_SQUEEZE_PERMUTATIONS);
    let mut permutations =
        Vec::with_capacity(SHAKE512_AUTHORIZATION_ABSORB_OR_SQUEEZE_PERMUTATIONS);
    for block in 0..SHAKE512_AUTHORIZATION_MAX_ABSORB_BLOCKS {
        for bit in 0..SHAKE512_RATE_BYTES * 8 {
            state[bit] = builder.xor(state[bit], selected[block * SHAKE512_RATE_BYTES * 8 + bit]);
        }
        let absorbed_state_bit_wires = state.iter().map(|bit| bit.wire).collect();
        state = keccak_f1600(&mut builder, state);
        let output_state_bit_wires = state.iter().map(|bit| bit.wire).collect();
        permutations.push(KeccakPermutationBoundary {
            permutation_index: block,
            phase: if block + 1 == SHAKE512_AUTHORIZATION_MAX_ABSORB_BLOCKS {
                KeccakPermutationPhase::AbsorbOrSqueezeMux
            } else {
                KeccakPermutationPhase::Absorb
            },
            absorbed_state_bit_wires,
            output_state_bit_wires,
        });
        states_after.push(state);
    }

    let absorbed_state_bit_wires = state.iter().map(|bit| bit.wire).collect();
    state = keccak_f1600(&mut builder, state);
    let output_state_bit_wires = state.iter().map(|bit| bit.wire).collect();
    permutations.push(KeccakPermutationBoundary {
        permutation_index: SHAKE512_AUTHORIZATION_MAX_ABSORB_BLOCKS,
        phase: KeccakPermutationPhase::Squeeze,
        absorbed_state_bit_wires,
        output_state_bit_wires,
    });
    states_after.push(state);

    let mut digest_bit_wires = Vec::with_capacity(SHAKE512_896_OUTPUT_BYTES * 8);
    for output_bit in 0..SHAKE512_896_OUTPUT_BYTES * 8 {
        let squeeze_block = output_bit / (SHAKE512_RATE_BYTES * 8);
        let bit_in_block = output_bit % (SHAKE512_RATE_BYTES * 8);
        let inputs = core::array::from_fn(|mode| {
            let state_index = arm_absorption_blocks[mode] - 1 + squeeze_block;
            states_after[state_index][bit_in_block]
        });
        digest_bit_wires.push(builder.one_hot_mux5(selectors, inputs).wire);
    }

    let role = rejected_hgf6hr02_hash_role_spec(ROLE_AUTH_MUX)?;
    if role.algorithm != V6HashAlgorithm::Shake512Output448
        || role.purpose != V6HashPurpose::PrfKdf
        || role.rate_bytes as usize != SHAKE512_RATE_BYTES
        || role.max_frame_bytes as usize != AUTHORIZATION_ACCUMULATOR_FRAME_BYTES
        || role.output_bytes as usize != SHAKE512_896_OUTPUT_BYTES
        || role.permutations_per_call as usize
            != SHAKE512_AUTHORIZATION_ABSORB_OR_SQUEEZE_PERMUTATIONS
    {
        return Err(Shake256RelationError::HashRoleGeometry {
            role: ROLE_AUTH_MUX,
        });
    }

    Ok(FixedAuthorizationMuxTrace {
        slot,
        inner: Shake256ConstraintTrace {
            metadata: KeccakXofTraceMetadata {
                algorithm: V6HashAlgorithm::Shake512Output448,
                role: Some(role),
                rate_bytes: SHAKE512_RATE_BYTES,
                message_bytes: AUTHORIZATION_ACCUMULATOR_FRAME_BYTES,
                output_bytes: SHAKE512_896_OUTPUT_BYTES,
                absorption_permutations: SHAKE512_AUTHORIZATION_MAX_ABSORB_BLOCKS,
                squeeze_permutations: 1,
                total_permutations: SHAKE512_AUTHORIZATION_ABSORB_OR_SQUEEZE_PERMUTATIONS,
            },
            message_len: 0,
            output_bytes: SHAKE512_896_OUTPUT_BYTES,
            witness: builder.witness,
            constraints: builder.constraints,
            message_bit_wires: Vec::new(),
            padding_bit_wires,
            digest_bit_wires,
            public_digest_bit_wires: Vec::new(),
            permutations,
        },
        selector_wires,
        arm_source_bit_wires,
        selected_absorption_bit_wires,
    })
}

fn fixed_authorization_padded_arm_with_rate(
    builder: &mut ConstraintBuilder,
    kind: FixedAuthorizationArmKind,
    frame: &[u8],
    rate_bytes: usize,
    maximum_blocks: usize,
    padding_bit_wires: &mut Vec<Shake256Wire>,
) -> Result<(Vec<Bit>, Vec<Shake256Wire>, usize), Shake256RelationError> {
    let absorption_blocks = frame
        .len()
        .checked_div(rate_bytes)
        .and_then(|blocks| blocks.checked_add(1))
        .ok_or(Shake256RelationError::MessageLengthOverflow)?;
    if absorption_blocks > maximum_blocks {
        return Err(Shake256RelationError::MessageLengthOverflow);
    }
    let maximum_bytes = maximum_blocks
        .checked_mul(rate_bytes)
        .ok_or(Shake256RelationError::MessageLengthOverflow)?;
    let padded_len = absorption_blocks
        .checked_mul(rate_bytes)
        .ok_or(Shake256RelationError::MessageLengthOverflow)?;
    let mut padded = vec![0u8; maximum_bytes];
    padded[..frame.len()].copy_from_slice(frame);
    padded[frame.len()] ^= SHAKE_DOMAIN_SUFFIX;
    padded[padded_len - 1] ^= 0x80;

    let mut block = Vec::with_capacity(maximum_bytes * 8);
    let mut sources = Vec::with_capacity(frame.len() * 8);
    for byte in 0..maximum_bytes {
        for bit in 0..8 {
            let value = (padded[byte] >> bit) & 1 == 1;
            let value = if byte < frame.len() && kind != FixedAuthorizationArmKind::Dummy {
                let input = builder.input_bit(value);
                sources.push(input.wire);
                input
            } else {
                let constant = builder.constant(value);
                // Expose every fixed dummy, FIPS padding, and absent-block bit for mutation KATs.
                padding_bit_wires.push(constant.wire);
                constant
            };
            block.push(value);
        }
    }
    Ok((block, sources, absorption_blocks))
}

fn fixed_authorization_padded_arm(
    builder: &mut ConstraintBuilder,
    kind: FixedAuthorizationArmKind,
    frame: &[u8],
    padding_bit_wires: &mut Vec<Shake256Wire>,
) -> (Vec<Bit>, Vec<Shake256Wire>) {
    let mut padded = [0u8; AUTHORIZATION_PADDED_BYTES];
    padded[..frame.len()].copy_from_slice(frame);
    padded[frame.len()] ^= SHAKE_DOMAIN_SUFFIX;
    padded[AUTHORIZATION_PADDED_BYTES - 1] ^= 0x80;
    let mut block = Vec::with_capacity(AUTHORIZATION_PADDED_BYTES * 8);
    let mut sources = Vec::with_capacity(frame.len() * 8);
    for byte in 0..AUTHORIZATION_PADDED_BYTES {
        for bit in 0..8 {
            let value = (padded[byte] >> bit) & 1 == 1;
            let value = if byte < frame.len() && kind != FixedAuthorizationArmKind::Dummy {
                let input = builder.input_bit(value);
                sources.push(input.wire);
                input
            } else {
                let constant = builder.constant(value);
                if byte >= frame.len() {
                    padding_bit_wires.push(constant.wire);
                }
                constant
            };
            block.push(value);
        }
    }
    (block, sources)
}

fn validate_fixed_authorization_frame(
    slot: FixedAuthorizationMuxSlot,
    mode: usize,
    kind: FixedAuthorizationArmKind,
    frame: &[u8],
) -> Result<(), Shake256RelationError> {
    validate_fixed_authorization_frame_for_dummy_len(
        slot,
        mode,
        kind,
        frame,
        AUTHORIZATION_DUMMY_FRAME_BYTES,
    )
}

fn validate_fixed_authorization_frame_for_dummy_len(
    slot: FixedAuthorizationMuxSlot,
    mode: usize,
    kind: FixedAuthorizationArmKind,
    frame: &[u8],
    dummy_frame_bytes: usize,
) -> Result<(), Shake256RelationError> {
    let expected = match kind {
        FixedAuthorizationArmKind::Dummy => dummy_frame_bytes,
        FixedAuthorizationArmKind::Accumulator => AUTHORIZATION_ACCUMULATOR_FRAME_BYTES,
        FixedAuthorizationArmKind::ValueLock => AUTHORIZATION_VALUE_LOCK_FRAME_BYTES,
    };
    if frame.len() != expected {
        return Err(Shake256RelationError::AuthorizationFrameLength {
            slot,
            mode,
            expected,
            actual: frame.len(),
        });
    }
    match kind {
        FixedAuthorizationArmKind::Dummy if frame.iter().any(|byte| *byte != 0) => {
            Err(Shake256RelationError::AuthorizationDummyNonZero { slot, mode })
        }
        FixedAuthorizationArmKind::Dummy => Ok(()),
        FixedAuthorizationArmKind::Accumulator => {
            if semantic_frame_has_layout(frame, ROLE_ACCUMULATOR, &[8, 56, 56, 8, 8, 8, 6]) {
                Ok(())
            } else {
                Err(Shake256RelationError::AuthorizationFrameDomain { slot, mode })
            }
        }
        FixedAuthorizationArmKind::ValueLock => {
            if semantic_frame_has_layout(frame, ROLE_VALUE_LOCK, &[8, 56, 56]) {
                Ok(())
            } else {
                Err(Shake256RelationError::AuthorizationFrameDomain { slot, mode })
            }
        }
    }
}

fn semantic_frame_has_layout(frame: &[u8], role: [u8; 8], field_lengths: &[usize]) -> bool {
    if frame.len() < 17
        || frame[..8] != V6_PROFILE_TAG
        || frame[8..16] != role
        || frame[16] as usize != field_lengths.len()
    {
        return false;
    }
    let mut cursor = 17;
    for expected in field_lengths {
        let Some(length_bytes) = frame.get(cursor..cursor + 2) else {
            return false;
        };
        if usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]])) != *expected {
            return false;
        }
        cursor += 2;
        let Some(next) = cursor.checked_add(*expected) else {
            return false;
        };
        if next > frame.len() {
            return false;
        }
        cursor = next;
    }
    cursor == frame.len()
}

fn keccak_xof_relation(
    message: &[u8],
    output_bytes: usize,
    algorithm: V6HashAlgorithm,
    role: Option<V6HashRoleSpec>,
) -> Result<Shake256ConstraintTrace, Shake256RelationError> {
    let (rate_bytes, maximum_output_bytes) = match algorithm {
        V6HashAlgorithm::Shake256Output448 => (SHAKE256_RATE_BYTES, SHAKE256_RATE_BYTES),
        V6HashAlgorithm::Shake512Output448 => (SHAKE512_RATE_BYTES, 2 * SHAKE512_RATE_BYTES),
    };
    if !(1..=maximum_output_bytes).contains(&output_bytes) {
        return Err(match algorithm {
            V6HashAlgorithm::Shake256Output448 => {
                Shake256RelationError::InvalidOutputLength(output_bytes)
            }
            V6HashAlgorithm::Shake512Output448 => {
                Shake256RelationError::InvalidShake512OutputLength(output_bytes)
            }
        });
    }
    let padded_blocks = message
        .len()
        .checked_div(rate_bytes)
        .and_then(|blocks| blocks.checked_add(1))
        .ok_or(Shake256RelationError::MessageLengthOverflow)?;
    let padded_len = padded_blocks
        .checked_mul(rate_bytes)
        .ok_or(Shake256RelationError::MessageLengthOverflow)?;
    let message_bits = message
        .len()
        .checked_mul(8)
        .ok_or(Shake256RelationError::MessageLengthOverflow)?;

    let mut builder = ConstraintBuilder::new();
    let mut message_bit_wires = Vec::with_capacity(message_bits);
    let mut message_wires = Vec::with_capacity(message_bits);
    for byte in message {
        for bit in 0..8 {
            let input = builder.input_bit((byte >> bit) & 1 == 1);
            message_bit_wires.push(input.wire);
            message_wires.push(input);
        }
    }

    let mut padded = vec![0u8; padded_len];
    padded[..message.len()].copy_from_slice(message);
    padded[message.len()] ^= SHAKE_DOMAIN_SUFFIX;
    padded[padded_len - 1] ^= 0x80;

    let mut state = [builder.zero(); KECCAK_STATE_BITS];
    let mut padding_bit_wires = Vec::with_capacity((padded_len - message.len()) * 8);
    let squeeze_permutations = output_bytes.saturating_sub(1) / rate_bytes;
    let mut permutations = Vec::with_capacity(padded_blocks + squeeze_permutations);
    for block in 0..padded_blocks {
        for byte in 0..rate_bytes {
            let absolute_byte = block * rate_bytes + byte;
            for bit in 0..8 {
                let absolute_bit = absolute_byte * 8 + bit;
                let absorbed = if absolute_byte < message.len() {
                    message_wires[absolute_bit]
                } else {
                    let padding = builder.constant((padded[absolute_byte] >> bit) & 1 == 1);
                    padding_bit_wires.push(padding.wire);
                    padding
                };
                state[byte * 8 + bit] = builder.xor(state[byte * 8 + bit], absorbed);
            }
        }
        let absorbed_state_bit_wires = state.iter().map(|bit| bit.wire).collect();
        state = keccak_f1600(&mut builder, state);
        let output_state_bit_wires = state.iter().map(|bit| bit.wire).collect();
        permutations.push(KeccakPermutationBoundary {
            permutation_index: block,
            phase: KeccakPermutationPhase::Absorb,
            absorbed_state_bit_wires,
            output_state_bit_wires,
        });
    }

    let mut digest_bit_wires = Vec::with_capacity(output_bytes * 8);
    let mut remaining = output_bytes;
    let mut squeeze_block = 0;
    loop {
        let take = remaining.min(rate_bytes);
        digest_bit_wires.extend(state[..take * 8].iter().map(|bit| bit.wire));
        remaining -= take;
        if remaining == 0 {
            break;
        }
        let absorbed_state_bit_wires = state.iter().map(|bit| bit.wire).collect();
        state = keccak_f1600(&mut builder, state);
        let output_state_bit_wires = state.iter().map(|bit| bit.wire).collect();
        permutations.push(KeccakPermutationBoundary {
            permutation_index: padded_blocks + squeeze_block,
            phase: KeccakPermutationPhase::Squeeze,
            absorbed_state_bit_wires,
            output_state_bit_wires,
        });
        squeeze_block += 1;
    }
    Ok(Shake256ConstraintTrace {
        metadata: KeccakXofTraceMetadata {
            algorithm,
            role,
            rate_bytes,
            message_bytes: message.len(),
            output_bytes,
            absorption_permutations: padded_blocks,
            squeeze_permutations,
            total_permutations: padded_blocks + squeeze_permutations,
        },
        message_len: message.len(),
        output_bytes,
        witness: builder.witness,
        constraints: builder.constraints,
        message_bit_wires,
        padding_bit_wires,
        digest_bit_wires,
        public_digest_bit_wires: Vec::new(),
        permutations,
    })
}

/// Construct exact SHAKE256 constraints.  No native hash is used to populate internal state.
pub fn shake256_relation(
    message: &[u8],
    output_bytes: usize,
) -> Result<Shake256ConstraintTrace, Shake256RelationError> {
    keccak_xof_relation(
        message,
        output_bytes,
        V6HashAlgorithm::Shake256Output448,
        None,
    )
}

/// Construct exact SHAKE512 constraints with the FIPS-202 72-byte rate, `0x1f` suffix, and
/// final `0x80` pad bit.  Outputs longer than 72 bytes are linked to a constrained extra
/// Keccak-f[1600] squeeze permutation.
fn rejected_rate72_xof_relation(
    message: &[u8],
    output_bytes: usize,
) -> Result<RejectedRate72ConstraintTrace, Shake256RelationError> {
    keccak_xof_relation(
        message,
        output_bytes,
        V6HashAlgorithm::Shake512Output448,
        None,
    )
}

/// Construct one exact, typed `HGF6HR02` role trace.  This rejects non-maximum frames so activity
/// masks and witness values cannot change the registry-owned geometry.
fn rejected_hgf6hr02_hash_role_relation(
    spec: V6HashRoleSpec,
    message: &[u8],
) -> Result<Shake256ConstraintTrace, Shake256RelationError> {
    if message.len() != spec.max_frame_bytes as usize {
        return Err(Shake256RelationError::HashRoleFrameLength {
            role: spec.role,
            expected: spec.max_frame_bytes as usize,
            actual: message.len(),
        });
    }
    let mut trace = keccak_xof_relation(
        message,
        spec.output_bytes as usize,
        spec.algorithm,
        Some(spec),
    )?;
    let metadata = trace.metadata();
    if metadata.rate_bytes != spec.rate_bytes as usize
        || metadata.total_permutations != spec.permutations_per_call as usize
    {
        return Err(Shake256RelationError::HashRoleGeometry { role: spec.role });
    }
    trace.metadata.role = Some(spec);
    Ok(trace)
}

fn rejected_hgf6hr02_hash_role_spec(
    role: [u8; 8],
) -> Result<V6HashRoleSpec, Shake256RelationError> {
    V6_HASH_ROLE_REGISTRY
        .iter()
        .copied()
        .find(|spec| spec.role == role)
        .ok_or(Shake256RelationError::HashRoleUnregistered(role))
}

/// Construct the 56-byte semantic-hash relation used by note, nullifier, Merkle, policy,
/// intent, balance, and ciphertext domains.
pub fn shake256_448_relation(
    message: &[u8],
) -> Result<Shake256ConstraintTrace, Shake256RelationError> {
    shake256_relation(message, SHAKE256_448_OUTPUT_BYTES)
}

/// Construct the 112-byte KDF relation split as `auth[0..56] || nullifier[56..112]`.
pub fn shake256_896_relation(
    message: &[u8],
) -> Result<Shake256ConstraintTrace, Shake256RelationError> {
    shake256_relation(message, SHAKE256_448_OUTPUT_BYTES * 2)
}

/// Construct the 56-byte SHAKE512 semantic-hash relation used by secret/preimage roles.
fn rejected_rate72_448_relation(
    message: &[u8],
) -> Result<RejectedRate72ConstraintTrace, Shake256RelationError> {
    rejected_rate72_xof_relation(message, SHAKE512_448_OUTPUT_BYTES)
}

/// Construct the 112-byte SHAKE512 KDF relation.  Bytes 72..112 come from a separately
/// constrained squeeze permutation, not from capacity lanes of the first state.
fn rejected_rate72_896_relation(
    message: &[u8],
) -> Result<RejectedRate72ConstraintTrace, Shake256RelationError> {
    rejected_rate72_xof_relation(message, SHAKE512_896_OUTPUT_BYTES)
}

/// Production activation stays closed until the non-hash relation and every frame binding are
/// compiled into the same committed SmallWood relation and the release/security gates pass.
pub fn ensure_full_relation_production_authorized() -> Result<(), Shake256RelationError> {
    Err(Shake256RelationError::ProductionAuthorizationUnavailable)
}

#[derive(Clone, Copy)]
struct Bit {
    wire: Shake256Wire,
    known: Option<bool>,
}

struct ConstraintBuilder {
    witness: Vec<u64>,
    constraints: Vec<Shake256Constraint>,
    zero: Bit,
    one: Bit,
}

impl ConstraintBuilder {
    fn new() -> Self {
        let placeholder = Bit {
            wire: Shake256Wire(0),
            known: Some(false),
        };
        let mut builder = Self {
            witness: Vec::new(),
            constraints: Vec::new(),
            zero: placeholder,
            one: Bit {
                wire: Shake256Wire(0),
                known: Some(true),
            },
        };
        let zero = builder.allocate(false, Some(false));
        builder.constraints.push(Shake256Constraint::Constant {
            output: zero.wire,
            value: false,
        });
        let one = builder.allocate(true, Some(true));
        builder.constraints.push(Shake256Constraint::Constant {
            output: one.wire,
            value: true,
        });
        builder.zero = zero;
        builder.one = one;
        builder
    }

    const fn zero(&self) -> Bit {
        self.zero
    }

    const fn constant(&self, value: bool) -> Bit {
        if value {
            self.one
        } else {
            self.zero
        }
    }

    fn allocate(&mut self, value: bool, known: Option<bool>) -> Bit {
        let wire = Shake256Wire(self.witness.len());
        self.witness.push(u64::from(value));
        Bit { wire, known }
    }

    fn input_bit(&mut self, value: bool) -> Bit {
        let bit = self.allocate(value, None);
        self.constraints
            .push(Shake256Constraint::Boolean { wire: bit.wire });
        bit
    }

    fn constrain_one_hot5(&mut self, selectors: [Bit; 5]) {
        self.constraints.push(Shake256Constraint::OneHot5 {
            selectors: selectors.map(|selector| selector.wire),
        });
    }

    fn one_hot_mux5(&mut self, selectors: [Bit; 5], inputs: [Bit; 5]) -> Bit {
        let selected = selectors
            .iter()
            .position(|selector| self.value(*selector))
            .map(|index| self.value(inputs[index]))
            .unwrap_or(false);
        let output = self.allocate(selected, None);
        self.constraints.push(Shake256Constraint::OneHotMux5 {
            selectors: selectors.map(|selector| selector.wire),
            inputs: inputs.map(|input| input.wire),
            output: output.wire,
        });
        output
    }

    fn value(&self, bit: Bit) -> bool {
        self.witness[bit.wire.index()] == 1
    }

    fn not(&mut self, input: Bit) -> Bit {
        if let Some(value) = input.known {
            return self.constant(!value);
        }
        let output = self.allocate(!self.value(input), None);
        self.constraints.push(Shake256Constraint::Not {
            input: input.wire,
            output: output.wire,
        });
        output
    }

    fn xor(&mut self, left: Bit, right: Bit) -> Bit {
        if left.wire == right.wire {
            return self.zero;
        }
        match (left.known, right.known) {
            (Some(left), Some(right)) => self.constant(left ^ right),
            (Some(false), None) => right,
            (None, Some(false)) => left,
            (Some(true), None) => self.not(right),
            (None, Some(true)) => self.not(left),
            (None, None) => {
                let output = self.allocate(self.value(left) ^ self.value(right), None);
                self.constraints.push(Shake256Constraint::Xor {
                    left: left.wire,
                    right: right.wire,
                    output: output.wire,
                });
                output
            }
        }
    }

    fn parity5(&mut self, inputs: [Bit; 5]) -> Bit {
        if inputs.iter().all(|input| input.known.is_some()) {
            let value = inputs.iter().fold(false, |parity, input| {
                parity ^ input.known.expect("all inputs were checked")
            });
            return self.constant(value);
        }
        let value = inputs
            .iter()
            .fold(false, |parity, input| parity ^ self.value(*input));
        let output = self.allocate(value, None);
        self.constraints.push(Shake256Constraint::Parity5 {
            inputs: inputs.map(|input| input.wire),
            output: output.wire,
        });
        output
    }

    fn fused_chi(&mut self, a: Bit, b: Bit, c: Bit) -> Bit {
        if let (Some(a), Some(b), Some(c)) = (a.known, b.known, c.known) {
            return self.constant(a ^ ((!b) & c));
        }
        let output = self.allocate(self.value(a) ^ ((!self.value(b)) & self.value(c)), None);
        self.constraints.push(Shake256Constraint::FusedChi {
            a: a.wire,
            b: b.wire,
            c: c.wire,
            output: output.wire,
        });
        output
    }
}

fn keccak_f1600(
    builder: &mut ConstraintBuilder,
    mut state: [Bit; KECCAK_STATE_BITS],
) -> [Bit; KECCAK_STATE_BITS] {
    for round_constant in KECCAK_ROUND_CONSTANTS {
        let mut parity = [[builder.zero(); KECCAK_LANE_BITS]; 5];
        for x in 0..5 {
            for z in 0..KECCAK_LANE_BITS {
                parity[x][z] =
                    builder.parity5(core::array::from_fn(|y| state[state_index(x, y, z)]));
            }
        }
        let mut theta = [builder.zero(); KECCAK_STATE_BITS];
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..KECCAK_LANE_BITS {
                    let rotated = parity[(x + 1) % 5][(z + KECCAK_LANE_BITS - 1) % 64];
                    let delta = builder.xor(parity[(x + 4) % 5][z], rotated);
                    theta[state_index(x, y, z)] = builder.xor(state[state_index(x, y, z)], delta);
                }
            }
        }

        let mut rho_pi = [builder.zero(); KECCAK_STATE_BITS];
        for x in 0..5 {
            for y in 0..5 {
                let target_x = y;
                let target_y = (2 * x + 3 * y) % 5;
                let rotation = KECCAK_RHO_OFFSETS[x][y];
                for z in 0..KECCAK_LANE_BITS {
                    rho_pi[state_index(target_x, target_y, (z + rotation) % 64)] =
                        theta[state_index(x, y, z)];
                }
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                for z in 0..KECCAK_LANE_BITS {
                    state[state_index(x, y, z)] = builder.fused_chi(
                        rho_pi[state_index(x, y, z)],
                        rho_pi[state_index((x + 1) % 5, y, z)],
                        rho_pi[state_index((x + 2) % 5, y, z)],
                    );
                }
            }
        }

        for z in 0..KECCAK_LANE_BITS {
            if (round_constant >> z) & 1 == 1 {
                let index = state_index(0, 0, z);
                state[index] = builder.not(state[index]);
            }
        }
    }
    state
}

const fn state_index(x: usize, y: usize, z: usize) -> usize {
    (x + 5 * y) * KECCAK_LANE_BITS + z
}

fn field_add(left: u64, right: u64) -> u64 {
    let modulus = GOLDILOCKS_MODULUS as u128;
    ((left as u128 + right as u128) % modulus) as u64
}

fn field_sub(left: u64, right: u64) -> u64 {
    let modulus = GOLDILOCKS_MODULUS as u128;
    ((left as u128 + modulus - right as u128) % modulus) as u64
}

fn field_mul(left: u64, right: u64) -> u64 {
    let modulus = GOLDILOCKS_MODULUS as u128;
    ((left as u128 * right as u128) % modulus) as u64
}

fn field_mul_small(value: u64, scalar: u64) -> u64 {
    field_mul(value, scalar)
}

fn field_xor(left: u64, right: u64) -> u64 {
    field_sub(
        field_add(left, right),
        field_mul_small(field_mul(left, right), 2),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const N: usize>(encoded: &str) -> [u8; N] {
        assert_eq!(encoded.len(), N * 2);
        core::array::from_fn(|index| {
            u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).expect("KAT hex is valid")
        })
    }

    fn authorization_frame_fixtures() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let dummy = vec![0; AUTHORIZATION_DUMMY_FRAME_BYTES];
        let key_order = *b"auth.nf1";
        let policy_current = [0x21; 56];
        let intent_current = [0x22; 56];
        let policy_next = [0x31; 56];
        let intent_next = [0x32; 56];
        let threshold = 3u64.to_be_bytes();
        let signer_count = 5u64.to_be_bytes();
        let approval_count = 2u64.to_be_bytes();
        let approved = [1, 0, 1, 0, 0, 0];
        let current = encode_v6_semantic_frame(
            ROLE_ACCUMULATOR,
            [
                key_order.as_slice(),
                policy_current.as_slice(),
                intent_current.as_slice(),
                threshold.as_slice(),
                signer_count.as_slice(),
                approval_count.as_slice(),
                approved.as_slice(),
            ],
        )
        .unwrap();
        let next = encode_v6_semantic_frame(
            ROLE_ACCUMULATOR,
            [
                key_order.as_slice(),
                policy_next.as_slice(),
                intent_next.as_slice(),
                threshold.as_slice(),
                signer_count.as_slice(),
                approval_count.as_slice(),
                approved.as_slice(),
            ],
        )
        .unwrap();
        let value_lock = encode_v6_semantic_frame(
            ROLE_VALUE_LOCK,
            [
                key_order.as_slice(),
                policy_current.as_slice(),
                intent_current.as_slice(),
            ],
        )
        .unwrap();
        assert_eq!(current.len(), AUTHORIZATION_ACCUMULATOR_FRAME_BYTES);
        assert_eq!(next.len(), AUTHORIZATION_ACCUMULATOR_FRAME_BYTES);
        assert_eq!(value_lock.len(), AUTHORIZATION_VALUE_LOCK_FRAME_BYTES);
        (dummy, current, next, value_lock)
    }

    fn canonical_statement_fixture() -> [u8; V6_STATEMENT_BYTES] {
        encode_v6_statement(&FullShake448Statement {
            input_flags: [true, true],
            output_flags: [true, true],
            anchor: [0x11; 56],
            nullifiers: [[0x21; 56], [0x22; 56]],
            commitments: [[0x31; 56], [0x32; 56]],
            ciphertext_hashes: [[0x41; 56], [0x42; 56]],
            ciphertext_sizes: [2_147, 2_147],
            balance_asset_ids: [0, 7, 9, u64::MAX],
            fee: 13,
            value_balance: SignedMagnitude {
                negative: true,
                magnitude: 17,
            },
            stablecoin: StablecoinStatementBinding {
                enabled: true,
                asset_id: 7,
                policy_version: 23,
                issuance_delta: SignedMagnitude {
                    negative: false,
                    magnitude: 29,
                },
                policy_hash: [0x51; 56],
                oracle_commitment: [0x52; 56],
                attestation_commitment: [0x53; 56],
            },
            balance_tag: [0x61; 56],
            activation: V6ActivationBinding {
                circuit_version: V6_CIRCUIT_VERSION,
                crypto_suite: V6_CRYPTO_SUITE,
                family_id: V6_FAMILY_ID,
                action_id: V6_ACTION_ID,
                backend_id: V6_BACKEND_ID,
                proof_profile: V6_PROOF_PROFILE,
                domain_set: V6_DOMAIN_SET,
                network_id: 0x0102_0304,
                chain_id: [0x71; 56],
                genesis_id: [0x72; 56],
                rules_hash: [0x73; 56],
            },
        })
        .unwrap()
    }

    fn duplicate_boolean_sources(
        existing: &[Shake256Wire],
        witness: &mut Vec<u64>,
        constraints: &mut Vec<Shake256Constraint>,
    ) -> Vec<Shake256Wire> {
        let values = existing
            .iter()
            .map(|wire| witness[wire.index()])
            .collect::<Vec<_>>();
        values
            .into_iter()
            .map(|value| {
                let wire = Shake256Wire::from_index(witness.len());
                witness.push(value);
                constraints.push(Shake256Constraint::Boolean { wire });
                wire
            })
            .collect()
    }

    #[test]
    fn fips202_shake256_known_answers_match_at_448_bits() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"",
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab486",
            ),
            (
                b"abc",
                "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4f",
            ),
        ];
        for (message, expected) in cases {
            let trace = shake256_448_relation(message).expect("SHAKE relation builds");
            trace
                .verify_digest(&decode_hex::<SHAKE256_448_OUTPUT_BYTES>(expected))
                .expect("KAT satisfies every constraint");
        }
    }

    #[test]
    fn exact_112_byte_kdf_squeeze_is_constrained_in_the_same_permutation() {
        let expected = decode_hex::<112>(
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e41385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78dbcddbd912993f0913f164fb2ce95131",
        );
        let trace = shake256_896_relation(b"abc").expect("112-byte relation builds");
        assert_eq!(trace.output_bytes(), 112);
        assert_eq!(trace.permutations().len(), 1);
        trace
            .verify_digest(&expected)
            .expect("the full auth/nullifier KDF output is constrained");
        assert_eq!(trace.gate_counts().external_output_binding_constraints, 896);
        assert_eq!(
            trace
                .smallwood_row_accounting()
                .external_output_binding_rows,
            14
        );
        assert_eq!(
            shake256_relation(b"abc", 0).err(),
            Some(Shake256RelationError::InvalidOutputLength(0))
        );
        assert_eq!(
            shake256_relation(b"abc", 137).err(),
            Some(Shake256RelationError::InvalidOutputLength(137))
        );
    }

    #[test]
    fn fixed_authorization_mux_matches_all_five_modes_with_one_geometry() {
        let (dummy, current, next, value_lock) = authorization_frame_fixtures();
        let slot_a = [
            dummy.as_slice(),
            next.as_slice(),
            current.as_slice(),
            value_lock.as_slice(),
            current.as_slice(),
        ];
        let slot_b = [
            dummy.as_slice(),
            dummy.as_slice(),
            next.as_slice(),
            dummy.as_slice(),
            value_lock.as_slice(),
        ];
        let mut geometry_a = None;
        let mut geometry_b = None;
        for mode in 0..AUTHORIZATION_MODE_COUNT {
            let selectors = core::array::from_fn(|index| index == mode);
            let trace_a =
                fixed_authorization_mux_relation(FixedAuthorizationMuxSlot::A, selectors, slot_a)
                    .unwrap();
            let trace_b =
                fixed_authorization_mux_relation(FixedAuthorizationMuxSlot::B, selectors, slot_b)
                    .unwrap();
            trace_a.verify_constraints().unwrap();
            trace_b.verify_constraints().unwrap();
            assert_eq!(trace_a.permutations().len(), AUTHORIZATION_ABSORB_BLOCKS);
            assert_eq!(trace_b.permutations().len(), AUTHORIZATION_ABSORB_BLOCKS);
            assert_eq!(trace_a.gate_counts().one_hot_constraints, 1);
            assert_eq!(trace_b.gate_counts().one_hot_constraints, 1);
            assert_eq!(trace_a.gate_counts().one_hot_mux_constraints, 272 * 8);
            assert_eq!(trace_b.gate_counts().one_hot_mux_constraints, 272 * 8);
            assert_eq!(
                trace_a.digest(),
                shake256_896_relation(slot_a[mode]).unwrap().digest()
            );
            assert_eq!(
                trace_b.digest(),
                shake256_896_relation(slot_b[mode]).unwrap().digest()
            );
            let counts_a = trace_a.gate_counts();
            let counts_b = trace_b.gate_counts();
            if let Some(expected) = geometry_a {
                assert_eq!(counts_a, expected);
            } else {
                geometry_a = Some(counts_a);
            }
            if let Some(expected) = geometry_b {
                assert_eq!(counts_b, expected);
            } else {
                geometry_b = Some(counts_b);
            }
        }
    }

    #[test]
    fn fixed_authorization_mux_rejects_bad_frames_and_mutations() {
        let (dummy, current, next, value_lock) = authorization_frame_fixtures();
        let frames = [
            dummy.as_slice(),
            next.as_slice(),
            current.as_slice(),
            value_lock.as_slice(),
            current.as_slice(),
        ];
        let selectors = [false, false, true, false, false];
        let trace =
            fixed_authorization_mux_relation(FixedAuthorizationMuxSlot::A, selectors, frames)
                .unwrap();
        trace.verify_constraints().unwrap();

        let invalid_one_hot = fixed_authorization_mux_relation(
            FixedAuthorizationMuxSlot::A,
            [true, true, false, false, false],
            frames,
        )
        .unwrap();
        assert!(matches!(
            invalid_one_hot.verify_constraints(),
            Err(Shake256RelationError::ConstraintViolation {
                kind: Shake256ConstraintKind::OneHot5,
                ..
            })
        ));

        let mut selector_mutation = trace.clone();
        let wire = selector_mutation.selector_wires[2];
        selector_mutation.inner.witness[wire.index()] ^= 1;
        assert!(selector_mutation.verify_constraints().is_err());

        let mut mux_mutation = trace.clone();
        let wire = mux_mutation.selected_absorption_bit_wires[0];
        mux_mutation.inner.witness[wire.index()] ^= 1;
        assert!(mux_mutation.verify_constraints().is_err());

        let mut padding_mutation = trace.clone();
        let wire = padding_mutation.inner.padding_bit_wires[0];
        padding_mutation.inner.witness[wire.index()] ^= 1;
        assert!(padding_mutation.verify_constraints().is_err());

        let mut bad_dummy = dummy.clone();
        bad_dummy[0] = 1;
        let bad_dummy_frames = [
            bad_dummy.as_slice(),
            next.as_slice(),
            current.as_slice(),
            value_lock.as_slice(),
            current.as_slice(),
        ];
        assert!(matches!(
            fixed_authorization_mux_relation(
                FixedAuthorizationMuxSlot::A,
                selectors,
                bad_dummy_frames,
            ),
            Err(Shake256RelationError::AuthorizationDummyNonZero { .. })
        ));

        let mut bad_domain = next.clone();
        bad_domain[8] ^= 1;
        let bad_domain_frames = [
            dummy.as_slice(),
            bad_domain.as_slice(),
            current.as_slice(),
            value_lock.as_slice(),
            current.as_slice(),
        ];
        assert!(matches!(
            fixed_authorization_mux_relation(
                FixedAuthorizationMuxSlot::A,
                selectors,
                bad_domain_frames,
            ),
            Err(Shake256RelationError::AuthorizationFrameDomain { .. })
        ));

        let short_frames = [
            dummy.as_slice(),
            &next[..next.len() - 1],
            current.as_slice(),
            value_lock.as_slice(),
            current.as_slice(),
        ];
        assert!(matches!(
            fixed_authorization_mux_relation(FixedAuthorizationMuxSlot::A, selectors, short_frames,),
            Err(Shake256RelationError::AuthorizationFrameLength { .. })
        ));
    }

    #[test]
    fn fixed_authorization_mux_source_coverage_is_fail_closed() {
        let (dummy, current, next, value_lock) = authorization_frame_fixtures();
        let frames = [
            dummy.as_slice(),
            next.as_slice(),
            current.as_slice(),
            value_lock.as_slice(),
            current.as_slice(),
        ];
        let trace = fixed_authorization_mux_relation(
            FixedAuthorizationMuxSlot::A,
            [false, false, false, false, true],
            frames,
        )
        .unwrap();
        let mut witness = Vec::new();
        let mut constraints = Vec::new();
        let mut embedding = trace.append_to(&mut witness, &mut constraints).unwrap();
        assert!(!embedding.binding_coverage().is_complete());
        assert!(matches!(
            embedding.ensure_fully_bound(),
            Err(Shake256RelationError::IncompleteTraceBinding { .. })
        ));

        let selector_sources =
            duplicate_boolean_sources(&embedding.selector_wires, &mut witness, &mut constraints);
        embedding
            .bind_selector_sources(&selector_sources, &mut constraints)
            .unwrap();
        for mode in 0..AUTHORIZATION_MODE_COUNT {
            let arm_wires = embedding.arm_source_bit_wires[mode].clone();
            if arm_wires.is_empty() {
                continue;
            }
            let sources = duplicate_boolean_sources(&arm_wires, &mut witness, &mut constraints);
            embedding
                .bind_arm_sources(mode, &sources, &mut constraints)
                .unwrap();
        }
        let digest_wires = embedding.inner.digest_bit_wires.clone();
        let digest_targets =
            duplicate_boolean_sources(&digest_wires, &mut witness, &mut constraints);
        embedding
            .bind_digest_targets(&digest_targets, &mut constraints)
            .unwrap();
        let coverage = embedding.binding_coverage();
        assert_eq!(coverage.expected_selector_source_bits, 5);
        assert_eq!(coverage.expected_arm_source_bits, (181 * 3 + 143) * 8);
        assert_eq!(coverage.hash_boundary.expected_message_source_bits, 0);
        assert_eq!(coverage.hash_boundary.expected_digest_target_bits, 896);
        assert!(coverage.is_complete());
        embedding.ensure_fully_bound().unwrap();
        verify_constraint_system(&witness, &constraints).unwrap();

        witness[selector_sources[4].index()] ^= 1;
        assert!(verify_constraint_system(&witness, &constraints).is_err());
    }

    #[test]
    fn exact_rate_boundary_padding_and_permutation_counts_hold() {
        for (length, expected) in [(0, 1), (1, 1), (135, 1), (136, 2), (272, 3)] {
            let trace = shake256_448_relation(&vec![0x42; length]).expect("trace builds");
            assert_eq!(trace.permutations().len(), expected);
            assert_eq!(trace.gate_counts().permutation_count, expected);
            trace.verify_constraints().expect("constraints hold");
        }
    }

    #[test]
    fn message_padding_state_and_output_mutations_fail_closed() {
        let trace = shake256_448_relation(b"mutation target").expect("trace builds");
        trace.verify_constraints().expect("honest trace holds");

        let mut message = trace.clone();
        let wire = message.message_bit_wires[0];
        message.witness[wire.index()] ^= 1;
        assert!(message.verify_constraints().is_err());

        let mut padding = trace.clone();
        let wire = padding.padding_bit_wires[0];
        padding.witness[wire.index()] ^= 1;
        assert!(padding.verify_constraints().is_err());

        let mut internal = trace.clone();
        let wire = internal
            .constraints
            .iter()
            .find_map(|constraint| match constraint {
                Shake256Constraint::FusedChi { output, .. } => Some(*output),
                _ => None,
            })
            .expect("a nonconstant chi wire exists");
        internal.witness[wire.index()] ^= 1;
        assert!(internal.verify_constraints().is_err());

        let mut output = trace.clone();
        let wire = output.digest_bit_wires[0];
        output.witness[wire.index()] ^= 1;
        assert!(output.verify_constraints().is_err());

        let mut wrong = trace.digest();
        wrong[0] ^= 1;
        assert_eq!(
            trace.verify_digest(&wrong),
            Err(Shake256RelationError::DigestMismatch)
        );

        let digest = trace.digest();
        let bound = trace
            .clone()
            .bind_public_digest(&digest)
            .expect("public digest binding is well formed");
        bound.verify_constraints().expect("bound trace holds");
        assert_eq!(bound.public_digest_bit_wires().len(), 448);
        assert_eq!(bound.gate_counts().public_output_boolean_constraints, 448);
        assert_eq!(bound.gate_counts().included_output_binding_constraints, 448);
        assert_eq!(bound.gate_counts().external_output_binding_constraints, 0);

        let mut wrong_public = digest;
        wrong_public[0] ^= 1;
        let wrong_bound = trace
            .bind_public_digest(&wrong_public)
            .expect("wrong public bytes still form a trace");
        assert!(matches!(
            wrong_bound.verify_constraints(),
            Err(Shake256RelationError::ConstraintViolation {
                kind: Shake256ConstraintKind::Equality,
                ..
            })
        ));
    }

    #[test]
    fn aggregate_rebasing_supports_explicit_internal_digest_equalities() {
        let first = shake256_448_relation(b"same framed value").expect("trace builds");
        let second = shake256_448_relation(b"same framed value").expect("trace builds");
        let mut witness = Vec::new();
        let mut constraints = Vec::new();
        let first = first.append_to(&mut witness, &mut constraints).unwrap();
        let mut second = second.append_to(&mut witness, &mut constraints).unwrap();
        assert_eq!(first.wire_offset, 0);
        assert_eq!(second.wire_offset, first.wire_count);
        assert!(matches!(
            second.bind_message_sources(
                &first.message_bit_wires[..first.message_bit_wires.len() - 1],
                &mut constraints,
            ),
            Err(Shake256RelationError::TraceBindingLength {
                boundary: "message-source",
                ..
            })
        ));
        second
            .bind_message_sources(&first.message_bit_wires, &mut constraints)
            .unwrap();
        second
            .bind_digest_targets(&first.digest_bit_wires, &mut constraints)
            .unwrap();
        assert!(second.binding_coverage().is_complete());
        second.ensure_fully_bound().unwrap();
        verify_constraint_system(&witness, &constraints).expect("rebased traces and links hold");

        witness[second.message_bit_wires[0].index()] ^= 1;
        assert!(verify_constraint_system(&witness, &constraints).is_err());
    }

    #[test]
    fn gated_digest_equality_is_inactive_only_when_selector_is_zero() {
        let selector = Shake256Wire::from_index(0);
        let left = Shake256Wire::from_index(1);
        let right = Shake256Wire::from_index(2);
        let constraints = [
            Shake256Constraint::Boolean { wire: selector },
            Shake256Constraint::Boolean { wire: left },
            Shake256Constraint::Boolean { wire: right },
            Shake256Constraint::GatedEquality {
                selector,
                left,
                right,
            },
        ];
        verify_constraint_system(&[0, 0, 1], &constraints)
            .expect("inactive selector gates the mismatch");
        assert!(matches!(
            verify_constraint_system(&[1, 0, 1], &constraints),
            Err(Shake256RelationError::ConstraintViolation {
                kind: Shake256ConstraintKind::GatedEquality,
                ..
            })
        ));
    }

    #[test]
    fn constraint_geometry_depends_on_length_not_secret_bytes() {
        let zeros = shake256_448_relation(&[0u8; 77]).expect("trace builds");
        let ones = shake256_448_relation(&[0xffu8; 77]).expect("trace builds");
        assert_eq!(zeros.gate_counts(), ones.gate_counts());
        assert_eq!(
            zeros.smallwood_row_accounting(),
            ones.smallwood_row_accounting()
        );
        assert_ne!(zeros.digest(), ones.digest());
        assert_eq!(zeros.gate_counts().maximum_degree, 5);
        assert_eq!(zeros.gate_counts().external_output_binding_constraints, 448);
        assert_eq!(
            zeros
                .smallwood_row_accounting()
                .external_output_binding_rows,
            7
        );
    }

    #[test]
    fn shared_statement_projection_is_lossless_and_rejects_aliases() {
        let statement = canonical_statement_fixture();
        let projected = project_v6_statement(&statement).expect("canonical statement projects");
        let limbs = *projected.limbs();
        assert_eq!(projected.limbs().len(), 128);
        assert!(projected
            .limbs()
            .iter()
            .all(|limb| *limb < GOLDILOCKS_MODULUS));
        assert_eq!(projected.reconstruct(), statement);
        assert!(matches!(
            V6StatementProjection::from_limbs([0; V6_STATEMENT_LIMBS]),
            Err(FullShake448StatementError::Magic)
        ));

        let mut noncanonical = limbs;
        noncanonical[0] = 1u64 << 56;
        assert_eq!(
            V6StatementProjection::from_limbs(noncanonical),
            Err(FullShake448StatementError::NonCanonicalStatementLimb { index: 0, bits: 56 })
        );
        let mut noncanonical_tail = limbs;
        noncanonical_tail[V6_STATEMENT_LIMBS - 1] = 1u64 << 32;
        assert_eq!(
            V6StatementProjection::from_limbs(noncanonical_tail),
            Err(FullShake448StatementError::NonCanonicalStatementLimb {
                index: 127,
                bits: 32,
            })
        );
    }

    #[test]
    fn semantic_frame_is_unambiguous_and_length_bound() {
        let first =
            encode_v6_semantic_frame(ROLE_NOTE_COMMITMENT, [b"ab".as_slice(), b"c".as_slice()])
                .expect("frame builds");
        let second =
            encode_v6_semantic_frame(ROLE_NOTE_COMMITMENT, [b"a".as_slice(), b"bc".as_slice()])
                .expect("frame builds");
        assert_ne!(first, second);
        assert_eq!(&first[..8], b"HEG-F6V2");
        assert_eq!(&first[8..16], b"note.cm3");
        assert_eq!(first[16], 2);
        assert_eq!(&first[17..], &[0, 2, b'a', b'b', 0, 1, b'c']);
        let expected = decode_hex::<56>(
            "3ee46fb7042c80926381318f9bffedb906268f9268894bf429abba059786bb35e38b2617c967b91fd2bc4d429d128557a5a022cfba1c0141",
        );
        shake256_448_relation(&first)
            .unwrap()
            .verify_digest(&expected)
            .expect("V6 semantic frame KAT satisfies every SHAKE constraint");
        assert_ne!(
            shake256_448_relation(&first).unwrap().digest(),
            shake256_448_relation(&second).unwrap().digest()
        );
    }

    #[test]
    fn full_authority_geometry_adds_all_host_externalized_hashes() {
        assert_eq!(V6_STATEMENT_BYTES, 893);
        assert_eq!(V6_STATEMENT_LIMBS, 128);
        assert_eq!(V6_PUBLIC_VALUES, 128);
        assert_eq!(
            INTENT_STATEMENT_PAYLOAD_BYTES,
            V6_STATEMENT_BYTES - 56 - 2 * 56
        );
        assert_eq!(INTENT_FRAME_BYTES, 17 + 2 + INTENT_STATEMENT_PAYLOAD_BYTES);
        assert_eq!(INTENT_FRAME_BYTES / SHAKE256_RATE_BYTES + 1, 6);
        assert_eq!(BALANCE_TAG_FRAME_BYTES / SHAKE256_RATE_BYTES + 1, 1);
        assert_eq!(LEGACY_M4_SHAKE256_INVOCATIONS, 75);
        assert_eq!(PRE_CIPHERTEXT_BASE_SHAKE_INVOCATIONS, 75 + 1 + 1);
        assert_eq!(PRE_CIPHERTEXT_BASE_KECCAK_PERMUTATIONS, 90);
        assert_eq!(CIPHERTEXT_HASH_FRAME_BYTES, 17 + 3 + 4 + 3 + 6 + 2_149);
        let ciphertext_frame = encode_v6_ciphertext_hash_frame(0, &vec![0; 2_147]).unwrap();
        assert_eq!(ciphertext_frame.len(), CIPHERTEXT_HASH_FRAME_BYTES);
        assert_eq!(CIPHERTEXT_HASH_FRAME_BYTES / SHAKE256_RATE_BYTES + 1, 17);
        assert_eq!(FULL_RELATION_SHAKE256_INVOCATIONS, 79);
        assert_eq!(FULL_RELATION_AUTHORITY_KECCAK_PERMUTATIONS, 124);
        assert_eq!(TOURNAMENT_PARITY5_FUSED_CHI_CORE_ROW_PROJECTION, 178_560);
        assert_eq!(
            FULL_RELATION_HASH_GEOMETRY
                .iter()
                .map(|entry| entry.invocations)
                .sum::<usize>(),
            79
        );
        assert_eq!(
            FULL_RELATION_HASH_GEOMETRY
                .iter()
                .map(|entry| entry.invocations * entry.permutations_per_invocation)
                .sum::<usize>(),
            124
        );
        assert_eq!(
            ensure_full_relation_production_authorized(),
            Err(Shake256RelationError::ProductionAuthorizationUnavailable)
        );
    }
}
