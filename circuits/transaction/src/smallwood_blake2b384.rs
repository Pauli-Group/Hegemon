//! Exact RFC 7693 BLAKE2b Boolean constraints for the SmallWood relation.
//!
//! The production transaction relation needs a conventional hash whose
//! semantics can be checked inside a field proof.  This module expands
//! unkeyed and keyed/personalized RFC 7693 BLAKE2b into explicit bit wires and
//! polynomial constraints over the Goldilocks field.  It does not call a
//! native hash from inside the relation and it has no Poseidon fallback.
//!
//! Bits in bytes and 64-bit words are little-endian, matching RFC 7693.  XOR
//! is represented by `z = x + y - 2xy`; NOT by `z = 1 - x`; and a full-adder
//! by the exact degree-three Boolean formulas for its sum and carry bits.  The
//! maximum constraint degree is therefore three, below SmallWood's active
//! degree-eight ceiling.  Rotations are wire permutations and add no
//! constraints.
//!
//! This is an isolated relation gadget.  Its output wires still need equality
//! constraints to the appropriate public or parent-relation digest wires.  The
//! module deliberately does not change production routing and makes no
//! zero-knowledge or post-quantum security claim.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use hegemon_hash384::BLAKE2B_384_FRAME_V1;

/// RFC 7693 BLAKE2b block size.
pub const BLAKE2B_BLOCK_BYTES: usize = 128;
/// Native BLAKE2b word width.
pub const BLAKE2B_WORD_BITS: usize = 64;
/// Number of BLAKE2b compression rounds.
pub const BLAKE2B_ROUNDS: usize = 12;
/// Size of the production BLAKE2b-384 output.
pub const BLAKE2B_384_OUTPUT_BYTES: usize = 48;
/// Successor-screen output width; RFC 7693 permits every digest length in `1..=64`.
pub const BLAKE2B_448_OUTPUT_BYTES: usize = 56;
/// Maximum RFC 7693 BLAKE2b key length.
pub const BLAKE2B_MAX_KEY_BYTES: usize = 64;
/// RFC 7693 salt and personalization widths for BLAKE2b.
pub const BLAKE2B_SALT_BYTES: usize = 16;
pub const BLAKE2B_PERSONALIZATION_BYTES: usize = 16;
/// SmallWood's active packing factor, used only for exact row projections.
pub const SMALLWOOD_BOOLEAN_PACKING_FACTOR: usize = 64;

const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
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
const BLAKE2B_SIGMA: [[usize; 16]; BLAKE2B_ROUNDS] = [
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

/// Index of one scalar bit witness in a BLAKE2b constraint trace.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Blake2bWire(usize);

impl Blake2bWire {
    /// Return the zero-based index into the trace's witness-value slice.
    pub const fn index(self) -> usize {
        self.0
    }
}

/// Stable category for one polynomial constraint.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Blake2bConstraintKind {
    Constant,
    Boolean,
    Xor,
    Not,
    FullAdderSum,
    FullAdderCarry,
}

/// One exact Goldilocks polynomial identity in the Boolean BLAKE2b relation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Blake2bConstraint {
    /// `output - value = 0`.
    Constant { output: Blake2bWire, value: bool },
    /// `wire * (wire - 1) = 0`.
    Boolean { wire: Blake2bWire },
    /// `output - (left + right - 2 * left * right) = 0`.
    Xor {
        left: Blake2bWire,
        right: Blake2bWire,
        output: Blake2bWire,
    },
    /// `output + input - 1 = 0`.
    Not {
        input: Blake2bWire,
        output: Blake2bWire,
    },
    /// Exact three-input full-adder sum bit, of degree three.
    FullAdderSum {
        left: Blake2bWire,
        right: Blake2bWire,
        carry_in: Blake2bWire,
        sum: Blake2bWire,
    },
    /// Exact three-input full-adder carry bit, of degree three.
    FullAdderCarry {
        left: Blake2bWire,
        right: Blake2bWire,
        carry_in: Blake2bWire,
        carry_out: Blake2bWire,
    },
}

impl Blake2bConstraint {
    /// Stable category of this identity.
    pub const fn kind(self) -> Blake2bConstraintKind {
        match self {
            Self::Constant { .. } => Blake2bConstraintKind::Constant,
            Self::Boolean { .. } => Blake2bConstraintKind::Boolean,
            Self::Xor { .. } => Blake2bConstraintKind::Xor,
            Self::Not { .. } => Blake2bConstraintKind::Not,
            Self::FullAdderSum { .. } => Blake2bConstraintKind::FullAdderSum,
            Self::FullAdderCarry { .. } => Blake2bConstraintKind::FullAdderCarry,
        }
    }

    /// Total polynomial degree after lowering to Goldilocks arithmetic.
    pub const fn degree(self) -> usize {
        match self {
            Self::Constant { .. } | Self::Not { .. } => 1,
            Self::Boolean { .. } | Self::Xor { .. } => 2,
            Self::FullAdderSum { .. } | Self::FullAdderCarry { .. } => 3,
        }
    }

    /// Evaluate this constraint in the Goldilocks field.
    ///
    /// A return value of zero means the identity is satisfied.
    pub fn residual(self, witness: &[u64]) -> Result<u64, Blake2bRelationError> {
        self.residual_with_lookup(|wire| {
            witness
                .get(wire.index())
                .copied()
                .ok_or(Blake2bRelationError::WireOutOfBounds {
                    wire: wire.index(),
                    witness_len: witness.len(),
                })
        })
    }

    /// Evaluate this constraint through a caller-supplied wire lookup.
    ///
    /// The aggregate SmallWood compiler uses this to map a local BLAKE2b trace
    /// wire to a packed row polynomial evaluation without reimplementing any
    /// RFC 7693 gate formulas. The lookup must return canonical Goldilocks
    /// values and should report an out-of-bounds wire as
    /// [`Blake2bRelationError::WireOutOfBounds`].
    pub(crate) fn residual_with_lookup(
        self,
        value: impl Fn(Blake2bWire) -> Result<u64, Blake2bRelationError>,
    ) -> Result<u64, Blake2bRelationError> {
        match self {
            Self::Constant { output, value: bit } => Ok(field_sub(value(output)?, u64::from(bit))),
            Self::Boolean { wire } => {
                let bit = value(wire)?;
                Ok(field_mul(bit, field_sub(bit, 1)))
            }
            Self::Xor {
                left,
                right,
                output,
            } => {
                let left = value(left)?;
                let right = value(right)?;
                let expected = field_sub(
                    field_add(left, right),
                    field_mul_small(field_mul(left, right), 2),
                );
                Ok(field_sub(value(output)?, expected))
            }
            Self::Not { input, output } => {
                Ok(field_sub(field_add(value(output)?, value(input)?), 1))
            }
            Self::FullAdderSum {
                left,
                right,
                carry_in,
                sum,
            } => {
                let left = value(left)?;
                let right = value(right)?;
                let carry_in = value(carry_in)?;
                let left_right = field_mul(left, right);
                let left_carry = field_mul(left, carry_in);
                let right_carry = field_mul(right, carry_in);
                let triple = field_mul(left_right, carry_in);
                let pair_sum = field_add(field_add(left_right, left_carry), right_carry);
                let expected = field_add(
                    field_sub(
                        field_add(field_add(left, right), carry_in),
                        field_mul_small(pair_sum, 2),
                    ),
                    field_mul_small(triple, 4),
                );
                Ok(field_sub(value(sum)?, expected))
            }
            Self::FullAdderCarry {
                left,
                right,
                carry_in,
                carry_out,
            } => {
                let left = value(left)?;
                let right = value(right)?;
                let carry_in = value(carry_in)?;
                let triple = field_mul(field_mul(left, right), carry_in);
                let pair_sum = field_add(
                    field_add(field_mul(left, right), field_mul(left, carry_in)),
                    field_mul(right, carry_in),
                );
                let expected = field_sub(pair_sum, field_mul_small(triple, 2));
                Ok(field_sub(value(carry_out)?, expected))
            }
        }
    }
}

/// Exact per-block counter and final-block data used by RFC 7693 compression.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Blake2bBlockKind {
    Key,
    Message,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Blake2bBlockDescriptor {
    pub block_index: usize,
    pub kind: Blake2bBlockKind,
    pub message_offset: usize,
    pub absorbed_bytes: usize,
    pub counter: u128,
    pub is_final: bool,
}

/// Exact gate inventory for one generated trace.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Blake2bGateCounts {
    pub key_bytes: usize,
    pub message_bytes: usize,
    pub output_bytes: usize,
    pub block_count: usize,
    pub wire_count: usize,
    pub constant_constraints: usize,
    pub input_boolean_constraints: usize,
    pub xor_constraints: usize,
    pub not_constraints: usize,
    pub full_adder_gates: usize,
    pub full_adder_sum_constraints: usize,
    pub full_adder_carry_constraints: usize,
    pub linear_constraints: usize,
    pub quadratic_constraints: usize,
    pub cubic_constraints: usize,
    pub scalar_constraint_count: usize,
    /// Equality constraints the parent relation must add to bind every key bit
    /// to its source wire. This is zero for unkeyed mode.
    pub external_key_binding_constraints: usize,
    /// Equality constraints the parent relation must add to bind every message
    /// bit to its source wire.
    pub external_message_binding_constraints: usize,
    /// Sum of key- and message-source equality constraints.
    pub external_input_binding_constraints: usize,
    /// Equality constraints the parent relation must add to bind every output
    /// bit to public or parent-relation digest wires.
    pub external_output_binding_constraints: usize,
    /// Sum of all external input- and output-wire equality constraints.
    pub external_binding_constraints: usize,
    pub maximum_degree: usize,
}

/// Deterministic flat-packing accounting for SmallWood rows.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Blake2bRowAccounting {
    pub packing_factor: usize,
    pub scalar_witness_values: usize,
    pub witness_rows: usize,
    pub witness_padding_values: usize,
    pub scalar_constraints: usize,
    pub constraint_rows: usize,
    pub constraint_padding_values: usize,
    pub external_input_binding_constraints: usize,
    pub external_input_binding_rows: usize,
    pub external_output_binding_constraints: usize,
    pub external_output_binding_rows: usize,
    /// Input and output equality constraints packed together for this trace.
    pub external_binding_constraints: usize,
    pub external_binding_rows: usize,
}

/// Failure while constructing or validating a Boolean BLAKE2b relation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Blake2bRelationError {
    #[error("RFC 7693 BLAKE2b output length must be in 1..=64 bytes, got {0}")]
    InvalidOutputLength(usize),
    #[error("RFC 7693 BLAKE2b key must contain 1..=64 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("{component} length {bytes} does not fit RFC framing's u64 length")]
    FrameLengthDoesNotFitU64 {
        component: &'static str,
        bytes: usize,
    },
    #[error("framed BLAKE2b message length overflow")]
    FrameLengthOverflow,
    #[error("SmallWood packing factor must be non-zero")]
    ZeroPackingFactor,
    #[error("BLAKE2b wire {wire} is outside witness length {witness_len}")]
    WireOutOfBounds { wire: usize, witness_len: usize },
    #[error("BLAKE2b witness value at wire {wire} is not a canonical Goldilocks element")]
    NonCanonicalWitness { wire: usize },
    #[error(
        "BLAKE2b constraint {constraint} ({kind:?}) failed with Goldilocks residual {residual}"
    )]
    ConstraintViolation {
        constraint: usize,
        kind: Blake2bConstraintKind,
        residual: u64,
    },
    #[error("BLAKE2b digest does not equal the expected digest")]
    DigestMismatch,
    #[error(
        "BLAKE2b {component} length mismatch: trace has {trace_bytes} bytes, caller supplied {supplied_bytes}"
    )]
    InputLengthMismatch {
        component: &'static str,
        trace_bytes: usize,
        supplied_bytes: usize,
    },
    #[error("BLAKE2b {component} source bit {bit} does not equal its trace witness")]
    InputBitMismatch { component: &'static str, bit: usize },
    #[error("BLAKE2b block counter/final metadata does not match the RFC 7693 schedule")]
    BlockScheduleMismatch,
}

/// A fully materialized Boolean constraint trace for RFC 7693 BLAKE2b.
///
/// `OUTPUT_BYTES` is encoded in the RFC parameter block.  The production alias
/// [`Blake2b384ConstraintTrace`] fixes it to 48, while retaining the same core
/// for wider profiles that need additional quantum-composition margin.
#[derive(Clone)]
pub struct Blake2bConstraintTrace<const OUTPUT_BYTES: usize> {
    key_len: usize,
    message_len: usize,
    personalization: [u8; BLAKE2B_PERSONALIZATION_BYTES],
    witness: Vec<u64>,
    constraints: Vec<Blake2bConstraint>,
    key_bit_wires: Vec<Blake2bWire>,
    message_bit_wires: Vec<Blake2bWire>,
    digest_bit_wires: Vec<Blake2bWire>,
    blocks: Vec<Blake2bBlockDescriptor>,
}

/// Production-width RFC 7693 BLAKE2b-384 constraint trace.
pub type Blake2b384ConstraintTrace = Blake2bConstraintTrace<BLAKE2B_384_OUTPUT_BYTES>;

impl<const OUTPUT_BYTES: usize> Blake2bConstraintTrace<OUTPUT_BYTES> {
    /// RFC key length.  Zero denotes the unkeyed mode.
    pub const fn key_len(&self) -> usize {
        self.key_len
    }

    /// Original unframed message length in bytes.
    pub const fn message_len(&self) -> usize {
        self.message_len
    }

    pub const fn personalization(&self) -> &[u8; BLAKE2B_PERSONALIZATION_BYTES] {
        &self.personalization
    }

    /// Ordered scalar Goldilocks witnesses.  Every value generated here is a
    /// bit; the constraint list independently enforces the required identities.
    pub fn witness_values(&self) -> &[u64] {
        &self.witness
    }

    /// Ordered polynomial constraints for lowering into SmallWood.
    pub fn constraints(&self) -> &[Blake2bConstraint] {
        &self.constraints
    }

    /// Message bit wires in byte order, least-significant bit first per byte.
    pub fn message_bit_wires(&self) -> &[Blake2bWire] {
        &self.message_bit_wires
    }

    /// Key bit wires in byte order.  Key-block zero padding is constant-constrained and omitted.
    pub fn key_bit_wires(&self) -> &[Blake2bWire] {
        &self.key_bit_wires
    }

    /// Digest bit wires in byte order, least-significant bit first per byte.
    pub fn digest_bit_wires(&self) -> &[Blake2bWire] {
        &self.digest_bit_wires
    }

    /// RFC counter/final metadata for every compression call.
    pub fn blocks(&self) -> &[Blake2bBlockDescriptor] {
        &self.blocks
    }

    /// Reconstruct the digest from the output witness bits.
    pub fn digest(&self) -> [u8; OUTPUT_BYTES] {
        core::array::from_fn(|byte_index| {
            let mut byte = 0u8;
            for bit_index in 0..8 {
                let wire = self.digest_bit_wires[byte_index * 8 + bit_index];
                byte |= (self.witness[wire.index()] as u8) << bit_index;
            }
            byte
        })
    }

    /// Verify canonical field encoding and every relation constraint.
    pub fn verify_constraints(&self) -> Result<(), Blake2bRelationError> {
        if self.blocks != expected_block_descriptors(self.key_len, self.message_len)? {
            return Err(Blake2bRelationError::BlockScheduleMismatch);
        }
        for (wire, value) in self.witness.iter().copied().enumerate() {
            if value >= GOLDILOCKS_MODULUS {
                return Err(Blake2bRelationError::NonCanonicalWitness { wire });
            }
        }
        for (constraint_index, constraint) in self.constraints.iter().copied().enumerate() {
            let residual = constraint.residual(&self.witness)?;
            if residual != 0 {
                return Err(Blake2bRelationError::ConstraintViolation {
                    constraint: constraint_index,
                    kind: constraint.kind(),
                    residual,
                });
            }
        }
        Ok(())
    }

    /// Check the host-side source binding for every externally supplied input
    /// bit. This is a diagnostic/refinement check, not a substitute for the
    /// equality constraints that a parent proof relation must emit.
    pub fn verify_input_bindings(
        &self,
        expected_key: &[u8],
        expected_message: &[u8],
    ) -> Result<(), Blake2bRelationError> {
        verify_source_bits(
            "key",
            self.key_len,
            &self.key_bit_wires,
            expected_key,
            &self.witness,
        )?;
        verify_source_bits(
            "message",
            self.message_len,
            &self.message_bit_wires,
            expected_message,
            &self.witness,
        )
    }

    /// Verify the constraints and bind the computed output to an expected
    /// digest.  A parent proof relation must express the same binding with the
    /// output wires returned by [`Self::digest_bit_wires`].
    pub fn verify_digest(&self, expected: &[u8; OUTPUT_BYTES]) -> Result<(), Blake2bRelationError> {
        self.verify_constraints()?;
        if &self.digest() != expected {
            return Err(Blake2bRelationError::DigestMismatch);
        }
        Ok(())
    }

    /// Count exact generated gates and scalar constraints.
    pub fn gate_counts(&self) -> Blake2bGateCounts {
        let mut constant_constraints = 0usize;
        let mut input_boolean_constraints = 0usize;
        let mut xor_constraints = 0usize;
        let mut not_constraints = 0usize;
        let mut full_adder_sum_constraints = 0usize;
        let mut full_adder_carry_constraints = 0usize;
        for constraint in &self.constraints {
            match constraint {
                Blake2bConstraint::Constant { .. } => constant_constraints += 1,
                Blake2bConstraint::Boolean { .. } => input_boolean_constraints += 1,
                Blake2bConstraint::Xor { .. } => xor_constraints += 1,
                Blake2bConstraint::Not { .. } => not_constraints += 1,
                Blake2bConstraint::FullAdderSum { .. } => {
                    full_adder_sum_constraints += 1;
                }
                Blake2bConstraint::FullAdderCarry { .. } => {
                    full_adder_carry_constraints += 1;
                }
            }
        }
        debug_assert_eq!(full_adder_sum_constraints, full_adder_carry_constraints);
        let linear_constraints = constant_constraints + not_constraints;
        let quadratic_constraints = input_boolean_constraints + xor_constraints;
        let cubic_constraints = full_adder_sum_constraints + full_adder_carry_constraints;
        let external_key_binding_constraints = self.key_len * 8;
        let external_message_binding_constraints = self.message_len * 8;
        let external_input_binding_constraints =
            external_key_binding_constraints + external_message_binding_constraints;
        let external_output_binding_constraints = OUTPUT_BYTES * 8;
        Blake2bGateCounts {
            key_bytes: self.key_len,
            message_bytes: self.message_len,
            output_bytes: OUTPUT_BYTES,
            block_count: self.blocks.len(),
            wire_count: self.witness.len(),
            constant_constraints,
            input_boolean_constraints,
            xor_constraints,
            not_constraints,
            full_adder_gates: full_adder_sum_constraints,
            full_adder_sum_constraints,
            full_adder_carry_constraints,
            linear_constraints,
            quadratic_constraints,
            cubic_constraints,
            scalar_constraint_count: self.constraints.len(),
            external_key_binding_constraints,
            external_message_binding_constraints,
            external_input_binding_constraints,
            external_output_binding_constraints,
            external_binding_constraints: external_input_binding_constraints
                + external_output_binding_constraints,
            maximum_degree: self
                .constraints
                .iter()
                .copied()
                .map(Blake2bConstraint::degree)
                .max()
                .unwrap_or(0),
        }
    }

    /// Compute exact rows and padding for deterministic flat packing.
    pub fn row_accounting(
        &self,
        packing_factor: usize,
    ) -> Result<Blake2bRowAccounting, Blake2bRelationError> {
        if packing_factor == 0 {
            return Err(Blake2bRelationError::ZeroPackingFactor);
        }
        let witness_rows = self.witness.len().div_ceil(packing_factor);
        let constraint_rows = self.constraints.len().div_ceil(packing_factor);
        let input_bindings = (self.key_len + self.message_len) * 8;
        let input_binding_rows = input_bindings.div_ceil(packing_factor);
        let output_bindings = OUTPUT_BYTES * 8;
        let output_binding_rows = output_bindings.div_ceil(packing_factor);
        let external_bindings = input_bindings + output_bindings;
        let external_binding_rows = external_bindings.div_ceil(packing_factor);
        Ok(Blake2bRowAccounting {
            packing_factor,
            scalar_witness_values: self.witness.len(),
            witness_rows,
            witness_padding_values: witness_rows * packing_factor - self.witness.len(),
            scalar_constraints: self.constraints.len(),
            constraint_rows,
            constraint_padding_values: constraint_rows * packing_factor - self.constraints.len(),
            external_input_binding_constraints: input_bindings,
            external_input_binding_rows: input_binding_rows,
            external_output_binding_constraints: output_bindings,
            external_output_binding_rows: output_binding_rows,
            external_binding_constraints: external_bindings,
            external_binding_rows,
        })
    }

    /// Active 64-lane SmallWood row accounting.
    pub fn smallwood_row_accounting(&self) -> Blake2bRowAccounting {
        self.row_accounting(SMALLWOOD_BOOLEAN_PACKING_FACTOR)
            .expect("the active SmallWood Boolean packing factor is non-zero")
    }
}

/// Build exact unkeyed RFC 7693 BLAKE2b constraints for a chosen legal output
/// width.  Output width changes the RFC parameter block, not compression cost.
pub fn blake2b_relation<const OUTPUT_BYTES: usize>(
    message: &[u8],
) -> Result<Blake2bConstraintTrace<OUTPUT_BYTES>, Blake2bRelationError> {
    blake2b_relation_with_parameters::<OUTPUT_BYTES>(
        &[],
        message,
        [0; BLAKE2B_PERSONALIZATION_BYTES],
    )
}

/// Build exact unkeyed, personalized RFC 7693 BLAKE2b constraints.
pub fn blake2b_personalized_relation<const OUTPUT_BYTES: usize>(
    message: &[u8],
    personalization: [u8; BLAKE2B_PERSONALIZATION_BYTES],
) -> Result<Blake2bConstraintTrace<OUTPUT_BYTES>, Blake2bRelationError> {
    blake2b_relation_with_parameters::<OUTPUT_BYTES>(&[], message, personalization)
}

/// Build exact keyed, personalized RFC 7693 BLAKE2b constraints.
///
/// RFC keyed mode absorbs one 128-byte key block, zero-padded after the actual key, and counts the
/// whole block in `t`.  A non-empty message begins in the next block.  The 16-byte
/// personalization is encoded in parameter bytes 48..64 and never prepended to the message.
pub fn blake2b_keyed_personalized_relation<const OUTPUT_BYTES: usize>(
    key: &[u8],
    message: &[u8],
    personalization: [u8; BLAKE2B_PERSONALIZATION_BYTES],
) -> Result<Blake2bConstraintTrace<OUTPUT_BYTES>, Blake2bRelationError> {
    if !(1..=BLAKE2B_MAX_KEY_BYTES).contains(&key.len()) {
        return Err(Blake2bRelationError::InvalidKeyLength(key.len()));
    }
    blake2b_relation_with_parameters::<OUTPUT_BYTES>(key, message, personalization)
}

fn blake2b_relation_with_parameters<const OUTPUT_BYTES: usize>(
    key: &[u8],
    message: &[u8],
    personalization: [u8; BLAKE2B_PERSONALIZATION_BYTES],
) -> Result<Blake2bConstraintTrace<OUTPUT_BYTES>, Blake2bRelationError> {
    if !(1..=64).contains(&OUTPUT_BYTES) {
        return Err(Blake2bRelationError::InvalidOutputLength(OUTPUT_BYTES));
    }
    if key.len() > BLAKE2B_MAX_KEY_BYTES {
        return Err(Blake2bRelationError::InvalidKeyLength(key.len()));
    }

    let mut builder = ConstraintBuilder::new();
    let mut state = core::array::from_fn(|index| builder.constant_word(BLAKE2B_IV[index]));
    let parameter_word = 0x0101_0000u64 ^ ((key.len() as u64) << 8) ^ OUTPUT_BYTES as u64;
    state[0] = builder.xor_word(state[0], builder.constant_word(parameter_word));
    let personalization_words = [
        u64::from_le_bytes(
            personalization[..8]
                .try_into()
                .expect("fixed eight-byte half"),
        ),
        u64::from_le_bytes(
            personalization[8..]
                .try_into()
                .expect("fixed eight-byte half"),
        ),
    ];
    state[6] = builder.xor_word(state[6], builder.constant_word(personalization_words[0]));
    state[7] = builder.xor_word(state[7], builder.constant_word(personalization_words[1]));

    let expected_blocks = expected_block_descriptors(key.len(), message.len())?;
    let message_block_count = expected_blocks
        .iter()
        .filter(|block| block.kind == Blake2bBlockKind::Message)
        .count();
    let mut key_bit_wires = Vec::with_capacity(
        key.len()
            .checked_mul(8)
            .ok_or(Blake2bRelationError::FrameLengthOverflow)?,
    );
    let mut message_bit_wires = Vec::with_capacity(
        message
            .len()
            .checked_mul(8)
            .ok_or(Blake2bRelationError::FrameLengthOverflow)?,
    );
    let mut blocks = Vec::with_capacity(expected_blocks.len());

    if !key.is_empty() {
        let descriptor = expected_blocks[0];
        let mut block_bits = [builder.zero(); BLAKE2B_BLOCK_BYTES * 8];
        for (byte_index, byte) in key.iter().copied().enumerate() {
            for bit_index in 0..8 {
                let bit = builder.input_bit(((byte >> bit_index) & 1) == 1);
                block_bits[byte_index * 8 + bit_index] = bit;
                key_bit_wires.push(bit.wire);
            }
        }
        let block_words = core::array::from_fn(|word_index| {
            core::array::from_fn(|bit_index| block_bits[word_index * 64 + bit_index])
        });
        state = compress(
            &mut builder,
            state,
            block_words,
            descriptor.counter,
            descriptor.is_final,
        );
        blocks.push(descriptor);
    }

    for message_block_index in 0..message_block_count {
        let descriptor = expected_blocks[usize::from(!key.is_empty()) + message_block_index];
        let message_offset = descriptor.message_offset;
        let absorbed_bytes = descriptor.absorbed_bytes;
        let mut block_bits = [builder.zero(); BLAKE2B_BLOCK_BYTES * 8];
        for byte_index in 0..absorbed_bytes {
            let byte = message[message_offset + byte_index];
            for bit_index in 0..8 {
                let bit = builder.input_bit(((byte >> bit_index) & 1) == 1);
                block_bits[byte_index * 8 + bit_index] = bit;
                message_bit_wires.push(bit.wire);
            }
        }
        let block_words = core::array::from_fn(|word_index| {
            core::array::from_fn(|bit_index| block_bits[word_index * 64 + bit_index])
        });
        state = compress(
            &mut builder,
            state,
            block_words,
            descriptor.counter,
            descriptor.is_final,
        );
        blocks.push(descriptor);
    }

    debug_assert_eq!(blocks, expected_blocks);

    let mut digest_bit_wires = Vec::with_capacity(OUTPUT_BYTES * 8);
    for byte_index in 0..OUTPUT_BYTES {
        let word_index = byte_index / 8;
        let word_byte_index = byte_index % 8;
        for bit_index in 0..8 {
            digest_bit_wires.push(state[word_index][word_byte_index * 8 + bit_index].wire);
        }
    }

    Ok(Blake2bConstraintTrace {
        key_len: key.len(),
        message_len: message.len(),
        personalization,
        witness: builder.witness,
        constraints: builder.constraints,
        key_bit_wires,
        message_bit_wires,
        digest_bit_wires,
        blocks,
    })
}

/// Build the production-width RFC 7693 BLAKE2b-384 relation.
pub fn blake2b384_relation(
    message: &[u8],
) -> Result<Blake2b384ConstraintTrace, Blake2bRelationError> {
    blake2b_relation::<BLAKE2B_384_OUTPUT_BYTES>(message)
}

/// Exact number of RFC 7693 compression calls for an unkeyed message.
///
/// An empty message still executes one final zero block.  A non-empty exact
/// multiple of 128 bytes uses its last data block as the final block and does
/// not append another block.
pub const fn blake2b_compression_block_count(message_len: usize) -> usize {
    if message_len == 0 {
        1
    } else {
        message_len.div_ceil(BLAKE2B_BLOCK_BYTES)
    }
}

fn expected_block_descriptors(
    key_len: usize,
    message_len: usize,
) -> Result<Vec<Blake2bBlockDescriptor>, Blake2bRelationError> {
    if key_len > BLAKE2B_MAX_KEY_BYTES {
        return Err(Blake2bRelationError::InvalidKeyLength(key_len));
    }
    let message_block_count = if key_len == 0 && message_len == 0 {
        1
    } else {
        message_len.div_ceil(BLAKE2B_BLOCK_BYTES)
    };
    let block_count = usize::from(key_len != 0)
        .checked_add(message_block_count)
        .ok_or(Blake2bRelationError::FrameLengthOverflow)?;
    let mut blocks = Vec::with_capacity(block_count);
    if key_len != 0 {
        blocks.push(Blake2bBlockDescriptor {
            block_index: 0,
            kind: Blake2bBlockKind::Key,
            message_offset: 0,
            absorbed_bytes: BLAKE2B_BLOCK_BYTES,
            counter: BLAKE2B_BLOCK_BYTES as u128,
            is_final: message_len == 0,
        });
    }
    for message_block_index in 0..message_block_count {
        let message_offset = message_block_index
            .checked_mul(BLAKE2B_BLOCK_BYTES)
            .ok_or(Blake2bRelationError::FrameLengthOverflow)?;
        let absorbed_bytes = message_len
            .saturating_sub(message_offset)
            .min(BLAKE2B_BLOCK_BYTES);
        let counter = (u128::from(key_len != 0) * BLAKE2B_BLOCK_BYTES as u128)
            .checked_add(message_offset as u128)
            .and_then(|counter| counter.checked_add(absorbed_bytes as u128))
            .ok_or(Blake2bRelationError::FrameLengthOverflow)?;
        blocks.push(Blake2bBlockDescriptor {
            block_index: blocks.len(),
            kind: Blake2bBlockKind::Message,
            message_offset,
            absorbed_bytes,
            counter,
            is_final: message_block_index + 1 == message_block_count,
        });
    }
    Ok(blocks)
}

fn verify_source_bits(
    component: &'static str,
    trace_bytes: usize,
    wires: &[Blake2bWire],
    supplied: &[u8],
    witness: &[u64],
) -> Result<(), Blake2bRelationError> {
    if trace_bytes != supplied.len() || wires.len() != trace_bytes * 8 {
        return Err(Blake2bRelationError::InputLengthMismatch {
            component,
            trace_bytes,
            supplied_bytes: supplied.len(),
        });
    }
    for (bit, wire) in wires.iter().copied().enumerate() {
        let actual =
            witness
                .get(wire.index())
                .copied()
                .ok_or(Blake2bRelationError::WireOutOfBounds {
                    wire: wire.index(),
                    witness_len: witness.len(),
                })?;
        let expected = u64::from((supplied[bit / 8] >> (bit % 8)) & 1);
        if actual != expected {
            return Err(Blake2bRelationError::InputBitMismatch { component, bit });
        }
    }
    Ok(())
}

/// Exact byte length of Hegemon's framed domain transcript for known part
/// lengths, without allocating or hashing it.
pub fn blake2b384_framed_len(
    domain_len: usize,
    part_lengths: &[usize],
) -> Result<usize, Blake2bRelationError> {
    u64::try_from(domain_len).map_err(|_| Blake2bRelationError::FrameLengthDoesNotFitU64 {
        component: "domain",
        bytes: domain_len,
    })?;
    let mut length = BLAKE2B_384_FRAME_V1
        .len()
        .checked_add(8)
        .and_then(|length| length.checked_add(domain_len))
        .ok_or(Blake2bRelationError::FrameLengthOverflow)?;
    for part_len in part_lengths.iter().copied() {
        u64::try_from(part_len).map_err(|_| Blake2bRelationError::FrameLengthDoesNotFitU64 {
            component: "part",
            bytes: part_len,
        })?;
        length = length
            .checked_add(8)
            .and_then(|length| length.checked_add(part_len))
            .ok_or(Blake2bRelationError::FrameLengthOverflow)?;
    }
    Ok(length)
}

/// Construct Hegemon's unambiguous BLAKE2b domain frame.
///
/// The exact bytes are
/// `frame || u64le(domain_len) || domain || (u64le(part_len) || part)*`.
pub fn blake2b384_framed_message<'a>(
    domain: &[u8],
    parts: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, Blake2bRelationError> {
    let domain_len = u64::try_from(domain.len()).map_err(|_| {
        Blake2bRelationError::FrameLengthDoesNotFitU64 {
            component: "domain",
            bytes: domain.len(),
        }
    })?;
    let initial_capacity = blake2b384_framed_len(domain.len(), &[])?;
    let mut framed = Vec::with_capacity(initial_capacity);
    framed.extend_from_slice(BLAKE2B_384_FRAME_V1);
    framed.extend_from_slice(&domain_len.to_le_bytes());
    framed.extend_from_slice(domain);
    for part in parts {
        let part_len = u64::try_from(part.len()).map_err(|_| {
            Blake2bRelationError::FrameLengthDoesNotFitU64 {
                component: "part",
                bytes: part.len(),
            }
        })?;
        let additional = 8usize
            .checked_add(part.len())
            .ok_or(Blake2bRelationError::FrameLengthOverflow)?;
        framed
            .len()
            .checked_add(additional)
            .ok_or(Blake2bRelationError::FrameLengthOverflow)?;
        framed.extend_from_slice(&part_len.to_le_bytes());
        framed.extend_from_slice(part);
    }
    Ok(framed)
}

/// Build exact BLAKE2b-384 constraints over Hegemon's domain-separated frame.
pub fn blake2b384_domain_relation<'a>(
    domain: &[u8],
    parts: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Blake2b384ConstraintTrace, Blake2bRelationError> {
    let framed = blake2b384_framed_message(domain, parts)?;
    blake2b384_relation(&framed)
}

type Word = [Bit; BLAKE2B_WORD_BITS];

#[derive(Clone, Copy)]
struct Bit {
    wire: Blake2bWire,
    known: Option<bool>,
}

struct ConstraintBuilder {
    witness: Vec<u64>,
    constraints: Vec<Blake2bConstraint>,
    zero: Bit,
    one: Bit,
}

impl ConstraintBuilder {
    fn new() -> Self {
        let mut builder = Self {
            witness: Vec::new(),
            constraints: Vec::new(),
            zero: Bit {
                wire: Blake2bWire(0),
                known: Some(false),
            },
            one: Bit {
                wire: Blake2bWire(0),
                known: Some(true),
            },
        };
        let zero = builder.allocate(false, Some(false));
        builder.constraints.push(Blake2bConstraint::Constant {
            output: zero.wire,
            value: false,
        });
        let one = builder.allocate(true, Some(true));
        builder.constraints.push(Blake2bConstraint::Constant {
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

    fn allocate(&mut self, value: bool, known: Option<bool>) -> Bit {
        let wire = Blake2bWire(self.witness.len());
        self.witness.push(u64::from(value));
        Bit { wire, known }
    }

    const fn constant(&self, value: bool) -> Bit {
        if value {
            self.one
        } else {
            self.zero
        }
    }

    fn input_bit(&mut self, value: bool) -> Bit {
        let bit = self.allocate(value, None);
        self.constraints
            .push(Blake2bConstraint::Boolean { wire: bit.wire });
        bit
    }

    fn not(&mut self, input: Bit) -> Bit {
        if let Some(value) = input.known {
            return self.constant(!value);
        }
        let output = self.allocate(self.value(input) == 0, None);
        self.constraints.push(Blake2bConstraint::Not {
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
                let output = self.allocate(self.value(left) != self.value(right), None);
                self.constraints.push(Blake2bConstraint::Xor {
                    left: left.wire,
                    right: right.wire,
                    output: output.wire,
                });
                output
            }
        }
    }

    fn full_adder(&mut self, left: Bit, right: Bit, carry_in: Bit) -> (Bit, Bit) {
        if let (Some(left), Some(right), Some(carry_in)) = (left.known, right.known, carry_in.known)
        {
            let total = u8::from(left) + u8::from(right) + u8::from(carry_in);
            return (self.constant(total & 1 == 1), self.constant(total >= 2));
        }
        let total = self.value(left) + self.value(right) + self.value(carry_in);
        let sum = self.allocate(total & 1 == 1, None);
        let carry_out = self.allocate(total >= 2, None);
        self.constraints.push(Blake2bConstraint::FullAdderSum {
            left: left.wire,
            right: right.wire,
            carry_in: carry_in.wire,
            sum: sum.wire,
        });
        self.constraints.push(Blake2bConstraint::FullAdderCarry {
            left: left.wire,
            right: right.wire,
            carry_in: carry_in.wire,
            carry_out: carry_out.wire,
        });
        (sum, carry_out)
    }

    fn value(&self, bit: Bit) -> u64 {
        self.witness[bit.wire.index()]
    }

    fn constant_word(&self, value: u64) -> Word {
        core::array::from_fn(|bit| self.constant(((value >> bit) & 1) == 1))
    }

    fn xor_word(&mut self, left: Word, right: Word) -> Word {
        core::array::from_fn(|bit| self.xor(left[bit], right[bit]))
    }

    fn not_word(&mut self, input: Word) -> Word {
        core::array::from_fn(|bit| self.not(input[bit]))
    }

    fn add_word(&mut self, left: Word, right: Word) -> Word {
        let mut carry = self.zero;
        core::array::from_fn(|bit| {
            let (sum, next_carry) = self.full_adder(left[bit], right[bit], carry);
            carry = next_carry;
            sum
        })
    }
}

fn rotate_right(word: Word, amount: usize) -> Word {
    core::array::from_fn(|bit| word[(bit + amount) % BLAKE2B_WORD_BITS])
}

fn compress(
    builder: &mut ConstraintBuilder,
    state: [Word; 8],
    message: [Word; 16],
    counter: u128,
    is_final: bool,
) -> [Word; 8] {
    let zero_word = builder.constant_word(0);
    let mut work = [zero_word; 16];
    work[..8].copy_from_slice(&state);
    for (index, iv) in BLAKE2B_IV.iter().copied().enumerate() {
        work[index + 8] = builder.constant_word(iv);
    }
    work[12] = builder.xor_word(work[12], builder.constant_word(counter as u64));
    work[13] = builder.xor_word(work[13], builder.constant_word((counter >> 64) as u64));
    if is_final {
        work[14] = builder.not_word(work[14]);
    }

    for schedule in BLAKE2B_SIGMA {
        mix(
            builder,
            &mut work,
            [0, 4, 8, 12],
            message[schedule[0]],
            message[schedule[1]],
        );
        mix(
            builder,
            &mut work,
            [1, 5, 9, 13],
            message[schedule[2]],
            message[schedule[3]],
        );
        mix(
            builder,
            &mut work,
            [2, 6, 10, 14],
            message[schedule[4]],
            message[schedule[5]],
        );
        mix(
            builder,
            &mut work,
            [3, 7, 11, 15],
            message[schedule[6]],
            message[schedule[7]],
        );
        mix(
            builder,
            &mut work,
            [0, 5, 10, 15],
            message[schedule[8]],
            message[schedule[9]],
        );
        mix(
            builder,
            &mut work,
            [1, 6, 11, 12],
            message[schedule[10]],
            message[schedule[11]],
        );
        mix(
            builder,
            &mut work,
            [2, 7, 8, 13],
            message[schedule[12]],
            message[schedule[13]],
        );
        mix(
            builder,
            &mut work,
            [3, 4, 9, 14],
            message[schedule[14]],
            message[schedule[15]],
        );
    }

    core::array::from_fn(|index| {
        let mixed = builder.xor_word(work[index], work[index + 8]);
        builder.xor_word(state[index], mixed)
    })
}

fn mix(
    builder: &mut ConstraintBuilder,
    work: &mut [Word; 16],
    indices: [usize; 4],
    message_x: Word,
    message_y: Word,
) {
    let [a, b, c, d] = indices;
    let a_plus_b = builder.add_word(work[a], work[b]);
    work[a] = builder.add_word(a_plus_b, message_x);
    work[d] = rotate_right(builder.xor_word(work[d], work[a]), 32);
    work[c] = builder.add_word(work[c], work[d]);
    work[b] = rotate_right(builder.xor_word(work[b], work[c]), 24);
    let a_plus_b = builder.add_word(work[a], work[b]);
    work[a] = builder.add_word(a_plus_b, message_y);
    work[d] = rotate_right(builder.xor_word(work[d], work[a]), 16);
    work[c] = builder.add_word(work[c], work[d]);
    work[b] = rotate_right(builder.xor_word(work[b], work[c]), 63);
}

fn field_add(left: u64, right: u64) -> u64 {
    let modulus = GOLDILOCKS_MODULUS as u128;
    ((left as u128 % modulus + right as u128 % modulus) % modulus) as u64
}

fn field_sub(left: u64, right: u64) -> u64 {
    let modulus = GOLDILOCKS_MODULUS as u128;
    let left = left as u128 % modulus;
    let right = right as u128 % modulus;
    ((left + modulus - right) % modulus) as u64
}

fn field_mul(left: u64, right: u64) -> u64 {
    let modulus = GOLDILOCKS_MODULUS as u128;
    (((left as u128 % modulus) * (right as u128 % modulus)) % modulus) as u64
}

fn field_mul_small(value: u64, scalar: u64) -> u64 {
    field_mul(value, scalar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hegemon_hash384::{blake2b_384, blake2b_384_domain_hash};

    fn hex48(encoded: &str) -> [u8; 48] {
        let decoded = hex::decode(encoded).expect("test vector is valid hex");
        decoded.try_into().expect("test vector has 48 bytes")
    }

    fn hex56(encoded: &str) -> [u8; 56] {
        let decoded = hex::decode(encoded).expect("test vector is valid hex");
        decoded.try_into().expect("test vector has 56 bytes")
    }

    #[test]
    fn rfc7693_blake2b384_known_answers_match() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"",
                "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100",
            ),
            (
                b"abc",
                "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4",
            ),
        ];
        for (message, expected_hex) in cases {
            let trace = blake2b384_relation(message).expect("relation builds");
            let expected = hex48(expected_hex);
            trace.verify_digest(&expected).expect("constraints hold");
            assert_eq!(trace.digest(), blake2b_384(message));
        }
    }

    #[test]
    fn exact_full_and_partial_final_block_vectors_match() {
        let block: Vec<u8> = (0u8..=127).collect();
        let mut block_plus_one = block.clone();
        block_plus_one.push(0x80);
        for (message, expected_hex) in [
            (
                block.as_slice(),
                "a2c2acf7ce4079c02b7f38e2ef33bff531a31a7c7effe712c5348b4d616c0cba9b152679317984ec632d0c70eb11eece",
            ),
            (
                block_plus_one.as_slice(),
                "a95db6e5ccd191793ad20179bfd63e8c7aedf0cc1084549f73127e3fccc738b405ac2a93d692e76214320089121073e5",
            ),
        ] {
            let trace = blake2b384_relation(message).expect("relation builds");
            trace
                .verify_digest(&hex48(expected_hex))
                .expect("constraints and digest hold");
            assert_eq!(trace.digest(), blake2b_384(message));
        }
    }

    #[test]
    fn counters_and_final_flags_cover_empty_and_block_boundary_cases() {
        let empty = blake2b384_relation(b"").expect("empty relation builds");
        assert_eq!(
            empty.blocks(),
            &[Blake2bBlockDescriptor {
                block_index: 0,
                kind: Blake2bBlockKind::Message,
                message_offset: 0,
                absorbed_bytes: 0,
                counter: 0,
                is_final: true,
            }]
        );

        let full = blake2b384_relation(&[0x5a; 128]).expect("full block builds");
        assert_eq!(full.blocks().len(), 1);
        assert_eq!(full.blocks()[0].counter, 128);
        assert!(full.blocks()[0].is_final);

        let split = blake2b384_relation(&[0x5a; 129]).expect("split block builds");
        assert_eq!(split.blocks().len(), 2);
        assert_eq!(split.blocks()[0].counter, 128);
        assert!(!split.blocks()[0].is_final);
        assert_eq!(split.blocks()[1].counter, 129);
        assert_eq!(split.blocks()[1].absorbed_bytes, 1);
        assert!(split.blocks()[1].is_final);
        assert_ne!(full.digest(), split.digest());
    }

    #[test]
    fn byte_and_bit_order_are_little_endian() {
        let trace = blake2b384_relation(&[0x81]).expect("relation builds");
        let actual: Vec<u64> = trace
            .message_bit_wires()
            .iter()
            .map(|wire| trace.witness_values()[wire.index()])
            .collect();
        assert_eq!(actual, vec![1, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(trace.digest(), blake2b_384(&[0x81]));
    }

    #[test]
    fn constraint_geometry_depends_on_length_not_secret_bytes() {
        for length in [1, 127, 128, 129] {
            let zeros = vec![0u8; length];
            let ones = vec![0xffu8; length];
            let zero_trace = blake2b384_relation(&zeros).expect("zero relation builds");
            let one_trace = blake2b384_relation(&ones).expect("one relation builds");
            assert_eq!(zero_trace.gate_counts(), one_trace.gate_counts());
            assert_eq!(
                zero_trace.smallwood_row_accounting(),
                one_trace.smallwood_row_accounting()
            );
            assert_ne!(zero_trace.digest(), one_trace.digest());
        }
    }

    #[test]
    fn domain_frame_matches_consensus_implementation_and_is_unambiguous() {
        let framed =
            blake2b384_framed_message(b"domain-a", [b"ab".as_slice(), b"c"]).expect("frame builds");
        assert_eq!(
            blake2b384_framed_len(b"domain-a".len(), &[2, 1]),
            Ok(framed.len())
        );
        assert_eq!(
            blake2b_compression_block_count(framed.len()),
            framed.len().div_ceil(BLAKE2B_BLOCK_BYTES)
        );
        let trace = blake2b384_domain_relation(b"domain-a", [b"ab".as_slice(), b"c"])
            .expect("relation builds");
        let expected = hex48(
            "b313d1b7ebd77d7ef47bc7623cdfbe2eb2ff36827289ae055c928fc69f2d753519f7c6f03e2210b5a5e4163a4761d343",
        );
        trace.verify_digest(&expected).expect("constraints hold");
        assert_eq!(trace.digest(), blake2b_384(&framed));
        assert_eq!(
            trace.digest(),
            blake2b_384_domain_hash(b"domain-a", [b"ab".as_slice(), b"c"])
        );
        assert_ne!(
            trace.digest(),
            blake2b384_domain_relation(b"domain-a", [b"a".as_slice(), b"bc"])
                .expect("non-alias relation builds")
                .digest()
        );
        assert_ne!(
            trace.digest(),
            blake2b384_domain_relation(b"domain-a", [b"ab".as_slice(), b"c", b""],)
                .expect("empty final part relation builds")
                .digest()
        );
    }

    #[test]
    fn wider_output_reuses_compression_but_changes_parameter_and_binding_width() {
        assert!(matches!(
            blake2b_relation::<0>(b"abc"),
            Err(Blake2bRelationError::InvalidOutputLength(0))
        ));
        assert!(matches!(
            blake2b_relation::<65>(b"abc"),
            Err(Blake2bRelationError::InvalidOutputLength(65))
        ));
        let digest384 = blake2b_relation::<48>(b"abc").expect("384 relation builds");
        let digest512 = blake2b_relation::<64>(b"abc").expect("512 relation builds");
        assert_ne!(digest384.digest().as_slice(), &digest512.digest()[..48]);
        assert_eq!(
            digest384.gate_counts().external_output_binding_constraints,
            384
        );
        assert_eq!(
            digest512.gate_counts().external_output_binding_constraints,
            512
        );
        let counts384 = digest384.gate_counts();
        let counts512 = digest512.gate_counts();
        assert_eq!(
            counts384.input_boolean_constraints,
            counts512.input_boolean_constraints
        );
        assert_eq!(counts384.full_adder_gates, counts512.full_adder_gates);
        // The RFC output-length parameter is a protocol constant. Constant
        // folding can save a handful of XOR/NOT identities for one width, but
        // does not change the ARX addition geometry.
        assert!(
            counts384
                .scalar_constraint_count
                .abs_diff(counts512.scalar_constraint_count)
                <= BLAKE2B_WORD_BITS
        );
    }

    #[test]
    fn rfc7693_blake2b448_keyed_personalized_kat_and_block_semantics() {
        let key = [0x11; 48];
        let personalization = *b"HEG-test-half-01";
        let trace = blake2b_keyed_personalized_relation::<BLAKE2B_448_OUTPUT_BYTES>(
            &key,
            b"keyed payload",
            personalization,
        )
        .expect("keyed relation builds");
        trace
            .verify_digest(&hex56(
                "17717a8ead79718ab6442b2d10d6c3e830fd668463ad566d98ce618e11e8ca9427ab891da9de2f4527b654d6f8272a4d12b0f17064150724",
            ))
            .expect("Python hashlib/RFC 7693 KAT satisfies every constraint");
        trace
            .verify_input_bindings(&key, b"keyed payload")
            .expect("all key and message bits bind to their caller sources");
        assert_eq!(trace.key_len(), 48);
        assert_eq!(trace.key_bit_wires().len(), 48 * 8);
        assert_eq!(trace.message_bit_wires().len(), 13 * 8);
        assert_eq!(trace.personalization(), &personalization);
        assert_eq!(
            trace.blocks(),
            &[
                Blake2bBlockDescriptor {
                    block_index: 0,
                    kind: Blake2bBlockKind::Key,
                    message_offset: 0,
                    absorbed_bytes: 128,
                    counter: 128,
                    is_final: false,
                },
                Blake2bBlockDescriptor {
                    block_index: 1,
                    kind: Blake2bBlockKind::Message,
                    message_offset: 0,
                    absorbed_bytes: 13,
                    counter: 141,
                    is_final: true,
                },
            ]
        );

        let mut key_mutation = trace.clone();
        let wire = key_mutation.key_bit_wires[0];
        key_mutation.witness[wire.index()] ^= 1;
        assert!(key_mutation.verify_constraints().is_err());

        let mut wrong_key = key;
        wrong_key[0] ^= 1;
        assert!(matches!(
            trace.verify_input_bindings(&wrong_key, b"keyed payload"),
            Err(Blake2bRelationError::InputBitMismatch {
                component: "key",
                ..
            })
        ));
        assert!(matches!(
            trace.verify_input_bindings(&key, b"keyed payloae"),
            Err(Blake2bRelationError::InputBitMismatch {
                component: "message",
                ..
            })
        ));
        assert!(matches!(
            trace.verify_input_bindings(&key[..47], b"keyed payload"),
            Err(Blake2bRelationError::InputLengthMismatch {
                component: "key",
                ..
            })
        ));
        let counts = trace.gate_counts();
        let rows = trace.smallwood_row_accounting();
        assert_eq!(counts.external_key_binding_constraints, 48 * 8);
        assert_eq!(counts.external_message_binding_constraints, 13 * 8);
        assert_eq!(counts.external_input_binding_constraints, 61 * 8);
        assert_eq!(counts.external_output_binding_constraints, 56 * 8);
        assert_eq!(counts.external_binding_constraints, 117 * 8);
        assert_eq!(rows.external_input_binding_rows, 8);
        assert_eq!(rows.external_output_binding_rows, 7);
        assert_eq!(rows.external_binding_rows, 15);

        let changed_personalization =
            blake2b_keyed_personalized_relation::<56>(&key, b"keyed payload", *b"HEG-test-half-02")
                .unwrap();
        assert_ne!(trace.digest(), changed_personalization.digest());
        assert!(matches!(
            blake2b_keyed_personalized_relation::<56>(&[], b"payload", personalization),
            Err(Blake2bRelationError::InvalidKeyLength(0))
        ));

        let empty_message =
            blake2b_keyed_personalized_relation::<56>(&key, b"", personalization).unwrap();
        empty_message
            .verify_digest(&hex56(
                "b538644986f7e942c66d1ff3469acc45719002b9c74e434868e66c78159c25656bc9c80858a0eadaf36ba0f68dd602f2962f39565aa84039",
            ))
            .expect("key-only final-block KAT satisfies every constraint");
        assert_eq!(
            empty_message.blocks(),
            &[Blake2bBlockDescriptor {
                block_index: 0,
                kind: Blake2bBlockKind::Key,
                message_offset: 0,
                absorbed_bytes: 128,
                counter: 128,
                is_final: true,
            }]
        );
    }

    #[test]
    fn rfc7693_blake2b448_unkeyed_personalized_kat() {
        let personalization = *b"HEG-test-half-01";
        let trace =
            blake2b_personalized_relation::<BLAKE2B_448_OUTPUT_BYTES>(b"abc", personalization)
                .expect("personalized relation builds");
        trace
            .verify_digest(&hex56(
                "8c29074f8df3b4b2f567956895713f9518067375b619660a7fdba17671653ead99dd3ba56c47473651fafdf6f4c4cfaa4ef95d9da5d42b3b",
            ))
            .expect("Python hashlib/RFC 7693 KAT satisfies every constraint");
        assert_eq!(trace.key_len(), 0);
        assert!(trace.key_bit_wires().is_empty());
        assert_eq!(trace.blocks()[0].kind, Blake2bBlockKind::Message);
    }

    #[test]
    fn full_adder_constraints_cover_all_boolean_inputs() {
        for left in [false, true] {
            for right in [false, true] {
                for carry_in in [false, true] {
                    let mut builder = ConstraintBuilder::new();
                    let left = builder.input_bit(left);
                    let right = builder.input_bit(right);
                    let carry_in = builder.input_bit(carry_in);
                    let (sum, carry_out) = builder.full_adder(left, right, carry_in);
                    for constraint in builder.constraints {
                        assert_eq!(constraint.residual(&builder.witness), Ok(0));
                    }
                    let total = builder.witness[left.wire.index()]
                        + builder.witness[right.wire.index()]
                        + builder.witness[carry_in.wire.index()];
                    assert_eq!(builder.witness[sum.wire.index()], total & 1);
                    assert_eq!(builder.witness[carry_out.wire.index()], total >> 1);
                }
            }
        }
    }

    #[test]
    fn mutations_and_wrong_digest_fail_closed() {
        let trace = blake2b384_relation(b"mutation target").expect("relation builds");
        trace.verify_constraints().expect("honest trace holds");

        let mut non_boolean = trace.clone();
        let input_wire = non_boolean.message_bit_wires[0];
        non_boolean.witness[input_wire.index()] = 2;
        assert!(matches!(
            non_boolean.verify_constraints(),
            Err(Blake2bRelationError::ConstraintViolation {
                kind: Blake2bConstraintKind::Boolean,
                ..
            })
        ));

        let mut non_canonical = trace.clone();
        let input_wire = non_canonical.message_bit_wires[0];
        non_canonical.witness[input_wire.index()] = GOLDILOCKS_MODULUS;
        assert_eq!(
            non_canonical.verify_constraints(),
            Err(Blake2bRelationError::NonCanonicalWitness {
                wire: input_wire.index()
            })
        );

        let mut changed_input = trace.clone();
        let input_wire = changed_input.message_bit_wires[3];
        changed_input.witness[input_wire.index()] ^= 1;
        assert!(changed_input.verify_constraints().is_err());

        let mut changed_output = trace.clone();
        let output_wire = changed_output.digest_bit_wires[0];
        changed_output.witness[output_wire.index()] ^= 1;
        assert!(changed_output.verify_constraints().is_err());

        let mut wrong_digest = trace.digest();
        wrong_digest[0] ^= 1;
        assert_eq!(
            trace.verify_digest(&wrong_digest),
            Err(Blake2bRelationError::DigestMismatch)
        );
    }

    #[test]
    fn every_constraint_family_and_block_metadata_mutation_fails_closed() {
        let trace = blake2b384_relation(&[0xa5; 129]).expect("two-block relation builds");
        let kinds = [
            Blake2bConstraintKind::Constant,
            Blake2bConstraintKind::Boolean,
            Blake2bConstraintKind::Xor,
            Blake2bConstraintKind::Not,
            Blake2bConstraintKind::FullAdderSum,
            Blake2bConstraintKind::FullAdderCarry,
        ];
        for kind in kinds {
            let constraint = trace
                .constraints
                .iter()
                .copied()
                .find(|constraint| constraint.kind() == kind)
                .unwrap_or_else(|| panic!("missing {kind:?} constraint"));
            let output = match constraint {
                Blake2bConstraint::Constant { output, .. } => output,
                Blake2bConstraint::Boolean { wire } => wire,
                Blake2bConstraint::Xor { output, .. } => output,
                Blake2bConstraint::Not { output, .. } => output,
                Blake2bConstraint::FullAdderSum { sum, .. } => sum,
                Blake2bConstraint::FullAdderCarry { carry_out, .. } => carry_out,
            };
            let mut mutated = trace.clone();
            mutated.witness[output.index()] ^= 1;
            assert!(mutated.verify_constraints().is_err(), "{kind:?} mutation");
        }

        let mutators: [fn(&mut Blake2bBlockDescriptor); 4] = [
            |block: &mut Blake2bBlockDescriptor| block.counter ^= 1,
            |block: &mut Blake2bBlockDescriptor| block.is_final = !block.is_final,
            |block: &mut Blake2bBlockDescriptor| block.absorbed_bytes ^= 1,
            |block: &mut Blake2bBlockDescriptor| block.message_offset ^= 1,
        ];
        for mutate in mutators {
            let mut mutated = trace.clone();
            mutate(&mut mutated.blocks[0]);
            assert_eq!(
                mutated.verify_constraints(),
                Err(Blake2bRelationError::BlockScheduleMismatch)
            );
        }
    }

    #[test]
    fn exact_gate_and_row_accounting_is_self_consistent() {
        let cases: &[(&[u8], usize, usize, usize)] = &[
            (b"", 2, 1, 1),
            (b"abc", 95_054, 1_486, 1_486),
            (&[0x42; 128], 99_349, 1_553, 1_553),
            (&[0x42; 129], 198_560, 3_103, 3_103),
        ];
        for (message, exact_scalar_constraints, exact_witness_rows, exact_constraint_rows) in cases
        {
            let trace = blake2b384_relation(message).expect("relation builds");
            let counts = trace.gate_counts();
            let rows = trace.smallwood_row_accounting();
            assert_eq!(counts.input_boolean_constraints, message.len() * 8);
            assert_eq!(counts.external_key_binding_constraints, 0);
            assert_eq!(
                counts.external_message_binding_constraints,
                message.len() * 8
            );
            assert_eq!(counts.external_input_binding_constraints, message.len() * 8);
            assert_eq!(counts.constant_constraints, 2);
            assert_eq!(
                counts.maximum_degree,
                if message.is_empty() { 1 } else { 3 }
            );
            assert_eq!(counts.scalar_constraint_count, *exact_scalar_constraints);
            assert_eq!(rows.witness_rows, *exact_witness_rows);
            assert_eq!(rows.constraint_rows, *exact_constraint_rows);
            assert_eq!(
                counts.linear_constraints + counts.quadratic_constraints + counts.cubic_constraints,
                counts.scalar_constraint_count
            );
            assert_eq!(counts.wire_count, rows.scalar_witness_values);
            assert_eq!(
                rows.witness_rows * rows.packing_factor,
                rows.scalar_witness_values + rows.witness_padding_values
            );
            assert_eq!(
                rows.constraint_rows * rows.packing_factor,
                rows.scalar_constraints + rows.constraint_padding_values
            );
            assert_eq!(rows.external_output_binding_constraints, 384);
            assert_eq!(rows.external_output_binding_rows, 6);
            assert_eq!(rows.external_input_binding_constraints, message.len() * 8);
            assert_eq!(
                rows.external_input_binding_rows,
                (message.len() * 8).div_ceil(SMALLWOOD_BOOLEAN_PACKING_FACTOR)
            );
            assert_eq!(
                rows.external_binding_constraints,
                (message.len() + BLAKE2B_384_OUTPUT_BYTES) * 8
            );
            assert_eq!(
                rows.external_binding_rows,
                ((message.len() + BLAKE2B_384_OUTPUT_BYTES) * 8)
                    .div_ceil(SMALLWOOD_BOOLEAN_PACKING_FACTOR)
            );
        }
        assert_eq!(
            blake2b384_relation(b"abc")
                .expect("relation builds")
                .row_accounting(0),
            Err(Blake2bRelationError::ZeroPackingFactor)
        );
    }
}
