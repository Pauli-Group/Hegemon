use blake3::Hasher;
use hegemon_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::HashMap,
    fmt,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use transaction_core::{
    constants::POSEIDON2_WIDTH,
    poseidon2::{poseidon2_step_ring, Felt},
    range::{RANGE_LIMB_BITS, RANGE_LIMB_COUNT, RANGE_TOP_LIMB_MAX},
};

use crate::{
    error::TransactionCircuitError, smallwood_engine::SmallwoodArithmetization,
    smallwood_frontend::SMALLWOOD_MULTISIG_MAX_SIGNERS,
};

const GOLDILOCKS_MODULUS: u128 = 0xffff_ffff_0000_0001;
const SMALLWOOD_XOF_DOMAIN: &[u8] = b"hegemon.smallwood.f64-xof.v1";

const MAX_INPUTS: usize = 2;
const MAX_OUTPUTS: usize = 2;
const BALANCE_SLOTS: usize = 4;
const MERKLE_DEPTH: usize = 32;
const POSEIDON_STEPS: usize = 31;
const POSEIDON_ROWS_PER_PERMUTATION: usize = POSEIDON_STEPS + 1;
const HASH_LIMBS: usize = 6;
const INLINE_MERKLE_BINDING_SLOTS: usize = MAX_INPUTS * MERKLE_DEPTH * HASH_LIMBS;
const INLINE_MERKLE_ROWS_PER_GROUP: usize = 4;
const INLINE_POLICY_BINDING_ROWS: usize = 3;
const INPUT_ROWS: usize = 130;
const PUBLIC_ROWS: usize = 0;
const PUBLIC_VALUE_COUNT: usize = 78;
const SIGNER_TAG_WORDS: usize = 5;
const MULTISIG_MAX_SIGNERS: usize = SMALLWOOD_MULTISIG_MAX_SIGNERS;
const MULTISIG_PAIR_COUNT: usize = MULTISIG_MAX_SIGNERS * (MULTISIG_MAX_SIGNERS - 1) / 2;
const AUTH_MODE_ROWS: usize = 3;
const AUTH_INPUT_PRF_ROWS: usize = MAX_INPUTS;
const AUTH_INPUT_KEY_ROWS: usize = MAX_INPUTS * 4;
const AUTH_LEGACY_DIGEST_ROWS: usize = 5;
const AUTH_ACCUMULATOR_DIGEST_ROWS: usize = HASH_LIMBS;
const AUTH_NEXT_ACCUMULATOR_DIGEST_ROWS: usize = HASH_LIMBS;
const AUTH_VALUE_LOCK_DIGEST_ROWS: usize = HASH_LIMBS;
const AUTH_STATEMENT_DIGEST_ROWS: usize = HASH_LIMBS;
const AUTH_POLICY_ROWS: usize = HASH_LIMBS;
const AUTH_INTENT_ROWS: usize = HASH_LIMBS;
const AUTH_SCALAR_ROWS: usize = 4 + (MULTISIG_MAX_SIGNERS * 2) + 2;
const AUTH_THRESHOLD_FLAG_ROWS: usize = MULTISIG_MAX_SIGNERS;
const AUTH_SIGNER_COUNT_FLAG_ROWS: usize = MULTISIG_MAX_SIGNERS;
const AUTH_COUNT_FLAG_ROWS: usize = MULTISIG_MAX_SIGNERS + 1;
const AUTH_NEXT_COUNT_FLAG_ROWS: usize = MULTISIG_MAX_SIGNERS + 1;
const AUTH_POLICY_SIGNER_ROWS: usize = MULTISIG_MAX_SIGNERS * SIGNER_TAG_WORDS;
const AUTH_MEMBERSHIP_FLAG_ROWS: usize = MULTISIG_MAX_SIGNERS;
const AUTH_POLICY_DISTINCT_INVERSE_ROWS: usize = MULTISIG_PAIR_COUNT;
const OUTPUT_AUTH_KEY_ROWS: usize = 4;
const AUTH_ROWS: usize = AUTH_MODE_ROWS
    + AUTH_INPUT_PRF_ROWS
    + AUTH_INPUT_KEY_ROWS
    + AUTH_LEGACY_DIGEST_ROWS
    + AUTH_ACCUMULATOR_DIGEST_ROWS
    + AUTH_NEXT_ACCUMULATOR_DIGEST_ROWS
    + AUTH_VALUE_LOCK_DIGEST_ROWS
    + AUTH_STATEMENT_DIGEST_ROWS
    + AUTH_POLICY_ROWS
    + AUTH_INTENT_ROWS
    + AUTH_SCALAR_ROWS
    + AUTH_THRESHOLD_FLAG_ROWS
    + AUTH_SIGNER_COUNT_FLAG_ROWS
    + AUTH_COUNT_FLAG_ROWS
    + AUTH_NEXT_COUNT_FLAG_ROWS
    + AUTH_POLICY_SIGNER_ROWS
    + AUTH_MEMBERSHIP_FLAG_ROWS
    + AUTH_POLICY_DISTINCT_INVERSE_ROWS;
const INPUT_PERMUTATIONS: usize = 3 + MERKLE_DEPTH * 2 + 1;
const OUTPUT_PERMUTATIONS: usize = 3;
const AUTH_INTENT_PERMUTATIONS: usize = PUBLIC_VALUE_COUNT.div_ceil(6);
const AUTH_ACCUMULATOR_INPUTS: usize = HASH_LIMBS * 2 + 3 + MULTISIG_MAX_SIGNERS;
const AUTH_ACCUMULATOR_PERMUTATIONS: usize = AUTH_ACCUMULATOR_INPUTS.div_ceil(6);
const AUTH_POLICY_INPUTS: usize = 2 + AUTH_POLICY_SIGNER_ROWS;
const AUTH_POLICY_PERMUTATIONS: usize = AUTH_POLICY_INPUTS.div_ceil(6);
const AUTH_VALUE_LOCK_INPUTS: usize = HASH_LIMBS * 2;
const AUTH_VALUE_LOCK_PERMUTATIONS: usize = AUTH_VALUE_LOCK_INPUTS.div_ceil(6);
const AUTH_POSEIDON_PERMUTATIONS: usize = AUTH_INTENT_PERMUTATIONS
    + AUTH_POLICY_PERMUTATIONS
    + AUTH_ACCUMULATOR_PERMUTATIONS * 2
    + AUTH_VALUE_LOCK_PERMUTATIONS;
const AUTH_CONSTRAINTS: usize = 374;
const POSEIDON_PERMUTATION_COUNT: usize = 1
    + MAX_INPUTS * INPUT_PERMUTATIONS
    + MAX_OUTPUTS * OUTPUT_PERMUTATIONS
    + AUTH_POSEIDON_PERMUTATIONS;
const PUB_INPUT_FLAG0: usize = 0;
const PUB_OUTPUT_FLAG0: usize = 2;
const PUB_CIPHERTEXT_HASHES: usize = 28;
const PUB_FEE: usize = 40;
const PUB_VALUE_BALANCE_SIGN: usize = 41;
const PUB_VALUE_BALANCE_MAG: usize = 42;
const PUB_SLOT_ASSETS: usize = 49;
const PUB_STABLE_ENABLED: usize = 53;
const PUB_STABLE_ASSET: usize = 54;
const PUB_STABLE_POLICY_VERSION: usize = 55;
const PUB_STABLE_ISSUANCE_SIGN: usize = 56;
const PUB_STABLE_ISSUANCE_MAG: usize = 57;
const PUB_STABLE_POLICY_HASH: usize = 58;
const PUB_STABLE_ORACLE: usize = 64;
const PUB_STABLE_ATTESTATION: usize = 70;
const EFFECTIVE_CONSTRAINT_DEGREE: usize = 8;
const BASE_INPUT_ROWS: usize = 1 + 1 + MERKLE_DEPTH;
const PUBLIC_VALUE_RANGE_VALUE_COUNT: usize = 3;
const VALUE_RANGE_VALUE_COUNT: usize = MAX_INPUTS + MAX_OUTPUTS + PUBLIC_VALUE_RANGE_VALUE_COUNT;
const VALUE_RANGE_ROWS: usize = VALUE_RANGE_VALUE_COUNT * RANGE_LIMB_COUNT;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SmallwoodConstraintExpression {
    Constant(u64),
    PublicValue(u32),
    WitnessRow(u32),
    SlotDenominatorInverse(u8),
    StableSelectorBit(u8),
    Add { left: u32, right: u32 },
    Sub { left: u32, right: u32 },
    Mul { left: u32, right: u32 },
    Neg { value: u32 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodProductionConstraintProgram {
    pub public_value_count: usize,
    pub witness_row_count: usize,
    pub packing_factor: usize,
    pub nonlinear_constraint_count: usize,
    pub expressions: Vec<SmallwoodConstraintExpression>,
    pub constraint_roots: Vec<u32>,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SmallwoodProductionConstraintFamilyRange {
    pub name: &'static str,
    pub start: usize,
    pub count: usize,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
struct SymbolicValue(u32);

impl fmt::Debug for SymbolicValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "e{}", self.0)
    }
}

struct SymbolicArena {
    expressions: Vec<SmallwoodConstraintExpression>,
    interned: HashMap<SmallwoodConstraintExpression, u32>,
}

impl SymbolicArena {
    fn new() -> Self {
        let mut arena = Self {
            expressions: Vec::new(),
            interned: HashMap::new(),
        };
        for value in [0, 1, 2, hegemon_field::GOLDILOCKS_MODULUS - 1] {
            arena.intern(SmallwoodConstraintExpression::Constant(value));
        }
        arena
    }

    fn intern(&mut self, expression: SmallwoodConstraintExpression) -> SymbolicValue {
        if let Some(index) = self.interned.get(&expression) {
            return SymbolicValue(*index);
        }
        let index = u32::try_from(self.expressions.len())
            .expect("SmallWood symbolic expression table fits u32");
        self.expressions.push(expression);
        self.interned.insert(expression, index);
        SymbolicValue(index)
    }
}

thread_local! {
    static SYMBOLIC_ARENA: RefCell<Option<SymbolicArena>> = const { RefCell::new(None) };
}

impl SymbolicValue {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);
    const TWO: Self = Self(2);
    const NEG_ONE: Self = Self(3);

    fn intern(expression: SmallwoodConstraintExpression) -> Self {
        SYMBOLIC_ARENA.with(|slot| {
            slot.borrow_mut()
                .as_mut()
                .expect("SmallWood symbolic arena is active")
                .intern(expression)
        })
    }

    fn public_value(index: usize) -> Self {
        Self::intern(SmallwoodConstraintExpression::PublicValue(
            u32::try_from(index).expect("SmallWood public index fits u32"),
        ))
    }

    fn witness_row(index: usize) -> Self {
        Self::intern(SmallwoodConstraintExpression::WitnessRow(
            u32::try_from(index).expect("SmallWood witness row index fits u32"),
        ))
    }

    fn slot_denominator_inverse(slot: usize) -> Self {
        Self::intern(SmallwoodConstraintExpression::SlotDenominatorInverse(
            u8::try_from(slot).expect("SmallWood slot index fits u8"),
        ))
    }

    fn stable_selector_bit(bit: usize) -> Self {
        Self::intern(SmallwoodConstraintExpression::StableSelectorBit(
            u8::try_from(bit).expect("SmallWood stable selector bit fits u8"),
        ))
    }
}

impl Add for SymbolicValue {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        if self == Self::ZERO {
            return rhs;
        }
        if rhs == Self::ZERO {
            return self;
        }
        let (left, right) = if self.0 <= rhs.0 {
            (self.0, rhs.0)
        } else {
            (rhs.0, self.0)
        };
        Self::intern(SmallwoodConstraintExpression::Add { left, right })
    }
}

impl AddAssign for SymbolicValue {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for SymbolicValue {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        if rhs == Self::ZERO {
            return self;
        }
        if self == rhs {
            return Self::ZERO;
        }
        Self::intern(SmallwoodConstraintExpression::Sub {
            left: self.0,
            right: rhs.0,
        })
    }
}

impl SubAssign for SymbolicValue {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for SymbolicValue {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        if self == Self::ZERO || rhs == Self::ZERO {
            return Self::ZERO;
        }
        if self == Self::ONE {
            return rhs;
        }
        if rhs == Self::ONE {
            return self;
        }
        let (left, right) = if self.0 <= rhs.0 {
            (self.0, rhs.0)
        } else {
            (rhs.0, self.0)
        };
        Self::intern(SmallwoodConstraintExpression::Mul { left, right })
    }
}

impl MulAssign for SymbolicValue {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Neg for SymbolicValue {
    type Output = Self;

    fn neg(self) -> Self::Output {
        if self == Self::ZERO {
            return self;
        }
        Self::intern(SmallwoodConstraintExpression::Neg { value: self.0 })
    }
}

impl Sum for SymbolicValue {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}

impl<'a> Sum<&'a SymbolicValue> for SymbolicValue {
    fn sum<I: Iterator<Item = &'a SymbolicValue>>(iter: I) -> Self {
        iter.copied().sum()
    }
}

impl Product for SymbolicValue {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, Mul::mul)
    }
}

impl<'a> Product<&'a SymbolicValue> for SymbolicValue {
    fn product<I: Iterator<Item = &'a SymbolicValue>>(iter: I) -> Self {
        iter.copied().product()
    }
}

impl PrimeCharacteristicRing for SymbolicValue {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;
    const TWO: Self = Self::TWO;
    const NEG_ONE: Self = Self::NEG_ONE;

    fn from_bool(value: bool) -> Self {
        if value {
            Self::ONE
        } else {
            Self::ZERO
        }
    }

    fn from_u64(value: u64) -> Self {
        Self::intern(SmallwoodConstraintExpression::Constant(
            value % hegemon_field::GOLDILOCKS_MODULUS,
        ))
    }
}

#[derive(Clone, Copy)]
struct PackedRowLayout {
    input_rows: usize,
    output_rows: usize,
    stable_binding_rows: usize,
    value_range_rows: usize,
    inline_merkle_aggregates: bool,
    committed_inline_bindings: bool,
    poseidon_rows_per_permutation: usize,
    skip_initial_mds_poseidon: bool,
}

impl PackedRowLayout {
    const fn for_arithmetization(arithmetization: SmallwoodArithmetization) -> Self {
        match arithmetization {
            SmallwoodArithmetization::Bridge64V1 | SmallwoodArithmetization::DirectPacked64V1 => {
                Self {
                    input_rows: INPUT_ROWS,
                    output_rows: 2 + HASH_LIMBS + OUTPUT_AUTH_KEY_ROWS,
                    stable_binding_rows: 1 + (HASH_LIMBS * 3),
                    value_range_rows: 0,
                    inline_merkle_aggregates: false,
                    committed_inline_bindings: false,
                    poseidon_rows_per_permutation: POSEIDON_ROWS_PER_PERMUTATION,
                    skip_initial_mds_poseidon: false,
                }
            }
            SmallwoodArithmetization::DirectPacked64CompactBindingsV1
            | SmallwoodArithmetization::DirectPacked128CompactBindingsV1
            | SmallwoodArithmetization::DirectPacked16CompactBindingsV1
            | SmallwoodArithmetization::DirectPacked32CompactBindingsV1 => Self {
                input_rows: INPUT_ROWS,
                output_rows: 2 + OUTPUT_AUTH_KEY_ROWS,
                stable_binding_rows: 0,
                value_range_rows: 0,
                inline_merkle_aggregates: false,
                committed_inline_bindings: false,
                poseidon_rows_per_permutation: POSEIDON_ROWS_PER_PERMUTATION,
                skip_initial_mds_poseidon: false,
            },
            SmallwoodArithmetization::DirectPacked64CompactBindingsSkipInitialMdsV1 => Self {
                input_rows: INPUT_ROWS,
                output_rows: 2 + OUTPUT_AUTH_KEY_ROWS,
                stable_binding_rows: 0,
                value_range_rows: 0,
                inline_merkle_aggregates: false,
                committed_inline_bindings: false,
                poseidon_rows_per_permutation: POSEIDON_ROWS_PER_PERMUTATION - 1,
                skip_initial_mds_poseidon: true,
            },
            SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
            | SmallwoodArithmetization::DirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1 => {
                Self {
                    input_rows: BASE_INPUT_ROWS,
                    output_rows: 2 + HASH_LIMBS + OUTPUT_AUTH_KEY_ROWS,
                    stable_binding_rows: 0,
                    value_range_rows: 0,
                    inline_merkle_aggregates: true,
                    committed_inline_bindings: false,
                    poseidon_rows_per_permutation: POSEIDON_ROWS_PER_PERMUTATION - 1,
                    skip_initial_mds_poseidon: true,
                }
            }
            SmallwoodArithmetization::DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2 => {
                Self {
                    input_rows: BASE_INPUT_ROWS,
                    output_rows: 2 + HASH_LIMBS + OUTPUT_AUTH_KEY_ROWS,
                    stable_binding_rows: 0,
                    value_range_rows: VALUE_RANGE_ROWS,
                    inline_merkle_aggregates: true,
                    committed_inline_bindings: true,
                    poseidon_rows_per_permutation: POSEIDON_ROWS_PER_PERMUTATION - 1,
                    skip_initial_mds_poseidon: true,
                }
            }
        }
    }

    const fn secret_rows(self) -> usize {
        (MAX_INPUTS * self.input_rows)
            + (MAX_OUTPUTS * self.output_rows)
            + self.stable_binding_rows
            + self.value_range_rows
            + AUTH_ROWS
    }

    const fn poseidon_transition_count(self) -> usize {
        self.poseidon_rows_per_permutation - 1
    }

    const fn poseidon_last_row(self) -> usize {
        self.poseidon_rows_per_permutation - 1
    }

    const fn poseidon_trace_row(self, logical_row: usize) -> usize {
        if self.skip_initial_mds_poseidon {
            if logical_row == 0 {
                0
            } else {
                logical_row + 1
            }
        } else {
            logical_row
        }
    }

    const fn input_current_offset(self) -> Option<usize> {
        if self.inline_merkle_aggregates {
            None
        } else {
            Some(BASE_INPUT_ROWS)
        }
    }

    const fn input_left_offset(self) -> Option<usize> {
        if self.inline_merkle_aggregates {
            None
        } else {
            Some(BASE_INPUT_ROWS + MERKLE_DEPTH)
        }
    }

    const fn input_right_offset(self) -> Option<usize> {
        if self.inline_merkle_aggregates {
            None
        } else {
            Some(BASE_INPUT_ROWS + MERKLE_DEPTH * 2)
        }
    }
}

#[derive(Clone)]
pub(crate) struct PackedStatement<'a> {
    arithmetization: SmallwoodArithmetization,
    public_values: &'a [u64],
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    linear_constraint_count: usize,
    constraint_count: usize,
    linear_constraint_offsets: &'a [u32],
    linear_constraint_indices: &'a [u32],
    linear_constraint_coefficients: &'a [u64],
    linear_constraint_targets: &'a [u64],
    auxiliary_words: &'a [u64],
    auxiliary_limb_count: usize,
    output_ciphertext_challenges: [Felt; MAX_OUTPUTS],
    slot_denominator_inverses: [Felt; BALANCE_SLOTS],
    stable_selector_bits: [Felt; 2],
    stable_policy_hash_challenge: Felt,
    stable_oracle_challenge: Felt,
    stable_attestation_challenge: Felt,
    poseidon_transition_challenges: Vec<Felt>,
}

pub(crate) fn test_candidate_witness_rust(
    arithmetization: SmallwoodArithmetization,
    public_values: &[u64],
    witness_values: &[u64],
    row_count: usize,
    packing_factor: usize,
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
) -> Result<(), TransactionCircuitError> {
    test_candidate_witness_with_auxiliary_rust(
        arithmetization,
        public_values,
        witness_values,
        row_count,
        packing_factor,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
        &[],
    )
}

pub(crate) fn test_candidate_witness_with_auxiliary_rust(
    arithmetization: SmallwoodArithmetization,
    public_values: &[u64],
    witness_values: &[u64],
    row_count: usize,
    packing_factor: usize,
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
    auxiliary_words: &[u64],
) -> Result<(), TransactionCircuitError> {
    if packing_factor == 0 || row_count == 0 {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "unsupported smallwood packing_factor {packing_factor}"
        )));
    }
    if witness_values.len() != row_count * packing_factor {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood witness length {} does not match rows {} x packing {}",
            witness_values.len(),
            row_count,
            packing_factor
        )));
    }
    if linear_constraint_offsets.len() != linear_constraint_targets.len() + 1 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood linear-constraint offset/target mismatch",
        ));
    }
    let statement = PackedStatement::new(
        arithmetization,
        public_values,
        row_count,
        packing_factor,
        EFFECTIVE_CONSTRAINT_DEGREE,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    );
    let constraint_count = statement.constraint_count();
    let mut lane_rows = vec![Felt::ZERO; row_count];
    let mut constraint_row = vec![Felt::ZERO; constraint_count];
    let felt_auxiliary = auxiliary_words
        .iter()
        .copied()
        .map(Felt::from_u64)
        .collect::<Vec<_>>();

    for lane in 0..packing_factor {
        for row in 0..row_count {
            lane_rows[row] = Felt::from_u64(witness_values[row * packing_factor + lane]);
        }
        compute_constraints(&statement, &lane_rows, &felt_auxiliary, &mut constraint_row);
        if let Some((idx, value)) = constraint_row
            .iter()
            .enumerate()
            .find(|(_, value)| **value != Felt::ZERO)
        {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood packed witness poly constraint failed at lane {lane}, constraint {idx}, value {}",
                value.as_canonical_u64()
            )));
        }
    }

    verify_linear_constraints(
        witness_values,
        auxiliary_words,
        witness_values.len(),
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    )?;
    Ok(())
}

fn verify_linear_constraints(
    witness_values: &[u64],
    auxiliary_words: &[u64],
    witness_size: usize,
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
) -> Result<(), TransactionCircuitError> {
    for check in 0..linear_constraint_targets.len() {
        let start = linear_constraint_offsets[check] as usize;
        let end = linear_constraint_offsets[check + 1] as usize;
        let mut acc = Felt::ZERO;
        for term_idx in start..end {
            let idx = linear_constraint_indices[term_idx] as usize;
            let coeff = Felt::from_u64(linear_constraint_coefficients[term_idx]);
            let value = if idx < witness_size {
                witness_values[idx]
            } else {
                let aux_idx = idx - witness_size;
                *auxiliary_words.get(aux_idx).ok_or_else(|| {
                    TransactionCircuitError::ConstraintViolationOwned(format!(
                        "smallwood packed witness linear constraint auxiliary index out of range at constraint {check}: idx={idx} witness_size={witness_size} auxiliary_len={}",
                        auxiliary_words.len()
                    ))
                })?
            };
            acc += coeff * Felt::from_u64(value);
        }
        let expected = Felt::from_u64(linear_constraint_targets[check]);
        if acc != expected {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood packed witness linear constraint failed at constraint {check}: got {}, expected {}",
                acc.as_canonical_u64(),
                expected.as_canonical_u64()
            )));
        }
    }
    Ok(())
}

#[inline]
fn poseidon_group_count(packing_factor: usize) -> usize {
    POSEIDON_PERMUTATION_COUNT.div_ceil(packing_factor)
}

#[allow(dead_code)]
impl<'a> PackedStatement<'a> {
    pub(crate) fn new(
        arithmetization: SmallwoodArithmetization,
        public_values: &'a [u64],
        row_count: usize,
        packing_factor: usize,
        constraint_degree: usize,
        linear_constraint_offsets: &'a [u32],
        linear_constraint_indices: &'a [u32],
        linear_constraint_coefficients: &'a [u64],
        linear_constraint_targets: &'a [u64],
    ) -> Self {
        Self::new_with_auxiliary(
            arithmetization,
            public_values,
            row_count,
            packing_factor,
            constraint_degree,
            linear_constraint_offsets,
            linear_constraint_indices,
            linear_constraint_coefficients,
            linear_constraint_targets,
            &[],
            0,
        )
    }

    pub(crate) fn new_with_auxiliary(
        arithmetization: SmallwoodArithmetization,
        public_values: &'a [u64],
        row_count: usize,
        packing_factor: usize,
        constraint_degree: usize,
        linear_constraint_offsets: &'a [u32],
        linear_constraint_indices: &'a [u32],
        linear_constraint_coefficients: &'a [u64],
        linear_constraint_targets: &'a [u64],
        auxiliary_words: &'a [u64],
        auxiliary_limb_count: usize,
    ) -> Self {
        let mut statement = Self {
            arithmetization,
            public_values,
            row_count,
            packing_factor,
            constraint_degree,
            linear_constraint_count: linear_constraint_targets.len(),
            constraint_count: constraint_count(arithmetization, packing_factor),
            linear_constraint_offsets,
            linear_constraint_indices,
            linear_constraint_coefficients,
            linear_constraint_targets,
            auxiliary_words,
            auxiliary_limb_count,
            output_ciphertext_challenges: [Felt::ZERO; MAX_OUTPUTS],
            slot_denominator_inverses: derive_slot_denominator_inverses(public_values),
            stable_selector_bits: derive_stable_selector_bits(public_values),
            stable_policy_hash_challenge: Felt::ZERO,
            stable_oracle_challenge: Felt::ZERO,
            stable_attestation_challenge: Felt::ZERO,
            poseidon_transition_challenges: vec![
                Felt::ZERO;
                poseidon_group_count(packing_factor)
                    * PackedRowLayout::for_arithmetization(
                        arithmetization
                    )
                    .poseidon_transition_count()
            ],
        };
        for output in 0..MAX_OUTPUTS {
            statement.output_ciphertext_challenges[output] =
                nontrivial_challenge(&statement, 5, output as u64, 0);
        }
        statement.stable_policy_hash_challenge = nontrivial_challenge(&statement, 6, 0, 0);
        statement.stable_oracle_challenge = nontrivial_challenge(&statement, 7, 0, 0);
        statement.stable_attestation_challenge = nontrivial_challenge(&statement, 8, 0, 0);
        let layout = PackedRowLayout::for_arithmetization(arithmetization);
        for group in 0..poseidon_group_count(packing_factor) {
            for step in 0..layout.poseidon_transition_count() {
                let idx = poseidon_transition_challenge_index(layout, group, step);
                statement.poseidon_transition_challenges[idx] =
                    nontrivial_challenge(&statement, 11, group as u64, step as u64);
            }
        }
        statement
    }

    pub(crate) fn row_count(&self) -> usize {
        self.row_count
    }

    pub(crate) fn packing_factor(&self) -> usize {
        self.packing_factor
    }

    pub(crate) fn constraint_degree(&self) -> usize {
        self.constraint_degree
    }

    pub(crate) fn linear_constraint_count(&self) -> usize {
        self.linear_constraint_count
    }

    pub(crate) fn constraint_count(&self) -> usize {
        self.constraint_count
    }

    pub(crate) fn linear_targets(&self) -> &[u64] {
        self.linear_constraint_targets
    }

    pub(crate) fn linear_constraint_offsets(&self) -> &[u32] {
        self.linear_constraint_offsets
    }

    pub(crate) fn linear_constraint_indices(&self) -> &[u32] {
        self.linear_constraint_indices
    }

    pub(crate) fn linear_constraint_coefficients(&self) -> &[u64] {
        self.linear_constraint_coefficients
    }

    pub(crate) fn arithmetization(&self) -> SmallwoodArithmetization {
        self.arithmetization
    }
}

pub trait SmallwoodConstraintAdapter: Sync {
    fn arithmetization(&self) -> SmallwoodArithmetization;
    fn row_count(&self) -> usize;
    fn packing_factor(&self) -> usize;
    fn constraint_degree(&self) -> usize;
    fn linear_constraint_count(&self) -> usize;
    fn constraint_count(&self) -> usize;
    fn linear_constraint_offsets(&self) -> &[u32];
    fn linear_constraint_indices(&self) -> &[u32];
    fn linear_constraint_coefficients(&self) -> &[u64];
    fn linear_targets(&self) -> &[u64];
    fn auxiliary_witness_words(&self) -> &[u64];
    fn auxiliary_witness_limb_count(&self) -> Option<usize>;
    fn linear_constraint_form(&self) -> SmallwoodLinearConstraintForm {
        SmallwoodLinearConstraintForm::Generic
    }
    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        row_scalars: &'a [u64],
        auxiliary_words: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a>;
    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodLinearConstraintForm {
    Generic,
    IdentityWitness,
}

#[derive(Clone, Copy, Debug)]
pub enum SmallwoodNonlinearEvalView<'a> {
    RowScalars {
        eval_point: u64,
        rows: &'a [u64],
        auxiliary_words: &'a [u64],
    },
}

impl<'a> SmallwoodConstraintAdapter for PackedStatement<'a> {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        self.arithmetization
    }

    fn row_count(&self) -> usize {
        self.row_count
    }

    fn packing_factor(&self) -> usize {
        self.packing_factor
    }

    fn constraint_degree(&self) -> usize {
        self.constraint_degree
    }

    fn linear_constraint_count(&self) -> usize {
        self.linear_constraint_count
    }

    fn constraint_count(&self) -> usize {
        self.constraint_count
    }

    fn linear_constraint_offsets(&self) -> &[u32] {
        self.linear_constraint_offsets
    }

    fn linear_constraint_indices(&self) -> &[u32] {
        self.linear_constraint_indices
    }

    fn linear_constraint_coefficients(&self) -> &[u64] {
        self.linear_constraint_coefficients
    }

    fn linear_targets(&self) -> &[u64] {
        self.linear_constraint_targets
    }

    fn auxiliary_witness_words(&self) -> &[u64] {
        self.auxiliary_words
    }

    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(self.auxiliary_limb_count)
    }

    fn nonlinear_eval_view<'b>(
        &self,
        eval_point: u64,
        row_scalars: &'b [u64],
        auxiliary_words: &'b [u64],
    ) -> SmallwoodNonlinearEvalView<'b> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows: row_scalars,
            auxiliary_words,
        }
    }

    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        compute_bridge_constraints_u64(self, view, out)
    }
}

fn xof_words(input_words: &[u64], output_words: &mut [u64]) {
    let mut hasher = Hasher::new();
    hasher.update(SMALLWOOD_XOF_DOMAIN);
    hasher.update(&(input_words.len() as u64).to_le_bytes());
    for word in input_words {
        hasher.update(&word.to_le_bytes());
    }
    let mut reader = hasher.finalize_xof();
    for output in output_words {
        let mut buf = [0u8; 16];
        reader.fill(&mut buf);
        *output = (u128::from_le_bytes(buf) % GOLDILOCKS_MODULUS) as u64;
    }
}

fn nontrivial_challenge(statement: &PackedStatement<'_>, tag: u64, a: u64, b: u64) -> Felt {
    let mut input = Vec::with_capacity(PUBLIC_VALUE_COUNT + 4);
    input.push(0x736d_616c_6c77_6f6f);
    input.push(tag);
    input.push(a);
    input.push(b);
    input.extend_from_slice(statement.public_values);
    let mut output = [0u64; 1];
    xof_words(&input, &mut output);
    if output[0] <= 1 {
        output[0] += 2;
    }
    Felt::from_u64(output[0])
}

#[inline]
fn row_input_base(statement: &PackedStatement<'_>, input: usize) -> usize {
    let layout = PackedRowLayout::for_arithmetization(statement.arithmetization);
    PUBLIC_ROWS + input * layout.input_rows
}

#[inline]
fn row_input_direction(statement: &PackedStatement<'_>, input: usize, bit: usize) -> usize {
    row_input_base(statement, input) + 2 + bit
}

#[inline]
fn row_input_value(statement: &PackedStatement<'_>, input: usize) -> usize {
    row_input_base(statement, input)
}

#[inline]
fn row_input_asset(statement: &PackedStatement<'_>, input: usize) -> usize {
    row_input_base(statement, input) + 1
}

#[inline]
fn row_input_current_agg(statement: &PackedStatement<'_>, input: usize, level: usize) -> usize {
    let layout = PackedRowLayout::for_arithmetization(statement.arithmetization);
    row_input_base(statement, input)
        + layout.input_current_offset().expect("merkle rows present")
        + level
}

#[inline]
fn row_input_left_agg(statement: &PackedStatement<'_>, input: usize, level: usize) -> usize {
    let layout = PackedRowLayout::for_arithmetization(statement.arithmetization);
    row_input_base(statement, input)
        + layout.input_left_offset().expect("merkle rows present")
        + level
}

#[inline]
fn row_input_right_agg(statement: &PackedStatement<'_>, input: usize, level: usize) -> usize {
    let layout = PackedRowLayout::for_arithmetization(statement.arithmetization);
    row_input_base(statement, input)
        + layout.input_right_offset().expect("merkle rows present")
        + level
}

#[inline]
fn row_output_base(statement: &PackedStatement<'_>, output: usize) -> usize {
    let layout = PackedRowLayout::for_arithmetization(statement.arithmetization);
    PUBLIC_ROWS + MAX_INPUTS * layout.input_rows + output * layout.output_rows
}

#[inline]
fn row_output_value(statement: &PackedStatement<'_>, output: usize) -> usize {
    row_output_base(statement, output)
}

#[inline]
fn row_output_asset(statement: &PackedStatement<'_>, output: usize) -> usize {
    row_output_base(statement, output) + 1
}

#[inline]
fn row_output_auth_key(statement: &PackedStatement<'_>, output: usize, limb: usize) -> usize {
    let layout = PackedRowLayout::for_arithmetization(statement.arithmetization);
    row_output_base(statement, output) + layout.output_rows - OUTPUT_AUTH_KEY_ROWS + limb
}

#[inline]
fn row_value_range_base(statement: &PackedStatement<'_>) -> usize {
    let layout = PackedRowLayout::for_arithmetization(statement.arithmetization);
    PUBLIC_ROWS
        + MAX_INPUTS * layout.input_rows
        + MAX_OUTPUTS * layout.output_rows
        + layout.stable_binding_rows
}

#[inline]
fn row_input_value_range_limb(statement: &PackedStatement<'_>, input: usize, limb: usize) -> usize {
    debug_assert!(
        PackedRowLayout::for_arithmetization(statement.arithmetization).value_range_rows > 0
    );
    row_value_range_base(statement) + input * RANGE_LIMB_COUNT + limb
}

#[inline]
fn row_output_value_range_limb(
    statement: &PackedStatement<'_>,
    output: usize,
    limb: usize,
) -> usize {
    debug_assert!(
        PackedRowLayout::for_arithmetization(statement.arithmetization).value_range_rows > 0
    );
    row_value_range_base(statement) + (MAX_INPUTS + output) * RANGE_LIMB_COUNT + limb
}

#[inline]
fn row_public_value_range_limb(
    statement: &PackedStatement<'_>,
    public_value: usize,
    limb: usize,
) -> usize {
    debug_assert!(
        PackedRowLayout::for_arithmetization(statement.arithmetization).value_range_rows > 0
    );
    debug_assert!(public_value < PUBLIC_VALUE_RANGE_VALUE_COUNT);
    row_value_range_base(statement)
        + (MAX_INPUTS + MAX_OUTPUTS + public_value) * RANGE_LIMB_COUNT
        + limb
}

#[inline]
fn row_auth_base(statement: &PackedStatement<'_>) -> usize {
    let layout = PackedRowLayout::for_arithmetization(statement.arithmetization);
    row_value_range_base(statement) + layout.value_range_rows
}

#[inline]
fn row_auth_mode(statement: &PackedStatement<'_>, mode: usize) -> usize {
    row_auth_base(statement) + mode
}

#[inline]
fn row_auth_input_prf(statement: &PackedStatement<'_>, input: usize) -> usize {
    row_auth_base(statement) + AUTH_MODE_ROWS + input
}

#[inline]
fn row_auth_input_key(statement: &PackedStatement<'_>, input: usize, limb: usize) -> usize {
    row_auth_base(statement) + AUTH_MODE_ROWS + AUTH_INPUT_PRF_ROWS + input * 4 + limb
}

#[inline]
fn row_auth_legacy_digest(statement: &PackedStatement<'_>, limb: usize) -> usize {
    row_auth_base(statement) + AUTH_MODE_ROWS + AUTH_INPUT_PRF_ROWS + AUTH_INPUT_KEY_ROWS + limb
}

#[inline]
fn row_auth_current_digest(statement: &PackedStatement<'_>, limb: usize) -> usize {
    row_auth_base(statement)
        + AUTH_MODE_ROWS
        + AUTH_INPUT_PRF_ROWS
        + AUTH_INPUT_KEY_ROWS
        + AUTH_LEGACY_DIGEST_ROWS
        + limb
}

#[inline]
fn row_auth_next_digest(statement: &PackedStatement<'_>, limb: usize) -> usize {
    row_auth_base(statement)
        + AUTH_MODE_ROWS
        + AUTH_INPUT_PRF_ROWS
        + AUTH_INPUT_KEY_ROWS
        + AUTH_LEGACY_DIGEST_ROWS
        + AUTH_ACCUMULATOR_DIGEST_ROWS
        + limb
}

#[inline]
fn row_auth_value_lock_digest(statement: &PackedStatement<'_>, limb: usize) -> usize {
    row_auth_base(statement)
        + AUTH_MODE_ROWS
        + AUTH_INPUT_PRF_ROWS
        + AUTH_INPUT_KEY_ROWS
        + AUTH_LEGACY_DIGEST_ROWS
        + AUTH_ACCUMULATOR_DIGEST_ROWS
        + AUTH_NEXT_ACCUMULATOR_DIGEST_ROWS
        + limb
}

#[inline]
fn row_auth_statement_digest(statement: &PackedStatement<'_>, limb: usize) -> usize {
    row_auth_base(statement)
        + AUTH_MODE_ROWS
        + AUTH_INPUT_PRF_ROWS
        + AUTH_INPUT_KEY_ROWS
        + AUTH_LEGACY_DIGEST_ROWS
        + AUTH_ACCUMULATOR_DIGEST_ROWS
        + AUTH_NEXT_ACCUMULATOR_DIGEST_ROWS
        + AUTH_VALUE_LOCK_DIGEST_ROWS
        + limb
}

#[inline]
fn row_auth_policy(statement: &PackedStatement<'_>, limb: usize) -> usize {
    row_auth_base(statement)
        + AUTH_MODE_ROWS
        + AUTH_INPUT_PRF_ROWS
        + AUTH_INPUT_KEY_ROWS
        + AUTH_LEGACY_DIGEST_ROWS
        + AUTH_ACCUMULATOR_DIGEST_ROWS
        + AUTH_NEXT_ACCUMULATOR_DIGEST_ROWS
        + AUTH_VALUE_LOCK_DIGEST_ROWS
        + AUTH_STATEMENT_DIGEST_ROWS
        + limb
}

#[inline]
fn row_auth_intent(statement: &PackedStatement<'_>, limb: usize) -> usize {
    row_auth_base(statement)
        + AUTH_MODE_ROWS
        + AUTH_INPUT_PRF_ROWS
        + AUTH_INPUT_KEY_ROWS
        + AUTH_LEGACY_DIGEST_ROWS
        + AUTH_ACCUMULATOR_DIGEST_ROWS
        + AUTH_NEXT_ACCUMULATOR_DIGEST_ROWS
        + AUTH_VALUE_LOCK_DIGEST_ROWS
        + AUTH_STATEMENT_DIGEST_ROWS
        + AUTH_POLICY_ROWS
        + limb
}

#[inline]
fn row_auth_threshold(statement: &PackedStatement<'_>) -> usize {
    row_auth_base(statement)
        + AUTH_MODE_ROWS
        + AUTH_INPUT_PRF_ROWS
        + AUTH_INPUT_KEY_ROWS
        + AUTH_LEGACY_DIGEST_ROWS
        + AUTH_ACCUMULATOR_DIGEST_ROWS
        + AUTH_NEXT_ACCUMULATOR_DIGEST_ROWS
        + AUTH_VALUE_LOCK_DIGEST_ROWS
        + AUTH_STATEMENT_DIGEST_ROWS
        + AUTH_POLICY_ROWS
        + AUTH_INTENT_ROWS
}

#[inline]
fn row_auth_signer_count(statement: &PackedStatement<'_>) -> usize {
    row_auth_threshold(statement) + 1
}

#[inline]
fn row_auth_count(statement: &PackedStatement<'_>) -> usize {
    row_auth_threshold(statement) + 2
}

#[inline]
fn row_auth_slot(statement: &PackedStatement<'_>, slot: usize) -> usize {
    row_auth_threshold(statement) + 3 + slot
}

#[inline]
fn row_auth_next_count(statement: &PackedStatement<'_>) -> usize {
    row_auth_threshold(statement) + 3 + MULTISIG_MAX_SIGNERS
}

#[inline]
fn row_auth_next_slot(statement: &PackedStatement<'_>, slot: usize) -> usize {
    row_auth_threshold(statement) + 4 + MULTISIG_MAX_SIGNERS + slot
}

#[inline]
fn row_auth_signer(statement: &PackedStatement<'_>) -> usize {
    row_auth_threshold(statement) + 4 + (MULTISIG_MAX_SIGNERS * 2)
}

#[inline]
fn row_auth_duplicate_inverse(statement: &PackedStatement<'_>) -> usize {
    row_auth_signer(statement) + 1
}

#[inline]
fn row_auth_threshold_flag(statement: &PackedStatement<'_>, flag: usize) -> usize {
    row_auth_threshold(statement) + AUTH_SCALAR_ROWS + flag
}

#[inline]
fn row_auth_signer_count_flag(statement: &PackedStatement<'_>, flag: usize) -> usize {
    row_auth_threshold(statement) + AUTH_SCALAR_ROWS + AUTH_THRESHOLD_FLAG_ROWS + flag
}

#[inline]
fn row_auth_count_flag(statement: &PackedStatement<'_>, flag: usize) -> usize {
    row_auth_threshold(statement)
        + AUTH_SCALAR_ROWS
        + AUTH_THRESHOLD_FLAG_ROWS
        + AUTH_SIGNER_COUNT_FLAG_ROWS
        + flag
}

#[inline]
fn row_auth_next_count_flag(statement: &PackedStatement<'_>, flag: usize) -> usize {
    row_auth_threshold(statement)
        + AUTH_SCALAR_ROWS
        + AUTH_THRESHOLD_FLAG_ROWS
        + AUTH_SIGNER_COUNT_FLAG_ROWS
        + AUTH_COUNT_FLAG_ROWS
        + flag
}

#[inline]
fn row_auth_policy_signer(statement: &PackedStatement<'_>, signer: usize) -> usize {
    row_auth_threshold(statement)
        + AUTH_SCALAR_ROWS
        + AUTH_THRESHOLD_FLAG_ROWS
        + AUTH_SIGNER_COUNT_FLAG_ROWS
        + AUTH_COUNT_FLAG_ROWS
        + AUTH_NEXT_COUNT_FLAG_ROWS
        + signer
}

#[inline]
fn row_auth_membership_flag(statement: &PackedStatement<'_>, flag: usize) -> usize {
    row_auth_threshold(statement)
        + AUTH_SCALAR_ROWS
        + AUTH_THRESHOLD_FLAG_ROWS
        + AUTH_SIGNER_COUNT_FLAG_ROWS
        + AUTH_COUNT_FLAG_ROWS
        + AUTH_NEXT_COUNT_FLAG_ROWS
        + AUTH_POLICY_SIGNER_ROWS
        + flag
}

#[allow(dead_code)]
#[inline]
fn row_auth_policy_distinct_inverse(statement: &PackedStatement<'_>, pair: usize) -> usize {
    row_auth_threshold(statement)
        + AUTH_SCALAR_ROWS
        + AUTH_THRESHOLD_FLAG_ROWS
        + AUTH_SIGNER_COUNT_FLAG_ROWS
        + AUTH_COUNT_FLAG_ROWS
        + AUTH_NEXT_COUNT_FLAG_ROWS
        + AUTH_POLICY_SIGNER_ROWS
        + AUTH_MEMBERSHIP_FLAG_ROWS
        + pair
}

#[allow(dead_code)]
#[inline]
fn bridge_prf_permutation() -> usize {
    0
}

#[inline]
fn bridge_input_commitment_permutation(input: usize, chunk: usize) -> usize {
    1 + input * (3 + MERKLE_DEPTH * 2 + 1) + chunk
}

#[inline]
fn bridge_input_merkle_permutation(input: usize, level: usize, chunk: usize) -> usize {
    1 + input * (3 + MERKLE_DEPTH * 2 + 1) + 3 + level * 2 + chunk
}

#[allow(dead_code)]
#[inline]
fn bridge_input_nullifier_permutation(input: usize) -> usize {
    1 + input * (3 + MERKLE_DEPTH * 2 + 1) + (3 + MERKLE_DEPTH * 2 + 1) - 1
}

#[allow(dead_code)]
#[inline]
fn bridge_output_commitment_permutation(output: usize, chunk: usize) -> usize {
    1 + MAX_INPUTS * (3 + MERKLE_DEPTH * 2 + 1) + output * 3 + chunk
}

#[inline]
fn bridge_auth_permutation_base() -> usize {
    1 + MAX_INPUTS * INPUT_PERMUTATIONS + MAX_OUTPUTS * OUTPUT_PERMUTATIONS
}

#[inline]
fn bridge_auth_intent_permutation(chunk: usize) -> usize {
    bridge_auth_permutation_base() + chunk
}

#[inline]
fn bridge_auth_policy_permutation(chunk: usize) -> usize {
    bridge_auth_permutation_base() + AUTH_INTENT_PERMUTATIONS + chunk
}

#[inline]
fn bridge_auth_current_permutation(chunk: usize) -> usize {
    bridge_auth_permutation_base() + AUTH_INTENT_PERMUTATIONS + AUTH_POLICY_PERMUTATIONS + chunk
}

#[inline]
fn bridge_auth_next_permutation(chunk: usize) -> usize {
    bridge_auth_permutation_base()
        + AUTH_INTENT_PERMUTATIONS
        + AUTH_POLICY_PERMUTATIONS
        + AUTH_ACCUMULATOR_PERMUTATIONS
        + chunk
}

#[inline]
fn bridge_auth_value_lock_permutation(chunk: usize) -> usize {
    bridge_auth_permutation_base()
        + AUTH_INTENT_PERMUTATIONS
        + AUTH_POLICY_PERMUTATIONS
        + AUTH_ACCUMULATOR_PERMUTATIONS * 2
        + chunk
}

#[inline]
fn inline_merkle_binding_group_count(packing_factor: usize) -> usize {
    INLINE_MERKLE_BINDING_SLOTS.div_ceil(packing_factor)
}

#[inline]
fn inline_binding_row_count(layout: PackedRowLayout, packing_factor: usize) -> usize {
    if layout.committed_inline_bindings {
        inline_merkle_binding_group_count(packing_factor) * INLINE_MERKLE_ROWS_PER_GROUP
            + INLINE_POLICY_BINDING_ROWS
    } else {
        0
    }
}

#[inline]
fn inline_binding_rows_start(statement: &PackedStatement<'_>) -> usize {
    PUBLIC_ROWS + PackedRowLayout::for_arithmetization(statement.arithmetization).secret_rows()
}

#[inline]
fn row_inline_merkle_binding(
    statement: &PackedStatement<'_>,
    group: usize,
    component: usize,
) -> usize {
    inline_binding_rows_start(statement) + group * INLINE_MERKLE_ROWS_PER_GROUP + component
}

#[inline]
fn row_inline_policy_binding(statement: &PackedStatement<'_>, component: usize) -> usize {
    inline_binding_rows_start(statement)
        + inline_merkle_binding_group_count(statement.packing_factor) * INLINE_MERKLE_ROWS_PER_GROUP
        + component
}

#[inline]
fn poseidon_rows_start(statement: &PackedStatement<'_>) -> usize {
    let layout = PackedRowLayout::for_arithmetization(statement.arithmetization);
    PUBLIC_ROWS + layout.secret_rows() + inline_binding_row_count(layout, statement.packing_factor)
}
#[inline]
fn poseidon_group_row(
    statement: &PackedStatement<'_>,
    group: usize,
    step_row: usize,
    limb: usize,
) -> usize {
    let layout = PackedRowLayout::for_arithmetization(statement.arithmetization);
    poseidon_rows_start(statement)
        + (group * layout.poseidon_rows_per_permutation + step_row) * POSEIDON2_WIDTH
        + limb
}

#[inline]
fn poseidon_transition_challenge_index(
    layout: PackedRowLayout,
    group: usize,
    step: usize,
) -> usize {
    group * layout.poseidon_transition_count() + step
}

#[inline]
fn felt_bool_v<R: PrimeCharacteristicRing>(bit: R) -> R {
    bit * (bit - R::ONE)
}

#[inline]
fn bounded_value_limb_zero<R: PrimeCharacteristicRing>(limb: R, limb_index: usize) -> R {
    if limb_index + 1 == RANGE_LIMB_COUNT {
        debug_assert_eq!(RANGE_TOP_LIMB_MAX, 1);
        return felt_bool_v(limb);
    }
    let radix = 1usize << RANGE_LIMB_BITS;
    (0..radix).fold(R::ONE, |acc, digit| {
        acc * (limb - R::from_u64(digit as u64))
    })
}

#[inline]
fn selected_slot_weight<R: PrimeCharacteristicRing>(bit0: R, bit1: R, slot: usize) -> R {
    let inv0 = R::ONE - bit0;
    let inv1 = R::ONE - bit1;
    match slot {
        0 => inv0 * inv1,
        1 => bit0 * inv1,
        2 => inv0 * bit1,
        _ => bit0 * bit1,
    }
}

fn selected_slot_asset<R: PrimeCharacteristicRing>(public_values: &[R], bit0: R, bit1: R) -> R {
    let mut result = R::ZERO;
    for slot in 0..BALANCE_SLOTS {
        let weight = selected_slot_weight(bit0, bit1, slot);
        result += weight * public_values[PUB_SLOT_ASSETS + slot];
    }
    result
}

fn derive_slot_denominator_inverses(public_values: &[u64]) -> [Felt; BALANCE_SLOTS] {
    let mut inverses = [Felt::ZERO; BALANCE_SLOTS];
    for slot in 0..BALANCE_SLOTS {
        let asset = Felt::from_u64(public_values[PUB_SLOT_ASSETS + slot]);
        let mut denominator = Felt::ONE;
        for other in 0..BALANCE_SLOTS {
            if other == slot {
                continue;
            }
            denominator *= asset - Felt::from_u64(public_values[PUB_SLOT_ASSETS + other]);
        }
        inverses[slot] = denominator.try_inverse().unwrap_or(Felt::ZERO);
    }
    inverses
}

fn slot_membership_weights<R: PrimeCharacteristicRing>(
    public_values: &[R],
    slot_denominator_inverses: &[R; BALANCE_SLOTS],
    asset: R,
) -> [R; BALANCE_SLOTS] {
    let mut weights = [R::ZERO; BALANCE_SLOTS];
    for (slot, weight) in weights.iter_mut().enumerate().take(BALANCE_SLOTS) {
        let mut numerator = R::ONE;
        for other in 0..BALANCE_SLOTS {
            if other == slot {
                continue;
            }
            numerator *= asset - public_values[PUB_SLOT_ASSETS + other];
        }
        *weight = numerator * slot_denominator_inverses[slot];
    }
    weights
}

fn slot_membership_zero<R: PrimeCharacteristicRing>(public_values: &[R], asset: R) -> R {
    let mut acc = R::ONE;
    for slot in 0..BALANCE_SLOTS {
        acc *= asset - public_values[PUB_SLOT_ASSETS + slot];
    }
    acc
}

fn aggregate_hash_limbs<R: PrimeCharacteristicRing>(challenge: R, limbs: &[R; HASH_LIMBS]) -> R {
    let mut acc = R::ZERO;
    let mut power = R::ONE;
    for limb in limbs {
        acc += power * *limb;
        power *= challenge;
    }
    acc
}

fn auxiliary_input_current_agg(input: usize, level: usize) -> usize {
    input * MERKLE_DEPTH * 3 + level * 3
}

fn auxiliary_input_left_agg(input: usize, level: usize) -> usize {
    input * MERKLE_DEPTH * 3 + level * 3 + 1
}

fn auxiliary_input_right_agg(input: usize, level: usize) -> usize {
    input * MERKLE_DEPTH * 3 + level * 3 + 2
}

fn aggregate_weighted_differences<R: PrimeCharacteristicRing>(
    challenge: R,
    lhs: &[R],
    rhs: &[R],
) -> R {
    let mut acc = R::ZERO;
    let mut power = R::ONE;
    for (&left, &right) in lhs.iter().zip(rhs.iter()) {
        acc += power * (left - right);
        power *= challenge;
    }
    acc
}

fn derive_stable_selector_bits(public_values: &[u64]) -> [Felt; 2] {
    if public_values[PUB_STABLE_ENABLED] == 0 {
        return [Felt::ZERO, Felt::ZERO];
    }
    let stable_asset = public_values[PUB_STABLE_ASSET];
    let slot = (0..BALANCE_SLOTS)
        .find(|slot| public_values[PUB_SLOT_ASSETS + slot] == stable_asset)
        .unwrap_or(0);
    [
        Felt::from_u64((slot & 1) as u64),
        Felt::from_u64(((slot >> 1) & 1) as u64),
    ]
}

fn signed_from_parts<R: PrimeCharacteristicRing>(sign: R, magnitude: R) -> R {
    magnitude - (sign + sign) * magnitude
}

fn apply_poseidon_transition<R: PrimeCharacteristicRing>(
    layout: PackedRowLayout,
    logical_step: usize,
    state: &mut [R; POSEIDON2_WIDTH],
) {
    if layout.skip_initial_mds_poseidon && logical_step == 0 {
        poseidon2_step_ring(state, 0);
        poseidon2_step_ring(state, 1);
        return;
    }
    poseidon2_step_ring(state, layout.poseidon_trace_row(logical_step));
}

#[allow(dead_code)]
pub(crate) fn packed_constraint_count() -> usize {
    constraint_count(SmallwoodArithmetization::Bridge64V1, 64)
}

pub(crate) fn packed_constraint_count_for_packing_factor(packing_factor: usize) -> usize {
    constraint_count(SmallwoodArithmetization::Bridge64V1, packing_factor)
}

pub(crate) fn compute_bridge_constraints_u64(
    statement: &PackedStatement<'_>,
    view: SmallwoodNonlinearEvalView<'_>,
    out: &mut [u64],
) -> Result<(), TransactionCircuitError> {
    let expected = constraint_count(statement.arithmetization, statement.packing_factor);
    if out.len() != expected {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood constraint buffer has length {}, expected {expected}",
            out.len()
        )));
    }
    let SmallwoodNonlinearEvalView::RowScalars {
        eval_point: _eval_point,
        rows,
        auxiliary_words,
    } = view;
    let felt_rows = rows.iter().copied().map(Felt::from_u64).collect::<Vec<_>>();
    let felt_auxiliary = auxiliary_words
        .iter()
        .copied()
        .map(Felt::from_u64)
        .collect::<Vec<_>>();
    let mut felt_out = vec![Felt::ZERO; expected];
    compute_constraints(statement, &felt_rows, &felt_auxiliary, &mut felt_out);
    for (dst, src) in out.iter_mut().zip(felt_out.iter()) {
        *dst = src.as_canonical_u64();
    }
    Ok(())
}

fn constraint_count(arithmetization: SmallwoodArithmetization, packing_factor: usize) -> usize {
    let layout = PackedRowLayout::for_arithmetization(arithmetization);
    let public_bools = MAX_INPUTS + MAX_OUTPUTS + 3;
    let merkle_selection_constraints = if layout.committed_inline_bindings {
        inline_merkle_binding_group_count(packing_factor)
    } else {
        MAX_INPUTS * MERKLE_DEPTH
    };
    let input_constraints = MAX_INPUTS * (MERKLE_DEPTH + 1) + merkle_selection_constraints;
    let output_constraints = if layout.committed_inline_bindings {
        MAX_OUTPUTS * (1 + HASH_LIMBS)
    } else {
        MAX_OUTPUTS * (1 + 1)
    };
    let stablecoin_constraints = if layout.committed_inline_bindings {
        6 + HASH_LIMBS * 3
    } else {
        1 + 1 + 7
    };
    let balance_constraints = BALANCE_SLOTS;
    let value_range_constraints = layout.value_range_rows;
    let auth_constraints = AUTH_CONSTRAINTS;
    let poseidon_transition = poseidon_group_count(packing_factor)
        * layout.poseidon_transition_count()
        * if layout.committed_inline_bindings {
            POSEIDON2_WIDTH
        } else {
            1
        };
    public_bools
        + input_constraints
        + output_constraints
        + stablecoin_constraints
        + balance_constraints
        + value_range_constraints
        + auth_constraints
        + poseidon_transition
}

#[cfg(test)]
pub(crate) fn production_constraint_family_ranges() -> Vec<SmallwoodProductionConstraintFamilyRange>
{
    let arithmetization =
        SmallwoodArithmetization::DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2;
    let packing_factor = 64;
    let layout = PackedRowLayout::for_arithmetization(arithmetization);
    let counts = [
        ("public_shape", MAX_INPUTS + MAX_OUTPUTS + 3),
        (
            "input_spend",
            MAX_INPUTS * (MERKLE_DEPTH + 1) + inline_merkle_binding_group_count(packing_factor),
        ),
        ("output_validity", MAX_OUTPUTS * (1 + HASH_LIMBS)),
        ("stablecoin", 6 + HASH_LIMBS * 3),
        ("balance_conservation", BALANCE_SLOTS),
        ("value_ranges", layout.value_range_rows),
        ("spend_authorization", AUTH_CONSTRAINTS),
        (
            "poseidon_transitions",
            poseidon_group_count(packing_factor)
                * layout.poseidon_transition_count()
                * POSEIDON2_WIDTH,
        ),
    ];
    let mut start = 0;
    let ranges = counts
        .into_iter()
        .map(|(name, count)| {
            let range = SmallwoodProductionConstraintFamilyRange { name, start, count };
            start += count;
            range
        })
        .collect::<Vec<_>>();
    debug_assert_eq!(start, constraint_count(arithmetization, packing_factor));
    ranges
}

fn compute_constraints(
    statement: &PackedStatement<'_>,
    rows: &[Felt],
    auxiliary_words: &[Felt],
    out: &mut [Felt],
) {
    let public_values = statement
        .public_values
        .iter()
        .copied()
        .map(Felt::from_u64)
        .collect::<Vec<_>>();
    compute_constraints_ring(
        statement,
        &public_values,
        rows,
        auxiliary_words,
        &statement.output_ciphertext_challenges,
        &statement.slot_denominator_inverses,
        statement.stable_selector_bits,
        statement.stable_policy_hash_challenge,
        statement.stable_oracle_challenge,
        statement.stable_attestation_challenge,
        &statement.poseidon_transition_challenges,
        out,
    );
}

#[allow(clippy::too_many_arguments)]
fn compute_constraints_ring<R: PrimeCharacteristicRing>(
    statement: &PackedStatement<'_>,
    public_values: &[R],
    rows: &[R],
    auxiliary_words: &[R],
    output_ciphertext_challenges: &[R; MAX_OUTPUTS],
    slot_denominator_inverses: &[R; BALANCE_SLOTS],
    stable_selector_bits: [R; 2],
    stable_policy_hash_challenge: R,
    stable_oracle_challenge: R,
    stable_attestation_challenge: R,
    poseidon_transition_challenges: &[R],
    out: &mut [R],
) {
    let mut c = 0usize;
    let layout = PackedRowLayout::for_arithmetization(statement.arithmetization);

    for input in 0..MAX_INPUTS {
        out[c] = felt_bool_v(public_values[PUB_INPUT_FLAG0 + input]);
        c += 1;
    }
    for output in 0..MAX_OUTPUTS {
        out[c] = felt_bool_v(public_values[PUB_OUTPUT_FLAG0 + output]);
        c += 1;
    }
    out[c] = felt_bool_v(public_values[PUB_VALUE_BALANCE_SIGN]);
    c += 1;
    out[c] = felt_bool_v(public_values[PUB_STABLE_ENABLED]);
    c += 1;
    out[c] = felt_bool_v(public_values[PUB_STABLE_ISSUANCE_SIGN]);
    c += 1;

    for input in 0..MAX_INPUTS {
        let asset = rows[row_input_asset(statement, input)];
        let flag = public_values[PUB_INPUT_FLAG0 + input];
        for bit in 0..MERKLE_DEPTH {
            out[c] = felt_bool_v(rows[row_input_direction(statement, input, bit)]);
            c += 1;
        }
        let mut position_sum = R::ZERO;
        for bit in 0..MERKLE_DEPTH {
            position_sum +=
                rows[row_input_direction(statement, input, bit)] * R::from_u64(1u64 << bit);
        }
        let _ = position_sum;
        out[c] = flag * slot_membership_zero(public_values, asset);
        c += 1;

        if !layout.committed_inline_bindings {
            for level in 0..MERKLE_DEPTH {
                let dir = rows[row_input_direction(statement, input, level)];
                let (current, left, right) = if layout.inline_merkle_aggregates {
                    let challenge = R::from_u64(
                        nontrivial_challenge(statement, 9, input as u64, level as u64)
                            .as_canonical_u64(),
                    );
                    let current_source = if level == 0 {
                        bridge_input_commitment_permutation(input, 2)
                    } else {
                        bridge_input_merkle_permutation(input, level - 1, 1)
                    };
                    let merkle0 = bridge_input_merkle_permutation(input, level, 0);
                    let merkle1 = bridge_input_merkle_permutation(input, level, 1);
                    let mut current_hash = [R::ZERO; HASH_LIMBS];
                    let mut left_hash = [R::ZERO; HASH_LIMBS];
                    let mut right_hash = [R::ZERO; HASH_LIMBS];
                    for limb in 0..HASH_LIMBS {
                        current_hash[limb] = rows[poseidon_group_row(
                            statement,
                            current_source / statement.packing_factor,
                            layout.poseidon_last_row(),
                            limb,
                        )];
                        left_hash[limb] = rows[poseidon_group_row(
                            statement,
                            merkle0 / statement.packing_factor,
                            layout.poseidon_last_row(),
                            limb,
                        )];
                        right_hash[limb] = rows[poseidon_group_row(
                            statement,
                            merkle1 / statement.packing_factor,
                            layout.poseidon_last_row(),
                            limb,
                        )];
                    }
                    let current =
                        if auxiliary_words.len() > auxiliary_input_current_agg(input, level) {
                            auxiliary_words[auxiliary_input_current_agg(input, level)]
                        } else {
                            aggregate_hash_limbs(challenge, &current_hash)
                        };
                    let left = if auxiliary_words.len() > auxiliary_input_left_agg(input, level) {
                        auxiliary_words[auxiliary_input_left_agg(input, level)]
                    } else {
                        aggregate_hash_limbs(challenge, &left_hash)
                    };
                    let right = if auxiliary_words.len() > auxiliary_input_right_agg(input, level) {
                        auxiliary_words[auxiliary_input_right_agg(input, level)]
                    } else {
                        aggregate_hash_limbs(challenge, &right_hash)
                    };
                    (current, left, right)
                } else {
                    (
                        rows[row_input_current_agg(statement, input, level)],
                        rows[row_input_left_agg(statement, input, level)],
                        rows[row_input_right_agg(statement, input, level)],
                    )
                };
                out[c] = flag * (current - (left + dir * (right - left)));
                c += 1;
            }
        }
    }

    if layout.committed_inline_bindings {
        for group in 0..inline_merkle_binding_group_count(statement.packing_factor) {
            let current = rows[row_inline_merkle_binding(statement, group, 0)];
            let left = rows[row_inline_merkle_binding(statement, group, 1)];
            let right = rows[row_inline_merkle_binding(statement, group, 2)];
            let direction = rows[row_inline_merkle_binding(statement, group, 3)];
            out[c] = current - (left + direction * (right - left));
            c += 1;
        }
    }

    for output_idx in 0..MAX_OUTPUTS {
        let asset = rows[row_output_asset(statement, output_idx)];
        let flag = public_values[PUB_OUTPUT_FLAG0 + output_idx];
        let inactive = R::ONE - flag;
        out[c] = flag * slot_membership_zero(public_values, asset);
        c += 1;

        if layout.committed_inline_bindings {
            for limb in 0..HASH_LIMBS {
                out[c] = inactive
                    * public_values[PUB_CIPHERTEXT_HASHES + output_idx * HASH_LIMBS + limb];
                c += 1;
            }
        } else {
            let mut lhs_hash = [R::ZERO; HASH_LIMBS];
            let rhs_hash = [R::ZERO; HASH_LIMBS];
            for (limb, lhs_limb) in lhs_hash.iter_mut().enumerate() {
                *lhs_limb = inactive
                    * public_values[PUB_CIPHERTEXT_HASHES + output_idx * HASH_LIMBS + limb];
            }
            out[c] = aggregate_weighted_differences(
                output_ciphertext_challenges[output_idx],
                &lhs_hash,
                &rhs_hash,
            );
            c += 1;
        }
    }

    let stable_selector0 = stable_selector_bits[0];
    let stable_selector1 = stable_selector_bits[1];
    let stable_enabled = public_values[PUB_STABLE_ENABLED];
    let stable_disabled = R::ONE - stable_enabled;
    out[c] = selected_slot_asset(public_values, stable_selector0, stable_selector1)
        - public_values[PUB_STABLE_ASSET];
    c += 1;
    out[c] = stable_enabled * selected_slot_weight(stable_selector0, stable_selector1, 0);
    c += 1;
    out[c] = stable_disabled * public_values[PUB_STABLE_ASSET];
    c += 1;
    out[c] = stable_disabled * public_values[PUB_STABLE_POLICY_VERSION];
    c += 1;
    out[c] = stable_disabled * public_values[PUB_STABLE_ISSUANCE_SIGN];
    c += 1;
    out[c] = stable_disabled * public_values[PUB_STABLE_ISSUANCE_MAG];
    c += 1;

    if layout.committed_inline_bindings {
        for limb in 0..HASH_LIMBS {
            out[c] = stable_disabled * public_values[PUB_STABLE_POLICY_HASH + limb];
            c += 1;
        }
        for limb in 0..HASH_LIMBS {
            out[c] = stable_disabled * public_values[PUB_STABLE_ORACLE + limb];
            c += 1;
        }
        for limb in 0..HASH_LIMBS {
            out[c] = stable_disabled * public_values[PUB_STABLE_ATTESTATION + limb];
            c += 1;
        }
    } else {
        let rhs_hash = [R::ZERO; HASH_LIMBS];
        let mut lhs_hash: [R; HASH_LIMBS] = core::array::from_fn(|limb| {
            stable_disabled * public_values[PUB_STABLE_POLICY_HASH + limb]
        });
        out[c] = aggregate_weighted_differences(stable_policy_hash_challenge, &lhs_hash, &rhs_hash);
        c += 1;
        lhs_hash =
            core::array::from_fn(|limb| stable_disabled * public_values[PUB_STABLE_ORACLE + limb]);
        out[c] = aggregate_weighted_differences(stable_oracle_challenge, &lhs_hash, &rhs_hash);
        c += 1;
        lhs_hash = core::array::from_fn(|limb| {
            stable_disabled * public_values[PUB_STABLE_ATTESTATION + limb]
        });
        out[c] = aggregate_weighted_differences(stable_attestation_challenge, &lhs_hash, &rhs_hash);
        c += 1;
    }

    let signed_value_balance = signed_from_parts(
        public_values[PUB_VALUE_BALANCE_SIGN],
        public_values[PUB_VALUE_BALANCE_MAG],
    );
    let signed_stable_issuance = signed_from_parts(
        public_values[PUB_STABLE_ISSUANCE_SIGN],
        public_values[PUB_STABLE_ISSUANCE_MAG],
    );
    let native_expected = public_values[PUB_FEE] - signed_value_balance;

    for slot in 0..BALANCE_SLOTS {
        let mut delta = R::ZERO;
        for input in 0..MAX_INPUTS {
            let flag = public_values[PUB_INPUT_FLAG0 + input];
            let value = rows[row_input_value(statement, input)];
            let asset = rows[row_input_asset(statement, input)];
            let weight =
                slot_membership_weights(public_values, slot_denominator_inverses, asset)[slot];
            delta += flag * value * weight;
        }
        for output_idx in 0..MAX_OUTPUTS {
            let flag = public_values[PUB_OUTPUT_FLAG0 + output_idx];
            let value = rows[row_output_value(statement, output_idx)];
            let asset = rows[row_output_asset(statement, output_idx)];
            let weight =
                slot_membership_weights(public_values, slot_denominator_inverses, asset)[slot];
            delta -= flag * value * weight;
        }
        out[c] = if slot == 0 {
            delta - native_expected
        } else {
            let stable_weight = selected_slot_weight(stable_selector0, stable_selector1, slot);
            let expected = stable_enabled * stable_weight * signed_stable_issuance;
            delta - expected
        };
        c += 1;
    }

    if layout.value_range_rows > 0 {
        for input in 0..MAX_INPUTS {
            for limb in 0..RANGE_LIMB_COUNT {
                out[c] = bounded_value_limb_zero(
                    rows[row_input_value_range_limb(statement, input, limb)],
                    limb,
                );
                c += 1;
            }
        }
        for output in 0..MAX_OUTPUTS {
            for limb in 0..RANGE_LIMB_COUNT {
                out[c] = bounded_value_limb_zero(
                    rows[row_output_value_range_limb(statement, output, limb)],
                    limb,
                );
                c += 1;
            }
        }
        for public_value in 0..PUBLIC_VALUE_RANGE_VALUE_COUNT {
            for limb in 0..RANGE_LIMB_COUNT {
                out[c] = bounded_value_limb_zero(
                    rows[row_public_value_range_limb(statement, public_value, limb)],
                    limb,
                );
                c += 1;
            }
        }
    }

    let auth_start = c;
    let mode_single = rows[row_auth_mode(statement, 0)];
    let mode_approval = rows[row_auth_mode(statement, 1)];
    let mode_final = rows[row_auth_mode(statement, 2)];
    let input0_flag = public_values[PUB_INPUT_FLAG0];
    let input1_flag = public_values[PUB_INPUT_FLAG0 + 1];
    let output0_flag = public_values[PUB_OUTPUT_FLAG0];
    let non_single = mode_approval + mode_final;
    for mode in [mode_single, mode_approval, mode_final] {
        out[c] = felt_bool_v(mode);
        c += 1;
    }
    out[c] = mode_single + mode_approval + mode_final - R::ONE;
    c += 1;

    let threshold = rows[row_auth_threshold(statement)];
    let signer_count = rows[row_auth_signer_count(statement)];
    let count = rows[row_auth_count(statement)];
    let approved_slots = core::array::from_fn::<_, MULTISIG_MAX_SIGNERS, _>(|slot| {
        rows[row_auth_slot(statement, slot)]
    });
    let next_count = rows[row_auth_next_count(statement)];
    let next_approved_slots = core::array::from_fn::<_, MULTISIG_MAX_SIGNERS, _>(|slot| {
        rows[row_auth_next_slot(statement, slot)]
    });
    let reserved_signer = rows[row_auth_signer(statement)];
    let reserved_duplicate_inverse = rows[row_auth_duplicate_inverse(statement)];
    let threshold_flags = core::array::from_fn::<_, AUTH_THRESHOLD_FLAG_ROWS, _>(|flag| {
        rows[row_auth_threshold_flag(statement, flag)]
    });
    let signer_count_flags = core::array::from_fn::<_, AUTH_SIGNER_COUNT_FLAG_ROWS, _>(|flag| {
        rows[row_auth_signer_count_flag(statement, flag)]
    });
    let count_flags = core::array::from_fn::<_, AUTH_COUNT_FLAG_ROWS, _>(|flag| {
        rows[row_auth_count_flag(statement, flag)]
    });
    let next_count_flags = core::array::from_fn::<_, AUTH_NEXT_COUNT_FLAG_ROWS, _>(|flag| {
        rows[row_auth_next_count_flag(statement, flag)]
    });
    let policy_signer_tags = core::array::from_fn::<_, AUTH_POLICY_SIGNER_ROWS, _>(|idx| {
        rows[row_auth_policy_signer(statement, idx)]
    });
    let membership_flags = core::array::from_fn::<_, AUTH_MEMBERSHIP_FLAG_ROWS, _>(|flag| {
        rows[row_auth_membership_flag(statement, flag)]
    });
    let policy_distinct_inverses =
        core::array::from_fn::<_, AUTH_POLICY_DISTINCT_INVERSE_ROWS, _>(|pair| {
            rows[row_auth_policy_distinct_inverse(statement, pair)]
        });
    let slot_active = |slot: usize| -> R {
        signer_count_flags[slot..]
            .iter()
            .copied()
            .fold(R::ZERO, |acc, value| acc + value)
    };

    for limb in 0..HASH_LIMBS {
        out[c] = mode_single * rows[row_auth_policy(statement, limb)];
        c += 1;
        out[c] = mode_single * rows[row_auth_intent(statement, limb)];
        c += 1;
    }
    for value in [
        threshold,
        signer_count,
        count,
        next_count,
        reserved_signer,
        reserved_duplicate_inverse,
    ] {
        out[c] = mode_single * value;
        c += 1;
    }
    for value in approved_slots {
        out[c] = mode_single * value;
        c += 1;
    }
    for value in next_approved_slots {
        out[c] = mode_single * value;
        c += 1;
    }
    for value in threshold_flags {
        out[c] = mode_single * value;
        c += 1;
    }
    for value in signer_count_flags {
        out[c] = mode_single * value;
        c += 1;
    }
    for value in count_flags {
        out[c] = mode_single * value;
        c += 1;
    }
    for value in next_count_flags {
        out[c] = mode_single * value;
        c += 1;
    }
    for value in membership_flags {
        out[c] = mode_single * value;
        c += 1;
    }
    for value in policy_signer_tags {
        out[c] = mode_single * value;
        c += 1;
    }
    for value in policy_distinct_inverses {
        out[c] = mode_single * value;
        c += 1;
    }

    if statement.packing_factor == 1 {
        let prf_group = bridge_prf_permutation();
        for limb in 0..5 {
            out[c] = rows[row_auth_legacy_digest(statement, limb)]
                - rows[poseidon_group_row(statement, prf_group, layout.poseidon_last_row(), limb)];
            c += 1;
        }
        for limb in 0..HASH_LIMBS {
            let statement_group = bridge_auth_intent_permutation(AUTH_INTENT_PERMUTATIONS - 1);
            let current_group = bridge_auth_current_permutation(AUTH_ACCUMULATOR_PERMUTATIONS - 1);
            let next_group = bridge_auth_next_permutation(AUTH_ACCUMULATOR_PERMUTATIONS - 1);
            let value_lock_group =
                bridge_auth_value_lock_permutation(AUTH_VALUE_LOCK_PERMUTATIONS - 1);
            out[c] = rows[row_auth_statement_digest(statement, limb)]
                - rows[poseidon_group_row(
                    statement,
                    statement_group,
                    layout.poseidon_last_row(),
                    limb,
                )];
            c += 1;
            out[c] = rows[row_auth_current_digest(statement, limb)]
                - rows[poseidon_group_row(
                    statement,
                    current_group,
                    layout.poseidon_last_row(),
                    limb,
                )];
            c += 1;
            out[c] = rows[row_auth_next_digest(statement, limb)]
                - rows[poseidon_group_row(statement, next_group, layout.poseidon_last_row(), limb)];
            c += 1;
            out[c] = rows[row_auth_value_lock_digest(statement, limb)]
                - rows[poseidon_group_row(
                    statement,
                    value_lock_group,
                    layout.poseidon_last_row(),
                    limb,
                )];
            c += 1;
            let policy_group = bridge_auth_policy_permutation(AUTH_POLICY_PERMUTATIONS - 1);
            out[c] = non_single
                * (rows[row_auth_policy(statement, limb)]
                    - rows[poseidon_group_row(
                        statement,
                        policy_group,
                        layout.poseidon_last_row(),
                        limb,
                    )]);
            c += 1;
        }
    } else if layout.committed_inline_bindings {
        for _ in 0..(5 + HASH_LIMBS * 4) {
            out[c] = R::ZERO;
            c += 1;
        }
        out[c] = rows[row_inline_policy_binding(statement, 2)]
            * (rows[row_inline_policy_binding(statement, 0)]
                - rows[row_inline_policy_binding(statement, 1)]);
        c += 1;
    } else {
        for _ in 0..(5 + HASH_LIMBS * 5) {
            out[c] = R::ZERO;
            c += 1;
        }
    }

    let legacy_prf = rows[row_auth_legacy_digest(statement, 0)];
    let current_prf = rows[row_auth_current_digest(statement, 4)];
    let value_lock_prf = rows[row_auth_value_lock_digest(statement, 4)];
    for input in 0..MAX_INPUTS {
        let flag = public_values[PUB_INPUT_FLAG0 + input];
        let approval_prf = if input == 0 { current_prf } else { legacy_prf };
        let final_prf = if input == 0 {
            value_lock_prf
        } else {
            current_prf
        };
        let expected_prf = flag
            * (mode_single * legacy_prf + mode_approval * approval_prf + mode_final * final_prf);
        out[c] = rows[row_auth_input_prf(statement, input)] - expected_prf;
        c += 1;
        for limb in 0..4 {
            let legacy_key = rows[row_auth_legacy_digest(statement, 1 + limb)];
            let current_key = rows[row_auth_current_digest(statement, limb)];
            let value_lock_key = rows[row_auth_value_lock_digest(statement, limb)];
            let approval_key = if input == 0 { current_key } else { legacy_key };
            let final_key = if input == 0 {
                value_lock_key
            } else {
                current_key
            };
            let expected_key = flag
                * (mode_single * legacy_key
                    + mode_approval * approval_key
                    + mode_final * final_key);
            out[c] = rows[row_auth_input_key(statement, input, limb)] - expected_key;
            c += 1;
        }
    }
    out[c] = mode_approval * (input0_flag - R::ONE);
    c += 1;
    out[c] = mode_approval * (input1_flag - R::ONE);
    c += 1;
    out[c] = mode_approval * (output0_flag - R::ONE);
    c += 1;
    out[c] = mode_final * (input0_flag - R::ONE);
    c += 1;
    out[c] = mode_final * (input1_flag - R::ONE);
    c += 1;
    for limb in 0..4 {
        out[c] = mode_approval
            * (rows[row_output_auth_key(statement, 0, limb)]
                - rows[row_auth_next_digest(statement, limb)]);
        c += 1;
    }

    for bit in threshold_flags {
        out[c] = non_single * felt_bool_v(bit);
        c += 1;
    }
    out[c] = non_single
        * (threshold_flags
            .iter()
            .copied()
            .fold(R::ZERO, |acc, bit| acc + bit)
            - R::ONE);
    c += 1;
    out[c] = non_single
        * (threshold
            - threshold_flags
                .iter()
                .enumerate()
                .fold(R::ZERO, |acc, (idx, bit)| {
                    acc + *bit * R::from_u64((idx + 1) as u64)
                }));
    c += 1;
    for bit in signer_count_flags {
        out[c] = non_single * felt_bool_v(bit);
        c += 1;
    }
    out[c] = non_single
        * (signer_count_flags
            .iter()
            .copied()
            .fold(R::ZERO, |acc, bit| acc + bit)
            - R::ONE);
    c += 1;
    out[c] = non_single
        * (signer_count
            - signer_count_flags
                .iter()
                .enumerate()
                .fold(R::ZERO, |acc, (idx, bit)| {
                    acc + *bit * R::from_u64((idx + 1) as u64)
                }));
    c += 1;
    let mut threshold_exceeds_signer_count = R::ZERO;
    for (threshold_idx, threshold_flag) in threshold_flags.iter().enumerate() {
        let invalid_signer_counts = signer_count_flags[..threshold_idx]
            .iter()
            .copied()
            .fold(R::ZERO, |acc, bit| acc + bit);
        threshold_exceeds_signer_count += *threshold_flag * invalid_signer_counts;
    }
    out[c] = non_single * threshold_exceeds_signer_count;
    c += 1;
    for bit in count_flags {
        out[c] = non_single * felt_bool_v(bit);
        c += 1;
    }
    out[c] = non_single
        * (count_flags
            .iter()
            .copied()
            .fold(R::ZERO, |acc, bit| acc + bit)
            - R::ONE);
    c += 1;
    out[c] = non_single
        * (count
            - count_flags
                .iter()
                .enumerate()
                .fold(R::ZERO, |acc, (idx, bit)| {
                    acc + *bit * R::from_u64(idx as u64)
                }));
    c += 1;
    for bit in next_count_flags {
        out[c] = mode_approval * felt_bool_v(bit);
        c += 1;
    }
    out[c] = mode_approval
        * (next_count_flags
            .iter()
            .copied()
            .fold(R::ZERO, |acc, bit| acc + bit)
            - R::ONE);
    c += 1;
    out[c] = mode_approval
        * (next_count
            - next_count_flags
                .iter()
                .enumerate()
                .fold(R::ZERO, |acc, (idx, bit)| {
                    acc + *bit * R::from_u64(idx as u64)
                }));
    c += 1;
    out[c] = mode_approval * (next_count - count - R::ONE);
    c += 1;
    out[c] = mode_approval * count_flags[MULTISIG_MAX_SIGNERS];
    c += 1;
    for (slot, approved) in approved_slots.iter().copied().enumerate() {
        out[c] = non_single * felt_bool_v(approved);
        c += 1;
        out[c] = non_single * approved * (R::ONE - slot_active(slot));
        c += 1;
    }
    out[c] = non_single
        * (count
            - approved_slots
                .iter()
                .copied()
                .fold(R::ZERO, |acc, bit| acc + bit));
    c += 1;
    for (slot, approved) in next_approved_slots.iter().copied().enumerate() {
        out[c] = mode_approval * felt_bool_v(approved);
        c += 1;
        out[c] = mode_approval * approved * (R::ONE - slot_active(slot));
        c += 1;
    }
    out[c] = mode_approval
        * (next_count
            - next_approved_slots
                .iter()
                .copied()
                .fold(R::ZERO, |acc, bit| acc + bit));
    c += 1;
    for slot in 0..MULTISIG_MAX_SIGNERS {
        out[c] = mode_approval * membership_flags[slot] * approved_slots[slot];
        c += 1;
        out[c] = mode_approval
            * (next_approved_slots[slot] - approved_slots[slot] - membership_flags[slot]);
        c += 1;
    }
    out[c] = mode_approval * reserved_signer;
    c += 1;
    out[c] = mode_approval * reserved_duplicate_inverse;
    c += 1;
    for bit in membership_flags {
        out[c] = mode_approval * felt_bool_v(bit);
        c += 1;
    }
    out[c] = mode_approval
        * (membership_flags
            .iter()
            .copied()
            .fold(R::ZERO, |acc, bit| acc + bit)
            - R::ONE);
    c += 1;
    for (slot, membership) in membership_flags.iter().copied().enumerate() {
        out[c] = mode_approval * membership * (R::ONE - slot_active(slot));
        c += 1;
        for limb in 0..SIGNER_TAG_WORDS {
            out[c] = mode_approval
                * membership
                * (rows[row_auth_legacy_digest(statement, limb)]
                    - policy_signer_tags[slot * SIGNER_TAG_WORDS + limb]);
            c += 1;
        }
    }
    for slot in 0..MULTISIG_MAX_SIGNERS {
        let active = slot_active(slot);
        for limb in 0..SIGNER_TAG_WORDS {
            out[c] =
                non_single * (R::ONE - active) * policy_signer_tags[slot * SIGNER_TAG_WORDS + limb];
            c += 1;
        }
    }
    let mut pair = 0;
    for left in 0..MULTISIG_MAX_SIGNERS {
        for right in (left + 1)..MULTISIG_MAX_SIGNERS {
            let active_pair = slot_active(left) * slot_active(right);
            let diff = policy_signer_tags[left * SIGNER_TAG_WORDS]
                - policy_signer_tags[right * SIGNER_TAG_WORDS];
            let inverse = policy_distinct_inverses[pair];
            out[c] = non_single * active_pair * (diff * inverse - R::ONE);
            c += 1;
            out[c] = non_single * (R::ONE - active_pair) * inverse;
            c += 1;
            pair += 1;
        }
    }

    let mut final_below_threshold = R::ZERO;
    for (threshold_idx, threshold_flag) in threshold_flags.iter().enumerate() {
        let below = count_flags[..=threshold_idx]
            .iter()
            .copied()
            .fold(R::ZERO, |acc, bit| acc + bit);
        final_below_threshold += *threshold_flag * below;
    }
    out[c] = mode_final * final_below_threshold;
    c += 1;
    for limb in 0..HASH_LIMBS {
        out[c] = mode_final
            * (rows[row_auth_intent(statement, limb)]
                - rows[row_auth_statement_digest(statement, limb)]);
        c += 1;
    }
    out[c] = mode_final * next_count;
    c += 1;
    for approved in next_approved_slots {
        out[c] = mode_final * approved;
        c += 1;
    }
    out[c] = mode_final * reserved_signer;
    c += 1;
    out[c] = mode_final * reserved_duplicate_inverse;
    c += 1;
    out[c] = mode_final * (next_count_flags[0] - R::ONE);
    c += 1;
    for flag in next_count_flags.iter().skip(1) {
        out[c] = mode_final * *flag;
        c += 1;
    }
    for flag in membership_flags {
        out[c] = mode_final * flag;
        c += 1;
    }
    while c < auth_start + AUTH_CONSTRAINTS {
        out[c] = R::ZERO;
        c += 1;
    }

    for group in 0..poseidon_group_count(statement.packing_factor) {
        for step in 0..layout.poseidon_transition_count() {
            let mut state = [R::ZERO; POSEIDON2_WIDTH];
            let mut next_actual = [R::ZERO; POSEIDON2_WIDTH];
            for limb in 0..POSEIDON2_WIDTH {
                state[limb] = rows[poseidon_group_row(statement, group, step, limb)];
                next_actual[limb] = rows[poseidon_group_row(statement, group, step + 1, limb)];
            }
            apply_poseidon_transition(layout, step, &mut state);
            if layout.committed_inline_bindings {
                for limb in 0..POSEIDON2_WIDTH {
                    out[c] = next_actual[limb] - state[limb];
                    c += 1;
                }
            } else {
                out[c] = aggregate_weighted_differences(
                    poseidon_transition_challenges
                        [poseidon_transition_challenge_index(layout, group, step)],
                    &next_actual,
                    &state,
                );
                c += 1;
            }
        }
    }
}

pub(crate) fn production_constraint_program(
    statement: &PackedStatement<'_>,
) -> Result<SmallwoodProductionConstraintProgram, TransactionCircuitError> {
    if statement.arithmetization
        != SmallwoodArithmetization::DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "production constraint program requires the deployed committed SmallWood relation",
        ));
    }
    if statement.public_values.len() != PUBLIC_VALUE_COUNT
        || statement.packing_factor != 64
        || statement.auxiliary_limb_count != 0
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "production constraint program geometry does not match the deployed SmallWood relation",
        ));
    }

    SYMBOLIC_ARENA.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "SmallWood symbolic constraint program generation is already active",
            ));
        }
        *slot = Some(SymbolicArena::new());
        Ok(())
    })?;

    let public_values = (0..PUBLIC_VALUE_COUNT)
        .map(SymbolicValue::public_value)
        .collect::<Vec<_>>();
    let rows = (0..statement.row_count)
        .map(SymbolicValue::witness_row)
        .collect::<Vec<_>>();
    let output_ciphertext_challenges = [SymbolicValue::ZERO; MAX_OUTPUTS];
    let slot_denominator_inverses = core::array::from_fn(SymbolicValue::slot_denominator_inverse);
    let stable_selector_bits = core::array::from_fn(SymbolicValue::stable_selector_bit);
    let poseidon_transition_challenges =
        vec![
            SymbolicValue::ZERO;
            poseidon_group_count(statement.packing_factor)
                * PackedRowLayout::for_arithmetization(statement.arithmetization)
                    .poseidon_transition_count()
        ];
    let mut constraint_roots = vec![SymbolicValue::ZERO; statement.constraint_count];
    compute_constraints_ring(
        statement,
        &public_values,
        &rows,
        &[],
        &output_ciphertext_challenges,
        &slot_denominator_inverses,
        stable_selector_bits,
        SymbolicValue::ZERO,
        SymbolicValue::ZERO,
        SymbolicValue::ZERO,
        &poseidon_transition_challenges,
        &mut constraint_roots,
    );

    let arena = SYMBOLIC_ARENA.with(|slot| {
        slot.borrow_mut()
            .take()
            .expect("SmallWood symbolic constraint arena remains active")
    });
    Ok(SmallwoodProductionConstraintProgram {
        public_value_count: PUBLIC_VALUE_COUNT,
        witness_row_count: statement.row_count,
        packing_factor: statement.packing_factor,
        nonlinear_constraint_count: statement.constraint_count,
        expressions: arena.expressions,
        constraint_roots: constraint_roots.into_iter().map(|value| value.0).collect(),
    })
}
