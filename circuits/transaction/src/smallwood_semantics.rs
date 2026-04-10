use blake3::Hasher;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use transaction_core::{
    constants::POSEIDON2_WIDTH,
    poseidon2::{poseidon2_step, Felt},
};

use crate::{error::TransactionCircuitError, smallwood_engine::SmallwoodArithmetization};

const GOLDILOCKS_MODULUS: u128 = 0xffff_ffff_0000_0001;
const SMALLWOOD_XOF_DOMAIN: &[u8] = b"hegemon.smallwood.f64-xof.v1";

const MAX_INPUTS: usize = 2;
const MAX_OUTPUTS: usize = 2;
const BALANCE_SLOTS: usize = 4;
const MERKLE_DEPTH: usize = 32;
const POSEIDON_STEPS: usize = 31;
const POSEIDON_ROWS_PER_PERMUTATION: usize = POSEIDON_STEPS + 1;
const HASH_LIMBS: usize = 6;
const INPUT_ROWS: usize = 130;
const OUTPUT_ROWS: usize = 2 + HASH_LIMBS;
const STABLE_BINDING_ROWS: usize = 1 + (HASH_LIMBS * 3);
const PUBLIC_ROWS: usize = 0;
const PUBLIC_VALUE_COUNT: usize = 78;
const SECRET_ROWS: usize =
    (MAX_INPUTS * INPUT_ROWS) + (MAX_OUTPUTS * OUTPUT_ROWS) + STABLE_BINDING_ROWS;
const PACKING_FACTOR: usize = 64;
const INPUT_PERMUTATIONS: usize = 3 + MERKLE_DEPTH * 2 + 1;
const OUTPUT_PERMUTATIONS: usize = 3;
const POSEIDON_PERMUTATION_COUNT: usize =
    1 + MAX_INPUTS * INPUT_PERMUTATIONS + MAX_OUTPUTS * OUTPUT_PERMUTATIONS;
const POSEIDON_GROUP_COUNT: usize =
    (POSEIDON_PERMUTATION_COUNT + PACKING_FACTOR - 1) / PACKING_FACTOR;
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
    if packing_factor != PACKING_FACTOR || row_count == 0 {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "unsupported smallwood packing_factor {packing_factor}, expected {PACKING_FACTOR}"
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

    for lane in 0..packing_factor {
        for row in 0..row_count {
            lane_rows[row] = Felt::from_u64(witness_values[row * packing_factor + lane]);
        }
        compute_constraints(&statement, &lane_rows, &mut constraint_row);
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
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    )?;
    Ok(())
}

fn verify_linear_constraints(
    witness_values: &[u64],
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
            acc += coeff * Felt::from_u64(witness_values[idx]);
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
        let mut statement = Self {
            arithmetization,
            public_values,
            row_count,
            packing_factor,
            constraint_degree,
            linear_constraint_count: linear_constraint_targets.len(),
            constraint_count: constraint_count(),
            linear_constraint_offsets,
            linear_constraint_indices,
            linear_constraint_coefficients,
            linear_constraint_targets,
            output_ciphertext_challenges: [Felt::ZERO; MAX_OUTPUTS],
            slot_denominator_inverses: derive_slot_denominator_inverses(public_values),
            stable_selector_bits: derive_stable_selector_bits(public_values),
            stable_policy_hash_challenge: Felt::ZERO,
            stable_oracle_challenge: Felt::ZERO,
            stable_attestation_challenge: Felt::ZERO,
            poseidon_transition_challenges: vec![Felt::ZERO; POSEIDON_GROUP_COUNT * POSEIDON_STEPS],
        };
        for output in 0..MAX_OUTPUTS {
            statement.output_ciphertext_challenges[output] =
                nontrivial_challenge(&statement, 5, output as u64, 0);
        }
        statement.stable_policy_hash_challenge = nontrivial_challenge(&statement, 6, 0, 0);
        statement.stable_oracle_challenge = nontrivial_challenge(&statement, 7, 0, 0);
        statement.stable_attestation_challenge = nontrivial_challenge(&statement, 8, 0, 0);
        for group in 0..POSEIDON_GROUP_COUNT {
            for step in 0..POSEIDON_STEPS {
                let idx = poseidon_transition_challenge_index(group, step);
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

pub(crate) trait SmallwoodConstraintAdapter: Sync {
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
    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        row_scalars: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a>;
    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError>;
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum SmallwoodNonlinearEvalView<'a> {
    RowScalars { eval_point: u64, rows: &'a [u64] },
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

    fn nonlinear_eval_view<'b>(
        &self,
        eval_point: u64,
        row_scalars: &'b [u64],
    ) -> SmallwoodNonlinearEvalView<'b> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows: row_scalars,
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

fn public_value(statement: &PackedStatement<'_>, row: usize) -> Felt {
    Felt::from_u64(statement.public_values[row])
}

#[inline]
fn row_input_base(input: usize) -> usize {
    PUBLIC_ROWS + input * INPUT_ROWS
}

#[inline]
fn row_input_direction(input: usize, bit: usize) -> usize {
    row_input_base(input) + 2 + bit
}

#[inline]
fn row_input_value(input: usize) -> usize {
    row_input_base(input)
}

#[inline]
fn row_input_asset(input: usize) -> usize {
    row_input_base(input) + 1
}

#[inline]
fn row_input_current_agg(input: usize, level: usize) -> usize {
    row_input_base(input) + 34 + level
}

#[inline]
fn row_input_left_agg(input: usize, level: usize) -> usize {
    row_input_base(input) + 66 + level
}

#[inline]
fn row_input_right_agg(input: usize, level: usize) -> usize {
    row_input_base(input) + 98 + level
}

#[inline]
fn row_output_base(output: usize) -> usize {
    PUBLIC_ROWS + MAX_INPUTS * INPUT_ROWS + output * OUTPUT_ROWS
}

#[inline]
fn row_output_value(output: usize) -> usize {
    row_output_base(output)
}

#[inline]
fn row_output_asset(output: usize) -> usize {
    row_output_base(output) + 1
}

#[inline]
fn poseidon_rows_start() -> usize {
    PUBLIC_ROWS + SECRET_ROWS
}
#[inline]
fn poseidon_group_row(group: usize, step_row: usize, limb: usize) -> usize {
    poseidon_rows_start()
        + (group * POSEIDON_ROWS_PER_PERMUTATION + step_row) * POSEIDON2_WIDTH
        + limb
}
#[inline]
fn poseidon_transition_challenge_index(group: usize, step: usize) -> usize {
    group * POSEIDON_STEPS + step
}

#[inline]
fn felt_bool_v(bit: Felt) -> Felt {
    bit * (bit - Felt::ONE)
}

#[inline]
fn selected_slot_weight(bit0: Felt, bit1: Felt, slot: usize) -> Felt {
    let inv0 = Felt::ONE - bit0;
    let inv1 = Felt::ONE - bit1;
    match slot {
        0 => inv0 * inv1,
        1 => bit0 * inv1,
        2 => inv0 * bit1,
        _ => bit0 * bit1,
    }
}

fn selected_slot_asset(statement: &PackedStatement<'_>, bit0: Felt, bit1: Felt) -> Felt {
    let mut result = Felt::ZERO;
    for slot in 0..BALANCE_SLOTS {
        let weight = selected_slot_weight(bit0, bit1, slot);
        result += weight * public_value(statement, PUB_SLOT_ASSETS + slot);
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

fn slot_membership_weights(statement: &PackedStatement<'_>, asset: Felt) -> [Felt; BALANCE_SLOTS] {
    let mut weights = [Felt::ZERO; BALANCE_SLOTS];
    for (slot, weight) in weights.iter_mut().enumerate().take(BALANCE_SLOTS) {
        let mut numerator = Felt::ONE;
        for other in 0..BALANCE_SLOTS {
            if other == slot {
                continue;
            }
            numerator *= asset - public_value(statement, PUB_SLOT_ASSETS + other);
        }
        *weight = numerator * statement.slot_denominator_inverses[slot];
    }
    weights
}

fn slot_membership_zero(statement: &PackedStatement<'_>, asset: Felt) -> Felt {
    let mut acc = Felt::ONE;
    for slot in 0..BALANCE_SLOTS {
        acc *= asset - public_value(statement, PUB_SLOT_ASSETS + slot);
    }
    acc
}

fn aggregate_weighted_differences(challenge: Felt, lhs: &[Felt], rhs: &[Felt]) -> Felt {
    let mut acc = Felt::ZERO;
    let mut power = Felt::ONE;
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

fn signed_from_parts(sign: Felt, magnitude: Felt) -> Felt {
    magnitude - (sign + sign) * magnitude
}

#[allow(dead_code)]
pub(crate) fn packed_constraint_count() -> usize {
    constraint_count()
}

pub(crate) fn compute_bridge_constraints_u64(
    statement: &PackedStatement<'_>,
    view: SmallwoodNonlinearEvalView<'_>,
    out: &mut [u64],
) -> Result<(), TransactionCircuitError> {
    let expected = constraint_count();
    if out.len() != expected {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood constraint buffer has length {}, expected {expected}",
            out.len()
        )));
    }
    let SmallwoodNonlinearEvalView::RowScalars {
        eval_point: _eval_point,
        rows,
    } = view;
    let felt_rows = rows.iter().copied().map(Felt::from_u64).collect::<Vec<_>>();
    let mut felt_out = vec![Felt::ZERO; expected];
    compute_constraints(statement, &felt_rows, &mut felt_out);
    for (dst, src) in out.iter_mut().zip(felt_out.iter()) {
        *dst = src.as_canonical_u64();
    }
    Ok(())
}

fn constraint_count() -> usize {
    let public_bools = MAX_INPUTS + MAX_OUTPUTS + 3;
    let input_constraints = MAX_INPUTS * (MERKLE_DEPTH + 1 + MERKLE_DEPTH);
    let output_constraints = MAX_OUTPUTS * (1 + 1);
    let stablecoin_constraints = 1 + 1 + 7;
    let balance_constraints = BALANCE_SLOTS;
    let poseidon_transition = POSEIDON_GROUP_COUNT * POSEIDON_STEPS;
    public_bools
        + input_constraints
        + output_constraints
        + stablecoin_constraints
        + balance_constraints
        + poseidon_transition
}

fn compute_constraints(statement: &PackedStatement<'_>, rows: &[Felt], out: &mut [Felt]) {
    let mut c = 0usize;

    for input in 0..MAX_INPUTS {
        out[c] = felt_bool_v(public_value(statement, PUB_INPUT_FLAG0 + input));
        c += 1;
    }
    for output in 0..MAX_OUTPUTS {
        out[c] = felt_bool_v(public_value(statement, PUB_OUTPUT_FLAG0 + output));
        c += 1;
    }
    out[c] = felt_bool_v(public_value(statement, PUB_VALUE_BALANCE_SIGN));
    c += 1;
    out[c] = felt_bool_v(public_value(statement, PUB_STABLE_ENABLED));
    c += 1;
    out[c] = felt_bool_v(public_value(statement, PUB_STABLE_ISSUANCE_SIGN));
    c += 1;

    for input in 0..MAX_INPUTS {
        let asset = rows[row_input_asset(input)];
        let flag = public_value(statement, PUB_INPUT_FLAG0 + input);
        for bit in 0..MERKLE_DEPTH {
            out[c] = felt_bool_v(rows[row_input_direction(input, bit)]);
            c += 1;
        }
        let mut position_sum = Felt::ZERO;
        for bit in 0..MERKLE_DEPTH {
            position_sum += rows[row_input_direction(input, bit)] * Felt::from_u64(1u64 << bit);
        }
        let _ = position_sum;
        out[c] = flag * slot_membership_zero(statement, asset);
        c += 1;

        for level in 0..MERKLE_DEPTH {
            let dir = rows[row_input_direction(input, level)];
            let current = rows[row_input_current_agg(input, level)];
            let left = rows[row_input_left_agg(input, level)];
            let right = rows[row_input_right_agg(input, level)];
            out[c] = flag * (current - (left + dir * (right - left)));
            c += 1;
        }
    }

    for output_idx in 0..MAX_OUTPUTS {
        let asset = rows[row_output_asset(output_idx)];
        let flag = public_value(statement, PUB_OUTPUT_FLAG0 + output_idx);
        let inactive = Felt::ONE - flag;
        out[c] = flag * slot_membership_zero(statement, asset);
        c += 1;

        let mut lhs_hash = [Felt::ZERO; HASH_LIMBS];
        let rhs_hash = [Felt::ZERO; HASH_LIMBS];
        for (limb, lhs_limb) in lhs_hash.iter_mut().enumerate().take(HASH_LIMBS) {
            *lhs_limb = inactive
                * public_value(
                    statement,
                    PUB_CIPHERTEXT_HASHES + output_idx * HASH_LIMBS + limb,
                );
        }
        out[c] = aggregate_weighted_differences(
            statement.output_ciphertext_challenges[output_idx],
            &lhs_hash,
            &rhs_hash,
        );
        c += 1;
    }

    let stable_selector0 = statement.stable_selector_bits[0];
    let stable_selector1 = statement.stable_selector_bits[1];
    let stable_enabled = public_value(statement, PUB_STABLE_ENABLED);
    let stable_disabled = Felt::ONE - stable_enabled;
    out[c] = selected_slot_asset(statement, stable_selector0, stable_selector1)
        - public_value(statement, PUB_STABLE_ASSET);
    c += 1;
    out[c] = stable_enabled * selected_slot_weight(stable_selector0, stable_selector1, 0);
    c += 1;
    out[c] = stable_disabled * public_value(statement, PUB_STABLE_ASSET);
    c += 1;
    out[c] = stable_disabled * public_value(statement, PUB_STABLE_POLICY_VERSION);
    c += 1;
    out[c] = stable_disabled * public_value(statement, PUB_STABLE_ISSUANCE_SIGN);
    c += 1;
    out[c] = stable_disabled * public_value(statement, PUB_STABLE_ISSUANCE_MAG);
    c += 1;

    let mut lhs_hash = [Felt::ZERO; HASH_LIMBS];
    let rhs_hash = [Felt::ZERO; HASH_LIMBS];
    for (limb, lhs_limb) in lhs_hash.iter_mut().enumerate().take(HASH_LIMBS) {
        *lhs_limb = stable_disabled * public_value(statement, PUB_STABLE_POLICY_HASH + limb);
    }
    out[c] = aggregate_weighted_differences(
        statement.stable_policy_hash_challenge,
        &lhs_hash,
        &rhs_hash,
    );
    c += 1;
    for (limb, lhs_limb) in lhs_hash.iter_mut().enumerate().take(HASH_LIMBS) {
        *lhs_limb = stable_disabled * public_value(statement, PUB_STABLE_ORACLE + limb);
    }
    out[c] =
        aggregate_weighted_differences(statement.stable_oracle_challenge, &lhs_hash, &rhs_hash);
    c += 1;
    for (limb, lhs_limb) in lhs_hash.iter_mut().enumerate().take(HASH_LIMBS) {
        *lhs_limb = stable_disabled * public_value(statement, PUB_STABLE_ATTESTATION + limb);
    }
    out[c] = aggregate_weighted_differences(
        statement.stable_attestation_challenge,
        &lhs_hash,
        &rhs_hash,
    );
    c += 1;

    let signed_value_balance = signed_from_parts(
        public_value(statement, PUB_VALUE_BALANCE_SIGN),
        public_value(statement, PUB_VALUE_BALANCE_MAG),
    );
    let signed_stable_issuance = signed_from_parts(
        public_value(statement, PUB_STABLE_ISSUANCE_SIGN),
        public_value(statement, PUB_STABLE_ISSUANCE_MAG),
    );
    let native_expected = public_value(statement, PUB_FEE) - signed_value_balance;

    for slot in 0..BALANCE_SLOTS {
        let mut delta = Felt::ZERO;
        for input in 0..MAX_INPUTS {
            let flag = public_value(statement, PUB_INPUT_FLAG0 + input);
            let value = rows[row_input_value(input)];
            let asset = rows[row_input_asset(input)];
            let weight = slot_membership_weights(statement, asset)[slot];
            delta += flag * value * weight;
        }
        for output_idx in 0..MAX_OUTPUTS {
            let flag = public_value(statement, PUB_OUTPUT_FLAG0 + output_idx);
            let value = rows[row_output_value(output_idx)];
            let asset = rows[row_output_asset(output_idx)];
            let weight = slot_membership_weights(statement, asset)[slot];
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

    for group in 0..POSEIDON_GROUP_COUNT {
        for step in 0..POSEIDON_STEPS {
            let mut state = [Felt::ZERO; POSEIDON2_WIDTH];
            let mut next_actual = [Felt::ZERO; POSEIDON2_WIDTH];
            for limb in 0..POSEIDON2_WIDTH {
                state[limb] = rows[poseidon_group_row(group, step, limb)];
                next_actual[limb] = rows[poseidon_group_row(group, step + 1, limb)];
            }
            poseidon2_step(&mut state, step);
            out[c] = aggregate_weighted_differences(
                statement.poseidon_transition_challenges
                    [poseidon_transition_challenge_index(group, step)],
                &next_actual,
                &state,
            );
            c += 1;
        }
    }
}
