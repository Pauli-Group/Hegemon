use blake3::Hasher;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use transaction_core::{
    constants::POSEIDON2_WIDTH,
    poseidon2::{poseidon2_step, Felt},
};

use crate::error::TransactionCircuitError;

const GOLDILOCKS_MODULUS: u128 = 0xffff_ffff_0000_0001;
const SMALLWOOD_XOF_DOMAIN: &[u8] = b"hegemon.smallwood.f64-xof.v1";

const MAX_INPUTS: usize = 2;
const MAX_OUTPUTS: usize = 2;
const BALANCE_SLOTS: usize = 4;
const MERKLE_DEPTH: usize = 32;
const POSEIDON_STEPS: usize = 31;
const POSEIDON_ROWS_PER_PERMUTATION: usize = POSEIDON_STEPS + 1;
const WORDS_PER_32_BYTES: usize = 4;
const HASH_LIMBS: usize = 6;
const INPUT_ROWS: usize = 245;
const OUTPUT_ROWS: usize = 20;
const PUBLIC_ROWS: usize = 78;
const SECRET_ROWS: usize = 536;
const LANE_SELECTOR_ROWS: usize = 4;
const POSEIDON_SLOT_COUNT: usize = 67;
const NOTE_DOMAIN_TAG: u64 = 1;
const NULLIFIER_DOMAIN_TAG: u64 = 2;
const MERKLE_DOMAIN_TAG: u64 = 4;

const PUB_INPUT_FLAG0: usize = 0;
const PUB_OUTPUT_FLAG0: usize = 2;
const PUB_NULLIFIERS: usize = 4;
const PUB_COMMITMENTS: usize = 16;
const PUB_CIPHERTEXT_HASHES: usize = 28;
const PUB_FEE: usize = 40;
const PUB_VALUE_BALANCE_SIGN: usize = 41;
const PUB_VALUE_BALANCE_MAG: usize = 42;
const PUB_MERKLE_ROOT: usize = 43;
const PUB_SLOT_ASSETS: usize = 49;
const PUB_STABLE_ENABLED: usize = 53;
const PUB_STABLE_ASSET: usize = 54;
const PUB_STABLE_POLICY_VERSION: usize = 55;
const PUB_STABLE_ISSUANCE_SIGN: usize = 56;
const PUB_STABLE_ISSUANCE_MAG: usize = 57;
const PUB_STABLE_POLICY_HASH: usize = 58;
const PUB_STABLE_ORACLE: usize = 64;
const PUB_STABLE_ATTESTATION: usize = 70;

#[derive(Clone)]
pub(crate) struct PackedStatement<'a> {
    linear_constraint_targets: &'a [u64],
    input_pk_auth_challenges: [Felt; MAX_INPUTS],
    input_nullifier_challenges: [Felt; MAX_INPUTS],
    input_root_challenges: [Felt; MAX_INPUTS],
    output_commitment_challenges: [Felt; MAX_OUTPUTS],
    output_ciphertext_challenges: [Felt; MAX_OUTPUTS],
    stable_policy_hash_challenge: Felt,
    stable_oracle_challenge: Felt,
    stable_attestation_challenge: Felt,
    poseidon_init_challenges: Vec<Felt>,
    poseidon_transition_challenges: Vec<Felt>,
}

pub(crate) fn test_candidate_witness_rust(
    witness_values: &[u64],
    row_count: usize,
    packing_factor: usize,
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
) -> Result<(), TransactionCircuitError> {
    if packing_factor != LANE_SELECTOR_ROWS || row_count == 0 {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "unsupported smallwood packing_factor {packing_factor}, expected {LANE_SELECTOR_ROWS}"
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
        row_count,
        packing_factor,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    );
    let constraint_count = constraint_count();
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

impl<'a> PackedStatement<'a> {
    pub(crate) fn new(
        _row_count: usize,
        _packing_factor: usize,
        _linear_constraint_offsets: &'a [u32],
        _linear_constraint_indices: &'a [u32],
        _linear_constraint_coefficients: &'a [u64],
        linear_constraint_targets: &'a [u64],
    ) -> Self {
        let mut statement = Self {
            linear_constraint_targets,
            input_pk_auth_challenges: [Felt::ZERO; MAX_INPUTS],
            input_nullifier_challenges: [Felt::ZERO; MAX_INPUTS],
            input_root_challenges: [Felt::ZERO; MAX_INPUTS],
            output_commitment_challenges: [Felt::ZERO; MAX_OUTPUTS],
            output_ciphertext_challenges: [Felt::ZERO; MAX_OUTPUTS],
            stable_policy_hash_challenge: Felt::ZERO,
            stable_oracle_challenge: Felt::ZERO,
            stable_attestation_challenge: Felt::ZERO,
            poseidon_init_challenges: vec![Felt::ZERO; POSEIDON_SLOT_COUNT],
            poseidon_transition_challenges: vec![Felt::ZERO; POSEIDON_SLOT_COUNT * POSEIDON_STEPS],
        };
        for input in 0..MAX_INPUTS {
            statement.input_pk_auth_challenges[input] =
                nontrivial_challenge(&statement, 1, input as u64, 0);
            statement.input_nullifier_challenges[input] =
                nontrivial_challenge(&statement, 2, input as u64, 0);
            statement.input_root_challenges[input] =
                nontrivial_challenge(&statement, 3, input as u64, 0);
        }
        for output in 0..MAX_OUTPUTS {
            statement.output_commitment_challenges[output] =
                nontrivial_challenge(&statement, 4, output as u64, 0);
            statement.output_ciphertext_challenges[output] =
                nontrivial_challenge(&statement, 5, output as u64, 0);
        }
        statement.stable_policy_hash_challenge = nontrivial_challenge(&statement, 6, 0, 0);
        statement.stable_oracle_challenge = nontrivial_challenge(&statement, 7, 0, 0);
        statement.stable_attestation_challenge = nontrivial_challenge(&statement, 8, 0, 0);
        for slot in 0..POSEIDON_SLOT_COUNT {
            statement.poseidon_init_challenges[slot] =
                nontrivial_challenge(&statement, 9, slot as u64, 0);
            for step in 0..POSEIDON_STEPS {
                let idx = poseidon_transition_challenge_index(slot, step);
                statement.poseidon_transition_challenges[idx] =
                    nontrivial_challenge(&statement, 10, slot as u64, step as u64);
            }
        }
        statement
    }

    pub(crate) fn linear_targets(&self) -> &[u64] {
        self.linear_constraint_targets
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
    let mut input = Vec::with_capacity(PUBLIC_ROWS + 4);
    input.push(0x736d_616c_6c77_6f6f);
    input.push(tag);
    input.push(a);
    input.push(b);
    input.extend_from_slice(&statement.linear_constraint_targets[..PUBLIC_ROWS]);
    let mut output = [0u64; 1];
    xof_words(&input, &mut output);
    if output[0] <= 1 {
        output[0] += 2;
    }
    Felt::from_u64(output[0])
}

fn public_value(statement: &PackedStatement<'_>, row: usize) -> Felt {
    Felt::from_u64(statement.linear_constraint_targets[row])
}

#[inline]
fn row_sk_chunk(chunk: usize) -> usize {
    PUBLIC_ROWS + chunk
}

#[inline]
fn row_input_base(input: usize) -> usize {
    PUBLIC_ROWS + WORDS_PER_32_BYTES + input * INPUT_ROWS
}

#[inline]
fn row_output_base(output: usize) -> usize {
    PUBLIC_ROWS + WORDS_PER_32_BYTES + MAX_INPUTS * INPUT_ROWS + output * OUTPUT_ROWS
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
fn row_input_pk_recipient(input: usize, limb: usize) -> usize {
    row_input_base(input) + 2 + limb
}
#[inline]
fn row_input_pk_auth(input: usize, limb: usize) -> usize {
    row_input_base(input) + 6 + limb
}
#[inline]
fn row_input_rho(input: usize, limb: usize) -> usize {
    row_input_base(input) + 10 + limb
}
#[inline]
fn row_input_r(input: usize, limb: usize) -> usize {
    row_input_base(input) + 14 + limb
}
#[inline]
fn row_input_position(input: usize) -> usize {
    row_input_base(input) + 18
}
#[inline]
fn row_input_selector(input: usize, bit: usize) -> usize {
    row_input_base(input) + 19 + bit
}
#[inline]
fn row_input_direction(input: usize, bit: usize) -> usize {
    row_input_base(input) + 21 + bit
}
#[inline]
fn row_input_sibling(input: usize, level: usize, limb: usize) -> usize {
    row_input_base(input) + 53 + level * HASH_LIMBS + limb
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
fn row_output_pk_recipient(output: usize, limb: usize) -> usize {
    row_output_base(output) + 2 + limb
}
#[inline]
fn row_output_pk_auth(output: usize, limb: usize) -> usize {
    row_output_base(output) + 6 + limb
}
#[inline]
fn row_output_rho(output: usize, limb: usize) -> usize {
    row_output_base(output) + 10 + limb
}
#[inline]
fn row_output_r(output: usize, limb: usize) -> usize {
    row_output_base(output) + 14 + limb
}
#[inline]
fn row_output_selector(output: usize, bit: usize) -> usize {
    row_output_base(output) + 18 + bit
}

#[inline]
fn row_stable_selector(bit: usize) -> usize {
    PUBLIC_ROWS + SECRET_ROWS - 2 + bit
}
#[inline]
fn row_lane_selector(lane: usize) -> usize {
    PUBLIC_ROWS + SECRET_ROWS + lane
}
#[inline]
fn poseidon_rows_start() -> usize {
    PUBLIC_ROWS + SECRET_ROWS + LANE_SELECTOR_ROWS
}
#[inline]
fn poseidon_row(slot: usize, step_row: usize, limb: usize) -> usize {
    poseidon_rows_start()
        + (slot * POSEIDON_ROWS_PER_PERMUTATION + step_row) * POSEIDON2_WIDTH
        + limb
}
#[inline]
fn poseidon_transition_challenge_index(slot: usize, step: usize) -> usize {
    slot * POSEIDON_STEPS + step
}

#[inline]
fn input_commitment_slot(chunk: usize) -> usize {
    chunk
}
#[inline]
fn input_merkle_slot(level: usize, chunk: usize) -> usize {
    3 + level * 2 + chunk
}
#[inline]
fn input_nullifier_slot(input: usize) -> usize {
    1 + input
}
#[inline]
fn output_commitment_slot(output: usize, chunk: usize) -> usize {
    3 + output * 3 + chunk
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

fn aggregate_weighted_differences(challenge: Felt, lhs: &[Felt], rhs: &[Felt]) -> Felt {
    let mut acc = Felt::ZERO;
    let mut power = Felt::ONE;
    for (&left, &right) in lhs.iter().zip(rhs.iter()) {
        acc += power * (left - right);
        power *= challenge;
    }
    acc
}

#[inline]
fn lane_weight(rows: &[Felt], lane: usize) -> Felt {
    rows[row_lane_selector(lane)]
}

fn signed_from_parts(sign: Felt, magnitude: Felt) -> Felt {
    magnitude - (sign + sign) * magnitude
}

fn fill_zero_state(state: &mut [Felt; POSEIDON2_WIDTH]) {
    *state = [Felt::ZERO; POSEIDON2_WIDTH];
}

fn initial_fresh_state(state: &mut [Felt; POSEIDON2_WIDTH], domain_tag: u64, absorb: &[Felt]) {
    fill_zero_state(state);
    state[0] = Felt::from_u64(domain_tag);
    state[POSEIDON2_WIDTH - 1] = Felt::ONE;
    for (idx, value) in absorb.iter().enumerate() {
        state[idx] += *value;
    }
}

fn continued_state(
    state: &mut [Felt; POSEIDON2_WIDTH],
    previous: &[Felt; POSEIDON2_WIDTH],
    absorb: &[Felt],
) {
    *state = *previous;
    for (idx, value) in absorb.iter().enumerate() {
        state[idx] += *value;
    }
}

fn input_commitment_chunk(rows: &[Felt], input: usize, chunk: usize, absorb: &mut [Felt; 6]) {
    if chunk == 0 {
        absorb[0] = rows[row_input_value(input)];
        absorb[1] = rows[row_input_asset(input)];
        for limb in 0..4 {
            absorb[2 + limb] = rows[row_input_pk_recipient(input, limb)];
        }
        return;
    }
    if chunk == 1 {
        for limb in 0..4 {
            absorb[limb] = rows[row_input_rho(input, limb)];
        }
        absorb[4] = rows[row_input_r(input, 0)];
        absorb[5] = rows[row_input_r(input, 1)];
        return;
    }
    absorb[0] = rows[row_input_r(input, 2)];
    absorb[1] = rows[row_input_r(input, 3)];
    for limb in 0..4 {
        absorb[2 + limb] = rows[row_input_pk_auth(input, limb)];
    }
}

fn output_commitment_chunk(rows: &[Felt], output: usize, chunk: usize, absorb: &mut [Felt; 6]) {
    if chunk == 0 {
        absorb[0] = rows[row_output_value(output)];
        absorb[1] = rows[row_output_asset(output)];
        for limb in 0..4 {
            absorb[2 + limb] = rows[row_output_pk_recipient(output, limb)];
        }
        return;
    }
    if chunk == 1 {
        for limb in 0..4 {
            absorb[limb] = rows[row_output_rho(output, limb)];
        }
        absorb[4] = rows[row_output_r(output, 0)];
        absorb[5] = rows[row_output_r(output, 1)];
        return;
    }
    absorb[0] = rows[row_output_r(output, 2)];
    absorb[1] = rows[row_output_r(output, 3)];
    for limb in 0..4 {
        absorb[2 + limb] = rows[row_output_pk_auth(output, limb)];
    }
}

fn input_hash_output(rows: &[Felt], level: usize, limb: usize) -> Felt {
    if level == 0 {
        rows[poseidon_row(input_commitment_slot(2), POSEIDON_STEPS, limb)]
    } else {
        rows[poseidon_row(input_merkle_slot(level - 1, 1), POSEIDON_STEPS, limb)]
    }
}

fn merkle_absorb_chunk(
    rows: &[Felt],
    input: usize,
    level: usize,
    chunk: usize,
    absorb: &mut [Felt; 6],
) {
    let dir = rows[row_input_direction(input, level)];
    for (limb, slot) in absorb.iter_mut().enumerate().take(HASH_LIMBS) {
        let current = input_hash_output(rows, level, limb);
        let sibling = rows[row_input_sibling(input, level, limb)];
        let left = current + dir * (sibling - current);
        let right = sibling + dir * (current - sibling);
        *slot = if chunk == 0 { left } else { right };
    }
}

fn nullifier_absorb_chunk(rows: &[Felt], input: usize, absorb: &mut [Felt; 6]) {
    absorb[0] = rows[poseidon_row(0, POSEIDON_STEPS, 0)];
    absorb[1] = rows[row_input_position(input)];
    for limb in 0..4 {
        absorb[2 + limb] = rows[row_input_rho(input, limb)];
    }
}

fn dummy_initial_state(expected: &mut [Felt; POSEIDON2_WIDTH]) {
    initial_fresh_state(expected, 0, &[]);
}

fn expected_initial_state_for_lane(
    rows: &[Felt],
    lane: usize,
    slot: usize,
    expected: &mut [Felt; POSEIDON2_WIDTH],
) {
    let mut absorb = [Felt::ZERO; 6];
    if lane == 0 || lane == 1 {
        let input = lane;
        if slot < 3 {
            input_commitment_chunk(rows, input, slot, &mut absorb);
            if slot == 0 {
                initial_fresh_state(expected, NOTE_DOMAIN_TAG, &absorb);
            } else {
                let mut previous = [Felt::ZERO; POSEIDON2_WIDTH];
                for limb in 0..POSEIDON2_WIDTH {
                    previous[limb] = rows[poseidon_row(slot - 1, POSEIDON_STEPS, limb)];
                }
                continued_state(expected, &previous, &absorb);
            }
            return;
        }
        if slot < POSEIDON_SLOT_COUNT {
            let merkle_local = slot - 3;
            let level = merkle_local / 2;
            let chunk = merkle_local % 2;
            merkle_absorb_chunk(rows, input, level, chunk, &mut absorb);
            if chunk == 0 {
                initial_fresh_state(expected, MERKLE_DOMAIN_TAG, &absorb);
            } else {
                let mut previous = [Felt::ZERO; POSEIDON2_WIDTH];
                for limb in 0..POSEIDON2_WIDTH {
                    previous[limb] = rows[poseidon_row(slot - 1, POSEIDON_STEPS, limb)];
                }
                continued_state(expected, &previous, &absorb);
            }
            return;
        }
    }

    if lane == 2 {
        if slot == 0 {
            for limb in 0..WORDS_PER_32_BYTES {
                absorb[limb] = rows[row_sk_chunk(limb)];
            }
            initial_fresh_state(expected, NULLIFIER_DOMAIN_TAG, &absorb[..WORDS_PER_32_BYTES]);
            return;
        }
        if slot == 1 || slot == 2 {
            nullifier_absorb_chunk(rows, slot - 1, &mut absorb);
            initial_fresh_state(expected, NULLIFIER_DOMAIN_TAG, &absorb);
            return;
        }
        if (3..=8).contains(&slot) {
            let output = if slot < 6 { 0 } else { 1 };
            let chunk = if slot < 6 { slot - 3 } else { slot - 6 };
            output_commitment_chunk(rows, output, chunk, &mut absorb);
            if chunk == 0 {
                initial_fresh_state(expected, NOTE_DOMAIN_TAG, &absorb);
            } else {
                let mut previous = [Felt::ZERO; POSEIDON2_WIDTH];
                for limb in 0..POSEIDON2_WIDTH {
                    previous[limb] = rows[poseidon_row(slot - 1, POSEIDON_STEPS, limb)];
                }
                continued_state(expected, &previous, &absorb);
            }
            return;
        }
    }

    dummy_initial_state(expected);
}

fn expected_initial_state(rows: &[Felt], slot: usize, expected: &mut [Felt; POSEIDON2_WIDTH]) {
    let lane_weights = [
        lane_weight(rows, 0),
        lane_weight(rows, 1),
        lane_weight(rows, 2),
        lane_weight(rows, 3),
    ];
    let mut lane_expected = [[Felt::ZERO; POSEIDON2_WIDTH]; 4];
    for lane in 0..4 {
        expected_initial_state_for_lane(rows, lane, slot, &mut lane_expected[lane]);
    }
    for limb in 0..POSEIDON2_WIDTH {
        expected[limb] = Felt::ZERO;
        for lane in 0..4 {
            expected[limb] += lane_weights[lane] * lane_expected[lane][limb];
        }
    }
}

pub(crate) fn packed_constraint_count() -> usize {
    constraint_count()
}

pub(crate) fn compute_constraints_u64(
    statement: &PackedStatement<'_>,
    rows: &[u64],
    out: &mut [u64],
) -> Result<(), TransactionCircuitError> {
    let expected = constraint_count();
    if out.len() != expected {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood constraint buffer has length {}, expected {expected}",
            out.len()
        )));
    }
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
    let input_constraints = MAX_INPUTS * (2 + MERKLE_DEPTH + 1 + 1 + 1 + 1 + 1);
    let output_constraints = MAX_OUTPUTS * (2 + 1 + 1 + 1);
    let stablecoin_constraints = 2 + 1 + 1 + 7;
    let balance_constraints = BALANCE_SLOTS;
    let poseidon_init = POSEIDON_SLOT_COUNT;
    let poseidon_transition = POSEIDON_SLOT_COUNT * POSEIDON_STEPS;
    public_bools
        + input_constraints
        + output_constraints
        + stablecoin_constraints
        + balance_constraints
        + poseidon_init
        + poseidon_transition
}

fn compute_constraints(statement: &PackedStatement<'_>, rows: &[Felt], out: &mut [Felt]) {
    let mut c = 0usize;
    let lane0 = lane_weight(rows, 0);
    let lane1 = lane_weight(rows, 1);
    let lane2 = lane_weight(rows, 2);

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
        let selector0 = rows[row_input_selector(input, 0)];
        let selector1 = rows[row_input_selector(input, 1)];
        let flag = public_value(statement, PUB_INPUT_FLAG0 + input);
        out[c] = felt_bool_v(selector0);
        c += 1;
        out[c] = felt_bool_v(selector1);
        c += 1;
        for bit in 0..MERKLE_DEPTH {
            out[c] = felt_bool_v(rows[row_input_direction(input, bit)]);
            c += 1;
        }
        let mut position_sum = Felt::ZERO;
        for bit in 0..MERKLE_DEPTH {
            position_sum += rows[row_input_direction(input, bit)] * Felt::from_u64(1u64 << bit);
        }
        out[c] = rows[row_input_position(input)] - position_sum;
        c += 1;
        out[c] =
            selected_slot_asset(statement, selector0, selector1) - rows[row_input_asset(input)];
        c += 1;

        let mut lhs = [Felt::ZERO; WORDS_PER_32_BYTES];
        let mut rhs = [Felt::ZERO; WORDS_PER_32_BYTES];
        for limb in 0..WORDS_PER_32_BYTES {
            lhs[limb] = rows[row_input_pk_auth(input, limb)];
            rhs[limb] = rows[poseidon_row(0, POSEIDON_STEPS, limb + 1)];
        }
        out[c] = lane2
            * flag
            * aggregate_weighted_differences(statement.input_pk_auth_challenges[input], &lhs, &rhs);
        c += 1;

        let mut lhs_hash = [Felt::ZERO; HASH_LIMBS];
        let mut rhs_hash = [Felt::ZERO; HASH_LIMBS];
        for limb in 0..HASH_LIMBS {
            lhs_hash[limb] = public_value(statement, PUB_NULLIFIERS + input * HASH_LIMBS + limb);
            rhs_hash[limb] =
                flag * rows[poseidon_row(input_nullifier_slot(input), POSEIDON_STEPS, limb)];
        }
        out[c] = lane2
            * aggregate_weighted_differences(
                statement.input_nullifier_challenges[input],
                &lhs_hash,
                &rhs_hash,
            );
        c += 1;

        let lane_weight_for_root = if input == 0 { lane0 } else { lane1 };
        for limb in 0..HASH_LIMBS {
            lhs_hash[limb] =
                rows[poseidon_row(input_merkle_slot(MERKLE_DEPTH - 1, 1), POSEIDON_STEPS, limb)];
            rhs_hash[limb] = public_value(statement, PUB_MERKLE_ROOT + limb);
        }
        out[c] = lane_weight_for_root
            * flag
            * aggregate_weighted_differences(statement.input_root_challenges[input], &lhs_hash, &rhs_hash);
        c += 1;
    }

    for output_idx in 0..MAX_OUTPUTS {
        let selector0 = rows[row_output_selector(output_idx, 0)];
        let selector1 = rows[row_output_selector(output_idx, 1)];
        let flag = public_value(statement, PUB_OUTPUT_FLAG0 + output_idx);
        let inactive = Felt::ONE - flag;
        out[c] = felt_bool_v(selector0);
        c += 1;
        out[c] = felt_bool_v(selector1);
        c += 1;
        out[c] =
            selected_slot_asset(statement, selector0, selector1) - rows[row_output_asset(output_idx)];
        c += 1;

        let mut lhs_hash = [Felt::ZERO; HASH_LIMBS];
        let mut rhs_hash = [Felt::ZERO; HASH_LIMBS];
        for limb in 0..HASH_LIMBS {
            lhs_hash[limb] =
                public_value(statement, PUB_COMMITMENTS + output_idx * HASH_LIMBS + limb);
            rhs_hash[limb] = flag
                * rows[poseidon_row(output_commitment_slot(output_idx, 2), POSEIDON_STEPS, limb)];
        }
        out[c] = lane2
            * aggregate_weighted_differences(
                statement.output_commitment_challenges[output_idx],
                &lhs_hash,
                &rhs_hash,
            );
        c += 1;

        for limb in 0..HASH_LIMBS {
            lhs_hash[limb] = inactive
                * public_value(statement, PUB_CIPHERTEXT_HASHES + output_idx * HASH_LIMBS + limb);
            rhs_hash[limb] = Felt::ZERO;
        }
        out[c] = aggregate_weighted_differences(
            statement.output_ciphertext_challenges[output_idx],
            &lhs_hash,
            &rhs_hash,
        );
        c += 1;
    }

    let stable_selector0 = rows[row_stable_selector(0)];
    let stable_selector1 = rows[row_stable_selector(1)];
    let stable_enabled = public_value(statement, PUB_STABLE_ENABLED);
    let stable_disabled = Felt::ONE - stable_enabled;
    out[c] = felt_bool_v(stable_selector0);
    c += 1;
    out[c] = felt_bool_v(stable_selector1);
    c += 1;
    out[c] =
        selected_slot_asset(statement, stable_selector0, stable_selector1)
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
    for limb in 0..HASH_LIMBS {
        lhs_hash[limb] = stable_disabled * public_value(statement, PUB_STABLE_POLICY_HASH + limb);
    }
    out[c] = aggregate_weighted_differences(statement.stable_policy_hash_challenge, &lhs_hash, &rhs_hash);
    c += 1;
    for limb in 0..HASH_LIMBS {
        lhs_hash[limb] = stable_disabled * public_value(statement, PUB_STABLE_ORACLE + limb);
    }
    out[c] = aggregate_weighted_differences(statement.stable_oracle_challenge, &lhs_hash, &rhs_hash);
    c += 1;
    for limb in 0..HASH_LIMBS {
        lhs_hash[limb] = stable_disabled * public_value(statement, PUB_STABLE_ATTESTATION + limb);
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
            let weight = selected_slot_weight(
                rows[row_input_selector(input, 0)],
                rows[row_input_selector(input, 1)],
                slot,
            );
            delta += flag * rows[row_input_value(input)] * weight;
        }
        for output_idx in 0..MAX_OUTPUTS {
            let flag = public_value(statement, PUB_OUTPUT_FLAG0 + output_idx);
            let weight = selected_slot_weight(
                rows[row_output_selector(output_idx, 0)],
                rows[row_output_selector(output_idx, 1)],
                slot,
            );
            delta -= flag * rows[row_output_value(output_idx)] * weight;
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

    for slot in 0..POSEIDON_SLOT_COUNT {
        let mut expected = [Felt::ZERO; POSEIDON2_WIDTH];
        expected_initial_state(rows, slot, &mut expected);
        let mut current = [Felt::ZERO; POSEIDON2_WIDTH];
        for limb in 0..POSEIDON2_WIDTH {
            current[limb] = rows[poseidon_row(slot, 0, limb)];
        }
        out[c] = aggregate_weighted_differences(
            statement.poseidon_init_challenges[slot],
            &current,
            &expected,
        );
        c += 1;

        for step in 0..POSEIDON_STEPS {
            let mut state = [Felt::ZERO; POSEIDON2_WIDTH];
            let mut next_actual = [Felt::ZERO; POSEIDON2_WIDTH];
            for limb in 0..POSEIDON2_WIDTH {
                state[limb] = rows[poseidon_row(slot, step, limb)];
                next_actual[limb] = rows[poseidon_row(slot, step + 1, limb)];
            }
            poseidon2_step(&mut state, step);
            out[c] = aggregate_weighted_differences(
                statement.poseidon_transition_challenges
                    [poseidon_transition_challenge_index(slot, step)],
                &next_actual,
                &state,
            );
            c += 1;
        }
    }
}
