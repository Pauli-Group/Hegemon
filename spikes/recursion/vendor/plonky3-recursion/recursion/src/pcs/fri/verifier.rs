use alloc::collections::btree_map::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::iter;

use p3_circuit::{CircuitBuilder, CircuitBuilderError};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{ExtensionField, Field, PrimeField64, TwoAdicField};
use p3_matrix::Dimensions;
use p3_util::zip_eq::zip_eq;

use super::{BatchOpeningTargets, FriProofTargets, InputProofTargets};
use crate::Target;
use crate::traits::{ComsWithOpeningsTargets, Recursive, RecursiveExtensionMmcs, RecursiveMmcs};
use crate::verifier::{ObservableCommitment, VerificationError};

/// Inputs for one FRI fold phase (matches the values used by the verifier per round).
#[derive(Clone, Debug)]
pub struct FoldPhaseInputsTarget {
    /// Per-phase challenge β (sampled after observing that layer's commitment).
    pub beta: Target,
    /// Subgroup point x₀ for this phase (the other point is x₁ = −x₀).
    pub x0: Target,
    /// Sibling evaluation at the opposite child index.
    pub e_sibling: Target,
    /// Boolean {0,1}. Equals 1 iff sibling occupies evals[1] (the "right" slot).
    /// In Plonky3 this is 1 − (domain_index & 1) at this phase.
    pub sibling_is_right: Target,
    /// Optional reduced opening to roll in at this height (added as β² · roll_in).
    pub roll_in: Option<Target>,
}

const GOLDILOCKS_ORDER_U64: u64 = 18446744069414584321;
const POSEIDON2_WIDTH: usize = 12;
const POSEIDON2_RATE: usize = 6;
const POSEIDON2_EXTERNAL_ROUNDS: usize = 4;
const POSEIDON2_INTERNAL_ROUNDS: usize = 22;

const INTERNAL_MATRIX_DIAG: [u64; POSEIDON2_WIDTH] = [
    0xc3b6c08e23ba9300,
    0xd84b5de94a324fb6,
    0x0d0c371c5b35b84f,
    0x7964f570e7188037,
    0x5daf18bbd996604b,
    0x6743bc47b9595257,
    0x5528b9362c59bb70,
    0xac45e25b7127b68b,
    0xa2077d7dfbb606b5,
    0xf3faac6faee378ae,
    0x0c6388b51545e883,
    0xd27dbb6944917b60,
];

const EXTERNAL_ROUND_CONSTANTS: [[[u64; POSEIDON2_WIDTH]; POSEIDON2_EXTERNAL_ROUNDS]; 2] = [
    [
        [
            0x7914ff869d09bdc3,
            0xb03ee00cfebfb05b,
            0x375eb98de727052d,
            0xdd8d1543e04114c3,
            0xfb0767ab77ed1f7a,
            0x542cc730c3972c50,
            0xa825a62cfe711418,
            0xe47f81105525816a,
            0xeb5c7dcde6c3738a,
            0x6b8104926185e10e,
            0xa06eee93a6045fb8,
            0xbd87e85188445457,
        ],
        [
            0xb1b6960dc01581f4,
            0x1115e21368af8891,
            0x14d94244202b4d15,
            0x92e83baa9d07f0ef,
            0x1966581757bdfb99,
            0x1902430824b960d7,
            0xcb327f95f40eaecd,
            0xe5fafddec3c17c1f,
            0x92421473488f71bd,
            0x2168f2b2f622ae51,
            0xd191e8bda72fe558,
            0x31ae6876405abab5,
        ],
        [
            0xf39272caff95caab,
            0x44bf5ad3597e99f6,
            0xcc2ba812e2327d54,
            0x6bd5380bf8ed35d8,
            0x8473d71f7750b0ba,
            0xea023aa925dee3a0,
            0xea08e2de3aa450e0,
            0xf49b8ee36da12b44,
            0x2ef5f3f207eba00c,
            0x827abbd7733372f4,
            0xf04714126b1385ab,
            0x37800dcceb8107e2,
        ],
        [
            0xe85ff87c7c8f77a6,
            0xb8268cefb3261610,
            0x14d0bb9f7604547f,
            0x788cf96ecb430dde,
            0x3cbe69615ba2e1d0,
            0x55ae1c01d4262c04,
            0x7429dc16119c28f6,
            0xcda93b327917418b,
            0x2497a9225c187b37,
            0x91ac79167a6f377e,
            0xa5effac16d7668a3,
            0xd78a26ce76d4d811,
        ],
    ],
    [
        [
            0x5e0497fa4c4f1682,
            0x547d0d0b9b99a7e3,
            0xd229d5678cced1de,
            0xc12e48a54ac5022e,
            0xc00d4ab46ef4d7b2,
            0xb4645340a95b0b6a,
            0xbb06f800d2bd2524,
            0x596b284ffd64c009,
            0x885736fcd5b663bf,
            0x7fbe08c4afe0a5cd,
            0x0c2b541d80c5d2aa,
            0x0685f06c8e1189d3,
        ],
        [
            0xbf0934418bc86dc0,
            0x345243ffbec349d4,
            0xa9332c45ff7c7d82,
            0xb8cc956e50dd0450,
            0xbfe62fe64e38ae9c,
            0x8583d2cd534f1b9b,
            0x04520d21cc10efed,
            0x99e81987be9932a3,
            0xf0d3a301a33955e0,
            0x5a5dbcbf1df5522b,
            0x0c13e879a2360261,
            0x094a1123513e9ba3,
        ],
        [
            0x858d9ad9c453649d,
            0xfdce777f1dbb0ff9,
            0x24194bbf7e6ee44f,
            0x15a6a88ce9f441a5,
            0x55a03ae2f62e843c,
            0x515c6e41f49d9b3d,
            0x431ba02861d0f884,
            0xeefd245429d11dd9,
            0x831f1811991a26a4,
            0x2269f8805c3d40c2,
            0x6c8a794a8943b2a9,
            0x2298bd8b15776de9,
        ],
        [
            0x959639a90173c751,
            0x65b6244a78e84c2b,
            0x8a04fc785b1407be,
            0x68e27a5a1cde026f,
            0xa408bb722d770889,
            0x804491c567e5f3d5,
            0xcbc7d07164231f8b,
            0x3441ffec6f80800d,
            0x190b7cc675a4192a,
            0x8944fdce36a23877,
            0xe2a24e1ce229fb4d,
            0xffcb89b9e9a6e223,
        ],
    ],
];

const INTERNAL_ROUND_CONSTANTS: [u64; POSEIDON2_INTERNAL_ROUNDS] = [
    0xc0929f33e2853d1b,
    0xd87c59fd9506f59c,
    0x9b8986da30c5661d,
    0xacb45c9caf8f9bab,
    0x4f64d87fd0164596,
    0x04bddf3342d684d9,
    0xcaa3498150fc3e3b,
    0x5ddd38a00e26563b,
    0x5105844dcef0279d,
    0x63f9e1ff40676ef7,
    0x64bb32f2134ce6ba,
    0xa2a96bba1042ab02,
    0x17f6c4815e81af65,
    0x6b49fe48b8e0cc07,
    0x2e5e3d70d8fe257d,
    0xd4bed28c49c172e9,
    0xcfb25a871027d329,
    0xb62ad38bb2bf0f3b,
    0xdfe40c70f2c288dc,
    0x2fbb65b92fa854d9,
    0xb0fe72a89100504b,
    0xfec87ab0375b5da0,
];

fn sbox7<EF: Field>(builder: &mut CircuitBuilder<EF>, x: Target) -> Target {
    let x2 = builder.mul(x, x);
    let x4 = builder.mul(x2, x2);
    let x6 = builder.mul(x4, x2);
    builder.mul(x6, x)
}

fn apply_mds4<EF: Field>(builder: &mut CircuitBuilder<EF>, values: &mut [Target; 4]) {
    let x0 = values[0];
    let x1 = values[1];
    let x2 = values[2];
    let x3 = values[3];

    let t01 = builder.add(x0, x1);
    let t23 = builder.add(x2, x3);
    let t0123 = builder.add(t01, t23);
    let t01123 = builder.add(t0123, x1);
    let t01233 = builder.add(t0123, x3);

    let two_x0 = builder.add(x0, x0);
    let two_x2 = builder.add(x2, x2);
    values[3] = builder.add(t01233, two_x0);
    values[1] = builder.add(t01123, two_x2);
    values[0] = builder.add(t01123, t01);
    values[2] = builder.add(t01233, t23);
}

fn mds_light<EF: Field>(builder: &mut CircuitBuilder<EF>, state: &mut [Target; POSEIDON2_WIDTH]) {
    for chunk_idx in 0..(POSEIDON2_WIDTH / 4) {
        let base = chunk_idx * 4;
        let mut chunk = [
            state[base],
            state[base + 1],
            state[base + 2],
            state[base + 3],
        ];
        apply_mds4(builder, &mut chunk);
        state[base..base + 4].copy_from_slice(&chunk);
    }

    let zero = builder.add_const(EF::ZERO);
    let mut sums = [zero; 4];
    for (k, sum_slot) in sums.iter_mut().enumerate() {
        let mut acc = zero;
        let mut idx = k;
        while idx < POSEIDON2_WIDTH {
            acc = builder.add(acc, state[idx]);
            idx += 4;
        }
        *sum_slot = acc;
    }

    for idx in 0..POSEIDON2_WIDTH {
        state[idx] = builder.add(state[idx], sums[idx % 4]);
    }
}

fn matmul_internal<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    state: &mut [Target; POSEIDON2_WIDTH],
) {
    let mut sum = builder.add_const(EF::ZERO);
    for &value in state.iter() {
        sum = builder.add(sum, value);
    }
    for (idx, slot) in state.iter_mut().enumerate() {
        let diag = builder.add_const(EF::from_u64(INTERNAL_MATRIX_DIAG[idx]));
        let scaled = builder.mul(*slot, diag);
        *slot = builder.add(scaled, sum);
    }
}

fn external_round<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    state: &mut [Target; POSEIDON2_WIDTH],
    side: usize,
    round: usize,
) {
    for idx in 0..POSEIDON2_WIDTH {
        let rc = builder.add_const(EF::from_u64(EXTERNAL_ROUND_CONSTANTS[side][round][idx]));
        let shifted = builder.add(state[idx], rc);
        state[idx] = sbox7(builder, shifted);
    }
    mds_light(builder, state);
}

fn internal_round<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    state: &mut [Target; POSEIDON2_WIDTH],
    round: usize,
) {
    let rc = builder.add_const(EF::from_u64(INTERNAL_ROUND_CONSTANTS[round]));
    let shifted = builder.add(state[0], rc);
    state[0] = sbox7(builder, shifted);
    matmul_internal(builder, state);
}

fn poseidon2_permute_goldilocks<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    state: &mut [Target; POSEIDON2_WIDTH],
) {
    mds_light(builder, state);
    for round in 0..POSEIDON2_EXTERNAL_ROUNDS {
        external_round(builder, state, 0, round);
    }
    for round in 0..POSEIDON2_INTERNAL_ROUNDS {
        internal_round(builder, state, round);
    }
    for round in 0..POSEIDON2_EXTERNAL_ROUNDS {
        external_round(builder, state, 1, round);
    }
}

fn poseidon2_hash_targets<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    input: &[Target],
) -> [Target; POSEIDON2_RATE] {
    let zero = builder.add_const(EF::ZERO);
    let mut state = [zero; POSEIDON2_WIDTH];
    if input.is_empty() {
        return state[..POSEIDON2_RATE]
            .try_into()
            .expect("fixed digest width");
    }

    let mut cursor = 0usize;
    while cursor < input.len() {
        let take = core::cmp::min(POSEIDON2_RATE, input.len() - cursor);
        for (idx, value) in input[cursor..cursor + take].iter().enumerate() {
            state[idx] = *value;
        }
        poseidon2_permute_goldilocks(builder, &mut state);
        cursor += take;
    }

    state[..POSEIDON2_RATE]
        .try_into()
        .expect("fixed digest width")
}

fn poseidon2_compress_targets<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    left: &[Target; POSEIDON2_RATE],
    right: &[Target; POSEIDON2_RATE],
) -> [Target; POSEIDON2_RATE] {
    let zero = builder.add_const(EF::ZERO);
    let mut state = [zero; POSEIDON2_WIDTH];
    state[..POSEIDON2_RATE].copy_from_slice(left);
    state[POSEIDON2_RATE..POSEIDON2_RATE * 2].copy_from_slice(right);
    poseidon2_permute_goldilocks(builder, &mut state);
    state[..POSEIDON2_RATE]
        .try_into()
        .expect("fixed digest width")
}

fn enforce_base_target<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    target: Target,
) -> Result<(), CircuitBuilderError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    let _ = builder.decompose_to_bits::<F>(target, F::bits())?;
    Ok(())
}

pub(crate) fn flatten_extension_rows_to_base_targets<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    opened_values: &[Vec<Target>],
) -> Result<Vec<Vec<Target>>, CircuitBuilderError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    let bits_per_element = F::bits() * EF::DIMENSION;
    let mut flattened = Vec::with_capacity(opened_values.len());
    for row in opened_values {
        let mut row_flattened = Vec::with_capacity(row.len() * EF::DIMENSION);
        for &value in row {
            let bits = builder.decompose_to_bits::<F>(value, bits_per_element)?;
            for coeff_bits in bits.chunks(F::bits()) {
                let coeff = builder.reconstruct_index_from_bits::<F>(coeff_bits)?;
                row_flattened.push(coeff);
            }
        }
        flattened.push(row_flattened);
    }
    Ok(flattened)
}

fn hash_opening_group<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    group_indices: &[usize],
    opened_values: &[Vec<Target>],
) -> Result<[Target; POSEIDON2_RATE], CircuitBuilderError>
where
    F: PrimeField64,
    EF: ExtensionField<F>,
{
    let mut leaf = Vec::new();
    for &idx in group_indices {
        for &value in &opened_values[idx] {
            enforce_base_target::<F, EF>(builder, value)?;
            leaf.push(value);
        }
    }
    Ok(poseidon2_hash_targets(builder, &leaf))
}

pub(crate) fn verify_merkle_batch_circuit<F, EF, const DIGEST_ELEMS: usize>(
    builder: &mut CircuitBuilder<EF>,
    commitment_observation: &[Target],
    dimensions: &[Dimensions],
    index_bits: &[Target],
    opened_values: &[Vec<Target>],
    opening_proof: &[[Target; DIGEST_ELEMS]],
) -> Result<(), CircuitBuilderError>
where
    F: PrimeField64 + TwoAdicField,
    EF: ExtensionField<F>,
{
    if F::ORDER_U64 != GOLDILOCKS_ORDER_U64 || DIGEST_ELEMS != POSEIDON2_RATE {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "verify_merkle_batch_circuit",
            expected: "goldilocks digest_elems=6".to_string(),
            got: DIGEST_ELEMS,
        });
    }

    if dimensions.len() != opened_values.len() {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "verify_merkle_batch_circuit",
            expected: dimensions.len().to_string(),
            got: opened_values.len(),
        });
    }

    if commitment_observation.len() != POSEIDON2_RATE {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "verify_merkle_batch_circuit",
            expected: POSEIDON2_RATE.to_string(),
            got: commitment_observation.len(),
        });
    }

    let mut heights_tallest_first: Vec<usize> = (0..dimensions.len()).collect();
    heights_tallest_first.sort_by_key(|&idx| core::cmp::Reverse(dimensions[idx].height));

    if heights_tallest_first.is_empty() {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "verify_merkle_batch_circuit",
            expected: "non-empty dimensions".to_string(),
            got: 0,
        });
    }

    for pair in heights_tallest_first.windows(2) {
        let curr = dimensions[pair[0]].height;
        let next = dimensions[pair[1]].height;
        if curr != next && curr.next_power_of_two() == next.next_power_of_two() {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "verify_merkle_batch_circuit",
                expected: "compatible matrix heights".to_string(),
                got: next,
            });
        }
    }

    let mut curr_height_padded = dimensions[heights_tallest_first[0]].height.next_power_of_two();
    let log_max_height = curr_height_padded.ilog2() as usize;

    if opening_proof.len() != log_max_height {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "verify_merkle_batch_circuit",
            expected: log_max_height.to_string(),
            got: opening_proof.len(),
        });
    }
    if index_bits.len() < log_max_height {
        return Err(CircuitBuilderError::NonPrimitiveOpArity {
            op: "verify_merkle_batch_circuit",
            expected: log_max_height.to_string(),
            got: index_bits.len(),
        });
    }

    for &bit in index_bits.iter().take(log_max_height) {
        builder.assert_bool(bit);
    }

    let mut cursor = 0usize;
    let mut first_group = Vec::new();
    while cursor < heights_tallest_first.len() {
        let idx = heights_tallest_first[cursor];
        if dimensions[idx].height.next_power_of_two() == curr_height_padded {
            first_group.push(idx);
            cursor += 1;
        } else {
            break;
        }
    }

    let mut root = hash_opening_group::<F, EF>(builder, &first_group, opened_values)?;
    for &entry in &root {
        enforce_base_target::<F, EF>(builder, entry)?;
    }

    for (level, sibling) in opening_proof.iter().enumerate() {
        let bit = index_bits[level];
        let mut sibling_digest = [builder.add_const(EF::ZERO); POSEIDON2_RATE];
        for i in 0..POSEIDON2_RATE {
            enforce_base_target::<F, EF>(builder, sibling[i])?;
            sibling_digest[i] = sibling[i];
        }

        let mut left = [builder.add_const(EF::ZERO); POSEIDON2_RATE];
        let mut right = [builder.add_const(EF::ZERO); POSEIDON2_RATE];
        for i in 0..POSEIDON2_RATE {
            left[i] = builder.select(bit, sibling_digest[i], root[i]);
            right[i] = builder.select(bit, root[i], sibling_digest[i]);
        }
        root = poseidon2_compress_targets(builder, &left, &right);
        for &entry in &root {
            enforce_base_target::<F, EF>(builder, entry)?;
        }

        curr_height_padded >>= 1;
        if cursor < heights_tallest_first.len() {
            let next_idx = heights_tallest_first[cursor];
            let next_height = dimensions[next_idx].height;
            if next_height.next_power_of_two() == curr_height_padded {
                let mut next_group = Vec::new();
                while cursor < heights_tallest_first.len() {
                    let idx = heights_tallest_first[cursor];
                    if dimensions[idx].height == next_height {
                        next_group.push(idx);
                        cursor += 1;
                    } else {
                        break;
                    }
                }
                let next_digest = hash_opening_group::<F, EF>(builder, &next_group, opened_values)?;
                root = poseidon2_compress_targets(builder, &root, &next_digest);
                for &entry in &root {
                    enforce_base_target::<F, EF>(builder, entry)?;
                }
            }
        }
    }

    for (computed, &expected) in root.iter().zip(commitment_observation.iter()) {
        enforce_base_target::<F, EF>(builder, expected)?;
        builder.connect(*computed, expected);
    }
    Ok(())
}

/// Perform the arity-2 FRI fold chain with optional roll-ins.
/// Starts from the initial reduced opening at max height; returns the final folded value.
/// All arithmetic is over the circuit field `EF`.
///
/// Interpolation per phase:
///   folded ← e0 + (β − x0)·(e1 − e0)·(x1 − x0)^{-1}, with x1 = −x0
///           = e0 + (β − x0)·(e1 − e0)·(−1/2)·x0^{-1}
fn fold_row_chain<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    initial_folded_eval: Target,
    phases: &[FoldPhaseInputsTarget],
) -> Target {
    builder.push_scope("fold_row_chain");

    let mut folded = initial_folded_eval;

    let one = builder.alloc_const(EF::ONE, "1");

    // Precompute constants as field constants: 2^{-1} and −1/2.
    let two_inv_val = EF::ONE.halve(); // 1/2
    let neg_half = builder.alloc_const(EF::NEG_ONE * two_inv_val, "−1/2"); // −1/2

    for FoldPhaseInputsTarget {
        beta,
        x0,
        e_sibling,
        sibling_is_right,
        roll_in,
    } in phases.iter().cloned()
    {
        // Commit-phase MMCS openings are verified in `verify_fri_circuit`.

        // e0 = select(bit, folded, e_sibling)
        let e0 = builder.select(sibling_is_right, folded, e_sibling);

        // inv = (x1 − x0)^{-1} = (−2x0)^{-1} = (−1/2) / x0
        let inv = builder.alloc_div(neg_half, x0, "inv");

        // e1 − e0 = (2b − 1) · (e_sibling − folded)
        let d = builder.alloc_sub(e_sibling, folded, "d");
        let two_b = builder.alloc_add(sibling_is_right, sibling_is_right, "two_b");
        let two_b_minus_one = builder.alloc_sub(two_b, one, "two_b_minus_one");
        let e1_minus_e0 = builder.alloc_mul(two_b_minus_one, d, "e1_minus_e0");

        // t = (β − x0) * (e1 − e0)
        let beta_minus_x0 = builder.alloc_sub(beta, x0, "beta_minus_x0");
        let t = builder.alloc_mul(beta_minus_x0, e1_minus_e0, "t");

        // folded = e0 + t * inv
        let t_inv = builder.alloc_mul(t, inv, "t_inv");
        folded = builder.alloc_add(e0, t_inv, "folded 1");

        // Optional roll-in: folded += β² · roll_in
        if let Some(ro) = roll_in {
            let beta_sq = builder.alloc_mul(beta, beta, "beta_sq");
            let add_term = builder.alloc_mul(beta_sq, ro, "add_term");
            folded = builder.alloc_add(folded, add_term, "folded 2");
        }
    }

    builder.pop_scope(); // close `fold_row_chain` scope
    folded
}

/// Evaluate a polynomial at a point `x` using Horner's method.
/// Given coefficients [c0, c1, c2, ...], compute `p(x) = c0 + x*(c1 + x*(c2 + ...))`.
fn evaluate_polynomial<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    coefficients: &[Target],
    point: Target,
) -> Target {
    builder.push_scope("evaluate_polynomial");

    assert!(
        !coefficients.is_empty(),
        "we should have at least a constant polynomial"
    );
    if coefficients.len() == 1 {
        return coefficients[0];
    }

    let mut result = coefficients[coefficients.len() - 1];
    for &coeff in coefficients.iter().rev().skip(1) {
        result = builder.mul(result, point);
        result = builder.add(result, coeff);
    }

    builder.pop_scope(); // close `evaluate_polynomial` scope
    result
}

/// Arithmetic-only version of Plonky3 `verify_query`:
/// - Applies the fold chain and enforces equality to the provided final polynomial evaluation.
/// - Caller must supply `initial_folded_eval` (the reduced opening at max height).
fn verify_query<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    initial_folded_eval: Target,
    phases: &[FoldPhaseInputsTarget],
    final_value: Target,
) {
    builder.push_scope("verify_query");
    let folded_eval = fold_row_chain(builder, initial_folded_eval, phases);
    builder.connect(folded_eval, final_value);
    builder.pop_scope(); // close `verify_query` scope
}

#[cfg(test)]
mod tests {
    use hashbrown::HashMap;
    use p3_circuit::{CircuitError, Op, WitnessId};
    use p3_challenger::DuplexChallenger;
    use p3_batch_stark::CommonData;
    use p3_circuit_prover::TablePacking;
    use p3_circuit_prover::air::PublicAir;
    use p3_circuit_prover::common::CircuitTableAir;
    use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
    use p3_circuit_prover::BatchStarkProver;
    use p3_dft::Radix2DitParallel;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;
    use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
    use p3_lookup::logup::LogUpGadget;
    use p3_poseidon2::ExternalLayerConstants;
    use p3_symmetric::{
        CryptographicHasher, PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation,
    };
    use p3_commit::{ExtensionMmcs, Mmcs};
    use p3_uni_stark::StarkConfig;

    use super::*;
    use crate::BatchStarkVerifierInputsBuilder;
    use crate::generation::generate_batch_challenges;
    use crate::FriVerifierParams;
    use crate::pcs::{
        FriProofTargets, HashTargets, InputProofTargets, RecExtensionValMmcs, RecValMmcs,
        Witness,
    };
    use crate::verifier::verify_batch_circuit;

    type Challenge = BinomialExtensionField<Goldilocks, 2>;
    type Perm = Poseidon2Goldilocks<POSEIDON2_WIDTH>;
    type Hash = PaddingFreeSponge<Perm, POSEIDON2_WIDTH, POSEIDON2_RATE, POSEIDON2_RATE>;
    type Compress = TruncatedPermutation<Perm, 2, POSEIDON2_RATE, POSEIDON2_WIDTH>;
    type ValMmcs = p3_merkle_tree::MerkleTreeMmcs<
        <Goldilocks as p3_field::Field>::Packing,
        <Goldilocks as p3_field::Field>::Packing,
        Hash,
        Compress,
        POSEIDON2_RATE,
    >;
    type ChallengeMmcs = ExtensionMmcs<Goldilocks, Challenge, ValMmcs>;
    type Dft = Radix2DitParallel<Goldilocks>;
    type Challenger = DuplexChallenger<Goldilocks, Perm, POSEIDON2_WIDTH, POSEIDON2_RATE>;
    type Pcs = TwoAdicFriPcs<Goldilocks, Dft, ValMmcs, ChallengeMmcs>;
    type Config = StarkConfig<Pcs, Challenge, Challenger>;
    type InnerFri = FriProofTargets<
        Goldilocks,
        Challenge,
        RecExtensionValMmcs<
            Goldilocks,
            Challenge,
            POSEIDON2_RATE,
            RecValMmcs<Goldilocks, POSEIDON2_RATE, Hash, Compress>,
        >,
        InputProofTargets<
            Goldilocks,
            Challenge,
            RecValMmcs<Goldilocks, POSEIDON2_RATE, Hash, Compress>,
        >,
        Witness<Goldilocks>,
    >;

    fn native_perm() -> Perm {
        let external_constants =
            ExternalLayerConstants::<Goldilocks, POSEIDON2_WIDTH>::new_from_saved_array(
                EXTERNAL_ROUND_CONSTANTS,
                Goldilocks::new_array,
            );
        let internal_constants = Goldilocks::new_array(INTERNAL_ROUND_CONSTANTS).to_vec();
        Perm::new(external_constants, internal_constants)
    }

    #[test]
    fn poseidon2_hash_targets_matches_native_goldilocks12() {
        let native_hash = Hash::new(native_perm());
        let inputs = [
            Goldilocks::from_u64(3),
            Goldilocks::from_u64(5),
            Goldilocks::from_u64(8),
            Goldilocks::from_u64(13),
            Goldilocks::from_u64(21),
            Goldilocks::from_u64(34),
            Goldilocks::from_u64(55),
        ];
        let expected = native_hash.hash_iter(inputs);

        let mut builder = CircuitBuilder::<Challenge>::new();
        let targets = inputs
            .iter()
            .enumerate()
            .map(|(idx, value)| {
                let target = builder.add_const(Challenge::from(*value));
                builder.tag(target, format!("input-{idx}")).unwrap();
                target
            })
            .collect::<Vec<_>>();
        let digest = poseidon2_hash_targets(&mut builder, &targets);
        for (idx, target) in digest.into_iter().enumerate() {
            builder.tag(target, format!("digest-{idx}")).unwrap();
        }

        let circuit = builder.build().unwrap();
        let traces = circuit.runner().run().unwrap();
        for (idx, expected_limb) in expected.into_iter().enumerate() {
            let observed = traces
                .probe(&format!("digest-{idx}"))
                .copied()
                .expect("digest tag should exist");
            assert_eq!(observed, Challenge::from(expected_limb));
        }
    }

    #[test]
    fn poseidon2_compress_targets_matches_native_goldilocks12() {
        let native_compress = Compress::new(native_perm());
        let left = Goldilocks::new_array([2, 4, 6, 8, 10, 12]);
        let right = Goldilocks::new_array([1, 3, 5, 7, 9, 11]);
        let expected = native_compress.compress([left, right]);

        let mut builder = CircuitBuilder::<Challenge>::new();
        let left_targets = left
            .iter()
            .copied()
            .map(|value| builder.add_const(Challenge::from(value)))
            .collect::<Vec<_>>();
        let right_targets = right
            .iter()
            .copied()
            .map(|value| builder.add_const(Challenge::from(value)))
            .collect::<Vec<_>>();
        let digest = poseidon2_compress_targets(
            &mut builder,
            &left_targets.try_into().unwrap(),
            &right_targets.try_into().unwrap(),
        );
        for (idx, target) in digest.into_iter().enumerate() {
            builder.tag(target, format!("compress-{idx}")).unwrap();
        }

        let circuit = builder.build().unwrap();
        let traces = circuit.runner().run().unwrap();
        for (idx, expected_limb) in expected.into_iter().enumerate() {
            let observed = traces
                .probe(&format!("compress-{idx}"))
                .copied()
                .expect("compress tag should exist");
            assert_eq!(observed, Challenge::from(expected_limb));
        }
    }

    #[test]
    fn rec_extension_val_mmcs_matches_native_goldilocks12() {
        let native_mmcs = ChallengeMmcs::new(ValMmcs::new(
            Hash::new(native_perm()),
            Compress::new(native_perm()),
        ));

        let mat_a = RowMajorMatrix::new(
            vec![
                Challenge::from_basis_coefficients_slice(&[Goldilocks::from_u64(1), Goldilocks::from_u64(2)]).unwrap(),
                Challenge::from_basis_coefficients_slice(&[Goldilocks::from_u64(3), Goldilocks::from_u64(4)]).unwrap(),
                Challenge::from_basis_coefficients_slice(&[Goldilocks::from_u64(5), Goldilocks::from_u64(6)]).unwrap(),
                Challenge::from_basis_coefficients_slice(&[Goldilocks::from_u64(7), Goldilocks::from_u64(8)]).unwrap(),
            ],
            1,
        );
        let mat_b = RowMajorMatrix::new(
            vec![
                Challenge::from_basis_coefficients_slice(&[Goldilocks::from_u64(9), Goldilocks::from_u64(10)]).unwrap(),
                Challenge::from_basis_coefficients_slice(&[Goldilocks::from_u64(11), Goldilocks::from_u64(12)]).unwrap(),
            ],
            1,
        );

        let dimensions = vec![
            p3_matrix::Dimensions {
                width: mat_a.width(),
                height: mat_a.height(),
            },
            p3_matrix::Dimensions {
                width: mat_b.width(),
                height: mat_b.height(),
            },
        ];

        let (commitment, prover_data) = native_mmcs.commit(vec![mat_a, mat_b]);
        let index = 1usize;
        let opening = native_mmcs.open_batch(index, &prover_data);
        native_mmcs
            .verify_batch(&commitment, &dimensions, index, (&opening).into())
            .unwrap();

        let mut builder = CircuitBuilder::<Challenge>::new();
        let commitment_targets = commitment
            .as_ref()
            .iter()
            .copied()
            .map(|value| builder.add_const(Challenge::from(value)))
            .collect::<Vec<_>>();
        let index_bits = (0..2)
            .map(|bit| {
                let value = if (index >> bit) & 1 == 1 {
                    Challenge::ONE
                } else {
                    Challenge::ZERO
                };
                builder.add_const(value)
            })
            .collect::<Vec<_>>();
        let opened_targets = opening
            .opened_values
            .iter()
            .map(|row| {
                row.iter()
                    .copied()
                    .map(|value| builder.add_const(value))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let proof_targets = opening
            .opening_proof
            .iter()
            .map(|digest| {
                digest
                    .iter()
                    .copied()
                    .map(|value| builder.add_const(Challenge::from(value)))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<[Target; POSEIDON2_RATE]>>();

        let flattened_dimensions = dimensions
            .iter()
            .map(|dim| p3_matrix::Dimensions {
                width: dim.width * <Challenge as BasedVectorSpace<Goldilocks>>::DIMENSION,
                height: dim.height,
            })
            .collect::<Vec<_>>();
        let flattened_openings =
            flatten_extension_rows_to_base_targets::<Goldilocks, Challenge>(&mut builder, &opened_targets)
                .unwrap();
        verify_merkle_batch_circuit::<Goldilocks, Challenge, POSEIDON2_RATE>(
            &mut builder,
            &commitment_targets,
            &flattened_dimensions,
            &index_bits,
            &flattened_openings,
            &proof_targets,
        )
        .unwrap();

        let circuit = builder.build().unwrap();
        let _traces = circuit.runner().run().unwrap();
    }

    #[test]
    fn recursive_batch_verifier_accepts_simple_goldilocks_d2_circuit_table_proof() {
        let mut builder = CircuitBuilder::<Challenge>::new();
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let z = builder.add_public_input();
        let expected = builder.add_public_input();

        let xy = builder.mul(x, y);
        let res = builder.add(xy, z);
        let diff = builder.sub(res, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let (airs_degrees, witness_multiplicities) =
            get_airs_and_degrees_with_prep::<Config, _, 2>(&circuit, TablePacking::default(), None)
                .unwrap();
        let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

        let x_val = Challenge::from_basis_coefficients_slice(&[
            Goldilocks::from_u64(3),
            Goldilocks::NEG_ONE,
        ])
        .unwrap();
        let y_val = Challenge::from_basis_coefficients_slice(&[
            Goldilocks::from_u64(7),
            Goldilocks::from_u64(11),
        ])
        .unwrap();
        let z_val = Challenge::from_basis_coefficients_slice(&[
            Goldilocks::from_u64(13),
            Goldilocks::from_u64(17),
        ])
        .unwrap();
        let expected_val = x_val * y_val + z_val;

        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[x_val, y_val, z_val, expected_val])
            .unwrap();
        let traces = runner.run().unwrap();

        let perm = native_perm();
        let val_mmcs = ValMmcs::new(Hash::new(perm.clone()), Compress::new(perm.clone()));
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri_params = create_test_fri_params(challenge_mmcs, 0);
        let query_pow_bits = fri_params.query_proof_of_work_bits;
        let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
        let perm_for_config = native_perm();
        let val_mmcs_for_config =
            ValMmcs::new(Hash::new(perm_for_config.clone()), Compress::new(perm_for_config.clone()));
        let challenge_mmcs_for_config = ChallengeMmcs::new(val_mmcs_for_config.clone());
        let fri_params_for_config = create_test_fri_params(challenge_mmcs_for_config, 0);
        let pcs = Pcs::new(Dft::default(), val_mmcs_for_config, fri_params_for_config);
        let config = Config::new(pcs, Challenger::new(perm_for_config));
        let fri_verifier_params = FriVerifierParams::from(&fri_params);

        let common = CommonData::from_airs_and_degrees(&config, &mut airs, &degrees);
        let perm_for_prover = native_perm();
        let val_mmcs_for_prover =
            ValMmcs::new(Hash::new(perm_for_prover.clone()), Compress::new(perm_for_prover.clone()));
        let challenge_mmcs_for_prover = ChallengeMmcs::new(val_mmcs_for_prover.clone());
        let fri_params_for_prover = create_test_fri_params(challenge_mmcs_for_prover, 0);
        let prover_config = Config::new(
            Pcs::new(Dft::default(), val_mmcs_for_prover, fri_params_for_prover),
            Challenger::new(perm_for_prover),
        );
        let prover = BatchStarkProver::new(prover_config);
        let proof = prover
            .prove_all_tables(&traces, &common, witness_multiplicities)
            .unwrap();
        let public_values =
            PublicAir::<Goldilocks, 2>::trace_to_public_values(&traces.public_trace);
        prover
            .verify_all_tables_with_public_values(&proof, &common, Some(public_values.clone()))
            .unwrap();

        let mut public_values_by_air = vec![Vec::new(); airs.len()];
        for (idx, air) in airs.iter().enumerate() {
            if matches!(air, CircuitTableAir::Public(_)) {
                public_values_by_air[idx] = public_values.clone();
            }
        }
        let air_public_counts = public_values_by_air
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>();

        let mut recursive_builder = CircuitBuilder::<Challenge>::new();
        let verifier_inputs = BatchStarkVerifierInputsBuilder::<
            Config,
            HashTargets<Goldilocks, POSEIDON2_RATE>,
            InnerFri,
        >::allocate(
            &mut recursive_builder,
            &proof.proof,
            &common,
            &air_public_counts,
        );
        verify_batch_circuit::<
            CircuitTableAir<Config, 2>,
            Config,
            HashTargets<Goldilocks, POSEIDON2_RATE>,
            InputProofTargets<Goldilocks, Challenge, RecValMmcs<Goldilocks, POSEIDON2_RATE, Hash, Compress>>,
            InnerFri,
            LogUpGadget,
            POSEIDON2_RATE,
        >(
            &config,
            &airs,
            &mut recursive_builder,
            &verifier_inputs.proof_targets,
            &verifier_inputs.air_public_targets,
            &fri_verifier_params,
            &verifier_inputs.common_data,
            &LogUpGadget::new(),
        )
        .unwrap();

        let recursive_circuit = recursive_builder.build().unwrap();
        let challenges = generate_batch_challenges(
            &airs,
            &config,
            &proof.proof,
            &public_values_by_air,
            Some(&[query_pow_bits, log_height_max]),
            &common,
            &LogUpGadget::new(),
        )
        .unwrap();
        let public_inputs = verifier_inputs.pack_values(
            &public_values_by_air,
            &proof.proof,
            &common,
            &challenges,
        );

        let mut recursive_runner = recursive_circuit.runner();
        recursive_runner.set_public_inputs(&public_inputs).unwrap();
        let (private_targets, private_values) =
            verifier_inputs.private_witness_inputs(&proof.proof, &common);
        let mut private_positions = HashMap::<WitnessId, Vec<usize>>::new();
        for (position, (target, value)) in private_targets
            .into_iter()
            .zip(private_values.into_iter())
            .enumerate()
        {
            let witness = recursive_circuit.expr_to_widx[&target];
            private_positions.entry(witness).or_default().push(position);
            recursive_runner.set_witness_value(witness, value).unwrap();
        }

        match recursive_runner.run() {
            Ok(_traces) => {}
            Err(CircuitError::PrimitiveExecutionFailed {
                operation_index,
                op,
                message,
            }) => {
                let op_ref = &recursive_circuit.ops[operation_index];
                let detail = match op_ref {
                    Op::Add { a, b, out } => format!(
                        "a={a:?} a_positions={:?} b={b:?} b_positions={:?} out={out:?} out_positions={:?}",
                        private_positions.get(a),
                        private_positions.get(b),
                        private_positions.get(out),
                    ),
                    Op::Mul { a, b, out } => format!(
                        "a={a:?} a_positions={:?} b={b:?} b_positions={:?} out={out:?} out_positions={:?}",
                        private_positions.get(a),
                        private_positions.get(b),
                        private_positions.get(out),
                    ),
                    _ => format!("{op_ref:?}"),
                };
                panic!("recursive batch verifier failed: op={op}; message={message}; detail={detail}");
            }
            Err(err) => panic!("recursive batch verifier failed: {err:?}"),
        }
    }
}

/// Compute the final query point after all FRI folding rounds.
/// This is the point at which the final polynomial should be evaluated.
fn compute_final_query_point<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    index_bits: &[Target],
    log_max_height: usize,
    num_phases: usize,
) -> Target
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    builder.push_scope("compute_final_query_point");

    // Extract the bits that form domain_index (bits [num_phases..log_max_height]) after `num_phases` folds
    let domain_index_bits: Vec<Target> = index_bits[num_phases..log_max_height].to_vec();

    // Pad bits and reverse
    let mut reversed_bits = vec![builder.add_const(EF::ZERO); num_phases];
    reversed_bits.extend(domain_index_bits.iter().rev().copied());

    // Compute g^{reversed_index}
    let g = F::two_adic_generator(log_max_height);
    let powers_of_g: Vec<_> = iter::successors(Some(g), |&prev| Some(prev.square()))
        .take(log_max_height)
        .map(|p| builder.add_const(EF::from(p)))
        .collect();

    let one = builder.add_const(EF::ONE);
    let mut result = one;
    for (&bit, &power) in reversed_bits.iter().zip(&powers_of_g) {
        let multiplier = builder.select(bit, power, one);
        result = builder.mul(result, multiplier);
    }

    builder.pop_scope(); // close `compute_final_query_point` scope
    result
}

/// Compute x₀ for phase `i` from the query index bits and a caller-provided power ladder.
///
/// For phase with folded height `k` (log_folded_height), caller must pass:
///   `pows = [g^{2^0}, g^{2^1}, ..., g^{2^{k-1}}]`
/// where `g = two_adic_generator(k + 1)` (note the +1 for arity-2).
///
/// We use bit window `bits[i+1 .. i+1+k]` (little-endian), but multiplied in reverse to match
/// `reverse_bits_len(index >> (i+1), k)` semantics from the verifier.
fn compute_x0_from_index_bits<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    index_bits: &[Target],
    phase: usize,
    pows: &[EF],
) -> Target {
    builder.push_scope("compute_x0_from_index_bits");

    let one = builder.add_const(EF::ONE);
    let mut res = one;

    // Bits window: offset = i+1, length = pows.len() = k
    let offset = phase + 1;
    let k = pows.len();

    for j in 0..k {
        let bit = index_bits[offset + k - 1 - j]; // reversed
        let pow_const = builder.add_const(pows[j]);
        let diff = builder.sub(pow_const, one);
        let diff_bit = builder.mul(diff, bit);
        let gate = builder.add(one, diff_bit);
        res = builder.mul(res, gate);
    }

    builder.pop_scope(); // close `compute_x0_from_index_bits` scope
    res
}

/// Build and verify the fold chain from index bits:
/// - `index_bits`: little-endian query index bits (must be boolean-constrained by caller).
/// - `betas`/`sibling_values`/`roll_ins`: per-phase arrays.
/// - `pows_per_phase[i]`: power ladder for the generator at that phase (see `compute_x0_from_index_bits`).
#[allow(clippy::too_many_arguments)]
fn verify_query_from_index_bits<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    initial_folded_eval: Target,
    index_bits: &[Target],
    betas: &[Target],
    sibling_values: &[Target],
    roll_ins: &[Option<Target>],
    pows_per_phase: &[Vec<EF>],
    final_value: Target,
) {
    builder.push_scope("verify_query_from_index_bits");

    let num_phases = betas.len();
    debug_assert_eq!(
        sibling_values.len(),
        num_phases,
        "sibling_values len mismatch"
    );
    debug_assert_eq!(roll_ins.len(), num_phases, "roll_ins len mismatch");
    debug_assert_eq!(
        pows_per_phase.len(),
        num_phases,
        "pows_per_phase len mismatch"
    );

    let one = builder.add_const(EF::ONE);

    let mut phases_vec = Vec::with_capacity(num_phases);
    for i in 0..num_phases {
        // x0 from bits (using the appropriate generator ladder for this phase)
        let x0 = compute_x0_from_index_bits(builder, index_bits, i, &pows_per_phase[i]);

        // sibling_is_right = 1 − (index_bit[i])
        let raw_bit = index_bits[i];
        let sibling_is_right = builder.sub(one, raw_bit);

        phases_vec.push(FoldPhaseInputsTarget {
            beta: betas[i],
            x0,
            e_sibling: sibling_values[i],
            sibling_is_right,
            roll_in: roll_ins[i],
        });
    }

    verify_query(builder, initial_folded_eval, &phases_vec, final_value);
    builder.pop_scope(); // close `verify_query_from_index_bits` scope
}

/// Compute evaluation point x from domain height and reversed reduced index bits in the circuit field EF.
/// x = GENERATOR * two_adic_generator(log_height)^{rev_reduced_index}
fn compute_evaluation_point<F, EF>(
    builder: &mut CircuitBuilder<EF>,
    log_height: usize,
    rev_reduced_index_bits: &[Target],
) -> Target
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    builder.push_scope("compute_evaluation_point");

    // Build power-of-two ladder for two-adic generator g: [g, g^2, g^4, ...]
    let g = F::two_adic_generator(log_height);
    let powers_of_g: Vec<_> = iter::successors(Some(g), |&prev| Some(prev.square()))
        .take(rev_reduced_index_bits.len())
        .map(|p| builder.add_const(EF::from(p)))
        .collect();

    // Compute g^{rev_reduced_index} using the provided reversed bits
    let one = builder.add_const(EF::ONE);
    let mut g_pow_index = one;
    for (&bit, &power) in rev_reduced_index_bits.iter().zip(&powers_of_g) {
        let multiplier = builder.select(bit, power, one);
        g_pow_index = builder.mul(g_pow_index, multiplier);
    }

    // Multiply by the coset generator (also lifted to EF) to get x
    let generator = builder.alloc_const(EF::from(F::GENERATOR), "coset_generator");
    let eval_point = builder.alloc_mul(generator, g_pow_index, "eval_point");

    builder.pop_scope(); // close `compute_evaluation_point` scope
    eval_point
}

/// Compute reduced opening for a single matrix in circuit form (EF-field).
/// ro += alpha_pow * (p_at_z - p_at_x) * (z - x)^{-1}; and alpha_pow *= alpha (per column)
fn compute_single_reduced_opening<EF: Field>(
    builder: &mut CircuitBuilder<EF>,
    opened_values: &[Target], // Values at evaluation point x
    point_values: &[Target],  // Values at challenge point z
    evaluation_point: Target, // x
    challenge_point: Target,  // z
    alpha_pow: Target,        // Current alpha power (for this height)
    alpha: Target,            // Alpha challenge
) -> (Target, Target) // (new_alpha_pow, reduced_opening_contrib)
{
    builder.push_scope("compute_single_reduced_opening");

    let mut reduced_opening = builder.add_const(EF::ZERO);
    let mut current_alpha_pow = alpha_pow;

    // quotient = (z - x)^{-1}
    let z_minus_x = builder.sub(challenge_point, evaluation_point);
    let one = builder.add_const(EF::ONE);
    let quotient = builder.div(one, z_minus_x);

    for (&p_at_x, &p_at_z) in opened_values.iter().zip(point_values.iter()) {
        // diff = p_at_z - p_at_x
        let diff = builder.sub(p_at_z, p_at_x);

        // term = alpha_pow * diff * quotient
        let alpha_diff = builder.mul(current_alpha_pow, diff);
        let term = builder.mul(alpha_diff, quotient);

        reduced_opening = builder.add(reduced_opening, term);

        // advance alpha power for the *next column in this height*
        current_alpha_pow = builder.mul(current_alpha_pow, alpha);
    }

    builder.pop_scope(); // close `compute_single_reduced_opening` scope
    (current_alpha_pow, reduced_opening)
}

/// Compute reduced openings grouped **by height** with **per-height alpha powers**,
/// Returns a vector of (log_height, ro) sorted by descending height.
///
/// Reference (Plonky3): `p3_fri::verifier::open_input`
#[allow(clippy::too_many_arguments)]
fn open_input<F, EF, Comm, Inner>(
    builder: &mut CircuitBuilder<EF>,
    log_global_max_height: usize,
    index_bits: &[Target],
    alpha: Target,
    log_blowup: usize,
    commitments_with_opening_points: &ComsWithOpeningsTargets<Comm, TwoAdicMultiplicativeCoset<F>>,
    batch_openings: &[BatchOpeningTargets<F, EF, Inner>], // Per batch -> per matrix -> per column
) -> Result<Vec<(usize, Target)>, VerificationError>
where
    F: PrimeField64 + TwoAdicField,
    EF: ExtensionField<F>,
    Comm: ObservableCommitment,
    Inner: RecursiveMmcs<F, EF>,
{
    builder.push_scope("open_input");

    // TODO(challenger): Indices should be sampled from a RecursiveChallenger, not passed in.
    for &b in index_bits {
        builder.assert_bool(b);
    }
    debug_assert_eq!(
        index_bits.len(),
        log_global_max_height,
        "index_bits.len() must equal log_global_max_height"
    );

    // height -> (alpha_pow_for_this_height, ro_sum_for_this_height)
    let mut reduced_openings = BTreeMap::<usize, (Target, Target)>::new();

    // Process each batch
    for (batch_idx, ((batch_commit, mats), batch_opening)) in zip_eq(
        commitments_with_opening_points.iter(),
        batch_openings.iter(),
        VerificationError::InvalidProofShape(
            "Opened values and commitments count must match".to_string(),
        ),
    )?
    .enumerate()
    {
        if mats.len() != batch_opening.opened_values.len() {
            return Err(VerificationError::InvalidProofShape(format!(
                "batch {batch_idx}: opened_values and matrix count must match"
            )));
        }

        let batch_heights = mats
            .iter()
            .map(|(domain, _)| 1usize << (domain.log_size() + log_blowup))
            .collect::<Vec<_>>();
        let batch_dims = batch_heights
            .iter()
            .zip(batch_opening.opened_values.iter())
            .map(|(height, opened_row)| Dimensions {
                width: opened_row.len(),
                height: *height,
            })
            .collect::<Vec<_>>();

        let reduced_index_bits = if let Some(max_height) = batch_heights.iter().copied().max() {
            let log_batch_max_height = max_height.ilog2() as usize;
            let bits_reduced = log_global_max_height.checked_sub(log_batch_max_height).ok_or_else(|| {
                VerificationError::InvalidProofShape(format!(
                    "batch {batch_idx}: max height exceeds global max height"
                ))
            })?;
            index_bits[bits_reduced..bits_reduced + log_batch_max_height].to_vec()
        } else {
            Vec::new()
        };

        Inner::verify_batch_circuit(
            builder,
            &batch_commit.to_observation_targets(),
            &batch_dims,
            &reduced_index_bits,
            &batch_opening.opened_values,
            &batch_opening.opening_proof,
        )?;

        // For each matrix in the batch
        for (mat_idx, ((mat_domain, mat_points_and_values), mat_opening)) in zip_eq(
            mats.iter(),
            batch_opening.opened_values.iter(),
            VerificationError::InvalidProofShape(format!(
                "batch {batch_idx}: opened_values and point_values count must match"
            )),
        )?
        .enumerate()
        {
            let log_height = mat_domain.log_size() + log_blowup;

            let bits_reduced = log_global_max_height - log_height;
            let rev_bits: Vec<Target> = index_bits[bits_reduced..bits_reduced + log_height]
                .iter()
                .rev()
                .copied()
                .collect();

            // Compute evaluation point x
            let x = compute_evaluation_point::<F, EF>(builder, log_height, &rev_bits);

            // Initialize / fetch per-height (alpha_pow, ro)
            let (alpha_pow_h, ro_h) = reduced_openings
                .entry(log_height)
                .or_insert_with(|| (builder.add_const(EF::ONE), builder.add_const(EF::ZERO)));

            // Process each (z, ps_at_z) pair for this matrix
            for (z, ps_at_z) in mat_points_and_values {
                if mat_opening.len() != ps_at_z.len() {
                    return Err(VerificationError::InvalidProofShape(format!(
                        "batch {batch_idx} mat {mat_idx}: opened_values columns must match point_values columns"
                    )));
                }

                let (new_alpha_pow_h, ro_contrib) = compute_single_reduced_opening(
                    builder,
                    mat_opening,
                    ps_at_z,
                    x,
                    *z,
                    *alpha_pow_h,
                    alpha,
                );

                *ro_h = builder.add(*ro_h, ro_contrib);
                *alpha_pow_h = new_alpha_pow_h;
            }
        }

        // `reduced_openings` would have a log_height = log_blowup entry only if there was a
        // trace matrix of height 1. In this case `f` is constant, so `(f(zeta) - f(x))/(zeta - x)`
        // must equal `0`.
        if let Some((_ap, ro0)) = reduced_openings.get(&log_blowup) {
            let zero = builder.add_const(EF::ZERO);
            builder.connect(*ro0, zero);
        }
    }

    builder.pop_scope(); // close `open_input` scope

    // Into descending (height, ro) list
    Ok(reduced_openings
        .into_iter()
        .rev()
        .map(|(h, (_ap, ro))| (h, ro))
        .collect())
}

/// Verify FRI arithmetic and MMCS openings in-circuit.
///
/// Challenge/indices generation lives in the outer verifier. This function takes
/// `alpha`, `betas`, and `index_bits_per_query` as inputs and enforces:
/// - input-batch MMCS openings (`open_input`)
/// - per-phase commit MMCS openings
/// - FRI fold arithmetic and final polynomial binding
///
/// Reference (Plonky3): `p3_fri::verifier::verify_fri`
#[allow(clippy::too_many_arguments)]
pub fn verify_fri_circuit<F, EF, RecMmcs, Inner, Witness, Comm>(
    builder: &mut CircuitBuilder<EF>,
    fri_proof_targets: &FriProofTargets<F, EF, RecMmcs, InputProofTargets<F, EF, Inner>, Witness>,
    alpha: Target,
    betas: &[Target],
    index_bits_per_query: &[Vec<Target>],
    commitments_with_opening_points: &ComsWithOpeningsTargets<Comm, TwoAdicMultiplicativeCoset<F>>,
    log_blowup: usize,
) -> Result<(), VerificationError>
where
    F: PrimeField64 + TwoAdicField,
    EF: ExtensionField<F>,
    RecMmcs: RecursiveExtensionMmcs<F, EF>,
    Inner: RecursiveMmcs<F, EF>,
    Witness: Recursive<EF>,
    Comm: ObservableCommitment,
{
    builder.push_scope("verify_fri");

    let num_phases = betas.len();
    let num_queries = fri_proof_targets.query_proofs.len();

    // Validate shape.
    if num_phases != fri_proof_targets.commit_phase_commits.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "betas length must equal number of commit-phase commitments: expected {}, got {}",
            num_phases,
            fri_proof_targets.commit_phase_commits.len()
        )));
    }

    if num_phases != fri_proof_targets.commit_pow_witnesses.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "Number of commit-phase commitments must equal number of commit-phase pow witnesses: expected {}, got {}",
            num_phases,
            fri_proof_targets.commit_pow_witnesses.len()
        )));
    }

    if num_queries != index_bits_per_query.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "index_bits_per_query length must equal number of query proofs: expected {}, got {}",
            num_queries,
            index_bits_per_query.len()
        )));
    }

    let log_max_height = index_bits_per_query[0].len();
    if index_bits_per_query
        .iter()
        .any(|v| v.len() != log_max_height)
    {
        return Err(VerificationError::InvalidProofShape(
            "all index_bits_per_query entries must have same length".to_string(),
        ));
    }

    if betas.is_empty() {
        return Err(VerificationError::InvalidProofShape(
            "FRI must have at least one fold phase".to_string(),
        ));
    }

    // Compute the expected final polynomial length from FRI parameters
    // log_max_height = num_phases + log_final_poly_len + log_blowup
    // So: log_final_poly_len = log_max_height - num_phases - log_blowup
    let log_final_poly_len = log_max_height
        .checked_sub(num_phases)
        .and_then(|x| x.checked_sub(log_blowup))
        .ok_or_else(|| {
            VerificationError::InvalidProofShape(
                "Invalid FRI parameters: log_max_height too small".to_string(),
            )
        })?;

    let expected_final_poly_len = 1 << log_final_poly_len;
    let actual_final_poly_len = fri_proof_targets.final_poly.len();

    //  Check the final polynomial length.
    if actual_final_poly_len != expected_final_poly_len {
        return Err(VerificationError::InvalidProofShape(format!(
            "Final polynomial length mismatch: expected 2^{log_final_poly_len} = {expected_final_poly_len}, got {actual_final_poly_len}"
        )));
    }

    // Precompute two-adic generator ladders for each phase (in circuit field EF).
    //
    // For phase i, folded height k = log_max_height - i - 1.
    // Use generator g = two_adic_generator(k + 1) and ladder [g^{2^0},...,g^{2^{k-1}}].
    let pows_per_phase: Vec<Vec<EF>> = (0..num_phases)
        .map(|i| {
            // `k` is the height of the folded domain after `i` rounds of folding.
            let k = log_max_height.saturating_sub(i + 1);
            if k == 0 {
                return Vec::new();
            }
            let g = F::two_adic_generator(k + 1);
            // Create the power ladder [g, g^2, g^4, ...].
            iter::successors(Some(g), |&prev| Some(prev.square()))
                .take(k)
                .map(EF::from)
                .collect()
        })
        .collect();

    // For each query, extract opened values from proof and compute reduced openings and fold.
    for (q, query_proof) in fri_proof_targets.query_proofs.iter().enumerate() {
        if query_proof.commit_phase_openings.len() != num_phases {
            return Err(VerificationError::InvalidProofShape(format!(
                "query {q}: commit-phase openings must match number of phases: expected {}, got {}",
                num_phases,
                query_proof.commit_phase_openings.len()
            )));
        }

        // Verify input-batch MMCS openings and compute arithmetic reductions by height.
        let reduced_by_height = open_input::<F, EF, Comm, Inner>(
            builder,
            log_max_height,
            &index_bits_per_query[q],
            alpha,
            log_blowup,
            commitments_with_opening_points,
            &query_proof.input_proof,
        )?;

        // Must have the max-height entry at the front

        if reduced_by_height.is_empty() {
            return Err(VerificationError::InvalidProofShape(
                "No reduced openings; did you commit to zero polynomials?".to_string(),
            ));
        }
        if reduced_by_height[0].0 != log_max_height {
            return Err(VerificationError::InvalidProofShape(format!(
                "First reduced opening must be at max height {}, got {}",
                log_max_height, reduced_by_height[0].0
            )));
        }
        let initial_folded_eval = reduced_by_height[0].1;

        // Build height-aligned roll-ins for each phase (desc heights -> phases)
        let mut roll_ins: Vec<Option<Target>> = vec![None; num_phases];
        for &(h, ro) in reduced_by_height.iter().skip(1) {
            // height -> phase index mapping
            let i = log_max_height
                .checked_sub(1)
                .and_then(|x| x.checked_sub(h))
                .expect("height->phase mapping underflow");
            if i < num_phases {
                // There should be at most one roll-in per phase since `reduced_by_height`
                // aggregates all matrices at the same height already (and we only support a
                // single input batch). Multiple entries mapping to the same phase indicate an
                // invariant violation.
                if roll_ins[i].is_some() {
                    return Err(VerificationError::InvalidProofShape(format!(
                        "duplicate roll-in for phase {i} (height {h})",
                    )));
                }
                roll_ins[i] = Some(ro);
            } else {
                // If a height is below final folded height, it should be unused; connect to zero.
                let zero = builder.add_const(EF::ZERO);
                builder.connect(ro, zero);
            }
        }

        // Compute the final query point for this query and evaluate the final polynomial
        let final_query_point = compute_final_query_point::<F, EF>(
            builder,
            &index_bits_per_query[q],
            log_max_height,
            num_phases,
        );

        let final_poly_eval =
            evaluate_polynomial(builder, &fri_proof_targets.final_poly, final_query_point);

        // Perform the fold chain. At every phase, verify the corresponding MMCS opening.
        let one = builder.add_const(EF::ONE);
        let mut folded = initial_folded_eval;
        for i in 0..num_phases {
            let opening = &query_proof.commit_phase_openings[i];
            let raw_bit = index_bits_per_query[q][i];
            let sibling_is_right = builder.sub(one, raw_bit);
            let e_sibling = opening.sibling_value;

            // Build the pair of sibling evaluations in verifier order [left, right].
            // If bit=0 current node is left, sibling is right; if bit=1 the opposite.
            let eval_left = builder.select(raw_bit, e_sibling, folded);
            let eval_right = builder.select(raw_bit, folded, e_sibling);
            let opened_evals = vec![vec![eval_left, eval_right]];

            let log_folded_height = log_max_height.saturating_sub(i + 1);
            let phase_dimensions = [Dimensions {
                width: 2,
                height: 1usize << log_folded_height,
            }];
            let phase_index_bits =
                &index_bits_per_query[q][i + 1..i + 1 + log_folded_height];
            RecMmcs::verify_batch_circuit(
                builder,
                &fri_proof_targets.commit_phase_commits[i].to_observation_targets(),
                &phase_dimensions,
                phase_index_bits,
                &opened_evals,
                &opening.opening_proof,
            )?;

            // Standard FRI fold interpolation for this phase.
            let x0 = compute_x0_from_index_bits(builder, &index_bits_per_query[q], i, &pows_per_phase[i]);
            let e0 = builder.select(sibling_is_right, folded, e_sibling);
            let neg_half = builder.add_const(EF::NEG_ONE * EF::ONE.halve());
            let inv = builder.div(neg_half, x0);
            let d = builder.sub(e_sibling, folded);
            let two_b = builder.add(sibling_is_right, sibling_is_right);
            let two_b_minus_one = builder.sub(two_b, one);
            let e1_minus_e0 = builder.mul(two_b_minus_one, d);
            let beta_minus_x0 = builder.sub(betas[i], x0);
            let t = builder.mul(beta_minus_x0, e1_minus_e0);
            let t_inv = builder.mul(t, inv);
            folded = builder.add(e0, t_inv);

            if let Some(ro) = roll_ins[i] {
                let beta_sq = builder.mul(betas[i], betas[i]);
                let add_term = builder.mul(beta_sq, ro);
                folded = builder.add(folded, add_term);
            }
        }

        builder.connect(folded, final_poly_eval);
    }

    builder.pop_scope(); // close `verify_fri` scope
    Ok(())
}
