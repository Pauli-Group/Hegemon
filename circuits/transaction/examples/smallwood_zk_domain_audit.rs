//! Executable complete-ZK audit for SmallWood's LVCS/DECS boundary.
//!
//! This file is deliberately dependency-free so the leakage certificate can
//! be compiled with `rustc --test` without building Hegemon's large workspace.
//! It proves an exact defect in the retained Level-5 geometry and exercises
//! the smallest domain-level repair.  It does **not** authorize production or
//! claim a complete simulator for the whole serialized proof.

use std::fmt::Write as _;

const GOLDILOCKS_ORDER: u64 = 0xffff_ffff_0000_0001;
const GOLDILOCKS_TWO_ADIC_ROOT: u64 = 0x1856_29dc_da58_878c;
const GOLDILOCKS_TWO_ADICITY: u32 = 32;

const ACTIVE_DECS_DOMAIN_SIZE: usize = 1 << 20;
const ACTIVE_DECS_OPENINGS: usize = 23;
const ACTIVE_LVCS_COLUMNS: usize = 375;
const ACTIVE_LVCS_RANDOM_PREFIX: usize = ACTIVE_DECS_OPENINGS;
const ACTIVE_LVCS_INTERPOLATION_POINTS: usize = ACTIVE_LVCS_COLUMNS + ACTIVE_LVCS_RANDOM_PREFIX;
const ACTIVE_PIOP_OPENINGS: usize = 5;
const ACTIVE_PACKING_FACTOR: usize = 64;
const ACTIVE_WITNESS_POLYNOMIAL_COEFFICIENTS: usize = ACTIVE_PACKING_FACTOR + ACTIVE_PIOP_OPENINGS;

const LEAK_FIELD_POINT: u64 = 64;
const LEAK_LEAF_INDEX: usize = 163_840;
const LEAK_LVCS_COLUMN: usize = LEAK_FIELD_POINT as usize - ACTIVE_LVCS_RANDOM_PREFIX;

// The strict QROM target uses 512 bits.  A 256-bit tape would contribute a
// `Q_H^2 / 2^256` term of one at `Q_H = 2^128` before constants or unions.
const STRICT_DECS_LEAF_TAPE_BYTES: usize = 64;
const STRICT_DECS_LEAF_DOMAIN: &[u8] = b"hegemon.smallwood.strict-zk.merkle-leaf.v1";

fn add_mod(left: u64, right: u64) -> u64 {
    ((left as u128 + right as u128) % GOLDILOCKS_ORDER as u128) as u64
}

fn sub_mod(left: u64, right: u64) -> u64 {
    ((left as u128 + GOLDILOCKS_ORDER as u128 - right as u128) % GOLDILOCKS_ORDER as u128) as u64
}

fn mul_mod(left: u64, right: u64) -> u64 {
    ((left as u128 * right as u128) % GOLDILOCKS_ORDER as u128) as u64
}

fn pow_mod(mut base: u64, mut exponent: u64) -> u64 {
    let mut result = 1u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base);
        }
        base = mul_mod(base, base);
        exponent >>= 1;
    }
    result
}

fn inv_mod(value: u64) -> Result<u64, &'static str> {
    if value == 0 || value >= GOLDILOCKS_ORDER {
        return Err("cannot invert a non-field or zero value");
    }
    Ok(pow_mod(value, GOLDILOCKS_ORDER - 2))
}

fn subgroup_generator(size: usize) -> Result<u64, &'static str> {
    if size == 0 || !size.is_power_of_two() {
        return Err("radix-2 domain size must be a nonzero power of two");
    }
    let log_size = size.ilog2();
    if log_size > GOLDILOCKS_TWO_ADICITY {
        return Err("radix-2 domain exceeds Goldilocks two-adicity");
    }
    let root = pow_mod(
        GOLDILOCKS_TWO_ADIC_ROOT,
        1u64 << (GOLDILOCKS_TWO_ADICITY - log_size),
    );
    if pow_mod(root, size as u64) != 1 || (size > 1 && pow_mod(root, (size / 2) as u64) == 1) {
        return Err("derived root does not have the requested order");
    }
    Ok(root)
}

fn subgroup_point(size: usize, leaf_index: usize) -> Result<u64, &'static str> {
    if leaf_index >= size {
        return Err("leaf index exceeds DECS domain");
    }
    Ok(pow_mod(subgroup_generator(size)?, leaf_index as u64))
}

fn point_is_in_subgroup(point: u64, size: usize) -> bool {
    point != 0 && point < GOLDILOCKS_ORDER && pow_mod(point, size as u64) == 1
}

fn coset_is_disjoint(
    size: usize,
    interpolation_point_count: usize,
    shift: u64,
) -> Result<bool, &'static str> {
    let inverse = inv_mod(shift)?;
    Ok((1..interpolation_point_count)
        .all(|point| !point_is_in_subgroup(mul_mod(point as u64, inverse), size)))
}

fn first_disjoint_coset_shift(
    size: usize,
    interpolation_point_count: usize,
) -> Result<u64, &'static str> {
    if interpolation_point_count == 0 {
        return Err("interpolation domain must not be empty");
    }
    for offset in 0..4096u64 {
        let candidate = interpolation_point_count as u64 + offset;
        if coset_is_disjoint(size, interpolation_point_count, candidate)? {
            return Ok(candidate);
        }
    }
    Err("bounded disjoint-coset search exhausted")
}

fn coset_point(size: usize, shift: u64, leaf_index: usize) -> Result<u64, &'static str> {
    Ok(mul_mod(shift, subgroup_point(size, leaf_index)?))
}

fn polynomial_eval(coefficients: &[u64], point: u64) -> u64 {
    coefficients.iter().rev().fold(0u64, |acc, &coefficient| {
        add_mod(mul_mod(acc, point), coefficient)
    })
}

fn matrix_rank(mut matrix: Vec<Vec<u64>>) -> Result<usize, &'static str> {
    if matrix.is_empty() {
        return Ok(0);
    }
    let columns = matrix[0].len();
    if matrix.iter().any(|row| row.len() != columns) {
        return Err("ragged matrix");
    }
    let mut rank = 0usize;
    for column in 0..columns {
        let Some(pivot) = (rank..matrix.len()).find(|&row| matrix[row][column] != 0) else {
            continue;
        };
        matrix.swap(rank, pivot);
        let inverse = inv_mod(matrix[rank][column])?;
        for entry in &mut matrix[rank][column..] {
            *entry = mul_mod(*entry, inverse);
        }
        let pivot_row = matrix[rank].clone();
        for (row_index, row) in matrix.iter_mut().enumerate() {
            if row_index == rank || row[column] == 0 {
                continue;
            }
            let factor = row[column];
            for index in column..columns {
                row[index] = sub_mod(row[index], mul_mod(factor, pivot_row[index]));
            }
        }
        rank += 1;
        if rank == matrix.len() {
            break;
        }
    }
    Ok(rank)
}

/// Rank of the view available when the leaking DECS leaf is opened:
/// coefficients 5..68 are exposed by LVCS subset evaluations and the five
/// ordinary PIOP openings expose five polynomial evaluations.
fn active_sensitive_view_rank(opening_points: &[u64]) -> Result<usize, &'static str> {
    if opening_points.len() != ACTIVE_PIOP_OPENINGS {
        return Err("wrong PIOP opening count");
    }
    let mut observation = Vec::with_capacity(ACTIVE_WITNESS_POLYNOMIAL_COEFFICIENTS);
    for coefficient in ACTIVE_PIOP_OPENINGS..ACTIVE_WITNESS_POLYNOMIAL_COEFFICIENTS {
        let mut selector = vec![0u64; ACTIVE_WITNESS_POLYNOMIAL_COEFFICIENTS];
        selector[coefficient] = 1;
        observation.push(selector);
    }
    for &point in opening_points {
        let mut row = vec![0u64; ACTIVE_WITNESS_POLYNOMIAL_COEFFICIENTS];
        let mut power = 1u64;
        for entry in &mut row {
            *entry = power;
            power = mul_mod(power, point);
        }
        observation.push(row);
    }
    matrix_rank(observation)
}

/// Rank of the LVCS random-tail action on a strict set of DECS openings.
/// For interpolation nodes `0..397`, the 23 columns belonging to random nodes
/// `375..397` reduce, up to invertible row and column scalings, to the Cauchy
/// matrix `1 / (query_i - random_node_j)`. Distinct coset queries outside the
/// interpolation domain therefore give full rank.
fn strict_lvcs_random_tail_rank(leaf_indexes: &[usize]) -> Result<usize, &'static str> {
    if leaf_indexes.len() != ACTIVE_DECS_OPENINGS {
        return Err("wrong strict DECS opening count");
    }
    let mut sorted = leaf_indexes.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("strict DECS leaf indexes must be distinct");
    }
    let shift =
        first_disjoint_coset_shift(ACTIVE_DECS_DOMAIN_SIZE, ACTIVE_LVCS_INTERPOLATION_POINTS)?;
    let query_points = leaf_indexes
        .iter()
        .map(|&index| coset_point(ACTIVE_DECS_DOMAIN_SIZE, shift, index))
        .collect::<Result<Vec<_>, _>>()?;
    let cauchy = query_points
        .iter()
        .map(|&query| {
            (ACTIVE_LVCS_COLUMNS..ACTIVE_LVCS_INTERPOLATION_POINTS)
                .map(|random_node| inv_mod(sub_mod(query, random_node as u64)))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    matrix_rank(cauchy)
}

fn solve_square_system(coefficients: &[Vec<u64>], rhs: &[u64]) -> Result<Vec<u64>, &'static str> {
    let size = coefficients.len();
    if size == 0 || rhs.len() != size || coefficients.iter().any(|row| row.len() != size) {
        return Err("linear system is not square");
    }
    let mut augmented = Vec::with_capacity(size);
    for (row, &value) in coefficients.iter().zip(rhs) {
        let mut augmented_row = row.clone();
        augmented_row.push(value);
        augmented.push(augmented_row);
    }
    for column in 0..size {
        let Some(pivot) = (column..size).find(|&row| augmented[row][column] != 0) else {
            return Err("linear system is singular");
        };
        augmented.swap(column, pivot);
        let inverse = inv_mod(augmented[column][column])?;
        for entry in &mut augmented[column][column..=size] {
            *entry = mul_mod(*entry, inverse);
        }
        let pivot_row = augmented[column].clone();
        for (row_index, row) in augmented.iter_mut().enumerate() {
            if row_index == column || row[column] == 0 {
                continue;
            }
            let factor = row[column];
            for index in column..=size {
                row[index] = sub_mod(row[index], mul_mod(factor, pivot_row[index]));
            }
        }
    }
    Ok(augmented.into_iter().map(|row| row[size]).collect())
}

fn recover_polynomial_from_sensitive_view(
    leaked_coefficients_5_through_68: &[u64],
    opening_points: &[u64],
    opening_values: &[u64],
) -> Result<Vec<u64>, &'static str> {
    if leaked_coefficients_5_through_68.len()
        != ACTIVE_WITNESS_POLYNOMIAL_COEFFICIENTS - ACTIVE_PIOP_OPENINGS
        || opening_points.len() != ACTIVE_PIOP_OPENINGS
        || opening_values.len() != ACTIVE_PIOP_OPENINGS
    {
        return Err("sensitive view has the wrong shape");
    }
    let mut system = vec![vec![0u64; ACTIVE_PIOP_OPENINGS]; ACTIVE_PIOP_OPENINGS];
    let mut residuals = vec![0u64; ACTIVE_PIOP_OPENINGS];
    for row in 0..ACTIVE_PIOP_OPENINGS {
        let point = opening_points[row];
        let mut power = 1u64;
        for column in 0..ACTIVE_PIOP_OPENINGS {
            system[row][column] = power;
            power = mul_mod(power, point);
        }
        let mut leaked_contribution = 0u64;
        for &coefficient in leaked_coefficients_5_through_68 {
            leaked_contribution = add_mod(leaked_contribution, mul_mod(coefficient, power));
            power = mul_mod(power, point);
        }
        residuals[row] = sub_mod(opening_values[row], leaked_contribution);
    }
    let mut recovered = solve_square_system(&system, &residuals)?;
    recovered.extend_from_slice(leaked_coefficients_5_through_68);
    Ok(recovered)
}

fn strict_decs_leaf_preimage(
    salt: &[u8; 32],
    leaf_index: u32,
    tape: &[u8; STRICT_DECS_LEAF_TAPE_BYTES],
    committed_evaluations: &[u64],
    masking_evaluations: &[u64],
) -> Vec<u8> {
    let word_count = 4usize
        + 1
        + STRICT_DECS_LEAF_TAPE_BYTES / 8
        + 1
        + committed_evaluations.len()
        + 1
        + masking_evaluations.len();
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(STRICT_DECS_LEAF_DOMAIN.len() as u64).to_le_bytes());
    encoded.extend_from_slice(STRICT_DECS_LEAF_DOMAIN);
    encoded.extend_from_slice(&(word_count as u64).to_le_bytes());
    encoded.extend_from_slice(salt);
    encoded.extend_from_slice(&(leaf_index as u64).to_le_bytes());
    encoded.extend_from_slice(tape);
    encoded.extend_from_slice(&(committed_evaluations.len() as u64).to_le_bytes());
    for value in committed_evaluations {
        encoded.extend_from_slice(&value.to_le_bytes());
    }
    encoded.extend_from_slice(&(masking_evaluations.len() as u64).to_le_bytes());
    for value in masking_evaluations {
        encoded.extend_from_slice(&value.to_le_bytes());
    }
    encoded.extend_from_slice(&0u64.to_le_bytes());
    encoded
}

fn report() -> Result<String, &'static str> {
    let opening_points = [1000, 1001, 1002, 1003, 1004];
    if subgroup_point(ACTIVE_DECS_DOMAIN_SIZE, LEAK_LEAF_INDEX)? != LEAK_FIELD_POINT {
        return Err("retained DECS leak leaf no longer maps to field point 64");
    }
    let observation_rank = active_sensitive_view_rank(&opening_points)?;
    let coefficients = (0..ACTIVE_WITNESS_POLYNOMIAL_COEFFICIENTS)
        .map(|index| (index as u64 + 17) * 1_000_003 % GOLDILOCKS_ORDER)
        .collect::<Vec<_>>();
    let opening_values = opening_points
        .iter()
        .map(|&point| polynomial_eval(&coefficients, point))
        .collect::<Vec<_>>();
    let recovered = recover_polynomial_from_sensitive_view(
        &coefficients[ACTIVE_PIOP_OPENINGS..],
        &opening_points,
        &opening_values,
    )?;
    if recovered != coefficients {
        return Err("sensitive DECS view did not recover the witness polynomial");
    }
    let coset_shift =
        first_disjoint_coset_shift(ACTIVE_DECS_DOMAIN_SIZE, ACTIVE_LVCS_INTERPOLATION_POINTS)?;
    if (0..ACTIVE_DECS_DOMAIN_SIZE)
        .step_by(ACTIVE_DECS_DOMAIN_SIZE / 16)
        .map(|leaf| coset_point(ACTIVE_DECS_DOMAIN_SIZE, coset_shift, leaf))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|point| *point < ACTIVE_LVCS_INTERPOLATION_POINTS as u64)
    {
        return Err("disjoint-coset sample intersects the interpolation domain");
    }
    let salt = [7u8; 32];
    let tape = [11u8; STRICT_DECS_LEAF_TAPE_BYTES];
    let baseline_leaf_frame = strict_decs_leaf_preimage(&salt, 9, &tape, &[1, 2, 3], &[4, 5]);
    let mut changed_tape = tape;
    changed_tape[0] ^= 1;
    if baseline_leaf_frame
        == strict_decs_leaf_preimage(&salt, 9, &changed_tape, &[1, 2, 3], &[4, 5])
    {
        return Err("strict DECS leaf framing does not bind its random tape");
    }
    let mut output = String::new();
    let strict_tail_rank =
        strict_lvcs_random_tail_rank(&(0..ACTIVE_DECS_OPENINGS).collect::<Vec<_>>())?;
    writeln!(output, "smallwood_complete_zk_domain_audit_v1").unwrap();
    writeln!(output, "field_order={GOLDILOCKS_ORDER}").unwrap();
    writeln!(output, "decs_domain_size={ACTIVE_DECS_DOMAIN_SIZE}").unwrap();
    writeln!(output, "decs_openings={ACTIVE_DECS_OPENINGS}").unwrap();
    writeln!(output, "leak_field_point={LEAK_FIELD_POINT}").unwrap();
    writeln!(output, "leak_leaf_index={LEAK_LEAF_INDEX}").unwrap();
    writeln!(output, "leak_lvcs_column={LEAK_LVCS_COLUMN}").unwrap();
    writeln!(
        output,
        "exact_leak_hit_probability={ACTIVE_DECS_OPENINGS}/{ACTIVE_DECS_DOMAIN_SIZE}"
    )
    .unwrap();
    writeln!(
        output,
        "sensitive_view_rank={observation_rank}/{ACTIVE_WITNESS_POLYNOMIAL_COEFFICIENTS}"
    )
    .unwrap();
    writeln!(output, "first_disjoint_coset_shift={coset_shift}").unwrap();
    writeln!(
        output,
        "strict_lvcs_tail_to_openings_rank={strict_tail_rank}/{ACTIVE_DECS_OPENINGS}"
    )
    .unwrap();
    writeln!(
        output,
        "opened_leaf_tape_wire_delta_bytes={}",
        ACTIVE_DECS_OPENINGS * STRICT_DECS_LEAF_TAPE_BYTES
    )
    .unwrap();
    writeln!(output, "complete_zk=false").unwrap();
    Ok(output)
}

fn main() {
    match report() {
        Ok(report) => print!("{report}"),
        Err(error) => {
            eprintln!("smallwood complete-ZK audit failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_subgroup_leaf_163840_is_exactly_field_point_64() {
        assert_eq!(
            subgroup_point(ACTIVE_DECS_DOMAIN_SIZE, LEAK_LEAF_INDEX).unwrap(),
            LEAK_FIELD_POINT
        );
        assert_eq!(LEAK_LVCS_COLUMN, 41);
        assert!(LEAK_FIELD_POINT as usize >= ACTIVE_LVCS_RANDOM_PREFIX);
        assert!((LEAK_FIELD_POINT as usize) < ACTIVE_LVCS_INTERPOLATION_POINTS);
    }

    #[test]
    fn sensitive_leaf_plus_five_openings_has_full_polynomial_rank() {
        let opening_points = [1000, 1001, 1002, 1003, 1004];
        assert_eq!(
            active_sensitive_view_rank(&opening_points).unwrap(),
            ACTIVE_WITNESS_POLYNOMIAL_COEFFICIENTS
        );
    }

    #[test]
    fn sensitive_view_recovers_every_packed_witness_value() {
        let coefficients = (0..ACTIVE_WITNESS_POLYNOMIAL_COEFFICIENTS)
            .map(|index| (index as u64 + 17) * 1_000_003 % GOLDILOCKS_ORDER)
            .collect::<Vec<_>>();
        let opening_points = [1000, 1001, 1002, 1003, 1004];
        let opening_values = opening_points
            .iter()
            .map(|&point| polynomial_eval(&coefficients, point))
            .collect::<Vec<_>>();
        let recovered = recover_polynomial_from_sensitive_view(
            &coefficients[ACTIVE_PIOP_OPENINGS..],
            &opening_points,
            &opening_values,
        )
        .unwrap();
        assert_eq!(recovered, coefficients);
        let packed_witness = (0..ACTIVE_PACKING_FACTOR)
            .map(|point| polynomial_eval(&coefficients, point as u64))
            .collect::<Vec<_>>();
        let recovered_witness = (0..ACTIVE_PACKING_FACTOR)
            .map(|point| polynomial_eval(&recovered, point as u64))
            .collect::<Vec<_>>();
        assert_eq!(recovered_witness, packed_witness);
    }

    #[test]
    fn exact_fixed_leaf_hit_probability_is_not_negligible() {
        assert_eq!(ACTIVE_DECS_OPENINGS, 23);
        assert_eq!(ACTIVE_DECS_DOMAIN_SIZE, 1_048_576);
        // A uniform subset without replacement of size ell contains one fixed
        // leaf with exact probability ell/N.  Cross multiplication pins that
        // this is greater than 2^-16.
        assert!(ACTIVE_DECS_OPENINGS * (1usize << 16) > ACTIVE_DECS_DOMAIN_SIZE);
    }

    #[test]
    fn deterministic_coset_repair_is_disjoint_from_every_interpolation_point() {
        let shift =
            first_disjoint_coset_shift(ACTIVE_DECS_DOMAIN_SIZE, ACTIVE_LVCS_INTERPOLATION_POINTS)
                .unwrap();
        assert_eq!(shift, 398);
        assert!(coset_is_disjoint(
            ACTIVE_DECS_DOMAIN_SIZE,
            ACTIVE_LVCS_INTERPOLATION_POINTS,
            shift
        )
        .unwrap());
        for leaf in [0, 1, LEAK_LEAF_INDEX, ACTIVE_DECS_DOMAIN_SIZE - 1] {
            let point = coset_point(ACTIVE_DECS_DOMAIN_SIZE, shift, leaf).unwrap();
            assert!(point >= ACTIVE_LVCS_INTERPOLATION_POINTS as u64);
        }
    }

    #[test]
    fn strict_coset_openings_are_fully_masked_by_the_23_lvcs_random_tail_values() {
        let samples = [
            (0..ACTIVE_DECS_OPENINGS).collect::<Vec<_>>(),
            (0..ACTIVE_DECS_OPENINGS)
                .map(|index| LEAK_LEAF_INDEX + index)
                .collect::<Vec<_>>(),
            (0..ACTIVE_DECS_OPENINGS)
                .map(|index| index * (ACTIVE_DECS_DOMAIN_SIZE / ACTIVE_DECS_OPENINGS))
                .collect::<Vec<_>>(),
        ];
        for leaf_indexes in samples {
            assert_eq!(
                strict_lvcs_random_tail_rank(&leaf_indexes).unwrap(),
                ACTIVE_DECS_OPENINGS
            );
        }
    }

    #[test]
    fn strict_leaf_frame_binds_index_and_independent_tape() {
        let salt = [7u8; 32];
        let tape = [11u8; STRICT_DECS_LEAF_TAPE_BYTES];
        let baseline = strict_decs_leaf_preimage(&salt, 9, &tape, &[1, 2, 3], &[4, 5]);

        let mut changed_tape = tape;
        changed_tape[0] ^= 1;
        assert_ne!(
            baseline,
            strict_decs_leaf_preimage(&salt, 9, &changed_tape, &[1, 2, 3], &[4, 5])
        );
        assert_ne!(
            baseline,
            strict_decs_leaf_preimage(&salt, 10, &tape, &[1, 2, 3], &[4, 5])
        );
        assert_eq!(ACTIVE_DECS_OPENINGS * STRICT_DECS_LEAF_TAPE_BYTES, 1_472);
    }

    #[test]
    fn report_is_fail_closed_and_pins_the_repair_geometry() {
        let report = report().unwrap();
        assert!(report.contains("leak_leaf_index=163840"));
        assert!(report.contains("exact_leak_hit_probability=23/1048576"));
        assert!(report.contains("sensitive_view_rank=69/69"));
        assert!(report.contains("first_disjoint_coset_shift=398"));
        assert!(report.contains("strict_lvcs_tail_to_openings_rank=23/23"));
        assert!(report.contains("complete_zk=false"));
    }
}
