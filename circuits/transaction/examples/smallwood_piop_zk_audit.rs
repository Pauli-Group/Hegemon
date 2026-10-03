//! Dependency-free algebraic audit for SmallWood's local PIOP masking view.
//!
//! The executable proves the exact finite-field bijections used to simulate
//! witness openings, nonlinear quotient messages, zero-sum linear quotient
//! messages, and PCS partial splits. It deliberately excludes Merkle/DECS,
//! Fiat--Shamir, abort conditioning, QROM programming, and compiled-prover
//! refinement, so it never reports complete zero knowledge.

use std::fmt::Write as _;

const GOLDILOCKS_ORDER: u64 = 0xffff_ffff_0000_0001;
const PACKING_FACTOR: usize = 64;
const PIOP_OPENINGS: usize = 5;
const WITNESS_DEGREE: usize = PACKING_FACTOR + PIOP_OPENINGS - 1;
const LINEAR_MASK_DEGREE: usize = WITNESS_DEGREE + PACKING_FACTOR - 1;
const REPRESENTATIVE_OPENING_POINTS: [u64; PIOP_OPENINGS] = [1000, 1001, 1002, 1003, 1004];
const AUDITED_CONSTRAINT_DEGREES: [usize; 4] = [2, 3, 5, 8];

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
        return Err("cannot invert zero or a non-field value");
    }
    Ok(pow_mod(value, GOLDILOCKS_ORDER - 2))
}

fn div_mod(left: u64, right: u64) -> Result<u64, &'static str> {
    Ok(mul_mod(left, inv_mod(right)?))
}

fn neg_mod(value: u64) -> u64 {
    if value == 0 {
        0
    } else {
        GOLDILOCKS_ORDER - value
    }
}

fn polynomial_eval(coefficients: &[u64], point: u64) -> u64 {
    coefficients.iter().rev().fold(0u64, |acc, &coefficient| {
        add_mod(mul_mod(acc, point), coefficient)
    })
}

fn polynomial_add(left: &[u64], right: &[u64]) -> Vec<u64> {
    let mut output = vec![0u64; left.len().max(right.len())];
    for (index, value) in left.iter().enumerate() {
        output[index] = add_mod(output[index], *value);
    }
    for (index, value) in right.iter().enumerate() {
        output[index] = add_mod(output[index], *value);
    }
    output
}

fn polynomial_sub(left: &[u64], right: &[u64]) -> Vec<u64> {
    let mut output = vec![0u64; left.len().max(right.len())];
    for (index, value) in left.iter().enumerate() {
        output[index] = add_mod(output[index], *value);
    }
    for (index, value) in right.iter().enumerate() {
        output[index] = sub_mod(output[index], *value);
    }
    output
}

fn polynomial_add_scaled(target: &mut Vec<u64>, source: &[u64], scale: u64) {
    if target.len() < source.len() {
        target.resize(source.len(), 0);
    }
    for (target, source) in target.iter_mut().zip(source) {
        *target = add_mod(*target, mul_mod(*source, scale));
    }
}

fn polynomial_mul_linear(poly: &[u64], root: u64) -> Vec<u64> {
    let mut output = vec![0u64; poly.len() + 1];
    for (index, coefficient) in poly.iter().enumerate() {
        output[index] = sub_mod(output[index], mul_mod(*coefficient, root));
        output[index + 1] = add_mod(output[index + 1], *coefficient);
    }
    output
}

fn interpolate(points: &[u64], values: &[u64]) -> Result<Vec<u64>, &'static str> {
    if points.is_empty() || points.len() != values.len() {
        return Err("interpolation shape mismatch");
    }
    let mut output = vec![0u64; points.len()];
    for (index, (&point, &value)) in points.iter().zip(values).enumerate() {
        let mut basis = vec![1u64];
        let mut denominator = 1u64;
        for (other_index, &other) in points.iter().enumerate() {
            if index == other_index {
                continue;
            }
            if point == other {
                return Err("interpolation points are not distinct");
            }
            basis = polynomial_mul_linear(&basis, other);
            denominator = mul_mod(denominator, sub_mod(point, other));
        }
        polynomial_add_scaled(&mut output, &basis, div_mod(value, denominator)?);
    }
    Ok(output)
}

fn lagrange_basis(points: &[u64], selected: usize) -> Result<Vec<u64>, &'static str> {
    if points.is_empty() || selected >= points.len() {
        return Err("invalid Lagrange basis request");
    }
    let mut basis = vec![1u64];
    let mut denominator = 1u64;
    for (index, &point) in points.iter().enumerate() {
        if index == selected {
            continue;
        }
        if point == points[selected] {
            return Err("Lagrange points are not distinct");
        }
        basis = polynomial_mul_linear(&basis, point);
        denominator = mul_mod(denominator, sub_mod(points[selected], point));
    }
    let scale = inv_mod(denominator)?;
    for coefficient in &mut basis {
        *coefficient = mul_mod(*coefficient, scale);
    }
    Ok(basis)
}

/// Exact counterpart of the engine's `poly_restore`: `high[k]` is the
/// coefficient at degree `evals.len() + k`.
fn restore_from_high_and_evaluations(
    high: &[u64],
    evals: &[u64],
    eval_points: &[u64],
    degree: usize,
) -> Result<Vec<u64>, &'static str> {
    if evals.is_empty()
        || evals.len() != eval_points.len()
        || high.len() + evals.len() != degree + 1
    {
        return Err("restore shape mismatch");
    }
    let low_count = evals.len();
    let shifted = eval_points
        .iter()
        .zip(evals)
        .map(|(&point, &evaluation)| {
            let high_contribution = mul_mod(
                polynomial_eval(high, point),
                pow_mod(point, low_count as u64),
            );
            sub_mod(evaluation, high_contribution)
        })
        .collect::<Vec<_>>();
    let low = interpolate(eval_points, &shifted)?;
    let mut output = vec![0u64; degree + 1];
    output[..low_count].copy_from_slice(&low);
    output[low_count..].copy_from_slice(high);
    Ok(output)
}

fn packing_sum(poly: &[u64]) -> u64 {
    (0..PACKING_FACTOR).fold(0u64, |sum, point| {
        add_mod(sum, polynomial_eval(poly, point as u64))
    })
}

fn opening_points_valid(points: &[u64]) -> bool {
    points.len() == PIOP_OPENINGS
        && points.iter().enumerate().all(|(index, point)| {
            *point >= PACKING_FACTOR as u64 && !points[..index].contains(point)
        })
}

fn linear_correction_factor(eval_points: &[u64]) -> Result<u64, &'static str> {
    if !opening_points_valid(eval_points) {
        return Err("invalid PIOP opening points");
    }
    let mut points_with_zero = eval_points.to_vec();
    points_with_zero.push(0);
    let zero_lagrange = lagrange_basis(&points_with_zero, PIOP_OPENINGS)?;
    Ok(packing_sum(&zero_lagrange))
}

fn construct_zero_correction_openings() -> Result<[u64; PIOP_OPENINGS], &'static str> {
    let prefix = [1000u64, 1001, 1002, 1003];
    let mut sum_a = 0u64;
    let mut sum_xa = 0u64;
    for x in 0..PACKING_FACTOR as u64 {
        let mut a = 1u64;
        for &point in &prefix {
            a = mul_mod(a, sub_mod(1, div_mod(x, point)?));
        }
        sum_a = add_mod(sum_a, a);
        sum_xa = add_mod(sum_xa, mul_mod(x, a));
    }
    let fifth = div_mod(sum_xa, sum_a)?;
    let points = [prefix[0], prefix[1], prefix[2], prefix[3], fifth];
    if !opening_points_valid(&points) || linear_correction_factor(&points)? != 0 {
        return Err("failed to construct a valid zero-correction opening set");
    }
    Ok(points)
}

fn restore_linear_message(
    high: &[u64],
    evaluations: &[u64],
    eval_points: &[u64],
    target_packing_sum: u64,
) -> Result<Vec<u64>, &'static str> {
    if high.len() + PIOP_OPENINGS + 1 != LINEAR_MASK_DEGREE + 1
        || evaluations.len() != PIOP_OPENINGS
    {
        return Err("linear message shape mismatch");
    }
    let mut points_with_zero = eval_points.to_vec();
    points_with_zero.push(0);
    let mut evaluations_with_zero = evaluations.to_vec();
    evaluations_with_zero.push(0);
    let mut output = restore_from_high_and_evaluations(
        high,
        &evaluations_with_zero,
        &points_with_zero,
        LINEAR_MASK_DEGREE,
    )?;
    let zero_lagrange = lagrange_basis(&points_with_zero, PIOP_OPENINGS)?;
    let correction = packing_sum(&zero_lagrange);
    if correction == 0 {
        return Err("linear correction factor is zero");
    }
    let scale = div_mod(
        sub_mod(target_packing_sum, packing_sum(&output)),
        correction,
    )?;
    polynomial_add_scaled(&mut output, &zero_lagrange, scale);
    Ok(output)
}

fn deterministic_poly(size: usize, domain: u64) -> Vec<u64> {
    (0..size)
        .map(|index| {
            let x = (index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15 ^ domain);
            ((x as u128 * (x.rotate_left(17) | 1) as u128) % GOLDILOCKS_ORDER as u128) as u64
        })
        .collect()
}

fn zero_sum_linear_mask() -> Result<Vec<u64>, &'static str> {
    let mut mask = vec![0u64; LINEAR_MASK_DEGREE + 1];
    mask[1..].copy_from_slice(&deterministic_poly(LINEAR_MASK_DEGREE, 0x4c49_4e));
    let sum_without_constant = packing_sum(&mask);
    mask[0] = div_mod(neg_mod(sum_without_constant), PACKING_FACTOR as u64)?;
    if packing_sum(&mask) != 0 {
        return Err("failed to construct zero-sum linear mask");
    }
    Ok(mask)
}

fn simulate_witness_polynomial(
    packing_values: &[u64],
    desired_openings: &[u64],
    opening_points: &[u64],
) -> Result<Vec<u64>, &'static str> {
    if packing_values.len() != PACKING_FACTOR
        || desired_openings.len() != PIOP_OPENINGS
        || !opening_points_valid(opening_points)
    {
        return Err("witness simulator shape mismatch");
    }
    let mut points = (0..PACKING_FACTOR)
        .map(|point| point as u64)
        .collect::<Vec<_>>();
    points.extend_from_slice(opening_points);
    let mut values = packing_values.to_vec();
    values.extend_from_slice(desired_openings);
    interpolate(&points, &values)
}

fn simulate_nonlinear_view(
    base_evaluations: &[u64],
    sampled_mask_evaluations: &[u64],
    sampled_combined_high: &[u64],
    eval_points: &[u64],
) -> Result<Vec<u64>, &'static str> {
    if base_evaluations.len() != PIOP_OPENINGS
        || sampled_mask_evaluations.len() != PIOP_OPENINGS
        || eval_points.len() != PIOP_OPENINGS
    {
        return Err("nonlinear view shape mismatch");
    }
    let combined_evaluations = base_evaluations
        .iter()
        .zip(sampled_mask_evaluations)
        .map(|(&base, &mask)| add_mod(base, mask))
        .collect::<Vec<_>>();
    let degree = sampled_combined_high
        .len()
        .checked_add(PIOP_OPENINGS)
        .and_then(|size| size.checked_sub(1))
        .ok_or("empty nonlinear view")?;
    restore_from_high_and_evaluations(
        sampled_combined_high,
        &combined_evaluations,
        eval_points,
        degree,
    )
}

fn simulate_linear_view(
    base_evaluations: &[u64],
    sampled_mask_evaluations: &[u64],
    sampled_combined_high: &[u64],
    eval_points: &[u64],
    target_packing_sum: u64,
) -> Result<Vec<u64>, &'static str> {
    if base_evaluations.len() != PIOP_OPENINGS || sampled_mask_evaluations.len() != PIOP_OPENINGS {
        return Err("linear view shape mismatch");
    }
    let combined_evaluations = base_evaluations
        .iter()
        .zip(sampled_mask_evaluations)
        .map(|(&base, &mask)| add_mod(base, mask))
        .collect::<Vec<_>>();
    restore_linear_message(
        sampled_combined_high,
        &combined_evaluations,
        eval_points,
        target_packing_sum,
    )
}

fn simulate_partial_split(
    row_scalar: u64,
    weights: &[u64],
    sampled_partials: &[u64],
) -> Result<Vec<u64>, &'static str> {
    if weights.is_empty() || sampled_partials.len() + 1 != weights.len() || weights[0] == 0 {
        return Err("partial split shape or leading weight mismatch");
    }
    let tail = sampled_partials
        .iter()
        .zip(&weights[1..])
        .fold(0u64, |sum, (&value, &weight)| {
            add_mod(sum, mul_mod(value, weight))
        });
    let first = div_mod(sub_mod(row_scalar, tail), weights[0])?;
    let mut components = vec![first];
    components.extend_from_slice(sampled_partials);
    Ok(components)
}

fn nonlinear_mask_degree(constraint_degree: usize) -> Result<usize, &'static str> {
    constraint_degree
        .checked_mul(WITNESS_DEGREE)
        .and_then(|degree| degree.checked_sub(PACKING_FACTOR))
        .ok_or("nonlinear mask degree underflow/overflow")
}

fn report() -> Result<String, &'static str> {
    let correction = linear_correction_factor(&REPRESENTATIVE_OPENING_POINTS)?;
    if correction == 0 {
        return Err("representative linear correction factor is zero");
    }
    let zero_correction_points = construct_zero_correction_openings()?;
    let packing_values = deterministic_poly(PACKING_FACTOR, 0x5749_54);
    let desired_openings = deterministic_poly(PIOP_OPENINGS, 0x4f50_454e);
    let witness = simulate_witness_polynomial(
        &packing_values,
        &desired_openings,
        &REPRESENTATIVE_OPENING_POINTS,
    )?;
    if witness.len() != WITNESS_DEGREE + 1 {
        return Err("witness simulator returned the wrong degree");
    }
    for (point, expected) in (0..PACKING_FACTOR).zip(&packing_values) {
        if polynomial_eval(&witness, point as u64) != *expected {
            return Err("witness simulator changed a packed value");
        }
    }
    for (&point, &expected) in REPRESENTATIVE_OPENING_POINTS.iter().zip(&desired_openings) {
        if polynomial_eval(&witness, point) != expected {
            return Err("witness simulator missed an opening value");
        }
    }

    for constraint_degree in AUDITED_CONSTRAINT_DEGREES {
        let degree = nonlinear_mask_degree(constraint_degree)?;
        let base = deterministic_poly(degree + 1, 0x4e4c ^ constraint_degree as u64);
        let mask = deterministic_poly(degree + 1, 0x4d41_534b ^ constraint_degree as u64);
        let combined = polynomial_add(&base, &mask);
        let high = &combined[PIOP_OPENINGS..];
        let base_evaluations = REPRESENTATIVE_OPENING_POINTS
            .iter()
            .map(|&point| polynomial_eval(&base, point))
            .collect::<Vec<_>>();
        let mask_evaluations = REPRESENTATIVE_OPENING_POINTS
            .iter()
            .map(|&point| polynomial_eval(&mask, point))
            .collect::<Vec<_>>();
        let simulated = simulate_nonlinear_view(
            &base_evaluations,
            &mask_evaluations,
            high,
            &REPRESENTATIVE_OPENING_POINTS,
        )?;
        if simulated != combined {
            return Err("nonlinear view did not reconstruct the combined message");
        }
    }

    let linear_base = deterministic_poly(LINEAR_MASK_DEGREE + 1, 0x4241_5345);
    let linear_mask = zero_sum_linear_mask()?;
    let linear_combined = polynomial_add(&linear_base, &linear_mask);
    let linear_high = &linear_combined[(PIOP_OPENINGS + 1)..];
    let linear_base_evaluations = REPRESENTATIVE_OPENING_POINTS
        .iter()
        .map(|&point| polynomial_eval(&linear_base, point))
        .collect::<Vec<_>>();
    let linear_mask_evaluations = REPRESENTATIVE_OPENING_POINTS
        .iter()
        .map(|&point| polynomial_eval(&linear_mask, point))
        .collect::<Vec<_>>();
    let simulated_linear = simulate_linear_view(
        &linear_base_evaluations,
        &linear_mask_evaluations,
        linear_high,
        &REPRESENTATIVE_OPENING_POINTS,
        packing_sum(&linear_base),
    )?;
    let simulated_linear_mask = polynomial_sub(&simulated_linear, &linear_base);
    if simulated_linear != linear_combined || simulated_linear_mask != linear_mask {
        return Err("linear zero-sum view did not reconstruct its exact message");
    }

    let split_weights = (0..8)
        .map(|index| pow_mod(17, index as u64))
        .collect::<Vec<_>>();
    let sampled_partials = deterministic_poly(split_weights.len() - 1, 0x5041_5254);
    let row_scalar = 0x1234_5678_9abc_def0 % GOLDILOCKS_ORDER;
    let split = simulate_partial_split(row_scalar, &split_weights, &sampled_partials)?;
    let recombined = split
        .iter()
        .zip(&split_weights)
        .fold(0u64, |sum, (&value, &weight)| {
            add_mod(sum, mul_mod(value, weight))
        });
    if recombined != row_scalar || split[1..] != sampled_partials {
        return Err("partial split view was not bijective");
    }

    let mut output = String::new();
    writeln!(output, "smallwood_piop_zk_audit_v1").unwrap();
    writeln!(output, "field_order={GOLDILOCKS_ORDER}").unwrap();
    writeln!(output, "packing_factor={PACKING_FACTOR}").unwrap();
    writeln!(output, "piop_openings={PIOP_OPENINGS}").unwrap();
    writeln!(output, "witness_opening_view_rank=5/5").unwrap();
    for constraint_degree in AUDITED_CONSTRAINT_DEGREES {
        let degree = nonlinear_mask_degree(constraint_degree)?;
        writeln!(
            output,
            "nonlinear_degree_{constraint_degree}_view_rank={}/{}",
            degree + 1,
            degree + 1
        )
        .unwrap();
    }
    writeln!(output, "linear_zero_sum_view_rank=131/131").unwrap();
    writeln!(output, "linear_correction_factor={correction}").unwrap();
    writeln!(
        output,
        "zero_correction_opening_points={},{},{},{},{}",
        zero_correction_points[0],
        zero_correction_points[1],
        zero_correction_points[2],
        zero_correction_points[3],
        zero_correction_points[4]
    )
    .unwrap();
    writeln!(
        output,
        "current_nonce_predicate_accepts_zero_correction=true"
    )
    .unwrap();
    writeln!(
        output,
        "honest_prover_can_emit_verifier_rejected_linear_view=true"
    )
    .unwrap();
    writeln!(output, "partial_split_is_bijective=true").unwrap();
    writeln!(output, "local_piop_algebraic_simulator=true").unwrap();
    writeln!(output, "whole_proof_simulator=false").unwrap();
    writeln!(output, "complete_zk=false").unwrap();
    Ok(output)
}

fn main() {
    match report() {
        Ok(report) => print!("{report}"),
        Err(error) => {
            eprintln!("smallwood PIOP ZK audit failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_openings_are_a_bijective_view_of_five_random_coefficients() {
        let packing_values = deterministic_poly(PACKING_FACTOR, 0x5749_54);
        let desired_openings = deterministic_poly(PIOP_OPENINGS, 0x4f50_454e);
        let polynomial = simulate_witness_polynomial(
            &packing_values,
            &desired_openings,
            &REPRESENTATIVE_OPENING_POINTS,
        )
        .unwrap();
        assert_eq!(polynomial.len(), WITNESS_DEGREE + 1);
        for (point, expected) in (0..PACKING_FACTOR).zip(&packing_values) {
            assert_eq!(polynomial_eval(&polynomial, point as u64), *expected);
        }
        for (&point, &expected) in REPRESENTATIVE_OPENING_POINTS.iter().zip(&desired_openings) {
            assert_eq!(polynomial_eval(&polynomial, point), expected);
        }
        let restored = restore_from_high_and_evaluations(
            &polynomial[PACKING_FACTOR..],
            &packing_values,
            &(0..PACKING_FACTOR)
                .map(|point| point as u64)
                .collect::<Vec<_>>(),
            WITNESS_DEGREE,
        )
        .unwrap();
        assert_eq!(restored, polynomial);
    }

    #[test]
    fn nonlinear_mask_view_reconstructs_the_exact_combined_polynomial() {
        for constraint_degree in AUDITED_CONSTRAINT_DEGREES {
            let degree = nonlinear_mask_degree(constraint_degree).unwrap();
            let base = deterministic_poly(degree + 1, 0x4e4c ^ constraint_degree as u64);
            let mask = deterministic_poly(degree + 1, 0x4d41_534b ^ constraint_degree as u64);
            let combined = polynomial_add(&base, &mask);
            let high = combined[PIOP_OPENINGS..].to_vec();
            let base_evaluations = REPRESENTATIVE_OPENING_POINTS
                .iter()
                .map(|&point| polynomial_eval(&base, point))
                .collect::<Vec<_>>();
            let mask_evaluations = REPRESENTATIVE_OPENING_POINTS
                .iter()
                .map(|&point| polynomial_eval(&mask, point))
                .collect::<Vec<_>>();
            let simulated = simulate_nonlinear_view(
                &base_evaluations,
                &mask_evaluations,
                &high,
                &REPRESENTATIVE_OPENING_POINTS,
            )
            .unwrap();
            assert_eq!(simulated, combined);
        }
    }

    #[test]
    fn linear_mask_view_is_bijective_on_the_zero_sum_affine_space() {
        let base = deterministic_poly(LINEAR_MASK_DEGREE + 1, 0x4241_5345);
        let mask = zero_sum_linear_mask().unwrap();
        let combined = polynomial_add(&base, &mask);
        let high = combined[(PIOP_OPENINGS + 1)..].to_vec();
        let base_evaluations = REPRESENTATIVE_OPENING_POINTS
            .iter()
            .map(|&point| polynomial_eval(&base, point))
            .collect::<Vec<_>>();
        let mask_evaluations = REPRESENTATIVE_OPENING_POINTS
            .iter()
            .map(|&point| polynomial_eval(&mask, point))
            .collect::<Vec<_>>();
        let simulated = simulate_linear_view(
            &base_evaluations,
            &mask_evaluations,
            &high,
            &REPRESENTATIVE_OPENING_POINTS,
            packing_sum(&base),
        )
        .unwrap();
        assert_eq!(simulated, combined);
        let simulated_mask = polynomial_sub(&simulated, &base);
        assert_eq!(simulated_mask, mask);
        assert_eq!(packing_sum(&simulated), packing_sum(&base));
    }

    #[test]
    fn arbitrary_linear_free_view_variables_produce_one_valid_mask() {
        let base = deterministic_poly(LINEAR_MASK_DEGREE + 1, 0x4241_5345);
        let high = deterministic_poly(LINEAR_MASK_DEGREE + 1 - (PIOP_OPENINGS + 1), 0x4849_4748);
        let base_evaluations = REPRESENTATIVE_OPENING_POINTS
            .iter()
            .map(|&point| polynomial_eval(&base, point))
            .collect::<Vec<_>>();
        let mask_evaluations = deterministic_poly(PIOP_OPENINGS, 0x4556_414c);
        let combined = simulate_linear_view(
            &base_evaluations,
            &mask_evaluations,
            &high,
            &REPRESENTATIVE_OPENING_POINTS,
            packing_sum(&base),
        )
        .unwrap();
        let mask = polynomial_sub(&combined, &base);
        assert_eq!(packing_sum(&mask), 0);
        assert_eq!(&combined[(PIOP_OPENINGS + 1)..], high.as_slice());
        for (((&point, base_eval), mask_eval), expected_mask_eval) in REPRESENTATIVE_OPENING_POINTS
            .iter()
            .zip(&base_evaluations)
            .zip(&mask_evaluations)
            .zip(REPRESENTATIVE_OPENING_POINTS.iter().map(|&point| {
                sub_mod(
                    polynomial_eval(&combined, point),
                    polynomial_eval(&base, point),
                )
            }))
        {
            assert_eq!(
                polynomial_eval(&combined, point),
                add_mod(*base_eval, *mask_eval)
            );
            assert_eq!(expected_mask_eval, *mask_eval);
        }
    }

    #[test]
    fn partial_split_serializes_only_independent_free_coordinates() {
        for width in [2usize, 8] {
            let weights = (0..width)
                .map(|index| pow_mod(17, index as u64))
                .collect::<Vec<_>>();
            let partials = deterministic_poly(width - 1, 0x5041_5254 ^ width as u64);
            let row_scalar = 0x1234_5678_9abc_def0 % GOLDILOCKS_ORDER;
            let components = simulate_partial_split(row_scalar, &weights, &partials).unwrap();
            assert_eq!(&components[1..], partials);
            let recomputed = components
                .iter()
                .zip(weights)
                .fold(0u64, |sum, (&value, weight)| {
                    add_mod(sum, mul_mod(value, weight))
                });
            assert_eq!(recomputed, row_scalar);
        }
    }

    #[test]
    fn strict_nonce_rule_must_include_the_linear_correction_factor() {
        assert!(opening_points_valid(&REPRESENTATIVE_OPENING_POINTS));
        assert_ne!(
            linear_correction_factor(&REPRESENTATIVE_OPENING_POINTS).unwrap(),
            0
        );
        let duplicate = [1000, 1001, 1002, 1003, 1000];
        assert!(!opening_points_valid(&duplicate));
        let counterexample = construct_zero_correction_openings().unwrap();
        assert_eq!(
            counterexample,
            [1000, 1001, 1002, 1003, 9145141821497892284]
        );
        assert!(opening_points_valid(&counterexample));
        assert_eq!(linear_correction_factor(&counterexample).unwrap(), 0);
    }

    #[test]
    fn report_preserves_the_complete_zk_claim_boundary() {
        let report = report().unwrap();
        assert!(report.contains("witness_opening_view_rank=5/5"));
        assert!(report.contains("nonlinear_degree_3_view_rank=141/141"));
        assert!(report.contains("nonlinear_degree_5_view_rank=277/277"));
        assert!(report.contains("linear_zero_sum_view_rank=131/131"));
        assert!(report.contains("current_nonce_predicate_accepts_zero_correction=true"));
        assert!(report.contains("honest_prover_can_emit_verifier_rejected_linear_view=true"));
        assert!(report.contains("local_piop_algebraic_simulator=true"));
        assert!(report.contains("whole_proof_simulator=false"));
        assert!(report.contains("complete_zk=false"));
    }
}
