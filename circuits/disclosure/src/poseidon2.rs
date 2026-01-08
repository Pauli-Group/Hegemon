//! Poseidon2 permutation over Winterfell's base field for disclosure proofs.

use transaction_core::constants::{
    POSEIDON2_EXTERNAL_ROUNDS, POSEIDON2_INTERNAL_ROUNDS, POSEIDON2_STEPS, POSEIDON2_WIDTH,
};
use transaction_core::poseidon2_constants::{
    EXTERNAL_ROUND_CONSTANTS, INTERNAL_MATRIX_DIAG, INTERNAL_ROUND_CONSTANTS,
};
use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;

#[inline(always)]
fn sbox(x: BaseElement) -> BaseElement {
    x.exp(7u64)
}

#[inline(always)]
fn apply_mds4(x: &mut [BaseElement; 4]) {
    let x0 = x[0];
    let x1 = x[1];
    let x2 = x[2];
    let x3 = x[3];

    let t01 = x0 + x1;
    let t23 = x2 + x3;
    let t0123 = t01 + t23;
    let t01123 = t0123 + x1;
    let t01233 = t0123 + x3;

    x[3] = t01233 + (x0 + x0);
    x[1] = t01123 + (x2 + x2);
    x[0] = t01123 + t01;
    x[2] = t01233 + t23;
}

#[inline(always)]
fn mds_light(state: &mut [BaseElement; POSEIDON2_WIDTH]) {
    for chunk in state.chunks_exact_mut(4) {
        let mut tmp = [chunk[0], chunk[1], chunk[2], chunk[3]];
        apply_mds4(&mut tmp);
        chunk.copy_from_slice(&tmp);
    }

    let mut sums = [BaseElement::ZERO; 4];
    for k in 0..4 {
        let mut acc = BaseElement::ZERO;
        let mut idx = k;
        while idx < POSEIDON2_WIDTH {
            acc += state[idx];
            idx += 4;
        }
        sums[k] = acc;
    }

    for (idx, elem) in state.iter_mut().enumerate() {
        *elem += sums[idx % 4];
    }
}

#[inline(always)]
fn matmul_internal(state: &mut [BaseElement; POSEIDON2_WIDTH]) {
    let mut sum = BaseElement::ZERO;
    for elem in state.iter() {
        sum += *elem;
    }

    for (idx, elem) in state.iter_mut().enumerate() {
        let diag = BaseElement::new(INTERNAL_MATRIX_DIAG[idx]);
        *elem = *elem * diag + sum;
    }
}

#[inline(always)]
fn external_round(state: &mut [BaseElement; POSEIDON2_WIDTH], rc: &[u64; POSEIDON2_WIDTH]) {
    for (idx, elem) in state.iter_mut().enumerate() {
        *elem = sbox(*elem + BaseElement::new(rc[idx]));
    }
    mds_light(state);
}

#[inline(always)]
fn internal_round(state: &mut [BaseElement; POSEIDON2_WIDTH], rc: u64) {
    state[0] = sbox(state[0] + BaseElement::new(rc));
    matmul_internal(state);
}

pub fn poseidon2_step(state: &mut [BaseElement; POSEIDON2_WIDTH], step: usize) {
    debug_assert!(step < POSEIDON2_STEPS);
    if step == 0 {
        mds_light(state);
        return;
    }

    let mut idx = step - 1;
    if idx < POSEIDON2_EXTERNAL_ROUNDS {
        external_round(state, &EXTERNAL_ROUND_CONSTANTS[0][idx]);
        return;
    }
    idx -= POSEIDON2_EXTERNAL_ROUNDS;

    if idx < POSEIDON2_INTERNAL_ROUNDS {
        internal_round(state, INTERNAL_ROUND_CONSTANTS[idx]);
        return;
    }
    idx -= POSEIDON2_INTERNAL_ROUNDS;

    if idx < POSEIDON2_EXTERNAL_ROUNDS {
        external_round(state, &EXTERNAL_ROUND_CONSTANTS[1][idx]);
    }
}
