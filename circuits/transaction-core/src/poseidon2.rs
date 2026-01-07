//! Poseidon2 permutation helpers for the Plonky3 in-circuit sponge.

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

use crate::constants::{
    POSEIDON2_EXTERNAL_ROUNDS, POSEIDON2_INTERNAL_ROUNDS, POSEIDON2_STEPS, POSEIDON2_WIDTH,
};
use crate::poseidon2_constants::{EXTERNAL_ROUND_CONSTANTS, INTERNAL_MATRIX_DIAG, INTERNAL_ROUND_CONSTANTS};

pub type Felt = Goldilocks;

/// Deterministic seed used to generate Poseidon2 round constants.
pub const POSEIDON2_SEED: [u8; 32] = *b"hegemon-tx-poseidon2-seed-2026!!";

#[inline(always)]
fn sbox(x: Felt) -> Felt {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    x6 * x
}

#[inline(always)]
fn apply_mds4(x: &mut [Felt; 4]) {
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
fn mds_light(state: &mut [Felt; POSEIDON2_WIDTH]) {
    for chunk in state.chunks_exact_mut(4) {
        let mut tmp = [chunk[0], chunk[1], chunk[2], chunk[3]];
        apply_mds4(&mut tmp);
        chunk.copy_from_slice(&tmp);
    }

    let mut sums = [Felt::ZERO; 4];
    for k in 0..4 {
        let mut acc = Felt::ZERO;
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
fn matmul_internal(state: &mut [Felt; POSEIDON2_WIDTH]) {
    let mut sum = Felt::ZERO;
    for elem in state.iter() {
        sum += *elem;
    }

    for (idx, elem) in state.iter_mut().enumerate() {
        let diag = Felt::from_u64(INTERNAL_MATRIX_DIAG[idx]);
        *elem = *elem * diag + sum;
    }
}

#[inline(always)]
fn external_round(state: &mut [Felt; POSEIDON2_WIDTH], rc: &[u64; POSEIDON2_WIDTH]) {
    for (idx, elem) in state.iter_mut().enumerate() {
        *elem = sbox(*elem + Felt::from_u64(rc[idx]));
    }
    mds_light(state);
}

#[inline(always)]
fn internal_round(state: &mut [Felt; POSEIDON2_WIDTH], rc: u64) {
    state[0] = sbox(state[0] + Felt::from_u64(rc));
    matmul_internal(state);
}

pub fn poseidon2_step(state: &mut [Felt; POSEIDON2_WIDTH], step: usize) {
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

pub fn poseidon2_permutation(state: &mut [Felt; POSEIDON2_WIDTH]) {
    for step in 0..POSEIDON2_STEPS {
        poseidon2_step(state, step);
    }
}
