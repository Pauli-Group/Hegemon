//! Inactive private-spend packed-permutation candidate: 128 live calls, K64.
//!
//! This module does not change a profile, decoder, relation ID, or production gate.
//! It reuses the retained native-round witness builder and degree-seven evaluator.
//! The graph owner must constrain every `Binding`, append every packed row, and
//! include every nonlinear identity. Call count alone does not bind a program:
//! the graph checker must independently bind call order, inputs and output nodes.
#![forbid(unsafe_code)]

use crate::smallwood_poseidon2_v8_hash_constraints::{
    build_smallwood_poseidon2_v8_single_call_trace,
    evaluate_smallwood_poseidon2_v8_single_group_constraints_ring,
    SmallwoodPoseidon2V8HashConstraintError as Error,
    SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINTS_PER_GROUP,
    SMALLWOOD_POSEIDON2_V8_HASH_MAX_CONSTRAINT_DEGREE, SMALLWOOD_POSEIDON2_V8_HASH_ROWS_PER_GROUP,
};
use hegemon_field::PrimeCharacteristicRing;

pub(crate) const LIVE_CALLS: usize = 128;
pub(crate) const PACKING: usize = 64;
pub(crate) const WIDTH: usize = 16;
pub(crate) const SBOX_INPUTS: usize = 150;
pub(crate) const GROUPS: usize = LIVE_CALLS.div_ceil(PACKING);
pub(crate) const PADDED_CALLS: usize = GROUPS * PACKING;
pub(crate) const ROWS_PER_GROUP: usize = SMALLWOOD_POSEIDON2_V8_HASH_ROWS_PER_GROUP;
pub(crate) const CONSTRAINTS_PER_GROUP: usize = SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINTS_PER_GROUP;
pub(crate) const DEGREE: usize = SMALLWOOD_POSEIDON2_V8_HASH_MAX_CONSTRAINT_DEGREE;
pub(crate) const ROWS: usize = GROUPS * ROWS_PER_GROUP;
pub(crate) const CONSTRAINTS: usize = GROUPS * CONSTRAINTS_PER_GROUP;
pub(crate) const LIVE_IO_BINDINGS: usize = LIVE_CALLS * 2 * WIDTH;
pub(crate) const DUMMY_ZERO_BINDINGS: usize = (PADDED_CALLS - LIVE_CALLS) * WIDTH;
const _: () = assert!(GROUPS == 2 && ROWS == 364 && CONSTRAINTS == 332 && DEGREE == 7);
const _: () = assert!(LIVE_IO_BINDINGS == 4096 && DUMMY_ZERO_BINDINGS == 0);

/// `output` contains the raw permutation's 16 output wires. Compression's seven
/// left-feed-forward additions are separate graph linear nodes, after this call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PackedPoseidonCall<W> {
    pub(crate) input: [W; WIDTH],
    pub(crate) output: [W; WIDTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Binding<W> {
    Equal { packed_index: usize, source: W },
    Zero { packed_index: usize },
}

pub(crate) const fn initial_index(row_base: usize, call: usize, lane: usize) -> usize {
    (row_base + (call / PACKING) * ROWS_PER_GROUP + lane) * PACKING + call % PACKING
}
pub(crate) const fn final_index(row_base: usize, call: usize, lane: usize) -> usize {
    (row_base + (call / PACKING) * ROWS_PER_GROUP + WIDTH + SBOX_INPUTS + lane) * PACKING
        + call % PACKING
}

/// Complete ordered CSR specification. For an Equal entry emit packed-source=0;
/// for Zero emit packed=0. Constants in source must be normalized into the RHS.
/// Keep all these equations before the final 86 public-input binding rows.
pub(crate) fn source_bindings<W: Copy>(
    calls: &[PackedPoseidonCall<W>],
    row_base: usize,
) -> Result<Vec<Binding<W>>, Error> {
    if calls.len() != LIVE_CALLS {
        return Err(Error::WrongCallCount {
            expected: LIVE_CALLS,
            actual: calls.len(),
        });
    }
    let mut out = Vec::with_capacity(LIVE_IO_BINDINGS + DUMMY_ZERO_BINDINGS);
    for (call, wires) in calls.iter().enumerate() {
        for lane in 0..WIDTH {
            out.push(Binding::Equal {
                packed_index: initial_index(row_base, call, lane),
                source: wires.input[lane],
            });
            out.push(Binding::Equal {
                packed_index: final_index(row_base, call, lane),
                source: wires.output[lane],
            });
        }
    }
    for call in LIVE_CALLS..PADDED_CALLS {
        for lane in 0..WIDTH {
            out.push(Binding::Zero {
                packed_index: initial_index(row_base, call, lane),
            });
        }
    }
    Ok(out)
}

/// A trace is 16 initial words, then 150 S-box input words in native round order,
/// then 16 raw permutation output words. All values are canonical Goldilocks.
pub(crate) fn native_trace(input: [u64; WIDTH]) -> Result<[u64; ROWS_PER_GROUP], Error> {
    build_smallwood_poseidon2_v8_single_call_trace(input)
}

/// Pack already evaluated call traces. The graph evaluator obtains every trace
/// from native_trace when it reaches output lane zero, caches it, and appends the
/// remaining output lanes without accepting witness-authored output values.
pub(crate) fn pack_traces(traces: &[[u64; ROWS_PER_GROUP]]) -> Result<Vec<[u64; PACKING]>, Error> {
    if traces.len() != LIVE_CALLS {
        return Err(Error::WrongCallCount {
            expected: LIVE_CALLS,
            actual: traces.len(),
        });
    }
    for (call, trace) in traces.iter().enumerate() {
        for (row, value) in trace.iter().enumerate() {
            if *value >= hegemon_field::GOLDILOCKS_MODULUS {
                return Err(Error::NonCanonicalRow {
                    row: (call / PACKING) * ROWS_PER_GROUP + row,
                    lane: call % PACKING,
                });
            }
        }
    }
    let dummy = native_trace([0; WIDTH])?;
    let mut rows = vec![[0u64; PACKING]; ROWS];
    for call in 0..PADDED_CALLS {
        let trace = if call < LIVE_CALLS {
            &traces[call]
        } else {
            &dummy
        };
        for row in 0..ROWS_PER_GROUP {
            rows[(call / PACKING) * ROWS_PER_GROUP + row][call % PACKING] = trace[row];
        }
    }
    Ok(rows)
}

pub(crate) fn build_rows(inputs: &[[u64; WIDTH]]) -> Result<Vec<[u64; PACKING]>, Error> {
    if inputs.len() != LIVE_CALLS {
        return Err(Error::WrongCallCount {
            expected: LIVE_CALLS,
            actual: inputs.len(),
        });
    }
    let traces = inputs
        .iter()
        .copied()
        .map(native_trace)
        .collect::<Result<Vec<_>, _>>()?;
    pack_traces(&traces)
}

/// One scalar per packed row, evaluated at an arbitrary SmallWood point. This
/// is not a witness-only test: these identities must enter the prover/verifier.
pub(crate) fn evaluate_group<R: PrimeCharacteristicRing>(
    rows: &[R],
    out: &mut [R],
) -> Result<(), Error> {
    evaluate_smallwood_poseidon2_v8_single_group_constraints_ring(rows, out)
}

pub(crate) fn evaluate_all<R: PrimeCharacteristicRing>(
    rows: &[R],
    out: &mut [R],
) -> Result<(), Error> {
    if rows.len() != ROWS {
        return Err(Error::WrongLaneRowCount {
            expected: ROWS,
            actual: rows.len(),
        });
    }
    if out.len() != CONSTRAINTS {
        return Err(Error::WrongConstraintCount {
            expected: CONSTRAINTS,
            actual: out.len(),
        });
    }
    for group in 0..GROUPS {
        evaluate_group(
            &rows[group * ROWS_PER_GROUP..(group + 1) * ROWS_PER_GROUP],
            &mut out[group * CONSTRAINTS_PER_GROUP..(group + 1) * CONSTRAINTS_PER_GROUP],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use transaction_core::poseidon2_width16::{poseidon2_width16_permutation_ring, Felt};

    #[test]
    fn packed128_native_outputs_and_constraints() {
        let inputs: Vec<[u64; WIDTH]> = (0..LIVE_CALLS)
            .map(|call| core::array::from_fn(|lane| (call * WIDTH + lane + 1) as u64))
            .collect();
        let rows = build_rows(&inputs).unwrap();
        for (call, input) in inputs.iter().enumerate() {
            let mut native = input.map(Felt::from_u64);
            poseidon2_width16_permutation_ring(&mut native);
            for lane in 0..WIDTH {
                let index = final_index(0, call, lane);
                assert_eq!(
                    rows[index / PACKING][index % PACKING],
                    native[lane].as_canonical_u64()
                );
            }
        }
        for lane in 0..PACKING {
            let scalars: Vec<Felt> = rows.iter().map(|row| Felt::from_u64(row[lane])).collect();
            let mut out = vec![Felt::ZERO; CONSTRAINTS];
            evaluate_all(&scalars, &mut out).unwrap();
            assert!(out.iter().all(|x| *x == Felt::ZERO));
        }
        // Corrupt one S-box input of the last live call; its identity must fail.
        let lane = (LIVE_CALLS - 1) % PACKING;
        let mut scalars: Vec<Felt> = rows.iter().map(|row| Felt::from_u64(row[lane])).collect();
        scalars[(GROUPS - 1) * ROWS_PER_GROUP + WIDTH] += Felt::ONE;
        let mut out = vec![Felt::ZERO; CONSTRAINTS];
        evaluate_all(&scalars, &mut out).unwrap();
        assert!(out.iter().any(|x| *x != Felt::ZERO));
    }

    #[test]
    fn packed128_binding_inventory_and_dummy_constraints() {
        let calls: Vec<_> = (0..LIVE_CALLS)
            .map(|call| PackedPoseidonCall {
                input: core::array::from_fn(|i| call * 32 + i),
                output: core::array::from_fn(|i| call * 32 + 16 + i),
            })
            .collect();
        let bindings = source_bindings(&calls, 17).unwrap();
        assert_eq!(bindings.len(), 4096);
        assert_eq!(
            bindings
                .iter()
                .filter(|x| matches!(x, Binding::Zero { .. }))
                .count(),
            0
        );
        assert_eq!(
            bindings[0],
            Binding::Equal {
                packed_index: 17 * 64,
                source: 0
            }
        );
        assert_eq!(bindings[4095], Binding::Equal { packed_index: (17 + 182 + 181) * 64 + 63, source: 4095 });
        assert!(source_bindings(&calls[..127], 17).is_err());
    }
}
