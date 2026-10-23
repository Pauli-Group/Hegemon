//! Independent ordered CSR inventory for the frozen compact SHA layout.
//! This reconstructs linear equations only; it does not certify nonlinear SHA.
use super::compact_sha256::{Linear, Variable};

const P: u64 = 18_446_744_069_414_584_321;
const BASE: u64 = 1u64 << 32;
const ROWS: usize = 297;
const A: usize = 0;
const B: usize = 32;
const C: usize = 64;
const E: usize = 96;
const F: usize = 128;
const G: usize = 160;
const D: usize = 192;
const H: usize = 193;
const NEXT_A: usize = 194;
const NEXT_E: usize = 195;
const W: usize = 196;
const W_MINUS_2: usize = 228;
const W_MINUS_15: usize = 260;
const W_MINUS_7: usize = 292;
const W_MINUS_16: usize = 293;
const CARRY_W: usize = 296;
const INITIAL: [u64; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn cell(row: usize, lane: usize) -> Variable {
    Variable::Cell(row, lane)
}

// The first sixteen lanes of the early W[t-15] rows hold final-state data.
fn saved(index: usize) -> Variable {
    cell(W_MINUS_15 + index / 16, index % 16)
}

fn negative(value: u64) -> u64 {
    if value == 0 {
        0
    } else {
        P - value
    }
}

/// Sort and coalesce a flat list, independently of the producer's BTreeMap.
/// Preserve even empty equations: their position is part of the inventory.
fn emit(out: &mut Vec<Linear>, mut terms: Vec<(Variable, u64)>, target: u64) {
    terms.sort_unstable_by_key(|entry| entry.0);
    let mut normalized: Vec<(Variable, u64)> = Vec::with_capacity(terms.len());
    for (variable, coefficient) in terms {
        assert!(coefficient < P);
        if let Some(last) = normalized.last_mut() {
            if last.0 == variable {
                last.1 = ((last.1 as u128 + coefficient as u128) % P as u128) as u64;
                continue;
            }
        }
        normalized.push((variable, coefficient));
    }
    normalized.retain(|entry| entry.1 != 0);
    out.push(Linear {
        terms: normalized,
        target,
    });
}

fn pin(out: &mut Vec<Linear>, variable: Variable, value: u64) {
    emit(out, vec![(variable, 1)], value);
}

fn same(out: &mut Vec<Linear>, destination: Variable, source: Variable) {
    emit(out, vec![(destination, 1), (source, P - 1)], 0);
}

fn word(base: usize, lane: usize) -> Vec<(Variable, u64)> {
    (0..32)
        .map(|bit| (cell(base + bit, lane), 1u64 << bit))
        .collect()
}

fn saved_word(first: usize) -> Vec<(Variable, u64)> {
    (0..32)
        .map(|bit| (saved(first + bit), 1u64 << bit))
        .collect()
}

fn reconstruct(out: &mut Vec<Linear>, destination: Variable, bits: Vec<(Variable, u64)>) {
    let mut terms = Vec::with_capacity(bits.len() + 1);
    terms.push((destination, 1));
    terms.extend(
        bits.into_iter()
            .map(|(variable, weight)| (variable, negative(weight))),
    );
    emit(out, terms, 0);
}

pub(super) fn linear_constraints(packing: usize) -> Vec<super::compact_sha256::Linear> {
    assert!(
        (64..=1024).contains(&packing),
        "compact SHA certificate packing"
    );
    let mut equations = Vec::new();
    for round in 0..64 {
        // A/E are reconstructed from the preceding round's next-state words.
        for (base, next, initial) in [(A, NEXT_A, INITIAL[0]), (E, NEXT_E, INITIAL[4])] {
            if round == 0 {
                for bit in 0..32 {
                    pin(
                        &mut equations,
                        cell(base + bit, round),
                        (initial >> bit) & 1,
                    );
                }
            } else {
                reconstruct(&mut equations, cell(next, round - 1), word(base, round));
            }
        }
        // The remaining bit-sliced state words shift by one round.
        for (destination, source, initial) in [
            (B, A, INITIAL[1]),
            (C, B, INITIAL[2]),
            (F, E, INITIAL[5]),
            (G, F, INITIAL[6]),
        ] {
            for bit in 0..32 {
                if round == 0 {
                    pin(
                        &mut equations,
                        cell(destination + bit, round),
                        (initial >> bit) & 1,
                    );
                } else {
                    same(
                        &mut equations,
                        cell(destination + bit, round),
                        cell(source + bit, round - 1),
                    );
                }
            }
        }
        for (destination, source, initial) in [(D, C, INITIAL[3]), (H, G, INITIAL[7])] {
            if round == 0 {
                pin(&mut equations, cell(destination, round), initial);
            } else {
                reconstruct(
                    &mut equations,
                    cell(destination, round),
                    word(source, round - 1),
                );
            }
        }
        for bit in 0..32 {
            if round < 8 {
                // External bits are byte-wise LE; SHA's message words are BE.
                let input_bit = (round * 4 + 3 - bit / 8) * 8 + bit % 8;
                same(
                    &mut equations,
                    cell(W + bit, round),
                    Variable::InputBit(input_bit),
                );
            } else if round < 16 {
                let padding: u64 = match round {
                    8 => 0x80000000,
                    15 => 256,
                    _ => 0,
                };
                pin(&mut equations, cell(W + bit, round), (padding >> bit) & 1);
            }
            for (destination, distance) in [(W_MINUS_2, 2), (W_MINUS_15, 15)] {
                if round >= 16 {
                    same(
                        &mut equations,
                        cell(destination + bit, round),
                        cell(W + bit, round - distance),
                    );
                } else {
                    let reserved_final_state = destination == W_MINUS_15 && bit * 16 + round < 328;
                    if !reserved_final_state {
                        pin(&mut equations, cell(destination + bit, round), 0);
                    }
                }
            }
        }
        for (destination, distance) in [(W_MINUS_7, 7), (W_MINUS_16, 16)] {
            if round >= 16 {
                reconstruct(
                    &mut equations,
                    cell(destination, round),
                    word(W, round - distance),
                );
            } else {
                pin(&mut equations, cell(destination, round), 0);
            }
        }
        if round < 16 {
            pin(&mut equations, cell(CARRY_W, round), 0);
        }
    }
    reconstruct(&mut equations, cell(NEXT_A, 63), saved_word(0));
    reconstruct(&mut equations, cell(NEXT_E, 63), saved_word(32));
    for digest in 0..8 {
        let final_state = match digest {
            0 => saved_word(0),
            1 => word(A, 63),
            2 => word(B, 63),
            3 => word(C, 63),
            4 => saved_word(32),
            5 => word(E, 63),
            6 => word(F, 63),
            _ => word(G, 63),
        };
        reconstruct(
            &mut equations,
            Variable::DigestWord(digest),
            saved_word(64 + digest * 32),
        );
        let mut terms = vec![(saved(320 + digest), BASE)];
        for bit in 0..32 {
            let byte_reversed_bit = (3 - bit / 8) * 8 + bit % 8;
            terms.push((saved(64 + digest * 32 + bit), 1u64 << byte_reversed_bit));
        }
        terms.extend(
            final_state
                .into_iter()
                .map(|(variable, weight)| (variable, negative(weight))),
        );
        emit(&mut equations, terms, INITIAL[digest]);
    }
    for row in 0..ROWS {
        for lane in 64..packing {
            pin(&mut equations, cell(row, lane), 0);
        }
    }
    equations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_compact_sha_inventory_matches_frozen_producer_k64_k67() {
        for packing in [64, 67] {
            let producer = super::super::compact_sha256::Layout::new(packing).unwrap();
            assert_eq!(linear_constraints(packing), producer.linear_constraints());
        }
    }
}
