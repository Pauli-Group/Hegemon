//! Candidate compact exact-32-byte SHA-256 relation, not an accepted proof mode.
//!64 real rounds are packing lanes. Every copy/range/IO/padding rule is emitted.
//! Public packing points MUST be exactly0..packing-1, as SmallwoodConfig uses.
//! Witness generation may use word operations; verification uses field polynomials.
#![forbid(unsafe_code)]
const P: u64 = 18446744069414584321;
const B: u64 = 1u64 << 32;
pub const TRACE_ROWS: usize = 297;
pub const CONSTRAINTS: usize = 294;
pub const MAX_DEGREE: usize = 7;
const INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn add(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % P as u128) as u64
}
fn sub(a: u64, b: u64) -> u64 {
    ((a as u128 + P as u128 - b as u128) % P as u128) as u64
}
fn mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % P as u128) as u64
}
fn pow(mut a: u64, mut n: u64) -> u64 {
    let mut r = 1;
    while n > 0 {
        if n & 1 != 0 {
            r = mul(r, a);
        }
        a = mul(a, a);
        n >>= 1;
    }
    r
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variable {
    Cell(usize, usize),
    InputBit(usize),
    DigestWord(usize),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Linear {
    pub terms: Vec<(Variable, u64)>,
    pub target: u64,
}
/// No Debug/serde: this carries private witness bits.
pub struct Trace {
    pub rows: Vec<Vec<u64>>,
}
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub packing: usize,
}
const A: usize = 0;
const BB: usize = 32;
const C: usize = 64;
const E: usize = 96;
const F: usize = 128;
const G: usize = 160;
const D: usize = 192;
const H: usize = 193;
const NA: usize = 194;
const NE: usize = 195;
const W: usize = 196;
const W2: usize = 228;
const W15: usize = 260;
const W7: usize = 292;
const W16: usize = 293;
const CA: usize = 294;
const CE: usize = 295;
const CW: usize = 296;
fn cell(row: usize, lane: usize) -> Variable {
    Variable::Cell(row, lane)
}
fn stash(i: usize) -> Variable {
    cell(W15 + i / 16, i % 16)
}
fn word_terms(row: usize, lane: usize) -> Vec<(Variable, u64)> {
    (0..32).map(|b| (cell(row + b, lane), 1u64 << b)).collect()
}
fn stash_terms(first: usize) -> Vec<(Variable, u64)> {
    (0..32).map(|b| (stash(first + b), 1u64 << b)).collect()
}
fn equation(out: &mut Vec<Linear>, terms: Vec<(Variable, u64)>, target: u64) {
    let mut map = std::collections::BTreeMap::new();
    for (v, c) in terms {
        let old = map.get(&v).copied().unwrap_or(0);
        map.insert(v, add(old, c));
    }
    out.push(Linear {
        terms: map.into_iter().filter(|(_, c)| *c != 0).collect(),
        target,
    });
}
fn copy(out: &mut Vec<Linear>, a: Variable, b: Variable) {
    equation(out, vec![(a, 1), (b, P - 1)], 0);
}
fn pin(out: &mut Vec<Linear>, a: Variable, value: u64) {
    equation(out, vec![(a, 1)], value);
}
fn weighted_copy(out: &mut Vec<Linear>, a: Variable, terms: Vec<(Variable, u64)>) {
    let mut t = vec![(a, 1)];
    t.extend(terms.into_iter().map(|(v, c)| (v, sub(0, c))));
    equation(out, t, 0);
}
fn bits(value: u32, bit: usize) -> u64 {
    u64::from((value >> bit) & 1)
}
fn parity(a: u64, b: u64, c: u64) -> u64 {
    add(
        sub(
            add(add(a, b), c),
            mul(2, add(add(mul(a, b), mul(a, c)), mul(b, c))),
        ),
        mul(4, mul(mul(a, b), c)),
    )
}
fn maj(a: u64, b: u64, c: u64) -> u64 {
    sub(
        add(add(mul(a, b), mul(a, c)), mul(b, c)),
        mul(2, mul(mul(a, b), c)),
    )
}
fn sum_bits(rows: &[u64], base: usize) -> u64 {
    (0..32).fold(0, |s, b| add(s, mul(1u64 << b, rows[base + b])))
}
fn sigma(rows: &[u64], base: usize, x: usize, y: usize, z: usize, shift: bool) -> u64 {
    (0..32).fold(0, |s, b| {
        let c = if shift {
            if b + z < 32 {
                rows[base + b + z]
            } else {
                0
            }
        } else {
            rows[base + (b + z) % 32]
        };
        add(
            s,
            mul(
                1u64 << b,
                parity(rows[base + (b + x) % 32], rows[base + (b + y) % 32], c),
            ),
        )
    })
}
fn range_poly(v: u64, max: u64) -> u64 {
    (0..=max).fold(1, |p, k| mul(p, sub(v, k)))
}
impl Layout {
    pub fn new(packing: usize) -> Result<Self, &'static str> {
        if !(64..=1024).contains(&packing) {
            return Err("compact SHA requires64..1024 consecutive packing points");
        }
        Ok(Self { packing })
    }
    /// Exact public degree packing-1 polynomial, not a prover-chosen constant column.
    fn round_constant(&self, x: u64) -> u64 {
        if x < (self.packing as u64) {
            return if x < 64 { u64::from(K[x as usize]) } else { 0 };
        }
        let mut acc = 0;
        for (i, k) in K.iter().enumerate() {
            let mut n = 1;
            let mut d = 1;
            for j in 0..self.packing {
                if i != j {
                    n = mul(n, sub(x, j as u64));
                    d = mul(d, sub(i as u64, j as u64));
                }
            }
            acc = add(acc, mul(u64::from(*k), mul(n, pow(d, P - 2))));
        }
        acc
    }
    pub fn linear_constraints(&self) -> Vec<Linear> {
        let mut out = Vec::new();
        for t in 0..64 {
            for (row, iv) in [(A, INITIAL[0]), (E, INITIAL[4])] {
                if t == 0 {
                    for b in 0..32 {
                        pin(&mut out, cell(row + b, t), bits(iv, b));
                    }
                } else {
                    weighted_copy(
                        &mut out,
                        cell(if row == A { NA } else { NE }, t - 1),
                        word_terms(row, t),
                    );
                }
            }
            for (dst, src, iv) in [
                (BB, A, INITIAL[1]),
                (C, BB, INITIAL[2]),
                (F, E, INITIAL[5]),
                (G, F, INITIAL[6]),
            ] {
                for b in 0..32 {
                    if t == 0 {
                        pin(&mut out, cell(dst + b, t), bits(iv, b));
                    } else {
                        copy(&mut out, cell(dst + b, t), cell(src + b, t - 1));
                    }
                }
            }
            for (dst, src, iv) in [(D, C, INITIAL[3]), (H, G, INITIAL[7])] {
                if t == 0 {
                    pin(&mut out, cell(dst, t), u64::from(iv));
                } else {
                    weighted_copy(&mut out, cell(dst, t), word_terms(src, t - 1));
                }
            }
            for b in 0..32 {
                if t < 8 {
                    copy(
                        &mut out,
                        cell(W + b, t),
                        Variable::InputBit((t * 4 + 3 - b / 8) * 8 + b % 8),
                    );
                } else if t < 16 {
                    let v = if t == 8 {
                        0x80000000
                    } else if t == 15 {
                        256
                    } else {
                        0
                    };
                    pin(&mut out, cell(W + b, t), bits(v, b));
                }
                for (dst, lag) in [(W2, 2), (W15, 15)] {
                    if t >= 16 {
                        copy(&mut out, cell(dst + b, t), cell(W + b, t - lag));
                    } else if !(dst == W15 && b * 16 + t < 328) {
                        pin(&mut out, cell(dst + b, t), 0);
                    }
                }
            }
            for (dst, lag) in [(W7, 7), (W16, 16)] {
                if t >= 16 {
                    weighted_copy(&mut out, cell(dst, t), word_terms(W, t - lag));
                } else {
                    pin(&mut out, cell(dst, t), 0);
                }
            }
            if t < 16 {
                pin(&mut out, cell(CW, t), 0);
            }
        }
        weighted_copy(&mut out, cell(NA, 63), stash_terms(0));
        weighted_copy(&mut out, cell(NE, 63), stash_terms(32));
        for i in 0..8 {
            let final_terms = match i {
                0 => stash_terms(0),
                4 => stash_terms(32),
                1 => word_terms(A, 63),
                2 => word_terms(BB, 63),
                3 => word_terms(C, 63),
                5 => word_terms(E, 63),
                6 => word_terms(F, 63),
                _ => word_terms(G, 63),
            };
            weighted_copy(&mut out, Variable::DigestWord(i), stash_terms(64 + i * 32));
            let mut terms = vec![(stash(320 + i), B)];
            // SHA addition is internal BE-u32 order; public digest groups are LE-u32.
            terms.extend(
                (0..32).map(|b| (stash(64 + i * 32 + b), 1u64 << ((3 - b / 8) * 8 + b % 8))),
            );
            terms.extend(final_terms.into_iter().map(|(v, c)| (v, sub(0, c))));
            equation(&mut out, terms, u64::from(INITIAL[i]));
        }
        for r in 0..TRACE_ROWS {
            for lane in 64..self.packing {
                pin(&mut out, cell(r, lane), 0);
            }
        }
        out
    }
    pub fn compute_constraints(
        &self,
        x: u64,
        rows: &[u64],
        out: &mut [u64],
    ) -> Result<(), &'static str> {
        if rows.len() != TRACE_ROWS || out.len() != CONSTRAINTS {
            return Err("compact SHA constraint shape");
        }
        let mut n = 0;
        for base in [A, BB, C, E, F, G, W, W2, W15] {
            for b in 0..32 {
                out[n] = mul(rows[base + b], sub(rows[base + b], 1));
                n += 1;
            }
        }
        let rm = (64..self.packing).fold(1, |p, k| mul(p, sub(x, k as u64)));
        let sm = (0..16).fold(rm, |p, k| mul(p, sub(x, k)));
        let se = sigma(rows, E, 6, 11, 25, false);
        let sa = sigma(rows, A, 2, 13, 22, false);
        let ch = (0..32).fold(0, |s, b| {
            add(
                s,
                mul(
                    1u64 << b,
                    add(
                        mul(rows[E + b], rows[F + b]),
                        mul(sub(1, rows[E + b]), rows[G + b]),
                    ),
                ),
            )
        });
        let mj = (0..32).fold(0, |s, b| {
            add(
                s,
                mul(1u64 << b, maj(rows[A + b], rows[BB + b], rows[C + b])),
            )
        });
        let t1 = add(
            add(add(add(rows[H], se), ch), self.round_constant(x)),
            sum_bits(rows, W),
        );
        out[n] = mul(
            rm,
            sub(sub(add(add(t1, sa), mj), rows[NA]), mul(B, rows[CA])),
        );
        n += 1;
        out[n] = mul(rm, sub(sub(add(rows[D], t1), rows[NE]), mul(B, rows[CE])));
        n += 1;
        out[n] = range_poly(rows[CA], 6);
        n += 1;
        out[n] = range_poly(rows[CE], 5);
        n += 1;
        let ws = add(
            add(sigma(rows, W2, 17, 19, 10, true), rows[W7]),
            add(sigma(rows, W15, 7, 18, 3, true), rows[W16]),
        );
        out[n] = mul(sm, sub(sub(ws, sum_bits(rows, W)), mul(B, rows[CW])));
        n += 1;
        out[n] = range_poly(rows[CW], 3);
        n += 1;
        debug_assert_eq!(n, CONSTRAINTS);
        Ok(())
    }
    pub fn evaluate(&self, input: &[u8; 32]) -> (Trace, [u64; 8]) {
        let mut trace = Trace {
            rows: vec![vec![0; self.packing]; TRACE_ROWS],
        };
        let mut w = [0u32; 64];
        for i in 0..8 {
            w[i] = u32::from_be_bytes(input[i * 4..i * 4 + 4].try_into().unwrap());
        }
        w[8] = 0x80000000;
        w[15] = 256;
        let mut schedule_carry = [0u64; 64];
        for t in 16..64 {
            let a = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let b = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
            let sum = u64::from(a) + u64::from(b) + u64::from(w[t - 7]) + u64::from(w[t - 16]);
            w[t] = sum as u32;
            schedule_carry[t] = sum >> 32;
        }
        let mut state = INITIAL;
        for t in 0..64 {
            let [a, b, c, d, e, f, g, h] = state;
            for (base, value) in [(A, a), (BB, b), (C, c), (E, e), (F, f), (G, g), (W, w[t])] {
                for bit in 0..32 {
                    trace.rows[base + bit][t] = bits(value, bit);
                }
            }
            for (base, lag) in [(W2, 2), (W15, 15)] {
                if t >= 16 {
                    for bit in 0..32 {
                        trace.rows[base + bit][t] = bits(w[t - lag], bit);
                    }
                }
            }
            trace.rows[D][t] = u64::from(d);
            trace.rows[H][t] = u64::from(h);
            if t >= 16 {
                trace.rows[W7][t] = u64::from(w[t - 7]);
                trace.rows[W16][t] = u64::from(w[t - 16]);
            }
            trace.rows[CW][t] = schedule_carry[t];
            let se = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let sa = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let ch = (e & f) ^ (!e & g);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t1 =
                u64::from(h) + u64::from(se) + u64::from(ch) + u64::from(K[t]) + u64::from(w[t]);
            let na = t1 + u64::from(sa) + u64::from(majority);
            let ne = t1 + u64::from(d);
            trace.rows[NA][t] = u64::from(na as u32);
            trace.rows[NE][t] = u64::from(ne as u32);
            trace.rows[CA][t] = na >> 32;
            trace.rows[CE][t] = ne >> 32;
            state = [na as u32, a, b, c, ne as u32, e, f, g];
        }
        let mut words = [0; 8];
        let mut put = |i: usize, v: u64| {
            if let Variable::Cell(r, l) = stash(i) {
                trace.rows[r][l] = v;
            }
        };
        for b in 0..32 {
            put(b, bits(state[0], b));
            put(32 + b, bits(state[4], b));
        }
        for i in 0..8 {
            let sum = u64::from(INITIAL[i]) + u64::from(state[i]);
            let digest = sum as u32;
            words[i] = u64::from(u32::from_le_bytes(digest.to_be_bytes()));
            // External digest words are LE groups of four output bytes, matching sha().
            let internal_digest = words[i] as u32;
            for b in 0..32 {
                put(64 + i * 32 + b, bits(internal_digest, b));
            }
            put(320 + i, sum >> 32);
        }
        (trace, words)
    }
    pub fn verify(
        &self,
        trace: &Trace,
        input_bits: &[u64; 256],
        digest_words: &[u64; 8],
    ) -> Result<(), &'static str> {
        if trace.rows.len() != TRACE_ROWS
            || trace
                .rows
                .iter()
                .any(|r| r.len() != self.packing || r.iter().any(|v| *v >= P))
            || input_bits.iter().chain(digest_words).any(|v| *v >= P)
        {
            return Err("compact SHA witness shape/canonicality");
        }
        let read = |v: Variable| match v {
            Variable::Cell(r, l) => trace.rows[r][l],
            Variable::InputBit(i) => input_bits[i],
            Variable::DigestWord(i) => digest_words[i],
        };
        for eq in self.linear_constraints() {
            if eq
                .terms
                .iter()
                .fold(0, |s, (v, c)| add(s, mul(read(*v), *c)))
                != eq.target
            {
                return Err("compact SHA linear/copy equation");
            }
        }
        let mut out = vec![0; CONSTRAINTS];
        for lane in 0..self.packing {
            let rows = trace.rows.iter().map(|r| r[lane]).collect::<Vec<_>>();
            self.compute_constraints(lane as u64, &rows, &mut out)?;
            if out.iter().any(|v| *v != 0) {
                return Err("compact SHA nonlinear equation");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn input_bits(input: &[u8; 32]) -> [u64; 256] {
        core::array::from_fn(|i| u64::from((input[i / 8] >> (i % 8)) & 1))
    }
    #[test]
    fn compact_word_sha_matches_sha256_and_preserves_endian() {
        let mut one = [0; 32];
        one[0] = 1;
        for packing in [64, 67] {
            let layout = Layout::new(packing).unwrap();
            for input in [[0; 32], [255; 32], core::array::from_fn(|i| i as u8), one] {
                let (trace, words) = layout.evaluate(&input);
                let expected = Sha256::digest(input);
                let wanted: [u64; 8] = core::array::from_fn(|i| {
                    u64::from(u32::from_le_bytes(
                        expected[i * 4..i * 4 + 4].try_into().unwrap(),
                    ))
                });
                assert_eq!(words, wanted);
                layout.verify(&trace, &input_bits(&input), &words).unwrap();
            }
        }
    }
    #[test]
    fn compact_word_sha_rejects_tampering_nonboolean_carries_io_and_padding() {
        for packing in [64, 67] {
            let layout = Layout::new(packing).unwrap();
            let input = core::array::from_fn(|i| i as u8);
            let (mut trace, words) = layout.evaluate(&input);
            let bits = input_bits(&input);
            for (r, l) in [
                (A, 0),
                (BB, 31),
                (E + 31, 63),
                (NA, 12),
                (W, 0),
                (W + 31, 15),
                (W2, 17),
                (W15, 0),
                (W15 + 17, 0),
                (W15 + 20, 7),
                (CA, 4),
                (CE, 12),
                (CW, 25),
            ] {
                let old = trace.rows[r][l];
                trace.rows[r][l] = add(old, 1);
                assert!(
                    layout.verify(&trace, &bits, &words).is_err(),
                    "undetected cell{r}/{l}"
                );
                trace.rows[r][l] = old;
            }
            if packing > 64 {
                trace.rows[H][66] = 1;
                assert!(layout.verify(&trace, &bits, &words).is_err());
                trace.rows[H][66] = 0;
            }
            let mut wrongbits = bits;
            wrongbits[0] = 2;
            assert!(layout.verify(&trace, &wrongbits, &words).is_err());
            let mut wrongwords = words;
            wrongwords[7] = add(wrongwords[7], 1);
            assert!(layout.verify(&trace, &bits, &wrongwords).is_err());
        }
    }
    #[test]
    fn public_masks_have_exact_grid_support_and_degree_budget() {
        for packing in [64, 67] {
            let l = Layout::new(packing).unwrap();
            for x in 0..packing {
                let rm = (64..packing).fold(1, |p, k| mul(p, sub(x as u64, k as u64)));
                let sm = (0..16).fold(rm, |p, k| mul(p, sub(x as u64, k)));
                assert_eq!(rm == 0, x >= 64);
                assert_eq!(sm == 0, x < 16 || x >= 64);
                assert_eq!(
                    l.round_constant(x as u64),
                    if x < 64 { u64::from(K[x]) } else { 0 }
                );
            }
            let degree = packing + 5;
            assert!(3 * degree + (packing - 64) + 16 <= 7 * degree);
        }
    }
}
