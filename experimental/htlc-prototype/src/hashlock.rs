//! Fixed 32-byte SHA-256 bit circuit, independently evaluated and checked.
//! This is a Boolean constraint IR, not a compiled RP05/QIR program or proof.

type Wire = usize;
type Word = [Wire; 32]; // Least significant bit first.

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

#[derive(Clone, Copy, Debug)]
pub enum BooleanGate {
    Constant(u8),
    Not(Wire),
    Xor(Wire, Wire),
    And(Wire, Wire),
    Parity(Wire, Wire, Wire),
    Majority(Wire, Wire, Wire),
}

type Op = BooleanGate;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConstraintError {
    AssignmentLength,
    NonBoolean(Wire),
    InputPin(usize),
    OutputPin(usize),
    Gate(usize),
}

/// One equation per gate, one Boolean-domain constraint per assignment wire,
/// and 256 input/256 output pin equations. No proof-system cost is implied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    pub wires: usize,
    pub constants: usize,
    pub not: usize,
    pub xor: usize,
    pub and: usize,
    pub parity: usize,
    pub majority: usize,
    pub gate_equations: usize,
    pub boolean_constraints: usize,
    pub input_pins: usize,
    pub output_pins: usize,
    pub total_constraints: usize,
}

/// Constructed circuit topology is independent of the preimage or digest.
/// The first 256 wires are input byte bits (least significant bit first).
/// Gate i always defines wire 256+i. All fields are private to prevent callers
/// from deleting constraints or replacing the pinned output topology.
pub struct Sha256Hashlock {
    gates: Vec<Op>,
    outputs: [Wire; 256],
}

impl Default for Sha256Hashlock {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Hashlock {
    /// Read-only fixed topology for independent proof-backend lowering.
    /// Gate i defines canonical wire 256+i; inputs remain existential/private
    /// when the lowering does not install the host checker's input pins.
    pub fn gates(&self) -> &[BooleanGate] {
        &self.gates
    }

    pub fn output_wires(&self) -> &[usize; 256] {
        &self.outputs
    }

    pub fn new() -> Self {
        let mut b = Builder {
            gates: Vec::new(),
            zero: 0,
            one: 0,
        };
        b.zero = b.push(Op::Constant(0));
        b.one = b.push(Op::Constant(1));
        let mut w = [b.word(0); 64];
        for (i, word) in w.iter_mut().enumerate().take(8) {
            *word = core::array::from_fn(|bit| (i * 4 + 3 - bit / 8) * 8 + bit % 8);
        }
        // 32 input bytes, then 0x80, 23 zero bytes and 64-bit BE length 256.
        w[8] = b.word(0x80000000);
        w[15] = b.word(256);
        for i in 16..64 {
            let a = b.small_sigma(w[i - 15], 7, 18, 3);
            let c = b.small_sigma(w[i - 2], 17, 19, 10);
            let x = b.add(w[i - 16], a);
            let y = b.add(x, w[i - 7]);
            w[i] = b.add(y, c);
        }
        let initial = INITIAL.map(|x| b.word(x));
        let mut s = initial;
        for i in 0..64 {
            let [a, bb, c, d, e, f, g, h] = s;
            let sigma_e = b.big_sigma(e, 6, 11, 25);
            let choose = core::array::from_fn(|bit| {
                let ef = b.push(Op::And(e[bit], f[bit]));
                let ne = b.push(Op::Not(e[bit]));
                let ng = b.push(Op::And(ne, g[bit]));
                b.push(Op::Xor(ef, ng))
            });
            let x = b.add(h, sigma_e);
            let x = b.add(x, choose);
            let x = b.add(x, b.word(K[i]));
            let t1 = b.add(x, w[i]);
            let sigma_a = b.big_sigma(a, 2, 13, 22);
            let maj = core::array::from_fn(|bit| b.push(Op::Majority(a[bit], bb[bit], c[bit])));
            let t2 = b.add(sigma_a, maj);
            s = [b.add(t1, t2), a, bb, c, b.add(d, t1), e, f, g];
        }
        let digest: [Word; 8] = core::array::from_fn(|i| b.add(initial[i], s[i]));
        let outputs = core::array::from_fn(|bit| {
            let byte = bit / 8;
            digest[byte / 4][(3 - byte % 4) * 8 + bit % 8]
        });
        Self {
            gates: b.gates,
            outputs,
        }
    }

    /// Evaluate only to produce a proposed witness. Verification below does
    /// not invoke this evaluator or sha2, and does not trust derived values.
    pub fn evaluate(&self, preimage: &[u8; 32]) -> Vec<u8> {
        let mut v: Vec<u8> = (0..256).map(|i| (preimage[i / 8] >> (i % 8)) & 1).collect();
        for gate in &self.gates {
            let out = match *gate {
                Op::Constant(x) => x,
                Op::Not(a) => 1 ^ v[a],
                Op::Xor(a, b) => v[a] ^ v[b],
                Op::And(a, b) => v[a] & v[b],
                Op::Parity(a, b, c) => v[a] ^ v[b] ^ v[c],
                Op::Majority(a, b, c) => (v[a] & v[b]) | (v[a] & v[c]) | (v[b] & v[c]),
            };
            v.push(out);
        }
        v
    }

    pub fn digest(&self, assignment: &[u8]) -> Result<[u8; 32], ConstraintError> {
        if assignment.len() != 256 + self.gates.len() {
            return Err(ConstraintError::AssignmentLength);
        }
        let mut bytes = [0; 32];
        for (i, wire) in self.outputs.iter().enumerate() {
            if assignment[*wire] > 1 {
                return Err(ConstraintError::NonBoolean(*wire));
            }
            bytes[i / 8] |= assignment[*wire] << (i % 8);
        }
        Ok(bytes)
    }

    pub fn verify(
        &self,
        preimage: &[u8; 32],
        digest: &[u8; 32],
        assignment: &[u8],
    ) -> Result<(), ConstraintError> {
        self.verify_starting_at(preimage, digest, assignment, 0)
    }

    // Rotating gate traversal preserves the exact accepted relation. Tests
    // start at a mutated wire's defining gate to avoid quadratic negative-test
    // work. Success still checks every gate and every assignment's domain.
    fn verify_starting_at(
        &self,
        preimage: &[u8; 32],
        digest: &[u8; 32],
        v: &[u8],
        first: usize,
    ) -> Result<(), ConstraintError> {
        if v.len() != 256 + self.gates.len() {
            return Err(ConstraintError::AssignmentLength);
        }
        for (i, value) in v.iter().enumerate().take(256) {
            if *value > 1 {
                return Err(ConstraintError::NonBoolean(i));
            }
            if *value != (preimage[i / 8] >> (i % 8)) & 1 {
                return Err(ConstraintError::InputPin(i));
            }
        }
        for (i, wire) in self.outputs.iter().enumerate() {
            if v[*wire] > 1 {
                return Err(ConstraintError::NonBoolean(*wire));
            }
            if v[*wire] != (digest[i / 8] >> (i % 8)) & 1 {
                return Err(ConstraintError::OutputPin(i));
            }
        }
        for i in (first..self.gates.len()).chain(0..first) {
            let out = 256 + i;
            if v[out] > 1 {
                return Err(ConstraintError::NonBoolean(out));
            }
            let val = |wire: Wire| -> i32 { i32::from(v[wire]) };
            let z = val(out);
            // Ordinary integer Boolean polynomials, independently of evaluator.
            // These are IR equations; field lowering/degree must be measured
            // by any future proof backend (parity3 has degree three).
            let residual = match self.gates[i] {
                Op::Constant(x) => z - i32::from(x),
                Op::Not(a) => z + val(a) - 1,
                Op::Xor(a, b) => z - val(a) - val(b) + 2 * val(a) * val(b),
                Op::And(a, b) => z - val(a) * val(b),
                Op::Parity(a, b, c) => {
                    let (a, b, c) = (val(a), val(b), val(c));
                    z - a - b - c + 2 * (a * b + a * c + b * c) - 4 * a * b * c
                }
                Op::Majority(a, b, c) => {
                    let (a, b, c) = (val(a), val(b), val(c));
                    z - a * b - a * c - b * c + 2 * a * b * c
                }
            };
            if residual != 0 {
                return Err(ConstraintError::Gate(i));
            }
        }
        Ok(())
    }

    pub fn counts(&self) -> Counts {
        let mut c = Counts {
            wires: 256 + self.gates.len(),
            constants: 0,
            not: 0,
            xor: 0,
            and: 0,
            parity: 0,
            majority: 0,
            gate_equations: self.gates.len(),
            boolean_constraints: 256 + self.gates.len(),
            input_pins: 256,
            output_pins: 256,
            total_constraints: 0,
        };
        for g in &self.gates {
            match g {
                Op::Constant(_) => c.constants += 1,
                Op::Not(_) => c.not += 1,
                Op::Xor(..) => c.xor += 1,
                Op::And(..) => c.and += 1,
                Op::Parity(..) => c.parity += 1,
                Op::Majority(..) => c.majority += 1,
            }
        }
        c.total_constraints =
            c.gate_equations + c.boolean_constraints + c.input_pins + c.output_pins;
        c
    }
}

struct Builder {
    gates: Vec<Op>,
    zero: Wire,
    one: Wire,
}
impl Builder {
    fn push(&mut self, op: Op) -> Wire {
        let wire = 256 + self.gates.len();
        self.gates.push(op);
        wire
    }
    fn word(&self, x: u32) -> Word {
        core::array::from_fn(|i| {
            if (x >> i) & 1 == 1 {
                self.one
            } else {
                self.zero
            }
        })
    }
    fn rotate(w: Word, n: usize) -> Word {
        core::array::from_fn(|i| w[(i + n) % 32])
    }
    fn xor3(&mut self, a: Word, b: Word, c: Word) -> Word {
        core::array::from_fn(|i| self.push(Op::Parity(a[i], b[i], c[i])))
    }
    fn big_sigma(&mut self, w: Word, a: usize, b: usize, c: usize) -> Word {
        self.xor3(Self::rotate(w, a), Self::rotate(w, b), Self::rotate(w, c))
    }
    fn small_sigma(&mut self, w: Word, a: usize, b: usize, shift: usize) -> Word {
        let shifted = core::array::from_fn(|i| {
            if i + shift < 32 {
                w[i + shift]
            } else {
                self.zero
            }
        });
        self.xor3(Self::rotate(w, a), Self::rotate(w, b), shifted)
    }
    fn add(&mut self, a: Word, b: Word) -> Word {
        let mut carry = self.zero;
        core::array::from_fn(|i| {
            let sum = self.push(Op::Parity(a[i], b[i], carry));
            if i < 31 {
                carry = self.push(Op::Majority(a[i], b[i], carry));
            }
            sum
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn known_and_reproducible_random_vectors() {
        let circuit = Sha256Hashlock::new();
        // Known 32-byte all-zero vector, independently pinned as hex bytes.
        let known = [
            0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, 0x6c, 0x8f, 0xc1, 0x8b, 0x8e, 0x9f,
            0x8e, 0x20, 0x08, 0x97, 0x14, 0x85, 0x6e, 0xe2, 0x33, 0xb3, 0x90, 0x2a, 0x59, 0x1d,
            0x0d, 0x5f, 0x29, 0x25,
        ];
        let mut inputs = vec![
            [0; 32],
            [0xff; 32],
            core::array::from_fn(|i| i as u8),
            [b'a'; 32],
        ];
        let mut rng = 0x2a034b9e6c81d7f0u64;
        for _ in 0..64 {
            inputs.push(core::array::from_fn(|_| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng as u8
            }));
        }
        for (i, preimage) in inputs.iter().enumerate() {
            let witness = circuit.evaluate(preimage);
            let expected: [u8; 32] = Sha256::digest(preimage).into();
            assert_eq!(circuit.digest(&witness).unwrap(), expected, "vector {i}");
            circuit.verify(preimage, &expected, &witness).unwrap();
            if i == 0 {
                assert_eq!(expected, known);
            }
        }
        println!(
            "SHA256 constrained vectors={} counts={:?}",
            inputs.len(),
            circuit.counts()
        );
    }

    #[test]
    fn every_wire_flip_and_non_boolean_assignment_rejects() {
        let circuit = Sha256Hashlock::new();
        let input = core::array::from_fn(|i| i as u8);
        let mut witness = circuit.evaluate(&input);
        let digest = circuit.digest(&witness).unwrap();
        circuit.verify(&input, &digest, &witness).unwrap();
        for wire in 0..witness.len() {
            let old = witness[wire];
            witness[wire] = old ^ 1;
            let first = wire.saturating_sub(256);
            assert!(
                circuit
                    .verify_starting_at(&input, &digest, &witness, first)
                    .is_err(),
                "flip wire {wire}"
            );
            witness[wire] = 2;
            assert!(
                circuit
                    .verify_starting_at(&input, &digest, &witness, first)
                    .is_err(),
                "non-Boolean wire {wire}"
            );
            witness[wire] = old;
        }
        // Also exercise ordinary gate order at representative schedule/round wires.
        for wire in (256..witness.len()).step_by(257) {
            witness[wire] ^= 1;
            assert!(circuit.verify(&input, &digest, &witness).is_err());
            witness[wire] ^= 1;
        }
        println!("exhaustive flipped/non-Boolean wires={}", witness.len());
    }

    #[test]
    fn pins_and_assignment_length_are_binding() {
        let c = Sha256Hashlock::new();
        let input = [7; 32];
        let v = c.evaluate(&input);
        let digest = c.digest(&v).unwrap();
        let mut other = input;
        other[0] ^= 1;
        assert!(matches!(
            c.verify(&other, &digest, &v),
            Err(ConstraintError::InputPin(_))
        ));
        let mut other = digest;
        other[31] ^= 1;
        assert!(matches!(
            c.verify(&input, &other, &v),
            Err(ConstraintError::OutputPin(_))
        ));
        assert_eq!(
            c.verify(&input, &digest, &v[..v.len() - 1]),
            Err(ConstraintError::AssignmentLength)
        );
        let mut extra = v.clone();
        extra.push(0);
        assert_eq!(
            c.verify(&input, &digest, &extra),
            Err(ConstraintError::AssignmentLength)
        );
    }

    #[test]
    fn full_adder_equations_cover_all_boolean_cases() {
        for a in 0u8..2 {
            for b in 0u8..2 {
                for c in 0u8..2 {
                    let sum = a ^ b ^ c;
                    let carry = (a & b) | (a & c) | (b & c);
                    assert_eq!(a + b + c, sum + 2 * carry);
                    let (a, b, c, s, k) = (
                        i32::from(a),
                        i32::from(b),
                        i32::from(c),
                        i32::from(sum),
                        i32::from(carry),
                    );
                    assert_eq!(
                        s - a - b - c + 2 * (a * b + a * c + b * c) - 4 * a * b * c,
                        0
                    );
                    assert_eq!(k - a * b - a * c - b * c + 2 * a * b * c, 0);
                }
            }
        }
    }
}
