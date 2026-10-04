//! Witness-independent Goldilocks row lowering for existential SHA256(secret32).
//!
//! Digest bits are public CSR targets. Input bits stay private canonical wires.
//! All occurrences are copy constrained and all canonical wires Boolean.
//! This module does not generate a proof; the isolated nested backend does.

use crate::hashlock::{BooleanGate, Sha256Hashlock};

pub const MODULUS: u64 = 0xffff_ffff_0000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polynomial {
    Boolean,
    Not,
    Xor,
    And,
    Parity,
    Majority,
}

impl Polynomial {
    fn arity(self) -> usize {
        match self {
            Self::Boolean => 1,
            Self::Not => 2,
            Self::Xor | Self::And => 3,
            Self::Parity | Self::Majority => 4,
        }
    }

    /// Operand order is output, followed by inputs. Evaluation uses field
    /// operations at arbitrary row-polynomial opening points, not Boolean-only
    /// host predicates. Maximum formal degree is three.
    pub fn residual(self, operands: &[u64]) -> u64 {
        let z = operands[0];
        match self {
            Self::Boolean => mul(z, sub(z, 1)),
            Self::Not => sub(add(z, operands[1]), 1),
            Self::Xor => {
                let (a, b) = (operands[1], operands[2]);
                add(sub(sub(z, a), b), mul(2, mul(a, b)))
            }
            Self::And => sub(z, mul(operands[1], operands[2])),
            Self::Parity => {
                let (a, b, c) = (operands[1], operands[2], operands[3]);
                let pairs = add(add(mul(a, b), mul(a, c)), mul(b, c));
                sub(
                    add(sub(sub(sub(z, a), b), c), mul(2, pairs)),
                    mul(4, mul(mul(a, b), c)),
                )
            }
            Self::Majority => {
                let (a, b, c) = (operands[1], operands[2], operands[3]);
                let pairs = add(add(mul(a, b), mul(a, c)), mul(b, c));
                add(sub(z, pairs), mul(2, mul(mul(a, b), c)))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub polynomial: Polynomial,
    pub operand_rows: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub packing_factor: usize,
    pub canonical_wires: usize,
    pub canonical_rows: usize,
    pub canonical_padding: usize,
    pub occurrence_rows: usize,
    pub occurrence_copies: usize,
    pub total_rows: usize,
    pub packed_witness_values: usize,
    pub nonlinear_polynomials: usize,
    pub scalar_gate_equations: usize,
    pub scalar_boolean_equations: usize,
    pub linear_constraints: usize,
    pub maximum_degree: usize,
    pub public_digest_pins: usize,
    pub private_input_pins: usize,
}

/// Circuit topology and CSR arrays depend only on the fixed SHA circuit,
/// selected packing factor, and public digest. Verifier construction needs no
/// preimage, assignment or secret-derived constants.
pub struct HashlockProgram {
    geometry: Geometry,
    digest: [u8; 32],
    batches: Vec<Batch>,
    occurrence_sources: Vec<usize>,
    offsets: Vec<u32>,
    indices: Vec<u32>,
    coefficients: Vec<u64>,
    targets: Vec<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoweringError {
    Packing,
    AssignmentLength,
    NonCanonicalField(usize),
    Linear(usize),
    Nonlinear { batch: usize, lane: usize },
}

impl HashlockProgram {
    pub fn compile(
        circuit: &Sha256Hashlock,
        digest: [u8; 32],
        packing: usize,
    ) -> Result<Self, LoweringError> {
        if !packing.is_power_of_two() || packing > 512 {
            return Err(LoweringError::Packing);
        }
        let canonical_wires = circuit.counts().wires;
        let canonical_rows = canonical_wires.div_ceil(packing);
        let canonical_padded = canonical_rows * packing;
        let mut p = Self {
            geometry: Geometry {
                packing_factor: packing,
                canonical_wires,
                canonical_rows,
                canonical_padding: canonical_padded - canonical_wires,
                occurrence_rows: 0,
                occurrence_copies: 0,
                total_rows: canonical_rows,
                packed_witness_values: 0,
                nonlinear_polynomials: 0,
                scalar_gate_equations: circuit.gates().len(),
                scalar_boolean_equations: canonical_padded,
                linear_constraints: 0,
                maximum_degree: 3,
                public_digest_pins: 256,
                private_input_pins: 0,
            },
            digest,
            batches: Vec::new(),
            occurrence_sources: Vec::new(),
            offsets: vec![0],
            indices: Vec::new(),
            coefficients: Vec::new(),
            targets: Vec::new(),
        };
        for row in 0..canonical_rows {
            p.batches.push(Batch {
                polynomial: Polynomial::Boolean,
                operand_rows: vec![row],
            });
        }
        for wire in canonical_wires..canonical_padded {
            p.linear(&[(wire, 1)], 0);
        }
        let kinds = [
            Polynomial::Not,
            Polynomial::Xor,
            Polynomial::And,
            Polynomial::Parity,
            Polynomial::Majority,
        ];
        let mut groups: [Vec<Vec<usize>>; 5] = core::array::from_fn(|_| Vec::new());
        for (i, gate) in circuit.gates().iter().enumerate() {
            let z = 256 + i;
            let (group, operands) = match *gate {
                BooleanGate::Constant(value) => {
                    p.linear(&[(z, 1)], u64::from(value));
                    continue;
                }
                BooleanGate::Not(a) => (0, vec![z, a]),
                BooleanGate::Xor(a, b) => (1, vec![z, a, b]),
                BooleanGate::And(a, b) => (2, vec![z, a, b]),
                BooleanGate::Parity(a, b, c) => (3, vec![z, a, b, c]),
                BooleanGate::Majority(a, b, c) => (4, vec![z, a, b, c]),
            };
            groups[group].push(operands);
        }
        for (polynomial, group) in kinds.into_iter().zip(groups) {
            for chunk in group.chunks(packing) {
                let start_row = p.geometry.total_rows;
                let arity = polynomial.arity();
                for operand in 0..arity {
                    for lane in 0..packing {
                        // Repeat a real gate for unused lanes. Zero-fill is
                        // invalid for NOT and can alter the proven relation.
                        let source =
                            chunk.get(lane).unwrap_or_else(|| chunk.last().unwrap())[operand];
                        let occurrence = canonical_padded + p.occurrence_sources.len();
                        p.occurrence_sources.push(source);
                        p.linear(&[(occurrence, 1), (source, MODULUS - 1)], 0);
                    }
                }
                p.geometry.total_rows += arity;
                p.batches.push(Batch {
                    polynomial,
                    operand_rows: (start_row..start_row + arity).collect(),
                });
            }
        }
        for (bit, wire) in circuit.output_wires().iter().enumerate() {
            p.linear(&[(*wire, 1)], u64::from((digest[bit / 8] >> (bit % 8)) & 1));
        }
        p.geometry.occurrence_rows = p.geometry.total_rows - canonical_rows;
        p.geometry.occurrence_copies = p.occurrence_sources.len();
        p.geometry.packed_witness_values = p.geometry.total_rows * packing;
        p.geometry.nonlinear_polynomials = p.batches.len();
        p.geometry.linear_constraints = p.targets.len();
        Ok(p)
    }

    fn linear(&mut self, terms: &[(usize, u64)], target: u64) {
        for (index, coefficient) in terms {
            self.indices
                .push(u32::try_from(*index).expect("bounded circuit index"));
            self.coefficients.push(*coefficient);
        }
        self.targets.push(target);
        self.offsets
            .push(u32::try_from(self.indices.len()).expect("bounded circuit CSR"));
    }

    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn batches(&self) -> &[Batch] {
        &self.batches
    }
    pub fn linear_offsets(&self) -> &[u32] {
        &self.offsets
    }
    pub fn linear_indices(&self) -> &[u32] {
        &self.indices
    }
    pub fn linear_coefficients(&self) -> &[u64] {
        &self.coefficients
    }
    pub fn linear_targets(&self) -> &[u64] {
        &self.targets
    }

    pub fn pack(&self, assignment: &[u8]) -> Result<Vec<u64>, LoweringError> {
        if assignment.len() != self.geometry.canonical_wires {
            return Err(LoweringError::AssignmentLength);
        }
        let mut v: Vec<u64> = assignment.iter().copied().map(u64::from).collect();
        v.resize(
            self.geometry.canonical_rows * self.geometry.packing_factor,
            0,
        );
        v.extend(
            self.occurrence_sources
                .iter()
                .map(|source| u64::from(assignment[*source])),
        );
        Ok(v)
    }

    /// Direct equation checking for compiler validation, independently of the
    /// proof engine. A proof verifier never receives this private witness.
    pub fn verify_packed(&self, witness: &[u64]) -> Result<(), LoweringError> {
        if witness.len() != self.geometry.packed_witness_values {
            return Err(LoweringError::AssignmentLength);
        }
        if let Some(i) = witness.iter().position(|value| *value >= MODULUS) {
            return Err(LoweringError::NonCanonicalField(i));
        }
        for (i, target) in self.targets.iter().enumerate() {
            let mut value = 0;
            for term in self.offsets[i] as usize..self.offsets[i + 1] as usize {
                value = add(
                    value,
                    mul(
                        self.coefficients[term],
                        witness[self.indices[term] as usize],
                    ),
                );
            }
            if value != *target {
                return Err(LoweringError::Linear(i));
            }
        }
        for (i, batch) in self.batches.iter().enumerate() {
            for lane in 0..self.geometry.packing_factor {
                let operands: Vec<u64> = batch
                    .operand_rows
                    .iter()
                    .map(|row| witness[row * self.geometry.packing_factor + lane])
                    .collect();
                if batch.polynomial.residual(&operands) != 0 {
                    return Err(LoweringError::Nonlinear { batch: i, lane });
                }
            }
        }
        Ok(())
    }
}

pub fn add(a: u64, b: u64) -> u64 {
    ((u128::from(a) + u128::from(b)) % u128::from(MODULUS)) as u64
}
pub fn sub(a: u64, b: u64) -> u64 {
    ((u128::from(a) + u128::from(MODULUS) - u128::from(b)) % u128::from(MODULUS)) as u64
}
pub fn mul(a: u64, b: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) % u128::from(MODULUS)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_lowering_is_witness_independent_and_exact() {
        let c = Sha256Hashlock::new();
        let a = c.evaluate(&[17; 32]);
        let digest = c.digest(&a).unwrap();
        for packing in [64, 128, 256, 512] {
            let p = HashlockProgram::compile(&c, digest, packing).unwrap();
            let v = p.pack(&a).unwrap();
            p.verify_packed(&v).unwrap();
            assert_eq!(p.geometry.private_input_pins, 0);
            assert_eq!(p.geometry.public_digest_pins, 256);
            assert_eq!(p.geometry.maximum_degree, 3);
            let copy = HashlockProgram::compile(&Sha256Hashlock::new(), digest, packing).unwrap();
            assert_eq!(p.offsets, copy.offsets);
            assert_eq!(p.indices, copy.indices);
            assert_eq!(p.targets, copy.targets);
            assert_eq!(p.batches, copy.batches);
            println!("native hashlock lowering geometry={:?}", p.geometry);
        }
    }

    #[test]
    fn private_lowering_rejects_changed_digest_wires_copies_and_padding() {
        let c = Sha256Hashlock::new();
        let a = c.evaluate(&[29; 32]);
        let digest = c.digest(&a).unwrap();
        let p = HashlockProgram::compile(&c, digest, 64).unwrap();
        let v = p.pack(&a).unwrap();
        p.verify_packed(&v).unwrap();
        let mut wrong = digest;
        wrong[0] ^= 1;
        assert!(HashlockProgram::compile(&c, wrong, 64)
            .unwrap()
            .verify_packed(&v)
            .is_err());
        let pad = p.geometry.canonical_wires;
        for wire in [
            0,
            255,
            256,
            300,
            pad - 1,
            pad,
            p.geometry.canonical_rows * 64,
            v.len() - 1,
        ] {
            let mut altered = v.clone();
            altered[wire] ^= 1;
            assert!(p.verify_packed(&altered).is_err(), "wire {wire}");
        }
        let mut non_boolean = a.clone();
        non_boolean[0] = 2;
        assert!(matches!(
            p.verify_packed(&p.pack(&non_boolean).unwrap()),
            Err(LoweringError::Nonlinear { batch: 0, lane: 0 })
        ));
        let mut non_boolean_field = v.clone();
        non_boolean_field[0] = MODULUS - 1;
        for (offset, source) in p.occurrence_sources.iter().enumerate() {
            if *source == 0 {
                non_boolean_field[p.geometry.canonical_rows * 64 + offset] = MODULUS - 1;
            }
        }
        assert!(matches!(
            p.verify_packed(&non_boolean_field),
            Err(LoweringError::Nonlinear { batch: 0, lane: 0 })
        ));
        // Change a canonical input and every occurrence consistently. Copy
        // checks now pass, but fixed SHA equations/digest still must reject.
        let mut altered = a.clone();
        altered[0] ^= 1;
        assert!(p.verify_packed(&p.pack(&altered).unwrap()).is_err());
    }
}
