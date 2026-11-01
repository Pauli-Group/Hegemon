//! Candidate only: direct Boolean SHA constraints, degree at most three.
//! The existing fixed 32-byte SHA topology remains the sole topology producer.
//! No host digest or evaluator result is trusted by the constraint verifier.
use super::*;
use crate::smallwood_htlc::sha256::{BooleanGate, Sha256Hashlock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Xor,
    And,
    Not,
    Parity,
    Majority,
    /// `z = t + c(a + b - 2t)` with `t = ab`. Degree 2. Four inputs.
    QuadraticMajority,
}
impl Kind {
    pub(super) const ALL: [Self; 6] = [
        Self::Xor,
        Self::And,
        Self::Not,
        Self::Parity,
        Self::Majority,
        Self::QuadraticMajority,
    ];
    pub(super) const fn index(self) -> usize {
        match self {
            Self::Xor => 0,
            Self::And => 1,
            Self::Not => 2,
            Self::Parity => 3,
            Self::Majority => 4,
            Self::QuadraticMajority => 5,
        }
    }
    pub(super) const fn batch_rows(self) -> usize {
        match self {
            Self::QuadraticMajority => 5,
            _ => 4,
        }
    }
    pub(super) const fn is_cubic(self) -> bool {
        matches!(self, Self::Parity | Self::Majority)
    }
    fn residual(self, z: u64, a: u64, b: u64, c: u64) -> u64 {
        let ab = mul(a, b);
        match self {
            Self::Xor => add(sub(sub(z, a), b), mul(2, ab)),
            Self::And => sub(z, ab),
            Self::Parity => sub(
                add(
                    sub(sub(sub(z, a), b), c),
                    mul(2, add(add(ab, mul(a, c)), mul(b, c))),
                ),
                mul(4, mul(ab, c)),
            ),
            Self::Majority => add(
                sub(sub(sub(z, ab), mul(a, c)), mul(b, c)),
                mul(2, mul(ab, c)),
            ),
            Self::Not => sub(add(z, a), 1),
            Self::QuadraticMajority => {
                unreachable!("quadratic majority is checked through residual_sampled")
            }
        }
    }
    fn value(self, a: u64, b: u64, c: u64) -> u64 {
        sub(0, self.residual(0, a, b, c))
    }
    fn residual_sampled(self, vals: &[u64]) -> u64 {
        match self {
            Self::Not => sub(add(vals[0], vals[1]), 1),
            Self::QuadraticMajority => {
                let (z, t, a, b, c) = (vals[0], vals[1], vals[2], vals[3], vals[4]);
                let inner = sub(add(a, b), mul(2, t));
                sub(sub(z, t), mul(c, inner))
            }
            _ => self.residual(vals[0], vals[1], vals[2], vals[3]),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DirectGate {
    pub(super) kind: Kind,
    pub(super) args: [Word; 4],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DirectBatch {
    pub(super) kind: Kind,
    /// Packed witness rows. Kinds other than quadratic majority use the first four.
    pub(super) rows: [usize; 5],
}

/// Packed witness rows occupied by Boolean SHA batches, in `Kind::ALL` order.
pub(super) fn packed_row_count(nodes: &[Node]) -> usize {
    let mut counts = [0usize; Kind::ALL.len()];
    for node in nodes {
        if let Node::Boolean(gate) = node {
            counts[gate.kind.index()] += 1;
        }
    }
    Kind::ALL
        .iter()
        .zip(counts)
        .map(|(kind, n)| kind.batch_rows() * n.div_ceil(PACKING))
        .sum()
}

fn append(kind: Kind, args: [Word; 4]) -> Word {
    let used = kind.batch_rows() - 1;
    if args.iter().take(used).all(|w| matches!(w, Word::Constant(_))) {
        let c = |i| match args[i] {
            Word::Constant(v) => v,
            Word::Wire(_) => 0,
        };
        let folded = match kind {
            Kind::Not => sub(1, c(0)),
            Kind::QuadraticMajority => {
                let t = c(0);
                add(t, mul(c(3), sub(add(c(1), c(2)), mul(2, t))))
            }
            _ => kind.value(c(0), c(1), c(2)),
        };
        return Word::Constant(folded);
    }
    GRAPH.with(|cell| {
        let mut g = cell.borrow_mut();
        let g = g.as_mut().expect("SHA graph scope");
        let i = g.nodes.len();
        g.nodes.push(Node::Boolean(DirectGate { kind, args }));
        Word::Wire(i)
    })
}
fn xor_gate(a: Word, b: Word) -> Word {
    append(Kind::Xor, [a, b, Word::ZERO, Word::ZERO])
}
fn and_gate(a: Word, b: Word) -> Word {
    append(Kind::And, [a, b, Word::ZERO, Word::ZERO])
}
fn not_gate(a: Word) -> Word {
    append(Kind::Not, [a, Word::ZERO, Word::ZERO, Word::ZERO])
}
/// Same input-bit and output-word endian convention as historical sha().
/// Inputs are constrained Boolean here even if the caller already did so.
pub(crate) fn sha256_direct(input: [Word; 256]) -> [Word; 8] {
    for bit in input {
        boolean(bit);
    }
    let topology = Sha256Hashlock::new();
    let mut wires = input.to_vec();
    for gate in topology.gates() {
        let out = match *gate {
            BooleanGate::Constant(v) => Word::Constant(v as u64),
            BooleanGate::Not(a) => Word::ONE - wires[a],
            BooleanGate::Xor(a, b) => xor_gate(wires[a], wires[b]),
            BooleanGate::And(a, b) => and_gate(wires[a], wires[b]),
            BooleanGate::Parity(a, b, c) => {
                append(Kind::Parity, [wires[a], wires[b], wires[c], Word::ZERO])
            }
            BooleanGate::Majority(a, b, c) => {
                append(Kind::Majority, [wires[a], wires[b], wires[c], Word::ZERO])
            }
        };
        wires.push(out);
    }
    digest_words(&topology, &wires)
}
/// Degree-2 claim lowering. Parity is two XOR gates. Majority is one AND plus
/// `z = t + c(a + b - 2t)`. Every later-gate input is a retained Boolean wire.
pub(crate) fn sha256_quadratic(input: [Word; 256]) -> [Word; 8] {
    for bit in input {
        boolean(bit);
    }
    let topology = Sha256Hashlock::new();
    let mut wires = input.to_vec();
    for gate in topology.gates() {
        let out = match *gate {
            BooleanGate::Constant(v) => Word::Constant(v as u64),
            BooleanGate::Not(a) => not_gate(wires[a]),
            BooleanGate::Xor(a, b) => xor_gate(wires[a], wires[b]),
            BooleanGate::And(a, b) => and_gate(wires[a], wires[b]),
            BooleanGate::Parity(a, b, c) => {
                let t = xor_gate(wires[a], wires[b]);
                xor_gate(t, wires[c])
            }
            BooleanGate::Majority(a, b, c) => {
                let t = and_gate(wires[a], wires[b]);
                append(
                    Kind::QuadraticMajority,
                    [t, wires[a], wires[b], wires[c]],
                )
            }
        };
        wires.push(out);
    }
    digest_words(&topology, &wires)
}
fn digest_words(topology: &Sha256Hashlock, wires: &[Word]) -> [Word; 8] {
    core::array::from_fn(|word| {
        (0..32).fold(Word::ZERO, |acc, bit| {
            acc + wires[topology.output_wires()[word * 32 + bit]] * Word::from_u64(1u64 << bit)
        })
    })
}
impl DirectGate {
    pub(super) fn evaluate(&self, canonical: &[u64]) -> u64 {
        let a = read(self.args[0], canonical);
        let b = read(self.args[1], canonical);
        let c = read(self.args[2], canonical);
        let d = read(self.args[3], canonical);
        match self.kind {
            Kind::Not => sub(1, a),
            Kind::QuadraticMajority => add(a, mul(d, sub(add(b, c), mul(2, a)))),
            _ => self.kind.value(a, b, c),
        }
    }
    pub(super) fn valid_before(&self, before: usize) -> bool {
        self.args.iter().all(|w| match w {
            Word::Constant(v) => *v < P,
            Word::Wire(i) => *i < before,
        })
    }
}
impl HtlcAdapter {
    fn direct_groups(&self) -> Vec<(Kind, Vec<[Word; 5]>)> {
        Kind::ALL
            .into_iter()
            .map(|kind| {
                let entries = self
                    .graph
                    .nodes
                    .iter()
                    .enumerate()
                    .filter_map(|(i, node)| match node {
                        Node::Boolean(g) if g.kind == kind => {
                            let mut entry = [Word::ZERO; 5];
                            entry[0] = Word::Wire(i);
                            let args = kind.batch_rows() - 1;
                            entry[1..1 + args].copy_from_slice(&g.args[..args]);
                            Some(entry)
                        }
                        _ => None,
                    })
                    .collect();
                (kind, entries)
            })
            .collect()
    }
    pub(super) fn direct_batch_count(&self) -> usize {
        self.direct_groups()
            .iter()
            .map(|(_, g)| g.len().div_ceil(PACKING))
            .sum()
    }
    pub(super) fn append_direct_batches(&mut self) {
        for (kind, entries) in self.direct_groups() {
            for gates in entries.chunks(PACKING) {
                let start = self.geometry.rows;
                let width = kind.batch_rows();
                let mut rows = [0usize; 5];
                for operand in 0..width {
                    rows[operand] = start + operand;
                }
                self.direct_batches.push(DirectBatch { kind, rows });
                for operand in 0..width {
                    for lane in 0..PACKING {
                        let source = gates[lane.min(gates.len() - 1)][operand];
                        self.occurrence_sources.push(source);
                        self.copy_to_packed((start + operand) * PACKING + lane, source);
                    }
                }
                self.geometry.rows += width;
            }
        }
    }
    /// Independently enumerate every direct gate, padded lane, canonical copy
    /// and CSR equation. Existing check_row independently normalizes each row.
    pub(super) fn check_direct_batches<F>(
        &self,
        start: usize,
        occurrence: &mut usize,
        mut check_row: F,
    ) -> Result<(), &'static str>
    where
        F: FnMut(usize, Word) -> Result<(), &'static str>,
    {
        let mut slot = 0;
        let mut row = start;
        // Separate enumeration from producer direct_groups(): a producer-side
        // omission/reordering must not reproduce itself in the certificate.
        for kind in Kind::ALL {
            let mut entries = Vec::new();
            let args = kind.batch_rows() - 1;
            for (index, node) in self.graph.nodes.iter().enumerate() {
                if let Node::Boolean(gate) = node {
                    if gate.kind == kind {
                        let mut entry = [Word::ZERO; 5];
                        entry[0] = Word::Wire(index);
                        entry[1..1 + args].copy_from_slice(&gate.args[..args]);
                        entries.push(entry);
                    }
                }
            }

            let width = kind.batch_rows();
            for gates in entries.chunks(PACKING) {
                let mut rows = [0usize; 5];
                for operand in 0..width {
                    rows[operand] = row + operand;
                }
                if self.direct_batches.get(slot) != Some(&DirectBatch { kind, rows }) {
                    return Err("direct SHA batch topology mismatch");
                }
                for operand in 0..width {
                    for lane in 0..PACKING {
                        let source = gates[lane.min(gates.len() - 1)][operand];
                        if self.occurrence_sources.get(*occurrence) != Some(&source) {
                            return Err("direct SHA copy source mismatch");
                        }
                        *occurrence += 1;
                        check_row((row + operand) * PACKING + lane, source)?;
                    }
                }
                row += width;
                slot += 1;
            }
        }
        if slot != self.direct_batches.len() {
            return Err("extra direct SHA batches");
        }
        Ok(())
    }
    pub(super) fn verify_direct_witness(
        &self,
        witness: &[u64],
    ) -> Result<(), TransactionCircuitError> {
        for batch in &self.direct_batches {
            let width = batch.kind.batch_rows();
            for lane in 0..PACKING {
                let vals: [u64; 5] = core::array::from_fn(|i| {
                    if i < width {
                        witness[batch.rows[i] * PACKING + lane]
                    } else {
                        0
                    }
                });
                if batch.kind.residual_sampled(&vals[..width]) != 0 {
                    return Err(TransactionCircuitError::ConstraintViolation(
                        "direct SHA gate equation",
                    ));
                }
            }
        }
        Ok(())
    }
    pub(super) fn eval_direct_constraints(&self, rows: &[u64], out: &mut [u64]) {
        for (batch, value) in self.direct_batches.iter().zip(out) {
            let width = batch.kind.batch_rows();
            let vals: [u64; 5] = core::array::from_fn(|i| if i < width { rows[batch.rows[i]] } else { 0 });
            *value = batch.kind.residual_sampled(&vals[..width]);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::smallwood_semantics::SmallwoodConstraintAdapter;
    #[test]
    fn direct_gate_equations_enforce_exact_boolean_truth_tables() {
        for kind in [Kind::Xor, Kind::And, Kind::Parity, Kind::Majority] {
            for a in 0..2 {
                for b in 0..2 {
                    for c in 0..2 {
                        let expected = match kind {
                            Kind::Xor => a ^ b,
                            Kind::And => a & b,
                            Kind::Parity => a ^ b ^ c,
                            Kind::Majority => (a & b) | (a & c) | (b & c),
                            Kind::Not | Kind::QuadraticMajority => unreachable!("cubic table"),
                        };
                        assert_eq!(kind.value(a, b, c), expected);
                        for z in [0, 1, 2, P - 1] {
                            assert_eq!(kind.residual(z, a, b, c) == 0, z == expected);
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn direct_sha_witness_matches_fixed_bit_topology_and_all_copies_are_bound() {
        for input in [[0u8; 32], [0xffu8; 32], core::array::from_fn(|i| i as u8)] {
            let scope = Scope::start();
            let bits = core::array::from_fn(|_| super::super::input());
            let digest = sha256_direct(bits);
            let adapter = HtlcAdapter::from_graph(scope.finish());
            let values = (0..256)
                .map(|i| u64::from((input[i / 8] >> (i % 8)) & 1))
                .collect::<Vec<_>>();
            let packed = adapter.evaluate(&values).unwrap();
            adapter.verify_packed_witness(&packed).unwrap();
            adapter.check_source_lowering(&[], &[]).unwrap();
            let top = Sha256Hashlock::new();
            let expected = top.digest(&top.evaluate(&input)).unwrap();
            for (i, w) in digest.iter().enumerate() {
                assert_eq!(
                    adapter.graph_word_from_packed(*w, &packed),
                    u32::from_le_bytes(expected[i * 4..i * 4 + 4].try_into().unwrap()) as u64
                );
            }
            assert_eq!(adapter.geometry.degree, 3);
            // For each kind, mutate both boundary lanes of its first and final
            // batch. The independent source checker covers every CSR copy.
            let mut probes = Vec::new();
            for kind in Kind::ALL {
                if let Some(first) = adapter.direct_batches.iter().position(|b| b.kind == kind) {
                    probes.push(first);
                }
                if let Some(last) = adapter.direct_batches.iter().rposition(|b| b.kind == kind) {
                    if !probes.contains(&last) {
                        probes.push(last);
                    }
                }
            }
            for slot in probes {
                let batch = &adapter.direct_batches[slot];
                for r in batch.rows.into_iter().take(batch.kind.batch_rows()) {
                    for lane in [0, 63] {
                        let mut bad = packed.clone();
                        let p = r * PACKING + lane;
                        bad[p] = add(bad[p], 1);
                        assert!(adapter.verify_packed_witness(&bad).is_err());
                    }
                }
            }
            let mut nonboolean = values;
            nonboolean[0] = 2;
            assert!(adapter
                .verify_packed_witness(&adapter.evaluate(&nonboolean).unwrap())
                .is_err());
        }
    }
    #[test]
    fn quadratic_parity_and_majority_match_boolean_truth_tables() {
        for a in 0..2u64 {
            for b in 0..2u64 {
                for c in 0..2u64 {
                    let t = Kind::Xor.value(a, b, 0);
                    let parity = Kind::Xor.value(t, c, 0);
                    assert_eq!(parity, a ^ b ^ c);
                    let and_t = Kind::And.value(a, b, 0);
                    let maj = add(and_t, mul(c, sub(add(a, b), mul(2, and_t))));
                    let expected = (a & b) | (a & c) | (b & c);
                    assert_eq!(maj, expected);
                    assert_eq!(
                        Kind::QuadraticMajority.residual_sampled(&[maj, and_t, a, b, c]),
                        0
                    );
                    assert_ne!(
                        Kind::QuadraticMajority.residual_sampled(&[maj ^ 1, and_t, a, b, c]),
                        0
                    );
                    assert_eq!(Kind::Not.residual_sampled(&[1 - a, a]), 0);
                    assert_ne!(Kind::Not.residual_sampled(&[a, a]), 0);
                }
            }
        }
    }
    #[test]
    fn quadratic_sha_witness_matches_sha2_at_degree_two() {
        use sha2::{Digest, Sha256};
        for input in [[0u8; 32], [0xffu8; 32], core::array::from_fn(|i| i as u8)] {
            let scope = Scope::start();
            let bits = core::array::from_fn(|_| super::super::input());
            let digest = sha256_quadratic(bits);
            let adapter = HtlcAdapter::from_graph(scope.finish());
            let values = (0..256)
                .map(|i| u64::from((input[i / 8] >> (i % 8)) & 1))
                .collect::<Vec<_>>();
            let packed = adapter.evaluate(&values).unwrap();
            adapter.verify_packed_witness(&packed).unwrap();
            adapter.check_source_lowering(&[], &[]).unwrap();
            assert_eq!(adapter.constraint_degree(), 2);
            let max_terms = adapter
                .affine
                .forms
                .iter()
                .map(|form| form.terms.len())
                .max()
                .unwrap_or(0);
            assert!(max_terms <= 64, "affine form length {max_terms}");
            let expected: [u8; 32] = Sha256::digest(input).into();
            for (i, w) in digest.iter().enumerate() {
                assert_eq!(
                    adapter.graph_word_from_packed(*w, &packed),
                    u32::from_le_bytes(expected[i * 4..i * 4 + 4].try_into().unwrap()) as u64
                );
            }
        }
    }
}
