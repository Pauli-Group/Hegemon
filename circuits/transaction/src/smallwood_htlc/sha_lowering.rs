//! Candidate only: direct Boolean SHA constraints, degree at most three.
//! The existing fixed 32-byte SHA topology remains the sole topology producer.
//! No host digest or evaluator result is trusted by the constraint verifier.
use super::*;
use crate::smallwood_htlc::sha256::{BooleanGate, Sha256Hashlock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Xor,
    And,
    Parity,
    Majority,
}
impl Kind {
    const ALL: [Self; 4] = [Self::Xor, Self::And, Self::Parity, Self::Majority];
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
        }
    }
    fn value(self, a: u64, b: u64, c: u64) -> u64 {
        sub(0, self.residual(0, a, b, c))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DirectGate {
    pub(super) kind: Kind,
    pub(super) args: [Word; 3],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DirectBatch {
    pub(super) kind: Kind,
    pub(super) rows: [usize; 4],
}

fn append(kind: Kind, args: [Word; 3]) -> Word {
    if let [Word::Constant(a), Word::Constant(b), Word::Constant(c)] = args {
        return Word::Constant(kind.value(a, b, c));
    }
    GRAPH.with(|cell| {
        let mut g = cell.borrow_mut();
        let g = g.as_mut().expect("SHA graph scope");
        let i = g.nodes.len();
        g.nodes.push(Node::Boolean(DirectGate { kind, args }));
        Word::Wire(i)
    })
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
            BooleanGate::Xor(a, b) => append(Kind::Xor, [wires[a], wires[b], Word::ZERO]),
            BooleanGate::And(a, b) => append(Kind::And, [wires[a], wires[b], Word::ZERO]),
            BooleanGate::Parity(a, b, c) => append(Kind::Parity, [wires[a], wires[b], wires[c]]),
            BooleanGate::Majority(a, b, c) => {
                append(Kind::Majority, [wires[a], wires[b], wires[c]])
            }
        };
        wires.push(out);
    }
    core::array::from_fn(|word| {
        (0..32).fold(Word::ZERO, |acc, bit| {
            acc + wires[topology.output_wires()[word * 32 + bit]] * Word::from_u64(1u64 << bit)
        })
    })
}
impl DirectGate {
    pub(super) fn evaluate(&self, canonical: &[u64]) -> u64 {
        self.kind.value(
            read(self.args[0], canonical),
            read(self.args[1], canonical),
            read(self.args[2], canonical),
        )
    }
    pub(super) fn valid_before(&self, before: usize) -> bool {
        self.args.iter().all(|w| match w {
            Word::Constant(v) => *v < P,
            Word::Wire(i) => *i < before,
        })
    }
}
impl HtlcAdapter {
    fn direct_groups(&self) -> Vec<(Kind, Vec<[Word; 4]>)> {
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
                            Some([Word::Wire(i), g.args[0], g.args[1], g.args[2]])
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
                self.direct_batches.push(DirectBatch {
                    kind,
                    rows: [start, start + 1, start + 2, start + 3],
                });
                for operand in 0..4 {
                    for lane in 0..PACKING {
                        let source = gates[lane.min(gates.len() - 1)][operand];
                        self.occurrence_sources.push(source);
                        self.copy_to_packed((start + operand) * PACKING + lane, source);
                    }
                }
                self.geometry.rows += 4;
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
        // Separate enumeration from producer direct_groups(): a producer-side
        // omission/reordering must not reproduce itself in the certificate.
        for kind in [Kind::Xor, Kind::And, Kind::Parity, Kind::Majority] {
            let mut entries = Vec::new();
            for (index, node) in self.graph.nodes.iter().enumerate() {
                if let Node::Boolean(gate) = node {
                    if gate.kind == kind {
                        entries.push([Word::Wire(index), gate.args[0], gate.args[1], gate.args[2]]);
                    }
                }
            }

            for gates in entries.chunks(PACKING) {
                let row = start + slot * 4;
                if self.direct_batches.get(slot)
                    != Some(&DirectBatch {
                        kind,
                        rows: [row, row + 1, row + 2, row + 3],
                    })
                {
                    return Err("direct SHA batch topology mismatch");
                }
                for operand in 0..4 {
                    for lane in 0..PACKING {
                        let source = gates[lane.min(gates.len() - 1)][operand];
                        if self.occurrence_sources.get(*occurrence) != Some(&source) {
                            return Err("direct SHA copy source mismatch");
                        }
                        *occurrence += 1;
                        check_row((row + operand) * PACKING + lane, source)?;
                    }
                }
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
            for lane in 0..PACKING {
                let [z, a, b, c] = batch.rows.map(|r| witness[r * PACKING + lane]);
                if batch.kind.residual(z, a, b, c) != 0 {
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
            let [z, a, b, c] = batch.rows.map(|r| rows[r]);
            *value = batch.kind.residual(z, a, b, c);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_gate_equations_enforce_exact_boolean_truth_tables() {
        for kind in Kind::ALL {
            for a in 0..2 {
                for b in 0..2 {
                    for c in 0..2 {
                        let expected = match kind {
                            Kind::Xor => a ^ b,
                            Kind::And => a & b,
                            Kind::Parity => a ^ b ^ c,
                            Kind::Majority => (a & b) | (a & c) | (b & c),
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
                for r in batch.rows {
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
}
