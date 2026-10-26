//! Experimental private-spend graph glue for the source-owned packed gadget.
//! Canonical rows and ordinary/SHA occurrences precede these trace rows.
use super::*;
use packed_poseidon::Binding;

/// Record one raw permutation. Compression feed-forward remains an explicit
/// outer graph equation, so this recorder cannot silently change its semantics.
pub(crate) fn record_poseidon2(input: [Word; 16]) -> [Word; 16] {
    GRAPH.with(|cell| {
        let mut borrowed = cell.borrow_mut();
        let graph = borrowed.as_mut().expect("private-spend graph scope");
        let call = graph.packed_poseidon_calls.len();
        let first = graph.nodes.len();
        let output = core::array::from_fn(|lane| Word::Wire(first + lane));
        for lane in 0..16 {
            graph.nodes.push(Node::PoseidonOutput { call, lane });
        }
        graph
            .packed_poseidon_calls
            .push(PackedPoseidonCall { input, output });
        output
    })
}

impl HtlcAdapter {
    pub(crate) fn require_private_spend_packed_poseidon_schedule(
        &self,
    ) -> Result<(), TransactionCircuitError> {
        if self.graph.packed_poseidon_calls.len() != packed_poseidon::LIVE_CALLS {
            return Err(TransactionCircuitError::ConstraintViolation(
                "private-spend packed Poseidon call count",
            ));
        }
        Ok(())
    }

    pub(super) fn packed_poseidon_constraint_count(&self) -> usize {
        if self.graph.packed_poseidon_calls.is_empty() {
            0
        } else {
            packed_poseidon::CONSTRAINTS
        }
    }

    fn packed_poseidon_row_base(&self) -> usize {
        self.affine.canonical_slots().div_ceil(PACKING)
            + self.ordinary_product_row_count()
            + 4 * self.direct_batches.len()
    }

    pub(super) fn append_packed_poseidon_bindings(&mut self) {
        if self.graph.packed_poseidon_calls.is_empty() {
            return;
        }
        let start = self.geometry.rows;
        let bindings = packed_poseidon::source_bindings(&self.graph.packed_poseidon_calls, start)
            .expect("source-owned private-spend packed Poseidon schedule");
        for binding in bindings {
            match binding {
                Binding::Equal {
                    packed_index,
                    source,
                } => {
                    self.copy_to_packed(packed_index, source);
                }
                Binding::Zero { packed_index } => self.linear_committed(&[(packed_index, 1)], 0),
            }
        }
        self.geometry.rows += packed_poseidon::ROWS;
    }

    /// Reconstruct the complete 128-call K64 layout independently of the
    /// producer's source_bindings/index helpers and constants. Each live input
    /// and raw output is bound; there are no dummy calls in this exact128-call layout.
    pub(super) fn check_packed_poseidon_bindings<F>(
        &self,
        start: usize,
        mut check_row: F,
    ) -> Result<(), &'static str>
    where
        F: FnMut(usize, Word) -> Result<(), &'static str>,
    {
        let calls = &self.graph.packed_poseidon_calls;
        if calls.is_empty() {
            return Ok(());
        }
        if calls.len() != 128 {
            return Err("packed Poseidon source call count");
        }
        for (call, descriptor) in calls.iter().enumerate() {
            for limb in 0..16 {
                let initial = (start + (call / 64) * 182 + limb) * 64 + call % 64;
                let final_word = (start + (call / 64) * 182 + 166 + limb) * 64 + call % 64;
                check_row(initial, descriptor.input[limb])?;
                check_row(final_word, descriptor.output[limb])?;
            }
        }
        for call in 128..128 {
            for limb in 0..16 {
                let initial = (start + (call / 64) * 182 + limb) * 64 + call % 64;
                check_row(initial, Word::ZERO)?;
            }
        }
        Ok(())
    }

    pub(super) fn verify_packed_poseidon_witness(
        &self,
        witness: &[u64],
    ) -> Result<(), TransactionCircuitError> {
        if self.graph.packed_poseidon_calls.is_empty() {
            return Ok(());
        }
        let start = self.packed_poseidon_row_base();
        for lane in 0..64 {
            let rows: Vec<hegemon_field::Goldilocks> = (0..packed_poseidon::ROWS)
                .map(|row| hegemon_field::Goldilocks::from_u64(witness[(start + row) * 64 + lane]))
                .collect();
            let mut out = vec![hegemon_field::Goldilocks::ZERO; packed_poseidon::CONSTRAINTS];
            packed_poseidon::evaluate_all(&rows, &mut out).map_err(|_| {
                TransactionCircuitError::ConstraintViolation("packed Poseidon witness shape")
            })?;
            if out.iter().any(|v| *v != hegemon_field::Goldilocks::ZERO) {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "packed Poseidon identity",
                ));
            }
        }
        Ok(())
    }

    /// Inputs here are arbitrary field evaluations, never host bit/word values.
    /// Reuse the canonical bounded-degree identity evaluator for all 332 roots.
    pub(super) fn eval_packed_poseidon_constraints(
        &self,
        rows: &[u64],
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        if self.graph.packed_poseidon_calls.is_empty() {
            if out.is_empty() {
                return Ok(());
            }
            return Err(TransactionCircuitError::ConstraintViolation(
                "empty packed Poseidon shape",
            ));
        }
        let start = self.packed_poseidon_row_base();
        let scalar_rows: Vec<hegemon_field::Goldilocks> = rows
            [start..start + packed_poseidon::ROWS]
            .iter()
            .copied()
            .map(hegemon_field::Goldilocks::from_u64)
            .collect();
        let mut scalar_out = vec![hegemon_field::Goldilocks::ZERO; out.len()];
        packed_poseidon::evaluate_all(&scalar_rows, &mut scalar_out).map_err(|_| {
            TransactionCircuitError::ConstraintViolation("packed Poseidon evaluator shape")
        })?;
        for (value, scalar) in out.iter_mut().zip(scalar_out) {
            *value = scalar.as_canonical_u64();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> HtlcAdapter {
        let scope = Scope::start();
        let x = input();
        let mut state = [x; 16];
        for _ in 0..128 {
            state = record_poseidon2(state);
        }
        let mut adapter = HtlcAdapter::from_graph(scope.finish());
        adapter.bind_public(x, 7);
        adapter.check_source_lowering(&[x], &[7]).unwrap();
        adapter
            .require_private_spend_packed_poseidon_schedule()
            .unwrap();
        adapter
    }

    #[test]
    fn packed_poseidon_graph_binds_all_calls_and_checks_live_and_dummy_lanes() {
        let adapter = fixture();
        assert_eq!(adapter.geometry.degree, 7);
        assert_eq!(adapter.geometry.rows, 1 + 364);
        assert_eq!(adapter.geometry.nonlinear_batches, 332);
        assert!(adapter.occurrence_sources.is_empty());
        let witness = adapter.evaluate(&[7]).unwrap();
        adapter.verify_packed_witness(&witness).unwrap();
        let start = adapter.packed_poseidon_row_base();
        for call in [0, 63, 64, 127] {
            for row in [0, 16, 166, 181] {
                let index = (start + (call / 64) * 182 + row) * 64 + call % 64;
                let mut bad = witness.clone();
                bad[index] = add(bad[index], 1);
                assert!(adapter.verify_packed_witness(&bad).is_err());
            }
        }
    }

    #[test]
    fn packed_poseidon_source_certificate_rejects_bad_schedule_and_bindings() {
        let mut bad = fixture();
        bad.graph.packed_poseidon_calls[0].input[0] = Word::Wire(1);
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[7]).is_err());
        let mut bad = fixture();
        bad.graph.packed_poseidon_calls[0].output[15] = Word::Wire(1);
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[7]).is_err());
        let mut bad = fixture();
        bad.graph.nodes[1] = Node::PoseidonOutput { call: 1, lane: 0 };
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[7]).is_err());
        // A Bit node adds no CSR row, so this specifically checks that the
        // complete 16-node call block is certified, including missing lane0.
        let mut bad = fixture();
        bad.graph.nodes[1] = Node::Bit(Word::Wire(0), 0);
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[7]).is_err());
        let mut bad = fixture();
        bad.graph.nodes[8] = Node::Bit(Word::Wire(0), 0);
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[7]).is_err());
        let mut bad = fixture();
        bad.coefficients[0] = add(bad.coefficients[0], 1);
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[7]).is_err());
        let mut bad = fixture();
        bad.geometry.degree = 2;
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[7]).is_err());
        let mut bad = fixture();
        bad.graph.packed_poseidon_calls.pop();
        assert!(bad
            .require_private_spend_packed_poseidon_schedule()
            .is_err());
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[7]).is_err());
    }
}
