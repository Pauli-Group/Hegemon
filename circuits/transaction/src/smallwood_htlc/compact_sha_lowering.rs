//! Experimental compact-SHA glue. Source graph indices and packed slots remain
//! distinct; every module equation is installed and independently reconstructed.
use super::*;
use compact_sha256::Variable;

#[derive(Clone, Debug)]
pub(super) struct CompactShaCall {
    pub(super) input: [Word; 256],
    pub(super) output: [Word; 8],
}

pub(crate) fn sha256_compact(input: [Word; 256]) -> [Word; 8] {
    GRAPH.with(|cell| {
        let mut borrowed = cell.borrow_mut();
        let graph = borrowed.as_mut().expect("private-spend SHA graph scope");
        let call = graph.compact_sha_calls.len();
        let first = graph.nodes.len();
        let output = core::array::from_fn(|lane| Word::Wire(first + lane));
        for lane in 0..8 {
            graph.nodes.push(Node::CompactShaOutput { call, lane });
        }
        graph
            .compact_sha_calls
            .push(CompactShaCall { input, output });
        output
    })
}

impl HtlcAdapter {
    pub(crate) fn require_private_spend_compact_sha_schedule(
        &self,
    ) -> Result<(), TransactionCircuitError> {
        if self.graph.compact_sha_calls.len() != 1 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "private-spend compact SHA call count",
            ));
        }
        Ok(())
    }
    pub(super) fn compact_sha_constraint_count(&self) -> usize {
        self.graph.compact_sha_calls.len() * compact_sha256::CONSTRAINTS
    }
    fn compact_sha_row_base(&self) -> usize {
        self.geometry.rows - self.graph.compact_sha_calls.len() * compact_sha256::TRACE_ROWS
    }
    pub(super) fn append_compact_sha_bindings(&mut self) {
        if self.graph.compact_sha_calls.is_empty() {
            return;
        }
        assert_eq!(
            self.graph.compact_sha_calls.len(),
            1,
            "source-owned compact SHA schedule"
        );
        let start = self.geometry.rows;
        let call = self.graph.compact_sha_calls[0].clone();
        let layout = compact_sha256::Layout::new(PACKING).expect("source packing");
        for equation in layout.linear_constraints() {
            let mut packed = Vec::new();
            let mut source = Vec::new();
            for (variable, coefficient) in equation.terms {
                match variable {
                    Variable::Cell(row, lane) => {
                        packed.push(((start + row) * PACKING + lane, coefficient))
                    }
                    Variable::InputBit(index) => source.push((call.input[index], coefficient)),
                    Variable::DigestWord(index) => source.push((call.output[index], coefficient)),
                }
            }
            let form = self.affine.combine(&source);
            packed.extend(form.terms);
            self.linear_committed(&packed, sub(equation.target, form.constant));
        }
        self.geometry.rows += compact_sha256::TRACE_ROWS;
    }

    pub(super) fn check_compact_sha_bindings(
        &self,
        start: usize,
        checked: &mut affine::SourceRows<'_>,
    ) -> Result<(), &'static str> {
        if self.graph.compact_sha_calls.is_empty() {
            return Ok(());
        }
        if self.graph.compact_sha_calls.len() != 1 {
            return Err("compact SHA source call count");
        }
        let call = &self.graph.compact_sha_calls[0];
        // This inventory is independently constructed with literal round and
        // stash schedules; it does not call Layout::linear_constraints().
        for equation in compact_sha_certificate::linear_constraints(PACKING) {
            let mut packed_terms = Vec::new();
            let mut source_terms = Vec::new();
            for (variable, coefficient) in equation.terms {
                match variable {
                    Variable::Cell(row, lane) if row < 297 && lane < PACKING => {
                        let slot = start
                            .checked_add(row)
                            .and_then(|r| r.checked_mul(PACKING))
                            .and_then(|i| i.checked_add(lane))
                            .ok_or("compact SHA slot overflow")?;
                        packed_terms.push((slot, coefficient));
                    }
                    Variable::InputBit(index) if index < 256 => {
                        source_terms.push((call.input[index], coefficient))
                    }
                    Variable::DigestWord(index) if index < 8 => {
                        source_terms.push((call.output[index], coefficient))
                    }
                    _ => return Err("compact SHA source variable out of range"),
                }
            }
            checked.mixed(&packed_terms, &source_terms, equation.target)?;
        }
        Ok(())
    }

    pub(super) fn verify_compact_sha_witness(
        &self,
        witness: &[u64],
    ) -> Result<(), TransactionCircuitError> {
        if self.graph.compact_sha_calls.is_empty() {
            return Ok(());
        }
        let start = self.compact_sha_row_base();
        let layout = compact_sha256::Layout::new(PACKING).expect("source packing");
        let mut out = vec![0; compact_sha256::CONSTRAINTS];
        for lane in 0..PACKING {
            let rows: Vec<u64> = (0..compact_sha256::TRACE_ROWS)
                .map(|row| witness[(start + row) * PACKING + lane])
                .collect();
            layout
                .compute_constraints(lane as u64, &rows, &mut out)
                .map_err(|_| {
                    TransactionCircuitError::ConstraintViolation("compact SHA witness shape")
                })?;
            if out.iter().any(|v| *v != 0) {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "compact SHA polynomial identity",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn eval_compact_sha_constraints(
        &self,
        x: u64,
        rows: &[u64],
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        if self.graph.compact_sha_calls.is_empty() {
            if out.is_empty() {
                return Ok(());
            }
            return Err(TransactionCircuitError::ConstraintViolation(
                "empty compact SHA shape",
            ));
        }
        let start = self.compact_sha_row_base();
        compact_sha256::Layout::new(PACKING)
            .expect("source packing")
            .compute_constraints(x, &rows[start..start + compact_sha256::TRACE_ROWS], out)
            .map_err(|_| {
                TransactionCircuitError::ConstraintViolation("compact SHA evaluator shape")
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn fixture(bytes: [u8; 32]) -> (HtlcAdapter, [Word; 256], [u64; 256], [Word; 8]) {
        let scope = Scope::start();
        let inputs = core::array::from_fn(|_| input());
        let digest = sha256_compact(inputs);
        let bits = core::array::from_fn(|i| u64::from((bytes[i / 8] >> (i % 8)) & 1));
        let mut adapter = HtlcAdapter::from_graph(scope.finish());
        for (wire, target) in inputs.into_iter().zip(bits) {
            adapter.bind_public(wire, target);
        }
        adapter.check_source_lowering(&inputs, &bits).unwrap();
        adapter
            .require_private_spend_compact_sha_schedule()
            .unwrap();
        (adapter, inputs, bits, digest)
    }

    #[test]
    fn compact_sha_glue_preserves_digest_and_binds_trace_io() {
        for bytes in [[0; 32], [255; 32], core::array::from_fn(|i| i as u8)] {
            let (adapter, _, bits, digest) = fixture(bytes);
            assert_eq!(adapter.geometry.degree, 7);
            assert_eq!(adapter.geometry.canonical_wires, 256);
            assert_eq!(adapter.geometry.rows, 301);
            assert_eq!(adapter.geometry.nonlinear_batches, 294);
            let witness = adapter.evaluate(&bits).unwrap();
            adapter.verify_packed_witness(&witness).unwrap();
            let expected = Sha256::digest(bytes);
            for i in 0..8 {
                let wanted = u64::from(u32::from_le_bytes(
                    expected[i * 4..i * 4 + 4].try_into().unwrap(),
                ));
                assert_eq!(adapter.graph_word_from_packed(digest[i], &witness), wanted);
            }
            let start = adapter.compact_sha_row_base();
            for (row, lane) in [
                (0, 0),
                (194, 63),
                (196, 0),
                (228, 17),
                (260, 0),
                (280, 7),
                (294, 4),
                (295, 12),
                (296, 25),
            ] {
                let mut bad = witness.clone();
                let index = (start + row) * PACKING + lane;
                bad[index] = add(bad[index], 1);
                assert!(adapter.verify_packed_witness(&bad).is_err());
            }
            let mut malformed = bits;
            malformed[0] = 2;
            assert!(adapter.evaluate(&malformed).is_err());
        }
    }

    #[test]
    fn compact_sha_glue_rejects_source_schedule_and_csr_mutations() {
        let (mut bad, inputs, bits, _) = fixture([0; 32]);
        bad.graph.nodes[256] = Node::Bit(Word::Wire(0), 0);
        assert!(bad.check_source_lowering(&inputs, &bits).is_err());
        let (mut bad, inputs, bits, _) = fixture([0; 32]);
        bad.graph.compact_sha_calls[0].input[0] = Word::Wire(256);
        assert!(bad.check_source_lowering(&inputs, &bits).is_err());
        let (mut bad, inputs, bits, _) = fixture([0; 32]);
        bad.graph.compact_sha_calls[0].input.swap(0, 1);
        assert!(bad.check_source_lowering(&inputs, &bits).is_err());
        let (mut bad, inputs, bits, _) = fixture([0; 32]);
        bad.graph.compact_sha_calls[0].output[7] = Word::Wire(256);
        assert!(bad.check_source_lowering(&inputs, &bits).is_err());
        let (mut bad, inputs, bits, _) = fixture([0; 32]);
        bad.coefficients[0] = add(bad.coefficients[0], 1);
        assert!(bad.check_source_lowering(&inputs, &bits).is_err());
        let (mut bad, inputs, bits, _) = fixture([0; 32]);
        bad.geometry.degree = 2;
        assert!(bad.check_source_lowering(&inputs, &bits).is_err());
    }

    #[test]
    fn compact_sha_glue_passes_arbitrary_field_point_and_all_constraints() {
        let (adapter, _, _, _) = fixture([0; 32]);
        let rows: Vec<u64> = (0..adapter.geometry.rows)
            .map(|i| (i as u64 + 3) * 17)
            .collect();
        let x = 12345;
        let mut actual = vec![0; adapter.constraint_count()];
        adapter
            .compute_constraints_u64(
                SmallwoodNonlinearEvalView::RowScalars {
                    eval_point: x,
                    rows: &rows,
                    auxiliary_words: &[],
                },
                &mut actual,
            )
            .unwrap();
        let start = adapter.compact_sha_row_base();
        let mut expected = vec![0; 294];
        compact_sha256::Layout::new(PACKING)
            .unwrap()
            .compute_constraints(x, &rows[start..start + 297], &mut expected)
            .unwrap();
        assert_eq!(actual, expected);
        let mut wrong_point = vec![0; 294];
        compact_sha256::Layout::new(PACKING)
            .unwrap()
            .compute_constraints(0, &rows[start..start + 297], &mut wrong_point)
            .unwrap();
        assert_ne!(actual, wrong_point);
    }
}
