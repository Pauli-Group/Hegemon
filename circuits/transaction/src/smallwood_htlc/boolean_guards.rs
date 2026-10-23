//! Exact source Boolean guards lowered directly on grouped canonical bit rows.
//! Only the exact source pattern z=x*(x-1), plus an explicit z=0 equality,
//! qualifies. Original Graph nodes/products/equalities remain intact for roles.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BooleanGuard {
    pub(super) output_node: usize,
    pub(super) source: Word,
}
pub(super) fn discover(graph: &Graph) -> Vec<BooleanGuard> {
    graph
        .nodes
        .iter()
        .enumerate()
        .filter_map(|(output, node)| {
            let Node::Product(x, Word::Wire(difference)) = node else {
                return None;
            };
            let Some(Node::Linear(a, Word::Constant(1), true)) = graph.nodes.get(*difference)
            else {
                return None;
            };
            if !matches!(x,Word::Wire(i) if matches!(graph.nodes.get(*i),Some(Node::Bit(..)))) {
                return None;
            }
            if a != x
                || *difference >= output
                || !graph.equalities.contains(&(Word::Wire(output), Word::ZERO))
            {
                return None;
            }
            Some(BooleanGuard {
                output_node: output,
                source: *x,
            })
        })
        .collect()
}
/// Independent enumeration starts from the product schedule, not discover().
/// Exact source/output correspondence is checked rather than trusting a mask.
pub(super) fn check(graph: &Graph, actual: &[BooleanGuard]) -> Result<(), &'static str> {
    let mut expected = Vec::new();
    for &(output, x, difference) in &graph.products {
        let Word::Wire(index) = output else {
            return Err("guard output is not a source node");
        };
        if !matches!(graph.nodes.get(index),Some(Node::Product(a,b)) if *a==x && *b==difference) {
            return Err("guard product metadata mismatch");
        }
        let mut has_zero = false;
        for &(a, b) in &graph.equalities {
            if a == output && b == Word::Constant(0) {
                has_zero = true;
            }
        }
        if !has_zero
            || !matches!(x,Word::Wire(i) if matches!(graph.nodes.get(i),Some(Node::Bit(..))))
        {
            continue;
        }
        let Word::Wire(difference_index) = difference else {
            continue;
        };
        if difference_index >= index {
            continue;
        }
        if let Some(Node::Linear(left, right, subtract)) = graph.nodes.get(difference_index) {
            if *subtract && *left == x && *right == Word::Constant(1) {
                expected.push(BooleanGuard {
                    output_node: index,
                    source: x,
                });
            }
        }
    }
    if expected == actual {
        Ok(())
    } else {
        Err("Boolean guard catalogue differs from source")
    }
}
pub(super) fn residual(value: u64) -> u64 {
    mul(value, sub(value, 1))
}

impl HtlcAdapter {
    pub fn packed_boolean_guard_count(&self) -> usize {
        self.affine.guards.len()
    }
    pub fn packed_boolean_row_count(&self) -> usize {
        self.affine.boolean_rows.len()
    }
    pub fn canonical_padding_slot_count(&self) -> usize {
        self.affine
            .packed_nodes
            .iter()
            .filter(|node| node.is_none())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> HtlcAdapter {
        let scope = Scope::start();
        let a = input();
        let b = input();
        let bits = range(a, 8);
        range(b, 8);
        boolean(bits[0]); // Repeated source guards share a single canonical bit.
        let mut adapter = HtlcAdapter::from_graph(scope.finish());
        adapter.bind_public(a, 5);
        adapter.bind_public(b, 12);
        adapter
    }
    #[test]
    fn grouped_boolean_rows_preserve_source_and_reject_nonboolean_recomposition() {
        let adapter = fixture();
        assert_eq!(adapter.graph.products.len(), 17);
        assert_eq!(adapter.packed_boolean_guard_count(), 17);
        assert_eq!(adapter.packed_boolean_row_count(), 1);
        assert_eq!(adapter.geometry.rows, 2);
        assert!(adapter.batches.is_empty());
        assert_eq!(adapter.affine.graph_to_packed[0], Some(0));
        assert_eq!(adapter.affine.graph_to_packed[1], Some(1));
        adapter
            .check_source_lowering(&[Word::Wire(0), Word::Wire(1)], &[5, 12])
            .unwrap();
        let witness = adapter.evaluate(&[5, 12]).unwrap();
        adapter.verify_packed_witness(&witness).unwrap();
        let mut bad = witness.clone();
        // +2 at bit 0 and -1 at bit 1 keep the linear recomposition unchanged.
        let row = adapter.affine.boolean_rows[0];
        bad[row * PACKING] = 3;
        bad[row * PACKING + 1] = P - 1;
        for (i, target) in adapter.targets.iter().enumerate() {
            let sum =
                (adapter.offsets[i] as usize..adapter.offsets[i + 1] as usize).fold(0, |v, j| {
                    add(
                        v,
                        mul(adapter.coefficients[j], bad[adapter.indices[j] as usize]),
                    )
                });
            assert_eq!(sum, *target);
        }
        assert!(adapter.verify_packed_witness(&bad).is_err());
        let mut row_values = vec![0; adapter.geometry.rows];
        row_values[row] = 3;
        let mut constraints = vec![0; adapter.constraint_count()];
        adapter
            .compute_constraints_u64(
                SmallwoodNonlinearEvalView::RowScalars {
                    eval_point: 0,
                    rows: &row_values,
                    auxiliary_words: &[],
                },
                &mut constraints,
            )
            .unwrap();
        assert_eq!(constraints, vec![6]);
        let mut padded = witness;
        padded[2] = 1;
        assert!(adapter.verify_packed_witness(&padded).is_err());
    }
    #[test]
    fn independent_boolean_certificate_rejects_guard_map_row_and_padding_changes() {
        let check =
            |a: &HtlcAdapter| a.check_source_lowering(&[Word::Wire(0), Word::Wire(1)], &[5, 12]);
        let mut a = fixture();
        a.affine.boolean_rows.clear();
        assert!(check(&a).is_err());
        let mut a = fixture();
        a.affine.guards.pop();
        assert!(check(&a).is_err());
        let mut a = fixture();
        let output = a.affine.guards[0].output_node;
        a.graph
            .equalities
            .retain(|eq| *eq != (Word::Wire(output), Word::ZERO));
        assert!(check(&a).is_err());
        let mut a = fixture();
        a.affine.packed_nodes[2] = Some(0);
        assert!(check(&a).is_err());
        let mut a = fixture();
        a.affine.forms[output].constant = 1;
        assert!(check(&a).is_err());
    }
    #[test]
    fn guards_on_other_sources_retain_ordinary_product_constraints() {
        let scope = Scope::start();
        let bit = input();
        boolean(bit);
        let adapter = HtlcAdapter::from_graph(scope.finish());
        assert_eq!(adapter.packed_boolean_guard_count(), 0);
        assert_eq!(adapter.batches.len(), 1);
        adapter.check_source_lowering::<0>(&[], &[]).unwrap();
        adapter
            .verify_packed_witness(&adapter.evaluate(&[1]).unwrap())
            .unwrap();
        assert!(adapter
            .verify_packed_witness(&adapter.evaluate(&[2]).unwrap())
            .is_err());
    }
}
