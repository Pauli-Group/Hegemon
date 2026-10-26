//! Source-derived algebraic aliases. Original graph and role metadata remain intact.
use super::affine::Form;
use super::*;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Symbols {
    pub(super) forms: Vec<Form>,
    pub(super) retained: Vec<bool>,
    pub(super) products: Vec<usize>,
}
fn unit(i: usize) -> Form {
    Form {
        constant: 0,
        terms: vec![(i, 1)],
    }
}
fn zero() -> Form {
    Form {
        constant: 0,
        terms: vec![],
    }
}
fn scaled(f: &Form, c: u64) -> Form {
    Form {
        constant: mul(f.constant, c),
        terms: f
            .terms
            .iter()
            .filter_map(|&(i, v)| {
                let v = mul(v, c);
                (v != 0).then_some((i, v))
            })
            .collect(),
    }
}
fn combine(forms: &[Form], words: &[(Word, u64)]) -> Form {
    let mut constant = 0;
    let mut terms = BTreeMap::new();
    for &(w, c) in words {
        match w {
            Word::Constant(v) => constant = add(constant, mul(v, c)),
            Word::Wire(i) => {
                constant = add(constant, mul(forms[i].constant, c));
                for &(j, v) in &forms[i].terms {
                    let old = terms.get(&j).copied().unwrap_or(0);
                    terms.insert(j, add(old, mul(v, c)));
                }
            }
        }
    }
    Form {
        constant,
        terms: terms.into_iter().filter(|(_, v)| *v != 0).collect(),
    }
}
fn sign_normalize(f: Form) -> (Form, u64) {
    let neg = scaled(&f, P - 1);
    if neg < f {
        (neg, P - 1)
    } else {
        (f, 1)
    }
}
pub(super) fn build(graph: &Graph, guards: &[boolean_guards::BooleanGuard]) -> Symbols {
    let guarded: BTreeSet<_> = guards.iter().map(|g| g.output_node).collect();
    let zeros: BTreeSet<_> = graph
        .equalities
        .iter()
        .filter_map(|&(a, b)| {
            if b == Word::ZERO {
                if let Word::Wire(i) = a {
                    Some(i)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    let mut forms = vec![];
    let mut retained = vec![];
    let mut products = vec![];
    let mut bits = BTreeMap::new();
    let mut multiplication = BTreeMap::new();
    for (i, node) in graph.nodes.iter().enumerate() {
        let mut keep = false;
        let form = if guarded.contains(&i) {
            zero()
        } else {
            match *node {
                Node::Linear(a, b, s) => combine(&forms, &[(a, 1), (b, if s { P - 1 } else { 1 })]),
                Node::Scale(a, c) => combine(&forms, &[(a, c)]),
                Node::Bit(Word::Wire(j), bit)
                    if bit < 64
                        && matches!(graph.nodes.get(j), Some(Node::Input(slot))
                            if graph.public_bit_bindings.as_ref().is_some_and(|p| *slot < p.len())) =>
                {
                    let Node::Input(slot) = graph.nodes[j] else {
                        unreachable!()
                    };
                    Form {
                        constant: (graph.public_bit_bindings.as_ref().unwrap()[slot] >> bit) & 1,
                        terms: vec![],
                    }
                }
                Node::Bit(a, bit) => {
                    let key = (combine(&forms, &[(a, 1)]), bit);
                    if let Some(previous) = bits.get(&key) {
                        unit(*previous)
                    } else {
                        bits.insert(key, i);
                        keep = true;
                        unit(i)
                    }
                }
                Node::Product(a, b) => {
                    let (mut left, ls) = sign_normalize(combine(&forms, &[(a, 1)]));
                    let (mut right, rs) = sign_normalize(combine(&forms, &[(b, 1)]));
                    if right < left {
                        std::mem::swap(&mut left, &mut right);
                    }
                    let sign = mul(ls, rs);
                    let key = (left, right);
                    if let Some(previous) = multiplication.get(&key) {
                        scaled(previous, sign)
                    } else {
                        products.push(i);
                        let value = if zeros.contains(&i) {
                            zero()
                        } else {
                            keep = true;
                            unit(i)
                        };
                        multiplication.insert(key, scaled(&value, sign));
                        value
                    }
                }
                _ => {
                    keep = true;
                    unit(i)
                }
            }
        };
        forms.push(form);
        retained.push(keep);
    }
    Symbols {
        forms,
        retained,
        products,
    }
}
// Independent checker: separate expansion arithmetic, explicit equality scan,
// and separately constructed sign keys. It never reads producer symbols/maps.
pub(super) fn reconstruct(
    graph: &Graph,
    guards: &[boolean_guards::BooleanGuard],
) -> Result<Symbols, &'static str> {
    let mut forms = Vec::new();
    let mut retained = Vec::new();
    let mut products = Vec::new();
    let mut bit_table: BTreeMap<(Form, u8), usize> = BTreeMap::new();
    let mut product_table: BTreeMap<(Form, Form), Form> = BTreeMap::new();
    let modulo = |a: u64, b: u64| ((a as u128 * b as u128) % P as u128) as u64;
    let negate = |f: &Form| Form {
        constant: if f.constant == 0 { 0 } else { P - f.constant },
        terms: f.terms.iter().map(|&(i, c)| (i, P - c)).collect(),
    };
    for (i, node) in graph.nodes.iter().enumerate() {
        let guarded = guards.iter().any(|g| g.output_node == i);
        let mut keep = false;
        let value = if guarded {
            Form {
                constant: 0,
                terms: Vec::new(),
            }
        } else {
            match *node {
                Node::Linear(a, b, s) => {
                    affine::expand(&forms, &[(a, 1), (b, if s { P - 1 } else { 1 })])?
                }
                Node::Scale(a, c) => affine::expand(&forms, &[(a, c)])?,
                Node::Bit(a, bit) => {
                    if bit >= 64 {
                        return Err("invalid bit index");
                    }
                    let public_literal = match (a, &graph.public_bit_bindings) {
                        (Word::Wire(j), Some(values)) => match graph.nodes.get(j) {
                            Some(Node::Input(slot)) => values.get(*slot).copied(),
                            _ => None,
                        },
                        _ => None,
                    };
                    if let Some(value) = public_literal {
                        if value >= P {
                            return Err("noncanonical public bit binding");
                        }
                        forms.push(Form {
                            constant: (value / (1u64 << bit)) % 2,
                            terms: Vec::new(),
                        });
                        retained.push(false);
                        continue;
                    }
                    let source = affine::expand(&forms, &[(a, 1)])?;
                    let key = (source, bit);
                    let index = if let Some(j) = bit_table.get(&key) {
                        *j
                    } else {
                        bit_table.insert(key, i);
                        keep = true;
                        i
                    };
                    Form {
                        constant: 0,
                        terms: vec![(index, 1)],
                    }
                }
                Node::Product(a, b) => {
                    let mut lhs = affine::expand(&forms, &[(a, 1)])?;
                    let mut rhs = affine::expand(&forms, &[(b, 1)])?;
                    let mut sign = 1;
                    let inverse = negate(&lhs);
                    if inverse < lhs {
                        lhs = inverse;
                        sign = P - 1;
                    }
                    let inverse = negate(&rhs);
                    if inverse < rhs {
                        rhs = inverse;
                        sign = if sign == 1 { P - 1 } else { 1 };
                    }
                    if lhs > rhs {
                        let tmp = lhs;
                        lhs = rhs;
                        rhs = tmp;
                    }
                    let key = (lhs, rhs);
                    if let Some(v) = product_table.get(&key) {
                        Form {
                            constant: modulo(v.constant, sign),
                            terms: v.terms.iter().map(|&(j, c)| (j, modulo(c, sign))).collect(),
                        }
                    } else {
                        products.push(i);
                        let mut fixed_zero = false;
                        for &(a, b) in &graph.equalities {
                            if a == Word::Wire(i) && b == Word::Constant(0) {
                                fixed_zero = true;
                            }
                        }
                        let value = if fixed_zero {
                            Form {
                                constant: 0,
                                terms: Vec::new(),
                            }
                        } else {
                            keep = true;
                            Form {
                                constant: 0,
                                terms: vec![(i, 1)],
                            }
                        };
                        let normalized = Form {
                            constant: modulo(value.constant, sign),
                            terms: value
                                .terms
                                .iter()
                                .map(|&(j, c)| (j, modulo(c, sign)))
                                .collect(),
                        };
                        product_table.insert(key, normalized);
                        value
                    }
                }
                _ => {
                    keep = true;
                    Form {
                        constant: 0,
                        terms: vec![(i, 1)],
                    }
                }
            }
        };
        forms.push(value);
        retained.push(keep);
    }
    Ok(Symbols {
        forms,
        retained,
        products,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (HtlcAdapter, Vec<Word>) {
        let scope = Scope::start();
        let x = input();
        let y = input();
        let first = range(x, 8);
        let second = range(x, 8);
        let p = first[0] * (y - x);
        let negative = (x - y) * second[0];
        let duplicate = (y - x) * first[0];
        // Copied wire handles deliberately cancel in the source graph.
        let same_y = y;
        let zero = x * (y - same_y);
        equal(zero, Word::ZERO);
        let mut adapter = HtlcAdapter::from_graph(scope.finish());
        adapter.bind_public(x, 5);
        adapter.bind_public(y, 12);
        (
            adapter,
            vec![first[0], second[0], p, negative, duplicate, zero],
        )
    }
    #[test]
    fn source_cse_preserves_repeated_ranges_and_signed_commuted_products() {
        let (adapter, words) = fixture();
        let producer = build(&adapter.graph, &adapter.affine.guards);
        assert_eq!(
            producer,
            reconstruct(&adapter.graph, &adapter.affine.guards).unwrap()
        );
        assert_eq!(
            adapter
                .graph
                .nodes
                .iter()
                .filter(|n| matches!(n, Node::Bit(..)))
                .count(),
            16
        );
        assert_eq!(
            adapter
                .affine
                .committed_nodes
                .iter()
                .filter(|&&i| matches!(adapter.graph.nodes[i], Node::Bit(..)))
                .count(),
            8
        );
        assert_eq!(adapter.affine.source_products.len(), 2);
        adapter
            .check_source_lowering(&[Word::Wire(0), Word::Wire(1)], &[5, 12])
            .unwrap();
        let witness = adapter.evaluate(&[5, 12]).unwrap();
        adapter.verify_packed_witness(&witness).unwrap();
        let values: Vec<_> = words
            .iter()
            .map(|&w| adapter.graph_word_from_packed(w, &witness))
            .collect();
        assert_eq!(values, vec![1, 1, 7, P - 7, 7, 0]);
    }
    #[test]
    fn source_cse_certificate_rejects_alias_and_gate_schedule_mutations() {
        let (mut adapter, words) = fixture();
        adapter.affine.source_products.pop();
        assert!(adapter
            .check_source_lowering(&[Word::Wire(0), Word::Wire(1)], &[5, 12])
            .is_err());
        let (mut adapter, _) = fixture();
        let Word::Wire(i) = words[3] else {
            unreachable!()
        };
        adapter.affine.forms[i].terms[0].1 = 1;
        assert!(adapter
            .check_source_lowering(&[Word::Wire(0), Word::Wire(1)], &[5, 12])
            .is_err());
        let (mut adapter, _) = fixture();
        let Word::Wire(i) = words[1] else {
            unreachable!()
        };
        adapter.graph.nodes[i] = Node::Bit(Word::Wire(1), 0);
        assert!(adapter
            .check_source_lowering(&[Word::Wire(0), Word::Wire(1)], &[5, 12])
            .is_err());
    }
    #[test]
    fn zero_product_output_elimination_keeps_the_product_equation() {
        let scope = Scope::start();
        let x = input();
        let y = input();
        let z = x * y;
        equal(z, Word::ZERO);
        let adapter = HtlcAdapter::from_graph(scope.finish());
        assert_eq!(adapter.affine.committed_nodes.len(), 2);
        assert_eq!(adapter.affine.source_products.len(), 1);
        adapter.check_source_lowering::<0>(&[], &[]).unwrap();
        adapter
            .verify_packed_witness(&adapter.evaluate(&[0, 9]).unwrap())
            .unwrap();
        assert!(adapter
            .verify_packed_witness(&adapter.evaluate(&[1, 9]).unwrap())
            .is_err());
    }
    fn public_bit_fixture() -> (HtlcAdapter, Word, Word) {
        let scope = Scope::start();
        let public = input();
        let private = input();
        let public_bits = range(public, 8);
        let private_bits = range(private, 8);
        let mut adapter = HtlcAdapter::from_graph_with_public_bindings(scope.finish(), &[5]);
        adapter.bind_public(public, 5);
        (adapter, public_bits[0], private_bits[0])
    }
    #[test]
    fn public_bit_specialization_preserves_inputs_ranges_guards_and_private_bits() {
        let (adapter, public_bit, private_bit) = public_bit_fixture();
        adapter
            .check_source_lowering(&[Word::Wire(0)], &[5])
            .unwrap();
        let symbols = build(&adapter.graph, &adapter.affine.guards);
        assert_eq!(
            symbols,
            reconstruct(&adapter.graph, &adapter.affine.guards).unwrap()
        );
        assert_eq!(adapter.graph.ranges.len(), 2);
        assert_eq!(adapter.affine.guards.len(), 16);
        assert_eq!(
            adapter
                .graph
                .nodes
                .iter()
                .filter(|n| matches!(n, Node::Bit(..)))
                .count(),
            16
        );
        assert_eq!(
            adapter
                .affine
                .committed_nodes
                .iter()
                .filter(|&&i| matches!(adapter.graph.nodes[i], Node::Bit(..)))
                .count(),
            8
        );
        assert!(adapter.affine.graph_to_packed[0].is_some());
        assert!(adapter.affine.graph_to_packed[1].is_some());
        let Word::Wire(public_bit) = public_bit else {
            unreachable!()
        };
        let Word::Wire(private_bit) = private_bit else {
            unreachable!()
        };
        assert_eq!(adapter.affine.forms[public_bit].constant, 1);
        assert!(adapter.affine.forms[public_bit].terms.is_empty());
        assert!(!adapter.affine.forms[private_bit].terms.is_empty());
        let mut witness = adapter.evaluate(&[5, 19]).unwrap();
        adapter.verify_packed_witness(&witness).unwrap();
        let public_slot = adapter.affine.graph_to_packed[0].unwrap();
        witness[public_slot] = 4;
        assert!(adapter.verify_packed_witness(&witness).is_err());
    }
    #[test]
    fn public_bit_specialization_rejects_wrong_or_unbound_statement_and_literals() {
        let (mut adapter, _, _) = public_bit_fixture();
        adapter.graph.public_bit_bindings.as_mut().unwrap()[0] = 4;
        assert!(adapter
            .check_source_lowering(&[Word::Wire(0)], &[5])
            .is_err());
        let (adapter, _, _) = public_bit_fixture();
        assert!(adapter
            .check_source_lowering(&[Word::Wire(0)], &[4])
            .is_err());
        assert!(adapter
            .check_source_lowering(&[Word::Wire(1)], &[5])
            .is_err());
        let (mut adapter, _, _) = public_bit_fixture();
        adapter.graph.public_bit_bindings.as_mut().unwrap().clear();
        assert!(adapter
            .check_source_lowering(&[Word::Wire(0)], &[5])
            .is_err());
        let (mut adapter, _, _) = public_bit_fixture();
        adapter.graph.public_bit_bindings = None;
        assert!(adapter
            .check_source_lowering(&[Word::Wire(0)], &[5])
            .is_err());
        let (mut adapter, public_bit, _) = public_bit_fixture();
        let Word::Wire(i) = public_bit else {
            unreachable!()
        };
        adapter.affine.forms[i].constant = 0;
        assert!(adapter
            .check_source_lowering(&[Word::Wire(0)], &[5])
            .is_err());
        let (mut adapter, _, _) = public_bit_fixture();
        adapter.affine.guards.pop();
        assert!(adapter
            .check_source_lowering(&[Word::Wire(0)], &[5])
            .is_err());
        let (mut adapter, _, _) = public_bit_fixture();
        adapter.targets.pop();
        assert!(adapter
            .check_source_lowering(&[Word::Wire(0)], &[5])
            .is_err());
    }
    #[test]
    fn public_bit_specialization_does_not_fold_arbitrary_public_expressions() {
        let scope = Scope::start();
        let public = input();
        let bits = range(public + Word::ONE, 8);
        let mut adapter = HtlcAdapter::from_graph_with_public_bindings(scope.finish(), &[5]);
        adapter.bind_public(public, 5);
        adapter.check_source_lowering(&[public], &[5]).unwrap();
        for bit in bits {
            let Word::Wire(i) = bit else { unreachable!() };
            assert!(!adapter.affine.forms[i].terms.is_empty());
        }
        adapter
            .verify_packed_witness(&adapter.evaluate(&[5]).unwrap())
            .unwrap();
    }
    #[test]
    fn public_bit_specialization_retains_an_all_public_input_prefix() {
        let scope = Scope::start();
        let public = input();
        range(public, 8);
        let mut adapter = HtlcAdapter::from_graph_with_public_bindings(scope.finish(), &[5]);
        adapter.bind_public(public, 5);
        adapter.check_source_lowering(&[public], &[5]).unwrap();
        assert_eq!(adapter.affine.committed_nodes, vec![0]);
        assert!(adapter.affine.boolean_rows.is_empty());
        assert_eq!(adapter.affine.guards.len(), 8);
        adapter
            .verify_packed_witness(&adapter.evaluate(&[5]).unwrap())
            .unwrap();
    }
}
