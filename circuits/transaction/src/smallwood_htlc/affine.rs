//! Candidate affine elimination. Graph wire indices and committed slots differ.
//! Producer forms use BTreeMap accumulation; checker forms are independently
//! rebuilt in graph order with sorted sparse-vector normalization.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Form {
    pub(super) constant: u64,
    pub(super) terms: Vec<(usize, u64)>,
}
#[derive(Clone, Debug)]
pub(super) struct AffineMap {
    pub(super) committed_nodes: Vec<usize>,
    pub(super) graph_to_packed: Vec<Option<usize>>,
    pub(super) forms: Vec<Form>,
    pub(super) packed_nodes: Vec<Option<usize>>,
    pub(super) guards: Vec<boolean_guards::BooleanGuard>,
    pub(super) boolean_rows: Vec<usize>,
    pub(super) source_products: Vec<usize>,
}
impl AffineMap {
    pub(super) fn build(graph: &Graph) -> Self {
        let nodes = &graph.nodes;
        let guards = boolean_guards::discover(graph);
        let symbols = source_cse::build(graph, &guards);
        let bits: std::collections::BTreeSet<_> = guards
            .iter()
            .filter_map(|g| {
                let Word::Wire(i) = g.source else {
                    unreachable!()
                };
                let form = &symbols.forms[i];
                if form.terms.is_empty() {
                    assert!(form.constant <= 1, "literal Boolean source");
                    return None;
                }
                assert_eq!(form.constant, 0);
                assert_eq!(form.terms.len(), 1);
                assert_eq!(form.terms[0].1, 1);
                Some(form.terms[0].0)
            })
            .collect();
        let mut product_positions = vec![None; nodes.len()];
        let mut zero_count = 0usize;
        let mut nonzero_count = 0usize;
        for &node in &symbols.products {
            let output = &symbols.forms[node];
            if output.constant == 0 && output.terms.is_empty() {
                zero_count += 1;
            } else {
                product_positions[node] = Some(nonzero_count);
                nonzero_count += 1;
            }
        }
        let zero_rows = 2 * zero_count.div_ceil(PACKING);
        let mut packed_nodes = Vec::new();
        let mut boolean_rows = Vec::new();
        // Preserve the complete original input prefix, including public inputs.
        if !bits.is_empty() {
            packed_nodes.extend(
                nodes
                    .iter()
                    .enumerate()
                    .filter_map(|(i, n)| matches!(n, Node::Input(..)).then_some(Some(i))),
            );
            packed_nodes.resize(packed_nodes.len().div_ceil(PACKING) * PACKING, None);
            let start = packed_nodes.len() / PACKING;
            packed_nodes.extend(bits.iter().copied().map(Some));
            packed_nodes.resize(packed_nodes.len().div_ceil(PACKING) * PACKING, None);
            boolean_rows.extend(start..packed_nodes.len() / PACKING);
        }
        for (i, node) in nodes.iter().enumerate() {
            if !symbols.retained[i]
                || (matches!(
                    node,
                    Node::PoseidonOutput { .. } | Node::CompactShaOutput { .. }
                ) && !bits.contains(&i))
                || (product_positions[i].is_some() && !bits.contains(&i))
                || (!bits.is_empty() && (matches!(node, Node::Input(..)) || bits.contains(&i)))
            {
                continue;
            }
            packed_nodes.push(Some(i));
        }
        let committed_nodes = packed_nodes.iter().filter_map(|i| *i).collect();
        let mut graph_to_packed = vec![None; nodes.len()];
        for (slot, node) in packed_nodes.iter().enumerate() {
            if let Some(i) = node {
                graph_to_packed[*i] = Some(slot);
            }
        }
        let mut map = Self {
            committed_nodes,
            graph_to_packed,
            forms: vec![],
            packed_nodes,
            guards,
            boolean_rows,
            source_products: symbols.products.clone(),
        };
        // CSE symbols are affine forms over representative GRAPH node IDs.
        // Substitute complete authenticated trace forms for every representative,
        // including downstream linear forms that refer to a hash output.
        let product_rows = zero_rows + 3 * nonzero_count.div_ceil(PACKING);
        let mut direct_counts = [0usize; 4];
        for node in nodes {
            if let Node::Boolean(gate) = node {
                let kind = match gate.kind {
                    sha_lowering::Kind::Xor => 0,
                    sha_lowering::Kind::And => 1,
                    sha_lowering::Kind::Parity => 2,
                    sha_lowering::Kind::Majority => 3,
                };
                direct_counts[kind] += 1;
            }
        }
        let direct_rows: usize = direct_counts.iter().map(|n| 4 * n.div_ceil(PACKING)).sum();
        let poseidon_start = map.canonical_slots().div_ceil(PACKING) + product_rows + direct_rows;
        let sha_start = poseidon_start
            + if graph.packed_poseidon_calls.is_empty() {
                0
            } else {
                packed_poseidon::ROWS
            };
        for form in symbols.forms {
            let mut terms = BTreeMap::new();
            for (i, coefficient) in form.terms {
                let cells: Vec<(usize, u64)> = if let Some(slot) = map.graph_to_packed[i] {
                    vec![(slot, 1)]
                } else {
                    match nodes[i] {
                        Node::Product(..) => {
                            let position = product_positions[i].expect("retained source product");
                            vec![(
                                (map.canonical_slots().div_ceil(PACKING)
                                    + zero_rows
                                    + 3 * (position / PACKING))
                                    * PACKING
                                    + position % PACKING,
                                1,
                            )]
                        }
                        Node::PoseidonOutput { call, lane } => {
                            vec![(packed_poseidon::final_index(poseidon_start, call, lane), 1)]
                        }
                        Node::CompactShaOutput { call, lane } => (0..32)
                            .map(|bit| {
                                let stash = 64 + 32 * lane + bit;
                                (
                                    ((sha_start
                                        + call * compact_sha256::TRACE_ROWS
                                        + 260
                                        + stash / 16)
                                        * PACKING
                                        + stash % 16),
                                    1u64 << bit,
                                )
                            })
                            .collect(),
                        _ => panic!("non-trace source representative unretained"),
                    }
                };
                for (slot, weight) in cells {
                    let prior = terms.get(&slot).copied().unwrap_or(0);
                    terms.insert(slot, add(prior, mul(coefficient, weight)));
                }
            }
            map.forms.push(Form {
                constant: form.constant,
                terms: terms.into_iter().filter(|(_, c)| *c != 0).collect(),
            });
        }
        map
    }
    pub(super) fn canonical_slots(&self) -> usize {
        self.packed_nodes.len()
    }
    pub(super) fn ordinary_products(&self, graph: &Graph) -> Vec<(Word, Word, Word)> {
        self.source_products
            .iter()
            .map(|&i| {
                let Node::Product(a, b) = graph.nodes[i] else {
                    unreachable!()
                };
                (Word::Wire(i), a, b)
            })
            .collect()
    }
    pub(super) fn combine(&self, terms: &[(Word, u64)]) -> Form {
        let mut constant = 0;
        let mut sparse = BTreeMap::new();
        for &(word, coefficient) in terms {
            match word {
                Word::Constant(value) => constant = add(constant, mul(coefficient, value)),
                Word::Wire(index) => {
                    let source = &self.forms[index];
                    constant = add(constant, mul(coefficient, source.constant));
                    for &(slot, value) in &source.terms {
                        let prior = sparse.get(&slot).copied().unwrap_or(0);
                        sparse.insert(slot, add(prior, mul(coefficient, value)));
                    }
                }
            }
        }
        Form {
            constant,
            terms: sparse.into_iter().filter(|(_, c)| *c != 0).collect(),
        }
    }
}

fn checked_add(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % P as u128) as u64
}
fn checked_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % P as u128) as u64
}
fn normalize(mut terms: Vec<(usize, u64)>) -> Vec<(usize, u64)> {
    terms.sort_unstable_by_key(|t| t.0);
    let mut out: Vec<(usize, u64)> = Vec::new();
    for (slot, value) in terms {
        if let Some(last) = out.last_mut().filter(|last| last.0 == slot) {
            last.1 = checked_add(last.1, value);
        } else {
            out.push((slot, value));
        }
    }
    out.retain(|(_, c)| *c != 0);
    out
}
pub(super) fn expand(forms: &[Form], terms: &[(Word, u64)]) -> Result<Form, &'static str> {
    let mut result = Form {
        constant: 0,
        terms: Vec::new(),
    };
    for &(word, coefficient) in terms {
        if coefficient >= P {
            return Err("affine coefficient is noncanonical");
        }
        match word {
            Word::Constant(value) => {
                if value >= P {
                    return Err("affine constant is noncanonical");
                }
                result.constant = checked_add(result.constant, checked_mul(value, coefficient));
            }
            Word::Wire(index) => {
                let source = forms
                    .get(index)
                    .ok_or("affine source does not precede node")?;
                result.constant =
                    checked_add(result.constant, checked_mul(source.constant, coefficient));
                result.terms.extend(
                    source
                        .terms
                        .iter()
                        .map(|&(slot, value)| (slot, checked_mul(value, coefficient))),
                );
            }
        }
    }
    result.terms = normalize(result.terms);
    Ok(result)
}
/// Independently reconstruct both the compact slot map and every affine form.
/// No producer form or producer map is used to derive the expected values.
pub(super) fn reconstruct(graph: &Graph, actual: &AffineMap) -> Result<Vec<Form>, &'static str> {
    boolean_guards::check(graph, &actual.guards)?;
    let nodes = &graph.nodes;
    let symbols = source_cse::reconstruct(graph, &actual.guards)?;
    let mut bit = vec![false; nodes.len()];
    for guard in &actual.guards {
        let Word::Wire(i) = guard.source else {
            return Err("nonwire Boolean source");
        };
        let form = &symbols.forms[i];
        if form.terms.is_empty() {
            if form.constant > 1 {
                return Err("nonboolean literal source");
            }
            continue;
        }
        if form.constant != 0 || form.terms.len() != 1 || form.terms[0].1 != 1 {
            return Err("invalid Boolean representative");
        }
        bit[form.terms[0].0] = true;
    }
    let mut product_positions = vec![None; nodes.len()];
    let mut zero_count = 0usize;
    let mut nonzero_count = 0usize;
    for &node in &symbols.products {
        let output = symbols
            .forms
            .get(node)
            .ok_or("source product out of range")?;
        if output.constant == 0 && output.terms.is_empty() {
            zero_count = zero_count
                .checked_add(1)
                .ok_or("zero product count overflow")?;
        } else {
            let slot = product_positions
                .get_mut(node)
                .ok_or("source product out of range")?;
            if slot.replace(nonzero_count).is_some() {
                return Err("duplicate source product representative");
            }
            nonzero_count = nonzero_count
                .checked_add(1)
                .ok_or("nonzero product count overflow")?;
        }
    }

    let has_bits = bit.iter().any(|v| *v);
    let mut slots = Vec::new();
    let mut boolean_rows = Vec::new();
    if has_bits {
        for (i, n) in nodes.iter().enumerate() {
            if matches!(n, Node::Input(..)) {
                slots.push(Some(i));
            }
        }
        while slots.len() % PACKING != 0 {
            slots.push(None);
        }
        let first = slots.len() / PACKING;
        for (i, is_bit) in bit.iter().enumerate() {
            if *is_bit {
                slots.push(Some(i));
            }
        }
        while slots.len() % PACKING != 0 {
            slots.push(None);
        }
        for row in first..slots.len() / PACKING {
            boolean_rows.push(row);
        }
    }
    for (i, n) in nodes.iter().enumerate() {
        if symbols.retained[i]
            && !(matches!(
                n,
                Node::PoseidonOutput { .. } | Node::CompactShaOutput { .. }
            ) && !bit[i])
            && !(product_positions[i].is_some() && !bit[i])
            && !(has_bits && (matches!(n, Node::Input(..)) || bit[i]))
        {
            slots.push(Some(i));
        }
    }
    let mut mapping = vec![None; nodes.len()];
    let mut kept = vec![];
    for (slot, node) in slots.iter().enumerate() {
        if let Some(i) = node {
            mapping[*i] = Some(slot);
            kept.push(*i);
        }
    }
    // Independent physical layout uses only the independently reconstructed
    // representative product catalogue, never producer source_products/forms.
    let prefix = slots.len().checked_add(63).ok_or("trace prefix overflow")? / 64;
    let zero_groups = zero_count
        .checked_add(63)
        .ok_or("zero product count overflow")?
        / 64;
    let nonzero_groups = nonzero_count
        .checked_add(63)
        .ok_or("nonzero product count overflow")?
        / 64;
    let zero_rows = zero_groups
        .checked_mul(2)
        .ok_or("zero product row overflow")?;
    let nonzero_base = prefix
        .checked_add(zero_rows)
        .ok_or("nonzero product base overflow")?;
    let mut poseidon_base = nonzero_base
        .checked_add(
            nonzero_groups
                .checked_mul(3)
                .ok_or("nonzero product row overflow")?,
        )
        .ok_or("trace base overflow")?;

    let mut direct = [0usize; 4];
    for node in nodes {
        if let Node::Boolean(gate) = node {
            match gate.kind {
                sha_lowering::Kind::Xor => direct[0] += 1,
                sha_lowering::Kind::And => direct[1] += 1,
                sha_lowering::Kind::Parity => direct[2] += 1,
                sha_lowering::Kind::Majority => direct[3] += 1,
            }
        }
    }
    for count in direct {
        let groups = count.checked_add(63).ok_or("trace direct overflow")? / 64;
        poseidon_base = poseidon_base
            .checked_add(groups.checked_mul(4).ok_or("trace direct overflow")?)
            .ok_or("trace direct overflow")?;
    }
    let sha_base = poseidon_base
        .checked_add(if graph.packed_poseidon_calls.is_empty() {
            0
        } else {
            364
        })
        .ok_or("trace SHA overflow")?;
    let mut forms = Vec::with_capacity(nodes.len());
    for source in &symbols.forms {
        let mut terms = Vec::new();
        for &(i, coefficient) in &source.terms {
            if coefficient >= P {
                return Err("trace source coefficient noncanonical");
            }
            if let Some(slot) = mapping.get(i).copied().flatten() {
                terms.push((slot, coefficient));
                continue;
            }
            match nodes
                .get(i)
                .ok_or("trace source representative out of range")?
            {
                Node::Product(..) => {
                    let position = product_positions
                        .get(i)
                        .copied()
                        .flatten()
                        .ok_or("unretained source product representative")?;
                    let row = nonzero_base
                        .checked_add(
                            (position / 64)
                                .checked_mul(3)
                                .ok_or("product output row overflow")?,
                        )
                        .ok_or("product output row overflow")?;
                    let slot = row
                        .checked_mul(64)
                        .and_then(|r| r.checked_add(position % 64))
                        .ok_or("product output slot overflow")?;
                    terms.push((slot, coefficient));
                }
                Node::PoseidonOutput { call, lane } => {
                    if *call >= graph.packed_poseidon_calls.len() || *lane >= 16 {
                        return Err("trace Poseidon output out of range");
                    }
                    let row = poseidon_base
                        .checked_add(
                            (call / 64)
                                .checked_mul(182)
                                .ok_or("trace Poseidon overflow")?,
                        )
                        .and_then(|r| r.checked_add(166 + lane))
                        .ok_or("trace Poseidon overflow")?;
                    let slot = row
                        .checked_mul(64)
                        .and_then(|r| r.checked_add(call % 64))
                        .ok_or("trace Poseidon overflow")?;
                    terms.push((slot, coefficient));
                }
                Node::CompactShaOutput { call, lane } => {
                    if *call >= graph.compact_sha_calls.len() || *call >= 1 || *lane >= 8 {
                        return Err("trace SHA output out of range");
                    }
                    for b in 0..32 {
                        let offset = 64 + lane * 32 + b;
                        let row = sha_base
                            .checked_add(call * 297)
                            .and_then(|r| r.checked_add(260 + offset / 16))
                            .ok_or("trace SHA overflow")?;
                        let slot = row
                            .checked_mul(64)
                            .and_then(|r| r.checked_add(offset % 16))
                            .ok_or("trace SHA overflow")?;
                        terms.push((slot, checked_mul(coefficient, 1u64 << b)));
                    }
                }
                _ => return Err("unretained non-trace source representative"),
            }
        }
        forms.push(Form {
            constant: source.constant,
            terms: normalize(terms),
        });
    }
    if kept != actual.committed_nodes
        || mapping != actual.graph_to_packed
        || forms != actual.forms
        || slots != actual.packed_nodes
        || boolean_rows != actual.boolean_rows
        || symbols.products != actual.source_products
    {
        return Err("affine/Boolean source map mismatch");
    }
    Ok(forms)
}

pub(super) struct SourceRows<'a> {
    adapter: &'a HtlcAdapter,
    forms: Vec<Form>,
    row: usize,
    entry: usize,
    packed_len: usize,
}
impl<'a> SourceRows<'a> {
    pub(super) fn new(adapter: &'a HtlcAdapter, forms: Vec<Form>, packed_len: usize) -> Self {
        Self {
            adapter,
            forms,
            row: 0,
            entry: 0,
            packed_len,
        }
    }
    fn check(&mut self, terms: Vec<(usize, u64)>, rhs: u64) -> Result<(), &'static str> {
        let terms = normalize(terms);
        if rhs >= P
            || terms
                .iter()
                .any(|&(slot, c)| slot >= self.packed_len || c >= P)
        {
            return Err("expanded CSR term out of range");
        }
        if terms.is_empty() && rhs == 0 {
            return Ok(());
        }
        if self
            .adapter
            .offsets
            .get(self.row)
            .copied()
            .map(|x| x as usize)
            != Some(self.entry)
            || self.adapter.targets.get(self.row) != Some(&rhs)
        {
            return Err("expanded CSR row mismatch");
        }
        for (slot, coefficient) in terms {
            if self
                .adapter
                .indices
                .get(self.entry)
                .copied()
                .map(|x| x as usize)
                != Some(slot)
                || self.adapter.coefficients.get(self.entry) != Some(&coefficient)
            {
                return Err("expanded CSR term mismatch");
            }
            self.entry += 1;
        }
        self.row += 1;
        if self
            .adapter
            .offsets
            .get(self.row)
            .copied()
            .map(|x| x as usize)
            != Some(self.entry)
        {
            return Err("expanded CSR end mismatch");
        }
        Ok(())
    }
    pub(super) fn source(
        &mut self,
        terms: &[(Word, u64)],
        target: u64,
    ) -> Result<(), &'static str> {
        let form = expand(&self.forms, terms)?;
        if target >= P {
            return Err("expanded CSR target noncanonical");
        }
        let rhs = ((target as u128 + P as u128 - form.constant as u128) % P as u128) as u64;
        self.check(form.terms, rhs)
    }
    pub(super) fn copy(&mut self, slot: usize, source: Word) -> Result<(), &'static str> {
        let form = expand(&self.forms, &[(source, P - 1)])?;
        let mut terms = form.terms;
        terms.push((slot, 1));
        let rhs = if form.constant == 0 {
            0
        } else {
            P - form.constant
        };
        self.check(terms, rhs)
    }
    pub(super) fn mixed(
        &mut self,
        packed: &[(usize, u64)],
        source: &[(Word, u64)],
        target: u64,
    ) -> Result<(), &'static str> {
        if target >= P {
            return Err("mixed CSR target noncanonical");
        }
        let form = expand(&self.forms, source)?;
        let mut terms = form.terms;
        terms.extend_from_slice(packed);
        let rhs = ((target as u128 + P as u128 - form.constant as u128) % P as u128) as u64;
        self.check(terms, rhs)
    }
    pub(super) fn zero(&mut self, slot: usize) -> Result<(), &'static str> {
        self.check(vec![(slot, 1)], 0)
    }
    pub(super) fn finish(&self) -> Result<(), &'static str> {
        if self.row == self.adapter.targets.len() && self.entry == self.adapter.indices.len() {
            Ok(())
        } else {
            Err("expanded CSR has omitted or extra rows")
        }
    }
}

impl HtlcAdapter {
    // Only graph operands are accepted here; occurrence indices use the APIs below.
    pub(super) fn linear(&mut self, terms: &[(Word, u64)], target: u64) {
        let form = self.affine.combine(terms);
        self.linear_committed(&form.terms, sub(target, form.constant));
    }
    pub(super) fn linear_committed(&mut self, terms: &[(usize, u64)], target: u64) {
        let mut normalized = BTreeMap::new();
        for &(slot, coefficient) in terms {
            let old = normalized.get(&slot).copied().unwrap_or(0);
            normalized.insert(slot, add(old, coefficient));
        }
        normalized.retain(|_, c| *c != 0);
        if normalized.is_empty() && target == 0 {
            return;
        }
        for (slot, coefficient) in normalized {
            self.indices
                .push(u32::try_from(slot).expect("source-owned packed slot fits u32"));
            self.coefficients.push(coefficient);
        }
        self.targets.push(target);
        self.offsets.push(self.indices.len() as u32);
    }
    pub(super) fn copy_to_packed(&mut self, slot: usize, source: Word) {
        let form = self.affine.combine(&[(source, P - 1)]);
        let mut terms = form.terms;
        terms.push((slot, 1));
        self.linear_committed(&terms, sub(0, form.constant));
    }
    pub fn source_graph_node_count(&self) -> usize {
        self.graph.nodes.len()
    }
    pub fn affine_eliminated_node_count(&self) -> usize {
        self.graph.nodes.len() - self.affine.committed_nodes.len()
    }
    pub fn trace_output_aliased_node_count(&self) -> usize {
        self.graph
            .nodes
            .iter()
            .enumerate()
            .filter(|(i, node)| {
                matches!(
                    node,
                    Node::PoseidonOutput { .. } | Node::CompactShaOutput { .. }
                ) && self.affine.graph_to_packed[*i].is_none()
            })
            .count()
    }
    pub fn product_output_aliased_node_count(&self) -> usize {
        self.affine
            .source_products
            .iter()
            .filter(|&&i| {
                self.affine.graph_to_packed[i].is_none() && !self.affine.forms[i].terms.is_empty()
            })
            .count()
    }
    #[cfg(test)]
    pub(crate) fn graph_word_from_packed(&self, word: Word, packed: &[u64]) -> u64 {
        let form = self.affine.combine(&[(word, 1)]);
        form.terms.iter().fold(form.constant, |sum, &(slot, c)| {
            add(sum, mul(c, packed[slot]))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> HtlcAdapter {
        let scope = Scope::start();
        let x = input();
        let y = input();
        let translated = x + Word::Constant(3);
        let scaled = translated * Word::Constant(7);
        let product = scaled * y;
        equal(product, Word::Constant(126));
        let mut adapter = HtlcAdapter::from_graph(scope.finish());
        adapter.bind_public(x, 3);
        adapter.bind_public(y, 3);
        adapter
    }
    #[test]
    fn affine_slots_preserve_nonlinear_source_and_witness() {
        let adapter = fixture();
        assert_eq!(adapter.source_graph_node_count(), 5);
        assert_eq!(adapter.geometry.canonical_wires, 2);
        assert_eq!(
            adapter.affine.graph_to_packed,
            vec![Some(0), Some(1), None, None, None]
        );
        adapter
            .check_source_lowering(&[Word::Wire(0), Word::Wire(1)], &[3, 3])
            .unwrap();
        let witness = adapter.evaluate(&[3, 3]).unwrap();
        assert_eq!(&witness[..2], &[3, 3]);
        assert_eq!(adapter.graph_word_from_packed(Word::Wire(4), &witness), 126);
        adapter.verify_packed_witness(&witness).unwrap();
        let mut bad = witness.clone();
        bad[2] = 127;
        assert!(adapter.verify_packed_witness(&bad).is_err());
        let mut bad = witness;
        bad[PACKING + 1] = 127;
        assert!(adapter.verify_packed_witness(&bad).is_err());
    }
    #[test]
    fn independent_affine_certificate_rejects_form_mapping_and_source_mutation() {
        let mut a = fixture();
        a.affine.graph_to_packed[4] = Some(1);
        assert!(a
            .check_source_lowering(&[Word::Wire(0), Word::Wire(1)], &[3, 3])
            .is_err());
        let mut a = fixture();
        a.affine.forms[3].constant = 22;
        assert!(a
            .check_source_lowering(&[Word::Wire(0), Word::Wire(1)], &[3, 3])
            .is_err());
        let mut a = fixture();
        a.graph.nodes[3] = Node::Scale(Word::Wire(2), 8);
        assert!(a
            .check_source_lowering(&[Word::Wire(0), Word::Wire(1)], &[3, 3])
            .is_err());
        let mut a = fixture();
        a.coefficients[0] = add(a.coefficients[0], 1);
        assert!(a
            .check_source_lowering(&[Word::Wire(0), Word::Wire(1)], &[3, 3])
            .is_err());
    }
}

#[cfg(test)]
mod trace_output_tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn fixture() -> (
        HtlcAdapter,
        [Word; 256],
        [u64; 256],
        [Word; 16],
        [Word; 8],
        Word,
    ) {
        let scope = Scope::start();
        let inputs: [Word; 256] = core::array::from_fn(|_| input());
        let mut state = [inputs[0]; 16];
        for _ in 0..128 {
            state = record_poseidon2(state);
        }
        let digest = sha256_compact(inputs);
        let zero_guard = inputs[2] * state[0];
        equal(zero_guard, Word::ZERO);
        let expression = state[0] * Word::Constant(7) + digest[0];
        let product = expression * state[0];
        let bytes: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        let bits = core::array::from_fn(|i| u64::from((bytes[i / 8] >> (i % 8)) & 1));
        let mut adapter = HtlcAdapter::from_graph(scope.finish());
        for (word, value) in inputs.into_iter().zip(bits) {
            adapter.bind_public(word, value);
        }
        adapter.check_source_lowering(&inputs, &bits).unwrap();
        (adapter, inputs, bits, state, digest, product)
    }

    #[test]
    fn trace_output_aliases_preserve_values_and_authenticate_all_families() {
        let (adapter, _, bits, state, digest, product) = fixture();
        assert_eq!(adapter.trace_output_aliased_node_count(), 2056);
        assert_eq!(adapter.geometry.canonical_wires, 256);
        assert_eq!(adapter.product_output_aliased_node_count(), 1);
        assert_eq!(adapter.geometry.rows, 4 + 2 + 3 + 364 + 297);
        assert_eq!(adapter.geometry.degree, 7);
        let witness = adapter.evaluate(&bits).unwrap();
        adapter.verify_packed_witness(&witness).unwrap();
        let mut expected_state = [bits[0]; 16];
        for call in 0..128 {
            let trace = packed_poseidon::native_trace(expected_state).unwrap();
            expected_state = core::array::from_fn(|lane| trace[166 + lane]);
            for lane in 0..16 {
                let word = adapter.graph.packed_poseidon_calls[call].output[lane];
                let Word::Wire(index) = word else {
                    unreachable!()
                };
                assert!(adapter.affine.graph_to_packed[index].is_none());
                assert_eq!(
                    adapter.graph_word_from_packed(word, &witness),
                    expected_state[lane]
                );
            }
        }
        assert_eq!(
            adapter.graph_word_from_packed(state[0], &witness),
            expected_state[0]
        );
        let bytes: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        let expected = Sha256::digest(bytes);
        let expected_words: [u64; 8] = core::array::from_fn(|i| {
            u64::from(u32::from_le_bytes(
                expected[i * 4..i * 4 + 4].try_into().unwrap(),
            ))
        });
        for lane in 0..8 {
            assert_eq!(
                adapter.graph_word_from_packed(digest[lane], &witness),
                expected_words[lane]
            );
        }
        assert_eq!(
            adapter.graph_word_from_packed(product, &witness),
            mul(
                add(mul(expected_state[0], 7), expected_words[0]),
                expected_state[0]
            )
        );
        for call in [0, 63, 64, 127] {
            for lane in [0, 15] {
                let Word::Wire(index) = adapter.graph.packed_poseidon_calls[call].output[lane]
                else {
                    unreachable!()
                };
                let slot = adapter.affine.forms[index].terms[0].0;
                let mut changed = witness.clone();
                changed[slot] = add(changed[slot], 1);
                assert!(adapter.verify_packed_witness(&changed).is_err());
            }
        }
        for word in digest {
            let Word::Wire(index) = word else {
                unreachable!()
            };
            assert!(adapter.affine.graph_to_packed[index].is_none());
            assert_eq!(adapter.affine.forms[index].terms.len(), 32);
            for bit in [0, 31] {
                let mut changed = witness.clone();
                let slot = adapter.affine.forms[index].terms[bit].0;
                changed[slot] = add(changed[slot], 1);
                assert!(adapter.verify_packed_witness(&changed).is_err());
            }
        }
    }

    #[test]
    fn trace_output_certificate_rejects_wrong_aliases_and_malformed_sources() {
        let (mut bad, inputs, bits, state, _, _) = fixture();
        let Word::Wire(index) = state[0] else {
            unreachable!()
        };
        bad.affine.forms[index].terms[0].0 += 1;
        assert!(bad.check_source_lowering(&inputs, &bits).is_err());
        let (mut bad, inputs, bits, _, digest, _) = fixture();
        let Word::Wire(index) = digest[0] else {
            unreachable!()
        };
        bad.affine.forms[index].terms[0].1 = 2;
        assert!(bad.check_source_lowering(&inputs, &bits).is_err());
        let (mut bad, inputs, bits, state, _, _) = fixture();
        let Word::Wire(index) = state[0] else {
            unreachable!()
        };
        bad.affine.graph_to_packed[index] = Some(0);
        assert!(bad.check_source_lowering(&inputs, &bits).is_err());
        let (mut bad, inputs, bits, state, _, _) = fixture();
        let Word::Wire(index) = state[0] else {
            unreachable!()
        };
        bad.graph.nodes[index] = Node::PoseidonOutput {
            call: usize::MAX,
            lane: 0,
        };
        assert!(bad.check_source_lowering(&inputs, &bits).is_err());
        let (mut bad, inputs, bits, _, digest, _) = fixture();
        let Word::Wire(index) = digest[0] else {
            unreachable!()
        };
        bad.graph.nodes[index] = Node::CompactShaOutput {
            call: 0,
            lane: usize::MAX,
        };
        assert!(bad.check_source_lowering(&inputs, &bits).is_err());
    }

    #[test]
    fn trace_output_aliases_retain_ordinary_boolean_guards() {
        let scope = Scope::start();
        let x = input();
        let mut state = [x; 16];
        for _ in 0..128 {
            state = record_poseidon2(state);
        }
        boolean(state[0]);
        let mut adapter = HtlcAdapter::from_graph(scope.finish());
        adapter.bind_public(x, 1);
        adapter.check_source_lowering(&[x], &[1]).unwrap();
        let Word::Wire(index) = state[0] else {
            unreachable!()
        };
        // discover() groups Bit sources only. A hash-output Boolean check
        // remains an ordinary product/equality guard, and must not disappear.
        assert!(adapter.affine.graph_to_packed[index].is_none());
        assert_eq!(adapter.trace_output_aliased_node_count(), 2048);
        assert_eq!(adapter.affine.forms[index].terms.len(), 1);
        assert!(adapter.affine.boolean_rows.is_empty());
        assert_eq!(adapter.affine.source_products.len(), 1);
        let guard = adapter.affine.source_products[0];
        assert!(adapter
            .graph
            .equalities
            .contains(&(Word::Wire(guard), Word::ZERO)));
        let witness = adapter.evaluate(&[1]).unwrap();
        let value = adapter.graph_word_from_packed(state[0], &witness);
        assert!(
            value > 1,
            "fixed native hash fixture must exercise a non-Boolean output"
        );
        assert!(adapter.verify_packed_witness(&witness).is_err());
    }
}

#[cfg(test)]
mod product_output_tests {
    use super::*;

    fn fixture() -> (HtlcAdapter, [Word; 2]) {
        let scope = Scope::start();
        let inputs = [input(), input()];
        for i in 0..65 {
            let _ = inputs[0] * (inputs[1] + Word::Constant(i));
        }
        let mut adapter = HtlcAdapter::from_graph(scope.finish());
        adapter.bind_public(inputs[0], 3);
        adapter.bind_public(inputs[1], 5);
        adapter.check_source_lowering(&inputs, &[3, 5]).unwrap();
        (adapter, inputs)
    }

    #[test]
    fn product_outputs_reuse_authenticated_occurrences_and_bind_padding() {
        let (adapter, _) = fixture();
        assert_eq!(adapter.affine.source_products.len(), 65);
        assert_eq!(adapter.product_output_aliased_node_count(), 65);
        assert_eq!(adapter.geometry.canonical_wires, 2);
        assert_eq!(adapter.geometry.rows, 1 + 6);
        let witness = adapter.evaluate(&[3, 5]).unwrap();
        adapter.verify_packed_witness(&witness).unwrap();
        for (position, &node) in adapter.affine.source_products.iter().enumerate() {
            let expected_slot = (1 + 3 * (position / 64)) * 64 + position % 64;
            assert_eq!(adapter.affine.forms[node].terms, vec![(expected_slot, 1)]);
            assert_eq!(
                adapter.graph_word_from_packed(Word::Wire(node), &witness),
                3 * (5 + position as u64)
            );
        }
        // Every original gate and every duplicate padding occurrence remains bound.
        for index in 64..witness.len() {
            let mut changed = witness.clone();
            changed[index] = add(changed[index], 1);
            assert!(
                adapter.verify_packed_witness(&changed).is_err(),
                "unbound slot {index}"
            );
        }
    }

    #[test]
    fn product_output_alias_certificate_rejects_catalogue_slot_and_coefficient_mutations() {
        let (mut bad, inputs) = fixture();
        bad.affine.source_products.swap(0, 1);
        assert!(bad.check_source_lowering(&inputs, &[3, 5]).is_err());
        let (mut bad, inputs) = fixture();
        let index = bad.affine.source_products[64];
        bad.affine.forms[index].terms[0].0 += 1;
        assert!(bad.check_source_lowering(&inputs, &[3, 5]).is_err());
        let (mut bad, inputs) = fixture();
        let index = bad.affine.source_products[0];
        bad.affine.forms[index].terms[0].1 = 2;
        assert!(bad.check_source_lowering(&inputs, &[3, 5]).is_err());
        let (mut bad, inputs) = fixture();
        let index = bad.affine.source_products[0];
        bad.affine.graph_to_packed[index] = Some(0);
        assert!(bad.check_source_lowering(&inputs, &[3, 5]).is_err());
    }

    #[test]
    fn product_output_aliases_retain_ordinary_boolean_guards() {
        let scope = Scope::start();
        let a = input();
        let b = input();
        let product = a * b;
        boolean(product);
        let mut adapter = HtlcAdapter::from_graph(scope.finish());
        adapter.bind_public(a, 1);
        adapter.bind_public(b, 1);
        adapter.check_source_lowering(&[a, b], &[1, 1]).unwrap();
        // Both p=a*b and the p*(p-1)=0 Boolean guard remain authenticated
        // ordinary products; only their duplicate canonical cells are absent.
        assert_eq!(adapter.affine.source_products.len(), 2);
        assert_eq!(adapter.product_output_aliased_node_count(), 1);
        let Word::Wire(index) = product else {
            unreachable!()
        };
        assert!(adapter.affine.graph_to_packed[index].is_none());
        assert!(adapter.affine.boolean_rows.is_empty());
        let guard = adapter.affine.source_products[1];
        assert!(adapter
            .graph
            .equalities
            .contains(&(Word::Wire(guard), Word::ZERO)));
        let witness = adapter.evaluate(&[1, 1]).unwrap();
        adapter.verify_packed_witness(&witness).unwrap();
        let mut changed = witness;
        let slot = adapter.affine.forms[index].terms[0].0;
        changed[slot] = 2;
        assert!(adapter.verify_packed_witness(&changed).is_err());
    }
}

#[cfg(test)]
mod mixed_zero_alias_tests {
    use super::*;

    fn fixture() -> (HtlcAdapter, [Word; 2], Vec<(Word, Word)>) {
        let scope = Scope::start();
        let inputs = [input(), input()];
        let mut outputs = Vec::new();
        for i in 0..65 {
            let zero = inputs[0] * (inputs[1] + Word::Constant(i));
            equal(zero, Word::ZERO);
            let nonzero = inputs[1] * (inputs[1] + Word::Constant(66 + i));
            outputs.push((zero, nonzero));
        }
        let mut adapter = HtlcAdapter::from_graph(scope.finish());
        adapter.bind_public(inputs[0], 0);
        adapter.bind_public(inputs[1], 5);
        adapter.check_source_lowering(&inputs, &[0, 5]).unwrap();
        (adapter, inputs, outputs)
    }

    #[test]
    fn mixed_zero_two_row_and_nonzero_output_aliases_bind_group_boundaries() {
        let (adapter, _, outputs) = fixture();
        assert_eq!(adapter.affine.source_products.len(), 130);
        assert_eq!(adapter.product_output_aliased_node_count(), 65);
        assert_eq!(adapter.geometry.canonical_wires, 2);
        assert_eq!(adapter.geometry.rows, 1 + 4 + 6);
        let witness = adapter.evaluate(&[0, 5]).unwrap();
        adapter.verify_packed_witness(&witness).unwrap();
        for (j, &(zero, nonzero)) in outputs.iter().enumerate() {
            let Word::Wire(zero_node) = zero else {
                unreachable!()
            };
            let Word::Wire(nonzero_node) = nonzero else {
                unreachable!()
            };
            assert_eq!(
                adapter.affine.forms[zero_node],
                Form {
                    constant: 0,
                    terms: vec![]
                }
            );
            let expected = (1 + 4 + 3 * (j / 64)) * 64 + j % 64;
            assert_eq!(
                adapter.affine.forms[nonzero_node].terms,
                vec![(expected, 1)]
            );
            assert_eq!(
                adapter.graph_word_from_packed(nonzero, &witness),
                5 * (71 + j as u64)
            );
        }
        for index in 64..witness.len() {
            let mut bad = witness.clone();
            bad[index] = add(bad[index], 1);
            assert!(
                adapter.verify_packed_witness(&bad).is_err(),
                "unbound mixed occurrence {index}"
            );
        }
    }

    #[test]
    fn mixed_alias_source_check_rejects_output_placed_before_zero_groups() {
        let (mut bad, inputs, outputs) = fixture();
        let Word::Wire(index) = outputs[64].1 else {
            unreachable!()
        };
        bad.affine.forms[index].terms[0].0 -= 4 * PACKING;
        assert!(bad.check_source_lowering(&inputs, &[0, 5]).is_err());
    }
}

#[cfg(test)]
mod public_bit_alias_composition_tests {
    use super::*;

    #[test]
    fn declared_public_bits_zero_batches_and_both_hash_aliases_compose() {
        let scope = Scope::start();
        let a = input();
        let b = input();
        let public_bits = range(a, 8);
        boolean(b);
        let mut state = [a; 16];
        for _ in 0..128 {
            state = record_poseidon2(state);
        }
        let digest = sha256_compact([public_bits[0]; 256]);
        let product = (state[0] + digest[0]) * b;
        let mut adapter = HtlcAdapter::from_graph_with_public_bindings(scope.finish(), &[0]);
        adapter.bind_public(a, 0);
        adapter.check_source_lowering(&[a], &[0]).unwrap();
        assert!(adapter.affine.boolean_rows.is_empty());
        assert_eq!(adapter.affine.guards.len(), 8);
        assert_eq!(adapter.trace_output_aliased_node_count(), 2056);
        assert_eq!(adapter.product_output_aliased_node_count(), 1);
        assert_eq!(adapter.affine.source_products.len(), 2);
        assert_eq!(adapter.geometry.canonical_wires, 2);
        assert_eq!(adapter.geometry.rows, 1 + 2 + 3 + 364 + 297);
        for word in public_bits {
            let Word::Wire(i) = word else { unreachable!() };
            assert_eq!(
                adapter.affine.forms[i],
                Form {
                    constant: 0,
                    terms: vec![]
                }
            );
        }
        let witness = adapter.evaluate(&[0, 1]).unwrap();
        adapter.verify_packed_witness(&witness).unwrap();
        let expected = add(
            adapter.graph_word_from_packed(state[0], &witness),
            adapter.graph_word_from_packed(digest[0], &witness),
        );
        assert_eq!(adapter.graph_word_from_packed(product, &witness), expected);
        let Word::Wire(index) = product else {
            unreachable!()
        };
        assert_eq!(adapter.affine.forms[index].terms, vec![((1 + 2) * 64, 1)]);
        let mut bad = witness.clone();
        bad[(1 + 2) * 64] = add(bad[(1 + 2) * 64], 1);
        assert!(adapter.verify_packed_witness(&bad).is_err());
        assert!(adapter.check_source_lowering(&[a], &[1]).is_err());
        adapter.graph.public_bit_bindings.as_mut().unwrap()[0] = 1;
        assert!(adapter.check_source_lowering(&[a], &[0]).is_err());
    }
}
