//! Deterministic arithmetic graph and K64 lowering for the HTLC successor.
//! All nonlinear occurrences are copy constrained to canonical private wires.

use crate::{
    smallwood_engine::SmallwoodArithmetization,
    smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView},
    TransactionCircuitError,
};
use hegemon_field::{PrimeCharacteristicRing, GOLDILOCKS_MODULUS as P};
use std::{
    cell::RefCell,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[path = "sha_lowering.rs"]
mod sha_lowering;
pub(crate) use sha_lowering::sha256_direct;
use sha_lowering::{DirectBatch, DirectGate};
#[path = "compact_sha256.rs"]
mod compact_sha256;
#[path = "compact_sha_certificate.rs"]
mod compact_sha_certificate;
#[path = "compact_sha_lowering.rs"]
mod compact_sha_lowering;
pub(crate) use compact_sha_lowering::sha256_compact;
use compact_sha_lowering::CompactShaCall;
#[path = "packed_poseidon_lowering.rs"]
mod packed_poseidon_lowering;
use crate::private_spend_packed_poseidon::{self as packed_poseidon, PackedPoseidonCall};
pub(crate) use packed_poseidon_lowering::record_poseidon2;

#[path = "affine.rs"]
mod affine;
#[path = "boolean_guards.rs"]
mod boolean_guards;
#[path = "source_cse.rs"]
mod source_cse;

pub(crate) const PACKING: usize = 64;
fn add(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % P as u128) as u64
}
fn sub(a: u64, b: u64) -> u64 {
    ((a as u128 + P as u128 - b as u128) % P as u128) as u64
}
fn mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % P as u128) as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Word {
    Constant(u64),
    Wire(usize),
}
impl Default for Word {
    fn default() -> Self {
        Self::ZERO
    }
}
#[derive(Clone, Debug)]
enum Node {
    Boolean(DirectGate),
    CompactShaOutput { call: usize, lane: usize },
    PoseidonOutput { call: usize, lane: usize },
    Input(usize),
    Linear(Word, Word, bool),
    Product(Word, Word),
    // Field multiplication by a public compiler constant is affine, not a
    // nonlinear gate. Keep its canonical wire and constrain it with CSR.
    Scale(Word, u64),
    Bit(Word, u8),
    Inverse(Word),
}
#[derive(Default)]
pub(crate) struct Graph {
    nodes: Vec<Node>,
    input_count: usize,
    // Only direct Bit(Input) nodes may use these exact checked public targets.
    public_bit_bindings: Option<Vec<u64>>,
    equalities: Vec<(Word, Word)>,
    products: Vec<(Word, Word, Word)>,
    ranges: Vec<RangeTrace>,
    packed_poseidon_calls: Vec<PackedPoseidonCall<Word>>,
    compact_sha_calls: Vec<CompactShaCall>,
}
thread_local! { static GRAPH:RefCell<Option<Graph>> = const { RefCell::new(None) }; }

impl Word {
    fn operation(self, rhs: Self, kind: u8) -> Self {
        if let (Self::Constant(a), Self::Constant(b)) = (self, rhs) {
            return Self::Constant(match kind {
                0 => add(a, b),
                1 => sub(a, b),
                _ => mul(a, b),
            });
        }
        if rhs == Self::ZERO && kind < 2 {
            return self;
        }
        if kind == 0 && self == Self::ZERO {
            return rhs;
        }
        if kind == 2 {
            if self == Self::ZERO || rhs == Self::ZERO {
                return Self::ZERO;
            }
            if self == Self::ONE {
                return rhs;
            }
            if rhs == Self::ONE {
                return self;
            }
        }
        GRAPH.with(|cell| {
            let mut borrowed = cell.borrow_mut();
            let g = borrowed.as_mut().expect("HTLC graph scope");
            let index = g.nodes.len();
            let node = if kind == 2 {
                match (self, rhs) {
                    (Self::Constant(coefficient), source)
                    | (source, Self::Constant(coefficient)) => Node::Scale(source, coefficient),
                    _ => Node::Product(self, rhs),
                }
            } else {
                Node::Linear(self, rhs, kind == 1)
            };
            let nonlinear = matches!(node, Node::Product(..));
            g.nodes.push(node);
            let output = Self::Wire(index);
            if nonlinear {
                g.products.push((output, self, rhs));
            }
            output
        })
    }
}
impl Add for Word {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        self.operation(rhs, 0)
    }
}
impl Sub for Word {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self.operation(rhs, 1)
    }
}
impl Mul for Word {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        self.operation(rhs, 2)
    }
}
impl AddAssign for Word {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl SubAssign for Word {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl MulAssign for Word {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}
impl Neg for Word {
    type Output = Self;
    fn neg(self) -> Self {
        Self::ZERO - self
    }
}
impl Sum for Word {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |a, b| a + b)
    }
}
impl Product for Word {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |a, b| a * b)
    }
}
impl PrimeCharacteristicRing for Word {
    const ZERO: Self = Self::Constant(0);
    const ONE: Self = Self::Constant(1);
    const TWO: Self = Self::Constant(2);
    const NEG_ONE: Self = Self::Constant(P - 1);
    fn from_bool(v: bool) -> Self {
        Self::Constant(v as u64)
    }
    fn from_u64(v: u64) -> Self {
        assert!(v < P);
        Self::Constant(v)
    }
}

/// Scope drops the partially built graph on errors and unwinding, so unrelated
/// compiler invocations never consume leftover topology or private assignments.
pub(crate) struct Scope;
impl Scope {
    pub(crate) fn start() -> Self {
        GRAPH.with(|cell| {
            assert!(cell.borrow().is_none(), "nested HTLC compilation");
            *cell.borrow_mut() = Some(Graph::default());
        });
        Self
    }
    pub(crate) fn finish(self) -> Graph {
        let result = GRAPH.with(|cell| cell.borrow_mut().take().unwrap());
        drop(self);
        result
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        GRAPH.with(|cell| {
            cell.borrow_mut().take();
        });
    }
}
pub(crate) fn input() -> Word {
    GRAPH.with(|cell| {
        let mut borrowed = cell.borrow_mut();
        let g = borrowed.as_mut().unwrap();
        let index = g.nodes.len();
        let slot = g.input_count;
        g.input_count += 1;
        g.nodes.push(Node::Input(slot));
        Word::Wire(index)
    })
}
pub(crate) fn equal(a: Word, b: Word) {
    GRAPH.with(|cell| cell.borrow_mut().as_mut().unwrap().equalities.push((a, b)));
}
pub(crate) fn boolean(a: Word) {
    equal(a * (a - Word::ONE), Word::ZERO);
}
pub(crate) fn nonzero(a: Word) {
    let inv = GRAPH.with(|cell| {
        let mut borrowed = cell.borrow_mut();
        let g = borrowed.as_mut().unwrap();
        let index = g.nodes.len();
        g.nodes.push(Node::Inverse(a));
        Word::Wire(index)
    });
    equal(a * inv, Word::ONE);
}
pub(crate) fn range(a: Word, bits: u8) -> Vec<Word> {
    let mut recomposed = Word::ZERO;
    let mut result = Vec::with_capacity(bits as usize);
    let mut trace = RangeTrace {
        source: a,
        steps: Vec::with_capacity(bits as usize),
    };
    for bit in 0..bits {
        let b = GRAPH.with(|cell| {
            let mut borrowed = cell.borrow_mut();
            let g = borrowed.as_mut().unwrap();
            let index = g.nodes.len();
            g.nodes.push(Node::Bit(a, bit));
            Word::Wire(index)
        });
        boolean(b);
        let scaled = b * Word::from_u64(1u64 << bit);
        recomposed += scaled;
        trace.steps.push((b, scaled, recomposed));
        result.push(b);
    }
    equal(a, recomposed);
    GRAPH.with(|cell| cell.borrow_mut().as_mut().unwrap().ranges.push(trace));
    result
}
pub(crate) fn select(bit: Word, a: Word, b: Word) -> Word {
    a + bit * (b - a)
}

#[derive(Clone, Debug)]
struct Batch {
    output: Option<usize>,
    left: usize,
    right: usize,
}
#[derive(Clone, Debug)]
pub struct HtlcGeometry {
    pub canonical_wires: usize,
    pub rows: usize,
    pub nonlinear_batches: usize,
    pub linear_equations: usize,
    pub private_inputs: usize,
    pub packing: usize,
    pub degree: usize,
}

pub struct HtlcAdapter {
    graph: Graph,
    affine: affine::AffineMap,
    smzc: bool,
    geometry: HtlcGeometry,
    batches: Vec<Batch>,
    direct_batches: Vec<DirectBatch>,
    occurrence_sources: Vec<Word>,
    offsets: Vec<u32>,
    indices: Vec<u32>,
    coefficients: Vec<u64>,
    targets: Vec<u64>,
}
impl HtlcAdapter {
    pub(crate) fn from_graph_with_public_bindings(mut graph: Graph, public: &[u64]) -> Self {
        graph.public_bit_bindings = Some(public.to_vec());
        Self::from_graph(graph)
    }
    pub(crate) fn from_graph(graph: Graph) -> Self {
        let affine = affine::AffineMap::build(&graph);
        let canonical_rows = affine.canonical_slots().div_ceil(PACKING);
        let mut adapter = Self {
            geometry: HtlcGeometry {
                canonical_wires: affine.committed_nodes.len(),
                rows: canonical_rows,
                nonlinear_batches: 0,
                linear_equations: 0,
                private_inputs: graph.input_count,
                packing: PACKING,
                degree: 2,
            },
            graph,
            affine,
            smzc: false,
            batches: vec![],
            direct_batches: vec![],
            occurrence_sources: vec![],
            offsets: vec![0],
            indices: vec![],
            coefficients: vec![],
            targets: vec![],
        };
        let eqs = adapter.graph.equalities.clone();
        for (a, b) in eqs {
            adapter.linear(&[(a, 1), (b, P - 1)], 0);
        }
        for index in 0..canonical_rows * PACKING {
            if adapter
                .affine
                .packed_nodes
                .get(index)
                .is_some_and(|node| node.is_some())
            {
                continue;
            }
            adapter.linear_committed(&[(index, 1)], 0);
        }
        let products = adapter.affine.ordinary_products(&adapter.graph);
        let (zero_products, nonzero_products): (Vec<_>, Vec<_>) =
            products.into_iter().partition(|(output, _, _)| {
                let form = adapter.affine.combine(&[(*output, 1)]);
                form.constant == 0 && form.terms.is_empty()
            });
        for (zero, products) in [(true, zero_products), (false, nonzero_products)] {
            for gates in products.chunks(PACKING) {
                let start = adapter.geometry.rows;
                adapter.batches.push(Batch {
                    output: if zero { None } else { Some(start) },
                    left: start + usize::from(!zero),
                    right: start + 1 + usize::from(!zero),
                });
                for operand in usize::from(zero)..3 {
                    for lane in 0..PACKING {
                        let gate = gates[lane.min(gates.len() - 1)];
                        let source = match operand {
                            0 => gate.0,
                            1 => gate.1,
                            _ => gate.2,
                        };
                        let occurrence = adapter.geometry.rows * PACKING + lane;
                        adapter.occurrence_sources.push(source);
                        adapter.copy_to_packed(occurrence, source);
                        adapter.geometry.rows += usize::from(lane == PACKING - 1);
                    }
                }
            }
        }
        adapter.append_direct_batches();
        adapter.append_packed_poseidon_bindings();
        adapter.append_compact_sha_bindings();
        adapter.geometry.degree = if !adapter.graph.packed_poseidon_calls.is_empty()
            || !adapter.graph.compact_sha_calls.is_empty()
        {
            packed_poseidon::DEGREE
        } else if adapter.direct_batches.is_empty() {
            2
        } else {
            3
        };
        adapter.geometry.nonlinear_batches = adapter.affine.boolean_rows.len()
            + adapter.batches.len()
            + adapter.direct_batches.len()
            + adapter.packed_poseidon_constraint_count()
            + adapter.compact_sha_constraint_count();
        adapter.geometry.linear_equations = adapter.targets.len();
        adapter
    }
    pub(super) fn ordinary_product_row_count(&self) -> usize {
        self.batches
            .iter()
            .map(|batch| if batch.output.is_some() { 3 } else { 2 })
            .sum()
    }
    pub(crate) fn bind_public(&mut self, word: Word, target: u64) {
        self.linear(&[(word, 1)], target);
        self.geometry.linear_equations = self.targets.len();
    }
    pub(crate) fn check_source_lowering<const N: usize>(
        &self,
        public_wires: &[Word; N],
        public_values: &[u64; N],
    ) -> Result<(), &'static str> {
        let fail = || Err("source lowering certificate mismatch");
        let n = self.graph.nodes.len();
        // Check the specialization inputs before reconstructing any folded form.
        // The CSR rows below still bind every original public Input wire.
        if let Some(bindings) = &self.graph.public_bit_bindings {
            if bindings.as_slice() != public_values.as_slice() {
                return fail();
            }
            for i in 0..N {
                if public_wires[i] != Word::Wire(i)
                    || public_values[i] >= P
                    || !matches!(self.graph.nodes.get(i), Some(Node::Input(slot)) if *slot == i)
                {
                    return fail();
                }
            }
        }
        let checked_forms = affine::reconstruct(&self.graph, &self.affine)?;
        let committed_count = self.affine.committed_nodes.len();
        let canonical_rows = self
            .affine
            .canonical_slots()
            .checked_add(PACKING - 1)
            .ok_or("size overflow")?
            / PACKING;
        let canonical_len = canonical_rows.checked_mul(64).ok_or("size overflow")?;
        let checked_symbols = source_cse::reconstruct(&self.graph, &self.affine.guards)?;
        let mut zero_products = Vec::new();
        let mut nonzero_products = Vec::new();
        for index in checked_symbols.products {
            let Node::Product(a, b) = self.graph.nodes[index] else {
                return fail();
            };
            let form = &checked_symbols.forms[index];
            if form.constant == 0 && form.terms.is_empty() {
                zero_products.push((Word::Wire(index), a, b));
            } else {
                nonzero_products.push((Word::Wire(index), a, b));
            }
        }
        let zero_batches = zero_products.len().checked_add(63).ok_or("size overflow")? / 64;
        let nonzero_batches = nonzero_products
            .len()
            .checked_add(63)
            .ok_or("size overflow")?
            / 64;
        let batch_count = zero_batches
            .checked_add(nonzero_batches)
            .ok_or("size overflow")?;
        let product_rows = zero_batches
            .checked_mul(2)
            .and_then(|r| r.checked_add(nonzero_batches.checked_mul(3)?))
            .ok_or("size overflow")?;
        let direct_count = self.direct_batch_count();
        let compact_sha_calls = self.graph.compact_sha_calls.len();
        if compact_sha_calls > 1 {
            return fail();
        }
        let compact_sha_rows = compact_sha_calls.checked_mul(297).ok_or("size overflow")?;
        let compact_sha_constraints = compact_sha_calls.checked_mul(294).ok_or("size overflow")?;
        let poseidon_calls = self.graph.packed_poseidon_calls.len();
        if poseidon_calls != 0 && poseidon_calls != 128 {
            return fail();
        }
        let poseidon_rows = if poseidon_calls == 0 { 0 } else { 364 };
        let poseidon_constraints = if poseidon_calls == 0 { 0 } else { 332 };
        let degree = if poseidon_calls != 0 || compact_sha_calls != 0 {
            7
        } else if direct_count == 0 {
            2
        } else {
            3
        };
        let row_count = canonical_rows
            .checked_add(product_rows)
            .and_then(|r| r.checked_add(direct_count.checked_mul(4)?))
            .and_then(|r| r.checked_add(poseidon_rows))
            .and_then(|r| r.checked_add(compact_sha_rows))
            .ok_or("size overflow")?;
        let packed_len = row_count.checked_mul(64).ok_or("size overflow")?;
        if self.geometry.canonical_wires != committed_count
            || self.geometry.rows != row_count
            || self.geometry.packing != 64
            || self.geometry.degree != degree
            || self.geometry.nonlinear_batches
                != self.affine.boolean_rows.len()
                    + batch_count
                    + direct_count
                    + poseidon_constraints
                    + compact_sha_constraints
            || self.batches.len() != batch_count
            || self.geometry.linear_equations != self.targets.len()
            || self.offsets.len() != self.targets.len().checked_add(1).ok_or("size overflow")?
            || self.offsets.first() != Some(&0)
            || self.indices.len() != self.coefficients.len()
            || self.offsets.last().copied().map(|v| v as usize) != Some(self.indices.len())
            || self.indices.iter().any(|i| *i as usize >= packed_len)
            || self
                .coefficients
                .iter()
                .chain(self.targets.iter())
                .any(|v| *v >= P)
        {
            return fail();
        }
        let valid = |w: Word, before: usize| match w {
            Word::Constant(v) => v < P,
            Word::Wire(i) => i < before,
        };
        let mut input_slot = 0;
        let mut product_slot = 0;
        let mut poseidon_slot = 0;
        let mut compact_sha_slot = 0;
        for (i, node) in self.graph.nodes.iter().enumerate() {
            match node {
                Node::CompactShaOutput { call, lane } => {
                    if *lane >= 8 || *call != compact_sha_slot {
                        return fail();
                    }
                    let Some(d) = self.graph.compact_sha_calls.get(*call) else {
                        return fail();
                    };
                    let first = i.checked_sub(*lane).ok_or("invalid compact SHA lane")?;
                    let end = first.checked_add(8).ok_or("size overflow")?;
                    if end>n || d.input.iter().any(|w| !valid(*w,first)) || d.output.iter().enumerate().any(|(j,w)| *w!=Word::Wire(first+j))
                    || self.graph.nodes[first..end].iter().enumerate().any(|(j,node)| !matches!(node,Node::CompactShaOutput{call:other,lane} if *other==*call && *lane==j)) { return fail(); }
                    if *lane == 7 {
                        compact_sha_slot += 1;
                    }
                }
                Node::PoseidonOutput { call, lane } => {
                    if *lane >= 16 || *call != poseidon_slot {
                        return fail();
                    }
                    let Some(descriptor) = self.graph.packed_poseidon_calls.get(*call) else {
                        return fail();
                    };
                    let first = i.checked_sub(*lane).ok_or("invalid Poseidon lane")?;
                    let end = first.checked_add(16).ok_or("size overflow")?;
                    if end > n
                        || descriptor.input.iter().any(|w| !valid(*w, first))
                        || descriptor.output.iter().enumerate().any(|(j,w)| *w != Word::Wire(first+j))
                        || self.graph.nodes[first..end].iter().enumerate().any(|(j,node)|
                            !matches!(node, Node::PoseidonOutput { call: other, lane } if *other == *call && *lane == j))
                    {
                        return fail();
                    }
                    if *lane == 15 {
                        poseidon_slot += 1;
                    }
                }
                Node::Boolean(gate) => {
                    if !gate.valid_before(i) {
                        return fail();
                    }
                }
                Node::Input(slot) => {
                    if *slot != input_slot {
                        return fail();
                    }
                    input_slot += 1;
                }
                Node::Linear(a, b, _) | Node::Product(a, b) => {
                    if !valid(*a, i) || !valid(*b, i) {
                        return fail();
                    }
                }
                Node::Scale(source, coefficient) => {
                    if !valid(*source, i) || *coefficient >= P {
                        return fail();
                    }
                }
                Node::Bit(a, bit) => {
                    if !valid(*a, i) || *bit >= 64 {
                        return fail();
                    }
                }
                Node::Inverse(a) => {
                    if !valid(*a, i) {
                        return fail();
                    }
                }
            }
            if let Node::Product(a, b) = node {
                if self.graph.products.get(product_slot) != Some(&(Word::Wire(i), *a, *b)) {
                    return fail();
                }
                product_slot += 1;
            }
        }
        if compact_sha_slot != self.graph.compact_sha_calls.len()
            || poseidon_slot != self.graph.packed_poseidon_calls.len()
            || product_slot != self.graph.products.len()
            || input_slot != self.graph.input_count
            || self.geometry.private_inputs != input_slot
        {
            return fail();
        }
        for i in 0..N {
            if public_wires[i] != Word::Wire(i)
                || public_values[i] >= P
                || !matches!(self.graph.nodes.get(i), Some(Node::Input(slot)) if *slot == i)
            {
                return fail();
            }
        }
        let mut checked = affine::SourceRows::new(self, checked_forms, packed_len);
        for &(a, b) in &self.graph.equalities {
            if !valid(a, n) || !valid(b, n) {
                return fail();
            }
            checked.source(&[(a, 1), (b, P - 1)], 0)?;
        }
        for index in 0..canonical_len {
            if self
                .affine
                .packed_nodes
                .get(index)
                .is_some_and(|node| node.is_some())
            {
                continue;
            }
            checked.zero(index)?;
        }
        let mut occurrence = 0;
        let mut batch_index = 0;
        let mut next_row = canonical_rows;
        for (is_zero, products) in [(true, zero_products), (false, nonzero_products)] {
            for gates in products.chunks(64) {
                let descriptor = &self.batches[batch_index];
                let output = if is_zero { None } else { Some(next_row) };
                let left = next_row + usize::from(!is_zero);
                let right = left + 1;
                if descriptor.output != output
                    || descriptor.left != left
                    || descriptor.right != right
                {
                    return fail();
                }
                for operand in usize::from(is_zero)..3 {
                    let row = match operand {
                        0 => output.ok_or("missing product output row")?,
                        1 => left,
                        _ => right,
                    };
                    for lane in 0..64 {
                        let gate = gates[lane.min(gates.len() - 1)];
                        let source = match operand {
                            0 => gate.0,
                            1 => gate.1,
                            _ => gate.2,
                        };
                        if self.occurrence_sources.get(occurrence) != Some(&source) {
                            return fail();
                        }
                        occurrence += 1;
                        checked.copy(row * 64 + lane, source)?;
                    }
                }
                next_row = right + 1;
                batch_index += 1;
            }
        }
        if next_row != canonical_rows + product_rows || batch_index != batch_count {
            return fail();
        }
        self.check_direct_batches(
            canonical_rows + product_rows,
            &mut occurrence,
            |slot, source| checked.copy(slot, source),
        )?;
        self.check_packed_poseidon_bindings(
            canonical_rows + product_rows + 4 * direct_count,
            |slot, source| checked.copy(slot, source),
        )?;
        self.check_compact_sha_bindings(
            canonical_rows + product_rows + 4 * direct_count + poseidon_rows,
            &mut checked,
        )?;
        for i in 0..N {
            checked.source(&[(public_wires[i], 1)], public_values[i])?;
        }
        checked.finish()?;
        if occurrence != self.occurrence_sources.len() {
            return fail();
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn adversarial_probe_indices(&self) -> Vec<usize> {
        let mut indices = Vec::new();
        for kind in 0..6 {
            if let Some(i) = self.graph.nodes.iter().enumerate().find_map(|(i, n)| {
                matches!(
                    (kind, n),
                    (0, Node::Bit(..))
                        | (1, Node::Inverse(..))
                        | (2, Node::Product(..))
                        | (3, Node::Boolean(..))
                        | (4, Node::PoseidonOutput { .. })
                        | (5, Node::CompactShaOutput { .. })
                )
                .then_some(i)
                .filter(|i| !self.affine.forms[*i].terms.is_empty())
            }) {
                // A source value may live in authenticated trace/occurrence
                // cells rather than a separately copied canonical scalar.
                indices.push(self.affine.forms[i].terms[0].0);
            }
        }
        indices
    }

    pub(crate) fn use_smzc(&mut self) {
        self.smzc = true;
    }
    pub fn geometry(&self) -> &HtlcGeometry {
        &self.geometry
    }
    pub(crate) fn evaluate(&self, inputs: &[u64]) -> Result<Vec<u64>, TransactionCircuitError> {
        if inputs.len() != self.graph.input_count || inputs.iter().any(|v| *v >= P) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HTLC private input shape/canonicality",
            ));
        }
        let mut canonical = Vec::with_capacity(self.graph.nodes.len());
        let mut poseidon_traces = Vec::with_capacity(self.graph.packed_poseidon_calls.len());
        let mut compact_sha_traces = Vec::with_capacity(self.graph.compact_sha_calls.len());
        for node in &self.graph.nodes {
            let value = match *node {
                Node::CompactShaOutput { call, lane } => {
                    if lane == 0 {
                        let bits = self.graph.compact_sha_calls[call]
                            .input
                            .map(|w| read(w, &canonical));
                        if bits.iter().any(|v| *v > 1) {
                            return Err(TransactionCircuitError::ConstraintViolation(
                                "compact SHA input bit",
                            ));
                        }
                        let bytes: [u8; 32] = core::array::from_fn(|i| {
                            (0..8).fold(0u8, |v, b| v | ((bits[i * 8 + b] as u8) << b))
                        });
                        compact_sha_traces.push(
                            compact_sha256::Layout::new(PACKING)
                                .expect("source packing")
                                .evaluate(&bytes),
                        );
                    }
                    compact_sha_traces[call].1[lane]
                }
                Node::PoseidonOutput { call, lane } => {
                    if lane == 0 {
                        let input = self.graph.packed_poseidon_calls[call]
                            .input
                            .map(|w| read(w, &canonical));
                        poseidon_traces.push(packed_poseidon::native_trace(input).map_err(
                            |_| {
                                TransactionCircuitError::ConstraintViolation(
                                    "packed Poseidon native trace",
                                )
                            },
                        )?);
                    }
                    poseidon_traces[call][166 + lane]
                }
                Node::Boolean(gate) => gate.evaluate(&canonical),
                Node::Input(i) => inputs[i],
                Node::Linear(a, b, s) => {
                    if s {
                        sub(read(a, &canonical), read(b, &canonical))
                    } else {
                        add(read(a, &canonical), read(b, &canonical))
                    }
                }
                Node::Product(a, b) => mul(read(a, &canonical), read(b, &canonical)),
                Node::Scale(source, coefficient) => mul(read(source, &canonical), coefficient),
                Node::Bit(a, bit) => (read(a, &canonical) >> bit) & 1,
                Node::Inverse(a) => hegemon_field::Goldilocks::from_u64(read(a, &canonical))
                    .try_inverse()
                    .map_or(0, |v| v.as_canonical_u64()),
            };
            canonical.push(value);
        }
        let canonical_rows = self.affine.canonical_slots().div_ceil(PACKING);
        let mut packed: Vec<u64> = self
            .affine
            .packed_nodes
            .iter()
            .map(|i| i.map_or(0, |i| canonical[i]))
            .collect();
        packed.resize(canonical_rows * PACKING, 0);
        packed.extend(
            self.occurrence_sources
                .iter()
                .map(|source| read(*source, &canonical)),
        );
        if !poseidon_traces.is_empty() {
            packed.extend(
                packed_poseidon::pack_traces(&poseidon_traces)
                    .map_err(|_| {
                        TransactionCircuitError::ConstraintViolation("packed Poseidon trace shape")
                    })?
                    .into_iter()
                    .flatten(),
            );
        }
        for (trace, _) in compact_sha_traces {
            packed.extend(trace.rows.into_iter().flatten());
        }
        Ok(packed)
    }
    pub fn verify_packed_witness(&self, witness: &[u64]) -> Result<(), TransactionCircuitError> {
        if witness.len() != self.geometry.rows * PACKING || witness.iter().any(|v| *v >= P) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HTLC packed witness shape/canonicality",
            ));
        }
        for (i, target) in self.targets.iter().enumerate() {
            let value =
                (self.offsets[i] as usize..self.offsets[i + 1] as usize).fold(0, |sum, j| {
                    add(
                        sum,
                        mul(self.coefficients[j], witness[self.indices[j] as usize]),
                    )
                });
            if value != *target {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "HTLC linear equation",
                ));
            }
        }
        for batch in &self.batches {
            for lane in 0..PACKING {
                if batch.output.map_or(0, |row| witness[row * PACKING + lane])
                    != mul(
                        witness[batch.left * PACKING + lane],
                        witness[batch.right * PACKING + lane],
                    )
                {
                    return Err(TransactionCircuitError::ConstraintViolation(
                        "HTLC multiplication equation",
                    ));
                }
            }
        }
        for &row in &self.affine.boolean_rows {
            for lane in 0..PACKING {
                if boolean_guards::residual(witness[row * PACKING + lane]) != 0 {
                    return Err(TransactionCircuitError::ConstraintViolation(
                        "HTLC Boolean equation",
                    ));
                }
            }
        }
        self.verify_direct_witness(witness)?;
        self.verify_packed_poseidon_witness(witness)?;
        self.verify_compact_sha_witness(witness)?;
        Ok(())
    }
}
fn read(word: Word, values: &[u64]) -> u64 {
    match word {
        Word::Constant(v) => v,
        Word::Wire(i) => values[i],
    }
}
impl SmallwoodConstraintAdapter for HtlcAdapter {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        if self.smzc {
            SmallwoodArithmetization::DirectPacked64NativeHtlcSha512Smzc
        } else {
            SmallwoodArithmetization::DirectPacked64CompressedLevel5StrictZkSmz1
        }
    }
    fn row_count(&self) -> usize {
        self.geometry.rows
    }
    fn packing_factor(&self) -> usize {
        PACKING
    }
    fn constraint_degree(&self) -> usize {
        self.geometry.degree
    }
    fn linear_constraint_count(&self) -> usize {
        self.targets.len()
    }
    fn constraint_count(&self) -> usize {
        self.affine.boolean_rows.len()
            + self.batches.len()
            + self.direct_batches.len()
            + self.packed_poseidon_constraint_count()
            + self.compact_sha_constraint_count()
    }
    fn linear_constraint_offsets(&self) -> &[u32] {
        &self.offsets
    }
    fn linear_constraint_indices(&self) -> &[u32] {
        &self.indices
    }
    fn linear_constraint_coefficients(&self) -> &[u64] {
        &self.coefficients
    }
    fn linear_targets(&self) -> &[u64] {
        &self.targets
    }
    fn auxiliary_witness_words(&self) -> &[u64] {
        &[]
    }
    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(0)
    }
    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        row_scalars: &'a [u64],
        auxiliary_words: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows: row_scalars,
            auxiliary_words,
        }
    }
    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        let SmallwoodNonlinearEvalView::RowScalars {
            rows,
            auxiliary_words,
            eval_point,
        } = view;
        if rows.len() != self.geometry.rows
            || !auxiliary_words.is_empty()
            || out.len()
                != self.affine.boolean_rows.len()
                    + self.batches.len()
                    + self.direct_batches.len()
                    + self.packed_poseidon_constraint_count()
                    + self.compact_sha_constraint_count()
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HTLC evaluator shape",
            ));
        }
        let (booleans, remainder) = out.split_at_mut(self.affine.boolean_rows.len());
        for (&row, value) in self.affine.boolean_rows.iter().zip(booleans) {
            *value = boolean_guards::residual(rows[row]);
        }
        let (products, remainder) = remainder.split_at_mut(self.batches.len());
        let (direct, remainder) = remainder.split_at_mut(self.direct_batches.len());
        let (poseidon, compact_sha) =
            remainder.split_at_mut(self.packed_poseidon_constraint_count());
        for (batch, value) in self.batches.iter().zip(products) {
            *value = sub(
                batch.output.map_or(0, |row| rows[row]),
                mul(rows[batch.left], rows[batch.right]),
            );
        }
        self.eval_direct_constraints(rows, direct);
        self.eval_packed_poseidon_constraints(rows, poseidon)?;
        self.eval_compact_sha_constraints(eval_point, rows, compact_sha)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scale_fixture(coefficient: u64, sample: u64, constant_first: bool) -> HtlcAdapter {
        let scope = Scope::start();
        let x = input();
        let constant = Word::Constant(coefficient);
        let scaled = if constant_first {
            constant * x
        } else {
            x * constant
        };
        assert!(matches!(scaled, Word::Wire(1)));
        let mut adapter = HtlcAdapter::from_graph(scope.finish());
        adapter.bind_public(x, sample);
        adapter.check_source_lowering(&[x], &[sample]).unwrap();
        assert!(adapter.arithmetic_op(x, constant, 2, scaled));
        assert!(adapter.arithmetic_op(constant, x, 2, scaled));
        adapter
    }

    #[test]
    fn constant_scale_preserves_field_values_and_removes_only_nonlinear_copies() {
        for coefficient in [2, 1 << 32, P - 1] {
            for sample in [0, 1, 7, 1 << 32, P - 1] {
                for constant_first in [false, true] {
                    let adapter = scale_fixture(coefficient, sample, constant_first);
                    assert_eq!(adapter.graph.input_count, 1);
                    assert_eq!(adapter.graph.nodes.len(), 2);
                    assert!(adapter.graph.products.is_empty());
                    assert_eq!(adapter.geometry.rows, 1);
                    assert_eq!(adapter.geometry.nonlinear_batches, 0);
                    let packed = adapter.evaluate(&[sample]).unwrap();
                    assert_eq!(
                        adapter.graph_word_from_packed(Word::Wire(1), &packed),
                        mul(sample, coefficient)
                    );
                    adapter.verify_packed_witness(&packed).unwrap();
                    let mut bad = packed.clone();
                    bad[1] = add(bad[1], 1);
                    assert!(adapter.verify_packed_witness(&bad).is_err());

                    // Retained old lowering provides an independent comparison:
                    // one canonical row plus three nonlinear occurrence rows.
                    let mut graph = Graph::default();
                    graph.nodes = vec![
                        Node::Input(0),
                        Node::Product(Word::Wire(0), Word::Constant(coefficient)),
                    ];
                    graph.input_count = 1;
                    graph.products.push((
                        Word::Wire(1),
                        Word::Wire(0),
                        Word::Constant(coefficient),
                    ));
                    let mut legacy = HtlcAdapter::from_graph(graph);
                    legacy.bind_public(Word::Wire(0), sample);
                    legacy
                        .check_source_lowering(&[Word::Wire(0)], &[sample])
                        .unwrap();
                    let old = legacy.evaluate(&[sample]).unwrap();
                    legacy.verify_packed_witness(&old).unwrap();
                    assert_eq!(
                        legacy.graph_word_from_packed(Word::Wire(1), &old),
                        adapter.graph_word_from_packed(Word::Wire(1), &packed)
                    );
                    assert_eq!(legacy.geometry.rows, adapter.geometry.rows + 3);
                }
            }
        }
    }

    #[test]
    fn scale_source_certificate_rejects_coefficient_and_csr_mutations() {
        let mut bad = scale_fixture(7, 3, false);
        bad.graph.nodes[1] = Node::Scale(Word::Wire(0), P);
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[3]).is_err());
        let mut bad = scale_fixture(7, 3, false);
        bad.graph.nodes[1] = Node::Scale(Word::Wire(0), 8);
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[3]).is_err());
        let mut bad = scale_fixture(7, 3, false);
        bad.graph.nodes[1] = Node::Scale(Word::Wire(1), 7);
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[3]).is_err());
        let mut bad = scale_fixture(7, 3, false);
        bad.coefficients[0] = add(bad.coefficients[0], 1);
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[3]).is_err());
        let mut bad = scale_fixture(7, 3, false);
        bad.graph
            .products
            .push((Word::Wire(1), Word::Wire(0), Word::Constant(7)));
        assert!(bad.check_source_lowering(&[Word::Wire(0)], &[3]).is_err());
    }

    fn lowering_fixture() -> (HtlcAdapter, [Word; 77], [u64; 77]) {
        let mut graph = Graph::default();
        graph.nodes.extend((0..77).map(Node::Input));
        graph.input_count = 77;
        graph
            .nodes
            .push(Node::Linear(Word::Wire(0), Word::Constant(9), false));
        graph
            .nodes
            .push(Node::Product(Word::Wire(77), Word::Constant(5)));
        graph
            .products
            .push((Word::Wire(78), Word::Wire(77), Word::Constant(5)));
        graph.nodes.push(Node::Bit(Word::Wire(78), 4));
        graph.nodes.push(Node::Inverse(Word::Wire(78)));
        // Duplicate source operands force the independent row normalizer to coalesce aliases.
        graph
            .nodes
            .push(Node::Linear(Word::Wire(0), Word::Wire(0), false));
        graph.equalities.push((Word::Wire(78), Word::Constant(50)));
        let wires = core::array::from_fn(|i| Word::Wire(i));
        let values = [7u64; 77];
        let mut adapter = HtlcAdapter::from_graph(graph);
        for (wire, value) in wires.iter().copied().zip(values) {
            adapter.bind_public(wire, value);
        }
        (adapter, wires, values)
    }

    #[test]
    fn source_lowering_checker_rejects_csr_and_graph_corruption() {
        let (adapter, wires, values) = lowering_fixture();
        adapter.check_source_lowering(&wires, &values).unwrap();

        let mut bad = lowering_fixture().0;
        let alias_row_start = bad.offsets[1] as usize;
        bad.coefficients[alias_row_start] = add(bad.coefficients[alias_row_start], 1);
        assert!(bad.check_source_lowering(&wires, &values).is_err());
        let mut bad = lowering_fixture().0;
        bad.graph.nodes[77] = Node::Linear(Word::Wire(0), Word::Constant(P), false);
        assert!(bad.check_source_lowering(&wires, &values).is_err());
        let mut bad = lowering_fixture().0;
        bad.graph.equalities.push((Word::Wire(1), Word::Wire(2)));
        assert!(bad.check_source_lowering(&wires, &values).is_err());
        let mut bad = lowering_fixture().0;
        bad.bind_public(Word::Wire(0), 99);
        assert!(bad.check_source_lowering(&wires, &values).is_err());
        let mut bad = lowering_fixture().0;
        bad.targets[0] = add(bad.targets[0], 1);
        assert!(bad.check_source_lowering(&wires, &values).is_err());
        let mut bad = lowering_fixture().0;
        bad.offsets[1] = bad.offsets[1].saturating_add(1);
        assert!(bad.check_source_lowering(&wires, &values).is_err());
        let mut bad = lowering_fixture().0;
        bad.indices[0] = bad.indices[0].saturating_add(1);
        assert!(bad.check_source_lowering(&wires, &values).is_err());
        let mut bad = lowering_fixture().0;
        bad.coefficients[0] = add(bad.coefficients[0], 1);
        assert!(bad.check_source_lowering(&wires, &values).is_err());
        let (mut bad, _, _) = lowering_fixture();
        bad.graph.products.clear();
        assert!(bad.check_source_lowering(&wires, &values).is_err());
        let mut bad = lowering_fixture().0;
        bad.occurrence_sources[0] = Word::Wire(1);
        assert!(bad.check_source_lowering(&wires, &values).is_err());
        let mut bad = lowering_fixture().0;
        bad.batches[0].left += 1;
        assert!(bad.check_source_lowering(&wires, &values).is_err());
        let mut graph = Graph::default();
        graph.nodes.extend((0..77).map(Node::Input));
        graph.nodes[0] = Node::Input(1);
        graph.input_count = 77;
        let bad = HtlcAdapter::from_graph(graph);
        assert!(bad.check_source_lowering(&wires, &values).is_err());
    }

    fn range_fixture() -> HtlcAdapter {
        let scope = Scope::start();
        let source = input();
        assert_eq!(source, Word::Wire(0));
        assert_eq!(range(source, 56).len(), 56);
        HtlcAdapter::from_graph(scope.finish())
    }

    #[test]
    fn arithmetic_range_metadata_rejects_corruption() {
        let source = Word::Wire(0);
        let adapter = range_fixture();
        assert!(adapter.arithmetic_range(source, 56));
        assert!(!adapter.arithmetic_range(source, 55));
        assert_eq!(
            adapter.graph.ranges[0].steps[0].1,
            adapter.graph.ranges[0].steps[0].0
        );

        let mut bad = range_fixture();
        bad.graph.ranges[0].steps[7].0 = Word::Wire(0);
        assert!(!bad.arithmetic_range(source, 56));
        let mut bad = range_fixture();
        let bit0 = match bad.graph.ranges[0].steps[0].0 {
            Word::Wire(i) => i,
            _ => unreachable!(),
        };
        bad.graph.nodes[bit0] = Node::Bit(Word::Wire(1), 0);
        assert!(!bad.arithmetic_range(source, 56));
        let mut bad = range_fixture();
        bad.graph.ranges[0].steps[0].1 = Word::Constant(1);
        assert!(!bad.arithmetic_range(source, 56));
        let mut bad = range_fixture();
        bad.graph.ranges[0].steps[9].2 = Word::Wire(0);
        assert!(!bad.arithmetic_range(source, 56));
        let mut bad = range_fixture();
        bad.graph
            .equalities
            .retain(|&(a, b)| !(a == source && b == bad.graph.ranges[0].steps[55].2));
        assert!(!bad.arithmetic_range(source, 56));
        let mut bad = range_fixture();
        let bit = bad.graph.ranges[0].steps[0].0;
        let guard = bad
            .graph
            .equalities
            .iter()
            .copied()
            .find(|&(a, b)| {
                b == Word::ZERO
                    && matches!(bad.arithmetic_node(a), Some(Node::Product(s, _)) if *s == bit)
            })
            .unwrap();
        bad.graph.equalities.retain(|&equation| equation != guard);
        assert!(!bad.arithmetic_range(source, 56));
        let mut bad = range_fixture();
        bad.graph.ranges[0].steps.pop();
        assert!(!bad.arithmetic_range(source, 56));
    }

    #[test]
    fn every_product_occurrence_and_padding_lane_is_bound() {
        let scope = Scope::start();
        let a = input();
        let b = input();
        for i in 0..65 {
            let _ = a * (b + Word::from_u64(i));
        }
        let adapter = HtlcAdapter::from_graph(scope.finish());
        let packed = adapter.evaluate(&[3, 5]).unwrap();
        adapter.verify_packed_witness(&packed).unwrap();
        let first = adapter.affine.canonical_slots().div_ceil(PACKING) * PACKING;
        for index in first..packed.len() {
            let mut changed = packed.clone();
            changed[index] = add(changed[index], 1);
            assert!(
                adapter.verify_packed_witness(&changed).is_err(),
                "unbound product occurrence {index}"
            );
        }
    }
}

// Uncompiled additions inside smallwood_htlc/circuit.rs. No witness values.
#[derive(Clone, Debug)]
struct RangeTrace {
    source: Word,
    // (bit auxiliary, scaled term, recomposed prefix after this step)
    steps: Vec<(Word, Word, Word)>,
}
#[derive(Clone, Debug)]
pub(crate) struct PrivateSpendArithmeticRoles {
    pub public: [Word; 77],
    pub modes: [Word; 6],
    pub selector_prefix: [Word; 7],
    pub values: [Word; 5],
    pub balance: [Word; 3],
    pub timeout: Word,
    pub lock_steps: [Word; 3],
    pub refund_steps: [Word; 2],
    pub intent: [Word; 54],
    pub unlocked: Word,
}
impl HtlcAdapter {
    fn arithmetic_node(&self, w: Word) -> Option<&Node> {
        match w {
            Word::Wire(i) => self.graph.nodes.get(i),
            _ => None,
        }
    }
    // Independent data match, including exactly the existing constant folds.
    fn arithmetic_op(&self, a: Word, b: Word, kind: u8, out: Word) -> bool {
        if let (Word::Constant(x), Word::Constant(y)) = (a, b) {
            return out
                == Word::Constant(match kind {
                    0 => add(x, y),
                    1 => sub(x, y),
                    _ => mul(x, y),
                });
        }
        if b == Word::ZERO && kind < 2 {
            return out == a;
        }
        if kind == 0 && a == Word::ZERO {
            return out == b;
        }
        if kind == 2 {
            if a == Word::ZERO || b == Word::ZERO {
                return out == Word::ZERO;
            }
            if a == Word::ONE {
                return out == b;
            }
            if b == Word::ONE {
                return out == a;
            }
        }
        match self.arithmetic_node(out) {
            Some(Node::Linear(x, y, s)) => kind < 2 && *x == a && *y == b && *s == (kind == 1),
            Some(Node::Product(x, y)) => kind == 2 && *x == a && *y == b,
            Some(Node::Scale(source, coefficient)) => {
                kind == 2
                    && ((a == Word::Constant(*coefficient) && b == *source)
                        || (b == Word::Constant(*coefficient) && a == *source))
            }
            _ => false,
        }
    }
    // All callers here have selector/a/b wires or the explicit constant one.
    // General folded gates need an expanded certificate, not this shortcut.
    fn arithmetic_gate(&self, selector: Word, a: Word, b: Word) -> bool {
        self.graph.equalities.iter().any(|&(product, zero)| {
            if zero != Word::ZERO {
                return false;
            }
            match self.arithmetic_node(product) {
                Some(Node::Product(s, difference)) if *s == selector => {
                    self.arithmetic_op(a, b, 1, *difference)
                }
                _ => false,
            }
        })
    }
    fn arithmetic_boolean(&self, bit: Word) -> bool {
        self.arithmetic_gate(bit, bit, Word::ONE)
    }
    fn arithmetic_range(&self, source: Word, width: usize) -> bool {
        self.graph.ranges.iter().any(|trace| {
            if trace.source != source || trace.steps.len() != width || width >= 64 { return false; }
            let mut prior = Word::ZERO;
            for (j, &(bit, scaled, next)) in trace.steps.iter().enumerate() {
                if !matches!(self.arithmetic_node(bit), Some(Node::Bit(a,k)) if *a == source && *k as usize == j)
                    || !self.arithmetic_boolean(bit)
                    || !self.arithmetic_op(bit, Word::Constant(1u64 << j), 2, scaled)
                    || !self.arithmetic_op(prior, scaled, 0, next) { return false; }
                prior = next;
            }
            self.graph.equalities.contains(&(source, prior))
        })
    }
    pub(crate) fn check_arithmetic_roles(
        &self,
        r: &PrivateSpendArithmeticRoles,
    ) -> Result<(), &'static str> {
        let fail = || Err("private spend arithmetic topology mismatch");
        for i in 0..77 {
            if r.public[i] != Word::Wire(i) {
                return fail();
            }
        }
        if r.selector_prefix[0] != Word::ZERO {
            return fail();
        }
        for i in 0..6 {
            if !matches!(self.arithmetic_node(r.modes[i]), Some(Node::Input(_)))
                || !self.arithmetic_boolean(r.modes[i])
                || !self.arithmetic_op(
                    r.selector_prefix[i],
                    r.modes[i],
                    0,
                    r.selector_prefix[i + 1],
                )
            {
                return fail();
            }
        }
        if !self
            .graph
            .equalities
            .contains(&(r.selector_prefix[6], Word::ONE))
        {
            return fail();
        }
        if r.values[4] != r.public[24] {
            return fail();
        }
        for value in r.values {
            if !self.arithmetic_range(value, 56) {
                return fail();
            }
        }
        if !self.arithmetic_op(r.values[0], r.values[1], 0, r.balance[0])
            || !self.arithmetic_op(r.values[2], r.values[3], 0, r.balance[1])
            || !self.arithmetic_op(r.balance[1], r.values[4], 0, r.balance[2])
            || !self
                .graph
                .equalities
                .contains(&(r.balance[0], r.balance[2]))
        {
            return fail();
        }
        if !self.arithmetic_range(r.public[16], 48)
            || !self.arithmetic_range(r.timeout, 48)
            || !self.arithmetic_op(r.timeout, r.public[16], 1, r.lock_steps[0])
            || !self.arithmetic_op(r.lock_steps[0], Word::Constant(14), 1, r.lock_steps[1])
            || !self.arithmetic_op(r.modes[3], r.lock_steps[1], 2, r.lock_steps[2])
            || !self.arithmetic_range(r.lock_steps[2], 48)
            || !self.arithmetic_op(r.public[16], r.timeout, 1, r.refund_steps[0])
            || !self.arithmetic_op(r.modes[5], r.refund_steps[0], 2, r.refund_steps[1])
            || !self.arithmetic_range(r.refund_steps[1], 48)
        {
            return fail();
        }
        for i in 0..54 {
            let source = if i < 8 {
                i
            } else if i == 8 {
                24
            } else if i < 16 {
                i + 16
            } else {
                i + 23
            };
            if !self.arithmetic_gate(r.modes[2], r.intent[i], r.public[source]) {
                return fail();
            }
        }
        if !self.arithmetic_op(r.modes[4], r.modes[5], 0, r.unlocked)
            || !self.arithmetic_gate(r.unlocked, r.values[2], r.values[0])
        {
            return fail();
        }
        Ok(())
    }
}

#[cfg(test)]
impl HtlcAdapter {
    pub fn lowering_census(&self) -> Vec<(&'static str, usize)> {
        let nodes = &self.graph.nodes;
        let ordinary = self.affine.ordinary_products(&self.graph);
        let zero_products = ordinary
            .iter()
            .filter(|(o, _, _)| self.graph.equalities.contains(&(*o, Word::ZERO)))
            .count();
        vec![
            ("source_nodes", nodes.len()),
            ("canonical_nodes", self.affine.committed_nodes.len()),
            ("canonical_slots", self.affine.canonical_slots()),
            (
                "canonical_rows",
                self.affine.canonical_slots().div_ceil(PACKING),
            ),
            ("source_inputs", self.graph.input_count),
            (
                "source_bits",
                nodes.iter().filter(|n| matches!(n, Node::Bit(..))).count(),
            ),
            ("boolean_guards", self.affine.guards.len()),
            ("boolean_rows", self.affine.boolean_rows.len()),
            ("source_products", self.graph.products.len()),
            ("ordinary_products", ordinary.len()),
            ("ordinary_batches", self.batches.len()),
            (
                "ordinary_zero_batches",
                self.batches.iter().filter(|b| b.output.is_none()).count(),
            ),
            ("ordinary_product_rows", self.ordinary_product_row_count()),
            ("ordinary_zero_products", zero_products),
            (
                "poseidon_outputs",
                nodes
                    .iter()
                    .filter(|n| matches!(n, Node::PoseidonOutput { .. }))
                    .count(),
            ),
            (
                "sha_outputs",
                nodes
                    .iter()
                    .filter(|n| matches!(n, Node::CompactShaOutput { .. }))
                    .count(),
            ),
            (
                "inverse_nodes",
                nodes
                    .iter()
                    .filter(|n| matches!(n, Node::Inverse(..)))
                    .count(),
            ),
            ("total_rows", self.geometry.rows),
        ]
    }
}

#[cfg(test)]
mod zero_product_tests {
    use super::*;
    fn fixture() -> HtlcAdapter {
        let scope = Scope::start();
        let zero = input();
        let a = input();
        let b = input();
        for i in 0..65 {
            equal(zero * (a + Word::from_u64(i)), Word::ZERO);
            let _ = a * (b + Word::from_u64(i));
        }
        HtlcAdapter::from_graph(scope.finish())
    }
    #[test]
    fn mixed_zero_and_nonzero_products_use_two_and_three_rows() {
        let adapter = fixture();
        assert_eq!(adapter.batches.len(), 4);
        assert_eq!(
            adapter
                .batches
                .iter()
                .filter(|b| b.output.is_none())
                .count(),
            2
        );
        assert_eq!(adapter.ordinary_product_row_count(), 10);
        assert_eq!(
            adapter.geometry.rows,
            adapter.affine.canonical_slots().div_ceil(PACKING) + 10
        );
        adapter.check_source_lowering::<0>(&[], &[]).unwrap();
        let witness = adapter.evaluate(&[0, 5, 7]).unwrap();
        adapter.verify_packed_witness(&witness).unwrap();
        assert!(adapter
            .verify_packed_witness(&adapter.evaluate(&[1, 5, 7]).unwrap())
            .is_err());
        let rows = vec![1; adapter.geometry.rows];
        let mut out = vec![0; adapter.constraint_count()];
        adapter
            .compute_constraints_u64(
                SmallwoodNonlinearEvalView::RowScalars {
                    eval_point: 0,
                    rows: &rows,
                    auxiliary_words: &[],
                },
                &mut out,
            )
            .unwrap();
        assert_eq!(out, vec![P - 1, P - 1, 0, 0]);
    }
    #[test]
    fn zero_product_rows_bind_every_real_and_padding_operand() {
        let adapter = fixture();
        let witness = adapter.evaluate(&[0, 5, 7]).unwrap();
        let first = adapter.affine.canonical_slots().div_ceil(PACKING) * PACKING;
        for slot in first..witness.len() {
            let mut bad = witness.clone();
            bad[slot] = add(bad[slot], 1);
            assert!(
                adapter.verify_packed_witness(&bad).is_err(),
                "unbound occurrence {slot}"
            );
        }
        let mut adapter = fixture();
        adapter.batches[0].output = Some(adapter.batches[0].left);
        assert!(adapter.check_source_lowering::<0>(&[], &[]).is_err());
        let mut adapter = fixture();
        adapter.batches[0].right = adapter.batches[0].left;
        assert!(adapter.check_source_lowering::<0>(&[], &[]).is_err());
        let mut adapter = fixture();
        adapter.occurrence_sources[0] = Word::ONE;
        assert!(adapter.check_source_lowering::<0>(&[], &[]).is_err());
    }
}
