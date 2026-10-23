//! Development-only finite CSR/COMPFF01 locator export; no proof execution.
//!
//! Staged source: integrate as a crate-local feature-gated module only after the
//! frozen lifecycle ends. All symbolic arithmetic delegates to the existing
//! `Word` implementation and the existing generic compressor. No secret or
//! satisfying assignment is needed. Matching rows is finite source evidence,
//! not a Lean certificate or an acceptance-to-assignment theorem.
#![forbid(unsafe_code)]

use crate::{
    asset_policy_admin_v1::{self as admin, PolicyAdminPublicV1},
    smallwood_htlc::circuit::{input, HtlcAdapter, Scope, Word},
    smallwood_semantics::SmallwoodConstraintAdapter,
    TransactionCircuitError,
};
use hegemon_field::{PrimeCharacteristicRing, GOLDILOCKS_MODULUS as P};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use transaction_core::poseidon2_width16::{
    poseidon2_width16_compress14_ring, poseidon2_width16_step_ring,
    POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER, POSEIDON2_WIDTH16_STEPS,
};

const PUBLIC: usize = 134;
const SECRET: usize = 134;
const ASSET: usize = 32;
const ADMIN: usize = 35;
const INITIAL_INPUTS: usize = 148;
const MAX_CANONICAL_WIRES: usize = 65_536;

fn error(message: &'static str) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolation(message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Add,
    Sub,
    Mul,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Operation {
    kind: Kind,
    left: Word,
    right: Word,
    output: Word,
}
thread_local! {
    static OPERATIONS: RefCell<Vec<Operation>> = const { RefCell::new(Vec::new()) };
}

/// Instrumentation wrapper only: arithmetic and constant folding are performed
/// by the original Word operator, with its original Graph scope and allocator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
struct Logged(Word);
impl Logged {
    fn operation(self, rhs: Self, kind: Kind) -> Self {
        let output = match kind {
            Kind::Add => self.0 + rhs.0,
            Kind::Sub => self.0 - rhs.0,
            Kind::Mul => self.0 * rhs.0,
        };
        OPERATIONS.with(|v| {
            v.borrow_mut().push(Operation {
                kind,
                left: self.0,
                right: rhs.0,
                output,
            });
        });
        Self(output)
    }
}
impl Add for Logged {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        self.operation(rhs, Kind::Add)
    }
}
impl Sub for Logged {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self.operation(rhs, Kind::Sub)
    }
}
impl Mul for Logged {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        self.operation(rhs, Kind::Mul)
    }
}
impl AddAssign for Logged {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl SubAssign for Logged {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl MulAssign for Logged {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}
impl Neg for Logged {
    type Output = Self;
    fn neg(self) -> Self {
        Self::ZERO - self
    }
}
impl Sum for Logged {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |a, b| a + b)
    }
}
impl Product for Logged {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |a, b| a * b)
    }
}
impl PrimeCharacteristicRing for Logged {
    const ZERO: Self = Self(Word::Constant(0));
    const ONE: Self = Self(Word::Constant(1));
    const TWO: Self = Self(Word::Constant(2));
    const NEG_ONE: Self = Self(Word::Constant(P - 1));
    fn from_bool(value: bool) -> Self {
        Self(Word::from_bool(value))
    }
    fn from_u64(value: u64) -> Self {
        Self(Word::from_u64(value))
    }
}

fn word(value: Word) -> Value {
    match value {
        Word::Constant(value) => json!({"constant":value}),
        Word::Wire(index) => json!({"wire":index}),
    }
}
fn words<const N: usize>(values: [Word; N]) -> Vec<Value> {
    values.into_iter().map(word).collect()
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Row {
    entries: Vec<(u32, u64)>,
    target: u64,
}

/// Finite row normalizer for comparison only, including moved constants and
/// duplicate-index coalescing. No assignment or witness evaluator is defined.
fn normalize(terms: &[(Word, u64)], mut target: u64) -> Option<Row> {
    let mut entries = BTreeMap::<u32, u64>::new();
    for &(value, coefficient) in terms {
        match value {
            Word::Constant(value) => {
                let product = (coefficient as u128 * value as u128) % P as u128;
                target = ((target as u128 + P as u128 - product) % P as u128) as u64;
            }
            Word::Wire(index) => {
                let old = entries.get(&(index as u32)).copied().unwrap_or(0);
                entries.insert(
                    index as u32,
                    ((old as u128 + coefficient as u128) % P as u128) as u64,
                );
            }
        }
    }
    entries.retain(|_, value| *value != 0);
    if entries.is_empty() && target == 0 {
        None
    } else {
        Some(Row {
            entries: entries.into_iter().collect(),
            target,
        })
    }
}

fn rows(adapter: &impl SmallwoodConstraintAdapter) -> Result<Vec<Row>, TransactionCircuitError> {
    let offsets = adapter.linear_constraint_offsets();
    let indices = adapter.linear_constraint_indices();
    let coefficients = adapter.linear_constraint_coefficients();
    let targets = adapter.linear_targets();
    let bound = adapter
        .row_count()
        .checked_mul(64)
        .ok_or_else(|| error("admin topology overflow"))?;
    if offsets.len() != targets.len() + 1
        || offsets.first() != Some(&0)
        || offsets.last().copied().map(|v| v as usize) != Some(indices.len())
        || indices.len() != coefficients.len()
        || offsets.windows(2).any(|v| v[0] > v[1])
    {
        return Err(error("admin topology malformed CSR arrays"));
    }
    let mut result = Vec::with_capacity(targets.len());
    for (row, &target) in targets.iter().enumerate() {
        let begin = offsets[row] as usize;
        let end = offsets[row + 1] as usize;
        let entries: Vec<_> = indices[begin..end]
            .iter()
            .copied()
            .zip(coefficients[begin..end].iter().copied())
            .collect();
        if target >= P
            || entries.iter().any(|&(index, coefficient)| {
                index as usize >= bound || coefficient == 0 || coefficient >= P
            })
            || entries.windows(2).any(|v| v[0].0 >= v[1].0)
        {
            return Err(error("admin topology noncanonical CSR row"));
        }
        result.push(Row { entries, target });
    }
    Ok(result)
}

fn row_index(values: &[Row]) -> BTreeMap<Row, Vec<usize>> {
    let mut result = BTreeMap::<Row, Vec<usize>>::new();
    for (i, value) in values.iter().enumerate() {
        result.entry(value.clone()).or_default().push(i);
    }
    result
}

fn unique_row(
    index: &BTreeMap<Row, Vec<usize>>,
    row: &Row,
) -> Result<usize, TransactionCircuitError> {
    match index.get(row).map(Vec::as_slice) {
        Some([found]) => Ok(*found),
        _ => Err(error("admin topology expected unique actual CSR row")),
    }
}

#[derive(Clone, Debug)]
struct ProductOccurrence {
    output: Word,
    left: Word,
    right: Word,
    copies: [usize; 3],
    occurrence_indices: [usize; 3],
    batch: usize,
    lane: usize,
}

fn product_occurrences(
    actual: &[Row],
    canonical: usize,
    batches: usize,
    total_rows: usize,
) -> Result<Vec<ProductOccurrence>, TransactionCircuitError> {
    let base = canonical.div_ceil(64) * 64;
    if total_rows != canonical.div_ceil(64) + 3 * batches {
        return Err(error("admin topology unexpected packed nonlinear geometry"));
    }
    // Each occurrence copy is an exact source Word, never a value inferred
    // from a satisfying witness. The last product may be padded repeatedly.
    let mut copies = BTreeMap::<usize, Vec<(Word, usize)>>::new();
    for (row_index, row) in actual.iter().enumerate() {
        let source = match row.entries.as_slice() {
            &[(occurrence, 1)] if occurrence as usize >= base => {
                Some((occurrence as usize, Word::Constant(row.target)))
            }
            &[(source, coefficient), (occurrence, 1)]
                if coefficient == P - 1
                    && row.target == 0
                    && (source as usize) < canonical
                    && occurrence as usize >= base =>
            {
                Some((occurrence as usize, Word::Wire(source as usize)))
            }
            _ => None,
        };
        if let Some((occurrence, source)) = source {
            copies
                .entry(occurrence)
                .or_default()
                .push((source, row_index));
        }
    }
    let mut result = Vec::with_capacity(64 * batches);
    for batch in 0..batches {
        for lane in 0..64 {
            let ids = core::array::from_fn(|operand| base + batch * 192 + operand * 64 + lane);
            let mut values = [Word::ZERO; 3];
            let mut row_ids = [0; 3];
            for operand in 0..3 {
                match copies.get(&ids[operand]).map(Vec::as_slice) {
                    Some(&[(source, row)]) => {
                        values[operand] = source;
                        row_ids[operand] = row;
                    }
                    _ => return Err(error("admin topology occurrence lacks unique source copy")),
                }
            }
            result.push(ProductOccurrence {
                output: values[0],
                left: values[1],
                right: values[2],
                copies: row_ids,
                occurrence_indices: ids,
                batch,
                lane,
            });
        }
    }
    Ok(result)
}

struct PrimitiveTrace {
    adapter: HtlcAdapter,
    output: [Word; 7],
    operations: Vec<Operation>,
    round_states: Vec<[Word; 16]>,
}

fn primitive(
    prefix: usize,
    capture_rounds: bool,
) -> Result<PrimitiveTrace, TransactionCircuitError> {
    if !(INITIAL_INPUTS..=MAX_CANONICAL_WIRES).contains(&prefix) {
        return Err(error("admin topology primitive prefix bound"));
    }
    let scope = Scope::start();
    for index in 0..prefix {
        if input() != Word::Wire(index) {
            return Err(error("admin topology fresh input allocator mismatch"));
        }
    }
    OPERATIONS.with(|v| v.borrow_mut().clear());
    let left = core::array::from_fn(|i| Logged(Word::Wire(SECRET + i)));
    let right = core::array::from_fn(|i| {
        if i == 0 {
            Logged(Word::Wire(ASSET))
        } else {
            Logged::ZERO
        }
    });
    let mut round_states = Vec::new();
    let output = if capture_rounds {
        // This exposes boundaries of the existing public step function. The
        // entire operator stream is then required to equal the monolithic
        // original compress14 call, so no new permutation semantics is used.
        let mut state = [Logged::ZERO; 16];
        state[..7].copy_from_slice(&left);
        state[7..14].copy_from_slice(&right);
        state[14] = Logged::from_u64(admin::POLICY_ADMIN_COMMITMENT_DOMAIN);
        state[15] = Logged::from_u64(POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER);
        round_states.push(state.map(|w| w.0));
        for step in 0..POSEIDON2_WIDTH16_STEPS {
            poseidon2_width16_step_ring(&mut state, step);
            round_states.push(state.map(|w| w.0));
        }
        core::array::from_fn(|i| (state[i] + left[i]).0)
    } else {
        poseidon2_width16_compress14_ring(admin::POLICY_ADMIN_COMMITMENT_DOMAIN, &left, &right)
            .map(|w| w.0)
    };
    let operations = OPERATIONS.with(|v| std::mem::take(&mut *v.borrow_mut()));
    let adapter = HtlcAdapter::from_graph(scope.finish());
    Ok(PrimitiveTrace {
        adapter,
        output,
        operations,
        round_states,
    })
}

fn validate_fold(operation: Operation) -> bool {
    let Operation {
        kind,
        left,
        right,
        output,
    } = operation;
    let expected = match (left, right) {
        (Word::Constant(a), Word::Constant(b)) => Some(Word::Constant(match kind {
            Kind::Add => ((a as u128 + b as u128) % P as u128) as u64,
            Kind::Sub => ((a as u128 + P as u128 - b as u128) % P as u128) as u64,
            Kind::Mul => ((a as u128 * b as u128) % P as u128) as u64,
        })),
        (_, Word::Constant(0)) if kind != Kind::Mul => Some(left),
        (Word::Constant(0), _) if kind == Kind::Add => Some(right),
        (_, Word::Constant(0)) | (Word::Constant(0), _) if kind == Kind::Mul => Some(Word::ZERO),
        (Word::Constant(1), _) if kind == Kind::Mul => Some(right),
        (_, Word::Constant(1)) if kind == Kind::Mul => Some(left),
        _ => None,
    };
    expected == Some(output)
}

fn check_operations(
    trace: &PrimitiveTrace,
    start: usize,
    canonical: usize,
    actual: &[Row],
    products: &[ProductOccurrence],
) -> Result<Vec<Value>, TransactionCircuitError> {
    let index = row_index(actual);
    let mut next = start;
    let mut result = Vec::with_capacity(trace.operations.len());
    for (ordinal, &operation) in trace.operations.iter().enumerate() {
        if [operation.left, operation.right]
            .into_iter()
            .any(|value| matches!(value, Word::Wire(index) if index >= next))
        {
            return Err(error("admin topology forward operation operand"));
        }
        let allocated = operation.output == Word::Wire(next);
        let evidence = if allocated {
            next += 1;
            if operation.kind == Kind::Mul {
                let matches: Vec<_> = products
                    .iter()
                    .filter(|p| {
                        p.output == operation.output
                            && p.left == operation.left
                            && p.right == operation.right
                    })
                    .collect();
                if matches.is_empty() {
                    return Err(error(
                        "admin topology primitive product absent from actual CSR",
                    ));
                }
                json!({"product_occurrences":matches.iter().map(|p|json!({"batch":p.batch,"lane":p.lane,
                    "copy_rows":p.copies,"occurrence_indices":p.occurrence_indices})).collect::<Vec<_>>()})
            } else {
                let rhs = if operation.kind == Kind::Sub {
                    1
                } else {
                    P - 1
                };
                let row = normalize(
                    &[
                        (operation.output, 1),
                        (operation.left, P - 1),
                        (operation.right, rhs),
                    ],
                    0,
                )
                .ok_or_else(|| error("admin topology allocated linear row vanished"))?;
                json!({"linear_row":unique_row(&index,&row)?})
            }
        } else {
            if !validate_fold(operation) {
                return Err(error("admin topology invalid constant/zero/one fold"));
            }
            json!({"constant_or_identity_fold":"checked against existing Word fold cases"})
        };
        result.push(json!({"ordinal":ordinal,"kind":match operation.kind {Kind::Add=>"add",Kind::Sub=>"sub",Kind::Mul=>"mul"},
            "left":word(operation.left),"right":word(operation.right),"output":word(operation.output),"evidence":evidence}));
    }
    if next != canonical {
        return Err(error(
            "admin topology primitive does not cover exact canonical suffix",
        ));
    }
    Ok(result)
}

const CSR_DIGEST_FORMAT: &str = "Hegemon.AdminTopology.CSR.mixed-width-le.v1";

fn csr_digest(adapter: &impl SmallwoodConstraintAdapter) -> String {
    let mut hash = Sha256::new();
    hash.update(CSR_DIGEST_FORMAT.as_bytes());
    for count in [
        adapter.row_count(),
        64,
        adapter.constraint_count(),
        adapter.linear_constraint_count(),
    ] {
        hash.update((count as u64).to_le_bytes());
    }
    for values in [
        adapter.linear_constraint_offsets(),
        adapter.linear_constraint_indices(),
    ] {
        hash.update((values.len() as u64).to_le_bytes());
        for value in values {
            hash.update(value.to_le_bytes());
        }
    }
    for values in [
        adapter.linear_constraint_coefficients(),
        adapter.linear_targets(),
    ] {
        hash.update((values.len() as u64).to_le_bytes());
        for value in values {
            hash.update(value.to_le_bytes());
        }
    }
    hex::encode(hash.finalize())
}

/// Actual existing admin adapter -> CSR and exact compressor/equality locators.
/// Does not evaluate a witness, verify a proof, or authenticate a registry row.
pub fn admin_topology_readout(
    public: &PolicyAdminPublicV1,
) -> Result<Value, TransactionCircuitError> {
    public.validate_structure()?;
    let adapter = admin::PolicyAdminAdapterV1::from_public(public)?;
    let geometry = adapter.geometry();
    let canonical = geometry.canonical_wires;
    if canonical > MAX_CANONICAL_WIRES
        || geometry.private_inputs != INITIAL_INPUTS
        || geometry.packing != 64
        || geometry.degree != 2
    {
        return Err(error("admin topology unexpected source geometry"));
    }
    let actual = rows(&adapter)?;
    let index = row_index(&actual);
    let public_values = public.words();
    let mut public_rows = Vec::new();
    for i in 0..PUBLIC {
        let expected = Row {
            entries: vec![(i as u32, 1)],
            target: public_values[i],
        };
        let last = actual
            .len()
            .checked_sub(PUBLIC)
            .ok_or_else(|| error("admin topology missing public suffix"))?
            + i;
        if actual[last] != expected {
            return Err(error("admin topology exact134 public suffix mismatch"));
        }
        public_rows.push(last);
    }
    let mut output = [Word::ZERO; 7];
    let mut output_rows = [0; 7];
    for limb in 0..7 {
        let public_index = (ADMIN + limb) as u32;
        let candidates: Vec<_> = actual
            .iter()
            .enumerate()
            .filter_map(|(i, row)| match row.entries.as_slice() {
                &[(p, c), (out, 1)]
                    if p == public_index
                        && c == P - 1
                        && row.target == 0
                        && out as usize >= INITIAL_INPUTS
                        && (out as usize) < canonical =>
                {
                    Some((i, out as usize))
                }
                _ => None,
            })
            .collect();
        match candidates.as_slice() {
            &[(row, out)] => {
                output[limb] = Word::Wire(out);
                output_rows[limb] = row;
            }
            _ => return Err(error("admin topology admin output equality is not unique")),
        }
    }
    if output
        .iter()
        .filter_map(|w| {
            if let Word::Wire(i) = w {
                Some(*i)
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>()
        .len()
        != 7
    {
        return Err(error("admin topology repeated commitment output wire"));
    }
    let reference = primitive(INITIAL_INPUTS, false)?;
    let primitive_nodes = reference.adapter.geometry().canonical_wires - INITIAL_INPUTS;
    let start = canonical
        .checked_sub(primitive_nodes)
        .ok_or_else(|| error("admin topology source shorter than compressor"))?;
    let trace = primitive(start, false)?;
    if trace.adapter.geometry().canonical_wires != canonical || trace.output != output {
        return Err(error(
            "admin topology actual outputs differ from exact generic compressor",
        ));
    }
    let staged = primitive(start, true)?;
    if staged.output != trace.output
        || staged.operations != trace.operations
        || rows(&staged.adapter)? != rows(&trace.adapter)?
    {
        return Err(error(
            "admin topology stepped compressor differs from original generic call",
        ));
    }
    let products = product_occurrences(
        &actual,
        canonical,
        adapter.constraint_count(),
        adapter.row_count(),
    )?;
    let checked_operations = check_operations(&trace, start, canonical, &actual, &products)?;
    // Explicit direct rows accompany output locators, independently of search.
    for limb in 0..7 {
        let expected =
            normalize(&[(output[limb], 1), (Word::Wire(ADMIN + limb), P - 1)], 0).unwrap();
        if unique_row(&index, &expected)? != output_rows[limb] {
            return Err(error(
                "admin topology commitment equality readback mismatch",
            ));
        }
    }
    Ok(json!({
        "schema":"hegemon.asset-admin.actual-csr-topology.v1",
        "relation_id":admin::RELATION_ID,"source_sha512":hex::encode(admin::relation_digest()),
        "interpretation":"Finite CSR/operation-locator match to actual existing source adapter; not proof acceptance or source extraction",
        "public_words":public_values.to_vec(),"public_binding_rows":public_rows,
        "input_ordinals":{"public":[0,133],"secret":[134,140],"selector":[141,147]},
        "geometry":{"canonical_wires":canonical,"packed_rows":adapter.row_count(),"packing":64,
            "nonlinear_batches":adapter.constraint_count(),"linear_rows":actual.len()},
        "csr":{"sha256_format":CSR_DIGEST_FORMAT,"sha256":csr_digest(&adapter),
            "sha256_grammar":"domain UTF-8 bytes without length prefix; row_count, packing=64, nonlinear_batches, linear_rows as u64LE; offsets then indices, each prefixed by element count u64LE and encoded as u32LE elements; coefficients then targets, each prefixed by element count u64LE and encoded as u64LE elements",
            "offsets":adapter.linear_constraint_offsets(),"indices":adapter.linear_constraint_indices(),
            "coefficients":adapter.linear_constraint_coefficients(),"targets":adapter.linear_targets()},
        "compressor":{"domain":admin::POLICY_ADMIN_COMMITMENT_DOMAIN,"canonical_start":start,
            "canonical_end_exclusive":canonical,"allocated_nodes":primitive_nodes,
            "left":words(core::array::from_fn::<_,7,_>(|i|Word::Wire(SECRET+i))),
            "right":words([Word::Wire(ASSET),Word::ZERO,Word::ZERO,Word::ZERO,Word::ZERO,Word::ZERO,Word::ZERO]),
            "outputs":words(output),"public_output_indices":[35,36,37,38,39,40,41],"output_equality_rows":output_rows,
            "operations":checked_operations,"round_states":staged.round_states.into_iter().map(words).collect::<Vec<_>>(),
            "step_count":POSEIDON2_WIDTH16_STEPS,
            "round_capture_method":"existing step_ring; identical operator stream and CSR to original generic compress14_ring"},
        "residual_obligations":[
            "Lean construction/checking of current literal topology certificates against exported actual CSR and operation locators",
            "CSR/compiler/field representation interpretation under retained assumptions",
            "same original accepted branch/basis recovered assignment and missing-source/abort coverage",
            "administrator knowledge/extraction, actual primitive-game advantages and shared-oracle composition",
            "authenticated registry transition/replay publication and separately defined privacy game"
        ],
        "executions":{"proof_generation":0,"proof_verification":0,"witness_evaluation":0},
        "authority_effect":"none"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn public() -> PolicyAdminPublicV1 {
        use transaction_core::{asset_registry_v1::AssetControlsV1, poseidon2_width16::Felt};
        PolicyAdminPublicV1 {
            chain_id: [1; 32],
            reference_parent_hash: [2; 32],
            parent_height: 100,
            registry_root: [3; 7],
            after_registry_root: [4; 7],
            asset_id: 17,
            old_policy_version: 1,
            new_policy_version: 1,
            policy_admin_commitment: [5; 7],
            before_policy_leaf: [6; 7],
            after_policy_leaf: [7; 7],
            controls: AssetControlsV1 {
                credential_root: [Felt::from_u64(8); 7],
                credential_depth: 4,
                frozen: false,
                mint_enabled: true,
            },
            expires_at: 200,
            action_intent: [9; 7],
        }
    }
    #[test]
    fn actual_admin_topology_exports_exact_public_and_compressor() {
        let p = public();
        let value = admin_topology_readout(&p).unwrap();
        assert_eq!(value["public_words"], json!(p.words().to_vec()));
        assert_eq!(value["compressor"]["outputs"].as_array().unwrap().len(), 7);
        assert_eq!(
            value["compressor"]["round_states"]
                .as_array()
                .unwrap()
                .len(),
            POSEIDON2_WIDTH16_STEPS + 1
        );
    }
    #[test]
    fn changed_actual_linear_coefficient_is_rejected() {
        let adapter = admin::PolicyAdminAdapterV1::from_public(&public()).unwrap();
        let mut actual = rows(&adapter).unwrap();
        let canonical = adapter.geometry().canonical_wires;
        let n = primitive(INITIAL_INPUTS, false)
            .unwrap()
            .adapter
            .geometry()
            .canonical_wires
            - INITIAL_INPUTS;
        let trace = primitive(canonical - n, false).unwrap();
        let products = product_occurrences(
            &actual,
            canonical,
            adapter.constraint_count(),
            adapter.row_count(),
        )
        .unwrap();
        let op = trace
            .operations
            .iter()
            .find(|op| {
                op.kind == Kind::Add
                    && matches!(op.output,Word::Wire(i) if i>=canonical-n)
                    && !validate_fold(**op)
            })
            .copied()
            .unwrap();
        let row = normalize(&[(op.output, 1), (op.left, P - 1), (op.right, P - 1)], 0).unwrap();
        let i = unique_row(&row_index(&actual), &row).unwrap();
        actual[i].entries[0].1 = (actual[i].entries[0].1 + 1) % P;
        assert!(check_operations(&trace, canonical - n, canonical, &actual, &products).is_err());
    }
    #[test]
    fn changed_actual_product_operand_is_rejected() {
        let adapter = admin::PolicyAdminAdapterV1::from_public(&public()).unwrap();
        let mut actual = rows(&adapter).unwrap();
        let canonical = adapter.geometry().canonical_wires;
        let n = primitive(INITIAL_INPUTS, false)
            .unwrap()
            .adapter
            .geometry()
            .canonical_wires
            - INITIAL_INPUTS;
        let trace = primitive(canonical - n, false).unwrap();
        let products = product_occurrences(
            &actual,
            canonical,
            adapter.constraint_count(),
            adapter.row_count(),
        )
        .unwrap();
        let target = trace
            .operations
            .iter()
            .find(|op| {
                op.kind == Kind::Mul
                    && matches!(op.output,Word::Wire(i) if i>=canonical-n)
                    && !validate_fold(**op)
            })
            .unwrap()
            .output;
        for occurrence in &products {
            if occurrence.output == target {
                // Alter the actual copied operand equation, then reconstruct
                // the product topology from the damaged CSR itself.
                actual[occurrence.copies[1]] = Row {
                    entries: vec![(occurrence.occurrence_indices[1] as u32, 1)],
                    target: 42,
                };
            }
        }
        let products = product_occurrences(
            &actual,
            canonical,
            adapter.constraint_count(),
            adapter.row_count(),
        )
        .unwrap();
        assert!(check_operations(&trace, canonical - n, canonical, &actual, &products).is_err());
    }
}
