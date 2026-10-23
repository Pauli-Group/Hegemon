//! Disposable-fixture PACKED relation export; no proof/source-AST certificate.
//! Add only `#[cfg(test)] mod asset_recovery_certificate_v1;` to lib.rs.
//! Does not write assignments. The output contains every CSR cell and every
//! packed nonlinear lane. HtlcAdapter's source-to-packed interpretation remains
//! explicit: the public trait does not expose its original Graph node table.

use crate::{
    asset_recovery_admin_v1 as admin, asset_recovery_capsule_v1 as capsule,
    asset_recovery_spend_v1 as spend,
    smallwood_engine::SmallwoodArithmetization,
    smallwood_htlc::HtlcGeometry,
    smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodLinearConstraintForm},
};
use serde::Serialize;
use sha2::{Digest, Sha512};
use std::{fs::{File, OpenOptions}, io::{self, BufWriter, Write}, path::Path};
use transaction_core::asset_recovery_v1 as recovery;

const P: u64 = 0xffff_ffff_0000_0001;
const K: usize = 64;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn require(ok: bool, what: &str) -> Result<()> {
    if !ok { return Err(io::Error::other(what.to_owned()).into()); }
    Ok(())
}
fn add(a: u64, b: u64) -> u64 { ((a as u128 + b as u128) % P as u128) as u64 }
fn mul(a: u64, b: u64) -> u64 { ((a as u128 * b as u128) % P as u128) as u64 }
fn sub(a: u64, b: u64) -> u64 { ((a as u128 + P as u128 - b as u128) % P as u128) as u64 }

#[derive(Serialize)]
struct Product {
    // Output, left, right ABSOLUTE packed-cell indices; all lanes included.
    packed: [usize; 3],
    // Canonical source descriptor [tag,value]: tag0 constant, tag1 wire.
    // Recovered from the actual three complete CSR copy rows, not a guess.
    canonical_sources: [[u64; 2]; 3],
}
#[derive(Serialize)]
struct Program<'a> {
    schema: &'static str,
    source_sha512: String,
    source_interpretation: &'static str,
    exporter_sha512: String,
    name: &'a str,
    route: u64,
    modulus: u64,
    packing: usize,
    degree: usize,
    canonical_wires: usize,
    canonical_rows: usize,
    packed_rows: usize,
    packed_cells: usize,
    graph_input_count_including_public: usize,
    auxiliary_limbs: usize,
    public_words: &'a [u64],
    full_binding_hex: String,
    transcript134_words: Vec<u64>,
    offsets: &'a [u32],
    indices: &'a [u32],
    coefficients: &'a [u64],
    targets: &'a [u64],
    public_row_start: usize,
    zero_padding_range: [usize; 2],
    zero_padding_row_start: usize,
    copy_row_start: usize,
    products: Vec<Product>,
    raw_csr_sha512: String,
    public_rhs_normalized_csr_sha512: String,
    fixture_packed_cells_checked: usize,
    fixture_csr_rows_checked: usize,
    fixture_nonlinear_lanes_checked: usize,
    fixture_assignment_exported: bool,
}

// Fixed integer/array boundaries, never JSON presentation, define these hashes.
fn csr_digest(a: &dyn SmallwoodConstraintAdapter, public_start: usize, normalize: bool) -> String {
    let mut h = Sha512::new();
    h.update(b"Hegemon.Recovery.PackedCsr.v1");
    for values in [a.linear_constraint_offsets(), a.linear_constraint_indices()] {
        h.update((values.len() as u64).to_le_bytes());
        for v in values { h.update(v.to_le_bytes()); }
    }
    let values = a.linear_constraint_coefficients();
    h.update((values.len() as u64).to_le_bytes());
    for v in values { h.update(v.to_le_bytes()); }
    let values = a.linear_targets();
    h.update((values.len() as u64).to_le_bytes());
    for (i, v) in values.iter().enumerate() {
        h.update((if normalize && i >= public_start { 0 } else { *v }).to_le_bytes());
    }
    hex::encode(h.finalize())
}

struct HashedWriter { file: BufWriter<File>, digest: Sha512 }
impl Write for HashedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.file.write(bytes)?;
        self.digest.update(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> { self.file.flush() }
}

fn export(
    directory: &Path, name: &str, route: u64, source: [u8; 64],
    a: &dyn SmallwoodConstraintAdapter, g: &HtlcGeometry,
    public: &[u64], binding: &[u8], packed: &[u64],
) -> Result<serde_json::Value> {
    require(a.arithmetization() == SmallwoodArithmetization::DirectPacked64AssetSpendSha512Smze,
        "arithmetization differs")?;
    require(a.packing_factor() == K && a.constraint_degree() == 2
        && a.linear_constraint_form() == SmallwoodLinearConstraintForm::Generic,
        "packing/degree/linear form differs")?;
    require(a.auxiliary_witness_words().is_empty() && a.auxiliary_witness_limb_count() == Some(0),
        "unexpected auxiliary witness")?;
    let canonical_rows = g.canonical_wires.div_ceil(K);
    let canonical_len = canonical_rows.checked_mul(K).ok_or("canonical size overflow")?;
    let cells = a.row_count().checked_mul(K).ok_or("packed size overflow")?;
    let batches = a.constraint_count();
    let product_rows = batches.checked_mul(3).ok_or("product row overflow")?;
    require(cells <= u32::MAX as usize && public.len() <= g.canonical_wires,
        "uniform packed index/public bound")?;
    require(g.rows == a.row_count() && g.packing == K && g.degree == 2
        && g.nonlinear_batches == batches
        && Some(g.rows) == canonical_rows.checked_add(product_rows)
        && g.linear_equations == a.linear_constraint_count(), "geometry disagreement")?;
    require(packed.len() == cells && packed.iter().all(|v| *v < P), "fixture shape/canonicality")?;
    let offsets = a.linear_constraint_offsets();
    let indices = a.linear_constraint_indices();
    let coefficients = a.linear_constraint_coefficients();
    let targets = a.linear_targets();
    require(offsets.len() == targets.len() + 1 && offsets.first() == Some(&0)
        && offsets.last().map(|v| *v as usize) == Some(indices.len())
        && indices.len() == coefficients.len() && targets.len() == a.linear_constraint_count(),
        "CSR array shape")?;
    require(offsets.windows(2).all(|w| w[0] <= w[1])
        && indices.iter().all(|i| (*i as usize) < cells)
        && coefficients.iter().all(|v| *v > 0 && *v < P)
        && targets.iter().all(|v| *v < P), "CSR bounds/canonicality")?;
    let row = |r: usize| offsets[r] as usize..offsets[r + 1] as usize;
    // Independently replay EVERY CSR equation using exact integer modular math.
    for r in 0..targets.len() {
        require(indices[row(r)].windows(2).all(|w| w[0] < w[1]), "CSR row order/duplicate")?;
        let value = row(r).fold(0, |v, j| add(v, mul(coefficients[j], packed[indices[j] as usize])));
        require(value == targets[r], "fixture CSR residual")?;
    }
    let public_start = targets.len().checked_sub(public.len()).ok_or("public row underflow")?;
    for (i, value) in public.iter().enumerate() {
        let r = public_start + i;
        require(indices[row(r)] == [i as u32] && coefficients[row(r)] == [1]
            && targets[r] == *value, "exact public suffix row differs")?;
    }
    let copy_count = batches.checked_mul(3 * K).ok_or("copy size overflow")?;
    let copy_start = public_start.checked_sub(copy_count).ok_or("copy row underflow")?;
    let pad_count = canonical_len - g.canonical_wires;
    let pad_start = copy_start.checked_sub(pad_count).ok_or("pad row underflow")?;
    for i in 0..pad_count {
        let r = pad_start + i;
        let cell = g.canonical_wires + i;
        require(indices[row(r)] == [cell as u32] && coefficients[row(r)] == [1]
            && targets[r] == 0 && packed[cell] == 0, "canonical zero padding differs")?;
    }
    let mut products = Vec::with_capacity(batches * K);
    for b in 0..batches {
        let start = canonical_rows + 3 * b;
        for lane in 0..K {
            let mut sources = [[0; 2]; 3];
            let positions = core::array::from_fn(|operand| (start + operand) * K + lane);
            for operand in 0..3 {
                let r = copy_start + (b * 3 + operand) * K + lane;
                let js: Vec<_> = row(r).collect();
                let last = *js.last().ok_or("empty copy row")?;
                require(indices[last] as usize == positions[operand] && coefficients[last] == 1,
                    "copy destination differs")?;
                sources[operand] = if js.len() == 1 {
                    [0, targets[r]]
                } else {
                    require(js.len() == 2 && (indices[js[0]] as usize) < g.canonical_wires
                        && coefficients[js[0]] == P - 1 && targets[r] == 0, "copy source differs")?;
                    [1, indices[js[0]] as u64]
                };
            }
            require(packed[positions[0]] == mul(packed[positions[1]], packed[positions[2]]),
                "fixture nonlinear residual")?;
            products.push(Product { packed: positions, canonical_sources: sources });
        }
    }
    // Check the EXISTING trait evaluator against independent row-triple replay at
    // every lane of this disposable actual packed assignment, with no aux words.
    for lane in 0..K {
        let scalars: Vec<_> = (0..g.rows).map(|r| packed[r * K + lane]).collect();
        let mut actual = vec![0; batches];
        a.compute_constraints_u64(a.nonlinear_eval_view(0, &scalars, &[]), &mut actual)
            .map_err(|e| io::Error::other(e.to_string()))?;
        for (b, actual) in actual.iter().enumerate() {
            let s = canonical_rows + 3 * b;
            let expected = sub(scalars[s], mul(scalars[s + 1], scalars[s + 2]));
            require(*actual == expected && *actual == 0, "trait/packed fixture residual disagreement")?;
        }
    }
    require(binding.len() == 16 + public.len() * 8 && &binding[..8] == b"HGRECOV1"
        && u64::from_le_bytes(binding[8..16].try_into()?) == route, "full binding header")?;
    for (bytes, word) in binding[16..].chunks_exact(8).zip(public) {
        require(u64::from_le_bytes(bytes.try_into()?) == *word && *word < P, "full public binding")?;
    }
    require(matches!((route, public.len()), (1,182) | (2,82) | (3,128)), "new public width")?;
    // Independent documented backend-envelope construction; NOT public arity.
    let mut transcript = vec![0; 134];
    transcript[0] = u64::from_le_bytes(*b"HGRCBE01");
    transcript[1] = 1;
    transcript[2] = route;
    let digest = Sha512::digest(binding);
    for (i, bytes) in source.chunks_exact(4).chain(digest.chunks_exact(4)).enumerate() {
        transcript[3 + i] = u32::from_le_bytes(bytes.try_into()?) as u64;
    }
    let raw_hash = csr_digest(a, public_start, false);
    let normalized_hash = csr_digest(a, public_start, true);
    let program = Program {
        schema: "hegemon.recovery.complete-packed-program.v1",
        source_sha512: hex::encode(source),
        source_interpretation: "pinned Htlc source-to-packed/compiler/F1 boundary; no source AST export",
        exporter_sha512: hex::encode(Sha512::digest(include_bytes!("asset_recovery_certificate_v1.rs"))),
        name, route, modulus: P, packing: K, degree: 2,
        canonical_wires: g.canonical_wires, canonical_rows, packed_rows: g.rows, packed_cells: cells,
        graph_input_count_including_public: g.private_inputs, auxiliary_limbs: 0,
        public_words: public, full_binding_hex: hex::encode(binding), transcript134_words: transcript,
        offsets, indices, coefficients, targets, public_row_start: public_start,
        zero_padding_range: [g.canonical_wires, canonical_len], zero_padding_row_start: pad_start,
        copy_row_start: copy_start, products, raw_csr_sha512: raw_hash.clone(),
        public_rhs_normalized_csr_sha512: normalized_hash.clone(),
        fixture_packed_cells_checked: cells, fixture_csr_rows_checked: targets.len(),
        fixture_nonlinear_lanes_checked: batches * K, fixture_assignment_exported: false,
    };
    let path = directory.join(format!("{name}.packed.json"));
    let file = OpenOptions::new().write(true).create_new(true).open(&path)?;
    let mut out = HashedWriter { file: BufWriter::new(file), digest: Sha512::new() };
    serde_json::to_writer(&mut out, &program)?;
    out.write_all(b"\n")?;
    out.flush()?;
    let file_hash = hex::encode(out.digest.finalize());
    Ok(serde_json::json!({"name":name,"file":path.file_name().unwrap().to_string_lossy(),
        "file_sha512":file_hash,"source_sha512":hex::encode(source),"public_words":public.len(),
        "canonical_wires":g.canonical_wires,"rows":g.rows,"packing":K,"degree":2,
        "linear_rows":targets.len(),"csr_entries":indices.len(),"nonlinear_lanes":batches*K,
        "raw_csr_sha512":raw_hash,"public_rhs_normalized_csr_sha512":normalized_hash,
        "fixture_assignment_exported":false,"proof_generated":false,"proof_verified":false}))
}

fn source_pins() -> serde_json::Value {
    let files: &[(&str, &[u8])] = &[
        ("asset_recovery_capsule_v1.rs",include_bytes!("asset_recovery_capsule_v1.rs")),
        ("asset_recovery_chacha_v1.rs",include_bytes!("asset_recovery_chacha_v1.rs")),
        ("asset_recovery_backend_v1.rs",include_bytes!("asset_recovery_backend_v1.rs")),
        ("asset_recovery_spend_v1.rs",include_bytes!("asset_recovery_spend_v1.rs")),
        ("asset_recovery_admin_v1.rs",include_bytes!("asset_recovery_admin_v1.rs")),
        ("transaction-core/asset_recovery_v1.rs",include_bytes!("../../transaction-core/src/asset_recovery_v1.rs")),
        ("smallwood_htlc/circuit.rs",include_bytes!("smallwood_htlc/circuit.rs")),
        ("smallwood_htlc/sha256.rs",include_bytes!("smallwood_htlc/sha256.rs")),
        ("smallwood_engine.rs",include_bytes!("smallwood_engine.rs")),
        ("smallwood_semantics.rs",include_bytes!("smallwood_semantics.rs")),
        ("Cargo.lock",include_bytes!("../../../Cargo.lock")),
        ("asset_recovery_certificate_v1.rs",include_bytes!("asset_recovery_certificate_v1.rs")),
    ];
    let pins: Vec<_> = files.iter().map(|(name,bytes)| serde_json::json!({
        "name":name,"bytes":bytes.len(),"sha512":hex::encode(Sha512::digest(bytes))})).collect();
    serde_json::json!({"direct_members":pins,
        "retained_dependency_manifest_sha512":hex::encode(crate::asset_spend_v1::relation_digest()),
        "retained_admin_manifest_sha512":hex::encode(crate::asset_policy_admin_v1::relation_digest())})
}

#[test]
#[ignore = "coordinator only: exports full programs; requires a new HEGEMON_RECOVERY_CERTIFICATE_DIR"]
fn export_complete_recovery_packed_certificates_v1() -> Result<()> {
    let output = std::env::var_os("HEGEMON_RECOVERY_CERTIFICATE_DIR")
        .ok_or("set HEGEMON_RECOVERY_CERTIFICATE_DIR to a new output directory")?;
    let directory = Path::new(&output);
    std::fs::create_dir(directory)?; // Never replace historical evidence.
    let mut receipts = Vec::new();
    for (op, delegate, name) in [(0,false,"holder_transfer"),(0,true,"delegate_transfer"),
        (1,false,"mint"),(2,false,"holder_burn"),(2,true,"delegate_burn")] {
        let (p,w) = spend::fixtures::fixture(op,delegate).expect("public spend fixture");
        let (a,z) = spend::compile(&p,&w).expect("actual spend graph compile/check");
        a.verify_packed_witness(&z).expect("actual packed check");
        receipts.push(export(directory,name,1,spend::relation_digest(),&a,a.geometry(),
            &p.words().expect("public words"),&p.binding_bytes().expect("binding"),&z)?);
    }
    {
        require(capsule::SEGMENT_COUNT == 2, "certificate expects two capsule segments")?;
        let (p,w) = capsule::fixtures::fixture().expect("public capsule fixture");
        for segment in 0..capsule::SEGMENT_COUNT {
            let (a,z) = capsule::compile_segment(&p,&w,segment)
                .expect("actual admitted capsule segment graph compile/check");
            a.verify_packed_witness(&z).expect("actual packed check");
            receipts.push(export(directory,if segment == 0 {"capsule_segment0"} else {"capsule_segment1"},
                2,capsule::segment_relation_digest(capsule::relation_digest(),segment)
                    .expect("compiled segment source"),&a,a.geometry(),
                &p.words().expect("public words"),&p.binding_bytes().expect("binding"),&z)?);
        }
    }
    let secret = [0,2,3,4,5,6,7];
    let chain = [21;32];
    let descriptor = recovery::RecoveryDescriptorV1 { asset_id:17,stable_policy_id:[3;7],
        policy_admin_commitment:crate::asset_policy_admin_v1::policy_admin_commitment(17,secret)
            .expect("public admin fixture"),archive_key_commitment:[4;7],
        maximum_powers:recovery::RecoveryPowersV1 {transfer:true,burn:true} };
    let defaults = recovery::freeze_defaults(&descriptor,chain).expect("freeze defaults");
    let before = recovery::RecoveryRowV1 {descriptor,controls:recovery::RecoveryControlsV1 {
        epoch:0,delegate_action_commitment:[13;7],revoked:false,
        powers:recovery::RecoveryPowersV1 {transfer:true,burn:false},note_freeze_root:defaults[32]}};
    let context = recovery::RecoveryContextV1 {chain_id:chain,parent_hash:[22;32],parent_height:40,
        row_commitment:before.commitment(chain).expect("before row")};
    for freeze in [false,true] {
        let mut after = recovery::RecoveryControlsV1 {epoch:1,delegate_action_commitment:[17;7],..before.controls};
        let siblings = core::array::from_fn(|i| defaults[i]);
        let mutation = if freeze {
            after.note_freeze_root = recovery::freeze_root(&descriptor,chain,41,[9;7],true,&siblings)
                .expect("public freeze fixture");
            Some(admin::FreezeMutation {position:41,note_commitment:[9;7],before_frozen:false,after_frozen:true})
        } else { None };
        let prepared = recovery::prepare_controls_update(context,before,after).expect("admin prepare");
        let p = admin::Public::from_prepared(&prepared,42,[23;7],mutation).expect("admin public");
        let w = admin::Witness {admin_secret:secret,freeze_siblings:if freeze {siblings} else {[[0;7];32]}};
        let (a,z) = admin::compile(&p,&w).expect("actual admin graph compile/check");
        a.verify_packed_witness(&z).expect("actual packed check");
        receipts.push(export(directory,if freeze {"admin_freeze"} else {"admin_rotation"},3,
            admin::relation_digest(),&a,a.geometry(),&p.words().expect("public words"),
            &p.binding_bytes().expect("binding"),&z)?);
    }
    let path = directory.join("receipts.json");
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file,&serde_json::json!({
        "schema":"hegemon.recovery.packed-program-batch.v1","cases":receipts,
        "compiled_source_pins":source_pins(),
        "source_ast_exported":false,"compiler_equivalence_proved":false,
        "fixture_assignment_exported":false,"production_authorized":false}))?;
    file.write_all(b"\n")?;
    Ok(())
}
