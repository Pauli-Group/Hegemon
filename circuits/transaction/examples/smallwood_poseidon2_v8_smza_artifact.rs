//! Fresh q38 SMZA proof pair for the unchanged repaired positive-value relation.
//! Commands: project; generate NEW_DIRECTORY; verify DIRECTORY.
//! Retained metadata is informational and never production authorization.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "smallwood_poseidon2_v8_artifact.rs"]
mod shared;

use protocol_shielded_pool::poseidon2_production_transport::{
    decode_poseidon2_production_smza_inline_args_exact, encode_poseidon2_production_smza_envelope,
    encode_poseidon2_production_smza_inline_args, encode_poseidon2_production_smza_native_leaf,
    Poseidon2ProductionExpectedContext,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use transaction_circuit::{
    smallwood_poseidon2_v8_frontend::{
        build_smallwood_poseidon2_v8_smza_candidate_verifier_trace_v1,
        compile_and_prove_smallwood_poseidon2_v8_smza_candidate_v1,
        project_smallwood_poseidon2_v8_smza_candidate_bytes_v1,
        report_smallwood_poseidon2_v8_smza_candidate_v1, verify_smallwood_poseidon2_v8_candidate,
        verify_smallwood_poseidon2_v8_smza_candidate_v1, SmallwoodPoseidon2V8VerifierInput,
    },
    smallwood_poseidon2_v8_semantics::{
        compile_smallwood_poseidon2_v8_relation, SmallwoodPoseidon2V8ConstraintAdapter,
    },
    smallwood_poseidon2_v8_zk_refinement::validate_accepted_smallwood_poseidon2_v8_smza_local_audit_v1,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const NETWORK_ID: u32 = 0x4847_4d38;
const SCHEMA: &str = "hegemon-smallwood-poseidon2-v8-smza-retained-artifact-v1";
const FILE_CAP: u64 = 2 * 1024 * 1024;

fn ensure(condition: bool, message: &str) -> Result<()> {
    if !condition {
        return Err(std::io::Error::other(message).into());
    }
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha512::digest(bytes))
}
fn words(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|v| v.to_le_bytes()).collect()
}
fn descriptor(bytes: &[u8]) -> Value {
    json!({"bytes": bytes.len(), "sha512": digest(bytes)})
}
fn file_identity(path: &Path) -> Result<Value> {
    let mut file = File::open(path)?;
    let mut hasher = Sha512::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        hasher.update(&buffer[..n]);
    }
    Ok(json!({"bytes": total, "sha512": hex::encode(hasher.finalize())}))
}
fn generator_identity() -> Result<Value> {
    Ok(json!({
        "source_path": "circuits/transaction/examples/smallwood_poseidon2_v8_smza_artifact.rs",
        "source": file_identity(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/smallwood_poseidon2_v8_smza_artifact.rs"))?,
        "executable": file_identity(&env::current_exe()?)?,
        "scope": "informational_unattested_generation_metadata",
    }))
}
fn read(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= FILE_CAP,
        "artifact must be a bounded regular file",
    )?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(FILE_CAP + 1)
        .read_to_end(&mut bytes)?;
    ensure(bytes.len() as u64 <= FILE_CAP, "artifact exceeded read cap")?;
    Ok(bytes)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure(
        bytes.len() as u64 <= FILE_CAP,
        "artifact exceeded write cap",
    )?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    ensure(read(path)? == bytes, "written artifact changed on readback")
}
fn output_path(path: &Path) -> Result<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    ensure(
        path.starts_with(root.join(".agent/artifacts/smallwood-poseidon2-v8-smza")),
        "SMZA output must have its own .agent/artifacts/smallwood-poseidon2-v8-smza path",
    )?;
    for ancestor in path.ancestors() {
        ensure(
            !ancestor
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
            "parent traversal forbidden",
        )?;
        if let Ok(metadata) = fs::symlink_metadata(ancestor) {
            ensure(
                !metadata.file_type().is_symlink(),
                "symlink artifact path forbidden",
            )?;
        }
    }
    Ok(path)
}
fn project() -> Result<Value> {
    // Construct, decrypt and exact-decode both new action-11 carriers before any prover work.
    let coinbase_files = shared::shared_coinbase_fixture_files()?;
    let coinbase_descriptors = coinbase_files
        .iter()
        .map(|(name, bytes)| (*name, descriptor(bytes)))
        .collect::<BTreeMap<_, _>>();
    let (statement, witness, ciphertexts, fixture) = shared::shared_positive_fixture()?;
    let statement_bytes = statement.to_public_bytes();
    let witness_bytes = witness.to_witness_bytes();
    let ciphertext_bytes = ciphertexts.to_inline_ciphertext_bytes();
    let mut authorization = [0u64; 7];
    authorization[..4].copy_from_slice(&witness.inputs[0].note.authorization_key);
    authorization[4..].copy_from_slice(&witness.inputs[0].note.randomness[..3]);
    let fixture_known_answer = json!({
        "public_test_seed_only": true,
        "root_secret_hex": "51".repeat(32),
        "address_index": 9,
        "ciphertext_version": 5,
        "spend_key_words": witness.inputs[0].spend_key,
        "spend_key_word_count": witness.inputs[0].spend_key.len(),
        "authorization_words": authorization,
        "authorization_word_count": authorization.len(),
        "authorization_prefix_words": witness.inputs[0].note.authorization_key.len(),
        "authorization_extension_words": 3,
        "statement": descriptor(&statement_bytes),
        "typed_witness": descriptor(&witness_bytes),
        "inline_ciphertexts": descriptor(&ciphertext_bytes),
        "output_ciphertexts": ciphertexts.ciphertexts.iter()
            .map(|ciphertext| ciphertext.as_ref().map(|bytes| descriptor(bytes)))
            .collect::<Vec<_>>(),
    });
    let lowered = compile_smallwood_poseidon2_v8_relation(&statement, &witness)?;
    lowered
        .adapter
        .verify_packed_witness(&lowered.witness_values)?;
    let inner = project_smallwood_poseidon2_v8_smza_candidate_bytes_v1(&lowered.adapter)?;
    ensure(inner == 164_113, "SMZA source projection drift")?;
    let program = shared::shared_relation_program()?;
    ensure(
        program.len() == 843_715,
        "repaired relation program length drift",
    )?;
    ensure(
        digest(&program) == "580ee045ad26fe3f385185717107b7d669ef024a710f0525530d7c600b3dcecdc96963a01f327166dea78e9b93edb2097efb62adb101c6ce0518f6e7169848e6",
        "repaired relation program digest drift",
    )?;
    Ok(json!({
        "schema": "hegemon-smallwood-poseidon2-v8-smza-projection-v1",
        "fresh_coinbase_carriers": coinbase_descriptors,
        "fixture_known_answer": fixture_known_answer,
        "identity": {"inner_magic": "SMZA", "native_leaf_magic": "HGV8TX03", "rpc_envelope_magic": "SWP8LC03", "network_id": NETWORK_ID, "profile_id": 9, "domain_set": 5, "relation_program_profile_lineage": 6, "relation_digest_hex": hex::encode(SmallwoodPoseidon2V8VerifierInput::from_relation(NETWORK_ID, &lowered.adapter).relation_digest), "relation_program": descriptor(&program)},
        "projected_bytes": {"inner_proof": inner, "inline_args": inner + 5434, "rpc_envelope": inner + 5430, "pending_action": inner + 5659},
        "fixture": fixture,
        "relation_mutations": shared::shared_relation_mutations(&statement, &lowered.adapter, &lowered.witness_values)?,
        "production_eligible": false,
    }))
}

fn mutations(
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof: &[u8],
    args: &[u8],
) -> Result<Value> {
    let mut results = BTreeMap::new();
    let mut changed = proof.to_vec();
    *changed.last_mut().ok_or("empty proof")? ^= 1;
    results.insert(
        "proof_last_byte",
        verify_smallwood_poseidon2_v8_smza_candidate_v1(input, &changed).is_err(),
    );
    results.insert(
        "proof_truncated",
        verify_smallwood_poseidon2_v8_smza_candidate_v1(input, &proof[..proof.len() - 1]).is_err(),
    );
    changed = proof.to_vec();
    changed.extend_from_slice(&[0]);
    results.insert(
        "proof_trailing_byte",
        verify_smallwood_poseidon2_v8_smza_candidate_v1(input, &changed).is_err(),
    );
    results.insert(
        "q20_verifier_cross_profile",
        verify_smallwood_poseidon2_v8_candidate(input, proof).is_err(),
    );
    let mut context = input.clone();
    context.network_id ^= 1;
    results.insert(
        "network",
        verify_smallwood_poseidon2_v8_smza_candidate_v1(&context, proof).is_err(),
    );
    context = input.clone();
    context.relation_digest[0] ^= 1;
    results.insert(
        "relation_digest",
        verify_smallwood_poseidon2_v8_smza_candidate_v1(&context, proof).is_err(),
    );
    context = input.clone();
    context.public_values[44] ^= 1;
    results.insert(
        "public_fee",
        verify_smallwood_poseidon2_v8_smza_candidate_v1(&context, proof).is_err(),
    );
    context = input.clone();
    context.relation_balance_binding[0] ^= 1;
    results.insert(
        "kernel_binding",
        verify_smallwood_poseidon2_v8_smza_candidate_v1(&context, proof).is_err(),
    );
    let expected = Poseidon2ProductionExpectedContext::new(NETWORK_ID, input.relation_digest)?;
    changed = args.to_vec();
    changed.push(0);
    results.insert(
        "inline_trailing_byte",
        decode_poseidon2_production_smza_inline_args_exact(expected, &changed).is_err(),
    );
    results.insert(
        "inline_truncated",
        decode_poseidon2_production_smza_inline_args_exact(expected, &args[..args.len() - 1])
            .is_err(),
    );
    ensure(results.values().all(|v| *v), "SMZA mutation accepted")?;
    Ok(serde_json::to_value(results)?)
}

fn proof_evidence(input: &SmallwoodPoseidon2V8VerifierInput, proof: &[u8]) -> Result<Value> {
    let (statement, _, _, _) = shared::shared_positive_fixture()?;
    let adapter = SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement)?;
    let preamble = input.smza_candidate_transcript_preamble_v1()?;
    let trace = build_smallwood_poseidon2_v8_smza_candidate_verifier_trace_v1(input, proof)?;
    ensure(
        trace.accept && trace.proof.salt != [0; 32] && trace.pcs_trace.root_digest != [0; 64],
        "invalid accepted-proof randomness binding",
    )?;
    let local_audit = validate_accepted_smallwood_poseidon2_v8_smza_local_audit_v1(
        &adapter,
        preamble.as_bytes(),
        proof,
    )?;
    Ok(
        json!({"wire_salt_hex": hex::encode(trace.proof.salt), "decs_transcript_root_hex": hex::encode(trace.pcs_trace.root_digest), "local_audit": local_audit}),
    )
}

fn canonical_files(
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let (statement, _, ciphertexts, _) = shared::shared_positive_fixture()?;
    ensure(
        words(&input.public_values) == statement.to_public_bytes(),
        "proof uses different fixture statement",
    )?;
    verify_smallwood_poseidon2_v8_smza_candidate_v1(input, proof)?;
    let expected = Poseidon2ProductionExpectedContext::new(NETWORK_ID, input.relation_digest)?;
    let leaf = encode_poseidon2_production_smza_native_leaf(
        expected,
        &input.public_values,
        &input.relation_balance_binding,
        [
            ciphertexts.ciphertexts[0].as_ref(),
            ciphertexts.ciphertexts[1].as_ref(),
        ],
        proof,
    )?;
    let envelope = encode_poseidon2_production_smza_envelope(expected, &leaf)?;
    let args = encode_poseidon2_production_smza_inline_args(expected, &envelope)?;
    let decoded = decode_poseidon2_production_smza_inline_args_exact(expected, &args)?;
    ensure(
        decoded.envelope().native_leaf() == leaf
            && decoded.envelope().decoded_native_leaf().proof() == proof,
        "transport changed proof bytes",
    )?;
    ensure(
        proof.len() <= 164_113
            && args.len() == proof.len() + 5434
            && envelope.len() == proof.len() + 5430,
        "SMZA actual carrier size drift",
    )?;
    Ok(BTreeMap::from([
        ("proof.bin".into(), proof.to_vec()),
        (
            "context.bin".into(),
            input
                .smza_candidate_transcript_preamble_v1()?
                .as_bytes()
                .to_vec(),
        ),
        (
            "kernel-binding.bin".into(),
            words(&input.relation_balance_binding),
        ),
        ("public-inputs.bin".into(), words(&input.public_values)),
        ("native-leaf.bin".into(), leaf),
        ("rpc-envelope.bin".into(), envelope),
        ("inline-args.bin".into(), args),
    ]))
}

fn verify(directory: &Path) -> Result<Value> {
    let directory = output_path(directory)?;
    let manifest: Value = serde_json::from_slice(&read(&directory.join("manifest.json"))?)?;
    let projection = project()?;
    ensure(
        manifest["schema"] == SCHEMA
            && manifest["production_eligible"] == false
            && manifest["projection"] == projection
            && manifest["identity"] == projection["identity"]
            && manifest["fixture"] == projection["fixture"],
        "SMZA manifest identity or source projection mismatch",
    )?;
    ensure(
        manifest["proof_source_inventory"] == shared::shared_current_source_inventory()?,
        "current v5 source inventory mismatch",
    )?;
    ensure(
        read(&directory.join("relation-program.bin"))? == shared::shared_relation_program()?,
        "relation program mismatch",
    )?;
    for (name, bytes) in shared::shared_coinbase_fixture_files()? {
        ensure(
            read(&directory.join(name))? == bytes
                && manifest["fixture_files"][name] == descriptor(&bytes),
            "coinbase fixture mismatch",
        )?;
    }
    let (statement, witness, _, _) = shared::shared_positive_fixture()?;
    let lowered = compile_smallwood_poseidon2_v8_relation(&statement, &witness)?;
    let input = SmallwoodPoseidon2V8VerifierInput::from_relation(NETWORK_ID, &lowered.adapter);
    let mut receipts = BTreeMap::new();
    let mut hashes = Vec::new();
    let mut randomness = Vec::new();
    for role in ["primary", "independent"] {
        let proof = read(&directory.join(role).join("proof.bin"))?;
        let files = canonical_files(&input, &proof)?;
        let expected_files: BTreeMap<_, _> = files
            .iter()
            .map(|(k, v)| (k.clone(), descriptor(v)))
            .collect();
        ensure(
            manifest["artifacts"][role]["files"] == serde_json::to_value(expected_files)?,
            "artifact file hash inventory mismatch",
        )?;
        for (name, bytes) in &files {
            ensure(
                read(&directory.join(role).join(name))? == *bytes,
                "readback differs from source canonical carrier",
            )?;
        }
        let mutation_receipt = mutations(&input, &proof, &files["inline-args.bin"])?;
        ensure(
            manifest["artifacts"][role]["mutations"] == mutation_receipt,
            "mutation report mismatch",
        )?;
        let evidence = proof_evidence(&input, &proof)?;
        ensure(
            manifest["artifacts"][role]["proof_evidence"] == evidence,
            "local proof audit mismatch",
        )?;
        ensure(
            manifest["artifacts"][role]["opening_surface"]
                == serde_json::to_value(report_smallwood_poseidon2_v8_smza_candidate_v1(
                    &input, &proof,
                )?)?,
            "opening surface report mismatch",
        )?;
        randomness.push((
            evidence["wire_salt_hex"].clone(),
            evidence["decs_transcript_root_hex"].clone(),
        ));
        hashes.push(digest(&proof));
        receipts.insert(role, json!({"proof_sha512": digest(&proof), "proof_bytes": proof.len(), "source_owned_verification": true, "unchanged_carriers": true, "mutations": mutation_receipt}));
    }
    ensure(hashes[0] != hashes[1], "independent proofs are identical")?;
    ensure(
        randomness[0].0 != randomness[1].0 && randomness[0].1 != randomness[1].1,
        "independent proof salts or roots collide",
    )?;
    ensure(
        manifest["proof_source_inventory"] == shared::shared_current_source_inventory()?,
        "source changed during verification",
    )?;
    Ok(
        json!({"schema": "hegemon-smallwood-poseidon2-v8-smza-readback-v1", "artifacts": receipts, "distinct_proofs": true, "distinct_salts_and_roots": true, "production_eligible": false}),
    )
}

fn generate(directory: &Path) -> Result<Value> {
    let directory = output_path(directory)?;
    ensure(
        !directory.exists(),
        "output already exists; generation is create-only",
    )?;
    let inventory = shared::shared_current_source_inventory()?;
    let generator = generator_identity()?;
    let projection = project()?;
    fs::create_dir_all(directory.parent().ok_or("output has no parent")?)?;
    fs::create_dir(&directory)?;
    write_new(
        &directory.join("relation-program.bin"),
        &shared::shared_relation_program()?,
    )?;
    let mut fixture_files = BTreeMap::new();
    for (name, bytes) in shared::shared_coinbase_fixture_files()? {
        write_new(&directory.join(name), &bytes)?;
        fixture_files.insert(name, descriptor(&bytes));
    }
    let mut artifacts = BTreeMap::new();
    for role in ["primary", "independent"] {
        let start = Instant::now();
        let (statement, witness, _, _) = shared::shared_positive_fixture()?;
        // Each invocation obtains fresh OS entropy inside the source prover.
        let candidate = compile_and_prove_smallwood_poseidon2_v8_smza_candidate_v1(
            &statement, &witness, NETWORK_ID,
        )?;
        let files = canonical_files(candidate.verifier_input(), candidate.proof_bytes())?;
        let mutation_receipt = mutations(
            candidate.verifier_input(),
            candidate.proof_bytes(),
            &files["inline-args.bin"],
        )?;
        let opening_surface = report_smallwood_poseidon2_v8_smza_candidate_v1(
            candidate.verifier_input(),
            candidate.proof_bytes(),
        )?;
        let evidence = proof_evidence(candidate.verifier_input(), candidate.proof_bytes())?;
        fs::create_dir(directory.join(role))?;
        let mut file_receipts = BTreeMap::new();
        for (name, bytes) in files {
            write_new(&directory.join(role).join(&name), &bytes)?;
            file_receipts.insert(name, descriptor(&bytes));
        }
        artifacts.insert(role, json!({"files": file_receipts, "mutations": mutation_receipt, "opening_surface": opening_surface, "proof_evidence": evidence, "elapsed_millis": start.elapsed().as_millis()}));
        eprintln!("SMZA {role} generated, source verified, and read back");
    }
    ensure(
        inventory == shared::shared_current_source_inventory()?,
        "source changed during generation",
    )?;
    ensure(
        generator == generator_identity()?,
        "generator changed during generation",
    )?;
    let manifest = json!({"schema": SCHEMA, "projection": projection, "identity": projection["identity"], "fixture": projection["fixture"], "proof_source_inventory": inventory, "generator": generator, "generation_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(), "entropy_scope": "two_fresh_os_entropy_prover_invocations_same_process", "fixture_files": fixture_files, "artifacts": artifacts, "production_eligible": false});
    write_new(
        &directory.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    let receipt = verify(&directory)?;
    write_new(
        &directory.join("readback.json"),
        &serde_json::to_vec_pretty(&receipt)?,
    )?;
    Ok(receipt)
}
fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let result = match args.as_slice() {
        [command] if command == "project" => project()?,
        [command, directory] if command == "generate" => generate(Path::new(directory))?,
        [command, directory] if command == "verify" => verify(Path::new(directory))?,
        _ => return Err("usage: smallwood_poseidon2_v8_smza_artifact project | generate NEW_DIRECTORY | verify DIRECTORY".into()),
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
