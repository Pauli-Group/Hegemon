//! Create-only, source-bound RP05 SMZA proof pair for native lifecycle tests.
//! This development artifact never authorizes production.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "smallwood_poseidon2_v8_artifact.rs"]
mod shared;

use protocol_shielded_pool::poseidon2_pending_action_artifact::SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES;
use protocol_shielded_pool::poseidon2_production_transport::{
    decode_poseidon2_production_smza_inline_args_exact, encode_poseidon2_production_smza_envelope,
    encode_poseidon2_production_smza_inline_args, encode_poseidon2_production_smza_native_leaf,
    Poseidon2ProductionExpectedContext, POSEIDON2_PRODUCTION_SMZA_INNER_PROOF_MAGIC,
    POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES, POSEIDON2_PRODUCTION_SMZA_MAX_ENVELOPE_BYTES,
    POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES, POSEIDON2_PRODUCTION_SMZA_NATIVE_LEAF_MAGIC,
    POSEIDON2_PRODUCTION_SMZA_TRANSPORT_MAGIC,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use transaction_circuit::{
    smallwood_poseidon2_v8_frontend::{
        build_smallwood_poseidon2_v8_smza_development_artifact_verifier_trace_v1,
        compile_and_prove_smallwood_poseidon2_v8_smza_development_artifact_v1,
        project_smallwood_poseidon2_v8_smza_candidate_bytes_v1,
        verify_smallwood_poseidon2_v8_smza_development_artifact_v1,
        SmallwoodPoseidon2V8VerifierInput, SMALLWOOD_POSEIDON2_V8_SMZA_DOMAIN_SET,
        SMALLWOOD_POSEIDON2_V8_SMZA_INLINE_ACTION_BYTES, SMALLWOOD_POSEIDON2_V8_SMZA_PROFILE_ID,
    },
    smallwood_poseidon2_v8_program::{
        smallwood_poseidon2_v8_program_digest_from_bytes,
        SMALLWOOD_POSEIDON2_V8_PROFILE_ID as RP05_PROFILE_LINEAGE,
        SMALLWOOD_POSEIDON2_V8_PROGRAM_IDENTITY_REGENERATION_REQUIRED,
    },
    smallwood_poseidon2_v8_semantics::{
        compile_smallwood_poseidon2_v8_relation_for_development_artifact,
        SmallwoodPoseidon2V8ConstraintAdapter,
    },
    smallwood_poseidon2_v8_zk_refinement::validate_accepted_smallwood_poseidon2_v8_smza_local_audit_v1,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SCHEMA: &str = "hegemon-smallwood-poseidon2-v8-smza-retained-artifact-v1";
const NETWORK_ID: u32 = protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID;
const INNER_CAP: usize = POSEIDON2_PRODUCTION_SMZA_MAX_PROOF_BYTES;
const INLINE_CAP: usize = POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES;
const RPC_CAP: usize = POSEIDON2_PRODUCTION_SMZA_MAX_ENVELOPE_BYTES;
const PENDING_ACTION_OVERHEAD: usize = SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES;
const PENDING_CAP: usize = INLINE_CAP + PENDING_ACTION_OVERHEAD;
const FILE_CAP: u64 = 2 * 1024 * 1024;
const PROGRAM_FIXTURE: &str =
    "testdata/formal_core_vectors/poseidon2_v8_relation_program_hgv8rp05.bin";
const QUALIFICATION_SCOPE: &str = "source_bound_development_only";

fn ensure(ok: bool, message: &str) -> Result<()> {
    if !ok {
        return Err(std::io::Error::other(message).into());
    }
    Ok(())
}

fn sha512(bytes: &[u8]) -> String {
    hex::encode(Sha512::digest(bytes))
}

fn ascii(bytes: &[u8]) -> Result<String> {
    Ok(std::str::from_utf8(bytes)?.to_owned())
}

fn descriptor(bytes: &[u8]) -> Value {
    json!({"bytes": bytes.len(), "sha512": sha512(bytes)})
}

fn words(values: &[u64]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn repository_root() -> Result<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?)
}

fn artifact_path(path: &Path) -> Result<PathBuf> {
    let root = repository_root()?.join(".agent/artifacts/smallwood-poseidon2-v8-smza");
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    ensure(
        path.starts_with(&root),
        "artifact path must be under .agent/artifacts/smallwood-poseidon2-v8-smza",
    )?;
    for ancestor in path.ancestors() {
        ensure(
            !ancestor
                .components()
                .any(|component| matches!(component, Component::ParentDir)),
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

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
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
    ensure(read_bounded(path)? == bytes, "artifact changed on readback")
}

fn file_identity(path: &Path) -> Result<Value> {
    let metadata = fs::symlink_metadata(path)?;
    ensure(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "identity input must be a regular file",
    )?;
    let mut file = File::open(path)?;
    let mut hasher = Sha512::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or("identity file size overflow")?;
        ensure(
            total <= 1024 * 1024 * 1024,
            "identity input exceeds one GiB",
        )?;
        hasher.update(&buffer[..count]);
    }
    Ok(json!({"bytes": total, "sha512": hex::encode(hasher.finalize())}))
}

fn generator_identity() -> Result<Value> {
    let source = repository_root()?
        .join("circuits/transaction/examples/rp05_smza_qualification_artifact.rs");
    Ok(json!({
        "source_path": "circuits/transaction/examples/rp05_smza_qualification_artifact.rs",
        "source": file_identity(&source)?,
        "executable": file_identity(&env::current_exe()?)?,
        "feature": "rp05-dev-artifacts",
        "scope": "informational_unattested_generation_metadata"
    }))
}

fn source_identity() -> Result<(Vec<u8>, Value, Value)> {
    let program = read_bounded(&repository_root()?.join(PROGRAM_FIXTURE))?;
    ensure(
        program.starts_with(b"HGV8RP05"),
        "checked-in relation fixture is not HGV8RP05",
    )?;
    let digest = smallwood_poseidon2_v8_program_digest_from_bytes(&program);
    let sha = Sha512::digest(&program);
    ensure(
        digest.as_slice() == &sha[..48],
        "HGV8RP05 digest is not the SHA-512 prefix",
    )?;
    let identity = json!({
        "inner_magic": ascii(&POSEIDON2_PRODUCTION_SMZA_INNER_PROOF_MAGIC)?,
        "native_leaf_magic": ascii(&POSEIDON2_PRODUCTION_SMZA_NATIVE_LEAF_MAGIC)?,
        "rpc_envelope_magic": ascii(&POSEIDON2_PRODUCTION_SMZA_TRANSPORT_MAGIC)?,
        "network_id": NETWORK_ID,
        "profile_id": SMALLWOOD_POSEIDON2_V8_SMZA_PROFILE_ID,
        "domain_set": SMALLWOOD_POSEIDON2_V8_SMZA_DOMAIN_SET,
        "relation_program_profile_lineage": RP05_PROFILE_LINEAGE,
        "relation_digest_hex": hex::encode(digest),
        "relation_program": descriptor(&program)
    });
    let source_relation_fixture = json!({
        "path": PROGRAM_FIXTURE,
        "program": descriptor(&program),
        "identity_regeneration_required": SMALLWOOD_POSEIDON2_V8_PROGRAM_IDENTITY_REGENERATION_REQUIRED,
        "production_authorized": false
    });
    Ok((program.clone(), identity, source_relation_fixture))
}

fn fixture_files() -> Result<(BTreeMap<String, Vec<u8>>, Value)> {
    let mut files = BTreeMap::new();
    let mut pins = BTreeMap::new();
    for (name, bytes) in shared::shared_coinbase_fixture_files()? {
        files.insert(name.to_owned(), bytes.clone());
        pins.insert(name.to_owned(), descriptor(&bytes));
    }
    Ok((files, Value::Object(pins.into_iter().collect())))
}

fn canonical_files(
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof: &[u8],
) -> Result<BTreeMap<String, Vec<u8>>> {
    ensure(
        SMALLWOOD_POSEIDON2_V8_SMZA_INLINE_ACTION_BYTES == INLINE_CAP,
        "source inline-action cap drift",
    )?;
    let (statement, _, ciphertexts, _) = shared::shared_positive_fixture()?;
    ensure(
        words(&input.public_values) == statement.to_public_bytes(),
        "proof statement differs from repaired positive fixture",
    )?;
    verify_smallwood_poseidon2_v8_smza_development_artifact_v1(input, proof)?;
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
        decoded.envelope().raw() == envelope.as_slice(),
        "envelope bytes changed in exact decode",
    )?;
    ensure(
        decoded.envelope().decoded_native_leaf().raw() == leaf.as_slice(),
        "native leaf bytes changed in exact decode",
    )?;
    ensure(
        decoded.envelope().decoded_native_leaf().proof() == proof,
        "proof bytes changed across carriers",
    )?;
    let pending = args
        .len()
        .checked_add(PENDING_ACTION_OVERHEAD)
        .ok_or("pending-action size overflow")?;
    ensure(
        proof.len() <= INNER_CAP && args.len() <= INLINE_CAP && pending <= PENDING_CAP,
        "measured proof or carrier exceeds RP05 cap",
    )?;
    ensure(
        args.len() == proof.len() + 5_434 && envelope.len() == proof.len() + 5_430,
        "SMZA carrier size drift",
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

fn relation_for_fixture() -> Result<(
    SmallwoodPoseidon2V8VerifierInput,
    SmallwoodPoseidon2V8ConstraintAdapter,
)> {
    let (statement, witness, _, _) = shared::shared_positive_fixture()?;
    let lowered =
        compile_smallwood_poseidon2_v8_relation_for_development_artifact(&statement, &witness)?;
    let input = SmallwoodPoseidon2V8VerifierInput::from_relation(NETWORK_ID, &lowered.adapter);
    Ok((input, lowered.adapter))
}

fn proof_evidence(
    input: &SmallwoodPoseidon2V8VerifierInput,
    relation: &SmallwoodPoseidon2V8ConstraintAdapter,
    proof: &[u8],
) -> Result<Value> {
    let expected = SmallwoodPoseidon2V8VerifierInput::from_relation(NETWORK_ID, relation);
    ensure(
        input.relation_digest == expected.relation_digest
            && input.public_values == expected.public_values
            && input.relation_balance_binding == expected.relation_balance_binding,
        "proof evidence relation differs from the current RP05 source adapter",
    )?;

    // Keep all evidence within the explicitly feature-gated development
    // verifier. The normal trace constructor retains its identity gate.
    verify_smallwood_poseidon2_v8_smza_development_artifact_v1(input, proof)?;
    let preamble = input.smza_candidate_transcript_preamble_v1()?;
    let trace =
        build_smallwood_poseidon2_v8_smza_development_artifact_verifier_trace_v1(input, proof)?;
    ensure(
        trace.accept && trace.proof.salt != [0; 32] && trace.pcs_trace.root_digest != [0; 64],
        "RP05 proof has invalid source-verifier randomness binding",
    )?;
    let local_audit = validate_accepted_smallwood_poseidon2_v8_smza_local_audit_v1(
        relation,
        preamble.as_bytes(),
        proof,
    )?;
    Ok(json!({
        "wire_salt_hex": hex::encode(trace.proof.salt),
        "decs_transcript_root_hex": hex::encode(trace.pcs_trace.root_digest),
        "local_audit": local_audit
    }))
}

fn source_projection() -> Result<Value> {
    let (_, identity, _) = source_identity()?;
    let coinbase_files = shared::shared_coinbase_fixture_files()?;
    let coinbase_descriptors = coinbase_files
        .iter()
        .map(|(name, bytes)| (*name, descriptor(bytes)))
        .collect::<BTreeMap<_, _>>();
    let (statement, witness, ciphertexts, fixture) = shared::shared_positive_fixture()?;
    let lowered =
        compile_smallwood_poseidon2_v8_relation_for_development_artifact(&statement, &witness)?;
    lowered
        .adapter
        .verify_packed_witness(&lowered.witness_values)?;
    let inner = project_smallwood_poseidon2_v8_smza_candidate_bytes_v1(&lowered.adapter)?;
    let input = SmallwoodPoseidon2V8VerifierInput::from_relation(NETWORK_ID, &lowered.adapter);
    ensure(
        hex::encode(input.relation_digest) == identity["relation_digest_hex"],
        "RP05 source projection identity differs from the development adapter",
    )?;

    // Project the real carriers through the transport encoder with an
    // unmistakably synthetic proof payload. Only their exact lengths are
    // retained; no proof or verifier result is claimed by this projection.
    let mut projected_proof = vec![0; inner];
    ensure(
        projected_proof.len() >= POSEIDON2_PRODUCTION_SMZA_INNER_PROOF_MAGIC.len(),
        "projected proof is shorter than its wire magic",
    )?;
    projected_proof[..POSEIDON2_PRODUCTION_SMZA_INNER_PROOF_MAGIC.len()]
        .copy_from_slice(&POSEIDON2_PRODUCTION_SMZA_INNER_PROOF_MAGIC);
    let expected = Poseidon2ProductionExpectedContext::new(NETWORK_ID, input.relation_digest)?;
    let leaf = encode_poseidon2_production_smza_native_leaf(
        expected,
        &input.public_values,
        &input.relation_balance_binding,
        [
            ciphertexts.ciphertexts[0].as_ref(),
            ciphertexts.ciphertexts[1].as_ref(),
        ],
        &projected_proof,
    )?;
    let envelope = encode_poseidon2_production_smza_envelope(expected, &leaf)?;
    let inline_args = encode_poseidon2_production_smza_inline_args(expected, &envelope)?;
    let pending_action = inline_args
        .len()
        .checked_add(PENDING_ACTION_OVERHEAD)
        .ok_or("pending-action projection overflow")?;
    ensure(
        SMALLWOOD_POSEIDON2_V8_SMZA_INLINE_ACTION_BYTES == INLINE_CAP
            && inner <= INNER_CAP
            && inline_args.len() <= INLINE_CAP
            && envelope.len() <= RPC_CAP
            && pending_action <= PENDING_CAP,
        "RP05 source projection exceeds the exact SMZA carrier caps",
    )?;

    Ok(json!({
        "schema": "hegemon-smallwood-poseidon2-v8-smza-projection-v1",
        "fresh_coinbase_carriers": coinbase_descriptors,
        "identity": identity,
        "projected_bytes": {
            "inner_proof": inner,
            "rpc_envelope": envelope.len(),
            "inline_args": inline_args.len(),
            "pending_action": pending_action
        },
        "fixture": fixture,
        "relation_mutations": shared::shared_relation_mutations(
            &statement,
            &lowered.adapter,
            &lowered.witness_values
        )?,
        "qualification_scope": QUALIFICATION_SCOPE,
        "production_eligible": false,
        "production_authorized": false
    }))
}

fn verify_contents(directory: &Path, require_readback: bool) -> Result<Value> {
    let directory = artifact_path(directory)?;
    let manifest: Value = serde_json::from_slice(&read_bounded(&directory.join("manifest.json"))?)?;
    let inventory = shared::shared_current_source_inventory()?;
    let generator = generator_identity()?;
    let (program, identity, source_relation_fixture) = source_identity()?;
    let projection = source_projection()?;
    ensure(
        manifest["schema"] == SCHEMA
            && manifest["production_eligible"] == false
            && manifest["production_authorized"] == false,
        "unsupported or authorizing retained manifest",
    )?;
    ensure(
        manifest["features"] == json!(["rp05-dev-artifacts"]),
        "manifest omitted explicit development feature",
    )?;
    ensure(
        manifest["qualification_scope"] == QUALIFICATION_SCOPE,
        "manifest omitted the source-bound development-only qualification scope",
    )?;
    ensure(
        manifest["proof_source_inventory"] == inventory,
        "current proof source inventory differs",
    )?;
    ensure(
        manifest["generator"] == generator,
        "generator source or executable identity differs",
    )?;
    ensure(
        manifest["identity"] == identity,
        "current HGV8RP05 fixture identity differs",
    )?;
    ensure(
        manifest["source_relation_fixture"] == source_relation_fixture,
        "source relation fixture metadata differs",
    )?;
    ensure(
        manifest["projection"] == projection
            && projection["qualification_scope"] == QUALIFICATION_SCOPE
            && projection["production_eligible"] == false
            && projection["production_authorized"] == false,
        "source-derived RP05 projection or its authority boundary differs",
    )?;
    ensure(
        manifest["fixture"] == projection["fixture"],
        "manifest fixture differs from the source projection",
    )?;
    ensure(
        read_bounded(&directory.join("relation-program.bin"))? == program,
        "HGV8RP05 relation fixture bytes differ",
    )?;
    let (fixture_bytes, fixture_pins) = fixture_files()?;
    ensure(
        manifest["fixture_files"] == fixture_pins,
        "coinbase fixture pin mismatch",
    )?;
    for (name, bytes) in fixture_bytes {
        ensure(
            read_bounded(&directory.join(name))? == bytes,
            "coinbase fixture readback differs",
        )?;
    }
    let (input, relation) = relation_for_fixture()?;
    ensure(
        hex::encode(input.relation_digest) == identity["relation_digest_hex"],
        "proof relation digest differs from HGV8RP05 source fixture",
    )?;
    let mut readback_artifacts = BTreeMap::new();
    let mut randomness = Vec::new();
    for role in ["primary", "independent"] {
        let proof = read_bounded(&directory.join(role).join("proof.bin"))?;
        let files = canonical_files(&input, &proof)?;
        let evidence = proof_evidence(&input, &relation, &proof)?;
        ensure(
            manifest["artifacts"][role]["proof_evidence"] == evidence,
            "nested proof evidence differs from the source verifier and local audit",
        )?;
        ensure(
            manifest["artifacts"][role].get("wire_salt_hex").is_none()
                && manifest["artifacts"][role]
                    .get("decs_transcript_root_hex")
                    .is_none(),
            "proof randomness must be represented only in nested proof_evidence",
        )?;
        randomness.push((
            evidence["wire_salt_hex"]
                .as_str()
                .ok_or("proof evidence omitted the wire salt")?
                .to_owned(),
            evidence["decs_transcript_root_hex"]
                .as_str()
                .ok_or("proof evidence omitted the DECS transcript root")?
                .to_owned(),
        ));
        let pins: BTreeMap<_, _> = files
            .iter()
            .map(|(name, bytes)| (name.clone(), descriptor(bytes)))
            .collect();
        ensure(
            manifest["artifacts"][role]["files"] == serde_json::to_value(&pins)?,
            "retained carrier inventory mismatch",
        )?;
        let inline_len = files["inline-args.bin"].len();
        let pending_len = inline_len
            .checked_add(PENDING_ACTION_OVERHEAD)
            .ok_or("pending-action size overflow")?;
        ensure(
            manifest["artifacts"][role]["proof_bytes"].as_u64() == Some(proof.len() as u64)
                && manifest["artifacts"][role]["inline_action_bytes"].as_u64()
                    == Some(inline_len as u64)
                && manifest["artifacts"][role]["pending_action_max_projection_bytes"].as_u64()
                    == Some(pending_len as u64),
            "manifest carrier measurements differ from exact retained bytes",
        )?;
        ensure(
            proof.len() <= INNER_CAP && inline_len <= INLINE_CAP && pending_len <= PENDING_CAP,
            "retained artifact exceeds RP05 carrier caps",
        )?;
        ensure(
            manifest["artifacts"][role]["projected_proof_cap_bytes"].as_u64()
                == projection["projected_bytes"]["inner_proof"].as_u64()
                && manifest["artifacts"][role]["independent_entropy_invocation"] == true,
            "manifest source-projected proof cap or independent invocation marker differs",
        )?;
        for (name, bytes) in &files {
            ensure(
                read_bounded(&directory.join(role).join(name))? == *bytes,
                "carrier readback differs from canonical construction",
            )?;
        }
        readback_artifacts.insert(
            role,
            json!({
                "source_owned_verification": true,
                "unchanged_carriers": true,
                "proof_sha512": sha512(&proof)
            }),
        );
    }
    ensure(
        readback_artifacts["primary"]["proof_sha512"]
            != readback_artifacts["independent"]["proof_sha512"],
        "independent proof bytes are identical",
    )?;
    ensure(
        randomness[0].0 != randomness[1].0 && randomness[0].1 != randomness[1].1,
        "independent proof salts or transcript roots collide",
    )?;
    ensure(
        shared::shared_current_source_inventory()? == inventory
            && generator_identity()? == generator,
        "source or generator changed during verification",
    )?;
    let readback = json!({
        "schema": "hegemon-smallwood-poseidon2-v8-smza-readback-v1",
        "artifacts": readback_artifacts,
        "distinct_proofs": true,
        "distinct_salts_and_roots": true,
        "production_eligible": false,
        "production_authorized": false
    });
    if require_readback {
        let expected = serde_json::to_vec_pretty(&readback)?;
        ensure(
            read_bounded(&directory.join("readback.json"))? == expected,
            "retained source readback differs from verifier result",
        )?;
    }
    Ok(readback)
}

fn verify(directory: &Path) -> Result<Value> {
    verify_contents(directory, true)
}

fn generate(directory: &Path) -> Result<Value> {
    let directory = artifact_path(directory)?;
    ensure(
        !directory.exists(),
        "generation is create-only; output directory already exists",
    )?;
    let inventory = shared::shared_current_source_inventory()?;
    let generator = generator_identity()?;
    let (program, identity, source_relation_fixture) = source_identity()?;
    let projection = source_projection()?;
    let fixture = projection["fixture"].clone();
    fs::create_dir_all(directory.parent().ok_or("output directory has no parent")?)?;
    fs::create_dir(&directory)?;
    write_new(&directory.join("relation-program.bin"), &program)?;
    let (coinbase_files, fixture_pins) = fixture_files()?;
    for (name, bytes) in &coinbase_files {
        write_new(&directory.join(name), bytes)?;
    }
    let (statement, witness, _, _) = shared::shared_positive_fixture()?;
    let (_, relation) = relation_for_fixture()?;
    let mut artifacts = BTreeMap::new();
    for role in ["primary", "independent"] {
        let candidate = compile_and_prove_smallwood_poseidon2_v8_smza_development_artifact_v1(
            &statement, &witness, NETWORK_ID,
        )?;
        verify_smallwood_poseidon2_v8_smza_development_artifact_v1(
            candidate.verifier_input(),
            candidate.proof_bytes(),
        )?;
        let files = canonical_files(candidate.verifier_input(), candidate.proof_bytes())?;
        let evidence = proof_evidence(
            candidate.verifier_input(),
            &relation,
            candidate.proof_bytes(),
        )?;
        let inline_len = files["inline-args.bin"].len();
        let pending_len = inline_len
            .checked_add(PENDING_ACTION_OVERHEAD)
            .ok_or("pending-action size overflow")?;
        ensure(
            candidate.measured_action_bytes() == inline_len,
            "prover action measurement differs from exact inline carrier",
        )?;
        ensure(
            candidate.proof_bytes().len() <= INNER_CAP
                && candidate.projected_max_proof_bytes() <= INNER_CAP
                && inline_len <= INLINE_CAP
                && pending_len <= PENDING_CAP,
            "candidate exceeds RP05 carrier caps",
        )?;
        let mut pins = BTreeMap::new();
        fs::create_dir(directory.join(role))?;
        for (name, bytes) in files {
            pins.insert(name.clone(), descriptor(&bytes));
            write_new(&directory.join(role).join(name), &bytes)?;
        }
        artifacts.insert(
            role,
            json!({
                "files": pins,
                "proof_bytes": candidate.proof_bytes().len(),
                "projected_proof_cap_bytes": candidate.projected_max_proof_bytes(),
                "inline_action_bytes": inline_len,
                "pending_action_max_projection_bytes": pending_len,
                "proof_evidence": evidence,
                "independent_entropy_invocation": true
            }),
        );
    }
    ensure(
        inventory == shared::shared_current_source_inventory()?,
        "proof source inventory changed during generation",
    )?;
    ensure(
        generator == generator_identity()?,
        "generator source or executable changed during generation",
    )?;
    let manifest = json!({
        "schema": SCHEMA,
        "features": ["rp05-dev-artifacts"],
        "qualification_scope": QUALIFICATION_SCOPE,
        "projection": projection,
        "identity": identity,
        "source_relation_fixture": source_relation_fixture,
        "fixture": fixture,
        "proof_source_inventory": inventory,
        "generator": generator,
        "generation_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "fixture_files": fixture_pins,
        "artifacts": artifacts,
        "production_eligible": false,
        "production_authorized": false
    });
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    write_new(&directory.join("manifest.json"), &bytes)?;
    let result = verify_contents(&directory, false)?;
    let readback = serde_json::to_vec_pretty(&result)?;
    write_new(&directory.join("readback.json"), &readback)?;
    Ok(result)
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let result =
        match args.as_slice() {
            [command, path] if command == "generate" => generate(Path::new(path))?,
            [command, path] if command == "verify" => verify(Path::new(path))?,
            _ => return Err(
                "usage: rp05_smza_qualification_artifact generate NEW_DIRECTORY | verify DIRECTORY"
                    .into(),
            ),
        };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
