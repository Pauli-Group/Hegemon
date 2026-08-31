//! Retained maximum-shape SmallWood Poseidon2 V8 proof artifact runner.
//!
//! `project` performs the source-compiler, executable-relation mutation, and
//! exact byte-budget gates without invoking the expensive DECS prover.
//! `generate` repeats those gates, proves with the fixed V8 N=2^23/q=20
//! profile, verifies through the source-owned verifier factory, exercises
//! proof and statement mutations, and atomically publishes a read-back-
//! verified artifact.  The private witness is never written to disk.

#![forbid(unsafe_code)]

use codec::{Decode, Encode};
use getrandom::fill as getrandom_fill;
use protocol_shielded_pool::{
    family::FAMILY_SHIELDED_POOL,
    poseidon2_pending_action_artifact::{
        audit_poseidon2_v8_pending_action_artifact_mutations_v1,
        encode_poseidon2_v8_pending_action_artifact,
        verify_poseidon2_v8_pending_action_artifact_exact,
        Poseidon2V8PendingActionArtifactReadback, SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES,
        SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES,
        SMALLWOOD_POSEIDON2_V8_PROJECTED_PENDING_ACTION_BYTES,
    },
    poseidon2_production_transport::{
        decode_poseidon2_production_smz9_envelope_exact,
        decode_poseidon2_production_smz9_inline_args_exact,
        decode_poseidon2_production_smz9_native_leaf_exact,
        encode_poseidon2_production_smz9_envelope, encode_poseidon2_production_smz9_inline_args,
        encode_poseidon2_production_smz9_native_leaf, ensure_poseidon2_production_smz9_stage_bytes,
        Poseidon2ProductionExpectedContext, Poseidon2ProductionTransportStage,
        POSEIDON2_PRODUCTION_MAX_ACTION_BYTES, POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES,
        POSEIDON2_PRODUCTION_SMZ9_NATIVE_LEAF_MAGIC, POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_MAGIC,
    },
    poseidon2_v8_coinbase::{MintPoseidon2V8CoinbaseArgs, Poseidon2V8CoinbaseNoteOpening},
    poseidon2_v8_retained_vectors::{
        RETAINED_V8_COINBASE_0_SCALE, RETAINED_V8_COINBASE_1_SCALE,
        RETAINED_V8_INLINE_CIPHERTEXT_SHA512, RETAINED_V8_OUTPUT_0_RAW, RETAINED_V8_OUTPUT_1_RAW,
        RETAINED_V8_OUTPUT_OPENINGS, RETAINED_V8_STATEMENT_SHA512, RETAINED_V8_WITNESS_SHA512,
    },
};
use protocol_versioning::{CIRCUIT_V8, CRYPTO_SUITE_ETA};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use transaction_circuit::{
    build_smallwood_poseidon2_v8_smz9_verifier_trace_v1,
    smallwood_poseidon2_v8_coinbase::{
        poseidon2_v8_note_commitment, poseidon2_v8_single_key_authorization_key,
        poseidon2_v8_two_note_frontier, Poseidon2V8TwoNoteFrontier,
    },
    smallwood_poseidon2_v8_frontend::{
        compile_and_prove_smallwood_poseidon2_v8_candidate,
        project_smallwood_poseidon2_v8_candidate_bytes, report_smallwood_poseidon2_v8_candidate,
        smallwood_poseidon2_v8_exact_action_bytes, verify_smallwood_poseidon2_v8_candidate,
        SmallwoodPoseidon2V8VerifierInput, SMALLWOOD_POSEIDON2_V8_INLINE_FIXED_BYTES,
    },
    smallwood_poseidon2_v8_hash_constraints::smallwood_poseidon2_v8_hash_call_initial_witness_index,
    smallwood_poseidon2_v8_hash_schedule::build_smallwood_poseidon2_v8_hash_schedule,
    smallwood_poseidon2_v8_program::{
        encode_smallwood_poseidon2_v8_program, smallwood_poseidon2_v8_program_digest_from_bytes,
        SMALLWOOD_POSEIDON2_V8_ACTION_ID, SMALLWOOD_POSEIDON2_V8_BACKEND_ID,
        SMALLWOOD_POSEIDON2_V8_DOMAIN_SET, SMALLWOOD_POSEIDON2_V8_PROFILE_ID,
        SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST, SMALLWOOD_POSEIDON2_V8_PROGRAM_MAGIC,
        SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512, SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES,
    },
    smallwood_poseidon2_v8_relation::SMALLWOOD_POSEIDON2_V8_RELATION_ID,
    smallwood_poseidon2_v8_semantics::{
        compile_smallwood_poseidon2_v8_relation, SmallwoodPoseidon2V8ConstraintAdapter,
        SMALLWOOD_POSEIDON2_V8_HASH_ROW_START, SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR,
    },
    smallwood_poseidon2_v8_types::{
        smallwood_poseidon2_v8_ciphertext_commitment, SmallwoodPoseidon2V8Ciphertext,
        SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8InlineCiphertexts,
        SmallwoodPoseidon2V8InputWitness, SmallwoodPoseidon2V8NoteOpening,
        SmallwoodPoseidon2V8OutputWitness, SmallwoodPoseidon2V8PublicStatement,
        SmallwoodPoseidon2V8Witness, SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES,
        SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH, SMALLWOOD_POSEIDON2_V8_PUBLIC_BYTES,
    },
    smallwood_poseidon2_v8_zk_refinement::validate_accepted_smallwood_poseidon2_v8_smz9_refinement_v1,
};
use transaction_core::{
    constants::{MERKLE_DOMAIN_TAG, NATIVE_ASSET_ID},
    poseidon2_width16::{poseidon2_width16_compress14, Felt},
    stablecoin_poseidon2_v8::StablecoinPoseidon2V8Public,
};

type RunnerResult<T> = Result<T, Box<dyn Error>>;

const NETWORK_ID: u32 = 0x4847_4d38;
const MAXIMUM_SHAPE_MASK: u8 = 0b1111;
const EXPECTED_PROJECTED_PROOF_BYTES: usize = 122_863;
const EXPECTED_PROJECTED_SCALE_INLINE_ARGS_BYTES: usize = 128_297;
const EXPECTED_PROJECTED_RPC_ENVELOPE_BYTES: usize = 128_293;
const EXPECTED_PROJECTED_PENDING_ACTION_BYTES: usize = 128_522;
const INPUT_0_NOTE_FINAL: usize = 3;
const INPUT_0_ROOT_FINAL: usize = 35;
const INPUT_0_NULLIFIER_FINAL: usize = 36;
const INPUT_1_NOTE_FINAL: usize = 39;
const INPUT_1_ROOT_FINAL: usize = 71;
const INPUT_1_NULLIFIER_FINAL: usize = 72;
const OUTPUT_0_NOTE_FINAL: usize = 75;
const OUTPUT_1_NOTE_FINAL: usize = 78;
const RETAINED_PROOF_PRIMARY: &str = "retained_proof_primary";
const RETAINED_PROOF_INDEPENDENT: &str = "retained_proof_independent";
const RETAINED_LIFECYCLE_SEED: &str = "retained_lifecycle_seed";
const RETAINED_SPEND_FIXTURE_GROUP: &str = "retained_coinbase_spend_positions_0_1_v1";
const RETAINED_ZERO_SEED_FIXTURE_GROUP: &str = "retained_zero_value_seed_0x2_v1";
const RETAINED_SPEND_PARENT_HEIGHT: u64 = 2;
const RETAINED_SEED_PARENT_HEIGHT: u64 = 0;
const RETAINED_STABLECOIN_ROOT: [Felt; 7] = [Felt::ZERO; 7];
// Exact `RootSecret([0x51; 32]).derive()` V8 spend words. The wallet owns this
// key and derives the matching address-v4/Eta recipient at index 9.
const RETAINED_SPEND_KEY: [u64; 4] = [
    12_387_129_418_859_519_852,
    3_275_605_879_553_790_158,
    18_179_312_849_545_706_498,
    6_480_565_605_584_441_507,
];
const RETAINED_RECIPIENT_KEY: [u64; 4] = [
    14_132_942_956_216_209_493,
    7_685_267_610_787_277_800,
    16_563_171_182_421_170_277,
    17_300_113_818_709_955_652,
];
const RETAINED_COINBASE_AMOUNTS: [u64; 2] = [499_429_223, 499_429_223];
const LEGACY_ARTIFACT_SCHEMA: &str = "hegemon-smallwood-poseidon2-v8-retained-artifact-v4";
const FINAL_ARTIFACT_SCHEMA: &str = "hegemon-smallwood-poseidon2-v8-retained-artifact-v5";
const PROGRAM_MAGIC_ASCII: &str = "HGV8RP03";
const NATIVE_LEAF_MAGIC_ASCII: &str = "HGV8TX02";
const TRANSPORT_MAGIC_ASCII: &str = "SWP8LC02";
const GENERATION_PROVENANCE_SCHEMA: &str =
    "hegemon-smallwood-poseidon2-v8-generation-provenance-v1";
const LEGACY_GENERATION_INDEPENDENCE_SCOPE: &str = "separate_process_fresh_rng_same_source";
const FINAL_GENERATION_METADATA_SCOPE: &str = "informational_unattested_generation_metadata";
const SOURCE_INVENTORY_SCHEMA: &str = "hegemon-smallwood-poseidon2-v8-release-source-inventory-v2";
const SOURCE_INVENTORY_DOMAIN: &[u8] =
    b"hegemon.smallwood.poseidon2-v8.release-source-inventory.v2\0";
const RETIRED_SOURCE_INVENTORY_V1_DOMAIN: &[u8] =
    b"hegemon.smallwood.poseidon2-v8.proof-source-inventory.v1\0";
const PROVENANCE_TRANSITION_SCHEMA: &str =
    "hegemon-smallwood-poseidon2-v8-provenance-transition-v1";
const VERIFIER_PROVENANCE_SCHEMA: &str = "hegemon-smallwood-poseidon2-v8-verifier-provenance-v1";
const SOURCE_INVENTORY_ROOT_PACKAGE: &str = "transaction-circuit";
const SOURCE_INVENTORY_ROOT_PACKAGES: [&str; 4] =
    ["transaction-circuit", "hegemon-node", "wallet", "walletd"];
const SOURCE_INVENTORY_REQUIRED_ROOT_FILES: [&str; 7] = [
    ".cargo/config.toml",
    ".gitignore",
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "formal/crypto/HegemonCrypto/SmallWoodV8Smz9ZeroKnowledge.lean",
    "formal/crypto/HegemonCrypto/SmallWoodV8Smz9AdaptiveFiniteAccounting.lean",
];
const SOURCE_INVENTORY_REQUIRED_ROOT_DIRECTORIES: [&str; 2] = ["formal/crypto", "formal/lean"];
const SOURCE_INVENTORY_MAX_FILES: usize = 4_096;
const SOURCE_INVENTORY_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const SOURCE_INVENTORY_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const GENERATOR_SOURCE_PATH: &str =
    "circuits/transaction/examples/smallwood_poseidon2_v8_artifact.rs";

fn runner_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::Other, message.into()))
}

fn ensure_frozen_identity_constants() -> RunnerResult<()> {
    if SMALLWOOD_POSEIDON2_V8_PROGRAM_MAGIC.as_slice() != PROGRAM_MAGIC_ASCII.as_bytes()
        || POSEIDON2_PRODUCTION_SMZ9_NATIVE_LEAF_MAGIC.as_slice()
            != NATIVE_LEAF_MAGIC_ASCII.as_bytes()
        || POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_MAGIC.as_slice() != TRANSPORT_MAGIC_ASCII.as_bytes()
        || SMALLWOOD_POSEIDON2_V8_ACTION_ID != 10
        || CIRCUIT_V8 != 8
        || CRYPTO_SUITE_ETA != 7
        || FAMILY_SHIELDED_POOL != 1
        || SMALLWOOD_POSEIDON2_V8_BACKEND_ID != 2
        || SMALLWOOD_POSEIDON2_V8_PROFILE_ID != 6
        || SMALLWOOD_POSEIDON2_V8_DOMAIN_SET != 4
        || SMALLWOOD_POSEIDON2_V8_RELATION_ID
            != "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v2"
    {
        return Err(runner_error("frozen V8 identity constants drifted"));
    }
    Ok(())
}

fn validated_relation_program() -> RunnerResult<Vec<u8>> {
    ensure_frozen_identity_constants()?;
    let relation_program = encode_smallwood_poseidon2_v8_program();
    let recomputed_program_sha512 = Sha512::digest(&relation_program);
    let recomputed_program_digest =
        smallwood_poseidon2_v8_program_digest_from_bytes(&relation_program);
    if relation_program.len() != SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES
        || recomputed_program_sha512.as_slice() != SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512
        || SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST == [0; 48]
        || recomputed_program_digest != SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST
    {
        return Err(runner_error(
            "V8 source-derived HGV8RP03 relation program digest is not pinned",
        ));
    }
    Ok(relation_program)
}

fn ensure_artifact_role(role: &str) -> RunnerResult<()> {
    if matches!(
        role,
        RETAINED_PROOF_PRIMARY | RETAINED_PROOF_INDEPENDENT | RETAINED_LIFECYCLE_SEED
    ) {
        Ok(())
    } else {
        Err(runner_error(format!(
            "artifact role must be {RETAINED_PROOF_PRIMARY}, {RETAINED_PROOF_INDEPENDENT}, or {RETAINED_LIFECYCLE_SEED}"
        )))
    }
}

fn ensure_resealable_artifact_role(role: &str) -> RunnerResult<()> {
    if matches!(role, RETAINED_PROOF_PRIMARY | RETAINED_PROOF_INDEPENDENT) {
        Ok(())
    } else {
        Err(runner_error(format!(
            "v4 reseal role must be {RETAINED_PROOF_PRIMARY} or {RETAINED_PROOF_INDEPENDENT}"
        )))
    }
}

struct GenerationProvenanceStart {
    source_revision: String,
    generator_source_sha512: String,
    generator_binary_bytes: u64,
    generator_binary_sha512: String,
    run_id_hex: String,
    process_id: u32,
    started_unix_seconds: u64,
}

impl GenerationProvenanceStart {
    fn report(&self, artifact_role: &str, proof_sha512: &str, metadata_scope: &str) -> Value {
        json!({
            "schema": GENERATION_PROVENANCE_SCHEMA,
            "independence_scope": metadata_scope,
            "artifact_role": artifact_role,
            "source_revision": self.source_revision,
            "generator_source_path": GENERATOR_SOURCE_PATH,
            "generator_source_sha512": self.generator_source_sha512,
            "generator_binary_bytes": self.generator_binary_bytes,
            "generator_binary_sha512": self.generator_binary_sha512,
            "run_id_hex": self.run_id_hex,
            "process_id": self.process_id,
            "started_unix_seconds": self.started_unix_seconds,
            "proof_sha512": proof_sha512,
        })
    }
}

fn canonical_lower_hex(value: &str, encoded_bytes: usize) -> bool {
    value.len() == encoded_bytes.saturating_mul(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProofSourceInventory {
    report: Value,
    root_sha512: String,
}

#[derive(Debug)]
struct ProofSourcePackageClosure {
    package_roots: Vec<PathBuf>,
    activated_features: BTreeMap<PathBuf, BTreeSet<String>>,
    inactive_optional_local_dependencies: Vec<(String, String, String)>,
}

fn canonical_repo_relative_path(root: &Path, path: &Path) -> RunnerResult<String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        runner_error(format!(
            "proof source path {} escapes workspace root {}",
            path.display(),
            root.display()
        ))
    })?;
    if relative.as_os_str().is_empty() {
        return Err(runner_error("proof source path is the workspace root"));
    }
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or_else(|| runner_error("proof source path is not UTF-8"))?,
            ),
            _ => {
                return Err(runner_error(
                    "proof source path is not a canonical repository-relative path",
                ))
            }
        }
    }
    Ok(parts.join("/"))
}

fn proof_source_repository_root() -> RunnerResult<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = fs::canonicalize(&root).map_err(|error| {
        runner_error(format!(
            "proof source repository root {} is unavailable: {error}",
            root.display()
        ))
    })?;
    ensure_no_symlink_path_components(&root)?;
    Ok(root)
}

fn proof_source_metadata(
    repository_root: &Path,
    manifest_path: Option<&Path>,
) -> RunnerResult<Value> {
    let mut command = Command::new("cargo");
    command.args([
        "metadata",
        "--locked",
        "--offline",
        "--format-version",
        "1",
        "--no-deps",
    ]);
    if let Some(manifest_path) = manifest_path {
        command.arg("--manifest-path").arg(manifest_path);
    }
    let output = command
        .current_dir(repository_root)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(runner_error(format!(
            "proof source inventory cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| runner_error(format!("proof source cargo metadata is invalid: {error}")))
}

fn source_inventory_dependency_name(dependency: &Value) -> RunnerResult<String> {
    dependency
        .get("rename")
        .and_then(Value::as_str)
        .or_else(|| dependency.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .ok_or_else(|| runner_error("proof source cargo dependency omitted its name"))
}

fn load_excluded_proof_source_package(
    repository_root: &Path,
    package_root: &Path,
    packages_by_root: &mut BTreeMap<PathBuf, Value>,
) -> RunnerResult<()> {
    if packages_by_root.contains_key(package_root) {
        return Ok(());
    }
    let canonical_root = fs::canonicalize(package_root).map_err(|error| {
        runner_error(format!(
            "active proof source local dependency {} is unavailable: {error}",
            package_root.display()
        ))
    })?;
    if canonical_root != package_root
        || fs::symlink_metadata(package_root)?.file_type().is_symlink()
        || canonical_root.strip_prefix(repository_root).is_err()
    {
        return Err(runner_error(
            "active proof source local dependency path is noncanonical, symlinked, or outside the release root",
        ));
    }
    let manifest_path = package_root.join("Cargo.toml");
    let metadata = proof_source_metadata(repository_root, Some(&manifest_path))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| runner_error("excluded local package metadata omitted packages"))?;
    let mut matched = None;
    for package in packages {
        let observed_manifest = package["manifest_path"]
            .as_str()
            .map(Path::new)
            .ok_or_else(|| runner_error("excluded cargo package omitted manifest_path"))?;
        if observed_manifest == manifest_path {
            if matched.replace(package.clone()).is_some() {
                return Err(runner_error(
                    "excluded local package metadata identified duplicate manifests",
                ));
            }
        }
    }
    let package = matched.ok_or_else(|| {
        runner_error("excluded local package metadata did not identify one exact manifest")
    })?;
    packages_by_root.insert(package_root.to_path_buf(), package);
    Ok(())
}

type ProofSourceFeatureExpansion = (
    BTreeSet<String>,
    BTreeSet<String>,
    BTreeMap<String, BTreeSet<String>>,
);

fn expand_proof_source_features(
    package: &Value,
    seeds: &BTreeSet<String>,
) -> RunnerResult<ProofSourceFeatureExpansion> {
    let raw_feature_table = package["features"]
        .as_object()
        .ok_or_else(|| runner_error("proof source cargo package features must be an object"))?;
    let mut feature_table = BTreeMap::<String, Vec<String>>::new();
    for (name, raw_members) in raw_feature_table {
        let members = raw_members
            .as_array()
            .ok_or_else(|| runner_error("proof source cargo feature members must be an array"))?
            .iter()
            .map(|member| {
                member.as_str().map(str::to_owned).ok_or_else(|| {
                    runner_error("proof source cargo feature members must be strings")
                })
            })
            .collect::<RunnerResult<Vec<_>>>()?;
        feature_table.insert(name.clone(), members);
    }
    let dependencies = package["dependencies"]
        .as_array()
        .ok_or_else(|| runner_error("proof source cargo package dependencies must be an array"))?;
    let dependency_names = dependencies
        .iter()
        .map(source_inventory_dependency_name)
        .collect::<RunnerResult<BTreeSet<_>>>()?;

    let mut active_features = BTreeSet::new();
    let mut enabled_dependencies = BTreeSet::new();
    let mut forwarded = BTreeMap::<String, BTreeSet<String>>::new();
    let mut feature_queue = seeds.iter().cloned().collect::<Vec<_>>();
    let mut deferred_conditional = Vec::<(String, String)>::new();
    while let Some(token) = feature_queue.pop() {
        if let Some(dependency_name) = token.strip_prefix("dep:") {
            if !dependency_names.contains(dependency_name) {
                return Err(runner_error(
                    "proof source Cargo feature enables an unknown dependency",
                ));
            }
            enabled_dependencies.insert(dependency_name.to_owned());
            continue;
        }
        if let Some((dependency_name, dependency_feature)) = token.split_once('/') {
            let (dependency_name, conditional) = dependency_name
                .strip_suffix('?')
                .map_or((dependency_name, false), |name| (name, true));
            if !dependency_names.contains(dependency_name) {
                return Err(runner_error(
                    "proof source Cargo feature forwards to an unknown dependency",
                ));
            }
            if conditional && !enabled_dependencies.contains(dependency_name) {
                deferred_conditional
                    .push((dependency_name.to_owned(), dependency_feature.to_owned()));
                continue;
            }
            enabled_dependencies.insert(dependency_name.to_owned());
            forwarded
                .entry(dependency_name.to_owned())
                .or_default()
                .insert(dependency_feature.to_owned());
            continue;
        }
        if let Some(members) = feature_table.get(&token) {
            if active_features.insert(token) {
                feature_queue.extend(members.iter().cloned());
            }
            continue;
        }
        if token == "default" {
            continue;
        }
        if dependency_names.contains(&token) {
            enabled_dependencies.insert(token);
            continue;
        }
        return Err(runner_error(format!(
            "proof source Cargo feature references unknown token {token:?}",
        )));
    }
    for (dependency_name, dependency_feature) in deferred_conditional {
        if enabled_dependencies.contains(&dependency_name) {
            forwarded
                .entry(dependency_name)
                .or_default()
                .insert(dependency_feature);
        }
    }
    Ok((active_features, enabled_dependencies, forwarded))
}

fn proof_source_package_closure(
    metadata: &Value,
    repository_root: &Path,
) -> RunnerResult<ProofSourcePackageClosure> {
    let metadata_root = metadata["workspace_root"]
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| runner_error("cargo metadata omitted workspace_root"))?;
    if fs::canonicalize(&metadata_root)? != repository_root {
        return Err(runner_error(
            "proof source cargo workspace root differs from release root",
        ));
    }
    ensure_no_symlink_path_components(&metadata_root)?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| runner_error("cargo metadata omitted packages"))?;
    let mut packages_by_root = BTreeMap::<PathBuf, Value>::new();
    let mut root_packages = BTreeMap::<String, PathBuf>::new();
    for package in packages {
        let manifest = package["manifest_path"]
            .as_str()
            .map(PathBuf::from)
            .ok_or_else(|| runner_error("cargo package omitted manifest_path"))?;
        let package_root = manifest
            .parent()
            .ok_or_else(|| runner_error("cargo package manifest has no parent"))?
            .to_path_buf();
        if package_root.strip_prefix(repository_root).is_err() {
            continue;
        }
        if packages_by_root
            .insert(package_root.clone(), package.clone())
            .is_some()
        {
            return Err(runner_error(
                "cargo metadata contains duplicate local package roots",
            ));
        }
        let Some(package_name) = package["name"].as_str() else {
            return Err(runner_error("cargo package omitted name"));
        };
        if SOURCE_INVENTORY_ROOT_PACKAGES.contains(&package_name)
            && root_packages
                .insert(package_name.to_owned(), package_root)
                .is_some()
        {
            return Err(runner_error(
                "cargo metadata contains duplicate release root packages",
            ));
        }
    }
    if root_packages.len() != SOURCE_INVENTORY_ROOT_PACKAGES.len()
        || SOURCE_INVENTORY_ROOT_PACKAGES
            .iter()
            .any(|name| !root_packages.contains_key(*name))
    {
        return Err(runner_error(
            "cargo metadata omitted a required release root package",
        ));
    }

    let mut requested_features = root_packages
        .iter()
        .map(|(name, root)| {
            let features = if name == "hegemon-node" {
                BTreeSet::new()
            } else {
                BTreeSet::from(["default".to_owned()])
            };
            (root.clone(), features)
        })
        .collect::<BTreeMap<_, _>>();
    let mut expanded_features = BTreeMap::<PathBuf, BTreeSet<String>>::new();
    let mut enabled_optional_dependencies = BTreeMap::<PathBuf, BTreeSet<String>>::new();
    let mut forwarded_dependency_features =
        BTreeMap::<PathBuf, BTreeMap<String, BTreeSet<String>>>::new();
    let mut pending = root_packages.values().cloned().collect::<Vec<_>>();
    let mut closure = BTreeSet::<PathBuf>::new();
    while let Some(package_root) = pending.pop() {
        closure.insert(package_root.clone());
        let package = packages_by_root
            .get(&package_root)
            .cloned()
            .ok_or_else(|| runner_error("proof source local package closure escaped metadata"))?;
        let seeds = requested_features
            .get(&package_root)
            .cloned()
            .unwrap_or_default();
        let (active_features, enabled_dependencies, forwarded) =
            expand_proof_source_features(&package, &seeds)?;
        if expanded_features.get(&package_root) == Some(&active_features)
            && enabled_optional_dependencies.get(&package_root) == Some(&enabled_dependencies)
            && forwarded_dependency_features.get(&package_root) == Some(&forwarded)
        {
            continue;
        }
        expanded_features.insert(package_root.clone(), active_features);
        enabled_optional_dependencies.insert(package_root.clone(), enabled_dependencies.clone());
        forwarded_dependency_features.insert(package_root.clone(), forwarded.clone());

        let dependencies = package["dependencies"].as_array().ok_or_else(|| {
            runner_error("proof source cargo package dependencies must be an array")
        })?;
        for dependency in dependencies {
            let Some(path) = dependency["path"].as_str() else {
                continue;
            };
            let dependency_root = PathBuf::from(path);
            if dependency_root.strip_prefix(repository_root).is_err() {
                continue;
            }
            let dependency_name = source_inventory_dependency_name(dependency)?;
            let optional = dependency["optional"].as_bool().ok_or_else(|| {
                runner_error("proof source cargo dependency optional flag must be Boolean")
            })?;
            if optional && !enabled_dependencies.contains(&dependency_name) {
                continue;
            }
            if !packages_by_root.contains_key(&dependency_root) {
                load_excluded_proof_source_package(
                    repository_root,
                    &dependency_root,
                    &mut packages_by_root,
                )?;
            }
            let dependency_features = dependency["features"].as_array().ok_or_else(|| {
                runner_error("proof source cargo dependency features must be an array")
            })?;
            let mut child_features = dependency_features
                .iter()
                .map(|feature| {
                    feature.as_str().map(str::to_owned).ok_or_else(|| {
                        runner_error("proof source cargo dependency features must be strings")
                    })
                })
                .collect::<RunnerResult<BTreeSet<_>>>()?;
            child_features.extend(forwarded.get(&dependency_name).cloned().unwrap_or_default());
            if dependency["uses_default_features"]
                .as_bool()
                .ok_or_else(|| {
                    runner_error(
                        "proof source cargo dependency default-feature flag must be Boolean",
                    )
                })?
            {
                child_features.insert("default".to_owned());
            }
            let observed = requested_features
                .entry(dependency_root.clone())
                .or_default();
            let needs_revisit = !closure.contains(&dependency_root)
                || child_features
                    .iter()
                    .any(|feature| !observed.contains(feature));
            if needs_revisit {
                observed.extend(child_features);
                pending.push(dependency_root);
            }
        }
    }

    let mut inactive_optional_local_dependencies = Vec::new();
    for package_root in &closure {
        let package = packages_by_root
            .get(package_root)
            .ok_or_else(|| runner_error("proof source closure package disappeared"))?;
        let dependencies = package["dependencies"].as_array().ok_or_else(|| {
            runner_error("proof source cargo package dependencies must be an array")
        })?;
        let enabled_dependencies = enabled_optional_dependencies
            .get(package_root)
            .cloned()
            .unwrap_or_default();
        for dependency in dependencies {
            let Some(path) = dependency["path"].as_str() else {
                continue;
            };
            let dependency_root = PathBuf::from(path);
            if dependency_root.strip_prefix(repository_root).is_err() {
                continue;
            }
            let dependency_name = source_inventory_dependency_name(dependency)?;
            if dependency["optional"].as_bool() == Some(true)
                && !enabled_dependencies.contains(&dependency_name)
            {
                inactive_optional_local_dependencies.push((
                    canonical_repo_relative_path(
                        repository_root,
                        &package_root.join("Cargo.toml"),
                    )?,
                    dependency_name,
                    canonical_repo_relative_path(repository_root, &dependency_root)?,
                ));
            }
        }
    }
    inactive_optional_local_dependencies.sort();
    Ok(ProofSourcePackageClosure {
        package_roots: closure.into_iter().collect(),
        activated_features: expanded_features,
        inactive_optional_local_dependencies,
    })
}

fn collect_proof_source_files(
    workspace_root: &Path,
    package_root: &Path,
    files: &mut BTreeSet<PathBuf>,
) -> RunnerResult<()> {
    if !package_root.starts_with(workspace_root) {
        return Err(runner_error("proof source package escapes workspace root"));
    }
    let mut pending = vec![package_root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        ensure_no_symlink_path_components(&directory)?;
        let metadata = fs::symlink_metadata(&directory)?;
        if !metadata.file_type().is_dir() {
            return Err(runner_error(format!(
                "proof source package entry {} is not a directory",
                directory.display()
            )));
        }
        let mut entries = fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                return Err(runner_error(format!(
                    "proof source inventory rejects symlink {}",
                    path.display()
                )));
            }
            if file_type.is_dir() {
                let name = entry.file_name();
                if matches!(name.to_str(), Some("target" | ".git" | ".agent" | ".lake")) {
                    continue;
                }
                pending.push(path);
            } else if file_type.is_file() {
                files.insert(path.clone());
                if files.len() > SOURCE_INVENTORY_MAX_FILES {
                    return Err(runner_error("proof source inventory file cap exceeded"));
                }
            } else {
                return Err(runner_error(format!(
                    "proof source inventory rejects non-regular entry {}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

fn proof_source_inventory_root_sha512(domain: &[u8], entries: &[Value]) -> RunnerResult<String> {
    let mut root_hasher = Sha512::new();
    root_hasher.update(domain);
    for entry in entries {
        let relative = entry["path"]
            .as_str()
            .ok_or_else(|| runner_error("proof source inventory entry omitted its path"))?;
        let bytes = entry["bytes"]
            .as_u64()
            .ok_or_else(|| runner_error("proof source inventory entry omitted its byte count"))?;
        let digest = entry["sha512"]
            .as_str()
            .ok_or_else(|| runner_error("proof source inventory entry omitted its SHA-512"))?;
        if !canonical_lower_hex(digest, 64) {
            return Err(runner_error(
                "proof source inventory entry SHA-512 is not canonical",
            ));
        }
        let path_bytes = relative.as_bytes();
        let path_len = u32::try_from(path_bytes.len())
            .map_err(|_| runner_error("proof source path length exceeds u32"))?;
        root_hasher.update(path_len.to_le_bytes());
        root_hasher.update(path_bytes);
        root_hasher.update(bytes.to_le_bytes());
        root_hasher.update(
            hex::decode(digest)
                .map_err(|_| runner_error("proof source SHA-512 encoding is invalid"))?,
        );
    }
    Ok(hex::encode(root_hasher.finalize()))
}

fn compute_proof_source_inventory() -> RunnerResult<ProofSourceInventory> {
    let repository_root = proof_source_repository_root()?;
    let metadata = proof_source_metadata(&repository_root, None)?;
    let closure = proof_source_package_closure(&metadata, &repository_root)?;
    let mut files = BTreeSet::new();
    for relative in SOURCE_INVENTORY_REQUIRED_ROOT_FILES {
        files.insert(repository_root.join(relative));
    }
    for package_root in &closure.package_roots {
        collect_proof_source_files(&repository_root, package_root, &mut files)?;
    }
    for relative in SOURCE_INVENTORY_REQUIRED_ROOT_DIRECTORIES {
        collect_proof_source_files(
            &repository_root,
            &repository_root.join(relative),
            &mut files,
        )?;
    }
    if files.len() > SOURCE_INVENTORY_MAX_FILES {
        return Err(runner_error("proof source inventory file cap exceeded"));
    }

    let file_count = files.len();
    let mut ordered_files = files
        .into_iter()
        .map(|path| {
            let relative = canonical_repo_relative_path(&repository_root, &path)?;
            Ok((relative, path))
        })
        .collect::<RunnerResult<Vec<_>>>()?;
    ordered_files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut entries = Vec::with_capacity(file_count);
    let mut total_bytes = 0u64;
    for (relative, path) in ordered_files {
        ensure_no_symlink_path_components(&path)?;
        let (bytes, sha512) = sha512_file(&path)?;
        if bytes > SOURCE_INVENTORY_MAX_FILE_BYTES {
            return Err(runner_error(format!(
                "proof source file {relative} exceeds the per-file cap"
            )));
        }
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or_else(|| runner_error("proof source inventory byte count overflow"))?;
        if total_bytes > SOURCE_INVENTORY_MAX_TOTAL_BYTES {
            return Err(runner_error(
                "proof source inventory total byte cap exceeded",
            ));
        }
        entries.push(json!({"path": relative, "bytes": bytes, "sha512": sha512}));
    }
    let mut packages = closure
        .package_roots
        .iter()
        .map(|root| {
            Ok((
                canonical_repo_relative_path(&repository_root, &root.join("Cargo.toml"))?,
                root,
            ))
        })
        .collect::<RunnerResult<Vec<_>>>()?;
    // Python's pathlib orders paths by their component tuple, not by the raw
    // slash-containing string (`block` sorts before `block-recursion`).
    packages.sort_by(|left, right| left.0.split('/').cmp(right.0.split('/')));
    let package_manifests = packages
        .iter()
        .map(|(manifest, _)| manifest.clone())
        .collect::<Vec<_>>();
    let activated_features = packages
        .iter()
        .map(|(package_manifest, root)| {
            let features = closure
                .activated_features
                .get(*root)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();
            json!({
                "package_manifest": package_manifest,
                "features": features,
            })
        })
        .collect::<Vec<_>>();
    let inactive_optional_local_dependencies = closure
        .inactive_optional_local_dependencies
        .iter()
        .map(|(package_manifest, dependency_name, dependency_path)| {
            json!({
                "package_manifest": package_manifest,
                "dependency_name": dependency_name,
                "dependency_path": dependency_path,
                "reason": "inactive_in_source_owned_default_feature_graph",
            })
        })
        .collect::<Vec<_>>();
    let root_sha512 = proof_source_inventory_root_sha512(SOURCE_INVENTORY_DOMAIN, &entries)?;
    let report = json!({
        "schema": SOURCE_INVENTORY_SCHEMA,
        "root_package": SOURCE_INVENTORY_ROOT_PACKAGE,
        "root_packages": SOURCE_INVENTORY_ROOT_PACKAGES,
        "root_features": {
            "transaction-circuit": ["default"],
            "hegemon-node": [],
            "wallet": ["default"],
            "walletd": ["default"],
        },
        "required_root_directories": SOURCE_INVENTORY_REQUIRED_ROOT_DIRECTORIES,
        "cargo_metadata_arguments": [
            "metadata", "--locked", "--offline", "--format-version", "1", "--no-deps"
        ],
        "excluded_directory_names": [".agent", ".git", ".lake", "target"],
        "maximum_files": SOURCE_INVENTORY_MAX_FILES,
        "maximum_file_bytes": SOURCE_INVENTORY_MAX_FILE_BYTES,
        "maximum_total_bytes": SOURCE_INVENTORY_MAX_TOTAL_BYTES,
        "package_manifests": package_manifests,
        "activated_features": activated_features,
        "inactive_optional_local_dependencies": inactive_optional_local_dependencies,
        "file_count": entries.len(),
        "total_bytes": total_bytes,
        "root_sha512": root_sha512,
        "entries": entries,
    });
    Ok(ProofSourceInventory {
        report,
        root_sha512,
    })
}

fn verify_proof_source_inventory(report: &Value) -> RunnerResult<ProofSourceInventory> {
    let observed = compute_proof_source_inventory()?;
    if report != &observed.report {
        return Err(runner_error(
            "artifact proof-source inventory differs from independently recomputed source",
        ));
    }
    Ok(observed)
}

fn canonical_json_bytes(value: &Value) -> RunnerResult<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn generator_source_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/smallwood_poseidon2_v8_artifact.rs")
}

fn source_revision() -> RunnerResult<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .arg("rev-parse")
        .arg("--verify")
        .arg("HEAD")
        .output()?;
    if !output.status.success() {
        return Err(runner_error(format!(
            "failed to resolve generator source revision: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let revision = String::from_utf8(output.stdout)?.trim().to_owned();
    if !matches!(revision.len(), 40 | 64)
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(runner_error(
            "generator source revision is not a canonical lowercase Git object id",
        ));
    }
    Ok(revision)
}

fn sha512_file(path: &Path) -> RunnerResult<(u64, String)> {
    let path_metadata = fs::symlink_metadata(path)?;
    if !path_metadata.file_type().is_file() {
        return Err(runner_error(format!(
            "provenance input {} is not a regular file",
            path.display()
        )));
    }
    let mut file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if opened_metadata.len() != path_metadata.len() {
        return Err(runner_error(format!(
            "provenance input {} changed before hashing",
            path.display()
        )));
    }
    #[cfg(unix)]
    if opened_metadata.dev() != path_metadata.dev() || opened_metadata.ino() != path_metadata.ino()
    {
        return Err(runner_error(format!(
            "provenance input {} changed before descriptor binding",
            path.display()
        )));
    }
    let mut hasher = Sha512::new();
    let mut observed_bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        observed_bytes = observed_bytes
            .checked_add(read as u64)
            .ok_or_else(|| runner_error("provenance file byte count overflow"))?;
    }
    let terminal_metadata = file.metadata()?;
    if observed_bytes != opened_metadata.len()
        || terminal_metadata.len() != opened_metadata.len()
        || terminal_metadata.modified()? != opened_metadata.modified()?
    {
        return Err(runner_error(format!(
            "provenance input {} changed while hashing",
            path.display()
        )));
    }
    Ok((observed_bytes, hex::encode(hasher.finalize())))
}

fn collect_generation_provenance() -> RunnerResult<GenerationProvenanceStart> {
    let executable = env::current_exe()?;
    let source_revision = source_revision()?;
    let source_bytes = fs::read(generator_source_file())?;
    let generator_source_sha512 = sha512_hex(&source_bytes);
    let (generator_binary_bytes, generator_binary_sha512) = sha512_file(&executable)?;
    let mut run_id = [0u8; 32];
    getrandom_fill(&mut run_id)
        .map_err(|error| runner_error(format!("generation run-id entropy failed: {error}")))?;
    if run_id == [0; 32] {
        return Err(runner_error(
            "generation run-id entropy returned all zeroes",
        ));
    }
    Ok(GenerationProvenanceStart {
        source_revision,
        generator_source_sha512,
        generator_binary_bytes,
        generator_binary_sha512,
        run_id_hex: hex::encode(run_id),
        process_id: std::process::id(),
        started_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    })
}

fn begin_generation_provenance() -> RunnerResult<GenerationProvenanceStart> {
    let executable = env::current_exe()?;
    let retained_profile_component = executable
        .components()
        .any(|component| component.as_os_str() == "retained-proof");
    if cfg!(debug_assertions) || !retained_profile_component {
        return Err(runner_error(
            "retained proofs must be generated by `cargo build --profile retained-proof -p transaction-circuit --example smallwood_poseidon2_v8_artifact`",
        ));
    }
    collect_generation_provenance()
}

fn verify_generation_provenance(
    manifest: &Value,
    artifact_role: &str,
    proof_sha512: &str,
    require_current_generator_identity: bool,
) -> RunnerResult<Value> {
    let provenance = manifest
        .get("generation_provenance")
        .and_then(Value::as_object)
        .ok_or_else(|| runner_error("artifact report is missing generation_provenance"))?;
    let expected_keys = [
        "schema",
        "independence_scope",
        "artifact_role",
        "source_revision",
        "generator_source_path",
        "generator_source_sha512",
        "generator_binary_bytes",
        "generator_binary_sha512",
        "run_id_hex",
        "process_id",
        "started_unix_seconds",
        "proof_sha512",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let observed_keys = provenance
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if observed_keys != expected_keys {
        return Err(runner_error(
            "artifact generation provenance key inventory mismatch",
        ));
    }
    let reported_revision = provenance["source_revision"]
        .as_str()
        .ok_or_else(|| runner_error("generation provenance source_revision is not a string"))?;
    let source_hash = provenance["generator_source_sha512"]
        .as_str()
        .ok_or_else(|| runner_error("generation provenance source hash is not a string"))?;
    let binary_hash = provenance["generator_binary_sha512"]
        .as_str()
        .ok_or_else(|| runner_error("generation provenance binary hash is not a string"))?;
    let run_id = provenance["run_id_hex"]
        .as_str()
        .ok_or_else(|| runner_error("generation provenance run id is not a string"))?;
    let started_unix_seconds = provenance["started_unix_seconds"]
        .as_u64()
        .ok_or_else(|| runner_error("generation provenance start time is not a u64"))?;
    let generated_unix_seconds = manifest["generated_unix_seconds"]
        .as_u64()
        .ok_or_else(|| runner_error("artifact generated_unix_seconds is not a u64"))?;
    let (verifier_binary_bytes, verifier_binary_sha512) = sha512_file(&env::current_exe()?)?;
    let expected_scope = match manifest["schema"].as_str() {
        Some(LEGACY_ARTIFACT_SCHEMA) => LEGACY_GENERATION_INDEPENDENCE_SCOPE,
        Some(FINAL_ARTIFACT_SCHEMA)
            if manifest["provenance_transition"]["kind"] == "direct_generation" =>
        {
            FINAL_GENERATION_METADATA_SCOPE
        }
        Some(FINAL_ARTIFACT_SCHEMA) => LEGACY_GENERATION_INDEPENDENCE_SCOPE,
        _ => return Err(runner_error("artifact provenance schema is unsupported")),
    };
    if provenance["schema"] != GENERATION_PROVENANCE_SCHEMA
        || provenance["independence_scope"] != expected_scope
        || provenance["artifact_role"] != artifact_role
        || provenance["generator_source_path"] != GENERATOR_SOURCE_PATH
        || provenance["proof_sha512"] != proof_sha512
        || !matches!(reported_revision.len(), 40 | 64)
        || !reported_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !canonical_lower_hex(source_hash, 64)
        || !canonical_lower_hex(binary_hash, 64)
        || !canonical_lower_hex(run_id, 32)
        || run_id.bytes().all(|byte| byte == b'0')
        || provenance["process_id"].as_u64().unwrap_or(0) == 0
        || started_unix_seconds == 0
        || started_unix_seconds > generated_unix_seconds
    {
        return Err(runner_error(
            "artifact generation provenance is not source-bound and canonical",
        ));
    }
    if require_current_generator_identity
        && (reported_revision != source_revision()?
            || source_hash != sha512_hex(&fs::read(generator_source_file())?)
            || provenance["generator_binary_bytes"].as_u64() != Some(verifier_binary_bytes)
            || binary_hash != verifier_binary_sha512)
    {
        return Err(runner_error(
            "legacy artifact generator does not equal the current source verifier",
        ));
    }
    Ok(Value::Object(provenance.clone()))
}

fn note_with_authorization(
    tag: u64,
    value: u64,
    authorization_key: [u64; 4],
) -> SmallwoodPoseidon2V8NoteOpening {
    SmallwoodPoseidon2V8NoteOpening {
        value,
        asset_id: NATIVE_ASSET_ID,
        recipient_key: core::array::from_fn(|limb| tag + 10 + limb as u64),
        authorization_key,
        rho: core::array::from_fn(|limb| tag + 20 + limb as u64),
        randomness: core::array::from_fn(|limb| tag + 30 + limb as u64),
    }
}

fn relation_opening_from_protocol(
    opening: Poseidon2V8CoinbaseNoteOpening,
) -> SmallwoodPoseidon2V8NoteOpening {
    SmallwoodPoseidon2V8NoteOpening {
        value: opening.value,
        asset_id: opening.asset_id,
        recipient_key: opening.recipient_key,
        authorization_key: opening.authorization_key,
        rho: opening.rho,
        randomness: opening.randomness,
    }
}

fn ciphertext(tag: u8) -> SmallwoodPoseidon2V8Ciphertext {
    core::array::from_fn(|index| {
        tag.wrapping_add((index as u8).wrapping_mul(29))
            .wrapping_add((index >> 8) as u8)
    })
}

fn single_key_authorization_key(spend_key: [u64; 4]) -> RunnerResult<[u64; 4]> {
    poseidon2_v8_single_key_authorization_key(spend_key)
        .map_err(|error| runner_error(format!("single-key PRF materialization failed: {error:?}")))
}

fn note_commitment(
    opening: SmallwoodPoseidon2V8NoteOpening,
) -> RunnerResult<SmallwoodPoseidon2V8Digest> {
    poseidon2_v8_note_commitment(opening)
        .map_err(|error| runner_error(format!("note commitment materialization failed: {error:?}")))
}

fn compress_note_nodes(
    left: SmallwoodPoseidon2V8Digest,
    right: SmallwoodPoseidon2V8Digest,
) -> SmallwoodPoseidon2V8Digest {
    poseidon2_width16_compress14(
        MERKLE_DOMAIN_TAG,
        &left.map(Felt::from_u64),
        &right.map(Felt::from_u64),
    )
    .map(|value| value.as_canonical_u64())
}

/// Canonical empty nodes for the depth-32 V8 note tree.  Index zero is the
/// zero leaf and index `level + 1` is the parent of two index-`level` nodes.
fn canonical_empty_note_nodes(
) -> [SmallwoodPoseidon2V8Digest; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH + 1] {
    let mut nodes = [[0u64; 7]; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH + 1];
    for level in 0..SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH {
        nodes[level + 1] = compress_note_nodes(nodes[level], nodes[level]);
    }
    nodes
}

type TwoNoteFrontier = Poseidon2V8TwoNoteFrontier;

/// Insert two supplied commitments at canonical positions zero and one and
/// return their exact authentication paths and the resulting tree root.
fn canonical_two_note_frontier(commitments: [SmallwoodPoseidon2V8Digest; 2]) -> TwoNoteFrontier {
    poseidon2_v8_two_note_frontier(commitments)
        .expect("retained note commitments are canonical Goldilocks words")
}

/// Deterministic positive-value note openings produced by the first two V8
/// coinbase blocks in the retained lifecycle fixture.  The coinbase action
/// carries the matching public note commitment; no private opening is inferred
/// from ciphertext bytes or from a receipt.
fn retained_coinbase_public_openings() -> RunnerResult<[Poseidon2V8CoinbaseNoteOpening; 2]> {
    let authorization_key = single_key_authorization_key(RETAINED_SPEND_KEY)?;
    let carriers = [
        RETAINED_V8_COINBASE_0_SCALE.as_slice(),
        RETAINED_V8_COINBASE_1_SCALE.as_slice(),
    ];
    let mut openings = [Poseidon2V8CoinbaseNoteOpening::default(); 2];
    for (index, carrier) in carriers.into_iter().enumerate() {
        let mut cursor = carrier;
        let args = MintPoseidon2V8CoinbaseArgs::decode(&mut cursor)
            .map_err(|error| runner_error(format!("decode retained coinbase {index}: {error}")))?;
        if !cursor.is_empty() || args.encode().as_slice() != carrier {
            return Err(runner_error(format!(
                "retained coinbase {index} is not canonical SCALE"
            )));
        }
        let opening = args.miner_note.opening;
        if opening.value != RETAINED_COINBASE_AMOUNTS[index]
            || opening.asset_id != NATIVE_ASSET_ID
            || opening.recipient_key != RETAINED_RECIPIENT_KEY
            || opening.authorization_key != authorization_key
        {
            return Err(runner_error(format!(
                "retained coinbase {index} is not owned by the pinned wallet vector"
            )));
        }
        let relation_opening = relation_opening_from_protocol(opening);
        if note_commitment(relation_opening)? != args.miner_note.commitment {
            return Err(runner_error(format!(
                "retained coinbase {index} commitment differs from its opening"
            )));
        }
        openings[index] = opening;
    }
    Ok(openings)
}

fn retained_coinbase_note_openings() -> RunnerResult<[SmallwoodPoseidon2V8NoteOpening; 2]> {
    Ok(retained_coinbase_public_openings()?.map(relation_opening_from_protocol))
}

fn retained_zero_value_seed_note_openings() -> RunnerResult<[SmallwoodPoseidon2V8NoteOpening; 2]> {
    let authorization_key = single_key_authorization_key(RETAINED_SPEND_KEY)?;
    Ok([
        note_with_authorization(5_000, 0, authorization_key),
        note_with_authorization(5_100, 0, authorization_key),
    ])
}

fn retained_lifecycle_seed_fixture() -> RunnerResult<(
    SmallwoodPoseidon2V8PublicStatement,
    SmallwoodPoseidon2V8Witness,
    SmallwoodPoseidon2V8InlineCiphertexts,
)> {
    let output_notes = retained_zero_value_seed_note_openings()?;
    let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
    let mut witness = SmallwoodPoseidon2V8Witness::default();
    statement.output_flags = [true, true];
    statement.stablecoin = StablecoinPoseidon2V8Public::disabled_at_context(
        RETAINED_SEED_PARENT_HEIGHT,
        RETAINED_STABLECOIN_ROOT,
    );
    for (output, output_note) in output_notes.into_iter().enumerate() {
        witness.outputs[output] = SmallwoodPoseidon2V8OutputWitness {
            active: true,
            note: output_note,
            balance_slot_selectors: [true, false, false, false],
        };
    }

    let inline_ciphertexts = SmallwoodPoseidon2V8InlineCiphertexts {
        ciphertexts: [Some(ciphertext(0x21)), Some(ciphertext(0x72))],
    };
    for output in 0..2 {
        statement.ciphertext_commitments[output] = smallwood_poseidon2_v8_ciphertext_commitment(
            inline_ciphertexts.ciphertexts[output]
                .as_ref()
                .expect("zero-value lifecycle seed output is active"),
        );
    }

    let hashes = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness)?;
    statement.commitments[0] = hashes.calls[OUTPUT_0_NOTE_FINAL].final_digest();
    statement.commitments[1] = hashes.calls[OUTPUT_1_NOTE_FINAL].final_digest();
    witness
        .validate_against_statement(&statement)
        .map_err(|error| {
            runner_error(format!("zero-value lifecycle seed is invalid: {error:?}"))
        })?;
    inline_ciphertexts
        .validate_against_statement(&statement)
        .map_err(|error| runner_error(format!("seed ciphertext binding failed: {error:?}")))?;
    Ok((statement, witness, inline_ciphertexts))
}

/// Build a maximum two-input/two-output spend from exact note openings that
/// were inserted at canonical note-tree positions zero and one.
fn maximum_shape_fixture_from_input_notes(
    input_notes: [SmallwoodPoseidon2V8NoteOpening; 2],
    parent_height: u64,
) -> RunnerResult<(
    SmallwoodPoseidon2V8PublicStatement,
    SmallwoodPoseidon2V8Witness,
    SmallwoodPoseidon2V8InlineCiphertexts,
)> {
    let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
    let mut witness = SmallwoodPoseidon2V8Witness::default();
    statement.input_flags = [true, true];
    statement.output_flags = [true, true];
    statement.stablecoin =
        StablecoinPoseidon2V8Public::disabled_at_context(parent_height, RETAINED_STABLECOIN_ROOT);

    for input in 0..2 {
        witness.inputs[input] = SmallwoodPoseidon2V8InputWitness {
            active: true,
            spend_key: RETAINED_SPEND_KEY,
            note: input_notes[input],
            position: input as u64,
            siblings: [[0; 7]; 32],
            balance_slot_selectors: [true, false, false, false],
        };
    }
    for output in 0..2 {
        let note = relation_opening_from_protocol(RETAINED_V8_OUTPUT_OPENINGS[output]);
        if note.value != input_notes[output].value
            || note.authorization_key != single_key_authorization_key(RETAINED_SPEND_KEY)?
        {
            return Err(runner_error(format!(
                "retained wallet output {output} does not conserve or authorize value"
            )));
        }
        witness.outputs[output] = SmallwoodPoseidon2V8OutputWitness {
            active: true,
            note,
            balance_slot_selectors: [true, false, false, false],
        };
    }

    let inline_ciphertexts = SmallwoodPoseidon2V8InlineCiphertexts {
        ciphertexts: [
            Some(*RETAINED_V8_OUTPUT_0_RAW),
            Some(*RETAINED_V8_OUTPUT_1_RAW),
        ],
    };
    for output in 0..2 {
        statement.ciphertext_commitments[output] = smallwood_poseidon2_v8_ciphertext_commitment(
            inline_ciphertexts.ciphertexts[output]
                .as_ref()
                .expect("maximum-shape output is active"),
        );
    }

    // SingleKey mode ties every active input authorization key to the one
    // transaction PRF.  Cross-check the supplied seed/coinbase openings rather
    // than rewriting them: the proof must spend exactly those openings.
    let transaction_prf =
        build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness)?.calls[0].final_digest();
    for input in 0..2 {
        if witness.inputs[input].note.authorization_key != transaction_prf[1..5] {
            return Err(runner_error(format!(
                "supplied input note {input} does not authorize the retained spend key"
            )));
        }
    }

    // Place the supplied source notes at positions zero and one under the
    // canonical empty-tree frontier.  This is the exact state transition used
    // when the first two V8 coinbase commitments are appended in block order.
    let preliminary = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness)?;
    let scheduled_commitments = [
        preliminary.calls[INPUT_0_NOTE_FINAL].final_digest(),
        preliminary.calls[INPUT_1_NOTE_FINAL].final_digest(),
    ];
    let direct_commitments = [
        note_commitment(input_notes[0])?,
        note_commitment(input_notes[1])?,
    ];
    if scheduled_commitments != direct_commitments {
        return Err(runner_error(
            "supplied input note commitments disagree with the executable hash schedule",
        ));
    }
    let frontier = canonical_two_note_frontier(direct_commitments);
    witness.inputs[0].siblings = frontier.paths[0];
    witness.inputs[1].siblings = frontier.paths[1];

    let rooted = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness)?;
    let root0 = rooted.calls[INPUT_0_ROOT_FINAL].final_digest();
    let root1 = rooted.calls[INPUT_1_ROOT_FINAL].final_digest();
    if root0 != root1 || root0 != frontier.root {
        return Err(runner_error(
            "maximum-shape canonical position-zero/one Merkle paths did not converge",
        ));
    }
    statement.merkle_root = frontier.root;

    let public_hashes = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness)?;
    statement.nullifiers[0] = public_hashes.calls[INPUT_0_NULLIFIER_FINAL].final_digest();
    statement.nullifiers[1] = public_hashes.calls[INPUT_1_NULLIFIER_FINAL].final_digest();
    statement.commitments[0] = public_hashes.calls[OUTPUT_0_NOTE_FINAL].final_digest();
    statement.commitments[1] = public_hashes.calls[OUTPUT_1_NOTE_FINAL].final_digest();

    witness
        .validate_against_statement(&statement)
        .map_err(|error| runner_error(format!("maximum-shape fixture is invalid: {error:?}")))?;
    inline_ciphertexts
        .validate_against_statement(&statement)
        .map_err(|error| runner_error(format!("inline ciphertext binding failed: {error:?}")))?;
    Ok((statement, witness, inline_ciphertexts))
}

fn maximum_shape_fixture() -> RunnerResult<(
    SmallwoodPoseidon2V8PublicStatement,
    SmallwoodPoseidon2V8Witness,
    SmallwoodPoseidon2V8InlineCiphertexts,
)> {
    maximum_shape_fixture_from_input_notes(
        retained_coinbase_note_openings()?,
        RETAINED_SPEND_PARENT_HEIGHT,
    )
}

fn digest_hex(words: &SmallwoodPoseidon2V8Digest) -> String {
    hex::encode(words_to_bytes(words))
}

fn merkle_path_bytes(
    path: &[SmallwoodPoseidon2V8Digest; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH * 7 * 8);
    for sibling in path {
        bytes.extend_from_slice(&words_to_bytes(sibling));
    }
    bytes
}

fn fixture_descriptor(
    artifact_role: &str,
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
    inline_ciphertexts: &SmallwoodPoseidon2V8InlineCiphertexts,
) -> RunnerResult<Value> {
    ensure_artifact_role(artifact_role)?;
    let witness_definition_sha512 = sha512_hex(&witness.to_witness_bytes());
    let base = json!({
        "activity_mask": statement.activity_mask(),
        "authorization_mode": "SingleKey",
        "active_inputs": statement.input_flags.iter().filter(|active| **active).count(),
        "active_outputs": statement.output_flags.iter().filter(|active| **active).count(),
        "ciphertext_bytes_per_output": SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES,
        "inline_ciphertext_bytes": inline_ciphertexts.encoded_len(),
        "fee": statement.fee,
        "parent_height": statement.stablecoin.parent_height,
        "stablecoin_root_hex": hex::encode(
            words_to_bytes(&statement.stablecoin.before_root.map(|value| value.as_canonical_u64()))
        ),
        "merkle_root_hex": digest_hex(&statement.merkle_root),
        "synthetic_fixture_witness_definition_sha512": witness_definition_sha512,
        "retains_private_witness": false,
        "artifact_alone_authorizes_production": false,
    });
    let mut descriptor = base
        .as_object()
        .cloned()
        .ok_or_else(|| runner_error("fixture descriptor base is not an object"))?;

    if artifact_role == RETAINED_LIFECYCLE_SEED {
        let notes = retained_zero_value_seed_note_openings()?;
        let commitments = [note_commitment(notes[0])?, note_commitment(notes[1])?];
        let frontier = canonical_two_note_frontier(commitments);
        if statement.commitments != commitments
            || statement.input_flags != [false, false]
            || statement.output_flags != [true, true]
            || statement.merkle_root != [0; 7]
            || statement.stablecoin.parent_height != RETAINED_SEED_PARENT_HEIGHT
        {
            return Err(runner_error(
                "zero-value lifecycle seed fixture differs from its canonical source definition",
            ));
        }
        descriptor.insert(
            "kind".to_owned(),
            json!("zero_input_two_output_zero_value_seed"),
        );
        descriptor.insert(
            "fixture_group".to_owned(),
            json!(RETAINED_ZERO_SEED_FIXTURE_GROUP),
        );
        descriptor.insert(
            "economic_value_source".to_owned(),
            json!("none_zero_value_diagnostic"),
        );
        descriptor.insert("economic_production_evidence".to_owned(), json!(false));
        descriptor.insert("input_positions".to_owned(), json!([]));
        descriptor.insert(
            "output_commitments_hex".to_owned(),
            json!(commitments.map(|commitment| digest_hex(&commitment))),
        );
        descriptor.insert(
            "resulting_note_root_hex".to_owned(),
            json!(digest_hex(&frontier.root)),
        );
    } else {
        let public_openings = retained_coinbase_public_openings()?;
        let notes = retained_coinbase_note_openings()?;
        let commitments = [note_commitment(notes[0])?, note_commitment(notes[1])?];
        let frontier = canonical_two_note_frontier(commitments);
        if statement.input_flags != [true, true]
            || statement.output_flags != [true, true]
            || statement.merkle_root != frontier.root
            || witness.inputs[0].position != 0
            || witness.inputs[1].position != 1
            || witness.inputs[0].note != notes[0]
            || witness.inputs[1].note != notes[1]
            || witness.inputs[0].siblings != frontier.paths[0]
            || witness.inputs[1].siblings != frontier.paths[1]
            || statement.stablecoin.parent_height != RETAINED_SPEND_PARENT_HEIGHT
            || statement.stablecoin.before_root != RETAINED_STABLECOIN_ROOT
            || statement.stablecoin.after_root != RETAINED_STABLECOIN_ROOT
        {
            return Err(runner_error(
                "retained coinbase spend fixture differs from its canonical source definition",
            ));
        }
        descriptor.insert(
            "kind".to_owned(),
            json!("two_input_two_output_coinbase_spend"),
        );
        descriptor.insert(
            "fixture_group".to_owned(),
            json!(RETAINED_SPEND_FIXTURE_GROUP),
        );
        descriptor.insert(
            "economic_value_source".to_owned(),
            json!("v8_coinbase_action_11"),
        );
        descriptor.insert("economic_production_evidence".to_owned(), json!(false));
        descriptor.insert(
            "requires_live_coinbase_carrier_lifecycle".to_owned(),
            json!(true),
        );
        descriptor.insert("input_positions".to_owned(), json!([0, 1]));
        descriptor.insert("input_values".to_owned(), json!(RETAINED_COINBASE_AMOUNTS));
        descriptor.insert(
            "coinbase_opening_words_sha512".to_owned(),
            json!(public_openings
                .map(|opening| sha512_hex(&words_to_bytes(&opening.note_hash_words())))),
        );
        descriptor.insert(
            "input_note_commitments_hex".to_owned(),
            json!(commitments.map(|commitment| digest_hex(&commitment))),
        );
        descriptor.insert(
            "input_merkle_path_sha512".to_owned(),
            json!(frontier
                .paths
                .map(|path| sha512_hex(&merkle_path_bytes(&path)))),
        );
        descriptor.insert(
            "canonical_empty_note_root_hex".to_owned(),
            json!(digest_hex(
                canonical_empty_note_nodes()
                    .last()
                    .expect("depth-32 default-node array is nonempty")
            )),
        );
    }
    Ok(Value::Object(descriptor))
}

fn fixture_for_artifact_role(
    artifact_role: &str,
) -> RunnerResult<(
    SmallwoodPoseidon2V8PublicStatement,
    SmallwoodPoseidon2V8Witness,
    SmallwoodPoseidon2V8InlineCiphertexts,
)> {
    ensure_artifact_role(artifact_role)?;
    if artifact_role == RETAINED_LIFECYCLE_SEED {
        retained_lifecycle_seed_fixture()
    } else {
        maximum_shape_fixture()
    }
}

struct Projection {
    statement: SmallwoodPoseidon2V8PublicStatement,
    witness: SmallwoodPoseidon2V8Witness,
    inline_ciphertexts: SmallwoodPoseidon2V8InlineCiphertexts,
    relation_program: Vec<u8>,
    projected_proof_bytes: usize,
    projected_scale_inline_args_bytes: usize,
    projected_rpc_envelope_bytes: usize,
    projected_pending_action_bytes: usize,
    geometry: Value,
    fixture: Value,
    relation_mutations: Vec<Value>,
}

fn reject_relation_mutations(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    adapter: &SmallwoodPoseidon2V8ConstraintAdapter,
    witness_values: &[u64],
) -> RunnerResult<Vec<Value>> {
    let mut results = Vec::new();
    let mut private_row = witness_values.to_vec();
    private_row[0] ^= 1;
    let rejected = adapter.verify_packed_witness(&private_row).is_err();
    results.push(json!({"name": "private_row", "rejected": rejected}));

    let mut hash_initial = witness_values.to_vec();
    let relative = smallwood_poseidon2_v8_hash_call_initial_witness_index(0, 0);
    let index =
        SMALLWOOD_POSEIDON2_V8_HASH_ROW_START * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR + relative;
    hash_initial[index] ^= 1;
    let hash_rejected = adapter.verify_packed_witness(&hash_initial).is_err();
    results.push(json!({"name": "hash_initial", "rejected": hash_rejected}));

    let mut changed_public = *statement;
    changed_public.ciphertext_commitments[0][0] ^= 1;
    let changed_adapter =
        SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&changed_public)?;
    let public_rejected = changed_adapter
        .verify_packed_witness(witness_values)
        .is_err();
    results.push(json!({"name": "public_ciphertext_commitment", "rejected": public_rejected}));

    if results
        .iter()
        .any(|result| result["rejected"] != Value::Bool(true))
    {
        return Err(runner_error("an executable-relation mutation was accepted"));
    }
    Ok(results)
}

fn project_for_artifact_role(artifact_role: &str) -> RunnerResult<Projection> {
    ensure_frozen_identity_constants()?;
    ensure_artifact_role(artifact_role)?;
    let (statement, witness, inline_ciphertexts) = fixture_for_artifact_role(artifact_role)?;
    let fixture = fixture_descriptor(artifact_role, &statement, &witness, &inline_ciphertexts)?;
    let relation_program = validated_relation_program()?;
    let lowered = compile_smallwood_poseidon2_v8_relation(&statement, &witness)?;
    lowered
        .adapter
        .verify_packed_witness(&lowered.witness_values)?;
    let relation_mutations =
        reject_relation_mutations(&statement, &lowered.adapter, &lowered.witness_values)?;
    let projected_proof_bytes = project_smallwood_poseidon2_v8_candidate_bytes(&lowered.adapter)?;
    let projected_scale_inline_args_bytes = smallwood_poseidon2_v8_exact_action_bytes(
        lowered.adapter.public_values(),
        projected_proof_bytes,
    )?;
    let projected_rpc_envelope_bytes = projected_scale_inline_args_bytes
        .checked_sub(4)
        .ok_or_else(|| runner_error("projected SCALE inline arguments omitted their prefix"))?;
    let projected_pending_action_bytes = projected_scale_inline_args_bytes
        .checked_add(SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES)
        .ok_or_else(|| runner_error("projected PendingAction byte count overflowed"))?;
    let geometry = lowered.adapter.geometry();
    let geometry_json = json!({
        "public_words": geometry.public_words,
        "relation_balance_limbs": geometry.relation_balance_limbs,
        "witness_rows": geometry.witness_rows,
        "packing_factor": geometry.packing_factor,
        "packed_witness_words": geometry.packed_witness_words,
        "constraint_degree": geometry.constraint_degree,
        "nonlinear_constraints": geometry.nonlinear_constraints,
        "linear_constraints": geometry.linear_constraints,
        "auxiliary_words": geometry.auxiliary_words,
        "hash_calls": geometry.hash_calls,
    });
    if projected_proof_bytes != EXPECTED_PROJECTED_PROOF_BYTES
        || projected_scale_inline_args_bytes != EXPECTED_PROJECTED_SCALE_INLINE_ARGS_BYTES
        || projected_rpc_envelope_bytes != EXPECTED_PROJECTED_RPC_ENVELOPE_BYTES
        || projected_pending_action_bytes != EXPECTED_PROJECTED_PENDING_ACTION_BYTES
        || projected_pending_action_bytes != SMALLWOOD_POSEIDON2_V8_PROJECTED_PENDING_ACTION_BYTES
    {
        return Err(runner_error(format!(
            "V8 frozen byte projection drifted: proof={projected_proof_bytes} (expected {EXPECTED_PROJECTED_PROOF_BYTES}), envelope={projected_rpc_envelope_bytes} (expected {EXPECTED_PROJECTED_RPC_ENVELOPE_BYTES}), inline_args={projected_scale_inline_args_bytes} (expected {EXPECTED_PROJECTED_SCALE_INLINE_ARGS_BYTES}), pending_action={projected_pending_action_bytes} (expected {EXPECTED_PROJECTED_PENDING_ACTION_BYTES})"
        )));
    }
    if projected_scale_inline_args_bytes > POSEIDON2_PRODUCTION_MAX_ACTION_BYTES
        || projected_rpc_envelope_bytes > POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES
        || projected_pending_action_bytes > SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES
    {
        return Err(runner_error(
            "V8 projected carrier exceeds a source-owned cap",
        ));
    }
    Ok(Projection {
        statement,
        witness,
        inline_ciphertexts,
        relation_program,
        projected_proof_bytes,
        projected_scale_inline_args_bytes,
        projected_rpc_envelope_bytes,
        projected_pending_action_bytes,
        geometry: geometry_json,
        fixture,
        relation_mutations,
    })
}

fn sha512_hex(bytes: &[u8]) -> String {
    hex::encode(Sha512::digest(bytes))
}

fn words_to_bytes(words: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 8);
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn mutation_result(name: &str, input: &SmallwoodPoseidon2V8VerifierInput, proof: &[u8]) -> Value {
    match verify_smallwood_poseidon2_v8_candidate(input, proof) {
        Ok(()) => json!({"name": name, "rejected": false, "error": null}),
        Err(error) => json!({
            "name": name,
            "rejected": true,
            "error": error.to_string(),
        }),
    }
}

fn reject_proof_and_input_mutations(
    input: &SmallwoodPoseidon2V8VerifierInput,
    proof: &[u8],
) -> RunnerResult<Vec<Value>> {
    if proof.len() < 8 {
        return Err(runner_error("SMZ9 proof is unexpectedly short"));
    }
    let mut results = Vec::new();

    let mut magic = proof.to_vec();
    magic[0] ^= 1;
    results.push(mutation_result("proof_magic", input, &magic));

    let mut middle = proof.to_vec();
    let middle_index = middle.len() / 2;
    middle[middle_index] ^= 1;
    results.push(mutation_result("proof_middle", input, &middle));

    results.push(mutation_result(
        "proof_truncated",
        input,
        &proof[..proof.len() - 1],
    ));

    let mut trailing = proof.to_vec();
    trailing.push(0);
    results.push(mutation_result("proof_trailing_byte", input, &trailing));

    let mut network = input.clone();
    network.network_id ^= 1;
    results.push(mutation_result("network_id", &network, proof));

    let mut relation_digest = input.clone();
    relation_digest.relation_digest[0] ^= 1;
    results.push(mutation_result("relation_digest", &relation_digest, proof));

    let mut public = input.clone();
    public.public_values[44] = public.public_values[44].wrapping_add(1);
    results.push(mutation_result("public_fee", &public, proof));

    let mut balance_binding = input.clone();
    balance_binding.relation_balance_binding[0] ^= 1;
    results.push(mutation_result(
        "relation_balance_binding",
        &balance_binding,
        proof,
    ));

    if results
        .iter()
        .any(|result| result["rejected"] != Value::Bool(true))
    {
        return Err(runner_error(
            "a proof or verifier-input mutation was accepted",
        ));
    }
    Ok(results)
}

fn honest_map_audit(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    transcript_preamble: &[u8],
    proof: &[u8],
) -> RunnerResult<Value> {
    let adapter = SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(statement)?;
    let refinement = validate_accepted_smallwood_poseidon2_v8_smz9_refinement_v1(
        &adapter,
        transcript_preamble,
        proof,
    )?;
    let audit = refinement.honest_map_audit;
    if !audit.exact_square_full_rank_decomposition() {
        return Err(runner_error(
            "SMZ9 honest-map audit is not exact square and full rank",
        ));
    }
    Ok(json!({
        "accepted_proof_refinement_schema": refinement.schema,
        "lean_wire_model": refinement.lean_wire_model,
        "proof_bytes": refinement.proof_bytes,
        "proof_sha512": refinement.proof_sha512_hex,
        "canonical_decode_reencode_exact": refinement.canonical_decode_reencode_exact,
        "verifier_trace_replay_exact": refinement.verifier_trace_replay_exact,
        "production_verifier_accepts": refinement.production_verifier_accepts,
        "auxiliary_witness_words": refinement.auxiliary_witness_words,
        "auxiliary_witness_limbs": refinement.auxiliary_witness_limbs,
        "external_sha512_qrom_claim": refinement.external_sha512_qrom_claim,
        "external_poseidon2_security_claim": refinement.external_poseidon2_security_claim,
        "production_eligible": refinement.production_eligible,
        "exact_square_full_rank": true,
        "witness_interpolation_coin_count": audit.witness_interpolation_coin_count,
        "witness_opening_view_count": audit.witness_opening_view_count,
        "witness_interpolation_rank": audit.witness_interpolation_rank,
        "pcs_unstack_coin_count": audit.pcs_unstack_coin_count,
        "pcs_partial_view_count": audit.pcs_partial_view_count,
        "pcs_unstack_block_count": audit.pcs_unstack_block_count,
        "pcs_unstack_min_block_rank": audit.pcs_unstack_min_block_rank,
        "pcs_unstack_total_rank": audit.pcs_unstack_total_rank,
        "nonlinear_piop_coin_count": audit.nonlinear_piop_coin_count,
        "nonlinear_piop_view_count": audit.nonlinear_piop_view_count,
        "nonlinear_piop_low_rank": audit.nonlinear_piop_low_rank,
        "linear_piop_coin_count": audit.linear_piop_coin_count,
        "linear_piop_view_count": audit.linear_piop_view_count,
        "linear_piop_low_rank": audit.linear_piop_low_rank,
        "lvcs_tail_coin_count": audit.lvcs_tail_coin_count,
        "lvcs_joint_view_count": audit.lvcs_joint_view_count,
        "lvcs_tail_evaluation_rank": audit.lvcs_tail_evaluation_rank,
        "lvcs_selected_combination_rank": audit.lvcs_selected_combination_rank,
        "decs_mask_coin_count": audit.decs_mask_coin_count,
        "decs_evaluation_high_view_count": audit.decs_evaluation_high_view_count,
        "decs_low_coefficient_rank": audit.decs_low_coefficient_rank,
    }))
}

fn proof_randomness_binding(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    transcript_preamble: &[u8],
    proof: &[u8],
) -> RunnerResult<Value> {
    let adapter = SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(statement)?;
    let trace =
        build_smallwood_poseidon2_v8_smz9_verifier_trace_v1(&adapter, transcript_preamble, proof)?;
    if !trace.accept || trace.proof.salt == [0; 32] || trace.pcs_trace.root_digest == [0; 64] {
        return Err(runner_error(
            "accepted SMZ9 proof has an invalid salt or transcript commitment root",
        ));
    }
    Ok(json!({
        "wire_salt_hex": hex::encode(trace.proof.salt),
        "decs_transcript_root_hex": hex::encode(trace.pcs_trace.root_digest),
    }))
}

fn current_verifier_provenance(source_inventory_root_sha512: &str) -> RunnerResult<Value> {
    let (binary_bytes, binary_sha512) = sha512_file(&env::current_exe()?)?;
    let rustc = Command::new("rustc").arg("-vV").output()?;
    if !rustc.status.success() {
        return Err(runner_error(format!(
            "failed to obtain verifier rustc provenance: {}",
            String::from_utf8_lossy(&rustc.stderr).trim()
        )));
    }
    Ok(json!({
        "schema": VERIFIER_PROVENANCE_SCHEMA,
        "binary_bytes": binary_bytes,
        "binary_sha512": binary_sha512,
        "target_os": env::consts::OS,
        "target_arch": env::consts::ARCH,
        "rustc_verbose_sha512": sha512_hex(&rustc.stdout),
        "source_inventory_root_sha512": source_inventory_root_sha512,
        "generator_binary_equality_required": false,
    }))
}

fn ensure_native_leaf_matches_verifier_files(
    expected: Poseidon2ProductionExpectedContext,
    native_leaf: &[u8],
    statement_bytes: &[u8],
    relation_binding_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> RunnerResult<()> {
    let decoded = decode_poseidon2_production_smz9_native_leaf_exact(expected, native_leaf)?;
    let mut carried_ciphertexts = Vec::new();
    for slot in 0..2 {
        if let Some(ciphertext) = decoded.ciphertext(slot) {
            carried_ciphertexts.extend_from_slice(ciphertext);
        }
    }
    if decoded.statement_bytes().as_slice() != statement_bytes
        || decoded.relation_balance_binding_bytes().as_slice() != relation_binding_bytes
        || carried_ciphertexts != ciphertext_bytes
    {
        return Err(runner_error(
            "native leaf statement, relation binding, or ciphertexts differ from verifier files",
        ));
    }
    Ok(())
}

fn canonical_rewrap_rejected_at_verifier_file_seam(
    expected: Poseidon2ProductionExpectedContext,
    native_leaf: &[u8],
    statement_bytes: &[u8],
    relation_binding_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> RunnerResult<bool> {
    let envelope = encode_poseidon2_production_smz9_envelope(expected, native_leaf)?;
    let inline_args = encode_poseidon2_production_smz9_inline_args(expected, &envelope)?;
    let pending_action = encode_poseidon2_v8_pending_action_artifact(NETWORK_ID, &inline_args)?;
    verify_poseidon2_v8_pending_action_artifact_exact(
        NETWORK_ID,
        &inline_args,
        &pending_action.encoded_pending_action,
    )?;
    Ok(ensure_native_leaf_matches_verifier_files(
        expected,
        native_leaf,
        statement_bytes,
        relation_binding_bytes,
        ciphertext_bytes,
    )
    .is_err())
}

fn reject_transport_mutations(
    expected: Poseidon2ProductionExpectedContext,
    native_leaf: &[u8],
    envelope: &[u8],
    inline_args: &[u8],
    statement_bytes: &[u8],
    relation_binding_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> RunnerResult<Vec<Value>> {
    let mut results = Vec::new();

    let mut leaf_magic = native_leaf.to_vec();
    leaf_magic[0] ^= 1;
    results.push(json!({
        "name": "native_leaf_magic",
        "rejected": decode_poseidon2_production_smz9_native_leaf_exact(expected, &leaf_magic).is_err(),
    }));

    let mut leaf_proof_length = native_leaf.to_vec();
    leaf_proof_length[32] ^= 1;
    results.push(json!({
        "name": "native_leaf_proof_length",
        "rejected": decode_poseidon2_production_smz9_native_leaf_exact(expected, &leaf_proof_length).is_err(),
    }));

    let mut envelope_magic = envelope.to_vec();
    envelope_magic[0] ^= 1;
    results.push(json!({
        "name": "rpc_envelope_magic",
        "rejected": decode_poseidon2_production_smz9_envelope_exact(expected, &envelope_magic).is_err(),
    }));

    let mut inline_scale_prefix = inline_args.to_vec();
    inline_scale_prefix[0] ^= 4;
    results.push(json!({
        "name": "scale_compact_length",
        "rejected": decode_poseidon2_production_smz9_inline_args_exact(expected, &inline_scale_prefix).is_err(),
    }));

    let mut inline_trailing = inline_args.to_vec();
    inline_trailing.push(0);
    results.push(json!({
        "name": "scale_inline_trailing_byte",
        "rejected": decode_poseidon2_production_smz9_inline_args_exact(expected, &inline_trailing).is_err(),
    }));

    let decoded = decode_poseidon2_production_smz9_native_leaf_exact(expected, native_leaf)?;
    let mut public_values = core::array::from_fn(|index| {
        decoded
            .statement_word(index)
            .expect("decoded native leaf fixes the statement word count")
    });
    let relation_binding = core::array::from_fn(|index| {
        decoded
            .relation_balance_binding_limb(index)
            .expect("decoded native leaf fixes the relation-binding limb count")
    });
    let ciphertexts = [decoded.ciphertext(0), decoded.ciphertext(1)];
    public_values[44] = public_values[44].wrapping_add(1);
    let statement_rewrap = encode_poseidon2_production_smz9_native_leaf(
        expected,
        &public_values,
        &relation_binding,
        ciphertexts,
        decoded.proof(),
    )?;
    results.push(json!({
        "name": "native_leaf_statement_rewrap",
        "rejected": canonical_rewrap_rejected_at_verifier_file_seam(
            expected,
            &statement_rewrap,
            statement_bytes,
            relation_binding_bytes,
            ciphertext_bytes,
        )?,
    }));

    public_values[44] = public_values[44].wrapping_sub(1);
    let mut changed_relation_binding = relation_binding;
    changed_relation_binding[0] ^= 1;
    let binding_rewrap = encode_poseidon2_production_smz9_native_leaf(
        expected,
        &public_values,
        &changed_relation_binding,
        ciphertexts,
        decoded.proof(),
    )?;
    results.push(json!({
        "name": "native_leaf_relation_binding_rewrap",
        "rejected": canonical_rewrap_rejected_at_verifier_file_seam(
            expected,
            &binding_rewrap,
            statement_bytes,
            relation_binding_bytes,
            ciphertext_bytes,
        )?,
    }));

    if results
        .iter()
        .any(|result| result["rejected"] != Value::Bool(true))
    {
        return Err(runner_error("a canonical transport mutation was accepted"));
    }
    Ok(results)
}

fn transport_parser_stage_checks(
    expected: Poseidon2ProductionExpectedContext,
    envelope: &[u8],
    inline_args: &[u8],
) -> RunnerResult<Vec<Value>> {
    let stages = [
        Poseidon2ProductionTransportStage::Wallet,
        Poseidon2ProductionTransportStage::Rpc,
        Poseidon2ProductionTransportStage::Relay,
        Poseidon2ProductionTransportStage::Mempool,
        Poseidon2ProductionTransportStage::Mining,
        Poseidon2ProductionTransportStage::Block,
        Poseidon2ProductionTransportStage::Restart,
        Poseidon2ProductionTransportStage::Sync,
        Poseidon2ProductionTransportStage::Reorg,
        Poseidon2ProductionTransportStage::FreshNodeVerify,
    ];
    let mut results = Vec::with_capacity(stages.len());
    for stage in stages {
        ensure_poseidon2_production_smz9_stage_bytes(expected, envelope, inline_args, stage)?;
        results.push(json!({"stage": stage.label(), "exact_bytes": true}));
    }
    Ok(results)
}

fn node_pending_action_lifecycle(
    readback: &Poseidon2V8PendingActionArtifactReadback,
    encoded_pending_action: &[u8],
    exact_inline_args: &[u8],
    exact_proof: &[u8],
) -> RunnerResult<Value> {
    if readback.network_id != NETWORK_ID
        || readback.relation_digest != SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST
        || readback.binding_circuit != CIRCUIT_V8
        || readback.binding_crypto != CRYPTO_SUITE_ETA
        || readback.family_id != FAMILY_SHIELDED_POOL
        || readback.action_id != SMALLWOOD_POSEIDON2_V8_ACTION_ID
        || readback.active_outputs != 2
        || !readback.transport_reencoded_exactly
        || !readback.candidate_artifact_absent
        || readback.production_authorized
    {
        return Err(runner_error(
            "typed PendingAction readback identity or authority boundary drifted",
        ));
    }
    let encoded_size_matches = readback.encoded_pending_action_bytes
        == encoded_pending_action.len()
        && readback.inline_args_bytes == exact_inline_args.len()
        && readback.proof_bytes == exact_proof.len()
        && readback.outer_overhead_bytes
            == encoded_pending_action
                .len()
                .checked_sub(exact_inline_args.len())
                .ok_or_else(|| {
                    runner_error("PendingAction is shorter than its inline arguments")
                })?;
    let lifecycle = json!({
        "constructed_from_exact_scale_inline_args": true,
        "canonical_scale_decode": true,
        "canonical_reencode_equal": readback.pending_action_reencoded_exactly,
        "public_args_byte_identical": readback.public_args_preserved_exactly,
        "tx_hash_recomputed": readback.transaction_hash_exact,
        "route_tuple_matches": readback.route_fields_exact,
        "no_legacy_outer_state": readback.legacy_state_absent,
        "encoded_size_matches": encoded_size_matches,
        "same_smz9_proof_bytes": readback.proof_preserved_exactly,
    });
    if lifecycle
        .as_object()
        .ok_or_else(|| runner_error("PendingAction lifecycle report is not an object"))?
        .values()
        .any(|value| value != &Value::Bool(true))
    {
        return Err(runner_error(
            "canonical PendingAction lifecycle evidence is incomplete",
        ));
    }
    Ok(lifecycle)
}

fn reject_pending_action_mutations(
    network_id: u32,
    exact_inline_args: &[u8],
    encoded_pending_action: &[u8],
) -> RunnerResult<Vec<Value>> {
    let receipts = audit_poseidon2_v8_pending_action_artifact_mutations_v1(
        network_id,
        exact_inline_args,
        encoded_pending_action,
    )?;
    let results = receipts
        .into_iter()
        .map(|receipt| json!({"name": receipt.name, "rejected": receipt.rejected}))
        .collect::<Vec<_>>();
    if results.len() != 15
        || results
            .iter()
            .any(|result| result["rejected"] != Value::Bool(true))
    {
        return Err(runner_error(
            "a canonical PendingAction outer-field mutation was accepted",
        ));
    }
    Ok(results)
}

fn write_new(path: &Path, bytes: &[u8]) -> RunnerResult<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn publish_relation_program(path: &Path) -> RunnerResult<Value> {
    let bytes = validated_relation_program()?;
    if path.exists() {
        if !fs::symlink_metadata(path)?.file_type().is_file() {
            return Err(runner_error(format!(
                "relation program path {} is not a regular file",
                path.display()
            )));
        }
        if fs::read(path)? != bytes {
            return Err(runner_error(format!(
                "refusing to overwrite noncanonical relation program {}",
                path.display()
            )));
        }
    } else {
        let parent = path.parent().ok_or_else(|| {
            runner_error(format!(
                "relation program path {} has no parent",
                path.display()
            ))
        })?;
        fs::create_dir_all(parent)?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| runner_error("relation program path has no UTF-8 file name"))?;
        let staging = parent.join(format!(".{file_name}.staging-{}", std::process::id()));
        write_new(&staging, &bytes)?;
        fs::rename(&staging, path)?;
        File::open(parent)?.sync_all()?;
    }
    Ok(json!({
        "path": path,
        "bytes": bytes.len(),
        "magic": PROGRAM_MAGIC_ASCII,
        "sha512": sha512_hex(&bytes),
        "relation_id": hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST),
        "semantic_relation": SMALLWOOD_POSEIDON2_V8_RELATION_ID,
    }))
}

const RETAINED_ARTIFACT_FILE_LIMITS: [(&str, usize); 14] = [
    ("artifact-report.json", 1_048_576),
    ("parent-artifact-report-v4.json", 1_048_576),
    ("proof.bin", 131_072),
    ("public-statement.bin", 960),
    ("ciphertexts.bin", 4_294),
    ("network-id.bin", 4),
    ("relation-digest.bin", 48),
    ("relation-binding.bin", 56),
    (
        "relation-program.bin",
        SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES,
    ),
    ("transcript-preamble.bin", 1_104),
    ("native-leaf.bin", 131_072),
    ("rpc-envelope.bin", POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES),
    (
        "scale-inline-args.bin",
        POSEIDON2_PRODUCTION_MAX_ACTION_BYTES,
    ),
    (
        "pending-action.bin",
        SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES,
    ),
];

struct RetainedArtifactSnapshot {
    files: BTreeMap<&'static str, Vec<u8>>,
}

impl RetainedArtifactSnapshot {
    fn get(&self, name: &'static str) -> RunnerResult<&[u8]> {
        self.files
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| runner_error(format!("artifact snapshot omitted {name}")))
    }
}

fn ensure_no_symlink_path_components(path: &Path) -> RunnerResult<()> {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(runner_error(
                    "artifact directory path must not contain parent traversal",
                ));
            }
            _ => cursor.push(component.as_os_str()),
        }
        let metadata = fs::symlink_metadata(&cursor)?;
        if metadata.file_type().is_symlink() {
            return Err(runner_error(format!(
                "artifact path component {} is a symlink",
                cursor.display()
            )));
        }
    }
    Ok(())
}

fn read_retained_artifact_snapshot(directory: &Path) -> RunnerResult<RetainedArtifactSnapshot> {
    ensure_no_symlink_path_components(directory)?;
    let directory_metadata = fs::symlink_metadata(directory)?;
    if !directory_metadata.file_type().is_dir() {
        return Err(runner_error(format!(
            "artifact path {} is not a directory",
            directory.display()
        )));
    }

    let final_expected = RETAINED_ARTIFACT_FILE_LIMITS
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    let legacy_expected = final_expected
        .iter()
        .cloned()
        .filter(|name| name != "parent-artifact-report-v4.json")
        .collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| runner_error("artifact contains a non-UTF-8 file name"))?;
        if !final_expected.contains(name.as_str()) {
            return Err(runner_error(format!(
                "artifact contains unexpected entry {name}"
            )));
        }
        if !entry.file_type()?.is_file() {
            return Err(runner_error(format!(
                "artifact entry {name} is not a regular file"
            )));
        }
        if !observed.insert(name) {
            return Err(runner_error("artifact contains a duplicate file name"));
        }
    }
    if observed != final_expected && observed != legacy_expected {
        return Err(runner_error("artifact file inventory is incomplete"));
    }

    let mut files = BTreeMap::new();
    for (name, maximum) in RETAINED_ARTIFACT_FILE_LIMITS {
        if !observed.contains(name) {
            continue;
        }
        let path = directory.join(name);
        let path_metadata_before = fs::symlink_metadata(&path)?;
        if !path_metadata_before.file_type().is_file() {
            return Err(runner_error(format!(
                "artifact entry {name} is not a regular file"
            )));
        }
        if path_metadata_before.len() > maximum as u64 {
            return Err(runner_error(format!(
                "artifact entry {name} exceeds its {maximum}-byte allocation cap"
            )));
        }
        let mut file = File::open(&path)?;
        let opened_metadata = file.metadata()?;
        if !opened_metadata.is_file() || opened_metadata.len() != path_metadata_before.len() {
            return Err(runner_error(format!(
                "artifact entry {name} changed before descriptor snapshot"
            )));
        }
        #[cfg(unix)]
        if opened_metadata.dev() != path_metadata_before.dev()
            || opened_metadata.ino() != path_metadata_before.ino()
        {
            return Err(runner_error(format!(
                "artifact entry {name} changed identity before descriptor snapshot"
            )));
        }
        let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
        Read::by_ref(&mut file)
            .take((maximum as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > maximum || bytes.len() as u64 != opened_metadata.len() {
            return Err(runner_error(format!(
                "artifact entry {name} changed size during descriptor snapshot"
            )));
        }
        let path_metadata_after = fs::symlink_metadata(&path)?;
        if !path_metadata_after.file_type().is_file()
            || path_metadata_after.len() != opened_metadata.len()
        {
            return Err(runner_error(format!(
                "artifact entry {name} changed after descriptor snapshot"
            )));
        }
        #[cfg(unix)]
        if opened_metadata.dev() != path_metadata_after.dev()
            || opened_metadata.ino() != path_metadata_after.ino()
        {
            return Err(runner_error(format!(
                "artifact entry {name} changed identity after descriptor snapshot"
            )));
        }
        files.insert(name, bytes);
    }
    Ok(RetainedArtifactSnapshot { files })
}

fn read_fixed<const N: usize>(label: &str, bytes: &[u8]) -> RunnerResult<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| runner_error(format!("{label} has {} bytes, expected {N}", bytes.len())))
}

fn read_words(label: &str, bytes: &[u8], count: usize) -> RunnerResult<Vec<u64>> {
    if bytes.len() != count * 8 {
        return Err(runner_error(format!(
            "{label} has {} bytes, expected {}",
            bytes.len(),
            count * 8
        )));
    }
    Ok(bytes
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk")))
        .collect())
}

fn manifest_string<'a>(manifest: &'a Value, section: &str, name: &str) -> RunnerResult<&'a str> {
    manifest[section][name]
        .as_str()
        .ok_or_else(|| runner_error(format!("artifact report is missing {section}.{name}")))
}

fn manifest_usize(manifest: &Value, section: &str, name: &str) -> RunnerResult<usize> {
    let value = manifest[section][name]
        .as_u64()
        .ok_or_else(|| runner_error(format!("artifact report is missing {section}.{name}")))?;
    usize::try_from(value).map_err(|_| {
        runner_error(format!(
            "artifact report {section}.{name} does not fit usize"
        ))
    })
}

fn ensure_manifest_hash(manifest: &Value, name: &str, bytes: &[u8]) -> RunnerResult<()> {
    let expected = manifest_string(manifest, "sha512", name)?;
    let observed = sha512_hex(bytes);
    if observed != expected {
        return Err(runner_error(format!(
            "artifact SHA-512 mismatch for {name}: observed {observed}, expected {expected}"
        )));
    }
    Ok(())
}

fn verify_v5_provenance_transition(
    manifest: &Value,
    snapshot: &RetainedArtifactSnapshot,
    artifact_role: &str,
    proof_sha512: &str,
    source_inventory: &ProofSourceInventory,
) -> RunnerResult<()> {
    let transition = manifest["provenance_transition"]
        .as_object()
        .ok_or_else(|| runner_error("v5 artifact omitted provenance_transition"))?;
    let expected_keys = [
        "schema",
        "kind",
        "source_inventory_scope",
        "source_inventory_root_sha512",
        "parent_artifact_report_path",
        "parent_artifact_report_bytes",
        "parent_artifact_report_sha512",
        "v4_verifier_binary_bytes",
        "v4_verifier_binary_sha512",
        "v4_verifier_output_sha512",
        "proof_bytes_preserved_from_parent",
        "pending_action_bytes_preserved_from_parent",
        "generation_independence_established",
        "claim",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let observed_keys = transition
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_claim = if artifact_role == RETAINED_LIFECYCLE_SEED {
        "diagnostic_zero_value_seed_proof"
    } else {
        "two_distinct_source_verified_proofs"
    };
    if observed_keys != expected_keys
        || transition["schema"] != PROVENANCE_TRANSITION_SCHEMA
        || transition["source_inventory_root_sha512"] != source_inventory.root_sha512
        || transition["generation_independence_established"] != Value::Bool(false)
        || transition["claim"] != expected_claim
    {
        return Err(runner_error("v5 provenance transition identity mismatch"));
    }

    match transition["kind"].as_str() {
        Some("direct_generation") => {
            if transition["source_inventory_scope"] != "generation_start_and_prepublication"
                || !transition["parent_artifact_report_path"].is_null()
                || transition["parent_artifact_report_bytes"].as_u64() != Some(0)
                || !transition["parent_artifact_report_sha512"].is_null()
                || transition["v4_verifier_binary_bytes"].as_u64() != Some(0)
                || !transition["v4_verifier_binary_sha512"].is_null()
                || !transition["v4_verifier_output_sha512"].is_null()
                || transition["proof_bytes_preserved_from_parent"] != Value::Bool(false)
                || transition["pending_action_bytes_preserved_from_parent"] != Value::Bool(false)
                || snapshot
                    .files
                    .contains_key("parent-artifact-report-v4.json")
            {
                return Err(runner_error("direct-generation v5 provenance is malformed"));
            }
        }
        Some("verified_v4_reseal") => {
            let parent = snapshot.get("parent-artifact-report-v4.json")?;
            let parent_sha512 = sha512_hex(parent);
            let parent_manifest: Value = serde_json::from_slice(parent)?;
            if transition["source_inventory_scope"] != "source_verification_at_reseal"
                || transition["parent_artifact_report_path"] != "parent-artifact-report-v4.json"
                || transition["parent_artifact_report_bytes"].as_u64() != Some(parent.len() as u64)
                || transition["parent_artifact_report_sha512"] != parent_sha512
                || !canonical_lower_hex(
                    transition["v4_verifier_binary_sha512"]
                        .as_str()
                        .unwrap_or(""),
                    64,
                )
                || transition["v4_verifier_binary_bytes"].as_u64().unwrap_or(0) == 0
                || !canonical_lower_hex(
                    transition["v4_verifier_output_sha512"]
                        .as_str()
                        .unwrap_or(""),
                    64,
                )
                || transition["proof_bytes_preserved_from_parent"] != Value::Bool(true)
                || transition["pending_action_bytes_preserved_from_parent"] != Value::Bool(true)
                || parent_manifest["schema"] != LEGACY_ARTIFACT_SCHEMA
                || parent_manifest["artifact_role"] != artifact_role
                || parent_manifest["sha512"]["proof"] != proof_sha512
                || parent_manifest["sha512"]["pending_action"]
                    != manifest["sha512"]["pending_action"]
                || parent_manifest["generation_provenance"] != manifest["generation_provenance"]
            {
                return Err(runner_error("verified-v4 reseal provenance is malformed"));
            }
            let parent_generator = &parent_manifest["generation_provenance"];
            if transition["v4_verifier_binary_bytes"] != parent_generator["generator_binary_bytes"]
                || transition["v4_verifier_binary_sha512"]
                    != parent_generator["generator_binary_sha512"]
            {
                return Err(runner_error(
                    "reseal v4 verifier does not equal the parent generator binary",
                ));
            }
        }
        _ => return Err(runner_error("v5 provenance transition kind is unsupported")),
    }
    Ok(())
}

fn verify_artifact_with_legacy_generator_check(
    directory: &Path,
    require_legacy_current_generator_identity: bool,
) -> RunnerResult<Value> {
    ensure_frozen_identity_constants()?;
    let snapshot = read_retained_artifact_snapshot(directory)?;
    let manifest_bytes = snapshot.get("artifact-report.json")?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    let schema = manifest["schema"]
        .as_str()
        .ok_or_else(|| runner_error("artifact report schema is not a string"))?;
    let is_legacy_v4 = schema == LEGACY_ARTIFACT_SCHEMA;
    let is_final_v5 = schema == FINAL_ARTIFACT_SCHEMA;
    if (!is_legacy_v4 && !is_final_v5) || manifest["retains_private_witness"] != Value::Bool(false)
    {
        return Err(runner_error("artifact report authority boundary mismatch"));
    }
    let artifact_role = manifest["artifact_role"]
        .as_str()
        .ok_or_else(|| runner_error("artifact report is missing artifact_role"))?;
    ensure_artifact_role(artifact_role)?;

    let proof = snapshot.get("proof.bin")?;
    let proof_sha512 = sha512_hex(proof);
    let generation_provenance = verify_generation_provenance(
        &manifest,
        artifact_role,
        &proof_sha512,
        is_legacy_v4 && require_legacy_current_generator_identity,
    )?;
    let source_inventory = if is_final_v5 {
        Some(verify_proof_source_inventory(
            manifest
                .get("proof_source_inventory")
                .ok_or_else(|| runner_error("v5 artifact omitted proof_source_inventory"))?,
        )?)
    } else {
        None
    };
    if let Some(source_inventory) = source_inventory.as_ref() {
        verify_v5_provenance_transition(
            &manifest,
            &snapshot,
            artifact_role,
            &proof_sha512,
            source_inventory,
        )?;
    }
    let statement_bytes = snapshot.get("public-statement.bin")?;
    let statement = SmallwoodPoseidon2V8PublicStatement::try_from_public_bytes(&statement_bytes)
        .map_err(|error| runner_error(format!("read-back statement failed: {error:?}")))?;
    let source_projection = project_for_artifact_role(artifact_role)?;
    if source_projection.statement.to_public_bytes() != statement_bytes
        || manifest["geometry"] != source_projection.geometry
        || manifest["fixture"] != source_projection.fixture
        || manifest["verification"]["relation_mutations"]
            != Value::Array(source_projection.relation_mutations.clone())
    {
        return Err(runner_error(
            "artifact fixture, geometry, or relation mutation receipt differs from fresh source projection",
        ));
    }
    let relation_digest =
        read_fixed::<48>("relation-digest.bin", snapshot.get("relation-digest.bin")?)?;
    let relation_binding_bytes = snapshot.get("relation-binding.bin")?;
    let relation_balance_words = read_words("relation-binding.bin", relation_binding_bytes, 7)?;
    let relation_balance_binding: [u64; 7] = relation_balance_words
        .try_into()
        .map_err(|_| runner_error("read-back relation binding length drift"))?;
    let network_id = u32::from_le_bytes(read_fixed::<4>(
        "network-id.bin",
        snapshot.get("network-id.bin")?,
    )?);
    let input = SmallwoodPoseidon2V8VerifierInput {
        network_id,
        relation_digest,
        public_values: statement.to_public_words(),
        relation_balance_binding,
    };
    let relation_program_bytes = snapshot.get("relation-program.bin")?;
    let relation_program_sha512 = Sha512::digest(&relation_program_bytes);
    if relation_program_bytes.len() != SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES
        || relation_program_bytes.get(..SMALLWOOD_POSEIDON2_V8_PROGRAM_MAGIC.len())
            != Some(SMALLWOOD_POSEIDON2_V8_PROGRAM_MAGIC.as_slice())
        || relation_program_sha512.as_slice() != SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512
        || smallwood_poseidon2_v8_program_digest_from_bytes(&relation_program_bytes)
            != relation_digest
        || relation_digest != SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST
    {
        return Err(runner_error(
            "read-back HGV8RP03 program identity does not match the proof relation digest",
        ));
    }

    let expected = Poseidon2ProductionExpectedContext::new(network_id, relation_digest)?;
    let native_leaf_bytes = snapshot.get("native-leaf.bin")?;
    let envelope_bytes = snapshot.get("rpc-envelope.bin")?;
    let inline_args_bytes = snapshot.get("scale-inline-args.bin")?;
    let pending_action_bytes = snapshot.get("pending-action.bin")?;
    let ciphertext_bytes = snapshot.get("ciphertexts.bin")?;
    let native_leaf =
        decode_poseidon2_production_smz9_native_leaf_exact(expected, &native_leaf_bytes)?;
    let envelope = decode_poseidon2_production_smz9_envelope_exact(expected, &envelope_bytes)?;
    let inline_args =
        decode_poseidon2_production_smz9_inline_args_exact(expected, &inline_args_bytes)?;
    if native_leaf.proof() != proof
        || envelope.native_leaf() != native_leaf_bytes
        || inline_args.envelope().raw() != envelope_bytes
        || inline_args.envelope().decoded_native_leaf().proof() != proof
    {
        return Err(runner_error(
            "read-back transport bytes do not preserve the exact SMZ9 proof",
        ));
    }
    ensure_native_leaf_matches_verifier_files(
        expected,
        native_leaf_bytes,
        statement_bytes,
        relation_binding_bytes,
        ciphertext_bytes,
    )?;
    let parser_stage_checks =
        transport_parser_stage_checks(expected, envelope_bytes, inline_args_bytes)?;
    if manifest["verification"]["transport_parser_stage_checks"]
        != Value::Array(parser_stage_checks)
    {
        return Err(runner_error(
            "reported transport parser-stage checks differ from fresh readback",
        ));
    }
    verify_smallwood_poseidon2_v8_candidate(&input, proof)?;
    let opening_surface = report_smallwood_poseidon2_v8_candidate(&input, proof)?;
    if manifest["opening_surface"] != serde_json::to_value(&opening_surface)? {
        return Err(runner_error(
            "artifact opening-surface report differs from fresh proof parsing",
        ));
    }
    let pending_action = verify_poseidon2_v8_pending_action_artifact_exact(
        network_id,
        &inline_args_bytes,
        &pending_action_bytes,
    )?;
    let node_pending_action_lifecycle = node_pending_action_lifecycle(
        &pending_action.readback,
        &pending_action_bytes,
        &inline_args_bytes,
        &proof,
    )?;
    if pending_action.encoded_pending_action != pending_action_bytes
        || manifest["verification"]["node_pending_action_lifecycle"]
            != node_pending_action_lifecycle
    {
        return Err(runner_error(
            "artifact PendingAction lifecycle does not match typed readback",
        ));
    }
    let inline_ciphertexts =
        SmallwoodPoseidon2V8InlineCiphertexts::try_from_inline_ciphertext_bytes(
            &statement,
            &ciphertext_bytes,
        )
        .map_err(|error| runner_error(format!("read-back ciphertexts failed: {error:?}")))?;
    let preamble = input.transcript_preamble()?;
    let preamble_bytes = snapshot.get("transcript-preamble.bin")?;
    if preamble_bytes != preamble.as_bytes() {
        return Err(runner_error("read-back transcript preamble drift"));
    }
    let honest_map_audit = honest_map_audit(&statement, &preamble_bytes, &proof)?;
    if manifest["verification"]["honest_map_audit"] != honest_map_audit {
        return Err(runner_error(
            "artifact honest-map rank inventory does not match verifier-derived trace",
        ));
    }
    let proof_randomness_binding = proof_randomness_binding(&statement, preamble_bytes, proof)?;
    if is_final_v5 && manifest["proof_randomness_binding"] != proof_randomness_binding {
        return Err(runner_error(
            "artifact proof randomness binding differs from fresh verifier trace",
        ));
    }

    for (name, bytes) in [
        ("proof", proof),
        ("public_statement", statement_bytes),
        ("ciphertexts", ciphertext_bytes),
        ("relation_binding", relation_binding_bytes),
        ("relation_program", relation_program_bytes),
        ("transcript_preamble", preamble_bytes),
        ("native_leaf", native_leaf_bytes),
        ("rpc_envelope", envelope_bytes),
        ("scale_inline_action", inline_args_bytes),
        ("pending_action", pending_action_bytes),
    ] {
        ensure_manifest_hash(&manifest, name, bytes)?;
    }
    let identity = &manifest["identity"];
    if identity["inner_magic"] != "SMZ9"
        || identity["network_id"].as_u64() != Some(u64::from(network_id))
        || identity["relation_digest_hex"] != hex::encode(relation_digest)
        || identity["relation_program"]["magic"] != PROGRAM_MAGIC_ASCII
        || identity["relation_program"]["bytes"].as_u64()
            != Some(SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES as u64)
        || identity["relation_program"]["sha512"]
            != hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512)
        || identity["semantic_relation"] != SMALLWOOD_POSEIDON2_V8_RELATION_ID
        || identity["transport"]["native_leaf_magic"] != NATIVE_LEAF_MAGIC_ASCII
        || identity["transport"]["rpc_envelope_magic"] != TRANSPORT_MAGIC_ASCII
        || identity["consensus_tuple"]["circuit_version"].as_u64() != Some(u64::from(CIRCUIT_V8))
        || identity["consensus_tuple"]["crypto_suite"].as_u64() != Some(u64::from(CRYPTO_SUITE_ETA))
        || identity["consensus_tuple"]["family_id"].as_u64()
            != Some(u64::from(FAMILY_SHIELDED_POOL))
        || identity["consensus_tuple"]["action_id"].as_u64()
            != Some(u64::from(SMALLWOOD_POSEIDON2_V8_ACTION_ID))
        || identity["consensus_tuple"]["backend_id"].as_u64()
            != Some(u64::from(SMALLWOOD_POSEIDON2_V8_BACKEND_ID))
        || identity["consensus_tuple"]["profile_id"].as_u64()
            != Some(u64::from(SMALLWOOD_POSEIDON2_V8_PROFILE_ID))
        || identity["consensus_tuple"]["domain_set"].as_u64()
            != Some(u64::from(SMALLWOOD_POSEIDON2_V8_DOMAIN_SET))
        || native_leaf_bytes.get(..POSEIDON2_PRODUCTION_SMZ9_NATIVE_LEAF_MAGIC.len())
            != Some(POSEIDON2_PRODUCTION_SMZ9_NATIVE_LEAF_MAGIC.as_slice())
        || envelope_bytes.get(..POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_MAGIC.len())
            != Some(POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_MAGIC.as_slice())
        || manifest_usize(&manifest, "bytes", "measured_inner_proof")? != proof.len()
        || manifest_usize(&manifest, "bytes", "native_leaf")? != native_leaf_bytes.len()
        || manifest_usize(&manifest, "bytes", "measured_rpc_envelope")? != envelope_bytes.len()
        || manifest_usize(&manifest, "bytes", "projected_max_rpc_envelope")?
            != EXPECTED_PROJECTED_RPC_ENVELOPE_BYTES
        || manifest_usize(&manifest, "bytes", "measured_scale_inline_args")?
            != inline_args_bytes.len()
        || manifest_usize(&manifest, "bytes", "projected_max_scale_inline_args")?
            != EXPECTED_PROJECTED_SCALE_INLINE_ARGS_BYTES
        || manifest_usize(&manifest, "bytes", "measured_pending_action")?
            != pending_action_bytes.len()
        || manifest_usize(&manifest, "bytes", "projected_max_pending_action")?
            != EXPECTED_PROJECTED_PENDING_ACTION_BYTES
        || manifest_usize(&manifest, "bytes", "fixed_pending_action_overhead")?
            != SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES
        || manifest_usize(&manifest, "bytes", "max_inline_route_args_bytes")?
            != POSEIDON2_PRODUCTION_MAX_ACTION_BYTES
        || manifest_usize(&manifest, "bytes", "max_outer_envelope_bytes")?
            != POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES
        || manifest_usize(&manifest, "bytes", "max_v8_pending_action_bytes")?
            != SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES
        || manifest_usize(&manifest, "bytes", "relation_program")? != relation_program_bytes.len()
        || pending_action_bytes.len()
            != inline_args_bytes.len() + SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES
        || inline_args_bytes.len() > POSEIDON2_PRODUCTION_MAX_ACTION_BYTES
        || envelope_bytes.len() > POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES
        || pending_action_bytes.len() > SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES
    {
        return Err(runner_error("artifact byte or identity report mismatch"));
    }
    let proof_evidence = &manifest["successor_evidence"]["proof"];
    let program_evidence = &manifest["successor_evidence"]["relation_program"];
    if proof_evidence["id"] != artifact_role
        || proof_evidence["kind"] != "proof"
        || proof_evidence["path"] != "proof.bin"
        || proof_evidence["bytes"].as_u64() != Some(proof.len() as u64)
        || proof_evidence["sha512"] != sha512_hex(&proof)
        || program_evidence["id"] != "relation_program"
        || program_evidence["kind"] != "program"
        || program_evidence["path"] != "relation-program.bin"
        || program_evidence["bytes"].as_u64() != Some(relation_program_bytes.len() as u64)
        || program_evidence["sha512"] != sha512_hex(&relation_program_bytes)
    {
        return Err(runner_error(
            "successor evidence labels do not match artifact bytes",
        ));
    }

    let proof_mutations = reject_proof_and_input_mutations(&input, &proof)?;
    let transport_mutations = reject_transport_mutations(
        expected,
        native_leaf_bytes,
        envelope_bytes,
        inline_args_bytes,
        statement_bytes,
        relation_binding_bytes,
        ciphertext_bytes,
    )?;
    let pending_action_mutations =
        reject_pending_action_mutations(network_id, &inline_args_bytes, &pending_action_bytes)?;
    if manifest["verification"]["proof_and_input_mutations"]
        != Value::Array(proof_mutations.clone())
        || manifest["verification"]["transport_mutations"]
            != Value::Array(transport_mutations.clone())
        || manifest["verification"]["pending_action_mutations"]
            != Value::Array(pending_action_mutations.clone())
    {
        return Err(runner_error(
            "artifact mutation report differs from fresh-process rejection results",
        ));
    }
    let mut mutated_ciphertexts = inline_ciphertexts;
    mutated_ciphertexts.ciphertexts[0]
        .as_mut()
        .ok_or_else(|| runner_error("maximum-shape artifact is missing output zero"))?[0] ^= 1;
    if mutated_ciphertexts
        .validate_against_statement(&statement)
        .is_ok()
    {
        return Err(runner_error(
            "fresh-process ciphertext mutation was accepted",
        ));
    }

    let verifier_provenance = current_verifier_provenance(
        source_inventory
            .as_ref()
            .map(|inventory| inventory.root_sha512.as_str())
            .unwrap_or("legacy-v4-no-source-inventory"),
    )?;
    Ok(json!({
        "artifact": directory,
        "artifact_schema": schema,
        "proof_bytes": proof.len(),
        "rpc_envelope_bytes": envelope_bytes.len(),
        "scale_inline_args_bytes": inline_args_bytes.len(),
        "pending_action_bytes": pending_action_bytes.len(),
        "proof_sha512": proof_sha512,
        "pending_action_sha512": sha512_hex(&pending_action_bytes),
        "relation_id": hex::encode(relation_digest),
        "relation_program_sha512": hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512),
        "semantic_relation": SMALLWOOD_POSEIDON2_V8_RELATION_ID,
        "native_leaf_magic": NATIVE_LEAF_MAGIC_ASCII,
        "rpc_envelope_magic": TRANSPORT_MAGIC_ASCII,
        "consensus_tuple": {
            "circuit_version": CIRCUIT_V8,
            "crypto_suite": CRYPTO_SUITE_ETA,
            "family_id": FAMILY_SHIELDED_POOL,
            "action_id": SMALLWOOD_POSEIDON2_V8_ACTION_ID,
            "backend_id": SMALLWOOD_POSEIDON2_V8_BACKEND_ID,
            "profile_id": SMALLWOOD_POSEIDON2_V8_PROFILE_ID,
            "domain_set": SMALLWOOD_POSEIDON2_V8_DOMAIN_SET,
        },
        "generation_provenance": generation_provenance,
        "verifier_provenance": verifier_provenance,
        "proof_randomness_binding": proof_randomness_binding,
        "fixture": source_projection.fixture,
        "source_factory_verified": true,
        "canonical_transport_verified": true,
        "canonical_pending_action_verified": true,
        "hash_manifest_verified": true,
        "honest_map_audit": honest_map_audit,
        "node_pending_action_lifecycle": node_pending_action_lifecycle,
        "proof_and_input_mutations": proof_mutations,
        "transport_mutations": transport_mutations,
        "pending_action_mutations": pending_action_mutations,
        "ciphertext_mutation_rejected": true,
    }))
}

fn verify_artifact(directory: &Path) -> RunnerResult<Value> {
    verify_artifact_with_legacy_generator_check(directory, true)
}

fn verify_v5_artifact(directory: &Path) -> RunnerResult<Value> {
    let verification = verify_artifact_with_legacy_generator_check(directory, false)?;
    if verification["artifact_schema"] != FINAL_ARTIFACT_SCHEMA {
        return Err(runner_error(
            "release retained-artifact verification requires exact schema v5",
        ));
    }
    Ok(verification)
}

#[derive(Debug)]
struct VerifiedSpendArtifact {
    verification: Value,
    manifest: Value,
    statement: SmallwoodPoseidon2V8PublicStatement,
    statement_bytes: Vec<u8>,
    ciphertext_bytes: Vec<u8>,
    relation_binding_bytes: Vec<u8>,
    transcript_preamble_bytes: Vec<u8>,
    proof_sha512: String,
    wire_salt_hex: String,
    transcript_root_hex: String,
    carrier_sha512: BTreeMap<&'static str, String>,
}

fn load_verified_spend_artifact(
    directory: &Path,
    expected_role: &str,
) -> RunnerResult<VerifiedSpendArtifact> {
    if !matches!(
        expected_role,
        RETAINED_PROOF_PRIMARY | RETAINED_PROOF_INDEPENDENT
    ) {
        return Err(runner_error(
            "verify-chain accepts only the two retained spend roles",
        ));
    }
    let verification = verify_v5_artifact(directory)?;
    let snapshot = read_retained_artifact_snapshot(directory)?;
    let manifest: Value = serde_json::from_slice(snapshot.get("artifact-report.json")?)?;
    if manifest["artifact_role"] != expected_role
        || manifest["fixture"]["fixture_group"] != RETAINED_SPEND_FIXTURE_GROUP
        || manifest["fixture"]["kind"] != "two_input_two_output_coinbase_spend"
    {
        return Err(runner_error(format!(
            "verify-chain artifact {} does not have role {expected_role} and the canonical coinbase-spend fixture",
            directory.display()
        )));
    }
    let statement_bytes = snapshot.get("public-statement.bin")?.to_vec();
    let statement = SmallwoodPoseidon2V8PublicStatement::try_from_public_bytes(&statement_bytes)
        .map_err(|error| runner_error(format!("verify-chain statement failed: {error:?}")))?;
    let proof = snapshot.get("proof.bin")?;
    let proof_sha512 = sha512_hex(proof);
    if verification["proof_sha512"] != proof_sha512
        || verification["pending_action_sha512"] != sha512_hex(snapshot.get("pending-action.bin")?)
        || verification["proof_randomness_binding"] != manifest["proof_randomness_binding"]
        || verification["fixture"] != manifest["fixture"]
    {
        return Err(runner_error(
            "verify-chain artifact changed after exact v5 verification",
        ));
    }
    let wire_salt_hex = manifest["proof_randomness_binding"]["wire_salt_hex"]
        .as_str()
        .ok_or_else(|| runner_error("verify-chain artifact omitted canonical wire salt"))?
        .to_owned();
    let transcript_root_hex = manifest["proof_randomness_binding"]["decs_transcript_root_hex"]
        .as_str()
        .ok_or_else(|| runner_error("verify-chain artifact omitted canonical transcript root"))?
        .to_owned();
    if !canonical_lower_hex(&wire_salt_hex, 32) || !canonical_lower_hex(&transcript_root_hex, 64) {
        return Err(runner_error(
            "verify-chain proof randomness binding is not canonical",
        ));
    }

    let carrier_sha512 = BTreeMap::from([
        ("native_leaf", sha512_hex(snapshot.get("native-leaf.bin")?)),
        (
            "rpc_envelope",
            sha512_hex(snapshot.get("rpc-envelope.bin")?),
        ),
        (
            "scale_inline_action",
            sha512_hex(snapshot.get("scale-inline-args.bin")?),
        ),
        (
            "pending_action",
            sha512_hex(snapshot.get("pending-action.bin")?),
        ),
    ]);
    Ok(VerifiedSpendArtifact {
        verification,
        manifest,
        statement,
        statement_bytes,
        ciphertext_bytes: snapshot.get("ciphertexts.bin")?.to_vec(),
        relation_binding_bytes: snapshot.get("relation-binding.bin")?.to_vec(),
        transcript_preamble_bytes: snapshot.get("transcript-preamble.bin")?.to_vec(),
        proof_sha512,
        wire_salt_hex,
        transcript_root_hex,
        carrier_sha512,
    })
}

fn ensure_distinct_chain_proof_bindings(
    primary_proof_sha512: &str,
    primary_wire_salt_hex: &str,
    primary_transcript_root_hex: &str,
    independent_proof_sha512: &str,
    independent_wire_salt_hex: &str,
    independent_transcript_root_hex: &str,
) -> RunnerResult<()> {
    if primary_proof_sha512 == independent_proof_sha512
        || primary_wire_salt_hex == independent_wire_salt_hex
        || primary_transcript_root_hex == independent_transcript_root_hex
    {
        Err(runner_error(
            "verify-chain requires distinct proof hashes, wire salts, and transcript roots",
        ))
    } else {
        Ok(())
    }
}

fn verify_retained_chain(
    primary_directory: &Path,
    independent_directory: &Path,
) -> RunnerResult<Value> {
    let primary = load_verified_spend_artifact(primary_directory, RETAINED_PROOF_PRIMARY)?;
    let independent =
        load_verified_spend_artifact(independent_directory, RETAINED_PROOF_INDEPENDENT)?;

    ensure_distinct_chain_proof_bindings(
        &primary.proof_sha512,
        &primary.wire_salt_hex,
        &primary.transcript_root_hex,
        &independent.proof_sha512,
        &independent.wire_salt_hex,
        &independent.transcript_root_hex,
    )?;
    if primary.statement_bytes != independent.statement_bytes
        || primary.ciphertext_bytes != independent.ciphertext_bytes
        || primary.relation_binding_bytes != independent.relation_binding_bytes
        || primary.transcript_preamble_bytes != independent.transcript_preamble_bytes
        || primary.manifest["fixture"]["synthetic_fixture_witness_definition_sha512"]
            != independent.manifest["fixture"]["synthetic_fixture_witness_definition_sha512"]
    {
        return Err(runner_error(
            "verify-chain proofs do not share one exact source fixture and public statement",
        ));
    }
    if primary.statement != independent.statement
        || primary.statement.activity_mask() != MAXIMUM_SHAPE_MASK
        || primary.statement.stablecoin.parent_height != RETAINED_SPEND_PARENT_HEIGHT
        || RETAINED_SPEND_PARENT_HEIGHT == 0
        || primary.statement.stablecoin
            != StablecoinPoseidon2V8Public::disabled_at_context(
                RETAINED_SPEND_PARENT_HEIGHT,
                RETAINED_STABLECOIN_ROOT,
            )
    {
        return Err(runner_error(
            "verify-chain statement is not the nonzero-height HGV8RP03 maximum shape",
        ));
    }

    let input_notes = retained_coinbase_note_openings()?;
    let public_openings = retained_coinbase_public_openings()?;
    let commitments = [
        note_commitment(input_notes[0])?,
        note_commitment(input_notes[1])?,
    ];
    let frontier = canonical_two_note_frontier(commitments);
    let expected_fixture =
        maximum_shape_fixture_from_input_notes(input_notes, RETAINED_SPEND_PARENT_HEIGHT)?;
    if primary.statement != expected_fixture.0 || primary.statement.merkle_root != frontier.root {
        return Err(runner_error(
            "verify-chain statement does not spend the exact two V8 coinbase notes at positions zero and one",
        ));
    }
    for input in 0..2 {
        let mut current = commitments[input];
        let mut position = input as u64;
        for sibling in frontier.paths[input] {
            current = if position & 1 == 0 {
                compress_note_nodes(current, sibling)
            } else {
                compress_note_nodes(sibling, current)
            };
            position >>= 1;
        }
        if current != frontier.root {
            return Err(runner_error(format!(
                "verify-chain canonical input path {input} does not reach the retained root"
            )));
        }
    }

    if primary
        .carrier_sha512
        .values()
        .any(|digest| !canonical_lower_hex(digest, 64))
        || independent
            .carrier_sha512
            .values()
            .any(|digest| !canonical_lower_hex(digest, 64))
        || primary
            .carrier_sha512
            .keys()
            .any(|stage| primary.carrier_sha512.get(stage) == independent.carrier_sha512.get(stage))
    {
        return Err(runner_error(
            "verify-chain canonical carrier digest inventory is malformed or not proof-distinct",
        ));
    }

    Ok(json!({
        "schema": "hegemon-smallwood-poseidon2-v8-retained-chain-verification-v1",
        "relation_program_magic": PROGRAM_MAGIC_ASCII,
        "relation_program_sha512": hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512),
        "semantic_relation": SMALLWOOD_POSEIDON2_V8_RELATION_ID,
        "fixture_group": RETAINED_SPEND_FIXTURE_GROUP,
        "same_public_statement": true,
        "same_source_fixture_witness_definition": true,
        "proof_witness_is_not_extracted_or_published": true,
        "distinct_proof_hashes": true,
        "distinct_wire_salts": true,
        "distinct_transcript_roots": true,
        "canonical_input_positions": [0, 1],
        "coinbase_input_values": RETAINED_COINBASE_AMOUNTS,
        "coinbase_opening_words_sha512": public_openings.map(|opening| sha512_hex(&words_to_bytes(&opening.note_hash_words()))),
        "coinbase_input_commitments_hex": commitments.map(|commitment| digest_hex(&commitment)),
        "input_merkle_path_sha512": frontier.paths.map(|path| sha512_hex(&merkle_path_bytes(&path))),
        "input_merkle_root_hex": digest_hex(&frontier.root),
        "parent_height": RETAINED_SPEND_PARENT_HEIGHT,
        "parent_height_nonzero": true,
        "same_proof_bytes_preserved_inside_each_carrier": true,
        "production_capability_enabled": false,
        "primary": {
            "artifact": primary_directory,
            "proof_sha512": primary.proof_sha512,
            "wire_salt_hex": primary.wire_salt_hex,
            "decs_transcript_root_hex": primary.transcript_root_hex,
            "carrier_sha512": primary.carrier_sha512,
            "source_factory_verified": primary.verification["source_factory_verified"],
        },
        "independent": {
            "artifact": independent_directory,
            "proof_sha512": independent.proof_sha512,
            "wire_salt_hex": independent.wire_salt_hex,
            "decs_transcript_root_hex": independent.transcript_root_hex,
            "carrier_sha512": independent.carrier_sha512,
            "source_factory_verified": independent.verification["source_factory_verified"],
        },
    }))
}

fn read_regular_file_capped(path: &Path, maximum: u64) -> RunnerResult<Vec<u8>> {
    ensure_no_symlink_path_components(path)?;
    let path_metadata = fs::symlink_metadata(path)?;
    if !path_metadata.file_type().is_file() || path_metadata.len() > maximum {
        return Err(runner_error(format!(
            "bounded provenance input {} is not a regular file within cap",
            path.display()
        )));
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.len() != path_metadata.len() {
        return Err(runner_error("bounded provenance input changed before read"));
    }
    #[cfg(unix)]
    if opened.dev() != path_metadata.dev() || opened.ino() != path_metadata.ino() {
        return Err(runner_error(
            "bounded provenance input changed identity before read",
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > maximum {
        return Err(runner_error(
            "bounded provenance input changed while reading",
        ));
    }
    let terminal = file.metadata()?;
    if terminal.len() != opened.len() || terminal.modified()? != opened.modified()? {
        return Err(runner_error("bounded provenance input changed after read"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn set_read_only_artifact_snapshot(directory: &Path, executable: &Path) -> RunnerResult<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.path() == executable {
            continue;
        }
        fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o444))?;
    }
    fs::set_permissions(executable, fs::Permissions::from_mode(0o555))?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o555))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_read_only_artifact_snapshot(_directory: &Path, _executable: &Path) -> RunnerResult<()> {
    Ok(())
}

#[cfg(unix)]
fn make_snapshot_removable(directory: &Path) -> RunnerResult<()> {
    fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_snapshot_removable(_directory: &Path) -> RunnerResult<()> {
    Ok(())
}

fn reseal_v4(
    artifact_role: &str,
    legacy_directory: &Path,
    legacy_verifier: &Path,
    output_root: &Path,
) -> RunnerResult<PathBuf> {
    ensure_resealable_artifact_role(artifact_role)?;
    let legacy_snapshot = read_retained_artifact_snapshot(legacy_directory)?;
    if legacy_snapshot
        .files
        .contains_key("parent-artifact-report-v4.json")
    {
        return Err(runner_error("reseal input is not an exact v4 artifact"));
    }
    let parent_report = legacy_snapshot.get("artifact-report.json")?;
    let parent_manifest: Value = serde_json::from_slice(parent_report)?;
    if parent_manifest["schema"] != LEGACY_ARTIFACT_SCHEMA
        || parent_manifest["artifact_role"] != artifact_role
    {
        return Err(runner_error(
            "reseal parent schema or artifact role mismatch",
        ));
    }
    let proof = legacy_snapshot.get("proof.bin")?;
    let proof_sha512 = sha512_hex(proof);
    let pending_action_sha512 = sha512_hex(legacy_snapshot.get("pending-action.bin")?);
    let parent_generator = parent_manifest["generation_provenance"]
        .as_object()
        .ok_or_else(|| runner_error("reseal parent omitted generation provenance"))?;
    let expected_verifier_bytes = parent_generator["generator_binary_bytes"]
        .as_u64()
        .ok_or_else(|| runner_error("reseal parent generator byte count is invalid"))?;
    let expected_verifier_sha512 = parent_generator["generator_binary_sha512"]
        .as_str()
        .ok_or_else(|| runner_error("reseal parent generator SHA-512 is invalid"))?;
    let verifier_bytes = read_regular_file_capped(legacy_verifier, 64 * 1024 * 1024)?;
    if verifier_bytes.len() as u64 != expected_verifier_bytes
        || sha512_hex(&verifier_bytes) != expected_verifier_sha512
    {
        return Err(runner_error(
            "reseal verifier does not equal the exact parent generator binary",
        ));
    }

    fs::create_dir_all(output_root)?;
    let verification_workspace =
        output_root.join(format!(".v4-verification-workspace-{}", std::process::id()));
    fs::create_dir(&verification_workspace)?;
    let verification_snapshot = verification_workspace.join("artifact");
    fs::create_dir(&verification_snapshot)?;
    for (name, bytes) in &legacy_snapshot.files {
        write_new(&verification_snapshot.join(name), bytes)?;
    }
    let verifier_snapshot = verification_workspace.join("v4-generator-verifier");
    write_new(&verifier_snapshot, &verifier_bytes)?;
    set_read_only_artifact_snapshot(&verification_snapshot, &verifier_snapshot)?;
    let legacy_output = Command::new(&verifier_snapshot)
        .arg("verify")
        .arg(&verification_snapshot)
        .output()?;
    if !legacy_output.status.success() {
        make_snapshot_removable(&verification_snapshot)?;
        fs::remove_dir_all(&verification_workspace)?;
        return Err(runner_error(format!(
            "exact v4 generator verification failed: {}",
            String::from_utf8_lossy(&legacy_output.stderr).trim()
        )));
    }
    let legacy_result: Value = serde_json::from_slice(&legacy_output.stdout)?;
    if legacy_result["proof_sha512"] != proof_sha512
        || legacy_result["pending_action_sha512"] != pending_action_sha512
    {
        make_snapshot_removable(&verification_snapshot)?;
        fs::remove_dir_all(&verification_workspace)?;
        return Err(runner_error(
            "exact v4 generator verification output does not bind parent proof/carrier",
        ));
    }
    let v4_verifier_output_sha512 = sha512_hex(&legacy_output.stdout);
    let reread = read_retained_artifact_snapshot(&verification_snapshot)?;
    if reread.files != legacy_snapshot.files {
        make_snapshot_removable(&verification_snapshot)?;
        fs::remove_dir_all(&verification_workspace)?;
        return Err(runner_error(
            "v4 artifact changed during exact verification",
        ));
    }
    make_snapshot_removable(&verification_snapshot)?;
    fs::remove_dir_all(&verification_workspace)?;

    let current_result = verify_artifact_with_legacy_generator_check(legacy_directory, false)?;
    if current_result["proof_sha512"] != proof_sha512
        || current_result["pending_action_sha512"] != pending_action_sha512
    {
        return Err(runner_error(
            "current source verifier did not bind the resealed v4 proof/carrier",
        ));
    }
    let source_inventory = compute_proof_source_inventory()?;
    let mut v5_manifest = parent_manifest.clone();
    let object = v5_manifest
        .as_object_mut()
        .ok_or_else(|| runner_error("v4 artifact report is not an object"))?;
    object.insert(
        "schema".to_owned(),
        Value::String(FINAL_ARTIFACT_SCHEMA.to_owned()),
    );
    object.insert(
        "proof_source_inventory".to_owned(),
        source_inventory.report.clone(),
    );
    object.insert(
        "proof_randomness_binding".to_owned(),
        current_result["proof_randomness_binding"].clone(),
    );
    object.insert(
        "provenance_transition".to_owned(),
        json!({
            "schema": PROVENANCE_TRANSITION_SCHEMA,
            "kind": "verified_v4_reseal",
            "source_inventory_scope": "source_verification_at_reseal",
            "source_inventory_root_sha512": source_inventory.root_sha512,
            "parent_artifact_report_path": "parent-artifact-report-v4.json",
            "parent_artifact_report_bytes": parent_report.len(),
            "parent_artifact_report_sha512": sha512_hex(parent_report),
            "v4_verifier_binary_bytes": verifier_bytes.len(),
            "v4_verifier_binary_sha512": sha512_hex(&verifier_bytes),
            "v4_verifier_output_sha512": v4_verifier_output_sha512,
            "proof_bytes_preserved_from_parent": true,
            "pending_action_bytes_preserved_from_parent": true,
            "generation_independence_established": false,
            "claim": "two_distinct_source_verified_proofs",
        }),
    );
    let v5_report = serde_json::to_vec_pretty(&v5_manifest)?;
    let staging = output_root.join(format!(".v5-staging-{}", std::process::id()));
    fs::create_dir(&staging)?;
    for (name, bytes) in &legacy_snapshot.files {
        if *name != "artifact-report.json" {
            write_new(&staging.join(name), bytes)?;
        }
    }
    write_new(
        &staging.join("parent-artifact-report-v4.json"),
        parent_report,
    )?;
    write_new(&staging.join("artifact-report.json"), &v5_report)?;
    File::open(&staging)?.sync_all()?;
    verify_v5_artifact(&staging)?;
    let source_inventory_after = compute_proof_source_inventory()?;
    if source_inventory_after != source_inventory {
        return Err(runner_error("proof source changed during v4-to-v5 reseal"));
    }
    let final_directory = output_root.join(format!("smz9-{}", &proof_sha512[..24]));
    if final_directory.exists() {
        return Err(runner_error(format!(
            "refusing to overwrite retained v5 artifact {}",
            final_directory.display()
        )));
    }
    fs::rename(&staging, &final_directory)?;
    File::open(output_root)?.sync_all()?;
    let status = Command::new(env::current_exe()?)
        .arg("verify-v5")
        .arg(&final_directory)
        .status()?;
    if !status.success() {
        return Err(runner_error(format!(
            "fresh-process v5 reseal verification failed with status {status}"
        )));
    }
    Ok(final_directory)
}

fn generate(artifact_role: &str, output_root: &Path) -> RunnerResult<PathBuf> {
    ensure_artifact_role(artifact_role)?;
    let generation_provenance_start = begin_generation_provenance()?;
    let source_inventory_start = compute_proof_source_inventory()?;
    let projection_start = Instant::now();
    let projection = project_for_artifact_role(artifact_role)?;
    let projection_millis = projection_start.elapsed().as_millis();

    let prove_start = Instant::now();
    let candidate = compile_and_prove_smallwood_poseidon2_v8_candidate(
        &projection.statement,
        &projection.witness,
        NETWORK_ID,
    )?;
    let prove_and_internal_verify_millis = prove_start.elapsed().as_millis();

    let verify_start = Instant::now();
    verify_smallwood_poseidon2_v8_candidate(candidate.verifier_input(), candidate.proof_bytes())?;
    let independent_verify_millis = verify_start.elapsed().as_millis();
    let opening_surface = report_smallwood_poseidon2_v8_candidate(
        candidate.verifier_input(),
        candidate.proof_bytes(),
    )?;

    if candidate.projected_max_proof_bytes() != projection.projected_proof_bytes
        || candidate.projected_action_bytes() != projection.projected_scale_inline_args_bytes
        || candidate.measured_action_bytes() > projection.projected_scale_inline_args_bytes
    {
        return Err(runner_error(
            "candidate byte accounting disagrees with projection",
        ));
    }

    let proof = candidate.proof_bytes();
    let proof_sha512 = sha512_hex(proof);
    let statement_bytes = projection.statement.to_public_bytes();
    let ciphertext_bytes = projection.inline_ciphertexts.to_inline_ciphertext_bytes();
    let input = candidate.verifier_input();
    let relation_binding_bytes = words_to_bytes(&input.relation_balance_binding);
    let transcript_preamble = input.transcript_preamble()?;
    let honest_map_audit_start = Instant::now();
    let honest_map_audit =
        honest_map_audit(&projection.statement, transcript_preamble.as_bytes(), proof)?;
    let proof_randomness_binding =
        proof_randomness_binding(&projection.statement, transcript_preamble.as_bytes(), proof)?;
    let honest_map_audit_millis = honest_map_audit_start.elapsed().as_millis();

    let expected = Poseidon2ProductionExpectedContext::new(NETWORK_ID, input.relation_digest)?;
    let native_leaf = encode_poseidon2_production_smz9_native_leaf(
        expected,
        &input.public_values,
        &input.relation_balance_binding,
        [
            projection.inline_ciphertexts.ciphertexts[0].as_ref(),
            projection.inline_ciphertexts.ciphertexts[1].as_ref(),
        ],
        proof,
    )?;
    let rpc_envelope = encode_poseidon2_production_smz9_envelope(expected, &native_leaf)?;
    let scale_inline_args = encode_poseidon2_production_smz9_inline_args(expected, &rpc_envelope)?;
    if scale_inline_args.len() != candidate.measured_action_bytes() {
        return Err(runner_error(format!(
            "canonical SCALE action has {} bytes, frontend measured {}",
            scale_inline_args.len(),
            candidate.measured_action_bytes()
        )));
    }
    let decoded_inline =
        decode_poseidon2_production_smz9_inline_args_exact(expected, &scale_inline_args)?;
    if decoded_inline.envelope().native_leaf() != native_leaf
        || decoded_inline.envelope().decoded_native_leaf().proof() != proof
    {
        return Err(runner_error(
            "canonical transport encoding changed the SMZ9 proof bytes",
        ));
    }
    ensure_native_leaf_matches_verifier_files(
        expected,
        &native_leaf,
        &statement_bytes,
        &relation_binding_bytes,
        &ciphertext_bytes,
    )?;
    let pending_action =
        encode_poseidon2_v8_pending_action_artifact(NETWORK_ID, &scale_inline_args)?;
    let pending_action_bytes = pending_action.encoded_pending_action;
    let pending_action_readback = verify_poseidon2_v8_pending_action_artifact_exact(
        NETWORK_ID,
        &scale_inline_args,
        &pending_action_bytes,
    )?;
    let node_pending_action_lifecycle = node_pending_action_lifecycle(
        &pending_action_readback.readback,
        &pending_action_bytes,
        &scale_inline_args,
        proof,
    )?;
    if pending_action_readback.encoded_pending_action != pending_action_bytes
        || rpc_envelope.len() > POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES
        || scale_inline_args.len() > POSEIDON2_PRODUCTION_MAX_ACTION_BYTES
        || pending_action_bytes.len() > SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES
        || pending_action_bytes.len()
            != scale_inline_args.len() + SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES
    {
        return Err(runner_error(
            "canonical full PendingAction byte accounting or readback failed",
        ));
    }
    let transport_parser_stage_checks =
        transport_parser_stage_checks(expected, &rpc_envelope, &scale_inline_args)?;

    let mut ciphertext_mutation = projection.inline_ciphertexts;
    ciphertext_mutation.ciphertexts[0]
        .as_mut()
        .expect("maximum-shape ciphertext exists")[0] ^= 1;
    let ciphertext_mutation_rejected = ciphertext_mutation
        .validate_against_statement(&projection.statement)
        .is_err();
    if !ciphertext_mutation_rejected {
        return Err(runner_error("ciphertext mutation was accepted"));
    }

    let proof_mutations = reject_proof_and_input_mutations(input, proof)?;
    let transport_mutations = reject_transport_mutations(
        expected,
        &native_leaf,
        &rpc_envelope,
        &scale_inline_args,
        &statement_bytes,
        &relation_binding_bytes,
        &ciphertext_bytes,
    )?;
    let pending_action_mutations =
        reject_pending_action_mutations(NETWORK_ID, &scale_inline_args, &pending_action_bytes)?;
    let generated_unix_seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let source_inventory_prepublication = compute_proof_source_inventory()?;
    if source_inventory_prepublication != source_inventory_start {
        return Err(runner_error(
            "proof-affecting source inventory changed during generation",
        ));
    }
    let generation_provenance = generation_provenance_start.report(
        artifact_role,
        &proof_sha512,
        FINAL_GENERATION_METADATA_SCOPE,
    );
    let provenance_claim = if artifact_role == RETAINED_LIFECYCLE_SEED {
        "diagnostic_zero_value_seed_proof"
    } else {
        "two_distinct_source_verified_proofs"
    };
    let manifest_value = json!({
        "schema": FINAL_ARTIFACT_SCHEMA,
        "artifact_role": artifact_role,
        "generation_provenance": generation_provenance,
        "proof_source_inventory": source_inventory_start.report,
        "provenance_transition": {
            "schema": PROVENANCE_TRANSITION_SCHEMA,
            "kind": "direct_generation",
            "source_inventory_scope": "generation_start_and_prepublication",
            "source_inventory_root_sha512": source_inventory_start.root_sha512,
            "parent_artifact_report_path": Value::Null,
            "parent_artifact_report_bytes": 0,
            "parent_artifact_report_sha512": Value::Null,
            "v4_verifier_binary_bytes": 0,
            "v4_verifier_binary_sha512": Value::Null,
            "v4_verifier_output_sha512": Value::Null,
            "proof_bytes_preserved_from_parent": false,
            "pending_action_bytes_preserved_from_parent": false,
            "generation_independence_established": false,
            "claim": provenance_claim,
        },
        "proof_randomness_binding": proof_randomness_binding,
        "fixture": projection.fixture,
        "identity": {
            "inner_magic": "SMZ9",
            "network_id": NETWORK_ID,
            "relation_digest_hex": hex::encode(input.relation_digest),
            "relation_program": {
                "magic": PROGRAM_MAGIC_ASCII,
                "bytes": SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES,
                "sha512": hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512),
            },
            "semantic_relation": SMALLWOOD_POSEIDON2_V8_RELATION_ID,
            "transport": {
                "native_leaf_magic": NATIVE_LEAF_MAGIC_ASCII,
                "rpc_envelope_magic": TRANSPORT_MAGIC_ASCII,
            },
            "consensus_tuple": {
                "circuit_version": CIRCUIT_V8,
                "crypto_suite": CRYPTO_SUITE_ETA,
                "family_id": FAMILY_SHIELDED_POOL,
                "action_id": SMALLWOOD_POSEIDON2_V8_ACTION_ID,
                "backend_id": SMALLWOOD_POSEIDON2_V8_BACKEND_ID,
                "profile_id": SMALLWOOD_POSEIDON2_V8_PROFILE_ID,
                "domain_set": SMALLWOOD_POSEIDON2_V8_DOMAIN_SET,
            },
            "profile": {
                "rho": 5,
                "opened_evaluations": 6,
                "beta": 2,
                "decs_evaluations": 1usize << 23,
                "decs_opened_leaves": 20,
                "decs_eta": 5,
                "leaf_tape_bytes": 64,
                "evaluation_domain": "radix2-disjoint-coset",
                "transcript": "SHA-512 Poseidon2 V8",
            },
        },
        "geometry": projection.geometry,
        "bytes": {
            "measured_inner_proof": proof.len(),
            "projected_max_inner_proof": candidate.projected_max_proof_bytes(),
            "relation_program": projection.relation_program.len(),
            "native_leaf": native_leaf.len(),
            "measured_rpc_envelope": rpc_envelope.len(),
            "projected_max_rpc_envelope": projection.projected_rpc_envelope_bytes,
            "measured_scale_inline_args": scale_inline_args.len(),
            "projected_max_scale_inline_args": projection.projected_scale_inline_args_bytes,
            "measured_pending_action": pending_action_bytes.len(),
            "projected_max_pending_action": projection.projected_pending_action_bytes,
            "fixed_pending_action_overhead": SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES,
            "max_inline_route_args_bytes": POSEIDON2_PRODUCTION_MAX_ACTION_BYTES,
            "max_outer_envelope_bytes": POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES,
            "max_v8_pending_action_bytes": SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES,
            "fixed_action": SMALLWOOD_POSEIDON2_V8_INLINE_FIXED_BYTES,
            "inline_ciphertexts": ciphertext_bytes.len(),
        },
        "sha512": {
            "proof": proof_sha512,
            "public_statement": sha512_hex(&statement_bytes),
            "ciphertexts": sha512_hex(&ciphertext_bytes),
            "relation_binding": sha512_hex(&relation_binding_bytes),
            "relation_program": sha512_hex(&projection.relation_program),
            "transcript_preamble": sha512_hex(transcript_preamble.as_bytes()),
            "native_leaf": sha512_hex(&native_leaf),
            "rpc_envelope": sha512_hex(&rpc_envelope),
            "scale_inline_action": sha512_hex(&scale_inline_args),
            "pending_action": sha512_hex(&pending_action_bytes),
        },
        "successor_evidence": {
            "proof": {
                "id": artifact_role,
                "kind": "proof",
                "path": "proof.bin",
                "bytes": proof.len(),
                "sha512": proof_sha512,
            },
            "relation_program": {
                "id": "relation_program",
                "kind": "program",
                "path": "relation-program.bin",
                "bytes": projection.relation_program.len(),
                "sha512": sha512_hex(&projection.relation_program),
            },
        },
        "verification": {
            "source_factory_immediate": true,
            "readback_before_publish": true,
            "same_smz9_bytes_at_every_layer": true,
            "node_pending_action_lifecycle": node_pending_action_lifecycle,
            "honest_map_audit": honest_map_audit,
            "transport_parser_stage_checks": transport_parser_stage_checks,
            "relation_mutations": projection.relation_mutations,
            "proof_and_input_mutations": proof_mutations,
            "transport_mutations": transport_mutations,
            "pending_action_mutations": pending_action_mutations,
            "ciphertext_mutation": {"name": "ciphertext_byte", "rejected": true},
        },
        "opening_surface": opening_surface,
        "timing_milliseconds": {
            "projection_and_relation_mutations": projection_millis,
            "prove_and_internal_verify": prove_and_internal_verify_millis,
            "independent_source_factory_verify": independent_verify_millis,
            "honest_map_audit": honest_map_audit_millis,
        },
        "generated_unix_seconds": generated_unix_seconds,
        "retains_private_witness": false,
    });
    let manifest = serde_json::to_vec_pretty(&manifest_value)?;

    fs::create_dir_all(output_root)?;
    let staging = output_root.join(format!(".staging-{}", std::process::id()));
    fs::create_dir(&staging)?;
    write_new(&staging.join("proof.bin"), proof)?;
    write_new(&staging.join("public-statement.bin"), &statement_bytes)?;
    write_new(&staging.join("ciphertexts.bin"), &ciphertext_bytes)?;
    write_new(&staging.join("network-id.bin"), &NETWORK_ID.to_le_bytes())?;
    write_new(&staging.join("relation-digest.bin"), &input.relation_digest)?;
    write_new(
        &staging.join("relation-binding.bin"),
        &relation_binding_bytes,
    )?;
    write_new(
        &staging.join("relation-program.bin"),
        &projection.relation_program,
    )?;
    write_new(
        &staging.join("transcript-preamble.bin"),
        transcript_preamble.as_bytes(),
    )?;
    write_new(&staging.join("native-leaf.bin"), &native_leaf)?;
    write_new(&staging.join("rpc-envelope.bin"), &rpc_envelope)?;
    write_new(&staging.join("scale-inline-args.bin"), &scale_inline_args)?;
    write_new(&staging.join("pending-action.bin"), &pending_action_bytes)?;
    write_new(&staging.join("artifact-report.json"), &manifest)?;
    File::open(&staging)?.sync_all()?;
    verify_v5_artifact(&staging)?;

    let final_directory = output_root.join(format!("smz9-{}", &proof_sha512[..24]));
    if final_directory.exists() {
        return Err(runner_error(format!(
            "refusing to overwrite retained artifact {}",
            final_directory.display()
        )));
    }
    fs::rename(&staging, &final_directory)?;
    File::open(output_root)?.sync_all()?;
    let status = Command::new(env::current_exe()?)
        .arg("verify-v5")
        .arg(&final_directory)
        .status()?;
    if !status.success() {
        return Err(runner_error(format!(
            "fresh-process artifact verification failed with status {status}"
        )));
    }
    Ok(final_directory)
}

fn print_projection(projection: &Projection) -> RunnerResult<()> {
    let source_inventory = compute_proof_source_inventory()?;
    let output = json!({
        "activity_mask": projection.statement.activity_mask(),
        "fixture": projection.fixture,
        "geometry": projection.geometry,
        "projected_inner_proof_bytes": projection.projected_proof_bytes,
        "projected_rpc_envelope_bytes": projection.projected_rpc_envelope_bytes,
        "projected_scale_inline_args_bytes": projection.projected_scale_inline_args_bytes,
        "projected_pending_action_bytes": projection.projected_pending_action_bytes,
        "max_outer_envelope_bytes": POSEIDON2_PRODUCTION_MAX_ENVELOPE_BYTES,
        "max_inline_route_args_bytes": POSEIDON2_PRODUCTION_MAX_ACTION_BYTES,
        "max_v8_pending_action_bytes": SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES,
        "remaining_pending_action_bytes": SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES
            - projection.projected_pending_action_bytes,
        "proof_source_inventory_root_sha512": source_inventory.root_sha512,
        "proof_source_inventory_file_count": source_inventory.report["file_count"],
        "proof_source_inventory_total_bytes": source_inventory.report["total_bytes"],
        "relation_mutations": projection.relation_mutations,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn usage() -> &'static str {
    "usage: smallwood_poseidon2_v8_artifact source-inventory | project [retained_proof_primary|retained_proof_independent|retained_lifecycle_seed] | program [output-path] | generate <retained_proof_primary|retained_proof_independent|retained_lifecycle_seed> [output-root] | reseal-v4 <retained_proof_primary|retained_proof_independent> <v4-artifact-directory> <exact-v4-generator-binary> [output-root] | verify <artifact-directory> | verify-v5 <artifact-directory> | verify-chain <primary-artifact-directory> <independent-artifact-directory>"
}

fn main() -> RunnerResult<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("source-inventory") => {
            if args.next().is_some() {
                return Err(runner_error(usage()));
            }
            io::stdout().write_all(&canonical_json_bytes(
                &compute_proof_source_inventory()?.report,
            )?)?;
            Ok(())
        }
        Some("project") => {
            let artifact_role = args
                .next()
                .unwrap_or_else(|| RETAINED_PROOF_PRIMARY.to_owned());
            ensure_artifact_role(&artifact_role)?;
            if args.next().is_some() {
                return Err(runner_error(usage()));
            }
            print_projection(&project_for_artifact_role(&artifact_role)?)
        }
        Some("program") => {
            let output = args.next().map(PathBuf::from).unwrap_or_else(|| {
                PathBuf::from(".agent/artifacts/smallwood-poseidon2-v8/relation-program.bin")
            });
            if args.next().is_some() {
                return Err(runner_error(usage()));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&publish_relation_program(&output)?)?
            );
            Ok(())
        }
        Some("generate") => {
            let artifact_role = args.next().ok_or_else(|| runner_error(usage()))?;
            ensure_artifact_role(&artifact_role)?;
            let output_root = args.next().map(PathBuf::from).unwrap_or_else(|| {
                PathBuf::from(".agent/artifacts/smallwood-poseidon2-v8").join(&artifact_role)
            });
            if args.next().is_some() {
                return Err(runner_error(usage()));
            }
            let final_directory = generate(&artifact_role, &output_root)?;
            println!("{}", final_directory.display());
            Ok(())
        }
        Some("reseal-v4") => {
            let artifact_role = args.next().ok_or_else(|| runner_error(usage()))?;
            ensure_resealable_artifact_role(&artifact_role)?;
            let legacy_directory = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| runner_error(usage()))?;
            let legacy_verifier = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| runner_error(usage()))?;
            let output_root = args.next().map(PathBuf::from).unwrap_or_else(|| {
                PathBuf::from(".agent/artifacts/smallwood-poseidon2-v8-v5").join(&artifact_role)
            });
            if args.next().is_some() {
                return Err(runner_error(usage()));
            }
            let final_directory = reseal_v4(
                &artifact_role,
                &legacy_directory,
                &legacy_verifier,
                &output_root,
            )?;
            println!("{}", final_directory.display());
            Ok(())
        }
        Some("verify") => {
            let directory = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| runner_error(usage()))?;
            if args.next().is_some() {
                return Err(runner_error(usage()));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&verify_artifact(&directory)?)?
            );
            Ok(())
        }
        Some("verify-v5") => {
            let directory = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| runner_error(usage()))?;
            if args.next().is_some() {
                return Err(runner_error(usage()));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&verify_v5_artifact(&directory)?)?
            );
            Ok(())
        }
        Some("verify-chain") => {
            let primary = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| runner_error(usage()))?;
            let independent = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| runner_error(usage()))?;
            if args.next().is_some() {
                return Err(runner_error(usage()));
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&verify_retained_chain(&primary, &independent)?)?
            );
            Ok(())
        }
        _ => Err(runner_error(usage())),
    }
}

const _: () = assert!(MAXIMUM_SHAPE_MASK == 15);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_PUBLIC_BYTES == 960);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES == 2_147);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_coinbase_openings_and_position_zero_one_paths_are_exact() -> RunnerResult<()> {
        assert_eq!(
            single_key_authorization_key(RETAINED_SPEND_KEY)?,
            [
                1_741_146_651_100_274_088,
                9_539_478_460_468_656_252,
                7_097_725_263_314_205_436,
                1_436_916_868_072_586_276,
            ]
        );
        let public_openings = retained_coinbase_public_openings()?;
        assert_eq!(
            public_openings[0].note_hash_words(),
            [
                499_429_223,
                0,
                14_132_942_956_216_209_493,
                7_685_267_610_787_277_800,
                16_563_171_182_421_170_277,
                17_300_113_818_709_955_652,
                31,
                32,
                33,
                34,
                41,
                42,
                43,
                44,
                1_741_146_651_100_274_088,
                9_539_478_460_468_656_252,
                7_097_725_263_314_205_436,
                1_436_916_868_072_586_276,
            ]
        );
        let notes = retained_coinbase_note_openings()?;
        let commitments = [note_commitment(notes[0])?, note_commitment(notes[1])?];
        assert_eq!(
            commitments,
            [
                [
                    18_259_492_048_087_240_027,
                    7_531_590_084_034_765_769,
                    13_832_855_441_552_585_900,
                    10_259_413_316_072_182_562,
                    8_159_847_284_554_373_283,
                    7_764_619_155_970_330_813,
                    17_704_496_476_243_124_233,
                ],
                [
                    17_163_717_373_116_784_760,
                    13_164_473_423_282_992_000,
                    1_608_449_966_275_840_194,
                    6_492_075_582_679_948_467,
                    9_438_899_898_515_079_769,
                    252_098_020_066_066_352,
                    13_644_583_900_996_167_472,
                ],
            ]
        );

        let frontier = canonical_two_note_frontier(commitments);
        assert_eq!(frontier.paths[0][0], commitments[1]);
        assert_eq!(frontier.paths[1][0], commitments[0]);
        assert_eq!(
            digest_hex(&frontier.root),
            "4234cd0433f8d6908835707d621d274826d6a08124a5b27304f0ecec137d4d9129e54a87060390ac6bf87eb775c873df4d1e2139275a629a"
        );
        for input in 0..2 {
            let mut current = commitments[input];
            let mut position = input as u64;
            for sibling in frontier.paths[input] {
                current = if position & 1 == 0 {
                    compress_note_nodes(current, sibling)
                } else {
                    compress_note_nodes(sibling, current)
                };
                position >>= 1;
            }
            assert_eq!(current, frontier.root);
        }
        Ok(())
    }

    #[test]
    fn retained_roles_select_exact_positive_spend_or_zero_seed_fixture() -> RunnerResult<()> {
        let primary = project_for_artifact_role(RETAINED_PROOF_PRIMARY)?;
        let independent = project_for_artifact_role(RETAINED_PROOF_INDEPENDENT)?;
        assert_eq!(primary.statement, independent.statement);
        assert_eq!(primary.witness, independent.witness);
        assert_eq!(primary.fixture, independent.fixture);
        assert_eq!(
            sha512_hex(&primary.statement.to_public_bytes()),
            RETAINED_V8_STATEMENT_SHA512
        );
        assert_eq!(
            sha512_hex(&primary.witness.to_witness_bytes()),
            RETAINED_V8_WITNESS_SHA512
        );
        assert_eq!(
            sha512_hex(&primary.inline_ciphertexts.to_inline_ciphertext_bytes()),
            RETAINED_V8_INLINE_CIPHERTEXT_SHA512
        );
        assert_eq!(primary.statement.activity_mask(), MAXIMUM_SHAPE_MASK);
        assert_eq!(
            primary.statement.stablecoin,
            StablecoinPoseidon2V8Public::disabled_at_context(
                RETAINED_SPEND_PARENT_HEIGHT,
                RETAINED_STABLECOIN_ROOT,
            )
        );
        assert_eq!(primary.witness.stablecoin, Default::default());
        assert_ne!(primary.statement.stablecoin.parent_height, 0);
        assert!(!primary.statement.value_balance_sign);
        assert_eq!(primary.statement.value_balance_magnitude, 0);
        assert_eq!(primary.statement.fee, 0);
        assert_eq!(
            primary.fixture["economic_value_source"],
            "v8_coinbase_action_11"
        );
        assert_eq!(
            primary.fixture["artifact_alone_authorizes_production"],
            false
        );

        let seed = project_for_artifact_role(RETAINED_LIFECYCLE_SEED)?;
        assert_eq!(seed.statement.activity_mask(), 0b1100);
        assert_eq!(seed.fixture["economic_production_evidence"], false);
        assert_eq!(
            seed.fixture["economic_value_source"],
            "none_zero_value_diagnostic"
        );
        assert_eq!(seed.statement.value_balance_sign, false);
        assert_eq!(seed.statement.value_balance_magnitude, 0);
        assert_eq!(seed.statement.fee, 0);
        assert!(ensure_artifact_role("not-a-retained-role").is_err());
        assert!(ensure_resealable_artifact_role(RETAINED_LIFECYCLE_SEED).is_err());
        Ok(())
    }

    #[test]
    fn verify_chain_requires_all_three_randomness_identities_to_differ() {
        assert!(ensure_distinct_chain_proof_bindings("aa", "bb", "cc", "dd", "ee", "ff").is_ok());
        assert!(ensure_distinct_chain_proof_bindings("aa", "bb", "cc", "aa", "ee", "ff").is_err());
        assert!(ensure_distinct_chain_proof_bindings("aa", "bb", "cc", "dd", "bb", "ff").is_err());
        assert!(ensure_distinct_chain_proof_bindings("aa", "bb", "cc", "dd", "ee", "cc").is_err());
        assert!(usage().contains("verify-v5 <artifact-directory>"));
        assert!(usage().contains("verify-chain <primary-artifact-directory>"));
    }

    #[test]
    fn v4_generation_provenance_is_source_and_proof_bound() -> RunnerResult<()> {
        let start = collect_generation_provenance()?;
        let proof_sha512 = sha512_hex(b"provenance-only test proof bytes");
        let mut manifest = json!({
            "schema": LEGACY_ARTIFACT_SCHEMA,
            "generation_provenance": start.report(
                RETAINED_PROOF_PRIMARY,
                &proof_sha512,
                LEGACY_GENERATION_INDEPENDENCE_SCOPE,
            ),
            "generated_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        });
        assert_eq!(
            verify_generation_provenance(&manifest, RETAINED_PROOF_PRIMARY, &proof_sha512, true,)?
                ["proof_sha512"],
            proof_sha512
        );

        manifest["generation_provenance"]["proof_sha512"] = Value::String("00".repeat(64));
        assert!(verify_generation_provenance(
            &manifest,
            RETAINED_PROOF_PRIMARY,
            &proof_sha512,
            true,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn v5_generation_provenance_treats_head_and_generator_binary_as_informational(
    ) -> RunnerResult<()> {
        let start = collect_generation_provenance()?;
        let proof_sha512 = sha512_hex(b"v5 provenance test proof bytes");
        let mut manifest = json!({
            "schema": FINAL_ARTIFACT_SCHEMA,
            "provenance_transition": {"kind": "direct_generation"},
            "generation_provenance": start.report(
                RETAINED_PROOF_PRIMARY,
                &proof_sha512,
                FINAL_GENERATION_METADATA_SCOPE,
            ),
            "generated_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        });
        manifest["generation_provenance"]["source_revision"] = Value::String("ab".repeat(20));
        manifest["generation_provenance"]["generator_source_sha512"] =
            Value::String("cd".repeat(64));
        manifest["generation_provenance"]["generator_binary_bytes"] = Value::from(1u64);
        manifest["generation_provenance"]["generator_binary_sha512"] =
            Value::String("ef".repeat(64));
        assert!(verify_generation_provenance(
            &manifest,
            RETAINED_PROOF_PRIMARY,
            &proof_sha512,
            false,
        )
        .is_ok());
        assert!(verify_generation_provenance(
            &manifest,
            RETAINED_PROOF_PRIMARY,
            &proof_sha512,
            true,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn v5_source_inventory_rejects_source_digest_missing_path_and_order_drift() -> RunnerResult<()>
    {
        let inventory = compute_proof_source_inventory()?;
        assert!(verify_proof_source_inventory(&inventory.report).is_ok());

        let mut changed_digest = inventory.report.clone();
        changed_digest["entries"][0]["sha512"] = Value::String("00".repeat(64));
        assert!(verify_proof_source_inventory(&changed_digest).is_err());

        let mut missing = inventory.report.clone();
        missing["entries"]
            .as_array_mut()
            .expect("inventory entries array")
            .remove(0);
        assert!(verify_proof_source_inventory(&missing).is_err());

        let mut reordered = inventory.report.clone();
        reordered["entries"]
            .as_array_mut()
            .expect("inventory entries array")
            .swap(0, 1);
        assert!(verify_proof_source_inventory(&reordered).is_err());
        Ok(())
    }

    #[test]
    fn release_source_inventory_v2_matches_python_policy_bytes() -> RunnerResult<()> {
        let inventory = compute_proof_source_inventory()?;
        assert_eq!(inventory.report["schema"], SOURCE_INVENTORY_SCHEMA);
        assert_eq!(
            inventory.report["root_packages"],
            json!(SOURCE_INVENTORY_ROOT_PACKAGES)
        );
        assert_eq!(
            inventory.report["root_features"],
            json!({
                "transaction-circuit": ["default"],
                "hegemon-node": [],
                "wallet": ["default"],
                "walletd": ["default"],
            })
        );
        let paths = inventory.report["entries"]
            .as_array()
            .ok_or_else(|| runner_error("release source inventory entries are not an array"))?
            .iter()
            .filter_map(|entry| entry["path"].as_str())
            .collect::<BTreeSet<_>>();
        assert!(paths.contains("formal/crypto/HegemonCrypto/SmallWoodV8Smz9QromAccounting.lean"));
        assert!(paths.contains("formal/crypto/lakefile.toml"));
        assert!(paths.contains("formal/crypto/lean-toolchain"));
        assert!(paths.contains("formal/lean/lakefile.lean"));
        assert!(paths.contains("formal/lean/lean-toolchain"));
        assert!(!paths.iter().any(|path| path.contains("/.lake/")));

        let repository_root = proof_source_repository_root()?;
        let python = Command::new("python3")
            .args([
                "-I",
                "-B",
                "-c",
                r#"import sys
from pathlib import Path
root = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(root))
import scripts.check_transaction_proof_successor_authorization as gate
inventory = gate.recompute_retained_proof_source_inventory(root)
sys.stdout.buffer.write(gate.canonical_json_bytes(inventory))
"#,
            ])
            .arg(&repository_root)
            .current_dir(&repository_root)
            .stdin(Stdio::null())
            .output()?;
        if !python.status.success() {
            return Err(runner_error(format!(
                "Python release source inventory failed: {}",
                String::from_utf8_lossy(&python.stderr).trim()
            )));
        }
        assert_eq!(canonical_json_bytes(&inventory.report)?, python.stdout);
        Ok(())
    }

    #[test]
    fn release_source_inventory_v2_rejects_v1_domain_replay() -> RunnerResult<()> {
        let inventory = compute_proof_source_inventory()?;
        let entries = inventory.report["entries"]
            .as_array()
            .ok_or_else(|| runner_error("release source inventory entries are not an array"))?;
        let retired_root =
            proof_source_inventory_root_sha512(RETIRED_SOURCE_INVENTORY_V1_DOMAIN, entries)?;
        assert_ne!(retired_root, inventory.root_sha512);

        let mut replay = inventory.report.clone();
        replay["root_sha512"] = Value::String(retired_root);
        assert!(verify_proof_source_inventory(&replay).is_err());
        Ok(())
    }

    #[test]
    fn verifier_binary_self_attestation_is_observed_not_manifest_echo() -> RunnerResult<()> {
        let inventory = compute_proof_source_inventory()?;
        let provenance = current_verifier_provenance(&inventory.root_sha512)?;
        let (bytes, sha512) = sha512_file(&env::current_exe()?)?;
        assert_eq!(provenance["binary_bytes"].as_u64(), Some(bytes));
        assert_eq!(provenance["binary_sha512"], sha512);
        assert_eq!(provenance["generator_binary_equality_required"], false);
        Ok(())
    }

    #[test]
    fn v4_carrier_seam_rewraps_canonically_and_rejects_cross_input_mutations() -> RunnerResult<()> {
        let (statement, _, inline_ciphertexts) = maximum_shape_fixture()?;
        let public_values = statement.to_public_words();
        let relation_binding = statement.expected_action_intent().map_err(|error| {
            runner_error(format!(
                "maximum-shape fixture action-intent derivation failed: {error:?}"
            ))
        })?;
        let statement_bytes = statement.to_public_bytes();
        let relation_binding_bytes = words_to_bytes(&relation_binding);
        let ciphertext_bytes = inline_ciphertexts.to_inline_ciphertext_bytes();
        let expected = Poseidon2ProductionExpectedContext::new(
            NETWORK_ID,
            SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST,
        )?;
        let mut proof = vec![0xa5; EXPECTED_PROJECTED_PROOF_BYTES];
        proof[..4].copy_from_slice(b"SMZ9");
        let native_leaf = encode_poseidon2_production_smz9_native_leaf(
            expected,
            &public_values,
            &relation_binding,
            [
                inline_ciphertexts.ciphertexts[0].as_ref(),
                inline_ciphertexts.ciphertexts[1].as_ref(),
            ],
            &proof,
        )?;
        let envelope = encode_poseidon2_production_smz9_envelope(expected, &native_leaf)?;
        let inline_args = encode_poseidon2_production_smz9_inline_args(expected, &envelope)?;
        ensure_native_leaf_matches_verifier_files(
            expected,
            &native_leaf,
            &statement_bytes,
            &relation_binding_bytes,
            &ciphertext_bytes,
        )?;

        let mutation_results = reject_transport_mutations(
            expected,
            &native_leaf,
            &envelope,
            &inline_args,
            &statement_bytes,
            &relation_binding_bytes,
            &ciphertext_bytes,
        )?;
        assert_eq!(mutation_results.len(), 7);
        assert_eq!(
            mutation_results[5],
            json!({"name": "native_leaf_statement_rewrap", "rejected": true})
        );
        assert_eq!(
            mutation_results[6],
            json!({"name": "native_leaf_relation_binding_rewrap", "rejected": true})
        );

        let mut changed_ciphertexts = ciphertext_bytes.clone();
        changed_ciphertexts[0] ^= 1;
        assert!(ensure_native_leaf_matches_verifier_files(
            expected,
            &native_leaf,
            &statement_bytes,
            &relation_binding_bytes,
            &changed_ciphertexts,
        )
        .is_err());
        assert_eq!(
            transport_parser_stage_checks(expected, &envelope, &inline_args)?.len(),
            10
        );
        Ok(())
    }
}
