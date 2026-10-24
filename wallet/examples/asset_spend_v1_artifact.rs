//! Disposable asset proof/geometry runner. Feature: private-spend-dev-artifacts.
//!
//! Usage (all outputs are candidate-only, keys publicly disclosed):
//!   asset_spend_v1_artifact transfer --depth 4 --geometry-only OUTDIR
//!   asset_spend_v1_artifact mint --depth 8 OUTDIR
//!   asset_spend_v1_artifact burn --depth 16 --profile bounded OUTDIR
//! OUTDIR must be absent. The coordinator measures peak process memory with
//! scripts/measure_stablecoin_v1.py and retains that external receipt. This never contacts a
//! node, submits an action, writes wallet state, or claims production authority.
#![recursion_limit = "256"]

use anyhow::{bail, Context, Result};
use rand::{RngCore, SeedableRng};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256, Sha512};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
use transaction_circuit::{
    asset_spend_v1 as relation,
    asset_spend_v1_state::{AssetLedgerContextV1, AssetLedgerV1},
    asset_spend_v1_wire::{
        decode_asset_spend_action_v1, encode_asset_spend_action_v1, ASSET_SPEND_V1_FIXED_BYTES,
        ASSET_SPEND_V1_HEADER_BYTES,
    },
};
use wallet::asset_spend_v1_fixture::{AssetFixtureProfileV1, DisposableAssetFixtureV1, FIXTURE_ID};
use zeroize::Zeroize;

struct Options {
    operation: u8,
    name: String,
    depth: u8,
    geometry_only: bool,
    profile: AssetFixtureProfileV1,
    outdir: PathBuf,
}
fn options() -> Result<Options> {
    let mut args = env::args().skip(1);
    let name = args.next().context(
        "usage: asset_spend_v1_artifact transfer|mint|burn --depth 4|8|16 [--profile ordinary|bounded] [--geometry-only] OUTDIR",
    )?;
    let operation = match name.as_str() {
        "transfer" => relation::TRANSFER,
        "mint" => relation::MINT,
        "burn" => relation::BURN,
        _ => bail!("operation must be transfer, mint or burn"),
    };
    let mut depth = 4;
    let mut geometry_only = false;
    let mut profile = AssetFixtureProfileV1::Ordinary;
    let mut outdir = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--depth" => {
                depth = args
                    .next()
                    .context("missing --depth value")?
                    .parse()
                    .context("invalid depth")?
            }
            "--geometry-only" => geometry_only = true,
            "--profile" => {
                profile = match args.next().context("missing profile")?.as_str() {
                    "ordinary" => AssetFixtureProfileV1::Ordinary,
                    "bounded" => AssetFixtureProfileV1::Bounded,
                    _ => bail!("profile must be ordinary or bounded"),
                }
            }
            _ if !arg.starts_with('-') && outdir.is_none() => outdir = Some(PathBuf::from(arg)),
            _ => bail!("unexpected argument {arg}"),
        }
    }
    if !matches!(depth, 4 | 8 | 16) {
        bail!("depth must be 4, 8 or 16");
    }
    Ok(Options {
        operation,
        name,
        depth,
        geometry_only,
        profile,
        outdir: outdir.context("missing output directory")?,
    })
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create new {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn write_json(path: &Path, value: &Value) -> Result<()> {
    write_new(path, &serde_json::to_vec_pretty(value)?)
}
fn hashes(bytes: &[u8]) -> Value {
    json!({"bytes": bytes.len(), "sha256": hex::encode(Sha256::digest(bytes)), "sha512": hex::encode(Sha512::digest(bytes))})
}
fn command_text(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
fn create_output_directory(outdir: &Path) -> Result<()> {
    if outdir.exists() {
        bail!("output directory must be new: {}", outdir.display());
    }
    fs::create_dir(outdir).with_context(|| format!("create new directory {}", outdir.display()))?;
    Ok(())
}
// Deterministic encryption is restricted to this disclosed disposable fixture.
// The proof backend retains its own unchanged randomness/security profile.
struct DisposableEncryptionRng(rand::rngs::StdRng);
impl rand_core09::TryRngCore for DisposableEncryptionRng {
    type Error = rand::Error;
    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }
    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
        self.0.try_fill_bytes(dst)
    }
}
impl rand_core09::TryCryptoRng for DisposableEncryptionRng {}

fn run(options: &Options) -> Result<()> {
    let started = Instant::now();
    let mut fixture = DisposableAssetFixtureV1::build_with_profile(
        options.operation,
        options.depth,
        options.profile,
    )?;
    let ciphertexts = fixture.encrypt_and_check(&mut DisposableEncryptionRng(
        rand::rngs::StdRng::seed_from_u64(0x4153_4e31),
    ))?;
    let fixture_seconds = started.elapsed().as_secs_f64();
    let compile_start = Instant::now();
    let (adapter, mut packed) = relation::compile(&fixture.public, &fixture.witness)?;
    let packed_witness_words = packed.len();
    packed.zeroize();
    drop(adapter);
    let initial_compile_seconds = compile_start.elapsed().as_secs_f64();
    let geometry_start = Instant::now();
    let geometry = relation::geometry_receipt(&fixture.public)?;
    let geometry_seconds = geometry_start.elapsed().as_secs_f64();
    let binding = fixture.public.binding_bytes();
    write_new(&options.outdir.join("public-binding.bin"), &binding)?;
    let ciphertext_bytes = ciphertexts
        .each_ref()
        .map(|ciphertext| *ciphertext.as_bytes());
    for (slot, ciphertext) in ciphertext_bytes.iter().enumerate() {
        write_new(
            &options.outdir.join(format!("ciphertext-{slot}.bin")),
            ciphertext,
        )?;
    }
    write_json(&options.outdir.join("geometry.json"), &geometry)?;
    let relation_digest = relation::relation_digest();
    let mut report = json!({
        "receipt_version": 2,
        "fixture_id": FIXTURE_ID,
        "scope": "Inactive controlled-asset candidate with optional bounded policy; no node/PendingAction/network-admission claim",
        "production_authorized": false,
        "operation": options.name,
        "profile": options.profile.name(),
        "policy_mode": fixture.public.policy_mode,
        "public_secret_release": fixture.public.secret_release,
        "credential_active_leaves": if options.profile == AssetFixtureProfileV1::Bounded { 2 } else { 1 },
        "credential_depth": options.depth,
        "geometry_only": options.geometry_only,
        "relation_id": relation::RELATION_ID,
        "relation_source_sha512": hex::encode(relation_digest),
        "wire_relation_digest48": hex::encode(&relation_digest[..48]),
        "fixture_source": hashes(include_bytes!("../src/asset_spend_v1_fixture.rs")),
        "wallet_construction_source": hashes(include_bytes!("../src/asset_spend_v1.rs")),
        "runner_source": hashes(include_bytes!("asset_spend_v1_artifact.rs")),
        "public_binding": hashes(&binding),
        "public_words": relation::PUBLIC_WORDS,
        "public_words_le_u64": fixture.public.words().as_slice(),
        "packed_witness_words": packed_witness_words,
        "ciphertext_bytes_each": 2608,
        "ciphertext_bytes_total": 3 * 2608,
        "ciphertexts": ciphertext_bytes.iter().map(|bytes| hashes(bytes)).collect::<Vec<_>>(),
        "all_three_outputs_decrypted_and_exact_openings_checked": true,
        "current_registry_accounting_preparation_passed": true,
        "relation_compile_passed": true,
        "disclosed_disposable_key_material": true,
        "encryption_rng": "StdRng public seed0x41534e31; disposable qualification only",
        "timing_method": "std::time::Instant; proof and verification public APIs each include adapter construction",
        "timings_seconds": {"fixture_and_three_encrypt_decrypt": fixture_seconds, "initial_compile": initial_compile_seconds, "geometry": geometry_seconds, "prove": null, "independent_verify": null},
        "peak_memory_bytes": null,
        "peak_memory_method": "Measured externally by scripts/measure_stablecoin_v1.py; null here means consult its receipt, never zero usage",
        "peak_memory_scope": "entire runner process including fixture, geometry, compilation, proving, independent verification and encoding",
        "hardware": {"os": env::consts::OS, "arch": env::consts::ARCH, "logical_parallelism": std::thread::available_parallelism().ok().map(usize::from), "uname": command_text("/usr/bin/uname", &["-a"]), "cpu_brand": command_text("/usr/sbin/sysctl", &["-n", "machdep.cpu.brand_string"])},
        "geometry": geometry,
        "proof_generated": false,
        "proof_verified": false,
        "ledger_apply_passed": false,
        "actual_proof": null,
        "actual_candidate_action": null,
        "candidate_action_fixed_nonproof_bytes": ASSET_SPEND_V1_FIXED_BYTES,
        "candidate_action_header_bytes": ASSET_SPEND_V1_HEADER_BYTES,
    });
    write_json(&options.outdir.join("checkpoint.json"), &report)?;
    if !options.geometry_only {
        let prove_start = Instant::now();
        let proof = relation::prove_candidate(&fixture.public, &fixture.witness)?;
        let proving_seconds = prove_start.elapsed().as_secs_f64();
        // Retain completed expensive work before independent verification.
        write_new(&options.outdir.join("proof.smze"), &proof)?;
        let verify_start = Instant::now();
        relation::verify_candidate(&fixture.public, &proof)?;
        let verification_seconds = verify_start.elapsed().as_secs_f64();
        let proof_wire = relation::proof_wire_receipt(&proof)?;
        let negatives_start = Instant::now();
        let mut crossed_mode = fixture.public.clone();
        crossed_mode.policy_mode ^= 1;
        if crossed_mode.policy_mode == 0 {
            crossed_mode.secret_release = 0;
            crossed_mode.released_secret = [0; 32];
        }
        if relation::verify_candidate(&crossed_mode, &proof).is_ok() {
            bail!("proof accepted under different policy mode");
        }
        let mut padded = fixture.public.clone();
        padded.secret_release = 0;
        padded.released_secret = [0; 32];
        padded.released_secret[0] = 1;
        if encode_asset_spend_action_v1(&padded, &ciphertext_bytes, &proof).is_ok() {
            bail!("noncanonical release padding accepted");
        }
        let mut invalid_mode = fixture.public.clone();
        invalid_mode.policy_mode = 2;
        if encode_asset_spend_action_v1(&invalid_mode, &ciphertext_bytes, &proof).is_ok() {
            bail!("invalid policy mode accepted");
        }
        let negative_checks_seconds = negatives_start.elapsed().as_secs_f64();
        let wire_start = Instant::now();
        let action = encode_asset_spend_action_v1(&fixture.public, &ciphertext_bytes, &proof)?;
        let decoded = decode_asset_spend_action_v1(&action)?;
        if decoded.public != fixture.public
            || decoded.proof != proof.as_slice()
            || decoded
                .ciphertexts
                .iter()
                .zip(ciphertext_bytes.iter())
                .any(|(got, expected)| *got != expected)
        {
            bail!("candidate wire readback mismatch");
        }
        let wire_seconds = wire_start.elapsed().as_secs_f64();
        let action_name = format!(
            "action.{}",
            std::str::from_utf8(
                &transaction_circuit::asset_spend_v1_wire::ASSET_SPEND_V1_ACTION_MAGIC
            )?
            .to_ascii_lowercase()
        );
        write_new(&options.outdir.join(action_name), &action)?;
        let initial_commitments = fixture.initial_commitments()?;
        let context = AssetLedgerContextV1 {
            chain_id: fixture.public.chain_id,
            reference_parent_hash: fixture.public.reference_parent_hash,
            parent_height: fixture.public.parent_height,
            note_root: fixture.public.note_root,
            registry_root: fixture.public.registry_root,
        };
        let mut ledger = AssetLedgerV1::from_authenticated_snapshot(
            context,
            fixture.registry.clone(),
            &initial_commitments,
            &[],
            &[],
        )?;
        let before = ledger.snapshot();
        let ledger_start = Instant::now();
        let applied = ledger.apply_action(&action)?;
        let ledger_apply_seconds = ledger_start.elapsed().as_secs_f64();
        let after = ledger.snapshot();
        if applied.consumed_nullifiers != fixture.public.nullifiers
            || applied.native_fee != fixture.public.fee
            || applied.operation != fixture.public.operation
            || applied.policy_mode != fixture.public.policy_mode
            || applied.released_secret
                != if fixture.public.secret_release == 1 {
                    Some(fixture.public.released_secret)
                } else {
                    None
                }
            || after.commitments.len() != initial_commitments.len() + 3
            || after.spent_nullifiers.len() != 2
            || after.accepted_native_fees_since_snapshot != u128::from(fixture.public.fee)
        {
            bail!("candidate ledger application mismatch");
        }
        if ledger.apply_action(&action).is_ok() || ledger.snapshot() != after {
            bail!("candidate replay was accepted or mutated state");
        }
        let before_counters = before.registry.row(fixture.public.asset_id)?.counters;
        let after_counters = after.registry.row(fixture.public.asset_id)?.counters;
        let expected_debt = match fixture.public.operation {
            relation::MINT => before_counters
                .total_debt
                .checked_add(fixture.public.magnitude),
            relation::BURN => before_counters
                .total_debt
                .checked_sub(fixture.public.magnitude),
            _ => Some(before_counters.total_debt),
        }
        .context("fixture debt arithmetic overflow")?;
        if after_counters.total_debt != expected_debt {
            bail!("ledger debt delta mismatch");
        }
        let ledger_receipt = json!({
            "before_note_root": applied.before_note_root,
            "after_note_root": applied.after_note_root,
            "before_registry_root": applied.before_registry_root,
            "after_registry_root": applied.after_registry_root,
            "output_positions": applied.output_positions,
            "consumed_nullifiers": applied.consumed_nullifiers,
            "native_fee": applied.native_fee,
            "operation": applied.operation,
            "policy_mode": applied.policy_mode,
            "released_secret": applied.released_secret,
            "release_receipt_matches_verified_public_statement": true,
            "note_count_before": before.commitments.len(),
            "note_count_after": after.commitments.len(),
            "spent_nullifier_count_after": after.spent_nullifiers.len(),
            "accepted_native_fees_since_snapshot": after.accepted_native_fees_since_snapshot,
            "before_counters": {"epoch_id": before_counters.epoch_id, "minted_in_epoch": before_counters.minted_in_epoch, "total_debt": before_counters.total_debt, "sequence": before_counters.sequence},
            "after_counters": {"epoch_id": after_counters.epoch_id, "minted_in_epoch": after_counters.minted_in_epoch, "total_debt": after_counters.total_debt, "sequence": after_counters.sequence},
            "replay_rejected_without_state_mutation": true,
            "scope": "disposable in-memory proof-aware candidate ledger; no persistence or node admission",
        });
        write_json(&options.outdir.join("ledger-receipt.json"), &ledger_receipt)?;
        report["ledger_apply_passed"] = json!(true);
        report["ledger_receipt"] = ledger_receipt;
        report["timings_seconds"]["proof_aware_ledger_apply"] = json!(ledger_apply_seconds);
        report["proof_generated"] = json!(true);
        report["proof_verified"] = json!(true);
        report["actual_proof"] = hashes(&proof);
        report["actual_candidate_action"] = hashes(&action);
        report["candidate_wire_roundtrip_passed"] = json!(true);
        report["proof_wire_receipt"] = proof_wire;
        report["timings_seconds"]["prove"] = json!(proving_seconds);
        report["timings_seconds"]["independent_verify"] = json!(verification_seconds);
        report["timings_seconds"]["negative_cross_mode_and_padding_checks"] =
            json!(negative_checks_seconds);
        report["negative_checks"] = json!({"different_policy_mode_proof_rejected": true, "noncanonical_release_padding_rejected": true, "invalid_policy_mode_rejected": true, "replay_rejected_without_state_mutation": true});
        report["timings_seconds"]["wire_encode_decode"] = json!(wire_seconds);
    }
    report["timings_seconds"]["runner_total_before_receipt"] =
        json!(started.elapsed().as_secs_f64());
    write_json(&options.outdir.join("report.json"), &report)?;
    println!("{}", options.outdir.join("report.json").display());
    Ok(())
}

fn main() -> Result<()> {
    let options = options()?;
    create_output_directory(&options.outdir)?;
    run(&options)
}
