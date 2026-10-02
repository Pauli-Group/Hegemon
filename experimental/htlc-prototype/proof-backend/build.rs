//! Generate a source facade, not a copied/forked production backend.
//! Cargo/rustc still compile each existing file at its original exact path.
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn source_files(path: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).expect("source directory") {
        let entry = entry.expect("source entry");
        let path = entry.path();
        if path.is_dir() {
            source_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn main() {
    let own = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = own
        .join("../../..")
        .canonicalize()
        .expect("repository root");
    let tx_src = root.join("circuits/transaction/src");
    let original = fs::read_to_string(tx_src.join("lib.rs")).expect("transaction source root");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut facade =
        String::from("// Generated facade. Existing source modules remain unchanged.\n");
    for line in original.lines() {
        if line.starts_with("//!") {
            continue;
        }
        if line.starts_with("mod ")
            || line.starts_with("pub mod ")
            || line.starts_with("pub(crate) mod ")
        {
            let module = line
                .split_whitespace()
                .last()
                .unwrap()
                .trim_end_matches(';');
            assert!(
                module
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "unsupported module declaration"
            );
            let source = tx_src.join(format!("{module}.rs"));
            assert!(
                source.is_file(),
                "source facade requires a real unchanged module: {module}"
            );
            if module == "smallwood_engine" {
                // Same unchanged body; a local read-only seam exposes only
                // its private size/config calculator for later projections.
                facade.push_str(&format!(
                    "mod smallwood_engine {{ include!({:?});\n",
                    source.to_str().unwrap()
                ));
                facade.push_str("pub(crate) fn isolated_layout_metrics(statement: &(dyn crate::smallwood_semantics::SmallwoodConstraintAdapter + Sync), profile: SmallwoodNoGrindingProfileV1) -> Result<[usize;8], crate::TransactionCircuitError> { let cfg=SmallwoodConfig::new_with_profile(statement,profile)?; let bytes=serialized_proof_size_hint_with_profile(&cfg,profile,0,SmallwoodTranscriptBackend::Sha512Level5,SmallwoodDecsEvaluationDomain::Radix2DisjointCoset)?; Ok([bytes,cfg.wit_poly_degree,cfg.mpol_poly_degree,cfg.mlin_poly_degree,cfg.nb_polys,cfg.nb_lvcs_rows,cfg.nb_lvcs_cols,cfg.nb_lvcs_cols+profile.decs_nb_opened_evals]) }\n}\n");
                continue;
            }
            if module == "smallwood_poseidon2_v8_rng_refinement" {
                // Explicit #[path] changes rustc's implicit nested-module base.
                // Mechanically resolve its one child declaration; keep the
                // original parent and mapping function bodies unchanged.
                let mapping = tx_src.join(module).join("mapping.rs");
                let body = fs::read_to_string(&source).expect("RNG refinement source");
                assert_eq!(body.matches("mod mapping;").count(), 1);
                let resolved = body.replace(
                    "mod mapping;",
                    &format!("#[path = {:?}]\nmod mapping;", mapping.to_str().unwrap()),
                );
                let generated = output.join("rng_refinement_facade.rs");
                fs::write(&generated, resolved).expect("resolved RNG source facade");
                facade.push_str(&format!("#[path = {:?}]\n", generated.to_str().unwrap()));
            } else {
                facade.push_str(&format!("#[path = {:?}]\n", source.to_str().unwrap()));
            }
        }
        facade.push_str(line);
        facade.push('\n');
    }
    fs::write(output.join("transaction_facade.rs"), facade).expect("generated facade");

    // Conservative source closure: every Rust file in the original transaction
    // crate and its local dependency crates, their manifests, workspace pins,
    // and both isolated crates. Broader than the compiled import closure, never
    // weaker; registry versions/checksums are pinned by the nested Cargo.lock.
    let mut files = vec![root.join("Cargo.toml"), root.join("rust-toolchain.toml")];
    for package in [
        "circuits/transaction",
        "circuits/transaction-core",
        "circuits/hegemon-field",
        "crypto",
        "crypto/hash384",
        "crypto/hash448",
        "protocol/kernel",
        "protocol/versioning",
        "protocol/shielded-pool",
        "experimental/htlc-prototype",
        "experimental/htlc-prototype/proof-backend",
    ] {
        files.push(root.join(package).join("Cargo.toml"));
        source_files(&root.join(package).join("src"), &mut files);
    }
    files.push(own.join("build.rs"));
    files.push(own.join("Cargo.lock"));
    files.push(own.join("../Cargo.lock"));
    files = files
        .into_iter()
        .map(|file| file.canonicalize().expect("source closure path"))
        .collect();
    files.sort();
    files.dedup();
    let mut inventory = String::new();
    let mut closure = Sha256::new();
    for file in files {
        println!("cargo:rerun-if-changed={}", file.display());
        let relative = file.strip_prefix(&root).unwrap().to_str().unwrap();
        let bytes = fs::read(&file).expect("source closure member");
        let digest = Sha256::digest(&bytes);
        inventory.push_str(&format!("{digest:x}  {relative}\n"));
        closure.update((relative.len() as u64).to_le_bytes());
        closure.update(relative.as_bytes());
        closure.update((bytes.len() as u64).to_le_bytes());
        closure.update(&bytes);
    }
    fs::write(output.join("source-closure.sha256"), inventory).expect("source inventory");
    println!(
        "cargo:rustc-env=HTLC_SOURCE_CLOSURE_SHA256={:x}",
        closure.finalize()
    );
    let rustc = Command::new(env::var_os("RUSTC").unwrap())
        .arg("--version")
        .output()
        .expect("rustc identity");
    let version = String::from_utf8(rustc.stdout).expect("rustc version UTF8");
    println!("cargo:rustc-env=HTLC_RUSTC_VERSION={}", version.trim());
}
