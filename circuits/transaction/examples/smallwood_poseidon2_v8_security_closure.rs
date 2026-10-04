//! Rebuild and verify the exact executable SMZ9 zero-knowledge refinement report.
//!
//! This is deliberately a local executable-evidence generator.  Its report
//! keeps both adaptive/global QROM receipts absent and cannot authorize the
//! production route.

use std::{env, fs, io::Write, path::Path, process::ExitCode};

use sha2::{Digest, Sha512};
use transaction_circuit::smallwood_poseidon2_v8_zk_refinement::{
    report_smallwood_poseidon2_v8_smz9_executable_zk_refinement_v1,
    SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REPORT_BYTES,
    SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REPORT_SHA512_HEX,
};

fn report_bytes() -> Result<Vec<u8>, String> {
    let report = report_smallwood_poseidon2_v8_smz9_executable_zk_refinement_v1()
        .map_err(|error| format!("could not rebuild SMZ9 executable ZK refinement: {error}"))?;
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("could not serialize SMZ9 executable ZK refinement: {error}"))?;
    bytes.push(b'\n');
    let digest = hex::encode(Sha512::digest(&bytes));
    if bytes.len() != SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REPORT_BYTES
        || digest != SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REPORT_SHA512_HEX
    {
        return Err(format!(
            "source-rebuilt SMZ9 executable ZK report changed: expected bytes={} sha512={}, observed bytes={} sha512={}; review and update the explicit pin before regeneration",
            SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REPORT_BYTES,
            SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REPORT_SHA512_HEX,
            bytes.len(),
            digest,
        ));
    }
    Ok(bytes)
}

fn check(path: &Path, expected: &[u8]) -> Result<(), String> {
    let observed =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if observed != expected {
        return Err(format!(
            "{} is not the current source-rebuilt SMZ9 executable ZK refinement report",
            path.display()
        ));
    }
    let digest = Sha512::digest(&observed);
    println!(
        "SMZ9 executable ZK refinement verified: bytes={} sha512={} production_eligible=false",
        observed.len(),
        hex::encode(digest)
    );
    Ok(())
}

fn write(path: &Path, expected: &[u8]) -> Result<(), String> {
    fs::write(path, expected)
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    println!(
        "SMZ9 executable ZK refinement regenerated: bytes={} sha512={} production_eligible=false",
        expected.len(),
        hex::encode(Sha512::digest(expected))
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let expected = report_bytes()?;
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => std::io::stdout()
            .write_all(&expected)
            .map_err(|error| format!("could not write report: {error}")),
        [flag, path] if flag == "--check" => check(Path::new(path), &expected),
        [flag, path] if flag == "--write" => write(Path::new(path), &expected),
        _ => Err(
            "usage: smallwood_poseidon2_v8_security_closure [--check <report.json> | --write <report.json>]"
                .to_owned(),
        ),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
