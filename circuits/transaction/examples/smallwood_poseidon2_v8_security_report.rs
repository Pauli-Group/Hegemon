//! Emit the deterministic, non-authorizing current-source V8/SMZ9 security report.

#![forbid(unsafe_code)]

use std::{env, error::Error, fs, io::Write, path::PathBuf};

use transaction_circuit::{
    ensure_smallwood_poseidon2_v8_deployed_security_v1,
    report_smallwood_poseidon2_v8_current_source_security_v1,
};

enum OutputMode {
    Diagnostic(Option<PathBuf>),
    Check(PathBuf),
    RequireDeployed,
}

fn output_mode() -> Result<OutputMode, String> {
    let mut arguments = env::args_os().skip(1);
    match arguments.next() {
        None => Ok(OutputMode::Diagnostic(None)),
        Some(flag) if flag == "--output" => {
            let path = arguments
                .next()
                .ok_or_else(|| "--output requires one path".to_owned())?;
            if arguments.next().is_some() {
                return Err("unexpected argument after --output path".to_owned());
            }
            Ok(OutputMode::Diagnostic(Some(path.into())))
        }
        Some(flag) if flag == "--check" => {
            let path = arguments
                .next()
                .ok_or_else(|| "--check requires one path".to_owned())?;
            if arguments.next().is_some() {
                return Err("unexpected argument after --check path".to_owned());
            }
            Ok(OutputMode::Check(path.into()))
        }
        Some(flag) if flag == "--require-deployed" => {
            if arguments.next().is_some() {
                return Err("unexpected argument after --require-deployed".to_owned());
            }
            Ok(OutputMode::RequireDeployed)
        }
        Some(_) => Err(
            "usage: smallwood_poseidon2_v8_security_report [--output PATH | --check PATH | --require-deployed]"
                .to_owned(),
        ),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mode = output_mode().map_err(std::io::Error::other)?;
    let report = report_smallwood_poseidon2_v8_current_source_security_v1()?;
    if matches!(&mode, OutputMode::RequireDeployed) {
        ensure_smallwood_poseidon2_v8_deployed_security_v1(&report)?;
    }
    let canonical_value = serde_json::to_value(report)?;
    let mut bytes = serde_json::to_vec_pretty(&canonical_value)?;
    bytes.push(b'\n');

    match mode {
        OutputMode::Diagnostic(Some(path)) => fs::write(path, bytes)?,
        OutputMode::Check(path) => {
            if fs::read(&path)? != bytes {
                return Err(format!(
                    "{} is not the current source-derived security report",
                    path.display()
                )
                .into());
            }
            println!(
                "SMZ9 source security report verified: {} production_eligible=false",
                path.display()
            );
        }
        OutputMode::Diagnostic(None) | OutputMode::RequireDeployed => {
            std::io::stdout().lock().write_all(&bytes)?
        }
    }
    Ok(())
}
