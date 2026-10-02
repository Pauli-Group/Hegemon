use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let mut output = None;
    let mut verify_artifact = None;
    let mut project = false;
    let mut invalid = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                output = args.next().map(PathBuf::from);
            }
            "--negative-engine" | "--exercise-invalid-engine" => invalid = true,
            "--verify-artifact" => verify_artifact = args.next().map(PathBuf::from),
            "--project-layouts" => project = true,
            _ => {
                eprintln!("usage: hegemon-isolated-htlc-smallwood --out FRESH_DIRECTORY [--negative-engine] | --verify-artifact DIRECTORY");
                return ExitCode::FAILURE;
            }
        }
    }
    if project {
        if output.is_some() || verify_artifact.is_some() || invalid {
            eprintln!("projection cannot be combined with proof options");
            return ExitCode::FAILURE;
        }
        return match hegemon_isolated_htlc_smallwood::projection::layouts() {
            Ok(layouts) => {
                println!("{}", serde_json::to_string(&layouts).unwrap());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("native layout projection: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if let Some(directory) = verify_artifact {
        if output.is_some() || invalid {
            eprintln!("artifact verification cannot be combined with proving options");
            return ExitCode::FAILURE;
        }
        return match hegemon_isolated_htlc_smallwood::measurement::verify_artifact(&directory) {
            Ok(receipt) => {
                println!("{}", serde_json::to_string(&receipt).unwrap());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("retained hashlock verification: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let Some(output) = output else {
        eprintln!("--out FRESH_DIRECTORY is required");
        return ExitCode::FAILURE;
    };
    match hegemon_isolated_htlc_smallwood::measurement::measure(&output, invalid) {
        Ok(result) => {
            println!("{}", serde_json::to_string(&result).unwrap());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("native private hashlock measurement: {error}");
            ExitCode::FAILURE
        }
    }
}
