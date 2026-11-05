use assert_cmd::Command;
use serde_json::Value;
use std::fs;

fn run(args: &[&str]) -> Value {
    let output = Command::cargo_bin("reward-account")
        .unwrap()
        .args(args)
        .assert()
        .success();
    serde_json::from_slice(&output.get_output().stdout).unwrap()
}

#[test]
fn reward_accounts_cli_funded_genesis_and_network_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("genesis.json");
    let path = path.to_str().unwrap();
    run(&[
        "development-genesis",
        "--out",
        path,
        "--reward-epoch-blocks",
        "2",
    ]);
    let summary = run(&["genesis-check", "--genesis", path]);
    let g = summary["genesis_allocated_atoms"].as_u64().unwrap();
    let b = summary["remaining_mining_atoms"].as_u64().unwrap();
    assert_eq!(g, 2000 * 100_000_000);
    assert_eq!(g + b, 21_000_000 * 100_000_000);
    assert_eq!(summary["epoch_zero_first_claim_height"], 5);
    assert_eq!(summary["treasury_quorum"]["required"], 5);
    assert_eq!(summary["treasury_quorum"]["members"], 7);
    assert_eq!(summary["runtime_activation"], false);
    let address = summary["treasury_address"].as_str().unwrap();
    assert!(address.starts_with("heg_test1"));
    assert_eq!(
        run(&["address-check", "--genesis", path, "--address", address])["kind"],
        "public-account"
    );
    let mut other: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let first = other["network"]["discriminator"][0].as_u64().unwrap();
    other["network"]["discriminator"][0] = Value::from(first ^ 1);
    let alternate = dir.path().join("other-network.json");
    fs::write(&alternate, serde_json::to_vec(&other).unwrap()).unwrap();
    Command::cargo_bin("reward-account")
        .unwrap()
        .args([
            "address-check",
            "--genesis",
            alternate.to_str().unwrap(),
            "--address",
            address,
        ])
        .assert()
        .failure();
}

#[test]
fn reward_accounts_cli_never_overwrites_existing_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("genesis.json");
    fs::write(&path, b"existing operator file").unwrap();
    Command::cargo_bin("reward-account")
        .unwrap()
        .args(["development-genesis", "--out", path.to_str().unwrap()])
        .assert()
        .failure();
    assert_eq!(fs::read(path).unwrap(), b"existing operator file");
}
