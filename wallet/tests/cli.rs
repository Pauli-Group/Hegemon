use std::{fs, io::Write};

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::tempdir;

use wallet::{keys::RootSecret, viewing::IncomingViewingKey};

#[test]
fn generate_and_address_round_trip() {
    let output = cargo_bin_cmd!("wallet")
        .args(["generate", "--count", "2"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let export: Value = serde_json::from_slice(&output).expect("json");
    let root = export["root_secret"]
        .as_str()
        .expect("root hex")
        .to_string();
    let address = export["addresses"][0]["address"].as_str().expect("addr");
    cargo_bin_cmd!("wallet")
        .args(["address", "--root", &root, "--index", "0"])
        .assert()
        .success()
        .stdout(predicate::str::contains(address));
}

#[test]
fn tx_craft_and_scan_flow() {
    let temp = tempdir().expect("tempdir");
    let inputs_path = temp.path().join("inputs.json");
    fs::write(&inputs_path, b"[]").expect("write inputs");

    let sender_root = RootSecret::from_bytes([3u8; 32]);
    let sender_hex = hex::encode(sender_root.to_bytes());

    let recipient_root = RootSecret::from_bytes([9u8; 32]);
    let recipient_keys = recipient_root.derive();
    let recipient_address = recipient_keys
        .address(0)
        .expect("addr")
        .shielded_address()
        .encode()
        .expect("encode address");

    let recipients_path = temp.path().join("recipients.json");
    let recipients = vec![RecipientSpec {
        address: recipient_address,
        value: 42,
        asset_id: 7,
        memo: None,
    }];
    fs::File::create(&recipients_path)
        .expect("recipients file")
        .write_all(serde_json::to_string(&recipients).unwrap().as_bytes())
        .expect("write recipients");

    let ivk_path = temp.path().join("ivk.json");
    let ivk = IncomingViewingKey::from_keys(&recipient_keys);
    fs::write(&ivk_path, serde_json::to_vec(&ivk).unwrap()).expect("ivk");

    let witness_out = temp.path().join("witness.json");
    let ledger_out = temp.path().join("ledger.json");

    cargo_bin_cmd!("wallet")
        .args([
            "tx-craft",
            "--root",
            &sender_hex,
            "--inputs",
            inputs_path.to_str().unwrap(),
            "--recipients",
            recipients_path.to_str().unwrap(),
            "--merkle-root",
            "0",
            "--fee",
            "0",
            "--witness-out",
            witness_out.to_str().unwrap(),
            "--ciphertext-out",
            ledger_out.to_str().unwrap(),
            "--rng-seed",
            "1234",
        ])
        .assert()
        .success();

    let report_out = temp.path().join("report.json");
    cargo_bin_cmd!("wallet")
        .args([
            "scan",
            "--ivk",
            ivk_path.to_str().unwrap(),
            "--ledger",
            ledger_out.to_str().unwrap(),
            "--out",
            report_out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let report: Value = serde_json::from_slice(&fs::read(&report_out).unwrap()).unwrap();
    assert_eq!(report["totals"]["7"].as_u64(), Some(42));
}

#[derive(Serialize, Deserialize)]
struct RecipientSpec {
    address: String,
    value: u64,
    asset_id: u64,
    memo: Option<String>,
}
