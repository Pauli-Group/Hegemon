use std::fs;

use tempfile::tempdir;

#[allow(dead_code)]
#[path = "../src/bin/wallet.rs"]
mod wallet_bin;

use wallet::RecipientSpec;
use wallet_bin::randomize_recipient_specs;

#[test]
fn randomize_memo_order_shuffles_specs_loaded_from_json() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("recipients.json");
    let json = r#"[
        {
            "address": "shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcug6c",
            "value": 7,
            "asset_id": 1,
            "memo": "alpha"
        },
        {
            "address": "shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwty0x",
            "value": 11,
            "asset_id": 1,
            "memo": "beta"
        },
        {
            "address": "shield1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz4ezw",
            "value": 13,
            "asset_id": 1,
            "memo": "gamma"
        }
    ]"#;
    fs::write(&path, json).expect("write recipients");
    let specs: Vec<RecipientSpec> =
        serde_json::from_slice(&fs::read(&path).expect("read")).expect("parse recipients");

    let randomized = randomize_recipient_specs(&specs, true);
    assert_eq!(randomized.len(), specs.len());
    assert_ne!(
        randomized, specs,
        "randomization should shuffle memo order when specs are distinct"
    );
}
