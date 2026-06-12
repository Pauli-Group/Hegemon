use serde::Deserialize;
use synthetic_crypto::note_encryption::NoteCiphertext as CryptoNoteCiphertext;
use wallet::NoteCiphertext as WalletNoteCiphertext;

#[derive(Debug, Deserialize)]
struct VectorFile {
    schema_version: u32,
    note_ciphertext_wire_cases: Vec<VectorCase>,
}

#[derive(Debug, Deserialize)]
struct VectorCase {
    name: String,
    format: String,
    wire_hex: String,
    expected_valid: bool,
    expected_summary: Option<ExpectedSummary>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct ExpectedSummary {
    version: u8,
    crypto_suite: u16,
    diversifier_index: u32,
    kem_len: usize,
    note_payload_len: usize,
    memo_payload_len: usize,
}

fn decode_hex(input: &str) -> Vec<u8> {
    let hex = input.strip_prefix("0x").unwrap_or(input);
    hex::decode(hex).expect("valid hex vector")
}

#[test]
fn lean_generated_note_ciphertext_wire_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_NOTE_CIPHERTEXT_WIRE_VECTORS") else {
        eprintln!(
            "HEGEMON_LEAN_NOTE_CIPHERTEXT_WIRE_VECTORS not set; skipping generated Lean vector check"
        );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean note-ciphertext wire vectors");
    let vectors: VectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean note-ciphertext wire vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.note_ciphertext_wire_cases.is_empty(),
        "Lean note-ciphertext wire cases must not be empty"
    );

    let mut names = std::collections::BTreeSet::new();
    for case in &vectors.note_ciphertext_wire_cases {
        assert!(names.insert(case.name.clone()), "duplicate case name");
        verify_case(case);
    }
}

fn verify_case(case: &VectorCase) {
    let bytes = decode_hex(&case.wire_hex);
    let actual = match case.format.as_str() {
        "crypto" => CryptoNoteCiphertext::from_bytes(&bytes)
            .map(|ct| ExpectedSummary {
                version: ct.version,
                crypto_suite: ct.crypto_suite,
                diversifier_index: ct.diversifier_index,
                kem_len: ct.kem_ciphertext.len(),
                note_payload_len: ct.note_payload.len(),
                memo_payload_len: ct.memo_payload.len(),
            })
            .map_err(|_| ()),
        "chain" => WalletNoteCiphertext::from_chain_bytes(&bytes)
            .map(|ct| ExpectedSummary {
                version: ct.version,
                crypto_suite: ct.crypto_suite,
                diversifier_index: ct.diversifier_index,
                kem_len: ct.kem_ciphertext.len(),
                note_payload_len: ct.note_payload.len(),
                memo_payload_len: ct.memo_payload.len(),
            })
            .map_err(|_| ()),
        other => panic!("unsupported vector format {other}"),
    };

    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "validity mismatch for {}",
        case.name
    );
    if case.expected_valid {
        assert_eq!(
            actual.ok().as_ref(),
            case.expected_summary.as_ref(),
            "summary mismatch for {}",
            case.name
        );
    }
}
