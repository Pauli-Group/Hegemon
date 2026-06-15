use serde::Deserialize;
use synthetic_crypto::note_encryption::NoteCiphertext as CryptoNoteCiphertext;
use transaction_circuit::hashing_pq::ciphertext_hash_bytes;
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
    expected_wire_len: usize,
    expected_valid: bool,
    expected_summary: Option<ExpectedSummary>,
    expected_da_hex: Option<String>,
    expected_da_len: Option<usize>,
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

const ML_KEM_COMPACT_LEN_BYTES: usize = 2;

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
    assert_eq!(vectors.schema_version, 3);
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
    assert_eq!(
        bytes.len(),
        case.expected_wire_len,
        "wire length mismatch for {}",
        case.name
    );
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
        "da" => WalletNoteCiphertext::from_da_bytes(&bytes)
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
    if case.format == "chain" && case.expected_valid {
        assert_eq!(
            case.expected_wire_len,
            wallet::notes::CHAIN_CIPHERTEXT_SIZE
                + ML_KEM_COMPACT_LEN_BYTES
                + synthetic_crypto::ml_kem::ML_KEM_CIPHERTEXT_LEN,
            "fixed chain wire length mismatch for {}",
            case.name
        );
        let expected_da_hex = case
            .expected_da_hex
            .as_ref()
            .expect("valid chain vector includes DA bytes");
        let expected_da_bytes = decode_hex(expected_da_hex);
        assert_eq!(
            case.expected_da_len,
            Some(expected_da_bytes.len()),
            "DA length metadata mismatch for {}",
            case.name
        );
        assert_eq!(
            expected_da_bytes.len(),
            wallet::notes::CHAIN_CIPHERTEXT_SIZE + synthetic_crypto::ml_kem::ML_KEM_CIPHERTEXT_LEN,
            "fixed DA ciphertext length mismatch for {}",
            case.name
        );

        let mut projected_da_bytes = Vec::with_capacity(bytes.len() - ML_KEM_COMPACT_LEN_BYTES);
        projected_da_bytes.extend_from_slice(&bytes[..wallet::notes::CHAIN_CIPHERTEXT_SIZE]);
        projected_da_bytes.extend_from_slice(
            &bytes[wallet::notes::CHAIN_CIPHERTEXT_SIZE + ML_KEM_COMPACT_LEN_BYTES..],
        );
        assert_eq!(
            projected_da_bytes, expected_da_bytes,
            "Lean DA projection mismatch for {}",
            case.name
        );

        let ciphertext = WalletNoteCiphertext::from_chain_bytes(&bytes)
            .expect("valid chain vector parses as wallet ciphertext");
        let production_da_bytes = ciphertext
            .to_da_bytes()
            .expect("valid chain vector converts to production DA bytes");
        assert_eq!(
            production_da_bytes, expected_da_bytes,
            "production DA bytes mismatch for {}",
            case.name
        );
        assert_eq!(
            ciphertext_hash_bytes(&production_da_bytes),
            ciphertext_hash_bytes(&expected_da_bytes),
            "production ciphertext hash must use the Lean-projected DA preimage for {}",
            case.name
        );
    } else if case.format == "da" && case.expected_valid {
        assert_eq!(
            case.expected_wire_len,
            wallet::notes::CHAIN_CIPHERTEXT_SIZE + synthetic_crypto::ml_kem::ML_KEM_CIPHERTEXT_LEN,
            "fixed DA wire length mismatch for {}",
            case.name
        );
        let ciphertext = WalletNoteCiphertext::from_da_bytes(&bytes)
            .expect("valid DA vector parses as wallet ciphertext");
        assert_eq!(
            ciphertext
                .to_da_bytes()
                .expect("valid DA vector roundtrips"),
            bytes,
            "production DA parser must roundtrip strict DA bytes for {}",
            case.name
        );
    } else {
        assert!(
            case.expected_da_hex.is_none(),
            "non-valid-chain vector must not expose DA bytes for {}",
            case.name
        );
        assert!(
            case.expected_da_len.is_none(),
            "non-valid-chain vector must not expose DA length for {}",
            case.name
        );
    }
    if case.expected_valid {
        assert_eq!(
            actual.ok().as_ref(),
            case.expected_summary.as_ref(),
            "summary mismatch for {}",
            case.name
        );
    }
}
