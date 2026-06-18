use serde::Deserialize;
use synthetic_crypto::note_encryption::NoteCiphertext as CryptoNoteCiphertext;
use transaction_circuit::hashing_pq::ciphertext_hash_bytes;
use wallet::{
    AddressKeyMaterial, MemoPlaintext, NoteCiphertext as WalletNoteCiphertext, NotePlaintext,
    RootSecret, WalletError,
};

#[derive(Debug, Deserialize)]
struct VectorFile {
    schema_version: u32,
    production_profile: ProductionProfile,
    note_ciphertext_wire_cases: Vec<VectorCase>,
    note_ciphertext_decrypt_cases: Vec<DecryptVectorCase>,
}

#[derive(Debug, Deserialize)]
struct ProductionProfile {
    note_aead_label_hex: String,
    memo_aead_label_hex: String,
    aead_kdf_domain_hex: String,
    kem_randomness_len: usize,
    aead_key_len: usize,
    aead_nonce_len: usize,
    aead_tag_len: usize,
    note_plaintext_payload_len: usize,
    metadata_aad_len: usize,
    chain_ciphertext_size: usize,
    chain_compact_kem_len_hex: String,
    ml_kem_ciphertext_len: usize,
    sample_metadata_aad_hex: String,
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
    expected_projected_da_valid: bool,
    expected_projected_da_summary: Option<ExpectedSummary>,
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

#[derive(Debug, Deserialize)]
struct DecryptVectorCase {
    name: String,
    production_fixture: String,
    ciphertext: ExpectedSummary,
    material: ExpectedDecryptMaterial,
    crypto_authenticates: bool,
    expected_accept: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct ExpectedDecryptMaterial {
    version: u8,
    crypto_suite: u16,
    diversifier_index: u32,
}

const ML_KEM_COMPACT_LEN_BYTES: usize = 2;
const DECRYPT_FIXTURE_ADDRESS_INDEX: u32 = 7;

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
    assert_eq!(vectors.schema_version, 7);
    verify_production_profile(&vectors.production_profile);
    assert!(
        !vectors.note_ciphertext_wire_cases.is_empty(),
        "Lean note-ciphertext wire cases must not be empty"
    );
    assert!(
        !vectors.note_ciphertext_decrypt_cases.is_empty(),
        "Lean note-ciphertext decrypt cases must not be empty"
    );

    let mut names = std::collections::BTreeSet::new();
    for case in &vectors.note_ciphertext_wire_cases {
        assert!(names.insert(case.name.clone()), "duplicate case name");
        verify_case(case);
    }
    verify_alternate_chain_fixture(&vectors.note_ciphertext_wire_cases);

    let mut decrypt_names = std::collections::BTreeSet::new();
    for case in &vectors.note_ciphertext_decrypt_cases {
        assert!(
            decrypt_names.insert(case.name.clone()),
            "duplicate decrypt case name"
        );
        verify_decrypt_case(case);
    }
}

fn verify_production_profile(profile: &ProductionProfile) {
    assert_eq!(
        decode_hex(&profile.note_aead_label_hex),
        wallet::notes::NOTE_CIPHERTEXT_NOTE_AEAD_LABEL,
        "Lean note AEAD payload label drifted from wallet profile"
    );
    assert_eq!(
        decode_hex(&profile.memo_aead_label_hex),
        wallet::notes::NOTE_CIPHERTEXT_MEMO_AEAD_LABEL,
        "Lean memo AEAD payload label drifted from wallet profile"
    );
    assert_ne!(
        profile.note_aead_label_hex, profile.memo_aead_label_hex,
        "note and memo AEAD labels must stay domain separated"
    );
    assert_eq!(
        decode_hex(&profile.aead_kdf_domain_hex),
        wallet::notes::NOTE_CIPHERTEXT_AEAD_KDF_DOMAIN,
        "Lean AEAD KDF domain drifted from wallet profile"
    );
    assert_eq!(
        profile.kem_randomness_len,
        wallet::notes::NOTE_CIPHERTEXT_KEM_RANDOMNESS_LEN
    );
    assert_eq!(
        profile.aead_key_len,
        wallet::notes::NOTE_CIPHERTEXT_AEAD_KEY_LEN
    );
    assert_eq!(
        profile.aead_nonce_len,
        wallet::notes::NOTE_CIPHERTEXT_AEAD_NONCE_LEN
    );
    assert_eq!(
        profile.aead_tag_len,
        wallet::notes::NOTE_CIPHERTEXT_AEAD_TAG_LEN
    );
    assert_eq!(
        profile.note_plaintext_payload_len,
        wallet::notes::NOTE_CIPHERTEXT_PLAINTEXT_PAYLOAD_LEN
    );
    assert_eq!(
        profile.metadata_aad_len,
        wallet::notes::NOTE_CIPHERTEXT_METADATA_AAD_LEN
    );
    assert_eq!(
        profile.chain_ciphertext_size,
        wallet::notes::CHAIN_CIPHERTEXT_SIZE
    );
    assert_eq!(
        decode_hex(&profile.chain_compact_kem_len_hex),
        (synthetic_crypto::ml_kem::ML_KEM_CIPHERTEXT_LEN as u16 * 4 + 1)
            .to_le_bytes()
            .to_vec(),
        "Lean chain compact ML-KEM length drifted from production SCALE compact bytes"
    );
    assert_eq!(
        profile.ml_kem_ciphertext_len,
        synthetic_crypto::ml_kem::ML_KEM_CIPHERTEXT_LEN
    );
    assert_eq!(
        decode_hex(&profile.sample_metadata_aad_hex),
        wallet::notes::note_ciphertext_aad_bytes(
            3,
            protocol_versioning::CRYPTO_SUITE_GAMMA,
            DECRYPT_FIXTURE_ADDRESS_INDEX
        )
        .to_vec(),
        "Lean sample metadata AAD drifted from wallet production AAD bytes"
    );
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
        assert_eq!(
            summary_from_wallet_ciphertext(&ciphertext),
            *case
                .expected_summary
                .as_ref()
                .expect("valid chain vector includes summary"),
            "production chain parser summary mismatch for {}",
            case.name
        );
        let production_da_bytes = ciphertext
            .to_da_bytes()
            .expect("valid chain vector converts to production DA bytes");
        assert_eq!(
            production_da_bytes, expected_da_bytes,
            "production DA bytes mismatch for {}",
            case.name
        );
        let projected_da_actual = WalletNoteCiphertext::from_da_bytes(&expected_da_bytes)
            .map(|ct| summary_from_wallet_ciphertext(&ct))
            .map_err(|_| ());
        assert_eq!(
            projected_da_actual.is_ok(),
            case.expected_projected_da_valid,
            "projected DA validity mismatch for {}",
            case.name
        );
        assert_eq!(
            projected_da_actual.ok().as_ref(),
            case.expected_projected_da_summary.as_ref(),
            "projected DA summary mismatch for {}",
            case.name
        );
        assert_eq!(
            case.expected_projected_da_summary.as_ref(),
            case.expected_summary.as_ref(),
            "valid chain projection must parse as DA with the same summary for {}",
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
        assert!(
            !case.expected_projected_da_valid,
            "direct DA vector must not carry chain-projected DA metadata for {}",
            case.name
        );
        assert!(
            case.expected_projected_da_summary.is_none(),
            "direct DA vector must not carry projected DA summary for {}",
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
        assert!(
            !case.expected_projected_da_valid,
            "non-valid-chain vector must not expose projected DA validity for {}",
            case.name
        );
        assert!(
            case.expected_projected_da_summary.is_none(),
            "non-valid-chain vector must not expose projected DA summary for {}",
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

fn summary_from_wallet_ciphertext(ciphertext: &WalletNoteCiphertext) -> ExpectedSummary {
    ExpectedSummary {
        version: ciphertext.version,
        crypto_suite: ciphertext.crypto_suite,
        diversifier_index: ciphertext.diversifier_index,
        kem_len: ciphertext.kem_ciphertext.len(),
        note_payload_len: ciphertext.note_payload.len(),
        memo_payload_len: ciphertext.memo_payload.len(),
    }
}

fn material_summary(material: &AddressKeyMaterial) -> ExpectedDecryptMaterial {
    ExpectedDecryptMaterial {
        version: material.version(),
        crypto_suite: material.crypto_suite(),
        diversifier_index: material.diversifier_index,
    }
}

fn sample_material_note_ciphertext(
    seed: u64,
    memo: &[u8],
) -> (AddressKeyMaterial, NotePlaintext, WalletNoteCiphertext) {
    use rand::{rngs::StdRng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(seed);
    let root = RootSecret::from_rng(&mut rng);
    let keys = root.derive();
    let material = keys
        .address(DECRYPT_FIXTURE_ADDRESS_INDEX)
        .expect("derive fixture address");
    let address = material.shielded_address();
    let note = NotePlaintext::random(100, 0, MemoPlaintext::new(memo.to_vec()), &mut rng);
    let ciphertext =
        WalletNoteCiphertext::encrypt(&address, &note, &mut rng).expect("encrypt fixture note");
    (material, note, ciphertext)
}

fn wrong_material(seed: u64) -> AddressKeyMaterial {
    use rand::{rngs::StdRng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(seed);
    RootSecret::from_rng(&mut rng)
        .derive()
        .address(DECRYPT_FIXTURE_ADDRESS_INDEX)
        .expect("derive wrong-recipient fixture address")
}

fn lean_model_rejection(case: &DecryptVectorCase) -> Option<&'static str> {
    if case.ciphertext.version != case.material.version {
        Some("version_mismatch")
    } else if case.ciphertext.crypto_suite != case.material.crypto_suite {
        Some("crypto_suite_mismatch")
    } else if case.ciphertext.diversifier_index != case.material.diversifier_index {
        Some("diversifier_mismatch")
    } else if !case.crypto_authenticates {
        Some("crypto_failure")
    } else {
        None
    }
}

fn production_rejection(result: Result<NotePlaintext, WalletError>) -> Option<&'static str> {
    match result {
        Ok(_) => None,
        Err(WalletError::NoteMismatch("note version mismatch")) => Some("version_mismatch"),
        Err(WalletError::NoteMismatch("note crypto suite mismatch")) => {
            Some("crypto_suite_mismatch")
        }
        Err(WalletError::NoteMismatch("diversifier index mismatch")) => {
            Some("diversifier_mismatch")
        }
        Err(WalletError::DecryptionFailure) => Some("crypto_failure"),
        Err(other) => panic!("unexpected production decrypt result: {other:?}"),
    }
}

fn verify_decrypt_case(case: &DecryptVectorCase) {
    let expected_rejection = case.expected_rejection.as_deref();
    assert_eq!(
        case.expected_accept,
        expected_rejection.is_none(),
        "decrypt accept/rejection metadata disagrees for {}",
        case.name
    );
    assert_eq!(
        lean_model_rejection(case),
        expected_rejection,
        "Rust mirror of Lean decrypt admission disagrees for {}",
        case.name
    );

    let (material, expected_note, mut ciphertext) = sample_material_note_ciphertext(940, b"memo");
    let mut decrypt_material = material.clone();
    match case.production_fixture.as_str() {
        "valid" => {}
        "wrong-version" => ciphertext.version = ciphertext.version.wrapping_add(1),
        "wrong-crypto-suite" => ciphertext.crypto_suite = ciphertext.crypto_suite.wrapping_add(1),
        "wrong-diversifier" => {
            ciphertext.diversifier_index = ciphertext.diversifier_index.wrapping_add(1);
        }
        "wrong-recipient" => decrypt_material = wrong_material(941),
        "malleated-kem" => ciphertext.kem_ciphertext[0] ^= 0x01,
        "malleated-note-payload" => ciphertext.note_payload[0] ^= 0x01,
        "malleated-memo-payload" => ciphertext.memo_payload[0] ^= 0x01,
        other => panic!("unsupported decrypt production fixture {other}"),
    }

    assert_eq!(
        summary_from_wallet_ciphertext(&ciphertext),
        case.ciphertext,
        "decrypt ciphertext summary mismatch for {}",
        case.name
    );
    assert_eq!(
        material_summary(&decrypt_material),
        case.material,
        "decrypt material summary mismatch for {}",
        case.name
    );

    let production = ciphertext.decrypt(&decrypt_material);
    if case.expected_accept {
        assert_eq!(
            production.expect("valid decrypt fixture must decrypt"),
            expected_note,
            "valid decrypt fixture plaintext mismatch for {}",
            case.name
        );
    } else {
        assert_eq!(
            production_rejection(production),
            expected_rejection,
            "production decrypt rejection mismatch for {}",
            case.name
        );
    }
}

fn verify_alternate_chain_fixture(cases: &[VectorCase]) {
    let valid = cases
        .iter()
        .find(|case| case.name == "chain-valid")
        .expect("chain-valid vector present");
    let alternate = cases
        .iter()
        .find(|case| case.name == "chain-alternate-valid-same-summary-different-wire")
        .expect("alternate chain vector present");

    assert_eq!(
        valid.expected_summary.as_ref(),
        alternate.expected_summary.as_ref(),
        "alternate chain fixture must preserve public parser summary"
    );
    assert_ne!(
        valid.wire_hex, alternate.wire_hex,
        "alternate chain fixture must change raw chain wire bytes"
    );

    let valid_da = decode_hex(
        valid
            .expected_da_hex
            .as_ref()
            .expect("valid chain vector has projected DA bytes"),
    );
    let alternate_da = decode_hex(
        alternate
            .expected_da_hex
            .as_ref()
            .expect("alternate chain vector has projected DA bytes"),
    );
    assert_ne!(
        valid_da, alternate_da,
        "alternate chain fixture must change projected DA bytes"
    );
    assert_ne!(
        ciphertext_hash_bytes(&valid_da),
        ciphertext_hash_bytes(&alternate_da),
        "same-summary alternate ciphertexts must bind different DA hash preimages"
    );
}
