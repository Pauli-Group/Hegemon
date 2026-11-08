//! Finite conformance to an independently executed Lean Nat/Int model.
//! This test is not a general Rust refinement or a security certification.
use consensus_light_client::{
    asert_next_bits, bitcoin80_validate_compact, AsertAnchor, LightClientError, PowRulesSchedule,
    BITCOIN80_POW_LIMIT_BITS, HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vectors {
    schema_version: u32,
    model: String,
    claim: String,
    cases: Vec<Case>,
    activation_cases: Vec<ActivationCase>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    anchor_height: u64,
    anchor_parent_timestamp_ms: u64,
    anchor_bits: u32,
    parent_height: u64,
    parent_timestamp_ms: u64,
    spacing_ms: u64,
    half_life_ms: u64,
    expected_bits: Option<u32>,
    expected_result: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationCase {
    activation: u64,
    height: u64,
    valid: bool,
    active: bool,
}

#[test]
fn asert_lean_vectors_match_production_arithmetic_and_schedule() {
    let raw = match std::env::var("HEGEMON_ASERT_FORMAL_VECTORS") {
        Ok(path) => std::fs::read_to_string(path).expect("read freshly generated ASERT vectors"),
        Err(_) => include_str!("../../formal/asert/fixtures/asert-v1.json").to_owned(),
    };
    let vectors: Vectors = serde_json::from_str(&raw).expect("parse Lean ASERT vectors");
    assert_eq!(vectors.schema_version, 1);
    assert_eq!(vectors.model, "Hegemon.Consensus.Asert");
    assert!(vectors.claim.contains("no general Rust refinement"));
    assert_eq!(vectors.cases.len(), 62);
    assert_eq!(vectors.activation_cases.len(), 45);
    let limit = bitcoin80_validate_compact(BITCOIN80_POW_LIMIT_BITS).unwrap();
    for case in vectors.cases {
        let actual = asert_next_bits(
            AsertAnchor {
                height: case.anchor_height,
                parent_timestamp_ms: case.anchor_parent_timestamp_ms,
                pow_bits: case.anchor_bits,
            },
            case.parent_height,
            case.parent_timestamp_ms,
            case.spacing_ms,
            case.half_life_ms,
        );
        let (label, bits) = match actual {
            Ok(bits) => {
                let target = bitcoin80_validate_compact(bits).unwrap();
                assert!(target > [0; 32] && target <= limit, "{}", case.name);
                ("accepted", Some(bits))
            }
            Err(LightClientError::InvalidAsertParameters) => ("invalid_parameters", None),
            Err(LightClientError::InvalidAsertAnchor) => ("invalid_anchor", None),
            Err(LightClientError::InvalidCompactTarget) => ("invalid_compact_target", None),
            Err(LightClientError::AsertArithmeticOverflow) => ("arithmetic_overflow", None),
            Err(error) => panic!("unexpected ASERT result for {}: {error:?}", case.name),
        };
        assert_eq!(label, case.expected_result, "{}", case.name);
        assert_eq!(bits, case.expected_bits, "{}", case.name);
    }
    for case in vectors.activation_cases {
        let schedule = PowRulesSchedule::asert_at(case.activation);
        assert_eq!(
            schedule.is_ok(),
            case.valid,
            "activation {}",
            case.activation
        );
        match schedule {
            Ok(schedule) => assert_eq!(
                schedule.rules_hash(case.height) == HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT,
                case.active,
                "activation {} height {}",
                case.activation,
                case.height,
            ),
            Err(error) => assert_eq!(error, LightClientError::InvalidPowRulesSchedule),
        }
    }
}
