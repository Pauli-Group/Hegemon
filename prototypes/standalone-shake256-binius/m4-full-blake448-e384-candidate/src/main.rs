//! Disk-gated compiled-geometry driver for the exact mixed M4 candidate.

#![forbid(unsafe_code)]

use hegemon_m4_full_blake448_e384_candidate::mixed_candidate::{
    build_candidate_m4, physical_hash_calls, primitive_cores, program_digest,
    raw_blake_addition_linear_words, raw_hash_and_words, raw_hash_rotation_linear_words,
    source_digest, source_static_constraint_ledger, DiagnosticActivationBinding, SecretHashProfile,
    ACTIVE_STABLECOIN_MANIFEST_ADAPTER_INTEGRATED, CANDIDATE_PRIVATE_WORDS,
    CANDIDATE_STATEMENT_BYTES, CANDIDATE_STATEMENT_WORDS, COMPLETE_ZERO_KNOWLEDGE_PROVED,
    COMPOSED_QROM_PQ128_PROVED, E384_PCS_CHANNEL_INTEGRATED, IDENTITY_FROZEN,
    M4_AGGREGATE_RELATION_ARTIFACT_VERIFIED, PRODUCTION_AUTHORIZED, WINNER,
};

fn diagnostic_activation() -> DiagnosticActivationBinding {
    DiagnosticActivationBinding {
        circuit_version: 0x4481,
        crypto_suite: 0x4482,
        family_id: 0x4483,
        action_id: 0x4484,
        network_id: 7,
        backend_id: 0x45,
        proof_profile: 0x46,
        domain_set: 0x4487,
        chain_id: [1; 56],
        genesis_id: [2; 56],
        rules_hash: [3; 56],
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn profile_from_arg(arg: &str) -> SecretHashProfile {
    match arg {
        "blake" | "blake2b448-mixed" => SecretHashProfile::Blake2b448Mixed,
        "sha3" | "sha3-512-split-control" => SecretHashProfile::Sha3_512SplitControl,
        _ => panic!("profile must be `blake` or `sha3`"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let profile = args
        .get(1)
        .map(|arg| profile_from_arg(arg))
        .unwrap_or(SecretHashProfile::Blake2b448Mixed);
    let activation = diagnostic_activation();
    println!(
        "profile={} statement_bytes={} statement_words={} private_words={} calls={} cores={} raw_hash_and_words={} raw_blake_addition_linear_words={} raw_hash_rotation_linear_words={} source_static_hash_ledger={:?} winner={WINNER:?} production={PRODUCTION_AUTHORIZED} aggregate_artifact_verified={M4_AGGREGATE_RELATION_ARTIFACT_VERIFIED} zk={COMPLETE_ZERO_KNOWLEDGE_PROVED} qrom_pq128={COMPOSED_QROM_PQ128_PROVED} e384_pcs={E384_PCS_CHANNEL_INTEGRATED} stablecoin_manifest_adapter={ACTIVE_STABLECOIN_MANIFEST_ADAPTER_INTEGRATED} identity_frozen={IDENTITY_FROZEN} program_sha512={} source_sha512={}",
        profile.name(),
        CANDIDATE_STATEMENT_BYTES,
        CANDIDATE_STATEMENT_WORDS,
        CANDIDATE_PRIVATE_WORDS,
        physical_hash_calls(profile),
        primitive_cores(profile),
        raw_hash_and_words(profile),
        raw_blake_addition_linear_words(profile),
        raw_hash_rotation_linear_words(profile),
        source_static_constraint_ledger(profile),
        hex(&program_digest(profile, activation)),
        hex(&source_digest()),
    );

    if args.iter().any(|arg| arg == "--compile-geometry") {
        assert_eq!(
            std::env::var("HEGEMON_M4_ALLOW_COMPILE_GEOMETRY").as_deref(),
            Ok("1"),
            "compiled geometry is disk-gated; set HEGEMON_M4_ALLOW_COMPILE_GEOMETRY=1 only after the >=28 GiB gate passes"
        );
        let candidate = build_candidate_m4(profile, activation);
        let geometry = candidate.compiled_geometry();
        println!("compiled_geometry={geometry:?}");
    } else {
        println!("compiled_geometry=not_run disk_gate_required=true");
    }
}
