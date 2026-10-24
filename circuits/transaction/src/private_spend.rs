//! One static, native-only relation for private ordinary/treasury/HTLC spending.
//! This module implements constraints and witness lowering, not a proof wrapper,
//! production profile, transport, ciphertext implementation or release authority.
#![forbid(unsafe_code)]
#[path = "private_spend/circuit.rs"]
pub(crate) mod circuit;
#[path = "private_spend/helpers.rs"]
mod helpers;
#[path = "private_spend/proof.rs"]
mod proof;
#[path = "private_spend/types.rs"]
mod types;
use crate::TransactionCircuitError;
pub use circuit::{compile, PrivateSpendAdapter};
pub use helpers::*;
pub use proof::*;
pub use types::*;
/// Disposable qualification fixtures, absent from normal builds.
#[cfg(feature = "private-spend-dev-artifacts")]
#[path = "private_spend/qualification.rs"]
pub mod qualification;
pub(crate) fn error(s: &'static str) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolation(s)
}
#[cfg(test)]
#[path = "private_spend/policy_tests.rs"]
mod policy_tests;
#[cfg(test)]
#[path = "private_spend/tests.rs"]
mod tests;

/// Source identity for the new candidate, including inherited arithmetic and hash code.
/// This is not production authorization or a proof of implementation refinement.
pub fn relation_digest() -> [u8; 64] {
    use sha2::{Digest as _, Sha512};
    static DIGEST: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut h = Sha512::new();
        h.update(b"Hegemon.PrivateSpend.SourceManifest.v1");
        h.update(RELATION_ID.as_bytes());
        let files: &[(&str, &[u8])] = &[
            ("private_spend.rs", include_bytes!("private_spend.rs")),
            (
                "private_spend/types.rs",
                include_bytes!("private_spend/types.rs"),
            ),
            (
                "private_spend/circuit.rs",
                include_bytes!("private_spend/circuit.rs"),
            ),
            (
                "private_spend/helpers.rs",
                include_bytes!("private_spend/helpers.rs"),
            ),
            (
                "private_spend/proof.rs",
                include_bytes!("private_spend/proof.rs"),
            ),
            (
                "smallwood_htlc/circuit.rs",
                include_bytes!("smallwood_htlc/circuit.rs"),
            ),
            (
                "smallwood_htlc/sha256.rs",
                include_bytes!("smallwood_htlc/sha256.rs"),
            ),
            ("smallwood_htlc.rs", include_bytes!("smallwood_htlc.rs")),
            ("smallwood_engine.rs", include_bytes!("smallwood_engine.rs")),
            (
                "smallwood_semantics.rs",
                include_bytes!("smallwood_semantics.rs"),
            ),
            (
                "smallwood_hx512_transcript.rs",
                include_bytes!("smallwood_hx512_transcript.rs"),
            ),
            (
                "smallwood_v6_transcript.rs",
                include_bytes!("smallwood_v6_transcript.rs"),
            ),
            (
                "smallwood_poseidon2_v8_rng_refinement.rs",
                include_bytes!("smallwood_poseidon2_v8_rng_refinement.rs"),
            ),
            (
                "smallwood_poseidon2_v8_hash_schedule.rs",
                include_bytes!("smallwood_poseidon2_v8_hash_schedule.rs"),
            ),
            (
                "smallwood_poseidon2_v8_types.rs",
                include_bytes!("smallwood_poseidon2_v8_types.rs"),
            ),
            (
                "../../transaction-core/src/constants.rs",
                include_bytes!("../../transaction-core/src/constants.rs"),
            ),
            (
                "../../transaction-core/src/poseidon2_width16.rs",
                include_bytes!("../../transaction-core/src/poseidon2_width16.rs"),
            ),
            (
                "../../transaction-core/src/poseidon2.rs",
                include_bytes!("../../transaction-core/src/poseidon2.rs"),
            ),
            (
                "../../transaction-core/src/hashing_pq.rs",
                include_bytes!("../../transaction-core/src/hashing_pq.rs"),
            ),
            (
                "../../hegemon-field/src/lib.rs",
                include_bytes!("../../hegemon-field/src/lib.rs"),
            ),
            (
                "../../../crypto/src/private_note_encryption.rs",
                include_bytes!("../../../crypto/src/private_note_encryption.rs"),
            ),
            (
                "../../../crypto/src/private_note_payload.rs",
                include_bytes!("../../../crypto/src/private_note_payload.rs"),
            ),
            (
                "../../../crypto/src/ml_kem.rs",
                include_bytes!("../../../crypto/src/ml_kem.rs"),
            ),
            (
                "../../../crypto/src/deterministic.rs",
                include_bytes!("../../../crypto/src/deterministic.rs"),
            ),
            (
                "../../../crypto/src/traits.rs",
                include_bytes!("../../../crypto/src/traits.rs"),
            ),
            (
                "../../../crypto/hash384/src/lib.rs",
                include_bytes!("../../../crypto/hash384/src/lib.rs"),
            ),
            (
                "../../../protocol/shielded-pool/src/private_spend_transport.rs",
                include_bytes!("../../../protocol/shielded-pool/src/private_spend_transport.rs"),
            ),
            (
                "../../../protocol/versioning/src/launch_candidate_identity.rs",
                include_bytes!("../../../protocol/versioning/src/launch_candidate_identity.rs"),
            ),
            (
                "../../transaction-core/src/bounded_policy.rs",
                include_bytes!("../../transaction-core/src/bounded_policy.rs"),
            ),
            ("lib.rs", include_bytes!("lib.rs")),
            ("smallwood_htlc/affine.rs", include_bytes!("smallwood_htlc/affine.rs")),
            ("smallwood_htlc/boolean_guards.rs", include_bytes!("smallwood_htlc/boolean_guards.rs")),
            ("smallwood_htlc/source_cse.rs", include_bytes!("smallwood_htlc/source_cse.rs")),
            ("smallwood_htlc/sha_lowering.rs", include_bytes!("smallwood_htlc/sha_lowering.rs")),
            ("smallwood_htlc/compact_sha256.rs", include_bytes!("smallwood_htlc/compact_sha256.rs")),
            ("smallwood_htlc/compact_sha_certificate.rs", include_bytes!("smallwood_htlc/compact_sha_certificate.rs")),
            ("smallwood_htlc/compact_sha_lowering.rs", include_bytes!("smallwood_htlc/compact_sha_lowering.rs")),
            ("smallwood_htlc/packed_poseidon_lowering.rs", include_bytes!("smallwood_htlc/packed_poseidon_lowering.rs")),
            ("private_spend_packed_poseidon.rs", include_bytes!("private_spend_packed_poseidon.rs")),
            ("smallwood_poseidon2_v8_hash_constraints.rs", include_bytes!("smallwood_poseidon2_v8_hash_constraints.rs")),
            ("../../../Cargo.lock", include_bytes!("../../../Cargo.lock")),
        ];
        for (path, bytes) in files {
            h.update((path.len() as u64).to_le_bytes());
            h.update(path.as_bytes());
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        h.finalize().into()
    })
}
