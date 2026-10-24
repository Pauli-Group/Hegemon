//! Separate, inactive non-native asset candidate. Native PrivateSpend remains native-only.
//!
//! A proof authenticates two note inputs, three outputs, credential
//! membership through reference height H+12, issuer knowledge for minting, and
//! separate asset/native balances. H+12 must fit in 48 bits; every active asset
//! input/payment/change credential covers that horizon, including zero change.
//! Public policy_mode selects an ordinary-only graph or the shared bounded-policy
//! graph, revealing that choice. The asset input/payment may use that exact
//! interpreter; current credentials, freeze and balances stay outside every OR.
//! The caller MUST authenticate every disclosed policy field against the current
//! registry root and apply the issuance counters before accepting this proof.
//! Compilation and candidate proof verification do not create release authority.
#![forbid(unsafe_code)]

#[path = "asset_spend_v1/circuit.rs"]
mod circuit;
#[path = "asset_spend_v1/helpers.rs"]
mod helpers;
#[path = "asset_spend_v1/proof.rs"]
mod proof;
#[path = "asset_spend_v1/types.rs"]
mod types;

pub use circuit::{compile, AssetSpendAdapter};
pub use helpers::*;
pub use proof::*;
pub use types::*;

/// Disposable deterministic fixtures, absent from normal production builds.
#[cfg(any(test, feature = "private-spend-dev-artifacts"))]
#[path = "asset_spend_v1/fixtures.rs"]
pub mod fixtures;

pub(crate) fn error(message: &'static str) -> crate::TransactionCircuitError {
    crate::TransactionCircuitError::ConstraintViolation(message)
}

/// Source identity includes the actual graph, compression and proof backend.
/// It is a provenance binding, not a proof of Rust/Lean equivalence.
pub fn relation_digest() -> [u8; 64] {
    use sha2::{Digest as _, Sha512};
    static DIGEST: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut hash = Sha512::new();
        hash.update(b"Hegemon.AssetSpend.SourceManifest.v2");
        hash.update(RELATION_ID.as_bytes());
        let sources: &[(&str, &[u8])] = &[
            ("asset_spend_v1.rs", include_bytes!("asset_spend_v1.rs")),
            (
                "asset_spend_v1/types.rs",
                include_bytes!("asset_spend_v1/types.rs"),
            ),
            (
                "asset_spend_v1/circuit.rs",
                include_bytes!("asset_spend_v1/circuit.rs"),
            ),
            (
                "asset_spend_v1/helpers.rs",
                include_bytes!("asset_spend_v1/helpers.rs"),
            ),
            (
                "asset_spend_v1/proof.rs",
                include_bytes!("asset_spend_v1/proof.rs"),
            ),
            (
                "private_spend/types.rs",
                include_bytes!("private_spend/types.rs"),
            ),
            (
                "private_spend/helpers.rs",
                include_bytes!("private_spend/helpers.rs"),
            ),
            (
                "private_spend/circuit.rs",
                include_bytes!("private_spend/circuit.rs"),
            ),
            (
                "../../transaction-core/src/bounded_policy.rs",
                include_bytes!("../../transaction-core/src/bounded_policy.rs"),
            ),
            (
                "smallwood_htlc/sha256.rs",
                include_bytes!("smallwood_htlc/sha256.rs"),
            ),
            (
                "smallwood_htlc/circuit.rs",
                include_bytes!("smallwood_htlc/circuit.rs"),
            ),
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
                "../../transaction-core/src/stablecoin_poseidon2_v8.rs",
                include_bytes!("../../transaction-core/src/stablecoin_poseidon2_v8.rs"),
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
                "../../../crypto/src/asset_note_encryption_v1.rs",
                include_bytes!("../../../crypto/src/asset_note_encryption_v1.rs"),
            ),
            (
                "../../../crypto/src/private_note_encryption.rs",
                include_bytes!("../../../crypto/src/private_note_encryption.rs"),
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
            ("../../../Cargo.lock", include_bytes!("../../../Cargo.lock")),
        ];
        for (path, bytes) in sources {
            hash.update((path.len() as u64).to_le_bytes());
            hash.update(path.as_bytes());
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        hash.finalize().into()
    })
}

#[cfg(test)]
#[path = "asset_spend_v1/tests.rs"]
mod tests;
