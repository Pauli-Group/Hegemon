//! Recovery envelope around the unchanged SMZE implementation and numeric profile.
//!
//! SMZR is an outer versioned envelope, not a relabeled inner proof. Header80:
//! magic4 | version u16LE | route u8 | zero u8 | compiled source64 |
//! inner length u32LE | zero u32LE. The remainder is exactly canonical SMZE.
//! Full public binding is HGRECOV1 | route u64LE | canonical public u64 words:
//! route1 spend182, route2 source-separated Compact22 capsule-segment82, route3 controls128. Its SHA512 and the
//! compiled source digest are encoded as u32 limbs in the fixed134-word SMZE
//! transcript statement. Callers supply their compiled relation_digest(), never
//! a source identity selected from the untrusted envelope, and include this file
//! in that source closure. The adapter keeps the original AssetSpend arith tag.
//! This wrapper adds no production authority or inherited-backend security claim.
#![forbid(unsafe_code)]

use crate::{
    smallwood_engine::{
        self, SmallwoodDecsEvaluationDomain, SmallwoodTranscriptBackend,
        ASSET_SPEND_SMZE_SMALLWOOD_NO_GRINDING_PROFILE,
    },
    smallwood_semantics::SmallwoodConstraintAdapter,
    TransactionCircuitError,
};
use sha2::{Digest, Sha512};

pub const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
pub const OUTER_HEADER_BYTES: usize = 80;
const FIELD_ORDER: u64 = 0xffff_ffff_0000_0001;
const TRANSCRIPT_DOMAIN: u64 = u64::from_le_bytes(*b"HGRCBE01");
const VERSION: u16 = 1;
fn error(message: &'static str) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolation(message)
}

fn route(full_binding: &[u8]) -> Result<u8, TransactionCircuitError> {
    if full_binding.len() < 16 || &full_binding[..8] != b"HGRECOV1" {
        return Err(error("SMZR full binding header differs"));
    }
    let selector = u64::from_le_bytes(full_binding[8..16].try_into().unwrap());
    let words = match selector {
        1 => 182,
        2 => crate::asset_recovery_capsule_v1::PUBLIC_WORDS,
        3 => 128,
        _ => return Err(error("SMZR full binding route differs")),
    };
    if full_binding.len() != 16 + words * 8
        || full_binding[16..]
            .chunks_exact(8)
            .any(|w| u64::from_le_bytes(w.try_into().unwrap()) >= FIELD_ORDER)
    {
        return Err(error("SMZR full binding canonical schema differs"));
    }
    Ok(selector as u8)
}

/// Exactly1072 bytes/134 canonical field words; full public inputs remain in the
/// adapter. Both public commitment and compiled source affect every SMZE leaf.
fn transcript_binding(
    full_binding: &[u8],
    source: &[u8; 64],
) -> Result<[u8; 1072], TransactionCircuitError> {
    let selector = route(full_binding)?;
    let digest: [u8; 64] = Sha512::digest(full_binding).into();
    let mut words = [0u64; 134];
    words[0] = TRANSCRIPT_DOMAIN;
    words[1] = VERSION as u64;
    words[2] = selector as u64;
    for (index, bytes) in source
        .chunks_exact(4)
        .chain(digest.chunks_exact(4))
        .enumerate()
    {
        words[3 + index] = u32::from_le_bytes(bytes.try_into().unwrap()) as u64;
    }
    let mut result = [0u8; 1072];
    for (chunk, word) in result.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Ok(result)
}

struct Envelope<'a> {
    route: u8,
    source: [u8; 64],
    inner: &'a [u8],
}
/// Framing only. Canonical inner parsing is performed separately below.
fn parse_header(proof: &[u8]) -> Result<Envelope<'_>, TransactionCircuitError> {
    if proof.len() < OUTER_HEADER_BYTES + 4 || proof.len() > MAX_PROOF_BYTES {
        return Err(error("SMZR outer proof size differs"));
    }
    if &proof[..4] != b"SMZR"
        || u16::from_le_bytes(proof[4..6].try_into().unwrap()) != VERSION
        || !matches!(proof[6], 1..=3)
        || proof[7] != 0
        || proof[76..80] != [0; 4]
    {
        return Err(error("SMZR outer version/route/reserved header differs"));
    }
    let len = u32::from_le_bytes(proof[72..76].try_into().unwrap()) as usize;
    if len != proof.len() - OUTER_HEADER_BYTES || &proof[80..84] != b"SMZE" {
        return Err(error("SMZR exact inner SMZE framing differs"));
    }
    Ok(Envelope {
        route: proof[6],
        source: proof[8..72].try_into().unwrap(),
        inner: &proof[80..],
    })
}
fn check_expected(
    envelope: &Envelope<'_>,
    selector: u8,
    expected_source: &[u8; 64],
) -> Result<(), TransactionCircuitError> {
    if envelope.route != selector || &envelope.source != expected_source {
        return Err(error("SMZR compiled source or route differs"));
    }
    Ok(())
}
/// Strict wrapper framing plus caller-owned source/route. This does not
/// authenticate a proof; canonical decoding and the verifier still run below.
pub(crate) fn check_component_envelope(
    proof: &[u8],
    selector: u8,
    expected_source: &[u8; 64],
) -> Result<(), TransactionCircuitError> {
    check_expected(&parse_header(proof)?, selector, expected_source)
}
fn assemble(
    inner: &[u8],
    selector: u8,
    source: &[u8; 64],
) -> Result<Vec<u8>, TransactionCircuitError> {
    let len = inner
        .len()
        .checked_add(OUTER_HEADER_BYTES)
        .ok_or(error("SMZR length overflow"))?;
    if len > MAX_PROOF_BYTES
        || inner.get(..4) != Some(b"SMZE".as_slice())
        || !matches!(selector, 1..=3)
    {
        return Err(error("SMZR exact inner type or outer cap differs"));
    }
    let mut proof = Vec::with_capacity(len);
    proof.extend_from_slice(b"SMZR");
    proof.extend_from_slice(&VERSION.to_le_bytes());
    proof.push(selector);
    proof.push(0);
    proof.extend_from_slice(source);
    proof.extend_from_slice(&(inner.len() as u32).to_le_bytes());
    proof.extend_from_slice(&[0; 4]);
    proof.extend_from_slice(inner);
    Ok(proof)
}

/// Projection includes the complete80-byte outer envelope; exceeding the cap is
/// reported by prove, allowing callers to inspect infeasible geometry first.
pub(crate) fn projected_bytes(
    adapter: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<usize, TransactionCircuitError> {
    smallwood_engine::projected_asset_spend_smze_inner_proof_bytes(adapter)?
        .checked_add(OUTER_HEADER_BYTES)
        .ok_or(error("SMZR projected length overflow"))
}
pub(crate) fn prove(
    adapter: &(dyn SmallwoodConstraintAdapter + Sync),
    packed: &[u64],
    full_binding: &[u8],
    source: &[u8; 64],
) -> Result<Vec<u8>, TransactionCircuitError> {
    let selector = route(full_binding)?;
    let binding = transcript_binding(full_binding, source)?;
    if projected_bytes(adapter)? > MAX_PROOF_BYTES {
        return Err(error("SMZR projection exceeds outer2MiB cap"));
    }
    let inner = smallwood_engine::prove_statement_with_transcript_backend_profile_and_domain(
        adapter,
        packed,
        &binding,
        ASSET_SPEND_SMZE_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512AssetSpendSmze,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    // Existing readback decodes and canonical-reencodes exact SMZE, no remainder.
    smallwood_engine::asset_spend_smze_proof_wire_receipt(&inner)?;
    assemble(&inner, selector, source)
}
pub(crate) fn verify(
    adapter: &(dyn SmallwoodConstraintAdapter + Sync),
    full_binding: &[u8],
    expected_source: &[u8; 64],
    proof: &[u8],
) -> Result<(), TransactionCircuitError> {
    let selector = route(full_binding)?;
    let envelope = parse_header(proof)?;
    check_expected(&envelope, selector, expected_source)?;
    let binding = transcript_binding(full_binding, expected_source)?;
    smallwood_engine::asset_spend_smze_proof_wire_receipt(envelope.inner)?;
    smallwood_engine::verify_statement_with_transcript_backend_profile_and_domain(
        adapter,
        &binding,
        envelope.inner,
        ASSET_SPEND_SMZE_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512AssetSpendSmze,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}
pub(crate) fn geometry_receipt(
    adapter: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<serde_json::Value, TransactionCircuitError> {
    let mut value = smallwood_engine::asset_spend_smze_geometry_receipt(adapter)?;
    value["proof_magic"] = serde_json::json!("SMZR");
    value["inner_proof_magic"] = serde_json::json!("SMZE");
    value["wrapper_version"] = serde_json::json!(VERSION);
    value["wrapper_bytes"] = serde_json::json!(OUTER_HEADER_BYTES);
    value["projected_outer_bytes"] = serde_json::json!(projected_bytes(adapter)?);
    value["outer_cap_bytes"] = serde_json::json!(MAX_PROOF_BYTES);
    value["transcript_binding_words"] = serde_json::json!(134);
    value["source_digest_required"] = serde_json::json!(true);
    Ok(value)
}
/// Structural envelope/inner readback, not cryptographic verification or a
/// compiled-source check. verify() performs both with its compiled caller source.
pub(crate) fn wire_receipt(proof: &[u8]) -> Result<serde_json::Value, TransactionCircuitError> {
    if proof.starts_with(&crate::asset_recovery_capsule_v1::PROOF_MAGIC) {
        return crate::asset_recovery_capsule_v1::proof_wire_receipt(proof);
    }
    let envelope = parse_header(proof)?;
    let inner = smallwood_engine::asset_spend_smze_proof_wire_receipt(envelope.inner)?;
    Ok(
        serde_json::json!({"proof_magic":"SMZR","wrapper_version":VERSION,
        "route":envelope.route,"source_digest":hex::encode(envelope.source),
        "outer_bytes":proof.len(),"wrapper_bytes":OUTER_HEADER_BYTES,
        "inner_proof_magic":"SMZE","inner":inner,"proof_verified":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn full(selector: u64, words: usize) -> Vec<u8> {
        let mut b = b"HGRECOV1".to_vec();
        b.extend_from_slice(&selector.to_le_bytes());
        b.resize(16 + 8 * words, 0);
        b
    }
    #[test]
    fn fixed_statement_commits_source_route_and_complete_public_bytes() {
        let source = [0xff; 64];
        let b = full(1, 182);
        let t = transcript_binding(&b, &source).unwrap();
        let words: Vec<_> = t
            .chunks_exact(8)
            .map(|w| u64::from_le_bytes(w.try_into().unwrap()))
            .collect();
        assert_eq!(words.len(), 134);
        assert!(words.iter().all(|w| *w < FIELD_ORDER));
        assert_eq!(&words[..3], &[TRANSCRIPT_DOMAIN, 1, 1]);
        assert_eq!(&words[3..19], &[u32::MAX as u64; 16]);
        assert!(words[35..].iter().all(|w| *w == 0));
        let mut changed = b.clone();
        *changed.last_mut().unwrap() = 1;
        assert_ne!(t, transcript_binding(&changed, &source).unwrap());
        assert_ne!(t, transcript_binding(&b, &[0; 64]).unwrap());
        assert_ne!(
            t,
            transcript_binding(
                &full(2, crate::asset_recovery_capsule_v1::PUBLIC_WORDS),
                &source
            )
            .unwrap()
        );
    }
    #[test]
    fn finite_full_binding_schemas_reject_crossroutes_and_noncanonical_fields() {
        for (selector, words) in [
            (1, 182),
            (2, crate::asset_recovery_capsule_v1::PUBLIC_WORDS),
            (3, 128),
        ] {
            let b = full(selector, words);
            assert_eq!(route(&b).unwrap(), selector as u8);
            for other in [82, 98, 128, 182] {
                if other != words {
                    assert!(route(&full(selector, other)).is_err());
                }
            }
            let mut bad = b.clone();
            bad[16..24].copy_from_slice(&FIELD_ORDER.to_le_bytes());
            assert!(route(&bad).is_err());
            let mut bad = b.clone();
            bad[0] ^= 1;
            assert!(route(&bad).is_err());
            let mut bad = b.clone();
            bad.push(0);
            assert!(route(&bad).is_err());
        }
        assert!(route(&full(2, 98)).is_err()); // Historical full30 schema.
        assert!(route(&full(4, 182)).is_err());
    }
    #[test]
    fn header_roundtrip_only_is_not_proof_acceptance_and_binds_expected_identity() {
        let proof = assemble(b"SMZE", 1, &[7; 64]).unwrap();
        let e = parse_header(&proof).unwrap();
        assert_eq!(e.inner, b"SMZE");
        check_expected(&e, 1, &[7; 64]).unwrap();
        assert!(check_expected(&e, 2, &[7; 64]).is_err());
        assert!(check_expected(&e, 1, &[8; 64]).is_err());
        assert!(wire_receipt(&proof).is_err()); // Four magic bytes are not an inner proof.
        for offset in [0, 4, 6, 7, 72, 76, 80] {
            let mut bad = proof.clone();
            bad[offset] ^= 0x80;
            assert!(parse_header(&bad).is_err());
        }
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(parse_header(&trailing).is_err());
        for len in [0, 4, 79, 80, 83] {
            assert!(parse_header(&proof[..len]).is_err());
        }
        let mut oversized = vec![0; MAX_PROOF_BYTES + 1];
        oversized[..4].copy_from_slice(b"SMZR");
        assert!(parse_header(&oversized).is_err());
        assert!(assemble(&vec![0; MAX_PROOF_BYTES], 1, &[0; 64]).is_err());
    }
}
