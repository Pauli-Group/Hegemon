//! Native treasury successor with explicit feed-forward compression identity.
//! Retained RP05 and grammar-1 RP06 artifacts remain historical.
//!
//! RP06 adds an explicit32-byte network context to the public schema, uses policy-only value
//! custody, and preserves ledger-proven distinct approvals of one exact source/payment operation.
//! Compilation/proofs are development evidence; this module does not select production authority.
#![forbid(unsafe_code)]

use crate::{
    smallwood_engine::{
        self, SmallwoodArithmetization, SmallwoodDecsEvaluationDomain, SmallwoodTranscriptBackend,
        POSEIDON2_V8_SMZA_SMALLWOOD_NO_GRINDING_PROFILE,
    },
    smallwood_poseidon2_v8_hash_schedule::{
        SMALLWOOD_POSEIDON2_V8_AUTH_ACCUMULATOR_DOMAIN,
        SMALLWOOD_POSEIDON2_V8_AUTH_MODE_BIND_DOMAIN, SMALLWOOD_POSEIDON2_V8_AUTH_POLICY_DOMAIN,
        SMALLWOOD_POSEIDON2_V8_AUTH_VALUE_LOCK_DOMAIN, SMALLWOOD_POSEIDON2_V8_NULLIFIER_DOMAIN,
    },
    smallwood_poseidon2_v8_semantics::{
        compile_smallwood_poseidon2_v8_rp06_inner, SmallwoodPoseidon2V8ConstraintAdapter,
        SmallwoodPoseidon2V8RelationError,
    },
    smallwood_poseidon2_v8_types::{
        SmallwoodPoseidon2V8AccumulatorOpening, SmallwoodPoseidon2V8Digest,
        SmallwoodPoseidon2V8PublicStatement, SmallwoodPoseidon2V8SurfaceError,
        SmallwoodPoseidon2V8Witness, SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_WORDS,
    },
    smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView},
    TransactionCircuitError,
};
use sha2::{Digest, Sha512};
use transaction_core::{
    constants::{BALANCE_SLOT_PADDING_FIELD_ID, FIELD_MODULUS_U64, NATIVE_ASSET_ID},
    poseidon2_width16::{poseidon2_width16_compress14, poseidon2_width16_sponge, Felt},
};

/// Exact source-owned q38 serialization ceiling; it is not a maximum observed proof size.
pub const RP06_MAX_INNER_PROOF_BYTES: usize =
    smallwood_engine::SMALLWOOD_RP06_MAX_INNER_PROOF_BYTES;
pub fn rp06_projected_inner_proof_bytes(
    statement: Rp06PublicStatement,
) -> Result<usize, TransactionCircuitError> {
    let adapter = Rp06ConstraintAdapter::from_public_statement(statement).map_err(circuit_error)?;
    smallwood_engine::projected_rp06_smzb_inner_proof_bytes(&adapter)
}

pub const RP06_PROGRAM_MAGIC: [u8; 8] = *b"HGV8RP06";
/// Grammar 2 carries COMPFF01 and the complete compression mode ID before its parent.
pub const RP06_PROGRAM_GRAMMAR: u16 = 2;
pub const RP06_COMPRESSION_MODE_ID: &str =
    crate::smallwood_poseidon2_v8_program::SMALLWOOD_POSEIDON2_V8_COMPRESSION_MODE_ID;
pub const RP06_COMPRESSION_MODE_MARKER: u64 =
    crate::smallwood_poseidon2_v8_program::SMALLWOOD_POSEIDON2_V8_COMPRESSION_MODE_MARKER;
pub const RP06_PUBLIC_WORDS: usize = 128;
pub const RP06_ACTION_INTENT_DOMAIN: u64 = 0x4854_5838_494e_5402;
pub const RP06_PRODUCTION_AUTHORIZED: bool = false;
pub const RP06_CIRCUIT_VERSION: u16 = 9;
pub const RP06_CRYPTO_SUITE: u16 = 7;
pub const RP06_PROOF_PROFILE: u8 = 10;
pub const RP06_DOMAIN_SET: u16 = 6;
/// Original public positions used only as fixed-zero coordinates in the derived intent preimage.
pub const RP06_INTENT_NETWORK_POSITIONS: [usize; 8] = [49, 50, 51, 52, 53, 87, 88, 89];
pub const RP06_INTENT_VALUE_NULLIFIER_POSITIONS: [usize; 7] = [90, 91, 92, 93, 113, 114, 115];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rp06PublicStatement {
    pub base: SmallwoodPoseidon2V8PublicStatement,
    pub chain_id: [u8; 32],
}

impl Rp06PublicStatement {
    pub fn validate(&self) -> Result<(), SmallwoodPoseidon2V8SurfaceError> {
        self.base.validate_public_structure()?;
        let words = self.base.to_public_words();
        // Narrow native custody scope: active stablecoin operations remain on their own relation.
        if self.chain_id == [0; 32]
            || words[58] != 0
            || words[83] != 0
            || self.base.value_balance_sign
            || self.base.value_balance_magnitude != 0
            || self
                .base
                .balance_assets
                .iter()
                .any(|asset| *asset != NATIVE_ASSET_ID && *asset != BALANCE_SLOT_PADDING_FIELD_ID)
        {
            return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationShape);
        }
        Ok(())
    }
    pub fn network_words(&self) -> [u32; 8] {
        core::array::from_fn(|i| {
            u32::from_le_bytes(
                self.chain_id[i * 4..i * 4 + 4]
                    .try_into()
                    .expect("four-byte word"),
            )
        })
    }
    pub fn to_public_words(&self) -> [u64; RP06_PUBLIC_WORDS] {
        let mut words = [0u64; RP06_PUBLIC_WORDS];
        words[..120].copy_from_slice(&self.base.to_public_words());
        words[120..].copy_from_slice(&self.network_words().map(u64::from));
        words
    }
    pub fn try_from_public_words(words: &[u64]) -> Result<Self, SmallwoodPoseidon2V8SurfaceError> {
        if words.len() != RP06_PUBLIC_WORDS {
            return Err(SmallwoodPoseidon2V8SurfaceError::WrongPublicLength);
        }
        let base = SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&words[..120])?;
        let mut chain_id = [0u8; 32];
        for (i, word) in words[120..].iter().copied().enumerate() {
            let word = u32::try_from(word)
                .map_err(|_| SmallwoodPoseidon2V8SurfaceError::NonCanonicalField)?;
            chain_id[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        let statement = Self { base, chain_id };
        statement.validate()?;
        Ok(statement)
    }
    pub fn expected_action_intent(
        &self,
    ) -> Result<SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8SurfaceError> {
        let words = rp06_intent_projection_from_public(
            &self.base.to_public_words(),
            self.network_words().map(u64::from),
        );
        if words.iter().any(|word| *word >= FIELD_MODULUS_U64) {
            return Err(SmallwoodPoseidon2V8SurfaceError::ActionIntentMismatch);
        }
        poseidon2_width16_sponge(RP06_ACTION_INTENT_DOMAIN, &words.map(Felt::from_u64))
            .map(|digest| digest.map(|word| word.as_canonical_u64()))
            .map_err(|_| SmallwoodPoseidon2V8SurfaceError::ActionIntentMismatch)
    }
}

/// Exact injective compression of native operation fields + network + source value nullifier.
/// Current anchor, parent height, disabled stable state and the accumulator nullifier are context,
/// checked separately for every proof. They are not frozen human spending authorization.
pub(crate) fn rp06_intent_projection_from_public(
    public: &[u64; 120],
    network: [u64; 8],
) -> [u64; SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_WORDS] {
    let mut words = *public;
    words[49..54].fill(0);
    words[87..94].fill(0);
    words[113..120].fill(0);
    words[94] = 0;
    words[95..109].fill(0);
    for (position, value) in RP06_INTENT_NETWORK_POSITIONS.into_iter().zip(network) {
        words[position] = value;
    }
    for (position, value) in RP06_INTENT_VALUE_NULLIFIER_POSITIONS
        .into_iter()
        .zip(public[4..11].iter().copied())
    {
        words[position] = value;
    }
    let mut projection = [0u64; SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_WORDS];
    let mut next = 0;
    for (i, word) in words.into_iter().enumerate() {
        if (4..18).contains(&i) || (47..49).contains(&i) {
            continue;
        }
        projection[next] = word;
        next += 1;
    }
    debug_assert_eq!(next, projection.len());
    projection
}

pub fn rp06_policy_root(
    threshold: u64,
    signer_count: u64,
    tags: [[u64; 7]; 6],
) -> Result<SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8SurfaceError> {
    if threshold == 0 || threshold > signer_count || signer_count > 6 {
        return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
    }
    let mut words = Vec::with_capacity(44);
    words.extend([threshold, signer_count]);
    for (i, tag) in tags.into_iter().enumerate() {
        if tag.iter().any(|word| *word >= FIELD_MODULUS_U64)
            || (i < signer_count as usize
                && (tag == [0; 7] || tags[..i].iter().any(|other| other[0] == tag[0])))
            || (i >= signer_count as usize && tag != [0; 7])
        {
            return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
        }
        words.extend(tag);
    }
    sponge(SMALLWOOD_POSEIDON2_V8_AUTH_POLICY_DOMAIN, &words)
}
fn sponge(
    domain: u64,
    words: &[u64],
) -> Result<SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8SurfaceError> {
    if words.iter().any(|word| *word >= FIELD_MODULUS_U64) {
        return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
    }
    poseidon2_width16_sponge(
        domain,
        &words
            .iter()
            .copied()
            .map(Felt::from_u64)
            .collect::<Vec<_>>(),
    )
    .map(|digest| digest.map(|word| word.as_canonical_u64()))
    .map_err(|_| SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening)
}
fn bind_policy_key(
    key: [u64; 5],
    digest: SmallwoodPoseidon2V8Digest,
) -> Result<SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8SurfaceError> {
    if key[0] == 0
        || key
            .iter()
            .chain(digest.iter())
            .any(|word| *word >= FIELD_MODULUS_U64)
    {
        return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
    }
    let padded = core::array::from_fn(|i| key.get(i).copied().unwrap_or(0));
    Ok(poseidon2_width16_compress14(
        SMALLWOOD_POSEIDON2_V8_AUTH_MODE_BIND_DOMAIN,
        &padded.map(Felt::from_u64),
        &digest.map(Felt::from_u64),
    )
    .map(|word| word.as_canonical_u64()))
}
pub fn rp06_value_authorization(
    policy_root: SmallwoodPoseidon2V8Digest,
    key: [u64; 5],
) -> Result<SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8SurfaceError> {
    if policy_root == [0; 7] || policy_root.iter().any(|word| *word >= FIELD_MODULUS_U64) {
        return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
    }
    let value = poseidon2_width16_compress14(
        SMALLWOOD_POSEIDON2_V8_AUTH_VALUE_LOCK_DOMAIN,
        &policy_root.map(Felt::from_u64),
        &[Felt::ZERO; 7],
    )
    .map(|word| word.as_canonical_u64());
    bind_policy_key(key, value)
}
pub fn rp06_accumulator_authorization(
    opening: SmallwoodPoseidon2V8AccumulatorOpening,
    key: [u64; 5],
) -> Result<SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8SurfaceError> {
    let mut words = Vec::with_capacity(23);
    words.extend(opening.policy_root);
    words.extend(opening.intent_digest);
    words.extend([
        opening.threshold,
        opening.signer_count,
        opening.approval_count,
    ]);
    words.extend(opening.approved_slots.map(u64::from));
    bind_policy_key(
        key,
        sponge(SMALLWOOD_POSEIDON2_V8_AUTH_ACCUMULATOR_DOMAIN, &words)?,
    )
}
pub fn rp06_policy_note_nullifier(
    key: [u64; 5],
    position: u64,
    rho: [u64; 4],
) -> Result<SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8SurfaceError> {
    if key[0] == 0 || position >= (1u64 << 32) {
        return Err(SmallwoodPoseidon2V8SurfaceError::InvalidAuthorizationOpening);
    }
    let mut words = Vec::with_capacity(12);
    words.extend(key);
    words.extend([0, 0, position]);
    words.extend(rho);
    sponge(SMALLWOOD_POSEIDON2_V8_NULLIFIER_DOMAIN, &words)
}

/// Conservative union bound counts every source CSR attempt, including eliminated zero rows.
pub fn rp06_source_csr_attempt_count() -> usize {
    crate::smallwood_poseidon2_v8_semantics::smallwood_poseidon2_v8_rp06_csr_expression_program()
        .attempts
        .len()
}
pub fn rp06_program_identity_sha512() -> [u8; 64] {
    static DIGEST: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(|| {
        Sha512::digest(
            crate::smallwood_poseidon2_v8_program::encode_smallwood_poseidon2_v8_rp06_program(),
        )
        .into()
    })
}
pub fn rp06_program_digest() -> [u8; 48] {
    static DIGEST: std::sync::OnceLock<[u8; 48]> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(|| {
        let bytes =
            crate::smallwood_poseidon2_v8_program::encode_smallwood_poseidon2_v8_rp06_program();
        Sha512::digest(bytes)[..48]
            .try_into()
            .expect("digest length")
    })
}

#[derive(Clone, Debug)]
pub struct Rp06ConstraintAdapter {
    pub statement: Rp06PublicStatement,
    inner: SmallwoodPoseidon2V8ConstraintAdapter,
}
impl Rp06ConstraintAdapter {
    pub fn from_public_statement(
        statement: Rp06PublicStatement,
    ) -> Result<Self, SmallwoodPoseidon2V8RelationError> {
        let (inner, _) = compile_smallwood_poseidon2_v8_rp06_inner(&statement, None)?;
        Ok(Self { statement, inner })
    }
    pub fn verify_packed_witness(
        &self,
        packed: &[u64],
    ) -> Result<(), SmallwoodPoseidon2V8RelationError> {
        self.inner.verify_packed_witness(packed)
    }
}
pub fn compile_rp06_relation(
    statement: Rp06PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
) -> Result<(Rp06ConstraintAdapter, Vec<u64>), SmallwoodPoseidon2V8RelationError> {
    let (inner, packed) = compile_smallwood_poseidon2_v8_rp06_inner(&statement, Some(witness))?;
    Ok((
        Rp06ConstraintAdapter { statement, inner },
        packed.expect("requested witness"),
    ))
}
impl SmallwoodConstraintAdapter for Rp06ConstraintAdapter {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::DirectPacked64Poseidon2Rp06Sha512Smzb
    }
    fn row_count(&self) -> usize {
        self.inner.row_count()
    }
    fn packing_factor(&self) -> usize {
        self.inner.packing_factor()
    }
    fn constraint_degree(&self) -> usize {
        self.inner.constraint_degree()
    }
    fn linear_constraint_count(&self) -> usize {
        self.inner.linear_constraint_count()
    }
    fn constraint_count(&self) -> usize {
        self.inner.constraint_count()
    }
    fn linear_constraint_offsets(&self) -> &[u32] {
        self.inner.linear_constraint_offsets()
    }
    fn linear_constraint_indices(&self) -> &[u32] {
        self.inner.linear_constraint_indices()
    }
    fn linear_constraint_coefficients(&self) -> &[u64] {
        self.inner.linear_constraint_coefficients()
    }
    fn linear_targets(&self) -> &[u64] {
        self.inner.linear_targets()
    }
    fn auxiliary_witness_words(&self) -> &[u64] {
        &[]
    }
    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(0)
    }
    fn nonlinear_eval_view<'a>(
        &self,
        point: u64,
        rows: &'a [u64],
        aux: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        self.inner.nonlinear_eval_view(point, rows, aux)
    }
    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        self.inner.compute_constraints_u64(view, out)
    }
}

#[derive(Clone, Debug)]
pub struct Rp06CandidateProof {
    pub public_words: [u64; RP06_PUBLIC_WORDS],
    pub relation_digest: [u8; 48],
    pub proof_bytes: Vec<u8>,
}
pub fn rp06_transcript_bytes(
    statement: &Rp06PublicStatement,
) -> Result<Vec<u8>, TransactionCircuitError> {
    statement.validate().map_err(circuit_error)?;
    let mut bytes = Vec::with_capacity(1200);
    bytes.extend_from_slice(b"HGR6PB01");
    bytes.extend(RP06_PROGRAM_MAGIC);
    for word in [
        1u16,
        RP06_CIRCUIT_VERSION,
        RP06_CRYPTO_SUITE,
        1,
        14,
        RP06_DOMAIN_SET,
    ] {
        bytes.extend(word.to_le_bytes());
    }
    bytes.extend([2u8, RP06_PROOF_PROFILE, 1, 0]);
    bytes.extend(rp06_program_digest());
    bytes.extend(statement.chain_id);
    for word in statement.to_public_words() {
        bytes.extend(word.to_le_bytes());
    }
    for word in statement.expected_action_intent().map_err(circuit_error)? {
        bytes.extend(word.to_le_bytes());
    }
    debug_assert_eq!(bytes.len() % 8, 0);
    Ok(bytes)
}
/// Engine leaf parser accepts only this complete canonical successor grammar.
pub fn validate_rp06_transcript_bytes(bytes: &[u8]) -> Result<(), TransactionCircuitError> {
    if bytes.len() != 1192 || &bytes[..8] != b"HGR6PB01" || bytes[8..16] != RP06_PROGRAM_MAGIC {
        return Err(circuit_error("wrong RP06 preamble length/magic"));
    }
    let public = bytes[112..1136]
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("word")))
        .collect::<Vec<_>>();
    let statement = Rp06PublicStatement::try_from_public_words(&public).map_err(circuit_error)?;
    if bytes != rp06_transcript_bytes(&statement)?.as_slice() {
        return Err(circuit_error("noncanonical RP06 preamble/context/intent"));
    }
    Ok(())
}
fn circuit_error(error: impl core::fmt::Debug) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolationOwned(format!(
        "RP06 source-owned treasury relation rejected: {error:?}"
    ))
}
/// Genuine source-owned proof. No admission/release capability is changed.
pub fn prove_rp06_candidate(
    statement: Rp06PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
) -> Result<Rp06CandidateProof, TransactionCircuitError> {
    let (adapter, packed) = compile_rp06_relation(statement, witness).map_err(circuit_error)?;
    let binding = rp06_transcript_bytes(&statement)?;
    let proof_bytes = smallwood_engine::prove_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        &packed,
        &binding,
        POSEIDON2_V8_SMZA_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2Rp06Smzb,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let candidate = Rp06CandidateProof {
        public_words: statement.to_public_words(),
        relation_digest: rp06_program_digest(),
        proof_bytes,
    };
    verify_rp06_candidate(&candidate, statement.chain_id)?;
    Ok(candidate)
}
pub fn verify_rp06_candidate(
    candidate: &Rp06CandidateProof,
    expected_chain_id: [u8; 32],
) -> Result<(), TransactionCircuitError> {
    verify_rp06_candidate_bytes(
        &candidate.public_words,
        candidate.relation_digest,
        &candidate.proof_bytes,
        expected_chain_id,
    )
}
/// Borrow the original proof range for canonical node admission; no carrier copy/re-encoding.
pub fn verify_rp06_candidate_bytes(
    public_words: &[u64],
    relation_digest: [u8; 48],
    proof_bytes: &[u8],
    expected_chain_id: [u8; 32],
) -> Result<(), TransactionCircuitError> {
    let statement =
        Rp06PublicStatement::try_from_public_words(public_words).map_err(circuit_error)?;
    if statement.chain_id != expected_chain_id || relation_digest != rp06_program_digest() {
        return Err(circuit_error("network/program identity mismatch"));
    }
    let adapter = Rp06ConstraintAdapter::from_public_statement(statement).map_err(circuit_error)?;
    smallwood_engine::verify_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        &rp06_transcript_bytes(&statement)?,
        proof_bytes,
        POSEIDON2_V8_SMZA_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2Rp06Smzb,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feedforward_rp06_program_carries_mode_before_current_parent() {
        let bytes =
            crate::smallwood_poseidon2_v8_program::encode_smallwood_poseidon2_v8_rp06_program();
        assert_eq!(&bytes[..8], &RP06_PROGRAM_MAGIC);
        assert_eq!(u16::from_le_bytes(bytes[8..10].try_into().unwrap()), 2);
        assert_eq!(
            u64::from_le_bytes(bytes[10..18].try_into().unwrap()),
            0x434f_4d50_4646_3031
        );
        let mode_len = u64::from_le_bytes(bytes[18..26].try_into().unwrap()) as usize;
        assert_eq!(
            &bytes[26..26 + mode_len],
            RP06_COMPRESSION_MODE_ID.as_bytes()
        );
        let offset = 26 + mode_len;
        let parent_len = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as usize;
        let parent = &bytes[offset + 8..offset + 8 + parent_len];
        assert_eq!(
            parent,
            crate::smallwood_poseidon2_v8_program::encode_smallwood_poseidon2_v8_program()
        );
        assert_eq!(u16::from_le_bytes(parent[8..10].try_into().unwrap()), 4);
        let expected: [u8; 64] = Sha512::digest(&bytes).into();
        assert_eq!(rp06_program_identity_sha512(), expected);
        assert_eq!(
            rp06_program_digest().as_slice(),
            &rp06_program_identity_sha512()[..48]
        );
    }

    fn statement() -> Rp06PublicStatement {
        Rp06PublicStatement {
            base: SmallwoodPoseidon2V8PublicStatement::default(),
            chain_id: [1; 32],
        }
    }
    #[test]
    fn rp06_network_codec_preserves_every_byte_and_rejects_reduction() {
        for i in 0..32 {
            let mut s = statement();
            s.chain_id[i] = 255;
            assert_eq!(
                Rp06PublicStatement::try_from_public_words(&s.to_public_words()).unwrap(),
                s
            );
            assert_ne!(
                s.expected_action_intent().unwrap(),
                statement().expected_action_intent().unwrap()
            );
        }
        let mut words = statement().to_public_words();
        words[120] = u64::from(u32::MAX) + 1;
        assert!(Rp06PublicStatement::try_from_public_words(&words).is_err());
    }
    #[test]
    fn rp06_intent_fixes_source_and_payment_but_allows_dynamic_context() {
        let base = statement();
        let projection = base.expected_action_intent().unwrap();
        for i in 0..7 {
            let mut s = base;
            s.base.nullifiers[0][i] = 1;
            assert_ne!(s.expected_action_intent().unwrap(), projection);
        }
        let mut s = base;
        s.base.nullifiers[1] = [5; 7];
        s.base.merkle_root = [9; 7];
        s.base.stablecoin.parent_height = 40;
        assert_eq!(s.expected_action_intent().unwrap(), projection);
        let mut s = base;
        s.base.fee = 1;
        assert_ne!(s.expected_action_intent().unwrap(), projection);
        for i in 0..7 {
            let mut s = base;
            s.base.commitments[0][i] = 3;
            assert_ne!(s.expected_action_intent().unwrap(), projection);
        }
        for i in 0..6 {
            let mut s = base;
            s.base.ciphertext_commitments[0][i] = 7;
            assert_ne!(s.expected_action_intent().unwrap(), projection);
        }
    }
    #[test]
    fn rp06_policy_value_key_does_not_change_with_future_intent() {
        let mut tags = [[0; 7]; 6];
        tags[0] = [1; 7];
        tags[1] = [2; 7];
        tags[2] = [3; 7];
        let root = rp06_policy_root(2, 3, tags).unwrap();
        let value = rp06_value_authorization(root, [5, 6, 7, 8, 9]).unwrap();
        assert_ne!(value, [0; 7]);
        assert_ne!(
            value,
            rp06_value_authorization(root, [6, 6, 7, 8, 9]).unwrap()
        );
        tags[2] = tags[1];
        assert!(rp06_policy_root(2, 3, tags).is_err());
        assert!(!RP06_PRODUCTION_AUTHORIZED);
    }
    fn key(index: usize) -> [u64; 5] {
        [101 + index as u64 * 10, 102, 103, 104, 105]
    }
    fn tags() -> [[u64; 7]; 6] {
        let mut tags = [[0; 7]; 6];
        for (i, tag) in tags[..3].iter_mut().enumerate() {
            *tag=crate::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest(key(i)).unwrap();
        }
        tags
    }
    fn note(
        value: u64,
        authorization: [u64; 7],
        seed: u64,
    ) -> crate::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8NoteOpening {
        crate::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8NoteOpening {
            value,
            asset_id: NATIVE_ASSET_ID,
            recipient_key: [seed + 1, seed + 2, seed + 3, seed + 4],
            authorization_key: authorization[..4].try_into().unwrap(),
            rho: [seed + 5, seed + 6, seed + 7, seed + 8],
            randomness: [
                authorization[4],
                authorization[5],
                authorization[6],
                seed + 9,
            ],
        }
    }
    fn final_fixture(pair: [usize; 2]) -> (Rp06PublicStatement, SmallwoodPoseidon2V8Witness) {
        use crate::smallwood_poseidon2_v8_coinbase::*;
        use crate::smallwood_poseidon2_v8_types::*;
        let policy_key = [31, 32, 33, 34, 35];
        let tags = tags();
        let root = rp06_policy_root(2, 3, tags).unwrap();
        let value = note(
            100,
            rp06_value_authorization(root, policy_key).unwrap(),
            1000,
        );
        let outputs = [
            note(60, tags[0], 2000),
            note(
                39,
                rp06_value_authorization(root, policy_key).unwrap(),
                3000,
            ),
        ];
        let mut base = SmallwoodPoseidon2V8PublicStatement {
            input_flags: [true, true],
            output_flags: [true, true],
            fee: 1,
            merkle_root: [1; 7],
            ..SmallwoodPoseidon2V8PublicStatement::default()
        };
        base.nullifiers[0] = rp06_policy_note_nullifier(policy_key, 0, value.rho).unwrap();
        for (i, output) in outputs.iter().enumerate() {
            base.commitments[i] = poseidon2_v8_note_commitment(*output).unwrap();
            base.ciphertext_commitments[i] = [71 + i as u64; 6];
        }
        let mut statement = Rp06PublicStatement {
            base,
            chain_id: [9; 32],
        };
        let mut approved = [false; 6];
        for slot in pair {
            approved[slot] = true;
        }
        let opening = SmallwoodPoseidon2V8AccumulatorOpening {
            policy_root: root,
            intent_digest: statement.expected_action_intent().unwrap(),
            threshold: 2,
            signer_count: 3,
            approval_count: 2,
            approved_slots: approved,
        };
        let accumulator = note(
            0,
            rp06_accumulator_authorization(opening, policy_key).unwrap(),
            4000,
        );
        let frontier = poseidon2_v8_two_note_frontier([
            poseidon2_v8_note_commitment(value).unwrap(),
            poseidon2_v8_note_commitment(accumulator).unwrap(),
        ])
        .unwrap();
        statement.base.merkle_root = frontier.root;
        statement.base.nullifiers[1] =
            rp06_policy_note_nullifier(policy_key, 1, accumulator.rho).unwrap();
        let witness = SmallwoodPoseidon2V8Witness {
            inputs: core::array::from_fn(|i| SmallwoodPoseidon2V8InputWitness {
                active: true,
                spend_key: policy_key,
                note: if i == 0 { value } else { accumulator },
                position: i as u64,
                siblings: frontier.paths[i],
                balance_slot_selectors: [true, false, false, false],
            }),
            outputs: outputs.map(|note| SmallwoodPoseidon2V8OutputWitness {
                active: true,
                note,
                balance_slot_selectors: [true, false, false, false],
            }),
            auth: SmallwoodPoseidon2V8PrivateAuthWitness {
                mode: crate::SmallwoodPrivateAuthMode::FinalThresholdSpend,
                policy_nullifier_key: policy_key,
                current: opening,
                next: SmallwoodPoseidon2V8AccumulatorOpening::ZERO,
                policy_signer_tags: tags,
            },
            ..SmallwoodPoseidon2V8Witness::default()
        };
        (statement, witness)
    }
    fn approval_fixture(
        final_statement: Rp06PublicStatement,
        final_witness: SmallwoodPoseidon2V8Witness,
        signer: usize,
        approved: &[usize],
    ) -> (Rp06PublicStatement, SmallwoodPoseidon2V8Witness) {
        use crate::smallwood_poseidon2_v8_coinbase::*;
        use crate::smallwood_poseidon2_v8_types::*;
        let mut current = final_witness.auth.current;
        current.approval_count = approved.len() as u64;
        current.approved_slots = [false; 6];
        for slot in approved {
            current.approved_slots[*slot] = true;
        }
        let mut next = current;
        next.approval_count += 1;
        next.approved_slots[signer] = true;
        let predecessor = note(
            0,
            rp06_accumulator_authorization(current, final_witness.auth.policy_nullifier_key)
                .unwrap(),
            5000,
        );
        let capability = note(10, tags()[signer], 6000 + signer as u64 * 20);
        let successor = note(
            0,
            rp06_accumulator_authorization(next, final_witness.auth.policy_nullifier_key).unwrap(),
            if next.approval_count == 1 { 5000 } else { 4000 },
        );
        let change = note(9, tags()[signer], 8000);
        let frontier = poseidon2_v8_two_note_frontier([
            poseidon2_v8_note_commitment(predecessor).unwrap(),
            poseidon2_v8_note_commitment(capability).unwrap(),
        ])
        .unwrap();
        let mut statement = Rp06PublicStatement {
            base: SmallwoodPoseidon2V8PublicStatement {
                input_flags: [!approved.is_empty(), true],
                output_flags: [true, true],
                fee: 1,
                merkle_root: frontier.root,
                ..SmallwoodPoseidon2V8PublicStatement::default()
            },
            chain_id: final_statement.chain_id,
        };
        let mut inputs = [SmallwoodPoseidon2V8InputWitness::ZERO; 2];
        for i in 0..2 {
            if statement.base.input_flags[i] {
                let value = if i == 0 { predecessor } else { capability };
                inputs[i] = SmallwoodPoseidon2V8InputWitness {
                    active: true,
                    spend_key: key(signer),
                    note: value,
                    position: i as u64,
                    siblings: frontier.paths[i],
                    balance_slot_selectors: [true, false, false, false],
                };
                statement.base.nullifiers[i] = rp06_policy_note_nullifier(
                    if i == 0 {
                        final_witness.auth.policy_nullifier_key
                    } else {
                        key(signer)
                    },
                    i as u64,
                    value.rho,
                )
                .unwrap();
            }
        }
        let outputs = [successor, change];
        for (i, output) in outputs.iter().enumerate() {
            statement.base.commitments[i] = poseidon2_v8_note_commitment(*output).unwrap();
            statement.base.ciphertext_commitments[i] = [81 + i as u64; 6];
        }
        let witness = SmallwoodPoseidon2V8Witness {
            inputs,
            outputs: outputs.map(|note| SmallwoodPoseidon2V8OutputWitness {
                active: true,
                note,
                balance_slot_selectors: [true, false, false, false],
            }),
            auth: SmallwoodPoseidon2V8PrivateAuthWitness {
                mode: crate::SmallwoodPrivateAuthMode::ApprovalStep,
                policy_nullifier_key: final_witness.auth.policy_nullifier_key,
                current,
                next,
                policy_signer_tags: tags(),
            },
            ..SmallwoodPoseidon2V8Witness::default()
        };
        (statement, witness)
    }
    #[test]
    fn rp06_all_pairs_accept_distinct_ledger_approvals_and_reject_malicious_changes() {
        for pair in [[0, 1], [0, 2], [1, 2]] {
            let (statement, witness) = final_fixture(pair);
            let (adapter, packed) =
                compile_rp06_relation(statement, &witness).expect("genuine final source witness");
            adapter.verify_packed_witness(&packed).unwrap();
            assert_eq!(adapter.row_count(), 686);
            assert_eq!(adapter.constraint_count(), 818);
            assert_eq!(
                rp06_projected_inner_proof_bytes(statement).unwrap(),
                RP06_MAX_INNER_PROOF_BYTES
            );
            assert_eq!(RP06_MAX_INNER_PROOF_BYTES, 164_113);
            assert_eq!(rp06_source_csr_attempt_count(), 20_588);
            eprintln!(
                "RP06 pair={pair:?} final CSR={} source-attempts={} program-sha512={:02x?}",
                adapter.linear_constraint_count(),
                rp06_source_csr_attempt_count(),
                rp06_program_identity_sha512()
            );
            for (signer, approved) in [(pair[0], vec![]), (pair[1], vec![pair[0]])] {
                let (s, w) = approval_fixture(statement, witness, signer, &approved);
                compile_rp06_relation(s, &w).expect("genuine approval witness");
            }
            let (s, duplicate) = approval_fixture(statement, witness, pair[0], &[pair[0]]);
            assert!(compile_rp06_relation(s, &duplicate).is_err());
            let mut one = witness;
            one.auth.current.approval_count = 1;
            one.auth.current.approved_slots[pair[1]] = false;
            assert!(compile_rp06_relation(statement, &one).is_err());
            let mut wrong_intent = witness;
            wrong_intent.auth.current.intent_digest[6] ^= 1;
            assert!(compile_rp06_relation(statement, &wrong_intent).is_err());
            let mut changed = statement;
            changed.chain_id[31] ^= 1;
            assert!(compile_rp06_relation(changed, &witness).is_err());
            let mut changed = statement;
            changed.base.nullifiers[0][6] ^= 1;
            assert!(compile_rp06_relation(changed, &witness).is_err());
            let mut changed = statement;
            changed.base.commitments[0][6] ^= 1;
            assert!(compile_rp06_relation(changed, &witness).is_err());
            let mut changed = statement;
            changed.base.fee += 1;
            assert!(compile_rp06_relation(changed, &witness).is_err());
        }
    }
    fn retain_public_proof(stem: &str, statement: Rp06PublicStatement, proof: &Rp06CandidateProof) {
        if let Ok(directory) = std::env::var("HEGEMON_RP06_RETAINED_DIRECTORY") {
            for (suffix, bytes) in [
                ("smzb", proof.proof_bytes.clone()),
                ("preamble", rp06_transcript_bytes(&statement).unwrap()),
            ] {
                use std::io::Write;
                let path = std::path::Path::new(&directory).join(format!("{stem}.{suffix}"));
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .expect("retain public proof without replacing an artifact");
                file.write_all(&bytes).unwrap();
                file.sync_all().unwrap();
            }
        }
        eprintln!(
            "RP06 retained public {stem}: proof_bytes={} program_sha512={}",
            proof.proof_bytes.len(),
            hex::encode(rp06_program_identity_sha512())
        );
    }
    #[test]
    #[ignore = "full q38 N2^23 proofs; run only under the coordinator's bounded proving lane"]
    fn rp06_all_pairs_generate_and_verify_genuine_proofs() {
        for pair in [[0, 1], [0, 2], [1, 2]] {
            let (statement, witness) = final_fixture(pair);
            for (approval_index, (signer, approved)) in
                [(pair[0], vec![]), (pair[1], vec![pair[0]])]
                    .into_iter()
                    .enumerate()
            {
                let (s, w) = approval_fixture(statement, witness, signer, &approved);
                let proof = prove_rp06_candidate(s, &w).unwrap();
                assert_eq!(&proof.proof_bytes[..4], b"SMZB");
                verify_rp06_candidate(&proof, s.chain_id).unwrap();
                retain_public_proof(
                    &format!("pair{}{}-approval{}", pair[0], pair[1], approval_index + 1),
                    s,
                    &proof,
                );
            }
            let proof = prove_rp06_candidate(statement, &witness).unwrap();
            assert_eq!(&proof.proof_bytes[..4], b"SMZB");
            verify_rp06_candidate(&proof, statement.chain_id).unwrap();
            retain_public_proof(&format!("pair{}{}", pair[0], pair[1]), statement, &proof);
            let mut wrong_chain = statement.chain_id;
            wrong_chain[31] ^= 1;
            assert!(verify_rp06_candidate(&proof, wrong_chain).is_err());
            let mut truncated = proof.clone();
            truncated.proof_bytes.pop();
            assert!(verify_rp06_candidate(&truncated, statement.chain_id).is_err());
            let mut trailing = proof.clone();
            trailing.proof_bytes.push(0);
            assert!(verify_rp06_candidate(&trailing, statement.chain_id).is_err());
            let mut relabelled = proof.clone();
            relabelled.proof_bytes[..4].copy_from_slice(b"SMZA");
            assert!(verify_rp06_candidate(&relabelled, statement.chain_id).is_err());
        }
    }
}
