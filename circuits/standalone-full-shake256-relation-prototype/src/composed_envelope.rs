//! Exact direct-proof envelope and action-composition boundary for V5/Delta.
//!
//! This module remains prospective and isolated from consensus.  Its purpose is
//! to make the production boundary unambiguous: the proof envelope contains no
//! public statement, the verifier reconstructs the unique 853-byte statement
//! from authoritative action fields and exact canonical ciphertext bytes, and
//! the backend must consume the complete proof transcript.

use core::fmt;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::{
    ActivationBinding, BALANCE_SLOTS, CANONICAL_STATEMENT_BYTES, DIGEST_BYTES, Digest,
    FullStatement, MAX_INPUTS, MAX_OUTPUTS, PROFILE_TAG, SignedAmount, StablecoinBinding,
    StatementDecodeError, StatementEncodeError, decode_canonical_statement,
    encode_canonical_statement, intent_digest,
};
use crate::action_adapter::{
    ActionAdapterError, AdaptedAction, RouteAuthority, adapt_fixed_slot_action,
};

pub const ENVELOPE_MAGIC: [u8; 4] = *b"HGSP";
pub const ENVELOPE_VERSION: u16 = 2;
pub const ENVELOPE_BACKEND_M4: u8 = 2;
pub const ENVELOPE_PROFILE_FULL_2X2: u8 = 3;
pub const ENVELOPE_HEADER_BYTES: usize = 12;
/// Complete direct-proof envelope cap, including the 12-byte routing header.
pub const MAX_ENVELOPE_BYTES: usize = 512 * 1024;
pub const MAX_PROOF_BYTES: usize = MAX_ENVELOPE_BYTES - ENVELOPE_HEADER_BYTES;
pub const WALLET_V3_CIPHERTEXT_CONTAINER_BYTES: usize = 579;
pub const WALLET_V3_ML_KEM_1024_CIPHERTEXT_BYTES: usize = 1_568;
/// Exact active wallet-v3 Gamma DA ciphertext length. The concrete wallet
/// canonicalizer must still prove the grammar, suite, padding, and exact
/// re-encoding; length alone is not a certificate.
pub const MAX_CANONICAL_CIPHERTEXT_BYTES: usize =
    WALLET_V3_CIPHERTEXT_CONTAINER_BYTES + WALLET_V3_ML_KEM_1024_CIPHERTEXT_BYTES;
pub const ACTION_BINDING_BYTES: usize = 64;
pub const M4_PUBLIC_WORD_BYTES: usize = 8;
pub const M4_STATEMENT_WORDS: usize = CANONICAL_STATEMENT_BYTES.div_ceil(M4_PUBLIC_WORD_BYTES);
pub const M4_PUBLIC_TRANSPORT_BYTES: usize =
    M4_STATEMENT_WORDS * M4_PUBLIC_WORD_BYTES + DIGEST_BYTES;

const ROLE_CIPHERTEXT_HASH: [u8; 8] = *b"ct.hash1";
const ACTION_BINDING_DOMAIN: &[u8] = b"hegemon.full-action-binding.v2\0";
const PROOF_BINDING_DOMAIN: &[u8] = b"hegemon.full-m4-direct-proof.v3\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedEnvelope<'a> {
    pub proof: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    HeaderTooShort { observed: usize },
    InvalidMagic([u8; 4]),
    UnsupportedVersion(u16),
    UnsupportedBackend(u8),
    UnsupportedProfile(u8),
    EmptyProof,
    ProofTooLarge { declared: usize, maximum: usize },
    TruncatedProof { declared: usize, available: usize },
    TrailingBytes { trailing: usize },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for EnvelopeError {}

pub fn encode_envelope(proof: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    validate_proof_len(proof.len())?;
    let mut encoded = Vec::with_capacity(ENVELOPE_HEADER_BYTES + proof.len());
    encoded.extend_from_slice(&ENVELOPE_MAGIC);
    encoded.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    encoded.push(ENVELOPE_BACKEND_M4);
    encoded.push(ENVELOPE_PROFILE_FULL_2X2);
    encoded.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    encoded.extend_from_slice(proof);
    Ok(encoded)
}

/// Borrow one complete proof.  Size and routing checks happen before action,
/// ciphertext, or backend work.
pub fn decode_envelope_exact(encoded: &[u8]) -> Result<DecodedEnvelope<'_>, EnvelopeError> {
    if encoded.len() < ENVELOPE_HEADER_BYTES {
        return Err(EnvelopeError::HeaderTooShort {
            observed: encoded.len(),
        });
    }
    let magic: [u8; 4] = encoded[..4].try_into().expect("fixed header was checked");
    if magic != ENVELOPE_MAGIC {
        return Err(EnvelopeError::InvalidMagic(magic));
    }
    let version = u16::from_le_bytes(encoded[4..6].try_into().expect("fixed header was checked"));
    if version != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion(version));
    }
    if encoded[6] != ENVELOPE_BACKEND_M4 {
        return Err(EnvelopeError::UnsupportedBackend(encoded[6]));
    }
    if encoded[7] != ENVELOPE_PROFILE_FULL_2X2 {
        return Err(EnvelopeError::UnsupportedProfile(encoded[7]));
    }
    let declared =
        u32::from_le_bytes(encoded[8..12].try_into().expect("fixed header was checked")) as usize;
    validate_proof_len(declared)?;
    let available = encoded.len() - ENVELOPE_HEADER_BYTES;
    if available < declared {
        return Err(EnvelopeError::TruncatedProof {
            declared,
            available,
        });
    }
    if available > declared {
        return Err(EnvelopeError::TrailingBytes {
            trailing: available - declared,
        });
    }
    Ok(DecodedEnvelope {
        proof: &encoded[ENVELOPE_HEADER_BYTES..],
    })
}

fn validate_proof_len(proof_len: usize) -> Result<(), EnvelopeError> {
    if proof_len == 0 {
        return Err(EnvelopeError::EmptyProof);
    }
    if proof_len > MAX_PROOF_BYTES {
        return Err(EnvelopeError::ProofTooLarge {
            declared: proof_len,
            maximum: MAX_PROOF_BYTES,
        });
    }
    Ok(())
}

/// Authoritative prospective action projection.  Digest slots are fixed-width;
/// inactive slots remain present and canonical zero.  The proof is deliberately
/// passed separately so no legacy artifact can become a second authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProspectiveFullInlineAction<'a> {
    pub input_flags: [bool; MAX_INPUTS],
    pub output_flags: [bool; MAX_OUTPUTS],
    pub anchor: Digest,
    pub nullifiers: [Digest; MAX_INPUTS],
    pub commitments: [Digest; MAX_OUTPUTS],
    pub ciphertexts: [&'a [u8]; MAX_OUTPUTS],
    pub ciphertext_sizes: [u32; MAX_OUTPUTS],
    pub balance_slot_asset_ids: [u64; BALANCE_SLOTS],
    pub fee: u64,
    pub value_balance: SignedAmount,
    pub stablecoin: StablecoinBinding,
    pub balance_tag: Digest,
    pub activation: ActivationBinding,
    pub statement_binding: [u8; ACTION_BINDING_BYTES],
    pub legacy_candidate_artifact: Option<&'a [u8]>,
}

/// Trusted wallet/parser boundary. Implementations must exact-decode the
/// selected ciphertext grammar and write its unique canonical re-encoding.
///
/// In production this must be a concrete adapter to the wallet's v3 DA parser,
/// not a prefix parser or a closure that merely copies `encoded`. Until that
/// adapter and its parser-refinement evidence exist, this trait is an explicit
/// external certificate blocker rather than ciphertext-validation evidence.
pub trait CanonicalCiphertextValidator {
    type Error;

    fn canonicalize_exact(
        &self,
        slot: usize,
        encoded: &[u8],
        canonical: &mut Vec<u8>,
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullProofBinding<'a> {
    statement: &'a [u8; CANONICAL_STATEMENT_BYTES],
    derived_intent: Digest,
}

impl<'a> FullProofBinding<'a> {
    /// Construct the verifier capability only inside authoritative action
    /// composition. External callers cannot turn arbitrary statement bytes
    /// into a value accepted by [`FullProofVerifier`].
    fn from_canonical_statement(
        statement: &'a [u8; CANONICAL_STATEMENT_BYTES],
    ) -> Result<Self, StatementDecodeError> {
        let decoded = decode_canonical_statement(statement)?;
        Ok(Self {
            statement,
            derived_intent: intent_digest(&decoded),
        })
    }

    pub const fn statement(&self) -> &'a [u8; CANONICAL_STATEMENT_BYTES] {
        self.statement
    }

    /// Seven additional public M4 words derived from the exact statement.
    /// The circuit consumes these words instead of recomputing the public
    /// `intent.1` hash.  A backend must therefore append this digest to its
    /// public vector and observe it in Fiat--Shamir; treating it as metadata
    /// would make the public-hash size optimization unsound.
    pub const fn derived_intent(&self) -> &Digest {
        &self.derived_intent
    }

    /// Exact byte layout of the M4 public words: the 853-byte statement,
    /// three constrained zero pad bytes completing its final word, then the
    /// 56-byte derived intent.  Keeping the word-alignment gap here prevents
    /// independent prover/verifier packers from silently shifting the digest.
    pub fn m4_public_transport(&self) -> [u8; M4_PUBLIC_TRANSPORT_BYTES] {
        let mut output = [0; M4_PUBLIC_TRANSPORT_BYTES];
        output[..CANONICAL_STATEMENT_BYTES].copy_from_slice(self.statement);
        let intent_offset = M4_STATEMENT_WORDS * M4_PUBLIC_WORD_BYTES;
        output[intent_offset..intent_offset + DIGEST_BYTES].copy_from_slice(&self.derived_intent);
        output
    }

    /// Canonical context every prover and verifier must observe before the
    /// backend transcript.  It binds the compact envelope route and the entire
    /// locally reconstructed public statement.
    pub fn write_transcript_preamble(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(PROOF_BINDING_DOMAIN);
        output.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
        output.push(ENVELOPE_BACKEND_M4);
        output.push(ENVELOPE_PROFILE_FULL_2X2);
        output.extend_from_slice(&(CANONICAL_STATEMENT_BYTES as u32).to_le_bytes());
        output.extend_from_slice(self.statement);
        output.extend_from_slice(&(DIGEST_BYTES as u16).to_le_bytes());
        output.extend_from_slice(&self.derived_intent);
    }

    pub fn shake256_512(&self) -> [u8; 64] {
        let mut preimage = Vec::new();
        self.write_transcript_preamble(&mut preimage);
        shake::<64>(&preimage)
    }
}

/// Non-authorizing prover material derived from one exact canonical statement.
///
/// This deliberately is a different type from [`FullProofBinding`] and has no
/// conversion into it. Wallets and research provers may derive the public M4
/// transport and transcript preamble, but only authoritative action
/// composition can create the verifier capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullProofProverBinding<'a> {
    statement: &'a [u8; CANONICAL_STATEMENT_BYTES],
    derived_intent: Digest,
}

impl<'a> FullProofProverBinding<'a> {
    pub fn from_canonical_statement(
        statement: &'a [u8; CANONICAL_STATEMENT_BYTES],
    ) -> Result<Self, StatementDecodeError> {
        let decoded = decode_canonical_statement(statement)?;
        Ok(Self {
            statement,
            derived_intent: intent_digest(&decoded),
        })
    }

    pub const fn statement(&self) -> &'a [u8; CANONICAL_STATEMENT_BYTES] {
        self.statement
    }

    pub const fn derived_intent(&self) -> &Digest {
        &self.derived_intent
    }

    pub fn m4_public_transport(&self) -> [u8; M4_PUBLIC_TRANSPORT_BYTES] {
        let mut output = [0; M4_PUBLIC_TRANSPORT_BYTES];
        output[..CANONICAL_STATEMENT_BYTES].copy_from_slice(self.statement);
        let intent_offset = M4_STATEMENT_WORDS * M4_PUBLIC_WORD_BYTES;
        output[intent_offset..intent_offset + DIGEST_BYTES].copy_from_slice(&self.derived_intent);
        output
    }

    pub fn write_transcript_preamble(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(PROOF_BINDING_DOMAIN);
        output.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
        output.push(ENVELOPE_BACKEND_M4);
        output.push(ENVELOPE_PROFILE_FULL_2X2);
        output.extend_from_slice(&(CANONICAL_STATEMENT_BYTES as u32).to_le_bytes());
        output.extend_from_slice(self.statement);
        output.extend_from_slice(&(DIGEST_BYTES as u16).to_le_bytes());
        output.extend_from_slice(&self.derived_intent);
    }

    pub fn shake256_512(&self) -> [u8; 64] {
        let mut preimage = Vec::new();
        self.write_transcript_preamble(&mut preimage);
        shake::<64>(&preimage)
    }
}

/// The implementation must build its verifier-owned public words only from
/// [`FullProofBinding::m4_public_transport`], observe the complete binding
/// preamble, reject malformed proofs, and exact-consume its transcript
/// (including rejecting internal trailing bytes). Loose raw-proof verification
/// must remain private.
pub trait FullProofVerifier {
    type Error;

    fn verify_exact(&self, binding: FullProofBinding<'_>, proof: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum ComposedVerificationError<CiphertextError, BackendError> {
    Envelope(EnvelopeError),
    LegacyCandidateArtifact,
    CiphertextSizeOverflow(usize),
    CiphertextSizeMismatch {
        slot: usize,
        declared: u32,
        actual: usize,
    },
    InactiveCiphertext(usize),
    EmptyActiveCiphertext(usize),
    NonCanonicalCiphertextLength {
        slot: usize,
        expected: usize,
        actual: usize,
    },
    CiphertextValidator {
        slot: usize,
        error: CiphertextError,
    },
    NonCanonicalCiphertext(usize),
    StatementEncode(StatementEncodeError),
    StatementReparse(StatementDecodeError),
    StatementBinding,
    Action(ActionAdapterError),
    Backend(BackendError),
}

/// Verify one direct proof against an action projection and exact ciphertexts.
/// The returned stablecoin update is still a CAS token and must be committed in
/// the same canonical state transaction as action acceptance.
pub fn verify_composed_action<C, V>(
    envelope_bytes: &[u8],
    action: &ProspectiveFullInlineAction<'_>,
    authority: &RouteAuthority<'_>,
    ciphertext_validator: &C,
    verifier: &V,
) -> Result<AdaptedAction, ComposedVerificationError<C::Error, V::Error>>
where
    C: CanonicalCiphertextValidator,
    V: FullProofVerifier,
{
    let envelope =
        decode_envelope_exact(envelope_bytes).map_err(ComposedVerificationError::Envelope)?;
    if action.legacy_candidate_artifact.is_some() {
        return Err(ComposedVerificationError::LegacyCandidateArtifact);
    }
    let statement = reconstruct_statement(action, ciphertext_validator)?;
    let statement_bytes = encode_canonical_statement(&statement)
        .map_err(ComposedVerificationError::StatementEncode)?;
    if action.statement_binding != action_binding_digest(&statement_bytes) {
        return Err(ComposedVerificationError::StatementBinding);
    }
    let adapted = adapt_fixed_slot_action(&statement_bytes, authority)
        .map_err(ComposedVerificationError::Action)?;
    let binding = FullProofBinding::from_canonical_statement(&statement_bytes)
        .map_err(ComposedVerificationError::StatementReparse)?;
    verifier
        .verify_exact(binding, envelope.proof)
        .map_err(ComposedVerificationError::Backend)?;
    Ok(adapted)
}

pub fn reconstruct_statement<C, BackendError>(
    action: &ProspectiveFullInlineAction<'_>,
    ciphertext_validator: &C,
) -> Result<FullStatement, ComposedVerificationError<C::Error, BackendError>>
where
    C: CanonicalCiphertextValidator,
{
    let mut ciphertext_hashes = [[0; DIGEST_BYTES]; MAX_OUTPUTS];
    for slot in 0..MAX_OUTPUTS {
        let encoded = action.ciphertexts[slot];
        if encoded.len() > MAX_CANONICAL_CIPHERTEXT_BYTES {
            return Err(ComposedVerificationError::CiphertextSizeOverflow(slot));
        }
        if usize::try_from(action.ciphertext_sizes[slot]).ok() != Some(encoded.len()) {
            return Err(ComposedVerificationError::CiphertextSizeMismatch {
                slot,
                declared: action.ciphertext_sizes[slot],
                actual: encoded.len(),
            });
        }
        if !action.output_flags[slot] {
            if !encoded.is_empty() {
                return Err(ComposedVerificationError::InactiveCiphertext(slot));
            }
            continue;
        }
        if encoded.is_empty() {
            return Err(ComposedVerificationError::EmptyActiveCiphertext(slot));
        }
        if encoded.len() != MAX_CANONICAL_CIPHERTEXT_BYTES {
            return Err(ComposedVerificationError::NonCanonicalCiphertextLength {
                slot,
                expected: MAX_CANONICAL_CIPHERTEXT_BYTES,
                actual: encoded.len(),
            });
        }
        let mut canonical = Vec::with_capacity(encoded.len());
        ciphertext_validator
            .canonicalize_exact(slot, encoded, &mut canonical)
            .map_err(|error| ComposedVerificationError::CiphertextValidator { slot, error })?;
        if canonical != encoded {
            return Err(ComposedVerificationError::NonCanonicalCiphertext(slot));
        }
        ciphertext_hashes[slot] = ciphertext_hash(slot, encoded);
    }

    Ok(FullStatement {
        input_flags: action.input_flags,
        output_flags: action.output_flags,
        anchor: action.anchor,
        nullifiers: action.nullifiers,
        commitments: action.commitments,
        ciphertext_hashes,
        balance_slot_asset_ids: action.balance_slot_asset_ids,
        fee: action.fee,
        value_balance: action.value_balance,
        stablecoin: action.stablecoin.clone(),
        balance_tag: action.balance_tag,
        activation: action.activation.clone(),
    })
}

pub fn ciphertext_hash(slot: usize, ciphertext: &[u8]) -> Digest {
    assert!(slot < MAX_OUTPUTS);
    assert!(ciphertext.len() <= MAX_CANONICAL_CIPHERTEXT_BYTES);
    let mut frame = Vec::with_capacity(8 + 8 + 1 + 2 + 1 + 2 + ciphertext.len());
    frame.extend_from_slice(&PROFILE_TAG);
    frame.extend_from_slice(&ROLE_CIPHERTEXT_HASH);
    frame.push(2);
    frame.extend_from_slice(&1u16.to_be_bytes());
    frame.push(slot as u8);
    frame.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    frame.extend_from_slice(ciphertext);
    shake::<DIGEST_BYTES>(&frame)
}

pub fn action_binding_digest(statement: &[u8; CANONICAL_STATEMENT_BYTES]) -> [u8; 64] {
    let mut frame = Vec::with_capacity(ACTION_BINDING_DOMAIN.len() + 4 + statement.len());
    frame.extend_from_slice(ACTION_BINDING_DOMAIN);
    frame.extend_from_slice(&(statement.len() as u32).to_le_bytes());
    frame.extend_from_slice(statement);
    shake::<64>(&frame)
}

fn shake<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = [0; N];
    reader.read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::{encode_canonical_statement, expected_balance_tag, mask_fixture};

    const PROOF: &[u8] = b"canonical-proof";
    static CT0_BYTES: [u8; MAX_CANONICAL_CIPHERTEXT_BYTES] = mock_ciphertext(b'0');
    static CT1_BYTES: [u8; MAX_CANONICAL_CIPHERTEXT_BYTES] = mock_ciphertext(b'1');
    const CT0: &[u8] = &CT0_BYTES;
    const CT1: &[u8] = &CT1_BYTES;

    const fn mock_ciphertext(label: u8) -> [u8; MAX_CANONICAL_CIPHERTEXT_BYTES] {
        let mut bytes = [0; MAX_CANONICAL_CIPHERTEXT_BYTES];
        bytes[0] = b'c';
        bytes[1] = b't';
        bytes[2] = b':';
        bytes[3] = label;
        bytes
    }

    struct Canonicalizer {
        calls: Cell<usize>,
    }

    impl CanonicalCiphertextValidator for Canonicalizer {
        type Error = &'static str;

        fn canonicalize_exact(
            &self,
            _slot: usize,
            encoded: &[u8],
            canonical: &mut Vec<u8>,
        ) -> Result<(), Self::Error> {
            self.calls.set(self.calls.get() + 1);
            if !encoded.starts_with(b"ct:") {
                return Err("ciphertext grammar");
            }
            canonical.extend_from_slice(encoded);
            Ok(())
        }
    }

    struct Verifier {
        calls: Cell<usize>,
        expected_binding: [u8; 64],
    }

    impl FullProofVerifier for Verifier {
        type Error = &'static str;

        fn verify_exact(
            &self,
            binding: FullProofBinding<'_>,
            proof: &[u8],
        ) -> Result<(), Self::Error> {
            self.calls.set(self.calls.get() + 1);
            if binding.shake256_512() != self.expected_binding {
                return Err("binding");
            }
            if proof != PROOF {
                return Err("proof");
            }
            assert_eq!(binding.statement().len(), CANONICAL_STATEMENT_BYTES);
            let decoded = crate::decode_canonical_statement(binding.statement())
                .map_err(|_| "statement decode")?;
            if binding.derived_intent() != &crate::intent_digest(&decoded) {
                return Err("derived intent");
            }
            let transport = binding.m4_public_transport();
            assert_eq!(transport.len(), 912);
            assert_eq!(&transport[..CANONICAL_STATEMENT_BYTES], binding.statement());
            assert_eq!(&transport[CANONICAL_STATEMENT_BYTES..856], &[0; 3]);
            assert_eq!(&transport[856..], binding.derived_intent());
            Ok(())
        }
    }

    struct ReencodingCanonicalizer;

    impl CanonicalCiphertextValidator for ReencodingCanonicalizer {
        type Error = &'static str;

        fn canonicalize_exact(
            &self,
            _slot: usize,
            encoded: &[u8],
            canonical: &mut Vec<u8>,
        ) -> Result<(), Self::Error> {
            canonical.extend_from_slice(encoded);
            canonical.push(0);
            Ok(())
        }
    }

    fn action<'a>(mask: u8) -> ProspectiveFullInlineAction<'a> {
        let (mut statement, _) = mask_fixture(mask);
        let ciphertexts = [
            if statement.output_flags[0] { CT0 } else { b"" },
            if statement.output_flags[1] { CT1 } else { b"" },
        ];
        statement.ciphertext_hashes = core::array::from_fn(|slot| {
            if statement.output_flags[slot] {
                ciphertext_hash(slot, ciphertexts[slot])
            } else {
                [0; DIGEST_BYTES]
            }
        });
        statement.balance_tag = expected_balance_tag(&statement);
        let encoded = encode_canonical_statement(&statement).unwrap();
        ProspectiveFullInlineAction {
            input_flags: statement.input_flags,
            output_flags: statement.output_flags,
            anchor: statement.anchor,
            nullifiers: statement.nullifiers,
            commitments: statement.commitments,
            ciphertexts,
            ciphertext_sizes: ciphertexts.map(|bytes| bytes.len() as u32),
            balance_slot_asset_ids: statement.balance_slot_asset_ids,
            fee: statement.fee,
            value_balance: statement.value_balance,
            stablecoin: statement.stablecoin,
            balance_tag: statement.balance_tag,
            activation: statement.activation,
            statement_binding: action_binding_digest(&encoded),
            legacy_candidate_artifact: None,
        }
    }

    fn authority<'a>(action: &'a ProspectiveFullInlineAction<'_>) -> RouteAuthority<'a> {
        RouteAuthority::from_active_snapshot(&action.activation, 7, 11, &[]).unwrap()
    }

    fn expected_binding(action: &ProspectiveFullInlineAction<'_>) -> [u8; 64] {
        let canonicalizer = Canonicalizer {
            calls: Cell::new(0),
        };
        let statement = reconstruct_statement::<_, &'static str>(action, &canonicalizer).unwrap();
        let statement_bytes = encode_canonical_statement(&statement).unwrap();
        FullProofBinding::from_canonical_statement(&statement_bytes)
            .unwrap()
            .shake256_512()
    }

    fn verifier(action: &ProspectiveFullInlineAction<'_>) -> Verifier {
        Verifier {
            calls: Cell::new(0),
            expected_binding: expected_binding(action),
        }
    }

    #[test]
    fn prover_material_matches_but_cannot_become_verifier_capability() {
        let action = action(0b1111);
        let canonicalizer = Canonicalizer {
            calls: Cell::new(0),
        };
        let statement = reconstruct_statement::<_, &'static str>(&action, &canonicalizer).unwrap();
        let statement_bytes = encode_canonical_statement(&statement).unwrap();
        let verifier_binding =
            FullProofBinding::from_canonical_statement(&statement_bytes).unwrap();
        let prover_binding =
            FullProofProverBinding::from_canonical_statement(&statement_bytes).unwrap();
        assert_eq!(
            verifier_binding.m4_public_transport(),
            prover_binding.m4_public_transport()
        );
        assert_eq!(
            verifier_binding.shake256_512(),
            prover_binding.shake256_512()
        );
    }

    #[test]
    fn exact_composition_accepts_and_binds_ciphertexts_statement_and_proof() {
        let action = action(0b1111);
        let canonicalizer = Canonicalizer {
            calls: Cell::new(0),
        };
        let verifier = verifier(&action);
        let envelope = encode_envelope(PROOF).unwrap();
        let adapted = verify_composed_action(
            &envelope,
            &action,
            &authority(&action),
            &canonicalizer,
            &verifier,
        )
        .unwrap();
        assert_eq!(adapted.statement().output_flags, [true, true]);
        assert_eq!(canonicalizer.calls.get(), 2);
        assert_eq!(verifier.calls.get(), 1);
    }

    #[test]
    fn envelope_failures_are_cheap_and_precede_action_work() {
        let action = action(0b1111);
        let valid = encode_envelope(PROOF).unwrap();
        let mut cases = Vec::new();
        cases.push(Vec::new());
        let mut bad = valid.clone();
        bad[0] ^= 1;
        cases.push(bad);
        let mut bad = valid.clone();
        bad[4] ^= 1;
        cases.push(bad);
        let mut bad = valid.clone();
        bad[6] ^= 1;
        cases.push(bad);
        let mut bad = valid.clone();
        bad[7] ^= 1;
        cases.push(bad);
        let mut bad = valid.clone();
        bad[8..12].copy_from_slice(&0u32.to_le_bytes());
        cases.push(bad);
        let mut bad = valid.clone();
        bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(bad);
        cases.push(valid[..valid.len() - 1].to_vec());
        let mut bad = valid;
        bad.push(0);
        cases.push(bad);

        for encoded in cases {
            let canonicalizer = Canonicalizer {
                calls: Cell::new(0),
            };
            let verifier = verifier(&action);
            assert!(
                verify_composed_action(
                    &encoded,
                    &action,
                    &authority(&action),
                    &canonicalizer,
                    &verifier,
                )
                .is_err()
            );
            assert_eq!(canonicalizer.calls.get(), 0);
            assert_eq!(verifier.calls.get(), 0);
        }
    }

    #[test]
    fn action_ciphertext_and_binding_mutations_never_reach_backend() {
        let envelope = encode_envelope(PROOF).unwrap();
        let mut actions = Vec::new();

        let mut changed = action(0b1111);
        changed.ciphertext_sizes[0] += 1;
        actions.push(changed);

        let mut changed = action(0b1111);
        changed.ciphertexts[0] = b"not-canonical";
        changed.ciphertext_sizes[0] = changed.ciphertexts[0].len() as u32;
        actions.push(changed);

        let mut changed = action(0b1111);
        changed.statement_binding[0] ^= 1;
        actions.push(changed);

        let mut changed = action(0b0101);
        changed.ciphertexts[1] = CT1;
        changed.ciphertext_sizes[1] = CT1.len() as u32;
        actions.push(changed);

        let mut changed = action(0b1111);
        changed.legacy_candidate_artifact = Some(b"legacy");
        actions.push(changed);

        for changed in actions {
            let canonicalizer = Canonicalizer {
                calls: Cell::new(0),
            };
            // These cases must fail before the backend. Use an independently
            // valid expected binding so constructing the mock cannot bless or
            // attempt to canonicalize the malformed action under test.
            let verifier = verifier(&action(0b1111));
            assert!(
                verify_composed_action(
                    &envelope,
                    &changed,
                    &authority(&changed),
                    &canonicalizer,
                    &verifier,
                )
                .is_err()
            );
            assert_eq!(verifier.calls.get(), 0);
        }
    }

    #[test]
    fn proof_mutation_reaches_only_the_exact_backend_gate() {
        let action = action(0b1111);
        let canonicalizer = Canonicalizer {
            calls: Cell::new(0),
        };
        let verifier = verifier(&action);
        let envelope = encode_envelope(b"changed-proof").unwrap();
        assert!(matches!(
            verify_composed_action(
                &envelope,
                &action,
                &authority(&action),
                &canonicalizer,
                &verifier,
            ),
            Err(ComposedVerificationError::Backend("proof"))
        ));
        assert_eq!(verifier.calls.get(), 1);
    }

    #[test]
    fn ciphertext_resource_and_canonicality_fail_before_backend() {
        let envelope = encode_envelope(PROOF).unwrap();

        let mut empty = action(0b1111);
        empty.ciphertexts[0] = b"";
        empty.ciphertext_sizes[0] = 0;
        let verifier = verifier(&action(0b1111));
        assert!(matches!(
            verify_composed_action(
                &envelope,
                &empty,
                &authority(&empty),
                &Canonicalizer {
                    calls: Cell::new(0),
                },
                &verifier,
            ),
            Err(ComposedVerificationError::EmptyActiveCiphertext(0))
        ));
        assert_eq!(verifier.calls.get(), 0);

        let oversized_bytes = vec![0x41; MAX_CANONICAL_CIPHERTEXT_BYTES + 1];
        let mut oversized = action(0b1111);
        oversized.ciphertexts[0] = &oversized_bytes;
        oversized.ciphertext_sizes[0] = oversized_bytes.len() as u32;
        let verifier = verifier(&action(0b1111));
        assert!(matches!(
            verify_composed_action(
                &envelope,
                &oversized,
                &authority(&oversized),
                &Canonicalizer {
                    calls: Cell::new(0),
                },
                &verifier,
            ),
            Err(ComposedVerificationError::CiphertextSizeOverflow(0))
        ));
        assert_eq!(verifier.calls.get(), 0);

        let mut undersized = action(0b1111);
        undersized.ciphertexts[0] = &CT0[..CT0.len() - 1];
        undersized.ciphertext_sizes[0] = undersized.ciphertexts[0].len() as u32;
        let verifier = verifier(&action(0b1111));
        assert!(matches!(
            verify_composed_action(
                &envelope,
                &undersized,
                &authority(&undersized),
                &Canonicalizer {
                    calls: Cell::new(0),
                },
                &verifier,
            ),
            Err(ComposedVerificationError::NonCanonicalCiphertextLength { slot: 0, .. })
        ));
        assert_eq!(verifier.calls.get(), 0);

        let changed = action(0b1111);
        let verifier = verifier(&changed);
        assert!(matches!(
            verify_composed_action(
                &envelope,
                &changed,
                &authority(&changed),
                &ReencodingCanonicalizer,
                &verifier,
            ),
            Err(ComposedVerificationError::NonCanonicalCiphertext(0))
        ));
        assert_eq!(verifier.calls.get(), 0);
    }

    #[test]
    fn recomputed_action_binding_cannot_retarget_a_proof() {
        let original = action(0b1111);
        let verifier = verifier(&original);
        let mut changed = original.clone();
        changed.fee += 1;
        let canonicalizer = Canonicalizer {
            calls: Cell::new(0),
        };
        let mut changed_statement =
            reconstruct_statement::<_, &'static str>(&changed, &canonicalizer).unwrap();
        changed_statement.balance_tag = expected_balance_tag(&changed_statement);
        changed.balance_tag = changed_statement.balance_tag;
        let changed_bytes = encode_canonical_statement(&changed_statement).unwrap();
        changed.statement_binding = action_binding_digest(&changed_bytes);

        let envelope = encode_envelope(PROOF).unwrap();
        assert!(matches!(
            verify_composed_action(
                &envelope,
                &changed,
                &authority(&changed),
                &canonicalizer,
                &verifier,
            ),
            Err(ComposedVerificationError::Backend("binding"))
        ));
        assert_eq!(verifier.calls.get(), 1);
    }

    #[test]
    fn backend_rejects_internal_proof_trailing_bytes() {
        let action = action(0b1111);
        let verifier = verifier(&action);
        let mut proof = PROOF.to_vec();
        proof.push(0);
        let envelope = encode_envelope(&proof).unwrap();
        assert!(matches!(
            verify_composed_action(
                &envelope,
                &action,
                &authority(&action),
                &Canonicalizer {
                    calls: Cell::new(0),
                },
                &verifier,
            ),
            Err(ComposedVerificationError::Backend("proof"))
        ));
        assert_eq!(verifier.calls.get(), 1);
    }
}
