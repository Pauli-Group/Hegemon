//! Canonical direct-proof envelope prototype for Hegemon.
//!
//! This crate is intentionally isolated from the production workspace. It defines the
//! byte boundary that a future standalone binary proof must cross, but it does not
//! activate a proof backend or a consensus route.
//!
//! The envelope contains only a fixed header followed by the backend's proof bytes.
//! It does not carry a second copy of the public statement, a receipt, an aggregate,
//! a sidecar locator, or the retired `NativeTxLeafArtifact`. Verification reconstructs
//! the canonical public statement from the action and supplies those exact bytes to
//! the backend through [`ProofBinding`].

use core::fmt;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// The envelope magic, chosen to make the format distinguishable before routing.
pub const ENVELOPE_MAGIC: [u8; 4] = *b"HGSP";

/// The only envelope version implemented by this prototype.
pub const ENVELOPE_VERSION_V1: u16 = 1;

/// Four magic bytes, a little-endian `u16` version, one backend byte, one profile
/// byte, and a little-endian `u32` proof length.
pub const ENVELOPE_HEADER_BYTES: usize = 12;

/// The maximum accepted complete standalone artifact, including its header.
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576;

/// The maximum backend-proof payload that leaves room for the canonical header.
pub const MAX_PROOF_BYTES: usize = MAX_ENVELOPE_BYTES - ENVELOPE_HEADER_BYTES;

/// A defensive cap for reconstructed public statement bytes in the prototype.
pub const MAX_CANONICAL_STATEMENT_BYTES: usize = 65_536;

/// Domain used when a backend reduces the exact binding preimage to SHAKE256-512.
///
/// A backend may absorb [`ProofBinding::write_transcript_preimage`] directly instead.
pub const BINDING_DIGEST_DOMAIN: &[u8] = b"hegemon.standalone-proof-binding.v1\0";

/// The single backend identifier admitted by the prototype parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BackendId {
    /// The selected direct IronSpartan path in the reviewed Binius64 fork.
    Binius64IronSpartan = 1,
}

impl BackendId {
    fn parse(value: u8) -> Result<Self, EnvelopeError> {
        match value {
            1 => Ok(Self::Binius64IronSpartan),
            other => Err(EnvelopeError::UnsupportedBackend(other)),
        }
    }
}

/// Fixed transaction shapes. Each shape has its own relation and verifier profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofProfile {
    /// One hidden input and two hidden outputs: the normal payment path.
    Pay1x2 = 1,
    /// Two hidden inputs and one hidden output: the wallet consolidation path.
    Consolidate2x1 = 2,
}

impl ProofProfile {
    fn parse(value: u8) -> Result<Self, EnvelopeError> {
        match value {
            1 => Ok(Self::Pay1x2),
            2 => Ok(Self::Consolidate2x1),
            other => Err(EnvelopeError::UnsupportedProfile(other)),
        }
    }
}

/// A borrowed, exactly decoded direct-proof envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedEnvelope<'a> {
    pub backend: BackendId,
    pub profile: ProofProfile,
    pub proof: &'a [u8],
}

impl DecodedEnvelope<'_> {
    /// The complete canonical envelope size for this proof.
    pub const fn encoded_len(&self) -> usize {
        ENVELOPE_HEADER_BYTES + self.proof.len()
    }
}

/// Fail-closed parser and encoder errors.
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTooShort { observed } => write!(
                f,
                "standalone proof envelope header is short: observed {observed}, expected {ENVELOPE_HEADER_BYTES}"
            ),
            Self::InvalidMagic(magic) => {
                write!(f, "invalid standalone proof envelope magic: {magic:02x?}")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported standalone proof envelope version {version}")
            }
            Self::UnsupportedBackend(backend) => {
                write!(f, "unsupported standalone proof backend {backend}")
            }
            Self::UnsupportedProfile(profile) => {
                write!(f, "unsupported standalone proof profile {profile}")
            }
            Self::EmptyProof => f.write_str("standalone proof payload is empty"),
            Self::ProofTooLarge { declared, maximum } => write!(
                f,
                "standalone proof payload declares {declared} bytes, above the {maximum}-byte cap"
            ),
            Self::TruncatedProof {
                declared,
                available,
            } => write!(
                f,
                "standalone proof payload is truncated: declared {declared}, available {available}"
            ),
            Self::TrailingBytes { trailing } => write!(
                f,
                "standalone proof envelope has {trailing} trailing bytes"
            ),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Encode the fixed V1 header and the backend proof without another artifact wrapper.
pub fn encode_envelope(
    backend: BackendId,
    profile: ProofProfile,
    proof: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    validate_proof_len(proof.len())?;

    let mut encoded = Vec::with_capacity(ENVELOPE_HEADER_BYTES + proof.len());
    encoded.extend_from_slice(&ENVELOPE_MAGIC);
    encoded.extend_from_slice(&ENVELOPE_VERSION_V1.to_le_bytes());
    encoded.push(backend as u8);
    encoded.push(profile as u8);
    encoded.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    encoded.extend_from_slice(proof);
    Ok(encoded)
}

/// Decode one complete envelope without allocating or accepting any trailing bytes.
///
/// The declared proof cap is checked before the parser compares the declared length
/// with the available body, so an oversized declaration fails before backend work.
pub fn decode_envelope_exact(encoded: &[u8]) -> Result<DecodedEnvelope<'_>, EnvelopeError> {
    if encoded.len() < ENVELOPE_HEADER_BYTES {
        return Err(EnvelopeError::HeaderTooShort {
            observed: encoded.len(),
        });
    }

    let magic: [u8; 4] = encoded[0..4]
        .try_into()
        .expect("the fixed header length was checked");
    if magic != ENVELOPE_MAGIC {
        return Err(EnvelopeError::InvalidMagic(magic));
    }

    let version = u16::from_le_bytes(
        encoded[4..6]
            .try_into()
            .expect("the fixed header length was checked"),
    );
    if version != ENVELOPE_VERSION_V1 {
        return Err(EnvelopeError::UnsupportedVersion(version));
    }

    let backend = BackendId::parse(encoded[6])?;
    let profile = ProofProfile::parse(encoded[7])?;
    let declared = u32::from_le_bytes(
        encoded[8..12]
            .try_into()
            .expect("the fixed header length was checked"),
    ) as usize;
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
        backend,
        profile,
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

/// Production adapters implement this on the canonical action type.
///
/// The method must reconstruct the public statement from validated action fields. It
/// must not copy a statement or digest supplied by the proof envelope. Fixed-size
/// integers must use their profile-specified canonical encoding.
pub trait CanonicalStatement {
    fn write_canonical_statement(&self, output: &mut Vec<u8>) -> Result<(), &'static str>;
}

/// Exact public material a backend must observe before checking the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofBinding<'a> {
    envelope_version: u16,
    backend: BackendId,
    profile: ProofProfile,
    canonical_statement: &'a [u8],
}

impl<'a> ProofBinding<'a> {
    /// Construct a binding for the V1 envelope after statement reconstruction.
    pub fn v1(
        backend: BackendId,
        profile: ProofProfile,
        canonical_statement: &'a [u8],
    ) -> Result<Self, BindingError> {
        if canonical_statement.len() > MAX_CANONICAL_STATEMENT_BYTES {
            return Err(BindingError::StatementTooLarge {
                observed: canonical_statement.len(),
                maximum: MAX_CANONICAL_STATEMENT_BYTES,
            });
        }
        Ok(Self {
            envelope_version: ENVELOPE_VERSION_V1,
            backend,
            profile,
            canonical_statement,
        })
    }

    pub const fn envelope_version(&self) -> u16 {
        self.envelope_version
    }

    pub const fn backend(&self) -> BackendId {
        self.backend
    }

    pub const fn profile(&self) -> ProofProfile {
        self.profile
    }

    pub const fn canonical_statement(&self) -> &'a [u8] {
        self.canonical_statement
    }

    /// Write the unambiguous transcript preimage.
    ///
    /// This contains the complete canonical statement, not a statement embedded in
    /// the proof. The statement length is little-endian and checked by
    /// [`verify_envelope_exact`] before this method is reached.
    pub fn write_transcript_preimage(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(BINDING_DIGEST_DOMAIN);
        output.extend_from_slice(&self.envelope_version.to_le_bytes());
        output.push(self.backend as u8);
        output.push(self.profile as u8);
        output.extend_from_slice(&(self.canonical_statement.len() as u32).to_le_bytes());
        output.extend_from_slice(self.canonical_statement);
    }

    /// Reference SHAKE256-512 reduction of the exact transcript preimage.
    pub fn shake256_512(&self) -> [u8; 64] {
        let mut preimage = Vec::with_capacity(
            BINDING_DIGEST_DOMAIN.len() + 2 + 1 + 1 + 4 + self.canonical_statement.len(),
        );
        self.write_transcript_preimage(&mut preimage);

        let mut hasher = Shake256::default();
        hasher.update(&preimage);
        let mut reader = hasher.finalize_xof();
        let mut digest = [0u8; 64];
        reader.read(&mut digest);
        digest
    }
}

/// Errors constructing a transcript binding outside the complete verifier path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingError {
    StatementTooLarge { observed: usize, maximum: usize },
}

/// Minimal adapter expected from the selected standalone backend.
pub trait StandaloneProofVerifier {
    type Error;

    /// The backend implemented by this verifier instance.
    fn backend(&self) -> BackendId;

    /// Verify the direct proof against the exact envelope/profile/statement binding.
    fn verify(&self, binding: ProofBinding<'_>, proof: &[u8]) -> Result<(), Self::Error>;
}

/// Errors from the complete cheap-parse, reconstruction, and backend-verification path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationError<BackendError> {
    Envelope(EnvelopeError),
    BackendMismatch {
        envelope: BackendId,
        verifier: BackendId,
    },
    ProfileMismatch {
        envelope: ProofProfile,
        expected: ProofProfile,
    },
    StatementReconstruction(&'static str),
    StatementTooLarge {
        observed: usize,
        maximum: usize,
    },
    Backend(BackendError),
}

/// Verify one complete direct-proof envelope against a statement reconstructed locally.
///
/// Parsing, cap checks, backend routing, and profile routing all happen before statement
/// reconstruction or backend work. This function never accepts statement bytes from the
/// envelope itself.
pub fn verify_envelope_exact<S, V>(
    encoded: &[u8],
    expected_profile: ProofProfile,
    statement_source: &S,
    verifier: &V,
) -> Result<(), VerificationError<V::Error>>
where
    S: CanonicalStatement,
    V: StandaloneProofVerifier,
{
    let envelope = decode_envelope_exact(encoded).map_err(VerificationError::Envelope)?;

    let verifier_backend = verifier.backend();
    if envelope.backend != verifier_backend {
        return Err(VerificationError::BackendMismatch {
            envelope: envelope.backend,
            verifier: verifier_backend,
        });
    }
    if envelope.profile != expected_profile {
        return Err(VerificationError::ProfileMismatch {
            envelope: envelope.profile,
            expected: expected_profile,
        });
    }

    let mut statement = Vec::new();
    statement_source
        .write_canonical_statement(&mut statement)
        .map_err(VerificationError::StatementReconstruction)?;
    if statement.len() > MAX_CANONICAL_STATEMENT_BYTES {
        return Err(VerificationError::StatementTooLarge {
            observed: statement.len(),
            maximum: MAX_CANONICAL_STATEMENT_BYTES,
        });
    }

    let binding = ProofBinding::v1(envelope.backend, envelope.profile, &statement).map_err(
        |BindingError::StatementTooLarge { observed, maximum }| {
            VerificationError::StatementTooLarge { observed, maximum }
        },
    )?;

    verifier
        .verify(binding, envelope.proof)
        .map_err(VerificationError::Backend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use std::cell::Cell;

    const STATEMENT_DOMAIN: &[u8] = b"hegemon.test.pay1x2.statement.v1\0";

    #[derive(Clone)]
    struct TestAction {
        chain_id: u32,
        anchor: [u8; 56],
        nullifier: [u8; 56],
        output_commitments: [[u8; 56]; 2],
        fee: u64,
    }

    impl TestAction {
        fn canonical_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::new();
            self.write_canonical_statement(&mut bytes)
                .expect("test action is canonical");
            bytes
        }
    }

    impl CanonicalStatement for TestAction {
        fn write_canonical_statement(&self, output: &mut Vec<u8>) -> Result<(), &'static str> {
            output.extend_from_slice(STATEMENT_DOMAIN);
            output.extend_from_slice(&self.chain_id.to_le_bytes());
            output.extend_from_slice(&self.anchor);
            output.extend_from_slice(&self.nullifier);
            output.extend_from_slice(&self.output_commitments[0]);
            output.extend_from_slice(&self.output_commitments[1]);
            output.extend_from_slice(&self.fee.to_le_bytes());
            Ok(())
        }
    }

    fn action() -> TestAction {
        TestAction {
            chain_id: 7,
            anchor: [0x11; 56],
            nullifier: [0x22; 56],
            output_commitments: [[0x33; 56], [0x44; 56]],
            fee: 19,
        }
    }

    /// Test-only authenticator used to prove the envelope supplies the exact binding.
    /// It is not presented as a zero-knowledge proof backend.
    struct BindingDigestVerifier {
        calls: Cell<usize>,
    }

    impl BindingDigestVerifier {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
            }
        }
    }

    impl StandaloneProofVerifier for BindingDigestVerifier {
        type Error = &'static str;

        fn backend(&self) -> BackendId {
            BackendId::Binius64IronSpartan
        }

        fn verify(&self, binding: ProofBinding<'_>, proof: &[u8]) -> Result<(), Self::Error> {
            self.calls.set(self.calls.get() + 1);
            if proof == binding.shake256_512() {
                Ok(())
            } else {
                Err("binding digest mismatch")
            }
        }
    }

    fn bound_test_proof(action: &TestAction, profile: ProofProfile) -> Vec<u8> {
        ProofBinding::v1(
            BackendId::Binius64IronSpartan,
            profile,
            &action.canonical_bytes(),
        )
        .expect("test statement is below the cap")
        .shake256_512()
        .to_vec()
    }

    #[test]
    fn wire_kat_is_header_then_unchanged_direct_proof() {
        let proof = [0xaa, 0xbb, 0xcc];
        let encoded = encode_envelope(BackendId::Binius64IronSpartan, ProofProfile::Pay1x2, &proof)
            .expect("encode");
        assert_eq!(
            encoded,
            vec![b'H', b'G', b'S', b'P', 1, 0, 1, 1, 3, 0, 0, 0, 0xaa, 0xbb, 0xcc,]
        );
        assert_eq!(encoded.len() - proof.len(), ENVELOPE_HEADER_BYTES);

        let decoded = decode_envelope_exact(&encoded).expect("decode");
        assert_eq!(decoded.proof, proof);
        assert_eq!(decoded.encoded_len(), encoded.len());
    }

    #[test]
    fn empty_proof_rejects_on_encode_and_decode() {
        assert_eq!(
            encode_envelope(BackendId::Binius64IronSpartan, ProofProfile::Pay1x2, &[],),
            Err(EnvelopeError::EmptyProof)
        );

        let empty_wire = [b'H', b'G', b'S', b'P', 1, 0, 1, 1, 0, 0, 0, 0];
        assert_eq!(
            decode_envelope_exact(&empty_wire),
            Err(EnvelopeError::EmptyProof)
        );
    }

    #[test]
    fn exact_decoder_rejects_trailing_and_truncated_bytes() {
        let proof = [0x5a; 32];
        let encoded = encode_envelope(BackendId::Binius64IronSpartan, ProofProfile::Pay1x2, &proof)
            .expect("encode");

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_envelope_exact(&trailing),
            Err(EnvelopeError::TrailingBytes { trailing: 1 })
        );

        assert_eq!(
            decode_envelope_exact(&encoded[..encoded.len() - 1]),
            Err(EnvelopeError::TruncatedProof {
                declared: proof.len(),
                available: proof.len() - 1,
            })
        );

        let mut declared_short = encoded;
        declared_short[8..12].copy_from_slice(&31u32.to_le_bytes());
        assert_eq!(
            decode_envelope_exact(&declared_short),
            Err(EnvelopeError::TrailingBytes { trailing: 1 })
        );
    }

    #[test]
    fn decoder_rejects_unknown_routing_before_proof_work() {
        let proof = [0x5a];
        let encoded = encode_envelope(BackendId::Binius64IronSpartan, ProofProfile::Pay1x2, &proof)
            .expect("encode");

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert!(matches!(
            decode_envelope_exact(&bad_magic),
            Err(EnvelopeError::InvalidMagic(_))
        ));

        let mut bad_version = encoded.clone();
        bad_version[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            decode_envelope_exact(&bad_version),
            Err(EnvelopeError::UnsupportedVersion(2))
        );

        let mut bad_backend = encoded.clone();
        bad_backend[6] = 2;
        assert_eq!(
            decode_envelope_exact(&bad_backend),
            Err(EnvelopeError::UnsupportedBackend(2))
        );

        let mut bad_profile = encoded;
        bad_profile[7] = 3;
        assert_eq!(
            decode_envelope_exact(&bad_profile),
            Err(EnvelopeError::UnsupportedProfile(3))
        );
    }

    #[test]
    fn proof_cap_is_enforced_on_encode_and_before_body_access() {
        let too_large = vec![0u8; MAX_PROOF_BYTES + 1];
        assert_eq!(
            encode_envelope(
                BackendId::Binius64IronSpartan,
                ProofProfile::Pay1x2,
                &too_large,
            ),
            Err(EnvelopeError::ProofTooLarge {
                declared: MAX_PROOF_BYTES + 1,
                maximum: MAX_PROOF_BYTES,
            })
        );

        let mut declaration_only = vec![0u8; ENVELOPE_HEADER_BYTES];
        declaration_only[0..4].copy_from_slice(&ENVELOPE_MAGIC);
        declaration_only[4..6].copy_from_slice(&ENVELOPE_VERSION_V1.to_le_bytes());
        declaration_only[6] = BackendId::Binius64IronSpartan as u8;
        declaration_only[7] = ProofProfile::Pay1x2 as u8;
        declaration_only[8..12].copy_from_slice(&((MAX_PROOF_BYTES + 1) as u32).to_le_bytes());
        assert_eq!(
            decode_envelope_exact(&declaration_only),
            Err(EnvelopeError::ProofTooLarge {
                declared: MAX_PROOF_BYTES + 1,
                maximum: MAX_PROOF_BYTES,
            })
        );

        let at_cap = vec![0x7c; MAX_PROOF_BYTES];
        let encoded = encode_envelope(
            BackendId::Binius64IronSpartan,
            ProofProfile::Pay1x2,
            &at_cap,
        )
        .expect("the exact cap is admitted");
        assert_eq!(encoded.len(), MAX_ENVELOPE_BYTES);
        assert_eq!(
            decode_envelope_exact(&encoded).expect("decode").proof.len(),
            MAX_PROOF_BYTES
        );
    }

    #[test]
    fn statement_proof_and_profile_mutations_all_reject() {
        let original = action();
        let proof = bound_test_proof(&original, ProofProfile::Pay1x2);
        let encoded = encode_envelope(BackendId::Binius64IronSpartan, ProofProfile::Pay1x2, &proof)
            .expect("encode");
        let verifier = BindingDigestVerifier::new();

        verify_envelope_exact(&encoded, ProofProfile::Pay1x2, &original, &verifier)
            .expect("matching proof and statement");

        let mut changed_statement = original.clone();
        changed_statement.fee += 1;
        assert_eq!(
            verify_envelope_exact(
                &encoded,
                ProofProfile::Pay1x2,
                &changed_statement,
                &verifier,
            ),
            Err(VerificationError::Backend("binding digest mismatch"))
        );

        let mut changed_proof = encoded.clone();
        changed_proof[ENVELOPE_HEADER_BYTES] ^= 1;
        assert_eq!(
            verify_envelope_exact(&changed_proof, ProofProfile::Pay1x2, &original, &verifier,),
            Err(VerificationError::Backend("binding digest mismatch"))
        );

        let calls_before_profile_rejection = verifier.calls.get();
        assert_eq!(
            verify_envelope_exact(&encoded, ProofProfile::Consolidate2x1, &original, &verifier,),
            Err(VerificationError::ProfileMismatch {
                envelope: ProofProfile::Pay1x2,
                expected: ProofProfile::Consolidate2x1,
            })
        );
        assert_eq!(verifier.calls.get(), calls_before_profile_rejection);

        let cross_profile = encode_envelope(
            BackendId::Binius64IronSpartan,
            ProofProfile::Consolidate2x1,
            &proof,
        )
        .expect("encode cross-profile envelope");
        assert_eq!(
            verify_envelope_exact(
                &cross_profile,
                ProofProfile::Consolidate2x1,
                &original,
                &verifier,
            ),
            Err(VerificationError::Backend("binding digest mismatch"))
        );
    }

    #[test]
    fn binding_preimage_contains_exact_reconstructed_statement_once() {
        let statement = action().canonical_bytes();
        let binding = ProofBinding::v1(
            BackendId::Binius64IronSpartan,
            ProofProfile::Pay1x2,
            &statement,
        )
        .expect("statement below cap");
        let mut preimage = Vec::new();
        binding.write_transcript_preimage(&mut preimage);

        let statement_offset = BINDING_DIGEST_DOMAIN.len() + 2 + 1 + 1 + 4;
        assert_eq!(&preimage[statement_offset..], statement);
        assert_eq!(
            &preimage[statement_offset - 4..statement_offset],
            &(statement.len() as u32).to_le_bytes()
        );
        assert_eq!(preimage[statement_offset - 5], ProofProfile::Pay1x2 as u8);
    }

    #[test]
    fn binding_shake256_512_kat_matches_independent_reference() {
        let statement = action().canonical_bytes();
        let binding = ProofBinding::v1(
            BackendId::Binius64IronSpartan,
            ProofProfile::Pay1x2,
            &statement,
        )
        .expect("statement below cap");
        assert_eq!(
            binding.shake256_512(),
            [
                0xee, 0x97, 0x88, 0x0c, 0xb3, 0x98, 0x89, 0xca, 0x4f, 0x45, 0x90, 0x1f, 0x84, 0xc4,
                0x58, 0x82, 0xbe, 0x83, 0x22, 0x68, 0xe1, 0x3a, 0x72, 0x98, 0xc6, 0x8d, 0xed, 0xf6,
                0xa8, 0x44, 0xbb, 0xcb, 0x45, 0xbc, 0x1a, 0x79, 0x87, 0x70, 0x00, 0x1d, 0x95, 0x35,
                0xa8, 0xa8, 0x3c, 0x8f, 0xf5, 0x6d, 0xc7, 0xac, 0xb2, 0x4f, 0xd4, 0x13, 0x20, 0x04,
                0x42, 0xff, 0x71, 0xd8, 0x07, 0xa8, 0xc6, 0x2c,
            ]
        );
    }

    struct OversizedStatement;

    impl CanonicalStatement for OversizedStatement {
        fn write_canonical_statement(&self, output: &mut Vec<u8>) -> Result<(), &'static str> {
            output.resize(MAX_CANONICAL_STATEMENT_BYTES + 1, 0);
            Ok(())
        }
    }

    struct NeverCalledVerifier;

    impl StandaloneProofVerifier for NeverCalledVerifier {
        type Error = Infallible;

        fn backend(&self) -> BackendId {
            BackendId::Binius64IronSpartan
        }

        fn verify(&self, _binding: ProofBinding<'_>, _proof: &[u8]) -> Result<(), Self::Error> {
            panic!("backend must not run for an oversized statement")
        }
    }

    #[test]
    fn reconstructed_statement_is_capped_before_backend_verification() {
        let encoded = encode_envelope(BackendId::Binius64IronSpartan, ProofProfile::Pay1x2, &[1])
            .expect("encode");
        assert_eq!(
            verify_envelope_exact(
                &encoded,
                ProofProfile::Pay1x2,
                &OversizedStatement,
                &NeverCalledVerifier,
            ),
            Err(VerificationError::StatementTooLarge {
                observed: MAX_CANONICAL_STATEMENT_BYTES + 1,
                maximum: MAX_CANONICAL_STATEMENT_BYTES,
            })
        );
    }
}
