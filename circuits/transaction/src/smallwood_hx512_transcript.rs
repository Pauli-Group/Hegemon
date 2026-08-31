//! Fresh SHA-512 transcript and outer proof-wire primitive for the inactive
//! direct-radix SmallWood/HX512 candidate.
//!
//! This module allocates no public identity.  A release-owned caller supplies
//! the exact identity header and proof cap, and the 983-byte action grammar
//! supplies the statement separately.  Every SHA-512 request starts with the
//! resulting statement-binding digest, uses one role from a closed candidate
//! domain registry, and length-prefixes every variable-width byte string.  The
//! proof wire carries only the caller header, a 64-byte global salt, and the
//! complete opaque inner proof.  `decode_hx512_wire_view_exact` validates that
//! complete frame without allocation; the owned decoder allocates only after
//! all lengths and the caller's cap have passed.
//!
//! The executable codec and hash functions are not production authority.  In
//! particular, this file does not prove that SHA-512 is a quantum random
//! oracle, that the direct SmallWood IOP has the required round-by-round
//! randomness or honest-verifier zero knowledge, or that a Rust verifier
//! refines the final relation.  All security and release gates below remain
//! false.

#![forbid(unsafe_code)]

use sha2::{Digest as ShaDigest, Sha512};
use sha3::{
    digest::{ExtendableOutput, Update as Sha3Update, XofReader},
    Shake256,
};

pub const HX512_DIGEST_BYTES: usize = 64;
pub const HX512_SALT_BYTES: usize = 64;
pub const HX512_EXTERNAL_STATEMENT_BYTES: usize = 983;
pub const HX512_VERIFIER_CONTEXT_BYTES: usize = 136;
/// The provisional direct profile uses 72-byte (576-bit) leaf tapes.  The
/// hashing API is const-generic so a future profile cannot silently reinterpret
/// one tape width as another; this profile rejects every width except 72.
pub const HX512_PROFILE_LEAF_TAPE_BYTES: usize = 72;
pub const HX512_PROFILE_LEAF_TAPE_ENTROPY_BITS: u16 = 8 * HX512_PROFILE_LEAF_TAPE_BYTES as u16;
pub const HX512_GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

/// Allocation ceiling for one profile-derived field challenge vector.  The
/// executable K=1024 relation requires 106,207,505 PIOP coefficients; the old
/// `2^20` placeholder rejected that exact engine geometry before proving.
/// `2^27` is the smallest power-of-two ceiling that admits the frozen shape
/// while preserving a deterministic pre-allocation bound.
pub const HX512_MAX_FIELD_SAMPLES: usize = 1 << 27;
pub const HX512_MAX_INDEX_SAMPLES: usize = 4_096;
pub const HX512_MAX_INDEX_DOMAIN_SIZE: u32 = 1 << 30;
pub const HX512_MAX_LEAF_EVALUATIONS_PER_FAMILY: usize = 1 << 16;
pub const HX512_FIELD_SAMPLER_EXTRA_CANDIDATES: usize = 256;
pub const HX512_INDEX_SAMPLER_EXTRA_CANDIDATES: usize = 512;
/// Parser safety ceiling only.  A selected production profile must choose a
/// smaller measured cap; this candidate constant is not release authority.
pub const HX512_ABSOLUTE_MAX_IDENTITY_HEADER_BYTES: usize = 4 * 1024;
pub const HX512_ABSOLUTE_MAX_INNER_PROOF_BYTES: usize = 16 * 1024 * 1024;

/// No magic, version, suite id, action id, or release identity is allocated by
/// this candidate module.  Those bytes must come from a reviewed release
/// manifest if the architecture is ever selected.
pub const IDENTITY_ALLOCATED: bool = false;
pub const HX512_IDENTITY_ALLOCATED: bool = IDENTITY_ALLOCATED;
pub const HX512_ROLE_DOMAIN_REGISTRY_MANIFEST_BOUND: bool = false;
pub const HX512_OUTER_FRAMER_CAP_BEFORE_BUFFERING_VERIFIED: bool = false;
pub const HX512_INNER_PROOF_VERIFICATION_REFINEMENT_VERIFIED: bool = false;
pub const HX512_ENGINE_TRANSCRIPT_SCHEDULE_REFINEMENT_VERIFIED: bool = false;

/// Internal request-frame domains are candidate registry entries, not public
/// protocol identities.  They remain unauthorized until a release manifest
/// binds this registry byte-for-byte.
const HX512_BINDING_FRAME_DOMAIN: &[u8] = b"hegemon.smallwood.hx512.candidate.statement-binding\0";
const HX512_REQUEST_FRAME_DOMAIN: &[u8] = b"hegemon.smallwood.hx512.candidate.request-frame\0";
const HX512_XOF_FRAME_DOMAIN: &[u8] = b"hegemon.smallwood.hx512.candidate.shake256-frame\0";

/// Total-length word, identity-header length, salt length and bytes, and
/// inner-proof length.  The caller-owned identity header is additional.
pub const HX512_WIRE_BASE_OVERHEAD_BYTES: usize = 8 + 2 + 2 + HX512_SALT_BYTES + 4;
pub const HX512_ABSOLUTE_MAX_WIRE_BYTES: usize = HX512_WIRE_BASE_OVERHEAD_BYTES
    + HX512_ABSOLUTE_MAX_IDENTITY_HEADER_BYTES
    + HX512_ABSOLUTE_MAX_INNER_PROOF_BYTES;

/// Exact inactive candidate schedule, traced from the existing SmallWood
/// engine.  It contains four SHA-512 absorb events and four SHAKE256 challenge
/// events.  This registry is not a production identity and is not claimed to
/// refine the engine until the explicit refinement flag below is discharged.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hx512TranscriptStage {
    DecsRootBinding = 0,
    DecsCoefficientChallenge = 1,
    PiopInputBinding = 2,
    PiopCoefficientChallenge = 3,
    PiopTranscriptBinding = 4,
    PiopOpeningChallenge = 5,
    DecsOpeningBinding = 6,
    DecsQueryChallenge = 7,
}

#[cfg(test)]
mod schedule_tests {
    use super::*;
    use std::collections::BTreeSet;

    const TEST_IDENTITY_HEADER: &[u8] = b"test-only-unallocated-hx512-release-header-0001";
    const TEST_INNER_PROOF_CAP: usize = 4_096;

    fn parameters() -> Hx512WireParameters<'static> {
        Hx512WireParameters::new(TEST_IDENTITY_HEADER, TEST_INNER_PROOF_CAP).unwrap()
    }

    fn external_statement() -> [u8; HX512_EXTERNAL_STATEMENT_BYTES] {
        std::array::from_fn(|index| (index as u8).wrapping_mul(17))
    }

    fn verifier_context() -> Hx512VerifierContextBinding {
        Hx512VerifierContextBinding::new(
            std::array::from_fn(|index| 0x31u8.wrapping_add(index as u8)),
            0x0102_0304_0506_0708,
            std::array::from_fn(|index| 0xd3u8.wrapping_sub(index as u8)),
        )
    }

    /// Test-only corrected s=6 fixture.  It is deliberately caller supplied,
    /// has no public identity, and does not claim to be frozen engine geometry.
    fn geometry_with_q(q: u32) -> Hx512TranscriptGeometry {
        let relation_rows = 11_900;
        let lvcs_columns = 5_970;
        let core = Hx512CoreGeometry {
            n: 1 << 20,
            r: relation_rows,
            k: 1_024,
            packing_factor: 1_024,
            maximum_constraint_degree: 6,
            beta: 2,
            rho: 5,
            eta: 5,
            piop_opening_count: 6,
            decs_query_count: q,
            topology_radix: 1_024,
            topology_direct_base_rows: 11_892,
            topology_cell_count: 12_177_408,
            adapter_row_count: relation_rows,
            nonlinear_constraint_count: relation_rows,
            linear_constraint_count: 1_024,
            witness_polynomial_degree: 1_029,
            mpol_polynomial_degree: 5_150,
            linear_polynomial_degree: 2_052,
            polynomial_count: 11_910,
            unstacked_rows: 1_030,
            unstacked_columns: 11_940,
            lvcs_rows: 2_060,
            lvcs_columns,
            lvcs_opened_combinations: 12,
            interpolation_point_count: lvcs_columns + q,
            auxiliary_count: 0,
        };
        let matrices = Hx512ProofMatrixGeometry {
            public_polynomials: Hx512MatrixDimensions {
                rows: 5,
                columns: 5_145,
            },
            linear_polynomials: Hx512MatrixDimensions {
                rows: 5,
                columns: 2_046,
            },
            recombination_tails: Hx512MatrixDimensions {
                rows: 12,
                columns: q,
            },
            subset_evaluations: Hx512MatrixDimensions {
                rows: q,
                columns: 2_048,
            },
            partial_evaluations: Hx512MatrixDimensions {
                rows: 6,
                columns: 30,
            },
            masking_evaluations: Hx512MatrixDimensions {
                rows: q,
                columns: 5,
            },
            high_coefficients: Hx512MatrixDimensions {
                rows: 5,
                columns: lvcs_columns,
            },
            opened_witness: Hx512MatrixDimensions {
                rows: 6,
                columns: 11_910,
            },
        };
        Hx512TranscriptGeometry::new(
            core,
            matrices,
            Hx512OpeningGeometry {
                authentication_path_count: q,
                authentication_path_depth: 20,
                compact_authentication_paths: true,
            },
            Hx512DomainGeometry {
                field_modulus: HX512_GOLDILOCKS_MODULUS,
                subgroup_generator: derive_radix2_subgroup_generator(1 << 20).unwrap(),
                canonical_coset_shift: derive_canonical_coset_shift(1 << 20, lvcs_columns + q)
                    .unwrap(),
                domain_kind: Hx512DomainKind::Radix2DisjointCoset,
                field_encoding: Hx512FieldEncoding::CanonicalU64BigEndian,
                index_encoding: Hx512IndexEncoding::CanonicalU32BigEndian,
                polynomial_order: Hx512PolynomialOrder::ConstantTermFirst,
                context_height_encoding: Hx512ContextHeightEncoding::CanonicalU64LittleEndian,
            },
            [0x11; 64],
            [0x22; 64],
        )
        .unwrap()
    }

    fn deferred_test_geometry() -> Hx512TranscriptGeometry {
        let mut core = Hx512CoreGeometry {
            n: 1 << 10,
            r: 1,
            k: 1_024,
            packing_factor: 1_024,
            maximum_constraint_degree: 6,
            beta: 2,
            rho: 5,
            eta: 5,
            piop_opening_count: 6,
            decs_query_count: 8,
            topology_radix: 1_024,
            topology_direct_base_rows: 1,
            topology_cell_count: 0,
            adapter_row_count: 1,
            nonlinear_constraint_count: 3,
            linear_constraint_count: 2,
            witness_polynomial_degree: 0,
            mpol_polynomial_degree: 0,
            linear_polynomial_degree: 0,
            polynomial_count: 0,
            unstacked_rows: 0,
            unstacked_columns: 0,
            lvcs_rows: 0,
            lvcs_columns: 0,
            lvcs_opened_combinations: 0,
            interpolation_point_count: 0,
            auxiliary_count: 0,
        };
        let derived = derive_profile_dimensions(core).unwrap();
        core.topology_cell_count = derived.topology_cell_count;
        core.witness_polynomial_degree = derived.witness_polynomial_degree;
        core.mpol_polynomial_degree = derived.mpol_polynomial_degree;
        core.linear_polynomial_degree = derived.linear_polynomial_degree;
        core.polynomial_count = derived.polynomial_count;
        core.unstacked_rows = derived.unstacked_rows;
        core.unstacked_columns = derived.unstacked_columns;
        core.lvcs_rows = derived.lvcs_rows;
        core.lvcs_columns = derived.lvcs_columns;
        core.lvcs_opened_combinations = derived.lvcs_opened_combinations;
        core.interpolation_point_count = derived.interpolation_point_count;
        Hx512TranscriptGeometry::new(
            core,
            derived.matrices,
            Hx512OpeningGeometry {
                authentication_path_count: core.decs_query_count,
                authentication_path_depth: core.n.trailing_zeros(),
                compact_authentication_paths: true,
            },
            Hx512DomainGeometry {
                field_modulus: HX512_GOLDILOCKS_MODULUS,
                subgroup_generator: derive_radix2_subgroup_generator(core.n).unwrap(),
                canonical_coset_shift: derive_canonical_coset_shift(
                    core.n,
                    core.interpolation_point_count,
                )
                .unwrap(),
                domain_kind: Hx512DomainKind::Radix2DisjointCoset,
                field_encoding: Hx512FieldEncoding::CanonicalU64BigEndian,
                index_encoding: Hx512IndexEncoding::CanonicalU32BigEndian,
                polynomial_order: Hx512PolynomialOrder::ConstantTermFirst,
                context_height_encoding: Hx512ContextHeightEncoding::CanonicalU64LittleEndian,
            },
            [0x33; 64],
            [0x44; 64],
        )
        .unwrap()
    }

    fn fixture() -> Hx512ProofWire {
        let salt = std::array::from_fn(|index| (index as u8).wrapping_mul(29));
        let proof: Vec<u8> = (0..521).map(|index| (index * 31) as u8).collect();
        Hx512ProofWire::from_exact_parts(parameters(), salt, &proof).unwrap()
    }

    fn transcript(wire: &Hx512ProofWire, geometry: Hx512TranscriptGeometry) -> Hx512Transcript {
        wire.transcript(
            parameters(),
            &external_statement(),
            &verifier_context(),
            geometry,
        )
        .unwrap()
    }

    fn advance_to_query(transcript: &mut Hx512Transcript) {
        transcript
            .hash_merkle_root(transcript.geometry().decs_leaf_count(), &[0x42; 64])
            .unwrap();
        transcript.sample_decs_coefficients().unwrap();
        transcript
            .absorb_piop_input(b"canonical-piop-input")
            .unwrap();
        transcript.sample_piop_coefficients().unwrap();
        transcript
            .absorb_piop_transcript(b"canonical-piop-transcript")
            .unwrap();
        transcript.sample_piop_openings().unwrap();
        transcript
            .absorb_decs_opening(b"canonical-decs-opening")
            .unwrap();
    }

    const DEFERRED_ROOT: [u8; HX512_DIGEST_BYTES] = [0x52; HX512_DIGEST_BYTES];
    const DEFERRED_PIOP_INPUT: &[u8] = b"deferred-canonical-piop-input";
    const DEFERRED_PIOP_TRANSCRIPT: &[u8] = b"deferred-canonical-piop-transcript";
    const DEFERRED_DECS_OPENING: &[u8] = b"deferred-canonical-decs-opening";

    fn deferred_claims(
        wire: &Hx512ProofWire,
        geometry: Hx512TranscriptGeometry,
    ) -> ([u8; 64], [u8; 64], [u8; 64]) {
        let mut prover = transcript(wire, geometry);
        prover
            .hash_merkle_root(geometry.decs_leaf_count(), &DEFERRED_ROOT)
            .unwrap();
        prover.sample_decs_coefficients().unwrap();
        let h3 = prover.absorb_piop_input(DEFERRED_PIOP_INPUT).unwrap();
        prover.sample_piop_coefficients().unwrap();
        let h5 = prover
            .absorb_piop_transcript(DEFERRED_PIOP_TRANSCRIPT)
            .unwrap();
        prover.sample_piop_openings().unwrap();
        prover.absorb_decs_opening(DEFERRED_DECS_OPENING).unwrap();
        prover.sample_decs_queries().unwrap();
        (h3, h5, prover.finish().unwrap())
    }

    fn drive_deferred_verifier(
        wire: &Hx512ProofWire,
        geometry: Hx512TranscriptGeometry,
        root: [u8; 64],
        h3: [u8; 64],
        h5: [u8; 64],
    ) -> Hx512DeferredVerifierTranscript {
        let mut verifier = Hx512DeferredVerifierTranscript::new(
            parameters(),
            &external_statement(),
            &verifier_context(),
            wire.salt(),
            geometry,
        )
        .unwrap();
        verifier
            .bind_claimed_decs_root(geometry.decs_leaf_count(), &root)
            .unwrap();
        verifier.sample_decs_coefficients().unwrap();
        verifier.claim_piop_input_digest(h3).unwrap();
        verifier.sample_piop_coefficients().unwrap();
        verifier.claim_piop_transcript_digest(h5).unwrap();
        verifier.sample_piop_openings().unwrap();
        verifier.absorb_decs_opening(DEFERRED_DECS_OPENING).unwrap();
        verifier.sample_decs_queries().unwrap();
        verifier
    }

    struct ExactInnerVerifier<'a> {
        expected: &'a [u8],
    }

    impl Hx512InnerProofVerificationHook for ExactInnerVerifier<'_> {
        fn verify_opaque_inner_proof(
            &self,
            external_statement: &[u8],
            verifier_context: &Hx512VerifierContextBinding,
            geometry: Hx512TranscriptGeometry,
            _statement_binding_digest: &[u8; HX512_DIGEST_BYTES],
            opaque_inner_proof: &[u8],
        ) -> Result<(), Hx512Error> {
            if external_statement.len() == HX512_EXTERNAL_STATEMENT_BYTES
                && verifier_context.encode_exact().len() == HX512_VERIFIER_CONTEXT_BYTES
                && geometry.encode_canonical().len() == HX512_PROFILE_DESCRIPTOR_BYTES
                && opaque_inner_proof == self.expected
            {
                Ok(())
            } else {
                Err(Hx512Error::OpaqueInnerProofRejected)
            }
        }
    }

    #[derive(Debug)]
    struct FixtureLayout {
        total_length: std::ops::Range<usize>,
        identity_length: std::ops::Range<usize>,
        identity_header: std::ops::Range<usize>,
        salt_length: std::ops::Range<usize>,
        salt: std::ops::Range<usize>,
        proof_length: std::ops::Range<usize>,
        proof: std::ops::Range<usize>,
    }

    fn fixture_layout(identity_header_len: usize, proof_len: usize) -> FixtureLayout {
        let identity_header = 10..10 + identity_header_len;
        let salt_length = identity_header.end..identity_header.end + 2;
        let salt = salt_length.end..salt_length.end + HX512_SALT_BYTES;
        let proof_length = salt.end..salt.end + 4;
        let proof = proof_length.end..proof_length.end + proof_len;
        FixtureLayout {
            total_length: 0..8,
            identity_length: 8..10,
            identity_header,
            salt_length,
            salt,
            proof_length,
            proof,
        }
    }

    #[test]
    fn canonical_wire_codec_roundtrips_without_statement_context_or_profile_duplication() {
        let wire = fixture();
        let parameters = parameters();
        let statement = external_statement();
        let context = verifier_context();
        let geometry = geometry_with_q(48);
        let encoded = wire.encode(parameters).unwrap();
        assert_eq!(encoded.len(), 80 + TEST_IDENTITY_HEADER.len() + 521);
        assert_eq!(
            parameters.wire_overhead_bytes(),
            80 + TEST_IDENTITY_HEADER.len()
        );
        let view = decode_hx512_wire_view_exact(&encoded, parameters).unwrap();
        assert_eq!(view.canonical_bytes(), encoded);
        assert_eq!(view.identity_header(), TEST_IDENTITY_HEADER);
        assert_eq!(view.salt, wire.salt());
        assert_eq!(view.inner_proof, wire.inner_proof());
        assert_eq!(
            Hx512Transcript::from_wire_view(&statement, &context, view, geometry)
                .unwrap()
                .statement_binding_digest(),
            wire.transcript(parameters, &statement, &context, geometry)
                .unwrap()
                .statement_binding_digest()
        );
        let decoded = Hx512ProofWire::decode_exact(&encoded, parameters).unwrap();
        assert_eq!(decoded, wire);
        assert_eq!(decoded.encode(parameters).unwrap(), encoded);
        assert_eq!(decoded.try_clone().unwrap(), decoded);
        let moved = Hx512ProofWire::decode_owned_exact(encoded.clone(), parameters).unwrap();
        assert_eq!(moved, decoded);
        assert_eq!(moved.encode(parameters).unwrap(), encoded);
        assert_eq!(
            geometry,
            Hx512TranscriptGeometry::decode_canonical(&geometry.encode_canonical()).unwrap()
        );
        assert_eq!(
            context,
            Hx512VerifierContextBinding::decode_exact(&context.encode_exact()).unwrap()
        );
        assert_eq!(
            &context.encode_exact()[64..72],
            &context.parent_height.to_le_bytes()
        );
        assert_eq!(
            hex::encode(transcript(&wire, geometry).statement_binding_digest()),
            "03178075e4e476830b5c4c80a1d20757bb245f938a28cb7947ad86639662bd6f0c11b9a7961d43bb4d72a588cb5857c271b623c81e65b780ba19dd3db4709ade"
        );
        assert_eq!(
            hex::encode(hx512_transcript_schedule_digest()),
            "9d12eb29e1e07d8172729010e3b85d74efadfda060d3491ecbf9caa615901c935bf4165b396322179f7c6ff590d13f41fa778631a22dc6b667d7873d595ea68e"
        );
    }

    #[test]
    fn every_wire_header_length_and_trailing_byte_is_rejected_noncanonically() {
        let wire = fixture();
        let parameters = parameters();
        let encoded = wire.encode(parameters).unwrap();
        let layout = fixture_layout(parameters.identity_header().len(), wire.inner_proof().len());
        assert_eq!(layout.proof.end, encoded.len());
        for range in [
            &layout.total_length,
            &layout.identity_length,
            &layout.salt_length,
            &layout.proof_length,
        ] {
            for offset in range.clone() {
                let mut changed = encoded.clone();
                changed[offset] ^= 1;
                assert!(
                    decode_hx512_wire_view_exact(&changed, parameters).is_err(),
                    "length mutation {offset}"
                );
            }
        }
        for offset in layout.identity_header {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(matches!(
                decode_hx512_wire_view_exact(&changed, parameters),
                Err(Hx512Error::IdentityHeaderMismatch)
            ));
        }
        for trailing in 0u8..=u8::MAX {
            let mut changed = encoded.clone();
            changed.push(trailing);
            let declared = changed.len() as u64;
            changed[..8].copy_from_slice(&declared.to_be_bytes());
            assert!(matches!(
                decode_hx512_wire_view_exact(&changed, parameters),
                Err(Hx512Error::TrailingBytes)
            ));
        }
        let mut wrong_identity = TEST_IDENTITY_HEADER.to_vec();
        wrong_identity[0] ^= 1;
        let wrong_parameters =
            Hx512WireParameters::new(&wrong_identity, TEST_INNER_PROOF_CAP).unwrap();
        assert!(matches!(
            decode_hx512_wire_view_exact(&encoded, wrong_parameters),
            Err(Hx512Error::IdentityHeaderMismatch)
        ));
    }

    #[test]
    fn statement_context_profile_salt_and_inner_proof_bytes_are_bound_at_the_right_layer() {
        let wire = fixture();
        let parameters = parameters();
        let statement = external_statement();
        let context = verifier_context();
        let geometry = geometry_with_q(48);
        let encoded = wire.encode(parameters).unwrap();
        let layout = fixture_layout(parameters.identity_header().len(), wire.inner_proof().len());
        let baseline = transcript(&wire, geometry);
        for offset in 0..statement.len() {
            let mut changed = statement;
            changed[offset] ^= 1;
            assert_ne!(
                wire.transcript(parameters, &changed, &context, geometry)
                    .unwrap()
                    .statement_binding_digest(),
                baseline.statement_binding_digest()
            );
            assert_eq!(wire.encode(parameters).unwrap(), encoded);
        }
        let context_bytes = context.encode_exact();
        for offset in 0..context_bytes.len() {
            let mut changed = context_bytes;
            changed[offset] ^= 1;
            let changed = Hx512VerifierContextBinding::decode_exact(&changed).unwrap();
            assert_ne!(
                wire.transcript(parameters, &statement, &changed, geometry)
                    .unwrap()
                    .statement_binding_digest(),
                baseline.statement_binding_digest()
            );
        }
        let profile = geometry.encode_canonical();
        for offset in 0..profile.len() {
            let mut changed = profile;
            changed[offset] ^= 1;
            assert_ne!(
                statement_binding_digest_with_domain(
                    HX512_BINDING_FRAME_DOMAIN,
                    parameters.identity_header(),
                    parameters.max_inner_proof_bytes(),
                    &statement,
                    &context_bytes,
                    wire.salt(),
                    &changed
                ),
                *baseline.statement_binding_digest()
            );
            if let Ok(decoded) = Hx512TranscriptGeometry::decode_canonical(&changed) {
                assert_eq!(decoded.encode_canonical(), changed);
                assert_ne!(
                    wire.transcript(parameters, &statement, &context, decoded)
                        .unwrap()
                        .statement_binding_digest(),
                    baseline.statement_binding_digest()
                );
            }
        }
        for offset in layout.salt {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            let decoded = Hx512ProofWire::decode_exact(&changed, parameters).unwrap();
            assert_eq!(decoded.encode(parameters).unwrap(), changed);
            assert_ne!(
                decoded
                    .transcript(parameters, &statement, &context, geometry)
                    .unwrap()
                    .statement_binding_digest(),
                baseline.statement_binding_digest()
            );
        }
        let exact = ExactInnerVerifier {
            expected: wire.inner_proof(),
        };
        assert!(wire
            .verify_inner_with(parameters, &statement, &context, geometry, &exact)
            .is_ok());
        for offset in layout.proof {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            let decoded = Hx512ProofWire::decode_exact(&changed, parameters).unwrap();
            assert_eq!(decoded.encode(parameters).unwrap(), changed);
            assert!(matches!(
                decoded.verify_inner_with(parameters, &statement, &context, geometry, &exact),
                Err(Hx512Error::OpaqueInnerProofRejected)
            ));
            assert_eq!(
                decoded
                    .transcript(parameters, &statement, &context, geometry)
                    .unwrap()
                    .statement_binding_digest(),
                baseline.statement_binding_digest()
            );
        }
    }

    #[test]
    fn parser_caps_typed_profile_invariants_and_q_deltas_are_exact() {
        let wire = fixture();
        let parameters = parameters();
        let encoded = wire.encode(parameters).unwrap();
        let layout = fixture_layout(parameters.identity_header().len(), wire.inner_proof().len());
        let mut oversized = encoded.clone();
        oversized[layout.proof_length]
            .copy_from_slice(&((TEST_INNER_PROOF_CAP + 1) as u32).to_be_bytes());
        assert!(matches!(
            decode_hx512_wire_view_exact(&oversized, parameters),
            Err(Hx512Error::FrameLengthLimit {
                frame: Hx512WireFrame::InnerProof,
                ..
            })
        ));
        assert!(matches!(
            Hx512WireParameters::new(&[], 1),
            Err(Hx512Error::IdentityHeaderEmpty)
        ));
        assert!(matches!(
            Hx512WireParameters::new(TEST_IDENTITY_HEADER, 0),
            Err(Hx512Error::ProofCap { .. })
        ));
        assert!(matches!(
            wire.transcript(
                parameters,
                &[0; HX512_EXTERNAL_STATEMENT_BYTES - 1],
                &verifier_context(),
                geometry_with_q(48)
            ),
            Err(Hx512Error::ExternalStatementLength { .. })
        ));
        assert!(matches!(
            Hx512VerifierContextBinding::decode_exact(&[0; HX512_VERIFIER_CONTEXT_BYTES - 1]),
            Err(Hx512Error::VerifierContextLength { .. })
        ));
        assert!(matches!(
            Hx512TranscriptGeometry::decode_canonical(&[0; HX512_PROFILE_DESCRIPTOR_BYTES - 1]),
            Err(Hx512Error::ProfileDescriptorLength { .. })
        ));
        let mut invalid = geometry_with_q(48).core();
        invalid.piop_opening_count = 5;
        assert!(matches!(
            Hx512TranscriptGeometry::new(
                invalid,
                geometry_with_q(48).matrices(),
                geometry_with_q(48).openings(),
                geometry_with_q(48).domain(),
                [0x11; 64],
                [0x22; 64]
            ),
            Err(Hx512Error::ProfileInvariant(
                "PIOP opening count must be exactly six"
            ))
        ));
        let mut invalid = geometry_with_q(48).core();
        invalid.auxiliary_count = 1;
        assert!(matches!(
            Hx512TranscriptGeometry::new(
                invalid,
                geometry_with_q(48).matrices(),
                geometry_with_q(48).openings(),
                geometry_with_q(48).domain(),
                [0x11; 64],
                [0x22; 64]
            ),
            Err(Hx512Error::ProfileInvariant("auxiliary count must be zero"))
        ));
        assert!(matches!(
            Hx512TranscriptGeometry::new(
                geometry_with_q(48).core(),
                geometry_with_q(48).matrices(),
                geometry_with_q(48).openings(),
                geometry_with_q(48).domain(),
                [0; 64],
                [0x22; 64]
            ),
            Err(Hx512Error::ProfileInvariant(
                "relation/topology digest must be nonzero"
            ))
        ));
        let mut decs_overflow = geometry_with_q(48);
        decs_overflow.core.eta = 1_431_655_766;
        decs_overflow.matrices.masking_evaluations.columns = decs_overflow.core.eta;
        decs_overflow.matrices.high_coefficients.rows = decs_overflow.core.eta;
        assert!(matches!(
            decs_overflow.decs_coefficient_count(),
            Err(Hx512Error::FieldSampleLimit {
                requested,
                maximum
            }) if requested > u64::from(u32::MAX)
                && maximum == HX512_MAX_FIELD_SAMPLES as u64
        ));
        assert!(matches!(
            decs_overflow.validate(),
            Err(Hx512Error::FieldSampleLimit { .. })
        ));
        let mut piop_overflow = geometry_with_q(48);
        piop_overflow.core.nonlinear_constraint_count = u32::MAX;
        assert!(matches!(
            piop_overflow.piop_coefficient_count(),
            Err(Hx512Error::FieldSampleLimit {
                requested,
                maximum
            }) if requested > u64::from(u32::MAX)
                && maximum == HX512_MAX_FIELD_SAMPLES as u64
        ));
        assert!(matches!(
            piop_overflow.validate(),
            Err(Hx512Error::FieldSampleLimit { .. })
        ));
        let q23 = geometry_with_q(23);
        let q48 = geometry_with_q(48);
        let q55 = geometry_with_q(55);
        assert_eq!(q48.decs_coefficient_count().unwrap(), 10_300);
        assert_eq!(q48.piop_coefficient_count().unwrap(), 59_500);
        assert_ne!(q23.encode_canonical(), q48.encode_canonical());
        assert_ne!(q48.encode_canonical(), q55.encode_canonical());
        assert_eq!(
            hx512_opened_tape_payload_bytes(q23.decs_leaf_count(), 23).unwrap(),
            1_656
        );
        assert_eq!(
            hx512_opened_tape_payload_bytes(q48.decs_leaf_count(), 48).unwrap(),
            3_456
        );
        assert_eq!(
            hx512_opened_tape_payload_bytes(q55.decs_leaf_count(), 55).unwrap(),
            3_960
        );
        assert_eq!(HX512_WIRE_BASE_OVERHEAD_BYTES, 80);
        assert_eq!(HX512_ABSOLUTE_MAX_WIRE_BYTES, 16_781_392);
        let maximum_header = vec![0xa5; HX512_ABSOLUTE_MAX_IDENTITY_HEADER_BYTES];
        let maximum =
            Hx512WireParameters::new(&maximum_header, HX512_ABSOLUTE_MAX_INNER_PROOF_BYTES)
                .unwrap();
        assert_eq!(maximum.max_wire_bytes(), HX512_ABSOLUTE_MAX_WIRE_BYTES);
        assert!(HX512_ABSOLUTE_MAX_WIRE_BYTES <= u32::MAX as usize);
    }

    #[test]
    fn exact_eight_stage_schedule_has_parity_and_rejects_duplicate_omitted_or_out_of_order_calls() {
        let wire = fixture();
        let geometry = geometry_with_q(48);
        let mut early = transcript(&wire, geometry);
        assert!(matches!(
            early.sample_decs_coefficients(),
            Err(Hx512Error::ScheduleViolation {
                expected: Hx512TranscriptStage::DecsRootBinding,
                actual: Hx512TranscriptStage::DecsCoefficientChallenge
            })
        ));
        assert!(matches!(
            early.finish(),
            Err(Hx512Error::ScheduleIncomplete(
                Hx512TranscriptStage::DecsRootBinding
            ))
        ));

        let mut empty = transcript(&wire, geometry);
        empty
            .hash_merkle_root(geometry.decs_leaf_count(), &[0x42; 64])
            .unwrap();
        empty.sample_decs_coefficients().unwrap();
        let before = empty.schedule_state();
        assert!(matches!(
            empty.absorb_piop_input(&[]),
            Err(Hx512Error::EmptyStageMessage(
                Hx512TranscriptStage::PiopInputBinding
            ))
        ));
        assert_eq!(empty.schedule_state(), before);

        let mut prover = transcript(&wire, geometry);
        let mut verifier = transcript(&wire, geometry);
        assert_eq!(
            prover
                .hash_merkle_root(geometry.decs_leaf_count(), &[0x42; 64])
                .unwrap(),
            verifier
                .hash_merkle_root(geometry.decs_leaf_count(), &[0x42; 64])
                .unwrap()
        );
        assert!(matches!(
            prover.hash_merkle_root(geometry.decs_leaf_count(), &[0x42; 64]),
            Err(Hx512Error::ScheduleViolation {
                expected: Hx512TranscriptStage::DecsCoefficientChallenge,
                actual: Hx512TranscriptStage::DecsRootBinding
            })
        ));
        assert_eq!(
            prover.sample_decs_coefficients().unwrap(),
            verifier.sample_decs_coefficients().unwrap()
        );
        assert!(matches!(
            prover.sample_decs_coefficients(),
            Err(Hx512Error::ScheduleViolation {
                expected: Hx512TranscriptStage::PiopInputBinding,
                actual: Hx512TranscriptStage::DecsCoefficientChallenge
            })
        ));
        assert!(matches!(
            prover.sample_piop_coefficients(),
            Err(Hx512Error::ScheduleViolation {
                expected: Hx512TranscriptStage::PiopInputBinding,
                actual: Hx512TranscriptStage::PiopCoefficientChallenge
            })
        ));
        assert_eq!(
            prover.absorb_piop_input(b"canonical-piop-input").unwrap(),
            verifier.absorb_piop_input(b"canonical-piop-input").unwrap()
        );
        assert_eq!(
            prover.sample_piop_coefficients().unwrap(),
            verifier.sample_piop_coefficients().unwrap()
        );
        assert_eq!(
            prover
                .absorb_piop_transcript(b"canonical-piop-transcript")
                .unwrap(),
            verifier
                .absorb_piop_transcript(b"canonical-piop-transcript")
                .unwrap()
        );
        assert_eq!(
            prover.sample_piop_openings().unwrap(),
            verifier.sample_piop_openings().unwrap()
        );
        assert_eq!(
            prover
                .absorb_decs_opening(b"canonical-decs-opening")
                .unwrap(),
            verifier
                .absorb_decs_opening(b"canonical-decs-opening")
                .unwrap()
        );
        let queries = prover.sample_decs_queries().unwrap();
        assert_eq!(queries, verifier.sample_decs_queries().unwrap());
        assert_eq!(prover.event_count(), 8);
        assert_eq!(prover.schedule_state(), Hx512ScheduleState::Complete);
        assert_eq!(queries.indexes.len(), 48);
        assert!(queries.indexes.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            queries.indexes,
            vec![
                60_829, 65_218, 67_825, 70_397, 81_460, 93_306, 113_700, 119_093, 139_957, 172_423,
                194_016, 239_796, 254_416, 434_784, 438_437, 480_687, 483_533, 491_080, 498_776,
                503_039, 568_683, 589_076, 604_272, 606_042, 637_205, 640_107, 662_970, 666_005,
                676_214, 749_723, 820_585, 824_873, 826_700, 848_155, 879_078, 890_975, 920_194,
                921_702, 930_695, 949_771, 970_100, 1_000_840, 1_002_356, 1_006_559, 1_008_746,
                1_020_194, 1_033_767, 1_035_214
            ]
        );
        assert!(matches!(
            prover.sample_decs_queries(),
            Err(Hx512Error::ScheduleComplete)
        ));
        let prover_final = prover.finish().unwrap();
        let verifier_final = verifier.finish().unwrap();
        assert_eq!(prover_final, verifier_final);
        assert_eq!(
            hex::encode(prover_final),
            "a2e51e2cb3e6b7ab3d98299831a5df411acbaa2a0ce3409c6950a1558988ad700abf22d38de221e03461c1a34e88c39d5111e361df3578f0d495c3c208524e60"
        );
    }

    #[test]
    fn deferred_verifier_replays_exact_h3_h5_preimages_and_rejects_every_prefix_byte_mutation() {
        assert_eq!(HX512_DEFERRED_VERIFIER_PREFIX_BYTES, 192);
        assert_eq!(HX512_DEFERRED_VERIFIER_ADDITIONAL_INNER_BYTES, 128);
        let wire = fixture();
        let geometry = deferred_test_geometry();
        let (h3, h5, terminal) = deferred_claims(&wire, geometry);

        let mut early = Hx512DeferredVerifierTranscript::new(
            parameters(),
            &external_statement(),
            &verifier_context(),
            wire.salt(),
            geometry,
        )
        .unwrap();
        assert!(matches!(
            early.verify_reconstructed_root(&DEFERRED_ROOT),
            Err(Hx512Error::DeferredVerifierOrder {
                expected: Hx512DeferredVerifierState::AwaitingReconstructedRoot,
                actual: Hx512DeferredVerifierState::DrivingSchedule
            })
        ));
        early
            .bind_claimed_decs_root(geometry.decs_leaf_count(), &DEFERRED_ROOT)
            .unwrap();
        early.sample_decs_coefficients().unwrap();
        assert!(matches!(
            early.sample_piop_coefficients(),
            Err(Hx512Error::ScheduleViolation {
                expected: Hx512TranscriptStage::PiopInputBinding,
                actual: Hx512TranscriptStage::PiopCoefficientChallenge
            })
        ));
        early.claim_piop_input_digest(h3).unwrap();
        assert!(matches!(
            early.claim_piop_input_digest(h3),
            Err(Hx512Error::DeferredClaimAlreadySet(
                Hx512TranscriptStage::PiopInputBinding
            ))
        ));

        let unresolved = drive_deferred_verifier(&wire, geometry, DEFERRED_ROOT, h3, h5);
        assert!(matches!(
            unresolved.finish(),
            Err(Hx512Error::DeferredClaimsUnresolved(
                Hx512DeferredVerifierState::AwaitingReconstructedRoot
            ))
        ));

        let mut canonical = drive_deferred_verifier(&wire, geometry, DEFERRED_ROOT, h3, h5);
        assert_eq!(canonical.event_count(), 8);
        let tape: [u8; HX512_PROFILE_LEAF_TAPE_BYTES] =
            std::array::from_fn(|index| (index as u8).wrapping_mul(13));
        let forwarded_leaf = canonical
            .hash_leaf(wire.salt(), 7, &tape, &[1, 2, 3], &[4, 5])
            .unwrap();
        let direct = transcript(&wire, geometry);
        assert_eq!(
            forwarded_leaf,
            direct
                .hash_leaf(wire.salt(), 7, &tape, &[1, 2, 3], &[4, 5])
                .unwrap()
        );
        let opened = canonical.hash_opened_leaf_tape(7, &tape).unwrap();
        assert_eq!(opened, direct.hash_opened_leaf_tape(7, &tape).unwrap());
        let node = canonical.hash_merkle_node(0, 3, &forwarded_leaf, &opened);
        assert_eq!(
            node,
            direct.hash_merkle_node(0, 3, &forwarded_leaf, &opened)
        );
        for byte in 0..HX512_PROFILE_LEAF_TAPE_BYTES {
            let mut changed_tape = tape;
            changed_tape[byte] ^= 1;
            assert_ne!(
                canonical
                    .hash_leaf(wire.salt(), 7, &changed_tape, &[1, 2, 3], &[4, 5])
                    .unwrap(),
                forwarded_leaf
            );
        }
        assert_eq!(canonical.event_count(), 8);
        canonical.verify_reconstructed_root(&DEFERRED_ROOT).unwrap();
        canonical
            .verify_reconstructed_piop_input(DEFERRED_PIOP_INPUT)
            .unwrap();
        canonical
            .verify_reconstructed_piop_transcript(DEFERRED_PIOP_TRANSCRIPT)
            .unwrap();
        assert_eq!(canonical.event_count(), 8);
        assert_eq!(canonical.finish().unwrap(), terminal);

        for byte in 0..HX512_DIGEST_BYTES {
            let mut changed_root = DEFERRED_ROOT;
            changed_root[byte] ^= 1;
            let mut verifier = drive_deferred_verifier(&wire, geometry, changed_root, h3, h5);
            assert!(matches!(
                verifier.verify_reconstructed_root(&DEFERRED_ROOT),
                Err(Hx512Error::DeferredRootMismatch)
            ));
            assert_eq!(
                verifier.verification_state(),
                Hx512DeferredVerifierState::Poisoned(Hx512TranscriptStage::DecsRootBinding)
            );
        }
        for byte in 0..HX512_DIGEST_BYTES {
            let mut changed_h3 = h3;
            changed_h3[byte] ^= 1;
            let mut verifier =
                drive_deferred_verifier(&wire, geometry, DEFERRED_ROOT, changed_h3, h5);
            verifier.verify_reconstructed_root(&DEFERRED_ROOT).unwrap();
            assert!(matches!(
                verifier.verify_reconstructed_piop_input(DEFERRED_PIOP_INPUT),
                Err(Hx512Error::DeferredClaimMismatch(
                    Hx512TranscriptStage::PiopInputBinding
                ))
            ));
        }
        for byte in 0..HX512_DIGEST_BYTES {
            let mut changed_h5 = h5;
            changed_h5[byte] ^= 1;
            let mut verifier =
                drive_deferred_verifier(&wire, geometry, DEFERRED_ROOT, h3, changed_h5);
            verifier.verify_reconstructed_root(&DEFERRED_ROOT).unwrap();
            verifier
                .verify_reconstructed_piop_input(DEFERRED_PIOP_INPUT)
                .unwrap();
            assert!(matches!(
                verifier.verify_reconstructed_piop_transcript(DEFERRED_PIOP_TRANSCRIPT),
                Err(Hx512Error::DeferredClaimMismatch(
                    Hx512TranscriptStage::PiopTranscriptBinding
                ))
            ));
        }
    }

    #[test]
    fn every_candidate_domain_byte_is_bound_and_no_public_identity_is_allocated() {
        let wire = fixture();
        let geometry = geometry_with_q(48);
        let parameters = parameters();
        let statement = external_statement();
        let context = verifier_context();
        let transcript = transcript(&wire, geometry);
        let domains: BTreeSet<&[u8]> = Hx512Role::ALL.iter().map(|role| role.domain()).collect();
        assert_eq!(domains.len(), Hx512Role::ALL.len());
        assert!(!HX512_IDENTITY_ALLOCATED);
        assert!(!HX512_ROLE_DOMAIN_REGISTRY_MANIFEST_BOUND);
        for domain in domains {
            assert!(!domain.windows(2).any(|pair| pair == b"v5" || pair == b"v6"));
        }
        let context_bytes = context.encode_exact();
        let profile = geometry.encode_canonical();
        let baseline_binding = *transcript.statement_binding_digest();
        for offset in 0..HX512_BINDING_FRAME_DOMAIN.len() {
            let mut changed = HX512_BINDING_FRAME_DOMAIN.to_vec();
            changed[offset] ^= 1;
            assert_ne!(
                statement_binding_digest_with_domain(
                    &changed,
                    parameters.identity_header(),
                    parameters.max_inner_proof_bytes(),
                    &statement,
                    &context_bytes,
                    wire.salt(),
                    &profile
                ),
                baseline_binding
            );
        }
        let request_baseline = hash_request_with_domains(
            HX512_REQUEST_FRAME_DOMAIN,
            Hx512Role::PiopInputBinding.domain(),
            transcript.statement_binding_digest(),
            Hx512RequestKind::StageAbsorb,
            2,
            transcript.chain_digest(),
            &[],
            b"domain-mutation",
            0,
        );
        for offset in 0..HX512_REQUEST_FRAME_DOMAIN.len() {
            let mut changed = HX512_REQUEST_FRAME_DOMAIN.to_vec();
            changed[offset] ^= 1;
            assert_ne!(
                hash_request_with_domains(
                    &changed,
                    Hx512Role::PiopInputBinding.domain(),
                    transcript.statement_binding_digest(),
                    Hx512RequestKind::StageAbsorb,
                    2,
                    transcript.chain_digest(),
                    &[],
                    b"domain-mutation",
                    0
                ),
                request_baseline
            );
        }
        let mut xof_baseline = [0u8; 64];
        shake256_request_reader_with_domains(
            HX512_XOF_FRAME_DOMAIN,
            Hx512Role::DecsCoefficientChallenge.domain(),
            transcript.statement_binding_digest(),
            Hx512RequestKind::FieldXof,
            1,
            transcript.chain_digest(),
            &[0; 13],
        )
        .read(&mut xof_baseline);
        for offset in 0..HX512_XOF_FRAME_DOMAIN.len() {
            let mut changed = HX512_XOF_FRAME_DOMAIN.to_vec();
            changed[offset] ^= 1;
            let mut output = [0u8; 64];
            shake256_request_reader_with_domains(
                &changed,
                Hx512Role::DecsCoefficientChallenge.domain(),
                transcript.statement_binding_digest(),
                Hx512RequestKind::FieldXof,
                1,
                transcript.chain_digest(),
                &[0; 13],
            )
            .read(&mut output);
            assert_ne!(output, xof_baseline);
        }
        for role in Hx512Role::ALL {
            let baseline = hash_request_with_domains(
                HX512_REQUEST_FRAME_DOMAIN,
                role.domain(),
                transcript.statement_binding_digest(),
                Hx512RequestKind::StageAbsorb,
                0,
                transcript.chain_digest(),
                &[],
                b"role-domain",
                0,
            );
            for offset in 0..role.domain().len() {
                let mut changed = role.domain().to_vec();
                changed[offset] ^= 1;
                assert_ne!(
                    hash_request_with_domains(
                        HX512_REQUEST_FRAME_DOMAIN,
                        &changed,
                        transcript.statement_binding_digest(),
                        Hx512RequestKind::StageAbsorb,
                        0,
                        transcript.chain_digest(),
                        &[],
                        b"role-domain",
                        0
                    ),
                    baseline
                );
            }
        }
        let alternate_header =
            Hx512WireParameters::new(b"test-only-alternate-release-header", TEST_INNER_PROOF_CAP)
                .unwrap();
        assert_ne!(
            wire.transcript(alternate_header, &statement, &context, geometry)
                .unwrap()
                .statement_binding_digest(),
            transcript.statement_binding_digest()
        );
        let alternate_cap =
            Hx512WireParameters::new(TEST_IDENTITY_HEADER, TEST_INNER_PROOF_CAP + 1).unwrap();
        assert_ne!(
            wire.transcript(alternate_cap, &statement, &context, geometry)
                .unwrap()
                .statement_binding_digest(),
            transcript.statement_binding_digest()
        );
    }

    #[test]
    fn samplers_are_single_use_bounded_unbiased_and_history_hashes_are_chain_independent() {
        let wire = fixture();
        let geometry = geometry_with_q(48);
        let mut first = transcript(&wire, geometry);
        let mut second = transcript(&wire, geometry);
        let tape: [u8; HX512_PROFILE_LEAF_TAPE_BYTES] =
            std::array::from_fn(|index| (index as u8).wrapping_mul(7));
        let leaf = first
            .hash_leaf(
                wire.salt(),
                41,
                &tape,
                &[1, 2, HX512_GOLDILOCKS_MODULUS - 1],
                &[3, 4],
            )
            .unwrap();
        assert_eq!(
            hex::encode(leaf),
            "731d6d632994c1751773ee568c4fad94953e0e715e167a4285299dab7f36452de500afe0fd976fd46a3243ceb1ea305578d5b3fc97ff436bf5dc172a7e243b47"
        );
        let opened = first.hash_opened_leaf_tape(41, &tape).unwrap();
        let node = first.hash_merkle_node(0, 20, &leaf, &opened);
        first
            .hash_merkle_root(geometry.decs_leaf_count(), &node)
            .unwrap();
        second
            .hash_merkle_root(geometry.decs_leaf_count(), &node)
            .unwrap();
        let fields = first.sample_decs_coefficients().unwrap();
        assert_eq!(fields, second.sample_decs_coefficients().unwrap());
        assert_eq!(
            fields.values.len(),
            geometry.decs_coefficient_count().unwrap()
        );
        assert!(fields
            .values
            .iter()
            .all(|value| *value < HX512_GOLDILOCKS_MODULUS));
        assert_eq!(fields.accounting.xof_invocations, 1);
        assert_eq!(fields.accounting.sampler_aborts, 0);
        assert!(
            fields.accounting.candidates_examined
                <= u64::from(fields.accounting.max_candidate_words)
        );
        assert_eq!(
            first
                .hash_leaf(
                    wire.salt(),
                    41,
                    &tape,
                    &[1, 2, HX512_GOLDILOCKS_MODULUS - 1],
                    &[3, 4]
                )
                .unwrap(),
            leaf
        );
        assert_eq!(
            hex::encode(
                fields
                    .values
                    .iter()
                    .take(8)
                    .flat_map(|value| value.to_be_bytes())
                    .collect::<Vec<_>>()
            ),
            "ffc9bc5dfe40906ac7cca06b1fab566a271cdd7496a642c022055e13fde804cff0022c6ff7905f463553c6a807ac91f5d4b65c5f9ad063d198bd8f2c7bce7aef"
        );

        let saturated_geometry = geometry_with_q(4_096);
        let mut saturated = transcript(&wire, saturated_geometry);
        advance_to_query(&mut saturated);
        let error = saturated
            .sample_index_stage(Hx512TranscriptStage::DecsQueryChallenge, 4_096, 4_096)
            .expect_err("bounded coupon sampler must exhaust");
        let Hx512Error::SamplerExhausted(accounting) = error else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(accounting.xof_invocations, 1);
        assert_eq!(accounting.sampler_aborts, 1);
        assert!(accounting.accepted < accounting.requested);
        assert!(matches!(
            saturated.sample_decs_queries(),
            Err(Hx512Error::SchedulePoisoned(
                Hx512TranscriptStage::DecsQueryChallenge
            ))
        ));
        assert!(matches!(
            first.hash_leaf(wire.salt(), geometry.decs_leaf_count(), &tape, &[1], &[2]),
            Err(Hx512Error::LeafIndex(_))
        ));
        assert!(matches!(
            first.hash_leaf(wire.salt(), 1, &[0u8; 64], &[1], &[2]),
            Err(Hx512Error::LeafTapeBytes {
                expected: 72,
                actual: 64
            })
        ));
    }

    #[test]
    fn physical_ghcm_ledger_is_conditional_and_every_authority_gate_fails_closed() {
        let geometry = geometry_with_q(48);
        assert_eq!(HX512_TRANSCRIPT_SCHEDULE.len(), 8);
        assert_eq!(HX512_TRANSCRIPT_EVENT_LEDGER.len(), 8);
        for (ordinal, event) in HX512_TRANSCRIPT_EVENT_LEDGER.iter().enumerate() {
            assert_eq!(event.ordinal as usize, ordinal);
            assert_eq!(event.stage, HX512_TRANSCRIPT_SCHEDULE[ordinal]);
            assert_eq!(event.operation, event.stage.operation());
        }
        assert_eq!(
            HX512_TRANSCRIPT_EVENT_LEDGER
                .iter()
                .filter(|event| event.primitive == Hx512OraclePrimitive::Sha512)
                .count(),
            4
        );
        assert_eq!(
            HX512_TRANSCRIPT_EVENT_LEDGER
                .iter()
                .filter(|event| event.primitive == Hx512OraclePrimitive::Shake256)
                .count(),
            4
        );
        let ledger = hx512_ghcm_accounting(geometry, 64, 64).unwrap();
        assert_eq!(ledger.leaf_count, 1 << 20);
        assert_eq!(ledger.opened_leaf_count, 48);
        assert_eq!(ledger.opened_leaf_tape_payload_bytes, 3_456);
        assert_eq!(ledger.leaf_program_events_per_proof, 2_097_152);
        assert_eq!(ledger.chain_program_events_per_proof, 8);
        assert_eq!(ledger.leaf_term_numerator, 3);
        assert_eq!(ledger.leaf_term_denominator_log2, 172);
        assert_eq!(ledger.chain_term_numerator, 3);
        assert_eq!(ledger.chain_term_denominator_log2, 158);
        assert_eq!(ledger.combined_term_numerator, 49_155);
        assert_eq!(ledger.combined_term_denominator_log2, 172);
        assert_eq!(ledger.conditional_ideal_qro_security_bits_floor, 156);
        assert!(!ledger.independent_uniform_tapes_verified);
        assert!(!ledger.leaf_conditional_min_entropy_verified);
        assert!(!ledger.fresh_chain_entropy_verified);
        assert!(!ledger.global_salt_reuse_excluded);
        assert!(!ledger.adaptive_program_schedule_verified);
        assert!(!ledger.concrete_sha512_qro_bridge_verified);
        assert!(!ledger.concrete_shake256_xof_bridge_verified);
        assert_eq!(HX512_PRODUCTION_BLOCKERS.len(), 16);
        assert!(!HX512_SECURITY_AUTHORIZATION.engine_transcript_schedule_refinement_verified);
        assert!(!HX512_SECURITY_AUTHORIZATION.full_relation_compiler_refinement_verified);
        assert!(!HX512_SECURITY_AUTHORIZATION.honest_verifier_zero_knowledge_verified);
        assert!(!HX512_SECURITY_AUTHORIZATION.complete_zero_knowledge_verified);
        assert!(!HX512_SECURITY_AUTHORIZATION.concrete_sha512_qro_bridge_verified);
        assert!(!HX512_SECURITY_AUTHORIZATION.concrete_shake256_xof_bridge_verified);
        assert!(!HX512_SECURITY_AUTHORIZATION.production_authorized());
        assert!(matches!(
            ensure_hx512_production_authorized(),
            Err(Hx512Error::ProductionAuthorizationUnavailable)
        ));
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512StageOperation {
    MerkleRoot,
    AbsorbMessage,
    FieldXof,
    IndexXof,
}

impl Hx512TranscriptStage {
    pub const fn operation(self) -> Hx512StageOperation {
        match self {
            Self::DecsRootBinding => Hx512StageOperation::MerkleRoot,
            Self::DecsCoefficientChallenge
            | Self::PiopCoefficientChallenge
            | Self::PiopOpeningChallenge => Hx512StageOperation::FieldXof,
            Self::PiopInputBinding | Self::PiopTranscriptBinding | Self::DecsOpeningBinding => {
                Hx512StageOperation::AbsorbMessage
            }
            Self::DecsQueryChallenge => Hx512StageOperation::IndexXof,
        }
    }

    const fn role(self) -> Hx512Role {
        match self {
            Self::DecsRootBinding => Hx512Role::DecsRootBinding,
            Self::DecsCoefficientChallenge => Hx512Role::DecsCoefficientChallenge,
            Self::PiopInputBinding => Hx512Role::PiopInputBinding,
            Self::PiopCoefficientChallenge => Hx512Role::PiopCoefficientChallenge,
            Self::PiopTranscriptBinding => Hx512Role::PiopTranscriptBinding,
            Self::PiopOpeningChallenge => Hx512Role::PiopOpeningChallenge,
            Self::DecsOpeningBinding => Hx512Role::DecsOpeningBinding,
            Self::DecsQueryChallenge => Hx512Role::DecsQueryChallenge,
        }
    }
}

pub const HX512_TRANSCRIPT_SCHEDULE: [Hx512TranscriptStage; 8] = [
    Hx512TranscriptStage::DecsRootBinding,
    Hx512TranscriptStage::DecsCoefficientChallenge,
    Hx512TranscriptStage::PiopInputBinding,
    Hx512TranscriptStage::PiopCoefficientChallenge,
    Hx512TranscriptStage::PiopTranscriptBinding,
    Hx512TranscriptStage::PiopOpeningChallenge,
    Hx512TranscriptStage::DecsOpeningBinding,
    Hx512TranscriptStage::DecsQueryChallenge,
];
pub const HX512_TRANSCRIPT_PROGRAM_EVENTS_PER_PROOF: u32 = HX512_TRANSCRIPT_SCHEDULE.len() as u32;
/// Fresh verifier prefix: raw DECS root, claimed event-2 output `h3`, and the
/// existing claimed event-4 output `h5` (`h_piop`).  Only `h3` is additional
/// to the raw root and existing `h5` fields required by the engine handoff;
/// compared with the prior fresh inner layout, raw root plus `h3` adds 128 B.
pub const HX512_DEFERRED_VERIFIER_PREFIX_BYTES: usize = 3 * HX512_DIGEST_BYTES;
pub const HX512_DEFERRED_VERIFIER_ADDITIONAL_INNER_BYTES: usize = 2 * HX512_DIGEST_BYTES;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512OraclePrimitive {
    Sha512,
    Shake256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512TranscriptEventDescriptor {
    pub ordinal: u8,
    pub stage: Hx512TranscriptStage,
    pub operation: Hx512StageOperation,
    pub primitive: Hx512OraclePrimitive,
}

/// Physical oracle-event ledger for the only executable transcript schedule.
/// History-tree hashes are separately accounted and do not advance this chain.
pub const HX512_TRANSCRIPT_EVENT_LEDGER: [Hx512TranscriptEventDescriptor; 8] = [
    Hx512TranscriptEventDescriptor {
        ordinal: 0,
        stage: Hx512TranscriptStage::DecsRootBinding,
        operation: Hx512StageOperation::MerkleRoot,
        primitive: Hx512OraclePrimitive::Sha512,
    },
    Hx512TranscriptEventDescriptor {
        ordinal: 1,
        stage: Hx512TranscriptStage::DecsCoefficientChallenge,
        operation: Hx512StageOperation::FieldXof,
        primitive: Hx512OraclePrimitive::Shake256,
    },
    Hx512TranscriptEventDescriptor {
        ordinal: 2,
        stage: Hx512TranscriptStage::PiopInputBinding,
        operation: Hx512StageOperation::AbsorbMessage,
        primitive: Hx512OraclePrimitive::Sha512,
    },
    Hx512TranscriptEventDescriptor {
        ordinal: 3,
        stage: Hx512TranscriptStage::PiopCoefficientChallenge,
        operation: Hx512StageOperation::FieldXof,
        primitive: Hx512OraclePrimitive::Shake256,
    },
    Hx512TranscriptEventDescriptor {
        ordinal: 4,
        stage: Hx512TranscriptStage::PiopTranscriptBinding,
        operation: Hx512StageOperation::AbsorbMessage,
        primitive: Hx512OraclePrimitive::Sha512,
    },
    Hx512TranscriptEventDescriptor {
        ordinal: 5,
        stage: Hx512TranscriptStage::PiopOpeningChallenge,
        operation: Hx512StageOperation::FieldXof,
        primitive: Hx512OraclePrimitive::Shake256,
    },
    Hx512TranscriptEventDescriptor {
        ordinal: 6,
        stage: Hx512TranscriptStage::DecsOpeningBinding,
        operation: Hx512StageOperation::AbsorbMessage,
        primitive: Hx512OraclePrimitive::Sha512,
    },
    Hx512TranscriptEventDescriptor {
        ordinal: 7,
        stage: Hx512TranscriptStage::DecsQueryChallenge,
        operation: Hx512StageOperation::IndexXof,
        primitive: Hx512OraclePrimitive::Shake256,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512ScheduleState {
    Awaiting(Hx512TranscriptStage),
    Complete,
    Poisoned(Hx512TranscriptStage),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512DeferredVerifierState {
    DrivingSchedule,
    AwaitingReconstructedRoot,
    AwaitingReconstructedPiopInput,
    AwaitingReconstructedPiopTranscript,
    ReadyToFinish,
    Poisoned(Hx512TranscriptStage),
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hx512Role {
    DecsRootBinding = 0,
    DecsCoefficientChallenge = 1,
    PiopInputBinding = 2,
    PiopCoefficientChallenge = 3,
    PiopTranscriptBinding = 4,
    PiopOpeningChallenge = 5,
    DecsOpeningBinding = 6,
    DecsQueryChallenge = 7,
    MerkleLeaf = 8,
    MerkleNode = 9,
    OpenedLeafTape = 10,
}

impl Hx512Role {
    pub const ALL: [Self; 11] = [
        Self::DecsRootBinding,
        Self::DecsCoefficientChallenge,
        Self::PiopInputBinding,
        Self::PiopCoefficientChallenge,
        Self::PiopTranscriptBinding,
        Self::PiopOpeningChallenge,
        Self::DecsOpeningBinding,
        Self::DecsQueryChallenge,
        Self::MerkleLeaf,
        Self::MerkleNode,
        Self::OpenedLeafTape,
    ];

    pub(crate) const fn domain(self) -> &'static [u8] {
        match self {
            Self::DecsRootBinding => b"hegemon.smallwood.hx512.candidate.role.decs-root\0",
            Self::DecsCoefficientChallenge => {
                b"hegemon.smallwood.hx512.candidate.role.decs-coefficient\0"
            }
            Self::PiopInputBinding => b"hegemon.smallwood.hx512.candidate.role.piop-input\0",
            Self::PiopCoefficientChallenge => {
                b"hegemon.smallwood.hx512.candidate.role.piop-coefficient\0"
            }
            Self::PiopTranscriptBinding => {
                b"hegemon.smallwood.hx512.candidate.role.piop-transcript\0"
            }
            Self::PiopOpeningChallenge => b"hegemon.smallwood.hx512.candidate.role.piop-opening\0",
            Self::DecsOpeningBinding => b"hegemon.smallwood.hx512.candidate.role.decs-opening\0",
            Self::DecsQueryChallenge => b"hegemon.smallwood.hx512.candidate.role.decs-query\0",
            Self::MerkleLeaf => b"hegemon.smallwood.hx512.candidate.role.merkle-leaf\0",
            Self::MerkleNode => b"hegemon.smallwood.hx512.candidate.role.merkle-node\0",
            Self::OpenedLeafTape => b"hegemon.smallwood.hx512.candidate.role.opened-leaf-tape\0",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512WireFrame {
    IdentityHeader,
    Salt,
    InnerProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512SamplerKind {
    GoldilocksField,
    DistinctIndex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512VerifierContextBinding {
    pub stable_current_root: [u8; 64],
    pub parent_height: u64,
    pub expected_action_intent: [u8; 64],
}

impl Hx512VerifierContextBinding {
    pub const fn new(
        stable_current_root: [u8; 64],
        parent_height: u64,
        expected_action_intent: [u8; 64],
    ) -> Self {
        Self {
            stable_current_root,
            parent_height,
            expected_action_intent,
        }
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, Hx512Error> {
        if bytes.len() != HX512_VERIFIER_CONTEXT_BYTES {
            return Err(Hx512Error::VerifierContextLength {
                expected: HX512_VERIFIER_CONTEXT_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            stable_current_root: bytes[..64].try_into().map_err(|_| {
                Hx512Error::VerifierContextLength {
                    expected: HX512_VERIFIER_CONTEXT_BYTES,
                    actual: bytes.len(),
                }
            })?,
            parent_height: u64::from_le_bytes(bytes[64..72].try_into().map_err(|_| {
                Hx512Error::VerifierContextLength {
                    expected: HX512_VERIFIER_CONTEXT_BYTES,
                    actual: bytes.len(),
                }
            })?),
            expected_action_intent: bytes[72..].try_into().map_err(|_| {
                Hx512Error::VerifierContextLength {
                    expected: HX512_VERIFIER_CONTEXT_BYTES,
                    actual: bytes.len(),
                }
            })?,
        })
    }

    pub fn encode_exact(self) -> [u8; HX512_VERIFIER_CONTEXT_BYTES] {
        let mut output = [0u8; HX512_VERIFIER_CONTEXT_BYTES];
        output[..64].copy_from_slice(&self.stable_current_root);
        output[64..72].copy_from_slice(&self.parent_height.to_le_bytes());
        output[72..].copy_from_slice(&self.expected_action_intent);
        output
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512DomainKind {
    Radix2DisjointCoset = 1,
}
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512FieldEncoding {
    CanonicalU64BigEndian = 1,
}
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512IndexEncoding {
    CanonicalU32BigEndian = 1,
}
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512PolynomialOrder {
    ConstantTermFirst = 1,
}
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512ContextHeightEncoding {
    CanonicalU64LittleEndian = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512CoreGeometry {
    pub n: u32,
    pub r: u32,
    pub k: u32,
    pub packing_factor: u32,
    pub maximum_constraint_degree: u32,
    pub beta: u32,
    pub rho: u32,
    pub eta: u32,
    pub piop_opening_count: u32,
    pub decs_query_count: u32,
    pub topology_radix: u32,
    pub topology_direct_base_rows: u32,
    pub topology_cell_count: u32,
    pub adapter_row_count: u32,
    pub nonlinear_constraint_count: u32,
    pub linear_constraint_count: u32,
    pub witness_polynomial_degree: u32,
    pub mpol_polynomial_degree: u32,
    pub linear_polynomial_degree: u32,
    pub polynomial_count: u32,
    pub unstacked_rows: u32,
    pub unstacked_columns: u32,
    pub lvcs_rows: u32,
    pub lvcs_columns: u32,
    pub lvcs_opened_combinations: u32,
    pub interpolation_point_count: u32,
    pub auxiliary_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512MatrixDimensions {
    pub rows: u32,
    pub columns: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512ProofMatrixGeometry {
    pub public_polynomials: Hx512MatrixDimensions,
    pub linear_polynomials: Hx512MatrixDimensions,
    pub recombination_tails: Hx512MatrixDimensions,
    pub subset_evaluations: Hx512MatrixDimensions,
    pub partial_evaluations: Hx512MatrixDimensions,
    pub masking_evaluations: Hx512MatrixDimensions,
    pub high_coefficients: Hx512MatrixDimensions,
    pub opened_witness: Hx512MatrixDimensions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512OpeningGeometry {
    pub authentication_path_count: u32,
    pub authentication_path_depth: u32,
    pub compact_authentication_paths: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512DomainGeometry {
    pub field_modulus: u64,
    pub subgroup_generator: u64,
    pub canonical_coset_shift: u64,
    pub domain_kind: Hx512DomainKind,
    pub field_encoding: Hx512FieldEncoding,
    pub index_encoding: Hx512IndexEncoding,
    pub polynomial_order: Hx512PolynomialOrder,
    pub context_height_encoding: Hx512ContextHeightEncoding,
}

pub const HX512_PROFILE_DESCRIPTOR_BYTES: usize = 422;

/// Fully typed, canonical profile geometry bound before event zero.  It does
/// not select a release profile: the relation and topology compilers supply
/// their exact digests and every dimension, while this module computes the
/// digest of its own eight-event schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512TranscriptGeometry {
    core: Hx512CoreGeometry,
    matrices: Hx512ProofMatrixGeometry,
    openings: Hx512OpeningGeometry,
    domain: Hx512DomainGeometry,
    relation_digest_sha512: [u8; 64],
    topology_digest_sha512: [u8; 64],
    transcript_schedule_digest_sha512: [u8; 64],
}

pub type Hx512ProfileDescriptor = Hx512TranscriptGeometry;

impl Hx512TranscriptGeometry {
    pub fn new(
        core: Hx512CoreGeometry,
        matrices: Hx512ProofMatrixGeometry,
        openings: Hx512OpeningGeometry,
        domain: Hx512DomainGeometry,
        relation_digest_sha512: [u8; 64],
        topology_digest_sha512: [u8; 64],
    ) -> Result<Self, Hx512Error> {
        let value = Self {
            core,
            matrices,
            openings,
            domain,
            relation_digest_sha512,
            topology_digest_sha512,
            transcript_schedule_digest_sha512: hx512_transcript_schedule_digest(),
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn core(self) -> Hx512CoreGeometry {
        self.core
    }
    pub const fn matrices(self) -> Hx512ProofMatrixGeometry {
        self.matrices
    }
    pub const fn openings(self) -> Hx512OpeningGeometry {
        self.openings
    }
    pub const fn domain(self) -> Hx512DomainGeometry {
        self.domain
    }
    pub const fn relation_digest_sha512(self) -> [u8; 64] {
        self.relation_digest_sha512
    }
    pub const fn topology_digest_sha512(self) -> [u8; 64] {
        self.topology_digest_sha512
    }
    pub const fn transcript_schedule_digest_sha512(self) -> [u8; 64] {
        self.transcript_schedule_digest_sha512
    }
    pub const fn decs_opened_leaf_count(self) -> usize {
        self.core.decs_query_count as usize
    }
    pub const fn piop_opening_count(self) -> usize {
        self.core.piop_opening_count as usize
    }
    pub const fn decs_leaf_count(self) -> u32 {
        self.core.n
    }
    pub fn decs_coefficient_count(self) -> Result<usize, Hx512Error> {
        checked_profile_sample_product(
            Hx512TranscriptStage::DecsCoefficientChallenge,
            self.core.eta,
            self.core.lvcs_rows,
        )
    }
    pub fn piop_coefficient_count(self) -> Result<usize, Hx512Error> {
        checked_profile_sample_product(
            Hx512TranscriptStage::PiopCoefficientChallenge,
            self.core.rho,
            self.core
                .nonlinear_constraint_count
                .max(self.core.linear_constraint_count),
        )
    }

    pub fn encode_canonical(self) -> [u8; HX512_PROFILE_DESCRIPTOR_BYTES] {
        let mut output = [0u8; HX512_PROFILE_DESCRIPTOR_BYTES];
        let mut cursor = 0usize;
        for value in [
            self.core.n,
            self.core.r,
            self.core.k,
            self.core.packing_factor,
            self.core.maximum_constraint_degree,
            self.core.beta,
            self.core.rho,
            self.core.eta,
            self.core.piop_opening_count,
            self.core.decs_query_count,
            self.core.topology_radix,
            self.core.topology_direct_base_rows,
            self.core.topology_cell_count,
            self.core.adapter_row_count,
            self.core.nonlinear_constraint_count,
            self.core.linear_constraint_count,
            self.core.witness_polynomial_degree,
            self.core.mpol_polynomial_degree,
            self.core.linear_polynomial_degree,
            self.core.polynomial_count,
            self.core.unstacked_rows,
            self.core.unstacked_columns,
            self.core.lvcs_rows,
            self.core.lvcs_columns,
            self.core.lvcs_opened_combinations,
            self.core.interpolation_point_count,
            self.core.auxiliary_count,
        ] {
            put_u32(&mut output, &mut cursor, value);
        }
        for matrix in self.matrix_array() {
            put_u32(&mut output, &mut cursor, matrix.rows);
            put_u32(&mut output, &mut cursor, matrix.columns);
        }
        put_u32(
            &mut output,
            &mut cursor,
            self.openings.authentication_path_count,
        );
        put_u32(
            &mut output,
            &mut cursor,
            self.openings.authentication_path_depth,
        );
        put_u8(
            &mut output,
            &mut cursor,
            u8::from(self.openings.compact_authentication_paths),
        );
        for width in [
            HX512_SALT_BYTES as u32,
            HX512_DIGEST_BYTES as u32,
            HX512_PROFILE_LEAF_TAPE_BYTES as u32,
            HX512_EXTERNAL_STATEMENT_BYTES as u32,
            HX512_VERIFIER_CONTEXT_BYTES as u32,
        ] {
            put_u32(&mut output, &mut cursor, width);
        }
        put_u64(&mut output, &mut cursor, self.domain.field_modulus);
        put_u64(&mut output, &mut cursor, self.domain.subgroup_generator);
        put_u64(&mut output, &mut cursor, self.domain.canonical_coset_shift);
        for tag in [
            self.domain.domain_kind as u8,
            self.domain.field_encoding as u8,
            self.domain.index_encoding as u8,
            self.domain.polynomial_order as u8,
            self.domain.context_height_encoding as u8,
        ] {
            put_u8(&mut output, &mut cursor, tag);
        }
        put_bytes(&mut output, &mut cursor, &self.relation_digest_sha512);
        put_bytes(&mut output, &mut cursor, &self.topology_digest_sha512);
        put_bytes(
            &mut output,
            &mut cursor,
            &self.transcript_schedule_digest_sha512,
        );
        debug_assert_eq!(cursor, HX512_PROFILE_DESCRIPTOR_BYTES);
        output
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, Hx512Error> {
        if bytes.len() != HX512_PROFILE_DESCRIPTOR_BYTES {
            return Err(Hx512Error::ProfileDescriptorLength {
                expected: HX512_PROFILE_DESCRIPTOR_BYTES,
                actual: bytes.len(),
            });
        }
        let mut cursor = 0usize;
        let mut values = [0u32; 27];
        for value in &mut values {
            *value = take_u32(bytes, &mut cursor)?;
        }
        let core = Hx512CoreGeometry {
            n: values[0],
            r: values[1],
            k: values[2],
            packing_factor: values[3],
            maximum_constraint_degree: values[4],
            beta: values[5],
            rho: values[6],
            eta: values[7],
            piop_opening_count: values[8],
            decs_query_count: values[9],
            topology_radix: values[10],
            topology_direct_base_rows: values[11],
            topology_cell_count: values[12],
            adapter_row_count: values[13],
            nonlinear_constraint_count: values[14],
            linear_constraint_count: values[15],
            witness_polynomial_degree: values[16],
            mpol_polynomial_degree: values[17],
            linear_polynomial_degree: values[18],
            polynomial_count: values[19],
            unstacked_rows: values[20],
            unstacked_columns: values[21],
            lvcs_rows: values[22],
            lvcs_columns: values[23],
            lvcs_opened_combinations: values[24],
            interpolation_point_count: values[25],
            auxiliary_count: values[26],
        };
        let mut dims = [Hx512MatrixDimensions {
            rows: 0,
            columns: 0,
        }; 8];
        for dim in &mut dims {
            dim.rows = take_u32(bytes, &mut cursor)?;
            dim.columns = take_u32(bytes, &mut cursor)?;
        }
        let matrices = Hx512ProofMatrixGeometry {
            public_polynomials: dims[0],
            linear_polynomials: dims[1],
            recombination_tails: dims[2],
            subset_evaluations: dims[3],
            partial_evaluations: dims[4],
            masking_evaluations: dims[5],
            high_coefficients: dims[6],
            opened_witness: dims[7],
        };
        let openings = Hx512OpeningGeometry {
            authentication_path_count: take_u32(bytes, &mut cursor)?,
            authentication_path_depth: take_u32(bytes, &mut cursor)?,
            compact_authentication_paths: match take_u8(bytes, &mut cursor)? {
                0 => false,
                1 => true,
                _ => {
                    return Err(Hx512Error::ProfileInvariant(
                        "noncanonical compact-auth-path flag",
                    ));
                }
            },
        };
        let widths = [
            take_u32(bytes, &mut cursor)?,
            take_u32(bytes, &mut cursor)?,
            take_u32(bytes, &mut cursor)?,
            take_u32(bytes, &mut cursor)?,
            take_u32(bytes, &mut cursor)?,
        ];
        if widths
            != [
                HX512_SALT_BYTES as u32,
                HX512_DIGEST_BYTES as u32,
                HX512_PROFILE_LEAF_TAPE_BYTES as u32,
                HX512_EXTERNAL_STATEMENT_BYTES as u32,
                HX512_VERIFIER_CONTEXT_BYTES as u32,
            ]
        {
            return Err(Hx512Error::ProfileInvariant("protocol widths"));
        }
        let field_modulus = take_u64(bytes, &mut cursor)?;
        let subgroup_generator = take_u64(bytes, &mut cursor)?;
        let canonical_coset_shift = take_u64(bytes, &mut cursor)?;
        let domain = Hx512DomainGeometry {
            field_modulus,
            subgroup_generator,
            canonical_coset_shift,
            domain_kind: decode_domain_kind(take_u8(bytes, &mut cursor)?)?,
            field_encoding: decode_field_encoding(take_u8(bytes, &mut cursor)?)?,
            index_encoding: decode_index_encoding(take_u8(bytes, &mut cursor)?)?,
            polynomial_order: decode_polynomial_order(take_u8(bytes, &mut cursor)?)?,
            context_height_encoding: decode_context_height_encoding(take_u8(bytes, &mut cursor)?)?,
        };
        let relation_digest_sha512 = take(bytes, &mut cursor, 64)?.try_into().map_err(|_| {
            Hx512Error::ProfileDescriptorLength {
                expected: HX512_PROFILE_DESCRIPTOR_BYTES,
                actual: bytes.len(),
            }
        })?;
        let topology_digest_sha512 = take(bytes, &mut cursor, 64)?.try_into().map_err(|_| {
            Hx512Error::ProfileDescriptorLength {
                expected: HX512_PROFILE_DESCRIPTOR_BYTES,
                actual: bytes.len(),
            }
        })?;
        let transcript_schedule_digest_sha512: [u8; 64] = take(bytes, &mut cursor, 64)?
            .try_into()
            .map_err(|_| Hx512Error::ProfileDescriptorLength {
                expected: HX512_PROFILE_DESCRIPTOR_BYTES,
                actual: bytes.len(),
            })?;
        if cursor != bytes.len() {
            return Err(Hx512Error::ProfileDescriptorLength {
                expected: cursor,
                actual: bytes.len(),
            });
        }
        let value = Self {
            core,
            matrices,
            openings,
            domain,
            relation_digest_sha512,
            topology_digest_sha512,
            transcript_schedule_digest_sha512,
        };
        value.validate()?;
        if value.transcript_schedule_digest_sha512 != hx512_transcript_schedule_digest() {
            return Err(Hx512Error::ProfileScheduleDigestMismatch);
        }
        Ok(value)
    }

    fn matrix_array(self) -> [Hx512MatrixDimensions; 8] {
        [
            self.matrices.public_polynomials,
            self.matrices.linear_polynomials,
            self.matrices.recombination_tails,
            self.matrices.subset_evaluations,
            self.matrices.partial_evaluations,
            self.matrices.masking_evaluations,
            self.matrices.high_coefficients,
            self.matrices.opened_witness,
        ]
    }

    pub fn validate(self) -> Result<(), Hx512Error> {
        if self.core.n == 0
            || !self.core.n.is_power_of_two()
            || self.core.n > HX512_MAX_INDEX_DOMAIN_SIZE
        {
            return Err(Hx512Error::ProfileInvariant(
                "N must be a bounded power of two",
            ));
        }
        if self.core.r == 0
            || self.core.maximum_constraint_degree == 0
            || self.core.beta == 0
            || self.core.rho == 0
            || self.core.eta == 0
        {
            return Err(Hx512Error::ProfileInvariant(
                "core dimensions must be nonzero",
            ));
        }
        if self.core.k != 1_024
            || self.core.packing_factor != self.core.k
            || self.core.topology_radix != 1_024
        {
            return Err(Hx512Error::ProfileInvariant(
                "HX512 requires exact K=packing=topology-radix=1024",
            ));
        }
        if self.core.piop_opening_count != 6 {
            return Err(Hx512Error::ProfileInvariant(
                "PIOP opening count must be exactly six",
            ));
        }
        if self.core.decs_query_count == 0
            || self.core.decs_query_count as usize > HX512_MAX_INDEX_SAMPLES
            || self.core.decs_query_count > self.core.n
        {
            return Err(Hx512Error::ProfileInvariant("DECS query count"));
        }
        if self.core.auxiliary_count != 0 {
            return Err(Hx512Error::ProfileInvariant("auxiliary count must be zero"));
        }
        if self.core.topology_direct_base_rows == 0
            || self.core.topology_cell_count == 0
            || self.core.adapter_row_count == 0
            || self.core.nonlinear_constraint_count == 0
            || self.core.linear_constraint_count == 0
            || self.core.polynomial_count == 0
            || self.core.unstacked_rows == 0
            || self.core.unstacked_columns == 0
            || self.core.lvcs_rows == 0
            || self.core.lvcs_columns == 0
            || self.core.lvcs_opened_combinations == 0
            || self.core.interpolation_point_count == 0
        {
            return Err(Hx512Error::ProfileInvariant(
                "engine and topology dimensions must be nonzero",
            ));
        }
        let expected = derive_profile_dimensions(self.core)?;
        if self.core.adapter_row_count != self.core.r
            || self.core.topology_direct_base_rows > self.core.r
            || self.core.topology_cell_count != expected.topology_cell_count
            || self.core.witness_polynomial_degree != expected.witness_polynomial_degree
            || self.core.mpol_polynomial_degree != expected.mpol_polynomial_degree
            || self.core.linear_polynomial_degree != expected.linear_polynomial_degree
            || self.core.polynomial_count != expected.polynomial_count
            || self.core.unstacked_rows != expected.unstacked_rows
            || self.core.unstacked_columns != expected.unstacked_columns
            || self.core.lvcs_rows != expected.lvcs_rows
            || self.core.lvcs_columns != expected.lvcs_columns
            || self.core.lvcs_opened_combinations != expected.lvcs_opened_combinations
            || self.core.interpolation_point_count != expected.interpolation_point_count
        {
            return Err(Hx512Error::ProfileInvariant(
                "derived engine/profile dimensions",
            ));
        }
        if self.matrices != expected.matrices {
            return Err(Hx512Error::ProfileInvariant(
                "derived proof matrix dimensions",
            ));
        }
        if self.openings.authentication_path_count != self.core.decs_query_count
            || self.openings.authentication_path_depth != self.core.n.trailing_zeros()
            || !self.openings.compact_authentication_paths
        {
            return Err(Hx512Error::ProfileInvariant(
                "authentication opening geometry",
            ));
        }
        if self.domain.field_modulus != HX512_GOLDILOCKS_MODULUS
            || self.domain.subgroup_generator != derive_radix2_subgroup_generator(self.core.n)?
            || self.domain.canonical_coset_shift
                != derive_canonical_coset_shift(self.core.n, self.core.interpolation_point_count)?
            || !radix2_coset_is_disjoint(
                self.core.n,
                self.core.interpolation_point_count,
                self.domain.canonical_coset_shift,
            )?
        {
            return Err(Hx512Error::ProfileInvariant("field/domain descriptor"));
        }
        if self.relation_digest_sha512.iter().all(|byte| *byte == 0)
            || self.topology_digest_sha512.iter().all(|byte| *byte == 0)
        {
            return Err(Hx512Error::ProfileInvariant(
                "relation/topology digest must be nonzero",
            ));
        }
        self.decs_coefficient_count()?;
        self.piop_coefficient_count()?;
        validate_geometry_field_count(
            Hx512TranscriptStage::PiopOpeningChallenge,
            self.piop_opening_count(),
        )?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Hx512DerivedProfileDimensions {
    topology_cell_count: u32,
    witness_polynomial_degree: u32,
    mpol_polynomial_degree: u32,
    linear_polynomial_degree: u32,
    polynomial_count: u32,
    unstacked_rows: u32,
    unstacked_columns: u32,
    lvcs_rows: u32,
    lvcs_columns: u32,
    lvcs_opened_combinations: u32,
    interpolation_point_count: u32,
    matrices: Hx512ProofMatrixGeometry,
}

fn derive_profile_dimensions(
    core: Hx512CoreGeometry,
) -> Result<Hx512DerivedProfileDimensions, Hx512Error> {
    let overflow = || Hx512Error::ProfileInvariant("derived profile arithmetic overflow");
    let s = core.piop_opening_count;
    let witness_polynomial_degree = core
        .packing_factor
        .checked_add(s)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(overflow)?;
    let mpol_polynomial_degree = core
        .maximum_constraint_degree
        .checked_mul(witness_polynomial_degree)
        .and_then(|value| value.checked_sub(core.packing_factor))
        .ok_or_else(overflow)?;
    let linear_polynomial_degree = witness_polynomial_degree
        .checked_add(core.packing_factor.checked_sub(1).ok_or_else(overflow)?)
        .ok_or_else(overflow)?;
    let polynomial_count = core
        .rho
        .checked_mul(2)
        .and_then(|extra| core.r.checked_add(extra))
        .ok_or_else(overflow)?;
    let public_polynomial_columns = mpol_polynomial_degree
        .checked_add(1)
        .and_then(|value| value.checked_sub(s))
        .ok_or_else(overflow)?;
    let linear_polynomial_columns = linear_polynomial_degree
        .checked_add(1)
        .and_then(|value| value.checked_sub(s.checked_add(1)?))
        .ok_or_else(overflow)?;
    let public_width = div_ceil_u32(public_polynomial_columns, core.packing_factor)?;
    let linear_width = div_ceil_u32(linear_polynomial_columns, core.packing_factor)?;
    let unstacked_columns = core
        .rho
        .checked_mul(public_width)
        .and_then(|value| {
            core.rho
                .checked_mul(linear_width)
                .and_then(|linear| value.checked_add(linear))
        })
        .and_then(|extra| core.r.checked_add(extra))
        .ok_or_else(overflow)?;
    let unstacked_rows = core.packing_factor.checked_add(s).ok_or_else(overflow)?;
    let lvcs_rows = unstacked_rows.checked_mul(core.beta).ok_or_else(overflow)?;
    let lvcs_columns = div_ceil_u32(unstacked_columns, core.beta)?;
    let lvcs_opened_combinations = core.beta.checked_mul(s).ok_or_else(overflow)?;
    let interpolation_point_count = lvcs_columns
        .checked_add(core.decs_query_count)
        .ok_or_else(overflow)?;
    let topology_cell_count = core
        .topology_direct_base_rows
        .checked_mul(core.topology_radix)
        .ok_or_else(overflow)?;
    let matrices = Hx512ProofMatrixGeometry {
        public_polynomials: Hx512MatrixDimensions {
            rows: core.rho,
            columns: public_polynomial_columns,
        },
        linear_polynomials: Hx512MatrixDimensions {
            rows: core.rho,
            columns: linear_polynomial_columns,
        },
        recombination_tails: Hx512MatrixDimensions {
            rows: lvcs_opened_combinations,
            columns: core.decs_query_count,
        },
        subset_evaluations: Hx512MatrixDimensions {
            rows: core.decs_query_count,
            columns: lvcs_rows
                .checked_sub(lvcs_opened_combinations)
                .ok_or_else(overflow)?,
        },
        partial_evaluations: Hx512MatrixDimensions {
            rows: s,
            columns: unstacked_columns
                .checked_sub(polynomial_count)
                .ok_or_else(overflow)?,
        },
        masking_evaluations: Hx512MatrixDimensions {
            rows: core.decs_query_count,
            columns: core.eta,
        },
        high_coefficients: Hx512MatrixDimensions {
            rows: core.eta,
            columns: lvcs_columns,
        },
        opened_witness: Hx512MatrixDimensions {
            rows: s,
            columns: polynomial_count,
        },
    };
    Ok(Hx512DerivedProfileDimensions {
        topology_cell_count,
        witness_polynomial_degree,
        mpol_polynomial_degree,
        linear_polynomial_degree,
        polynomial_count,
        unstacked_rows,
        unstacked_columns,
        lvcs_rows,
        lvcs_columns,
        lvcs_opened_combinations,
        interpolation_point_count,
        matrices,
    })
}

fn div_ceil_u32(numerator: u32, denominator: u32) -> Result<u32, Hx512Error> {
    if denominator == 0 {
        return Err(Hx512Error::ProfileInvariant(
            "zero profile division denominator",
        ));
    }
    numerator
        .checked_add(denominator - 1)
        .map(|value| value / denominator)
        .ok_or(Hx512Error::ProfileInvariant(
            "derived profile arithmetic overflow",
        ))
}

const HX512_GOLDILOCKS_TWO_ADIC_ROOT: u64 = 0x1856_29dc_da58_878c;
const HX512_GOLDILOCKS_TWO_ADICITY: u32 = 32;
const HX512_COSET_SEARCH_LIMIT: u32 = 1 << 12;

fn field_mul(left: u64, right: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(HX512_GOLDILOCKS_MODULUS)) as u64
}

fn field_pow(mut base: u64, mut exponent: u64) -> u64 {
    let mut result = 1u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = field_mul(result, base);
        }
        base = field_mul(base, base);
        exponent >>= 1;
    }
    result
}

fn derive_radix2_subgroup_generator(domain_size: u32) -> Result<u64, Hx512Error> {
    if domain_size == 0
        || !domain_size.is_power_of_two()
        || domain_size.trailing_zeros() > HX512_GOLDILOCKS_TWO_ADICITY
    {
        return Err(Hx512Error::ProfileInvariant("radix-2 subgroup size"));
    }
    let log_size = domain_size.ilog2();
    let root = field_pow(
        HX512_GOLDILOCKS_TWO_ADIC_ROOT,
        1u64 << (HX512_GOLDILOCKS_TWO_ADICITY - log_size),
    );
    if field_pow(root, u64::from(domain_size)) != 1
        || (domain_size > 1 && field_pow(root, u64::from(domain_size / 2)) == 1)
    {
        return Err(Hx512Error::ProfileInvariant(
            "radix-2 subgroup generator order",
        ));
    }
    Ok(root)
}

fn radix2_coset_is_disjoint(
    domain_size: u32,
    interpolation_point_count: u32,
    shift: u64,
) -> Result<bool, Hx512Error> {
    if shift == 0 || shift >= HX512_GOLDILOCKS_MODULUS {
        return Ok(false);
    }
    let inverse = field_pow(shift, HX512_GOLDILOCKS_MODULUS - 2);
    for point in 1..interpolation_point_count {
        if field_pow(field_mul(u64::from(point), inverse), u64::from(domain_size)) == 1 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn derive_canonical_coset_shift(
    domain_size: u32,
    interpolation_point_count: u32,
) -> Result<u64, Hx512Error> {
    if interpolation_point_count == 0 || interpolation_point_count > domain_size {
        return Err(Hx512Error::ProfileInvariant(
            "disjoint-coset interpolation geometry",
        ));
    }
    let _ = derive_radix2_subgroup_generator(domain_size)?;
    let start = u64::from(interpolation_point_count);
    for offset in 0..HX512_COSET_SEARCH_LIMIT {
        let candidate = start
            .checked_add(u64::from(offset))
            .ok_or(Hx512Error::ProfileInvariant("coset search overflow"))?;
        if radix2_coset_is_disjoint(domain_size, interpolation_point_count, candidate)? {
            return Ok(candidate);
        }
    }
    Err(Hx512Error::ProfileInvariant("coset search exhausted"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512SamplerAccounting {
    pub kind: Hx512SamplerKind,
    pub requested: u32,
    pub accepted: u32,
    pub max_candidate_words: u32,
    pub xof_invocations: u32,
    pub candidates_examined: u64,
    pub modulus_bias_rejections: u64,
    pub duplicate_rejections: u64,
    pub sampler_aborts: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hx512Error {
    WireTooShort,
    WireTooLarge {
        actual: usize,
        maximum: usize,
    },
    WireDeclaredLength {
        declared: u64,
        actual: usize,
    },
    IdentityHeaderEmpty,
    IdentityHeaderTooLarge {
        actual: usize,
        maximum: usize,
    },
    IdentityHeaderMismatch,
    ProofCap {
        actual: usize,
        maximum: usize,
    },
    FrameLength(Hx512WireFrame),
    FrameLengthLimit {
        frame: Hx512WireFrame,
        declared: usize,
        maximum: usize,
    },
    ExternalStatementLength {
        expected: usize,
        actual: usize,
    },
    VerifierContextLength {
        expected: usize,
        actual: usize,
    },
    ProfileDescriptorLength {
        expected: usize,
        actual: usize,
    },
    ProfileInvariant(&'static str),
    ProfileScheduleDigestMismatch,
    EmptyInnerProof,
    TrailingBytes,
    HashMessageLimit {
        actual: usize,
        maximum: usize,
    },
    ScheduleViolation {
        expected: Hx512TranscriptStage,
        actual: Hx512TranscriptStage,
    },
    ScheduleOperation {
        stage: Hx512TranscriptStage,
        required: Hx512StageOperation,
        actual: Hx512StageOperation,
    },
    ScheduleComplete,
    ScheduleIncomplete(Hx512TranscriptStage),
    SchedulePoisoned(Hx512TranscriptStage),
    EmptyStageMessage(Hx512TranscriptStage),
    DeferredVerifierOrder {
        expected: Hx512DeferredVerifierState,
        actual: Hx512DeferredVerifierState,
    },
    DeferredClaimAlreadySet(Hx512TranscriptStage),
    DeferredClaimMismatch(Hx512TranscriptStage),
    DeferredRootMismatch,
    DeferredClaimsUnresolved(Hx512DeferredVerifierState),
    ChallengeCountZero(Hx512TranscriptStage),
    SaltMismatch,
    LeafTapeBytes {
        expected: usize,
        actual: usize,
    },
    LeafIndex(u32),
    LeafEvaluationLimit {
        actual: usize,
        maximum: usize,
    },
    NonCanonicalFieldWord {
        index: usize,
        value: u64,
    },
    FieldSampleLimit {
        requested: u64,
        maximum: u64,
    },
    IndexSampleLimit {
        requested: usize,
        maximum: usize,
    },
    IndexDomain(u32),
    SamplerBudgetOverflow,
    SamplerExhausted(Hx512SamplerAccounting),
    AllocationFailed(&'static str),
    OpaqueInnerProofRejected,
    GhcmAccounting(&'static str),
    ProductionAuthorizationUnavailable,
}

impl std::fmt::Display for Hx512Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Hx512Error {}

/// Release-owned wire inputs.  Constructing this value does not allocate an
/// identity; it only tells the inactive codec which exact external header and
/// proof cap to enforce for this call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512WireParameters<'a> {
    identity_header: &'a [u8],
    max_inner_proof_bytes: usize,
}

impl<'a> Hx512WireParameters<'a> {
    pub fn new(
        identity_header: &'a [u8],
        max_inner_proof_bytes: usize,
    ) -> Result<Self, Hx512Error> {
        if identity_header.is_empty() {
            return Err(Hx512Error::IdentityHeaderEmpty);
        }
        if identity_header.len() > HX512_ABSOLUTE_MAX_IDENTITY_HEADER_BYTES {
            return Err(Hx512Error::IdentityHeaderTooLarge {
                actual: identity_header.len(),
                maximum: HX512_ABSOLUTE_MAX_IDENTITY_HEADER_BYTES,
            });
        }
        if max_inner_proof_bytes == 0
            || max_inner_proof_bytes > HX512_ABSOLUTE_MAX_INNER_PROOF_BYTES
        {
            return Err(Hx512Error::ProofCap {
                actual: max_inner_proof_bytes,
                maximum: HX512_ABSOLUTE_MAX_INNER_PROOF_BYTES,
            });
        }
        wire_length(
            identity_header.len(),
            max_inner_proof_bytes,
            max_inner_proof_bytes,
        )?;
        Ok(Self {
            identity_header,
            max_inner_proof_bytes,
        })
    }

    pub const fn identity_header(&self) -> &'a [u8] {
        self.identity_header
    }

    pub const fn max_inner_proof_bytes(&self) -> usize {
        self.max_inner_proof_bytes
    }

    pub fn wire_overhead_bytes(&self) -> usize {
        HX512_WIRE_BASE_OVERHEAD_BYTES + self.identity_header.len()
    }

    /// Exact wire equation: `80 + caller_identity_header_bytes + inner_proof_bytes`.
    pub fn wire_bytes_for_inner_proof(
        &self,
        inner_proof_bytes: usize,
    ) -> Result<usize, Hx512Error> {
        wire_length(
            self.identity_header.len(),
            inner_proof_bytes,
            self.max_inner_proof_bytes,
        )
    }

    pub fn max_wire_bytes(&self) -> usize {
        self.wire_overhead_bytes() + self.max_inner_proof_bytes
    }
}

/// A fully checked, allocation-free view of one HX512 proof wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512ProofWireView<'a> {
    canonical_bytes: &'a [u8],
    identity_header: &'a [u8],
    max_inner_proof_bytes: usize,
    pub salt: &'a [u8; HX512_SALT_BYTES],
    pub inner_proof: &'a [u8],
}

impl<'a> Hx512ProofWireView<'a> {
    pub const fn canonical_bytes(&self) -> &'a [u8] {
        self.canonical_bytes
    }

    pub const fn identity_header(&self) -> &'a [u8] {
        self.identity_header
    }

    pub const fn max_inner_proof_bytes(&self) -> usize {
        self.max_inner_proof_bytes
    }

    pub fn try_to_owned(self) -> Result<Hx512ProofWire, Hx512Error> {
        Ok(Hx512ProofWire {
            salt: *self.salt,
            inner_proof: try_copy_bytes(self.inner_proof, "owned inner proof")?,
        })
    }
}

/// Owned canonical outer wire.  The inner proof remains opaque until the
/// final relation-owned parser exists; that missing parser is a production
/// blocker rather than an implied acceptance path.
#[derive(Debug, PartialEq, Eq)]
pub struct Hx512ProofWire {
    salt: [u8; HX512_SALT_BYTES],
    inner_proof: Vec<u8>,
}

/// No implementation is supplied here.  The outer codec yields opaque bytes;
/// a selected relation/verifier must implement this hook and separately prove
/// parser and acceptance refinement before the result can carry authority.
pub trait Hx512InnerProofVerificationHook {
    fn verify_opaque_inner_proof(
        &self,
        external_statement: &[u8],
        verifier_context: &Hx512VerifierContextBinding,
        geometry: Hx512TranscriptGeometry,
        statement_binding_digest: &[u8; HX512_DIGEST_BYTES],
        opaque_inner_proof: &[u8],
    ) -> Result<(), Hx512Error>;
}

impl Hx512ProofWire {
    pub fn from_exact_parts(
        parameters: Hx512WireParameters<'_>,
        salt: [u8; HX512_SALT_BYTES],
        inner_proof: &[u8],
    ) -> Result<Self, Hx512Error> {
        validate_proof_length(parameters, inner_proof.len())?;
        Ok(Self {
            salt,
            inner_proof: try_copy_bytes(inner_proof, "inner proof constructor")?,
        })
    }

    pub fn try_clone(&self) -> Result<Self, Hx512Error> {
        Ok(Self {
            salt: self.salt,
            inner_proof: try_copy_bytes(&self.inner_proof, "inner proof clone")?,
        })
    }

    pub fn decode_exact(
        bytes: &[u8],
        parameters: Hx512WireParameters<'_>,
    ) -> Result<Self, Hx512Error> {
        decode_hx512_wire_view_exact(bytes, parameters)?.try_to_owned()
    }

    /// Consume a validated outer frame and reuse its allocation for the inner
    /// proof.  This is the preferred owned transport path after the outer
    /// framer has enforced its receive cap.
    pub fn decode_owned_exact(
        mut bytes: Vec<u8>,
        parameters: Hx512WireParameters<'_>,
    ) -> Result<Self, Hx512Error> {
        let view = decode_hx512_wire_view_exact(&bytes, parameters)?;
        let salt = *view.salt;
        let proof_len = view.inner_proof.len();
        let proof_offset = bytes
            .len()
            .checked_sub(proof_len)
            .ok_or(Hx512Error::WireTooShort)?;
        drop(bytes.drain(..proof_offset));
        debug_assert_eq!(bytes.len(), proof_len);
        Ok(Self {
            salt,
            inner_proof: bytes,
        })
    }

    pub fn encode(&self, parameters: Hx512WireParameters<'_>) -> Result<Vec<u8>, Hx512Error> {
        let total = parameters.wire_bytes_for_inner_proof(self.inner_proof.len())?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(total)
            .map_err(|_| Hx512Error::AllocationFailed("encoded proof wire"))?;
        output.extend_from_slice(&(total as u64).to_be_bytes());
        append_u16_framed(&mut output, parameters.identity_header);
        output.extend_from_slice(&(HX512_SALT_BYTES as u16).to_be_bytes());
        output.extend_from_slice(&self.salt);
        output.extend_from_slice(&(self.inner_proof.len() as u32).to_be_bytes());
        output.extend_from_slice(&self.inner_proof);
        debug_assert_eq!(output.len(), total);
        Ok(output)
    }

    pub fn transcript(
        &self,
        parameters: Hx512WireParameters<'_>,
        external_statement: &[u8],
        verifier_context: &Hx512VerifierContextBinding,
        geometry: Hx512TranscriptGeometry,
    ) -> Result<Hx512Transcript, Hx512Error> {
        Hx512Transcript::new(
            parameters,
            external_statement,
            verifier_context,
            &self.salt,
            geometry,
        )
    }

    pub fn verify_inner_with(
        &self,
        parameters: Hx512WireParameters<'_>,
        external_statement: &[u8],
        verifier_context: &Hx512VerifierContextBinding,
        geometry: Hx512TranscriptGeometry,
        verifier: &impl Hx512InnerProofVerificationHook,
    ) -> Result<(), Hx512Error> {
        let transcript =
            self.transcript(parameters, external_statement, verifier_context, geometry)?;
        verifier.verify_opaque_inner_proof(
            external_statement,
            verifier_context,
            geometry,
            transcript.statement_binding_digest(),
            &self.inner_proof,
        )
    }

    pub const fn salt(&self) -> &[u8; HX512_SALT_BYTES] {
        &self.salt
    }

    pub fn inner_proof(&self) -> &[u8] {
        &self.inner_proof
    }
}

/// Validate the complete outer frame without allocating.  The total wire cap
/// and caller-owned proof cap are checked before any owned copy can occur.
pub fn decode_hx512_wire_view_exact<'a>(
    bytes: &'a [u8],
    parameters: Hx512WireParameters<'_>,
) -> Result<Hx512ProofWireView<'a>, Hx512Error> {
    if bytes.len() > parameters.max_wire_bytes() {
        return Err(Hx512Error::WireTooLarge {
            actual: bytes.len(),
            maximum: parameters.max_wire_bytes(),
        });
    }
    let minimum_wire_bytes =
        parameters
            .wire_overhead_bytes()
            .checked_add(1)
            .ok_or(Hx512Error::WireTooLarge {
                actual: usize::MAX,
                maximum: parameters.max_wire_bytes(),
            })?;
    if bytes.len() < minimum_wire_bytes {
        return Err(Hx512Error::WireTooShort);
    }

    let mut cursor = 0usize;
    let declared_total = take_u64(bytes, &mut cursor)?;
    if declared_total != bytes.len() as u64 {
        return Err(Hx512Error::WireDeclaredLength {
            declared: declared_total,
            actual: bytes.len(),
        });
    }

    let identity_length = take_u16(bytes, &mut cursor)? as usize;
    if identity_length != parameters.identity_header.len() {
        return Err(Hx512Error::FrameLength(Hx512WireFrame::IdentityHeader));
    }
    let identity_header = take(bytes, &mut cursor, identity_length)?;
    if identity_header != parameters.identity_header {
        return Err(Hx512Error::IdentityHeaderMismatch);
    }
    let salt_len = take_u16(bytes, &mut cursor)? as usize;
    if salt_len != HX512_SALT_BYTES {
        return Err(Hx512Error::FrameLength(Hx512WireFrame::Salt));
    }
    let salt: &[u8; HX512_SALT_BYTES] = take(bytes, &mut cursor, salt_len)?
        .try_into()
        .map_err(|_| Hx512Error::FrameLength(Hx512WireFrame::Salt))?;

    let proof_len = take_u32(bytes, &mut cursor)? as usize;
    if proof_len == 0 {
        return Err(Hx512Error::EmptyInnerProof);
    }
    if proof_len > parameters.max_inner_proof_bytes {
        return Err(Hx512Error::FrameLengthLimit {
            frame: Hx512WireFrame::InnerProof,
            declared: proof_len,
            maximum: parameters.max_inner_proof_bytes,
        });
    }
    let inner_proof = take(bytes, &mut cursor, proof_len)?;
    if cursor != bytes.len() {
        return Err(Hx512Error::TrailingBytes);
    }
    let expected = wire_length(
        parameters.identity_header.len(),
        proof_len,
        parameters.max_inner_proof_bytes,
    )?;
    if expected != bytes.len() {
        return Err(Hx512Error::WireDeclaredLength {
            declared: expected as u64,
            actual: bytes.len(),
        });
    }

    Ok(Hx512ProofWireView {
        canonical_bytes: bytes,
        identity_header,
        max_inner_proof_bytes: parameters.max_inner_proof_bytes,
        salt,
        inner_proof,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Hx512DeferredSha512Claim {
    stage: Hx512TranscriptStage,
    event_index: u64,
    statement_binding_digest: [u8; HX512_DIGEST_BYTES],
    prior_chain_digest: [u8; HX512_DIGEST_BYTES],
    claimed_output_digest: [u8; HX512_DIGEST_BYTES],
}

#[derive(Debug, PartialEq, Eq)]
pub struct Hx512Transcript {
    salt: [u8; HX512_SALT_BYTES],
    max_inner_proof_bytes: usize,
    geometry: Hx512TranscriptGeometry,
    statement_binding_digest: [u8; HX512_DIGEST_BYTES],
    chain_digest: [u8; HX512_DIGEST_BYTES],
    completed_events: u8,
    schedule_state: Hx512ScheduleState,
}

impl Hx512Transcript {
    pub fn new(
        parameters: Hx512WireParameters<'_>,
        external_statement: &[u8],
        verifier_context: &Hx512VerifierContextBinding,
        salt: &[u8; HX512_SALT_BYTES],
        geometry: Hx512TranscriptGeometry,
    ) -> Result<Self, Hx512Error> {
        if external_statement.len() != HX512_EXTERNAL_STATEMENT_BYTES {
            return Err(Hx512Error::ExternalStatementLength {
                expected: HX512_EXTERNAL_STATEMENT_BYTES,
                actual: external_statement.len(),
            });
        }
        validate_domain_registry()?;
        geometry.validate()?;
        let statement_binding_digest = statement_binding_digest(
            parameters.identity_header,
            parameters.max_inner_proof_bytes,
            external_statement,
            verifier_context,
            salt,
            geometry,
        );
        Ok(Self {
            salt: *salt,
            max_inner_proof_bytes: parameters.max_inner_proof_bytes,
            geometry,
            statement_binding_digest,
            chain_digest: statement_binding_digest,
            completed_events: 0,
            schedule_state: Hx512ScheduleState::Awaiting(HX512_TRANSCRIPT_SCHEDULE[0]),
        })
    }

    pub fn from_wire_view(
        external_statement: &[u8],
        verifier_context: &Hx512VerifierContextBinding,
        view: Hx512ProofWireView<'_>,
        geometry: Hx512TranscriptGeometry,
    ) -> Result<Self, Hx512Error> {
        let parameters =
            Hx512WireParameters::new(view.identity_header, view.max_inner_proof_bytes)?;
        Self::new(
            parameters,
            external_statement,
            verifier_context,
            view.salt,
            geometry,
        )
    }

    pub const fn geometry(&self) -> Hx512TranscriptGeometry {
        self.geometry
    }

    pub const fn statement_binding_digest(&self) -> &[u8; HX512_DIGEST_BYTES] {
        &self.statement_binding_digest
    }

    pub const fn chain_digest(&self) -> &[u8; HX512_DIGEST_BYTES] {
        &self.chain_digest
    }

    pub const fn event_count(&self) -> u64 {
        self.completed_events as u64
    }

    pub const fn schedule_state(&self) -> Hx512ScheduleState {
        self.schedule_state
    }

    /// Return the terminal eight-event chain without issuing a ninth oracle
    /// request.  Consuming `self` prevents accidental post-finalization reuse.
    pub fn finish(self) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        match self.schedule_state {
            Hx512ScheduleState::Complete => Ok(self.chain_digest),
            Hx512ScheduleState::Awaiting(stage) => Err(Hx512Error::ScheduleIncomplete(stage)),
            Hx512ScheduleState::Poisoned(stage) => Err(Hx512Error::SchedulePoisoned(stage)),
        }
    }

    pub fn absorb_piop_input(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        self.absorb_exact_stage(Hx512TranscriptStage::PiopInputBinding, message)
    }

    pub fn absorb_piop_transcript(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        self.absorb_exact_stage(Hx512TranscriptStage::PiopTranscriptBinding, message)
    }

    pub fn absorb_decs_opening(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        self.absorb_exact_stage(Hx512TranscriptStage::DecsOpeningBinding, message)
    }

    pub fn sample_decs_coefficients(&mut self) -> Result<Hx512FieldSamples, Hx512Error> {
        self.sample_field_stage(
            Hx512TranscriptStage::DecsCoefficientChallenge,
            self.geometry.decs_coefficient_count()?,
        )
    }

    pub fn sample_piop_coefficients(&mut self) -> Result<Hx512FieldSamples, Hx512Error> {
        self.sample_field_stage(
            Hx512TranscriptStage::PiopCoefficientChallenge,
            self.geometry.piop_coefficient_count()?,
        )
    }

    pub fn sample_piop_openings(&mut self) -> Result<Hx512FieldSamples, Hx512Error> {
        self.sample_field_stage(
            Hx512TranscriptStage::PiopOpeningChallenge,
            self.geometry.piop_opening_count(),
        )
    }

    /// Sample the caller-bound number of canonical sorted distinct indexes
    /// from the fixed 2^20 candidate tree.  The stage can be consumed once.
    pub fn sample_decs_queries(&mut self) -> Result<Hx512IndexSamples, Hx512Error> {
        self.sample_index_stage(
            Hx512TranscriptStage::DecsQueryChallenge,
            self.geometry.decs_opened_leaf_count(),
            self.geometry.decs_leaf_count(),
        )
    }

    fn absorb_exact_stage(
        &mut self,
        stage: Hx512TranscriptStage,
        message: &[u8],
    ) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        self.ensure_stage(stage, Hx512StageOperation::AbsorbMessage)?;
        if message.is_empty() {
            return Err(Hx512Error::EmptyStageMessage(stage));
        }
        validate_hash_message_length(message.len(), self.max_inner_proof_bytes)?;
        let digest =
            self.scheduled_sha512_request(stage, Hx512RequestKind::StageAbsorb, &[], message);
        self.advance_stage(stage, digest)?;
        Ok(digest)
    }

    fn accept_deferred_sha512_claim(
        &mut self,
        stage: Hx512TranscriptStage,
        claimed_output_digest: [u8; HX512_DIGEST_BYTES],
    ) -> Result<Hx512DeferredSha512Claim, Hx512Error> {
        if !matches!(
            stage,
            Hx512TranscriptStage::PiopInputBinding | Hx512TranscriptStage::PiopTranscriptBinding
        ) {
            return Err(Hx512Error::ProfileInvariant(
                "only event-2/event-4 SHA-512 outputs may be deferred",
            ));
        }
        self.ensure_stage(stage, Hx512StageOperation::AbsorbMessage)?;
        let claim = Hx512DeferredSha512Claim {
            stage,
            event_index: self.completed_events as u64,
            statement_binding_digest: self.statement_binding_digest,
            prior_chain_digest: self.chain_digest,
            claimed_output_digest,
        };
        self.advance_stage(stage, claimed_output_digest)?;
        Ok(claim)
    }

    fn sample_field_stage(
        &mut self,
        stage: Hx512TranscriptStage,
        count: usize,
    ) -> Result<Hx512FieldSamples, Hx512Error> {
        self.ensure_stage(stage, Hx512StageOperation::FieldXof)?;
        validate_geometry_field_count(stage, count)?;
        let max_candidate_words = count
            .checked_add(HX512_FIELD_SAMPLER_EXTRA_CANDIDATES)
            .ok_or(Hx512Error::SamplerBudgetOverflow)?;
        let descriptor = sampler_descriptor(stage, count, HX512_GOLDILOCKS_MODULUS)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| Hx512Error::AllocationFailed("field sampler output"))?;
        let mut accounting = Hx512SamplerAccounting {
            kind: Hx512SamplerKind::GoldilocksField,
            requested: count as u32,
            accepted: 0,
            max_candidate_words: max_candidate_words as u32,
            xof_invocations: 0,
            candidates_examined: 0,
            modulus_bias_rejections: 0,
            duplicate_rejections: 0,
            sampler_aborts: 0,
        };

        self.begin_challenge(stage)?;
        let mut reader = self.shake256_reader(stage, Hx512RequestKind::FieldXof, &descriptor);
        accounting.xof_invocations = 1;
        for _ in 0..max_candidate_words {
            let mut word = [0u8; 8];
            reader.read(&mut word);
            let candidate = u64::from_be_bytes(word);
            accounting.candidates_examined += 1;
            if candidate >= HX512_GOLDILOCKS_MODULUS {
                accounting.modulus_bias_rejections += 1;
                continue;
            }
            values.push(candidate);
            accounting.accepted += 1;
            if values.len() == count {
                let mut next_chain = [0u8; HX512_DIGEST_BYTES];
                reader.read(&mut next_chain);
                self.complete_challenge(stage, next_chain)?;
                return Ok(Hx512FieldSamples { values, accounting });
            }
        }
        accounting.sampler_aborts = 1;
        Err(Hx512Error::SamplerExhausted(accounting))
    }

    fn sample_index_stage(
        &mut self,
        stage: Hx512TranscriptStage,
        count: usize,
        domain_size: u32,
    ) -> Result<Hx512IndexSamples, Hx512Error> {
        self.ensure_stage(stage, Hx512StageOperation::IndexXof)?;
        if count == 0 {
            return Err(Hx512Error::ChallengeCountZero(stage));
        }
        if count > HX512_MAX_INDEX_SAMPLES {
            return Err(Hx512Error::IndexSampleLimit {
                requested: count,
                maximum: HX512_MAX_INDEX_SAMPLES,
            });
        }
        if domain_size == 0
            || domain_size > HX512_MAX_INDEX_DOMAIN_SIZE
            || count > domain_size as usize
        {
            return Err(Hx512Error::IndexDomain(domain_size));
        }
        let max_candidate_words = count
            .checked_add(HX512_INDEX_SAMPLER_EXTRA_CANDIDATES)
            .ok_or(Hx512Error::SamplerBudgetOverflow)?;
        let descriptor = sampler_descriptor(stage, count, u64::from(domain_size))?;
        let mut seen = Vec::new();
        seen.try_reserve_exact(count)
            .map_err(|_| Hx512Error::AllocationFailed("index sampler output"))?;
        let mut accounting = Hx512SamplerAccounting {
            kind: Hx512SamplerKind::DistinctIndex,
            requested: count as u32,
            accepted: 0,
            max_candidate_words: max_candidate_words as u32,
            xof_invocations: 0,
            candidates_examined: 0,
            modulus_bias_rejections: 0,
            duplicate_rejections: 0,
            sampler_aborts: 0,
        };

        self.begin_challenge(stage)?;
        let mut reader = self.shake256_reader(stage, Hx512RequestKind::IndexXof, &descriptor);
        accounting.xof_invocations = 1;
        let domain = u128::from(domain_size);
        let acceptance_ceiling = ((u128::from(u64::MAX) + 1) / domain) * domain;
        for _ in 0..max_candidate_words {
            let mut word = [0u8; 8];
            reader.read(&mut word);
            let candidate = u64::from_be_bytes(word);
            accounting.candidates_examined += 1;
            if u128::from(candidate) >= acceptance_ceiling {
                accounting.modulus_bias_rejections += 1;
                continue;
            }
            let index = (u128::from(candidate) % domain) as u32;
            if seen.contains(&index) {
                accounting.duplicate_rejections += 1;
                continue;
            }
            seen.push(index);
            accounting.accepted += 1;
            if seen.len() == count {
                seen.sort_unstable();
                let mut next_chain = [0u8; HX512_DIGEST_BYTES];
                reader.read(&mut next_chain);
                self.complete_challenge(stage, next_chain)?;
                return Ok(Hx512IndexSamples {
                    indexes: seen,
                    accounting,
                });
            }
        }
        accounting.sampler_aborts = 1;
        Err(Hx512Error::SamplerExhausted(accounting))
    }

    /// Hash one DECS leaf.  The tape is an independent profile-width proof value;
    /// this API deliberately has no function that derives it from the global
    /// salt or transcript.
    pub fn hash_leaf<const TAPE_BYTES: usize>(
        &self,
        salt: &[u8; HX512_SALT_BYTES],
        leaf_index: u32,
        independent_tape: &[u8; TAPE_BYTES],
        committed_evaluations: &[u64],
        masking_evaluations: &[u64],
    ) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        if salt != &self.salt {
            return Err(Hx512Error::SaltMismatch);
        }
        if TAPE_BYTES != HX512_PROFILE_LEAF_TAPE_BYTES {
            return Err(Hx512Error::LeafTapeBytes {
                expected: HX512_PROFILE_LEAF_TAPE_BYTES,
                actual: TAPE_BYTES,
            });
        }
        if leaf_index >= self.geometry.decs_leaf_count() {
            return Err(Hx512Error::LeafIndex(leaf_index));
        }
        if committed_evaluations.len() > HX512_MAX_LEAF_EVALUATIONS_PER_FAMILY {
            return Err(Hx512Error::LeafEvaluationLimit {
                actual: committed_evaluations.len(),
                maximum: HX512_MAX_LEAF_EVALUATIONS_PER_FAMILY,
            });
        }
        if masking_evaluations.len() > HX512_MAX_LEAF_EVALUATIONS_PER_FAMILY {
            return Err(Hx512Error::LeafEvaluationLimit {
                actual: masking_evaluations.len(),
                maximum: HX512_MAX_LEAF_EVALUATIONS_PER_FAMILY,
            });
        }
        validate_field_words(committed_evaluations)?;
        validate_field_words(masking_evaluations)?;
        let committed_bytes = committed_evaluations
            .len()
            .checked_mul(8)
            .ok_or(Hx512Error::AllocationFailed("leaf hash payload length"))?;
        let masking_bytes = masking_evaluations
            .len()
            .checked_mul(8)
            .ok_or(Hx512Error::AllocationFailed("leaf hash payload length"))?;
        let payload_bytes = 2usize
            .checked_add(HX512_SALT_BYTES)
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(2))
            .and_then(|value| value.checked_add(TAPE_BYTES))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(committed_bytes))
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(masking_bytes))
            .ok_or(Hx512Error::AllocationFailed("leaf hash payload length"))?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_bytes)
            .map_err(|_| Hx512Error::AllocationFailed("leaf hash payload"))?;
        append_u16_bytes(&mut payload, salt);
        payload.extend_from_slice(&leaf_index.to_be_bytes());
        append_u16_bytes(&mut payload, independent_tape);
        append_field_words(&mut payload, committed_evaluations);
        append_field_words(&mut payload, masking_evaluations);
        Ok(self.history_sha512_request(
            Hx512Role::MerkleLeaf,
            Hx512RequestKind::LeafCommitment,
            &[],
            &payload,
        ))
    }

    pub fn hash_opened_leaf_tape<const TAPE_BYTES: usize>(
        &self,
        leaf_index: u32,
        independent_tape: &[u8; TAPE_BYTES],
    ) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        if TAPE_BYTES != HX512_PROFILE_LEAF_TAPE_BYTES {
            return Err(Hx512Error::LeafTapeBytes {
                expected: HX512_PROFILE_LEAF_TAPE_BYTES,
                actual: TAPE_BYTES,
            });
        }
        if leaf_index >= self.geometry.decs_leaf_count() {
            return Err(Hx512Error::LeafIndex(leaf_index));
        }
        let mut payload = [0u8; 4 + 2 + HX512_PROFILE_LEAF_TAPE_BYTES];
        payload[..4].copy_from_slice(&leaf_index.to_be_bytes());
        payload[4..6].copy_from_slice(&(HX512_PROFILE_LEAF_TAPE_BYTES as u16).to_be_bytes());
        payload[6..].copy_from_slice(independent_tape);
        Ok(self.history_sha512_request(
            Hx512Role::OpenedLeafTape,
            Hx512RequestKind::OpenedLeafTape,
            &[],
            &payload,
        ))
    }

    pub fn hash_merkle_node(
        &self,
        level: u8,
        node_index: u32,
        left: &[u8; HX512_DIGEST_BYTES],
        right: &[u8; HX512_DIGEST_BYTES],
    ) -> [u8; HX512_DIGEST_BYTES] {
        let mut payload = [0u8; 1 + 4 + 2 + HX512_DIGEST_BYTES + 2 + HX512_DIGEST_BYTES];
        payload[0] = level;
        payload[1..5].copy_from_slice(&node_index.to_be_bytes());
        payload[5..7].copy_from_slice(&(HX512_DIGEST_BYTES as u16).to_be_bytes());
        payload[7..7 + HX512_DIGEST_BYTES].copy_from_slice(left);
        let right_length_offset = 7 + HX512_DIGEST_BYTES;
        payload[right_length_offset..right_length_offset + 2]
            .copy_from_slice(&(HX512_DIGEST_BYTES as u16).to_be_bytes());
        payload[right_length_offset + 2..].copy_from_slice(right);
        self.history_sha512_request(
            Hx512Role::MerkleNode,
            Hx512RequestKind::MerkleNode,
            &[],
            &payload,
        )
    }

    pub fn hash_merkle_root(
        &mut self,
        leaf_count: u32,
        root: &[u8; HX512_DIGEST_BYTES],
    ) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        if leaf_count != self.geometry.decs_leaf_count() {
            return Err(Hx512Error::IndexDomain(leaf_count));
        }
        let stage = Hx512TranscriptStage::DecsRootBinding;
        self.ensure_stage(stage, Hx512StageOperation::MerkleRoot)?;
        let mut payload = [0u8; 4 + 2 + HX512_SALT_BYTES + 2 + HX512_DIGEST_BYTES];
        payload[..4].copy_from_slice(&leaf_count.to_be_bytes());
        payload[4..6].copy_from_slice(&(HX512_SALT_BYTES as u16).to_be_bytes());
        payload[6..6 + HX512_SALT_BYTES].copy_from_slice(&self.salt);
        let root_length_offset = 6 + HX512_SALT_BYTES;
        payload[root_length_offset..root_length_offset + 2]
            .copy_from_slice(&(HX512_DIGEST_BYTES as u16).to_be_bytes());
        payload[root_length_offset + 2..].copy_from_slice(root);
        let digest =
            self.scheduled_sha512_request(stage, Hx512RequestKind::MerkleRoot, &[], &payload);
        self.advance_stage(stage, digest)?;
        Ok(digest)
    }

    fn ensure_stage(
        &self,
        actual_stage: Hx512TranscriptStage,
        actual_operation: Hx512StageOperation,
    ) -> Result<(), Hx512Error> {
        let expected_stage = match self.schedule_state {
            Hx512ScheduleState::Awaiting(stage) => stage,
            Hx512ScheduleState::Complete => return Err(Hx512Error::ScheduleComplete),
            Hx512ScheduleState::Poisoned(stage) => return Err(Hx512Error::SchedulePoisoned(stage)),
        };
        if expected_stage != actual_stage {
            return Err(Hx512Error::ScheduleViolation {
                expected: expected_stage,
                actual: actual_stage,
            });
        }
        let required_operation = expected_stage.operation();
        if required_operation != actual_operation {
            return Err(Hx512Error::ScheduleOperation {
                stage: expected_stage,
                required: required_operation,
                actual: actual_operation,
            });
        }
        Ok(())
    }

    fn begin_challenge(&mut self, stage: Hx512TranscriptStage) -> Result<(), Hx512Error> {
        self.ensure_stage(stage, stage.operation())?;
        self.schedule_state = Hx512ScheduleState::Poisoned(stage);
        Ok(())
    }

    fn advance_stage(
        &mut self,
        stage: Hx512TranscriptStage,
        next_chain: [u8; HX512_DIGEST_BYTES],
    ) -> Result<(), Hx512Error> {
        self.ensure_stage(stage, stage.operation())?;
        self.chain_digest = next_chain;
        self.completed_events = self
            .completed_events
            .checked_add(1)
            .ok_or(Hx512Error::ScheduleComplete)?;
        self.schedule_state = next_schedule_state(self.completed_events);
        Ok(())
    }

    fn complete_challenge(
        &mut self,
        stage: Hx512TranscriptStage,
        next_chain: [u8; HX512_DIGEST_BYTES],
    ) -> Result<(), Hx512Error> {
        if self.schedule_state != Hx512ScheduleState::Poisoned(stage) {
            return match self.schedule_state {
                Hx512ScheduleState::Awaiting(expected) => Err(Hx512Error::ScheduleViolation {
                    expected,
                    actual: stage,
                }),
                Hx512ScheduleState::Complete => Err(Hx512Error::ScheduleComplete),
                Hx512ScheduleState::Poisoned(poisoned) => {
                    Err(Hx512Error::SchedulePoisoned(poisoned))
                }
            };
        }
        self.chain_digest = next_chain;
        self.completed_events = self
            .completed_events
            .checked_add(1)
            .ok_or(Hx512Error::ScheduleComplete)?;
        self.schedule_state = next_schedule_state(self.completed_events);
        Ok(())
    }

    fn scheduled_sha512_request(
        &self,
        stage: Hx512TranscriptStage,
        request_kind: Hx512RequestKind,
        descriptor: &[u8],
        message: &[u8],
    ) -> [u8; HX512_DIGEST_BYTES] {
        hash_request_with_domains(
            HX512_REQUEST_FRAME_DOMAIN,
            stage.role().domain(),
            &self.statement_binding_digest,
            request_kind,
            self.completed_events as u64,
            &self.chain_digest,
            descriptor,
            message,
            0,
        )
    }

    fn history_sha512_request(
        &self,
        role: Hx512Role,
        request_kind: Hx512RequestKind,
        descriptor: &[u8],
        message: &[u8],
    ) -> [u8; HX512_DIGEST_BYTES] {
        hash_request_with_domains(
            HX512_REQUEST_FRAME_DOMAIN,
            role.domain(),
            &self.statement_binding_digest,
            request_kind,
            0,
            &self.statement_binding_digest,
            descriptor,
            message,
            0,
        )
    }

    fn shake256_reader(
        &self,
        stage: Hx512TranscriptStage,
        request_kind: Hx512RequestKind,
        descriptor: &[u8],
    ) -> sha3::Shake256Reader {
        shake256_request_reader_with_domains(
            HX512_XOF_FRAME_DOMAIN,
            stage.role().domain(),
            &self.statement_binding_digest,
            request_kind,
            self.completed_events as u64,
            &self.chain_digest,
            descriptor,
        )
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hx512RequestKind {
    StageAbsorb = 0,
    FieldXof = 1,
    IndexXof = 2,
    LeafCommitment = 3,
    OpenedLeafTape = 4,
    MerkleNode = 5,
    MerkleRoot = 6,
}

/// Verifier-only driver for the legacy dependency graph without weakening the
/// logical eight-event schedule.  The fresh proof supplies exactly
/// `raw_root || h3 || h5`: event 0 hashes `raw_root` normally, while `h3` and
/// `h5` provisionally advance events 2 and 4.  Their immutable request
/// snapshots are recomputed after event 7 from the exact reconstructed
/// messages.  No claim can reach `finish` unresolved or after a mismatch.
pub struct Hx512DeferredVerifierTranscript {
    transcript: Hx512Transcript,
    claimed_root: Option<[u8; HX512_DIGEST_BYTES]>,
    piop_input_claim: Option<Hx512DeferredSha512Claim>,
    piop_transcript_claim: Option<Hx512DeferredSha512Claim>,
    verification_state: Hx512DeferredVerifierState,
}

impl Hx512DeferredVerifierTranscript {
    pub fn new(
        parameters: Hx512WireParameters<'_>,
        external_statement: &[u8],
        verifier_context: &Hx512VerifierContextBinding,
        salt: &[u8; HX512_SALT_BYTES],
        geometry: Hx512TranscriptGeometry,
    ) -> Result<Self, Hx512Error> {
        Ok(Self {
            transcript: Hx512Transcript::new(
                parameters,
                external_statement,
                verifier_context,
                salt,
                geometry,
            )?,
            claimed_root: None,
            piop_input_claim: None,
            piop_transcript_claim: None,
            verification_state: Hx512DeferredVerifierState::DrivingSchedule,
        })
    }

    pub fn from_wire_view(
        external_statement: &[u8],
        verifier_context: &Hx512VerifierContextBinding,
        view: Hx512ProofWireView<'_>,
        geometry: Hx512TranscriptGeometry,
    ) -> Result<Self, Hx512Error> {
        let parameters =
            Hx512WireParameters::new(view.identity_header, view.max_inner_proof_bytes)?;
        Self::new(
            parameters,
            external_statement,
            verifier_context,
            view.salt,
            geometry,
        )
    }

    pub const fn verification_state(&self) -> Hx512DeferredVerifierState {
        self.verification_state
    }

    pub const fn event_count(&self) -> u64 {
        self.transcript.event_count()
    }

    /// Chain-independent history hashing forwards to the sole statement-bound
    /// transcript object.  These calls do not consume or reorder any of the
    /// eight logical FS events and are used to reconstruct the claimed root
    /// after event 7.
    pub fn hash_leaf<const TAPE_BYTES: usize>(
        &self,
        salt: &[u8; HX512_SALT_BYTES],
        leaf_index: u32,
        independent_tape: &[u8; TAPE_BYTES],
        committed_evaluations: &[u64],
        masking_evaluations: &[u64],
    ) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        self.transcript.hash_leaf(
            salt,
            leaf_index,
            independent_tape,
            committed_evaluations,
            masking_evaluations,
        )
    }

    pub fn hash_opened_leaf_tape<const TAPE_BYTES: usize>(
        &self,
        leaf_index: u32,
        independent_tape: &[u8; TAPE_BYTES],
    ) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        self.transcript
            .hash_opened_leaf_tape(leaf_index, independent_tape)
    }

    pub fn hash_merkle_node(
        &self,
        level: u8,
        node_index: u32,
        left: &[u8; HX512_DIGEST_BYTES],
        right: &[u8; HX512_DIGEST_BYTES],
    ) -> [u8; HX512_DIGEST_BYTES] {
        self.transcript
            .hash_merkle_node(level, node_index, left, right)
    }

    pub fn bind_claimed_decs_root(
        &mut self,
        leaf_count: u32,
        claimed_raw_root: &[u8; HX512_DIGEST_BYTES],
    ) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        self.ensure_driving()?;
        if self.claimed_root.is_some() {
            return Err(Hx512Error::DeferredClaimAlreadySet(
                Hx512TranscriptStage::DecsRootBinding,
            ));
        }
        let digest = self
            .transcript
            .hash_merkle_root(leaf_count, claimed_raw_root)?;
        self.claimed_root = Some(*claimed_raw_root);
        Ok(digest)
    }

    pub fn sample_decs_coefficients(&mut self) -> Result<Hx512FieldSamples, Hx512Error> {
        self.ensure_driving()?;
        self.transcript.sample_decs_coefficients()
    }

    pub fn claim_piop_input_digest(
        &mut self,
        claimed_h3: [u8; HX512_DIGEST_BYTES],
    ) -> Result<(), Hx512Error> {
        self.ensure_driving()?;
        if self.piop_input_claim.is_some() {
            return Err(Hx512Error::DeferredClaimAlreadySet(
                Hx512TranscriptStage::PiopInputBinding,
            ));
        }
        self.piop_input_claim = Some(
            self.transcript
                .accept_deferred_sha512_claim(Hx512TranscriptStage::PiopInputBinding, claimed_h3)?,
        );
        Ok(())
    }

    pub fn sample_piop_coefficients(&mut self) -> Result<Hx512FieldSamples, Hx512Error> {
        self.ensure_driving()?;
        self.transcript.sample_piop_coefficients()
    }

    pub fn claim_piop_transcript_digest(
        &mut self,
        claimed_h5: [u8; HX512_DIGEST_BYTES],
    ) -> Result<(), Hx512Error> {
        self.ensure_driving()?;
        if self.piop_transcript_claim.is_some() {
            return Err(Hx512Error::DeferredClaimAlreadySet(
                Hx512TranscriptStage::PiopTranscriptBinding,
            ));
        }
        self.piop_transcript_claim = Some(self.transcript.accept_deferred_sha512_claim(
            Hx512TranscriptStage::PiopTranscriptBinding,
            claimed_h5,
        )?);
        Ok(())
    }

    pub fn sample_piop_openings(&mut self) -> Result<Hx512FieldSamples, Hx512Error> {
        self.ensure_driving()?;
        self.transcript.sample_piop_openings()
    }

    pub fn absorb_decs_opening(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        self.ensure_driving()?;
        self.transcript.absorb_decs_opening(message)
    }

    pub fn sample_decs_queries(&mut self) -> Result<Hx512IndexSamples, Hx512Error> {
        self.ensure_driving()?;
        let result = self.transcript.sample_decs_queries()?;
        if self.claimed_root.is_none()
            || self.piop_input_claim.is_none()
            || self.piop_transcript_claim.is_none()
        {
            self.verification_state =
                Hx512DeferredVerifierState::Poisoned(Hx512TranscriptStage::DecsQueryChallenge);
            return Err(Hx512Error::DeferredClaimsUnresolved(
                self.verification_state,
            ));
        }
        self.verification_state = Hx512DeferredVerifierState::AwaitingReconstructedRoot;
        Ok(result)
    }

    pub fn verify_reconstructed_root(
        &mut self,
        reconstructed_root: &[u8; HX512_DIGEST_BYTES],
    ) -> Result<(), Hx512Error> {
        self.ensure_verification_state(Hx512DeferredVerifierState::AwaitingReconstructedRoot)?;
        if self.claimed_root.as_ref() != Some(reconstructed_root) {
            self.verification_state =
                Hx512DeferredVerifierState::Poisoned(Hx512TranscriptStage::DecsRootBinding);
            return Err(Hx512Error::DeferredRootMismatch);
        }
        self.verification_state = Hx512DeferredVerifierState::AwaitingReconstructedPiopInput;
        Ok(())
    }

    pub fn verify_reconstructed_piop_input(
        &mut self,
        reconstructed_message: &[u8],
    ) -> Result<(), Hx512Error> {
        self.ensure_verification_state(Hx512DeferredVerifierState::AwaitingReconstructedPiopInput)?;
        self.verify_reconstructed_claim(
            Hx512TranscriptStage::PiopInputBinding,
            self.piop_input_claim,
            reconstructed_message,
        )?;
        self.verification_state = Hx512DeferredVerifierState::AwaitingReconstructedPiopTranscript;
        Ok(())
    }

    pub fn verify_reconstructed_piop_transcript(
        &mut self,
        reconstructed_message: &[u8],
    ) -> Result<(), Hx512Error> {
        self.ensure_verification_state(
            Hx512DeferredVerifierState::AwaitingReconstructedPiopTranscript,
        )?;
        self.verify_reconstructed_claim(
            Hx512TranscriptStage::PiopTranscriptBinding,
            self.piop_transcript_claim,
            reconstructed_message,
        )?;
        self.verification_state = Hx512DeferredVerifierState::ReadyToFinish;
        Ok(())
    }

    /// Consume the verifier transcript only after all three proof-carried
    /// values have been checked.  Deferred recomputation uses the original
    /// logical event snapshots and therefore adds no ninth transcript event.
    pub fn finish(self) -> Result<[u8; HX512_DIGEST_BYTES], Hx512Error> {
        if self.verification_state != Hx512DeferredVerifierState::ReadyToFinish {
            return Err(Hx512Error::DeferredClaimsUnresolved(
                self.verification_state,
            ));
        }
        self.transcript.finish()
    }

    fn ensure_driving(&self) -> Result<(), Hx512Error> {
        self.ensure_verification_state(Hx512DeferredVerifierState::DrivingSchedule)
    }

    fn ensure_verification_state(
        &self,
        expected: Hx512DeferredVerifierState,
    ) -> Result<(), Hx512Error> {
        if self.verification_state == expected {
            Ok(())
        } else {
            Err(Hx512Error::DeferredVerifierOrder {
                expected,
                actual: self.verification_state,
            })
        }
    }

    fn verify_reconstructed_claim(
        &mut self,
        expected_stage: Hx512TranscriptStage,
        claim: Option<Hx512DeferredSha512Claim>,
        reconstructed_message: &[u8],
    ) -> Result<(), Hx512Error> {
        if reconstructed_message.is_empty() {
            self.verification_state = Hx512DeferredVerifierState::Poisoned(expected_stage);
            return Err(Hx512Error::EmptyStageMessage(expected_stage));
        }
        if let Err(error) = validate_hash_message_length(
            reconstructed_message.len(),
            self.transcript.max_inner_proof_bytes,
        ) {
            self.verification_state = Hx512DeferredVerifierState::Poisoned(expected_stage);
            return Err(error);
        }
        let claim = match claim {
            Some(claim) => claim,
            None => {
                self.verification_state = Hx512DeferredVerifierState::Poisoned(expected_stage);
                return Err(Hx512Error::DeferredClaimsUnresolved(
                    self.verification_state,
                ));
            }
        };
        if claim.stage != expected_stage {
            self.verification_state = Hx512DeferredVerifierState::Poisoned(expected_stage);
            return Err(Hx512Error::DeferredClaimMismatch(expected_stage));
        }
        let recomputed = hash_request_with_domains(
            HX512_REQUEST_FRAME_DOMAIN,
            expected_stage.role().domain(),
            &claim.statement_binding_digest,
            Hx512RequestKind::StageAbsorb,
            claim.event_index,
            &claim.prior_chain_digest,
            &[],
            reconstructed_message,
            0,
        );
        if recomputed != claim.claimed_output_digest {
            self.verification_state = Hx512DeferredVerifierState::Poisoned(expected_stage);
            return Err(Hx512Error::DeferredClaimMismatch(expected_stage));
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Hx512FieldSamples {
    pub values: Vec<u64>,
    pub accounting: Hx512SamplerAccounting,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Hx512IndexSamples {
    pub indexes: Vec<u32>,
    pub accounting: Hx512SamplerAccounting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512GhcmAccounting {
    pub leaf_count: u32,
    pub opened_leaf_count: u32,
    pub leaf_tape_bytes: u16,
    pub opened_leaf_tape_payload_bytes: u64,
    pub leaf_conditional_min_entropy_bits: u16,
    pub chain_conditional_min_entropy_bits: u16,
    pub leaf_program_events_per_proof: u64,
    pub chain_program_events_per_proof: u32,
    pub proof_union_log2: u16,
    pub qrom_query_log2: u16,
    pub leaf_total_program_events_upper: u128,
    pub chain_total_program_events_upper: u128,
    pub leaf_term_numerator: u128,
    pub leaf_term_denominator_log2: u16,
    pub chain_term_numerator: u128,
    pub chain_term_denominator_log2: u16,
    pub combined_term_numerator: u128,
    pub combined_term_denominator_log2: u16,
    pub conditional_ideal_qro_security_bits_floor: u16,
    pub independent_uniform_tapes_verified: bool,
    pub leaf_conditional_min_entropy_verified: bool,
    pub fresh_chain_entropy_verified: bool,
    pub global_salt_reuse_excluded: bool,
    pub adaptive_program_schedule_verified: bool,
    pub concrete_sha512_qro_bridge_verified: bool,
    pub concrete_shake256_xof_bridge_verified: bool,
}

/// Compute the arithmetic inputs to the GHCM `3R/2 * sqrt(q * p_max)`
/// reprogramming term.  The two event classes are intentionally separate:
/// `2N` leaf/history events provisionally use 576-bit tapes, while exactly four
/// SHA-512 and four SHAKE256 chain events provisionally use a fresh conditional
/// 512-bit input digest.  One public global salt cannot provide that entropy
/// after its first use; the final protocol needs proved conditional digest
/// entropy or independent stage salts.  The returned bit count is explicitly
/// conditional and ideal-QRO-only, and every theorem/instantiation flag is
/// false.
pub fn hx512_opened_tape_payload_bytes(
    leaf_count: u32,
    opened_leaf_count: u32,
) -> Result<u64, Hx512Error> {
    if opened_leaf_count == 0 || opened_leaf_count > leaf_count {
        return Err(Hx512Error::GhcmAccounting(
            "opened-leaf count must be nonzero and no larger than the tree",
        ));
    }
    u64::from(opened_leaf_count)
        .checked_mul(HX512_PROFILE_LEAF_TAPE_BYTES as u64)
        .ok_or(Hx512Error::GhcmAccounting("opened-tape bytes overflow"))
}

pub fn hx512_ghcm_accounting(
    geometry: Hx512TranscriptGeometry,
    proof_union_log2: u16,
    qrom_query_log2: u16,
) -> Result<Hx512GhcmAccounting, Hx512Error> {
    const CHAIN_CONDITIONAL_ENTROPY_BITS: u16 = 512;
    geometry.validate()?;
    let leaf_count = geometry.decs_leaf_count();
    let opened_leaf_count = geometry.core.decs_query_count;
    let opened_leaf_tape_payload_bytes =
        hx512_opened_tape_payload_bytes(leaf_count, opened_leaf_count)?;
    if qrom_query_log2 >= CHAIN_CONDITIONAL_ENTROPY_BITS {
        return Err(Hx512Error::GhcmAccounting(
            "q * p_max must be strictly below one for every program class",
        ));
    }
    let proof_union =
        1u128
            .checked_shl(u32::from(proof_union_log2))
            .ok_or(Hx512Error::GhcmAccounting(
                "proof-union exponent does not fit the u128 ledger",
            ))?;
    let leaf_program_events_per_proof = u64::from(leaf_count)
        .checked_mul(2)
        .ok_or(Hx512Error::GhcmAccounting("leaf-event overflow"))?;
    let leaf_total_program_events_upper = u128::from(leaf_program_events_per_proof)
        .checked_mul(proof_union)
        .ok_or(Hx512Error::GhcmAccounting("leaf union-event overflow"))?;
    let chain_total_program_events_upper = u128::from(HX512_TRANSCRIPT_PROGRAM_EVENTS_PER_PROOF)
        .checked_mul(proof_union)
        .ok_or(Hx512Error::GhcmAccounting("chain union-event overflow"))?;

    let (leaf_term_numerator, leaf_term_denominator_log2) = ghcm_dyadic_term(
        leaf_total_program_events_upper,
        HX512_PROFILE_LEAF_TAPE_ENTROPY_BITS,
        qrom_query_log2,
    )?;
    let (chain_term_numerator, chain_term_denominator_log2) = ghcm_dyadic_term(
        chain_total_program_events_upper,
        CHAIN_CONDITIONAL_ENTROPY_BITS,
        qrom_query_log2,
    )?;
    let common_denominator_log2 = leaf_term_denominator_log2.max(chain_term_denominator_log2);
    let leaf_shift = common_denominator_log2 - leaf_term_denominator_log2;
    let chain_shift = common_denominator_log2 - chain_term_denominator_log2;
    let combined_term_numerator = leaf_term_numerator
        .checked_shl(u32::from(leaf_shift))
        .and_then(|leaf| {
            chain_term_numerator
                .checked_shl(u32::from(chain_shift))
                .and_then(|chain| leaf.checked_add(chain))
        })
        .ok_or(Hx512Error::GhcmAccounting("combined GHCM term overflow"))?;
    let combined_numerator_ceil_log2 = ceil_log2(combined_term_numerator)?;
    let conditional_security = common_denominator_log2.saturating_sub(combined_numerator_ceil_log2);
    Ok(Hx512GhcmAccounting {
        leaf_count,
        opened_leaf_count,
        leaf_tape_bytes: HX512_PROFILE_LEAF_TAPE_BYTES as u16,
        opened_leaf_tape_payload_bytes,
        leaf_conditional_min_entropy_bits: HX512_PROFILE_LEAF_TAPE_ENTROPY_BITS,
        chain_conditional_min_entropy_bits: CHAIN_CONDITIONAL_ENTROPY_BITS,
        leaf_program_events_per_proof,
        chain_program_events_per_proof: HX512_TRANSCRIPT_PROGRAM_EVENTS_PER_PROOF,
        proof_union_log2,
        qrom_query_log2,
        leaf_total_program_events_upper,
        chain_total_program_events_upper,
        leaf_term_numerator,
        leaf_term_denominator_log2,
        chain_term_numerator,
        chain_term_denominator_log2,
        combined_term_numerator,
        combined_term_denominator_log2: common_denominator_log2,
        conditional_ideal_qro_security_bits_floor: conditional_security,
        independent_uniform_tapes_verified: false,
        leaf_conditional_min_entropy_verified: false,
        fresh_chain_entropy_verified: false,
        global_salt_reuse_excluded: false,
        adaptive_program_schedule_verified: false,
        concrete_sha512_qro_bridge_verified: false,
        concrete_shake256_xof_bridge_verified: false,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512SecurityAuthorization {
    pub wire_identity_allocated: bool,
    pub role_domain_registry_manifest_bound: bool,
    pub outer_framer_cap_before_buffering_verified: bool,
    pub engine_transcript_schedule_refinement_verified: bool,
    pub full_relation_compiler_refinement_verified: bool,
    pub inner_proof_parser_refinement_verified: bool,
    pub rust_verifier_refinement_verified: bool,
    pub round_by_round_randomness_verified: bool,
    pub honest_verifier_zero_knowledge_verified: bool,
    pub complete_zero_knowledge_verified: bool,
    pub pcs_iop_soundness_verified: bool,
    pub adaptive_ghcm_schedule_verified: bool,
    pub concrete_sha512_qro_bridge_verified: bool,
    pub concrete_shake256_xof_bridge_verified: bool,
    pub composed_pq128_verified: bool,
    pub release_manifest_bound: bool,
}

pub const HX512_SECURITY_AUTHORIZATION: Hx512SecurityAuthorization = Hx512SecurityAuthorization {
    wire_identity_allocated: HX512_IDENTITY_ALLOCATED,
    role_domain_registry_manifest_bound: HX512_ROLE_DOMAIN_REGISTRY_MANIFEST_BOUND,
    outer_framer_cap_before_buffering_verified: HX512_OUTER_FRAMER_CAP_BEFORE_BUFFERING_VERIFIED,
    engine_transcript_schedule_refinement_verified:
        HX512_ENGINE_TRANSCRIPT_SCHEDULE_REFINEMENT_VERIFIED,
    full_relation_compiler_refinement_verified: false,
    inner_proof_parser_refinement_verified: HX512_INNER_PROOF_VERIFICATION_REFINEMENT_VERIFIED,
    rust_verifier_refinement_verified: false,
    round_by_round_randomness_verified: false,
    honest_verifier_zero_knowledge_verified: false,
    complete_zero_knowledge_verified: false,
    pcs_iop_soundness_verified: false,
    adaptive_ghcm_schedule_verified: false,
    concrete_sha512_qro_bridge_verified: false,
    concrete_shake256_xof_bridge_verified: false,
    composed_pq128_verified: false,
    release_manifest_bound: false,
};

impl Hx512SecurityAuthorization {
    pub const fn production_authorized(self) -> bool {
        self.wire_identity_allocated
            && self.role_domain_registry_manifest_bound
            && self.outer_framer_cap_before_buffering_verified
            && self.engine_transcript_schedule_refinement_verified
            && self.full_relation_compiler_refinement_verified
            && self.inner_proof_parser_refinement_verified
            && self.rust_verifier_refinement_verified
            && self.round_by_round_randomness_verified
            && self.honest_verifier_zero_knowledge_verified
            && self.complete_zero_knowledge_verified
            && self.pcs_iop_soundness_verified
            && self.adaptive_ghcm_schedule_verified
            && self.concrete_sha512_qro_bridge_verified
            && self.concrete_shake256_xof_bridge_verified
            && self.composed_pq128_verified
            && self.release_manifest_bound
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512ProductionBlocker {
    WireIdentityAllocation,
    RoleDomainRegistryManifestBinding,
    OuterFramerCapBeforeBuffering,
    EngineTranscriptScheduleRefinement,
    FullRelationCompilerRefinement,
    InnerProofParserRefinement,
    RustVerifierRefinement,
    RoundByRoundRandomness,
    HonestVerifierZeroKnowledge,
    CompleteZeroKnowledge,
    PcsIopSoundness,
    AdaptiveGhcmProgramSchedule,
    ConcreteSha512QroBridge,
    ConcreteShake256XofBridge,
    ComposedPostQuantum128,
    ReleaseManifestBinding,
}

pub const HX512_PRODUCTION_BLOCKERS: [Hx512ProductionBlocker; 16] = [
    Hx512ProductionBlocker::WireIdentityAllocation,
    Hx512ProductionBlocker::RoleDomainRegistryManifestBinding,
    Hx512ProductionBlocker::OuterFramerCapBeforeBuffering,
    Hx512ProductionBlocker::EngineTranscriptScheduleRefinement,
    Hx512ProductionBlocker::FullRelationCompilerRefinement,
    Hx512ProductionBlocker::InnerProofParserRefinement,
    Hx512ProductionBlocker::RustVerifierRefinement,
    Hx512ProductionBlocker::RoundByRoundRandomness,
    Hx512ProductionBlocker::HonestVerifierZeroKnowledge,
    Hx512ProductionBlocker::CompleteZeroKnowledge,
    Hx512ProductionBlocker::PcsIopSoundness,
    Hx512ProductionBlocker::AdaptiveGhcmProgramSchedule,
    Hx512ProductionBlocker::ConcreteSha512QroBridge,
    Hx512ProductionBlocker::ConcreteShake256XofBridge,
    Hx512ProductionBlocker::ComposedPostQuantum128,
    Hx512ProductionBlocker::ReleaseManifestBinding,
];

pub fn ensure_hx512_production_authorized() -> Result<(), Hx512Error> {
    if HX512_SECURITY_AUTHORIZATION.production_authorized() {
        Ok(())
    } else {
        Err(Hx512Error::ProductionAuthorizationUnavailable)
    }
}

fn statement_binding_digest(
    identity_header: &[u8],
    max_inner_proof_bytes: usize,
    external_statement: &[u8],
    verifier_context: &Hx512VerifierContextBinding,
    salt: &[u8; HX512_SALT_BYTES],
    geometry: Hx512TranscriptGeometry,
) -> [u8; HX512_DIGEST_BYTES] {
    let context = verifier_context.encode_exact();
    let profile = geometry.encode_canonical();
    statement_binding_digest_with_domain(
        HX512_BINDING_FRAME_DOMAIN,
        identity_header,
        max_inner_proof_bytes,
        external_statement,
        &context,
        salt,
        &profile,
    )
}

fn statement_binding_digest_with_domain(
    binding_frame_domain: &[u8],
    identity_header: &[u8],
    max_inner_proof_bytes: usize,
    external_statement: &[u8],
    verifier_context: &[u8],
    salt: &[u8; HX512_SALT_BYTES],
    profile_descriptor: &[u8],
) -> [u8; HX512_DIGEST_BYTES] {
    let mut hasher = Sha512::new();
    sha512_update_u64_framed(&mut hasher, binding_frame_domain);
    sha512_update_u64_framed(&mut hasher, identity_header);
    ShaDigest::update(&mut hasher, (max_inner_proof_bytes as u64).to_be_bytes());
    sha512_update_u64_framed(&mut hasher, external_statement);
    sha512_update_u64_framed(&mut hasher, verifier_context);
    sha512_update_u64_framed(&mut hasher, salt);
    sha512_update_u64_framed(&mut hasher, profile_descriptor);
    hasher.finalize().into()
}

pub fn hx512_transcript_schedule_digest() -> [u8; HX512_DIGEST_BYTES] {
    let mut hasher = Sha512::new();
    sha512_update_u64_framed(&mut hasher, HX512_BINDING_FRAME_DOMAIN);
    sha512_update_u64_framed(&mut hasher, HX512_REQUEST_FRAME_DOMAIN);
    sha512_update_u64_framed(&mut hasher, HX512_XOF_FRAME_DOMAIN);
    ShaDigest::update(
        &mut hasher,
        (HX512_TRANSCRIPT_EVENT_LEDGER.len() as u64).to_be_bytes(),
    );
    for event in HX512_TRANSCRIPT_EVENT_LEDGER {
        ShaDigest::update(
            &mut hasher,
            [
                event.ordinal,
                event.stage as u8,
                event.operation as u8,
                event.primitive as u8,
            ],
        );
        sha512_update_u64_framed(&mut hasher, event.stage.role().domain());
    }
    hasher.finalize().into()
}

fn put_u8<const N: usize>(output: &mut [u8; N], cursor: &mut usize, value: u8) {
    output[*cursor] = value;
    *cursor += 1;
}

fn put_u32<const N: usize>(output: &mut [u8; N], cursor: &mut usize, value: u32) {
    put_bytes(output, cursor, &value.to_be_bytes());
}

fn put_u64<const N: usize>(output: &mut [u8; N], cursor: &mut usize, value: u64) {
    put_bytes(output, cursor, &value.to_be_bytes());
}

fn put_bytes<const N: usize>(output: &mut [u8; N], cursor: &mut usize, value: &[u8]) {
    let end = *cursor + value.len();
    output[*cursor..end].copy_from_slice(value);
    *cursor = end;
}

fn decode_domain_kind(value: u8) -> Result<Hx512DomainKind, Hx512Error> {
    match value {
        1 => Ok(Hx512DomainKind::Radix2DisjointCoset),
        _ => Err(Hx512Error::ProfileInvariant("domain kind")),
    }
}

fn decode_field_encoding(value: u8) -> Result<Hx512FieldEncoding, Hx512Error> {
    match value {
        1 => Ok(Hx512FieldEncoding::CanonicalU64BigEndian),
        _ => Err(Hx512Error::ProfileInvariant("field encoding")),
    }
}

fn decode_index_encoding(value: u8) -> Result<Hx512IndexEncoding, Hx512Error> {
    match value {
        1 => Ok(Hx512IndexEncoding::CanonicalU32BigEndian),
        _ => Err(Hx512Error::ProfileInvariant("index encoding")),
    }
}

fn decode_polynomial_order(value: u8) -> Result<Hx512PolynomialOrder, Hx512Error> {
    match value {
        1 => Ok(Hx512PolynomialOrder::ConstantTermFirst),
        _ => Err(Hx512Error::ProfileInvariant("polynomial order")),
    }
}

fn decode_context_height_encoding(value: u8) -> Result<Hx512ContextHeightEncoding, Hx512Error> {
    match value {
        1 => Ok(Hx512ContextHeightEncoding::CanonicalU64LittleEndian),
        _ => Err(Hx512Error::ProfileInvariant("context height encoding")),
    }
}

#[allow(clippy::too_many_arguments)]
fn hash_request_with_domains(
    request_frame_domain: &[u8],
    role_domain: &[u8],
    statement_binding_digest: &[u8; HX512_DIGEST_BYTES],
    request_kind: Hx512RequestKind,
    event_index: u64,
    chain_digest: &[u8; HX512_DIGEST_BYTES],
    descriptor: &[u8],
    message: &[u8],
    counter: u64,
) -> [u8; HX512_DIGEST_BYTES] {
    let mut hasher = Sha512::new();
    sha512_update_u64_framed(&mut hasher, request_frame_domain);
    sha512_update_u64_framed(&mut hasher, role_domain);
    sha512_update_u64_framed(&mut hasher, statement_binding_digest);
    ShaDigest::update(&mut hasher, [request_kind as u8]);
    ShaDigest::update(&mut hasher, event_index.to_be_bytes());
    sha512_update_u64_framed(&mut hasher, chain_digest);
    sha512_update_u64_framed(&mut hasher, descriptor);
    sha512_update_u64_framed(&mut hasher, message);
    ShaDigest::update(&mut hasher, counter.to_be_bytes());
    hasher.finalize().into()
}

fn sha512_update_u64_framed(hasher: &mut Sha512, bytes: &[u8]) {
    ShaDigest::update(hasher, (bytes.len() as u64).to_be_bytes());
    ShaDigest::update(hasher, bytes);
}

fn shake256_request_reader_with_domains(
    xof_frame_domain: &[u8],
    role_domain: &[u8],
    statement_binding_digest: &[u8; HX512_DIGEST_BYTES],
    request_kind: Hx512RequestKind,
    event_index: u64,
    chain_digest: &[u8; HX512_DIGEST_BYTES],
    descriptor: &[u8],
) -> sha3::Shake256Reader {
    let mut hasher = Shake256::default();
    shake256_update_u64_framed(&mut hasher, xof_frame_domain);
    shake256_update_u64_framed(&mut hasher, role_domain);
    shake256_update_u64_framed(&mut hasher, statement_binding_digest);
    Sha3Update::update(&mut hasher, &[request_kind as u8]);
    Sha3Update::update(&mut hasher, &event_index.to_be_bytes());
    shake256_update_u64_framed(&mut hasher, chain_digest);
    shake256_update_u64_framed(&mut hasher, descriptor);
    hasher.finalize_xof()
}

fn shake256_update_u64_framed(hasher: &mut Shake256, bytes: &[u8]) {
    Sha3Update::update(hasher, &(bytes.len() as u64).to_be_bytes());
    Sha3Update::update(hasher, bytes);
}

fn try_copy_bytes(bytes: &[u8], context: &'static str) -> Result<Vec<u8>, Hx512Error> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| Hx512Error::AllocationFailed(context))?;
    output.extend_from_slice(bytes);
    Ok(output)
}

fn sampler_descriptor(
    stage: Hx512TranscriptStage,
    count: usize,
    modulus: u64,
) -> Result<[u8; 13], Hx512Error> {
    let count = u32::try_from(count).map_err(|_| Hx512Error::SamplerBudgetOverflow)?;
    let mut descriptor = [0u8; 13];
    descriptor[0] = stage as u8;
    descriptor[1..5].copy_from_slice(&count.to_be_bytes());
    descriptor[5..].copy_from_slice(&modulus.to_be_bytes());
    Ok(descriptor)
}

fn validate_geometry_field_count(
    stage: Hx512TranscriptStage,
    count: usize,
) -> Result<(), Hx512Error> {
    if count == 0 {
        return Err(Hx512Error::ChallengeCountZero(stage));
    }
    if count > HX512_MAX_FIELD_SAMPLES {
        return Err(Hx512Error::FieldSampleLimit {
            requested: count as u64,
            maximum: HX512_MAX_FIELD_SAMPLES as u64,
        });
    }
    Ok(())
}

/// Multiply two caller-supplied profile dimensions without ever routing an
/// unchecked product through the platform-width `usize`.  The protocol bound
/// is applied to the canonical `u64` product before the fallible conversion,
/// so a single descriptor cannot validate differently on 32- and 64-bit
/// targets.
fn checked_profile_sample_product(
    stage: Hx512TranscriptStage,
    left: u32,
    right: u32,
) -> Result<usize, Hx512Error> {
    let count = u64::from(left)
        .checked_mul(u64::from(right))
        .ok_or(Hx512Error::SamplerBudgetOverflow)?;
    if count == 0 {
        return Err(Hx512Error::ChallengeCountZero(stage));
    }
    if count > HX512_MAX_FIELD_SAMPLES as u64 {
        return Err(Hx512Error::FieldSampleLimit {
            requested: count,
            maximum: HX512_MAX_FIELD_SAMPLES as u64,
        });
    }
    usize::try_from(count).map_err(|_| Hx512Error::SamplerBudgetOverflow)
}

fn next_schedule_state(completed_events: u8) -> Hx512ScheduleState {
    HX512_TRANSCRIPT_SCHEDULE
        .get(completed_events as usize)
        .copied()
        .map(Hx512ScheduleState::Awaiting)
        .unwrap_or(Hx512ScheduleState::Complete)
}

fn validate_hash_message_length(length: usize, maximum: usize) -> Result<(), Hx512Error> {
    if length > maximum {
        return Err(Hx512Error::HashMessageLimit {
            actual: length,
            maximum,
        });
    }
    Ok(())
}

fn validate_field_words(words: &[u64]) -> Result<(), Hx512Error> {
    if let Some((index, value)) = words
        .iter()
        .copied()
        .enumerate()
        .find(|(_, value)| *value >= HX512_GOLDILOCKS_MODULUS)
    {
        return Err(Hx512Error::NonCanonicalFieldWord { index, value });
    }
    Ok(())
}

fn validate_domain_registry() -> Result<(), Hx512Error> {
    for (index, role) in Hx512Role::ALL.iter().copied().enumerate() {
        if role.domain().is_empty()
            || Hx512Role::ALL[index + 1..]
                .iter()
                .any(|other| other.domain() == role.domain())
        {
            return Err(Hx512Error::GhcmAccounting(
                "HX512 transcript role domains must be nonempty and unique",
            ));
        }
    }
    Ok(())
}

fn validate_proof_length(
    parameters: Hx512WireParameters<'_>,
    proof_len: usize,
) -> Result<(), Hx512Error> {
    if proof_len == 0 {
        return Err(Hx512Error::EmptyInnerProof);
    }
    if proof_len > parameters.max_inner_proof_bytes {
        return Err(Hx512Error::FrameLengthLimit {
            frame: Hx512WireFrame::InnerProof,
            declared: proof_len,
            maximum: parameters.max_inner_proof_bytes,
        });
    }
    wire_length(
        parameters.identity_header.len(),
        proof_len,
        parameters.max_inner_proof_bytes,
    )?;
    Ok(())
}

fn wire_length(
    identity_header_len: usize,
    proof_len: usize,
    max_inner_proof_bytes: usize,
) -> Result<usize, Hx512Error> {
    if proof_len > max_inner_proof_bytes {
        return Err(Hx512Error::ProofCap {
            actual: proof_len,
            maximum: max_inner_proof_bytes,
        });
    }
    let maximum = HX512_WIRE_BASE_OVERHEAD_BYTES
        .checked_add(identity_header_len)
        .and_then(|value| value.checked_add(max_inner_proof_bytes))
        .ok_or(Hx512Error::WireTooLarge {
            actual: usize::MAX,
            maximum: usize::MAX,
        })?;
    HX512_WIRE_BASE_OVERHEAD_BYTES
        .checked_add(identity_header_len)
        .and_then(|value| value.checked_add(proof_len))
        .ok_or(Hx512Error::WireTooLarge {
            actual: usize::MAX,
            maximum,
        })
}

fn append_u16_framed(output: &mut Vec<u8>, bytes: &[u8]) {
    let length = u16::try_from(bytes.len()).expect("fixed HX512 frame domain fits u16");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
}

fn append_u16_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    let length = u16::try_from(bytes.len()).expect("bounded HX512 field fits u16");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
}

fn append_field_words(output: &mut Vec<u8>, words: &[u64]) {
    output.extend_from_slice(
        &u32::try_from(words.len())
            .expect("bounded HX512 field-vector length fits u32")
            .to_be_bytes(),
    );
    for word in words {
        output.extend_from_slice(&word.to_be_bytes());
    }
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], Hx512Error> {
    let end = cursor.checked_add(length).ok_or(Hx512Error::WireTooShort)?;
    let value = bytes.get(*cursor..end).ok_or(Hx512Error::WireTooShort)?;
    *cursor = end;
    Ok(value)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, Hx512Error> {
    Ok(u16::from_be_bytes(
        take(bytes, cursor, 2)?
            .try_into()
            .map_err(|_| Hx512Error::WireTooShort)?,
    ))
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, Hx512Error> {
    Ok(*take(bytes, cursor, 1)?
        .first()
        .ok_or(Hx512Error::WireTooShort)?)
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, Hx512Error> {
    Ok(u32::from_be_bytes(
        take(bytes, cursor, 4)?
            .try_into()
            .map_err(|_| Hx512Error::WireTooShort)?,
    ))
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, Hx512Error> {
    Ok(u64::from_be_bytes(
        take(bytes, cursor, 8)?
            .try_into()
            .map_err(|_| Hx512Error::WireTooShort)?,
    ))
}

/// Return the exact reduced dyadic representation of
/// `(3R/2) * sqrt(2^q * 2^-h)` as `numerator / 2^denominator_log2`.
fn ghcm_dyadic_term(
    total_program_events: u128,
    conditional_entropy_bits: u16,
    qrom_query_log2: u16,
) -> Result<(u128, u16), Hx512Error> {
    if total_program_events == 0 || qrom_query_log2 >= conditional_entropy_bits {
        return Err(Hx512Error::GhcmAccounting("invalid GHCM class inputs"));
    }
    let entropy_gap = conditional_entropy_bits - qrom_query_log2;
    if entropy_gap % 2 != 0 {
        return Err(Hx512Error::GhcmAccounting(
            "exact dyadic GHCM ledger requires an even entropy gap",
        ));
    }
    let raw_denominator_log2 = 1u16
        .checked_add(entropy_gap / 2)
        .ok_or(Hx512Error::GhcmAccounting("GHCM denominator overflow"))?;
    let removable_twos = u16::try_from(total_program_events.trailing_zeros())
        .map_err(|_| Hx512Error::GhcmAccounting("GHCM factor overflow"))?
        .min(raw_denominator_log2);
    let reduced_events = total_program_events >> u32::from(removable_twos);
    let numerator = reduced_events
        .checked_mul(3)
        .ok_or(Hx512Error::GhcmAccounting("GHCM numerator overflow"))?;
    Ok((numerator, raw_denominator_log2 - removable_twos))
}

fn ceil_log2(value: u128) -> Result<u16, Hx512Error> {
    if value == 0 {
        return Err(Hx512Error::GhcmAccounting("zero logarithm input"));
    }
    let floor = 127u32 - value.leading_zeros();
    let result = floor + u32::from(!value.is_power_of_two());
    u16::try_from(result).map_err(|_| Hx512Error::GhcmAccounting("log2 overflow"))
}
