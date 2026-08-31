//! SHAKE256-400 hash plumbing for the prospective strict Hegemon Binius profile.
//!
//! This crate implements only the proof hash, Merkle compression, and Fiat–Shamir
//! digest boundary. It does not establish zero knowledge, protocol soundness, a
//! QROM reduction, or production authorization.

#![forbid(unsafe_code)]

use binius_hash::{
    CompressionFunction, ParallelCompressionAdaptor, ParallelDigestAdapter,
    binary_merkle_tree::HashSuite,
};
use binius_transcript::{ProverTranscript, VerifierTranscript, fiat_shamir::Challenger};
use digest::{
    ExtendableOutput, FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset,
    Update, XofFixedWrapper, XofReader,
    block_api::BlockSizeUser,
    consts::{U50, U136},
};
use shake::Shake256;

type Shake256Fixed400 = XofFixedWrapper<Shake256, U50>;

const LEAF_DOMAIN: &[u8] = b"hegemon.proof.merkle-leaf.shake256-400.v1";
const NODE_DOMAIN: &[u8] = b"hegemon.proof.merkle-node.shake256-400.v1";
const TRANSCRIPT_DOMAIN: &[u8] = b"hegemon.proof.fiat-shamir.shake256-400.v1";

/// Canonical transcript-context encoding magic and schema version.
pub const STRICT_CONTEXT_MAGIC: &[u8; 8] = b"HGM4CTX1";
pub const STRICT_CONTEXT_SCHEMA: u16 = 1;

/// The exact upstream backend revision used by this isolated integration.
pub const STRICT_BACKEND_REVISION: &str = "3f96163049f680b2909f6545690bd929f1b48c44";

/// Fixed protocol identities observed before the public statement.
pub const STRICT_CIRCUIT_PROFILE_ID: &str = "hegemon.pay1x2.m4.full-inline.single-main.v1";
pub const STRICT_RELATION_PROFILE_ID: &str = "hegemon.pay1x2.hgs2.statement-v2.circuit-v5.crypto-suite-v4.backend-v1.profile-v1.semantic-shake256-448.depth32.v1";
pub const STRICT_HASH_PROFILE_ID: &str =
    "hegemon.binius64.basefold.prospective-strict-hash.shake256-400.v1";
/// Actual challenge field used by the pinned M4 prover/verifier. The ID names
/// the irreducible polynomial, coefficient basis, and wire byte order.
pub const STRICT_CHALLENGE_FIELD_ID: &str =
    "binius.b128-ghash.gf2.modulus-x128+x7+x2+x+1.lsb-polynomial-basis.serialization-u128-le.v1";
/// Candidate field ID used only for negative/profile-separation tests. The
/// pinned M4 prover/verifier does not implement this mixed-field arithmetic.
pub const PROSPECTIVE_E384_CHALLENGE_FIELD_ID: &str = "hegemon.e384.over-binius-b128.modulus-y3+y+1.coefficient-b128-lsb-polynomial-basis.serialization-3xb128-le.v1";

const SOURCE_DIGEST_DOMAIN: &[u8] = b"hegemon.pay1x2.m4.relation-source-bundle.shake256-512.v1";

// This conservative bundle pins the integration, the full inline M4 circuit, its
// scalar relation/statement/semantic sources, and all direct lockfiles. Including
// this crate's own sources means a context-affecting code change automatically
// changes the digest; the backend Git revision remains a separate explicit field.
const RELATION_SOURCE_FILES: &[(&[u8], &[u8])] = &[
    (
        b"strict-hash-profile/Cargo.toml",
        include_bytes!("../Cargo.toml"),
    ),
    (
        b"strict-hash-profile/Cargo.lock",
        include_bytes!("../Cargo.lock"),
    ),
    (b"strict-hash-profile/src/lib.rs", include_bytes!("lib.rs")),
    (
        b"strict-hash-profile/src/bin/m4_strict_hash.rs",
        include_bytes!("bin/m4_strict_hash.rs"),
    ),
    (
        b"m4-full-pay1x2-prototype/Cargo.toml",
        include_bytes!("../../m4-full-pay1x2-prototype/Cargo.toml"),
    ),
    (
        b"m4-full-pay1x2-prototype/Cargo.lock",
        include_bytes!("../../m4-full-pay1x2-prototype/Cargo.lock"),
    ),
    (
        b"m4-full-pay1x2-prototype/src/lib.rs",
        include_bytes!("../../m4-full-pay1x2-prototype/src/lib.rs"),
    ),
    (
        b"circuits/standalone-pay1x2-relation-prototype/Cargo.toml",
        include_bytes!("../../../../circuits/standalone-pay1x2-relation-prototype/Cargo.toml"),
    ),
    (
        b"circuits/standalone-pay1x2-relation-prototype/Cargo.lock",
        include_bytes!("../../../../circuits/standalone-pay1x2-relation-prototype/Cargo.lock"),
    ),
    (
        b"circuits/standalone-pay1x2-relation-prototype/src/lib.rs",
        include_bytes!("../../../../circuits/standalone-pay1x2-relation-prototype/src/lib.rs"),
    ),
    (
        b"circuits/standalone-pay1x2-statement-prototype/Cargo.toml",
        include_bytes!("../../../../circuits/standalone-pay1x2-statement-prototype/Cargo.toml"),
    ),
    (
        b"circuits/standalone-pay1x2-statement-prototype/Cargo.lock",
        include_bytes!("../../../../circuits/standalone-pay1x2-statement-prototype/Cargo.lock"),
    ),
    (
        b"circuits/standalone-pay1x2-statement-prototype/src/lib.rs",
        include_bytes!("../../../../circuits/standalone-pay1x2-statement-prototype/src/lib.rs"),
    ),
    (
        b"circuits/standalone-pay1x2-statement-prototype/src/action.rs",
        include_bytes!("../../../../circuits/standalone-pay1x2-statement-prototype/src/action.rs"),
    ),
    (
        b"circuits/standalone-shake256-prototype/Cargo.toml",
        include_bytes!("../../../../circuits/standalone-shake256-prototype/Cargo.toml"),
    ),
    (
        b"circuits/standalone-shake256-prototype/Cargo.lock",
        include_bytes!("../../../../circuits/standalone-shake256-prototype/Cargo.lock"),
    ),
    (
        b"circuits/standalone-shake256-prototype/src/lib.rs",
        include_bytes!("../../../../circuits/standalone-shake256-prototype/src/lib.rs"),
    ),
];

fn relation_source_digest() -> [u8; 64] {
    let mut hash = Shake256::default();
    Update::update(&mut hash, SOURCE_DIGEST_DOMAIN);
    Update::update(
        &mut hash,
        &u32::try_from(RELATION_SOURCE_FILES.len())
            .expect("the source-file count fits u32")
            .to_be_bytes(),
    );
    for &(label, data) in RELATION_SOURCE_FILES {
        Update::update(
            &mut hash,
            &u16::try_from(label.len())
                .expect("a source label fits u16")
                .to_be_bytes(),
        );
        Update::update(&mut hash, label);
        Update::update(
            &mut hash,
            &u64::try_from(data.len())
                .expect("a source file length fits u64")
                .to_be_bytes(),
        );
        Update::update(&mut hash, data);
    }
    let mut out = [0u8; 64];
    hash.finalize_xof().read(&mut out);
    out
}

fn append_context_field(out: &mut Vec<u8>, tag: u16, value: &[u8]) {
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(
        &u32::try_from(value.len())
            .expect("a transcript-context field fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(value);
}

/// Canonical context observed before the M4 public statement on both sides.
///
/// Callers using the helpers below bind backend/circuit/profile/field/rate identity
/// for this prototype. The raw upstream M4 transcript API does not enforce this
/// preamble. It is observed rather than serialized, so it changes challenges
/// but contributes zero bytes to the proof tape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictTranscriptContext {
    log_inverse_rate: u64,
    challenge_field_id: String,
    relation_source_digest: [u8; 64],
    encoded: Vec<u8>,
}

impl StrictTranscriptContext {
    pub fn new(log_inverse_rate: usize) -> Self {
        Self::new_for_challenge_field(log_inverse_rate, STRICT_CHALLENGE_FIELD_ID)
    }

    /// Construct an explicitly field-bound context.
    ///
    /// This changes transcript identity only; it does not change the prover or
    /// verifier arithmetic. A caller must not select an ID unless the backend
    /// actually implements that field. It is public so negative tests can prove
    /// that otherwise identical contexts cannot be replayed across field profiles.
    pub fn new_for_challenge_field(log_inverse_rate: usize, challenge_field_id: &str) -> Self {
        assert!(
            !challenge_field_id.is_empty(),
            "challenge field ID must be nonempty"
        );
        let log_inverse_rate = u64::try_from(log_inverse_rate).expect("log inverse rate fits u64");
        let relation_source_digest = relation_source_digest();
        let mut encoded = Vec::with_capacity(448);
        encoded.extend_from_slice(STRICT_CONTEXT_MAGIC);
        encoded.extend_from_slice(&STRICT_CONTEXT_SCHEMA.to_be_bytes());
        encoded.extend_from_slice(&7u16.to_be_bytes());
        append_context_field(&mut encoded, 1, STRICT_BACKEND_REVISION.as_bytes());
        append_context_field(&mut encoded, 2, STRICT_CIRCUIT_PROFILE_ID.as_bytes());
        append_context_field(&mut encoded, 3, STRICT_RELATION_PROFILE_ID.as_bytes());
        append_context_field(&mut encoded, 4, STRICT_HASH_PROFILE_ID.as_bytes());
        append_context_field(&mut encoded, 5, challenge_field_id.as_bytes());
        append_context_field(&mut encoded, 6, &relation_source_digest);
        append_context_field(&mut encoded, 7, &log_inverse_rate.to_be_bytes());
        Self {
            log_inverse_rate,
            challenge_field_id: challenge_field_id.to_owned(),
            relation_source_digest,
            encoded,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    pub const fn log_inverse_rate(&self) -> u64 {
        self.log_inverse_rate
    }

    pub fn challenge_field_id(&self) -> &str {
        &self.challenge_field_id
    }

    pub const fn relation_source_digest(&self) -> &[u8; 64] {
        &self.relation_source_digest
    }
}

/// Observe the canonical context before calling the M4 prover.
pub fn observe_prover_context<C: Challenger>(
    transcript: &mut ProverTranscript<C>,
    context: &StrictTranscriptContext,
) {
    transcript.observe().write_bytes(context.as_bytes());
}

/// Observe the canonical context before calling the M4 verifier.
pub fn observe_verifier_context<C: Challenger>(
    transcript: &mut VerifierTranscript<C>,
    context: &StrictTranscriptContext,
) {
    transcript.observe().write_bytes(context.as_bytes());
}

macro_rules! domain_digest {
    ($name:ident, $domain:ident) => {
        #[derive(Clone, Debug)]
        pub struct $name(Shake256Fixed400);

        impl Default for $name {
            fn default() -> Self {
                let mut inner = Shake256Fixed400::default();
                Update::update(&mut inner, $domain);
                Self(inner)
            }
        }

        impl HashMarker for $name {}

        impl OutputSizeUser for $name {
            type OutputSize = U50;
        }

        impl BlockSizeUser for $name {
            type BlockSize = U136;
        }

        impl Update for $name {
            fn update(&mut self, data: &[u8]) {
                Update::update(&mut self.0, data);
            }
        }

        impl Reset for $name {
            fn reset(&mut self) {
                Reset::reset(&mut self.0);
                Update::update(&mut self.0, $domain);
            }
        }

        impl FixedOutput for $name {
            fn finalize_into(self, out: &mut Output<Self>) {
                let mut inner_out = Output::<Shake256Fixed400>::default();
                FixedOutput::finalize_into(self.0, &mut inner_out);
                out.copy_from_slice(&inner_out);
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                let mut inner_out = Output::<Shake256Fixed400>::default();
                FixedOutputReset::finalize_into_reset(&mut self.0, &mut inner_out);
                out.copy_from_slice(&inner_out);
                Update::update(&mut self.0, $domain);
            }
        }
    };
}

domain_digest!(StrictLeafDigest, LEAF_DOMAIN);
domain_digest!(StrictTranscriptDigest, TRANSCRIPT_DOMAIN);

/// Two-to-one SHAKE256-400 Merkle compression with an independent node domain.
#[derive(Clone, Debug, Default)]
pub struct StrictNodeCompression;

impl CompressionFunction<Output<StrictLeafDigest>, 2> for StrictNodeCompression {
    fn compress(&self, input: [Output<StrictLeafDigest>; 2]) -> Output<StrictLeafDigest> {
        let mut hash = Shake256Fixed400::default();
        Update::update(&mut hash, NODE_DOMAIN);
        Update::update(&mut hash, &input[0]);
        Update::update(&mut hash, &input[1]);
        FixedOutput::finalize_fixed(hash)
    }
}

/// Binius hash-suite adapter for 50-byte SHAKE256 commitments.
#[derive(Clone, Debug, Default)]
pub struct StrictShake256HashSuite;

impl HashSuite for StrictShake256HashSuite {
    type LeafHash = StrictLeafDigest;
    type Compression = StrictNodeCompression;
    type ParLeafHash = ParallelDigestAdapter<StrictLeafDigest>;
    type ParCompression = ParallelCompressionAdaptor<StrictNodeCompression>;
}

#[cfg(test)]
mod tests {
    use binius_compute::GlobalAllocator;
    use binius_field::BinaryField128bGhash as B128;
    use binius_hash::CompressionFunction;
    use binius_hash::binary_merkle_tree::BinaryMerkleTree;
    use binius_transcript::fiat_shamir::{CanSample, Challenger, HasherChallenger};
    use binius_transcript::{Buf, BufMut};
    use digest::Digest;
    use shake::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };

    use super::*;

    // Framing reference only: this intentionally exercises the raw XOF API from
    // the same RustCrypto implementation. The leaf KAT below is the independent
    // cross-implementation check.
    fn reference_shake(parts: &[&[u8]]) -> [u8; 50] {
        let mut hash = Shake256::default();
        for part in parts {
            Update::update(&mut hash, part);
        }
        let mut out = [0u8; 50];
        hash.finalize_xof().read(&mut out);
        out
    }

    #[test]
    fn leaf_digest_matches_external_python_hashlib_vector_and_is_50_bytes() {
        let message = b"strict-leaf-kat";
        let got = StrictLeafDigest::digest(message);
        // Generated once with Python 3 hashlib/OpenSSL:
        // hashlib.shake_256(LEAF_DOMAIN + b"strict-leaf-kat").digest(50)
        let expected = [
            0x10, 0xc8, 0xa5, 0x72, 0xe2, 0xd1, 0x7c, 0x9d, 0x99, 0xa8, 0xaf, 0xc3, 0x22, 0x6b,
            0xec, 0x34, 0x8b, 0x9b, 0x70, 0xb4, 0x4b, 0xb1, 0x25, 0x24, 0xd4, 0x69, 0xf2, 0xc0,
            0xf9, 0x35, 0x05, 0x08, 0x3f, 0x2b, 0x24, 0x4f, 0x15, 0xf9, 0x75, 0xa9, 0xd0, 0x16,
            0x27, 0x64, 0xd9, 0x48, 0x2d, 0x89, 0xac, 0x10,
        ];
        assert_eq!(got.len(), 50);
        assert_eq!(got.as_slice(), expected);
    }

    #[test]
    fn node_compression_is_ordered_and_domain_separated() {
        let left = StrictLeafDigest::digest(b"left");
        let right = StrictLeafDigest::digest(b"right");
        let got = StrictNodeCompression.compress([left, right]);
        let expected = reference_shake(&[NODE_DOMAIN, &left, &right]);
        assert_eq!(got.as_slice(), expected);
        assert_ne!(got, StrictNodeCompression.compress([right, left]));
        assert_ne!(
            got,
            StrictLeafDigest::digest([left.as_slice(), right.as_slice()].concat())
        );
    }

    #[test]
    fn reset_reinstalls_the_domain() {
        let mut hash = StrictLeafDigest::default();
        Digest::update(&mut hash, b"same");
        let first = hash.finalize_reset();
        Digest::update(&mut hash, b"same");
        let second = hash.finalize_reset();
        assert_eq!(first, second);
        assert_eq!(first.as_slice(), reference_shake(&[LEAF_DOMAIN, b"same"]));

        Digest::update(&mut hash, b"discarded");
        Reset::reset(&mut hash);
        Digest::update(&mut hash, b"same");
        assert_eq!(hash.finalize(), first);
    }

    #[test]
    fn transcript_digest_has_an_independent_domain() {
        let message = b"same";
        assert_ne!(
            StrictLeafDigest::digest(message),
            StrictTranscriptDigest::digest(message)
        );
    }

    #[test]
    fn challenger_transition_matches_reference_framing() {
        type StrictChallenger = HasherChallenger<StrictTranscriptDigest>;

        let initial = StrictTranscriptDigest::digest([]);
        let mut challenger = StrictChallenger::default();
        let mut first = [0u8; 16];
        challenger.sampler().copy_to_slice(&mut first);
        assert_eq!(first, initial[..16]);

        let observed = b"hegemon-strict-transcript-kat";
        challenger.observer().put_slice(observed);
        let mut sampled = [0u8; 50];
        challenger.sampler().copy_to_slice(&mut sampled);

        let index = 16u64.to_le_bytes();
        let expected = reference_shake(&[TRANSCRIPT_DOMAIN, &initial, &index, observed]);
        assert_eq!(sampled, expected);
    }

    #[test]
    fn transcript_context_is_canonical_rate_and_field_bound() {
        let context = StrictTranscriptContext::new(2);
        assert_eq!(&context.as_bytes()[..8], STRICT_CONTEXT_MAGIC);
        assert_eq!(
            &context.as_bytes()[8..10],
            &STRICT_CONTEXT_SCHEMA.to_be_bytes()
        );
        assert_eq!(&context.as_bytes()[10..12], &7u16.to_be_bytes());
        assert_eq!(
            STRICT_BACKEND_REVISION,
            hegemon_m4_full_pay1x2_prototype::UPSTREAM_REVISION
        );
        assert_eq!(context.log_inverse_rate(), 2);
        assert_eq!(context.challenge_field_id(), STRICT_CHALLENGE_FIELD_ID);
        assert_eq!(context.relation_source_digest().len(), 64);
        assert_ne!(context, StrictTranscriptContext::new(3));
        let e384_context = StrictTranscriptContext::new_for_challenge_field(
            2,
            PROSPECTIVE_E384_CHALLENGE_FIELD_ID,
        );
        assert_ne!(context, e384_context);

        type StrictChallenger = HasherChallenger<StrictTranscriptDigest>;
        let mut rate_2 = StrictChallenger::default();
        rate_2.observer().put_slice(context.as_bytes());
        let mut rate_2_sample = [0u8; 64];
        rate_2.sampler().copy_to_slice(&mut rate_2_sample);

        let mut rate_3 = StrictChallenger::default();
        rate_3
            .observer()
            .put_slice(StrictTranscriptContext::new(3).as_bytes());
        let mut rate_3_sample = [0u8; 64];
        rate_3.sampler().copy_to_slice(&mut rate_3_sample);
        assert_ne!(rate_2_sample, rate_3_sample);

        let mut e384 = StrictChallenger::default();
        e384.observer().put_slice(e384_context.as_bytes());
        let mut e384_sample = [0u8; 64];
        e384.sampler().copy_to_slice(&mut e384_sample);
        assert_ne!(rate_2_sample, e384_sample);

        let mut prover_transcript = ProverTranscript::new(StrictChallenger::default());
        observe_prover_context(&mut prover_transcript, &context);
        let prover_sample: B128 = CanSample::sample(&mut prover_transcript);
        let proof_tape = prover_transcript.finalize();
        assert!(proof_tape.is_empty(), "the context must be observe-only");

        let mut verifier_transcript =
            VerifierTranscript::new(StrictChallenger::default(), proof_tape);
        observe_verifier_context(&mut verifier_transcript, &context);
        let verifier_sample: B128 = CanSample::sample(&mut verifier_transcript);
        assert_eq!(prover_sample, verifier_sample);
        verifier_transcript
            .finalize()
            .expect("the observe-only context leaves no unread proof bytes");
    }

    #[test]
    fn hash_suite_builds_and_authenticates_a_binius_merkle_tree() {
        let values = (0..8).map(B128::new).collect::<Vec<_>>();
        let tree =
            BinaryMerkleTree::new::<B128, StrictShake256HashSuite>(&values, 2, &GlobalAllocator)
                .expect("four two-field leaves form a complete tree");

        // The tree builder uses ParallelDigestAdapter. Recompute one leaf from
        // the canonical B128 little-endian serialization through the sequential
        // digest to prove that both adapter paths have the same domain/reset state.
        let expected_leaf =
            StrictLeafDigest::digest([4u128.to_le_bytes(), 5u128.to_le_bytes()].concat());
        assert_eq!(tree.layer(tree.log_len).unwrap()[2], expected_leaf);

        let leaf_index = 2usize;
        let mut node = tree.layer(tree.log_len).unwrap()[leaf_index];
        let mut index = leaf_index;
        let branch = tree.branch(leaf_index, 0).unwrap();
        for sibling in &branch {
            node = if index & 1 == 0 {
                StrictNodeCompression.compress([node, *sibling])
            } else {
                StrictNodeCompression.compress([*sibling, node])
            };
            index >>= 1;
        }
        assert_eq!(node, tree.root());

        let mut bad_branch = branch;
        bad_branch[0][0] ^= 1;
        let mut bad_node = tree.layer(tree.log_len).unwrap()[leaf_index];
        let mut index = leaf_index;
        for sibling in bad_branch {
            bad_node = if index & 1 == 0 {
                StrictNodeCompression.compress([bad_node, sibling])
            } else {
                StrictNodeCompression.compress([sibling, bad_node])
            };
            index >>= 1;
        }
        assert_ne!(bad_node, tree.root());
    }
}
