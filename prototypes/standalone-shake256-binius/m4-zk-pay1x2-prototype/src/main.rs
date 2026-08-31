#![forbid(unsafe_code)]

use std::{env, fs, process, time::Instant};

use binius_core::{
    Word,
    constraint_system::{AndConstraint, ConstraintSystem, ValueIndex, ValueVec},
};
use binius_field::BinaryField128bGhash as B128;
use binius_hash::{StdHashSuite, binary_merkle_tree::HashSuite};
use binius_iop::{fri, merkle_tree::BinaryMerkleTreeScheme};
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_transcript::{
    ProverTranscript, VerifierTranscript,
    fiat_shamir::{Challenger, HasherChallenger},
};
use binius_utils::{DeserializeBytes, SerializeBytes};
use binius_verifier::{config::StdChallenger, zk_config::ZKVerifier};
use digest::Output;
use hegemon_binius_strict_hash_profile::{
    StrictShake256HashSuite, StrictTranscriptContext, StrictTranscriptDigest,
};
use hegemon_m4_full_pay1x2_prototype::{
    canonical_fixture, generate_fixture_witness, pack_public_words, serialize_private_witness,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use serde_json::json;
use sha2::{Digest, Sha256};

const DEFAULT_RATE: usize = 3;
const WEAK_PROOF_BYTES: [usize; 6] = [440_288, 334_016, 317_312, 325_888, 343_712, 367_264];
// The original main has 24,160 AND constraints and fewer than 2^15 private words. Adding these
// satisfiable random constraints keeps both dimensions in the same 2^15 tier. The experiment is
// rejected as a ZK transform: this contiguous subspace has annihilating evaluation points.
const BLINDING_AND_CONSTRAINTS: usize = 128;
const BLINDING_WORDS: usize = 3 * BLINDING_AND_CONSTRAINTS;

struct Args {
    rate: usize,
    deterministic_test_seed: Option<u64>,
    proof_out: Option<String>,
    compare_freshness: bool,
    hash_mode: HashMode,
    setup_only: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HashMode {
    Standard,
    Strict,
}

impl HashMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard-sha256",
            Self::Strict => "strict-shake256-512",
        }
    }
}

type StrictChallenger = HasherChallenger<StrictTranscriptDigest>;

fn main() {
    let args = parse_args();
    match args.hash_mode {
        HashMode::Standard => run::<StdHashSuite, StdChallenger>(args, None),
        HashMode::Strict => {
            let context = strict_transcript_context(args.rate);
            run::<StrictShake256HashSuite, StrictChallenger>(args, Some(&context));
        }
    }
}

fn run<H, Challenger_>(args: Args, transcript_context: Option<&[u8]>)
where
    H: HashSuite,
    Output<H::LeafHash>: SerializeBytes + DeserializeBytes,
    Challenger_: Challenger + Default,
{
    let (master_seed, coin_source, test_only) = match args.deterministic_test_seed {
        Some(seed) => (
            deterministic_master_seed(seed),
            "explicit-deterministic-test-seed",
            true,
        ),
        None => (system_master_seed(), "system-entropy", false),
    };
    let built = hegemon_m4_full_pay1x2_prototype::build_pay1x2_m4();
    let (_, scalar_witness, statement) = canonical_fixture();
    let witness = generate_fixture_witness(&built, &scalar_witness, &statement)
        .expect("the canonical witness must populate the exact M4 circuit");
    let composite_cs = built.circuit.to_constraint_system();
    composite_cs
        .validate()
        .expect("the exact M4 constraint system must validate");
    witness
        .verify(&composite_cs)
        .expect("the canonical witness must satisfy the exact M4 system");
    assert!(
        composite_cs.chips.is_empty() && witness.tables.is_empty(),
        "the ZK adapter is admitted only for one M4 main with no numbered chips"
    );

    // A chip-free M4 system's main is exactly the ordinary Binius64 constraint system and
    // ValueVec already consumed by ProverM4. Route those same objects through the full upstream
    // ZK wrapper: BaseFold oracle masking, OTP-encrypted inner messages, and the outer Spartan
    // verifier circuit. This is not the transparent M4 channel with one flag changed.
    let original_inner_cs = composite_cs.main.cs.clone();
    let original_private_words = original_inner_cs.n_private;
    let inner_cs = add_inner_transcript_blinding(original_inner_cs);
    let canonical_blinded_witness = blinded_witness(&inner_cs, &witness.main, &master_seed);
    inner_cs
        .verify(&canonical_blinded_witness)
        .expect("the satisfiable blinding constraints must preserve the Pay1x2 relation");
    let mut bad_blinding = canonical_blinded_witness.clone();
    let bad_index = ValueIndex::private((original_private_words + 2) as u32);
    bad_blinding[bad_index] = bad_blinding[bad_index] ^ Word::ONE;
    let malformed_blinding_rejected = inner_cs.verify(&bad_blinding).is_err();
    let setup_start = Instant::now();
    let verifier = ZKVerifier::<H>::setup(inner_cs.clone(), args.rate)
        .expect("ZK verifier setup must succeed");
    let prover =
        ZKProver::<OptimalPackedB128, H>::setup(&verifier).expect("ZK prover setup must succeed");
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1_000.0;
    let size_model = proof_size_model::<H>(&inner_cs, &verifier, args.hash_mode, args.rate);

    if args.setup_only {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "hegemon.m4-zk-pay1x2-setup.v1",
                "relation": "pay1x2-core",
                "hash_mode": args.hash_mode.as_str(),
                "setup_only": true,
                "proof_executed": false,
                "upstream_revision": hegemon_m4_full_pay1x2_prototype::UPSTREAM_REVISION,
                "log_inverse_rate": args.rate,
                "numbered_chips": 0,
                "setup_ms": setup_ms,
                "transcript_context_bound": transcript_context.is_some(),
                "proof_size_model": size_model,
                "security_status": {
                    "rejected_experiment": true,
                    "upstream_wrapper_mode": "zk",
                    "complete_zero_knowledge_established": false,
                    "local_simulator_theorem_complete": false,
                    "local_formal_zk_complete": false,
                    "strict_algebraic_profile": false,
                    "strict_pq128": false,
                    "production_authorized": false
                }
            }))
            .expect("the setup report must serialize")
        );
        return;
    }

    let prove_start = Instant::now();
    let proof = prove::<H, Challenger_>(
        &prover,
        &inner_cs,
        &witness.main,
        &master_seed,
        transcript_context,
    );
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;
    let public = pack_public_words(&statement).map(Word);

    let verify_start = Instant::now();
    let honest_roundtrip =
        verify_exact::<H, Challenger_>(&verifier, &public, &proof, transcript_context);
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;

    let mutation_offsets = [
        0usize, 5, 7, 9, 10, 11, 12, 13, 21, 29, 30, 86, 142, 198, 254, 310, 366, 422,
    ];
    let all_public_mutations_rejected = mutation_offsets.into_iter().all(|offset| {
        let mut changed = statement;
        changed[offset] ^= 1;
        !verify_exact::<H, Challenger_>(
            &verifier,
            &pack_public_words(&changed).map(Word),
            &proof,
            transcript_context,
        )
    });

    let mut changed_proof = proof.clone();
    let flip = changed_proof.len() / 2;
    changed_proof[flip] ^= 1;
    let changed_proof_rejected =
        !verify_exact::<H, Challenger_>(&verifier, &public, &changed_proof, transcript_context);
    let mut trailing = proof.clone();
    trailing.push(0);
    let trailing_proof_rejected =
        !verify_exact::<H, Challenger_>(&verifier, &public, &trailing, transcript_context);

    // Leakage-oriented executable checks. These are necessary negative controls, not a simulator
    // theorem: the report keeps formal/simulation-complete ZK false until that proof exists.
    let private_bytes = serialize_private_witness(&scalar_witness);
    let no_literal_private_16_byte_block = private_bytes
        .windows(16)
        .all(|needle| !proof.windows(needle.len()).any(|window| window == needle));
    let deterministic_replay_matches = prove::<H, Challenger_>(
        &prover,
        &inner_cs,
        &witness.main,
        &master_seed,
        transcript_context,
    ) == proof;
    let (fresh_rng_changes_proof, fresh_rng_preserves_length) = if args.compare_freshness {
        let fresh_seed = match args.deterministic_test_seed {
            Some(seed) => deterministic_master_seed(seed ^ 0xa5a5_a5a5_a5a5_a5a5),
            None => system_master_seed(),
        };
        let fresh = prove::<H, Challenger_>(
            &prover,
            &inner_cs,
            &witness.main,
            &fresh_seed,
            transcript_context,
        );
        (fresh != proof, fresh.len() == proof.len())
    } else {
        (false, false)
    };

    assert!(honest_roundtrip, "the honest ZK-wrapped proof must verify");
    assert!(
        all_public_mutations_rejected,
        "every sampled public mutation must reject"
    );
    assert!(changed_proof_rejected, "a changed proof must reject");
    assert!(trailing_proof_rejected, "trailing proof bytes must reject");
    assert!(
        no_literal_private_16_byte_block,
        "the transcript must not contain a literal 16-byte private-witness block"
    );
    assert!(
        deterministic_replay_matches,
        "a fixed test seed must reproduce the same transcript"
    );
    assert!(
        malformed_blinding_rejected,
        "the inner blinding words must be relation-bound, not free trace padding"
    );
    if args.compare_freshness {
        assert!(
            fresh_rng_changes_proof,
            "fresh mask coins must change the proof"
        );
        assert!(
            fresh_rng_preserves_length,
            "fresh mask coins must preserve canonical proof length"
        );
    }

    if let Some(path) = args.proof_out.as_deref() {
        fs::write(path, &proof).expect("the verified proof artifact must write");
    }

    let proof_sha256 = format!("{:x}", Sha256::digest(&proof));
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "hegemon.m4-zk-pay1x2-prototype.v1",
            "upstream_revision": hegemon_m4_full_pay1x2_prototype::UPSTREAM_REVISION,
            "relation": "pay1x2-core",
            "numbered_chips": 0,
            "hash_mode": args.hash_mode.as_str(),
            "transcript_context_bound": transcript_context.is_some(),
            "coin_source": {
                "mode": coin_source,
                "test_only": test_only
            },
            "log_inverse_rate": args.rate,
            "proof_bytes": proof.len(),
            "proof_sha256": proof_sha256,
            "setup_ms": setup_ms,
            "prove_ms": prove_ms,
            "verify_ms": verify_ms,
            "proof_size_model": size_model,
            "gates": {
                "honest_roundtrip": honest_roundtrip,
                "all_public_mutations_rejected": all_public_mutations_rejected,
                "changed_proof_rejected": changed_proof_rejected,
                "trailing_proof_rejected": trailing_proof_rejected,
                "no_literal_private_16_byte_block": no_literal_private_16_byte_block,
                "deterministic_replay_matches": deterministic_replay_matches,
                "fresh_rng_compared": args.compare_freshness,
                "fresh_rng_changes_proof": fresh_rng_changes_proof,
                "fresh_rng_preserves_length": fresh_rng_preserves_length,
                "malformed_blinding_rejected": malformed_blinding_rejected
            },
            "zk_transform": {
                "trace_oracle_masked": true,
                "private_inner_messages_one_time_padded": true,
                "inner_verifier_symbolically_constrained": true,
                "outer_spartan_proof": true,
                "trace_mask_only": false,
                "inner_statistical_blinding_words": BLINDING_WORDS,
                "inner_satisfiable_blinding_constraints": BLINDING_AND_CONSTRAINTS,
                "blinding_stays_in_original_private_tier": true,
                "blinding_stays_in_original_and_tier": true
            },
            "security_status": {
                "rejected_experiment": true,
                "upstream_wrapper_mode": "zk",
                "complete_zero_knowledge_established": false,
                "local_simulator_theorem_complete": false,
                "local_formal_zk_complete": false,
                "strict_hash_component_enabled": args.hash_mode == HashMode::Strict,
                "strict_algebraic_profile": false,
                "strict_pq128": false,
                "production_authorized": false,
                "limitations": [
                    "the appended-row mask has annihilating evaluation points",
                    "leakage negative controls are not a zero-knowledge simulator proof",
                    "pinned upstream uses a 96-bit query budget and GF(2^128)",
                    "the compact terminal-target and padding-fiber transparent wire is not used"
                ]
            }
        }))
        .expect("the report must serialize")
    );
}

fn prove<H, Challenger_>(
    prover: &ZKProver<OptimalPackedB128, H>,
    cs: &ConstraintSystem,
    base_witness: &ValueVec,
    master_seed: &[u8; 32],
    transcript_context: Option<&[u8]>,
) -> Vec<u8>
where
    H: HashSuite,
    Output<H::LeafHash>: SerializeBytes,
    Challenger_: Challenger + Default,
{
    let witness = blinded_witness(cs, base_witness, master_seed);
    let mut rng = domain_rng(master_seed, b"zk-wrapper-coins");
    let mut transcript = ProverTranscript::new(Challenger_::default());
    if let Some(context) = transcript_context {
        transcript.observe().write_bytes(context);
    }
    prover
        .prove(&witness, &mut rng, &mut transcript)
        .expect("the exact witness must produce a ZK-wrapped proof");
    transcript.finalize()
}

/// Extend the exact relation with existentially quantified, satisfiable random AND rows.
///
/// Each row is `a & b = c` with fresh private `a,b` and derived `c`. Projecting a satisfying
/// augmented witness onto its original prefix yields exactly the original Pay1x2 witness, while
/// all three words are committed, consumed by the reduction, and relation-checked. This remains a
/// rejected experiment because their contiguous multilinear support can be annihilated.
fn add_inner_transcript_blinding(mut cs: ConstraintSystem) -> ConstraintSystem {
    let first = cs.n_private;
    cs.n_private += BLINDING_WORDS;
    for row in 0..BLINDING_AND_CONSTRAINTS {
        let base = first + 3 * row;
        cs.and_constraints.push(AndConstraint::plain_abc(
            [ValueIndex::private(base as u32)],
            [ValueIndex::private((base + 1) as u32)],
            [ValueIndex::private((base + 2) as u32)],
        ));
    }
    cs.validate()
        .expect("the augmented constraint system must remain canonical");
    assert_eq!(
        cs.log_and_constraints(),
        Some(15),
        "blinding must not raise the 2^15 AND tier"
    );
    assert_eq!(
        cs.log_witness_words(binius_core::constraint_system::InoutSegment::Public),
        15,
        "blinding must not raise the 2^15 private-word tier"
    );
    cs
}

fn blinded_witness(cs: &ConstraintSystem, base: &ValueVec, master_seed: &[u8; 32]) -> ValueVec {
    let mut rng = domain_rng(master_seed, b"active-inner-blinding");
    let mut private = Vec::with_capacity(base.non_public().len() + BLINDING_WORDS);
    private.extend_from_slice(base.non_public());
    for _ in 0..BLINDING_AND_CONSTRAINTS {
        let a = rng.random::<u64>();
        let b = rng.random::<u64>();
        private.extend([Word(a), Word(b), Word(a & b)]);
    }
    let witness = cs.value_vec_from_data(base.inout(), &private);
    cs.verify(&witness)
        .expect("fresh blinding words must satisfy every augmented constraint");
    witness
}

fn system_master_seed() -> [u8; 32] {
    let mut rng = rand::rng();
    rng.random()
}

fn deterministic_master_seed(seed: u64) -> [u8; 32] {
    let mut rng = StdRng::seed_from_u64(seed);
    rng.random()
}

fn domain_rng(master_seed: &[u8; 32], domain: &[u8]) -> StdRng {
    let mut hasher = Sha256::new();
    hasher.update(b"hegemon-m4-zk-pay1x2-prototype-v1");
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update(master_seed);
    StdRng::from_seed(hasher.finalize().into())
}

fn verify_exact<H, Challenger_>(
    verifier: &ZKVerifier<H>,
    public: &[Word],
    proof: &[u8],
    transcript_context: Option<&[u8]>,
) -> bool
where
    H: HashSuite,
    Output<H::LeafHash>: DeserializeBytes,
    Challenger_: Challenger + Default,
{
    let mut transcript = VerifierTranscript::new(Challenger_::default(), proof.to_vec());
    if let Some(context) = transcript_context {
        transcript.observe().write_bytes(context);
    }
    verifier.verify(public, &mut transcript).is_ok() && transcript.finalize().is_ok()
}

fn proof_size_model<H>(
    cs: &ConstraintSystem,
    verifier: &ZKVerifier<H>,
    hash_mode: HashMode,
    rate: usize,
) -> serde_json::Value
where
    H: HashSuite,
{
    let selected_fri_bytes = fri_proof_bytes(verifier);
    let standard_fri_bytes = if hash_mode == HashMode::Standard {
        selected_fri_bytes
    } else {
        let standard = ZKVerifier::<StdHashSuite>::setup(cs.clone(), rate)
            .expect("the standard-hash comparison setup must succeed");
        fri_proof_bytes(&standard)
    };
    let standard_measured_bytes = WEAK_PROOF_BYTES[rate - 1];
    let hash_independent_bytes = standard_measured_bytes
        .checked_sub(standard_fri_bytes)
        .expect("the measured proof must include its FRI proof");
    let predicted_total_bytes = hash_independent_bytes + selected_fri_bytes;
    json!({
        "status": if hash_mode == HashMode::Standard {
            "measured-standard-baseline"
        } else {
            "exact-structural-prediction-not-measurement"
        },
        "standard_measured_proof_bytes": standard_measured_bytes,
        "standard_fri_bytes": standard_fri_bytes,
        "hash_independent_bytes": hash_independent_bytes,
        "selected_fri_bytes": selected_fri_bytes,
        "predicted_total_proof_bytes": predicted_total_bytes,
        "method": "standard measured total - exact standard FRI model + exact selected-hash FRI model",
        "transcript_context_serialized_bytes": 0
    })
}

fn fri_proof_bytes<H>(verifier: &ZKVerifier<H>) -> usize
where
    H: HashSuite,
{
    let merkle_scheme = BinaryMerkleTreeScheme::<B128, H>::new();
    fri::proof_size(verifier.basefold_compiler().fri_params(), &merkle_scheme)
}

fn strict_transcript_context(rate: usize) -> Vec<u8> {
    const ZK_PROFILE: &[u8] = b"hegemon.pay1x2-core.m4.zk-wrapper.active-and-blinding-128.v1";
    let strict = StrictTranscriptContext::new(rate);
    let mut context = Vec::with_capacity(strict.as_bytes().len() + ZK_PROFILE.len() + 24);
    context.extend_from_slice(b"HGM4ZKC1");
    context.extend_from_slice(&(strict.as_bytes().len() as u64).to_be_bytes());
    context.extend_from_slice(strict.as_bytes());
    context.extend_from_slice(&(ZK_PROFILE.len() as u64).to_be_bytes());
    context.extend_from_slice(ZK_PROFILE);
    context
}

fn parse_args() -> Args {
    let mut rate = DEFAULT_RATE;
    let mut deterministic_test_seed = None;
    let mut proof_out = None;
    let mut compare_freshness = false;
    let mut hash_mode = HashMode::Standard;
    let mut setup_only = false;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--rate" => {
                rate = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .filter(|value| (1..=6).contains(value))
                    .unwrap_or_else(|| usage("--rate requires an integer in 1..=6"));
            }
            "--seed" => {
                deterministic_test_seed = Some(
                    args.next()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or_else(|| usage("--seed requires a u64")),
                );
            }
            "--proof-out" => {
                proof_out = Some(
                    args.next()
                        .unwrap_or_else(|| usage("--proof-out requires a path")),
                );
            }
            "--compare-freshness" => compare_freshness = true,
            "--hash-mode" => {
                hash_mode = match args.next().as_deref() {
                    Some("standard") => HashMode::Standard,
                    Some("strict") => HashMode::Strict,
                    _ => usage("--hash-mode requires standard or strict"),
                };
            }
            "--setup-only" => setup_only = true,
            "-h" | "--help" => usage(""),
            _ => usage(&format!("unknown argument: {arg}")),
        }
    }
    Args {
        rate,
        deterministic_test_seed,
        proof_out,
        compare_freshness,
        hash_mode,
        setup_only,
    }
}

fn usage(error: &str) -> ! {
    if !error.is_empty() {
        eprintln!("{error}");
    }
    eprintln!(
        "usage: hegemon-m4-zk-pay1x2-prototype [--rate 1..6] [--seed U64] \
         [--hash-mode standard|strict] [--setup-only] [--compare-freshness] \
         [--proof-out PATH]"
    );
    process::exit(if error.is_empty() { 0 } else { 2 });
}
