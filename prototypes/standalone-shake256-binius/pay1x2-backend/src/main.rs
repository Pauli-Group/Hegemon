use std::{cell::Cell, env, process::ExitCode, time::Instant};

use binius_field::{arch::OptimalPackedB128, BinaryField128bGhash as B128};
use binius_hash::StdHashSuite;
use binius_spartan_frontend::{
    circuit_builder::{
        ConstraintBuilder, InstanceGenerator, PublicWire, WitnessGenerator, WitnessWire,
    },
    compiler::compile,
    constraint_system::{ConstraintSystem, ConstraintWire, Witness, WitnessLayout},
};
use binius_spartan_prover::Prover;
use binius_spartan_verifier::{config::StdChallenger, Verifier};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use hegemon_standalone_pay1x2_relation_prototype::{
    derive_statement_unchecked, valid_fixture, verify_relation, Pay1x2Statement, Pay1x2Witness,
    MAX_NOTE_VALUE,
};
use hegemon_standalone_pay1x2_statement_prototype::{
    adapt_action, adapt_canonical_action, verify_canonical_action_statement, BlockId48,
    CanonicalCiphertextBytes, ChainId32, NetworkBinding56, NetworkIdentity, ProspectiveActionId,
    ProspectiveCandidateArtifact, ProspectiveFamilyId, ProspectiveKernelBinding,
    ProspectivePay1x2InlineAction, ProspectiveStablecoinBinding, RulesHash48,
    CANONICAL_STATEMENT_BYTES, KAT_NETWORK_IDENTITY,
};
use hegemon_standalone_shake256_binius_backend::bytes_to_field_bits;
use hegemon_standalone_shake256_pay1x2_binius_backend::{
    allocate_pay1x2_wires, constrain_pay1x2, NoteWires, Pay1x2Wires, StatementWires, DIGEST_BITS,
    KECCAK_CHI_MULTIPLICATIONS, MERKLE_DEPTH, OFFSET_ANCHOR, OFFSET_BALANCE_TAG,
    OFFSET_CIPHERTEXT_0, OFFSET_CIPHERTEXT_1, OFFSET_FEE, OFFSET_NETWORK_BINDING, OFFSET_NULLIFIER,
    OFFSET_OUTPUT_0, OFFSET_OUTPUT_1, PAY1X2_SHAKE256_PERMUTATIONS, PRIVATE_WITNESS_BYTES,
    PUBLIC_STATEMENT_BYTES,
};
use hegemon_standalone_shake256_prototype::{NoteOpening, PROFILE_TAG};
use rand::{rngs::StdRng, SeedableRng};
use serde_json::{json, Value};
use standalone_proof_envelope_prototype::{
    encode_envelope, verify_envelope_exact, BackendId as EnvelopeBackendId,
    CanonicalStatement as EnvelopeCanonicalStatement, ProofBinding,
    ProofProfile as EnvelopeProofProfile, StandaloneProofVerifier,
    VerificationError as EnvelopeVerificationError, ENVELOPE_HEADER_BYTES, ENVELOPE_VERSION_V1,
};

const BACKEND_SCHEMA: &str = "hegemon.standalone-shake256.backend-measurement.v1";
const PROFILE: &str = "pay1x2";
const UPSTREAM_REVISION: &str = "3f96163049f680b2909f6545690bd929f1b48c44";
const RECIPIENT_CIPHERTEXT: &[u8] = b"canonical-recipient-ciphertext-v1";
const CHANGE_CIPHERTEXT: &[u8] = b"canonical-change-ciphertext-v1";

const EXTERNAL_BOOLEANITY_MULTIPLICATIONS: usize =
    (PRIVATE_WITNESS_BYTES + PUBLIC_STATEMENT_BYTES) * 8;
const NONZERO_MULTIPLICATIONS: usize = 4 * DIGEST_BITS;
const PATH_SWAP_MULTIPLICATIONS: usize = MERKLE_DEPTH * DIGEST_BITS;
const RIPPLE_CARRY_MULTIPLICATIONS: usize = 2 * 64 + 2 * 65;
const NON_HASH_MULTIPLICATIONS: usize = EXTERNAL_BOOLEANITY_MULTIPLICATIONS
    + NONZERO_MULTIPLICATIONS
    + PATH_SWAP_MULTIPLICATIONS
    + RIPPLE_CARRY_MULTIPLICATIONS;
const SOURCE_NONLINEAR_OPERATIONS: usize = KECCAK_CHI_MULTIPLICATIONS + NON_HASH_MULTIPLICATIONS;
// The frontend lowers private XORs and explicit equalities to additional
// Spartan constraint rows. This exact count is pinned separately from the
// source-level nonlinear operation inventory above.
const EXPECTED_COMPILED_CONSTRAINT_ROWS: usize = 1_883_192;
const PRIVATE_LINEAR_AND_EQUALITY_ROWS: usize =
    EXPECTED_COMPILED_CONSTRAINT_ROWS - SOURCE_NONLINEAR_OPERATIONS;

#[derive(Clone, Debug)]
struct Options {
    rates: Vec<usize>,
    deterministic_test: bool,
}

struct RateContext<'a> {
    constraint_system: &'a ConstraintSystem<B128>,
    base_layout: &'a WitnessLayout<B128>,
    wires: &'a Pay1x2Wires<ConstraintWire>,
    statement: &'a [u8; CANONICAL_STATEMENT_BYTES],
    relation_statement: &'a Pay1x2Statement,
    witness_value: &'a Pay1x2Witness,
    action: &'a ProspectivePay1x2InlineAction<'static>,
    deterministic_test: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BiniusEnvelopeVerificationError {
    BindingRouteMismatch,
    StatementLength(usize),
    ProofRejected,
}

type ComposedVerificationResult =
    Result<(), EnvelopeVerificationError<BiniusEnvelopeVerificationError>>;

struct CanonicalActionStatementSource<'action, 'ciphertext> {
    action: &'action ProspectivePay1x2InlineAction<'ciphertext>,
    network: NetworkIdentity,
    reconstruction_calls: Cell<usize>,
}

impl<'action, 'ciphertext> CanonicalActionStatementSource<'action, 'ciphertext> {
    fn new(
        action: &'action ProspectivePay1x2InlineAction<'ciphertext>,
        network: NetworkIdentity,
    ) -> Self {
        Self {
            action,
            network,
            reconstruction_calls: Cell::new(0),
        }
    }
}

impl EnvelopeCanonicalStatement for CanonicalActionStatementSource<'_, '_> {
    fn write_canonical_statement(&self, output: &mut Vec<u8>) -> Result<(), &'static str> {
        self.reconstruction_calls
            .set(self.reconstruction_calls.get() + 1);
        let reconstructed = adapt_canonical_action(self.action, self.network)
            .map_err(|_| "prospective action projection rejected")?;
        let encoded = reconstructed.encode();
        let verified = verify_canonical_action_statement(self.action, &encoded, self.network)
            .map_err(|_| "canonical action statement verification rejected")?;
        if verified != reconstructed {
            return Err("canonical action statement verification drifted");
        }
        output.extend_from_slice(&encoded);
        Ok(())
    }
}

struct PreparedPay1x2Verifier<'a> {
    verifier: &'a Verifier<B128, StdHashSuite>,
    layout: &'a WitnessLayout<B128>,
    wires: &'a Pay1x2Wires<ConstraintWire>,
    proof_calls: Cell<usize>,
}

impl<'a> PreparedPay1x2Verifier<'a> {
    fn new(
        verifier: &'a Verifier<B128, StdHashSuite>,
        layout: &'a WitnessLayout<B128>,
        wires: &'a Pay1x2Wires<ConstraintWire>,
    ) -> Self {
        Self {
            verifier,
            layout,
            wires,
            proof_calls: Cell::new(0),
        }
    }
}

impl StandaloneProofVerifier for PreparedPay1x2Verifier<'_> {
    type Error = BiniusEnvelopeVerificationError;

    fn backend(&self) -> EnvelopeBackendId {
        EnvelopeBackendId::Binius64IronSpartan
    }

    fn verify(&self, binding: ProofBinding<'_>, proof: &[u8]) -> Result<(), Self::Error> {
        self.proof_calls.set(self.proof_calls.get() + 1);
        if binding.envelope_version() != ENVELOPE_VERSION_V1
            || binding.backend() != EnvelopeBackendId::Binius64IronSpartan
            || binding.profile() != EnvelopeProofProfile::Pay1x2
        {
            return Err(BiniusEnvelopeVerificationError::BindingRouteMismatch);
        }
        let statement: &[u8; CANONICAL_STATEMENT_BYTES] =
            binding.canonical_statement().try_into().map_err(|_| {
                BiniusEnvelopeVerificationError::StatementLength(
                    binding.canonical_statement().len(),
                )
            })?;
        let public = build_public(self.layout, self.wires, statement);
        if uncomposed_raw_verify_exact_internal(self.verifier, &public, proof) {
            Ok(())
        } else {
            Err(BiniusEnvelopeVerificationError::ProofRejected)
        }
    }
}

#[derive(Debug)]
struct ComposedVerificationAttempt {
    result: ComposedVerificationResult,
    statement_reconstruction_calls: usize,
    proof_verification_calls: usize,
}

fn attempt_pay1x2_envelope_exact(
    prepared: &PreparedPay1x2Verifier<'_>,
    action: &ProspectivePay1x2InlineAction<'_>,
    network: NetworkIdentity,
    envelope: &[u8],
) -> ComposedVerificationAttempt {
    let source = CanonicalActionStatementSource::new(action, network);
    let proof_calls_before = prepared.proof_calls.get();
    let result = verify_envelope_exact(envelope, EnvelopeProofProfile::Pay1x2, &source, prepared);
    ComposedVerificationAttempt {
        result,
        statement_reconstruction_calls: source.reconstruction_calls.get(),
        proof_verification_calls: prepared.proof_calls.get() - proof_calls_before,
    }
}

fn verify_pay1x2_envelope_exact(
    prepared: &PreparedPay1x2Verifier<'_>,
    action: &ProspectivePay1x2InlineAction<'_>,
    network: NetworkIdentity,
    envelope: &[u8],
) -> ComposedVerificationResult {
    attempt_pay1x2_envelope_exact(prepared, action, network, envelope).result
}

#[derive(Debug)]
struct RateOutcome {
    log_inverse_rate: usize,
    canonical_proof_bytes: usize,
    padded_constraints: usize,
    setup_ms: f64,
    witness_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    honest_roundtrip: bool,
    all_public_mutations_rejected: bool,
    adapter_profile_mutation_rejected: bool,
    ciphertext_hash_mutation_rejected: bool,
    network_binding_mutation_rejected: bool,
    network_source_mutations_rejected: bool,
    balance_tag_mutation_rejected: bool,
    changed_proof_rejected: bool,
    trailing_proof_rejected: bool,
    recomputed_balance_violation_rejected: bool,
    recomputed_native_asset_violation_rejected: bool,
    recomputed_authorization_violation_rejected: bool,
    carry_boundary_valid: bool,
    carry_overflow_rejected: bool,
    range_boundary_rejected: bool,
    fresh_change_recipient_accepted: bool,
    envelope_admission: EnvelopeAdmissionChecks,
    action_projection: ActionProjectionChecks,
    fresh_forgery: FreshForgeryChecks,
}

impl RateOutcome {
    fn verification_passed(&self) -> bool {
        self.honest_roundtrip
            && self.all_public_mutations_rejected
            && self.adapter_profile_mutation_rejected
            && self.ciphertext_hash_mutation_rejected
            && self.network_binding_mutation_rejected
            && self.network_source_mutations_rejected
            && self.balance_tag_mutation_rejected
            && self.changed_proof_rejected
            && self.trailing_proof_rejected
            && self.recomputed_balance_violation_rejected
            && self.recomputed_native_asset_violation_rejected
            && self.recomputed_authorization_violation_rejected
            && self.carry_boundary_valid
            && self.carry_overflow_rejected
            && self.range_boundary_rejected
            && self.fresh_change_recipient_accepted
            && self.envelope_admission.passed()
            && self.action_projection.passed()
            && self.fresh_forgery.passed()
    }

    fn as_json(&self) -> Value {
        json!({
            "log_inverse_rate": self.log_inverse_rate,
            "canonical_proof_bytes": self.canonical_proof_bytes,
            "padded_constraints": self.padded_constraints,
            "setup_ms": self.setup_ms,
            "witness_ms": self.witness_ms,
            "prove_ms": self.prove_ms,
            "verify_ms": self.verify_ms,
            "verification": self.verification_json()
        })
    }

    fn verification_json(&self) -> Value {
        json!({
            "valid": self.honest_roundtrip,
            "mutation_rejected": self.all_public_mutations_rejected
                && self.changed_proof_rejected
                && self.recomputed_balance_violation_rejected
                && self.recomputed_native_asset_violation_rejected
                && self.recomputed_authorization_violation_rejected
                && self.envelope_admission.passed()
                && self.action_projection.passed()
                && self.fresh_forgery.passed(),
            "canonical_roundtrip": self.honest_roundtrip,
            "all_public_mutations_rejected": self.all_public_mutations_rejected,
            "adapter_profile_mutation_rejected": self.adapter_profile_mutation_rejected,
            "ciphertext_hash_mutation_rejected": self.ciphertext_hash_mutation_rejected,
            "network_binding_mutation_rejected": self.network_binding_mutation_rejected,
            "network_source_mutations_rejected": self.network_source_mutations_rejected,
            "balance_tag_mutation_rejected": self.balance_tag_mutation_rejected,
            "changed_proof_rejected": self.changed_proof_rejected,
            "trailing_proof_rejected": self.trailing_proof_rejected,
            "recomputed_balance_violation_rejected": self.recomputed_balance_violation_rejected,
            "recomputed_native_asset_violation_rejected": self.recomputed_native_asset_violation_rejected,
            "recomputed_authorization_violation_rejected": self.recomputed_authorization_violation_rejected,
            "carry_boundary_valid": self.carry_boundary_valid,
            "carry_overflow_rejected": self.carry_overflow_rejected,
            "range_boundary_rejected": self.range_boundary_rejected,
            "fresh_change_recipient_accepted": self.fresh_change_recipient_accepted,
            "envelope_admission": {
                "wrong_magic_rejected_before_projection": self.envelope_admission.wrong_magic_rejected_before_projection,
                "wrong_version_rejected_before_projection": self.envelope_admission.wrong_version_rejected_before_projection,
                "wrong_backend_rejected_before_projection": self.envelope_admission.wrong_backend_rejected_before_projection,
                "wrong_profile_rejected_before_projection": self.envelope_admission.wrong_profile_rejected_before_projection,
                "truncated_length_rejected_before_projection": self.envelope_admission.truncated_length_rejected_before_projection,
                "short_declared_length_rejected_before_projection": self.envelope_admission.short_declared_length_rejected_before_projection,
                "trailing_envelope_rejected_before_projection": self.envelope_admission.trailing_envelope_rejected_before_projection
            },
            "action_projection": {
                "wrong_kernel_binding_rejected_before_proof": self.action_projection.wrong_kernel_binding_rejected_before_proof,
                "wrong_family_route_rejected_before_proof": self.action_projection.wrong_family_route_rejected_before_proof,
                "wrong_action_route_rejected_before_proof": self.action_projection.wrong_action_route_rejected_before_proof,
                "wrong_ciphertext_count_rejected_before_proof": self.action_projection.wrong_ciphertext_count_rejected_before_proof,
                "wrong_ciphertext_size_count_rejected_before_proof": self.action_projection.wrong_ciphertext_size_count_rejected_before_proof,
                "wrong_ciphertext_size_rejected_before_proof": self.action_projection.wrong_ciphertext_size_rejected_before_proof,
                "wrong_nullifier_count_rejected_before_proof": self.action_projection.wrong_nullifier_count_rejected_before_proof,
                "wrong_commitment_count_rejected_before_proof": self.action_projection.wrong_commitment_count_rejected_before_proof,
                "wrong_balance_slot_count_rejected_before_proof": self.action_projection.wrong_balance_slot_count_rejected_before_proof,
                "wrong_native_slots_rejected_before_proof": self.action_projection.wrong_native_slots_rejected_before_proof,
                "nonzero_value_balance_rejected_before_proof": self.action_projection.nonzero_value_balance_rejected_before_proof,
                "stablecoin_rejected_before_proof": self.action_projection.stablecoin_rejected_before_proof,
                "candidate_artifact_rejected_before_proof": self.action_projection.candidate_artifact_rejected_before_proof,
                "wrong_network_binding_rejected_before_proof": self.action_projection.wrong_network_binding_rejected_before_proof,
                "wrong_binding_digest_rejected_before_proof": self.action_projection.wrong_binding_digest_rejected_before_proof
            },
            "fresh_forgery_negative_control": {
                "ciphertext_hash_raw_accepted": self.fresh_forgery.ciphertext_hash_raw_accepted,
                "ciphertext_hash_composed_rejected": self.fresh_forgery.ciphertext_hash_composed_rejected,
                "network_binding_raw_accepted": self.fresh_forgery.network_binding_raw_accepted,
                "network_binding_composed_rejected": self.fresh_forgery.network_binding_composed_rejected,
                "balance_tag_raw_accepted": self.fresh_forgery.balance_tag_raw_accepted,
                "balance_tag_composed_rejected": self.fresh_forgery.balance_tag_composed_rejected,
                "prove_ms": self.fresh_forgery.prove_ms
            }
        })
    }
}

fn usage() -> &'static str {
    "usage: hegemon-standalone-shake256-pay1x2-binius-backend [--rate 1..4]... [--deterministic-test]"
}

fn parse_options() -> Result<Options, String> {
    let mut rates = Vec::new();
    let mut deterministic_test = false;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--rate" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--rate requires a value".to_owned())?;
                rates.push(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --rate value {value:?}"))?,
                );
            }
            "--deterministic-test" => deterministic_test = true,
            "--help" | "-h" => return Err(usage().to_owned()),
            _ => return Err(format!("unknown argument {argument:?}; {}", usage())),
        }
    }
    if rates.is_empty() {
        rates = vec![1, 2, 3, 4];
    }
    rates.sort_unstable();
    rates.dedup();
    if rates.iter().any(|rate| !(1..=4).contains(rate)) {
        return Err("every --rate must be in 1..=4".to_owned());
    }
    Ok(Options {
        rates,
        deterministic_test,
    })
}

/// Uncomposed proof verification is deliberately private. Protocol callers
/// must use `verify_pay1x2_envelope_exact`; direct calls exist only for the
/// adversarial negative controls that demonstrate why composition is needed.
fn uncomposed_raw_verify_exact_internal(
    verifier: &Verifier<B128, StdHashSuite>,
    public: &[B128],
    proof: &[u8],
) -> bool {
    let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof.to_vec());
    if verifier.verify(public, &mut transcript).is_err() {
        return false;
    }
    transcript.finalize().is_ok()
}

fn canonical_statement(relation: &Pay1x2Statement) -> [u8; CANONICAL_STATEMENT_BYTES] {
    canonical_statement_for_network(relation, KAT_NETWORK_IDENTITY)
}

fn canonical_ciphertexts() -> [CanonicalCiphertextBytes<'static>; 2] {
    [
        CanonicalCiphertextBytes::from_validated_exact(RECIPIENT_CIPHERTEXT)
            .expect("fixed recipient ciphertext is canonical and nonempty"),
        CanonicalCiphertextBytes::from_validated_exact(CHANGE_CIPHERTEXT)
            .expect("fixed change ciphertext is canonical and nonempty"),
    ]
}

fn canonical_action(
    relation: &Pay1x2Statement,
    network: NetworkIdentity,
) -> ProspectivePay1x2InlineAction<'static> {
    ProspectivePay1x2InlineAction::from_relation(relation, canonical_ciphertexts(), network)
        .expect("valid scalar fixture must project into the prospective V5/Delta action")
}

fn canonical_statement_for_network(
    relation: &Pay1x2Statement,
    network: NetworkIdentity,
) -> [u8; CANONICAL_STATEMENT_BYTES] {
    adapt_action(relation, canonical_ciphertexts(), network)
        .expect("61-bit scalar statement must adapt")
        .encode()
}

fn network_source_mutations(relation: &Pay1x2Statement) -> Vec<[u8; CANONICAL_STATEMENT_BYTES]> {
    let mut chain_id = KAT_NETWORK_IDENTITY.chain_id.into_bytes();
    chain_id[0] ^= 1;
    let mut genesis = KAT_NETWORK_IDENTITY.genesis.into_bytes();
    genesis[0] ^= 1;
    let mut rules_hash = KAT_NETWORK_IDENTITY.rules_hash.into_bytes();
    rules_hash[0] ^= 1;
    [
        NetworkIdentity {
            chain_id: ChainId32::from_bytes(chain_id),
            ..KAT_NETWORK_IDENTITY
        },
        NetworkIdentity {
            genesis: BlockId48::from_bytes(genesis),
            ..KAT_NETWORK_IDENTITY
        },
        NetworkIdentity {
            rules_hash: RulesHash48::from_bytes(rules_hash),
            ..KAT_NETWORK_IDENTITY
        },
    ]
    .into_iter()
    .map(|network| canonical_statement_for_network(relation, network))
    .collect()
}

fn field_bits(bytes: &[u8], expected: usize) -> Vec<B128> {
    let values = bytes_to_field_bits(bytes);
    assert_eq!(values.len(), expected);
    values
}

fn placeholder_bits(
    generator: &mut InstanceGenerator<B128, &WitnessLayout<B128>>,
    wires: &[ConstraintWire],
) -> Vec<PublicWire<B128>> {
    wires
        .iter()
        .map(|&wire| generator.placeholder_precommit(wire))
        .collect()
}

fn write_instance_bits(
    generator: &mut InstanceGenerator<B128, &WitnessLayout<B128>>,
    wires: &[ConstraintWire],
    bytes: &[u8],
) -> Vec<PublicWire<B128>> {
    wires
        .iter()
        .zip(field_bits(bytes, wires.len()))
        .map(|(&wire, value)| generator.write_inout(wire, value))
        .collect()
}

fn write_witness_bits(
    generator: &mut WitnessGenerator<B128, &WitnessLayout<B128>>,
    wires: &[ConstraintWire],
    bytes: &[u8],
) -> Vec<WitnessWire<B128>> {
    wires
        .iter()
        .zip(field_bits(bytes, wires.len()))
        .map(|(&wire, value)| generator.write_precommit(wire, value))
        .collect()
}

fn write_witness_public_bits(
    generator: &mut WitnessGenerator<B128, &WitnessLayout<B128>>,
    wires: &[ConstraintWire],
    bytes: &[u8],
) -> Vec<WitnessWire<B128>> {
    wires
        .iter()
        .zip(field_bits(bytes, wires.len()))
        .map(|(&wire, value)| generator.write_inout(wire, value))
        .collect()
}

fn placeholder_note(
    generator: &mut InstanceGenerator<B128, &WitnessLayout<B128>>,
    wires: &NoteWires<ConstraintWire>,
) -> NoteWires<PublicWire<B128>> {
    NoteWires {
        value: placeholder_bits(generator, &wires.value),
        asset_id: placeholder_bits(generator, &wires.asset_id),
        pk_recipient: placeholder_bits(generator, &wires.pk_recipient),
        rho: placeholder_bits(generator, &wires.rho),
        randomness: placeholder_bits(generator, &wires.randomness),
        pk_auth: placeholder_bits(generator, &wires.pk_auth),
    }
}

fn write_note(
    generator: &mut WitnessGenerator<B128, &WitnessLayout<B128>>,
    wires: &NoteWires<ConstraintWire>,
    note: &NoteOpening,
) -> NoteWires<WitnessWire<B128>> {
    NoteWires {
        value: write_witness_bits(generator, &wires.value, &note.value.to_be_bytes()),
        asset_id: write_witness_bits(generator, &wires.asset_id, &note.asset_id.to_be_bytes()),
        pk_recipient: write_witness_bits(generator, &wires.pk_recipient, &note.pk_recipient),
        rho: write_witness_bits(generator, &wires.rho, &note.rho),
        randomness: write_witness_bits(generator, &wires.randomness, &note.randomness),
        pk_auth: write_witness_bits(generator, &wires.pk_auth, &note.pk_auth),
    }
}

fn build_public(
    layout: &WitnessLayout<B128>,
    base: &Pay1x2Wires<ConstraintWire>,
    statement: &[u8; CANONICAL_STATEMENT_BYTES],
) -> Vec<B128> {
    let mut generator = InstanceGenerator::new(layout);
    let mapped = Pay1x2Wires {
        spend_key: placeholder_bits(&mut generator, &base.spend_key),
        input_note: placeholder_note(&mut generator, &base.input_note),
        position: placeholder_bits(&mut generator, &base.position),
        siblings: base
            .siblings
            .iter()
            .map(|sibling| placeholder_bits(&mut generator, sibling))
            .collect(),
        output_notes: [
            placeholder_note(&mut generator, &base.output_notes[0]),
            placeholder_note(&mut generator, &base.output_notes[1]),
        ],
        statement: StatementWires {
            canonical: write_instance_bits(&mut generator, &base.statement.canonical, statement),
        },
    };
    constrain_pay1x2(&mut generator, &mapped);
    generator.build()
}

fn try_build_witness(
    layout: &WitnessLayout<B128>,
    base: &Pay1x2Wires<ConstraintWire>,
    statement: &[u8; CANONICAL_STATEMENT_BYTES],
    witness: &Pay1x2Witness,
) -> Option<Witness<B128>> {
    let mut generator = WitnessGenerator::new(layout);
    let mapped = Pay1x2Wires {
        spend_key: write_witness_bits(&mut generator, &base.spend_key, &witness.spend_key),
        input_note: write_note(&mut generator, &base.input_note, &witness.input.note),
        position: write_witness_bits(
            &mut generator,
            &base.position,
            &witness.input.position.to_be_bytes(),
        ),
        siblings: base
            .siblings
            .iter()
            .zip(&witness.input.siblings)
            .map(|(sibling_wires, sibling)| {
                write_witness_bits(&mut generator, sibling_wires, sibling.as_bytes())
            })
            .collect(),
        output_notes: [
            write_note(&mut generator, &base.output_notes[0], &witness.outputs[0]),
            write_note(&mut generator, &base.output_notes[1], &witness.outputs[1]),
        ],
        statement: StatementWires {
            canonical: write_witness_public_bits(
                &mut generator,
                &base.statement.canonical,
                statement,
            ),
        },
    };
    constrain_pay1x2(&mut generator, &mapped);
    generator.build().ok()
}

fn prove(
    prover: &Prover<OptimalPackedB128, StdHashSuite>,
    witness: &Witness<B128>,
    deterministic_test: bool,
    log_inverse_rate: usize,
    deterministic_domain: u64,
) -> Vec<u8> {
    let mut transcript = ProverTranscript::new(StdChallenger::default());
    if deterministic_test {
        let seed = 0x4845_4745_4d4f_4e02u64
            ^ log_inverse_rate as u64
            ^ deterministic_domain.rotate_left(17);
        let mut rng = StdRng::seed_from_u64(seed);
        prover
            .prove(witness, &mut rng, &mut transcript)
            .expect("honest deterministic-test proof generation must succeed");
    } else {
        let mut rng = rand::rng();
        prover
            .prove(witness, &mut rng, &mut transcript)
            .expect("honest OS-seeded proof generation must succeed");
    }
    transcript.finalize()
}

fn public_mutations(
    statement: &[u8; CANONICAL_STATEMENT_BYTES],
) -> Vec<[u8; CANONICAL_STATEMENT_BYTES]> {
    let mut mutations = Vec::new();
    for offset in [
        0,              // magic
        5,              // statement version
        7,              // circuit version
        9,              // crypto suite
        10,             // backend
        11,             // profile
        12,             // input count
        13,             // output count
        21,             // native asset
        OFFSET_FEE + 7, // fee
        OFFSET_ANCHOR,
        OFFSET_NULLIFIER,
        OFFSET_OUTPUT_0,
        OFFSET_OUTPUT_1,
        OFFSET_CIPHERTEXT_0,
        OFFSET_CIPHERTEXT_1,
        OFFSET_NETWORK_BINDING,
        OFFSET_BALANCE_TAG,
    ] {
        let mut changed = *statement;
        changed[offset] ^= 1;
        mutations.push(changed);
    }
    let mut fee_range = *statement;
    fee_range[OFFSET_FEE] |= 0x80;
    mutations.push(fee_range);
    for offset in [OFFSET_NULLIFIER, OFFSET_OUTPUT_0, OFFSET_OUTPUT_1] {
        let mut zero = *statement;
        zero[offset..offset + 56].fill(0);
        mutations.push(zero);
    }
    mutations
}

#[derive(Debug)]
struct RelationMutationChecks {
    recomputed_balance_violation_rejected: bool,
    recomputed_native_asset_violation_rejected: bool,
    recomputed_authorization_violation_rejected: bool,
    carry_boundary_valid: bool,
    carry_overflow_rejected: bool,
    range_boundary_rejected: bool,
    fresh_change_recipient_accepted: bool,
}

#[derive(Debug)]
struct EnvelopeAdmissionChecks {
    wrong_magic_rejected_before_projection: bool,
    wrong_version_rejected_before_projection: bool,
    wrong_backend_rejected_before_projection: bool,
    wrong_profile_rejected_before_projection: bool,
    truncated_length_rejected_before_projection: bool,
    short_declared_length_rejected_before_projection: bool,
    trailing_envelope_rejected_before_projection: bool,
}

impl EnvelopeAdmissionChecks {
    fn passed(&self) -> bool {
        self.wrong_magic_rejected_before_projection
            && self.wrong_version_rejected_before_projection
            && self.wrong_backend_rejected_before_projection
            && self.wrong_profile_rejected_before_projection
            && self.truncated_length_rejected_before_projection
            && self.short_declared_length_rejected_before_projection
            && self.trailing_envelope_rejected_before_projection
    }
}

#[derive(Debug)]
struct ActionProjectionChecks {
    wrong_kernel_binding_rejected_before_proof: bool,
    wrong_family_route_rejected_before_proof: bool,
    wrong_action_route_rejected_before_proof: bool,
    wrong_ciphertext_count_rejected_before_proof: bool,
    wrong_ciphertext_size_count_rejected_before_proof: bool,
    wrong_ciphertext_size_rejected_before_proof: bool,
    wrong_nullifier_count_rejected_before_proof: bool,
    wrong_commitment_count_rejected_before_proof: bool,
    wrong_balance_slot_count_rejected_before_proof: bool,
    wrong_native_slots_rejected_before_proof: bool,
    nonzero_value_balance_rejected_before_proof: bool,
    stablecoin_rejected_before_proof: bool,
    candidate_artifact_rejected_before_proof: bool,
    wrong_network_binding_rejected_before_proof: bool,
    wrong_binding_digest_rejected_before_proof: bool,
}

impl ActionProjectionChecks {
    fn passed(&self) -> bool {
        self.wrong_kernel_binding_rejected_before_proof
            && self.wrong_family_route_rejected_before_proof
            && self.wrong_action_route_rejected_before_proof
            && self.wrong_ciphertext_count_rejected_before_proof
            && self.wrong_ciphertext_size_count_rejected_before_proof
            && self.wrong_ciphertext_size_rejected_before_proof
            && self.wrong_nullifier_count_rejected_before_proof
            && self.wrong_commitment_count_rejected_before_proof
            && self.wrong_balance_slot_count_rejected_before_proof
            && self.wrong_native_slots_rejected_before_proof
            && self.nonzero_value_balance_rejected_before_proof
            && self.stablecoin_rejected_before_proof
            && self.candidate_artifact_rejected_before_proof
            && self.wrong_network_binding_rejected_before_proof
            && self.wrong_binding_digest_rejected_before_proof
    }
}

#[derive(Debug)]
struct FreshForgeryChecks {
    ciphertext_hash_raw_accepted: bool,
    ciphertext_hash_composed_rejected: bool,
    network_binding_raw_accepted: bool,
    network_binding_composed_rejected: bool,
    balance_tag_raw_accepted: bool,
    balance_tag_composed_rejected: bool,
    prove_ms: f64,
}

impl FreshForgeryChecks {
    fn passed(&self) -> bool {
        self.ciphertext_hash_raw_accepted
            && self.ciphertext_hash_composed_rejected
            && self.network_binding_raw_accepted
            && self.network_binding_composed_rejected
            && self.balance_tag_raw_accepted
            && self.balance_tag_composed_rejected
    }
}

fn relation_mutation_checks(
    layout: &WitnessLayout<B128>,
    wires: &Pay1x2Wires<ConstraintWire>,
    base: &Pay1x2Witness,
) -> RelationMutationChecks {
    let mut wrong_balance = base.clone();
    wrong_balance.outputs[0].value += 1;
    let wrong_balance_statement =
        derive_statement_unchecked(&wrong_balance, 3).expect("derive changed hashes");
    let wrong_balance_canonical = canonical_statement(&wrong_balance_statement);

    let mut wrong_asset = base.clone();
    wrong_asset.outputs[0].asset_id = 1;
    let wrong_asset_statement =
        derive_statement_unchecked(&wrong_asset, 3).expect("derive changed hashes");
    let wrong_asset_canonical = canonical_statement(&wrong_asset_statement);

    let mut wrong_auth = base.clone();
    wrong_auth.input.note.pk_auth[0] ^= 1;
    let wrong_auth_statement =
        derive_statement_unchecked(&wrong_auth, 3).expect("derive changed hashes");
    let wrong_auth_canonical = canonical_statement(&wrong_auth_statement);

    let mut boundary = base.clone();
    boundary.input.note.value = MAX_NOTE_VALUE;
    boundary.outputs[0].value = MAX_NOTE_VALUE - 2;
    boundary.outputs[1].value = 1;
    let boundary_statement = derive_statement_unchecked(&boundary, 1).expect("derive boundary");
    let boundary_canonical = canonical_statement(&boundary_statement);
    let scalar_boundary_valid = verify_relation(&boundary_statement, &boundary).is_ok();

    let mut carry_overflow = base.clone();
    carry_overflow.input.note.value = MAX_NOTE_VALUE;
    carry_overflow.outputs[0].value = MAX_NOTE_VALUE;
    carry_overflow.outputs[1].value = 1;
    let carry_overflow_statement =
        derive_statement_unchecked(&carry_overflow, 1).expect("derive carry overflow");
    let carry_overflow_canonical = canonical_statement(&carry_overflow_statement);

    let mut range = base.clone();
    range.input.note.value = MAX_NOTE_VALUE + 1;
    range.outputs[0].value = MAX_NOTE_VALUE;
    range.outputs[1].value = 0;
    let range_statement = derive_statement_unchecked(&range, 1).expect("derive range boundary");
    let range_canonical = canonical_statement(&range_statement);

    let mut fresh_change = base.clone();
    fresh_change.outputs[1].pk_recipient[0] ^= 1;
    let fresh_change_statement =
        derive_statement_unchecked(&fresh_change, 3).expect("derive fresh change");
    let fresh_change_canonical = canonical_statement(&fresh_change_statement);
    let scalar_fresh_change_valid = verify_relation(&fresh_change_statement, &fresh_change).is_ok();

    RelationMutationChecks {
        recomputed_balance_violation_rejected: try_build_witness(
            layout,
            wires,
            &wrong_balance_canonical,
            &wrong_balance,
        )
        .is_none(),
        recomputed_native_asset_violation_rejected: try_build_witness(
            layout,
            wires,
            &wrong_asset_canonical,
            &wrong_asset,
        )
        .is_none(),
        recomputed_authorization_violation_rejected: try_build_witness(
            layout,
            wires,
            &wrong_auth_canonical,
            &wrong_auth,
        )
        .is_none(),
        carry_boundary_valid: scalar_boundary_valid
            && try_build_witness(layout, wires, &boundary_canonical, &boundary).is_some(),
        carry_overflow_rejected: verify_relation(&carry_overflow_statement, &carry_overflow)
            .is_err()
            && try_build_witness(layout, wires, &carry_overflow_canonical, &carry_overflow)
                .is_none(),
        range_boundary_rejected: verify_relation(&range_statement, &range).is_err()
            && try_build_witness(layout, wires, &range_canonical, &range).is_none(),
        fresh_change_recipient_accepted: scalar_fresh_change_valid
            && try_build_witness(layout, wires, &fresh_change_canonical, &fresh_change).is_some(),
    }
}

fn envelope_admission_checks(
    prepared: &PreparedPay1x2Verifier<'_>,
    action: &ProspectivePay1x2InlineAction<'_>,
    envelope: &[u8],
) -> EnvelopeAdmissionChecks {
    let rejected_before_projection = |candidate: &[u8]| {
        let attempt =
            attempt_pay1x2_envelope_exact(prepared, action, KAT_NETWORK_IDENTITY, candidate);
        attempt.result.is_err()
            && attempt.statement_reconstruction_calls == 0
            && attempt.proof_verification_calls == 0
    };

    let mut wrong_magic = envelope.to_vec();
    wrong_magic[0] ^= 1;
    let mut wrong_version = envelope.to_vec();
    wrong_version[4] ^= 1;
    let mut wrong_backend = envelope.to_vec();
    wrong_backend[6] = 2;
    let mut wrong_profile = envelope.to_vec();
    wrong_profile[7] = EnvelopeProofProfile::Consolidate2x1 as u8;

    let declared = u32::from_le_bytes(
        envelope[8..12]
            .try_into()
            .expect("canonical envelope has a complete header"),
    );
    let mut truncated_length = envelope.to_vec();
    truncated_length[8..12].copy_from_slice(&(declared + 1).to_le_bytes());
    let mut short_declared_length = envelope.to_vec();
    short_declared_length[8..12].copy_from_slice(&(declared - 1).to_le_bytes());
    let mut trailing_envelope = envelope.to_vec();
    trailing_envelope.push(0);

    EnvelopeAdmissionChecks {
        wrong_magic_rejected_before_projection: rejected_before_projection(&wrong_magic),
        wrong_version_rejected_before_projection: rejected_before_projection(&wrong_version),
        wrong_backend_rejected_before_projection: rejected_before_projection(&wrong_backend),
        wrong_profile_rejected_before_projection: rejected_before_projection(&wrong_profile),
        truncated_length_rejected_before_projection: rejected_before_projection(&truncated_length),
        short_declared_length_rejected_before_projection: rejected_before_projection(
            &short_declared_length,
        ),
        trailing_envelope_rejected_before_projection: rejected_before_projection(
            &trailing_envelope,
        ),
    }
}

fn action_projection_checks(
    prepared: &PreparedPay1x2Verifier<'_>,
    action: &ProspectivePay1x2InlineAction<'_>,
    envelope: &[u8],
) -> ActionProjectionChecks {
    let rejected_before_proof = |candidate: &ProspectivePay1x2InlineAction<'_>| {
        let attempt =
            attempt_pay1x2_envelope_exact(prepared, candidate, KAT_NETWORK_IDENTITY, envelope);
        matches!(
            attempt.result,
            Err(EnvelopeVerificationError::StatementReconstruction(_))
        ) && attempt.statement_reconstruction_calls == 1
            && attempt.proof_verification_calls == 0
    };

    let mut wrong_kernel = action.clone();
    wrong_kernel.kernel_binding = ProspectiveKernelBinding {
        circuit: 4,
        crypto: 4,
    };
    let mut wrong_family = action.clone();
    wrong_family.family_id = ProspectiveFamilyId(2);
    let mut wrong_action = action.clone();
    wrong_action.action_id = ProspectiveActionId(1);
    let mut ciphertext_count = action.clone();
    ciphertext_count.ciphertexts.pop();
    let mut ciphertext_size_count = action.clone();
    ciphertext_size_count.ciphertext_sizes.pop();
    let mut ciphertext_size = action.clone();
    ciphertext_size.ciphertext_sizes[0] += 1;
    let mut nullifier_count = action.clone();
    nullifier_count.nullifiers.clear();
    let mut commitment_count = action.clone();
    commitment_count.commitments.pop();
    let mut balance_slot_count = action.clone();
    balance_slot_count.balance_slot_asset_ids.pop();
    let mut native_slots = action.clone();
    native_slots.balance_slot_asset_ids[1] = 0;
    let mut value_balance = action.clone();
    value_balance.value_balance = 1;
    let mut stablecoin = action.clone();
    stablecoin.stablecoin = Some(ProspectiveStablecoinBinding {
        opaque_marker: [0x51; 32],
    });
    let mut candidate_artifact = action.clone();
    candidate_artifact.candidate_artifact = Some(ProspectiveCandidateArtifact {
        opaque_bytes: vec![0x52],
    });
    let mut network_binding = action.clone();
    let mut changed_network_binding = network_binding.network_binding.into_bytes();
    changed_network_binding[0] ^= 1;
    network_binding.network_binding = NetworkBinding56::from_bytes(changed_network_binding);
    let mut binding_digest = action.clone();
    binding_digest.binding_digest[0] ^= 1;

    ActionProjectionChecks {
        wrong_kernel_binding_rejected_before_proof: rejected_before_proof(&wrong_kernel),
        wrong_family_route_rejected_before_proof: rejected_before_proof(&wrong_family),
        wrong_action_route_rejected_before_proof: rejected_before_proof(&wrong_action),
        wrong_ciphertext_count_rejected_before_proof: rejected_before_proof(&ciphertext_count),
        wrong_ciphertext_size_count_rejected_before_proof: rejected_before_proof(
            &ciphertext_size_count,
        ),
        wrong_ciphertext_size_rejected_before_proof: rejected_before_proof(&ciphertext_size),
        wrong_nullifier_count_rejected_before_proof: rejected_before_proof(&nullifier_count),
        wrong_commitment_count_rejected_before_proof: rejected_before_proof(&commitment_count),
        wrong_balance_slot_count_rejected_before_proof: rejected_before_proof(&balance_slot_count),
        wrong_native_slots_rejected_before_proof: rejected_before_proof(&native_slots),
        nonzero_value_balance_rejected_before_proof: rejected_before_proof(&value_balance),
        stablecoin_rejected_before_proof: rejected_before_proof(&stablecoin),
        candidate_artifact_rejected_before_proof: rejected_before_proof(&candidate_artifact),
        wrong_network_binding_rejected_before_proof: rejected_before_proof(&network_binding),
        wrong_binding_digest_rejected_before_proof: rejected_before_proof(&binding_digest),
    }
}

struct ForgeryContext<'a> {
    prepared: &'a PreparedPay1x2Verifier<'a>,
    prover: &'a Prover<OptimalPackedB128, StdHashSuite>,
    layout: &'a WitnessLayout<B128>,
    wires: &'a Pay1x2Wires<ConstraintWire>,
    honest_statement: &'a [u8; CANONICAL_STATEMENT_BYTES],
    action: &'a ProspectivePay1x2InlineAction<'static>,
    witness_value: &'a Pay1x2Witness,
    deterministic_test: bool,
    log_inverse_rate: usize,
}

fn fresh_forgery_check(
    context: &ForgeryContext<'_>,
    offset: usize,
    deterministic_domain: u64,
) -> (bool, bool) {
    let mut forged_statement = *context.honest_statement;
    forged_statement[offset] ^= 1;
    let forged_witness = try_build_witness(
        context.layout,
        context.wires,
        &forged_statement,
        context.witness_value,
    )
    .expect("externally derived statement bytes are deliberately not relation outputs");
    let forged_proof = prove(
        context.prover,
        &forged_witness,
        context.deterministic_test,
        context.log_inverse_rate,
        deterministic_domain,
    );
    let forged_public = build_public(context.layout, context.wires, &forged_statement);
    let raw_accepted = uncomposed_raw_verify_exact_internal(
        context.prepared.verifier,
        &forged_public,
        &forged_proof,
    );
    let forged_envelope = encode_envelope(
        EnvelopeBackendId::Binius64IronSpartan,
        EnvelopeProofProfile::Pay1x2,
        &forged_proof,
    )
    .expect("fresh proof must fit the canonical envelope");
    let composed = attempt_pay1x2_envelope_exact(
        context.prepared,
        context.action,
        KAT_NETWORK_IDENTITY,
        &forged_envelope,
    );
    let composed_rejected = matches!(
        composed.result,
        Err(EnvelopeVerificationError::Backend(
            BiniusEnvelopeVerificationError::ProofRejected
        ))
    ) && composed.statement_reconstruction_calls == 1
        && composed.proof_verification_calls == 1;
    (raw_accepted, composed_rejected)
}

fn fresh_forgery_checks(context: &ForgeryContext<'_>) -> FreshForgeryChecks {
    let started = Instant::now();
    let (ciphertext_hash_raw_accepted, ciphertext_hash_composed_rejected) =
        fresh_forgery_check(context, OFFSET_CIPHERTEXT_0, 1);
    let (network_binding_raw_accepted, network_binding_composed_rejected) =
        fresh_forgery_check(context, OFFSET_NETWORK_BINDING, 2);
    let (balance_tag_raw_accepted, balance_tag_composed_rejected) =
        fresh_forgery_check(context, OFFSET_BALANCE_TAG, 3);
    FreshForgeryChecks {
        ciphertext_hash_raw_accepted,
        ciphertext_hash_composed_rejected,
        network_binding_raw_accepted,
        network_binding_composed_rejected,
        balance_tag_raw_accepted,
        balance_tag_composed_rejected,
        prove_ms: started.elapsed().as_secs_f64() * 1_000.0,
    }
}

fn run_rate(context: &RateContext<'_>, log_inverse_rate: usize) -> RateOutcome {
    let constraint_system = context.constraint_system;
    let base_layout = context.base_layout;
    let wires = context.wires;
    let statement = context.statement;
    let relation_statement = context.relation_statement;
    let witness_value = context.witness_value;
    let action = context.action;
    let deterministic_test = context.deterministic_test;
    let setup_started = Instant::now();
    let verifier = Verifier::<_, StdHashSuite>::setup(constraint_system.clone(), log_inverse_rate)
        .expect("upstream verifier setup must succeed");
    let prover = Prover::<OptimalPackedB128, StdHashSuite>::setup(&verifier)
        .expect("upstream prover setup must succeed");
    let setup_ms = setup_started.elapsed().as_secs_f64() * 1_000.0;
    let padded_constraints = verifier.constraint_system().mul_constraints().len();
    let layout = base_layout
        .clone()
        .with_blinding(*verifier.constraint_system().blinding_info());
    let prepared = PreparedPay1x2Verifier::new(&verifier, &layout, wires);

    let witness_started = Instant::now();
    let witness = try_build_witness(&layout, wires, statement, witness_value)
        .expect("scalar-valid Pay1x2 fixture must satisfy the binary circuit");
    verifier.constraint_system().validate(&witness);
    let public = build_public(&layout, wires, statement);
    assert_eq!(public, witness.public());
    let relation_checks = relation_mutation_checks(&layout, wires, witness_value);
    let witness_ms = witness_started.elapsed().as_secs_f64() * 1_000.0;

    let prove_started = Instant::now();
    let proof = prove(&prover, &witness, deterministic_test, log_inverse_rate, 0);
    let prove_ms = prove_started.elapsed().as_secs_f64() * 1_000.0;
    let envelope = encode_envelope(
        EnvelopeBackendId::Binius64IronSpartan,
        EnvelopeProofProfile::Pay1x2,
        &proof,
    )
    .expect("honest proof must fit the exact direct envelope");
    assert_eq!(envelope.len(), proof.len() + ENVELOPE_HEADER_BYTES);

    let verify_started = Instant::now();
    let honest_roundtrip =
        verify_pay1x2_envelope_exact(&prepared, action, KAT_NETWORK_IDENTITY, &envelope).is_ok();
    let verify_ms = verify_started.elapsed().as_secs_f64() * 1_000.0;
    assert!(
        honest_roundtrip,
        "honest proof must verify and consume exactly"
    );

    let all_public_mutations_rejected = public_mutations(statement).iter().all(|mutation| {
        let changed_public = build_public(&layout, wires, mutation);
        !uncomposed_raw_verify_exact_internal(&verifier, &changed_public, &proof)
    });
    assert!(all_public_mutations_rejected);

    let rejects_adapter_offset = |offset: usize| {
        let mut mutation = *statement;
        mutation[offset] ^= 1;
        let changed_public = build_public(&layout, wires, &mutation);
        !uncomposed_raw_verify_exact_internal(&verifier, &changed_public, &proof)
    };
    let adapter_profile_mutation_rejected = rejects_adapter_offset(11);
    let ciphertext_hash_mutation_rejected = rejects_adapter_offset(OFFSET_CIPHERTEXT_0);
    let network_binding_mutation_rejected = rejects_adapter_offset(OFFSET_NETWORK_BINDING);
    let network_source_mutations_rejected = network_source_mutations(relation_statement)
        .iter()
        .all(|mutation| {
            let changed_public = build_public(&layout, wires, mutation);
            !uncomposed_raw_verify_exact_internal(&verifier, &changed_public, &proof)
        });
    let balance_tag_mutation_rejected = rejects_adapter_offset(OFFSET_BALANCE_TAG);
    assert!(adapter_profile_mutation_rejected);
    assert!(ciphertext_hash_mutation_rejected);
    assert!(network_binding_mutation_rejected);
    assert!(network_source_mutations_rejected);
    assert!(balance_tag_mutation_rejected);

    let mut changed_proof = proof.clone();
    let changed_index = changed_proof.len() / 2;
    changed_proof[changed_index] ^= 1;
    let changed_envelope = encode_envelope(
        EnvelopeBackendId::Binius64IronSpartan,
        EnvelopeProofProfile::Pay1x2,
        &changed_proof,
    )
    .expect("changed proof length remains canonical");
    let changed_proof_rejected =
        verify_pay1x2_envelope_exact(&prepared, action, KAT_NETWORK_IDENTITY, &changed_envelope)
            .is_err();
    assert!(changed_proof_rejected);

    let mut trailing_proof = proof.clone();
    trailing_proof.push(0);
    let trailing_proof_envelope = encode_envelope(
        EnvelopeBackendId::Binius64IronSpartan,
        EnvelopeProofProfile::Pay1x2,
        &trailing_proof,
    )
    .expect("proof-internal trailing byte remains below the envelope cap");
    let trailing_proof_rejected = verify_pay1x2_envelope_exact(
        &prepared,
        action,
        KAT_NETWORK_IDENTITY,
        &trailing_proof_envelope,
    )
    .is_err();
    assert!(trailing_proof_rejected);

    let envelope_admission = envelope_admission_checks(&prepared, action, &envelope);
    assert!(envelope_admission.passed());
    let action_projection = action_projection_checks(&prepared, action, &envelope);
    assert!(action_projection.passed());
    let fresh_forgery = fresh_forgery_checks(&ForgeryContext {
        prepared: &prepared,
        prover: &prover,
        layout: &layout,
        wires,
        honest_statement: statement,
        action,
        witness_value,
        deterministic_test,
        log_inverse_rate,
    });
    assert!(fresh_forgery.passed());

    RateOutcome {
        log_inverse_rate,
        canonical_proof_bytes: proof.len(),
        padded_constraints,
        setup_ms,
        witness_ms,
        prove_ms,
        verify_ms,
        honest_roundtrip,
        all_public_mutations_rejected,
        adapter_profile_mutation_rejected,
        ciphertext_hash_mutation_rejected,
        network_binding_mutation_rejected,
        network_source_mutations_rejected,
        balance_tag_mutation_rejected,
        changed_proof_rejected,
        trailing_proof_rejected,
        recomputed_balance_violation_rejected: relation_checks
            .recomputed_balance_violation_rejected,
        recomputed_native_asset_violation_rejected: relation_checks
            .recomputed_native_asset_violation_rejected,
        recomputed_authorization_violation_rejected: relation_checks
            .recomputed_authorization_violation_rejected,
        carry_boundary_valid: relation_checks.carry_boundary_valid,
        carry_overflow_rejected: relation_checks.carry_overflow_rejected,
        range_boundary_rejected: relation_checks.range_boundary_rejected,
        fresh_change_recipient_accepted: relation_checks.fresh_change_recipient_accepted,
        envelope_admission,
        action_projection,
        fresh_forgery,
    }
}

fn execute(options: Options) -> Value {
    let (relation_statement, witness_value) =
        valid_fixture().expect("build deterministic scalar fixture");
    verify_relation(&relation_statement, &witness_value)
        .expect("scalar fixture must satisfy relation");
    let action = canonical_action(&relation_statement, KAT_NETWORK_IDENTITY);
    let statement = adapt_canonical_action(&action, KAT_NETWORK_IDENTITY)
        .expect("authoritative action projection must reconstruct")
        .encode();
    verify_canonical_action_statement(&action, &statement, KAT_NETWORK_IDENTITY)
        .expect("authoritative action and exact statement must agree");

    let compile_started = Instant::now();
    let mut builder = ConstraintBuilder::<B128>::new();
    let wires = allocate_pay1x2_wires(&mut builder);
    constrain_pay1x2(&mut builder, &wires);
    let (constraint_system, layout) = compile(builder);
    let compile_ms = compile_started.elapsed().as_secs_f64() * 1_000.0;
    let compiled_constraints = constraint_system.mul_constraints().len();
    assert_eq!(
        compiled_constraints, EXPECTED_COMPILED_CONSTRAINT_ROWS,
        "the fixed relation constraint-row inventory drifted"
    );
    let compiled_private_wires = constraint_system.n_private();
    let compiled_precommit_wires = constraint_system.n_precommit();
    let compiled_public_wires = constraint_system.n_public();

    let rate_context = RateContext {
        constraint_system: &constraint_system,
        base_layout: &layout,
        wires: &wires,
        statement: &statement,
        relation_statement: &relation_statement,
        witness_value: &witness_value,
        action: &action,
        deterministic_test: options.deterministic_test,
    };
    let outcomes: Vec<_> = options
        .rates
        .iter()
        .copied()
        .map(|rate| run_rate(&rate_context, rate))
        .collect();
    let selected = outcomes
        .iter()
        .min_by_key(|outcome| outcome.canonical_proof_bytes)
        .expect("at least one rate is required");
    assert!(outcomes.iter().all(RateOutcome::verification_passed));

    json!({
        "schema": BACKEND_SCHEMA,
        "profile": PROFILE,
        "canonical_proof_bytes": selected.canonical_proof_bytes,
        "envelope_bytes": selected.canonical_proof_bytes + ENVELOPE_HEADER_BYTES,
        "prove_ms": selected.prove_ms,
        "verify_ms": selected.verify_ms,
        "peak_rss_bytes": Value::Null,
        "shake256_permutations": PAY1X2_SHAKE256_PERMUTATIONS,
        "security_profile": {
            "status": "unsupported",
            "release_qualified": false,
            "semantic_hash": "SHAKE256-448",
            "proof_hash": "SHA-256 StdHashSuite (target: SHAKE256-512)",
            "challenge_field": "GF(2^128) BinaryField128bGhash (target: GF(2^384))",
            "fri_classical_bits": binius_spartan_verifier::SECURITY_BITS,
            "qrom_accounting_complete": false,
            "composed_pq_bits": Value::Null,
            "zero_knowledge": false,
            "upstream_protocol_claims_zero_knowledge": true,
            "limitation": "Upstream fixes 96 query-security bits, SHA-256 proof hashing, and GF(2^128); the Hegemon-specific end-to-end ZK and composed strict-PQ128 arguments are incomplete."
        },
        "verification": selected.verification_json(),
        "coverage": {
            "full_pay1x2_cryptographic_core": true,
            "canonical_action_adapter_public_binding": true,
            "canonical_action_adapter_node_recomputation": true,
            "exact_hgsp_envelope_composition": true,
            "prospective_kernel_route": "V5/Delta family=1 action=7",
            "geometry_proxy": false,
            "native_asset_only": true,
            "description": "actual one-input/two-output native Pay1x2 core composed behind exact HGSP parsing and authoritative prospective V5/Delta action plus network reconstruction; exact wallet ciphertext parsing remains an explicit caller premise"
        },
        "semantic_registry": {
            "profile_tag_ascii": String::from_utf8_lossy(&PROFILE_TAG),
            "spend_key_bytes": 48,
            "rho_bytes": 48,
            "randomness_bytes": 48,
            "kdf_frame_bytes": 75,
            "note_frame_bytes": 229,
            "nullifier_frame_bytes": 135,
            "merkle_parent_frame_bytes": 133,
            "absorbed_bytes": 5_153,
            "balance_tag_in_relation": false,
            "canonical_statement_bytes": CANONICAL_STATEMENT_BYTES,
            "canonical_statement_bound_in_fiat_shamir": true
        },
        "constraint_system": {
            "compiled_constraints": compiled_constraints,
            "expected_compiled_constraints": EXPECTED_COMPILED_CONSTRAINT_ROWS,
            "compiled_precommit_wires": compiled_precommit_wires,
            "compiled_private_wires": compiled_private_wires,
            "compiled_public_wires": compiled_public_wires,
            "private_witness_bytes": PRIVATE_WITNESS_BYTES,
            "public_statement_bytes": PUBLIC_STATEMENT_BYTES,
            "keccak_chi_multiplications": KECCAK_CHI_MULTIPLICATIONS,
            "external_booleanity_multiplications": EXTERNAL_BOOLEANITY_MULTIPLICATIONS,
            "path_swap_multiplications": PATH_SWAP_MULTIPLICATIONS,
            "nonzero_multiplications": NONZERO_MULTIPLICATIONS,
            "ripple_carry_multiplications": RIPPLE_CARRY_MULTIPLICATIONS,
            "non_hash_multiplications": NON_HASH_MULTIPLICATIONS,
            "source_nonlinear_operations": SOURCE_NONLINEAR_OPERATIONS,
            "private_linear_and_equality_rows": PRIVATE_LINEAR_AND_EQUALITY_ROWS,
            "compile_ms": compile_ms
        },
        "selected_log_inverse_rate": selected.log_inverse_rate,
        "rate_sweep": outcomes.iter().map(RateOutcome::as_json).collect::<Vec<_>>(),
        "rng": {
            "mode": if options.deterministic_test { "deterministic-test-only" } else { "OS-seeded thread CSPRNG" },
            "production_approved": false,
            "warning": if options.deterministic_test {
                "The deterministic seed is only for repeatable measurements and must never be used by a production prover."
            } else {
                "Fresh OS-seeded randomness is exercised, but this prototype remains non-production for independent security reasons."
            }
        },
        "upstream": {
            "repository": "https://github.com/binius-zk/binius64.git",
            "revision": UPSTREAM_REVISION,
            "rust_toolchain": "1.97.1"
        }
    })
}

fn main() -> ExitCode {
    let options = match parse_options() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let result = execute(options);
    println!(
        "{}",
        serde_json::to_string(&result).expect("measurement JSON must serialize")
    );
    ExitCode::SUCCESS
}
