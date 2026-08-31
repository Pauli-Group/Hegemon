//! End-to-end harness for the dormant full BLAKE2b-384 SmallWood relation.
//!
//! This binary is intentionally fail-closed until a reviewed BLAKE2b-to-
//! SmallWood lowering exposes a real prover/verifier.  It does not call the
//! active Poseidon prover, synthesize proof bytes, use projected sizes, or
//! count source-only rows as a proof measurement.  Once the lowering exists,
//! `prove_full_relation` and `verify_full_relation` are the only two seams
//! that need to be connected to it.

use std::{fmt, process, time::Instant};

use hegemon_field::GOLDILOCKS_MODULUS;
use hegemon_hash384::{blake2b_384_domain_hash, domains};
use protocol_versioning::SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING;
use serde::Serialize;
use transaction_circuit::constants::{BALANCE_SLOTS, MAX_INPUTS, NATIVE_ASSET_ID};
use transaction_circuit::hashing_pq::bytes48_to_felts;
use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
use transaction_circuit::smallwood_blake2b384_semantics::{
    build_smallwood_blake2b384_relation_material, smallwood_blake2b384_relation_schedule_digest,
    smallwood_blake2b384_v5_statement_and_schedule, SmallwoodBlake2b384RelationMaterial,
    SMALLWOOD_BLAKE2B384_HASH_CALL_COUNT,
};
use transaction_circuit::smallwood_frontend::{
    smallwood_blake2b384_boolean_relation_is_compiled, SmallwoodPrivateAuthWitness,
};
use transaction_circuit::smallwood_v5_envelope::{
    canonical_statement_from_values_and_balance_tag, decode_envelope_exact, encode_envelope,
    ensure_identical_envelope_bytes, verify_production_inline, SmallwoodV5ActionContext,
    SmallwoodV5BackendVerifier, SmallwoodV5ProofBinding, SmallwoodV5ProofSources,
    SMALLWOOD_V5_INLINE_ACTION_ID, SMALLWOOD_V5_RELATION_BINDING_BYTES,
    SMALLWOOD_V5_SHIELDED_FAMILY_ID,
};
use transaction_circuit::witness::TransactionWitness;

const NETWORK_ID: u32 = 0x4847_4d35;
const MEASUREMENT_SCHEMA: &str = "hegemon.smallwood.blake2b384.e2e.v1";
const MAXIMUM_ACTIVITY_MASK: u8 = 0b1111;

#[derive(Debug)]
enum RunnerError {
    Relation(String),
    Envelope(String),
    LoweringUnavailable(&'static str),
    Backend(String),
    Schema(String),
}

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relation(message) => write!(formatter, "relation: {message}"),
            Self::Envelope(message) => write!(formatter, "envelope: {message}"),
            Self::LoweringUnavailable(message) => {
                write!(formatter, "lowering unavailable: {message}")
            }
            Self::Backend(message) => write!(formatter, "backend: {message}"),
            Self::Schema(message) => write!(formatter, "schema: {message}"),
        }
    }
}

impl std::error::Error for RunnerError {}

#[derive(Clone, Debug)]
struct FullRelationProof {
    /// Canonical bytes emitted by the compiled SmallWood backend.  This field
    /// must never be populated by a size formula or a test fixture.
    proof_bytes: Vec<u8>,
    /// Exact compiled geometry reported by the backend, not a projection.
    geometry: CompiledProofGeometry,
}

#[derive(Clone, Debug, Serialize)]
struct CompiledProofGeometry {
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    constraint_count: usize,
    public_value_count: usize,
    witness_value_count: usize,
    /// Every packed row has one lane shape; a flat div64 adapter that lets
    /// residual evaluation collapse distinct lanes is not admissible.
    lane_homogeneous_packing: bool,
    /// Public/constant identities are reconstructed by the verifier, never
    /// copied from secret-dependent witness material.
    verifier_owned_witness_independent_constraints: bool,
}

#[derive(Clone, Debug, Serialize)]
struct MutationGateReport {
    proof_byte_mutation_rejected: bool,
    statement_mutation_rejected: bool,
    truncated_envelope_rejected: bool,
    trailing_envelope_bytes_rejected: bool,
}

#[derive(Clone, Debug, Serialize)]
struct MeasurementRecord {
    schema: &'static str,
    status: &'static str,
    relation_profile: String,
    relation_schedule_digest_hex: String,
    production_authorized: bool,
    lowering_compiled: bool,
    actual_backend_invoked: bool,
    witness: WitnessShape,
    geometry: CompiledProofGeometry,
    statement_bytes: usize,
    proof_bytes: usize,
    envelope_bytes: usize,
    proof_blake2b384_hex: String,
    envelope_blake2b384_hex: String,
    prove_ms: u128,
    verify_ms: u128,
    restart_verify_ms: u128,
    mutation_gates: MutationGateReport,
}

#[derive(Clone, Debug, Serialize)]
struct WitnessShape {
    input_count: usize,
    output_count: usize,
    activity_mask: u8,
    hash_call_count: usize,
    framed_message_bytes: usize,
    compression_block_count: usize,
    output_bit_binding_constraints: usize,
    digest_reduction_constraints: usize,
    balance_slots: usize,
}

#[derive(Clone, Debug)]
struct RelationInstance {
    witness: TransactionWitness,
    auth: SmallwoodPrivateAuthWitness,
    relation_binding: [u8; SMALLWOOD_V5_RELATION_BINDING_BYTES],
    statement: [u8; 672],
}

impl RelationInstance {
    fn build() -> Result<Self, RunnerError> {
        let witness = maximum_two_by_two_witness()?;
        let auth = SmallwoodPrivateAuthWitness::default();
        let (public_values, balance_tag, relation_binding) =
            smallwood_blake2b384_v5_statement_and_schedule(&witness, &auth)
                .map_err(|error| RunnerError::Relation(error.to_string()))?;
        let statement =
            canonical_statement_from_values_and_balance_tag(&public_values, balance_tag)
                .map_err(|error| RunnerError::Envelope(error.to_string()))?;
        let expected_binding = smallwood_blake2b384_relation_schedule_digest();
        if relation_binding != expected_binding {
            return Err(RunnerError::Relation(
                "relation returned a schedule binding different from its fixed descriptor"
                    .to_owned(),
            ));
        }
        Ok(Self {
            witness,
            auth,
            relation_binding,
            statement,
        })
    }

    fn material(&self) -> Result<SmallwoodBlake2b384RelationMaterial, RunnerError> {
        build_smallwood_blake2b384_relation_material(&self.witness, &self.auth)
            .map_err(|error| RunnerError::Relation(error.to_string()))
    }
}

/// This is the sole backend integration seam.  A future implementation must
/// call the real full-relation SmallWood prover and return the exact proof
/// geometry it compiled.  The expected lowering API is an assignment-aware
/// entry point taking the already materialized `material`, the fixed relation
/// binding, and the canonical statement (and, where needed, the private
/// witness/auth opening), and returning canonical proof bytes plus
/// `CompiledProofGeometry`.  In particular, it must expose
/// lane-homogeneous packing and verifier-owned witness-independent constraints
/// as facts obtained from the compiled backend.  Keeping the unavailable arm
/// explicit prevents the historical Poseidon prover or the current flat
/// div64 adapter from being mistaken for a BLAKE2b proof.
fn prove_full_relation(
    _instance: &RelationInstance,
    _material: &SmallwoodBlake2b384RelationMaterial,
) -> Result<FullRelationProof, RunnerError> {
    if !smallwood_blake2b384_boolean_relation_is_compiled() {
        return Err(RunnerError::LoweringUnavailable(
            "the BLAKE2b Boolean relation is not compiled into SmallWood",
        ));
    }
    Err(RunnerError::LoweringUnavailable(
        "compiled relation has no public full-relation prover entrypoint yet",
    ))
}

/// Verify the backend proof against the exact relation statement.  This must
/// be replaced together with `prove_full_relation`; no parser-only or digest-
/// equality check is accepted as proof verification.  The backend receives
/// the `SmallwoodV5ProofBinding` so it can absorb the exact transport
/// preamble/statement in its transcript; it must not reconstruct those bytes
/// from secret-dependent witness values.
fn verify_full_relation(
    instance: &RelationInstance,
    binding: SmallwoodV5ProofBinding<'_>,
    _proof: &[u8],
) -> Result<(), RunnerError> {
    if binding.relation_binding() != &instance.relation_binding
        || binding.statement() != &instance.statement
    {
        return Err(RunnerError::Envelope(
            "backend binding does not match the relation-owned statement/binding".to_owned(),
        ));
    }
    if !smallwood_blake2b384_boolean_relation_is_compiled() {
        return Err(RunnerError::LoweringUnavailable(
            "the BLAKE2b Boolean relation is not compiled into SmallWood",
        ));
    }
    Err(RunnerError::LoweringUnavailable(
        "compiled relation has no public full-relation verifier entrypoint yet",
    ))
}

struct BackendVerifier<'a> {
    instance: &'a RelationInstance,
}

impl SmallwoodV5BackendVerifier for BackendVerifier<'_> {
    type Error = RunnerError;

    fn verify_exact(
        &self,
        binding: SmallwoodV5ProofBinding<'_>,
        proof: &[u8],
    ) -> Result<(), Self::Error> {
        verify_full_relation(self.instance, binding, proof)
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("smallwood_blake2b384_e2e: {error}");
        process::exit(2);
    }
}

fn run() -> Result<(), RunnerError> {
    let instance = RelationInstance::build()?;
    let material = instance.material()?;
    ensure_maximum_shape(&material)?;

    let prove_start = Instant::now();
    let proof = prove_full_relation(&instance, &material)?;
    let prove_ms = prove_start.elapsed().as_millis();
    if proof.proof_bytes.is_empty() {
        return Err(RunnerError::Backend(
            "compiled prover returned an empty proof".to_owned(),
        ));
    }
    if !proof.geometry.lane_homogeneous_packing
        || !proof
            .geometry
            .verifier_owned_witness_independent_constraints
    {
        return Err(RunnerError::Backend(
            "compiled geometry does not establish lane-homogeneous packing and verifier-owned witness-independent constraints"
                .to_owned(),
        ));
    }
    let envelope = encode_envelope(
        NETWORK_ID,
        instance.relation_binding,
        &instance.statement,
        &proof.proof_bytes,
    )
    .map_err(|error| RunnerError::Envelope(error.to_string()))?;
    let action = SmallwoodV5ActionContext {
        network_id: NETWORK_ID,
        version: SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING,
        family_id: SMALLWOOD_V5_SHIELDED_FAMILY_ID,
        action_id: SMALLWOOD_V5_INLINE_ACTION_ID,
        relation_binding: instance.relation_binding,
        canonical_statement: &instance.statement,
    };

    let verify_start = Instant::now();
    verify_transport(&instance, &envelope, action)?;
    let verify_ms = verify_start.elapsed().as_millis();

    // Simulate restart/persistence by decoding a fresh owned copy.  The exact
    // byte comparison is mandatory before the backend gets the bytes again.
    let persisted = envelope.clone();
    ensure_identical_envelope_bytes(&envelope, &persisted)
        .map_err(|error| RunnerError::Envelope(format!("restart byte drift: {error:?}")))?;
    let restart_start = Instant::now();
    verify_transport(&instance, &persisted, action)?;
    let restart_verify_ms = restart_start.elapsed().as_millis();

    let mutation_gates = run_mutation_gates(&instance, &envelope, action, &proof.proof_bytes)?;
    if !mutation_gates.proof_byte_mutation_rejected
        || !mutation_gates.statement_mutation_rejected
        || !mutation_gates.truncated_envelope_rejected
        || !mutation_gates.trailing_envelope_bytes_rejected
    {
        return Err(RunnerError::Backend(
            "one or more canonical mutation gates accepted a mutation".to_owned(),
        ));
    }

    let witness = WitnessShape {
        input_count: instance.witness.inputs.len(),
        output_count: instance.witness.outputs.len(),
        activity_mask: material.activity_mask,
        hash_call_count: material.geometry.hash_call_count,
        framed_message_bytes: material.geometry.framed_message_bytes,
        compression_block_count: material.geometry.compression_block_count,
        output_bit_binding_constraints: material.geometry.output_bit_binding_constraints,
        digest_reduction_constraints: material.geometry.digest_reduction_constraints,
        balance_slots: BALANCE_SLOTS,
    };
    let record = MeasurementRecord {
        schema: MEASUREMENT_SCHEMA,
        status: "measured",
        relation_profile: "hegemon.smallwood.blake2b-384.full-relation.v5".to_owned(),
        relation_schedule_digest_hex: hex::encode(instance.relation_binding),
        production_authorized: false,
        lowering_compiled: true,
        actual_backend_invoked: true,
        witness,
        geometry: proof.geometry,
        statement_bytes: instance.statement.len(),
        proof_bytes: proof.proof_bytes.len(),
        envelope_bytes: envelope.len(),
        proof_blake2b384_hex: hex::encode(blake2b_384_domain_hash(
            domains::TRANSACTION_PROOF_ARTIFACT_V2,
            [proof.proof_bytes.as_slice()],
        )),
        envelope_blake2b384_hex: hex::encode(blake2b_384_domain_hash(
            domains::TRANSACTION_PROOF_ARTIFACT_V2,
            [envelope.as_slice()],
        )),
        prove_ms,
        verify_ms,
        restart_verify_ms,
        mutation_gates,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&record)
            .map_err(|error| RunnerError::Schema(error.to_string()))?
    );
    Ok(())
}

fn verify_transport(
    instance: &RelationInstance,
    envelope: &[u8],
    action: SmallwoodV5ActionContext<'_>,
) -> Result<(), RunnerError> {
    let decoded = decode_envelope_exact(envelope)
        .map_err(|error| RunnerError::Envelope(error.to_string()))?;
    if decoded.relation_binding != instance.relation_binding
        || decoded.statement != &instance.statement
    {
        return Err(RunnerError::Envelope(
            "decoded bytes do not match the relation-owned statement/binding".to_owned(),
        ));
    }
    if action.version != SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING
        || action.family_id != SMALLWOOD_V5_SHIELDED_FAMILY_ID
        || action.action_id != SMALLWOOD_V5_INLINE_ACTION_ID
        || action.network_id != decoded.network_id
        || action.relation_binding != decoded.relation_binding
        || action.canonical_statement != decoded.statement
    {
        return Err(RunnerError::Envelope(
            "transport action does not bind the decoded canonical envelope".to_owned(),
        ));
    }
    let verifier = BackendVerifier { instance };
    // Keep this on the shipped V5 production-shaped route.  It is expected
    // to reject before backend work while the private capability lock is
    // false; a measured record is therefore emitted only after the reviewed
    // artifact/certificate path makes this route reach `verify_exact`.
    verify_production_inline(SmallwoodV5ProofSources::inline(envelope), action, &verifier)
        .map_err(|error| RunnerError::Backend(format!("{error:?}")))
}

fn run_mutation_gates(
    instance: &RelationInstance,
    envelope: &[u8],
    action: SmallwoodV5ActionContext<'_>,
    proof_bytes: &[u8],
) -> Result<MutationGateReport, RunnerError> {
    let mut proof_mutation = envelope.to_vec();
    let proof_offset = proof_mutation
        .len()
        .checked_sub(proof_bytes.len())
        .ok_or_else(|| RunnerError::Envelope("proof is not a suffix of its envelope".to_owned()))?;
    proof_mutation[proof_offset] ^= 1;
    let proof_byte_mutation_rejected = verify_transport(instance, &proof_mutation, action).is_err();

    let mut statement_mutation = envelope.to_vec();
    let statement_offset =
        transaction_circuit::smallwood_v5_envelope::SMALLWOOD_V5_ENVELOPE_HEADER_BYTES;
    statement_mutation[statement_offset] ^= 1;
    let statement_mutation_rejected =
        verify_transport(instance, &statement_mutation, action).is_err();

    let truncated_envelope_rejected = envelope
        .get(..envelope.len().saturating_sub(1))
        .map(|bytes| verify_transport(instance, bytes, action).is_err())
        .unwrap_or(true);
    let mut trailing = envelope.to_vec();
    trailing.push(0);
    let trailing_envelope_bytes_rejected = verify_transport(instance, &trailing, action).is_err();

    Ok(MutationGateReport {
        proof_byte_mutation_rejected,
        statement_mutation_rejected,
        truncated_envelope_rejected,
        trailing_envelope_bytes_rejected,
    })
}

fn ensure_maximum_shape(material: &SmallwoodBlake2b384RelationMaterial) -> Result<(), RunnerError> {
    if material.activity_mask != MAXIMUM_ACTIVITY_MASK
        || material.hash_calls.len() != SMALLWOOD_BLAKE2B384_HASH_CALL_COUNT
    {
        return Err(RunnerError::Relation(format!(
            "expected maximum 2x2 activity mask {MAXIMUM_ACTIVITY_MASK:#x} and {SMALLWOOD_BLAKE2B384_HASH_CALL_COUNT} hash calls, got mask {:#x} and {} calls",
            material.activity_mask,
            material.hash_calls.len()
        )));
    }
    Ok(())
}

fn maximum_two_by_two_witness() -> Result<TransactionWitness, RunnerError> {
    let sk_spend = [0x31; 32];
    let spend_auth =
        transaction_circuit::smallwood_blake2b384_semantics::smallwood_blake2b384_spend_auth_key(
            &sk_spend,
        )
        .map_err(|error| RunnerError::Relation(error.to_string()))?;
    let stablecoin_asset = 4_242;
    let inputs = vec![
        InputNoteWitness {
            note: NoteData {
                value: 13,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [0x11; 32],
                pk_auth: spend_auth,
                rho: [0x21; 32],
                r: [0x31; 32],
            },
            position: 0,
            rho_seed: [0x41; 32],
            merkle_path: MerklePath::default(),
        },
        InputNoteWitness {
            note: NoteData {
                value: 17,
                asset_id: stablecoin_asset,
                pk_recipient: [0x12; 32],
                pk_auth: spend_auth,
                rho: [0x22; 32],
                r: [0x32; 32],
            },
            position: 1,
            rho_seed: [0x42; 32],
            merkle_path: MerklePath::default(),
        },
    ];
    let outputs = vec![
        OutputNoteWitness {
            note: NoteData {
                value: 10,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [0x51; 32],
                pk_auth: [0x61; 32],
                rho: [0x71; 32],
                r: [0x81; 32],
            },
        },
        OutputNoteWitness {
            note: NoteData {
                value: 17,
                asset_id: stablecoin_asset,
                pk_recipient: [0x52; 32],
                pk_auth: [0x62; 32],
                rho: [0x72; 32],
                r: [0x82; 32],
            },
        },
    ];
    let mut witness = TransactionWitness {
        inputs,
        outputs,
        ciphertext_hashes: vec![field_bytes(0x91), field_bytes(0x92)],
        sk_spend,
        merkle_root: [0; 48],
        fee: 3,
        value_balance: 0,
        stablecoin: transaction_circuit::StablecoinPolicyBinding {
            enabled: true,
            asset_id: stablecoin_asset,
            policy_hash: field_bytes(0xa1),
            oracle_commitment: field_bytes(0xa2),
            attestation_commitment: field_bytes(0xa3),
            issuance_delta: 0,
            policy_version: 7,
        },
        version: SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING,
    };
    rebuild_blake2b_merkle_paths(&mut witness)?;
    witness
        .validate()
        .map_err(|error| RunnerError::Relation(error.to_string()))?;
    Ok(witness)
}

fn field_bytes(seed: u8) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    for (index, chunk) in bytes.chunks_exact_mut(8).enumerate() {
        chunk[7] = seed.wrapping_add(index as u8);
    }
    bytes
}

fn canonicalize_digest(raw: [u8; 48]) -> [u8; 48] {
    let mut canonical = [0u8; 48];
    for (index, chunk) in raw.chunks_exact(8).enumerate() {
        let raw_word = u64::from_be_bytes(chunk.try_into().expect("eight-byte digest limb"));
        let word = if raw_word >= GOLDILOCKS_MODULUS {
            raw_word - GOLDILOCKS_MODULUS
        } else {
            raw_word
        };
        canonical[index * 8..(index + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    canonical
}

fn blake_note_digest(note: &NoteData) -> [u8; 48] {
    let value = note.value.to_le_bytes();
    let asset = note.asset_id.to_le_bytes();
    canonicalize_digest(blake2b_384_domain_hash(
        domains::CRYPTO_NOTE_COMMITMENT_V2,
        [
            value.as_slice(),
            asset.as_slice(),
            &note.pk_recipient,
            &note.rho,
            &note.r,
            &note.pk_auth,
        ],
    ))
}

fn blake_merkle_node(left: &[u8; 48], right: &[u8; 48]) -> [u8; 48] {
    canonicalize_digest(blake2b_384_domain_hash(
        domains::TRANSACTION_MERKLE_NODE_V3,
        [left.as_slice(), right.as_slice()],
    ))
}

fn rebuild_blake2b_merkle_paths(witness: &mut TransactionWitness) -> Result<(), RunnerError> {
    if witness.inputs.len() != MAX_INPUTS {
        return Err(RunnerError::Relation(
            "maximum runner requires exactly two inputs".to_owned(),
        ));
    }
    let leaves = witness
        .inputs
        .iter()
        .map(|input| blake_note_digest(&input.note))
        .collect::<Vec<_>>();
    let zero = [0u8; 48];
    let mut root = blake_merkle_node(&leaves[0], &leaves[1]);
    for _ in 1..transaction_circuit::note::MERKLE_TREE_DEPTH {
        root = blake_merkle_node(&root, &zero);
    }
    for (index, input) in witness.inputs.iter_mut().enumerate() {
        let mut siblings = Vec::with_capacity(transaction_circuit::note::MERKLE_TREE_DEPTH);
        siblings.push(bytes48_to_felts(&leaves[1 - index]).ok_or_else(|| {
            RunnerError::Relation("noncanonical BLAKE leaf in Merkle path".to_owned())
        })?);
        for _ in 1..transaction_circuit::note::MERKLE_TREE_DEPTH {
            siblings.push(bytes48_to_felts(&zero).expect("zero is canonical"));
        }
        input.merkle_path = MerklePath { siblings };
    }
    witness.merkle_root = root;
    Ok(())
}
