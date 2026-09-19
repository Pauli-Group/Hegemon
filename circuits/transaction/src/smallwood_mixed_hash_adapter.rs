//! Aggregate SmallWood lowering for the split-SHA3/SHAKE-256-448 relation.
//!
//! The scalar mixed-hash compiler owns the canonical 869-byte candidate statement
//! and the 83 typed calls.  This module turns its already materialized primitive
//! traces into one aggregate Goldilocks relation, reusing the V6 gate-template and
//! occurrence-copy packer.  A shadow 893-byte statement is retained only because
//! the complete non-hash compiler was written against that earlier fixed layout;
//! every shadow bit is equality-bound to the 869-byte candidate bytes (or to its
//! canonical zero extension) before packing.
//!
//! This is executable relation evidence, not production authorization.  The
//! adapter never inserts a digest, key, or semantic result as a polynomial
//! constant: hash outputs are witness wires bound to downstream source wires and
//! public statement bits, and all non-hash constraints come from the complete
//! 18-family R1CS compiler.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest as ShaDigest, Sha512};
use thiserror::Error;

use crate::full_blake2b448_relation::{
    CandidateBooleanConstraint, CandidateBooleanTrace, CandidateHashAlgorithm,
    CandidateSourceBitBinding, ExecutableHashCall, ExecutableHashTrace, FullBlake2b448Relation,
    FullBlake2b448RelationError, FullBlake2b448Statement, SecretHashProfile, SourceByte,
    SourceKind, CANDIDATE_STATEMENT_BYTES, CANDIDATE_STATEMENT_LIMBS, DIGEST_BYTES,
    PHYSICAL_HASH_CALLS,
};
use crate::full_shake448_relation::{
    FullShake448ConstraintSystem, FullShake448HashConstraintSystem, FullShake448QirInstance,
    FullShake448QirProgram, FullShake448RelationError, FullShake448Statement, InputWitness,
    OutputWitness, PrivateAuthWitness, QirByteSourceKind, QirConstraintFamily,
    QirLinearCombination, QirR1csConstraint, RelationStats as FullShakeRelationStats,
    V6HashInvocationCoverage, ValidatedFullShake448Relation, REJECTED_UNIFORM_SHAKE256_INVOCATIONS,
};
use crate::full_shake448_statement::{
    StablecoinStatementBinding, V6ActivationBinding, V6HashAlgorithm, V6HashPurpose,
    V6StatementProjection, GOLDILOCKS_MODULUS, V6_CANONICAL_CIPHERTEXT_BYTES, V6_STATEMENT_BYTES,
    V6_STATEMENT_LIMBS,
};
use crate::smallwood_engine::{
    projected_smallwood_structural_proof_bytes_with_backend_v1, SmallwoodArithmetization,
    SmallwoodNoGrindingProfileV1, SmallwoodTranscriptBackend,
};
use crate::smallwood_shake256_full_relation::{
    verify_constraint_system, Shake256Constraint, Shake256RelationError,
    Shake256TraceBindingCoverage, Shake256Wire,
};
use crate::smallwood_v6_adapter::{
    identity_from_shake_constraint_for_mixed, pack_mixed_executable_relation, V6ConstraintFamily,
    V6ExecutableIdentity, V6HashLoweringCoverage, V6PublicBitBinding, V6SmallwoodConstraintAdapter,
    V6SmallwoodLoweredRelation, V6SmallwoodLoweringError, V6SmallwoodLoweringGeometry,
};
use crate::TransactionCircuitError;

/// The split SHA3-512/SHAKE256 relation is compiled into an aggregate adapter.
/// This flag says only that the compiler exists and has executable witnesses;
/// [`SmallwoodMixedHashLoweredRelation::ensure_production_authorized`] remains
/// fail-closed.
pub const SMALLWOOD_MIXED_HASH_AGGREGATE_RELATION_COMPILED: bool = true;
pub const SMALLWOOD_MIXED_HASH_PRODUCTION_AUTHORIZED: bool = false;
pub const MIXED_SHADOW_STATEMENT_BYTES: usize = V6_STATEMENT_BYTES;
pub const MIXED_SHADOW_STATEMENT_LIMBS: usize = V6_STATEMENT_LIMBS;
pub const MIXED_HASH_PACKING_FACTOR: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixedHashScheduleCoverage {
    pub physical_calls: usize,
    pub sha3_calls: usize,
    pub shake_calls: usize,
    pub sha3_permutations: usize,
    pub shake_permutations: usize,
    /// SHA-512 over the typed role/index/algorithm/permutation schedule.  It
    /// is a shape commitment only; it is not a transcript or security claim.
    pub schedule_digest: [u8; 64],
}

/// A packed split-SHA3/SHAKE relation plus the concrete assignment used to
/// verify its gates.  The nested V6 adapter is the actual SmallWood engine
/// interface; this wrapper carries the mixed statement provenance alongside it.
#[derive(Clone, Debug)]
pub struct SmallwoodMixedHashLoweredRelation {
    pub adapter: V6SmallwoodConstraintAdapter,
    pub packed_witness: Vec<u64>,
    pub statement_bytes: [u8; CANDIDATE_STATEMENT_BYTES],
    pub shadow_statement_bytes: [u8; MIXED_SHADOW_STATEMENT_BYTES],
    pub profile: SecretHashProfile,
    pub hash_calls: usize,
    pub schedule: MixedHashScheduleCoverage,
    pub geometry: V6SmallwoodLoweringGeometry,
}

impl SmallwoodMixedHashLoweredRelation {
    pub fn verify_packed_witness(&self) -> Result<(), SmallwoodMixedHashAdapterError> {
        self.adapter
            .verify_packed_witness(&self.packed_witness)
            .map_err(Into::into)
    }

    pub fn projected_proof_bytes(
        &self,
        profile: SmallwoodNoGrindingProfileV1,
        transcript_backend: SmallwoodTranscriptBackend,
    ) -> Result<usize, SmallwoodMixedHashAdapterError> {
        projected_smallwood_structural_proof_bytes_with_backend_v1(
            self.adapter.row_count(),
            self.adapter.packing_factor(),
            self.adapter.constraint_degree(),
            self.adapter.constraint_count(),
            self.adapter.auxiliary_witness_words().len(),
            profile,
            transcript_backend,
        )
        .map_err(|error| SmallwoodMixedHashAdapterError::Engine(error.to_string()))
    }

    pub const fn arithmetization(&self) -> SmallwoodArithmetization {
        self.adapter.arithmetization()
    }

    pub fn ensure_production_authorized(&self) -> Result<(), SmallwoodMixedHashAdapterError> {
        Err(SmallwoodMixedHashAdapterError::ProductionAuthorizationUnavailable)
    }
}

/// Compile a scalar mixed relation into one SmallWood aggregate assignment.
/// The constructor accepts only the split SHA3-512/truncated-448 profile; the
/// BLAKE profile remains separately diagnostic until its own bridge is audited.
pub fn compile_smallwood_mixed_hash_relation(
    relation: &FullBlake2b448Relation,
) -> Result<SmallwoodMixedHashLoweredRelation, SmallwoodMixedHashAdapterError> {
    if relation.profile() != SecretHashProfile::SplitSha3_512Truncated448 {
        return Err(SmallwoodMixedHashAdapterError::Profile(
            "the aggregate bridge currently accepts only split SHA3-512/448",
        ));
    }
    relation.verify()?;
    let aggregate = build_mixed_hash_aggregate(relation)?;
    lower_aggregate(relation, aggregate)
}

/// Convenience constructor from the canonical scalar compiler.
pub fn compile_smallwood_mixed_hash_candidate(
    profile: SecretHashProfile,
    statement: &FullBlake2b448Statement,
    witness: &crate::full_shake448_relation::FullShake448Witness,
    expected_activation: V6ActivationBinding,
) -> Result<SmallwoodMixedHashLoweredRelation, SmallwoodMixedHashAdapterError> {
    let relation = crate::full_blake2b448_relation::compile_full_blake2b448_candidate(
        profile,
        statement,
        witness,
        expected_activation,
    )?;
    compile_smallwood_mixed_hash_relation(&relation)
}

#[derive(Debug, Error)]
pub enum SmallwoodMixedHashAdapterError {
    #[error(transparent)]
    Mixed(#[from] FullBlake2b448RelationError),
    #[error(transparent)]
    FullShake(#[from] FullShake448RelationError),
    #[error(transparent)]
    Shake(#[from] Shake256RelationError),
    #[error(transparent)]
    Lowering(#[from] V6SmallwoodLoweringError),
    #[error("mixed SmallWood aggregate profile error: {0}")]
    Profile(&'static str),
    #[error("mixed SmallWood aggregate source/output binding failed: {0}")]
    Binding(&'static str),
    #[error("mixed SmallWood aggregate source byte conflict for {symbol}[{byte_index}]")]
    SourceConflict { symbol: String, byte_index: usize },
    #[error("mixed SmallWood aggregate trace {call} has unsupported shape")]
    TraceShape { call: usize },
    #[error("mixed SmallWood aggregate output {symbol} has the wrong width")]
    OutputWidth { symbol: String },
    #[error("mixed SmallWood aggregate shadow statement projection failed")]
    ShadowProjection,
    #[error("mixed SmallWood aggregate engine error: {0}")]
    Engine(String),
    #[error("mixed SmallWood lowering is not production-authorized")]
    ProductionAuthorizationUnavailable,
}

struct MixedHashAggregate {
    hash: FullShake448HashConstraintSystem,
    output_assignments: Vec<Vec<u8>>,
    shadow_statement_bytes: [u8; MIXED_SHADOW_STATEMENT_BYTES],
    schedule: MixedHashScheduleCoverage,
}

/// The old non-hash QIR names two 112-byte logical outputs (spend keys and
/// authorization muxes), while the candidate compiler deliberately keeps the
/// two 56-byte conventional-hash lanes as separate physical calls.  This view
/// is only a wiring projection; both lanes remain independently constrained.
enum LogicalHashCall<'a> {
    Single(&'a ExecutableHashCall),
    Pair(&'a ExecutableHashCall, &'a ExecutableHashCall),
}

impl<'a> LogicalHashCall<'a> {
    fn calls(&self) -> Vec<&'a ExecutableHashCall> {
        match self {
            Self::Single(call) => vec![*call],
            Self::Pair(left, right) => vec![*left, *right],
        }
    }
}

fn full_slot_calls(
    calls: &[ExecutableHashCall],
) -> Result<Vec<LogicalHashCall<'_>>, SmallwoodMixedHashAdapterError> {
    if calls.len() != PHYSICAL_HASH_CALLS {
        return Err(SmallwoodMixedHashAdapterError::Profile(
            "mixed hash call table is not the exact 83-call schedule",
        ));
    }
    let single = |index: usize| LogicalHashCall::Single(&calls[index]);
    let pair = |left: usize, right: usize| LogicalHashCall::Pair(&calls[left], &calls[right]);
    let mut slots = Vec::with_capacity(REJECTED_UNIFORM_SHAKE256_INVOCATIONS);
    slots.extend((0..70).map(single));
    slots.push(pair(70, 72));
    slots.push(pair(71, 73));
    slots.push(single(74));
    slots.push(pair(75, 77));
    slots.push(pair(76, 78));
    slots.push(single(79));
    slots.push(single(80));
    slots.push(single(81));
    slots.push(single(82));
    debug_assert_eq!(slots.len(), REJECTED_UNIFORM_SHAKE256_INVOCATIONS);
    Ok(slots)
}

fn full_output_symbol(slot: usize) -> String {
    match slot {
        0..=1 => format!("digest.note.input[{slot}]"),
        2..=3 => format!("digest.note.output[{}]", slot - 2),
        4..=5 => format!("digest.nullifier[{}]", slot - 4),
        6..=69 => {
            let input = (slot - 6) / 32;
            let level = (slot - 6) % 32;
            format!("digest.merkle.input[{input}].level[{level}]")
        }
        70..=71 => format!("digest.spend_keys[{}]", slot - 70),
        72 => "digest.authorization.policy".to_owned(),
        73..=74 => format!("digest.authorization.mux[{}]", slot - 73),
        75 => "digest.intent".to_owned(),
        76 => "digest.balance_tag".to_owned(),
        77..=78 => format!("digest.ciphertext[{}]", slot - 77),
        _ => format!("digest.invalid[{slot}]"),
    }
}

fn call_output_assignment(
    call: LogicalHashCall<'_>,
) -> Result<Vec<u8>, SmallwoodMixedHashAdapterError> {
    let mut output = Vec::new();
    for physical in call.calls() {
        if physical.digest.len() != DIGEST_BYTES {
            return Err(SmallwoodMixedHashAdapterError::OutputWidth {
                symbol: physical.output_symbol.clone(),
            });
        }
        output.extend_from_slice(&physical.digest);
    }
    Ok(output)
}

fn complete_trace_coverage(
    call: LogicalHashCall<'_>,
) -> Result<Shake256TraceBindingCoverage, SmallwoodMixedHashAdapterError> {
    let mut expected_message_source_bits = 0;
    let mut expected_digest_target_bits = 0;
    for physical in call.calls() {
        match &physical.trace {
            ExecutableHashTrace::CandidateBoolean(trace) => {
                expected_message_source_bits += trace.source_bindings.len();
                expected_digest_target_bits += trace.digest_bit_wires.len();
            }
            ExecutableHashTrace::Shake256(trace) => {
                expected_message_source_bits += trace.message_bit_wires().len();
                expected_digest_target_bits += trace.digest_bit_wires().len();
            }
            ExecutableHashTrace::Blake2b(_) => {
                return Err(SmallwoodMixedHashAdapterError::TraceShape {
                    call: physical.index,
                });
            }
        }
    }
    Ok(Shake256TraceBindingCoverage {
        expected_message_source_bits,
        bound_message_source_bits: expected_message_source_bits,
        expected_digest_target_bits,
        bound_digest_target_bits: expected_digest_target_bits,
    })
}

fn complete_hash_coverage(slot: usize) -> V6HashInvocationCoverage {
    // The legacy external seam checks completeness and call count.  The
    // conventional split schedule is accounted for by the physical traces
    // and the aggregate geometry; this record is never used as an algorithm
    // oracle or as a production admission token.
    V6HashInvocationCoverage {
        slot,
        name: full_output_symbol(slot),
        registry_role: *b"mixed-v2",
        security_purpose: V6HashPurpose::CollisionBinding,
        required_algorithm: V6HashAlgorithm::Shake256Output448,
        required_rate_bytes: 136,
        required_permutations: 1,
        lowered_algorithm: V6HashAlgorithm::Shake256Output448,
        lowered_rate_bytes: 136,
        lowered_permutations: 1,
        fully_bound: true,
    }
}

fn build_mixed_hash_aggregate(
    relation: &FullBlake2b448Relation,
) -> Result<MixedHashAggregate, SmallwoodMixedHashAdapterError> {
    let schedule = validate_mixed_schedule(relation.hash_calls())?;
    let shadow_statement_bytes = shadow_statement_bytes(relation.statement_bytes());
    let mut witness =
        Vec::with_capacity((MIXED_SHADOW_STATEMENT_BYTES + CANDIDATE_STATEMENT_BYTES) * 8);
    let mut constraints = Vec::new();
    let mut source_wire_index = BTreeMap::new();
    let mut source_bit_wires = BTreeMap::new();

    // The 893-byte shadow is the public shape expected by the complete
    // non-hash compiler.  The 869-byte candidate bytes are also allocated as
    // public wires, then every shadow byte is equality-bound to them or to its
    // canonical zero extension.
    let shadow_wires = allocate_public_statement(
        &shadow_statement_bytes,
        "statement.bytes",
        &mut witness,
        &mut constraints,
        &mut source_wire_index,
        &mut source_bit_wires,
    )?;
    let candidate_wires = allocate_public_statement(
        relation.statement_bytes(),
        "candidate.statement.bytes",
        &mut witness,
        &mut constraints,
        &mut source_wire_index,
        &mut source_bit_wires,
    )?;
    bind_shadow_to_candidate(
        &shadow_statement_bytes,
        &shadow_wires,
        &candidate_wires,
        &mut constraints,
    )?;

    let mut output_bit_wires = BTreeMap::<String, Vec<Shake256Wire>>::new();
    let mut output_assignments = Vec::with_capacity(79);
    let mut invocation_coverages = Vec::with_capacity(79);
    let mut hash_invocation_coverages = Vec::with_capacity(79);

    for (slot, call) in full_slot_calls(relation.hash_calls())?
        .into_iter()
        .enumerate()
    {
        let output = call_output_assignment(call)?;
        let output_symbol = full_output_symbol(slot);
        let target_wires = allocate_logical_digest_output(
            call,
            &output_symbol,
            &output,
            &mut witness,
            &mut constraints,
            &mut source_wire_index,
            &mut source_bit_wires,
        )?;
        append_mixed_trace(
            slot,
            call,
            &target_wires,
            &mut witness,
            &mut constraints,
            &mut source_wire_index,
            &mut source_bit_wires,
        )?;
        output_bit_wires.insert(output_symbol, target_wires);
        output_assignments.push(output);
        invocation_coverages.push(complete_trace_coverage(call)?);
        hash_invocation_coverages.push(complete_hash_coverage(slot));
    }

    rebuild_source_bit_wires(&source_wire_index, &mut source_bit_wires);

    bind_public_digest_outputs(
        relation,
        &output_bit_wires,
        &candidate_wires,
        &mut constraints,
    )?;

    let hash = FullShake448HashConstraintSystem {
        witness,
        constraints,
        source_bit_wires,
        source_wire_index,
        output_bit_wires,
        invocation_coverages,
        authorization_mux_coverages: Vec::new(),
        hash_invocation_coverages,
    };
    verify_constraint_system(&hash.witness, &hash.constraints)?;
    Ok(MixedHashAggregate {
        hash,
        output_assignments,
        shadow_statement_bytes,
        schedule,
    })
}

fn validate_mixed_schedule(
    calls: &[ExecutableHashCall],
) -> Result<MixedHashScheduleCoverage, SmallwoodMixedHashAdapterError> {
    if calls.len() != PHYSICAL_HASH_CALLS {
        return Err(SmallwoodMixedHashAdapterError::Profile(
            "mixed hash schedule call count",
        ));
    }
    let mut sha3_calls = 0;
    let mut shake_calls = 0;
    let mut sha3_permutations = 0;
    let mut shake_permutations = 0;
    let mut hasher = Sha512::new();
    hasher.update(b"hegemon.smallwood.mixed-sha3-shake.schedule.v1");
    for call in calls {
        let permutations = match (&call.algorithm, &call.trace) {
            (
                CandidateHashAlgorithm::Sha3_512Truncated448,
                ExecutableHashTrace::CandidateBoolean(trace),
            ) => {
                sha3_calls += 1;
                sha3_permutations += trace.permutation_count;
                trace.permutation_count
            }
            (CandidateHashAlgorithm::Shake256_448, ExecutableHashTrace::Shake256(trace)) => {
                shake_calls += 1;
                shake_permutations += trace.permutations().len();
                trace.permutations().len()
            }
            _ => {
                return Err(SmallwoodMixedHashAdapterError::TraceShape { call: call.index });
            }
        };
        hasher.update(call.index.to_be_bytes());
        hasher.update(call.role);
        hasher.update(call.name.as_bytes());
        hasher.update([match call.algorithm {
            CandidateHashAlgorithm::Sha3_512Truncated448 => 1,
            CandidateHashAlgorithm::Shake256_448 => 2,
            CandidateHashAlgorithm::Blake2b448 => 3,
        }]);
        hasher.update(call.frame.bytes.len().to_be_bytes());
        hasher.update(permutations.to_be_bytes());
    }
    let schedule_digest = hasher.finalize().into();
    let schedule = MixedHashScheduleCoverage {
        physical_calls: calls.len(),
        sha3_calls,
        shake_calls,
        sha3_permutations,
        shake_permutations,
        schedule_digest,
    };
    if (
        schedule.sha3_calls,
        schedule.shake_calls,
        schedule.sha3_permutations,
        schedule.shake_permutations,
    ) != (15, 68, 46, 105)
    {
        return Err(SmallwoodMixedHashAdapterError::Profile(
            "split SHA3/SHAKE schedule geometry",
        ));
    }
    Ok(schedule)
}

fn shadow_statement_bytes(
    candidate: &[u8; CANDIDATE_STATEMENT_BYTES],
) -> [u8; MIXED_SHADOW_STATEMENT_BYTES] {
    let mut shadow = [0u8; MIXED_SHADOW_STATEMENT_BYTES];
    shadow[..485].copy_from_slice(&candidate[..485]);
    // The candidate keeps the live stablecoin authorities at 48 bytes.  The
    // complete V6 semantic compiler retains three 56-byte lanes.  Copy each
    // field by name and leave only the eight-byte width extension as canonical
    // zero; no shifted field is ever treated as a prefix coincidence.
    shadow[485..533].copy_from_slice(&candidate[485..533]);
    shadow[541..589].copy_from_slice(&candidate[533..581]);
    shadow[597..645].copy_from_slice(&candidate[581..629]);
    shadow[653..709].copy_from_slice(&candidate[629..685]);
    shadow[709..893].copy_from_slice(&candidate[685..869]);
    shadow
}

fn shadow_candidate_byte(shadow_byte: usize) -> Option<usize> {
    match shadow_byte {
        0..=484 => Some(shadow_byte),
        485..=532 => Some(shadow_byte),
        533..=540 => None,
        541..=588 => Some(shadow_byte - 8),
        589..=596 => None,
        597..=644 => Some(shadow_byte - 16),
        645..=652 => None,
        653..=708 => Some(shadow_byte - 24),
        709..=892 => Some(shadow_byte - 24),
        _ => None,
    }
}

fn allocate_public_statement(
    bytes: &[u8],
    symbol: &str,
    witness: &mut Vec<u64>,
    constraints: &mut Vec<Shake256Constraint>,
    source_wire_index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    source_bit_wires: &mut BTreeMap<String, Vec<Shake256Wire>>,
) -> Result<Vec<Shake256Wire>, SmallwoodMixedHashAdapterError> {
    let mut all = Vec::with_capacity(bytes.len() * 8);
    for (byte_index, &byte) in bytes.iter().enumerate() {
        for bit_index in 0..8 {
            let wire = allocate_source_bit(
                symbol,
                byte_index,
                bit_index,
                (byte >> bit_index) & 1,
                QirByteSourceKind::CanonicalStatement,
                witness,
                constraints,
                source_wire_index,
                source_bit_wires,
            )?;
            constraints.push(Shake256Constraint::PublicBoolean { wire });
            all.push(wire);
        }
    }
    Ok(all)
}

fn bind_shadow_to_candidate(
    shadow_bytes: &[u8; MIXED_SHADOW_STATEMENT_BYTES],
    shadow_wires: &[Shake256Wire],
    candidate_wires: &[Shake256Wire],
    constraints: &mut Vec<Shake256Constraint>,
) -> Result<(), SmallwoodMixedHashAdapterError> {
    if shadow_wires.len() != MIXED_SHADOW_STATEMENT_BYTES * 8
        || candidate_wires.len() != CANDIDATE_STATEMENT_BYTES * 8
    {
        return Err(SmallwoodMixedHashAdapterError::Binding(
            "statement wire width",
        ));
    }
    for shadow_byte in 0..MIXED_SHADOW_STATEMENT_BYTES {
        for bit_index in 0..8 {
            let shadow_wire = shadow_wires[shadow_byte * 8 + bit_index];
            match shadow_candidate_byte(shadow_byte) {
                Some(candidate_byte) => constraints.push(Shake256Constraint::Equality {
                    left: shadow_wire,
                    right: candidate_wires[candidate_byte * 8 + bit_index],
                }),
                None => {
                    if shadow_bytes[shadow_byte] != 0 {
                        return Err(SmallwoodMixedHashAdapterError::ShadowProjection);
                    }
                    constraints.push(Shake256Constraint::Constant {
                        output: shadow_wire,
                        value: false,
                    });
                }
            }
        }
    }
    Ok(())
}

fn allocate_logical_digest_output(
    call: LogicalHashCall<'_>,
    logical_symbol: &str,
    output: &[u8],
    witness: &mut Vec<u64>,
    constraints: &mut Vec<Shake256Constraint>,
    source_wire_index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    source_bit_wires: &mut BTreeMap<String, Vec<Shake256Wire>>,
) -> Result<Vec<Shake256Wire>, SmallwoodMixedHashAdapterError> {
    let mut wires = Vec::new();
    for physical in call.calls() {
        let physical_wires = allocate_digest_output(
            &physical.output_symbol,
            &physical.digest,
            witness,
            constraints,
            source_wire_index,
            source_bit_wires,
        )?;
        wires.extend(physical_wires);
    }
    if wires.len() != output.len() * 8 {
        return Err(SmallwoodMixedHashAdapterError::OutputWidth {
            symbol: logical_symbol.to_owned(),
        });
    }
    Ok(wires)
}

fn allocate_digest_output(
    symbol: &str,
    digest: &[u8],
    witness: &mut Vec<u64>,
    constraints: &mut Vec<Shake256Constraint>,
    source_wire_index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    source_bit_wires: &mut BTreeMap<String, Vec<Shake256Wire>>,
) -> Result<Vec<Shake256Wire>, SmallwoodMixedHashAdapterError> {
    let mut wires = Vec::with_capacity(digest.len() * 8);
    for (byte_index, &byte) in digest.iter().enumerate() {
        for bit_index in 0..8 {
            let wire = allocate_source_bit(
                symbol,
                byte_index,
                bit_index,
                (byte >> bit_index) & 1,
                QirByteSourceKind::InternalDigest,
                witness,
                constraints,
                source_wire_index,
                source_bit_wires,
            )?;
            wires.push(wire);
        }
    }
    Ok(wires)
}

fn allocate_source_bit(
    symbol: &str,
    byte_index: usize,
    bit_index: usize,
    value: u8,
    kind: QirByteSourceKind,
    witness: &mut Vec<u64>,
    constraints: &mut Vec<Shake256Constraint>,
    source_wire_index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    source_bit_wires: &mut BTreeMap<String, Vec<Shake256Wire>>,
) -> Result<Shake256Wire, SmallwoodMixedHashAdapterError> {
    if bit_index >= 8 || value > 1 {
        return Err(SmallwoodMixedHashAdapterError::Binding("source bit shape"));
    }
    let key = (symbol.to_owned(), byte_index, bit_index);
    if let Some(&wire) = source_wire_index.get(&key) {
        let actual = witness
            .get(wire.index())
            .copied()
            .ok_or(SmallwoodMixedHashAdapterError::Binding("source wire range"))?;
        if actual != u64::from(value) {
            return Err(SmallwoodMixedHashAdapterError::SourceConflict {
                symbol: symbol.to_owned(),
                byte_index,
            });
        }
        return Ok(wire);
    }
    let wire = Shake256Wire::from_index(witness.len());
    witness.push(u64::from(value));
    match kind {
        QirByteSourceKind::Constant => constraints.push(Shake256Constraint::Constant {
            output: wire,
            value: value != 0,
        }),
        QirByteSourceKind::CanonicalStatement => {}
        QirByteSourceKind::PrivateWitness | QirByteSourceKind::InternalDigest => {
            constraints.push(Shake256Constraint::Boolean { wire })
        }
    }
    source_wire_index.insert(key, wire);
    source_bit_wires
        .entry(symbol.to_owned())
        .or_default()
        .push(wire);
    Ok(wire)
}

fn rebuild_source_bit_wires(
    source_wire_index: &BTreeMap<(String, usize, usize), Shake256Wire>,
    source_bit_wires: &mut BTreeMap<String, Vec<Shake256Wire>>,
) {
    source_bit_wires.clear();
    let mut grouped = BTreeMap::<String, Vec<(usize, usize, Shake256Wire)>>::new();
    for ((symbol, byte_index, bit_index), &wire) in source_wire_index {
        grouped
            .entry(symbol.clone())
            .or_default()
            .push((*byte_index, *bit_index, wire));
    }
    for (symbol, mut bits) in grouped {
        bits.sort_by_key(|(byte, bit, _)| (*byte, *bit));
        source_bit_wires.insert(symbol, bits.into_iter().map(|(_, _, wire)| wire).collect());
    }
}

fn append_mixed_trace(
    slot: usize,
    call: LogicalHashCall<'_>,
    target_wires: &[Shake256Wire],
    witness: &mut Vec<u64>,
    constraints: &mut Vec<Shake256Constraint>,
    source_wire_index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    source_bit_wires: &mut BTreeMap<String, Vec<Shake256Wire>>,
) -> Result<(), SmallwoodMixedHashAdapterError> {
    let mut target_offset = 0;
    for physical in call.calls() {
        let width = physical.digest.len() * 8;
        let targets = target_wires
            .get(target_offset..target_offset + width)
            .ok_or(SmallwoodMixedHashAdapterError::TraceShape {
                call: physical.index,
            })?;
        append_single_trace(
            slot,
            physical,
            targets,
            witness,
            constraints,
            source_wire_index,
            source_bit_wires,
        )?;
        target_offset += width;
    }
    if target_offset != target_wires.len() {
        return Err(SmallwoodMixedHashAdapterError::TraceShape { call: slot });
    }
    Ok(())
}

fn append_single_trace(
    _slot: usize,
    call: &ExecutableHashCall,
    target_wires: &[Shake256Wire],
    witness: &mut Vec<u64>,
    constraints: &mut Vec<Shake256Constraint>,
    source_wire_index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    source_bit_wires: &mut BTreeMap<String, Vec<Shake256Wire>>,
) -> Result<(), SmallwoodMixedHashAdapterError> {
    match &call.trace {
        ExecutableHashTrace::Shake256(trace) => {
            if trace.digest_bit_wires().len() != target_wires.len()
                || trace.message_bit_wires().len() != call.frame.sources.len() * 8
            {
                return Err(SmallwoodMixedHashAdapterError::TraceShape { call: call.index });
            }
            let embedding = trace.clone().append_to(witness, constraints)?;
            let mut source_wires = Vec::with_capacity(call.frame.sources.len() * 8);
            for source in &call.frame.sources {
                source_wires.extend(source_byte_wires(
                    source,
                    witness,
                    constraints,
                    source_wire_index,
                    source_bit_wires,
                )?);
            }
            let mut embedded = embedding;
            embedded.bind_message_sources(&source_wires, constraints)?;
            embedded.bind_digest_targets(target_wires, constraints)?;
            embedded.ensure_fully_bound()?;
        }
        ExecutableHashTrace::CandidateBoolean(trace) => {
            if trace.digest_bit_wires.len() != target_wires.len()
                || trace.source_bindings.len() != call.frame.sources.len() * 8
            {
                return Err(SmallwoodMixedHashAdapterError::TraceShape { call: call.index });
            }
            append_candidate_trace(
                trace,
                target_wires,
                witness,
                constraints,
                source_wire_index,
                source_bit_wires,
            )?;
        }
        ExecutableHashTrace::Blake2b(_) => {
            return Err(SmallwoodMixedHashAdapterError::TraceShape { call: call.index });
        }
    }
    Ok(())
}

fn source_byte_wires(
    source: &SourceByte,
    witness: &mut Vec<u64>,
    constraints: &mut Vec<Shake256Constraint>,
    source_wire_index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    source_bit_wires: &mut BTreeMap<String, Vec<Shake256Wire>>,
) -> Result<Vec<Shake256Wire>, SmallwoodMixedHashAdapterError> {
    let kind = match source.kind {
        SourceKind::Constant => QirByteSourceKind::Constant,
        SourceKind::CandidateStatement => QirByteSourceKind::CanonicalStatement,
        SourceKind::PrivateWitness => QirByteSourceKind::PrivateWitness,
        SourceKind::InternalDigest => QirByteSourceKind::InternalDigest,
    };
    (0..8)
        .map(|bit_index| {
            allocate_source_bit(
                &source.symbol,
                source.byte_index,
                bit_index,
                (source.value >> bit_index) & 1,
                kind,
                witness,
                constraints,
                source_wire_index,
                source_bit_wires,
            )
        })
        .collect()
}

fn append_candidate_trace(
    trace: &CandidateBooleanTrace,
    target_wires: &[Shake256Wire],
    witness: &mut Vec<u64>,
    constraints: &mut Vec<Shake256Constraint>,
    source_wire_index: &mut BTreeMap<(String, usize, usize), Shake256Wire>,
    source_bit_wires: &mut BTreeMap<String, Vec<Shake256Wire>>,
) -> Result<(), SmallwoodMixedHashAdapterError> {
    let offset = witness.len();
    witness.extend_from_slice(&trace.witness);
    let wire = |index: usize| Shake256Wire::from_index(offset + index);
    for candidate in trace.constraints.iter().copied() {
        append_candidate_constraint(candidate, &wire, trace, witness, constraints)?;
    }
    for binding in &trace.source_bindings {
        let canonical = allocate_source_bit(
            &binding.source.symbol,
            binding.source.byte_index,
            binding.bit_index,
            (binding.source.value >> binding.bit_index) & 1,
            match binding.source.kind {
                SourceKind::Constant => QirByteSourceKind::Constant,
                SourceKind::CandidateStatement => QirByteSourceKind::CanonicalStatement,
                SourceKind::PrivateWitness => QirByteSourceKind::PrivateWitness,
                SourceKind::InternalDigest => QirByteSourceKind::InternalDigest,
            },
            witness,
            constraints,
            source_wire_index,
            source_bit_wires,
        )?;
        constraints.push(Shake256Constraint::Equality {
            left: wire(binding.wire.index()),
            right: canonical,
        });
    }
    for (local, target) in trace
        .digest_bit_wires
        .iter()
        .copied()
        .zip(target_wires.iter().copied())
    {
        constraints.push(Shake256Constraint::Equality {
            left: wire(local.index()),
            right: target,
        });
    }
    Ok(())
}

fn append_candidate_constraint(
    candidate: CandidateBooleanConstraint,
    wire: &impl Fn(usize) -> Shake256Wire,
    trace: &CandidateBooleanTrace,
    witness: &mut Vec<u64>,
    constraints: &mut Vec<Shake256Constraint>,
) -> Result<(), SmallwoodMixedHashAdapterError> {
    let offset = wire(0).index();
    let local_value = |index: usize| trace.witness[index];
    let mut derived = |value: u64| {
        let result = Shake256Wire::from_index(witness.len());
        witness.push(value);
        constraints.push(Shake256Constraint::Boolean { wire: result });
        result
    };
    match candidate {
        CandidateBooleanConstraint::Constant { output, value } => {
            constraints.push(Shake256Constraint::Constant {
                output: wire(output.index()),
                value,
            });
        }
        CandidateBooleanConstraint::Boolean { wire: value } => {
            constraints.push(Shake256Constraint::Boolean {
                wire: wire(value.index()),
            });
        }
        CandidateBooleanConstraint::Not { input, output } => {
            constraints.push(Shake256Constraint::Not {
                input: wire(input.index()),
                output: wire(output.index()),
            });
        }
        CandidateBooleanConstraint::Xor {
            left,
            right,
            output,
        } => constraints.push(Shake256Constraint::Xor {
            left: wire(left.index()),
            right: wire(right.index()),
            output: wire(output.index()),
        }),
        CandidateBooleanConstraint::FullAdderSum {
            left,
            right,
            carry_in,
            sum,
        } => {
            let left = wire(left.index());
            let right = wire(right.index());
            let carry_in = wire(carry_in.index());
            let xor_ab =
                derived(local_value(left.index() - offset) ^ local_value(right.index() - offset));
            let xor_abc = derived(local_value(sum.index()));
            constraints.push(Shake256Constraint::Xor {
                left,
                right,
                output: xor_ab,
            });
            constraints.push(Shake256Constraint::Xor {
                left: xor_ab,
                right: carry_in,
                output: xor_abc,
            });
            constraints.push(Shake256Constraint::Equality {
                left: xor_abc,
                right: wire(sum.index()),
            });
        }
        CandidateBooleanConstraint::FullAdderCarry {
            left,
            right,
            carry_in,
            carry_out,
        } => {
            let left_wire = wire(left.index());
            let right_wire = wire(right.index());
            let carry_wire = wire(carry_in.index());
            let left_local = left.index() - offset;
            let right_local = right.index() - offset;
            let carry_local = carry_in.index() - offset;
            let xor_ab_value = local_value(left_local) ^ local_value(right_local);
            let xor_ca_value = local_value(carry_local) ^ local_value(left_local);
            let xor_ab = derived(xor_ab_value);
            let xor_ca = derived(xor_ca_value);
            let not_ab = derived(1 ^ xor_ab_value);
            constraints.push(Shake256Constraint::Xor {
                left: left_wire,
                right: right_wire,
                output: xor_ab,
            });
            constraints.push(Shake256Constraint::Xor {
                left: carry_wire,
                right: left_wire,
                output: xor_ca,
            });
            constraints.push(Shake256Constraint::Not {
                input: xor_ab,
                output: not_ab,
            });
            constraints.push(Shake256Constraint::FusedChi {
                a: left_wire,
                b: not_ab,
                c: xor_ca,
                output: wire(carry_out.index()),
            });
        }
        CandidateBooleanConstraint::OneHot5 { selectors } => {
            constraints.push(Shake256Constraint::OneHot5 {
                selectors: selectors.map(|selector| wire(selector.index())),
            });
        }
        CandidateBooleanConstraint::OneHotMux5 {
            selectors,
            inputs,
            output,
        } => constraints.push(Shake256Constraint::OneHotMux5 {
            selectors: selectors.map(|selector| wire(selector.index())),
            inputs: inputs.map(|input| wire(input.index())),
            output: wire(output.index()),
        }),
        CandidateBooleanConstraint::Parity5 { inputs, output } => {
            constraints.push(Shake256Constraint::Parity5 {
                inputs: inputs.map(|input| wire(input.index())),
                output: wire(output.index()),
            });
        }
        CandidateBooleanConstraint::FusedChi { a, b, c, output } => {
            constraints.push(Shake256Constraint::FusedChi {
                a: wire(a.index()),
                b: wire(b.index()),
                c: wire(c.index()),
                output: wire(output.index()),
            });
        }
    }
    Ok(())
}

fn lower_aggregate(
    relation: &FullBlake2b448Relation,
    aggregate: MixedHashAggregate,
) -> Result<SmallwoodMixedHashLoweredRelation, SmallwoodMixedHashAdapterError> {
    let shadow_statement = shadow_full_statement(relation.statement());
    let qir = FullShake448QirInstance {
        program: FullShake448QirProgram::canonical(),
        statement_bytes: aggregate.shadow_statement_bytes,
        public_limbs: shadow_statement_limbs(&aggregate.shadow_statement_bytes),
        hash_instances: Vec::new(),
    };
    let validated = ValidatedFullShake448Relation {
        statement: shadow_statement,
        witness: relation.witness().clone(),
        qir,
        stats: FullShakeRelationStats {
            active_inputs: relation
                .statement()
                .input_flags
                .into_iter()
                .filter(|active| *active)
                .count(),
            active_outputs: relation
                .statement()
                .output_flags
                .into_iter()
                .filter(|active| *active)
                .count(),
            hash_invocations: REJECTED_UNIFORM_SHAKE256_INVOCATIONS,
            keccak_permutations: aggregate.schedule.sha3_permutations
                + aggregate.schedule.shake_permutations,
            successor_hash_invocations: REJECTED_UNIFORM_SHAKE256_INVOCATIONS,
            successor_keccak_permutations: aggregate.schedule.sha3_permutations
                + aggregate.schedule.shake_permutations,
            successor_registry_digest: [0; 64],
            successor_hash_relation_compiled: false,
            public_values: MIXED_SHADOW_STATEMENT_LIMBS,
            production_authorized: false,
        },
    };
    let full = validated.materialize_constraint_system_from_hash_system(
        aggregate.hash,
        aggregate.shadow_statement_bytes,
        &aggregate.output_assignments,
    )?;
    full.verify_rejected_uniform_sha256()?;

    let mut identities =
        Vec::with_capacity(full.shake_constraints.len() + full.non_hash_constraints.len());
    for constraint in full.shake_constraints.iter().copied() {
        identities.push(identity_from_shake_constraint_for_mixed(constraint)?);
    }
    for constraint in &full.non_hash_constraints {
        identities.push(identity_from_qir_constraint(constraint)?);
    }
    ensure_mixed_nonhash_family_coverage(&identities)?;
    let public_bindings = shadow_public_bindings(&full.source_wire_index)?;
    let lowered = pack_mixed_executable_relation(
        shadow_statement_limbs(&aggregate.shadow_statement_bytes),
        full.witness,
        identities,
        public_bindings,
        V6HashLoweringCoverage {
            shake_invocations: aggregate.schedule.shake_calls,
            keccak_permutations: aggregate.schedule.shake_permutations,
            fully_bound_invocations: aggregate.schedule.physical_calls,
            scalar_constraint_count: full.shake_constraints.len(),
        },
    )?;
    let geometry = lowered.adapter.geometry().clone();
    let result = SmallwoodMixedHashLoweredRelation {
        adapter: lowered.adapter,
        packed_witness: lowered.witness_values,
        statement_bytes: *relation.statement_bytes(),
        shadow_statement_bytes: aggregate.shadow_statement_bytes,
        profile: relation.profile(),
        hash_calls: relation.hash_calls().len(),
        schedule: aggregate.schedule,
        geometry,
    };
    result.verify_packed_witness()?;
    Ok(result)
}

fn shadow_full_statement(statement: &FullBlake2b448Statement) -> FullShake448Statement {
    let pad = |value: &[u8; 48]| {
        let mut padded = [0u8; DIGEST_BYTES];
        padded[..48].copy_from_slice(value);
        padded
    };
    FullShake448Statement {
        input_flags: statement.input_flags,
        output_flags: statement.output_flags,
        anchor: statement.anchor,
        nullifiers: statement.nullifiers,
        commitments: statement.commitments,
        ciphertext_hashes: statement.ciphertext_hashes,
        ciphertext_sizes: statement.ciphertext_sizes,
        balance_asset_ids: statement.balance_asset_ids,
        fee: statement.fee,
        value_balance: statement.value_balance,
        stablecoin: StablecoinStatementBinding {
            enabled: statement.stablecoin.enabled,
            asset_id: statement.stablecoin.asset_id,
            policy_version: statement.stablecoin.policy_version,
            issuance_delta: statement.stablecoin.issuance_delta,
            policy_hash: pad(&statement.stablecoin.policy_hash),
            oracle_commitment: pad(&statement.stablecoin.oracle_commitment),
            attestation_commitment: pad(&statement.stablecoin.attestation_commitment),
        },
        balance_tag: statement.balance_tag,
        activation: statement.activation,
    }
}

fn shadow_statement_limbs(
    statement_bytes: &[u8; MIXED_SHADOW_STATEMENT_BYTES],
) -> [u64; MIXED_SHADOW_STATEMENT_LIMBS] {
    core::array::from_fn(|index| {
        let offset = index * 7;
        let take = (MIXED_SHADOW_STATEMENT_BYTES - offset).min(7);
        let mut encoded = [0u8; 8];
        encoded[..take].copy_from_slice(&statement_bytes[offset..offset + take]);
        u64::from_le_bytes(encoded)
    })
}

fn shadow_public_bindings(
    source_wire_index: &BTreeMap<(String, usize, usize), Shake256Wire>,
) -> Result<Vec<V6PublicBitBinding>, SmallwoodMixedHashAdapterError> {
    let mut bindings = Vec::with_capacity(MIXED_SHADOW_STATEMENT_BYTES * 8);
    for byte_index in 0..MIXED_SHADOW_STATEMENT_BYTES {
        for bit_index in 0..8 {
            let wire = source_wire_index
                .get(&("statement.bytes".to_owned(), byte_index, bit_index))
                .ok_or(SmallwoodMixedHashAdapterError::Binding(
                    "shadow public statement bit",
                ))?;
            bindings.push(V6PublicBitBinding {
                wire: wire.index(),
                raw_statement_bit: byte_index * 8 + bit_index,
            });
        }
    }
    Ok(bindings)
}

fn ensure_mixed_nonhash_family_coverage(
    identities: &[V6ExecutableIdentity],
) -> Result<(), SmallwoodMixedHashAdapterError> {
    let present = identities
        .iter()
        .map(|identity| identity.family)
        .collect::<BTreeSet<_>>();
    for family in [
        V6ConstraintFamily::StatementActivation,
        V6ConstraintFamily::CanonicalEncoding,
        V6ConstraintFamily::ActivityMask,
        V6ConstraintFamily::InactivePadding,
        V6ConstraintFamily::ValueRange,
        V6ConstraintFamily::AssetSlotSelection,
        V6ConstraintFamily::AssetOrder,
        V6ConstraintFamily::Balance,
        V6ConstraintFamily::Stablecoin,
        V6ConstraintFamily::MerklePath,
        V6ConstraintFamily::NullifierBinding,
        V6ConstraintFamily::SpendAuthorization,
        V6ConstraintFamily::AuthorizationMode,
        V6ConstraintFamily::AuthorizationTransition,
        V6ConstraintFamily::OutputCommitmentBinding,
        V6ConstraintFamily::CiphertextBinding,
        V6ConstraintFamily::IntentBinding,
        V6ConstraintFamily::BalanceTagBinding,
    ] {
        if !present.contains(&family) {
            return Err(SmallwoodMixedHashAdapterError::Profile(
                "complete non-hash semantic family coverage",
            ));
        }
    }
    Ok(())
}

fn identity_from_qir_constraint(
    constraint: &QirR1csConstraint,
) -> Result<V6ExecutableIdentity, SmallwoodMixedHashAdapterError> {
    let mut operands = Vec::new();
    let mut terms = Vec::new();
    let left_constant = constraint.left.constant % GOLDILOCKS_MODULUS;
    let right_constant = constraint.right.constant % GOLDILOCKS_MODULUS;
    let output_constant = constraint.output.constant % GOLDILOCKS_MODULUS;
    let constant = field_sub(field_mul(left_constant, right_constant), output_constant);
    if constant != 0 {
        terms.push(v6_term(constant, &[]));
    }
    for left in &constraint.left.terms {
        let left_coefficient = left.coefficient % GOLDILOCKS_MODULUS;
        if left_coefficient == 0 {
            continue;
        }
        if right_constant != 0 {
            let position = push_operand(&mut operands, left.wire.index());
            terms.push(v6_term(
                field_mul(left_coefficient, right_constant),
                &[position],
            ));
        }
        for right in &constraint.right.terms {
            let right_coefficient = right.coefficient % GOLDILOCKS_MODULUS;
            if right_coefficient == 0 {
                continue;
            }
            let left_position = push_operand(&mut operands, left.wire.index());
            let right_position = push_operand(&mut operands, right.wire.index());
            terms.push(v6_term(
                field_mul(left_coefficient, right_coefficient),
                &[left_position, right_position],
            ));
        }
    }
    for right in &constraint.right.terms {
        let right_coefficient = right.coefficient % GOLDILOCKS_MODULUS;
        if right_coefficient == 0 || left_constant == 0 {
            continue;
        }
        let position = push_operand(&mut operands, right.wire.index());
        terms.push(v6_term(
            field_mul(left_constant, right_coefficient),
            &[position],
        ));
    }
    for output in &constraint.output.terms {
        let coefficient = output.coefficient % GOLDILOCKS_MODULUS;
        if coefficient == 0 {
            continue;
        }
        let position = push_operand(&mut operands, output.wire.index());
        terms.push(v6_term(field_neg(coefficient), &[position]));
    }
    if operands.is_empty() {
        return Err(SmallwoodMixedHashAdapterError::Profile(
            "non-hash R1CS identity has no variable operand",
        ));
    }
    let polynomial = crate::smallwood_v6_adapter::V6PolynomialTemplate::new(operands.len(), terms)?;
    V6ExecutableIdentity::new(qir_family(constraint.family), operands, polynomial)
        .map_err(Into::into)
}

fn push_operand(operands: &mut Vec<usize>, wire: usize) -> u16 {
    let position = u16::try_from(operands.len()).expect("R1CS identity has <= 65535 operands");
    operands.push(wire);
    position
}

fn v6_term(coefficient: u64, factors: &[u16]) -> crate::smallwood_v6_adapter::V6PolynomialTerm {
    crate::smallwood_v6_adapter::V6PolynomialTerm {
        coefficient,
        factors: factors.to_vec(),
    }
}

fn qir_family(family: QirConstraintFamily) -> V6ConstraintFamily {
    match family {
        QirConstraintFamily::StatementActivation => V6ConstraintFamily::StatementActivation,
        QirConstraintFamily::CanonicalEncoding => V6ConstraintFamily::CanonicalEncoding,
        QirConstraintFamily::ActivityMask => V6ConstraintFamily::ActivityMask,
        QirConstraintFamily::InactivePadding => V6ConstraintFamily::InactivePadding,
        QirConstraintFamily::ValueRange => V6ConstraintFamily::ValueRange,
        QirConstraintFamily::AssetSlotSelection => V6ConstraintFamily::AssetSlotSelection,
        QirConstraintFamily::AssetOrder => V6ConstraintFamily::AssetOrder,
        QirConstraintFamily::Balance => V6ConstraintFamily::Balance,
        QirConstraintFamily::Stablecoin => V6ConstraintFamily::Stablecoin,
        QirConstraintFamily::MerklePath => V6ConstraintFamily::MerklePath,
        QirConstraintFamily::NullifierBinding => V6ConstraintFamily::NullifierBinding,
        QirConstraintFamily::SpendAuthorization => V6ConstraintFamily::SpendAuthorization,
        QirConstraintFamily::AuthorizationMode => V6ConstraintFamily::AuthorizationMode,
        QirConstraintFamily::AuthorizationTransition => V6ConstraintFamily::AuthorizationTransition,
        QirConstraintFamily::OutputCommitmentBinding => V6ConstraintFamily::OutputCommitmentBinding,
        QirConstraintFamily::CiphertextBinding => V6ConstraintFamily::CiphertextBinding,
        QirConstraintFamily::IntentBinding => V6ConstraintFamily::IntentBinding,
        QirConstraintFamily::BalanceTagBinding => V6ConstraintFamily::BalanceTagBinding,
    }
}

fn field_add(left: u64, right: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(GOLDILOCKS_MODULUS)) as u64
}

fn field_sub(left: u64, right: u64) -> u64 {
    field_add(
        left,
        if right == 0 {
            0
        } else {
            GOLDILOCKS_MODULUS - right
        },
    )
}

fn field_mul(left: u64, right: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(GOLDILOCKS_MODULUS)) as u64
}

fn field_neg(value: u64) -> u64 {
    if value == 0 {
        0
    } else {
        GOLDILOCKS_MODULUS - value
    }
}

fn bind_public_digest_outputs(
    _relation: &FullBlake2b448Relation,
    output_bit_wires: &BTreeMap<String, Vec<Shake256Wire>>,
    candidate_wires: &[Shake256Wire],
    constraints: &mut Vec<Shake256Constraint>,
) -> Result<(), SmallwoodMixedHashAdapterError> {
    if candidate_wires.len() != CANDIDATE_STATEMENT_BYTES * 8 {
        return Err(SmallwoodMixedHashAdapterError::Binding(
            "candidate statement output binding width",
        ));
    }
    let mut gate = |symbol: &str, statement_offset: usize, selector_offset: usize| {
        let outputs =
            output_bit_wires
                .get(symbol)
                .ok_or(SmallwoodMixedHashAdapterError::Binding(
                    "missing hash output",
                ))?;
        if outputs.len() != DIGEST_BYTES * 8 {
            return Err(SmallwoodMixedHashAdapterError::OutputWidth {
                symbol: symbol.to_owned(),
            });
        }
        let selector = candidate_wires[selector_offset * 8];
        for bit in 0..DIGEST_BYTES * 8 {
            constraints.push(Shake256Constraint::GatedEquality {
                selector,
                left: outputs[bit],
                right: candidate_wires[statement_offset * 8 + bit],
            });
        }
        Ok::<(), SmallwoodMixedHashAdapterError>(())
    };
    gate("digest.note.output[0]", 182, 12)?;
    gate("digest.note.output[1]", 238, 13)?;
    gate("digest.nullifier[0]", 70, 10)?;
    gate("digest.nullifier[1]", 126, 11)?;
    gate("digest.ciphertext[0]", 294, 12)?;
    gate("digest.ciphertext[1]", 350, 13)?;
    let balance = output_bit_wires.get("digest.balance_tag").ok_or(
        SmallwoodMixedHashAdapterError::Binding("missing balance output"),
    )?;
    if balance.len() != DIGEST_BYTES * 8 {
        return Err(SmallwoodMixedHashAdapterError::OutputWidth {
            symbol: "digest.balance_tag".to_owned(),
        });
    }
    for bit in 0..DIGEST_BYTES * 8 {
        constraints.push(Shake256Constraint::Equality {
            left: balance[bit],
            right: candidate_wires[629 * 8 + bit],
        });
    }
    Ok(())
}
