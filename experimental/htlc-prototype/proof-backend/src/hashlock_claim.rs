//! Complete constrained claim is only exists(secret32):SHA256(secret32)=digest.
//! Public context is transcript-bound opaque bytes, not authenticated HTLC state.

use crate::{
    smallwood_engine::{
        prove_statement_with_transcript_backend_profile_and_domain,
        verify_statement_with_transcript_backend_profile_and_domain, SmallwoodArithmetization,
        SmallwoodDecsEvaluationDomain, SmallwoodNoGrindingProfileV1, SmallwoodTranscriptBackend,
        STRICT_ZK_SMZ1_SMALLWOOD_NO_GRINDING_PROFILE,
    },
    smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView},
    TransactionCircuitError,
};
use htlc_prototype::{
    hashlock::{BooleanGate, Sha256Hashlock},
    lowering::HashlockProgram,
};
use sha2::{Digest, Sha512};

pub const CLAIM_VERSION: u32 = 1;
pub const CLAIM_DOMAIN: &[u8] = b"hegemon.experimental.private-sha256-claim.v1";
pub const PACKING: usize = 64;
pub const PROFILE: SmallwoodNoGrindingProfileV1 = STRICT_ZK_SMZ1_SMALLWOOD_NO_GRINDING_PROFILE;
pub const PRODUCTION_RP05_INNER_CAP: usize = 164_113;
const MAX_CONTEXT: usize = 4096;

/// Public verifier-owned statement. No preimage or witness is required to
/// reconstruct its complete deterministic constraint adapter.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimStatement {
    pub version: u32,
    pub digest: [u8; 32],
    pub context: Vec<u8>,
}

pub struct ClaimAdapter {
    pub(crate) program: HashlockProgram,
}

impl ClaimAdapter {
    pub fn from_statement(statement: &ClaimStatement) -> Result<Self, TransactionCircuitError> {
        if statement.version != CLAIM_VERSION || statement.context.len() > MAX_CONTEXT {
            return Err(TransactionCircuitError::ConstraintViolation(
                "unsupported isolated hashlock statement",
            ));
        }
        Ok(Self {
            program: HashlockProgram::compile(&Sha256Hashlock::new(), statement.digest, PACKING)
                .map_err(|_| {
                    TransactionCircuitError::ConstraintViolation("hashlock lowering failed")
                })?,
        })
    }
    pub fn geometry(&self) -> &htlc_prototype::lowering::Geometry {
        self.program.geometry()
    }
}

impl SmallwoodConstraintAdapter for ClaimAdapter {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::DirectPacked64CompressedLevel5StrictZkSmz1
    }
    fn row_count(&self) -> usize {
        self.program.geometry().total_rows
    }
    fn packing_factor(&self) -> usize {
        self.program.geometry().packing_factor
    }
    fn constraint_degree(&self) -> usize {
        3
    }
    fn linear_constraint_count(&self) -> usize {
        self.program.linear_targets().len()
    }
    fn constraint_count(&self) -> usize {
        self.program.batches().len()
    }
    fn linear_constraint_offsets(&self) -> &[u32] {
        self.program.linear_offsets()
    }
    fn linear_constraint_indices(&self) -> &[u32] {
        self.program.linear_indices()
    }
    fn linear_constraint_coefficients(&self) -> &[u64] {
        self.program.linear_coefficients()
    }
    fn linear_targets(&self) -> &[u64] {
        self.program.linear_targets()
    }
    fn auxiliary_witness_words(&self) -> &[u64] {
        &[]
    }
    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(0)
    }
    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        row_scalars: &'a [u64],
        auxiliary_words: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows: row_scalars,
            auxiliary_words,
        }
    }
    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        let SmallwoodNonlinearEvalView::RowScalars {
            rows,
            auxiliary_words,
            ..
        } = view;
        if rows.len() != self.row_count()
            || out.len() != self.constraint_count()
            || !auxiliary_words.is_empty()
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "isolated hashlock evaluator shape",
            ));
        }
        for (batch, value) in self.program.batches().iter().zip(out) {
            let operands: Vec<u64> = batch.operand_rows.iter().map(|row| rows[*row]).collect();
            *value = batch.polynomial.residual(&operands);
        }
        Ok(())
    }
}

/// Hash fixed gate topology/output selection and exact packing/profile/domain,
/// so no statement can accidentally alias another locally compiled relation.
pub fn topology_digest() -> [u8; 64] {
    let circuit = Sha256Hashlock::new();
    let mut h = Sha512::new();
    h.update(b"hegemon.experimental.sha256-bit-topology.v1");
    h.update((circuit.counts().wires as u64).to_le_bytes());
    for (i, gate) in circuit.gates().iter().enumerate() {
        h.update((i as u64).to_le_bytes());
        let (tag, operands): (u8, Vec<usize>) = match *gate {
            BooleanGate::Constant(v) => (0, vec![v as usize]),
            BooleanGate::Not(a) => (1, vec![a]),
            BooleanGate::Xor(a, b) => (2, vec![a, b]),
            BooleanGate::And(a, b) => (3, vec![a, b]),
            BooleanGate::Parity(a, b, c) => (4, vec![a, b, c]),
            BooleanGate::Majority(a, b, c) => (5, vec![a, b, c]),
        };
        h.update([tag]);
        for operand in operands {
            h.update((operand as u64).to_le_bytes());
        }
    }
    for output in circuit.output_wires() {
        h.update((*output as u64).to_le_bytes());
    }
    h.finalize().into()
}

pub fn binding_bytes(statement: &ClaimStatement) -> Result<Vec<u8>, TransactionCircuitError> {
    if statement.version != CLAIM_VERSION || statement.context.len() > MAX_CONTEXT {
        return Err(TransactionCircuitError::ConstraintViolation(
            "unsupported isolated hashlock statement",
        ));
    }
    let mut binding = Vec::new();
    binding.extend_from_slice(&(CLAIM_DOMAIN.len() as u64).to_le_bytes());
    binding.extend_from_slice(CLAIM_DOMAIN);
    binding.extend_from_slice(&statement.version.to_le_bytes());
    binding.extend_from_slice(&topology_digest());
    binding.extend_from_slice(SOURCE_CLOSURE_SHA256.as_bytes());
    binding.extend_from_slice(&(RUSTC_VERSION.len() as u64).to_le_bytes());
    binding.extend_from_slice(RUSTC_VERSION.as_bytes());
    binding.extend_from_slice(&(PACKING as u64).to_le_bytes());
    for parameter in [
        PROFILE.rho,
        PROFILE.nb_opened_evals,
        PROFILE.beta,
        PROFILE.opening_pow_bits as usize,
        PROFILE.decs_nb_evals,
        PROFILE.decs_nb_opened_evals,
        PROFILE.decs_eta,
        PROFILE.decs_pow_bits as usize,
    ] {
        binding.extend_from_slice(&(parameter as u64).to_le_bytes());
    }
    binding.extend_from_slice(b"SMZ1/SHA512/Goldilocks/degree3/disjoint-coset");
    binding.extend_from_slice(&statement.digest);
    binding.extend_from_slice(&(statement.context.len() as u64).to_le_bytes());
    binding.extend_from_slice(&statement.context);
    binding.resize(binding.len().div_ceil(8) * 8, 0);
    Ok(binding)
}

/// Private witness exists only on the prover side. No witness values are
/// inserted into public CSR targets, public binding or auxiliary openings.
pub fn prove(
    statement: &ClaimStatement,
    secret: &[u8; 32],
) -> Result<Vec<u8>, TransactionCircuitError> {
    let adapter = ClaimAdapter::from_statement(statement)?;
    let circuit = Sha256Hashlock::new();
    let assignment = circuit.evaluate(secret);
    let witness = adapter
        .program
        .pack(&assignment)
        .map_err(|_| TransactionCircuitError::ConstraintViolation("hashlock witness length"))?;
    adapter.program.verify_packed(&witness).map_err(|_| {
        TransactionCircuitError::ConstraintViolation("hashlock witness fails constraints")
    })?;
    prove_unchecked_for_falsification(&adapter, &binding_bytes(statement)?, &witness)
}

// Not exported: integration falsification harness exercises this internal
// engine path without a host relation/preflight check.
pub(crate) fn prove_unchecked_for_falsification(
    adapter: &ClaimAdapter,
    binding: &[u8],
    witness: &[u64],
) -> Result<Vec<u8>, TransactionCircuitError> {
    prove_statement_with_transcript_backend_profile_and_domain(
        adapter,
        witness,
        binding,
        PROFILE,
        SmallwoodTranscriptBackend::Sha512Level5,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

pub fn verify(statement: &ClaimStatement, proof: &[u8]) -> Result<(), TransactionCircuitError> {
    let adapter = ClaimAdapter::from_statement(statement)?;
    verify_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        &binding_bytes(statement)?,
        proof,
        PROFILE,
        SmallwoodTranscriptBackend::Sha512Level5,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

pub const SOURCE_CLOSURE_SHA256: &str = env!("HTLC_SOURCE_CLOSURE_SHA256");
pub const RUSTC_VERSION: &str = env!("HTLC_RUSTC_VERSION");
pub const SOURCE_INVENTORY: &str = include_str!(concat!(env!("OUT_DIR"), "/source-closure.sha256"));
