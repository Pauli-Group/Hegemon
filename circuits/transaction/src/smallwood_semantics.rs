use blake3::Hasher;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use protocol_versioning::VersionBinding;
use transaction_core::{
    constants::POSEIDON2_WIDTH,
    constants::{BALANCE_DOMAIN_TAG, MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG},
    p3_air::TransactionPublicInputsP3,
    poseidon2::{poseidon2_step, Felt},
};

use crate::{
    error::TransactionCircuitError,
    hashing_pq::{bytes48_to_felts, HashFelt},
    note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
    proof::{transaction_public_inputs_p3_from_parts, SerializedStarkInputs},
    public_inputs::{StablecoinPolicyBinding, TransactionPublicInputs},
    smallwood_engine::SmallwoodArithmetization,
    witness::TransactionWitness,
};

const GOLDILOCKS_MODULUS: u128 = 0xffff_ffff_0000_0001;
const SMALLWOOD_XOF_DOMAIN: &[u8] = b"hegemon.smallwood.f64-xof.v1";

const MAX_INPUTS: usize = 2;
const MAX_OUTPUTS: usize = 2;
const BALANCE_SLOTS: usize = 4;
const MERKLE_DEPTH: usize = 32;
const POSEIDON_STEPS: usize = 31;
const POSEIDON_ROWS_PER_PERMUTATION: usize = POSEIDON_STEPS + 1;
const HASH_LIMBS: usize = 6;
const INPUT_ROWS: usize = 130;
const OUTPUT_ROWS: usize = 2;
const PUBLIC_ROWS: usize = 0;
const PUBLIC_VALUE_COUNT: usize = 78;
const SECRET_ROWS: usize = 264;
const PACKING_FACTOR: usize = 64;
const INPUT_PERMUTATIONS: usize = 3 + MERKLE_DEPTH * 2 + 1;
const OUTPUT_PERMUTATIONS: usize = 3;
const POSEIDON_PERMUTATION_COUNT: usize =
    1 + MAX_INPUTS * INPUT_PERMUTATIONS + MAX_OUTPUTS * OUTPUT_PERMUTATIONS;
const BALANCE_TAG_PERMUTATIONS: usize = 2;
const DIRECT_POSEIDON_PERMUTATION_COUNT: usize =
    POSEIDON_PERMUTATION_COUNT + BALANCE_TAG_PERMUTATIONS;
const POSEIDON_GROUP_COUNT: usize =
    (POSEIDON_PERMUTATION_COUNT + PACKING_FACTOR - 1) / PACKING_FACTOR;
const PUB_INPUT_FLAG0: usize = 0;
const PUB_OUTPUT_FLAG0: usize = 2;
const PUB_CIPHERTEXT_HASHES: usize = 28;
const PUB_FEE: usize = 40;
const PUB_VALUE_BALANCE_SIGN: usize = 41;
const PUB_VALUE_BALANCE_MAG: usize = 42;
const PUB_SLOT_ASSETS: usize = 49;
const PUB_STABLE_ENABLED: usize = 53;
const PUB_STABLE_ASSET: usize = 54;
const PUB_STABLE_POLICY_VERSION: usize = 55;
const PUB_STABLE_ISSUANCE_SIGN: usize = 56;
const PUB_STABLE_ISSUANCE_MAG: usize = 57;
const PUB_STABLE_POLICY_HASH: usize = 58;
const PUB_STABLE_ORACLE: usize = 64;
const PUB_STABLE_ATTESTATION: usize = 70;
pub(crate) const DIRECT_RAW_WITNESS_LEN: usize = 3_991;
const DIRECT_EXPANDED_WITNESS_LEN: usize = 59_749;
const DIRECT_ROW_COUNT: usize = 934;
const DIRECT_PACKED_WITNESS_LEN: usize = DIRECT_ROW_COUNT * PACKING_FACTOR;
const DIRECT_PACKED_PADDING_LEN: usize = DIRECT_PACKED_WITNESS_LEN - DIRECT_EXPANDED_WITNESS_LEN;
const DIRECT_RAW_WITNESS_OFFSET: usize = PUBLIC_VALUE_COUNT;
const DIRECT_POSEIDON_WITNESS_OFFSET: usize = DIRECT_RAW_WITNESS_OFFSET + DIRECT_RAW_WITNESS_LEN;
const EFFECTIVE_CONSTRAINT_DEGREE: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PackedCellRef {
    row: usize,
    col: usize,
}

#[allow(dead_code)]
impl PackedCellRef {
    pub(crate) const fn new(row: usize, col: usize) -> Self {
        Self { row, col }
    }

    pub(crate) const fn row(self) -> usize {
        self.row
    }

    pub(crate) const fn col(self) -> usize {
        self.col
    }

    pub(crate) const fn index(self, packing_factor: usize) -> usize {
        self.row * packing_factor + self.col
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) struct PackedWitnessMatrix<'a> {
    flat: &'a [u64],
    row_count: usize,
    packing_factor: usize,
}

#[allow(dead_code)]
impl<'a> PackedWitnessMatrix<'a> {
    pub(crate) fn new(
        flat: &'a [u64],
        row_count: usize,
        packing_factor: usize,
    ) -> Result<Self, TransactionCircuitError> {
        if flat.len() != row_count * packing_factor {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood packed matrix length {} does not match rows {} x packing {}",
                flat.len(),
                row_count,
                packing_factor
            )));
        }
        Ok(Self {
            flat,
            row_count,
            packing_factor,
        })
    }

    pub(crate) fn direct(flat: &'a [u64]) -> Result<Self, TransactionCircuitError> {
        Self::new(flat, DIRECT_ROW_COUNT, PACKING_FACTOR)
    }

    pub(crate) fn flat(&self) -> &'a [u64] {
        self.flat
    }

    pub(crate) fn row_count(&self) -> usize {
        self.row_count
    }

    pub(crate) fn packing_factor(&self) -> usize {
        self.packing_factor
    }

    pub(crate) fn row_offset(&self, row: usize) -> Result<usize, TransactionCircuitError> {
        if row >= self.row_count {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood packed matrix row {row} exceeds {}",
                self.row_count
            )));
        }
        Ok(row * self.packing_factor)
    }

    pub(crate) fn cell_index(
        &self,
        row: usize,
        col: usize,
    ) -> Result<usize, TransactionCircuitError> {
        if col >= self.packing_factor {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood packed matrix column {col} exceeds {}",
                self.packing_factor
            )));
        }
        Ok(self.row_offset(row)? + col)
    }

    pub(crate) fn row(&self, row: usize) -> Result<&'a [u64], TransactionCircuitError> {
        let start = self.row_offset(row)?;
        Ok(&self.flat[start..start + self.packing_factor])
    }

    pub(crate) fn cell(&self, row: usize, col: usize) -> Result<u64, TransactionCircuitError> {
        Ok(self.flat[self.cell_index(row, col)?])
    }

    pub(crate) fn cell_ref(row: usize, col: usize) -> PackedCellRef {
        PackedCellRef::new(row, col)
    }
}

#[allow(dead_code)]
pub(crate) fn direct_packed_cell_ref_from_offset(offset: usize) -> PackedCellRef {
    PackedCellRef::new(offset / PACKING_FACTOR, offset % PACKING_FACTOR)
}

#[allow(dead_code)]
pub(crate) fn direct_packed_public_value_cell(index: usize) -> PackedCellRef {
    direct_packed_cell_ref_from_offset(index)
}

#[allow(dead_code)]
pub(crate) fn direct_packed_raw_witness_cell(index: usize) -> PackedCellRef {
    direct_packed_cell_ref_from_offset(DIRECT_RAW_WITNESS_OFFSET + index)
}

#[allow(dead_code)]
pub(crate) fn direct_packed_poseidon_cell(
    permutation: usize,
    step_row: usize,
    limb: usize,
) -> PackedCellRef {
    let offset = DIRECT_POSEIDON_WITNESS_OFFSET
        + (permutation * POSEIDON_ROWS_PER_PERMUTATION + step_row) * POSEIDON2_WIDTH
        + limb;
    direct_packed_cell_ref_from_offset(offset)
}

#[allow(dead_code)]
pub(crate) fn direct_packed_poseidon_offset(
    permutation: usize,
    step_row: usize,
    limb: usize,
) -> usize {
    direct_packed_poseidon_cell(permutation, step_row, limb).index(PACKING_FACTOR)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectPackedRange {
    start: usize,
    len: usize,
}

impl DirectPackedRange {
    pub(crate) const fn new(start: usize, len: usize) -> Self {
        Self { start, len }
    }

    pub(crate) const fn start(self) -> usize {
        self.start
    }

    #[allow(dead_code)]
    pub(crate) const fn len(self) -> usize {
        self.len
    }

    pub(crate) const fn end(self) -> usize {
        self.start + self.len
    }

    pub(crate) fn slice<'a>(self, flat: &'a [u64]) -> Result<&'a [u64], TransactionCircuitError> {
        flat.get(self.start..self.end()).ok_or_else(|| {
            TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood direct packed range [{}..{}) exceeds witness length {}",
                self.start,
                self.end(),
                flat.len()
            ))
        })
    }

    pub(crate) fn cell_ref(self, index: usize) -> PackedCellRef {
        direct_packed_cell_ref_from_offset(self.start + index)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectPackedInputPlan {
    pub(crate) value: PackedCellRef,
    pub(crate) asset: PackedCellRef,
    pub(crate) pk_recipient: DirectPackedRange,
    pub(crate) pk_auth: DirectPackedRange,
    pub(crate) rho: DirectPackedRange,
    pub(crate) r: DirectPackedRange,
    pub(crate) position: PackedCellRef,
    pub(crate) rho_seed: DirectPackedRange,
    pub(crate) merkle_siblings: DirectPackedRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectPackedOutputPlan {
    pub(crate) value: PackedCellRef,
    pub(crate) asset: PackedCellRef,
    pub(crate) pk_recipient: DirectPackedRange,
    pub(crate) pk_auth: DirectPackedRange,
    pub(crate) rho: DirectPackedRange,
    pub(crate) r: DirectPackedRange,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectPackedProgram {
    pub(crate) public_values: DirectPackedRange,
    pub(crate) raw_witness: DirectPackedRange,
    pub(crate) poseidon_segment: DirectPackedRange,
    pub(crate) padding: DirectPackedRange,
    pub(crate) header: DirectPackedRange,
    pub(crate) input_value_range: DirectPackedRange,
    pub(crate) input_asset_range: DirectPackedRange,
    pub(crate) inputs: [DirectPackedInputPlan; MAX_INPUTS],
    pub(crate) output_value_range: DirectPackedRange,
    pub(crate) output_asset_range: DirectPackedRange,
    pub(crate) outputs: [DirectPackedOutputPlan; MAX_OUTPUTS],
    pub(crate) ciphertext_hashes: DirectPackedRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectPackedPermutationSpan {
    start: usize,
    len: usize,
}

#[allow(dead_code)]
impl DirectPackedPermutationSpan {
    pub(crate) const fn new(start: usize, len: usize) -> Self {
        Self { start, len }
    }

    pub(crate) const fn start(self) -> usize {
        self.start
    }

    pub(crate) const fn len(self) -> usize {
        self.len
    }

    pub(crate) const fn end(self) -> usize {
        self.start + self.len
    }

    pub(crate) const fn word_range(self) -> DirectPackedRange {
        DirectPackedRange::new(
            self.start * POSEIDON_ROWS_PER_PERMUTATION * POSEIDON2_WIDTH,
            self.len * POSEIDON_ROWS_PER_PERMUTATION * POSEIDON2_WIDTH,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectPackedInputPoseidonPlan {
    pub(crate) commitment: DirectPackedPermutationSpan,
    pub(crate) merkle_nodes: [DirectPackedPermutationSpan; MERKLE_DEPTH],
    pub(crate) nullifier: DirectPackedPermutationSpan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectPackedOutputPoseidonPlan {
    pub(crate) commitment: DirectPackedPermutationSpan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectPackedPoseidonProgram {
    pub(crate) prf: DirectPackedPermutationSpan,
    pub(crate) inputs: [DirectPackedInputPoseidonPlan; MAX_INPUTS],
    pub(crate) outputs: [DirectPackedOutputPoseidonPlan; MAX_OUTPUTS],
    pub(crate) balance_tag: DirectPackedPermutationSpan,
}

fn take_direct_range(cursor: &mut usize, len: usize) -> DirectPackedRange {
    let range = DirectPackedRange::new(*cursor, len);
    *cursor += len;
    range
}

fn take_permutation_span(cursor: &mut usize, len: usize) -> DirectPackedPermutationSpan {
    let range = DirectPackedPermutationSpan::new(*cursor, len);
    *cursor += len;
    range
}

pub(crate) fn direct_packed_program() -> DirectPackedProgram {
    let public_values = DirectPackedRange::new(0, PUBLIC_VALUE_COUNT);
    let raw_witness = DirectPackedRange::new(DIRECT_RAW_WITNESS_OFFSET, DIRECT_RAW_WITNESS_LEN);
    let poseidon_segment = DirectPackedRange::new(
        DIRECT_POSEIDON_WITNESS_OFFSET,
        DIRECT_EXPANDED_WITNESS_LEN - DIRECT_POSEIDON_WITNESS_OFFSET,
    );
    let padding = DirectPackedRange::new(DIRECT_EXPANDED_WITNESS_LEN, DIRECT_PACKED_PADDING_LEN);

    let mut raw_cursor = DIRECT_RAW_WITNESS_OFFSET;
    let header = take_direct_range(&mut raw_cursor, 237);

    let input_value_range = take_direct_range(&mut raw_cursor, MAX_INPUTS);
    let input_asset_range = take_direct_range(&mut raw_cursor, MAX_INPUTS);
    let input_pk_recipient_range = take_direct_range(&mut raw_cursor, MAX_INPUTS * 32);
    let input_pk_auth_range = take_direct_range(&mut raw_cursor, MAX_INPUTS * 32);
    let input_rho_range = take_direct_range(&mut raw_cursor, MAX_INPUTS * 32);
    let input_r_range = take_direct_range(&mut raw_cursor, MAX_INPUTS * 32);
    let input_position_range = take_direct_range(&mut raw_cursor, MAX_INPUTS);
    let input_rho_seed_range = take_direct_range(&mut raw_cursor, MAX_INPUTS * 32);
    let input_merkle_sibling_range =
        take_direct_range(&mut raw_cursor, MAX_INPUTS * MERKLE_DEPTH * 48);

    let output_value_range = take_direct_range(&mut raw_cursor, MAX_OUTPUTS);
    let output_asset_range = take_direct_range(&mut raw_cursor, MAX_OUTPUTS);
    let output_pk_recipient_range = take_direct_range(&mut raw_cursor, MAX_OUTPUTS * 32);
    let output_pk_auth_range = take_direct_range(&mut raw_cursor, MAX_OUTPUTS * 32);
    let output_rho_range = take_direct_range(&mut raw_cursor, MAX_OUTPUTS * 32);
    let output_r_range = take_direct_range(&mut raw_cursor, MAX_OUTPUTS * 32);
    let ciphertext_hashes = take_direct_range(&mut raw_cursor, MAX_OUTPUTS * 48);

    debug_assert_eq!(
        raw_cursor,
        DIRECT_RAW_WITNESS_OFFSET + DIRECT_RAW_WITNESS_LEN
    );

    let inputs = core::array::from_fn(|idx| DirectPackedInputPlan {
        value: input_value_range.cell_ref(idx),
        asset: input_asset_range.cell_ref(idx),
        pk_recipient: DirectPackedRange::new(input_pk_recipient_range.start() + idx * 32, 32),
        pk_auth: DirectPackedRange::new(input_pk_auth_range.start() + idx * 32, 32),
        rho: DirectPackedRange::new(input_rho_range.start() + idx * 32, 32),
        r: DirectPackedRange::new(input_r_range.start() + idx * 32, 32),
        position: input_position_range.cell_ref(idx),
        rho_seed: DirectPackedRange::new(input_rho_seed_range.start() + idx * 32, 32),
        merkle_siblings: DirectPackedRange::new(
            input_merkle_sibling_range.start() + idx * MERKLE_DEPTH * 48,
            MERKLE_DEPTH * 48,
        ),
    });

    let outputs = core::array::from_fn(|idx| DirectPackedOutputPlan {
        value: output_value_range.cell_ref(idx),
        asset: output_asset_range.cell_ref(idx),
        pk_recipient: DirectPackedRange::new(output_pk_recipient_range.start() + idx * 32, 32),
        pk_auth: DirectPackedRange::new(output_pk_auth_range.start() + idx * 32, 32),
        rho: DirectPackedRange::new(output_rho_range.start() + idx * 32, 32),
        r: DirectPackedRange::new(output_r_range.start() + idx * 32, 32),
    });

    DirectPackedProgram {
        public_values,
        raw_witness,
        poseidon_segment,
        padding,
        header,
        input_value_range,
        input_asset_range,
        inputs,
        output_value_range,
        output_asset_range,
        outputs,
        ciphertext_hashes,
    }
}

pub(crate) fn direct_packed_poseidon_program() -> DirectPackedPoseidonProgram {
    let mut permutation_cursor = 0usize;
    let prf = take_permutation_span(&mut permutation_cursor, 1);
    let inputs = core::array::from_fn(|_| {
        let commitment = take_permutation_span(&mut permutation_cursor, 3);
        let merkle_nodes =
            core::array::from_fn(|_| take_permutation_span(&mut permutation_cursor, 2));
        let nullifier = take_permutation_span(&mut permutation_cursor, 1);
        DirectPackedInputPoseidonPlan {
            commitment,
            merkle_nodes,
            nullifier,
        }
    });
    let outputs = core::array::from_fn(|_| DirectPackedOutputPoseidonPlan {
        commitment: take_permutation_span(&mut permutation_cursor, 3),
    });
    let balance_tag = take_permutation_span(&mut permutation_cursor, BALANCE_TAG_PERMUTATIONS);
    debug_assert_eq!(permutation_cursor, DIRECT_POSEIDON_PERMUTATION_COUNT);
    DirectPackedPoseidonProgram {
        prf,
        inputs,
        outputs,
        balance_tag,
    }
}

#[derive(Clone)]
pub(crate) struct PackedStatement<'a> {
    arithmetization: SmallwoodArithmetization,
    public_values: &'a [u64],
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    linear_constraint_count: usize,
    constraint_count: usize,
    linear_constraint_offsets: &'a [u32],
    linear_constraint_indices: &'a [u32],
    linear_constraint_coefficients: &'a [u64],
    linear_constraint_targets: &'a [u64],
    output_ciphertext_challenges: [Felt; MAX_OUTPUTS],
    slot_denominator_inverses: [Felt; BALANCE_SLOTS],
    stable_selector_bits: [Felt; 2],
    stable_policy_hash_challenge: Felt,
    stable_oracle_challenge: Felt,
    stable_attestation_challenge: Felt,
    poseidon_transition_challenges: Vec<Felt>,
}

pub(crate) fn test_candidate_witness_rust(
    arithmetization: SmallwoodArithmetization,
    public_values: &[u64],
    witness_values: &[u64],
    row_count: usize,
    packing_factor: usize,
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
) -> Result<(), TransactionCircuitError> {
    if packing_factor != PACKING_FACTOR || row_count == 0 {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "unsupported smallwood packing_factor {packing_factor}, expected {PACKING_FACTOR}"
        )));
    }
    if witness_values.len() != row_count * packing_factor {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood witness length {} does not match rows {} x packing {}",
            witness_values.len(),
            row_count,
            packing_factor
        )));
    }
    if linear_constraint_offsets.len() != linear_constraint_targets.len() + 1 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood linear-constraint offset/target mismatch",
        ));
    }
    let statement = PackedStatement::new(
        arithmetization,
        public_values,
        row_count,
        packing_factor,
        EFFECTIVE_CONSTRAINT_DEGREE,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    );
    if matches!(arithmetization, SmallwoodArithmetization::DirectPacked64V1) {
        if row_count != DIRECT_ROW_COUNT {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "direct packed SmallWood witness row_count {row_count}, expected {DIRECT_ROW_COUNT}"
            )));
        }
        let mut direct_constraints = vec![0u64; statement.constraint_count()];
        statement.compute_constraints_u64(
            SmallwoodNonlinearEvalView::DirectPackedMatrix {
                flat: witness_values,
            },
            &mut direct_constraints,
        )?;
        if let Some((idx, value)) = direct_constraints
            .iter()
            .enumerate()
            .find(|(_, value)| **value != 0)
        {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood direct packed witness constraint failed at constraint {idx}, value {value}",
            )));
        }
    } else {
        let constraint_count = constraint_count();
        let mut lane_rows = vec![Felt::ZERO; row_count];
        let mut constraint_row = vec![Felt::ZERO; constraint_count];

        for lane in 0..packing_factor {
            for row in 0..row_count {
                lane_rows[row] = Felt::from_u64(witness_values[row * packing_factor + lane]);
            }
            compute_constraints(&statement, &lane_rows, &mut constraint_row);
            if let Some((idx, value)) = constraint_row
                .iter()
                .enumerate()
                .find(|(_, value)| **value != Felt::ZERO)
            {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "smallwood packed witness poly constraint failed at lane {lane}, constraint {idx}, value {}",
                    value.as_canonical_u64()
                )));
            }
        }
    }

    verify_linear_constraints(
        witness_values,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    )?;
    Ok(())
}

fn verify_linear_constraints(
    witness_values: &[u64],
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
) -> Result<(), TransactionCircuitError> {
    for check in 0..linear_constraint_targets.len() {
        let start = linear_constraint_offsets[check] as usize;
        let end = linear_constraint_offsets[check + 1] as usize;
        let mut acc = Felt::ZERO;
        for term_idx in start..end {
            let idx = linear_constraint_indices[term_idx] as usize;
            let coeff = Felt::from_u64(linear_constraint_coefficients[term_idx]);
            acc += coeff * Felt::from_u64(witness_values[idx]);
        }
        let expected = Felt::from_u64(linear_constraint_targets[check]);
        if acc != expected {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood packed witness linear constraint failed at constraint {check}: got {}, expected {}",
                acc.as_canonical_u64(),
                expected.as_canonical_u64()
            )));
        }
    }
    Ok(())
}

#[allow(dead_code)]
impl<'a> PackedStatement<'a> {
    pub(crate) fn new(
        arithmetization: SmallwoodArithmetization,
        public_values: &'a [u64],
        row_count: usize,
        packing_factor: usize,
        constraint_degree: usize,
        linear_constraint_offsets: &'a [u32],
        linear_constraint_indices: &'a [u32],
        linear_constraint_coefficients: &'a [u64],
        linear_constraint_targets: &'a [u64],
    ) -> Self {
        let mut statement = Self {
            arithmetization,
            public_values,
            row_count,
            packing_factor,
            constraint_degree,
            linear_constraint_count: linear_constraint_targets.len(),
            constraint_count: match arithmetization {
                SmallwoodArithmetization::Bridge64V1 => constraint_count(),
                SmallwoodArithmetization::DirectPacked64V1 => direct_packed_constraint_count(),
            },
            linear_constraint_offsets,
            linear_constraint_indices,
            linear_constraint_coefficients,
            linear_constraint_targets,
            output_ciphertext_challenges: [Felt::ZERO; MAX_OUTPUTS],
            slot_denominator_inverses: derive_slot_denominator_inverses(public_values),
            stable_selector_bits: derive_stable_selector_bits(public_values),
            stable_policy_hash_challenge: Felt::ZERO,
            stable_oracle_challenge: Felt::ZERO,
            stable_attestation_challenge: Felt::ZERO,
            poseidon_transition_challenges: vec![Felt::ZERO; POSEIDON_GROUP_COUNT * POSEIDON_STEPS],
        };
        for output in 0..MAX_OUTPUTS {
            statement.output_ciphertext_challenges[output] =
                nontrivial_challenge(&statement, 5, output as u64, 0);
        }
        statement.stable_policy_hash_challenge = nontrivial_challenge(&statement, 6, 0, 0);
        statement.stable_oracle_challenge = nontrivial_challenge(&statement, 7, 0, 0);
        statement.stable_attestation_challenge = nontrivial_challenge(&statement, 8, 0, 0);
        for group in 0..POSEIDON_GROUP_COUNT {
            for step in 0..POSEIDON_STEPS {
                let idx = poseidon_transition_challenge_index(group, step);
                statement.poseidon_transition_challenges[idx] =
                    nontrivial_challenge(&statement, 11, group as u64, step as u64);
            }
        }
        statement
    }

    pub(crate) fn row_count(&self) -> usize {
        self.row_count
    }

    pub(crate) fn packing_factor(&self) -> usize {
        self.packing_factor
    }

    pub(crate) fn constraint_degree(&self) -> usize {
        self.constraint_degree
    }

    pub(crate) fn linear_constraint_count(&self) -> usize {
        self.linear_constraint_count
    }

    pub(crate) fn constraint_count(&self) -> usize {
        self.constraint_count
    }

    pub(crate) fn linear_targets(&self) -> &[u64] {
        self.linear_constraint_targets
    }

    pub(crate) fn linear_constraint_offsets(&self) -> &[u32] {
        self.linear_constraint_offsets
    }

    pub(crate) fn linear_constraint_indices(&self) -> &[u32] {
        self.linear_constraint_indices
    }

    pub(crate) fn linear_constraint_coefficients(&self) -> &[u64] {
        self.linear_constraint_coefficients
    }

    pub(crate) fn public_values(&self) -> &[u64] {
        self.public_values
    }

    pub(crate) fn arithmetization(&self) -> SmallwoodArithmetization {
        self.arithmetization
    }
}

pub(crate) trait SmallwoodConstraintAdapter: Sync {
    fn arithmetization(&self) -> SmallwoodArithmetization;
    fn row_count(&self) -> usize;
    fn packing_factor(&self) -> usize;
    fn constraint_degree(&self) -> usize;
    fn linear_constraint_count(&self) -> usize;
    fn constraint_count(&self) -> usize;
    fn linear_constraint_offsets(&self) -> &[u32];
    fn linear_constraint_indices(&self) -> &[u32];
    fn linear_constraint_coefficients(&self) -> &[u64];
    fn linear_targets(&self) -> &[u64];
    fn public_values(&self) -> &[u64];
    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        row_scalars: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a>;
    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError>;
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum SmallwoodNonlinearEvalView<'a> {
    RowScalars { eval_point: u64, rows: &'a [u64] },
    DirectPackedMatrix { flat: &'a [u64] },
}

impl<'a> SmallwoodConstraintAdapter for PackedStatement<'a> {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        self.arithmetization
    }

    fn row_count(&self) -> usize {
        self.row_count
    }

    fn packing_factor(&self) -> usize {
        self.packing_factor
    }

    fn constraint_degree(&self) -> usize {
        self.constraint_degree
    }

    fn linear_constraint_count(&self) -> usize {
        self.linear_constraint_count
    }

    fn constraint_count(&self) -> usize {
        self.constraint_count
    }

    fn linear_constraint_offsets(&self) -> &[u32] {
        self.linear_constraint_offsets
    }

    fn linear_constraint_indices(&self) -> &[u32] {
        self.linear_constraint_indices
    }

    fn linear_constraint_coefficients(&self) -> &[u64] {
        self.linear_constraint_coefficients
    }

    fn linear_targets(&self) -> &[u64] {
        self.linear_constraint_targets
    }

    fn public_values(&self) -> &[u64] {
        self.public_values
    }

    fn nonlinear_eval_view<'b>(
        &self,
        eval_point: u64,
        row_scalars: &'b [u64],
    ) -> SmallwoodNonlinearEvalView<'b> {
        match self.arithmetization {
            SmallwoodArithmetization::Bridge64V1 => SmallwoodNonlinearEvalView::RowScalars {
                eval_point,
                rows: row_scalars,
            },
            SmallwoodArithmetization::DirectPacked64V1 => SmallwoodNonlinearEvalView::RowScalars {
                eval_point,
                rows: row_scalars,
            },
        }
    }

    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        match self.arithmetization {
            SmallwoodArithmetization::Bridge64V1 => compute_bridge_constraints_u64(self, view, out),
            SmallwoodArithmetization::DirectPacked64V1 => {
                compute_direct_packed_constraints_u64(self, view, out)
            }
        }
    }
}

fn xof_words(input_words: &[u64], output_words: &mut [u64]) {
    let mut hasher = Hasher::new();
    hasher.update(SMALLWOOD_XOF_DOMAIN);
    hasher.update(&(input_words.len() as u64).to_le_bytes());
    for word in input_words {
        hasher.update(&word.to_le_bytes());
    }
    let mut reader = hasher.finalize_xof();
    for output in output_words {
        let mut buf = [0u8; 16];
        reader.fill(&mut buf);
        *output = (u128::from_le_bytes(buf) % GOLDILOCKS_MODULUS) as u64;
    }
}

struct RawCursor<'a> {
    words: &'a [u64],
    index: usize,
}

impl<'a> RawCursor<'a> {
    fn new(words: &'a [u64]) -> Self {
        Self { words, index: 0 }
    }

    fn take_word(&mut self, label: &str) -> Result<u64, TransactionCircuitError> {
        let value = self.words.get(self.index).copied().ok_or_else(|| {
            TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood packed frontend missing raw witness word for {label}"
            ))
        })?;
        self.index += 1;
        Ok(value)
    }

    fn take_u8(&mut self, label: &str) -> Result<u8, TransactionCircuitError> {
        let value = self.take_word(label)?;
        u8::try_from(value).map_err(|_| {
            TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood packed frontend {label} value {value} exceeds u8"
            ))
        })
    }

    fn take_u32(&mut self, label: &str) -> Result<u32, TransactionCircuitError> {
        let value = self.take_word(label)?;
        u32::try_from(value).map_err(|_| {
            TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood packed frontend {label} value {value} exceeds u32"
            ))
        })
    }

    fn take_bytes<const N: usize>(
        &mut self,
        label: &str,
    ) -> Result<[u8; N], TransactionCircuitError> {
        let mut out = [0u8; N];
        for byte in &mut out {
            let value = self.take_word(label)?;
            *byte = u8::try_from(value).map_err(|_| {
                TransactionCircuitError::ConstraintViolationOwned(format!(
                    "smallwood packed frontend {label} byte value {value} exceeds u8"
                ))
            })?;
        }
        Ok(out)
    }
}

pub(crate) fn parse_direct_raw_witness(
    raw_witness: &[u64],
) -> Result<TransactionWitness, TransactionCircuitError> {
    if raw_witness.len() != DIRECT_RAW_WITNESS_LEN {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood packed frontend raw witness length {}, expected {}",
            raw_witness.len(),
            DIRECT_RAW_WITNESS_LEN
        )));
    }
    let mut cursor = RawCursor::new(raw_witness);
    let input_count = usize::try_from(cursor.take_word("input_count")?).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood packed frontend input_count overflow",
        )
    })?;
    let output_count = usize::try_from(cursor.take_word("output_count")?).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood packed frontend output_count overflow",
        )
    })?;
    let ciphertext_hash_count = usize::try_from(cursor.take_word("ciphertext_hash_count")?)
        .map_err(|_| {
            TransactionCircuitError::ConstraintViolation(
                "smallwood packed frontend ciphertext_hash_count overflow",
            )
        })?;
    if input_count > MAX_INPUTS || output_count > MAX_OUTPUTS || ciphertext_hash_count > MAX_OUTPUTS
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood packed frontend witness count exceeds padded capacity",
        ));
    }

    let sk_spend = cursor.take_bytes::<32>("sk_spend")?;
    let merkle_root = cursor.take_bytes::<48>("merkle_root")?;
    let fee = cursor.take_word("fee")?;
    let value_balance_sign = cursor.take_u8("value_balance_sign")?;
    let value_balance_magnitude = cursor.take_word("value_balance_magnitude")?;
    let stablecoin_enabled = cursor.take_u8("stablecoin_enabled")?;
    let stablecoin_asset_id = cursor.take_word("stablecoin_asset_id")?;
    let stablecoin_policy_hash = cursor.take_bytes::<48>("stablecoin_policy_hash")?;
    let stablecoin_oracle_commitment = cursor.take_bytes::<48>("stablecoin_oracle_commitment")?;
    let stablecoin_attestation_commitment =
        cursor.take_bytes::<48>("stablecoin_attestation_commitment")?;
    let stablecoin_issuance_sign = cursor.take_u8("stablecoin_issuance_sign")?;
    let stablecoin_issuance_magnitude = cursor.take_word("stablecoin_issuance_magnitude")?;
    let stablecoin_policy_version = cursor.take_u32("stablecoin_policy_version")?;
    let version = VersionBinding::new(
        u16::try_from(cursor.take_word("version_circuit")?).map_err(|_| {
            TransactionCircuitError::ConstraintViolation(
                "smallwood packed frontend version circuit overflow",
            )
        })?,
        u16::try_from(cursor.take_word("version_crypto")?).map_err(|_| {
            TransactionCircuitError::ConstraintViolation(
                "smallwood packed frontend version crypto overflow",
            )
        })?,
    );

    let mut input_values = [0u64; MAX_INPUTS];
    let mut input_assets = [0u64; MAX_INPUTS];
    for slot in &mut input_values {
        *slot = cursor.take_word("input_value")?;
    }
    for slot in &mut input_assets {
        *slot = cursor.take_word("input_asset")?;
    }
    let mut input_pk_recipient = [[0u8; 32]; MAX_INPUTS];
    let mut input_pk_auth = [[0u8; 32]; MAX_INPUTS];
    let mut input_rho = [[0u8; 32]; MAX_INPUTS];
    let mut input_r = [[0u8; 32]; MAX_INPUTS];
    let mut input_positions = [0u64; MAX_INPUTS];
    let mut input_rho_seed = [[0u8; 32]; MAX_INPUTS];
    let mut input_merkle_paths: [Vec<HashFelt>; MAX_INPUTS] = core::array::from_fn(|_| Vec::new());
    for slot in &mut input_pk_recipient {
        *slot = cursor.take_bytes::<32>("input_pk_recipient")?;
    }
    for slot in &mut input_pk_auth {
        *slot = cursor.take_bytes::<32>("input_pk_auth")?;
    }
    for slot in &mut input_rho {
        *slot = cursor.take_bytes::<32>("input_rho")?;
    }
    for slot in &mut input_r {
        *slot = cursor.take_bytes::<32>("input_r")?;
    }
    for slot in &mut input_positions {
        *slot = cursor.take_word("input_position")?;
    }
    for slot in &mut input_rho_seed {
        *slot = cursor.take_bytes::<32>("input_rho_seed")?;
    }
    for siblings in &mut input_merkle_paths {
        for _ in 0..MERKLE_DEPTH {
            let bytes = cursor.take_bytes::<48>("input_merkle_sibling")?;
            let sibling =
                bytes48_to_felts(&bytes).ok_or(TransactionCircuitError::ConstraintViolation(
                    "smallwood packed frontend merkle sibling is non-canonical",
                ))?;
            siblings.push(sibling);
        }
    }

    let mut output_values = [0u64; MAX_OUTPUTS];
    let mut output_assets = [0u64; MAX_OUTPUTS];
    for slot in &mut output_values {
        *slot = cursor.take_word("output_value")?;
    }
    for slot in &mut output_assets {
        *slot = cursor.take_word("output_asset")?;
    }
    let mut output_pk_recipient = [[0u8; 32]; MAX_OUTPUTS];
    let mut output_pk_auth = [[0u8; 32]; MAX_OUTPUTS];
    let mut output_rho = [[0u8; 32]; MAX_OUTPUTS];
    let mut output_r = [[0u8; 32]; MAX_OUTPUTS];
    for slot in &mut output_pk_recipient {
        *slot = cursor.take_bytes::<32>("output_pk_recipient")?;
    }
    for slot in &mut output_pk_auth {
        *slot = cursor.take_bytes::<32>("output_pk_auth")?;
    }
    for slot in &mut output_rho {
        *slot = cursor.take_bytes::<32>("output_rho")?;
    }
    for slot in &mut output_r {
        *slot = cursor.take_bytes::<32>("output_r")?;
    }

    let mut ciphertext_hashes = Vec::with_capacity(ciphertext_hash_count);
    for idx in 0..MAX_OUTPUTS {
        let bytes = cursor.take_bytes::<48>("ciphertext_hash")?;
        if idx < ciphertext_hash_count {
            ciphertext_hashes.push(bytes);
        }
    }
    if cursor.index != raw_witness.len() {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood packed frontend parser stopped at {}, expected {}",
            cursor.index,
            raw_witness.len()
        )));
    }

    let mut inputs = Vec::with_capacity(input_count);
    for idx in 0..input_count {
        inputs.push(InputNoteWitness {
            note: NoteData {
                value: input_values[idx],
                asset_id: input_assets[idx],
                pk_recipient: input_pk_recipient[idx],
                pk_auth: input_pk_auth[idx],
                rho: input_rho[idx],
                r: input_r[idx],
            },
            position: input_positions[idx],
            rho_seed: input_rho_seed[idx],
            merkle_path: MerklePath {
                siblings: input_merkle_paths[idx].clone(),
            },
        });
    }

    let mut outputs = Vec::with_capacity(output_count);
    for idx in 0..output_count {
        outputs.push(OutputNoteWitness {
            note: NoteData {
                value: output_values[idx],
                asset_id: output_assets[idx],
                pk_recipient: output_pk_recipient[idx],
                pk_auth: output_pk_auth[idx],
                rho: output_rho[idx],
                r: output_r[idx],
            },
        });
    }

    let value_balance = decode_signed_magnitude(value_balance_sign, value_balance_magnitude)?;
    let stablecoin_issuance =
        decode_signed_magnitude(stablecoin_issuance_sign, stablecoin_issuance_magnitude)?;
    let stablecoin = StablecoinPolicyBinding {
        enabled: stablecoin_enabled != 0,
        asset_id: stablecoin_asset_id,
        policy_hash: stablecoin_policy_hash,
        oracle_commitment: stablecoin_oracle_commitment,
        attestation_commitment: stablecoin_attestation_commitment,
        issuance_delta: stablecoin_issuance,
        policy_version: stablecoin_policy_version,
    };

    Ok(TransactionWitness {
        inputs,
        outputs,
        ciphertext_hashes,
        sk_spend,
        merkle_root,
        fee,
        value_balance,
        stablecoin,
        version,
    })
}

fn decode_signed_magnitude(sign: u8, magnitude: u64) -> Result<i128, TransactionCircuitError> {
    match sign {
        0 => Ok(magnitude as i128),
        1 => Ok(-(magnitude as i128)),
        _ => Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood packed frontend sign bit {sign} is invalid"
        ))),
    }
}

fn serialize_smallwood_stark_inputs(
    witness: &TransactionWitness,
    public_inputs: &TransactionPublicInputs,
) -> Result<SerializedStarkInputs, TransactionCircuitError> {
    let (value_balance_sign, value_balance_magnitude) =
        signed_magnitude_u64(witness.value_balance, "value_balance")?;
    let (stablecoin_issuance_sign, stablecoin_issuance_magnitude) =
        signed_magnitude_u64(witness.stablecoin.issuance_delta, "stablecoin_issuance")?;
    Ok(SerializedStarkInputs {
        input_flags: (0..MAX_INPUTS)
            .map(|idx| u8::from(idx < witness.inputs.len()))
            .collect(),
        output_flags: (0..MAX_OUTPUTS)
            .map(|idx| u8::from(idx < witness.outputs.len()))
            .collect(),
        fee: witness.fee,
        value_balance_sign,
        value_balance_magnitude,
        merkle_root: witness.merkle_root,
        balance_slot_asset_ids: public_inputs
            .balance_slots
            .iter()
            .map(|slot| slot.asset_id)
            .collect(),
        stablecoin_enabled: u8::from(witness.stablecoin.enabled),
        stablecoin_asset_id: witness.stablecoin.asset_id,
        stablecoin_policy_version: witness.stablecoin.policy_version,
        stablecoin_issuance_sign,
        stablecoin_issuance_magnitude,
        stablecoin_policy_hash: witness.stablecoin.policy_hash,
        stablecoin_oracle_commitment: witness.stablecoin.oracle_commitment,
        stablecoin_attestation_commitment: witness.stablecoin.attestation_commitment,
    })
}

fn signed_magnitude_u64(value: i128, label: &str) -> Result<(u8, u64), TransactionCircuitError> {
    let sign = u8::from(value < 0);
    let magnitude = value.unsigned_abs();
    if magnitude > u128::from(u64::MAX) {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "{label} magnitude {magnitude} exceeds u64::MAX"
        )));
    }
    Ok((sign, magnitude as u64))
}

fn push_bytes32_words(out: &mut Vec<u64>, bytes: &[u8; 32]) {
    out.extend(bytes.iter().map(|byte| u64::from(*byte)));
}

fn push_bytes48_words(out: &mut Vec<u64>, bytes: &[u8; 48]) {
    out.extend(bytes.iter().map(|byte| u64::from(*byte)));
}

fn serialize_direct_raw_witness(
    witness: &TransactionWitness,
) -> Result<Vec<u64>, TransactionCircuitError> {
    witness.validate()?;
    let mut values = Vec::with_capacity(DIRECT_RAW_WITNESS_LEN);
    let (value_balance_sign, value_balance_magnitude) =
        signed_magnitude_u64(witness.value_balance, "value_balance")?;
    let (stablecoin_issuance_sign, stablecoin_issuance_magnitude) =
        signed_magnitude_u64(witness.stablecoin.issuance_delta, "stablecoin_issuance")?;

    values.push(witness.inputs.len() as u64);
    values.push(witness.outputs.len() as u64);
    values.push(witness.ciphertext_hashes.len() as u64);
    push_bytes32_words(&mut values, &witness.sk_spend);
    push_bytes48_words(&mut values, &witness.merkle_root);
    values.push(witness.fee);
    values.push(u64::from(value_balance_sign));
    values.push(value_balance_magnitude);
    values.push(u64::from(witness.stablecoin.enabled));
    values.push(witness.stablecoin.asset_id);
    push_bytes48_words(&mut values, &witness.stablecoin.policy_hash);
    push_bytes48_words(&mut values, &witness.stablecoin.oracle_commitment);
    push_bytes48_words(&mut values, &witness.stablecoin.attestation_commitment);
    values.push(u64::from(stablecoin_issuance_sign));
    values.push(stablecoin_issuance_magnitude);
    values.push(u64::from(witness.stablecoin.policy_version));
    values.push(u64::from(witness.version.circuit));
    values.push(u64::from(witness.version.crypto));

    let inputs = padded_inputs(&witness.inputs);
    for input in &inputs {
        values.push(input.note.value);
    }
    for input in &inputs {
        values.push(input.note.asset_id);
    }
    for input in &inputs {
        push_bytes32_words(&mut values, &input.note.pk_recipient);
    }
    for input in &inputs {
        push_bytes32_words(&mut values, &input.note.pk_auth);
    }
    for input in &inputs {
        push_bytes32_words(&mut values, &input.note.rho);
    }
    for input in &inputs {
        push_bytes32_words(&mut values, &input.note.r);
    }
    for input in &inputs {
        values.push(input.position);
    }
    for input in &inputs {
        push_bytes32_words(&mut values, &input.rho_seed);
    }
    for input in &inputs {
        for sibling in &input.merkle_path.siblings {
            let sibling_bytes = crate::hashing_pq::felts_to_bytes48(sibling);
            push_bytes48_words(&mut values, &sibling_bytes);
        }
    }

    let outputs = padded_outputs(&witness.outputs);
    for output in &outputs {
        values.push(output.note.value);
    }
    for output in &outputs {
        values.push(output.note.asset_id);
    }
    for output in &outputs {
        push_bytes32_words(&mut values, &output.note.pk_recipient);
    }
    for output in &outputs {
        push_bytes32_words(&mut values, &output.note.pk_auth);
    }
    for output in &outputs {
        push_bytes32_words(&mut values, &output.note.rho);
    }
    for output in &outputs {
        push_bytes32_words(&mut values, &output.note.r);
    }

    let mut ciphertext_hashes = witness.ciphertext_hashes.clone();
    while ciphertext_hashes.len() < MAX_OUTPUTS {
        ciphertext_hashes.push([0u8; 48]);
    }
    for hash in ciphertext_hashes.iter().take(MAX_OUTPUTS) {
        push_bytes48_words(&mut values, hash);
    }

    if values.len() != DIRECT_RAW_WITNESS_LEN {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood direct raw witness serialization length {}, expected {}",
            values.len(),
            DIRECT_RAW_WITNESS_LEN
        )));
    }
    Ok(values)
}

fn packed_public_values_from_p3(
    public_inputs: &TransactionPublicInputsP3,
    version: VersionBinding,
) -> Vec<u64> {
    public_inputs
        .to_vec()
        .into_iter()
        .map(|felt| felt.as_canonical_u64())
        .chain([u64::from(version.circuit), u64::from(version.crypto)])
        .collect()
}

fn flatten_poseidon_rows(
    poseidon_rows: &[[[u64; POSEIDON2_WIDTH]; POSEIDON_ROWS_PER_PERMUTATION]],
) -> Vec<u64> {
    let mut flat =
        Vec::with_capacity(poseidon_rows.len() * POSEIDON_ROWS_PER_PERMUTATION * POSEIDON2_WIDTH);
    for permutation in poseidon_rows {
        for row in permutation {
            flat.extend_from_slice(row);
        }
    }
    flat
}

fn aggregate_u64_differences(challenge: Felt, lhs: &[u64], rhs: &[u64]) -> Felt {
    let mut acc = Felt::ZERO;
    let mut power = Felt::ONE;
    for (&left, &right) in lhs.iter().zip(rhs.iter()) {
        acc += power * (Felt::from_u64(left) - Felt::from_u64(right));
        power *= challenge;
    }
    acc
}

fn aggregate_u64_zeros(challenge: Felt, values: &[u64]) -> Felt {
    let mut acc = Felt::ZERO;
    let mut power = Felt::ONE;
    for &value in values {
        acc += power * Felt::from_u64(value);
        power *= challenge;
    }
    acc
}

fn direct_packed_poseidon_constraint_count() -> usize {
    1 + MAX_INPUTS * (1 + MERKLE_DEPTH + 1) + MAX_OUTPUTS + 1
}

fn direct_packed_constraint_count() -> usize {
    3 + direct_packed_poseidon_constraint_count()
}

fn compute_direct_packed_constraints_u64(
    statement: &PackedStatement<'_>,
    view: SmallwoodNonlinearEvalView<'_>,
    out: &mut [u64],
) -> Result<(), TransactionCircuitError> {
    let flat = match view {
        SmallwoodNonlinearEvalView::DirectPackedMatrix { flat } => flat,
        SmallwoodNonlinearEvalView::RowScalars { .. } => {
            return Err(TransactionCircuitError::ConstraintViolation(
                "direct packed SmallWood arithmetization requires matrix-aware witness access and is not implemented in the row-polynomial proof engine yet",
            ))
        }
    };
    let expected = direct_packed_constraint_count();
    if out.len() != expected {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood direct packed constraint buffer has length {}, expected {expected}",
            out.len()
        )));
    }

    let matrix = PackedWitnessMatrix::direct(flat)?;
    let program = direct_packed_program();
    let poseidon_program = direct_packed_poseidon_program();

    let public_values = program.public_values.slice(matrix.flat())?;
    let raw_witness = program.raw_witness.slice(matrix.flat())?;
    let poseidon_flat = program.poseidon_segment.slice(matrix.flat())?;
    let padding = program.padding.slice(matrix.flat())?;

    let witness = parse_direct_raw_witness(raw_witness)?;
    witness.validate()?;
    let public_inputs = witness.public_inputs()?;
    let serialized_inputs = serialize_smallwood_stark_inputs(&witness, &public_inputs)?;
    let p3_inputs = transaction_public_inputs_p3_from_parts(&public_inputs, &serialized_inputs)?;
    let expected_public_values = packed_public_values_from_p3(&p3_inputs, witness.version);
    let expected_raw_witness = serialize_direct_raw_witness(&witness)?;
    let expected_poseidon_rows =
        packed_poseidon_subtrace_rows_from_witness(&witness, &public_inputs)?;
    let expected_poseidon_flat = flatten_poseidon_rows(&expected_poseidon_rows);

    if expected_public_values.len() != public_values.len() {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood direct packed public value count {}, expected {}",
            public_values.len(),
            expected_public_values.len()
        )));
    }
    if expected_raw_witness.len() != raw_witness.len() {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood direct packed raw witness length {}, expected {}",
            raw_witness.len(),
            expected_raw_witness.len()
        )));
    }
    if expected_poseidon_flat.len() != poseidon_flat.len() {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood direct packed poseidon word length {}, expected {}",
            poseidon_flat.len(),
            expected_poseidon_flat.len()
        )));
    }

    let mut constraint_idx = 0usize;
    out[constraint_idx] = aggregate_u64_differences(
        nontrivial_challenge(statement, 20, 0, 0),
        public_values,
        &expected_public_values,
    )
    .as_canonical_u64();
    constraint_idx += 1;
    out[constraint_idx] = aggregate_u64_differences(
        nontrivial_challenge(statement, 21, 0, 0),
        raw_witness,
        &expected_raw_witness,
    )
    .as_canonical_u64();
    constraint_idx += 1;
    out[constraint_idx] =
        aggregate_u64_zeros(nontrivial_challenge(statement, 22, 0, 0), padding).as_canonical_u64();
    constraint_idx += 1;

    let mut push_poseidon_span = |label_tag: u64,
                                  major: u64,
                                  minor: u64,
                                  span: DirectPackedPermutationSpan|
     -> Result<(), TransactionCircuitError> {
        let actual = poseidon_span_words(poseidon_flat, span)?;
        let expected = poseidon_span_words(&expected_poseidon_flat, span)?;
        out[constraint_idx] = aggregate_u64_differences(
            nontrivial_challenge(statement, label_tag, major, minor),
            actual,
            expected,
        )
        .as_canonical_u64();
        constraint_idx += 1;
        Ok(())
    };

    push_poseidon_span(23, 0, 0, poseidon_program.prf)?;
    for (input_idx, input_plan) in poseidon_program.inputs.iter().enumerate() {
        push_poseidon_span(24, input_idx as u64, 0, input_plan.commitment)?;
        for (level, span) in input_plan.merkle_nodes.iter().enumerate() {
            push_poseidon_span(25, input_idx as u64, level as u64, *span)?;
        }
        push_poseidon_span(26, input_idx as u64, 0, input_plan.nullifier)?;
    }
    for (output_idx, output_plan) in poseidon_program.outputs.iter().enumerate() {
        push_poseidon_span(27, output_idx as u64, 0, output_plan.commitment)?;
    }
    push_poseidon_span(28, 0, 0, poseidon_program.balance_tag)?;

    debug_assert_eq!(constraint_idx, expected);
    Ok(())
}

fn poseidon_span_words<'a>(
    poseidon_flat: &'a [u64],
    span: DirectPackedPermutationSpan,
) -> Result<&'a [u64], TransactionCircuitError> {
    span.word_range().slice(poseidon_flat)
}

fn packed_poseidon_subtrace_rows_from_witness(
    witness: &TransactionWitness,
    public_inputs: &TransactionPublicInputs,
) -> Result<Vec<[[u64; POSEIDON2_WIDTH]; POSEIDON_ROWS_PER_PERMUTATION]>, TransactionCircuitError> {
    let mut traces = poseidon_subtrace_rows_from_witness(witness)?;
    let native_delta = public_inputs
        .balance_slots
        .iter()
        .find(|slot| slot.asset_id == crate::constants::NATIVE_ASSET_ID)
        .map(|slot| slot.delta)
        .unwrap_or(0);
    let (_, balance_tag_traces) = trace_sponge_hash_from_inputs(
        BALANCE_DOMAIN_TAG,
        &balance_commitment_inputs_from_slots(native_delta, &public_inputs.balance_slots)?,
    );
    traces.extend(balance_tag_traces);
    Ok(traces)
}

fn poseidon_subtrace_rows_from_witness(
    witness: &TransactionWitness,
) -> Result<Vec<[[u64; POSEIDON2_WIDTH]; POSEIDON_ROWS_PER_PERMUTATION]>, TransactionCircuitError> {
    let inputs = padded_inputs(&witness.inputs);
    let outputs = padded_outputs(&witness.outputs);
    let mut traces = Vec::new();

    let (prf_hash, prf_traces) =
        trace_sponge_hash_from_inputs(NULLIFIER_DOMAIN_TAG, &bytes_to_felts32(&witness.sk_spend));
    let prf = prf_hash[0];
    traces.extend(prf_traces);

    for input in &inputs {
        let (commitment, commitment_traces) = trace_sponge_hash_from_inputs(
            NOTE_DOMAIN_TAG,
            &commitment_inputs_from_note(&input.note),
        );
        traces.extend(commitment_traces);

        let mut current = commitment;
        let mut pos = input.position;
        for level in 0..MERKLE_DEPTH {
            let sibling = input
                .merkle_path
                .siblings
                .get(level)
                .copied()
                .unwrap_or([Felt::ZERO; HASH_LIMBS]);
            let (left, right) = if pos & 1 == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            let (next, merkle_traces) = trace_merkle_node_from_hashes(left, right);
            traces.extend(merkle_traces);
            current = next;
            pos >>= 1;
        }

        let (_, nullifier_traces) = trace_sponge_hash_from_inputs(
            NULLIFIER_DOMAIN_TAG,
            &nullifier_inputs_from_note(prf, input),
        );
        traces.extend(nullifier_traces);
    }

    for output in &outputs {
        let (_, commitment_traces) = trace_sponge_hash_from_inputs(
            NOTE_DOMAIN_TAG,
            &commitment_inputs_from_note(&output.note),
        );
        traces.extend(commitment_traces);
    }

    Ok(traces)
}

fn padded_inputs(inputs: &[InputNoteWitness]) -> Vec<InputNoteWitness> {
    let mut padded = inputs.to_vec();
    while padded.len() < MAX_INPUTS {
        padded.push(dummy_input());
    }
    padded
}

fn padded_outputs(outputs: &[OutputNoteWitness]) -> Vec<OutputNoteWitness> {
    let mut padded = outputs.to_vec();
    while padded.len() < MAX_OUTPUTS {
        padded.push(dummy_output());
    }
    padded
}

fn dummy_input() -> InputNoteWitness {
    InputNoteWitness {
        note: NoteData {
            value: 0,
            asset_id: 0,
            pk_recipient: [0u8; 32],
            pk_auth: [0u8; 32],
            rho: [0u8; 32],
            r: [0u8; 32],
        },
        position: 0,
        rho_seed: [0u8; 32],
        merkle_path: MerklePath::default(),
    }
}

fn dummy_output() -> OutputNoteWitness {
    OutputNoteWitness {
        note: NoteData {
            value: 0,
            asset_id: 0,
            pk_recipient: [0u8; 32],
            pk_auth: [0u8; 32],
            rho: [0u8; 32],
            r: [0u8; 32],
        },
    }
}

fn bytes_to_felts32(bytes: &[u8; 32]) -> Vec<Felt> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf[8 - chunk.len()..].copy_from_slice(chunk);
            Felt::from_u64(u64::from_be_bytes(buf))
        })
        .collect()
}

fn commitment_inputs_from_note(note: &NoteData) -> Vec<Felt> {
    let mut inputs = Vec::new();
    inputs.push(Felt::from_u64(note.value));
    inputs.push(Felt::from_u64(note.asset_id));
    inputs.extend(bytes_to_felts32(&note.pk_recipient));
    inputs.extend(bytes_to_felts32(&note.rho));
    inputs.extend(bytes_to_felts32(&note.r));
    inputs.extend(bytes_to_felts32(&note.pk_auth));
    inputs
}

fn nullifier_inputs_from_note(prf: Felt, input: &InputNoteWitness) -> Vec<Felt> {
    let mut inputs = Vec::new();
    inputs.push(prf);
    inputs.push(Felt::from_u64(input.position));
    inputs.extend(bytes_to_felts32(&input.note.rho));
    inputs
}

fn balance_commitment_inputs_from_slots(
    native_delta: i128,
    slots: &[transaction_core::BalanceSlot],
) -> Result<Vec<Felt>, TransactionCircuitError> {
    let native_magnitude = u64::try_from(native_delta.unsigned_abs()).map_err(|_| {
        TransactionCircuitError::ConstraintViolation("native balance magnitude exceeds u64::MAX")
    })?;
    let mut inputs = Vec::with_capacity(1 + slots.len() * 2);
    inputs.push(Felt::from_u64(native_magnitude));
    for slot in slots {
        let magnitude = u64::try_from(slot.delta.unsigned_abs()).map_err(|_| {
            TransactionCircuitError::ConstraintViolationOwned(format!(
                "balance slot {} magnitude exceeds u64::MAX",
                slot.asset_id
            ))
        })?;
        inputs.push(Felt::from_u64(slot.asset_id));
        inputs.push(Felt::from_u64(magnitude));
    }
    Ok(inputs)
}

fn trace_merkle_node_from_hashes(
    left: HashFelt,
    right: HashFelt,
) -> (
    HashFelt,
    Vec<[[u64; POSEIDON2_WIDTH]; POSEIDON_ROWS_PER_PERMUTATION]>,
) {
    let mut inputs = Vec::with_capacity(HASH_LIMBS * 2);
    inputs.extend_from_slice(&left);
    inputs.extend_from_slice(&right);
    trace_sponge_hash_from_inputs(MERKLE_DOMAIN_TAG, &inputs)
}

fn trace_sponge_hash_from_inputs(
    domain_tag: u64,
    inputs: &[Felt],
) -> (
    HashFelt,
    Vec<[[u64; POSEIDON2_WIDTH]; POSEIDON_ROWS_PER_PERMUTATION]>,
) {
    let mut state = [Felt::ZERO; POSEIDON2_WIDTH];
    state[0] = Felt::from_u64(domain_tag);
    state[POSEIDON2_WIDTH - 1] = Felt::ONE;
    let mut cursor = 0usize;
    let mut permutations = Vec::new();
    while cursor < inputs.len() {
        let take = core::cmp::min(
            transaction_core::constants::POSEIDON2_RATE,
            inputs.len() - cursor,
        );
        for idx in 0..take {
            state[idx] += inputs[cursor + idx];
        }
        let mut rows = [[0u64; POSEIDON2_WIDTH]; POSEIDON_ROWS_PER_PERMUTATION];
        rows[0] = snapshot_state(&state);
        for step in 0..POSEIDON_STEPS {
            poseidon2_step(&mut state, step);
            rows[step + 1] = snapshot_state(&state);
        }
        permutations.push(rows);
        cursor += take;
    }
    let mut output = [Felt::ZERO; HASH_LIMBS];
    output.copy_from_slice(&state[..HASH_LIMBS]);
    (output, permutations)
}

fn snapshot_state(state: &[Felt; POSEIDON2_WIDTH]) -> [u64; POSEIDON2_WIDTH] {
    let mut row = [0u64; POSEIDON2_WIDTH];
    for (idx, value) in state.iter().enumerate() {
        row[idx] = value.as_canonical_u64();
    }
    row
}

fn nontrivial_challenge(statement: &PackedStatement<'_>, tag: u64, a: u64, b: u64) -> Felt {
    let mut input = Vec::with_capacity(PUBLIC_VALUE_COUNT + 4);
    input.push(0x736d_616c_6c77_6f6f);
    input.push(tag);
    input.push(a);
    input.push(b);
    input.extend_from_slice(statement.public_values());
    let mut output = [0u64; 1];
    xof_words(&input, &mut output);
    if output[0] <= 1 {
        output[0] += 2;
    }
    Felt::from_u64(output[0])
}

fn public_value(statement: &PackedStatement<'_>, row: usize) -> Felt {
    Felt::from_u64(statement.public_values[row])
}

#[inline]
fn row_input_base(input: usize) -> usize {
    PUBLIC_ROWS + input * INPUT_ROWS
}

#[inline]
fn row_input_direction(input: usize, bit: usize) -> usize {
    row_input_base(input) + 2 + bit
}

#[inline]
fn row_input_value(input: usize) -> usize {
    row_input_base(input)
}

#[inline]
fn row_input_asset(input: usize) -> usize {
    row_input_base(input) + 1
}

#[inline]
fn row_input_current_agg(input: usize, level: usize) -> usize {
    row_input_base(input) + 34 + level
}

#[inline]
fn row_input_left_agg(input: usize, level: usize) -> usize {
    row_input_base(input) + 66 + level
}

#[inline]
fn row_input_right_agg(input: usize, level: usize) -> usize {
    row_input_base(input) + 98 + level
}

#[inline]
fn row_output_base(output: usize) -> usize {
    PUBLIC_ROWS + MAX_INPUTS * INPUT_ROWS + output * OUTPUT_ROWS
}

#[inline]
fn row_output_value(output: usize) -> usize {
    row_output_base(output)
}

#[inline]
fn row_output_asset(output: usize) -> usize {
    row_output_base(output) + 1
}

#[inline]
fn poseidon_rows_start() -> usize {
    PUBLIC_ROWS + SECRET_ROWS
}
#[inline]
fn poseidon_group_row(group: usize, step_row: usize, limb: usize) -> usize {
    poseidon_rows_start()
        + (group * POSEIDON_ROWS_PER_PERMUTATION + step_row) * POSEIDON2_WIDTH
        + limb
}
#[inline]
fn poseidon_transition_challenge_index(group: usize, step: usize) -> usize {
    group * POSEIDON_STEPS + step
}

#[inline]
fn felt_bool_v(bit: Felt) -> Felt {
    bit * (bit - Felt::ONE)
}

#[inline]
fn selected_slot_weight(bit0: Felt, bit1: Felt, slot: usize) -> Felt {
    let inv0 = Felt::ONE - bit0;
    let inv1 = Felt::ONE - bit1;
    match slot {
        0 => inv0 * inv1,
        1 => bit0 * inv1,
        2 => inv0 * bit1,
        _ => bit0 * bit1,
    }
}

fn selected_slot_asset(statement: &PackedStatement<'_>, bit0: Felt, bit1: Felt) -> Felt {
    let mut result = Felt::ZERO;
    for slot in 0..BALANCE_SLOTS {
        let weight = selected_slot_weight(bit0, bit1, slot);
        result += weight * public_value(statement, PUB_SLOT_ASSETS + slot);
    }
    result
}

fn derive_slot_denominator_inverses(public_values: &[u64]) -> [Felt; BALANCE_SLOTS] {
    let mut inverses = [Felt::ZERO; BALANCE_SLOTS];
    for slot in 0..BALANCE_SLOTS {
        let asset = Felt::from_u64(public_values[PUB_SLOT_ASSETS + slot]);
        let mut denominator = Felt::ONE;
        for other in 0..BALANCE_SLOTS {
            if other == slot {
                continue;
            }
            denominator *= asset - Felt::from_u64(public_values[PUB_SLOT_ASSETS + other]);
        }
        inverses[slot] = denominator.try_inverse().unwrap_or(Felt::ZERO);
    }
    inverses
}

fn slot_membership_weights(statement: &PackedStatement<'_>, asset: Felt) -> [Felt; BALANCE_SLOTS] {
    let mut weights = [Felt::ZERO; BALANCE_SLOTS];
    for slot in 0..BALANCE_SLOTS {
        let mut numerator = Felt::ONE;
        for other in 0..BALANCE_SLOTS {
            if other == slot {
                continue;
            }
            numerator *= asset - public_value(statement, PUB_SLOT_ASSETS + other);
        }
        weights[slot] = numerator * statement.slot_denominator_inverses[slot];
    }
    weights
}

fn slot_membership_zero(statement: &PackedStatement<'_>, asset: Felt) -> Felt {
    let mut acc = Felt::ONE;
    for slot in 0..BALANCE_SLOTS {
        acc *= asset - public_value(statement, PUB_SLOT_ASSETS + slot);
    }
    acc
}

fn aggregate_weighted_differences(challenge: Felt, lhs: &[Felt], rhs: &[Felt]) -> Felt {
    let mut acc = Felt::ZERO;
    let mut power = Felt::ONE;
    for (&left, &right) in lhs.iter().zip(rhs.iter()) {
        acc += power * (left - right);
        power *= challenge;
    }
    acc
}

fn derive_stable_selector_bits(public_values: &[u64]) -> [Felt; 2] {
    if public_values[PUB_STABLE_ENABLED] == 0 {
        return [Felt::ZERO, Felt::ZERO];
    }
    let stable_asset = public_values[PUB_STABLE_ASSET];
    let slot = (0..BALANCE_SLOTS)
        .find(|slot| public_values[PUB_SLOT_ASSETS + slot] == stable_asset)
        .unwrap_or(0);
    [
        Felt::from_u64((slot & 1) as u64),
        Felt::from_u64(((slot >> 1) & 1) as u64),
    ]
}

fn signed_from_parts(sign: Felt, magnitude: Felt) -> Felt {
    magnitude - (sign + sign) * magnitude
}

#[allow(dead_code)]
pub(crate) fn packed_constraint_count() -> usize {
    constraint_count()
}

pub(crate) fn compute_bridge_constraints_u64(
    statement: &PackedStatement<'_>,
    view: SmallwoodNonlinearEvalView<'_>,
    out: &mut [u64],
) -> Result<(), TransactionCircuitError> {
    if !matches!(
        statement.arithmetization(),
        SmallwoodArithmetization::Bridge64V1
    ) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "direct packed SmallWood arithmetization is not implemented in the proof engine yet",
        ));
    }
    let expected = constraint_count();
    if out.len() != expected {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood constraint buffer has length {}, expected {expected}",
            out.len()
        )));
    }
    let rows = match view {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point: _eval_point,
            rows,
        } => rows,
        SmallwoodNonlinearEvalView::DirectPackedMatrix { .. } => {
            return Err(TransactionCircuitError::ConstraintViolation(
                "bridge SmallWood constraints require row-scalar evaluations, not direct packed matrix access",
            ))
        }
    };
    let felt_rows = rows.iter().copied().map(Felt::from_u64).collect::<Vec<_>>();
    let mut felt_out = vec![Felt::ZERO; expected];
    compute_constraints(statement, &felt_rows, &mut felt_out);
    for (dst, src) in out.iter_mut().zip(felt_out.iter()) {
        *dst = src.as_canonical_u64();
    }
    Ok(())
}

fn constraint_count() -> usize {
    let public_bools = MAX_INPUTS + MAX_OUTPUTS + 3;
    let input_constraints = MAX_INPUTS * (MERKLE_DEPTH + 1 + MERKLE_DEPTH);
    let output_constraints = MAX_OUTPUTS * (1 + 1);
    let stablecoin_constraints = 1 + 1 + 7;
    let balance_constraints = BALANCE_SLOTS;
    let poseidon_transition = POSEIDON_GROUP_COUNT * POSEIDON_STEPS;
    public_bools
        + input_constraints
        + output_constraints
        + stablecoin_constraints
        + balance_constraints
        + poseidon_transition
}

fn compute_constraints(statement: &PackedStatement<'_>, rows: &[Felt], out: &mut [Felt]) {
    let mut c = 0usize;

    for input in 0..MAX_INPUTS {
        out[c] = felt_bool_v(public_value(statement, PUB_INPUT_FLAG0 + input));
        c += 1;
    }
    for output in 0..MAX_OUTPUTS {
        out[c] = felt_bool_v(public_value(statement, PUB_OUTPUT_FLAG0 + output));
        c += 1;
    }
    out[c] = felt_bool_v(public_value(statement, PUB_VALUE_BALANCE_SIGN));
    c += 1;
    out[c] = felt_bool_v(public_value(statement, PUB_STABLE_ENABLED));
    c += 1;
    out[c] = felt_bool_v(public_value(statement, PUB_STABLE_ISSUANCE_SIGN));
    c += 1;

    for input in 0..MAX_INPUTS {
        let asset = rows[row_input_asset(input)];
        let flag = public_value(statement, PUB_INPUT_FLAG0 + input);
        for bit in 0..MERKLE_DEPTH {
            out[c] = felt_bool_v(rows[row_input_direction(input, bit)]);
            c += 1;
        }
        let mut position_sum = Felt::ZERO;
        for bit in 0..MERKLE_DEPTH {
            position_sum += rows[row_input_direction(input, bit)] * Felt::from_u64(1u64 << bit);
        }
        let _ = position_sum;
        out[c] = flag * slot_membership_zero(statement, asset);
        c += 1;

        for level in 0..MERKLE_DEPTH {
            let dir = rows[row_input_direction(input, level)];
            let current = rows[row_input_current_agg(input, level)];
            let left = rows[row_input_left_agg(input, level)];
            let right = rows[row_input_right_agg(input, level)];
            out[c] = flag * (current - (left + dir * (right - left)));
            c += 1;
        }
    }

    for output_idx in 0..MAX_OUTPUTS {
        let asset = rows[row_output_asset(output_idx)];
        let flag = public_value(statement, PUB_OUTPUT_FLAG0 + output_idx);
        let inactive = Felt::ONE - flag;
        out[c] = flag * slot_membership_zero(statement, asset);
        c += 1;

        let mut lhs_hash = [Felt::ZERO; HASH_LIMBS];
        let rhs_hash = [Felt::ZERO; HASH_LIMBS];
        for limb in 0..HASH_LIMBS {
            lhs_hash[limb] = inactive
                * public_value(
                    statement,
                    PUB_CIPHERTEXT_HASHES + output_idx * HASH_LIMBS + limb,
                );
        }
        out[c] = aggregate_weighted_differences(
            statement.output_ciphertext_challenges[output_idx],
            &lhs_hash,
            &rhs_hash,
        );
        c += 1;
    }

    let stable_selector0 = statement.stable_selector_bits[0];
    let stable_selector1 = statement.stable_selector_bits[1];
    let stable_enabled = public_value(statement, PUB_STABLE_ENABLED);
    let stable_disabled = Felt::ONE - stable_enabled;
    out[c] = selected_slot_asset(statement, stable_selector0, stable_selector1)
        - public_value(statement, PUB_STABLE_ASSET);
    c += 1;
    out[c] = stable_enabled * selected_slot_weight(stable_selector0, stable_selector1, 0);
    c += 1;
    out[c] = stable_disabled * public_value(statement, PUB_STABLE_ASSET);
    c += 1;
    out[c] = stable_disabled * public_value(statement, PUB_STABLE_POLICY_VERSION);
    c += 1;
    out[c] = stable_disabled * public_value(statement, PUB_STABLE_ISSUANCE_SIGN);
    c += 1;
    out[c] = stable_disabled * public_value(statement, PUB_STABLE_ISSUANCE_MAG);
    c += 1;

    let mut lhs_hash = [Felt::ZERO; HASH_LIMBS];
    let rhs_hash = [Felt::ZERO; HASH_LIMBS];
    for limb in 0..HASH_LIMBS {
        lhs_hash[limb] = stable_disabled * public_value(statement, PUB_STABLE_POLICY_HASH + limb);
    }
    out[c] = aggregate_weighted_differences(
        statement.stable_policy_hash_challenge,
        &lhs_hash,
        &rhs_hash,
    );
    c += 1;
    for limb in 0..HASH_LIMBS {
        lhs_hash[limb] = stable_disabled * public_value(statement, PUB_STABLE_ORACLE + limb);
    }
    out[c] =
        aggregate_weighted_differences(statement.stable_oracle_challenge, &lhs_hash, &rhs_hash);
    c += 1;
    for limb in 0..HASH_LIMBS {
        lhs_hash[limb] = stable_disabled * public_value(statement, PUB_STABLE_ATTESTATION + limb);
    }
    out[c] = aggregate_weighted_differences(
        statement.stable_attestation_challenge,
        &lhs_hash,
        &rhs_hash,
    );
    c += 1;

    let signed_value_balance = signed_from_parts(
        public_value(statement, PUB_VALUE_BALANCE_SIGN),
        public_value(statement, PUB_VALUE_BALANCE_MAG),
    );
    let signed_stable_issuance = signed_from_parts(
        public_value(statement, PUB_STABLE_ISSUANCE_SIGN),
        public_value(statement, PUB_STABLE_ISSUANCE_MAG),
    );
    let native_expected = public_value(statement, PUB_FEE) - signed_value_balance;

    for slot in 0..BALANCE_SLOTS {
        let mut delta = Felt::ZERO;
        for input in 0..MAX_INPUTS {
            let flag = public_value(statement, PUB_INPUT_FLAG0 + input);
            let value = rows[row_input_value(input)];
            let asset = rows[row_input_asset(input)];
            let weight = slot_membership_weights(statement, asset)[slot];
            delta += flag * value * weight;
        }
        for output_idx in 0..MAX_OUTPUTS {
            let flag = public_value(statement, PUB_OUTPUT_FLAG0 + output_idx);
            let value = rows[row_output_value(output_idx)];
            let asset = rows[row_output_asset(output_idx)];
            let weight = slot_membership_weights(statement, asset)[slot];
            delta -= flag * value * weight;
        }
        out[c] = if slot == 0 {
            delta - native_expected
        } else {
            let stable_weight = selected_slot_weight(stable_selector0, stable_selector1, slot);
            let expected = stable_enabled * stable_weight * signed_stable_issuance;
            delta - expected
        };
        c += 1;
    }

    for group in 0..POSEIDON_GROUP_COUNT {
        for step in 0..POSEIDON_STEPS {
            let mut state = [Felt::ZERO; POSEIDON2_WIDTH];
            let mut next_actual = [Felt::ZERO; POSEIDON2_WIDTH];
            for limb in 0..POSEIDON2_WIDTH {
                state[limb] = rows[poseidon_group_row(group, step, limb)];
                next_actual[limb] = rows[poseidon_group_row(group, step + 1, limb)];
            }
            poseidon2_step(&mut state, step);
            out[c] = aggregate_weighted_differences(
                statement.poseidon_transition_challenges
                    [poseidon_transition_challenge_index(group, step)],
                &next_actual,
                &state,
            );
            c += 1;
        }
    }
}
