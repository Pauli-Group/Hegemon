use blake3::Hasher as Blake3Hasher;
use transaction_circuit::constants::POSEIDON_ROUNDS;
use transaction_circuit::hashing::bytes32_to_felts;
use transaction_circuit::stark_air::{round_constant, CYCLE_LENGTH};
use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

pub const BLOCK_COMMITMENT_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"blkcmmt1");

pub const TRACE_WIDTH: usize = 35;

pub const COL_S0: usize = 0;
pub const COL_S1: usize = 1;
pub const COL_S2: usize = 2;
pub const COL_INPUT0: usize = 3;
pub const COL_INPUT1: usize = 4;
pub const COL_START_ROOT0: usize = 5;
pub const COL_START_ROOT1: usize = 6;
pub const COL_START_ROOT2: usize = 7;
pub const COL_START_ROOT3: usize = 8;
pub const COL_END_ROOT0: usize = 9;
pub const COL_END_ROOT1: usize = 10;
pub const COL_END_ROOT2: usize = 11;
pub const COL_END_ROOT3: usize = 12;
pub const COL_NULLIFIER_ROOT0: usize = 13;
pub const COL_NULLIFIER_ROOT1: usize = 14;
pub const COL_NULLIFIER_ROOT2: usize = 15;
pub const COL_NULLIFIER_ROOT3: usize = 16;
pub const COL_DA_ROOT0: usize = 17;
pub const COL_DA_ROOT1: usize = 18;
pub const COL_DA_ROOT2: usize = 19;
pub const COL_DA_ROOT3: usize = 20;
pub const COL_NF_U0: usize = 21;
pub const COL_NF_U1: usize = 22;
pub const COL_NF_U2: usize = 23;
pub const COL_NF_U3: usize = 24;
pub const COL_NF_S0: usize = 25;
pub const COL_NF_S1: usize = 26;
pub const COL_NF_S2: usize = 27;
pub const COL_NF_S3: usize = 28;
pub const COL_NF_PERM: usize = 29;
pub const COL_NF_PERM_INV: usize = 30;
pub const COL_NF_DIFF_INV: usize = 31;
pub const COL_NF_DIFF_NZ: usize = 32;
pub const COL_NF_SORTED_INV: usize = 33;
pub const COL_NF_SORTED_NZ: usize = 34;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitmentBlockPublicInputs {
    pub tx_proofs_commitment: [u8; 32],
    pub starting_state_root: [u8; 32],
    pub ending_state_root: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub da_root: [u8; 32],
    pub tx_count: u32,
    pub nullifiers: Vec<[u8; 32]>,
    pub sorted_nullifiers: Vec<[u8; 32]>,
}

impl ToElements<BaseElement> for CommitmentBlockPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::with_capacity(
            21 + (self.nullifiers.len().saturating_add(self.sorted_nullifiers.len()) * 4),
        );
        elements.extend_from_slice(&commitment_to_felts(&self.tx_proofs_commitment));
        elements.extend_from_slice(&commitment_to_felts(&self.starting_state_root));
        elements.extend_from_slice(&commitment_to_felts(&self.ending_state_root));
        elements.extend_from_slice(&hash_to_felts(&self.nullifier_root));
        elements.extend_from_slice(&hash_to_felts(&self.da_root));
        elements.push(BaseElement::new(self.tx_count as u64));
        for nullifier in &self.nullifiers {
            elements.extend_from_slice(&commitment_to_felts(nullifier));
        }
        for nullifier in &self.sorted_nullifiers {
            elements.extend_from_slice(&commitment_to_felts(nullifier));
        }
        elements
    }
}

pub struct CommitmentBlockAir {
    context: AirContext<BaseElement>,
    pub_inputs: CommitmentBlockPublicInputs,
    nullifier_count: usize,
    perm_alpha: BaseElement,
    perm_beta: BaseElement,
}

impl CommitmentBlockAir {
    pub fn trace_length(tx_count: usize) -> usize {
        total_cycles(tx_count) * CYCLE_LENGTH
    }

    pub fn output_rows(tx_count: usize) -> (usize, usize) {
        let total = total_cycles(tx_count);
        let input_cycles = tx_count.saturating_mul(2).max(1);
        let output0_row = input_cycles * CYCLE_LENGTH - 1;
        let output2_row = total * CYCLE_LENGTH - 1;
        (output0_row, output2_row)
    }
}

impl Air for CommitmentBlockAir {
    type BaseField = BaseElement;
    type PublicInputs = CommitmentBlockPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let full_cycle = trace_info.length();
        let nullifier_count = pub_inputs.nullifiers.len();
        debug_assert_eq!(nullifier_count, pub_inputs.sorted_nullifiers.len());
        let (perm_alpha, perm_beta) = derive_nullifier_challenges(
            &pub_inputs.starting_state_root,
            &pub_inputs.ending_state_root,
            &pub_inputs.nullifier_root,
            &pub_inputs.da_root,
            pub_inputs.tx_count,
            &pub_inputs.nullifiers,
            &pub_inputs.sorted_nullifiers,
        );
        let diff_degree = 2;
        let uniq_degree = 2;
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(1, vec![full_cycle]),
            TransitionConstraintDegree::with_cycles(1, vec![full_cycle]),
            TransitionConstraintDegree::with_cycles(1, vec![full_cycle]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(3, vec![full_cycle]),
            TransitionConstraintDegree::with_cycles(2, vec![full_cycle]),
            TransitionConstraintDegree::with_cycles(2, vec![full_cycle]),
            TransitionConstraintDegree::with_cycles(2, vec![full_cycle]),
            TransitionConstraintDegree::with_cycles(2, vec![full_cycle]),
            TransitionConstraintDegree::with_cycles(diff_degree, vec![full_cycle]),
            TransitionConstraintDegree::with_cycles(diff_degree, vec![full_cycle]),
            TransitionConstraintDegree::with_cycles(diff_degree, vec![full_cycle]),
            TransitionConstraintDegree::with_cycles(uniq_degree, vec![full_cycle]),
        ];

        let num_assertions = 22 + nullifier_count.saturating_mul(8);

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
            nullifier_count,
            perm_alpha,
            perm_beta,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        let init_mask = periodic_values[0];
        let absorb_mask = periodic_values[1];
        let hash_mask = periodic_values[2];
        let rc0 = periodic_values[3];
        let rc1 = periodic_values[4];
        let rc2 = periodic_values[5];
        let perm_mask = periodic_values[6];
        let adj_mask = periodic_values[7];

        let input0 = current[COL_INPUT0];
        let input1 = current[COL_INPUT1];
        let next_input0 = next[COL_INPUT0];
        let next_input1 = next[COL_INPUT1];

        result[0] = init_mask
            * (current[COL_S0] - (E::from(BaseElement::new(BLOCK_COMMITMENT_DOMAIN_TAG)) + input0));
        result[1] = init_mask * (current[COL_S1] - input1);
        result[2] = init_mask * (current[COL_S2] - E::ONE);

        result[3] =
            absorb_mask * (next[COL_S0] - (current[COL_S0] + next_input0));
        result[4] =
            absorb_mask * (next[COL_S1] - (current[COL_S1] + next_input1));
        result[5] = absorb_mask * (next[COL_S2] - current[COL_S2]);

        let t0 = current[COL_S0] + rc0;
        let t1 = current[COL_S1] + rc1;
        let t2 = current[COL_S2] + rc2;

        let s0 = t0.exp(5u64.into());
        let s1 = t1.exp(5u64.into());
        let s2 = t2.exp(5u64.into());

        let mds = transaction_circuit::poseidon_constants::MDS_MATRIX;
        let hash_s0 = s0 * E::from(BaseElement::new(mds[0][0]))
            + s1 * E::from(BaseElement::new(mds[0][1]))
            + s2 * E::from(BaseElement::new(mds[0][2]));
        let hash_s1 = s0 * E::from(BaseElement::new(mds[1][0]))
            + s1 * E::from(BaseElement::new(mds[1][1]))
            + s2 * E::from(BaseElement::new(mds[1][2]));
        let hash_s2 = s0 * E::from(BaseElement::new(mds[2][0]))
            + s1 * E::from(BaseElement::new(mds[2][1]))
            + s2 * E::from(BaseElement::new(mds[2][2]));

        result[6] = hash_mask * (next[COL_S0] - hash_s0);
        result[7] = hash_mask * (next[COL_S1] - hash_s1);
        result[8] = hash_mask * (next[COL_S2] - hash_s2);

        let alpha = E::from(self.perm_alpha);
        let beta = E::from(self.perm_beta);
        let alpha2 = alpha * alpha;
        let alpha3 = alpha2 * alpha;

        let u0 = current[COL_NF_U0];
        let u1 = current[COL_NF_U1];
        let u2 = current[COL_NF_U2];
        let u3 = current[COL_NF_U3];
        let s0 = current[COL_NF_S0];
        let s1 = current[COL_NF_S1];
        let s2 = current[COL_NF_S2];
        let s3 = current[COL_NF_S3];

        let u = u0 + u1 * alpha + u2 * alpha2 + u3 * alpha3;
        let v = s0 + s1 * alpha + s2 * alpha2 + s3 * alpha3;
        let perm = current[COL_NF_PERM];
        let perm_inv = current[COL_NF_PERM_INV];
        let v_inv = current[COL_NF_SORTED_INV];
        let v_nz = current[COL_NF_SORTED_NZ];

        result[9] = perm_mask * (next[COL_NF_PERM] - perm * (u + beta) * perm_inv);
        result[10] = perm_mask * ((v + beta) * perm_inv - E::ONE);
        result[11] = perm_mask * (v * v_inv - v_nz);
        result[12] = perm_mask * (v * (E::ONE - v_nz));
        result[13] = perm_mask * (v_nz * (v_nz - E::ONE));

        let next_s0 = next[COL_NF_S0];
        let next_s1 = next[COL_NF_S1];
        let next_s2 = next[COL_NF_S2];
        let next_s3 = next[COL_NF_S3];
        let next_v = next_s0 + next_s1 * alpha + next_s2 * alpha2 + next_s3 * alpha3;
        let diff = next_v - v;
        let diff_inv = current[COL_NF_DIFF_INV];
        let diff_nz = current[COL_NF_DIFF_NZ];

        result[14] = adj_mask * (diff * diff_inv - diff_nz);
        result[15] = adj_mask * (diff * (E::ONE - diff_nz));
        result[16] = adj_mask * (diff_nz * (diff_nz - E::ONE));
        result[17] = adj_mask * v_nz * (E::ONE - diff_nz);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let tx_count = self.pub_inputs.tx_count as usize;
        let (output0_row, output2_row) = CommitmentBlockAir::output_rows(tx_count);
        let output = commitment_to_felts(&self.pub_inputs.tx_proofs_commitment);
        let start_root = commitment_to_felts(&self.pub_inputs.starting_state_root);
        let end_root = commitment_to_felts(&self.pub_inputs.ending_state_root);
        let nullifier_root = hash_to_felts(&self.pub_inputs.nullifier_root);
        let da_root = hash_to_felts(&self.pub_inputs.da_root);
        let nullifier_count = self.pub_inputs.nullifiers.len();

        let mut assertions = vec![
            Assertion::single(COL_START_ROOT0, 0, start_root[0]),
            Assertion::single(COL_START_ROOT1, 0, start_root[1]),
            Assertion::single(COL_START_ROOT2, 0, start_root[2]),
            Assertion::single(COL_START_ROOT3, 0, start_root[3]),
            Assertion::single(COL_END_ROOT0, 0, end_root[0]),
            Assertion::single(COL_END_ROOT1, 0, end_root[1]),
            Assertion::single(COL_END_ROOT2, 0, end_root[2]),
            Assertion::single(COL_END_ROOT3, 0, end_root[3]),
            Assertion::single(COL_NULLIFIER_ROOT0, 0, nullifier_root[0]),
            Assertion::single(COL_NULLIFIER_ROOT1, 0, nullifier_root[1]),
            Assertion::single(COL_NULLIFIER_ROOT2, 0, nullifier_root[2]),
            Assertion::single(COL_NULLIFIER_ROOT3, 0, nullifier_root[3]),
            Assertion::single(COL_DA_ROOT0, 0, da_root[0]),
            Assertion::single(COL_DA_ROOT1, 0, da_root[1]),
            Assertion::single(COL_DA_ROOT2, 0, da_root[2]),
            Assertion::single(COL_DA_ROOT3, 0, da_root[3]),
            Assertion::single(COL_S0, output0_row, output[0]),
            Assertion::single(COL_S1, output0_row, output[1]),
            Assertion::single(COL_S0, output2_row, output[2]),
            Assertion::single(COL_S1, output2_row, output[3]),
            Assertion::single(COL_NF_PERM, 0, BaseElement::ONE),
            Assertion::single(COL_NF_PERM, nullifier_count, BaseElement::ONE),
        ];

        for (row, nullifier) in self.pub_inputs.nullifiers.iter().enumerate() {
            let limbs = commitment_to_felts(nullifier);
            assertions.push(Assertion::single(COL_NF_U0, row, limbs[0]));
            assertions.push(Assertion::single(COL_NF_U1, row, limbs[1]));
            assertions.push(Assertion::single(COL_NF_U2, row, limbs[2]));
            assertions.push(Assertion::single(COL_NF_U3, row, limbs[3]));
        }

        for (row, nullifier) in self.pub_inputs.sorted_nullifiers.iter().enumerate() {
            let limbs = commitment_to_felts(nullifier);
            assertions.push(Assertion::single(COL_NF_S0, row, limbs[0]));
            assertions.push(Assertion::single(COL_NF_S1, row, limbs[1]));
            assertions.push(Assertion::single(COL_NF_S2, row, limbs[2]));
            assertions.push(Assertion::single(COL_NF_S3, row, limbs[3]));
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![
            make_init_mask(self.trace_length()),
            make_absorb_mask(),
            make_hash_mask(),
        ];

        for pos in 0..3 {
            let mut column = Vec::with_capacity(CYCLE_LENGTH);
            for step in 0..CYCLE_LENGTH {
                if step < POSEIDON_ROUNDS {
                    column.push(round_constant(step, pos));
                } else {
                    column.push(BaseElement::ZERO);
                }
            }
            result.push(column);
        }

        result.push(make_perm_mask(
            self.trace_length(),
            self.nullifier_count,
        ));
        result.push(make_adjacent_mask(
            self.trace_length(),
            self.nullifier_count,
        ));

        result
    }
}

fn make_init_mask(trace_length: usize) -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; trace_length];
    if let Some(first) = mask.first_mut() {
        *first = BaseElement::ONE;
    }
    mask
}

fn make_absorb_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    mask[CYCLE_LENGTH - 1] = BaseElement::ONE;
    mask
}

fn make_hash_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    for value in mask.iter_mut().take(POSEIDON_ROUNDS) {
        *value = BaseElement::ONE;
    }
    mask
}

fn make_perm_mask(trace_length: usize, nullifier_count: usize) -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; trace_length];
    let rows = nullifier_count.min(trace_length.saturating_sub(1));
    for value in mask.iter_mut().take(rows) {
        *value = BaseElement::ONE;
    }
    mask
}

fn make_adjacent_mask(trace_length: usize, nullifier_count: usize) -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; trace_length];
    if nullifier_count == 0 {
        return mask;
    }
    let end = nullifier_count.saturating_sub(1);
    if end > 0 {
        for value in mask.iter_mut().take(end) {
            *value = BaseElement::ONE;
        }
    }
    mask
}

fn commitment_to_felts(value: &[u8; 32]) -> [BaseElement; 4] {
    bytes32_to_felts(value).unwrap_or([BaseElement::ZERO; 4])
}

fn hash_to_felts(value: &[u8; 32]) -> [BaseElement; 4] {
    let mut felts = [BaseElement::ZERO; 4];
    for (idx, chunk) in value.chunks(8).enumerate() {
        let limb = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
        felts[idx] = BaseElement::new(limb);
    }
    felts
}

pub(crate) fn derive_nullifier_challenges(
    starting_state_root: &[u8; 32],
    ending_state_root: &[u8; 32],
    nullifier_root: &[u8; 32],
    da_root: &[u8; 32],
    tx_count: u32,
    nullifiers: &[[u8; 32]],
    sorted_nullifiers: &[[u8; 32]],
) -> (BaseElement, BaseElement) {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"blk-nullifier-perm-v1");
    hasher.update(starting_state_root);
    hasher.update(ending_state_root);
    hasher.update(nullifier_root);
    hasher.update(da_root);
    hasher.update(&tx_count.to_le_bytes());
    hasher.update(&(nullifiers.len() as u64).to_le_bytes());
    hasher.update(&(sorted_nullifiers.len() as u64).to_le_bytes());
    for nullifier in nullifiers {
        hasher.update(nullifier);
    }
    for nullifier in sorted_nullifiers {
        hasher.update(nullifier);
    }
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    let mut alpha = BaseElement::new(u64::from_le_bytes(
        bytes[0..8].try_into().expect("8-byte alpha"),
    ));
    let mut beta = BaseElement::new(u64::from_le_bytes(
        bytes[8..16].try_into().expect("8-byte beta"),
    ));
    if alpha == BaseElement::ZERO {
        alpha = BaseElement::ONE;
    }
    if beta == BaseElement::ZERO {
        beta = BaseElement::new(2);
    }
    (alpha, beta)
}

fn total_cycles(tx_count: usize) -> usize {
    let input_elements = tx_count.saturating_mul(4);
    let input_cycles = ((input_elements + 1) / 2).max(1);
    (input_cycles + 1).next_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_length_pads_to_power_of_two_cycles() {
        assert_eq!(CommitmentBlockAir::trace_length(1), 256);
        assert_eq!(CommitmentBlockAir::trace_length(2), 512);
        assert_eq!(CommitmentBlockAir::trace_length(3), 512);
        assert_eq!(CommitmentBlockAir::trace_length(100), 16384);
    }
}
