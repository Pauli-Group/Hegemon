//! Disclosure circuit AIR (Algebraic Intermediate Representation).
//!
//! Proves knowledge of rho and r such that the note commitment matches
//! the public claim (value, asset_id, pk_recipient, commitment).

use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::constants::{
    CYCLE_LENGTH, INPUT_CHUNKS, NOTE_DOMAIN_TAG, POSEIDON2_SBOX_DEGREE, POSEIDON2_STEPS,
    POSEIDON2_WIDTH, TRACE_LENGTH,
};

// ================================================================================================
// TRACE CONFIGURATION
// ================================================================================================

pub const COL_S0: usize = 0;
pub const COL_S1: usize = 1;
pub const COL_S2: usize = 2;
pub const COL_S3: usize = 3;
pub const COL_S4: usize = 4;
pub const COL_S5: usize = 5;
pub const COL_S6: usize = 6;
pub const COL_S7: usize = 7;
pub const COL_S8: usize = 8;
pub const COL_S9: usize = 9;
pub const COL_S10: usize = 10;
pub const COL_S11: usize = 11;

pub const COL_IN0: usize = 12;
pub const COL_IN1: usize = 13;
pub const COL_IN2: usize = 14;
pub const COL_IN3: usize = 15;
pub const COL_IN4: usize = 16;
pub const COL_IN5: usize = 17;

pub const COL_RESET: usize = 18;
pub const COL_DOMAIN: usize = 19;

pub fn absorb_row(cycle: usize) -> usize {
    cycle * CYCLE_LENGTH + (CYCLE_LENGTH - 1)
}

pub fn commitment_row() -> usize {
    let last_cycle = crate::constants::DUMMY_CYCLES + INPUT_CHUNKS - 1;
    absorb_row(last_cycle)
}

// ================================================================================================
// PUBLIC INPUTS
// ================================================================================================

#[derive(Clone, Debug)]
pub struct DisclosurePublicInputs {
    pub value: BaseElement,
    pub asset_id: BaseElement,
    pub pk_recipient: [BaseElement; 4],
    pub commitment: [BaseElement; 6],
}

impl Default for DisclosurePublicInputs {
    fn default() -> Self {
        Self {
            value: BaseElement::ZERO,
            asset_id: BaseElement::ZERO,
            pk_recipient: [BaseElement::ZERO; 4],
            commitment: [BaseElement::ZERO; 6],
        }
    }
}

impl ToElements<BaseElement> for DisclosurePublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = Vec::with_capacity(12);
        out.push(self.value);
        out.push(self.asset_id);
        out.extend(self.pk_recipient);
        out.extend(self.commitment);
        out
    }
}

// ================================================================================================
// AIR IMPLEMENTATION
// ================================================================================================

pub struct DisclosureAir {
    context: AirContext<BaseElement>,
    pub_inputs: DisclosurePublicInputs,
}

const NUM_CONSTRAINTS: usize = 13;
const NUM_ASSERTIONS: usize = 60;

impl Air for DisclosureAir {
    type BaseField = BaseElement;
    type PublicInputs = DisclosurePublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Dominant transition term is degree-6 once periodic masks/constants are accounted for.
        let base_degree = 6;
        let transition_exemptions =
            POSEIDON2_STEPS + (TRACE_LENGTH / CYCLE_LENGTH).saturating_sub(1);
        let mut degrees = vec![
            TransitionConstraintDegree::with_cycles(
                base_degree,
                vec![CYCLE_LENGTH, CYCLE_LENGTH, TRACE_LENGTH, TRACE_LENGTH],
            );
            POSEIDON2_WIDTH
        ];
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![TRACE_LENGTH]));
        debug_assert_eq!(degrees.len(), NUM_CONSTRAINTS);

        Self {
            context: AirContext::new(trace_info, degrees, NUM_ASSERTIONS, options)
                .set_num_transition_exemptions(transition_exemptions),
            pub_inputs,
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

        let hash_flag = periodic_values[0];
        let absorb_flag = periodic_values[1];
        let external_flag = periodic_values[2];
        let internal_flag = periodic_values[3];

        let mut rc = [E::ZERO; POSEIDON2_WIDTH];
        for i in 0..POSEIDON2_WIDTH {
            rc[i] = periodic_values[4 + i];
        }
        let transition_mask = periodic_values[4 + POSEIDON2_WIDTH];

        let mut state = [E::ZERO; POSEIDON2_WIDTH];
        for i in 0..POSEIDON2_WIDTH {
            state[i] = current[COL_S0 + i];
        }

        let one = E::ONE;
        let copy_flag = one - hash_flag - absorb_flag;
        let mds_flag = hash_flag - external_flag - internal_flag;
        let hash_state = poseidon2_hash_state(&state, &rc, mds_flag, external_flag, internal_flag);

        let reset = current[COL_RESET];
        let domain = current[COL_DOMAIN];
        let inputs = [
            current[COL_IN0],
            current[COL_IN1],
            current[COL_IN2],
            current[COL_IN3],
            current[COL_IN4],
            current[COL_IN5],
        ];

        let mut start_state = [E::ZERO; POSEIDON2_WIDTH];
        start_state[0] = domain + inputs[0];
        start_state[1] = inputs[1];
        start_state[2] = inputs[2];
        start_state[3] = inputs[3];
        start_state[4] = inputs[4];
        start_state[5] = inputs[5];
        start_state[POSEIDON2_WIDTH - 1] = one;

        let mut cont_state = state;
        for i in 0..inputs.len() {
            cont_state[i] = cont_state[i] + inputs[i];
        }

        let mut absorb_state = [E::ZERO; POSEIDON2_WIDTH];
        for i in 0..POSEIDON2_WIDTH {
            let start = start_state[i];
            let cont = cont_state[i];
            absorb_state[i] = reset * start + (one - reset) * cont;
        }

        for i in 0..POSEIDON2_WIDTH {
            let expected =
                hash_flag * hash_state[i] + absorb_flag * absorb_state[i] + copy_flag * state[i];
            result[i] = transition_mask * (next[COL_S0 + i] - expected);
        }

        result[POSEIDON2_WIDTH] = transition_mask * reset * (reset - one);

        debug_assert_eq!(POSEIDON2_WIDTH + 1, NUM_CONSTRAINTS);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::with_capacity(NUM_ASSERTIONS);

        // Initial state is zero.
        for idx in 0..POSEIDON2_WIDTH {
            assertions.push(Assertion::single(COL_S0 + idx, 0, BaseElement::ZERO));
        }

        // Bind public inputs to absorption rows.
        let row_inputs = absorb_row(0);
        assertions.push(Assertion::single(COL_IN0, row_inputs, self.pub_inputs.value));
        assertions.push(Assertion::single(COL_IN1, row_inputs, self.pub_inputs.asset_id));
        assertions.push(Assertion::single(
            COL_IN2,
            row_inputs,
            self.pub_inputs.pk_recipient[0],
        ));
        assertions.push(Assertion::single(
            COL_IN3,
            row_inputs,
            self.pub_inputs.pk_recipient[1],
        ));
        assertions.push(Assertion::single(
            COL_IN4,
            row_inputs,
            self.pub_inputs.pk_recipient[2],
        ));
        assertions.push(Assertion::single(
            COL_IN5,
            row_inputs,
            self.pub_inputs.pk_recipient[3],
        ));

        // Pad unused inputs in the final chunk to zero.
        let padded_row = absorb_row(INPUT_CHUNKS - 1);
        assertions.push(Assertion::single(COL_IN2, padded_row, BaseElement::ZERO));
        assertions.push(Assertion::single(COL_IN3, padded_row, BaseElement::ZERO));
        assertions.push(Assertion::single(COL_IN4, padded_row, BaseElement::ZERO));
        assertions.push(Assertion::single(COL_IN5, padded_row, BaseElement::ZERO));

        // Enforce reset/domain for each absorption row.
        for cycle in 0..crate::constants::TOTAL_CYCLES {
            let row = absorb_row(cycle);
            if cycle == 0 {
                assertions.push(Assertion::single(COL_RESET, row, BaseElement::ONE));
                assertions.push(Assertion::single(
                    COL_DOMAIN,
                    row,
                    BaseElement::new(NOTE_DOMAIN_TAG),
                ));
            } else {
                assertions.push(Assertion::single(COL_RESET, row, BaseElement::ZERO));
                assertions.push(Assertion::single(COL_DOMAIN, row, BaseElement::ZERO));
            }
        }

        // Final commitment output (6 limbs).
        let row = commitment_row();
        assertions.push(Assertion::single(COL_S0, row, self.pub_inputs.commitment[0]));
        assertions.push(Assertion::single(COL_S1, row, self.pub_inputs.commitment[1]));
        assertions.push(Assertion::single(COL_S2, row, self.pub_inputs.commitment[2]));
        assertions.push(Assertion::single(COL_S3, row, self.pub_inputs.commitment[3]));
        assertions.push(Assertion::single(COL_S4, row, self.pub_inputs.commitment[4]));
        assertions.push(Assertion::single(COL_S5, row, self.pub_inputs.commitment[5]));

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![
            make_hash_mask(),
            make_absorb_mask(),
            make_external_mask(),
            make_internal_mask(),
        ];

        for pos in 0..POSEIDON2_WIDTH {
            let mut column = Vec::with_capacity(CYCLE_LENGTH);
            for step in 0..CYCLE_LENGTH {
                column.push(round_constant(step, pos));
            }
            result.push(column);
        }
        result.push(make_transition_mask());

        result
    }
}

fn poseidon2_hash_state<E: FieldElement<BaseField = BaseElement>>(
    state: &[E; POSEIDON2_WIDTH],
    rc: &[E; POSEIDON2_WIDTH],
    mds_flag: E,
    external_flag: E,
    internal_flag: E,
) -> [E; POSEIDON2_WIDTH] {
    let mds_state = mds_light(state);

    let mut external_state = [E::ZERO; POSEIDON2_WIDTH];
    for i in 0..POSEIDON2_WIDTH {
        external_state[i] = sbox(state[i] + rc[i]);
    }
    let external_state = mds_light(&external_state);

    let mut internal_state = [E::ZERO; POSEIDON2_WIDTH];
    internal_state[0] = sbox(state[0] + rc[0]);
    for i in 1..POSEIDON2_WIDTH {
        internal_state[i] = state[i];
    }
    let internal_state = matmul_internal(&internal_state);

    let mut out = [E::ZERO; POSEIDON2_WIDTH];
    for i in 0..POSEIDON2_WIDTH {
        out[i] = mds_flag * mds_state[i]
            + external_flag * external_state[i]
            + internal_flag * internal_state[i];
    }
    out
}

fn sbox<E: FieldElement<BaseField = BaseElement>>(value: E) -> E {
    value.exp(POSEIDON2_SBOX_DEGREE.into())
}

fn mds_light<E: FieldElement<BaseField = BaseElement>>(
    state: &[E; POSEIDON2_WIDTH],
) -> [E; POSEIDON2_WIDTH] {
    let mut out = [E::ZERO; POSEIDON2_WIDTH];
    for chunk in 0..(POSEIDON2_WIDTH / 4) {
        let offset = chunk * 4;
        let mixed = apply_mds4([
            state[offset],
            state[offset + 1],
            state[offset + 2],
            state[offset + 3],
        ]);
        out[offset..offset + 4].copy_from_slice(&mixed);
    }

    let mut sums = [E::ZERO; 4];
    for k in 0..4 {
        let mut acc = E::ZERO;
        let mut idx = k;
        while idx < POSEIDON2_WIDTH {
            acc += out[idx];
            idx += 4;
        }
        sums[k] = acc;
    }

    for (idx, elem) in out.iter_mut().enumerate() {
        *elem += sums[idx % 4];
    }

    out
}

fn apply_mds4<E: FieldElement<BaseField = BaseElement>>(x: [E; 4]) -> [E; 4] {
    let x0 = x[0];
    let x1 = x[1];
    let x2 = x[2];
    let x3 = x[3];

    let t01 = x0 + x1;
    let t23 = x2 + x3;
    let t0123 = t01 + t23;
    let t01123 = t0123 + x1;
    let t01233 = t0123 + x3;

    [
        t01123 + t01,
        t01123 + (x2 + x2),
        t01233 + t23,
        t01233 + (x0 + x0),
    ]
}

fn matmul_internal<E: FieldElement<BaseField = BaseElement>>(
    state: &[E; POSEIDON2_WIDTH],
) -> [E; POSEIDON2_WIDTH] {
    let mut sum = E::ZERO;
    for elem in state.iter() {
        sum += *elem;
    }

    let mut out = [E::ZERO; POSEIDON2_WIDTH];
    for (idx, elem) in state.iter().enumerate() {
        let diag = E::from(BaseElement::new(
            transaction_core::poseidon2_constants::INTERNAL_MATRIX_DIAG[idx],
        ));
        out[idx] = *elem * diag + sum;
    }
    out
}

fn make_hash_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    for value in mask.iter_mut().take(POSEIDON2_STEPS) {
        *value = BaseElement::ONE;
    }
    mask
}

fn make_absorb_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    mask[CYCLE_LENGTH - 1] = BaseElement::ONE;
    mask
}

fn make_external_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    for step in 1..POSEIDON2_STEPS {
        let mut idx = step - 1;
        if idx < transaction_core::constants::POSEIDON2_EXTERNAL_ROUNDS {
            mask[step] = BaseElement::ONE;
            continue;
        }
        idx -= transaction_core::constants::POSEIDON2_EXTERNAL_ROUNDS;
        if idx < transaction_core::constants::POSEIDON2_INTERNAL_ROUNDS {
            continue;
        }
        idx -= transaction_core::constants::POSEIDON2_INTERNAL_ROUNDS;
        if idx < transaction_core::constants::POSEIDON2_EXTERNAL_ROUNDS {
            mask[step] = BaseElement::ONE;
        }
    }
    mask
}

fn make_internal_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    for step in 1..POSEIDON2_STEPS {
        let mut idx = step - 1;
        if idx < transaction_core::constants::POSEIDON2_EXTERNAL_ROUNDS {
            continue;
        }
        idx -= transaction_core::constants::POSEIDON2_EXTERNAL_ROUNDS;
        if idx < transaction_core::constants::POSEIDON2_INTERNAL_ROUNDS {
            mask[step] = BaseElement::ONE;
        }
    }
    mask
}

fn make_transition_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ONE; TRACE_LENGTH];
    let exemptions = POSEIDON2_STEPS + (TRACE_LENGTH / CYCLE_LENGTH).saturating_sub(1);
    for idx in 0..exemptions {
        let pos = TRACE_LENGTH - 1 - idx;
        mask[pos] = BaseElement::ZERO;
    }
    mask
}

fn round_constant(step: usize, pos: usize) -> BaseElement {
    if step == 0 || step >= POSEIDON2_STEPS {
        return BaseElement::ZERO;
    }

    let mut idx = step - 1;
    if idx < transaction_core::constants::POSEIDON2_EXTERNAL_ROUNDS {
        return BaseElement::new(transaction_core::poseidon2_constants::EXTERNAL_ROUND_CONSTANTS[0]
            [idx][pos]);
    }
    idx -= transaction_core::constants::POSEIDON2_EXTERNAL_ROUNDS;

    if idx < transaction_core::constants::POSEIDON2_INTERNAL_ROUNDS {
        if pos == 0 {
            return BaseElement::new(
                transaction_core::poseidon2_constants::INTERNAL_ROUND_CONSTANTS[idx],
            );
        }
        return BaseElement::ZERO;
    }
    idx -= transaction_core::constants::POSEIDON2_INTERNAL_ROUNDS;

    if idx < transaction_core::constants::POSEIDON2_EXTERNAL_ROUNDS {
        return BaseElement::new(transaction_core::poseidon2_constants::EXTERNAL_ROUND_CONSTANTS[1]
            [idx][pos]);
    }

    BaseElement::ZERO
}

#[cfg(test)]
mod tests {
    use crate::constants::TRACE_LENGTH;

    #[test]
    fn trace_length_is_power_of_two() {
        assert_eq!(TRACE_LENGTH, 1024);
        assert!(TRACE_LENGTH.is_power_of_two());
    }
}
