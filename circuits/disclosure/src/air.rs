//! Disclosure circuit AIR (Algebraic Intermediate Representation).
//!
//! Proves knowledge of rho and r such that the note commitment matches
//! the public claim (value, asset_id, pk_recipient, commitment).

use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::constants::{CYCLE_LENGTH, INPUT_PAIRS, NOTE_DOMAIN_TAG, POSEIDON_ROUNDS};

// ================================================================================================
// TRACE CONFIGURATION
// ================================================================================================

pub const COL_S0: usize = 0;
pub const COL_S1: usize = 1;
pub const COL_S2: usize = 2;

pub const COL_IN0: usize = 3;
pub const COL_IN1: usize = 4;

pub const COL_RESET: usize = 5;
pub const COL_DOMAIN: usize = 6;

pub fn absorb_row(cycle: usize) -> usize {
    cycle * CYCLE_LENGTH + (CYCLE_LENGTH - 1)
}

pub fn commitment_row() -> usize {
    commitment_row_01()
}

pub fn commitment_row_01() -> usize {
    let last_cycle = crate::constants::DUMMY_CYCLES + INPUT_PAIRS - 1;
    absorb_row(last_cycle)
}

pub fn commitment_row_23() -> usize {
    let squeeze_cycle = crate::constants::DUMMY_CYCLES + INPUT_PAIRS;
    absorb_row(squeeze_cycle)
}

// ================================================================================================
// PUBLIC INPUTS
// ================================================================================================

#[derive(Clone, Debug)]
pub struct DisclosurePublicInputs {
    pub value: BaseElement,
    pub asset_id: BaseElement,
    pub pk_recipient: [BaseElement; 4],
    pub commitment: [BaseElement; 4],
}

impl Default for DisclosurePublicInputs {
    fn default() -> Self {
        Self {
            value: BaseElement::ZERO,
            asset_id: BaseElement::ZERO,
            pk_recipient: [BaseElement::ZERO; 4],
            commitment: [BaseElement::ZERO; 4],
        }
    }
}

impl ToElements<BaseElement> for DisclosurePublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = Vec::with_capacity(10);
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

const NUM_CONSTRAINTS: usize = 4;
const NUM_ASSERTIONS: usize = 45;

impl Air for DisclosureAir {
    type BaseField = BaseElement;
    type PublicInputs = DisclosurePublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::new(2),
        ];
        debug_assert_eq!(degrees.len(), NUM_CONSTRAINTS);

        Self {
            context: AirContext::new(trace_info, degrees, NUM_ASSERTIONS, options),
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
        let rc0 = periodic_values[2];
        let rc1 = periodic_values[3];
        let rc2 = periodic_values[4];

        let t0 = current[COL_S0] + rc0;
        let t1 = current[COL_S1] + rc1;
        let t2 = current[COL_S2] + rc2;

        let s0 = t0.exp(5u64.into());
        let s1 = t1.exp(5u64.into());
        let s2 = t2.exp(5u64.into());

        let mds = transaction_core::poseidon_constants::MDS_MATRIX;
        let hash_s0 = s0 * E::from(BaseElement::new(mds[0][0]))
            + s1 * E::from(BaseElement::new(mds[0][1]))
            + s2 * E::from(BaseElement::new(mds[0][2]));
        let hash_s1 = s0 * E::from(BaseElement::new(mds[1][0]))
            + s1 * E::from(BaseElement::new(mds[1][1]))
            + s2 * E::from(BaseElement::new(mds[1][2]));
        let hash_s2 = s0 * E::from(BaseElement::new(mds[2][0]))
            + s1 * E::from(BaseElement::new(mds[2][1]))
            + s2 * E::from(BaseElement::new(mds[2][2]));

        let one = E::ONE;
        let copy_flag = one - hash_flag - absorb_flag;

        let reset = current[COL_RESET];
        let domain = current[COL_DOMAIN];
        let in0 = current[COL_IN0];
        let in1 = current[COL_IN1];

        let start_s0 = domain + in0;
        let start_s1 = in1;
        let start_s2 = one;

        let cont_s0 = current[COL_S0] + in0;
        let cont_s1 = current[COL_S1] + in1;
        let cont_s2 = current[COL_S2];

        let absorb_s0 = reset * start_s0 + (one - reset) * cont_s0;
        let absorb_s1 = reset * start_s1 + (one - reset) * cont_s1;
        let absorb_s2 = reset * start_s2 + (one - reset) * cont_s2;

        let expected_s0 =
            hash_flag * hash_s0 + copy_flag * current[COL_S0] + absorb_flag * absorb_s0;
        let expected_s1 =
            hash_flag * hash_s1 + copy_flag * current[COL_S1] + absorb_flag * absorb_s1;
        let expected_s2 =
            hash_flag * hash_s2 + copy_flag * current[COL_S2] + absorb_flag * absorb_s2;

        let mut idx = 0;
        result[idx] = next[COL_S0] - expected_s0;
        idx += 1;
        result[idx] = next[COL_S1] - expected_s1;
        idx += 1;
        result[idx] = next[COL_S2] - expected_s2;
        idx += 1;

        result[idx] = reset * (reset - one);
        idx += 1;

        debug_assert_eq!(idx, NUM_CONSTRAINTS);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::with_capacity(NUM_ASSERTIONS);

        // Initial state is zero.
        assertions.push(Assertion::single(COL_S0, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(COL_S1, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(COL_S2, 0, BaseElement::ZERO));

        // Bind public inputs to absorption rows.
        let row_value = absorb_row(0);
        assertions.push(Assertion::single(COL_IN0, row_value, self.pub_inputs.value));
        assertions.push(Assertion::single(
            COL_IN1,
            row_value,
            self.pub_inputs.asset_id,
        ));

        let row_pk0 = absorb_row(1);
        assertions.push(Assertion::single(
            COL_IN0,
            row_pk0,
            self.pub_inputs.pk_recipient[0],
        ));
        assertions.push(Assertion::single(
            COL_IN1,
            row_pk0,
            self.pub_inputs.pk_recipient[1],
        ));

        let row_pk1 = absorb_row(2);
        assertions.push(Assertion::single(
            COL_IN0,
            row_pk1,
            self.pub_inputs.pk_recipient[2],
        ));
        assertions.push(Assertion::single(
            COL_IN1,
            row_pk1,
            self.pub_inputs.pk_recipient[3],
        ));

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

        // Final commitment output (4 limbs).
        let row_01 = commitment_row_01();
        let row_23 = commitment_row_23();
        assertions.push(Assertion::single(
            COL_S0,
            row_01,
            self.pub_inputs.commitment[0],
        ));
        assertions.push(Assertion::single(
            COL_S1,
            row_01,
            self.pub_inputs.commitment[1],
        ));
        assertions.push(Assertion::single(
            COL_S0,
            row_23,
            self.pub_inputs.commitment[2],
        ));
        assertions.push(Assertion::single(
            COL_S1,
            row_23,
            self.pub_inputs.commitment[3],
        ));

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![make_hash_mask(), make_absorb_mask()];

        for pos in 0..3 {
            let mut column = Vec::with_capacity(CYCLE_LENGTH);
            for step in 0..CYCLE_LENGTH {
                if step < POSEIDON_ROUNDS {
                    column.push(transaction_core::stark_air::round_constant(step, pos));
                } else {
                    column.push(BaseElement::ZERO);
                }
            }
            result.push(column);
        }

        result
    }
}

fn make_hash_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    for value in mask.iter_mut().take(POSEIDON_ROUNDS) {
        *value = BaseElement::ONE;
    }
    mask
}

fn make_absorb_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    mask[CYCLE_LENGTH - 1] = BaseElement::ONE;
    mask
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
