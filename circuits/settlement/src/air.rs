use alloc::vec::Vec;
use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::constants::{
    COL_IN0, COL_IN1, COL_S0, COL_S1, COL_S2, CYCLE_LENGTH, INPUT_PAIRS_PER_TRACE,
    MAX_INSTRUCTIONS, MAX_NULLIFIERS, PADDED_INPUT_COUNT, SETTLEMENT_DOMAIN_TAG, TRACE_LENGTH,
    TRACE_WIDTH,
};
use crate::hashing::Felt;

#[derive(Clone, Debug)]
pub struct SettlementPublicInputs {
    pub instruction_count: u32,
    pub nullifier_count: u32,
    pub instructions: Vec<Felt>,
    pub nullifiers: Vec<Felt>,
    pub commitment: Felt,
}

impl SettlementPublicInputs {
    pub fn validate(&self) -> Result<(), alloc::string::String> {
        if self.instructions.len() != MAX_INSTRUCTIONS {
            return Err("instructions length mismatch".into());
        }
        if self.nullifiers.len() != MAX_NULLIFIERS {
            return Err("nullifiers length mismatch".into());
        }
        if self.instruction_count as usize > MAX_INSTRUCTIONS {
            return Err("instruction_count exceeds maximum".into());
        }
        if self.nullifier_count as usize > MAX_NULLIFIERS {
            return Err("nullifier_count exceeds maximum".into());
        }
        Ok(())
    }

    pub fn input_elements(&self) -> Vec<Felt> {
        let mut inputs = Vec::with_capacity(PADDED_INPUT_COUNT);
        inputs.push(Felt::new(self.instruction_count as u64));
        inputs.push(Felt::new(self.nullifier_count as u64));
        inputs.extend(self.instructions.iter().copied());
        inputs.extend(self.nullifiers.iter().copied());
        while inputs.len() < PADDED_INPUT_COUNT {
            inputs.push(Felt::ZERO);
        }
        inputs
    }
}

impl ToElements<BaseElement> for SettlementPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::with_capacity(2 + MAX_INSTRUCTIONS + MAX_NULLIFIERS + 1);
        elements.push(BaseElement::new(self.instruction_count as u64));
        elements.push(BaseElement::new(self.nullifier_count as u64));
        elements.extend(self.instructions.iter().copied());
        elements.extend(self.nullifiers.iter().copied());
        elements.push(self.commitment);
        elements
    }
}

pub struct SettlementAir {
    context: AirContext<BaseElement>,
    pub_inputs: SettlementPublicInputs,
}

impl Air for SettlementAir {
    type BaseField = BaseElement;
    type PublicInputs = SettlementPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
        ];

        let num_assertions = 3 + (INPUT_PAIRS_PER_TRACE * 2) + 1;

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
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

        let absorb_mask = periodic_values[0];
        let hash_mask = periodic_values[1];
        let copy_mask = periodic_values[2];
        let hold_mask = periodic_values[3];
        let rc0 = periodic_values[4];
        let rc1 = periodic_values[5];
        let rc2 = periodic_values[6];

        let input0 = current[COL_IN0];
        let input1 = current[COL_IN1];

        // Absorb step: next = current + inputs.
        result[0] = absorb_mask * (next[COL_S0] - (current[COL_S0] + input0));
        result[1] = absorb_mask * (next[COL_S1] - (current[COL_S1] + input1));
        result[2] = absorb_mask * (next[COL_S2] - current[COL_S2]);

        // Poseidon round step.
        let t0 = current[COL_S0] + rc0;
        let t1 = current[COL_S1] + rc1;
        let t2 = current[COL_S2] + rc2;

        let s0 = t0.exp(5u64.into());
        let s1 = t1.exp(5u64.into());
        let s2 = t2.exp(5u64.into());

        let two: E = E::from(BaseElement::new(2));
        let hash_s0 = s0 * two + s1 + s2;
        let hash_s1 = s0 + s1 * two + s2;
        let hash_s2 = s0 + s1 + s2 * two;

        result[3] = hash_mask * (next[COL_S0] - hash_s0);
        result[4] = hash_mask * (next[COL_S1] - hash_s1);
        result[5] = hash_mask * (next[COL_S2] - hash_s2);

        // Copy step: state remains unchanged.
        result[6] = copy_mask * (next[COL_S0] - current[COL_S0]);
        result[7] = copy_mask * (next[COL_S1] - current[COL_S1]);
        result[8] = copy_mask * (next[COL_S2] - current[COL_S2]);

        // Hold inputs constant within a cycle.
        result[9] = hold_mask * (next[COL_IN0] - current[COL_IN0]);
        result[10] = hold_mask * (next[COL_IN1] - current[COL_IN1]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        assertions.push(Assertion::single(
            COL_S0,
            0,
            BaseElement::new(SETTLEMENT_DOMAIN_TAG),
        ));
        assertions.push(Assertion::single(COL_S1, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(COL_S2, 0, BaseElement::ONE));

        let inputs = self.pub_inputs.input_elements();
        debug_assert_eq!(inputs.len(), PADDED_INPUT_COUNT);

        for cycle in 0..INPUT_PAIRS_PER_TRACE {
            let row = cycle * CYCLE_LENGTH;
            let in0 = inputs[2 * cycle];
            let in1 = inputs[2 * cycle + 1];
            assertions.push(Assertion::single(COL_IN0, row, in0));
            assertions.push(Assertion::single(COL_IN1, row, in1));
        }

        let final_row = TRACE_LENGTH - 1;
        assertions.push(Assertion::single(
            COL_S0,
            final_row,
            self.pub_inputs.commitment,
        ));

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut columns = Vec::new();
        columns.push(absorb_mask());
        columns.push(hash_mask());
        columns.push(copy_mask());
        columns.push(hold_mask());
        columns.push(round_constants(0));
        columns.push(round_constants(1));
        columns.push(round_constants(2));
        columns
    }
}

fn absorb_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    mask[0] = BaseElement::ONE;
    mask
}

fn hash_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    for step in 1..=8 {
        mask[step] = BaseElement::ONE;
    }
    mask
}

fn copy_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    for step in 9..CYCLE_LENGTH {
        mask[step] = BaseElement::ONE;
    }
    mask
}

fn hold_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ONE; CYCLE_LENGTH];
    mask[CYCLE_LENGTH - 1] = BaseElement::ZERO;
    mask
}

fn round_constants(position: usize) -> Vec<BaseElement> {
    let mut column = Vec::with_capacity(CYCLE_LENGTH);
    for step in 0..CYCLE_LENGTH {
        if (1..=8).contains(&step) {
            column.push(crate::hashing::poseidon_round_constant(step - 1, position));
        } else {
            column.push(BaseElement::ZERO);
        }
    }
    column
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_padding() {
        let inputs = SettlementPublicInputs {
            instruction_count: 1,
            nullifier_count: 1,
            instructions: vec![Felt::new(10); MAX_INSTRUCTIONS],
            nullifiers: vec![Felt::new(11); MAX_NULLIFIERS],
            commitment: Felt::ZERO,
        };
        let flattened = inputs.input_elements();
        assert_eq!(flattened.len(), PADDED_INPUT_COUNT);
    }

    #[test]
    fn test_air_dimensions() {
        let trace_info = TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH);
        let pub_inputs = SettlementPublicInputs {
            instruction_count: 0,
            nullifier_count: 0,
            instructions: vec![Felt::ZERO; MAX_INSTRUCTIONS],
            nullifiers: vec![Felt::ZERO; MAX_NULLIFIERS],
            commitment: Felt::ZERO,
        };
        let options = ProofOptions::new(
            32,
            16,
            0,
            winterfell::FieldExtension::None,
            4,
            31,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        );

        let air = SettlementAir::new(trace_info, pub_inputs, options);
        assert_eq!(air.context().trace_info().width(), TRACE_WIDTH);
        assert_eq!(air.context().trace_len(), TRACE_LENGTH);
    }
}
