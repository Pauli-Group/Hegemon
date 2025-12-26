use alloc::vec;
use alloc::vec::Vec;
use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::constants::{
    ABSORB_CYCLES, COL_IN0, COL_IN1, COL_S0, COL_S1, COL_S2, COMMITMENT_LIMBS, CYCLE_LENGTH,
    INPUT_PAIRS_PER_TRACE, MAX_INSTRUCTIONS, MAX_NULLIFIERS, NULLIFIER_LIMBS, PADDED_INPUT_COUNT,
    SETTLEMENT_DOMAIN_TAG,
};
use crate::hashing::{Felt, HashFelt};

pub fn commitment_row_01() -> usize {
    (ABSORB_CYCLES - 1) * CYCLE_LENGTH + (CYCLE_LENGTH - 1)
}

pub fn commitment_row_23() -> usize {
    ABSORB_CYCLES * CYCLE_LENGTH + (CYCLE_LENGTH - 1)
}

#[derive(Clone, Debug)]
pub struct SettlementPublicInputs {
    pub instruction_count: u32,
    pub nullifier_count: u32,
    pub instructions: Vec<Felt>,
    pub nullifiers: Vec<HashFelt>,
    pub commitment: HashFelt,
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
        for nf in &self.nullifiers {
            inputs.extend_from_slice(nf);
        }
        while inputs.len() < PADDED_INPUT_COUNT {
            inputs.push(Felt::ZERO);
        }
        inputs
    }
}

impl ToElements<BaseElement> for SettlementPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::with_capacity(
            2 + MAX_INSTRUCTIONS + (MAX_NULLIFIERS * NULLIFIER_LIMBS) + COMMITMENT_LIMBS,
        );
        elements.push(BaseElement::new(self.instruction_count as u64));
        elements.push(BaseElement::new(self.nullifier_count as u64));
        elements.extend(self.instructions.iter().copied());
        for nf in &self.nullifiers {
            elements.extend_from_slice(nf);
        }
        elements.extend(self.commitment);
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
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
        ];

        let num_assertions = 2 * INPUT_PAIRS_PER_TRACE + 7;

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
        let rc0 = periodic_values[2];
        let rc1 = periodic_values[3];
        let rc2 = periodic_values[4];

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

        result[3] = hash_mask * (next[COL_S0] - hash_s0);
        result[4] = hash_mask * (next[COL_S1] - hash_s1);
        result[5] = hash_mask * (next[COL_S2] - hash_s2);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        let inputs = self.pub_inputs.input_elements();
        debug_assert_eq!(inputs.len(), PADDED_INPUT_COUNT);
        let init_in0 = inputs[0];
        let init_in1 = inputs[1];

        assertions.push(Assertion::single(
            COL_S0,
            0,
            BaseElement::new(SETTLEMENT_DOMAIN_TAG) + init_in0,
        ));
        assertions.push(Assertion::single(COL_S1, 0, init_in1));
        assertions.push(Assertion::single(COL_S2, 0, BaseElement::ONE));

        for cycle in 0..INPUT_PAIRS_PER_TRACE {
            let row = cycle * CYCLE_LENGTH;
            let pair_index = cycle + 1;
            let (in0, in1) = if pair_index < ABSORB_CYCLES {
                (inputs[2 * pair_index], inputs[2 * pair_index + 1])
            } else {
                (BaseElement::ZERO, BaseElement::ZERO)
            };
            assertions.push(Assertion::single(COL_IN0, row, in0));
            assertions.push(Assertion::single(COL_IN1, row, in1));
        }

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
        vec![
            absorb_mask(),
            hash_mask(),
            round_constants(0),
            round_constants(1),
            round_constants(2),
        ]
    }
}

fn absorb_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    mask[CYCLE_LENGTH - 1] = BaseElement::ONE;
    mask
}

fn hash_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    for (idx, slot) in mask.iter_mut().enumerate() {
        if idx < transaction_core::constants::POSEIDON_ROUNDS {
            *slot = BaseElement::ONE;
        }
    }
    mask
}

fn round_constants(position: usize) -> Vec<BaseElement> {
    let mut column = Vec::with_capacity(CYCLE_LENGTH);
    for step in 0..CYCLE_LENGTH {
        if step < transaction_core::constants::POSEIDON_ROUNDS {
            column.push(crate::hashing::poseidon_round_constant(step, position));
        } else {
            column.push(BaseElement::ZERO);
        }
    }
    column
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::TRACE_WIDTH;

    #[test]
    fn test_input_padding() {
        let inputs = SettlementPublicInputs {
            instruction_count: 1,
            nullifier_count: 1,
            instructions: vec![Felt::new(10); MAX_INSTRUCTIONS],
            nullifiers: vec![[Felt::new(11); 4]; MAX_NULLIFIERS],
            commitment: [Felt::ZERO; 4],
        };
        let flattened = inputs.input_elements();
        assert_eq!(flattened.len(), PADDED_INPUT_COUNT);
    }

    #[test]
    fn test_air_dimensions() {
        let trace_info = TraceInfo::new(TRACE_WIDTH, crate::constants::TRACE_LENGTH);
        let pub_inputs = SettlementPublicInputs {
            instruction_count: 0,
            nullifier_count: 0,
            instructions: vec![Felt::ZERO; MAX_INSTRUCTIONS],
            nullifiers: vec![[Felt::ZERO; 4]; MAX_NULLIFIERS],
            commitment: [Felt::ZERO; 4],
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
        assert_eq!(air.context().trace_len(), crate::constants::TRACE_LENGTH);
    }
}
