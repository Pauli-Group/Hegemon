use serde::{Deserialize, Serialize};

use crate::constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvingKey {
    pub max_inputs: usize,
    pub max_outputs: usize,
    pub balance_slots: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyingKey {
    pub max_inputs: usize,
    pub max_outputs: usize,
    pub balance_slots: usize,
}

pub fn generate_keys() -> (ProvingKey, VerifyingKey) {
    let proving = ProvingKey {
        max_inputs: MAX_INPUTS,
        max_outputs: MAX_OUTPUTS,
        balance_slots: BALANCE_SLOTS,
    };
    let verifying = VerifyingKey {
        max_inputs: MAX_INPUTS,
        max_outputs: MAX_OUTPUTS,
        balance_slots: BALANCE_SLOTS,
    };
    (proving, verifying)
}
