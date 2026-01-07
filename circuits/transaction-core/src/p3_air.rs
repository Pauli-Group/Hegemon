//! Plonky3 AIR for transaction circuits using Poseidon hash.
//!
//! This AIR enforces:
//! - Poseidon hash transitions with explicit absorption/reset steps
//! - Note commitment correctness
//! - Merkle path verification
//! - Nullifier correctness
//! - MASP balance conservation with value balance

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;

use crate::constants::{
    CIRCUIT_MERKLE_DEPTH, MAX_INPUTS, MAX_OUTPUTS, MERKLE_DOMAIN_TAG, NATIVE_ASSET_ID,
    NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG, POSEIDON_ROUNDS, POSEIDON_WIDTH,
};
use crate::poseidon_constants;

pub type Felt = Goldilocks;

// ================================================================================================
// TRACE CONFIGURATION
// ================================================================================================

/// Trace width (columns) for the transaction circuit.
pub const TRACE_WIDTH: usize = 101;

/// Poseidon state columns.
pub const COL_S0: usize = 0;
pub const COL_S1: usize = 1;
pub const COL_S2: usize = 2;

/// Absorbed input pair for the *next* cycle (written at cycle end).
pub const COL_IN0: usize = 3;
pub const COL_IN1: usize = 4;

/// Cycle control flags for the *next* cycle (written at cycle end).
pub const COL_RESET: usize = 5;
pub const COL_DOMAIN: usize = 6;
pub const COL_MERKLE_LEFT_23: usize = 7;

/// Active flags for inputs/outputs (set at note start rows).
pub const COL_IN_ACTIVE0: usize = 8;
pub const COL_IN_ACTIVE1: usize = 9;
pub const COL_OUT_ACTIVE0: usize = 10;
pub const COL_OUT_ACTIVE1: usize = 11;

/// Note values/asset ids (set at note start rows).
pub const COL_IN0_VALUE: usize = 12;
pub const COL_IN0_ASSET: usize = 13;
pub const COL_IN1_VALUE: usize = 14;
pub const COL_IN1_ASSET: usize = 15;
pub const COL_OUT0_VALUE: usize = 16;
pub const COL_OUT0_ASSET: usize = 17;
pub const COL_OUT1_VALUE: usize = 18;
pub const COL_OUT1_ASSET: usize = 19;

/// Balance slots (asset id + running sum in/out).
pub const COL_SLOT0_ASSET: usize = 20;
pub const COL_SLOT0_IN: usize = 21;
pub const COL_SLOT0_OUT: usize = 22;
pub const COL_SLOT1_ASSET: usize = 23;
pub const COL_SLOT1_IN: usize = 24;
pub const COL_SLOT1_OUT: usize = 25;
pub const COL_SLOT2_ASSET: usize = 26;
pub const COL_SLOT2_IN: usize = 27;
pub const COL_SLOT2_OUT: usize = 28;
pub const COL_SLOT3_ASSET: usize = 29;
pub const COL_SLOT3_IN: usize = 30;
pub const COL_SLOT3_OUT: usize = 31;

/// Selector flags: input note 0.
pub const COL_SEL_IN0_SLOT0: usize = 32;
pub const COL_SEL_IN0_SLOT1: usize = 33;
pub const COL_SEL_IN0_SLOT2: usize = 34;
pub const COL_SEL_IN0_SLOT3: usize = 35;

/// Selector flags: input note 1.
pub const COL_SEL_IN1_SLOT0: usize = 36;
pub const COL_SEL_IN1_SLOT1: usize = 37;
pub const COL_SEL_IN1_SLOT2: usize = 38;
pub const COL_SEL_IN1_SLOT3: usize = 39;

/// Selector flags: output note 0.
pub const COL_SEL_OUT0_SLOT0: usize = 40;
pub const COL_SEL_OUT0_SLOT1: usize = 41;
pub const COL_SEL_OUT0_SLOT2: usize = 42;
pub const COL_SEL_OUT0_SLOT3: usize = 43;

/// Selector flags: output note 1.
pub const COL_SEL_OUT1_SLOT0: usize = 44;
pub const COL_SEL_OUT1_SLOT1: usize = 45;
pub const COL_SEL_OUT1_SLOT2: usize = 46;
pub const COL_SEL_OUT1_SLOT3: usize = 47;

/// Fee and value balance (sign + magnitude).
pub const COL_FEE: usize = 48;
pub const COL_VALUE_BALANCE_SIGN: usize = 49;
pub const COL_VALUE_BALANCE_MAG: usize = 50;

/// Note start flags (mark commitment absorption for each note).
pub const COL_NOTE_START_IN0: usize = 51;
pub const COL_NOTE_START_IN1: usize = 52;
pub const COL_NOTE_START_OUT0: usize = 53;
pub const COL_NOTE_START_OUT1: usize = 54;

/// Captured hash limbs (first two limbs) carried across squeeze cycles.
pub const COL_OUT0: usize = 55;
pub const COL_OUT1: usize = 56;

/// Merkle pair flag for left limbs 0/1 (set on the second pair).
pub const COL_MERKLE_LEFT_01: usize = 57;

/// Capture flag to latch out0/out1 from the Poseidon state at cycle boundaries.
pub const COL_CAPTURE: usize = 58;

/// Merkle pair flag for right limbs 2/3 (third pair).
pub const COL_MERKLE_RIGHT_23: usize = 59;

/// Merkle pair flag for right limbs 0/1 (fourth pair).
pub const COL_MERKLE_RIGHT_01: usize = 60;

/// Capture flag to latch out2/out3 (squeeze output) at cycle boundaries.
pub const COL_CAPTURE2: usize = 61;

/// Captured hash limbs (second two limbs) carried across cycles.
pub const COL_OUT2: usize = 62;
pub const COL_OUT3: usize = 63;

/// Direction bit for Merkle path (0 = current is left, 1 = current is right).
pub const COL_DIR: usize = 64;

/// Stablecoin policy binding and issuance fields (final row only).
pub const COL_STABLECOIN_ENABLED: usize = 65;
pub const COL_STABLECOIN_ASSET: usize = 66;
pub const COL_STABLECOIN_POLICY_VERSION: usize = 67;
pub const COL_STABLECOIN_ISSUANCE_SIGN: usize = 68;
pub const COL_STABLECOIN_ISSUANCE_MAG: usize = 69;
pub const COL_STABLECOIN_POLICY_HASH0: usize = 70;
pub const COL_STABLECOIN_POLICY_HASH1: usize = 71;
pub const COL_STABLECOIN_POLICY_HASH2: usize = 72;
pub const COL_STABLECOIN_POLICY_HASH3: usize = 73;
pub const COL_STABLECOIN_ORACLE0: usize = 74;
pub const COL_STABLECOIN_ORACLE1: usize = 75;
pub const COL_STABLECOIN_ORACLE2: usize = 76;
pub const COL_STABLECOIN_ORACLE3: usize = 77;
pub const COL_STABLECOIN_ATTEST0: usize = 78;
pub const COL_STABLECOIN_ATTEST1: usize = 79;
pub const COL_STABLECOIN_ATTEST2: usize = 80;
pub const COL_STABLECOIN_ATTEST3: usize = 81;
pub const COL_STABLECOIN_SLOT_SEL0: usize = 82;
pub const COL_STABLECOIN_SLOT_SEL1: usize = 83;
pub const COL_STABLECOIN_SLOT_SEL2: usize = 84;
pub const COL_STABLECOIN_SLOT_SEL3: usize = 85;

/// Schedule counters (binary).
pub const COL_STEP_BIT0: usize = 86;
pub const COL_STEP_BIT1: usize = 87;
pub const COL_STEP_BIT2: usize = 88;
pub const COL_STEP_BIT3: usize = 89;
pub const COL_STEP_BIT4: usize = 90;
pub const COL_STEP_BIT5: usize = 91;
pub const COL_CYCLE_BIT0: usize = 92;
pub const COL_CYCLE_BIT1: usize = 93;
pub const COL_CYCLE_BIT2: usize = 94;
pub const COL_CYCLE_BIT3: usize = 95;
pub const COL_CYCLE_BIT4: usize = 96;
pub const COL_CYCLE_BIT5: usize = 97;
pub const COL_CYCLE_BIT6: usize = 98;
pub const COL_CYCLE_BIT7: usize = 99;
pub const COL_CYCLE_BIT8: usize = 100;

/// Cycle length: power of 2, must be > POSEIDON_ROUNDS.
pub const CYCLE_LENGTH: usize = 64;

/// Number of absorb cycles for a commitment hash (14 inputs / rate 2 = 7 cycles).
pub const COMMITMENT_ABSORB_CYCLES: usize = 7;

/// One squeeze cycle to output the final two limbs.
pub const COMMITMENT_SQUEEZE_CYCLES: usize = 1;

/// Total cycles for a commitment hash (absorb + squeeze).
pub const COMMITMENT_CYCLES: usize = COMMITMENT_ABSORB_CYCLES + COMMITMENT_SQUEEZE_CYCLES;

/// Number of absorb cycles for a nullifier hash (6 inputs / rate 2 = 3 cycles).
pub const NULLIFIER_ABSORB_CYCLES: usize = 3;

/// One squeeze cycle to output the final two limbs.
pub const NULLIFIER_SQUEEZE_CYCLES: usize = 1;

/// Total cycles for a nullifier hash (absorb + squeeze).
pub const NULLIFIER_CYCLES: usize = NULLIFIER_ABSORB_CYCLES + NULLIFIER_SQUEEZE_CYCLES;

/// Number of absorb cycles per Merkle level (8 inputs / rate 2 = 4 cycles).
pub const MERKLE_ABSORB_CYCLES: usize = 4;

/// One squeeze cycle to output the final two limbs.
pub const MERKLE_SQUEEZE_CYCLES: usize = 1;

/// Total cycles per Merkle level.
pub const MERKLE_CYCLES_PER_LEVEL: usize = MERKLE_ABSORB_CYCLES + MERKLE_SQUEEZE_CYCLES;

/// Number of cycles for Merkle path verification (hash per level).
pub const MERKLE_CYCLES: usize = CIRCUIT_MERKLE_DEPTH * MERKLE_CYCLES_PER_LEVEL;

/// Cycles per input note: commitment + merkle + nullifier.
pub const CYCLES_PER_INPUT: usize = COMMITMENT_CYCLES + MERKLE_CYCLES + NULLIFIER_CYCLES;

/// Dummy cycle at the start to seed the first absorption.
pub const DUMMY_CYCLES: usize = 1;

/// Total cycles used by the real computation (excluding padding cycles).
pub const TOTAL_USED_CYCLES: usize =
    DUMMY_CYCLES + (MAX_INPUTS * CYCLES_PER_INPUT) + (MAX_OUTPUTS * COMMITMENT_CYCLES);

/// Minimum trace length (power of 2).
/// For MAX_INPUTS=2, MAX_OUTPUTS=2, depth=32: 361 cycles * 64 = 23104 -> 32768.
pub const MIN_TRACE_LENGTH: usize = 32768;

/// Total cycles in the trace (including padding cycles).
pub const TOTAL_TRACE_CYCLES: usize = MIN_TRACE_LENGTH / CYCLE_LENGTH;

#[inline]
pub fn round_constant(round: usize, position: usize) -> Felt {
    Felt::from_canonical_u64(poseidon_constants::ROUND_CONSTANTS[round][position])
}

// ================================================================================================
// PUBLIC INPUTS
// ================================================================================================

#[derive(Clone, Debug)]
pub struct TransactionPublicInputsP3 {
    pub input_flags: Vec<Felt>,
    pub output_flags: Vec<Felt>,
    pub nullifiers: Vec<[Felt; 4]>,
    pub commitments: Vec<[Felt; 4]>,
    pub fee: Felt,
    pub value_balance_sign: Felt,
    pub value_balance_magnitude: Felt,
    pub merkle_root: [Felt; 4],
    pub stablecoin_enabled: Felt,
    pub stablecoin_asset: Felt,
    pub stablecoin_policy_version: Felt,
    pub stablecoin_issuance_sign: Felt,
    pub stablecoin_issuance_magnitude: Felt,
    pub stablecoin_policy_hash: [Felt; 4],
    pub stablecoin_oracle_commitment: [Felt; 4],
    pub stablecoin_attestation_commitment: [Felt; 4],
}

impl Default for TransactionPublicInputsP3 {
    fn default() -> Self {
        let zero = [Felt::zero(); 4];
        Self {
            input_flags: vec![Felt::zero(); MAX_INPUTS],
            output_flags: vec![Felt::zero(); MAX_OUTPUTS],
            nullifiers: vec![zero; MAX_INPUTS],
            commitments: vec![zero; MAX_OUTPUTS],
            fee: Felt::zero(),
            value_balance_sign: Felt::zero(),
            value_balance_magnitude: Felt::zero(),
            merkle_root: zero,
            stablecoin_enabled: Felt::zero(),
            stablecoin_asset: Felt::zero(),
            stablecoin_policy_version: Felt::zero(),
            stablecoin_issuance_sign: Felt::zero(),
            stablecoin_issuance_magnitude: Felt::zero(),
            stablecoin_policy_hash: zero,
            stablecoin_oracle_commitment: zero,
            stablecoin_attestation_commitment: zero,
        }
    }
}

impl TransactionPublicInputsP3 {
    pub fn to_vec(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity((MAX_INPUTS + MAX_OUTPUTS) * 5 + 24);
        elements.extend(&self.input_flags);
        elements.extend(&self.output_flags);
        for nf in &self.nullifiers {
            elements.extend_from_slice(nf);
        }
        for cm in &self.commitments {
            elements.extend_from_slice(cm);
        }
        elements.push(self.fee);
        elements.push(self.value_balance_sign);
        elements.push(self.value_balance_magnitude);
        elements.extend_from_slice(&self.merkle_root);
        elements.push(self.stablecoin_enabled);
        elements.push(self.stablecoin_asset);
        elements.push(self.stablecoin_policy_version);
        elements.push(self.stablecoin_issuance_sign);
        elements.push(self.stablecoin_issuance_magnitude);
        elements.extend_from_slice(&self.stablecoin_policy_hash);
        elements.extend_from_slice(&self.stablecoin_oracle_commitment);
        elements.extend_from_slice(&self.stablecoin_attestation_commitment);
        elements
    }

    pub fn try_from_slice(elements: &[Felt]) -> Result<Self, String> {
        let expected_len = (MAX_INPUTS + MAX_OUTPUTS) * 5 + 24;
        if elements.len() != expected_len {
            return Err(format!(
                "transaction public inputs length mismatch: expected {expected_len}, got {}",
                elements.len()
            ));
        }

        let mut idx = 0usize;
        fn take<'a>(slice: &'a [Felt], idx: &mut usize, len: usize) -> &'a [Felt] {
            let start = *idx;
            let end = start + len;
            *idx = end;
            &slice[start..end]
        }

        let input_flags = take(elements, &mut idx, MAX_INPUTS).to_vec();
        let output_flags = take(elements, &mut idx, MAX_OUTPUTS).to_vec();

        let mut nullifiers = Vec::with_capacity(MAX_INPUTS);
        for _ in 0..MAX_INPUTS {
            let nf = take(elements, &mut idx, 4);
            nullifiers.push([nf[0], nf[1], nf[2], nf[3]]);
        }

        let mut commitments = Vec::with_capacity(MAX_OUTPUTS);
        for _ in 0..MAX_OUTPUTS {
            let cm = take(elements, &mut idx, 4);
            commitments.push([cm[0], cm[1], cm[2], cm[3]]);
        }

        let fee = elements[idx];
        idx += 1;
        let value_balance_sign = elements[idx];
        idx += 1;
        let value_balance_magnitude = elements[idx];
        idx += 1;

        let merkle_root = {
            let root = take(elements, &mut idx, 4);
            [root[0], root[1], root[2], root[3]]
        };

        let stablecoin_enabled = elements[idx];
        idx += 1;
        let stablecoin_asset = elements[idx];
        idx += 1;
        let stablecoin_policy_version = elements[idx];
        idx += 1;
        let stablecoin_issuance_sign = elements[idx];
        idx += 1;
        let stablecoin_issuance_magnitude = elements[idx];
        idx += 1;

        let stablecoin_policy_hash = {
            let hash = take(elements, &mut idx, 4);
            [hash[0], hash[1], hash[2], hash[3]]
        };
        let stablecoin_oracle_commitment = {
            let hash = take(elements, &mut idx, 4);
            [hash[0], hash[1], hash[2], hash[3]]
        };
        let stablecoin_attestation_commitment = {
            let hash = take(elements, &mut idx, 4);
            [hash[0], hash[1], hash[2], hash[3]]
        };

        Ok(Self {
            input_flags,
            output_flags,
            nullifiers,
            commitments,
            fee,
            value_balance_sign,
            value_balance_magnitude,
            merkle_root,
            stablecoin_enabled,
            stablecoin_asset,
            stablecoin_policy_version,
            stablecoin_issuance_sign,
            stablecoin_issuance_magnitude,
            stablecoin_policy_hash,
            stablecoin_oracle_commitment,
            stablecoin_attestation_commitment,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.input_flags.len() != MAX_INPUTS {
            return Err("input_flags length mismatch".into());
        }
        if self.output_flags.len() != MAX_OUTPUTS {
            return Err("output_flags length mismatch".into());
        }
        if self.nullifiers.len() != MAX_INPUTS {
            return Err("nullifiers length mismatch".into());
        }
        if self.commitments.len() != MAX_OUTPUTS {
            return Err("commitments length mismatch".into());
        }

        let zero = Felt::zero();
        let one = Felt::one();
        let is_zero_hash = |value: &[Felt; 4]| value.iter().all(|elem| *elem == zero);

        for (idx, flag) in self.input_flags.iter().enumerate() {
            if *flag != zero && *flag != one {
                return Err("input flag must be 0 or 1".into());
            }
            let nf = &self.nullifiers[idx];
            if *flag == zero && !is_zero_hash(nf) {
                return Err("inactive input has non-zero nullifier".into());
            }
            if *flag == one && is_zero_hash(nf) {
                return Err("active input has zero nullifier".into());
            }
        }

        for (idx, flag) in self.output_flags.iter().enumerate() {
            if *flag != zero && *flag != one {
                return Err("output flag must be 0 or 1".into());
            }
            let cm = &self.commitments[idx];
            if *flag == zero && !is_zero_hash(cm) {
                return Err("inactive output has non-zero commitment".into());
            }
            if *flag == one && is_zero_hash(cm) {
                return Err("active output has zero commitment".into());
            }
        }

        let has_input = self.nullifiers.iter().any(|nf| !is_zero_hash(nf));
        let has_output = self.commitments.iter().any(|cm| !is_zero_hash(cm));
        if !has_input && !has_output {
            return Err("Transaction has no inputs or outputs".into());
        }

        if self.value_balance_sign != zero && self.value_balance_sign != one {
            return Err("Value balance sign must be 0 or 1".into());
        }
        if self.stablecoin_enabled != zero && self.stablecoin_enabled != one {
            return Err("Stablecoin enabled flag must be 0 or 1".into());
        }
        if self.stablecoin_issuance_sign != zero && self.stablecoin_issuance_sign != one {
            return Err("Stablecoin issuance sign must be 0 or 1".into());
        }

        Ok(())
    }
}

// ================================================================================================
// CYCLE LAYOUT HELPERS
// ================================================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CycleKind {
    Dummy,
    InputCommitment {
        input: usize,
        chunk: usize,
    },
    InputMerkle {
        input: usize,
        level: usize,
        chunk: usize,
    },
    InputNullifier {
        input: usize,
        chunk: usize,
    },
    OutputCommitment {
        output: usize,
        chunk: usize,
    },
    Padding,
}

fn cycle_kind(cycle: usize) -> CycleKind {
    if cycle == 0 {
        return CycleKind::Dummy;
    }

    if cycle < DUMMY_CYCLES + MAX_INPUTS * CYCLES_PER_INPUT {
        let rel = cycle - DUMMY_CYCLES;
        let input = rel / CYCLES_PER_INPUT;
        let offset = rel % CYCLES_PER_INPUT;
        if offset < COMMITMENT_CYCLES {
            return CycleKind::InputCommitment {
                input,
                chunk: offset,
            };
        }
        let merkle_offset = offset - COMMITMENT_CYCLES;
        if merkle_offset < MERKLE_CYCLES {
            let level = merkle_offset / MERKLE_CYCLES_PER_LEVEL;
            let chunk = merkle_offset % MERKLE_CYCLES_PER_LEVEL;
            return CycleKind::InputMerkle {
                input,
                level,
                chunk,
            };
        }
        return CycleKind::InputNullifier {
            input,
            chunk: merkle_offset - MERKLE_CYCLES,
        };
    }

    let output_start = DUMMY_CYCLES + MAX_INPUTS * CYCLES_PER_INPUT;
    let output_end = output_start + MAX_OUTPUTS * COMMITMENT_CYCLES;
    if cycle < output_end {
        let rel = cycle - output_start;
        let output = rel / COMMITMENT_CYCLES;
        let chunk = rel % COMMITMENT_CYCLES;
        return CycleKind::OutputCommitment { output, chunk };
    }

    CycleKind::Padding
}

pub fn cycle_reset_domain(cycle: usize) -> Option<u64> {
    match cycle_kind(cycle) {
        CycleKind::InputCommitment { chunk: 0, .. } => Some(NOTE_DOMAIN_TAG),
        CycleKind::InputMerkle { chunk: 0, .. } => Some(MERKLE_DOMAIN_TAG),
        CycleKind::InputNullifier { chunk: 0, .. } => Some(NULLIFIER_DOMAIN_TAG),
        CycleKind::OutputCommitment { chunk: 0, .. } => Some(NOTE_DOMAIN_TAG),
        _ => None,
    }
}

pub fn cycle_is_merkle_pair(cycle: usize, pair: usize) -> bool {
    matches!(cycle_kind(cycle), CycleKind::InputMerkle { chunk, .. } if chunk == pair)
}

pub fn cycle_is_merkle_left_23(cycle: usize) -> bool {
    cycle_is_merkle_pair(cycle, 0)
}

pub fn cycle_is_merkle_left_01(cycle: usize) -> bool {
    cycle_is_merkle_pair(cycle, 1)
}

pub fn cycle_is_merkle_right_23(cycle: usize) -> bool {
    cycle_is_merkle_pair(cycle, 2)
}

pub fn cycle_is_merkle_right_01(cycle: usize) -> bool {
    cycle_is_merkle_pair(cycle, 3)
}

pub fn cycle_is_squeeze(cycle: usize) -> bool {
    match cycle_kind(cycle) {
        CycleKind::InputCommitment { chunk, .. } => chunk >= COMMITMENT_ABSORB_CYCLES,
        CycleKind::InputNullifier { chunk, .. } => chunk >= NULLIFIER_ABSORB_CYCLES,
        CycleKind::OutputCommitment { chunk, .. } => chunk >= COMMITMENT_ABSORB_CYCLES,
        CycleKind::InputMerkle { chunk, .. } => chunk >= MERKLE_ABSORB_CYCLES,
        _ => false,
    }
}

pub fn input_commitment_start_cycle(input_index: usize) -> usize {
    DUMMY_CYCLES + input_index * CYCLES_PER_INPUT
}

pub fn input_merkle_start_cycle(input_index: usize) -> usize {
    input_commitment_start_cycle(input_index) + COMMITMENT_CYCLES
}

pub fn input_nullifier_start_cycle(input_index: usize) -> usize {
    input_merkle_start_cycle(input_index) + MERKLE_CYCLES
}

pub fn output_commitment_start_cycle(output_index: usize) -> usize {
    DUMMY_CYCLES + MAX_INPUTS * CYCLES_PER_INPUT + output_index * COMMITMENT_CYCLES
}

pub fn nullifier_output_row(input_index: usize) -> usize {
    (input_nullifier_start_cycle(input_index) + NULLIFIER_CYCLES) * CYCLE_LENGTH - 1
}

pub fn merkle_root_output_row(input_index: usize) -> usize {
    (input_merkle_start_cycle(input_index) + MERKLE_CYCLES) * CYCLE_LENGTH - 1
}

pub fn commitment_output_row(output_index: usize) -> usize {
    (output_commitment_start_cycle(output_index) + COMMITMENT_CYCLES) * CYCLE_LENGTH - 1
}

pub fn note_start_row_input(input_index: usize) -> usize {
    (input_commitment_start_cycle(input_index) - 1) * CYCLE_LENGTH + (CYCLE_LENGTH - 1)
}

pub fn note_start_row_output(output_index: usize) -> usize {
    (output_commitment_start_cycle(output_index) - 1) * CYCLE_LENGTH + (CYCLE_LENGTH - 1)
}

// ================================================================================================
// AIR IMPLEMENTATION
// ================================================================================================

pub struct TransactionAirP3;

impl BaseAir<Felt> for TransactionAirP3 {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<AB> Air<AB> for TransactionAirP3
where
    AB: AirBuilderWithPublicValues<F = Felt>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current = main.row_slice(0);
        let next = main.row_slice(1);

        let is_first_row = builder.is_first_row();
        let one = AB::Expr::one();
        let two = AB::Expr::from_canonical_u64(2);
        let not_first_row = one.clone() - is_first_row.clone();

        let step_bits = [
            current[COL_STEP_BIT0],
            current[COL_STEP_BIT1],
            current[COL_STEP_BIT2],
            current[COL_STEP_BIT3],
            current[COL_STEP_BIT4],
            current[COL_STEP_BIT5],
        ];
        let step_bits_next = [
            next[COL_STEP_BIT0],
            next[COL_STEP_BIT1],
            next[COL_STEP_BIT2],
            next[COL_STEP_BIT3],
            next[COL_STEP_BIT4],
            next[COL_STEP_BIT5],
        ];
        let cycle_bits = [
            current[COL_CYCLE_BIT0],
            current[COL_CYCLE_BIT1],
            current[COL_CYCLE_BIT2],
            current[COL_CYCLE_BIT3],
            current[COL_CYCLE_BIT4],
            current[COL_CYCLE_BIT5],
            current[COL_CYCLE_BIT6],
            current[COL_CYCLE_BIT7],
            current[COL_CYCLE_BIT8],
        ];
        let cycle_bits_next = [
            next[COL_CYCLE_BIT0],
            next[COL_CYCLE_BIT1],
            next[COL_CYCLE_BIT2],
            next[COL_CYCLE_BIT3],
            next[COL_CYCLE_BIT4],
            next[COL_CYCLE_BIT5],
            next[COL_CYCLE_BIT6],
            next[COL_CYCLE_BIT7],
            next[COL_CYCLE_BIT8],
        ];

        let bit_selector = |bits: &[AB::Var], value: usize| -> AB::Expr {
            let mut acc = one.clone();
            for (idx, bit) in bits.iter().enumerate() {
                let bit_expr: AB::Expr = (*bit).into();
                if ((value >> idx) & 1) == 1 {
                    acc = acc * bit_expr;
                } else {
                    acc = acc * (one.clone() - bit_expr);
                }
            }
            acc
        };
        let cycle_selector = |value: usize| -> AB::Expr { bit_selector(&cycle_bits, value) };
        let row_selector = |row: usize| -> AB::Expr {
            let cycle = row / CYCLE_LENGTH;
            let step = row % CYCLE_LENGTH;
            cycle_selector(cycle) * bit_selector(&step_bits, step)
        };

        let absorb_flag = bit_selector(&step_bits, CYCLE_LENGTH - 1);
        let hash_flag = one.clone() - absorb_flag.clone();

        let mut rc0 = AB::Expr::zero();
        let mut rc1 = AB::Expr::zero();
        let mut rc2 = AB::Expr::zero();
        for round in 0..POSEIDON_ROUNDS {
            let sel = bit_selector(&step_bits, round);
            rc0 += sel.clone()
                * AB::Expr::from_canonical_u64(poseidon_constants::ROUND_CONSTANTS[round][0]);
            rc1 += sel.clone()
                * AB::Expr::from_canonical_u64(poseidon_constants::ROUND_CONSTANTS[round][1]);
            rc2 += sel
                * AB::Expr::from_canonical_u64(poseidon_constants::ROUND_CONSTANTS[round][2]);
        }

        let final_row_mask = row_selector(MIN_TRACE_LENGTH - 2);

        let public_values = builder.public_values();
        let expected_len = (MAX_INPUTS + MAX_OUTPUTS) * 5 + 24;
        debug_assert_eq!(public_values.len(), expected_len);
        let pv = |index: usize| -> AB::Expr { public_values[index].into() };

        let mut idx = 0usize;
        let input_flags: Vec<AB::Expr> = (0..MAX_INPUTS).map(|i| pv(idx + i)).collect();
        idx += MAX_INPUTS;
        let output_flags: Vec<AB::Expr> = (0..MAX_OUTPUTS).map(|i| pv(idx + i)).collect();
        idx += MAX_OUTPUTS;

        let mut nullifiers = Vec::with_capacity(MAX_INPUTS);
        for _ in 0..MAX_INPUTS {
            let limbs = vec![pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
            idx += 4;
            nullifiers.push(limbs);
        }

        let mut commitments = Vec::with_capacity(MAX_OUTPUTS);
        for _ in 0..MAX_OUTPUTS {
            let limbs = vec![pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
            idx += 4;
            commitments.push(limbs);
        }

        let fee = pv(idx);
        idx += 1;
        let value_balance_sign = pv(idx);
        idx += 1;
        let value_balance_magnitude = pv(idx);
        idx += 1;

        let merkle_root = vec![pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
        idx += 4;

        let stablecoin_enabled = pv(idx);
        idx += 1;
        let stablecoin_asset = pv(idx);
        idx += 1;
        let stablecoin_policy_version = pv(idx);
        idx += 1;
        let stablecoin_issuance_sign = pv(idx);
        idx += 1;
        let stablecoin_issuance_magnitude = pv(idx);
        idx += 1;

        let stablecoin_policy_hash = vec![pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
        idx += 4;
        let stablecoin_oracle_commitment = vec![pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
        idx += 4;
        let stablecoin_attestation_commitment = vec![
            pv(idx),
            pv(idx + 1),
            pv(idx + 2),
            pv(idx + 3),
        ];

        let expected_note_start_in0 = row_selector(note_start_row_input(0));
        let expected_note_start_in1 = row_selector(note_start_row_input(1));
        let expected_note_start_out0 = row_selector(note_start_row_output(0));
        let expected_note_start_out1 = row_selector(note_start_row_output(1));

        let nf0_row = row_selector(nullifier_output_row(0));
        let nf1_row = row_selector(nullifier_output_row(1));
        let mr0_row = row_selector(merkle_root_output_row(0));
        let mr1_row = row_selector(merkle_root_output_row(1));
        let cm0_row = row_selector(commitment_output_row(0));
        let cm1_row = row_selector(commitment_output_row(1));

        let mut expected_reset = AB::Expr::zero();
        let mut expected_domain = AB::Expr::zero();
        let mut expected_left_23 = AB::Expr::zero();
        let mut expected_left_01 = AB::Expr::zero();
        let mut expected_right_23 = AB::Expr::zero();
        let mut expected_right_01 = AB::Expr::zero();
        let mut expected_capture = AB::Expr::zero();
        let mut expected_capture2 = AB::Expr::zero();

        for cycle in 0..TOTAL_TRACE_CYCLES {
            let row_sel = cycle_selector(cycle) * absorb_flag.clone();
            let next_cycle = cycle + 1;
            if next_cycle < TOTAL_TRACE_CYCLES {
                if let Some(domain_tag) = cycle_reset_domain(next_cycle) {
                    expected_reset += row_sel.clone();
                    expected_domain +=
                        row_sel.clone() * AB::Expr::from_canonical_u64(domain_tag);
                }
                if cycle_is_merkle_left_23(next_cycle) {
                    expected_left_23 += row_sel.clone();
                }
                if cycle_is_merkle_left_01(next_cycle) {
                    expected_left_01 += row_sel.clone();
                }
                if cycle_is_merkle_right_23(next_cycle) {
                    expected_right_23 += row_sel.clone();
                }
                if cycle_is_merkle_right_01(next_cycle) {
                    expected_right_01 += row_sel.clone();
                }
                if cycle_is_squeeze(next_cycle) {
                    expected_capture += row_sel.clone();
                }
            }
            if cycle_is_squeeze(cycle) {
                expected_capture2 += row_sel.clone();
            }
        }

        let t0 = current[COL_S0] + rc0;
        let t1 = current[COL_S1] + rc1;
        let t2 = current[COL_S2] + rc2;

        let s0 = t0.exp_const_u64::<5>();
        let s1 = t1.exp_const_u64::<5>();
        let s2 = t2.exp_const_u64::<5>();

        let mds = poseidon_constants::MDS_MATRIX;
        let m00 = AB::Expr::from_canonical_u64(mds[0][0]);
        let m01 = AB::Expr::from_canonical_u64(mds[0][1]);
        let m02 = AB::Expr::from_canonical_u64(mds[0][2]);
        let m10 = AB::Expr::from_canonical_u64(mds[1][0]);
        let m11 = AB::Expr::from_canonical_u64(mds[1][1]);
        let m12 = AB::Expr::from_canonical_u64(mds[1][2]);
        let m20 = AB::Expr::from_canonical_u64(mds[2][0]);
        let m21 = AB::Expr::from_canonical_u64(mds[2][1]);
        let m22 = AB::Expr::from_canonical_u64(mds[2][2]);

        let hash_s0 = s0.clone() * m00 + s1.clone() * m01 + s2.clone() * m02;
        let hash_s1 = s0.clone() * m10 + s1.clone() * m11 + s2.clone() * m12;
        let hash_s2 = s0 * m20 + s1 * m21 + s2 * m22;
        let copy_flag = one.clone() - hash_flag.clone() - absorb_flag.clone();

        let reset = current[COL_RESET];
        let domain = current[COL_DOMAIN];
        let in0 = current[COL_IN0];
        let in1 = current[COL_IN1];

        let start_s0 = domain + in0;
        let start_s1 = in1;
        let start_s2 = one.clone();

        let cont_s0 = current[COL_S0] + in0;
        let cont_s1 = current[COL_S1] + in1;
        let cont_s2 = current[COL_S2];

        let absorb_s0 = reset * start_s0 + (one.clone() - reset) * cont_s0;
        let absorb_s1 = reset * start_s1 + (one.clone() - reset) * cont_s1;
        let absorb_s2 = reset * start_s2 + (one.clone() - reset) * cont_s2;

        let expected_s0 = hash_flag.clone() * hash_s0
            + copy_flag.clone() * current[COL_S0]
            + absorb_flag.clone() * absorb_s0;
        let expected_s1 = hash_flag.clone() * hash_s1
            + copy_flag.clone() * current[COL_S1]
            + absorb_flag.clone() * absorb_s1;
        let expected_s2 = hash_flag * hash_s2
            + copy_flag * current[COL_S2]
            + absorb_flag.clone() * absorb_s2;

        {
            let mut when_first = builder.when_first_row();
            for bit in step_bits.iter().chain(cycle_bits.iter()) {
                when_first.assert_zero(*bit);
            }
        }

        let mut when = builder.when_transition();
        when.assert_zero(next[COL_S0] - expected_s0);
        when.assert_zero(next[COL_S1] - expected_s1);
        when.assert_zero(next[COL_S2] - expected_s2);

        for bit in step_bits.iter() {
            when.assert_bool(*bit);
        }
        for bit in cycle_bits.iter() {
            when.assert_bool(*bit);
        }

        let mut carry = one.clone();
        for (idx, bit) in step_bits.iter().enumerate() {
            let bit_expr: AB::Expr = (*bit).into();
            let carry_next = carry.clone() * bit_expr.clone();
            let next_expr: AB::Expr = step_bits_next[idx].into();
            when.assert_zero(
                next_expr - (bit_expr + carry.clone() - two.clone() * carry_next.clone()),
            );
            carry = carry_next;
        }

        let mut carry = absorb_flag.clone();
        for (idx, bit) in cycle_bits.iter().enumerate() {
            let bit_expr: AB::Expr = (*bit).into();
            let carry_next = carry.clone() * bit_expr.clone();
            let next_expr: AB::Expr = cycle_bits_next[idx].into();
            when.assert_zero(
                next_expr - (bit_expr + carry.clone() - two.clone() * carry_next.clone()),
            );
            carry = carry_next;
        }

        when.assert_bool(reset);
        when.assert_bool(value_balance_sign.clone());
        when.assert_bool(stablecoin_enabled.clone());
        when.assert_bool(stablecoin_issuance_sign.clone());

        let stablecoin_sel_cols = [
            COL_STABLECOIN_SLOT_SEL0,
            COL_STABLECOIN_SLOT_SEL1,
            COL_STABLECOIN_SLOT_SEL2,
            COL_STABLECOIN_SLOT_SEL3,
        ];
        for &col in stablecoin_sel_cols.iter() {
            let sel = current[col];
            when.assert_bool(sel);
        }

        let slot_assets = [
            current[COL_SLOT0_ASSET],
            current[COL_SLOT1_ASSET],
            current[COL_SLOT2_ASSET],
            current[COL_SLOT3_ASSET],
        ];
        let slot_in_cols = [COL_SLOT0_IN, COL_SLOT1_IN, COL_SLOT2_IN, COL_SLOT3_IN];
        let slot_out_cols = [COL_SLOT0_OUT, COL_SLOT1_OUT, COL_SLOT2_OUT, COL_SLOT3_OUT];

        let stablecoin_sel_sum = stablecoin_sel_cols
            .iter()
            .fold(AB::Expr::zero(), |acc, col| acc + current[*col]);
        when.assert_zero(final_row_mask.clone() * (stablecoin_sel_sum - stablecoin_enabled.clone()));

        for slot in 0..4 {
            when.assert_zero(
                final_row_mask.clone()
                    * current[stablecoin_sel_cols[slot]]
                    * (slot_assets[slot] - stablecoin_asset.clone()),
            );
        }

        let stablecoin_signed = stablecoin_issuance_magnitude.clone()
            - (stablecoin_issuance_sign.clone()
                * stablecoin_issuance_magnitude.clone()
                * two.clone());
        let mut selected_delta = AB::Expr::zero();
        for slot in 0..4 {
            let delta = current[slot_in_cols[slot]] - current[slot_out_cols[slot]];
            selected_delta += current[stablecoin_sel_cols[slot]] * delta;
        }
        when.assert_zero(final_row_mask.clone() * (selected_delta - stablecoin_signed));

        for slot in 1..4 {
            let delta = current[slot_in_cols[slot]] - current[slot_out_cols[slot]];
            when.assert_zero(
                final_row_mask.clone() * delta * (one.clone() - current[stablecoin_sel_cols[slot]]),
            );
        }

        let stablecoin_disabled = one.clone() - stablecoin_enabled.clone();
        let stablecoin_zero_cols = [
            COL_STABLECOIN_ASSET,
            COL_STABLECOIN_POLICY_VERSION,
            COL_STABLECOIN_ISSUANCE_SIGN,
            COL_STABLECOIN_ISSUANCE_MAG,
            COL_STABLECOIN_POLICY_HASH0,
            COL_STABLECOIN_POLICY_HASH1,
            COL_STABLECOIN_POLICY_HASH2,
            COL_STABLECOIN_POLICY_HASH3,
            COL_STABLECOIN_ORACLE0,
            COL_STABLECOIN_ORACLE1,
            COL_STABLECOIN_ORACLE2,
            COL_STABLECOIN_ORACLE3,
            COL_STABLECOIN_ATTEST0,
            COL_STABLECOIN_ATTEST1,
            COL_STABLECOIN_ATTEST2,
            COL_STABLECOIN_ATTEST3,
        ];
        for &col in stablecoin_zero_cols.iter() {
            when.assert_zero(final_row_mask.clone() * stablecoin_disabled.clone() * current[col]);
        }

        let active_cols = [
            COL_IN_ACTIVE0,
            COL_IN_ACTIVE1,
            COL_OUT_ACTIVE0,
            COL_OUT_ACTIVE1,
        ];
        for &col in active_cols.iter() {
            when.assert_bool(current[col]);
        }

        for &sel_col in SELECTOR_COLUMNS.iter() {
            when.assert_bool(current[sel_col]);
        }

        let input_active = [current[COL_IN_ACTIVE0], current[COL_IN_ACTIVE1]];
        let output_active = [current[COL_OUT_ACTIVE0], current[COL_OUT_ACTIVE1]];
        let note_start_in0 = current[COL_NOTE_START_IN0];
        let note_start_in1 = current[COL_NOTE_START_IN1];
        let note_start_out0 = current[COL_NOTE_START_OUT0];
        let note_start_out1 = current[COL_NOTE_START_OUT1];

        let in0_sel_sum = current[COL_SEL_IN0_SLOT0]
            + current[COL_SEL_IN0_SLOT1]
            + current[COL_SEL_IN0_SLOT2]
            + current[COL_SEL_IN0_SLOT3];
        when.assert_zero(note_start_in0 * (in0_sel_sum - input_active[0]));

        let in1_sel_sum = current[COL_SEL_IN1_SLOT0]
            + current[COL_SEL_IN1_SLOT1]
            + current[COL_SEL_IN1_SLOT2]
            + current[COL_SEL_IN1_SLOT3];
        when.assert_zero(note_start_in1 * (in1_sel_sum - input_active[1]));

        let out0_sel_sum = current[COL_SEL_OUT0_SLOT0]
            + current[COL_SEL_OUT0_SLOT1]
            + current[COL_SEL_OUT0_SLOT2]
            + current[COL_SEL_OUT0_SLOT3];
        when.assert_zero(note_start_out0 * (out0_sel_sum - output_active[0]));

        let out1_sel_sum = current[COL_SEL_OUT1_SLOT0]
            + current[COL_SEL_OUT1_SLOT1]
            + current[COL_SEL_OUT1_SLOT2]
            + current[COL_SEL_OUT1_SLOT3];
        when.assert_zero(note_start_out1 * (out1_sel_sum - output_active[1]));

        let in0_asset = current[COL_IN0_ASSET];
        let in0_selected = current[COL_SEL_IN0_SLOT0] * slot_assets[0]
            + current[COL_SEL_IN0_SLOT1] * slot_assets[1]
            + current[COL_SEL_IN0_SLOT2] * slot_assets[2]
            + current[COL_SEL_IN0_SLOT3] * slot_assets[3];
        when.assert_zero(note_start_in0 * (in0_asset * input_active[0] - in0_selected));

        let in1_asset = current[COL_IN1_ASSET];
        let in1_selected = current[COL_SEL_IN1_SLOT0] * slot_assets[0]
            + current[COL_SEL_IN1_SLOT1] * slot_assets[1]
            + current[COL_SEL_IN1_SLOT2] * slot_assets[2]
            + current[COL_SEL_IN1_SLOT3] * slot_assets[3];
        when.assert_zero(note_start_in1 * (in1_asset * input_active[1] - in1_selected));

        let out0_asset = current[COL_OUT0_ASSET];
        let out0_selected = current[COL_SEL_OUT0_SLOT0] * slot_assets[0]
            + current[COL_SEL_OUT0_SLOT1] * slot_assets[1]
            + current[COL_SEL_OUT0_SLOT2] * slot_assets[2]
            + current[COL_SEL_OUT0_SLOT3] * slot_assets[3];
        when.assert_zero(note_start_out0 * (out0_asset * output_active[0] - out0_selected));

        let out1_asset = current[COL_OUT1_ASSET];
        let out1_selected = current[COL_SEL_OUT1_SLOT0] * slot_assets[0]
            + current[COL_SEL_OUT1_SLOT1] * slot_assets[1]
            + current[COL_SEL_OUT1_SLOT2] * slot_assets[2]
            + current[COL_SEL_OUT1_SLOT3] * slot_assets[3];
        when.assert_zero(note_start_out1 * (out1_asset * output_active[1] - out1_selected));

        let in_values = [current[COL_IN0_VALUE], current[COL_IN1_VALUE]];
        let out_values = [current[COL_OUT0_VALUE], current[COL_OUT1_VALUE]];

        let sel_in = [
            [
                COL_SEL_IN0_SLOT0,
                COL_SEL_IN0_SLOT1,
                COL_SEL_IN0_SLOT2,
                COL_SEL_IN0_SLOT3,
            ],
            [
                COL_SEL_IN1_SLOT0,
                COL_SEL_IN1_SLOT1,
                COL_SEL_IN1_SLOT2,
                COL_SEL_IN1_SLOT3,
            ],
        ];
        let sel_out = [
            [
                COL_SEL_OUT0_SLOT0,
                COL_SEL_OUT0_SLOT1,
                COL_SEL_OUT0_SLOT2,
                COL_SEL_OUT0_SLOT3,
            ],
            [
                COL_SEL_OUT1_SLOT0,
                COL_SEL_OUT1_SLOT1,
                COL_SEL_OUT1_SLOT2,
                COL_SEL_OUT1_SLOT3,
            ],
        ];
        let note_in_flags = [note_start_in0, note_start_in1];
        let note_out_flags = [note_start_out0, note_start_out1];

        for slot in 0..4 {
            let mut add_in = AB::Expr::zero();
            let mut add_out = AB::Expr::zero();
            for note in 0..2 {
                add_in += note_in_flags[note] * current[sel_in[note][slot]] * in_values[note];
                add_out += note_out_flags[note] * current[sel_out[note][slot]] * out_values[note];
            }
            when.assert_zero(
                not_first_row.clone()
                    * (next[slot_in_cols[slot]] - (current[slot_in_cols[slot]] + add_in)),
            );
            when.assert_zero(
                not_first_row.clone()
                    * (next[slot_out_cols[slot]] - (current[slot_out_cols[slot]] + add_out)),
            );
        }

        let note_start_any = note_start_in0 + note_start_in1 + note_start_out0 + note_start_out1;
        when.assert_zero(
            note_start_any * (current[COL_SLOT0_ASSET]
                - AB::Expr::from_canonical_u64(NATIVE_ASSET_ID)),
        );

        let vb_signed = value_balance_magnitude.clone()
            - (value_balance_sign.clone() * value_balance_magnitude.clone() * two.clone());
        let slot0_in = current[COL_SLOT0_IN];
        let slot0_out = current[COL_SLOT0_OUT];
        when.assert_zero(final_row_mask.clone() * (slot0_in + vb_signed - slot0_out - fee.clone()));

        for slot in 1..4 {
            let delta = current[slot_in_cols[slot]] - current[slot_out_cols[slot]];
            when.assert_zero(final_row_mask.clone() * stablecoin_disabled.clone() * delta);
        }

        let dir = current[COL_DIR];
        when.assert_bool(dir);
        when.assert_zero((one.clone() - reset) * (next[COL_DIR] - current[COL_DIR]));

        let left_23 = current[COL_MERKLE_LEFT_23];
        let left_01 = current[COL_MERKLE_LEFT_01];
        let right_23 = current[COL_MERKLE_RIGHT_23];
        let right_01 = current[COL_MERKLE_RIGHT_01];
        let next_dir = next[COL_DIR];
        let not_next_dir = one.clone() - next_dir;

        when.assert_zero(
            absorb_flag.clone() * left_23 * not_next_dir.clone() * (current[COL_IN0] - next[COL_OUT2]),
        );
        when.assert_zero(
            absorb_flag.clone() * left_23 * not_next_dir.clone() * (current[COL_IN1] - next[COL_OUT3]),
        );
        when.assert_zero(
            absorb_flag.clone() * left_01 * not_next_dir.clone() * (current[COL_IN0] - next[COL_OUT0]),
        );
        when.assert_zero(
            absorb_flag.clone() * left_01 * not_next_dir.clone() * (current[COL_IN1] - next[COL_OUT1]),
        );
        when.assert_zero(absorb_flag.clone() * right_23 * next_dir * (current[COL_IN0] - next[COL_OUT2]));
        when.assert_zero(absorb_flag.clone() * right_23 * next_dir * (current[COL_IN1] - next[COL_OUT3]));
        when.assert_zero(absorb_flag.clone() * right_01 * next_dir * (current[COL_IN0] - next[COL_OUT0]));
        when.assert_zero(absorb_flag.clone() * right_01 * next_dir * (current[COL_IN1] - next[COL_OUT1]));

        let capture = current[COL_CAPTURE];
        when.assert_bool(capture);
        let capture_guard = current[COL_IN_ACTIVE0] + one.clone();
        when.assert_zero(capture * (one.clone() - absorb_flag.clone()) * capture_guard.clone());
        when.assert_zero(
            next[COL_OUT0]
                - (capture * current[COL_S0] + (one.clone() - capture) * current[COL_OUT0]),
        );
        when.assert_zero(
            next[COL_OUT1]
                - (capture * current[COL_S1] + (one.clone() - capture) * current[COL_OUT1]),
        );

        let capture2 = current[COL_CAPTURE2];
        when.assert_bool(capture2);
        when.assert_zero(capture2 * (one.clone() - absorb_flag.clone()) * capture_guard);
        when.assert_zero(
            next[COL_OUT2]
                - (capture2 * current[COL_S0] + (one.clone() - capture2) * current[COL_OUT2]),
        );
        when.assert_zero(
            next[COL_OUT3]
                - (capture2 * current[COL_S1] + (one.clone() - capture2) * current[COL_OUT3]),
        );

        let note_flags = [
            (COL_NOTE_START_IN0, COL_IN0_VALUE, COL_IN0_ASSET),
            (COL_NOTE_START_IN1, COL_IN1_VALUE, COL_IN1_ASSET),
            (COL_NOTE_START_OUT0, COL_OUT0_VALUE, COL_OUT0_ASSET),
            (COL_NOTE_START_OUT1, COL_OUT1_VALUE, COL_OUT1_ASSET),
        ];

        for (flag_col, value_col, asset_col) in note_flags {
            let flag = current[flag_col];
            when.assert_zero(flag * (current[COL_IN0] - current[value_col]));
            when.assert_zero(flag * (current[COL_IN1] - current[asset_col]));
        }

        when.assert_zero(current[COL_RESET] - expected_reset);
        when.assert_zero(current[COL_DOMAIN] - expected_domain);
        when.assert_zero(current[COL_MERKLE_LEFT_23] - expected_left_23);
        when.assert_zero(current[COL_MERKLE_LEFT_01] - expected_left_01);
        when.assert_zero(current[COL_MERKLE_RIGHT_23] - expected_right_23);
        when.assert_zero(current[COL_MERKLE_RIGHT_01] - expected_right_01);
        when.assert_zero(current[COL_CAPTURE] - expected_capture);
        when.assert_zero(current[COL_CAPTURE2] - expected_capture2);
        when.assert_zero(current[COL_NOTE_START_IN0] - expected_note_start_in0.clone());
        when.assert_zero(current[COL_NOTE_START_IN1] - expected_note_start_in1.clone());
        when.assert_zero(current[COL_NOTE_START_OUT0] - expected_note_start_out0.clone());
        when.assert_zero(current[COL_NOTE_START_OUT1] - expected_note_start_out1.clone());

        let nf0_gate = nf0_row * input_flags[0].clone();
        when.assert_zero(nf0_gate.clone() * (current[COL_OUT0] - nullifiers[0][0].clone()));
        when.assert_zero(nf0_gate.clone() * (current[COL_OUT1] - nullifiers[0][1].clone()));
        when.assert_zero(nf0_gate.clone() * (current[COL_S0] - nullifiers[0][2].clone()));
        when.assert_zero(nf0_gate * (current[COL_S1] - nullifiers[0][3].clone()));

        let nf1_gate = nf1_row * input_flags[1].clone();
        when.assert_zero(nf1_gate.clone() * (current[COL_OUT0] - nullifiers[1][0].clone()));
        when.assert_zero(nf1_gate.clone() * (current[COL_OUT1] - nullifiers[1][1].clone()));
        when.assert_zero(nf1_gate.clone() * (current[COL_S0] - nullifiers[1][2].clone()));
        when.assert_zero(nf1_gate * (current[COL_S1] - nullifiers[1][3].clone()));

        let mr0_gate = mr0_row * input_flags[0].clone();
        when.assert_zero(mr0_gate.clone() * (current[COL_OUT0] - merkle_root[0].clone()));
        when.assert_zero(mr0_gate.clone() * (current[COL_OUT1] - merkle_root[1].clone()));
        when.assert_zero(mr0_gate.clone() * (current[COL_S0] - merkle_root[2].clone()));
        when.assert_zero(mr0_gate * (current[COL_S1] - merkle_root[3].clone()));

        let mr1_gate = mr1_row * input_flags[1].clone();
        when.assert_zero(mr1_gate.clone() * (current[COL_OUT0] - merkle_root[0].clone()));
        when.assert_zero(mr1_gate.clone() * (current[COL_OUT1] - merkle_root[1].clone()));
        when.assert_zero(mr1_gate.clone() * (current[COL_S0] - merkle_root[2].clone()));
        when.assert_zero(mr1_gate * (current[COL_S1] - merkle_root[3].clone()));

        let cm0_gate = cm0_row * output_flags[0].clone();
        when.assert_zero(cm0_gate.clone() * (current[COL_OUT0] - commitments[0][0].clone()));
        when.assert_zero(cm0_gate.clone() * (current[COL_OUT1] - commitments[0][1].clone()));
        when.assert_zero(cm0_gate.clone() * (current[COL_S0] - commitments[0][2].clone()));
        when.assert_zero(cm0_gate * (current[COL_S1] - commitments[0][3].clone()));

        let cm1_gate = cm1_row * output_flags[1].clone();
        when.assert_zero(cm1_gate.clone() * (current[COL_OUT0] - commitments[1][0].clone()));
        when.assert_zero(cm1_gate.clone() * (current[COL_OUT1] - commitments[1][1].clone()));
        when.assert_zero(cm1_gate.clone() * (current[COL_S0] - commitments[1][2].clone()));
        when.assert_zero(cm1_gate * (current[COL_S1] - commitments[1][3].clone()));

        when.assert_zero(
            expected_note_start_in0 * (current[COL_IN_ACTIVE0] - input_flags[0].clone()),
        );
        when.assert_zero(
            expected_note_start_in1 * (current[COL_IN_ACTIVE1] - input_flags[1].clone()),
        );
        when.assert_zero(
            expected_note_start_out0 * (current[COL_OUT_ACTIVE0] - output_flags[0].clone()),
        );
        when.assert_zero(
            expected_note_start_out1 * (current[COL_OUT_ACTIVE1] - output_flags[1].clone()),
        );

        when.assert_zero(final_row_mask.clone() * (current[COL_FEE] - fee));
        when.assert_zero(final_row_mask.clone() * (current[COL_VALUE_BALANCE_SIGN] - value_balance_sign));
        when.assert_zero(
            final_row_mask.clone() * (current[COL_VALUE_BALANCE_MAG] - value_balance_magnitude),
        );
        when.assert_zero(final_row_mask.clone() * (current[COL_STABLECOIN_ENABLED] - stablecoin_enabled));
        when.assert_zero(final_row_mask.clone() * (current[COL_STABLECOIN_ASSET] - stablecoin_asset));
        when.assert_zero(
            final_row_mask.clone() * (current[COL_STABLECOIN_POLICY_VERSION] - stablecoin_policy_version),
        );
        when.assert_zero(
            final_row_mask.clone() * (current[COL_STABLECOIN_ISSUANCE_SIGN] - stablecoin_issuance_sign),
        );
        when.assert_zero(
            final_row_mask.clone() * (current[COL_STABLECOIN_ISSUANCE_MAG] - stablecoin_issuance_magnitude),
        );

        for (col, value) in [
            (COL_STABLECOIN_POLICY_HASH0, stablecoin_policy_hash[0].clone()),
            (COL_STABLECOIN_POLICY_HASH1, stablecoin_policy_hash[1].clone()),
            (COL_STABLECOIN_POLICY_HASH2, stablecoin_policy_hash[2].clone()),
            (COL_STABLECOIN_POLICY_HASH3, stablecoin_policy_hash[3].clone()),
            (COL_STABLECOIN_ORACLE0, stablecoin_oracle_commitment[0].clone()),
            (COL_STABLECOIN_ORACLE1, stablecoin_oracle_commitment[1].clone()),
            (COL_STABLECOIN_ORACLE2, stablecoin_oracle_commitment[2].clone()),
            (COL_STABLECOIN_ORACLE3, stablecoin_oracle_commitment[3].clone()),
            (COL_STABLECOIN_ATTEST0, stablecoin_attestation_commitment[0].clone()),
            (COL_STABLECOIN_ATTEST1, stablecoin_attestation_commitment[1].clone()),
            (COL_STABLECOIN_ATTEST2, stablecoin_attestation_commitment[2].clone()),
            (COL_STABLECOIN_ATTEST3, stablecoin_attestation_commitment[3].clone()),
        ] {
            when.assert_zero(final_row_mask.clone() * (current[col] - value));
        }
    }
}

const SELECTOR_COLUMNS: [usize; 16] = [
    COL_SEL_IN0_SLOT0,
    COL_SEL_IN0_SLOT1,
    COL_SEL_IN0_SLOT2,
    COL_SEL_IN0_SLOT3,
    COL_SEL_IN1_SLOT0,
    COL_SEL_IN1_SLOT1,
    COL_SEL_IN1_SLOT2,
    COL_SEL_IN1_SLOT3,
    COL_SEL_OUT0_SLOT0,
    COL_SEL_OUT0_SLOT1,
    COL_SEL_OUT0_SLOT2,
    COL_SEL_OUT0_SLOT3,
    COL_SEL_OUT1_SLOT0,
    COL_SEL_OUT1_SLOT1,
    COL_SEL_OUT1_SLOT2,
    COL_SEL_OUT1_SLOT3,
];

// ================================================================================================
// POSEIDON HELPERS
// ================================================================================================

#[inline]
pub fn sbox(x: Felt) -> Felt {
    x.exp_u64(5)
}

pub fn mds_mix(state: &[Felt; 3]) -> [Felt; 3] {
    let mut out = [Felt::zero(); 3];
    for (row_idx, out_slot) in out.iter_mut().enumerate() {
        let mut acc = Felt::zero();
        for (col_idx, value) in state.iter().enumerate() {
            let coeff = Felt::from_canonical_u64(poseidon_constants::MDS_MATRIX[row_idx][col_idx]);
            acc += *value * coeff;
        }
        *out_slot = acc;
    }
    out
}

pub fn poseidon_round(state: &mut [Felt; 3], round: usize) {
    state[0] += round_constant(round, 0);
    state[1] += round_constant(round, 1);
    state[2] += round_constant(round, 2);
    state[0] = sbox(state[0]);
    state[1] = sbox(state[1]);
    state[2] = sbox(state[2]);
    *state = mds_mix(state);
}

pub fn poseidon_permutation(state: &mut [Felt; 3]) {
    for round in 0..POSEIDON_ROUNDS {
        poseidon_round(state, round);
    }
}

pub fn poseidon_hash(domain_tag: u64, inputs: &[Felt]) -> Felt {
    let mut state = [Felt::from_canonical_u64(domain_tag), Felt::zero(), Felt::one()];
    let rate = POSEIDON_WIDTH - 1;
    let mut cursor = 0;
    while cursor < inputs.len() {
        let take = core::cmp::min(rate, inputs.len() - cursor);
        for i in 0..take {
            state[i] += inputs[cursor + i];
        }
        poseidon_permutation(&mut state);
        cursor += take;
    }
    state[0]
}
