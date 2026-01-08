//! Plonky3 AIR for transaction circuits using Poseidon2 hash.
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
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::constants::{
    CIRCUIT_MERKLE_DEPTH, MAX_INPUTS, MAX_OUTPUTS, MERKLE_DOMAIN_TAG, NATIVE_ASSET_ID,
    NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG, POSEIDON2_EXTERNAL_ROUNDS, POSEIDON2_INTERNAL_ROUNDS,
    POSEIDON2_RATE, POSEIDON2_STEPS, POSEIDON2_WIDTH, POSEIDON_ROUNDS, POSEIDON_WIDTH,
};
use crate::{poseidon2_constants, poseidon_constants};

pub type Felt = Goldilocks;

// ================================================================================================
// TRACE CONFIGURATION
// ================================================================================================

/// Poseidon2 state columns.
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

/// Absorbed inputs for the *next* cycle (written at cycle end).
pub const COL_IN0: usize = 12;
pub const COL_IN1: usize = 13;
pub const COL_IN2: usize = 14;
pub const COL_IN3: usize = 15;
pub const COL_IN4: usize = 16;
pub const COL_IN5: usize = 17;

/// Cycle control flags for the *next* cycle (written at cycle end).
pub const COL_RESET: usize = 18;
pub const COL_DOMAIN: usize = 19;
pub const COL_DIR: usize = 20;

/// Merkle schedule flags for the *next* cycle (written at cycle end).
pub const COL_MERKLE_LEFT: usize = 21;
pub const COL_MERKLE_RIGHT: usize = 22;

/// Active flags for inputs/outputs (set at note start rows).
pub const COL_IN_ACTIVE0: usize = 23;
pub const COL_IN_ACTIVE1: usize = 24;
pub const COL_OUT_ACTIVE0: usize = 25;
pub const COL_OUT_ACTIVE1: usize = 26;

/// Note values/asset ids (set at note start rows).
pub const COL_IN0_VALUE: usize = 27;
pub const COL_IN0_ASSET: usize = 28;
pub const COL_IN1_VALUE: usize = 29;
pub const COL_IN1_ASSET: usize = 30;
pub const COL_OUT0_VALUE: usize = 31;
pub const COL_OUT0_ASSET: usize = 32;
pub const COL_OUT1_VALUE: usize = 33;
pub const COL_OUT1_ASSET: usize = 34;

/// Balance slots (asset id + running sum in/out).
pub const COL_SLOT0_ASSET: usize = 35;
pub const COL_SLOT0_IN: usize = 36;
pub const COL_SLOT0_OUT: usize = 37;
pub const COL_SLOT1_ASSET: usize = 38;
pub const COL_SLOT1_IN: usize = 39;
pub const COL_SLOT1_OUT: usize = 40;
pub const COL_SLOT2_ASSET: usize = 41;
pub const COL_SLOT2_IN: usize = 42;
pub const COL_SLOT2_OUT: usize = 43;
pub const COL_SLOT3_ASSET: usize = 44;
pub const COL_SLOT3_IN: usize = 45;
pub const COL_SLOT3_OUT: usize = 46;

/// Selector flags: input note 0.
pub const COL_SEL_IN0_SLOT0: usize = 47;
pub const COL_SEL_IN0_SLOT1: usize = 48;
pub const COL_SEL_IN0_SLOT2: usize = 49;
pub const COL_SEL_IN0_SLOT3: usize = 50;

/// Selector flags: input note 1.
pub const COL_SEL_IN1_SLOT0: usize = 51;
pub const COL_SEL_IN1_SLOT1: usize = 52;
pub const COL_SEL_IN1_SLOT2: usize = 53;
pub const COL_SEL_IN1_SLOT3: usize = 54;

/// Selector flags: output note 0.
pub const COL_SEL_OUT0_SLOT0: usize = 55;
pub const COL_SEL_OUT0_SLOT1: usize = 56;
pub const COL_SEL_OUT0_SLOT2: usize = 57;
pub const COL_SEL_OUT0_SLOT3: usize = 58;

/// Selector flags: output note 1.
pub const COL_SEL_OUT1_SLOT0: usize = 59;
pub const COL_SEL_OUT1_SLOT1: usize = 60;
pub const COL_SEL_OUT1_SLOT2: usize = 61;
pub const COL_SEL_OUT1_SLOT3: usize = 62;

/// Fee and value balance (sign + magnitude).
pub const COL_FEE: usize = 63;
pub const COL_VALUE_BALANCE_SIGN: usize = 64;
pub const COL_VALUE_BALANCE_MAG: usize = 65;

/// Captured hash limbs (rate = 6).
pub const COL_OUT0: usize = 66;
pub const COL_OUT1: usize = 67;
pub const COL_OUT2: usize = 68;
pub const COL_OUT3: usize = 69;
pub const COL_OUT4: usize = 70;
pub const COL_OUT5: usize = 71;

/// Stablecoin policy binding and issuance fields (final row only).
pub const COL_STABLECOIN_ENABLED: usize = 72;
pub const COL_STABLECOIN_ASSET: usize = 73;
pub const COL_STABLECOIN_POLICY_VERSION: usize = 74;
pub const COL_STABLECOIN_ISSUANCE_SIGN: usize = 75;
pub const COL_STABLECOIN_ISSUANCE_MAG: usize = 76;
pub const COL_STABLECOIN_POLICY_HASH0: usize = 77;
pub const COL_STABLECOIN_POLICY_HASH1: usize = 78;
pub const COL_STABLECOIN_POLICY_HASH2: usize = 79;
pub const COL_STABLECOIN_POLICY_HASH3: usize = 80;
pub const COL_STABLECOIN_POLICY_HASH4: usize = 81;
pub const COL_STABLECOIN_POLICY_HASH5: usize = 82;
pub const COL_STABLECOIN_ORACLE0: usize = 83;
pub const COL_STABLECOIN_ORACLE1: usize = 84;
pub const COL_STABLECOIN_ORACLE2: usize = 85;
pub const COL_STABLECOIN_ORACLE3: usize = 86;
pub const COL_STABLECOIN_ORACLE4: usize = 87;
pub const COL_STABLECOIN_ORACLE5: usize = 88;
pub const COL_STABLECOIN_ATTEST0: usize = 89;
pub const COL_STABLECOIN_ATTEST1: usize = 90;
pub const COL_STABLECOIN_ATTEST2: usize = 91;
pub const COL_STABLECOIN_ATTEST3: usize = 92;
pub const COL_STABLECOIN_ATTEST4: usize = 93;
pub const COL_STABLECOIN_ATTEST5: usize = 94;
pub const COL_STABLECOIN_SLOT_SEL0: usize = 95;
pub const COL_STABLECOIN_SLOT_SEL1: usize = 96;
pub const COL_STABLECOIN_SLOT_SEL2: usize = 97;
pub const COL_STABLECOIN_SLOT_SEL3: usize = 98;
/// Base trace width (columns) for the transaction circuit.
pub const BASE_TRACE_WIDTH: usize = COL_STABLECOIN_SLOT_SEL3 + 1;

// ================================================================================================
// SCHEDULE COLUMNS (fixed schedule stored in main trace)
// ================================================================================================

/// Poseidon2 hash flag for each row (1 during permutation steps).
pub const PREP_HASH_FLAG: usize = 0;
/// Poseidon2 absorb flag for each row (1 on the absorb step).
pub const PREP_ABSORB_FLAG: usize = PREP_HASH_FLAG + 1;
/// Poseidon2 round-kind selectors.
pub const PREP_INIT_ROUND: usize = PREP_ABSORB_FLAG + 1;
pub const PREP_EXTERNAL_ROUND: usize = PREP_INIT_ROUND + 1;
pub const PREP_INTERNAL_ROUND: usize = PREP_EXTERNAL_ROUND + 1;
/// Poseidon2 round constants (per row).
pub const PREP_RC0: usize = PREP_INTERNAL_ROUND + 1;
pub const PREP_RC1: usize = PREP_RC0 + 1;
pub const PREP_RC2: usize = PREP_RC1 + 1;
pub const PREP_RC3: usize = PREP_RC2 + 1;
pub const PREP_RC4: usize = PREP_RC3 + 1;
pub const PREP_RC5: usize = PREP_RC4 + 1;
pub const PREP_RC6: usize = PREP_RC5 + 1;
pub const PREP_RC7: usize = PREP_RC6 + 1;
pub const PREP_RC8: usize = PREP_RC7 + 1;
pub const PREP_RC9: usize = PREP_RC8 + 1;
pub const PREP_RC10: usize = PREP_RC9 + 1;
pub const PREP_RC11: usize = PREP_RC10 + 1;
/// Cycle-boundary schedule flags (precomputed at cycle end rows).
pub const PREP_RESET: usize = PREP_RC11 + 1;
pub const PREP_DOMAIN: usize = PREP_RESET + 1;
pub const PREP_MERKLE_LEFT: usize = PREP_DOMAIN + 1;
pub const PREP_MERKLE_RIGHT: usize = PREP_MERKLE_LEFT + 1;
pub const PREP_CAPTURE: usize = PREP_MERKLE_RIGHT + 1;
/// Note start flags.
pub const PREP_NOTE_START_IN0: usize = PREP_CAPTURE + 1;
pub const PREP_NOTE_START_IN1: usize = PREP_NOTE_START_IN0 + 1;
pub const PREP_NOTE_START_OUT0: usize = PREP_NOTE_START_IN1 + 1;
pub const PREP_NOTE_START_OUT1: usize = PREP_NOTE_START_OUT0 + 1;
/// Row selector flags for public input assertions.
pub const PREP_FINAL_ROW: usize = PREP_NOTE_START_OUT1 + 1;
pub const PREP_NF0_ROW: usize = PREP_FINAL_ROW + 1;
pub const PREP_NF1_ROW: usize = PREP_NF0_ROW + 1;
pub const PREP_MR0_ROW: usize = PREP_NF1_ROW + 1;
pub const PREP_MR1_ROW: usize = PREP_MR0_ROW + 1;
pub const PREP_CM0_ROW: usize = PREP_MR1_ROW + 1;
pub const PREP_CM1_ROW: usize = PREP_CM0_ROW + 1;

/// Schedule trace width (columns).
pub const PREPROCESSED_WIDTH: usize = PREP_CM1_ROW + 1;

/// Schedule columns are appended after the witness columns in the main trace.
pub const COL_SCHEDULE_START: usize = BASE_TRACE_WIDTH;

/// Trace width (columns) for the transaction circuit.
pub const TRACE_WIDTH: usize = COL_SCHEDULE_START + PREPROCESSED_WIDTH;

/// Cycle length: power of 2, must be > POSEIDON2_STEPS.
pub const CYCLE_LENGTH: usize = 32;

/// Number of absorb cycles for a commitment hash (14 inputs / rate 6 = 3 cycles).
pub const COMMITMENT_ABSORB_CYCLES: usize = 3;

/// No squeeze cycles needed when output matches the rate.
pub const COMMITMENT_SQUEEZE_CYCLES: usize = 0;

/// Total cycles for a commitment hash (absorb + squeeze).
pub const COMMITMENT_CYCLES: usize = COMMITMENT_ABSORB_CYCLES + COMMITMENT_SQUEEZE_CYCLES;

/// Number of absorb cycles for a nullifier hash (6 inputs / rate 6 = 1 cycle).
pub const NULLIFIER_ABSORB_CYCLES: usize = 1;

/// No squeeze cycles needed when output matches the rate.
pub const NULLIFIER_SQUEEZE_CYCLES: usize = 0;

/// Total cycles for a nullifier hash (absorb + squeeze).
pub const NULLIFIER_CYCLES: usize = NULLIFIER_ABSORB_CYCLES + NULLIFIER_SQUEEZE_CYCLES;

/// Number of absorb cycles per Merkle level (12 inputs / rate 6 = 2 cycles).
pub const MERKLE_ABSORB_CYCLES: usize = 2;

/// No squeeze cycles needed when output matches the rate.
pub const MERKLE_SQUEEZE_CYCLES: usize = 0;

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
/// For MAX_INPUTS=2, MAX_OUTPUTS=2, depth=32: 143 cycles * 32 = 4576 -> 8192.
pub const MIN_TRACE_LENGTH: usize = 8192;

/// Total cycles in the trace (including padding cycles).
pub const TOTAL_TRACE_CYCLES: usize = MIN_TRACE_LENGTH / CYCLE_LENGTH;

#[inline]
pub fn round_constant(round: usize, position: usize) -> Felt {
    Felt::from_u64(poseidon_constants::ROUND_CONSTANTS[round][position])
}

// ================================================================================================
// PUBLIC INPUTS
// ================================================================================================

#[derive(Clone, Debug)]
pub struct TransactionPublicInputsP3 {
    pub input_flags: Vec<Felt>,
    pub output_flags: Vec<Felt>,
    pub nullifiers: Vec<[Felt; 6]>,
    pub commitments: Vec<[Felt; 6]>,
    pub fee: Felt,
    pub value_balance_sign: Felt,
    pub value_balance_magnitude: Felt,
    pub merkle_root: [Felt; 6],
    pub stablecoin_enabled: Felt,
    pub stablecoin_asset: Felt,
    pub stablecoin_policy_version: Felt,
    pub stablecoin_issuance_sign: Felt,
    pub stablecoin_issuance_magnitude: Felt,
    pub stablecoin_policy_hash: [Felt; 6],
    pub stablecoin_oracle_commitment: [Felt; 6],
    pub stablecoin_attestation_commitment: [Felt; 6],
}

impl Default for TransactionPublicInputsP3 {
    fn default() -> Self {
        let zero6 = [Felt::ZERO; 6];
        Self {
            input_flags: vec![Felt::ZERO; MAX_INPUTS],
            output_flags: vec![Felt::ZERO; MAX_OUTPUTS],
            nullifiers: vec![zero6; MAX_INPUTS],
            commitments: vec![zero6; MAX_OUTPUTS],
            fee: Felt::ZERO,
            value_balance_sign: Felt::ZERO,
            value_balance_magnitude: Felt::ZERO,
            merkle_root: zero6,
            stablecoin_enabled: Felt::ZERO,
            stablecoin_asset: Felt::ZERO,
            stablecoin_policy_version: Felt::ZERO,
            stablecoin_issuance_sign: Felt::ZERO,
            stablecoin_issuance_magnitude: Felt::ZERO,
            stablecoin_policy_hash: zero6,
            stablecoin_oracle_commitment: zero6,
            stablecoin_attestation_commitment: zero6,
        }
    }
}

impl TransactionPublicInputsP3 {
    pub const fn expected_len() -> usize {
        (MAX_INPUTS + MAX_OUTPUTS) * (1 + POSEIDON2_RATE) + 32
    }

    pub fn to_vec(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(Self::expected_len());
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
        let expected_len = Self::expected_len();
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
            let nf = take(elements, &mut idx, 6);
            nullifiers.push([nf[0], nf[1], nf[2], nf[3], nf[4], nf[5]]);
        }

        let mut commitments = Vec::with_capacity(MAX_OUTPUTS);
        for _ in 0..MAX_OUTPUTS {
            let cm = take(elements, &mut idx, 6);
            commitments.push([cm[0], cm[1], cm[2], cm[3], cm[4], cm[5]]);
        }

        let fee = elements[idx];
        idx += 1;
        let value_balance_sign = elements[idx];
        idx += 1;
        let value_balance_magnitude = elements[idx];
        idx += 1;

        let merkle_root = {
            let root = take(elements, &mut idx, 6);
            [root[0], root[1], root[2], root[3], root[4], root[5]]
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
            let hash = take(elements, &mut idx, 6);
            [hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]]
        };
        let stablecoin_oracle_commitment = {
            let hash = take(elements, &mut idx, 6);
            [hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]]
        };
        let stablecoin_attestation_commitment = {
            let hash = take(elements, &mut idx, 6);
            [hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]]
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

        let zero = Felt::ZERO;
        let one = Felt::ONE;
        let is_zero_hash = |value: &[Felt; 6]| value.iter().all(|elem| *elem == zero);

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

pub fn cycle_is_merkle_left(cycle: usize) -> bool {
    matches!(cycle_kind(cycle), CycleKind::InputMerkle { chunk: 0, .. })
}

pub fn cycle_is_merkle_right(cycle: usize) -> bool {
    matches!(cycle_kind(cycle), CycleKind::InputMerkle { chunk: 1, .. })
}

pub fn cycle_is_output(cycle: usize) -> bool {
    match cycle_kind(cycle) {
        CycleKind::InputCommitment { chunk, .. } => chunk + 1 == COMMITMENT_CYCLES,
        CycleKind::InputNullifier { chunk, .. } => chunk + 1 == NULLIFIER_CYCLES,
        CycleKind::OutputCommitment { chunk, .. } => chunk + 1 == COMMITMENT_CYCLES,
        CycleKind::InputMerkle { chunk, .. } => chunk + 1 == MERKLE_CYCLES_PER_LEVEL,
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

pub fn build_schedule_trace() -> RowMajorMatrix<Felt> {
    let trace_len = MIN_TRACE_LENGTH;
    let mut values = vec![Felt::ZERO; trace_len * PREPROCESSED_WIDTH];

    for row in 0..trace_len {
        let step = row % CYCLE_LENGTH;
        let cycle = row / CYCLE_LENGTH;
        let row_slice =
            &mut values[row * PREPROCESSED_WIDTH..(row + 1) * PREPROCESSED_WIDTH];

        row_slice[PREP_HASH_FLAG] = Felt::from_bool(step < POSEIDON2_STEPS);
        row_slice[PREP_ABSORB_FLAG] = Felt::from_bool(step == CYCLE_LENGTH - 1);
        if step < POSEIDON2_STEPS {
            if step == 0 {
                row_slice[PREP_INIT_ROUND] = Felt::ONE;
            } else if step <= POSEIDON2_EXTERNAL_ROUNDS {
                let idx = step - 1;
                row_slice[PREP_EXTERNAL_ROUND] = Felt::ONE;
                let rc = &poseidon2_constants::EXTERNAL_ROUND_CONSTANTS[0][idx];
                row_slice[PREP_RC0] = Felt::from_u64(rc[0]);
                row_slice[PREP_RC1] = Felt::from_u64(rc[1]);
                row_slice[PREP_RC2] = Felt::from_u64(rc[2]);
                row_slice[PREP_RC3] = Felt::from_u64(rc[3]);
                row_slice[PREP_RC4] = Felt::from_u64(rc[4]);
                row_slice[PREP_RC5] = Felt::from_u64(rc[5]);
                row_slice[PREP_RC6] = Felt::from_u64(rc[6]);
                row_slice[PREP_RC7] = Felt::from_u64(rc[7]);
                row_slice[PREP_RC8] = Felt::from_u64(rc[8]);
                row_slice[PREP_RC9] = Felt::from_u64(rc[9]);
                row_slice[PREP_RC10] = Felt::from_u64(rc[10]);
                row_slice[PREP_RC11] = Felt::from_u64(rc[11]);
            } else if step <= POSEIDON2_EXTERNAL_ROUNDS + POSEIDON2_INTERNAL_ROUNDS {
                let idx = step - 1 - POSEIDON2_EXTERNAL_ROUNDS;
                row_slice[PREP_INTERNAL_ROUND] = Felt::ONE;
                row_slice[PREP_RC0] =
                    Felt::from_u64(poseidon2_constants::INTERNAL_ROUND_CONSTANTS[idx]);
            } else {
                let idx = step - 1 - POSEIDON2_EXTERNAL_ROUNDS - POSEIDON2_INTERNAL_ROUNDS;
                row_slice[PREP_EXTERNAL_ROUND] = Felt::ONE;
                let rc = &poseidon2_constants::EXTERNAL_ROUND_CONSTANTS[1][idx];
                row_slice[PREP_RC0] = Felt::from_u64(rc[0]);
                row_slice[PREP_RC1] = Felt::from_u64(rc[1]);
                row_slice[PREP_RC2] = Felt::from_u64(rc[2]);
                row_slice[PREP_RC3] = Felt::from_u64(rc[3]);
                row_slice[PREP_RC4] = Felt::from_u64(rc[4]);
                row_slice[PREP_RC5] = Felt::from_u64(rc[5]);
                row_slice[PREP_RC6] = Felt::from_u64(rc[6]);
                row_slice[PREP_RC7] = Felt::from_u64(rc[7]);
                row_slice[PREP_RC8] = Felt::from_u64(rc[8]);
                row_slice[PREP_RC9] = Felt::from_u64(rc[9]);
                row_slice[PREP_RC10] = Felt::from_u64(rc[10]);
                row_slice[PREP_RC11] = Felt::from_u64(rc[11]);
            }
        }

        if step == CYCLE_LENGTH - 1 {
            let next_cycle = cycle + 1;
            if next_cycle < TOTAL_TRACE_CYCLES {
                if let Some(domain_tag) = cycle_reset_domain(next_cycle) {
                    row_slice[PREP_RESET] = Felt::ONE;
                    row_slice[PREP_DOMAIN] = Felt::from_u64(domain_tag);
                }
                row_slice[PREP_MERKLE_LEFT] = Felt::from_bool(cycle_is_merkle_left(next_cycle));
                row_slice[PREP_MERKLE_RIGHT] = Felt::from_bool(cycle_is_merkle_right(next_cycle));
            }
            row_slice[PREP_CAPTURE] = Felt::from_bool(cycle_is_output(cycle));
        }

        row_slice[PREP_NOTE_START_IN0] = Felt::from_bool(row == note_start_row_input(0));
        row_slice[PREP_NOTE_START_IN1] = Felt::from_bool(row == note_start_row_input(1));
        row_slice[PREP_NOTE_START_OUT0] = Felt::from_bool(row == note_start_row_output(0));
        row_slice[PREP_NOTE_START_OUT1] = Felt::from_bool(row == note_start_row_output(1));

        row_slice[PREP_FINAL_ROW] = Felt::from_bool(row == MIN_TRACE_LENGTH - 2);
        row_slice[PREP_NF0_ROW] = Felt::from_bool(row == nullifier_output_row(0));
        row_slice[PREP_NF1_ROW] = Felt::from_bool(row == nullifier_output_row(1));
        row_slice[PREP_MR0_ROW] = Felt::from_bool(row == merkle_root_output_row(0));
        row_slice[PREP_MR1_ROW] = Felt::from_bool(row == merkle_root_output_row(1));
        row_slice[PREP_CM0_ROW] = Felt::from_bool(row == commitment_output_row(0));
        row_slice[PREP_CM1_ROW] = Felt::from_bool(row == commitment_output_row(1));
    }

    RowMajorMatrix::new(values, PREPROCESSED_WIDTH)
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
        let current = main.row_slice(0).expect("trace must have >= 1 row");
        let next = main.row_slice(1).expect("trace must have >= 2 rows");

        let is_first_row = builder.is_first_row();
        let one = AB::Expr::ONE;
        let two = AB::Expr::TWO;
        // Plonky3 row selectors are unnormalized; scale by N^{-1} for a 0/1 first-row mask.
        let trace_len_inv = Felt::from_u64(MIN_TRACE_LENGTH as u64).inverse();
        let first_row = is_first_row.clone()
            * AB::Expr::from_u64(trace_len_inv.as_canonical_u64());
        let not_first_row = one.clone() - first_row;
        let schedule_base = COL_SCHEDULE_START;

        let hash_flag: AB::Expr = current[schedule_base + PREP_HASH_FLAG].clone().into();
        let absorb_flag: AB::Expr = current[schedule_base + PREP_ABSORB_FLAG].clone().into();
        let init_round: AB::Expr = current[schedule_base + PREP_INIT_ROUND].clone().into();
        let external_round: AB::Expr = current[schedule_base + PREP_EXTERNAL_ROUND].clone().into();
        let internal_round: AB::Expr = current[schedule_base + PREP_INTERNAL_ROUND].clone().into();
        let rc0: AB::Expr = current[schedule_base + PREP_RC0].clone().into();
        let rc1: AB::Expr = current[schedule_base + PREP_RC1].clone().into();
        let rc2: AB::Expr = current[schedule_base + PREP_RC2].clone().into();
        let rc3: AB::Expr = current[schedule_base + PREP_RC3].clone().into();
        let rc4: AB::Expr = current[schedule_base + PREP_RC4].clone().into();
        let rc5: AB::Expr = current[schedule_base + PREP_RC5].clone().into();
        let rc6: AB::Expr = current[schedule_base + PREP_RC6].clone().into();
        let rc7: AB::Expr = current[schedule_base + PREP_RC7].clone().into();
        let rc8: AB::Expr = current[schedule_base + PREP_RC8].clone().into();
        let rc9: AB::Expr = current[schedule_base + PREP_RC9].clone().into();
        let rc10: AB::Expr = current[schedule_base + PREP_RC10].clone().into();
        let rc11: AB::Expr = current[schedule_base + PREP_RC11].clone().into();

        let prep_reset: AB::Expr = current[schedule_base + PREP_RESET].clone().into();
        let prep_domain: AB::Expr = current[schedule_base + PREP_DOMAIN].clone().into();
        let prep_merkle_left: AB::Expr =
            current[schedule_base + PREP_MERKLE_LEFT].clone().into();
        let prep_merkle_right: AB::Expr =
            current[schedule_base + PREP_MERKLE_RIGHT].clone().into();
        let prep_capture: AB::Expr = current[schedule_base + PREP_CAPTURE].clone().into();

        let prep_note_start_in0: AB::Expr =
            current[schedule_base + PREP_NOTE_START_IN0].clone().into();
        let prep_note_start_in1: AB::Expr =
            current[schedule_base + PREP_NOTE_START_IN1].clone().into();
        let prep_note_start_out0: AB::Expr =
            current[schedule_base + PREP_NOTE_START_OUT0].clone().into();
        let prep_note_start_out1: AB::Expr =
            current[schedule_base + PREP_NOTE_START_OUT1].clone().into();

        let final_row_mask: AB::Expr =
            current[schedule_base + PREP_FINAL_ROW].clone().into();
        let nf0_row: AB::Expr = current[schedule_base + PREP_NF0_ROW].clone().into();
        let nf1_row: AB::Expr = current[schedule_base + PREP_NF1_ROW].clone().into();
        let mr0_row: AB::Expr = current[schedule_base + PREP_MR0_ROW].clone().into();
        let mr1_row: AB::Expr = current[schedule_base + PREP_MR1_ROW].clone().into();
        let cm0_row: AB::Expr = current[schedule_base + PREP_CM0_ROW].clone().into();
        let cm1_row: AB::Expr = current[schedule_base + PREP_CM1_ROW].clone().into();

        let public_values = builder.public_values();
        let expected_len = TransactionPublicInputsP3::expected_len();
        debug_assert_eq!(public_values.len(), expected_len);
        let pv = |index: usize| -> AB::Expr { public_values[index].into() };

        let mut idx = 0usize;
        let input_flags: Vec<AB::Expr> = (0..MAX_INPUTS).map(|i| pv(idx + i)).collect();
        idx += MAX_INPUTS;
        let output_flags: Vec<AB::Expr> = (0..MAX_OUTPUTS).map(|i| pv(idx + i)).collect();
        idx += MAX_OUTPUTS;

        let mut nullifiers = Vec::with_capacity(MAX_INPUTS);
        for _ in 0..MAX_INPUTS {
            let limbs = vec![
                pv(idx),
                pv(idx + 1),
                pv(idx + 2),
                pv(idx + 3),
                pv(idx + 4),
                pv(idx + 5),
            ];
            idx += 6;
            nullifiers.push(limbs);
        }

        let mut commitments = Vec::with_capacity(MAX_OUTPUTS);
        for _ in 0..MAX_OUTPUTS {
            let limbs = vec![
                pv(idx),
                pv(idx + 1),
                pv(idx + 2),
                pv(idx + 3),
                pv(idx + 4),
                pv(idx + 5),
            ];
            idx += 6;
            commitments.push(limbs);
        }

        let fee = pv(idx);
        idx += 1;
        let value_balance_sign = pv(idx);
        idx += 1;
        let value_balance_magnitude = pv(idx);
        idx += 1;

        let merkle_root = vec![
            pv(idx),
            pv(idx + 1),
            pv(idx + 2),
            pv(idx + 3),
            pv(idx + 4),
            pv(idx + 5),
        ];
        idx += 6;

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

        let stablecoin_policy_hash = vec![
            pv(idx),
            pv(idx + 1),
            pv(idx + 2),
            pv(idx + 3),
            pv(idx + 4),
            pv(idx + 5),
        ];
        idx += 6;
        let stablecoin_oracle_commitment = vec![
            pv(idx),
            pv(idx + 1),
            pv(idx + 2),
            pv(idx + 3),
            pv(idx + 4),
            pv(idx + 5),
        ];
        idx += 6;
        let stablecoin_attestation_commitment = vec![
            pv(idx),
            pv(idx + 1),
            pv(idx + 2),
            pv(idx + 3),
            pv(idx + 4),
            pv(idx + 5),
        ];

        let sbox = |value: AB::Expr| -> AB::Expr {
            let v2 = value.clone() * value.clone();
            let v4 = v2.clone() * v2.clone();
            let v6 = v4.clone() * v2;
            v6 * value
        };

        let current_state = [
            current[COL_S0].clone().into(),
            current[COL_S1].clone().into(),
            current[COL_S2].clone().into(),
            current[COL_S3].clone().into(),
            current[COL_S4].clone().into(),
            current[COL_S5].clone().into(),
            current[COL_S6].clone().into(),
            current[COL_S7].clone().into(),
            current[COL_S8].clone().into(),
            current[COL_S9].clone().into(),
            current[COL_S10].clone().into(),
            current[COL_S11].clone().into(),
        ];

        let mds_light = |state: &mut [AB::Expr; POSEIDON2_WIDTH]| {
            for chunk in state.chunks_exact_mut(4) {
                let x0 = chunk[0].clone();
                let x1 = chunk[1].clone();
                let x2 = chunk[2].clone();
                let x3 = chunk[3].clone();

                let t01 = x0.clone() + x1.clone();
                let t23 = x2.clone() + x3.clone();
                let t0123 = t01.clone() + t23.clone();
                let t01123 = t0123.clone() + x1.clone();
                let t01233 = t0123 + x3.clone();

                chunk[3] = t01233.clone() + x0.clone() + x0;
                chunk[1] = t01123.clone() + x2.clone() + x2;
                chunk[0] = t01123 + t01;
                chunk[2] = t01233 + t23;
            }

            let mut sums: [AB::Expr; 4] = core::array::from_fn(|_| AB::Expr::ZERO);
            for k in 0..4 {
                let mut acc = AB::Expr::ZERO;
                let mut idx = k;
                while idx < POSEIDON2_WIDTH {
                    acc += state[idx].clone();
                    idx += 4;
                }
                sums[k] = acc;
            }

            for (idx, elem) in state.iter_mut().enumerate() {
                *elem = elem.clone() + sums[idx % 4].clone();
            }
        };

        let matmul_internal = |state: &mut [AB::Expr; POSEIDON2_WIDTH]| {
            let mut sum = AB::Expr::ZERO;
            for elem in state.iter() {
                sum += elem.clone();
            }
            for (idx, elem) in state.iter_mut().enumerate() {
                let diag = AB::Expr::from_u64(poseidon2_constants::INTERNAL_MATRIX_DIAG[idx]);
                *elem = elem.clone() * diag + sum.clone();
            }
        };

        let mut init_state = current_state.clone();
        mds_light(&mut init_state);

        let mut external_state = core::array::from_fn(|idx| {
            let rc = match idx {
                0 => rc0.clone(),
                1 => rc1.clone(),
                2 => rc2.clone(),
                3 => rc3.clone(),
                4 => rc4.clone(),
                5 => rc5.clone(),
                6 => rc6.clone(),
                7 => rc7.clone(),
                8 => rc8.clone(),
                9 => rc9.clone(),
                10 => rc10.clone(),
                _ => rc11.clone(),
            };
            sbox(current_state[idx].clone() + rc)
        });
        mds_light(&mut external_state);

        let mut internal_state = current_state.clone();
        internal_state[0] = sbox(current_state[0].clone() + rc0.clone());
        matmul_internal(&mut internal_state);

        let round_sum = init_round.clone() + external_round.clone() + internal_round.clone();
        let mut hash_state: [AB::Expr; POSEIDON2_WIDTH] =
            core::array::from_fn(|_| AB::Expr::ZERO);
        for idx in 0..POSEIDON2_WIDTH {
            hash_state[idx] = init_round.clone() * init_state[idx].clone()
                + external_round.clone() * external_state[idx].clone()
                + internal_round.clone() * internal_state[idx].clone();
        }

        let copy_flag = one.clone() - hash_flag.clone() - absorb_flag.clone();

        let reset: AB::Expr = current[COL_RESET].clone().into();
        let domain: AB::Expr = current[COL_DOMAIN].clone().into();
        let in0: AB::Expr = current[COL_IN0].clone().into();
        let in1: AB::Expr = current[COL_IN1].clone().into();
        let in2: AB::Expr = current[COL_IN2].clone().into();
        let in3: AB::Expr = current[COL_IN3].clone().into();
        let in4: AB::Expr = current[COL_IN4].clone().into();
        let in5: AB::Expr = current[COL_IN5].clone().into();

        let start_state = [
            domain.clone() + in0.clone(),
            in1.clone(),
            in2.clone(),
            in3.clone(),
            in4.clone(),
            in5.clone(),
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            one.clone(),
        ];

        let cont_state = [
            current_state[0].clone() + in0,
            current_state[1].clone() + in1,
            current_state[2].clone() + in2,
            current_state[3].clone() + in3,
            current_state[4].clone() + in4,
            current_state[5].clone() + in5,
            current_state[6].clone(),
            current_state[7].clone(),
            current_state[8].clone(),
            current_state[9].clone(),
            current_state[10].clone(),
            current_state[11].clone(),
        ];

        let absorb_state: [AB::Expr; POSEIDON2_WIDTH] = core::array::from_fn(|idx| {
            reset.clone() * start_state[idx].clone()
                + (one.clone() - reset.clone()) * cont_state[idx].clone()
        });

        let mut when = builder.when_transition();
        when.assert_zero(hash_flag.clone() - round_sum);
        for idx in 0..POSEIDON2_WIDTH {
            let expected = hash_flag.clone() * hash_state[idx].clone()
                + copy_flag.clone() * current_state[idx].clone()
                + absorb_flag.clone() * absorb_state[idx].clone();
            let next_col = match idx {
                0 => COL_S0,
                1 => COL_S1,
                2 => COL_S2,
                3 => COL_S3,
                4 => COL_S4,
                5 => COL_S5,
                6 => COL_S6,
                7 => COL_S7,
                8 => COL_S8,
                9 => COL_S9,
                10 => COL_S10,
                _ => COL_S11,
            };
            when.assert_zero(next[next_col].clone() - expected);
        }

        when.assert_zero(current[COL_RESET].clone() - prep_reset);
        when.assert_zero(current[COL_DOMAIN].clone() - prep_domain);
        when.assert_zero(current[COL_MERKLE_LEFT].clone() - prep_merkle_left);
        when.assert_zero(current[COL_MERKLE_RIGHT].clone() - prep_merkle_right);
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
            let sel = current[col].clone();
            when.assert_bool(sel);
        }

        let slot_assets = [
            current[COL_SLOT0_ASSET].clone(),
            current[COL_SLOT1_ASSET].clone(),
            current[COL_SLOT2_ASSET].clone(),
            current[COL_SLOT3_ASSET].clone(),
        ];
        let slot_in_cols = [COL_SLOT0_IN, COL_SLOT1_IN, COL_SLOT2_IN, COL_SLOT3_IN];
        let slot_out_cols = [COL_SLOT0_OUT, COL_SLOT1_OUT, COL_SLOT2_OUT, COL_SLOT3_OUT];

        let stablecoin_sel_sum = stablecoin_sel_cols
            .iter()
            .fold(AB::Expr::ZERO, |acc, col| acc + current[*col].clone());
        when.assert_zero(final_row_mask.clone() * (stablecoin_sel_sum - stablecoin_enabled.clone()));

        for slot in 0..4 {
            when.assert_zero(
                final_row_mask.clone()
                    * current[stablecoin_sel_cols[slot]].clone()
                    * (slot_assets[slot].clone() - stablecoin_asset.clone()),
            );
        }

        let stablecoin_signed = stablecoin_issuance_magnitude.clone()
            - (stablecoin_issuance_sign.clone()
                * stablecoin_issuance_magnitude.clone()
                * two.clone());
        let mut selected_delta = AB::Expr::ZERO;
        for slot in 0..4 {
            let delta = current[slot_in_cols[slot]].clone() - current[slot_out_cols[slot]].clone();
            selected_delta += current[stablecoin_sel_cols[slot]].clone() * delta;
        }
        when.assert_zero(final_row_mask.clone() * (selected_delta - stablecoin_signed));

        for slot in 1..4 {
            let delta = current[slot_in_cols[slot]].clone() - current[slot_out_cols[slot]].clone();
            when.assert_zero(
                final_row_mask.clone()
                    * delta
                    * (one.clone() - current[stablecoin_sel_cols[slot]].clone()),
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
            COL_STABLECOIN_POLICY_HASH4,
            COL_STABLECOIN_POLICY_HASH5,
            COL_STABLECOIN_ORACLE0,
            COL_STABLECOIN_ORACLE1,
            COL_STABLECOIN_ORACLE2,
            COL_STABLECOIN_ORACLE3,
            COL_STABLECOIN_ORACLE4,
            COL_STABLECOIN_ORACLE5,
            COL_STABLECOIN_ATTEST0,
            COL_STABLECOIN_ATTEST1,
            COL_STABLECOIN_ATTEST2,
            COL_STABLECOIN_ATTEST3,
            COL_STABLECOIN_ATTEST4,
            COL_STABLECOIN_ATTEST5,
        ];
        for &col in stablecoin_zero_cols.iter() {
            when.assert_zero(final_row_mask.clone() * stablecoin_disabled.clone() * current[col].clone());
        }

        let active_cols = [
            COL_IN_ACTIVE0,
            COL_IN_ACTIVE1,
            COL_OUT_ACTIVE0,
            COL_OUT_ACTIVE1,
        ];
        for &col in active_cols.iter() {
            when.assert_bool(current[col].clone());
        }

        for &sel_col in SELECTOR_COLUMNS.iter() {
            when.assert_bool(current[sel_col].clone());
        }

        let input_active = [current[COL_IN_ACTIVE0].clone(), current[COL_IN_ACTIVE1].clone()];
        let output_active = [current[COL_OUT_ACTIVE0].clone(), current[COL_OUT_ACTIVE1].clone()];
        let note_start_in0 = prep_note_start_in0.clone();
        let note_start_in1 = prep_note_start_in1.clone();
        let note_start_out0 = prep_note_start_out0.clone();
        let note_start_out1 = prep_note_start_out1.clone();

        let in0_sel_sum = current[COL_SEL_IN0_SLOT0].clone()
            + current[COL_SEL_IN0_SLOT1].clone()
            + current[COL_SEL_IN0_SLOT2].clone()
            + current[COL_SEL_IN0_SLOT3].clone();
        when.assert_zero(note_start_in0.clone() * (in0_sel_sum - input_active[0].clone()));

        let in1_sel_sum = current[COL_SEL_IN1_SLOT0].clone()
            + current[COL_SEL_IN1_SLOT1].clone()
            + current[COL_SEL_IN1_SLOT2].clone()
            + current[COL_SEL_IN1_SLOT3].clone();
        when.assert_zero(note_start_in1.clone() * (in1_sel_sum - input_active[1].clone()));

        let out0_sel_sum = current[COL_SEL_OUT0_SLOT0].clone()
            + current[COL_SEL_OUT0_SLOT1].clone()
            + current[COL_SEL_OUT0_SLOT2].clone()
            + current[COL_SEL_OUT0_SLOT3].clone();
        when.assert_zero(note_start_out0.clone() * (out0_sel_sum - output_active[0].clone()));

        let out1_sel_sum = current[COL_SEL_OUT1_SLOT0].clone()
            + current[COL_SEL_OUT1_SLOT1].clone()
            + current[COL_SEL_OUT1_SLOT2].clone()
            + current[COL_SEL_OUT1_SLOT3].clone();
        when.assert_zero(note_start_out1.clone() * (out1_sel_sum - output_active[1].clone()));

        let in0_asset = current[COL_IN0_ASSET].clone();
        let in0_selected = current[COL_SEL_IN0_SLOT0].clone() * slot_assets[0].clone()
            + current[COL_SEL_IN0_SLOT1].clone() * slot_assets[1].clone()
            + current[COL_SEL_IN0_SLOT2].clone() * slot_assets[2].clone()
            + current[COL_SEL_IN0_SLOT3].clone() * slot_assets[3].clone();
        when.assert_zero(
            note_start_in0.clone() * (in0_asset * input_active[0].clone() - in0_selected),
        );

        let in1_asset = current[COL_IN1_ASSET].clone();
        let in1_selected = current[COL_SEL_IN1_SLOT0].clone() * slot_assets[0].clone()
            + current[COL_SEL_IN1_SLOT1].clone() * slot_assets[1].clone()
            + current[COL_SEL_IN1_SLOT2].clone() * slot_assets[2].clone()
            + current[COL_SEL_IN1_SLOT3].clone() * slot_assets[3].clone();
        when.assert_zero(
            note_start_in1.clone() * (in1_asset * input_active[1].clone() - in1_selected),
        );

        let out0_asset = current[COL_OUT0_ASSET].clone();
        let out0_selected = current[COL_SEL_OUT0_SLOT0].clone() * slot_assets[0].clone()
            + current[COL_SEL_OUT0_SLOT1].clone() * slot_assets[1].clone()
            + current[COL_SEL_OUT0_SLOT2].clone() * slot_assets[2].clone()
            + current[COL_SEL_OUT0_SLOT3].clone() * slot_assets[3].clone();
        when.assert_zero(
            note_start_out0.clone() * (out0_asset * output_active[0].clone() - out0_selected),
        );

        let out1_asset = current[COL_OUT1_ASSET].clone();
        let out1_selected = current[COL_SEL_OUT1_SLOT0].clone() * slot_assets[0].clone()
            + current[COL_SEL_OUT1_SLOT1].clone() * slot_assets[1].clone()
            + current[COL_SEL_OUT1_SLOT2].clone() * slot_assets[2].clone()
            + current[COL_SEL_OUT1_SLOT3].clone() * slot_assets[3].clone();
        when.assert_zero(
            note_start_out1.clone() * (out1_asset * output_active[1].clone() - out1_selected),
        );

        let in_values = [current[COL_IN0_VALUE].clone(), current[COL_IN1_VALUE].clone()];
        let out_values = [current[COL_OUT0_VALUE].clone(), current[COL_OUT1_VALUE].clone()];

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
        let note_in_flags = [note_start_in0.clone(), note_start_in1.clone()];
        let note_out_flags = [note_start_out0.clone(), note_start_out1.clone()];

        for slot in 0..4 {
            let mut add_in = AB::Expr::ZERO;
            let mut add_out = AB::Expr::ZERO;
            for note in 0..2 {
                add_in += note_in_flags[note].clone()
                    * current[sel_in[note][slot]].clone()
                    * in_values[note].clone();
                add_out += note_out_flags[note].clone()
                    * current[sel_out[note][slot]].clone()
                    * out_values[note].clone();
            }
            when.assert_zero(
                not_first_row.clone()
                    * (next[slot_in_cols[slot]].clone()
                        - (current[slot_in_cols[slot]].clone() + add_in)),
            );
            when.assert_zero(
                not_first_row.clone()
                    * (next[slot_out_cols[slot]].clone()
                        - (current[slot_out_cols[slot]].clone() + add_out)),
            );
        }

        let note_start_any = note_start_in0 + note_start_in1 + note_start_out0 + note_start_out1;
        when.assert_zero(
            note_start_any * (current[COL_SLOT0_ASSET].clone()
                - AB::Expr::from_u64(NATIVE_ASSET_ID)),
        );

        let vb_signed = value_balance_magnitude.clone()
            - (value_balance_sign.clone() * value_balance_magnitude.clone() * two.clone());
        let slot0_in = current[COL_SLOT0_IN].clone();
        let slot0_out = current[COL_SLOT0_OUT].clone();
        when.assert_zero(final_row_mask.clone() * (slot0_in + vb_signed - slot0_out - fee.clone()));

        for slot in 1..4 {
            let delta = current[slot_in_cols[slot]].clone() - current[slot_out_cols[slot]].clone();
            when.assert_zero(final_row_mask.clone() * stablecoin_disabled.clone() * delta);
        }

        let dir = current[COL_DIR].clone();
        when.assert_bool(dir);
        when.assert_zero((one.clone() - reset) * (next[COL_DIR].clone() - current[COL_DIR].clone()));

        let merkle_left = current[COL_MERKLE_LEFT].clone();
        let merkle_right = current[COL_MERKLE_RIGHT].clone();
        let next_dir = next[COL_DIR].clone();
        let not_next_dir = one.clone() - next_dir.clone();

        let merkle_inputs = [
            (COL_IN0, COL_OUT0),
            (COL_IN1, COL_OUT1),
            (COL_IN2, COL_OUT2),
            (COL_IN3, COL_OUT3),
            (COL_IN4, COL_OUT4),
            (COL_IN5, COL_OUT5),
        ];
        for (in_col, out_col) in merkle_inputs {
            when.assert_zero(
                absorb_flag.clone()
                    * merkle_left.clone()
                    * not_next_dir.clone()
                    * (current[in_col].clone() - next[out_col].clone()),
            );
            when.assert_zero(
                absorb_flag.clone()
                    * merkle_right.clone()
                    * next_dir.clone()
                    * (current[in_col].clone() - next[out_col].clone()),
            );
        }

        let capture = prep_capture.clone();
        when.assert_bool(capture.clone());
        when.assert_zero(capture.clone() * (one.clone() - absorb_flag.clone()));
        let out_cols = [
            (COL_OUT0, COL_S0),
            (COL_OUT1, COL_S1),
            (COL_OUT2, COL_S2),
            (COL_OUT3, COL_S3),
            (COL_OUT4, COL_S4),
            (COL_OUT5, COL_S5),
        ];
        for (out_col, state_col) in out_cols {
            when.assert_zero(
                next[out_col].clone()
                    - (capture.clone() * current[state_col].clone()
                        + (one.clone() - capture.clone()) * current[out_col].clone()),
            );
        }

        let note_flags = [
            (prep_note_start_in0.clone(), COL_IN0_VALUE, COL_IN0_ASSET),
            (prep_note_start_in1.clone(), COL_IN1_VALUE, COL_IN1_ASSET),
            (prep_note_start_out0.clone(), COL_OUT0_VALUE, COL_OUT0_ASSET),
            (prep_note_start_out1.clone(), COL_OUT1_VALUE, COL_OUT1_ASSET),
        ];

        for (flag, value_col, asset_col) in note_flags {
            when.assert_zero(flag.clone() * (current[COL_IN0].clone() - current[value_col].clone()));
            when.assert_zero(flag * (current[COL_IN1].clone() - current[asset_col].clone()));
        }

        let state_output_cols = [COL_S0, COL_S1, COL_S2, COL_S3, COL_S4, COL_S5];

        let nf0_gate = nf0_row * input_flags[0].clone();
        for (idx, col) in state_output_cols.iter().enumerate() {
            when.assert_zero(nf0_gate.clone() * (current[*col].clone() - nullifiers[0][idx].clone()));
        }

        let nf1_gate = nf1_row * input_flags[1].clone();
        for (idx, col) in state_output_cols.iter().enumerate() {
            when.assert_zero(nf1_gate.clone() * (current[*col].clone() - nullifiers[1][idx].clone()));
        }

        let mr0_gate = mr0_row * input_flags[0].clone();
        for (idx, col) in state_output_cols.iter().enumerate() {
            when.assert_zero(mr0_gate.clone() * (current[*col].clone() - merkle_root[idx].clone()));
        }

        let mr1_gate = mr1_row * input_flags[1].clone();
        for (idx, col) in state_output_cols.iter().enumerate() {
            when.assert_zero(mr1_gate.clone() * (current[*col].clone() - merkle_root[idx].clone()));
        }

        let cm0_gate = cm0_row * output_flags[0].clone();
        for (idx, col) in state_output_cols.iter().enumerate() {
            when.assert_zero(cm0_gate.clone() * (current[*col].clone() - commitments[0][idx].clone()));
        }

        let cm1_gate = cm1_row * output_flags[1].clone();
        for (idx, col) in state_output_cols.iter().enumerate() {
            when.assert_zero(cm1_gate.clone() * (current[*col].clone() - commitments[1][idx].clone()));
        }

        when.assert_zero(
            prep_note_start_in0.clone()
                * (current[COL_IN_ACTIVE0].clone() - input_flags[0].clone()),
        );
        when.assert_zero(
            prep_note_start_in1.clone()
                * (current[COL_IN_ACTIVE1].clone() - input_flags[1].clone()),
        );
        when.assert_zero(
            prep_note_start_out0.clone()
                * (current[COL_OUT_ACTIVE0].clone() - output_flags[0].clone()),
        );
        when.assert_zero(
            prep_note_start_out1.clone()
                * (current[COL_OUT_ACTIVE1].clone() - output_flags[1].clone()),
        );

        when.assert_zero(final_row_mask.clone() * (current[COL_FEE].clone() - fee));
        when.assert_zero(final_row_mask.clone() * (current[COL_VALUE_BALANCE_SIGN].clone() - value_balance_sign));
        when.assert_zero(
            final_row_mask.clone() * (current[COL_VALUE_BALANCE_MAG].clone() - value_balance_magnitude),
        );
        when.assert_zero(final_row_mask.clone() * (current[COL_STABLECOIN_ENABLED].clone() - stablecoin_enabled));
        when.assert_zero(final_row_mask.clone() * (current[COL_STABLECOIN_ASSET].clone() - stablecoin_asset));
        when.assert_zero(
            final_row_mask.clone() * (current[COL_STABLECOIN_POLICY_VERSION].clone() - stablecoin_policy_version),
        );
        when.assert_zero(
            final_row_mask.clone() * (current[COL_STABLECOIN_ISSUANCE_SIGN].clone() - stablecoin_issuance_sign),
        );
        when.assert_zero(
            final_row_mask.clone() * (current[COL_STABLECOIN_ISSUANCE_MAG].clone() - stablecoin_issuance_magnitude),
        );

        for (col, value) in [
            (COL_STABLECOIN_POLICY_HASH0, stablecoin_policy_hash[0].clone()),
            (COL_STABLECOIN_POLICY_HASH1, stablecoin_policy_hash[1].clone()),
            (COL_STABLECOIN_POLICY_HASH2, stablecoin_policy_hash[2].clone()),
            (COL_STABLECOIN_POLICY_HASH3, stablecoin_policy_hash[3].clone()),
            (COL_STABLECOIN_POLICY_HASH4, stablecoin_policy_hash[4].clone()),
            (COL_STABLECOIN_POLICY_HASH5, stablecoin_policy_hash[5].clone()),
            (COL_STABLECOIN_ORACLE0, stablecoin_oracle_commitment[0].clone()),
            (COL_STABLECOIN_ORACLE1, stablecoin_oracle_commitment[1].clone()),
            (COL_STABLECOIN_ORACLE2, stablecoin_oracle_commitment[2].clone()),
            (COL_STABLECOIN_ORACLE3, stablecoin_oracle_commitment[3].clone()),
            (COL_STABLECOIN_ORACLE4, stablecoin_oracle_commitment[4].clone()),
            (COL_STABLECOIN_ORACLE5, stablecoin_oracle_commitment[5].clone()),
            (COL_STABLECOIN_ATTEST0, stablecoin_attestation_commitment[0].clone()),
            (COL_STABLECOIN_ATTEST1, stablecoin_attestation_commitment[1].clone()),
            (COL_STABLECOIN_ATTEST2, stablecoin_attestation_commitment[2].clone()),
            (COL_STABLECOIN_ATTEST3, stablecoin_attestation_commitment[3].clone()),
            (COL_STABLECOIN_ATTEST4, stablecoin_attestation_commitment[4].clone()),
            (COL_STABLECOIN_ATTEST5, stablecoin_attestation_commitment[5].clone()),
        ] {
            when.assert_zero(final_row_mask.clone() * (current[col].clone() - value));
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
// LEGACY POSEIDON HELPERS (width 3, used by non-transaction circuits)
// ================================================================================================

#[inline]
pub fn sbox(x: Felt) -> Felt {
    x.exp_u64(5)
}

pub fn mds_mix(state: &[Felt; 3]) -> [Felt; 3] {
    let mut out = [Felt::ZERO; 3];
    for (row_idx, out_slot) in out.iter_mut().enumerate() {
        let mut acc = Felt::ZERO;
        for (col_idx, value) in state.iter().enumerate() {
            let coeff = Felt::from_u64(poseidon_constants::MDS_MATRIX[row_idx][col_idx]);
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
    let mut state = [Felt::from_u64(domain_tag), Felt::ZERO, Felt::ONE];
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

#[cfg(all(test, feature = "plonky3"))]
mod tests {
    use super::{Felt, TransactionAirP3, TransactionPublicInputsP3};
    use p3_uni_stark::get_log_num_quotient_chunks;

    #[test]
    fn log_quotient_degree_transaction_air_p3() {
        let num_public_values = TransactionPublicInputsP3::default().to_vec().len();
        let log_chunks = get_log_num_quotient_chunks::<Felt, _>(
            &TransactionAirP3,
            0,
            num_public_values,
            0,
        );
        println!("TransactionAirP3 log_num_quotient_chunks={}", log_chunks);
    }
}
