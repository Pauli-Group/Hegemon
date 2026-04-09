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
const PUBLIC_ROWS: usize = 2;
const PUBLIC_VALUE_COUNT: usize = 78;
const SECRET_ROWS: usize = 264;
const PACKING_FACTOR: usize = 64;
const INPUT_PERMUTATIONS: usize = 3 + MERKLE_DEPTH * 2 + 1;
const OUTPUT_PERMUTATIONS: usize = 3;
const POSEIDON_PERMUTATION_COUNT: usize =
    1 + MAX_INPUTS * INPUT_PERMUTATIONS + MAX_OUTPUTS * OUTPUT_PERMUTATIONS;
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
const DIRECT_RAW_WITNESS_LEN: usize = 3_991;
const DIRECT_EXPANDED_WITNESS_LEN: usize = 59_749;
const DIRECT_ROW_COUNT: usize = 934;

#[derive(Clone)]
pub(crate) struct PackedStatement<'a> {
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
    if row_count == DIRECT_ROW_COUNT {
        return test_direct_packed_frontend_witness(
            witness_values,
            linear_constraint_offsets,
            linear_constraint_indices,
            linear_constraint_coefficients,
            linear_constraint_targets,
        );
    }
    let statement = PackedStatement::new(
        row_count,
        packing_factor,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    );
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

fn test_direct_packed_frontend_witness(
    witness_values: &[u64],
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
) -> Result<(), TransactionCircuitError> {
    verify_linear_constraints(
        witness_values,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    )?;
    if linear_constraint_targets.len() != PUBLIC_VALUE_COUNT {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood packed frontend expected {PUBLIC_VALUE_COUNT} public values, got {}",
            linear_constraint_targets.len()
        )));
    }

    let expanded = &witness_values[..DIRECT_EXPANDED_WITNESS_LEN];
    if witness_values[DIRECT_EXPANDED_WITNESS_LEN..]
        .iter()
        .any(|value| *value != 0)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood packed frontend padding must be zero",
        ));
    }

    let public_values = &expanded[..PUBLIC_VALUE_COUNT];
    if public_values != linear_constraint_targets {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood packed frontend public prefix mismatch",
        ));
    }

    let raw_start = PUBLIC_VALUE_COUNT;
    let raw_end = raw_start + DIRECT_RAW_WITNESS_LEN;
    let raw_witness = &expanded[raw_start..raw_end];
    let poseidon_flat = &expanded[raw_end..DIRECT_EXPANDED_WITNESS_LEN];

    let witness = parse_direct_raw_witness(raw_witness)?;
    witness.validate()?;
    let public_inputs = witness.public_inputs()?;
    let serialized_inputs = serialize_smallwood_stark_inputs(&witness, &public_inputs)?;
    let p3_inputs = transaction_public_inputs_p3_from_parts(&public_inputs, &serialized_inputs)?;
    let expected_public_values = packed_public_values_from_p3(&p3_inputs, witness.version);
    if public_values != expected_public_values.as_slice() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood packed frontend public values do not match parsed witness",
        ));
    }

    let expected_poseidon = flatten_poseidon_rows(&packed_poseidon_subtrace_rows_from_witness(
        &witness,
        &public_inputs,
    )?);
    if poseidon_flat != expected_poseidon.as_slice() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood packed frontend poseidon subtrace mismatch",
        ));
    }

    Ok(())
}

impl<'a> PackedStatement<'a> {
    pub(crate) fn new(
        _row_count: usize,
        _packing_factor: usize,
        _linear_constraint_offsets: &'a [u32],
        _linear_constraint_indices: &'a [u32],
        _linear_constraint_coefficients: &'a [u64],
        linear_constraint_targets: &'a [u64],
    ) -> Self {
        let mut statement = Self {
            linear_constraint_targets,
            output_ciphertext_challenges: [Felt::ZERO; MAX_OUTPUTS],
            slot_denominator_inverses: derive_slot_denominator_inverses(linear_constraint_targets),
            stable_selector_bits: derive_stable_selector_bits(linear_constraint_targets),
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

    pub(crate) fn linear_targets(&self) -> &[u64] {
        self.linear_constraint_targets
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

fn parse_direct_raw_witness(
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
    input.extend_from_slice(&statement.linear_constraint_targets[..PUBLIC_VALUE_COUNT]);
    let mut output = [0u64; 1];
    xof_words(&input, &mut output);
    if output[0] <= 1 {
        output[0] += 2;
    }
    Felt::from_u64(output[0])
}

fn public_value(statement: &PackedStatement<'_>, row: usize) -> Felt {
    Felt::from_u64(statement.linear_constraint_targets[row])
}

#[inline]
fn row_input_base(input: usize) -> usize {
    PUBLIC_ROWS + input * INPUT_ROWS
}

#[inline]
fn row_output_base(output: usize) -> usize {
    PUBLIC_ROWS + MAX_INPUTS * INPUT_ROWS + output * OUTPUT_ROWS
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
fn row_input_direction(input: usize, bit: usize) -> usize {
    row_input_base(input) + 2 + bit
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

pub(crate) fn packed_constraint_count() -> usize {
    constraint_count()
}

pub(crate) fn compute_constraints_u64(
    statement: &PackedStatement<'_>,
    rows: &[u64],
    out: &mut [u64],
) -> Result<(), TransactionCircuitError> {
    let expected = constraint_count();
    if out.len() != expected {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood constraint buffer has length {}, expected {expected}",
            out.len()
        )));
    }
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
            let asset = rows[row_input_asset(input)];
            let weight = slot_membership_weights(statement, asset)[slot];
            delta += flag * rows[row_input_value(input)] * weight;
        }
        for output_idx in 0..MAX_OUTPUTS {
            let flag = public_value(statement, PUB_OUTPUT_FLAG0 + output_idx);
            let asset = rows[row_output_asset(output_idx)];
            let weight = slot_membership_weights(statement, asset)[slot];
            delta -= flag * rows[row_output_value(output_idx)] * weight;
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
