use std::{env, fmt::Write};

use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, spend_auth_key_bytes, Felt};
use transaction_circuit::note::{MerklePath, NoteData};
use transaction_circuit::{
    smallwood_production_constraint_map_for_public_values_unchecked_for_generation as smallwood_production_constraint_map_for_public_values,
    smallwood_production_constraint_map_unchecked_for_generation as smallwood_production_constraint_map,
    smallwood_production_runtime_contract_digests_for_generation, InputNoteWitness,
    OutputNoteWitness, SmallwoodConstraintExpression, SmallwoodProductionConstraintMap,
    StablecoinPolicyBinding, TransactionWitness,
};

const PUBLIC_VALUE_COUNT: usize = 78;
const CIRCUIT_VERSION_INDEX: usize = 76;
const CRYPTO_SUITE_INDEX: usize = 77;
const FIELD_MODULUS: u64 = transaction_circuit::constants::FIELD_MODULUS_U64;
const DEPLOYED_PACKING_FACTOR: usize = 64;
const DEPLOYED_ROW_COUNT: usize = 1531;
const DEPLOYED_INPUT_ROWS: usize = 34;
const DEPLOYED_OUTPUT_ROWS: usize = 12;
const DEPLOYED_RANGE_BASE_ROW: usize = 92;
const DEPLOYED_POSEIDON_BASE_ROW: usize = 415;
const DEPLOYED_POSEIDON_ROWS_PER_PERMUTATION: usize = 31;
const DEPLOYED_POSEIDON_WIDTH: usize = 12;
const DEPLOYED_RANGE_LIMB_COUNT: usize = 21;
const DEPLOYED_RANGE_LIMB_BITS: usize = 3;

#[derive(Clone, Copy, Debug)]
struct TargetBinding {
    target_index: usize,
    public_value_index: usize,
    additive_constant: u64,
}

#[derive(Clone, Debug)]
struct LinearConstraintPatch {
    constraint_start: usize,
    removed_constraint_count: usize,
    removed_term_count: usize,
    replacement_term_offsets: Vec<u32>,
    replacement_term_indices: Vec<u32>,
    replacement_term_coefficients: Vec<u64>,
    replacement_targets: Vec<u64>,
}

#[derive(Clone, Copy, Debug)]
struct TargetOverride {
    target_index: usize,
    value: u64,
}

struct ConstraintMapTemplate {
    name: String,
    input_flags: [u64; 2],
    output_flags: [u64; 2],
    linear_constraint_patches: Vec<LinearConstraintPatch>,
    target_overrides: Vec<TargetOverride>,
    target_bindings: Vec<TargetBinding>,
}

fn build_merkle_path(
    leaves: &[transaction_circuit::hashing_pq::HashFelt],
    index: usize,
) -> (MerklePath, [Felt; 6]) {
    let sibling = leaves.get(index ^ 1).copied().unwrap_or([Felt::ZERO; 6]);
    let mut siblings = vec![sibling];
    let left = leaves.first().copied().unwrap_or([Felt::ZERO; 6]);
    let right = leaves.get(1).copied().unwrap_or([Felt::ZERO; 6]);
    let mut root = merkle_node(left, right);
    for _ in 1..transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH {
        let zero = [Felt::ZERO; 6];
        siblings.push(zero);
        root = merkle_node(root, zero);
    }
    (MerklePath { siblings }, root)
}

fn active_witness() -> TransactionWitness {
    let sk_spend = [42u8; 32];
    let pk_auth = spend_auth_key_bytes(&sk_spend);
    let input_native = NoteData {
        value: 8,
        asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
        pk_recipient: [2u8; 32],
        pk_auth,
        rho: [3u8; 32],
        r: [4u8; 32],
    };
    let input_asset = NoteData {
        value: 5,
        asset_id: 1,
        pk_recipient: [5u8; 32],
        pk_auth,
        rho: [6u8; 32],
        r: [7u8; 32],
    };
    let leaves = [input_native.commitment(), input_asset.commitment()];
    let (path0, root) = build_merkle_path(&leaves, 0);
    let (path1, _) = build_merkle_path(&leaves, 1);
    TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_native,
                position: 0,
                rho_seed: [9u8; 32],
                merkle_path: path0,
            },
            InputNoteWitness {
                note: input_asset,
                position: 1,
                rho_seed: [8u8; 32],
                merkle_path: path1,
            },
        ],
        outputs: vec![
            OutputNoteWitness {
                note: NoteData {
                    value: 3,
                    asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
                    pk_recipient: [11u8; 32],
                    pk_auth: [111u8; 32],
                    rho: [12u8; 32],
                    r: [13u8; 32],
                },
            },
            OutputNoteWitness {
                note: NoteData {
                    value: 5,
                    asset_id: 1,
                    pk_recipient: [21u8; 32],
                    pk_auth: [121u8; 32],
                    rho: [22u8; 32],
                    r: [23u8; 32],
                },
            },
        ],
        ciphertext_hashes: vec![[0u8; 48]; 2],
        sk_spend,
        merkle_root: felts_to_bytes48(&root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    }
}

fn stablecoin_witness() -> TransactionWitness {
    let sk_spend = [8u8; 32];
    let pk_auth = spend_auth_key_bytes(&sk_spend);
    let input_native = NoteData {
        value: 5,
        asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
        pk_recipient: [1u8; 32],
        pk_auth,
        rho: [2u8; 32],
        r: [3u8; 32],
    };
    let leaves = [input_native.commitment(), [Felt::ZERO; 6]];
    let (path, root) = build_merkle_path(&leaves, 0);
    TransactionWitness {
        inputs: vec![InputNoteWitness {
            note: input_native,
            position: 0,
            rho_seed: [7u8; 32],
            merkle_path: path,
        }],
        outputs: vec![OutputNoteWitness {
            note: NoteData {
                value: 5,
                asset_id: 4242,
                pk_recipient: [4u8; 32],
                pk_auth: [104u8; 32],
                rho: [5u8; 32],
                r: [6u8; 32],
            },
        }],
        ciphertext_hashes: vec![[9u8; 48]],
        sk_spend,
        merkle_root: felts_to_bytes48(&root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding {
            enabled: true,
            asset_id: 4242,
            policy_hash: [10u8; 48],
            oracle_commitment: [11u8; 48],
            attestation_commitment: [12u8; 48],
            issuance_delta: -5,
            policy_version: 1,
        },
        version: TransactionWitness::default_version_binding(),
    }
}

fn public_values_for_mask(mask: u8, probe: u8) -> Vec<u64> {
    let mut values = vec![0u64; PUBLIC_VALUE_COUNT];
    for (index, value) in values.iter_mut().enumerate().take(4) {
        *value = u64::from((mask >> index) & 1);
    }
    for (index, value) in values
        .iter_mut()
        .enumerate()
        .take(CIRCUIT_VERSION_INDEX)
        .skip(4)
    {
        *value = match probe {
            0 => 0,
            1 => index as u64 + 1,
            2 => 1_000 + index as u64 * 97,
            3 => 50_000 + index as u64 * 193,
            _ => unreachable!("unsupported target-binding probe"),
        };
    }
    let balance_slots = match probe {
        0 => [
            0,
            u64::MAX % FIELD_MODULUS,
            u64::MAX % FIELD_MODULUS,
            u64::MAX % FIELD_MODULUS,
        ],
        1 => [0, 50, 100, 150],
        2 => [0, 1_000, 2_000, 3_000],
        3 => [0, 50_000, 60_000, 70_000],
        _ => unreachable!("unsupported target-binding probe"),
    };
    values[49..53].copy_from_slice(&balance_slots);
    values[CIRCUIT_VERSION_INDEX] = 3;
    values[CRYPTO_SUITE_INDEX] = 2;
    values
}

fn field_sub(left: u64, right: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        FIELD_MODULUS - (right - left)
    }
}

fn assert_same_structure(
    left: &SmallwoodProductionConstraintMap,
    right: &SmallwoodProductionConstraintMap,
) -> Result<(), Box<dyn std::error::Error>> {
    let same = left.arithmetization == right.arithmetization
        && left.public_field_ranges == right.public_field_ranges
        && left.public_value_count == right.public_value_count
        && left.raw_witness_len == right.raw_witness_len
        && left.lppc_row_count == right.lppc_row_count
        && left.lppc_packing_factor == right.lppc_packing_factor
        && left.effective_constraint_degree == right.effective_constraint_degree
        && left.linear_constraint_count == right.linear_constraint_count
        && left.linear_term_count == right.linear_term_count
        && left.auxiliary_witness_limb_count == right.auxiliary_witness_limb_count
        && left.linear_term_offsets == right.linear_term_offsets
        && left.linear_term_indices == right.linear_term_indices
        && left.linear_term_coefficients == right.linear_term_coefficients
        && left.nonlinear_constraint_count == right.nonlinear_constraint_count
        && left.nonlinear_expression_count == right.nonlinear_expression_count
        && left.nonlinear_expressions == right.nonlinear_expressions
        && left.nonlinear_constraint_roots == right.nonlinear_constraint_roots
        && left.nonlinear_program_digest == right.nonlinear_program_digest;
    if same {
        Ok(())
    } else {
        Err("production map structure unexpectedly depends on non-flag public values".into())
    }
}

fn instantiate_targets(
    base_targets: &[u64],
    bindings: &[TargetBinding],
    public_values: &[u64],
) -> Vec<u64> {
    let mut targets = base_targets.to_vec();
    for binding in bindings {
        targets[binding.target_index] = (u128::from(public_values[binding.public_value_index])
            + u128::from(binding.additive_constant))
        .rem_euclid(u128::from(FIELD_MODULUS)) as u64;
    }
    targets
}

fn linear_constraint_terms_equal(
    left: &SmallwoodProductionConstraintMap,
    left_index: usize,
    right: &SmallwoodProductionConstraintMap,
    right_index: usize,
) -> bool {
    let left_start = left.linear_term_offsets[left_index] as usize;
    let left_stop = left.linear_term_offsets[left_index + 1] as usize;
    let right_start = right.linear_term_offsets[right_index] as usize;
    let right_stop = right.linear_term_offsets[right_index + 1] as usize;
    left.linear_term_indices[left_start..left_stop]
        == right.linear_term_indices[right_start..right_stop]
        && left.linear_term_coefficients[left_start..left_stop]
            == right.linear_term_coefficients[right_start..right_stop]
}

fn derive_linear_constraint_patch(
    current: &SmallwoodProductionConstraintMap,
    target: &SmallwoodProductionConstraintMap,
) -> Option<LinearConstraintPatch> {
    let current_count = current.linear_targets.len();
    let target_count = target.linear_targets.len();
    let mut prefix = 0usize;
    while prefix < current_count
        && prefix < target_count
        && linear_constraint_terms_equal(current, prefix, target, prefix)
    {
        prefix += 1;
    }

    let mut suffix = 0usize;
    while suffix < current_count - prefix
        && suffix < target_count - prefix
        && linear_constraint_terms_equal(
            current,
            current_count - suffix - 1,
            target,
            target_count - suffix - 1,
        )
    {
        suffix += 1;
    }

    if prefix == current_count && prefix == target_count {
        return None;
    }

    let current_stop = current_count - suffix;
    let target_stop = target_count - suffix;
    let old_term_start = current.linear_term_offsets[prefix] as usize;
    let old_term_stop = current.linear_term_offsets[current_stop] as usize;
    let new_term_start = target.linear_term_offsets[prefix] as usize;
    let new_term_stop = target.linear_term_offsets[target_stop] as usize;
    let replacement_term_offsets = target.linear_term_offsets[prefix..=target_stop]
        .iter()
        .map(|offset| offset - target.linear_term_offsets[prefix])
        .collect();

    Some(LinearConstraintPatch {
        constraint_start: prefix,
        removed_constraint_count: current_stop - prefix,
        removed_term_count: old_term_stop - old_term_start,
        replacement_term_offsets,
        replacement_term_indices: target.linear_term_indices[new_term_start..new_term_stop]
            .to_vec(),
        replacement_term_coefficients: target.linear_term_coefficients
            [new_term_start..new_term_stop]
            .to_vec(),
        replacement_targets: target.linear_targets[prefix..target_stop].to_vec(),
    })
}

fn apply_linear_constraint_patch(
    map: &mut SmallwoodProductionConstraintMap,
    patch: &LinearConstraintPatch,
) -> Result<(), Box<dyn std::error::Error>> {
    let constraint_stop = patch.constraint_start + patch.removed_constraint_count;
    let old_term_start = map.linear_term_offsets[patch.constraint_start] as usize;
    let old_term_stop = map.linear_term_offsets[constraint_stop] as usize;
    if old_term_stop - old_term_start != patch.removed_term_count
        || patch.replacement_term_offsets.first() != Some(&0)
        || patch
            .replacement_term_offsets
            .last()
            .copied()
            .unwrap_or_default() as usize
            != patch.replacement_term_indices.len()
        || patch.replacement_term_indices.len() != patch.replacement_term_coefficients.len()
        || patch.replacement_term_offsets.len() != patch.replacement_targets.len() + 1
    {
        return Err("invalid generated linear constraint patch".into());
    }

    let replacement_term_count = patch.replacement_term_indices.len();
    let mut offsets = map.linear_term_offsets[..=patch.constraint_start].to_vec();
    offsets.extend(
        patch
            .replacement_term_offsets
            .iter()
            .skip(1)
            .map(|offset| u32::try_from(old_term_start + *offset as usize))
            .collect::<Result<Vec<_>, _>>()?,
    );
    offsets.extend(
        map.linear_term_offsets
            .iter()
            .skip(constraint_stop + 1)
            .map(|offset| {
                u32::try_from(
                    old_term_start + replacement_term_count + (*offset as usize - old_term_stop),
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
    );

    map.linear_term_offsets = offsets;
    map.linear_term_indices.splice(
        old_term_start..old_term_stop,
        patch.replacement_term_indices.iter().copied(),
    );
    map.linear_term_coefficients.splice(
        old_term_start..old_term_stop,
        patch.replacement_term_coefficients.iter().copied(),
    );
    map.linear_targets.splice(
        patch.constraint_start..constraint_stop,
        patch.replacement_targets.iter().copied(),
    );
    map.linear_constraint_count = map.linear_targets.len();
    map.linear_term_count = map.linear_term_indices.len();
    Ok(())
}

fn derive_template_patches(
    mask: u8,
    baseline_maps: &[SmallwoodProductionConstraintMap],
) -> Result<
    (Vec<LinearConstraintPatch>, SmallwoodProductionConstraintMap),
    Box<dyn std::error::Error>,
> {
    let mut current_mask = 0u8;
    let mut current = baseline_maps[0].clone();
    let mut patches = Vec::new();
    for bit in 0..4 {
        if mask & (1 << bit) == 0 {
            continue;
        }
        let target_mask = current_mask | (1 << bit);
        let target = &baseline_maps[usize::from(target_mask)];
        if let Some(patch) = derive_linear_constraint_patch(&current, target) {
            apply_linear_constraint_patch(&mut current, &patch)?;
            patches.push(patch);
        }
        current_mask = target_mask;
    }
    Ok((patches, current))
}

fn instantiate_template_map(
    base_map: &SmallwoodProductionConstraintMap,
    template: &ConstraintMapTemplate,
    public_values: &[u64],
    exact_table_digest: [u8; 32],
) -> Result<SmallwoodProductionConstraintMap, Box<dyn std::error::Error>> {
    let mut map = base_map.clone();
    for patch in &template.linear_constraint_patches {
        apply_linear_constraint_patch(&mut map, patch)?;
    }
    for target_override in &template.target_overrides {
        map.linear_targets[target_override.target_index] = target_override.value;
    }
    map.linear_targets = instantiate_targets(
        &map.linear_targets,
        &template.target_bindings,
        public_values,
    );
    map.public_values = public_values.to_vec();
    map.exact_table_digest = exact_table_digest;
    Ok(map)
}

fn infer_constraint_map_template(
    mask: u8,
    baseline_maps: &[SmallwoodProductionConstraintMap],
) -> Result<ConstraintMapTemplate, Box<dyn std::error::Error>> {
    let public_sets = (0..=3)
        .map(|probe| public_values_for_mask(mask, probe))
        .collect::<Vec<_>>();
    let maps = public_sets
        .iter()
        .map(|values| smallwood_production_constraint_map_for_public_values(values))
        .collect::<Result<Vec<_>, _>>()?;
    for map in maps.iter().skip(1) {
        assert_same_structure(&maps[0], map)?;
    }

    let (linear_constraint_patches, mut patched_baseline) =
        derive_template_patches(mask, baseline_maps)?;
    let target_overrides = patched_baseline
        .linear_targets
        .iter()
        .zip(&maps[0].linear_targets)
        .enumerate()
        .filter_map(|(target_index, (actual, expected))| {
            (actual != expected).then_some(TargetOverride {
                target_index,
                value: *expected,
            })
        })
        .collect::<Vec<_>>();
    for target_override in &target_overrides {
        patched_baseline.linear_targets[target_override.target_index] = target_override.value;
    }
    patched_baseline.public_values = maps[0].public_values.clone();
    patched_baseline.exact_table_digest = maps[0].exact_table_digest;
    if patched_baseline != maps[0] {
        return Err(format!(
            "compressed baseline reconstruction failed for activity mask {mask:04b}"
        )
        .into());
    }

    let mut target_bindings = Vec::new();
    for target_index in 0..maps[0].linear_targets.len() {
        let baseline = maps[0].linear_targets[target_index];
        let target_delta1 = field_sub(maps[1].linear_targets[target_index], baseline);
        let target_delta2 = field_sub(maps[2].linear_targets[target_index], baseline);
        if target_delta1 == 0 && target_delta2 == 0 {
            continue;
        }
        let candidates = (4..CIRCUIT_VERSION_INDEX)
            .filter(|public_index| {
                field_sub(public_sets[1][*public_index], public_sets[0][*public_index])
                    == target_delta1
                    && field_sub(public_sets[2][*public_index], public_sets[0][*public_index])
                        == target_delta2
            })
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return Err(format!(
                "target {target_index} in activity mask {mask:04b} has unsupported public dependency candidates {candidates:?}"
            )
            .into());
        }
        let public_value_index = candidates[0];
        target_bindings.push(TargetBinding {
            target_index,
            public_value_index,
            additive_constant: field_sub(baseline, public_sets[0][public_value_index]),
        });
    }

    let template = ConstraintMapTemplate {
        name: format!("productionConstraintMapTemplate{mask:04b}"),
        input_flags: [u64::from(mask & 1), u64::from((mask >> 1) & 1)],
        output_flags: [u64::from((mask >> 2) & 1), u64::from((mask >> 3) & 1)],
        linear_constraint_patches,
        target_overrides,
        target_bindings,
    };
    let reconstructed = instantiate_template_map(
        &baseline_maps[0],
        &template,
        &public_sets[3],
        maps[3].exact_table_digest,
    )?;
    if reconstructed != maps[3] {
        return Err(
            format!("target binding reconstruction failed for activity mask {mask:04b}").into(),
        );
    }

    Ok(template)
}

fn lean_nat_list<T: ToString>(values: &[T]) -> String {
    let mut output = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
            if index % 12 == 0 {
                output.push_str("\n      ");
            } else {
                output.push(' ');
            }
        }
        output.push_str(&value.to_string());
    }
    output.push(']');
    output
}

fn lean_chunked_nat_list<T: ToString>(values: &[T]) -> String {
    const CHUNK_SIZE: usize = 256;
    if values.len() <= CHUNK_SIZE {
        return lean_nat_list(values);
    }
    let chunks = values
        .chunks(CHUNK_SIZE)
        .map(lean_nat_list)
        .collect::<Vec<_>>();
    format!("List.flatten [\n      {}]", chunks.join(",\n      "))
}

fn lean_constraint_expression(expression: &SmallwoodConstraintExpression) -> String {
    match expression {
        SmallwoodConstraintExpression::Constant(value) => {
            format!("ProductionConstraintExpression.constExpr {value}")
        }
        SmallwoodConstraintExpression::PublicValue(index) => {
            format!("ProductionConstraintExpression.publicExpr {index}")
        }
        SmallwoodConstraintExpression::WitnessRow(index) => {
            format!("ProductionConstraintExpression.witnessExpr {index}")
        }
        SmallwoodConstraintExpression::SlotDenominatorInverse(slot) => {
            format!("ProductionConstraintExpression.slotInverseExpr {slot}")
        }
        SmallwoodConstraintExpression::StableSelectorBit(bit) => {
            format!("ProductionConstraintExpression.stableSelectorExpr {bit}")
        }
        SmallwoodConstraintExpression::Add { left, right } => {
            format!("ProductionConstraintExpression.addExpr {left} {right}")
        }
        SmallwoodConstraintExpression::Sub { left, right } => {
            format!("ProductionConstraintExpression.subExpr {left} {right}")
        }
        SmallwoodConstraintExpression::Mul { left, right } => {
            format!("ProductionConstraintExpression.mulExpr {left} {right}")
        }
        SmallwoodConstraintExpression::Neg { value } => {
            format!("ProductionConstraintExpression.negExpr {value}")
        }
    }
}

fn lean_constraint_expression_list(values: &[SmallwoodConstraintExpression]) -> String {
    const CHUNK_SIZE: usize = 32;
    let chunks = values
        .chunks(CHUNK_SIZE)
        .map(|chunk| {
            let values = chunk
                .iter()
                .map(lean_constraint_expression)
                .collect::<Vec<_>>();
            format!(
                "([{}] : List ProductionConstraintExpression)",
                values.join(", ")
            )
        })
        .collect::<Vec<_>>();
    if chunks.len() == 1 {
        chunks[0].clone()
    } else {
        format!("List.flatten [\n    {}]", chunks.join(",\n    "))
    }
}

fn map_definition(name: &str, map: &SmallwoodProductionConstraintMap) -> String {
    let mut output = String::new();
    writeln!(&mut output, "def {name} : ProductionConstraintMap :=").unwrap();
    writeln!(&mut output, "  {{ publicFieldRanges :=").unwrap();
    for (index, range) in map.public_field_ranges.iter().enumerate() {
        let prefix = if index == 0 { "    [" } else { "      " };
        let suffix = if index + 1 == map.public_field_ranges.len() {
            " ]"
        } else {
            ","
        };
        writeln!(
            &mut output,
            "{prefix}{{ name := \"{}\", start := {}, stop := {} }}{suffix}",
            range.name, range.start, range.end
        )
        .unwrap();
    }
    writeln!(
        &mut output,
        "    publicValues := {}",
        lean_nat_list(&map.public_values)
    )
    .unwrap();
    writeln!(
        &mut output,
        "    publicValueCount := {}",
        map.public_value_count
    )
    .unwrap();
    writeln!(
        &mut output,
        "    rawWitnessLength := {}",
        map.raw_witness_len
    )
    .unwrap();
    writeln!(&mut output, "    lppcRowCount := {}", map.lppc_row_count).unwrap();
    writeln!(
        &mut output,
        "    lppcPackingFactor := {}",
        map.lppc_packing_factor
    )
    .unwrap();
    writeln!(
        &mut output,
        "    effectiveConstraintDegree := {}",
        map.effective_constraint_degree
    )
    .unwrap();
    writeln!(
        &mut output,
        "    linearConstraintCount := {}",
        map.linear_constraint_count
    )
    .unwrap();
    writeln!(
        &mut output,
        "    linearTermCount := {}",
        map.linear_term_count
    )
    .unwrap();
    writeln!(
        &mut output,
        "    auxiliaryWitnessLimbCount := {}",
        map.auxiliary_witness_limb_count
    )
    .unwrap();
    writeln!(
        &mut output,
        "    linearTermOffsets := {}",
        lean_chunked_nat_list(&map.linear_term_offsets)
    )
    .unwrap();
    writeln!(
        &mut output,
        "    linearTermIndices := {}",
        lean_chunked_nat_list(&map.linear_term_indices)
    )
    .unwrap();
    writeln!(
        &mut output,
        "    linearTermCoefficients := {}",
        lean_chunked_nat_list(&map.linear_term_coefficients)
    )
    .unwrap();
    writeln!(
        &mut output,
        "    linearTargets := {}",
        lean_chunked_nat_list(&map.linear_targets)
    )
    .unwrap();
    writeln!(
        &mut output,
        "    nonlinearConstraintCount := {}",
        map.nonlinear_constraint_count
    )
    .unwrap();
    writeln!(
        &mut output,
        "    nonlinearExpressionCount := {}",
        map.nonlinear_expression_count
    )
    .unwrap();
    writeln!(
        &mut output,
        "    nonlinearExpressions := productionNonlinearExpressions"
    )
    .unwrap();
    writeln!(
        &mut output,
        "    nonlinearConstraintRoots := productionNonlinearConstraintRoots"
    )
    .unwrap();
    writeln!(
        &mut output,
        "    nonlinearProgramDigest := {} }}",
        lean_nat_list(&map.nonlinear_program_digest)
    )
    .unwrap();
    output
}

fn lean_target_bindings(bindings: &[TargetBinding]) -> String {
    if bindings.is_empty() {
        return "[]".to_string();
    }
    let entries = bindings
        .iter()
        .map(|binding| {
            format!(
                "{{ targetIndex := {}, publicValueIndex := {}, additiveConstant := {} }}",
                binding.target_index, binding.public_value_index, binding.additive_constant
            )
        })
        .collect::<Vec<_>>();
    format!("[\n      {} ]", entries.join(",\n      "))
}

fn lean_linear_constraint_patches(patches: &[LinearConstraintPatch]) -> String {
    if patches.is_empty() {
        return "[]".to_string();
    }
    let entries = patches
        .iter()
        .map(|patch| {
            format!(
                "{{ constraintStart := {}\n        removedConstraintCount := {}\n        removedTermCount := {}\n        replacementTermOffsets := {}\n        replacementTermIndices := {}\n        replacementTermCoefficients := {}\n        replacementTargets := {} }}",
                patch.constraint_start,
                patch.removed_constraint_count,
                patch.removed_term_count,
                lean_chunked_nat_list(&patch.replacement_term_offsets),
                lean_chunked_nat_list(&patch.replacement_term_indices),
                lean_chunked_nat_list(&patch.replacement_term_coefficients),
                lean_chunked_nat_list(&patch.replacement_targets),
            )
        })
        .collect::<Vec<_>>();
    format!("[\n      {} ]", entries.join(",\n      "))
}

fn lean_target_overrides(overrides: &[TargetOverride]) -> String {
    if overrides.is_empty() {
        return "[]".to_string();
    }
    let entries = overrides
        .iter()
        .map(|target_override| {
            format!(
                "{{ targetIndex := {}, value := {} }}",
                target_override.target_index, target_override.value
            )
        })
        .collect::<Vec<_>>();
    format!("[\n      {} ]", entries.join(",\n      "))
}

fn template_definition(template: &ConstraintMapTemplate, base_name: &str) -> String {
    let mut output = String::new();
    writeln!(
        &mut output,
        "def {} : ProductionConstraintMapTemplate :=",
        template.name
    )
    .unwrap();
    writeln!(
        &mut output,
        "  {{ inputFlags := {}",
        lean_nat_list(&template.input_flags)
    )
    .unwrap();
    writeln!(
        &mut output,
        "    outputFlags := {}",
        lean_nat_list(&template.output_flags)
    )
    .unwrap();
    writeln!(&mut output, "    baseMap := {base_name}").unwrap();
    writeln!(
        &mut output,
        "    linearConstraintPatches := {}",
        lean_linear_constraint_patches(&template.linear_constraint_patches)
    )
    .unwrap();
    writeln!(
        &mut output,
        "    linearTargetOverrides := {}",
        lean_target_overrides(&template.target_overrides)
    )
    .unwrap();
    writeln!(
        &mut output,
        "    linearTargetBindings := {} }}",
        lean_target_bindings(&template.target_bindings)
    )
    .unwrap();
    output
}

fn activity_mask(public_values: &[u64]) -> u8 {
    public_values
        .iter()
        .take(4)
        .enumerate()
        .fold(0u8, |mask, (index, value)| {
            mask | (u8::try_from(*value).expect("Boolean production activity flag") << index)
        })
}

#[derive(Debug, PartialEq, Eq)]
struct RequiredLinearConstraintSpec {
    term_indices: Vec<u32>,
    term_coefficients: Vec<u64>,
    target: u64,
}

fn output_hash_poseidon_index(
    map: &SmallwoodProductionConstraintMap,
    output: usize,
    chunk: usize,
    step: usize,
    limb: usize,
) -> u32 {
    let packing = map.lppc_packing_factor;
    let permutation = 137 + output * 3 + chunk;
    let lane = permutation % packing;
    let row = DEPLOYED_POSEIDON_BASE_ROW
        + ((permutation / packing) * DEPLOYED_POSEIDON_ROWS_PER_PERMUTATION + step)
            * DEPLOYED_POSEIDON_WIDTH
        + limb;
    u32::try_from(row * packing + lane).expect("production output hash index fits u32")
}

fn output_hash_secret_index(
    map: &SmallwoodProductionConstraintMap,
    output: usize,
    chunk: usize,
    row_offset: usize,
) -> u32 {
    let packing = map.lppc_packing_factor;
    let lane = (137 + output * 3 + chunk) % packing;
    u32::try_from((68 + output * 12 + row_offset) * packing + lane)
        .expect("production output secret index fits u32")
}

fn output_hash_required_linear_specs(
    map: &SmallwoodProductionConstraintMap,
    output: usize,
) -> Vec<RequiredLinearConstraintSpec> {
    let neg_one = FIELD_MODULUS - 1;
    let mut specs = vec![
        RequiredLinearConstraintSpec {
            term_indices: vec![
                output_hash_poseidon_index(map, output, 0, 0, 0),
                output_hash_secret_index(map, output, 0, 0),
            ],
            term_coefficients: vec![1, neg_one],
            target: 1,
        },
        RequiredLinearConstraintSpec {
            term_indices: vec![
                output_hash_poseidon_index(map, output, 0, 0, 1),
                output_hash_secret_index(map, output, 0, 1),
            ],
            term_coefficients: vec![1, neg_one],
            target: 0,
        },
    ];
    for limb in 6..12 {
        specs.push(RequiredLinearConstraintSpec {
            term_indices: vec![output_hash_poseidon_index(map, output, 0, 0, limb)],
            term_coefficients: vec![1],
            target: u64::from(limb == 11),
        });
    }
    for previous_chunk in 0..2 {
        for limb in 6..12 {
            specs.push(RequiredLinearConstraintSpec {
                term_indices: vec![
                    output_hash_poseidon_index(map, output, previous_chunk + 1, 0, limb),
                    output_hash_poseidon_index(map, output, previous_chunk, 30, limb),
                ],
                term_coefficients: vec![1, neg_one],
                target: 0,
            });
        }
    }
    for limb in 0..4 {
        specs.push(RequiredLinearConstraintSpec {
            term_indices: vec![
                output_hash_poseidon_index(map, output, 2, 0, 2 + limb),
                output_hash_poseidon_index(map, output, 1, 30, 2 + limb),
                output_hash_secret_index(map, output, 2, 8 + limb),
            ],
            term_coefficients: vec![1, neg_one, neg_one],
            target: 0,
        });
    }
    for limb in 0..6 {
        specs.push(RequiredLinearConstraintSpec {
            term_indices: vec![output_hash_poseidon_index(map, output, 2, 30, limb)],
            term_coefficients: vec![1],
            target: map.public_values[16 + output * 6 + limb],
        });
    }
    specs
}

fn output_hash_binding_constraint_indices(
    map: &SmallwoodProductionConstraintMap,
    output: usize,
) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
    if map.public_values[2 + output] == 0 {
        return Ok(Vec::new());
    }
    if map.lppc_row_count != 1531 || map.lppc_packing_factor != 64 {
        return Err("unexpected deployed output hash geometry".into());
    }
    output_hash_required_linear_specs(map, output)
        .into_iter()
        .map(|required| {
            let matches = (0..map.linear_targets.len())
                .filter(|constraint| {
                    let start = map.linear_term_offsets[*constraint] as usize;
                    let stop = map.linear_term_offsets[*constraint + 1] as usize;
                    map.linear_term_indices[start..stop] == required.term_indices
                        && map.linear_term_coefficients[start..stop]
                            == required.term_coefficients
                        && map.linear_targets[*constraint] == required.target
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [constraint] => Ok(*constraint),
                _ => Err(format!(
                    "activity mask {:04b} output {output} required hash binding has {} matches: {required:?}",
                    activity_mask(&map.public_values),
                    matches.len()
                )
                .into()),
            }
        })
        .collect()
}

fn input_hash_commitment_permutation(input: usize, chunk: usize) -> usize {
    1 + input * 68 + chunk
}

fn input_hash_poseidon_index(
    map: &SmallwoodProductionConstraintMap,
    input: usize,
    chunk: usize,
    step: usize,
    limb: usize,
) -> u32 {
    let packing = map.lppc_packing_factor;
    let permutation = input_hash_commitment_permutation(input, chunk);
    let lane = permutation % packing;
    let row = DEPLOYED_POSEIDON_BASE_ROW
        + ((permutation / packing) * DEPLOYED_POSEIDON_ROWS_PER_PERMUTATION + step)
            * DEPLOYED_POSEIDON_WIDTH
        + limb;
    u32::try_from(row * packing + lane).expect("production input hash index fits u32")
}

fn input_hash_secret_index(
    map: &SmallwoodProductionConstraintMap,
    input: usize,
    row_offset: usize,
) -> u32 {
    let packing = map.lppc_packing_factor;
    let lane = input_hash_commitment_permutation(input, 0) % packing;
    u32::try_from((input * DEPLOYED_INPUT_ROWS + row_offset) * packing + lane)
        .expect("production input secret index fits u32")
}

fn input_hash_required_linear_specs(
    map: &SmallwoodProductionConstraintMap,
    input: usize,
) -> Vec<RequiredLinearConstraintSpec> {
    let neg_one = FIELD_MODULUS - 1;
    vec![
        RequiredLinearConstraintSpec {
            term_indices: vec![
                input_hash_poseidon_index(map, input, 0, 0, 0),
                input_hash_secret_index(map, input, 0),
            ],
            term_coefficients: vec![1, neg_one],
            target: 1,
        },
        RequiredLinearConstraintSpec {
            term_indices: vec![
                input_hash_poseidon_index(map, input, 0, 0, 1),
                input_hash_secret_index(map, input, 1),
            ],
            term_coefficients: vec![1, neg_one],
            target: 0,
        },
    ]
}

fn input_hash_binding_constraint_indices(
    map: &SmallwoodProductionConstraintMap,
    input: usize,
) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
    if map.public_values[input] == 0 {
        return Ok(Vec::new());
    }
    if map.lppc_row_count != DEPLOYED_ROW_COUNT
        || map.lppc_packing_factor != DEPLOYED_PACKING_FACTOR
    {
        return Err("unexpected deployed input hash geometry".into());
    }
    input_hash_required_linear_specs(map, input)
        .into_iter()
        .map(|required| {
            let matches = (0..map.linear_targets.len())
                .filter(|constraint| {
                    let start = map.linear_term_offsets[*constraint] as usize;
                    let stop = map.linear_term_offsets[*constraint + 1] as usize;
                    map.linear_term_indices[start..stop] == required.term_indices
                        && map.linear_term_coefficients[start..stop]
                            == required.term_coefficients
                        && map.linear_targets[*constraint] == required.target
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [constraint] => Ok(*constraint),
                _ => Err(format!(
                    "activity mask {:04b} input {input} required hash binding has {} matches: {required:?}",
                    activity_mask(&map.public_values),
                    matches.len()
                )
                .into()),
            }
        })
        .collect()
}

fn lean_input_hash_binding_index_table(
    maps: &[SmallwoodProductionConstraintMap],
) -> Result<String, Box<dyn std::error::Error>> {
    let rows = maps
        .iter()
        .map(|map| {
            let inputs = (0..2)
                .map(|input| input_hash_binding_constraint_indices(map, input))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!(
                "[{}, {}]",
                lean_nat_list(&inputs[0]),
                lean_nat_list(&inputs[1])
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    Ok(format!("[\n    {} ]", rows.join(",\n    ")))
}

fn packed_index(row: usize) -> u32 {
    u32::try_from(row * DEPLOYED_PACKING_FACTOR).expect("production reconstruction index fits u32")
}

fn reconstruction_limb_coefficient(limb: usize) -> u64 {
    1u64 << (limb * DEPLOYED_RANGE_LIMB_BITS)
}

fn witness_value_reconstruction_spec(
    value_row: usize,
    range_row: usize,
) -> RequiredLinearConstraintSpec {
    let mut term_indices = vec![packed_index(value_row)];
    let mut term_coefficients = vec![1];
    for limb in 0..DEPLOYED_RANGE_LIMB_COUNT {
        term_indices.push(packed_index(range_row + limb));
        term_coefficients.push(FIELD_MODULUS - reconstruction_limb_coefficient(limb));
    }
    RequiredLinearConstraintSpec {
        term_indices,
        term_coefficients,
        target: 0,
    }
}

fn public_value_reconstruction_spec(
    map: &SmallwoodProductionConstraintMap,
    range_slot: usize,
    public_value_index: usize,
) -> RequiredLinearConstraintSpec {
    RequiredLinearConstraintSpec {
        term_indices: (0..DEPLOYED_RANGE_LIMB_COUNT)
            .map(|limb| {
                packed_index(
                    DEPLOYED_RANGE_BASE_ROW + (4 + range_slot) * DEPLOYED_RANGE_LIMB_COUNT + limb,
                )
            })
            .collect(),
        term_coefficients: (0..DEPLOYED_RANGE_LIMB_COUNT)
            .map(reconstruction_limb_coefficient)
            .collect(),
        target: map.public_values[public_value_index],
    }
}

fn monetary_reconstruction_required_linear_specs(
    map: &SmallwoodProductionConstraintMap,
) -> Vec<RequiredLinearConstraintSpec> {
    let mut specs = Vec::with_capacity(7);
    for input in 0..2 {
        specs.push(witness_value_reconstruction_spec(
            input * DEPLOYED_INPUT_ROWS,
            DEPLOYED_RANGE_BASE_ROW + input * DEPLOYED_RANGE_LIMB_COUNT,
        ));
    }
    for output in 0..2 {
        specs.push(witness_value_reconstruction_spec(
            2 * DEPLOYED_INPUT_ROWS + output * DEPLOYED_OUTPUT_ROWS,
            DEPLOYED_RANGE_BASE_ROW + (2 + output) * DEPLOYED_RANGE_LIMB_COUNT,
        ));
    }
    for (range_slot, public_value_index) in [40usize, 42, 57].into_iter().enumerate() {
        specs.push(public_value_reconstruction_spec(
            map,
            range_slot,
            public_value_index,
        ));
    }
    specs
}

fn monetary_reconstruction_constraint_indices(
    map: &SmallwoodProductionConstraintMap,
) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
    if map.lppc_row_count != DEPLOYED_ROW_COUNT
        || map.lppc_packing_factor != DEPLOYED_PACKING_FACTOR
    {
        return Err("unexpected deployed monetary reconstruction geometry".into());
    }
    monetary_reconstruction_required_linear_specs(map)
        .into_iter()
        .enumerate()
        .map(|(binding, required)| {
            let matches = (0..map.linear_targets.len())
                .filter(|constraint| {
                    let start = map.linear_term_offsets[*constraint] as usize;
                    let stop = map.linear_term_offsets[*constraint + 1] as usize;
                    map.linear_term_indices[start..stop] == required.term_indices
                        && map.linear_term_coefficients[start..stop]
                            == required.term_coefficients
                        && map.linear_targets[*constraint] == required.target
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [constraint] => Ok(*constraint),
                _ => Err(format!(
                    "activity mask {:04b} monetary reconstruction binding {binding} has {} matches: {required:?}",
                    activity_mask(&map.public_values),
                    matches.len()
                )
                .into()),
            }
        })
        .collect()
}

fn lean_monetary_reconstruction_index_table(
    maps: &[SmallwoodProductionConstraintMap],
) -> Result<String, Box<dyn std::error::Error>> {
    let rows = maps
        .iter()
        .map(monetary_reconstruction_constraint_indices)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!(
        "[\n    {} ]",
        rows.iter()
            .map(|row| lean_nat_list(row))
            .collect::<Vec<_>>()
            .join(",\n    ")
    ))
}

fn lean_output_hash_binding_index_table(
    maps: &[SmallwoodProductionConstraintMap],
) -> Result<String, Box<dyn std::error::Error>> {
    let rows = maps
        .iter()
        .map(|map| {
            let outputs = (0..2)
                .map(|output| output_hash_binding_constraint_indices(map, output))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!(
                "[{}, {}]",
                lean_nat_list(&outputs[0]),
                lean_nat_list(&outputs[1])
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    Ok(format!("[\n    {} ]", rows.join(",\n    ")))
}

fn rust_byte_array(bytes: &[u8; 32]) -> String {
    format!(
        "[{}]",
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn rust_runtime_contracts(
    maps: &[SmallwoodProductionConstraintMap],
    templates: &[ConstraintMapTemplate],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut output = String::from(
        "// @generated by gen_smallwood_production_constraint_lean --rust-runtime-contract.\n\n\
#[derive(Clone, Copy, Debug)]\n\
pub(crate) struct SmallwoodProductionRuntimeContract {\n\
    pub(crate) activity_mask: u8,\n\
    pub(crate) structure_digest: [u8; 32],\n\
    pub(crate) normalized_targets_digest: [u8; 32],\n\
    pub(crate) target_bindings: &'static [(u32, u16)],\n\
}\n\n\
pub(crate) const SMALLWOOD_PRODUCTION_RUNTIME_CONTRACTS:\n\
    [SmallwoodProductionRuntimeContract; 16] = [\n",
    );
    for (mask, (map, template)) in maps.iter().zip(templates).enumerate() {
        let bindings = template
            .target_bindings
            .iter()
            .map(|binding| {
                Ok((
                    u32::try_from(binding.target_index)?,
                    u16::try_from(binding.public_value_index)?,
                ))
            })
            .collect::<Result<Vec<_>, std::num::TryFromIntError>>()?;
        let (structure_digest, normalized_targets_digest) =
            smallwood_production_runtime_contract_digests_for_generation(map, &bindings)?;
        let binding_text = bindings
            .iter()
            .map(|(target, public)| format!("({target}, {public})"))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            &mut output,
            "    SmallwoodProductionRuntimeContract {{\n        activity_mask: {mask},\n        structure_digest: {},\n        normalized_targets_digest: {},\n        target_bindings: &[{binding_text}],\n    }},",
            rust_byte_array(&structure_digest),
            rust_byte_array(&normalized_targets_digest),
        )?;
    }
    output.push_str("];\n");
    Ok(output)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_mode = env::args().nth(1);
    if output_mode
        .as_deref()
        .is_some_and(|mode| mode != "--rust-runtime-contract")
    {
        return Err(
            "usage: gen_smallwood_production_constraint_lean [--rust-runtime-contract]".into(),
        );
    }
    let active = smallwood_production_constraint_map(&active_witness())?;
    let stablecoin = smallwood_production_constraint_map(&stablecoin_witness())?;
    if active.nonlinear_expressions != stablecoin.nonlinear_expressions
        || active.nonlinear_constraint_roots != stablecoin.nonlinear_constraint_roots
        || active.nonlinear_program_digest != stablecoin.nonlinear_program_digest
    {
        return Err("production nonlinear program unexpectedly depends on fixture values".into());
    }
    let baseline_maps = (0u8..16)
        .map(|mask| {
            smallwood_production_constraint_map_for_public_values(&public_values_for_mask(mask, 0))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let templates = (0u8..16)
        .map(|mask| infer_constraint_map_template(mask, &baseline_maps))
        .collect::<Result<Vec<_>, _>>()?;
    if output_mode.as_deref() == Some("--rust-runtime-contract") {
        print!("{}", rust_runtime_contracts(&baseline_maps, &templates)?);
        return Ok(());
    }
    for (template, baseline_map) in templates.iter().zip(&baseline_maps) {
        if active.nonlinear_expressions != baseline_map.nonlinear_expressions
            || active.nonlinear_constraint_roots != baseline_map.nonlinear_constraint_roots
            || active.nonlinear_program_digest != baseline_map.nonlinear_program_digest
        {
            return Err(format!(
                "production nonlinear program unexpectedly depends on activity template {}",
                template.name
            )
            .into());
        }
    }
    let active_template = &templates[usize::from(activity_mask(&active.public_values))];
    let stablecoin_template = &templates[usize::from(activity_mask(&stablecoin.public_values))];
    if instantiate_template_map(
        &baseline_maps[0],
        active_template,
        &active.public_values,
        active.exact_table_digest,
    )? != active
        || instantiate_template_map(
            &baseline_maps[0],
            stablecoin_template,
            &stablecoin.public_values,
            stablecoin.exact_table_digest,
        )? != stablecoin
    {
        return Err("fixture maps do not instantiate from compressed activity templates".into());
    }
    let nonlinear_expressions = lean_constraint_expression_list(&active.nonlinear_expressions);
    let nonlinear_roots = lean_chunked_nat_list(&active.nonlinear_constraint_roots);
    let output_hash_binding_indices = lean_output_hash_binding_index_table(&baseline_maps)?;
    let input_hash_binding_indices = lean_input_hash_binding_index_table(&baseline_maps)?;
    let monetary_reconstruction_indices = lean_monetary_reconstruction_index_table(&baseline_maps)?;
    let base_name = "productionConstraintMapTemplateBase";
    let base_definition = map_definition(base_name, &baseline_maps[0]);
    let template_definitions = templates
        .iter()
        .map(|template| template_definition(template, base_name))
        .collect::<Vec<_>>()
        .join("\n");
    let template_names = templates
        .iter()
        .map(|template| template.name.as_str())
        .collect::<Vec<_>>()
        .join(",\n    ");
    print!(
        "import Hegemon.Transaction.SmallWoodProductionConstraintModel\n\nset_option maxHeartbeats 0\nset_option maxRecDepth 1000000\n\nnamespace Hegemon\nnamespace Transaction\nnamespace SmallWoodProductionConstraintRefinement\n\ndef productionNonlinearExpressions : List ProductionConstraintExpression :=\n  {nonlinear_expressions}\n\ndef productionNonlinearConstraintRoots : List Nat :=\n  {nonlinear_roots}\n\n{base_definition}\n{template_definitions}\n\ndef productionConstraintMapTemplates : List ProductionConstraintMapTemplate :=\n  [ {template_names} ]\n\ndef productionOutputHashBindingConstraintIndicesByActivityMask :\n    List (List (List Nat)) :=\n  {output_hash_binding_indices}\n\ndef productionInputHashBindingConstraintIndicesByActivityMask :\n    List (List (List Nat)) :=\n  {input_hash_binding_indices}\n\ndef productionMonetaryReconstructionConstraintIndicesByActivityMask :\n    List (List Nat) :=\n  {monetary_reconstruction_indices}\n\ndef activeConstraintTableDigest : List Nat :=\n  {}\n\ndef stablecoinConstraintTableDigest : List Nat :=\n  {}\n\ndef activeConstraintMap : ProductionConstraintMap :=\n  {}.instantiate {}\n\ndef stablecoinConstraintMap : ProductionConstraintMap :=\n  {}.instantiate {}\nend SmallWoodProductionConstraintRefinement\nend Transaction\nend Hegemon\n",
        lean_nat_list(&active.exact_table_digest),
        lean_nat_list(&stablecoin.exact_table_digest),
        active_template.name,
        lean_nat_list(&active.public_values),
        stablecoin_template.name,
        lean_nat_list(&stablecoin.public_values),
    );
    Ok(())
}
