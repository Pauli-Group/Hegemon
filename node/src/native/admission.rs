//! Action, transfer, bridge, sidecar, and resource admission evaluators.

use super::*;

pub(crate) fn validate_binding_hash(
    anchor: [u8; 48],
    nullifiers: &[[u8; 48]],
    commitments: &[[u8; 48]],
    ciphertext_hashes: &[[u8; 48]],
    balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
    fee: u64,
    binding_hash: [u8; 64],
    stablecoin: Option<protocol_shielded_pool::types::StablecoinPolicyBinding>,
) -> Result<()> {
    if !binding_hash_matches(
        anchor,
        nullifiers,
        commitments,
        ciphertext_hashes,
        balance_slot_asset_ids,
        fee,
        binding_hash,
        stablecoin,
    ) {
        return Err(anyhow!("binding hash mismatch"));
    }
    Ok(())
}

pub(crate) fn binding_hash_matches(
    anchor: [u8; 48],
    nullifiers: &[[u8; 48]],
    commitments: &[[u8; 48]],
    ciphertext_hashes: &[[u8; 48]],
    balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
    fee: u64,
    binding_hash: [u8; 64],
    stablecoin: Option<protocol_shielded_pool::types::StablecoinPolicyBinding>,
) -> bool {
    let inputs = ShieldedTransferInputs {
        anchor,
        nullifiers: nullifiers.to_vec(),
        commitments: commitments.to_vec(),
        ciphertext_hashes: ciphertext_hashes.to_vec(),
        balance_slot_asset_ids,
        fee,
        value_balance: 0,
        stablecoin,
    };
    let expected = StarkVerifier::compute_binding_hash(&inputs).data;
    expected == binding_hash
}

pub(crate) fn native_tx_leaf_artifact_stablecoin_binding(
    decoded: &consensus::backend_interface::NativeTxLeafArtifact,
) -> Result<Option<StablecoinPolicyBinding>> {
    Ok(match decoded.stark_public_inputs.stablecoin_enabled {
        0 => {
            if decoded.stark_public_inputs.stablecoin_asset_id != 0
                || decoded.stark_public_inputs.stablecoin_policy_version != 0
                || decoded.stark_public_inputs.stablecoin_issuance_sign != 0
                || decoded.stark_public_inputs.stablecoin_issuance_magnitude != 0
                || decoded.stark_public_inputs.stablecoin_policy_hash != [0u8; 48]
                || decoded.stark_public_inputs.stablecoin_oracle_commitment != [0u8; 48]
                || decoded
                    .stark_public_inputs
                    .stablecoin_attestation_commitment
                    != [0u8; 48]
            {
                return Err(anyhow!(
                    "disabled native tx-leaf stablecoin public fields must be zero"
                ));
            }
            None
        }
        1 => Some(StablecoinPolicyBinding {
            asset_id: decoded.stark_public_inputs.stablecoin_asset_id,
            policy_hash: decoded.stark_public_inputs.stablecoin_policy_hash,
            oracle_commitment: decoded.stark_public_inputs.stablecoin_oracle_commitment,
            attestation_commitment: decoded
                .stark_public_inputs
                .stablecoin_attestation_commitment,
            issuance_delta: native_tx_leaf_decode_signed_magnitude(
                decoded.stark_public_inputs.stablecoin_issuance_sign,
                decoded.stark_public_inputs.stablecoin_issuance_magnitude,
                "stablecoin_issuance",
            )?,
            policy_version: decoded.stark_public_inputs.stablecoin_policy_version,
        }),
        other => {
            return Err(anyhow!(
                "native tx-leaf stablecoin_enabled flag must be 0 or 1, got {other}"
            ));
        }
    })
}

pub(crate) fn native_tx_leaf_artifact_binding_hash(
    decoded: &consensus::backend_interface::NativeTxLeafArtifact,
) -> Result<[u8; 64]> {
    let balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS] = decoded
        .stark_public_inputs
        .balance_slot_asset_ids
        .clone()
        .try_into()
        .map_err(|slots: Vec<u64>| {
            anyhow!(
                "native tx-leaf balance slot length {} does not match {}",
                slots.len(),
                transaction_core::constants::BALANCE_SLOTS
            )
        })?;
    let stablecoin = native_tx_leaf_artifact_stablecoin_binding(decoded)?;
    let value_balance = native_tx_leaf_decode_signed_magnitude(
        decoded.stark_public_inputs.value_balance_sign,
        decoded.stark_public_inputs.value_balance_magnitude,
        "value_balance",
    )?;
    let inputs = ShieldedTransferInputs {
        anchor: decoded.stark_public_inputs.merkle_root,
        nullifiers: decoded.tx.nullifiers.clone(),
        commitments: decoded.tx.commitments.clone(),
        ciphertext_hashes: decoded.tx.ciphertext_hashes.clone(),
        balance_slot_asset_ids,
        fee: decoded.stark_public_inputs.fee,
        value_balance,
        stablecoin,
    };
    Ok(StarkVerifier::compute_binding_hash(&inputs).data)
}

pub(crate) fn native_tx_leaf_artifact_binding_hash_matches_key(
    binding_hash: [u8; 64],
    proof: &[u8],
) -> bool {
    consensus::backend_interface::decode_native_tx_leaf_artifact_bytes(proof)
        .and_then(|decoded| native_tx_leaf_artifact_binding_hash(&decoded))
        .is_ok_and(|expected| expected == binding_hash)
}

pub(crate) fn evaluate_native_transfer_payload_admission(
    input: NativeTransferPayloadAdmissionInput,
) -> Result<(), NativeTransferPayloadAdmissionRejection> {
    if input.proof_bytes == 0 {
        Err(NativeTransferPayloadAdmissionRejection::ProofMissing)
    } else if input.proof_bytes > input.max_proof_bytes {
        Err(NativeTransferPayloadAdmissionRejection::ProofTooLarge)
    } else if !input.anchor_matches {
        Err(NativeTransferPayloadAdmissionRejection::AnchorMismatch)
    } else if !input.commitments_match {
        Err(NativeTransferPayloadAdmissionRejection::CommitmentsMismatch)
    } else if input.inline_ciphertext_bytes > input.max_ciphertext_bytes {
        Err(NativeTransferPayloadAdmissionRejection::InlineCiphertextTooLarge)
    } else if !input.ciphertext_hashes_match {
        Err(NativeTransferPayloadAdmissionRejection::CiphertextHashesMismatch)
    } else if !input.ciphertext_sizes_match {
        Err(NativeTransferPayloadAdmissionRejection::CiphertextSizesMismatch)
    } else if !input.binding_hash_matches {
        Err(NativeTransferPayloadAdmissionRejection::BindingHashMismatch)
    } else if !input.proof_binding_hash_matches_key {
        Err(NativeTransferPayloadAdmissionRejection::ProofBindingHashMismatch)
    } else if !input.fee_matches {
        Err(NativeTransferPayloadAdmissionRejection::FeeMismatch)
    } else {
        Ok(())
    }
}

pub(crate) fn native_transfer_payload_admission_error(
    route: NativeTransferPayloadRoute,
    input: NativeTransferPayloadAdmissionInput,
    rejection: NativeTransferPayloadAdmissionRejection,
) -> anyhow::Error {
    let route_label = match route {
        NativeTransferPayloadRoute::Inline => "inline",
        NativeTransferPayloadRoute::Sidecar => "sidecar",
    };
    match rejection {
        NativeTransferPayloadAdmissionRejection::ProofMissing => {
            anyhow!("shielded {route_label} transfer missing proof")
        }
        NativeTransferPayloadAdmissionRejection::ProofTooLarge => anyhow!(
            "shielded {route_label} proof size {} exceeds native tx-leaf artifact limit {}",
            input.proof_bytes,
            input.max_proof_bytes
        ),
        NativeTransferPayloadAdmissionRejection::AnchorMismatch => {
            anyhow!("shielded {route_label} anchor mismatch")
        }
        NativeTransferPayloadAdmissionRejection::CommitmentsMismatch => {
            anyhow!("shielded {route_label} commitments mismatch")
        }
        NativeTransferPayloadAdmissionRejection::InlineCiphertextTooLarge => anyhow!(
            "inline ciphertext size {} exceeds limit {}",
            input.inline_ciphertext_bytes,
            input.max_ciphertext_bytes
        ),
        NativeTransferPayloadAdmissionRejection::CiphertextHashesMismatch => {
            anyhow!("shielded {route_label} ciphertext hashes mismatch")
        }
        NativeTransferPayloadAdmissionRejection::CiphertextSizesMismatch => {
            anyhow!("shielded {route_label} ciphertext sizes mismatch")
        }
        NativeTransferPayloadAdmissionRejection::BindingHashMismatch => {
            anyhow!("binding hash mismatch")
        }
        NativeTransferPayloadAdmissionRejection::ProofBindingHashMismatch => {
            anyhow!("proof binding hash mismatch")
        }
        NativeTransferPayloadAdmissionRejection::FeeMismatch => {
            anyhow!("shielded {route_label} fee mismatch")
        }
    }
}

pub(crate) fn evaluate_native_transfer_state_admission(
    input: NativeTransferStateAdmissionInput,
) -> Result<(), NativeTransferStateAdmissionRejection> {
    if !input.anchor_known {
        Err(NativeTransferStateAdmissionRejection::UnknownAnchor)
    } else {
        match input.nullifier_state {
            NativeTransferNullifierAdmissionState::Valid => {
                if !input.commitments_nonzero {
                    Err(NativeTransferStateAdmissionRejection::CommitmentZero)
                } else if !input.stablecoin_policy_authorized {
                    Err(NativeTransferStateAdmissionRejection::StablecoinPolicyUnauthorized)
                } else if !input.sidecar_route {
                    Ok(())
                } else if !input.sidecar_ciphertexts_available {
                    Err(NativeTransferStateAdmissionRejection::SidecarCiphertextMissing)
                } else if !input.sidecar_ciphertext_sizes_present {
                    Err(NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMissing)
                } else if !input.sidecar_ciphertext_sizes_match {
                    Err(NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMismatch)
                } else {
                    Ok(())
                }
            }
            NativeTransferNullifierAdmissionState::Zero => {
                Err(NativeTransferStateAdmissionRejection::NullifierZero)
            }
            NativeTransferNullifierAdmissionState::AlreadySpent => {
                Err(NativeTransferStateAdmissionRejection::NullifierAlreadySpent)
            }
            NativeTransferNullifierAdmissionState::Duplicate => {
                Err(NativeTransferStateAdmissionRejection::DuplicateNullifier)
            }
            NativeTransferNullifierAdmissionState::AlreadyPending => {
                Err(NativeTransferStateAdmissionRejection::NullifierAlreadyPending)
            }
        }
    }
}

pub(crate) fn native_transfer_state_admission_error(
    context: NativeTransferStateAdmissionContext,
    rejection: NativeTransferStateAdmissionRejection,
) -> anyhow::Error {
    match (context, rejection) {
        (_, NativeTransferStateAdmissionRejection::UnknownAnchor) => match context {
            NativeTransferStateAdmissionContext::Mempool => anyhow!("unknown shielded anchor"),
            NativeTransferStateAdmissionContext::Block => {
                anyhow!("block action references unknown anchor")
            }
        },
        (
            NativeTransferStateAdmissionContext::Mempool,
            NativeTransferStateAdmissionRejection::NullifierZero,
        ) => {
            anyhow!("zero nullifier rejected")
        }
        (
            NativeTransferStateAdmissionContext::Block,
            NativeTransferStateAdmissionRejection::NullifierZero,
        ) => {
            anyhow!("zero nullifier in block action")
        }
        (
            NativeTransferStateAdmissionContext::Mempool,
            NativeTransferStateAdmissionRejection::NullifierAlreadySpent,
        ) => {
            anyhow!("nullifier already spent")
        }
        (
            NativeTransferStateAdmissionContext::Block,
            NativeTransferStateAdmissionRejection::NullifierAlreadySpent,
        ) => {
            anyhow!("duplicate nullifier in block action")
        }
        (
            NativeTransferStateAdmissionContext::Mempool,
            NativeTransferStateAdmissionRejection::DuplicateNullifier,
        ) => {
            anyhow!("duplicate nullifier in action")
        }
        (
            NativeTransferStateAdmissionContext::Block,
            NativeTransferStateAdmissionRejection::DuplicateNullifier,
        ) => {
            anyhow!("duplicate nullifier in block action")
        }
        (
            NativeTransferStateAdmissionContext::Mempool,
            NativeTransferStateAdmissionRejection::NullifierAlreadyPending,
        ) => {
            anyhow!("nullifier already pending")
        }
        (
            NativeTransferStateAdmissionContext::Block,
            NativeTransferStateAdmissionRejection::NullifierAlreadyPending,
        ) => {
            anyhow!("duplicate nullifier in block action")
        }
        (
            NativeTransferStateAdmissionContext::Mempool,
            NativeTransferStateAdmissionRejection::CommitmentZero,
        ) => {
            anyhow!("zero commitment rejected")
        }
        (
            NativeTransferStateAdmissionContext::Block,
            NativeTransferStateAdmissionRejection::CommitmentZero,
        ) => {
            anyhow!("zero commitment in block action")
        }
        (_, NativeTransferStateAdmissionRejection::StablecoinPolicyUnauthorized) => {
            anyhow!("stablecoin policy unauthorized")
        }
        (_, NativeTransferStateAdmissionRejection::SidecarCiphertextMissing) => {
            anyhow!("missing staged ciphertext")
        }
        (_, NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMissing) => {
            anyhow!("missing staged ciphertext size")
        }
        (_, NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMismatch) => {
            anyhow!("staged ciphertext size mismatch")
        }
    }
}

pub(crate) fn native_action_state_effect_error(
    rejection: NativeActionStateEffectRejection,
) -> anyhow::Error {
    anyhow!("native action state effect rejected: {}", rejection.label())
}

pub(crate) fn evaluate_native_action_state_effect(
    leaf_start: u64,
    commitment_count: usize,
    ciphertext_count: usize,
    nullifiers: &[[u8; 48]],
    replay_key: Option<[u8; 48]>,
    nullifier_state: &mut NullifierState,
    bridge_replay_state: &mut InboundReplayState,
) -> Result<NativeActionStateEffect, NativeActionStateEffectRejection> {
    if commitment_count != ciphertext_count {
        return Err(NativeActionStateEffectRejection::CiphertextCountMismatch);
    }
    let commitment_count_u64 = u64::try_from(commitment_count)
        .map_err(|_| NativeActionStateEffectRejection::CommitmentIndexOverflow)?;
    let next_leaf_count = leaf_start
        .checked_add(commitment_count_u64)
        .ok_or(NativeActionStateEffectRejection::CommitmentIndexOverflow)?;

    for nullifier in nullifiers {
        match nullifier_state.import_one(*nullifier) {
            Ok(()) => {}
            Err(NullifierReject::Zero) => {
                return Err(NativeActionStateEffectRejection::NullifierZero);
            }
            Err(NullifierReject::AlreadySpent | NullifierReject::AlreadyPending) => {
                return Err(NativeActionStateEffectRejection::DuplicateNullifier);
            }
        }
    }

    let imported_bridge_replay = if let Some(replay_key) = replay_key {
        bridge_replay_state
            .import_one(replay_key)
            .map_err(|_| NativeActionStateEffectRejection::BridgeReplayDuplicate)?;
        true
    } else {
        false
    };

    Ok(NativeActionStateEffect {
        next_leaf_count,
        imported_nullifier_count: nullifiers.len(),
        imported_bridge_replay,
    })
}

pub(crate) fn evaluate_native_action_stream_effect<'a>(
    leaf_start: u64,
    steps: impl IntoIterator<Item = NativeActionStreamStep<'a>>,
    nullifier_state: &mut NullifierState,
    bridge_replay_state: &mut InboundReplayState,
) -> Result<NativeActionStreamEffect, NativeActionStateEffectRejection> {
    let mut next_leaf_count = leaf_start;
    let mut imported_nullifier_count = 0usize;
    let mut imported_bridge_replay_count = 0usize;
    let mut planned_starts = Vec::new();

    for step in steps {
        planned_starts.push(next_leaf_count);
        let effect = evaluate_native_action_state_effect(
            next_leaf_count,
            step.commitment_count,
            step.ciphertext_count,
            step.nullifiers,
            step.replay_key,
            nullifier_state,
            bridge_replay_state,
        )?;
        next_leaf_count = effect.next_leaf_count;
        imported_nullifier_count = imported_nullifier_count
            .checked_add(effect.imported_nullifier_count)
            .ok_or(NativeActionStateEffectRejection::CommitmentIndexOverflow)?;
        if effect.imported_bridge_replay {
            imported_bridge_replay_count = imported_bridge_replay_count
                .checked_add(1)
                .ok_or(NativeActionStateEffectRejection::CommitmentIndexOverflow)?;
        }
    }

    Ok(NativeActionStreamEffect {
        next_leaf_count,
        imported_nullifier_count,
        imported_bridge_replay_count,
        planned_starts,
    })
}

pub(crate) fn evaluate_native_action_plan_application_admission(
    leaf_start: u64,
    action_commitment_counts: &[usize],
    planned_starts: &[u64],
) -> Result<NativeActionPlanApplicationSummary, NativeActionPlanApplicationAdmissionRejection> {
    if action_commitment_counts.len() != planned_starts.len() {
        return Err(NativeActionPlanApplicationAdmissionRejection::PlanLengthMismatch);
    }

    let mut next_leaf_count = leaf_start;
    for (commitment_count, planned_start) in action_commitment_counts
        .iter()
        .copied()
        .zip(planned_starts.iter().copied())
    {
        if planned_start != next_leaf_count {
            return Err(NativeActionPlanApplicationAdmissionRejection::PlannedStartMismatch);
        }
        let commitment_count = u64::try_from(commitment_count)
            .map_err(|_| NativeActionPlanApplicationAdmissionRejection::CommitmentIndexOverflow)?;
        next_leaf_count = next_leaf_count
            .checked_add(commitment_count)
            .ok_or(NativeActionPlanApplicationAdmissionRejection::CommitmentIndexOverflow)?;
    }

    Ok(NativeActionPlanApplicationSummary {
        next_leaf_count,
        applied_action_count: action_commitment_counts.len(),
    })
}

pub(crate) fn native_action_plan_application_admission_error(
    context: &'static str,
    rejection: NativeActionPlanApplicationAdmissionRejection,
) -> anyhow::Error {
    anyhow!("{context}: {}", rejection.label())
}

pub(crate) fn action_commitment_counts(actions: &[PendingAction]) -> Vec<usize> {
    actions
        .iter()
        .map(|action| action.commitments.len())
        .collect()
}

pub(crate) fn planned_action_starts(planned: &[NativePlannedActionEffect]) -> Vec<u64> {
    planned
        .iter()
        .map(|effect| effect.commitment_start)
        .collect()
}

pub(crate) fn admit_native_action_plan_application(
    context: &'static str,
    leaf_start: u64,
    actions: &[PendingAction],
    planned: &[NativePlannedActionEffect],
) -> Result<NativeActionPlanApplicationSummary> {
    evaluate_native_action_plan_application_admission(
        leaf_start,
        &action_commitment_counts(actions),
        &planned_action_starts(planned),
    )
    .map_err(|rejection| native_action_plan_application_admission_error(context, rejection))
}

pub(crate) fn evaluate_native_action_wire_replay_projection_admission(
    action_count: usize,
    planned_count: usize,
    steps: &[NativeActionWireReplayProjectionStep],
) -> Result<
    NativeActionWireReplayProjectionSummary,
    NativeActionWireReplayProjectionAdmissionRejection,
> {
    if action_count != planned_count || action_count != steps.len() {
        return Err(NativeActionWireReplayProjectionAdmissionRejection::PlanLength);
    }

    let mut projected_ciphertext_row_count = 0usize;
    let mut projected_bridge_replay_row_count = 0usize;
    for step in steps {
        if step.ciphertext_hash_count != step.ciphertext_size_count
            || step.ciphertext_hash_count != step.planned_ciphertext_count
        {
            return Err(NativeActionWireReplayProjectionAdmissionRejection::CiphertextCount);
        }
        if !step.ciphertext_hashes_match {
            return Err(NativeActionWireReplayProjectionAdmissionRejection::CiphertextHash);
        }
        if !step.ciphertext_sizes_match {
            return Err(NativeActionWireReplayProjectionAdmissionRejection::CiphertextSize);
        }
        if !step.replay_key_matches {
            return Err(NativeActionWireReplayProjectionAdmissionRejection::ReplayKey);
        }
        projected_ciphertext_row_count = projected_ciphertext_row_count
            .checked_add(step.planned_ciphertext_count)
            .ok_or(NativeActionWireReplayProjectionAdmissionRejection::CiphertextCount)?;
        if step.planned_replay_present {
            projected_bridge_replay_row_count = projected_bridge_replay_row_count
                .checked_add(1)
                .ok_or(NativeActionWireReplayProjectionAdmissionRejection::ReplayKey)?;
        }
    }

    Ok(NativeActionWireReplayProjectionSummary {
        projected_action_count: steps.len(),
        projected_ciphertext_row_count,
        projected_bridge_replay_row_count,
    })
}

pub(crate) fn native_action_wire_replay_projection_admission_error(
    context: &'static str,
    rejection: NativeActionWireReplayProjectionAdmissionRejection,
) -> anyhow::Error {
    anyhow!("{context}: {}", rejection.label())
}

pub(crate) fn native_action_wire_replay_projection_step(
    action: &PendingAction,
    effect: &NativePlannedActionEffect,
) -> Result<NativeActionWireReplayProjectionStep> {
    let ciphertext_counts_match = action.ciphertext_hashes.len() == action.ciphertext_sizes.len()
        && action.ciphertext_hashes.len() == effect.ciphertexts.len();
    let ciphertext_hashes_match = ciphertext_counts_match
        && effect
            .ciphertexts
            .iter()
            .zip(action.ciphertext_hashes.iter())
            .all(|(bytes, expected_hash)| ciphertext_hash_bytes(bytes) == *expected_hash);
    let ciphertext_sizes_match = ciphertext_counts_match
        && effect
            .ciphertexts
            .iter()
            .zip(action.ciphertext_sizes.iter())
            .all(|(bytes, expected_size)| bytes.len() == *expected_size as usize);
    let expected_replay_key = bridge_inbound_replay_key_from_action(action)
        .map_err(|err| anyhow!("decode native action replay key projection failed: {err}"))?;

    Ok(NativeActionWireReplayProjectionStep {
        ciphertext_hash_count: action.ciphertext_hashes.len(),
        ciphertext_size_count: action.ciphertext_sizes.len(),
        planned_ciphertext_count: effect.ciphertexts.len(),
        ciphertext_hashes_match,
        ciphertext_sizes_match,
        planned_replay_present: effect.replay_key.is_some(),
        replay_key_matches: effect.replay_key == expected_replay_key,
    })
}

pub(crate) fn admit_native_action_wire_replay_projection(
    context: &'static str,
    actions: &[PendingAction],
    planned: &[NativePlannedActionEffect],
) -> Result<NativeActionWireReplayProjectionSummary> {
    if actions.len() != planned.len() {
        return Err(native_action_wire_replay_projection_admission_error(
            context,
            NativeActionWireReplayProjectionAdmissionRejection::PlanLength,
        ));
    }
    let steps = actions
        .iter()
        .zip(planned.iter())
        .map(|(action, effect)| native_action_wire_replay_projection_step(action, effect))
        .collect::<Result<Vec<_>>>()?;
    evaluate_native_action_wire_replay_projection_admission(actions.len(), planned.len(), &steps)
        .map_err(|rejection| {
            native_action_wire_replay_projection_admission_error(context, rejection)
        })
}

pub(crate) fn mempool_transfer_nullifier_admission_state(
    state: &NativeState,
    action: &PendingAction,
) -> NativeTransferNullifierAdmissionState {
    let mut nullifier_state = shielded_nullifier_state_for_mempool(state);
    mempool_transfer_nullifier_admission_state_from_nullifiers(
        &mut nullifier_state,
        &action.nullifiers,
    )
}

pub(crate) fn mempool_transfer_nullifier_admission_state_from_nullifiers(
    nullifier_state: &mut NullifierState,
    nullifiers: &[[u8; 48]],
) -> NativeTransferNullifierAdmissionState {
    let mut action_seen = BTreeSet::new();
    for nullifier in nullifiers {
        let duplicate_in_action = !action_seen.insert(*nullifier);
        match nullifier_state.stage(*nullifier) {
            Ok(()) => {}
            Err(NullifierReject::Zero) => return NativeTransferNullifierAdmissionState::Zero,
            Err(NullifierReject::AlreadySpent) => {
                return NativeTransferNullifierAdmissionState::AlreadySpent;
            }
            Err(NullifierReject::AlreadyPending) if duplicate_in_action => {
                return NativeTransferNullifierAdmissionState::Duplicate;
            }
            Err(NullifierReject::AlreadyPending) => {
                return NativeTransferNullifierAdmissionState::AlreadyPending;
            }
        }
    }
    NativeTransferNullifierAdmissionState::Valid
}

pub(crate) fn block_transfer_nullifier_admission_state(
    nullifier_state: &mut NullifierState,
    action: &PendingAction,
) -> NativeTransferNullifierAdmissionState {
    block_transfer_nullifier_admission_state_from_nullifiers(nullifier_state, &action.nullifiers)
}

pub(crate) fn block_transfer_nullifier_admission_state_from_nullifiers(
    nullifier_state: &mut NullifierState,
    nullifiers: &[[u8; 48]],
) -> NativeTransferNullifierAdmissionState {
    for nullifier in nullifiers {
        match nullifier_state.import_one(*nullifier) {
            Ok(()) => {}
            Err(NullifierReject::Zero) => return NativeTransferNullifierAdmissionState::Zero,
            Err(NullifierReject::AlreadySpent | NullifierReject::AlreadyPending) => {
                return NativeTransferNullifierAdmissionState::Duplicate;
            }
        }
    }
    NativeTransferNullifierAdmissionState::Valid
}

pub(crate) fn sidecar_ciphertext_state_for_action(
    state: &NativeState,
    action: &PendingAction,
) -> (bool, bool, bool) {
    let mut all_available = true;
    let mut all_sizes_present = true;
    let mut all_sizes_match = true;
    for (idx, hash) in action.ciphertext_hashes.iter().enumerate() {
        let observed = state.staged_ciphertexts.get(&hex48(hash)).copied();
        let expected = action.ciphertext_sizes.get(idx).copied();
        match (observed, expected) {
            (Some(observed), Some(expected)) if observed == expected => {}
            (Some(_), Some(_)) => all_sizes_match = false,
            (Some(_), None) => all_sizes_present = false,
            (None, _) => all_available = false,
        }
    }
    (all_available, all_sizes_present, all_sizes_match)
}

#[cfg(test)]
pub(crate) fn stablecoin_policy_authorization_key(binding: &StablecoinPolicyBinding) -> Vec<u8> {
    binding.encode()
}

pub(crate) fn evaluate_native_stablecoin_policy_authorization(
    input: NativeStablecoinPolicyAuthorizationInput,
) -> Result<(), NativeStablecoinPolicyAuthorizationRejection> {
    if !input.stablecoin_present {
        Ok(())
    } else if !input.policy_known {
        Err(NativeStablecoinPolicyAuthorizationRejection::PolicyMissing)
    } else if !input.policy_active {
        Err(NativeStablecoinPolicyAuthorizationRejection::PolicyInactive)
    } else if !input.policy_lifecycle_open {
        Err(NativeStablecoinPolicyAuthorizationRejection::PolicyNotLive)
    } else if !input.asset_matches {
        Err(NativeStablecoinPolicyAuthorizationRejection::AssetMismatch)
    } else if !input.policy_hash_matches {
        Err(NativeStablecoinPolicyAuthorizationRejection::PolicyHashMismatch)
    } else if !input.policy_version_matches {
        Err(NativeStablecoinPolicyAuthorizationRejection::PolicyVersionMismatch)
    } else if !input.oracle_commitment_matches {
        Err(NativeStablecoinPolicyAuthorizationRejection::OracleCommitmentMismatch)
    } else if !input.attestation_commitment_matches {
        Err(NativeStablecoinPolicyAuthorizationRejection::AttestationCommitmentMismatch)
    } else if !input.attestation_not_disputed {
        Err(NativeStablecoinPolicyAuthorizationRejection::AttestationDisputed)
    } else if !input.oracle_fresh {
        Err(NativeStablecoinPolicyAuthorizationRejection::OracleStale)
    } else if !input.issuance_nonzero {
        Err(NativeStablecoinPolicyAuthorizationRejection::IssuanceZero)
    } else if !input.issuance_within_limit {
        Err(NativeStablecoinPolicyAuthorizationRejection::IssuanceOverLimit)
    } else {
        Ok(())
    }
}

pub(crate) fn native_stablecoin_policy_authorization_input_for_entry(
    current_height: u64,
    binding: &StablecoinPolicyBinding,
    entry: Option<&StablecoinPolicyManifestEntry>,
) -> NativeStablecoinPolicyAuthorizationInput {
    let Some(entry) = entry else {
        return NativeStablecoinPolicyAuthorizationInput {
            stablecoin_present: true,
            policy_known: false,
            policy_active: false,
            policy_lifecycle_open: false,
            asset_matches: false,
            policy_hash_matches: false,
            policy_version_matches: false,
            oracle_commitment_matches: false,
            attestation_commitment_matches: false,
            attestation_not_disputed: false,
            oracle_fresh: false,
            issuance_nonzero: false,
            issuance_within_limit: false,
        };
    };
    let oracle_fresh = entry.oracle_submitted_at <= current_height
        && current_height.saturating_sub(entry.oracle_submitted_at) <= entry.oracle_max_age;
    let policy_lifecycle_open = current_height >= entry.enabled_at
        && match entry.retired_at {
            Some(retired_at) => current_height < retired_at,
            None => true,
        };
    let issuance_abs = binding.issuance_delta.unsigned_abs();
    NativeStablecoinPolicyAuthorizationInput {
        stablecoin_present: true,
        policy_known: true,
        policy_active: entry.active,
        policy_lifecycle_open,
        asset_matches: u64::from(entry.asset_id) == binding.asset_id,
        policy_hash_matches: entry.policy_hash() == binding.policy_hash,
        policy_version_matches: entry.policy_version == binding.policy_version,
        oracle_commitment_matches: entry.oracle_commitment == binding.oracle_commitment,
        attestation_commitment_matches: entry.attestation_commitment
            == binding.attestation_commitment,
        attestation_not_disputed: !entry.attestation_disputed,
        oracle_fresh,
        issuance_nonzero: binding.issuance_delta != 0,
        issuance_within_limit: issuance_abs <= entry.max_mint_per_epoch
            && issuance_abs <= u64::MAX as u128,
    }
}

pub(crate) fn native_stablecoin_policy_binding_authorized_by_entries(
    current_height: u64,
    binding: &StablecoinPolicyBinding,
    entries: &[StablecoinPolicyManifestEntry],
) -> bool {
    entries.iter().any(|entry| {
        let plausible_candidate = u64::from(entry.asset_id) == binding.asset_id
            || entry.policy_hash() == binding.policy_hash;
        plausible_candidate
            && evaluate_native_stablecoin_policy_authorization(
                native_stablecoin_policy_authorization_input_for_entry(
                    current_height,
                    binding,
                    Some(entry),
                ),
            )
            .is_ok()
    })
}

pub(crate) fn native_stablecoin_policy_binding_authorized_by_protocol_manifest(
    current_height: u64,
    binding: &StablecoinPolicyBinding,
) -> bool {
    let manifest = protocol_manifest();
    native_stablecoin_policy_binding_authorized_by_entries(
        current_height,
        binding,
        &manifest.stablecoin_policies,
    )
}

pub(crate) fn native_transfer_stablecoin_policy_authorized(
    state: &NativeState,
    action: &PendingAction,
) -> bool {
    match transfer_action_stablecoin_binding(action) {
        Ok(None) => true,
        Ok(Some(binding)) => {
            let manifest_authorized =
                native_stablecoin_policy_binding_authorized_by_protocol_manifest(
                    state.best.height,
                    &binding,
                );
            #[cfg(test)]
            {
                manifest_authorized
                    || state
                        .stablecoin_policy_authorizations
                        .contains(&stablecoin_policy_authorization_key(&binding))
            }
            #[cfg(not(test))]
            {
                manifest_authorized
            }
        }
        Err(_) => false,
    }
}

pub(crate) fn native_transfer_state_admission_input_for_mempool(
    state: &NativeState,
    action: &PendingAction,
) -> NativeTransferStateAdmissionInput {
    let sidecar_route = action.family_id == FAMILY_SHIELDED_POOL
        && action.action_id == ACTION_SHIELDED_TRANSFER_SIDECAR;
    let (
        sidecar_ciphertexts_available,
        sidecar_ciphertext_sizes_present,
        sidecar_ciphertext_sizes_match,
    ) = if sidecar_route {
        sidecar_ciphertext_state_for_action(state, action)
    } else {
        (true, true, true)
    };
    NativeTransferStateAdmissionInput {
        anchor_known: state.commitment_tree.contains_root(&action.anchor),
        nullifier_state: mempool_transfer_nullifier_admission_state(state, action),
        commitments_nonzero: action
            .commitments
            .iter()
            .all(|commitment| *commitment != [0u8; 48]),
        stablecoin_policy_authorized: native_transfer_stablecoin_policy_authorized(state, action),
        sidecar_route,
        sidecar_ciphertexts_available,
        sidecar_ciphertext_sizes_present,
        sidecar_ciphertext_sizes_match,
    }
}

pub(crate) fn native_transfer_state_admission_input_for_block(
    state: &NativeState,
    nullifier_state: &mut NullifierState,
    action: &PendingAction,
) -> NativeTransferStateAdmissionInput {
    NativeTransferStateAdmissionInput {
        anchor_known: state.commitment_tree.contains_root(&action.anchor),
        nullifier_state: block_transfer_nullifier_admission_state(nullifier_state, action),
        commitments_nonzero: action
            .commitments
            .iter()
            .all(|commitment| *commitment != [0u8; 48]),
        stablecoin_policy_authorized: native_transfer_stablecoin_policy_authorized(state, action),
        sidecar_route: false,
        sidecar_ciphertexts_available: true,
        sidecar_ciphertext_sizes_present: true,
        sidecar_ciphertext_sizes_match: true,
    }
}

pub(crate) fn inline_transfer_ciphertext_resource_input(
    route_payload_bytes: usize,
    proof_bytes: usize,
    ciphertexts: &[protocol_shielded_pool::types::EncryptedNote],
) -> NativeInlineTransferCiphertextResourceInput {
    let mut max_ciphertext_bytes_observed = 0usize;
    let mut aggregate_ciphertext_bytes = 0usize;
    for note in ciphertexts {
        let ciphertext_bytes = note
            .ciphertext
            .len()
            .saturating_add(note.kem_ciphertext.len());
        max_ciphertext_bytes_observed = max_ciphertext_bytes_observed.max(ciphertext_bytes);
        aggregate_ciphertext_bytes = aggregate_ciphertext_bytes.saturating_add(ciphertext_bytes);
    }
    let output_count_cap = transaction_core::constants::MAX_OUTPUTS;
    NativeInlineTransferCiphertextResourceInput {
        raw_byte_cap: MAX_NATIVE_RPC_ACTION_BYTES,
        decoded_byte_cap: MAX_NATIVE_RPC_ACTION_BYTES,
        item_count_cap: output_count_cap,
        item_byte_cap: MAX_CIPHERTEXT_BYTES,
        aggregate_byte_cap: output_count_cap.saturating_mul(MAX_CIPHERTEXT_BYTES),
        work_unit_cap: output_count_cap,
        route_payload_bytes,
        proof_bytes,
        ciphertext_count: ciphertexts.len(),
        max_ciphertext_bytes_observed,
        aggregate_ciphertext_bytes,
    }
}

pub(crate) fn inline_transfer_ciphertext_resource_bounded_request(
    input: NativeInlineTransferCiphertextResourceInput,
) -> NativeBoundedRequestAdmissionInput {
    NativeBoundedRequestAdmissionInput {
        raw_byte_cap: input.raw_byte_cap,
        decoded_byte_cap: input.decoded_byte_cap,
        item_count_cap: input.item_count_cap,
        item_byte_cap: input.item_byte_cap,
        aggregate_byte_cap: input.aggregate_byte_cap,
        work_unit_cap: input.work_unit_cap,
        raw_bytes: input.route_payload_bytes,
        decoded_bytes: input
            .proof_bytes
            .saturating_add(input.aggregate_ciphertext_bytes),
        item_count: input.ciphertext_count,
        max_item_bytes: input.max_ciphertext_bytes_observed,
        aggregate_bytes: input.aggregate_ciphertext_bytes,
        work_units: input.ciphertext_count,
    }
}

pub(crate) fn validate_inline_transfer_ciphertext_resource(
    input: NativeInlineTransferCiphertextResourceInput,
) -> Result<NativeBoundedRequestAdmissionInput> {
    let bounded = inline_transfer_ciphertext_resource_bounded_request(input);
    evaluate_native_bounded_request_admission(bounded)
        .map(|_| bounded)
        .map_err(|rejection| {
            inline_transfer_ciphertext_resource_admission_error(bounded, rejection)
        })
}

pub(crate) fn inline_transfer_ciphertext_resource_admission_error(
    input: NativeBoundedRequestAdmissionInput,
    rejection: NativeBoundedRequestAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeBoundedRequestAdmissionRejection::RawBytes => anyhow!(
            "inline transfer route payload bytes {} exceeds cap {}",
            input.raw_bytes,
            input.raw_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::DecodedBytes => anyhow!(
            "inline transfer decoded proof+ciphertext bytes {} exceeds cap {}",
            input.decoded_bytes,
            input.decoded_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::ItemCount => anyhow!(
            "inline ciphertext count {} exceeds limit {}",
            input.item_count,
            input.item_count_cap
        ),
        NativeBoundedRequestAdmissionRejection::ItemBytes => anyhow!(
            "inline ciphertext size {} exceeds limit {}",
            input.max_item_bytes,
            input.item_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::AggregateBytes => anyhow!(
            "inline ciphertext aggregate bytes {} exceeds cap {}",
            input.aggregate_bytes,
            input.aggregate_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::WorkUnits => anyhow!(
            "inline ciphertext work units {} exceeds cap {}",
            input.work_units,
            input.work_unit_cap
        ),
    }
}

pub(crate) fn inline_ciphertext_metadata(
    ciphertexts: &[protocol_shielded_pool::types::EncryptedNote],
) -> (usize, Option<(Vec<[u8; 48]>, Vec<u32>)>) {
    let max_inline_ciphertext_bytes = ciphertexts
        .iter()
        .map(|note| {
            note.ciphertext
                .len()
                .saturating_add(note.kem_ciphertext.len())
        })
        .max()
        .unwrap_or(0);
    if max_inline_ciphertext_bytes > MAX_CIPHERTEXT_BYTES {
        return (max_inline_ciphertext_bytes, None);
    }
    let ciphertext_hashes = ciphertexts
        .iter()
        .map(|note| {
            let total_len = note
                .ciphertext
                .len()
                .saturating_add(note.kem_ciphertext.len());
            let mut bytes = Vec::with_capacity(total_len);
            bytes.extend_from_slice(&note.ciphertext);
            bytes.extend_from_slice(&note.kem_ciphertext);
            ciphertext_hash_bytes(&bytes)
        })
        .collect::<Vec<_>>();
    let ciphertext_sizes = ciphertexts
        .iter()
        .map(|note| {
            u32::try_from(
                note.ciphertext
                    .len()
                    .saturating_add(note.kem_ciphertext.len()),
            )
            .unwrap_or(u32::MAX)
        })
        .collect::<Vec<_>>();
    (
        max_inline_ciphertext_bytes,
        Some((ciphertext_hashes, ciphertext_sizes)),
    )
}

pub(crate) fn admitted_inline_ciphertext_metadata(
    route_payload_bytes: usize,
    proof_bytes: usize,
    ciphertexts: &[protocol_shielded_pool::types::EncryptedNote],
) -> Result<(usize, Vec<[u8; 48]>, Vec<u32>)> {
    let input =
        inline_transfer_ciphertext_resource_input(route_payload_bytes, proof_bytes, ciphertexts);
    validate_inline_transfer_ciphertext_resource(input)?;
    let (max_inline_ciphertext_bytes, metadata) = inline_ciphertext_metadata(ciphertexts);
    let (ciphertext_hashes, ciphertext_sizes) = metadata.ok_or_else(|| {
        inline_transfer_ciphertext_resource_admission_error(
            inline_transfer_ciphertext_resource_bounded_request(input),
            NativeBoundedRequestAdmissionRejection::ItemBytes,
        )
    })?;
    Ok((
        max_inline_ciphertext_bytes,
        ciphertext_hashes,
        ciphertext_sizes,
    ))
}

pub(crate) fn validate_transfer_action_payload(action: &PendingAction) -> Result<()> {
    if !is_shielded_transfer_action(action) {
        return Err(anyhow!("action is not a shielded transfer"));
    }
    if action.nullifiers.is_empty() {
        return Err(anyhow!(
            "shielded transfer must include at least one nullifier"
        ));
    }
    if action.nullifiers.len() > transaction_core::constants::MAX_INPUTS {
        return Err(anyhow!("too many nullifiers"));
    }
    if action.commitments.is_empty() {
        return Err(anyhow!(
            "shielded transfer must include at least one commitment"
        ));
    }
    if action.commitments.len() > transaction_core::constants::MAX_OUTPUTS {
        return Err(anyhow!("too many commitments"));
    }
    if action.ciphertext_hashes.len() != action.commitments.len() {
        return Err(anyhow!("ciphertext hash count must match commitments"));
    }
    if action.ciphertext_sizes.len() != action.commitments.len() {
        return Err(anyhow!("ciphertext size count must match commitments"));
    }
    for size in &action.ciphertext_sizes {
        if *size as usize > MAX_CIPHERTEXT_BYTES {
            return Err(anyhow!(
                "ciphertext size {} exceeds limit {}",
                size,
                MAX_CIPHERTEXT_BYTES
            ));
        }
    }

    match action.action_id {
        ACTION_SHIELDED_TRANSFER_INLINE => {
            let args: ShieldedTransferInlineArgs =
                decode_scale_exact(&action.public_args, "shielded inline action args")?;
            let (inline_ciphertext_bytes, ciphertext_hashes, ciphertext_sizes) =
                admitted_inline_ciphertext_metadata(
                    action.public_args.len(),
                    args.proof.len(),
                    &args.ciphertexts,
                )?;
            let input = NativeTransferPayloadAdmissionInput {
                proof_bytes: args.proof.len(),
                max_proof_bytes: NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                anchor_matches: args.anchor == action.anchor,
                commitments_match: args.commitments == action.commitments,
                inline_ciphertext_bytes,
                max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
                ciphertext_hashes_match: ciphertext_hashes == action.ciphertext_hashes,
                ciphertext_sizes_match: ciphertext_sizes == action.ciphertext_sizes,
                binding_hash_matches: binding_hash_matches(
                    args.anchor,
                    &action.nullifiers,
                    &args.commitments,
                    &ciphertext_hashes,
                    args.balance_slot_asset_ids,
                    args.fee,
                    args.binding_hash,
                    args.stablecoin,
                ),
                proof_binding_hash_matches_key: native_tx_leaf_artifact_binding_hash_matches_key(
                    args.binding_hash,
                    &args.proof,
                ),
                fee_matches: args.fee == action.fee,
            };
            evaluate_native_transfer_payload_admission(input).map_err(|rejection| {
                native_transfer_payload_admission_error(
                    NativeTransferPayloadRoute::Inline,
                    input,
                    rejection,
                )
            })?;
        }
        ACTION_SHIELDED_TRANSFER_SIDECAR => {
            let args: ShieldedTransferSidecarArgs =
                decode_scale_exact(&action.public_args, "shielded sidecar action args")?;
            let input = NativeTransferPayloadAdmissionInput {
                proof_bytes: args.proof.len(),
                max_proof_bytes: NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                anchor_matches: args.anchor == action.anchor,
                commitments_match: args.commitments == action.commitments,
                inline_ciphertext_bytes: 0,
                max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
                ciphertext_hashes_match: args.ciphertext_hashes == action.ciphertext_hashes,
                ciphertext_sizes_match: args.ciphertext_sizes == action.ciphertext_sizes,
                binding_hash_matches: binding_hash_matches(
                    args.anchor,
                    &action.nullifiers,
                    &args.commitments,
                    &args.ciphertext_hashes,
                    args.balance_slot_asset_ids,
                    args.fee,
                    args.binding_hash,
                    args.stablecoin,
                ),
                proof_binding_hash_matches_key: native_tx_leaf_artifact_binding_hash_matches_key(
                    args.binding_hash,
                    &args.proof,
                ),
                fee_matches: args.fee == action.fee,
            };
            evaluate_native_transfer_payload_admission(input).map_err(|rejection| {
                native_transfer_payload_admission_error(
                    NativeTransferPayloadRoute::Sidecar,
                    input,
                    rejection,
                )
            })?;
        }
        _ => unreachable!("transfer action checked above"),
    }

    Ok(())
}

pub(crate) fn validate_candidate_artifact(artifact: &CandidateArtifact) -> Result<()> {
    let input = native_candidate_artifact_admission_input(true, true, true, Some(artifact));
    evaluate_native_candidate_artifact_admission(input)
        .map_err(|rejection| native_candidate_artifact_admission_error(input, rejection))?;
    validate_candidate_artifact_resource_projection(artifact)
}

pub(crate) fn validate_candidate_action_payload(action: &PendingAction) -> Result<()> {
    if !is_candidate_artifact_action(action) {
        return Err(anyhow!("not a candidate artifact action"));
    }
    let route_payload = decode_scale_exact::<SubmitCandidateArtifactArgs>(
        &action.public_args,
        "candidate artifact action args",
    );
    let route_payload_decodes_exactly = route_payload.is_ok();
    let route_payload_matches_artifact = match (
        route_payload.as_ref().ok(),
        action.candidate_artifact.as_ref(),
    ) {
        (Some(args), Some(artifact)) => &args.payload == artifact,
        _ => true,
    };
    let input = native_candidate_artifact_admission_input(
        candidate_action_has_no_state_deltas(action),
        route_payload_decodes_exactly,
        route_payload_matches_artifact,
        action.candidate_artifact.as_ref(),
    );
    evaluate_native_candidate_artifact_admission(input)
        .map_err(|rejection| native_candidate_artifact_admission_error(input, rejection))?;
    validate_candidate_artifact_resource_projection(
        action
            .candidate_artifact
            .as_ref()
            .expect("candidate artifact was accepted as present"),
    )
}

pub(crate) fn candidate_action_has_no_state_deltas(action: &PendingAction) -> bool {
    action.nullifiers.is_empty()
        && action.commitments.is_empty()
        && action.ciphertext_hashes.is_empty()
        && action.ciphertext_sizes.is_empty()
        && action.fee == 0
        && action.anchor == [0u8; 48]
}

pub(crate) fn native_candidate_artifact_admission_input(
    state_deltas_absent: bool,
    route_payload_decodes_exactly: bool,
    route_payload_matches_artifact: bool,
    artifact: Option<&CandidateArtifact>,
) -> NativeCandidateArtifactAdmissionInput {
    let Some(artifact) = artifact else {
        return NativeCandidateArtifactAdmissionInput {
            state_deltas_absent,
            route_payload_decodes_exactly,
            route_payload_matches_artifact,
            artifact_present: false,
            schema_matches: false,
            tx_count: 0,
            max_tx_count: MAX_BATCH_SIZE,
            da_chunk_count: 0,
            proof_mode_recursive_block: false,
            proof_kind_recursive_block_v2: false,
            verifier_profile_matches: false,
            commitment_proof_empty: false,
            receipt_root_absent: false,
            recursive_payload_present: false,
            recursive_proof_bytes: 0,
            max_recursive_proof_bytes: RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
        };
    };
    NativeCandidateArtifactAdmissionInput {
        state_deltas_absent,
        route_payload_decodes_exactly,
        route_payload_matches_artifact,
        artifact_present: true,
        schema_matches: artifact.version == BLOCK_PROOF_BUNDLE_SCHEMA,
        tx_count: artifact.tx_count,
        max_tx_count: MAX_BATCH_SIZE,
        da_chunk_count: artifact.da_chunk_count,
        proof_mode_recursive_block: artifact.proof_mode == BlockProofMode::RecursiveBlock,
        proof_kind_recursive_block_v2: artifact.proof_kind
            == PoolProofArtifactKind::RecursiveBlockV2,
        verifier_profile_matches: artifact.verifier_profile
            == consensus::proof::recursive_block_artifact_verifier_profile(),
        commitment_proof_empty: artifact.commitment_proof.data.is_empty(),
        receipt_root_absent: artifact.receipt_root.is_none(),
        recursive_payload_present: artifact.recursive_block.is_some(),
        recursive_proof_bytes: artifact
            .recursive_block
            .as_ref()
            .map_or(0, |recursive| recursive.proof.data.len()),
        max_recursive_proof_bytes: RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
    }
}

pub(crate) fn native_candidate_artifact_resource_projection_input(
    artifact: &CandidateArtifact,
) -> NativeCandidateArtifactResourceProjectionInput {
    let proof_bytes = artifact.commitment_proof.data.len();
    let receipt_bytes = artifact
        .receipt_root
        .as_ref()
        .map_or(0, |receipt| receipt.encoded_size());
    let recursive_bytes = artifact
        .recursive_block
        .as_ref()
        .map_or(0, |recursive| recursive.proof.data.len());
    let variable_bytes = proof_bytes
        .saturating_add(receipt_bytes)
        .saturating_add(recursive_bytes);
    let declared_bytes = artifact.encoded_size().saturating_sub(variable_bytes);
    NativeCandidateArtifactResourceProjectionInput {
        raw_byte_cap: MAX_NATIVE_RPC_ACTION_BYTES,
        decoded_byte_cap: MAX_NATIVE_RPC_ACTION_BYTES,
        item_count_cap: MAX_BATCH_SIZE as usize,
        item_byte_cap: RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
        aggregate_byte_cap: RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
        work_unit_cap: usize::MAX,
        declared_bytes,
        proof_bytes,
        receipt_bytes,
        recursive_bytes,
        tx_count: artifact.tx_count as usize,
        da_chunk_count: artifact.da_chunk_count as usize,
    }
}

pub(crate) fn native_candidate_artifact_resource_bounded_request(
    input: NativeCandidateArtifactResourceProjectionInput,
) -> NativeBoundedRequestAdmissionInput {
    let aggregate_bytes = input
        .proof_bytes
        .saturating_add(input.receipt_bytes)
        .saturating_add(input.recursive_bytes);
    NativeBoundedRequestAdmissionInput {
        raw_byte_cap: input.raw_byte_cap,
        decoded_byte_cap: input.decoded_byte_cap,
        item_count_cap: input.item_count_cap,
        item_byte_cap: input.item_byte_cap,
        aggregate_byte_cap: input.aggregate_byte_cap,
        work_unit_cap: input.work_unit_cap,
        raw_bytes: input.declared_bytes,
        decoded_bytes: input.declared_bytes.saturating_add(aggregate_bytes),
        item_count: input.tx_count,
        max_item_bytes: input
            .proof_bytes
            .max(input.receipt_bytes)
            .max(input.recursive_bytes),
        aggregate_bytes,
        work_units: input.da_chunk_count,
    }
}

pub(crate) fn validate_candidate_artifact_resource_projection(
    artifact: &CandidateArtifact,
) -> Result<()> {
    let input = native_candidate_artifact_resource_projection_input(artifact);
    let bounded = native_candidate_artifact_resource_bounded_request(input);
    evaluate_native_bounded_request_admission(bounded)
        .map_err(|rejection| native_candidate_artifact_resource_admission_error(bounded, rejection))
}

pub(crate) fn evaluate_native_candidate_artifact_admission(
    input: NativeCandidateArtifactAdmissionInput,
) -> Result<(), NativeCandidateArtifactAdmissionRejection> {
    if !input.state_deltas_absent {
        Err(NativeCandidateArtifactAdmissionRejection::StateDeltasPresent)
    } else if !input.route_payload_decodes_exactly {
        Err(NativeCandidateArtifactAdmissionRejection::RoutePayloadDecodeFailed)
    } else if !input.route_payload_matches_artifact {
        Err(NativeCandidateArtifactAdmissionRejection::RoutePayloadArtifactMismatch)
    } else if !input.artifact_present {
        Err(NativeCandidateArtifactAdmissionRejection::ArtifactMissing)
    } else if !input.schema_matches {
        Err(NativeCandidateArtifactAdmissionRejection::SchemaMismatch)
    } else if input.tx_count == 0 {
        Err(NativeCandidateArtifactAdmissionRejection::TxCountZero)
    } else if input.tx_count > input.max_tx_count {
        Err(NativeCandidateArtifactAdmissionRejection::TxCountTooLarge)
    } else if input.da_chunk_count == 0 {
        Err(NativeCandidateArtifactAdmissionRejection::DaChunkCountZero)
    } else if !input.proof_mode_recursive_block {
        Err(NativeCandidateArtifactAdmissionRejection::WrongProofMode)
    } else if !input.proof_kind_recursive_block_v2 {
        Err(NativeCandidateArtifactAdmissionRejection::WrongProofKind)
    } else if !input.verifier_profile_matches {
        Err(NativeCandidateArtifactAdmissionRejection::VerifierProfileMismatch)
    } else if !input.commitment_proof_empty {
        Err(NativeCandidateArtifactAdmissionRejection::CommitmentProofPresent)
    } else if !input.receipt_root_absent {
        Err(NativeCandidateArtifactAdmissionRejection::ReceiptRootPresent)
    } else if !input.recursive_payload_present {
        Err(NativeCandidateArtifactAdmissionRejection::RecursivePayloadMissing)
    } else if input.recursive_proof_bytes == 0 {
        Err(NativeCandidateArtifactAdmissionRejection::RecursiveProofEmpty)
    } else if input.recursive_proof_bytes > input.max_recursive_proof_bytes {
        Err(NativeCandidateArtifactAdmissionRejection::RecursiveProofTooLarge)
    } else {
        Ok(())
    }
}

pub(crate) fn native_candidate_artifact_resource_admission_error(
    input: NativeBoundedRequestAdmissionInput,
    rejection: NativeBoundedRequestAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeBoundedRequestAdmissionRejection::RawBytes => anyhow!(
            "candidate artifact declared byte count {} exceeds cap {}",
            input.raw_bytes,
            input.raw_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::DecodedBytes => anyhow!(
            "candidate artifact decoded byte count {} exceeds cap {}",
            input.decoded_bytes,
            input.decoded_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::ItemCount => anyhow!(
            "candidate artifact tx_count {} exceeds bounded request cap {}",
            input.item_count,
            input.item_count_cap
        ),
        NativeBoundedRequestAdmissionRejection::ItemBytes => anyhow!(
            "candidate artifact proof-like item byte count {} exceeds cap {}",
            input.max_item_bytes,
            input.item_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::AggregateBytes => anyhow!(
            "candidate artifact aggregate proof-like byte count {} exceeds cap {}",
            input.aggregate_bytes,
            input.aggregate_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::WorkUnits => anyhow!(
            "candidate artifact DA chunk count {} exceeds bounded request work cap {}",
            input.work_units,
            input.work_unit_cap
        ),
    }
}

pub(crate) fn native_candidate_artifact_admission_error(
    input: NativeCandidateArtifactAdmissionInput,
    rejection: NativeCandidateArtifactAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeCandidateArtifactAdmissionRejection::StateDeltasPresent => {
            anyhow!("candidate artifact actions must not carry shielded state deltas")
        }
        NativeCandidateArtifactAdmissionRejection::RoutePayloadDecodeFailed => {
            anyhow!("candidate artifact action args must decode exactly")
        }
        NativeCandidateArtifactAdmissionRejection::RoutePayloadArtifactMismatch => {
            anyhow!("candidate artifact action args do not match candidate artifact payload")
        }
        NativeCandidateArtifactAdmissionRejection::ArtifactMissing => {
            anyhow!("candidate artifact action missing payload")
        }
        NativeCandidateArtifactAdmissionRejection::SchemaMismatch => {
            anyhow!("candidate artifact schema mismatch")
        }
        NativeCandidateArtifactAdmissionRejection::TxCountZero => {
            anyhow!("candidate artifact tx_count must be non-zero")
        }
        NativeCandidateArtifactAdmissionRejection::TxCountTooLarge => anyhow!(
            "candidate artifact tx_count {} exceeds max {}",
            input.tx_count,
            input.max_tx_count
        ),
        NativeCandidateArtifactAdmissionRejection::DaChunkCountZero => {
            anyhow!("candidate artifact must declare DA chunks")
        }
        NativeCandidateArtifactAdmissionRejection::WrongProofMode => {
            anyhow!("native cutover requires recursive block artifacts")
        }
        NativeCandidateArtifactAdmissionRejection::WrongProofKind => {
            anyhow!("native candidate artifact must use the shipped recursive_block_v2 route")
        }
        NativeCandidateArtifactAdmissionRejection::VerifierProfileMismatch => {
            anyhow!("native candidate artifact recursive_block_v2 verifier profile mismatch")
        }
        NativeCandidateArtifactAdmissionRejection::CommitmentProofPresent => {
            anyhow!("recursive candidate artifact must not carry commitment proof bytes")
        }
        NativeCandidateArtifactAdmissionRejection::ReceiptRootPresent => {
            anyhow!("recursive candidate artifact must not carry receipt-root payload")
        }
        NativeCandidateArtifactAdmissionRejection::RecursivePayloadMissing => {
            anyhow!("candidate artifact missing recursive proof payload")
        }
        NativeCandidateArtifactAdmissionRejection::RecursiveProofEmpty => {
            anyhow!("candidate artifact recursive proof is empty")
        }
        NativeCandidateArtifactAdmissionRejection::RecursiveProofTooLarge => anyhow!(
            "candidate artifact recursive proof size {} exceeds {}",
            input.recursive_proof_bytes,
            input.max_recursive_proof_bytes
        ),
    }
}

pub(crate) fn coinbase_ciphertext_metadata(
    note: &protocol_shielded_pool::types::EncryptedNote,
) -> (usize, Option<([u8; 48], u32)>) {
    let total_len = note
        .ciphertext
        .len()
        .saturating_add(note.kem_ciphertext.len());
    if total_len > MAX_CIPHERTEXT_BYTES {
        return (total_len, None);
    }
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(&note.ciphertext);
    bytes.extend_from_slice(&note.kem_ciphertext);
    (
        total_len,
        Some((
            ciphertext_hash_bytes(&bytes),
            u32::try_from(total_len).unwrap_or(u32::MAX),
        )),
    )
}

pub(crate) fn coinbase_recipient_address_bytes(
    address: &ShieldedAddress,
) -> [u8; DIVERSIFIED_ADDRESS_SIZE] {
    let mut out = [0u8; DIVERSIFIED_ADDRESS_SIZE];
    out[0] = address.version;
    out[1..5].copy_from_slice(&address.diversifier_index.to_le_bytes());
    out[5..37].copy_from_slice(&address.pk_recipient);
    out[37..69].copy_from_slice(&address.pk_auth);
    out
}

pub(crate) fn coinbase_note_data_commitment(note: &CoinbaseNoteData) -> [u8; 48] {
    let mut pk_recipient = [0u8; 32];
    pk_recipient.copy_from_slice(&note.recipient_address[5..37]);
    let mut pk_auth = [0u8; 32];
    pk_auth.copy_from_slice(&note.recipient_address[37..69]);
    let note_plaintext = NotePlaintext::coinbase(note.amount, &note.public_seed);
    felts_to_bytes48(
        &note_plaintext
            .to_note_data(pk_recipient, pk_auth)
            .commitment(),
    )
}

pub(crate) fn coinbase_note_commitment_matches(
    action_commitment: &[u8; 48],
    note: &CoinbaseNoteData,
) -> bool {
    *action_commitment == note.commitment && note.commitment == coinbase_note_data_commitment(note)
}

pub(crate) fn evaluate_native_coinbase_action_payload_admission(
    input: NativeCoinbaseActionPayloadAdmissionInput,
) -> Result<(), NativeCoinbaseActionPayloadAdmissionRejection> {
    if !input.amount_nonzero {
        Err(NativeCoinbaseActionPayloadAdmissionRejection::AmountZero)
    } else if !input.commitment_matches {
        Err(NativeCoinbaseActionPayloadAdmissionRejection::CommitmentMismatch)
    } else if !input.commitment_nonzero {
        Err(NativeCoinbaseActionPayloadAdmissionRejection::CommitmentZero)
    } else if input.ciphertext_bytes > input.max_ciphertext_bytes {
        Err(NativeCoinbaseActionPayloadAdmissionRejection::CiphertextTooLarge)
    } else if !input.ciphertext_hash_matches {
        Err(NativeCoinbaseActionPayloadAdmissionRejection::CiphertextHashMismatch)
    } else if !input.ciphertext_size_matches {
        Err(NativeCoinbaseActionPayloadAdmissionRejection::CiphertextSizeMismatch)
    } else {
        Ok(())
    }
}

pub(crate) fn native_coinbase_action_payload_admission_error(
    input: NativeCoinbaseActionPayloadAdmissionInput,
    rejection: NativeCoinbaseActionPayloadAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeCoinbaseActionPayloadAdmissionRejection::AmountZero => {
            anyhow!("coinbase amount must be non-zero")
        }
        NativeCoinbaseActionPayloadAdmissionRejection::CommitmentMismatch => {
            anyhow!("coinbase commitment mismatch")
        }
        NativeCoinbaseActionPayloadAdmissionRejection::CommitmentZero => {
            anyhow!("zero coinbase commitment rejected")
        }
        NativeCoinbaseActionPayloadAdmissionRejection::CiphertextTooLarge => anyhow!(
            "coinbase ciphertext size {} exceeds limit {}",
            input.ciphertext_bytes,
            input.max_ciphertext_bytes
        ),
        NativeCoinbaseActionPayloadAdmissionRejection::CiphertextHashMismatch => {
            anyhow!("coinbase ciphertext hash mismatch")
        }
        NativeCoinbaseActionPayloadAdmissionRejection::CiphertextSizeMismatch => {
            anyhow!("coinbase ciphertext size mismatch")
        }
    }
}

pub(crate) fn validate_coinbase_action_payload(action: &PendingAction) -> Result<()> {
    if !is_coinbase_action(action) {
        return Err(anyhow!("not a coinbase action"));
    }
    if !action.nullifiers.is_empty()
        || action.commitments.len() != 1
        || action.ciphertext_hashes.len() != 1
        || action.ciphertext_sizes.len() != 1
        || action.fee != 0
        || action.anchor != [0u8; 48]
        || action.candidate_artifact.is_some()
    {
        return Err(anyhow!(
            "coinbase action must contain exactly one output and no other state deltas"
        ));
    }
    let args: MintCoinbaseArgs = decode_scale_exact(&action.public_args, "coinbase action args")?;
    let note = &args.reward_bundle.miner_note.encrypted_note;
    let (ciphertext_bytes, ciphertext_metadata) = coinbase_ciphertext_metadata(note);
    let commitment_matches = action.commitments.first().is_some_and(|commitment| {
        coinbase_note_commitment_matches(commitment, &args.reward_bundle.miner_note)
    });
    let input = NativeCoinbaseActionPayloadAdmissionInput {
        amount_nonzero: args.reward_bundle.miner_note.amount != 0,
        commitment_matches,
        commitment_nonzero: action
            .commitments
            .first()
            .is_some_and(|commitment| *commitment != [0u8; 48]),
        ciphertext_bytes,
        max_ciphertext_bytes: MAX_CIPHERTEXT_BYTES,
        ciphertext_hash_matches: ciphertext_metadata
            .as_ref()
            .is_some_and(|(hash, _)| action.ciphertext_hashes.first() == Some(hash)),
        ciphertext_size_matches: ciphertext_metadata
            .as_ref()
            .is_some_and(|(_, size)| action.ciphertext_sizes.first() == Some(size)),
    };
    evaluate_native_coinbase_action_payload_admission(input)
        .map_err(|rejection| native_coinbase_action_payload_admission_error(input, rejection))
}

pub(crate) fn pending_action_hash(action: &PendingAction) -> [u8; 32] {
    let mut canonical = action.clone();
    canonical.tx_hash = [0u8; 32];
    let encoded = canonical.encode();
    hash32_with_parts(&[b"hegemon-native-action-v1", &encoded])
}

pub(crate) fn pending_action_semantic_hash(action: &PendingAction) -> [u8; 32] {
    let mut canonical = action.clone();
    canonical.tx_hash = [0u8; 32];
    canonical.received_ms = 0;
    let encoded = canonical.encode();
    hash32_with_parts(&[b"hegemon-native-action-semantic-v1", &encoded])
}

pub(crate) fn pending_action_semantic_duplicate_exists(
    actions: &BTreeMap<[u8; 32], PendingAction>,
    candidate: &PendingAction,
) -> bool {
    let candidate_hash = pending_action_semantic_hash(candidate);
    actions
        .values()
        .any(|action| pending_action_semantic_hash(action) == candidate_hash)
}

pub(crate) fn pending_action_mempool_bytes(action: &PendingAction) -> usize {
    action.encoded_size()
}

pub(crate) fn pending_mempool_bytes(actions: &BTreeMap<[u8; 32], PendingAction>) -> usize {
    actions.values().fold(0usize, |acc, action| {
        acc.saturating_add(pending_action_mempool_bytes(action))
    })
}

pub(crate) fn validate_mempool_byte_budget(
    actions: &BTreeMap<[u8; 32], PendingAction>,
    candidate: &PendingAction,
    max_bytes: usize,
) -> Result<()> {
    let input = NativeMempoolByteBudgetAdmissionInput {
        pending_bytes: pending_mempool_bytes(actions),
        candidate_bytes: pending_action_mempool_bytes(candidate),
        max_bytes,
    };
    evaluate_native_mempool_byte_budget_admission(input).map_err(|rejection| {
        native_resource_budget_admission_error(
            input.pending_bytes,
            input.candidate_bytes,
            input.max_bytes,
            rejection,
        )
    })?;
    Ok(())
}

pub(crate) fn staged_proof_bytes(proofs: &BTreeMap<String, Vec<u8>>) -> usize {
    proofs
        .values()
        .fold(0usize, |acc, proof| acc.saturating_add(proof.len()))
}

pub(crate) fn validate_staged_proof_byte_budget(
    staged: &BTreeMap<String, Vec<u8>>,
    binding_hash_key: &str,
    proof_len: usize,
    max_bytes: usize,
) -> Result<()> {
    let input = NativeStagedProofByteBudgetAdmissionInput {
        staged_bytes: staged_proof_bytes(staged),
        existing_bytes: staged
            .get(binding_hash_key)
            .map(Vec::len)
            .unwrap_or_default(),
        proof_bytes: proof_len,
        max_bytes,
    };
    evaluate_native_staged_proof_byte_budget_admission(input).map_err(|rejection| {
        native_resource_budget_admission_error(
            input.staged_bytes.saturating_sub(input.existing_bytes),
            input.proof_bytes,
            input.max_bytes,
            rejection,
        )
    })?;
    Ok(())
}

pub(crate) fn evaluate_native_mempool_byte_budget_admission(
    input: NativeMempoolByteBudgetAdmissionInput,
) -> Result<usize, NativeResourceBudgetAdmissionRejection> {
    let total = input.pending_bytes.saturating_add(input.candidate_bytes);
    if total > input.max_bytes {
        Err(NativeResourceBudgetAdmissionRejection::MempoolByteBudgetExceeded)
    } else {
        Ok(total)
    }
}

pub(crate) fn evaluate_native_staged_proof_byte_budget_admission(
    input: NativeStagedProofByteBudgetAdmissionInput,
) -> Result<usize, NativeResourceBudgetAdmissionRejection> {
    let total = input
        .staged_bytes
        .saturating_sub(input.existing_bytes)
        .saturating_add(input.proof_bytes);
    if total > input.max_bytes {
        Err(NativeResourceBudgetAdmissionRejection::StagedProofByteBudgetExceeded)
    } else {
        Ok(total)
    }
}

pub(crate) fn evaluate_native_bounded_request_admission(
    input: NativeBoundedRequestAdmissionInput,
) -> Result<(), NativeBoundedRequestAdmissionRejection> {
    if input.raw_bytes > input.raw_byte_cap {
        Err(NativeBoundedRequestAdmissionRejection::RawBytes)
    } else if input.decoded_bytes > input.decoded_byte_cap {
        Err(NativeBoundedRequestAdmissionRejection::DecodedBytes)
    } else if input.item_count > input.item_count_cap {
        Err(NativeBoundedRequestAdmissionRejection::ItemCount)
    } else if input.max_item_bytes > input.item_byte_cap {
        Err(NativeBoundedRequestAdmissionRejection::ItemBytes)
    } else if input.aggregate_bytes > input.aggregate_byte_cap {
        Err(NativeBoundedRequestAdmissionRejection::AggregateBytes)
    } else if input.work_units > input.work_unit_cap {
        Err(NativeBoundedRequestAdmissionRejection::WorkUnits)
    } else {
        Ok(())
    }
}

pub(crate) fn native_resource_budget_admission_error(
    current_bytes: usize,
    candidate_bytes: usize,
    max_bytes: usize,
    rejection: NativeResourceBudgetAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeResourceBudgetAdmissionRejection::MempoolByteBudgetExceeded => anyhow!(
            "native mempool byte budget exceeded: {} + {} > {}",
            current_bytes,
            candidate_bytes,
            max_bytes
        ),
        NativeResourceBudgetAdmissionRejection::StagedProofByteBudgetExceeded => anyhow!(
            "staged proof byte budget exceeded: {} + {} > {}",
            current_bytes,
            candidate_bytes,
            max_bytes
        ),
    }
}

pub(crate) fn native_sync_response_range(
    input: NativeSyncResponseRangeInput,
) -> Option<NativeSyncRange> {
    if input.max_blocks == 0 {
        return None;
    }
    let capped_to = input
        .to_height
        .min(input.best_height)
        .min(input.from_height.saturating_add(input.max_blocks - 1));
    (input.from_height <= capped_to).then_some(NativeSyncRange {
        from_height: input.from_height,
        to_height: capped_to,
    })
}

pub(crate) fn evaluate_native_sync_request_rate_admission(
    input: NativeSyncRequestRateAdmissionInput,
) -> Result<(), NativeSyncAdmissionRejection> {
    if input.max_requests == 0 {
        return Err(NativeSyncAdmissionRejection::RequestRateLimited);
    }
    if input.window_elapsed_ms >= input.window_ms {
        return Ok(());
    }
    if input.requests_in_window < input.max_requests {
        Ok(())
    } else {
        Err(NativeSyncAdmissionRejection::RequestRateLimited)
    }
}

pub(crate) fn native_sync_missing_request_range(
    input: NativeSyncMissingRequestInput,
) -> Option<NativeSyncRange> {
    if input.max_blocks == 0 || input.announced_height <= input.best_height {
        return None;
    }
    let from_height = if input.best_height > 0 && input.best_height < input.max_blocks {
        NATIVE_SYNC_BOOTSTRAP_BACKFILL_FLOOR
    } else {
        input.best_height.saturating_add(1)
    };
    let cap_end = input
        .max_blocks
        .saturating_sub(1)
        .saturating_add(from_height)
        .max(from_height);
    Some(NativeSyncRange {
        from_height,
        to_height: input.announced_height.min(cap_end),
    })
}

#[cfg(test)]
pub(crate) fn native_sync_missing_request_range_with_reorg_backfill(
    input: NativeSyncMissingRequestInput,
    backfill_blocks: u64,
) -> Option<NativeSyncRange> {
    let range = native_sync_missing_request_range(input)?;
    Some(native_sync_missing_request_range_apply_reorg_backfill(
        input,
        range,
        backfill_blocks,
    ))
}

pub(crate) fn native_sync_observed_tip_request_range(
    best_height: u64,
    best_hash: [u8; 32],
    announced_height: u64,
    announced_hash: Option<[u8; 32]>,
    max_blocks: u64,
    backfill_blocks: u64,
) -> Option<NativeSyncRange> {
    let input = NativeSyncMissingRequestInput {
        best_height,
        announced_height,
        max_blocks,
    };
    let admitted_missing_range = native_sync_missing_request_range(input);
    native_sync_observed_tip_request_range_from_admitted_missing(
        input,
        best_hash,
        announced_hash,
        backfill_blocks,
        admitted_missing_range,
    )
}

pub(crate) fn native_sync_observed_tip_request_range_from_admitted_missing(
    input: NativeSyncMissingRequestInput,
    best_hash: [u8; 32],
    announced_hash: Option<[u8; 32]>,
    backfill_blocks: u64,
    admitted_missing_range: Option<NativeSyncRange>,
) -> Option<NativeSyncRange> {
    if let Some(admitted_range) = admitted_missing_range {
        let gap = input.announced_height.saturating_sub(input.best_height);
        if gap > input.max_blocks && backfill_blocks <= NATIVE_SYNC_REORG_BACKFILL_BLOCKS {
            return Some(admitted_range);
        }
        return Some(native_sync_missing_request_range_apply_reorg_backfill(
            input,
            admitted_range,
            backfill_blocks,
        ));
    }

    if input.announced_height == 0
        || input.announced_height != input.best_height
        || announced_hash.is_none_or(|hash| hash == best_hash)
        || input.max_blocks == 0
    {
        return None;
    }

    let from_height = input
        .announced_height
        .saturating_sub(backfill_blocks)
        .saturating_add(1);
    Some(NativeSyncRange {
        from_height,
        to_height: input
            .announced_height
            .min(from_height.saturating_add(input.max_blocks - 1)),
    })
}

pub(crate) fn native_sync_missing_request_range_apply_reorg_backfill(
    input: NativeSyncMissingRequestInput,
    range: NativeSyncRange,
    backfill_blocks: u64,
) -> NativeSyncRange {
    let gap = input.announced_height.saturating_sub(input.best_height);
    if gap == 0 || backfill_blocks == 0 || input.max_blocks <= backfill_blocks {
        return range;
    }

    let from_height = input
        .best_height
        .saturating_sub(backfill_blocks)
        .saturating_add(1)
        .min(range.from_height);
    let to_height = input
        .announced_height
        .min(from_height.saturating_add(input.max_blocks - 1));
    NativeSyncRange {
        from_height,
        to_height,
    }
}

pub(crate) fn native_sync_block_range_publication_rows(
    blocks: Vec<NativeBlockMeta>,
) -> Vec<NativeBlockMeta> {
    blocks
}

pub(crate) fn evaluate_native_sync_block_range_publication_admission(
    input: NativeSyncBlockRangePublicationAdmissionInput,
) -> Result<(), NativeSyncBlockRangePublicationAdmissionRejection> {
    if !input.range_admitted {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::RangeNotAdmitted)
    } else if !input.served_count_matches_range {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::ServedCountMismatch)
    } else if !input.first_height_matches_range {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::FirstHeightMismatch)
    } else if !input.last_height_matches_range {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::LastHeightMismatch)
    } else if !input.served_heights_contiguous {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::HeightContinuityMismatch)
    } else if !input.previous_parent_anchor_verified || !input.parent_hashes_contiguous {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::ParentHashMismatch)
    } else if !input.canonical_rows_verified {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::CanonicalRowsUnverified)
    } else if !input.action_bodies_verified {
        Err(NativeSyncBlockRangePublicationAdmissionRejection::ActionBodiesUnverified)
    } else {
        Ok(())
    }
}

pub(crate) fn native_sync_block_range_publication_admission_input(
    range: NativeSyncRange,
    blocks: &[NativeBlockMeta],
    canonical_rows_verified: usize,
    action_bodies_verified: usize,
    previous_parent_anchor_verified: bool,
) -> NativeSyncBlockRangePublicationAdmissionInput {
    let expected_count = range
        .to_height
        .checked_sub(range.from_height)
        .and_then(|delta| delta.checked_add(1))
        .and_then(|count| usize::try_from(count).ok());
    let served_count_matches_range = expected_count == Some(blocks.len());
    let first_height_matches_range = blocks
        .first()
        .map(|meta| meta.height == range.from_height)
        .unwrap_or(false);
    let last_height_matches_range = blocks
        .last()
        .map(|meta| meta.height == range.to_height)
        .unwrap_or(false);
    let served_heights_contiguous = blocks.windows(2).all(|window| {
        window[0]
            .height
            .checked_add(1)
            .map(|expected| window[1].height == expected)
            .unwrap_or(false)
    });
    let parent_hashes_contiguous = blocks
        .windows(2)
        .all(|window| window[1].parent_hash == window[0].hash);
    let expected_action_body_rows = blocks.iter().filter(|meta| meta.height != 0).count();

    NativeSyncBlockRangePublicationAdmissionInput {
        range_admitted: true,
        served_count_matches_range,
        first_height_matches_range,
        last_height_matches_range,
        served_heights_contiguous,
        previous_parent_anchor_verified,
        parent_hashes_contiguous,
        canonical_rows_verified: canonical_rows_verified == blocks.len(),
        action_bodies_verified: action_bodies_verified == expected_action_body_rows,
    }
}

pub(crate) fn evaluate_native_sync_response_count_admission(
    input: NativeSyncResponseCountAdmissionInput,
) -> Result<(), NativeSyncAdmissionRejection> {
    let bounded = native_sync_response_count_bounded_request(input);
    evaluate_native_bounded_request_admission(bounded)
        .map_err(|_| NativeSyncAdmissionRejection::ResponseBlockCountTooLarge)
}

pub(crate) fn native_sync_response_count_bounded_request(
    input: NativeSyncResponseCountAdmissionInput,
) -> NativeBoundedRequestAdmissionInput {
    NativeBoundedRequestAdmissionInput {
        raw_byte_cap: usize::MAX,
        decoded_byte_cap: usize::MAX,
        item_count_cap: input.max_blocks,
        item_byte_cap: usize::MAX,
        aggregate_byte_cap: usize::MAX,
        work_unit_cap: usize::MAX,
        raw_bytes: 0,
        decoded_bytes: 0,
        item_count: input.block_count,
        max_item_bytes: 0,
        aggregate_bytes: 0,
        work_units: 0,
    }
}

pub(crate) fn admit_and_sort_native_sync_response_blocks(
    blocks: &mut [NativeBlockMeta],
    max_blocks: usize,
) -> Result<(), NativeSyncAdmissionRejection> {
    evaluate_native_sync_response_count_admission(NativeSyncResponseCountAdmissionInput {
        block_count: blocks.len(),
        max_blocks,
    })?;
    blocks.sort_by_key(|meta| meta.height);
    Ok(())
}

#[cfg(test)]
pub(crate) fn native_sync_response_import_progress<I>(
    response_block_count: usize,
    outcomes: I,
) -> NativeSyncResponseImportProgress
where
    I: IntoIterator<Item = NativeSyncResponseImportOutcome>,
{
    let mut progress = NativeSyncResponseImportProgress::new(response_block_count);
    for outcome in outcomes {
        if !progress.record(outcome) {
            break;
        }
    }
    progress
}

pub(crate) fn evaluate_native_ciphertext_sidecar_request_admission(
    input: NativeSidecarRequestCountAdmissionInput,
) -> Result<(), NativeSidecarUploadAdmissionRejection> {
    if input.item_count > input.max_items {
        Err(NativeSidecarUploadAdmissionRejection::TooManyCiphertexts)
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate_native_proof_sidecar_request_admission(
    input: NativeSidecarRequestCountAdmissionInput,
) -> Result<(), NativeSidecarUploadAdmissionRejection> {
    if input.item_count > input.max_items {
        Err(NativeSidecarUploadAdmissionRejection::TooManyProofs)
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate_native_ciphertext_sidecar_capacity_admission(
    input: NativeSidecarCapacityAdmissionInput,
) -> Result<(), NativeSidecarUploadAdmissionRejection> {
    if !input.replaces_existing && input.staged_count >= input.max_staged_count {
        Err(NativeSidecarUploadAdmissionRejection::StagedCiphertextCapacityReached)
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate_native_proof_sidecar_capacity_admission(
    input: NativeSidecarCapacityAdmissionInput,
) -> Result<(), NativeSidecarUploadAdmissionRejection> {
    if !input.replaces_existing && input.staged_count >= input.max_staged_count {
        Err(NativeSidecarUploadAdmissionRejection::StagedProofCapacityReached)
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate_native_proof_sidecar_metadata_admission(
    input: NativeProofSidecarMetadataAdmissionInput,
) -> Result<(), NativeSidecarUploadAdmissionRejection> {
    if !input.binding_hash_present {
        Err(NativeSidecarUploadAdmissionRejection::ProofBindingHashMissing)
    } else if !input.binding_hash_valid {
        Err(NativeSidecarUploadAdmissionRejection::InvalidBindingHash)
    } else if !input.proof_present {
        Err(NativeSidecarUploadAdmissionRejection::ProofMissing)
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate_native_proof_sidecar_decoded_admission(
    input: NativeProofSidecarDecodedAdmissionInput,
) -> Result<(), NativeSidecarUploadAdmissionRejection> {
    if input.proof_bytes == 0 {
        Err(NativeSidecarUploadAdmissionRejection::ProofEmpty)
    } else if input.proof_bytes > input.max_proof_bytes {
        Err(NativeSidecarUploadAdmissionRejection::ProofTooLarge)
    } else if !input.proof_binding_hash_matches_key {
        Err(NativeSidecarUploadAdmissionRejection::ProofBindingHashMismatch)
    } else {
        Ok(())
    }
}

pub(crate) fn native_sidecar_upload_admission_error(
    rejection: NativeSidecarUploadAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeSidecarUploadAdmissionRejection::TooManyCiphertexts => anyhow!(
            "too many ciphertexts in one request: exceeds {}",
            MAX_NATIVE_DA_CIPHERTEXT_UPLOADS
        ),
        NativeSidecarUploadAdmissionRejection::TooManyProofs => anyhow!(
            "too many proofs in one request: exceeds {}",
            MAX_NATIVE_DA_PROOF_UPLOADS
        ),
        NativeSidecarUploadAdmissionRejection::StagedCiphertextCapacityReached => anyhow!(
            "staged ciphertext capacity reached: {}",
            MAX_NATIVE_STAGED_CIPHERTEXTS
        ),
        NativeSidecarUploadAdmissionRejection::StagedProofCapacityReached => {
            anyhow!(
                "staged proof capacity reached: {}",
                MAX_NATIVE_STAGED_PROOFS
            )
        }
        NativeSidecarUploadAdmissionRejection::ProofBindingHashMissing => {
            anyhow!("proof item missing binding_hash")
        }
        NativeSidecarUploadAdmissionRejection::InvalidBindingHash => {
            anyhow!("invalid binding_hash hex")
        }
        NativeSidecarUploadAdmissionRejection::ProofMissing => {
            anyhow!("proof item missing proof")
        }
        NativeSidecarUploadAdmissionRejection::ProofEmpty => {
            anyhow!("proof item proof must be non-empty")
        }
        NativeSidecarUploadAdmissionRejection::ProofTooLarge => anyhow!(
            "proof size exceeds native tx-leaf artifact limit {}",
            NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE
        ),
        NativeSidecarUploadAdmissionRejection::ProofBindingHashMismatch => {
            anyhow!("proof binding hash does not match native tx-leaf public fields")
        }
    }
}

pub(crate) fn ordered_pending_actions(state: &NativeState) -> Vec<PendingAction> {
    let mut actions = state.pending_actions.values().cloned().collect::<Vec<_>>();
    actions.sort_by_key(action_order_key);
    actions
}

pub(crate) fn select_mineable_actions(state: &NativeState) -> Vec<PendingAction> {
    let actions = ordered_pending_actions(state);
    let transfer_count = actions
        .iter()
        .filter(|action| is_shielded_transfer_action(action))
        .filter(|action| {
            let input = native_mineable_action_admission_input(state, action, None);
            evaluate_native_mineable_action_admission(input).is_ok()
        })
        .count();
    let selected_candidate_hash = if transfer_count == 0 {
        None
    } else {
        actions
            .iter()
            .find(|action| {
                is_candidate_artifact_action(action)
                    && action
                        .candidate_artifact
                        .as_ref()
                        .is_some_and(|artifact| artifact.tx_count as usize == transfer_count)
            })
            .map(|action| action.tx_hash)
    };
    actions
        .into_iter()
        .filter(|action| {
            let input =
                native_mineable_action_admission_input(state, action, selected_candidate_hash);
            evaluate_native_mineable_action_admission(input).is_ok()
        })
        .collect()
}

pub(crate) fn prepared_mining_actions_match_state(
    state: &NativeState,
    actions: &[PendingAction],
) -> bool {
    actions
        .iter()
        .filter(|action| !is_coinbase_action(action) && !is_candidate_artifact_action(action))
        .all(|action| {
            state
                .pending_actions
                .get(&action.tx_hash)
                .is_some_and(|pending| pending.encode() == action.encode())
        })
}

pub(crate) fn native_mineable_action_admission_input(
    state: &NativeState,
    action: &PendingAction,
    selected_candidate_hash: Option<[u8; 32]>,
) -> NativeMineableActionAdmissionInput {
    let candidate_artifact_route = is_candidate_artifact_action(action);
    let candidate_artifact_selected =
        selected_candidate_hash.is_some_and(|hash| hash == action.tx_hash);
    let sidecar_transfer_route = action.family_id == FAMILY_SHIELDED_POOL
        && action.action_id == ACTION_SHIELDED_TRANSFER_SIDECAR;
    let (
        sidecar_ciphertexts_available,
        sidecar_ciphertext_sizes_present,
        sidecar_ciphertext_sizes_match,
    ) = if sidecar_transfer_route {
        sidecar_ciphertext_state_for_action(state, action)
    } else {
        (true, true, true)
    };
    NativeMineableActionAdmissionInput {
        candidate_artifact_route,
        candidate_artifact_selected,
        sidecar_transfer_route,
        sidecar_ciphertexts_available,
        sidecar_ciphertext_sizes_present,
        sidecar_ciphertext_sizes_match,
    }
}

pub(crate) fn evaluate_native_mineable_action_admission(
    input: NativeMineableActionAdmissionInput,
) -> Result<(), NativeMineableActionAdmissionRejection> {
    if input.candidate_artifact_route {
        if input.candidate_artifact_selected {
            Ok(())
        } else {
            Err(NativeMineableActionAdmissionRejection::UnselectedCandidateArtifact)
        }
    } else if input.sidecar_transfer_route {
        if !input.sidecar_ciphertexts_available {
            Err(NativeMineableActionAdmissionRejection::SidecarCiphertextMissing)
        } else if !input.sidecar_ciphertext_sizes_present {
            Err(NativeMineableActionAdmissionRejection::SidecarCiphertextSizeMissing)
        } else if !input.sidecar_ciphertext_sizes_match {
            Err(NativeMineableActionAdmissionRejection::SidecarCiphertextSizeMismatch)
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}

pub(crate) fn is_transfer_action(action_id: u16) -> bool {
    matches!(
        action_id,
        ACTION_SHIELDED_TRANSFER_INLINE | ACTION_SHIELDED_TRANSFER_SIDECAR
    )
}

pub(crate) fn is_shielded_transfer_action(action: &PendingAction) -> bool {
    action.family_id == FAMILY_SHIELDED_POOL && is_transfer_action(action.action_id)
}

pub(crate) fn is_coinbase_action(action: &PendingAction) -> bool {
    action.family_id == FAMILY_SHIELDED_POOL && action.action_id == ACTION_MINT_COINBASE
}

pub(crate) fn wallet_commitment_source_label(action: &PendingAction) -> &'static str {
    if is_coinbase_action(action) {
        "mining_reward"
    } else if is_shielded_transfer_action(action) {
        "transfer"
    } else {
        "unknown"
    }
}

pub(crate) fn is_candidate_artifact_action(action: &PendingAction) -> bool {
    action.family_id == FAMILY_SHIELDED_POOL && action.action_id == ACTION_SUBMIT_CANDIDATE_ARTIFACT
}

pub(crate) fn pending_action_peer_relayable(action: &PendingAction) -> bool {
    !is_coinbase_action(action) && !is_candidate_artifact_action(action)
}

pub(crate) fn stage_relayed_pending_action(
    node: &NativeNode,
    pending: PendingAction,
) -> Result<Option<PendingAction>> {
    node.stage_relayed_pending_action(pending)
}

pub(crate) fn action_order_key_preimage(action: &PendingAction) -> Vec<u8> {
    let mut preimage = Vec::new();
    match (action.family_id, action.action_id) {
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE) => {
            if let Ok(args) = decode_scale_exact::<ShieldedTransferInlineArgs>(
                &action.public_args,
                "shielded inline action args",
            ) {
                preimage.extend_from_slice(&args.binding_hash);
            }
        }
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR) => {
            if let Ok(args) = decode_scale_exact::<ShieldedTransferSidecarArgs>(
                &action.public_args,
                "shielded sidecar action args",
            ) {
                preimage.extend_from_slice(&args.binding_hash);
            }
        }
        _ => {
            return non_transfer_action_order_key_preimage(
                action.family_id,
                action.action_id,
                pending_action_semantic_hash(action),
                &action.nullifiers,
            );
        }
    }
    for nullifier in &action.nullifiers {
        preimage.extend_from_slice(nullifier);
    }
    if preimage.is_empty() {
        preimage.extend_from_slice(&action.tx_hash);
    }
    preimage
}

pub(crate) fn non_transfer_action_order_key_preimage(
    family_id: u16,
    action_id: u16,
    semantic_hash: [u8; 32],
    nullifiers: &[[u8; 48]],
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(12 + 2 + 2 + 32 + 48 * nullifiers.len());
    preimage.extend_from_slice(b"non-transfer");
    preimage.extend_from_slice(&family_id.to_le_bytes());
    preimage.extend_from_slice(&action_id.to_le_bytes());
    preimage.extend_from_slice(&semantic_hash);
    for nullifier in nullifiers {
        preimage.extend_from_slice(nullifier);
    }
    preimage
}

pub(crate) fn action_order_key(action: &PendingAction) -> [u8; 32] {
    let preimage = action_order_key_preimage(action);
    crypto::hashes::blake2_256(&preimage)
}

pub(crate) fn transfer_key_extends_canonical_order(
    previous_transfer_key: Option<&[u8; 32]>,
    transfer_key: &[u8; 32],
) -> bool {
    previous_transfer_key.is_none_or(|previous| transfer_key >= previous)
}

pub(crate) fn validate_bridge_action_payload(action: &PendingAction) -> Result<()> {
    validate_bridge_action_payload_with_replay_state(action, None)
}

pub(crate) fn validate_bridge_action_payload_with_replay_state(
    action: &PendingAction,
    replay_state: Option<&InboundReplayState>,
) -> Result<()> {
    let bridge_route = action.family_id == FAMILY_BRIDGE;
    let state_deltas_absent = bridge_action_has_no_state_deltas(action);
    let action_kind = native_bridge_action_payload_kind(action.action_id);
    if !bridge_route || !state_deltas_absent {
        let input = native_bridge_action_payload_admission_input(
            bridge_route,
            state_deltas_absent,
            action_kind,
            true,
            true,
            true,
            true,
            true,
        );
        return evaluate_native_bridge_action_payload_admission(input).map_err(|rejection| {
            native_bridge_action_payload_admission_error(action.action_id, rejection)
        });
    }
    match action_kind {
        NativeBridgeActionPayloadKind::Outbound => {
            let args: OutboundBridgeArgsV1 =
                decode_scale_exact(&action.public_args, "outbound bridge action args")?;
            let input = native_bridge_action_payload_admission_input(
                bridge_route,
                state_deltas_absent,
                action_kind,
                !args.payload.is_empty(),
                true,
                true,
                true,
                true,
            );
            evaluate_native_bridge_action_payload_admission(input).map_err(|rejection| {
                native_bridge_action_payload_admission_error(action.action_id, rejection)
            })?;
            validate_bridge_action_resource_projection(
                native_bridge_action_resource_projection_input(
                    action_kind,
                    action.public_args.len(),
                    args.payload.len(),
                    0,
                    0,
                ),
            )?;
            Ok(())
        }
        NativeBridgeActionPayloadKind::Inbound => {
            let args: InboundBridgeArgsV1 =
                decode_scale_exact(&action.public_args, "inbound bridge action args")?;
            validate_bridge_action_resource_projection(
                native_bridge_action_resource_projection_input(
                    action_kind,
                    action.public_args.len(),
                    0,
                    args.proof_receipt.len(),
                    args.message.payload.len(),
                ),
            )?;
            let input = native_bridge_action_payload_admission_input(
                bridge_route,
                state_deltas_absent,
                action_kind,
                true,
                !args.proof_receipt.is_empty(),
                args.message.source_chain_id == args.source_chain_id
                    && args.message.message_nonce == args.source_message_nonce,
                args.message.destination_chain_id == HEGEMON_CHAIN_ID_V1,
                args.message.payload_hash == bridge_payload_hash(&args.message.payload),
            );
            evaluate_native_bridge_action_payload_admission(input).map_err(|rejection| {
                native_bridge_action_payload_admission_error(action.action_id, rejection)
            })?;
            verify_inbound_bridge_receipt(action, &args, replay_state.cloned())?;
            Ok(())
        }
        NativeBridgeActionPayloadKind::Register => {
            let registration: BridgeVerifierRegistrationV1 =
                decode_scale_exact(&action.public_args, "bridge verifier registration args")?;
            let input = native_bridge_action_payload_admission_input(
                bridge_route,
                state_deltas_absent,
                action_kind,
                true,
                true,
                true,
                true,
                true,
            );
            evaluate_native_bridge_action_payload_admission(input).map_err(|rejection| {
                native_bridge_action_payload_admission_error(action.action_id, rejection)
            })?;
            let registration_effect = evaluate_native_bridge_verifier_registration_policy(
                native_bridge_verifier_registration_policy_input(action, Some(&registration)),
            )
            .map_err(native_bridge_verifier_registration_policy_error)?;
            debug_assert!(!registration_effect.production_mint_verifier_enabled);
            validate_bridge_action_resource_projection(
                native_bridge_action_resource_projection_input(
                    action_kind,
                    action.public_args.len(),
                    0,
                    0,
                    0,
                ),
            )?;
            Ok(())
        }
        NativeBridgeActionPayloadKind::Unsupported => {
            let input = native_bridge_action_payload_admission_input(
                bridge_route,
                state_deltas_absent,
                action_kind,
                true,
                true,
                true,
                true,
                true,
            );
            evaluate_native_bridge_action_payload_admission(input).map_err(|rejection| {
                native_bridge_action_payload_admission_error(action.action_id, rejection)
            })?;
            Ok(())
        }
    }
}

pub(crate) fn native_bridge_action_payload_kind(action_id: u16) -> NativeBridgeActionPayloadKind {
    match action_id {
        ACTION_BRIDGE_OUTBOUND => NativeBridgeActionPayloadKind::Outbound,
        ACTION_BRIDGE_INBOUND => NativeBridgeActionPayloadKind::Inbound,
        ACTION_REGISTER_BRIDGE_VERIFIER => NativeBridgeActionPayloadKind::Register,
        _ => NativeBridgeActionPayloadKind::Unsupported,
    }
}

pub(crate) fn bridge_action_has_no_state_deltas(action: &PendingAction) -> bool {
    action.nullifiers.is_empty()
        && action.commitments.is_empty()
        && action.ciphertext_hashes.is_empty()
        && action.ciphertext_sizes.is_empty()
        && action.fee == 0
        && action.anchor == [0u8; 48]
        && action.candidate_artifact.is_none()
}

pub(crate) fn native_bridge_action_resource_projection_input(
    action_kind: NativeBridgeActionPayloadKind,
    public_args_bytes: usize,
    outbound_payload_bytes: usize,
    inbound_proof_receipt_bytes: usize,
    inbound_message_payload_bytes: usize,
) -> NativeBridgeActionResourceAdmissionInput {
    NativeBridgeActionResourceAdmissionInput {
        raw_byte_cap: MAX_NATIVE_RPC_ACTION_BYTES,
        decoded_byte_cap: MAX_NATIVE_RPC_ACTION_BYTES,
        item_count_cap: 2,
        item_byte_cap: MAX_NATIVE_BRIDGE_PROOF_RECEIPT_BYTES,
        aggregate_byte_cap: MAX_NATIVE_BRIDGE_ACTION_DYNAMIC_BYTES,
        work_unit_cap: MAX_NATIVE_BRIDGE_MESSAGE_PAYLOAD_BYTES,
        action_kind,
        public_args_bytes,
        outbound_payload_bytes,
        inbound_proof_receipt_bytes,
        inbound_message_payload_bytes,
    }
}

pub(crate) fn native_bridge_action_resource_item_count(
    input: NativeBridgeActionResourceAdmissionInput,
) -> usize {
    match input.action_kind {
        NativeBridgeActionPayloadKind::Outbound => 1,
        NativeBridgeActionPayloadKind::Inbound => 2,
        NativeBridgeActionPayloadKind::Register | NativeBridgeActionPayloadKind::Unsupported => 0,
    }
}

pub(crate) fn bridge_action_resource_bounded_request(
    input: NativeBridgeActionResourceAdmissionInput,
) -> NativeBoundedRequestAdmissionInput {
    let aggregate_bytes = input
        .outbound_payload_bytes
        .saturating_add(input.inbound_proof_receipt_bytes)
        .saturating_add(input.inbound_message_payload_bytes);
    NativeBoundedRequestAdmissionInput {
        raw_byte_cap: input.raw_byte_cap,
        decoded_byte_cap: input.decoded_byte_cap,
        item_count_cap: input.item_count_cap,
        item_byte_cap: input.item_byte_cap,
        aggregate_byte_cap: input.aggregate_byte_cap,
        work_unit_cap: input.work_unit_cap,
        raw_bytes: input.public_args_bytes,
        decoded_bytes: input.public_args_bytes,
        item_count: native_bridge_action_resource_item_count(input),
        max_item_bytes: input
            .outbound_payload_bytes
            .max(input.inbound_proof_receipt_bytes)
            .max(input.inbound_message_payload_bytes),
        aggregate_bytes,
        work_units: input
            .outbound_payload_bytes
            .max(input.inbound_message_payload_bytes),
    }
}

pub(crate) fn validate_bridge_action_resource_projection(
    input: NativeBridgeActionResourceAdmissionInput,
) -> Result<NativeBoundedRequestAdmissionInput> {
    let bounded = bridge_action_resource_bounded_request(input);
    evaluate_native_bounded_request_admission(bounded)
        .map(|_| bounded)
        .map_err(|rejection| bridge_action_resource_admission_error(bounded, rejection))
}

pub(crate) fn native_bridge_action_payload_admission_input(
    bridge_route: bool,
    state_deltas_absent: bool,
    action_kind: NativeBridgeActionPayloadKind,
    outbound_payload_nonempty: bool,
    inbound_proof_receipt_nonempty: bool,
    inbound_replay_key_matches: bool,
    inbound_destination_matches: bool,
    inbound_payload_hash_matches: bool,
) -> NativeBridgeActionPayloadAdmissionInput {
    NativeBridgeActionPayloadAdmissionInput {
        bridge_route,
        state_deltas_absent,
        action_kind,
        outbound_payload_nonempty,
        inbound_proof_receipt_nonempty,
        inbound_replay_key_matches,
        inbound_destination_matches,
        inbound_payload_hash_matches,
    }
}

pub(crate) fn bridge_action_resource_admission_error(
    input: NativeBoundedRequestAdmissionInput,
    rejection: NativeBoundedRequestAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeBoundedRequestAdmissionRejection::RawBytes => anyhow!(
            "bridge action public_args byte count {} exceeds cap {}",
            input.raw_bytes,
            input.raw_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::DecodedBytes => anyhow!(
            "bridge action decoded byte count {} exceeds cap {}",
            input.decoded_bytes,
            input.decoded_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::ItemCount => anyhow!(
            "bridge action dynamic item count {} exceeds cap {}",
            input.item_count,
            input.item_count_cap
        ),
        NativeBoundedRequestAdmissionRejection::ItemBytes => anyhow!(
            "bridge action proof receipt or payload item byte count {} exceeds cap {}",
            input.max_item_bytes,
            input.item_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::AggregateBytes => anyhow!(
            "bridge action dynamic byte aggregate {} exceeds cap {}",
            input.aggregate_bytes,
            input.aggregate_byte_cap
        ),
        NativeBoundedRequestAdmissionRejection::WorkUnits => anyhow!(
            "bridge action message payload byte count {} exceeds cap {}",
            input.work_units,
            input.work_unit_cap
        ),
    }
}

pub(crate) fn evaluate_native_bridge_action_payload_admission(
    input: NativeBridgeActionPayloadAdmissionInput,
) -> Result<(), NativeBridgeActionPayloadAdmissionRejection> {
    if !input.bridge_route {
        Err(NativeBridgeActionPayloadAdmissionRejection::NotBridgeAction)
    } else if !input.state_deltas_absent {
        Err(NativeBridgeActionPayloadAdmissionRejection::StateDeltasPresent)
    } else {
        match input.action_kind {
            NativeBridgeActionPayloadKind::Outbound => {
                if !input.outbound_payload_nonempty {
                    Err(NativeBridgeActionPayloadAdmissionRejection::OutboundPayloadEmpty)
                } else {
                    Ok(())
                }
            }
            NativeBridgeActionPayloadKind::Inbound => {
                if !input.inbound_proof_receipt_nonempty {
                    Err(NativeBridgeActionPayloadAdmissionRejection::InboundProofReceiptEmpty)
                } else if !input.inbound_replay_key_matches {
                    Err(NativeBridgeActionPayloadAdmissionRejection::InboundReplayKeyMismatch)
                } else if !input.inbound_destination_matches {
                    Err(NativeBridgeActionPayloadAdmissionRejection::InboundDestinationMismatch)
                } else if !input.inbound_payload_hash_matches {
                    Err(NativeBridgeActionPayloadAdmissionRejection::InboundPayloadHashMismatch)
                } else {
                    Ok(())
                }
            }
            NativeBridgeActionPayloadKind::Register => Ok(()),
            NativeBridgeActionPayloadKind::Unsupported => {
                Err(NativeBridgeActionPayloadAdmissionRejection::UnsupportedBridgeAction)
            }
        }
    }
}

pub(crate) fn evaluate_native_bridge_mint_replay_policy(
    input: NativeBridgeMintReplayPolicyInput,
) -> Result<InboundReplayState, NativeBridgeMintReplayPolicyRejection> {
    if !input.inbound_bridge_mint {
        Err(NativeBridgeMintReplayPolicyRejection::NotInboundBridgeMint)
    } else if !input.state_deltas_absent {
        Err(NativeBridgeMintReplayPolicyRejection::StateDeltaMintPresent)
    } else if !input.receipt_envelope_present {
        Err(NativeBridgeMintReplayPolicyRejection::ReceiptEnvelopeMissing)
    } else if !input.receipt_verified {
        Err(NativeBridgeMintReplayPolicyRejection::ReceiptNotVerified)
    } else if !input.receipt_payload_matches {
        Err(NativeBridgeMintReplayPolicyRejection::ReceiptPayloadMismatch)
    } else if input.replay_state.consumed().contains(&input.replay_key) {
        Err(NativeBridgeMintReplayPolicyRejection::ReplayAlreadyConsumed)
    } else if !input.mint_authorized {
        Err(NativeBridgeMintReplayPolicyRejection::MintNotAuthorized)
    } else if !input.amount_matches_receipt {
        Err(NativeBridgeMintReplayPolicyRejection::AmountDoesNotMatchReceipt)
    } else if !input.amount_within_bound {
        Err(NativeBridgeMintReplayPolicyRejection::AmountOutOfBounds)
    } else {
        let mut next_replay_state = input.replay_state;
        next_replay_state
            .import_one(input.replay_key)
            .map_err(|_| NativeBridgeMintReplayPolicyRejection::ReplayAlreadyConsumed)?;
        Ok(next_replay_state)
    }
}

pub(crate) fn evaluate_native_bridge_mint_payload_admission(
    input: NativeBridgeMintPayloadAdmissionInput,
) -> Result<(), NativeBridgeMintPayloadAdmissionRejection> {
    if !input.payload_decoded {
        Err(NativeBridgeMintPayloadAdmissionRejection::PayloadDecodeFailed)
    } else if !input.payload_hash_matches {
        Err(NativeBridgeMintPayloadAdmissionRejection::PayloadHashMismatch)
    } else if !input.receipt_message_hash_matches {
        Err(NativeBridgeMintPayloadAdmissionRejection::ReceiptMessageHashMismatch)
    } else if !input.version_matches {
        Err(NativeBridgeMintPayloadAdmissionRejection::VersionMismatch)
    } else if !input.source_app_family_matches {
        Err(NativeBridgeMintPayloadAdmissionRejection::SourceAppFamilyMismatch)
    } else if !input.destination_matches {
        Err(NativeBridgeMintPayloadAdmissionRejection::DestinationMismatch)
    } else if !input.mint_nonce_matches {
        Err(NativeBridgeMintPayloadAdmissionRejection::MintNonceMismatch)
    } else if !input.recipient_commitment_nonzero {
        Err(NativeBridgeMintPayloadAdmissionRejection::RecipientCommitmentZero)
    } else if !input.amount_nonzero {
        Err(NativeBridgeMintPayloadAdmissionRejection::AmountZero)
    } else if !input.amount_within_bound {
        Err(NativeBridgeMintPayloadAdmissionRejection::AmountOutOfBounds)
    } else if !input.asset_non_native {
        Err(NativeBridgeMintPayloadAdmissionRejection::NativeAssetNotAllowed)
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate_native_bridge_verifier_registration_policy(
    input: NativeBridgeVerifierRegistrationPolicyInput,
) -> Result<
    NativeBridgeVerifierRegistrationPolicyEffect,
    NativeBridgeVerifierRegistrationPolicyRejection,
> {
    if !input.bridge_verifier_registration {
        Err(NativeBridgeVerifierRegistrationPolicyRejection::NotBridgeVerifierRegistration)
    } else if !input.state_deltas_absent {
        Err(NativeBridgeVerifierRegistrationPolicyRejection::StateDeltasPresent)
    } else if !input.registration_decoded {
        Err(NativeBridgeVerifierRegistrationPolicyRejection::RegistrationDecodeFailed)
    } else {
        Ok(NativeBridgeVerifierRegistrationPolicyEffect {
            registration_observed: true,
            production_mint_verifier_enabled: input.descriptor_matches_release
                && input.activation_height_reached
                && input.pq_clean_verifier_bound
                && input.external_verifier_soundness_accepted
                && input.positive_minting_enabled,
        })
    }
}

pub(crate) fn native_bridge_verifier_registration_policy_input(
    action: &PendingAction,
    registration: Option<&BridgeVerifierRegistrationV1>,
) -> NativeBridgeVerifierRegistrationPolicyInput {
    NativeBridgeVerifierRegistrationPolicyInput {
        bridge_verifier_registration: action.family_id == FAMILY_BRIDGE
            && action.action_id == ACTION_REGISTER_BRIDGE_VERIFIER,
        state_deltas_absent: bridge_action_has_no_state_deltas(action),
        registration_decoded: registration.is_some(),
        descriptor_matches_release: registration.is_some_and(|registration| {
            registration.source_chain_id == HEGEMON_CHAIN_ID_V1
                && registration.verifier_program_hash == HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1
                && registration.rules_hash == HEGEMON_LIGHT_CLIENT_RULES_HASH_V1
        }),
        activation_height_reached: registration
            .is_some_and(|registration| registration.enabled_at_height == 0),
        pq_clean_verifier_bound: NATIVE_PQ_CLEAN_BRIDGE_VERIFIER_BOUND,
        external_verifier_soundness_accepted: NATIVE_EXTERNAL_BRIDGE_VERIFIER_SOUNDNESS_ACCEPTED,
        positive_minting_enabled: NATIVE_POSITIVE_INBOUND_BRIDGE_MINT_ENABLED,
    }
}

pub(crate) fn bridge_mint_payload_admission_input(
    args: &InboundBridgeArgsV1,
    output: &BridgeCheckpointOutputV1,
    payload: Option<&BridgeMintPayloadV1>,
) -> NativeBridgeMintPayloadAdmissionInput {
    let payload_hash_matches =
        args.message.payload_hash == bridge_payload_hash(&args.message.payload);
    let receipt_message_hash_matches = output.message_hash == args.message.message_hash();
    if let Some(payload) = payload {
        NativeBridgeMintPayloadAdmissionInput {
            payload_decoded: true,
            payload_hash_matches,
            receipt_message_hash_matches,
            version_matches: payload.version == BRIDGE_MINT_PAYLOAD_VERSION_V1,
            source_app_family_matches: args.message.app_family_id == BRIDGE_MINT_APP_FAMILY_ID_V1,
            destination_matches: payload.destination_chain_id == HEGEMON_CHAIN_ID_V1,
            mint_nonce_matches: payload.mint_nonce == args.source_message_nonce,
            recipient_commitment_nonzero: payload.recipient_commitment != [0u8; 48],
            amount_nonzero: payload.amount != 0,
            amount_within_bound: payload.amount <= MAX_NATIVE_BRIDGE_MINT_AMOUNT,
            asset_non_native: payload.asset_id != transaction_core::constants::NATIVE_ASSET_ID,
        }
    } else {
        NativeBridgeMintPayloadAdmissionInput {
            payload_decoded: false,
            payload_hash_matches,
            receipt_message_hash_matches,
            version_matches: false,
            source_app_family_matches: false,
            destination_matches: false,
            mint_nonce_matches: false,
            recipient_commitment_nonzero: false,
            amount_nonzero: false,
            amount_within_bound: false,
            asset_non_native: false,
        }
    }
}

pub(crate) fn native_bridge_mint_payload_admission_error(
    rejection: NativeBridgeMintPayloadAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeMintPayloadAdmissionRejection::PayloadDecodeFailed => anyhow!(
            "inbound bridge mint payload exact decode failed ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::PayloadHashMismatch => anyhow!(
            "inbound bridge mint payload hash mismatch ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::ReceiptMessageHashMismatch => anyhow!(
            "inbound bridge mint receipt/message hash mismatch ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::VersionMismatch => anyhow!(
            "inbound bridge mint payload version mismatch ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::SourceAppFamilyMismatch => anyhow!(
            "inbound bridge mint source app family mismatch ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::DestinationMismatch => anyhow!(
            "inbound bridge mint payload is not addressed to Hegemon ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::MintNonceMismatch => anyhow!(
            "inbound bridge mint payload nonce does not match receipt replay nonce ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::RecipientCommitmentZero => anyhow!(
            "inbound bridge mint payload recipient commitment is zero ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::AmountZero => {
            anyhow!("inbound bridge mint amount is zero ({})", rejection.label())
        }
        NativeBridgeMintPayloadAdmissionRejection::AmountOutOfBounds => anyhow!(
            "inbound bridge mint amount exceeds native bridge mint cap ({})",
            rejection.label()
        ),
        NativeBridgeMintPayloadAdmissionRejection::NativeAssetNotAllowed => anyhow!(
            "inbound bridge mint payload must target a non-native bridge asset ({})",
            rejection.label()
        ),
    }
}

pub(crate) fn native_bridge_verifier_registration_policy_error(
    rejection: NativeBridgeVerifierRegistrationPolicyRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeVerifierRegistrationPolicyRejection::NotBridgeVerifierRegistration => {
            anyhow!("not a bridge verifier registration ({})", rejection.label())
        }
        NativeBridgeVerifierRegistrationPolicyRejection::StateDeltasPresent => anyhow!(
            "bridge verifier registration carries shielded state deltas ({})",
            rejection.label()
        ),
        NativeBridgeVerifierRegistrationPolicyRejection::RegistrationDecodeFailed => anyhow!(
            "bridge verifier registration exact decode failed ({})",
            rejection.label()
        ),
    }
}

pub(crate) fn native_bridge_action_payload_admission_error(
    action_id: u16,
    rejection: NativeBridgeActionPayloadAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeActionPayloadAdmissionRejection::NotBridgeAction => {
            anyhow!("not a bridge action")
        }
        NativeBridgeActionPayloadAdmissionRejection::StateDeltasPresent => {
            anyhow!("bridge actions must not carry shielded state deltas")
        }
        NativeBridgeActionPayloadAdmissionRejection::UnsupportedBridgeAction => {
            anyhow!("unsupported bridge action {action_id}")
        }
        NativeBridgeActionPayloadAdmissionRejection::OutboundPayloadEmpty => {
            anyhow!("outbound bridge payload must be non-empty")
        }
        NativeBridgeActionPayloadAdmissionRejection::InboundProofReceiptEmpty => {
            anyhow!("inbound bridge proof receipt must be non-empty")
        }
        NativeBridgeActionPayloadAdmissionRejection::InboundReplayKeyMismatch => {
            anyhow!("inbound bridge replay key does not match message")
        }
        NativeBridgeActionPayloadAdmissionRejection::InboundDestinationMismatch => {
            anyhow!("inbound bridge message is not addressed to Hegemon")
        }
        NativeBridgeActionPayloadAdmissionRejection::InboundPayloadHashMismatch => {
            anyhow!("inbound bridge message payload hash mismatch")
        }
    }
}

pub(crate) fn native_bridge_mint_replay_policy_error(
    rejection: NativeBridgeMintReplayPolicyRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeMintReplayPolicyRejection::NotInboundBridgeMint => {
            anyhow!("not an inbound bridge mint action ({})", rejection.label())
        }
        NativeBridgeMintReplayPolicyRejection::StateDeltaMintPresent => anyhow!(
            "inbound bridge mint action carries shielded state deltas ({})",
            rejection.label()
        ),
        NativeBridgeMintReplayPolicyRejection::ReceiptEnvelopeMissing => {
            anyhow!(
                "inbound bridge receipt envelope missing ({})",
                rejection.label()
            )
        }
        NativeBridgeMintReplayPolicyRejection::ReceiptNotVerified => {
            anyhow!(
                "inbound bridge receipt is not verified ({})",
                rejection.label()
            )
        }
        NativeBridgeMintReplayPolicyRejection::ReceiptPayloadMismatch => {
            anyhow!(
                "inbound bridge receipt payload mismatch ({})",
                rejection.label()
            )
        }
        NativeBridgeMintReplayPolicyRejection::ReplayAlreadyConsumed => {
            anyhow!(
                "inbound bridge message already consumed ({})",
                rejection.label()
            )
        }
        NativeBridgeMintReplayPolicyRejection::MintNotAuthorized => anyhow!(
            "inbound bridge mint authorization is disabled until a PQ-clean bridge mint decoder and verifier are production-bound ({})",
            rejection.label()
        ),
        NativeBridgeMintReplayPolicyRejection::AmountDoesNotMatchReceipt => anyhow!(
            "inbound bridge mint amount does not match receipt ({})",
            rejection.label()
        ),
        NativeBridgeMintReplayPolicyRejection::AmountOutOfBounds => {
            anyhow!(
                "inbound bridge mint amount out of bounds ({})",
                rejection.label()
            )
        }
    }
}

pub(crate) fn native_bridge_witness_confirmations_checked(
    best_height: u64,
    message_height: u64,
) -> Option<u32> {
    let delta = best_height.checked_sub(message_height)?;
    Some(delta.saturating_add(1).min(u32::MAX as u64) as u32)
}

pub(crate) fn evaluate_native_bridge_witness_export_admission(
    input: NativeBridgeWitnessExportAdmissionInput,
) -> Result<u32, NativeBridgeWitnessExportAdmissionRejection> {
    if !input.block_hash_parameter_valid {
        Err(NativeBridgeWitnessExportAdmissionRejection::MalformedBlockHash)
    } else if !input.block_known {
        Err(NativeBridgeWitnessExportAdmissionRejection::UnknownBlock)
    } else if !input.canonical_height_present {
        Err(NativeBridgeWitnessExportAdmissionRejection::MissingCanonicalHeight)
    } else if !input.block_is_canonical {
        Err(NativeBridgeWitnessExportAdmissionRejection::NoncanonicalBlock)
    } else if !input.block_actions_decoded {
        Err(NativeBridgeWitnessExportAdmissionRejection::BlockActionsDecodeFailed)
    } else if !input.message_index_in_bounds {
        Err(NativeBridgeWitnessExportAdmissionRejection::MessageIndexOutOfBounds)
    } else if !input.parent_known {
        Err(NativeBridgeWitnessExportAdmissionRejection::MissingParent)
    } else {
        let confirmations =
            native_bridge_witness_confirmations_checked(input.best_height, input.message_height)
                .ok_or(NativeBridgeWitnessExportAdmissionRejection::TipBeforeMessage)?;
        if input.explicit_block_hash && u64::from(confirmations) > input.max_explicit_history {
            Err(NativeBridgeWitnessExportAdmissionRejection::ExplicitHistoryTooLong)
        } else if input.best_height > input.max_materialized_history {
            Err(NativeBridgeWitnessExportAdmissionRejection::MaterializedHistoryTooLong)
        } else {
            Ok(confirmations)
        }
    }
}

pub(crate) fn native_inbound_bridge_receipt_height_confirmations(
    canonical_tip_height: u64,
    checkpoint_height: u64,
) -> Result<u32, NativeInboundBridgeReceiptAdmissionRejection> {
    let delta = canonical_tip_height
        .checked_sub(checkpoint_height)
        .ok_or(NativeInboundBridgeReceiptAdmissionRejection::TipBeforeMessage)?;
    let confirmations = delta
        .checked_add(1)
        .ok_or(NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverflow)?;
    u32::try_from(confirmations)
        .map_err(|_| NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverflow)
}

pub(crate) fn evaluate_native_inbound_bridge_receipt_admission(
    input: NativeInboundBridgeReceiptAdmissionInput,
) -> Result<u32, NativeInboundBridgeReceiptAdmissionRejection> {
    if !input.source_chain_matches {
        Err(NativeInboundBridgeReceiptAdmissionRejection::SourceChainMismatch)
    } else if !input.rules_hash_matches {
        Err(NativeInboundBridgeReceiptAdmissionRejection::RulesHashMismatch)
    } else if !input.message_nonce_matches {
        Err(NativeInboundBridgeReceiptAdmissionRejection::MessageNonceMismatch)
    } else if !input.message_hash_matches {
        Err(NativeInboundBridgeReceiptAdmissionRejection::MessageHashMismatch)
    } else {
        let height_confirmations = native_inbound_bridge_receipt_height_confirmations(
            input.canonical_tip_height,
            input.checkpoint_height,
        )?;
        if height_confirmations < input.confirmations_checked {
            Err(NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverstated)
        } else if input.confirmations_checked < input.min_confirmations {
            Err(NativeInboundBridgeReceiptAdmissionRejection::Underconfirmed)
        } else if compare_work(&input.canonical_tip_work, &input.min_tip_work).is_lt()
            || compare_work(&input.min_work_checked, &input.min_tip_work).is_lt()
        {
            Err(NativeInboundBridgeReceiptAdmissionRejection::WorkPolicyMismatch)
        } else {
            Ok(height_confirmations)
        }
    }
}

pub(crate) fn evaluate_native_bridge_witness_backscan(
    entries: &[NativeBridgeWitnessBackscanEntry],
) -> Result<u64, NativeBridgeWitnessBackscanRejection> {
    for entry in entries {
        if !entry.canonical_hash_present || !entry.block_known {
            continue;
        }
        if !entry.block_actions_decoded {
            return Err(NativeBridgeWitnessBackscanRejection::BlockActionsDecodeFailed);
        }
        if entry.message_index_in_bounds {
            return Ok(entry.height);
        }
    }
    Err(NativeBridgeWitnessBackscanRejection::NoBridgeMessageInBackscan)
}

pub(crate) fn native_bridge_witness_export_admission_error(
    rejection: NativeBridgeWitnessExportAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeWitnessExportAdmissionRejection::MalformedBlockHash => {
            anyhow!(
                "malformed bridge witness block hash ({})",
                rejection.label()
            )
        }
        NativeBridgeWitnessExportAdmissionRejection::UnknownBlock => {
            anyhow!("unknown bridge witness block ({})", rejection.label())
        }
        NativeBridgeWitnessExportAdmissionRejection::MissingCanonicalHeight => anyhow!(
            "missing canonical block at bridge witness height ({})",
            rejection.label()
        ),
        NativeBridgeWitnessExportAdmissionRejection::NoncanonicalBlock => {
            anyhow!(
                "bridge witness block is not canonical ({})",
                rejection.label()
            )
        }
        NativeBridgeWitnessExportAdmissionRejection::BlockActionsDecodeFailed => anyhow!(
            "bridge witness block action decode failed ({})",
            rejection.label()
        ),
        NativeBridgeWitnessExportAdmissionRejection::MessageIndexOutOfBounds => {
            anyhow!("bridge message index out of bounds ({})", rejection.label())
        }
        NativeBridgeWitnessExportAdmissionRejection::MissingParent => {
            anyhow!("missing parent for bridge witness ({})", rejection.label())
        }
        NativeBridgeWitnessExportAdmissionRejection::TipBeforeMessage => anyhow!(
            "bridge witness tip height is before message height ({})",
            rejection.label()
        ),
        NativeBridgeWitnessExportAdmissionRejection::ExplicitHistoryTooLong => anyhow!(
            "explicit bridge witness block is too old for full export; checked confirmations exceed {MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS} ({})",
            rejection.label()
        ),
        NativeBridgeWitnessExportAdmissionRejection::MaterializedHistoryTooLong => anyhow!(
            "bridge witness export requires a materialized header history longer than {MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS}; enable an indexed bridge proof store before raising this safe-RPC cap ({})",
            rejection.label()
        ),
    }
}

pub(crate) fn native_inbound_bridge_receipt_admission_error(
    input: NativeInboundBridgeReceiptAdmissionInput,
    rejection: NativeInboundBridgeReceiptAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeInboundBridgeReceiptAdmissionRejection::SourceChainMismatch
        | NativeInboundBridgeReceiptAdmissionRejection::RulesHashMismatch
        | NativeInboundBridgeReceiptAdmissionRejection::MessageNonceMismatch
        | NativeInboundBridgeReceiptAdmissionRejection::MessageHashMismatch => {
            anyhow!("Hegemon light-client bridge receipt output mismatch")
        }
        NativeInboundBridgeReceiptAdmissionRejection::TipBeforeMessage => {
            anyhow!("Hegemon light-client bridge receipt tip precedes message")
        }
        NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverflow => {
            anyhow!("Hegemon light-client bridge receipt confirmation count exceeds native width")
        }
        NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverstated => {
            anyhow!("Hegemon light-client bridge receipt overstates confirmations")
        }
        NativeInboundBridgeReceiptAdmissionRejection::Underconfirmed => anyhow!(
            "Hegemon light-client bridge receipt underconfirmed: {} < {}",
            input.confirmations_checked,
            input.min_confirmations
        ),
        NativeInboundBridgeReceiptAdmissionRejection::WorkPolicyMismatch => {
            anyhow!("Hegemon light-client bridge receipt does not meet native work policy")
        }
    }
}

pub(crate) fn evaluate_native_risc0_release_verifier(
    input: NativeRisc0ReleaseVerifierInput,
) -> Result<(), NativeRisc0ReleaseVerifierRejection> {
    if !input.image_id_matches {
        Err(NativeRisc0ReleaseVerifierRejection::ImageIdMismatch)
    } else if !input.journal_decodes {
        Err(NativeRisc0ReleaseVerifierRejection::JournalDecodeFailed)
    } else if !input.verifier_enabled {
        Err(NativeRisc0ReleaseVerifierRejection::VerifierDisabled)
    } else {
        Ok(())
    }
}

pub(crate) fn native_risc0_release_verifier_error(
    rejection: NativeRisc0ReleaseVerifierRejection,
) -> anyhow::Error {
    match rejection {
        NativeRisc0ReleaseVerifierRejection::ImageIdMismatch => {
            anyhow!("RISC Zero bridge image id mismatch")
        }
        NativeRisc0ReleaseVerifierRejection::JournalDecodeFailed => {
            anyhow!("decode RISC Zero bridge journal failed")
        }
        NativeRisc0ReleaseVerifierRejection::VerifierDisabled => anyhow!(
            "RISC Zero bridge receipt verification is disabled in the PQ-only native node build"
        ),
    }
}

pub(crate) fn verify_inbound_bridge_receipt(
    action: &PendingAction,
    args: &InboundBridgeArgsV1,
    replay_state: Option<InboundReplayState>,
) -> Result<()> {
    if args.source_chain_id != HEGEMON_CHAIN_ID_V1 {
        return Err(anyhow!(
            "Hegemon RISC Zero bridge verifier only accepts Hegemon source chain"
        ));
    }
    let receipt: RiscZeroBridgeReceiptV1 =
        decode_scale_exact(&args.proof_receipt, "RISC Zero bridge receipt")?;
    if args.verifier_program_hash != HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1 {
        return Err(anyhow!("unregistered Hegemon RISC Zero bridge verifier"));
    }
    let output = verify_risc0_bridge_receipt(&receipt, HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1)?;
    let admission_input = NativeInboundBridgeReceiptAdmissionInput {
        source_chain_matches: output.source_chain_id == args.source_chain_id,
        rules_hash_matches: output.rules_hash == HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        message_nonce_matches: output.message_nonce == args.source_message_nonce,
        message_hash_matches: output.message_hash == args.message.message_hash(),
        checkpoint_height: output.checkpoint_height,
        canonical_tip_height: output.canonical_tip_height,
        canonical_tip_work: output.canonical_tip_cumulative_work,
        confirmations_checked: output.confirmations_checked,
        min_confirmations: MIN_INBOUND_BRIDGE_CONFIRMATIONS,
        min_work_checked: output.min_work_checked,
        min_tip_work: HEGEMON_BRIDGE_LONG_RANGE_MIN_TIP_WORK_V1,
    };
    evaluate_native_inbound_bridge_receipt_admission(admission_input).map_err(|rejection| {
        native_inbound_bridge_receipt_admission_error(admission_input, rejection)
    })?;
    enforce_verified_inbound_bridge_mint_replay_policy(action, args, &output, replay_state)?;
    Ok(())
}

pub(crate) fn enforce_verified_inbound_bridge_mint_replay_policy(
    action: &PendingAction,
    args: &InboundBridgeArgsV1,
    output: &BridgeCheckpointOutputV1,
    replay_state: Option<InboundReplayState>,
) -> Result<()> {
    let Some(replay_state) = replay_state else {
        return Err(anyhow!(
            "inbound bridge mint replay state is required before accepting verified bridge receipts"
        ));
    };
    let mint_payload = decode_scale_exact::<BridgeMintPayloadV1>(
        &args.message.payload,
        "inbound bridge mint payload",
    );
    let payload_input =
        bridge_mint_payload_admission_input(args, output, mint_payload.as_ref().ok());
    evaluate_native_bridge_mint_payload_admission(payload_input)
        .map_err(native_bridge_mint_payload_admission_error)?;
    let _mint_payload = mint_payload.expect("payload admission requires exact decode");
    let replay_key = inbound_replay_key(args.source_chain_id, args.source_message_nonce);
    let policy_input = NativeBridgeMintReplayPolicyInput {
        inbound_bridge_mint: action.family_id == FAMILY_BRIDGE
            && action.action_id == ACTION_BRIDGE_INBOUND,
        state_deltas_absent: bridge_action_has_no_state_deltas(action),
        receipt_envelope_present: !args.proof_receipt.is_empty(),
        receipt_verified: true,
        receipt_payload_matches: output.source_chain_id == args.source_chain_id
            && output.rules_hash == HEGEMON_LIGHT_CLIENT_RULES_HASH_V1
            && output.message_nonce == args.source_message_nonce
            && output.message_hash == args.message.message_hash(),
        replay_state,
        replay_key,
        mint_authorized: false,
        amount_matches_receipt: true,
        amount_within_bound: true,
    };
    match evaluate_native_bridge_mint_replay_policy(policy_input) {
        Ok(_) => Err(anyhow!(
            "inbound bridge mint policy unexpectedly accepted without production mint authorization"
        )),
        Err(rejection) => Err(native_bridge_mint_replay_policy_error(rejection)),
    }
}

pub(crate) fn verify_risc0_bridge_receipt(
    envelope: &RiscZeroBridgeReceiptV1,
    expected_image_id: [u8; 32],
) -> Result<BridgeCheckpointOutputV1> {
    let mut release_input = NativeRisc0ReleaseVerifierInput {
        image_id_matches: envelope.image_id == expected_image_id,
        journal_decodes: false,
        verifier_enabled: NATIVE_RISC0_RECEIPT_VERIFIER_ENABLED,
    };
    if !release_input.image_id_matches {
        let rejection = evaluate_native_risc0_release_verifier(release_input)
            .expect_err("image mismatch must reject");
        return Err(native_risc0_release_verifier_error(rejection));
    }
    let output = match decode_risc0_bridge_journal(envelope) {
        Ok(output) => {
            release_input.journal_decodes = true;
            output
        }
        Err(err) => {
            let rejection = evaluate_native_risc0_release_verifier(release_input)
                .expect_err("journal decode failure must reject");
            let base = native_risc0_release_verifier_error(rejection);
            return Err(anyhow!("{base}: {err:?}"));
        }
    };
    evaluate_native_risc0_release_verifier(release_input)
        .map_err(native_risc0_release_verifier_error)?;
    Ok(output)
}

pub(crate) fn bridge_inbound_replay_key_from_action(
    action: &PendingAction,
) -> Result<Option<[u8; 48]>> {
    if action.family_id != FAMILY_BRIDGE || action.action_id != ACTION_BRIDGE_INBOUND {
        return Ok(None);
    }
    let args: InboundBridgeArgsV1 =
        decode_scale_exact(&action.public_args, "inbound bridge action args")?;
    Ok(Some(inbound_replay_key(
        args.source_chain_id,
        args.source_message_nonce,
    )))
}

pub(crate) fn inbound_replay_state_for_mempool(state: &NativeState) -> Result<InboundReplayState> {
    let mut pending = BTreeSet::new();
    for action in state.pending_actions.values() {
        if let Some(replay_key) = bridge_inbound_replay_key_from_action(action)? {
            if !pending.insert(replay_key) {
                return Err(anyhow!("duplicate inbound bridge message already pending"));
            }
        }
    }
    Ok(InboundReplayState::new(
        state.consumed_bridge_messages.clone(),
        pending,
    ))
}

pub(crate) fn shielded_nullifier_state_for_mempool(state: &NativeState) -> NullifierState {
    let mut pending = BTreeSet::new();
    for action in state.pending_actions.values() {
        for nullifier in &action.nullifiers {
            pending.insert(*nullifier);
        }
    }
    NullifierState::new(state.nullifiers.clone(), pending)
}

pub(crate) fn bridge_messages_from_actions(
    actions: &[PendingAction],
    source_height: u64,
) -> Result<Vec<BridgeMessageV1>> {
    let mut messages = Vec::new();
    for action in actions {
        if action.family_id != FAMILY_BRIDGE || action.action_id != ACTION_BRIDGE_OUTBOUND {
            continue;
        }
        let args = decode_scale_exact::<OutboundBridgeArgsV1>(
            &action.public_args,
            "outbound bridge action args",
        )?;
        let message_nonce = ((source_height as u128) << 64) | messages.len() as u128;
        messages.push(BridgeMessageV1 {
            source_chain_id: HEGEMON_CHAIN_ID_V1,
            destination_chain_id: args.destination_chain_id,
            app_family_id: args.app_family_id,
            message_nonce,
            source_height,
            payload_hash: bridge_payload_hash(&args.payload),
            payload: args.payload,
        });
    }
    Ok(messages)
}

pub(crate) fn decode_block_actions(meta: &NativeBlockMeta) -> Result<Vec<PendingAction>> {
    validate_block_action_byte_budget(
        meta.tx_count,
        meta.action_bytes.len(),
        meta.action_bytes.iter().map(Vec::len),
    )?;
    evaluate_native_action_hash_admission(NativeActionHashAdmissionInput {
        action_count_matches: meta.action_bytes.len() == meta.tx_count as usize,
        action_hashes_match: true,
        action_hashes_unique: true,
    })
    .map_err(native_action_hash_admission_error)?;
    let mut actions = Vec::with_capacity(meta.action_bytes.len());
    for bytes in &meta.action_bytes {
        let action = decode_scale_exact::<PendingAction>(bytes, "native block action")?;
        if action.encode().as_slice() != bytes.as_slice() {
            return Err(anyhow!(
                "native block action has noncanonical SCALE encoding"
            ));
        }
        actions.push(action);
    }
    evaluate_native_action_hash_admission(NativeActionHashAdmissionInput {
        action_count_matches: true,
        action_hashes_match: block_action_hashes_match(&actions),
        action_hashes_unique: block_action_hashes_unique(&actions),
    })
    .map_err(native_action_hash_admission_error)?;
    Ok(actions)
}

pub(crate) fn validate_block_action_byte_budget<I>(
    declared_tx_count: u32,
    action_payload_count: usize,
    action_payload_lengths: I,
) -> Result<()>
where
    I: IntoIterator<Item = usize>,
{
    let declared_count = declared_tx_count as usize;
    if declared_count > MAX_NATIVE_BLOCK_ACTIONS || action_payload_count > MAX_NATIVE_BLOCK_ACTIONS
    {
        return Err(anyhow!(
            "native block action count exceeds limit: declared={}, payloads={}, max={}",
            declared_count,
            action_payload_count,
            MAX_NATIVE_BLOCK_ACTIONS
        ));
    }

    let mut total = 0usize;
    for len in action_payload_lengths {
        if len > MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES {
            return Err(anyhow!(
                "native block action payload exceeds per-action limit: {} > {}",
                len,
                MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES
            ));
        }
        total = total
            .checked_add(len)
            .ok_or_else(|| anyhow!("native block action byte total overflow"))?;
        if total > MAX_NATIVE_BLOCK_ACTION_BYTES {
            return Err(anyhow!(
                "native block action bytes exceed aggregate limit: {} > {}",
                total,
                MAX_NATIVE_BLOCK_ACTION_BYTES
            ));
        }
    }
    Ok(())
}

pub(crate) fn evaluate_native_action_hash_admission(
    input: NativeActionHashAdmissionInput,
) -> Result<(), NativeActionHashAdmissionRejection> {
    if !input.action_count_matches {
        Err(NativeActionHashAdmissionRejection::ActionCountMismatch)
    } else if !input.action_hashes_match {
        Err(NativeActionHashAdmissionRejection::ActionHashMismatch)
    } else if !input.action_hashes_unique {
        Err(NativeActionHashAdmissionRejection::DuplicateActionHash)
    } else {
        Ok(())
    }
}

pub(crate) fn native_action_hash_admission_error(
    rejection: NativeActionHashAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeActionHashAdmissionRejection::ActionCountMismatch => {
            anyhow!("block action payload count mismatch")
        }
        NativeActionHashAdmissionRejection::ActionHashMismatch => {
            anyhow!("block action hash mismatch")
        }
        NativeActionHashAdmissionRejection::DuplicateActionHash => {
            anyhow!("duplicate action in block")
        }
    }
}

pub(crate) fn action_has_no_shielded_state_deltas(action: &PendingAction) -> bool {
    action.nullifiers.is_empty()
        && action.commitments.is_empty()
        && action.ciphertext_hashes.is_empty()
        && action.ciphertext_sizes.is_empty()
        && action.fee == 0
        && action.anchor == [0u8; 48]
}

pub(crate) fn bridge_action_scope_valid(action: &PendingAction) -> bool {
    action_has_no_shielded_state_deltas(action) && action.candidate_artifact.is_none()
}

pub(crate) fn candidate_artifact_action_scope_valid(action: &PendingAction) -> bool {
    action_has_no_shielded_state_deltas(action)
}

pub(crate) fn coinbase_action_scope_valid(action: &PendingAction) -> bool {
    action.nullifiers.is_empty()
        && action.commitments.len() == 1
        && action.ciphertext_hashes.len() == 1
        && action.ciphertext_sizes.len() == 1
        && action.fee == 0
        && action.anchor == [0u8; 48]
        && action.candidate_artifact.is_none()
}

pub(crate) fn transfer_action_scope_valid(action: &PendingAction) -> bool {
    !action.nullifiers.is_empty()
        && action.nullifiers.len() <= transaction_core::constants::MAX_INPUTS
        && !action.commitments.is_empty()
        && action.commitments.len() <= transaction_core::constants::MAX_OUTPUTS
        && action.ciphertext_hashes.len() == action.commitments.len()
        && action.ciphertext_sizes.len() == action.commitments.len()
        && action
            .ciphertext_sizes
            .iter()
            .all(|size| *size as usize <= MAX_CIPHERTEXT_BYTES)
}

pub(crate) fn native_action_scope_admission_input(
    action: &PendingAction,
) -> NativeActionScopeAdmissionInput {
    NativeActionScopeAdmissionInput {
        candidate_artifact_payload_scoped: action.candidate_artifact.is_none()
            || is_candidate_artifact_action(action),
        bridge_route: action.family_id == FAMILY_BRIDGE,
        bridge_scope_valid: bridge_action_scope_valid(action),
        candidate_artifact_route: is_candidate_artifact_action(action),
        candidate_scope_valid: candidate_artifact_action_scope_valid(action),
        candidate_payload_present: action.candidate_artifact.is_some(),
        coinbase_route: is_coinbase_action(action),
        coinbase_scope_valid: coinbase_action_scope_valid(action),
        transfer_route: is_shielded_transfer_action(action),
        transfer_scope_valid: transfer_action_scope_valid(action),
    }
}

pub(crate) fn evaluate_native_action_scope_admission(
    input: NativeActionScopeAdmissionInput,
) -> Result<NativeActionScopeAdmissionRoute, NativeActionScopeAdmissionRejection> {
    if !input.candidate_artifact_payload_scoped {
        Err(NativeActionScopeAdmissionRejection::CandidateArtifactPayloadWrongRoute)
    } else if input.bridge_route {
        if !input.bridge_scope_valid {
            Err(NativeActionScopeAdmissionRejection::BridgeScopeInvalid)
        } else {
            Ok(NativeActionScopeAdmissionRoute::Bridge)
        }
    } else if input.candidate_artifact_route {
        if !input.candidate_scope_valid {
            Err(NativeActionScopeAdmissionRejection::CandidateScopeInvalid)
        } else if !input.candidate_payload_present {
            Err(NativeActionScopeAdmissionRejection::CandidatePayloadMissing)
        } else {
            Ok(NativeActionScopeAdmissionRoute::CandidateArtifact)
        }
    } else if input.coinbase_route {
        if !input.coinbase_scope_valid {
            Err(NativeActionScopeAdmissionRejection::CoinbaseScopeInvalid)
        } else {
            Ok(NativeActionScopeAdmissionRoute::Coinbase)
        }
    } else if !input.transfer_route {
        Err(NativeActionScopeAdmissionRejection::UnsupportedActionRoute)
    } else if !input.transfer_scope_valid {
        Err(NativeActionScopeAdmissionRejection::TransferScopeInvalid)
    } else {
        Ok(NativeActionScopeAdmissionRoute::Transfer)
    }
}

pub(crate) fn native_action_scope_admission_error(
    rejection: NativeActionScopeAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeActionScopeAdmissionRejection::CandidateArtifactPayloadWrongRoute => {
            anyhow!("candidate artifact payload is only valid on candidate artifact actions")
        }
        NativeActionScopeAdmissionRejection::BridgeScopeInvalid => {
            anyhow!("bridge actions must not carry shielded state deltas")
        }
        NativeActionScopeAdmissionRejection::CandidateScopeInvalid => {
            anyhow!("candidate artifact actions must not carry shielded state deltas")
        }
        NativeActionScopeAdmissionRejection::CandidatePayloadMissing => {
            anyhow!("candidate artifact action missing payload")
        }
        NativeActionScopeAdmissionRejection::CoinbaseScopeInvalid => {
            anyhow!("coinbase action must contain exactly one output and no other state deltas")
        }
        NativeActionScopeAdmissionRejection::UnsupportedActionRoute => {
            anyhow!("action is not a shielded transfer")
        }
        NativeActionScopeAdmissionRejection::TransferScopeInvalid => {
            anyhow!("shielded transfer action has invalid public metadata shape")
        }
    }
}

pub(crate) fn native_block_action_validation_scope_rejection(
    rejection: NativeActionScopeAdmissionRejection,
) -> NativeBlockActionValidationRejection {
    match rejection {
        NativeActionScopeAdmissionRejection::CandidateArtifactPayloadWrongRoute => {
            NativeBlockActionValidationRejection::CandidateArtifactPayloadWrongRoute
        }
        NativeActionScopeAdmissionRejection::BridgeScopeInvalid => {
            NativeBlockActionValidationRejection::BridgeScopeInvalid
        }
        NativeActionScopeAdmissionRejection::CandidateScopeInvalid => {
            NativeBlockActionValidationRejection::CandidateScopeInvalid
        }
        NativeActionScopeAdmissionRejection::CandidatePayloadMissing => {
            NativeBlockActionValidationRejection::CandidatePayloadMissing
        }
        NativeActionScopeAdmissionRejection::CoinbaseScopeInvalid => {
            NativeBlockActionValidationRejection::CoinbaseScopeInvalid
        }
        NativeActionScopeAdmissionRejection::UnsupportedActionRoute => {
            NativeBlockActionValidationRejection::UnsupportedActionRoute
        }
        NativeActionScopeAdmissionRejection::TransferScopeInvalid => {
            NativeBlockActionValidationRejection::TransferScopeInvalid
        }
    }
}

pub(crate) fn native_block_action_validation_hash_rejection(
    rejection: NativeActionHashAdmissionRejection,
) -> NativeBlockActionValidationRejection {
    match rejection {
        NativeActionHashAdmissionRejection::ActionCountMismatch => {
            NativeBlockActionValidationRejection::ActionCountMismatch
        }
        NativeActionHashAdmissionRejection::ActionHashMismatch => {
            NativeBlockActionValidationRejection::ActionHashMismatch
        }
        NativeActionHashAdmissionRejection::DuplicateActionHash => {
            NativeBlockActionValidationRejection::DuplicateActionHash
        }
    }
}

pub(crate) fn native_block_action_validation_payload_rejection(
    route: NativeActionScopeAdmissionRoute,
) -> NativeBlockActionValidationRejection {
    match route {
        NativeActionScopeAdmissionRoute::Bridge => {
            NativeBlockActionValidationRejection::BridgePayloadInvalid
        }
        NativeActionScopeAdmissionRoute::CandidateArtifact => {
            NativeBlockActionValidationRejection::CandidatePayloadInvalid
        }
        NativeActionScopeAdmissionRoute::Coinbase => {
            NativeBlockActionValidationRejection::CoinbasePayloadInvalid
        }
        NativeActionScopeAdmissionRoute::Transfer => {
            NativeBlockActionValidationRejection::TransferPayloadInvalid
        }
    }
}

pub(crate) fn native_block_action_validation_transfer_rejection(
    rejection: NativeTransferStateAdmissionRejection,
) -> NativeBlockActionValidationRejection {
    match rejection {
        NativeTransferStateAdmissionRejection::UnknownAnchor => {
            NativeBlockActionValidationRejection::TransferUnknownAnchor
        }
        NativeTransferStateAdmissionRejection::NullifierZero => {
            NativeBlockActionValidationRejection::TransferNullifierZero
        }
        NativeTransferStateAdmissionRejection::NullifierAlreadySpent => {
            NativeBlockActionValidationRejection::TransferNullifierAlreadySpent
        }
        NativeTransferStateAdmissionRejection::DuplicateNullifier => {
            NativeBlockActionValidationRejection::TransferDuplicateNullifier
        }
        NativeTransferStateAdmissionRejection::NullifierAlreadyPending => {
            NativeBlockActionValidationRejection::TransferNullifierAlreadyPending
        }
        NativeTransferStateAdmissionRejection::CommitmentZero => {
            NativeBlockActionValidationRejection::TransferCommitmentZero
        }
        NativeTransferStateAdmissionRejection::StablecoinPolicyUnauthorized => {
            NativeBlockActionValidationRejection::TransferStablecoinPolicyUnauthorized
        }
        NativeTransferStateAdmissionRejection::SidecarCiphertextMissing => {
            NativeBlockActionValidationRejection::TransferSidecarCiphertextMissing
        }
        NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMissing => {
            NativeBlockActionValidationRejection::TransferSidecarCiphertextSizeMissing
        }
        NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMismatch => {
            NativeBlockActionValidationRejection::TransferSidecarCiphertextSizeMismatch
        }
    }
}

pub(crate) fn evaluate_native_block_action_validation_start(
    action_count_matches: bool,
    action_hashes_match: bool,
    action_hashes_unique: bool,
    consumed_bridge_messages: BTreeSet<[u8; 48]>,
) -> Result<NativeBlockActionValidationState, NativeBlockActionValidationRejection> {
    evaluate_native_action_hash_admission(NativeActionHashAdmissionInput {
        action_count_matches,
        action_hashes_match,
        action_hashes_unique,
    })
    .map_err(native_block_action_validation_hash_rejection)?;
    Ok(NativeBlockActionValidationState {
        bridge_replay_state: InboundReplayState::new(consumed_bridge_messages, BTreeSet::new()),
        previous_transfer_key: None,
        validated_action_count: 0,
        imported_bridge_replay_count: 0,
    })
}

pub(crate) fn evaluate_native_block_action_validation_step(
    state: &mut NativeBlockActionValidationState,
    step: NativeBlockActionValidationStep,
) -> Result<NativeActionScopeAdmissionRoute, NativeBlockActionValidationRejection> {
    let route = evaluate_native_action_scope_admission(step.scope_input)
        .map_err(native_block_action_validation_scope_rejection)?;
    if !step.payload_valid {
        return Err(native_block_action_validation_payload_rejection(route));
    }

    match route {
        NativeActionScopeAdmissionRoute::Bridge => {
            if let Some(replay_key) = step.bridge_replay_key {
                state
                    .bridge_replay_state
                    .import_one(replay_key)
                    .map_err(|_| NativeBlockActionValidationRejection::BridgeReplayDuplicate)?;
                state.imported_bridge_replay_count = state
                    .imported_bridge_replay_count
                    .checked_add(1)
                    .expect("usize bridge replay count cannot overflow on one block");
            }
        }
        NativeActionScopeAdmissionRoute::Transfer => {
            if !transfer_key_extends_canonical_order(
                state.previous_transfer_key.as_ref(),
                &step.transfer_key,
            ) {
                return Err(NativeBlockActionValidationRejection::TransferOrderInvalid);
            }
            state.previous_transfer_key = Some(step.transfer_key);
            evaluate_native_transfer_state_admission(step.transfer_state_input)
                .map_err(native_block_action_validation_transfer_rejection)?;
        }
        NativeActionScopeAdmissionRoute::CandidateArtifact
        | NativeActionScopeAdmissionRoute::Coinbase => {}
    }

    state.validated_action_count = state
        .validated_action_count
        .checked_add(1)
        .expect("usize validated action count cannot overflow on one block");
    Ok(route)
}

#[cfg(test)]
pub(crate) fn native_block_action_validation_summary(
    state: NativeBlockActionValidationState,
) -> NativeBlockActionValidationSummary {
    NativeBlockActionValidationSummary {
        validated_action_count: state.validated_action_count,
        imported_bridge_replay_count: state.imported_bridge_replay_count,
        last_transfer_key: state.previous_transfer_key,
    }
}

pub(crate) fn native_block_action_validation_error(
    rejection: NativeBlockActionValidationRejection,
) -> anyhow::Error {
    anyhow!(
        "native block action validation failed: {}",
        rejection.label()
    )
}

pub(crate) fn native_block_action_validation_transfer_state_rejection(
    rejection: NativeBlockActionValidationRejection,
) -> Option<NativeTransferStateAdmissionRejection> {
    match rejection {
        NativeBlockActionValidationRejection::TransferUnknownAnchor => {
            Some(NativeTransferStateAdmissionRejection::UnknownAnchor)
        }
        NativeBlockActionValidationRejection::TransferNullifierZero => {
            Some(NativeTransferStateAdmissionRejection::NullifierZero)
        }
        NativeBlockActionValidationRejection::TransferNullifierAlreadySpent => {
            Some(NativeTransferStateAdmissionRejection::NullifierAlreadySpent)
        }
        NativeBlockActionValidationRejection::TransferDuplicateNullifier => {
            Some(NativeTransferStateAdmissionRejection::DuplicateNullifier)
        }
        NativeBlockActionValidationRejection::TransferNullifierAlreadyPending => {
            Some(NativeTransferStateAdmissionRejection::NullifierAlreadyPending)
        }
        NativeBlockActionValidationRejection::TransferCommitmentZero => {
            Some(NativeTransferStateAdmissionRejection::CommitmentZero)
        }
        NativeBlockActionValidationRejection::TransferStablecoinPolicyUnauthorized => {
            Some(NativeTransferStateAdmissionRejection::StablecoinPolicyUnauthorized)
        }
        NativeBlockActionValidationRejection::TransferSidecarCiphertextMissing => {
            Some(NativeTransferStateAdmissionRejection::SidecarCiphertextMissing)
        }
        NativeBlockActionValidationRejection::TransferSidecarCiphertextSizeMissing => {
            Some(NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMissing)
        }
        NativeBlockActionValidationRejection::TransferSidecarCiphertextSizeMismatch => {
            Some(NativeTransferStateAdmissionRejection::SidecarCiphertextSizeMismatch)
        }
        _ => None,
    }
}
