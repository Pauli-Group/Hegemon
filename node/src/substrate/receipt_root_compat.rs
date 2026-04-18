pub(crate) fn is_canonical_experimental_receipt_root_payload(
    payload: &pallet_shielded_pool::types::BlockProofBundle,
) -> bool {
    payload.route().is_experimental()
        && payload.verifier_profile
            == consensus::experimental_native_receipt_root_verifier_profile()
        && payload.receipt_root.is_some()
}

pub(crate) fn ensure_experimental_receipt_root_payload(
    payload: &pallet_shielded_pool::types::BlockProofBundle,
) -> Result<(), String> {
    if !is_canonical_experimental_receipt_root_payload(payload) {
        return Err(format!(
            "explicit experimental receipt_root lane requires canonical native receipt_root artifacts; got proof_mode {:?}, proof_kind {:?}, verifier_profile {}",
            payload.proof_mode,
            payload.proof_kind,
            hex::encode(payload.verifier_profile),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_native_block_proof_payload(
    payload: &pallet_shielded_pool::types::BlockProofBundle,
    native_required: bool,
) -> Result<(), String> {
    if !native_required {
        return Ok(());
    }
    match payload.route().mode {
        pallet_shielded_pool::types::BlockProofMode::ReceiptRoot => {
            ensure_experimental_receipt_root_payload(payload).map_err(|_| {
                format!(
                    "HEGEMON_REQUIRE_NATIVE=1 rejects block proof mode {:?}, proof_kind {:?}, verifier_profile {}; canonical explicit receipt_root or recursive_block is required",
                    payload.proof_mode,
                    payload.proof_kind,
                    hex::encode(payload.verifier_profile),
                )
            })
        }
        pallet_shielded_pool::types::BlockProofMode::RecursiveBlock => {
            if !matches!(
                payload.proof_kind,
                pallet_shielded_pool::types::ProofArtifactKind::RecursiveBlockV1
                    | pallet_shielded_pool::types::ProofArtifactKind::RecursiveBlockV2
            ) {
                return Err(format!(
                    "HEGEMON_REQUIRE_NATIVE=1 rejects recursive_block payload kind {:?}; recursive_block_v1 or recursive_block_v2 is required",
                    payload.proof_kind,
                ));
            }
            if payload.recursive_block.is_none() {
                return Err(
                    "HEGEMON_REQUIRE_NATIVE=1 rejects recursive_block payloads without recursive artifact bytes".to_string(),
                );
            }
            if payload.receipt_root.is_some() {
                return Err(
                    "HEGEMON_REQUIRE_NATIVE=1 rejects recursive_block payloads that also carry receipt_root bytes".to_string(),
                );
            }
            if !payload.commitment_proof.data.is_empty() {
                return Err(
                    "HEGEMON_REQUIRE_NATIVE=1 rejects recursive_block payloads that carry commitment proof bytes".to_string(),
                );
            }
            Ok(())
        }
        pallet_shielded_pool::types::BlockProofMode::InlineTx => Err(format!(
            "HEGEMON_REQUIRE_NATIVE=1 rejects block proof mode {:?}, proof_kind {:?}, verifier_profile {}; a native block-proof lane is required",
            payload.proof_mode,
            payload.proof_kind,
            hex::encode(payload.verifier_profile),
        )),
    }
}

pub(crate) fn receipt_root_lane_requires_embedded_proof_bytes(
    missing_proof_bindings: usize,
) -> Result<(), String> {
    if missing_proof_bindings == 0 {
        return Ok(());
    }
    Err(format!(
        "receipt_root requires embedded proof bytes for every shielded transfer; candidate has {missing_proof_bindings} transfers whose proof bytes are available only via local sidecar state"
    ))
}
