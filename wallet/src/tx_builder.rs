use protocol_shielded_pool::verifier::{ShieldedTransferInputs, StarkVerifier};
use rand::{rngs::OsRng, RngCore};
use superneo_hegemon::{
    build_native_tx_leaf_artifact_bytes_with_auth, decode_native_tx_leaf_artifact_bytes,
};
use transaction_circuit::constants::{MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID};
use transaction_circuit::hashing_pq::{
    bytes48_to_felts, ciphertext_hash_bytes, felts_to_bytes48, merkle_node,
};
use transaction_circuit::note::{InputNoteWitness, OutputNoteWitness};
use transaction_circuit::witness::TransactionWitness;
use transaction_circuit::StablecoinPolicyBinding;
use transaction_circuit::{
    smallwood_accumulator_auth_key_bytes, smallwood_private_auth_intent_digest_bytes,
    SmallwoodAccumulatorAuthOpening, SmallwoodPrivateAuthMode, SmallwoodPrivateAuthWitness,
};

use crate::address::ShieldedAddress;
use crate::error::WalletError;
use crate::multisig::{
    approval_duplicate_tag, next_accumulator_after_approval, MultisigAccountRecord,
};
#[cfg(feature = "rpc-client")]
use crate::node_rpc::NodeRpcClient;
use crate::notes::{MemoPlaintext, NoteCiphertext, NotePlaintext};
use crate::rpc::TransactionBundle;
use crate::store::{
    LocalMultisigAccumulatorOpening, OutgoingDisclosureDraft, SpendableNote, WalletMode,
    WalletStore,
};
use crate::viewing::RecoveredNote;

pub struct Recipient {
    pub address: ShieldedAddress,
    pub value: u64,
    pub asset_id: u64,
    pub memo: MemoPlaintext,
}

#[derive(Debug)]
pub struct BuiltTransaction {
    pub bundle: TransactionBundle,
    pub nullifiers: Vec<[u8; 48]>,
    pub spent_note_indexes: Vec<usize>,
    pub outgoing_disclosures: Vec<OutgoingDisclosureDraft>,
}

#[derive(Debug)]
pub struct PreparedMultisigFinalPlan {
    pub intent_digest: [u8; 48],
    pub value_note_commitment: [u8; 48],
    pub fee: u64,
    outputs: Vec<OutputNoteWitness>,
    ciphertexts: Vec<NoteCiphertext>,
    ciphertext_hashes: Vec<[u8; 48]>,
    outgoing_disclosures: Vec<OutgoingDisclosureDraft>,
}

#[derive(Debug)]
struct SubmissionProofMaterial {
    proof_bytes: Vec<u8>,
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    anchor: [u8; 48],
    balance_slot_asset_ids: [u64; 4],
    fee: u64,
    value_balance: i128,
}

fn submission_proof_material_from_witness(
    witness: &TransactionWitness,
) -> Result<SubmissionProofMaterial, WalletError> {
    submission_proof_material_from_witness_with_auth(
        witness,
        &SmallwoodPrivateAuthWitness::default(),
    )
}

fn submission_proof_material_from_witness_with_auth(
    witness: &TransactionWitness,
    auth: &SmallwoodPrivateAuthWitness,
) -> Result<SubmissionProofMaterial, WalletError> {
    witness
        .validate()
        .map_err(|err| WalletError::InvalidArgument(Box::leak(err.to_string().into_boxed_str())))?;
    let built = build_native_tx_leaf_artifact_bytes_with_auth(witness, auth).map_err(|err| {
        WalletError::Serialization(format!("native tx-leaf artifact generation failed: {err}"))
    })?;
    let decoded = decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes).map_err(|err| {
        WalletError::Serialization(format!("native tx-leaf artifact decode failed: {err}"))
    })?;
    let balance_slot_asset_ids = decoded
        .stark_public_inputs
        .balance_slot_asset_ids
        .clone()
        .try_into()
        .map_err(|_| WalletError::InvalidState("native tx-leaf balance slot count mismatch"))?;
    Ok(SubmissionProofMaterial {
        proof_bytes: built.artifact_bytes,
        nullifiers: decoded.tx.nullifiers,
        commitments: decoded.tx.commitments,
        anchor: decoded.stark_public_inputs.merkle_root,
        balance_slot_asset_ids,
        fee: decoded.stark_public_inputs.fee,
        value_balance: witness.value_balance,
    })
}

/// Pre-flight check: compute nullifiers for notes and verify none are spent on-chain.
///
/// This should be called before `build_transaction` to avoid wasting time on
/// proof generation if any notes are already spent.
///
/// Returns Ok(nullifiers) if all notes are unspent, or Err with the index of the first spent note.
#[cfg(feature = "rpc-client")]
pub async fn precheck_nullifiers(
    store: &WalletStore,
    rpc: &NodeRpcClient,
    recipients: &[Recipient],
    fee: u64,
) -> Result<(), WalletError> {
    let stablecoin = StablecoinPolicyBinding::default();
    precheck_nullifiers_with_binding(store, rpc, recipients, fee, &stablecoin).await
}

/// Pre-flight check that supports stablecoin issuance/burn bindings.
#[cfg(feature = "rpc-client")]
pub async fn precheck_nullifiers_with_binding(
    store: &WalletStore,
    rpc: &NodeRpcClient,
    recipients: &[Recipient],
    fee: u64,
    stablecoin: &StablecoinPolicyBinding,
) -> Result<(), WalletError> {
    let fvk = store
        .full_viewing_key()?
        .ok_or(WalletError::InvalidState("missing viewing key"))?;

    let plan = plan_selections(store, recipients, fee, stablecoin)?;
    let inputs = plan.inputs();

    // Compute nullifiers for selected notes
    let nullifiers: Vec<[u8; 48]> = inputs
        .iter()
        .map(|note| fvk.compute_nullifier(&note.recovered.note.rho, note.position))
        .collect();

    // Check each nullifier against on-chain state
    let spent_status = rpc.check_nullifiers_spent(&nullifiers).await?;

    for (i, is_spent) in spent_status.iter().enumerate() {
        if *is_spent {
            return Err(WalletError::NullifierSpent {
                note_index: inputs[i].index,
            });
        }
    }

    Ok(())
}

pub fn build_transaction(
    store: &WalletStore,
    recipients: &[Recipient],
    fee: u64,
) -> Result<BuiltTransaction, WalletError> {
    let stablecoin = StablecoinPolicyBinding::default();
    build_transaction_with_binding(store, recipients, fee, stablecoin)
}

pub fn build_transaction_with_binding(
    store: &WalletStore,
    recipients: &[Recipient],
    fee: u64,
    stablecoin: StablecoinPolicyBinding,
) -> Result<BuiltTransaction, WalletError> {
    if recipients.is_empty() {
        return Err(WalletError::InvalidArgument("at least one recipient"));
    }
    if recipients.len() > 1 {
        return Err(WalletError::InvalidArgument(
            "wallet supports a single recipient",
        ));
    }
    // Reject zero-value outputs - they waste chain space and could be used for spam
    if recipients.iter().any(|r| r.value == 0) {
        return Err(WalletError::InvalidArgument(
            "recipient value must be greater than zero",
        ));
    }
    if store.mode()? == WalletMode::WatchOnly {
        return Err(WalletError::WatchOnly);
    }
    let derived = store
        .derived_keys()?
        .ok_or(WalletError::InvalidState("missing derived keys"))?;
    let plan = plan_selections(store, recipients, fee, &stablecoin)?;

    let mut rng = OsRng;
    let mut outputs = Vec::new();
    let mut ciphertexts = Vec::new();
    let mut outgoing_disclosures = Vec::new();
    for recipient in recipients {
        let (output, ciphertext, note) = build_output(recipient, &mut rng)?;
        let output_index = outputs.len() as u32;
        let recipient_address = recipient.address.encode()?;
        let memo = if note.memo.as_bytes().is_empty() {
            None
        } else {
            Some(note.memo.clone())
        };
        let commitment = felts_to_bytes48(&output.note.commitment());
        outgoing_disclosures.push(OutgoingDisclosureDraft {
            output_index,
            recipient_address,
            note: output.note.clone(),
            commitment,
            memo,
        });
        outputs.push(output);
        ciphertexts.push(ciphertext);
    }

    append_change_output(
        store,
        &mut outputs,
        &mut ciphertexts,
        &mut outgoing_disclosures,
        plan.output_change,
        plan.output_asset,
        "change would exceed output limit",
        &mut rng,
    )?;
    append_change_output(
        store,
        &mut outputs,
        &mut ciphertexts,
        &mut outgoing_disclosures,
        plan.native_change,
        NATIVE_ASSET_ID,
        "native change would exceed output limit",
        &mut rng,
    )?;

    let tree = store.commitment_tree()?;
    let wallet_root = tree.root();

    let plan_inputs = plan.inputs();
    let mut inputs = Vec::new();
    for note in plan_inputs.iter() {
        let expected_commitment = transaction_circuit::hashing_pq::felts_to_bytes48(
            &note.recovered.note_data.commitment(),
        );
        match store.find_commitment_index(expected_commitment)? {
            Some(index) if index == note.position => {}
            Some(index) => {
                return Err(WalletError::InvalidState(Box::leak(
                    format!(
                        "commitment index mismatch: note position {} != commitment index {}",
                        note.position, index
                    )
                    .into_boxed_str(),
                )));
            }
            None => {
                return Err(WalletError::InvalidState(
                    "note commitment not found in local commitment list",
                ));
            }
        }
        // Get the Merkle authentication path for this note's position
        let auth_path = tree
            .authentication_path(note.position as usize)
            .map_err(|e| {
                WalletError::InvalidState(Box::leak(
                    format!("merkle path error: {}", e).into_boxed_str(),
                ))
            })?;

        let leaf = note.recovered.note_data.commitment();
        let mut current = leaf;
        let mut pos = note.position;
        let mut siblings = Vec::with_capacity(auth_path.len());
        for sibling in auth_path.iter() {
            let felts = bytes48_to_felts(sibling).ok_or(WalletError::InvalidState(
                "non-canonical merkle sibling encoding",
            ))?;
            siblings.push(felts);
            let (left, right) = if pos & 1 == 0 {
                (current, felts)
            } else {
                (felts, current)
            };
            current = merkle_node(left, right);
            pos >>= 1;
        }
        if felts_to_bytes48(&current) != wallet_root {
            return Err(WalletError::InvalidState(
                "merkle path does not match wallet root",
            ));
        }

        // Convert Felt path to MerklePath
        let merkle_path = transaction_circuit::note::MerklePath { siblings };

        // Create input witness with the merkle path
        let mut input_witness = note.recovered.to_input_witness(note.position);
        input_witness.merkle_path = merkle_path;
        inputs.push(input_witness);
    }
    let ciphertext_hashes = ciphertexts
        .iter()
        .map(|ct| ct.to_da_bytes().map(|bytes| ciphertext_hash_bytes(&bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    let witness = TransactionWitness {
        inputs,
        outputs,
        ciphertext_hashes: ciphertext_hashes.clone(),
        sk_spend: derived.spend.to_bytes(),
        merkle_root: tree.root(),
        fee,
        value_balance: 0,
        stablecoin: stablecoin.clone(),
        version: TransactionWitness::default_version_binding(),
    };

    let submission = submission_proof_material_from_witness(&witness)?;

    // Compute binding hash commitment (domain-separated Blake2-256 of public inputs)
    let binding_hash = compute_binding_hash(
        &submission.anchor,
        &submission.nullifiers,
        &submission.commitments,
        &ciphertext_hashes,
        submission.balance_slot_asset_ids,
        submission.fee,
        submission.value_balance,
        to_chain_stablecoin_binding(&witness.stablecoin),
    );
    let bundle = TransactionBundle::new(
        submission.proof_bytes,
        submission.nullifiers.clone(),
        submission.commitments.clone(),
        &ciphertexts,
        submission.anchor,
        binding_hash,
        submission.balance_slot_asset_ids,
        submission.fee,
        submission.value_balance,
        witness.stablecoin.clone(),
    )?;
    let spent_indexes = plan_inputs.iter().map(|note| note.index).collect();

    Ok(BuiltTransaction {
        bundle,
        nullifiers: submission.nullifiers,
        spent_note_indexes: spent_indexes,
        outgoing_disclosures,
    })
}

pub fn build_multisig_initial_accumulator_transaction(
    store: &WalletStore,
    record: &MultisigAccountRecord,
    intent_digest: [u8; 48],
    funding_note_commitment: [u8; 48],
    fee: u64,
) -> Result<BuiltTransaction, WalletError> {
    if store.mode()? == WalletMode::WatchOnly {
        return Err(WalletError::WatchOnly);
    }
    if fee == 0 {
        return Err(WalletError::InvalidArgument(
            "multisig setup fee must be greater than zero",
        ));
    }
    let derived = store
        .derived_keys()?
        .ok_or(WalletError::InvalidState("missing derived keys"))?;
    let funding_note = store
        .spendable_note_by_commitment(&funding_note_commitment)?
        .ok_or(WalletError::InvalidArgument(
            "multisig setup funding note is not spendable",
        ))?;
    if funding_note.asset_id() != NATIVE_ASSET_ID {
        return Err(WalletError::InvalidArgument(
            "multisig setup funding note must use the native asset",
        ));
    }
    if funding_note.value() < fee {
        return Err(WalletError::InsufficientFunds {
            needed: fee,
            available: funding_note.value(),
        });
    }
    let opening = SmallwoodAccumulatorAuthOpening {
        policy_root: record.policy_root,
        intent_digest,
        threshold: record.threshold,
        approval_count: 0,
        signer_slots: [0, 0],
    };
    let mut rng = OsRng;
    let (output, ciphertext, recovered, commitment) =
        build_accumulator_output(store, record, &opening, &mut rng)?;
    let mut outputs = vec![output];
    let mut ciphertexts = vec![ciphertext];
    let mut outgoing_disclosures = Vec::new();
    let change = funding_note.value().saturating_sub(fee);
    append_change_output(
        store,
        &mut outputs,
        &mut ciphertexts,
        &mut outgoing_disclosures,
        change,
        NATIVE_ASSET_ID,
        "multisig setup change would exceed output limit",
        &mut rng,
    )?;
    let ciphertext_hashes = ciphertext_hashes(&ciphertexts)?;
    let tree = store.commitment_tree()?;
    let witness = TransactionWitness {
        inputs: vec![checked_input_witness(store, &tree, &funding_note)?],
        outputs,
        ciphertext_hashes: ciphertext_hashes.clone(),
        sk_spend: derived.spend.to_bytes(),
        merkle_root: tree.root(),
        fee,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    };
    let built = built_transaction_from_witness(
        &witness,
        &SmallwoodPrivateAuthWitness::default(),
        &ciphertexts,
        vec![funding_note.index],
        outgoing_disclosures,
    )?;
    store.record_local_note_opening_with_multisig(
        recovered,
        Some(local_accumulator_metadata(record, &opening)),
    )?;
    debug_assert_eq!(built.bundle.commitments.first().copied(), Some(commitment));
    Ok(built)
}

pub fn build_multisig_approval_transaction(
    store: &WalletStore,
    record: &MultisigAccountRecord,
    current_accumulator_commitment: [u8; 48],
    signer_note_commitment: [u8; 48],
    fee: u64,
) -> Result<BuiltTransaction, WalletError> {
    if store.mode()? == WalletMode::WatchOnly {
        return Err(WalletError::WatchOnly);
    }
    let derived = store
        .derived_keys()?
        .ok_or(WalletError::InvalidState("missing derived keys"))?;
    let current_note = store
        .spendable_note_by_commitment(&current_accumulator_commitment)?
        .ok_or(WalletError::InvalidArgument(
            "current multisig accumulator note is not spendable",
        ))?;
    let signer_note = store
        .spendable_note_by_commitment(&signer_note_commitment)?
        .ok_or(WalletError::InvalidArgument(
            "multisig signer value note is not spendable",
        ))?;
    if current_note.index == signer_note.index {
        return Err(WalletError::InvalidArgument(
            "multisig approval requires distinct accumulator and signer notes",
        ));
    }
    if signer_note.value() == 0 || signer_note.value() < fee {
        return Err(WalletError::InsufficientFunds {
            needed: fee.max(1),
            available: signer_note.value(),
        });
    }

    let current_local = store
        .local_note_opening_by_commitment(&current_accumulator_commitment)?
        .ok_or(WalletError::InvalidArgument(
            "missing local multisig accumulator opening",
        ))?;
    let current_meta =
        current_local
            .multisig_accumulator
            .as_ref()
            .ok_or(WalletError::InvalidArgument(
                "local note opening is not a multisig accumulator",
            ))?;
    ensure_accumulator_matches_record(record, current_meta)?;
    if current_meta.approval_count >= record.threshold {
        return Err(WalletError::InvalidArgument(
            "multisig accumulator already satisfies threshold",
        ));
    }
    let current_opening = current_meta.to_smallwood();
    ensure_accumulator_note_auth(&current_note, &current_opening)?;

    let signer_id = store.local_multisig_signer_id()?;
    if !record.policy_signers.contains(&signer_id) {
        return Err(WalletError::InvalidArgument(
            "local signer is not in hidden multisig policy",
        ));
    }
    let duplicate_tag = approval_duplicate_tag(
        &record.public.account_id,
        &current_opening.intent_digest,
        signer_id,
    );
    let (next_opening, duplicate_inverse) =
        next_accumulator_after_approval(&current_opening, signer_id)?;
    let mut rng = OsRng;
    let (next_output, next_ciphertext, next_recovered, _next_commitment) =
        build_accumulator_output(store, record, &next_opening, &mut rng)?;
    let mut outputs = vec![next_output];
    let mut ciphertexts = vec![next_ciphertext];
    let mut outgoing_disclosures = Vec::new();
    let signer_change = signer_note.value().saturating_sub(fee);
    append_change_output(
        store,
        &mut outputs,
        &mut ciphertexts,
        &mut outgoing_disclosures,
        signer_change,
        signer_note.asset_id(),
        "multisig approval change would exceed output limit",
        &mut rng,
    )?;

    let tree = store.commitment_tree()?;
    let inputs = vec![
        checked_input_witness(store, &tree, &current_note)?,
        checked_input_witness(store, &tree, &signer_note)?,
    ];
    let ciphertext_hashes = ciphertext_hashes(&ciphertexts)?;
    let witness = TransactionWitness {
        inputs,
        outputs,
        ciphertext_hashes,
        sk_spend: derived.spend.to_bytes(),
        merkle_root: tree.root(),
        fee,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    };
    let auth = SmallwoodPrivateAuthWitness {
        mode: SmallwoodPrivateAuthMode::ApprovalStep,
        accumulator: current_opening,
        next_accumulator: next_opening.clone(),
        policy_signers: record.policy_signers,
        signer_id,
        duplicate_inverse,
    };
    let built = built_transaction_from_witness(
        &witness,
        &auth,
        &ciphertexts,
        vec![current_note.index, signer_note.index],
        outgoing_disclosures,
    )?;
    store.record_local_note_opening_with_multisig(
        next_recovered,
        Some(local_accumulator_metadata(record, &next_opening)),
    )?;
    let _ = duplicate_tag;
    Ok(built)
}

pub fn prepare_multisig_final_plan(
    store: &WalletStore,
    record: &MultisigAccountRecord,
    value_note_commitment: [u8; 48],
    recipients: &[Recipient],
    fee: u64,
) -> Result<PreparedMultisigFinalPlan, WalletError> {
    if store.mode()? == WalletMode::WatchOnly {
        return Err(WalletError::WatchOnly);
    }
    if recipients.is_empty() {
        return Err(WalletError::InvalidArgument("at least one recipient"));
    }
    if recipients.len() > 1 {
        return Err(WalletError::InvalidArgument(
            "multisig final spend supports a single recipient",
        ));
    }
    let value_note = store
        .spendable_note_by_commitment(&value_note_commitment)?
        .ok_or(WalletError::InvalidArgument(
            "multisig value note is not spendable",
        ))?;
    let recipient = &recipients[0];
    if recipient.value == 0 {
        return Err(WalletError::InvalidArgument(
            "recipient value must be greater than zero",
        ));
    }
    if recipient.asset_id != value_note.asset_id() {
        return Err(WalletError::InvalidArgument(
            "multisig final recipient asset mismatch",
        ));
    }
    let required = if value_note.asset_id() == NATIVE_ASSET_ID {
        recipient
            .value
            .checked_add(fee)
            .ok_or(WalletError::InvalidArgument("fee overflow"))?
    } else {
        if fee != 0 {
            return Err(WalletError::InvalidArgument(
                "non-native multisig final spend cannot pay a native fee in the proven two-input shape",
            ));
        }
        recipient.value
    };
    if value_note.value() < required {
        return Err(WalletError::InsufficientFunds {
            needed: required,
            available: value_note.value(),
        });
    }

    let mut rng = OsRng;
    let (recipient_output, recipient_ciphertext, recipient_note) =
        build_output(recipient, &mut rng)?;
    let mut outputs = vec![recipient_output];
    let mut ciphertexts = vec![recipient_ciphertext];
    let recipient_address = recipient.address.encode()?;
    let memo = if recipient_note.memo.as_bytes().is_empty() {
        None
    } else {
        Some(recipient_note.memo.clone())
    };
    let mut outgoing_disclosures = vec![OutgoingDisclosureDraft {
        output_index: 0,
        recipient_address,
        note: outputs[0].note.clone(),
        commitment: felts_to_bytes48(&outputs[0].note.commitment()),
        memo,
    }];
    let change = value_note.value().saturating_sub(required);
    append_change_output(
        store,
        &mut outputs,
        &mut ciphertexts,
        &mut outgoing_disclosures,
        change,
        value_note.asset_id(),
        "multisig final change would exceed output limit",
        &mut rng,
    )?;
    let ciphertext_hashes = ciphertext_hashes(&ciphertexts)?;

    let dummy_accumulator = SmallwoodAccumulatorAuthOpening {
        policy_root: record.policy_root,
        intent_digest: [0u8; 48],
        threshold: record.threshold,
        approval_count: record.threshold,
        signer_slots: threshold_signer_slots(record),
    };
    let dummy_acc_note = dummy_accumulator_input(&dummy_accumulator)?;
    let mut value_input = value_note.recovered.to_input_witness(value_note.position);
    value_input.merkle_path = Default::default();
    let witness = TransactionWitness {
        inputs: vec![value_input, dummy_acc_note],
        outputs: outputs.clone(),
        ciphertext_hashes: ciphertext_hashes.clone(),
        sk_spend: store
            .derived_keys()?
            .ok_or(WalletError::InvalidState("missing derived keys"))?
            .spend
            .to_bytes(),
        merkle_root: store.commitment_tree()?.root(),
        fee,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    };
    let auth = SmallwoodPrivateAuthWitness {
        mode: SmallwoodPrivateAuthMode::FinalThresholdSpend,
        accumulator: dummy_accumulator,
        next_accumulator: SmallwoodAccumulatorAuthOpening::default(),
        policy_signers: record.policy_signers,
        signer_id: 0,
        duplicate_inverse: 0,
    };
    let intent_digest = smallwood_private_auth_intent_digest_bytes(&witness, &auth)
        .map_err(|err| WalletError::InvalidState(Box::leak(err.to_string().into_boxed_str())))?;
    Ok(PreparedMultisigFinalPlan {
        intent_digest,
        value_note_commitment,
        fee,
        outputs,
        ciphertexts,
        ciphertext_hashes,
        outgoing_disclosures,
    })
}

pub fn build_multisig_final_transaction_from_plan(
    store: &WalletStore,
    record: &MultisigAccountRecord,
    plan: &PreparedMultisigFinalPlan,
    accumulator_commitment: [u8; 48],
) -> Result<BuiltTransaction, WalletError> {
    if store.mode()? == WalletMode::WatchOnly {
        return Err(WalletError::WatchOnly);
    }
    let derived = store
        .derived_keys()?
        .ok_or(WalletError::InvalidState("missing derived keys"))?;
    let value_note = store
        .spendable_note_by_commitment(&plan.value_note_commitment)?
        .ok_or(WalletError::InvalidArgument(
            "multisig value note is not spendable",
        ))?;
    let accumulator_note = store
        .spendable_note_by_commitment(&accumulator_commitment)?
        .ok_or(WalletError::InvalidArgument(
            "threshold multisig accumulator note is not spendable",
        ))?;
    if value_note.index == accumulator_note.index {
        return Err(WalletError::InvalidArgument(
            "multisig final spend requires distinct value and accumulator notes",
        ));
    }
    let local = store
        .local_note_opening_by_commitment(&accumulator_commitment)?
        .ok_or(WalletError::InvalidArgument(
            "missing local threshold accumulator opening",
        ))?;
    let meta = local
        .multisig_accumulator
        .as_ref()
        .ok_or(WalletError::InvalidArgument(
            "local note opening is not a multisig accumulator",
        ))?;
    ensure_accumulator_matches_record(record, meta)?;
    if meta.intent_digest != plan.intent_digest {
        return Err(WalletError::InvalidArgument(
            "multisig final plan digest does not match threshold accumulator",
        ));
    }
    if meta.approval_count < record.threshold {
        return Err(WalletError::InvalidArgument(
            "multisig threshold accumulator is incomplete",
        ));
    }
    let accumulator_opening = meta.to_smallwood();
    ensure_accumulator_note_auth(&accumulator_note, &accumulator_opening)?;

    let tree = store.commitment_tree()?;
    let inputs = vec![
        checked_input_witness(store, &tree, &value_note)?,
        checked_input_witness(store, &tree, &accumulator_note)?,
    ];
    let witness = TransactionWitness {
        inputs,
        outputs: plan.outputs.clone(),
        ciphertext_hashes: plan.ciphertext_hashes.clone(),
        sk_spend: derived.spend.to_bytes(),
        merkle_root: tree.root(),
        fee: plan.fee,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    };
    let auth = SmallwoodPrivateAuthWitness {
        mode: SmallwoodPrivateAuthMode::FinalThresholdSpend,
        accumulator: accumulator_opening,
        next_accumulator: SmallwoodAccumulatorAuthOpening::default(),
        policy_signers: record.policy_signers,
        signer_id: 0,
        duplicate_inverse: 0,
    };
    let digest = smallwood_private_auth_intent_digest_bytes(&witness, &auth)
        .map_err(|err| WalletError::InvalidState(Box::leak(err.to_string().into_boxed_str())))?;
    if digest != plan.intent_digest {
        return Err(WalletError::InvalidArgument(
            "multisig final statement digest drifted",
        ));
    }
    built_transaction_from_witness(
        &witness,
        &auth,
        &plan.ciphertexts,
        vec![value_note.index, accumulator_note.index],
        plan.outgoing_disclosures.clone(),
    )
}

pub fn build_stablecoin_burn(
    store: &WalletStore,
    asset_id: u64,
    fee: u64,
    stablecoin: StablecoinPolicyBinding,
) -> Result<BuiltTransaction, WalletError> {
    if store.mode()? == WalletMode::WatchOnly {
        return Err(WalletError::WatchOnly);
    }
    if !stablecoin.enabled {
        return Err(WalletError::InvalidArgument(
            "stablecoin binding required for burn",
        ));
    }
    if asset_id == NATIVE_ASSET_ID {
        return Err(WalletError::InvalidArgument(
            "stablecoin asset id cannot be native",
        ));
    }
    if stablecoin.asset_id != asset_id {
        return Err(WalletError::InvalidArgument(
            "stablecoin binding asset id mismatch",
        ));
    }
    if stablecoin.issuance_delta <= 0 {
        return Err(WalletError::InvalidArgument(
            "stablecoin burn requires positive issuance delta",
        ));
    }
    let burn_amount = u64::try_from(stablecoin.issuance_delta)
        .map_err(|_| WalletError::InvalidArgument("stablecoin burn amount exceeds u64 range"))?;

    let derived = store
        .derived_keys()?
        .ok_or(WalletError::InvalidState("missing derived keys"))?;
    let fvk = store
        .full_viewing_key()?
        .ok_or(WalletError::InvalidState("missing viewing key"))?;

    let mut spendable_asset = store.spendable_notes(asset_id)?;
    let asset_selection = select_notes(&mut spendable_asset, burn_amount)?;
    let asset_change = asset_selection.total.saturating_sub(burn_amount);

    let mut native_selection = Selection::empty();
    let mut native_change = 0;
    if fee > 0 {
        let mut spendable_native = store.spendable_notes(NATIVE_ASSET_ID)?;
        native_selection = select_notes(&mut spendable_native, fee)?;
        native_change = native_selection.total.saturating_sub(fee);
    }

    let total_inputs = asset_selection.spent.len() + native_selection.spent.len();
    if total_inputs > MAX_INPUTS {
        return Err(WalletError::TooManyInputs {
            needed: total_inputs,
            max: MAX_INPUTS,
        });
    }

    let outputs_needed = burn_output_batch_count(asset_change, native_change);
    if outputs_needed > MAX_OUTPUTS {
        return Err(WalletError::InvalidArgument(
            "burn outputs exceed output limit",
        ));
    }

    let mut rng = OsRng;
    let mut outputs = Vec::new();
    let mut ciphertexts = Vec::new();
    let mut outgoing_disclosures = Vec::new();

    append_change_output(
        store,
        &mut outputs,
        &mut ciphertexts,
        &mut outgoing_disclosures,
        asset_change,
        asset_id,
        "burn asset change would exceed output limit",
        &mut rng,
    )?;
    append_change_output(
        store,
        &mut outputs,
        &mut ciphertexts,
        &mut outgoing_disclosures,
        native_change,
        NATIVE_ASSET_ID,
        "burn native change would exceed output limit",
        &mut rng,
    )?;

    let tree = store.commitment_tree()?;
    let mut inputs = Vec::new();
    let mut nullifiers = Vec::new();
    let mut spent_notes = Vec::new();
    spent_notes.extend_from_slice(&asset_selection.spent);
    spent_notes.extend_from_slice(&native_selection.spent);

    for note in spent_notes.iter() {
        let auth_path = tree
            .authentication_path(note.position as usize)
            .map_err(|e| {
                WalletError::InvalidState(Box::leak(
                    format!("merkle path error: {}", e).into_boxed_str(),
                ))
            })?;

        let mut siblings = Vec::with_capacity(auth_path.len());
        for sibling in auth_path.iter() {
            let felts = bytes48_to_felts(sibling).ok_or(WalletError::InvalidState(
                "non-canonical merkle sibling encoding",
            ))?;
            siblings.push(felts);
        }

        let merkle_path = transaction_circuit::note::MerklePath { siblings };
        let mut input_witness = note.recovered.to_input_witness(note.position);
        input_witness.merkle_path = merkle_path;
        inputs.push(input_witness);
        nullifiers.push(fvk.compute_nullifier(&note.recovered.note.rho, note.position));
    }

    let ciphertext_hashes = ciphertexts
        .iter()
        .map(|ct| ct.to_da_bytes().map(|bytes| ciphertext_hash_bytes(&bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    let witness = TransactionWitness {
        inputs,
        outputs,
        ciphertext_hashes: ciphertext_hashes.clone(),
        sk_spend: derived.spend.to_bytes(),
        merkle_root: tree.root(),
        fee,
        value_balance: 0,
        stablecoin: stablecoin.clone(),
        version: TransactionWitness::default_version_binding(),
    };

    let submission = submission_proof_material_from_witness(&witness)?;

    let binding_hash = compute_binding_hash(
        &submission.anchor,
        &submission.nullifiers,
        &submission.commitments,
        &ciphertext_hashes,
        submission.balance_slot_asset_ids,
        submission.fee,
        submission.value_balance,
        to_chain_stablecoin_binding(&witness.stablecoin),
    );
    let bundle = TransactionBundle::new(
        submission.proof_bytes,
        submission.nullifiers.clone(),
        submission.commitments.clone(),
        &ciphertexts,
        submission.anchor,
        binding_hash,
        submission.balance_slot_asset_ids,
        submission.fee,
        submission.value_balance,
        witness.stablecoin.clone(),
    )?;
    let spent_indexes = spent_notes.iter().map(|note| note.index).collect();

    Ok(BuiltTransaction {
        bundle,
        nullifiers: submission.nullifiers,
        spent_note_indexes: spent_indexes,
        outgoing_disclosures,
    })
}

/// Build a consolidation transaction that spends exactly two notes and creates exactly one output.
///
/// This is used by `wallet::execute_consolidation` to safely parallelize merges without the
/// automatic coin-selection selecting unintended inputs.
pub fn build_consolidation_transaction(
    store: &WalletStore,
    note_a: &SpendableNote,
    note_b: &SpendableNote,
    fee: u64,
) -> Result<BuiltTransaction, WalletError> {
    if store.mode()? == WalletMode::WatchOnly {
        return Err(WalletError::WatchOnly);
    }
    if note_a.index == note_b.index {
        return Err(WalletError::InvalidArgument(
            "consolidation notes must be distinct",
        ));
    }
    if note_a.recovered.note.asset_id != NATIVE_ASSET_ID
        || note_b.recovered.note.asset_id != NATIVE_ASSET_ID
    {
        return Err(WalletError::InvalidArgument(
            "consolidation only supports native asset notes",
        ));
    }

    let total = note_a.value().saturating_add(note_b.value());
    if total <= fee {
        return Err(WalletError::InsufficientFunds {
            needed: fee,
            available: total,
        });
    }

    let derived = store
        .derived_keys()?
        .ok_or(WalletError::InvalidState("missing derived keys"))?;
    let fvk = store
        .full_viewing_key()?
        .ok_or(WalletError::InvalidState("missing viewing key"))?;

    let address = store.primary_address()?;
    let recipient = Recipient {
        address: address.clone(),
        value: total.saturating_sub(fee),
        asset_id: NATIVE_ASSET_ID,
        memo: MemoPlaintext::default(),
    };

    let mut rng = OsRng;
    let (output, ciphertext, note) = build_output(&recipient, &mut rng)?;
    let recipient_address = address.encode()?;
    let memo = if note.memo.as_bytes().is_empty() {
        None
    } else {
        Some(note.memo.clone())
    };
    let commitment = felts_to_bytes48(&output.note.commitment());
    let outgoing_disclosures = vec![OutgoingDisclosureDraft {
        output_index: 0,
        recipient_address,
        note: output.note.clone(),
        commitment,
        memo,
    }];

    let tree = store.commitment_tree()?;
    let wallet_root = tree.root();

    let mut inputs = Vec::new();
    let mut nullifiers = Vec::new();
    for note in [note_a.clone(), note_b.clone()] {
        let expected_commitment = transaction_circuit::hashing_pq::felts_to_bytes48(
            &note.recovered.note_data.commitment(),
        );
        match store.find_commitment_index(expected_commitment)? {
            Some(index) if index == note.position => {}
            Some(index) => {
                return Err(WalletError::InvalidState(Box::leak(
                    format!(
                        "commitment index mismatch: note position {} != commitment index {}",
                        note.position, index
                    )
                    .into_boxed_str(),
                )));
            }
            None => {
                return Err(WalletError::InvalidState(
                    "note commitment not found in local commitment list",
                ));
            }
        }

        let auth_path = tree
            .authentication_path(note.position as usize)
            .map_err(|e| {
                WalletError::InvalidState(Box::leak(
                    format!("merkle path error: {}", e).into_boxed_str(),
                ))
            })?;

        let mut siblings = Vec::with_capacity(auth_path.len());
        let mut current = note.recovered.note_data.commitment();
        let mut pos = note.position;
        for sibling in auth_path.iter() {
            let felts = bytes48_to_felts(sibling).ok_or(WalletError::InvalidState(
                "non-canonical merkle sibling encoding",
            ))?;
            siblings.push(felts);
            let (left, right) = if pos & 1 == 0 {
                (current, felts)
            } else {
                (felts, current)
            };
            current = merkle_node(left, right);
            pos >>= 1;
        }
        if felts_to_bytes48(&current) != wallet_root {
            return Err(WalletError::InvalidState(
                "merkle path does not match wallet root",
            ));
        }

        let merkle_path = transaction_circuit::note::MerklePath { siblings };
        let mut input_witness = note.recovered.to_input_witness(note.position);
        input_witness.merkle_path = merkle_path;
        inputs.push(input_witness);
        nullifiers.push(fvk.compute_nullifier(&note.recovered.note.rho, note.position));
    }

    let ciphertext_hashes = vec![ciphertext_hash_bytes(&ciphertext.to_da_bytes()?)];
    let witness = TransactionWitness {
        inputs,
        outputs: vec![output],
        ciphertext_hashes: ciphertext_hashes.clone(),
        sk_spend: derived.spend.to_bytes(),
        merkle_root: tree.root(),
        fee,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    };

    let submission = submission_proof_material_from_witness(&witness)?;

    let binding_hash = compute_binding_hash(
        &submission.anchor,
        &submission.nullifiers,
        &submission.commitments,
        &ciphertext_hashes,
        submission.balance_slot_asset_ids,
        submission.fee,
        submission.value_balance,
        to_chain_stablecoin_binding(&witness.stablecoin),
    );
    let bundle = TransactionBundle::new(
        submission.proof_bytes,
        submission.nullifiers.clone(),
        submission.commitments.clone(),
        &[ciphertext],
        submission.anchor,
        binding_hash,
        submission.balance_slot_asset_ids,
        submission.fee,
        submission.value_balance,
        witness.stablecoin.clone(),
    )?;

    Ok(BuiltTransaction {
        bundle,
        nullifiers: submission.nullifiers,
        spent_note_indexes: vec![note_a.index, note_b.index],
        outgoing_disclosures,
    })
}

/// Compute binding hash for transaction commitment.
///
/// Returns the 64-byte binding hash of the public inputs:
/// Blake2_256(domain || 0 || message) || Blake2_256(domain || 1 || message)
fn compute_binding_hash(
    anchor: &[u8; 48],
    nullifiers: &[[u8; 48]],
    commitments: &[[u8; 48]],
    ciphertext_hashes: &[[u8; 48]],
    balance_slot_asset_ids: [u64; 4],
    fee: u64,
    value_balance: i128,
    stablecoin: Option<protocol_shielded_pool::types::StablecoinPolicyBinding>,
) -> [u8; 64] {
    let inputs = ShieldedTransferInputs {
        anchor: *anchor,
        nullifiers: nullifiers.to_vec(),
        commitments: commitments.to_vec(),
        ciphertext_hashes: ciphertext_hashes.to_vec(),
        balance_slot_asset_ids,
        fee,
        value_balance,
        stablecoin,
    };
    StarkVerifier::compute_binding_hash(&inputs).data
}

fn to_chain_stablecoin_binding(
    binding: &StablecoinPolicyBinding,
) -> Option<protocol_shielded_pool::types::StablecoinPolicyBinding> {
    binding
        .enabled
        .then_some(protocol_shielded_pool::types::StablecoinPolicyBinding {
            asset_id: binding.asset_id,
            policy_hash: binding.policy_hash,
            oracle_commitment: binding.oracle_commitment,
            attestation_commitment: binding.attestation_commitment,
            issuance_delta: binding.issuance_delta,
            policy_version: binding.policy_version,
        })
}

fn built_transaction_from_witness(
    witness: &TransactionWitness,
    auth: &SmallwoodPrivateAuthWitness,
    ciphertexts: &[NoteCiphertext],
    spent_note_indexes: Vec<usize>,
    outgoing_disclosures: Vec<OutgoingDisclosureDraft>,
) -> Result<BuiltTransaction, WalletError> {
    let submission = submission_proof_material_from_witness_with_auth(witness, auth)?;
    let binding_hash = compute_binding_hash(
        &submission.anchor,
        &submission.nullifiers,
        &submission.commitments,
        &witness.ciphertext_hashes,
        submission.balance_slot_asset_ids,
        submission.fee,
        submission.value_balance,
        to_chain_stablecoin_binding(&witness.stablecoin),
    );
    let bundle = TransactionBundle::new(
        submission.proof_bytes,
        submission.nullifiers.clone(),
        submission.commitments.clone(),
        ciphertexts,
        submission.anchor,
        binding_hash,
        submission.balance_slot_asset_ids,
        submission.fee,
        submission.value_balance,
        witness.stablecoin.clone(),
    )?;
    Ok(BuiltTransaction {
        bundle,
        nullifiers: submission.nullifiers,
        spent_note_indexes,
        outgoing_disclosures,
    })
}

fn checked_input_witness(
    store: &WalletStore,
    tree: &state_merkle::CommitmentTree,
    note: &SpendableNote,
) -> Result<InputNoteWitness, WalletError> {
    let expected_commitment =
        transaction_circuit::hashing_pq::felts_to_bytes48(&note.recovered.note_data.commitment());
    match store.find_commitment_index(expected_commitment)? {
        Some(index) if index == note.position => {}
        Some(index) => {
            return Err(WalletError::InvalidState(Box::leak(
                format!(
                    "commitment index mismatch: note position {} != commitment index {}",
                    note.position, index
                )
                .into_boxed_str(),
            )));
        }
        None => {
            return Err(WalletError::InvalidState(
                "note commitment not found in local commitment list",
            ));
        }
    }

    let auth_path = tree
        .authentication_path(note.position as usize)
        .map_err(|e| {
            WalletError::InvalidState(Box::leak(
                format!("merkle path error: {e}").into_boxed_str(),
            ))
        })?;
    let wallet_root = tree.root();
    let mut current = note.recovered.note_data.commitment();
    let mut pos = note.position;
    let mut siblings = Vec::with_capacity(auth_path.len());
    for sibling in auth_path.iter() {
        let felts = bytes48_to_felts(sibling).ok_or(WalletError::InvalidState(
            "non-canonical merkle sibling encoding",
        ))?;
        siblings.push(felts);
        let (left, right) = if pos & 1 == 0 {
            (current, felts)
        } else {
            (felts, current)
        };
        current = merkle_node(left, right);
        pos >>= 1;
    }
    if felts_to_bytes48(&current) != wallet_root {
        return Err(WalletError::InvalidState(
            "merkle path does not match wallet root",
        ));
    }
    let mut input = note.recovered.to_input_witness(note.position);
    input.merkle_path = transaction_circuit::note::MerklePath { siblings };
    Ok(input)
}

fn build_accumulator_output(
    store: &WalletStore,
    record: &MultisigAccountRecord,
    opening: &SmallwoodAccumulatorAuthOpening,
    rng: &mut OsRng,
) -> Result<(OutputNoteWitness, NoteCiphertext, RecoveredNote, [u8; 48]), WalletError> {
    if opening.policy_root != record.policy_root || opening.threshold != record.threshold {
        return Err(WalletError::InvalidArgument(
            "multisig accumulator opening does not match account policy",
        ));
    }
    let auth_key = smallwood_accumulator_auth_key_bytes(opening)
        .map_err(|err| WalletError::InvalidState(Box::leak(err.to_string().into_boxed_str())))?;
    let mut address = store.primary_address()?;
    address.pk_auth = auth_key;
    let note = NotePlaintext::random(0, NATIVE_ASSET_ID, MemoPlaintext::default(), rng);
    let ciphertext = NoteCiphertext::encrypt(&address, &note, rng)?;
    let note_data = note.to_note_data(address.pk_recipient, auth_key);
    let commitment = felts_to_bytes48(&note_data.commitment());
    let recovered = RecoveredNote {
        diversifier_index: address.diversifier_index,
        note,
        note_data: note_data.clone(),
        address,
    };
    Ok((
        OutputNoteWitness { note: note_data },
        ciphertext,
        recovered,
        commitment,
    ))
}

fn ciphertext_hashes(ciphertexts: &[NoteCiphertext]) -> Result<Vec<[u8; 48]>, WalletError> {
    ciphertexts
        .iter()
        .map(|ct| ct.to_da_bytes().map(|bytes| ciphertext_hash_bytes(&bytes)))
        .collect()
}

fn local_accumulator_metadata(
    record: &MultisigAccountRecord,
    opening: &SmallwoodAccumulatorAuthOpening,
) -> LocalMultisigAccumulatorOpening {
    LocalMultisigAccumulatorOpening {
        account_id: record.public.account_id,
        policy_root: opening.policy_root,
        intent_digest: opening.intent_digest,
        threshold: opening.threshold,
        approval_count: opening.approval_count,
        signer_slots: opening.signer_slots,
    }
}

fn ensure_accumulator_matches_record(
    record: &MultisigAccountRecord,
    meta: &LocalMultisigAccumulatorOpening,
) -> Result<(), WalletError> {
    if meta.account_id != record.public.account_id
        || meta.policy_root != record.policy_root
        || meta.threshold != record.threshold
    {
        return Err(WalletError::InvalidArgument(
            "local multisig accumulator does not match account record",
        ));
    }
    Ok(())
}

fn ensure_accumulator_note_auth(
    note: &SpendableNote,
    opening: &SmallwoodAccumulatorAuthOpening,
) -> Result<(), WalletError> {
    if note.value() != 0 || note.asset_id() != NATIVE_ASSET_ID {
        return Err(WalletError::InvalidArgument(
            "multisig accumulator note must be zero-value native asset",
        ));
    }
    let expected = smallwood_accumulator_auth_key_bytes(opening)
        .map_err(|err| WalletError::InvalidState(Box::leak(err.to_string().into_boxed_str())))?;
    if note.recovered.note_data.pk_auth != expected {
        return Err(WalletError::InvalidArgument(
            "multisig accumulator note auth key mismatch",
        ));
    }
    Ok(())
}

fn threshold_signer_slots(record: &MultisigAccountRecord) -> [u64; 2] {
    if record.threshold == 1 {
        [record.policy_signers[0], 0]
    } else {
        record.policy_signers
    }
}

fn dummy_accumulator_input(
    opening: &SmallwoodAccumulatorAuthOpening,
) -> Result<InputNoteWitness, WalletError> {
    let auth_key = smallwood_accumulator_auth_key_bytes(opening)
        .map_err(|err| WalletError::InvalidState(Box::leak(err.to_string().into_boxed_str())))?;
    Ok(InputNoteWitness {
        note: transaction_circuit::note::NoteData {
            value: 0,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [0u8; 32],
            pk_auth: auth_key,
            rho: [7u8; 32],
            r: [8u8; 32],
        },
        position: 0,
        rho_seed: [7u8; 32],
        merkle_path: Default::default(),
    })
}

struct Selection {
    spent: Vec<SpendableNote>,
    total: u64,
}

impl Selection {
    fn empty() -> Self {
        Self {
            spent: Vec::new(),
            total: 0,
        }
    }
}

struct SelectionPlan {
    output_asset: u64,
    output_selection: Selection,
    output_change: u64,
    native_selection: Selection,
    native_change: u64,
}

impl SelectionPlan {
    fn inputs(&self) -> Vec<SpendableNote> {
        let mut inputs = Vec::new();
        inputs.extend_from_slice(&self.output_selection.spent);
        inputs.extend_from_slice(&self.native_selection.spent);
        inputs
    }
}

fn transfer_output_batch_count(
    recipient_count: usize,
    output_change: u64,
    native_change: u64,
) -> usize {
    recipient_count + usize::from(output_change > 0) + usize::from(native_change > 0)
}

fn burn_output_batch_count(asset_change: u64, native_change: u64) -> usize {
    usize::from(asset_change > 0) + usize::from(native_change > 0)
}

fn change_output_address(store: &WalletStore) -> Result<ShieldedAddress, WalletError> {
    store.primary_address()
}

fn append_change_output<R: RngCore + ?Sized>(
    store: &WalletStore,
    outputs: &mut Vec<OutputNoteWitness>,
    ciphertexts: &mut Vec<NoteCiphertext>,
    outgoing_disclosures: &mut Vec<OutgoingDisclosureDraft>,
    value: u64,
    asset_id: u64,
    limit_error: &'static str,
    rng: &mut R,
) -> Result<(), WalletError> {
    if value == 0 {
        return Ok(());
    }
    if outputs.len() >= MAX_OUTPUTS {
        return Err(WalletError::InvalidArgument(limit_error));
    }

    let address = change_output_address(store)?;
    let note = NotePlaintext::random(value, asset_id, MemoPlaintext::default(), rng);
    let ciphertext = NoteCiphertext::encrypt(&address, &note, rng)?;
    let note_data = note.to_note_data(address.pk_recipient, address.pk_auth);
    let output_index = outputs.len() as u32;
    let recipient_address = address.encode()?;
    let memo = if note.memo.as_bytes().is_empty() {
        None
    } else {
        Some(note.memo.clone())
    };
    let commitment = felts_to_bytes48(&note_data.commitment());
    outgoing_disclosures.push(OutgoingDisclosureDraft {
        output_index,
        recipient_address,
        note: note_data.clone(),
        commitment,
        memo,
    });
    ciphertexts.push(ciphertext);
    outputs.push(OutputNoteWitness { note: note_data });
    Ok(())
}

fn select_notes(notes: &mut [SpendableNote], target: u64) -> Result<Selection, WalletError> {
    // Sort by value descending - prefer larger notes to minimize input count
    notes.sort_by_key(|n| std::cmp::Reverse(n.value()));
    let mut total = 0u64;
    let mut spent = Vec::new();
    for note in notes.iter() {
        spent.push(note.clone());
        total = total.saturating_add(note.value());
        if total >= target {
            break;
        }
    }
    if total < target {
        return Err(WalletError::InsufficientFunds {
            needed: target,
            available: total,
        });
    }
    Ok(Selection { spent, total })
}

fn select_notes_exact(
    notes: &[SpendableNote],
    target: u64,
    max_inputs: usize,
) -> Result<Selection, WalletError> {
    if target == 0 {
        return Ok(Selection::empty());
    }
    if max_inputs == 0 {
        return Err(WalletError::TooManyInputs { needed: 1, max: 0 });
    }

    if let Some(note) = notes.iter().find(|note| note.value() == target) {
        return Ok(Selection {
            spent: vec![note.clone()],
            total: target,
        });
    }

    if max_inputs < 2 {
        return Err(WalletError::InvalidArgument(
            "native fee must be paid with an exact note when stablecoin change is required",
        ));
    }

    for (i, note_a) in notes.iter().enumerate() {
        for note_b in notes.iter().skip(i + 1) {
            let total = note_a.value().saturating_add(note_b.value());
            if total == target {
                return Ok(Selection {
                    spent: vec![note_a.clone(), note_b.clone()],
                    total,
                });
            }
        }
    }

    Err(WalletError::InvalidArgument(
        "native fee must be paid with an exact note when stablecoin change is required",
    ))
}

fn plan_selections(
    store: &WalletStore,
    recipients: &[Recipient],
    fee: u64,
    stablecoin: &StablecoinPolicyBinding,
) -> Result<SelectionPlan, WalletError> {
    if recipients.is_empty() {
        return Err(WalletError::InvalidArgument("at least one recipient"));
    }
    if recipients.len() > 1 {
        return Err(WalletError::InvalidArgument(
            "wallet supports a single recipient",
        ));
    }
    if recipients.iter().any(|r| r.value == 0) {
        return Err(WalletError::InvalidArgument(
            "recipient value must be greater than zero",
        ));
    }

    let output_asset = recipients[0].asset_id;
    if recipients
        .iter()
        .any(|recipient| recipient.asset_id != output_asset)
    {
        return Err(WalletError::InvalidArgument(
            "multi-asset recipients not supported",
        ));
    }

    if stablecoin.enabled {
        if output_asset == NATIVE_ASSET_ID {
            return Err(WalletError::InvalidArgument(
                "stablecoin binding cannot be used with native asset outputs",
            ));
        }
        if stablecoin.asset_id != output_asset {
            return Err(WalletError::InvalidArgument(
                "stablecoin binding asset id mismatch",
            ));
        }
        if stablecoin.issuance_delta == 0 {
            return Err(WalletError::InvalidArgument(
                "stablecoin issuance delta must be non-zero",
            ));
        }
    }

    let output_total: u64 = recipients.iter().map(|r| r.value).sum();

    if output_asset == NATIVE_ASSET_ID {
        let required = output_total
            .checked_add(fee)
            .ok_or(WalletError::InvalidArgument("fee overflow"))?;
        let mut spendable = store.spendable_notes(NATIVE_ASSET_ID)?;
        let selection = select_notes(&mut spendable, required)?;
        if selection.spent.len() > MAX_INPUTS {
            return Err(WalletError::TooManyInputs {
                needed: selection.spent.len(),
                max: MAX_INPUTS,
            });
        }
        let output_change = selection.total.saturating_sub(required);
        let outputs_needed = transfer_output_batch_count(recipients.len(), output_change, 0);
        if outputs_needed > MAX_OUTPUTS {
            return Err(WalletError::InvalidArgument(
                "change would exceed output limit",
            ));
        }
        return Ok(SelectionPlan {
            output_asset,
            output_selection: selection,
            output_change,
            native_selection: Selection::empty(),
            native_change: 0,
        });
    }

    let issuance_delta = if stablecoin.enabled {
        stablecoin.issuance_delta
    } else {
        0
    };
    let required_output_i128 = output_total as i128 + issuance_delta;
    if required_output_i128 < 0 {
        return Err(WalletError::InvalidArgument(
            "issuance exceeds output amount",
        ));
    }
    let required_output = required_output_i128 as u64;
    let output_selection = if required_output == 0 {
        Selection::empty()
    } else {
        let mut spendable = store.spendable_notes(output_asset)?;
        select_notes(&mut spendable, required_output)?
    };
    let output_change = output_selection.total.saturating_sub(required_output);

    let mut native_selection = Selection::empty();
    let mut native_change = 0;
    if fee > 0 {
        let available_inputs = MAX_INPUTS.saturating_sub(output_selection.spent.len());
        if available_inputs == 0 {
            return Err(WalletError::TooManyInputs {
                needed: output_selection.spent.len() + 1,
                max: MAX_INPUTS,
            });
        }
        let spendable = store.spendable_notes(NATIVE_ASSET_ID)?;
        if output_change > 0 {
            native_selection = select_notes_exact(&spendable, fee, available_inputs)?;
        } else {
            let mut spendable = spendable;
            native_selection = select_notes(&mut spendable, fee)?;
            native_change = native_selection.total.saturating_sub(fee);
        }
    }

    let total_inputs = output_selection.spent.len() + native_selection.spent.len();
    if total_inputs > MAX_INPUTS {
        return Err(WalletError::TooManyInputs {
            needed: total_inputs,
            max: MAX_INPUTS,
        });
    }

    let outputs_needed =
        transfer_output_batch_count(recipients.len(), output_change, native_change);
    if outputs_needed > MAX_OUTPUTS {
        return Err(WalletError::InvalidArgument(
            "multi-asset transfer exceeds output limit",
        ));
    }

    Ok(SelectionPlan {
        output_asset,
        output_selection,
        output_change,
        native_selection,
        native_change,
    })
}

fn build_output(
    recipient: &Recipient,
    rng: &mut OsRng,
) -> Result<(OutputNoteWitness, NoteCiphertext, NotePlaintext), WalletError> {
    let note = NotePlaintext::random(
        recipient.value,
        recipient.asset_id,
        recipient.memo.clone(),
        rng,
    );
    let ciphertext = NoteCiphertext::encrypt(&recipient.address, &note, rng)?;
    Ok((
        OutputNoteWitness {
            note: note.to_note_data(recipient.address.pk_recipient, recipient.address.pk_auth),
        },
        ciphertext,
        note,
    ))
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};
    use serde::Deserialize;
    use superneo_hegemon::{
        decode_native_tx_leaf_artifact_bytes, verify_native_tx_leaf_artifact_bytes,
    };
    use tempfile::{tempdir, TempDir};

    use protocol_shielded_pool::verifier::{ShieldedTransferInputs, StarkVerifier};
    use transaction_circuit::hashing_pq::{ciphertext_hash_bytes, felts_to_bytes48};

    use super::*;

    const LEAN_WALLET_OUTPUT_BATCH_STABLE_ASSET: u64 = 7;

    #[derive(Debug, Deserialize)]
    struct LeanWalletOutputBatchVectorFile {
        schema_version: u32,
        max_outputs: usize,
        wallet_output_batch_cases: Vec<LeanWalletOutputBatchCase>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanWalletOutputBatchCase {
        name: String,
        kind: String,
        recipient_count: usize,
        recipient_total: u64,
        fee: u64,
        selected_asset_total: u64,
        selected_native_total: u64,
        issuance_delta: i128,
        burn_amount: u64,
        private_witness_seed: u64,
        local_metadata_seed: u64,
        alternate_private_witness_seed: u64,
        alternate_local_metadata_seed: u64,
        expected_output_count: usize,
        expected_recipient_output_count: usize,
        expected_change_output_count: usize,
        expected_change_diversifier_index: u32,
        expected_change_diversifier_cursor_independent: bool,
        expected_valid: bool,
        expected_within_max_outputs: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct WalletOutputBatchProjection {
        output_count: usize,
        recipient_output_count: usize,
        change_diversifier_indices: Vec<u32>,
    }

    struct WalletOutputBatchFixture {
        _dir: TempDir,
        sender: WalletStore,
        recipient: WalletStore,
    }

    fn seeded_sender_and_recipient(seed: u64) -> (WalletStore, WalletStore, rand::rngs::StdRng) {
        let dir = tempdir().unwrap();
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "passphrase").unwrap();
        let recipient_store = WalletStore::create_full(&recipient_path, "passphrase").unwrap();

        let sender_fvk = sender.full_viewing_key().unwrap().unwrap();
        let sender_addr = sender_fvk.incoming().shielded_address(0).unwrap();
        let mut rng = StdRng::seed_from_u64(seed);

        for (position, value) in [(0u64, 150_000_000u64), (1u64, 160_000_000u64)] {
            let note = NotePlaintext::random(value, 0, MemoPlaintext::default(), &mut rng);
            let ciphertext = NoteCiphertext::encrypt(&sender_addr, &note, &mut rng).unwrap();
            let recovered = sender_fvk.decrypt_note(&ciphertext).unwrap();
            let commitment = felts_to_bytes48(&recovered.note_data.commitment());
            sender
                .append_commitments(&[(position, commitment)])
                .unwrap();
            sender.register_ciphertext_index(position).unwrap();
            sender
                .record_recovered_note(recovered, position, position)
                .unwrap();
        }

        (sender, recipient_store, rng)
    }

    fn stablecoin_binding(issuance_delta: i128) -> StablecoinPolicyBinding {
        StablecoinPolicyBinding {
            enabled: true,
            asset_id: LEAN_WALLET_OUTPUT_BATCH_STABLE_ASSET,
            policy_hash: [1u8; 48],
            oracle_commitment: [2u8; 48],
            attestation_commitment: [3u8; 48],
            issuance_delta,
            policy_version: 1,
        }
    }

    fn seed_recovered_note(
        store: &WalletStore,
        asset_id: u64,
        value: u64,
        position: u64,
        rng: &mut StdRng,
    ) {
        if value == 0 {
            return;
        }
        let fvk = store.full_viewing_key().unwrap().unwrap();
        let address = fvk.incoming().shielded_address(position as u32).unwrap();
        let note = NotePlaintext::random(value, asset_id, MemoPlaintext::default(), rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, rng).unwrap();
        let recovered = fvk.decrypt_note(&ciphertext).unwrap();
        let commitment = felts_to_bytes48(&recovered.note_data.commitment());
        store.append_commitments(&[(position, commitment)]).unwrap();
        store.register_ciphertext_index(position).unwrap();
        store
            .record_recovered_note(recovered, position, position)
            .unwrap();
    }

    fn test_multisig_record(store: &WalletStore) -> MultisigAccountRecord {
        let local_signer = store.local_multisig_signer_id().unwrap();
        let other_signer = crate::multisig::signer_id_from_spend_key(&[91u8; 32]);
        let public = store
            .create_multisig_account(1, [local_signer, other_signer])
            .unwrap();
        store
            .multisig_account_record(&public.account_id)
            .unwrap()
            .unwrap()
    }

    fn apply_built_outputs(store: &WalletStore, built: &BuiltTransaction) {
        let start = store.next_commitment_index().unwrap();
        let entries: Vec<_> = built
            .bundle
            .commitments
            .iter()
            .enumerate()
            .map(|(idx, commitment)| (start + idx as u64, *commitment))
            .collect();
        store.append_commitments(&entries).unwrap();
        let ciphertexts = built.bundle.decode_notes().unwrap();
        let fvk = store.full_viewing_key().unwrap().unwrap();
        let recovered = ciphertexts
            .iter()
            .map(|ciphertext| Some(fvk.decrypt_note(ciphertext).unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            store
                .apply_ciphertext_batch(store.next_ciphertext_index().unwrap(), recovered)
                .unwrap(),
            ciphertexts.len()
        );
    }

    #[test]
    fn multisig_setup_requires_spendable_native_funding_note() {
        let dir = tempdir().unwrap();
        let sender_path = dir.path().join("sender.wallet");
        let sender = WalletStore::create_full(&sender_path, "passphrase").unwrap();
        let record = test_multisig_record(&sender);
        let err = build_multisig_initial_accumulator_transaction(
            &sender, &record, [3u8; 48], [9u8; 48], 1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("funding note is not spendable"));

        let mut rng = StdRng::seed_from_u64(912);
        seed_recovered_note(&sender, 7, 10, 0, &mut rng);
        let non_native = sender.spendable_notes(7).unwrap();
        let non_native_commitment =
            felts_to_bytes48(&non_native[0].recovered.note_data.commitment());
        let err = build_multisig_initial_accumulator_transaction(
            &sender,
            &record,
            [3u8; 48],
            non_native_commitment,
            1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must use the native asset"));
    }

    #[test]
    fn multisig_setup_rejects_zero_fee_and_insufficient_funding() {
        let dir = tempdir().unwrap();
        let sender_path = dir.path().join("sender.wallet");
        let sender = WalletStore::create_full(&sender_path, "passphrase").unwrap();
        let record = test_multisig_record(&sender);
        let mut rng = StdRng::seed_from_u64(913);
        seed_recovered_note(&sender, NATIVE_ASSET_ID, 2, 0, &mut rng);
        let notes = sender.spendable_notes(NATIVE_ASSET_ID).unwrap();
        let funding_commitment = felts_to_bytes48(&notes[0].recovered.note_data.commitment());

        let err = build_multisig_initial_accumulator_transaction(
            &sender,
            &record,
            [4u8; 48],
            funding_commitment,
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("fee must be greater than zero"));

        let err = build_multisig_initial_accumulator_transaction(
            &sender,
            &record,
            [4u8; 48],
            funding_commitment,
            3,
        )
        .unwrap_err();
        assert!(matches!(err, WalletError::InsufficientFunds { .. }));
    }

    #[test]
    fn multisig_setup_bundle_has_fee_nullifier_and_reconciled_accumulator() {
        let dir = tempdir().unwrap();
        let sender_path = dir.path().join("sender.wallet");
        let sender = WalletStore::create_full(&sender_path, "passphrase").unwrap();
        let record = test_multisig_record(&sender);
        let mut rng = StdRng::seed_from_u64(914);
        seed_recovered_note(&sender, NATIVE_ASSET_ID, 9, 0, &mut rng);
        let notes = sender.spendable_notes(NATIVE_ASSET_ID).unwrap();
        let funding_commitment = felts_to_bytes48(&notes[0].recovered.note_data.commitment());

        let setup = build_multisig_initial_accumulator_transaction(
            &sender,
            &record,
            [5u8; 48],
            funding_commitment,
            4,
        )
        .unwrap();
        assert_eq!(setup.bundle.fee, 4);
        assert_eq!(setup.spent_note_indexes.len(), 1);
        assert!(setup
            .bundle
            .nullifiers
            .iter()
            .any(|nullifier| nullifier.iter().any(|byte| *byte != 0)));
        apply_built_outputs(&sender, &setup);

        let accumulator_commitment = setup.bundle.commitments[0];
        let local = sender
            .local_note_opening_by_commitment(&accumulator_commitment)
            .unwrap()
            .unwrap();
        assert_eq!(local.commitment, accumulator_commitment);
        assert_eq!(
            felts_to_bytes48(&local.note.note_data.commitment()),
            accumulator_commitment
        );
        assert!(sender
            .spendable_note_by_commitment(&accumulator_commitment)
            .unwrap()
            .is_some());
    }

    fn wallet_output_batch_fixture(
        case: &LeanWalletOutputBatchCase,
        private_witness_seed: u64,
        local_metadata_seed: u64,
    ) -> WalletOutputBatchFixture {
        let dir = tempdir().unwrap();
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "passphrase").unwrap();
        let recipient = WalletStore::create_full(&recipient_path, "passphrase").unwrap();
        let mut rng = StdRng::seed_from_u64(private_witness_seed);
        let mut position = 0u64;

        match case.kind.as_str() {
            "native" => {
                seed_recovered_note(
                    &sender,
                    NATIVE_ASSET_ID,
                    case.selected_asset_total,
                    position,
                    &mut rng,
                );
            }
            "stablecoin" => {
                seed_recovered_note(
                    &sender,
                    LEAN_WALLET_OUTPUT_BATCH_STABLE_ASSET,
                    case.selected_asset_total,
                    position,
                    &mut rng,
                );
                position += usize::from(case.selected_asset_total > 0) as u64;
                seed_recovered_note(
                    &sender,
                    NATIVE_ASSET_ID,
                    case.selected_native_total,
                    position,
                    &mut rng,
                );
            }
            "burn" => {
                seed_recovered_note(
                    &sender,
                    LEAN_WALLET_OUTPUT_BATCH_STABLE_ASSET,
                    case.selected_asset_total,
                    position,
                    &mut rng,
                );
                position += usize::from(case.selected_asset_total > 0) as u64;
                seed_recovered_note(
                    &sender,
                    NATIVE_ASSET_ID,
                    case.selected_native_total,
                    position,
                    &mut rng,
                );
            }
            "consolidation" => {
                let first = case.selected_asset_total / 2 + (case.selected_asset_total % 2);
                let second = case.selected_asset_total.saturating_sub(first);
                seed_recovered_note(&sender, NATIVE_ASSET_ID, first, 0, &mut rng);
                seed_recovered_note(&sender, NATIVE_ASSET_ID, second, 1, &mut rng);
            }
            other => panic!("unknown Lean wallet output-batch kind {other}"),
        }

        for _ in 0..(local_metadata_seed % 3) {
            sender.reserve_internal_address().unwrap();
        }

        WalletOutputBatchFixture {
            _dir: dir,
            sender,
            recipient,
        }
    }

    #[test]
    fn multisig_builders_create_approval_and_final_transactions_with_hidden_policy_shape() {
        let dir = tempdir().unwrap();
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "passphrase").unwrap();
        let recipient_store = WalletStore::create_full(&recipient_path, "passphrase").unwrap();
        let mut rng = StdRng::seed_from_u64(910);
        seed_recovered_note(&sender, NATIVE_ASSET_ID, 12, 0, &mut rng);
        seed_recovered_note(&sender, NATIVE_ASSET_ID, 25, 1, &mut rng);
        seed_recovered_note(&sender, NATIVE_ASSET_ID, 60, 2, &mut rng);
        let notes = sender.spendable_notes(NATIVE_ASSET_ID).unwrap();
        let setup_funding_commitment = felts_to_bytes48(&notes[0].recovered.note_data.commitment());
        let signer_note_commitment = felts_to_bytes48(&notes[1].recovered.note_data.commitment());
        let value_note_commitment = felts_to_bytes48(&notes[2].recovered.note_data.commitment());

        let local_signer = sender.local_multisig_signer_id().unwrap();
        let other_signer = crate::multisig::signer_id_from_spend_key(&[77u8; 32]);
        let public = sender
            .create_multisig_account(1, [local_signer, other_signer])
            .unwrap();
        let record = sender
            .multisig_account_record(&public.account_id)
            .unwrap()
            .unwrap();
        let recipient = Recipient {
            address: recipient_store.primary_address().unwrap(),
            value: 40,
            asset_id: NATIVE_ASSET_ID,
            memo: MemoPlaintext::new(b"private multisig final".to_vec()),
        };
        let final_plan =
            prepare_multisig_final_plan(&sender, &record, value_note_commitment, &[recipient], 0)
                .unwrap();

        let setup = build_multisig_initial_accumulator_transaction(
            &sender,
            &record,
            final_plan.intent_digest,
            setup_funding_commitment,
            3,
        )
        .unwrap();
        assert_eq!(setup.spent_note_indexes.len(), 1);
        assert_eq!(setup.bundle.fee, 3);
        assert!(setup
            .bundle
            .nullifiers
            .iter()
            .any(|nullifier| nullifier.iter().any(|byte| *byte != 0)));
        apply_built_outputs(&sender, &setup);
        let initial_accumulator_commitment = setup.bundle.commitments[0];
        let initial_tracked = sender
            .spendable_note_by_commitment(&initial_accumulator_commitment)
            .unwrap()
            .unwrap();
        assert_eq!(initial_tracked.recovered.note_data.pk_auth, {
            let local = sender
                .local_note_opening_by_commitment(&initial_accumulator_commitment)
                .unwrap()
                .unwrap();
            local.note.note_data.pk_auth
        });

        let approval = build_multisig_approval_transaction(
            &sender,
            &record,
            initial_accumulator_commitment,
            signer_note_commitment,
            0,
        )
        .unwrap();
        assert_eq!(approval.spent_note_indexes.len(), 2);
        apply_built_outputs(&sender, &approval);
        let threshold_accumulator_commitment = approval.bundle.commitments[0];
        let threshold_local = sender
            .local_note_opening_by_commitment(&threshold_accumulator_commitment)
            .unwrap()
            .unwrap();
        let threshold_meta = threshold_local.multisig_accumulator.unwrap();
        assert_eq!(threshold_meta.intent_digest, final_plan.intent_digest);
        assert_eq!(threshold_meta.approval_count, 1);
        assert_eq!(threshold_meta.signer_slots, [local_signer, 0]);

        let final_tx = build_multisig_final_transaction_from_plan(
            &sender,
            &record,
            &final_plan,
            threshold_accumulator_commitment,
        )
        .unwrap();
        assert_eq!(final_tx.spent_note_indexes.len(), 2);
        assert_eq!(final_tx.bundle.commitments.len(), final_plan.outputs.len());
        let public_json = serde_json::to_string(&final_tx.bundle).unwrap();
        assert!(!public_json.contains("policy_signers"));
        assert!(!public_json.contains("policy_root"));
        assert!(!public_json.contains("approval_count"));
        assert!(!public_json.contains("signer_slots"));

        decode_native_tx_leaf_artifact_bytes(&approval.bundle.proof_bytes).unwrap();
        decode_native_tx_leaf_artifact_bytes(&final_tx.bundle.proof_bytes).unwrap();
    }

    #[test]
    fn multisig_final_rejects_plan_digest_drift() {
        let dir = tempdir().unwrap();
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "passphrase").unwrap();
        let recipient_store = WalletStore::create_full(&recipient_path, "passphrase").unwrap();
        let mut rng = StdRng::seed_from_u64(911);
        seed_recovered_note(&sender, NATIVE_ASSET_ID, 12, 0, &mut rng);
        seed_recovered_note(&sender, NATIVE_ASSET_ID, 25, 1, &mut rng);
        seed_recovered_note(&sender, NATIVE_ASSET_ID, 60, 2, &mut rng);
        let notes = sender.spendable_notes(NATIVE_ASSET_ID).unwrap();
        let setup_funding_commitment = felts_to_bytes48(&notes[0].recovered.note_data.commitment());
        let signer_note_commitment = felts_to_bytes48(&notes[1].recovered.note_data.commitment());
        let value_note_commitment = felts_to_bytes48(&notes[2].recovered.note_data.commitment());
        let local_signer = sender.local_multisig_signer_id().unwrap();
        let other_signer = crate::multisig::signer_id_from_spend_key(&[78u8; 32]);
        let public = sender
            .create_multisig_account(1, [local_signer, other_signer])
            .unwrap();
        let record = sender
            .multisig_account_record(&public.account_id)
            .unwrap()
            .unwrap();
        let recipient = Recipient {
            address: recipient_store.primary_address().unwrap(),
            value: 40,
            asset_id: NATIVE_ASSET_ID,
            memo: MemoPlaintext::default(),
        };
        let mut final_plan =
            prepare_multisig_final_plan(&sender, &record, value_note_commitment, &[recipient], 0)
                .unwrap();
        let setup = build_multisig_initial_accumulator_transaction(
            &sender,
            &record,
            final_plan.intent_digest,
            setup_funding_commitment,
            3,
        )
        .unwrap();
        apply_built_outputs(&sender, &setup);
        let approval = build_multisig_approval_transaction(
            &sender,
            &record,
            setup.bundle.commitments[0],
            signer_note_commitment,
            0,
        )
        .unwrap();
        apply_built_outputs(&sender, &approval);
        final_plan.intent_digest[0] ^= 1;

        let err = build_multisig_final_transaction_from_plan(
            &sender,
            &record,
            &final_plan,
            approval.bundle.commitments[0],
        )
        .unwrap_err();
        assert!(err.to_string().contains("digest does not match"));
    }

    fn split_recipient_values(total: u64, count: usize) -> Vec<u64> {
        if count == 0 {
            return Vec::new();
        }
        let base = total / count as u64;
        let mut remainder = total % count as u64;
        (0..count)
            .map(|_| {
                let extra = u64::from(remainder > 0);
                remainder = remainder.saturating_sub(1);
                base + extra
            })
            .collect()
    }

    fn recipients_for_case(
        fixture: &WalletOutputBatchFixture,
        case: &LeanWalletOutputBatchCase,
        private_witness_seed: u64,
    ) -> Vec<Recipient> {
        let asset_id = match case.kind.as_str() {
            "native" => NATIVE_ASSET_ID,
            "stablecoin" => LEAN_WALLET_OUTPUT_BATCH_STABLE_ASSET,
            other => panic!("case {other} does not use explicit recipients"),
        };
        split_recipient_values(case.recipient_total, case.recipient_count)
            .into_iter()
            .enumerate()
            .map(|(index, value)| Recipient {
                address: fixture.recipient.primary_address().unwrap(),
                value,
                asset_id,
                memo: MemoPlaintext::new(
                    format!(
                        "lean-output-batch:{}:{}:{}",
                        case.name, private_witness_seed, index
                    )
                    .into_bytes(),
                ),
            })
            .collect()
    }

    fn projection_from_counts(
        fixture: &WalletOutputBatchFixture,
        output_count: usize,
        recipient_output_count: usize,
    ) -> Result<WalletOutputBatchProjection, WalletError> {
        let change_output_count =
            output_count
                .checked_sub(recipient_output_count)
                .ok_or(WalletError::InvalidState(
                    "recipient output count exceeds output count",
                ))?;
        let change_diversifier_indices = if change_output_count == 0 {
            Vec::new()
        } else {
            let index = change_output_address(&fixture.sender)?.diversifier_index;
            vec![index; change_output_count]
        };
        Ok(WalletOutputBatchProjection {
            output_count,
            recipient_output_count,
            change_diversifier_indices,
        })
    }

    fn planned_wallet_output_batch_case_projection(
        case: &LeanWalletOutputBatchCase,
        private_witness_seed: u64,
        local_metadata_seed: u64,
    ) -> Result<WalletOutputBatchProjection, WalletError> {
        let fixture = wallet_output_batch_fixture(case, private_witness_seed, local_metadata_seed);
        match case.kind.as_str() {
            "native" => {
                let recipients = recipients_for_case(&fixture, case, private_witness_seed);
                let stablecoin = StablecoinPolicyBinding::default();
                let plan = plan_selections(&fixture.sender, &recipients, case.fee, &stablecoin)?;
                projection_from_counts(
                    &fixture,
                    transfer_output_batch_count(recipients.len(), plan.output_change, 0),
                    recipients.len(),
                )
            }
            "stablecoin" => {
                let recipients = recipients_for_case(&fixture, case, private_witness_seed);
                let binding = stablecoin_binding(case.issuance_delta);
                let plan = plan_selections(&fixture.sender, &recipients, case.fee, &binding)?;
                projection_from_counts(
                    &fixture,
                    transfer_output_batch_count(
                        recipients.len(),
                        plan.output_change,
                        plan.native_change,
                    ),
                    recipients.len(),
                )
            }
            "burn" => {
                assert_eq!(
                    case.issuance_delta,
                    i128::from(case.burn_amount),
                    "burn vectors bind issuance_delta to burn_amount"
                );
                let mut spendable_asset = fixture
                    .sender
                    .spendable_notes(LEAN_WALLET_OUTPUT_BATCH_STABLE_ASSET)?;
                let asset_selection = select_notes(&mut spendable_asset, case.burn_amount)?;
                let asset_change = asset_selection.total.saturating_sub(case.burn_amount);

                let mut native_selection = Selection::empty();
                let mut native_change = 0;
                if case.fee > 0 {
                    let mut spendable_native = fixture.sender.spendable_notes(NATIVE_ASSET_ID)?;
                    native_selection = select_notes(&mut spendable_native, case.fee)?;
                    native_change = native_selection.total.saturating_sub(case.fee);
                }

                let total_inputs = asset_selection.spent.len() + native_selection.spent.len();
                if total_inputs > MAX_INPUTS {
                    return Err(WalletError::TooManyInputs {
                        needed: total_inputs,
                        max: MAX_INPUTS,
                    });
                }
                let outputs_needed = burn_output_batch_count(asset_change, native_change);
                if outputs_needed > MAX_OUTPUTS {
                    return Err(WalletError::InvalidArgument(
                        "burn outputs exceed output limit",
                    ));
                }
                projection_from_counts(&fixture, outputs_needed, 0)
            }
            "consolidation" => {
                let notes = fixture.sender.spendable_notes(NATIVE_ASSET_ID)?;
                assert!(
                    notes.len() >= 2,
                    "consolidation vector must seed two spendable notes"
                );
                let total = notes[0].value().saturating_add(notes[1].value());
                if total <= case.fee {
                    return Err(WalletError::InsufficientFunds {
                        needed: case.fee,
                        available: total,
                    });
                }
                projection_from_counts(&fixture, 1, 0)
            }
            other => panic!("unknown Lean wallet output-batch kind {other}"),
        }
    }

    #[test]
    fn sidecar_binding_hash_matches_protocol_verifier() {
        let dir = tempdir().unwrap();
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "passphrase").unwrap();
        let recipient_store = WalletStore::create_full(&recipient_path, "passphrase").unwrap();

        let sender_fvk = sender.full_viewing_key().unwrap().unwrap();
        let sender_addr = sender_fvk.incoming().shielded_address(0).unwrap();
        let mut rng = StdRng::seed_from_u64(123);

        for (position, value) in [(0u64, 150_000_000u64), (1u64, 160_000_000u64)] {
            let note = NotePlaintext::random(value, 0, MemoPlaintext::default(), &mut rng);
            let ciphertext = NoteCiphertext::encrypt(&sender_addr, &note, &mut rng).unwrap();
            let recovered = sender_fvk.decrypt_note(&ciphertext).unwrap();
            let commitment = felts_to_bytes48(&recovered.note_data.commitment());
            sender
                .append_commitments(&[(position, commitment)])
                .unwrap();
            sender.register_ciphertext_index(position).unwrap();
            sender
                .record_recovered_note(recovered, position, position)
                .unwrap();
        }

        let recipient = Recipient {
            address: recipient_store.primary_address().unwrap(),
            value: 100_000_000,
            asset_id: 0,
            memo: MemoPlaintext::new(b"sidecar regression".to_vec()),
        };
        let stablecoin = StablecoinPolicyBinding::default();
        let plan = plan_selections(&sender, &[recipient], 0, &stablecoin).unwrap();

        let mut rng = OsRng;
        let mut outputs = Vec::new();
        let mut ciphertexts = Vec::new();
        let recipient = Recipient {
            address: recipient_store.primary_address().unwrap(),
            value: 100_000_000,
            asset_id: 0,
            memo: MemoPlaintext::new(b"sidecar regression".to_vec()),
        };
        let (output, ciphertext, _) = build_output(&recipient, &mut rng).unwrap();
        outputs.push(output);
        ciphertexts.push(ciphertext);

        if plan.output_change > 0 {
            let address = sender.reserve_internal_address().unwrap();
            let note = NotePlaintext::random(
                plan.output_change,
                plan.output_asset,
                MemoPlaintext::default(),
                &mut rng,
            );
            let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
            let note_data = note.to_note_data(address.pk_recipient, address.pk_auth);
            outputs.push(OutputNoteWitness { note: note_data });
            ciphertexts.push(ciphertext);
        }

        let nullifiers = {
            let fvk = sender.full_viewing_key().unwrap().unwrap();
            plan.inputs()
                .iter()
                .map(|note| fvk.compute_nullifier(&note.recovered.note.rho, note.position))
                .collect::<Vec<_>>()
        };
        let commitments = outputs
            .iter()
            .map(|output| felts_to_bytes48(&output.note.commitment()))
            .collect::<Vec<_>>();
        let anchor = sender.commitment_tree().unwrap().root();
        let ciphertext_hashes = ciphertexts
            .iter()
            .map(|note| {
                note.to_da_bytes()
                    .map(|bytes| ciphertext_hash_bytes(&bytes))
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let balance_slot_asset_ids = [0u64, u64::MAX, u64::MAX, u64::MAX];
        let binding_hash = compute_binding_hash(
            &anchor,
            &nullifiers,
            &commitments,
            &ciphertext_hashes,
            balance_slot_asset_ids,
            0,
            0,
            to_chain_stablecoin_binding(&stablecoin),
        );
        let bundle = TransactionBundle::new(
            Vec::new(),
            nullifiers.clone(),
            commitments.clone(),
            &ciphertexts,
            anchor,
            binding_hash,
            balance_slot_asset_ids,
            0,
            0,
            stablecoin.clone(),
        )
        .unwrap();
        let decoded = bundle.decode_notes().unwrap();
        let decoded_hashes = decoded
            .iter()
            .map(|note| {
                note.to_da_bytes()
                    .map(|bytes| ciphertext_hash_bytes(&bytes))
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let stablecoin = bundle.stablecoin.enabled.then_some(
            protocol_shielded_pool::types::StablecoinPolicyBinding {
                asset_id: bundle.stablecoin.asset_id,
                policy_hash: bundle.stablecoin.policy_hash,
                oracle_commitment: bundle.stablecoin.oracle_commitment,
                attestation_commitment: bundle.stablecoin.attestation_commitment,
                issuance_delta: bundle.stablecoin.issuance_delta,
                policy_version: bundle.stablecoin.policy_version,
            },
        );
        let inputs = ShieldedTransferInputs {
            anchor: bundle.anchor,
            nullifiers: bundle.nullifiers.clone(),
            commitments: bundle.commitments.clone(),
            ciphertext_hashes: decoded_hashes.clone(),
            balance_slot_asset_ids: bundle.balance_slot_asset_ids,
            fee: bundle.fee,
            value_balance: bundle.value_balance,
            stablecoin,
        };
        let expected = StarkVerifier::compute_binding_hash(&inputs);

        assert_eq!(decoded_hashes, ciphertext_hashes);
        assert_eq!(bundle.binding_hash, expected.data);
    }

    #[test]
    fn build_transaction_can_emit_native_tx_leaf_payloads() {
        let (sender, recipient_store, _) = seeded_sender_and_recipient(777);
        let recipient_fvk = recipient_store.full_viewing_key().unwrap().unwrap();

        let recipient = Recipient {
            address: recipient_store.primary_address().unwrap(),
            value: 160_000_000,
            asset_id: 0,
            memo: MemoPlaintext::new(b"native tx leaf".to_vec()),
        };
        let built = build_transaction(&sender, &[recipient], 0).unwrap();
        assert_eq!(built.bundle.commitments.len(), 1);
        assert_eq!(built.outgoing_disclosures.len(), 1);
        assert_eq!(
            built.outgoing_disclosures[0].commitment,
            built.bundle.commitments[0]
        );

        let decoded_notes = built.bundle.decode_notes().unwrap();
        assert_eq!(decoded_notes.len(), 1);
        let recovered = recipient_fvk.decrypt_note(&decoded_notes[0]).unwrap();
        let recovered_commitment = felts_to_bytes48(&recovered.note_data.commitment());
        assert_eq!(recovered_commitment, built.bundle.commitments[0]);
        assert_eq!(
            felts_to_bytes48(&built.outgoing_disclosures[0].note.commitment()),
            recovered_commitment
        );

        let decoded = decode_native_tx_leaf_artifact_bytes(&built.bundle.proof_bytes)
            .expect("native tx-leaf payload should decode");
        assert_eq!(decoded.tx.commitments, built.bundle.commitments);
        let decoded_ciphertext_hashes = decoded_notes
            .iter()
            .map(|note| {
                note.to_da_bytes()
                    .map(|bytes| ciphertext_hash_bytes(&bytes))
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("decoded notes should serialize to DA bytes");
        assert_eq!(decoded.tx.ciphertext_hashes.len(), decoded_notes.len());
        assert_eq!(decoded.tx.ciphertext_hashes, decoded_ciphertext_hashes);
        let artifact_balance_slot_asset_ids: [u64; 4] = decoded
            .stark_public_inputs
            .balance_slot_asset_ids
            .clone()
            .try_into()
            .expect("artifact balance slot count");
        assert_eq!(decoded.stark_public_inputs.merkle_root, built.bundle.anchor);
        assert_eq!(decoded.tx.nullifiers, built.bundle.nullifiers);
        assert_eq!(decoded.tx.commitments, built.bundle.commitments);
        assert_eq!(decoded.tx.ciphertext_hashes, decoded_ciphertext_hashes);
        assert_eq!(
            artifact_balance_slot_asset_ids,
            built.bundle.balance_slot_asset_ids
        );
        assert_eq!(decoded.stark_public_inputs.fee, built.bundle.fee);
        let artifact_binding_inputs = ShieldedTransferInputs {
            anchor: decoded.stark_public_inputs.merkle_root,
            nullifiers: decoded.tx.nullifiers.clone(),
            commitments: decoded.tx.commitments.clone(),
            ciphertext_hashes: decoded.tx.ciphertext_hashes.clone(),
            balance_slot_asset_ids: artifact_balance_slot_asset_ids,
            fee: decoded.stark_public_inputs.fee,
            value_balance: 0,
            stablecoin: None,
        };
        assert_eq!(
            StarkVerifier::compute_binding_hash(&artifact_binding_inputs).data,
            built.bundle.binding_hash,
            "wallet action binding hash must match the native tx-leaf artifact binding"
        );
        verify_native_tx_leaf_artifact_bytes(
            &decoded.tx,
            &decoded.receipt,
            &built.bundle.proof_bytes,
        )
        .expect("native tx-leaf payload should verify");
        assert_eq!(
            decoded.receipt.verifier_profile,
            superneo_hegemon::experimental_native_tx_leaf_verifier_profile()
        );
        assert_eq!(built.bundle.nullifiers.len(), built.nullifiers.len());
    }

    #[test]
    fn lean_generated_wallet_output_batch_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_WALLET_OUTPUT_BATCH_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_WALLET_OUTPUT_BATCH_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean wallet output-batch vectors");
        let vectors: LeanWalletOutputBatchVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean wallet output-batch vectors");
        assert_eq!(vectors.schema_version, 2);
        assert_eq!(vectors.max_outputs, MAX_OUTPUTS);
        assert!(
            vectors.wallet_output_batch_cases.len() >= 10,
            "expected native/stablecoin/burn/consolidation output-batch coverage"
        );

        for case in &vectors.wallet_output_batch_cases {
            assert_eq!(
                case.expected_within_max_outputs,
                case.expected_output_count <= MAX_OUTPUTS,
                "Lean case {} has inconsistent MAX_OUTPUTS flag",
                case.name
            );

            assert_eq!(
                case.expected_output_count,
                case.expected_recipient_output_count + case.expected_change_output_count,
                "Lean case {} has inconsistent output role counts",
                case.name
            );

            let first = planned_wallet_output_batch_case_projection(
                case,
                case.private_witness_seed,
                case.local_metadata_seed,
            );
            if case.expected_valid {
                let first_projection = first.unwrap_or_else(|err| {
                    panic!(
                        "Lean wallet output-batch case {} rejected: {err}",
                        case.name
                    )
                });
                assert_eq!(
                    first_projection.output_count, case.expected_output_count,
                    "production output count drifted from Lean case {}",
                    case.name
                );
                assert_eq!(
                    first_projection.recipient_output_count, case.expected_recipient_output_count,
                    "production recipient output count drifted from Lean case {}",
                    case.name
                );
                assert_eq!(
                    first_projection.change_diversifier_indices.len(),
                    case.expected_change_output_count,
                    "production change output count drifted from Lean case {}",
                    case.name
                );
                assert!(
                    first_projection
                        .change_diversifier_indices
                        .iter()
                        .all(|index| *index == case.expected_change_diversifier_index),
                    "production change diversifier policy drifted from Lean case {}",
                    case.name
                );
                assert!(
                    first_projection.output_count <= MAX_OUTPUTS,
                    "production accepted over-MAX_OUTPUTS output batch for {}",
                    case.name
                );

                let second_projection = planned_wallet_output_batch_case_projection(
                    case,
                    case.alternate_private_witness_seed,
                    case.alternate_local_metadata_seed,
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "Lean wallet output-batch alternate metadata case {} rejected: {err}",
                        case.name
                    )
                });
                assert_eq!(
                    second_projection.output_count, first_projection.output_count,
                    "private witness/local metadata changed output count for {}",
                    case.name
                );
                if case.expected_change_diversifier_cursor_independent {
                    assert_eq!(
                        second_projection.change_diversifier_indices,
                        first_projection.change_diversifier_indices,
                        "local metadata changed change-output public diversifier summary for {}",
                        case.name
                    );
                }
            } else {
                assert!(
                    first.is_err(),
                    "Lean wallet output-batch case {} expected rejection but production accepted",
                    case.name
                );
            }
        }
    }
}
