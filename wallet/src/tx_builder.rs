use pallet_shielded_pool::verifier::{ShieldedTransferInputs, StarkVerifier};
use rand::rngs::OsRng;
use superneo_hegemon::build_native_tx_leaf_artifact_bytes;
use transaction_circuit::constants::{MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID};
use transaction_circuit::hashing_pq::{
    bytes48_to_felts, ciphertext_hash_bytes, felts_to_bytes48, merkle_node,
};
use transaction_circuit::note::OutputNoteWitness;
use transaction_circuit::witness::TransactionWitness;
use transaction_circuit::StablecoinPolicyBinding;

use crate::address::ShieldedAddress;
use crate::error::WalletError;
use crate::notes::{MemoPlaintext, NoteCiphertext, NotePlaintext};
use crate::rpc::TransactionBundle;
use crate::store::{OutgoingDisclosureDraft, SpendableNote, WalletMode, WalletStore};
use crate::substrate_rpc::SubstrateRpcClient;

pub struct Recipient {
    pub address: ShieldedAddress,
    pub value: u64,
    pub asset_id: u64,
    pub memo: MemoPlaintext,
}

pub struct BuiltTransaction {
    pub bundle: TransactionBundle,
    pub nullifiers: Vec<[u8; 48]>,
    pub spent_note_indexes: Vec<usize>,
    pub outgoing_disclosures: Vec<OutgoingDisclosureDraft>,
}

struct SubmissionProofMaterial {
    proof_bytes: Vec<u8>,
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    anchor: [u8; 48],
    balance_slot_asset_ids: [u64; 4],
    fee: u64,
    value_balance: i128,
}

fn balance_slot_asset_ids_from_witness(
    witness: &TransactionWitness,
) -> Result<[u64; 4], WalletError> {
    let slots = witness
        .balance_slots()
        .map_err(|err| WalletError::InvalidArgument(Box::leak(err.to_string().into_boxed_str())))?;
    let ids = slots.iter().map(|slot| slot.asset_id).collect::<Vec<_>>();
    ids.try_into()
        .map_err(|_| WalletError::InvalidState("balance slot count mismatch"))
}

fn submission_proof_material_from_witness(
    witness: &TransactionWitness,
) -> Result<SubmissionProofMaterial, WalletError> {
    witness
        .validate()
        .map_err(|err| WalletError::InvalidArgument(Box::leak(err.to_string().into_boxed_str())))?;
    let public_inputs = witness
        .public_inputs()
        .map_err(|err| WalletError::InvalidArgument(Box::leak(err.to_string().into_boxed_str())))?;
    let built = build_native_tx_leaf_artifact_bytes(witness).map_err(|err| {
        WalletError::Serialization(format!("native tx-leaf artifact generation failed: {err}"))
    })?;
    Ok(SubmissionProofMaterial {
        proof_bytes: built.artifact_bytes,
        nullifiers: public_inputs.nullifiers[..witness.inputs.len()].to_vec(),
        commitments: public_inputs.commitments[..witness.outputs.len()].to_vec(),
        anchor: witness.merkle_root,
        balance_slot_asset_ids: balance_slot_asset_ids_from_witness(witness)?,
        fee: witness.fee,
        value_balance: witness.value_balance,
    })
}

/// Pre-flight check: compute nullifiers for notes and verify none are spent on-chain.
///
/// This should be called before `build_transaction` to avoid wasting time on
/// proof generation if any notes are already spent.
///
/// Returns Ok(nullifiers) if all notes are unspent, or Err with the index of the first spent note.
pub async fn precheck_nullifiers(
    store: &WalletStore,
    rpc: &SubstrateRpcClient,
    recipients: &[Recipient],
    fee: u64,
) -> Result<(), WalletError> {
    let stablecoin = StablecoinPolicyBinding::default();
    precheck_nullifiers_with_binding(store, rpc, recipients, fee, &stablecoin).await
}

/// Pre-flight check that supports stablecoin issuance/burn bindings.
pub async fn precheck_nullifiers_with_binding(
    store: &WalletStore,
    rpc: &SubstrateRpcClient,
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

    if plan.output_change > 0 {
        if outputs.len() >= MAX_OUTPUTS {
            return Err(WalletError::InvalidArgument(
                "change would exceed output limit",
            ));
        }
        let address = store.reserve_internal_address()?;
        let note = NotePlaintext::random(
            plan.output_change,
            plan.output_asset,
            MemoPlaintext::default(),
            &mut rng,
        );
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng)?;
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
        ciphertexts.push(ciphertext.clone());
        outputs.push(OutputNoteWitness { note: note_data });
    }

    if plan.native_change > 0 {
        if outputs.len() >= MAX_OUTPUTS {
            return Err(WalletError::InvalidArgument(
                "native change would exceed output limit",
            ));
        }
        let address = store.reserve_internal_address()?;
        let note = NotePlaintext::random(
            plan.native_change,
            NATIVE_ASSET_ID,
            MemoPlaintext::default(),
            &mut rng,
        );
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng)?;
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
        ciphertexts.push(ciphertext.clone());
        outputs.push(OutputNoteWitness { note: note_data });
    }

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
        to_pallet_stablecoin_binding(&witness.stablecoin),
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

    let outputs_needed = usize::from(asset_change > 0) + usize::from(native_change > 0);
    if outputs_needed > MAX_OUTPUTS {
        return Err(WalletError::InvalidArgument(
            "burn outputs exceed output limit",
        ));
    }

    let mut rng = OsRng;
    let mut outputs = Vec::new();
    let mut ciphertexts = Vec::new();
    let mut outgoing_disclosures = Vec::new();

    if asset_change > 0 {
        let address = store.reserve_internal_address()?;
        let note =
            NotePlaintext::random(asset_change, asset_id, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng)?;
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
        ciphertexts.push(ciphertext.clone());
        outputs.push(OutputNoteWitness { note: note_data });
    }

    if native_change > 0 {
        let address = store.reserve_internal_address()?;
        let note = NotePlaintext::random(
            native_change,
            NATIVE_ASSET_ID,
            MemoPlaintext::default(),
            &mut rng,
        );
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng)?;
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
        ciphertexts.push(ciphertext.clone());
        outputs.push(OutputNoteWitness { note: note_data });
    }

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
        to_pallet_stablecoin_binding(&witness.stablecoin),
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
        to_pallet_stablecoin_binding(&witness.stablecoin),
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
    stablecoin: Option<pallet_shielded_pool::types::StablecoinPolicyBinding>,
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

fn to_pallet_stablecoin_binding(
    binding: &StablecoinPolicyBinding,
) -> Option<pallet_shielded_pool::types::StablecoinPolicyBinding> {
    binding
        .enabled
        .then_some(pallet_shielded_pool::types::StablecoinPolicyBinding {
            asset_id: binding.asset_id,
            policy_hash: binding.policy_hash,
            oracle_commitment: binding.oracle_commitment,
            attestation_commitment: binding.attestation_commitment,
            issuance_delta: binding.issuance_delta,
            policy_version: binding.policy_version,
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
        let outputs_needed = recipients.len() + usize::from(output_change > 0);
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
        recipients.len() + usize::from(output_change > 0) + usize::from(native_change > 0);
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
    use superneo_hegemon::decode_native_tx_leaf_artifact_bytes;
    use tempfile::tempdir;

    use pallet_shielded_pool::verifier::{ShieldedTransferInputs, StarkVerifier};
    use transaction_circuit::hashing_pq::{ciphertext_hash_bytes, felts_to_bytes48};

    use super::*;

    #[test]
    fn sidecar_binding_hash_matches_pallet_verifier() {
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
            to_pallet_stablecoin_binding(&stablecoin),
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
            pallet_shielded_pool::types::StablecoinPolicyBinding {
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
        let dir = tempdir().unwrap();
        let sender_path = dir.path().join("sender.wallet");
        let recipient_path = dir.path().join("recipient.wallet");
        let sender = WalletStore::create_full(&sender_path, "passphrase").unwrap();
        let recipient_store = WalletStore::create_full(&recipient_path, "passphrase").unwrap();

        let sender_fvk = sender.full_viewing_key().unwrap().unwrap();
        let sender_addr = sender_fvk.incoming().shielded_address(0).unwrap();
        let mut rng = StdRng::seed_from_u64(777);

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
            memo: MemoPlaintext::new(b"native tx leaf".to_vec()),
        };
        let built = build_transaction(&sender, &[recipient], 0).unwrap();

        let decoded = decode_native_tx_leaf_artifact_bytes(&built.bundle.proof_bytes)
            .expect("native tx-leaf payload should decode");
        assert_eq!(
            decoded.receipt.verifier_profile,
            superneo_hegemon::experimental_native_tx_leaf_verifier_profile()
        );
        assert_eq!(built.bundle.nullifiers.len(), built.nullifiers.len());
    }
}
