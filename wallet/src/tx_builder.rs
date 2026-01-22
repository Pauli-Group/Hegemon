use rand::rngs::OsRng;
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
use crate::prover::{StarkProver, StarkProverConfig};
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

fn build_stark_prover() -> StarkProver {
    let fast = std::env::var("HEGEMON_WALLET_PROVER_FAST")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if fast {
        StarkProver::new(StarkProverConfig::fast())
    } else {
        StarkProver::with_defaults()
    }
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
    let fvk = store
        .full_viewing_key()?
        .ok_or(WalletError::InvalidState("missing viewing key"))?;
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
        let note_data = note.to_note_data(address.pk_recipient);
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
        let note_data = note.to_note_data(address.pk_recipient);
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
    // eprintln!("DEBUG: wallet merkle_root = {:?}", wallet_root);
    // eprintln!("DEBUG: tree.len = {}", tree.len());

    let plan_inputs = plan.inputs();
    let mut inputs = Vec::new();
    let mut nullifiers = Vec::new();
    for note in plan_inputs.iter() {
        // Get the Merkle authentication path for this note's position
        let auth_path = tree
            .authentication_path(note.position as usize)
            .map_err(|e| {
                WalletError::InvalidState(Box::leak(
                    format!("merkle path error: {}", e).into_boxed_str(),
                ))
            })?;

        // eprintln!("DEBUG: note.position = {}", note.position);
        // eprintln!("DEBUG: auth_path.len() = {}", auth_path.len());

        // Verify the path locally to debug
        let leaf = note.recovered.note_data.commitment();
        // eprintln!("DEBUG: recovered note commitment (Poseidon) = {:?}", leaf);

        // Get tree leaf at that position and compare
        let tree_leaf = auth_path.first().map(|_| {
            // Actually need to get the leaf from tree.levels[0][position]
            // But we don't have direct access. Let me print the first few siblings
            // eprintln!("DEBUG: auth_path siblings: {:?}", &auth_path[..std::cmp::min(3, auth_path.len())]);
        });
        let _ = tree_leaf;

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
        // eprintln!("DEBUG: computed_root = {:?}", current);
        // eprintln!("DEBUG: expected_root = {:?}", wallet_root);
        if felts_to_bytes48(&current) != wallet_root {
            // eprintln!("DEBUG: ROOT MISMATCH!");
        }

        // Convert Felt path to MerklePath
        let merkle_path = transaction_circuit::note::MerklePath { siblings };

        // Create input witness with the merkle path
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
        sk_spend: derived.view.nullifier_key(),
        merkle_root: tree.root(),
        fee,
        value_balance: 0,
        stablecoin: stablecoin.clone(),
        version: TransactionWitness::default_version_binding(),
    };

    // Generate STARK proof using the real prover
    let prover = build_stark_prover();
    let proof_result = prover.prove(&witness)?;

    // Debug: compare wallet-computed nullifiers vs prover nullifiers (only in debug builds)
    #[cfg(debug_assertions)]
    {
        eprintln!("DEBUG tx_builder: wallet computed nullifiers vs prover nullifiers:");
        for (i, (wallet_nf, prover_nf)) in nullifiers
            .iter()
            .zip(proof_result.nullifiers.iter())
            .enumerate()
        {
            eprintln!("  [{}] wallet:  {}", i, hex::encode(wallet_nf));
            eprintln!("  [{}] prover:  {}", i, hex::encode(prover_nf));
            if wallet_nf != prover_nf {
                eprintln!("  [{}] MISMATCH!", i);
            }
        }
    }

    // eprintln!("DEBUG tx_builder: proof_result.value_balance = {}", proof_result.value_balance);
    // eprintln!("DEBUG tx_builder: proof_result.commitments.len() = {}", proof_result.commitments.len());
    // eprintln!("DEBUG tx_builder: ciphertexts.len() = {}", ciphertexts.len());

    // Compute binding hash commitment (domain-separated Blake2-256 of public inputs)
    let binding_hash = compute_binding_hash(
        &proof_result.anchor,
        &proof_result.nullifiers,
        &proof_result.commitments,
        &ciphertext_hashes,
        proof_result.fee,
        proof_result.value_balance,
    );

    let bundle = TransactionBundle::new(
        proof_result.proof_bytes,
        proof_result.nullifiers.to_vec(),
        proof_result.commitments.to_vec(),
        &ciphertexts,
        proof_result.anchor,
        binding_hash,
        proof_result.fee,
        proof_result.value_balance,
        witness.stablecoin.clone(),
    )?;
    let spent_indexes = plan_inputs.iter().map(|note| note.index).collect();

    Ok(BuiltTransaction {
        bundle,
        // Use prover nullifiers, not wallet-computed, to match what's actually submitted
        nullifiers: proof_result.nullifiers.to_vec(),
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
        let note_data = note.to_note_data(address.pk_recipient);
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
        let note_data = note.to_note_data(address.pk_recipient);
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
        sk_spend: derived.view.nullifier_key(),
        merkle_root: tree.root(),
        fee,
        value_balance: 0,
        stablecoin: stablecoin.clone(),
        version: TransactionWitness::default_version_binding(),
    };

    let prover = build_stark_prover();
    let proof_result = prover.prove(&witness)?;

    let binding_hash = compute_binding_hash(
        &proof_result.anchor,
        &proof_result.nullifiers,
        &proof_result.commitments,
        &ciphertext_hashes,
        proof_result.fee,
        proof_result.value_balance,
    );

    let bundle = TransactionBundle::new(
        proof_result.proof_bytes,
        proof_result.nullifiers.to_vec(),
        proof_result.commitments.to_vec(),
        &ciphertexts,
        proof_result.anchor,
        binding_hash,
        proof_result.fee,
        proof_result.value_balance,
        witness.stablecoin.clone(),
    )?;
    let spent_indexes = spent_notes.iter().map(|note| note.index).collect();

    Ok(BuiltTransaction {
        bundle,
        nullifiers: proof_result.nullifiers.to_vec(),
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

    let mut inputs = Vec::new();
    let mut nullifiers = Vec::new();
    for note in [note_a.clone(), note_b.clone()] {
        let auth_path = tree
            .authentication_path(note.position as usize)
            .map_err(|e| WalletError::Serialization(format!("merkle path error: {e}")))?;

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

    let ciphertext_hashes = vec![ciphertext_hash_bytes(&ciphertext.to_da_bytes()?)];
    let witness = TransactionWitness {
        inputs,
        outputs: vec![output],
        ciphertext_hashes: ciphertext_hashes.clone(),
        sk_spend: derived.view.nullifier_key(),
        merkle_root: tree.root(),
        fee,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    };

    let prover = build_stark_prover();
    let proof_result = prover.prove(&witness)?;

    let binding_hash = compute_binding_hash(
        &proof_result.anchor,
        &proof_result.nullifiers,
        &proof_result.commitments,
        &ciphertext_hashes,
        proof_result.fee,
        proof_result.value_balance,
    );

    let bundle = TransactionBundle::new(
        proof_result.proof_bytes,
        proof_result.nullifiers.to_vec(),
        proof_result.commitments.to_vec(),
        &[ciphertext],
        proof_result.anchor,
        binding_hash,
        proof_result.fee,
        proof_result.value_balance,
        witness.stablecoin.clone(),
    )?;

    Ok(BuiltTransaction {
        bundle,
        nullifiers: proof_result.nullifiers.to_vec(),
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
    fee: u64,
    value_balance: i128,
) -> [u8; 64] {
    // Debug: print binding hash inputs
    // eprintln!("DEBUG binding: anchor = {}", hex::encode(anchor));
    // eprintln!("DEBUG binding: nullifiers.len = {}", nullifiers.len());
    // for (i, nf) in nullifiers.iter().enumerate() {
    //     eprintln!("DEBUG binding: nullifiers[{}] = {}", i, hex::encode(nf));
    // }
    // eprintln!("DEBUG binding: commitments.len = {}", commitments.len());
    // for (i, cm) in commitments.iter().enumerate() {
    //     eprintln!("DEBUG binding: commitments[{}] = {}", i, hex::encode(cm));
    // }
    // eprintln!("DEBUG binding: value_balance = {}", value_balance);

    let mut data = Vec::new();
    data.extend_from_slice(anchor);
    for nf in nullifiers {
        data.extend_from_slice(nf);
    }
    for cm in commitments {
        data.extend_from_slice(cm);
    }
    for ct in ciphertext_hashes {
        data.extend_from_slice(ct);
    }
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&value_balance.to_le_bytes());

    // eprintln!("DEBUG binding: data.len = {}", data.len());
    const BINDING_HASH_DOMAIN: &[u8] = b"binding-hash-v1";
    let mut msg0 = Vec::with_capacity(BINDING_HASH_DOMAIN.len() + 1 + data.len());
    msg0.extend_from_slice(BINDING_HASH_DOMAIN);
    msg0.push(0);
    msg0.extend_from_slice(&data);
    let hash0 = synthetic_crypto::hashes::blake2_256(&msg0);

    let mut msg1 = Vec::with_capacity(BINDING_HASH_DOMAIN.len() + 1 + data.len());
    msg1.extend_from_slice(BINDING_HASH_DOMAIN);
    msg1.push(1);
    msg1.extend_from_slice(&data);
    let hash1 = synthetic_crypto::hashes::blake2_256(&msg1);

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&hash0);
    out[32..].copy_from_slice(&hash1);
    out
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
            note: note.to_note_data(recipient.address.pk_recipient),
        },
        ciphertext,
        note,
    ))
}
