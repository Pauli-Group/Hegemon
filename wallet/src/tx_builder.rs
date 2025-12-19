use rand::rngs::OsRng;
use transaction_circuit::constants::{MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID};
use transaction_circuit::hashing::felt_to_bytes32;
use transaction_circuit::note::OutputNoteWitness;
use transaction_circuit::witness::TransactionWitness;

use crate::address::ShieldedAddress;
use crate::error::WalletError;
use crate::notes::{MemoPlaintext, NoteCiphertext, NotePlaintext};
use crate::prover::StarkProver;
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
    pub nullifiers: Vec<[u8; 32]>,
    pub spent_note_indexes: Vec<usize>,
    pub outgoing_disclosures: Vec<OutgoingDisclosureDraft>,
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
    if recipients.is_empty() {
        return Err(WalletError::InvalidArgument("at least one recipient"));
    }

    let fvk = store
        .full_viewing_key()?
        .ok_or(WalletError::InvalidState("missing viewing key"))?;

    let required_asset = recipients[0].asset_id;
    let target_value: u64 = recipients
        .iter()
        .map(|r| r.value)
        .sum::<u64>()
        .saturating_add(fee);

    let mut spendable = store.spendable_notes(required_asset)?;
    if spendable.is_empty() {
        return Err(WalletError::InsufficientFunds {
            needed: target_value,
            available: 0,
        });
    }

    // Select notes (same algorithm as build_transaction)
    let selection = select_notes(&mut spendable, target_value)?;

    if selection.spent.len() > MAX_INPUTS {
        return Err(WalletError::TooManyInputs {
            needed: selection.spent.len(),
            max: MAX_INPUTS,
        });
    }

    // Compute nullifiers for selected notes
    let nullifiers: Vec<[u8; 32]> = selection
        .spent
        .iter()
        .map(|note| fvk.compute_nullifier(&note.recovered.note.rho, note.position))
        .collect();

    // Check each nullifier against on-chain state
    let spent_status = rpc.check_nullifiers_spent(&nullifiers).await?;

    for (i, is_spent) in spent_status.iter().enumerate() {
        if *is_spent {
            return Err(WalletError::NullifierSpent {
                note_index: selection.spent[i].index,
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
    let required_asset = recipients[0].asset_id;
    if required_asset != NATIVE_ASSET_ID {
        return Err(WalletError::InvalidArgument("only native asset supported"));
    }
    let mut spendable = store.spendable_notes(required_asset)?;
    if spendable.is_empty() {
        return Err(WalletError::InsufficientFunds {
            needed: recipients[0].value + fee,
            available: 0,
        });
    }
    let target_value = recipients[0].value.saturating_add(fee);
    let selection = select_notes(&mut spendable, target_value)?;
    if selection.spent.len() > MAX_INPUTS {
        return Err(WalletError::TooManyInputs {
            needed: selection.spent.len(),
            max: MAX_INPUTS,
        });
    }

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
        let commitment = felt_to_bytes32(output.note.commitment());
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

    let change_value = selection.total.saturating_sub(target_value);
    // eprintln!("DEBUG: selection.total = {}, target_value = {}, change_value = {}", selection.total, target_value, change_value);
    if change_value > 0 {
        if outputs.len() >= MAX_OUTPUTS {
            return Err(WalletError::InvalidArgument(
                "change would exceed output limit",
            ));
        }
        let address = store.reserve_internal_address()?;
        let note = NotePlaintext::random(
            change_value,
            required_asset,
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
        let commitment = felt_to_bytes32(note_data.commitment());
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

    let mut inputs = Vec::new();
    let mut nullifiers = Vec::new();
    for note in &selection.spent {
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
        for (_level, sibling) in auth_path.iter().enumerate() {
            use transaction_circuit::hashing::merkle_node;
            let (left, right) = if pos & 1 == 0 {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            current = merkle_node(left, right);
            pos >>= 1;
        }
        // eprintln!("DEBUG: computed_root = {:?}", current);
        // eprintln!("DEBUG: expected_root = {:?}", wallet_root);
        if current != wallet_root {
            // eprintln!("DEBUG: ROOT MISMATCH!");
        }

        // Convert Felt path to MerklePath
        let merkle_path = transaction_circuit::note::MerklePath {
            siblings: auth_path,
        };

        // Create input witness with the merkle path
        let mut input_witness = note.recovered.to_input_witness(note.position);
        input_witness.merkle_path = merkle_path;
        inputs.push(input_witness);

        nullifiers.push(fvk.compute_nullifier(&note.recovered.note.rho, note.position));
    }
    let witness = TransactionWitness {
        inputs,
        outputs,
        sk_spend: derived.spend.to_bytes(),
        merkle_root: tree.root(),
        fee,
        value_balance: 0,
        version: TransactionWitness::default_version_binding(),
    };

    // Generate STARK proof using the real prover
    let prover = StarkProver::with_defaults();
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

    // Compute binding signature commitment (Blake2-256 hash of public inputs)
    let binding_hash = compute_binding_hash(
        &proof_result.anchor,
        &proof_result.nullifiers,
        &proof_result.commitments,
        proof_result.fee,
        proof_result.value_balance,
    );
    // The binding signature is the 32-byte hash duplicated to 64 bytes
    let mut binding_sig_64 = [0u8; 64];
    binding_sig_64[..32].copy_from_slice(&binding_hash);
    binding_sig_64[32..].copy_from_slice(&binding_hash);

    let bundle = TransactionBundle::new(
        proof_result.proof_bytes,
        proof_result.nullifiers.to_vec(),
        proof_result.commitments.to_vec(),
        &ciphertexts,
        proof_result.anchor,
        binding_sig_64,
        proof_result.fee,
        proof_result.value_balance,
    )?;
    let spent_indexes = selection.spent.iter().map(|note| note.index).collect();

    Ok(BuiltTransaction {
        bundle,
        // Use prover nullifiers, not wallet-computed, to match what's actually submitted
        nullifiers: proof_result.nullifiers.to_vec(),
        spent_note_indexes: spent_indexes,
        outgoing_disclosures,
    })
}

/// Compute binding signature hash for transaction commitment.
///
/// Returns the 32-byte Blake2-256 hash of the public inputs:
/// Blake2_256(anchor || nullifiers || commitments || fee || value_balance)
fn compute_binding_hash(
    anchor: &[u8; 32],
    nullifiers: &[[u8; 32]],
    commitments: &[[u8; 32]],
    fee: u64,
    value_balance: i128,
) -> [u8; 32] {
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
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&value_balance.to_le_bytes());

    // eprintln!("DEBUG binding: data.len = {}", data.len());
    let hash = synthetic_crypto::hashes::blake2_256(&data);
    // eprintln!("DEBUG binding: hash = {}", hex::encode(&hash));

    hash
}

struct Selection {
    spent: Vec<SpendableNote>,
    total: u64,
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
