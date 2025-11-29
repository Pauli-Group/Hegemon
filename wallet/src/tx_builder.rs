use rand::rngs::OsRng;
use transaction_circuit::constants::{MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID};
use transaction_circuit::note::OutputNoteWitness;
use transaction_circuit::witness::TransactionWitness;

use crate::address::ShieldedAddress;
use crate::error::WalletError;
use crate::notes::{MemoPlaintext, NoteCiphertext, NotePlaintext};
use crate::prover::StarkProver;
use crate::rpc::TransactionBundle;
use crate::store::{SpendableNote, WalletMode, WalletStore};

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
        return Err(WalletError::InvalidArgument("too many inputs required"));
    }

    let mut rng = OsRng;
    let mut outputs = Vec::new();
    let mut ciphertexts = Vec::new();
    for recipient in recipients {
        let (output, ciphertext) = build_output(recipient, &mut rng)?;
        outputs.push(output);
        ciphertexts.push(ciphertext);
    }

    let change_value = selection.total.saturating_sub(target_value);
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
        ciphertexts.push(ciphertext.clone());
        outputs.push(OutputNoteWitness {
            note: note.to_note_data(address.pk_recipient),
        });
    }

    let tree = store.commitment_tree()?;
    let mut inputs = Vec::new();
    let mut nullifiers = Vec::new();
    for note in &selection.spent {
        inputs.push(note.recovered.to_input_witness(note.position));
        nullifiers.push(fvk.compute_nullifier(&note.recovered.note.rho, note.position));
    }
    let witness = TransactionWitness {
        inputs,
        outputs,
        sk_spend: derived.spend.to_bytes(),
        merkle_root: tree.root(),
        fee,
        version: TransactionWitness::default_version_binding(),
    };
    
    // Generate STARK proof using the real prover
    let prover = StarkProver::with_defaults();
    let proof_result = prover.prove(&witness)?;
    
    // Compute binding signature commitment
    let binding_data = compute_binding_data(
        &proof_result.anchor,
        &proof_result.nullifiers,
        &proof_result.commitments,
        proof_result.value_balance,
    );
    let binding_sig = synthetic_crypto::hashes::blake2_256(&binding_data);
    let mut binding_sig_64 = [0u8; 64];
    binding_sig_64[..32].copy_from_slice(&binding_sig);
    binding_sig_64[32..].copy_from_slice(&binding_sig); // Double for 64 bytes
    
    let bundle = TransactionBundle::new(
        proof_result.proof_bytes,
        proof_result.nullifiers.to_vec(),
        proof_result.commitments.to_vec(),
        &ciphertexts,
        proof_result.anchor,
        binding_sig_64,
        proof_result.value_balance,
    )?;
    let spent_indexes = selection.spent.iter().map(|note| note.index).collect();
    Ok(BuiltTransaction {
        bundle,
        nullifiers,
        spent_note_indexes: spent_indexes,
    })
}

/// Compute binding data for signature commitment.
fn compute_binding_data(
    anchor: &[u8; 32],
    nullifiers: &[[u8; 32]],
    commitments: &[[u8; 32]],
    value_balance: i128,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(anchor);
    for nf in nullifiers {
        data.extend_from_slice(nf);
    }
    for cm in commitments {
        data.extend_from_slice(cm);
    }
    data.extend_from_slice(&value_balance.to_le_bytes());
    data
}

struct Selection {
    spent: Vec<SpendableNote>,
    total: u64,
}

fn select_notes(notes: &mut [SpendableNote], target: u64) -> Result<Selection, WalletError> {
    notes.sort_by_key(|note| note.position);
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
) -> Result<(OutputNoteWitness, NoteCiphertext), WalletError> {
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
    ))
}
