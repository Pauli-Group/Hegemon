//! Decode a public SCALE PendingActionWire and display allocated-reward openings.
//! This is offline receipt inspection; it takes no wallet, key, or RPC inputs.

use anyhow::{bail, Context, Result};
use protocol_shielded_pool::poseidon2_v8_coinbase::Poseidon2V8CoinbaseNoteOpening;
use protocol_versioning::launch_candidate;
use serde_json::{json, Value};
use std::{env, fs, path::PathBuf};
use wallet::poseidon2_v8_sync::poseidon2_v8_reward_notes_from_canonical_action;

fn opening_json(opening: Poseidon2V8CoinbaseNoteOpening) -> Value {
    json!({
        "value": opening.value,
        "asset_id": opening.asset_id,
        "recipient_key": opening.recipient_key,
        "authorization_key": opening.authorization_key,
        "rho": opening.rho,
        "randomness": opening.randomness,
    })
}

fn main() -> Result<()> {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let path = args.next().map(PathBuf::from).ok_or_else(|| {
        anyhow::anyhow!(
            "usage: {} ACTION_WIRE.scale",
            PathBuf::from(program).display()
        )
    })?;
    if args.next().is_some() {
        bail!("expected exactly one SCALE PendingActionWire path");
    }

    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let notes = poseidon2_v8_reward_notes_from_canonical_action(&bytes)?
        .ok_or_else(|| anyhow::anyhow!("wire is not a canonical V8 reward action"))?;
    if notes.len() != 2 {
        bail!("allocated reward receipt must contain miner and funding notes");
    }
    // The wallet decoder returns two notes only for action 12 with its RP06
    // binding; action 11 has one note. It also exact-decodes the SCALE wire,
    // canonical action ID, reward args and note openings.
    let miner = &notes[0];
    let funding = &notes[1];
    let miner_value = miner.opening.value;
    let funding_value = funding.opening.value;
    let total_opened = miner_value
        .checked_add(funding_value)
        .ok_or_else(|| anyhow::anyhow!("opened reward sum overflows u64"))?;
    let expected_funding = total_opened / 5;

    let output: Value = json!({
        "action": {
            "family_id": launch_candidate::LAUNCH_SHIELDED_FAMILY_ID,
            "action_id": launch_candidate::ALLOCATED_REWARD_ACTION_ID,
            "binding": {
                "circuit": launch_candidate::RP06_VERSION_BINDING.circuit,
                "crypto": launch_candidate::RP06_VERSION_BINDING.crypto,
            },
            "decoded_bytes": bytes.len(),
        },
        "miner": {
            "opening": opening_json(miner.opening),
            "commitment": miner.commitment,
        },
        "funding": {
            "opening": opening_json(funding.opening),
            "commitment": funding.commitment,
        },
        "reward_only_zero_fee_check": {
            "opened_total": total_opened,
            "expected_funding_floor_total_over_5": expected_funding,
            "funding_matches": funding_value == expected_funding,
            "scope": "Assumes reward-only, zero-fee context; the action alone does not establish fee context.",
        },
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
