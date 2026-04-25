use anyhow::{anyhow, Context, Result};
use base64::Engine;
use clap::Parser;
use codec::{Decode, Encode};
use consensus_light_client::{RiscZeroBridgeReceiptV1, HEGEMON_CHAIN_ID_V1};
use protocol_kernel::{
    bridge_payload_hash, BridgeMessageV1, InboundBridgeArgsV1, OutboundBridgeArgsV1,
    ACTION_BRIDGE_INBOUND, ACTION_BRIDGE_OUTBOUND, FAMILY_BRIDGE,
};
use protocol_versioning::DEFAULT_VERSION_BINDING;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

#[derive(Debug, Parser)]
#[command(about = "Example Hegemon->Hegemon loopback bridge flow over JSON-RPC")]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:9944")]
    source_rpc: String,
    #[arg(long, default_value = "http://127.0.0.1:9955")]
    destination_rpc: String,
    #[arg(long, default_value = "hegemon-to-hegemon loopback")]
    payload: String,
    #[arg(long, default_value_t = 60)]
    poll_seconds: u64,
    #[arg(long)]
    risc0_receipt_hex: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let client = reqwest::Client::new();

    let outbound = OutboundBridgeArgsV1 {
        destination_chain_id: HEGEMON_CHAIN_ID_V1,
        app_family_id: FAMILY_BRIDGE,
        payload: args.payload.into_bytes(),
    };
    let submit_outbound = json!({
        "binding_circuit": DEFAULT_VERSION_BINDING.circuit,
        "binding_crypto": DEFAULT_VERSION_BINDING.crypto,
        "family_id": FAMILY_BRIDGE,
        "action_id": ACTION_BRIDGE_OUTBOUND,
        "new_nullifiers": [],
        "public_args": base64::engine::general_purpose::STANDARD.encode(outbound.encode()),
    });
    let outbound_result = rpc(
        &client,
        &args.source_rpc,
        "hegemon_submitAction",
        json!([submit_outbound]),
    )
    .await?;
    println!("source outbound submission: {outbound_result}");

    let witness = poll_bridge_witness(&client, &args.source_rpc, args.poll_seconds).await?;
    let message = parse_witness_message(&witness)?;
    let long_range_proof = parse_hex_bytes(
        witness
            .pointer("/canonical/long_range_proof")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!(
                    "witness missing compact long-range proof; wait for a confirming source block"
                )
            })?,
    )?;
    println!(
        "exported compact Hegemon proof input: {} bytes",
        long_range_proof.len()
    );
    let proof_receipt = args
        .risc0_receipt_hex
        .as_deref()
        .map(parse_hex_bytes)
        .transpose()?
        .ok_or_else(|| {
            anyhow!(
                "missing --risc0-receipt-hex; prove canonical.long_range_proof with zk/risc0-bridge/prover first"
            )
        })?;
    let mut envelope_bytes = proof_receipt.as_slice();
    let risc0_receipt = RiscZeroBridgeReceiptV1::decode(&mut envelope_bytes)
        .map_err(|err| anyhow!("decode RISC Zero bridge receipt failed: {err:?}"))?;
    if !envelope_bytes.is_empty() {
        return Err(anyhow!("RISC Zero bridge receipt has trailing bytes"));
    }

    let inbound = InboundBridgeArgsV1 {
        source_chain_id: message.source_chain_id,
        source_message_nonce: message.message_nonce,
        verifier_program_hash: risc0_receipt.image_id,
        proof_receipt,
        message,
    };
    let submit_inbound = json!({
        "binding_circuit": DEFAULT_VERSION_BINDING.circuit,
        "binding_crypto": DEFAULT_VERSION_BINDING.crypto,
        "family_id": FAMILY_BRIDGE,
        "action_id": ACTION_BRIDGE_INBOUND,
        "new_nullifiers": [],
        "public_args": base64::engine::general_purpose::STANDARD.encode(inbound.encode()),
    });
    let inbound_result = rpc(
        &client,
        &args.destination_rpc,
        "hegemon_submitAction",
        json!([submit_inbound]),
    )
    .await?;
    println!("destination inbound submission: {inbound_result}");
    println!("RISC Zero bridge receipt accepted for staging; mine/import a destination block to consume the replay key");

    Ok(())
}

async fn poll_bridge_witness(
    client: &reqwest::Client,
    source_rpc: &str,
    poll_seconds: u64,
) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(poll_seconds);
    loop {
        match rpc(client, source_rpc, "hegemon_exportBridgeWitness", json!([])).await {
            Ok(witness)
                if witness
                    .pointer("/canonical/long_range_proof")
                    .and_then(Value::as_str)
                    .is_some() =>
            {
                return Ok(witness)
            }
            Ok(_) if Instant::now() < deadline => {
                eprintln!("waiting for source confirmation over bridge message");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Ok(_) => {
                return Err(anyhow!(
                    "bridge witness never gained a compact long-range proof"
                ))
            }
            Err(err) if Instant::now() < deadline => {
                eprintln!("waiting for source block with bridge message: {err}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(err) => return Err(err).context("bridge witness did not become available"),
        }
    }
}

async fn rpc(client: &reqwest::Client, url: &str, method: &str, params: Value) -> Result<Value> {
    let response = client
        .post(url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .send()
        .await
        .with_context(|| format!("send {method}"))?
        .error_for_status()
        .with_context(|| format!("HTTP status for {method}"))?
        .json::<Value>()
        .await
        .with_context(|| format!("decode {method} response"))?;
    if let Some(error) = response.get("error") {
        return Err(anyhow!("{method} failed: {error}"));
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| anyhow!("{method} response missing result"))
}

fn parse_witness_message(witness: &Value) -> Result<BridgeMessageV1> {
    let message = witness
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| messages.first())
        .ok_or_else(|| anyhow!("witness contains no bridge messages"))?;
    let payload = parse_hex_bytes(required_str(message, "payload")?)?;
    let payload_hash = parse_hash48(required_str(message, "payload_hash")?)?;
    if payload_hash != bridge_payload_hash(&payload) {
        return Err(anyhow!("witness payload hash mismatch"));
    }
    Ok(BridgeMessageV1 {
        source_chain_id: parse_hash32(required_str(message, "source_chain_id")?)?,
        destination_chain_id: parse_hash32(required_str(message, "destination_chain_id")?)?,
        app_family_id: required_u64(message, "app_family_id")?
            .try_into()
            .map_err(|_| anyhow!("app_family_id out of range"))?,
        message_nonce: required_str(message, "message_nonce")?
            .parse()
            .context("parse message_nonce")?,
        source_height: required_u64(message, "source_height")?,
        payload_hash,
        payload,
    })
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {key}"))
}

fn required_u64(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing numeric field {key}"))
}

fn parse_hash32(raw: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex_bytes(raw)?;
    let mut out = [0u8; 32];
    if bytes.len() != out.len() {
        return Err(anyhow!("expected 32-byte hash"));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hash48(raw: &str) -> Result<[u8; 48]> {
    let bytes = parse_hex_bytes(raw)?;
    let mut out = [0u8; 48];
    if bytes.len() != out.len() {
        return Err(anyhow!("expected 48-byte hash"));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>> {
    let stripped = raw.strip_prefix("0x").unwrap_or(raw);
    hex::decode(stripped).context("decode hex")
}
