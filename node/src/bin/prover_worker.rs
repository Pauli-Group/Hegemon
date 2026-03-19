use std::time::{Duration, Instant};

use aggregation_circuit::{
    prewarm_thread_local_aggregation_cache_from_env, prove_leaf_aggregation,
    prove_merge_aggregation,
};
use anyhow::{Context, Result};
use base64::Engine;
use clap::Parser;
use codec::Encode;
use consensus::{encode_flat_batch_proof_bytes_with_kind, FLAT_BATCH_PROOF_KIND_TX_PROOF_MANIFEST};
use hegemon_node::substrate::rpc::prover::{
    LeafBatchPayloadResponse, SubmitWorkResultRequest, TxProofManifestPayloadResponse,
    WorkPackageResponse,
};
use pallet_shielded_pool::types::{
    BatchProofItem, BlockProofMode, CandidateArtifact, StarkProof, BLOCK_PROOF_BUNDLE_SCHEMA,
    BLOCK_PROOF_FORMAT_ID_V5,
};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::json;
use transaction_circuit::proof::TransactionProof;
use tx_proof_manifest::build_transaction_proof_manifest;

#[derive(Parser, Debug)]
#[command(name = "hegemon-prover-worker")]
#[command(about = "Standalone external prover worker for recursive stage packages")]
struct Args {
    #[arg(
        long,
        env = "HEGEMON_PROVER_RPC_URL",
        default_value = "http://127.0.0.1:9944"
    )]
    rpc_url: String,
    #[arg(
        long,
        env = "HEGEMON_PROVER_SOURCE",
        default_value = "standalone-prover"
    )]
    source: String,
    #[arg(long, env = "HEGEMON_PROVER_RPC_POLL_MS", default_value_t = 1000)]
    poll_ms: u64,
    #[arg(long, env = "HEGEMON_PROVER_RPC_TOKEN")]
    auth_token: Option<String>,
    #[arg(long)]
    once: bool,
}

#[derive(Clone)]
struct RpcClient {
    client: Client,
    url: String,
}

impl RpcClient {
    fn new(url: String) -> Self {
        Self {
            client: Client::new(),
            url,
        }
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let response = self
            .client
            .post(&self.url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .with_context(|| format!("RPC {method} request failed"))?;

        let payload: serde_json::Value = response
            .json()
            .await
            .with_context(|| format!("RPC {method} response decode failed"))?;
        if let Some(error) = payload.get("error") {
            return Err(anyhow::anyhow!("RPC {method} error: {}", error));
        }
        serde_json::from_value(
            payload
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .with_context(|| format!("RPC {method} result decode failed"))
    }
}

fn parse_hex_48(value: &str) -> Result<[u8; 48]> {
    let bytes = hex::decode(value.trim_start_matches("0x"))?;
    if bytes.len() != 48 {
        anyhow::bail!("expected 48-byte hex value, got {}", bytes.len());
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_leaf_payload(
    payload: &LeafBatchPayloadResponse,
) -> Result<(Vec<[u8; 48]>, Vec<TransactionProof>, [u8; 48], u16, u16)> {
    let statement_hashes = payload
        .statement_hashes
        .iter()
        .map(|value| parse_hex_48(value))
        .collect::<Result<Vec<_>>>()?;
    let tx_proofs_bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.tx_proofs_bincode)
        .context("tx proof bundle base64 decode failed")?;
    let tx_proofs: Vec<TransactionProof> =
        bincode::deserialize(&tx_proofs_bytes).context("tx proof bundle decode failed")?;
    Ok((
        statement_hashes,
        tx_proofs,
        parse_hex_48(&payload.tx_statements_commitment)?,
        payload.tree_levels,
        payload.root_level,
    ))
}

fn decode_tx_proof_manifest_payload(
    payload: &TxProofManifestPayloadResponse,
) -> Result<(
    Vec<[u8; 48]>,
    Vec<TransactionProof>,
    [u8; 48],
    [u8; 48],
    u32,
)> {
    let statement_hashes = payload
        .statement_hashes
        .iter()
        .map(|value| parse_hex_48(value))
        .collect::<Result<Vec<_>>>()?;
    let tx_proofs_bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.tx_proofs_bincode)
        .context("flat chunk tx proof bundle base64 decode failed")?;
    let tx_proofs: Vec<TransactionProof> = bincode::deserialize(&tx_proofs_bytes)
        .context("tx-proof-manifest tx proof bundle decode failed")?;
    Ok((
        statement_hashes,
        tx_proofs,
        parse_hex_48(&payload.tx_statements_commitment)?,
        parse_hex_48(&payload.da_root)?,
        payload.da_chunk_count,
    ))
}

fn worker_prewarm_disabled() -> bool {
    std::env::var("HEGEMON_AGG_DISABLE_WORKER_PREWARM")
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

async fn work_flat_once(client: &RpcClient, args: &Args) -> Result<bool> {
    let package: Option<WorkPackageResponse> =
        client.call("prover_getWorkPackage", json!([])).await?;
    let Some(package) = package else {
        return Ok(false);
    };
    let Some(tx_proof_manifest_payload) = package.tx_proof_manifest_payload.as_ref() else {
        return Ok(false);
    };

    let started = Instant::now();
    eprintln!(
        "starting flat package stage_type={} height={} tx_count={} package_id={}",
        package.stage_type, package.block_number, package.tx_count, package.package_id
    );

    let (statement_hashes, tx_proofs, tx_statements_commitment, da_root, da_chunk_count) =
        decode_tx_proof_manifest_payload(tx_proof_manifest_payload)?;
    let (tx_proof_manifest_bytes, public_inputs) = build_transaction_proof_manifest(&tx_proofs)
        .context("tx-proof-manifest generation failed")?;
    if public_inputs.statement_hashes != statement_hashes {
        anyhow::bail!("tx-proof-manifest statement hashes do not match package payload");
    }
    let encoded_batch_proof = encode_flat_batch_proof_bytes_with_kind(
        FLAT_BATCH_PROOF_KIND_TX_PROOF_MANIFEST,
        &tx_proof_manifest_bytes,
        &public_inputs
            .to_values()
            .context("tx-proof-manifest public value encoding failed")?,
    )
    .context("tx-proof-manifest payload encoding failed")?;
    let artifact = CandidateArtifact {
        version: BLOCK_PROOF_BUNDLE_SCHEMA,
        tx_count: package.tx_count,
        tx_statements_commitment,
        da_root,
        da_chunk_count,
        commitment_proof: StarkProof::from_bytes(Vec::new()),
        proof_mode: BlockProofMode::FlatBatches,
        flat_batches: vec![BatchProofItem {
            start_tx_index: package.chunk_start_tx_index,
            tx_count: package.chunk_tx_count,
            proof_format: BLOCK_PROOF_FORMAT_ID_V5,
            proof: StarkProof::from_bytes(encoded_batch_proof),
        }],
        merge_root: None,
        artifact_claim: None,
    };
    let request = SubmitWorkResultRequest {
        source: args.source.clone(),
        package_id: package.package_id.clone(),
        payload: format!("0x{}", hex::encode(artifact.encode())),
    };
    let response: serde_json::Value = client
        .call("prover_submitWorkResult", json!([request]))
        .await?;
    let accepted = response
        .get("accepted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if !accepted {
        let error = response
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown flat work rejection");
        eprintln!(
            "flat work rejected package_id={} elapsed_ms={}: {}",
            package.package_id,
            started.elapsed().as_millis(),
            error
        );
        return Ok(false);
    }
    eprintln!(
        "submitted flat package stage_type={} height={} tx_count={} package_id={} elapsed_ms={}",
        package.stage_type,
        package.block_number,
        package.tx_count,
        package.package_id,
        started.elapsed().as_millis()
    );
    Ok(true)
}

async fn work_stage_once(client: &RpcClient, args: &Args) -> Result<bool> {
    let stage_request = if let Some(token) = args.auth_token.as_deref() {
        json!([{ "auth_token": token }])
    } else {
        json!([{}])
    };
    let package: Option<WorkPackageResponse> = client
        .call("prover_getStageWorkPackage", stage_request)
        .await?;

    let Some(package) = package else {
        return Ok(false);
    };
    let stage_started = Instant::now();
    eprintln!(
        "starting stage package stage_type={} height={} tx_count={} package_id={}",
        package.stage_type, package.block_number, package.tx_count, package.package_id
    );
    let payload_bytes = match package.stage_type.as_str() {
        "leaf_batch_prove" => {
            let leaf_payload = package
                .leaf_batch_payload
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing leaf batch payload"))?;
            let (statement_hashes, tx_proofs, _tx_statements_commitment, tree_levels, root_level) =
                decode_leaf_payload(leaf_payload)?;
            prove_leaf_aggregation(&tx_proofs, &statement_hashes, tree_levels, root_level)
                .context("leaf aggregation proof generation failed")?
        }
        "merge_node_prove" | "root_aggregate_prove" => {
            let merge_payload = package
                .merge_node_payload
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing merge node payload"))?;
            let child_payloads_bytes = base64::engine::general_purpose::STANDARD
                .decode(&merge_payload.child_proof_payloads_bincode)
                .context("child payload bundle base64 decode failed")?;
            let child_payloads: Vec<Vec<u8>> = bincode::deserialize(&child_payloads_bytes)
                .context("child payload bundle decode failed")?;
            prove_merge_aggregation(
                &child_payloads,
                parse_hex_48(&merge_payload.tx_statements_commitment)?,
                merge_payload.tree_levels,
                merge_payload.root_level,
            )
            .context("merge aggregation proof generation failed")?
        }
        _ => {
            return Ok(false);
        }
    };
    let package_id = package.package_id.clone();
    let proof_bytes_len = payload_bytes.len();
    let request = SubmitWorkResultRequest {
        source: args.source.clone(),
        package_id: package_id.clone(),
        payload: format!("0x{}", hex::encode(&payload_bytes)),
    };
    let submit_params = json!([request]);
    let response: serde_json::Value = client
        .call("prover_submitStageWorkResult", submit_params)
        .await?;
    let accepted = response
        .get("accepted")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if !accepted {
        let error = response
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown stage work rejection");
        eprintln!(
            "stage work rejected package_id={package_id} elapsed_ms={}: {error}",
            stage_started.elapsed().as_millis()
        );
        return Ok(false);
    }
    eprintln!(
        "submitted stage package stage_type={} height={} tx_count={} package_id={} elapsed_ms={} proof_bytes={}",
        package.stage_type,
        package.block_number,
        package.tx_count,
        package_id,
        stage_started.elapsed().as_millis(),
        proof_bytes_len
    );
    Ok(true)
}

async fn work_once(client: &RpcClient, args: &Args) -> Result<bool> {
    if work_flat_once(client, args).await? {
        return Ok(true);
    }
    work_stage_once(client, args).await
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let client = RpcClient::new(args.rpc_url.clone());

    if worker_prewarm_disabled() {
        eprintln!("skipping aggregation cache prewarm by configuration");
    } else {
        let started = Instant::now();
        prewarm_thread_local_aggregation_cache_from_env()
            .context("aggregation cache prewarm failed")?;
        eprintln!(
            "aggregation cache prewarm complete elapsed_ms={}",
            started.elapsed().as_millis()
        );
    }

    loop {
        let worked = work_once(&client, &args).await?;
        if args.once {
            break;
        }
        if !worked {
            tokio::time::sleep(Duration::from_millis(args.poll_ms)).await;
        }
    }

    Ok(())
}
