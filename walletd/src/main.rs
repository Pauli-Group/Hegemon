use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use chrono::{TimeZone, Utc};
use disclosure_circuit::{
    prove_payment_disclosure, verify_payment_disclosure, PaymentDisclosureClaim,
    PaymentDisclosureProofBundle, PaymentDisclosureWitness,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::runtime::Builder as RuntimeBuilder;
use transaction_circuit::{
    hashing_pq::{bytes48_to_felts, note_commitment_bytes},
    note::MerklePath,
};
use wallet::{
    api::{parse_recipients, transfer_recipients_from_specs, RecipientSpec},
    async_sync::AsyncWalletSyncEngine,
    disclosure::{
        decode_base64, encode_base64, DisclosureChainInfo, DisclosureClaim, DisclosureConfirmation,
        DisclosurePackage, DisclosureProof,
    },
    build_transaction,
    precheck_nullifiers,
    notes::MemoPlaintext,
    store::{PendingStatus, TransferRecipient, WalletMode, WalletStore},
    substrate_rpc::SubstrateRpcClient,
    ConsolidationPlan, MAX_INPUTS,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WalletdMode {
    Open,
    Create,
}

fn parse_mode(value: &str) -> Result<WalletdMode> {
    match value {
        "open" => Ok(WalletdMode::Open),
        "create" => Ok(WalletdMode::Create),
        _ => anyhow::bail!("invalid mode {value} (expected open or create)"),
    }
}

#[derive(Deserialize)]
struct RequestEnvelope {
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct ResponseEnvelope {
    id: Value,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletStatusResponse {
    primary_address: String,
    last_synced_height: u64,
    balances: Vec<BalanceEntry>,
    pending: Vec<PendingEntry>,
    notes: Option<NoteSummary>,
    genesis_hash: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BalanceEntry {
    asset_id: u64,
    label: String,
    spendable: u64,
    locked: u64,
    total: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingEntry {
    id: String,
    tx_id: String,
    direction: String,
    address: String,
    memo: Option<String>,
    amount: u64,
    fee: u64,
    status: String,
    confirmations: u64,
    created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NoteSummary {
    asset_id: u64,
    spendable_count: usize,
    max_inputs: usize,
    needs_consolidation: bool,
    plan: Option<ConsolidationPlanSummary>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConsolidationPlanSummary {
    txs_needed: u64,
    blocks_needed: u64,
}

#[derive(Deserialize)]
struct SyncParams {
    ws_url: String,
    #[serde(default)]
    force_rescan: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncResponse {
    new_height: u64,
    commitments: usize,
    ciphertexts: usize,
    recovered: usize,
    spent: usize,
}

#[derive(Deserialize)]
struct SendParams {
    ws_url: String,
    recipients: Vec<RecipientSpec>,
    fee: u64,
    #[serde(default)]
    auto_consolidate: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendResponse {
    tx_hash: String,
    recipients: Vec<TransferRecipient>,
}

#[derive(Deserialize)]
struct DisclosureCreateParams {
    ws_url: String,
    tx_id: String,
    output: u32,
}

#[derive(Deserialize)]
struct DisclosureVerifyParams {
    ws_url: String,
    package: DisclosurePackage,
}

#[derive(Serialize)]
struct DisclosureVerifyResponse {
    verified: bool,
    recipient_address: String,
    value: u64,
    asset_id: u64,
    commitment: String,
    anchor: String,
    chain: String,
}

fn main() -> Result<()> {
    let (store_path, mode) = parse_args()?;
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let passphrase = lines
        .next()
        .ok_or_else(|| anyhow!("expected passphrase on first line"))??
        .trim()
        .to_string();

    if passphrase.is_empty() {
        anyhow::bail!("passphrase is empty");
    }

    let store = Arc::new(open_store(&store_path, &passphrase, mode)?);
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    for line in lines {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("walletd stdin error: {err}");
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<RequestEnvelope>(&line) {
            Ok(request) => handle_request(&runtime, store.clone(), request),
            Err(err) => ResponseEnvelope {
                id: Value::Null,
                ok: false,
                result: None,
                error: Some(format!("invalid request: {err}")),
            },
        };

        let payload = serde_json::to_string(&response)?;
        writeln!(stdout, "{payload}")?;
        stdout.flush()?;
    }

    Ok(())
}

fn parse_args() -> Result<(String, WalletdMode)> {
    let mut args = std::env::args().skip(1);
    let mut store_path: Option<String> = None;
    let mut mode = WalletdMode::Open;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--store" => {
                store_path = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("--store requires a path"))?,
                );
            }
            "--mode" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow!("--mode requires a value"))?;
                mode = parse_mode(&value)?;
            }
            _ => {}
        }
    }
    let store_path =
        store_path.ok_or_else(|| anyhow!("usage: walletd --store <PATH> [--mode open|create]"))?;
    Ok((store_path, mode))
}

fn open_store(store_path: &str, passphrase: &str, mode: WalletdMode) -> Result<WalletStore> {
    let exists = Path::new(store_path).exists();
    match mode {
        WalletdMode::Open => {
            if !exists {
                anyhow::bail!("wallet store not found");
            }
            WalletStore::open(store_path, passphrase).context("failed to open wallet store")
        }
        WalletdMode::Create => {
            if exists {
                anyhow::bail!("wallet store already exists");
            }
            WalletStore::create_full(store_path, passphrase).context("failed to create wallet store")
        }
    }
}

fn handle_request(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    request: RequestEnvelope,
) -> ResponseEnvelope {
    let result = (|| -> Result<Value> {
        match request.method.as_str() {
            "status.get" => serde_json::to_value(status_get(&store)?).map_err(anyhow::Error::from),
            "sync.once" => {
                let params: SyncParams = parse_params(request.params)?;
                serde_json::to_value(sync_once(runtime, store, params)?)
                    .map_err(anyhow::Error::from)
            }
            "tx.send" => {
                let params: SendParams = parse_params(request.params)?;
                serde_json::to_value(tx_send(runtime, store, params)?)
                    .map_err(anyhow::Error::from)
            }
            "disclosure.create" => {
                let params: DisclosureCreateParams = parse_params(request.params)?;
                serde_json::to_value(disclosure_create(runtime, store, params)?)
                    .map_err(anyhow::Error::from)
            }
            "disclosure.verify" => {
                let params: DisclosureVerifyParams = parse_params(request.params)?;
                serde_json::to_value(disclosure_verify(runtime, params)?)
                    .map_err(anyhow::Error::from)
            }
            _ => Err(anyhow!("unknown method {}", request.method)),
        }
    })();

    match result {
        Ok(value) => ResponseEnvelope {
            id: request.id,
            ok: true,
            result: Some(value),
            error: None,
        },
        Err(err) => ResponseEnvelope {
            id: request.id,
            ok: false,
            result: None,
            error: Some(err.to_string()),
        },
    }
}

fn parse_params<T: for<'de> Deserialize<'de>>(params: Value) -> Result<T> {
    serde_json::from_value(params).map_err(|err| anyhow!("invalid params: {err}"))
}

fn status_get(store: &Arc<WalletStore>) -> Result<WalletStatusResponse> {
    let mode = store.mode()?;
    let balances = store.balances()?;
    let pending_balances = store.pending_balances()?;
    let latest = store.last_synced_height()?;
    let pending_txs = store.pending_transactions()?;

    let primary_address = if mode == WalletMode::Full {
        store
            .derived_keys()?
            .and_then(|keys| keys.address(0).ok())
            .and_then(|mat| mat.shielded_address().encode().ok())
    } else {
        store
            .incoming_key()
            .ok()
            .and_then(|ivk| ivk.shielded_address(0).ok())
            .and_then(|addr| addr.encode().ok())
    }
    .unwrap_or_else(|| "—".to_string());

    let mut asset_ids: Vec<u64> = balances.keys().copied().collect();
    for asset_id in pending_balances.keys() {
        if !asset_ids.contains(asset_id) {
            asset_ids.push(*asset_id);
        }
    }
    asset_ids.sort_unstable();

    let balance_entries = asset_ids
        .iter()
        .map(|asset_id| {
            let spendable = balances.get(asset_id).copied().unwrap_or(0);
            let locked = pending_balances.get(asset_id).copied().unwrap_or(0);
            let total = spendable.saturating_add(locked);
            let label = if *asset_id == transaction_circuit::constants::NATIVE_ASSET_ID {
                "HGM".to_string()
            } else {
                format!("asset {}", asset_id)
            };
            BalanceEntry {
                asset_id: *asset_id,
                label,
                spendable,
                locked,
                total,
            }
        })
        .collect();

    let pending_entries = pending_txs
        .iter()
        .map(|tx| render_pending(tx, latest))
        .collect();

    let notes = summarize_notes(store)?;
    let genesis_hash = store
        .genesis_hash()?
        .map(|hash| format!("0x{}", hex::encode(hash)));

    Ok(WalletStatusResponse {
        primary_address,
        last_synced_height: latest,
        balances: balance_entries,
        pending: pending_entries,
        notes,
        genesis_hash,
    })
}

fn summarize_notes(store: &Arc<WalletStore>) -> Result<Option<NoteSummary>> {
    let asset_id = transaction_circuit::constants::NATIVE_ASSET_ID;
    let spendable_notes = store.spendable_notes(asset_id)?;
    let count = spendable_notes.len();
    if count <= MAX_INPUTS {
        return Ok(Some(NoteSummary {
            asset_id,
            spendable_count: count,
            max_inputs: MAX_INPUTS,
            needs_consolidation: false,
            plan: None,
        }));
    }

    let plan = ConsolidationPlan::estimate(count);
    Ok(Some(NoteSummary {
        asset_id,
        spendable_count: count,
        max_inputs: MAX_INPUTS,
        needs_consolidation: true,
        plan: Some(ConsolidationPlanSummary {
            txs_needed: plan.txs_needed as u64,
            blocks_needed: plan.blocks_needed as u64,
        }),
    }))
}

fn render_pending(tx: &wallet::PendingTransaction, latest_height: u64) -> PendingEntry {
    let tx_id = hex::encode(tx.tx_id);
    let amount: u64 = tx.recipients.iter().map(|rec| rec.value).sum();
    let address = tx
        .recipients
        .first()
        .map(|rec| rec.address.clone())
        .unwrap_or_else(|| "—".to_string());
    let memo = tx.recipients.first().and_then(|rec| rec.memo.clone());
    PendingEntry {
        id: tx_id.clone(),
        tx_id,
        direction: "outgoing".to_string(),
        address,
        memo,
        amount,
        fee: tx.fee,
        status: match tx.status {
            PendingStatus::InMempool => "pending".to_string(),
            PendingStatus::Mined { .. } => "confirmed".to_string(),
        },
        confirmations: tx.confirmations(latest_height),
        created_at: Utc
            .timestamp_opt(tx.submitted_at as i64, 0)
            .single()
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| {
                Utc.timestamp_opt(0, 0)
                    .single()
                    .expect("unix epoch")
                    .to_rfc3339()
            }),
    }
}

fn sync_once(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    params: SyncParams,
) -> Result<SyncResponse> {
    runtime.block_on(async {
        let client = Arc::new(
            SubstrateRpcClient::connect(&params.ws_url)
                .await
                .map_err(|e| anyhow!("Failed to connect: {e}"))?,
        );

        let engine = AsyncWalletSyncEngine::new(client, store.clone())
            .with_skip_genesis_check(params.force_rescan);
        let outcome = engine.sync_once().await.map_err(|e| anyhow!(e.to_string()))?;
        let new_height = store.last_synced_height()?;
        Ok(SyncResponse {
            new_height,
            commitments: outcome.commitments,
            ciphertexts: outcome.ciphertexts,
            recovered: outcome.recovered,
            spent: outcome.spent,
        })
    })
}

fn tx_send(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    params: SendParams,
) -> Result<SendResponse> {
    if store.mode()? == WalletMode::WatchOnly {
        anyhow::bail!("watch-only wallets cannot send");
    }

    runtime.block_on(async {
        let client = Arc::new(
            SubstrateRpcClient::connect(&params.ws_url)
                .await
                .map_err(|e| anyhow!("Failed to connect: {e}"))?,
        );
        let engine = AsyncWalletSyncEngine::new(client.clone(), store.clone());
        engine.sync_once().await.map_err(|e| anyhow!(e.to_string()))?;

        let recipients = parse_recipients(&params.recipients)?;
        let metadata = transfer_recipients_from_specs(&params.recipients);
        let output_asset = recipients
            .first()
            .map(|recipient| recipient.asset_id)
            .unwrap_or(transaction_circuit::constants::NATIVE_ASSET_ID);

        if output_asset == transaction_circuit::constants::NATIVE_ASSET_ID {
            let mut notes = store.spendable_notes(0)?;
            notes.sort_by(|a, b| b.recovered.note.value.cmp(&a.recovered.note.value));
            let total_needed = recipients.iter().map(|r| r.value).sum::<u64>() + params.fee;
            let mut selected_count = 0;
            let mut selected_value = 0u64;
            for note in &notes {
                if selected_value >= total_needed {
                    break;
                }
                selected_value += note.recovered.note.value;
                selected_count += 1;
            }
            let plan = ConsolidationPlan::estimate(selected_count);
            if !plan.is_empty() {
                if !params.auto_consolidate {
                    anyhow::bail!("note consolidation required before sending");
                }
                wallet::execute_consolidation(store.clone(), &client, total_needed, params.fee, true)
                    .await
                    .map_err(|e| anyhow!("Consolidation failed: {e}"))?;
            }
        }

        precheck_nullifiers(&store, &client, &recipients, params.fee)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;

        let built = build_transaction(&store, &recipients, params.fee)?;
        store.mark_notes_pending(&built.spent_note_indexes, true)?;

        let result = client
            .submit_shielded_transfer_unsigned(&built.bundle)
            .await;

        match result {
            Ok(tx_hash) => {
                let genesis_hash = match store.genesis_hash()? {
                    Some(hash) => hash,
                    None => {
                        let metadata = client.get_chain_metadata().await?;
                        store.set_genesis_hash(metadata.genesis_hash)?;
                        metadata.genesis_hash
                    }
                };
                store.record_outgoing_disclosures(
                    tx_hash,
                    genesis_hash,
                    built.outgoing_disclosures.clone(),
                )?;
                store.record_pending_submission(
                    tx_hash,
                    built.nullifiers.clone(),
                    built.spent_note_indexes.clone(),
                    metadata.clone(),
                    params.fee,
                )?;
                Ok(SendResponse {
                    tx_hash: format!("0x{}", hex::encode(tx_hash)),
                    recipients: metadata,
                })
            }
            Err(err) => {
                store.mark_notes_pending(&built.spent_note_indexes, false)?;
                Err(anyhow!("Transaction submission failed: {err}"))
            }
        }
    })
}

fn disclosure_create(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    params: DisclosureCreateParams,
) -> Result<DisclosurePackage> {
    if store.mode()? == WalletMode::WatchOnly {
        anyhow::bail!("watch-only wallets cannot create payment proofs");
    }

    let tx_id = parse_hex_32(&params.tx_id)?;

    runtime.block_on(async {
        let client = Arc::new(
            SubstrateRpcClient::connect(&params.ws_url)
                .await
                .map_err(|e| anyhow!("Failed to connect: {e}"))?,
        );
        let engine = AsyncWalletSyncEngine::new(client.clone(), store.clone());
        engine.sync_once().await.map_err(|e| anyhow!(e.to_string()))?;

        let record = store
            .find_outgoing_disclosure(&tx_id, params.output)?
            .ok_or_else(|| anyhow!("no outgoing disclosure record for tx output"))?;

        let expected_commitment = note_commitment_bytes(
            record.note.value,
            record.note.asset_id,
            &record.note.pk_recipient,
            &record.note.rho,
            &record.note.r,
        );
        if expected_commitment != record.commitment {
            anyhow::bail!("stored disclosure record has mismatched commitment");
        }

        let claim = PaymentDisclosureClaim {
            value: record.note.value,
            asset_id: record.note.asset_id,
            pk_recipient: record.note.pk_recipient,
            commitment: record.commitment,
        };
        let witness = PaymentDisclosureWitness {
            rho: record.note.rho,
            r: record.note.r,
        };
        let proof_bundle = prove_payment_disclosure(&claim, &witness)
            .map_err(|e| anyhow!("proof generation failed: {e}"))?;

        let leaf_index = store
            .find_commitment_index(record.commitment)?
            .ok_or_else(|| anyhow!("commitment not found in wallet tree"))?;
        let tree = store.commitment_tree()?;
        let auth_path = tree
            .authentication_path(leaf_index as usize)
            .map_err(|e| anyhow!("merkle path error: {e}"))?;
        let anchor = tree.root();
        let siblings = auth_path;

        Ok(DisclosurePackage {
            version: 1,
            chain: DisclosureChainInfo {
                genesis_hash: record.genesis_hash,
            },
            claim: DisclosureClaim {
                recipient_address: record.recipient_address.clone(),
                pk_recipient: record.note.pk_recipient,
                value: record.note.value,
                asset_id: record.note.asset_id,
                commitment: record.commitment,
            },
            confirmation: DisclosureConfirmation {
                anchor,
                leaf_index,
                siblings,
            },
            proof: DisclosureProof {
                air_hash: proof_bundle.air_hash,
                bytes: encode_base64(&proof_bundle.proof_bytes),
            },
            disclosed_memo: memo_to_disclosed_string(&record.memo),
        })
    })
}

fn disclosure_verify(
    runtime: &tokio::runtime::Runtime,
    params: DisclosureVerifyParams,
) -> Result<DisclosureVerifyResponse> {
    let package = params.package;

    let commitment_felt = bytes48_to_felts(&package.claim.commitment)
        .ok_or_else(|| anyhow!("commitment is not a canonical field encoding"))?;
    let anchor_felt = bytes48_to_felts(&package.confirmation.anchor)
        .ok_or_else(|| anyhow!("anchor is not a canonical field encoding"))?;
    let sibling_felts = package
        .confirmation
        .siblings
        .iter()
        .map(|bytes| bytes48_to_felts(bytes).ok_or_else(|| anyhow!("non-canonical merkle sibling")))
        .collect::<Result<_, _>>()?;

    let merkle_path = MerklePath {
        siblings: sibling_felts,
    };
    if !merkle_path.verify(
        commitment_felt,
        package.confirmation.leaf_index,
        anchor_felt,
    ) {
        anyhow::bail!("merkle path verification failed");
    }

    runtime.block_on(async {
        let client = SubstrateRpcClient::connect(&params.ws_url)
            .await
            .map_err(|e| anyhow!("Failed to connect: {e}"))?;
        let metadata = client.get_chain_metadata().await?;
        if metadata.genesis_hash != package.chain.genesis_hash {
            anyhow::bail!("genesis hash mismatch");
        }
        let anchor_valid = client.is_valid_anchor(&package.confirmation.anchor).await?;
        if !anchor_valid {
            anyhow::bail!("anchor is not valid on chain");
        }
        Ok::<_, anyhow::Error>(())
    })?;

    let proof_bytes = decode_base64(&package.proof.bytes)?;
    let bundle = PaymentDisclosureProofBundle {
        claim: PaymentDisclosureClaim {
            value: package.claim.value,
            asset_id: package.claim.asset_id,
            pk_recipient: package.claim.pk_recipient,
            commitment: package.claim.commitment,
        },
        proof_bytes,
        air_hash: package.proof.air_hash,
    };

    verify_payment_disclosure(&bundle).map_err(|e| anyhow!(e.to_string()))?;

    Ok(DisclosureVerifyResponse {
        verified: true,
        recipient_address: package.claim.recipient_address.clone(),
        value: package.claim.value,
        asset_id: package.claim.asset_id,
        commitment: format!("0x{}", hex::encode(package.claim.commitment)),
        anchor: format!("0x{}", hex::encode(package.confirmation.anchor)),
        chain: format!("0x{}", hex::encode(package.chain.genesis_hash)),
    })
}

fn parse_hex_32(input: &str) -> Result<[u8; 32]> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(trimmed).map_err(|e| anyhow!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32-byte hex value");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn memo_to_disclosed_string(memo: &Option<MemoPlaintext>) -> Option<String> {
    let memo = memo.as_ref()?;
    if memo.as_bytes().is_empty() {
        return None;
    }
    match String::from_utf8(memo.as_bytes().to_vec()) {
        Ok(text) => Some(text),
        Err(_) => Some(format!("base64:{}", encode_base64(memo.as_bytes()))),
    }
}
