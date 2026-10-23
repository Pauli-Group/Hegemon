//! Explicit launch-chain tooling. RPC is a trusted full-node data source.
//! Every exported payment keeps a durable input hold and exact recoverable bytes.

#[cfg(feature = "rpc-client")]
pub use supported::{run, LaunchCommands};

#[cfg(feature = "rpc-client")]
#[allow(dead_code)]
fn main() -> anyhow::Result<()> {
    use clap::Parser;
    run(supported::ExampleCli::parse().command)
}

#[cfg(not(feature = "rpc-client"))]
fn main() {
    eprintln!("launch_wallet_prepare requires the rpc-client feature");
}

#[cfg(feature = "rpc-client")]
mod supported {
    use anyhow::{anyhow, bail, Context, Result};
    use base64::Engine;
    use clap::{Args, Parser, Subcommand};
    use jsonrpsee_core::{client::ClientT, rpc_params};
    use rand::rngs::OsRng;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::{
        fs,
        io::{self, Read, Write},
        path::{Path, PathBuf},
    };
    use wallet::{
        address::ShieldedAddress,
        node_rpc::NodeRpcClient,
        poseidon2_v8_sync::{LaunchWalletContext, Poseidon2V8CanonicalTip},
        store::{write_private_file, WalletStore},
    };
    use zeroize::Zeroizing;

    #[derive(Parser)]
    #[command(about = "Explicitly pinned launch wallet preparation; exports never submit")]
    pub struct ExampleCli {
        #[command(subcommand)]
        pub command: LaunchCommands,
    }

    #[derive(Subcommand)]
    pub enum LaunchCommands {
        /// Create or open a wallet and pin the exact launch genesis and source.
        Init(StoreArgs),
        /// Reconcile the canonical journal with the pinned trusted full node.
        Sync(SyncArgs),
        /// Approve and prepare a payment, durably retaining its exported carrier.
        Prepare(PrepareArgs),
        /// Show cached public balance and durable reservation status.
        Status(StoreArgs),
        /// Recover the identical retained payment carrier without rebuilding it.
        Recover(RecoverArgs),
        /// Submit an exact retained RP06 candidate through the source-gated wallet journal.
        Submit(SubmitArgs),
        /// Set up encrypted HTLC agreements and approve exact Lock/Claim/Refund carriers.
        Htlc {
            #[command(subcommand)]
            command: HtlcCommands,
        },
    }

    #[derive(Args)]
    pub struct StoreArgs {
        #[arg(long)]
        store: PathBuf,
        /// Local public context JSON with full chain, genesis, manifest and lifetime.
        #[arg(long)]
        context: PathBuf,
        /// Trusted full-node RPC. Credentials are never copied into artifacts.
        #[arg(long, default_value = "http://127.0.0.1:9944")]
        rpc: String,
        /// Explicit candidate testing; requires a retained-support build.
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        #[arg(long, default_value_t = false)]
        retained_test: bool,
    }
    impl StoreArgs {
        fn retained(&self) -> bool {
            #[cfg(feature = "poseidon2-v8-retained-test-support")]
            {
                self.retained_test
            }
            #[cfg(not(feature = "poseidon2-v8-retained-test-support"))]
            {
                false
            }
        }
    }
    #[derive(Args)]
    pub struct SyncArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        to_height: Option<u64>,
        /// Maximum new blocks per invocation; repeat sync to continue safely.
        #[arg(long, default_value_t = 1000)]
        max_blocks: u64,
    }
    #[derive(Args)]
    pub struct PrepareArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        to: String,
        /// Native asset amount in base units.
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = 0)]
        fee: u64,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 1000)]
        max_blocks: u64,
    }
    #[derive(Args)]
    pub struct RecoverArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        reservation_id: String,
        #[arg(long)]
        out: PathBuf,
        /// Recover bytes without an RPC readiness check; carrier status stays explicit.
        #[arg(long, default_value_t = false)]
        offline: bool,
        #[arg(long, default_value_t = 1000)]
        max_blocks: u64,
    }
    #[derive(Args)]
    pub struct SubmitArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        reservation_id: String,
        /// Retained candidate submission requires the node's exact Development manifest.
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        #[arg(long)]
        runtime_manifest: Option<PathBuf>,
    }

    #[derive(Subcommand)]
    pub enum HtlcCommands {
        /// Create a HiddenOnHegemon offer from two unlocked, full V8 wallet addresses.
        OfferCreate(HtlcOfferCreateArgs),
        /// Accept an exact public offer on the pinned chain; no funds are spent.
        OfferAccept(HtlcOfferAcceptArgs),
        /// Export the already accepted public offer to a new file.
        OfferExport(HtlcFileArgs),
        /// Show public swap, attempt and selectable note metadata.
        Status(HtlcStatusArgs),
        /// Create and retain the private locked-note agreement inside the wallet.
        AgreementCreate(HtlcAgreementCreateArgs),
        /// Import the counterparty's encrypted locked-note agreement.
        AgreementImport(HtlcAgreementImportArgs),
        /// Encrypt the retained agreement to the exact counterparty address.
        AgreementExport(HtlcAgreementExportArgs),
        /// Import an exact 32-byte preimage from a private binary file.
        SecretImport(HtlcSecretArgs),
        /// Lock one exact-value ordinary input; never prepares an extra split.
        PrepareLock(HtlcPrepareArgs),
        /// Claim the selected canonical locked-note occurrence.
        PrepareClaim(HtlcPrepareArgs),
        /// Refund the selected canonical locked-note occurrence after maturity.
        PrepareRefund(HtlcPrepareArgs),
        /// Recover identical retained carrier bytes, preserving the durable hold.
        Recover(HtlcRecoverArgs),
        /// Submit a retained candidate through the source-gated wallet journal.
        Submit(HtlcSubmitArgs),
    }
    #[derive(Args)]
    pub struct HtlcOfferCreateArgs {
        #[arg(long)]
        context: PathBuf,
        #[arg(long)]
        claim_store: PathBuf,
        #[arg(long)]
        refund_store: PathBuf,
        #[arg(long, default_value_t = 0)]
        claim_index: u32,
        #[arg(long, default_value_t = 0)]
        refund_index: u32,
        #[arg(long)]
        hashlock: String,
        #[arg(long)]
        value: u64,
        #[arg(long)]
        maximum_fee: u64,
        #[arg(long)]
        timeout_height: u64,
        #[arg(long)]
        bitcoin_amount_sat: u64,
        #[arg(long)]
        bitcoin_claim_public_key: String,
        #[arg(long)]
        bitcoin_refund_public_key: String,
        #[arg(long)]
        bitcoin_refund_height: u32,
        #[arg(long, default_value_t = 1)]
        bitcoin_required_confirmations: u32,
        #[arg(long)]
        out: PathBuf,
        /// Candidate/dev contexts require explicit retained-test support.
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        #[arg(long, default_value_t = false)]
        retained_test: bool,
    }
    impl HtlcOfferCreateArgs {
        fn retained(&self) -> bool {
            #[cfg(feature = "poseidon2-v8-retained-test-support")]
            {
                self.retained_test
            }
            #[cfg(not(feature = "poseidon2-v8-retained-test-support"))]
            {
                false
            }
        }
    }
    #[derive(Args)]
    pub struct HtlcSubmitArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        attempt_id: String,
        /// Development submit additionally requires exact current manifest equality.
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        #[arg(long)]
        runtime_manifest: Option<PathBuf>,
    }
    #[derive(Args)]
    pub struct HtlcOfferAcceptArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        offer: PathBuf,
    }
    #[derive(Args)]
    pub struct HtlcFileArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        swap_id: String,
        #[arg(long)]
        out: PathBuf,
    }
    #[derive(Args)]
    pub struct HtlcStatusArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        swap_id: Option<String>,
        #[arg(long, default_value_t = false)]
        offline: bool,
        #[arg(long, default_value_t = 1000)]
        max_blocks: u64,
    }
    #[derive(Args)]
    pub struct HtlcAgreementCreateArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        swap_id: String,
        /// Exact V8 recipient for the agreed locked note.
        #[arg(long)]
        to: String,
    }
    #[derive(Args)]
    pub struct HtlcAgreementImportArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        swap_id: String,
        /// Encrypted agreement file, regular and mode0600.
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value_t = 0)]
        diversifier_index: u32,
    }
    #[derive(Args)]
    pub struct HtlcAgreementExportArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        swap_id: String,
        /// Full counterparty address receiving the encrypted agreement.
        #[arg(long)]
        to: String,
        #[arg(long)]
        out: PathBuf,
    }
    #[derive(Args)]
    pub struct HtlcSecretArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        swap_id: String,
        /// Exact32 raw bytes in a regular mode0600 file; JSON and hex are rejected.
        #[arg(long)]
        input: PathBuf,
    }
    #[derive(Args)]
    pub struct HtlcPrepareArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        swap_id: String,
        /// Explicit canonical occurrence; use htlc status to select it.
        #[arg(long)]
        input_position: u64,
        #[arg(long)]
        fee: u64,
        /// Full output recipient, checked against the agreed policy.
        #[arg(long)]
        to: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 1000)]
        max_blocks: u64,
    }
    #[derive(Args)]
    pub struct HtlcRecoverArgs {
        #[command(flatten)]
        common: StoreArgs,
        #[arg(long)]
        attempt_id: String,
        #[arg(long)]
        out: PathBuf,
        /// Exact recovery without live/source readiness; retained holds stay active.
        #[arg(long, default_value_t = false)]
        offline: bool,
        #[arg(long, default_value_t = 1000)]
        max_blocks: u64,
    }

    #[derive(Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct ContextFile {
        chain_id: String,
        genesis_hash: String,
        manifest_digest: String,
        activation_height: u64,
        deactivation_height_exclusive: u64,
        /// Candidate genesis only. Production roots come from source authority.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stablecoin_genesis_root: Option<[u64; 7]>,
    }
    impl ContextFile {
        fn context(&self) -> Result<LaunchWalletContext> {
            LaunchWalletContext::new(
                fixed_hex(&self.chain_id, "chain_id")?,
                fixed_hex(&self.genesis_hash, "genesis_hash")?,
                fixed_hex(&self.manifest_digest, "manifest_digest")?,
                self.activation_height,
                self.deactivation_height_exclusive,
            )
            .context("Invalid finite launch context")
        }
        fn load(path: &Path, retained: bool) -> Result<(Self, LaunchWalletContext)> {
            let bytes = fs::read(path).context("Read local public launch context")?;
            if bytes.len() > 16 * 1024 {
                bail!("Launch context exceeds 16 KiB");
            }
            let file: Self = serde_json::from_slice(&bytes).context("Parse launch context JSON")?;
            let context = file.context()?;
            if !retained && file.stablecoin_genesis_root.is_some() {
                bail!("Production genesis roots must come from source authority");
            }
            if retained && file.stablecoin_genesis_root.is_none() {
                bail!("Retained test context requires stablecoin_genesis_root");
            }
            // This CLI starts with a fresh launch genesis and has no preactivation route.
            if file.activation_height != 1 {
                bail!("Launch CLI requires activation_height=1 for sequential genesis replay");
            }
            Ok((file, context))
        }
    }
    fn fixed_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
        let raw = value
            .strip_prefix("0x")
            .ok_or_else(|| anyhow!("{field} requires 0x-prefixed lowercase hex"))?;
        if raw.len() != N * 2
            || !raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("{field} must encode exactly {N} bytes in lowercase hex");
        }
        let bytes = hex::decode(raw).map_err(|_| anyhow!("Invalid {field}"))?;
        bytes
            .try_into()
            .map_err(|_| anyhow!("Invalid {field} length"))
    }
    fn secret(new: bool) -> Result<Zeroizing<String>> {
        let pass = Zeroizing::new(
            rpassword::prompt_password(if new {
                "Enter new wallet passphrase: "
            } else {
                "Enter wallet passphrase: "
            })
            .context("Read passphrase from terminal")?,
        );
        if pass.is_empty() {
            bail!("Passphrase cannot be empty");
        }
        if new {
            let confirm = Zeroizing::new(
                rpassword::prompt_password("Confirm passphrase: ")
                    .context("Read passphrase confirmation")?,
            );
            if *pass != *confirm {
                bail!("Passphrases do not match");
            }
        }
        Ok(pass)
    }
    fn initialize(
        store: &WalletStore,
        file: &ContextFile,
        context: LaunchWalletContext,
        retained: bool,
    ) -> Result<()> {
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        if retained {
            return store
                .ensure_poseidon2_v8_launch_genesis_for_retained_test(
                    context,
                    file.stablecoin_genesis_root
                        .ok_or_else(|| anyhow!("Retained genesis root missing"))?,
                )
                .context("Initialize exact retained launch genesis");
        }
        let _ = (file, retained);
        store
            .ensure_poseidon2_v8_launch_genesis(context)
            .context("Initialize exact source-authorized launch genesis")
    }

    async fn header(endpoint: &str, hash: [u8; 32]) -> Result<Value> {
        let hash = format!("0x{}", hex::encode(hash));
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            let client = jsonrpsee_http_client::HttpClientBuilder::default()
                .build(endpoint)
                .map_err(|_| anyhow!("Connect trusted HTTP RPC"))?;
            client
                .request("chain_getHeader", rpc_params![hash])
                .await
                .map_err(|_| anyhow!("Fetch exact native header from trusted RPC"))
        } else if endpoint.starts_with("ws://") || endpoint.starts_with("wss://") {
            let client = jsonrpsee_ws_client::WsClientBuilder::default()
                .build(endpoint)
                .await
                .map_err(|_| anyhow!("Connect trusted WebSocket RPC"))?;
            client
                .request("chain_getHeader", rpc_params![hash])
                .await
                .map_err(|_| anyhow!("Fetch exact native header from trusted RPC"))
        } else {
            bail!("RPC must use http, https, ws, or wss");
        }
    }
    fn check_header(value: &Value, context: LaunchWalletContext, height: u64) -> Result<()> {
        let chain = value
            .get("chainId")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Native RPC header has no full chainId"))?;
        if fixed_hex::<32>(chain, "RPC chainId")? != context.chain_id() {
            bail!("Trusted RPC chain differs from pinned launch chain");
        }
        let number = value
            .get("number")
            .and_then(Value::as_str)
            .and_then(|s| s.strip_prefix("0x"))
            .and_then(|s| u64::from_str_radix(s, 16).ok());
        if number != Some(height) {
            bail!("Native RPC header height differs from selected hash");
        }
        Ok(())
    }
    async fn rpc_target(
        args: &StoreArgs,
        context: LaunchWalletContext,
        requested: Option<u64>,
    ) -> Result<(NodeRpcClient, u64, [u8; 32])> {
        let client = NodeRpcClient::connect(&args.rpc)
            .await
            .map_err(|_| anyhow!("Connect trusted launch RPC"))?;
        let metadata = client
            .get_chain_metadata()
            .await
            .map_err(|_| anyhow!("Read trusted RPC genesis"))?;
        if metadata.genesis_hash != context.genesis_hash() {
            bail!("Trusted RPC genesis differs from pinned launch genesis");
        }
        let latest = client
            .latest_block()
            .await
            .map_err(|_| anyhow!("Read trusted RPC latest height"))?;
        let height = requested.unwrap_or(latest.height);
        if height > latest.height {
            bail!("Requested height exceeds trusted node tip");
        }
        let hash = client
            .block_hash(height)
            .await
            .map_err(|_| anyhow!("Read selected canonical block hash"))?
            .ok_or_else(|| anyhow!("Selected canonical block is unavailable"))?;
        check_header(&header(&args.rpc, hash).await?, context, height)?;
        Ok((client, height, hash))
    }
    async fn sync(
        store: &WalletStore,
        args: &StoreArgs,
        file: &ContextFile,
        context: LaunchWalletContext,
        requested: Option<u64>,
        max_blocks: u64,
    ) -> Result<(u64, bool)> {
        if max_blocks == 0 {
            bail!("max-blocks must be positive");
        }
        let (client, target_height, target_hash) = rpc_target(args, context, requested).await?;
        if target_height >= file.deactivation_height_exclusive {
            bail!("Trusted node tip exceeds pinned finite launch lifetime");
        }
        initialize(store, file, context, args.retained())?;
        store.require_launch_context(context)?;
        let tip = store.poseidon2_v8_tip()?;
        let mut ancestor = tip.height.min(target_height);
        loop {
            let local = store.poseidon2_v8_canonical_hash(ancestor)?;
            let remote = client
                .block_hash(ancestor)
                .await
                .map_err(|_| anyhow!("Find canonical common ancestor"))?;
            if local.is_some() && local == remote {
                break;
            }
            if ancestor == 0 {
                bail!("Trusted RPC and wallet do not share pinned genesis");
            }
            ancestor -= 1;
        }
        let ancestor_hash = store
            .poseidon2_v8_canonical_hash(ancestor)?
            .ok_or_else(|| anyhow!("Wallet common ancestor missing"))?;
        if ancestor != tip.height {
            store.rollback_poseidon2_v8_to(ancestor, ancestor_hash)?;
        }
        let stop = ancestor.saturating_add(max_blocks).min(target_height);
        for height in ancestor + 1..=stop {
            let block = client
                .canonical_block_actions(height)
                .await
                .map_err(|_| anyhow!("Fetch bound canonical launch block at height {height}"))?
                .ok_or_else(|| anyhow!("Canonical launch body missing at height {height}"))?;
            #[cfg(feature = "poseidon2-v8-retained-test-support")]
            if args.retained() {
                store
                    .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&block, context)?;
                continue;
            }
            store.apply_poseidon2_v8_launch_canonical_block(&block, context)?;
        }
        if client
            .block_hash(target_height)
            .await
            .map_err(|_| anyhow!("Recheck canonical launch target"))?
            != Some(target_hash)
        {
            bail!("Canonical target changed during sync; repeat sync before preparing");
        }
        let now = store.poseidon2_v8_tip()?;
        if client
            .block_hash(now.height)
            .await
            .map_err(|_| anyhow!("Recheck resulting mirror tip"))?
            != Some(now.block_hash)
        {
            bail!("Canonical mirror tip changed during sync; repeat sync before preparing");
        }
        Ok((now.height, now.height == target_height))
    }
    fn status(store: &WalletStore, context: LaunchWalletContext) -> Result<Value> {
        store.require_launch_context(context)?;
        let tip = store.poseidon2_v8_tip()?;
        let notes = store.poseidon2_v8_owned_notes()?;
        let balance = notes
            .iter()
            .filter(|note| {
                !note.spent
                    && note.opening.asset_id == transaction_circuit::constants::NATIVE_ASSET_ID
            })
            .try_fold(0u64, |sum, note| {
                sum.checked_add(note.opening.value)
                    .ok_or_else(|| anyhow!("Native balance overflow"))
            })?;
        let reservations: Vec<Value> = store
            .poseidon2_v8_reservations()?
            .into_iter()
            .map(|entry| {
                json!({
                    "reservation_id": format!("0x{}", hex::encode(entry.reservation_id)),
                    "status": entry.status,
                    "inputs_consumed": entry.inputs_consumed,
                    "inputs_reserved": entry.inputs_reserved,
                })
            })
            .collect();
        Ok(json!({
            "chain_id": format!("0x{}", hex::encode(context.chain_id())),
            "height": tip.height,
            "block_hash": format!("0x{}", hex::encode(tip.block_hash)),
            "native_balance_base_units": balance,
            "balance_includes_reserved_inputs": true,
            "unspent_notes": notes.iter().filter(|note| !note.spent).count(),
            "reservations": reservations,
            "trust": "pinned trusted full-node RPC",
        }))
    }
    fn approve(value: &Value) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(value)?);
        eprint!("Type PREPARE to approve this exact payment and retain its exported input hold: ");
        io::stderr().flush()?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .context("Read exact operation approval")?;
        if answer.trim() != "PREPARE" {
            bail!("Payment preparation was not approved");
        }
        Ok(())
    }
    pub fn run(command: LaunchCommands) -> Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        match command {
            LaunchCommands::Init(args) => {
                let (file, context) = ContextFile::load(&args.context, args.retained())?;
                runtime.block_on(rpc_target(&args, context, Some(0)))?;
                let pass = secret(!args.store.exists())?;
                let store = if args.store.exists() {
                    WalletStore::open(&args.store, &pass)?
                } else {
                    WalletStore::create_full_if_missing(&args.store, &pass)?
                };
                initialize(&store, &file, context, args.retained())?;
                println!(
                    "{}",
                    json!({"chain_id": file.chain_id, "genesis_hash": file.genesis_hash,
                    "address": store.primary_address()?.encode()?, "height": store.poseidon2_v8_tip()?.height})
                );
                Ok(())
            }
            LaunchCommands::Sync(args) => {
                let (file, context) =
                    ContextFile::load(&args.common.context, args.common.retained())?;
                let pass = secret(false)?;
                let store = WalletStore::open(&args.common.store, &pass)?;
                let (height, complete) = runtime.block_on(sync(
                    &store,
                    &args.common,
                    &file,
                    context,
                    args.to_height,
                    args.max_blocks,
                ))?;
                println!("{}", json!({"height": height, "target_reached": complete}));
                Ok(())
            }
            LaunchCommands::Status(args) => {
                let (_, context) = ContextFile::load(&args.context, args.retained())?;
                let pass = secret(false)?;
                let store = WalletStore::open_read_only(&args.store, &pass)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&status(&store, context)?)?
                );
                Ok(())
            }
            LaunchCommands::Prepare(args) => prepare(&runtime, args),
            LaunchCommands::Recover(args) => recover(&runtime, args),
            LaunchCommands::Submit(args) => submit(&runtime, args),
            LaunchCommands::Htlc { command } => htlc_run(&runtime, command),
        }
    }

    fn output_preflight(path: &Path) -> Result<()> {
        if fs::symlink_metadata(path).is_ok() {
            bail!("Output already exists; choose a new artifact path");
        }
        Ok(())
    }
    fn artifact(
        file: &ContextFile,
        export: &wallet::rp06_transfer_store::Rp06TransferCandidateExport,
        retained: bool,
        live_reference_eligible: Option<bool>,
        operation: Option<Value>,
    ) -> Value {
        json!({
            "schema": "hegemon-rp06-transfer-export-v1",
            "context": file,
            "proof_mode": if retained { "retained_candidate" } else { "source_authorized" },
            "reservation_id": format!("0x{}", hex::encode(export.reservation_id)),
            "candidate_status": export.status,
            "parent_height": export.parent_height,
            "parent_hash": format!("0x{}", hex::encode(export.parent_hash)),
            "local_canonical_reference_eligible": export.current_parent_eligible(),
            "live_canonical_reference_eligible": live_reference_eligible,
            "reference_window_blocks": protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW,
            "note_anchor": export.tip().anchor,
            "stablecoin_root": export.tip().stablecoin_root,
            "carrier_sha512": format!("0x{}", hex::encode(export.carrier_sha512)),
            "inline_args_base64": base64::engine::general_purpose::STANDARD.encode(&export.inline_args),
            "family_id": protocol_versioning::launch_candidate::LAUNCH_SHIELDED_FAMILY_ID,
            "action_id": protocol_versioning::launch_candidate::RP06_ACTION_ID,
            "operation_review": operation,
            "submission": "not submitted by this command; exported inputs remain durably held",
        })
    }
    fn publish(path: &Path, value: &Value, id: [u8; 32]) -> Result<()> {
        // The store already retains this exact carrier and its uncertainty.
        // A filesystem failure must preserve that hold for explicit recovery.
        let bytes = serde_json::to_vec_pretty(value)?;
        write_private_file(path, &bytes).map_err(|error| anyhow!(
            "Artifact write failed ({error}); candidate remains held. Recover reservation 0x{} to a new output path",
            hex::encode(id)
        ))?;
        println!(
            "{}",
            json!({
                "reservation_id": format!("0x{}", hex::encode(id)),
                "artifact": path,
                "inputs_held": true,
            })
        );
        Ok(())
    }
    fn prepare(runtime: &tokio::runtime::Runtime, args: PrepareArgs) -> Result<()> {
        output_preflight(&args.out)?;
        let (file, context) = ContextFile::load(&args.common.context, args.common.retained())?;
        let recipient =
            ShieldedAddress::decode(&args.to).context("Decode exact payment recipient")?;
        let recipient_text = recipient.encode()?;
        let pass = secret(false)?;
        let store = WalletStore::open(&args.common.store, &pass)?;
        let (_, complete) = runtime.block_on(sync(
            &store,
            &args.common,
            &file,
            context,
            None,
            args.max_blocks,
        ))?;
        if !complete {
            bail!("Sync limit reached; repeat launch sync before payment preparation");
        }
        let tip = store.poseidon2_v8_tip()?;
        let operation = json!({
            "chain_id": file.chain_id,
            "genesis_hash": file.genesis_hash,
            "manifest_digest": file.manifest_digest,
            "parent_height": tip.height,
            "parent_hash": format!("0x{}", hex::encode(tip.block_hash)),
            "recipient": recipient_text,
            "native_amount_base_units": args.amount,
            "fee_base_units": args.fee,
            "candidate_testing": args.common.retained(),
            "input_selection": "first two available canonical native notes; total balance may include other or reserved notes",
        });
        approve(&operation)?;
        let mut rng = OsRng;
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        let prepared = if args.common.retained() {
            wallet::rp06_transfer::prepare_rp06_transfer_for_retained_test(
                &store,
                context,
                &recipient,
                args.amount,
                args.fee,
                &mut rng,
            )?
        } else {
            wallet::rp06_transfer::prepare_rp06_transfer(
                &store,
                context,
                &recipient,
                args.amount,
                args.fee,
                &mut rng,
            )?
        };
        #[cfg(not(feature = "poseidon2-v8-retained-test-support"))]
        let prepared = wallet::rp06_transfer::prepare_rp06_transfer(
            &store,
            context,
            &recipient,
            args.amount,
            args.fee,
            &mut rng,
        )?;
        // The proof keeps its original full reference. Reconcile new blocks
        // after proving, then require that exact checkpoint to remain attached.
        let (_, complete) = runtime.block_on(sync(
            &store,
            &args.common,
            &file,
            context,
            None,
            args.max_blocks,
        ))?;
        if !complete {
            bail!("Sync limit reached after proving; repeat sync and approve a fresh payment");
        }
        let (_, live_height, live_hash) =
            runtime.block_on(rpc_target(&args.common, context, None))?;
        if prepared.tip() != tip || !reference_eligible(&store, &file, tip, live_height, live_hash)?
        {
            bail!("Proof reference detached, expired, or beyond the canonical reference window; approve a fresh payment");
        }
        let export = prepared
            .export_candidate()
            .context("Durably retain exact payment before export")?;
        publish(
            &args.out,
            &artifact(
                &file,
                &export,
                args.common.retained(),
                Some(true),
                Some(operation),
            ),
            export.reservation_id,
        )
    }
    fn reference_eligible(
        store: &WalletStore,
        file: &ContextFile,
        captured: Poseidon2V8CanonicalTip,
        live_height: u64,
        live_hash: [u8; 32],
    ) -> Result<bool> {
        let mirror = store.poseidon2_v8_tip()?;
        let attached = store.poseidon2_v8_canonical_tip_at_height(captured.height)?;
        Ok(reference_checkpoint_eligible(
            file,
            captured,
            attached,
            mirror,
            live_height,
            live_hash,
        ))
    }
    fn reference_checkpoint_eligible(
        file: &ContextFile,
        captured: Poseidon2V8CanonicalTip,
        attached: Option<Poseidon2V8CanonicalTip>,
        mirror: Poseidon2V8CanonicalTip,
        live_height: u64,
        live_hash: [u8; 32],
    ) -> bool {
        let Some(inclusion_height) = live_height.checked_add(1) else {
            return false;
        };
        attached == Some(captured)
            && mirror.height == live_height
            && mirror.block_hash == live_hash
            && inclusion_height >= file.activation_height
            && inclusion_height < file.deactivation_height_exclusive
            && protocol_versioning::launch_reference_policy::launch_reference_distance_allowed(
                captured.height,
                live_height,
                false,
            )
    }
    fn recover(runtime: &tokio::runtime::Runtime, args: RecoverArgs) -> Result<()> {
        output_preflight(&args.out)?;
        let (file, context) = ContextFile::load(&args.common.context, args.common.retained())?;
        let id = fixed_hex::<32>(&args.reservation_id, "reservation_id")?;
        let pass = secret(false)?;
        let store = WalletStore::open(&args.common.store, &pass)?;
        store.require_launch_context(context)?;
        if !args.offline {
            let (_, complete) = runtime.block_on(sync(
                &store,
                &args.common,
                &file,
                context,
                None,
                args.max_blocks,
            ))?;
            if !complete {
                bail!("Sync limit reached; repeat launch sync before live recovery");
            }
        }
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        let export = if args.common.retained() {
            store.export_rp06_transfer_candidate_for_retained_test(id)?
        } else {
            store.export_rp06_transfer_candidate(id)?
        };
        #[cfg(not(feature = "poseidon2-v8-retained-test-support"))]
        let export = store.export_rp06_transfer_candidate(id)?;
        let live_eligible = if args.offline {
            None
        } else {
            let (_, height, hash) = runtime.block_on(rpc_target(&args.common, context, None))?;
            Some(reference_eligible(
                &store,
                &file,
                export.tip(),
                height,
                hash,
            )?)
        };
        publish(
            &args.out,
            &artifact(&file, &export, args.common.retained(), live_eligible, None),
            id,
        )
    }

    async fn submit_rp06_rpc(rpc: &str, inline_args: &[u8]) -> Result<wallet::ActionId48> {
        use protocol_versioning::launch_candidate;

        let request = json!({
            "binding_circuit": launch_candidate::RP06_VERSION_BINDING.circuit,
            "binding_crypto": launch_candidate::RP06_VERSION_BINDING.crypto,
            "family_id": launch_candidate::LAUNCH_SHIELDED_FAMILY_ID,
            "action_id": launch_candidate::RP06_ACTION_ID,
            "object_refs": [], "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(inline_args),
            "authorization_proof": null, "authorization_signatures": [], "aux_data": null
        });
        let response: Value = if rpc.starts_with("http://") || rpc.starts_with("https://") {
            let client = jsonrpsee_http_client::HttpClientBuilder::default()
                .build(rpc)
                .context("Connect RP06 submission RPC")?;
            client
                .request("hegemon_submitAction", rpc_params![request])
                .await
                .context("Submit RP06 candidate; wallet retains uncertain status on error")?
        } else if rpc.starts_with("ws://") || rpc.starts_with("wss://") {
            let client = jsonrpsee_ws_client::WsClientBuilder::default()
                .build(rpc)
                .await
                .context("Connect RP06 submission RPC")?;
            client
                .request("hegemon_submitAction", rpc_params![request])
                .await
                .context("Submit RP06 candidate; wallet retains uncertain status on error")?
        } else {
            bail!("RPC must use http, https, ws, or wss");
        };
        if response.get("success").and_then(Value::as_bool) != Some(true) {
            bail!(
                "Hegemon rejected RP06 candidate: {}",
                response
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown RPC rejection")
            );
        }
        let encoded = response
            .get("tx_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Successful RP06 response has no action id"))?;
        let encoded = encoded
            .strip_prefix("0x")
            .ok_or_else(|| anyhow!("RP06 action id lacks 0x prefix"))?;
        let bytes = hex::decode(encoded).context("Decode Hegemon RP06 action id")?;
        wallet::ActionId48::try_from(bytes.as_slice())
            .map_err(|_| anyhow!("Hegemon RP06 action id must contain 48 bytes"))
    }

    fn submit(runtime: &tokio::runtime::Runtime, args: SubmitArgs) -> Result<()> {
        let (file, context) = ContextFile::load(&args.common.context, args.common.retained())?;
        let reservation_id = fixed_hex::<32>(&args.reservation_id, "reservation_id")?;
        let pass = secret(false)?;
        let store = WalletStore::open(&args.common.store, &pass)?;
        store.require_launch_context(context)?;

        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        if args.common.retained() {
            let manifest = args
                .runtime_manifest
                .as_deref()
                .ok_or_else(|| anyhow!("Retained RP06 submit requires --runtime-manifest"))?;
            runtime.block_on(require_development_runtime(
                &args.common.rpc,
                manifest,
                context,
                file.activation_height,
            ))?;
        }

        let (_, complete) =
            runtime.block_on(sync(&store, &args.common, &file, context, None, 1000))?;
        if !complete {
            bail!("Sync limit reached; repeat launch sync before submission");
        }

        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        let export = if args.common.retained() {
            store.export_rp06_transfer_candidate_for_retained_test(reservation_id)?
        } else {
            store.export_rp06_transfer_candidate(reservation_id)?
        };
        #[cfg(not(feature = "poseidon2-v8-retained-test-support"))]
        let export = store.export_rp06_transfer_candidate(reservation_id)?;

        let (_, height, hash) = runtime.block_on(rpc_target(&args.common, context, None))?;
        if !reference_eligible(&store, &file, export.tip(), height, hash)? {
            bail!("RP06 candidate's exact parent is not eligible at the trusted node tip; inputs remain held");
        }
        let action_id = runtime.block_on(submit_rp06_rpc(&args.common.rpc, &export.inline_args))?;
        store.mark_rp06_transfer_candidate_submitted(reservation_id, action_id)?;
        println!(
            "{}",
            json!({"reservation_id":args.reservation_id,
            "action_id":format!("0x{}", hex::encode(action_id.as_bytes())),
            "candidate_status":"submitted","inputs_held_until_canonical_observation":true})
        );
        Ok(())
    }

    const HTLC_OFFER_MAX_BYTES: usize = 16 * 1024;
    const HTLC_AGREEMENT_MAX_BYTES: usize = 16 * 1024;

    fn read_bounded_file(path: &Path, maximum: usize, private: bool) -> Result<Zeroizing<Vec<u8>>> {
        let before = fs::symlink_metadata(path).context("Inspect input file")?;
        if !before.file_type().is_file() || before.len() > maximum as u64 {
            bail!("Input must be a bounded regular file; symlinks are rejected");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if private && before.mode() & 0o777 != 0o600 {
                bail!("Private input file must have mode0600");
            }
        }
        #[cfg(not(unix))]
        if private {
            bail!("Private input permission validation requires a Unix host");
        }
        let input = fs::File::open(path).context("Open input file")?;
        let opened = input.metadata().context("Inspect opened input file")?;
        if !opened.file_type().is_file() || opened.len() > maximum as u64 {
            bail!("Opened input is not a bounded regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if opened.dev() != before.dev()
                || opened.ino() != before.ino()
                || (private && opened.mode() & 0o777 != 0o600)
            {
                bail!("Input identity or private permissions changed while opening");
            }
        }
        let mut bytes = Zeroizing::new(Vec::new());
        input
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .context("Read bounded input file")?;
        if bytes.len() > maximum {
            bail!("Input exceeds its byte limit");
        }
        Ok(bytes)
    }
    fn htlc_offer(
        store: &WalletStore,
        context: LaunchWalletContext,
        id: [u8; 32],
    ) -> Result<wallet::htlc::HtlcOffer> {
        let offer = store
            .htlc_swaps()?
            .into_iter()
            .find(|swap| swap.id == id)
            .ok_or_else(|| anyhow!("Accepted HTLC offer not found"))?
            .offer;
        check_htlc_offer(&offer, context)?;
        Ok(offer)
    }
    fn check_htlc_offer(
        offer: &wallet::htlc::HtlcOffer,
        context: LaunchWalletContext,
    ) -> Result<()> {
        offer.validate()?;
        if offer.network_id != context.chain_id() {
            bail!("HTLC offer differs from the full pinned chain");
        }
        if offer.secret_release
            != transaction_circuit::smallwood_htlc::SecretRelease::HiddenOnHegemon
        {
            bail!("Launch HTLC CLI requires HiddenOnHegemon; preimages never enter public JSON");
        }
        Ok(())
    }
    fn htlc_open(
        runtime: &tokio::runtime::Runtime,
        args: &StoreArgs,
        read_only: bool,
        check_rpc: bool,
    ) -> Result<(ContextFile, LaunchWalletContext, WalletStore)> {
        let (file, context) = ContextFile::load(&args.context, args.retained())?;
        if check_rpc {
            runtime.block_on(rpc_target(args, context, Some(0)))?;
        }
        let pass = secret(false)?;
        let store = if read_only {
            WalletStore::open_read_only(&args.store, &pass)?
        } else {
            WalletStore::open(&args.store, &pass)?
        };
        store.require_launch_context(context)?;
        Ok((file, context, store))
    }
    fn htlc_sync_complete(
        runtime: &tokio::runtime::Runtime,
        store: &WalletStore,
        args: &StoreArgs,
        file: &ContextFile,
        context: LaunchWalletContext,
        max_blocks: u64,
    ) -> Result<()> {
        if !runtime
            .block_on(sync(store, args, file, context, None, max_blocks))?
            .1
        {
            bail!("Sync limit reached; repeat launch sync before preparing or live recovery");
        }
        Ok(())
    }
    fn htlc_status(
        store: &WalletStore,
        context: LaunchWalletContext,
        id: Option<[u8; 32]>,
        online: bool,
    ) -> Result<Value> {
        let swaps = store.htlc_swaps()?.into_iter().filter(|swap| id.map_or(true, |id| swap.id == id))
            .map(|swap| {
                check_htlc_offer(&swap.offer, context)?;
                Ok(json!({"swap_id":format!("0x{}",hex::encode(swap.id)),"offer":swap.offer,
                    "has_secret":swap.has_secret,"locked_note_positions":swap.locked_note_positions,
                    "attempts":swap.attempts.into_iter().map(|attempt| json!({
                        "attempt_id":format!("0x{}",hex::encode(attempt.id)),"action":attempt.action,
                        "status":attempt.status,"input_consumed":attempt.input_consumed,
                        "input_reserved":attempt.input_reserved,"canonical_confirmation":attempt.confirmation
                    })).collect::<Vec<_>>() }))
            }).collect::<Result<Vec<_>>>()?;
        if id.is_some() && swaps.is_empty() {
            bail!("Accepted HTLC offer not found");
        }
        let notes = store
            .poseidon2_v8_owned_notes()?
            .into_iter()
            .filter(|note| !note.spent && note.opening.asset_id == 0)
            .map(|note| {
                json!({"position":note.position,"native_value_base_units":note.opening.value,
                "commitment":note.commitment})
            })
            .collect::<Vec<_>>();
        Ok(
            json!({"schema":"hegemon-launch-htlc-status-v1","chain_id":format!("0x{}",hex::encode(context.chain_id())),
            "mirror_height":store.poseidon2_v8_tip()?.height,"swaps":swaps,"ordinary_native_notes":notes,
            "readiness":if online {"canonical mirror synced; preparation rechecks eligibility"} else {"unknown; offline cache"},
            "notes_may_be_reserved":true,"submission":"no RPC submission"}),
        )
    }
    fn approve_htlc(review: &Value, digest: [u8; 32]) -> Result<[u8; 32]> {
        println!("{}", serde_json::to_string_pretty(review)?);
        let expected = format!("0x{}", hex::encode(digest));
        eprint!("Type the exact review digest {expected} to approve this operation: ");
        io::stderr().flush()?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .context("Read exact HTLC review approval")?;
        if answer.trim() != expected {
            bail!("Exact HTLC operation was not approved");
        }
        Ok(digest)
    }
    fn htlc_run(runtime: &tokio::runtime::Runtime, command: HtlcCommands) -> Result<()> {
        use transaction_circuit::smallwood_htlc::HtlcAction;
        match command {
            HtlcCommands::OfferCreate(args) => htlc_offer_create(args),
            HtlcCommands::OfferAccept(args) => {
                let (_, context, store) = htlc_open(runtime, &args.common, false, true)?;
                let bytes = read_bounded_file(&args.offer, HTLC_OFFER_MAX_BYTES, false)?;
                let offer: wallet::htlc::HtlcOffer =
                    serde_json::from_slice(&bytes).context("Parse public HTLC offer")?;
                check_htlc_offer(&offer, context)?;
                let id = store.accept_htlc_offer(offer)?;
                println!(
                    "{}",
                    json!({"swap_id":format!("0x{}",hex::encode(id)),"offer_accepted":true,"funds_spent":false})
                );
                Ok(())
            }
            HtlcCommands::OfferExport(args) => {
                output_preflight(&args.out)?;
                let (_, context, store) = htlc_open(runtime, &args.common, true, true)?;
                let id = fixed_hex(&args.swap_id, "swap_id")?;
                let offer = htlc_offer(&store, context, id)?;
                write_private_file(&args.out, &serde_json::to_vec_pretty(&offer)?)?;
                println!(
                    "{}",
                    json!({"swap_id":args.swap_id,"public_offer":args.out})
                );
                Ok(())
            }
            HtlcCommands::Status(args) => {
                let (file, context, store) =
                    htlc_open(runtime, &args.common, args.offline, !args.offline)?;
                if !args.offline {
                    htlc_sync_complete(
                        runtime,
                        &store,
                        &args.common,
                        &file,
                        context,
                        args.max_blocks,
                    )?;
                }
                let id = args
                    .swap_id
                    .as_ref()
                    .map(|id| fixed_hex(id, "swap_id"))
                    .transpose()?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&htlc_status(
                        &store,
                        context,
                        id,
                        !args.offline
                    )?)?
                );
                Ok(())
            }
            HtlcCommands::AgreementCreate(args) => {
                let (_, context, store) = htlc_open(runtime, &args.common, false, true)?;
                let id = fixed_hex(&args.swap_id, "swap_id")?;
                htlc_offer(&store, context, id)?;
                let to = ShieldedAddress::decode(&args.to)
                    .context("Decode exact locked-note recipient")?;
                let info = wallet::htlc_prepare::create_htlc_agreement(&store, &context, id, &to)?;
                println!(
                    "{}",
                    json!({"swap_id":args.swap_id,"agreement":info,"private_material":"retained encrypted inside wallet"})
                );
                Ok(())
            }
            HtlcCommands::AgreementImport(args) => {
                let (_, context, store) = htlc_open(runtime, &args.common, false, true)?;
                let id = fixed_hex(&args.swap_id, "swap_id")?;
                htlc_offer(&store, context, id)?;
                let bytes = read_bounded_file(&args.input, HTLC_AGREEMENT_MAX_BYTES, true)?;
                let info = wallet::htlc_prepare::import_htlc_agreement(
                    &store,
                    &context,
                    id,
                    &bytes,
                    args.diversifier_index,
                )
                .map_err(|_| anyhow!("Encrypted HTLC agreement import failed"))?;
                println!(
                    "{}",
                    json!({"swap_id":args.swap_id,"agreement":info,"private_material":"retained encrypted inside wallet"})
                );
                Ok(())
            }
            HtlcCommands::AgreementExport(args) => {
                output_preflight(&args.out)?;
                let (_, context, store) = htlc_open(runtime, &args.common, true, true)?;
                let id = fixed_hex(&args.swap_id, "swap_id")?;
                htlc_offer(&store, context, id)?;
                let to = ShieldedAddress::decode(&args.to)
                    .context("Decode exact encrypted-agreement recipient")?;
                let bytes = wallet::htlc_prepare::export_htlc_agreement(&store, &context, id, &to)
                    .map_err(|_| anyhow!("Encrypt HTLC agreement failed"))?;
                if bytes.len() > HTLC_AGREEMENT_MAX_BYTES {
                    bail!("Encrypted agreement exceeds its byte limit");
                }
                write_private_file(&args.out, &bytes)?;
                println!(
                    "{}",
                    json!({"swap_id":args.swap_id,"encrypted_agreement":args.out,"recipient":to.encode()?})
                );
                Ok(())
            }
            HtlcCommands::SecretImport(args) => {
                let (_, context, store) = htlc_open(runtime, &args.common, false, true)?;
                let id = fixed_hex(&args.swap_id, "swap_id")?;
                htlc_offer(&store, context, id)?;
                let bytes = read_bounded_file(&args.input, 32, true)?;
                let preimage = Zeroizing::new(
                    <[u8; 32]>::try_from(bytes.as_slice())
                        .map_err(|_| anyhow!("Secret input must contain exactly32 raw bytes"))?,
                );
                store
                    .save_htlc_secret(id, *preimage)
                    .map_err(|_| anyhow!("Secret does not match the accepted HTLC offer"))?;
                println!(
                    "{}",
                    json!({"swap_id":args.swap_id,"secret_imported":true,"secret_output":false})
                );
                Ok(())
            }
            HtlcCommands::PrepareLock(args) => htlc_prepare(runtime, args, HtlcAction::Lock),
            HtlcCommands::PrepareClaim(args) => htlc_prepare(runtime, args, HtlcAction::Claim),
            HtlcCommands::PrepareRefund(args) => htlc_prepare(runtime, args, HtlcAction::Refund),
            HtlcCommands::Recover(args) => htlc_recover(runtime, args),
            HtlcCommands::Submit(args) => htlc_submit(runtime, args),
        }
    }

    fn htlc_offer_create(args: HtlcOfferCreateArgs) -> Result<()> {
        output_preflight(&args.out)?;
        let (file, context) = ContextFile::load(&args.context, args.retained())?;
        let claim_pass = secret(false)?;
        let claim_store = WalletStore::open(&args.claim_store, &claim_pass)?;
        claim_store.require_launch_context(context)?;
        let claim_keys = claim_store
            .derived_keys()?
            .ok_or_else(|| anyhow!("Claim wallet is watch-only"))?;
        let claim_address = claim_keys
            .poseidon2_v8_address(args.claim_index)?
            .shielded_address();

        let refund_pass = secret(false)?;
        let refund_store = WalletStore::open(&args.refund_store, &refund_pass)?;
        refund_store.require_launch_context(context)?;
        let refund_keys = refund_store
            .derived_keys()?
            .ok_or_else(|| anyhow!("Refund wallet is watch-only"))?;
        let refund_address = refund_keys
            .poseidon2_v8_address(args.refund_index)?
            .shielded_address();

        let offer = wallet::htlc::HtlcOffer::create_for_addresses(
            context.chain_id(),
            fixed_hex(&args.hashlock, "hashlock")?,
            args.value,
            args.maximum_fee,
            args.timeout_height,
            &claim_address,
            &refund_address,
            wallet::htlc::BitcoinRegtestTerms {
                amount_sat: args.bitcoin_amount_sat,
                claim_public_key: fixed_hex::<33>(
                    &args.bitcoin_claim_public_key,
                    "bitcoin_claim_public_key",
                )?
                .to_vec(),
                refund_public_key: fixed_hex::<33>(
                    &args.bitcoin_refund_public_key,
                    "bitcoin_refund_public_key",
                )?
                .to_vec(),
                refund_height: args.bitcoin_refund_height,
                required_confirmations: args.bitcoin_required_confirmations,
            },
        )?;
        let id = offer.id()?;
        write_private_file(&args.out, &serde_json::to_vec_pretty(&offer)?)?;
        println!(
            "{}",
            json!({"swap_id":format!("0x{}",hex::encode(id)),
            "chain_id":file.chain_id,"hashlock":args.hashlock,
            "claim_address":claim_address.encode()? , "refund_address":refund_address.encode()?,
            "offer":args.out,"secret_release":"HiddenOnHegemon"})
        );
        Ok(())
    }

    async fn submit_htlc_rpc(rpc: &str, carrier: Vec<u8>) -> Result<wallet::ActionId48> {
        use base64::Engine;
        use protocol_versioning::launch_candidate;

        let request = json!({
            "binding_circuit": launch_candidate::HTLC_VERSION_BINDING.circuit,
            "binding_crypto": launch_candidate::HTLC_VERSION_BINDING.crypto,
            "family_id": launch_candidate::LAUNCH_SHIELDED_FAMILY_ID,
            "action_id": launch_candidate::HTLC_ACTION_ID,
            "object_refs": [], "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(carrier),
            "authorization_proof": null, "authorization_signatures": [], "aux_data": null
        });
        let response: Value = if rpc.starts_with("http://") || rpc.starts_with("https://") {
            let client = jsonrpsee_http_client::HttpClientBuilder::default()
                .build(rpc)
                .context("Connect HTLC submission RPC")?;
            client
                .request("hegemon_submitAction", rpc_params![request])
                .await
                .context("Submit HTLC candidate; wallet retains uncertain status on error")?
        } else if rpc.starts_with("ws://") || rpc.starts_with("wss://") {
            let client = jsonrpsee_ws_client::WsClientBuilder::default()
                .build(rpc)
                .await
                .context("Connect HTLC submission RPC")?;
            client
                .request("hegemon_submitAction", rpc_params![request])
                .await
                .context("Submit HTLC candidate; wallet retains uncertain status on error")?
        } else {
            bail!("RPC must use http, https, ws, or wss");
        };
        if response.get("success").and_then(Value::as_bool) != Some(true) {
            bail!(
                "Hegemon rejected HTLC candidate: {}",
                response
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown RPC rejection")
            );
        }
        let encoded = response
            .get("tx_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Successful HTLC response has no action id"))?;
        let encoded = encoded
            .strip_prefix("0x")
            .ok_or_else(|| anyhow!("HTLC action id lacks 0x prefix"))?;
        let bytes = hex::decode(encoded).context("Decode Hegemon HTLC action id")?;
        wallet::ActionId48::try_from(bytes.as_slice())
            .map_err(|_| anyhow!("Hegemon HTLC action id must contain 48 bytes"))
    }

    async fn require_development_runtime(
        rpc: &str,
        manifest_path: &Path,
        context: LaunchWalletContext,
        inclusion_height: u64,
    ) -> Result<()> {
        let bytes = read_bounded_file(manifest_path, 16 * 1024, false)?;
        let expected: Value =
            serde_json::from_slice(&bytes).context("Parse retained Development manifest")?;
        let config: Value = if rpc.starts_with("http://") || rpc.starts_with("https://") {
            let client = jsonrpsee_http_client::HttpClientBuilder::default()
                .build(rpc)
                .context("Connect Development metadata RPC")?;
            client
                .request("hegemon_nodeConfig", rpc_params![])
                .await
                .context("Read current node profile and manifest")?
        } else if rpc.starts_with("ws://") || rpc.starts_with("wss://") {
            let client = jsonrpsee_ws_client::WsClientBuilder::default()
                .build(rpc)
                .await
                .context("Connect Development metadata RPC")?;
            client
                .request("hegemon_nodeConfig", rpc_params![])
                .await
                .context("Read current node profile and manifest")?
        } else {
            bail!("RPC must use http, https, ws, or wss");
        };
        if config.get("networkProfile").and_then(Value::as_str) != Some("development")
            || config.get("networkManifest") != Some(&expected)
            || fixed_hex::<32>(
                config.get("chainId").and_then(Value::as_str).unwrap_or(""),
                "node chainId",
            )? != context.chain_id()
        {
            bail!("Retained HTLC submit requires the exact current Development manifest and pinned chain");
        }
        context
            .require_canonical_parent(context.genesis_hash(), inclusion_height.saturating_sub(1))
            .context("HTLC inclusion is outside the pinned finite context")?;
        Ok(())
    }

    fn htlc_submit(runtime: &tokio::runtime::Runtime, args: HtlcSubmitArgs) -> Result<()> {
        let (file, context, store) = htlc_open(runtime, &args.common, false, true)?;
        htlc_sync_complete(runtime, &store, &args.common, &file, context, 1000)?;
        let attempt_id = fixed_hex(&args.attempt_id, "attempt_id")?;
        let (_, height, _) = runtime.block_on(rpc_target(&args.common, context, None))?;
        let inclusion = context.require_canonical_parent(context.genesis_hash(), height)?;
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        let action_id = if args.common.retained() {
            let manifest = args
                .runtime_manifest
                .as_deref()
                .ok_or_else(|| anyhow!("Retained HTLC submit requires --runtime-manifest"))?;
            runtime.block_on(require_development_runtime(
                &args.common.rpc,
                manifest,
                context,
                inclusion,
            ))?;
            let rpc = args.common.rpc.clone();
            runtime.block_on(store.submit_prepared_htlc_for_retained_test_with(
                attempt_id,
                move |bytes| async move {
                    submit_htlc_rpc(&rpc, bytes)
                        .await
                        .map_err(|error| wallet::WalletError::Rpc(error.to_string()))
                },
            ))?
        } else {
            let rpc = args.common.rpc.clone();
            runtime.block_on(store.submit_prepared_htlc_with(
                attempt_id,
                move |bytes| async move {
                    submit_htlc_rpc(&rpc, bytes)
                        .await
                        .map_err(|error| wallet::WalletError::Rpc(error.to_string()))
                },
            ))?
        };
        #[cfg(not(feature = "poseidon2-v8-retained-test-support"))]
        let action_id = {
            let rpc = args.common.rpc.clone();
            runtime.block_on(store.submit_prepared_htlc_with(
                attempt_id,
                move |bytes| async move {
                    submit_htlc_rpc(&rpc, bytes)
                        .await
                        .map_err(|error| wallet::WalletError::Rpc(error.to_string()))
                },
            ))?
        };
        println!(
            "{}",
            json!({"attempt_id":args.attempt_id,"action_id":format!("0x{}",hex::encode(action_id.as_bytes())),
            "candidate_status":"submitted","inputs_held_until_canonical_observation":true})
        );
        Ok(())
    }
    fn htlc_prepare(
        runtime: &tokio::runtime::Runtime,
        args: HtlcPrepareArgs,
        action: transaction_circuit::smallwood_htlc::HtlcAction,
    ) -> Result<()> {
        output_preflight(&args.out)?;
        let (file, context, store) = htlc_open(runtime, &args.common, false, true)?;
        htlc_sync_complete(
            runtime,
            &store,
            &args.common,
            &file,
            context,
            args.max_blocks,
        )?;
        let id = fixed_hex(&args.swap_id, "swap_id")?;
        let offer = htlc_offer(&store, context, id)?;
        let to =
            ShieldedAddress::decode(&args.to).context("Decode exact HTLC output destination")?;
        if action == transaction_circuit::smallwood_htlc::HtlcAction::Lock {
            let exact = offer
                .value
                .checked_add(args.fee)
                .ok_or_else(|| anyhow!("HTLC Lock input amount overflow"))?;
            if !store.poseidon2_v8_owned_notes()?.iter().any(|note| {
                !note.spent
                    && note.position == args.input_position
                    && note.opening.asset_id == 0
                    && note.opening.value == exact
            }) {
                bail!("HTLC Lock needs one unspent native note of exactly {exact} base units at the selected position. Prepare a separately reviewed RP06 self-transfer to split an input, sync its inclusion, then approve Lock; no additional spend was prepared");
            }
        }
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        let plan = if args.common.retained() {
            wallet::htlc_prepare::HtlcPreparation::new_for_retained_test(
                &store,
                context,
                id,
                action,
                args.input_position,
                args.fee,
                &to,
            )?
        } else {
            wallet::htlc_prepare::HtlcPreparation::new(
                &store,
                context,
                id,
                action,
                args.input_position,
                args.fee,
                &to,
            )?
        };
        #[cfg(not(feature = "poseidon2-v8-retained-test-support"))]
        let plan = wallet::htlc_prepare::HtlcPreparation::new(
            &store,
            context,
            id,
            action,
            args.input_position,
            args.fee,
            &to,
        )?;
        let digest = plan.review_digest();
        let operation = serde_json::to_value(plan.public_review())?;
        let review = json!({"context":file,"operation":operation,"review_digest":format!("0x{}",hex::encode(digest)),
            "candidate_testing":args.common.retained(),"submission":"artifact preparation only; no RPC submission"});
        let approved = approve_htlc(&review, digest)?;
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        let prepared = if args.common.retained() {
            plan.prove_for_retained_test(approved)?
        } else {
            plan.prove(approved)?
        };
        #[cfg(not(feature = "poseidon2-v8-retained-test-support"))]
        let prepared = plan.prove(approved)?;
        let attempt_id = prepared.attempt_id();
        htlc_sync_complete(
            runtime,
            &store,
            &args.common,
            &file,
            context,
            args.max_blocks,
        ).with_context(|| format!("Candidate 0x{} remains retained; inspect htlc status or recover it without rebuilding", hex::encode(attempt_id)))?;
        let (_, height, hash) = runtime.block_on(rpc_target(&args.common, context, None))?;
        if !htlc_reference_eligible(&store, &file, prepared.captured_tip(), height, hash, action)? {
            bail!("Exact HTLC reference detached, expired or beyond its route window; candidate 0x{} remains held and no carrier was exported",hex::encode(attempt_id));
        }
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        let export = if args.common.retained() {
            prepared.export_for_retained_test()?
        } else {
            prepared.export()?
        };
        #[cfg(not(feature = "poseidon2-v8-retained-test-support"))]
        let export = prepared.export()?;
        htlc_publish(
            &args.out,
            &file,
            context,
            &export,
            args.common.retained(),
            Some(true),
            Some(operation),
        )
    }
    fn htlc_reference_eligible(
        store: &WalletStore,
        file: &ContextFile,
        tip: Poseidon2V8CanonicalTip,
        height: u64,
        hash: [u8; 32],
        action: transaction_circuit::smallwood_htlc::HtlcAction,
    ) -> Result<bool> {
        Ok(reference_eligible(store, file, tip, height, hash)?
            && protocol_versioning::launch_reference_policy::launch_reference_distance_allowed(
                tip.height,
                height,
                action == transaction_circuit::smallwood_htlc::HtlcAction::Lock,
            ))
    }
    fn htlc_recover(runtime: &tokio::runtime::Runtime, args: HtlcRecoverArgs) -> Result<()> {
        output_preflight(&args.out)?;
        let (file, context, store) = htlc_open(runtime, &args.common, false, !args.offline)?;
        if !args.offline {
            htlc_sync_complete(
                runtime,
                &store,
                &args.common,
                &file,
                context,
                args.max_blocks,
            )?;
        }
        let id = fixed_hex(&args.attempt_id, "attempt_id")?;
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        let export = if args.offline {
            store.recover_htlc_attempt(id)?
        } else if args.common.retained() {
            store.export_htlc_attempt_for_retained_test(id)?
        } else {
            store.export_htlc_attempt(id)?
        };
        #[cfg(not(feature = "poseidon2-v8-retained-test-support"))]
        let export = if args.offline {
            store.recover_htlc_attempt(id)?
        } else {
            store.export_htlc_attempt(id)?
        };
        let review = export.review();
        htlc_offer(&store, context, review.swap_id)?;
        let live = if args.offline {
            None
        } else {
            let (_, height, hash) = runtime.block_on(rpc_target(&args.common, context, None))?;
            Some(match review.reference_tip {
                Some(tip) => {
                    htlc_reference_eligible(&store, &file, tip, height, hash, review.action)?
                }
                None => false,
            })
        };
        htlc_publish(
            &args.out,
            &file,
            context,
            &export,
            args.common.retained(),
            live,
            None,
        )
    }
    fn htlc_publish(
        path: &Path,
        file: &ContextFile,
        context: LaunchWalletContext,
        export: &wallet::htlc::HtlcAttemptExport,
        retained: bool,
        live: Option<bool>,
        operation: Option<Value>,
    ) -> Result<()> {
        use wallet::htlc::HtlcAttemptReadiness;
        let review = export.review();
        if review.chain_id != context.chain_id()
            || review.genesis_hash != context.genesis_hash()
            || review.manifest_digest != Some(context.manifest_digest())
            || review.statement.revealed_secret_present
        {
            bail!("HTLC receipt differs from pinned identity or exposes a preimage");
        }
        let readiness = match review.readiness {
            HtlcAttemptReadiness::Ready {
                actual_inclusion_height,
            } => json!({"state":"ready","actual_inclusion_height":actual_inclusion_height}),
            HtlcAttemptReadiness::Unknown => json!({"state":"unknown"}),
        };
        // This checkpoint type intentionally has no general-purpose Serialize
        // implementation. Emit only its public chain-position fields here.
        let reference_tip = review.reference_tip.map(|tip| {
            json!({
                "height": tip.height,
                "block_hash": format!("0x{}", hex::encode(tip.block_hash)),
                "anchor": tip.anchor,
                "stablecoin_root": tip.stablecoin_root
            })
        });
        let operation_available = operation.is_some();
        let value = json!({"schema":"hegemon-launch-htlc-export-v1","context":file,
            "proof_mode":if retained {"retained_candidate"} else {"source_authorized"},
            "attempt_id":format!("0x{}",hex::encode(review.attempt_id)),"swap_id":format!("0x{}",hex::encode(review.swap_id)),
            "candidate_status":review.status,"action":review.action,"amount_base_units":review.amount,"fee_base_units":review.fee,
            "parent_height":review.statement.parent_height,"parent_hash":format!("0x{}",hex::encode(review.statement.parent_hash)),
            "note_anchor":review.statement.merkle_root,"reference_tip":reference_tip,
            "reference_window_blocks":if review.action == transaction_circuit::smallwood_htlc::HtlcAction::Lock {0} else {protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW},
            "readiness":readiness,"live_canonical_reference_eligible":live,
            "carrier_sha512":format!("0x{}",hex::encode(review.carrier_sha512)),"carrier_bytes":review.carrier_bytes,
            "inline_args_base64":base64::engine::general_purpose::STANDARD.encode(export.exact_carrier()),
            "family_id":protocol_versioning::launch_candidate::LAUNCH_SHIELDED_FAMILY_ID,
            "action_id":protocol_versioning::launch_candidate::HTLC_ACTION_ID,
            "input_position":review.input_position,"input_commitment":review.input_commitment,"input_nullifier":review.input_nullifier,
            "output_commitment":review.output_commitment,"canonical_confirmation":review.confirmation,
            "operation_review":operation,"original_operation_review_available":operation_available,
            "recovery":"identical carrier bytes/hash; current readiness and status are separate; original review is unavailable after restart",
            "submission":"not submitted by this command; exported input remains durably held"});
        write_private_file(path,&serde_json::to_vec_pretty(&value)?).map_err(|error|anyhow!(
            "HTLC artifact write failed ({error}); input remains held. Recover attempt 0x{} to a new path",hex::encode(review.attempt_id)))?;
        println!(
            "{}",
            json!({"attempt_id":format!("0x{}",hex::encode(review.attempt_id)),"artifact":path,"inputs_held":true})
        );
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn canonical_reference_window_keeps_exact_full_checkpoint() {
            let mut file = ContextFile {
                chain_id: format!("0x{}", hex::encode([1; 32])),
                genesis_hash: format!("0x{}", hex::encode([2; 32])),
                manifest_digest: format!("0x{}", hex::encode([3; 64])),
                activation_height: 1,
                deactivation_height_exclusive: 100,
                stablecoin_genesis_root: None,
            };
            let captured = Poseidon2V8CanonicalTip {
                height: 10,
                block_hash: [4; 32],
                anchor: [5; 7],
                stablecoin_root: Some([6; 7]),
            };
            let current = Poseidon2V8CanonicalTip {
                height: 22,
                block_hash: [7; 32],
                anchor: [8; 7],
                stablecoin_root: captured.stablecoin_root,
            };
            let eligible = |attached, mirror, live_height, live_hash| {
                reference_checkpoint_eligible(
                    &file,
                    captured,
                    attached,
                    mirror,
                    live_height,
                    live_hash,
                )
            };
            assert!(eligible(Some(captured), current, 22, current.block_hash));
            assert!(eligible(Some(captured), captured, 10, captured.block_hash));
            let older = Poseidon2V8CanonicalTip {
                height: 23,
                ..current
            };
            assert!(!eligible(Some(captured), older, 23, older.block_hash));
            assert!(!eligible(None, current, 22, current.block_hash));
            assert!(!eligible(
                Some(Poseidon2V8CanonicalTip {
                    anchor: [9; 7],
                    ..captured
                }),
                current,
                22,
                current.block_hash
            ));
            assert!(!eligible(
                Some(Poseidon2V8CanonicalTip {
                    stablecoin_root: Some([9; 7]),
                    ..captured
                }),
                current,
                22,
                current.block_hash
            ));
            assert!(!eligible(
                Some(Poseidon2V8CanonicalTip {
                    block_hash: [9; 32],
                    ..captured
                }),
                current,
                22,
                current.block_hash
            ));
            assert!(!eligible(Some(captured), current, 21, current.block_hash));
            assert!(!eligible(Some(captured), current, 22, [9; 32]));
            assert!(!eligible(Some(captured), captured, 9, captured.block_hash));
            file.deactivation_height_exclusive = 23;
            assert!(!reference_checkpoint_eligible(
                &file,
                captured,
                Some(captured),
                current,
                22,
                current.block_hash
            ));
        }

        #[test]
        fn htlc_prepare_parser_requires_explicit_position_fee_and_destination() {
            let base = [
                "launch-wallet-prepare",
                "htlc",
                "prepare-lock",
                "--store",
                "wallet.enc",
                "--context",
                "context.json",
                "--swap-id",
                "0x01",
                "--out",
                "lock.json",
            ];
            assert!(ExampleCli::try_parse_from(base).is_err());
            let mut explicit = base.to_vec();
            explicit.extend(["--input-position", "7", "--fee", "0", "--to", "recipient"]);
            assert!(matches!(
                ExampleCli::try_parse_from(explicit).unwrap().command,
                LaunchCommands::Htlc {
                    command: HtlcCommands::PrepareLock(_)
                }
            ));
            assert!(ExampleCli::try_parse_from([
                "launch-wallet-prepare",
                "htlc",
                "recover",
                "--store",
                "wallet.enc",
                "--context",
                "context.json",
                "--attempt-id",
                "0x01",
                "--out",
                "recover.json",
                "--offline"
            ])
            .is_ok());
        }
        #[cfg(unix)]
        #[test]
        fn private_inputs_reject_symlinks_permissions_and_oversized_files() {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let directory = tempfile::tempdir().unwrap();
            let valid = directory.path().join("secret.bin");
            write_private_file(&valid, &[7; 32]).unwrap();
            assert_eq!(read_bounded_file(&valid, 32, true).unwrap().len(), 32);
            let link = directory.path().join("linked.bin");
            symlink(&valid, &link).unwrap();
            assert!(read_bounded_file(&link, 32, true).is_err());
            fs::set_permissions(&valid, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_bounded_file(&valid, 32, true).is_err());
            fs::set_permissions(&valid, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&valid, [7; 33]).unwrap();
            assert!(read_bounded_file(&valid, 32, true).is_err());
        }

        #[test]
        fn full_context_and_header_chain_are_exact() {
            let context = LaunchWalletContext::new([1; 32], [2; 32], [3; 64], 1, 10).unwrap();
            assert!(check_header(
                &json!({"chainId": format!("0x{}", hex::encode([1;32])), "number":"0x2"}),
                context,
                2
            )
            .is_ok());
            assert!(check_header(
                &json!({"chainId": format!("0x{}", hex::encode([4;32])), "number":"0x2"}),
                context,
                2
            )
            .is_err());
            assert!(check_header(
                &json!({"chainId": format!("0x{}", hex::encode([1;32])), "number":"0x3"}),
                context,
                2
            )
            .is_err());
            assert!(fixed_hex::<32>(&format!("0x{}", "A".repeat(64)), "chain").is_err());
            assert!(fixed_hex::<32>(&format!("0x{}", "1".repeat(62)), "chain").is_err());
        }
    }
}
