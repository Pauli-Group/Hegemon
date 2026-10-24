//! RP06 treasury coordination, retained candidate lifecycle, and source-gated submission.
use base64::Engine;
use clap::{Parser, Subcommand};
use jsonrpsee_core::{client::ClientT, rpc_params};
use protocol_shielded_pool::{
    poseidon2_v8_coinbase::Poseidon2V8CoinbaseNoteOpening,
    rp06_transport::{
        decode_rp06_inline_args_exact, encode_rp06_candidate_envelope,
        encode_rp06_candidate_inline_args, encode_rp06_candidate_native_leaf, Rp06ExpectedContext,
        RP06_PREAMBLE_BYTES,
    },
};
use rand::rngs::OsRng;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use transaction_circuit::{
    smallwood_poseidon2_v8_rp06::{
        prove_rp06_candidate, rp06_program_digest, rp06_program_identity_sha512,
        rp06_transcript_bytes, Rp06PublicStatement,
    },
    smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8InputWitness,
};
use wallet::{
    poseidon2_v8_multisig::{
        build_v8_treasury_approval, build_v8_treasury_final, note_from_words,
        v8_treasury_signer_tag, V8TreasuryDescriptor, V8TreasuryNote, V8TreasuryNoteView,
        V8TreasuryPlan, V8TreasurySpendMaterial,
    },
    ShieldedAddress, WalletStore,
};
#[derive(Parser)]
#[command(
    name = "treasury-v8",
    about = "Private RP06 treasury review, candidate recovery, and guarded submission"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(clap::Args)]
struct StoreArgs {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
}
#[derive(clap::Args)]
struct TreasuryArgs {
    #[command(flatten)]
    store: StoreArgs,
    #[arg(long)]
    account_id: String,
}
/// Named fields from the consensus-public coinbase opening, never a private accumulator.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicCoinbaseOpening {
    value: u64,
    asset_id: u64,
    recipient_key: [u64; 4],
    authorization_key: [u64; 4],
    rho: [u64; 4],
    randomness: [u64; 4],
}
impl From<PublicCoinbaseOpening> for Poseidon2V8CoinbaseNoteOpening {
    fn from(value: PublicCoinbaseOpening) -> Self {
        Self {
            value: value.value,
            asset_id: value.asset_id,
            recipient_key: value.recipient_key,
            authorization_key: value.authorization_key,
            rho: value.rho,
            randomness: value.randomness,
        }
    }
}
#[derive(Subcommand)]
enum Command {
    /// Generate an independent OS-random signer root in a new encrypted wallet.
    NewSigner {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Open an existing encrypted store with its writer lock and apply exact normal migrations.
    UpgradeStore {
        #[command(flatten)]
        store: StoreArgs,
    },
    /// Print only the public full seven-limb source signer tag.
    PublicTag {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Locate every exact position of a public full 56-byte V8 commitment in the current canonical wallet mirror.
    CanonicalPosition {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        commitment: String,
    },
    /// Create a permanent policy recipient from three public signer tags.
    CreatePolicy {
        #[arg(long)]
        keeper_wallet: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        chain_id: String,
        #[arg(long, num_args = 3)]
        signer_tags: Vec<String>,
        #[arg(long)]
        private_descriptor: PathBuf,
    },
    /// Import the private descriptor into this signer's encrypted wallet.
    ImportPolicy {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        private_descriptor: PathBuf,
    },
    /// Display only account identifiers and permanent receive addresses.
    ShowPolicy {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Bind a provisional policy to the public launch chain before any receipt or operation.
    BindNetwork {
        #[command(flatten)]
        treasury: TreasuryArgs,
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        private_descriptor: PathBuf,
    },
    /// Import a public coinbase opening JSON object at its exact canonical position.
    ImportCoinbase {
        #[command(flatten)]
        treasury: TreasuryArgs,
        #[arg(long)]
        public_opening: PathBuf,
        #[arg(long)]
        position: u64,
    },
    /// Create, durably store and privately export one exact payment plan.
    CreatePlan {
        #[command(flatten)]
        treasury: TreasuryArgs,
        #[arg(long)]
        source_commitment: String,
        #[arg(long)]
        source_position: u64,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        fee: u64,
        #[arg(long)]
        private_plan: PathBuf,
    },
    /// Import an exact private plan into this encrypted signer wallet.
    ImportPlan {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        private_plan: PathBuf,
    },
    /// Privately export an already stored plan selected by its full review digest.
    ExportPlan {
        #[command(flatten)]
        treasury: TreasuryArgs,
        #[arg(long)]
        review_digest: String,
        #[arg(long)]
        private_plan: PathBuf,
    },
    /// Import private value or accumulator coordination material at its canonical position.
    ImportNote {
        #[command(flatten)]
        treasury: TreasuryArgs,
        #[arg(long)]
        private_note: PathBuf,
        #[arg(long)]
        position: u64,
    },
    /// Export private coordination material for one exact unspent canonical note.
    ExportNote {
        #[command(flatten)]
        treasury: TreasuryArgs,
        #[arg(long)]
        commitment: String,
        #[arg(long)]
        position: u64,
        #[arg(long)]
        private_note: PathBuf,
    },
    /// Explicitly approve the reviewed digest using one exact signer capability.
    /// Writes only a local self-contained RP06 candidate carrier; never submits it.
    Approve {
        #[command(flatten)]
        treasury: TreasuryArgs,
        #[arg(long)]
        reviewed_digest: String,
        #[arg(long)]
        capability_commitment: String,
        #[arg(long)]
        capability_position: u64,
        #[arg(long, requires = "accumulator_position")]
        accumulator_commitment: Option<String>,
        #[arg(long, requires = "accumulator_commitment")]
        accumulator_position: Option<u64>,
        #[arg(long)]
        approval_fee: u64,
        #[arg(long)]
        candidate_output: PathBuf,
    },
    /// Build the exact reviewed payment using a canonically completed accumulator.
    /// Writes only a local self-contained RP06 candidate carrier; never submits it.
    Finalize {
        #[command(flatten)]
        treasury: TreasuryArgs,
        #[arg(long)]
        reviewed_digest: String,
        #[arg(long)]
        accumulator_commitment: String,
        #[arg(long)]
        accumulator_position: u64,
        #[arg(long)]
        candidate_output: PathBuf,
    },
    /// Inspect retained operation identifiers and recovery status, without private openings.
    Attempts {
        #[command(flatten)]
        treasury: TreasuryArgs,
    },
    /// Submit the unchanged retained RP06 carrier after source authority and canonical checks.
    Submit {
        #[command(flatten)]
        treasury: TreasuryArgs,
        #[arg(long)]
        attempt: usize,
        #[arg(long)]
        reviewed_digest: String,
        #[arg(long, default_value = "http://127.0.0.1:9944")]
        rpc: String,
        /// Explicit opt-in for an isolated Development node; unavailable in normal builds.
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        #[arg(long, default_value_t = false)]
        retained_test: bool,
        #[cfg(feature = "poseidon2-v8-retained-test-support")]
        #[arg(long)]
        runtime_manifest: Option<PathBuf>,
    },
    /// List safe treasury note metadata; never prints openings, nullifiers, or policy keys.
    Notes {
        #[command(flatten)]
        treasury: TreasuryArgs,
    },
    /// Explicitly abandon an expired canonical candidate, preserving all reorg tombstones.
    AbandonCandidate {
        #[command(flatten)]
        treasury: TreasuryArgs,
        #[arg(long)]
        attempt: usize,
    },
    /// Resume an interrupted proof or re-export its exact durably retained carrier.
    RecoverCandidate {
        #[command(flatten)]
        treasury: TreasuryArgs,
        #[arg(long)]
        attempt: usize,
        #[arg(long)]
        reviewed_digest: String,
        #[arg(long)]
        candidate_output: PathBuf,
    },
    /// Validate and print the exact recipient, amount, fee, source and network for review.
    ReviewPlan {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        private_plan: PathBuf,
    },
}
fn phrase(path: Option<PathBuf>) -> anyhow::Result<String> {
    match path {
        Some(path) => {
            let value = fs::read_to_string(path)?;
            Ok(value.trim_end_matches(['\r', '\n']).to_owned())
        }
        None => Ok(rpassword::prompt_password(
            "Encrypted signer wallet passphrase: ",
        )?),
    }
}

fn parse_v8_commitment_hex(value: &str) -> anyhow::Result<[u64; 7]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    anyhow::ensure!(
        value.len() == 112,
        "commitment must be exactly 56 bytes (112 hex characters)"
    );
    let bytes = hex::decode(value)?;
    let mut limbs = [0u64; 7];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(chunk.try_into()?);
    }
    Ok(limbs)
}
fn parse32(value: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32-byte hex identifier"))
}
fn tag(value: &str) -> anyhow::Result<[u64; 7]> {
    let bytes = hex::decode(value)?;
    anyhow::ensure!(
        bytes.len() == 56,
        "expected 56-byte full signer tag or commitment"
    );
    Ok(core::array::from_fn(|i| {
        u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().expect("eight"))
    }))
}
fn tag_hex(tag: [u64; 7]) -> String {
    hex::encode(
        tag.into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>(),
    )
}
fn private_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn parse_review_digest(value: &str) -> anyhow::Result<[u8; 64]> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected the full 64-byte SHA512 review digest"))
}
fn descriptor(store: &WalletStore, account_id: [u8; 32]) -> anyhow::Result<V8TreasuryDescriptor> {
    store
        .v8_treasury_descriptors()?
        .into_iter()
        .find(|descriptor| descriptor.account_id == account_id)
        .ok_or_else(|| anyhow::anyhow!("unknown treasury account"))
}
fn stored_plan(
    store: &WalletStore,
    account_id: [u8; 32],
    digest: [u8; 64],
) -> anyhow::Result<V8TreasuryPlan> {
    let mut selected = None;
    for plan in store.v8_treasury_plans(account_id)? {
        if plan.review_digest()? == digest {
            anyhow::ensure!(selected.is_none(), "ambiguous stored review digest");
            selected = Some(plan);
        }
    }
    selected.ok_or_else(|| anyhow::anyhow!("review digest does not select a stored plan"))
}
fn spendable_note(
    store: &WalletStore,
    account_id: [u8; 32],
    commitment: [u64; 7],
    position: u64,
    anchor: [u64; 7],
) -> anyhow::Result<V8TreasuryNoteView> {
    let view = store.v8_treasury_note_view(account_id, commitment, position)?;
    anyhow::ensure!(
        !view.spent && !view.reserved,
        "treasury note is spent or reserved"
    );
    anyhow::ensure!(view.path.anchor == anchor, "treasury note anchor is stale");
    Ok(view)
}
fn current_tip(store: &WalletStore) -> anyhow::Result<wallet::Poseidon2V8CanonicalTip> {
    let tip = store.poseidon2_v8_tip()?;
    anyhow::ensure!(
        tip.stablecoin_root.is_some(),
        "wallet mirror has no current stablecoin root"
    );
    Ok(tip)
}
fn require_launch_chain(
    store: &WalletStore,
    descriptor: &V8TreasuryDescriptor,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        store.launch_chain_id()? == descriptor.chain_id,
        "treasury descriptor does not match the wallet's trusted launch context"
    );
    Ok(())
}
fn require_canonical_candidate(
    store: &WalletStore,
    chain_id: [u8; 32],
    bytes: &[u8],
) -> anyhow::Result<()> {
    use hegemon_field::Goldilocks;
    let context = Rp06ExpectedContext::new(chain_id, rp06_program_digest())
        .map_err(|_| anyhow::anyhow!("candidate context rejected"))?;
    let leaf = decode_rp06_inline_args_exact(context, bytes)
        .map_err(|_| anyhow::anyhow!("retained candidate framing rejected"))?
        .native_leaf();
    let statement = Rp06PublicStatement::try_from_public_words(&leaf.public_words())
        .map_err(|_| anyhow::anyhow!("retained candidate statement rejected"))?;
    let tip = current_tip(store)?;
    let launch = store.launch_context()?;
    let genesis = store
        .poseidon2_v8_canonical_hash(0)?
        .ok_or_else(|| anyhow::anyhow!("wallet has no canonical launch genesis"))?;
    launch.require_canonical_parent(genesis, tip.height)?;
    let reference_height = statement.base.stablecoin.parent_height;
    launch.require_canonical_parent(genesis, reference_height)?;
    let reference = store
        .poseidon2_v8_canonical_tip_at_height(reference_height)?
        .ok_or_else(|| anyhow::anyhow!("candidate reference checkpoint has detached"))?;
    let stable = reference
        .stablecoin_root
        .ok_or_else(|| anyhow::anyhow!("candidate checkpoint lacks its stablecoin root"))?
        .map(Goldilocks::from_u64);
    anyhow::ensure!(launch.chain_id() == chain_id
        && protocol_versioning::launch_reference_policy::launch_reference_distance_allowed(reference_height, tip.height, false)
        && statement.base.merkle_root == reference.anchor
        && reference.stablecoin_root == tip.stablecoin_root
        && statement.base.stablecoin.before_root == stable
        && statement.base.stablecoin.after_root == stable,
        "candidate reference is detached or expired; exact bytes and input reservations remain retained for explicit recovery");
    Ok(())
}
fn require_new_output(path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        !path.try_exists()?,
        "output already exists; select a new private file"
    );
    Ok(())
}
fn export_candidate(
    store: &WalletStore,
    plan: &V8TreasuryPlan,
    material: &V8TreasurySpendMaterial,
    path: &Path,
) -> anyhow::Result<()> {
    // This durable reservation also preserves the exact future policy opening.
    // Every failure after this point retains the reservation for operator recovery.
    let attempt = store.reserve_v8_treasury_attempt(plan.account_id, plan, material)?;
    export_reserved_candidate(store, plan, material, attempt, path)
}
fn export_reserved_candidate(
    store: &WalletStore,
    plan: &V8TreasuryPlan,
    material: &V8TreasurySpendMaterial,
    attempt: usize,
    path: &Path,
) -> anyhow::Result<()> {
    let bytes = (|| -> anyhow::Result<Vec<u8>> {
        let candidate = prove_rp06_candidate(material.statement, &material.witness)
            .map_err(|_| anyhow::anyhow!("candidate proof generation failed"))?;
        let preamble: [u8; RP06_PREAMBLE_BYTES] = rp06_transcript_bytes(&material.statement)
            .map_err(|_| anyhow::anyhow!("candidate transcript rejected"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("candidate transcript width rejected"))?;
        let context =
            Rp06ExpectedContext::new(material.statement.chain_id, candidate.relation_digest)
                .map_err(|_| anyhow::anyhow!("candidate context rejected"))?;
        let ciphertexts =
            core::array::from_fn(|i| material.inline_ciphertexts.ciphertexts[i].as_ref());
        let leaf = encode_rp06_candidate_native_leaf(
            context,
            &preamble,
            ciphertexts,
            &candidate.proof_bytes,
        )
        .map_err(|_| anyhow::anyhow!("candidate carrier rejected"))?;
        let envelope = encode_rp06_candidate_envelope(context, &leaf)
            .map_err(|_| anyhow::anyhow!("candidate envelope rejected"))?;
        encode_rp06_candidate_inline_args(context, &envelope)
            .map_err(|_| anyhow::anyhow!("candidate inline carrier rejected"))
    })()
    .map_err(|_| {
        anyhow::anyhow!("RP06 candidate generation failed; attempt {attempt} retains its exact material and inputs")
    })?;
    store.record_v8_treasury_candidate_inline(plan.account_id, attempt, bytes.clone())?;
    require_canonical_candidate(store, material.statement.chain_id, &bytes)?;
    anyhow::ensure!(
        store.v8_treasury_attempt_ready(plan.account_id, attempt)?,
        "candidate inputs or reference are no longer ready; bytes and reservations retained"
    );
    private_write(path, &bytes).map_err(|_| {
        anyhow::anyhow!("RP06 candidate export failed; attempt {attempt} retains its complete carrier and inputs")
    })?;
    println!(
        "{}",
        serde_json::json!({
            "account_id": hex::encode(plan.account_id), "attempt": attempt,
            "production_authorized": false,
            "candidate_bytes": bytes.len(), "review_digest": hex::encode(plan.review_digest()?),
            "output_commitment": tag_hex(material.statement.base.commitments[0])
        })
    );
    Ok(())
}

fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Command::NewSigner {
            wallet,
            passphrase_file,
        } => {
            let store = WalletStore::create_full_if_missing(wallet, &phrase(passphrase_file)?)?;
            let keys = store
                .derived_keys()?
                .ok_or_else(|| anyhow::anyhow!("missing local signer"))?;
            println!(
                "{}",
                serde_json::json!({"signer_tag":tag_hex(v8_treasury_signer_tag(&keys)?),"signer_receive_address":keys.poseidon2_v8_address(0)?.shielded_address().encode()?})
            );
        }
        Command::UpgradeStore { store: args } => {
            let store = WalletStore::open(args.wallet, &phrase(args.passphrase_file)?)?;
            let keys = store
                .derived_keys()?
                .ok_or_else(|| anyhow::anyhow!("watch-only store has no signer"))?;
            println!(
                "{}",
                serde_json::json!({"store_opened_for_migration":true,
                "signer_tag":tag_hex(v8_treasury_signer_tag(&keys)?),
                "signer_receive_address":keys.poseidon2_v8_address(0)?.shielded_address().encode()?})
            );
        }
        Command::PublicTag {
            wallet,
            passphrase_file,
        } => {
            let store = WalletStore::open_read_only(wallet, &phrase(passphrase_file)?)?;
            let keys = store
                .derived_keys()?
                .ok_or_else(|| anyhow::anyhow!("watch-only wallet has no signer"))?;
            println!("{}", tag_hex(v8_treasury_signer_tag(&keys)?));
        }
        Command::CanonicalPosition {
            store: args,
            commitment,
        } => {
            let store = WalletStore::open_read_only(args.wallet, &phrase(args.passphrase_file)?)?;
            let commitment_words = parse_v8_commitment_hex(&commitment)?;
            let tip = store.poseidon2_v8_tip()?;
            let positions = store.poseidon2_v8_canonical_commitment_positions(commitment_words)?;
            println!(
                "{}",
                serde_json::json!({
                    "commitment": commitment,
                    "positions": positions,
                    "canonical_tip": {
                        "height": tip.height,
                        "block_hash": hex::encode(tip.block_hash),
                    },
                    "scope": "Current authenticated wallet mirror only; this query does not independently verify node canonicality."
                })
            );
        }
        Command::CreatePolicy {
            keeper_wallet,
            passphrase_file,
            chain_id,
            signer_tags,
            private_descriptor,
        } => {
            let store = WalletStore::open(keeper_wallet, &phrase(passphrase_file)?)?;
            let keys = store
                .derived_keys()?
                .ok_or_else(|| anyhow::anyhow!("watch-only keeper"))?;
            let tags: [String; 3] = signer_tags
                .try_into()
                .map_err(|_| anyhow::anyhow!("requires three signer tags"))?;
            let descriptor = V8TreasuryDescriptor::create(
                &keys,
                parse32(&chain_id)?,
                [tag(&tags[0])?, tag(&tags[1])?, tag(&tags[2])?],
                &mut OsRng,
            )?;
            private_write(
                &private_descriptor,
                &serde_json::to_vec_pretty(&descriptor)?,
            )?;
            store.import_v8_treasury_descriptor(descriptor.clone())?;
            println!(
                "{}",
                serde_json::json!({"account_id":hex::encode(descriptor.account_id),"receive_address":descriptor.receive_address.encode()?,"threshold":2,"signers":3})
            );
        }
        Command::ImportPolicy {
            wallet,
            passphrase_file,
            private_descriptor,
        } => {
            let descriptor: V8TreasuryDescriptor =
                serde_json::from_slice(&fs::read(private_descriptor)?)?;
            let store = WalletStore::open(wallet, &phrase(passphrase_file)?)?;
            store.import_v8_treasury_descriptor(descriptor.clone())?;
            println!("{}", hex::encode(descriptor.account_id));
        }
        Command::ShowPolicy {
            wallet,
            passphrase_file,
        } => {
            let store = WalletStore::open_read_only(wallet, &phrase(passphrase_file)?)?;
            for descriptor in store.v8_treasury_descriptors()? {
                println!(
                    "{}",
                    serde_json::json!({"account_id":hex::encode(descriptor.account_id),"chain_id":hex::encode(descriptor.chain_id),"receive_address":descriptor.receive_address.encode()?,"threshold":2,"signers":3})
                );
            }
        }
        Command::BindNetwork {
            treasury,
            chain_id,
            private_descriptor,
        } => {
            require_new_output(&private_descriptor)?;
            let store = WalletStore::open(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            let descriptor = store.bind_v8_treasury_network_before_activity(
                parse32(&treasury.account_id)?,
                parse32(&chain_id)?,
            )?;
            private_write(
                &private_descriptor,
                &serde_json::to_vec_pretty(&descriptor)?,
            )?;
            println!(
                "{}",
                serde_json::json!({"account_id":hex::encode(descriptor.account_id),
                "chain_id":hex::encode(descriptor.chain_id), "receive_address":descriptor.receive_address.encode()?})
            );
        }
        Command::ImportCoinbase {
            treasury,
            public_opening,
            position,
        } => {
            let opening: PublicCoinbaseOpening =
                serde_json::from_slice(&fs::read(public_opening)?)?;
            let store = WalletStore::open(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            let account_id = parse32(&treasury.account_id)?;
            let descriptor = descriptor(&store, account_id)?;
            let note = descriptor.receive_note(
                wallet::poseidon2_v8_coinbase::protocol_opening_to_relation(opening.into()),
            )?;
            store.track_v8_treasury_note(account_id, note, position)?;
        }
        Command::CreatePlan {
            treasury,
            source_commitment,
            source_position,
            recipient,
            amount,
            fee,
            private_plan,
        } => {
            require_new_output(&private_plan)?;
            let store = WalletStore::open(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            let account_id = parse32(&treasury.account_id)?;
            let descriptor = descriptor(&store, account_id)?;
            require_launch_chain(&store, &descriptor)?;
            let tip = current_tip(&store)?;
            let source = spendable_note(
                &store,
                account_id,
                tag(&source_commitment)?,
                source_position,
                tip.anchor,
            )?;
            let plan = V8TreasuryPlan::create(
                &descriptor,
                &source.note,
                source.path,
                &ShieldedAddress::decode(&recipient)?,
                amount,
                fee,
                &mut OsRng,
            )?;
            store.persist_v8_treasury_plan(plan.clone())?;
            private_write(&private_plan, &serde_json::to_vec_pretty(&plan)?)?;
            println!("{}", hex::encode(plan.review_digest()?));
        }
        Command::ImportPlan {
            store,
            private_plan,
        } => {
            let plan: V8TreasuryPlan = serde_json::from_slice(&fs::read(private_plan)?)?;
            let store = WalletStore::open(store.wallet, &phrase(store.passphrase_file)?)?;
            require_launch_chain(&store, &descriptor(&store, plan.account_id)?)?;
            let tip = current_tip(&store)?;
            let source = spendable_note(
                &store,
                plan.account_id,
                plan.source_commitment,
                plan.source_position,
                tip.anchor,
            )?;
            anyhow::ensure!(
                source.note.note_words == plan.source_note_words,
                "plan source differs from tracked opening"
            );
            store.persist_v8_treasury_plan(plan)?;
        }
        Command::ExportPlan {
            treasury,
            review_digest,
            private_plan,
        } => {
            let store = WalletStore::open_read_only(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            let plan = stored_plan(
                &store,
                parse32(&treasury.account_id)?,
                parse_review_digest(&review_digest)?,
            )?;
            private_write(&private_plan, &serde_json::to_vec_pretty(&plan)?)?;
        }
        Command::ImportNote {
            treasury,
            private_note,
            position,
        } => {
            let note: V8TreasuryNote = serde_json::from_slice(&fs::read(private_note)?)?;
            let store = WalletStore::open(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            store.track_v8_treasury_note(parse32(&treasury.account_id)?, note, position)?;
        }
        Command::ExportNote {
            treasury,
            commitment,
            position,
            private_note,
        } => {
            let store = WalletStore::open_read_only(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            let tip = current_tip(&store)?;
            let view = spendable_note(
                &store,
                parse32(&treasury.account_id)?,
                tag(&commitment)?,
                position,
                tip.anchor,
            )?;
            private_write(&private_note, &serde_json::to_vec_pretty(&view.note)?)?;
        }
        Command::Approve {
            treasury,
            reviewed_digest,
            capability_commitment,
            capability_position,
            accumulator_commitment,
            accumulator_position,
            approval_fee,
            candidate_output,
        } => {
            require_new_output(&candidate_output)?;
            let store = WalletStore::open(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            let account_id = parse32(&treasury.account_id)?;
            let descriptor = descriptor(&store, account_id)?;
            require_launch_chain(&store, &descriptor)?;
            let plan = stored_plan(&store, account_id, parse_review_digest(&reviewed_digest)?)?;
            // acknowledge_review is called only after the explicit full digest selected these immutable bytes.
            let review = plan.acknowledge_review(&descriptor)?;
            let tip = current_tip(&store)?;
            spendable_note(
                &store,
                account_id,
                plan.source_commitment,
                plan.source_position,
                tip.anchor,
            )?;
            let keys = store
                .derived_keys()?
                .ok_or_else(|| anyhow::anyhow!("watch-only wallet cannot approve"))?;
            let commitment = tag(&capability_commitment)?;
            let capability = store
                .poseidon2_v8_owned_notes()?
                .into_iter()
                .find(|note| note.commitment == commitment && note.position == capability_position)
                .ok_or_else(|| {
                    anyhow::anyhow!("exact signer capability is absent from wallet mirror")
                })?;
            anyhow::ensure!(
                !capability.spent && capability.anchor == tip.anchor,
                "capability is spent or stale"
            );
            let current = match (accumulator_commitment, accumulator_position) {
                (Some(commitment), Some(position)) => Some(spendable_note(
                    &store,
                    account_id,
                    tag(&commitment)?,
                    position,
                    tip.anchor,
                )?),
                (None, None) => None,
                _ => anyhow::bail!("accumulator requires both commitment and position"),
            };
            let input = SmallwoodPoseidon2V8InputWitness {
                active: true,
                spend_key: keys.spend.poseidon2_v8_words()?,
                note: capability.opening,
                position: capability.position,
                siblings: capability.path,
                balance_slot_selectors: [true, false, false, false],
            };
            let (mut material, _) = build_v8_treasury_approval(
                &descriptor,
                &plan,
                &review,
                &keys,
                input,
                capability.diversifier_index,
                current.as_ref().map(|view| (&view.note, view.path)),
                tip.anchor,
                tip.height,
                approval_fee,
                &mut OsRng,
            )?;
            material.set_current_context(
                tip.height,
                tip.stablecoin_root
                    .ok_or_else(|| anyhow::anyhow!("missing current stablecoin root"))?,
            )?;
            export_candidate(&store, &plan, &material, &candidate_output)?;
        }
        Command::Finalize {
            treasury,
            reviewed_digest,
            accumulator_commitment,
            accumulator_position,
            candidate_output,
        } => {
            require_new_output(&candidate_output)?;
            let store = WalletStore::open(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            let account_id = parse32(&treasury.account_id)?;
            let descriptor = descriptor(&store, account_id)?;
            require_launch_chain(&store, &descriptor)?;
            let plan = stored_plan(&store, account_id, parse_review_digest(&reviewed_digest)?)?;
            let review = plan.acknowledge_review(&descriptor)?;
            let tip = current_tip(&store)?;
            let source = spendable_note(
                &store,
                account_id,
                plan.source_commitment,
                plan.source_position,
                tip.anchor,
            )?;
            let accumulator = spendable_note(
                &store,
                account_id,
                tag(&accumulator_commitment)?,
                accumulator_position,
                tip.anchor,
            )?;
            let mut material = build_v8_treasury_final(
                &descriptor,
                &plan,
                &review,
                source.path,
                &accumulator.note,
                accumulator.path,
                tip.height,
            )?;
            material.set_current_context(
                tip.height,
                tip.stablecoin_root
                    .ok_or_else(|| anyhow::anyhow!("missing current stablecoin root"))?,
            )?;
            export_candidate(&store, &plan, &material, &candidate_output)?;
        }
        Command::Attempts { treasury } => {
            let store = WalletStore::open_read_only(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            for (attempt, view) in store
                .v8_treasury_attempt_views(parse32(&treasury.account_id)?)?
                .into_iter()
                .enumerate()
            {
                println!(
                    "{}",
                    serde_json::json!({"attempt":attempt,
                    "status":format!("{:?}", view.status), "review_digest":hex::encode(view.review_digest),
                    "candidate_bytes":view.candidate_bytes, "recoverable":view.recoverable,
                    "all_inputs_on_chain":view.all_inputs_on_chain,
                    "action_id":view.action_id.map(hex::encode),
                    "mined_in":view.mined_in.map(|(height, hash)| serde_json::json!({"height":height,"block_hash":hex::encode(hash)}))})
                );
            }
        }
        Command::Notes { treasury } => {
            let store = WalletStore::open_read_only(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            let account_id = parse32(&treasury.account_id)?;
            let notes = store.v8_treasury_notes(account_id)?;
            let owned = store.poseidon2_v8_owned_notes()?;
            for note in notes {
                let (kind, value) = match note.kind {
                    wallet::poseidon2_v8_multisig::V8TreasuryNoteKind::Value => {
                        let value = note_from_words(&note.note_words)?.value;
                        ("value", Some(value))
                    }
                    wallet::poseidon2_v8_multisig::V8TreasuryNoteKind::Accumulator { .. } => {
                        ("accumulator", None)
                    }
                };
                // Ordinary owned notes have a canonical position in the public wallet view.
                // Accumulator openings are private policy material and are deliberately not
                // serialized or probed through the view API here.
                let public = owned
                    .iter()
                    .find(|owned| owned.commitment == note.commitment);
                println!(
                    "{}",
                    serde_json::json!({
                        "commitment": note.commitment,
                        "kind": kind,
                        "value": value,
                        "position": public.map(|view| view.position),
                        "spent": public.map(|view| view.spent),
                        "canonical": public.map(|_| true)
                    })
                );
            }
        }
        Command::Submit {
            treasury,
            attempt,
            reviewed_digest,
            rpc,
            #[cfg(feature = "poseidon2-v8-retained-test-support")]
            retained_test,
            #[cfg(feature = "poseidon2-v8-retained-test-support")]
            runtime_manifest,
        } => {
            let store = WalletStore::open(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            let account_id = parse32(&treasury.account_id)?;
            let descriptor = descriptor(&store, account_id)?;
            require_launch_chain(&store, &descriptor)?;
            let context = store.launch_context()?;
            let views = store.v8_treasury_attempt_views(account_id)?;
            let view = views
                .get(attempt)
                .ok_or_else(|| anyhow::anyhow!("unknown treasury attempt"))?;
            anyhow::ensure!(
                view.review_digest == parse_review_digest(&reviewed_digest)?.to_vec(),
                "attempt belongs to another review digest"
            );
            anyhow::ensure!(
                store.v8_treasury_attempt_ready(account_id, attempt)?,
                "candidate inputs or reference are not ready; no RPC sent"
            );
            let bytes = store
                .v8_treasury_attempt_candidate(account_id, attempt)?
                .ok_or_else(|| {
                    anyhow::anyhow!("attempt has no durably retained candidate bytes")
                })?;
            require_canonical_candidate(&store, descriptor.chain_id, &bytes)?;
            let launch = store.launch_context()?;
            let tip = current_tip(&store)?;
            let genesis = store
                .poseidon2_v8_canonical_hash(0)?
                .ok_or_else(|| anyhow::anyhow!("wallet has no canonical launch genesis"))?;
            let inclusion_height = launch.require_canonical_parent(genesis, tip.height)?;
            let decoded = decode_rp06_inline_args_exact(
                Rp06ExpectedContext::new(descriptor.chain_id, rp06_program_digest())
                    .map_err(|_| anyhow::anyhow!("invalid RP06 context"))?,
                &bytes,
            )
            .map_err(|_| anyhow::anyhow!("retained RP06 carrier framing rejected"))?;
            #[cfg(feature = "poseidon2-v8-retained-test-support")]
            if !retained_test {
                require_rp06_launch_authority(
                    context,
                    inclusion_height,
                    decoded.native_leaf().proof().len(),
                )?;
            }
            #[cfg(not(feature = "poseidon2-v8-retained-test-support"))]
            require_rp06_launch_authority(
                context,
                inclusion_height,
                decoded.native_leaf().proof().len(),
            )?;
            let runtime = tokio::runtime::Runtime::new()?;
            let (latest, latest_hash) = runtime.block_on(trusted_submit_target(&rpc, context))?;
            anyhow::ensure!(
                latest == tip.height && latest_hash == tip.block_hash,
                "wallet mirror is stale relative to submit node; sync before submit"
            );
            #[cfg(feature = "poseidon2-v8-retained-test-support")]
            if retained_test {
                let manifest = runtime_manifest.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("retained Development submit requires --runtime-manifest")
                })?;
                runtime.block_on(require_development_manifest(
                    &rpc,
                    manifest,
                    context,
                    inclusion_height,
                ))?;
            } else {
                anyhow::ensure!(!retained_test, "retained test mode unavailable");
            }
            // All local and authority checks precede the durable uncertainty marker and RPC.
            store.mark_v8_treasury_submission_uncertain(account_id, attempt)?;
            let action_id = runtime.block_on(submit_rp06_rpc(&rpc, &bytes))?;
            store.mark_v8_treasury_submitted(
                account_id,
                attempt,
                action_id
                    .as_bytes()
                    .to_vec()
                    .try_into()
                    .expect("48-byte action id"),
            )?;
            println!(
                "{}",
                serde_json::json!({"account_id":hex::encode(account_id),"attempt":attempt,"action_id":format!("0x{}",hex::encode(action_id.as_bytes())),"status":"Submitted","inputs_held_until_canonical_observation":true})
            );
        }
        Command::AbandonCandidate { treasury, attempt } => {
            let store = WalletStore::open(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            let account_id = parse32(&treasury.account_id)?;
            require_launch_chain(&store, &descriptor(&store, account_id)?)?;
            store.abandon_v8_treasury_attempt(account_id, attempt, current_tip(&store)?)?;
            println!(
                "{}",
                serde_json::json!({"account_id":hex::encode(account_id),"attempt":attempt,"status":"Abandoned","retained_for_reorg":true})
            );
        }
        Command::RecoverCandidate {
            treasury,
            attempt,
            reviewed_digest,
            candidate_output,
        } => {
            require_new_output(&candidate_output)?;
            let store = WalletStore::open(
                treasury.store.wallet,
                &phrase(treasury.store.passphrase_file)?,
            )?;
            let account_id = parse32(&treasury.account_id)?;
            let descriptor = descriptor(&store, account_id)?;
            require_launch_chain(&store, &descriptor)?;
            let plan = stored_plan(&store, account_id, parse_review_digest(&reviewed_digest)?)?;
            let views = store.v8_treasury_attempt_views(account_id)?;
            let selected = views
                .get(attempt)
                .ok_or_else(|| anyhow::anyhow!("unknown treasury attempt"))?;
            anyhow::ensure!(
                selected.review_digest == plan.review_digest()?.to_vec(),
                "attempt belongs to another reviewed operation"
            );
            if let Some(bytes) = store.v8_treasury_attempt_candidate(account_id, attempt)? {
                require_canonical_candidate(&store, descriptor.chain_id, &bytes)?;
                anyhow::ensure!(store.v8_treasury_attempt_ready(account_id, attempt)?, "candidate inputs or reference are no longer ready; bytes and reservations retained");
                private_write(&candidate_output, &bytes)?;
                println!(
                    "{}",
                    serde_json::json!({"account_id":hex::encode(account_id),
                    "attempt":attempt, "candidate_bytes":bytes.len(), "production_authorized":false,
                    "review_digest":hex::encode(plan.review_digest()?), "unchanged_reexport":true})
                );
            } else {
                let material = if plan.has_private_output_encryption_witness() {
                    let review = plan.acknowledge_review(&descriptor)?;
                    store
                        .recover_v8_treasury_attempt_material(account_id, attempt, &plan, &review)?
                } else {
                    store.recover_v8_treasury_attempt_material_v14(account_id, attempt, &plan)?
                };
                export_reserved_candidate(&store, &plan, &material, attempt, &candidate_output)?;
            }
        }
        Command::ReviewPlan {
            wallet,
            passphrase_file,
            private_plan,
        } => {
            let plan: V8TreasuryPlan = serde_json::from_slice(&fs::read(private_plan)?)?;
            let store = WalletStore::open_read_only(wallet, &phrase(passphrase_file)?)?;
            let descriptor = store
                .v8_treasury_descriptors()?
                .into_iter()
                .find(|descriptor| descriptor.account_id == plan.account_id)
                .ok_or_else(|| anyhow::anyhow!("unknown treasury account"))?;
            plan.validate(&descriptor)?;
            let statement=transaction_circuit::smallwood_poseidon2_v8_rp06::Rp06PublicStatement::try_from_public_words(&plan.public_words).map_err(|error|anyhow::anyhow!("invalid plan: {error:?}"))?;
            println!(
                "{}",
                serde_json::json!({"account_id":hex::encode(plan.account_id),"chain_id":hex::encode(statement.chain_id),"recipient":plan.recipient_address.encode()?,"amount":note_from_words(&plan.output_note_words[0])?.value,"fee":statement.base.fee,"source_commitment":tag_hex(plan.source_commitment),"source_position":plan.source_position,"review_digest":hex::encode(plan.review_digest()?)})
            );
        }
    }
    Ok(())
}

fn require_rp06_launch_authority(
    context: wallet::poseidon2_v8_sync::LaunchWalletContext,
    height: u64,
    proof_bytes: usize,
) -> anyhow::Result<()> {
    use protocol_versioning::{
        launch_candidate::{self, LaunchProofKind, LaunchProofRequest},
        ProofAuthorityClass, TxProofBackend,
    };
    let request = LaunchProofRequest {
        kind: LaunchProofKind::Rp06,
        chain_id: context.chain_id(),
        genesis_hash: context.genesis_hash(),
        manifest_digest: context.manifest_digest(),
        relation_digest: rp06_program_identity_sha512(),
        height,
        binding: launch_candidate::RP06_VERSION_BINDING,
        family_id: launch_candidate::LAUNCH_SHIELDED_FAMILY_ID,
        action_id: launch_candidate::RP06_ACTION_ID,
        proof_class: ProofAuthorityClass::Transaction,
        backend_id: TxProofBackend::SmallwoodCandidate.wire_id(),
        profile_id: launch_candidate::RP06_PROFILE_ID,
        domain_set: launch_candidate::RP06_DOMAIN_SET,
        proof_bytes,
    };
    anyhow::ensure!(
        launch_candidate::launch_proof_authority(request).is_some(),
        "no exact source-owned RP06 launch authority for this candidate and height"
    );
    Ok(())
}

async fn trusted_submit_target(
    rpc: &str,
    context: wallet::poseidon2_v8_sync::LaunchWalletContext,
) -> anyhow::Result<(u64, [u8; 32])> {
    let client = wallet::NodeRpcClient::connect(rpc).await?;
    let metadata = client.get_chain_metadata().await?;
    anyhow::ensure!(
        metadata.genesis_hash == context.genesis_hash(),
        "submit node genesis differs from wallet launch context"
    );
    let latest = client.latest_block().await?;
    let hash = client
        .block_hash(latest.height)
        .await?
        .ok_or_else(|| anyhow::anyhow!("submit node canonical tip hash unavailable"))?;
    Ok((latest.height, hash))
}

#[cfg(feature = "poseidon2-v8-retained-test-support")]
async fn require_development_manifest(
    rpc: &str,
    manifest_path: &Path,
    context: wallet::poseidon2_v8_sync::LaunchWalletContext,
    inclusion_height: u64,
) -> anyhow::Result<()> {
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(manifest_path)?)?;
    let config = if rpc.starts_with("http://") || rpc.starts_with("https://") {
        jsonrpsee_http_client::HttpClientBuilder::default()
            .build(rpc)?
            .request::<serde_json::Value, _>("hegemon_nodeConfig", rpc_params![])
            .await?
    } else if rpc.starts_with("ws://") || rpc.starts_with("wss://") {
        jsonrpsee_ws_client::WsClientBuilder::default()
            .build(rpc)
            .await?
            .request::<serde_json::Value, _>("hegemon_nodeConfig", rpc_params![])
            .await?
    } else {
        anyhow::bail!("RPC must use http(s) or ws(s)")
    };
    anyhow::ensure!(config.get("networkProfile").and_then(serde_json::Value::as_str) == Some("development")
        && config.get("networkManifest") == Some(&manifest)
        && config.get("chainId").and_then(serde_json::Value::as_str) == Some(&format!("0x{}", hex::encode(context.chain_id())))
        && context.require_canonical_parent(context.genesis_hash(), inclusion_height.saturating_sub(1)).is_ok(),
        "retained-test submit requires exact Development manifest, chain, genesis, and finite launch context");
    Ok(())
}

async fn submit_rp06_rpc(rpc: &str, inline_args: &[u8]) -> anyhow::Result<wallet::ActionId48> {
    let request = serde_json::json!({
        "binding_circuit": protocol_versioning::launch_candidate::RP06_VERSION_BINDING.circuit,
        "binding_crypto": protocol_versioning::launch_candidate::RP06_VERSION_BINDING.crypto,
        "family_id": protocol_versioning::launch_candidate::LAUNCH_SHIELDED_FAMILY_ID,
        "action_id": protocol_versioning::launch_candidate::RP06_ACTION_ID,
        "object_refs": [], "new_nullifiers": [],
        "public_args": base64::engine::general_purpose::STANDARD.encode(inline_args),
        "authorization_proof": null, "authorization_signatures": [], "aux_data": null
    });
    let response: serde_json::Value = if rpc.starts_with("http://") || rpc.starts_with("https://") {
        jsonrpsee_http_client::HttpClientBuilder::default()
            .build(rpc)?
            .request("hegemon_submitAction", rpc_params![request])
            .await?
    } else if rpc.starts_with("ws://") || rpc.starts_with("wss://") {
        jsonrpsee_ws_client::WsClientBuilder::default()
            .build(rpc)
            .await?
            .request("hegemon_submitAction", rpc_params![request])
            .await?
    } else {
        anyhow::bail!("RPC must use http(s) or ws(s)")
    };
    anyhow::ensure!(
        response.get("success").and_then(serde_json::Value::as_bool) == Some(true),
        "RP06 candidate submission rejected: {}",
        response
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown RPC rejection")
    );
    let encoded = response
        .get("tx_hash")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or_else(|| anyhow::anyhow!("successful response lacks 0x action id"))?;
    let bytes = hex::decode(encoded)?;
    wallet::ActionId48::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("RP06 action id must be exactly 48 bytes"))
}
