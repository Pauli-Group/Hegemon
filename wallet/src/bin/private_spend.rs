//! Explicit local-operator common private-spend candidate workflow.
use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand};
use jsonrpsee_core::{client::ClientT, rpc_params};
use serde::Deserialize;
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use synthetic_crypto::private_note_payload::NoteState;
use transaction_circuit::private_spend as relation;
use wallet::{
    private_spend::StoredPrivateSpendNote,
    private_spend_build::{
        self as build, OutputRequest, SpendInput, SpendOperation, SpendReference,
        TreasuryFinalTemplate,
    },
    private_spend_rpc::{prepare_submit_request, SourcePrivateSpendAuthority},
    DerivedKeys, ShieldedAddress, WalletStore,
};
use zeroize::Zeroizing;

#[cfg(feature = "private-spend-dev-artifacts")]
use wallet::private_spend_rpc::{
    prepare_submit_request_local_candidate, DevelopmentPrivateSpendAuthority,
};
enum SpendAuthority {
    Source(SourcePrivateSpendAuthority),
    #[cfg(feature = "private-spend-dev-artifacts")]
    Development(DevelopmentPrivateSpendAuthority),
}
impl SpendAuthority {
    fn context(&self) -> wallet::poseidon2_v8_sync::LaunchWalletContext {
        match self {
            Self::Source(t) => t.context(),
            #[cfg(feature = "private-spend-dev-artifacts")]
            Self::Development(t) => t.context(),
        }
    }
    fn authorize_current(&self, height: u64) -> Result<()> {
        match self {
            Self::Source(t) => Ok(t.authorize_current(height)?),
            #[cfg(feature = "private-spend-dev-artifacts")]
            Self::Development(t) => Ok(t.authorize_current(height)?),
        }
    }
    fn initialize(&self, store: &WalletStore) -> Result<()> {
        match self {
            Self::Source(t) => Ok(store.initialize_private_spend_source_context(t)?),
            #[cfg(feature = "private-spend-dev-artifacts")]
            Self::Development(t) => Ok(store.initialize_private_spend_development_context(t)?),
        }
    }
    fn apply(
        &self,
        store: &WalletStore,
        block: &wallet::poseidon2_v8_sync::Poseidon2V8CanonicalBlock,
    ) -> Result<()> {
        match self {
            Self::Source(t) => {
                store.apply_private_spend_source_block(block, t)?;
                Ok(())
            }
            #[cfg(feature = "private-spend-dev-artifacts")]
            Self::Development(t) => {
                store.apply_private_spend_development_block(block, t)?;
                Ok(())
            }
        }
    }
    fn prove(&self, prepared: &build::PreparedPrivateSpend) -> Result<Vec<u8>> {
        match self {
            Self::Source(t) => Ok(prepared.prove_authorized(t.context())?),
            #[cfg(feature = "private-spend-dev-artifacts")]
            Self::Development(_) => Ok(prepared.prove_local_candidate()?),
        }
    }
    fn retain(&self, store: &WalletStore, id: [u8; 32], action: &[u8]) -> Result<()> {
        match self {
            Self::Source(t) => Ok(store.retain_private_spend_action(t.context(), id, action)?),
            #[cfg(feature = "private-spend-dev-artifacts")]
            Self::Development(t) => Ok(store.retain_private_spend_action_local_candidate(
                t.context(),
                id,
                action,
                t,
            )?),
        }
    }
    fn submission_bytes(&self, store: &WalletStore, id: [u8; 32]) -> Result<Vec<u8>> {
        match self {
            Self::Source(t) => Ok(store.private_spend_submission_bytes(t.context(), id)?),
            #[cfg(feature = "private-spend-dev-artifacts")]
            Self::Development(t) => {
                Ok(store.private_spend_submission_bytes_local_candidate(t.context(), id, t)?)
            }
        }
    }
    fn request(&self, height: u64, carrier: &[u8]) -> Result<Value> {
        match self {
            Self::Source(t) => Ok(prepare_submit_request(t.context(), height, carrier)?),
            #[cfg(feature = "private-spend-dev-artifacts")]
            Self::Development(t) => Ok(prepare_submit_request_local_candidate(t, height, carrier)?),
        }
    }
    fn import_refund(
        &self,
        store: &WalletStore,
        bytes: &[u8],
        passphrase: &str,
        index: u32,
        block: &wallet::poseidon2_v8_sync::Poseidon2V8CanonicalBlock,
    ) -> Result<relation::Digest> {
        match self {
            Self::Source(t) => Ok(store.import_private_htlc_refund_handoff_encrypted(
                t.context(),
                bytes,
                passphrase,
                index,
                block,
            )?),
            #[cfg(feature = "private-spend-dev-artifacts")]
            Self::Development(t) => Ok(store
                .import_private_htlc_refund_handoff_encrypted_local_candidate(
                    t.context(),
                    bytes,
                    passphrase,
                    index,
                    block,
                    t,
                )?),
        }
    }
    fn import_policy(
        &self,
        store: &WalletStore,
        bytes: &[u8],
        passphrase: &str,
        index: u32,
        block: &wallet::poseidon2_v8_sync::Poseidon2V8CanonicalBlock,
    ) -> Result<relation::Digest> {
        match self {
            Self::Source(t) => Ok(store.import_private_policy_handoff_encrypted(
                t.context(),
                bytes,
                passphrase,
                index,
                block,
            )?),
            #[cfg(feature = "private-spend-dev-artifacts")]
            Self::Development(t) => Ok(store
                .import_private_policy_handoff_encrypted_local_candidate(
                    t.context(),
                    bytes,
                    passphrase,
                    index,
                    block,
                    t,
                )?),
        }
    }
}

#[derive(Parser)]
#[command(
    name = "private-spend",
    version = protocol_versioning::RELEASE_VERSION,
    about = "Current common private-spend wallet with exact source-owned release authority"
)]
struct Args {
    #[arg(long)]
    wallet: PathBuf,
    #[arg(
        long,
        help = "Required for network commands; unused by offline bootstrap"
    )]
    manifest: Option<PathBuf>,
    #[arg(
        long,
        help = "Expected genesis hash for network commands; unused by offline bootstrap"
    )]
    genesis: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:9944")]
    rpc: String,
    #[arg(long)]
    development_local_candidate: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Create an encrypted single-key wallet offline; print only its public V8 address.
    BootstrapNew,
    /// Recover the same keys into a fresh wallet for a new-network rescan; source is untouched.
    BootstrapRecover {
        #[arg(long)]
        source: PathBuf,
    },
    /// Derive and persist a public V8 address offline, without a launch identity or RPC.
    BootstrapAddress {
        #[arg(long, default_value_t = 0)]
        index: u32,
    },
    /// Create a new encrypted wallet and pin its exact private-only context.
    New,
    Sync,
    Address {
        #[arg(long)]
        index: Option<u32>,
    },
    /// Print local positions and values, never private openings or policies.
    Notes,
    Attempts,
    Cancel {
        attempt: String,
    },
    Ordinary {
        #[arg(long,num_args=1..=2)]
        inputs: Vec<u64>,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        fee: u64,
    },
    Lock {
        #[arg(long,num_args=1..=2)]
        inputs: Vec<u64>,
        #[arg(long)]
        claim: String,
        #[arg(long)]
        refund: String,
        #[arg(long)]
        hashlock: String,
        #[arg(long)]
        timeout: u64,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        fee: u64,
        /// Encrypted handoff of the exact generated locked note for the refund wallet.
        #[arg(long)]
        refund_handoff: Option<PathBuf>,
        /// Reveal the claim preimage in public transaction bytes. Disclosure begins at export/broadcast and cannot be undone by an orphan or reorg.
        #[arg(long)]
        release_secret: bool,
    },
    /// Lock value under a bounded two-branch policy; JSON contains only public branch parameters.
    PolicyLock {
        /// Encrypted handoff allowing another enabled branch wallet to import the exact locked note.
        #[arg(long)]
        policy_handoff: Option<PathBuf>,
        #[arg(long, num_args = 1..=2)]
        inputs: Vec<u64>,
        #[arg(long)]
        policy: PathBuf,
        /// Full V8 address receiving the encrypted policy note; must control an enabled branch.
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        fee: u64,
    },
    /// Spend a policy note using one branch. A required preimage is prompted without echo, never accepted on the command line.
    PolicySpend {
        #[arg(long)]
        locked: u64,
        #[arg(long)]
        fee_input: u64,
        #[arg(long, value_parser = policy_branch)]
        branch: usize,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        fee: u64,
    },
    /// Retry an encrypted refund handoff already retained in the wallet.
    ExportRefundHandoff {
        attempt: String,
        path: PathBuf,
    },
    ImportRefundHandoff {
        path: PathBuf,
        #[arg(long)]
        block_height: u64,
        #[arg(long)]
        refund_index: u32,
    },
    /// Retry exporting an already retained policy note, encrypted for private transfer to another enabled branch wallet.
    ExportPolicyHandoff {
        attempt: String,
        path: PathBuf,
    },
    /// Import an encrypted policy note after verifying its canonical lock block and local branch authority.
    ImportPolicyHandoff {
        path: PathBuf,
        #[arg(long)]
        block_height: u64,
        #[arg(long)]
        recipient_index: u32,
    },
    Claim {
        #[arg(long)]
        locked: u64,
        #[arg(long)]
        fee_input: u64,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        fee: u64,
    },
    Refund {
        #[arg(long)]
        locked: u64,
        #[arg(long)]
        fee_input: u64,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        fee: u64,
    },
    TreasuryPropose {
        #[arg(long)]
        account: String,
        #[arg(long)]
        value_position: u64,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        change: String,
        #[arg(long)]
        fee: u64,
    },
    TreasuryApprove {
        #[arg(long)]
        template: String,
        #[arg(long)]
        accumulator: Option<u64>,
        #[arg(long)]
        signer: usize,
        #[arg(long)]
        fee_input: u64,
        #[arg(long)]
        next_recipient: String,
        #[arg(long)]
        fee: u64,
    },
    TreasuryFinalize {
        #[arg(long)]
        template: String,
        #[arg(long)]
        account: String,
        #[arg(long)]
        value_position: u64,
        #[arg(long)]
        accumulator: u64,
    },
    ExportTemplate {
        template: String,
        path: PathBuf,
    },
    ImportTemplate {
        path: PathBuf,
    },
    /// Persist SubmissionUncertain before writing complete public action bytes. Any opted-in hash preimage is disclosed to recipients of this file, even if never mined.
    Export {
        attempt: String,
        path: PathBuf,
    },
    /// Submit only a previously retained exact candidate. Any opted-in hash preimage becomes public on broadcast; orphaning does not undo disclosure.
    Submit {
        attempt: String,
    },
}
/// Public policy configuration deliberately has no nullifier key or preimage
/// field. Unknown fields are errors, so a secret-bearing JSON file cannot be
/// silently accepted as a public branch descriptor.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicPolicyConfig {
    branches: [PublicPolicyBranch; 2],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicPolicyBranch {
    enabled: bool,
    authority: relation::Digest,
    not_before: u64,
    hash_required: bool,
    hashlock: String,
    release_secret: bool,
}
fn policy_branches(bytes: &[u8]) -> Result<[relation::PolicyBranch; 2]> {
    const P: u64 = 0xffff_ffff_0000_0001;
    let config: PublicPolicyConfig = serde_json::from_slice(bytes).context(
        "expected exactly two public policy branches; secrets and nullifier keys are not accepted",
    )?;
    let mut branches = [
        relation::PolicyBranch::default(),
        relation::PolicyBranch::default(),
    ];
    for (branch, public) in branches.iter_mut().zip(config.branches) {
        ensure!(
            public.authority.iter().all(|word| *word < P),
            "noncanonical policy authority"
        );
        ensure!(
            public.not_before < 1 << 48,
            "policy height exceeds 48-bit bound"
        );
        let hashlock =
            unhex(&public.hashlock).context("policy hashlock must be exactly 32 bytes of hex")?;
        ensure!(
            !public.release_secret || public.hash_required,
            "secret release requires a hash condition"
        );
        ensure!(
            public.hash_required || hashlock == [0; 32],
            "hash-free branch must have a zero hashlock"
        );
        if public.enabled {
            ensure!(
                public.authority != [0; 7],
                "enabled branch requires a nonzero authority"
            );
        } else {
            ensure!(
                public.authority == [0; 7]
                    && public.not_before == 0
                    && !public.hash_required
                    && hashlock == [0; 32]
                    && !public.release_secret,
                "disabled branch must have zero parameters"
            );
        }
        branch.enabled = u64::from(public.enabled);
        branch.authority = public.authority;
        branch.not_before = public.not_before;
        branch.hash_required = u64::from(public.hash_required);
        branch.hashlock = hashlock;
        branch.release_secret = u64::from(public.release_secret);
    }
    ensure!(branches[0].enabled == 1, "policy branch 0 must be enabled");
    Ok(branches)
}
fn policy_branch(value: &str) -> std::result::Result<usize, String> {
    match value {
        "0" => Ok(0),
        "1" => Ok(1),
        _ => Err("policy branch must be 0 or 1".into()),
    }
}
fn disclosure_warning() {
    eprintln!("This policy releases its hash preimage in public transaction bytes. Exporting shares it with file recipients; broadcasting makes it public before confirmation. Rejection, orphaning or a reorg cannot undo disclosure.");
}
fn warn_carrier_disclosure(
    context: wallet::poseidon2_v8_sync::LaunchWalletContext,
    carrier: &[u8],
) -> Result<()> {
    use protocol_shielded_pool::private_spend_transport as wire;
    let expected = wire::ExpectedContext::new(
        context.chain_id(),
        relation::relation_digest()[..48].try_into()?,
    )?;
    if wire::decode_exact(expected, carrier)?.public.secret_release == 1 {
        disclosure_warning();
    }
    Ok(())
}
fn prompted_secret() -> Result<[u8; 32]> {
    let secret = Zeroizing::new(rpassword::prompt_password(
        "Private 32-byte preimage (hex): ",
    )?);
    let mut decoded = Zeroizing::new([0; 32]);
    hex::decode_to_slice(
        secret.strip_prefix("0x").unwrap_or(&secret),
        &mut decoded[..],
    )
    .context("preimage must be exactly 32 bytes of hex")?;
    Ok(*decoded)
}
fn unhex<const N: usize>(s: &str) -> Result<[u8; N]> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected {N} bytes"))
}
fn bounded_read(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let f = fs::File::open(path)?;
    ensure!(f.metadata()?.len() <= cap, "file exceeds bound");
    let mut b = Vec::new();
    f.take(cap + 1).read_to_end(&mut b)?;
    ensure!(b.len() as u64 <= cap, "file exceeds bound");
    Ok(b)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
async fn rpc(url: &str, method: &str, param: Option<Value>) -> Result<Value> {
    let params = match param {
        Some(p) => rpc_params![p],
        None => rpc_params![],
    };
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(jsonrpsee_http_client::HttpClientBuilder::default()
            .max_response_size(jsonrpsee_core::TEN_MB_SIZE_BYTES)
            .build(url)?
            .request(method, params)
            .await?)
    } else if url.starts_with("ws://") || url.starts_with("wss://") {
        Ok(jsonrpsee_ws_client::WsClientBuilder::default()
            .max_response_size(jsonrpsee_core::TEN_MB_SIZE_BYTES)
            .build(url)
            .await?
            .request(method, params)
            .await?)
    } else {
        bail!("RPC must use HTTP(S) or WS(S)")
    }
}
async fn authority(a: &Args, node: &wallet::node_rpc::NodeRpcClient) -> Result<SpendAuthority> {
    let config = rpc(&a.rpc, "hegemon_nodeConfig", None).await?;
    let params = rpc(&a.rpc, "hegemon_privateSpendParameters", None).await?;
    let genesis = node.block_hash(0).await?.context("genesis unavailable")?;
    let tip = node.latest_block().await?;
    let manifest = bounded_read(
        a.manifest
            .as_ref()
            .context("--manifest is required for network commands")?,
        16 * 1024,
    )?;
    let expected_genesis = unhex(
        a.genesis
            .as_deref()
            .context("--genesis is required for network commands")?,
    )?;
    if a.development_local_candidate {
        #[cfg(feature = "private-spend-dev-artifacts")]
        return Ok(SpendAuthority::Development(
            DevelopmentPrivateSpendAuthority::from_verified_node(
                &manifest,
                expected_genesis,
                genesis,
                &config,
                &params,
                tip.height,
            )?,
        ));
        #[cfg(not(feature = "private-spend-dev-artifacts"))]
        bail!("Development candidate mode is absent from this production build");
    }
    Ok(SpendAuthority::Source(
        SourcePrivateSpendAuthority::from_verified_node(
            &manifest,
            expected_genesis,
            genesis,
            &config,
            &params,
            tip.height,
        )?,
    ))
}
async fn sync(
    s: &WalletStore,
    node: &wallet::node_rpc::NodeRpcClient,
    token: &SpendAuthority,
) -> Result<()> {
    token.initialize(s)?;
    loop {
        let tip = s.poseidon2_v8_tip()?;
        if node.block_hash(tip.height).await? == Some(tip.block_hash) {
            break;
        }
        ensure!(tip.height > 0, "node genesis changed");
        let height = tip.height - 1;
        let hash = s
            .poseidon2_v8_canonical_hash(height)?
            .context("mirror rollback checkpoint absent")?;
        s.rollback_poseidon2_v8_to(height, hash)?;
    }
    let end = node.latest_block().await?.height;
    for height in s.poseidon2_v8_tip()?.height + 1..=end {
        let b = node
            .canonical_block_actions(height)
            .await?
            .context("canonical block missing")?;
        token.apply(s, &b)?;
    }
    Ok(())
}
fn reference(s: &WalletStore, t: &SpendAuthority) -> Result<SpendReference> {
    let tip = s.poseidon2_v8_tip()?;
    t.authorize_current(tip.height.checked_add(1).context("height overflow")?)?;
    s.require_launch_context(t.context())?;
    Ok(SpendReference {
        chain_id: t.context().chain_id(),
        parent_hash: tip.block_hash,
        parent_height: tip.height,
        merkle_root: tip.anchor,
    })
}
fn private_note(s: &WalletStore, position: u64) -> Result<StoredPrivateSpendNote> {
    s.private_spend_notes()?
        .into_iter()
        .find(|n| n.position == position && !n.spent)
        .context("unspent private note absent at position")
}
fn stored_input(
    s: &WalletStore,
    k: &DerivedKeys,
    n: &StoredPrivateSpendNote,
) -> Result<SpendInput> {
    let path = s
        .poseidon2_v8_canonical_note_witness_at(n.commitment, n.position)?
        .context("canonical membership absent")?;
    ensure!(
        path.anchor == s.poseidon2_v8_tip()?.anchor,
        "stale membership"
    );
    Ok(SpendInput::stored(n, k, path.path)?)
}
fn ordinary_input(
    s: &WalletStore,
    k: &DerivedKeys,
    r: SpendReference,
    position: u64,
) -> Result<(SpendInput, u64)> {
    if let Some(n) = s
        .private_spend_notes()?
        .into_iter()
        .find(|n| n.position == position && !n.spent)
    {
        let p = n.opening()?;
        ensure!(
            matches!(p.state, NoteState::Ordinary { .. }),
            "selected input is a policy note"
        );
        return Ok((stored_input(s, k, &n)?, p.note.value));
    }
    let n = s
        .poseidon2_v8_owned_notes()?
        .into_iter()
        .find(|n| n.position == position && !n.spent)
        .context("unspent ordinary input absent")?;
    Ok((
        SpendInput::legacy(n.opening, n.position.try_into()?, n.path, k, r.chain_id)?,
        n.opening.value,
    ))
}
fn ordinary_inputs(
    s: &WalletStore,
    k: &DerivedKeys,
    r: SpendReference,
    positions: &[u64],
) -> Result<([SpendInput; 2], u64)> {
    ensure!(
        (1..=2).contains(&positions.len()),
        "select one or two inputs"
    );
    ensure!(
        positions.len() == 1 || positions[0] != positions[1],
        "duplicate input"
    );
    let (first, a) = ordinary_input(s, k, r, positions[0])?;
    let (second, b) = if positions.len() == 2 {
        ordinary_input(s, k, r, positions[1])?
    } else {
        (SpendInput::dummy()?, 0)
    };
    Ok(([first, second], a.checked_add(b).context("value overflow")?))
}
fn outputs(
    recipient: &str,
    amount: u64,
    change: ShieldedAddress,
    total: u64,
    fee: u64,
) -> Result<[OutputRequest; 2]> {
    let remainder = total
        .checked_sub(amount)
        .and_then(|x| x.checked_sub(fee))
        .context("insufficient value")?;
    Ok([
        OutputRequest {
            recipient: ShieldedAddress::decode(recipient)?,
            value: amount,
        },
        OutputRequest {
            recipient: change,
            value: remainder,
        },
    ])
}
fn treasury_value(
    s: &WalletStore,
    r: SpendReference,
    account: &str,
    position: u64,
) -> Result<(SpendInput, relation::TreasuryOpening, u64)> {
    let id = unhex(account)?;
    let descriptor = s
        .v8_treasury_descriptors()?
        .into_iter()
        .find(|d| d.account_id == id)
        .context("treasury descriptor absent from encrypted wallet")?;
    let mut found = None;
    for n in s.v8_treasury_notes(id)? {
        if let Ok(v) = s.v8_treasury_note_view(id, n.commitment, position) {
            let amount = wallet::poseidon2_v8_multisig::note_from_words(&v.note.note_words)?.value;
            let (i, p) = build::treasury_value_input(r, &descriptor, &v)?;
            ensure!(found.is_none(), "ambiguous treasury position");
            found = Some((i, p, amount));
        }
    }
    found.context("canonical unreserved treasury value note absent")
}
fn accumulator(s: &WalletStore, k: &DerivedKeys, position: u64) -> Result<(SpendInput, [u64; 3])> {
    let n = private_note(s, position)?;
    let p = n.opening()?;
    let NoteState::TreasuryAccumulator(t) = &p.state else {
        bail!("not a treasury accumulator")
    };
    Ok((stored_input(s, k, &n)?, t.approved))
}
fn prove(
    s: &WalletStore,
    t: &SpendAuthority,
    p: build::PreparedPrivateSpend,
    is_lock: bool,
    refund_handoff: Option<&Path>,
    is_policy_lock: bool,
    policy_handoff: Option<&Path>,
) -> Result<()> {
    t.authorize_current(
        p.public_statement()
            .reference_parent_height
            .checked_add(1)
            .context("height overflow")?,
    )?;
    let id = s.reserve_private_spend(t.context(), &p)?;
    let carrier = t
        .prove(&p)
        .with_context(|| format!("attempt {} remains durably reserved", hex::encode(id)))?;
    let action =
        wallet::poseidon2_v8_sync::encode_private_spend_candidate_action(t.context(), &carrier)?;
    t.retain(s, id, &action)?;
    if is_lock {
        s.retain_private_htlc_refund_handoff(t.context(), id, &p)?;
    }
    if let Some(path) = refund_handoff {
        let pw = Zeroizing::new(rpassword::prompt_password(
            "Encrypted refund handoff passphrase: ",
        )?);
        let bytes = s.export_stored_private_htlc_refund_handoff_encrypted(t.context(), id, &pw)?;
        write_new(path, &bytes).with_context(|| {
            format!("attempt {} remains durably reserved; retry with export-refund-handoff and a new destination", hex::encode(id))
        })?;
    }
    if is_policy_lock {
        s.retain_private_policy_handoff(t.context(), id, &p)?;
    }
    if let Some(path) = policy_handoff {
        let pw = Zeroizing::new(rpassword::prompt_password(
            "Encrypted policy handoff passphrase: ",
        )?);
        let bytes = s.export_stored_private_policy_handoff_encrypted(t.context(), id, &pw)?;
        write_new(path, &bytes).with_context(|| {
            format!("attempt {} remains durably reserved; retry with export-policy-handoff and a new destination", hex::encode(id))
        })?;
    }
    println!("candidate {}", hex::encode(id));
    Ok(())
}
fn bootstrap_public(store: &WalletStore, index: u32) -> Result<Value> {
    // This registry write precedes publishing the address, so a restored wallet
    // retains the exact issued address even before its launch context exists.
    let address = store.private_spend_address(index)?;
    Ok(serde_json::json!({
        "schema": "hegemon.private-spend.bootstrap.v1",
        "custody": "single-key",
        "address_index": index,
        "address": address.encode()?,
    }))
}
fn bootstrap_new(path: &Path, passphrase: &str, confirmation: &str) -> Result<Value> {
    ensure!(
        !passphrase.is_empty(),
        "encrypted wallet passphrase must not be empty"
    );
    ensure!(
        passphrase == confirmation,
        "encrypted wallet passphrases differ"
    );
    // Uses OS randomness and the existing encrypted wallet format; the writer
    // lock makes refusal to replace an existing store race-safe.
    let store = WalletStore::create_full_if_missing(path, passphrase)?;
    bootstrap_public(&store, 0)
}
fn bootstrap_address(path: &Path, passphrase: &str, index: u32) -> Result<Value> {
    let store = WalletStore::open(path, passphrase)?;
    bootstrap_public(&store, index)
}
fn validate_network_args(args: &Args) -> Result<()> {
    ensure!(
        args.manifest.is_some(),
        "--manifest is required for network commands"
    );
    let genesis = args
        .genesis
        .as_deref()
        .context("--genesis is required for network commands")?;
    let _: [u8; 32] = unhex(genesis)?;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let identity_args: Vec<_> = std::env::args_os().skip(1).collect();
    if identity_args
        .iter()
        .any(|arg| arg == "--print-crypto-profile")
    {
        ensure!(
            identity_args.len() == 1,
            "--print-crypto-profile must be used alone"
        );
        let profile = transaction_circuit::proof::production_crypto_profile_attestation()?;
        println!("{}", serde_json::to_string(&profile)?);
        return Ok(());
    }
    let args = Args::parse();
    // Offline bootstrap intentionally precedes manifest/genesis validation,
    // RPC connection, authority lookup and chain synchronization.
    match &args.command {
        Command::BootstrapNew => {
            let phrase =
                Zeroizing::new(rpassword::prompt_password("Encrypted wallet passphrase: ")?);
            let confirmation = Zeroizing::new(rpassword::prompt_password(
                "Confirm encrypted wallet passphrase: ",
            )?);
            println!("{}", bootstrap_new(&args.wallet, &phrase, &confirmation)?);
            return Ok(());
        }
        Command::BootstrapRecover { source } => {
            let source_phrase = Zeroizing::new(rpassword::prompt_password(
                "Source encrypted wallet passphrase: ",
            )?);
            let phrase = Zeroizing::new(rpassword::prompt_password(
                "New encrypted wallet passphrase: ",
            )?);
            let confirmation = Zeroizing::new(rpassword::prompt_password(
                "Confirm new encrypted wallet passphrase: ",
            )?);
            ensure!(
                !phrase.is_empty(),
                "new encrypted wallet passphrase must not be empty"
            );
            ensure!(
                phrase == confirmation,
                "new encrypted wallet passphrases differ"
            );
            let original = WalletStore::open_read_only(source, &source_phrase)?;
            ensure!(
                original.mode()? == wallet::store::WalletMode::Full,
                "treasury bootstrap recovery requires a full wallet"
            );
            drop(original);
            let store = WalletStore::recover_keys_to_fresh_wallet(
                source,
                &source_phrase,
                &args.wallet,
                &phrase,
            )?;
            let mut public = bootstrap_public(&store, 0)?;
            public["recovered_same_keys"] = Value::Bool(true);
            public["requires_network_rescan"] = Value::Bool(true);
            eprintln!("Original wallet preserved. Fresh destination retains keys/accounts only; select and verify the intended network, then rescan before spending.");
            println!("{}", public);
            return Ok(());
        }
        Command::BootstrapAddress { index } => {
            let phrase =
                Zeroizing::new(rpassword::prompt_password("Encrypted wallet passphrase: ")?);
            println!("{}", bootstrap_address(&args.wallet, &phrase, *index)?);
            return Ok(());
        }
        _ => {}
    }
    validate_network_args(&args)?;
    let node = wallet::node_rpc::NodeRpcClient::connect(&args.rpc).await?;
    let token = authority(&args, &node).await?;
    let phrase = Zeroizing::new(rpassword::prompt_password("Encrypted wallet passphrase: ")?);
    let store = if matches!(&args.command, Command::New) {
        WalletStore::create_full_if_missing(&args.wallet, &phrase)?
    } else {
        WalletStore::open(&args.wallet, &phrase)?
    };
    sync(&store, &node, &token).await?;
    let r = reference(&store, &token)?;
    let submission_authority = if matches!(&args.command, Command::Submit { .. }) {
        Some(authority(&args, &node).await?)
    } else {
        None
    };
    match args.command {
        Command::BootstrapNew
        | Command::BootstrapRecover { .. }
        | Command::BootstrapAddress { .. } => unreachable!("offline bootstrap returned before RPC"),
        Command::New | Command::Sync => println!("synced {}", r.parent_height),
        Command::Address { index } => {
            let address = match index {
                Some(index) => store.private_spend_address(index)?,
                None => store.next_private_spend_address()?,
            };
            eprintln!("local address index {}", address.diversifier_index);
            println!("{}", address.encode()?);
        }
        Command::Notes => {
            for n in store
                .poseidon2_v8_owned_notes()?
                .into_iter()
                .filter(|n| !n.spent)
            {
                println!("ordinary position={} value={}", n.position, n.opening.value)
            }
            for n in store
                .private_spend_notes()?
                .into_iter()
                .filter(|n| !n.spent)
            {
                let p = n.opening()?;
                let kind = match &p.state {
                    NoteState::Ordinary { .. } => "ordinary",
                    NoteState::Htlc(_) => "htlc",
                    NoteState::Policy(_) => "policy",
                    NoteState::TreasuryValue(_) => "treasury-value",
                    NoteState::TreasuryAccumulator(_) => "accumulator",
                };
                println!("{} position={} value={}", kind, n.position, p.note.value)
            }
        }
        Command::Attempts => {
            for a in store.private_spend_attempts()? {
                println!(
                    "{} {:?} mined={:?}",
                    hex::encode(a.id),
                    a.status,
                    a.mined_in
                )
            }
        }
        Command::Cancel { attempt } => store.cancel_private_spend_preparation(unhex(&attempt)?)?,
        Command::ExportRefundHandoff { attempt, path } => {
            let pw = Zeroizing::new(rpassword::prompt_password(
                "Encrypted refund handoff passphrase: ",
            )?);
            let bytes = store.export_stored_private_htlc_refund_handoff_encrypted(
                token.context(),
                unhex(&attempt)?,
                &pw,
            )?;
            write_new(&path, &bytes)?;
        }
        Command::ImportRefundHandoff {
            path,
            block_height,
            refund_index,
        } => {
            let block = node
                .canonical_block_actions(block_height)
                .await?
                .context("canonical HTLC lock block missing")?;
            let pw = Zeroizing::new(rpassword::prompt_password(
                "Encrypted refund handoff passphrase: ",
            )?);
            let commitment = token.import_refund(
                &store,
                &bounded_read(&path, 1024 * 1024)?,
                &pw,
                refund_index,
                &block,
            )?;
            println!(
                "imported HTLC commitment {}",
                hex::encode(
                    commitment
                        .iter()
                        .flat_map(|word| word.to_le_bytes())
                        .collect::<Vec<_>>(),
                )
            );
        }
        Command::ExportPolicyHandoff { attempt, path } => {
            let pw = Zeroizing::new(rpassword::prompt_password(
                "Encrypted policy handoff passphrase: ",
            )?);
            let bytes = store.export_stored_private_policy_handoff_encrypted(
                token.context(),
                unhex(&attempt)?,
                &pw,
            )?;
            write_new(&path, &bytes)?;
        }
        Command::ImportPolicyHandoff {
            path,
            block_height,
            recipient_index,
        } => {
            let block = node
                .canonical_block_actions(block_height)
                .await?
                .context("canonical policy lock block missing")?;
            let pw = Zeroizing::new(rpassword::prompt_password(
                "Encrypted policy handoff passphrase: ",
            )?);
            let commitment = token.import_policy(
                &store,
                &bounded_read(&path, 1024 * 1024)?,
                &pw,
                recipient_index,
                &block,
            )?;
            println!(
                "imported policy commitment {}",
                hex::encode(
                    commitment
                        .iter()
                        .flat_map(|word| word.to_le_bytes())
                        .collect::<Vec<_>>()
                )
            );
        }
        Command::ExportTemplate { template, path } => {
            let pw = Zeroizing::new(rpassword::prompt_password(
                "Encrypted handoff passphrase: ",
            )?);
            let b = store.export_private_treasury_template_encrypted(
                token.context(),
                unhex(&template)?,
                &pw,
            )?;
            write_new(&path, &b)?;
        }
        Command::ImportTemplate { path } => {
            let pw = Zeroizing::new(rpassword::prompt_password(
                "Encrypted handoff passphrase: ",
            )?);
            let id = store.import_private_treasury_template_encrypted(
                token.context(),
                &bounded_read(&path, 1024 * 1024)?,
                &pw,
            )?;
            println!("template {}", hex::encode(id));
        }
        Command::Export { attempt, path } => {
            let id = unhex(&attempt)?;
            let b = token.submission_bytes(&store, id)?;
            let (_, carrier) =
                wallet::poseidon2_v8_sync::project_private_spend_candidate_action(&b)?;
            warn_carrier_disclosure(token.context(), &carrier)?;
            write_new(&path, &b)?;
        }
        Command::Submit { attempt } => {
            let fresh = submission_authority
                .as_ref()
                .context("submission authority absent")?;
            let id = unhex(&attempt)?;
            let action = fresh.submission_bytes(&store, id)?;
            let (expected, carrier) =
                wallet::poseidon2_v8_sync::project_private_spend_candidate_action(&action)?;
            warn_carrier_disclosure(fresh.context(), &carrier)?;
            let height = node
                .latest_block()
                .await?
                .height
                .checked_add(1)
                .context("height overflow")?;
            let request = fresh.request(height, &carrier)?;
            let reply = rpc(&args.rpc, "hegemon_submitAction", Some(request)).await?;
            ensure!(reply["success"] == true, "submission uncertain: {}", reply);
            let ack = reply
                .get("tx_hash")
                .or_else(|| reply.get("tx_id"))
                .and_then(Value::as_str)
                .context("submission acknowledgment missing")?;
            let ack = unhex(ack)?;
            ensure!(ack == expected, "submission acknowledgment differs");
            store.mark_private_spend_submitted(id, ack)?;
            println!("submitted {}", hex::encode(ack));
        }
        command => {
            let keys = store.derived_keys()?.context("watch-only wallet")?;
            let change = store.next_private_spend_address()?;
            let is_claim = matches!(&command, Command::Claim { .. });
            let is_lock = matches!(&command, Command::Lock { .. });
            let is_policy_lock = matches!(&command, Command::PolicyLock { .. });
            let policy_handoff = match &command {
                Command::PolicyLock { policy_handoff, .. } => policy_handoff.clone(),
                _ => None,
            };
            let refund_handoff = match &command {
                Command::Lock { refund_handoff, .. } => refund_handoff.clone(),
                _ => None,
            };
            for path in refund_handoff.iter().chain(policy_handoff.iter()) {
                ensure!(
                    !path.try_exists()?,
                    "encrypted handoff destination already exists"
                );
            }
            let p = match command {
                Command::Ordinary {
                    inputs,
                    recipient,
                    amount,
                    fee,
                } => {
                    let (i, total) = ordinary_inputs(&store, &keys, r, &inputs)?;
                    build::prepare(
                        r,
                        fee,
                        i,
                        outputs(&recipient, amount, change, total, fee)?,
                        SpendOperation::Ordinary,
                    )?
                }
                Command::Lock {
                    inputs,
                    claim,
                    refund,
                    hashlock,
                    timeout,
                    amount,
                    fee,
                    refund_handoff: _,
                    release_secret,
                } => {
                    let (i, total) = ordinary_inputs(&store, &keys, r, &inputs)?;
                    let ca = ShieldedAddress::decode(&claim)?;
                    let ra = ShieldedAddress::decode(&refund)?;
                    let mut policy =
                        build::new_htlc_policy(r, &ca, &ra, unhex(&hashlock)?, timeout)?;
                    policy.release_secret = u64::from(release_secret);
                    if release_secret {
                        eprintln!("HTLC claims will publish their hash preimage. Disclosure persists even if a claim is rejected, orphaned or reorganized away.");
                    }
                    build::prepare(
                        r,
                        fee,
                        i,
                        outputs(&claim, amount, change, total, fee)?,
                        SpendOperation::HtlcLock(policy),
                    )?
                }
                Command::PolicyLock {
                    inputs,
                    policy,
                    recipient,
                    amount,
                    fee,
                    policy_handoff: _,
                } => {
                    let branches = policy_branches(&bounded_read(&policy, 16 * 1024)?)?;
                    let policy = build::new_bounded_policy(r, branches)?;
                    let (inputs, total) = ordinary_inputs(&store, &keys, r, &inputs)?;
                    build::prepare(
                        r,
                        fee,
                        inputs,
                        outputs(&recipient, amount, change, total, fee)?,
                        SpendOperation::PolicyLock(policy),
                    )?
                }
                Command::PolicySpend {
                    locked,
                    fee_input,
                    branch,
                    recipient,
                    amount,
                    fee,
                } => {
                    ensure!(locked != fee_input, "policy note and fee input must differ");
                    let note = private_note(&store, locked)?;
                    let payload = note.opening()?;
                    let NoteState::Policy(policy) = &payload.state else {
                        bail!("not a bounded policy note")
                    };
                    let policy = build::bounded_policy_from_payload(policy);
                    let selected = policy
                        .branches
                        .get(branch)
                        .context("policy branch must be 0 or 1")?;
                    ensure!(selected.enabled == 1, "selected policy branch is disabled");
                    ensure!(
                        r.parent_height >= selected.not_before,
                        "selected policy branch has not reached its spend height"
                    );
                    if selected.release_secret == 1 {
                        disclosure_warning();
                    }
                    let secret = if selected.hash_required == 1 {
                        prompted_secret()?
                    } else {
                        [0; 32]
                    };
                    let input = stored_input(&store, &keys, &note)?;
                    let (fee_note, fee_value) = ordinary_input(&store, &keys, r, fee_input)?;
                    let total = payload
                        .note
                        .value
                        .checked_add(fee_value)
                        .context("value overflow")?;
                    build::prepare(
                        r,
                        fee,
                        [input, fee_note],
                        outputs(&recipient, amount, change, total, fee)?,
                        SpendOperation::PolicySpend {
                            policy,
                            branch,
                            secret,
                        },
                    )?
                }
                Command::Claim {
                    locked,
                    fee_input,
                    recipient,
                    fee,
                }
                | Command::Refund {
                    locked,
                    fee_input,
                    recipient,
                    fee,
                } => {
                    let claim = is_claim;
                    let n = private_note(&store, locked)?;
                    let payload = n.opening()?;
                    let NoteState::Htlc(h) = &payload.state else {
                        bail!("not an HTLC note")
                    };
                    let mut policy = relation::PrivateHtlcOpening {
                        nullifier_key: h.nullifier_key,
                        hashlock: h.hashlock,
                        claim_authority: h.claim_authority,
                        refund_authority: h.refund_authority,
                        claim_recipient: h.claim_recipient,
                        refund_recipient: h.refund_recipient,
                        timeout: h.timeout,
                        secret: [0; 32],
                        release_secret: h.release_secret,
                    };
                    if claim {
                        if policy.release_secret == 1 {
                            disclosure_warning();
                        }
                        policy.secret = prompted_secret()?;
                    }
                    let input = stored_input(&store, &keys, &n)?;
                    let (fee_note, total) = ordinary_input(&store, &keys, r, fee_input)?;
                    let req = outputs(
                        &recipient,
                        payload.note.value,
                        change,
                        total
                            .checked_add(payload.note.value)
                            .context("value overflow")?,
                        fee,
                    )?;
                    build::prepare(
                        r,
                        fee,
                        [input, fee_note],
                        req,
                        if claim {
                            SpendOperation::HtlcClaim(policy)
                        } else {
                            SpendOperation::HtlcRefund(policy)
                        },
                    )?
                }
                Command::TreasuryPropose {
                    account,
                    value_position,
                    recipient,
                    amount,
                    change,
                    fee,
                } => {
                    let (i, p, total) = treasury_value(&store, r, &account, value_position)?;
                    let template = TreasuryFinalTemplate::prepare(
                        r,
                        fee,
                        &i,
                        p,
                        outputs(
                            &recipient,
                            amount,
                            ShieldedAddress::decode(&change)?,
                            total,
                            fee,
                        )?,
                    )?;
                    let id = store.save_private_treasury_template(token.context(), &template)?;
                    println!("template {}", hex::encode(id));
                    return Ok(());
                }
                Command::TreasuryApprove {
                    template,
                    accumulator: position,
                    signer,
                    fee_input,
                    next_recipient,
                    fee,
                } => {
                    let template =
                        store.load_private_treasury_template(token.context(), unhex(&template)?)?;
                    let (acc, approved) = match position {
                        Some(p) => accumulator(&store, &keys, p)?,
                        None => (SpendInput::dummy()?, [0; 3]),
                    };
                    let policy = template.approval_policy(approved, signer)?;
                    let (input, total) = ordinary_input(&store, &keys, r, fee_input)?;
                    build::prepare(
                        r,
                        fee,
                        [acc, input],
                        outputs(&next_recipient, 0, change, total, fee)?,
                        SpendOperation::Approval(policy),
                    )?
                }
                Command::TreasuryFinalize {
                    template,
                    account,
                    value_position,
                    accumulator: position,
                } => {
                    let template =
                        store.load_private_treasury_template(token.context(), unhex(&template)?)?;
                    let (value, _, _) = treasury_value(&store, r, &account, value_position)?;
                    let (acc, approved) = accumulator(&store, &keys, position)?;
                    template.finalize(r, [value, acc], approved)?
                }
                _ => unreachable!(),
            };
            prove(
                &store,
                &token,
                p,
                is_lock,
                refund_handoff.as_deref(),
                is_policy_lock,
                policy_handoff.as_deref(),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod bootstrap_tests {
    use super::*;

    #[test]
    fn offline_commands_need_no_launch_settings() {
        let args =
            Args::try_parse_from(["private-spend", "--wallet", "new.store", "bootstrap-new"])
                .unwrap();
        assert!(matches!(args.command, Command::BootstrapNew));
        assert!(args.manifest.is_none() && args.genesis.is_none());
        let args = Args::try_parse_from([
            "private-spend",
            "--wallet",
            "new.store",
            "--rpc",
            "invalid-no-network",
            "bootstrap-address",
            "--index",
            "7",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Command::BootstrapAddress { index: 7 }
        ));
        let args = Args::try_parse_from([
            "private-spend",
            "--wallet",
            "fresh.store",
            "bootstrap-recover",
            "--source",
            "historical.store",
        ])
        .unwrap();
        assert!(matches!(args.command, Command::BootstrapRecover { .. }));
    }

    #[test]
    fn network_commands_still_require_launch_settings() {
        let args =
            Args::try_parse_from(["private-spend", "--wallet", "new.store", "sync"]).unwrap();
        assert!(validate_network_args(&args)
            .unwrap_err()
            .to_string()
            .contains("--manifest"));
    }

    #[test]
    fn bootstrap_refuses_overwrite_and_retains_public_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.store");
        let public = bootstrap_new(&path, "disposable-test-only", "disposable-test-only").unwrap();
        assert_eq!(public["custody"], "single-key");
        assert_eq!(public["address_index"], 0);
        assert_eq!(public.as_object().unwrap().len(), 4);
        let original = fs::read(&path).unwrap();
        assert!(bootstrap_new(&path, "replacement-test-only", "replacement-test-only").is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(
            bootstrap_address(&path, "disposable-test-only", 0).unwrap(),
            public
        );
        assert!(bootstrap_address(&path, "incorrect-test-only", 0).is_err());
        let additional = bootstrap_address(&path, "disposable-test-only", 7).unwrap();
        assert_eq!(additional["address_index"], 7);
        assert_ne!(additional["address"], public["address"]);
        assert_eq!(
            bootstrap_address(&path, "disposable-test-only", 7).unwrap(),
            additional
        );
    }

    #[test]
    fn invalid_new_passphrase_does_not_create_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.store");
        assert!(bootstrap_new(&path, "", "").is_err());
        assert!(!path.exists());
        assert!(bootstrap_new(&path, "one", "two").is_err());
        assert!(!path.exists());
    }
}

#[cfg(test)]
mod policy_cli_tests {
    use super::*;

    fn public_policy() -> Value {
        serde_json::json!({"branches": [
            {"enabled": true, "authority": [1,0,0,0,0,0,0], "not_before": 120,
             "hash_required": true, "hashlock": "ab".repeat(32), "release_secret": true},
            {"enabled": false, "authority": [0,0,0,0,0,0,0], "not_before": 0,
             "hash_required": false, "hashlock": "00".repeat(32), "release_secret": false}
        ]})
    }
    fn parsed(value: &Value) -> Result<[relation::PolicyBranch; 2]> {
        policy_branches(&serde_json::to_vec(value)?)
    }

    #[test]
    fn policy_configuration_accepts_only_public_branch_parameters() {
        let config = public_policy();
        let branches = parsed(&config).unwrap();
        assert_eq!(branches[0].not_before, 120);
        assert_eq!(branches[0].release_secret, 1);
        assert_eq!(branches[1].enabled, 0);
        let mut with_secret = config.clone();
        with_secret["branches"][0]["secret"] = Value::String("ab".repeat(32));
        assert!(parsed(&with_secret).is_err());
        let mut with_key = config;
        with_key["nullifier_key"] = serde_json::json!([1, 2, 3, 4, 5]);
        assert!(parsed(&with_key).is_err());
    }

    #[test]
    fn policy_configuration_rejects_ambiguous_and_unbounded_parameters() {
        let mut config = public_policy();
        config["branches"][0]["release_secret"] = Value::from(1);
        assert!(parsed(&config).is_err());
        let mut config = public_policy();
        config["branches"][0]["not_before"] = Value::from(1u64 << 48);
        assert!(parsed(&config).is_err());
        let mut config = public_policy();
        config["branches"][1]["authority"][0] = Value::from(1);
        assert!(parsed(&config).is_err());
        let mut config = public_policy();
        config["branches"][0]["hash_required"] = Value::Bool(false);
        assert!(parsed(&config).is_err());
        let mut config = public_policy();
        config["branches"].as_array_mut().unwrap().pop();
        assert!(parsed(&config).is_err());
        let mut config = public_policy();
        config["branches"].as_array_mut().unwrap().swap(0, 1);
        assert!(parsed(&config).is_err());
    }

    #[test]
    fn policy_cli_bounds_branch_selection_and_keeps_secrets_off_arguments() {
        let base = [
            "private-spend",
            "--wallet",
            "wallet.store",
            "policy-spend",
            "--locked",
            "1",
            "--fee-input",
            "2",
            "--recipient",
            "public-address",
            "--amount",
            "3",
            "--fee",
            "1",
            "--branch",
        ];
        let mut command = base.to_vec();
        command.push("1");
        let args = Args::try_parse_from(&command).unwrap();
        assert!(matches!(
            args.command,
            Command::PolicySpend { branch: 1, .. }
        ));
        command.pop();
        command.push("2");
        assert!(Args::try_parse_from(&command).is_err());
        command.pop();
        command.push("0");
        command.extend(["--secret", "ab"]);
        assert!(Args::try_parse_from(&command).is_err());
    }

    #[test]
    fn htlc_preimage_release_is_explicit_opt_in() {
        let base = [
            "private-spend",
            "--wallet",
            "wallet.store",
            "lock",
            "--inputs",
            "1",
            "--claim",
            "a",
            "--refund",
            "b",
            "--hashlock",
            "00",
            "--timeout",
            "120",
            "--amount",
            "3",
            "--fee",
            "1",
        ];
        let args = Args::try_parse_from(base).unwrap();
        assert!(matches!(
            args.command,
            Command::Lock {
                release_secret: false,
                ..
            }
        ));
        let mut opted_in = base.to_vec();
        opted_in.push("--release-secret");
        let args = Args::try_parse_from(opted_in).unwrap();
        assert!(matches!(
            args.command,
            Command::Lock {
                release_secret: true,
                ..
            }
        ));
    }
}
