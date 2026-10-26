//! Controlled-asset operations on the existing persistent wallet and node RPC.
//!
//! The stdio daemon and one-shot request-file mode use the same dispatch path;
//! neither command-line flags nor request metadata authorize registry changes.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use wallet::{
    asset_spend_rpc::{AssetNodeContext, AuthenticatedAssetPolicy},
    node_rpc::NodeRpcClient,
    store::WalletStore,
    WalletError,
};

use crate::{WalletdError, WalletdErrorCode, WalletdResult};

pub const HELP: &str = r#"Controlled assets use the existing encrypted wallet store.

Run walletd --store PATH [--mode create|open] and provide the passphrase on the
first stdin line, followed by JSON request lines. To perform one operation, use
--request-file PATH; that file contains one JSON request, including its id,
method and params. The passphrase is still read from stdin. Requests are limited
to 8 MiB; private material belongs in the encrypted wallet store.

Example request:
{"id":1,"method":"asset.balances","params":{}}

Offline methods:
  asset.address  {"index":0}  full public receiving address and credential owner
  asset.balances {}           issued assets and asset-route native fee change
  asset.notes    {}           owned note positions, state and policy ownership
  asset.journal  {}           durable reservations and submission outcomes
  asset.export   {"reservation_id":"<64 lowercase hex>"}  retained action bytes
  asset.abandon  {"reservation_id":"<64 lowercase hex>"}  safe stale tombstone
  asset.setup    {"rows":["<canonical 552-byte public row hex>"]}
                 descriptor for --development-assets-json on a fresh network
  asset.row      {"disposable":true,"asset_id":17,"policy_version":1,
    "issuer_secret":[7 field words],"admin_secret":[7 different field words],
    "credential_root":[7 field words],"credential_depth":4}
                 derive real role commitments and a zero-supply public row plus
                 descriptor. Optional config overrides the disposable public
                 V8 issuance/oracle/attestation/collateral defaults.
  asset.credentials {"asset_id":17,"policy_version":1,"depth":4,"entries":[
    {"index":0,"recipient":"<address>","expires_at":1000}]}
                 current credential root and each entry's witness
  asset.policyOwner {"chain_id":"<32-byte hex>","asset_id":17,"policy":{
    "nullifier_key":[1,2,3,4,5],"branches":[{"enabled":1,"authority":[1,2,3,4,5,6,7]},{}]}}
                 committed bounded owner for a credential's optional owner field

Online methods require ws_url (HTTP or WebSocket):
  asset.sync {"ws_url":"http://127.0.0.1:9944","manifest":"manifest.json",
    "expected_genesis":"<32-byte lowercase hex>"}
                 pin the exact Development network and sync/reconcile reorgs;
                 requires --features development-assets when building walletd
  asset.prepare {"ws_url":"...","asset_id":17,"operation":"mint|transfer|burn",
    "amount":1,"fee":1,"recipient":"<address>","credentials":[<input>,<payment>,<change>]}
                 each credential is {index,expires_at,siblings}; mint input is
                 {"index":0,"expires_at":0,"siblings":[]}; mint also needs
                 issuer_secret:[7 field words]. Defaults: both change indices 0,
                 ordinary policy. Active credentials must expire at/after H+12.
                 Returns durable reservation_id, selected H/hash and last valid
                 parent H+12. Sync first if the selected wallet tip is too old.
                 Optional policy:{create,spend,input,output,selected,secret};
                 input/output have the same shape as policyOwner's policy.
                 A policy input also requires input_position.
  asset.submit {"ws_url":"...","reservation_id":"<64 lowercase hex>"}
                 revalidate canonical H/current policy, durably mark intent,
                 submit exact retained bytes, record outcome. Retry uses the same
                 bytes/reservation; uncertain errors keep inputs reserved.
                 Reprove only after explicit abandonment beyond H+12 and sync.
  asset.admin {"ws_url":"...","asset_id":17,"admin_secret":[7 field words],
    "expires_at":1000,"action_intent":[7 fresh field words],"frozen":true}
                 prove and submit authenticated controls; optional controls are
                 credential_root, credential_depth, frozen and mint_enabled.
                 Omitted controls retain the current values.
  asset.adminPrepare same params as asset.admin; return exact action without submit
  asset.adminSubmit {"ws_url":"...","action":"<returned lowercase action hex>"}

Public development setup configures a fresh disposable network; it never changes
the registry of a running network.
Runtime credential and freeze changes require the current asset administrator
proof. Asset minting requires its separate issuer authority. Asset authorities
have no native HGN administration rights.
"#;

#[derive(Deserialize)]
struct Connection {
    ws_url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OnlineJournalParams {
    ws_url: String,
    reservation_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminParams {
    ws_url: String,
    asset_id: u32,
    admin_secret: [u64; 7],
    expires_at: u64,
    action_intent: [u64; 7],
    #[serde(default)]
    credential_root: Option<[u64; 7]>,
    #[serde(default)]
    credential_depth: Option<u8>,
    #[serde(default)]
    frozen: Option<bool>,
    #[serde(default)]
    mint_enabled: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminSubmitParams {
    ws_url: String,
    action: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Operation {
    Mint,
    Transfer,
    Burn,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialParams {
    index: u32,
    expires_at: u64,
    siblings: Vec<[u64; 7]>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BranchParams {
    enabled: u64,
    authority: [u64; 7],
    not_before: u64,
    hash_required: u64,
    hashlock: [u8; 32],
    release_secret: u64,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyParams {
    nullifier_key: [u64; 5],
    branches: [BranchParams; 2],
}

impl PolicyParams {
    fn into_relation(self) -> transaction_circuit::private_spend::BoundedPolicy {
        transaction_circuit::private_spend::BoundedPolicy {
            nullifier_key: self.nullifier_key,
            branches: self.branches.map(|branch| {
                transaction_circuit::private_spend::PolicyBranch {
                    enabled: branch.enabled,
                    authority: branch.authority,
                    not_before: branch.not_before,
                    hash_required: branch.hash_required,
                    hashlock: branch.hashlock,
                    release_secret: branch.release_secret,
                }
            }),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PolicyOpeningParams {
    create: u64,
    spend: u64,
    input: PolicyParams,
    output: PolicyParams,
    selected: [u64; 2],
    secret: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareParams {
    ws_url: String,
    asset_id: u32,
    operation: Operation,
    amount: u64,
    fee: u64,
    recipient: String,
    #[serde(default)]
    asset_change_index: u32,
    #[serde(default)]
    native_change_index: u32,
    credentials: [CredentialParams; 3],
    #[serde(default)]
    issuer_secret: [u64; 7],
    #[serde(default)]
    policy: PolicyOpeningParams,
    #[serde(default)]
    input_position: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncParams {
    ws_url: String,
    manifest: String,
    expected_genesis: String,
}

#[cfg(feature = "development-assets")]
async fn sync(store: &WalletStore, client: &NodeRpcClient, params: Value) -> WalletdResult<Value> {
    use std::io::Read;
    let params: SyncParams = serde_json::from_value(params)
        .map_err(|error| WalletdError::new(WalletdErrorCode::InvalidParams, error.to_string()))?;
    let expected = hex::decode(&params.expected_genesis).map_err(WalletdError::internal)?;
    if hex::encode(&expected) != params.expected_genesis {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "expected_genesis requires lowercase hexadecimal without a prefix",
        ));
    }
    let expected: [u8; 32] = expected.try_into().map_err(|_| {
        WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "expected_genesis requires 32 bytes",
        )
    })?;
    let mut manifest = Vec::new();
    std::fs::File::open(&params.manifest)
        .map_err(WalletdError::internal)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut manifest)
        .map_err(WalletdError::internal)?;
    if manifest.len() > 64 * 1024 {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "asset Development manifest exceeds 64 KiB",
        ));
    }
    let config = client.node_config().await.map_err(operation_error)?;
    let parameters = client
        .private_spend_parameters()
        .await
        .map_err(operation_error)?;
    let genesis = client
        .block_hash(0)
        .await
        .map_err(operation_error)?
        .ok_or_else(|| {
            WalletdError::new(WalletdErrorCode::SyncFailed, "node genesis unavailable")
        })?;
    let tip = client.latest_block().await.map_err(operation_error)?;
    let authority =
        wallet::private_spend_rpc::DevelopmentPrivateSpendAuthority::from_verified_node(
            &manifest,
            expected,
            genesis,
            &config,
            &parameters,
            tip.height,
        )
        .map_err(operation_error)?;
    let asset_parameters = client.asset_parameters().await.map_err(operation_error)?;
    AssetNodeContext::from_readback(authority.context(), &config, &asset_parameters)
        .map_err(operation_error)?;
    store
        .initialize_private_spend_development_context(&authority)
        .map_err(operation_error)?;
    let mut detached = 0u64;
    loop {
        let tip = store.poseidon2_v8_tip().map_err(operation_error)?;
        if client
            .block_hash(tip.height)
            .await
            .map_err(operation_error)?
            == Some(tip.block_hash)
        {
            break;
        }
        let parent = tip.height.checked_sub(1).ok_or_else(|| {
            WalletdError::new(WalletdErrorCode::SyncFailed, "node genesis changed")
        })?;
        let hash = store
            .poseidon2_v8_canonical_hash(parent)
            .map_err(operation_error)?
            .ok_or_else(|| {
                WalletdError::new(
                    WalletdErrorCode::SyncFailed,
                    "wallet rollback checkpoint absent",
                )
            })?;
        store
            .rollback_poseidon2_v8_to(parent, hash)
            .map_err(operation_error)?;
        detached += 1;
    }
    let end = client.latest_block().await.map_err(operation_error)?.height;
    let start = store.poseidon2_v8_tip().map_err(operation_error)?.height;
    for height in start.saturating_add(1)..=end {
        let block = client
            .canonical_block_actions(height)
            .await
            .map_err(operation_error)?
            .ok_or_else(|| {
                WalletdError::new(WalletdErrorCode::SyncFailed, "canonical block unavailable")
            })?;
        store
            .apply_private_spend_development_block(&block, &authority)
            .map_err(operation_error)?;
    }
    let tip = store.poseidon2_v8_tip().map_err(operation_error)?;
    Ok(
        serde_json::json!({"height":tip.height,"block_hash":hex::encode(tip.block_hash),
        "blocks_applied":end.saturating_sub(start),"blocks_detached":detached,
        "asset_balances":store.asset_spend_balances().map_err(operation_error)?}),
    )
}

#[cfg(not(feature = "development-assets"))]
async fn sync(_: &WalletStore, _: &NodeRpcClient, _: Value) -> WalletdResult<Value> {
    Err(WalletdError::new(
        WalletdErrorCode::UnknownMethod,
        "asset.sync requires a walletd build with the development-assets feature",
    ))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressParams {
    #[serde(default)]
    index: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalParams {
    reservation_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupParams {
    rows: Vec<String>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PublicRowConfig {
    active: bool,
    enabled_at: u64,
    retired_at: Option<u64>,
    min_collateral_ratio_ppm: u32,
    max_mint_per_epoch: u64,
    oracle_submitted_at: u64,
    oracle_max_age: u64,
    oracle_price_numerator: u32,
    oracle_price_denominator: u32,
    collateral_amount: u64,
    attestation_created_at: u64,
    attestation_disputed: bool,
    attestation_present: bool,
    attestation_max_age: u64,
    oracle_authority_commitment: [u64; 7],
    attestation_authority_commitment: [u64; 7],
    collateral_asset_id: u32,
    collateral_decimals: u8,
    collateral_scale: u64,
    locked_collateral_commitment: [u64; 7],
}

impl Default for PublicRowConfig {
    fn default() -> Self {
        Self {
            active: true,
            enabled_at: 1,
            retired_at: None,
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000_000,
            oracle_submitted_at: 0,
            oracle_max_age: 1_000_000,
            oracle_price_numerator: 2,
            oracle_price_denominator: 1,
            collateral_amount: 1_000_000,
            attestation_created_at: 0,
            attestation_disputed: false,
            attestation_present: true,
            attestation_max_age: 1_000_000,
            oracle_authority_commitment: [51; 7],
            attestation_authority_commitment: [61; 7],
            collateral_asset_id: 0,
            collateral_decimals: 6,
            collateral_scale: 1_000_000,
            locked_collateral_commitment: [71; 7],
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RowParams {
    disposable: bool,
    asset_id: u32,
    policy_version: u32,
    issuer_secret: [u64; 7],
    admin_secret: [u64; 7],
    credential_root: [u64; 7],
    credential_depth: u8,
    #[serde(default)]
    config: PublicRowConfig,
}

fn row(params: Value) -> WalletdResult<Value> {
    use transaction_circuit::asset_spend_v1_admission as admission;
    let params: RowParams = serde_json::from_value(params)
        .map_err(|error| WalletdError::new(WalletdErrorCode::InvalidParams, error.to_string()))?;
    if !params.disposable {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "asset.row is only for explicitly disposable Development authorities",
        ));
    }
    let issuer = transaction_circuit::asset_spend_v1::issuer_commitment(
        params.asset_id,
        params.policy_version,
        params.issuer_secret,
    )
    .map_err(WalletdError::internal)?;
    let administrator = transaction_circuit::asset_policy_admin_v1::policy_admin_commitment(
        params.asset_id,
        params.admin_secret,
    )
    .map_err(WalletdError::internal)?;
    let config = params.config;
    let mut fields = vec![
        u64::from(params.asset_id),
        u64::from(params.policy_version),
        u64::from(config.active),
        config.enabled_at,
        u64::from(config.retired_at.is_some()),
        config.retired_at.unwrap_or(0),
    ];
    fields.extend(issuer);
    fields.extend([
        u64::from(config.min_collateral_ratio_ppm),
        config.max_mint_per_epoch,
        config.oracle_submitted_at,
        config.oracle_max_age,
        u64::from(config.oracle_price_numerator),
        u64::from(config.oracle_price_denominator),
        config.collateral_amount,
        config.attestation_created_at,
        u64::from(config.attestation_disputed),
        u64::from(config.attestation_present),
        config.attestation_max_age,
    ]);
    fields.extend(administrator);
    fields.extend(config.oracle_authority_commitment);
    fields.extend(config.attestation_authority_commitment);
    fields.extend([
        u64::from(config.collateral_asset_id),
        u64::from(config.collateral_decimals),
        config.collateral_scale,
    ]);
    fields.extend(config.locked_collateral_commitment);
    fields.extend([0; 4]); // Genesis has no allocation, supply or accounting history.
    fields.extend(params.credential_root);
    fields.extend([u64::from(params.credential_depth), 0, 1]);
    let bytes: Vec<_> = fields.into_iter().flat_map(u64::to_le_bytes).collect();
    let row = admission::decode_asset_policy_row(&bytes).map_err(WalletdError::internal)?;
    let encoded =
        hex::encode(admission::encode_asset_policy_row(&row).map_err(WalletdError::internal)?);
    let descriptor = setup(serde_json::json!({"rows":[encoded.clone()]}))?;
    Ok(serde_json::json!({"row":encoded,"issuer_commitment":issuer,
        "policy_admin_commitment":administrator,"descriptor":descriptor,
        "development_only":true,"production_authorized":false}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialEntryParams {
    index: u32,
    recipient: String,
    #[serde(default)]
    owner: Option<[u64; 7]>,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialTreeParams {
    asset_id: u32,
    policy_version: u32,
    depth: u8,
    entries: Vec<CredentialEntryParams>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyOwnerParams {
    chain_id: String,
    asset_id: u32,
    policy: PolicyParams,
}

fn public_owner(address: &wallet::ShieldedAddress) -> WalletdResult<[u64; 7]> {
    if address.version != wallet::address::POSEIDON2_V8_ADDRESS_VERSION {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "asset credentials require the current full-authority address",
        ));
    }
    let mut owner = [0; 7];
    for (word, bytes) in owner.iter_mut().zip(
        address
            .pk_auth
            .chunks_exact(8)
            .chain(address.pk_auth_extension.chunks_exact(8)),
    ) {
        *word = u64::from_le_bytes(bytes.try_into().expect("eight bytes"));
    }
    Ok(owner)
}

fn policy_owner(params: Value) -> WalletdResult<Value> {
    let params: PolicyOwnerParams = serde_json::from_value(params)
        .map_err(|error| WalletdError::new(WalletdErrorCode::InvalidParams, error.to_string()))?;
    let chain = hex::decode(&params.chain_id).map_err(WalletdError::internal)?;
    if hex::encode(&chain) != params.chain_id {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "chain_id requires canonical lowercase hexadecimal",
        ));
    }
    let chain: [u8; 32] = chain.try_into().map_err(|_| {
        WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "chain_id requires 32 bytes",
        )
    })?;
    let owner = params
        .policy
        .into_relation()
        .owner(chain, u64::from(params.asset_id))
        .map_err(WalletdError::internal)?;
    Ok(serde_json::json!({"owner":owner}))
}

fn credentials(params: Value) -> WalletdResult<Value> {
    use std::collections::{BTreeMap, BTreeSet};
    use transaction_circuit::asset_spend_v1 as relation;
    let params: CredentialTreeParams = serde_json::from_value(params)
        .map_err(|error| WalletdError::new(WalletdErrorCode::InvalidParams, error.to_string()))?;
    let defaults =
        relation::credential_default_nodes(params.depth).map_err(WalletdError::internal)?;
    let capacity = 1usize << params.depth;
    if params.entries.is_empty() || params.entries.len() > capacity {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "credential entries must fit the selected supported depth",
        ));
    }
    let mut leaves = BTreeMap::new();
    let mut parsed = Vec::with_capacity(params.entries.len());
    for entry in params.entries {
        if entry.index as usize >= capacity || leaves.contains_key(&entry.index) {
            return Err(WalletdError::new(
                WalletdErrorCode::InvalidParams,
                "credential positions must be distinct and fit the selected depth",
            ));
        }
        let recipient =
            wallet::ShieldedAddress::decode(&entry.recipient).map_err(operation_error)?;
        let authority = public_owner(&recipient)?;
        let owner = entry.owner.unwrap_or(authority);
        let recipient_key = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes(
            recipient.pk_recipient).map_err(|error| WalletdError::new(
                WalletdErrorCode::InvalidParams, format!("asset recipient field encoding: {error:?}")))?;
        let leaf = relation::credential_leaf(
            params.asset_id,
            params.policy_version,
            recipient_key,
            owner,
            entry.expires_at,
        )
        .map_err(WalletdError::internal)?;
        leaves.insert(entry.index, leaf);
        parsed.push((entry, owner, leaf));
    }
    let mut layers = vec![leaves];
    for level in 0..usize::from(params.depth) {
        let current = &layers[level];
        let parents: BTreeSet<_> = current.keys().map(|index| index >> 1).collect();
        let mut next = BTreeMap::new();
        for parent in parents {
            let left = current
                .get(&(parent * 2))
                .copied()
                .unwrap_or(defaults[level]);
            let right = current
                .get(&(parent * 2 + 1))
                .copied()
                .unwrap_or(defaults[level]);
            next.insert(
                parent,
                relation::credential_node(level, left, right).map_err(WalletdError::internal)?,
            );
        }
        layers.push(next);
    }
    let root = layers[usize::from(params.depth)]
        .get(&0)
        .copied()
        .unwrap_or(defaults[usize::from(params.depth)]);
    let mut entries = Vec::with_capacity(parsed.len());
    for (entry, owner, leaf) in parsed {
        let siblings: Vec<_> = (0..usize::from(params.depth))
            .map(|level| {
                layers[level]
                    .get(&((entry.index >> level) ^ 1))
                    .copied()
                    .unwrap_or(defaults[level])
            })
            .collect();
        if relation::credential_root(leaf, entry.index, &siblings)
            .map_err(WalletdError::internal)?
            != root
        {
            return Err(WalletdError::new(
                WalletdErrorCode::InternalError,
                "credential path root mismatch",
            ));
        }
        entries.push(
            serde_json::json!({"recipient":entry.recipient,"owner":owner,"leaf":leaf,
            "witness":{"index":entry.index,"expires_at":entry.expires_at,"siblings":siblings}}),
        );
    }
    Ok(
        serde_json::json!({"asset_id":params.asset_id,"policy_version":params.policy_version,
        "credential_root":root,"credential_depth":params.depth,"entries":entries}),
    )
}

fn setup(params: Value) -> WalletdResult<Value> {
    use transaction_circuit::asset_spend_v1_admission as admission;
    let params: SetupParams = serde_json::from_value(params)
        .map_err(|error| WalletdError::new(WalletdErrorCode::InvalidParams, error.to_string()))?;
    if !(1..=16).contains(&params.rows.len()) {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "development setup requires 1 through 16 canonical public rows",
        ));
    }
    let mut rows = Vec::with_capacity(params.rows.len());
    for encoded in &params.rows {
        let bytes = hex::decode(encoded).map_err(WalletdError::internal)?;
        if hex::encode(&bytes) != *encoded {
            return Err(WalletdError::new(
                WalletdErrorCode::InvalidParams,
                "asset setup rows require canonical lowercase hexadecimal without a prefix",
            ));
        }
        let row = admission::decode_asset_policy_row(&bytes).map_err(WalletdError::internal)?;
        if row.counters.epoch_id != 0
            || row.counters.minted_in_epoch != 0
            || row.counters.total_debt != 0
            || row.counters.sequence != 0
            || rows.last().is_some_and(
                |previous: &transaction_circuit::asset_registry_v1::AssetPolicyV1| {
                    previous.config.asset_id >= row.config.asset_id
                },
            )
        {
            return Err(WalletdError::new(
                WalletdErrorCode::InvalidParams,
                "development genesis rows require distinct sorted asset ids and zero supply/counters",
            ));
        }
        rows.push(row);
    }
    let registry =
        transaction_circuit::asset_registry_v1::AssetRegistryV1::from_rows([1; 32], 0, &rows)
            .map_err(WalletdError::internal)?;
    Ok(serde_json::json!({
        "relation_digest": hex::encode(transaction_circuit::asset_spend_v1::relation_digest()),
        "admin_relation_digest": hex::encode(transaction_circuit::asset_policy_admin_v1::relation_digest()),
        "native_transport_identity": admission::NATIVE_SPEND_IDENTITY,
        "native_admin_transport_identity": admission::NATIVE_ADMIN_IDENTITY,
        "allowed_profiles": [[0,4],[0,8],[0,16],[1,4],[1,8]],
        "max_proof_bytes": admission::NATIVE_INNER_PROOF_CAP_BYTES,
        "max_actions_per_block": 1,
        "initial_registry_root": registry.root().map(|word| word.as_canonical_u64()),
        "initial_rows": params.rows,
    }))
}

fn journal_id(params: Value) -> WalletdResult<[u8; 32]> {
    let params: JournalParams = serde_json::from_value(params)
        .map_err(|error| WalletdError::new(WalletdErrorCode::InvalidParams, error.to_string()))?;
    let bytes = hex::decode(&params.reservation_id).map_err(|_| {
        WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "reservation_id must be 32 bytes of lowercase hexadecimal",
        )
    })?;
    if hex::encode(&bytes) != params.reservation_id {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "reservation_id must be canonical lowercase hexadecimal without a prefix",
        ));
    }
    bytes.try_into().map_err(|_| {
        WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "reservation_id must contain exactly 32 bytes",
        )
    })
}

fn require_empty(params: Value) -> WalletdResult<()> {
    serde_json::from_value::<EmptyParams>(params)
        .map(|_| ())
        .map_err(|error| WalletdError::new(WalletdErrorCode::InvalidParams, error.to_string()))
}

async fn current_snapshot(
    store: &WalletStore,
    client: &NodeRpcClient,
    asset_id: Option<u32>,
    reference_hash: [u8; 32],
) -> WalletdResult<(AssetNodeContext, Value)> {
    let launch = store.launch_context().map_err(operation_error)?;
    let config = client.node_config().await.map_err(operation_error)?;
    let snapshot = client
        .asset_snapshot(asset_id, Some(reference_hash))
        .await
        .map_err(operation_error)?;
    let node =
        AssetNodeContext::from_snapshot(launch, &config, &snapshot).map_err(operation_error)?;
    // The requested hash is a selector, never authority. The response must be
    // independently attached to the wallet's canonical mirror at H.
    if node.current().reference_parent_hash != reference_hash {
        return Err(operation_error(WalletError::InvalidState(
            "asset snapshot selected a different reference",
        )));
    }
    node.require_wallet_tip(store).map_err(operation_error)?;
    Ok((node, snapshot["registry"].clone()))
}

async fn prepare(
    store: &WalletStore,
    client: &NodeRpcClient,
    params: Value,
) -> WalletdResult<Value> {
    let params: PrepareParams = serde_json::from_value(params)
        .map_err(|error| WalletdError::new(WalletdErrorCode::InvalidParams, error.to_string()))?;
    let reference = store.poseidon2_v8_tip().map_err(operation_error)?;
    let (node, registry) =
        current_snapshot(store, client, Some(params.asset_id), reference.block_hash).await?;
    let authenticated =
        AuthenticatedAssetPolicy::from_registry_readback(&node, &registry, params.asset_id)
            .map_err(operation_error)?;
    let policy = params.policy;
    transaction_circuit::asset_spend_v1_admission::spend_profile_upper_bound_v1(
        u8::from(policy.create == 1 || policy.spend == 1),
        authenticated.row().credential_depth,
    )
    .map_err(WalletdError::internal)?;
    let request = wallet::asset_spend_v1::AssetSpendConstruction {
        asset_id: params.asset_id,
        operation: match params.operation {
            Operation::Transfer => transaction_circuit::asset_spend_v1::TRANSFER,
            Operation::Mint => transaction_circuit::asset_spend_v1::MINT,
            Operation::Burn => transaction_circuit::asset_spend_v1::BURN,
        },
        amount: params.amount,
        fee: params.fee,
        recipient: wallet::ShieldedAddress::decode(&params.recipient).map_err(operation_error)?,
        asset_change_index: params.asset_change_index,
        native_change_index: params.native_change_index,
        credentials: params.credentials.map(|credential| {
            transaction_circuit::asset_spend_v1::AssetCredentialWitness {
                index: credential.index,
                expires_at: credential.expires_at,
                siblings: credential.siblings,
            }
        }),
        issuer_secret: params.issuer_secret,
        policy: transaction_circuit::private_spend::PrivatePolicyOpening {
            create: policy.create,
            spend: policy.spend,
            input: policy.input.into_relation(),
            output: policy.output.into_relation(),
            selected: policy.selected,
            secret: policy.secret,
        },
        input_position: params.input_position,
    };
    let prepared = wallet::asset_spend_v1::prepare_persistent_asset_spend_os(
        store,
        &node,
        &authenticated,
        request,
    )
    .map_err(operation_error)?;
    let id = prepared.reservation_id();
    let body = prepared.prove_and_retain(store).map_err(operation_error)?;
    let decoded =
        transaction_circuit::asset_spend_v1_wire::decode_native_asset_spend_action_v1(&body)
            .map_err(WalletdError::internal)?;
    Ok(serde_json::json!({
        "reservation_id": hex::encode(id),
        "action_bytes": body.len(),
        "proof_bytes": decoded.proof.len(),
        "public_statement": decoded.public.words().to_vec(),
        "status": "candidate",
        "reference_parent_height": decoded.public.parent_height,
        "reference_parent_hash": hex::encode(decoded.public.reference_parent_hash),
        "last_valid_parent_height": wallet::asset_spend_rpc::reference_last_parent(decoded.public.parent_height).map_err(operation_error)?,
    }))
}

async fn submit(
    store: &WalletStore,
    client: &NodeRpcClient,
    params: Value,
) -> WalletdResult<Value> {
    let params: OnlineJournalParams = serde_json::from_value(params)
        .map_err(|error| WalletdError::new(WalletdErrorCode::InvalidParams, error.to_string()))?;
    let id = journal_id(serde_json::json!({"reservation_id": params.reservation_id}))?;
    let body = store.asset_spend_candidate(id).map_err(operation_error)?;
    let decoded =
        transaction_circuit::asset_spend_v1_wire::decode_native_asset_spend_action_v1(&body)
            .map_err(WalletdError::internal)?;
    let (node, registry) = current_snapshot(
        store,
        client,
        Some(decoded.public.asset_id),
        decoded.public.reference_parent_hash,
    )
    .await?;
    let policy =
        AuthenticatedAssetPolicy::from_registry_readback(&node, &registry, decoded.public.asset_id)
            .map_err(operation_error)?;
    let request = wallet::asset_spend_rpc::prepare_spend_request_with_policy(&node, &policy, &body)
        .map_err(operation_error)?;
    let durable = store
        .begin_asset_spend_submission(node.launch_context(), id)
        .map_err(operation_error)?;
    if durable != body {
        return Err(WalletdError::new(
            WalletdErrorCode::TransactionFailed,
            "durable asset candidate changed before submission",
        ));
    }
    let action_id = client
        .submit_native_asset_request(request)
        .await
        .map_err(operation_error)?;
    store
        .mark_asset_spend_submitted(node.launch_context(), id, action_id)
        .map_err(operation_error)?;
    Ok(serde_json::json!({
        "reservation_id": hex::encode(id),
        "action_id": hex::encode(action_id),
        "status": "submitted",
    }))
}

async fn prepare_admin(
    store: &WalletStore,
    client: &NodeRpcClient,
    params: Value,
) -> WalletdResult<Vec<u8>> {
    use transaction_circuit::{
        asset_policy_admin_v1 as admin, asset_registry_v1::AssetRegistryV1,
        asset_spend_v1_admission as admission,
    };
    let params: AdminParams = serde_json::from_value(params)
        .map_err(|error| WalletdError::new(WalletdErrorCode::InvalidParams, error.to_string()))?;
    let reference = store.poseidon2_v8_tip().map_err(operation_error)?;
    let (node, registry) = current_snapshot(store, client, None, reference.block_hash).await?;
    if params.expires_at < node.application().parent_height {
        return Err(operation_error(WalletError::InvalidState(
            "asset admin expired at current parent",
        )));
    }
    let entries = registry["rows"].as_array().ok_or_else(|| {
        WalletdError::new(WalletdErrorCode::TransactionFailed, "registry rows missing")
    })?;
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        let asset_id: u32 = entry["asset_id"]
            .as_u64()
            .and_then(|id| id.try_into().ok())
            .ok_or_else(|| {
                WalletdError::new(
                    WalletdErrorCode::TransactionFailed,
                    "registry asset id invalid",
                )
            })?;
        rows.push(
            *AuthenticatedAssetPolicy::from_registry_readback(&node, &registry, asset_id)
                .map_err(operation_error)?
                .row(),
        );
    }
    let current = node.current();
    let registry = AssetRegistryV1::from_rows(current.chain_id, current.parent_height, &rows)
        .map_err(WalletdError::internal)?;
    if registry.root().map(|word| word.as_canonical_u64()) != current.registry_root {
        return Err(WalletdError::new(
            WalletdErrorCode::TransactionFailed,
            "complete authenticated registry differs from node root",
        ));
    }
    let row = registry
        .row(params.asset_id)
        .map_err(WalletdError::internal)?;
    // The canonical row codec supplies field conversion and rejects aliases.
    // Only its final ten control words may change; prepare_controls_update
    // independently preserves the complete issuer configuration and counters.
    let mut updated = admission::encode_asset_policy_row(row).map_err(WalletdError::internal)?;
    let root = params
        .credential_root
        .unwrap_or_else(|| row.credential_root.map(|word| word.as_canonical_u64()));
    let mut controls = root.to_vec();
    controls.extend([
        u64::from(params.credential_depth.unwrap_or(row.credential_depth)),
        u64::from(params.frozen.unwrap_or(row.frozen)),
        u64::from(params.mint_enabled.unwrap_or(row.mint_enabled)),
    ]);
    let controls_start = admission::ASSET_POLICY_ROW_BYTES_V1 - controls.len() * 8;
    for (bytes, word) in updated[controls_start..].chunks_exact_mut(8).zip(controls) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    let controls = admission::decode_asset_policy_row(&updated)
        .map_err(WalletdError::internal)?
        .controls();
    let prepared = registry
        .prepare_controls_update(registry.context(), params.asset_id, controls)
        .map_err(WalletdError::internal)?;
    let public = admin::PolicyAdminPublicV1::from_prepared(
        &prepared,
        current.reference_parent_hash,
        params.expires_at,
        params.action_intent,
    )
    .map_err(WalletdError::internal)?;
    let witness = admin::PolicyAdminWitnessV1 {
        secret: params.admin_secret,
    };
    let proof = admin::prove_candidate(&public, &witness).map_err(WalletdError::internal)?;
    admin::verify_candidate(&public, &proof).map_err(WalletdError::internal)?;
    public
        .verify_prepared(&prepared, current.reference_parent_hash)
        .map_err(WalletdError::internal)?;
    transaction_circuit::asset_spend_v1_wire::encode_native_asset_admin_action_v1(&public, &proof)
        .map_err(WalletdError::internal)
}

fn admin_result(body: &[u8]) -> WalletdResult<Value> {
    let decoded =
        transaction_circuit::asset_spend_v1_wire::decode_native_asset_admin_action_v1(body)
            .map_err(WalletdError::internal)?;
    Ok(
        serde_json::json!({"action":hex::encode(body),"action_bytes":body.len(),
        "proof_bytes":decoded.proof.len(),"administrator_action_id":hex::encode(decoded.public.action_id()),
        "public_statement":decoded.public.words().to_vec()}),
    )
}

async fn submit_admin_body(
    store: &WalletStore,
    client: &NodeRpcClient,
    body: &[u8],
) -> WalletdResult<Value> {
    let decoded =
        transaction_circuit::asset_spend_v1_wire::decode_native_asset_admin_action_v1(body)
            .map_err(WalletdError::internal)?;
    let (node, _) =
        current_snapshot(store, client, None, decoded.public.reference_parent_hash).await?;
    transaction_circuit::asset_policy_admin_v1::verify_candidate(&decoded.public, decoded.proof)
        .map_err(WalletdError::internal)?;
    let request =
        wallet::asset_spend_rpc::prepare_admin_request(&node, body).map_err(operation_error)?;
    let action_id = client
        .submit_native_asset_request(request)
        .await
        .map_err(operation_error)?;
    let mut result = admin_result(body)?;
    result["action_id"] = Value::String(hex::encode(action_id));
    result["status"] = Value::String("submitted".into());
    Ok(result)
}

fn operation_error(error: WalletError) -> WalletdError {
    let code = match &error {
        WalletError::WatchOnly => WalletdErrorCode::WatchOnly,
        WalletError::InvalidArgument(_) | WalletError::AddressEncoding(_) => {
            WalletdErrorCode::InvalidParams
        }
        WalletError::Rpc(_) | WalletError::Http(_) => WalletdErrorCode::RpcConnectionFailed,
        WalletError::StoreBusy => WalletdErrorCode::StoreLocked,
        _ => WalletdErrorCode::TransactionFailed,
    };
    WalletdError::new(code, error.to_string())
}

fn address(store: &WalletStore, params: Value) -> WalletdResult<Value> {
    let params: AddressParams = serde_json::from_value(params)
        .map_err(|error| WalletdError::new(WalletdErrorCode::InvalidParams, error.to_string()))?;
    let address = store
        .private_spend_address(params.index)
        .map_err(operation_error)?;
    Ok(serde_json::json!({
        "index": params.index,
        "address": address.encode().map_err(WalletdError::internal)?,
        "recipient_key": address.pk_recipient.chunks_exact(8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
            .collect::<Vec<_>>(),
        "authority": address.pk_auth.chunks_exact(8)
            .chain(address.pk_auth_extension.chunks_exact(8))
            .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
            .collect::<Vec<_>>(),
    }))
}

pub(crate) fn handle(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    method: &str,
    params: Value,
) -> WalletdResult<Value> {
    if method == "asset.help" {
        return Ok(serde_json::json!({"help": HELP}));
    }
    if method == "asset.address" {
        return address(&store, params);
    }
    if method == "asset.setup" {
        return setup(params);
    }
    if method == "asset.row" {
        return row(params);
    }
    if method == "asset.credentials" {
        return credentials(params);
    }
    if method == "asset.policyOwner" {
        return policy_owner(params);
    }
    match method {
        "asset.balances" => {
            require_empty(params)?;
            return crate::to_json(store.asset_spend_balances().map_err(operation_error)?);
        }
        "asset.notes" => {
            require_empty(params)?;
            return crate::to_json(store.asset_spend_notes().map_err(operation_error)?);
        }
        "asset.journal" => {
            require_empty(params)?;
            return crate::to_json(store.asset_spend_attempts().map_err(operation_error)?);
        }
        "asset.export" => {
            let id = journal_id(params)?;
            let bytes = store.asset_spend_candidate(id).map_err(operation_error)?;
            return Ok(serde_json::json!({
                "reservation_id": hex::encode(id),
                "encoding": "hex",
                "action": hex::encode(&bytes),
                "action_bytes": bytes.len(),
            }));
        }
        "asset.abandon" => {
            let id = journal_id(params)?;
            let context = store.launch_context().map_err(operation_error)?;
            store
                .abandon_asset_spend(context, id)
                .map_err(operation_error)?;
            return Ok(serde_json::json!({"reservation_id": hex::encode(id)}));
        }
        _ => {}
    }
    // Launch builds expose the retained offline inspection/setup helpers, but
    // cannot start asset sync, reservations, proof work, or submission. A
    // Development build must still pass current_snapshot's exact pinned
    // manifest/source readback before preparation or submission below.
    #[cfg(not(feature = "development-assets"))]
    if matches!(
        method,
        "asset.sync"
            | "asset.prepare"
            | "asset.submit"
            | "asset.adminPrepare"
            | "asset.admin"
            | "asset.adminSubmit"
    ) {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidRequest,
            "asset mutations require development-assets and an authenticated Development network",
        ));
    }
    let connection: Connection = serde_json::from_value(params.clone()).map_err(|error| {
        WalletdError::new(
            WalletdErrorCode::InvalidParams,
            format!("asset operation requires ws_url: {error}"),
        )
    })?;
    runtime.block_on(async {
        let client = NodeRpcClient::connect(&connection.ws_url)
            .await
            .map_err(|error| {
                WalletdError::new(WalletdErrorCode::RpcConnectionFailed, error.to_string())
            })?;
        match method {
            "asset.sync" => sync(&store, &client, params).await,
            "asset.prepare" => prepare(&store, &client, params).await,
            "asset.submit" => submit(&store, &client, params).await,
            "asset.adminPrepare" => {
                let body = prepare_admin(&store, &client, params).await?;
                admin_result(&body)
            }
            "asset.admin" => {
                let body = prepare_admin(&store, &client, params).await?;
                submit_admin_body(&store, &client, &body).await
            }
            "asset.adminSubmit" => {
                let params: AdminSubmitParams =
                    serde_json::from_value(params).map_err(|error| {
                        WalletdError::new(WalletdErrorCode::InvalidParams, error.to_string())
                    })?;
                let body = hex::decode(&params.action).map_err(WalletdError::internal)?;
                if hex::encode(&body) != params.action {
                    return Err(WalletdError::new(
                        WalletdErrorCode::InvalidParams,
                        "administrator action requires canonical lowercase hexadecimal",
                    ));
                }
                submit_admin_body(&store, &client, &body).await
            }
            _ => Err(WalletdError::new(
                WalletdErrorCode::UnknownMethod,
                format!("unknown asset method {method}"),
            )),
        }
    })
}
