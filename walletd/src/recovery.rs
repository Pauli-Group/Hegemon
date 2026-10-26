//! Explicit operator requests for the fresh, genesis-opted Development route.
//! No request flag grants authority: current rows, witnesses and real proofs do.
use crate::{WalletdError, WalletdErrorCode, WalletdResult};
use serde_json::Value;
use std::sync::Arc;
use wallet::WalletStore;

pub const HELP: &str = r#"Recoverable assets (build walletd with --features development-assets):
  recovery.roles {archive_key?:"<32-byte lowerhex>",delegate_secret?:[7 fields]}
    Return public archive/delegate commitments only. Use independent operator keys.
  recovery.setup {rows:[{asset_row:"<552-byte lowerhex>",stable_policy_id:[7 fields],
    archive_key_commitment:[7 fields],delegate_action_commitment:[7 fields],
    maximum_transfer:true,maximum_burn:true,transfer:true,burn:true,revoked:false}]}
    Return public --development-recovery-json for fresh zero-issued genesis only.
  recovery.notes {} / recovery.journal {}  public local recovery/fee positions and holds
  recovery.info {ws_url,manifest,expected_genesis,asset_id?,position?}
    Authenticated selected descriptor/current rows and optional sparse32 freeze path.
  recovery.inspectInput {ws_url,manifest,expected_genesis,asset_id,position,
    input_action_file,input_output:0,archive_key:"<32-byte lowerhex>"}
    Decrypt locally; return only canonical public value/CM/NF, never shared-NF material.
  recovery.prepare {ws_url,manifest,expected_genesis,expected_parent_hash,expected_epoch,
    confirm:true,asset_id,operation:"mint|transfer|burn",route:"mint|holder|delegate",
    amount,fee,fee_position,recipient,change_recipient?,native_change_index:0,
    archive_key?:"<32-byte lowerhex>",archive_provider?:{executable,args,timeout_seconds:600},
    credentials:[{index,expires_at,siblings},...],
    input_position?,input_action_file?,input_output?,delegate_secret?,
    delegate_credential_recipient?,issuer_secret?}
    Mint needs issuer_secret. Holder uses this wallet's recovered input. Delegate
    needs current delegate_secret/address plus published carrier file and slot0/1.
    Both output credentials (even zero-valued change) and current actor are required.
    Exactly one archive_key OR archive_provider is required. Holder/mint may use a
    cooperating provider without receiving its archive key; delegate input decryption
    currently requires local archive_key. Reserves NFs before FIVE real components.
  recovery.export {reservation_id,action_file}  create new exact binary action file
  recovery.submit {ws_url,manifest,expected_genesis,reservation_id,confirm:true}
    Durably mark submission intent; submit the retained bytes. Uncertainty keeps holds.
  recovery.abandon {reservation_id,confirm:true}  existing safe stale tombstone rules
  recovery.adminPrepare {ws_url,manifest,expected_genesis,asset_id,expected_parent_hash,
    expected_epoch,confirm:true,operation:"freeze|unfreeze|rotate|revoke|enable|powers",
    admin_secret:[7 fields],expires_at,action_intent:[7 fresh fields],action_file,
    position?,new_delegate_commitment?,powers?:{transfer:true,burn:true}}
    Freeze key is canonical note position32, not a wallet/subject key. Rotate preserves
    revoked status; enable is explicit. Powers remain within genesis maximums.
  recovery.adminSubmit {ws_url,manifest,expected_genesis,action_file,
    expected_action_id:"<32-byte lowerhex>",confirm:true}
    Verify actual proof and exact CURRENT parent/row before typed action19 submission.
Use asset.sync first; asset.credentials and proof-backed asset.admin still update
current credential roots and whole-asset freeze. Old asset.prepare is not recovery.
No recovery of HGN, runtime registration, retrofit or archive-key rotation exists.
Archive worker (development-assets, Unix, no wallet/store/passphrase/network):
  walletd --recovery-archive-worker --archive-key-file /private/mode0600/raw32.key
    Accepts one private versioned recovery.archiveProve request on stdin; emits one
    verified public capsule/proof response. Never supply action secrets to a provider.
See walletd/README.md for schemas, custody boundaries and archive availability.
"#;

pub fn handle(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    method: &str,
    params: Value,
) -> WalletdResult<Value> {
    if method == "recovery.help" {
        return Ok(serde_json::json!({"help":HELP}));
    }
    #[cfg(feature = "development-assets")]
    {
        enabled::handle(runtime, store, method, params)
    }
    #[cfg(not(feature = "development-assets"))]
    {
        let _ = (runtime, store, method, params);
        Err(WalletdError::new(
            WalletdErrorCode::InvalidRequest,
            "recovery methods require development-assets",
        ))
    }
}

#[cfg(feature = "development-assets")]
mod enabled {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;
    use std::io::{Read, Write};
    use transaction_circuit::{
        asset_recovery_admin_v1 as admin, asset_recovery_capsule_v1 as capsule,
        asset_recovery_spend_v1 as spend, asset_recovery_v1 as core,
        asset_recovery_wire_v1 as wire, asset_spend_v1 as old, private_spend as private,
        smallwood_poseidon2_v8_coinbase as coinbase,
    };
    use wallet::asset_recovery_v1::operator::{
        fresh_canonical_fields as fresh_fields, NoteOpening, Zeroize, Zeroizing,
    };
    use wallet::{
        asset_recovery_build_v1 as build,
        asset_recovery_v1::RecoveryNoteMaterialV1,
        asset_spend_rpc::{AssetNodeContext, AuthenticatedAssetPolicy},
        node_rpc::NodeRpcClient,
        private_spend_rpc::{
            validate_recovery_snapshot_readback, DevelopmentPrivateSpendAuthority,
        },
        ShieldedAddress,
    };
    type D = [u64; 7];
    fn err(s: impl Into<String>) -> WalletdError {
        WalletdError::new(WalletdErrorCode::InvalidParams, s)
    }
    fn op(e: impl std::fmt::Display) -> WalletdError {
        WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
    }
    fn core_op(e: core::AssetRecoveryErrorV1) -> WalletdError {
        // The core error is a payload-free public enum, not a secret witness.
        WalletdError::new(WalletdErrorCode::TransactionFailed, format!("{e:?}"))
    }
    fn powers_bits(powers: core::RecoveryPowersV1) -> u64 {
        u64::from(powers.transfer) | (u64::from(powers.burn) << 1)
    }
    fn parse<T: serde::de::DeserializeOwned>(v: Value) -> WalletdResult<T> {
        serde_json::from_value(v)
            .map_err(|_| err("invalid recovery parameters; see recovery help/schema"))
    }
    fn words<const N: usize>(v: &Value) -> WalletdResult<[u64; N]> {
        let v: Vec<u64> =
            serde_json::from_value(v.clone()).map_err(|_| err("public word shape"))?;
        let w: [u64; N] = v.try_into().map_err(|_| err("public word width"))?;
        if w.iter().any(|x| *x >= 0xffff_ffff_0000_0001) {
            return Err(err("noncanonical public word"));
        }
        Ok(w)
    }
    fn hex_bytes<const N: usize>(s: &str) -> WalletdResult<[u8; N]> {
        let b = hex::decode(s).map_err(|_| err("canonical lowerhex required"))?;
        if hex::encode(&b) != s {
            return Err(err("canonical lowerhex required"));
        }
        b.try_into().map_err(|_| err("hex width mismatch"))
    }
    fn read_file(path: &str, cap: usize) -> WalletdResult<Vec<u8>> {
        let mut b = Vec::new();
        std::fs::File::open(path)
            .map_err(op)?
            .take((cap + 1) as u64)
            .read_to_end(&mut b)
            .map_err(op)?;
        if b.len() > cap {
            return Err(err("file exceeds finite route cap"));
        }
        Ok(b)
    }
    fn write_new(path: &str, bytes: &[u8]) -> WalletdResult<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(path).map_err(op)?;
        f.write_all(bytes).map_err(op)?;
        f.sync_all().map_err(op)
    }
    fn confirm(c: bool) -> WalletdResult<()> {
        if c {
            Ok(())
        } else {
            Err(err("explicit operator confirm:true required"))
        }
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Roles {
        archive_key: Option<String>,
        delegate_secret: Option<D>,
    }
    impl Drop for Roles {
        fn drop(&mut self) {
            self.archive_key.zeroize();
            self.delegate_secret.zeroize();
        }
    }
    fn roles(p: Roles) -> WalletdResult<Value> {
        if p.archive_key.is_none() && p.delegate_secret.is_none() {
            return Err(err("archive_key or delegate_secret required"));
        }
        let mut result = json!({});
        if let Some(k) = &p.archive_key {
            let key = Zeroizing::new(hex_bytes::<32>(k)?);
            result["archive_key_commitment"] =
                json!(core::archive_key_commitment(&key).map_err(core_op)?);
        }
        if let Some(secret) = p.delegate_secret {
            let d = core::delegate_action_commitment(secret).map_err(core_op)?;
            result["delegate_action_commitment"] = json!(d);
            // The selected-actor credential leaf uses this commitment DIRECTLY.
            result["delegate_credential_owner"] = json!(d);
        }
        Ok(result)
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Setup {
        rows: Vec<SetupRow>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SetupRow {
        asset_row: String,
        stable_policy_id: D,
        archive_key_commitment: D,
        delegate_action_commitment: D,
        maximum_transfer: bool,
        maximum_burn: bool,
        transfer: bool,
        burn: bool,
        revoked: bool,
    }
    fn setup(p: Setup) -> WalletdResult<Value> {
        if p.rows.is_empty() || p.rows.len() > 16 {
            return Err(err("one through sixteen sorted rows required"));
        }
        let mut rows = vec![];
        let mut last = 0;
        for r in p.rows {
            let b = hex_bytes::<552>(&r.asset_row)?;
            let old = transaction_circuit::asset_spend_v1_admission::decode_asset_policy_row(&b)
                .map_err(op)?;
            let id = old.config.asset_id;
            if id <= last
                || old.credential_depth != 4
                || old.counters.epoch_id != 0
                || old.counters.minted_in_epoch != 0
                || old.counters.total_debt != 0
                || old.counters.sequence != 0
            {
                return Err(err(
                    "recovery requires sorted nonnative zero-issued depth4 genesis rows",
                ));
            }
            let descriptor = core::RecoveryDescriptorV1 {
                asset_id: id,
                stable_policy_id: r.stable_policy_id,
                policy_admin_commitment: old
                    .config
                    .policy_admin_commitment
                    .map(|x| x.as_canonical_u64()),
                archive_key_commitment: r.archive_key_commitment,
                maximum_powers: core::RecoveryPowersV1 {
                    transfer: r.maximum_transfer,
                    burn: r.maximum_burn,
                },
            };
            descriptor.validate().map_err(core_op)?;
            let row = core::RecoveryRowV1 {
                descriptor,
                controls: core::RecoveryControlsV1 {
                    epoch: 0,
                    delegate_action_commitment: r.delegate_action_commitment,
                    revoked: r.revoked,
                    powers: core::RecoveryPowersV1 {
                        transfer: r.transfer,
                        burn: r.burn,
                    },
                    note_freeze_root: [1; 7],
                },
            };
            row.validate().map_err(core_op)?;
            last = id;
            rows.push(json!({"asset_id":id,"stable_policy_id":descriptor.stable_policy_id,
            "policy_admin_commitment":descriptor.policy_admin_commitment,
            "archive_key_commitment":descriptor.archive_key_commitment,
            "maximum_powers_bits":powers_bits(descriptor.maximum_powers),
            "initial_delegate_commitment":row.controls.delegate_action_commitment,
            "initial_revoked":row.controls.revoked,"initial_powers_bits":powers_bits(row.controls.powers)}));
        }
        Ok(json!({"schema":"hegemon.native.development-recovery.v1",
        "spend_relation_digest":hex::encode(spend::relation_digest()),
        "admin_relation_digest":hex::encode(admin::relation_digest()),
        "capsule_relation_digest":hex::encode(capsule::relation_digest()),"wire_version":wire::VERSION,
        "credential_depth":4,"max_proof_bytes":wire::MAX_PROOF_BYTES,
        "max_action_bytes":wire::MAX_SPEND_ACTION_BYTES,"max_actions_per_block":1,"initial_rows":rows}))
    }
    #[derive(Clone, Deserialize)]
    struct Online {
        ws_url: String,
        manifest: String,
        expected_genesis: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Info {
        #[serde(flatten)]
        online: Online,
        asset_id: Option<u32>,
        position: Option<u32>,
    }
    // The manifest and connected full node are explicit local trust inputs; all
    // current state below must also match the wallet's canonical mirror exactly.
    async fn authority(
        store: &WalletStore,
        c: &NodeRpcClient,
        p: &Online,
    ) -> WalletdResult<DevelopmentPrivateSpendAuthority> {
        let manifest = read_file(&p.manifest, 64 * 1024)?;
        let config = c.node_config().await.map_err(op)?;
        let parameters = c.private_spend_parameters().await.map_err(op)?;
        let genesis = c
            .block_hash(0)
            .await
            .map_err(op)?
            .ok_or_else(|| err("node genesis absent"))?;
        let height = c.latest_block().await.map_err(op)?.height;
        let t = DevelopmentPrivateSpendAuthority::from_verified_node(
            &manifest,
            hex_bytes(&p.expected_genesis)?,
            genesis,
            &config,
            &parameters,
            height,
        )
        .map_err(op)?;
        if !t.recovery_enabled() {
            return Err(err("manifest has no recovery opt-in"));
        }
        store.require_launch_context(t.context()).map_err(op)?;
        Ok(t)
    }
    async fn snapshot(
        store: &WalletStore,
        c: &NodeRpcClient,
        t: &DevelopmentPrivateSpendAuthority,
        asset: Option<u32>,
        position: Option<u32>,
    ) -> WalletdResult<(Value, Vec<core::RecoveryRowV1>)> {
        let s = c.recovery_snapshot(asset, position).await.map_err(op)?;
        let rows = validate_recovery_snapshot_readback(t, &s).map_err(op)?;
        let tip = store.poseidon2_v8_tip().map_err(op)?;
        if s["context"]["parent_height"] != tip.height
            || s["context"]["parent_hash"] != hex::encode(tip.block_hash)
            || words::<7>(&s["context"]["note_root"])? != tip.anchor
        {
            return Err(err("sync wallet to exact recovery snapshot first"));
        }
        Ok((s, rows))
    }
    fn expected(s: &Value, row: &core::RecoveryRowV1, hash: &str, epoch: u64) -> WalletdResult<()> {
        let _: [u8; 32] = hex_bytes(hash)?;
        if s["context"]["parent_hash"] != hash || row.controls.epoch != epoch {
            return Err(err("operator-approved parent/epoch changed; inspect again"));
        }
        Ok(())
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Credential {
        index: u32,
        expires_at: u64,
        siblings: Vec<D>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Prepare {
        #[serde(flatten)]
        online: Online,
        confirm: bool,
        expected_parent_hash: String,
        expected_epoch: u64,
        asset_id: u32,
        operation: String,
        route: String,
        amount: u64,
        fee: u64,
        fee_position: u64,
        recipient: String,
        change_recipient: Option<String>,
        #[serde(default)]
        native_change_index: u32,
        archive_key: Option<String>,
        archive_provider: Option<crate::recovery_archive_process::ProcessArchiveProviderSpec>,
        credentials: [Credential; 3],
        input_position: Option<u32>,
        input_action_file: Option<String>,
        input_output: Option<u8>,
        delegate_secret: Option<D>,
        delegate_credential_recipient: Option<String>,
        issuer_secret: Option<D>,
    }
    impl Drop for Prepare {
        fn drop(&mut self) {
            self.archive_key.zeroize();
            self.delegate_secret.zeroize();
            self.issuer_secret.zeroize();
        }
    }
    fn validate_archive_choice(p: &Prepare) -> WalletdResult<()> {
        match (&p.archive_key, &p.archive_provider) {
            (Some(_), None) => (),
            (None, Some(spec)) => {
                spec.validate().map_err(op)?;
                if p.route == "delegate" {
                    return Err(err("delegate input decryption requires local archive_key"));
                }
            }
            _ => {
                return Err(err(
                    "exactly one archive_key or archive_provider is required",
                ))
            }
        }
        Ok(())
    }
    fn address(s: &str) -> WalletdResult<(ShieldedAddress, [u64; 4], D)> {
        let a = ShieldedAddress::decode(s).map_err(op)?;
        if a.version != wallet::address::POSEIDON2_V8_ADDRESS_VERSION {
            return Err(err("full V8 address required"));
        }
        let recipient = coinbase::poseidon2_v8_words_from_canonical_bytes(a.pk_recipient)
            .map_err(|_| err("recipient encoding"))?;
        let mut d = [0; 7];
        d[..4].copy_from_slice(
            &coinbase::poseidon2_v8_words_from_canonical_bytes(a.pk_auth)
                .map_err(|_| err("authority encoding"))?,
        );
        for (w, b) in d[4..].iter_mut().zip(a.pk_auth_extension.chunks_exact(8)) {
            *w = u64::from_le_bytes(b.try_into().unwrap());
        }
        if d.iter().any(|x| *x >= 0xffff_ffff_0000_0001) {
            return Err(err("noncanonical authority"));
        }
        Ok((a, recipient, d))
    }
    fn material_from_carrier(
        path: &str,
        slot: u8,
        row: &core::RecoveryRowV1,
        chain: [u8; 32],
        key: &[u8; 32],
    ) -> WalletdResult<RecoveryNoteMaterialV1> {
        let b = read_file(path, wire::MAX_SPEND_ACTION_BYTES + 512)?;
        let slot = usize::from(slot);
        if slot > 1 {
            return Err(err("input_output must be 0 or 1"));
        }
        let public = if b.starts_with(&wire::MAGIC) {
            wire::decode_spend_ref(&b).map_err(op)?.capsules[slot]
                .public
                .clone()
        } else {
            wallet::poseidon2_v8_sync::recovery_archive_capsules_from_canonical_action(&b)
                .map_err(op)?
                .ok_or_else(|| err("input file is not a canonical recovery spend"))?[slot]
                .clone()
        };
        if public.chain_id != chain
            || public.asset_id != row.descriptor.asset_id
            || public.stable_policy_id != row.descriptor.stable_policy_id
            || public.archive_key_commitment != row.descriptor.archive_key_commitment
        {
            return Err(err(
                "archive capsule context differs from current immutable descriptor",
            ));
        }
        build::decrypt_archive_material(&public, key).map_err(op)
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct InspectInput {
        #[serde(flatten)]
        online: Online,
        asset_id: u32,
        position: u32,
        input_action_file: String,
        input_output: u8,
        archive_key: String,
    }
    impl Drop for InspectInput {
        fn drop(&mut self) {
            self.archive_key.zeroize();
        }
    }
    async fn inspect_input(
        store: &WalletStore,
        c: &NodeRpcClient,
        t: &DevelopmentPrivateSpendAuthority,
        p: InspectInput,
    ) -> WalletdResult<Value> {
        let (s, rows) = snapshot(store, c, t, Some(p.asset_id), Some(p.position)).await?;
        let row = rows.first().ok_or_else(|| err("recovery row absent"))?;
        let key = Zeroizing::new(hex_bytes::<32>(&p.archive_key)?);
        if core::archive_key_commitment(&key).map_err(core_op)?
            != row.descriptor.archive_key_commitment
        {
            return Err(err("archive key commitment mismatch"));
        }
        let m = material_from_carrier(
            &p.input_action_file,
            p.input_output,
            row,
            t.context().chain_id(),
            &key,
        )?;
        let cm = private::note_commitment(m.as_note()).map_err(op)?;
        store
            .poseidon2_v8_canonical_note_witness_at(cm, u64::from(p.position))
            .map_err(op)?
            .ok_or_else(|| err("archive material not canonical at requested position"))?;
        if words::<7>(&s["freeze_witness"]["note_commitment"])? != cm {
            return Err(err("snapshot note identity differs"));
        }
        let ctx = wallet::asset_recovery_v1::RecoveryNoteContextV1 {
            chain_id: t.context().chain_id(),
            asset_id: p.asset_id,
            stable_policy_id: row.descriptor.stable_policy_id,
            output_commitment: cm,
        };
        Ok(
            json!({"asset_id":p.asset_id,"position":p.position,"value":m.note.value,
            "commitment":cm,"nullifier":m.common_nullifier(&ctx,p.position).map_err(op)?,
            "epoch":row.controls.epoch,"parent_hash":s["context"]["parent_hash"],
            "frozen":s["freeze_witness"]["frozen"],"action_authority_granted":false}),
        )
    }
    async fn prepare(
        store: &WalletStore,
        c: &NodeRpcClient,
        t: &DevelopmentPrivateSpendAuthority,
        p: Prepare,
    ) -> WalletdResult<Value> {
        confirm(p.confirm)?;
        validate_archive_choice(&p)?;
        if p.amount == 0 || p.amount >= 1 << 56 || p.fee >= 1 << 56 {
            return Err(err("amount must be positive56bit; fee56bit"));
        }
        let position = if p.route == "mint" {
            None
        } else {
            Some(
                p.input_position
                    .ok_or_else(|| err("input_position required"))?,
            )
        };
        let (s, rows) = snapshot(store, c, t, Some(p.asset_id), position).await?;
        let row = *rows.first().ok_or_else(|| err("opted row absent"))?;
        expected(&s, &row, &p.expected_parent_hash, p.expected_epoch)?;
        let tip = store.poseidon2_v8_tip().map_err(op)?;
        let config = c.node_config().await.map_err(op)?;
        let a = c
            .asset_snapshot(Some(p.asset_id), Some(tip.block_hash))
            .await
            .map_err(op)?;
        let node = AssetNodeContext::from_snapshot(t.context(), &config, &a).map_err(op)?;
        node.require_wallet_tip(store).map_err(op)?;
        let policy =
            AuthenticatedAssetPolicy::from_registry_readback(&node, &a["registry"], p.asset_id)
                .map_err(op)?;
        let oldrow = policy.row();
        let current = node.current();
        if words::<7>(&s["context"]["asset_registry_root"])? != current.registry_root {
            return Err(err("snapshot registry roots differ"));
        }
        if oldrow.frozen {
            return Err(err("whole asset frozen; recovery cannot override"));
        }
        let operation = match p.operation.as_str() {
            "mint" => old::MINT,
            "transfer" => old::TRANSFER,
            "burn" => old::BURN,
            _ => return Err(err("operation mint|transfer|burn")),
        };
        if (p.route == "mint") != (operation == old::MINT) {
            return Err(err("mint operation requires mint route exclusively"));
        }
        let key = p
            .archive_key
            .as_deref()
            .map(hex_bytes::<32>)
            .transpose()?
            .map(Zeroizing::new);
        if let Some(key) = &key {
            if core::archive_key_commitment(key).map_err(core_op)?
                != row.descriptor.archive_key_commitment
            {
                return Err(err("archive key does not match immutable commitment"));
            }
        }
        if p.route == "delegate" && p.change_recipient.is_none() {
            return Err(err(
                "delegate requires explicit change_recipient, including zero change",
            ));
        }
        let material = if p.route == "delegate" {
            Some(material_from_carrier(
                p.input_action_file
                    .as_deref()
                    .ok_or_else(|| err("delegate needs input_action_file"))?,
                p.input_output
                    .ok_or_else(|| err("delegate needs input_output 0 or 1"))?,
                &row,
                current.chain_id,
                key.as_deref()
                    .ok_or_else(|| err("delegate requires archive_key"))?,
            )?)
        } else if p.route == "holder" {
            Some(
                store
                    .recovery_note_material(u64::from(position.unwrap()))
                    .map_err(op)?
                    .1,
            )
        } else if p.route == "mint" {
            None
        } else {
            return Err(err("route mint|holder|delegate"));
        };
        let value = material.as_ref().map_or(p.amount, |m| m.note.value);
        let change = if operation == old::MINT {
            0
        } else {
            value
                .checked_sub(p.amount)
                .ok_or_else(|| err("amount exceeds input"))?
        };
        if p.route == "delegate" {
            row.require_power(operation == old::BURN).map_err(core_op)?;
            if core::delegate_action_commitment(
                p.delegate_secret
                    .ok_or_else(|| err("delegate_secret required"))?,
            )
            .map_err(core_op)?
                != row.controls.delegate_action_commitment
            {
                return Err(err("delegate authority does not match CURRENT commitment"));
            }
        }
        let pay = if operation == old::BURN { 0 } else { p.amount };
        let (payaddr, payrec, payauth) = address(&p.recipient)?;
        let changeaddr = match &p.change_recipient {
            Some(s) => ShieldedAddress::decode(s).map_err(op)?,
            None => store.private_spend_address(0).map_err(op)?,
        };
        let (changeaddr, changerec, changeauth) = address(&changeaddr.encode().map_err(op)?)?;
        let feeaddr = store
            .private_spend_address(p.native_change_index)
            .map_err(op)?;
        let (feeaddr, feerec, feeauth) = address(&feeaddr.encode().map_err(op)?)?;
        let output0 = build::new_recovery_output_os(
            current.chain_id,
            p.asset_id,
            row.descriptor.stable_policy_id,
            pay,
            payrec,
            payauth,
        )
        .map_err(op)?;
        let output1 = build::new_recovery_output_os(
            current.chain_id,
            p.asset_id,
            row.descriptor.stable_policy_id,
            change,
            changerec,
            changeauth,
        )
        .map_err(op)?;
        let keys = store
            .derived_keys()
            .map_err(op)?
            .ok_or_else(|| err("full wallet needed for native fee"))?;
        let fee = store
            .poseidon2_v8_owned_notes()
            .map_err(op)?
            .into_iter()
            .find(|n| {
                n.position == p.fee_position
                    && !n.spent
                    && n.opening.asset_id == 0
                    && n.opening.value >= p.fee
            })
            .ok_or_else(|| err("mature owned native fee position absent"))?;
        let feeowner = private::ordinary_owner(feeauth).map_err(op)?;
        let mut feenote = NoteOpening {
            value: fee.opening.value - p.fee,
            asset_id: 0,
            recipient_key: feerec,
            authorization_key: [0; 4],
            rho: fresh_fields(),
            randomness: fresh_fields(),
        };
        feenote.authorization_key.copy_from_slice(&feeowner[..4]);
        feenote.randomness = fresh_fields();
        feenote.randomness[..3].copy_from_slice(&feeowner[4..]);
        feenote.rho = fresh_fields();
        let feechange = wallet::asset_spend_v1::AssetNotePayload {
            recipient_index: p.native_change_index,
            note: feenote,
            authority: feeauth,
        };
        let localkey = Zeroizing::new(keys.spend.poseidon2_v8_words().map_err(op)?);
        let localauth = coinbase::poseidon2_v8_single_key_authorization_digest(*localkey)
            .map_err(|_| err("local authority"))?;
        let ordinary = private::ordinary_owner(localauth).map_err(op)?;
        let n = fee.opening;
        let legacy =
            u64::from(n.authorization_key != ordinary[..4] || n.randomness[..3] != ordinary[4..]);
        let feeinput = private::PrivateInput {
            occupied: 1,
            legacy_ordinary: legacy,
            note: private::Note {
                value: n.value,
                asset_id: n.asset_id,
                recipient_key: n.recipient_key,
                authorization_key: n.authorization_key,
                rho: n.rho,
                randomness: n.randomness,
            },
            position: u32::try_from(fee.position).map_err(|_| err("fee position32"))?,
            siblings: fee.path,
            spend_key: *localkey,
            dummy_secret: [0; 5],
        };
        if private::real_nullifier(*localkey, feeinput.position, feeinput.note).map_err(op)?
            != fee.nullifier
        {
            return Err(err("owned fee NF differs"));
        }
        let mut path = [[0; 7]; 32];
        let mut frozenpath = [[0; 7]; 32];
        if let Some(m) = &material {
            let cm = private::note_commitment(m.as_note()).map_err(op)?;
            let witness = store
                .poseidon2_v8_canonical_note_witness_at(cm, u64::from(position.unwrap()))
                .map_err(op)?
                .ok_or_else(|| {
                    err("archive material is not canonical note at requested position")
                })?;
            if witness.anchor != current.note_root {
                return Err(err("input witness root changed"));
            }
            path = witness.path;
            let f = &s["freeze_witness"];
            if f["position"] != position.unwrap()
                || words::<7>(&f["note_commitment"])? != cm
                || f["frozen"] != false
            {
                return Err(err("target frozen or wrong canonical CM"));
            }
            frozenpath = serde_json::from_value::<Vec<D>>(f["siblings"].clone())
                .map_err(|_| err("freeze path shape"))?
                .try_into()
                .map_err(|_| err("freeze path32"))?;
        }
        let authorization = match p.route.as_str() {
            "mint" => build::RecoveryAuthorizationV1::Mint {
                dummy_secret: fresh_fields::<5>().into(),
                issuer_secret: p
                    .issuer_secret
                    .ok_or_else(|| err("issuer_secret required"))?
                    .into(),
            },
            "holder" => build::RecoveryAuthorizationV1::Holder {
                material: material.as_ref().unwrap(),
                position: position.unwrap(),
                siblings: path,
                freeze_siblings: frozenpath,
                spend_key: (*localkey).into(),
            },
            _ => {
                let (_, r, _) = address(
                    p.delegate_credential_recipient
                        .as_deref()
                        .ok_or_else(|| err("current delegate credential address required"))?,
                )?;
                build::RecoveryAuthorizationV1::Delegate {
                    material: material.as_ref().unwrap(),
                    position: position.unwrap(),
                    siblings: path,
                    freeze_siblings: frozenpath,
                    delegate_secret: p.delegate_secret.unwrap().into(),
                    credential_recipient: r,
                }
            }
        };
        let horizon = current
            .parent_height
            .checked_add(12)
            .ok_or_else(|| err("credential height overflow"))?;
        if p.credentials.iter().enumerate().any(|(i, c)| {
            if operation == old::MINT && i == 0 {
                c.index != 0
                    || c.expires_at != 0
                    || (!c.siblings.is_empty() && c.siblings.len() != 4)
                    || c.siblings.iter().any(|s| *s != [0; 7])
            } else {
                c.siblings.len() != 4 || c.expires_at < horizon
            }
        }) {
            return Err(err("active credentials require depth4 and expiry H+12; mint input requires canonical dummy"));
        }
        let credentials = std::array::from_fn(|i| old::AssetCredentialWitness {
            index: p.credentials[i].index,
            expires_at: p.credentials[i].expires_at,
            siblings: p.credentials[i].siblings.clone(),
        });
        let public = spend::Public {
            row,
            base: old::AssetSpendPublic {
                chain_id: current.chain_id,
                reference_parent_hash: current.reference_parent_hash,
                parent_height: current.parent_height,
                note_root: current.note_root,
                registry_root: current.registry_root,
                asset_id: p.asset_id,
                policy_version: oldrow.config.policy_version,
                credential_root: oldrow.credential_root.map(|x| x.as_canonical_u64()),
                credential_depth: oldrow.credential_depth,
                frozen: oldrow.frozen,
                mint_enabled: oldrow.mint_enabled,
                issuer_commitment: oldrow
                    .config
                    .issuer_commitment
                    .map(|x| x.as_canonical_u64()),
                operation,
                magnitude: if operation == old::TRANSFER {
                    0
                } else {
                    p.amount
                },
                fee: p.fee,
                nullifiers: [[1; 7], [2; 7]],
                commitments: [[1; 7]; 3],
                ciphertext_commitments: [[0; 48]; 3],
                policy_mode: 0,
                secret_release: 0,
                released_secret: [0; 32],
            },
        };
        let plan = build::prepare_recovery_spend_plan_os(
            build::RecoverySpendConstructionV1 {
                public,
                authorization,
                native_fee_input: build::NativeFeeInputV1::new(feeinput).map_err(op)?,
                outputs: [&output0, &output1],
                native_fee_change: &feechange,
                credentials,
            },
            [&payaddr.pk_enc, &changeaddr.pk_enc, &feeaddr.pk_enc],
        )
        .map_err(op)?;
        t.authorize_recovery_public(plan.public_statement())
            .map_err(op)?;
        let mut provider: Box<dyn build::ArchiveCapsuleProviderV1> = match key {
            Some(key) => Box::new(build::LocalArchiveProviderV1::new(key)),
            None => Box::new(
                crate::recovery_archive_process::ProcessArchiveProviderV1::new(
                    p.archive_provider
                        .as_ref()
                        .ok_or_else(|| err("archive provider absent"))?
                        .clone(),
                )
                .map_err(op)?,
            ),
        };
        let id = if p.route == "delegate" {
            store
                .reserve_recovery_delegate_spend(
                    t.context(),
                    plan.public_statement(),
                    material.as_ref().unwrap(),
                    position.unwrap(),
                    p.fee_position,
                )
                .map_err(op)?
        } else {
            store
                .reserve_recovery_spend(
                    t.context(),
                    plan.public_statement(),
                    &plan.real_input_positions(),
                )
                .map_err(op)?
        };
        let artifact = match plan
            .attach_capsules(provider.as_mut())
            .and_then(|p| p.prove_and_encode())
        {
            Ok(a) => a,
            Err(e) => {
                let cancellation = store.cancel_unexported_recovery_spend(id);
                return Err(op(format!(
                    "proving failed; reservation_id={}; cancellation_persisted={}; {e}",
                    hex::encode(id),
                    cancellation.is_ok()
                )));
            }
        };
        store
            .retain_recovery_spend(id, artifact.as_bytes())
            .map_err(|e| {
                op(format!(
                    "retention failed; reservation_id={}; hold preserved: {e}",
                    hex::encode(id)
                ))
            })?;
        Ok(
            json!({"reservation_id":hex::encode(id),"status":"candidate","action_bytes":artifact.as_bytes().len(),
        "proof_units":wire::PROOF_UNITS,"public_statement":artifact.public_statement().words().map_err(op)?,
        "reference_parent_hash":hex::encode(current.reference_parent_hash),"reference_parent_height":current.parent_height,
        "requires_exact_current_parent":true}),
        )
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Powers {
        transfer: bool,
        burn: bool,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Admin {
        #[serde(flatten)]
        online: Online,
        confirm: bool,
        asset_id: u32,
        expected_parent_hash: String,
        expected_epoch: u64,
        operation: String,
        admin_secret: D,
        expires_at: u64,
        action_intent: D,
        action_file: String,
        position: Option<u32>,
        new_delegate_commitment: Option<D>,
        powers: Option<Powers>,
    }
    impl Drop for Admin {
        fn drop(&mut self) {
            self.admin_secret.zeroize();
        }
    }
    async fn admin_prepare(
        store: &WalletStore,
        c: &NodeRpcClient,
        t: &DevelopmentPrivateSpendAuthority,
        p: Admin,
    ) -> WalletdResult<Value> {
        confirm(p.confirm)?;
        let is_freeze = matches!(p.operation.as_str(), "freeze" | "unfreeze");
        if is_freeze != p.position.is_some() {
            return Err(err("position is required only for freeze/unfreeze"));
        }
        if (p.operation == "rotate") != p.new_delegate_commitment.is_some() {
            return Err(err("new_delegate_commitment is required only for rotate"));
        }
        if (p.operation == "powers") != p.powers.is_some() {
            return Err(err("powers are required only for powers operation"));
        }
        let (s, rows) = snapshot(store, c, t, Some(p.asset_id), p.position).await?;
        let before = *rows.first().ok_or_else(|| err("recovery row absent"))?;
        expected(&s, &before, &p.expected_parent_hash, p.expected_epoch)?;
        if admin::policy_admin_commitment(p.asset_id, p.admin_secret).map_err(op)?
            != before.descriptor.policy_admin_commitment
        {
            return Err(err("administrator secret differs from current policy role"));
        }
        let mut after = before.controls;
        after.epoch = after
            .epoch
            .checked_add(1)
            .ok_or_else(|| err("epoch overflow"))?;
        let mut siblings = [[0; 7]; 32];
        let mut mutation = None;
        match p.operation.as_str() {
            "freeze" | "unfreeze" => {
                let f = &s["freeze_witness"];
                let position = p.position.unwrap();
                let cm = words::<7>(&f["note_commitment"])?;
                let was = f["frozen"]
                    .as_bool()
                    .ok_or_else(|| err("freeze flag missing"))?;
                let now = p.operation == "freeze";
                if f["asset_id"] != p.asset_id || f["position"] != position || was == now {
                    return Err(err("wrong target or unchanged freeze state"));
                }
                siblings = serde_json::from_value::<Vec<D>>(f["siblings"].clone())
                    .map_err(|_| err("freeze path shape"))?
                    .try_into()
                    .map_err(|_| err("freeze path32"))?;
                // Bind the RPC note occurrence independently to the synced canonical tree.
                store
                    .poseidon2_v8_canonical_note_witness_at(cm, u64::from(position))
                    .map_err(op)?
                    .ok_or_else(|| err("freeze target absent from wallet canonical mirror"))?;
                after.note_freeze_root = core::freeze_root(
                    &before.descriptor,
                    t.context().chain_id(),
                    position,
                    cm,
                    now,
                    &siblings,
                )
                .map_err(core_op)?;
                mutation = Some(admin::FreezeMutation {
                    position,
                    note_commitment: cm,
                    before_frozen: was,
                    after_frozen: now,
                });
            }
            "rotate" => after.delegate_action_commitment = p.new_delegate_commitment.unwrap(),
            "revoke" => after.revoked = true,
            "enable" => after.revoked = false,
            "powers" => {
                let p = p.powers.as_ref().unwrap();
                after.powers = core::RecoveryPowersV1 {
                    transfer: p.transfer,
                    burn: p.burn,
                }
            }
            _ => {
                return Err(err(
                    "admin operation freeze|unfreeze|rotate|revoke|enable|powers",
                ))
            }
        }
        let ctx = core::RecoveryContextV1 {
            chain_id: t.context().chain_id(),
            parent_hash: hex_bytes(&p.expected_parent_hash)?,
            parent_height: s["context"]["parent_height"]
                .as_u64()
                .ok_or_else(|| err("height"))?,
            row_commitment: before.commitment(t.context().chain_id()).map_err(core_op)?,
        };
        let prepared = core::prepare_controls_update(ctx, before, after).map_err(core_op)?;
        let public =
            admin::Public::from_prepared(&prepared, p.expires_at, p.action_intent, mutation)
                .map_err(op)?;
        t.authorize_recovery_admin_public(&public).map_err(op)?;
        let proof = admin::prove_candidate(
            &public,
            &admin::Witness {
                admin_secret: p.admin_secret,
                freeze_siblings: siblings,
            },
        )
        .map_err(op)?;
        admin::verify_candidate(&public, &proof).map_err(op)?;
        let body = wire::encode_admin(&public, &proof).map_err(op)?;
        write_new(&p.action_file, &body)?;
        Ok(
            json!({"status":"candidate","action_file":p.action_file,"action_bytes":body.len(),
        "administrator_action_id":hex::encode(public.action_id().map_err(op)?),
        "public_statement":public.words().map_err(op)?.to_vec(),"requires_exact_current_parent":true}),
        )
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Journal {
        reservation_id: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Export {
        reservation_id: String,
        action_file: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Abandon {
        reservation_id: String,
        confirm: bool,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Submit {
        #[serde(flatten)]
        online: Online,
        reservation_id: String,
        confirm: bool,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AdminSubmit {
        #[serde(flatten)]
        online: Online,
        action_file: String,
        expected_action_id: String,
        confirm: bool,
    }
    async fn admin_submit(
        store: &WalletStore,
        c: &NodeRpcClient,
        t: &DevelopmentPrivateSpendAuthority,
        p: AdminSubmit,
    ) -> WalletdResult<Value> {
        confirm(p.confirm)?;
        let body = read_file(&p.action_file, wire::MAX_ADMIN_ACTION_BYTES)?;
        let d = wire::decode_admin_ref(&body).map_err(op)?;
        let id = d.public.action_id().map_err(op)?;
        if hex_bytes::<32>(&p.expected_action_id)? != id {
            return Err(err("action file differs from operator-approved action ID"));
        }
        t.authorize_recovery_admin_public(&d.public).map_err(op)?;
        let (s, rows) = snapshot(
            store,
            c,
            t,
            Some(d.public.before.descriptor.asset_id),
            d.public.freeze.map(|f| f.position),
        )
        .await?;
        if rows.first() != Some(&d.public.before)
            || s["context"]["parent_height"] != d.public.context.parent_height
            || s["context"]["parent_hash"] != hex::encode(d.public.context.parent_hash)
        {
            return Err(err(
                "administrator candidate is not exact current parent/row",
            ));
        }
        admin::verify_candidate(&d.public, d.proof).map_err(op)?;
        let action = c
            .submit_native_recovery_action(t, 19, &body)
            .await
            .map_err(op)?;
        Ok(
            json!({"status":"submitted","action_id":hex::encode(action),"administrator_action_id":hex::encode(id)}),
        )
    }
    pub(super) fn handle(
        runtime: &tokio::runtime::Runtime,
        store: Arc<WalletStore>,
        method: &str,
        p: Value,
    ) -> WalletdResult<Value> {
        match method {
            "recovery.roles" => return roles(parse(p)?),
            "recovery.setup" => return setup(parse(p)?),
            "recovery.notes" => {
                let _: Empty = parse(p)?;
                let fees:Vec<_>=store.poseidon2_v8_owned_notes().map_err(op)?.iter().filter(|n|n.opening.asset_id==0)
            .map(|n|json!({"position":n.position,"value":n.opening.value,"spent":n.spent,"nullifier":n.nullifier})).collect();
                return Ok(
                    json!({"recovery_notes":store.recovery_notes().map_err(op)?,"native_fee_notes":fees}),
                );
            }
            "recovery.journal" => {
                let _: Empty = parse(p)?;
                return serde_json::to_value(store.recovery_attempts().map_err(op)?).map_err(op);
            }
            "recovery.export" => {
                let p: Export = parse(p)?;
                let body = store
                    .recovery_retained_bytes(hex_bytes(&p.reservation_id)?)
                    .map_err(op)?;
                write_new(&p.action_file, &body)?;
                return Ok(json!({"action_file":p.action_file,"action_bytes":body.len()}));
            }
            "recovery.abandon" => {
                let p: Abandon = parse(p)?;
                confirm(p.confirm)?;
                store
                    .abandon_recovery_spend(hex_bytes(&p.reservation_id)?)
                    .map_err(op)?;
                return Ok(json!({"status":"abandoned"}));
            }
            "recovery.info"
            | "recovery.inspectInput"
            | "recovery.prepare"
            | "recovery.submit"
            | "recovery.adminPrepare"
            | "recovery.adminSubmit" => (),
            _ => {
                return Err(WalletdError::new(
                    WalletdErrorCode::UnknownMethod,
                    "unknown recovery method",
                ))
            }
        }
        // Extract connection only; the method-specific deny-unknown-fields schema is
        // parsed BEFORE contacting any node or doing proof work.
        let online = match method {
            "recovery.info" => parse::<Info>(p.clone())?.online,
            "recovery.inspectInput" => parse::<InspectInput>(p.clone())?.online.clone(),
            "recovery.prepare" => {
                let r: Prepare = parse(p.clone())?;
                confirm(r.confirm)?;
                validate_archive_choice(&r)?;
                r.online.clone()
            }
            "recovery.submit" => {
                let r: Submit = parse(p.clone())?;
                confirm(r.confirm)?;
                r.online
            }
            "recovery.adminPrepare" => {
                let r: Admin = parse(p.clone())?;
                confirm(r.confirm)?;
                r.online.clone()
            }
            _ => {
                let r: AdminSubmit = parse(p.clone())?;
                confirm(r.confirm)?;
                r.online
            }
        };
        runtime.block_on(async{
        let c=NodeRpcClient::connect(&online.ws_url).await.map_err(op)?;
        let t=authority(&store,&c,&online).await?;
        match method {
            "recovery.info"=>{let p:Info=parse(p)?;let(s,_)=snapshot(&store,&c,&t,p.asset_id,p.position).await?;Ok(s)},
            "recovery.inspectInput"=>inspect_input(&store,&c,&t,parse(p)?).await,
            "recovery.prepare"=>prepare(&store,&c,&t,parse(p)?).await,
            "recovery.adminPrepare"=>admin_prepare(&store,&c,&t,parse(p)?).await,
            "recovery.adminSubmit"=>admin_submit(&store,&c,&t,parse(p)?).await,
            _=>{let p:Submit=parse(p)?;confirm(p.confirm)?;let id=hex_bytes(&p.reservation_id)?;
                let r=build::submit_retained_recovery_spend(&store,&c,&t,id).await.map_err(op)?;
                Ok(json!({"status":"submitted","action_id":hex::encode(r.action_id),"reservation_id":p.reservation_id}))},
        }
    })
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn exact_operator_schema_and_confirmation_fail_closed() {
            let v = json!({"ws_url":"http://127.0.0.1:9944","manifest":"m.json","expected_genesis":"00".repeat(32),"asset_id":17,"position":4});
            assert!(parse::<Info>(v.clone()).is_ok());
            let mut bad = v;
            bad["install_root"] = json!(vec![1u64; 7]);
            assert!(parse::<Info>(bad).is_err());
            assert!(confirm(false).is_err());
            assert!(confirm(true).is_ok());
            assert!(hex_bytes::<32>(&"AA".repeat(32)).is_err());
            assert!(hex_bytes::<32>(&"00".repeat(31)).is_err());
        }
        #[test]
        fn archive_provider_is_exclusive_and_delegate_decryption_is_explicit() {
            let base = json!({"ws_url":"http://127.0.0.1:9944","manifest":"m.json",
                "expected_genesis":"00".repeat(32),"expected_parent_hash":"00".repeat(32),
                "expected_epoch":0,"confirm":true,"asset_id":17,"operation":"transfer",
                "route":"holder","amount":1,"fee":1,"fee_position":4,
                "recipient":"validated-later-as-full-address",
                "credentials":[{"index":0,"expires_at":0,"siblings":[]},
                    {"index":0,"expires_at":0,"siblings":[]},
                    {"index":0,"expires_at":0,"siblings":[]}]});
            assert!(validate_archive_choice(&parse::<Prepare>(base.clone()).unwrap()).is_err());
            let mut local = base.clone();
            local["archive_key"] = json!("03".repeat(32));
            assert!(validate_archive_choice(&parse::<Prepare>(local.clone()).unwrap()).is_ok());
            local["archive_provider"] = json!({"executable":"/private/pinned/walletd","args":[]});
            assert!(validate_archive_choice(&parse::<Prepare>(local).unwrap()).is_err());
            let mut process = base;
            process["archive_provider"] = json!({"executable":"/private/pinned/walletd",
                "args":["--recovery-archive-worker","--archive-key-file","/private/archive.key"]});
            #[cfg(unix)]
            assert!(validate_archive_choice(&parse::<Prepare>(process.clone()).unwrap()).is_ok());
            process["route"] = json!("delegate");
            assert!(validate_archive_choice(&parse::<Prepare>(process).unwrap()).is_err());
        }
        #[test]
        fn archive_and_action_authorities_are_separate_public_commitments() {
            let key = [3; 32];
            let action = [7; 7];
            assert_ne!(
                core::archive_key_commitment(&key).unwrap(),
                core::delegate_action_commitment(action).unwrap()
            );
            let result = roles(Roles {
                archive_key: None,
                delegate_secret: Some(action),
            })
            .unwrap();
            assert_eq!(
                result["delegate_credential_owner"],
                json!(core::delegate_action_commitment(action).unwrap())
            );
            assert!(roles(Roles {
                archive_key: None,
                delegate_secret: None
            })
            .is_err());
            assert_ne!(
                core::archive_key_commitment(&key).unwrap(),
                core::archive_key_commitment(&[4; 32]).unwrap()
            );
        }
    }
}
