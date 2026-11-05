//! Safe public explorer RPCs. Only canonical publication installs the ledger;
//! these reads never initialize/repair storage or grant runtime proof authority.
use super::super::*;
use super::{read_model as view, wire};
use anyhow::ensure;
use protocol_reward_accounts::*;
use serde::de::DeserializeOwned;

pub(crate) const METHODS: &[&str] = &[
    "hegemon_rewardAccountsStatus",
    "hegemon_rewardAccount",
    "hegemon_rewardAccountsGenesis",
    "hegemon_rewardAccountsActivity",
];
const MAX_SCANNED_BLOCKS: u64 = 8;
fn default_limit() -> usize {
    25
}
fn first_height() -> u64 {
    1
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotQuery {
    at: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountQuery {
    address: String,
    at: Option<String>,
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GenesisQuery {
    offset: usize,
    limit: usize,
    at: Option<String>,
}
impl Default for GenesisQuery {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: default_limit(),
            at: None,
        }
    }
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ActivityQuery {
    at: Option<String>,
    address: Option<String>,
    #[serde(deserialize_with = "exact_u64")]
    from_height: u64,
    action_index: usize,
    limit: usize,
}
impl Default for ActivityQuery {
    fn default() -> Self {
        Self {
            at: None,
            address: None,
            from_height: first_height(),
            action_index: 0,
            limit: default_limit(),
        }
    }
}
/// Accept native integer requests and lossless decimal-string continuations.
fn exact_u64<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Exact {
        Number(u64),
        Text(String),
    }
    match Exact::deserialize(d)? {
        Exact::Number(n) => Ok(n),
        Exact::Text(s) => {
            if s.is_empty()
                || s.len() > 20
                || !s.bytes().all(|b| b.is_ascii_digit())
                || (s.len() > 1 && s.starts_with('0'))
            {
                return Err(serde::de::Error::custom(
                    "height must be a canonical unsigned decimal integer",
                ));
            }
            s.parse().map_err(serde::de::Error::custom)
        }
    }
}
fn query<T: DeserializeOwned + Default>(params: Value) -> Result<T> {
    let a = params
        .as_array()
        .ok_or_else(|| anyhow!("expected [] or [query object]"))?;
    ensure!(a.len() <= 1, "expected at most one query object");
    match a.first() {
        None => Ok(T::default()),
        Some(v) => Ok(serde_json::from_value(v.clone())?),
    }
}
fn limit(n: usize) -> Result<()> {
    ensure!(
        (1..=view::MAX_PAGE_SIZE).contains(&n),
        "limit must be between 1 and 100"
    );
    Ok(())
}
fn hash(s: &str) -> Result<[u8; 32]> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    ensure!(
        raw.len() == 64
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "snapshot hash must be 32-byte lowercase hex"
    );
    Ok(hex::decode(raw)?
        .try_into()
        .map_err(|_| anyhow!("snapshot hash length"))?)
}
fn require_current(at: Option<&str>, current_hash: [u8; 32]) -> Result<()> {
    if let Some(raw) = at {
        ensure!(
            hash(raw)? == current_hash,
            "canonical snapshot changed; refresh status"
        );
    }
    Ok(())
}
fn genesis<'a>(node: &'a NativeNode) -> Result<&'a RewardAccountsGenesis> {
    Ok(&node
        .config
        .network
        .reward_accounts()
        .ok_or_else(|| anyhow!("reward accounts are not configured on this network"))?
        .genesis)
}
fn block_record(
    g: &RewardAccountsGenesis,
    meta: &NativeBlockMeta,
) -> Result<wire::MandatoryRewardRecord> {
    ensure!(meta.height > 0, "genesis has no block reward record");
    let actions = decode_block_actions(meta)?;
    verify_decoded_action_root(&actions, meta, "reward explorer canonical action root")?;
    ensure!(actions.iter().filter(|a|a.family_id==FAMILY_SHIELDED_POOL && a.action_id==wire::REWARD_ACTION_ID).count()==1,"missing or duplicate mandatory reward record");
    let a = actions
        .last()
        .ok_or_else(|| anyhow!("missing final reward record"))?;
    ensure!(
        a.family_id == FAMILY_SHIELDED_POOL
            && a.action_id == wire::REWARD_ACTION_ID
            && a.binding.circuit == wire::CIRCUIT_VERSION
            && a.binding.crypto
                == protocol_versioning::launch_candidate::PRIVATE_SPEND_VERSION_BINDING.crypto
            && a.fee == 0
            && a.anchor == [0; 48]
            && a.nullifiers.is_empty()
            && a.commitments.is_empty()
            && a.ciphertext_hashes.is_empty()
            && a.ciphertext_sizes.is_empty()
            && a.candidate_artifact.is_none(),
        "invalid public reward record outer fields"
    );
    let r = wire::MandatoryRewardRecord::decode_native(&a.public_args)?;
    let fees = actions[..actions.len() - 1]
        .iter()
        .try_fold(0u64, |sum, a| {
            sum.checked_add(a.fee)
                .ok_or_else(|| anyhow!("miner fee overflow"))
        })?;
    ensure!(
        r.height == meta.height
            && r.context.chain_id == meta.chain_id
            && r.context.genesis_config_hash.as_bytes() == &g.commitment()?
            && r.subsidy == g.issuance()?.subsidy(meta.height)
            && r.miner_fees == fees,
        "reward record context/subsidy/fees differ from canonical block"
    );
    Ok(r)
}
fn active<'a>(
    node: &NativeNode,
    current_ledger: &'a Option<RewardAccountLedger>,
    tip: (u64, [u8; 32]),
) -> Result<(&'a RewardAccountLedger, [u64; 7], NativeBlockMeta)> {
    let g = genesis(node)?;
    let ledger = current_ledger.as_ref().ok_or_else(|| {
        anyhow!("canonical reward-account state is unavailable; runtime integration is not active")
    })?;
    let best = node.load_canonical_sync_block_at_height(tip.0)?;
    ensure!(best.hash == tip.1, "canonical account snapshot changed");
    ensure!(
        ledger.genesis() == g
            && ledger.height() == best.height
            && ledger.context().chain_id == node.config.chain_id()
            && node.hash_by_height(0)? == Some(ledger.context().genesis_hash)
            && node.hash_by_height(best.height)? == Some(best.hash),
        "reward ledger differs from canonical network/height"
    );
    ledger.context().validate(g)?;
    ensure!(
        best.supply_digest == u128::from(g.validate()?) + u128::from(ledger.issued()),
        "header supply differs from reward ledger"
    );
    let note = if best.height == 0 {
        let expected = genesis_meta_for_network(node.config.pow_bits, &node.config.network)?;
        ensure!(
            best.hash == expected.hash,
            "reward snapshot genesis identity differs"
        );
        transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes()[32]
    } else {
        let record = block_record(g, &best)?;
        ensure!(
            &record.context == ledger.context() && record.accounts_root == ledger.state_root(),
            "reward root/context differs from canonical block"
        );
        record.note_root
    };
    Ok((ledger, note, best))
}
pub(crate) fn dispatch(node: &NativeNode, method: &str, params: Value) -> Result<Value> {
    // Match the canonical writer's lock order. Reads cannot mix a newly
    // published tip with old height indexes or a different account snapshot.
    let _epoch = node.pending_action_persistence_lock.lock();
    let _store = node.block_store_persistence_lock.lock();
    let (tip, current_ledger) = {
        let state = node.state.read();
        (
            (state.best.height, state.best.hash),
            state.reward_accounts.clone(),
        )
    };
    match method {
        "hegemon_rewardAccountsStatus" => {
            let q: SnapshotQuery = query(params)?;
            require_current(q.at.as_deref(), tip.1)?;
            let Some(profile) = node.config.network.reward_accounts() else {
                ensure!(
                    current_ledger.is_none(),
                    "unexpected reward ledger on legacy network"
                );
                return Ok(
                    json!({"schema":view::SCHEMA,"configured":false,"active":false,
                    "reason":"network-does-not-use-reward-accounts","context":{"chain_id":hex::encode(node.config.chain_id()),
                    "height":tip.0.to_string(),"block_hash":hex::encode(tip.1)},
                    "parameters":null,"supply":null,"treasury":null,"governance":null}),
                );
            };
            if current_ledger.is_none() {
                return Ok(
                    json!({"schema":view::SCHEMA,"configured":true,"active":false,
                    "reason":"canonical-reward-state-unavailable","context":{"chain_id":hex::encode(node.config.chain_id()),
                    "height":tip.0.to_string(),"block_hash":hex::encode(tip.1)},
                    "parameters":view::parameters(&profile.genesis)?,"supply":null,"treasury":null,"governance":null}),
                );
            }
            let (ledger, note, best) = active(node, &current_ledger, tip)?;
            view::snapshot(ledger, best.hash, note)
        }
        "hegemon_rewardAccount" => {
            let q: AccountQuery = query(params)?;
            require_current(q.at.as_deref(), tip.1)?;
            ensure!(!q.address.is_empty(), "account address is required");
            let id = PublicAccountAddress::decode(&q.address, genesis(node)?.network)?.policy;
            let (ledger, note, _) = active(node, &current_ledger, tip)?;
            Ok(
                json!({"schema":view::SCHEMA,"context":view::context(ledger,tip.1,note)?,"account":view::account(ledger,id)?}),
            )
        }
        "hegemon_rewardAccountsGenesis" => {
            let q: GenesisQuery = query(params)?;
            limit(q.limit)?;
            require_current(q.at.as_deref(), tip.1)?;
            let g = genesis(node)?;
            let mut page = view::genesis_page(g, q.offset, q.limit)?;
            page["schema"] = json!(view::SCHEMA);
            page["chain_id"] = json!(hex::encode(node.config.chain_id()));
            page["genesis_hash"] = json!(hex::encode(
                node.hash_by_height(0)?
                    .ok_or_else(|| anyhow!("missing canonical genesis"))?
            ));
            Ok(page)
        }
        "hegemon_rewardAccountsActivity" => {
            let q: ActivityQuery = query(params)?;
            limit(q.limit)?;
            ensure!(
                q.from_height > 0,
                "genesis allocations use the genesis endpoint"
            );
            let (ledger, _, best) = active(node, &current_ledger, tip)?;
            activity(node, ledger, &best, q)
        }
        _ => Err(anyhow!("unknown reward-account explorer method")),
    }
}
fn activity(
    node: &NativeNode,
    ledger: &RewardAccountLedger,
    best: &NativeBlockMeta,
    q: ActivityQuery,
) -> Result<Value> {
    let g = ledger.genesis();
    let wanted = q
        .address
        .as_ref()
        .map(|s| PublicAccountAddress::decode(s, g.network).map(|a| a.policy))
        .transpose()?;
    let anchor = if let Some(raw) = q.at.as_deref() {
        let h = hash(raw)?;
        let meta = node
            .header_by_hash(&h)?
            .ok_or_else(|| anyhow!("unknown activity snapshot"))?;
        ensure!(
            node.hash_by_height(meta.height)? == Some(h) && meta.height <= best.height,
            "activity snapshot was reorganized; discard its cursor"
        );
        meta
    } else {
        best.clone()
    };
    activity_page(ledger, &anchor, &q, wanted, |height| {
        node.load_canonical_sync_block_at_height(height)
    })
}
/// The caller pins and authenticates the anchor and supplies canonical blocks.
/// Projection fixtures test traversal without granting any runtime authority.
fn activity_page(
    ledger: &RewardAccountLedger,
    anchor: &NativeBlockMeta,
    q: &ActivityQuery,
    wanted: Option<AccountPolicyId48>,
    mut load: impl FnMut(u64) -> Result<NativeBlockMeta>,
) -> Result<Value> {
    let g = ledger.genesis();
    ensure!(
        q.from_height <= anchor.height.saturating_add(1),
        "activity cursor exceeds snapshot"
    );
    ensure!(
        q.from_height <= anchor.height || q.action_index == 0,
        "invalid terminal activity cursor"
    );
    let mut rows = Vec::new();
    let mut height = q.from_height;
    let mut index = q.action_index;
    let mut scanned = 0;
    while height <= anchor.height && scanned < MAX_SCANNED_BLOCKS && rows.len() < q.limit {
        let meta = load(height)?;
        let record = block_record(g, &meta)?;
        ensure!(
            &record.context == ledger.context(),
            "activity block has foreign genesis context"
        );
        let actions = decode_block_actions(&meta)?;
        ensure!(index < actions.len(), "activity action index exceeds block");
        scanned += 1;
        while index < actions.len() && rows.len() < q.limit {
            let action = &actions[index];
            if let Some(mut event) = event(g, ledger.context(), &record, action, wanted)? {
                event["height"] = json!(height.to_string());
                event["block_hash"] = json!(hex::encode(meta.hash));
                event["action_index"] = json!(index);
                event["action_id"] = json!(hex::encode(action.tx_hash.as_bytes()));
                rows.push(event);
            }
            index += 1;
        }
        if index == actions.len() {
            height = height
                .checked_add(1)
                .ok_or_else(|| anyhow!("activity cursor height overflow"))?;
            index = 0;
        }
    }
    Ok(
        json!({"schema":view::SCHEMA,"chain_id":hex::encode(ledger.context().chain_id),
        "genesis_hash":hex::encode(ledger.context().genesis_hash),
        "anchor":{"height":anchor.height.to_string(),"block_hash":hex::encode(anchor.hash)},
        "rows":rows,"scanned_blocks":scanned,
        "next_cursor":if height<=anchor.height {Some(json!({"at":hex::encode(anchor.hash),"from_height":height.to_string(),"action_index":index,"address":q.address}))}else{None}}),
    )
}
fn event(
    g: &RewardAccountsGenesis,
    context: &AccountChainContext,
    reward: &wire::MandatoryRewardRecord,
    a: &PendingAction,
    wanted: Option<AccountPolicyId48>,
) -> Result<Option<Value>> {
    if a.family_id != FAMILY_SHIELDED_POOL {
        return Ok(None);
    }
    let pot = protocol_treasury_account_id();
    if a.action_id == wire::REWARD_ACTION_ID {
        if wanted.is_some_and(|id| id != pot && id != reward.miner) {
            return Ok(None);
        }
        let (miner, treasury) = reward_split(reward.subsidy, reward.miner_fees)?;
        let epoch = g.epochs()?.epoch_at(reward.height)?;
        let release_height = g.epochs()?.release_height(epoch)?;
        return Ok(Some(
            json!({"kind":"block-reward","miner_address":view::address(g,reward.miner)?,
            "treasury_address":view::address(g,pot)?,"subsidy_atoms":reward.subsidy.to_string(),
            "miner_fees_atoms":reward.miner_fees.to_string(),"miner_credit_atoms":miner.to_string(),
            "treasury_credit_atoms":treasury.to_string(),"earning_epoch":epoch.to_string(),"release_epoch":(epoch+2).to_string(),
            "release_height":release_height.to_string()}),
        ));
    }
    if !matches!(
        a.action_id,
        wire::CLAIM_ACTION_ID | wire::DONATION_ACTION_ID | wire::FORK_ACTION_ID
    ) {
        return Ok(None);
    }
    let decoded = wire::AccountNativeAction::decode_native(&a.public_args)?;
    ensure!(
        decoded.context() == context
            && decoded.action_id() == a.action_id
            && decoded.fee() == a.fee
            && a.binding.circuit == wire::CIRCUIT_VERSION
            && a.binding.crypto
                == protocol_versioning::launch_candidate::PRIVATE_SPEND_VERSION_BINDING.crypto,
        "canonical account action context/route/fee differs"
    );
    Ok(match decoded {
        wire::AccountNativeAction::Donation { donation, .. } => {
            if wanted.is_some_and(|id| id != pot) {
                None
            } else {
                Some(json!({"kind":"treasury-donation",
                "address":view::address(g,pot)?,"amount_atoms":donation.amount.to_string(),"fee_atoms":donation.fee.to_string(),
                "memo":std::str::from_utf8(&donation.memo)?,"first_claim_height":reward.height.checked_add(1).ok_or_else(||anyhow!("donation height overflow"))?.to_string()}))
            }
        }
        wire::AccountNativeAction::Claim { claim, policy, .. } => {
            if wanted.is_some_and(|id| id != claim.account) {
                None
            } else {
                Some(json!({
                    "kind":if claim.account==pot{"treasury-withdrawal"}else{"account-claim"},
                    "address":view::address(g,claim.account)?,"amount_atoms":claim.amount.to_string(),"fee_atoms":claim.fee.to_string(),
                    "sequence":claim.sequence.to_string(),"policy_generation":claim.policy_generation.to_string(),
                    "authorization":view::policy(&policy)?,
                    "recipient":wallet::NetworkShieldedAddress::from_bytes(&claim.recipient,g.network)?.encode()?,
                }))
            }
        }
        wire::AccountNativeAction::TreasuryFork { certificate } => {
            if wanted.is_some_and(|id| id != pot) {
                None
            } else {
                Some(json!({"kind":"treasury-signer-replacement",
                "address":view::address(g,pot)?,"current_generation":certificate.intent.current_generation.to_string(),
                "activation_height":certificate.intent.activation_height.to_string(),"successor_authority":view::policy(&certificate.intent.successor_policy)?,
                "successor_rules":hex::encode(certificate.intent.successor_rules.as_bytes()),
                "approval_count":certificate.approvals.len(),"certificate_digest":hex::encode(certificate.intent.authorization_digest())}))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reward_accounts_explorer_rpc_strict_queries_and_snapshot_binding() {
        assert!(query::<SnapshotQuery>(json!([])).is_ok());
        for bad in [
            json!({}),
            json!([{}, {}]),
            json!([null]),
            json!([{"unknown":1}]),
        ] {
            assert!(query::<SnapshotQuery>(bad).is_err());
        }
        for bad in [
            json!([{"limit":-1}]),
            json!([{"limit":0.5}]),
            json!([{"offset":-1}]),
        ] {
            assert!(query::<GenesisQuery>(bad).is_err());
        }
        assert_eq!(
            query::<ActivityQuery>(json!([{"from_height":"18446744073709551615"}]))
                .unwrap()
                .from_height,
            u64::MAX
        );
        for value in ["01", "-1", "1.0", "18446744073709551616"] {
            assert!(query::<ActivityQuery>(json!([{"from_height":value}])).is_err());
        }
        for n in [0, 101, usize::MAX] {
            assert!(limit(n).is_err());
        }
        assert_eq!(hash(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert_eq!(hash(&format!("0x{}", "ab".repeat(32))).unwrap(), [0xab; 32]);
        for s in ["AB".repeat(32), "a".repeat(63), "z".repeat(64)] {
            assert!(hash(&s).is_err());
        }
        let mut best = genesis_meta(super::super::super::NATIVE_DEV_POW_BITS).unwrap();
        best.hash = [3; 32];
        assert!(require_current(Some(&"03".repeat(32)), best.hash).is_ok());
        assert!(require_current(Some(&"04".repeat(32)), best.hash).is_err());
        for method in METHODS {
            assert!(rpc_method_allowed(RpcMethodPolicy::Safe, method));
            assert!(native_rpc_methods(RpcMethodPolicy::Safe).contains(method));
            assert!(!rpc_method_allowed(RpcMethodPolicy::Pool, method));
        }
    }
    struct RejectProofs;
    impl RewardAccountProofVerifier for RejectProofs {
        fn verify_claim(&self, _: &AccountClaim, _: &[u8]) -> Result<(), RewardAccountsError> {
            Err(RewardAccountsError::InvalidProof)
        }
        fn verify_donation(
            &self,
            _: &TreasuryDonation,
            _: &[u8],
        ) -> Result<(), RewardAccountsError> {
            Err(RewardAccountsError::InvalidProof)
        }
        fn verify_private_fee(
            &self,
            _: &AccountChainContext,
            _: u64,
            _: &[u8],
        ) -> Result<(), RewardAccountsError> {
            Err(RewardAccountsError::InvalidProof)
        }
    }
    fn history_fixture() -> (RewardAccountLedger, Vec<NativeBlockMeta>) {
        use crypto::{hash384::RulesHash48, ml_dsa::MlDsaSecretKey, traits::SigningKey};
        let key = MlDsaSecretKey::generate_deterministic(b"explorer history fixture");
        let next_key = MlDsaSecretKey::generate_deterministic(b"explorer history successor");
        let g = RewardAccountsGenesis {
            network: AddressNetwork {
                class: NetworkClass::Testnet,
                discriminator: [8; 32],
            },
            reward_epoch_blocks: 2,
            treasury_policy: AccountPolicy::single(&key.verify_key()),
            allocations: BoundedVec::default(),
        };
        let ctx = AccountChainContext {
            chain_id: [1; 32],
            genesis_hash: [2; 32],
            genesis_config_hash: RulesHash48::new(g.commitment().unwrap()),
        };
        let intent = TreasuryForkIntent {
            context: ctx.clone(),
            current_generation: 0,
            activation_height: 3,
            successor_rules: RulesHash48::new([3; 48]),
            successor_policy: AccountPolicy::single(&next_key.verify_key()),
        };
        let cert = TreasuryForkCertificate {
            approvals: BoundedVec::new(vec![AccountApproval::sign(
                0,
                &key,
                &intent.authorization_digest(),
            )])
            .unwrap(),
            intent,
        };
        let compiled = CompiledTreasuryFork {
            activation_height: 3,
            successor_rules: cert.intent.successor_rules,
            successor_policy: cert.intent.successor_policy.identifier().unwrap(),
        };
        let mut ledger = RewardAccountLedger::new(g, ctx).unwrap();
        let mut blocks = Vec::new();
        let miner = AccountPolicyId48::new([9; 48]);
        for h in 1..=12 {
            let native = wire::AccountNativeAction::TreasuryFork {
                certificate: cert.clone(),
            };
            let core = if h == 1 {
                vec![native.clone().into_account_action().unwrap()]
            } else {
                vec![]
            };
            let next = ledger
                .apply_block_with_fork(h, miner, &core, &RejectProofs, Some(&compiled))
                .unwrap();
            let reward =
                wire::MandatoryRewardRecord::from_transition(&ledger, &next, miner, [0; 7], 0)
                    .unwrap();
            let mut actions = Vec::new();
            if h == 1 {
                actions.push(pending(
                    wire::FORK_ACTION_ID,
                    native.encode_native().unwrap(),
                ));
            }
            actions.push(pending(
                wire::REWARD_ACTION_ID,
                reward.encode_native().unwrap(),
            ));
            // These are canonical-body projection fixtures, not mined headers.
            // Shared accounting and certificate signatures are checked above;
            // live RPC uses independently verified native block loaders.
            let mut meta = genesis_meta(NATIVE_DEV_POW_BITS).unwrap();
            meta.height = h;
            meta.chain_id = ledger.context().chain_id;
            meta.hash = [h as u8 + 10; 32];
            meta.supply_digest = u128::from(next.issued());
            meta.tx_count = actions.len() as u32;
            meta.extrinsics_root = actions_extrinsics_root(&actions);
            meta.action_bytes = actions.iter().map(Encode::encode).collect();
            blocks.push(meta);
            ledger = next;
        }
        (ledger, blocks)
    }
    fn pending(action_id: u16, public_args: Vec<u8>) -> PendingAction {
        let mut a = PendingAction {
            tx_hash: ActionId48::ZERO,
            binding: KernelVersionBinding {
                circuit: wire::CIRCUIT_VERSION,
                crypto: protocol_versioning::launch_candidate::PRIVATE_SPEND_VERSION_BINDING.crypto,
            },
            family_id: FAMILY_SHIELDED_POOL,
            action_id,
            anchor: [0; 48],
            nullifiers: vec![],
            commitments: vec![],
            ciphertext_hashes: vec![],
            ciphertext_sizes: vec![],
            public_args,
            fee: 0,
            candidate_artifact: None,
        };
        a.tx_hash = pending_action_hash(&a);
        a
    }
    #[test]
    fn reward_accounts_explorer_activity_cursor_counts_scanned_blocks_and_mid_block_rows() {
        let (ledger, blocks) = history_fixture();
        let anchor = blocks.last().unwrap();
        let page = |q: &ActivityQuery, wanted| {
            activity_page(&ledger, anchor, q, wanted, |h| {
                Ok(blocks[h as usize - 1].clone())
            })
            .unwrap()
        };
        let first = page(
            &ActivityQuery {
                limit: 1,
                ..Default::default()
            },
            None,
        );
        assert_eq!(first["rows"][0]["kind"], "treasury-signer-replacement");
        assert_eq!(first["next_cursor"]["from_height"], "1");
        assert_eq!(first["next_cursor"]["action_index"], 1);
        let second = page(
            &ActivityQuery {
                limit: 1,
                action_index: 1,
                ..Default::default()
            },
            None,
        );
        assert_eq!(second["rows"][0]["kind"], "block-reward");
        assert_eq!(second["next_cursor"]["from_height"], "2");
        assert_eq!(second["next_cursor"]["action_index"], 0);
        let empty = page(
            &ActivityQuery {
                limit: 100,
                ..Default::default()
            },
            Some(AccountPolicyId48::new([7; 48])),
        );
        assert_eq!(empty["scanned_blocks"], 8);
        assert!(empty["rows"].as_array().unwrap().is_empty());
        assert_eq!(empty["next_cursor"]["from_height"], "9");
        let last = page(
            &ActivityQuery {
                from_height: 9,
                limit: 100,
                ..Default::default()
            },
            None,
        );
        assert_eq!(last["rows"].as_array().unwrap().len(), 4);
        assert!(last["next_cursor"].is_null());
        assert!(activity_page(
            &ledger,
            anchor,
            &ActivityQuery {
                action_index: 99,
                ..Default::default()
            },
            None,
            |h| Ok(blocks[h as usize - 1].clone())
        )
        .is_err());
    }
    #[test]
    fn reward_accounts_explorer_canonical_body_mutations_fail_readback() {
        let (ledger, blocks) = history_fixture();
        let meta = &blocks[0];
        let r = block_record(ledger.genesis(), meta).unwrap();
        let actions = decode_block_actions(meta).unwrap();
        let projected = event(
            ledger.genesis(),
            ledger.context(),
            &r,
            actions.last().unwrap(),
            None,
        )
        .unwrap()
        .unwrap();
        assert!(projected.get("memo").is_none());
        assert_eq!(
            projected["treasury_credit_atoms"],
            (r.subsidy / 5).to_string()
        );
        assert_eq!(projected["release_height"], "5");
        let mut bad = meta.clone();
        bad.action_bytes[0][0] ^= 1;
        assert!(block_record(ledger.genesis(), &bad).is_err());
        let mut bad = meta.clone();
        let mut actions = decode_block_actions(meta).unwrap();
        let end = actions.len() - 1;
        actions[end].fee = 1;
        actions[end].tx_hash = pending_action_hash(&actions[end]);
        bad.action_bytes = actions.iter().map(Encode::encode).collect();
        bad.extrinsics_root = actions_extrinsics_root(&actions);
        assert!(block_record(ledger.genesis(), &bad).is_err());
        let mut foreign = ledger.genesis().clone();
        foreign.reward_epoch_blocks = 3;
        assert!(block_record(&foreign, meta).is_err());
    }
}
