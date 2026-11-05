//! Wallet-owned public account identity, real claim packages and offline approvals.
//! No private key leaves this process. Submission remains a separate native step.
use super::*;
use codec::{Decode, Encode};
use protocol_reward_accounts::*;
use serde_json::json;
use synthetic_crypto::{
    hash384::{ProofCommitment48, RulesHash48},
    traits::{SigningKey, VerifyKey},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentityParams {
    network: AddressNetwork,
    expected_genesis_hash: String,
    #[serde(default)]
    index: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClaimParams {
    ws_url: String,
    expected_chain_id: String,
    expected_genesis_hash: String,
    amount_atoms: String,
    fee_atoms: String,
    recipient: Option<String>,
    #[serde(default)]
    treasury: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DonationParams {
    ws_url: String,
    expected_chain_id: String,
    expected_genesis_hash: String,
    amount_atoms: String,
    fee_atoms: String,
    #[serde(default)]
    memo: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewParams {
    network: AddressNetwork,
    expected_context: AccountContextJson,
    kind: String,
    intent_hex: String,
    policy: AccountPolicy,
    carrier_hex: Option<String>,
    approved_digest: Option<String>,
    expected_authority_hash: Option<String>,
    expected_policy_generation: Option<String>,
    #[serde(default)]
    approvals: Vec<AccountApproval>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountContextJson {
    chain_id: String,
    genesis_hash: String,
    genesis_config_hash: String,
}
fn bytes<const N: usize>(s: &str) -> Result<[u8; N]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    anyhow::ensure!(s.len() == N * 2, "invalid identity length");
    let raw = hex::decode(s)?;
    Ok(raw
        .try_into()
        .map_err(|_| anyhow!("invalid identity width"))?)
}
fn atom(s: &str) -> Result<u64> {
    anyhow::ensure!(
        !s.is_empty()
            && s.len() <= 20
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0')),
        "amount must be an exact unsigned atom string"
    );
    let n = s.parse::<u64>()?;
    anyhow::ensure!(n <= MAX_SUPPLY, "amount exceeds HGN cap");
    Ok(n)
}
fn bound(store: &WalletStore, genesis: [u8; 32]) -> Result<()> {
    anyhow::ensure!(genesis != [0; 32], "expected genesis is required");
    if let Some(own) = store.genesis_hash()? {
        anyhow::ensure!(own==genesis,"Wallet belongs to another genesis. Recover keys into a separate wallet for this network.");
    }
    Ok(())
}
fn key(
    store: &WalletStore,
    network: AddressNetwork,
) -> Result<synthetic_crypto::ml_dsa::MlDsaSecretKey> {
    let root = Zeroizing::new(store.signing_seed()?);
    Ok(wallet::reward_identity::derive_reward_account_key(
        &root, network, 0,
    )?)
}
fn identity(store: &WalletStore, p: IdentityParams) -> Result<Value> {
    bound(store, bytes(&p.expected_genesis_hash)?)?;
    p.network.validate()?;
    anyhow::ensure!(
        p.index == 0,
        "this release exposes only the default reward account"
    );
    let k = key(store, p.network)?;
    let pk = k.verify_key();
    let policy = AccountPolicy::single(&pk);
    let address = PublicAccountAddress {
        network: p.network,
        policy: policy.identifier()?,
    }
    .encode()?;
    let recipient =
        wallet::NetworkShieldedAddress::from_recipient(p.network, store.private_spend_address(0)?)?
            .encode()?;
    Ok(
        json!({"network":p.network,"accountAddress":address,"shieldedAddress":recipient,"policy":policy,
        "signerKeyHash":hex::encode(account_key_hash(&pk).as_bytes()),"publicKey":hex::encode(pk.to_bytes()),
        "derivationVersion":1,"index":0,"backup":"existing-encrypted-wallet-root","submissionAvailable":false}),
    )
}
fn context_json(c: &AccountChainContext) -> Value {
    json!({"chainId":hex::encode(c.chain_id),"genesisHash":hex::encode(c.genesis_hash),"genesisConfigHash":hex::encode(c.genesis_config_hash.as_bytes())})
}
async fn selected(
    store: &WalletStore,
    url: &str,
    chain: &str,
    genesis: &str,
) -> Result<(NodeRpcClient, Value, AddressNetwork, AccountChainContext)> {
    let client = NodeRpcClient::connect(url).await?;
    let s = client
        .reward_accounts_read("hegemon_rewardAccountsStatus", json!({}))
        .await?;
    anyhow::ensure!(
        s["schema"] == "hegemon.native.reward-accounts.explorer.v1" && s["active"] == true,
        "This node has no active reward accounts."
    );
    let c = &s["context"];
    let ctx = AccountChainContext {
        chain_id: bytes(
            c["chain_id"]
                .as_str()
                .ok_or_else(|| anyhow!("node chain id missing"))?,
        )?,
        genesis_hash: bytes(
            c["genesis_hash"]
                .as_str()
                .ok_or_else(|| anyhow!("node genesis missing"))?,
        )?,
        genesis_config_hash: RulesHash48::new(bytes(
            c["genesis_config_hash"]
                .as_str()
                .ok_or_else(|| anyhow!("genesis configuration missing"))?,
        )?),
    };
    anyhow::ensure!(
        ctx.chain_id == bytes(chain)? && ctx.genesis_hash == bytes(genesis)?,
        "Selected chain/genesis changed. Refresh before continuing."
    );
    bound(store, ctx.genesis_hash)?;
    let network: AddressNetwork = serde_json::from_value(s["parameters"]["network"].clone())?;
    network.validate()?;
    Ok((client, s, network, ctx))
}
fn authority(v: &Value) -> Result<AccountPolicy> {
    let keys = v["signer_key_hashes"]
        .as_array()
        .ok_or_else(|| anyhow!("signer hashes absent"))?
        .iter()
        .map(|s| {
            Ok(AccountKeyHash48::new(bytes(
                s.as_str().ok_or_else(|| anyhow!("invalid signer hash"))?,
            )?))
        })
        .collect::<Result<Vec<_>>>()?;
    let n = v["required"]
        .as_u64()
        .and_then(|n| u8::try_from(n).ok())
        .ok_or_else(|| anyhow!("invalid quorum"))?;
    let expected = bytes::<48>(
        v["policy_hash"]
            .as_str()
            .ok_or_else(|| anyhow!("policy hash missing"))?,
    )?;
    if keys.len() == 1 && n == 1 {
        let p = AccountPolicy::SingleKey { key_hash: keys[0] };
        if p.identifier()?.as_bytes() == &expected {
            return Ok(p);
        }
    }
    let p = AccountPolicy::threshold(n, keys)?;
    anyhow::ensure!(
        p.identifier()?.as_bytes() == &expected,
        "committee descriptor hash mismatch"
    );
    Ok(p)
}
async fn prepare_claim(store: &WalletStore, p: ClaimParams) -> Result<Value> {
    let (client, s, network, ctx) = selected(
        store,
        &p.ws_url,
        &p.expected_chain_id,
        &p.expected_genesis_hash,
    )
    .await?;
    let k = key(store, network)?;
    let pk = k.verify_key();
    let single = AccountPolicy::single(&pk);
    let (id, policy, generation) = if p.treasury {
        (
            protocol_treasury_account_id(),
            authority(&s["governance"]["authority"])?,
            s["governance"]["policy_generation"]
                .as_str()
                .ok_or_else(|| anyhow!("policy generation missing"))?
                .parse::<u64>()?,
        )
    } else {
        (single.identifier()?, single, 0)
    };
    let index = policy
        .signer_hashes()
        .iter()
        .position(|h| *h == account_key_hash(&pk))
        .ok_or_else(|| anyhow!("This wallet is not a signer for the selected treasury policy."))?;
    let address = PublicAccountAddress {
        network,
        policy: id,
    }
    .encode()?;
    let row = client
        .reward_accounts_read(
            "hegemon_rewardAccount",
            json!({"address":address,"at":s["context"]["block_hash"]}),
        )
        .await?;
    anyhow::ensure!(
        row["context"] == s["context"],
        "Account snapshot changed. Refresh."
    );
    let amount = atom(&p.amount_atoms)?;
    let fee = atom(&p.fee_atoms)?;
    anyhow::ensure!(
        amount > 0
            && amount.checked_add(fee).is_some_and(|d| d
                <= atom(
                    row["account"]["claimable_next_block_atoms"]
                        .as_str()
                        .unwrap_or("")
                )
                .unwrap_or(0)),
        "Claim amount plus fee exceeds available account balance."
    );
    let recipient = match p.recipient {
        Some(a) => wallet::NetworkShieldedAddress::decode(&a, network)?,
        None => wallet::NetworkShieldedAddress::from_recipient(
            network,
            store.private_spend_address(0)?,
        )?,
    };
    let root = s["context"]["note_root"]
        .as_array()
        .ok_or_else(|| anyhow!("canonical note root missing"))?
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| anyhow!("note root must use exact strings"))?
                .parse::<u64>()
                .map_err(Into::into)
        })
        .collect::<Result<Vec<_>>>()?;
    let reference = wallet::private_spend_build::SpendReference {
        chain_id: ctx.chain_id,
        parent_hash: bytes(s["context"]["block_hash"].as_str().unwrap_or(""))?,
        parent_height: s["context"]["height"]
            .as_str()
            .ok_or_else(|| anyhow!("height missing"))?
            .parse()?,
        merkle_root: root.try_into().map_err(|_| anyhow!("note root width"))?,
    };
    let sequence = row["account"]["next_sequence"]
        .as_str()
        .ok_or_else(|| anyhow!("sequence missing"))?
        .parse()?;
    let prepared = wallet::reward_spend::prepare_account_claim_for_network(
        network,
        ctx.clone(),
        reference,
        wallet::reward_spend::AccountClaimRequest {
            account: id,
            policy_generation: generation,
            sequence,
            amount,
            fee,
            recipient,
        },
    )?;
    let carrier = prepared.prove()?;
    let claim = prepared.claim();
    let approval = AccountApproval::sign(index as u8, &k, &claim.authorization_digest());
    Ok(
        json!({"kind":"claim","network":network,"expectedContext":context_json(&ctx),"policy":policy,
        "intentHex":hex::encode(claim.encode()),"carrierHex":hex::encode(carrier.encode_carrier()?),"approvals":[approval],
        "digest":hex::encode(claim.authorization_digest()),"amountAtoms":amount.to_string(),"feeAtoms":fee.to_string(),
        "sequence":sequence.to_string(),"policyGeneration":generation.to_string(),"address":address,
        "referenceHeight":reference.parent_height.to_string(),"requiredApprovals":policy.required(),"submitted":false}),
    )
}
async fn donation_review(store: &WalletStore, p: DonationParams) -> Result<Value> {
    let (_, s, network, ctx) = selected(
        store,
        &p.ws_url,
        &p.expected_chain_id,
        &p.expected_genesis_hash,
    )
    .await?;
    let amount = atom(&p.amount_atoms)?;
    let fee = atom(&p.fee_atoms)?;
    anyhow::ensure!(
        amount > 0 && amount.checked_add(fee).is_some_and(|v| v <= MAX_SUPPLY),
        "Invalid donation amount plus fee."
    );
    let donation = TreasuryDonation {
        context: ctx.clone(),
        amount,
        fee,
        memo: BoundedVec::new(p.memo.into_bytes())
            .map_err(|_| anyhow!("Public memo exceeds 256 UTF-8 bytes."))?,
    };
    Ok(
        json!({"kind":"treasury-donation-review","network":network,"expectedContext":context_json(&ctx),
        "address":s["parameters"]["treasury_address"],"amountAtoms":amount.to_string(),"feeAtoms":fee.to_string(),
        "memo":std::str::from_utf8(&donation.memo)?,"publicAmountAndMemo":true,"intentHex":hex::encode(donation.encode()),
        "proofPrepared":false,"submitted":false,"submissionAvailable":false}),
    )
}
fn decode_exact<T: Decode + Encode>(s: &str) -> Result<T> {
    anyhow::ensure!(s.len() <= 128 * 1024, "intent exceeds size limit");
    let raw = hex::decode(s)?;
    let mut cursor = raw.as_slice();
    let value = T::decode(&mut cursor).map_err(|_| anyhow!("Invalid canonical intent"))?;
    anyhow::ensure!(
        cursor.is_empty() && value.encode() == raw,
        "Noncanonical intent"
    );
    Ok(value)
}
fn check_current_authority(p: &ReviewParams, generation: u64) -> Result<()> {
    let expected = p
        .expected_authority_hash
        .as_deref()
        .ok_or_else(|| anyhow!("Select the current treasury authority independently"))?;
    anyhow::ensure!(
        p.policy.identifier()?.as_bytes() == &bytes::<48>(expected)?,
        "Treasury policy differs from selected current authority"
    );
    let expected_generation = p
        .expected_policy_generation
        .as_deref()
        .ok_or_else(|| anyhow!("Select current policy generation independently"))?;
    anyhow::ensure!(
        generation == expected_generation.parse::<u64>()?,
        "Stale treasury policy generation"
    );
    Ok(())
}
fn review(store: &WalletStore, p: ReviewParams, sign: bool) -> Result<Value> {
    p.network.validate()?;
    let ctx = AccountChainContext {
        chain_id: bytes(&p.expected_context.chain_id)?,
        genesis_hash: bytes(&p.expected_context.genesis_hash)?,
        genesis_config_hash: RulesHash48::new(bytes(&p.expected_context.genesis_config_hash)?),
    };
    anyhow::ensure!(
        ctx.chain_id != [0; 32] && ctx.genesis_config_hash != RulesHash48::ZERO,
        "Expected chain and genesis configuration required"
    );
    bound(store, ctx.genesis_hash)?;
    p.policy.validate()?;
    let (digest, details) = match p.kind.as_str() {
        "claim" => {
            let claim: AccountClaim = decode_exact(&p.intent_hex)?;
            anyhow::ensure!(
                claim.context == ctx
                    && (claim.account == p.policy.identifier()?
                        || claim.account == protocol_treasury_account_id()),
                "Claim differs from independently selected context/policy."
            );
            if claim.account == protocol_treasury_account_id() {
                check_current_authority(&p, claim.policy_generation)?;
            }
            let addr = wallet::NetworkShieldedAddress::from_bytes(&claim.recipient, p.network)?;
            let raw = p
                .carrier_hex
                .as_ref()
                .ok_or_else(|| anyhow!("Claim payout proof is required for signing review"))?;
            anyhow::ensure!(
                raw.len() <= 2 * transaction_circuit::reward_account_spend::MAX_CARRIER_BYTES,
                "Payout proof exceeds cap"
            );
            let carrier =
                transaction_circuit::reward_account_spend::RewardSpendCarrier::decode_exact(
                    &hex::decode(raw)?,
                )?;
            let (recipient, auth) =
                wallet::reward_spend::claim_recipient_binding(addr.recipient())?;
            anyhow::ensure!(
                carrier.public.claim == 1
                    && carrier.public.amount == claim.amount
                    && carrier.public.base.fee == claim.fee
                    && carrier.public.operation_binding == claim.operation_binding()
                    && carrier.public.payout_binding() == claim.payout_binding.into_bytes()
                    && carrier.public.base.chain_id == ctx.chain_id
                    && carrier.public.recipient_key == recipient
                    && carrier.public.recipient_authority == auth
                    && claim.amount > 0
                    && claim
                        .amount
                        .checked_add(claim.fee)
                        .is_some_and(|d| d <= MAX_SUPPLY)
                    && claim.payout_binding != ProofCommitment48::ZERO,
                "Payout proof does not match reviewed claim"
            );
            carrier.verify()?;
            (
                claim.authorization_digest(),
                json!({"amountAtoms":claim.amount.to_string(),"feeAtoms":claim.fee.to_string(),"recipient":addr.encode()?,
                "sequence":claim.sequence.to_string(),"policyGeneration":claim.policy_generation.to_string(),"account":PublicAccountAddress{network:p.network,policy:claim.account}.encode()?}),
            )
        }
        "treasury-fork" => {
            let intent: TreasuryForkIntent = decode_exact(&p.intent_hex)?;
            check_current_authority(&p, intent.current_generation)?;
            intent.successor_policy.validate()?;
            anyhow::ensure!(
                intent.context == ctx
                    && intent.activation_height > 0
                    && intent.successor_rules != RulesHash48::ZERO
                    && intent.successor_policy.required() == p.policy.required()
                    && intent.successor_policy.signer_hashes().len()
                        == p.policy.signer_hashes().len()
                    && intent.successor_policy.identifier()? != p.policy.identifier()?,
                "Invalid signer replacement context/quorum"
            );
            (
                intent.authorization_digest(),
                json!({"activationHeight":intent.activation_height.to_string(),"currentGeneration":intent.current_generation.to_string(),
                "successorPolicy":intent.successor_policy,"successorRules":hex::encode(intent.successor_rules.as_bytes())}),
            )
        }
        _ => anyhow::bail!("Unsupported intent kind"),
    };
    anyhow::ensure!(
        p.approvals.len() <= p.policy.signer_hashes().len()
            && p.approvals
                .windows(2)
                .all(|w| w[0].signer_index < w[1].signer_index),
        "Duplicate, unordered or excessive approvals"
    );
    for approval in &p.approvals {
        let pk = synthetic_crypto::ml_dsa::MlDsaPublicKey::from_bytes(&approval.public_key)?;
        let signature = synthetic_crypto::ml_dsa::MlDsaSignature::from_bytes(&approval.signature)?;
        anyhow::ensure!(
            p.policy.signer_hashes().get(approval.signer_index as usize)
                == Some(&account_key_hash(&pk)),
            "Approval key is outside the reviewed policy"
        );
        pk.verify(&digest, &signature)?;
    }
    let approval = if sign {
        anyhow::ensure!(
            p.approved_digest.as_deref() == Some(hex::encode(digest).as_str()),
            "Review and confirm the exact intent digest before signing."
        );
        let k = key(store, p.network)?;
        let own = account_key_hash(&k.verify_key());
        let index = p
            .policy
            .signer_hashes()
            .iter()
            .position(|h| *h == own)
            .ok_or_else(|| anyhow!("This wallet is not a signer in the reviewed policy."))?;
        anyhow::ensure!(
            !p.approvals.iter().any(|a| a.signer_index as usize == index),
            "This signer already approved the package"
        );
        Some(AccountApproval::sign(index as u8, &k, &digest))
    } else {
        None
    };
    let mut approvals = p.approvals;
    if let Some(ref a) = approval {
        approvals.push(a.clone());
        approvals.sort_by_key(|a| a.signer_index);
    }
    let complete = approvals.len() >= p.policy.required();
    if complete {
        p.policy.verify(&digest, &approvals)?;
    }
    Ok(
        json!({"kind":p.kind,"intentHex":p.intent_hex,"carrierHex":p.carrier_hex,"network":p.network,"approvals":approvals,"requiredApprovals":p.policy.required(),"quorumComplete":complete,"digest":hex::encode(digest),"details":details,"policy":p.policy,"expectedContext":context_json(&ctx),
        "approval":approval,"canonicalInclusionChecked":false,"submitted":false}),
    )
}
pub(super) fn handle(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    method: &str,
    params: Value,
) -> WalletdResult<Value> {
    let result = (|| -> Result<Value> {
        match method {
            "reward.identity" => identity(&store, serde_json::from_value(params)?),
            "reward.recover" => {
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase", deny_unknown_fields)]
                struct Recovery {
                    destination: String,
                    passphrase: String,
                }
                anyhow::ensure!(
                    store.mode()? == WalletMode::Full,
                    "Watch-only wallets cannot recover signing keys"
                );
                let p: Recovery = serde_json::from_value(params)?;
                let pass = Zeroizing::new(p.passphrase);
                anyhow::ensure!(
                    pass.len() >= 12,
                    "New wallet passphrase must have at least 12 characters"
                );
                let recovered =
                    store.recover_unlocked_keys_to_fresh_wallet(&p.destination, &pass)?;
                drop(recovered);
                Ok(
                    json!({"destination":p.destination,"sourceUnchanged":true,"historyCopied":false}),
                )
            }
            "reward.prepareClaim" => {
                runtime.block_on(prepare_claim(&store, serde_json::from_value(params)?))
            }
            "reward.reviewDonation" => {
                runtime.block_on(donation_review(&store, serde_json::from_value(params)?))
            }
            "reward.reviewIntent" => review(&store, serde_json::from_value(params)?, false),
            "reward.signIntent" => review(&store, serde_json::from_value(params)?, true),
            _ => anyhow::bail!("Unknown reward wallet method"),
        }
    })();
    result.map_err(|e| WalletdError::new(WalletdErrorCode::InvalidParams, e.to_string()))
}

/// These methods prepare/review public artifacts; native admission is separate.
pub(super) const HELP:&str = "Reward-account wallet methods (walletd --store PATH --request-file JSON):
  reward.identity: network, expectedGenesisHash; returns root-backed public account and shielded recipient
  reward.prepareClaim: wsUrl, expectedChainId, expectedGenesisHash, amountAtoms, feeAtoms, treasury?
    Builds a real payout proof and one local approval; exports only, never submits.
  reward.reviewDonation: same selected context, amountAtoms, feeAtoms, memo
    Public amount/memo review only; no proof, reservation, or submission.
  reward.reviewIntent / reward.signIntent: network, expectedContext, kind, intentHex, policy,
    carrierHex (claims), expectedAuthorityHash/expectedPolicyGeneration (treasury), approvedDigest (sign).
    Independently select the current context/authority. Offline review is not canonical inclusion.
  reward.recover: destination, passphrase; creates a separate encrypted wallet retaining keys,
    not historical balances. Full wallets only. Existing destinations are never overwritten.
Amounts are canonical integer atom strings (8 decimals/HGN). Full wallet/passphrase required for signing.
Back up the encrypted wallet file and its passphrase; default reward authority uses its existing root.
Successor submission is unavailable until the native account runtime is integrated.";

#[cfg(test)]
mod tests {
    use super::*;
    use synthetic_crypto::ml_dsa::MlDsaSecretKey;

    fn fixture() -> (
        std::path::PathBuf,
        WalletStore,
        AddressNetwork,
        AccountChainContext,
    ) {
        let path = std::env::temp_dir().join(format!(
            "reward-ux-{}-{}.wallet",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = WalletStore::create_from_root(
            &path,
            "test-only-passphrase",
            wallet::RootSecret::from_bytes([8; 32]),
        )
        .unwrap();
        let network = AddressNetwork {
            class: NetworkClass::Testnet,
            discriminator: [9; 32],
        };
        let context = AccountChainContext {
            chain_id: [1; 32],
            genesis_hash: [2; 32],
            genesis_config_hash: RulesHash48::new([3; 48]),
        };
        store.set_genesis_hash(context.genesis_hash).unwrap();
        (path, store, network, context)
    }
    fn fork_params(
        store: &WalletStore,
        network: AddressNetwork,
        context: &AccountChainContext,
    ) -> (Value, AccountPolicy, TreasuryForkIntent) {
        let owner = key(store, network).unwrap();
        let policy = AccountPolicy::single(&owner.verify_key());
        let next = MlDsaSecretKey::generate_deterministic(&[55; 48]);
        let intent = TreasuryForkIntent {
            context: context.clone(),
            current_generation: 0,
            activation_height: 100,
            successor_rules: RulesHash48::new([6; 48]),
            successor_policy: AccountPolicy::single(&next.verify_key()),
        };
        (
            json!({"network":network,"expectedContext":context_json(context),"expectedAuthorityHash":hex::encode(policy.identifier().unwrap().as_bytes()),"expectedPolicyGeneration":"0","kind":"treasury-fork","intentHex":hex::encode(intent.encode()),"policy":policy}),
            policy,
            intent,
        )
    }
    #[test]
    fn reward_ux_identity_backup_recovery_preserves_keys_and_source_and_rejects_wrong_genesis() {
        let (path, store, network, context) = fixture();
        let p = || IdentityParams {
            network,
            expected_genesis_hash: hex::encode(context.genesis_hash),
            index: 0,
        };
        let first = identity(&store, p()).unwrap();
        assert!(first.get("privateKey").is_none());
        assert_eq!(first["submissionAvailable"], false);
        PublicAccountAddress::decode(first["accountAddress"].as_str().unwrap(), network).unwrap();
        wallet::NetworkShieldedAddress::decode(first["shieldedAddress"].as_str().unwrap(), network)
            .unwrap();
        let issued = store.private_spend_address(37).unwrap();
        let before = std::fs::read(&path).unwrap();
        let dest = path.with_extension("recovered");
        let recovered = store
            .recover_unlocked_keys_to_fresh_wallet(&dest, "new-test-passphrase")
            .unwrap();
        assert_eq!(
            identity(&recovered, p()).unwrap()["accountAddress"],
            first["accountAddress"]
        );
        assert_eq!(
            identity(&recovered, p()).unwrap()["shieldedAddress"],
            first["shieldedAddress"]
        );
        assert_eq!(issued, recovered.private_spend_address(37).unwrap());
        assert_eq!(recovered.genesis_hash().unwrap(), None);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(store
            .recover_unlocked_keys_to_fresh_wallet(&path, "cannot-overwrite")
            .is_err());
        assert!(store
            .recover_unlocked_keys_to_fresh_wallet(&dest, "cannot-overwrite")
            .is_err());
        assert!(identity(
            &store,
            IdentityParams {
                expected_genesis_hash: hex::encode([4; 32]),
                ..p()
            }
        )
        .is_err());
        let view_path = path.with_extension("watch");
        let watch = WalletStore::import_viewing_key(
            &view_path,
            "view-only-passphrase",
            store.incoming_key().unwrap(),
        )
        .unwrap();
        assert!(identity(&watch, p()).is_err());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(handle(&runtime,Arc::new(watch),"reward.recover",json!({"destination":path.with_extension("watch-recovery"),"passphrase":"new-password-test"})).is_err());
        drop(recovered);
        drop(store);
        for p in [path, dest, view_path] {
            let _ = std::fs::remove_file(p);
        }
    }
    #[test]
    fn reward_ux_review_signs_exact_fork_and_rejects_mutations_stale_policy_and_outsider() {
        let (path, store, network, context) = fixture();
        let (params, policy, intent) = fork_params(&store, network, &context);
        let reviewed = review(
            &store,
            serde_json::from_value(params.clone()).unwrap(),
            false,
        )
        .unwrap();
        assert_eq!(reviewed["canonicalInclusionChecked"], false);
        assert_eq!(reviewed["submitted"], false);
        let mut signed_params = params.clone();
        signed_params["approvedDigest"] = reviewed["digest"].clone();
        let signed = review(
            &store,
            serde_json::from_value(signed_params.clone()).unwrap(),
            true,
        )
        .unwrap();
        let approval: AccountApproval = serde_json::from_value(signed["approval"].clone()).unwrap();
        policy
            .verify(
                &intent.authorization_digest(),
                std::slice::from_ref(&approval),
            )
            .unwrap();
        let mut duplicate = params.clone();
        duplicate["approvals"] = json!([approval.clone(), approval.clone()]);
        assert!(review(&store, serde_json::from_value(duplicate).unwrap(), false).is_err());
        let mut repeated = signed_params.clone();
        repeated["approvals"] = json!([approval.clone()]);
        assert!(review(
            &store,
            serde_json::from_value(repeated.clone()).unwrap(),
            true
        )
        .is_err());
        assert_eq!(
            review(&store, serde_json::from_value(repeated).unwrap(), false).unwrap()
                ["quorumComplete"],
            true
        );
        let mut altered = intent.clone();
        altered.activation_height += 1;
        let mut p = signed_params.clone();
        p["intentHex"] = hex::encode(altered.encode()).into();
        assert!(review(&store, serde_json::from_value(p).unwrap(), true).is_err());
        for (field, value) in [
            ("approvedDigest", json!(hex::encode([0; 48]))),
            ("expectedPolicyGeneration", json!("1")),
            ("expectedAuthorityHash", json!(hex::encode([9; 48]))),
        ] {
            let mut p = signed_params.clone();
            p[field] = value;
            assert!(review(&store, serde_json::from_value(p).unwrap(), true).is_err());
        }
        let mut p = signed_params.clone();
        p["expectedContext"]["chainId"] = hex::encode([4; 32]).into();
        assert!(review(&store, serde_json::from_value(p).unwrap(), true).is_err());
        let outsider = MlDsaSecretKey::generate_deterministic(&[77; 48]);
        let other = AccountPolicy::single(&outsider.verify_key());
        let mut p = signed_params.clone();
        p["policy"] = serde_json::to_value(&other).unwrap();
        p["expectedAuthorityHash"] = hex::encode(other.identifier().unwrap().as_bytes()).into();
        assert!(review(&store, serde_json::from_value(p).unwrap(), true).is_err());
        let mut p = signed_params.clone();
        p["intentHex"] = format!("{}00", p["intentHex"].as_str().unwrap()).into();
        assert!(review(&store, serde_json::from_value(p).unwrap(), true).is_err());
        let mut p = signed_params;
        p["intentHex"] = hex::encode(altered.encode()).into();
        p["approvedDigest"] = hex::encode(altered.authorization_digest()).into();
        let signed = review(&store, serde_json::from_value(p).unwrap(), true).unwrap();
        let mutated_approval: AccountApproval =
            serde_json::from_value(signed["approval"].clone()).unwrap();
        assert!(policy
            .verify(&intent.authorization_digest(), &[mutated_approval])
            .is_err());
        drop(store);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn reward_ux_refuses_claim_without_real_payout_and_noncanonical_amounts() {
        let (path, store, network, context) = fixture();
        let owner = key(&store, network).unwrap();
        let policy = AccountPolicy::single(&owner.verify_key());
        let recipient = wallet::NetworkShieldedAddress::from_recipient(
            network,
            store.private_spend_address(0).unwrap(),
        )
        .unwrap();
        let claim = AccountClaim {
            context: context.clone(),
            account: policy.identifier().unwrap(),
            policy_generation: 0,
            sequence: 0,
            amount: 100,
            fee: 1,
            recipient: BoundedVec::new(recipient.to_bytes().unwrap()).unwrap(),
            payout_binding: ProofCommitment48::new([1; 48]),
        };
        let mut p = json!({"network":network,"expectedContext":context_json(&context),"kind":"claim","policy":policy,"intentHex":hex::encode(claim.encode())});
        assert!(
            review(&store, serde_json::from_value(p.clone()).unwrap(), false)
                .unwrap_err()
                .to_string()
                .contains("proof is required")
        );
        p["carrierHex"] = json!("00010203");
        assert!(review(&store, serde_json::from_value(p).unwrap(), false).is_err());
        for s in [
            "01",
            "-1",
            "1.0",
            "1e8",
            "18446744073709551616",
            "2100000000000001",
        ] {
            assert!(atom(s).is_err());
        }
        assert_eq!(atom("2100000000000000").unwrap(), MAX_SUPPLY);
        drop(store);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn reward_ux_collects_verified_partial_quorum_without_counting_duplicate_signers() {
        let (path, store, network, context) = fixture();
        let own = key(&store, network).unwrap();
        let peer = MlDsaSecretKey::generate_deterministic(&[71; 48]);
        let third = MlDsaSecretKey::generate_deterministic(&[72; 48]);
        let policy = AccountPolicy::threshold(
            2,
            vec![
                account_key_hash(&own.verify_key()),
                account_key_hash(&peer.verify_key()),
                account_key_hash(&third.verify_key()),
            ],
        )
        .unwrap();
        let next: Vec<_> = (80..83)
            .map(|i| MlDsaSecretKey::generate_deterministic(&[i; 48]))
            .collect();
        let intent = TreasuryForkIntent {
            context: context.clone(),
            current_generation: 0,
            activation_height: 100,
            successor_rules: RulesHash48::new([7; 48]),
            successor_policy: AccountPolicy::threshold(
                2,
                next.iter()
                    .map(|k| account_key_hash(&k.verify_key()))
                    .collect(),
            )
            .unwrap(),
        };
        let digest = intent.authorization_digest();
        let peer_index = policy
            .signer_hashes()
            .iter()
            .position(|h| *h == account_key_hash(&peer.verify_key()))
            .unwrap();
        let first = AccountApproval::sign(peer_index as u8, &peer, &digest);
        let p = json!({"network":network,"expectedContext":context_json(&context),"kind":"treasury-fork","policy":policy,"intentHex":hex::encode(intent.encode()),"expectedAuthorityHash":hex::encode(policy.identifier().unwrap().as_bytes()),"expectedPolicyGeneration":"0","approvals":[first],"approvedDigest":hex::encode(digest)});
        assert_eq!(
            review(&store, serde_json::from_value(p.clone()).unwrap(), false).unwrap()
                ["quorumComplete"],
            false
        );
        let complete = review(&store, serde_json::from_value(p).unwrap(), true).unwrap();
        assert_eq!(complete["quorumComplete"], true);
        let approvals: Vec<AccountApproval> =
            serde_json::from_value(complete["approvals"].clone()).unwrap();
        assert_eq!(approvals.len(), 2);
        policy.verify(&digest, &approvals).unwrap();
        drop(store);
        let _ = std::fs::remove_file(path);
    }
    #[test]
    #[ignore = "real payout proof qualification; run in release with --include-ignored"]
    fn reward_ux_real_claim_proof_review_binds_amount_fee_recipient_and_signature() {
        let (path, store, network, context) = fixture();
        let owner = key(&store, network).unwrap();
        let policy = AccountPolicy::single(&owner.verify_key());
        let recipient = wallet::NetworkShieldedAddress::from_recipient(
            network,
            store.private_spend_address(0).unwrap(),
        )
        .unwrap();
        let reference=wallet::private_spend_build::SpendReference{chain_id:context.chain_id,parent_hash:context.genesis_hash,parent_height:0,merkle_root:transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes()[32]};
        let prepared = wallet::reward_spend::prepare_account_claim_for_network(
            network,
            context.clone(),
            reference,
            wallet::reward_spend::AccountClaimRequest {
                account: policy.identifier().unwrap(),
                policy_generation: 0,
                sequence: 0,
                amount: 100000000,
                fee: 1000,
                recipient,
            },
        )
        .unwrap();
        let carrier = prepared.prove().unwrap();
        let claim = prepared.claim();
        let p = json!({"network":network,"expectedContext":context_json(&context),"kind":"claim","policy":policy,"intentHex":hex::encode(claim.encode()),"carrierHex":hex::encode(carrier.encode_carrier().unwrap()),"approvedDigest":hex::encode(claim.authorization_digest())});
        let signed = review(&store, serde_json::from_value(p.clone()).unwrap(), true).unwrap();
        let approvals: Vec<AccountApproval> =
            serde_json::from_value(signed["approvals"].clone()).unwrap();
        policy
            .verify(&claim.authorization_digest(), &approvals)
            .unwrap();
        let mut changed = claim.clone();
        changed.fee += 1;
        let mut altered = p.clone();
        altered["intentHex"] = hex::encode(changed.encode()).into();
        assert!(review(&store, serde_json::from_value(altered).unwrap(), true).is_err());
        let other = wallet::NetworkShieldedAddress::from_recipient(
            network,
            store.private_spend_address(1).unwrap(),
        )
        .unwrap();
        changed = claim.clone();
        changed.recipient = BoundedVec::new(other.to_bytes().unwrap()).unwrap();
        let mut altered = p.clone();
        altered["intentHex"] = hex::encode(changed.encode()).into();
        assert!(review(&store, serde_json::from_value(altered).unwrap(), true).is_err());
        let mut corrupted = carrier.encode_carrier().unwrap();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        let mut altered = p;
        altered["carrierHex"] = hex::encode(corrupted).into();
        assert!(review(&store, serde_json::from_value(altered).unwrap(), true).is_err());
        drop(store);
        let _ = std::fs::remove_file(path);
    }
}
