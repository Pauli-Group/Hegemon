//! Read-only projections of an already verified canonical account ledger.
//! JSON is not proof authority, and none of these builders mutates state.
use anyhow::{ensure, Result};
use protocol_reward_accounts::*;
use serde_json::{json, Value};

pub(crate) const SCHEMA: &str = "hegemon.native.reward-accounts.explorer.v1";
pub(crate) const MAX_PAGE_SIZE: usize = 100;

pub(crate) fn address(g: &RewardAccountsGenesis, id: AccountPolicyId48) -> Result<String> {
    Ok(PublicAccountAddress {
        network: g.network,
        policy: id,
    }
    .encode()?)
}
pub(crate) fn policy(policy: &AccountPolicy) -> Result<Value> {
    Ok(json!({
        "policy_hash":hex::encode(policy.identifier()?.as_bytes()),
        "required":policy.required(), "members":policy.signer_hashes().len(),
        "signer_key_hashes":policy.signer_hashes().iter()
            .map(|key|hex::encode(key.as_bytes())).collect::<Vec<_>>(),
    }))
}
pub(crate) fn parameters(g: &RewardAccountsGenesis) -> Result<Value> {
    let allocated = g.validate()?;
    Ok(json!({
        "network":g.network,
        "genesis_config_hash":hex::encode(g.commitment()?),
        "reward_epoch_blocks":g.reward_epoch_blocks.to_string(),
        "reward_availability":"earning-epoch-plus-two",
        "epoch_boundaries_are_finality":false,
        "treasury_address":address(g, g.treasury_account()?)?,
        "initial_treasury_authority":policy(&g.treasury_policy)?,
        "treasury_subsidy_numerator":TREASURY_SUBSIDY_NUMERATOR.to_string(),
        "treasury_subsidy_denominator":TREASURY_SUBSIDY_DENOMINATOR.to_string(),
        "genesis_allocation_atoms":allocated.to_string(),
        "mining_budget_atoms":(MAX_SUPPLY-allocated).to_string(),
        "max_supply_atoms":MAX_SUPPLY.to_string(),
        "genesis_allocation_count":g.allocations.len(),
        "atom_decimals":8,
        "public_account_transfers":false,
    }))
}
pub(crate) fn context(
    ledger: &RewardAccountLedger,
    block_hash: [u8; 32],
    note_root: [u64; 7],
) -> Result<Value> {
    ensure!(block_hash != [0; 32], "zero canonical snapshot hash");
    super::super::poseidon2_v8_state::Poseidon2V8NoteRoot::new(note_root)?;
    Ok(json!({
        "chain_id":hex::encode(ledger.context().chain_id),
        "genesis_hash":hex::encode(ledger.context().genesis_hash),
        "genesis_config_hash":hex::encode(ledger.context().genesis_config_hash.as_bytes()),
        "height":ledger.height().to_string(), "block_hash":hex::encode(block_hash),
        "accounts_root":hex::encode(ledger.state_root().as_bytes()), "note_root":note_root.map(|word|word.to_string()),
    }))
}
pub(crate) fn epochs(g: &RewardAccountsGenesis, height: u64) -> Result<Value> {
    let e = g.epochs()?;
    let current = (height != 0).then(|| e.epoch_at(height)).transpose()?;
    let next_height = height
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("next block overflow"))?;
    let next_epoch = e.epoch_at(next_height)?;
    let end = current
        .unwrap_or(0)
        .checked_add(1)
        .and_then(|v| v.checked_mul(e.blocks()))
        .ok_or_else(|| anyhow::anyhow!("epoch end overflow"))?;
    Ok(json!({
        "blocks_per_epoch":e.blocks().to_string(), "current_reward_epoch":current.map(|epoch|epoch.to_string()),
        "next_block_height":next_height.to_string(), "next_block_reward_epoch":next_epoch.to_string(),
        "next_epoch_boundary_height":(if height==0 {1} else {end.checked_add(1).ok_or_else(||anyhow::anyhow!("epoch boundary overflow"))?}).to_string(),
        "epoch_zero_release_height":e.release_height(0)?.to_string(),
        "boundaries_are_finality":false,
        "elapsed_time_is_variable":true,
    }))
}
fn buckets(
    g: &RewardAccountsGenesis,
    pending: &std::collections::BTreeMap<u64, u64>,
) -> Result<Vec<Value>> {
    let e = g.epochs()?;
    pending.iter().map(|(&epoch,&amount)|Ok(json!({
        "earning_epoch":epoch.to_string(), "release_epoch":epoch.checked_add(2).ok_or_else(||anyhow::anyhow!("release epoch overflow"))?.to_string(),
        "release_height":e.release_height(epoch)?.to_string(), "amount_atoms":amount.to_string(),
    }))).collect()
}
pub(crate) fn account(ledger: &RewardAccountLedger, id: AccountPolicyId48) -> Result<Value> {
    let g = ledger.genesis();
    let row = ledger.account_at(id, ledger.height())?;
    let next_height = ledger
        .height()
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("next block overflow"))?;
    let next = ledger.account_at(id, next_height)?;
    let total = row.total()?;
    Ok(json!({
        "address":address(g,id)?, "account_id":hex::encode(id.as_bytes()),
        "is_treasury":id==ledger.treasury(),
        "available_atoms":row.available().to_string(),
        "pending_atoms":(total-row.available()).to_string(), "total_atoms":total.to_string(),
        "claimable_next_block_atoms":next.available().to_string(),
        "next_sequence":row.next_sequence().to_string(),
        "policy_generation":if id==ledger.treasury(){ledger.policy_generation().to_string()}else{"0".into()},
        "authorization":if id==ledger.treasury(){Some(policy(ledger.treasury_policy())?)}else{None},
        "pending":buckets(g,row.pending())?,
    }))
}
pub(crate) fn snapshot(
    ledger: &RewardAccountLedger,
    hash: [u8; 32],
    note: [u64; 7],
) -> Result<Value> {
    let g = ledger.genesis();
    let allocated = g.validate()?;
    let pending = ledger
        .pending_epoch_totals()
        .values()
        .try_fold(0u64, |s, v| {
            s.checked_add(*v)
                .ok_or_else(|| anyhow::anyhow!("pending supply overflow"))
        })?;
    let issued_supply = allocated
        .checked_add(ledger.issued())
        .ok_or_else(|| anyhow::anyhow!("issued supply overflow"))?;
    let observed = ledger
        .shielded_value()
        .checked_add(ledger.available_total())
        .and_then(|v| v.checked_add(pending));
    ensure!(
        observed == Some(issued_supply) && issued_supply <= MAX_SUPPLY,
        "canonical reward supply conservation failure"
    );
    let pending_fork = ledger.pending_fork().map(|certificate| -> Result<Value> {
        let intent = &certificate.intent;
        Ok(json!({
            "current_generation":intent.current_generation.to_string(),
            "activation_height":intent.activation_height.to_string(),
            "successor_rules":hex::encode(intent.successor_rules.as_bytes()),
            "successor_authority":policy(&intent.successor_policy)?,
            "approval_count":certificate.approvals.len(),
            "approving_signer_indices":certificate.approvals.iter().map(|a|a.signer_index).collect::<Vec<_>>(),
            "certificate_digest":hex::encode(intent.authorization_digest()),
        }))
    }).transpose()?;
    Ok(json!({
        "schema":SCHEMA, "configured":true, "active":true,
        "context":context(ledger,hash,note)?, "parameters":parameters(g)?,
        "epochs":epochs(g,ledger.height())?,
        "supply":{
            "genesis_allocation_atoms":allocated.to_string(), "mining_issued_atoms":ledger.issued().to_string(),
            "shielded_atoms":ledger.shielded_value().to_string(), "available_account_atoms":ledger.available_total().to_string(),
            "pending_account_atoms":pending.to_string(), "total_issued_atoms":issued_supply.to_string(),
            "remaining_mining_atoms":(MAX_SUPPLY-issued_supply).to_string(), "max_supply_atoms":MAX_SUPPLY.to_string(),
        },
        "treasury":account(ledger,ledger.treasury())?,
        "governance":{"policy_generation":ledger.policy_generation().to_string(),
            "authority":policy(ledger.treasury_policy())?, "pending_replacement":pending_fork,
            "replacement_requires":"current-quorum-certificate-and-matching-software-hard-fork"},
    }))
}
pub(crate) fn genesis_page(
    g: &RewardAccountsGenesis,
    offset: usize,
    limit: usize,
) -> Result<Value> {
    ensure!(
        (1..=MAX_PAGE_SIZE).contains(&limit),
        "limit must be between 1 and 100"
    );
    ensure!(
        offset <= g.allocations.len(),
        "genesis offset exceeds distribution length"
    );
    let end = offset.saturating_add(limit).min(g.allocations.len());
    let rows = g.allocations[offset..end]
        .iter()
        .map(|row| {
            Ok(json!({
                "address":address(g,row.account)?, "initial_amount_atoms":row.amount.to_string(),
                "is_treasury":row.account==protocol_treasury_account_id(),
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({"parameters":parameters(g)?, "rows":rows,
        "next_offset":(end<g.allocations.len()).then_some(end), "total_rows":g.allocations.len()}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{hash384::RulesHash48, ml_dsa::MlDsaSecretKey, traits::SigningKey};
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
    fn fixture(funding: u64) -> (RewardAccountLedger, Vec<MlDsaSecretKey>) {
        let keys = (0..14)
            .map(|i| MlDsaSecretKey::generate_deterministic(&[i; 32]))
            .collect::<Vec<_>>();
        let policy = AccountPolicy::threshold(
            5,
            keys[..7]
                .iter()
                .map(|k| account_key_hash(&k.verify_key()))
                .collect(),
        )
        .unwrap();
        let allocations = if funding == 0 {
            vec![]
        } else {
            vec![GenesisAllocation {
                account: protocol_treasury_account_id(),
                amount: funding,
            }]
        };
        let g = RewardAccountsGenesis {
            network: AddressNetwork {
                class: NetworkClass::Testnet,
                discriminator: [6; 32],
            },
            reward_epoch_blocks: 2,
            treasury_policy: policy,
            allocations: BoundedVec::new(allocations).unwrap(),
        };
        let context = AccountChainContext {
            chain_id: [1; 32],
            genesis_hash: [2; 32],
            genesis_config_hash: RulesHash48::new(g.commitment().unwrap()),
        };
        (RewardAccountLedger::new(g, context).unwrap(), keys)
    }
    #[test]
    fn reward_accounts_explorer_exact_supply_empty_partial_and_full_genesis() {
        for funding in [0, 100 * COIN, MAX_SUPPLY] {
            let (mut l, _) = fixture(funding);
            for h in 0..=5 {
                if h > 0 {
                    l = l
                        .apply_block(h, AccountPolicyId48::new([9; 48]), &[], &RejectProofs)
                        .unwrap();
                }
                let s = snapshot(&l, [3; 32], [0; 7]).unwrap();
                let read =
                    |field: &str| s["supply"][field].as_str().unwrap().parse::<u64>().unwrap();
                assert_eq!(
                    read("shielded_atoms")
                        + read("available_account_atoms")
                        + read("pending_account_atoms"),
                    funding + l.issued()
                );
                assert_eq!(
                    read("total_issued_atoms") + read("remaining_mining_atoms"),
                    MAX_SUPPLY
                );
                assert_eq!(
                    s["parameters"]["genesis_allocation_atoms"],
                    funding.to_string()
                );
                assert_eq!(s["governance"]["authority"]["required"], 5);
                assert_eq!(s["governance"]["authority"]["members"], 7);
            }
        }
    }
    #[test]
    fn reward_accounts_explorer_current_balance_and_first_block_claimability_differ() {
        let (mut l, _) = fixture(100 * COIN);
        let miner = AccountPolicyId48::new([9; 48]);
        for h in 1..=4 {
            l = l.apply_block(h, miner, &[], &RejectProofs).unwrap();
        }
        let row = account(&l, miner).unwrap();
        let matured = reward_split(l.genesis().issuance().unwrap().subsidy(1), 0)
            .unwrap()
            .0
            + reward_split(l.genesis().issuance().unwrap().subsidy(2), 0)
                .unwrap()
                .0;
        assert_eq!(row["available_atoms"], "0");
        assert_eq!(row["claimable_next_block_atoms"], matured.to_string());
        assert_eq!(row["pending"][0]["release_height"], "5");
        let parent = l.clone();
        l = l.apply_block(5, miner, &[], &RejectProofs).unwrap();
        assert_eq!(
            account(&l, miner).unwrap()["available_atoms"],
            matured.to_string()
        );
        assert_eq!(account(&parent, miner).unwrap()["available_atoms"], "0");
        assert_eq!(
            epochs(l.genesis(), 0).unwrap()["current_reward_epoch"],
            Value::Null
        );
        assert_eq!(
            epochs(l.genesis(), 4).unwrap()["next_epoch_boundary_height"],
            "5"
        );
        assert_eq!(epochs(l.genesis(), 5).unwrap()["current_reward_epoch"], "2");
        assert!(snapshot(&l, [0; 32], [0; 7]).is_err());
        assert!(snapshot(&l, [3; 32], [u64::MAX; 7]).is_err());
        let word = super::super::super::poseidon2_v8_state::POSEIDON2_V8_GOLDILOCKS_MODULUS - 1;
        let ctx = context(&l, [3; 32], [word; 7]).unwrap();
        assert_eq!(ctx["note_root"][0], word.to_string());
        let mut long_epoch = l.genesis().clone();
        long_epoch.reward_epoch_blocks = 1u64 << 54;
        assert_eq!(
            parameters(&long_epoch).unwrap()["reward_epoch_blocks"],
            (1u64 << 54).to_string()
        );
        assert_eq!(
            epochs(&long_epoch, 1).unwrap()["next_epoch_boundary_height"],
            ((1u64 << 54) + 1).to_string()
        );
    }
    #[test]
    fn reward_accounts_explorer_genesis_pagination_and_network_validation() {
        let (l, _) = fixture(COIN);
        let g = l.genesis();
        let page = genesis_page(g, 0, 1).unwrap();
        assert_eq!(page["rows"].as_array().unwrap().len(), 1);
        assert!(page["next_offset"].is_null());
        assert_eq!(page["rows"][0]["initial_amount_atoms"], COIN.to_string());
        assert!(genesis_page(g, 1, 1).unwrap()["rows"]
            .as_array()
            .unwrap()
            .is_empty());
        for (o, n) in [(2, 1), (0, 0), (0, 101), (usize::MAX, 1)] {
            assert!(genesis_page(g, o, n).is_err());
        }
        let encoded = page["rows"][0]["address"].as_str().unwrap();
        assert_eq!(
            PublicAccountAddress::decode(encoded, g.network)
                .unwrap()
                .policy,
            protocol_treasury_account_id()
        );
        let mut wrong = g.network;
        wrong.discriminator[0] ^= 1;
        assert!(PublicAccountAddress::decode(encoded, wrong).is_err());
        assert!(
            PublicAccountAddress::decode(&hex::encode(l.treasury().as_bytes()), g.network).is_err()
        );
    }
    #[test]
    fn reward_accounts_explorer_governance_preserves_pot_and_tracks_certified_activation() {
        let (l, keys) = fixture(COIN);
        let next = AccountPolicy::threshold(
            5,
            keys[7..]
                .iter()
                .map(|k| account_key_hash(&k.verify_key()))
                .collect(),
        )
        .unwrap();
        let intent = TreasuryForkIntent {
            context: l.context().clone(),
            current_generation: 0,
            activation_height: 3,
            successor_rules: RulesHash48::new([8; 48]),
            successor_policy: next.clone(),
        };
        let mut approvals = keys[..5]
            .iter()
            .map(|key| {
                let index = l
                    .treasury_policy()
                    .signer_hashes()
                    .iter()
                    .position(|h| *h == account_key_hash(&key.verify_key()))
                    .unwrap();
                AccountApproval::sign(index as u8, key, &intent.authorization_digest())
            })
            .collect::<Vec<_>>();
        approvals.sort_by_key(|a| a.signer_index);
        let compiled = CompiledTreasuryFork {
            activation_height: 3,
            successor_rules: intent.successor_rules,
            successor_policy: next.identifier().unwrap(),
        };
        let l = l
            .apply_block_with_fork(
                1,
                AccountPolicyId48::new([9; 48]),
                &[RewardAccountAction::TreasuryFork {
                    certificate: TreasuryForkCertificate {
                        intent,
                        approvals: BoundedVec::new(approvals).unwrap(),
                    },
                }],
                &RejectProofs,
                Some(&compiled),
            )
            .unwrap();
        let before = snapshot(&l, [3; 32], [0; 7]).unwrap();
        assert_eq!(
            before["governance"]["pending_replacement"]["approval_count"],
            5
        );
        assert_eq!(
            before["governance"]["pending_replacement"]["activation_height"],
            "3"
        );
        let l = l
            .apply_block(2, AccountPolicyId48::new([9; 48]), &[], &RejectProofs)
            .unwrap();
        let l = l
            .apply_block_with_fork(
                3,
                AccountPolicyId48::new([9; 48]),
                &[],
                &RejectProofs,
                Some(&compiled),
            )
            .unwrap();
        let after = snapshot(&l, [4; 32], [0; 7]).unwrap();
        assert_eq!(before["treasury"]["address"], after["treasury"]["address"]);
        assert_eq!(after["governance"]["policy_generation"], "1");
        assert_eq!(
            after["governance"]["authority"]["policy_hash"],
            hex::encode(next.identifier().unwrap().as_bytes())
        );
        assert!(after["governance"]["pending_replacement"].is_null());
    }
}
