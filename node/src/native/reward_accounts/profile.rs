//! Fresh-genesis data and exact compiled source pins. Data validation is not
//! proof authority: runtime dispatch must separately install this source.
use super::super::network_profile::{
    DevelopmentCandidateManifest, DevelopmentPrivateSpendSource, NativeNetworkManifest,
    NativeNetworkProfile,
};
use super::wire;
use anyhow::{ensure, Result};
use protocol_reward_accounts::{NetworkClass, RewardAccountsGenesis};
use serde::{Deserialize, Serialize};

pub(crate) const NETWORK_SCHEMA: &str = "hegemon.native.network-manifest.v2";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewardAccountsProfile {
    pub genesis: RewardAccountsGenesis,
    pub proof_source: String,
    pub native_source: String,
}
impl RewardAccountsProfile {
    pub(crate) fn compiled(genesis: RewardAccountsGenesis) -> Result<Self> {
        genesis.validate()?;
        Ok(Self {
            genesis,
            proof_source: hex::encode(transaction_circuit::reward_account_spend::source_digest()),
            native_source: hex::encode(wire::source_digest()),
        })
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.genesis.validate()?;
        ensure!(
            self.proof_source
                == hex::encode(transaction_circuit::reward_account_spend::source_digest())
                && self.native_source == hex::encode(wire::source_digest()),
            "reward account source differs from compiled proof/native implementation"
        );
        Ok(())
    }
}
pub(crate) fn validate_manifest(manifest: &NativeNetworkManifest) -> Result<()> {
    let reward = manifest
        .reward_accounts
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("reward genesis profile is missing"))?;
    reward.validate()?;
    ensure!(cfg!(feature="development-candidate") && manifest.profile==NativeNetworkProfile::Development,"reward-account source requires the explicit Development build/profile; no production authority is installed");
    ensure!(
        reward.genesis.network.class == NetworkClass::Testnet,
        "Development reward accounts require test addresses"
    );
    ensure!(
        manifest.funding_address.is_none()
            && (
                manifest.funding_subsidy_numerator,
                manifest.funding_subsidy_denominator
            ) == (0, 1),
        "reward accounts cannot also allocate legacy funding notes"
    );
    let source = manifest.development_candidate.as_ref().ok_or_else(|| {
        anyhow::anyhow!("reward accounts require their finite Development source")
    })?;
    source.validate_private_spend_source()?;
    let empty =
        transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes()[32];
    ensure!(
        source.private_spend_only
            && source.assets.is_none()
            && source.recovery.is_none()
            && source.activation_height == 1
            && source.deactivation_height_exclusive > 1
            && source.deactivation_height_exclusive <= 10_001
            && source.max_proof_actions_per_block > 0
            && source.max_proof_actions_per_block <= 8
            && source.max_total_proofs > 0
            && source.max_total_proofs <= 128
            && source.max_proof_bytes >= transaction_circuit::reward_account_spend::PROOF_BYTES
            && source.max_proof_bytes
                <= protocol_shielded_pool::private_spend_transport::MAX_CARRIER_BYTES
            && source.stablecoin_genesis_root == [0; 7]
            && source.note_genesis_root == empty,
        "reward Development source scope/roots rejected"
    );
    Ok(())
}
pub(crate) fn development_source() -> DevelopmentCandidateManifest {
    DevelopmentCandidateManifest {
        activation_height: 1,
        deactivation_height_exclusive: 10_001,
        max_proof_actions_per_block: 8,
        max_total_proofs: 128,
        max_proof_bytes: protocol_shielded_pool::private_spend_transport::MAX_CARRIER_BYTES,
        stablecoin_genesis_root: [0; 7],
        note_genesis_root:
            transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes()
                [32],
        private_spend_only: true,
        private_spend_source: Some(DevelopmentPrivateSpendSource::compiled()),
        assets: None,
        recovery: None,
    }
}

/// Public data construction only. Runtime source selection remains separate.
pub(crate) fn development_manifest(
    genesis: RewardAccountsGenesis,
) -> Result<NativeNetworkManifest> {
    Ok(NativeNetworkManifest {
        reward_accounts: Some(RewardAccountsProfile::compiled(genesis)?),
        schema: NETWORK_SCHEMA.into(),
        profile: NativeNetworkProfile::Development,
        genesis_timestamp_ms: super::super::NATIVE_GENESIS_TIMESTAMP_MS,
        pow_bits: super::super::NATIVE_DEV_POW_BITS,
        rules_hash: super::super::hex32(
            &consensus_light_client::HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
        ),
        launch_reference_rules_hash: super::super::hex32(
            &super::super::network_profile::compiled_reward_accounts_reference_rules_hash(),
        ),
        funding_address: None,
        funding_subsidy_numerator: 0,
        funding_subsidy_denominator: 1,
        development_candidate: Some(development_source()),
    })
}
#[cfg(test)]
mod tests {
    use super::super::super::network_profile::NativeNetworkIdentity;
    use super::*;
    use crypto::{ml_dsa::MlDsaSecretKey, traits::SigningKey};
    use protocol_reward_accounts::*;
    fn genesis() -> RewardAccountsGenesis {
        let key = MlDsaSecretKey::generate_deterministic(b"reward network profile test");
        RewardAccountsGenesis {
            network: AddressNetwork {
                class: NetworkClass::Testnet,
                discriminator: [8; 32],
            },
            reward_epoch_blocks: 2,
            treasury_policy: AccountPolicy::single(&key.verify_key()),
            allocations: BoundedVec::default(),
        }
    }
    #[test]
    fn reward_accounts_native_profile_cannot_reinterpret_v1_or_enable_default_build() {
        let mut m = development_manifest(genesis()).unwrap();
        m.schema = "hegemon.native.network-manifest.v1".into();
        assert!(NativeNetworkIdentity::from_manifest(m).is_err());
        let m = development_manifest(genesis()).unwrap();
        if !cfg!(feature = "development-candidate") {
            assert!(NativeNetworkIdentity::from_manifest(m).is_err());
        }
        let legacy = NativeNetworkIdentity::development();
        assert!(!serde_json::to_string(legacy.manifest().unwrap())
            .unwrap()
            .contains("reward_accounts"));
    }
    #[test]
    fn reward_accounts_native_profile_rejects_source_changes() {
        let mut profile = RewardAccountsProfile::compiled(genesis()).unwrap();
        profile.validate().unwrap();
        profile.proof_source.replace_range(..2, "zz");
        assert!(profile.validate().is_err());
        let mut profile = RewardAccountsProfile::compiled(genesis()).unwrap();
        profile.native_source.replace_range(..2, "zz");
        assert!(profile.validate().is_err());
    }
    #[cfg(feature = "development-candidate")]
    #[test]
    fn reward_accounts_native_profile_strict_budget_network_and_scope() {
        let base = development_manifest(genesis()).unwrap();
        let identity = NativeNetworkIdentity::from_manifest(base.clone()).unwrap();
        assert!(identity.reward_accounts().is_some());
        // Until the account-specific dispatcher exists, startup must fail;
        // it must never borrow legacy Launch mint authority for this schema.
        assert!(
            super::super::super::native_proof_binding::NativeProofBinding::from_source_for_replay(
                &identity, [9; 32]
            )
            .is_err()
        );
        let mut wrong = base.clone();
        wrong.funding_address = Some("legacy funding".into());
        assert!(NativeNetworkIdentity::from_manifest(wrong).is_err());
        let mut wrong = base.clone();
        wrong
            .reward_accounts
            .as_mut()
            .unwrap()
            .genesis
            .network
            .class = NetworkClass::Mainnet;
        assert!(NativeNetworkIdentity::from_manifest(wrong).is_err());
        let mut wrong = base.clone();
        wrong.reward_accounts.as_mut().unwrap().genesis.allocations =
            BoundedVec::new(vec![GenesisAllocation {
                account: AccountPolicyId48::new([7; 48]),
                amount: MAX_SUPPLY + 1,
            }])
            .unwrap();
        assert!(NativeNetworkIdentity::from_manifest(wrong).is_err());
        let mut wrong = base.clone();
        wrong
            .development_candidate
            .as_mut()
            .unwrap()
            .max_total_proofs = 129;
        assert!(NativeNetworkIdentity::from_manifest(wrong).is_err());
        let mut changed = base;
        changed
            .reward_accounts
            .as_mut()
            .unwrap()
            .genesis
            .reward_epoch_blocks = 3;
        assert_ne!(
            NativeNetworkIdentity::from_manifest(changed)
                .unwrap()
                .chain_id(),
            identity.chain_id()
        );
    }
    #[cfg(feature = "development-candidate")]
    #[test]
    fn reward_accounts_native_profile_loads_bounded_distribution_above_legacy_cap() {
        let mut g = genesis();
        let mut rows = Vec::new();
        for i in 0..1000u64 {
            let mut bytes = [7; 48];
            bytes[40..].copy_from_slice(&i.to_le_bytes());
            rows.push(GenesisAllocation {
                account: AccountPolicyId48::new(bytes),
                amount: 1,
            });
        }
        rows.sort_by_key(|r| r.account);
        g.allocations = BoundedVec::new(rows).unwrap();
        let manifest = development_manifest(g).unwrap();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert!(bytes.len() > 64 * 1024);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("network.json");
        std::fs::write(&path, bytes).unwrap();
        let loaded = NativeNetworkIdentity::load(&path, NativeNetworkProfile::Development).unwrap();
        assert_eq!(
            loaded
                .reward_accounts()
                .unwrap()
                .genesis
                .validate()
                .unwrap(),
            1000
        );
    }
}
