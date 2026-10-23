//! Immutable, public genesis opt-in. No runtime activation or production grant.
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use transaction_circuit::asset_recovery_wire_v1 as wire;
use transaction_core::{asset_recovery_v1 as core, asset_registry_v1::AssetPolicyV1};

const SCHEMA: &str = "hegemon.native.development-recovery.v1";

mod geometry_catalog;

/// Chain and freeze roots are derived after manifest hashing, never JSON inputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryGenesisConfigV1 {
    pub asset_id: u32,
    pub stable_policy_id: [u64; 7],
    pub policy_admin_commitment: [u64; 7],
    pub archive_key_commitment: [u64; 7],
    pub maximum_powers_bits: u8,
    pub initial_delegate_commitment: [u64; 7],
    pub initial_revoked: bool,
    pub initial_powers_bits: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentRecoveryV1 {
    pub schema: String,
    pub spend_relation_digest: String,
    pub admin_relation_digest: String,
    pub capsule_relation_digest: String,
    pub wire_version: u16,
    pub credential_depth: u8,
    pub max_proof_bytes: usize,
    pub max_action_bytes: usize,
    pub max_actions_per_block: usize,
    pub initial_rows: Vec<RecoveryGenesisConfigV1>,
}

fn powers(bits: u8) -> Result<core::RecoveryPowersV1> {
    if bits & !3 != 0 {
        return Err(anyhow!("recovery powers contain unsupported bits"));
    }
    Ok(core::RecoveryPowersV1 {
        transfer: bits & 1 != 0,
        burn: bits & 2 != 0,
    })
}

impl RecoveryGenesisConfigV1 {
    fn row(&self, chain_id: [u8; 32]) -> Result<core::RecoveryRowV1> {
        let descriptor = core::RecoveryDescriptorV1 {
            asset_id: self.asset_id,
            stable_policy_id: self.stable_policy_id,
            policy_admin_commitment: self.policy_admin_commitment,
            archive_key_commitment: self.archive_key_commitment,
            maximum_powers: powers(self.maximum_powers_bits)?,
        };
        let row = core::RecoveryRowV1 {
            controls: core::RecoveryControlsV1 {
                epoch: 0,
                delegate_action_commitment: self.initial_delegate_commitment,
                revoked: self.initial_revoked,
                powers: powers(self.initial_powers_bits)?,
                note_freeze_root: core::freeze_defaults(&descriptor, chain_id)
                    .map_err(|e| anyhow!("recovery default freeze tree rejected: {e:?}"))?[32],
            },
            descriptor,
        };
        row.validate()
            .map_err(|e| anyhow!("recovery genesis row rejected: {e:?}"))?;
        Ok(row)
    }
}

impl DevelopmentRecoveryV1 {
    pub(crate) fn compiled(initial_rows: Vec<RecoveryGenesisConfigV1>) -> Result<Self> {
        let value = Self {
            schema: SCHEMA.into(),
            spend_relation_digest: hex::encode(
                transaction_circuit::asset_recovery_spend_v1::relation_digest(),
            ),
            admin_relation_digest: hex::encode(
                transaction_circuit::asset_recovery_admin_v1::relation_digest(),
            ),
            capsule_relation_digest: hex::encode(
                transaction_circuit::asset_recovery_capsule_v1::relation_digest(),
            ),
            wire_version: wire::VERSION,
            credential_depth: 4,
            max_proof_bytes: wire::MAX_PROOF_BYTES,
            max_action_bytes: wire::MAX_SPEND_ACTION_BYTES,
            max_actions_per_block: 1,
            initial_rows,
        };
        value.validate()?;
        Ok(value)
    }

    /// Structural/source checks only. This does not qualify proof geometry.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA
            || self.spend_relation_digest
                != hex::encode(transaction_circuit::asset_recovery_spend_v1::relation_digest())
            || self.admin_relation_digest
                != hex::encode(transaction_circuit::asset_recovery_admin_v1::relation_digest())
            || self.capsule_relation_digest
                != hex::encode(transaction_circuit::asset_recovery_capsule_v1::relation_digest())
            || self.wire_version != wire::VERSION
            || self.credential_depth != 4
            || self.max_proof_bytes != 2 * 1024 * 1024
            || self.max_proof_bytes != wire::MAX_PROOF_BYTES
            || self.max_action_bytes != wire::MAX_SPEND_ACTION_BYTES
            || self.max_actions_per_block != 1
        {
            return Err(anyhow!(
                "recovery requires exact compiled sources, wire, depth and proof/action limits"
            ));
        }
        if self.initial_rows.is_empty() || self.initial_rows.len() > 16 {
            return Err(anyhow!(
                "recovery requires one through sixteen genesis assets"
            ));
        }
        let mut previous = 0;
        for config in &self.initial_rows {
            if config.asset_id <= previous {
                return Err(anyhow!(
                    "recovery genesis assets must be sorted, distinct and non-native"
                ));
            }
            config.row([1; 32])?;
            previous = config.asset_id;
        }
        Ok(())
    }

    pub(crate) fn initial_state(
        &self,
        chain_id: [u8; 32],
        legacy_genesis_rows: &[AssetPolicyV1],
    ) -> Result<super::asset_recovery_state::RecoveryLedgerStateV1> {
        self.validate()?;
        for config in &self.initial_rows {
            let old = legacy_genesis_rows
                .iter()
                .find(|row| row.config.asset_id == config.asset_id)
                .ok_or_else(|| anyhow!("recovery asset is absent from asset genesis"))?;
            if old.credential_depth != 4 {
                return Err(anyhow!(
                    "recovery genesis asset requires credential depth four"
                ));
            }
        }
        let rows = self
            .initial_rows
            .iter()
            .map(|config| config.row(chain_id))
            .collect::<Result<Vec<_>>>()?;
        super::asset_recovery_state::RecoveryLedgerStateV1::from_genesis_rows(
            &chain_id,
            legacy_genesis_rows,
            &rows,
        )
        .map_err(|e| anyhow!("recovery genesis cross-validation rejected: {e}"))
    }

    /// Require the compiled, independently reviewed actual geometry catalog.
    /// This qualifies only finite Development source geometry; native lifecycle,
    /// security qualification and production authority remain separate gates.
    pub(crate) fn require_qualified_geometry(&self) -> Result<()> {
        geometry_catalog::require(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> RecoveryGenesisConfigV1 {
        RecoveryGenesisConfigV1 {
            asset_id: 1001,
            stable_policy_id: [7; 7],
            policy_admin_commitment: [2; 7],
            archive_key_commitment: [8; 7],
            maximum_powers_bits: 3,
            initial_delegate_commitment: [9; 7],
            initial_revoked: false,
            initial_powers_bits: 3,
        }
    }
    fn legacy() -> AssetPolicyV1 {
        use transaction_core::{
            poseidon2_width16::Felt,
            stablecoin_poseidon2_v8::{StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Counters},
        };
        AssetPolicyV1 {
            config: StablecoinPoseidon2V8Config {
                asset_id: 1001,
                policy_version: 1,
                issuer_commitment: [Felt::from_u64(1); 7],
                policy_admin_commitment: [Felt::from_u64(2); 7],
                oracle_authority_commitment: [Felt::from_u64(3); 7],
                attestation_authority_commitment: [Felt::from_u64(4); 7],
                locked_collateral_commitment: [Felt::from_u64(5); 7],
                collateral_scale: 1,
                ..StablecoinPoseidon2V8Config::default()
            },
            counters: StablecoinPoseidon2V8Counters::default(),
            credential_root: [Felt::from_u64(6); 7],
            credential_depth: 4,
            frozen: false,
            mint_enabled: false,
        }
    }
    #[test]
    fn recovery_genesis_derives_chain_bound_defaults_and_has_qualified_geometry() {
        let d = DevelopmentRecoveryV1::compiled(vec![config()]).unwrap();
        assert!(d.initial_state([1; 32], &[legacy()]).is_ok());
        assert!(d.initial_state([2; 32], &[legacy()]).is_ok());
        assert_ne!(
            config().row([1; 32]).unwrap().controls.note_freeze_root,
            config().row([2; 32]).unwrap().controls.note_freeze_root
        );
        if geometry_catalog::retained_catalog_matches_current_sources_for_test() {
            assert!(d.require_qualified_geometry().is_ok());
        } else {
            assert_eq!(
                d.require_qualified_geometry().unwrap_err().to_string(),
                "recovery geometry catalog differs from compiled sources or unchanged SMZE profile"
            );
            assert!(d.validate().is_ok());
            eprintln!("inactive recovery source: chain-bound genesis remains structural; current geometry qualification fails closed");
        }
        let mut json = serde_json::to_value(&d).unwrap();
        json["initial_rows"][0]["note_freeze_root"] = serde_json::json!([1, 1, 1, 1, 1, 1, 1]);
        assert!(serde_json::from_value::<DevelopmentRecoveryV1>(json).is_err());
    }
    #[test]
    fn recovery_rejects_native_duplicate_roles_powers_and_wrong_pins() {
        let mut c = config();
        c.asset_id = 0;
        assert!(DevelopmentRecoveryV1::compiled(vec![c]).is_err());
        assert!(DevelopmentRecoveryV1::compiled(vec![config(), config()]).is_err());
        let mut c = config();
        c.archive_key_commitment = [0; 7];
        assert!(DevelopmentRecoveryV1::compiled(vec![c]).is_err());
        let mut c = config();
        c.maximum_powers_bits = 1;
        c.initial_powers_bits = 2;
        assert!(DevelopmentRecoveryV1::compiled(vec![c]).is_err());
        let d = DevelopmentRecoveryV1::compiled(vec![config()]).unwrap();
        let changes: &[fn(&mut DevelopmentRecoveryV1)] = &[
            |v| v.spend_relation_digest = "00".repeat(64),
            |v| v.admin_relation_digest = "00".repeat(64),
            |v| v.capsule_relation_digest = "00".repeat(64),
            |v| v.wire_version += 1,
            |v| v.credential_depth = 8,
            |v| v.max_proof_bytes += 1,
            |v| v.max_action_bytes += 1,
            |v| v.max_actions_per_block = 2,
        ];
        for change in changes {
            let mut bad = d.clone();
            change(&mut bad);
            assert!(bad.validate().is_err());
        }
    }
    #[test]
    fn recovery_rejects_wrong_admin_issued_missing_and_wrong_depth_genesis() {
        let d = DevelopmentRecoveryV1::compiled(vec![config()]).unwrap();
        let mut old = legacy();
        old.config.policy_admin_commitment[0] =
            transaction_core::poseidon2_width16::Felt::from_u64(99);
        assert!(d.initial_state([1; 32], &[old]).is_err());
        let counter_changes: &[fn(&mut AssetPolicyV1)] = &[
            |old| old.counters.epoch_id = 1,
            |old| old.counters.minted_in_epoch = 1,
            |old| old.counters.total_debt = 1,
            |old| old.counters.sequence = 1,
        ];
        for change in counter_changes {
            let mut old = legacy();
            change(&mut old);
            assert!(d.initial_state([1; 32], &[old]).is_err());
        }
        let mut old = legacy();
        old.credential_depth = 8;
        assert!(d.initial_state([1; 32], &[old]).is_err());
        assert!(d.initial_state([1; 32], &[]).is_err());
    }
}
