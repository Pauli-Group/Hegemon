//! Local payout selection for template authors. Block validation never consults this file.

use super::{NativeConfig, NativeNode, ShieldedAddress};
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use wallet::solo_payout::{SoloPayoutSchedule, MAX_SOLO_PAYOUT_SCHEDULE_BYTES};

pub(super) struct SoloPayoutFile {
    path: PathBuf,
    chain_id: [u8; 32],
    cache: Mutex<ScheduleCache>,
}

struct ScheduleCache {
    schedule: SoloPayoutSchedule,
    retry_after: Option<Instant>,
}

fn load(path: &Path, chain_id: [u8; 32]) -> Result<SoloPayoutSchedule> {
    let file = File::open(path)
        .with_context(|| format!("open solo payout schedule {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("solo payout schedule must be a regular file");
    }
    let mut bytes = Vec::new();
    file.take(MAX_SOLO_PAYOUT_SCHEDULE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    SoloPayoutSchedule::from_json(&bytes, chain_id)
        .with_context(|| format!("invalid solo payout schedule {}", path.display()))
}

impl SoloPayoutFile {
    pub(super) fn from_config(config: &NativeConfig) -> Result<Option<Self>> {
        let Some(path) = &config.solo_payout_schedule else {
            return Ok(None);
        };
        if config.miner_address.is_some() {
            bail!("select only one of HEGEMON_SOLO_PAYOUT_SCHEDULE and HEGEMON_MINER_ADDRESS");
        }
        let chain_id = config.chain_id();
        let schedule = load(path, chain_id)?;
        Ok(Some(Self {
            path: path.clone(),
            chain_id,
            cache: Mutex::new(ScheduleCache {
                schedule,
                retry_after: None,
            }),
        }))
    }

    fn address_at(&self, height: u64) -> Result<ShieldedAddress> {
        let mut cache = self.cache.lock();
        if let Ok(address) = cache.schedule.address_at(height) {
            return Ok(address.clone());
        }

        // Only a height outside the current window needs a reload. Throttle failed
        // reads so an exhausted schedule cannot reparse megabytes on every work poll.
        let now = Instant::now();
        if cache.retry_after.is_some_and(|deadline| now < deadline) {
            bail!(
                "solo payout schedule does not cover height {height}; waiting to reload {}",
                self.path.display()
            );
        }
        cache.retry_after = Some(now + Duration::from_secs(2));
        let next = load(&self.path, self.chain_id)?;
        let address = next
            .address_at(height)
            .with_context(|| {
                format!(
                    "extend {} to cover solo payout height {height}",
                    self.path.display()
                )
            })?
            .clone();

        // Changing a recipient for a still-covered height would make restarts or
        // a reorganization issue different jobs for the same configured height.
        let first = next.first_height().max(cache.schedule.first_height());
        let last = next.last_height().min(cache.schedule.last_height());
        for overlap in first..=last {
            if next.address_at(overlap)? != cache.schedule.address_at(overlap)? {
                bail!("replacement solo payout schedule changes height {overlap}");
            }
        }
        cache.schedule = next;
        cache.retry_after = None;
        Ok(address)
    }
}

impl NativeNode {
    pub(super) fn miner_payout_address_at(&self, height: u64) -> Result<Option<ShieldedAddress>> {
        if let Some(schedule) = &self.solo_payout {
            return schedule.address_at(height).map(Some);
        }
        self.config
            .miner_address
            .as_deref()
            .map(ShieldedAddress::decode)
            .transpose()
            .context("decode HEGEMON_MINER_ADDRESS for native coinbase")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::tests::test_config;
    use crate::native::NativeCli;
    use clap::Parser;
    use std::fs;
    use wallet::RootSecret;

    #[test]
    fn launcher_schedule_flag_is_accepted_by_the_native_node() {
        let cli = NativeCli::try_parse_from([
            "hegemon-node",
            "--dev",
            "--tmp",
            "--solo-payout-schedule=operator files/payouts.json",
        ])
        .unwrap();
        let config = NativeConfig::from_cli(cli).unwrap();
        assert_eq!(
            config.solo_payout_schedule.as_deref(),
            Some(Path::new("operator files/payouts.json"))
        );
    }

    #[test]
    fn solo_schedule_reloads_at_the_next_height_and_preserves_overlapping_jobs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payouts.json");
        let mut config = test_config(dir.path(), 0x207f_ffff, "unsafe", false);
        config.solo_payout_schedule = Some(path.clone());
        let keys = RootSecret::from_bytes([43; 32]).derive();
        let first = SoloPayoutSchedule::derive(&keys, config.chain_id(), 10, 2).unwrap();
        fs::write(&path, first.to_json().unwrap()).unwrap();
        let source = SoloPayoutFile::from_config(&config).unwrap().unwrap();
        let original = source.address_at(11).unwrap();

        let next = SoloPayoutSchedule::derive(&keys, config.chain_id(), 11, 2).unwrap();
        let temp = dir.path().join("replacement");
        fs::write(&temp, next.to_json().unwrap()).unwrap();
        fs::rename(&temp, &path).unwrap();
        assert_eq!(
            source.address_at(12).unwrap(),
            *next.address_at(12).unwrap()
        );
        assert_eq!(source.address_at(11).unwrap(), original);
        assert!(source.address_at(13).is_err());

        let wrong_keys = RootSecret::from_bytes([44; 32]).derive();
        let changed = SoloPayoutSchedule::derive(&wrong_keys, config.chain_id(), 12, 2).unwrap();
        let restarted = SoloPayoutFile::from_config(&config).unwrap().unwrap();
        fs::write(&path, changed.to_json().unwrap()).unwrap();
        assert!(restarted
            .address_at(13)
            .unwrap_err()
            .to_string()
            .contains("changes height 12"));
        assert_eq!(
            restarted.address_at(12).unwrap(),
            *next.address_at(12).unwrap()
        );
        config.miner_address = Some(original.encode().unwrap());
        assert!(SoloPayoutFile::from_config(&config).is_err());
    }

    #[cfg(feature = "development-candidate")]
    #[test]
    fn solo_schedule_builds_two_distinct_miner_rewards_and_preserves_the_treasury() {
        use crate::native::{
            decode_scale_exact, network_profile, MintPoseidon2V8RewardsArgs, NativeNetworkIdentity,
        };
        use wallet::poseidon2_v8_coinbase::public_poseidon2_v8_reward_opening;

        let dir = tempfile::tempdir().unwrap();
        let funding = RootSecret::from_bytes([71; 32])
            .derive()
            .poseidon2_v8_address(0)
            .unwrap()
            .shielded_address();
        let mut manifest = network_profile::private_spend_only_development_candidate_manifest(
            &funding.encode().unwrap(),
        )
        .unwrap();
        manifest.pow_bits = 0x207f_ffff;
        let mut config = test_config(dir.path(), manifest.pow_bits, "unsafe", false);
        config.network = NativeNetworkIdentity::from_manifest(manifest).unwrap();
        let keys = RootSecret::from_bytes([72; 32]).derive();
        let schedule = SoloPayoutSchedule::derive(&keys, config.chain_id(), 1, 2).unwrap();
        let path = dir.path().join("payouts.json");
        fs::write(&path, schedule.to_json().unwrap()).unwrap();
        config.solo_payout_schedule = Some(path);
        let node = NativeNode::open(config).unwrap();
        for height in [1, 2] {
            let action = node.auto_coinbase_action(height, &[]).unwrap().unwrap();
            let args: MintPoseidon2V8RewardsArgs =
                decode_scale_exact(&action.public_args, "rewards").unwrap();
            let miner = schedule.address_at(height).unwrap();
            let other = schedule.address_at(3 - height).unwrap();
            public_poseidon2_v8_reward_opening(&args.miner_note, miner).unwrap();
            assert!(public_poseidon2_v8_reward_opening(&args.miner_note, other).is_err());
            public_poseidon2_v8_reward_opening(args.funding_note.as_ref().unwrap(), &funding)
                .unwrap();
        }
        assert!(node.auto_coinbase_action(3, &[]).is_err());
    }
}
