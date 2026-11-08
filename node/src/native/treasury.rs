//! Native selection of the shared combined-upgrade schedule.
use super::*;
use consensus::treasury::TreasuryRewardPolicy;

pub(crate) fn treasury_reward_policy_for_network(
    network: &network_profile::NativeNetworkIdentity,
) -> TreasuryRewardPolicy {
    #[cfg(test)]
    if let Some(policy) = TEST_POLICY.with(|slot| {
        slot.borrow()
            .as_ref()
            .and_then(|(chain, policy)| (*chain == network.chain_id()).then_some(*policy))
    }) {
        return policy;
    }
    consensus_light_client::native_combined_upgrade_activation_height(&network.chain_id())
        .and_then(TreasuryRewardPolicy::at)
        .unwrap_or_default()
}

#[cfg(test)]
thread_local! { static TEST_POLICY: std::cell::RefCell<Option<([u8;32], TreasuryRewardPolicy)>> = const { std::cell::RefCell::new(None) }; }

#[cfg(test)]
pub(crate) fn with_treasury_reward_policy_for_test<T>(
    chain_id: [u8; 32],
    policy: TreasuryRewardPolicy,
    f: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<([u8; 32], TreasuryRewardPolicy)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_POLICY.with(|slot| *slot.borrow_mut() = self.0);
        }
    }
    let _restore = Restore(TEST_POLICY.with(|slot| slot.replace(Some((chain_id, policy)))));
    f()
}
