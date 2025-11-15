use protocol_versioning::{DEFAULT_VERSION_BINDING, VersionBinding};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpgradeDirective {
    pub from: VersionBinding,
    pub to: VersionBinding,
    pub circuit: VersionBinding,
    pub activation_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionProposal {
    pub binding: VersionBinding,
    pub activates_at: u64,
    pub retires_at: Option<u64>,
    pub upgrade: Option<UpgradeDirective>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionSchedule {
    initial: BTreeSet<VersionBinding>,
    activations: BTreeMap<u64, Vec<VersionBinding>>,
    retirements: BTreeMap<u64, Vec<VersionBinding>>,
    proposals: Vec<VersionProposal>,
}

impl Default for VersionSchedule {
    fn default() -> Self {
        Self::new(vec![DEFAULT_VERSION_BINDING])
    }
}

impl VersionSchedule {
    pub fn new<I>(initial: I) -> Self
    where
        I: IntoIterator<Item = VersionBinding>,
    {
        Self {
            initial: initial.into_iter().collect(),
            activations: BTreeMap::new(),
            retirements: BTreeMap::new(),
            proposals: Vec::new(),
        }
    }

    pub fn register(&mut self, proposal: VersionProposal) {
        self.activations
            .entry(proposal.activates_at)
            .or_default()
            .push(proposal.binding);
        if let Some(height) = proposal.retires_at {
            self.retirements
                .entry(height)
                .or_default()
                .push(proposal.binding);
        }
        if let Some(upgrade) = &proposal.upgrade {
            self.activations
                .entry(upgrade.activation_height)
                .or_default()
                .push(upgrade.circuit);
        }
        self.proposals.push(proposal);
    }

    pub fn allowed_at(&self, height: u64) -> BTreeSet<VersionBinding> {
        let mut allowed = self.initial.clone();
        for (_height, versions) in self.activations.range(..=height) {
            for version in versions {
                allowed.insert(*version);
            }
        }
        for (_height, versions) in self.retirements.range(..=height) {
            for version in versions {
                allowed.remove(version);
            }
        }
        allowed
    }

    pub fn is_allowed(&self, version: VersionBinding, height: u64) -> bool {
        self.allowed_at(height).contains(&version)
    }

    pub fn proposals(&self) -> &[VersionProposal] {
        &self.proposals
    }

    pub fn first_unsupported<I>(&self, height: u64, versions: I) -> Option<VersionBinding>
    where
        I: IntoIterator<Item = VersionBinding>,
    {
        let allowed = self.allowed_at(height);
        for version in versions {
            if !allowed.contains(&version) {
                return Some(version);
            }
        }
        None
    }
}
