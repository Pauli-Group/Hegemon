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
        versions
            .into_iter()
            .find(|version| !allowed.contains(version))
    }

    pub fn validate_versions<I>(&self, height: u64, versions: I) -> Result<(), VersionBinding>
    where
        I: IntoIterator<Item = VersionBinding>,
    {
        match self.first_unsupported(height, versions) {
            Some(version) => Err(version),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanVersionPolicyVectorFile {
        schema_version: u32,
        version_policy_cases: Vec<LeanVersionPolicyCase>,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanVersionPolicyCase {
        name: String,
        height: u64,
        initial: Vec<VersionBinding>,
        activations: Vec<LeanVersionEvent>,
        retirements: Vec<LeanVersionEvent>,
        tx_versions: Vec<VersionBinding>,
        expected_allowed: Vec<VersionBinding>,
        expected_valid: bool,
        expected_first_unsupported: Option<VersionBinding>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanVersionEvent {
        height: u64,
        versions: Vec<VersionBinding>,
    }

    #[test]
    fn lean_generated_version_policy_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_VERSION_POLICY_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_VERSION_POLICY_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean version vectors");
        let vectors: LeanVersionPolicyVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean version vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            vectors.version_policy_cases.len() >= 8,
            "Lean version-policy cases cover too few policy branches"
        );

        let mut names = std::collections::BTreeSet::new();
        for case in &vectors.version_policy_cases {
            assert!(names.insert(case.name.clone()));
            verify_version_policy_case(case);
        }
    }

    fn verify_version_policy_case(case: &LeanVersionPolicyCase) {
        let mut schedule = VersionSchedule::new(case.initial.iter().copied());
        for event in &case.activations {
            schedule
                .activations
                .entry(event.height)
                .or_default()
                .extend(event.versions.iter().copied());
        }
        for event in &case.retirements {
            schedule
                .retirements
                .entry(event.height)
                .or_default()
                .extend(event.versions.iter().copied());
        }

        let allowed = schedule.allowed_at(case.height);
        let expected_allowed = case
            .expected_allowed
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            allowed, expected_allowed,
            "{} allowed set drifted from Lean spec",
            case.name
        );

        let result = schedule.validate_versions(case.height, case.tx_versions.iter().copied());
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} version-policy validity drifted from Lean spec",
            case.name
        );
        match result {
            Ok(()) => assert_eq!(
                None, case.expected_first_unsupported,
                "{} production accepted a case Lean rejected",
                case.name
            ),
            Err(version) => assert_eq!(
                Some(version),
                case.expected_first_unsupported,
                "{} first unsupported version drifted from Lean spec",
                case.name
            ),
        }
    }
}
