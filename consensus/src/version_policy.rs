use protocol_versioning::{
    HEGEMON_PROOF_NETWORK_ID, ProofAuthorityClass, ProofAuthorityContext, ProofAuthorityDecision,
    ProofAuthorityOperation, VersionBinding, fresh_transaction_proof_capabilities,
    proof_authority_decision,
};
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
        let mut schedule = Self::new([]);
        for capability in fresh_transaction_proof_capabilities() {
            schedule
                .activations
                .entry(capability.activation_height())
                .or_default()
                .push(capability.binding());
            schedule
                .retirements
                .entry(capability.deactivation_height_exclusive())
                .or_default()
                .push(capability.binding());
        }
        schedule
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

    fn scheduled_at(&self, height: u64) -> BTreeSet<VersionBinding> {
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

    /// Bind the configurable timing schedule to the source-owned proof
    /// capability registry. Schedule mutation may narrow or delay a release,
    /// but it cannot create proof authority for an arbitrary decoder binding.
    /// Historical replay is deliberately absent because this surface has no
    /// authenticated chain/checkpoint context.
    pub fn allowed_at(&self, height: u64) -> BTreeSet<VersionBinding> {
        let scheduled = self.scheduled_at(height);
        let source_authorized = fresh_transaction_proof_capabilities()
            .into_iter()
            .filter(|capability| {
                matches!(
                    proof_authority_decision(
                        ProofAuthorityOperation::BlockAcceptance,
                        ProofAuthorityContext {
                            network_id: HEGEMON_PROOF_NETWORK_ID,
                            height,
                            binding: capability.binding(),
                            family_id: capability.family_id(),
                            action_id: capability.action_id(),
                            proof_class: ProofAuthorityClass::Transaction,
                            historical_chain: None,
                        },
                        &[],
                    ),
                    ProofAuthorityDecision::Fresh(_)
                )
            })
            .map(|capability| capability.binding())
            .collect::<BTreeSet<_>>();
        scheduled
            .intersection(&source_authorized)
            .copied()
            .collect()
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

    #[test]
    fn default_schedule_contains_only_source_authorized_fresh_bindings() {
        let expected = fresh_transaction_proof_capabilities()
            .into_iter()
            .filter(|capability| capability.active_at(0))
            .map(|capability| capability.binding())
            .collect::<BTreeSet<_>>();
        let schedule = VersionSchedule::default();

        assert_eq!(schedule.allowed_at(0), expected);
        assert!(
            !schedule.is_allowed(protocol_versioning::DEFAULT_VERSION_BINDING, 0),
            "the V4 decoder default must not become fresh consensus authority"
        );
    }

    #[test]
    fn arbitrary_schedule_entries_cannot_create_proof_authority() {
        let decoder_only = protocol_versioning::DEFAULT_VERSION_BINDING;
        let invented = VersionBinding::new(
            decoder_only.circuit.saturating_add(100),
            decoder_only.crypto,
        );
        let mut schedule = VersionSchedule::new([decoder_only]);
        schedule.register(VersionProposal {
            binding: invented,
            activates_at: 0,
            retires_at: None,
            upgrade: None,
        });

        assert!(schedule.scheduled_at(0).contains(&decoder_only));
        assert!(schedule.scheduled_at(0).contains(&invented));
        assert!(schedule.allowed_at(0).is_empty());
        assert!(!schedule.is_allowed(decoder_only, 0));
        assert!(!schedule.is_allowed(invented, 0));
    }

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

        // The generated vectors model schedule arithmetic only. Production
        // `allowed_at` additionally intersects this set with source authority.
        let allowed = schedule.scheduled_at(case.height);
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

        let first_unsupported = case
            .tx_versions
            .iter()
            .copied()
            .find(|version| !allowed.contains(version));
        let result = first_unsupported.map_or(Ok(()), Err);
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
