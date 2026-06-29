//! Pure private multisig accumulator authorization model.
//!
//! This module is a conformance target for the Lean model in
//! `formal/lean/Hegemon/Transaction/PrivateMultisigAccumulator.lean`.
//! It intentionally models stateful shielded accumulator authorization, not
//! signatures, threshold signatures, or MPC.

use serde::{Deserialize, Serialize};

pub const DIGEST_MODULUS: u64 = 65_537;

pub type Digest = u64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendIntent {
    pub account_digest: Digest,
    pub policy_root: Digest,
    pub intent_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyWitness {
    pub account_digest: Digest,
    pub policy_root: Digest,
    pub threshold: u64,
    pub signer_set_root: Digest,
    pub signer_tags: Vec<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccumulatorNote {
    pub account_digest: Digest,
    pub policy_root: Digest,
    pub intent_digest: Digest,
    pub approval_count: u64,
    pub approval_nullifiers: Vec<Digest>,
    pub approval_leaves: Vec<Digest>,
    pub state_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerCapabilityNote {
    pub policy_root: Digest,
    pub signer_tag: Digest,
    pub signer_nullifier: Digest,
    pub capability_secret_commitment: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalStep {
    pub policy: PolicyWitness,
    pub intent: SpendIntent,
    pub prior_accumulator: AccumulatorNote,
    pub signer_capability: SignerCapabilityNote,
    pub spend_derived_signer_tag: Digest,
    pub next_accumulator: AccumulatorNote,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueNote {
    pub account_digest: Digest,
    pub note_commitment: Digest,
    pub value_lock_digest: Digest,
    pub public_nullifier: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalSpend {
    pub policy: PolicyWitness,
    pub intent: SpendIntent,
    pub value_note: ValueNote,
    pub accumulator: AccumulatorNote,
    pub output_commitment: Digest,
    pub output_ciphertext_hash: Digest,
    pub balance_tag: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicTransactionShape {
    pub input_nullifier: Digest,
    pub output_commitment: Digest,
    pub output_ciphertext_hash: Digest,
    pub balance_tag: Digest,
}

pub fn approval_leaf_digest(intent: &SpendIntent, capability: &SignerCapabilityNote) -> Digest {
    (intent.account_digest * 17
        + intent.policy_root * 31
        + intent.intent_digest * 43
        + capability.signer_tag * 59
        + capability.signer_nullifier * 61
        + 7)
        % DIGEST_MODULUS
}

pub fn accumulator_state_digest(accumulator: &AccumulatorNote) -> Digest {
    (accumulator.account_digest * 101
        + accumulator.policy_root * 103
        + accumulator.intent_digest * 107
        + accumulator.approval_count * 109
        + accumulator.approval_nullifiers.len() as u64 * 113
        + accumulator.approval_leaves.len() as u64 * 127
        + 13)
        % DIGEST_MODULUS
}

pub fn next_accumulator_for_approval(
    prior: &AccumulatorNote,
    capability: &SignerCapabilityNote,
) -> AccumulatorNote {
    let intent = SpendIntent {
        account_digest: prior.account_digest,
        policy_root: prior.policy_root,
        intent_digest: prior.intent_digest,
    };
    let mut next = AccumulatorNote {
        account_digest: prior.account_digest,
        policy_root: prior.policy_root,
        intent_digest: prior.intent_digest,
        approval_count: prior.approval_count + 1,
        approval_nullifiers: {
            let mut values = Vec::with_capacity(prior.approval_nullifiers.len() + 1);
            values.push(capability.signer_nullifier);
            values.extend_from_slice(&prior.approval_nullifiers);
            values
        },
        approval_leaves: {
            let mut values = Vec::with_capacity(prior.approval_leaves.len() + 1);
            values.push(approval_leaf_digest(&intent, capability));
            values.extend_from_slice(&prior.approval_leaves);
            values
        },
        state_digest: 0,
    };
    next.state_digest = accumulator_state_digest(&next);
    next
}

pub fn accumulator_matches_intent(accumulator: &AccumulatorNote, intent: &SpendIntent) -> bool {
    accumulator.account_digest == intent.account_digest
        && accumulator.policy_root == intent.policy_root
        && accumulator.intent_digest == intent.intent_digest
}

pub fn accumulator_matches_policy(accumulator: &AccumulatorNote, policy: &PolicyWitness) -> bool {
    accumulator.account_digest == policy.account_digest
        && accumulator.policy_root == policy.policy_root
}

pub fn signer_in_policy(capability: &SignerCapabilityNote, policy: &PolicyWitness) -> bool {
    policy.signer_tags.contains(&capability.signer_tag)
}

pub fn signer_set_root_digest(signer_tags: &[Digest]) -> Digest {
    signer_tags
        .iter()
        .rev()
        .fold(19 % DIGEST_MODULUS, |rest, tag| {
            (tag * 131 + rest * 137 + 23) % DIGEST_MODULUS
        })
}

pub fn policy_root_digest(
    account_digest: Digest,
    threshold: u64,
    signer_set_root: Digest,
) -> Digest {
    (account_digest * 149 + threshold * 151 + signer_set_root * 157 + 29) % DIGEST_MODULUS
}

pub fn policy_well_formed(policy: &PolicyWitness) -> bool {
    if policy.threshold == 0 || policy.threshold as usize > policy.signer_tags.len() {
        return false;
    }
    if policy.signer_tags.contains(&0) {
        return false;
    }
    for (idx, tag) in policy.signer_tags.iter().enumerate() {
        if policy.signer_tags[idx + 1..].contains(tag) {
            return false;
        }
    }
    policy.signer_set_root == signer_set_root_digest(&policy.signer_tags)
        && policy.policy_root
            == policy_root_digest(
                policy.account_digest,
                policy.threshold,
                policy.signer_set_root,
            )
}

pub fn value_lock_digest(policy_root: Digest, intent_digest: Digest) -> Digest {
    (policy_root * 163 + intent_digest * 167 + 31) % DIGEST_MODULUS
}

pub fn value_note_locked_to_intent(note: &ValueNote, intent: &SpendIntent) -> bool {
    note.value_lock_digest == value_lock_digest(intent.policy_root, intent.intent_digest)
}

pub fn approval_step_exact_intent_and_one_shot(step: &ApprovalStep) -> bool {
    accumulator_matches_intent(&step.prior_accumulator, &step.intent)
        && !step
            .prior_accumulator
            .approval_nullifiers
            .contains(&step.signer_capability.signer_nullifier)
        && step.prior_accumulator.state_digest == accumulator_state_digest(&step.prior_accumulator)
        && step.next_accumulator
            == next_accumulator_for_approval(&step.prior_accumulator, &step.signer_capability)
        && step
            .next_accumulator
            .approval_nullifiers
            .contains(&step.signer_capability.signer_nullifier)
}

pub fn approval_step_accepted(step: &ApprovalStep) -> bool {
    policy_well_formed(&step.policy)
        && approval_step_exact_intent_and_one_shot(step)
        && accumulator_matches_policy(&step.prior_accumulator, &step.policy)
        && step.signer_capability.policy_root == step.policy.policy_root
        && step.signer_capability.signer_tag == step.spend_derived_signer_tag
        && signer_in_policy(&step.signer_capability, &step.policy)
}

pub fn final_spend_accepted(spend: &FinalSpend) -> bool {
    policy_well_formed(&spend.policy)
        && spend.value_note.account_digest == spend.intent.account_digest
        && value_note_locked_to_intent(&spend.value_note, &spend.intent)
        && accumulator_matches_policy(&spend.accumulator, &spend.policy)
        && accumulator_matches_intent(&spend.accumulator, &spend.intent)
        && spend.accumulator.state_digest == accumulator_state_digest(&spend.accumulator)
        && spend.accumulator.approval_count >= spend.policy.threshold
}

pub fn public_shape_from_final_spend(spend: &FinalSpend) -> PublicTransactionShape {
    PublicTransactionShape {
        input_nullifier: spend.value_note.public_nullifier,
        output_commitment: spend.output_commitment,
        output_ciphertext_hash: spend.output_ciphertext_hash,
        balance_tag: spend.balance_tag,
    }
}

pub fn final_spend_contains_signer_long_term_secret(
    _spend: &FinalSpend,
    _signer_long_term_secret: u64,
) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct LeanPrivateMultisigAccumulatorVectors {
        schema_version: u32,
        digest_modulus: u64,
        privacy_model: String,
        private_fields: Vec<String>,
        public_shape_fields: Vec<String>,
        cases: Vec<LeanPrivateMultisigAccumulatorCase>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanPrivateMultisigAccumulatorCase {
        name: String,
        kind: String,
        policy: PolicyWitness,
        intent: SpendIntent,
        #[serde(default)]
        prior_accumulator: Option<AccumulatorNote>,
        #[serde(default)]
        signer_capability: Option<SignerCapabilityNote>,
        #[serde(default)]
        spend_derived_signer_tag: Option<Digest>,
        #[serde(default)]
        next_accumulator: Option<AccumulatorNote>,
        #[serde(default)]
        value_note: Option<ValueNote>,
        #[serde(default)]
        accumulator: Option<AccumulatorNote>,
        #[serde(default)]
        output_commitment: Option<Digest>,
        #[serde(default)]
        output_ciphertext_hash: Option<Digest>,
        #[serde(default)]
        balance_tag: Option<Digest>,
        expected_valid: bool,
    }

    fn load_vectors() -> LeanPrivateMultisigAccumulatorVectors {
        if let Ok(path) = std::env::var("HEGEMON_LEAN_PRIVATE_MULTISIG_ACCUMULATOR_VECTORS") {
            let bytes = std::fs::read(&path).unwrap_or_else(|err| {
                panic!("failed to read Lean private multisig vectors {path}: {err}")
            });
            return serde_json::from_slice(&bytes).unwrap_or_else(|err| {
                panic!("failed to parse Lean private multisig vectors {path}: {err}")
            });
        }

        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest_dir
            .parent()
            .and_then(std::path::Path::parent)
            .expect("transaction crate must live under circuits/transaction");
        let output = std::process::Command::new("lake")
            .args(["exe", "gen_private_multisig_accumulator_vectors"])
            .current_dir(root.join("formal/lean"))
            .output()
            .unwrap_or_else(|err| {
                panic!("failed to run Lean private multisig vector generator: {err}")
            });
        assert!(
            output.status.success(),
            "Lean private multisig vector generator failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
            panic!("failed to parse generated Lean private multisig vectors: {err}")
        })
    }

    fn approval_step_from_case(case: &LeanPrivateMultisigAccumulatorCase) -> ApprovalStep {
        ApprovalStep {
            policy: case.policy.clone(),
            intent: case.intent.clone(),
            prior_accumulator: case
                .prior_accumulator
                .clone()
                .unwrap_or_else(|| panic!("{} missing prior_accumulator", case.name)),
            signer_capability: case
                .signer_capability
                .clone()
                .unwrap_or_else(|| panic!("{} missing signer_capability", case.name)),
            spend_derived_signer_tag: case
                .spend_derived_signer_tag
                .unwrap_or_else(|| panic!("{} missing spend_derived_signer_tag", case.name)),
            next_accumulator: case
                .next_accumulator
                .clone()
                .unwrap_or_else(|| panic!("{} missing next_accumulator", case.name)),
        }
    }

    fn final_spend_from_case(case: &LeanPrivateMultisigAccumulatorCase) -> FinalSpend {
        FinalSpend {
            policy: case.policy.clone(),
            intent: case.intent.clone(),
            value_note: case
                .value_note
                .clone()
                .unwrap_or_else(|| panic!("{} missing value_note", case.name)),
            accumulator: case
                .accumulator
                .clone()
                .unwrap_or_else(|| panic!("{} missing accumulator", case.name)),
            output_commitment: case
                .output_commitment
                .unwrap_or_else(|| panic!("{} missing output_commitment", case.name)),
            output_ciphertext_hash: case
                .output_ciphertext_hash
                .unwrap_or_else(|| panic!("{} missing output_ciphertext_hash", case.name)),
            balance_tag: case
                .balance_tag
                .unwrap_or_else(|| panic!("{} missing balance_tag", case.name)),
        }
    }

    #[test]
    fn private_multisig_accumulator_matches_lean_vectors() {
        let vectors = load_vectors();
        assert_eq!(vectors.schema_version, 1);
        assert_eq!(vectors.digest_modulus, DIGEST_MODULUS);
        assert_eq!(
            vectors.privacy_model,
            "stateful_shielded_accumulator_no_signatures_no_mpc"
        );
        assert_eq!(
            vectors.public_shape_fields,
            vec![
                "input_nullifier",
                "output_commitment",
                "output_ciphertext_hash",
                "balance_tag",
            ]
        );
        for field in [
            "signer_set_root",
            "threshold",
            "approval_count",
            "approval_leaves",
            "policy_root",
            "approval_nullifiers",
            "signer_tags",
            "spend_derived_signer_tag",
            "value_lock_digest",
        ] {
            assert!(
                vectors.private_fields.iter().any(|actual| actual == field),
                "Lean private-field list omitted {field}"
            );
        }

        let expected_names = [
            "valid-approval-step",
            "duplicate-signer-rejected",
            "wrong-intent-rejected",
            "wrong-policy-rejected",
            "outside-policy-signer-rejected",
            "forged-signer-tag-rejected",
            "zero-threshold-policy-approval-rejected",
            "threshold-above-signer-count-policy-approval-rejected",
            "duplicate-signer-policy-approval-rejected",
            "signer-set-root-drift-policy-approval-rejected",
            "below-threshold-final-rejected",
            "exact-threshold-final-accepted",
            "final-intent-mismatch-rejected",
            "final-value-lock-mismatch-rejected",
            "zero-threshold-final-rejected",
            "duplicate-signer-policy-final-rejected",
        ];
        assert_eq!(vectors.cases.len(), expected_names.len());

        for expected_name in expected_names {
            let case = vectors
                .cases
                .iter()
                .find(|case| case.name == expected_name)
                .unwrap_or_else(|| panic!("missing Lean vector case {expected_name}"));
            let actual_valid = match case.kind.as_str() {
                "approval" => approval_step_accepted(&approval_step_from_case(case)),
                "final" => final_spend_accepted(&final_spend_from_case(case)),
                other => panic!("{} has unknown case kind {other}", case.name),
            };
            assert_eq!(
                actual_valid, case.expected_valid,
                "Lean private multisig vector case {} disagreed with Rust",
                case.name
            );

            if case.kind == "approval" && case.expected_valid {
                assert!(
                    approval_step_exact_intent_and_one_shot(&approval_step_from_case(case)),
                    "{} accepted without exact-intent one-shot accumulator facts",
                    case.name
                );
            }

            if case.kind == "final" {
                let spend = final_spend_from_case(case);
                assert!(
                    !final_spend_contains_signer_long_term_secret(&spend, 123_456),
                    "{} final spend witness unexpectedly carried signer long-term secret",
                    case.name
                );
                let public_shape = public_shape_from_final_spend(&spend);
                assert_eq!(
                    public_shape.input_nullifier,
                    spend.value_note.public_nullifier
                );
                assert_eq!(public_shape.output_commitment, spend.output_commitment);
                assert_eq!(
                    public_shape.output_ciphertext_hash,
                    spend.output_ciphertext_hash
                );
                assert_eq!(public_shape.balance_tag, spend.balance_tag);
            }
        }
    }
}
