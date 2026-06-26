use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use transaction_circuit::{
    constants::FIELD_MODULUS_U64, smallwood_policy_root_bytes, smallwood_signer_tag_from_spend_key,
    SmallwoodAccumulatorAuthOpening, SmallwoodSignerTag,
};

use crate::error::WalletError;

pub const MULTISIG_FLOW_VERSION: u8 = 2;
pub const REAL_APPROVAL_PROOF_HOOK: &str = "hegemon_multisig_approval_step_circuit_v1";
pub const REAL_FINAL_SPEND_PROOF_HOOK: &str = "hegemon_multisig_final_spend_circuit_v1";

const DOMAIN_POLICY_COMMITMENT: &[u8] = b"hegemon-wallet-smallwood-multisig-policy-commitment-v1";
const DOMAIN_ACCOUNT_ID: &[u8] = b"hegemon-wallet-smallwood-multisig-account-id-v1";
const DOMAIN_ACCOUNT_SETUP_HINT: &[u8] = b"hegemon-wallet-smallwood-multisig-account-setup-hint-v1";
const DOMAIN_INTENT_DIGEST: &[u8] = b"hegemon-wallet-multisig-intent-digest-v1";
const DOMAIN_APPROVAL_DUPLICATE_TAG: &[u8] =
    b"hegemon-wallet-smallwood-multisig-approval-duplicate-tag-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigIntentRecipient {
    pub address: String,
    pub value: u64,
    pub asset_id: u64,
    #[serde(default)]
    pub memo: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigSpendIntent {
    pub recipients: Vec<MultisigIntentRecipient>,
    pub fee: u64,
    #[serde(with = "serde_bytes48")]
    pub anchor: [u8; 48],
    #[serde(with = "serde_bytes48")]
    pub transaction_binding: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigAccountPublic {
    pub version: u8,
    #[serde(with = "serde_bytes32")]
    pub account_id: [u8; 32],
    #[serde(with = "serde_bytes48")]
    pub policy_commitment: [u8; 48],
    #[serde(with = "serde_bytes48")]
    pub initial_accumulator_note: [u8; 48],
    pub approval_proof_hook: String,
    pub final_spend_proof_hook: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigAccountRecord {
    pub public: MultisigAccountPublic,
    #[serde(with = "serde_bytes48")]
    pub policy_root: [u8; 48],
    pub threshold: u64,
    pub policy_signer_tags: [SmallwoodSignerTag; 2],
    #[serde(with = "serde_bytes32")]
    pub policy_commitment_randomness: [u8; 32],
    pub intents: Vec<MultisigIntentState>,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigIntentState {
    #[serde(with = "serde_bytes48")]
    pub intent_digest: [u8; 48],
    #[serde(with = "serde_bytes48")]
    pub current_accumulator_note: [u8; 48],
    pub approval_count: u64,
    pub approved_slots: [u64; 2],
    pub approvals: Vec<MultisigStoredApproval>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigStoredApproval {
    pub signer_tag: SmallwoodSignerTag,
    #[serde(with = "serde_bytes48")]
    pub duplicate_tag: [u8; 48],
    pub imported_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigApprovalPackage {
    pub version: u8,
    #[serde(with = "serde_bytes32")]
    pub account_id: [u8; 32],
    #[serde(with = "serde_bytes48")]
    pub intent_digest: [u8; 48],
    #[serde(with = "serde_bytes48")]
    pub previous_accumulator_note: [u8; 48],
    #[serde(with = "serde_bytes48")]
    pub next_accumulator_note: [u8; 48],
    #[serde(with = "serde_bytes48")]
    pub approval_commitment: [u8; 48],
    pub proof_hook: String,
    #[serde(with = "serde_bytes_vec")]
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigFinalSpendPackage {
    pub version: u8,
    #[serde(with = "serde_bytes32")]
    pub account_id: [u8; 32],
    #[serde(with = "serde_bytes48")]
    pub intent_digest: [u8; 48],
    #[serde(with = "serde_bytes48")]
    pub consumed_accumulator_note: [u8; 48],
    #[serde(with = "serde_bytes48")]
    pub final_spend_commitment: [u8; 48],
    pub proof_hook: String,
    #[serde(with = "serde_bytes_vec")]
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedApproval {
    pub signer_slot: u16,
    pub signer_tag: SmallwoodSignerTag,
    pub duplicate_tag: [u8; 48],
}

pub fn signer_tag_from_spend_key(spend_key: &[u8; 32]) -> SmallwoodSignerTag {
    smallwood_signer_tag_from_spend_key(spend_key)
}

pub fn create_account_record<R: RngCore + ?Sized>(
    threshold: u64,
    policy_signer_tags: [SmallwoodSignerTag; 2],
    rng: &mut R,
    created_at: u64,
) -> Result<MultisigAccountRecord, WalletError> {
    let policy_signer_tags = normalize_policy(threshold, policy_signer_tags)?;

    let mut policy_commitment_randomness = [0u8; 32];
    rng.fill_bytes(&mut policy_commitment_randomness);
    let mut account_nonce = [0u8; 32];
    rng.fill_bytes(&mut account_nonce);

    let policy_root = smallwood_policy_root_bytes(threshold, policy_signer_tags);
    let threshold_bytes = threshold.to_le_bytes();
    let signer0 = signer_tag_bytes(policy_signer_tags[0]);
    let signer1 = signer_tag_bytes(policy_signer_tags[1]);
    let policy_commitment = hash48(
        DOMAIN_POLICY_COMMITMENT,
        &[
            &policy_root,
            &threshold_bytes,
            &signer0,
            &signer1,
            &policy_commitment_randomness,
        ],
    );
    let account_id = hash32(
        DOMAIN_ACCOUNT_ID,
        &[
            &policy_commitment,
            &policy_commitment_randomness,
            &account_nonce,
        ],
    );
    let setup_hint = hash48(
        DOMAIN_ACCOUNT_SETUP_HINT,
        &[&account_id, &policy_commitment],
    );

    Ok(MultisigAccountRecord {
        public: MultisigAccountPublic {
            version: MULTISIG_FLOW_VERSION,
            account_id,
            policy_commitment,
            initial_accumulator_note: setup_hint,
            approval_proof_hook: REAL_APPROVAL_PROOF_HOOK.to_string(),
            final_spend_proof_hook: REAL_FINAL_SPEND_PROOF_HOOK.to_string(),
        },
        policy_root,
        threshold,
        policy_signer_tags,
        policy_commitment_randomness,
        intents: Vec::new(),
        created_at,
    })
}

pub fn intent_digest(intent: &MultisigSpendIntent) -> Result<[u8; 48], WalletError> {
    if intent.recipients.is_empty() {
        return Err(WalletError::InvalidArgument(
            "multisig intent requires at least one recipient",
        ));
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(intent.recipients.len() as u32).to_le_bytes());
    for recipient in &intent.recipients {
        let address = recipient.address.as_bytes();
        let memo = recipient.memo.as_deref().unwrap_or("").as_bytes();
        encoded.extend_from_slice(&(address.len() as u32).to_le_bytes());
        encoded.extend_from_slice(address);
        encoded.extend_from_slice(&recipient.value.to_le_bytes());
        encoded.extend_from_slice(&recipient.asset_id.to_le_bytes());
        encoded.extend_from_slice(&(memo.len() as u32).to_le_bytes());
        encoded.extend_from_slice(memo);
    }
    encoded.extend_from_slice(&intent.fee.to_le_bytes());
    encoded.extend_from_slice(&intent.anchor);
    encoded.extend_from_slice(&intent.transaction_binding);
    Ok(hash48(DOMAIN_INTENT_DIGEST, &[&encoded]))
}

pub fn approval_circuit_hooks_available() -> bool {
    true
}

pub fn create_approval(
    spend_key: &[u8; 32],
    account: &MultisigAccountPublic,
    intent: &MultisigSpendIntent,
    previous_accumulator_note: [u8; 48],
) -> Result<MultisigApprovalPackage, WalletError> {
    let _ = (spend_key, account, intent, previous_accumulator_note);
    Err(WalletError::InvalidState(
        "opaque multisig approval packages are unsupported; build a shielded approval transaction",
    ))
}

pub fn verify_approval_for_record(
    record: &MultisigAccountRecord,
    package: &MultisigApprovalPackage,
) -> Result<VerifiedApproval, WalletError> {
    let _ = (record, package);
    Err(WalletError::InvalidState(
        "opaque multisig approval packages are unsupported; verify the shielded approval transaction",
    ))
}

pub fn create_final_spend_package(
    record: &MultisigAccountRecord,
    intent: &MultisigSpendIntent,
    consumed_accumulator_note: [u8; 48],
) -> Result<MultisigFinalSpendPackage, WalletError> {
    let _ = (record, intent, consumed_accumulator_note);
    Err(WalletError::InvalidState(
        "opaque multisig final-spend packages are unsupported; build a shielded final transaction",
    ))
}

pub fn accumulator_opening(
    record: &MultisigAccountRecord,
    intent_digest: [u8; 48],
    approval_count: u64,
    approved_slots: [u64; 2],
) -> Result<SmallwoodAccumulatorAuthOpening, WalletError> {
    validate_accumulator_state(record.threshold, approved_slots, approval_count)?;
    Ok(SmallwoodAccumulatorAuthOpening {
        policy_root: record.policy_root,
        intent_digest,
        threshold: record.threshold,
        approval_count,
        approved_slots,
    })
}

pub fn initial_accumulator_opening(
    record: &MultisigAccountRecord,
    intent_digest: [u8; 48],
) -> SmallwoodAccumulatorAuthOpening {
    SmallwoodAccumulatorAuthOpening {
        policy_root: record.policy_root,
        intent_digest,
        threshold: record.threshold,
        approval_count: 0,
        approved_slots: [0, 0],
    }
}

pub fn next_accumulator_after_approval(
    current: &SmallwoodAccumulatorAuthOpening,
    policy_signer_tags: [SmallwoodSignerTag; 2],
    signer_tag: SmallwoodSignerTag,
) -> Result<SmallwoodAccumulatorAuthOpening, WalletError> {
    let slot = policy_signer_tags
        .iter()
        .position(|tag| *tag == signer_tag)
        .ok_or(WalletError::InvalidArgument(
            "local signer is not in hidden multisig policy",
        ))?;
    validate_accumulator_state(
        current.threshold,
        current.approved_slots,
        current.approval_count,
    )?;
    if current.approved_slots[slot] != 0 {
        return Err(WalletError::InvalidArgument(
            "multisig duplicate signer approval",
        ));
    }
    let mut next = current.clone();
    next.approval_count =
        current
            .approval_count
            .checked_add(1)
            .ok_or(WalletError::InvalidArgument(
                "multisig approval count overflow",
            ))?;
    next.approved_slots[slot] = 1;
    validate_accumulator_state(next.threshold, next.approved_slots, next.approval_count)?;
    Ok(next)
}

pub fn approval_duplicate_tag(
    account_id: &[u8; 32],
    intent_digest: &[u8; 48],
    signer_tag: SmallwoodSignerTag,
) -> [u8; 48] {
    let signer_tag = signer_tag_bytes(signer_tag);
    hash48(
        DOMAIN_APPROVAL_DUPLICATE_TAG,
        &[account_id, intent_digest, &signer_tag],
    )
}

fn normalize_policy(
    threshold: u64,
    mut policy_signer_tags: [SmallwoodSignerTag; 2],
) -> Result<[SmallwoodSignerTag; 2], WalletError> {
    if !(1..=2).contains(&threshold) {
        return Err(WalletError::InvalidArgument(
            "multisig threshold outside proven SmallWood scope",
        ));
    }
    validate_signer_tag(policy_signer_tags[0])?;
    validate_signer_tag(policy_signer_tags[1])?;
    policy_signer_tags.sort_unstable();
    if policy_signer_tags[0] == policy_signer_tags[1] {
        return Err(WalletError::InvalidArgument(
            "multisig policy signers must be distinct",
        ));
    }
    Ok(policy_signer_tags)
}

fn validate_accumulator_state(
    threshold: u64,
    approved_slots: [u64; 2],
    approval_count: u64,
) -> Result<(), WalletError> {
    if !(1..=2).contains(&threshold) {
        return Err(WalletError::InvalidArgument(
            "multisig threshold outside proven SmallWood scope",
        ));
    }
    if approved_slots.iter().any(|slot| !matches!(slot, 0 | 1)) {
        return Err(WalletError::InvalidArgument(
            "multisig approved slots must be boolean",
        ));
    }
    let actual_count = approved_slots[0] + approved_slots[1];
    if approval_count > 2 || approval_count != actual_count {
        return Err(WalletError::InvalidArgument(
            "multisig accumulator outside proven approval-count scope",
        ));
    }
    Ok(())
}

fn validate_signer_tag(signer_tag: SmallwoodSignerTag) -> Result<(), WalletError> {
    if signer_tag.iter().all(|limb| *limb == 0)
        || signer_tag.iter().any(|limb| *limb >= FIELD_MODULUS_U64)
    {
        return Err(WalletError::InvalidArgument(
            "multisig signer tag must be a nonzero canonical field tag",
        ));
    }
    Ok(())
}

fn signer_tag_bytes(
    signer_tag: SmallwoodSignerTag,
) -> [u8; transaction_circuit::SMALLWOOD_SIGNER_TAG_WORDS * 8] {
    let mut out = [0u8; transaction_circuit::SMALLWOOD_SIGNER_TAG_WORDS * 8];
    for (idx, limb) in signer_tag.iter().enumerate() {
        out[idx * 8..idx * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

fn hash32(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid blake2 output size");
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("output size matches");
    out
}

fn hash48(domain: &[u8], parts: &[&[u8]]) -> [u8; 48] {
    let mut hasher = Blake2bVar::new(48).expect("valid blake2 output size");
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let mut out = [0u8; 48];
    hasher
        .finalize_variable(&mut out)
        .expect("output size matches");
    out
}

mod serde_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod serde_bytes48 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 48 {
            return Err(serde::de::Error::custom("expected 48 bytes"));
        }
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn tag(seed: u64) -> SmallwoodSignerTag {
        [seed, seed + 1, seed + 2, seed + 3, seed + 4]
    }

    fn intent() -> MultisigSpendIntent {
        MultisigSpendIntent {
            recipients: vec![MultisigIntentRecipient {
                address: "shca1recipient".to_string(),
                value: 42,
                asset_id: 7,
                memo: Some("memo".to_string()),
            }],
            fee: 3,
            anchor: [4u8; 48],
            transaction_binding: [5u8; 48],
        }
    }

    #[test]
    fn multisig_intent_digest_binds_every_spend_field() {
        let base = intent();
        let digest = intent_digest(&base).unwrap();
        let mut changed = base.clone();
        changed.recipients[0].address.push('x');
        assert_ne!(digest, intent_digest(&changed).unwrap());
        let mut changed = base.clone();
        changed.recipients[0].value += 1;
        assert_ne!(digest, intent_digest(&changed).unwrap());
        let mut changed = base.clone();
        changed.recipients[0].asset_id += 1;
        assert_ne!(digest, intent_digest(&changed).unwrap());
        let mut changed = base.clone();
        changed.fee += 1;
        assert_ne!(digest, intent_digest(&changed).unwrap());
        let mut changed = base.clone();
        changed.anchor[0] ^= 1;
        assert_ne!(digest, intent_digest(&changed).unwrap());
        let mut changed = base;
        changed.transaction_binding[0] ^= 1;
        assert_ne!(digest, intent_digest(&changed).unwrap());
    }

    #[test]
    fn account_record_uses_smallwood_two_signer_policy_root() {
        let mut rng = StdRng::seed_from_u64(7);
        let tags = [tag(17), tag(11)];
        let expected_tags = [tag(11), tag(17)];
        let record = create_account_record(2, tags, &mut rng, 10).unwrap();
        assert_eq!(record.threshold, 2);
        assert_eq!(record.policy_signer_tags, expected_tags);
        assert_eq!(
            record.policy_root,
            smallwood_policy_root_bytes(2, expected_tags)
        );
        assert_eq!(record.public.approval_proof_hook, REAL_APPROVAL_PROOF_HOOK);

        let public_json = serde_json::to_string(&record.public).unwrap();
        assert!(!public_json.contains("threshold"));
        assert!(!public_json.contains("policy_signer_tags"));
        assert!(!public_json.contains("policyRoot"));
        assert!(!public_json.contains("approvalCount"));
    }

    #[test]
    fn unsupported_policy_shapes_fail_closed() {
        let mut rng = StdRng::seed_from_u64(8);
        assert!(create_account_record(0, [tag(11), tag(17)], &mut rng, 10)
            .unwrap_err()
            .to_string()
            .contains("outside proven"));
        assert!(create_account_record(3, [tag(11), tag(17)], &mut rng, 10)
            .unwrap_err()
            .to_string()
            .contains("outside proven"));
        assert!(create_account_record(2, [tag(11), tag(11)], &mut rng, 10)
            .unwrap_err()
            .to_string()
            .contains("distinct"));
    }

    #[test]
    fn approval_accumulator_transition_matches_smallwood_scope() {
        let mut rng = StdRng::seed_from_u64(9);
        let tags = [tag(11), tag(17)];
        let record = create_account_record(2, tags, &mut rng, 10).unwrap();
        let current = initial_accumulator_opening(&record, [3u8; 48]);
        let next =
            next_accumulator_after_approval(&current, record.policy_signer_tags, tag(11)).unwrap();
        assert_eq!(next.approval_count, 1);
        assert_eq!(next.approved_slots, [1, 0]);

        let next =
            next_accumulator_after_approval(&next, record.policy_signer_tags, tag(17)).unwrap();
        assert_eq!(next.approval_count, 2);
        assert_eq!(next.approved_slots, [1, 1]);
        assert!(
            next_accumulator_after_approval(&next, record.policy_signer_tags, tag(17)).is_err()
        );
    }

    #[test]
    fn opaque_packages_fail_closed() {
        let mut rng = StdRng::seed_from_u64(10);
        let record = create_account_record(2, [tag(11), tag(17)], &mut rng, 10).unwrap();
        assert!(approval_circuit_hooks_available());
        let err = create_approval(
            &[1u8; 32],
            &record.public,
            &intent(),
            record.public.initial_accumulator_note,
        )
        .unwrap_err();
        assert!(err.to_string().contains("shielded approval transaction"));
    }
}
