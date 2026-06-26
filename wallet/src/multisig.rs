use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use transaction_circuit::{
    constants::FIELD_MODULUS_U64, smallwood_policy_root_bytes, SmallwoodAccumulatorAuthOpening,
};

use crate::error::WalletError;

pub const MULTISIG_FLOW_VERSION: u8 = 2;
pub const REAL_APPROVAL_PROOF_HOOK: &str = "hegemon_multisig_approval_step_circuit_v1";
pub const REAL_FINAL_SPEND_PROOF_HOOK: &str = "hegemon_multisig_final_spend_circuit_v1";

const DOMAIN_SIGNER_ID: &[u8] = b"hegemon-wallet-smallwood-multisig-signer-id-v1";
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
    pub policy_signers: [u64; 2],
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
    pub signer_slots: [u64; 2],
    pub approvals: Vec<MultisigStoredApproval>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigStoredApproval {
    pub signer_id: u64,
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
    pub signer_id: u64,
    pub duplicate_tag: [u8; 48],
}

pub fn signer_id_from_spend_key(spend_key: &[u8; 32]) -> u64 {
    let digest = hash48(DOMAIN_SIGNER_ID, &[spend_key]);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    let modulus = u128::from(FIELD_MODULUS_U64);
    (u128::from_le_bytes(bytes) % (modulus - 1) + 1) as u64
}

pub fn create_account_record<R: RngCore + ?Sized>(
    threshold: u64,
    policy_signers: [u64; 2],
    rng: &mut R,
    created_at: u64,
) -> Result<MultisigAccountRecord, WalletError> {
    let policy_signers = normalize_policy(threshold, policy_signers)?;

    let mut policy_commitment_randomness = [0u8; 32];
    rng.fill_bytes(&mut policy_commitment_randomness);
    let mut account_nonce = [0u8; 32];
    rng.fill_bytes(&mut account_nonce);

    let policy_root = smallwood_policy_root_bytes(threshold, policy_signers);
    let threshold_bytes = threshold.to_le_bytes();
    let signer0 = policy_signers[0].to_le_bytes();
    let signer1 = policy_signers[1].to_le_bytes();
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
        policy_signers,
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
    signer_slots: [u64; 2],
) -> Result<SmallwoodAccumulatorAuthOpening, WalletError> {
    validate_accumulator_state(record.threshold, signer_slots, approval_count)?;
    Ok(SmallwoodAccumulatorAuthOpening {
        policy_root: record.policy_root,
        intent_digest,
        threshold: record.threshold,
        approval_count,
        signer_slots,
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
        signer_slots: [0, 0],
    }
}

pub fn next_accumulator_after_approval(
    current: &SmallwoodAccumulatorAuthOpening,
    signer_id: u64,
) -> Result<(SmallwoodAccumulatorAuthOpening, u64), WalletError> {
    validate_signer_id(signer_id)?;
    let mut next = current.clone();
    let duplicate_inverse = match current.approval_count {
        0 => {
            if current.signer_slots != [0, 0] {
                return Err(WalletError::InvalidArgument(
                    "empty multisig accumulator has nonempty signer slots",
                ));
            }
            next.approval_count = 1;
            next.signer_slots = [signer_id, 0];
            0
        }
        1 => {
            let existing = current.signer_slots[0];
            validate_signer_id(existing)?;
            if current.signer_slots[1] != 0 {
                return Err(WalletError::InvalidArgument(
                    "single-approval accumulator has a second signer slot",
                ));
            }
            let duplicate_inverse = signer_difference_inverse(signer_id, existing)?;
            next.approval_count = 2;
            next.signer_slots = [existing, signer_id];
            duplicate_inverse
        }
        _ => {
            return Err(WalletError::InvalidArgument(
                "multisig accumulator already reached the proven approval limit",
            ));
        }
    };
    Ok((next, duplicate_inverse))
}

pub fn approval_duplicate_tag(
    account_id: &[u8; 32],
    intent_digest: &[u8; 48],
    signer_id: u64,
) -> [u8; 48] {
    hash48(
        DOMAIN_APPROVAL_DUPLICATE_TAG,
        &[account_id, intent_digest, &signer_id.to_le_bytes()],
    )
}

fn normalize_policy(threshold: u64, mut policy_signers: [u64; 2]) -> Result<[u64; 2], WalletError> {
    if !(1..=2).contains(&threshold) {
        return Err(WalletError::InvalidArgument(
            "multisig threshold outside proven SmallWood scope",
        ));
    }
    validate_signer_id(policy_signers[0])?;
    validate_signer_id(policy_signers[1])?;
    policy_signers.sort_unstable();
    if policy_signers[0] == policy_signers[1] {
        return Err(WalletError::InvalidArgument(
            "multisig policy signers must be distinct",
        ));
    }
    Ok(policy_signers)
}

fn validate_accumulator_state(
    threshold: u64,
    signer_slots: [u64; 2],
    approval_count: u64,
) -> Result<(), WalletError> {
    if !(1..=2).contains(&threshold) {
        return Err(WalletError::InvalidArgument(
            "multisig threshold outside proven SmallWood scope",
        ));
    }
    match approval_count {
        0 => {
            if signer_slots != [0, 0] {
                return Err(WalletError::InvalidArgument(
                    "empty multisig accumulator has nonempty signer slots",
                ));
            }
        }
        1 => {
            validate_signer_id(signer_slots[0])?;
            if signer_slots[1] != 0 {
                return Err(WalletError::InvalidArgument(
                    "single-approval accumulator has a second signer slot",
                ));
            }
        }
        2 => {
            validate_signer_id(signer_slots[0])?;
            validate_signer_id(signer_slots[1])?;
            let _ = signer_difference_inverse(signer_slots[1], signer_slots[0])?;
        }
        _ => {
            return Err(WalletError::InvalidArgument(
                "multisig accumulator outside proven approval-count scope",
            ));
        }
    }
    Ok(())
}

fn validate_signer_id(signer_id: u64) -> Result<(), WalletError> {
    if signer_id == 0 || signer_id >= FIELD_MODULUS_U64 {
        return Err(WalletError::InvalidArgument(
            "multisig signer id must be a nonzero canonical field element",
        ));
    }
    Ok(())
}

fn signer_difference_inverse(signer_id: u64, existing: u64) -> Result<u64, WalletError> {
    validate_signer_id(signer_id)?;
    validate_signer_id(existing)?;
    let modulus = i128::from(FIELD_MODULUS_U64);
    let diff = (i128::from(signer_id) - i128::from(existing)).rem_euclid(modulus);
    if diff == 0 {
        return Err(WalletError::InvalidArgument(
            "multisig duplicate signer approval",
        ));
    }
    Ok(mod_inverse(diff as u64, FIELD_MODULUS_U64))
}

fn mod_inverse(value: u64, modulus: u64) -> u64 {
    let (mut t, mut next_t) = (0i128, 1i128);
    let (mut r, mut next_r) = (i128::from(modulus), i128::from(value));
    while next_r != 0 {
        let quotient = r / next_r;
        (t, next_t) = (next_t, t - quotient * next_t);
        (r, next_r) = (next_r, r - quotient * next_r);
    }
    if t < 0 {
        t += i128::from(modulus);
    }
    t as u64
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
        let record = create_account_record(2, [17, 11], &mut rng, 10).unwrap();
        assert_eq!(record.threshold, 2);
        assert_eq!(record.policy_signers, [11, 17]);
        assert_eq!(record.policy_root, smallwood_policy_root_bytes(2, [11, 17]));
        assert_eq!(record.public.approval_proof_hook, REAL_APPROVAL_PROOF_HOOK);

        let public_json = serde_json::to_string(&record.public).unwrap();
        assert!(!public_json.contains("threshold"));
        assert!(!public_json.contains("policy_signers"));
        assert!(!public_json.contains("policyRoot"));
        assert!(!public_json.contains("approvalCount"));
    }

    #[test]
    fn unsupported_policy_shapes_fail_closed() {
        let mut rng = StdRng::seed_from_u64(8);
        assert!(create_account_record(0, [11, 17], &mut rng, 10)
            .unwrap_err()
            .to_string()
            .contains("outside proven"));
        assert!(create_account_record(3, [11, 17], &mut rng, 10)
            .unwrap_err()
            .to_string()
            .contains("outside proven"));
        assert!(create_account_record(2, [11, 11], &mut rng, 10)
            .unwrap_err()
            .to_string()
            .contains("distinct"));
    }

    #[test]
    fn approval_accumulator_transition_matches_smallwood_scope() {
        let mut rng = StdRng::seed_from_u64(9);
        let record = create_account_record(2, [11, 17], &mut rng, 10).unwrap();
        let current = initial_accumulator_opening(&record, [3u8; 48]);
        let (next, inverse) = next_accumulator_after_approval(&current, 11).unwrap();
        assert_eq!(inverse, 0);
        assert_eq!(next.approval_count, 1);
        assert_eq!(next.signer_slots, [11, 0]);

        let (next, inverse) = next_accumulator_after_approval(&next, 17).unwrap();
        assert_ne!(inverse, 0);
        assert_eq!(next.approval_count, 2);
        assert_eq!(next.signer_slots, [11, 17]);
        assert!(next_accumulator_after_approval(&next, 17).is_err());
    }

    #[test]
    fn opaque_packages_fail_closed() {
        let mut rng = StdRng::seed_from_u64(10);
        let record = create_account_record(2, [11, 17], &mut rng, 10).unwrap();
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
