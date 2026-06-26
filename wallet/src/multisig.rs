use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use transaction_circuit::PredicateThresholdPolicyOpening;

use crate::error::WalletError;

pub const MULTISIG_FLOW_VERSION: u8 = 1;
pub const REAL_APPROVAL_PROOF_HOOK: &str = "hegemon_multisig_approval_step_circuit_v1";
pub const REAL_FINAL_SPEND_PROOF_HOOK: &str = "hegemon_multisig_final_spend_circuit_v1";
#[cfg(test)]
const PROVISIONAL_APPROVAL_PROOF_HOOK: &str =
    "PROVISIONAL_WALLET_MULTISIG_APPROVAL_PROOF_HOOK_REPLACE_WITH_CIRCUIT";
#[cfg(test)]
const PROVISIONAL_FINAL_SPEND_PROOF_HOOK: &str =
    "PROVISIONAL_WALLET_MULTISIG_FINAL_SPEND_PROOF_HOOK_REPLACE_WITH_CIRCUIT";

const DOMAIN_SIGNER_COMMITMENT: &[u8] = b"hegemon-wallet-multisig-signer-commitment-v1";
const DOMAIN_POLICY_ROOT: &[u8] = b"hegemon-wallet-multisig-policy-root-v1";
const DOMAIN_POLICY_COMMITMENT: &[u8] = b"hegemon-wallet-multisig-policy-commitment-v1";
const DOMAIN_ACCOUNT_ID: &[u8] = b"hegemon-wallet-multisig-account-id-v1";
const DOMAIN_INITIAL_ACCUMULATOR: &[u8] = b"hegemon-wallet-multisig-initial-accumulator-v1";
const DOMAIN_INTENT_DIGEST: &[u8] = b"hegemon-wallet-multisig-intent-digest-v1";
#[cfg(test)]
const DOMAIN_APPROVAL_COMMITMENT: &[u8] = b"hegemon-wallet-multisig-approval-commitment-v1";
#[cfg(test)]
const DOMAIN_APPROVAL_DUPLICATE_TAG: &[u8] = b"hegemon-wallet-multisig-approval-duplicate-tag-v1";
#[cfg(test)]
const DOMAIN_APPROVAL_PROOF: &[u8] = b"hegemon-wallet-multisig-provisional-approval-proof-v1";
#[cfg(test)]
const DOMAIN_NEXT_ACCUMULATOR: &[u8] = b"hegemon-wallet-multisig-next-accumulator-v1";
#[cfg(test)]
const DOMAIN_FINAL_PROOF: &[u8] = b"hegemon-wallet-multisig-provisional-final-proof-v1";

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
    pub threshold: u16,
    #[serde(with = "serde_vec_bytes48")]
    pub signer_commitments: Vec<[u8; 48]>,
    #[serde(with = "serde_bytes32")]
    pub policy_commitment_randomness: [u8; 32],
    #[serde(with = "serde_bytes32")]
    pub policy_pk_auth: [u8; 32],
    pub intents: Vec<MultisigIntentState>,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigIntentState {
    #[serde(with = "serde_bytes48")]
    pub intent_digest: [u8; 48],
    #[serde(with = "serde_bytes48")]
    pub current_accumulator_note: [u8; 48],
    pub approvals: Vec<MultisigStoredApproval>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigStoredApproval {
    pub signer_slot: u16,
    #[serde(with = "serde_bytes48")]
    pub duplicate_tag: [u8; 48],
    pub package: MultisigApprovalPackage,
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
    pub duplicate_tag: [u8; 48],
}

pub fn signer_commitment_from_spend_key(spend_key: &[u8; 32]) -> [u8; 48] {
    hash48(DOMAIN_SIGNER_COMMITMENT, &[spend_key])
}

pub fn create_account_record<R: RngCore + ?Sized>(
    threshold: u16,
    mut signer_commitments: Vec<[u8; 48]>,
    rng: &mut R,
    created_at: u64,
) -> Result<MultisigAccountRecord, WalletError> {
    if threshold == 0 {
        return Err(WalletError::InvalidArgument(
            "multisig threshold must be greater than zero",
        ));
    }
    if signer_commitments.is_empty() {
        return Err(WalletError::InvalidArgument(
            "multisig signer commitments are required",
        ));
    }
    signer_commitments.sort_unstable();
    signer_commitments.dedup();
    if usize::from(threshold) > signer_commitments.len() {
        return Err(WalletError::InvalidArgument(
            "multisig threshold exceeds signer commitments",
        ));
    }

    let mut policy_commitment_randomness = [0u8; 32];
    rng.fill_bytes(&mut policy_commitment_randomness);
    let mut account_nonce = [0u8; 32];
    rng.fill_bytes(&mut account_nonce);

    let signer_refs: Vec<&[u8]> = signer_commitments
        .iter()
        .map(|commitment| commitment.as_slice())
        .collect();
    let policy_root = hash48(DOMAIN_POLICY_ROOT, &signer_refs);
    let account_id = hash32(
        DOMAIN_ACCOUNT_ID,
        &[&policy_root, &policy_commitment_randomness, &account_nonce],
    );
    let threshold_bytes = threshold.to_le_bytes();
    let policy_commitment = hash48(
        DOMAIN_POLICY_COMMITMENT,
        &[
            &policy_root,
            &threshold_bytes,
            &policy_commitment_randomness,
        ],
    );
    let policy_pk_auth = PredicateThresholdPolicyOpening {
        policy_root,
        threshold,
        policy_commitment_randomness,
    }
    .policy_commitment_key()
    .map_err(|err| WalletError::InvalidState(Box::leak(err.to_string().into_boxed_str())))?;
    let initial_accumulator_note = hash48(
        DOMAIN_INITIAL_ACCUMULATOR,
        &[&account_id, &policy_commitment, &account_nonce],
    );

    Ok(MultisigAccountRecord {
        public: MultisigAccountPublic {
            version: MULTISIG_FLOW_VERSION,
            account_id,
            policy_commitment,
            initial_accumulator_note,
            approval_proof_hook: REAL_APPROVAL_PROOF_HOOK.to_string(),
            final_spend_proof_hook: REAL_FINAL_SPEND_PROOF_HOOK.to_string(),
        },
        policy_root,
        threshold,
        signer_commitments,
        policy_commitment_randomness,
        policy_pk_auth,
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
    false
}

pub fn create_approval(
    spend_key: &[u8; 32],
    account: &MultisigAccountPublic,
    intent: &MultisigSpendIntent,
    previous_accumulator_note: [u8; 48],
) -> Result<MultisigApprovalPackage, WalletError> {
    let _ = (spend_key, account, intent, previous_accumulator_note);
    Err(WalletError::InvalidState(
        "multisig approval circuit integration missing",
    ))
}

pub fn verify_approval_for_record(
    record: &MultisigAccountRecord,
    package: &MultisigApprovalPackage,
) -> Result<VerifiedApproval, WalletError> {
    let _ = (record, package);
    Err(WalletError::InvalidState(
        "multisig approval circuit integration missing",
    ))
}

pub fn create_final_spend_package(
    record: &MultisigAccountRecord,
    intent: &MultisigSpendIntent,
    consumed_accumulator_note: [u8; 48],
) -> Result<MultisigFinalSpendPackage, WalletError> {
    let _ = (record, intent, consumed_accumulator_note);
    Err(WalletError::InvalidState(
        "multisig final-spend circuit integration missing",
    ))
}

#[cfg(test)]
fn create_test_approval(
    spend_key: &[u8; 32],
    account: &MultisigAccountPublic,
    intent: &MultisigSpendIntent,
    previous_accumulator_note: [u8; 48],
) -> Result<MultisigApprovalPackage, WalletError> {
    if account.version != MULTISIG_FLOW_VERSION {
        return Err(WalletError::InvalidArgument(
            "unsupported multisig account version",
        ));
    }
    let signer_commitment = signer_commitment_from_spend_key(spend_key);
    let digest = intent_digest(intent)?;
    let approval_commitment = approval_commitment(
        &account.account_id,
        &digest,
        &previous_accumulator_note,
        &signer_commitment,
    );
    let proof_bytes = provisional_approval_proof_bytes(
        &account.account_id,
        &digest,
        &previous_accumulator_note,
        &approval_commitment,
        &signer_commitment,
    );
    let proof_hash = hash48(DOMAIN_APPROVAL_PROOF, &[&proof_bytes]);
    let next_accumulator_note = hash48(
        DOMAIN_NEXT_ACCUMULATOR,
        &[
            &account.account_id,
            &digest,
            &previous_accumulator_note,
            &approval_commitment,
            &proof_hash,
        ],
    );
    Ok(MultisigApprovalPackage {
        version: MULTISIG_FLOW_VERSION,
        account_id: account.account_id,
        intent_digest: digest,
        previous_accumulator_note,
        next_accumulator_note,
        approval_commitment,
        proof_hook: PROVISIONAL_APPROVAL_PROOF_HOOK.to_string(),
        proof_bytes,
    })
}

#[cfg(test)]
fn verify_test_approval_for_record(
    record: &MultisigAccountRecord,
    package: &MultisigApprovalPackage,
) -> Result<VerifiedApproval, WalletError> {
    if package.version != MULTISIG_FLOW_VERSION {
        return Err(WalletError::InvalidArgument(
            "unsupported multisig approval version",
        ));
    }
    if package.account_id != record.public.account_id {
        return Err(WalletError::InvalidArgument(
            "multisig approval account id mismatch",
        ));
    }
    if package.proof_hook != PROVISIONAL_APPROVAL_PROOF_HOOK {
        return Err(WalletError::InvalidArgument(
            "unsupported multisig approval proof hook",
        ));
    }
    let proof_hash = hash48(DOMAIN_APPROVAL_PROOF, &[&package.proof_bytes]);
    let expected_next = hash48(
        DOMAIN_NEXT_ACCUMULATOR,
        &[
            &package.account_id,
            &package.intent_digest,
            &package.previous_accumulator_note,
            &package.approval_commitment,
            &proof_hash,
        ],
    );
    if expected_next != package.next_accumulator_note {
        return Err(WalletError::InvalidArgument(
            "multisig approval accumulator transition mismatch",
        ));
    }

    for (idx, signer_commitment) in record.signer_commitments.iter().enumerate() {
        let expected_commitment = approval_commitment(
            &package.account_id,
            &package.intent_digest,
            &package.previous_accumulator_note,
            signer_commitment,
        );
        if expected_commitment != package.approval_commitment {
            continue;
        }
        let expected_proof = provisional_approval_proof_bytes(
            &package.account_id,
            &package.intent_digest,
            &package.previous_accumulator_note,
            &package.approval_commitment,
            signer_commitment,
        );
        if expected_proof != package.proof_bytes {
            return Err(WalletError::InvalidArgument(
                "multisig approval proof bytes mismatch",
            ));
        }
        let signer_slot = u16::try_from(idx)
            .map_err(|_| WalletError::InvalidState("multisig signer index overflow"))?;
        let duplicate_tag = approval_duplicate_tag(
            &package.account_id,
            &package.intent_digest,
            signer_commitment,
        );
        return Ok(VerifiedApproval {
            signer_slot,
            duplicate_tag,
        });
    }

    Err(WalletError::InvalidArgument(
        "multisig approval signer is not in hidden policy",
    ))
}

#[cfg(test)]
fn create_test_final_spend_package(
    record: &MultisigAccountRecord,
    intent: &MultisigSpendIntent,
    consumed_accumulator_note: [u8; 48],
) -> Result<MultisigFinalSpendPackage, WalletError> {
    let digest = intent_digest(intent)?;
    let state = record
        .intents
        .iter()
        .find(|state| state.intent_digest == digest)
        .ok_or(WalletError::InvalidArgument(
            "multisig intent has no accumulated approvals",
        ))?;
    if state.approvals.len() < usize::from(record.threshold) {
        return Err(WalletError::InvalidArgument(
            "multisig threshold accumulator is incomplete",
        ));
    }
    if state.current_accumulator_note != consumed_accumulator_note {
        return Err(WalletError::InvalidArgument(
            "multisig final spend accumulator note mismatch",
        ));
    }
    let threshold_bytes = record.threshold.to_le_bytes();
    let final_spend_commitment = hash48(
        DOMAIN_FINAL_PROOF,
        &[
            &record.public.account_id,
            &digest,
            &consumed_accumulator_note,
            &record.public.policy_commitment,
            &threshold_bytes,
        ],
    );
    let proof_bytes = hash48(
        DOMAIN_FINAL_PROOF,
        &[
            b"proof",
            &record.public.account_id,
            &digest,
            &consumed_accumulator_note,
            &final_spend_commitment,
        ],
    )
    .to_vec();
    Ok(MultisigFinalSpendPackage {
        version: MULTISIG_FLOW_VERSION,
        account_id: record.public.account_id,
        intent_digest: digest,
        consumed_accumulator_note,
        final_spend_commitment,
        proof_hook: PROVISIONAL_FINAL_SPEND_PROOF_HOOK.to_string(),
        proof_bytes,
    })
}

#[cfg(test)]
fn approval_commitment(
    account_id: &[u8; 32],
    intent_digest: &[u8; 48],
    previous_accumulator_note: &[u8; 48],
    signer_commitment: &[u8; 48],
) -> [u8; 48] {
    hash48(
        DOMAIN_APPROVAL_COMMITMENT,
        &[
            account_id,
            intent_digest,
            previous_accumulator_note,
            signer_commitment,
        ],
    )
}

#[cfg(test)]
fn approval_duplicate_tag(
    account_id: &[u8; 32],
    intent_digest: &[u8; 48],
    signer_commitment: &[u8; 48],
) -> [u8; 48] {
    hash48(
        DOMAIN_APPROVAL_DUPLICATE_TAG,
        &[account_id, intent_digest, signer_commitment],
    )
}

#[cfg(test)]
fn provisional_approval_proof_bytes(
    account_id: &[u8; 32],
    intent_digest: &[u8; 48],
    previous_accumulator_note: &[u8; 48],
    approval_commitment: &[u8; 48],
    signer_commitment: &[u8; 48],
) -> Vec<u8> {
    hash48(
        DOMAIN_APPROVAL_PROOF,
        &[
            account_id,
            intent_digest,
            previous_accumulator_note,
            approval_commitment,
            signer_commitment,
        ],
    )
    .to_vec()
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

mod serde_vec_bytes48 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(values: &[[u8; 48]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wrapped: Vec<_> = values
            .iter()
            .map(|bytes| serde_bytes::Bytes::new(bytes))
            .collect();
        wrapped.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 48]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wrapped: Vec<serde_bytes::ByteBuf> = Vec::deserialize(deserializer)?;
        wrapped
            .into_iter()
            .map(|buf| {
                let data = buf.into_vec();
                if data.len() != 48 {
                    return Err(serde::de::Error::custom("expected 48 bytes"));
                }
                let mut out = [0u8; 48];
                out.copy_from_slice(&data);
                Ok(out)
            })
            .collect()
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
    fn multisig_approval_package_keeps_policy_shape_private() {
        let signer_a = signer_commitment_from_spend_key(&[1u8; 32]);
        let signer_b = signer_commitment_from_spend_key(&[2u8; 32]);
        let mut rng = StdRng::seed_from_u64(7);
        let record = create_account_record(2, vec![signer_a, signer_b], &mut rng, 10).unwrap();
        assert!(!approval_circuit_hooks_available());
        assert_eq!(
            record.public.approval_proof_hook,
            REAL_APPROVAL_PROOF_HOOK.to_string()
        );
        let err = create_approval(
            &[1u8; 32],
            &record.public,
            &intent(),
            record.public.initial_accumulator_note,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("multisig approval circuit integration missing"));

        let package = create_test_approval(
            &[1u8; 32],
            &record.public,
            &intent(),
            record.public.initial_accumulator_note,
        )
        .unwrap();
        let json = serde_json::to_string(&package).unwrap();
        assert!(!json.contains("threshold"));
        assert!(!json.contains("signer"));
        assert!(!json.contains("policyRoot"));
        assert!(!json.contains("policy_root"));
        assert!(!json.contains("approvalCount"));
        assert!(!json.contains("approvalNullifier"));
        assert!(verify_test_approval_for_record(&record, &package).is_ok());
    }

    #[test]
    fn test_only_multisig_accumulator_finalizes_exact_intent_only() {
        let signer_a = signer_commitment_from_spend_key(&[1u8; 32]);
        let signer_b = signer_commitment_from_spend_key(&[2u8; 32]);
        let mut rng = StdRng::seed_from_u64(9);
        let mut record = create_account_record(2, vec![signer_a, signer_b], &mut rng, 10).unwrap();
        let intent = intent();
        let digest = intent_digest(&intent).unwrap();

        let approval_a = create_test_approval(
            &[1u8; 32],
            &record.public,
            &intent,
            record.public.initial_accumulator_note,
        )
        .unwrap();
        let verified_a = verify_test_approval_for_record(&record, &approval_a).unwrap();
        let approval_b = create_test_approval(
            &[2u8; 32],
            &record.public,
            &intent,
            approval_a.next_accumulator_note,
        )
        .unwrap();
        let verified_b = verify_test_approval_for_record(&record, &approval_b).unwrap();
        record.intents.push(MultisigIntentState {
            intent_digest: digest,
            current_accumulator_note: approval_b.next_accumulator_note,
            approvals: vec![
                MultisigStoredApproval {
                    signer_slot: verified_a.signer_slot,
                    duplicate_tag: verified_a.duplicate_tag,
                    package: approval_a,
                    imported_at: 11,
                },
                MultisigStoredApproval {
                    signer_slot: verified_b.signer_slot,
                    duplicate_tag: verified_b.duplicate_tag,
                    package: approval_b.clone(),
                    imported_at: 12,
                },
            ],
        });

        let final_spend =
            create_test_final_spend_package(&record, &intent, approval_b.next_accumulator_note)
                .unwrap();
        assert_eq!(final_spend.intent_digest, digest);

        let mut changed = intent.clone();
        changed.recipients[0].value += 1;
        assert!(create_test_final_spend_package(
            &record,
            &changed,
            approval_b.next_accumulator_note
        )
        .unwrap_err()
        .to_string()
        .contains("no accumulated approvals"));
        assert!(
            create_test_final_spend_package(&record, &intent, [0x55u8; 48])
                .unwrap_err()
                .to_string()
                .contains("accumulator note mismatch")
        );
    }
}
