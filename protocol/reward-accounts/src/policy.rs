use crate::{
    hash48, AccountKeyHash48, AccountPolicyId48, BoundedVec, RewardAccountsError as Error,
    MAX_ACCOUNT_SIGNERS,
};
use codec::{Decode, Encode};
use crypto::{
    ml_dsa::{
        MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, ML_DSA_PUBLIC_KEY_LEN, ML_DSA_SIGNATURE_LEN,
    },
    traits::{SigningKey, VerifyKey},
};
use serde::{Deserialize, Serialize};

const KEY_DOMAIN: &[u8] = b"hegemon.reward-account.ml-dsa-65.key.v1";
const POLICY_DOMAIN: &[u8] = b"hegemon.reward-account.ml-dsa-65.policy.v1";

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AccountPolicy {
    SingleKey {
        key_hash: AccountKeyHash48,
    },
    Threshold {
        threshold: u8,
        signer_hashes: BoundedVec<AccountKeyHash48, MAX_ACCOUNT_SIGNERS>,
    },
}
impl AccountPolicy {
    pub fn single(key: &MlDsaPublicKey) -> Self {
        Self::SingleKey {
            key_hash: account_key_hash(key),
        }
    }
    /// Hash order defines signer indices, independent of arrival order.
    pub fn threshold(threshold: u8, mut keys: Vec<AccountKeyHash48>) -> Result<Self, Error> {
        keys.sort();
        let policy = Self::Threshold {
            threshold,
            signer_hashes: BoundedVec::new(keys).map_err(|_| Error::InvalidPolicy)?,
        };
        policy.validate()?;
        Ok(policy)
    }
    pub fn validate(&self) -> Result<(), Error> {
        let keys = self.signer_hashes();
        if self.required() == 0
            || self.required() > keys.len()
            || keys.len() > MAX_ACCOUNT_SIGNERS
            || keys.contains(&AccountKeyHash48::ZERO)
            || keys.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::InvalidPolicy);
        }
        Ok(())
    }
    pub fn identifier(&self) -> Result<AccountPolicyId48, Error> {
        self.validate()?;
        Ok(AccountPolicyId48::new(hash48(
            POLICY_DOMAIN,
            &self.encode(),
        )))
    }
    pub fn required(&self) -> usize {
        match self {
            Self::SingleKey { .. } => 1,
            Self::Threshold { threshold, .. } => *threshold as usize,
        }
    }
    pub fn signer_hashes(&self) -> &[AccountKeyHash48] {
        match self {
            Self::SingleKey { key_hash } => std::slice::from_ref(key_hash),
            Self::Threshold { signer_hashes, .. } => signer_hashes,
        }
    }
    pub fn verify(&self, message: &[u8; 48], approvals: &[AccountApproval]) -> Result<(), Error> {
        self.validate()?;
        if approvals.len() < self.required()
            || approvals.len() > self.signer_hashes().len()
            || approvals
                .windows(2)
                .any(|pair| pair[0].signer_index >= pair[1].signer_index)
        {
            return Err(Error::InvalidApprovals);
        }
        for approval in approvals {
            let expected = self
                .signer_hashes()
                .get(approval.signer_index as usize)
                .ok_or(Error::InvalidApprovals)?;
            let key = MlDsaPublicKey::from_bytes(&approval.public_key)
                .map_err(|_| Error::InvalidApprovals)?;
            if account_key_hash(&key) != *expected {
                return Err(Error::InvalidApprovals);
            }
            let signature = MlDsaSignature::from_bytes(&approval.signature)
                .map_err(|_| Error::InvalidApprovals)?;
            key.verify(message, &signature)
                .map_err(|_| Error::InvalidApprovals)?;
        }
        Ok(())
    }
}

pub fn account_key_hash(key: &MlDsaPublicKey) -> AccountKeyHash48 {
    AccountKeyHash48::new(hash48(KEY_DOMAIN, &key.to_bytes()))
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountApproval {
    pub signer_index: u8,
    pub public_key: BoundedVec<u8, ML_DSA_PUBLIC_KEY_LEN>,
    pub signature: BoundedVec<u8, ML_DSA_SIGNATURE_LEN>,
}
impl AccountApproval {
    pub fn sign(signer_index: u8, key: &MlDsaSecretKey, message: &[u8; 48]) -> Self {
        Self {
            signer_index,
            public_key: BoundedVec::new(key.verify_key().to_bytes())
                .expect("fixed ML-DSA key size"),
            signature: BoundedVec::new(key.sign(message).to_bytes())
                .expect("fixed ML-DSA signature size"),
        }
    }
}
