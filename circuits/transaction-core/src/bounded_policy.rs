//! Fixed, native-compatible two-branch spending policies.
//!
//! This module owns canonical policy encoding and note-owner commitments. It
//! does not grant proof acceptance, evaluate SHA-256, or authorize a release.
use crate::poseidon2_width16::{poseidon2_width16_compress14, poseidon2_width16_sponge, Felt};
use alloc::vec::Vec;

pub const VERSION: u64 = 1;
pub const BRANCHES: usize = 2;
pub const BRANCH_WORDS: usize = 19;
pub const POLICY_WORDS: usize = 1 + BRANCHES * BRANCH_WORDS;
pub const POLICY_DOMAIN: u64 = 0x5053_4250_4f4c_0001;
pub const OWNER_DOMAIN: u64 = 0x5053_4250_574e_0001;
const P: u64 = 0xffff_ffff_0000_0001;

#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Branch {
    pub enabled: u64,
    pub authority: [u64; 7],
    /// Minimum proof-reference parent height, not actual inclusion height.
    pub not_before: u64,
    pub hash_required: u64,
    pub hashlock: [u8; 32],
    pub release_secret: u64,
}

// The shared nullifier key is private custody material: deliberately no Debug.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub nullifier_key: [u64; 5],
    pub branches: [Branch; BRANCHES],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PolicyError {
    Noncanonical,
    Boolean,
    Height,
    DisabledPadding,
    MissingBranch,
    MissingKey,
    HashPadding,
    ReleaseWithoutHash,
    Context,
}
impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "bounded spending policy: {self:?}")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for PolicyError {}

impl Policy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.nullifier_key.iter().any(|x| *x >= P) {
            return Err(PolicyError::Noncanonical);
        }
        if self.nullifier_key[0] == 0 {
            return Err(PolicyError::MissingKey);
        }
        if self.branches[0].enabled != 1 {
            return Err(PolicyError::MissingBranch);
        }
        for branch in &self.branches {
            if branch.enabled > 1 || branch.hash_required > 1 || branch.release_secret > 1 {
                return Err(PolicyError::Boolean);
            }
            if branch.authority.iter().any(|x| *x >= P) {
                return Err(PolicyError::Noncanonical);
            }
            if branch.not_before >= 1 << 48 {
                return Err(PolicyError::Height);
            }
            if branch.enabled == 0 {
                if branch.authority != [0; 7]
                    || branch.not_before != 0
                    || branch.hash_required != 0
                    || branch.hashlock != [0; 32]
                    || branch.release_secret != 0
                {
                    return Err(PolicyError::DisabledPadding);
                }
                continue;
            }
            if branch.authority == [0; 7] {
                return Err(PolicyError::MissingKey);
            }
            if branch.hash_required == 0 && branch.hashlock != [0; 32] {
                return Err(PolicyError::HashPadding);
            }
            if branch.release_secret > branch.hash_required {
                return Err(PolicyError::ReleaseWithoutHash);
            }
        }
        Ok(())
    }

    /// Version followed by two positional, completely padded branch encodings.
    /// The nullifier key is committed separately by `owner`, never per branch.
    pub fn words(&self) -> Result<[u64; POLICY_WORDS], PolicyError> {
        self.validate()?;
        let mut words = [0; POLICY_WORDS];
        words[0] = VERSION;
        for (index, branch) in self.branches.iter().enumerate() {
            let at = 1 + index * BRANCH_WORDS;
            words[at] = branch.enabled;
            words[at + 1..at + 8].copy_from_slice(&branch.authority);
            words[at + 8] = branch.not_before;
            words[at + 9] = branch.hash_required;
            for (j, bytes) in branch.hashlock.chunks_exact(4).enumerate() {
                words[at + 10 + j] =
                    u32::from_le_bytes(bytes.try_into().expect("four bytes")) as u64;
            }
            words[at + 18] = branch.release_secret;
        }
        Ok(words)
    }

    pub fn from_words(
        nullifier_key: [u64; 5],
        words: [u64; POLICY_WORDS],
    ) -> Result<Self, PolicyError> {
        if words[0] != VERSION {
            return Err(PolicyError::Noncanonical);
        }
        let mut branches = core::array::from_fn(|_| Branch::default());
        for (index, branch) in branches.iter_mut().enumerate() {
            let at = 1 + index * BRANCH_WORDS;
            branch.enabled = words[at];
            branch.authority.copy_from_slice(&words[at + 1..at + 8]);
            branch.not_before = words[at + 8];
            branch.hash_required = words[at + 9];
            for j in 0..8 {
                let word =
                    u32::try_from(words[at + 10 + j]).map_err(|_| PolicyError::Noncanonical)?;
                branch.hashlock[4 * j..4 * j + 4].copy_from_slice(&word.to_le_bytes());
            }
            branch.release_secret = words[at + 18];
        }
        let policy = Self {
            nullifier_key,
            branches,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn owner(&self, chain: [u8; 32], asset_id: u64) -> Result<[u64; 7], PolicyError> {
        let words = self.words()?;
        if chain == [0; 32] || asset_id >= P {
            return Err(PolicyError::Context);
        }
        let mut fields = Vec::with_capacity(8 + 1 + POLICY_WORDS);
        for bytes in chain.chunks_exact(4) {
            fields.push(u32::from_le_bytes(bytes.try_into().expect("four bytes")) as u64);
        }
        fields.push(asset_id);
        fields.extend(words);
        let digest = poseidon2_width16_sponge(
            POLICY_DOMAIN,
            &fields
                .iter()
                .copied()
                .map(Felt::from_u64)
                .collect::<Vec<_>>(),
        )
        .map_err(|_| PolicyError::Noncanonical)?;
        let mut key = [Felt::ZERO; 7];
        for (out, value) in key.iter_mut().zip(self.nullifier_key) {
            *out = Felt::from_u64(value);
        }
        Ok(poseidon2_width16_compress14(OWNER_DOMAIN, &key, &digest).map(|f| f.as_canonical_u64()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        Policy {
            nullifier_key: [7; 5],
            branches: [
                Branch {
                    enabled: 1,
                    authority: [2; 7],
                    ..Default::default()
                },
                Branch::default(),
            ],
        }
    }
    #[test]
    fn bounded_policy_exact_words_roundtrip_and_owner_bindings() {
        let p = policy();
        let words = p.words().unwrap();
        assert_eq!(words.len(), 39);
        assert!(Policy::from_words(p.nullifier_key, words).unwrap() == p);
        let owner = p.owner([3; 32], 0).unwrap();
        assert_ne!(owner, p.owner([4; 32], 0).unwrap());
        assert_ne!(owner, p.owner([3; 32], 1).unwrap());
        let mut changed = p.clone();
        changed.nullifier_key[1] += 1;
        assert_ne!(owner, changed.owner([3; 32], 0).unwrap());
        changed = p.clone();
        changed.branches[0].not_before = 10;
        assert_ne!(owner, changed.owner([3; 32], 0).unwrap());
        changed = p.clone();
        changed.branches[1] = Branch {
            enabled: 1,
            authority: [9; 7],
            ..Default::default()
        };
        assert_ne!(owner, changed.owner([3; 32], 0).unwrap());
        changed.branches[1].hash_required = 1;
        changed.branches[1].hashlock = [12; 32];
        let private = changed.owner([3; 32], 0).unwrap();
        changed.branches[1].release_secret = 1;
        assert_ne!(private, changed.owner([3; 32], 0).unwrap());
        assert!(
            Policy::from_words(changed.nullifier_key, changed.words().unwrap()).unwrap() == changed
        );
    }
    #[test]
    fn bounded_policy_rejects_noncanonical_padding_flags_and_keys() {
        let p = policy();
        let mut bad = p.clone();
        bad.branches[0].enabled = 0;
        assert!(bad.validate().is_err());
        bad = p.clone();
        bad.branches[1].not_before = 1;
        assert_eq!(bad.validate(), Err(PolicyError::DisabledPadding));
        bad = p.clone();
        bad.branches[0].hashlock[0] = 1;
        assert_eq!(bad.validate(), Err(PolicyError::HashPadding));
        bad = p.clone();
        bad.branches[0].release_secret = 1;
        assert_eq!(bad.validate(), Err(PolicyError::ReleaseWithoutHash));
        bad = p.clone();
        bad.branches[0].hash_required = 2;
        assert_eq!(bad.validate(), Err(PolicyError::Boolean));
        bad = p.clone();
        bad.branches[0].not_before = 1 << 48;
        assert_eq!(bad.validate(), Err(PolicyError::Height));
        bad = p.clone();
        bad.branches[0].authority[0] = P;
        assert_eq!(bad.validate(), Err(PolicyError::Noncanonical));
        bad = p.clone();
        bad.nullifier_key[0] = 0;
        assert_eq!(bad.validate(), Err(PolicyError::MissingKey));
        bad = p.clone();
        bad.branches[0].authority = [0; 7];
        assert_eq!(bad.validate(), Err(PolicyError::MissingKey));
        let mut words = p.words().unwrap();
        words[0] += 1;
        assert!(Policy::from_words(p.nullifier_key, words).is_err());
        words = p.words().unwrap();
        words[11] = 1 << 32;
        assert!(Policy::from_words(p.nullifier_key, words).is_err());
        assert_eq!(p.owner([0; 32], 0), Err(PolicyError::Context));
    }
}
