//! Successor-only explicit public-account credit/debit relation. Reuses the
//! ordinary note authority/membership graph, not its zero-external-value rule.
//! Candidate proofs are not production source or security authorization.
use crate::smallwood_engine::{
    prove_statement_with_transcript_backend_profile_and_domain,
    verify_statement_with_transcript_backend_profile_and_domain, SmallwoodDecsEvaluationDomain,
    SmallwoodTranscriptBackend, REWARD_ACCOUNTS_SMZT_SMALLWOOD_NO_GRINDING_PROFILE,
};
use crate::{
    private_spend::{Digest, PrivateSpendAdapter, PrivateSpendPublic, PrivateSpendWitness},
    TransactionCircuitError,
};
use codec::{Decode, Encode};
use protocol_reward_accounts::{BoundedVec, MAX_REWARD_PROOF_BYTES};
use zeroize::Zeroizing;

pub const RELATION_ID: &str = "Hegemon.RewardAccounts.Transfer.ExplicitCreditDebit.v1";
pub const EXTENSION_WORDS: usize = 37;
pub const PUBLIC_WORDS: usize = crate::private_spend::PUBLIC_WORDS + EXTENSION_WORDS;
pub const CARRIER_MAGIC: [u8; 8] = *b"HGRAC001";
pub const CIPHERTEXT_BYTES: usize = 2608;
pub const PROOF_BYTES: usize =
    crate::smallwood_engine::SMALLWOOD_REWARD_ACCOUNTS_SMZT_FIXED_INNER_PROOF_BYTES;
pub const MAX_CARRIER_BYTES: usize = PROOF_BYTES + 8192;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RewardSpendPublic {
    pub relation_digest: [u8; 48],
    pub base: PrivateSpendPublic,
    /// Zero donation, one account claim; neither is hidden behind the fee field.
    pub claim: u64,
    pub amount: u64,
    /// Domain hash of the complete account/donation context and exact operation.
    pub operation_binding: [u8; 48],
    pub memo_hash: [u8; 48],
    /// Full seven-limb recipient authority and public recipient key for claims.
    /// Donations have no public recipient and must encode these as zero.
    pub recipient_authority: Digest,
    pub recipient_key: [u64; 4],
}
fn error(s: &'static str) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolation(s)
}
impl RewardSpendPublic {
    pub fn validate(&self) -> Result<(), TransactionCircuitError> {
        if self.relation_digest != source_digest()
            || self.claim > 1
            || self.amount == 0
            || self.amount >= 1 << 56
            || self.operation_binding == [0; 48]
            || self.base.secret_release != 0
            || self.base.released_secret != [0; 32]
            || (self.claim == 0
                && (self.recipient_authority != [0; 7] || self.recipient_key != [0; 4]))
            || (self.claim == 1
                && (self.memo_hash != [0; 48]
                    || self.recipient_authority == [0; 7]
                    || self.recipient_key == [0; 4]))
            || self
                .recipient_authority
                .iter()
                .chain(&self.recipient_key)
                .any(|v| *v >= hegemon_field::GOLDILOCKS_MODULUS)
        {
            return Err(error("reward-account public shape"));
        }
        Ok(())
    }
    pub fn extension_words(&self) -> [u64; EXTENSION_WORDS] {
        let mut words = vec![self.claim, self.amount];
        for hash in [&self.operation_binding, &self.memo_hash] {
            words.extend(
                hash.chunks_exact(4)
                    .map(|c| u32::from_le_bytes(c.try_into().unwrap()) as u64),
            );
        }
        words.extend(self.recipient_authority);
        words.extend(self.recipient_key);
        words.try_into().expect("fixed reward statement")
    }
    pub fn binding_bytes(&self) -> Vec<u8> {
        self.base
            .words()
            .into_iter()
            .chain(self.extension_words())
            .chain(identity_binding_words())
            .flat_map(u64::to_le_bytes)
            .collect()
    }
    pub fn payout_binding(&self) -> [u8; 48] {
        synthetic_crypto::hash384::blake2b_384_domain_hash(
            b"hegemon.reward-account.payout-statement.v1",
            [self.binding_bytes().as_slice()],
        )
    }
}

/// Immutable source/domain words appended to the 123 relation inputs.
pub(crate) fn identity_binding_words() -> [u64; 24] {
    let domain = synthetic_crypto::hash384::blake2b_384_domain_hash(
        b"hegemon.reward-account.relation-identity.v1",
        [RELATION_ID.as_bytes()],
    );
    source_digest()
        .chunks_exact(4)
        .chain(domain.chunks_exact(4))
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub fn source_digest() -> [u8; 48] {
    use sha2::{Digest as _, Sha512};
    static DIGEST: std::sync::OnceLock<[u8; 48]> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut hash = Sha512::new();
        hash.update(b"Hegemon.RewardAccounts.SourceManifest.v1");
        hash.update(crate::private_spend::relation_digest());
        for (name, bytes) in [
            (
                "reward_account_spend.rs",
                include_bytes!("reward_account_spend.rs").as_slice(),
            ),
            (
                "reward_accounts/ledger.rs",
                include_bytes!("../../../protocol/reward-accounts/src/ledger.rs").as_slice(),
            ),
            (
                "reward_accounts/policy.rs",
                include_bytes!("../../../protocol/reward-accounts/src/policy.rs").as_slice(),
            ),
            (
                "reward_accounts/address.rs",
                include_bytes!("../../../protocol/reward-accounts/src/address.rs").as_slice(),
            ),
            (
                "reward_accounts/account_tree.rs",
                include_bytes!("../../../protocol/reward-accounts/src/account_tree.rs").as_slice(),
            ),
            (
                "reward_accounts/genesis.rs",
                include_bytes!("../../../protocol/reward-accounts/src/genesis.rs").as_slice(),
            ),
            (
                "reward_accounts/governance.rs",
                include_bytes!("../../../protocol/reward-accounts/src/governance.rs").as_slice(),
            ),
            (
                "reward_accounts/schedule.rs",
                include_bytes!("../../../protocol/reward-accounts/src/schedule.rs").as_slice(),
            ),
            (
                "reward_accounts/lib.rs",
                include_bytes!("../../../protocol/reward-accounts/src/lib.rs").as_slice(),
            ),
            (
                "reward_accounts/bounded.rs",
                include_bytes!("../../../protocol/reward-accounts/src/bounded.rs").as_slice(),
            ),
        ] {
            hash.update((name.len() as u64).to_le_bytes());
            hash.update(name.as_bytes());
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        hash.finalize()[..48].try_into().unwrap()
    })
}

pub fn compile(
    public: &RewardSpendPublic,
    witness: &PrivateSpendWitness,
) -> Result<(PrivateSpendAdapter, Zeroizing<Vec<u64>>), TransactionCircuitError> {
    let adapter = PrivateSpendAdapter::from_reward_public(public)?;
    let packed = Zeroizing::new(adapter.lower(&public.base, witness)?);
    adapter.verify_packed_witness(&packed)?;
    Ok((adapter, packed))
}
pub fn prove_candidate(
    public: &RewardSpendPublic,
    witness: &PrivateSpendWitness,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let (adapter, packed) = compile(public, witness)?;
    let hint = crate::smallwood_engine::projected_reward_accounts_smzt_inner_proof_bytes(&adapter)?;
    if hint != PROOF_BYTES || hint > MAX_REWARD_PROOF_BYTES {
        return Err(error("reward-account projected proof exceeds cap"));
    }
    prove_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        &packed,
        &public.binding_bytes(),
        REWARD_ACCOUNTS_SMZT_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512RewardAccountsSmzt,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}
pub fn verify_candidate(
    public: &RewardSpendPublic,
    proof: &[u8],
) -> Result<(), TransactionCircuitError> {
    if proof.len() != PROOF_BYTES || proof.get(..4) != Some(b"SMZT") {
        return Err(error("reward-account proof format or cap"));
    }
    let adapter = PrivateSpendAdapter::from_reward_public(public)?;
    verify_statement_with_transcript_backend_profile_and_domain(
        &adapter,
        &public.binding_bytes(),
        proof,
        REWARD_ACCOUNTS_SMZT_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512RewardAccountsSmzt,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RewardSpendCarrier {
    pub public: RewardSpendPublic,
    pub ciphertexts: [BoundedVec<u8, CIPHERTEXT_BYTES>; 2],
    pub proof: BoundedVec<u8, PROOF_BYTES>,
}
impl RewardSpendCarrier {
    pub fn encode_carrier(&self) -> Result<Vec<u8>, TransactionCircuitError> {
        self.validate_ciphertexts()?;
        let mut bytes = CARRIER_MAGIC.to_vec();
        bytes.extend(self.encode());
        if bytes.len() > MAX_CARRIER_BYTES {
            return Err(error("reward-account carrier cap"));
        }
        Ok(bytes)
    }
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, TransactionCircuitError> {
        if bytes.len() > MAX_CARRIER_BYTES || bytes.get(..8) != Some(&CARRIER_MAGIC) {
            return Err(error("reward-account carrier identity"));
        }
        let mut cursor = &bytes[8..];
        let value =
            Self::decode(&mut cursor).map_err(|_| error("reward-account carrier decoding"))?;
        if !cursor.is_empty() || value.encode() != bytes[8..] {
            return Err(error("noncanonical reward-account carrier"));
        }
        value.validate_ciphertexts()?;
        Ok(value)
    }
    pub fn validate_ciphertexts(&self) -> Result<(), TransactionCircuitError> {
        self.public.validate()?;
        for i in 0..2 {
            if self.ciphertexts[i].len() != CIPHERTEXT_BYTES
                || transaction_core::hashing_pq::ciphertext_hash_bytes(&self.ciphertexts[i])
                    != self.public.base.ciphertext_commitments[i]
            {
                return Err(error("reward-account ciphertext binding"));
            }
        }
        Ok(())
    }
    pub fn verify(&self) -> Result<(), TransactionCircuitError> {
        self.validate_ciphertexts()?;
        verify_candidate(&self.public, &self.proof)
    }
}

#[cfg(all(test, feature = "private-spend-dev-artifacts"))]
mod tests {
    use super::*;
    use crate::private_spend::{self as private, qualification};

    fn donation() -> (RewardSpendPublic, PrivateSpendWitness) {
        let (mut base, mut witness) = qualification::fixture(0);
        witness.outputs[0].value -= 20;
        qualification::refresh_fixture(&mut base, &mut witness);
        (
            RewardSpendPublic {
                relation_digest: source_digest(),
                base,
                claim: 0,
                amount: 20,
                operation_binding: [1; 48],
                memo_hash: [2; 48],
                recipient_authority: [0; 7],
                recipient_key: [0; 4],
            },
            witness,
        )
    }
    fn claim() -> (RewardSpendPublic, PrivateSpendWitness) {
        let (mut base, mut witness) = qualification::fixture(0);
        for i in 0..2 {
            witness.inputs[i] = private::PrivateInput {
                dummy_secret: [9 + i as u64, 2, 3, 4, 5],
                ..Default::default()
            };
        }
        witness.outputs[0].value = 90;
        witness.outputs[1].value = 0;
        qualification::refresh_fixture(&mut base, &mut witness);
        (
            RewardSpendPublic {
                relation_digest: source_digest(),
                base,
                claim: 1,
                amount: 90,
                operation_binding: [1; 48],
                memo_hash: [0; 48],
                recipient_authority: witness.output_authorities[0],
                recipient_key: witness.outputs[0].recipient_key,
            },
            witness,
        )
    }
    #[test]
    fn reward_accounts_explicit_credit_debit_constraints() {
        for (public, witness) in [donation(), claim()] {
            let (adapter, _) = compile(&public, &witness).unwrap();
            eprintln!(
                "reward kind {} geometry {:?}",
                public.claim,
                adapter.geometry()
            );
            let mut wrong = public.clone();
            wrong.amount += 1;
            assert!(compile(&wrong, &witness).is_err());
            let mut wrong = witness.clone();
            wrong.outputs[0].value += 1;
            assert!(compile(&public, &wrong).is_err());
            let mut wrong = public.clone();
            wrong.claim ^= 1;
            assert!(compile(&wrong, &witness).is_err());
        }
    }
    #[test]
    #[ignore = "real successor proof qualification; explicitly run in release"]
    fn reward_accounts_real_claim_and_donation_proofs() {
        for (public, witness) in [donation(), claim()] {
            let proof = prove_candidate(&public, &witness).unwrap();
            eprintln!("reward kind {} proof bytes {}", public.claim, proof.len());
            verify_candidate(&public, &proof).unwrap();
            assert!(crate::asset_recovery_backend_v1::wire_receipt(&proof).is_err());
            let mut recovery_alias = proof.clone();
            recovery_alias[..4].copy_from_slice(b"SMZR");
            assert!(verify_candidate(&public, &recovery_alias).is_err());
            let mut wrong = public.clone();
            wrong.amount += 1;
            assert!(verify_candidate(&wrong, &proof).is_err());
            let mut wrong = public.clone();
            wrong.memo_hash[0] ^= 1;
            assert!(verify_candidate(&wrong, &proof).is_err());
            let mut wrong = public.clone();
            wrong.operation_binding[0] ^= 1;
            assert!(verify_candidate(&wrong, &proof).is_err());
            let mut wrong = public.clone();
            wrong.base.fee += 1;
            assert!(verify_candidate(&wrong, &proof).is_err());
            let mut altered = proof.clone();
            altered[32] ^= 1;
            assert!(verify_candidate(&public, &altered).is_err());
            assert!(verify_candidate(&public, &proof[..proof.len() - 1]).is_err());
            let mut suffix = proof.clone();
            suffix.push(0);
            assert!(verify_candidate(&public, &suffix).is_err());
            assert!(private::verify_candidate(&public.base, &proof).is_err());
        }
    }
}
