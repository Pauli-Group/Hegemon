//! Closed native account and mandatory reward-record grammars. Decoding and
//! syntax checks grant no source authority and perform no private proof check.
use anyhow::{ensure, Result};
use codec::{Decode, Encode};
use protocol_reward_accounts::*;
use transaction_circuit::reward_account_spend as proof;

pub(crate) const CLAIM_ACTION_ID: u16 = 20;
pub(crate) const DONATION_ACTION_ID: u16 = 21;
pub(crate) const FORK_ACTION_ID: u16 = 22;
pub(crate) const REWARD_ACTION_ID: u16 = 23;
pub(crate) const CIRCUIT_VERSION: u16 = 15;
pub(crate) const PROFILE_ID: u8 = 15;
pub(crate) const DOMAIN_SET: u16 = 11;
pub(crate) const ACTION_MAGIC: [u8; 8] = *b"HGRACC01";
pub(crate) const REWARD_MAGIC: [u8; 8] = *b"HGREWD01";
pub(crate) const HEADER_BYTES: usize = 56;
pub(crate) const MAX_ACTION_BYTES: usize = 512 * 1024;
pub(crate) const REWARD_BYTES: usize = HEADER_BYTES + 336;

pub(crate) fn source_digest() -> [u8; 48] {
    static DIGEST: std::sync::OnceLock<[u8; 48]> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(|| {
        crypto::hash384::blake2b_384_domain_hash(
            b"hegemon.native.reward-accounts.source.v1",
            [
                proof::source_digest().as_slice(),
                include_bytes!("wire.rs").as_slice(),
                include_bytes!("profile.rs").as_slice(),
                include_bytes!("../reward_accounts.rs").as_slice(),
                include_bytes!("../network_profile.rs").as_slice(),
                include_bytes!("../node_impl.rs").as_slice(),
                include_bytes!("../native_proof_binding.rs").as_slice(),
                include_bytes!("../poseidon2_v8_state.rs").as_slice(),
            ],
        )
    })
}
fn context_shape(c: &AccountChainContext) -> Result<()> {
    ensure!(
        c.chain_id != [0; 32]
            && c.genesis_hash != [0; 32]
            && c.genesis_config_hash != crypto::hash384::RulesHash48::ZERO,
        "zero account chain identity"
    );
    Ok(())
}
fn approvals_shape(policy: &AccountPolicy, approvals: &[AccountApproval]) -> Result<()> {
    ensure!(
        approvals.len() >= policy.required()
            && approvals.len() <= policy.signer_hashes().len()
            && approvals
                .windows(2)
                .all(|p| p[0].signer_index < p[1].signer_index)
            && approvals
                .iter()
                .all(|a| (a.signer_index as usize) < policy.signer_hashes().len()
                    && a.public_key.len() == crypto::ml_dsa::ML_DSA_PUBLIC_KEY_LEN
                    && a.signature.len() == crypto::ml_dsa::ML_DSA_SIGNATURE_LEN),
        "noncanonical account approvals"
    );
    Ok(())
}
fn carrier(bytes: &[u8]) -> Result<proof::RewardSpendCarrier> {
    let c = proof::RewardSpendCarrier::decode_exact(bytes)?;
    ensure!(
        c.proof.len() == proof::PROOF_BYTES && c.proof.get(..4) == Some(b"SMZT"),
        "account action requires an exact SMZT proof frame"
    );
    ensure!(
        c.public
            .base
            .words()
            .iter()
            .all(|word| *word < super::super::poseidon2_v8_state::POSEIDON2_V8_GOLDILOCKS_MODULUS),
        "noncanonical account proof statement"
    );
    for ciphertext in &c.ciphertexts {
        crypto::private_note_encryption::PrivateNoteCiphertextRef::from_bytes_exact(ciphertext)?;
    }
    Ok(c)
}
fn encode<T: Encode>(magic: [u8; 8], value: &T, cap: usize) -> Result<Vec<u8>> {
    let mut bytes = magic.to_vec();
    bytes.extend(source_digest());
    bytes.extend(value.encode());
    ensure!(bytes.len() <= cap, "account native frame exceeds cap");
    Ok(bytes)
}
fn decode<T: Encode + Decode>(bytes: &[u8], magic: [u8; 8], cap: usize) -> Result<T> {
    ensure!(
        bytes.len() >= HEADER_BYTES && bytes.len() <= cap,
        "account native frame length"
    );
    ensure!(
        bytes[..8] == magic && bytes[8..HEADER_BYTES] == source_digest(),
        "account native frame magic/source mismatch"
    );
    super::exact(&bytes[HEADER_BYTES..], cap - HEADER_BYTES)
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) enum AccountNativeAction {
    Claim {
        claim: AccountClaim,
        policy: AccountPolicy,
        approvals: BoundedVec<AccountApproval, MAX_ACCOUNT_SIGNERS>,
        carrier: BoundedVec<u8, { proof::MAX_CARRIER_BYTES }>,
    },
    Donation {
        donation: TreasuryDonation,
        carrier: BoundedVec<u8, { proof::MAX_CARRIER_BYTES }>,
    },
    TreasuryFork {
        certificate: TreasuryForkCertificate,
    },
}
impl AccountNativeAction {
    pub(crate) fn action_id(&self) -> u16 {
        match self {
            Self::Claim { .. } => CLAIM_ACTION_ID,
            Self::Donation { .. } => DONATION_ACTION_ID,
            Self::TreasuryFork { .. } => FORK_ACTION_ID,
        }
    }
    pub(crate) fn fee(&self) -> u64 {
        match self {
            Self::Claim { claim, .. } => claim.fee,
            Self::Donation { donation, .. } => donation.fee,
            Self::TreasuryFork { .. } => 0,
        }
    }
    pub(crate) fn proof_units(&self) -> usize {
        usize::from(!matches!(self, Self::TreasuryFork { .. }))
    }
    pub(crate) fn context(&self) -> &AccountChainContext {
        match self {
            Self::Claim { claim, .. } => &claim.context,
            Self::Donation { donation, .. } => &donation.context,
            Self::TreasuryFork { certificate } => &certificate.intent.context,
        }
    }
    pub(crate) fn encode_native(&self) -> Result<Vec<u8>> {
        self.validate_syntax()?;
        encode(ACTION_MAGIC, self, MAX_ACTION_BYTES)
    }
    pub(crate) fn decode_native(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, ACTION_MAGIC, MAX_ACTION_BYTES)?;
        value.validate_syntax()?;
        Ok(value)
    }
    pub(crate) fn validate_syntax(&self) -> Result<()> {
        context_shape(self.context())?;
        match self {
            Self::Claim {
                claim,
                policy,
                approvals,
                carrier: bytes,
            } => {
                ensure!(
                    (policy.identifier()? == claim.account
                        || claim.account == protocol_treasury_account_id())
                        && claim.amount > 0
                        && claim
                            .amount
                            .checked_add(claim.fee)
                            .is_some_and(|v| v <= MAX_SUPPLY),
                    "account claim policy/amount/fee mismatch"
                );
                approvals_shape(policy, approvals)?;
                let c = carrier(bytes)?;
                ensure!(
                    c.public.claim == 1
                        && c.public.amount == claim.amount
                        && c.public.base.fee == claim.fee
                        && c.public.base.chain_id == claim.context.chain_id
                        && c.public.operation_binding == claim.operation_binding()
                        && c.public.payout_binding() == claim.payout_binding.into_bytes(),
                    "account claim carrier binding mismatch"
                );
            }
            Self::Donation {
                donation,
                carrier: bytes,
            } => {
                ensure!(
                    donation.amount > 0
                        && donation
                            .amount
                            .checked_add(donation.fee)
                            .is_some_and(|v| v <= MAX_SUPPLY)
                        && std::str::from_utf8(&donation.memo).is_ok(),
                    "donation amount/fee/memo mismatch"
                );
                let c = carrier(bytes)?;
                ensure!(
                    c.public.claim == 0
                        && c.public.amount == donation.amount
                        && c.public.base.fee == donation.fee
                        && c.public.base.chain_id == donation.context.chain_id
                        && c.public.operation_binding == donation.operation_binding()
                        && c.public.memo_hash == donation.memo_hash(),
                    "donation carrier binding mismatch"
                );
            }
            Self::TreasuryFork { certificate } => {
                let intent = &certificate.intent;
                intent.successor_policy.validate()?;
                ensure!(
                    intent.activation_height > 0
                        && intent.successor_rules != crypto::hash384::RulesHash48::ZERO,
                    "invalid fork activation/rules"
                );
                approvals_shape(&intent.successor_policy, &certificate.approvals)?;
            }
        }
        Ok(())
    }
    pub(crate) fn into_account_action(self) -> Result<RewardAccountAction> {
        Ok(match self {
            Self::Claim {
                claim,
                policy,
                approvals,
                carrier,
            } => RewardAccountAction::Claim {
                claim,
                policy,
                approvals,
                proof: BoundedVec::new(carrier.into_inner()).map_err(anyhow::Error::msg)?,
            },
            Self::Donation { donation, carrier } => RewardAccountAction::Donation {
                donation,
                proof: BoundedVec::new(carrier.into_inner()).map_err(anyhow::Error::msg)?,
            },
            Self::TreasuryFork { certificate } => RewardAccountAction::TreasuryFork { certificate },
        })
    }
}

/// Exactly one final public record is required on the successor path. There
/// is no memo, note opening, secret key or claimed private mint proof here.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct MandatoryRewardRecord {
    pub(crate) context: AccountChainContext,
    pub(crate) height: u64,
    pub(crate) miner: AccountPolicyId48,
    pub(crate) parent_accounts_root: RewardAccountsRoot48,
    pub(crate) accounts_root: RewardAccountsRoot48,
    pub(crate) note_root: [u64; 7],
    pub(crate) subsidy: u64,
    pub(crate) miner_fees: u64,
}
impl MandatoryRewardRecord {
    fn validate_syntax(&self) -> Result<()> {
        context_shape(&self.context)?;
        ensure!(
            self.height > 0
                && self.miner != AccountPolicyId48::ZERO
                && self.parent_accounts_root != RewardAccountsRoot48::ZERO
                && self.accounts_root != RewardAccountsRoot48::ZERO
                && self
                    .subsidy
                    .checked_add(self.miner_fees)
                    .is_some_and(|v| v <= MAX_SUPPLY),
            "invalid mandatory reward record"
        );
        super::super::poseidon2_v8_state::Poseidon2V8NoteRoot::new(self.note_root)?;
        Ok(())
    }
    pub(crate) fn from_transition(
        parent: &RewardAccountLedger,
        next: &RewardAccountLedger,
        miner: AccountPolicyId48,
        note_root: [u64; 7],
        miner_fees: u64,
    ) -> Result<Self> {
        ensure!(
            parent.height().checked_add(1) == Some(next.height())
                && parent.context() == next.context(),
            "reward transition context/height mismatch"
        );
        let record = Self {
            context: parent.context().clone(),
            height: next.height(),
            miner,
            parent_accounts_root: parent.state_root(),
            accounts_root: next.state_root(),
            note_root,
            // `next` is the node's independently verified account candidate,
            // not a snapshot advertised by the block. Its issuance was checked
            // by the shared transition; avoid rescanning genesis allocations.
            subsidy: next
                .issued()
                .checked_sub(parent.issued())
                .ok_or_else(|| anyhow::anyhow!("reward issuance decreased"))?,
            miner_fees,
        };
        record.validate_syntax()?;
        Ok(record)
    }
    pub(crate) fn validate_transition(
        &self,
        parent: &RewardAccountLedger,
        next: &RewardAccountLedger,
        miner: AccountPolicyId48,
        note_root: [u64; 7],
        miner_fees: u64,
    ) -> Result<()> {
        ensure!(
            self == &Self::from_transition(parent, next, miner, note_root, miner_fees)?,
            "mandatory reward record differs from verified transition"
        );
        Ok(())
    }
    pub(crate) fn encode_native(&self) -> Result<Vec<u8>> {
        self.validate_syntax()?;
        let bytes = encode(REWARD_MAGIC, self, REWARD_BYTES)?;
        ensure!(bytes.len() == REWARD_BYTES, "reward record fixed layout");
        Ok(bytes)
    }
    pub(crate) fn decode_native(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == REWARD_BYTES, "reward record fixed length");
        let value: Self = decode(bytes, REWARD_MAGIC, REWARD_BYTES)?;
        value.validate_syntax()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{hash384::RulesHash48, ml_dsa::MlDsaSecretKey, traits::SigningKey};
    struct RejectProofs;
    impl RewardAccountProofVerifier for RejectProofs {
        fn verify_claim(&self, _: &AccountClaim, _: &[u8]) -> Result<(), RewardAccountsError> {
            Err(RewardAccountsError::InvalidProof)
        }
        fn verify_donation(
            &self,
            _: &TreasuryDonation,
            _: &[u8],
        ) -> Result<(), RewardAccountsError> {
            Err(RewardAccountsError::InvalidProof)
        }
        fn verify_private_fee(
            &self,
            _: &AccountChainContext,
            _: u64,
            _: &[u8],
        ) -> Result<(), RewardAccountsError> {
            Err(RewardAccountsError::InvalidProof)
        }
    }
    fn fixture() -> (RewardAccountLedger, MlDsaSecretKey) {
        let key = MlDsaSecretKey::generate_deterministic(b"native wire unit test");
        let g = RewardAccountsGenesis {
            network: AddressNetwork {
                class: NetworkClass::Testnet,
                discriminator: [8; 32],
            },
            reward_epoch_blocks: 2,
            treasury_policy: AccountPolicy::single(&key.verify_key()),
            allocations: BoundedVec::default(),
        };
        let ctx = AccountChainContext {
            chain_id: [1; 32],
            genesis_hash: [2; 32],
            genesis_config_hash: RulesHash48::new(g.commitment().unwrap()),
        };
        (RewardAccountLedger::new(g, ctx).unwrap(), key)
    }
    #[test]
    fn reward_accounts_native_reward_record_framing_and_verified_binding() {
        let (parent, _) = fixture();
        let miner = AccountPolicyId48::new([9; 48]);
        let next = parent.apply_block(1, miner, &[], &RejectProofs).unwrap();
        let note_root =
            transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes()
                [32];
        let record =
            MandatoryRewardRecord::from_transition(&parent, &next, miner, note_root, 0).unwrap();
        let bytes = record.encode_native().unwrap();
        assert_eq!(bytes.len(), REWARD_BYTES);
        assert_eq!(
            MandatoryRewardRecord::decode_native(&bytes).unwrap(),
            record
        );
        assert!(AccountNativeAction::decode_native(&bytes).is_err());
        let mut wrong = bytes.clone();
        wrong[8] ^= 1;
        assert!(MandatoryRewardRecord::decode_native(&wrong).is_err());
        wrong = bytes;
        wrong.push(0);
        assert!(MandatoryRewardRecord::decode_native(&wrong).is_err());
        let check = |r: &MandatoryRewardRecord| {
            r.validate_transition(&parent, &next, miner, note_root, 0)
                .is_err()
        };
        let mut wrong = record.clone();
        wrong.subsidy += 1;
        assert!(check(&wrong));
        wrong = record.clone();
        wrong.miner_fees += 1;
        assert!(check(&wrong));
        wrong = record.clone();
        wrong.miner = AccountPolicyId48::new([7; 48]);
        assert!(check(&wrong));
        wrong = record.clone();
        wrong.accounts_root = RewardAccountsRoot48::new([4; 48]);
        assert!(check(&wrong));
        wrong = record;
        wrong.note_root[0] ^= 1;
        assert!(check(&wrong));
    }
    #[test]
    fn reward_accounts_native_certificate_syntax_grants_no_adoption() {
        let (ledger, key) = fixture();
        let successor = MlDsaSecretKey::generate_deterministic(b"wire successor");
        let intent = TreasuryForkIntent {
            context: ledger.context().clone(),
            current_generation: 0,
            activation_height: 5,
            successor_rules: RulesHash48::new([7; 48]),
            successor_policy: AccountPolicy::single(&successor.verify_key()),
        };
        let approval = AccountApproval::sign(0, &key, &intent.authorization_digest());
        let certificate = TreasuryForkCertificate {
            intent,
            approvals: BoundedVec::new(vec![approval.clone()]).unwrap(),
        };
        let action = AccountNativeAction::TreasuryFork {
            certificate: certificate.clone(),
        };
        assert_eq!(action.action_id(), FORK_ACTION_ID);
        assert_eq!(action.fee(), 0);
        assert_eq!(action.proof_units(), 0);
        let bytes = action.encode_native().unwrap();
        assert_eq!(AccountNativeAction::decode_native(&bytes).unwrap(), action);
        assert!(MandatoryRewardRecord::decode_native(&bytes).is_err());
        let miner = AccountPolicyId48::new([9; 48]);
        let decoded = AccountNativeAction::decode_native(&bytes)
            .unwrap()
            .into_account_action()
            .unwrap();
        assert_eq!(
            ledger
                .apply_block(1, miner, &[decoded], &RejectProofs)
                .unwrap_err(),
            RewardAccountsError::InvalidTreasuryFork
        );
        assert!(ledger.apply_block(1, miner, &[], &RejectProofs).is_ok());
        let mut wrong = bytes;
        wrong[9] ^= 1;
        assert!(AccountNativeAction::decode_native(&wrong).is_err());
        let duplicate = AccountNativeAction::TreasuryFork {
            certificate: TreasuryForkCertificate {
                approvals: BoundedVec::new(vec![approval.clone(), approval]).unwrap(),
                ..certificate
            },
        };
        assert!(duplicate.encode_native().is_err());
    }
    #[test]
    fn reward_accounts_native_grammar_excludes_transfers_and_unproven_deposits() {
        let (ledger, _) = fixture();
        let mut unknown = ACTION_MAGIC.to_vec();
        unknown.extend(source_digest());
        unknown.push(3);
        assert!(AccountNativeAction::decode_native(&unknown).is_err());
        let donation = AccountNativeAction::Donation {
            donation: TreasuryDonation {
                context: ledger.context().clone(),
                amount: 1,
                fee: 0,
                memo: BoundedVec::default(),
            },
            carrier: BoundedVec::default(),
        };
        assert!(donation.encode_native().is_err());
        unknown.resize(MAX_ACTION_BYTES + 1, 0);
        assert!(AccountNativeAction::decode_native(&unknown).is_err());
    }
    #[test]
    fn reward_accounts_native_valid_looking_frame_does_not_authorize_a_donation() {
        use transaction_circuit::private_spend::PrivateSpendPublic;
        let (ledger, _) = fixture();
        let donation = TreasuryDonation {
            context: ledger.context().clone(),
            amount: 1,
            fee: 0,
            memo: BoundedVec::default(),
        };
        let ciphertext = vec![0; proof::CIPHERTEXT_BYTES];
        let ct_hash = transaction_core::hashing_pq::ciphertext_hash_bytes(&ciphertext);
        let public = proof::RewardSpendPublic {
            relation_digest: proof::source_digest(),
            base: PrivateSpendPublic {
                chain_id: ledger.context().chain_id,
                reference_parent_hash: ledger.context().genesis_hash,
                reference_parent_height: 0,
                merkle_root: [1; 7],
                fee: 0,
                nullifiers: [[2; 7], [3; 7]],
                commitments: [[4; 7], [5; 7]],
                ciphertext_commitments: [ct_hash; 2],
                secret_release: 0,
                released_secret: [0; 32],
            },
            claim: 0,
            amount: 1,
            operation_binding: donation.operation_binding(),
            memo_hash: donation.memo_hash(),
            recipient_authority: [0; 7],
            recipient_key: [0; 4],
        };
        // Deliberately not a valid proof. Syntax recognition must never count
        // its shape as accepted cryptographic/source authority.
        let mut fake = vec![0; proof::PROOF_BYTES];
        fake[..4].copy_from_slice(b"SMZT");
        let carrier = proof::RewardSpendCarrier {
            public,
            ciphertexts: [
                BoundedVec::new(ciphertext.clone()).unwrap(),
                BoundedVec::new(ciphertext).unwrap(),
            ],
            proof: BoundedVec::new(fake).unwrap(),
        };
        let action = AccountNativeAction::Donation {
            donation: donation.clone(),
            carrier: BoundedVec::new(carrier.encode_carrier().unwrap()).unwrap(),
        };
        let bytes = action.encode_native().unwrap();
        let decoded = AccountNativeAction::decode_native(&bytes).unwrap();
        let root = ledger.state_root();
        assert_eq!(
            ledger
                .apply_block(
                    1,
                    AccountPolicyId48::new([9; 48]),
                    &[decoded.into_account_action().unwrap()],
                    &RejectProofs
                )
                .unwrap_err(),
            RewardAccountsError::InvalidProof
        );
        assert_eq!(ledger.state_root(), root);
        let mut wrong = carrier;
        wrong.public.base.merkle_root[0] =
            super::super::super::poseidon2_v8_state::POSEIDON2_V8_GOLDILOCKS_MODULUS;
        let wrong = AccountNativeAction::Donation {
            donation,
            carrier: BoundedVec::new(wrong.encode_carrier().unwrap()).unwrap(),
        };
        assert!(wrong.encode_native().is_err());
    }
}
