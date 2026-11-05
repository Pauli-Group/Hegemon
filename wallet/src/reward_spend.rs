//! Private output construction for public-account claims and treasury donations.
//! Secret witnesses are neither public fields nor serializable/debuggable.
use crate::{
    private_spend_build::{self as build, OutputRequest, SpendInput, SpendReference},
    NetworkShieldedAddress, WalletError,
};
use protocol_reward_accounts::*;
use synthetic_crypto::hash384::ProofCommitment48;
use transaction_circuit::{private_spend as private, reward_account_spend as relation};
use zeroize::Zeroize;

fn invalid(s: &'static str) -> WalletError {
    WalletError::InvalidState(s)
}

pub struct AccountClaimRequest {
    pub account: AccountPolicyId48,
    pub policy_generation: u64,
    pub sequence: u64,
    pub amount: u64,
    pub fee: u64,
    pub recipient: NetworkShieldedAddress,
}

pub struct PreparedRewardSpend {
    public: relation::RewardSpendPublic,
    witness: private::PrivateSpendWitness,
    outputs: build::Outputs,
}
impl Drop for PreparedRewardSpend {
    fn drop(&mut self) {
        for input in &mut self.witness.inputs {
            build::wipe_input(input);
        }
        for note in self
            .witness
            .outputs
            .iter_mut()
            .chain(self.outputs.notes.iter_mut())
        {
            note.value.zeroize();
            note.asset_id.zeroize();
            note.rho.zeroize();
            note.randomness.zeroize();
            note.authorization_key.zeroize();
            note.recipient_key.zeroize();
        }
        self.outputs.authorities.zeroize();
    }
}
impl PreparedRewardSpend {
    fn checked(self) -> Result<Self, WalletError> {
        let (_, mut packed) = relation::compile(&self.public, &self.witness)
            .map_err(|_| invalid("reward-account relation rejected material"))?;
        packed.zeroize();
        Ok(self)
    }
    pub fn public_statement(&self) -> &relation::RewardSpendPublic {
        &self.public
    }
    pub fn prove(&self) -> Result<relation::RewardSpendCarrier, WalletError> {
        let proof = relation::prove_candidate(&self.public, &self.witness)
            .map_err(|_| invalid("reward-account proving failed"))?;
        relation::verify_candidate(&self.public, &proof)
            .map_err(|_| invalid("reward-account proof self-check failed"))?;
        Ok(relation::RewardSpendCarrier {
            public: self.public.clone(),
            ciphertexts: self
                .outputs
                .ciphertexts
                .each_ref()
                .map(|c| BoundedVec::new(c.as_bytes().to_vec()).expect("fixed native ciphertext")),
            proof: BoundedVec::new(proof).map_err(|_| invalid("reward-account proof cap"))?,
        })
    }
}

pub struct PreparedAccountClaim {
    claim: AccountClaim,
    spend: PreparedRewardSpend,
}
impl PreparedAccountClaim {
    pub fn claim(&self) -> &AccountClaim {
        &self.claim
    }
    pub fn public_statement(&self) -> &relation::RewardSpendPublic {
        self.spend.public_statement()
    }
    pub fn prove(&self) -> Result<relation::RewardSpendCarrier, WalletError> {
        self.spend.prove()
    }
}

pub fn prepare_account_claim(
    genesis: &RewardAccountsGenesis,
    context: AccountChainContext,
    reference: SpendReference,
    request: AccountClaimRequest,
) -> Result<PreparedAccountClaim, WalletError> {
    context
        .validate(genesis)
        .map_err(|_| invalid("claim genesis context"))?;
    if request.recipient.network() != genesis.network
        || reference.chain_id != context.chain_id
        || request.account == AccountPolicyId48::ZERO
        || request.amount == 0
    {
        return Err(invalid("claim recipient or chain context"));
    }
    let receiver = request.recipient.recipient().clone();
    let (recipient_key, recipient_authority) = build::recipient(&receiver)?;
    let mut claim = AccountClaim {
        context,
        account: request.account,
        policy_generation: request.policy_generation,
        sequence: request.sequence,
        amount: request.amount,
        fee: request.fee,
        recipient: BoundedVec::new(request.recipient.to_bytes()?)
            .map_err(|_| invalid("claim recipient cap"))?,
        payout_binding: ProofCommitment48::ZERO,
    };
    let outputs = build::encrypted_outputs(
        reference,
        [
            OutputRequest {
                recipient: receiver.clone(),
                value: request.amount,
            },
            OutputRequest {
                recipient: receiver,
                value: 0,
            },
        ],
        0,
        &empty_treasury(),
        &Default::default(),
    )?;
    let inputs = [SpendInput::dummy()?, SpendInput::dummy()?];
    let (base, witness) = material(reference, request.fee, &inputs, &outputs)?;
    let public = relation::RewardSpendPublic {
        relation_digest: relation::source_digest(),
        base,
        claim: 1,
        amount: request.amount,
        operation_binding: claim.operation_binding(),
        memo_hash: [0; 48],
        recipient_authority,
        recipient_key,
    };
    claim.payout_binding = ProofCommitment48::new(public.payout_binding());
    let spend = PreparedRewardSpend {
        public,
        witness,
        outputs,
    }
    .checked()?;
    Ok(PreparedAccountClaim { claim, spend })
}

pub struct PreparedTreasuryDonation {
    donation: TreasuryDonation,
    spend: PreparedRewardSpend,
}
impl PreparedTreasuryDonation {
    pub fn donation(&self) -> &TreasuryDonation {
        &self.donation
    }
    pub fn public_statement(&self) -> &relation::RewardSpendPublic {
        self.spend.public_statement()
    }
    pub fn prove(&self) -> Result<relation::RewardSpendCarrier, WalletError> {
        self.spend.prove()
    }
}

pub fn prepare_treasury_donation(
    genesis: &RewardAccountsGenesis,
    donation: TreasuryDonation,
    reference: SpendReference,
    inputs: [SpendInput; 2],
    requests: [OutputRequest; 2],
) -> Result<PreparedTreasuryDonation, WalletError> {
    donation
        .context
        .validate(genesis)
        .map_err(|_| invalid("donation genesis context"))?;
    if reference.chain_id != donation.context.chain_id
        || donation.amount == 0
        || std::str::from_utf8(&donation.memo).is_err()
    {
        return Err(invalid("donation context, amount or public memo"));
    }
    let outputs = build::encrypted_outputs(
        reference,
        requests,
        0,
        &empty_treasury(),
        &Default::default(),
    )?;
    let (base, witness) = material(reference, donation.fee, &inputs, &outputs)?;
    let public = relation::RewardSpendPublic {
        relation_digest: relation::source_digest(),
        base,
        claim: 0,
        amount: donation.amount,
        operation_binding: donation.operation_binding(),
        memo_hash: donation.memo_hash(),
        recipient_authority: [0; 7],
        recipient_key: [0; 4],
    };
    let spend = PreparedRewardSpend {
        public,
        witness,
        outputs,
    }
    .checked()?;
    Ok(PreparedTreasuryDonation { donation, spend })
}
fn empty_treasury() -> private::TreasuryOpening {
    private::TreasuryOpening {
        intent: vec![0; private::INTENT_WORDS],
        ..Default::default()
    }
}
fn material(
    reference: SpendReference,
    fee: u64,
    inputs: &[SpendInput; 2],
    outputs: &build::Outputs,
) -> Result<(private::PrivateSpendPublic, private::PrivateSpendWitness), WalletError> {
    if reference.chain_id == [0; 32]
        || reference.parent_hash == [0; 32]
        || inputs
            .iter()
            .any(|i| i.chain_id.is_some_and(|c| c != reference.chain_id))
    {
        return Err(invalid("reward-account reference or input context"));
    }
    let mut base = build::statement(reference, fee, outputs);
    let witness = private::PrivateSpendWitness {
        selectors: [1, 0, 0, 0, 0, 0],
        inputs: inputs.each_ref().map(|i| i.inner.clone()),
        outputs: outputs.notes,
        output_authorities: outputs.authorities,
        treasury: empty_treasury(),
        htlc: Default::default(),
        policy: Default::default(),
    };
    for (slot, input) in witness.inputs.iter().enumerate() {
        base.nullifiers[slot] = if input.occupied == 0 {
            private::dummy_nullifier(reference.chain_id, input.dummy_secret)
        } else {
            private::real_nullifier(input.spend_key, input.position, input.note)
        }
        .map_err(|_| invalid("reward-account input nullifier"))?;
    }
    Ok((base, witness))
}

/// Real circuit verification plus a caller-supplied canonical reference check.
/// A node must provide its authenticated canonical note-root window here; merely
/// trusting a sender's reference does not satisfy node admission.
pub struct RewardProofVerifier<'a> {
    genesis: &'a RewardAccountsGenesis,
    context: &'a AccountChainContext,
    reference_check: &'a dyn Fn(SpendReference) -> Result<(), RewardAccountsError>,
}
impl<'a> RewardProofVerifier<'a> {
    pub fn new(
        genesis: &'a RewardAccountsGenesis,
        context: &'a AccountChainContext,
        reference_check: &'a dyn Fn(SpendReference) -> Result<(), RewardAccountsError>,
    ) -> Result<Self, RewardAccountsError> {
        context.validate(genesis)?;
        Ok(Self {
            genesis,
            context,
            reference_check,
        })
    }
    fn check_reference(
        &self,
        base: &private::PrivateSpendPublic,
    ) -> Result<(), RewardAccountsError> {
        if base.chain_id != self.context.chain_id {
            return Err(RewardAccountsError::InvalidContext);
        }
        (self.reference_check)(SpendReference {
            chain_id: base.chain_id,
            parent_hash: base.reference_parent_hash,
            parent_height: base.reference_parent_height,
            merkle_root: base.merkle_root,
        })
    }
}
impl RewardAccountProofVerifier for RewardProofVerifier<'_> {
    fn verify_claim(&self, claim: &AccountClaim, proof: &[u8]) -> Result<(), RewardAccountsError> {
        if &claim.context != self.context {
            return Err(RewardAccountsError::InvalidContext);
        }
        let carrier = relation::RewardSpendCarrier::decode_exact(proof)
            .map_err(|_| RewardAccountsError::InvalidProof)?;
        let public = &carrier.public;
        let address = NetworkShieldedAddress::from_bytes(&claim.recipient, self.genesis.network)
            .map_err(|_| RewardAccountsError::InvalidContext)?;
        let (recipient, authority) = build::recipient(address.recipient())
            .map_err(|_| RewardAccountsError::InvalidContext)?;
        if public.claim != 1
            || public.amount != claim.amount
            || public.base.fee != claim.fee
            || public.operation_binding != claim.operation_binding()
            || public.payout_binding() != claim.payout_binding.into_bytes()
            || public.recipient_authority != authority
            || public.recipient_key != recipient
        {
            return Err(RewardAccountsError::InvalidProof);
        }
        self.check_reference(&public.base)?;
        carrier
            .verify()
            .map_err(|_| RewardAccountsError::InvalidProof)
    }
    fn verify_donation(
        &self,
        donation: &TreasuryDonation,
        proof: &[u8],
    ) -> Result<(), RewardAccountsError> {
        if &donation.context != self.context {
            return Err(RewardAccountsError::InvalidContext);
        }
        let carrier = relation::RewardSpendCarrier::decode_exact(proof)
            .map_err(|_| RewardAccountsError::InvalidProof)?;
        let public = &carrier.public;
        if public.claim != 0
            || public.amount != donation.amount
            || public.base.fee != donation.fee
            || public.operation_binding != donation.operation_binding()
            || public.memo_hash != donation.memo_hash()
        {
            return Err(RewardAccountsError::InvalidProof);
        }
        self.check_reference(&public.base)?;
        carrier
            .verify()
            .map_err(|_| RewardAccountsError::InvalidProof)
    }
    fn verify_private_fee(
        &self,
        context: &AccountChainContext,
        fee: u64,
        carrier: &[u8],
    ) -> Result<(), RewardAccountsError> {
        use protocol_shielded_pool::private_spend_transport as transport;
        if context != self.context {
            return Err(RewardAccountsError::InvalidContext);
        }
        let expected = transport::ExpectedContext::new(
            context.chain_id,
            private::relation_digest()[..48].try_into().unwrap(),
        )
        .map_err(|_| RewardAccountsError::InvalidContext)?;
        let decoded = transport::decode_exact(expected, carrier)
            .map_err(|_| RewardAccountsError::InvalidProof)?;
        let p = &decoded.public;
        if p.fee != fee {
            return Err(RewardAccountsError::InvalidProof);
        }
        let base = private::PrivateSpendPublic {
            chain_id: p.chain_id,
            reference_parent_hash: p.reference_parent_hash,
            reference_parent_height: p.reference_parent_height,
            merkle_root: p.merkle_root,
            fee: p.fee,
            nullifiers: p.nullifiers,
            commitments: p.commitments,
            ciphertext_commitments: p.ciphertext_commitments,
            secret_release: p.secret_release,
            released_secret: p.released_secret,
        };
        self.check_reference(&base)?;
        private::verify_candidate(&base, decoded.proof)
            .map_err(|_| RewardAccountsError::InvalidProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        private_spend::{
            recover_private_spend_note, IssuedPrivateSpendAddresses, StoredPrivateSpendNote,
        },
        RootSecret,
    };
    use synthetic_crypto::{hash384::RulesHash48, ml_dsa::MlDsaSecretKey, traits::SigningKey};
    use transaction_circuit::smallwood_poseidon2_v8_coinbase::{
        poseidon2_v8_default_note_nodes, poseidon2_v8_note_tree_compress,
    };

    struct Fixture {
        genesis: RewardAccountsGenesis,
        context: AccountChainContext,
        signers: Vec<MlDsaSecretKey>,
        receiver: crate::DerivedKeys,
        address: NetworkShieldedAddress,
        reference: SpendReference,
    }
    fn fixture() -> Fixture {
        let signers: Vec<_> = (0..7u8)
            .map(|i| MlDsaSecretKey::generate_deterministic(&[i + 30; 32]))
            .collect();
        let policy = AccountPolicy::threshold(
            5,
            signers
                .iter()
                .map(|k| account_key_hash(&k.verify_key()))
                .collect(),
        )
        .unwrap();
        let id = policy.identifier().unwrap();
        let genesis = RewardAccountsGenesis {
            network: AddressNetwork {
                class: NetworkClass::Testnet,
                discriminator: [19; 32],
            },
            reward_epoch_blocks: 2,
            treasury_policy: policy,
            allocations: BoundedVec::new(vec![GenesisAllocation {
                account: id,
                amount: 100 * COIN,
            }])
            .unwrap(),
        };
        let context = AccountChainContext {
            chain_id: [3; 32],
            genesis_hash: [4; 32],
            genesis_config_hash: RulesHash48::new(genesis.commitment().unwrap()),
        };
        let receiver = RootSecret::from_bytes([8; 32]).derive();
        let address = NetworkShieldedAddress::from_recipient(
            genesis.network,
            receiver.poseidon2_v8_address(0).unwrap().shielded_address(),
        )
        .unwrap();
        let reference = SpendReference {
            chain_id: context.chain_id,
            parent_hash: context.genesis_hash,
            parent_height: 0,
            merkle_root: poseidon2_v8_default_note_nodes()[32],
        };
        Fixture {
            genesis,
            context,
            signers,
            receiver,
            address,
            reference,
        }
    }
    fn prepare(f: &Fixture) -> PreparedAccountClaim {
        prepare_account_claim(
            &f.genesis,
            f.context.clone(),
            f.reference,
            AccountClaimRequest {
                account: f.genesis.treasury_account().unwrap(),
                policy_generation: 0,
                sequence: 0,
                amount: 10 * COIN,
                fee: 1000,
                recipient: f.address.clone(),
            },
        )
        .unwrap()
    }
    fn recover(
        f: &Fixture,
        p: &PreparedAccountClaim,
    ) -> crate::private_spend::RecoveredPrivateSpendNote {
        let public = &p.public_statement().base;
        recover_private_spend_note(
            &f.receiver,
            &IssuedPrivateSpendAddresses::default(),
            private::relation_digest()[..48].try_into().unwrap(),
            f.context.chain_id,
            0,
            public.commitments[0],
            p.spend.outputs.ciphertexts[0].as_bytes(),
        )
        .unwrap()
        .unwrap()
    }
    #[test]
    fn reward_accounts_claim_builder_encrypts_recoverable_ordinary_note() {
        let f = fixture();
        let prepared = prepare(&f);
        let recovered = recover(&f, &prepared);
        assert_eq!(recovered.payload.note.value, 10 * COIN);
        assert!(matches!(
            recovered.payload.state,
            synthetic_crypto::private_note_payload::NoteState::Ordinary { .. }
        ));
        assert_eq!(
            prepared.claim().payout_binding.into_bytes(),
            prepared.public_statement().payout_binding()
        );
        assert_eq!(
            prepared.public_statement().operation_binding,
            prepared.claim().operation_binding()
        );
    }
    #[test]
    #[ignore = "real account claim and donation proofs with encryption and quorum; release qualification"]
    fn reward_accounts_actual_claim_then_donate_real_proofs() {
        let f = fixture();
        let prepared = prepare(&f);
        let carrier = prepared.prove().unwrap();
        eprintln!("actual encrypted claim proof {} bytes", carrier.proof.len());
        let policy = &f.genesis.treasury_policy;
        let mut approvals: Vec<_> = f
            .signers
            .iter()
            .take(5)
            .map(|key| {
                let i = policy
                    .signer_hashes()
                    .iter()
                    .position(|h| *h == account_key_hash(&key.verify_key()))
                    .unwrap() as u8;
                AccountApproval::sign(i, key, &prepared.claim().authorization_digest())
            })
            .collect();
        approvals.sort_by_key(|a| a.signer_index);
        let owner = AccountPolicy::single(&f.signers[0].verify_key())
            .identifier()
            .unwrap();
        let ledger = RewardAccountLedger::new(f.genesis.clone(), f.context.clone()).unwrap();
        let check_zero = |r: SpendReference| {
            if r.parent_height == 0
                && r.parent_hash == f.reference.parent_hash
                && r.merkle_root == f.reference.merkle_root
            {
                Ok(())
            } else {
                Err(RewardAccountsError::InvalidContext)
            }
        };
        let verifier = RewardProofVerifier::new(&f.genesis, &f.context, &check_zero).unwrap();
        let action = RewardAccountAction::Claim {
            claim: prepared.claim().clone(),
            policy: policy.clone(),
            approvals: BoundedVec::new(approvals).unwrap(),
            proof: BoundedVec::new(carrier.encode_carrier().unwrap()).unwrap(),
        };
        let ledger = ledger.apply_block(1, owner, &[action], &verifier).unwrap();
        assert_eq!(ledger.shielded_value(), 10 * COIN);
        let recovered = recover(&f, &prepared);
        let commitment = carrier.public.base.commitments[0];
        let stored = StoredPrivateSpendNote::new(
            recovered,
            &f.receiver,
            f.context.chain_id,
            commitment,
            0,
            1,
            [5; 32],
        )
        .unwrap();
        // Constructed canonical reference for this wallet/core qualification.
        // This is not a mined block, node import or shared-state replay receipt.
        let siblings: [private::Digest; 32] =
            poseidon2_v8_default_note_nodes()[..32].try_into().unwrap();
        let root = siblings.iter().fold(commitment, |left, right| {
            poseidon2_v8_note_tree_compress(left, *right)
        });
        let reference = SpendReference {
            chain_id: f.context.chain_id,
            parent_hash: [5; 32],
            parent_height: 1,
            merkle_root: root,
        };
        let input = SpendInput::stored(&stored, &f.receiver, siblings).unwrap();
        let donation = TreasuryDonation {
            context: f.context.clone(),
            amount: COIN,
            fee: 1000,
            memo: BoundedVec::new(b"public reward-account donation".to_vec()).unwrap(),
        };
        let output = f.address.recipient().clone();
        let prepared_donation = prepare_treasury_donation(
            &f.genesis,
            donation.clone(),
            reference,
            [input, SpendInput::dummy().unwrap()],
            [
                OutputRequest {
                    recipient: output.clone(),
                    value: 9 * COIN - 1000,
                },
                OutputRequest {
                    recipient: output,
                    value: 0,
                },
            ],
        )
        .unwrap();
        let carrier = prepared_donation.prove().unwrap();
        eprintln!(
            "actual encrypted donation proof {} bytes",
            carrier.proof.len()
        );
        let check_one = |r: SpendReference| {
            if r.parent_height == 1
                && r.parent_hash == reference.parent_hash
                && r.merkle_root == root
            {
                Ok(())
            } else {
                Err(RewardAccountsError::InvalidContext)
            }
        };
        let verifier = RewardProofVerifier::new(&f.genesis, &f.context, &check_one).unwrap();
        let action = RewardAccountAction::Donation {
            donation,
            proof: BoundedVec::new(carrier.encode_carrier().unwrap()).unwrap(),
        };
        let ledger = ledger.apply_block(2, owner, &[action], &verifier).unwrap();
        assert_eq!(ledger.shielded_value(), 9 * COIN - 1000);
        assert_eq!(
            ledger.account_at(ledger.treasury(), 3).unwrap().available(),
            91 * COIN - 1000
        );
        ledger.validate().unwrap();
    }
}
