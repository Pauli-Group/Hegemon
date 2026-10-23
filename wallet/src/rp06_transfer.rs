//! Ordinary native transfers on the exact RP06 launch chain.
//!
//! Inputs come from the canonical encrypted wallet mirror and are durably
//! reserved before construction or proving. No witness or key is caller supplied.
#![forbid(unsafe_code)]

use codec::Encode;
use protocol_shielded_pool::rp06_transport::{
    encode_rp06_candidate_envelope, encode_rp06_candidate_inline_args,
    encode_rp06_candidate_native_leaf, Rp06ExpectedContext, RP06_PREAMBLE_BYTES,
};
use protocol_versioning::launch_candidate::{self, LaunchProofKind};
use rand::{CryptoRng, RngCore};
use transaction_circuit::{
    constants::{MAX_IN_CIRCUIT_VALUE, NATIVE_ASSET_ID},
    smallwood_poseidon2_v8_hash_schedule::{
        build_smallwood_poseidon2_v8_hash_schedule, SmallwoodPoseidon2V8HashDigestRef,
        SmallwoodPoseidon2V8HashFinalBinding,
    },
    smallwood_poseidon2_v8_rp06::{
        compile_rp06_relation, prove_rp06_candidate, rp06_program_digest, rp06_transcript_bytes,
        verify_rp06_candidate, Rp06PublicStatement,
    },
    smallwood_poseidon2_v8_types::{
        smallwood_poseidon2_v8_ciphertext_commitment, SmallwoodPoseidon2V8InlineCiphertexts,
        SmallwoodPoseidon2V8OutputWitness, SmallwoodPoseidon2V8PublicStatement,
        SmallwoodPoseidon2V8Witness,
    },
};

use crate::{
    poseidon2_v8_coinbase::{
        build_poseidon2_v8_coinbase_args, build_poseidon2_v8_owned_spend_input,
        protocol_opening_to_relation,
    },
    poseidon2_v8_sync::{LaunchWalletContext, Poseidon2V8CanonicalTip},
    store::Poseidon2V8SpendReservation,
    ActionId48, NoteCiphertext, ShieldedAddress, WalletError, WalletStore,
};

fn invalid(message: &'static str) -> WalletError {
    WalletError::InvalidState(message)
}
fn surface(error: impl std::fmt::Debug) -> WalletError {
    WalletError::Serialization(format!("RP06 ordinary transfer: {error:?}"))
}

/// Public carrier plus exclusive input reservation. No private witness or key
/// survives proof preparation, and this value deliberately has no Debug/Clone.
pub struct PreparedRp06Transfer<'a> {
    store: &'a WalletStore,
    context: LaunchWalletContext,
    tip: Poseidon2V8CanonicalTip,
    statement: Rp06PublicStatement,
    inline_args: Vec<u8>,
    proof_bytes: usize,
    require_authority: bool,
    reservation: Poseidon2V8SpendReservation<'a>,
}
impl PreparedRp06Transfer<'_> {
    pub fn statement(&self) -> Rp06PublicStatement {
        self.statement
    }
    pub(crate) fn inline_args(&self) -> &[u8] {
        &self.inline_args
    }
    /// The carrier crosses the public API only after external ambiguity and
    /// its complete exact bytes have been retained in encrypted wallet state.
    pub fn export_candidate(
        &self,
    ) -> Result<crate::rp06_transfer_store::Rp06TransferCandidateExport, WalletError> {
        self.check_current(self.require_authority)?;
        self.store.begin_poseidon2_v8_reserved_submission(
            self.reservation.id(),
            self.context,
            self.tip,
            self.require_authority.then_some(self.proof_bytes),
        )?;
        let record = crate::rp06_transfer_store::StoredRp06TransferCandidate::new(
            self.reservation.id(),
            self.context,
            self.tip,
            self.inline_args.clone(),
        )?;
        self.store
            .retain_rp06_transfer_candidate(self.context, record)?;
        if self.require_authority {
            self.store
                .export_rp06_transfer_candidate(self.reservation.id())
        } else {
            #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
            {
                self.store
                    .export_rp06_transfer_candidate_for_retained_test(self.reservation.id())
            }
            #[cfg(not(any(test, feature = "poseidon2-v8-retained-test-support")))]
            {
                Err(invalid(
                    "retained export is absent from ordinary wallet builds",
                ))
            }
        }
    }
    pub fn reservation_id(&self) -> [u8; 32] {
        self.reservation.id()
    }
    pub fn tip(&self) -> Poseidon2V8CanonicalTip {
        self.tip
    }
    /// Persist uncertainty immediately before the caller starts a mutating
    /// submission. All transport preparation must already have completed.
    pub fn begin_submission(&self) -> Result<(), WalletError> {
        if !self.require_authority {
            return Err(invalid(
                "retained transfer requires explicit retained submission",
            ));
        }
        self.check_current(true)?;
        self.export_candidate().map(|_| ())
    }
    #[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
    pub fn begin_submission_for_retained_test(&self) -> Result<(), WalletError> {
        if self.require_authority {
            return Err(invalid(
                "production transfer requires source-authorized submission",
            ));
        }
        self.check_current(false)?;
        self.export_candidate().map(|_| ())
    }
    pub fn mark_submitted(&self, action_id: ActionId48) -> Result<(), WalletError> {
        self.store
            .mark_rp06_transfer_candidate_submitted(self.reservation.id(), action_id)
    }
    pub fn release(self) -> Result<(), WalletError> {
        if self.store.poseidon2_v8_reservations()?.iter().any(|entry| {
            entry.reservation_id == self.reservation.id()
                && entry.status != crate::store::Poseidon2V8ReservationStatus::Proving
        }) {
            return Err(invalid(
                "exported RP06 inputs require canonical abandonment, not release",
            ));
        }
        self.reservation.release()
    }
    fn check_current(&self, require_authority: bool) -> Result<(), WalletError> {
        let height = self
            .store
            .require_rp06_canonical_reference(self.context, self.tip)?;
        if require_authority {
            require_rp06_authority(self.context, height, self.proof_bytes)?;
        }
        Ok(())
    }
}

pub(crate) fn require_rp06_authority(
    context: LaunchWalletContext,
    height: u64,
    proof_bytes: usize,
) -> Result<(), WalletError> {
    if launch_candidate::launch_proof_authority(context.request(
        LaunchProofKind::Rp06,
        height,
        proof_bytes,
    ))
    .is_none()
    {
        return Err(invalid(
            "RP06 ordinary transfer has no exact source-owned launch authority",
        ));
    }
    Ok(())
}

/// Prepare a real ordinary native payment and optional change. The source
/// capability gate is checked before reservation/proving and again afterward.
pub fn prepare_rp06_transfer<'a, R: RngCore + CryptoRng + ?Sized>(
    store: &'a WalletStore,
    context: LaunchWalletContext,
    recipient: &ShieldedAddress,
    amount: u64,
    fee: u64,
    rng: &mut R,
) -> Result<PreparedRp06Transfer<'a>, WalletError> {
    prepare_inner(store, context, recipient, amount, fee, rng, true)
}

/// The same constrained RP06/SMZB path for an explicitly retained test node.
/// It neither installs production authority nor selects a legacy proof route.
#[cfg(any(test, feature = "poseidon2-v8-retained-test-support"))]
pub fn prepare_rp06_transfer_for_retained_test<'a, R: RngCore + CryptoRng + ?Sized>(
    store: &'a WalletStore,
    context: LaunchWalletContext,
    recipient: &ShieldedAddress,
    amount: u64,
    fee: u64,
    rng: &mut R,
) -> Result<PreparedRp06Transfer<'a>, WalletError> {
    prepare_inner(store, context, recipient, amount, fee, rng, false)
}

struct TransferMaterial<'a> {
    statement: Rp06PublicStatement,
    witness: SmallwoodPoseidon2V8Witness,
    ciphertexts: SmallwoodPoseidon2V8InlineCiphertexts,
    tip: Poseidon2V8CanonicalTip,
    reservation: Poseidon2V8SpendReservation<'a>,
}

fn construct_material<'a, R: RngCore + CryptoRng + ?Sized>(
    store: &'a WalletStore,
    context: LaunchWalletContext,
    recipient: &ShieldedAddress,
    amount: u64,
    fee: u64,
    rng: &mut R,
    require_authority: bool,
) -> Result<TransferMaterial<'a>, WalletError> {
    if amount == 0
        || u128::from(amount) > MAX_IN_CIRCUIT_VALUE
        || u128::from(fee) > MAX_IN_CIRCUIT_VALUE
    {
        return Err(invalid(
            "RP06 payment/fee is outside the native value range",
        ));
    }
    store.require_launch_context(context)?;
    let genesis = store
        .poseidon2_v8_canonical_hash(0)?
        .ok_or(invalid("RP06 mirror has no canonical genesis"))?;
    let next_height =
        context.require_canonical_parent(genesis, store.poseidon2_v8_tip()?.height)?;
    if require_authority {
        require_rp06_authority(context, next_height, 1)?;
    }
    // This atomically selects canonical unspent notes and persists Proving
    // before private witness construction, encryption or expensive proving.
    let reservation = store.reserve_poseidon2_v8_spend()?;
    let spend = reservation.context();
    let tip = spend.tip;
    let next_height = context.require_canonical_parent(genesis, tip.height)?;
    if require_authority {
        require_rp06_authority(context, next_height, 1)?;
    }
    if spend
        .notes
        .iter()
        .any(|note| note.spent || note.anchor != tip.anchor)
        || spend.notes[0].position == spend.notes[1].position
    {
        return Err(invalid(
            "RP06 reserved inputs do not share one canonical parent",
        ));
    }
    let keys = store.derived_keys()?.ok_or(WalletError::WatchOnly)?;
    let mut inputs =
        [transaction_circuit::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8InputWitness::ZERO;
            2];
    for input in 0..2 {
        let note = &spend.notes[input];
        let material = keys.poseidon2_v8_address(note.diversifier_index)?;
        inputs[input] = build_poseidon2_v8_owned_spend_input(
            &material,
            &keys.spend,
            note.opening,
            note.position,
            note.path,
        )?;
    }
    let total = spend.notes[0]
        .opening
        .value
        .checked_add(spend.notes[1].opening.value)
        .ok_or(invalid("RP06 reserved native value overflow"))?;
    let required = amount
        .checked_add(fee)
        .ok_or(invalid("RP06 payment plus fee overflow"))?;
    let change = total
        .checked_sub(required)
        .ok_or(invalid("RP06 payment plus fee exceeds reserved funds"))?;
    let change_address = keys.poseidon2_v8_address(0)?.shielded_address();
    let mut outputs = [SmallwoodPoseidon2V8OutputWitness::ZERO; 2];
    let mut ciphertexts = SmallwoodPoseidon2V8InlineCiphertexts {
        ciphertexts: [None, None],
    };
    for (output, address, value) in [(0, recipient, amount), (1, &change_address, change)] {
        if value == 0 {
            continue;
        }
        let note = build_poseidon2_v8_coinbase_args(address, value, rng)?.miner_note;
        let opening = protocol_opening_to_relation(note.opening);
        let raw = NoteCiphertext::from_chain_bytes(&note.encrypted_note.encode())?.to_da_bytes()?;
        ciphertexts.ciphertexts[output] = Some(
            raw.try_into()
                .map_err(|_| invalid("RP06 encrypted output has the wrong canonical width"))?,
        );
        outputs[output] = SmallwoodPoseidon2V8OutputWitness {
            active: true,
            note: opening,
            balance_slot_selectors: [true, false, false, false],
        };
    }
    let mut base = SmallwoodPoseidon2V8PublicStatement {
        input_flags: [true, true],
        output_flags: [true, change > 0],
        fee,
        merkle_root: tip.anchor,
        ..SmallwoodPoseidon2V8PublicStatement::default()
    };
    base.stablecoin.parent_height = tip.height;
    let stable = tip
        .stablecoin_root
        .unwrap_or([0; 7])
        .map(hegemon_field::Goldilocks::new);
    base.stablecoin.before_root = stable;
    base.stablecoin.after_root = stable;
    let witness = SmallwoodPoseidon2V8Witness {
        inputs,
        outputs,
        ..SmallwoodPoseidon2V8Witness::default()
    };
    let hashes = build_smallwood_poseidon2_v8_hash_schedule(&base, &witness).map_err(surface)?;
    let digest = |wanted| {
        hashes
            .calls
            .iter()
            .find(|call| call.final_binding == SmallwoodPoseidon2V8HashFinalBinding::Digest(wanted))
            .map(|call| call.final_digest())
            .ok_or(invalid("RP06 native digest binding is missing"))
    };
    for input in 0..2 {
        base.nullifiers[input] =
            digest(SmallwoodPoseidon2V8HashDigestRef::InputNullifier { input })?;
        if base.nullifiers[input] != spend.notes[input].nullifier {
            return Err(invalid(
                "RP06 input nullifier differs from reserved canonical note",
            ));
        }
    }
    for output in 0..2 {
        if let Some(raw) = ciphertexts.ciphertexts[output].as_ref() {
            base.commitments[output] =
                digest(SmallwoodPoseidon2V8HashDigestRef::OutputNote { output })?;
            base.ciphertext_commitments[output] = smallwood_poseidon2_v8_ciphertext_commitment(raw);
        }
    }
    let statement = Rp06PublicStatement {
        base,
        chain_id: context.chain_id(),
    };
    if witness
        .inputs
        .iter()
        .any(|input| input.note.asset_id != NATIVE_ASSET_ID)
    {
        return Err(invalid("RP06 ordinary transfer accepts only native inputs"));
    }
    ciphertexts
        .validate_against_statement(&statement.base)
        .map_err(surface)?;
    compile_rp06_relation(statement, &witness).map_err(surface)?;
    Ok(TransferMaterial {
        statement,
        witness,
        ciphertexts,
        tip,
        reservation,
    })
}

fn prepare_inner<'a, R: RngCore + CryptoRng + ?Sized>(
    store: &'a WalletStore,
    context: LaunchWalletContext,
    recipient: &ShieldedAddress,
    amount: u64,
    fee: u64,
    rng: &mut R,
    require_authority: bool,
) -> Result<PreparedRp06Transfer<'a>, WalletError> {
    let TransferMaterial {
        statement,
        witness,
        ciphertexts,
        tip,
        reservation,
    } = construct_material(
        store,
        context,
        recipient,
        amount,
        fee,
        rng,
        require_authority,
    )?;
    let proof = prove_rp06_candidate(statement, &witness).map_err(surface)?;
    verify_rp06_candidate(&proof, context.chain_id()).map_err(surface)?;
    let expected =
        Rp06ExpectedContext::new(context.chain_id(), rp06_program_digest()).map_err(surface)?;
    let preamble: [u8; RP06_PREAMBLE_BYTES] = rp06_transcript_bytes(&statement)
        .map_err(surface)?
        .try_into()
        .map_err(|_| invalid("RP06 source preamble is not exactly1192bytes"))?;
    let leaf = encode_rp06_candidate_native_leaf(
        expected,
        &preamble,
        ciphertexts.ciphertexts.each_ref().map(Option::as_ref),
        &proof.proof_bytes,
    )
    .map_err(surface)?;
    let envelope = encode_rp06_candidate_envelope(expected, &leaf).map_err(surface)?;
    let inline_args = encode_rp06_candidate_inline_args(expected, &envelope).map_err(surface)?;
    let prepared = PreparedRp06Transfer {
        store,
        context,
        tip,
        statement,
        inline_args,
        proof_bytes: proof.proof_bytes.len(),
        require_authority,
        reservation,
    };
    prepared.check_current(require_authority)?;
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_shielded_pool::{
        poseidon2_v8_coinbase::MintPoseidon2V8RewardsArgs, types::CandidateArtifact,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use transaction_circuit::hashing_pq::ciphertext_hash_bytes;

    const TEST_WALLET_FILENAME: &str = "rp06-ordinary-wallet.dat";

    fn append_empty_block(
        store: &WalletStore,
        context: LaunchWalletContext,
    ) -> crate::Poseidon2V8CanonicalBlock {
        let parent = store.poseidon2_v8_tip().unwrap();
        let block = crate::Poseidon2V8CanonicalBlock {
            height: parent.height + 1,
            hash: [100 + parent.height as u8; 32],
            parent_hash: parent.block_hash,
            action_bytes: Vec::new(),
        };
        store
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&block, context)
            .unwrap();
        block
    }

    fn retain_public_artifacts(
        context: LaunchWalletContext,
        exported: &crate::rp06_transfer_store::Rp06TransferCandidateExport,
    ) {
        use sha2::{Digest, Sha512};
        use std::io::Write;
        let Some(directory) = std::env::var_os("HEGEMON_RP06_ORDINARY_ARTIFACT_DIR") else {
            return;
        };
        let directory = std::path::PathBuf::from(directory);
        // The caller allocates a new directory, separate from the disposable
        // encrypted wallet. Existing artifacts are never overwritten.
        std::fs::create_dir(&directory).unwrap();
        let decoded = protocol_shielded_pool::rp06_transport::decode_rp06_inline_args_exact(
            Rp06ExpectedContext::new(context.chain_id(), rp06_program_digest()).unwrap(),
            exported.inline_args(),
        )
        .unwrap();
        let leaf = decoded.native_leaf();
        let receipt = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "hegemon-rp06-ordinary-public-artifact-v1",
            "production_authorized": false,
            "actual_smzb_generated_and_verified": true,
            "chain_id": hex::encode(context.chain_id()),
            "genesis_hash": hex::encode(context.genesis_hash()),
            "manifest_sha512": hex::encode(context.manifest_digest()),
            "relation_identity_sha512": hex::encode(
                transaction_circuit::smallwood_poseidon2_v8_rp06::rp06_program_identity_sha512()
            ),
            "reference_height": exported.tip().height,
            "reference_hash": hex::encode(exported.tip().block_hash),
            "reference_anchor": exported.tip().anchor,
            "stablecoin_root": exported.tip().stablecoin_root,
            "carrier_bytes": exported.inline_args().len(),
            "carrier_sha512": hex::encode(exported.carrier_sha512()),
            "preamble_bytes": leaf.preamble().len(),
            "preamble_sha512": hex::encode(Sha512::digest(leaf.preamble())),
            "smzb_bytes": leaf.proof().len(),
            "smzb_sha512": hex::encode(Sha512::digest(leaf.proof())),
            "public_words": leaf.public_words().to_vec(),
        }))
        .unwrap();
        for (name, bytes) in [
            ("carrier.bin", exported.inline_args()),
            ("preamble.bin", leaf.preamble()),
            ("proof.smzb", leaf.proof()),
            ("receipt.json", receipt.as_slice()),
        ] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
    }

    fn funded_wallet(
        directory: &std::path::Path,
    ) -> (WalletStore, LaunchWalletContext, ShieldedAddress) {
        let (store, context, recipient, _) = funded_wallet_with_blocks(directory);
        (store, context, recipient)
    }

    fn funded_wallet_with_blocks(
        directory: &std::path::Path,
    ) -> (
        WalletStore,
        LaunchWalletContext,
        ShieldedAddress,
        Vec<crate::Poseidon2V8CanonicalBlock>,
    ) {
        let store = WalletStore::create_from_root(
            directory.join(TEST_WALLET_FILENAME),
            "test-passphrase",
            crate::RootSecret::from_bytes([0x71; 32]),
        )
        .unwrap();
        let genesis = [81; 32];
        store
            .ensure_poseidon2_v8_genesis_for_test(genesis, [0; 7])
            .unwrap();
        let context = LaunchWalletContext::new([82; 32], genesis, [83; 64], 1, 500).unwrap();
        store
            .initialize_pinned_launch_context_for_retained_test(context)
            .unwrap();
        let mut parent = genesis;
        let mut blocks = Vec::new();
        for (height, amount, diversifier) in [(1, 100, 0), (2, 200, 1)] {
            let address = store
                .derived_keys()
                .unwrap()
                .unwrap()
                .poseidon2_v8_address(diversifier)
                .unwrap()
                .shielded_address();
            let args = MintPoseidon2V8RewardsArgs {
                miner_note: build_poseidon2_v8_coinbase_args(
                    &address,
                    amount,
                    &mut StdRng::seed_from_u64(height),
                )
                .unwrap()
                .miner_note,
                funding_note: None,
            };
            let raw = NoteCiphertext::from_chain_bytes(&args.miner_note.encrypted_note.encode())
                .unwrap()
                .to_da_bytes()
                .unwrap();
            // Exact pending-action SCALE grammar; the mirror verifies its full hash.
            let body = (
                (9u16, 7u16),
                1u16,
                12u16,
                [0u8; 48],
                Vec::<[u8; 48]>::new(),
                Vec::<[u8; 48]>::new(),
                vec![ciphertext_hash_bytes(&raw)],
                vec![raw.len() as u32],
                args.encode(),
                0u64,
                None::<CandidateArtifact>,
            );
            let body_bytes = body.encode();
            let action_hash = hegemon_hash384::blake2b_384_domain_hash(
                hegemon_hash384::domains::ACTION_ID_V3,
                [body_bytes.as_slice()],
            );
            let block_hash = [90 + height as u8; 32];
            let block = crate::Poseidon2V8CanonicalBlock {
                height,
                hash: block_hash,
                parent_hash: parent,
                action_bytes: vec![(action_hash, body).encode()],
            };
            store
                .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&block, context)
                .unwrap();
            blocks.push(block);
            parent = block_hash;
        }
        // Rewards enter the spend tree only at the actual 120-block maturity
        // boundary. Keep the immature, first-release and second-release states
        // explicit so this fixture cannot silently regress to immediate spends.
        assert!(store.poseidon2_v8_owned_notes().unwrap().is_empty());
        for height in 3..=protocol_versioning::COINBASE_MATURITY + 1 {
            blocks.push(append_empty_block(&store, context));
            if height >= protocol_versioning::COINBASE_MATURITY - 1 {
                assert_eq!(
                    store.poseidon2_v8_owned_notes().unwrap().len(),
                    (height + 1 - protocol_versioning::COINBASE_MATURITY) as usize,
                );
            }
        }
        let recipient = crate::RootSecret::from_bytes([0x72; 32])
            .derive()
            .poseidon2_v8_address(5)
            .unwrap()
            .shielded_address();
        (store, context, recipient, blocks)
    }

    #[test]
    fn canonical_rewards_form_a_constrained_ordinary_payment_and_durable_reservation() {
        let directory = tempfile::tempdir().unwrap();
        let (store, context, recipient) = funded_wallet(directory.path());
        let material = construct_material(
            &store,
            context,
            &recipient,
            257,
            3,
            &mut StdRng::seed_from_u64(7),
            false,
        )
        .unwrap();
        assert_eq!(material.statement.chain_id, context.chain_id());
        assert_eq!(material.statement.base.fee, 3);
        assert_eq!(material.witness.outputs[0].note.value, 257);
        assert_eq!(material.witness.outputs[1].note.value, 40);
        assert_ne!(
            material.witness.outputs[0].note.authorization_key,
            material.witness.inputs[0].note.authorization_key
        );
        assert_eq!(material.witness.inputs[0].position, 0);
        assert_eq!(material.witness.inputs[1].position, 1);
        assert_eq!(store.poseidon2_v8_reservations().unwrap().len(), 1);
        assert!(construct_material(
            &store,
            context,
            &recipient,
            1,
            0,
            &mut StdRng::seed_from_u64(8),
            false
        )
        .is_err());
        let mut changed = material.statement;
        changed.base.fee += 1;
        assert!(compile_rp06_relation(changed, &material.witness).is_err());
        let mut changed_witness = material.witness;
        changed_witness.outputs[0].note.recipient_key[3] ^= 1;
        assert!(compile_rp06_relation(material.statement, &changed_witness).is_err());
        drop(material);
        assert!(store.poseidon2_v8_reservations().unwrap().is_empty());
        assert!(prepare_rp06_transfer(
            &store,
            context,
            &recipient,
            1,
            0,
            &mut StdRng::seed_from_u64(9)
        )
        .is_err());
        assert!(store.poseidon2_v8_reservations().unwrap().is_empty());
    }

    #[test]
    fn full_value_payment_canonicalizes_inactive_change_and_rejects_foreign_context() {
        let directory = tempfile::tempdir().unwrap();
        let (store, context, recipient) = funded_wallet(directory.path());
        let foreign = LaunchWalletContext::new(
            [84; 32],
            context.genesis_hash(),
            context.manifest_digest(),
            1,
            500,
        )
        .unwrap();
        assert!(construct_material(
            &store,
            foreign,
            &recipient,
            1,
            0,
            &mut StdRng::seed_from_u64(10),
            false
        )
        .is_err());
        let material = construct_material(
            &store,
            context,
            &recipient,
            297,
            3,
            &mut StdRng::seed_from_u64(11),
            false,
        )
        .unwrap();
        assert_eq!(material.statement.base.output_flags, [true, false]);
        assert_eq!(
            material.witness.outputs[1],
            SmallwoodPoseidon2V8OutputWitness::ZERO
        );
        assert_eq!(material.ciphertexts.ciphertexts[1], None);
        assert_eq!(material.statement.base.commitments[1], [0; 7]);
        assert_eq!(material.statement.base.ciphertext_commitments[1], [0; 6]);
    }

    #[test]
    fn canonical_reference_window_rejects_expired_future_and_orphaned_checkpoints() {
        let directory = tempfile::tempdir().unwrap();
        let (store, context, _) = funded_wallet(directory.path());
        let reference = store.poseidon2_v8_tip().unwrap();
        let mut future = reference;
        future.height += 1;
        assert!(store
            .require_rp06_canonical_reference(context, future)
            .is_err());
        let mut orphan = reference;
        orphan.block_hash = [98; 32];
        assert!(store
            .require_rp06_canonical_reference(context, orphan)
            .is_err());
        let mut changed_root = reference;
        changed_root.anchor[0] ^= 1;
        assert!(store
            .require_rp06_canonical_reference(context, changed_root)
            .is_err());
        for age in 0..=protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW {
            assert_eq!(
                store
                    .require_rp06_canonical_reference(context, reference)
                    .unwrap(),
                reference.height + age + 1,
            );
            assert_eq!(
                store
                    .poseidon2_v8_canonical_tip_at_height(reference.height)
                    .unwrap(),
                Some(reference),
            );
            append_empty_block(&store, context);
        }
        assert!(store
            .require_rp06_canonical_reference(context, reference)
            .is_err());
    }

    #[test]
    #[ignore = "requires the coordinator's bounded actual SMZB proof lane"]
    fn actual_ordinary_candidate_uses_the_full_rp06_carrier() {
        let directory = tempfile::tempdir().unwrap();
        let (store, context, recipient, blocks) = funded_wallet_with_blocks(directory.path());
        let prepared = prepare_rp06_transfer_for_retained_test(
            &store,
            context,
            &recipient,
            257,
            3,
            &mut StdRng::seed_from_u64(12),
        )
        .unwrap();
        let expected = Rp06ExpectedContext::new(context.chain_id(), rp06_program_digest()).unwrap();
        let decoded = protocol_shielded_pool::rp06_transport::decode_rp06_inline_args_exact(
            expected,
            prepared.inline_args(),
        )
        .unwrap();
        assert_eq!(decoded.native_leaf().preamble().len(), 1192);
        assert_eq!(&decoded.native_leaf().proof()[..4], b"SMZB");
        assert_eq!(
            decoded.native_leaf().public_words(),
            prepared.statement().to_public_words()
        );
        assert!(prepared.begin_submission().is_err());
        let exported = prepared.export_candidate().unwrap();
        retain_public_artifacts(context, &exported);
        let reservation_id = prepared.reservation_id();
        prepared.begin_submission_for_retained_test().unwrap();
        assert!(store.poseidon2_v8_reservations().unwrap()[0].inputs_reserved);
        drop(prepared);
        assert_eq!(
            store.poseidon2_v8_reservations().unwrap()[0].status,
            crate::store::Poseidon2V8ReservationStatus::SubmissionUncertain
        );
        drop(store);
        let reopened = WalletStore::open(
            directory.path().join(TEST_WALLET_FILENAME),
            "test-passphrase",
        )
        .unwrap();
        let recovered = reopened
            .export_rp06_transfer_candidate_for_retained_test(reservation_id)
            .unwrap();
        assert_eq!(recovered.inline_args(), exported.inline_args());
        assert_eq!(recovered.carrier_sha512(), exported.carrier_sha512());
        assert_eq!(recovered.tip(), exported.tip());
        assert!(recovered.current_parent_eligible());
        assert!(reopened
            .export_rp06_transfer_candidate(reservation_id)
            .is_err());
        // The same retained proof cannot export against a future reference or
        // an orphaned block at its height. Restore the original public block.
        reopened
            .rollback_poseidon2_v8_to(exported.tip().height - 1, blocks[blocks.len() - 2].hash)
            .unwrap();
        assert!(reopened
            .export_rp06_transfer_candidate_for_retained_test(reservation_id)
            .is_err());
        append_empty_block(&reopened, context);
        assert!(reopened
            .export_rp06_transfer_candidate_for_retained_test(reservation_id)
            .is_err());
        reopened
            .rollback_poseidon2_v8_to(exported.tip().height - 1, blocks[blocks.len() - 2].hash)
            .unwrap();
        reopened
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(
                blocks.last().unwrap(),
                context,
            )
            .unwrap();
        assert!(construct_material(
            &reopened,
            context,
            &recipient,
            1,
            0,
            &mut StdRng::seed_from_u64(13),
            false
        )
        .is_err());
        assert!(reopened
            .abandon_rp06_transfer_candidate(reservation_id)
            .is_err());
        for _ in 0..protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW {
            append_empty_block(&reopened, context);
        }
        let at_last_parent = reopened
            .export_rp06_transfer_candidate_for_retained_test(reservation_id)
            .unwrap();
        assert!(at_last_parent.current_parent_eligible());
        assert_eq!(at_last_parent.inline_args(), exported.inline_args());
        assert_eq!(at_last_parent.carrier_sha512(), exported.carrier_sha512());
        assert_eq!(at_last_parent.tip(), exported.tip());
        reopened
            .begin_poseidon2_v8_reserved_submission(reservation_id, context, exported.tip(), None)
            .unwrap();
        assert!(reopened
            .abandon_rp06_transfer_candidate(reservation_id)
            .is_err());
        let last_tip = reopened.poseidon2_v8_tip().unwrap();
        append_empty_block(&reopened, context);
        assert!(reopened
            .export_rp06_transfer_candidate_for_retained_test(reservation_id)
            .is_err());
        assert!(reopened
            .begin_poseidon2_v8_reserved_submission(reservation_id, context, exported.tip(), None)
            .is_err());
        reopened
            .abandon_rp06_transfer_candidate(reservation_id)
            .unwrap();
        assert!(!reopened.poseidon2_v8_reservations().unwrap()[0].inputs_reserved);
        assert!(reopened
            .export_rp06_transfer_candidate_for_retained_test(reservation_id)
            .is_err());
        reopened
            .rollback_poseidon2_v8_to(last_tip.height, last_tip.block_hash)
            .unwrap();
        assert!(reopened.poseidon2_v8_reservations().unwrap()[0].inputs_reserved);
        assert!(reopened
            .export_rp06_transfer_candidate_for_retained_test(reservation_id)
            .is_err());
    }
}
