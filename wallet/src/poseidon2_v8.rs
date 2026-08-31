//! Production wallet entrypoint for the compact SmallWood/Poseidon2 V8 action.
//!
//! The public method in this module takes the canonical typed statement,
//! private witness, inline ciphertexts, and exact network/relation context. It
//! compiles and proves only through the source-owned V8 frontend, reconstructs
//! and runs the local verifier, creates one `HGV8TX02` native leaf, and hands
//! that leaf to the additive `SWP8LC02`/SCALE RPC helper. The private witness
//! is moved into the blocking proving task and is absent from the prepared
//! submission returned by that task.

#![forbid(unsafe_code)]

use protocol_shielded_pool::poseidon2_production_transport::{
    decode_poseidon2_production_smz9_native_leaf_exact, encode_poseidon2_production_smz9_envelope,
    encode_poseidon2_production_smz9_inline_args, encode_poseidon2_production_smz9_native_leaf,
    POSEIDON2_PRODUCTION_SMZ9_INNER_PROOF_MAGIC, POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID,
    POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID, POSEIDON2_PRODUCTION_TRANSPORT_BACKEND_ID,
    POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET, POSEIDON2_PRODUCTION_TRANSPORT_FAMILY_ID,
};
use transaction_circuit::{
    compile_and_prove_smallwood_poseidon2_v8_candidate, smallwood_poseidon2_v8_exact_action_bytes,
    verify_smallwood_poseidon2_v8_candidate, SmallwoodPoseidon2V8SourceRelationFactory,
    SmallwoodPoseidon2V8VerifierInput, SmallwoodPoseidon2V8VerifierRelationFactory,
};

use crate::prover::FreshTransactionProofAuthority;
use crate::{ActionId48, NodeRpcClient, WalletError, WalletStore};

pub use protocol_shielded_pool::poseidon2_production_transport::Poseidon2ProductionExpectedContext;
pub use transaction_circuit::smallwood_poseidon2_v8_types::{
    SmallwoodPoseidon2V8InlineCiphertexts, SmallwoodPoseidon2V8PublicStatement,
    SmallwoodPoseidon2V8Witness,
};

/// Exact source-derived maximum for the two-output SMZ9 SCALE inline arguments.
/// This is not the size of the enclosing native `PendingAction` record.
pub const SMALLWOOD_POSEIDON2_V8_WALLET_MAX_INLINE_ARGS_BYTES: usize =
    transaction_circuit::smallwood_poseidon2_v8_security::SMALLWOOD_POSEIDON2_V8_MAX_ACTION_BYTES
        as usize;
/// Exact projected size of the enclosing canonical two-output native
/// `PendingAction`. The node source-binds its 225-byte outer overhead with the
/// real SCALE encoder and enforces a separate 131,297-byte route cap.
pub const SMALLWOOD_POSEIDON2_V8_PROJECTED_PENDING_ACTION_BYTES: usize =
    transaction_circuit::smallwood_poseidon2_v8_security::SMALLWOOD_POSEIDON2_V8_MAX_PENDING_ACTION_BYTES
        as usize;
/// Compatibility name for callers that previously interpreted "action" as
/// the RPC `public_args` carrier. New code should use the explicit name above.
pub const SMALLWOOD_POSEIDON2_V8_WALLET_MAX_ACTION_BYTES: usize =
    SMALLWOOD_POSEIDON2_V8_WALLET_MAX_INLINE_ARGS_BYTES;

const PRODUCTION_DISABLED: &str = "SmallWood Poseidon2 V8 production capability is disabled";
const POSEIDON2_V8_MAX_FIELD_SCALAR_HEIGHT: u64 = (1u64 << 63) - 1;

pub(crate) fn poseidon2_v8_production_context_at(
    height: u64,
) -> Result<Poseidon2ProductionExpectedContext, WalletError> {
    let capability = protocol_versioning::smallwood_poseidon2_production_capability()
        .ok_or(WalletError::InvalidState(PRODUCTION_DISABLED))?;
    let source_digest = *SmallwoodPoseidon2V8SourceRelationFactory.expected_relation_digest();
    if !capability.active_at(height)
        || capability.binding()
            != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING
        || capability.network_id() != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID
        || capability.relation_digest() != source_digest
        || capability.family_id() != POSEIDON2_PRODUCTION_TRANSPORT_FAMILY_ID
        || capability.action_id() != POSEIDON2_PRODUCTION_TRANSPORT_ACTION_ID
        || capability.backend_id() != POSEIDON2_PRODUCTION_TRANSPORT_BACKEND_ID
        || capability.proof_profile_id() != POSEIDON2_PRODUCTION_SMZ9_TRANSPORT_PROFILE_ID
        || capability.domain_set() != POSEIDON2_PRODUCTION_TRANSPORT_DOMAIN_SET
        || capability.activation_height() > POSEIDON2_V8_MAX_FIELD_SCALAR_HEIGHT
        || capability
            .stablecoin_genesis_root()
            .into_iter()
            .any(|limb| limb >= transaction_circuit::constants::FIELD_MODULUS_U64)
        || capability
            .note_genesis_root()
            .into_iter()
            .any(|limb| limb >= transaction_circuit::constants::FIELD_MODULUS_U64)
        || capability.note_genesis_root()
            != protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NOTE_GENESIS_ROOT
    {
        return Err(WalletError::InvalidState(
            "SmallWood Poseidon2 V8 production capability tuple is invalid or inactive",
        ));
    }
    Poseidon2ProductionExpectedContext::new(capability.network_id(), source_digest).map_err(
        |error| {
            WalletError::Serialization(format!(
                "SmallWood Poseidon2 V8 production context rejected: {error}"
            ))
        },
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Poseidon2V8Nullifier56([u8; 56]);

impl Poseidon2V8Nullifier56 {
    fn from_canonical_limbs(limbs: [u64; 7]) -> Self {
        let mut bytes = [0u8; 56];
        for (index, limb) in limbs.into_iter().enumerate() {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&limb.to_le_bytes());
        }
        Self(bytes)
    }

    #[cfg(test)]
    const fn as_bytes(&self) -> &[u8; 56] {
        &self.0
    }
}

/// Proof material after the source compiler has discarded its packed witness.
/// No private witness or caller-supplied nullifier metadata can enter this
/// structure.
struct Poseidon2V8ProofMaterial {
    verifier_input: SmallwoodPoseidon2V8VerifierInput,
    proof_bytes: Vec<u8>,
    projected_max_proof_bytes: usize,
    projected_inline_args_bytes: usize,
    measured_inline_args_bytes: usize,
}

/// One locally verified leaf ready for the existing RPC transport helper.
/// The proof exists only as a byte range inside `native_leaf`.
struct PreparedPoseidon2V8Submission {
    expected: Poseidon2ProductionExpectedContext,
    native_leaf: Vec<u8>,
    proof_offset: usize,
    proof_len: usize,
    inline_args_bytes: usize,
    derived_new_nullifiers: Vec<Poseidon2V8Nullifier56>,
}

impl PreparedPoseidon2V8Submission {
    fn proof_bytes(&self) -> &[u8] {
        &self.native_leaf[self.proof_offset..self.proof_offset + self.proof_len]
    }
}

trait Poseidon2V8WalletProofEngine {
    fn expected_relation_digest(&self) -> [u8; 48];

    fn prove(
        &self,
        statement: &SmallwoodPoseidon2V8PublicStatement,
        witness: &SmallwoodPoseidon2V8Witness,
        network_id: u32,
    ) -> Result<Poseidon2V8ProofMaterial, WalletError>;

    fn verify(
        &self,
        input: &SmallwoodPoseidon2V8VerifierInput,
        proof_bytes: &[u8],
    ) -> Result<(), WalletError>;
}

#[derive(Clone, Copy, Debug, Default)]
struct SourcePoseidon2V8WalletProofEngine;

impl Poseidon2V8WalletProofEngine for SourcePoseidon2V8WalletProofEngine {
    fn expected_relation_digest(&self) -> [u8; 48] {
        *SmallwoodPoseidon2V8SourceRelationFactory.expected_relation_digest()
    }

    fn prove(
        &self,
        statement: &SmallwoodPoseidon2V8PublicStatement,
        witness: &SmallwoodPoseidon2V8Witness,
        network_id: u32,
    ) -> Result<Poseidon2V8ProofMaterial, WalletError> {
        let candidate =
            compile_and_prove_smallwood_poseidon2_v8_candidate(statement, witness, network_id)
                .map_err(wallet_proof_error)?;
        let verifier_input = candidate.verifier_input().clone();
        let projected_max_proof_bytes = candidate.projected_max_proof_bytes();
        let projected_inline_args_bytes = candidate.projected_action_bytes();
        let measured_inline_args_bytes = candidate.measured_action_bytes();
        let proof_bytes = candidate.into_proof_bytes();
        Ok(Poseidon2V8ProofMaterial {
            verifier_input,
            proof_bytes,
            projected_max_proof_bytes,
            projected_inline_args_bytes,
            measured_inline_args_bytes,
        })
    }

    fn verify(
        &self,
        input: &SmallwoodPoseidon2V8VerifierInput,
        proof_bytes: &[u8],
    ) -> Result<(), WalletError> {
        verify_smallwood_poseidon2_v8_candidate(input, proof_bytes).map_err(wallet_proof_error)
    }
}

fn wallet_proof_error(error: transaction_circuit::TransactionCircuitError) -> WalletError {
    WalletError::Serialization(format!(
        "SmallWood Poseidon2 V8 local proof rejected: {error}"
    ))
}

fn wallet_surface_error(error: impl core::fmt::Debug) -> WalletError {
    WalletError::Serialization(format!(
        "SmallWood Poseidon2 V8 wallet surface rejected: {error:?}"
    ))
}

fn derive_statement_nullifiers(
    statement: &SmallwoodPoseidon2V8PublicStatement,
) -> Vec<Poseidon2V8Nullifier56> {
    statement
        .input_flags
        .into_iter()
        .zip(statement.nullifiers)
        .filter_map(|(active, limbs)| {
            active.then(|| Poseidon2V8Nullifier56::from_canonical_limbs(limbs))
        })
        .collect()
}

fn prepare_poseidon2_v8_with_engine(
    expected: Poseidon2ProductionExpectedContext,
    statement: SmallwoodPoseidon2V8PublicStatement,
    witness: SmallwoodPoseidon2V8Witness,
    inline_ciphertexts: SmallwoodPoseidon2V8InlineCiphertexts,
    engine: &impl Poseidon2V8WalletProofEngine,
) -> Result<PreparedPoseidon2V8Submission, WalletError> {
    if statement.value_balance_sign || statement.value_balance_magnitude != 0 {
        return Err(WalletError::Serialization(
            "SmallWood Poseidon2 V8 production requires zero value_balance because no transparent pool exists"
                .to_owned(),
        ));
    }
    statement
        .validate_public_structure()
        .map_err(wallet_surface_error)?;
    witness
        .validate_against_statement(&statement)
        .map_err(wallet_surface_error)?;
    inline_ciphertexts
        .validate_against_statement(&statement)
        .map_err(wallet_surface_error)?;

    let source_relation_digest = engine.expected_relation_digest();
    if expected.relation_digest() != source_relation_digest {
        return Err(WalletError::Serialization(
            "SmallWood Poseidon2 V8 network context relation digest does not match the source compiler"
                .to_owned(),
        ));
    }

    let public_values = statement.to_public_words();
    let relation_balance_binding = statement
        .expected_action_intent()
        .map_err(wallet_surface_error)?;
    let material = engine.prove(&statement, &witness, expected.network_id())?;

    if material.verifier_input.network_id != expected.network_id() {
        return Err(WalletError::Serialization(
            "SmallWood Poseidon2 V8 prover returned a different network context".to_owned(),
        ));
    }
    if material.verifier_input.relation_digest != source_relation_digest {
        return Err(WalletError::Serialization(
            "SmallWood Poseidon2 V8 prover returned a different relation digest".to_owned(),
        ));
    }
    if material.verifier_input.public_values != public_values {
        return Err(WalletError::Serialization(
            "SmallWood Poseidon2 V8 prover returned a different public statement".to_owned(),
        ));
    }
    if material.verifier_input.relation_balance_binding != relation_balance_binding {
        return Err(WalletError::Serialization(
            "SmallWood Poseidon2 V8 prover returned a different relation binding".to_owned(),
        ));
    }
    if material.proof_bytes.len() < POSEIDON2_PRODUCTION_SMZ9_INNER_PROOF_MAGIC.len()
        || material.proof_bytes[..POSEIDON2_PRODUCTION_SMZ9_INNER_PROOF_MAGIC.len()]
            != POSEIDON2_PRODUCTION_SMZ9_INNER_PROOF_MAGIC
    {
        return Err(WalletError::Serialization(
            "SmallWood Poseidon2 V8 wallet accepts only the fresh SMZ9 proof wire".to_owned(),
        ));
    }
    let recomputed_projected_inline_args_bytes = smallwood_poseidon2_v8_exact_action_bytes(
        &public_values,
        material.projected_max_proof_bytes,
    )
    .map_err(wallet_proof_error)?;
    if material.projected_inline_args_bytes != recomputed_projected_inline_args_bytes {
        return Err(WalletError::Serialization(format!(
            "SmallWood Poseidon2 V8 inline-argument projection mismatch: reported={} exact={}",
            material.projected_inline_args_bytes, recomputed_projected_inline_args_bytes
        )));
    }
    if material.projected_inline_args_bytes > SMALLWOOD_POSEIDON2_V8_WALLET_MAX_INLINE_ARGS_BYTES {
        return Err(WalletError::Serialization(format!(
            "SmallWood Poseidon2 V8 compiler projects {} inline-argument bytes above the {} byte wallet cap",
            material.projected_inline_args_bytes,
            SMALLWOOD_POSEIDON2_V8_WALLET_MAX_INLINE_ARGS_BYTES
        )));
    }
    if material.measured_inline_args_bytes > material.projected_inline_args_bytes {
        return Err(WalletError::Serialization(format!(
            "SmallWood Poseidon2 V8 measured inline-argument bytes {} exceed compiler projection {}",
            material.measured_inline_args_bytes, material.projected_inline_args_bytes
        )));
    }

    // Reconstruct and run the verifier independently after proving. The RPC
    // helper is not reached unless this succeeds.
    engine.verify(&material.verifier_input, &material.proof_bytes)?;

    let ciphertext_refs = [
        inline_ciphertexts.ciphertexts[0].as_ref(),
        inline_ciphertexts.ciphertexts[1].as_ref(),
    ];
    let native_leaf = encode_poseidon2_production_smz9_native_leaf(
        expected,
        &public_values,
        &relation_balance_binding,
        ciphertext_refs,
        &material.proof_bytes,
    )
    .map_err(|error| {
        WalletError::Serialization(format!(
            "SmallWood Poseidon2 V8 native leaf construction rejected: {error}"
        ))
    })?;

    let decoded = decode_poseidon2_production_smz9_native_leaf_exact(expected, &native_leaf)
        .map_err(|error| {
            WalletError::Serialization(format!(
                "SmallWood Poseidon2 V8 native leaf readback rejected: {error}"
            ))
        })?;
    if decoded.proof() != material.proof_bytes.as_slice() {
        return Err(WalletError::Serialization(
            "SmallWood Poseidon2 V8 transport changed the locally verified proof bytes".to_owned(),
        ));
    }

    let envelope =
        encode_poseidon2_production_smz9_envelope(expected, &native_leaf).map_err(|error| {
            WalletError::Serialization(format!(
                "SmallWood Poseidon2 V8 envelope construction rejected: {error}"
            ))
        })?;
    let inline_args =
        encode_poseidon2_production_smz9_inline_args(expected, &envelope).map_err(|error| {
            WalletError::Serialization(format!(
                "SmallWood Poseidon2 V8 SCALE action construction rejected: {error}"
            ))
        })?;
    let recomputed_inline_args_bytes =
        smallwood_poseidon2_v8_exact_action_bytes(&public_values, material.proof_bytes.len())
            .map_err(wallet_proof_error)?;
    if inline_args.len() != recomputed_inline_args_bytes
        || inline_args.len() != material.measured_inline_args_bytes
    {
        return Err(WalletError::Serialization(format!(
            "SmallWood Poseidon2 V8 inline-argument byte accounting mismatch: wire={} compiler={} measured={}",
            inline_args.len(),
            recomputed_inline_args_bytes,
            material.measured_inline_args_bytes
        )));
    }
    if inline_args.len() > SMALLWOOD_POSEIDON2_V8_WALLET_MAX_INLINE_ARGS_BYTES {
        return Err(WalletError::Serialization(format!(
            "SmallWood Poseidon2 V8 inline arguments have {} bytes above the {} byte wallet cap",
            inline_args.len(),
            SMALLWOOD_POSEIDON2_V8_WALLET_MAX_INLINE_ARGS_BYTES
        )));
    }

    let proof_len = material.proof_bytes.len();
    let proof_offset =
        native_leaf
            .len()
            .checked_sub(proof_len)
            .ok_or(WalletError::Serialization(
                "SmallWood Poseidon2 V8 proof range underflow".to_owned(),
            ))?;
    let derived_new_nullifiers = derive_statement_nullifiers(&statement);

    Ok(PreparedPoseidon2V8Submission {
        expected,
        native_leaf,
        proof_offset,
        proof_len,
        inline_args_bytes: inline_args.len(),
        derived_new_nullifiers,
    })
}

impl NodeRpcClient {
    /// Build from wallet-owned notes at the one canonical mirrored anchor,
    /// compile, prove, locally verify, package, and submit one V8 transaction.
    /// There is no caller-supplied witness and no legacy prover fallback.
    pub async fn prove_verify_and_submit_poseidon2_v8(
        &self,
        store: &WalletStore,
        output_address_indices: [u32; 2],
    ) -> Result<ActionId48, WalletError> {
        let authority = self
            .fresh_submission_authority(
                protocol_shielded_pool::family::ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
            )
            .await?;
        authority.ensure_route(
            protocol_shielded_pool::family::ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
            protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING,
        )?;
        let metadata = self.get_chain_metadata().await?;
        if authority.genesis_hash() != metadata.genesis_hash {
            return Err(WalletError::InvalidState(
                "SmallWood Poseidon2 V8 authority genesis changed before proving",
            ));
        }
        let mut rng = rand::rngs::OsRng;
        let spend = crate::poseidon2_v8_coinbase::build_poseidon2_v8_wallet_self_spend(
            store,
            output_address_indices,
            &mut rng,
        )?;
        if spend.tip.height != metadata.block_number || spend.tip.block_hash != metadata.block_hash
        {
            return Err(WalletError::InvalidState(
                "SmallWood Poseidon2 V8 wallet mirror is not at the canonical node tip",
            ));
        }
        let next_height = metadata
            .block_number
            .checked_add(1)
            .ok_or(WalletError::InvalidState(
                "SmallWood Poseidon2 V8 candidate height overflow",
            ))?;
        if authority.height() != next_height {
            return Err(WalletError::InvalidState(
                "SmallWood Poseidon2 V8 authority height changed before proving",
            ));
        }
        self.prove_verify_and_submit_poseidon2_v8_material_at(authority, spend.material)
            .await
    }

    /// Prove one already wallet-constructed V8 relation tuple. This private
    /// seam keeps witness material out of the production caller surface.
    async fn prove_verify_and_submit_poseidon2_v8_material_at(
        &self,
        authority: FreshTransactionProofAuthority,
        material: crate::poseidon2_v8_coinbase::Poseidon2V8SpendMaterial,
    ) -> Result<ActionId48, WalletError> {
        let crate::poseidon2_v8_coinbase::Poseidon2V8SpendMaterial {
            statement,
            witness,
            inline_ciphertexts,
        } = material;

        // This method accepts no outer nullifier metadata. The 56-byte
        // nullifiers are derived from the two seven-limb public statement
        // slots; the RPC helper emits an empty legacy 48-byte list.
        let expected = poseidon2_v8_production_context_at(authority.height())?;
        let prepared = tokio::task::spawn_blocking(move || {
            authority.ensure_route(
                protocol_shielded_pool::family::ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
                protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING,
            )?;
            let expected_at_proving = poseidon2_v8_production_context_at(authority.height())?;
            if expected_at_proving != expected {
                return Err(WalletError::InvalidState(
                    "SmallWood Poseidon2 V8 production capability changed during proving",
                ));
            }
            prepare_poseidon2_v8_with_engine(
                expected,
                statement,
                witness,
                inline_ciphertexts,
                &SourcePoseidon2V8WalletProofEngine,
            )
        })
        .await
        .map_err(|error| {
            WalletError::InvalidState(if error.is_cancelled() {
                "SmallWood Poseidon2 V8 proving task was cancelled"
            } else {
                "SmallWood Poseidon2 V8 proving task panicked"
            })
        })??;

        // `PreparedPoseidon2V8Submission` has no witness. Its exact native leaf
        // contains the only owned copy of the verified SMZ9 proof.
        debug_assert_eq!(prepared.expected, expected);
        debug_assert_eq!(prepared.proof_bytes().len(), prepared.proof_len);
        debug_assert!(
            prepared.inline_args_bytes <= SMALLWOOD_POSEIDON2_V8_WALLET_MAX_INLINE_ARGS_BYTES
        );
        debug_assert!(prepared.derived_new_nullifiers.len() <= 2);
        self.submit_poseidon2_production_native_leaf(&prepared.native_leaf)
            .await
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::*;
    use transaction_circuit::smallwood_poseidon2_v8_types::{
        smallwood_poseidon2_v8_ciphertext_commitment, SmallwoodPoseidon2V8Ciphertext,
        SmallwoodPoseidon2V8InputWitness, SmallwoodPoseidon2V8NoteOpening,
        SmallwoodPoseidon2V8OutputWitness,
    };

    struct FixtureEngine {
        relation_digest: [u8; 48],
        proof_bytes: Vec<u8>,
        returned_network: Option<u32>,
        returned_relation_digest: Option<[u8; 48]>,
        projected_max_proof_override: Option<usize>,
        prove_calls: Cell<usize>,
        verify_calls: Cell<usize>,
    }

    impl FixtureEngine {
        fn new(proof_len: usize) -> Self {
            let mut proof_bytes = vec![0xa5; proof_len];
            proof_bytes[..4].copy_from_slice(b"SMZ9");
            Self {
                relation_digest: [0x42; 48],
                proof_bytes,
                returned_network: None,
                returned_relation_digest: None,
                projected_max_proof_override: None,
                prove_calls: Cell::new(0),
                verify_calls: Cell::new(0),
            }
        }
    }

    impl Poseidon2V8WalletProofEngine for FixtureEngine {
        fn expected_relation_digest(&self) -> [u8; 48] {
            self.relation_digest
        }

        fn prove(
            &self,
            statement: &SmallwoodPoseidon2V8PublicStatement,
            _witness: &SmallwoodPoseidon2V8Witness,
            network_id: u32,
        ) -> Result<Poseidon2V8ProofMaterial, WalletError> {
            self.prove_calls.set(self.prove_calls.get() + 1);
            let public_values = statement.to_public_words();
            let projected_max_proof_bytes = self.projected_max_proof_override.unwrap_or(
                transaction_circuit::smallwood_poseidon2_v8_security::SMALLWOOD_POSEIDON2_V8_PROJECTED_INNER_PROOF_BYTES,
            );
            let projected_inline_args_bytes = smallwood_poseidon2_v8_exact_action_bytes(
                &public_values,
                projected_max_proof_bytes,
            )
            .map_err(wallet_proof_error)?;
            let measured_inline_args_bytes =
                smallwood_poseidon2_v8_exact_action_bytes(&public_values, self.proof_bytes.len())
                    .map_err(wallet_proof_error)?;
            Ok(Poseidon2V8ProofMaterial {
                verifier_input: SmallwoodPoseidon2V8VerifierInput {
                    network_id: self.returned_network.unwrap_or(network_id),
                    relation_digest: self
                        .returned_relation_digest
                        .unwrap_or(self.relation_digest),
                    public_values,
                    relation_balance_binding: statement
                        .expected_action_intent()
                        .map_err(wallet_surface_error)?,
                },
                proof_bytes: self.proof_bytes.clone(),
                projected_max_proof_bytes,
                projected_inline_args_bytes,
                measured_inline_args_bytes,
            })
        }

        fn verify(
            &self,
            input: &SmallwoodPoseidon2V8VerifierInput,
            proof_bytes: &[u8],
        ) -> Result<(), WalletError> {
            self.verify_calls.set(self.verify_calls.get() + 1);
            if input.relation_digest != self.relation_digest
                || proof_bytes != self.proof_bytes.as_slice()
            {
                return Err(WalletError::Serialization(
                    "fixture local verifier rejected".to_owned(),
                ));
            }
            Ok(())
        }
    }

    fn context() -> Poseidon2ProductionExpectedContext {
        Poseidon2ProductionExpectedContext::new(17, [0x42; 48]).unwrap()
    }

    fn active_zero_value_note() -> SmallwoodPoseidon2V8NoteOpening {
        SmallwoodPoseidon2V8NoteOpening {
            value: 0,
            asset_id: 0,
            recipient_key: [0; 4],
            authorization_key: [0; 4],
            rho: [0; 4],
            randomness: [0; 4],
        }
    }

    fn two_output_fixture() -> (
        SmallwoodPoseidon2V8PublicStatement,
        SmallwoodPoseidon2V8Witness,
        SmallwoodPoseidon2V8InlineCiphertexts,
    ) {
        let ciphertexts: [SmallwoodPoseidon2V8Ciphertext; 2] = [[0x41; 2_147], [0x42; 2_147]];
        let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
        statement.output_flags = [true, true];
        statement.commitments = [[1; 7], [2; 7]];
        statement.ciphertext_commitments = [
            smallwood_poseidon2_v8_ciphertext_commitment(&ciphertexts[0]),
            smallwood_poseidon2_v8_ciphertext_commitment(&ciphertexts[1]),
        ];

        let output = |_slot: usize| SmallwoodPoseidon2V8OutputWitness {
            active: true,
            note: active_zero_value_note(),
            balance_slot_selectors: [true, false, false, false],
        };
        let witness = SmallwoodPoseidon2V8Witness {
            outputs: [output(0), output(1)],
            ..Default::default()
        };
        let inline = SmallwoodPoseidon2V8InlineCiphertexts {
            ciphertexts: [Some(ciphertexts[0]), Some(ciphertexts[1])],
        };
        (statement, witness, inline)
    }

    fn one_input_fixture() -> (
        SmallwoodPoseidon2V8PublicStatement,
        SmallwoodPoseidon2V8Witness,
        SmallwoodPoseidon2V8InlineCiphertexts,
    ) {
        let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
        statement.input_flags[0] = true;
        statement.nullifiers[0] = [
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            0x2122_2324_2526_2728,
            0x3132_3334_3536_3738,
            0x4142_4344_4546_4748,
            0x5152_5354_5556_5758,
            0x6162_6364_6566_6768,
        ];
        let witness = SmallwoodPoseidon2V8Witness {
            inputs: [
                SmallwoodPoseidon2V8InputWitness {
                    active: true,
                    spend_key: [1, 2, 3, 4],
                    note: active_zero_value_note(),
                    position: 0,
                    siblings: [[0; 7]; 32],
                    balance_slot_selectors: [true, false, false, false],
                },
                SmallwoodPoseidon2V8InputWitness::ZERO,
            ],
            ..Default::default()
        };
        (
            statement,
            witness,
            SmallwoodPoseidon2V8InlineCiphertexts::default(),
        )
    }

    #[test]
    fn maximum_shape_keeps_one_smz9_proof_and_exact_128297_byte_inline_args() {
        let (statement, witness, ciphertexts) = two_output_fixture();
        let engine = FixtureEngine::new(122_863);
        let prepared =
            prepare_poseidon2_v8_with_engine(context(), statement, witness, ciphertexts, &engine)
                .unwrap();
        assert_eq!(prepared.inline_args_bytes, 128_297);
        assert_eq!(
            prepared.inline_args_bytes,
            SMALLWOOD_POSEIDON2_V8_WALLET_MAX_INLINE_ARGS_BYTES
        );
        assert_eq!(
            SMALLWOOD_POSEIDON2_V8_PROJECTED_PENDING_ACTION_BYTES,
            128_522
        );
        assert_eq!(&prepared.native_leaf[..8], b"HGV8TX02");
        assert_eq!(prepared.native_leaf[19], 6);
        assert_eq!(prepared.proof_bytes(), engine.proof_bytes.as_slice());
        assert_eq!(engine.prove_calls.get(), 1);
        assert_eq!(engine.verify_calls.get(), 1);
        assert!(prepared.derived_new_nullifiers.is_empty());
        assert!(core::mem::size_of_val(&prepared) < prepared.native_leaf.len());
    }

    #[test]
    fn nullifiers_are_derived_as_exact_little_endian_statement_limbs() {
        let (statement, witness, ciphertexts) = one_input_fixture();
        // Production SMZ9 proofs are well above the SCALE four-byte compact
        // length threshold used by the frozen 1,140-byte action formula.
        let engine = FixtureEngine::new(20_000);
        let prepared =
            prepare_poseidon2_v8_with_engine(context(), statement, witness, ciphertexts, &engine)
                .unwrap();
        assert_eq!(prepared.derived_new_nullifiers.len(), 1);
        let expected = statement.nullifiers[0]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            prepared.derived_new_nullifiers[0].as_bytes(),
            expected.as_slice()
        );
    }

    #[test]
    fn ciphertext_mismatch_rejects_before_proving() {
        let (statement, witness, mut ciphertexts) = two_output_fixture();
        ciphertexts.ciphertexts[1].as_mut().unwrap()[0] ^= 1;
        let engine = FixtureEngine::new(64);
        assert!(prepare_poseidon2_v8_with_engine(
            context(),
            statement,
            witness,
            ciphertexts,
            &engine,
        )
        .is_err());
        assert_eq!(engine.prove_calls.get(), 0);
        assert_eq!(engine.verify_calls.get(), 0);
    }

    #[test]
    fn nonzero_or_signed_value_balance_rejects_before_proving() {
        for (sign, magnitude) in [(false, 1), (true, 1)] {
            let (mut statement, witness, ciphertexts) = two_output_fixture();
            statement.value_balance_sign = sign;
            statement.value_balance_magnitude = magnitude;
            let engine = FixtureEngine::new(64);
            let error = match prepare_poseidon2_v8_with_engine(
                context(),
                statement,
                witness,
                ciphertexts,
                &engine,
            ) {
                Ok(_) => panic!("production wallet accepted a transparent-pool value balance"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("zero value_balance"));
            assert_eq!(engine.prove_calls.get(), 0);
            assert_eq!(engine.verify_calls.get(), 0);
        }
    }

    #[test]
    fn context_and_prover_network_or_relation_mismatches_reject() {
        let (statement, witness, ciphertexts) = one_input_fixture();
        let mut wrong_source = FixtureEngine::new(64);
        wrong_source.relation_digest = [0x43; 48];
        assert!(prepare_poseidon2_v8_with_engine(
            context(),
            statement,
            witness,
            ciphertexts,
            &wrong_source,
        )
        .is_err());
        assert_eq!(wrong_source.prove_calls.get(), 0);

        let (statement, witness, ciphertexts) = one_input_fixture();
        let mut wrong_network = FixtureEngine::new(64);
        wrong_network.returned_network = Some(18);
        assert!(prepare_poseidon2_v8_with_engine(
            context(),
            statement,
            witness,
            ciphertexts,
            &wrong_network,
        )
        .is_err());
        assert_eq!(wrong_network.verify_calls.get(), 0);

        let (statement, witness, ciphertexts) = one_input_fixture();
        let mut wrong_proof_relation = FixtureEngine::new(64);
        wrong_proof_relation.returned_relation_digest = Some([0x44; 48]);
        assert!(prepare_poseidon2_v8_with_engine(
            context(),
            statement,
            witness,
            ciphertexts,
            &wrong_proof_relation,
        )
        .is_err());
        assert_eq!(wrong_proof_relation.verify_calls.get(), 0);
    }

    #[test]
    fn compiler_inline_args_projection_above_128297_rejects_before_local_verify_or_rpc() {
        let (statement, witness, ciphertexts) = two_output_fixture();
        let mut engine = FixtureEngine::new(122_863);
        engine.projected_max_proof_override = Some(122_864);
        assert!(prepare_poseidon2_v8_with_engine(
            context(),
            statement,
            witness,
            ciphertexts,
            &engine,
        )
        .is_err());
        assert_eq!(engine.prove_calls.get(), 1);
        assert_eq!(engine.verify_calls.get(), 0);
    }

    #[test]
    fn frozen_smz8_proof_rejects_before_local_verify_or_rpc_packaging() {
        let (statement, witness, ciphertexts) = two_output_fixture();
        let mut engine = FixtureEngine::new(122_863);
        engine.proof_bytes[..4].copy_from_slice(b"SMZ8");
        let error = match prepare_poseidon2_v8_with_engine(
            context(),
            statement,
            witness,
            ciphertexts,
            &engine,
        ) {
            Ok(_) => panic!("frozen SMZ8 proof entered the SMZ9 wallet transport"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("SMZ9 proof wire"));
        assert_eq!(engine.prove_calls.get(), 1);
        assert_eq!(engine.verify_calls.get(), 0);
    }

    #[test]
    fn sole_production_capability_remains_fail_closed() {
        assert!(!protocol_versioning::smallwood_poseidon2_production_authorized());
        assert!(matches!(
            poseidon2_v8_production_context_at(0),
            Err(WalletError::InvalidState(PRODUCTION_DISABLED))
        ));
    }
}
