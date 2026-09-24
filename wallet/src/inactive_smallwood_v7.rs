//! Wallet-side preparation for the inactive V7/Zeta lifecycle route.
//!
//! This module can construct canonical RPC-shaped bytes for source and codec
//! testing, but it deliberately exposes no network submission method. The
//! native node does not list this route as supported.

use base64::Engine;
use protocol_shielded_pool::inactive_smallwood_v7::{
    decode_inactive_smallwood_v7_inline_args, decode_inactive_smallwood_v7_statement_for_context,
    InactiveSmallwoodV7Envelope, InactiveSmallwoodV7ExpectedActivationContext,
    InactiveSmallwoodV7InlineArgs, InactiveSmallwoodV7ProspectiveActionId56,
    INACTIVE_SMALLWOOD_V7_ACTION_ID, INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION,
    INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA, INACTIVE_SMALLWOOD_V7_FAMILY_ID,
    INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS, INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES,
};
use serde::{Deserialize, Serialize};

use crate::WalletError;

pub const INACTIVE_SMALLWOOD_V7_WALLET_SUBMISSION_ENABLED: bool = false;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InactiveSmallwoodV7RpcObjectRef {
    pub family_id: u16,
    pub object_id: String,
    pub expected_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InactiveSmallwoodV7RpcSignature {
    pub key_id: String,
    pub signature_scheme: u16,
    pub signature_bytes: String,
}

/// JSON-compatible shape for the existing `hegemon_submitAction` boundary.
///
/// `new_nullifiers` stays empty because the current RPC field is owned by the
/// 48-byte route. V7 nullifiers remain inside the exact 893-byte statement and
/// are never converted to or from that legacy field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InactiveSmallwoodV7RpcRequest {
    pub binding_circuit: u16,
    pub binding_crypto: u16,
    pub family_id: u16,
    pub action_id: u16,
    pub object_refs: Vec<InactiveSmallwoodV7RpcObjectRef>,
    pub new_nullifiers: Vec<String>,
    pub public_args: String,
    pub authorization_proof: Option<String>,
    pub authorization_signatures: Vec<InactiveSmallwoodV7RpcSignature>,
    pub aux_data: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InactiveSmallwoodV7WalletPackage {
    /// Exact prospective 56-byte action id. It is deliberately not convertible
    /// to the live 48-byte action index while this route remains inactive.
    pub prospective_action_id: InactiveSmallwoodV7ProspectiveActionId56,
    pub canonical_public_args: Vec<u8>,
    pub request: InactiveSmallwoodV7RpcRequest,
}

impl InactiveSmallwoodV7WalletPackage {
    pub fn proof_bytes(&self) -> Result<Vec<u8>, WalletError> {
        let action = decode_inactive_smallwood_v7_inline_args(&self.canonical_public_args)
            .map_err(wallet_codec_error)?;
        Ok(action
            .envelope()
            .map_err(wallet_codec_error)?
            .proof_bytes()
            .to_vec())
    }
}

/// Construct but do not submit an inactive successor action.
pub fn prepare_inactive_smallwood_v7_rpc_request(
    statement: [u8; INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES],
    proof: &[u8],
    ciphertexts: [Vec<u8>; INACTIVE_SMALLWOOD_V7_MAX_OUTPUTS],
    expected_activation: &InactiveSmallwoodV7ExpectedActivationContext,
) -> Result<InactiveSmallwoodV7WalletPackage, WalletError> {
    decode_inactive_smallwood_v7_statement_for_context(&statement, expected_activation)
        .map_err(wallet_codec_error)?;
    let envelope =
        InactiveSmallwoodV7Envelope::from_parts(statement, proof).map_err(wallet_codec_error)?;
    let action =
        InactiveSmallwoodV7InlineArgs::new(envelope, ciphertexts).map_err(wallet_codec_error)?;
    let canonical_public_args = action.canonical_bytes().map_err(wallet_codec_error)?;
    let prospective_action_id = action.prospective_action_id().map_err(wallet_codec_error)?;
    let public_args = base64::engine::general_purpose::STANDARD.encode(&canonical_public_args);
    Ok(InactiveSmallwoodV7WalletPackage {
        prospective_action_id,
        canonical_public_args,
        request: InactiveSmallwoodV7RpcRequest {
            binding_circuit: INACTIVE_SMALLWOOD_V7_CIRCUIT_VERSION,
            binding_crypto: INACTIVE_SMALLWOOD_V7_CRYPTO_SUITE_ZETA,
            family_id: INACTIVE_SMALLWOOD_V7_FAMILY_ID,
            action_id: INACTIVE_SMALLWOOD_V7_ACTION_ID,
            object_refs: Vec::new(),
            new_nullifiers: Vec::new(),
            public_args,
            authorization_proof: None,
            authorization_signatures: Vec::new(),
            aux_data: None,
        },
    })
}

fn wallet_codec_error(error: impl core::fmt::Display) -> WalletError {
    WalletError::Serialization(format!(
        "inactive SmallWood V7 lifecycle preparation rejected: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_shielded_pool::inactive_smallwood_v7::{
        encode_inactive_smallwood_v7_statement, inactive_smallwood_v7_ciphertext_hash,
        InactiveSmallwoodV7ActivationBinding, InactiveSmallwoodV7Anchor56,
        InactiveSmallwoodV7AttestationCommitment56, InactiveSmallwoodV7BalanceTag56,
        InactiveSmallwoodV7ChainId56, InactiveSmallwoodV7CiphertextHash56,
        InactiveSmallwoodV7Commitment56, InactiveSmallwoodV7GenesisId56,
        InactiveSmallwoodV7Nullifier56, InactiveSmallwoodV7OracleCommitment56,
        InactiveSmallwoodV7PolicyHash56, InactiveSmallwoodV7RulesHash56,
        InactiveSmallwoodV7SignedMagnitude, InactiveSmallwoodV7StablecoinBinding,
        InactiveSmallwoodV7Statement,
    };

    fn fixture_context() -> InactiveSmallwoodV7ExpectedActivationContext {
        InactiveSmallwoodV7ExpectedActivationContext {
            network_id: 41,
            chain_id: InactiveSmallwoodV7ChainId56::new([11; 56]),
            genesis_id: InactiveSmallwoodV7GenesisId56::new([12; 56]),
            rules_hash: InactiveSmallwoodV7RulesHash56::new([13; 56]),
        }
    }

    fn fixture_statement() -> [u8; INACTIVE_SMALLWOOD_V7_STATEMENT_BYTES] {
        let mut activation = InactiveSmallwoodV7ActivationBinding::reserved_route();
        let context = fixture_context();
        activation.network_id = context.network_id;
        activation.chain_id = context.chain_id;
        activation.genesis_id = context.genesis_id;
        activation.rules_hash = context.rules_hash;
        encode_inactive_smallwood_v7_statement(&InactiveSmallwoodV7Statement {
            input_flags: [true, false],
            output_flags: [true, false],
            anchor: InactiveSmallwoodV7Anchor56::new([1; 56]),
            nullifiers: [
                InactiveSmallwoodV7Nullifier56::new([2; 56]),
                InactiveSmallwoodV7Nullifier56::ZERO,
            ],
            commitments: [
                InactiveSmallwoodV7Commitment56::new([3; 56]),
                InactiveSmallwoodV7Commitment56::ZERO,
            ],
            ciphertext_hashes: [
                inactive_smallwood_v7_ciphertext_hash(0, &[1, 2, 3]).unwrap(),
                InactiveSmallwoodV7CiphertextHash56::ZERO,
            ],
            ciphertext_sizes: [3, 0],
            balance_asset_ids: [0, 1, 2, 3],
            fee: 7,
            value_balance: InactiveSmallwoodV7SignedMagnitude::default(),
            stablecoin: InactiveSmallwoodV7StablecoinBinding {
                enabled: false,
                asset_id: 0,
                policy_version: 0,
                issuance_delta: InactiveSmallwoodV7SignedMagnitude::default(),
                policy_hash: InactiveSmallwoodV7PolicyHash56::ZERO,
                oracle_commitment: InactiveSmallwoodV7OracleCommitment56::ZERO,
                attestation_commitment: InactiveSmallwoodV7AttestationCommitment56::ZERO,
            },
            balance_tag: InactiveSmallwoodV7BalanceTag56::new([5; 56]),
            activation,
        })
        .unwrap()
    }

    #[test]
    fn wallet_preserves_proof_and_only_prepares_an_inactive_request() {
        let proof = [0xaa, 0xbb, 0xcc, 0xdd];
        let package = prepare_inactive_smallwood_v7_rpc_request(
            fixture_statement(),
            &proof,
            [vec![1, 2, 3], Vec::new()],
            &fixture_context(),
        )
        .unwrap();
        assert_eq!(package.proof_bytes().unwrap().as_slice(), proof.as_slice());
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&package.request.public_args)
                .unwrap(),
            package.canonical_public_args
        );
        assert!(package.request.new_nullifiers.is_empty());
        assert!(!INACTIVE_SMALLWOOD_V7_WALLET_SUBMISSION_ENABLED);
    }
}
