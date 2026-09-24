//! Wallet-side preparation for the still-unallocated HX512 inline action.
//!
//! The wallet owns one canonical raw action and moves it into the JSON-RPC
//! Base64 field without constructing a second proof object.  The route fields
//! are projected from the exact first 186 statement bytes.  This module does
//! not allocate or authorize a route, action identity, response identity, or
//! production proof cap.

use base64::Engine;
use protocol_shielded_pool::hx512_inline_transport::{
    project_hx512_inline_identity, Hx512InlineAction, Hx512InlineAdmissionVerifier,
    Hx512InlineTransportContext, Hx512InlineTransportError,
};
use serde::Serialize;

use crate::WalletError;

pub const HX512_WALLET_ROUTE_ALLOCATED: bool = false;
pub const HX512_WALLET_PRODUCTION_SUBMISSION_ENABLED: bool = false;
pub const HX512_WALLET_LEGACY_ACTION_ID48_RESPONSE_ALLOWED: bool = false;

/// Exact legacy-shaped RPC request used only to demonstrate the future raw
/// byte carriage boundary.  All fields are private so callers cannot add
/// legacy nullifiers, sidecars, authorization objects, or auxiliary validity
/// data after canonical preparation.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Hx512CandidateRpcRequest {
    binding_circuit: u16,
    binding_crypto: u16,
    family_id: u16,
    action_id: u16,
    object_refs: Vec<serde_json::Value>,
    new_nullifiers: Vec<String>,
    public_args: String,
    authorization_proof: Option<String>,
    authorization_signatures: Vec<serde_json::Value>,
    aux_data: Option<String>,
}

impl Hx512CandidateRpcRequest {
    pub const fn binding_circuit(&self) -> u16 {
        self.binding_circuit
    }

    pub const fn binding_crypto(&self) -> u16 {
        self.binding_crypto
    }

    pub const fn family_id(&self) -> u16 {
        self.family_id
    }

    pub const fn action_id(&self) -> u16 {
        self.action_id
    }

    pub fn canonical_action_bytes(&self) -> Result<Vec<u8>, WalletError> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&self.public_args)
            .map_err(|error| {
                WalletError::Serialization(format!("invalid prepared HX512 Base64 action: {error}"))
            })?;
        if base64::engine::general_purpose::STANDARD.encode(&decoded) != self.public_args {
            return Err(WalletError::Serialization(
                "prepared HX512 action uses noncanonical Base64".to_owned(),
            ));
        }
        Ok(decoded)
    }
}

fn hx512_transport_error(error: Hx512InlineTransportError) -> WalletError {
    WalletError::Serialization(format!("invalid unallocated HX512 inline action: {error}"))
}

/// Consume one already-framed action and prepare the exact RPC request.
///
/// `raw_action` is moved into the admitted carrier.  Its statement, proof,
/// and ciphertext bytes are never decoded into a second owned representation;
/// Base64 is the sole outer RPC encoding.
pub fn prepare_hx512_candidate_rpc_request<V: Hx512InlineAdmissionVerifier + ?Sized>(
    context: Hx512InlineTransportContext<'_>,
    raw_action: Vec<u8>,
    verifier: &V,
) -> Result<Hx512CandidateRpcRequest, WalletError> {
    let identity = project_hx512_inline_identity(context.expected_identity());
    let action = Hx512InlineAction::admit_owned(context, raw_action, verifier)
        .map_err(hx512_transport_error)?;
    let public_args = base64::engine::general_purpose::STANDARD.encode(action.into_bytes());
    Ok(Hx512CandidateRpcRequest {
        binding_circuit: identity.circuit_version,
        binding_crypto: identity.crypto_suite,
        family_id: identity.family_id,
        action_id: identity.action_id,
        object_refs: Vec::new(),
        new_nullifiers: Vec::new(),
        public_args,
        authorization_proof: None,
        authorization_signatures: Vec::new(),
        aux_data: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_shielded_pool::hx512_inline_transport::{
        HX512_INLINE_ACTIVITY_MASK_OFFSET, HX512_INLINE_CIPHERTEXT_BYTES,
        HX512_INLINE_IDENTITY_BYTES, HX512_INLINE_PREFIX_BYTES, HX512_INLINE_STATEMENT_BYTES,
    };

    struct ExactVerifier {
        statement: [u8; HX512_INLINE_STATEMENT_BYTES],
        proof: Vec<u8>,
        ciphertexts: [[u8; HX512_INLINE_CIPHERTEXT_BYTES]; 2],
    }

    impl Hx512InlineAdmissionVerifier for ExactVerifier {
        fn validate_statement(&self, statement: &[u8; HX512_INLINE_STATEMENT_BYTES]) -> bool {
            statement == &self.statement
        }

        fn validate_proof(
            &self,
            statement: &[u8; HX512_INLINE_STATEMENT_BYTES],
            proof: &[u8],
        ) -> bool {
            statement == &self.statement && proof == self.proof
        }

        fn validate_ciphertext(
            &self,
            output_slot: usize,
            statement: &[u8; HX512_INLINE_STATEMENT_BYTES],
            ciphertext: &[u8; HX512_INLINE_CIPHERTEXT_BYTES],
        ) -> bool {
            statement == &self.statement && self.ciphertexts.get(output_slot) == Some(ciphertext)
        }
    }

    fn fixture() -> ([u8; HX512_INLINE_IDENTITY_BYTES], Vec<u8>, ExactVerifier) {
        let mut identity = [0u8; HX512_INLINE_IDENTITY_BYTES];
        identity[..8].copy_from_slice(b"HXTEST01");
        identity[8..10].copy_from_slice(&1u16.to_be_bytes());
        identity[10..12].copy_from_slice(&65_000u16.to_be_bytes());
        identity[12..14].copy_from_slice(&65_001u16.to_be_bytes());
        identity[14..16].copy_from_slice(&65_002u16.to_be_bytes());
        identity[16..18].copy_from_slice(&65_003u16.to_be_bytes());
        identity[18] = 7;
        identity[19] = 8;
        identity[20..22].copy_from_slice(&9u16.to_be_bytes());
        identity[22..26].copy_from_slice(&41u32.to_be_bytes());
        identity[26..58].fill(0x31);
        identity[58..122].fill(0x32);
        identity[122..186].fill(0x33);

        let mut statement = [0u8; HX512_INLINE_STATEMENT_BYTES];
        statement[..HX512_INLINE_IDENTITY_BYTES].copy_from_slice(&identity);
        statement[HX512_INLINE_ACTIVITY_MASK_OFFSET] = 0x0c;
        let proof = vec![0xa5; 31];
        let ciphertexts = [[0x41; HX512_INLINE_CIPHERTEXT_BYTES]; 2];
        let mut raw = Vec::new();
        raw.extend_from_slice(&statement);
        raw.extend_from_slice(&(proof.len() as u32).to_be_bytes());
        raw.extend_from_slice(&proof);
        raw.extend_from_slice(&ciphertexts[0]);
        raw.extend_from_slice(&ciphertexts[1]);
        let verifier = ExactVerifier {
            statement,
            proof,
            ciphertexts,
        };
        (identity, raw, verifier)
    }

    #[test]
    fn request_keeps_the_exact_raw_action_and_projects_its_inner_route() {
        let (identity, raw, verifier) = fixture();
        let context = Hx512InlineTransportContext::new(&identity, 64, 315).unwrap();
        let request = prepare_hx512_candidate_rpc_request(context, raw.clone(), &verifier).unwrap();
        assert_eq!(request.binding_circuit(), 65_000);
        assert_eq!(request.binding_crypto(), 65_001);
        assert_eq!(request.family_id(), 65_002);
        assert_eq!(request.action_id(), 65_003);
        assert_eq!(request.canonical_action_bytes().unwrap(), raw);

        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["object_refs"], serde_json::json!([]));
        assert_eq!(value["new_nullifiers"], serde_json::json!([]));
        assert_eq!(value["authorization_proof"], serde_json::Value::Null);
        assert_eq!(value["authorization_signatures"], serde_json::json!([]));
        assert_eq!(value["aux_data"], serde_json::Value::Null);
        assert_eq!(
            request.canonical_action_bytes().unwrap().len(),
            HX512_INLINE_PREFIX_BYTES + verifier.proof.len() + 2 * HX512_INLINE_CIPHERTEXT_BYTES
        );
    }

    #[test]
    fn same_length_counterfeit_proof_rejects_before_rpc_preparation() {
        let (identity, mut raw, verifier) = fixture();
        raw[HX512_INLINE_PREFIX_BYTES] ^= 1;
        let context = Hx512InlineTransportContext::new(&identity, 64, 315).unwrap();
        assert!(prepare_hx512_candidate_rpc_request(context, raw, &verifier).is_err());
    }
}
