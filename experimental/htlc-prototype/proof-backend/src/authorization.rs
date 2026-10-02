//! Real native ML-DSA-65 authorization for the experimental *host* relation.
//! This signature check is not part of the private SHA component proof.

use htlc_prototype::relation::{AuthorizationError, Authorizer, Digest};
use sha2::{Digest as _, Sha256};
use synthetic_crypto::{
    ml_dsa::{
        MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, ML_DSA_PUBLIC_KEY_LEN, ML_DSA_SIGNATURE_LEN,
    },
    traits::{SigningKey, VerifyKey},
};

pub const AUTHORIZATION_BYTES: usize = ML_DSA_PUBLIC_KEY_LEN + ML_DSA_SIGNATURE_LEN;

/// Authority identity binds the algorithm and the exact canonical public key.
pub fn authority(key: &MlDsaPublicKey) -> Digest {
    let mut hash = Sha256::new();
    hash.update(b"hegemon-experimental-htlc-mldsa65-authority-v1");
    hash.update(key.to_bytes());
    hash.finalize().into()
}

/// Public evidence is exactly the native public key followed by its signature.
/// The caller supplies `relation::authorization_message` for its exact spend.
/// No private key or note/preimage material is encoded in this evidence.
pub fn sign_authorization(key: &MlDsaSecretKey, message: &Digest) -> Vec<u8> {
    let mut evidence = key.verify_key().to_bytes();
    evidence.extend_from_slice(&key.sign(message).to_bytes());
    evidence
}

#[derive(Clone, Copy, Default)]
pub struct MlDsaAuthorizer;

impl Authorizer for MlDsaAuthorizer {
    fn verify(
        &self,
        expected_authority: &Digest,
        message: &Digest,
        evidence: &[u8],
    ) -> Result<(), AuthorizationError> {
        if evidence.len() != AUTHORIZATION_BYTES {
            return Err(AuthorizationError);
        }
        let key = MlDsaPublicKey::from_bytes(&evidence[..ML_DSA_PUBLIC_KEY_LEN])
            .map_err(|_| AuthorizationError)?;
        if authority(&key) != *expected_authority {
            return Err(AuthorizationError);
        }
        let signature = MlDsaSignature::from_bytes(&evidence[ML_DSA_PUBLIC_KEY_LEN..])
            .map_err(|_| AuthorizationError)?;
        key.verify(message, &signature)
            .map_err(|_| AuthorizationError)
    }
}
