//! Host reference relation only. Apart from the SHA-256 preimage gadget, these
//! commitments, balance/version rules and external checks are not in a proof.

use crate::hashlock::{ConstraintError, Sha256Hashlock};
use sha2::{Digest as _, Sha256};

pub type Digest = [u8; 32];
pub const POLICY_VERSION: u32 = 1;

/// All fields are the private locked-note opening, including both identities
/// and the shared nullifier key. No Debug/serialization is provided for secrets.
pub struct LockedNote {
    pub version: u32,
    pub hashlock: Digest,
    pub claim_authority: Digest,
    pub refund_authority: Digest,
    pub timeout_height: u64,
    pub asset: Digest,
    pub value: u64,
    pub note_id: Digest,
    pub nullifier_key: Digest,
}

impl LockedNote {
    /// Fixed-width canonical encoding, domain separated from all other hashes.
    /// This binds the private nullifier key as well as the required policy.
    pub fn commitment(&self) -> Digest {
        hash(&[
            b"hegemon-experimental-htlc-note-v1",
            &self.version.to_le_bytes(),
            &self.hashlock,
            &self.claim_authority,
            &self.refund_authority,
            &self.timeout_height.to_le_bytes(),
            &self.asset,
            &self.value.to_le_bytes(),
            &self.note_id,
            &self.nullifier_key,
        ])
    }

    /// Independent of selected branch, signer and spend intent. An arbitrary
    /// branch-specific key fails the committed-opening check. This is a local
    /// host reference construction, not Hegemon's production nullifier PRF.
    pub fn nullifier(&self) -> Digest {
        hash(&[
            b"hegemon-experimental-htlc-nullifier-v1",
            &self.nullifier_key,
            &self.note_id,
            &self.commitment(),
        ])
    }
}

/// A single output, exact same-asset reference transfer. Fees are in that asset
/// for this model only. This does not assert production asset/fee semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendIntent {
    pub network_id: Digest,
    pub recipient_commitment: Digest,
    pub asset: Digest,
    pub output_value: u64,
    pub fee: u64,
    pub operation_nonce: Digest,
}

impl SpendIntent {
    pub fn commitment(&self) -> Digest {
        hash(&[
            b"hegemon-experimental-htlc-intent-v1",
            &self.network_id,
            &self.recipient_commitment,
            &self.asset,
            &self.output_value.to_le_bytes(),
            &self.fee.to_le_bytes(),
            &self.operation_nonce,
        ])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Branch {
    Claim,
    Refund,
}

/// Context must be returned by a trusted validator using consensus-accepted
/// parent hash/height. Local timers or supplied integers do not authenticate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub network_id: Digest,
    pub parent_hash: Digest,
    pub parent_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainError {
    UnknownNote,
    AlreadySpent,
    UnauthenticatedContext,
}

/// Integration obligation: validate note inclusion and nullifier unspent state
/// against this exact authenticated parent context. Recheck/consume atomically
/// at import; a stale snapshot is not permission to spend a note twice.
pub trait AuthenticatedChain {
    fn validate_locked_note(
        &self,
        note_commitment: &Digest,
        nullifier: &Digest,
    ) -> Result<Context, ChainError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationError;

/// Integration obligation: cryptographically verify the evidence under the
/// exact committed authority identity and message. Never implement by trusting
/// a caller's Boolean/signature-valid flag. Algorithm, key encoding and proof
/// of private signer possession require separate production design/validation.
pub trait Authorizer {
    fn verify(
        &self,
        authority: &Digest,
        message: &Digest,
        evidence: &[u8],
    ) -> Result<(), AuthorizationError>;
}

pub struct SpendStatement {
    pub note_commitment: Digest,
    pub nullifier: Digest,
    pub intent: SpendIntent,
}

pub enum SpendWitness<'a> {
    Claim {
        preimage: &'a Digest,
        sha_assignment: &'a [u8],
        authorization: &'a [u8],
    },
    Refund {
        authorization: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationError {
    Version,
    NoteCommitment,
    Nullifier,
    IntentAsset,
    IntentValue,
    Network,
    Chain(ChainError),
    Hashlock(ConstraintError),
    RefundImmature,
    Authorization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedSpend {
    pub note_commitment: Digest,
    pub nullifier: Digest,
    pub branch: Branch,
    pub intent_commitment: Digest,
    pub context: Context,
}

/// The external authorizer must bind the branch and the entire canonical
/// intent plus parent context. Policy/asset/value/note ID/authorities/timeout
/// are transitively bound by the opened note commitment. The secret is never
/// added to this transcript. Claims remain possible after timeout.
pub fn authorization_message(
    statement: &SpendStatement,
    branch: Branch,
    context: Context,
) -> Digest {
    hash(&[
        b"hegemon-experimental-htlc-authorize-v1",
        &statement.note_commitment,
        &statement.nullifier,
        &[match branch {
            Branch::Claim => 0,
            Branch::Refund => 1,
        }],
        &statement.intent.commitment(),
        &context.network_id,
        &context.parent_hash,
        &context.parent_height.to_le_bytes(),
    ])
}

pub fn check_spend(
    circuit: &Sha256Hashlock,
    note: &LockedNote,
    statement: &SpendStatement,
    witness: SpendWitness<'_>,
    chain: &impl AuthenticatedChain,
    authorizer: &impl Authorizer,
) -> Result<ValidatedSpend, RelationError> {
    if note.version != POLICY_VERSION {
        return Err(RelationError::Version);
    }
    if note.commitment() != statement.note_commitment {
        return Err(RelationError::NoteCommitment);
    }
    if note.nullifier() != statement.nullifier {
        return Err(RelationError::Nullifier);
    }
    if statement.intent.asset != note.asset {
        return Err(RelationError::IntentAsset);
    }
    if note.value == 0
        || statement.intent.output_value == 0
        || statement
            .intent
            .output_value
            .checked_add(statement.intent.fee)
            != Some(note.value)
    {
        return Err(RelationError::IntentValue);
    }
    let context = chain
        .validate_locked_note(&statement.note_commitment, &statement.nullifier)
        .map_err(RelationError::Chain)?;
    if statement.intent.network_id != context.network_id {
        return Err(RelationError::Network);
    }
    let (branch, authority, evidence) = match witness {
        SpendWitness::Claim {
            preimage,
            sha_assignment,
            authorization,
        } => {
            circuit
                .verify(preimage, &note.hashlock, sha_assignment)
                .map_err(RelationError::Hashlock)?;
            (Branch::Claim, &note.claim_authority, authorization)
        }
        SpendWitness::Refund { authorization } => {
            if context.parent_height < note.timeout_height {
                return Err(RelationError::RefundImmature);
            }
            (Branch::Refund, &note.refund_authority, authorization)
        }
    };
    authorizer
        .verify(
            authority,
            &authorization_message(statement, branch, context),
            evidence,
        )
        .map_err(|_| RelationError::Authorization)?;
    Ok(ValidatedSpend {
        note_commitment: statement.note_commitment,
        nullifier: statement.nullifier,
        branch,
        intent_commitment: statement.intent.commitment(),
        context,
    })
}

fn hash(parts: &[&[u8]]) -> Digest {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // Explicit external-authentication test double, not a signature scheme.
    // A receipt is issued by the fixture with an authority/message pair and
    // accepted only for that exact pair. Production cannot use this fixture.
    struct AuthReceipt {
        authority: Digest,
        message: Digest,
    }
    impl Authorizer for AuthReceipt {
        fn verify(&self, a: &Digest, m: &Digest, e: &[u8]) -> Result<(), AuthorizationError> {
            if a == &self.authority
                && m == &self.message
                && e == b"externally-validated-test-receipt"
            {
                Ok(())
            } else {
                Err(AuthorizationError)
            }
        }
    }
    const RECEIPT: &[u8] = b"externally-validated-test-receipt";
    struct Chain {
        note: Digest,
        context: Context,
        spent: HashSet<Digest>,
        authenticated: bool,
    }
    impl AuthenticatedChain for Chain {
        fn validate_locked_note(&self, n: &Digest, nf: &Digest) -> Result<Context, ChainError> {
            if !self.authenticated {
                return Err(ChainError::UnauthenticatedContext);
            }
            if n != &self.note {
                return Err(ChainError::UnknownNote);
            }
            if self.spent.contains(nf) {
                return Err(ChainError::AlreadySpent);
            }
            Ok(self.context)
        }
    }
    fn setup(
        height: u64,
    ) -> (
        Sha256Hashlock,
        LockedNote,
        SpendStatement,
        Chain,
        Digest,
        Vec<u8>,
    ) {
        let c = Sha256Hashlock::new();
        let preimage = [42; 32];
        let assignment = c.evaluate(&preimage);
        let note = LockedNote {
            version: POLICY_VERSION,
            hashlock: c.digest(&assignment).unwrap(),
            claim_authority: [1; 32],
            refund_authority: [2; 32],
            timeout_height: 100,
            asset: [3; 32],
            value: 1000,
            note_id: [4; 32],
            nullifier_key: [5; 32],
        };
        let statement = SpendStatement {
            note_commitment: note.commitment(),
            nullifier: note.nullifier(),
            intent: SpendIntent {
                network_id: [6; 32],
                recipient_commitment: [7; 32],
                asset: note.asset,
                output_value: 990,
                fee: 10,
                operation_nonce: [8; 32],
            },
        };
        let chain = Chain {
            note: statement.note_commitment,
            context: Context {
                network_id: [6; 32],
                parent_hash: [9; 32],
                parent_height: height,
            },
            spent: HashSet::new(),
            authenticated: true,
        };
        (c, note, statement, chain, preimage, assignment)
    }
    fn auth(n: &LockedNote, s: &SpendStatement, b: Branch, ctx: Context) -> AuthReceipt {
        AuthReceipt {
            authority: match b {
                Branch::Claim => n.claim_authority,
                Branch::Refund => n.refund_authority,
            },
            message: authorization_message(s, b, ctx),
        }
    }
    fn claim<'a>(p: &'a Digest, a: &'a [u8]) -> SpendWitness<'a> {
        SpendWitness::Claim {
            preimage: p,
            sha_assignment: a,
            authorization: RECEIPT,
        }
    }
    fn refund() -> SpendWitness<'static> {
        SpendWitness::Refund {
            authorization: RECEIPT,
        }
    }

    #[test]
    fn claim_survives_timeout_refund_matures_at_timeout() {
        for height in [0, 99, 100, 101, u64::MAX] {
            let (c, n, s, ch, p, a) = setup(height);
            assert_eq!(
                check_spend(
                    &c,
                    &n,
                    &s,
                    claim(&p, &a),
                    &ch,
                    &auth(&n, &s, Branch::Claim, ch.context)
                )
                .unwrap()
                .branch,
                Branch::Claim
            );
            let r = check_spend(
                &c,
                &n,
                &s,
                refund(),
                &ch,
                &auth(&n, &s, Branch::Refund, ch.context),
            );
            if height < 100 {
                assert_eq!(r, Err(RelationError::RefundImmature));
            } else {
                assert_eq!(r.unwrap().branch, Branch::Refund);
            }
        }
    }

    #[test]
    fn competing_branches_share_identity_and_only_first_spends() {
        for first in [Branch::Claim, Branch::Refund] {
            let (c, n, s, mut ch, p, a) = setup(100);
            let claim_result = check_spend(
                &c,
                &n,
                &s,
                claim(&p, &a),
                &ch,
                &auth(&n, &s, Branch::Claim, ch.context),
            )
            .unwrap();
            let refund_result = check_spend(
                &c,
                &n,
                &s,
                refund(),
                &ch,
                &auth(&n, &s, Branch::Refund, ch.context),
            )
            .unwrap();
            assert_eq!(claim_result.note_commitment, refund_result.note_commitment);
            assert_eq!(claim_result.nullifier, refund_result.nullifier);
            ch.spent.insert(match first {
                Branch::Claim => claim_result.nullifier,
                Branch::Refund => refund_result.nullifier,
            });
            assert_eq!(
                check_spend(
                    &c,
                    &n,
                    &s,
                    claim(&p, &a),
                    &ch,
                    &auth(&n, &s, Branch::Claim, ch.context)
                ),
                Err(RelationError::Chain(ChainError::AlreadySpent))
            );
            assert_eq!(
                check_spend(
                    &c,
                    &n,
                    &s,
                    refund(),
                    &ch,
                    &auth(&n, &s, Branch::Refund, ch.context)
                ),
                Err(RelationError::Chain(ChainError::AlreadySpent))
            );
        }
    }

    #[test]
    fn authorization_binds_authority_branch_intent_and_context() {
        let (c, n, mut s, mut ch, p, a) = setup(100);
        let original = auth(&n, &s, Branch::Claim, ch.context);
        let wrong = auth(&n, &s, Branch::Refund, ch.context);
        let wrong_authority = AuthReceipt {
            authority: n.refund_authority,
            message: original.message,
        };
        assert_eq!(
            check_spend(&c, &n, &s, claim(&p, &a), &ch, &wrong_authority),
            Err(RelationError::Authorization)
        );
        assert_eq!(
            check_spend(&c, &n, &s, claim(&p, &a), &ch, &wrong),
            Err(RelationError::Authorization)
        );
        assert_eq!(
            check_spend(&c, &n, &s, refund(), &ch, &original),
            Err(RelationError::Authorization)
        );
        let old = s.intent;
        for field in 0..5 {
            s.intent = old;
            match field {
                0 => s.intent.recipient_commitment[0] ^= 1,
                1 => s.intent.operation_nonce[0] ^= 1,
                2 => {
                    s.intent.output_value -= 1;
                    s.intent.fee += 1;
                }
                3 => s.intent.network_id[0] ^= 1,
                _ => s.intent.asset[0] ^= 1,
            }
            assert!(check_spend(&c, &n, &s, claim(&p, &a), &ch, &original).is_err());
        }
        s.intent = old;
        ch.context.parent_height += 1;
        assert_eq!(
            check_spend(&c, &n, &s, claim(&p, &a), &ch, &original),
            Err(RelationError::Authorization)
        );
        ch.context.parent_height -= 1;
        ch.context.parent_hash[0] ^= 1;
        assert_eq!(
            check_spend(&c, &n, &s, claim(&p, &a), &ch, &original),
            Err(RelationError::Authorization)
        );
        ch.context.parent_hash[0] ^= 1;
        ch.authenticated = false;
        assert_eq!(
            check_spend(&c, &n, &s, claim(&p, &a), &ch, &original),
            Err(RelationError::Chain(ChainError::UnauthenticatedContext))
        );
    }

    #[test]
    fn every_note_field_is_committed_and_nullifier_key_cannot_switch() {
        for field in 0..10 {
            let (c, mut n, s, ch, p, a) = setup(100);
            let original = auth(&n, &s, Branch::Claim, ch.context);
            match field {
                0 => n.version += 1,
                1 => n.hashlock[0] ^= 1,
                2 => n.claim_authority[0] ^= 1,
                3 => n.refund_authority[0] ^= 1,
                4 => n.timeout_height += 1,
                5 => n.asset[0] ^= 1,
                6 => n.value += 1,
                7 => n.note_id[0] ^= 1,
                8 => n.nullifier_key[0] ^= 1,
                _ => n.value = 0,
            }
            assert!(
                check_spend(&c, &n, &s, claim(&p, &a), &ch, &original).is_err(),
                "note field {field}"
            );
        }
        let (c, n, mut s, ch, p, a) = setup(100);
        let original = auth(&n, &s, Branch::Claim, ch.context);
        s.nullifier[0] ^= 1;
        assert_eq!(
            check_spend(&c, &n, &s, claim(&p, &a), &ch, &original),
            Err(RelationError::Nullifier)
        );
        let mut altered = setup(100).1;
        altered.nullifier_key[0] ^= 1;
        assert_ne!(n.nullifier(), altered.nullifier());
    }

    #[test]
    fn wrong_preimage_assignment_state_value_and_receipt_reject() {
        let (c, n, mut s, mut ch, p, a) = setup(100);
        let original = auth(&n, &s, Branch::Claim, ch.context);
        let wrong = [43; 32];
        let wrong_a = c.evaluate(&wrong);
        assert!(matches!(
            check_spend(&c, &n, &s, claim(&wrong, &wrong_a), &ch, &original),
            Err(RelationError::Hashlock(_))
        ));
        let mut bad_a = a.clone();
        bad_a[300] ^= 1;
        assert!(matches!(
            check_spend(&c, &n, &s, claim(&p, &bad_a), &ch, &original),
            Err(RelationError::Hashlock(_))
        ));
        assert_eq!(
            check_spend(
                &c,
                &n,
                &s,
                SpendWitness::Claim {
                    preimage: &p,
                    sha_assignment: &a,
                    authorization: b"forged"
                },
                &ch,
                &original
            ),
            Err(RelationError::Authorization)
        );
        ch.note[0] ^= 1;
        assert_eq!(
            check_spend(&c, &n, &s, claim(&p, &a), &ch, &original),
            Err(RelationError::Chain(ChainError::UnknownNote))
        );
        ch.note[0] ^= 1;
        for (value, fee) in [(0, 1000), (991, 10), (u64::MAX, 1)] {
            s.intent.output_value = value;
            s.intent.fee = fee;
            assert_eq!(
                check_spend(&c, &n, &s, claim(&p, &a), &ch, &original),
                Err(RelationError::IntentValue)
            );
        }
    }
}
