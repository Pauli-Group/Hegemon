//! Candidate common private-spend recovery. This module grants no production
//! authority and deliberately contains no RPC/proving or legacy-carrier fallback.
//! WalletStore must persist `IssuedPrivateSpendAddresses` in its encrypted state
//! before releasing an address, and pass that exact registry to recovery.

use crate::{DerivedKeys, WalletError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use synthetic_crypto::{
    private_note_encryption::{PrivateNoteCiphertextRef, PrivateNoteContext},
    private_note_payload::{NoteState, PrivateNotePayload},
};
use transaction_circuit::{
    private_spend::{note_commitment, Digest, Note},
    smallwood_poseidon2_v8_coinbase::poseidon2_v8_words_from_canonical_bytes,
};

/// Local encrypted-store metadata. Never attach this registry or its indices to
/// a transaction, note ciphertext header, RPC request, or public scan query.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssuedPrivateSpendAddresses {
    /// Compact record of sequential legacy issuance; never expanded on migration.
    legacy_issued_end: u32,
    indices: BTreeSet<u32>,
}
impl core::fmt::Debug for IssuedPrivateSpendAddresses {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IssuedPrivateSpendAddresses")
            .field("sparse_count", &self.indices.len())
            .finish_non_exhaustive()
    }
}
impl Default for IssuedPrivateSpendAddresses {
    fn default() -> Self {
        Self {
            legacy_issued_end: 1,
            indices: BTreeSet::new(),
        }
    }
}
impl IssuedPrivateSpendAddresses {
    pub(crate) fn contains(&self, index: u32) -> bool {
        index < self.legacy_issued_end || self.indices.contains(&index)
    }

    pub(crate) fn from_legacy_issued_count(end: u32) -> Self {
        Self {
            legacy_issued_end: end.max(1),
            indices: BTreeSet::new(),
        }
    }
    pub(crate) fn issued_indices(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.legacy_issued_end).chain(
            self.indices
                .iter()
                .copied()
                .filter(|index| *index >= self.legacy_issued_end),
        )
    }
    /// Call only within WalletStore's atomic write transaction, before returning
    /// the corresponding address. An in-memory insertion is not durable issuance.
    pub(crate) fn record_issued(&mut self, index: u32) {
        if index >= self.legacy_issued_end {
            self.indices.insert(index);
        }
    }
}

/// Authenticated, commitment-checked incoming data. A treasury or HTLC payload
/// must enter its policy ledger, never the ordinary coin selector. Possessing
/// an encryption key alone does not establish spending authority for a policy.
pub struct RecoveredPrivateSpendNote {
    pub address_index: u32,
    pub payload: PrivateNotePayload,
}

/// Trial-decrypt using locally persisted issued addresses. Both output slots,
/// including zero-value outputs, take this exact same recovery path. The caller
/// owns canonical block/reference checks and atomic application/reorg rollback.
pub fn recover_private_spend_note(
    keys: &DerivedKeys,
    issued: &IssuedPrivateSpendAddresses,
    relation_digest: [u8; 48],
    chain_id: [u8; 32],
    output_slot: u8,
    commitment: Digest,
    ciphertext: &[u8],
) -> Result<Option<RecoveredPrivateSpendNote>, WalletError> {
    let mut commitment_bytes = [0u8; 56];
    for (out, word) in commitment_bytes.chunks_exact_mut(8).zip(commitment) {
        out.copy_from_slice(&word.to_le_bytes());
    }
    let context = PrivateNoteContext::new(relation_digest, chain_id, output_slot, commitment_bytes)
        .map_err(|_| WalletError::InvalidState("invalid private-spend output context"))?;
    let ciphertext = PrivateNoteCiphertextRef::from_bytes_exact(ciphertext)
        .map_err(|_| WalletError::InvalidState("invalid private-spend ciphertext width"))?;
    // The caller passes a persisted finite set, not an attacker-controlled hint
    // or an unbounded address search. No public recipient metadata is consumed.
    for index in issued.issued_indices() {
        let material = keys.poseidon2_v8_address(index)?;
        let Ok(plaintext) = ciphertext.decrypt(material.secret_key(), &context) else {
            continue;
        };
        let Ok(payload) = PrivateNotePayload::decode(&plaintext, chain_id) else {
            continue;
        };
        if payload.recipient_index != index {
            continue;
        }
        let recipient = poseidon2_v8_words_from_canonical_bytes(material.pk_recipient)
            .map_err(|_| WalletError::InvalidState("noncanonical local private-spend recipient"))?;
        if payload.note.recipient_key != recipient {
            continue;
        }
        if validate_stored_payload_owner(&payload, keys).is_err() {
            continue;
        }
        let note = Note {
            value: payload.note.value,
            asset_id: payload.note.asset_id,
            recipient_key: payload.note.recipient_key,
            authorization_key: payload.note.authorization_key,
            rho: payload.note.rho,
            randomness: payload.note.randomness,
        };
        if note_commitment(note).ok() != Some(commitment) {
            continue;
        }
        return Ok(Some(RecoveredPrivateSpendNote {
            address_index: index,
            payload,
        }));
    }
    Ok(None)
}

/// Exact authenticated payload retained only inside the encrypted wallet file.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredPrivateSpendNote {
    pub chain_id: [u8; 32],
    pub commitment: Digest,
    pub position: u64,
    pub created_height: u64,
    pub created_block_hash: [u8; 32],
    pub nullifier: Digest,
    pub spent: bool,
    payload: Vec<u8>,
}
impl core::fmt::Debug for StoredPrivateSpendNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StoredPrivateSpendNote { [REDACTED] }")
    }
}
impl Drop for StoredPrivateSpendNote {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.payload.zeroize();
    }
}
impl StoredPrivateSpendNote {
    pub fn opening(&self) -> Result<PrivateNotePayload, WalletError> {
        let plaintext =
            synthetic_crypto::private_note_encryption::PrivateNotePlaintext::from_bytes_exact(
                &self.payload,
            )
            .map_err(|_| WalletError::InvalidState("private stored payload length"))?;
        PrivateNotePayload::decode(&plaintext, self.chain_id)
            .map_err(|_| WalletError::InvalidState("private stored payload invalid"))
    }
    pub(crate) fn validate(&self, keys: &DerivedKeys) -> Result<(), WalletError> {
        let payload = self.opening()?;
        validate_stored_payload_owner(&payload, keys)?;
        let recovered = RecoveredPrivateSpendNote {
            address_index: payload.recipient_index,
            payload,
        };
        let rebuilt = Self::new(
            recovered,
            keys,
            self.chain_id,
            self.commitment,
            self.position,
            self.created_height,
            self.created_block_hash,
        )?;
        if rebuilt.nullifier != self.nullifier {
            return Err(WalletError::InvalidState(
                "private stored nullifier mismatch",
            ));
        }
        Ok(())
    }
    pub(crate) fn new(
        recovered: RecoveredPrivateSpendNote,
        keys: &DerivedKeys,
        chain_id: [u8; 32],
        commitment: Digest,
        position: u64,
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<Self, WalletError> {
        let p = &recovered.payload;
        validate_stored_payload_owner(p, keys)?;
        let key = match &p.state {
            NoteState::Ordinary { .. } => keys.spend.poseidon2_v8_words()?,
            NoteState::Htlc(h) => h.nullifier_key,
            NoteState::Policy(policy) => policy.nullifier_key,
            NoteState::TreasuryValue(t) | NoteState::TreasuryAccumulator(t) => t.policy_key,
        };
        let note = Note {
            value: p.note.value,
            asset_id: p.note.asset_id,
            recipient_key: p.note.recipient_key,
            authorization_key: p.note.authorization_key,
            rho: p.note.rho,
            randomness: p.note.randomness,
        };
        if note_commitment(note).ok() != Some(commitment) {
            return Err(WalletError::InvalidState(
                "private stored note commitment mismatch",
            ));
        }
        let position32 = u32::try_from(position)
            .map_err(|_| WalletError::InvalidState("private note position exceeds tree"))?;
        let nullifier = transaction_circuit::private_spend::real_nullifier(key, position32, note)
            .map_err(|_| WalletError::InvalidState("private note nullifier invalid"))?;
        let plaintext = p
            .encode(chain_id)
            .map_err(|_| WalletError::InvalidState("private payload persistence encoding"))?;
        Ok(Self {
            chain_id,
            commitment,
            position,
            created_height: height,
            created_block_hash: block_hash,
            nullifier,
            spent: false,
            payload: plaintext.as_bytes().to_vec(),
        })
    }
}

fn validate_local_payload_authority(
    payload: &PrivateNotePayload,
    material: &crate::keys::AddressKeyMaterial,
) -> Result<(), WalletError> {
    if let NoteState::Ordinary { authority } = &payload.state {
        let mut local_authority = [0u64; 7];
        local_authority[..4].copy_from_slice(
            &poseidon2_v8_words_from_canonical_bytes(material.pk_auth).map_err(|_| {
                WalletError::InvalidState("noncanonical local private-spend authority")
            })?,
        );
        local_authority[4..]
            .copy_from_slice(&material.poseidon2_v8_authorization_extension_words()?);
        if *authority != local_authority {
            return Err(WalletError::InvalidState(
                "private stored ordinary authority mismatch",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod issued_registry_tests {
    use super::*;
    #[test]
    fn migrated_prefix_and_sparse_addresses_are_exact_without_expansion() {
        let mut issued = IssuedPrivateSpendAddresses::from_legacy_issued_count(3);
        issued.record_issued(9);
        issued.record_issued(1);
        assert_eq!(
            issued.issued_indices().collect::<Vec<_>>(),
            vec![0, 1, 2, 9]
        );
        assert!(!issued.contains(3));
        let large = IssuedPrivateSpendAddresses::from_legacy_issued_count(u32::MAX);
        assert!(bincode::serialize(&large).unwrap().len() < 32);
        assert_eq!(
            large.issued_indices().take(3).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }
}

/// A conditional refund owner need not own the claimant's encryption address.
/// HTLC recovery binds the full local SINGLE authority and issued refund
/// recipient. A policy handoff binds an enabled full local authority. Ordinary
/// foreign recipients remain rejected.
pub(crate) fn validate_stored_payload_owner(
    payload: &PrivateNotePayload,
    keys: &DerivedKeys,
) -> Result<(), WalletError> {
    let material = keys.poseidon2_v8_address(payload.recipient_index)?;
    let recipient = poseidon2_v8_words_from_canonical_bytes(material.pk_recipient)
        .map_err(|_| WalletError::InvalidState("noncanonical local recipient"))?;
    let authority = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest(keys.spend.poseidon2_v8_words()?)
        .map_err(|_| WalletError::InvalidState("invalid local SINGLE authority"))?;
    if let NoteState::Htlc(h) = &payload.state {
        let refund = authority == h.refund_authority && recipient == h.refund_recipient;
        let claim = authority == h.claim_authority
            && recipient == h.claim_recipient
            && recipient == payload.note.recipient_key;
        if !refund && !claim {
            return Err(WalletError::InvalidState(
                "HTLC payload has no local claim or refund authority",
            ));
        }
    } else if let NoteState::Policy(policy) = &payload.state {
        if !policy.branches.iter().any(|branch| branch.enabled == 1 && branch.authority == authority) {
            return Err(WalletError::InvalidState("policy payload has no local branch authority"));
        }
    } else {
        if recipient != payload.note.recipient_key {
            return Err(WalletError::InvalidState(
                "private stored recipient mismatch",
            ));
        }
        validate_local_payload_authority(payload, &material)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod refund_custody_tests {
    use super::*;
    use crate::keys::RootSecret;
    use synthetic_crypto::private_note_payload::{HtlcOpening, NoteOpening};
    pub(crate) fn fixture() -> (
        DerivedKeys,
        DerivedKeys,
        PrivateNotePayload,
        transaction_circuit::private_spend::PrivateHtlcOpening,
    ) {
        let claim = RootSecret::from_bytes([91; 32]).derive();
        let refund = RootSecret::from_bytes([92; 32]).derive();
        let c = claim.poseidon2_v8_address(7).unwrap().shielded_address();
        let r = refund.poseidon2_v8_address(9).unwrap().shielded_address();
        let h = crate::private_spend_build::new_htlc_policy(
            crate::private_spend_build::SpendReference {
                chain_id: [1; 32],
                parent_hash: [2; 32],
                parent_height: 100,
                merkle_root: [0; 7],
            },
            &c,
            &r,
            [3; 32],
            120,
        )
        .unwrap();
        let mut p = PrivateNotePayload {
            recipient_index: 7,
            note: NoteOpening {
                value: 100,
                asset_id: 0,
                recipient_key: h.claim_recipient,
                authorization_key: [0; 4],
                rho: [4; 4],
                randomness: [0, 0, 0, 5],
            },
            state: NoteState::Htlc(HtlcOpening {
                nullifier_key: h.nullifier_key,
                hashlock: h.hashlock,
                claim_authority: h.claim_authority,
                refund_authority: h.refund_authority,
                claim_recipient: h.claim_recipient,
                refund_recipient: h.refund_recipient,
                timeout: h.timeout,
                secret: [0; 32],
                release_secret: h.release_secret,
            }),
        };
        let owner = p.expected_owner([1; 32]).unwrap();
        p.note.authorization_key.copy_from_slice(&owner[..4]);
        p.note.randomness[..3].copy_from_slice(&owner[4..]);
        (claim, refund, p, h)
    }
    #[test]
    fn private_spend_distinct_refund_owner_preserves_claim_commitment_and_nullifier() {
        let (claim, refund, mut p, _) = fixture();
        let n = &p.note;
        let note = Note {
            value: n.value,
            asset_id: n.asset_id,
            recipient_key: n.recipient_key,
            authorization_key: n.authorization_key,
            rho: n.rho,
            randomness: n.randomness,
        };
        let cm = note_commitment(note).unwrap();
        let copy = PrivateNotePayload::decode(&p.encode([1; 32]).unwrap(), [1; 32]).unwrap();
        let claimed = StoredPrivateSpendNote::new(
            RecoveredPrivateSpendNote {
                address_index: 7,
                payload: copy,
            },
            &claim,
            [1; 32],
            cm,
            0,
            101,
            [8; 32],
        )
        .unwrap();
        p.recipient_index = 9;
        validate_stored_payload_owner(&p, &refund).unwrap();
        assert!(validate_stored_payload_owner(&p, &claim).is_err());
        assert!(
            validate_stored_payload_owner(&p, &RootSecret::from_bytes([93; 32]).derive()).is_err()
        );
        assert!(p.encode([2; 32]).is_err());
        let wrong = PrivateNotePayload::decode(&p.encode([1; 32]).unwrap(), [1; 32]).unwrap();
        assert!(StoredPrivateSpendNote::new(
            RecoveredPrivateSpendNote {
                address_index: 9,
                payload: wrong
            },
            &refund,
            [1; 32],
            [0; 7],
            0,
            101,
            [8; 32]
        )
        .is_err());
        let refunded = StoredPrivateSpendNote::new(
            RecoveredPrivateSpendNote {
                address_index: 9,
                payload: p,
            },
            &refund,
            [1; 32],
            cm,
            0,
            101,
            [8; 32],
        )
        .unwrap();
        refunded.validate(&refund).unwrap();
        assert_eq!(claimed.nullifier, refunded.nullifier);
        assert_eq!(claimed.commitment, refunded.commitment);
        let mut foreign = refunded.opening().unwrap();
        foreign.state = NoteState::Ordinary { authority: [0; 7] };
        assert!(validate_stored_payload_owner(&foreign, &refund).is_err());
    }
}


#[cfg(test)]
mod policy_custody_tests {
    use super::*;
    use crate::keys::RootSecret;
    use synthetic_crypto::private_note_payload::{NoteOpening, Policy, PolicyBranch};
    use transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest;

    fn fixture() -> (DerivedKeys, DerivedKeys, PrivateNotePayload) {
        let first = RootSecret::from_bytes([101; 32]).derive();
        let second = RootSecret::from_bytes([102; 32]).derive();
        let authority = |keys: &DerivedKeys| {
            poseidon2_v8_single_key_authorization_digest(keys.spend.poseidon2_v8_words().unwrap()).unwrap()
        };
        let recipient = first.poseidon2_v8_address(7).unwrap();
        let mut payload = PrivateNotePayload {
            recipient_index: 7,
            note: NoteOpening {
                value: 100,
                asset_id: 0,
                recipient_key: poseidon2_v8_words_from_canonical_bytes(recipient.pk_recipient).unwrap(),
                authorization_key: [0; 4],
                rho: [4; 4],
                randomness: [0, 0, 0, 5],
            },
            state: NoteState::Policy(Policy {
                nullifier_key: [11, 12, 13, 14, 15],
                branches: [
                    PolicyBranch {
                        enabled: 1,
                        authority: authority(&first),
                        not_before: 120,
                        hash_required: 1,
                        hashlock: [3; 32],
                        release_secret: 1,
                    },
                    PolicyBranch {
                        enabled: 1,
                        authority: authority(&second),
                        not_before: 240,
                        hash_required: 0,
                        hashlock: [0; 32],
                        release_secret: 0,
                    },
                ],
            }),
        };
        let owner = payload.expected_owner([1; 32]).unwrap();
        payload.note.authorization_key.copy_from_slice(&owner[..4]);
        payload.note.randomness[..3].copy_from_slice(&owner[4..]);
        (first, second, payload)
    }

    fn commitment(payload: &PrivateNotePayload) -> Digest {
        let note = &payload.note;
        note_commitment(Note {
            value: note.value,
            asset_id: note.asset_id,
            recipient_key: note.recipient_key,
            authorization_key: note.authorization_key,
            rho: note.rho,
            randomness: note.randomness,
        }).unwrap()
    }

    #[test]
    fn distinct_policy_controllers_share_commitment_and_nullifier_without_sharing_spend_keys() {
        let (first, second, mut payload) = fixture();
        let cm = commitment(&payload);
        let first_copy = PrivateNotePayload::decode(&payload.encode([1; 32]).unwrap(), [1; 32]).unwrap();
        let first_note = StoredPrivateSpendNote::new(
            RecoveredPrivateSpendNote { address_index: 7, payload: first_copy },
            &first, [1; 32], cm, 17, 101, [8; 32],
        ).unwrap();
        first_note.validate(&first).unwrap();

        // The second holder imports the same authenticated opening, changing
        // only its encrypted local address index. The recipient and policy
        // preimages remain identical, so commitment and spend-conflict identity
        // must be identical across the two independent controllers.
        payload.recipient_index = 9;
        validate_stored_payload_owner(&payload, &second).unwrap();
        let second_copy = PrivateNotePayload::decode(&payload.encode([1; 32]).unwrap(), [1; 32]).unwrap();
        let second_note = StoredPrivateSpendNote::new(
            RecoveredPrivateSpendNote { address_index: 9, payload: second_copy },
            &second, [1; 32], cm, 17, 101, [8; 32],
        ).unwrap();
        second_note.validate(&second).unwrap();
        assert_eq!(first_note.commitment, second_note.commitment);
        assert_eq!(first_note.nullifier, second_note.nullifier);
        assert_ne!(first.spend.poseidon2_v8_words().unwrap(), second.spend.poseidon2_v8_words().unwrap());

        let unrelated = RootSecret::from_bytes([103; 32]).derive();
        assert!(validate_stored_payload_owner(&payload, &unrelated).is_err());
        assert!(second_note.validate(&unrelated).is_err());
        assert!(payload.encode([2; 32]).is_err());

        let wrong_chain_copy = PrivateNotePayload::decode(&payload.encode([1; 32]).unwrap(), [1; 32]).unwrap();
        assert!(StoredPrivateSpendNote::new(
            RecoveredPrivateSpendNote { address_index: 9, payload: wrong_chain_copy },
            &second, [2; 32], cm, 17, 101, [8; 32],
        ).is_err());

        let mut changed = PrivateNotePayload::decode(&payload.encode([1; 32]).unwrap(), [1; 32]).unwrap();
        let NoteState::Policy(policy) = &mut changed.state else { panic!("policy fixture") };
        policy.branches[1].not_before += 1;
        assert!(changed.encode([1; 32]).is_err());
        assert!(StoredPrivateSpendNote::new(
            RecoveredPrivateSpendNote { address_index: 9, payload: changed },
            &second, [1; 32], cm, 17, 101, [8; 32],
        ).is_err());
    }
}
