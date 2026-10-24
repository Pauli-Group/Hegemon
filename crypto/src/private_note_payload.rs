//! Canonical private plaintext only. Never serialize this record onto a public
//! carrier. Owner hashing mirrors the common three-signer relation; this codec
//! is not a transaction proof or an authorization decision.
use crate::private_note_encryption::PrivateNotePlaintext;
use alloc::{vec, vec::Vec};
use transaction_core::poseidon2_width16::{
    poseidon2_width16_compress14, poseidon2_width16_sponge, Felt,
    POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
const P: u64 = 0xffff_ffff_0000_0001;
pub use transaction_core::bounded_policy::{Branch as PolicyBranch, Policy};
type Digest = [u64; 7];
pub const RELEASING_HTLC_OWNER_DOMAIN: u64 = 0x5053_4852_454c_0001;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadError {
    Length,
    Padding,
    Version,
    Kind,
    Noncanonical,
    Owner,
    Range,
    Overflow,
}
impl core::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "private note payload: {self:?}")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for PayloadError {}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NoteOpening {
    pub value: u64,
    pub asset_id: u64,
    pub recipient_key: [u64; 4],
    pub authorization_key: [u64; 4],
    pub rho: [u64; 4],
    pub randomness: [u64; 4],
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TreasuryOpening {
    pub policy_key: [u64; 5],
    pub signer_tags: [Digest; 3],
    pub approved: [u64; 3],
    pub selected_signer: [u64; 3],
    pub intent: [u64; 54],
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HtlcOpening {
    pub nullifier_key: [u64; 5],
    pub hashlock: [u8; 32],
    pub claim_authority: Digest,
    pub refund_authority: Digest,
    pub claim_recipient: [u64; 4],
    pub refund_recipient: [u64; 4],
    pub timeout: u64,
    pub secret: [u8; 32],
    pub release_secret: u64,
}
pub enum NoteState {
    Ordinary { authority: Digest },
    Htlc(HtlcOpening),
    TreasuryValue(TreasuryOpening),
    TreasuryAccumulator(TreasuryOpening),
    Policy(Policy),
}
// Manual drop uses the explicit implementation below because the policy type
// lives in transaction-core, which intentionally has no zeroize dependency.
impl Drop for NoteState {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for NoteState {}
impl Zeroize for NoteState {
    fn zeroize(&mut self) {
        match self {
            Self::Ordinary { authority } => authority.zeroize(),
            Self::Htlc(h) => h.zeroize(),
            Self::TreasuryValue(t) | Self::TreasuryAccumulator(t) => t.zeroize(),
            Self::Policy(policy) => {
                policy.nullifier_key.zeroize();
                for branch in &mut policy.branches {
                    branch.enabled.zeroize();
                    branch.authority.zeroize();
                    branch.not_before.zeroize();
                    branch.hash_required.zeroize();
                    branch.hashlock.zeroize();
                    branch.release_secret.zeroize();
                }
            }
        }
    }
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateNotePayload {
    pub recipient_index: u32,
    pub note: NoteOpening,
    pub state: NoteState,
}
fn hash(domain: u64, words: &[u64]) -> Result<Digest, PayloadError> {
    if words.iter().any(|x| *x >= P) {
        return Err(PayloadError::Noncanonical);
    }
    let fields = Zeroizing::new(words.to_vec());
    // Felt is public-library field storage; explicit zeroizing integer input owns
    // our retained secret copy. Temporary field values are not exported.
    let values = fields
        .iter()
        .copied()
        .map(Felt::from_u64)
        .collect::<Vec<_>>();
    poseidon2_width16_sponge(domain, &values)
        .map(|d| d.map(|x| x.as_canonical_u64()))
        .map_err(|_| PayloadError::Noncanonical)
}
fn compress(domain: u64, a: Digest, b: Digest) -> Digest {
    poseidon2_width16_compress14(domain, &a.map(Felt::from_u64), &b.map(Felt::from_u64))
        .map(|x| x.as_canonical_u64())
}
fn key7(k: [u64; 5]) -> Digest {
    [k[0], k[1], k[2], k[3], k[4], 0, 0]
}
fn append_bytes(w: &mut Vec<u64>, bytes: &[u8]) {
    for b in bytes.chunks_exact(4) {
        w.push(u32::from_le_bytes(b.try_into().expect("four bytes")) as u64);
    }
}
impl PrivateNotePayload {
    pub fn expected_owner(&self, chain: [u8; 32]) -> Result<Digest, PayloadError> {
        match &self.state {
            NoteState::Ordinary { authority } => hash(0x5053_4f57_4e52_0001, authority),
            NoteState::Htlc(h) => {
                if h.nullifier_key.iter().any(|x| *x >= P) {
                    return Err(PayloadError::Noncanonical);
                }
                if h.timeout >= 1 << 48 || h.release_secret > 1 {
                    return Err(PayloadError::Range);
                }
                let mut w = Zeroizing::new(Vec::new());
                append_bytes(&mut w, &chain);
                append_bytes(&mut w, &h.hashlock);
                w.extend(h.claim_authority);
                w.extend(h.refund_authority);
                w.extend(h.claim_recipient);
                w.extend(h.refund_recipient);
                w.push(h.timeout);
                Ok(compress(
                    if h.release_secret == 1 {
                        RELEASING_HTLC_OWNER_DOMAIN
                    } else {
                        0x5053_484f_574e_0001
                    },
                    key7(h.nullifier_key),
                    hash(0x5053_4850_4f4c_0001, &w)?,
                ))
            }
            NoteState::Policy(policy) => policy
                .owner(chain, self.note.asset_id)
                .map_err(|_| PayloadError::Range),
            NoteState::TreasuryValue(t) | NoteState::TreasuryAccumulator(t) => {
                if t.policy_key.iter().chain(t.intent.iter()).any(|x| *x >= P) {
                    return Err(PayloadError::Noncanonical);
                }
                if t.approved
                    .iter()
                    .chain(t.selected_signer.iter())
                    .any(|x| *x > 1)
                    || t.selected_signer.iter().sum::<u64>() > 1
                {
                    return Err(PayloadError::Range);
                }
                if t.signer_tags.iter().any(|tag| *tag == [0; 7])
                    || t.signer_tags[0] == t.signer_tags[1]
                    || t.signer_tags[0] == t.signer_tags[2]
                    || t.signer_tags[1] == t.signer_tags[2]
                {
                    return Err(PayloadError::Noncanonical);
                }
                let mut w = Zeroizing::new(vec![2, 3]);
                w.extend(t.signer_tags.into_iter().flatten());
                w.extend([0; 21]);
                let policy = hash(0x4841_5038_504f_4c01, &w)?;
                let inner = if matches!(&self.state, NoteState::TreasuryValue(_)) {
                    compress(0x4856_4c4b_5632_0001, policy, [0; 7])
                } else {
                    let mut v = Zeroizing::new(policy.to_vec());
                    v.extend(hash(0x5053_494e_544e_0001, &t.intent)?);
                    v.extend([2, 3, t.approved.iter().sum()]);
                    v.extend(t.approved);
                    v.extend([0; 3]);
                    hash(0x5053_4143_4355_0001, &v)?
                };
                Ok(compress(0x484d_4244_5632_0001, key7(t.policy_key), inner))
            }
        }
    }
    fn validate(&self, chain: [u8; 32]) -> Result<(), PayloadError> {
        let n = &self.note;
        if n.value >= 1 << 56 || n.asset_id != 0 {
            return Err(PayloadError::Range);
        }
        for word in n
            .recipient_key
            .iter()
            .chain(n.authorization_key.iter())
            .chain(n.rho.iter())
            .chain(n.randomness.iter())
        {
            if *word >= P {
                return Err(PayloadError::Noncanonical);
            }
        }
        let owner = self.expected_owner(chain)?;
        if n.authorization_key != owner[..4] || n.randomness[..3] != owner[4..] {
            return Err(PayloadError::Owner);
        }
        Ok(())
    }
    pub fn encode(&self, chain: [u8; 32]) -> Result<PrivateNotePlaintext, PayloadError> {
        self.validate(chain)?;
        let mut w = Writer {
            bytes: Zeroizing::new([0; 1024]),
            at: 0,
        };
        // Ordinary owners use the unchanged variable-length sponge. Their
        // exact PSN1 bytes remain valid. Conditional owners use compression,
        // so their fresh PSN2 format explicitly pins the compression mode.
        let compression_bound = !matches!(&self.state, NoteState::Ordinary { .. });
        let successor = matches!(&self.state, NoteState::Policy(_))
            || matches!(&self.state, NoteState::Htlc(h) if h.release_secret == 1);
        w.put(if successor {
            b"PSN3"
        } else if compression_bound {
            b"PSN2"
        } else {
            b"PSN1"
        })?;
        w.put(&[match self.state {
            NoteState::Ordinary { .. } => 0,
            NoteState::Htlc(_) => 1,
            NoteState::TreasuryValue(_) => 2,
            NoteState::TreasuryAccumulator(_) => 3,
            NoteState::Policy(_) => 4,
        }])?;
        if compression_bound {
            w.put(&POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER.to_le_bytes())?;
        }
        w.put(&self.recipient_index.to_le_bytes())?;
        let n = &self.note;
        w.words(&[n.value, n.asset_id])?;
        w.words(&n.recipient_key)?;
        w.words(&n.rho)?;
        w.words(&n.randomness)?;
        w.words(&n.authorization_key)?;
        match &self.state {
            NoteState::Ordinary { authority } => w.words(authority)?,
            NoteState::Htlc(h) => {
                w.words(&h.nullifier_key)?;
                w.put(&h.hashlock)?;
                w.words(&h.claim_authority)?;
                w.words(&h.refund_authority)?;
                w.words(&h.claim_recipient)?;
                w.words(&h.refund_recipient)?;
                w.words(&[h.timeout])?;
                w.put(&h.secret)?;
                if h.release_secret == 1 {
                    w.words(&[h.release_secret])?;
                }
            }
            NoteState::Policy(policy) => {
                w.words(&policy.nullifier_key)?;
                w.words(&policy.words().map_err(|_| PayloadError::Range)?)?;
            }
            NoteState::TreasuryValue(t) | NoteState::TreasuryAccumulator(t) => {
                w.words(&t.policy_key)?;
                for tag in &t.signer_tags {
                    w.words(tag)?;
                }
                w.words(&t.approved)?;
                w.words(&t.selected_signer)?;
                w.words(&t.intent)?;
            }
        }
        PrivateNotePlaintext::from_bytes_exact(&w.bytes[..]).map_err(|_| PayloadError::Length)
    }
    pub fn decode(plaintext: &PrivateNotePlaintext, chain: [u8; 32]) -> Result<Self, PayloadError> {
        let mut r = Reader {
            bytes: plaintext.as_bytes(),
            at: 0,
        };
        let magic = r.take(4)?;
        let kind = r.take(1)?[0];
        match magic {
            b"PSN1" if kind == 0 => {}
            b"PSN2" if (1..=3).contains(&kind) => {
                if r.take(8)? != POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER.to_le_bytes() {
                    return Err(PayloadError::Version);
                }
            }
            b"PSN3" if kind == 1 || kind == 4 => {
                if r.take(8)? != POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER.to_le_bytes() {
                    return Err(PayloadError::Version);
                }
            }
            // Reject predecessor conditional notes before interpreting their
            // fields or computing a replacement owner. Migration recreates
            // these notes under a fresh chain/proof identity, never in place.
            _ => return Err(PayloadError::Version),
        }
        let recipient_index =
            u32::from_le_bytes(r.take(4)?.try_into().map_err(|_| PayloadError::Length)?);
        let value = r.words::<1>()?[0];
        let asset_id = r.words::<1>()?[0];
        let recipient_key = r.words()?;
        let rho = r.words()?;
        let randomness = r.words()?;
        let authorization_key = r.words()?;
        let note = NoteOpening {
            value,
            asset_id,
            recipient_key,
            rho,
            randomness,
            authorization_key,
        };
        let state = match kind {
            0 => NoteState::Ordinary {
                authority: r.words()?,
            },
            1 => NoteState::Htlc(HtlcOpening {
                nullifier_key: r.words()?,
                hashlock: r.take(32)?.try_into().map_err(|_| PayloadError::Length)?,
                claim_authority: r.words()?,
                refund_authority: r.words()?,
                claim_recipient: r.words()?,
                refund_recipient: r.words()?,
                timeout: r.words::<1>()?[0],
                secret: r.take(32)?.try_into().map_err(|_| PayloadError::Length)?,
                release_secret: if magic == b"PSN3" {
                    let flag = r.words::<1>()?[0];
                    if flag != 1 {
                        return Err(PayloadError::Version);
                    }
                    flag
                } else {
                    0
                },
            }),
            2 | 3 => {
                let t = TreasuryOpening {
                    policy_key: r.words()?,
                    signer_tags: [r.words()?, r.words()?, r.words()?],
                    approved: r.words()?,
                    selected_signer: r.words()?,
                    intent: r.words()?,
                };
                if kind == 2 {
                    NoteState::TreasuryValue(t)
                } else {
                    NoteState::TreasuryAccumulator(t)
                }
            }
            4 => NoteState::Policy(
                Policy::from_words(r.words()?, r.words()?).map_err(|_| PayloadError::Range)?,
            ),
            _ => return Err(PayloadError::Kind),
        };
        if r.bytes[r.at..].iter().any(|x| *x != 0) {
            return Err(PayloadError::Padding);
        }
        let result = Self {
            recipient_index,
            note,
            state,
        };
        result.validate(chain)?;
        Ok(result)
    }
}
struct Writer {
    bytes: Zeroizing<[u8; 1024]>,
    at: usize,
}
impl Writer {
    fn put(&mut self, b: &[u8]) -> Result<(), PayloadError> {
        let end = self.at.checked_add(b.len()).ok_or(PayloadError::Overflow)?;
        let out = self
            .bytes
            .get_mut(self.at..end)
            .ok_or(PayloadError::Overflow)?;
        out.copy_from_slice(b);
        self.at = end;
        Ok(())
    }
    fn words(&mut self, w: &[u64]) -> Result<(), PayloadError> {
        for x in w {
            if *x >= P {
                return Err(PayloadError::Noncanonical);
            }
            self.put(&x.to_le_bytes())?;
        }
        Ok(())
    }
}
struct Reader<'a> {
    bytes: &'a [u8; 1024],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PayloadError> {
        let end = self.at.checked_add(n).ok_or(PayloadError::Overflow)?;
        let b = self.bytes.get(self.at..end).ok_or(PayloadError::Length)?;
        self.at = end;
        Ok(b)
    }
    fn words<const N: usize>(&mut self) -> Result<[u64; N], PayloadError> {
        let mut w = [0; N];
        for x in &mut w {
            *x = u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| PayloadError::Length)?);
            if *x >= P {
                return Err(PayloadError::Noncanonical);
            }
        }
        Ok(w)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ml_kem::MlKemKeyPair,
        private_note_encryption::{PrivateNoteCiphertext, PrivateNoteContext},
        traits::KemKeyPair,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    fn treasury() -> TreasuryOpening {
        TreasuryOpening {
            policy_key: [4; 5],
            signer_tags: [[1; 7], [2; 7], [3; 7]],
            approved: [1, 1, 0],
            selected_signer: [0, 0, 1],
            intent: core::array::from_fn(|i| i as u64),
        }
    }
    fn payload(state: NoteState) -> PrivateNotePayload {
        let mut p = PrivateNotePayload {
            recipient_index: 17,
            note: NoteOpening {
                value: 25,
                asset_id: 0,
                recipient_key: [3; 4],
                authorization_key: [0; 4],
                rho: [9; 4],
                randomness: [0, 0, 0, 7],
            },
            state,
        };
        let owner = p.expected_owner([6; 32]).unwrap();
        p.note.authorization_key.copy_from_slice(&owner[..4]);
        p.note.randomness[..3].copy_from_slice(&owner[4..]);
        p
    }
    #[test]
    fn private_note_payload_all_states_roundtrip() {
        let h = HtlcOpening {
            nullifier_key: [8; 5],
            hashlock: [11; 32],
            claim_authority: [2; 7],
            refund_authority: [3; 7],
            claim_recipient: [4; 4],
            refund_recipient: [5; 4],
            timeout: 42,
            secret: [12; 32],
            release_secret: 0,
        };
        for state in [
            NoteState::Ordinary { authority: [7; 7] },
            NoteState::Htlc(h),
            NoteState::TreasuryValue(treasury()),
            NoteState::TreasuryAccumulator(treasury()),
        ] {
            let p = payload(state);
            let bytes = p.encode([6; 32]).unwrap();
            let recovered = PrivateNotePayload::decode(&bytes, [6; 32]).unwrap();
            assert_eq!(recovered.recipient_index, 17);
            assert_eq!(
                recovered.encode([6; 32]).unwrap().as_bytes(),
                bytes.as_bytes()
            );
        }
    }
    #[test]
    fn private_note_payload_ordinary_psn1_bytes_remain_unchanged() {
        let p = payload(NoteState::Ordinary { authority: [7; 7] });
        // Retained PSN1 layout: magic, ordinary kind, index, eighteen note
        // words in payload order, seven authority words, then zero padding.
        let mut predecessor = [0u8; 1024];
        predecessor[..4].copy_from_slice(b"PSN1");
        predecessor[5..9].copy_from_slice(&17u32.to_le_bytes());
        let n = &p.note;
        let words = [n.value, n.asset_id]
            .into_iter()
            .chain(n.recipient_key)
            .chain(n.rho)
            .chain(n.randomness)
            .chain(n.authorization_key)
            .chain([7; 7]);
        for (i, word) in words.enumerate() {
            predecessor[9 + 8 * i..17 + 8 * i].copy_from_slice(&word.to_le_bytes());
        }
        let old = PrivateNotePlaintext::from_bytes_exact(&predecessor).unwrap();
        let decoded = PrivateNotePayload::decode(&old, [6; 32]).unwrap();
        assert!(matches!(&decoded.state, NoteState::Ordinary { .. }));
        assert_eq!(decoded.encode([6; 32]).unwrap().as_bytes(), &predecessor);
        assert_eq!(p.encode([6; 32]).unwrap().as_bytes(), &predecessor);

        let mut mislabeled = predecessor;
        mislabeled[..4].copy_from_slice(b"PSN2");
        assert!(matches!(
            PrivateNotePayload::decode(
                &PrivateNotePlaintext::from_bytes_exact(&mislabeled).unwrap(),
                [6; 32]
            ),
            Err(PayloadError::Version)
        ));
    }

    #[test]
    fn private_note_payload_conditional_mode_is_fixed_and_rejects_predecessors() {
        let keys = MlKemKeyPair::generate_deterministic(b"compression-mode-note-test-v2");
        let context = PrivateNoteContext::new([3; 48], [6; 32], 0, [5; 56]).unwrap();
        let h = HtlcOpening {
            nullifier_key: [8; 5],
            hashlock: [11; 32],
            claim_authority: [2; 7],
            refund_authority: [3; 7],
            claim_recipient: [4; 4],
            refund_recipient: [5; 4],
            timeout: 42,
            secret: [12; 32],
            release_secret: 0,
        };
        for state in [
            NoteState::Htlc(h),
            NoteState::TreasuryValue(treasury()),
            NoteState::TreasuryAccumulator(treasury()),
        ] {
            let p = payload(state);
            let bytes = p.encode([6; 32]).unwrap();
            assert_eq!(&bytes.as_bytes()[..4], b"PSN2");
            assert_eq!(
                &bytes.as_bytes()[5..13],
                &POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER.to_le_bytes()
            );
            let decoded = PrivateNotePayload::decode(&bytes, [6; 32]).unwrap();
            assert_eq!(
                decoded.expected_owner([6; 32]).unwrap(),
                p.expected_owner([6; 32]).unwrap()
            );
            assert_eq!(
                decoded.encode([6; 32]).unwrap().as_bytes(),
                bytes.as_bytes()
            );

            // PSN2's eight extra bytes fit in the original 1,024-byte frame;
            // the largest treasury plaintext uses 849 bytes plus zero padding.
            assert_eq!(bytes.as_bytes().len(), 1024);
            assert!(bytes.as_bytes()[849..].iter().all(|b| *b == 0));
            assert_eq!(
                crate::private_note_encryption::PRIVATE_NOTE_CIPHERTEXT_BYTES,
                2608
            );
            let ciphertext = PrivateNoteCiphertext::encrypt(
                &keys.public_key(),
                &context,
                &bytes,
                &mut ChaCha20Rng::from_seed([7; 32]),
            )
            .unwrap();
            assert_eq!(ciphertext.as_bytes().len(), 2608);
            let decrypted = ciphertext.decrypt(keys.secret_key(), &context).unwrap();
            assert_eq!(decrypted.as_bytes(), bytes.as_bytes());
            assert_eq!(
                PrivateNotePayload::decode(&decrypted, [6; 32])
                    .unwrap()
                    .expected_owner([6; 32])
                    .unwrap(),
                p.expected_owner([6; 32]).unwrap()
            );

            let mut predecessor = [0u8; 1024];
            predecessor[..5].copy_from_slice(&bytes.as_bytes()[..5]);
            predecessor[..4].copy_from_slice(b"PSN1");
            predecessor[5..1016].copy_from_slice(&bytes.as_bytes()[13..]);
            assert!(matches!(
                PrivateNotePayload::decode(
                    &PrivateNotePlaintext::from_bytes_exact(&predecessor).unwrap(),
                    [6; 32]
                ),
                Err(PayloadError::Version)
            ));
            let mut wrong_mode = *bytes.as_bytes();
            wrong_mode[5] ^= 1;
            assert!(matches!(
                PrivateNotePayload::decode(
                    &PrivateNotePlaintext::from_bytes_exact(&wrong_mode).unwrap(),
                    [6; 32]
                ),
                Err(PayloadError::Version)
            ));
        }
    }
    fn htlc(release_secret: u64) -> HtlcOpening {
        HtlcOpening {
            nullifier_key: [8; 5],
            hashlock: [11; 32],
            claim_authority: [2; 7],
            refund_authority: [3; 7],
            claim_recipient: [4; 4],
            refund_recipient: [5; 4],
            timeout: 42,
            secret: [12; 32],
            release_secret,
        }
    }
    fn bounded_policy() -> Policy {
        Policy {
            nullifier_key: [8; 5],
            branches: [
                PolicyBranch {
                    enabled: 1,
                    authority: [2; 7],
                    not_before: 42,
                    hash_required: 1,
                    hashlock: [11; 32],
                    release_secret: 1,
                },
                PolicyBranch {
                    enabled: 1,
                    authority: [3; 7],
                    not_before: 90,
                    ..Default::default()
                },
            ],
        }
    }
    #[test]
    fn private_note_payload_releasing_htlc_is_fresh_and_preserves_private_bytes() {
        let private = payload(NoteState::Htlc(htlc(0)));
        let public = payload(NoteState::Htlc(htlc(1)));
        let private_bytes = private.encode([6; 32]).unwrap();
        let public_bytes = public.encode([6; 32]).unwrap();
        assert_eq!(&private_bytes.as_bytes()[..4], b"PSN2");
        assert_eq!(&public_bytes.as_bytes()[..4], b"PSN3");
        assert_ne!(
            private.expected_owner([6; 32]).unwrap(),
            public.expected_owner([6; 32]).unwrap()
        );
        for bytes in [&private_bytes, &public_bytes] {
            let decoded = PrivateNotePayload::decode(bytes, [6; 32]).unwrap();
            assert_eq!(
                decoded.encode([6; 32]).unwrap().as_bytes(),
                bytes.as_bytes()
            );
        }
        // Reproduce the exact retained private PSN2 frame independently. Adding
        // opt-in release never inserts a flag into existing private notes.
        let mut old = Writer {
            bytes: Zeroizing::new([0; 1024]),
            at: 0,
        };
        old.put(b"PSN2").unwrap();
        old.put(&[1]).unwrap();
        old.put(&POSEIDON2_WIDTH16_COMPRESSION_MODE_MARKER.to_le_bytes())
            .unwrap();
        old.put(&17u32.to_le_bytes()).unwrap();
        let n = &private.note;
        old.words(&[n.value, n.asset_id]).unwrap();
        old.words(&n.recipient_key).unwrap();
        old.words(&n.rho).unwrap();
        old.words(&n.randomness).unwrap();
        old.words(&n.authorization_key).unwrap();
        let h = htlc(0);
        old.words(&h.nullifier_key).unwrap();
        old.put(&h.hashlock).unwrap();
        old.words(&h.claim_authority).unwrap();
        old.words(&h.refund_authority).unwrap();
        old.words(&h.claim_recipient).unwrap();
        old.words(&h.refund_recipient).unwrap();
        old.words(&[h.timeout]).unwrap();
        old.put(&h.secret).unwrap();
        assert_eq!(old.at, 449);
        assert_eq!(&old.bytes[..], private_bytes.as_bytes());
        let mut mislabeled = *public_bytes.as_bytes();
        mislabeled[..4].copy_from_slice(b"PSN2");
        assert!(PrivateNotePayload::decode(
            &PrivateNotePlaintext::from_bytes_exact(&mislabeled).unwrap(),
            [6; 32]
        )
        .is_err());
        mislabeled = *public_bytes.as_bytes();
        mislabeled[449..457].fill(0);
        assert!(matches!(
            PrivateNotePayload::decode(
                &PrivateNotePlaintext::from_bytes_exact(&mislabeled).unwrap(),
                [6; 32]
            ),
            Err(PayloadError::Version)
        ));
        let bad = PrivateNotePayload {
            recipient_index: 0,
            note: NoteOpening {
                value: 0,
                asset_id: 0,
                recipient_key: [0; 4],
                authorization_key: [0; 4],
                rho: [0; 4],
                randomness: [0; 4],
            },
            state: NoteState::Htlc(htlc(2)),
        };
        assert!(bad.expected_owner([6; 32]).is_err());
    }
    #[test]
    fn private_note_payload_bounded_policy_fits_fixed_frame_and_checks_identity() {
        let policy = bounded_policy();
        let p = payload(NoteState::Policy(policy.clone()));
        let bytes = p.encode([6; 32]).unwrap();
        assert_eq!(&bytes.as_bytes()[..5], b"PSN3\x04");
        assert!(bytes.as_bytes()[513..].iter().all(|b| *b == 0));
        let recovered = PrivateNotePayload::decode(&bytes, [6; 32]).unwrap();
        assert!(matches!(&recovered.state, NoteState::Policy(actual) if actual == &policy));
        assert_eq!(
            recovered.encode([6; 32]).unwrap().as_bytes(),
            bytes.as_bytes()
        );
        assert_eq!(bytes.as_bytes().len(), 1024);
        assert!(PrivateNotePayload::decode(&bytes, [7; 32]).is_err());
        let mut altered = *bytes.as_bytes();
        altered[..4].copy_from_slice(b"PSN2");
        assert!(matches!(
            PrivateNotePayload::decode(
                &PrivateNotePlaintext::from_bytes_exact(&altered).unwrap(),
                [6; 32]
            ),
            Err(PayloadError::Version)
        ));
        altered = *bytes.as_bytes();
        altered[201..209].copy_from_slice(&2u64.to_le_bytes());
        assert!(PrivateNotePayload::decode(
            &PrivateNotePlaintext::from_bytes_exact(&altered).unwrap(),
            [6; 32]
        )
        .is_err());
        altered = *bytes.as_bytes();
        altered[209..217].copy_from_slice(&0u64.to_le_bytes());
        assert!(PrivateNotePayload::decode(
            &PrivateNotePlaintext::from_bytes_exact(&altered).unwrap(),
            [6; 32]
        )
        .is_err());
        altered = *bytes.as_bytes();
        altered[1023] = 1;
        assert!(matches!(
            PrivateNotePayload::decode(
                &PrivateNotePlaintext::from_bytes_exact(&altered).unwrap(),
                [6; 32]
            ),
            Err(PayloadError::Padding)
        ));
        let mut state = NoteState::Policy(policy);
        state.zeroize();
        assert!(
            matches!(&state, NoteState::Policy(actual) if actual.nullifier_key == [0; 5] && actual.branches == [PolicyBranch::default(), PolicyBranch::default()])
        );
    }
    #[test]
    fn private_note_payload_rejects_padding_owner_and_field() {
        let mut p = payload(NoteState::Ordinary { authority: [7; 7] });
        let valid = p.encode([6; 32]).unwrap();
        p.note.authorization_key[0] ^= 1;
        assert!(matches!(p.encode([6; 32]), Err(PayloadError::Owner)));
        let mut bytes = *valid.as_bytes();
        bytes[1023] = 1;
        assert!(matches!(
            PrivateNotePayload::decode(
                &PrivateNotePlaintext::from_bytes_exact(&bytes).unwrap(),
                [6; 32]
            ),
            Err(PayloadError::Padding)
        ));
        bytes = *valid.as_bytes();
        bytes[9..17].copy_from_slice(&P.to_le_bytes());
        assert!(matches!(
            PrivateNotePayload::decode(
                &PrivateNotePlaintext::from_bytes_exact(&bytes).unwrap(),
                [6; 32]
            ),
            Err(PayloadError::Noncanonical)
        ));
    }
    #[test]
    fn private_note_payload_rejects_invalid_state_and_overflow() {
        let mut t = treasury();
        t.approved[0] = 2;
        let p = PrivateNotePayload {
            recipient_index: 0,
            note: NoteOpening {
                value: 0,
                asset_id: 0,
                recipient_key: [0; 4],
                authorization_key: [0; 4],
                rho: [0; 4],
                randomness: [0; 4],
            },
            state: NoteState::TreasuryAccumulator(t),
        };
        assert!(matches!(p.encode([0; 32]), Err(PayloadError::Range)));
        let mut w = Writer {
            bytes: Zeroizing::new([0; 1024]),
            at: 1023,
        };
        assert_eq!(w.put(&[1, 2]), Err(PayloadError::Overflow));
        let mut r = Reader {
            bytes: &[0; 1024],
            at: 1,
        };
        assert_eq!(r.take(usize::MAX), Err(PayloadError::Overflow));
    }
}
