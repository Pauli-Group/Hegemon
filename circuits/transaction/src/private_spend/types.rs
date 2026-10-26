//! Fixed native-only private spend inputs. No secret type implements Debug or serde.
pub type Digest = [u64; 7];
pub type Key = [u64; 5];
pub type Note = crate::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8NoteOpening;
pub const PUBLIC_WORDS: usize = 86;
pub const INTENT_WORDS: usize = 54;
pub const CIPHERTEXT_BYTES: usize = 2608;
pub const RELATION_ID: &str = "Hegemon.PrivateSpend.BoundedPolicy.CompFF01.Packed.v4";
pub const PRODUCTION_AUTHORIZED: bool = false;
// New successor-owned domains. Existing note, Merkle, real-nullifier and legacy
// funding owner preimages retain their original domains and exact encodings.
pub const ORDINARY_OWNER_DOMAIN: u64 = 0x5053_4f57_4e52_0001;
pub const DUMMY_NULLIFIER_DOMAIN: u64 = 0x5053_444e_554c_0001;
pub const HTLC_POLICY_DOMAIN: u64 = 0x5053_4850_4f4c_0001;
pub const HTLC_OWNER_DOMAIN: u64 = 0x5053_484f_574e_0001;
pub const HTLC_RELEASE_OWNER_DOMAIN: u64 = 0x5053_4852_454c_0001;
pub use transaction_core::bounded_policy::{Branch as PolicyBranch, Policy as BoundedPolicy};
pub const ACCUMULATOR_DOMAIN: u64 = 0x5053_4143_4355_0001;
pub const INTENT_DOMAIN: u64 = 0x5053_494e_544e_0001;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrivateSpendPublic {
    pub chain_id: [u8; 32],
    pub reference_parent_hash: [u8; 32],
    pub reference_parent_height: u64,
    pub merkle_root: Digest,
    pub fee: u64,
    pub nullifiers: [Digest; 2],
    pub commitments: [Digest; 2],
    pub ciphertext_commitments: [[u8; 48]; 2],
    /// Fixed public disclosure extension; zero mode requires zero bytes.
    pub secret_release: u64,
    pub released_secret: [u8; 32],
}
impl PrivateSpendPublic {
    pub fn binding_bytes(&self) -> Vec<u8> {
        self.words()
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect()
    }
    pub fn words(&self) -> [u64; PUBLIC_WORDS] {
        let mut w = Vec::with_capacity(PUBLIC_WORDS);
        append_bytes(&mut w, &self.chain_id);
        append_bytes(&mut w, &self.reference_parent_hash);
        w.push(self.reference_parent_height);
        w.extend(self.merkle_root);
        w.push(self.fee);
        w.extend(self.nullifiers.into_iter().flatten());
        w.extend(self.commitments.into_iter().flatten());
        for c in &self.ciphertext_commitments {
            append_bytes(&mut w, c);
        }
        w.push(self.secret_release);
        append_bytes(&mut w, &self.released_secret);
        w.try_into().expect("fixed public schema")
    }
    pub fn intent_words(&self) -> [u64; INTENT_WORDS] {
        let p = self.words();
        let mut w = Vec::with_capacity(INTENT_WORDS);
        w.extend_from_slice(&p[..8]); // chain
        w.push(p[24]); // exact final fee
        w.extend_from_slice(&p[25..32]); // value-note nullifier only
        w.extend_from_slice(&p[39..77]); // both commitments and ciphertext bindings
        w.try_into().expect("fixed intent schema")
    }
}
pub(crate) fn append_bytes(out: &mut Vec<u64>, bytes: &[u8]) {
    for b in bytes.chunks_exact(4) {
        out.push(u32::from_le_bytes(b.try_into().unwrap()) as u64);
    }
}
pub(crate) fn note_words(n: Note) -> [u64; 18] {
    [
        n.value,
        n.asset_id,
        n.recipient_key[0],
        n.recipient_key[1],
        n.recipient_key[2],
        n.recipient_key[3],
        n.rho[0],
        n.rho[1],
        n.rho[2],
        n.rho[3],
        n.randomness[0],
        n.randomness[1],
        n.randomness[2],
        n.randomness[3],
        n.authorization_key[0],
        n.authorization_key[1],
        n.authorization_key[2],
        n.authorization_key[3],
    ]
}
pub fn set_note_owner(note: &mut Note, owner: Digest) {
    note.authorization_key.copy_from_slice(&owner[..4]);
    note.randomness[..3].copy_from_slice(&owner[4..]);
}
#[derive(Clone)]
pub struct PrivateInput {
    pub occupied: u64,
    pub legacy_ordinary: u64,
    pub note: Note,
    pub position: u32,
    pub siblings: [Digest; 32],
    pub spend_key: Key,
    pub dummy_secret: Key,
}
impl Default for PrivateInput {
    fn default() -> Self {
        Self {
            occupied: 0,
            legacy_ordinary: 0,
            note: Note::ZERO,
            position: 0,
            siblings: [[0; 7]; 32],
            spend_key: [0; 5],
            dummy_secret: [0; 5],
        }
    }
}
#[derive(Clone, Default)]
pub struct TreasuryOpening {
    pub policy_key: Key,
    pub signer_tags: [Digest; 3],
    pub approved: [u64; 3],
    pub selected_signer: [u64; 3],
    pub intent: Vec<u64>, // exactly INTENT_WORDS; fixed graph never reads its length
}
#[derive(Clone, Default)]
pub struct PrivateHtlcOpening {
    pub nullifier_key: Key,
    pub hashlock: [u8; 32],
    pub claim_authority: Digest,
    pub refund_authority: Digest,
    pub claim_recipient: [u64; 4],
    pub refund_recipient: [u64; 4],
    pub timeout: u64,
    pub secret: [u8; 32],
    /// Committed at lock creation; a releasing claim cannot suppress disclosure.
    pub release_secret: u64,
}
/// Private fixed-size composition controls. Each enabled branch is one key AND
/// a minimum reference-parent height AND an optional SHA256 preimage. Branches OR.
#[derive(Clone, Default)]
pub struct PrivatePolicyOpening {
    pub create: u64,
    pub spend: u64,
    pub input: BoundedPolicy,
    pub output: BoundedPolicy,
    pub selected: [u64; 2],
    pub secret: [u8; 32],
}
impl PrivatePolicyOpening {
    fn append_policy(v: &mut Vec<u64>, policy: &BoundedPolicy) {
        v.extend(policy.nullifier_key);
        for b in &policy.branches {
            v.push(b.enabled);
            v.extend(b.authority);
            v.extend([b.not_before, b.hash_required]);
            append_bytes(v, &b.hashlock);
            v.push(b.release_secret);
            let chosen = b.authority.iter().position(|word| *word != 0);
            v.extend((0..7).map(|j| u64::from(b.enabled == 1 && chosen == Some(j))));
        }
    }
    pub(crate) fn append_words(&self, v: &mut Vec<u64>) {
        v.extend([self.create, self.spend]);
        Self::append_policy(v, &self.input);
        Self::append_policy(v, &self.output);
        v.extend(self.selected);
        v.extend((0..256).map(|i| ((self.secret[i / 8] >> (i % 8)) & 1) as u64));
    }
}
#[derive(Clone)]
pub struct PrivateSpendWitness {
    /// Ordinary, approval, final, lock, claim, refund: exact private one-hot bits.
    pub selectors: [u64; 6],
    pub inputs: [PrivateInput; 2],
    pub outputs: [Note; 2],
    /// Full recipient authorization digests, not recipient secret keys.
    pub output_authorities: [Digest; 2],
    pub treasury: TreasuryOpening,
    pub htlc: PrivateHtlcOpening,
    pub policy: PrivatePolicyOpening,
}
impl PrivateSpendWitness {
    pub(crate) fn words(&self) -> Result<Vec<u64>, crate::TransactionCircuitError> {
        if self.treasury.intent.len() != INTENT_WORDS {
            return Err(super::error("private spend intent length"));
        }
        let mut v = self.selectors.to_vec();
        for i in &self.inputs {
            v.extend([i.occupied, i.legacy_ordinary]);
            v.extend(note_words(i.note));
            v.push(i.position as u64);
            v.extend(i.siblings.into_iter().flatten());
            v.extend(i.spend_key);
            v.extend(i.dummy_secret);
        }
        for n in self.outputs {
            v.extend(note_words(n));
        }
        v.extend(self.output_authorities.into_iter().flatten());
        v.extend(self.treasury.policy_key);
        v.extend(self.treasury.signer_tags.into_iter().flatten());
        // Auxiliary first-nonzero-limb selectors; independently constrained.
        for tag in self.treasury.signer_tags {
            let chosen = tag.iter().position(|word| *word != 0);
            v.extend((0..7).map(|i| u64::from(chosen == Some(i))));
        }
        for i in 0..3 {
            for j in 0..i {
                let chosen = (0..7)
                    .find(|k| self.treasury.signer_tags[i][*k] != self.treasury.signer_tags[j][*k]);
                v.extend((0..7).map(|k| u64::from(chosen == Some(k))));
            }
        }
        v.extend(self.treasury.approved);
        v.extend(self.treasury.selected_signer);
        v.extend(&self.treasury.intent);
        v.extend(self.htlc.nullifier_key);
        append_bytes(&mut v, &self.htlc.hashlock);
        v.extend(self.htlc.claim_authority);
        v.extend(self.htlc.refund_authority);
        v.extend(self.htlc.claim_recipient);
        v.extend(self.htlc.refund_recipient);
        v.push(self.htlc.timeout);
        v.extend((0..256).map(|i| ((self.htlc.secret[i / 8] >> (i % 8)) & 1) as u64));
        v.push(self.htlc.release_secret);
        self.policy.append_words(&mut v);
        Ok(v)
    }
}
