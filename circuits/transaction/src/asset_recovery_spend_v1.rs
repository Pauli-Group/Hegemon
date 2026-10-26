//! Fresh recoverable-asset relation. No production authority is created here.
//! The caller authenticates every disclosed row field against CURRENT state.
//! Secret-bearing witness types deliberately have no Debug or serde implementation.
//! This opt-in profile credentials the selected spending actor: holder on the
//! holder route, CURRENT delegate commitment on the recovery route. Both output
//! credentials remain holder credentials. A revoked holder credential therefore
//! cannot prevent recovery by a currently credentialed delegate.
//! Holder authorization keys and shared nullifier keys are separate secrets.
#![forbid(unsafe_code)]
use crate::asset_spend_v1::{
    AssetSpendPublic, AssetSpendWitness, ASSET_REFERENCE_WINDOW, BURN, CREDENTIAL_LEAF_DOMAIN,
    CREDENTIAL_NODE_DOMAIN, DUMMY_NULLIFIER_DOMAIN, MINT,
};
use transaction_core::asset_recovery_v1::{self as recovery, RecoveryRowV1};
pub type Digest = [u64; 7];
pub const PUBLIC_WORDS: usize = 182;
pub const RELATION_ID: &str = "Hegemon.AssetRecoverySpend.Credentials4.CompFF01.v1";
pub const PRODUCTION_AUTHORIZED: bool = false;
pub const SOURCE_LOWERING_CERTIFICATE_COMPLETE: bool = false;
pub const BINDING_HEADER: &[u8; 16] = b"HGRECOV1\x01\x00\x00\x00\x00\x00\x00\x00";
fn error(message: &'static str) -> crate::TransactionCircuitError {
    crate::TransactionCircuitError::ConstraintViolation(message)
}
mod types {
    pub const HEIGHT: usize = 16;
    pub const NOTE_ROOT: usize = 17;
    pub const ASSET: usize = 31;
    pub const POLICY_VERSION: usize = 32;
    pub const CREDENTIAL_ROOT: usize = 33;
    pub const CREDENTIAL_DEPTH: usize = 40;
    pub const FROZEN: usize = 41;
    pub const MINT_ENABLED: usize = 42;
    pub const ISSUER: usize = 43;
    pub const OPERATION: usize = 50;
    pub const MAGNITUDE: usize = 51;
    pub const FEE: usize = 52;
    pub const NULLIFIERS: usize = 53;
    pub const COMMITMENTS: usize = 67;
    pub const CIPHERTEXTS: usize = 88;
    pub const POLICY_MODE: usize = 124;
    pub const SECRET_RELEASE: usize = 125;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    pub base: AssetSpendPublic,
    pub row: RecoveryRowV1,
}
impl Public {
    pub fn validate_structure(&self) -> Result<(), crate::TransactionCircuitError> {
        self.base.validate_structure()?;
        self.row
            .validate()
            .map_err(|_| error("recovery row shape"))?;
        if self.base.policy_mode != 0
            || self.base.credential_depth != 4
            || self.base.secret_release != 0
            || self.base.released_secret != [0; 32]
            || self.row.descriptor.asset_id != self.base.asset_id
        {
            return Err(error("recovery spend profile or asset mismatch"));
        }
        Ok(())
    }
    /// Base134, then ALL canonical descriptor31 and controls17 words.
    /// No descriptor/control field is replaced with only its hash.
    pub fn words(&self) -> Result<Vec<u64>, crate::TransactionCircuitError> {
        self.validate_structure()?;
        let mut words = self.base.words().to_vec();
        words.extend(
            recovery::descriptor_words(&self.row.descriptor, self.base.chain_id)
                .map_err(|_| error("recovery descriptor encoding"))?,
        );
        words.extend(
            recovery::controls_words(&self.row.controls)
                .map_err(|_| error("recovery controls encoding"))?,
        );
        if words.len() != PUBLIC_WORDS
            || words
                .iter()
                .any(|w| *w >= hegemon_field::GOLDILOCKS_MODULUS)
        {
            return Err(error("recovery public encoding"));
        }
        Ok(words)
    }
    pub fn binding_bytes(&self) -> Result<Vec<u8>, crate::TransactionCircuitError> {
        let mut bytes = BINDING_HEADER.to_vec();
        bytes.extend(self.words()?.into_iter().flat_map(u64::to_le_bytes));
        Ok(bytes)
    }
}
#[derive(Clone)]
pub struct Witness {
    pub base: AssetSpendWitness,
    pub input_holder_authority: Digest,
    pub input_shared_nf_key: [u64; 5],
    pub output_shared_nf_keys: [[u64; 5]; 2],
    pub delegate_secret: Digest,
    pub use_delegate: u64,
    /// Current delegate credential address; zero on the holder/mint route.
    pub delegate_credential_recipient: [u64; 4],
    pub note_freeze_siblings: [Digest; 32],
}
impl Witness {
    fn words(&self, public: &Public) -> Result<Vec<u64>, crate::TransactionCircuitError> {
        let mut words = self.base.words(&public.base)?;
        words.extend(self.input_holder_authority);
        words.extend(self.input_shared_nf_key);
        words.extend(self.output_shared_nf_keys.into_iter().flatten());
        words.extend(self.delegate_secret);
        words.push(self.use_delegate);
        words.extend(self.note_freeze_siblings.into_iter().flatten());
        words.extend(self.delegate_credential_recipient);
        let active = public.base.operation != MINT;
        let mut append_selector = |enabled: bool, values: &[u64]| {
            let chosen = values.iter().position(|word| *word != 0);
            words
                .extend((0..values.len()).map(|index| u64::from(enabled && chosen == Some(index))));
        };
        append_selector(active, &self.input_holder_authority);
        append_selector(active, &self.input_shared_nf_key);
        for key in &self.output_shared_nf_keys {
            append_selector(true, key);
        }
        for authority in &self.base.output_authorities[..2] {
            append_selector(true, authority);
        }
        append_selector(self.use_delegate == 1, &self.delegate_secret);
        if words
            .iter()
            .any(|w| *w >= hegemon_field::GOLDILOCKS_MODULUS)
        {
            return Err(error("recovery witness noncanonical word"));
        }
        Ok(words)
    }
}

use crate::smallwood_poseidon2_v8_hash_schedule::{
    SMALLWOOD_POSEIDON2_V8_NULLIFIER_DOMAIN as NULLIFIER,
    SMALLWOOD_POSEIDON2_V8_SINGLE_KEY_DOMAIN as SINGLE,
};
use crate::{
    smallwood_engine::SmallwoodArithmetization,
    smallwood_htlc::circuit::{
        boolean, equal, input, nonzero, range, select, HtlcAdapter, HtlcGeometry, Scope, Word,
    },
    smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView},
    TransactionCircuitError,
};
use hegemon_field::PrimeCharacteristicRing;
use transaction_core::{
    constants::{MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG},
    poseidon2_width16::{poseidon2_width16_compress14_ring, poseidon2_width16_sponge_ring},
    stablecoin_poseidon2_v8::STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_COMMITMENT,
};

fn c(value: u64) -> Word {
    Word::from_u64(value)
}
fn arr<const N: usize>() -> [Word; N] {
    core::array::from_fn(|_| input())
}
fn gate(active: Word, left: Word, right: Word) {
    equal(active * (left - right), Word::ZERO)
}
fn gates<const N: usize>(active: Word, left: [Word; N], right: [Word; N]) {
    for index in 0..N {
        gate(active, left[index], right[index]);
    }
}
fn pad(active: Word, words: &[Word]) {
    for &word in words {
        gate(Word::ONE - active, word, Word::ZERO);
    }
}
fn nz(active: Word, word: Word) {
    nonzero(Word::ONE - active + active * word);
}
fn vector_nonzero(active: Word, words: &[Word]) {
    let selectors = words.iter().map(|_| input()).collect::<Vec<_>>();
    for bit in &selectors {
        boolean(*bit);
    }
    equal(selectors.iter().copied().sum(), active);
    nz(
        active,
        words
            .iter()
            .zip(selectors)
            .map(|(word, bit)| *word * bit)
            .sum(),
    );
}
fn hash(domain: u64, words: &[Word]) -> Result<DigestWords, TransactionCircuitError> {
    poseidon2_width16_sponge_ring(domain, words).map_err(|_| error("asset circuit hash shape"))
}
type DigestWords = [Word; 7];
fn key7(key: [Word; 5]) -> DigestWords {
    [
        key[0],
        key[1],
        key[2],
        key[3],
        key[4],
        Word::ZERO,
        Word::ZERO,
    ]
}
fn owner(note: &[Word; 18]) -> DigestWords {
    [
        note[14], note[15], note[16], note[17], note[10], note[11], note[12],
    ]
}

struct InputWords {
    occupied: Word,
    legacy: Word,
    note: [Word; 18],
    position: Word,
    siblings: [DigestWords; 32],
    key: [Word; 5],
    dummy: [Word; 5],
}
impl InputWords {
    fn new() -> Self {
        Self {
            occupied: input(),
            legacy: input(),
            note: arr(),
            position: input(),
            siblings: core::array::from_fn(|_| arr()),
            key: arr(),
            dummy: arr(),
        }
    }
}
struct CredentialWords {
    index: Word,
    expires: Word,
    siblings: Vec<DigestWords>,
}

pub struct AssetRecoverySpendAdapter {
    inner: HtlcAdapter,
}
impl AssetRecoverySpendAdapter {
    pub fn from_public(public: &Public) -> Result<Self, TransactionCircuitError> {
        public.validate_structure()?;
        let words = public.words()?;
        let depth = public.base.credential_depth;
        let scope = Scope::start();
        let p: [Word; PUBLIC_WORDS] = arr();
        for &word in &p[..16] {
            range(word, 32);
        }
        range(p[types::HEIGHT], 48);
        // H+12 is below Goldilocks. Each always-active output constrains both
        // expiry and expiry-(H+12) to 48 bits below; hence H+12 <= expiry <2^48,
        // which also enforces no 48-bit wrap without a redundant range gadget.
        // Policy not_before checks intentionally continue to use H itself.
        let credential_horizon = p[types::HEIGHT] + c(ASSET_REFERENCE_WINDOW);
        range(p[types::ASSET], 32);
        nonzero(p[types::ASSET]);
        range(p[types::POLICY_VERSION], 32);
        equal(p[types::CREDENTIAL_DEPTH], c(u64::from(depth)));
        equal(p[types::FROZEN], Word::ZERO);
        boolean(p[types::MINT_ENABLED]);
        range(p[types::MAGNITUDE], 56);
        range(p[types::FEE], 56);
        for &word in &p[types::CIPHERTEXTS..types::POLICY_MODE] {
            range(word, 32);
        }

        equal(p[types::POLICY_MODE], Word::ZERO);
        {
            for &word in &p[types::SECRET_RELEASE..134] {
                equal(word, Word::ZERO);
            }
        }
        let modes: [Word; 3] = arr();
        for &mode in &modes {
            boolean(mode);
        }
        let [transfer, mint, burn] = modes;
        equal(transfer + mint + burn, Word::ONE);
        equal(p[types::OPERATION], mint + c(2) * burn);
        gate(transfer, p[types::MAGNITUDE], Word::ZERO);
        nz(mint + burn, p[types::MAGNITUDE]);
        gate(mint, p[types::MINT_ENABLED], Word::ONE);

        let inputs: [InputWords; 2] = core::array::from_fn(|_| InputWords::new());
        let outputs: [[Word; 18]; 3] = core::array::from_fn(|_| arr());
        let authorities: [DigestWords; 3] = core::array::from_fn(|_| arr());
        let credentials: [CredentialWords; 3] = core::array::from_fn(|_| CredentialWords {
            index: input(),
            expires: input(),
            siblings: (0..depth).map(|_| arr()).collect(),
        });
        let issuer: DigestWords = arr();
        let issuer_nonzero: DigestWords = arr();
        let input_holder: DigestWords = arr();
        let shared_key: [Word; 5] = arr();
        let output_keys: [[Word; 5]; 2] = core::array::from_fn(|_| arr());
        let delegate_secret: DigestWords = arr();
        let use_delegate = input();
        let freeze_siblings: [DigestWords; 32] = core::array::from_fn(|_| arr());
        let delegate_credential_recipient: [Word; 4] = arr();
        boolean(use_delegate);
        gate(use_delegate, mint, Word::ZERO);
        pad(Word::ONE - mint, &input_holder);
        pad(Word::ONE - mint, &shared_key);
        pad(use_delegate, &delegate_secret);
        pad(use_delegate, &delegate_credential_recipient);
        for sibling in freeze_siblings {
            pad(Word::ONE - mint, &sibling);
        }
        vector_nonzero(Word::ONE - mint, &input_holder);
        vector_nonzero(Word::ONE - mint, &shared_key);
        for key in output_keys {
            vector_nonzero(Word::ONE, &key);
        }
        for authority in &authorities[..2] {
            vector_nonzero(Word::ONE, authority);
        }
        vector_nonzero(use_delegate, &delegate_secret);
        range(p[165], 48);
        boolean(p[173]);
        let maximum = range(p[164], 2);
        let powers = range(p[174], 2);
        for i in 0..2 {
            gate(powers[i], maximum[i], Word::ONE);
        }
        gate(use_delegate, p[173], Word::ZERO);
        gate(use_delegate * transfer, powers[0], Word::ONE);
        gate(use_delegate * burn, powers[1], Word::ONE);
        gates(
            use_delegate,
            hash(recovery::DELEGATE_ACTION, &delegate_secret)?,
            p[166..173].try_into().unwrap(),
        );
        gates(
            (Word::ONE - mint) * (Word::ONE - use_delegate),
            hash(SINGLE, &key7(inputs[0].key))?,
            input_holder,
        );
        // Descriptor fields are public inputs, never witness-selected authority.
        gates::<8>(
            Word::ONE,
            p[134..142].try_into().unwrap(),
            p[..8].try_into().unwrap(),
        );
        equal(p[142], p[types::ASSET]);
        let descriptor = hash(recovery::DESCRIPTOR, &p[134..165])?;
        let recovery_owner = |authority: DigestWords,
                              key: [Word; 5]|
         -> Result<DigestWords, TransactionCircuitError> {
            let mut words = p[..8].to_vec();
            words.push(p[types::ASSET]);
            words.extend_from_slice(&p[143..150]);
            words.extend(authority);
            words.extend(hash(recovery::NF_KEY, &key7(key))?);
            hash(recovery::OWNER, &words)
        };

        equal(inputs[0].occupied, Word::ONE - mint);
        equal(inputs[0].legacy, Word::ZERO);
        equal(inputs[1].occupied, Word::ONE);
        let mut input_authorities = [[Word::ZERO; 7]; 2];
        for slot in 0..2 {
            let note = &inputs[slot];
            boolean(note.occupied);
            boolean(note.legacy);
            range(note.note[0], 56);
            if slot == 0 {
                gate(note.occupied, note.note[1], p[types::ASSET]);
            } else {
                equal(note.note[1], Word::ZERO);
            }
            pad(note.occupied, &note.note);
            pad(note.occupied, &[note.position]);
            for sibling in note.siblings {
                pad(note.occupied, &sibling);
            }
            pad(note.occupied, &note.key);
            pad(Word::ONE - note.occupied, &note.dummy);
            if slot == 0 {
                for word in note.key {
                    gate(use_delegate, word, Word::ZERO);
                }
                nz(note.occupied * (Word::ONE - use_delegate), note.key[0]);
            } else {
                nz(note.occupied, note.key[0]);
            }
            nz(Word::ONE - note.occupied, note.dummy[0]);
            let authority = hash(SINGLE, &key7(note.key))?;
            input_authorities[slot] = if slot == 0 {
                core::array::from_fn(|i| select(use_delegate, input_holder[i], p[166 + i]))
            } else {
                authority
            };
            if slot == 0 {
                gates(
                    note.occupied,
                    owner(&note.note),
                    recovery_owner(input_holder, shared_key)?,
                );
            } else {
                let ordinary = hash(crate::private_spend::ORDINARY_OWNER_DOMAIN, &authority)?;
                gates(
                    note.occupied,
                    owner(&note.note),
                    core::array::from_fn(|i| select(note.legacy, ordinary[i], authority[i])),
                );
            }
            let directions = range(note.position, 32);
            let mut root = hash(NOTE_DOMAIN_TAG, &note.note)?;
            for level in 0..32 {
                let sibling = note.siblings[level];
                let left = core::array::from_fn(|index| {
                    select(directions[level], root[index], sibling[index])
                });
                let right = core::array::from_fn(|index| {
                    select(directions[level], sibling[index], root[index])
                });
                root = poseidon2_width16_compress14_ring(MERKLE_DOMAIN_TAG, &left, &right);
            }
            gates(
                note.occupied,
                root,
                p[types::NOTE_ROOT..types::NOTE_ROOT + 7]
                    .try_into()
                    .unwrap(),
            );
            let nullifier_key = if slot == 0 { shared_key } else { note.key };
            let mut preimage = key7(nullifier_key).to_vec();
            preimage.push(note.position);
            preimage.extend_from_slice(&note.note[6..10]);
            let real = hash(NULLIFIER, &preimage)?;
            let mut dummy_words = p[..8].to_vec();
            dummy_words.extend(note.dummy);
            let dummy = hash(DUMMY_NULLIFIER_DOMAIN, &dummy_words)?;
            gates::<7>(
                Word::ONE,
                core::array::from_fn(|index| select(note.occupied, dummy[index], real[index])),
                p[types::NULLIFIERS + 7 * slot..types::NULLIFIERS + 7 * (slot + 1)]
                    .try_into()
                    .unwrap(),
            );
        }
        let frozen_note = &inputs[0];
        let directions = range(frozen_note.position, 32);
        let mut freeze_root = hash(recovery::EMPTY, &descriptor)?;
        for level in 0..32 {
            let sibling = freeze_siblings[level];
            let left: DigestWords =
                core::array::from_fn(|i| select(directions[level], freeze_root[i], sibling[i]));
            let right: DigestWords =
                core::array::from_fn(|i| select(directions[level], sibling[i], freeze_root[i]));
            freeze_root =
                poseidon2_width16_compress14_ring(recovery::NODE + level as u64, &left, &right);
        }
        gates(
            Word::ONE - mint,
            freeze_root,
            p[175..182].try_into().unwrap(),
        );
        for slot in 0..3 {
            let note = outputs[slot];
            range(note[0], 56);
            equal(
                note[1],
                if slot < 2 {
                    p[types::ASSET]
                } else {
                    Word::ZERO
                },
            );
            if slot < 2 {
                gates(
                    Word::ONE,
                    owner(&note),
                    recovery_owner(authorities[slot], output_keys[slot])?,
                );
            } else {
                gates(
                    Word::ONE,
                    owner(&note),
                    hash(
                        crate::private_spend::ORDINARY_OWNER_DOMAIN,
                        &authorities[slot],
                    )?,
                );
            }
            gates(
                Word::ONE,
                hash(NOTE_DOMAIN_TAG, &note)?,
                p[types::COMMITMENTS + 7 * slot..types::COMMITMENTS + 7 * (slot + 1)]
                    .try_into()
                    .unwrap(),
            );
        }
        // Each term is at most56 bits; either side is below2^58 and hence below
        // Goldilocks. These field equations therefore express integer balances.
        equal(
            inputs[0].note[0] + mint * p[types::MAGNITUDE],
            outputs[0][0] + outputs[1][0] + burn * p[types::MAGNITUDE],
        );
        equal(inputs[1].note[0], outputs[2][0] + p[types::FEE]);

        // Mint has no holder input. Both asset outputs always require a leaf,
        // even when their value is zero or they return change to the sender.
        let input_credential_recipient: [Word; 4] = core::array::from_fn(|i| {
            select(
                use_delegate,
                inputs[0].note[2 + i],
                delegate_credential_recipient[i],
            )
        });
        for slot in 0..3 {
            let active = if slot == 0 {
                Word::ONE - mint
            } else {
                Word::ONE
            };
            let credential = &credentials[slot];
            pad(active, &[credential.index, credential.expires]);
            for sibling in &credential.siblings {
                pad(active, sibling);
            }
            let directions = range(credential.index, depth);
            range(credential.expires, 48);
            // For active slots, a negative difference is a Goldilocks residue
            // above 2^48; the range proof therefore enforces expiry >= H+12.
            range(active * (credential.expires - credential_horizon), 48);
            let (recipient, authority) = if slot == 0 {
                (&input_credential_recipient[..], input_authorities[0])
            } else {
                let output_slot = slot - 1;
                let authority = authorities[output_slot];
                (&outputs[output_slot][2..6], authority)
            };
            let mut leaf_words = vec![p[types::ASSET], p[types::POLICY_VERSION]];
            leaf_words.extend_from_slice(recipient);
            leaf_words.extend(authority);
            leaf_words.push(credential.expires);
            let mut root = hash(CREDENTIAL_LEAF_DOMAIN, &leaf_words)?;
            for (level, sibling) in credential.siblings.iter().enumerate() {
                let left = core::array::from_fn(|index| {
                    select(directions[level], root[index], sibling[index])
                });
                let right = core::array::from_fn(|index| {
                    select(directions[level], sibling[index], root[index])
                });
                root = poseidon2_width16_compress14_ring(
                    CREDENTIAL_NODE_DOMAIN + level as u64,
                    &left,
                    &right,
                );
            }
            gates(
                active,
                root,
                p[types::CREDENTIAL_ROOT..types::CREDENTIAL_ROOT + 7]
                    .try_into()
                    .unwrap(),
            );
        }
        pad(mint, &issuer);
        for &bit in &issuer_nonzero {
            boolean(bit);
        }
        equal(issuer_nonzero.iter().copied().sum(), mint);
        nz(
            mint,
            issuer
                .iter()
                .zip(issuer_nonzero)
                .map(|(word, bit)| *word * bit)
                .sum(),
        );
        let issuer_binding = [
            p[types::ASSET],
            p[types::POLICY_VERSION],
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
            Word::ZERO,
        ];
        gates(
            mint,
            poseidon2_width16_compress14_ring(
                STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_COMMITMENT,
                &issuer,
                &issuer_binding,
            ),
            p[types::ISSUER..types::ISSUER + 7].try_into().unwrap(),
        );

        let mut inner = HtlcAdapter::from_graph(scope.finish());
        for (wire, value) in p.iter().copied().zip(words) {
            inner.bind_public(wire, value);
        }
        // The existing independent source-lowering certificate targets the
        // native relation. It is deliberately not claimed for this asset graph.
        Ok(Self { inner })
    }
    pub fn geometry(&self) -> &HtlcGeometry {
        self.inner.geometry()
    }
    pub fn lower(
        &self,
        public: &Public,
        witness: &Witness,
    ) -> Result<Vec<u64>, TransactionCircuitError> {
        let mut inputs = public.words()?;
        inputs.extend(witness.words(public)?);
        self.inner.evaluate(&inputs)
    }
    pub fn verify_packed_witness(&self, witness: &[u64]) -> Result<(), TransactionCircuitError> {
        self.inner.verify_packed_witness(witness)
    }
}
pub fn compile(
    public: &Public,
    witness: &Witness,
) -> Result<(AssetRecoverySpendAdapter, Vec<u64>), TransactionCircuitError> {
    let adapter = AssetRecoverySpendAdapter::from_public(public)?;
    let packed = adapter.lower(public, witness)?;
    adapter.verify_packed_witness(&packed)?;
    Ok((adapter, packed))
}
impl SmallwoodConstraintAdapter for AssetRecoverySpendAdapter {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::DirectPacked64AssetSpendSha512Smze
    }
    fn row_count(&self) -> usize {
        self.inner.row_count()
    }
    fn packing_factor(&self) -> usize {
        64
    }
    fn constraint_degree(&self) -> usize {
        2
    }
    fn linear_constraint_count(&self) -> usize {
        self.inner.linear_constraint_count()
    }
    fn constraint_count(&self) -> usize {
        self.inner.constraint_count()
    }
    fn linear_constraint_offsets(&self) -> &[u32] {
        self.inner.linear_constraint_offsets()
    }
    fn linear_constraint_indices(&self) -> &[u32] {
        self.inner.linear_constraint_indices()
    }
    fn linear_constraint_coefficients(&self) -> &[u64] {
        self.inner.linear_constraint_coefficients()
    }
    fn linear_targets(&self) -> &[u64] {
        self.inner.linear_targets()
    }
    fn auxiliary_witness_words(&self) -> &[u64] {
        &[]
    }
    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(0)
    }
    fn nonlinear_eval_view<'a>(
        &self,
        point: u64,
        rows: &'a [u64],
        auxiliary: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        self.inner.nonlinear_eval_view(point, rows, auxiliary)
    }
    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        self.inner.compute_constraints_u64(view, out)
    }
}

/// Fresh public binding over the fresh SMZR identity and the unchanged structural profile.
pub const CANDIDATE_PROOF_MAGIC: [u8; 4] = *b"SMZR";
pub const MAX_CANDIDATE_PROOF_BYTES: usize = crate::asset_recovery_backend_v1::MAX_PROOF_BYTES;
pub fn candidate_proof_size_hint(public: &Public) -> Result<usize, TransactionCircuitError> {
    crate::asset_recovery_backend_v1::projected_bytes(&AssetRecoverySpendAdapter::from_public(
        public,
    )?)
}
pub fn prove_candidate(
    public: &Public,
    witness: &Witness,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let (adapter, packed) = compile(public, witness)?;
    crate::asset_recovery_backend_v1::prove(
        &adapter,
        &packed,
        &public.binding_bytes()?,
        &relation_digest(),
    )
}
pub fn verify_candidate(public: &Public, proof: &[u8]) -> Result<(), TransactionCircuitError> {
    crate::asset_recovery_backend_v1::verify(
        &AssetRecoverySpendAdapter::from_public(public)?,
        &public.binding_bytes()?,
        &relation_digest(),
        proof,
    )
}
pub fn geometry_receipt(public: &Public) -> Result<serde_json::Value, TransactionCircuitError> {
    let adapter = AssetRecoverySpendAdapter::from_public(public)?;
    let mut value = crate::asset_recovery_backend_v1::geometry_receipt(&adapter)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| error("recovery geometry shape"))?;
    object.insert("relation_id".into(), serde_json::json!(RELATION_ID));
    object.insert("public_words".into(), serde_json::json!(PUBLIC_WORDS));
    object.insert(
        "source_lowering_certificate_complete".into(),
        serde_json::json!(false),
    );
    Ok(value)
}
/// Exact additive graph plus its core and unchanged backend dependency closure.
pub fn relation_digest() -> [u8; 64] {
    use sha2::{Digest as _, Sha512};
    static DIGEST: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut h = Sha512::new();
        h.update(b"Hegemon.AssetRecoverySpend.SourceManifest.v1");
        h.update(RELATION_ID.as_bytes());
        for (name, bytes) in [
            (
                "asset_recovery_spend_v1.rs",
                include_bytes!("asset_recovery_spend_v1.rs").as_slice(),
            ),
            (
                "asset_recovery_v1.rs",
                include_bytes!("../../transaction-core/src/asset_recovery_v1.rs").as_slice(),
            ),
        ] {
            h.update((name.len() as u64).to_le_bytes());
            h.update(name.as_bytes());
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        h.update(include_bytes!("asset_recovery_backend_v1.rs"));
        h.update(crate::asset_spend_v1::relation_digest());
        h.finalize().into()
    })
}

/// Disposable source fixtures only; absent from normal production builds.
#[cfg(any(test, feature = "private-spend-dev-artifacts"))]
pub mod fixtures {
    use super::*;
    pub fn fixture(
        operation: u8,
        delegate: bool,
    ) -> Result<(Public, Witness), TransactionCircuitError> {
        let (mut base, mut witness) = crate::asset_spend_v1::fixtures::fixture(operation, 4)?;
        let holder = transaction_core::poseidon2_width16::poseidon2_width16_sponge(
            SINGLE,
            &key_words(witness.inputs[0].spend_key),
        )
        .map_err(|_| error("recovery fixture authority"))?
        .map(|w| w.as_canonical_u64());
        let descriptor = recovery::RecoveryDescriptorV1 {
            asset_id: base.asset_id,
            stable_policy_id: [81; 7],
            policy_admin_commitment: [82; 7],
            archive_key_commitment: [83; 7],
            maximum_powers: recovery::RecoveryPowersV1 {
                transfer: true,
                burn: true,
            },
        };
        let defaults = recovery::freeze_defaults(&descriptor, base.chain_id)
            .map_err(|_| error("recovery fixture defaults"))?;
        let secret = [84; 7];
        let controls = recovery::RecoveryControlsV1 {
            epoch: 1,
            delegate_action_commitment: recovery::delegate_action_commitment(secret)
                .map_err(|_| error("recovery fixture delegate"))?,
            revoked: false,
            powers: recovery::RecoveryPowersV1 {
                transfer: true,
                burn: true,
            },
            note_freeze_root: defaults[32],
        };
        let shared = [31, 32, 33, 34, 35];
        let output_keys = [[41, 42, 43, 44, 45], [51, 52, 53, 54, 55]];
        if operation != MINT {
            let owner = recovery::recovery_owner(
                base.chain_id,
                base.asset_id,
                descriptor.stable_policy_id,
                holder,
                shared,
            )
            .map_err(|_| error("recovery fixture input owner"))?;
            crate::private_spend::set_note_owner(&mut witness.inputs[0].note, owner);
        }
        for i in 0..2 {
            let owner = recovery::recovery_owner(
                base.chain_id,
                base.asset_id,
                descriptor.stable_policy_id,
                witness.output_authorities[i],
                output_keys[i],
            )
            .map_err(|_| error("recovery fixture output owner"))?;
            crate::private_spend::set_note_owner(&mut witness.outputs[i], owner);
        }
        crate::asset_spend_v1::fixtures::rebind_inputs(&mut base, &mut witness)?;
        for i in 0..3 {
            base.commitments[i] = crate::private_spend::note_commitment(witness.outputs[i])?;
        }
        if operation != MINT {
            base.nullifiers[0] = recovery::recovery_nullifier(
                shared,
                witness.inputs[0].position,
                witness.inputs[0].note.rho,
            )
            .map_err(|_| error("recovery fixture nullifier"))?;
        }
        // Rebuild holder credentials before replacing the selected input leaf.
        crate::asset_spend_v1::fixtures::rebind_credentials(&mut base, &mut witness)?;
        if delegate && operation != MINT {
            let selected = controls.delegate_action_commitment;
            let leaves = [
                crate::asset_spend_v1::credential_leaf(
                    base.asset_id,
                    base.policy_version,
                    [85; 4],
                    selected,
                    witness.credentials[0].expires_at,
                )?,
                crate::asset_spend_v1::credential_leaf(
                    base.asset_id,
                    base.policy_version,
                    witness.outputs[0].recipient_key,
                    witness.output_authorities[0],
                    witness.credentials[1].expires_at,
                )?,
                crate::asset_spend_v1::credential_leaf(
                    base.asset_id,
                    base.policy_version,
                    witness.outputs[1].recipient_key,
                    witness.output_authorities[1],
                    witness.credentials[2].expires_at,
                )?,
            ];
            let mut layer = [[0; 7]; 16];
            layer[..3].copy_from_slice(&leaves);
            let mut paths: [Vec<Digest>; 3] = core::array::from_fn(|_| Vec::new());
            let mut width = 16;
            for level in 0..4 {
                for i in 0..3 {
                    paths[i].push(layer[(i >> level) ^ 1]);
                }
                for i in 0..width / 2 {
                    layer[i] = crate::asset_spend_v1::credential_node(
                        level,
                        layer[2 * i],
                        layer[2 * i + 1],
                    )?;
                }
                width /= 2;
            }
            base.credential_root = layer[0];
            for i in 0..3 {
                witness.credentials[i].siblings = paths[i].clone();
            }
        }
        if delegate {
            witness.inputs[0].spend_key = [0; 5];
        }
        let result = Witness {
            base: witness,
            input_holder_authority: if operation == MINT { [0; 7] } else { holder },
            input_shared_nf_key: if operation == MINT { [0; 5] } else { shared },
            output_shared_nf_keys: output_keys,
            delegate_secret: if delegate { secret } else { [0; 7] },
            use_delegate: delegate as u64,
            delegate_credential_recipient: if delegate { [85; 4] } else { [0; 4] },
            note_freeze_siblings: if operation == MINT {
                [[0; 7]; 32]
            } else {
                defaults[..32].try_into().unwrap()
            },
        };
        Ok((
            Public {
                base,
                row: RecoveryRowV1 {
                    descriptor,
                    controls,
                },
            },
            result,
        ))
    }
    fn key_words(key: [u64; 5]) -> Vec<transaction_core::poseidon2_width16::Felt> {
        use transaction_core::poseidon2_width16::Felt;
        [key[0], key[1], key[2], key[3], key[4], 0, 0]
            .into_iter()
            .map(Felt::from_u64)
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn holder_delegate_and_mint_compile_with_shared_global_nf_domain() {
        for (operation, delegate) in [(0, false), (0, true), (BURN, true), (MINT, false)] {
            let (public, witness) = fixtures::fixture(operation, delegate).unwrap();
            assert_eq!(public.words().unwrap().len(), PUBLIC_WORDS);
            compile(&public, &witness).unwrap();
        }
    }
    #[test]
    fn current_revoke_freeze_powers_and_target_path_are_mandatory() {
        let (public, witness) = fixtures::fixture(0, true).unwrap();
        let mut altered = public.clone();
        altered.row.controls.revoked = true;
        assert!(compile(&altered, &witness).is_err());
        altered = public.clone();
        altered.row.controls.powers.transfer = false;
        assert!(compile(&altered, &witness).is_err());
        altered = public.clone();
        altered.base.frozen = true;
        assert!(compile(&altered, &witness).is_err());
        let mut bad_path = witness.clone();
        bad_path.note_freeze_siblings[0][0] ^= 1;
        assert!(compile(&public, &bad_path).is_err());
    }
    #[test]
    fn delegate_cannot_mint_or_spend_without_current_credential() {
        let (mint, witness) = fixtures::fixture(MINT, true).unwrap();
        assert!(compile(&mint, &witness).is_err());
        let (public, mut witness) = fixtures::fixture(0, true).unwrap();
        witness.delegate_credential_recipient[0] ^= 1;
        assert!(compile(&public, &witness).is_err());
        witness.delegate_credential_recipient[0] ^= 1;
        witness.base.credentials[0].siblings[0][0] ^= 1;
        assert!(compile(&public, &witness).is_err());
        let (holder_public, mut holder_witness) = fixtures::fixture(0, false).unwrap();
        holder_witness.delegate_credential_recipient = [85; 4];
        assert!(compile(&holder_public, &holder_witness).is_err());
    }
}

/// Exact fresh SMZR frame readback; never reinterpret old SMZE proof bytes.
pub fn proof_wire_receipt(proof: &[u8]) -> Result<serde_json::Value, TransactionCircuitError> {
    crate::asset_recovery_backend_v1::wire_receipt(proof)
}
