//! Opt-in recovery capsule correctness prototype; no native admission authority.
//!
//! Compact22 encrypts the 22 independent material limbs and reconstructs asset
//! and the seven owner-embedding limbs from authenticated public context. All 30
//! witness limbs and the complete note commitment remain constrained.
//! The admitted SMRC bundle contains two source-separated SMZR proofs. Each
//! repeats all opening/owner/archive/KDF checks and binds all public82 words;
//! only ChaCha bytes0..128/counter1 versus128..176/counter3 are split.
//! Agreement of the two existential openings uses the retained note/archive
//! commitment binding assumptions; source framing alone is not that argument.
//!
//! The relation proves encryption of the exact recoverable note material, not
//! availability or encryption privacy. SHA-derived-key/ChaCha composition in a
//! shared QRO, archive custody, and the new graph's compiler/security refinement
//! remain separate obligations. This is raw ChaCha20 with a proof-bound context,
//! not a generic AEAD. Reusing one archive secret requires unique note contexts;
//! the surrounding note protocol must enforce fresh note randomness/commitments.
//!
//! Secrets/material deliberately have no Debug/serde/Clone implementation. The
//! transaction crate has no zeroize dependency: callers own secret lifecycle;
//! local fill(0) calls are best effort and do not promise compiler-safe erasure.
#![forbid(unsafe_code)]

use crate::{
    asset_recovery_chacha_v1::{chacha20_xor, chacha20_xor_reference},
    smallwood_engine::SmallwoodArithmetization,
    smallwood_htlc::{
        circuit::{boolean, equal, input, nonzero, range, Scope, Word},
        sha,
    },
    smallwood_htlc::{HtlcAdapter, HtlcGeometry},
    smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView},
    TransactionCircuitError,
};
use hegemon_field::{PrimeCharacteristicRing, GOLDILOCKS_MODULUS as P};
use sha2::{Digest as _, Sha256};
use transaction_core::{
    asset_recovery_v1 as recovery,
    constants::NOTE_DOMAIN_TAG,
    poseidon2_width16::{poseidon2_width16_sponge, poseidon2_width16_sponge_ring, Felt},
};

pub type Digest = [u64; 7];
pub const PUBLIC_WORDS: usize = 82;
pub const MATERIAL_WORDS: usize = 30;
pub const COMPACT_MATERIAL_WORDS: usize = 22;
pub const CIPHERTEXT_BYTES: usize = COMPACT_MATERIAL_WORDS * 8;
/// Full note18/holder7/shared-key5 witness indices serialized into the capsule.
/// Asset1 and owner embedding10..13/14..18 are reconstructed, never trusted.
const COMPACT_INDICES: [usize; COMPACT_MATERIAL_WORDS] = [
    0, 2, 3, 4, 5, 6, 7, 8, 9, 13, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
];
pub const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
pub const PROOF_MAGIC: [u8; 4] = *b"SMRC";
pub const SEGMENT_COUNT: usize = 2;
pub const BUNDLE_HEADER_BYTES: usize = 16;
pub const MAX_CAPSULE_BUNDLE_BYTES: usize = BUNDLE_HEADER_BYTES + SEGMENT_COUNT * MAX_PROOF_BYTES;
const BUNDLE_VERSION: u16 = 1;
pub const PRODUCTION_AUTHORIZED: bool = false;
pub const SOURCE_LOWERING_CERTIFICATE_COMPLETE: bool = false;
pub const RELATION_ID: &str =
    "Hegemon.AssetRecoveryCapsule.Compact22.ChaCha20.Segments2.Correctness.v2";
const CONTEXT_DOMAIN: &[u8] = b"Hegemon.AssetRecovery.CapsuleContext.Compact22.Segments2.v2";
const ASSET: usize = 8;
const POLICY: usize = 9;
const ARCHIVE: usize = 16;
const CM: usize = 23;
const CONTEXT: usize = 30;
const CT: usize = 38;

fn error(s: &'static str) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolation(s)
}
fn canonical(words: &[u64]) -> Result<(), TransactionCircuitError> {
    if words.iter().any(|v| *v >= P) {
        return Err(error("recovery capsule noncanonical field word"));
    }
    Ok(())
}
fn valid_digest(d: &Digest) -> Result<(), TransactionCircuitError> {
    canonical(d)?;
    if *d == [0; 7] {
        return Err(error("recovery capsule zero digest"));
    }
    Ok(())
}
fn le32(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64)
        .collect()
}
fn host_hash(domain: u64, words: &[u64]) -> Result<Digest, TransactionCircuitError> {
    canonical(words)?;
    poseidon2_width16_sponge(
        domain,
        &words
            .iter()
            .copied()
            .map(Felt::from_u64)
            .collect::<Vec<_>>(),
    )
    .map(|d| d.map(|f| f.as_canonical_u64()))
    .map_err(|_| error("recovery capsule hash"))
}

#[derive(Clone, PartialEq, Eq)]
pub struct AssetRecoveryCapsulePublicV1 {
    pub chain_id: [u8; 32],
    pub asset_id: u32,
    pub stable_policy_id: Digest,
    pub archive_key_commitment: Digest,
    pub note_commitment: Digest,
    pub ciphertext: [u8; CIPHERTEXT_BYTES],
}
impl AssetRecoveryCapsulePublicV1 {
    pub fn context_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(CONTEXT_DOMAIN);
        h.update(self.chain_id);
        h.update(self.asset_id.to_le_bytes());
        for word in self.stable_policy_id.iter().chain(&self.note_commitment) {
            h.update(word.to_le_bytes());
        }
        h.finalize().into()
    }
    /// Digest words are derived here; no externally supplied digest is accepted.
    pub fn words(&self) -> Result<[u64; PUBLIC_WORDS], TransactionCircuitError> {
        if self.asset_id == 0 {
            return Err(error("recovery capsule native asset"));
        }
        for d in [
            &self.stable_policy_id,
            &self.archive_key_commitment,
            &self.note_commitment,
        ] {
            valid_digest(d)?;
        }
        let mut w = le32(&self.chain_id);
        w.push(self.asset_id as u64);
        w.extend(self.stable_policy_id);
        w.extend(self.archive_key_commitment);
        w.extend(self.note_commitment);
        w.extend(le32(&self.context_digest()));
        w.extend(le32(&self.ciphertext));
        Ok(w.try_into().expect("82 capsule words"))
    }
    /// Shared recovery backend route2. Header/route are transcript binding only.
    pub fn binding_bytes(&self) -> Result<Vec<u8>, TransactionCircuitError> {
        let mut bytes = Vec::with_capacity(16 + PUBLIC_WORDS * 8);
        bytes.extend_from_slice(b"HGRECOV1");
        bytes.extend_from_slice(&2u64.to_le_bytes());
        for word in self.words()? {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        Ok(bytes)
    }
}

/// Exactly note18, holder authority7, independent shared-nullifier key5.
/// Contains neither the holder's ordinary spend secret nor a delegate secret.
pub struct AssetRecoveryCapsuleWitnessV1 {
    pub archive_secret: [u8; 32],
    pub material: [u64; MATERIAL_WORDS],
}

fn validate_material(
    public: &AssetRecoveryCapsulePublicV1,
    m: &[u64; MATERIAL_WORDS],
) -> Result<(), TransactionCircuitError> {
    public.words()?;
    canonical(m)?;
    if m[0] >= (1u64 << 56) || m[1] != public.asset_id as u64 {
        return Err(error("recovery capsule note amount/asset"));
    }
    let owner = recovery::recovery_owner(
        public.chain_id,
        public.asset_id,
        public.stable_policy_id,
        m[18..25].try_into().unwrap(),
        m[25..30].try_into().unwrap(),
    )
    .map_err(|_| error("recovery capsule recovery owner"))?;
    if owner != [m[14], m[15], m[16], m[17], m[10], m[11], m[12]] {
        return Err(error("recovery capsule owner embedding"));
    }
    if host_hash(NOTE_DOMAIN_TAG, &m[..18])? != public.note_commitment {
        return Err(error("recovery capsule note commitment"));
    }
    Ok(())
}
fn derived_key(secret: &[u8; 32], context: [u8; 32]) -> [u8; 32] {
    let mut mixed: [u8; 32] = core::array::from_fn(|i| secret[i] ^ context[i]);
    let key = Sha256::digest(mixed).into();
    mixed.fill(0);
    key
}
fn material_bytes(m: &[u64; MATERIAL_WORDS]) -> [u8; CIPHERTEXT_BYTES] {
    core::array::from_fn(|i| m[COMPACT_INDICES[i / 8]].to_le_bytes()[i % 8])
}
/// Host construction; the enclosing protocol must authenticate this archive
/// commitment against its immutable opt-in descriptor and require the proof.
pub fn encrypt(
    chain_id: [u8; 32],
    asset_id: u32,
    stable_policy_id: Digest,
    archive_secret: &[u8; 32],
    material: &[u64; MATERIAL_WORDS],
) -> Result<AssetRecoveryCapsulePublicV1, TransactionCircuitError> {
    let mut public = AssetRecoveryCapsulePublicV1 {
        chain_id,
        asset_id,
        stable_policy_id,
        archive_key_commitment: recovery::archive_key_commitment(archive_secret)
            .map_err(|_| error("recovery capsule archive commitment"))?,
        note_commitment: host_hash(NOTE_DOMAIN_TAG, &material[..18])?,
        ciphertext: [0; CIPHERTEXT_BYTES],
    };
    validate_material(&public, material)?;
    let mut key = derived_key(archive_secret, public.context_digest());
    let mut plain = material_bytes(material);
    let cipher = chacha20_xor_reference(&key, &[0; 12], 1, &plain);
    key.fill(0);
    plain.fill(0);
    public.ciphertext = cipher
        .map_err(error)?
        .try_into()
        .expect("176 ciphertext bytes");
    Ok(public)
}
/// Returns secret material for caller-managed storage/erasure. This validates the
/// opening but does not verify a capsule proof, descriptor or chain inclusion.
pub fn decrypt(
    public: &AssetRecoveryCapsulePublicV1,
    archive_secret: &[u8; 32],
) -> Result<[u64; MATERIAL_WORDS], TransactionCircuitError> {
    public.words()?;
    if recovery::archive_key_commitment(archive_secret)
        .map_err(|_| error("recovery capsule archive commitment"))?
        != public.archive_key_commitment
    {
        return Err(error("recovery capsule wrong archive key"));
    }
    let mut key = derived_key(archive_secret, public.context_digest());
    let plain = chacha20_xor_reference(&key, &[0; 12], 1, &public.ciphertext);
    key.fill(0);
    let mut plain = plain.map_err(error)?;
    let mut material = [0; MATERIAL_WORDS];
    for (index, bytes) in COMPACT_INDICES.into_iter().zip(plain.chunks_exact(8)) {
        material[index] = u64::from_le_bytes(bytes.try_into().unwrap());
    }
    plain.fill(0);
    material[1] = public.asset_id as u64;
    // The omitted seven limbs are the exact full owner embedded in the note.
    // Derive it from authenticated context and the transmitted holder/shared key,
    // then validate the COMPLETE note and commitment, including canonical limbs.
    let rebuilt = (|| {
        canonical(&material)?;
        let owner = recovery::recovery_owner(
            public.chain_id,
            public.asset_id,
            public.stable_policy_id,
            material[18..25].try_into().unwrap(),
            material[25..30].try_into().unwrap(),
        )
        .map_err(|_| error("recovery capsule recovery owner"))?;
        material[14..18].copy_from_slice(&owner[..4]);
        material[10..13].copy_from_slice(&owner[4..]);
        validate_material(public, &material)
    })();
    match rebuilt {
        Ok(()) => Ok(material),
        Err(e) => {
            material.fill(0);
            Err(e)
        }
    }
}

fn c(n: u64) -> Word {
    Word::from_u64(n)
}
fn pack(bits: &[Word]) -> Word {
    bits.iter()
        .enumerate()
        .fold(Word::ZERO, |w, (i, b)| w + *b * c(1u64 << i))
}
/// p=ffffffff00000001: upper32 allones is allowed ONLY with lower32 zero.
/// Combined with Boolean bits and recomposition this excludes every x+p alias.
fn canonical_bit_bound(bits: &[Word; 64]) {
    let upper_all_ones: Word = bits[32..].iter().copied().product();
    for bit in &bits[..32] {
        equal(upper_all_ones * *bit, Word::ZERO);
    }
}
fn canonical_bits(word: Word) -> [Word; 64] {
    let bits: [Word; 64] = range(word, 64).try_into().unwrap();
    canonical_bit_bound(&bits);
    bits
}
fn some_bit(bits: impl Iterator<Item = Word>) {
    equal(bits.map(|b| Word::ONE - b).product(), Word::ZERO);
}
fn hash(domain: u64, words: &[Word]) -> Result<[Word; 7], TransactionCircuitError> {
    poseidon2_width16_sponge_ring(domain, words).map_err(|_| error("recovery capsule graph hash"))
}

pub struct AssetRecoveryCapsuleAdapterV1 {
    inner: HtlcAdapter,
}
impl AssetRecoveryCapsuleAdapterV1 {
    pub fn from_public(
        public: &AssetRecoveryCapsulePublicV1,
    ) -> Result<Self, TransactionCircuitError> {
        Self::from_public_selection(public, None)
    }
    pub fn from_public_segment(
        public: &AssetRecoveryCapsulePublicV1,
        segment: usize,
    ) -> Result<Self, TransactionCircuitError> {
        segment_span(segment)?;
        Self::from_public_selection(public, Some(segment))
    }
    fn from_public_selection(
        public: &AssetRecoveryCapsulePublicV1,
        segment: Option<usize>,
    ) -> Result<Self, TransactionCircuitError> {
        let words = public.words()?;
        let (start, end, counter) = match segment {
            Some(index) => segment_span(index)?,
            None => (0, CIPHERTEXT_BYTES, 1), // Diagnostic whole graph only.
        };
        let scope = Scope::start();
        let p: [Word; PUBLIC_WORDS] = core::array::from_fn(|_| input());
        let secret: [Word; 8] = core::array::from_fn(|_| input());
        let m: [Word; MATERIAL_WORDS] = core::array::from_fn(|_| input());
        // Every byte-encoded public word is a u32, and every material limb has
        // a unique canonical64 encoding, not just a modular recomposition.
        for word in p[..9].iter().chain(&p[CONTEXT..]) {
            range(*word, 32);
        }
        nonzero(p[ASSET]);
        let secret_bits: [[Word; 32]; 8] = secret.map(|w| range(w, 32).try_into().unwrap());
        let material_bits = m.map(canonical_bits);
        for bit in &material_bits[0][56..] {
            equal(*bit, Word::ZERO);
        }
        equal(m[1], p[ASSET]);
        some_bit(material_bits[18..25].iter().flatten().copied());
        some_bit(material_bits[25..30].iter().flatten().copied());
        let nf_key = [m[25], m[26], m[27], m[28], m[29], Word::ZERO, Word::ZERO];
        let mut owner_words = p[..9].to_vec();
        owner_words.extend_from_slice(&p[POLICY..POLICY + 7]);
        owner_words.extend_from_slice(&m[18..25]);
        owner_words.extend(hash(recovery::NF_KEY, &nf_key)?);
        let owner = hash(recovery::OWNER, &owner_words)?;
        for (a, b) in owner
            .into_iter()
            .zip([m[14], m[15], m[16], m[17], m[10], m[11], m[12]])
        {
            equal(a, b);
        }
        for (a, b) in hash(NOTE_DOMAIN_TAG, &m[..18])?
            .into_iter()
            .zip(&p[CM..CM + 7])
        {
            equal(a, *b);
        }
        for (a, b) in hash(recovery::ARCHIVE_KEY_COMMITMENT_DOMAIN_V1, &secret)?
            .into_iter()
            .zip(&p[ARCHIVE..ARCHIVE + 7])
        {
            equal(a, *b);
        }
        // sha() input/output uses byte order, LSB-first bits within each byte;
        // its8 digest words are exactly SHA256 digest bytes grouped LE-u32.
        let context_bits: Vec<_> = p[CONTEXT..CONTEXT + 8]
            .iter()
            .flat_map(|w| range(*w, 32))
            .collect();
        let mixed: [Word; 256] = core::array::from_fn(|i| {
            let a = secret_bits[i / 32][i % 32];
            let b = context_bits[i];
            a + b - Word::TWO * a * b
        });
        let key = sha(mixed);
        // Encrypt exactly the 22 independent limbs. All 30 witness limbs above
        // remain canonical and bound to asset/owner/full note commitment.
        let bytes: Vec<_> = COMPACT_INDICES
            .iter()
            .flat_map(|index| material_bits[*index].chunks(8).map(pack))
            .collect();
        // Whole 30-limb opening/owner/archive/KDF checks above are repeated in
        // EACH segment. Only the block-aligned encryption slice differs.
        let encrypted =
            chacha20_xor(key, [Word::ZERO; 3], counter, &bytes[start..end]).map_err(error)?;
        for (chunk, public_word) in encrypted
            .chunks_exact(4)
            .zip(&p[CT + start / 4..CT + end / 4])
        {
            equal(
                chunk[0] + chunk[1] * c(256) + chunk[2] * c(65536) + chunk[3] * c(16777216),
                *public_word,
            );
        }
        let mut inner = HtlcAdapter::from_graph(scope.finish());
        for (wire, value) in p.into_iter().zip(words) {
            inner.bind_public(wire, value);
        }
        Ok(Self { inner })
    }
    pub fn geometry(&self) -> &HtlcGeometry {
        self.inner.geometry()
    }
    pub fn lower(
        &self,
        public: &AssetRecoveryCapsulePublicV1,
        witness: &AssetRecoveryCapsuleWitnessV1,
    ) -> Result<Vec<u64>, TransactionCircuitError> {
        canonical(&witness.material)?;
        let mut inputs = public.words()?.to_vec();
        inputs.extend(le32(&witness.archive_secret));
        inputs.extend(witness.material);
        self.inner.evaluate(&inputs)
    }
    pub fn verify_packed_witness(&self, packed: &[u64]) -> Result<(), TransactionCircuitError> {
        self.inner.verify_packed_witness(packed)
    }
}
fn segment_span(segment: usize) -> Result<(usize, usize, u32), TransactionCircuitError> {
    match segment {
        0 => Ok((0, 128, 1)),
        1 => Ok((128, CIPHERTEXT_BYTES, 3)),
        _ => Err(error("recovery capsule segment index")),
    }
}
/// Source-bound admitted component graph. compile() remains diagnostic only.
pub fn compile_segment(
    public: &AssetRecoveryCapsulePublicV1,
    witness: &AssetRecoveryCapsuleWitnessV1,
    segment: usize,
) -> Result<(AssetRecoveryCapsuleAdapterV1, Vec<u64>), TransactionCircuitError> {
    let adapter = AssetRecoveryCapsuleAdapterV1::from_public_segment(public, segment)?;
    let packed = adapter.lower(public, witness)?;
    adapter.verify_packed_witness(&packed)?;
    Ok((adapter, packed))
}
/// Diagnostic whole-encryption graph, never used by prove()/verify().
pub fn compile(
    public: &AssetRecoveryCapsulePublicV1,
    witness: &AssetRecoveryCapsuleWitnessV1,
) -> Result<(AssetRecoveryCapsuleAdapterV1, Vec<u64>), TransactionCircuitError> {
    let adapter = AssetRecoveryCapsuleAdapterV1::from_public(public)?;
    let packed = adapter.lower(public, witness)?;
    adapter.verify_packed_witness(&packed)?;
    Ok((adapter, packed))
}
impl SmallwoodConstraintAdapter for AssetRecoveryCapsuleAdapterV1 {
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
/// Each component has its own compiled source target. A component for index0
/// cannot be replayed as index1, even though both bind the same full public82.
pub fn segment_relation_digest(
    base: [u8; 64],
    segment: usize,
) -> Result<[u8; 64], TransactionCircuitError> {
    use sha2::Sha512;
    let (start, end, counter) = segment_span(segment)?;
    let mut h = Sha512::new();
    h.update(b"Hegemon.AssetRecoveryCapsule.SegmentSource.v2\0");
    h.update(base);
    for value in [segment as u64, start as u64, end as u64, counter as u64] {
        h.update(value.to_le_bytes());
    }
    Ok(h.finalize().into())
}
fn assemble_bundle(components: [&[u8]; 2]) -> Result<Vec<u8>, TransactionCircuitError> {
    let total = components
        .iter()
        .try_fold(BUNDLE_HEADER_BYTES, |n, p| n.checked_add(p.len()))
        .ok_or(error("recovery capsule bundle length overflow"))?;
    if total > MAX_CAPSULE_BUNDLE_BYTES {
        return Err(error("recovery capsule bundle cap"));
    }
    for (index, component) in components.iter().enumerate() {
        crate::asset_recovery_backend_v1::check_component_envelope(
            component,
            2,
            &segment_relation_digest(relation_digest(), index)?,
        )?;
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend(PROOF_MAGIC);
    bytes.extend(BUNDLE_VERSION.to_le_bytes());
    bytes.extend([SEGMENT_COUNT as u8, 0]);
    for component in components {
        bytes.extend((component.len() as u32).to_le_bytes());
    }
    for component in components {
        bytes.extend(component);
    }
    Ok(bytes)
}
/// Strict source/route/framing only. Actual verification is verify(), not this
/// parser: in particular a syntactically framed SMZE is not a valid proof.
pub fn bundle_components(bundle: &[u8]) -> Result<[&[u8]; 2], TransactionCircuitError> {
    if bundle.len() < BUNDLE_HEADER_BYTES
        || bundle.len() > MAX_CAPSULE_BUNDLE_BYTES
        || bundle[..4] != PROOF_MAGIC
        || u16::from_le_bytes(bundle[4..6].try_into().unwrap()) != BUNDLE_VERSION
        || bundle[6] != SEGMENT_COUNT as u8
        || bundle[7] != 0
    {
        return Err(error("recovery capsule bundle header/cap"));
    }
    let a = u32::from_le_bytes(bundle[8..12].try_into().unwrap()) as usize;
    let b = u32::from_le_bytes(bundle[12..16].try_into().unwrap()) as usize;
    if !(84..=MAX_PROOF_BYTES).contains(&a)
        || !(84..=MAX_PROOF_BYTES).contains(&b)
        || BUNDLE_HEADER_BYTES
            .checked_add(a)
            .and_then(|n| n.checked_add(b))
            != Some(bundle.len())
    {
        return Err(error("recovery capsule bundle component lengths"));
    }
    let components = [&bundle[16..16 + a], &bundle[16 + a..]];
    for (index, component) in components.iter().enumerate() {
        crate::asset_recovery_backend_v1::check_component_envelope(
            component,
            2,
            &segment_relation_digest(relation_digest(), index)?,
        )?;
    }
    Ok(components)
}
pub fn prove(
    public: &AssetRecoveryCapsulePublicV1,
    witness: &AssetRecoveryCapsuleWitnessV1,
) -> Result<Vec<u8>, TransactionCircuitError> {
    // Fail before ANY expensive proof if either exact graph cannot fit its cap.
    for segment in 0..SEGMENT_COUNT {
        if component_projected_size(public, segment)? > MAX_PROOF_BYTES {
            return Err(error("recovery capsule component projection exceeds2MiB"));
        }
    }
    let binding = public.binding_bytes()?;
    let mut components = Vec::with_capacity(SEGMENT_COUNT);
    for segment in 0..SEGMENT_COUNT {
        let (adapter, packed) = compile_segment(public, witness, segment)?;
        components.push(crate::asset_recovery_backend_v1::prove(
            &adapter,
            &packed,
            &binding,
            &segment_relation_digest(relation_digest(), segment)?,
        )?);
    }
    assemble_bundle([&components[0], &components[1]])
}
pub fn verify(
    public: &AssetRecoveryCapsulePublicV1,
    proof: &[u8],
) -> Result<(), TransactionCircuitError> {
    let components = bundle_components(proof)?;
    let binding = public.binding_bytes()?;
    for (segment, component) in components.into_iter().enumerate() {
        crate::asset_recovery_backend_v1::verify(
            &AssetRecoveryCapsuleAdapterV1::from_public_segment(public, segment)?,
            &binding,
            &segment_relation_digest(relation_digest(), segment)?,
            component,
        )?;
    }
    Ok(())
}

/// Exact additive source closure plus retained lowering/hash/field dependencies.
/// Source identity does not establish new-relation cryptographic refinement.
pub fn relation_digest() -> [u8; 64] {
    use sha2::Sha512;
    static DIGEST: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut h = Sha512::new();
        h.update(b"Hegemon.AssetRecoveryCapsule.Compact22.Segments2.SourceManifest.v2");
        h.update(RELATION_ID.as_bytes());
        for (name, bytes) in [
            (
                "asset_recovery_capsule_v1.rs",
                include_bytes!("asset_recovery_capsule_v1.rs").as_slice(),
            ),
            (
                "asset_recovery_v1.rs",
                include_bytes!("../../transaction-core/src/asset_recovery_v1.rs").as_slice(),
            ),
            (
                "asset_recovery_chacha_v1.rs",
                include_bytes!("asset_recovery_chacha_v1.rs").as_slice(),
            ),
            (
                "asset_recovery_backend_v1.rs",
                include_bytes!("asset_recovery_backend_v1.rs").as_slice(),
            ),
            (
                "smallwood_htlc.rs",
                include_bytes!("smallwood_htlc.rs").as_slice(),
            ),
        ] {
            h.update((name.len() as u64).to_le_bytes());
            h.update(name.as_bytes());
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        }
        h.update(crate::asset_spend_v1::relation_digest());
        h.finalize().into()
    })
}
pub fn component_projected_size(
    public: &AssetRecoveryCapsulePublicV1,
    segment: usize,
) -> Result<usize, TransactionCircuitError> {
    crate::asset_recovery_backend_v1::projected_bytes(
        &AssetRecoveryCapsuleAdapterV1::from_public_segment(public, segment)?,
    )
}
pub fn projected_size(
    public: &AssetRecoveryCapsulePublicV1,
) -> Result<usize, TransactionCircuitError> {
    let mut total = BUNDLE_HEADER_BYTES;
    for segment in 0..SEGMENT_COUNT {
        total = total
            .checked_add(component_projected_size(public, segment)?)
            .ok_or(error("recovery capsule projected bundle overflow"))?;
    }
    Ok(total)
}
pub fn component_geometry_receipt(
    public: &AssetRecoveryCapsulePublicV1,
    segment: usize,
) -> Result<serde_json::Value, TransactionCircuitError> {
    let (start, end, counter) = segment_span(segment)?;
    let adapter = AssetRecoveryCapsuleAdapterV1::from_public_segment(public, segment)?;
    let mut receipt = crate::asset_recovery_backend_v1::geometry_receipt(&adapter)?;
    let obj = receipt
        .as_object_mut()
        .ok_or(error("recovery capsule geometry shape"))?;
    obj.insert("relation_id".into(), serde_json::json!(RELATION_ID));
    obj.insert("segment".into(), serde_json::json!(segment));
    obj.insert(
        "segment_source".into(),
        serde_json::json!(hex::encode(segment_relation_digest(
            relation_digest(),
            segment
        )?)),
    );
    obj.insert("plaintext_range".into(), serde_json::json!([start, end]));
    obj.insert("initial_counter".into(), serde_json::json!(counter));
    obj.insert("public_words".into(), serde_json::json!(PUBLIC_WORDS));
    obj.insert(
        "full_material_words".into(),
        serde_json::json!(MATERIAL_WORDS),
    );
    obj.insert("capsule_bytes".into(), serde_json::json!(CIPHERTEXT_BYTES));
    obj.insert(
        "source_lowering_certificate_complete".into(),
        serde_json::json!(false),
    );
    Ok(receipt)
}
pub fn geometry_receipt(
    public: &AssetRecoveryCapsulePublicV1,
) -> Result<serde_json::Value, TransactionCircuitError> {
    Ok(
        serde_json::json!({"relation_id":RELATION_ID,"proof_magic":"SMRC",
        "bundle_version":BUNDLE_VERSION,"segments":[component_geometry_receipt(public,0)?,component_geometry_receipt(public,1)?],
        "bundle_header_bytes":BUNDLE_HEADER_BYTES,"projected_bundle_bytes":projected_size(public)?,
        "max_component_bytes":MAX_PROOF_BYTES,"max_bundle_bytes":MAX_CAPSULE_BUNDLE_BYTES,
        "public_words":PUBLIC_WORDS,"capsule_bytes":CIPHERTEXT_BYTES,
        "source_lowering_certificate_complete":false}),
    )
}
pub fn component_proof_wire_receipt(
    component: &[u8],
    segment: usize,
) -> Result<serde_json::Value, TransactionCircuitError> {
    crate::asset_recovery_backend_v1::check_component_envelope(
        component,
        2,
        &segment_relation_digest(relation_digest(), segment)?,
    )?;
    crate::asset_recovery_backend_v1::wire_receipt(component)
}
pub fn proof_wire_receipt(proof: &[u8]) -> Result<serde_json::Value, TransactionCircuitError> {
    let components = bundle_components(proof)?;
    Ok(
        serde_json::json!({"proof_magic":"SMRC","bundle_version":BUNDLE_VERSION,
        "bundle_bytes":proof.len(),"bundle_header_bytes":BUNDLE_HEADER_BYTES,
        "max_bundle_bytes":MAX_CAPSULE_BUNDLE_BYTES,"proof_verified":false,
        "components":[component_proof_wire_receipt(components[0],0)?,component_proof_wire_receipt(components[1],1)?]}),
    )
}
/// Public disposable constants, absent from normal production builds.
#[cfg(any(test, feature = "private-spend-dev-artifacts"))]
pub mod fixtures {
    use super::*;
    pub fn fixture() -> Result<
        (AssetRecoveryCapsulePublicV1, AssetRecoveryCapsuleWitnessV1),
        TransactionCircuitError,
    > {
        let mut m = [11; MATERIAL_WORDS];
        m[0] = 123;
        m[1] = 17;
        m[18..25].fill(7);
        m[25..30].copy_from_slice(&[1, 2, 3, 4, 5]);
        let owner = recovery::recovery_owner([4; 32], 17, [9; 7], [7; 7], [1, 2, 3, 4, 5])
            .map_err(|_| error("recovery capsule disposable fixture owner"))?;
        m[14..18].copy_from_slice(&owner[..4]);
        m[10..13].copy_from_slice(&owner[4..]);
        let witness = AssetRecoveryCapsuleWitnessV1 {
            archive_secret: [23; 32],
            material: m,
        };
        Ok((
            encrypt([4; 32], 17, [9; 7], &witness.archive_secret, &m)?,
            witness,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (AssetRecoveryCapsulePublicV1, AssetRecoveryCapsuleWitnessV1) {
        fixtures::fixture().unwrap()
    }
    #[test]
    fn host_roundtrip_context_and_material_rejections() {
        let (p, w) = fixture();
        assert_eq!(decrypt(&p, &w.archive_secret).unwrap(), w.material);
        assert_eq!(p.words().unwrap().len(), 82);
        assert_eq!(p.binding_bytes().unwrap().len(), 672);
        assert!(decrypt(&p, &[24; 32]).is_err());
        for index in [0, 1, 8, 14, 18, 25, 29] {
            let mut m = w.material;
            m[index] ^= 1;
            assert!(validate_material(&p, &m).is_err());
        }
        for change in 0..5 {
            let mut q = p.clone();
            match change {
                0 => q.chain_id[0] ^= 1,
                1 => q.asset_id += 1,
                2 => q.stable_policy_id[0] ^= 1,
                3 => q.note_commitment[0] ^= 1,
                _ => q.ciphertext[CIPHERTEXT_BYTES - 1] ^= 1,
            }
            assert!(decrypt(&q, &w.archive_secret).is_err());
        }
        let mut native = p.clone();
        native.asset_id = 0;
        assert!(native.words().is_err());
        let mut bad = w.material;
        bad[0] = 1 << 56;
        assert!(encrypt(
            p.chain_id,
            p.asset_id,
            p.stable_policy_id,
            &w.archive_secret,
            &bad
        )
        .is_err());
        bad = w.material;
        bad[6] = P;
        assert!(encrypt(
            p.chain_id,
            p.asset_id,
            p.stable_policy_id,
            &w.archive_secret,
            &bad
        )
        .is_err());
        // A ciphertext can contain arbitrary bytes. Decryption must reject a
        // noncanonical LE-u64 rather than silently reducing it modulo p.
        let mut malformed = p.clone();
        let mut key = derived_key(&w.archive_secret, p.context_digest());
        malformed.ciphertext = chacha20_xor_reference(&key, &[0; 12], 1, &material_bytes(&bad))
            .unwrap()
            .try_into()
            .unwrap();
        key.fill(0);
        assert!(decrypt(&malformed, &w.archive_secret).is_err());
    }
    #[test]
    fn compact22_reconstructs_all_omitted_limbs_and_separates_old_pad() {
        let (public, witness) = fixture();
        assert_eq!(CIPHERTEXT_BYTES, 176);
        let recovered = decrypt(&public, &witness.archive_secret).unwrap();
        assert_eq!(recovered, witness.material);
        let mut indices = COMPACT_INDICES;
        indices.sort_unstable();
        assert!(indices.windows(2).all(|pair| pair[0] != pair[1]));
        for omitted in [1, 10, 11, 12, 14, 15, 16, 17] {
            assert!(!indices.contains(&omitted));
        }
        let mut old = Sha256::new();
        old.update(b"Hegemon.AssetRecovery.CapsuleContext.v1");
        old.update(public.chain_id);
        old.update(public.asset_id.to_le_bytes());
        for word in public
            .stable_policy_id
            .iter()
            .chain(&public.note_commitment)
        {
            old.update(word.to_le_bytes());
        }
        let old_context: [u8; 32] = old.finalize().into();
        assert_ne!(old_context, public.context_digest());
        let mut old_key = derived_key(&witness.archive_secret, old_context);
        let mut old_plain = material_bytes(&witness.material);
        let mut wrong_domain = public.clone();
        wrong_domain.ciphertext = chacha20_xor_reference(&old_key, &[0; 12], 1, &old_plain)
            .unwrap()
            .try_into()
            .unwrap();
        old_key.fill(0);
        old_plain.fill(0);
        assert!(decrypt(&wrong_domain, &witness.archive_secret).is_err());
    }
    #[test]
    fn actual_graph_rejects_wrong_secret_owner_commitment_and_ciphertext() {
        let (p, mut w) = fixture();
        let adapter = AssetRecoveryCapsuleAdapterV1::from_public(&p).unwrap();
        adapter
            .verify_packed_witness(&adapter.lower(&p, &w).unwrap())
            .unwrap();
        w.archive_secret[0] ^= 1;
        assert!(adapter
            .verify_packed_witness(&adapter.lower(&p, &w).unwrap())
            .is_err());
        w.archive_secret[0] ^= 1;
        w.material[25] ^= 1;
        assert!(adapter
            .verify_packed_witness(&adapter.lower(&p, &w).unwrap())
            .is_err());
        w.material[25] ^= 1;
        w.material[6] ^= 1;
        assert!(adapter
            .verify_packed_witness(&adapter.lower(&p, &w).unwrap())
            .is_err());
        w.material[6] ^= 1;
        for index in [1, 10, 11, 12, 14, 15, 16, 17] {
            w.material[index] ^= 1;
            assert!(
                adapter
                    .verify_packed_witness(&adapter.lower(&p, &w).unwrap())
                    .is_err(),
                "omitted full-witness limb{index}"
            );
            w.material[index] ^= 1;
        }
        let mut q = p.clone();
        q.ciphertext[0] ^= 1;
        let bad = AssetRecoveryCapsuleAdapterV1::from_public(&q).unwrap();
        assert!(bad
            .verify_packed_witness(&bad.lower(&q, &w).unwrap())
            .is_err());
    }
    #[test]
    fn segment_graphs_repeat_opening_checks_and_cover_exact_chacha_stream() {
        let (p, mut w) = fixture();
        let mut key = derived_key(&w.archive_secret, p.context_digest());
        let mut plain = material_bytes(&w.material);
        for segment in 0..SEGMENT_COUNT {
            let (start, end, counter) = segment_span(segment).unwrap();
            let cipher =
                chacha20_xor_reference(&key, &[0; 12], counter, &plain[start..end]).unwrap();
            assert_eq!(cipher, p.ciphertext[start..end]);
            let (adapter, packed) = compile_segment(&p, &w, segment).unwrap();
            adapter.verify_packed_witness(&packed).unwrap();
            w.material[25] ^= 1;
            assert!(adapter
                .verify_packed_witness(&adapter.lower(&p, &w).unwrap())
                .is_err());
            w.material[25] ^= 1;
            w.archive_secret[0] ^= 1;
            assert!(adapter
                .verify_packed_witness(&adapter.lower(&p, &w).unwrap())
                .is_err());
            w.archive_secret[0] ^= 1;
            let mut bad = p.clone();
            bad.ciphertext[start] ^= 1;
            let adapter =
                AssetRecoveryCapsuleAdapterV1::from_public_segment(&bad, segment).unwrap();
            assert!(adapter
                .verify_packed_witness(&adapter.lower(&bad, &w).unwrap())
                .is_err());
        }
        key.fill(0);
        plain.fill(0);
        assert!(AssetRecoveryCapsuleAdapterV1::from_public_segment(&p, 2).is_err());
    }
    fn fake_component(segment: usize) -> Vec<u8> {
        let mut p = b"SMZR".to_vec();
        p.extend(1u16.to_le_bytes());
        p.extend([2, 0]);
        p.extend(segment_relation_digest(relation_digest(), segment).unwrap());
        p.extend(4u32.to_le_bytes());
        p.extend([0; 4]);
        p.extend(b"SMZE");
        p
    }
    #[test]
    fn strict_segment_bundle_rejects_swaps_old_proofs_caps_and_padding() {
        let a = fake_component(0);
        let b = fake_component(1);
        let bundle = assemble_bundle([&a, &b]).unwrap();
        assert_eq!(
            bundle_components(&bundle).unwrap(),
            [a.as_slice(), b.as_slice()]
        );
        assert!(assemble_bundle([&b, &a]).is_err());
        assert!(assemble_bundle([&a, &a]).is_err());
        assert!(bundle_components(&a).is_err()); // Old single SMZR is not a capsule.
        assert!(proof_wire_receipt(&bundle).is_err()); // Framing is not a proof.
        assert_ne!(
            segment_relation_digest(relation_digest(), 0).unwrap(),
            segment_relation_digest(relation_digest(), 1).unwrap()
        );
        for offset in [0, 4, 6, 7, 8, 12, 16, 22, 24] {
            let mut bad = bundle.clone();
            bad[offset] ^= 0x80;
            assert!(bundle_components(&bad).is_err(), "offset{offset}");
        }
        for end in [0, 4, 15, 16, bundle.len() - 1] {
            assert!(bundle_components(&bundle[..end]).is_err());
        }
        let mut trailing = bundle.clone();
        trailing.push(0);
        assert!(bundle_components(&trailing).is_err());
        let mut oversized = bundle;
        oversized[8..12].copy_from_slice(&((MAX_PROOF_BYTES + 1) as u32).to_le_bytes());
        assert!(bundle_components(&oversized).is_err());
    }
    #[test]
    fn canonical64_graph_excludes_modulus_alias_and_accepts_largest_field_word() {
        let scope = Scope::start();
        let word = input();
        let bits: [Word; 64] = core::array::from_fn(|_| input());
        for bit in bits {
            boolean(bit);
        }
        equal(pack(&bits), word);
        canonical_bit_bound(&bits);
        let adapter = HtlcAdapter::from_graph(scope.finish());
        for (value, encoding, valid) in [
            (0, 0, true),
            (P - 1, P - 1, true),
            (0, P, false),
            (1, P + 1, false),
        ] {
            let mut inputs = vec![value];
            inputs.extend((0..64).map(|i| (encoding >> i) & 1));
            let packed = adapter.evaluate(&inputs).unwrap();
            assert_eq!(adapter.verify_packed_witness(&packed).is_ok(), valid);
        }
    }
}
