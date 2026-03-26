use anyhow::{anyhow, ensure, Result};
use blake3::Hasher;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::Instant,
};
use superneo_ccs::{
    digest_shape, CcsShape, RelationId, ShapeDigest, StatementDigest, StatementEncoding,
};
use superneo_core::{validate_fold_pair, Backend, FoldedInstance, SecurityParams};
use superneo_ring::PackedWitness;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RingProfile {
    GoldilocksCyclotomic24,
    GoldilocksFrog,
}

impl RingProfile {
    fn label(self) -> &'static [u8] {
        match self {
            Self::GoldilocksCyclotomic24 => b"goldilocks-cyclotomic24",
            Self::GoldilocksFrog => b"goldilocks-frog",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeBackendConfig {
    pub ring_profile: RingProfile,
    pub security_bits: u32,
    pub challenge_bits: u32,
    pub commitment_rows: usize,
    pub ring_degree: usize,
    pub digit_bits: u16,
}

impl Default for LatticeBackendConfig {
    fn default() -> Self {
        Self {
            ring_profile: RingProfile::GoldilocksCyclotomic24,
            security_bits: 128,
            challenge_bits: 16,
            commitment_rows: 8,
            ring_degree: 8,
            digit_bits: 8,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeBackend {
    pub config: LatticeBackendConfig,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelCostReport {
    pub bit_unpack_ns: u128,
    pub digit_expand_ns: u128,
    pub matrix_prepare_ns: u128,
    pub commitment_kernel_ns: u128,
    pub leaf_hash_ns: u128,
    pub fold_kernel_ns: u128,
    pub small_small_ops: u64,
    pub small_big_ops: u64,
    pub big_big_ops: u64,
    pub delayed_reduction_batches: u64,
    pub evaluation_windows: u64,
    pub streamed_message_windows: u64,
    pub matrix_cache_hits: u64,
    pub matrix_cache_misses: u64,
    pub matrix_cache_evictions: u64,
}

impl KernelCostReport {
    pub fn merge(&mut self, other: &Self) {
        self.bit_unpack_ns += other.bit_unpack_ns;
        self.digit_expand_ns += other.digit_expand_ns;
        self.matrix_prepare_ns += other.matrix_prepare_ns;
        self.commitment_kernel_ns += other.commitment_kernel_ns;
        self.leaf_hash_ns += other.leaf_hash_ns;
        self.fold_kernel_ns += other.fold_kernel_ns;
        self.small_small_ops += other.small_small_ops;
        self.small_big_ops += other.small_big_ops;
        self.big_big_ops += other.big_big_ops;
        self.delayed_reduction_batches += other.delayed_reduction_batches;
        self.evaluation_windows += other.evaluation_windows;
        self.streamed_message_windows += other.streamed_message_windows;
        self.matrix_cache_hits += other.matrix_cache_hits;
        self.matrix_cache_misses += other.matrix_cache_misses;
        self.matrix_cache_evictions += other.matrix_cache_evictions;
    }
}

#[derive(Clone, Debug, Default)]
struct KernelLocalStats {
    small_small_ops: u64,
    small_big_ops: u64,
    big_big_ops: u64,
    delayed_reduction_batches: u64,
    evaluation_windows: u64,
    streamed_message_windows: u64,
}

#[derive(Clone, Debug)]
struct PreparedCommitmentMatrix {
    rows: Vec<Vec<RingElem>>,
}

#[derive(Clone, Debug, Default)]
struct PreparedMatrixCache {
    entries: BTreeMap<[u8; 32], Arc<PreparedCommitmentMatrix>>,
    access_order: VecDeque<[u8; 32]>,
}

#[derive(Clone, Debug)]
struct EmbeddedRingElem {
    ring: RingElem,
    source_width_bits: u16,
}

const GOLDILOCKS_MODULUS_I128: i128 = 18_446_744_069_414_584_321;
const COMMITMENT_WINDOW_COLUMNS: usize = 32;
const PREPARED_MATRIX_CACHE_MAX_ENTRIES: usize = 16;

thread_local! {
    static KERNEL_COST_REPORT: RefCell<KernelCostReport> = RefCell::new(KernelCostReport::default());
    static PREPARED_MATRIX_CACHE: RefCell<PreparedMatrixCache> =
        RefCell::new(PreparedMatrixCache::default());
}

impl PreparedMatrixCache {
    fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
    }

    fn get(&mut self, key: &[u8; 32]) -> Option<Arc<PreparedCommitmentMatrix>> {
        let entry = self.entries.get(key).cloned()?;
        self.touch(*key);
        Some(entry)
    }

    fn insert(
        &mut self,
        key: [u8; 32],
        value: Arc<PreparedCommitmentMatrix>,
        capacity: usize,
    ) -> u64 {
        if capacity == 0 {
            return 0;
        }
        self.entries.insert(key, value);
        self.touch(key);

        let mut evictions = 0;
        while self.entries.len() > capacity {
            let Some(evicted_key) = self.access_order.pop_front() else {
                break;
            };
            if self.entries.remove(&evicted_key).is_some() {
                evictions += 1;
            }
        }
        evictions
    }

    fn touch(&mut self, key: [u8; 32]) {
        if let Some(position) = self
            .access_order
            .iter()
            .position(|existing| *existing == key)
        {
            self.access_order.remove(position);
        }
        self.access_order.push_back(key);
    }
}

impl Default for LatticeBackend {
    fn default() -> Self {
        Self {
            config: LatticeBackendConfig::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendKey {
    pub shape_digest: ShapeDigest,
    pub security_bits: u32,
    pub challenge_bits: u32,
    pub max_fold_arity: u32,
    pub transcript_domain_digest: [u8; 32],
    pub ring_profile: RingProfile,
    pub commitment_rows: usize,
    pub ring_degree: usize,
    pub digit_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingElem {
    pub coeffs: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeCommitment {
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub digest: [u8; 48],
    pub rows: Vec<RingElem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafDigestProof {
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub witness_commitment_digest: [u8; 48],
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldDigestProof {
    pub challenge: u64,
    pub parent_statement_digest: StatementDigest,
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub parent_commitment_digest: [u8; 48],
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendShape {
    pub shape_digest: ShapeDigest,
    pub num_rows: usize,
    pub num_cols: usize,
    pub matrix_count: usize,
    pub selector_count: usize,
    pub witness_bits: usize,
}

impl RingElem {
    pub fn from_coeffs(coeffs: Vec<u64>) -> Self {
        Self { coeffs }
    }

    fn byte_size(&self) -> usize {
        4 + (self.coeffs.len() * 8)
    }
}

fn serialize_fixed_bytes_48<S>(
    bytes: &[u8; 48],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(bytes)
}

fn deserialize_fixed_bytes_48<'de, D>(deserializer: D) -> std::result::Result<[u8; 48], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::invalid_length(len, &"48 bytes"))
}

impl LatticeCommitment {
    pub const DIGEST_BYTES: usize = 48;

    pub fn from_rows(rows: Vec<RingElem>) -> Self {
        Self {
            digest: digest_commitment_rows(&rows),
            rows,
        }
    }

    pub fn digest_only(digest: [u8; 48]) -> Self {
        Self {
            digest,
            rows: Vec::new(),
        }
    }

    pub fn byte_size(&self) -> usize {
        Self::DIGEST_BYTES + 4 + self.rows.iter().map(RingElem::byte_size).sum::<usize>()
    }

    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(self.digest.len() * 2);
        for byte in self.digest {
            out.push(hex_nibble(byte >> 4));
            out.push(hex_nibble(byte & 0x0f));
        }
        out
    }
}

impl LeafDigestProof {
    pub fn byte_size(&self) -> usize {
        48 + 48
    }
}

impl FoldDigestProof {
    pub const BYTES: usize = 8 + StatementDigest::BYTES + LatticeCommitment::DIGEST_BYTES + 48;

    pub fn byte_size(&self) -> usize {
        Self::BYTES
    }
}

impl LatticeBackend {
    pub fn new(config: LatticeBackendConfig) -> Self {
        Self { config }
    }
}

pub fn reset_kernel_cost_report() {
    KERNEL_COST_REPORT.with(|report| {
        *report.borrow_mut() = KernelCostReport::default();
    });
}

pub fn reset_kernel_runtime_state() {
    reset_kernel_cost_report();
    clear_prepared_matrix_cache();
}

pub fn current_kernel_cost_report() -> KernelCostReport {
    KERNEL_COST_REPORT.with(|report| report.borrow().clone())
}

pub fn take_kernel_cost_report() -> KernelCostReport {
    KERNEL_COST_REPORT.with(|report| {
        let mut report = report.borrow_mut();
        let current = report.clone();
        *report = KernelCostReport::default();
        current
    })
}

pub fn clear_prepared_matrix_cache() {
    PREPARED_MATRIX_CACHE.with(|cache| cache.borrow_mut().clear());
}

fn update_kernel_cost_report(f: impl FnOnce(&mut KernelCostReport)) {
    KERNEL_COST_REPORT.with(|report| f(&mut report.borrow_mut()));
}

fn flush_kernel_stats(stats: &KernelLocalStats) {
    update_kernel_cost_report(|report| {
        report.small_small_ops += stats.small_small_ops;
        report.small_big_ops += stats.small_big_ops;
        report.big_big_ops += stats.big_big_ops;
        report.delayed_reduction_batches += stats.delayed_reduction_batches;
        report.evaluation_windows += stats.evaluation_windows;
        report.streamed_message_windows += stats.streamed_message_windows;
    });
}

impl Backend<Goldilocks> for LatticeBackend {
    type ProverKey = BackendKey;
    type VerifierKey = BackendKey;
    type PackedWitness = PackedWitness<u64>;
    type Commitment = LatticeCommitment;
    type LeafProof = LeafDigestProof;
    type FoldProof = FoldDigestProof;

    fn setup(
        &self,
        security: &SecurityParams,
        shape: &CcsShape<Goldilocks>,
    ) -> Result<(Self::ProverKey, Self::VerifierKey)> {
        shape.validate()?;
        ensure!(
            self.config.commitment_rows > 0,
            "commitment_rows must be strictly positive"
        );
        ensure!(
            self.config.ring_degree > 0,
            "ring_degree must be strictly positive"
        );
        ensure!(
            (1..=16).contains(&self.config.digit_bits),
            "digit_bits must be in 1..=16"
        );
        let key = BackendKey {
            shape_digest: digest_shape(shape),
            security_bits: security.target_security_bits,
            challenge_bits: self.config.challenge_bits,
            max_fold_arity: security.max_fold_arity,
            transcript_domain_digest: digest32_with_label(
                b"hegemon.superneo.transcript-domain.v1",
                security.transcript_domain,
            ),
            ring_profile: self.config.ring_profile,
            commitment_rows: self.config.commitment_rows,
            ring_degree: self.config.ring_degree,
            digit_bits: self.config.digit_bits,
        };
        Ok((key.clone(), key))
    }

    fn commit_witness(
        &self,
        pk: &Self::ProverKey,
        packed: &Self::PackedWitness,
    ) -> Result<Self::Commitment> {
        let ring_message = embed_packed_witness(pk, packed)?;
        let rows = commit_ring_message(pk, &ring_message);
        Ok(LatticeCommitment::from_rows(rows))
    }

    fn prove_leaf(
        &self,
        pk: &Self::ProverKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<Goldilocks>,
        packed: &Self::PackedWitness,
        commitment: &Self::Commitment,
    ) -> Result<Self::LeafProof> {
        let hash_start = Instant::now();
        let proof_digest = leaf_proof_digest(
            pk,
            relation_id,
            &statement.statement_digest,
            packed,
            &commitment.digest,
        );
        update_kernel_cost_report(|report| {
            report.leaf_hash_ns += hash_start.elapsed().as_nanos();
        });
        Ok(LeafDigestProof {
            witness_commitment_digest: commitment.digest,
            proof_digest,
        })
    }

    fn verify_leaf(
        &self,
        vk: &Self::VerifierKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<Goldilocks>,
        expected_packed: &Self::PackedWitness,
        proof: &Self::LeafProof,
    ) -> Result<()> {
        let expected_commitment = self.commit_witness(vk, expected_packed)?;
        ensure!(
            proof.witness_commitment_digest == expected_commitment.digest,
            "leaf witness commitment digest mismatch"
        );
        let expected_proof_digest = leaf_proof_digest(
            vk,
            relation_id,
            &statement.statement_digest,
            expected_packed,
            &expected_commitment.digest,
        );
        ensure!(
            proof.proof_digest == expected_proof_digest,
            "leaf proof digest mismatch"
        );
        Ok(())
    }

    fn fold_pair(
        &self,
        pk: &Self::ProverKey,
        left: &FoldedInstance<Self::Commitment>,
        right: &FoldedInstance<Self::Commitment>,
    ) -> Result<(FoldedInstance<Self::Commitment>, Self::FoldProof)> {
        validate_fold_pair(left, right)?;
        let challenge = derive_fold_challenge(pk, left, right);
        let fold_start = Instant::now();
        let parent_commitment = LatticeCommitment::from_rows(fold_commitment_rows(
            &left.witness_commitment,
            &right.witness_commitment,
            challenge,
        )?);
        let parent_statement_digest = fold_statement_digest(
            &left.statement_digest,
            &right.statement_digest,
            challenge,
            &parent_commitment.digest,
        );
        let proof_digest = fold_proof_digest(
            pk,
            &left.relation_id,
            left,
            right,
            challenge,
            &parent_statement_digest,
            &parent_commitment.digest,
        );
        let proof = FoldDigestProof {
            challenge,
            parent_statement_digest,
            parent_commitment_digest: parent_commitment.digest,
            proof_digest,
        };
        let parent = FoldedInstance {
            relation_id: left.relation_id,
            shape_digest: left.shape_digest,
            statement_digest: parent_statement_digest,
            witness_commitment: parent_commitment,
        };
        update_kernel_cost_report(|report| {
            report.fold_kernel_ns += fold_start.elapsed().as_nanos();
        });
        Ok((parent, proof))
    }

    fn verify_fold(
        &self,
        vk: &Self::VerifierKey,
        parent: &FoldedInstance<Self::Commitment>,
        left: &FoldedInstance<Self::Commitment>,
        right: &FoldedInstance<Self::Commitment>,
        proof: &Self::FoldProof,
    ) -> Result<()> {
        validate_fold_pair(left, right)?;
        ensure!(
            left.shape_digest == vk.shape_digest,
            "left folded instance shape digest does not match verifier key"
        );
        ensure!(
            right.shape_digest == vk.shape_digest,
            "right folded instance shape digest does not match verifier key"
        );
        ensure!(
            parent.shape_digest == vk.shape_digest,
            "parent folded instance shape digest does not match verifier key"
        );
        ensure!(
            parent.relation_id == left.relation_id && left.relation_id == right.relation_id,
            "parent relation id does not match folded children"
        );
        ensure!(
            parent.shape_digest == left.shape_digest && left.shape_digest == right.shape_digest,
            "parent shape digest does not match folded children"
        );

        let expected_challenge = derive_fold_challenge(vk, left, right);
        ensure!(
            proof.challenge == expected_challenge,
            "fold challenge mismatch"
        );

        let expected_commitment = LatticeCommitment::from_rows(fold_commitment_rows(
            &left.witness_commitment,
            &right.witness_commitment,
            expected_challenge,
        )?);
        ensure!(
            parent.witness_commitment.digest == expected_commitment.digest,
            "folded witness commitment digest mismatch"
        );
        if !parent.witness_commitment.rows.is_empty() {
            ensure!(
                parent.witness_commitment.rows == expected_commitment.rows,
                "folded witness commitment rows mismatch"
            );
        }
        ensure!(
            proof.parent_commitment_digest == expected_commitment.digest,
            "fold proof parent commitment digest mismatch"
        );

        let expected_statement_digest = fold_statement_digest(
            &left.statement_digest,
            &right.statement_digest,
            expected_challenge,
            &expected_commitment.digest,
        );
        ensure!(
            parent.statement_digest == expected_statement_digest,
            "folded statement digest mismatch"
        );
        ensure!(
            proof.parent_statement_digest == expected_statement_digest,
            "fold proof parent statement digest mismatch"
        );

        let expected_proof_digest = fold_proof_digest(
            vk,
            &left.relation_id,
            left,
            right,
            expected_challenge,
            &expected_statement_digest,
            &expected_commitment.digest,
        );
        ensure!(
            proof.proof_digest == expected_proof_digest,
            "fold proof digest mismatch"
        );
        Ok(())
    }
}

pub fn to_backend_ccs(shape: &CcsShape<Goldilocks>) -> Result<BackendShape> {
    shape.validate()?;
    Ok(BackendShape {
        shape_digest: digest_shape(shape),
        num_rows: shape.num_rows,
        num_cols: shape.num_cols,
        matrix_count: shape.matrices.len(),
        selector_count: shape.selectors.len(),
        witness_bits: shape.witness_schema.total_witness_bits(),
    })
}

fn embed_packed_witness(
    pk: &BackendKey,
    packed: &PackedWitness<u64>,
) -> Result<Vec<EmbeddedRingElem>> {
    ensure!(
        packed.value_bit_widths.len() == packed.original_len,
        "packed witness width metadata length {} does not match original_len {}",
        packed.value_bit_widths.len(),
        packed.original_len
    );
    let (digits, digit_source_widths) = expand_packed_digits(packed, pk.digit_bits)?;
    let mut ring_elems = Vec::with_capacity(digits.len().div_ceil(pk.ring_degree));
    for (chunk_index, chunk) in digits.chunks(pk.ring_degree).enumerate() {
        let mut coeffs = vec![0u64; pk.ring_degree];
        for (idx, digit) in chunk.iter().enumerate() {
            coeffs[idx] = *digit;
        }
        let source_width_bits = digit_source_widths
            .iter()
            .skip(chunk_index * pk.ring_degree)
            .take(chunk.len())
            .copied()
            .max()
            .unwrap_or(1);
        ring_elems.push(EmbeddedRingElem {
            ring: RingElem::from_coeffs(coeffs),
            source_width_bits,
        });
    }
    Ok(ring_elems)
}

fn expand_packed_digits(
    packed: &PackedWitness<u64>,
    digit_bits: u16,
) -> Result<(Vec<u64>, Vec<u16>)> {
    ensure!(
        (1..=64).contains(&packed.coeff_capacity_bits),
        "packed witness coeff capacity must be in 1..=64"
    );
    ensure!(
        (1..=16).contains(&digit_bits),
        "digit_bits must be in 1..=16"
    );
    let digit_start = Instant::now();
    let bits = expand_packed_bits(packed)?;
    let mut digits = Vec::with_capacity(bits.len().div_ceil(digit_bits as usize));
    let bit_source_widths = expand_packed_bit_source_widths(packed)?;
    ensure!(
        bit_source_widths.len() == bits.len(),
        "bit source width metadata length {} does not match expanded bits {}",
        bit_source_widths.len(),
        bits.len()
    );
    let mut digit_source_widths = Vec::with_capacity(bits.len().div_ceil(digit_bits as usize));
    let mut cursor = 0usize;
    while cursor < bits.len() {
        let mut digit = 0u64;
        let mut source_width_bits = 1u16;
        for offset in 0..digit_bits as usize {
            let bit_index = cursor + offset;
            if bit_index >= bits.len() {
                break;
            }
            digit |= u64::from(bits[bit_index]) << offset;
            source_width_bits = source_width_bits.max(bit_source_widths[bit_index]);
        }
        digits.push(digit);
        digit_source_widths.push(source_width_bits);
        cursor += digit_bits as usize;
    }
    update_kernel_cost_report(|report| {
        report.digit_expand_ns += digit_start.elapsed().as_nanos();
    });
    Ok((digits, digit_source_widths))
}

fn expand_packed_bits(packed: &PackedWitness<u64>) -> Result<Vec<u8>> {
    ensure!(
        (1..=64).contains(&packed.coeff_capacity_bits),
        "packed witness coeff capacity must be in 1..=64"
    );
    let bit_unpack_start = Instant::now();
    let coeff_capacity = packed.coeff_capacity_bits as usize;
    let mut bits = Vec::with_capacity(packed.used_bits);
    for bit_index in 0..packed.used_bits {
        let coeff_index = bit_index / coeff_capacity;
        let bit_offset = (bit_index % coeff_capacity) as u16;
        let coeff = *packed
            .coeffs
            .get(coeff_index)
            .ok_or_else(|| anyhow!("packed witness ended early while expanding bits"))?;
        bits.push(((coeff >> bit_offset) & 1) as u8);
    }
    update_kernel_cost_report(|report| {
        report.bit_unpack_ns += bit_unpack_start.elapsed().as_nanos();
    });
    Ok(bits)
}

fn expand_packed_bit_source_widths(packed: &PackedWitness<u64>) -> Result<Vec<u16>> {
    let total_value_bits = packed
        .value_bit_widths
        .iter()
        .map(|width| usize::from(*width))
        .sum::<usize>();
    ensure!(
        total_value_bits == packed.used_bits,
        "packed witness width metadata covers {} bits but used_bits is {}",
        total_value_bits,
        packed.used_bits
    );
    let mut bit_source_widths = Vec::with_capacity(packed.used_bits);
    for width in &packed.value_bit_widths {
        bit_source_widths.extend(std::iter::repeat_n(*width, usize::from(*width)));
    }
    Ok(bit_source_widths)
}

fn commit_ring_message(pk: &BackendKey, message: &[EmbeddedRingElem]) -> Vec<RingElem> {
    let prepared = prepare_commitment_matrix(pk, message.len());
    let commit_start = Instant::now();
    let window_size = message.len().max(1).min(COMMITMENT_WINDOW_COLUMNS);
    let mut accumulators = vec![vec![0i128; pk.ring_degree]; pk.commitment_rows];
    let mut stats = KernelLocalStats::default();
    let row_count = pk.commitment_rows;

    for (window_index, chunk) in message.chunks(window_size).enumerate() {
        stats.evaluation_windows += 1;
        stats.streamed_message_windows += 1;
        let base_col = window_index * window_size;
        for (offset, message_elem) in chunk.iter().enumerate() {
            let col_index = base_col + offset;
            for row_index in 0..row_count {
                if message_elem.source_width_bits <= 16 {
                    accumulate_negacyclic_product_narrow_source(
                        &mut accumulators[row_index],
                        &prepared.rows[row_index][col_index],
                        &message_elem.ring,
                        &mut stats,
                    );
                } else {
                    accumulate_negacyclic_product_generic_source(
                        &mut accumulators[row_index],
                        &prepared.rows[row_index][col_index],
                        &message_elem.ring,
                        &mut stats,
                    );
                }
            }
        }
    }

    let rows = accumulators
        .into_iter()
        .map(|coeffs| {
            stats.delayed_reduction_batches += 1;
            RingElem::from_coeffs(
                coeffs
                    .into_iter()
                    .map(reduce_goldilocks_signed)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    flush_kernel_stats(&stats);
    update_kernel_cost_report(|report| {
        report.commitment_kernel_ns += commit_start.elapsed().as_nanos();
    });
    rows
}

fn matrix_entry(pk: &BackendKey, row_index: usize, col_index: usize) -> RingElem {
    let mut coeffs = Vec::with_capacity(pk.ring_degree);
    for coeff_index in 0..pk.ring_degree {
        let mut hasher = Hasher::new();
        hasher.update(b"hegemon.superneo.ajtai-matrix.v1");
        hasher.update(pk.ring_profile.label());
        hasher.update(&pk.shape_digest.0);
        hasher.update(&pk.security_bits.to_le_bytes());
        hasher.update(&pk.challenge_bits.to_le_bytes());
        hasher.update(&pk.max_fold_arity.to_le_bytes());
        hasher.update(&pk.transcript_domain_digest);
        hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
        hasher.update(&(pk.ring_degree as u64).to_le_bytes());
        hasher.update(&pk.digit_bits.to_le_bytes());
        hasher.update(&(row_index as u64).to_le_bytes());
        hasher.update(&(col_index as u64).to_le_bytes());
        hasher.update(&(coeff_index as u64).to_le_bytes());
        let mut out = [0u8; 8];
        hasher.finalize_xof().fill(&mut out);
        coeffs.push(Goldilocks::new(u64::from_le_bytes(out)).as_canonical_u64());
    }
    RingElem::from_coeffs(coeffs)
}

fn prepare_commitment_matrix(pk: &BackendKey, message_len: usize) -> Arc<PreparedCommitmentMatrix> {
    let cache_key = prepared_matrix_cache_key(pk, message_len);
    if let Some(hit) = PREPARED_MATRIX_CACHE.with(|cache| cache.borrow_mut().get(&cache_key)) {
        update_kernel_cost_report(|report| {
            report.matrix_cache_hits += 1;
        });
        return hit;
    }

    let prepare_start = Instant::now();
    let mut rows = Vec::with_capacity(pk.commitment_rows);
    for row_index in 0..pk.commitment_rows {
        let mut row = Vec::with_capacity(message_len);
        for col_index in 0..message_len {
            row.push(matrix_entry(pk, row_index, col_index));
        }
        rows.push(row);
    }
    let prepared = Arc::new(PreparedCommitmentMatrix { rows });
    let evictions = PREPARED_MATRIX_CACHE.with(|cache| {
        cache.borrow_mut().insert(
            cache_key,
            prepared.clone(),
            PREPARED_MATRIX_CACHE_MAX_ENTRIES,
        )
    });
    update_kernel_cost_report(|report| {
        report.matrix_cache_misses += 1;
        report.matrix_cache_evictions += evictions;
        report.matrix_prepare_ns += prepare_start.elapsed().as_nanos();
    });
    prepared
}

fn prepared_matrix_cache_key(pk: &BackendKey, message_len: usize) -> [u8; 32] {
    let mut material = Vec::with_capacity(32 + 8 * 6);
    material.extend_from_slice(&pk.shape_digest.0);
    material.extend_from_slice(pk.ring_profile.label());
    material.extend_from_slice(&pk.security_bits.to_le_bytes());
    material.extend_from_slice(&pk.challenge_bits.to_le_bytes());
    material.extend_from_slice(&pk.max_fold_arity.to_le_bytes());
    material.extend_from_slice(&pk.transcript_domain_digest);
    material.extend_from_slice(&(pk.commitment_rows as u64).to_le_bytes());
    material.extend_from_slice(&(pk.ring_degree as u64).to_le_bytes());
    material.extend_from_slice(&pk.digit_bits.to_le_bytes());
    material.extend_from_slice(&(message_len as u64).to_le_bytes());
    digest32_with_label(b"hegemon.superneo.prepared-matrix.v1", &material)
}

fn digest_commitment_rows(rows: &[RingElem]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.commitment-digest.v2");
    hasher.update(&(rows.len() as u64).to_le_bytes());
    for row in rows {
        hasher.update(&(row.coeffs.len() as u64).to_le_bytes());
        for coeff in &row.coeffs {
            hasher.update(&coeff.to_le_bytes());
        }
    }
    hash48(hasher)
}

fn derive_fold_challenge(
    pk: &BackendKey,
    left: &FoldedInstance<LatticeCommitment>,
    right: &FoldedInstance<LatticeCommitment>,
) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-challenge.v2");
    hasher.update(pk.ring_profile.label());
    hasher.update(&pk.shape_digest.0);
    hasher.update(&left.relation_id.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
    hasher.update(&(pk.ring_degree as u64).to_le_bytes());
    hasher.update(&pk.digit_bits.to_le_bytes());
    hasher.update(&left.statement_digest.0);
    hasher.update(&right.statement_digest.0);
    hasher.update(&left.witness_commitment.digest);
    hasher.update(&right.witness_commitment.digest);
    let mut out = [0u8; 8];
    hasher.finalize_xof().fill(&mut out);
    let raw = u64::from_le_bytes(out);
    let mask_bits = pk.challenge_bits.min(16);
    let modulus = 1u64 << mask_bits;
    let reduced = if modulus <= 1 {
        1
    } else {
        (raw % (modulus - 1)) + 1
    };
    Goldilocks::new(reduced).as_canonical_u64()
}

fn fold_commitment_rows(
    left: &LatticeCommitment,
    right: &LatticeCommitment,
    challenge: u64,
) -> Result<Vec<RingElem>> {
    ensure!(
        !left.rows.is_empty() && !right.rows.is_empty(),
        "folded commitments require concrete row data"
    );
    ensure!(
        left.rows.len() == right.rows.len(),
        "folded commitments must have the same row length"
    );
    let mut stats = KernelLocalStats::default();
    let rows = left
        .rows
        .iter()
        .zip(&right.rows)
        .map(|(left_row, right_row)| {
            delayed_linear_combine(left_row, right_row, challenge, &mut stats)
        })
        .collect::<Result<Vec<_>>>()?;
    flush_kernel_stats(&stats);
    Ok(rows)
}

fn delayed_linear_combine(
    left: &RingElem,
    right: &RingElem,
    challenge: u64,
    stats: &mut KernelLocalStats,
) -> Result<RingElem> {
    ensure!(
        left.coeffs.len() == right.coeffs.len(),
        "cannot combine ring elements with different degrees"
    );
    stats.delayed_reduction_batches += 1;
    let challenge_bits = operand_bit_width(challenge);
    let mut coeffs = Vec::with_capacity(left.coeffs.len());
    for (left_coeff, right_coeff) in left.coeffs.iter().zip(&right.coeffs) {
        classify_mul_widths(challenge_bits, operand_bit_width(*right_coeff), 1, stats);
        let value = i128::from(*left_coeff) + i128::from(challenge) * i128::from(*right_coeff);
        coeffs.push(reduce_goldilocks_signed(value));
    }
    Ok(RingElem::from_coeffs(coeffs))
}

fn classify_mul_widths(left_bits: u16, right_bits: u16, count: u64, stats: &mut KernelLocalStats) {
    let left_small = left_bits <= 16;
    let right_small = right_bits <= 16;
    match (left_small, right_small) {
        (true, true) => stats.small_small_ops += count,
        (false, false) => stats.big_big_ops += count,
        _ => stats.small_big_ops += count,
    }
}

fn leaf_proof_digest(
    pk: &BackendKey,
    relation_id: &RelationId,
    statement_digest: &StatementDigest,
    packed: &PackedWitness<u64>,
    commitment_digest: &[u8; 48],
) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.leaf-proof.v2");
    hasher.update(pk.ring_profile.label());
    hasher.update(&pk.shape_digest.0);
    hasher.update(&relation_id.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
    hasher.update(&(pk.ring_degree as u64).to_le_bytes());
    hasher.update(&pk.digit_bits.to_le_bytes());
    hasher.update(&statement_digest.0);
    hasher.update(commitment_digest);
    hasher.update(&(packed.original_len as u64).to_le_bytes());
    hasher.update(&(packed.used_bits as u64).to_le_bytes());
    hasher.update(&packed.coeff_capacity_bits.to_le_bytes());
    hasher.update(&(packed.coeffs.len() as u64).to_le_bytes());
    for coeff in &packed.coeffs {
        hasher.update(&coeff.to_le_bytes());
    }
    hash48(hasher)
}

fn fold_statement_digest(
    left: &StatementDigest,
    right: &StatementDigest,
    challenge: u64,
    parent_commitment_digest: &[u8; 48],
) -> StatementDigest {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-statement.v2");
    hasher.update(&challenge.to_le_bytes());
    hasher.update(&left.0);
    hasher.update(&right.0);
    hasher.update(parent_commitment_digest);
    StatementDigest(hash48(hasher))
}

fn fold_proof_digest(
    pk: &BackendKey,
    relation_id: &RelationId,
    left: &FoldedInstance<LatticeCommitment>,
    right: &FoldedInstance<LatticeCommitment>,
    challenge: u64,
    parent_statement_digest: &StatementDigest,
    parent_commitment_digest: &[u8; 48],
) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-proof.v2");
    hasher.update(pk.ring_profile.label());
    hasher.update(&pk.shape_digest.0);
    hasher.update(&relation_id.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
    hasher.update(&(pk.ring_degree as u64).to_le_bytes());
    hasher.update(&pk.digit_bits.to_le_bytes());
    hasher.update(&challenge.to_le_bytes());
    hasher.update(&left.statement_digest.0);
    hasher.update(&right.statement_digest.0);
    hasher.update(&left.witness_commitment.digest);
    hasher.update(&right.witness_commitment.digest);
    hasher.update(&parent_statement_digest.0);
    hasher.update(parent_commitment_digest);
    hash48(hasher)
}

fn accumulate_negacyclic_product_narrow_source(
    accumulator: &mut [i128],
    left: &RingElem,
    right: &RingElem,
    stats: &mut KernelLocalStats,
) {
    accumulate_negacyclic_product_with_mode(accumulator, left, right, stats, true);
}

fn accumulate_negacyclic_product_generic_source(
    accumulator: &mut [i128],
    left: &RingElem,
    right: &RingElem,
    stats: &mut KernelLocalStats,
) {
    accumulate_negacyclic_product_with_mode(accumulator, left, right, stats, false);
}

fn accumulate_negacyclic_product_with_mode(
    accumulator: &mut [i128],
    left: &RingElem,
    right: &RingElem,
    stats: &mut KernelLocalStats,
    narrow_source: bool,
) {
    let degree = left.coeffs.len();
    stats.delayed_reduction_batches += 1;
    for (i, left_coeff) in left.coeffs.iter().enumerate() {
        for (j, right_coeff) in right.coeffs.iter().enumerate() {
            if *right_coeff == 0 {
                continue;
            }
            let target = i + j;
            let product = if narrow_source {
                stats.small_big_ops += 1;
                i128::from(*left_coeff) * i128::from((*right_coeff) as u16)
            } else {
                stats.big_big_ops += 1;
                i128::from(*left_coeff) * i128::from(*right_coeff)
            };
            if target < degree {
                accumulator[target] += product;
            } else {
                accumulator[target - degree] -= product;
            }
        }
    }
}

fn reduce_goldilocks_signed(value: i128) -> u64 {
    let mut reduced = value % GOLDILOCKS_MODULUS_I128;
    if reduced < 0 {
        reduced += GOLDILOCKS_MODULUS_I128;
    }
    reduced as u64
}

fn operand_bit_width(value: u64) -> u16 {
    let width = u64::BITS - value.leading_zeros();
    width.max(1) as u16
}

fn hash48(hasher: Hasher) -> [u8; 48] {
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn digest32_with_label(label: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(label);
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn hex_nibble(value: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[value as usize] as char
}

#[cfg(test)]
mod tests {
    use p3_goldilocks::Goldilocks;
    use superneo_ccs::{
        digest_statement, Assignment, CcsShape, SparseEntry, SparseMatrix, StatementEncoding,
        WitnessField, WitnessSchema,
    };
    use superneo_core::{Backend, FoldedInstance, SecurityParams};
    use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};

    use super::{
        clear_prepared_matrix_cache, reset_kernel_cost_report, take_kernel_cost_report,
        LatticeBackend, LatticeBackendConfig, LatticeCommitment, PreparedCommitmentMatrix,
        PreparedMatrixCache, RingElem, RingProfile,
    };
    use std::sync::Arc;

    fn shape() -> CcsShape<Goldilocks> {
        CcsShape {
            num_rows: 2,
            num_cols: 4,
            matrices: vec![SparseMatrix {
                row_count: 2,
                col_count: 4,
                entries: vec![SparseEntry {
                    row: 0,
                    col: 0,
                    value: Goldilocks::new(1),
                }],
            }],
            selectors: vec![Goldilocks::new(1)],
            witness_schema: WitnessSchema {
                fields: vec![
                    WitnessField {
                        name: "a",
                        bit_width: 8,
                        signed: false,
                        count: 2,
                    },
                    WitnessField {
                        name: "b",
                        bit_width: 4,
                        signed: false,
                        count: 1,
                    },
                ],
            },
        }
    }

    fn wide_shape() -> CcsShape<Goldilocks> {
        CcsShape {
            num_rows: 2,
            num_cols: 2,
            matrices: vec![SparseMatrix {
                row_count: 2,
                col_count: 2,
                entries: vec![SparseEntry {
                    row: 0,
                    col: 0,
                    value: Goldilocks::new(1),
                }],
            }],
            selectors: vec![Goldilocks::new(1)],
            witness_schema: WitnessSchema {
                fields: vec![
                    WitnessField {
                        name: "wide",
                        bit_width: 64,
                        signed: false,
                        count: 1,
                    },
                    WitnessField {
                        name: "narrow",
                        bit_width: 8,
                        signed: false,
                        count: 1,
                    },
                ],
            },
        }
    }

    #[test]
    fn leaf_and_fold_roundtrip() {
        let backend = LatticeBackend::new(LatticeBackendConfig::default());
        let security = SecurityParams::experimental_default();
        let (pk, vk) = backend.setup(&security, &shape()).unwrap();

        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let left_assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let right_assignment = Assignment {
            witness: vec![Goldilocks::new(11), Goldilocks::new(21), Goldilocks::new(4)],
        };
        let left_packed = packer.pack(&shape(), &left_assignment).unwrap();
        let right_packed = packer.pack(&shape(), &right_assignment).unwrap();
        let left_statement = StatementEncoding {
            public_inputs: vec![Goldilocks::new(1)],
            statement_digest: digest_statement(b"left"),
        };
        let right_statement = StatementEncoding {
            public_inputs: vec![Goldilocks::new(2)],
            statement_digest: digest_statement(b"right"),
        };
        let left_commitment = backend.commit_witness(&pk, &left_packed).unwrap();
        let right_commitment = backend.commit_witness(&pk, &right_packed).unwrap();

        let left_proof = backend
            .prove_leaf(
                &pk,
                &superneo_ccs::RelationId::from_label("test"),
                &left_statement,
                &left_packed,
                &left_commitment,
            )
            .unwrap();
        let right_proof = backend
            .prove_leaf(
                &pk,
                &superneo_ccs::RelationId::from_label("test"),
                &right_statement,
                &right_packed,
                &right_commitment,
            )
            .unwrap();
        backend
            .verify_leaf(
                &vk,
                &superneo_ccs::RelationId::from_label("test"),
                &left_statement,
                &left_packed,
                &left_proof,
            )
            .unwrap();
        backend
            .verify_leaf(
                &vk,
                &superneo_ccs::RelationId::from_label("test"),
                &right_statement,
                &right_packed,
                &right_proof,
            )
            .unwrap();

        let left_instance = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: left_statement.statement_digest,
            witness_commitment: left_commitment,
        };
        let right_instance = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: right_statement.statement_digest,
            witness_commitment: right_commitment,
        };
        let (parent, proof) = backend
            .fold_pair(&pk, &left_instance, &right_instance)
            .unwrap();
        backend
            .verify_fold(&vk, &parent, &left_instance, &right_instance, &proof)
            .unwrap();
    }

    #[test]
    fn verify_leaf_rejects_tampered_expected_witness() {
        let backend = LatticeBackend::new(LatticeBackendConfig::default());
        let security = SecurityParams::experimental_default();
        let (pk, vk) = backend.setup(&security, &shape()).unwrap();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let packed = packer.pack(&shape(), &assignment).unwrap();
        let statement = StatementEncoding {
            public_inputs: vec![Goldilocks::new(1)],
            statement_digest: digest_statement(b"left"),
        };
        let commitment = backend.commit_witness(&pk, &packed).unwrap();
        let proof = backend
            .prove_leaf(
                &pk,
                &superneo_ccs::RelationId::from_label("test"),
                &statement,
                &packed,
                &commitment,
            )
            .unwrap();
        let mut tampered = packed.clone();
        tampered.coeffs[0] ^= 1;
        assert!(backend
            .verify_leaf(
                &vk,
                &superneo_ccs::RelationId::from_label("test"),
                &statement,
                &tampered,
                &proof,
            )
            .is_err());
    }

    #[test]
    fn verify_fold_rejects_parent_metadata_mismatch() {
        let backend = LatticeBackend::new(LatticeBackendConfig::default());
        let security = SecurityParams::experimental_default();
        let (pk, vk) = backend.setup(&security, &shape()).unwrap();

        let left = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: digest_statement(b"left"),
            witness_commitment: LatticeCommitment::from_rows(vec![
                RingElem::from_coeffs(
                    vec![1u64; pk.ring_degree]
                );
                pk.commitment_rows
            ]),
        };
        let right = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: digest_statement(b"right"),
            witness_commitment: LatticeCommitment::from_rows(vec![
                RingElem::from_coeffs(
                    vec![2u64; pk.ring_degree]
                );
                pk.commitment_rows
            ]),
        };
        let (mut parent, proof) = backend.fold_pair(&pk, &left, &right).unwrap();
        parent.relation_id = superneo_ccs::RelationId::from_label("wrong");
        assert!(backend
            .verify_fold(&vk, &parent, &left, &right, &proof)
            .is_err());
    }

    #[test]
    fn kernel_report_tracks_cache_hits_and_delayed_reduction() {
        clear_prepared_matrix_cache();
        reset_kernel_cost_report();

        let backend = LatticeBackend::new(LatticeBackendConfig::default());
        let security = SecurityParams::experimental_default();
        let (pk, _) = backend.setup(&security, &shape()).unwrap();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let packed = packer.pack(&shape(), &assignment).unwrap();

        let first = backend.commit_witness(&pk, &packed).unwrap();
        let second = backend.commit_witness(&pk, &packed).unwrap();
        assert_eq!(first.digest, second.digest);

        let report = take_kernel_cost_report();
        assert_eq!(report.matrix_cache_misses, 1);
        assert!(report.matrix_cache_hits >= 1);
        assert!(report.commitment_kernel_ns > 0);
        assert!(report.delayed_reduction_batches > 0);
        assert!(report.small_big_ops > 0);
        assert_eq!(report.big_big_ops, 0);
    }

    #[test]
    fn prepared_matrix_cache_key_separates_ring_profiles() {
        clear_prepared_matrix_cache();
        reset_kernel_cost_report();

        let security = SecurityParams::experimental_default();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let packed = packer.pack(&shape(), &assignment).unwrap();

        let cyclotomic_backend = LatticeBackend::new(LatticeBackendConfig::default());
        let frog_backend = LatticeBackend::new(LatticeBackendConfig {
            ring_profile: RingProfile::GoldilocksFrog,
            ..LatticeBackendConfig::default()
        });
        let (cyclotomic_pk, _) = cyclotomic_backend.setup(&security, &shape()).unwrap();
        let (frog_pk, _) = frog_backend.setup(&security, &shape()).unwrap();

        let cyclotomic_commitment = cyclotomic_backend
            .commit_witness(&cyclotomic_pk, &packed)
            .unwrap();
        let frog_commitment = frog_backend.commit_witness(&frog_pk, &packed).unwrap();

        let report = take_kernel_cost_report();
        assert_eq!(report.matrix_cache_misses, 2);
        assert_eq!(report.matrix_cache_hits, 0);
        assert_ne!(cyclotomic_commitment.digest, frog_commitment.digest);
        assert_ne!(cyclotomic_commitment.rows, frog_commitment.rows);
    }

    #[test]
    fn prepared_matrix_cache_evicts_least_recently_used_entries() {
        let mut cache = PreparedMatrixCache::default();
        let matrix = |seed| {
            Arc::new(PreparedCommitmentMatrix {
                rows: vec![vec![RingElem::from_coeffs(vec![seed])]],
            })
        };
        let first = [1u8; 32];
        let second = [2u8; 32];
        let third = [3u8; 32];

        assert_eq!(cache.insert(first, matrix(1), 2), 0);
        assert_eq!(cache.insert(second, matrix(2), 2), 0);
        assert!(cache.get(&first).is_some());

        assert_eq!(cache.insert(third, matrix(3), 2), 1);
        assert!(cache.get(&first).is_some());
        assert!(cache.get(&second).is_none());
        assert!(cache.get(&third).is_some());
        assert_eq!(cache.entries.len(), 2);
    }

    #[test]
    fn width_metadata_drives_generic_commitment_kernel() {
        clear_prepared_matrix_cache();
        reset_kernel_cost_report();

        let backend = LatticeBackend::new(LatticeBackendConfig::default());
        let security = SecurityParams::experimental_default();
        let (pk, _) = backend.setup(&security, &wide_shape()).unwrap();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let assignment = Assignment {
            witness: vec![Goldilocks::new(1u64 << 40), Goldilocks::new(7)],
        };
        let packed = packer.pack(&wide_shape(), &assignment).unwrap();

        backend.commit_witness(&pk, &packed).unwrap();

        let report = take_kernel_cost_report();
        assert!(report.big_big_ops > 0);
    }
}
