use core::fmt;
use crypto::hash384::{domains, Nullifier48, NullifierAccumulatorRoot48};
use crypto::hashes::{blake2b_384_domain_hash, BLAKE2B_384_FRAME_V1};

const NULLIFIER_MMR_LEAF_DOMAIN_V3: &[u8] = domains::NULLIFIER_MMR_LEAF_V3;
const NULLIFIER_MMR_NODE_DOMAIN_V3: &[u8] = domains::NULLIFIER_MMR_NODE_V3;
const NULLIFIER_MMR_ROOT_DOMAIN_V3: &[u8] = domains::NULLIFIER_MMR_ROOT_V3;
const NULLIFIER_MMR_STATE_DOMAIN_V3: &[u8] = domains::NULLIFIER_MMR_STATE_V3;
const NULLIFIER_MMR_LEAF_DOMAIN_V2: &[u8] = domains::NULLIFIER_MMR_LEAF_V2;
const NULLIFIER_MMR_NODE_DOMAIN_V2: &[u8] = domains::NULLIFIER_MMR_NODE_V2;
const NULLIFIER_MMR_ROOT_DOMAIN_V2: &[u8] = domains::NULLIFIER_MMR_ROOT_V2;
const LEGACY_NULLIFIER_MMR_STATE_DOMAIN_V2: &[u8] = domains::NULLIFIER_MMR_STATE_V2;
const NULLIFIER_MMR_MAX_PEAKS: usize = u64::BITS as usize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NullifierAccumulatorV3 {
    leaf_count: u64,
    peaks: Vec<[u8; 48]>,
}

/// Exact suffix delta for the persisted `shielded_nullifiers` index.
///
/// Each row is `(append_index, nullifier)`; sled stores the nullifier as the
/// key and `append_index.to_be_bytes()` as the value. A reorg can plan the old
/// suffix from the common-ancestor checkpoint and compare `next_accumulator`
/// with the old tip before deleting these rows, then independently plan the
/// new suffix from the same checkpoint before inserting it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NullifierIndexedAppendV3 {
    pub(crate) base_leaf_count: u64,
    pub(crate) rows: Vec<(u64, Nullifier48)>,
    pub(crate) next_accumulator: NullifierAccumulatorV3,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NullifierAccumulatorWork {
    pub(crate) leaf_hashes: u64,
    pub(crate) node_hashes: u64,
    pub(crate) root_hashes: u64,
    pub(crate) transcript_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NullifierAccumulatorError {
    ZeroNullifier,
    LeafCountOverflow,
    InvalidIndexSequence,
    InvalidPeakShape,
    LegacyV2Encoding,
    InvalidEncoding,
    StoredRootMismatch,
}

impl fmt::Display for NullifierAccumulatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ZeroNullifier => "nullifier accumulator rejects the zero nullifier",
            Self::LeafCountOverflow => "nullifier accumulator leaf-count overflow",
            Self::InvalidIndexSequence => "nullifier accumulator index sequence is invalid",
            Self::InvalidPeakShape => "nullifier accumulator peak shape is invalid",
            Self::LegacyV2Encoding => {
                "legacy 48-byte nullifier accumulator v2 state is not valid under V3"
            }
            Self::InvalidEncoding => "nullifier accumulator encoding is invalid",
            Self::StoredRootMismatch => "nullifier accumulator stored root mismatch",
        };
        formatter.write_str(label)
    }
}

impl std::error::Error for NullifierAccumulatorError {}

/// Active raw-48/v2 accumulator. It stays byte-for-byte stable until every
/// V3 producer and consumer can switch atomically; no raw-to-typed adapter
/// exists at the version boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NullifierAccumulator {
    leaf_count: u64,
    peaks: Vec<[u8; 48]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NullifierIndexedAppend {
    pub(crate) base_leaf_count: u64,
    pub(crate) rows: Vec<(u64, [u8; 48])>,
    pub(crate) next_accumulator: NullifierAccumulator,
}

impl Default for NullifierAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl NullifierAccumulator {
    pub(crate) const fn new() -> Self {
        Self {
            leaf_count: 0,
            peaks: Vec::new(),
        }
    }

    pub(crate) fn from_append_order(
        nullifiers: impl IntoIterator<Item = [u8; 48]>,
    ) -> Result<Self, NullifierAccumulatorError> {
        let mut accumulator = Self::new();
        accumulator.append_all(nullifiers)?;
        Ok(accumulator)
    }

    pub(crate) fn from_indexed_rows(
        rows: &[(u64, [u8; 48])],
    ) -> Result<Self, NullifierAccumulatorError> {
        for (expected, (observed, _)) in rows.iter().enumerate() {
            if u64::try_from(expected).ok() != Some(*observed) {
                return Err(NullifierAccumulatorError::InvalidIndexSequence);
            }
        }
        Self::from_append_order(rows.iter().map(|(_, nullifier)| *nullifier))
    }

    pub(crate) const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub(crate) fn root(&self) -> [u8; 48] {
        legacy_nullifier_root(self.leaf_count, &self.peaks)
    }

    pub(crate) fn append(&mut self, nullifier: [u8; 48]) -> Result<(), NullifierAccumulatorError> {
        if nullifier == [0u8; 48] {
            return Err(NullifierAccumulatorError::ZeroNullifier);
        }
        self.validate_shape()?;
        let next_count = self
            .leaf_count
            .checked_add(1)
            .ok_or(NullifierAccumulatorError::LeafCountOverflow)?;
        let mut candidate_peaks = self.peaks.clone();
        let mut right = legacy_nullifier_mmr_leaf_hash(nullifier);
        let mut height = 0u32;
        let mut merges = self.leaf_count.trailing_ones();
        while merges != 0 {
            let left = candidate_peaks
                .pop()
                .ok_or(NullifierAccumulatorError::InvalidPeakShape)?;
            height = height
                .checked_add(1)
                .ok_or(NullifierAccumulatorError::InvalidPeakShape)?;
            right = legacy_nullifier_mmr_parent_hash(height, left, right);
            merges -= 1;
        }
        candidate_peaks.push(right);
        self.leaf_count = next_count;
        self.peaks = candidate_peaks;
        self.validate_shape()
    }

    pub(crate) fn append_all(
        &mut self,
        nullifiers: impl IntoIterator<Item = [u8; 48]>,
    ) -> Result<(), NullifierAccumulatorError> {
        let mut candidate = self.clone();
        for nullifier in nullifiers {
            candidate.append(nullifier)?;
        }
        *self = candidate;
        Ok(())
    }

    pub(crate) fn plan_indexed_append(
        &self,
        nullifiers: impl IntoIterator<Item = [u8; 48]>,
    ) -> Result<NullifierIndexedAppend, NullifierAccumulatorError> {
        self.validate_shape()?;
        let mut next_accumulator = self.clone();
        let mut rows = Vec::new();
        for nullifier in nullifiers {
            let index = next_accumulator.leaf_count;
            next_accumulator.append(nullifier)?;
            rows.push((index, nullifier));
        }
        Ok(NullifierIndexedAppend {
            base_leaf_count: self.leaf_count,
            rows,
            next_accumulator,
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, NullifierAccumulatorError> {
        self.validate_shape()?;
        let mut encoded = Vec::with_capacity(
            LEGACY_NULLIFIER_MMR_STATE_DOMAIN_V2.len() + 8 + 48 + 4 + self.peaks.len() * 48,
        );
        encoded.extend_from_slice(LEGACY_NULLIFIER_MMR_STATE_DOMAIN_V2);
        encoded.extend_from_slice(&self.leaf_count.to_le_bytes());
        encoded.extend_from_slice(&self.root());
        encoded.extend_from_slice(&(self.peaks.len() as u32).to_le_bytes());
        for peak in &self.peaks {
            encoded.extend_from_slice(peak);
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, NullifierAccumulatorError> {
        let fixed = LEGACY_NULLIFIER_MMR_STATE_DOMAIN_V2.len() + 8 + 48 + 4;
        if encoded.len() < fixed
            || &encoded[..LEGACY_NULLIFIER_MMR_STATE_DOMAIN_V2.len()]
                != LEGACY_NULLIFIER_MMR_STATE_DOMAIN_V2
        {
            return Err(NullifierAccumulatorError::InvalidEncoding);
        }
        let mut cursor = LEGACY_NULLIFIER_MMR_STATE_DOMAIN_V2.len();
        let leaf_count = read_u64_le(encoded, &mut cursor)?;
        let stored_root = read_array48(encoded, &mut cursor)?;
        let peak_count = usize::try_from(read_u32_le(encoded, &mut cursor)?)
            .map_err(|_| NullifierAccumulatorError::InvalidEncoding)?;
        if peak_count > NULLIFIER_MMR_MAX_PEAKS
            || encoded.len().checked_sub(cursor) != peak_count.checked_mul(48)
        {
            return Err(NullifierAccumulatorError::InvalidEncoding);
        }
        let mut peaks = Vec::with_capacity(peak_count);
        for _ in 0..peak_count {
            peaks.push(read_array48(encoded, &mut cursor)?);
        }
        let accumulator = Self { leaf_count, peaks };
        accumulator.validate_shape()?;
        if accumulator.root() != stored_root {
            return Err(NullifierAccumulatorError::StoredRootMismatch);
        }
        Ok(accumulator)
    }

    fn validate_shape(&self) -> Result<(), NullifierAccumulatorError> {
        if self.peaks.len() != self.leaf_count.count_ones() as usize
            || self.peaks.len() > NULLIFIER_MMR_MAX_PEAKS
        {
            return Err(NullifierAccumulatorError::InvalidPeakShape);
        }
        Ok(())
    }
}

impl Default for NullifierAccumulatorV3 {
    fn default() -> Self {
        Self::new()
    }
}

impl NullifierAccumulatorV3 {
    pub(crate) const fn new() -> Self {
        Self {
            leaf_count: 0,
            peaks: Vec::new(),
        }
    }

    pub(crate) fn from_append_order(
        nullifiers: impl IntoIterator<Item = Nullifier48>,
    ) -> Result<Self, NullifierAccumulatorError> {
        let mut accumulator = Self::new();
        accumulator.append_all(nullifiers)?;
        Ok(accumulator)
    }

    pub(crate) fn from_indexed_rows(
        rows: &[(u64, Nullifier48)],
    ) -> Result<Self, NullifierAccumulatorError> {
        for (expected, (observed, _)) in rows.iter().enumerate() {
            if u64::try_from(expected).ok() != Some(*observed) {
                return Err(NullifierAccumulatorError::InvalidIndexSequence);
            }
        }
        Self::from_append_order(rows.iter().map(|(_, nullifier)| *nullifier))
    }

    pub(crate) const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub(crate) fn root(&self) -> NullifierAccumulatorRoot48 {
        self.root_measured().0
    }

    pub(crate) fn append(
        &mut self,
        nullifier: Nullifier48,
    ) -> Result<(), NullifierAccumulatorError> {
        self.append_measured(nullifier).map(|_| ())
    }

    pub(crate) fn append_all(
        &mut self,
        nullifiers: impl IntoIterator<Item = Nullifier48>,
    ) -> Result<(), NullifierAccumulatorError> {
        let mut candidate = self.clone();
        for nullifier in nullifiers {
            candidate.append(nullifier)?;
        }
        *self = candidate;
        Ok(())
    }

    /// Plan a contiguous append-index suffix without mutating the checkpoint.
    ///
    /// This is the frozen reorg seam: both the orphaned and replacement
    /// suffix are derived from the same independently validated ancestor
    /// accumulator. Duplicate membership remains the caller's exact-set
    /// invariant; zero values, malformed checkpoint shape, and `u64` overflow
    /// reject before any externally visible mutation.
    pub(crate) fn plan_indexed_append(
        &self,
        nullifiers: impl IntoIterator<Item = Nullifier48>,
    ) -> Result<NullifierIndexedAppendV3, NullifierAccumulatorError> {
        self.validate_shape()?;
        let base_leaf_count = self.leaf_count;
        let mut next_accumulator = self.clone();
        let mut rows = Vec::new();
        for nullifier in nullifiers {
            let index = next_accumulator.leaf_count;
            next_accumulator.append(nullifier)?;
            rows.push((index, nullifier));
        }
        Ok(NullifierIndexedAppendV3 {
            base_leaf_count,
            rows,
            next_accumulator,
        })
    }

    pub(crate) fn append_measured(
        &mut self,
        nullifier: Nullifier48,
    ) -> Result<NullifierAccumulatorWork, NullifierAccumulatorError> {
        if nullifier == Nullifier48::ZERO {
            return Err(NullifierAccumulatorError::ZeroNullifier);
        }
        self.validate_shape()?;
        let next_count = self
            .leaf_count
            .checked_add(1)
            .ok_or(NullifierAccumulatorError::LeafCountOverflow)?;
        let mut work = NullifierAccumulatorWork {
            leaf_hashes: 1,
            transcript_bytes: framed_transcript_len(
                NULLIFIER_MMR_LEAF_DOMAIN_V3,
                [nullifier.as_bytes().len()],
            ),
            ..NullifierAccumulatorWork::default()
        };
        let mut height = 0u32;
        let mut right = nullifier_mmr_leaf_hash(nullifier);
        let mut merges = self.leaf_count.trailing_ones();
        while merges != 0 {
            let left = self
                .peaks
                .pop()
                .ok_or(NullifierAccumulatorError::InvalidPeakShape)?;
            height = height
                .checked_add(1)
                .ok_or(NullifierAccumulatorError::InvalidPeakShape)?;
            right = nullifier_mmr_parent_hash(height, left, right);
            work.node_hashes += 1;
            work.transcript_bytes +=
                framed_transcript_len(NULLIFIER_MMR_NODE_DOMAIN_V3, [4, 48, 48]);
            merges -= 1;
        }
        self.peaks.push(right);
        self.leaf_count = next_count;
        self.validate_shape()?;
        Ok(work)
    }

    pub(crate) fn root_measured(&self) -> (NullifierAccumulatorRoot48, NullifierAccumulatorWork) {
        let leaf_count = self.leaf_count.to_le_bytes();
        let peak_count = (self.peaks.len() as u32).to_le_bytes();
        let fixed: [&[u8]; 2] = [&leaf_count, &peak_count];
        let root = NullifierAccumulatorRoot48::new(blake2b_384_domain_hash(
            NULLIFIER_MMR_ROOT_DOMAIN_V3,
            fixed
                .into_iter()
                .chain(self.peaks.iter().map(|peak| peak.as_slice())),
        ));
        (
            root,
            NullifierAccumulatorWork {
                root_hashes: 1,
                transcript_bytes: framed_transcript_len(
                    NULLIFIER_MMR_ROOT_DOMAIN_V3,
                    core::iter::once(8)
                        .chain(core::iter::once(4))
                        .chain(core::iter::repeat_n(48, self.peaks.len())),
                ),
                ..NullifierAccumulatorWork::default()
            },
        )
    }

    /// Canonical durable encoding:
    /// `domain || leaf_count_le || root || peak_count_le || peaks`.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, NullifierAccumulatorError> {
        self.validate_shape()?;
        let root = self.root();
        let mut encoded = Vec::with_capacity(
            NULLIFIER_MMR_STATE_DOMAIN_V3.len() + 8 + 48 + 4 + self.peaks.len() * 48,
        );
        encoded.extend_from_slice(NULLIFIER_MMR_STATE_DOMAIN_V3);
        encoded.extend_from_slice(&self.leaf_count.to_le_bytes());
        encoded.extend_from_slice(root.as_bytes());
        encoded.extend_from_slice(&(self.peaks.len() as u32).to_le_bytes());
        for peak in &self.peaks {
            encoded.extend_from_slice(peak);
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, NullifierAccumulatorError> {
        if encoded.starts_with(LEGACY_NULLIFIER_MMR_STATE_DOMAIN_V2) {
            return Err(NullifierAccumulatorError::LegacyV2Encoding);
        }
        let fixed = NULLIFIER_MMR_STATE_DOMAIN_V3.len() + 8 + 48 + 4;
        if encoded.len() < fixed
            || &encoded[..NULLIFIER_MMR_STATE_DOMAIN_V3.len()] != NULLIFIER_MMR_STATE_DOMAIN_V3
        {
            return Err(NullifierAccumulatorError::InvalidEncoding);
        }
        let mut cursor = NULLIFIER_MMR_STATE_DOMAIN_V3.len();
        let leaf_count = read_u64_le(encoded, &mut cursor)?;
        let stored_root = NullifierAccumulatorRoot48::new(read_array48(encoded, &mut cursor)?);
        let peak_count = usize::try_from(read_u32_le(encoded, &mut cursor)?)
            .map_err(|_| NullifierAccumulatorError::InvalidEncoding)?;
        if peak_count > NULLIFIER_MMR_MAX_PEAKS {
            return Err(NullifierAccumulatorError::InvalidEncoding);
        }
        let peak_bytes = peak_count
            .checked_mul(48)
            .ok_or(NullifierAccumulatorError::InvalidEncoding)?;
        if encoded.len().checked_sub(cursor) != Some(peak_bytes) {
            return Err(NullifierAccumulatorError::InvalidEncoding);
        }
        let mut peaks = Vec::with_capacity(peak_count);
        for _ in 0..peak_count {
            peaks.push(read_array48(encoded, &mut cursor)?);
        }
        let accumulator = Self { leaf_count, peaks };
        accumulator.validate_shape()?;
        if accumulator.root() != stored_root {
            return Err(NullifierAccumulatorError::StoredRootMismatch);
        }
        Ok(accumulator)
    }

    pub(crate) fn validate_shape(&self) -> Result<(), NullifierAccumulatorError> {
        if self.peaks.len() != self.leaf_count.count_ones() as usize
            || self.peaks.len() > NULLIFIER_MMR_MAX_PEAKS
        {
            return Err(NullifierAccumulatorError::InvalidPeakShape);
        }
        Ok(())
    }
}

fn nullifier_mmr_leaf_hash(nullifier: Nullifier48) -> [u8; 48] {
    blake2b_384_domain_hash(
        NULLIFIER_MMR_LEAF_DOMAIN_V3,
        [nullifier.as_bytes().as_slice()],
    )
}

fn nullifier_mmr_parent_hash(parent_height: u32, left: [u8; 48], right: [u8; 48]) -> [u8; 48] {
    let parent_height = parent_height.to_le_bytes();
    let parts: [&[u8]; 3] = [parent_height.as_slice(), left.as_slice(), right.as_slice()];
    blake2b_384_domain_hash(NULLIFIER_MMR_NODE_DOMAIN_V3, parts)
}

fn legacy_nullifier_mmr_leaf_hash(nullifier: [u8; 48]) -> [u8; 48] {
    blake2b_384_domain_hash(NULLIFIER_MMR_LEAF_DOMAIN_V2, [nullifier.as_slice()])
}

fn legacy_nullifier_mmr_parent_hash(
    parent_height: u32,
    left: [u8; 48],
    right: [u8; 48],
) -> [u8; 48] {
    let height = parent_height.to_le_bytes();
    blake2b_384_domain_hash(
        NULLIFIER_MMR_NODE_DOMAIN_V2,
        [height.as_slice(), left.as_slice(), right.as_slice()],
    )
}

fn legacy_nullifier_root(leaf_count: u64, peaks: &[[u8; 48]]) -> [u8; 48] {
    let leaf_count = leaf_count.to_le_bytes();
    let peak_count = (peaks.len() as u32).to_le_bytes();
    let fixed: [&[u8]; 2] = [&leaf_count, &peak_count];
    blake2b_384_domain_hash(
        NULLIFIER_MMR_ROOT_DOMAIN_V2,
        fixed
            .into_iter()
            .chain(peaks.iter().map(|peak| peak.as_slice())),
    )
}

fn framed_transcript_len(domain: &[u8], part_lengths: impl IntoIterator<Item = usize>) -> u64 {
    let mut total = BLAKE2B_384_FRAME_V1.len() as u64 + 8 + domain.len() as u64;
    for part_len in part_lengths {
        total = total.saturating_add(8 + part_len as u64);
    }
    total
}

fn read_u64_le(bytes: &[u8], cursor: &mut usize) -> Result<u64, NullifierAccumulatorError> {
    let raw = read_exact::<8>(bytes, cursor)?;
    Ok(u64::from_le_bytes(raw))
}

fn read_u32_le(bytes: &[u8], cursor: &mut usize) -> Result<u32, NullifierAccumulatorError> {
    let raw = read_exact::<4>(bytes, cursor)?;
    Ok(u32::from_le_bytes(raw))
}

fn read_array48(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 48], NullifierAccumulatorError> {
    read_exact::<48>(bytes, cursor)
}

fn read_exact<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], NullifierAccumulatorError> {
    let end = cursor
        .checked_add(N)
        .ok_or(NullifierAccumulatorError::InvalidEncoding)?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(NullifierAccumulatorError::InvalidEncoding)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    *cursor = end;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::NullifierAccumulatorV3 as NullifierAccumulator;
    use super::*;

    #[derive(serde::Deserialize)]
    struct LeanNullifierAccumulatorVectorFile {
        schema_version: u32,
        hash_algorithm: String,
        accumulator_version: u32,
        nullifier_bytes: u32,
        leaf_domain: String,
        node_domain: String,
        root_domain: String,
        state_domain: String,
        nullifier_accumulator_cases: Vec<LeanNullifierAccumulatorCase>,
    }

    #[derive(serde::Deserialize)]
    struct LeanNullifierAccumulatorCase {
        name: String,
        blocks: Vec<Vec<u64>>,
        expected_valid: bool,
        expected_leaf_count: u64,
        expected_peak_heights: Vec<u32>,
        expected_peak_leaves: Vec<Vec<u64>>,
        expected_merge_counts: Vec<u64>,
    }

    #[test]
    fn incremental_roots_match_independent_full_recomputation() {
        let nullifiers = deterministic_nullifiers(512);
        let mut accumulator = NullifierAccumulator::new();
        assert_eq!(
            accumulator.root(),
            NullifierAccumulatorRoot48::new(reference_root(&[]))
        );
        for (index, nullifier) in nullifiers.iter().copied().enumerate() {
            accumulator.append(nullifier).expect("append nullifier");
            assert_eq!(
                accumulator.root(),
                NullifierAccumulatorRoot48::new(reference_root(&nullifiers[..=index])),
                "incremental root diverged after {} leaves",
                index + 1
            );
        }
    }

    #[test]
    fn fixed_transcript_vectors_pin_domains_and_byte_order() {
        let nullifiers = (1u8..=8).map(tagged_nullifier).collect::<Vec<_>>();
        for (count, expected) in [
            (
                0usize,
                [
                    1, 234, 226, 96, 28, 211, 122, 39, 9, 127, 94, 84, 177, 52, 160, 198, 66, 159,
                    212, 230, 87, 222, 119, 105, 146, 139, 62, 230, 113, 215, 128, 196, 219, 187,
                    214, 103, 84, 37, 189, 32, 73, 200, 126, 246, 227, 135, 77, 214,
                ],
            ),
            (
                1usize,
                [
                    64, 131, 2, 11, 120, 250, 9, 112, 154, 78, 245, 8, 87, 64, 161, 177, 6, 173,
                    109, 70, 202, 125, 145, 243, 2, 127, 78, 218, 52, 53, 201, 83, 141, 151, 193,
                    233, 236, 167, 229, 239, 101, 213, 100, 134, 19, 132, 199, 42,
                ],
            ),
            (
                3usize,
                [
                    214, 48, 36, 54, 27, 171, 224, 251, 26, 114, 234, 93, 133, 245, 179, 100, 236,
                    21, 79, 51, 139, 252, 106, 229, 238, 50, 109, 237, 60, 187, 88, 250, 221, 17,
                    67, 111, 58, 124, 21, 27, 181, 132, 224, 148, 51, 137, 106, 187,
                ],
            ),
            (
                8usize,
                [
                    193, 234, 231, 91, 75, 16, 137, 241, 82, 32, 220, 84, 109, 238, 131, 154, 45,
                    166, 233, 37, 12, 135, 58, 128, 161, 99, 143, 54, 178, 61, 250, 113, 161, 71,
                    47, 31, 92, 213, 189, 235, 145, 217, 227, 2, 112, 119, 99, 225,
                ],
            ),
        ] {
            let accumulator =
                NullifierAccumulator::from_append_order(nullifiers[..count].iter().copied())
                    .expect("build fixed-vector accumulator");
            assert_eq!(
                accumulator.root(),
                NullifierAccumulatorRoot48::new(expected),
                "fixed root at {count} leaves"
            );

            let encoded = accumulator.encode().expect("encode fixed-vector state");
            assert_eq!(
                encoded.get(..b"hegemon.nullifier-mmr.blake2b-384.state-v3".len()),
                Some(b"hegemon.nullifier-mmr.blake2b-384.state-v3".as_slice())
            );
            let count_offset = b"hegemon.nullifier-mmr.blake2b-384.state-v3".len();
            assert_eq!(
                encoded.get(count_offset..count_offset + 8),
                Some((count as u64).to_le_bytes().as_slice())
            );
            assert_eq!(
                encoded.get(count_offset + 8..count_offset + 8 + 48),
                Some(expected.as_slice())
            );
            assert_eq!(
                encoded.get(count_offset + 8 + 48..count_offset + 8 + 48 + 4),
                Some((count as u64).count_ones().to_le_bytes().as_slice())
            );
        }
    }

    #[test]
    fn active_v2_transcript_and_persisted_state_remain_byte_stable() {
        use super::NullifierAccumulator as LegacyNullifierAccumulatorV2;

        let nullifiers = (1u8..=8).map(|tag| [tag; 48]).collect::<Vec<_>>();
        for (count, expected) in [
            (
                0usize,
                [
                    159, 67, 113, 31, 148, 161, 185, 5, 34, 188, 101, 195, 35, 171, 247, 61, 16,
                    108, 61, 207, 148, 19, 198, 6, 203, 144, 207, 53, 34, 173, 60, 139, 107, 199,
                    51, 95, 90, 123, 8, 236, 100, 70, 136, 182, 194, 14, 39, 249,
                ],
            ),
            (
                1usize,
                [
                    147, 82, 46, 145, 27, 221, 62, 231, 234, 42, 8, 216, 26, 183, 57, 57, 110, 121,
                    127, 35, 160, 215, 183, 226, 56, 109, 166, 36, 85, 44, 72, 198, 26, 22, 130,
                    197, 222, 39, 164, 69, 223, 172, 80, 82, 229, 160, 34, 228,
                ],
            ),
            (
                3usize,
                [
                    121, 169, 32, 147, 147, 64, 148, 150, 70, 232, 194, 159, 48, 200, 84, 172, 66,
                    222, 185, 119, 166, 162, 81, 248, 211, 110, 198, 234, 234, 193, 132, 160, 16,
                    161, 147, 151, 255, 245, 198, 161, 135, 105, 154, 205, 64, 231, 230, 144,
                ],
            ),
            (
                8usize,
                [
                    232, 56, 195, 24, 255, 17, 24, 56, 9, 199, 16, 174, 200, 150, 236, 254, 42,
                    248, 62, 131, 253, 183, 194, 246, 20, 35, 166, 164, 250, 118, 206, 250, 90,
                    248, 157, 38, 113, 162, 192, 150, 199, 241, 126, 159, 181, 114, 206, 242,
                ],
            ),
        ] {
            let accumulator = LegacyNullifierAccumulatorV2::from_append_order(
                nullifiers[..count].iter().copied(),
            )
            .expect("build active V2 accumulator");
            assert_eq!(
                accumulator.root(),
                expected,
                "active V2 root at {count} leaves"
            );

            let persisted_v2 = accumulator.encode().expect("encode active V2 state");
            assert_eq!(
                LegacyNullifierAccumulatorV2::decode(&persisted_v2)
                    .expect("decode active V2 state"),
                accumulator
            );
            assert_eq!(
                NullifierAccumulator::decode(&persisted_v2),
                Err(NullifierAccumulatorError::LegacyV2Encoding),
                "V3 must reject persisted V2 state without a width adapter"
            );
        }
    }

    #[test]
    fn blake2b_384_known_answer_and_domain_mutations_are_pinned() {
        assert_eq!(
            hex::encode(crypto::hashes::blake2b_384(b"abc")),
            "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"
        );

        let nullifiers = (1u8..=3).map(tagged_nullifier).collect::<Vec<_>>();
        let canonical = reference_root(&nullifiers);
        for (label, leaf_domain, node_domain, root_domain) in [
            (
                "leaf",
                b"hegemon.nullifier-mmr.blake2b-384.leaf-v3!".as_slice(),
                b"hegemon.nullifier-mmr.blake2b-384.node-v3".as_slice(),
                b"hegemon.nullifier-mmr.blake2b-384.root-v3".as_slice(),
            ),
            (
                "node",
                b"hegemon.nullifier-mmr.blake2b-384.leaf-v3".as_slice(),
                b"hegemon.nullifier-mmr.blake2b-384.node-v3!".as_slice(),
                b"hegemon.nullifier-mmr.blake2b-384.root-v3".as_slice(),
            ),
            (
                "root",
                b"hegemon.nullifier-mmr.blake2b-384.leaf-v3".as_slice(),
                b"hegemon.nullifier-mmr.blake2b-384.node-v3".as_slice(),
                b"hegemon.nullifier-mmr.blake2b-384.root-v3!".as_slice(),
            ),
        ] {
            assert_ne!(
                reference_root_with_domains(&nullifiers, leaf_domain, node_domain, root_domain,),
                canonical,
                "{label} domain mutation must change the root"
            );
        }
    }

    #[test]
    fn lean_nullifier_accumulator_vectors_match_rust() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_NULLIFIER_ACCUMULATOR_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_NULLIFIER_ACCUMULATOR_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(path)
            .expect("read generated Lean nullifier-accumulator vectors");
        let vectors: LeanNullifierAccumulatorVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean nullifier-accumulator vectors");
        assert_eq!(vectors.schema_version, 3);
        assert_eq!(vectors.hash_algorithm, "RFC7693-BLAKE2b-384");
        assert_eq!(vectors.accumulator_version, 3);
        assert_eq!(vectors.nullifier_bytes, 48);
        assert_eq!(vectors.leaf_domain.as_bytes(), NULLIFIER_MMR_LEAF_DOMAIN_V3);
        assert_eq!(vectors.node_domain.as_bytes(), NULLIFIER_MMR_NODE_DOMAIN_V3);
        assert_eq!(vectors.root_domain.as_bytes(), NULLIFIER_MMR_ROOT_DOMAIN_V3);
        assert_eq!(
            vectors.state_domain.as_bytes(),
            NULLIFIER_MMR_STATE_DOMAIN_V3
        );
        assert!(!vectors.nullifier_accumulator_cases.is_empty());

        let mut names = std::collections::BTreeSet::new();
        for case in vectors.nullifier_accumulator_cases {
            assert!(names.insert(case.name.clone()), "duplicate vector name");
            let mut accumulator = NullifierAccumulator::new();
            let mut merge_counts = Vec::new();
            let mut accepted = true;
            'blocks: for block in &case.blocks {
                let before_block = accumulator.clone();
                for tag in block {
                    let tag = u8::try_from(*tag).expect("Lean nullifier tag fits one byte");
                    let before_append = accumulator.clone();
                    match accumulator.append_measured(tagged_nullifier(tag)) {
                        Ok(work) => merge_counts.push(work.node_hashes),
                        Err(NullifierAccumulatorError::ZeroNullifier) => {
                            assert_eq!(
                                accumulator, before_append,
                                "{} zero rejection mutated accumulator",
                                case.name
                            );
                            accepted = false;
                            break 'blocks;
                        }
                        Err(error) => panic!("{} unexpected append error: {error}", case.name),
                    }
                }
                if block.is_empty() {
                    assert_eq!(
                        accumulator, before_block,
                        "{} empty block mutated accumulator",
                        case.name
                    );
                }
            }

            assert_eq!(accepted, case.expected_valid, "{} validity", case.name);
            assert_eq!(
                merge_counts, case.expected_merge_counts,
                "{} carry schedule",
                case.name
            );
            if !accepted {
                assert_eq!(case.expected_leaf_count, 0);
                assert!(case.expected_peak_heights.is_empty());
                assert!(case.expected_peak_leaves.is_empty());
                continue;
            }

            assert_eq!(
                accumulator.leaf_count(),
                case.expected_leaf_count,
                "{} leaf count",
                case.name
            );
            let expected_heights = case
                .expected_peak_leaves
                .iter()
                .map(|leaves| {
                    assert!(leaves.len().is_power_of_two());
                    leaves.len().ilog2()
                })
                .collect::<Vec<_>>();
            assert_eq!(
                expected_heights, case.expected_peak_heights,
                "{} symbolic peak heights",
                case.name
            );
            let expected_peaks = case
                .expected_peak_leaves
                .iter()
                .map(|leaves| {
                    let nullifiers = leaves
                        .iter()
                        .map(|tag| {
                            tagged_nullifier(
                                u8::try_from(*tag).expect("Lean peak tag fits one byte"),
                            )
                        })
                        .collect::<Vec<_>>();
                    reference_perfect_root(&nullifiers)
                })
                .collect::<Vec<_>>();
            assert_eq!(
                accumulator.peaks, expected_peaks,
                "{} peak grouping/order",
                case.name
            );
        }
    }

    #[test]
    fn encoding_round_trip_and_corruption_fail_closed() {
        let accumulator = NullifierAccumulator::from_append_order(deterministic_nullifiers(77))
            .expect("build accumulator");
        let encoded = accumulator.encode().expect("encode accumulator");
        assert_eq!(
            NullifierAccumulator::decode(&encoded).expect("decode accumulator"),
            accumulator
        );

        for index in [0, NULLIFIER_MMR_STATE_DOMAIN_V3.len(), encoded.len() - 1] {
            let mut corrupt = encoded.clone();
            corrupt[index] ^= 1;
            assert!(NullifierAccumulator::decode(&corrupt).is_err());
        }
        assert!(NullifierAccumulator::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(NullifierAccumulator::decode(&trailing).is_err());

        let mut legacy_v2 = LEGACY_NULLIFIER_MMR_STATE_DOMAIN_V2.to_vec();
        legacy_v2
            .extend_from_slice(&trailing[NULLIFIER_MMR_STATE_DOMAIN_V3.len()..trailing.len() - 1]);
        assert_eq!(
            NullifierAccumulator::decode(&legacy_v2),
            Err(NullifierAccumulatorError::LegacyV2Encoding)
        );

        let mut legacy_v1 = b"hegemon.nullifier-mmr.state-v1".to_vec();
        legacy_v1
            .extend_from_slice(&trailing[NULLIFIER_MMR_STATE_DOMAIN_V3.len()..trailing.len() - 1]);
        assert_eq!(
            NullifierAccumulator::decode(&legacy_v1),
            Err(NullifierAccumulatorError::InvalidEncoding)
        );
    }

    #[test]
    fn order_is_bound_and_empty_append_is_identity() {
        let nullifiers = deterministic_nullifiers(4);
        let forward = NullifierAccumulator::from_append_order(nullifiers.iter().copied())
            .expect("forward accumulator");
        let reverse = NullifierAccumulator::from_append_order(nullifiers.iter().rev().copied())
            .expect("reverse accumulator");
        assert_ne!(forward.root(), reverse.root());

        let mut unchanged = forward.clone();
        unchanged
            .append_all(core::iter::empty())
            .expect("empty block append");
        assert_eq!(unchanged, forward);
    }

    #[test]
    fn multi_block_fork_reorg_matches_full_replay() {
        let nullifiers = deterministic_nullifiers(12);
        let mut common = NullifierAccumulator::new();
        common
            .append_all(nullifiers[..3].iter().copied())
            .expect("append common block one");
        common
            .append_all(core::iter::empty())
            .expect("append common zero-nullifier block");
        common
            .append_all(nullifiers[3..5].iter().copied())
            .expect("append common block three");

        let mut fork_a = common.clone();
        fork_a
            .append_all(nullifiers[5..8].iter().copied())
            .expect("append fork A block");
        let mut fork_b = common.clone();
        fork_b
            .append_all(nullifiers[8..12].iter().copied())
            .expect("append fork B block");
        assert_ne!(fork_a.root(), fork_b.root());

        let replay_a = NullifierAccumulator::from_append_order(nullifiers[..8].iter().copied())
            .expect("replay fork A");
        let replay_b = NullifierAccumulator::from_append_order(
            nullifiers[..5]
                .iter()
                .chain(nullifiers[8..12].iter())
                .copied(),
        )
        .expect("replay fork B");
        assert_eq!(fork_a, replay_a);
        assert_eq!(fork_b, replay_b);

        let reorganized = replay_b;
        assert_eq!(reorganized.root(), fork_b.root());
        assert_ne!(reorganized.root(), fork_a.root());
    }

    #[test]
    fn indexed_suffix_plan_binds_parent_count_order_and_is_atomic() {
        let nullifiers = deterministic_nullifiers(8);
        let base = NullifierAccumulator::from_append_order(nullifiers[..3].iter().copied())
            .expect("build suffix parent");
        let unchanged = base.clone();
        let suffix = base
            .plan_indexed_append(nullifiers[3..6].iter().copied())
            .expect("plan indexed suffix");
        assert_eq!(base, unchanged, "suffix planning mutated checkpoint");
        assert_eq!(suffix.base_leaf_count, 3);
        assert_eq!(
            suffix.rows,
            vec![(3, nullifiers[3]), (4, nullifiers[4]), (5, nullifiers[5]),]
        );
        let replay = NullifierAccumulator::from_append_order(nullifiers[..6].iter().copied())
            .expect("replay planned suffix");
        assert_eq!(suffix.next_accumulator, replay);

        let reversed = base
            .plan_indexed_append(nullifiers[3..6].iter().rev().copied())
            .expect("plan reversed suffix");
        assert_ne!(
            reversed.next_accumulator.root(),
            suffix.next_accumulator.root(),
            "suffix order must remain consensus-visible"
        );

        let zero_error = base
            .plan_indexed_append([nullifiers[6], Nullifier48::ZERO, nullifiers[7]])
            .expect_err("zero inside planned suffix must reject atomically");
        assert_eq!(zero_error, NullifierAccumulatorError::ZeroNullifier);
        assert_eq!(base, unchanged);

        let mut batch = base.clone();
        let batch_before = batch.clone();
        assert_eq!(
            batch.append_all([nullifiers[6], Nullifier48::ZERO, nullifiers[7]]),
            Err(NullifierAccumulatorError::ZeroNullifier)
        );
        assert_eq!(batch, batch_before, "failed batch append partially mutated");
    }

    #[test]
    fn append_work_is_log_bounded_independently_of_history() {
        let nullifiers = deterministic_nullifiers(131_073);
        let mut accumulator = NullifierAccumulator::new();
        for (index, nullifier) in nullifiers.into_iter().enumerate() {
            let work = accumulator
                .append_measured(nullifier)
                .expect("append measured nullifier");
            assert_eq!(work.leaf_hashes, 1);
            assert!(work.node_hashes <= u64::from(u64::BITS));
            assert_eq!(work.root_hashes, 0);
            assert!(accumulator.peaks.len() <= NULLIFIER_MMR_MAX_PEAKS);
            if matches!(index + 1, 1 | 1_024 | 65_536 | 131_073) {
                let (_, root_work) = accumulator.root_measured();
                assert_eq!(root_work.root_hashes, 1);
                assert!(root_work.transcript_bytes <= 64 * 48 + 64);
            }
        }
    }

    #[test]
    fn malformed_peak_shape_and_overflow_reject_without_mutation() {
        let mut empty = NullifierAccumulator::new();
        let before = empty.clone();
        assert_eq!(
            empty.append(Nullifier48::ZERO),
            Err(NullifierAccumulatorError::ZeroNullifier)
        );
        assert_eq!(empty, before);

        let mut malformed = NullifierAccumulator {
            leaf_count: 3,
            peaks: Vec::new(),
        };
        let before = malformed.clone();
        assert_eq!(
            malformed.append(tagged_nullifier(1)),
            Err(NullifierAccumulatorError::InvalidPeakShape)
        );
        assert_eq!(malformed, before);

        let mut overflow = NullifierAccumulator {
            leaf_count: u64::MAX,
            peaks: vec![[7u8; 48]; u64::MAX.count_ones() as usize],
        };
        let before = overflow.clone();
        assert_eq!(
            overflow.append(tagged_nullifier(2)),
            Err(NullifierAccumulatorError::LeafCountOverflow)
        );
        assert_eq!(overflow, before);
    }

    fn reference_root(nullifiers: &[Nullifier48]) -> [u8; 48] {
        reference_root_with_domains(
            nullifiers,
            b"hegemon.nullifier-mmr.blake2b-384.leaf-v3",
            b"hegemon.nullifier-mmr.blake2b-384.node-v3",
            b"hegemon.nullifier-mmr.blake2b-384.root-v3",
        )
    }

    fn reference_root_with_domains(
        nullifiers: &[Nullifier48],
        leaf_domain: &[u8],
        node_domain: &[u8],
        root_domain: &[u8],
    ) -> [u8; 48] {
        let mut peaks = Vec::new();
        let mut cursor = 0usize;
        let mut remaining = nullifiers.len();
        while remaining != 0 {
            let height = usize::BITS - 1 - remaining.leading_zeros();
            let size = 1usize << height;
            peaks.push(reference_perfect_root_with_domains(
                &nullifiers[cursor..cursor + size],
                leaf_domain,
                node_domain,
            ));
            cursor += size;
            remaining -= size;
        }
        let leaf_count = (nullifiers.len() as u64).to_le_bytes();
        let peak_count = (peaks.len() as u32).to_le_bytes();
        let fixed: [&[u8]; 2] = [&leaf_count, &peak_count];
        reference_domain_hash(
            root_domain,
            fixed
                .into_iter()
                .chain(peaks.iter().map(|peak| peak.as_slice())),
        )
    }

    fn reference_perfect_root(nullifiers: &[Nullifier48]) -> [u8; 48] {
        reference_perfect_root_with_domains(
            nullifiers,
            b"hegemon.nullifier-mmr.blake2b-384.leaf-v3",
            b"hegemon.nullifier-mmr.blake2b-384.node-v3",
        )
    }

    fn reference_perfect_root_with_domains(
        nullifiers: &[Nullifier48],
        leaf_domain: &[u8],
        node_domain: &[u8],
    ) -> [u8; 48] {
        assert!(nullifiers.len().is_power_of_two());
        if nullifiers.len() == 1 {
            return reference_domain_hash(leaf_domain, [nullifiers[0].as_bytes().as_slice()]);
        }
        let half = nullifiers.len() / 2;
        let height = nullifiers.len().ilog2();
        let left =
            reference_perfect_root_with_domains(&nullifiers[..half], leaf_domain, node_domain);
        let right =
            reference_perfect_root_with_domains(&nullifiers[half..], leaf_domain, node_domain);
        let height = height.to_le_bytes();
        let parts: [&[u8]; 3] = [height.as_slice(), left.as_slice(), right.as_slice()];
        reference_domain_hash(node_domain, parts)
    }

    fn reference_domain_hash<'a>(
        domain: &[u8],
        parts: impl IntoIterator<Item = &'a [u8]>,
    ) -> [u8; 48] {
        use blake2::{digest::consts::U48, Blake2b, Digest};

        let mut transcript = b"hegemon.blake2b-384.frame-v1".to_vec();
        transcript.extend_from_slice(&(domain.len() as u64).to_le_bytes());
        transcript.extend_from_slice(domain);
        for part in parts {
            transcript.extend_from_slice(&(part.len() as u64).to_le_bytes());
            transcript.extend_from_slice(part);
        }
        Blake2b::<U48>::digest(transcript).into()
    }

    fn deterministic_nullifiers(count: usize) -> Vec<Nullifier48> {
        (0..count)
            .map(|index| {
                let mut bytes = [0u8; 48];
                let mut state = (index as u64)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_add(1);
                for chunk in bytes.chunks_exact_mut(8) {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    chunk.copy_from_slice(&state.to_le_bytes());
                }
                Nullifier48::new(bytes)
            })
            .collect()
    }

    fn tagged_nullifier(tag: u8) -> Nullifier48 {
        Nullifier48::new([tag; 48])
    }
}
