//! Contiguous prover-only storage for fixed-width DECS randomness tapes.
//!
//! The entropy request schedule is unchanged: each batch is accounted for and
//! filled separately, then indexed by its original canonical leaf position.
//! Only opened tapes are copied into the existing proof representation.

use crate::error::TransactionCircuitError;

#[derive(Clone, Debug)]
pub(crate) struct FixedWidthTapesV1 {
    bytes: Vec<u8>,
    tape_bytes: usize,
}

impl FixedWidthTapesV1 {
    /// Non-hiding historical profiles have no tapes or entropy requests.
    pub(crate) fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            tape_bytes: 8,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len() / self.tape_bytes
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[inline]
    pub(crate) fn get(&self, index: usize) -> Option<&[u8]> {
        let start = index.checked_mul(self.tape_bytes)?;
        let end = start.checked_add(self.tape_bytes)?;
        self.bytes.get(start..end)
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> std::slice::ChunksExact<'_, u8> {
        self.bytes.chunks_exact(self.tape_bytes)
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(
        bytes: Vec<u8>,
        tape_bytes: usize,
    ) -> Result<Self, TransactionCircuitError> {
        validate_geometry(tape_bytes, 1)?;
        if !bytes.len().is_multiple_of(tape_bytes) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood runtime randomness tape partition is not exact",
            ));
        }
        Ok(Self { bytes, tape_bytes })
    }
}

fn validate_geometry(
    tape_bytes: usize,
    tapes_per_fill: usize,
) -> Result<(), TransactionCircuitError> {
    if tape_bytes == 0 || !tape_bytes.is_multiple_of(8) || tapes_per_fill == 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood runtime randomness tape geometry is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn sample_contiguous_tapes_with_source_v1(
    count: usize,
    tape_bytes: usize,
    tapes_per_fill: usize,
    mut before_fill: impl FnMut(usize) -> Result<(), TransactionCircuitError>,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), TransactionCircuitError>,
) -> Result<FixedWidthTapesV1, TransactionCircuitError> {
    validate_geometry(tape_bytes, tapes_per_fill)?;
    let total_bytes =
        count
            .checked_mul(tape_bytes)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-ZK DECS leaf-tape request overflows addressable memory",
            ))?;
    let mut bytes = Vec::new();
    // Vec's checked reservation also rejects sizes exceeding isize::MAX. No
    // entropy/accounting calls occur if this storage cannot be allocated.
    bytes.try_reserve_exact(total_bytes).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood strict-ZK DECS leaf-tape storage allocation failed",
        )
    })?;
    let mut filled_tapes = 0;
    while filled_tapes < count {
        let batch_count = (count - filled_tapes).min(tapes_per_fill);
        // Both arithmetic operations are bounded by the checked total above.
        let byte_count = batch_count * tape_bytes;
        before_fill(byte_count)?;
        let start = bytes.len();
        bytes.resize(start + byte_count, 0);
        fill(&mut bytes[start..])?;
        filled_tapes += batch_count;
    }
    Ok(FixedWidthTapesV1 { bytes, tape_bytes })
}
