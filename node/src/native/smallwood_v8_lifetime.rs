//! Consensus-visible conditional proof-count accounting for SmallWood V8.
//!
//! This counter records canonical accepted V8 transaction proofs from profile
//! activation through the current canonical tip. It never treats the
//! 4,096-block analysis window as a reset. The constants below are copied from
//! the source-derived conditional security report, but this module does not
//! claim that the missing SHA-512, Poseidon2, adaptive-QROM, or global-history
//! reductions are complete. The per-block ceiling is imported from the same
//! protocol-versioning source that owns fresh capability admission.

#![allow(dead_code)]

pub(crate) const SMALLWOOD_V8_CONDITIONAL_MAX_PROOFS_PER_BLOCK: u64 =
    protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_MAX_PROOF_ACTIONS_PER_BLOCK as u64;
pub(crate) const SMALLWOOD_V8_CONDITIONAL_ACCOUNTING_WINDOW_BLOCKS: u64 = 4_096;
pub(crate) const SMALLWOOD_V8_CONDITIONAL_ACCOUNTING_WINDOW_PROOFS: u64 =
    SMALLWOOD_V8_CONDITIONAL_MAX_PROOFS_PER_BLOCK
        * SMALLWOOD_V8_CONDITIONAL_ACCOUNTING_WINDOW_BLOCKS;
pub(crate) const SMALLWOOD_V8_CONDITIONAL_MAX_TOTAL_PROOFS_AT_128_BITS: u64 = 621_730_874;

const _: () = assert!(
    SMALLWOOD_V8_CONDITIONAL_MAX_PROOFS_PER_BLOCK
        * SMALLWOOD_V8_CONDITIONAL_ACCOUNTING_WINDOW_BLOCKS
        == SMALLWOOD_V8_CONDITIONAL_ACCOUNTING_WINDOW_PROOFS
);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SmallwoodV8ProofLifetimeCount(u64);

impl SmallwoodV8ProofLifetimeCount {
    pub(crate) const fn genesis() -> Self {
        Self(0)
    }

    pub(crate) fn new(value: u64) -> Result<Self, SmallwoodV8ProofLifetimeError> {
        if value > SMALLWOOD_V8_CONDITIONAL_MAX_TOTAL_PROOFS_AT_128_BITS {
            return Err(
                SmallwoodV8ProofLifetimeError::PersistedCountExceedsConditionalMaximum {
                    observed: value,
                    maximum: SMALLWOOD_V8_CONDITIONAL_MAX_TOTAL_PROOFS_AT_128_BITS,
                },
            );
        }
        Ok(Self(value))
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }

    pub(crate) const fn encode(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Self, SmallwoodV8ProofLifetimeError> {
        if bytes.len() != 8 {
            return Err(SmallwoodV8ProofLifetimeError::CodecLength {
                expected: 8,
                observed: bytes.len(),
            });
        }
        Self::new(u64::from_le_bytes(
            bytes
                .try_into()
                .expect("exact lifetime counter codec is eight bytes"),
        ))
    }

    pub(crate) fn checked_accept_block(
        self,
        proof_count: usize,
    ) -> Result<Self, SmallwoodV8ProofLifetimeError> {
        let proof_count = u64::try_from(proof_count)
            .map_err(|_| SmallwoodV8ProofLifetimeError::BlockProofCountConversion)?;
        if proof_count > SMALLWOOD_V8_CONDITIONAL_MAX_PROOFS_PER_BLOCK {
            return Err(SmallwoodV8ProofLifetimeError::BlockProofCapExceeded {
                observed: proof_count,
                maximum: SMALLWOOD_V8_CONDITIONAL_MAX_PROOFS_PER_BLOCK,
            });
        }
        let next = self
            .0
            .checked_add(proof_count)
            .ok_or(SmallwoodV8ProofLifetimeError::CountOverflow)?;
        if next > SMALLWOOD_V8_CONDITIONAL_MAX_TOTAL_PROOFS_AT_128_BITS {
            return Err(
                SmallwoodV8ProofLifetimeError::ConditionalLifetimeLimitExceeded {
                    before: self.0,
                    block_proofs: proof_count,
                    maximum: SMALLWOOD_V8_CONDITIONAL_MAX_TOTAL_PROOFS_AT_128_BITS,
                },
            );
        }
        Ok(Self(next))
    }

    #[cfg(test)]
    const fn unchecked_for_overflow_test(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum SmallwoodV8ProofLifetimeError {
    #[error(
        "SmallWood V8 lifetime counter has wrong length: expected {expected}, observed {observed}"
    )]
    CodecLength { expected: usize, observed: usize },
    #[error("SmallWood V8 proof count does not fit u64")]
    BlockProofCountConversion,
    #[error("SmallWood V8 block proof count exceeds the conditional cap: {observed} > {maximum}")]
    BlockProofCapExceeded { observed: u64, maximum: u64 },
    #[error("SmallWood V8 lifetime proof count overflow")]
    CountOverflow,
    #[error(
        "SmallWood V8 conditional lifetime limit exceeded: {before} + {block_proofs} > {maximum}"
    )]
    ConditionalLifetimeLimitExceeded {
        before: u64,
        block_proofs: u64,
        maximum: u64,
    },
    #[error(
        "persisted SmallWood V8 proof count exceeds the conditional maximum: {observed} > {maximum}"
    )]
    PersistedCountExceedsConditionalMaximum { observed: u64, maximum: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct ReferenceVectors {
        schema: String,
        max_proofs_per_block: u64,
        accounting_window_blocks: u64,
        accounting_window_proofs: u64,
        conditional_max_total_proofs_at_128_bits: u64,
        cases: Vec<ReferenceCase>,
    }

    #[derive(Debug, Deserialize)]
    struct ReferenceCase {
        name: String,
        before: u64,
        block_proofs: usize,
        accepted: bool,
        after: Option<u64>,
        error: Option<String>,
    }

    #[test]
    fn conditional_constants_and_reference_vectors_are_exact() {
        let vectors: ReferenceVectors = serde_json::from_str(include_str!(
            "../../../testdata/native_backend_vectors/smallwood_v8_lifetime_accounting.json"
        ))
        .unwrap();
        assert_eq!(
            vectors.schema,
            "hegemon.native.smallwood-v8-proof-lifetime-accounting.v1"
        );
        assert_eq!(
            vectors.max_proofs_per_block,
            SMALLWOOD_V8_CONDITIONAL_MAX_PROOFS_PER_BLOCK
        );
        assert_eq!(
            vectors.accounting_window_blocks,
            SMALLWOOD_V8_CONDITIONAL_ACCOUNTING_WINDOW_BLOCKS
        );
        assert_eq!(
            vectors.accounting_window_proofs,
            SMALLWOOD_V8_CONDITIONAL_ACCOUNTING_WINDOW_PROOFS
        );
        assert_eq!(
            vectors.conditional_max_total_proofs_at_128_bits,
            SMALLWOOD_V8_CONDITIONAL_MAX_TOTAL_PROOFS_AT_128_BITS
        );
        assert_eq!(
            vectors.max_proofs_per_block * vectors.accounting_window_blocks,
            vectors.accounting_window_proofs
        );
        for case in vectors.cases {
            let result = SmallwoodV8ProofLifetimeCount::new(case.before)
                .and_then(|count| count.checked_accept_block(case.block_proofs));
            assert_eq!(result.is_ok(), case.accepted, "{}", case.name);
            match result {
                Ok(count) => {
                    assert_eq!(Some(count.get()), case.after, "{}", case.name);
                    assert!(case.error.is_none(), "{}", case.name);
                }
                Err(error) => {
                    assert_eq!(Some(error.to_string()), case.error, "{}", case.name);
                    assert!(case.after.is_none(), "{}", case.name);
                }
            }
        }
    }

    #[test]
    fn codec_and_arithmetic_fail_closed() {
        let maximum = SmallwoodV8ProofLifetimeCount::new(
            SMALLWOOD_V8_CONDITIONAL_MAX_TOTAL_PROOFS_AT_128_BITS,
        )
        .unwrap();
        assert_eq!(
            SmallwoodV8ProofLifetimeCount::decode_exact(&maximum.encode()).unwrap(),
            maximum
        );
        assert!(matches!(
            SmallwoodV8ProofLifetimeCount::decode_exact(&maximum.encode()[..7]),
            Err(SmallwoodV8ProofLifetimeError::CodecLength { .. })
        ));
        assert!(matches!(
            SmallwoodV8ProofLifetimeCount::unchecked_for_overflow_test(u64::MAX)
                .checked_accept_block(1),
            Err(SmallwoodV8ProofLifetimeError::CountOverflow)
        ));
    }
}
