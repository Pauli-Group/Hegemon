//! Public inputs for batch transaction verification.

use winterfell::math::{fields::f64::BaseElement, FieldElement, ToElements};

/// Maximum transactions per batch (power of 2 for trace efficiency).
pub const MAX_BATCH_SIZE: usize = 16;

/// Maximum inputs per transaction.
pub const MAX_INPUTS: usize = 2;

/// Maximum outputs per transaction.
pub const MAX_OUTPUTS: usize = 2;

fn is_zero_hash(value: &[BaseElement; 4]) -> bool {
    value.iter().all(|elem| *elem == BaseElement::ZERO)
}

/// Public inputs for batch transaction verification.
///
/// These inputs are revealed to the verifier and used to construct
/// boundary assertions in the AIR.
#[derive(Clone, Debug)]
pub struct BatchPublicInputs {
    /// Number of transactions in this batch (2, 4, 8, or 16).
    pub batch_size: u32,

    /// Shared Merkle anchor for all input notes.
    /// All transactions in the batch must use the same anchor.
    pub anchor: [BaseElement; 4],

    /// Nullifiers from all transactions (batch_size × MAX_INPUTS).
    /// Zero values indicate unused slots.
    pub nullifiers: Vec<[BaseElement; 4]>,

    /// Commitments from all transactions (batch_size × MAX_OUTPUTS).
    /// Zero values indicate unused slots.
    pub commitments: Vec<[BaseElement; 4]>,

    /// Total fee across all transactions.
    pub total_fee: BaseElement,

    /// Circuit version for compatibility checking.
    pub circuit_version: u32,
}

impl BatchPublicInputs {
    /// Create new batch public inputs.
    pub fn new(
        batch_size: u32,
        anchor: [BaseElement; 4],
        nullifiers: Vec<[BaseElement; 4]>,
        commitments: Vec<[BaseElement; 4]>,
        total_fee: BaseElement,
    ) -> Self {
        Self {
            batch_size,
            anchor,
            nullifiers,
            commitments,
            total_fee,
            circuit_version: 1,
        }
    }

    /// Get the number of non-zero nullifiers.
    pub fn active_nullifier_count(&self) -> usize {
        self.nullifiers
            .iter()
            .filter(|nf| !is_zero_hash(nf))
            .count()
    }

    /// Get the number of non-zero commitments.
    pub fn active_commitment_count(&self) -> usize {
        self.commitments
            .iter()
            .filter(|cm| !is_zero_hash(cm))
            .count()
    }

    /// Validate the public inputs.
    pub fn validate(&self) -> Result<(), &'static str> {
        // Check batch size
        if self.batch_size == 0 {
            return Err("Batch size cannot be zero");
        }
        if !self.batch_size.is_power_of_two() {
            return Err("Batch size must be power of 2");
        }
        if self.batch_size > MAX_BATCH_SIZE as u32 {
            return Err("Batch size exceeds maximum");
        }

        // Check vector lengths
        let expected_nullifiers = self.batch_size as usize * MAX_INPUTS;
        let expected_commitments = self.batch_size as usize * MAX_OUTPUTS;

        if self.nullifiers.len() != expected_nullifiers {
            return Err("Incorrect number of nullifiers");
        }
        if self.commitments.len() != expected_commitments {
            return Err("Incorrect number of commitments");
        }

        // Must have at least one active nullifier
        if self.active_nullifier_count() == 0 {
            return Err("No active nullifiers");
        }

        Ok(())
    }

    /// Get nullifiers for a specific transaction in the batch.
    pub fn transaction_nullifiers(&self, tx_index: usize) -> &[[BaseElement; 4]] {
        let start = tx_index * MAX_INPUTS;
        let end = start + MAX_INPUTS;
        &self.nullifiers[start..end]
    }

    /// Get commitments for a specific transaction in the batch.
    pub fn transaction_commitments(&self, tx_index: usize) -> &[[BaseElement; 4]] {
        let start = tx_index * MAX_OUTPUTS;
        let end = start + MAX_OUTPUTS;
        &self.commitments[start..end]
    }
}

impl ToElements<BaseElement> for BatchPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::new();
        elements.push(BaseElement::new(self.batch_size as u64));
        elements.extend_from_slice(&self.anchor);
        for nf in &self.nullifiers {
            elements.extend_from_slice(nf);
        }
        for cm in &self.commitments {
            elements.extend_from_slice(cm);
        }
        elements.push(self.total_fee);
        elements.push(BaseElement::new(self.circuit_version as u64));
        elements
    }
}

impl Default for BatchPublicInputs {
    fn default() -> Self {
        Self {
            batch_size: 2,
            anchor: [BaseElement::ZERO; 4],
            nullifiers: vec![[BaseElement::ZERO; 4]; 2 * MAX_INPUTS],
            commitments: vec![[BaseElement::ZERO; 4]; 2 * MAX_OUTPUTS],
            total_fee: BaseElement::ZERO,
            circuit_version: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_public_inputs_validation() {
        // Valid batch of 2
        let zero = [BaseElement::ZERO; 4];
        let inputs = BatchPublicInputs {
            batch_size: 2,
            anchor: [BaseElement::new(123), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
            nullifiers: vec![
                [BaseElement::new(1), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
                zero,
                [BaseElement::new(2), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
                zero,
            ],
            commitments: vec![
                [BaseElement::new(10), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
                zero,
                [BaseElement::new(20), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
                zero,
            ],
            total_fee: BaseElement::new(100),
            circuit_version: 1,
        };
        assert!(inputs.validate().is_ok());
        assert_eq!(inputs.active_nullifier_count(), 2);
        assert_eq!(inputs.active_commitment_count(), 2);
    }

    #[test]
    fn test_invalid_batch_size() {
        let mut inputs = BatchPublicInputs::default();
        inputs.batch_size = 0;
        assert!(inputs.validate().is_err());

        inputs.batch_size = 3; // Not power of 2
        assert!(inputs.validate().is_err());

        inputs.batch_size = 32; // Too large
        assert!(inputs.validate().is_err());
    }

    #[test]
    fn test_to_elements() {
        let inputs = BatchPublicInputs::default();
        let elements = inputs.to_elements();

        // batch_size + anchor(4) + nullifiers(4 limbs each) + commitments(4 limbs each) + fee + version
        let expected_len =
            1 + 4 + (2 * MAX_INPUTS * 4) + (2 * MAX_OUTPUTS * 4) + 1 + 1;
        assert_eq!(elements.len(), expected_len);
    }

    #[test]
    fn test_transaction_accessors() {
        let inputs = BatchPublicInputs {
            batch_size: 2,
            anchor: BaseElement::ZERO,
            nullifiers: vec![
                BaseElement::new(1),
                BaseElement::new(2), // TX 0
                BaseElement::new(3),
                BaseElement::new(4), // TX 1
            ],
            commitments: vec![
                BaseElement::new(10),
                BaseElement::new(20), // TX 0
                BaseElement::new(30),
                BaseElement::new(40), // TX 1
            ],
            total_fee: BaseElement::ZERO,
            circuit_version: 1,
        };

        assert_eq!(inputs.transaction_nullifiers(0)[0], BaseElement::new(1));
        assert_eq!(inputs.transaction_nullifiers(1)[0], BaseElement::new(3));
        assert_eq!(inputs.transaction_commitments(0)[1], BaseElement::new(20));
        assert_eq!(inputs.transaction_commitments(1)[1], BaseElement::new(40));
    }
}
