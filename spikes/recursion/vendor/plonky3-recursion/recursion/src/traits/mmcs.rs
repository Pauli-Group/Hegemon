//! Traits for recursive MMCS operations.

use alloc::vec::Vec;

use p3_circuit::{CircuitBuilder, CircuitBuilderError};
use p3_commit::Mmcs;
use p3_field::{ExtensionField, Field};
use p3_matrix::Dimensions;

use super::Recursive;
use crate::Target;
use crate::verifier::ObservableCommitment;

/// Trait for the recursive version of an MMCS operating over the base field.
///
/// Associates a non-recursive MMCS with its recursive commitment and proof types.
/// This is used for commitments to trace polynomials (which are over the base field).
pub trait RecursiveMmcs<F: Field, EF: ExtensionField<F>> {
    /// The non-recursive MMCS type this corresponds to.
    type Input: Mmcs<F>;

    /// The recursive commitment type (targets representing the commitment).
    ///
    /// Must implement `Recursive` with `Input` being the commitment type from `Self::Input`.
    type Commitment: Recursive<EF, Input = <Self::Input as Mmcs<F>>::Commitment>
        + ObservableCommitment;

    /// The recursive proof type (targets representing the opening proof).
    ///
    /// Must implement `Recursive` with `Input` being the proof type from `Self::Input`.
    type Proof: Recursive<EF, Input = <Self::Input as Mmcs<F>>::Proof>;

    /// Add in-circuit constraints for `Mmcs::verify_batch`.
    ///
    /// `commitment_observation` is the commitment exposed as circuit targets.
    fn verify_batch_circuit(
        circuit: &mut CircuitBuilder<EF>,
        commitment_observation: &[Target],
        dimensions: &[Dimensions],
        index_bits: &[Target],
        opened_values: &[Vec<Target>],
        opening_proof: &Self::Proof,
    ) -> Result<(), CircuitBuilderError>;
}

/// Trait for the recursive version of an MMCS operating over the extension field.
///
/// Associates a non-recursive MMCS with its recursive commitment and proof types.
/// This is used for commitments to quotient polynomials and FRI layers
/// (which are over the extension field).
pub trait RecursiveExtensionMmcs<F: Field, EF: ExtensionField<F>> {
    /// The non-recursive MMCS type this corresponds to.
    type Input: Mmcs<EF>;

    /// The recursive commitment type (targets representing the commitment).
    ///
    /// Must implement `Recursive` with `Input` being the commitment type from `Self::Input`.
    type Commitment: Recursive<EF, Input = <Self::Input as Mmcs<EF>>::Commitment>
        + ObservableCommitment;

    /// The recursive proof type (targets representing the opening proof).
    ///
    /// Must implement `Recursive` with `Input` being the proof type from `Self::Input`.
    type Proof: Recursive<EF, Input = <Self::Input as Mmcs<EF>>::Proof>;

    /// Add in-circuit constraints for `Mmcs::verify_batch` on extension-field openings.
    fn verify_batch_circuit(
        circuit: &mut CircuitBuilder<EF>,
        commitment_observation: &[Target],
        dimensions: &[Dimensions],
        index_bits: &[Target],
        opened_values: &[Vec<Target>],
        opening_proof: &Self::Proof,
    ) -> Result<(), CircuitBuilderError>;
}
