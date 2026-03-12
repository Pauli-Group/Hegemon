//! Target structures for STARK proofs in recursive circuits.

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_batch_stark::common::PreprocessedInstanceMeta;
use p3_batch_stark::proof::OpenedValuesWithLookups;
use p3_batch_stark::{BatchCommitments, BatchOpenedValues, BatchProof, CommonData};
use p3_circuit::{CircuitBuilder, CircuitBuilderError};
use p3_commit::Pcs;
use p3_field::{ExtensionField, Field, PrimeField64};
use p3_lookup::lookup_traits::{Lookup, LookupData};
use p3_uni_stark::{OpenedValues, Proof, StarkGenericConfig, Val};

use crate::Target;
use crate::challenger::CircuitChallenger;
use crate::traits::Recursive;

/// Structure representing all the targets necessary for an input proof.
///
/// This contains the circuit representation of a STARK proof, with all
/// commitments, opened values, and the opening proof as targets.
#[derive(Clone)]
pub struct ProofTargets<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
> {
    /// Commitments to trace, quotient chunks, and optional random polynomial
    pub commitments_targets: CommitmentTargets<SC::Challenge, Comm>,
    /// Opened values at evaluation points (zeta, zeta_next)
    pub opened_values_targets: OpenedValuesTargets<SC>,
    /// PCS opening proof
    pub opening_proof: OpeningProof,
    /// Log₂ of the trace domain size
    pub degree_bits: usize,
}

/// Structure representing all the targets necessary for a batch-STARK input proof.
///
/// This contains the circuit representation of a STARK proof, with all
/// commitments, opened values, and the opening proof as targets.
#[derive(Clone)]
pub struct BatchProofTargets<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
> {
    /// Commitments to trace, quotient chunks, and optional random polynomial
    pub commitments_targets: CommitmentTargets<SC::Challenge, Comm>,
    pub flattened_opened_values_targets: OpenedValuesTargetsWithLookups<SC>,
    /// Opened values at evaluation points (zeta, zeta_next)
    pub opened_values_targets: BatchOpenedValuesTargets<SC>,
    /// PCS opening proof
    pub opening_proof: OpeningProof,
    /// Data necessary to verify the global lookup arguments across all instances
    /// We need both the `Target` (so that the values can be used in the circuit) and the offset within the public values,
    /// so we can compute the constraint evaluations using the associated symbolic expression
    pub global_lookup_data: Vec<Vec<LookupData<Target>>>,
    /// Log₂ of the trace domain size for all instances in a batch-STARK proof
    pub degree_bits: Vec<usize>,
}

/// Target structure for STARK commitments.
#[derive(Clone)]
pub struct CommitmentTargets<F: Field, Comm: Recursive<F>> {
    /// Commitment to the trace polynomial
    pub trace_targets: Comm,
    /// Commitment to all permutation polynomials.
    pub permutation_targets: Option<Comm>,
    /// Commitment to the quotient polynomial chunks
    pub quotient_chunks_targets: Comm,
    /// Optional commitment to random polynomial (ZK mode)
    pub random_commit: Option<Comm>,
    pub _phantom: PhantomData<F>,
}

/// Target structure for opened polynomial values.
pub struct OpenedValuesTargets<SC: StarkGenericConfig> {
    /// Trace values at point zeta
    pub trace_local_targets: Vec<Target>,
    /// Trace values at point zeta * g (next row)
    pub trace_next_targets: Vec<Target>,
    /// Optional preprocessed values at point zeta
    pub preprocessed_local_targets: Option<Vec<Target>>,
    /// Optional preprocessed values at point zeta * g (next row)
    pub preprocessed_next_targets: Option<Vec<Target>>,
    /// Quotient chunk values at zeta
    pub quotient_chunks_targets: Vec<Vec<Target>>,
    /// Optional random polynomial values (ZK mode)
    pub random_targets: Option<Vec<Target>>,
    pub _phantom: PhantomData<SC>,
}

impl<SC> Clone for OpenedValuesTargets<SC>
where
    SC: StarkGenericConfig,
{
    fn clone(&self) -> Self {
        Self {
            trace_local_targets: self.trace_local_targets.clone(),
            trace_next_targets: self.trace_next_targets.clone(),
            preprocessed_local_targets: self.preprocessed_local_targets.clone(),
            preprocessed_next_targets: self.preprocessed_next_targets.clone(),
            quotient_chunks_targets: self.quotient_chunks_targets.clone(),
            random_targets: self.random_targets.clone(),
            _phantom: PhantomData,
        }
    }
}

/// Target structure for opened polynomial values, including lookups.
#[derive(Clone)]
pub struct OpenedValuesTargetsWithLookups<SC: StarkGenericConfig> {
    /// Targets for opened values without lookups.
    pub opened_values_no_lookups: OpenedValuesTargets<SC>,
    /// Targets for opened lookup values at point zeta.
    pub permutation_local_targets: Vec<Target>,
    /// Targets for opened lookup values at point zeta * g (next row).
    pub permutation_next_targets: Vec<Target>,
}

/// Target structure for opened values for all instances in a batch-STARK proof.
#[derive(Clone)]
pub struct BatchOpenedValuesTargets<SC: StarkGenericConfig> {
    /// Opened values for each instance, in the same order as provided to the prover.
    pub instances: Vec<OpenedValuesTargetsWithLookups<SC>>,
}

/// Structure which holds the targets and metadata for existing global preprocessed data.
pub struct GlobalPreprocessedTargets<Comm> {
    /// Global commitment targets for all preprocessed columns, over all instances.
    pub commitment: Comm,
    /// Per-instance metadata for preprocessed traces.
    pub instances: PreprocessedInstanceMetas,
    /// Mapping from preprocessed matrix index to the corresponding instance index.
    pub matrix_to_instance: Vec<usize>,
}

/// Structure which holds per-instance metadata for preprocessed traces
pub struct PreprocessedInstanceMetas {
    /// Vector of optional per-instance metadata
    pub instances: Vec<Option<PreprocessedInstanceMeta>>,
}

/// Target structure which holds the common data shared between prover and verifier.
pub struct CommonDataTargets<SC: StarkGenericConfig, Comm> {
    /// Preprocessed verifier data targets.
    pub preprocessed: Option<GlobalPreprocessedTargets<Comm>>,
    /// Lookup data
    pub lookups: Vec<Vec<Lookup<Val<SC>>>>,
}

impl<SC: StarkGenericConfig, Comm> Recursive<SC::Challenge> for CommonDataTargets<SC, Comm>
where
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        >,
{
    type Input = CommonData<SC>;

    fn new(circuit: &mut CircuitBuilder<SC::Challenge>, input: &Self::Input) -> Self {
        let preprocessed = input
            .preprocessed
            .as_ref()
            .map(|prep| GlobalPreprocessedTargets {
                commitment: Comm::new(circuit, &prep.commitment),
                instances: PreprocessedInstanceMetas {
                    instances: prep.instances.clone(),
                },
                matrix_to_instance: prep.matrix_to_instance.clone(),
            });

        Self {
            preprocessed,
            lookups: input.lookups.clone(),
        }
    }

    fn get_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let mut values = vec![];
        if let Some(prep) = &input.preprocessed {
            values.extend(Comm::get_values(&prep.commitment));
        }

        // Lookups are given symbolically, so we don't need to extract concrete values here.
        values
    }

    fn get_private_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let mut values = vec![];
        if let Some(prep) = &input.preprocessed {
            values.extend(Comm::get_private_values(&prep.commitment));
        }
        values
    }

    fn get_private_targets(&self) -> Vec<Target> {
        let mut targets = vec![];
        if let Some(prep) = &self.preprocessed {
            targets.extend(prep.commitment.get_private_targets());
        }
        targets
    }
}

impl<SC: StarkGenericConfig> OpenedValuesTargetsWithLookups<SC> {
    /// Observe all opened values in the Fiat-Shamir transcript.
    ///
    /// This method absorbs all opened values into the challenger state,
    /// which is necessary before sampling PCS challenges.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder
    /// - `challenger`: Running challenger state
    pub fn observe<const RATE: usize>(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenger: &mut CircuitChallenger<RATE>,
    ) -> Result<(), CircuitBuilderError>
    where
        Val<SC>: PrimeField64,
        SC::Challenge: ExtensionField<Val<SC>>,
    {
        // Observe random values if in ZK mode
        if let Some(random_vals) = &self.opened_values_no_lookups.random_targets {
            challenger.observe_algebra_slice::<Val<SC>, SC::Challenge>(circuit, random_vals)?;
        }

        // Observe trace values at zeta and zeta_next
        challenger.observe_algebra_slice::<Val<SC>, SC::Challenge>(
            circuit,
            &self.opened_values_no_lookups.trace_local_targets,
        )?;
        challenger.observe_algebra_slice::<Val<SC>, SC::Challenge>(
            circuit,
            &self.opened_values_no_lookups.trace_next_targets,
        )?;

        // Observe quotient chunk values
        for chunk_values in &self.opened_values_no_lookups.quotient_chunks_targets {
            challenger.observe_algebra_slice::<Val<SC>, SC::Challenge>(circuit, chunk_values)?;
        }

        if let Some(preprocessed_local_targets) =
            &self.opened_values_no_lookups.preprocessed_local_targets
        {
            challenger.observe_algebra_slice::<Val<SC>, SC::Challenge>(
                circuit,
                preprocessed_local_targets,
            )?;
        }
        if let Some(preprocessed_next_targets) =
            &self.opened_values_no_lookups.preprocessed_next_targets
        {
            challenger.observe_algebra_slice::<Val<SC>, SC::Challenge>(
                circuit,
                preprocessed_next_targets,
            )?;
        }
        if !self.permutation_local_targets.is_empty() {
            challenger.observe_algebra_slice::<Val<SC>, SC::Challenge>(
                circuit,
                &self.permutation_local_targets,
            )?;
        }
        if !self.permutation_next_targets.is_empty() {
            challenger.observe_algebra_slice::<Val<SC>, SC::Challenge>(
                circuit,
                &self.permutation_next_targets,
            )?;
        }
        Ok(())
    }
}

impl<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    OpeningProof: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
> Recursive<SC::Challenge> for ProofTargets<SC, Comm, OpeningProof>
{
    type Input = Proof<SC>;

    /// Allocates the necessary circuit targets for storing the proof's public data.
    fn new(circuit: &mut CircuitBuilder<SC::Challenge>, input: &Self::Input) -> Self {
        let commitments_no_lookups = BatchCommitments {
            main: input.commitments.trace.clone(),
            permutation: None,
            quotient_chunks: input.commitments.quotient_chunks.clone(),
            random: input.commitments.random.clone(),
        };
        let commitments_targets = CommitmentTargets::new(circuit, &commitments_no_lookups);
        let opened_values_targets = OpenedValuesTargets::new(circuit, &input.opened_values);
        let opening_proof = OpeningProof::new(circuit, &input.opening_proof);

        Self {
            commitments_targets,
            opened_values_targets,
            opening_proof,
            degree_bits: input.degree_bits,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let Proof {
            commitments,
            opened_values,
            opening_proof,
            degree_bits: _,
        } = input;

        let commitments_no_lookups = BatchCommitments {
            main: commitments.trace.clone(),
            permutation: None,
            quotient_chunks: commitments.quotient_chunks.clone(),
            random: commitments.random.clone(),
        };
        CommitmentTargets::<SC::Challenge, Comm>::get_values(&commitments_no_lookups)
            .into_iter()
            .chain(OpenedValuesTargets::<SC>::get_values(opened_values))
            .chain(OpeningProof::get_values(opening_proof))
            .collect()
    }

    fn get_private_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let Proof {
            commitments,
            opened_values,
            opening_proof,
            degree_bits: _,
        } = input;

        let commitments_no_lookups = BatchCommitments {
            main: commitments.trace.clone(),
            permutation: None,
            quotient_chunks: commitments.quotient_chunks.clone(),
            random: commitments.random.clone(),
        };
        CommitmentTargets::<SC::Challenge, Comm>::get_private_values(&commitments_no_lookups)
            .into_iter()
            .chain(OpenedValuesTargets::<SC>::get_private_values(opened_values))
            .chain(OpeningProof::get_private_values(opening_proof))
            .collect()
    }

    fn get_private_targets(&self) -> Vec<Target> {
        self.commitments_targets
            .get_private_targets()
            .into_iter()
            .chain(self.opened_values_targets.get_private_targets())
            .chain(self.opening_proof.get_private_targets())
            .collect()
    }
}

impl<
    SC: StarkGenericConfig,
    Comm: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    OpeningProof: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
> Recursive<SC::Challenge> for BatchProofTargets<SC, Comm, OpeningProof>
{
    type Input = BatchProof<SC>;

    /// Allocates the necessary circuit targets for storing the proof's public data.
    fn new(circuit: &mut CircuitBuilder<SC::Challenge>, input: &Self::Input) -> Self {
        // Flattened opened values are only used for challenger observation.
        // Their order must match native batch-STARK challenge generation:
        // 1. Per instance: `trace_local`, then `trace_next`
        // 2. Quotient chunks for each instance in commit order
        // 3. Per instance with preprocessed columns: `preprocessed_local`, then `preprocessed_next`
        // 4. Per instance with lookups: `permutation_local`, then `permutation_next`
        let mut aggregated_trace_local = Vec::new();
        let aggregated_trace_next = Vec::new();
        let mut aggregated_permutation_local = Vec::new();
        let aggregated_permutation_next = Vec::new();
        let mut aggregated_preprocessed_local = Vec::new();
        let aggregated_preprocessed_next = Vec::new();
        let mut aggregated_quotient_chunks = Vec::new();

        let commitments_targets = CommitmentTargets::new(circuit, &input.commitments);
        let opened_values_targets = BatchOpenedValuesTargets::new(circuit, &input.opened_values);
        let opening_proof = OpeningProof::new(circuit, &input.opening_proof);
        let global_lookup_data = input
            .global_lookup_data
            .iter()
            .map(|instance_data| {
                instance_data
                    .iter()
                    .map(|ld| {
                        let target = circuit.alloc_public_input("global lookup data");
                        LookupData {
                            name: ld.name.clone(),
                            aux_idx: ld.aux_idx,
                            expected_cumulated: target,
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        for instance in &opened_values_targets.instances {
            aggregated_trace_local.extend(&instance.opened_values_no_lookups.trace_local_targets);
            aggregated_trace_local.extend(&instance.opened_values_no_lookups.trace_next_targets);
            if let Some(prep_local) = &instance.opened_values_no_lookups.preprocessed_local_targets
            {
                aggregated_preprocessed_local.extend(prep_local);
            }
            if let Some(prep_next) = &instance.opened_values_no_lookups.preprocessed_next_targets {
                aggregated_preprocessed_local.extend(prep_next);
            }
            aggregated_permutation_local.extend(&instance.permutation_local_targets);
            aggregated_permutation_local.extend(&instance.permutation_next_targets);
            for chunk in &instance.opened_values_no_lookups.quotient_chunks_targets {
                aggregated_quotient_chunks.push(chunk.clone());
            }
        }

        let flattened_opened_values_targets = OpenedValuesTargetsWithLookups {
            opened_values_no_lookups: OpenedValuesTargets {
                trace_local_targets: aggregated_trace_local,
                trace_next_targets: aggregated_trace_next,
                preprocessed_local_targets: if aggregated_preprocessed_local.is_empty() {
                    None
                } else {
                    Some(aggregated_preprocessed_local)
                },
                preprocessed_next_targets: if aggregated_preprocessed_next.is_empty() {
                    None
                } else {
                    Some(aggregated_preprocessed_next)
                },
                quotient_chunks_targets: aggregated_quotient_chunks,
                random_targets: None, // Batch proofs do not have random values
                _phantom: PhantomData,
            },
            permutation_local_targets: aggregated_permutation_local,
            permutation_next_targets: aggregated_permutation_next,
        };

        Self {
            commitments_targets,
            opened_values_targets,
            flattened_opened_values_targets,
            opening_proof,
            global_lookup_data,
            degree_bits: input.degree_bits.clone(),
        }
    }

    fn get_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let BatchProof {
            commitments,
            opened_values,
            opening_proof,
            global_lookup_data,
            degree_bits: _,
        } = input;

        CommitmentTargets::<SC::Challenge, Comm>::get_values(commitments)
            .into_iter()
            .chain(BatchOpenedValuesTargets::<SC>::get_values(opened_values))
            .chain(OpeningProof::get_values(opening_proof))
            .chain(
                global_lookup_data
                    .iter()
                    .flatten()
                    .map(|ld| ld.expected_cumulated),
            )
            .collect()
    }

    fn get_private_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let BatchProof {
            commitments,
            opened_values,
            opening_proof,
            global_lookup_data: _,
            degree_bits: _,
        } = input;

        CommitmentTargets::<SC::Challenge, Comm>::get_private_values(commitments)
            .into_iter()
            .chain(BatchOpenedValuesTargets::<SC>::get_private_values(opened_values))
            .chain(OpeningProof::get_private_values(opening_proof))
            .collect()
    }

    fn get_private_targets(&self) -> Vec<Target> {
        self.commitments_targets
            .get_private_targets()
            .into_iter()
            .chain(self.opened_values_targets.get_private_targets())
            .chain(self.opening_proof.get_private_targets())
            .collect()
    }
}

impl<F: Field, Comm> Recursive<F> for CommitmentTargets<F, Comm>
where
    Comm: Recursive<F>,
{
    type Input = BatchCommitments<Comm::Input>;

    fn new(circuit: &mut CircuitBuilder<F>, input: &Self::Input) -> Self {
        let trace_targets = Comm::new(circuit, &input.main);
        let permutation_targets = input
            .permutation
            .as_ref()
            .map(|perm| Comm::new(circuit, perm));
        let quotient_chunks_targets = Comm::new(circuit, &input.quotient_chunks);

        Self {
            trace_targets,
            permutation_targets,
            quotient_chunks_targets,
            random_commit: None, // ZK is not supported in batch proofs yet
            _phantom: PhantomData,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<F> {
        let BatchCommitments {
            main,
            permutation,
            quotient_chunks,
            random,
        } = input;

        let mut values = vec![];
        values.extend(Comm::get_values(main));
        if let Some(permutation) = permutation {
            values.extend(Comm::get_values(permutation));
        }
        values.extend(Comm::get_values(quotient_chunks));

        if let Some(random) = random {
            values.extend(Comm::get_values(random));
        }

        values
    }

    fn get_private_values(input: &Self::Input) -> Vec<F> {
        let BatchCommitments {
            main,
            permutation,
            quotient_chunks,
            random,
        } = input;

        let mut values = vec![];
        values.extend(Comm::get_private_values(main));
        if let Some(permutation) = permutation {
            values.extend(Comm::get_private_values(permutation));
        }
        values.extend(Comm::get_private_values(quotient_chunks));

        if let Some(random) = random {
            values.extend(Comm::get_private_values(random));
        }

        values
    }

    fn get_private_targets(&self) -> Vec<Target> {
        let mut targets = self.trace_targets.get_private_targets();
        if let Some(permutation) = &self.permutation_targets {
            targets.extend(permutation.get_private_targets());
        }
        targets.extend(self.quotient_chunks_targets.get_private_targets());
        if let Some(random) = &self.random_commit {
            targets.extend(random.get_private_targets());
        }
        targets
    }
}

impl<SC: StarkGenericConfig> Recursive<SC::Challenge> for OpenedValuesTargets<SC> {
    type Input = OpenedValues<SC::Challenge>;

    fn new(circuit: &mut CircuitBuilder<SC::Challenge>, input: &Self::Input) -> Self {
        let trace_local_len = input.trace_local.len();
        let trace_local_targets = circuit.alloc_proof_inputs(
            trace_local_len,
            "trace local opened values (witness)",
        );

        let trace_next_len = input.trace_next.len();
        let trace_next_targets =
            circuit.alloc_proof_inputs(trace_next_len, "trace next opened values (witness)");

        let preprocessed_local_targets = input
            .preprocessed_local
            .as_ref()
            .map(|prep| {
                circuit.alloc_proof_inputs(prep.len(), "local preprocessed opened values (witness)")
            });
        let preprocessed_next_targets = input
            .preprocessed_next
            .as_ref()
            .map(|prep| {
                circuit.alloc_proof_inputs(prep.len(), "next preprocessed opened values (witness)")
            });

        let quotient_chunks_len = input.quotient_chunks.len();
        let mut quotient_chunks_targets = Vec::with_capacity(quotient_chunks_len);
        for quotient_chunk in input.quotient_chunks.iter() {
            let quotient_chunks_cols_len = quotient_chunk.len();
            let quotient_col = circuit.alloc_proof_inputs(
                quotient_chunks_cols_len,
                "quotient chunk opened values (witness)",
            );
            quotient_chunks_targets.push(quotient_col);
        }

        let random_targets = input
            .random
            .as_ref()
            .map(|random| circuit.alloc_proof_inputs(random.len(), "random opened values (witness, ZK mode)"));

        Self {
            trace_local_targets,
            trace_next_targets,
            preprocessed_local_targets,
            preprocessed_next_targets,
            quotient_chunks_targets,
            random_targets,
            _phantom: PhantomData,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<SC::Challenge> {
        // Opened values are witness-only in recursion circuits.
        let _ = input;
        Vec::new()
    }

    fn get_private_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let mut values = Vec::new();
        values.extend(input.trace_local.iter().copied());
        values.extend(input.trace_next.iter().copied());
        if let Some(prep) = &input.preprocessed_local {
            values.extend(prep.iter().copied());
        }
        if let Some(prep) = &input.preprocessed_next {
            values.extend(prep.iter().copied());
        }
        for chunk in &input.quotient_chunks {
            values.extend(chunk.iter().copied());
        }
        if let Some(random) = &input.random {
            values.extend(random.iter().copied());
        }
        values
    }

    fn get_private_targets(&self) -> Vec<Target> {
        let mut targets = Vec::new();
        targets.extend(self.trace_local_targets.iter().copied());
        targets.extend(self.trace_next_targets.iter().copied());
        if let Some(prep) = &self.preprocessed_local_targets {
            targets.extend(prep.iter().copied());
        }
        if let Some(prep) = &self.preprocessed_next_targets {
            targets.extend(prep.iter().copied());
        }
        for chunk in &self.quotient_chunks_targets {
            targets.extend(chunk.iter().copied());
        }
        if let Some(random) = &self.random_targets {
            targets.extend(random.iter().copied());
        }
        targets
    }
}

impl<SC: StarkGenericConfig> Recursive<SC::Challenge> for OpenedValuesTargetsWithLookups<SC> {
    type Input = OpenedValuesWithLookups<SC::Challenge>;

    fn new(circuit: &mut CircuitBuilder<SC::Challenge>, input: &Self::Input) -> Self {
        let opened_values_no_lookups = OpenedValuesTargets::new(circuit, &input.base_opened_values);

        let permutation_local_targets = circuit.alloc_proof_inputs(
            input.permutation_local.len(),
            "permutation local opened values (witness)",
        );
        let permutation_next_targets = circuit.alloc_proof_inputs(
            input.permutation_next.len(),
            "permutation next opened values (witness)",
        );

        Self {
            opened_values_no_lookups,
            permutation_local_targets,
            permutation_next_targets,
        }
    }

    fn get_values(input: &Self::Input) -> Vec<SC::Challenge> {
        // Lookup opened values are witness-only in recursion circuits.
        let _ = input;
        Vec::new()
    }

    fn get_private_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let mut values =
            OpenedValuesTargets::<SC>::get_private_values(&input.base_opened_values);
        values.extend(input.permutation_local.iter().copied());
        values.extend(input.permutation_next.iter().copied());
        values
    }

    fn get_private_targets(&self) -> Vec<Target> {
        self.opened_values_no_lookups
            .get_private_targets()
            .into_iter()
            .chain(self.permutation_local_targets.iter().copied())
            .chain(self.permutation_next_targets.iter().copied())
            .collect()
    }
}

impl<SC: StarkGenericConfig> Recursive<SC::Challenge> for BatchOpenedValuesTargets<SC> {
    type Input = BatchOpenedValues<SC::Challenge>;

    fn new(circuit: &mut CircuitBuilder<SC::Challenge>, input: &Self::Input) -> Self {
        let instances = input
            .instances
            .iter()
            .map(|instance| OpenedValuesTargetsWithLookups::new(circuit, instance))
            .collect();

        Self { instances }
    }

    fn get_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let mut values = vec![];
        for instance in &input.instances {
            values.extend(OpenedValuesTargetsWithLookups::<SC>::get_values(instance));
        }
        values
    }

    fn get_private_values(input: &Self::Input) -> Vec<SC::Challenge> {
        let mut values = vec![];
        for instance in &input.instances {
            values.extend(OpenedValuesTargetsWithLookups::<SC>::get_private_values(
                instance,
            ));
        }
        values
    }

    fn get_private_targets(&self) -> Vec<Target> {
        self.instances
            .iter()
            .flat_map(OpenedValuesTargetsWithLookups::<SC>::get_private_targets)
            .collect()
    }
}
