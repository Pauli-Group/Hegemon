import HegemonCrypto.SmallWoodV8Smz9RuntimeBatchBridge

namespace HegemonCrypto.SmallWood.V8Smz9RuntimeBatchBridge

open V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open scoped ENNReal BigOperators

/-- Actual ordered scanner output, indexed only using the proved output count. -/
def batchOutputVector {n : Nat} (batch : BatchTrace n) : RuntimeFieldCoins n :=
  List.Vector.get (⟨scanAccepted batch.val.flatten,
    exact_scan_length (valid_batches_exact batch.property)⟩ : List.Vector IdealFieldCoin n)

theorem batch_output_vector_scan {n : Nat} (batch : BatchTrace n) :
    List.ofFn (batchOutputVector batch) = scanAccepted batch.val.flatten := by
  calc
    List.ofFn (batchOutputVector batch) =
        List.Vector.toList (List.Vector.ofFn (batchOutputVector batch)) :=
      (List.Vector.toList_ofFn _).symm
    _ = scanAccepted batch.val.flatten := by
      unfold batchOutputVector
      rw [List.Vector.ofFn_get]
      rfl

theorem batch_output_vector_matches_first {n : Nat} (batch : BatchTrace n) :
    batchOutputVector batch =
      (fun i => iidUniformTraceOutput (batchFirstAcceptEquiv n batch i)) := by
  apply List.ofFn_injective
  rw [batch_output_vector_scan]
  exact batch_first_accept_preserves_outputs batch

/-- Equality of the entire raw word list preserves any fixed byte serialization,
    including its order; this does not certify the Rust byte decoder. -/
theorem batch_preserves_serialization {Byte : Type*} (encode : RawWord → List Byte)
    {n : Nat} (batch : BatchTrace n) :
    (firstTraceCandidates (batchFirstAcceptEquiv n batch)).flatMap encode =
      batch.val.flatten.flatMap encode :=
  congrArg (fun raw => raw.flatMap encode) (batch_first_accept_preserves_raw batch)

theorem batch_total_requested_bytes {n : Nat} (batch : BatchTrace n) :
    (batch.val.map fun buffer => 8 * buffer.length).sum =
      8 * batch.val.flatten.length := by
  have h : ∀ rounds : List (List RawWord),
      (rounds.map fun buffer => 8 * buffer.length).sum = 8 * rounds.flatten.length := by
    intro rounds
    induction rounds with
    | nil => rfl
    | cons buffer rounds ih =>
        simp only [List.map_cons, List.sum_cons, List.flatten_cons, List.length_append, ih]
        omega
  exact h batch.val

theorem first_trace_total_raw_length {n : Nat} (traces : Fin n → IidUniformTerminatingTrace) :
    (firstTraceCandidates traces).length = ∑ i, ((traces i).1 + 1) := by
  simp [firstTraceCandidates, List.length_flatMap, iidUniformTraceCandidates,
    exactAttemptCandidates, List.sum_ofFn]

theorem first_trace_mass_by_raw_length {n : Nat} (traces : Fin n → IidUniformTerminatingTrace) :
    iidUniformRejectionTraceVectorPMF n traces =
      (rawWordCardinality : ℝ≥0∞)⁻¹ ^ (firstTraceCandidates traces).length := by
  rw [iid_uniform_rejection_trace_vector_mass, first_trace_total_raw_length]
  exact Finset.prod_pow_eq_pow_sum (Finset.univ : Finset (Fin n))
    (fun i => (traces i).1 + 1) ((rawWordCardinality : ℝ≥0∞)⁻¹)

/-- The existing normalized iid raw-prefix law transported through the proved
    batch bijection. No runtime/output equality is supplied as a premise. -/
noncomputable def iidBatchTracePMF (n : Nat) : PMF (BatchTrace n) :=
  pmfMap (iidUniformRejectionTraceVectorPMF n) (batchFirstAcceptEquiv n).symm

private theorem pmf_map_injective_point {Input Output : Type*} (law : PMF Input)
    (f : Input → Output) (injective : Function.Injective f) (input : Input) :
    pmfMap law f (f input) = law input := by
  rw [pmfMap_apply, tsum_eq_single input]
  · simp
  · intro other different
    rw [if_neg]
    intro equal
    exact different (injective equal).symm

/-- Every valid completed batch schedule has the exact iid raw-proposal mass,
    based on all consumed candidates rather than only its accepted outputs. -/
theorem iid_batch_trace_mass {n : Nat} (batch : BatchTrace n) :
    iidBatchTracePMF n batch =
      (rawWordCardinality : ℝ≥0∞)⁻¹ ^ batch.val.flatten.length := by
  have h := pmf_map_injective_point (iidUniformRejectionTraceVectorPMF n)
    (batchFirstAcceptEquiv n).symm (batchFirstAcceptEquiv n).symm.injective
    (batchFirstAcceptEquiv n batch)
  simp only [Equiv.symm_apply_apply] at h
  change iidBatchTracePMF n batch = _ at h
  rw [h, first_trace_mass_by_raw_length, batch_first_accept_preserves_length]

theorem iid_batch_output_law (n : Nat) :
    pmfMap (iidBatchTracePMF n) batchOutputVector =
      iidUniformRejectionSamplerOutputPMF n := by
  rw [iidBatchTracePMF, pmfMap_comp]
  unfold iidUniformRejectionSamplerOutputPMF
  apply congrArg (pmfMap (iidUniformRejectionTraceVectorPMF n))
  funext traces
  simp only [Function.comp_apply, batch_output_vector_matches_first,
    Equiv.apply_symm_apply]

theorem iid_batch_output_uniform (n : Nat) :
    pmfMap (iidBatchTracePMF n) batchOutputVector =
      uniformFintypePMF (RuntimeFieldCoins n) := by
  rw [iid_batch_output_law, iid_uniform_rejection_output_vector_uniform]

theorem iid_batch_output_mass (n : Nat) (outputs : RuntimeFieldCoins n) :
    pmfMap (iidBatchTracePMF n) batchOutputVector outputs =
      (fieldModulus : ℝ≥0∞)⁻¹ ^ n := by
  rw [iid_batch_output_law]
  exact iid_uniform_rejection_output_vector_mass n outputs

/-- Any successful finite batch-trace law with the stated ideal raw-prefix
    masses is this law. A real provider still needs its own premise/bridge. -/
theorem iid_raw_batch_law_unique (n : Nat) (law : PMF (BatchTrace n))
    (hraw : ∀ batch, law batch =
      (rawWordCardinality : ℝ≥0∞)⁻¹ ^ batch.val.flatten.length) :
    law = iidBatchTracePMF n := by
  apply PMF.ext
  intro batch
  rw [hraw, iid_batch_trace_mass]

/-- The existing downstream allocation theorem can use this transport directly. -/
theorem iid_batch_allocation_transport {Allocation : Type*} (n : Nat)
    (allocate : RuntimeFieldCoins n → Allocation) :
    pmfMap (iidBatchTracePMF n) (fun batch => allocate (batchOutputVector batch)) =
      pmfMap (iidUniformRejectionSamplerOutputPMF n) allocate := by
  rw [← iid_batch_output_law n, pmfMap_comp]
  rfl


end HegemonCrypto.SmallWood.V8Smz9RuntimeBatchBridge
