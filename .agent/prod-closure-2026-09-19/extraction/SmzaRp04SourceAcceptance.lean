import SmzaRp04DecodedPolynomialSource
namespace HegemonCrypto.SmallWood.SmzaRp04SourceAcceptance
open Hegemon.Transaction.Poseidon2V8RelationProgram
open SmzaRp04Components SmzaRp04PublicContext SmzaRp04DecodedPolynomialSource SmzaRp04PackedAcceptance
open V8Smz9ProgramPolynomials
open V8Smz9CurrentSourceAcceptance (field_roots_zero_supplies_source_acceptance source_packing_rows_field_values)
open V8Smz9CurrentPublicContext (source_packing_rows_match_packed_lane)
open scoped BigOperators Classical
noncomputable section
set_option maxRecDepth 10000
set_option maxHeartbeats 800000
theorem source_openings_zero_supplies_nonlinear_acceptance
    (publicValues witness : List Nat) (publicCanonical : CanonicalPublicWords publicValues)
    (witnessCanonical : CanonicalPackedWitness witness)
    (zero : ∀ root lane, SmzaRp04ProgramPiop.currentConstraintOpenings
      (publicParameters publicValues 0) (fun row => packingValues witness row lane) root = 0)
    (lane : Fin 64) :
    program.nonlinearExecutable.Accepts publicValues
      (packedWitnessLaneRows witness lane.val) := by
  rw [← source_packing_rows_match_packed_lane witnessCanonical lane]
  apply field_roots_zero_supplies_source_acceptance
  · exact Nat.le_of_eq publicCanonical.1.symm
  · simp only [V8Smz9CurrentProgramOpeningBinding.sourcePackingRows, List.length_ofFn, le_refl]
  · exact nonlinear_canonical
  · intro root member
    change root ∈ exactNonlinearRoots at member
    obtain ⟨index, bound, same⟩ := List.mem_iff_getElem.mp member
    have indexBound : index < 773 := by simpa only [SmzaRp04NonlinearTransport.actual_root_count] using bound
    have rootIndex : exactNonlinearRoots.getD index 0 = root := by
      simp only [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem bound, Option.getD_some, same]
    have vanishes := zero ⟨index, indexBound⟩ lane
    change fieldAt exactNonlinearExpressions (fun n => (publicValues.getD n 0 : Goldilocks))
      (V8Smz9EagerSimulator.openedWitnessAtNat (fun row => packingValues witness row lane))
      (exactNonlinearRoots.getD index 0) = 0 at vanishes
    rw [source_packing_rows_field_values, rootIndex] at vanishes
    exact vanishes

theorem decoded_source_relation_supplies_normalized_rows (publicValues : List Nat)
    (source : SourcePolynomials) (relation : DecodedSourceRelation publicValues source) :
    NormalizedRowsHold publicValues (packedWitness source) := by
  intro index
  have equation := relation.2 index
  change (∑ row : Fin 686, ∑ lane : Fin 64,
    normalizedCoefficient publicValues (retainedAttempts publicValues)[index.val]
      (finProdFinEquiv (row, lane)) *
        packedFieldValues (packedWitness source) (finProdFinEquiv (row, lane))) = _ at equation
  have reindex (f : PackedIndex → Goldilocks) :
      (∑ row : Fin 686, ∑ lane : Fin 64, f (finProdFinEquiv (row, lane))) = ∑ coordinate, f coordinate := by
    calc
      _ = ∑ pair : Fin 686 × Fin 64, f (finProdFinEquiv pair) :=
        (Fintype.sum_prod_type _).symm
      _ = _ := Equiv.sum_comp (finProdFinEquiv : Fin 686 × Fin 64 ≃ PackedIndex) f
  rw [reindex (fun coordinate => normalizedCoefficient publicValues
    (retainedAttempts publicValues)[index.val] coordinate *
      packedFieldValues (packedWitness source) coordinate)] at equation
  exact equation

/-- Complete unchanged raw packed interpreter acceptance, derived from the
generated decoded source relation. No evaluator-success or decoded validity
receipt is supplied. Public admission remains the explicit frontend boundary. -/
theorem decoded_source_relation_supplies_packed_acceptance (publicValues : List Nat)
    (source : SourcePolynomials) (publicCanonical : CanonicalPublicWords publicValues)
    (relation : DecodedSourceRelation publicValues source) :
    program.AcceptsPacked publicValues (packedWitness source) := by
  refine ⟨publicCanonical, packed_witness_canonical source, ?_, ?_⟩
  · intro lane bound
    exact source_openings_zero_supplies_nonlinear_acceptance publicValues (packedWitness source)
      publicCanonical (packed_witness_canonical source) relation.1 ⟨lane, bound⟩
  · exact normalized_rows_supply_csr_source_acceptance publicValues (packedWitness source)
      publicCanonical (packed_witness_canonical source)
      (decoded_source_relation_supplies_normalized_rows publicValues source relation)

theorem fully_satisfied_decoded_candidate_supplies_packed_acceptance
    (publicValues : List Nat) (source : SourcePolynomials)
    (publicCanonical : CanonicalPublicWords publicValues)
    (satisfied : PiopExtraction.FullySatisfied (sourcePiopCandidate publicValues source).system) :
    program.AcceptsPacked publicValues (packedWitness source) :=
  decoded_source_relation_supplies_packed_acceptance publicValues source publicCanonical
    (fully_satisfied_candidate_supplies_decoded_source_relation publicValues source satisfied)

end
end HegemonCrypto.SmallWood.SmzaRp04SourceAcceptance
