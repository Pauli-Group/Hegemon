import HegemonCrypto.SmallWoodV8Smz9HonestOpeningSchedule

/-! Actual fixed DECS candidate selection and the missing tail-rank proof.
The source index selector is not a supplied chooser: it scans the exact field
words, rejects the top residue, keeps first distinct positions and sorts them.
Its successful result constructs all LVCS target-admissibility fields. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceIndexSampler

open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9HiddenLeafQrom V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9HonestWholeViewGames V8Smz9HonestWholeViewFinalInput V8Smz9HonestFinalGame
open V8Smz9HonestRequestSchedule V8Smz9HonestOpeningSchedule V8Smz9EagerPrivacy
open V8Smz9EagerSimulator V8Smz9EagerOracleGame V8Smz9SingleProofPrivacy
open V8Smz9RuntimeDistribution V8Smz9WholeViewObservation V8Smz9ZeroKnowledge
open V8Smz9HiddenPatch
open Polynomial
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000

def tailPolynomial {F : Type*} [Field F] (tail : Fin 20 → F) : F[X] :=
  Lagrange.interpolate (Finset.univ : Finset (Fin 388)) (fun node => (node.val : F))
    (Fin.append tail (fun _ : Fin 368 => 0))

theorem tail_polynomial_evaluation {F : Type*} [Field F]
    (targets : Fin 20 → F) (tail : Fin 20 → F) (opening : Fin 20) :
    (tailPolynomial tail).eval (targets opening) = smz9LvcsTailEvaluationMap targets tail opening := by
  simp only [tailPolynomial, Lagrange.interpolate_apply, eval_finsetSum, eval_mul, eval_C]
  change (∑ node : Fin (20 + 368), _) = _
  rw [Fin.sum_univ_add]
  simp only [Fin.append_left, Fin.append_right, zero_mul, Finset.sum_const_zero, add_zero]
  unfold smz9LvcsTailEvaluationMap smz9LvcsTailLagrangeCoefficient smz9LvcsTailNode
  apply Finset.sum_congr rfl
  intro index _
  exact mul_comm _ _

/-- There are 368 fixed zero head nodes and twenty new distinct targets.
Consequently equality at the targets determines all twenty tail values. -/
theorem actual_tail_evaluation_injective {F : Type*} [Field F]
    (nodesDistinct : Function.Injective (fun node : Fin 388 => (node.val : F)))
    (targets : Fin 20 → F) (targetsDistinct : Function.Injective targets)
    (outside : ∀ opening (node : Fin 388), targets opening ≠ (node.val : F)) :
    Function.Injective (smz9LvcsTailEvaluationMap targets) := by
  let combined : Fin 368 ⊕ Fin 20 → F :=
    Sum.elim (fun head => ((20 + head.val : Nat) : F)) targets
  have combinedDistinct : Function.Injective combined := by
    intro left right same
    cases left with
    | inl left =>
        cases right with
        | inl right =>
            have equal : (⟨20 + left.val, by omega⟩ : Fin 388) = ⟨20 + right.val, by omega⟩ :=
              nodesDistinct same
            have indices := congrArg Fin.val equal
            exact congrArg Sum.inl (Fin.ext (by simpa using indices))
        | inr right => exact (outside right ⟨20 + left.val, by omega⟩ same.symm).elim
    | inr left =>
        cases right with
        | inl right => exact (outside left ⟨20 + right.val, by omega⟩ same).elim
        | inr right => exact congrArg Sum.inr (targetsDistinct same)
  refine fun (left : Fin 20 → F) (right : Fin 20 → F) same => ?_
  have polynomials : tailPolynomial left = tailPolynomial right := by
    apply Polynomial.eq_of_degrees_lt_of_eval_index_eq
      (Finset.univ : Finset (Fin 368 ⊕ Fin 20)) combinedDistinct.injOn
    · have degree := Lagrange.degree_interpolate_lt (s := (Finset.univ : Finset (Fin 388)))
        (Fin.append left (fun _ : Fin 368 => 0)) nodesDistinct.injOn
      simpa only [tailPolynomial, Finset.card_univ, Fintype.card_sum, Fintype.card_fin, Nat.reduceAdd] using degree
    · have degree := Lagrange.degree_interpolate_lt (s := (Finset.univ : Finset (Fin 388)))
        (Fin.append right (fun _ : Fin 368 => 0)) nodesDistinct.injOn
      simpa only [tailPolynomial, Finset.card_univ, Fintype.card_sum, Fintype.card_fin, Nat.reduceAdd] using degree
    · intro index _
      cases index with
      | inl head =>
          change (tailPolynomial left).eval ((20 + head.val : Nat) : F) =
            (tailPolynomial right).eval ((20 + head.val : Nat) : F)
          have leftEval := Lagrange.eval_interpolate_at_node
            (Fin.append left (fun _ : Fin 368 => 0)) nodesDistinct.injOn
            (Finset.mem_univ (Fin.natAdd 20 head))
          have rightEval := Lagrange.eval_interpolate_at_node
            (Fin.append right (fun _ : Fin 368 => 0)) nodesDistinct.injOn
            (Finset.mem_univ (Fin.natAdd 20 head))
          simp only [Fin.append_right] at leftEval rightEval
          exact leftEval.trans rightEval.symm
      | inr opening =>
          change (tailPolynomial left).eval (targets opening) = (tailPolynomial right).eval (targets opening)
          rw [tail_polynomial_evaluation, tail_polynomial_evaluation, same]
  funext index
  have leftEval := Lagrange.eval_interpolate_at_node
    (Fin.append left (fun _ : Fin 368 => 0)) nodesDistinct.injOn
    (Finset.mem_univ (Fin.castAdd 368 index))
  have rightEval := Lagrange.eval_interpolate_at_node
    (Fin.append right (fun _ : Fin 368 => 0)) nodesDistinct.injOn
    (Finset.mem_univ (Fin.castAdd 368 index))
  simp only [Fin.append_left] at leftEval rightEval
  have evals := congrArg (fun p : F[X] => p.eval (index.val : F)) polynomials
  exact leftEval.symm.trans (evals.trans rightEval)

theorem actual_interpolation_nodes_distinct :
    Function.Injective (fun node : Fin 388 => (node.val : Goldilocks)) := by
  intro left right same
  have leftBound : left.val < goldilocksModulus := left.isLt.trans_le (by decide)
  have rightBound : right.val < goldilocksModulus := right.isLt.trans_le (by decide)
  have values := congrArg ZMod.val same
  simp only [ZMod.val_natCast, Nat.mod_eq_of_lt leftBound, Nat.mod_eq_of_lt rightBound] at values
  exact Fin.ext values

theorem actual_indexed_targets_admissible (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (indices : Fin 20 → LeafIndex)
    (indicesDistinct : Function.Injective indices) :
    Smz9LvcsTailAdmissible points (indexedPoints indices) := by
  have targetDistinct : Function.Injective (indexedPoints indices) :=
    V8Smz9DisjointCoset.evaluation_point_injective.comp indicesDistinct
  have outside : ∀ opening (node : Fin 388), indexedPoints indices opening ≠ (node.val : Goldilocks) :=
    fun opening node => V8Smz9DisjointCoset.disjoint_from_interpolation_domain (indices opening) node
  exact ⟨distinct, targetDistinct, outside, actual_selected_block_injective distinct,
    actual_tail_evaluation_injective actual_interpolation_nodes_distinct _ targetDistinct outside⟩

/-- Source BTreeSet/first-twenty behavior. The accumulator order is insertion
order, so repeated values never replace an earlier accepted candidate. -/
def collectSourceIndices : List FieldWord → List LeafIndex → List LeafIndex
  | [], selected => selected
  | candidate :: rest, selected =>
      if selected.length = 20 then selected else
      if candidate.val < (goldilocksModulus / 8388608) * 8388608 then
        let index : LeafIndex := ⟨candidate.val % 8388608, Nat.mod_lt _ (by decide)⟩
        if index ∈ selected then collectSourceIndices rest selected
        else collectSourceIndices rest (selected.concat index)
      else collectSourceIndices rest selected

theorem source_index_collection_nodup (candidates : List FieldWord) (selected : List LeafIndex)
    (nodup : selected.Nodup) : (collectSourceIndices candidates selected).Nodup := by
  induction candidates generalizing selected with
  | nil => exact nodup
  | cons candidate rest ih =>
      simp only [collectSourceIndices]
      split
      · exact nodup
      · split
        · split
          · exact ih _ nodup
          · exact ih _ (List.Nodup.concat (by assumption) nodup)
        · exact ih _ nodup

def sourceSortedIndices (candidates : List FieldWord) : List LeafIndex :=
  (collectSourceIndices candidates []).mergeSort (fun left right => decide (left.val ≤ right.val))

theorem source_sorted_indices_nodup (candidates : List FieldWord) :
    (sourceSortedIndices candidates).Nodup :=
  (source_index_collection_nodup candidates [] (by simp)).mergeSort

/-- Successful actual source sampling constructs the full algebraic target
certificate. There is no external rank, disjointness or target-validity input. -/
def sourceIndexedTargets (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (candidates : List FieldWord) : Option (IndexedTargets points) :=
  let indices := sourceSortedIndices candidates
  if enough : indices.length = 20 then
    let selected : Fin 20 → LeafIndex := fun index => indices.get (index.cast enough.symm)
    let selectedDistinct : Function.Injective selected := by
      intro left right same
      have equal := (source_sorted_indices_nodup candidates).injective_get same
      exact Fin.ext (congrArg (fun index : Fin indices.length => index.val) equal)
    some ⟨selected, selectedDistinct, actual_indexed_targets_admissible points distinct selected selectedDistinct⟩
  else none

theorem source_index_exhaustion_is_none (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (candidates : List FieldWord)
    (exhausted : (sourceSortedIndices candidates).length ≠ 20) :
    sourceIndexedTargets points distinct candidates = none := by
  simp only [sourceIndexedTargets, exhausted, ↓reduceDIte]

def sourceDecsOpeningWords (digest : DigestRegister)
    (heads : Fin 12 → Fin 368 → Goldilocks) (tails : Fin 12 → Fin 20 → Goldilocks) : List Nat :=
  sourceDigestWords digest ++
    (List.ofFn fun combination : Fin 12 =>
      (List.ofFn fun column : Fin 368 => fromGoldilocks (heads combination column)) ++
      (List.ofFn fun tail : Fin 20 => fromGoldilocks (tails combination tail))).flatten

theorem source_decs_opening_word_count (digest : DigestRegister)
    (heads : Fin 12 → Fin 368 → Goldilocks) (tails : Fin 12 → Fin 20 → Goldilocks) :
    (sourceDecsOpeningWords digest heads tails).length = 4664 := by
  simp only [sourceDecsOpeningWords, List.length_append, source_digest_word_count,
    List.length_flatten, List.map_ofFn, Function.comp_def, List.length_ofFn,
    List.sum_ofFn, Finset.sum_const, Finset.card_univ, Fintype.card_fin, smul_eq_mul]

def sourceDecsOpeningKey (bound : Nat) (largeEnough : 37434 ≤ bound)
    (digest : DigestRegister) (heads : Fin 12 → Fin 368 → Goldilocks)
    (tails : Fin 12 → Fin 20 → Goldilocks) : OtherRawInput bound :=
  sourceCounterKey bound SmallWoodTranscript.decsOpeningDomain (sourceDecsOpeningWords digest heads tails)
    (by rw [source_decs_opening_word_count]; have role : SmallWoodTranscript.decsOpeningDomain.length = 37 := by decide
        rw [role]; omega)
    (by rw [source_decs_opening_word_count]; decide) ⟨0, by norm_num⟩

theorem source_decs_opening_key_length (bound : Nat) (largeEnough : 37434 ≤ bound)
    (digest : DigestRegister) (heads : Fin 12 → Fin 368 → Goldilocks)
    (tails : Fin 12 → Fin 20 → Goldilocks) :
    (rawBytes (Sum.inr (sourceDecsOpeningKey bound largeEnough digest heads tails))).length = 37434 := by
  rw [sourceDecsOpeningKey, source_counter_key_is_literal_input, source_counter_raw_length,
    source_decs_opening_word_count]
  decide

def sourceFixedIndexKey (bound : Nat) (largeEnough : 37434 ≤ bound)
    (digest : DigestRegister) (counter : Fin (2 ^ 64)) : OtherRawInput bound :=
  sourceCounterKey bound SmallWoodTranscript.decsFixedSamplingDomain (sourceDigestWords digest)
    (by rw [source_digest_word_count]; have role : SmallWoodTranscript.decsFixedSamplingDomain.length = 44 := by decide
        rw [role]; omega)
    (by rw [source_digest_word_count]; decide) counter

theorem source_fixed_index_key_length (bound : Nat) (largeEnough : 37434 ≤ bound)
    (digest : DigestRegister) (counter : Fin (2 ^ 64)) :
    (rawBytes (Sum.inr (sourceFixedIndexKey bound largeEnough digest counter))).length = 193 := by
  rw [sourceFixedIndexKey, source_counter_key_is_literal_input, source_counter_raw_length,
    source_digest_word_count]
  decide

/-- The active constant is fifty candidates; the old nearby Rust comment
describing forty candidates is not used. Field rejection permits eleven raw
digest blocks for this request, with exact early termination. -/
def sourceFixedIndexXof (bound : Nat) (largeEnough : 37434 ≤ bound) (digest : DigestRegister) :
    NonleafProgram (OtherRawInput bound) (Option (List FieldWord)) :=
  sourceFieldReadLoop 50 [] (List.ofFn fun index : Fin 11 =>
    sourceFixedIndexKey bound largeEnough digest ⟨index.val, by omega⟩)

structure DecsSelectionResult (points : Fin 6 → Goldilocks) where
  transcriptDigest : DigestRegister
  fieldCandidates : Option (List FieldWord)
  targets : Option (IndexedTargets points)
  pendingFailure : Bool

def sourceDecsSelection (bound : Nat) (largeEnough : 37434 ≤ bound)
    (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (digest : DigestRegister) (heads : Fin 12 → Fin 368 → Goldilocks)
    (tails : Fin 12 → Fin 20 → Goldilocks) (pending : Bool) :
    NonleafProgram (OtherRawInput bound) (DecsSelectionResult points) :=
  .read (sourceDecsOpeningKey bound largeEnough digest heads tails) fun challenge =>
    NonleafProgram.bind (sourceFixedIndexXof bound largeEnough challenge) fun sampled =>
      .done ⟨challenge, sampled, sourceIndexedTargets points distinct (sourceReturnedWords 50 sampled),
        sourcePendingFailure pending sampled⟩

def sourceCurrentDecsSelection (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : V8Smz9CurrentProgramPiop.CurrentPublicParameters)
    (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (witness : WitnessOpeningView Goldilocks) (partials : SourcePcsView Goldilocks)
    (tails : LvcsEarlierTails Goldilocks) (pending : Bool) :
    NonleafProgram (OtherRawInput bound) (DecsSelectionResult points) :=
  sourceDecsSelection bound largeEnough points distinct digest
    (reconstructedCombinationHeads points witness
      (V8Smz9CurrentProgramPiop.currentPublicMaskOpenings parameters points transcript witness) partials)
    tails pending

/-- The index chooser used by the current algebraic context is now an
execution of the actual source hash/XOF/selection schedule, not a free
oracle-dependent callback supplied by the caller. -/
def sourceCurrentIndexChooser (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : V8Smz9CurrentProgramPiop.CurrentPublicParameters)
    (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (oracle : OtherRawInput bound → DigestRegister) : IndexChooser points :=
  fun witness partials tails =>
    (NonleafProgram.interpret oracle
      (sourceCurrentDecsSelection bound largeEnough parameters points distinct transcript digest
        witness partials tails false)).targets

theorem source_current_decs_selection_executes_index_chooser
    (bound : Nat) (largeEnough : 37434 ≤ bound)
    (parameters : V8Smz9CurrentProgramPiop.CurrentPublicParameters)
    (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (transcript : PiopCoefficients Goldilocks) (digest : DigestRegister)
    (oracle : OtherRawInput bound → DigestRegister)
    (witness : WitnessOpeningView Goldilocks) (partials : SourcePcsView Goldilocks)
    (tails : LvcsEarlierTails Goldilocks) :
    (NonleafProgram.interpret oracle
      (sourceCurrentDecsSelection bound largeEnough parameters points distinct transcript digest
        witness partials tails false)).targets =
      sourceCurrentIndexChooser bound largeEnough parameters points distinct transcript digest oracle
        witness partials tails := rfl

def sourceScopeReturn {Value : Type} (pending : Bool) : Except String Value → Except String Value
  | .error message => .error message
  | .ok value => sourceScopeFinish pending value

/-- A genuine earlier source `?` return is not rewritten into the later TLS
diagnostic. In either case this return processing performs no oracle reset. -/
theorem genuine_source_error_precedes_scope_finish {Value : Type} (pending : Bool) (message : String) :
    sourceScopeReturn (Value := Value) pending (.error message) = .error message := rfl

theorem field_scope_failure_rejects_completed_value {Value : Type} (value : Value) :
    sourceScopeReturn true (.ok value) =
      .error "smallwood SHA-512 field-XOF rejection budget exhausted" := rfl

end
end HegemonCrypto.SmallWood.V8Smz9SourceIndexSampler
