import SmzaRp04RawRoleSamplingQ38
import SmzaRp04RoleBadCells

/-!
# Actual RP04 raw-role sampling

This facade packages exact restriction from a complete vector output and the
three per-role bad-and-success bounds.  The raw decoder and its finite-fiber
accounting live in `SmzaRp04RawRoleSamplingCore`; sampler failure remains in
the original denominator throughout.
-/

namespace HegemonCrypto.SmallWood.SmzaRp04RawRoleSampling

open HegemonCrypto.CmsClassicalDatabase
open V8Smz9RuntimeDistribution V8Smz9RuntimeRandomness
open V8Smz9RuntimeFieldLayout V8Smz9RawCounterCompiler
open V8Smz9CappedRawSampler V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle V8Smz9HiddenLeafQrom
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open V8Smz9AdaptiveFiniteAccounting.Historical
open V8Smz9AdmissibleRootProbability
open SmzaRp04ChronologicalAlgebra
open SmzaQ38OracleExtraction SmzaQ38McaSourceBinding
open SmzaRp04RoleBadCells
open SmzaRp04PublicContext
open scoped BigOperators Classical

noncomputable section

set_option maxHeartbeats 1500000
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024
set_option Elab.async false

attribute [local irreducible]
  V8Smz9McaRecovery.querySampleFintype
  V8Smz9AdaptiveFiniteAccounting.instFintypeFullAdmissibleOpeningTuple

noncomputable local instance facadeOpeningNonempty : Nonempty Opening :=
  Fintype.card_pos_iff.mp full_admissible_opening_tuple_card_positive

noncomputable local instance facadeQueryNonempty : Nonempty Query := by
  let embedding : Fin 38 ↪ SmzaQ38McaSourceBinding.Position :=
    { toFun := fun index => ⟨index.val, index.isLt.trans (by decide)⟩
      inj' := by
        intro left right equal
        apply Fin.ext
        exact congrArg
          (fun position : SmzaQ38McaSourceBinding.Position => position.val) equal }
  exact ⟨⟨Finset.univ.map embedding, by simp⟩⟩

/-! ## Exact restriction from a complete vector output -/

abbrev SelectionComplement {Raw Full : Type*} (select : Raw → Full) :=
  { input : Full // input ∉ Set.range select }

def selectionFactorization {Raw Full OutputType : Type*}
    (select : Raw → Full) (injective : Function.Injective select) :
    (Full → OutputType) ≃
      (Raw → OutputType) × (SelectionComplement select → OutputType) :=
  (Equiv.arrowCongr
      ((Equiv.sumCongr (Equiv.ofInjective select injective) (Equiv.refl _)).trans
        (Equiv.Set.sumCompl (Set.range select)))
      (Equiv.refl OutputType)).symm.trans
    (Equiv.sumArrowEquivProdArrow Raw (SelectionComplement select) OutputType)

@[simp] theorem selection_factorization_selected
    {Raw Full OutputType : Type*} (select : Raw → Full)
    (injective : Function.Injective select) (table : Full → OutputType)
    (input : Raw) :
    (selectionFactorization select injective table).1 input = table (select input) := rfl

theorem output_event_probability_equiv
    {Input OutputType : Type*} [Fintype Input] [Fintype OutputType]
    [DecidableEq Input] [DecidableEq OutputType]
    (equivalence : Input ≃ OutputType) (event : OutputType → Prop) :
    outputEventProbability (fun input => event (equivalence input)) =
      outputEventProbability event := by
  classical
  let eventSet := Finset.univ.filter event
  have count := V8Smz9CoherentVectorMerkle.equiv_event_card equivalence eventSet
  have denominator := Fintype.card_congr equivalence
  unfold outputEventProbability
  rw [show (Finset.univ.filter fun input : Input => event (equivalence input)).card =
      eventSet.card by simpa [eventSet] using count]
  rw [denominator]

theorem output_event_probability_fst
    {Left Right : Type*} [Fintype Left] [Fintype Right]
    [Nonempty Left] [Nonempty Right] [DecidableEq Left] [DecidableEq Right]
    (event : Left → Prop) :
    outputEventProbability (fun pair : Left × Right => event pair.1) =
      outputEventProbability event := by
  classical
  have filtered := Finset.filter_product_left
    (s := (Finset.univ : Finset Left))
    (t := (Finset.univ : Finset Right)) event
  have count := congrArg Finset.card filtered
  have count' :
      ((Finset.univ : Finset (Left × Right)).filter
          (fun pair => event pair.1)).card =
        (Finset.univ.filter event).card * Fintype.card Right := by
    simpa [Finset.univ_product_univ, Finset.card_product] using count
  unfold outputEventProbability
  rw [count', Fintype.card_prod, Nat.cast_mul, Nat.cast_mul]
  have rightNonzero : (Fintype.card Right : Rat) ≠ 0 := by
    exact_mod_cast Fintype.card_ne_zero
  exact mul_div_mul_right _ _ rightNonzero

theorem selection_output_event_probability
    {Raw Full OutputType : Type*}
    [Fintype Raw] [Fintype Full] [Fintype OutputType]
    [Nonempty OutputType] [DecidableEq Raw] [DecidableEq Full]
    [DecidableEq OutputType]
    (select : Raw ↪ Full) (event : (Raw → OutputType) → Prop) :
    outputEventProbability
        (fun table : Full → OutputType =>
          event (fun input => table (select input))) =
      outputEventProbability event := by
  let factor : (Full → OutputType) ≃
      (Raw → OutputType) × (SelectionComplement select → OutputType) :=
    selectionFactorization (select : Raw → Full) select.injective
  calc
    outputEventProbability
        (fun table : Full → OutputType =>
          event (fun input => table (select input))) =
        outputEventProbability (fun table => event (factor table).1) := by
      apply congrArg outputEventProbability
      funext table
      apply propext
      rfl
    _ = outputEventProbability
        (fun pair : (Raw → OutputType) ×
          (SelectionComplement select → OutputType) => event pair.1) :=
      output_event_probability_equiv factor (fun pair => event pair.1)
    _ = outputEventProbability event := output_event_probability_fst event

theorem selected_raw_blocks_event_probability
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    {blocks : Nat} (select : Fin blocks ↪ Counter)
    (event : (Fin blocks → RawByteBlock) → Prop) :
    outputEventProbability
        (fun vector : VectorOutput Counter => event (selectedRawBlocks select vector)) =
      outputEventProbability event := by
  calc
    _ = outputEventProbability
        (fun digests : Fin blocks → DigestRegister =>
          event (digestBlocksEquiv blocks digests)) :=
      selection_output_event_probability select
        (fun digests => event (digestBlocksEquiv blocks digests))
    _ = outputEventProbability event :=
      output_event_probability_equiv (digestBlocksEquiv blocks) event

/-! ## Per-role actual bad-and-success bounds -/

def rawPiopMatrixOutput (width : Nat)
    (raw : Fin (digestCallCap (5 * width)) → RawByteBlock) :
    Option (Matrix width) :=
  (rawFieldSample (digestCallCap (5 * width)) (5 * width) raw).bind
    (totalEquivDecoder (matrixFieldEquiv width))

def rawPiopOpeningOutput
    (raw : Fin (digestCallCap piopOpenings) → RawByteBlock) :
    Option Opening :=
  (rawFieldSample (digestCallCap piopOpenings) piopOpenings raw).bind
    openingDecoder

def rawDecsSampleOutput
    (raw : Fin (digestCallCap q38CandidateCount) → RawByteBlock) :
    Option Query :=
  (rawFieldSample (digestCallCap q38CandidateCount) q38CandidateCount raw).bind
    q38Decoder

theorem raw_piop_matrix_bad_and_success_le {publicWords : List Nat}
    (label : PiopMatrixLabel publicWords) :
    outputEventProbability
        (fun raw : Fin (digestCallCap (5 * batchingWidth publicWords)) → RawByteBlock =>
          ∃ output, rawPiopMatrixOutput (batchingWidth publicWords) raw = some output ∧
            piopMatrixCellBad label output) ≤
      roleLoss .piopMatrix := by
  let bad := piopMatrixBadEvent label.candidate
  have sampled := raw_field_then_partial_decoder_bad_le
    (digestCallCap (5 * batchingWidth publicWords))
    (5 * batchingWidth publicWords)
    (totalEquivDecoder (matrixFieldEquiv (batchingWidth publicWords)))
    (total_equiv_decoder_fibers_equal (matrixFieldEquiv (batchingWidth publicWords)))
    bad
  calc
    _ ≤ V8Smz9RobustQueryMismatch.FiniteEvents.probability bad := by
      simpa only [rawPiopMatrixOutput, piopMatrixCellBad, bad] using sampled
    _ = outputEventProbability (piopMatrixCellBad label) := by
      change V8Smz9RobustQueryMismatch.FiniteEvents.probability bad =
        outputEventProbability (fun output => output ∈ bad)
      exact (output_event_probability_membership bad).symm
    _ ≤ roleLoss .piopMatrix := piop_matrix_cell_density label

theorem raw_piop_opening_bad_and_success_le {publicWords : List Nat}
    (label : PiopOpeningLabel publicWords) :
    outputEventProbability
        (fun raw : Fin (digestCallCap piopOpenings) → RawByteBlock =>
          ∃ output, rawPiopOpeningOutput raw = some output ∧
            piopOpeningCellBad label output) ≤
      roleLoss .piopOpening := by
  let bad := piopOpeningBadEvent label.candidate label.matrix label.response
  have sampled := raw_field_then_partial_decoder_bad_le
    (digestCallCap piopOpenings) piopOpenings openingDecoder
    opening_decoder_fibers_equal bad
  calc
    _ ≤ V8Smz9RobustQueryMismatch.FiniteEvents.probability bad := by
      simpa only [rawPiopOpeningOutput, piopOpeningCellBad, bad] using sampled
    _ = outputEventProbability (piopOpeningCellBad label) := by
      change V8Smz9RobustQueryMismatch.FiniteEvents.probability bad =
        outputEventProbability (fun output => output ∈ bad)
      exact (output_event_probability_membership bad).symm
    _ ≤ roleLoss .piopOpening := piop_opening_cell_density label

theorem raw_decs_sample_bad_and_success_le (label : DecsSampleLabel) :
    outputEventProbability
        (fun raw : Fin (digestCallCap q38CandidateCount) → RawByteBlock =>
          ∃ output, rawDecsSampleOutput raw = some output ∧
            decsSampleCellBad label output) ≤
      roleLoss .decsSample := by
  let bad := lvcsBadQueryEvent label.rows label.points
    (claimedPolynomials label.claimedCoefficients)
  have sampled := raw_field_then_partial_decoder_bad_le
    (digestCallCap q38CandidateCount) q38CandidateCount q38Decoder
    (fun left right => q38_decoder_fibers_equal left right) bad
  calc
    _ ≤ V8Smz9RobustQueryMismatch.FiniteEvents.probability bad := by
      simpa only [rawDecsSampleOutput, decsSampleCellBad, bad] using sampled
    _ = outputEventProbability (decsSampleCellBad label) := by
      change V8Smz9RobustQueryMismatch.FiniteEvents.probability bad =
        outputEventProbability (fun output => output ∈ bad)
      exact (output_event_probability_membership bad).symm
    _ ≤ roleLoss .decsSample := decs_sample_cell_density label

def actualPiopMatrixOutput {Counter : Type*} {width : Nat}
    (select : Fin (digestCallCap (5 * width)) ↪ Counter)
    (vector : VectorOutput Counter) : Option (Matrix width) :=
  rawPiopMatrixOutput width (selectedRawBlocks select vector)

def actualPiopOpeningOutput {Counter : Type*}
    (select : Fin (digestCallCap piopOpenings) ↪ Counter)
    (vector : VectorOutput Counter) : Option Opening :=
  rawPiopOpeningOutput (selectedRawBlocks select vector)

def actualDecsSampleOutput {Counter : Type*}
    (select : Fin (digestCallCap q38CandidateCount) ↪ Counter)
    (vector : VectorOutput Counter) : Option Query :=
  rawDecsSampleOutput (selectedRawBlocks select vector)

theorem actual_piop_matrix_bad_and_success_le
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    {publicWords : List Nat}
    (select : Fin (digestCallCap (5 * batchingWidth publicWords)) ↪ Counter)
    (label : PiopMatrixLabel publicWords) :
    outputEventProbability (fun vector : VectorOutput Counter =>
        ∃ output, actualPiopMatrixOutput select vector = some output ∧
          piopMatrixCellBad label output) ≤
      roleLoss .piopMatrix := by
  change outputEventProbability
      (fun vector : VectorOutput Counter =>
        (fun raw : Fin (digestCallCap (5 * batchingWidth publicWords)) →
            RawByteBlock =>
          ∃ output, rawPiopMatrixOutput (batchingWidth publicWords) raw =
            some output ∧ piopMatrixCellBad label output)
          (selectedRawBlocks select vector)) ≤ _
  rw [selected_raw_blocks_event_probability select
    (fun raw => ∃ output,
      rawPiopMatrixOutput (batchingWidth publicWords) raw = some output ∧
        piopMatrixCellBad label output)]
  exact raw_piop_matrix_bad_and_success_le label

theorem actual_piop_opening_bad_and_success_le
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    {publicWords : List Nat}
    (select : Fin (digestCallCap piopOpenings) ↪ Counter)
    (label : PiopOpeningLabel publicWords) :
    outputEventProbability (fun vector : VectorOutput Counter =>
        ∃ output, actualPiopOpeningOutput select vector = some output ∧
          piopOpeningCellBad label output) ≤
      roleLoss .piopOpening := by
  change outputEventProbability
      (fun vector : VectorOutput Counter =>
        (fun raw : Fin (digestCallCap piopOpenings) → RawByteBlock =>
          ∃ output, rawPiopOpeningOutput raw = some output ∧
            piopOpeningCellBad label output)
          (selectedRawBlocks select vector)) ≤ _
  rw [selected_raw_blocks_event_probability select
    (fun raw => ∃ output, rawPiopOpeningOutput raw = some output ∧
      piopOpeningCellBad label output)]
  exact raw_piop_opening_bad_and_success_le label

theorem actual_decs_sample_bad_and_success_le
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap q38CandidateCount) ↪ Counter)
    (label : DecsSampleLabel) :
    outputEventProbability (fun vector : VectorOutput Counter =>
        ∃ output, actualDecsSampleOutput select vector = some output ∧
          decsSampleCellBad label output) ≤
      roleLoss .decsSample := by
  change outputEventProbability
      (fun vector : VectorOutput Counter =>
        (fun raw : Fin (digestCallCap q38CandidateCount) → RawByteBlock =>
          ∃ output, rawDecsSampleOutput raw = some output ∧
            decsSampleCellBad label output)
          (selectedRawBlocks select vector)) ≤ _
  rw [selected_raw_blocks_event_probability select
    (fun raw => ∃ output, rawDecsSampleOutput raw = some output ∧
      decsSampleCellBad label output)]
  exact raw_decs_sample_bad_and_success_le label

/-- A proof-free chronological matrix key has the same raw bound. The old
conditional theorem is used only after the guard is proved; if the guard is
false the guarded event is empty. -/
theorem actual_piop_matrix_prefix_bad_and_success_le
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    {publicWords : List Nat}
    (select : Fin (digestCallCap (5 * batchingWidth publicWords)) ↪ Counter)
    (key : PiopMatrixPrefixKey publicWords) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ output, actualPiopMatrixOutput select vector = some output ∧
        piopMatrixPrefixBad key output) ≤ roleLoss .piopMatrix := by
  by_cases invalid : ¬ PiopExtraction.FullySatisfied key.candidate.system
  · let label : PiopMatrixLabel publicWords := ⟨key.candidate, invalid⟩
    have sameEvent :
        (fun vector : VectorOutput Counter =>
          ∃ output, actualPiopMatrixOutput select vector = some output ∧
            piopMatrixPrefixBad key output) =
        (fun vector : VectorOutput Counter =>
          ∃ output, actualPiopMatrixOutput select vector = some output ∧
            piopMatrixCellBad label output) := by
      funext vector
      simp [piopMatrixPrefixBad, invalid, piopMatrixCellBad, label]
    rw [sameEvent]
    exact actual_piop_matrix_bad_and_success_le select label
  · have emptyEvent :
        (fun vector : VectorOutput Counter =>
          ∃ output, actualPiopMatrixOutput select vector = some output ∧
            piopMatrixPrefixBad key output) = (fun _ => False) := by
      funext vector
      simp [piopMatrixPrefixBad, invalid]
    rw [emptyEvent]
    have nonnegative : 0 ≤ roleLoss .piopMatrix := by
      unfold roleLoss
      positivity
    simpa [outputEventProbability] using nonnegative

/-- The q38 raw sample is charged only for degree-bounded rows. This is the
same event as the historical proof-valued label whenever that label exists. -/
theorem actual_decs_sample_prefix_bad_and_success_le
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap q38CandidateCount) ↪ Counter)
    (key : DecsSamplePrefixKey) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ output, actualDecsSampleOutput select vector = some output ∧
        decsSamplePrefixBad key output) ≤ roleLoss .decsSample := by
  by_cases rowsDegree : ∀ row, (key.rows row).natDegree ≤ 405
  · let label : DecsSampleLabel :=
      ⟨key.rows, rowsDegree, key.points, key.claimedCoefficients⟩
    have sameEvent :
        (fun vector : VectorOutput Counter =>
          ∃ output, actualDecsSampleOutput select vector = some output ∧
            decsSamplePrefixBad key output) =
        (fun vector : VectorOutput Counter =>
          ∃ output, actualDecsSampleOutput select vector = some output ∧
            decsSampleCellBad label output) := by
      funext vector
      simp [decsSamplePrefixBad, rowsDegree, decsSampleCellBad, label]
    rw [sameEvent]
    exact actual_decs_sample_bad_and_success_le select label
  · have emptyEvent :
        (fun vector : VectorOutput Counter =>
          ∃ output, actualDecsSampleOutput select vector = some output ∧
            decsSamplePrefixBad key output) = (fun _ => False) := by
      funext vector
      simp [decsSamplePrefixBad, rowsDegree]
    rw [emptyEvent]
    have nonnegative : 0 ≤ roleLoss .decsSample := by
      unfold roleLoss q38LvcsLoss q38SingleRootLoss
      positivity
    simpa [outputEventProbability] using nonnegative

/-- Counter coordinates used by the three output roles.  They may be placed
after an arbitrary fixed prefix; injectivity is the only independence fact
needed from the complete random-oracle vector. -/
structure RawRoutes (Counter : Type*) (publicWords : List Nat) where
  piopMatrix :
    Fin (digestCallCap (5 * batchingWidth publicWords)) ↪ Counter
  piopOpening : Fin (digestCallCap piopOpenings) ↪ Counter
  decsSample : Fin (digestCallCap q38CandidateCount) ↪ Counter

def rawOutput {Counter : Type*} {publicWords : List Nat}
    (routes : RawRoutes Counter publicWords) :
    (label : Label publicWords) → VectorOutput Counter → Option (Output label)
  | .piopMatrix _ => actualPiopMatrixOutput routes.piopMatrix
  | .piopOpening _ => actualPiopOpeningOutput routes.piopOpening
  | .decsSample _ => actualDecsSampleOutput routes.decsSample

def RawBad {Counter : Type*} {publicWords : List Nat}
    (routes : RawRoutes Counter publicWords) (label : Label publicWords)
    (vector : VectorOutput Counter) : Prop :=
  ∃ output, rawOutput routes label vector = some output ∧ IsBad label output

/-- Uniform per-fixed-prefix density in exactly the dependent form consumed by
the dynamic role database.  Failed raw parsing is outside `RawBad`. -/
theorem raw_bad_probability_le
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    {publicWords : List Nat} (routes : RawRoutes Counter publicWords)
    (label : Label publicWords) :
    outputEventProbability (RawBad routes label) ≤ roleLoss label.role := by
  cases label with
  | piopMatrix label =>
      change outputEventProbability (fun vector =>
        ∃ output, actualPiopMatrixOutput routes.piopMatrix vector =
          some output ∧ piopMatrixCellBad label output) ≤ _
      exact
        actual_piop_matrix_bad_and_success_le routes.piopMatrix label
  | piopOpening label =>
      change outputEventProbability (fun vector =>
        ∃ output, actualPiopOpeningOutput routes.piopOpening vector =
          some output ∧ piopOpeningCellBad label output) ≤ _
      exact
        actual_piop_opening_bad_and_success_le routes.piopOpening label
  | decsSample label =>
      change outputEventProbability (fun vector =>
        ∃ output, actualDecsSampleOutput routes.decsSample vector =
          some output ∧ decsSampleCellBad label output) ≤ _
      exact
        actual_decs_sample_bad_and_success_le routes.decsSample label

end
end HegemonCrypto.SmallWood.SmzaRp04RawRoleSampling
