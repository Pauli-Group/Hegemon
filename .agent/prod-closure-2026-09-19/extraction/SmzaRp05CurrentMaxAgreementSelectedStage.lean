import SmzaRp05CurrentMaxAgreementRecovery
import SmzaRp04RawMcaSampling
import SmzaSelectedStageSearch

/-! Fixed-prefix selected-stage specialization for the current maximum-
agreement decoder. The matrix coefficients and response rule are fixed before
the q38 output. This bounds only the good-matrix query stage; the separate
current matrix role event charges the exceptional matrix mass. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentMaxAgreementSelectedStage

open HegemonCrypto.SmallWood
open HegemonCrypto.SmallWood.SmzaRp05CurrentMaxAgreementRecovery
open HegemonCrypto.SmallWood.SmzaRp04RawMcaSampling
open HegemonCrypto.SmallWood.SmzaRp04RawRoleSampling
open HegemonCrypto.SmallWood.SmzaSelectedStageSearch
open HegemonCrypto.SmallWood.V8Smz9McaRecovery
open HegemonCrypto.SmallWood.SmzaRp05CurrentUniversalMatrixLoss
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge HegemonCrypto.CmsLifting
open HegemonCrypto.CmsFinitePhaseSystem
open HegemonCrypto.FiniteFieldSampling
open V8Smz9CoherentVectorMerkle
open V8Smz9RobustQueryMismatch
open V8Smz9CappedRawSampler V8Smz9RawCounterCompiler

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

attribute [local irreducible] querySampleFintype

abbrev CurrentPosition :=
  HegemonCrypto.SmallWood.SmzaRp05CurrentMaxAgreementRecovery.Position
abbrev CurrentQuery := QuerySample CurrentPosition 38
abbrev CurrentCoefficients :=
  HegemonCrypto.SmallWood.SmzaRp05CurrentMaxAgreementRecovery.Coefficients

noncomputable local instance currentQueryNonempty : Nonempty CurrentQuery := by
  classical
  let embedding : Fin 38 ↪ CurrentPosition :=
    { toFun := fun index => ⟨index.val, index.isLt.trans (by decide)⟩
      inj' := by
        intro left right equal
        apply Fin.ext
        exact congrArg (fun position : CurrentPosition => position.val) equal }
  exact ⟨⟨Finset.univ.map embedding, by simp⟩⟩

def currentGoodMatrixFailureQueries
    (data : Nat → CurrentPosition → Goldilocks)
    (masks : Fin 5 → CurrentPosition → Goldilocks)
    (response : ResponseRule) (coefficients : CurrentCoefficients) : Finset CurrentQuery :=
  by
    classical
    exact if currentMatrixBad data masks coefficients then ∅ else
      currentAcceptedExtractionFailureEvent data masks response coefficients

theorem current_good_matrix_failure_query_probability_le
    (data : Nat → CurrentPosition → Goldilocks)
    (masks : Fin 5 → CurrentPosition → Goldilocks)
    (response : ResponseRule) (coefficients : CurrentCoefficients)
    (notBad : ¬ currentMatrixBad data masks coefficients) :
    FiniteEvents.probability
      (currentGoodMatrixFailureQueries data masks response coefficients) ≤
      (Nat.choose (currentAgreementThreshold - 1) 38 : Rat) /
        Nat.choose (Fintype.card CurrentPosition) 38 := by
  have cardBound := current_good_matrix_failure_card_le
    data masks response coefficients notBad
  rw [currentGoodMatrixFailureQueries, if_neg notBad]
  unfold FiniteEvents.probability
  rw [query_sample_card (Position := CurrentPosition) 38]
  exact div_le_div_of_nonneg_right (by exact_mod_cast cardBound)
    (Nat.cast_nonneg _)

/-- Actual q38 capped-raw output density for the fixed good matrix and its
fixed pre-query response rule. Rejected field streams remain in the
denominator through `raw_field_then_partial_decoder_bad_le`. -/
theorem raw_current_good_matrix_decoder_failure_le
    (data : Nat → CurrentPosition → Goldilocks)
    (masks : Fin 5 → CurrentPosition → Goldilocks)
    (response : ResponseRule) (coefficients : CurrentCoefficients)
    (notBad : ¬ currentMatrixBad data masks coefficients) :
    outputEventProbability
      (fun raw : Fin (digestCallCap q38CandidateCount) → RawByteBlock =>
        ∃ query, rawDecsSampleOutput raw = some query ∧
          query ∈ currentGoodMatrixFailureQueries data masks response coefficients) ≤
      (Nat.choose (currentAgreementThreshold - 1) 38 : Rat) /
        Nat.choose (Fintype.card CurrentPosition) 38 := by
  let bad : Finset CurrentQuery :=
    currentGoodMatrixFailureQueries data masks response coefficients
  have fibers : ∀ left right : CurrentQuery,
      Fintype.card (SuccessfulFiber q38Decoder left) =
        Fintype.card (SuccessfulFiber q38Decoder right) :=
    fun left right => q38_decoder_fibers_equal left right
  have sampled := raw_field_then_partial_decoder_bad_le
    (digestCallCap q38CandidateCount) q38CandidateCount q38Decoder fibers bad
  calc
    _ ≤ FiniteEvents.probability bad := by
      simpa only [rawDecsSampleOutput, bad] using sampled
    _ ≤ (Nat.choose (currentAgreementThreshold - 1) 38 : Rat) /
        Nat.choose (Fintype.card CurrentPosition) 38 := by
      exact current_good_matrix_failure_query_probability_le
        data masks response coefficients notBad

/-- Restrict the same accepted-failure predicate to the concrete selected
50-candidate route in a full Counter-vector output. This is the per-input
density shape consumed by the CMS selected-stage search lemma. -/
theorem actual_current_good_matrix_decoder_failure_le
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap q38CandidateCount) ↪ Counter)
    (data : Nat → CurrentPosition → Goldilocks)
    (masks : Fin 5 → CurrentPosition → Goldilocks)
    (response : ResponseRule) (coefficients : CurrentCoefficients)
    (notBad : ¬ currentMatrixBad data masks coefficients) :
    outputEventProbability
      (fun vector : VectorOutput Counter =>
        ∃ query, actualDecsSampleOutput select vector = some query ∧
          query ∈ currentGoodMatrixFailureQueries data masks response coefficients) ≤
      (Nat.choose (currentAgreementThreshold - 1) 38 : Rat) /
        Nat.choose (Fintype.card CurrentPosition) 38 := by
  change outputEventProbability
      (fun vector : VectorOutput Counter =>
        (fun raw : Fin (digestCallCap q38CandidateCount) → RawByteBlock =>
          ∃ query, rawDecsSampleOutput raw = some query ∧
            query ∈ currentGoodMatrixFailureQueries data masks response coefficients)
          (selectedRawBlocks select vector)) ≤ _
  rw [selected_raw_blocks_event_probability select
    (fun raw => ∃ query, rawDecsSampleOutput raw = some query ∧
      query ∈ currentGoodMatrixFailureQueries data masks response coefficients)]
  exact raw_current_good_matrix_decoder_failure_le
    data masks response coefficients notBad

/-- Direct input-indexed density specialization for `selected_stage_oracle_search`.
Each key's fixed pre-query label supplies its current table and response rule,
and the matrix output is known to be outside the response-universal bad event.
No uniformity of a raw field decoder is assumed; the capped sampler lemma
above supplies the exact successful-output bound. -/
theorem current_decoder_bad_selected_stage_search
    {Input Phase Workspace Counter : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    [Fintype Counter] [DecidableEq Counter]
    (system : CompletePhaseSystem (VectorOutput Counter) Phase)
    (select : Input → Fin (digestCallCap q38CandidateCount) ↪ Counter)
    (data : Input → Nat → CurrentPosition → Goldilocks)
    (masks : Input → Fin 5 → CurrentPosition → Goldilocks)
    (response : Input → ResponseRule)
    (coefficients : Input → CurrentCoefficients)
    (goodMatrix : ∀ input, ¬ currentMatrixBad
      (data input) (masks input) (coefficients input))
    (steps : List (DatabaseIndependentContraction
      (Input := Input) (Output := VectorOutput Counter)
      (Phase := Phase) (Workspace := Workspace)))
    (registers : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (selected : Workspace → Input × VectorOutput Counter) :
    normSquared (workspaceEventProjection
      (selectedClaimEvent
        (fun input vector => ∃ query,
          actualDecsSampleOutput (select input) vector = some query ∧
            query ∈ currentGoodMatrixFailureQueries
              (data input) (masks input) (response input) (coefficients input))
        selected)
      (totalOracleFamilyState (oracleFamilyRun system.system steps (fun _ => registers)))) ≤
      oracleLoss (databaseLoss steps.length
        (((Nat.choose (currentAgreementThreshold - 1) 38 : Rat) /
          Nat.choose (Fintype.card CurrentPosition) 38 : Rat) : ℝ))
        (1 / (Fintype.card (VectorOutput Counter) : ℝ)) := by
  let smallLoss : Rat :=
    (Nat.choose (currentAgreementThreshold - 1) 38 : Rat) /
      Nat.choose (Fintype.card CurrentPosition) 38
  have perInput : ∀ input, outputEventProbability
      (fun vector : VectorOutput Counter => ∃ query,
        actualDecsSampleOutput (select input) vector = some query ∧
          query ∈ currentGoodMatrixFailureQueries
            (data input) (masks input) (response input) (coefficients input)) ≤ smallLoss := by
    intro input
    simpa only [smallLoss] using actual_current_good_matrix_decoder_failure_le
      (select input) (data input) (masks input) (response input) (coefficients input)
      (goodMatrix input)
  exact selected_stage_oracle_search system _ smallLoss
    (by dsimp [smallLoss]; positivity) perInput steps registers normalized selected

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentMaxAgreementSelectedStage
