import SmzaRp04RestoredTranscriptChecks

/-! The extractor is the existing pre-query MCA decoder followed by the exact
q38 row-to-witness map. Failure is derived from concrete decoder/algebra events;
neither successful decoding nor agreement with the oracle is a hypothesis of
the failure decomposition. Probability statements retain their actual uniform
matrix/query experiment and do not assert quantum sampling equivalence. -/
namespace HegemonCrypto.SmallWood.SmzaRp04CalculatedExtraction

open Polynomial SmzaQ38Recovery SmzaRp04ActualProgram SmzaQ38McaSourceBinding
open SmzaRp04RestoredTranscriptChecks
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open SmzaRp04PublicContext V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9ZeroKnowledge
open Hegemon.Transaction.Poseidon2V8RelationProgram
noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

private theorem combine_probability_bounds (a b c d : Rat)
    (first : a ≤ b + c) (second : b ≤ d) : a ≤ d + c := by
  exact first.trans (by simpa only [add_comm] using (_root_.add_le_add_right second c))

/-- All supplied fields are the actual claimed transcript scalars/polynomials. -/
structure Transcript (publicWords : List Nat) where
  matrix : Matrix (batchingWidth publicWords)
  response : ClaimedTranscript
  opening : Opening
  witness : WitnessOpeningView Goldilocks
  masks : MaskOpeningValues Goldilocks
  partials : SourcePcsView Goldilocks
  nonlinearHigh : Fin 5 → Goldilocks[X]
  linearHigh : Fin 5 → Goldilocks[X]
  correction : Fin 5 → Goldilocks
  claimed : SmzaQ38LvcsOpening.ClaimedPolynomials

def transcriptBound {publicWords : List Nat} (t : Transcript publicWords)
    (rows : RecoveredRows) : Prop :=
  SameRestoredTranscript publicWords rows t.matrix t.response t.opening t.witness t.masks
    t.nonlinearHigh t.linearHigh t.correction

def algebraBad {publicWords : List Nat} (t : Transcript publicWords)
    (query : Query) (rows : RecoveredRows) : Prop :=
  ¬ SmzaQ38LvcsOpening.DiscrepanciesDetected rows
      (baseOpeningPoints t.opening.1) t.claimed query ∨
  ¬ SmzaPiopGoodOutcome.DiscrepanciesDetected
      (recoveredCandidate publicWords rows) t.matrix t.response t.opening ∨
  ¬ SmzaPiopGoodOutcome.ResidualsDetected (recoveredCandidate publicWords rows) t.matrix

def extract (oracle : SmzaQ38OracleExtraction.CommittedOracle)
    (response : ResponseStrategy) (coefficients : Coefficients) : Option (List Nat) :=
  (recoverSource oracle response coefficients).map (fun source => packedFromRows source.data)

def extractionFailure (publicWords : List Nat) (oracle : SmzaQ38OracleExtraction.CommittedOracle)
    (response : ResponseStrategy) (coefficients : Coefficients) : Prop :=
  ¬ ∃ packed, extract oracle response coefficients = some packed ∧
    SmzaRp04Components.program.AcceptsPacked publicWords packed

/-- An accepted, bound transcript which fails actual extraction must fall in
the concrete MCA decoder failure or a named LVCS/PIOP algebraic event. -/
theorem accepted_extraction_failure_implies_named_bad_event
    (publicWords : List Nat) (canonical : CanonicalPublicWords publicWords)
    (oracle : SmzaQ38OracleExtraction.CommittedOracle)
    (response : ResponseStrategy) (coefficients : Coefficients) (query : Query)
    (t : Transcript publicWords)
    (accepted : QueryAccepts oracle response coefficients query)
    (headBinding : SmzaQ38OpeningFieldReadback.ClaimedHeadsReconstructed
      (baseOpeningPoints t.opening.1) t.claimed t.witness t.masks t.partials)
    (checked : SmzaQ38LvcsOpening.OracleOpeningChecks oracle
      (baseOpeningPoints t.opening.1) t.claimed query)
    (bound : ∀ source, recoverSource oracle response coefficients = some source →
      transcriptBound t source.data)
    (failed : extractionFailure publicWords oracle response coefficients) :
    DecoderFailure oracle response coefficients query ∨
      ∃ source, recoverSource oracle response coefficients = some source ∧
        algebraBad t query source.data := by
  classical
  cases recovered : recoverSource oracle response coefficients with
  | none => exact Or.inl ⟨accepted, recovered⟩
  | some source =>
    by_cases bad : algebraBad t query source.data
    · exact Or.inr ⟨source, rfl, bad⟩
    · have good :
          SmzaQ38LvcsOpening.DiscrepanciesDetected source.data
            (baseOpeningPoints t.opening.1) t.claimed query ∧
          SmzaPiopGoodOutcome.DiscrepanciesDetected
            (recoveredCandidate publicWords source.data) t.matrix t.response t.opening ∧
          SmzaPiopGoodOutcome.ResidualsDetected
            (recoveredCandidate publicWords source.data) t.matrix := by
        simpa only [algebraBad, not_or, not_not] using bad
      exfalso
      apply failed
      refine ⟨packedFromRows source.data, ?_, ?_⟩
      · simp only [extract, recovered, Option.map_some]
      · exact accepted_restored_oracle_outside_algebraic_events_supply_actual_program
          publicWords source.data canonical t.matrix t.response t.opening t.witness t.masks
          t.partials t.nonlinearHigh t.linearHigh t.correction (bound source recovered)
          oracle t.claimed query headBinding
          (recovered_rows_match_every_accepted_query oracle response coefficients source recovered
            query accepted) checked good.1 good.2.1 good.2.2

/-- This budget is an explicit combinatorial expression, not a stipulated
failure probability; replacing it by a useful numerical bound requires the
literal middle-support counting result. -/
def decoderBudget : Rat :=
  (Nat.choose (58288 - 1) 38 : Rat) /
      Nat.choose (Fintype.card (Fin SmzaQ38OracleExtraction.decsDomainSize)) 38 +
    (((140 : Nat) : Rat) * (V8Smz9McaRecovery.universalLineBudget (Row := Fin 5)
      SmzaQ38OracleExtraction.smz9EvaluationPoint 405 58288 38 : Rat)) /
      ((Fintype.card (Fin 5 → Goldilocks) : Rat) *
        Nat.choose (Fintype.card (Fin SmzaQ38OracleExtraction.decsDomainSize)) 38)

theorem actual_q38_decoder_failure_probability_le
    (oracle : SmzaQ38OracleExtraction.CommittedOracle) (response : ResponseStrategy) :
    V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
      (V8Smz9McaDecoder.decoderFailureEvent SmzaQ38OracleExtraction.smz9EvaluationPoint
        405 38 (oracleData oracle) (oracleMasks oracle) response) ≤ decoderBudget := by
  exact V8Smz9McaDecoder.decoder_failure_probability_le
      SmzaQ38OracleExtraction.smz9EvaluationPoint
      SmzaQ38OracleExtraction.smz9_evaluation_point_injective
      405 58288 38 (by decide) (by simp only [Fintype.card_fin]; decide)
      (oracleData oracle) (oracleMasks oracle) response

attribute [local irreducible] decoderBudget
  V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability

def acceptedFailureEvents (publicWords : List Nat)
    (oracle : SmzaQ38OracleExtraction.CommittedOracle) (response : ResponseStrategy)
    (transcript : Coefficients → Query → Transcript publicWords)
    (coefficients : Coefficients) : Finset Query := by
  classical
  exact Finset.univ.filter fun query => QueryAccepts oracle response coefficients query ∧
    (let t := transcript coefficients query
     SmzaQ38OpeningFieldReadback.ClaimedHeadsReconstructed
       (baseOpeningPoints t.opening.1) t.claimed t.witness t.masks t.partials ∧
     SmzaQ38LvcsOpening.OracleOpeningChecks oracle
       (baseOpeningPoints t.opening.1) t.claimed query ∧
     (∀ source, recoverSource oracle response coefficients = some source →
       transcriptBound t source.data)) ∧
    extractionFailure publicWords oracle response coefficients

def algebraEvents {publicWords : List Nat}
    (oracle : SmzaQ38OracleExtraction.CommittedOracle) (response : ResponseStrategy)
    (transcript : Coefficients → Query → Transcript publicWords)
    (coefficients : Coefficients) : Finset Query := by
  classical
  exact Finset.univ.filter fun query => ∃ source,
    recoverSource oracle response coefficients = some source ∧
      algebraBad (transcript coefficients query) query source.data

/-- Actual failed-extraction probability in the uniform MCA matrix/query
experiment. The remaining term is the probability of the explicitly calculated
LVCS/PIOP bad events, not an assumed failed-extraction bound. Adaptive quantum
readout/sampling identification and numerical algebra-event bounds are separate. -/
theorem accepted_extraction_probability_le_decoder_plus_algebra
    (publicWords : List Nat) (canonical : CanonicalPublicWords publicWords)
    (oracle : SmzaQ38OracleExtraction.CommittedOracle) (response : ResponseStrategy)
    (transcript : Coefficients → Query → Transcript publicWords) :
    V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
        (acceptedFailureEvents publicWords oracle response transcript) ≤
      decoderBudget + V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
        (algebraEvents oracle response transcript) := by
  classical
  let decs := V8Smz9McaDecoder.decoderFailureEvent
    SmzaQ38OracleExtraction.smz9EvaluationPoint 405 38
      (oracleData oracle) (oracleMasks oracle) response
  have subset (coefficients : Coefficients) :
      acceptedFailureEvents publicWords oracle response transcript coefficients ⊆
        decs coefficients ∪ algebraEvents oracle response transcript coefficients := by
    intro query member
    obtain ⟨accepted, ⟨headBinding, checked, bound⟩, failed⟩ := (Finset.mem_filter.mp member).2
    rcases accepted_extraction_failure_implies_named_bad_event publicWords canonical oracle
      response coefficients query (transcript coefficients query) accepted
      headBinding checked bound
      failed with decoder | algebra
    · apply Finset.mem_union_left
      apply Finset.mem_filter.mpr
      exact ⟨Finset.mem_univ _,
        (query_accepts_iff_prequery_agreement oracle response coefficients query).mp decoder.1,
        decoder.2⟩
    · exact Finset.mem_union_right _ (Finset.mem_filter.mpr ⟨Finset.mem_univ _, algebra⟩)
  have pointwise (coefficients : Coefficients) :
      V8Smz9RobustQueryMismatch.FiniteEvents.probability
          (acceptedFailureEvents publicWords oracle response transcript coefficients) ≤
        V8Smz9RobustQueryMismatch.FiniteEvents.probability (decs coefficients) +
        V8Smz9RobustQueryMismatch.FiniteEvents.probability
          (algebraEvents oracle response transcript coefficients) := by
    unfold V8Smz9RobustQueryMismatch.FiniteEvents.probability
    rw [← add_div]
    apply div_le_div_of_nonneg_right _ (Nat.cast_nonneg _)
    exact_mod_cast (Finset.card_le_card (subset coefficients)).trans (Finset.card_union_le _ _)
  have unionBound :
      V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
          (acceptedFailureEvents publicWords oracle response transcript) ≤
        V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability decs +
        V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
          (algebraEvents oracle response transcript) := by
    simp only [V8Smz9RobustQueryMismatch.FiniteEvents.joint_probability_eq_average]
    rw [← add_div, ← Finset.sum_add_distrib]
    apply div_le_div_of_nonneg_right _ (Nat.cast_nonneg _)
    exact Finset.sum_le_sum fun coefficients _ => pointwise coefficients
  have decoderBound : V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability decs ≤
      decoderBudget := actual_q38_decoder_failure_probability_le oracle response
  exact combine_probability_bounds
    (V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
      (acceptedFailureEvents publicWords oracle response transcript))
    (V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability decs)
    (V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
      (algebraEvents oracle response transcript))
    decoderBudget unionBound decoderBound

end
end HegemonCrypto.SmallWood.SmzaRp04CalculatedExtraction
