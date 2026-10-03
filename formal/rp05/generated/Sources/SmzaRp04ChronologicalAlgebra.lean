import SmzaRp04CalculatedExtraction
import HegemonCrypto.UniformSubsetSampling

/-!
# Chronological RP04 algebraic bad events

This file repairs the quantifier order which an arbitrary
`Coefficients → Query → Transcript` does not express.  After the DECS
coefficient matrix has fixed the recovered source, the PIOP response may
depend on the PIOP matrix but not on its six opening points.  The remaining
opening messages (including the twelve LVCS polynomials) may depend on those
points but not on the final 38-position query.

The three local events below are therefore suitable for the corresponding
Fiat--Shamir roles.  Their bounds are proved from the existing affine-rank,
admissible-root, and q38 polynomial-root counts.  No probability transfer from
an actual random-oracle execution is asserted here.
-/

namespace HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra

open Polynomial SmzaQ38Recovery SmzaQ38OracleExtraction
open SmzaQ38McaSourceBinding SmzaRp04ActualProgram
open SmzaRp04CalculatedExtraction SmzaRp04RestoredTranscriptChecks
open SmzaRp04ScalarCheckTransport SmzaRp04PublicContext
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open V8Smz9RobustQueryMismatch V8Smz9McaRecovery
open V8Smz9AdmissibleRootProbability
open scoped BigOperators

noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

abbrev Combination := SmzaQ38LvcsOpening.Combination
abbrev Fixed406Coefficients := Combination → Fin 406 → Goldilocks

/-- A fixed 406-coefficient representation of a claimed polynomial. The
physical DECS transcript contains heads and tails, not these coefficients:
`SmzaRp04TracePrefixes` rotates and interpolates those values before extracting
this representation. No coefficient at degree 406 or higher can occur. -/
def claimedPolynomials (coefficients : Fixed406Coefficients) :
    SmzaQ38LvcsOpening.ClaimedPolynomials :=
  fun combination => V8Smz9EagerPrivacy.coefficientPolynomial (coefficients combination)

theorem claimed_polynomials_degree405 (coefficients : Fixed406Coefficients) :
    ∀ combination, ((claimedPolynomials coefficients) combination).natDegree ≤ 405 := by
  intro combination
  simpa only [claimedPolynomials, Nat.reduceSub] using
    V8Smz9EagerPrivacy.coefficient_polynomial_nat_degree_le
      (coefficients combination)

/-- Messages selected only after the six PIOP opening points are known.
The claimed polynomial is represented by 406 coefficients obtained from the
transmitted evaluations; this is not a witness-validity assumption. -/
structure OpeningMessage where
  witness : V8Smz9ZeroKnowledge.WitnessOpeningView Goldilocks
  masks : V8Smz9EagerSimulator.MaskOpeningValues Goldilocks
  partials : V8Smz9EagerPrivacy.SourcePcsView Goldilocks
  nonlinearHigh : Fin 5 → Goldilocks[X]
  linearHigh : Fin 5 → Goldilocks[X]
  correction : Fin 5 → Goldilocks
  claimedCoefficients : Fixed406Coefficients

def OpeningMessage.claimed (message : OpeningMessage) :
    SmzaQ38LvcsOpening.ClaimedPolynomials :=
  claimedPolynomials message.claimedCoefficients

theorem OpeningMessage.claimedDegree (message : OpeningMessage) :
    ∀ combination, (message.claimed combination).natDegree ≤ 405 :=
  claimed_polynomials_degree405 message.claimedCoefficients

/-- An arbitrary malicious prover strategy with the protocol's actual
commitment order.  Both functions may close over the oracle, the DECS response
strategy, and any earlier adversarial state. -/
structure Strategy (publicWords : List Nat) where
  piopResponse : Coefficients →
    Matrix (batchingWidth publicWords) → ClaimedTranscript
  afterOpening : Coefficients → Matrix (batchingWidth publicWords) →
    Opening → OpeningMessage

/-- Forget chronology only after all three challenge stages have been fixed. -/
def transcriptAt {publicWords : List Nat} (strategy : Strategy publicWords)
    (coefficients : Coefficients) (matrix : Matrix (batchingWidth publicWords))
    (opening : Opening) : Transcript publicWords :=
  let message := strategy.afterOpening coefficients matrix opening
  { matrix := matrix
    response := strategy.piopResponse coefficients matrix
    opening := opening
    witness := message.witness
    masks := message.masks
    partials := message.partials
    nonlinearHigh := message.nonlinearHigh
    linearHigh := message.linearHigh
    correction := message.correction
    claimed := message.claimed }

/-! ## Final q38 role -/

private theorem mem_sample_within_event_iff
    {Position : Type*} [Fintype Position]
    (support : Finset Position) (queryCount : Nat)
    (sample : QuerySample Position queryCount) :
    sample ∈ sampleWithinEvent support queryCount ↔ sample.val ⊆ support := by
  classical
  simp only [sampleWithinEvent, Finset.mem_filter, Finset.mem_univ, true_and]

/-- Queries hidden by one fixed, nonzero LVCS discrepancy. -/
def combinationBadQueries (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials) (combination : Combination) :
    Finset Query :=
  let polynomial := SmzaQ38LvcsOpening.discrepancy rows points claimed combination
  if polynomial = 0 then ∅
  else sampleWithinEvent (decsRootIndices polynomial) 38

/-- Union of the twelve fixed-polynomial q38 root events. -/
def lvcsBadQueryEvent (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials) : Finset Query :=
  Finset.univ.biUnion (combinationBadQueries rows points claimed)

def q38SingleRootLoss : Rat :=
  (Nat.choose 405 38 : Rat) /
    Nat.choose (Fintype.card SmzaQ38McaSourceBinding.Position) 38

def q38LvcsLoss : Rat := 12 * q38SingleRootLoss

theorem not_lvcs_detected_mem_bad_query_event
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials) (query : Query)
    (notDetected : ¬ SmzaQ38LvcsOpening.DiscrepanciesDetected rows points claimed query) :
    query ∈ lvcsBadQueryEvent rows points claimed := by
  classical
  unfold SmzaQ38LvcsOpening.DiscrepanciesDetected at notDetected
  push Not at notDetected
  obtain ⟨combination, nonzero, roots⟩ := notDetected
  unfold lvcsBadQueryEvent
  apply Finset.mem_biUnion.mpr
  refine ⟨combination, Finset.mem_univ _, ?_⟩
  simp only [combinationBadQueries, if_neg nonzero]
  apply (mem_sample_within_event_iff
    (Position := SmzaQ38McaSourceBinding.Position)
    (decsRootIndices (SmzaQ38LvcsOpening.discrepancy rows points claimed combination))
    38 query).2
  intro index membership
  exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, roots index membership⟩

theorem combination_bad_query_probability_le
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (rowsDegree : ∀ row, (rows row).natDegree ≤ 405)
    (claimedDegree : ∀ combination, (claimed combination).natDegree ≤ 405)
    (combination : Combination) :
    FiniteEvents.probability (combinationBadQueries rows points claimed combination) ≤
      q38SingleRootLoss := by
  classical
  let polynomial := SmzaQ38LvcsOpening.discrepancy rows points claimed combination
  by_cases zero : polynomial = 0
  · rw [show combinationBadQueries rows points claimed combination = ∅ by
        simp [combinationBadQueries, polynomial, zero], FiniteEvents.probability_empty]
    unfold q38SingleRootLoss
    positivity
  · have degree : polynomial.natDegree ≤ 405 :=
      SmzaQ38LvcsOpening.discrepancy_degree405 rows points claimed
        rowsDegree claimedDegree combination
    have rootCard : (decsRootIndices polynomial).card ≤ 405 :=
      (decs_root_indices_card_le zero).trans degree
    let support : Finset SmzaQ38McaSourceBinding.Position :=
      decsRootIndices polynomial
    have supportCard : support.card ≤ 405 := by
      change (decsRootIndices polynomial).card ≤ 405
      exact rootCard
    have denominatorPositive :
        (0 : Rat) < Nat.choose
          (Fintype.card SmzaQ38McaSourceBinding.Position) 38 := by
      exact_mod_cast Nat.choose_pos (by
        rw [Fintype.card_fin]
        decide)
    have discrepancyNonzero :
        SmzaQ38LvcsOpening.discrepancy rows points claimed combination ≠ 0 := by
      simpa only [polynomial] using zero
    have event : combinationBadQueries rows points claimed combination =
        sampleWithinEvent support 38 := by
      unfold combinationBadQueries
      rw [if_neg discrepancyNonzero]
      unfold support polynomial
      rfl
    have eventCard : (combinationBadQueries rows points claimed combination).card =
        Nat.choose support.card 38 := by
      rw [event]
      exact sample_within_event_card support 38
    have queryCard : Fintype.card Query =
        Nat.choose (Fintype.card SmzaQ38McaSourceBinding.Position) 38 :=
      query_sample_card (Position := SmzaQ38McaSourceBinding.Position) 38
    unfold FiniteEvents.probability q38SingleRootLoss
    rw [eventCard, queryCard]
    apply (div_le_div_iff_of_pos_right denominatorPositive).2
    exact_mod_cast Nat.choose_le_choose 38 supportCard

theorem lvcs_bad_query_probability_le
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (rowsDegree : ∀ row, (rows row).natDegree ≤ 405)
    (claimedDegree : ∀ combination, (claimed combination).natDegree ≤ 405) :
    FiniteEvents.probability (lvcsBadQueryEvent rows points claimed) ≤ q38LvcsLoss := by
  classical
  unfold lvcsBadQueryEvent
  calc
    FiniteEvents.probability
        (Finset.univ.biUnion (combinationBadQueries rows points claimed)) ≤
        (Finset.univ : Finset Combination).card * q38SingleRootLoss :=
      FiniteEvents.union_probability_le Finset.univ
        (combinationBadQueries rows points claimed) q38SingleRootLoss
        (fun combination _ => combination_bad_query_probability_le
          rows points claimed rowsDegree claimedDegree combination)
    _ = q38LvcsLoss := by
      norm_num [q38LvcsLoss]

/-! ## PIOP matrix and opening roles -/

/-- The bad PIOP-matrix outputs are exactly the affine batching matrices that
hide an invalid candidate. -/
def piopMatrixBadEvent {width : Nat} (candidate : Candidate width) :
    Finset (Matrix width) :=
  PiopExtraction.affineBatchFailureSet candidate.system (maskSum candidate)

theorem piop_matrix_bad_probability_le {width : Nat} (candidate : Candidate width)
    (invalid : ¬ PiopExtraction.FullySatisfied candidate.system) :
    FiniteEvents.probability (piopMatrixBadEvent candidate) ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ 5 := by
  change PiopExtraction.affineBatchFailureProbability candidate.system
    (maskSum candidate) ≤ _
  exact PiopExtraction.unsatisfied_affine_batch_failure_probability_le
    candidate.system (maskSum candidate) invalid

/-- Once a non-affine matrix is fixed, a response committed before the six
points can pass only on the existing admissible-root event. -/
def piopOpeningBadEvent {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) : Finset Opening :=
  by
    classical
    exact if PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix
      then ∅ else openingEvent candidate matrix response

theorem piop_opening_bad_probability_le {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) :
    FiniteEvents.probability (piopOpeningBadEvent candidate matrix response) ≤ epsilon3 := by
  by_cases affine : PiopExtraction.AffineBatchAccepts candidate.system
      (maskSum candidate) matrix
  · unfold piopOpeningBadEvent
    rw [if_pos affine, FiniteEvents.probability_empty]
    unfold epsilon3
    positivity
  · unfold piopOpeningBadEvent
    rw [if_neg affine]
    exact opening_probability_le_of_affine_failure candidate matrix response affine

theorem opening_acceptance_is_matrix_or_opening_bad {width : Nat}
    (candidate : Candidate width) (matrix : Matrix width)
    (response : ClaimedTranscript) (opening : Opening)
    (accepted : OpeningAccepts candidate matrix response opening) :
    matrix ∈ piopMatrixBadEvent candidate ∨
      opening ∈ piopOpeningBadEvent candidate matrix response := by
  classical
  by_cases affine : PiopExtraction.AffineBatchAccepts candidate.system
      (maskSum candidate) matrix
  · left
    unfold piopMatrixBadEvent PiopExtraction.affineBatchFailureSet
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, affine⟩
  · right
    unfold piopOpeningBadEvent
    rw [if_neg affine]
    unfold openingEvent
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, accepted⟩

/-! ## Actual restored-transcript classification -/

/-- These are message equalities checked by the verifier/extractor.  They do
not constrain how the malicious strategy chooses any message beyond the
chronological types above. -/
structure AcceptedChecks (publicWords : List Nat)
    (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy publicWords) (coefficients : Coefficients)
    (matrix : Matrix (batchingWidth publicWords)) (opening : Opening) (query : Query) : Prop where
  queryAccepts : QueryAccepts oracle decsResponse coefficients query
  headBinding :
    let message := strategy.afterOpening coefficients matrix opening
    SmzaQ38OpeningFieldReadback.ClaimedHeadsReconstructed
      (baseOpeningPoints opening.1) message.claimed message.witness message.masks message.partials
  oracleOpeningChecks :
    let message := strategy.afterOpening coefficients matrix opening
    SmzaQ38LvcsOpening.OracleOpeningChecks oracle
      (baseOpeningPoints opening.1) message.claimed query
  restored : ∀ source, recoverSource oracle decsResponse coefficients = some source →
    transcriptBound (transcriptAt strategy coefficients matrix opening) source.data

attribute [local irreducible] SmzaQ38McaSourceBinding.recoverSource
  SmzaRp04ActualProgram.recoveredCandidate

/-- An accepted failed extraction is either the already-separated MCA decoder
event, or one of the three chronological algebra events.  In particular, the
PIOP response in the opening event is definitionally independent of `opening`,
and the LVCS claims in the query event are definitionally independent of
`query`. -/
theorem accepted_failure_implies_chronological_bad_event
    (publicWords : List Nat)
    (canonical : Hegemon.Transaction.Poseidon2V8RelationProgram.CanonicalPublicWords publicWords)
    (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy publicWords) (coefficients : Coefficients)
    (matrix : Matrix (batchingWidth publicWords)) (opening : Opening) (query : Query)
    (checks : AcceptedChecks publicWords oracle decsResponse strategy
      coefficients matrix opening query)
    (failed : extractionFailure publicWords oracle decsResponse coefficients) :
    DecoderFailure oracle decsResponse coefficients query ∨
      ∃ source, recoverSource oracle decsResponse coefficients = some source ∧
        ¬ PiopExtraction.FullySatisfied
          (recoveredCandidate publicWords source.data).system ∧
          (matrix ∈ piopMatrixBadEvent (recoveredCandidate publicWords source.data) ∨
           opening ∈ piopOpeningBadEvent (recoveredCandidate publicWords source.data) matrix
             (strategy.piopResponse coefficients matrix) ∨
           query ∈ lvcsBadQueryEvent source.data (baseOpeningPoints opening.1)
             (strategy.afterOpening coefficients matrix opening).claimed) := by
  classical
  cases recovered : recoverSource oracle decsResponse coefficients with
  | none => exact Or.inl ⟨checks.queryAccepts, recovered⟩
  | some source =>
    right
    have invalid : ¬ PiopExtraction.FullySatisfied
        (recoveredCandidate publicWords source.data).system := by
      intro satisfied
      apply failed
      refine ⟨packedFromRows source.data, ?_, ?_⟩
      · simp only [extract, recovered, Option.map_some]
      · exact recovered_candidate_satisfaction_supplies_actual_program
          publicWords source.data canonical satisfied
    refine Exists.intro source ?_
    constructor
    · rfl
    · constructor
      · exact invalid
      · let message := strategy.afterOpening coefficients matrix opening
        by_cases lvcsDetected : SmzaQ38LvcsOpening.DiscrepanciesDetected source.data
            (baseOpeningPoints opening.1) message.claimed query
        · have rowAgreement : ∀ row index, index ∈ query.val →
              (source.data row).eval (smz9EvaluationPoint index) =
                committedColumnValue oracle row index :=
            recovered_rows_match_every_accepted_query oracle decsResponse coefficients source
              recovered query checks.queryAccepts
          have columns :=
            SmzaQ38OpeningFieldReadback.accepted_heads_force_every_reconstructed_column
              oracle source.data (baseOpeningPoints opening.1) message.claimed query
              message.witness message.masks message.partials checks.headBinding rowAgreement
              checks.oracleOpeningChecks lvcsDetected
          have scalarChecks := restored_transcript_supplies_scalar_checks publicWords source.data
            matrix (strategy.piopResponse coefficients matrix) opening message.witness message.masks
            message.nonlinearHigh message.linearHigh message.correction
            (checks.restored source recovered)
          have openingAccepted : OpeningAccepts (recoveredCandidate publicWords source.data)
              matrix (strategy.piopResponse coefficients matrix) opening :=
            reconstructed_columns_and_actual_checks_imply_opening_acceptance publicWords source.data
              matrix (strategy.piopResponse coefficients matrix) opening message.witness message.masks
              message.partials columns scalarChecks
          rcases opening_acceptance_is_matrix_or_opening_bad
              (recoveredCandidate publicWords source.data) matrix
              (strategy.piopResponse coefficients matrix) opening openingAccepted with
            badMatrix | badOpening
          · exact Or.inl badMatrix
          · exact Or.inr (Or.inl badOpening)
        · exact Or.inr (Or.inr (not_lvcs_detected_mem_bad_query_event source.data
            (baseOpeningPoints opening.1) message.claimed query lvcsDetected))

/-- The actual recovered q38 rows and the syntactically degree-bounded message
instantiate the final-role density with no additional algebraic premise. -/
theorem recovered_lvcs_bad_query_probability_le
    {publicWords : List Nat} (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy publicWords) (coefficients : Coefficients)
    (matrix : Matrix (batchingWidth publicWords)) (opening : Opening)
    (source : RecoveredSource)
    (recovered : recoverSource oracle decsResponse coefficients = some source) :
    FiniteEvents.probability
      (lvcsBadQueryEvent source.data (baseOpeningPoints opening.1)
        (strategy.afterOpening coefficients matrix opening).claimed) ≤ q38LvcsLoss := by
  have degree := recovered_source_degree_and_agreement oracle decsResponse coefficients
    source recovered
  exact lvcs_bad_query_probability_le source.data (baseOpeningPoints opening.1)
    (strategy.afterOpening coefficients matrix opening).claimed degree.2.2.2
    (strategy.afterOpening coefficients matrix opening).claimedDegree

end
end HegemonCrypto.SmallWood.SmzaRp04ChronologicalAlgebra
