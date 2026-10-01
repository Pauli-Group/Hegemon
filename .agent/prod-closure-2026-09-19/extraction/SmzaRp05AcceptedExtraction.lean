import SmzaRp05TracePrefixes
import SmzaRp05AcceptedRelationInterface

/-!
# Relation-generic accepted extraction for RP05

This file deliberately does not reuse `SmzaRp04Components.program` or the
RP04 `batchingWidth`.  The chronological extraction argument is generic in
`SmzaRp05TracePrefixes.RelationModel.width` and `recoveredCandidate`.

There are exactly two relation-specific proof obligations below.  For the
current RP05 relation they must be generated from the current CSR (818
nonlinear constraints, maximum degree 8, and 686 witness rows):

* reconstructed q38 columns plus the verifier's scalar equations imply the
  generic PIOP `OpeningAccepts` predicate; and
* `PiopExtraction.FullySatisfied` for the generated candidate implies the
  current relation's packed acceptance predicate.

Those obligations are finite relation-refinement theorems, not security
assumptions.  No concrete RP05 instance is asserted here until those generated
theorems exist.  Subject to them, all remaining steps use the checked generic
q38 recovery/readback and PIOP good-outcome lemmas, and the result is packaged
in the exact four-role `completeBad`/`typedCompleteRawBad` events.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedExtraction

open Polynomial
open SmzaRp05TracePrefixes
open SmzaRp05StatementNamespace
open SmzaRp04ChronologicalAlgebra SmzaRp04McaRoleCells
open SmzaRp04RoleBadCells
open SmzaRp04RawRoleSampling SmzaRp04RawMcaSampling
open SmzaQ38Recovery SmzaQ38OracleExtraction SmzaQ38McaSourceBinding
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open V8Smz9EagerSimulator
open V8Smz9CoherentVectorMerkle V8Smz9RawCounterCompiler
open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

/-- Malicious messages with the protocol's real chronological dependencies.
The PIOP response precedes the opening points, and the q38 claims precede the
final query. -/
structure Strategy (model : RelationModel) (statement : Statement) where
  piopResponse : Coefficients → Matrix (model.width statement) → ClaimedTranscript
  afterOpening : Coefficients → Matrix (model.width statement) →
    Opening → OpeningMessage

/-- A fully selected transcript, used only after all three challenge stages
have been fixed. -/
structure Transcript (model : RelationModel) (statement : Statement) where
  matrix : Matrix (model.width statement)
  response : ClaimedTranscript
  opening : Opening
  message : OpeningMessage

def transcriptAt {model : RelationModel} {statement : Statement}
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) :
    Transcript model statement :=
  { matrix := matrix
    response := strategy.piopResponse coefficients matrix
    opening := opening
    message := strategy.afterOpening coefficients matrix opening }

/-- The exact pre-query MCA decoder followed by the fixed q38 row-to-packed
witness map. -/
def extract (oracle : CommittedOracle) (response : ResponseStrategy)
    (coefficients : Coefficients) : Option (List Nat) :=
  (recoverSource oracle response coefficients).map
    (fun source => packedFromRows source.data)

def ExtractionFailure {model : RelationModel}
    (refinement : RelationRefinement model) (statement : Statement)
    (oracle : CommittedOracle) (response : ResponseStrategy)
    (coefficients : Coefficients) : Prop :=
  ¬ ∃ packed, extract oracle response coefficients = some packed ∧
    refinement.AcceptsPacked statement packed

/-- The three fixed-polynomial/fixed-response algebraic failures.  This is the
relation-generic counterpart of the old calculated-extraction classification. -/
def AlgebraBad {model : RelationModel} {statement : Statement}
    (transcript : Transcript model statement) (query : Query)
    (rows : RecoveredRows) : Prop :=
  ¬ SmzaQ38LvcsOpening.DiscrepanciesDetected rows
      (baseOpeningPoints transcript.opening.1) transcript.message.claimed query ∨
  ¬ SmzaPiopGoodOutcome.DiscrepanciesDetected
      (model.recoveredCandidate statement rows) transcript.matrix
        transcript.response transcript.opening ∨
  ¬ SmzaPiopGoodOutcome.ResidualsDetected
      (model.recoveredCandidate statement rows) transcript.matrix

/-- Exact accepted checks which are independent of the final query, except for
the two q38 predicates explicitly carrying that query. -/
structure AcceptedChecks {model : RelationModel}
    (refinement : RelationRefinement model) (statement : Statement)
    (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (query : Query) : Prop where
  statementValid : refinement.StatementValid statement
  queryAccepts : QueryAccepts oracle decsResponse coefficients query
  headBinding :
    let message := strategy.afterOpening coefficients matrix opening
    SmzaQ38OpeningFieldReadback.ClaimedHeadsReconstructed
      (baseOpeningPoints opening.1) message.claimed
        message.witness message.masks message.partials
  oracleOpeningChecks :
    let message := strategy.afterOpening coefficients matrix opening
    SmzaQ38LvcsOpening.OracleOpeningChecks oracle
      (baseOpeningPoints opening.1) message.claimed query
  scalarChecks : ∀ source,
    recoverSource oracle decsResponse coefficients = some source →
    refinement.ScalarChecks statement source.data matrix
      (strategy.piopResponse coefficients matrix) opening
      (strategy.afterOpening coefficients matrix opening)

/-- Read back the 736 opened columns and apply only the explicit finite
relation-scalar bridge. -/
theorem recovered_opening_accepts {model : RelationModel}
    (refinement : RelationRefinement model) (statement : Statement)
    (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) (query : Query)
    (checks : AcceptedChecks refinement statement oracle decsResponse strategy
      coefficients matrix opening query)
    (source : RecoveredSource)
    (recovered : recoverSource oracle decsResponse coefficients = some source)
    (lvcsDetected : SmzaQ38LvcsOpening.DiscrepanciesDetected source.data
      (baseOpeningPoints opening.1)
      (strategy.afterOpening coefficients matrix opening).claimed query) :
    OpeningAccepts (model.recoveredCandidate statement source.data) matrix
      (strategy.piopResponse coefficients matrix) opening := by
  let message := strategy.afterOpening coefficients matrix opening
  have rowAgreement : ∀ row index, index ∈ query.val →
      (source.data row).eval (smz9EvaluationPoint index) =
        committedColumnValue oracle row index :=
    recovered_rows_match_every_accepted_query oracle decsResponse coefficients
      source recovered query checks.queryAccepts
  have columns :=
    SmzaQ38OpeningFieldReadback.accepted_heads_force_every_reconstructed_column
      oracle source.data (baseOpeningPoints opening.1) message.claimed query
      message.witness message.masks message.partials checks.headBinding
      rowAgreement checks.oracleOpeningChecks lvcsDetected
  exact refinement.openingAcceptsOfReadback statement source.data matrix
    (strategy.piopResponse coefficients matrix) opening message columns
    (checks.scalarChecks source recovered)

/-- Outside the three named algebraic events, the generic PIOP good-outcome
theorem supplies full candidate satisfaction and the explicit relation
refinement supplies current packed acceptance. -/
theorem outside_algebra_bad_accepts_packed {model : RelationModel}
    (refinement : RelationRefinement model) (statement : Statement)
    (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) (query : Query)
    (checks : AcceptedChecks refinement statement oracle decsResponse strategy
      coefficients matrix opening query)
    (source : RecoveredSource)
    (recovered : recoverSource oracle decsResponse coefficients = some source)
    (good : ¬ AlgebraBad (transcriptAt strategy coefficients matrix opening)
      query source.data) :
    refinement.AcceptsPacked statement (packedFromRows source.data) := by
  have detected :
      SmzaQ38LvcsOpening.DiscrepanciesDetected source.data
          (baseOpeningPoints opening.1)
            (strategy.afterOpening coefficients matrix opening).claimed query ∧
      SmzaPiopGoodOutcome.DiscrepanciesDetected
          (model.recoveredCandidate statement source.data) matrix
            (strategy.piopResponse coefficients matrix) opening ∧
      SmzaPiopGoodOutcome.ResidualsDetected
          (model.recoveredCandidate statement source.data) matrix := by
    simpa only [AlgebraBad, transcriptAt, not_or, not_not] using good
  have openingAccepted := recovered_opening_accepts refinement statement oracle
    decsResponse strategy coefficients matrix opening query checks source recovered
    detected.1
  apply refinement.fullySatisfiedAccepts statement source.data checks.statementValid
  exact SmzaPiopGoodOutcome.accepted_piop_outside_named_algebraic_events_satisfies_candidate
    (model.recoveredCandidate statement source.data) matrix
    (strategy.piopResponse coefficients matrix) opening openingAccepted
    detected.2.1 detected.2.2

/-- The relation-generic calculated-extraction classification. -/
theorem accepted_failure_implies_decoder_or_algebra_bad {model : RelationModel}
    (refinement : RelationRefinement model) (statement : Statement)
    (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) (query : Query)
    (checks : AcceptedChecks refinement statement oracle decsResponse strategy
      coefficients matrix opening query)
    (failed : ExtractionFailure refinement statement oracle decsResponse coefficients) :
    DecoderFailure oracle decsResponse coefficients query ∨
      ∃ source, recoverSource oracle decsResponse coefficients = some source ∧
        AlgebraBad (transcriptAt strategy coefficients matrix opening)
          query source.data := by
  cases recovered : recoverSource oracle decsResponse coefficients with
  | none => exact Or.inl ⟨checks.queryAccepts, recovered⟩
  | some source =>
      by_cases bad : AlgebraBad (transcriptAt strategy coefficients matrix opening)
          query source.data
      · refine Or.inr ⟨source, ?_, bad⟩
        rfl
      · exfalso
        apply failed
        refine ⟨packedFromRows source.data, ?_, ?_⟩
        · simp only [extract, recovered, Option.map_some]
        · exact outside_algebra_bad_accepts_packed refinement statement oracle
            decsResponse strategy coefficients matrix opening query checks source
            recovered bad

/-- The chronological form used by the four physical role events. -/
theorem accepted_failure_implies_chronological_bad_role {model : RelationModel}
    (refinement : RelationRefinement model) (statement : Statement)
    (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) (query : Query)
    (checks : AcceptedChecks refinement statement oracle decsResponse strategy
      coefficients matrix opening query)
    (failed : ExtractionFailure refinement statement oracle decsResponse coefficients) :
    DecoderFailure oracle decsResponse coefficients query ∨
      ∃ source, recoverSource oracle decsResponse coefficients = some source ∧
        ¬ PiopExtraction.FullySatisfied
          (model.recoveredCandidate statement source.data).system ∧
        (matrix ∈ piopMatrixBadEvent
            (model.recoveredCandidate statement source.data) ∨
         opening ∈ piopOpeningBadEvent
            (model.recoveredCandidate statement source.data) matrix
              (strategy.piopResponse coefficients matrix) ∨
         query ∈ lvcsBadQueryEvent source.data (baseOpeningPoints opening.1)
            (strategy.afterOpening coefficients matrix opening).claimed) := by
  cases recovered : recoverSource oracle decsResponse coefficients with
  | none => exact Or.inl ⟨checks.queryAccepts, recovered⟩
  | some source =>
      right
      have invalid : ¬ PiopExtraction.FullySatisfied
          (model.recoveredCandidate statement source.data).system := by
        intro satisfied
        apply failed
        refine ⟨packedFromRows source.data, ?_, ?_⟩
        · simp only [extract, recovered, Option.map_some]
        · exact refinement.fullySatisfiedAccepts statement source.data
            checks.statementValid satisfied
      refine ⟨source, ?_, invalid, ?_⟩ <;> try rfl
      let message := strategy.afterOpening coefficients matrix opening
      by_cases lvcsDetected : SmzaQ38LvcsOpening.DiscrepanciesDetected source.data
          (baseOpeningPoints opening.1) message.claimed query
      · have openingAccepted := recovered_opening_accepts refinement statement oracle
          decsResponse strategy coefficients matrix opening query checks source recovered
          lvcsDetected
        rcases opening_acceptance_is_matrix_or_opening_bad
            (model.recoveredCandidate statement source.data) matrix
            (strategy.piopResponse coefficients matrix) opening openingAccepted with
          badMatrix | badOpening
        · exact Or.inl badMatrix
        · exact Or.inr (Or.inl badOpening)
      · exact Or.inr (Or.inr (not_lvcs_detected_mem_bad_query_event source.data
          (baseOpeningPoints opening.1) message.claimed query lvcsDetected))

/-- Prefix values calculated from the same chronological messages as the
classification.  The later byte-trace theorem has only to identify these
values with `SmzaRp05TracePrefixes.prefixLabels`. -/
def calculatedLabels {model : RelationModel} (statement : Statement)
    (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) :
    Prefix (model.width statement) :=
  let recovered := recoverSource oracle decsResponse coefficients
  let message := strategy.afterOpening coefficients matrix opening
  { decsMatrix := some oracle
    piopMatrix := recovered.map fun source =>
      ⟨model.recoveredCandidate statement source.data⟩
    piopOpening := recovered.map fun source =>
      ⟨model.recoveredCandidate statement source.data, matrix,
        strategy.piopResponse coefficients matrix⟩
    smallSupport := SmzaRp04CompleteRawRoleCells.supportPrefix
      oracle decsResponse coefficients
    lvcs := recovered.map fun source =>
      recoveredDecsSampleKey source (baseOpeningPoints opening.1)
        message.claimedCoefficients }

/-- Accepted failed extraction lands in one of the exact capped raw role
events.  The four read premises only identify already-decoded sampler outputs;
they do not assume sampling success or a distributional theorem. -/
theorem accepted_failure_has_complete_bad_role
    {Counter : Type*} {model : RelationModel}
    (refinement : RelationRefinement model) (statement : Statement)
    (routes : Routes Counter (model.width statement))
    (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) (query : Query)
    (vectors : SmzaChallengeStageTargets.Role → VectorOutput Counter)
    (decsRead : actualDecsMatrixOutput routes.decsMatrix (vectors .decsMatrix) =
      some coefficients)
    (matrixRead : actualPiopMatrixOutput routes.piopMatrix (vectors .piopMatrix) =
      some matrix)
    (openingRead : actualPiopOpeningOutput routes.piopOpening (vectors .piopOpening) =
      some opening)
    (queryRead : actualDecsSampleOutput routes.decsSample (vectors .decsSample) =
      some query)
    (checks : AcceptedChecks refinement statement oracle decsResponse strategy
      coefficients matrix opening query)
    (failed : ExtractionFailure refinement statement oracle decsResponse coefficients) :
    ∃ role, completeBad routes role
      (calculatedLabels statement oracle decsResponse strategy coefficients matrix opening)
      (vectors role) := by
  rcases accepted_failure_implies_chronological_bad_role refinement statement oracle
      decsResponse strategy coefficients matrix opening query checks failed with
    decoder | ⟨source, recovered, invalid, bad⟩
  · rcases accepted_decoder_failure_is_matrix_or_query_cell oracle decsResponse
      coefficients query decoder with badMatrix | ⟨label, supportEq, badQuery⟩
    · exact ⟨.decsMatrix, oracle, rfl, coefficients, decsRead, badMatrix⟩
    · have small : (agreementSupport oracle decsResponse coefficients).card < 65536 := by
        rw [← supportEq]
        exact label.small
      refine ⟨.decsSample, Or.inl ?_⟩
      refine ⟨⟨agreementSupport oracle decsResponse coefficients, small⟩, ?_,
        query, queryRead, ?_⟩
      · simp only [calculatedLabels, SmzaRp04CompleteRawRoleCells.supportPrefix,
          dif_pos small]
      · change query.val ⊆ agreementSupport oracle decsResponse coefficients
        rw [← supportEq]
        exact badQuery
  · rcases bad with badMatrix | badOpening | badQuery
    · refine ⟨.piopMatrix,
        ⟨model.recoveredCandidate statement source.data⟩, ?_,
        matrix, matrixRead, ?_⟩
      · simp only [calculatedLabels, recovered, Option.map_some]
      · exact ⟨invalid, badMatrix⟩
    · refine ⟨.piopOpening,
        ⟨model.recoveredCandidate statement source.data, matrix,
          strategy.piopResponse coefficients matrix⟩, ?_,
        opening, openingRead, badOpening⟩
      simp only [calculatedLabels, recovered, Option.map_some]
    · refine ⟨.decsSample, Or.inr ?_⟩
      let label : DecsSamplePrefixKey := recoveredDecsSampleKey source
        (baseOpeningPoints opening.1)
        (strategy.afterOpening coefficients matrix opening).claimedCoefficients
      refine ⟨label, ?_, query, queryRead, ?_⟩
      · simp only [calculatedLabels, recovered, Option.map_some]
        rfl
      · exact recovered_decs_sample_key_bad oracle decsResponse coefficients
          source recovered (baseOpeningPoints opening.1)
          (strategy.afterOpening coefficients matrix opening).claimedCoefficients
          query badQuery

/-- Fixed-type wrapper consumed by the RP05 indexed database theorem. -/
theorem accepted_failure_has_typed_complete_raw_bad_role
    {Counter : Type*} {model : RelationModel}
    (refinement : RelationRefinement model) (statement : Statement)
    (routes : TypedRoutes model Counter)
    (oracle : CommittedOracle) (decsResponse : ResponseStrategy)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) (query : Query)
    (vectors : SmzaChallengeStageTargets.Role → VectorOutput Counter)
    (decsRead : actualDecsMatrixOutput (routes statement).decsMatrix
      (vectors .decsMatrix) = some coefficients)
    (matrixRead : actualPiopMatrixOutput (routes statement).piopMatrix
      (vectors .piopMatrix) = some matrix)
    (openingRead : actualPiopOpeningOutput (routes statement).piopOpening
      (vectors .piopOpening) = some opening)
    (queryRead : actualDecsSampleOutput (routes statement).decsSample
      (vectors .decsSample) = some query)
    (checks : AcceptedChecks refinement statement oracle decsResponse strategy
      coefficients matrix opening query)
    (failed : ExtractionFailure refinement statement oracle decsResponse coefficients) :
    ∃ role, typedCompleteRawBad model routes role
      (.decoded statement
        (calculatedLabels statement oracle decsResponse strategy coefficients matrix opening))
      (vectors role) := by
  simpa only [typedCompleteRawBad] using
    (accepted_failure_has_complete_bad_role refinement statement (routes statement)
      oracle decsResponse strategy coefficients matrix opening query vectors
      decsRead matrixRead openingRead queryRead checks failed)

end
end HegemonCrypto.SmallWood.SmzaRp05AcceptedExtraction
