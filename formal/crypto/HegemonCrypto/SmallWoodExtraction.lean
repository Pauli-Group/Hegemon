import HegemonCrypto.ProductionCCS
import HegemonCrypto.SmallWoodInteractive
import Hegemon.Transaction.SmallWoodNoGrindingSoundness
import Mathlib.Tactic.FieldSimp

/-!
# SmallWood extraction boundary and failure composition

The deployed SmallWood construction uses PACS-PIOP, PCS, LVCS, and DECS layers.  It does not use
FRI.  This module proves the deterministic end of extraction: a field-level production oracle that
satisfies the PIOP equations reflects to the exact natural-representative production relation.

It also defines the exact staged interface required from a straight-line cryptographic extractor
and proves generic event-union composition.  The interface is not an instantiation of the published
ROM extractor; the four published information-theoretic terms, hash security, and executable
refinement remain separately visible.
-/

namespace HegemonCrypto.SmallWood.Extraction

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open HegemonCrypto.SmallWood.Interactive

section ProductionSoundness

variable {F : Type*} [Field F]

/-- A satisfying extracted production oracle reflects to the exact bounded production relation. -/
theorem production_oracles_sound
    (statement : Statement)
    (witness : Witness)
    (encoding : ProductionFieldEncoding (F := F))
    (oracles : ProductionOracleRefinement statement witness encoding)
    (mapBound : ProductionConstraintMapBound statement)
    (witnessLength :
      witness.length = statement.lppcRowCount * statement.lppcPackingFactor)
    (satisfied : oracles.system.Satisfied) :
    (statement, witness) ∈ Relation := by
  refine ⟨mapBound, ?_⟩
  unfold ExactProductionConstraintMapEvaluates exactProductionConstraintMapEvaluatesB
  simp only [Bool.and_eq_true]
  refine ⟨⟨⟨ProductionCCS.sparse_table_well_formed_of_map_bound mapBound,
    decide_eq_true witnessLength⟩, ?_⟩, ?_⟩
  · unfold linearProgramEvaluatesB
    rw [List.all_eq_true]
    intro constraint constraintMembership
    have constraintBound := List.mem_range.mp constraintMembership
    unfold linearConstraintEvaluatesB
    apply decide_eq_true
    have systemMembership : constraint ∈ oracles.system.linearIndices := by
      simpa [ProductionOracleRefinement.system] using constraintBound
    have accepted := satisfied.2 constraint systemMembership
    change
      nodeSum (Finset.range statement.lppcPackingFactor) oracles.point
          (oracles.linearPolynomial constraint) =
        encoding.encode
          (toGoldilocks (fieldValue (statement.linearTargets.getD constraint 0))) at accepted
    have encodedEquation :
        encoding.encode (toGoldilocks
            (linearConstraintValue statement witness constraint)) =
          encoding.encode
            (toGoldilocks (fieldValue (statement.linearTargets.getD constraint 0))) :=
      (oracles.linearPackingSum constraint constraintBound).symm.trans accepted
    have fieldEquation := encoding.injective encodedEquation
    have naturalEquation := congrArg fromGoldilocks fieldEquation
    simp only [fromGoldilocks_toGoldilocks] at naturalEquation
    rw [ProductionCCS.linear_constraint_value_is_canonical] at naturalEquation
    simpa [fieldValue] using naturalEquation
  · unfold nonlinearProgramEvaluatesB
    rw [Bool.and_eq_true]
    refine ⟨decide_eq_true
      (ProductionCCS.nonlinear_constraint_count_of_map_bound mapBound), ?_⟩
    rw [List.all_eq_true]
    intro lane laneMembership
    have laneBound := List.mem_range.mp laneMembership
    unfold nonlinearLaneEvaluatesB
    rw [List.all_eq_true]
    intro constraint constraintMembership
    have constraintBound := List.mem_range.mp constraintMembership
    unfold nonlinearConstraintEvaluatesB
    apply decide_eq_true
    have systemConstraintMembership :
        constraint ∈ oracles.system.nonlinearIndices := by
      simpa [ProductionOracleRefinement.system] using constraintBound
    have systemLaneMembership : lane ∈ oracles.system.nodes := by
      simpa [ProductionOracleRefinement.system] using laneBound
    have accepted := satisfied.1 constraint systemConstraintMembership lane
      systemLaneMembership
    change
      (oracles.nonlinearPolynomial constraint).eval (oracles.point lane) = 0 at accepted
    have encodedZero :
        encoding.encode (toGoldilocks
            (nonlinearConstraintValue statement witness lane constraint)) =
          encoding.encode 0 := by
      calc
        encoding.encode (toGoldilocks
            (nonlinearConstraintValue statement witness lane constraint)) =
            (oracles.nonlinearPolynomial constraint).eval (oracles.point lane) :=
          (oracles.nonlinearAtPackingNode constraint constraintBound lane laneBound).symm
        _ = 0 := accepted
        _ = encoding.encode 0 := (map_zero encoding.encode).symm
    have fieldZero := encoding.injective encodedZero
    have naturalZero := congrArg fromGoldilocks fieldZero
    have canonical := ProductionCCS.nonlinear_constraint_value_is_canonical
      statement witness mapBound lane constraint constraintBound
    rw [fromGoldilocks_toGoldilocks] at naturalZero
    have zeroRepresentative : fromGoldilocks (0 : Goldilocks) = 0 := by
      simp [fromGoldilocks]
    rw [zeroRepresentative] at naturalZero
    have reducedZero :
        fieldValue (nonlinearConstraintValue statement witness lane constraint) = 0 :=
      naturalZero
    exact canonical.symm.trans reducedZero

/-- Fully checked output required from the cryptographic straight-line extractor. -/
structure Certificate (F : Type*) [Field F] (statement : Statement) where
  witness : Witness
  encoding : ProductionFieldEncoding (F := F)
  oracles : ProductionOracleRefinement statement witness encoding
  mapBound : ProductionConstraintMapBound statement
  witnessLength : witness.length = statement.lppcRowCount * statement.lppcPackingFactor
  piopSatisfied : oracles.system.Satisfied

/-- Every extraction certificate contains an exact Hegemon production witness. -/
theorem Certificate.relation
    {statement : Statement}
    (certificate : Certificate F statement) :
    (statement, certificate.witness) ∈ Relation := by
  exact production_oracles_sound statement certificate.witness certificate.encoding
    certificate.oracles certificate.mapBound certificate.witnessLength certificate.piopSatisfied

end ProductionSoundness

section StagedExtractor

/-- Actual commitment architecture used by deployed SmallWood. -/
inductive CommitmentArchitecture where
  | smallWoodDecsLvcs
  | fri
deriving DecidableEq, Repr

def deployedCommitmentArchitecture : CommitmentArchitecture := .smallWoodDecsLvcs

theorem deployed_smallwood_does_not_use_fri :
    deployedCommitmentArchitecture ≠ .fri := by
  decide

/-- Disjoint failure classes in extraction order. -/
inductive FailureLayer where
  | hashOrMerkleBinding
  | decsDegreeEnforcement
  | piopBatching
  | piopEvaluation
  | decsOpeningSampling
  | productionOracleRefinement
deriving DecidableEq, Repr

def allFailureLayers : Finset FailureLayer :=
  { .hashOrMerkleBinding,
    .decsDegreeEnforcement,
    .piopBatching,
    .piopEvaluation,
    .decsOpeningSampling,
    .productionOracleRefinement }

theorem all_failure_layers_complete (layer : FailureLayer) :
    layer ∈ allFailureLayers := by
  cases layer <;> simp [allFailureLayers]

variable {F Proof Commitment DegreeBound Batched Evaluated Opened : Type*}
variable [Field F]

/--
Executable shape required from a SmallWood straight-line extractor.  Each transition either
produces the next typed state or identifies the unique named failure class for that transition.
-/
structure LayeredExtractor where
  verifies : Statement -> Proof -> Bool
  extractCommitment : Statement -> Proof -> Option Commitment
  enforceDegree : Statement -> Commitment -> Option DegreeBound
  extractBatch : Statement -> DegreeBound -> Option Batched
  checkEvaluations : Statement -> Batched -> Option Evaluated
  extractOpenings : Statement -> Evaluated -> Option Opened
  certify : (statement : Statement) -> Opened -> Option (Certificate F statement)
  failure : FailureLayer -> Statement -> Proof -> Prop
  acceptedToCommitment : ∀ statement proof,
    verifies statement proof = true ->
      (∃ commitment, extractCommitment statement proof = some commitment) ∨
        failure .hashOrMerkleBinding statement proof
  commitmentToDegree : ∀ statement proof commitment,
    extractCommitment statement proof = some commitment ->
      (∃ degreeBound, enforceDegree statement commitment = some degreeBound) ∨
        failure .decsDegreeEnforcement statement proof
  degreeToBatch : ∀ statement proof commitment degreeBound,
    extractCommitment statement proof = some commitment ->
    enforceDegree statement commitment = some degreeBound ->
      (∃ batched, extractBatch statement degreeBound = some batched) ∨
        failure .piopBatching statement proof
  batchToEvaluated : ∀ statement proof commitment degreeBound batched,
    extractCommitment statement proof = some commitment ->
    enforceDegree statement commitment = some degreeBound ->
    extractBatch statement degreeBound = some batched ->
      (∃ evaluated, checkEvaluations statement batched = some evaluated) ∨
        failure .piopEvaluation statement proof
  evaluatedToOpened : ∀ statement proof commitment degreeBound batched evaluated,
    extractCommitment statement proof = some commitment ->
    enforceDegree statement commitment = some degreeBound ->
    extractBatch statement degreeBound = some batched ->
    checkEvaluations statement batched = some evaluated ->
      (∃ opened, extractOpenings statement evaluated = some opened) ∨
        failure .decsOpeningSampling statement proof
  openedToCertificate : ∀ statement proof commitment degreeBound batched evaluated opened,
    extractCommitment statement proof = some commitment ->
    enforceDegree statement commitment = some degreeBound ->
    extractBatch statement degreeBound = some batched ->
    checkEvaluations statement batched = some evaluated ->
    extractOpenings statement evaluated = some opened ->
      (∃ certificate, certify statement opened = some certificate) ∨
        failure .productionOracleRefinement statement proof

/-- Acceptance extracts an exact production witness unless one named stage fails. -/
theorem LayeredExtractor.accepted_yields_relation_or_named_failure
    (extractor : LayeredExtractor (F := F) (Proof := Proof)
      (Commitment := Commitment) (DegreeBound := DegreeBound) (Batched := Batched)
      (Evaluated := Evaluated) (Opened := Opened))
    (statement : Statement)
    (proof : Proof)
    (accepted : extractor.verifies statement proof = true) :
    (∃ witness, (statement, witness) ∈ Relation) ∨
      ∃ layer ∈ allFailureLayers, extractor.failure layer statement proof := by
  rcases extractor.acceptedToCommitment statement proof accepted with
    ⟨commitment, commitmentEquation⟩ | hashFailure
  · rcases extractor.commitmentToDegree statement proof commitment commitmentEquation with
      ⟨degreeBound, degreeEquation⟩ | degreeFailure
    · rcases extractor.degreeToBatch statement proof commitment degreeBound
        commitmentEquation degreeEquation with
        ⟨batched, batchEquation⟩ | batchFailure
      · rcases extractor.batchToEvaluated statement proof commitment degreeBound batched
          commitmentEquation degreeEquation batchEquation with
          ⟨evaluated, evaluationEquation⟩ | evaluationFailure
        · rcases extractor.evaluatedToOpened statement proof commitment degreeBound batched
            evaluated commitmentEquation degreeEquation batchEquation evaluationEquation with
            ⟨opened, openingEquation⟩ | openingFailure
          · rcases extractor.openedToCertificate statement proof commitment degreeBound batched
              evaluated opened commitmentEquation degreeEquation batchEquation evaluationEquation
              openingEquation with
              ⟨certificate, certificateEquation⟩ | refinementFailure
            · left
              exact ⟨certificate.witness, certificate.relation⟩
            · right
              exact ⟨.productionOracleRefinement,
                all_failure_layers_complete .productionOracleRefinement, refinementFailure⟩
          · right
            exact ⟨.decsOpeningSampling,
              all_failure_layers_complete .decsOpeningSampling, openingFailure⟩
        · right
          exact ⟨.piopEvaluation, all_failure_layers_complete .piopEvaluation,
            evaluationFailure⟩
      · right
        exact ⟨.piopBatching, all_failure_layers_complete .piopBatching, batchFailure⟩
    · right
      exact ⟨.decsDegreeEnforcement,
        all_failure_layers_complete .decsDegreeEnforcement, degreeFailure⟩
  · right
    exact ⟨.hashOrMerkleBinding,
      all_failure_layers_complete .hashOrMerkleBinding, hashFailure⟩

end StagedExtractor

section FailureProbability

open scoped BigOperators

/-- Minimal probability interface needed for a finite cryptographic union bound. -/
structure EventProbability (Omega : Type*) where
  probability : Set Omega -> ℚ
  empty : probability ∅ = 0
  monotone : ∀ {left right}, left ⊆ right -> probability left ≤ probability right
  union_le : ∀ left right,
    probability (left ∪ right) ≤ probability left + probability right

namespace EventProbability

/-- Finite union bound, proved from binary subadditivity rather than assumed wholesale. -/
theorem finite_iUnion_le_sum
    {Omega Index : Type*}
    [DecidableEq Index]
    (measure : EventProbability Omega)
    (indices : Finset Index)
    (event : Index -> Set Omega) :
    measure.probability (⋃ index ∈ indices, event index) ≤
      ∑ index ∈ indices, measure.probability (event index) := by
  classical
  induction indices using Finset.induction_on with
  | empty =>
      simp [measure.empty]
  | @insert index indices indexNotMem induction =>
      rw [Finset.sum_insert indexNotMem]
      have unionEquation :
          (⋃ selected ∈ insert index indices, event selected) =
            event index ∪ ⋃ selected ∈ indices, event selected := by
        ext outcome
        simp
      rw [unionEquation]
      exact (measure.union_le (event index) (⋃ selected ∈ indices, event selected)).trans
        (by
          simpa [add_comm] using
            add_le_add_left induction (measure.probability (event index)))

end EventProbability

/-- Event set corresponding to one named extractor failure layer. -/
def failureEvent
    {Omega : Type*}
    (failure : FailureLayer -> Omega -> Prop)
    (layer : FailureLayer) : Set Omega :=
  { outcome | failure layer outcome }

/-- Event that at least one extraction layer fails. -/
def anyFailureEvent
    {Omega : Type*}
    (failure : FailureLayer -> Omega -> Prop) : Set Omega :=
  ⋃ layer ∈ allFailureLayers, failureEvent failure layer

/-- Per-layer estimates compose to one explicit bound for all extraction failures. -/
theorem any_failure_probability_le_sum
    {Omega : Type*}
    (measure : EventProbability Omega)
    (failure : FailureLayer -> Omega -> Prop)
    (bound : FailureLayer -> ℚ)
    (layerBound : ∀ layer ∈ allFailureLayers,
      measure.probability (failureEvent failure layer) ≤ bound layer) :
    measure.probability (anyFailureEvent failure) ≤
      ∑ layer ∈ allFailureLayers, bound layer := by
  calc
    measure.probability (anyFailureEvent failure) ≤
        ∑ layer ∈ allFailureLayers,
          measure.probability (failureEvent failure layer) := by
      exact measure.finite_iUnion_le_sum allFailureLayers (failureEvent failure)
    _ ≤ ∑ layer ∈ allFailureLayers, bound layer := by
      exact Finset.sum_le_sum layerBound

end FailureProbability

section PublishedActiveLoss

open Hegemon.Transaction.SmallWoodNoGrindingSoundness

/-- Four algebraic failure layers covered by the published active SmallWood estimate. -/
def publishedAlgebraicFailureLayers : Finset FailureLayer :=
  { .decsDegreeEnforcement,
    .piopBatching,
    .piopEvaluation,
    .decsOpeningSampling }

theorem published_algebraic_failure_layers_complete (layer : FailureLayer) :
    layer ∈ publishedAlgebraicFailureLayers ↔
      layer = .decsDegreeEnforcement ∨
      layer = .piopBatching ∨
      layer = .piopEvaluation ∨
      layer = .decsOpeningSampling := by
  cases layer <;> simp [publishedAlgebraicFailureLayers]

/-- Exact rational error assigned to each published algebraic extraction layer. -/
def publishedLayerLoss : FailureLayer -> ℚ
  | .decsDegreeEnforcement => (epsilon1Numerator : ℚ) / epsilon1Denominator
  | .piopBatching => (epsilon2Numerator : ℚ) / epsilon2Denominator
  | .piopEvaluation => (epsilon3Numerator : ℚ) / epsilon3Denominator
  | .decsOpeningSampling => (epsilon4Numerator : ℚ) / epsilon4Denominator
  | .hashOrMerkleBinding => 0
  | .productionOracleRefinement => 0

/-- The four published fractions equal their common-denominator expression. -/
private theorem four_fraction_common_denominator
    (n1 d1 n2 d2 n3 d3 n4 d4 : ℚ)
    (d1Nonzero : d1 ≠ 0)
    (d2Nonzero : d2 ≠ 0)
    (d3Nonzero : d3 ≠ 0)
    (d4Nonzero : d4 ≠ 0) :
    n1 / d1 + n2 / d2 + n3 / d3 + n4 / d4 =
      (n1 * d2 * d3 * d4 + n2 * d1 * d3 * d4 +
          n3 * d1 * d2 * d4 + n4 * d1 * d2 * d3) /
        (d1 * d2 * d3 * d4) := by
  field_simp

/-- The named active layer sum is exactly the checked aggregate rational. -/
theorem published_layer_loss_sum_exact :
    (∑ layer ∈ publishedAlgebraicFailureLayers, publishedLayerLoss layer) =
      (aggregateErrorNumerator : ℚ) / aggregateErrorDenominator := by
  have d1Positive : 0 < epsilon1Denominator := by decide
  have d2Positive : 0 < epsilon2Denominator := by decide
  have d3Positive : 0 < epsilon3Denominator := by decide
  have d4Positive : 0 < epsilon4Denominator := by decide
  have d1Nonzero : (epsilon1Denominator : ℚ) ≠ 0 := by exact_mod_cast d1Positive.ne'
  have d2Nonzero : (epsilon2Denominator : ℚ) ≠ 0 := by exact_mod_cast d2Positive.ne'
  have d3Nonzero : (epsilon3Denominator : ℚ) ≠ 0 := by exact_mod_cast d3Positive.ne'
  have d4Nonzero : (epsilon4Denominator : ℚ) ≠ 0 := by exact_mod_cast d4Positive.ne'
  simpa [publishedAlgebraicFailureLayers, publishedLayerLoss,
    aggregateErrorNumerator, aggregateErrorDenominator, Nat.cast_add, Nat.cast_mul,
    add_assoc] using
    four_fraction_common_denominator
      (epsilon1Numerator : ℚ) epsilon1Denominator
      (epsilon2Numerator : ℚ) epsilon2Denominator
      (epsilon3Numerator : ℚ) epsilon3Denominator
      (epsilon4Numerator : ℚ) epsilon4Denominator
      d1Nonzero d2Nonzero d3Nonzero d4Nonzero

/-- Convert an exact natural-number scaled bound to its rational probability form. -/
theorem rational_ratio_le_inverse_of_scaled_le
    {numerator denominator scale : Nat}
    (denominatorPositive : 0 < denominator)
    (scalePositive : 0 < scale)
    (scaledBound : scale * numerator ≤ denominator) :
    (numerator : ℚ) / denominator ≤ 1 / scale := by
  apply (div_le_div_iff₀ (by exact_mod_cast denominatorPositive)
    (by exact_mod_cast scalePositive)).2
  norm_cast
  simpa [Nat.mul_comm] using scaledBound

/-- The published active algebraic layer sum is at most one in two to the 128. -/
theorem active_published_layer_loss_at_most_128_bits :
    (∑ layer ∈ publishedAlgebraicFailureLayers, publishedLayerLoss layer) ≤
      (1 : ℚ) / 2 ^ 128 := by
  rw [published_layer_loss_sum_exact]
  exact rational_ratio_le_inverse_of_scaled_le
    (by decide : 0 < aggregateErrorDenominator)
    (by positivity : 0 < 2 ^ 128)
    active_single_query_aggregate_error_supports_128_bits

/-- The published four-term estimate intentionally excludes hash and executable refinement loss. -/
theorem published_loss_excludes_external_layers :
    .hashOrMerkleBinding ∉ publishedAlgebraicFailureLayers ∧
      .productionOracleRefinement ∉ publishedAlgebraicFailureLayers := by
  simp [publishedAlgebraicFailureLayers]

end PublishedActiveLoss

end HegemonCrypto.SmallWood.Extraction
