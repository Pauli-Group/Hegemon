import HegemonCrypto.CmsAdaptiveClaimBridge
import HegemonCrypto.CmsFinitePhaseSystem
import HegemonCrypto.CmsLifting
import HegemonCrypto.SmallWoodCmsExtraction

/-!
# End-to-end finite-QROM extraction for active SmallWood

This module instantiates the proved CMS compressed-oracle machinery with the exact active
SmallWood logical transcript.  A final adversary workspace may adaptively select the verifier
query and oracle answer that certify an accepting transition without an extracted Hegemon
witness.  The theorem bounds that event by the round-by-round knowledge error, first database
collision probability, and one adaptive oracle/database claim.

No generic BCS/QROM theorem is assumed.  Replacing the ideal logical oracle by the deployed
domain-separated SHA-512 counter-mode sampler remains the explicit hash/XOF assumption.
-/

namespace HegemonCrypto.SmallWood.CmsQrom

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsFinitePhaseSystem
open HegemonCrypto.CmsLifting
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.CmsExtraction
open HegemonCrypto.SmallWood.LogicalOracle
open HegemonCrypto.SmallWood.ProductionBcsInstantiation
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.RoundByRound.Interactive

noncomputable section

set_option maxHeartbeats 0
set_option maxRecDepth 100000
set_option linter.unusedSectionVars false

local instance classicalPropDecidable (proposition : Prop) : Decidable proposition :=
  Classical.propDecidable proposition

noncomputable instance logicalOutputCardNeZero
    (statement : ActiveStatementType) :
    NeZero (Fintype.card (LogicalOutput statement)) :=
  ⟨Fintype.card_ne_zero⟩

/-- Concrete Fourier phase register for the active logical oracle output. -/
abbrev LogicalPhase (statement : ActiveStatementType) :=
  ZMod (Fintype.card (LogicalOutput statement))

/-- The full cyclic Fourier phase system, not a restricted phase-oracle interface. -/
noncomputable def activePhaseSystem (statement : ActiveStatementType) :
    PhaseSystem (LogicalOutput statement) (LogicalPhase statement) :=
  cyclicPhaseSystem (logicalOutputAddEquivZMod statement)

/-- Complete concrete Fourier model used by the active logical oracle. -/
noncomputable def activeCompletePhaseSystem
    (statement : ActiveStatementType) :
    CompletePhaseSystem
      (LogicalOutput statement) (LogicalPhase statement) :=
  cyclicCompletePhaseSystem (logicalOutputAddEquivZMod statement)

/-- One bad-database property covers either a first oracle collision or failed extraction. -/
def KnowledgeFailureProperty
    {statement : ActiveStatementType}
    (active : ActiveStatement statement) :
    Property (VerifierQuery statement) (LogicalOutput statement) :=
  union
    (HasCollision :
      Property (VerifierQuery statement) (LogicalOutput statement))
    (BadTransition active)

/--
The exact SmallWood instability is the sum of first-collision probability and the mechanized
interactive knowledge error.
-/
theorem knowledge_failure_instability
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (queryBound : Nat) :
    InstabilityBound
      (KnowledgeFailureProperty active)
      queryBound
      ((queryBound : Rat) / Fintype.card (LogicalOutput statement) +
        activeInteractiveKnowledgeError) := by
  exact collision_union_instability_bound
    (BadTransition active)
    queryBound
    (collision_instability_bound queryBound)
    (active_bad_transition_conditional_instability active queryBound)

/--
One final adversary workspace adaptively selects the oracle claim witnessing an accepting
false-to-true semantic transition for which deterministic extraction yields no valid witness.
-/
structure FailureSelector
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (Workspace : Type*) where
  enabled : Workspace -> Prop
  query : Workspace -> VerifierQuery statement
  output : Workspace -> LogicalOutput statement
  doomed : ∀ workspace, enabled workspace ->
    semanticState (queryPrefix active (query workspace)) = false
  accepted : ∀ workspace, enabled workspace ->
    semanticState
        (verifierExtension
          (queryPrefix active (query workspace))
          (queryChallenge active (query workspace) (output workspace))) =
      true
  noValidExtraction : ∀ workspace, enabled workspace ->
    NoValidExtraction active (query workspace)

def failureClaims
    {statement : ActiveStatementType}
    {active : ActiveStatement statement}
    {Workspace : Type*}
    (selector : FailureSelector active Workspace)
    (workspace : Workspace) :
    List (VerifierQuery statement × LogicalOutput statement) :=
  [(selector.query workspace, selector.output workspace)]

def FailureEvent
    {statement : ActiveStatementType}
    {active : ActiveStatement statement}
    {Workspace : Type*}
    (selector : FailureSelector active Workspace) :
    Workspace ->
      Database (VerifierQuery statement) (LogicalOutput statement) -> Prop :=
  AdaptiveClaimsEvent selector.enabled (failureClaims selector)

theorem failure_claim_inputs_nodup
    {statement : ActiveStatementType}
    {active : ActiveStatement statement}
    {Workspace : Type*}
    (selector : FailureSelector active Workspace)
    (workspace : Workspace) :
    ((failureClaims selector workspace).map Prod.fst).Nodup := by
  simp [failureClaims]

theorem failure_claim_length
    {statement : ActiveStatementType}
    {active : ActiveStatement statement}
    {Workspace : Type*}
    (selector : FailureSelector active Workspace)
    (workspace : Workspace) :
    (failureClaims selector workspace).length = 1 := by
  simp [failureClaims]

theorem failure_event_implies_knowledge_failure
    {statement : ActiveStatementType}
    {active : ActiveStatement statement}
    {Workspace : Type*}
    (selector : FailureSelector active Workspace)
    (workspace : Workspace)
    (database : Database (VerifierQuery statement) (LogicalOutput statement))
    (failure : FailureEvent selector workspace database) :
    KnowledgeFailureProperty active database := by
  rcases failure with ⟨enabled, records⟩
  apply Or.inr
  refine ⟨selector.query workspace, selector.output workspace, ?_,
    selector.doomed workspace enabled, selector.accepted workspace enabled,
    selector.noValidExtraction workspace enabled⟩
  exact records
    (selector.query workspace, selector.output workspace)
    (by simp [failureClaims])

theorem knowledge_failure_empty_false
    {statement : ActiveStatementType}
    (active : ActiveStatement statement) :
    ¬KnowledgeFailureProperty active
      (empty :
        Database (VerifierQuery statement) (LogicalOutput statement)) := by
  intro failure
  rcases failure with collision | transition
  · rcases collision with
      ⟨left, right, output, different, leftRecorded, _rightRecorded⟩
    simp at leftRecorded
  · rcases transition with
      ⟨query, output, recorded, _doomed, _accepted, _noExtraction⟩
    simp at recorded

theorem initial_knowledge_failure_project_eq_zero
    {statement : ActiveStatementType}
    {Phase : Type*}
    [Fintype Phase] [DecidableEq Phase]
    {Workspace : Type*}
    [Fintype Workspace] [DecidableEq Workspace]
    (active : ActiveStatement statement)
    (queryBound : Nat)
    (initialRegisters :
      RegisterBasis
        (Input := VerifierQuery statement)
        (Phase := Phase)
        (Workspace := Workspace) -> ℂ) :
    project (KnowledgeFailureProperty active) queryBound
        (partialRandomOracleState
          (Output := LogicalOutput statement) ∅ initialRegisters) =
      0 := by
  funext basis
  by_cases records :
      RecordsExactly (Output := LogicalOutput statement)
        ∅ basis.database
  · have databaseEmpty :
        basis.database =
          (empty :
            Database (VerifierQuery statement) (LogicalOutput statement)) :=
      (records_exactly_empty_iff basis.database).mp records
    simp [project, databaseEmpty,
      size_empty, knowledge_failure_empty_false active]
  · simp [project, partialRandomOracleState, records]

/-- Exact real instability used by the concrete finite-QROM theorem. -/
def activeInstability
    (statement : ActiveStatementType)
    (queries : Nat) : ℝ :=
  ((((queries : Rat) / Fintype.card (LogicalOutput statement)) +
      activeInteractiveKnowledgeError : Rat) : ℝ)

theorem knowledge_failure_real_instability
    {statement : ActiveStatementType}
    (active : ActiveStatement statement)
    (queryBound : Nat) :
    RealInstabilityBound
      (KnowledgeFailureProperty active)
      queryBound
      (activeInstability statement queryBound) := by
  unfold activeInstability
  exact (knowledge_failure_instability active queryBound).toReal

/-- One adaptive logical-oracle claim contributes `1 / |LogicalOutput|`. -/
def activeBridgeLoss
    (statement : ActiveStatementType) : ℝ :=
  1 / (Fintype.card (LogicalOutput statement) : ℝ)

/-- Final ideal logical-QROM extraction-failure bound. -/
def activeQromFailureBound
    (statement : ActiveStatementType)
    (queries : Nat) : ℝ :=
  oracleLoss
    (databaseLoss queries (activeInstability statement queries))
    (activeBridgeLoss statement)

/--
Final finite-QROM knowledge theorem.

For every finite quantum adversary computation and every adaptive final-workspace selector,
the probability that its selected transcript accepts while deterministic SmallWood extraction
has no valid Hegemon witness is at most `activeQromFailureBound`.
-/
theorem accepts_and_no_valid_witness_probability_le
    {statement : ActiveStatementType}
    {Phase : Type*}
    [Fintype Phase] [DecidableEq Phase]
    {Workspace : Type*}
    [Fintype Workspace] [DecidableEq Workspace]
    (active : ActiveStatement statement)
    (completePhaseSystem :
      CompletePhaseSystem (LogicalOutput statement) Phase)
    (steps : List (DatabaseIndependentContraction
      (Input := VerifierQuery statement)
      (Output := LogicalOutput statement)
      (Phase := Phase)
      (Workspace := Workspace)))
    (initialRegisters :
      RegisterBasis
        (Input := VerifierQuery statement)
        (Phase := Phase)
        (Workspace := Workspace) -> ℂ)
    (initialSubnormalized :
      Subnormalized
        (partialRandomOracleState
          (Output := LogicalOutput statement) ∅ initialRegisters))
    (selector : FailureSelector active Workspace) :
    normSquared
        (workspaceEventProjection (FailureEvent selector)
          (totalOracleFamilyState
            (oracleFamilyRun completePhaseSystem.system steps
              (fun _oracle => initialRegisters)))) <=
      activeQromFailureBound statement steps.length := by
  let system := completePhaseSystem.system
  let blindSteps :=
    steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let initialState :=
    partialRandomOracleState
      (Output := LogicalOutput statement) ∅ initialRegisters
  let compressedState :=
    rawRun system steps.length blindSteps initialState
  let family :=
    oracleFamilyRun system steps (fun _oracle => initialRegisters)
  have initialBounded : BoundedState 0 initialState := by
    exact partial_random_oracle_empty_bounded initialRegisters
  have capacity : blindSteps.length <= steps.length := by
    simp [blindSteps]
  have simulation :
      globalDecompress compressedState =
        totalOracleFamilyState family := by
    exact compressed_run_is_uniform_random_oracle_purification
      system steps.length steps initialRegisters (by simp)
  have compressedBounded :
      BoundedState steps.length compressedState := by
    exact raw_run_bounded_of_bounded
      system steps.length blindSteps initialState 0
        (by simpa using capacity) initialBounded
  have compressedSubnormalized :
      Subnormalized compressedState := by
    exact raw_run_subnormalized_of_bounded
      system steps.length blindSteps initialState 0
        (by simpa using capacity) initialBounded initialSubnormalized
  have databaseGame :
      normSquared
          (project (KnowledgeFailureProperty active) steps.length
            compressedState) <=
        databaseLoss steps.length
          (activeInstability statement steps.length) := by
    have lifted :=
      implemented_raw_database_game_le_database_loss
        system
        (KnowledgeFailureProperty active)
        steps.length
        blindSteps
        initialState
        (knowledge_failure_real_instability active steps.length)
        capacity
        initialBounded
        initialSubnormalized
        (initial_knowledge_failure_project_eq_zero
          active steps.length initialRegisters)
    have blindLength : blindSteps.length = steps.length := by
      simp [blindSteps]
    rw [blindLength] at lifted
    exact lifted
  have transferred :=
    adaptive_claims_probability_le
      compressedState
      family
      simulation
      selector.enabled
      (failureClaims selector)
      (failure_claim_inputs_nodup selector)
      1
      (by
        intro workspace
        rw [failure_claim_length selector workspace])
      (KnowledgeFailureProperty active)
      (failure_event_implies_knowledge_failure selector)
      steps.length
      compressedBounded
      compressedSubnormalized
      (databaseLoss steps.length
        (activeInstability statement steps.length))
      databaseGame
  have bridgeEq :
      ((1 : Nat) : ℝ) ^ 2 *
          (1 / (Fintype.card (LogicalOutput statement) : ℝ)) =
        activeBridgeLoss statement := by
    unfold activeBridgeLoss
    rw [Nat.cast_one, one_pow, one_mul]
  change
    normSquared
        (workspaceEventProjection
          (AdaptiveClaimsEvent selector.enabled (failureClaims selector))
          (totalOracleFamilyState family)) <=
      oracleLoss
        (databaseLoss steps.length
          (activeInstability statement steps.length))
        (activeBridgeLoss statement)
  rw [← bridgeEq]
  exact transferred

end

end HegemonCrypto.SmallWood.CmsQrom
