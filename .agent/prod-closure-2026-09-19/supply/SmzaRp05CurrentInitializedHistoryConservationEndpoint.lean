import SmzaRp05CurrentInitializedHistoryMassEndpoint
import SmzaRp05CurrentPublicHistoryAdmission
import SmzaRp05ActualAcceptedAuthorizationEndpoint

/-! # Conservation for the actual initialized accepted public history

Public acceptance is computed from parsed public transactions and unchanged
coinbase data. Every source-ledger envelope is recovered from the same original
verifier outcome. The failure event is charged to global extraction or to the
actual first source-input failure, on the literal original Born measure.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentInitializedHistoryConservationEndpoint

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation (RegisterBasis partialRandomOracleState)
open SmzaRp05CurrentSourceLedgerPrefix
open SmzaRp05CurrentSourceLedgerRunner
open SmzaRp05CurrentSourceLedgerTransitions
open SmzaRp05CurrentPublicHistoryAdmission
open SmzaRp05CurrentHistoryVerifierProgram (HistoryStage historyProgram)
open SmzaRp05CurrentHistoryFailureMass (historyFailureEvent)
open SmzaRp05CurrentHistorySelectedStageExtraction
  (CurrentHistoryOriginalOutcome CurrentHistoryBlockLayout
    currentHistoryBlockLayoutStageCount canonicalCurrentSelectedHistoryBlocks?
    packCanonicalCurrentPublicBlocks
    canonicalCurrentSelectedHistoryBlocks?_accepted_public_views
    canonicalCurrentSelectedHistoryBlocks?_block_stages_envelopes_present_of_no_history_failure)
open SmzaRp05CurrentHistoryCertificateMass
  (currentHistoryGenesisChargedFailureEvent
    currentHistoryGenesisPathNoteCommitmentGameEvent
    currentHistoryGenesisPathMerkleCompressionGameEvent
    currentHistoryGenesisComparisonOutput)
open SmzaRp05CurrentAuthorizationCertificate
  (outcomeEventMass nullifierPrimitiveEvent
    singleKeyPrimitiveEvent accumulatorPrimitiveEvent mixedClawPrimitiveEvent)
open SmzaRp05ActualAcceptedAuthorizationEndpoint (certificateOutput)
open SmzaRp05OriginalBornOutcomeMass
  (originalOutcomeWeight original_outcome_weight_nonnegative)
open SmzaRp05CurrentInitializedHistoryMassEndpoint
  (actual_current_initialized_history_failure_mass_bound)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05GroupedSuffix (GroupCounter)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult physicalRun)
open SmzaRp05OrdinarySoundnessExecution (OrdinaryPrefix ordinaryRun)
open SmzaRp05AdaptivePhysicalReadBound (physicalBranchesFintype)
open SmzaRp05CurrentAdaptiveExecution (Work)
open SmzaRp05SourceReadSchedule (readBudget)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentProtocolModelBound (current_model_within_protocol)
open SmzaRp05RelationRefinement (relationModel)
open SmzaRp05TracePrefixes (RelationModel)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05GeneratedCertificates (currentDsl)
open V8SmzaOracleParser (RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification (V8PublicStatement)
open SmzaFiniteLedgerSupply (potential allowance wealth)
open Hegemon.Consensus (maxMonetarySupply)
open SmzaRp05HistoricalTree (openingAt)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 18000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/-- An actual generated successful history, including its final native/source
trace and the lifetime cap at the exact final live-note registry. -/
def generatedGenesisHistoryConserved
    (blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))) : Prop :=
  ∃ (final : CurrentSourceLedgerPrefix)
    (trace : CurrentSelectedHistoryTrace (BaseWork := BaseWork)
      blocks initialCurrentSourceLedgerPrefix final)
    (boundary : final.stagedOpenings = final.snapshot.openings)
    (invariant : potential (openingAt final.stagedOpenings) final.ledger ≤
      allowance final.ledger),
    executeSelectedCurrentHistoryFromGenesis blocks =
      .complete trace boundary invariant ∧
    wealth (openingAt final.stagedOpenings) final.ledger.live ≤ maxMonetarySupply

private theorem generated_conservation_of_actual_complete
    (blocks : List (CurrentSelectedBlock (BaseWork := BaseWork)))
    (complete : ∃ (final : CurrentSourceLedgerPrefix)
      (trace : CurrentSelectedHistoryTrace (BaseWork := BaseWork)
        blocks initialCurrentSourceLedgerPrefix final)
      (boundary : final.stagedOpenings = final.snapshot.openings)
      (invariant : potential (openingAt final.stagedOpenings) final.ledger ≤
        allowance final.ledger),
      executeSelectedCurrentHistoryFromGenesis blocks =
        .complete trace boundary invariant) :
    generatedGenesisHistoryConserved blocks := by
  rcases complete with ⟨final, trace, boundary, invariant, actual⟩
  exact ⟨final, trace, boundary, invariant, actual,
    selected_history_invariant_implies_live_cap
      (BaseWork := BaseWork) (_blocks := blocks) invariant⟩

/-- A failure of generated conservation for an accepted canonical public
history is in the shared extraction event or its actual charged source-input
event. Native/coinbase rejection is excluded by the public executor and exact
receipt-prefix linkage, not by a supplied successful ledger outcome. -/
theorem accepted_canonical_public_history_failure_in_union
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ i : Fin stages.length,
      parseCurrentPublicStatement? (stages[i.val]).statement = some (typed i))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length)
    (outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages)
    (accepted : branchResult groupedDecode (historyProgram stages) outcome.1 = some ())
    (publicAccepted : CurrentPublicHistoryAccepted
      (packCanonicalCurrentPublicBlocks layout (List.ofFn typed)))
    (notConserved : ¬ generatedGenesisHistoryConserved
      ((canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
        stages commonNs stageNsEq typed parsed model bounded fallback
        outcome layout layoutCoversHistory).getD [])) :
    historyFailureEvent (BaseWork := BaseWork) stages commonNs stageNsEq
      fallback typed 28 model bounded outcome.1 outcome.2.database ∨
    currentHistoryGenesisChargedFailureEvent
      (fun original : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages =>
        (canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
          stages commonNs stageNsEq typed parsed model bounded fallback
          original layout layoutCoversHistory).getD []) outcome := by
  classical
  by_cases failure : historyFailureEvent (BaseWork := BaseWork) stages commonNs
      stageNsEq fallback typed 28 model bounded outcome.1 outcome.2.database
  · exact Or.inl failure
  · right
    let blocks := (canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
      stages commonNs stageNsEq typed parsed model bounded fallback
      outcome layout layoutCoversHistory).getD []
    have views := canonicalCurrentSelectedHistoryBlocks?_accepted_public_views
      (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed model bounded
      fallback outcome layout layoutCoversHistory accepted
    have blocksAccepted : CurrentPublicHistoryAccepted
        (blocks.map selectedBlockPublicView) := by
      rw [show blocks.map selectedBlockPublicView =
        packCanonicalCurrentPublicBlocks layout (List.ofFn typed) from views]
      exact publicAccepted
    have present :=
      canonicalCurrentSelectedHistoryBlocks?_block_stages_envelopes_present_of_no_history_failure
        (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed model bounded
        fallback outcome layout layoutCoversHistory accepted failure
    rcases public_history_acceptance_complete_or_charged
        blocks blocksAccepted present with complete | charged
    · exact False.elim (notConserved (generated_conservation_of_actual_complete
        blocks complete))
    · exact charged

private theorem event_mass_mono
    {Outcome : Type} [Fintype Outcome]
    (mass : Outcome → ℝ) (nonnegative : ∀ outcome, 0 ≤ mass outcome)
    (left right : Outcome → Prop) (included : ∀ outcome, left outcome → right outcome) :
    outcomeEventMass mass left ≤ outcomeEventMass mass right := by
  classical
  unfold outcomeEventMass
  apply Finset.sum_le_sum
  intro outcome _
  by_cases leftOccurs : left outcome
  · have rightOccurs := included outcome leftOccurs
    simp [leftOccurs, rightOccurs]
  · by_cases rightOccurs : right outcome <;>
      simp [leftOccurs, rightOccurs, nonnegative outcome]

/-- Final current-history conservation reduction on the original initialized
execution. The event requires the actual verifier branch and public native
history to accept, but does not assume extraction, successful ghost replay,
input availability, invariants, conservation, or game-event coverage. The six
advantages are of the actual induced games on these same original outcomes.
The global extraction loss is charged once, not once per transaction. -/
theorem actual_current_initialized_history_conservation_failure_mass_bound
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ i : Fin stages.length,
      parseCurrentPublicStatement? (stages[i.val]).statement = some (typed i))
    (fallback : RawDigest)
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := Key (historyProgram stages))
      (Counter := GroupCounter) (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key (historyProgram stages))
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (incomingUnit : normSquared
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers) = 1)
    (queriesWithin : queries + readBudget groupedDecode (historyProgram stages) ≤ cap)
    (capBound : cap ≤ 3 * 2 ^ 64)
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length) :
    let program := historyProgram stages
    let model := relationModel currentDsl SmzaRp05GeneratedCertificates.certificates
    let initial := ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
    letI := physicalBranchesFintype groupedDecode program
    let mass := originalOutcomeWeight
      (fun branch => physicalRun (encode program) groupedDecode program branch initial)
    let blocks := fun outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages =>
      (canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
        stages commonNs stageNsEq typed parsed model current_model_within_protocol
        fallback outcome layout layoutCoversHistory).getD []
    ∀ (epsilonNoteCommitment epsilonMerkle epsilonNullifier epsilonSingle
      epsilonAccumulator epsilonMixed : ℝ),
    outcomeEventMass mass (currentHistoryGenesisPathNoteCommitmentGameEvent blocks) ≤
      epsilonNoteCommitment →
    outcomeEventMass mass (currentHistoryGenesisPathMerkleCompressionGameEvent blocks) ≤
      epsilonMerkle →
    outcomeEventMass mass (nullifierPrimitiveEvent
      (certificateOutput (currentHistoryGenesisComparisonOutput blocks))) ≤
      epsilonNullifier →
    outcomeEventMass mass (singleKeyPrimitiveEvent
      (certificateOutput (currentHistoryGenesisComparisonOutput blocks))) ≤
      epsilonSingle →
    outcomeEventMass mass (accumulatorPrimitiveEvent
      (certificateOutput (currentHistoryGenesisComparisonOutput blocks))) ≤
      epsilonAccumulator →
    outcomeEventMass mass (mixedClawPrimitiveEvent
      (certificateOutput (currentHistoryGenesisComparisonOutput blocks))) ≤
      epsilonMixed →
    outcomeEventMass mass (fun outcome =>
      branchResult groupedDecode program outcome.1 = some () ∧
      CurrentPublicHistoryAccepted
        (packCanonicalCurrentPublicBlocks layout (List.ofFn typed)) ∧
      ¬ generatedGenesisHistoryConserved (blocks outcome)) <
      ((1 / (2 : Rat) ^ 130 : Rat) : ℝ) + epsilonNoteCommitment + epsilonMerkle +
        epsilonNullifier + epsilonSingle + epsilonAccumulator + epsilonMixed := by
  classical
  intro _program _model _initial _mass _blocks
  let program := historyProgram stages
  let model := relationModel currentDsl SmzaRp05GeneratedCertificates.certificates
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  letI := physicalBranchesFintype groupedDecode program
  let mass := originalOutcomeWeight
    (fun branch => physicalRun (encode program) groupedDecode program branch initial)
  let blocks := fun outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages =>
    (canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
      stages commonNs stageNsEq typed parsed model current_model_within_protocol
      fallback outcome layout layoutCoversHistory).getD []
  intro epsilonNoteCommitment epsilonMerkle epsilonNullifier epsilonSingle
    epsilonAccumulator epsilonMixed noteBound merkleBound nullifierBound singleBound
    accumulatorBound mixedBound
  let bad := fun outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages =>
    branchResult groupedDecode program outcome.1 = some () ∧
      CurrentPublicHistoryAccepted
        (packCanonicalCurrentPublicBlocks layout (List.ofFn typed)) ∧
      ¬ generatedGenesisHistoryConserved (blocks outcome)
  let failures := fun outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages =>
    (branchResult groupedDecode program outcome.1 = some () ∧
      historyFailureEvent (BaseWork := BaseWork) stages commonNs stageNsEq
        fallback typed 28 model current_model_within_protocol
        outcome.1 outcome.2.database) ∨
      currentHistoryGenesisChargedFailureEvent blocks outcome
  have included : ∀ outcome, bad outcome → failures outcome := by
    intro outcome badOutcome
    rcases badOutcome with ⟨accepted, publicAccepted, notConserved⟩
    rcases accepted_canonical_public_history_failure_in_union
        (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed model
        current_model_within_protocol fallback layout layoutCoversHistory outcome
        accepted publicAccepted notConserved with extraction | charged
    · exact Or.inl ⟨accepted, extraction⟩
    · exact Or.inr charged
  have nonnegative : ∀ outcome, 0 ≤ mass outcome :=
    original_outcome_weight_nonnegative
      (fun branch => physicalRun (encode program) groupedDecode program branch initial)
  have monotone := event_mass_mono mass nonnegative bad failures included
  have bound := actual_current_initialized_history_failure_mass_bound
    (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed fallback
    ordinaryProgram registers incomingUnit queriesWithin capBound layout layoutCoversHistory
    epsilonNoteCommitment epsilonMerkle epsilonNullifier epsilonSingle epsilonAccumulator
    epsilonMixed noteBound merkleBound nullifierBound singleBound accumulatorBound mixedBound
  exact lt_of_le_of_lt monotone bound

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentInitializedHistoryConservationEndpoint
