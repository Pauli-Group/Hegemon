import SmzaRp05CurrentHistoryExtractionFailureEndpoint
import SmzaRp05CurrentHistoryCertificateMass
import SmzaRp05CurrentHistorySelectedStageExtraction
import SmzaRp05CurrentHistoryFailureMass
import SmzaRp05OriginalBornOutcomeMass
import SmzaRp05OriginalMassLossJoin
import SmzaRp05ActualAcceptedAuthorizationEndpoint

/-! # Original-measure composition for initialized history failure

This consumer joins the global extraction-failure event and the canonical
empty-genesis source-ledger failure on the literal original branch/basis
measure. Rejected history branches keep their original weight and receive no
selected blocks; no acceptance-conditioned distribution is introduced.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentInitializedHistoryMassEndpoint

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation (RegisterBasis partialRandomOracleState)
open SmzaRp05CurrentHistoryVerifierProgram (HistoryStage historyProgram)
open SmzaRp05CurrentHistoryFailureMass (historyFailureEvent)
open SmzaRp05CurrentHistoryExtractionFailureEndpoint
  (actual_accepted_history_extraction_outcome_mass_below_130_bits)
open SmzaRp05CurrentHistorySelectedStageExtraction
  (CurrentHistoryOriginalOutcome CurrentHistoryBlockLayout
    currentHistoryBlockLayoutStageCount canonicalCurrentSelectedHistoryBlocks?)
open SmzaRp05CurrentHistoryCertificateMass
  (currentHistoryGenesisChargedFailureEvent
    currentHistoryGenesisPathNoteCommitmentGameEvent
    currentHistoryGenesisPathMerkleCompressionGameEvent
    currentHistoryGenesisComparisonOutput currentHistoryGenesis_mass_le_path_and_games)
open SmzaRp05CurrentAuthorizationCertificate
  (outcomeEventMass nullifierPrimitiveEvent
    singleKeyPrimitiveEvent accumulatorPrimitiveEvent mixedClawPrimitiveEvent)
open SmzaRp05ActualAcceptedAuthorizationEndpoint (certificateOutput)
open SmzaRp05OriginalBornOutcomeMass
  (originalOutcomeWeight original_outcome_weight_nonnegative)
open SmzaRp05OriginalMassLossJoin (outcome_mass_union_le_add)
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
open SmzaRp05GeneratedCertificates (currentDsl)
open V8SmzaOracleParser (RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification (V8PublicStatement)
open SmzaRp05CurrentHistoryVerifierProgram (HistoryStage)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 18000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/-- The actual parsed public history, initialized ordinary execution, exact
block partition, and six induced-game advantage bounds control the union of
the 130-bit global extraction event and the canonical source-ledger event.
The blocks and weights are constructed internally from each original outcome;
rejected branches are mapped to the empty block list by `getD []`. -/
theorem actual_current_initialized_history_failure_mass_bound
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (typed : ∀ _i : Fin stages.length, V8PublicStatement)
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
    let blocksForOriginalOutcome := fun (outcome :
        CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages) =>
      (canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
        stages commonNs stageNsEq typed parsed model current_model_within_protocol
        fallback outcome layout layoutCoversHistory).getD []
    ∀ (epsilonNoteCommitment epsilonMerkle epsilonNullifier epsilonSingle
      epsilonAccumulator epsilonMixed : ℝ),
    (noteBound : outcomeEventMass mass
      (currentHistoryGenesisPathNoteCommitmentGameEvent blocksForOriginalOutcome) ≤
        epsilonNoteCommitment) →
    (merkleBound : outcomeEventMass mass
      (currentHistoryGenesisPathMerkleCompressionGameEvent blocksForOriginalOutcome) ≤
        epsilonMerkle) →
    (nullifierBound : outcomeEventMass mass
      (nullifierPrimitiveEvent (certificateOutput
        (currentHistoryGenesisComparisonOutput blocksForOriginalOutcome))) ≤
        epsilonNullifier) →
    (singleBound : outcomeEventMass mass
      (singleKeyPrimitiveEvent (certificateOutput
        (currentHistoryGenesisComparisonOutput blocksForOriginalOutcome))) ≤
        epsilonSingle) →
    (accumulatorBound : outcomeEventMass mass
      (accumulatorPrimitiveEvent (certificateOutput
        (currentHistoryGenesisComparisonOutput blocksForOriginalOutcome))) ≤
        epsilonAccumulator) →
    (mixedBound : outcomeEventMass mass
      (mixedClawPrimitiveEvent (certificateOutput
        (currentHistoryGenesisComparisonOutput blocksForOriginalOutcome))) ≤
        epsilonMixed) →
    outcomeEventMass mass (fun outcome =>
      (branchResult groupedDecode program outcome.1 = some () ∧
        historyFailureEvent (BaseWork := BaseWork) stages commonNs stageNsEq
          fallback typed 28 model current_model_within_protocol
          outcome.1 outcome.2.database) ∨
      currentHistoryGenesisChargedFailureEvent blocksForOriginalOutcome outcome) <
      ((1 / (2 : Rat) ^ 130 : Rat) : ℝ) + epsilonNoteCommitment + epsilonMerkle +
        epsilonNullifier + epsilonSingle + epsilonAccumulator + epsilonMixed := by
  classical
  intro _program _model _initial _mass _blocksForOriginalOutcome
    epsilonNoteCommitment epsilonMerkle epsilonNullifier epsilonSingle
    epsilonAccumulator epsilonMixed noteBound merkleBound nullifierBound singleBound
    accumulatorBound mixedBound
  let program := historyProgram stages
  let model := relationModel currentDsl SmzaRp05GeneratedCertificates.certificates
  let initial := ordinaryRun ordinaryProgram
    (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)
  letI := physicalBranchesFintype groupedDecode program
  let mass := originalOutcomeWeight
    (fun branch => physicalRun (encode program) groupedDecode program branch initial)
  let blocksForOriginalOutcome := fun (outcome :
      CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages) =>
    (canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
      stages commonNs stageNsEq typed parsed model current_model_within_protocol
      fallback outcome layout layoutCoversHistory).getD []
  let extractionFailure := fun outcome : CurrentHistoryOriginalOutcome
      (BaseWork := BaseWork) stages =>
    branchResult groupedDecode program outcome.1 = some () ∧
      historyFailureEvent (BaseWork := BaseWork) stages commonNs stageNsEq
        fallback typed 28 model current_model_within_protocol
        outcome.1 outcome.2.database
  have massNonnegative : ∀ outcome, 0 ≤ mass outcome := by
    intro outcome
    exact original_outcome_weight_nonnegative
      (fun branch => physicalRun (encode program) groupedDecode program branch initial)
      outcome
  have extractionBound : outcomeEventMass mass extractionFailure <
      ((1 / (2 : Rat) ^ 130 : Rat) : ℝ) := by
    exact actual_accepted_history_extraction_outcome_mass_below_130_bits
      (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed fallback
      ordinaryProgram registers incomingUnit queriesWithin capBound
  have genesisBound := currentHistoryGenesis_mass_le_path_and_games
    blocksForOriginalOutcome mass massNonnegative epsilonNoteCommitment epsilonMerkle
    epsilonNullifier epsilonSingle epsilonAccumulator epsilonMixed
    noteBound merkleBound nullifierBound singleBound accumulatorBound mixedBound
  have unionBound := outcome_mass_union_le_add mass massNonnegative extractionFailure
    (currentHistoryGenesisChargedFailureEvent blocksForOriginalOutcome)
  have arithmetic :
      outcomeEventMass mass extractionFailure +
        outcomeEventMass mass
          (currentHistoryGenesisChargedFailureEvent blocksForOriginalOutcome) <
        ((1 / (2 : Rat) ^ 130 : Rat) : ℝ) + epsilonNoteCommitment + epsilonMerkle +
          epsilonNullifier + epsilonSingle + epsilonAccumulator + epsilonMixed := by
    linarith
  exact lt_of_le_of_lt unionBound arithmetic

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentInitializedHistoryMassEndpoint
