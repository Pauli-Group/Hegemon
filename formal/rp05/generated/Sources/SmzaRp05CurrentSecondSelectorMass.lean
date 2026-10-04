import SmzaRp05CurrentJointAuthorizationEndpoint
import SmzaRp05CurrentAcceptedMassToScalar
import SmzaRp05CurrentProtocolModelBound
import SmzaRp05OriginalBornOutcomeMass
import SmzaRp05CurrentJointExtractionPrograms
import SmzaRp05CmsEventEqualityTransport
import SmzaRp05CmsKeyEqualityTransport
import SmzaRp05ExecutableProgramEquality
import SmzaRp05FiniteSumEqualityTransport
import HegemonCrypto.CmsAdaptiveClaimBridge

/-! # Direct marginal for the second accepted selector

The target-2 program is the original chronological joint program itself.
This adapter derives its empty-authorization grouped context and expresses
the accepted selector projection as an event mass on the original branch and
basis outcomes, retaining the unnormalized physical state.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSecondSelectorMass

open HegemonCrypto.CmsCompressedOracle (State Basis normSquared)
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05CurrentJointAuthorizationEndpoint
  (currentJointSecondSelectorFailure)
open SmzaRp05CurrentJointAcceptedExecution
  (secondAcceptedVerifierProgram secondProducerAfterFirst)
open SmzaRp05CurrentJointExtractionPrograms
  (actualProgram_secondTarget_eq_joint secondTarget_key_eq_joint)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentAcceptedMassToScalar (currentAcceptedMassContexts)
open SmzaRp05CurrentProtocolModelBound (current_model_within_protocol)
open SmzaRp05CurrentFullOrRoleXViewCoverage
  (currentAcceptedXViewFullSuccessSelector)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05ConditionedExecution (xView)
open SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05CurrentAcceptedMassToScalar (currentAcceptedMassContexts)
open SmzaRp05RelationRefinement (relationModel)
open SmzaRp05GeneratedCertificates (currentDsl certificates)
open SmzaRp05CurrentJointObserverMass (branchesFintype)
open SmzaRp05ExecutableProgramEquality
  (castProgramBranch branchResult_cast_program physicalRun_cast_program)
open SmzaRp05CmsKeyEqualityTransport (physicalRun_cast_input)
open SmzaRp05FiniteSumEqualityTransport (sum_cast_program_eq)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult physicalRun)
open SmzaRp05OriginalBornOutcomeMass
  (originalOutcomeWeight original_accepted_event_mass_eq_projection_sum)
open SmzaRp05CurrentAuthorizationCertificate (outcomeEventMass)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05GroupedSuffix (GroupCounter)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8SmzaOracleParser (RawDigest)
open SmzaChallengeStageTargets (Role)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification (V8PublicStatement)
open SmzaRp05CmsEventEqualityTransport
  (databaseTypeEq stateTypeEq workspaceEventProjection_normSquared_cast_input)
open scoped Classical BigOperators

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

private theorem encode_cast_program_eq {α : Type} (p q : Program α)
    (h : p = q) (raw : V8SmzaOracleParser.RawInput) :
    cast (congrArg Key h) (encode p raw) = encode q raw := by
  cases h
  rfl

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl

/-- The target-2 selector loss on one actual target-2 branch and its terminal
state. Its empty-authorization grouped context is derived by the exported
theorem below, not supplied as a hypothesis. -/
private noncomputable def secondTargetSelectorBranchMass
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (fallback₂ : RawDigest) (typed₂ : V8PublicStatement) (fuel₂ : Nat)
    (ctx₂ : Context (Key := Key (actualProgram
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
      ns₂ statement₂ pending₂ nonce₂)) (Counter := GroupCounter)
      (BaseWork := BaseWork))
    (branch : Branches groupedDecode (actualProgram
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
      ns₂ statement₂ pending₂ nonce₂))
    (state : State (Key (actualProgram
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
      ns₂ statement₂ pending₂ nonce₂)) (VectorOutput GroupCounter)
      (VectorOutput GroupCounter)
      (Work (Counter := GroupCounter) (BaseWork := BaseWork))) : ℝ :=
  if branchResult groupedDecode (actualProgram
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
      ns₂ statement₂ pending₂ nonce₂) branch = some () then
    normSquared (workspaceEventProjection
      (fun _work database =>
        ¬ currentAcceptedXViewFullSuccessSelector
          (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
          ns₂ statement₂ pending₂ nonce₂ fallback₂ typed₂ fuel₂ ctx₂ branch
          (xView (nonchallengeRawKeySet ctx₂) database)) state)
  else 0

/-- The direct second-target selector projection sum equals its failure event
mass on the original joint branch/basis outcome space. The context is exactly
the current empty-advice `.decsMatrix` context at fuel 28/28, derived from the
accepted target-2 producer and current model bound. -/
theorem current_joint_second_selector_mass_eq_event_mass
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (fallback₂ : RawDigest) (typed₂ : V8PublicStatement) (fuel₂ : Nat)
    (state : State (Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂))
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (Work (Counter := GroupCounter) (BaseWork := BaseWork))) :
    let model := relationModel currentDsl certificates
    let bounded := current_model_within_protocol
    let advice : ∀ role : Role, AllEarlierTables model role :=
      fun _role => fun _ _ _ _ => none
    let joint := secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    let target := actualProgram
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
      ns₂ statement₂ pending₂ nonce₂
    letI := branchesFintype groupedDecode joint
    letI := branchesFintype groupedDecode target
    let ctx₂ := (currentAcceptedMassContexts (BaseWork := BaseWork)
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
      ns₂ statement₂ pending₂ nonce₂ model bounded advice 28 28)
      SmzaChallengeStageTargets.Role.decsMatrix
    let targetKeyEq := secondTarget_key_eq_joint producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    let targetState := cast (congrArg (fun key => State key
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (Work (BaseWork := BaseWork))) targetKeyEq.symm) state
    (∑ targetBranch : Branches groupedDecode target,
       secondTargetSelectorBranchMass (BaseWork := BaseWork)
         producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
         nonce₁ nonce₂ fallback₂ typed₂ fuel₂ ctx₂ targetBranch
         (physicalRun (encode target) groupedDecode target targetBranch targetState)) =
    outcomeEventMass
      (originalOutcomeWeight (fun branch =>
        physicalRun (encode joint) groupedDecode joint branch state))
      (currentJointSecondSelectorFailure (BaseWork := BaseWork)
        producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
        nonce₁ nonce₂ fallback₂ typed₂ fuel₂ ctx₂) := by
  classical
  let model := relationModel currentDsl certificates
  let bounded := current_model_within_protocol
  let advice : ∀ role : Role, AllEarlierTables model role :=
    fun _role => fun _ _ _ _ => none
  let joint := secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  let target := actualProgram
    (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
    ns₂ statement₂ pending₂ nonce₂
  let ctx₂ := (currentAcceptedMassContexts (BaseWork := BaseWork)
    (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
    ns₂ statement₂ pending₂ nonce₂ model bounded advice 28 28)
    SmzaChallengeStageTargets.Role.decsMatrix
  let targetKeyEq := secondTarget_key_eq_joint producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  let targetState := cast (congrArg (fun key => State key
    (VectorOutput GroupCounter) (VectorOutput GroupCounter)
    (Work (BaseWork := BaseWork))) targetKeyEq.symm) state
  let targetProgramEq := actualProgram_secondTarget_eq_joint producer₁ producer₂
    ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  let sameInput := targetKeyEq.symm
  have sameEncode : ∀ raw, encode target raw = cast sameInput (encode joint raw) := by
    intro raw
    have keyEq := congrArg Key targetProgramEq.symm
    have sameInputProof : sameInput = keyEq :=
      Subsingleton.elim _ _
    rw [sameInputProof]
    exact (encode_cast_program_eq joint target targetProgramEq.symm raw).symm
  let targetBranchOf (branch : Branches groupedDecode joint) :=
    castProgramBranch groupedDecode joint target targetProgramEq.symm branch
  let selectorFailureOnJoint := fun (branch : Branches groupedDecode joint)
      (work : Work (Counter := GroupCounter) (BaseWork := BaseWork))
      (database : Database (Key joint) (VectorOutput GroupCounter)) =>
    ¬ currentAcceptedXViewFullSuccessSelector
      (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
      ns₂ statement₂ pending₂ nonce₂ fallback₂ typed₂ fuel₂ ctx₂ (targetBranchOf branch)
      (xView (nonchallengeRawKeySet ctx₂)
        (cast (databaseTypeEq targetKeyEq.symm) database))
  let states := fun branch : Branches groupedDecode joint =>
    physicalRun (encode joint) groupedDecode joint branch state
  let accepted := fun branch : Branches groupedDecode joint =>
    branchResult groupedDecode joint branch = some ()
  letI : ∀ branch, Decidable (accepted branch) := fun _ => Classical.propDecidable _
  letI := branchesFintype groupedDecode joint
  letI := branchesFintype groupedDecode target
  have originalEventSum := original_accepted_event_mass_eq_projection_sum
    states accepted selectorFailureOnJoint
  let targetMass : Branches groupedDecode target → ℝ := fun targetBranch =>
    secondTargetSelectorBranchMass (BaseWork := BaseWork)
      producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
      nonce₁ nonce₂ fallback₂ typed₂ fuel₂ ctx₂ targetBranch
      (physicalRun (encode target) groupedDecode target targetBranch targetState)
  let jointMass : Branches groupedDecode joint → ℝ := fun branch =>
    if accepted branch then
      normSquared (workspaceEventProjection (selectorFailureOnJoint branch)
        (states branch))
    else 0
  have projectionTransport (branch : Branches groupedDecode joint) :
      jointMass branch = targetMass (targetBranchOf branch) := by
    by_cases branchAccepted : branchResult groupedDecode joint branch = some ()
    · have targetAccepted : branchResult groupedDecode target (targetBranchOf branch) = some () := by
        simpa only [targetBranchOf, branchResult_cast_program] using branchAccepted
      have runTransport :
          physicalRun (encode target) groupedDecode target (targetBranchOf branch)
              targetState =
            cast (stateTypeEq sameInput) (states branch) := by
        calc
          _ = physicalRun (encode target) groupedDecode joint branch targetState :=
            physicalRun_cast_program (encode target) groupedDecode joint target
              targetProgramEq.symm branch targetState
          _ = cast (stateTypeEq sameInput) (states branch) := by
            simpa only [states, targetState, sameInput] using
              (physicalRun_cast_input sameInput (encode joint) (encode target)
                sameEncode groupedDecode joint branch state).symm
      have eventTransport := workspaceEventProjection_normSquared_cast_input
        sameInput (selectorFailureOnJoint branch)
        (fun _work database =>
          ¬ currentAcceptedXViewFullSuccessSelector
            (secondProducerAfterFirst producer₁ producer₂ ns₁ statement₁ pending₁ nonce₁)
            ns₂ statement₂ pending₂ nonce₂ fallback₂ typed₂ fuel₂ ctx₂
            (targetBranchOf branch) (xView (nonchallengeRawKeySet ctx₂) database))
        (by intro _work database; rfl) (states branch)
      rw [show jointMass branch = normSquared
        (workspaceEventProjection (selectorFailureOnJoint branch) (states branch)) by
          simp [jointMass, accepted, branchAccepted]]
      dsimp [targetMass, secondTargetSelectorBranchMass]
      rw [if_pos targetAccepted, runTransport]
      exact eventTransport.symm
    · have targetRejected : branchResult groupedDecode target (targetBranchOf branch) ≠ some () := by
        intro targetAccepted
        apply branchAccepted
        simpa only [targetBranchOf, branchResult_cast_program] using targetAccepted
      rw [show jointMass branch = 0 by simp [jointMass, accepted, branchAccepted]]
      dsimp [targetMass, secondTargetSelectorBranchMass]
      rw [if_neg targetRejected]
  have targetSumEqJoint :
      (∑ targetBranch : Branches groupedDecode target, targetMass targetBranch) =
        ∑ branch : Branches groupedDecode joint, jointMass branch := by
    calc
      _ = ∑ branch : Branches groupedDecode joint,
          targetMass (targetBranchOf branch) :=
        (sum_cast_program_eq groupedDecode joint target targetProgramEq.symm
          targetMass).symm
      _ = ∑ branch : Branches groupedDecode joint, jointMass branch := by
        apply Finset.sum_congr rfl
        intro branch _
        exact (projectionTransport branch).symm
  have eventSumEq :
      (∑ branch : Branches groupedDecode joint, jointMass branch) =
        outcomeEventMass (originalOutcomeWeight states)
          (currentJointSecondSelectorFailure (BaseWork := BaseWork)
            producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
            nonce₁ nonce₂ fallback₂ typed₂ fuel₂ ctx₂) := by
    change (∑ branch : Branches groupedDecode joint,
        if accepted branch then
          normSquared (workspaceEventProjection (selectorFailureOnJoint branch) (states branch))
        else 0) =
      outcomeEventMass (originalOutcomeWeight states)
        (fun outcome => accepted outcome.1 ∧
          selectorFailureOnJoint outcome.1 outcome.2.workspace outcome.2.database)
    exact originalEventSum.symm
  calc
    _ = ∑ branch : Branches groupedDecode joint, jointMass branch := targetSumEqJoint
    _ = outcomeEventMass (originalOutcomeWeight (fun branch =>
          physicalRun (encode joint) groupedDecode joint branch state))
          (currentJointSecondSelectorFailure (BaseWork := BaseWork)
            producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
            nonce₁ nonce₂ fallback₂ typed₂ fuel₂ ctx₂) := eventSumEq

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentSecondSelectorMass
