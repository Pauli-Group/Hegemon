import SmzaRp05CurrentJointAuthorizationEndpoint
import SmzaRp05CurrentAcceptedMassToScalar
import SmzaRp05CurrentProtocolModelBound
import SmzaRp05OriginalBornOutcomeMass
import SmzaRp05CmsKeyEqualityTransport
import SmzaRp05CmsEventEqualityTransport
import SmzaRp05FiniteSumEqualityTransport
import HegemonCrypto.CmsAdaptiveClaimBridge

/-! # Full-observer marginal for the first current selector

The first-target selector is evaluated on the actual terminal replay branch.
Rejected replay suffixes contribute zero, while the replay marginal preserves
the original joint branch and its unnormalized final state. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFirstSelectorMass

open HegemonCrypto.SmallWood.SmzaRp05CurrentJointAuthorizationEndpoint
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointAcceptedExecution
  (sequentialUnitProgram sequentialUnitBranch firstAcceptedVerifierProgram secondAcceptedVerifierProgram
    twoAcceptedProgram_eq_sequentialUnitProgram)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointObserverMass
  (branchesFintype bindPrefixBranch sequential_first_prefix_full_observer_mass_eq_joint_mass)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointExtractionPrograms
  (actualProgram_firstTarget_eq_terminalUnitPrefixReplayObserver
    firstTarget_key_eq_terminalUnitPrefixReplayObserver)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointObserverKeys
  (terminalWholePrefixObserver terminal_observer_key_eq_joint encode_cast_terminal_key)
open HegemonCrypto.SmallWood.SmzaRp05CurrentJointRetainedProofs
  (terminalUnitPrefixReplayObserver)
open HegemonCrypto.SmallWood.SmzaRp05CmsEventEqualityTransport
  (basisTypeEq stateTypeEq databaseTypeEq workspaceEventProjection_normSquared_cast_input)
open HegemonCrypto.SmallWood.SmzaRp05CmsKeyEqualityTransport
  (physicalRun_cast_input)
open HegemonCrypto.SmallWood.SmzaRp05FiniteSumEqualityTransport
  (sum_cast_program_eq sum_cast_type_eq)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedMassToScalar
  (currentAcceptedMassContexts)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedOrdinaryMassBound
  (actualProgram)
open HegemonCrypto.SmallWood.SmzaRp05CurrentProtocolModelBound
  (current_model_within_protocol)
open HegemonCrypto.SmallWood.SmzaRp05CurrentFullOrRoleXViewCoverage
  (currentAcceptedXViewFullSuccessSelector)
open HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open HegemonCrypto.SmallWood.SmzaRp05ExecutableProgramEquality
  (castProgramBranch physicalRun_cast_program branchResult_cast_program)
open HegemonCrypto.SmallWood.SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult physicalRun)
open HegemonCrypto.SmallWood.SmzaRp05CurrentAdaptiveExecution (Context Work)
open HegemonCrypto.SmallWood.SmzaRp05ConditionedExecution (xView)
open HegemonCrypto.CmsCompressedOracle (State Basis normSquared)
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open HegemonCrypto.SmallWood.SmzaRp05OriginalBornOutcomeMass
  (originalOutcomeWeight original_accepted_event_mass_eq_projection_sum)
open SmzaRp05CurrentAuthorizationCertificate (outcomeEventMass)
open SmzaRp05ExecutableMerkleVerifier (Program)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05GeneratedCertificates (currentDsl certificates)
open SmzaRp05TracePrefixes (AllEarlierTables)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05GroupedSuffix (GroupCounter)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8SmzaOracleParser (RawDigest)
open SmzaChallengeStageTargets (Role)
open scoped Classical BigOperators

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

private theorem firstTarget_key_eq_joint
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32)) :
    Key (actualProgram
      ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁) =
    Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂) := by
  calc
    Key (actualProgram
      ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁) =
        Key (terminalUnitPrefixReplayObserver producer₁ producer₂ ns₁ ns₂
          statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) :=
      firstTarget_key_eq_terminalUnitPrefixReplayObserver producer₁ producer₂
        ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    _ = Key (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) := rfl
    _ = Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) :=
      (terminal_observer_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).symm

private theorem bindPrefix_accepted_of_terminal_accepted
    (decode : V8SmzaOracleParser.RawInput → VectorOutput GroupCounter → RawDigest)
    (program suffix : Program Unit)
    (observerBranch : Branches decode (program.bind fun _ => suffix))
    (accepted : branchResult decode (program.bind fun _ => suffix)
      observerBranch = some ()) :
    branchResult decode program
      (bindPrefixBranch decode program suffix observerBranch) = some () := by
  induction program with
  | done result =>
      cases result with
      | none => cases accepted
      | some value =>
          cases value
          rfl
  | read raw next ih =>
      rcases observerBranch with ⟨answer, tail⟩
      have tailAccepted :
          branchResult decode ((next (decode raw answer)).bind fun _ => suffix) tail =
            some () := by
        simpa only [Program.bind, branchResult] using accepted
      have prefixAccepted :=
        ih (decode raw answer) tail tailAccepted
      simpa only [Program.bind, branchResult, bindPrefixBranch] using prefixAccepted

private theorem encode_cast_of_program_eq
    (left right : Program Unit) (sameProgram : left = right) (raw :
      V8SmzaOracleParser.RawInput) :
    cast (congrArg Key sameProgram) (encode left raw) = encode right raw := by
  cases sameProgram
  rfl

private theorem cast_trans_input {Left Middle Right : Type}
    (first : Left = Middle) (second : Middle = Right) (value : Left) :
    cast second (cast first value) = cast (first.trans second) value := by
  cases first
  cases second
  rfl

/-- The full-success selector projection on a terminal first-prefix observer
branch. The explicit terminal acceptance guard is essential: an alternative
answer transcript can abort during replay and is not part of the numeric
accepted-terminal endpoint. -/
private noncomputable def terminalFirstSelectorMass
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (fallback₁ : RawDigest) (typed₁ : Hegemon.Transaction.Poseidon2V8SemanticSpecification.V8PublicStatement)
    (fuel₁ : Nat)
    (ctx₁ : Context (Key := Key (actualProgram
      ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁)) (Counter := GroupCounter)
      (BaseWork := BaseWork))
    (observerBranch : Branches groupedDecode
      (actualProgram
        ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
        ns₁ statement₁ pending₁ nonce₁))
    (state : State (Key (actualProgram
      ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁)) (VectorOutput GroupCounter)
      (VectorOutput GroupCounter) (Work (Counter := GroupCounter)
        (BaseWork := BaseWork))) : ℝ :=
  if branchResult groupedDecode
      (actualProgram
        ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
        ns₁ statement₁ pending₁ nonce₁) observerBranch = some () then
    normSquared (workspaceEventProjection
      (fun _work database =>
        ¬ currentAcceptedXViewFullSuccessSelector
          ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
            statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
          ns₁ statement₁ pending₁ nonce₁ fallback₁ typed₁ fuel₁ ctx₁
          observerBranch (xView (nonchallengeRawKeySet ctx₁) database)) state)
  else 0

/-- Selector-specific mass bridge for the exact first-target endpoint context.
The context/model/bounds are derived from the current certificates, and the
same unnormalized state is used on both sides. -/
theorem current_joint_first_selector_mass_eq_event_mass
    (producer₁ producer₂ : Program ExistingProofFieldView)
    (ns₁ ns₂ : Namespace)
    (statement₁ statement₂ : SmzaRp05StatementNamespace.Statement)
    (pending₁ pending₂ : Bool) (nonce₁ nonce₂ : Fin (2 ^ 32))
    (fallback₁ : RawDigest)
    (typed₁ : Hegemon.Transaction.Poseidon2V8SemanticSpecification.V8PublicStatement)
    (fuel₁ : Nat)
    (state : State (Key (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)) (VectorOutput GroupCounter)
      (VectorOutput GroupCounter) (Work (Counter := GroupCounter)
        (BaseWork := BaseWork))) :
    let model := SmzaRp05RelationRefinement.relationModel currentDsl certificates
    let bounded := current_model_within_protocol
    let advice : ∀ role : Role, AllEarlierTables model role :=
      fun _role _ _ _ _ => none
    let joint := secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    let target := actualProgram (joint.bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁
    letI := branchesFintype groupedDecode joint
    letI := branchesFintype groupedDecode target
    let ctx₁ := currentAcceptedMassContexts (BaseWork := BaseWork)
      (joint.bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁ model bounded advice 28 28 .decsMatrix
    let keyEq := firstTarget_key_eq_joint producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
    let targetState := cast (congrArg (fun key => State key (VectorOutput GroupCounter)
      (VectorOutput GroupCounter) (Work (Counter := GroupCounter)
        (BaseWork := BaseWork))) keyEq.symm) state
    (∑ observerBranch : Branches groupedDecode
        (actualProgram
          ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
            statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
          ns₁ statement₁ pending₁ nonce₁),
      terminalFirstSelectorMass (BaseWork := BaseWork) producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₁ typed₁ fuel₁
        ctx₁ observerBranch
        (physicalRun (encode (actualProgram
          ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
            statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
          ns₁ statement₁ pending₁ nonce₁)) groupedDecode
          (actualProgram
            ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
              statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
            ns₁ statement₁ pending₁ nonce₁) observerBranch targetState)) =
    outcomeEventMass
      (originalOutcomeWeight (fun branch =>
        physicalRun (encode (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
          statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂)) groupedDecode
          (secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
            statement₂ pending₁ pending₂ nonce₁ nonce₂) branch state))
      (currentJointFirstSelectorFailure (BaseWork := BaseWork)
        producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
        nonce₁ nonce₂ fallback₁ typed₁ fuel₁ ctx₁) := by
  classical
  let model := SmzaRp05RelationRefinement.relationModel currentDsl certificates
  let bounded := current_model_within_protocol
  let advice : ∀ role : Role, AllEarlierTables model role :=
    fun _role _ _ _ _ => none
  let ctx₁ := currentAcceptedMassContexts (BaseWork := BaseWork)
    ((secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂ statement₁
      statement₂ pending₁ pending₂ nonce₁ nonce₂).bind fun _ => producer₁)
    ns₁ statement₁ pending₁ nonce₁ model bounded advice 28 28 .decsMatrix
  let first := firstAcceptedVerifierProgram producer₁ ns₁ statement₁ pending₁ nonce₁
  let suffix := producer₂.bind fun wire₂ =>
    verifierProgram ns₂ currentDsl statement₂ pending₂ nonce₂ wire₂
  let seqJoint := sequentialUnitProgram first suffix
  let joint := secondAcceptedVerifierProgram producer₁ producer₂ ns₁ ns₂
    statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  have jointEq : joint = seqJoint := by
    exact twoAcceptedProgram_eq_sequentialUnitProgram producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  let seqObserver := sequentialUnitProgram seqJoint first
  let target := actualProgram (joint.bind fun _ => producer₁)
    ns₁ statement₁ pending₁ nonce₁
  have observerEq : seqObserver = target := by
    exact sequentialObserver_eq_currentFirstTarget producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
  have targetEq : target = terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ := by
    calc
      target = terminalUnitPrefixReplayObserver producer₁ producer₂ ns₁ ns₂
          statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ := by
        exact actualProgram_firstTarget_eq_terminalUnitPrefixReplayObserver producer₁
          producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
      _ = terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂ := rfl
  have firstTargetKeyEq : Key target = Key joint := by
    calc
      Key target = Key (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂
          statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) := congrArg Key targetEq
      _ = Key joint := (terminal_observer_key_eq_joint producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂).symm
  have expectedBranchEq (branch : Branches groupedDecode joint) :
      currentJointExpectedObserverBranch producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂ branch =
      castProgramBranch groupedDecode seqObserver target observerEq
        (sequentialUnitBranch groupedDecode seqJoint
          (castProgramBranch groupedDecode joint seqJoint jointEq branch) first
          (bindPrefixBranch groupedDecode first suffix
            (castProgramBranch groupedDecode joint seqJoint jointEq branch))) := by
    simpa only [joint, seqJoint, first, suffix, seqObserver, target,
      observerEq] using
      currentJointExpectedObserverBranch_eq_massExpected producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ branch
  let targetState := cast (congrArg (fun key => State key (VectorOutput GroupCounter)
      (VectorOutput GroupCounter) (Work (Counter := GroupCounter)
        (BaseWork := BaseWork))) firstTargetKeyEq.symm)
    state
  let sameInput := firstTargetKeyEq.symm
  have sameEncode : ∀ raw, encode target raw = cast sameInput (encode joint raw) := by
    intro raw
    have encoded := encode_cast_terminal_key producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ raw
    have observerToTarget : Key (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂
        statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂) = Key target :=
      congrArg Key targetEq.symm
    have sameInputProof :
        (terminal_observer_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
          statement₂ pending₁ pending₂ nonce₁ nonce₂).trans observerToTarget = sameInput :=
      Subsingleton.elim _ _
    calc
      encode target raw = cast observerToTarget
          (encode (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
            statement₂ pending₁ pending₂ nonce₁ nonce₂) raw) :=
        encode_cast_of_program_eq
          (terminalWholePrefixObserver producer₁ producer₂ ns₁ ns₂ statement₁
            statement₂ pending₁ pending₂ nonce₁ nonce₂)
          target targetEq.symm raw |>.symm
      _ = cast observerToTarget
          (cast (terminal_observer_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
            statement₂ pending₁ pending₂ nonce₁ nonce₂) (encode joint raw)) :=
        congrArg (fun value => cast observerToTarget value) encoded.symm
      _ = cast ((terminal_observer_key_eq_joint producer₁ producer₂ ns₁ ns₂ statement₁
            statement₂ pending₁ pending₂ nonce₁ nonce₂).trans observerToTarget)
          (encode joint raw) :=
        cast_trans_input _ _ _
      _ = cast sameInput (encode joint raw) :=
        congrArg (fun equality => cast equality (encode joint raw)) sameInputProof
  let mass : Branches groupedDecode seqObserver →
      State (Key target) (VectorOutput GroupCounter) (VectorOutput GroupCounter)
        (Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℝ :=
      fun observerBranch current =>
    terminalFirstSelectorMass (BaseWork := BaseWork) producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₁ typed₁ fuel₁
      ctx₁ (castProgramBranch groupedDecode seqObserver target observerEq observerBranch)
      current
  have massZero : ∀ observerBranch, mass observerBranch 0 = 0 := by
    intro observerBranch
    simp [mass, terminalFirstSelectorMass, workspaceEventProjection, normSquared]
  letI := branchesFintype groupedDecode target
  letI := branchesFintype groupedDecode seqObserver
  letI := branchesFintype groupedDecode seqJoint
  letI := branchesFintype groupedDecode joint
  have marginal := sequential_first_prefix_full_observer_mass_eq_joint_mass
    (encode target) groupedDecode first suffix targetState mass massZero
  let targetMass : Branches groupedDecode target → ℝ := fun observerBranch =>
    terminalFirstSelectorMass (BaseWork := BaseWork) producer₁ producer₂ ns₁ ns₂
      statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ fallback₁ typed₁ fuel₁
      ctx₁ observerBranch (physicalRun (encode target) groupedDecode target
        observerBranch targetState)
  let observerTotal :=
    ∑ observerBranch : Branches groupedDecode seqObserver,
      mass observerBranch
        (physicalRun (encode target) groupedDecode seqObserver observerBranch targetState)
  have targetSumEqObserver :
      (∑ observerBranch : Branches groupedDecode target, targetMass observerBranch) =
        observerTotal := by
    calc
      _ = ∑ observerBranch : Branches groupedDecode seqObserver,
          targetMass (castProgramBranch groupedDecode seqObserver target observerEq
            observerBranch) :=
        (sum_cast_program_eq groupedDecode seqObserver target observerEq targetMass).symm
      _ = observerTotal := by
        apply Finset.sum_congr rfl
        intro observerBranch _
        simp [targetMass, mass, physicalRun_cast_program]
  let marginalObserverTotal :=
    ∑ observerBranch : Branches groupedDecode seqObserver,
      if branchResult groupedDecode seqJoint
          (bindPrefixBranch groupedDecode seqJoint first observerBranch) = some () then
        mass observerBranch
          (physicalRun (encode target) groupedDecode seqObserver observerBranch targetState)
      else 0
  have observerTotalEqMarginal :
      observerTotal = marginalObserverTotal := by
    apply Finset.sum_congr rfl
    intro observerBranch _
    let prefixBranch := bindPrefixBranch groupedDecode seqJoint first observerBranch
    by_cases prefixAccepted : branchResult groupedDecode seqJoint prefixBranch = some ()
    · simp [prefixBranch, prefixAccepted]
    · have terminalRejected :
        branchResult groupedDecode target
          (castProgramBranch groupedDecode seqObserver target observerEq observerBranch) ≠
            some () := by
        intro terminalAccepted
        have observerAccepted :
            branchResult groupedDecode seqObserver observerBranch = some () := by
          simpa only [branchResult_cast_program] using terminalAccepted
        have observerAccepted' :
            branchResult groupedDecode (seqJoint.bind fun _ => first) observerBranch =
              some () := by
          simpa only [seqObserver, sequentialUnitProgram] using observerAccepted
        have prefixAccepted' :=
          bindPrefix_accepted_of_terminal_accepted groupedDecode seqJoint first
            observerBranch observerAccepted'
        exact prefixAccepted prefixAccepted'
      have rejectedMass :
          mass observerBranch
            (physicalRun (encode target) groupedDecode seqObserver observerBranch targetState) = 0 := by
        change (if branchResult groupedDecode target
            (castProgramBranch groupedDecode seqObserver target observerEq observerBranch) =
              some () then _ else 0) = 0
        rw [if_neg terminalRejected]
      rw [if_neg prefixAccepted]
      rw [rejectedMass]
  let expectedMass : Branches groupedDecode seqJoint → ℝ := fun branch =>
    if branchResult groupedDecode seqJoint branch = some () then
      mass (sequentialUnitBranch groupedDecode seqJoint branch first
        (bindPrefixBranch groupedDecode first suffix branch))
        (physicalRun (encode target) groupedDecode seqJoint branch targetState)
    else 0
  let states := fun branch : Branches groupedDecode joint =>
    physicalRun (encode joint) groupedDecode joint branch state
  let accepted := fun branch : Branches groupedDecode joint =>
    branchResult groupedDecode joint branch = some ()
  let selectorFailureOnJoint := fun (branch : Branches groupedDecode joint)
      (work : Work (Counter := GroupCounter) (BaseWork := BaseWork))
      (database : Database (Key joint) (VectorOutput GroupCounter)) =>
    ¬ currentAcceptedXViewFullSuccessSelector (joint.bind fun _ => producer₁)
      ns₁ statement₁ pending₁ nonce₁ fallback₁ typed₁ fuel₁ ctx₁
      (currentJointExpectedObserverBranch producer₁ producer₂ ns₁ ns₂ statement₁
        statement₂ pending₁ pending₂ nonce₁ nonce₂ branch)
      (xView (nonchallengeRawKeySet ctx₁)
        (cast (databaseTypeEq sameInput) database))
  let jointMass : Branches groupedDecode joint → ℝ := fun branch =>
    if accepted branch then
      normSquared (workspaceEventProjection (selectorFailureOnJoint branch)
        (states branch))
    else 0
  have expectedSumEqJoint :
      (∑ branch : Branches groupedDecode seqJoint, expectedMass branch) =
        ∑ branch : Branches groupedDecode joint, jointMass branch := by
    calc
      _ = ∑ branch : Branches groupedDecode seqJoint,
          jointMass (castProgramBranch groupedDecode seqJoint joint jointEq.symm branch) := by
        apply Finset.sum_congr rfl
        intro branch _
        by_cases branchAccepted : branchResult groupedDecode seqJoint branch = some ()
        · let originalBranch :=
            castProgramBranch groupedDecode seqJoint joint jointEq.symm branch
          have originalAccepted :
              branchResult groupedDecode joint originalBranch = some () := by
            simpa [originalBranch, branchResult_cast_program] using branchAccepted
          have targetBranchEq :
              castProgramBranch groupedDecode seqObserver target observerEq
                (sequentialUnitBranch groupedDecode seqJoint branch first
                  (bindPrefixBranch groupedDecode first suffix branch)) =
              currentJointExpectedObserverBranch producer₁ producer₂ ns₁ ns₂
                statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ originalBranch := by
            simpa only [originalBranch, castProgramBranch, cast_cast, cast_eq] using
              (expectedBranchEq originalBranch).symm
          have targetAccepted :
              branchResult groupedDecode target
                (currentJointExpectedObserverBranch producer₁ producer₂ ns₁ ns₂
                  statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ originalBranch) =
                  some () :=
            currentJointExpectedObserverBranch_accepted producer₁ producer₂ ns₁ ns₂
              statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂
              originalBranch originalAccepted
          have runTransport :
              physicalRun (encode target) groupedDecode seqJoint branch targetState =
                cast (stateTypeEq sameInput)
                  (physicalRun (encode joint) groupedDecode joint originalBranch state) := by
            calc
              _ = physicalRun (encode target) groupedDecode joint originalBranch targetState := by
                symm
                exact physicalRun_cast_program (encode target) groupedDecode seqJoint joint
                  jointEq.symm branch targetState
              _ = cast (stateTypeEq sameInput)
                  (physicalRun (encode joint) groupedDecode joint originalBranch state) :=
                (physicalRun_cast_input sameInput (encode joint) (encode target) sameEncode
                  groupedDecode joint originalBranch state).symm
          have eventTransport := workspaceEventProjection_normSquared_cast_input
            sameInput (selectorFailureOnJoint originalBranch)
            (fun work database =>
              ¬ currentAcceptedXViewFullSuccessSelector (joint.bind fun _ => producer₁)
                ns₁ statement₁ pending₁ nonce₁ fallback₁ typed₁ fuel₁ ctx₁
                (currentJointExpectedObserverBranch producer₁ producer₂ ns₁ ns₂
                  statement₁ statement₂ pending₁ pending₂ nonce₁ nonce₂ originalBranch)
                (xView (nonchallengeRawKeySet ctx₁) database))
            (by intro work database; rfl)
            (physicalRun (encode joint) groupedDecode joint originalBranch state)
          have acceptedOriginal : accepted originalBranch := originalAccepted
          change (if branchResult groupedDecode seqJoint branch = some () then
            terminalFirstSelectorMass (BaseWork := BaseWork)
              producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
              nonce₁ nonce₂ fallback₁ typed₁ fuel₁ ctx₁
              (castProgramBranch groupedDecode seqObserver target observerEq
                (sequentialUnitBranch groupedDecode seqJoint branch first
                  (bindPrefixBranch groupedDecode first suffix branch)))
              (physicalRun (encode target) groupedDecode seqJoint branch targetState)
            else 0) =
            if accepted originalBranch then
              normSquared (workspaceEventProjection (selectorFailureOnJoint originalBranch)
                (states originalBranch)) else 0
          rw [if_pos branchAccepted, if_pos acceptedOriginal]
          rw [targetBranchEq, runTransport]
          simp only [terminalFirstSelectorMass]
          have terminalAccepted := currentJointExpectedObserverBranch_accepted
            producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
            nonce₁ nonce₂ originalBranch originalAccepted
          rw [if_pos terminalAccepted]
          exact eventTransport
        · have originalRejected :
              branchResult groupedDecode joint
                (castProgramBranch groupedDecode seqJoint joint jointEq.symm branch) ≠
                  some () := by
            intro h
            have acceptedBranch : branchResult groupedDecode seqJoint branch = some () := by
              simpa only [branchResult_cast_program] using h
            exact branchAccepted acceptedBranch
          have notAcceptedCast :
              ¬ accepted (castProgramBranch groupedDecode seqJoint joint jointEq.symm branch) := by
            simpa only [accepted] using originalRejected
          simp only [expectedMass, if_neg branchAccepted]
          change 0 = if accepted (castProgramBranch groupedDecode seqJoint joint jointEq.symm branch)
            then _ else 0
          rw [if_neg notAcceptedCast]
      _ = ∑ branch : Branches groupedDecode joint, jointMass branch :=
        sum_cast_program_eq groupedDecode seqJoint joint jointEq.symm jointMass
  have originalEventSum :=
    original_accepted_event_mass_eq_projection_sum
      states accepted selectorFailureOnJoint
  have eventSumEq :
      (∑ branch : Branches groupedDecode joint, jointMass branch) =
        outcomeEventMass
          (originalOutcomeWeight (fun branch =>
            physicalRun (encode joint) groupedDecode joint branch state))
          (currentJointFirstSelectorFailure (BaseWork := BaseWork)
            producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
            nonce₁ nonce₂ fallback₁ typed₁ fuel₁ ctx₁) := by
    have originalEventSum' :
        (∑ branch : Branches groupedDecode joint,
          if accepted branch then
            normSquared (workspaceEventProjection (selectorFailureOnJoint branch)
              (states branch))
          else 0) =
        outcomeEventMass
          (originalOutcomeWeight (fun branch =>
            physicalRun (encode joint) groupedDecode joint branch state))
          (fun outcome => accepted outcome.1 ∧
            selectorFailureOnJoint outcome.1 outcome.2.workspace outcome.2.database) := by
      simpa only [states] using originalEventSum.symm
    have sameEvent :
        (fun outcome => accepted outcome.1 ∧
          selectorFailureOnJoint outcome.1 outcome.2.workspace outcome.2.database) =
        currentJointFirstSelectorFailure (BaseWork := BaseWork)
          producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
          nonce₁ nonce₂ fallback₁ typed₁ fuel₁ ctx₁ := by
      funext outcome
      unfold currentJointFirstSelectorFailure
      rfl
    rw [sameEvent] at originalEventSum'
    exact originalEventSum'
  calc
    _ = observerTotal := targetSumEqObserver
    _ = marginalObserverTotal := observerTotalEqMarginal
    _ = ∑ branch : Branches groupedDecode seqJoint, expectedMass branch := by
      exact marginal
    _ = ∑ branch : Branches groupedDecode joint, jointMass branch := expectedSumEqJoint
    _ = outcomeEventMass
        (originalOutcomeWeight (fun branch =>
          physicalRun (encode joint) groupedDecode joint branch state))
        (currentJointFirstSelectorFailure (BaseWork := BaseWork)
          producer₁ producer₂ ns₁ ns₂ statement₁ statement₂ pending₁ pending₂
          nonce₁ nonce₂ fallback₁ typed₁ fuel₁ ctx₁) := eventSumEq

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFirstSelectorMass
