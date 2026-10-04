import SmzaRp05CurrentHistoryFailureCoverage
import SmzaRp05CurrentHistorySelectorContexts
import SmzaRp05CurrentHistoryObserverReadback
import SmzaRp05CurrentAcceptedDecsExtractionFailureEvent
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentHistoryVerifierProgram
import SmzaRp05ExecutableProgramEquality
import SmzaRp05CurrentAcceptedMassToScalar
import SmzaRp05CurrentSelectedCurrentAdviceEventMass
import SmzaRp05CurrentHistoryObserverStateReplay
import SmzaRp05CurrentMixedBranchClaimReadback
import SmzaRp05CurrentHistoryFailureMass
import SmzaRp05CurrentPhysicalBranchClaimReadback
import SmzaRp05CurrentVerifierReplay
import SmzaRp05CurrentJointAcceptedExecution
import SmzaRp05CurrentProgramKeyReadbackTransport
import SmzaRp05CurrentSelectedRoleStateKeyTransport
import SmzaRp05CmsEventEqualityTransport
import SmzaRp05CmsKeyEqualityTransport
import SmzaRp05FiniteKeyStateEmbedding
import SmzaRp05CmsTwoTypeSelectedSupportTransport
import HegemonCrypto.CmsOracleSimulation
import SmzaRoleDomainActiveEmbedding

/-! # History selected-role support on an exact retained-stage observer

The full-history role selector stores the stage failure selector evaluated on
the transported global X-view.  This module connects that witness to the
stage-native selected-state coefficient used by the extraction dispatcher.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentHistorySelectedRoleStateReplay

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult branchKeys branchAnswers branchClaims answerLog
    branch_claims_eq_answer_log physicalRun KnownAt)
open SmzaRp05CurrentHistoryVerifierProgram
  (HistoryStage historyProgram terminalHistoryStageObserver
    terminalHistoryStageObserver_groups_eq indexedStageVerifierProgram)
open SmzaRp05CurrentHistoryFailureCoverage
  (currentHistoryFailureRoleSelector historyStageView historyStageContext
    historyStageProgramEq historyStageKeyCast historyDatabaseOnObserver
    historyObserverKeyEquiv terminal_observer_claims_complete_from_history
    historyStageNonchallengeMem AcceptedHistoryStageReadback)
open SmzaRp05CurrentVerifierReplay (physicalRun_eq_self_on_known_branch)
open SmzaRp05CurrentPhysicalBranchClaimReadback
  (physical_branch_claim_known_at_standard)
open SmzaRp05CurrentJointAcceptedExecution
  (sequentialUnitProgram sequentialUnitBranch sequentialUnitBranch_split
    sequentialUnitBranch_answerLog sequentialUnitBranch_physicalRun)
open SmzaRp05CurrentHistorySelectorContexts
  (historyStageProducer history_stage_target_key_eq_history
    history_stage_context_cast_eq)
open SmzaRp05CurrentAcceptedMassToScalar (currentAcceptedMassContexts)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05CurrentFullOrRoleExtraction (currentAcceptedXViewFailureRoleSelector)
open SmzaRp05ExecutableProgramEquality (castProgramBranch)
open SmzaRp05ExecutableProgramEquality (physicalRun_cast_program)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05CurrentSelectedRoleStateKeyTransport
  (active_key_type_eq_of_context_cast selected_projection_support_cast_at_basis)
open SmzaRp05CmsTwoTypeSelectedSupportTransport
  (stateTypeEq2 basisTypeEq2 selected_projection_support_cast_at_basis_two_types)
open SmzaRp05CmsEventEqualityTransport (stateTypeEq basisTypeEq databaseTypeEq)
open SmzaRp05CmsKeyEqualityTransport (physicalRun_cast_input)
open SmzaRp05CurrentHistoryFailureMass (emptyHistoryAdvice historyContext)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key included encode)
open SmzaRp05ExecutableAddressCompiler (groups)
open SmzaRp05FiniteKeyStateEmbedding
  (key_type_eq_of_groups_eq encode_cast_key_type_eq_of_groups_eq
    included_cast_key_type_eq_of_groups_eq)
open SmzaRp05CurrentSelectedChallengeClaims
  (nonchallengeRawKeySet nonchallenge_raw_key_set_unrecognized
    branchXRoleSelector SelectedWork)
open SmzaRp05AdaptiveRetainedAdviceTransport (mixedRun)
open SmzaRp05CurrentMixedBranchClaimReadback (mixedBranchClaims)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05CurrentAdaptiveExecution (CmsState)
open SmzaRp05ConditionedExecution (FixedTable ActiveState fixedFiberToActive
  otherRoleTransform ActiveMemory XKey activeXView)
open SmzaRoleDomainConditioning (ActiveKey ActiveRouteMemory)
open SmzaRp05OrdinarySoundnessExecution (emptyAuthorizationContexts)
open SmzaChallengeStageTargets (Role)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05GroupedSuffix (GroupCounter)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05CurrentProgramKeyReadbackTransport (acceptedBranchClaims_cast_program)
open SmzaRp05AdaptiveRetainedAdviceTransport (physical_run_to_mixed_same_fiber)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

def retainedStageActualProgram (stages : List HistoryStage)
    (i : Fin stages.length) : Program Unit :=
  actualProgram (historyStageProducer stages i) (stages[i.val]).ns
    (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce

def retainedStageActualBranch (stages : List HistoryStage)
    (i : Fin stages.length)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (readback : AcceptedHistoryStageReadback stages i historyBranch) :
    Branches groupedDecode (retainedStageActualProgram stages i) :=
  castProgramBranch groupedDecode (terminalHistoryStageObserver stages i)
    (retainedStageActualProgram stages i) (historyStageProgramEq stages i).symm
    readback.observerBranch

abbrev HistoryRetainedRoleFiber
    {KeyType : Type}
    (ctx : Context (Key := KeyType) (Counter := GroupCounter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) :=
  FixedTable ctx blockCap ×
    (ActiveKey ctx.role blockCap ctx.keyBytes ×
      Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
        (VectorOutput GroupCounter) (VectorOutput GroupCounter) (ActiveMemory ctx))

abbrev HistoryRetainedRoleFiberBundle (Key : Type)
    (blockCap : Role → Nat) :=
  Σ ctx : Context (Key := Key) (Counter := GroupCounter) (BaseWork := BaseWork),
    HistoryRetainedRoleFiber (BaseWork := BaseWork) ctx blockCap

private theorem history_retained_role_bundle_context_cast
    {KeyLeft KeyRight : Type}
    [Fintype KeyLeft] [DecidableEq KeyLeft]
    [Fintype KeyRight] [DecidableEq KeyRight]
    (sameKey : KeyLeft = KeyRight) (blockCap : Role → Nat)
    (fiber : HistoryRetainedRoleFiberBundle (BaseWork := BaseWork)
      KeyLeft blockCap) :
    (cast (congrArg (fun key => HistoryRetainedRoleFiberBundle
      (BaseWork := BaseWork) key blockCap) sameKey) fiber).1 =
      cast (congrArg (fun key => Context (Key := key)
        (Counter := GroupCounter) (BaseWork := BaseWork)) sameKey) fiber.1 := by
  cases sameKey
  rfl

private theorem history_retained_role_bundle_basis_cast
    {KeyLeft KeyRight : Type}
    [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
    [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
    (sameKey : KeyLeft = KeyRight) (blockCap : Role → Nat)
    (fiber : HistoryRetainedRoleFiberBundle (BaseWork := BaseWork)
      KeyLeft blockCap)
    (ctxRight : Context (Key := KeyRight) (Counter := GroupCounter)
      (BaseWork := BaseWork))
    (contextEq : cast (congrArg (fun key => Context (Key := key)
      (Counter := GroupCounter) (BaseWork := BaseWork)) sameKey) fiber.1 = ctxRight) :
    let target := cast (congrArg (fun key => HistoryRetainedRoleFiberBundle
      (BaseWork := BaseWork) key blockCap) sameKey) fiber
    let fiberEq := (history_retained_role_bundle_context_cast
      sameKey blockCap fiber).trans contextEq
    cast (congrArg (fun ctx => Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter) (ActiveMemory ctx))
      fiberEq) target.2.2.2 =
      cast (basisTypeEq2
        (active_key_type_eq_of_context_cast sameKey fiber.1 ctxRight contextEq blockCap)
        (congrArg (fun key => ActiveRouteMemory key (VectorOutput GroupCounter)
          (SmzaRp05CurrentAdaptiveExecution.Work (Counter := GroupCounter)
            (BaseWork := BaseWork))) sameKey)) fiber.2.2.2 := by
  cases sameKey
  have sameFintype : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEq
  have sameContext : fiber.1 = ctxRight := by simpa using contextEq
  cases sameContext
  rfl

private theorem history_basis_database_cast
    {InputLeft InputRight Output Phase WorkspaceLeft WorkspaceRight : Type}
    [fintypeInputLeft : Fintype InputLeft] [decEqInputLeft : DecidableEq InputLeft]
    [fintypeInputRight : Fintype InputRight] [decEqInputRight : DecidableEq InputRight]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [fintypeWorkLeft : Fintype WorkspaceLeft] [decEqWorkLeft : DecidableEq WorkspaceLeft]
    [fintypeWorkRight : Fintype WorkspaceRight] [decEqWorkRight : DecidableEq WorkspaceRight]
    (sameInput : InputLeft = InputRight) (sameWork : WorkspaceLeft = WorkspaceRight)
    (basis : Basis InputLeft Output Phase WorkspaceLeft) :
    (cast (basisTypeEq2 sameInput sameWork) basis).database =
      cast (databaseTypeEq sameInput) basis.database := by
  cases sameInput
  cases sameWork
  have sameFintypeInput : fintypeInputLeft = fintypeInputRight := Subsingleton.elim _ _
  cases sameFintypeInput
  have sameDecEqInput : decEqInputLeft = decEqInputRight := Subsingleton.elim _ _
  cases sameDecEqInput
  have sameFintypeWork : fintypeWorkLeft = fintypeWorkRight := Subsingleton.elim _ _
  cases sameFintypeWork
  have sameDecEqWork : decEqWorkLeft = decEqWorkRight := Subsingleton.elim _ _
  cases sameDecEqWork
  rfl

private theorem history_basis_workspace_cast
    {InputLeft InputRight Output Phase WorkspaceLeft WorkspaceRight : Type}
    [fintypeInputLeft : Fintype InputLeft] [decEqInputLeft : DecidableEq InputLeft]
    [fintypeInputRight : Fintype InputRight] [decEqInputRight : DecidableEq InputRight]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [fintypeWorkLeft : Fintype WorkspaceLeft] [decEqWorkLeft : DecidableEq WorkspaceLeft]
    [fintypeWorkRight : Fintype WorkspaceRight] [decEqWorkRight : DecidableEq WorkspaceRight]
    (sameInput : InputLeft = InputRight) (sameWork : WorkspaceLeft = WorkspaceRight)
    (basis : Basis InputLeft Output Phase WorkspaceLeft) :
    (cast (basisTypeEq2 sameInput sameWork) basis).workspace =
      cast sameWork basis.workspace := by
  cases sameInput
  cases sameWork
  have sameFintypeInput : fintypeInputLeft = fintypeInputRight := Subsingleton.elim _ _
  cases sameFintypeInput
  have sameDecEqInput : decEqInputLeft = decEqInputRight := Subsingleton.elim _ _
  cases sameDecEqInput
  have sameFintypeWork : fintypeWorkLeft = fintypeWorkRight := Subsingleton.elim _ _
  cases sameFintypeWork
  have sameDecEqWork : decEqWorkLeft = decEqWorkRight := Subsingleton.elim _ _
  cases sameDecEqWork
  rfl

private theorem history_active_x_view_cast
    {KeyLeft KeyRight : Type}
    [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
    [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
    (sameKey : KeyLeft = KeyRight)
    (ctxLeft : Context (Key := KeyLeft) (Counter := GroupCounter) (BaseWork := BaseWork))
    (ctxRight : Context (Key := KeyRight) (Counter := GroupCounter) (BaseWork := BaseWork))
    (contextEq : cast (congrArg (fun key => Context (Key := key)
      (Counter := GroupCounter) (BaseWork := BaseWork)) sameKey) ctxLeft = ctxRight)
    (blockCap : Role → Nat)
    (databaseLeft : Database (ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
      (VectorOutput GroupCounter))
    (member : ∀ key : XKey (nonchallengeRawKeySet ctxRight),
      cast sameKey.symm key.val ∈ nonchallengeRawKeySet ctxLeft) :
    activeXView ctxRight blockCap (nonchallengeRawKeySet ctxRight)
        (nonchallenge_raw_key_set_unrecognized ctxRight)
        (cast (databaseTypeEq
          (active_key_type_eq_of_context_cast sameKey ctxLeft ctxRight contextEq blockCap))
          databaseLeft) =
      fun key => activeXView ctxLeft blockCap (nonchallengeRawKeySet ctxLeft)
        (nonchallenge_raw_key_set_unrecognized ctxLeft) databaseLeft
        ⟨cast sameKey.symm key.val, member key⟩ := by
  cases sameKey
  have sameFintypeKey : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintypeKey
  have sameDecEqKey : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEqKey
  have sameContext : ctxLeft = ctxRight := by simpa using contextEq
  cases sameContext
  funext key
  rfl

private theorem history_retained_role_bundle_active_map_cast
    {KeyLeft KeyRight : Type}
    [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
    [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
    (sameKey : KeyLeft = KeyRight) (blockCap : Role → Nat)
    (fiber : HistoryRetainedRoleFiberBundle (BaseWork := BaseWork)
      KeyLeft blockCap)
    (ctxRight : Context (Key := KeyRight) (Counter := GroupCounter)
      (BaseWork := BaseWork))
    (contextEq : cast (congrArg (fun key => Context (Key := key)
      (Counter := GroupCounter) (BaseWork := BaseWork)) sameKey) fiber.1 = ctxRight)
    (state : CmsState (Key := KeyLeft) (Counter := GroupCounter)
      (BaseWork := BaseWork)) :
    let target := cast (congrArg (fun key => HistoryRetainedRoleFiberBundle
      (BaseWork := BaseWork) key blockCap) sameKey) fiber
    let fiberEq := (history_retained_role_bundle_context_cast
      sameKey blockCap fiber).trans contextEq
    let fixedRight := cast (congrArg (fun ctx => FixedTable ctx blockCap)
      fiberEq) target.2.1
    let dummyRight := cast (congrArg (fun ctx => ActiveKey ctx.role blockCap ctx.keyBytes)
      fiberEq) target.2.2.1
    let activeEq := active_key_type_eq_of_context_cast sameKey fiber.1 ctxRight
      contextEq blockCap
    let workEq := congrArg (fun key => ActiveRouteMemory key (VectorOutput GroupCounter)
      (SmzaRp05CurrentAdaptiveExecution.Work (Counter := GroupCounter)
        (BaseWork := BaseWork))) sameKey
    cast (stateTypeEq2 activeEq workEq)
        (fixedFiberToActive fiber.1 blockCap fiber.2.2.1 fiber.2.1
          (otherRoleTransform fiber.1 blockCap state)) =
      fixedFiberToActive ctxRight blockCap dummyRight fixedRight
        (otherRoleTransform ctxRight blockCap
          (cast (stateTypeEq2 sameKey rfl) state)) := by
  cases sameKey
  have sameFintypeKey : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintypeKey
  have sameDecEqKey : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEqKey
  have sameContext : fiber.1 = ctxRight := by simpa using contextEq
  cases sameContext
  rfl

/-- The per-role history and retained-stage contexts are related by the
canonical finite-Key equality, in the source-to-stage direction. -/
theorem history_stage_role_context_cast_eq
    (stages : List HistoryStage) (i : Fin stages.length)
    (commonNs : Namespace) (stageNsEq : (stages[i.val]).ns = commonNs)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (role : Role) (advice : ∀ role : Role, AllEarlierTables model role) :
    cast (congrArg (fun key => Context (Key := key)
      (Counter := GroupCounter) (BaseWork := BaseWork))
      (SmzaRp05CurrentHistorySelectorContexts.history_stage_target_key_eq_history
        stages i).symm)
      (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs role (advice role) 28 28 (fun _ => ∅)) =
    historyStageContext (BaseWork := BaseWork) stages i model bounded
      advice role := by
  let keyEq := SmzaRp05CurrentHistorySelectorContexts.history_stage_target_key_eq_history
    stages i
  have backwards := history_stage_context_cast_eq (BaseWork := BaseWork)
    stages i commonNs stageNsEq model bounded advice role
  have transported := congrArg
    (cast (congrArg (fun key => Context (Key := key)
      (Counter := GroupCounter) (BaseWork := BaseWork)) keyEq.symm)) backwards.symm
  simpa [keyEq, currentAcceptedMassContexts, historyStageContext,
    SmzaRp05CurrentHistorySelectorContexts.historyStageProducer,
    actualProgram, SmzaRp05CurrentHistoryVerifierProgram.stageProgram] using transported

/-- Every active mixed-branch claim, including recognized challenge claims,
is an exact raw key/answer in the same program branch transcript. -/
theorem mixed_active_claim_mem_branch_claims
    {Key Counter Result : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (claim : ActiveKey ctx.role blockCap ctx.keyBytes × VectorOutput Counter)
    (member : claim ∈ mixedBranchClaims ctx blockCap encode decode program branch) :
    (claim.1.val, claim.2) ∈
      branchClaims (branchKeys encode decode program branch)
        (branchAnswers encode decode program branch) := by
  induction program generalizing claim with
  | done result => simp [mixedBranchClaims] at member
  | read raw next ih =>
      rcases branch with ⟨answer, branch⟩
      by_cases live : SmzaRoleDomainConditioning.RoleActive ctx.role blockCap
          ctx.keyBytes (encode raw)
      · simp only [mixedBranchClaims, dif_pos live, List.mem_cons] at member
        rcases member with head | tail
        · cases head
          simp [branchKeys, branchAnswers, branchClaims]
        · change (claim.1.val, claim.2) ∈
            (encode raw, answer) :: branchClaims
              (branchKeys encode decode (next (decode raw answer)) branch)
              (branchAnswers encode decode (next (decode raw answer)) branch)
          exact List.mem_cons_of_mem _ (ih (decode raw answer) branch _ tail)
      · simp only [mixedBranchClaims, dif_neg live] at member
        change (claim.1.val, claim.2) ∈
          (encode raw, answer) :: branchClaims
            (branchKeys encode decode (next (decode raw answer)) branch)
            (branchAnswers encode decode (next (decode raw answer)) branch)
        exact List.mem_cons_of_mem _ (ih (decode raw answer) branch _ member)

/-- The stage-native program branch from an accepted history readback has
the same complete claim event as the retained observer, reindexed through
the checked stage/history Key cast. -/
theorem retained_readback_stage_claims_complete
    (stages : List HistoryStage) (i : Fin stages.length)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (readback : AcceptedHistoryStageReadback stages i historyBranch)
    (completion : Database (Key (historyProgram stages)) (VectorOutput GroupCounter))
    (historyComplete : ClaimsDatabaseEvent
      (branchClaims (branchKeys (encode (historyProgram stages)) groupedDecode
        (historyProgram stages) historyBranch)
        (branchAnswers (encode (historyProgram stages)) groupedDecode
          (historyProgram stages) historyBranch)) completion) :
    ClaimsDatabaseEvent
      (branchClaims (branchKeys (encode (retainedStageActualProgram stages i))
        groupedDecode (retainedStageActualProgram stages i)
        (retainedStageActualBranch stages i historyBranch readback))
        (branchAnswers (encode (retainedStageActualProgram stages i)) groupedDecode
          (retainedStageActualProgram stages i)
          (retainedStageActualBranch stages i historyBranch readback)))
      (fun key => completion (historyStageKeyCast stages i key)) := by
  have observerComplete := terminal_observer_claims_complete_from_history stages i
    historyBranch readback.observerBranch completion readback.answerLogSubset
    historyComplete
  have actualEq := historyStageProgramEq stages i
  have observerGroupsEq : groups (terminalHistoryStageObserver stages i) =
      groups (retainedStageActualProgram stages i) := congrArg groups actualEq.symm
  let sameKey : Key (terminalHistoryStageObserver stages i) =
      Key (retainedStageActualProgram stages i) := congrArg Key actualEq.symm
  have sameKeyEq : sameKey = key_type_eq_of_groups_eq
      (terminalHistoryStageObserver stages i) (retainedStageActualProgram stages i)
      observerGroupsEq := Subsingleton.elim _ _
  let observerDatabase := historyDatabaseOnObserver stages i completion
  let stageDatabase : Database (Key (retainedStageActualProgram stages i))
      (VectorOutput GroupCounter) :=
    fun key => completion (historyStageKeyCast stages i key)
  have encodeSame : ∀ raw,
      encode (retainedStageActualProgram stages i) raw =
        cast sameKey (encode (terminalHistoryStageObserver stages i) raw) := by
    intro raw
    rw [sameKeyEq]
    exact (encode_cast_key_type_eq_of_groups_eq
      (terminalHistoryStageObserver stages i) (retainedStageActualProgram stages i)
      observerGroupsEq raw).symm
  have databaseSame : ∀ key,
      stageDatabase (cast sameKey key) = observerDatabase key := by
    intro key
    have keySame : historyStageKeyCast stages i (cast sameKey key) =
        historyObserverKeyEquiv stages i key := by
      apply Subtype.ext
      change included (historyProgram stages)
          (cast (history_stage_target_key_eq_history stages i) (cast sameKey key)) =
        included (terminalHistoryStageObserver stages i) key
      have stageHistoryGroups : groups (retainedStageActualProgram stages i) =
          groups (historyProgram stages) :=
        (congrArg groups (historyStageProgramEq stages i)).trans
          (terminalHistoryStageObserver_groups_eq stages i)
      calc
        included (historyProgram stages)
            (cast (history_stage_target_key_eq_history stages i) (cast sameKey key)) =
          included (retainedStageActualProgram stages i) (cast sameKey key) := by
            exact included_cast_key_type_eq_of_groups_eq
              (retainedStageActualProgram stages i) (historyProgram stages)
              stageHistoryGroups (cast sameKey key)
        _ = included (terminalHistoryStageObserver stages i) key := by
            rw [sameKeyEq]
            exact included_cast_key_type_eq_of_groups_eq
              (terminalHistoryStageObserver stages i)
              (retainedStageActualProgram stages i) observerGroupsEq key
    change completion (historyStageKeyCast stages i (cast sameKey key)) =
      completion (historyObserverKeyEquiv stages i key)
    exact congrArg completion keySame
  exact acceptedBranchClaims_cast_program groupedDecode
    (terminalHistoryStageObserver stages i) (retainedStageActualProgram stages i)
    actualEq.symm sameKey (encode (terminalHistoryStageObserver stages i))
    (encode (retainedStageActualProgram stages i)) encodeSame readback.observerBranch
    observerDatabase stageDatabase databaseSame observerComplete

/-- Any accepted terminal readback whose raw calls are contained in one
completed history transcript has the original history as its exact branch
prefix.  This rules out an unrelated accepted replay branch without adding
oracle, readback, or selector hypotheses. -/
theorem accepted_readback_reuses_exact_history_prefix
    (stages : List HistoryStage) (i : Fin stages.length)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (readback : AcceptedHistoryStageReadback stages i historyBranch) :
    ∃ replayBranch : Branches groupedDecode (indexedStageVerifierProgram stages i),
      readback.observerBranch = sequentialUnitBranch groupedDecode
        (historyProgram stages) historyBranch (indexedStageVerifierProgram stages i)
        replayBranch ∧
      branchResult groupedDecode (indexedStageVerifierProgram stages i) replayBranch = some () := by
  exact ⟨readback.replayStageBranch, readback.observerBranchEq,
    readback.replayStageAccepted⟩

/-- Readback state identity is established for the readback stored by the
history selector itself.  Its accepted first component is forced to be the
original history branch by the common completion, and its retained suffix
replays only already-known history answers. -/
theorem accepted_readback_physical_run_eq_history
    (stages : List HistoryStage) (i : Fin stages.length)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (readback : AcceptedHistoryStageReadback stages i historyBranch)
    (initial : CmsState (Key := Key (historyProgram stages))
      (Counter := GroupCounter) (BaseWork := BaseWork)) :
    physicalRun (encode (historyProgram stages)) groupedDecode
        (terminalHistoryStageObserver stages i) readback.observerBranch initial =
      physicalRun (encode (historyProgram stages)) groupedDecode
        (historyProgram stages) historyBranch initial := by
  obtain ⟨replayBranch, observerEq, replayAccepted⟩ :=
    accepted_readback_reuses_exact_history_prefix stages i historyBranch readback
  have observerRun := sequentialUnitBranch_physicalRun
    groupedDecode (encode (historyProgram stages)) (historyProgram stages)
    (indexedStageVerifierProgram stages i) historyBranch replayBranch
    readback.historyAccepted initial
  rw [observerEq]
  have replayKnown : ∀ claim,
      claim ∈ branchClaims (branchKeys (encode (historyProgram stages)) groupedDecode
        (indexedStageVerifierProgram stages i) replayBranch)
        (branchAnswers (encode (historyProgram stages)) groupedDecode
          (indexedStageVerifierProgram stages i) replayBranch) →
      KnownAt claim.1 claim.2 (globalDecompress
        (physicalRun (encode (historyProgram stages)) groupedDecode
          (historyProgram stages) historyBranch initial)) := by
    intro claim member
    rw [branch_claims_eq_answer_log] at member
    rcases List.mem_map.mp member with ⟨call, callMember, rfl⟩
    have observerMember : call ∈ answerLog groupedDecode
        (terminalHistoryStageObserver stages i) readback.observerBranch := by
      change call ∈ answerLog groupedDecode
        (sequentialUnitProgram (historyProgram stages)
          (indexedStageVerifierProgram stages i)) readback.observerBranch
      rw [observerEq]
      rw [sequentialUnitBranch_answerLog groupedDecode (historyProgram stages)
        (indexedStageVerifierProgram stages i) historyBranch replayBranch
        readback.historyAccepted]
      exact List.mem_append.mpr (Or.inr callMember)
    have historyMember := readback.answerLogSubset call observerMember
    have historyClaim : (encode (historyProgram stages) call.1, call.2) ∈
        branchClaims (branchKeys (encode (historyProgram stages)) groupedDecode
          (historyProgram stages) historyBranch)
          (branchAnswers (encode (historyProgram stages)) groupedDecode
            (historyProgram stages) historyBranch) := by
      rw [branch_claims_eq_answer_log]
      exact List.mem_map.mpr ⟨call, historyMember, rfl⟩
    exact physical_branch_claim_known_at_standard
      (encode (historyProgram stages)) groupedDecode (historyProgram stages)
      historyBranch initial (encode (historyProgram stages) call.1, call.2) historyClaim
  have replayIdentity := physicalRun_eq_self_on_known_branch
    (encode (historyProgram stages)) groupedDecode
    (indexedStageVerifierProgram stages i) replayBranch
    (physicalRun (encode (historyProgram stages)) groupedDecode
      (historyProgram stages) historyBranch initial) replayKnown
  change physicalRun (encode (historyProgram stages)) groupedDecode
      (sequentialUnitProgram (historyProgram stages) (indexedStageVerifierProgram stages i))
      (sequentialUnitBranch groupedDecode (historyProgram stages) historyBranch
        (indexedStageVerifierProgram stages i) replayBranch) initial =
    physicalRun (encode (historyProgram stages)) groupedDecode
      (historyProgram stages) historyBranch initial
  rw [observerRun]
  exact replayIdentity

/-- Destructing the full-history selector yields its exact retained-stage
failure selector on the same global view, transported through
`historyStageView`.  The observer branch is the accepted readback branch
stored in that selector, not a fresh execution. -/
theorem history_role_selector_supplies_retained_stage_failure
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (fallback : RawDigest) (fuel : Nat)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (role : Role)
    (view : SmzaRp05ConditionedExecution.XKey (nonchallengeRawKeySet
      (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs role (advice role) 28 28 (fun _ => ∅))) →
      Option (VectorOutput GroupCounter))
    (selected : currentHistoryFailureRoleSelector (BaseWork := BaseWork)
      stages commonNs stageNsEq model bounded advice fallback fuel
      historyBranch role view) :
    ∃ i : Fin stages.length,
      ∃ readback : AcceptedHistoryStageReadback stages i historyBranch,
        currentAcceptedXViewFailureRoleSelector
          (historyStageProducer stages i) (stages[i.val]).ns
          (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce
          fallback fuel (historyStageContext stages i model bounded advice role)
          role
          (castProgramBranch groupedDecode (terminalHistoryStageObserver stages i)
            (actualProgram (historyStageProducer stages i) (stages[i.val]).ns
              (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce)
            (historyStageProgramEq stages i).symm readback.observerBranch)
          (historyStageView (BaseWork := BaseWork) stages i commonNs (stageNsEq i)
            model bounded advice role view) := by
  rcases selected with ⟨completion, viewMatches, historyComplete,
    i, readback, stageFailure⟩
  exact ⟨i, readback, stageFailure⟩

/-- A nonzero selected history-role coefficient transfers to the exact
retained-stage failure selector carried by that history branch.  All stage
data are the canonical casts of the one history fiber; the readback and
same-branch replay are the stored accepted-history witnesses. -/
theorem history_failure_role_selected_support_transfers_to_retained_stage
    (stages : List HistoryStage) (commonNs : Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : ∀ role : Role, AllEarlierTables model role)
    (fallback : RawDigest) (fuel : Nat) (blockCap : Role → Nat)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (role : Role)
    (dummy : ActiveKey
      (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs role (advice role) 28 28 (fun _ => ∅)).role
      blockCap
      (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs role (advice role) 28 28 (fun _ => ∅)).keyBytes)
    (fixed : FixedTable
      (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs role (advice role) 28 28 (fun _ => ∅)) blockCap)
    (initial : CmsState (Key := Key (historyProgram stages))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis
      (ActiveKey
        (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
          model bounded commonNs role (advice role) 28 28 (fun _ => ∅)).role
        blockCap
        (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
          model bounded commonNs role (advice role) 28 28 (fun _ => ∅)).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (ActiveMemory (currentGroupedContext (BaseWork := BaseWork)
        (historyProgram stages) model bounded commonNs role (advice role)
        28 28 (fun _ => ∅))))
    (support : selectedRoleState
      (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
        model bounded commonNs role (advice role) 28 28 (fun _ => ∅))
      blockCap (encode (historyProgram stages)) groupedDecode (historyProgram stages)
      historyBranch fixed
      (fixedFiberToActive
        (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
          model bounded commonNs role (advice role) 28 28 (fun _ => ∅))
        blockCap dummy fixed
        (otherRoleTransform
          (currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
            model bounded commonNs role (advice role) 28 28 (fun _ => ∅))
          blockCap initial))
      (fun view _work => currentHistoryFailureRoleSelector
        (BaseWork := BaseWork) stages commonNs stageNsEq model bounded advice
        fallback fuel historyBranch role view) basis ≠ 0) :
    ∃ i : Fin stages.length,
      ∃ readback : AcceptedHistoryStageReadback stages i historyBranch,
      let sourceFiberBundle : HistoryRetainedRoleFiberBundle (BaseWork := BaseWork)
          (Key (historyProgram stages)) blockCap :=
        ⟨currentGroupedContext (BaseWork := BaseWork) (historyProgram stages)
          model bounded commonNs role (advice role) 28 28 (fun _ => ∅),
          (fixed, (dummy, basis))⟩
      let sameKey := (history_stage_target_key_eq_history stages i).symm
      let targetFiberBundle := cast
        (congrArg (fun key => HistoryRetainedRoleFiberBundle (BaseWork := BaseWork)
          key blockCap) sameKey) sourceFiberBundle
      let fiberContextEq :=
        (history_retained_role_bundle_context_cast sameKey blockCap sourceFiberBundle).trans
          (history_stage_role_context_cast_eq (BaseWork := BaseWork) stages i
            commonNs (stageNsEq i) model bounded role advice)
      ∃ keyFiber : HistoryRetainedRoleFiberBundle (BaseWork := BaseWork)
        (Key (retainedStageActualProgram stages i)) blockCap,
      ∃ fixedStage : FixedTable (historyStageContext (BaseWork := BaseWork)
        stages i model bounded advice role) blockCap,
      ∃ dummyStage : ActiveKey
        (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role).role
        blockCap
        (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role).keyBytes,
      ∃ initialStage : CmsState
        (Key := Key (retainedStageActualProgram stages i))
        (Counter := GroupCounter) (BaseWork := BaseWork),
      ∃ basisStage : Basis
        (ActiveKey
          (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role).role
          blockCap
          (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role).keyBytes)
        (VectorOutput GroupCounter) (VectorOutput GroupCounter)
        (ActiveMemory (historyStageContext (BaseWork := BaseWork)
          stages i model bounded advice role)),
        keyFiber = targetFiberBundle ∧
        fixedStage = cast
          (congrArg (fun ctx => FixedTable ctx blockCap)
            fiberContextEq) targetFiberBundle.2.1 ∧
        dummyStage = cast
          (congrArg (fun ctx => ActiveKey ctx.role blockCap ctx.keyBytes)
            fiberContextEq) targetFiberBundle.2.2.1 ∧
        initialStage = cast
          (congrArg (fun key => CmsState (Key := key) (Counter := GroupCounter)
            (BaseWork := BaseWork))
            (history_stage_target_key_eq_history stages i).symm) initial ∧
        basisStage = cast
          (congrArg (fun ctx => Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
            (VectorOutput GroupCounter) (VectorOutput GroupCounter) (ActiveMemory ctx))
            fiberContextEq) targetFiberBundle.2.2.2 ∧
        selectedRoleState
          (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role)
          blockCap (encode (retainedStageActualProgram stages i)) groupedDecode
          (retainedStageActualProgram stages i)
          (retainedStageActualBranch stages i historyBranch readback)
          fixedStage
          (fixedFiberToActive
            (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role)
            blockCap dummyStage fixedStage
            (otherRoleTransform
              (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role)
              blockCap initialStage))
          (fun view _work => currentAcceptedXViewFailureRoleSelector
            (historyStageProducer stages i) (stages[i.val]).ns
            (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce
            fallback fuel
            (historyStageContext (BaseWork := BaseWork) stages i model bounded advice role)
            role (retainedStageActualBranch stages i historyBranch readback) view)
          basisStage ≠ 0 := by
  classical
  let historyCtx := currentGroupedContext (BaseWork := BaseWork)
    (historyProgram stages) model bounded commonNs role (advice role) 28 28 (fun _ => ∅)
  let sourceInitial := fixedFiberToActive historyCtx blockCap dummy fixed
    (otherRoleTransform historyCtx blockCap initial)
  let sourceSelect : (SmzaRp05ConditionedExecution.XKey
      (nonchallengeRawKeySet historyCtx) → Option (VectorOutput GroupCounter)) →
      SmzaRp05CurrentSelectedChallengeClaims.SelectedWork (Counter := GroupCounter)
        (BaseWork := BaseWork) → Prop :=
    fun view _work => currentHistoryFailureRoleSelector (BaseWork := BaseWork)
      stages commonNs stageNsEq model bounded advice fallback fuel historyBranch role view
  let sourceEvent : (work : ActiveMemory historyCtx) →
      Database (ActiveKey historyCtx.role blockCap historyCtx.keyBytes)
        (VectorOutput GroupCounter) → Prop := fun work database =>
    branchXRoleSelector historyCtx blockCap (encode (historyProgram stages)) groupedDecode
      (historyProgram stages) historyBranch (nonchallengeRawKeySet historyCtx)
      (by
        intro claim member
        exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
          of_decide_eq_true (List.mem_filter.mp member).2⟩)
      sourceSelect
      (activeXView historyCtx blockCap (nonchallengeRawKeySet historyCtx)
        (nonchallenge_raw_key_set_unrecognized historyCtx) database)
      work.original.2.2
  have sourceSupport : workspaceEventProjection sourceEvent
      (mixedRun historyCtx blockCap fixed (encode (historyProgram stages)) groupedDecode
        (historyProgram stages) historyBranch sourceInitial) basis ≠ 0 := by
    change workspaceEventProjection sourceEvent
      (mixedRun historyCtx blockCap fixed (encode (historyProgram stages)) groupedDecode
        (historyProgram stages) historyBranch sourceInitial) basis ≠ 0 at support
    exact support
  have sourceSelected : sourceEvent basis.workspace basis.database := by
    by_contra notSelected
    apply sourceSupport
    change (if sourceEvent basis.workspace basis.database then _ else 0) = 0
    exact if_neg notSelected
  rcases sourceSelected.1 with ⟨completion, completionView, historyComplete,
    i, readback, stageFailure⟩
  let stageCtx := historyStageContext (BaseWork := BaseWork) stages i model bounded advice role
  let contextEq := history_stage_role_context_cast_eq (BaseWork := BaseWork)
    stages i commonNs (stageNsEq i) model bounded role advice
  let sameKey := (history_stage_target_key_eq_history stages i).symm
  let sourceFiberBundle : HistoryRetainedRoleFiberBundle (BaseWork := BaseWork)
      (Key (historyProgram stages)) blockCap :=
    ⟨historyCtx, (fixed, (dummy, basis))⟩
  let keyFiber : HistoryRetainedRoleFiberBundle (BaseWork := BaseWork)
      (Key (retainedStageActualProgram stages i)) blockCap :=
    cast (congrArg (fun key => HistoryRetainedRoleFiberBundle (BaseWork := BaseWork)
      key blockCap) sameKey) sourceFiberBundle
  let fiberContextEq : keyFiber.1 = stageCtx :=
    (history_retained_role_bundle_context_cast sameKey blockCap sourceFiberBundle).trans
      contextEq
  let sameActiveKey := active_key_type_eq_of_context_cast sameKey historyCtx stageCtx
    contextEq blockCap
  let sameWork := congrArg (fun key => ActiveRouteMemory key (VectorOutput GroupCounter)
    (SmzaRp05CurrentAdaptiveExecution.Work (Counter := GroupCounter)
      (BaseWork := BaseWork))) sameKey
  let fixedStage : FixedTable stageCtx blockCap :=
    cast (congrArg (fun ctx => FixedTable ctx blockCap) fiberContextEq) keyFiber.2.1
  let dummyStage : ActiveKey stageCtx.role blockCap stageCtx.keyBytes :=
    cast (congrArg (fun ctx => ActiveKey ctx.role blockCap ctx.keyBytes) fiberContextEq)
      keyFiber.2.2.1
  let initialStage : CmsState (Key := Key (retainedStageActualProgram stages i))
      (Counter := GroupCounter) (BaseWork := BaseWork) := cast
        (congrArg (fun key => CmsState (Key := key) (Counter := GroupCounter)
          (BaseWork := BaseWork)) sameKey) initial
  let basisStage : Basis (ActiveKey stageCtx.role blockCap stageCtx.keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter) (ActiveMemory stageCtx) :=
    cast (congrArg (fun ctx => Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter) (ActiveMemory ctx))
      fiberContextEq) keyFiber.2.2.2
  have basisStageEq : basisStage = cast (basisTypeEq2 sameActiveKey sameWork) basis := by
    change cast (congrArg (fun ctx => Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter) (ActiveMemory ctx))
      fiberContextEq) keyFiber.2.2.2 = cast (basisTypeEq2 sameActiveKey sameWork) basis
    exact history_retained_role_bundle_basis_cast sameKey blockCap sourceFiberBundle
      stageCtx contextEq
  let stageBranch := retainedStageActualBranch stages i historyBranch readback
  let stageInitial := fixedFiberToActive stageCtx blockCap dummyStage fixedStage
    (otherRoleTransform stageCtx blockCap initialStage)
  let stageSelect : (SmzaRp05ConditionedExecution.XKey
      (nonchallengeRawKeySet stageCtx) → Option (VectorOutput GroupCounter)) →
      SmzaRp05CurrentSelectedChallengeClaims.SelectedWork (Counter := GroupCounter)
        (BaseWork := BaseWork) → Prop :=
    fun view _work => currentAcceptedXViewFailureRoleSelector
      (historyStageProducer stages i) (stages[i.val]).ns
      (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce
      fallback fuel stageCtx role stageBranch view
  let stageEvent : (work : ActiveMemory stageCtx) →
      Database (ActiveKey stageCtx.role blockCap stageCtx.keyBytes)
        (VectorOutput GroupCounter) → Prop := fun work database =>
    branchXRoleSelector stageCtx blockCap (encode (retainedStageActualProgram stages i))
      groupedDecode (retainedStageActualProgram stages i) stageBranch
      (nonchallengeRawKeySet stageCtx)
      (by
        intro claim member
        exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
          of_decide_eq_true (List.mem_filter.mp member).2⟩)
      stageSelect
      (activeXView stageCtx blockCap (nonchallengeRawKeySet stageCtx)
        (nonchallenge_raw_key_set_unrecognized stageCtx) database)
      work.original.2.2
  have sameView : activeXView stageCtx blockCap (nonchallengeRawKeySet stageCtx)
      (nonchallenge_raw_key_set_unrecognized stageCtx) basisStage.database =
    historyStageView (BaseWork := BaseWork) stages i commonNs (stageNsEq i)
      model bounded advice role
      (activeXView historyCtx blockCap (nonchallengeRawKeySet historyCtx)
        (nonchallenge_raw_key_set_unrecognized historyCtx) basis.database) := by
    rw [basisStageEq]
    rw [history_basis_database_cast sameActiveKey sameWork basis]
    have viewTransport := history_active_x_view_cast sameKey historyCtx stageCtx
      contextEq blockCap
        basis.database (by
          intro key
          exact historyStageNonchallengeMem stages i commonNs (stageNsEq i)
            model bounded advice role key.val key.property)
    exact viewTransport.trans (by
      funext key
      unfold historyStageView historyStageKeyCast
      rfl)
  have targetSelected : stageEvent basisStage.workspace basisStage.database := by
    unfold stageEvent
    rw [sameView]
    rcases stageFailure with ⟨stageCompletion, stageViewMatches, stageClaims, stageOutcome⟩
    refine ⟨⟨stageCompletion, stageViewMatches, stageClaims, stageOutcome⟩, ?_⟩
    intro claim member
    have mixedMember : claim ∈ mixedBranchClaims stageCtx blockCap
        (encode (retainedStageActualProgram stages i)) groupedDecode
        (retainedStageActualProgram stages i) stageBranch :=
      (List.mem_filter.mp member).1
    have rawMember := mixed_active_claim_mem_branch_claims stageCtx blockCap
      (encode (retainedStageActualProgram stages i)) groupedDecode
      (retainedStageActualProgram stages i) stageBranch claim mixedMember
    have complete := stageClaims (claim.1.val, claim.2) rawMember
    have activeMember : claim.1.val ∈ nonchallengeRawKeySet stageCtx := by
      apply Finset.mem_filter.mpr
      exact ⟨Finset.mem_univ _, of_decide_eq_true (List.mem_filter.mp member).2⟩
    exact (stageViewMatches claim.1.val activeMember).symm.trans complete
  have basisStageWorkspaceEq : basisStage.workspace = cast sameWork basis.workspace := by
    rw [basisStageEq]
    exact history_basis_workspace_cast sameActiveKey sameWork basis
  have basisStageDatabaseEq : basisStage.database =
      cast (databaseTypeEq sameActiveKey) basis.database := by
    rw [basisStageEq]
    exact history_basis_database_cast sameActiveKey sameWork basis
  have targetSelectedCast : stageEvent (cast sameWork basis.workspace)
      (cast (databaseTypeEq sameActiveKey) basis.database) := by
    have eventEq : stageEvent basisStage.workspace basisStage.database =
        stageEvent (cast sameWork basis.workspace)
          (cast (databaseTypeEq sameActiveKey) basis.database) :=
      congrArg₂ stageEvent basisStageWorkspaceEq basisStageDatabaseEq
    exact Eq.mp eventEq targetSelected
  have targetState : selectedRoleState stageCtx blockCap
      (encode (retainedStageActualProgram stages i)) groupedDecode
      (retainedStageActualProgram stages i) stageBranch fixedStage stageInitial stageSelect =
      workspaceEventProjection stageEvent
        (mixedRun stageCtx blockCap fixedStage
          (encode (retainedStageActualProgram stages i)) groupedDecode
          (retainedStageActualProgram stages i) stageBranch stageInitial) := rfl
  have physicalEq : cast
      (stateTypeEq2 sameKey rfl)
        (physicalRun (encode (historyProgram stages)) groupedDecode
          (historyProgram stages) historyBranch initial) =
      physicalRun (encode (retainedStageActualProgram stages i)) groupedDecode
        (retainedStageActualProgram stages i) stageBranch initialStage := by
    have stageProgramRun := physicalRun_cast_program
      (encode (retainedStageActualProgram stages i)) groupedDecode
      (terminalHistoryStageObserver stages i) (retainedStageActualProgram stages i)
      (historyStageProgramEq stages i).symm readback.observerBranch
      initialStage
    have observerIdentity := accepted_readback_physical_run_eq_history
      stages i historyBranch readback initial
    have encEq : ∀ raw, encode (retainedStageActualProgram stages i) raw =
        cast sameKey (encode (historyProgram stages) raw) := by
      intro raw
      have groupsEq : groups (historyProgram stages) =
          groups (retainedStageActualProgram stages i) :=
        (terminalHistoryStageObserver_groups_eq stages i).symm.trans
          (congrArg groups (historyStageProgramEq stages i).symm)
      exact (encode_cast_key_type_eq_of_groups_eq
        (historyProgram stages) (retainedStageActualProgram stages i)
        groupsEq raw).symm
    have inputRun := physicalRun_cast_input sameKey
      (encode (historyProgram stages)) (encode (retainedStageActualProgram stages i))
      encEq groupedDecode (terminalHistoryStageObserver stages i)
      readback.observerBranch initial
    -- The program transport identifies the exact accepted readback branch;
    -- input transport identifies the same history state on the stage Key.
    calc
      cast (stateTypeEq2 sameKey rfl)
          (physicalRun (encode (historyProgram stages)) groupedDecode
            (historyProgram stages) historyBranch initial) =
        cast (stateTypeEq2 sameKey rfl)
          (physicalRun (encode (historyProgram stages)) groupedDecode
            (terminalHistoryStageObserver stages i) readback.observerBranch initial) := by
              exact congrArg (cast (stateTypeEq2 sameKey rfl)) observerIdentity.symm
      _ = physicalRun (encode (retainedStageActualProgram stages i)) groupedDecode
          (terminalHistoryStageObserver stages i) readback.observerBranch initialStage :=
            inputRun
      _ = physicalRun (encode (retainedStageActualProgram stages i)) groupedDecode
          (retainedStageActualProgram stages i) stageBranch initialStage := by
            exact stageProgramRun.symm
  have mixedEq : cast
      (stateTypeEq2 sameActiveKey sameWork)
        (mixedRun historyCtx blockCap fixed (encode (historyProgram stages))
          groupedDecode (historyProgram stages) historyBranch sourceInitial) =
      mixedRun stageCtx blockCap fixedStage
        (encode (retainedStageActualProgram stages i)) groupedDecode
        (retainedStageActualProgram stages i) stageBranch stageInitial := by
    have sourceMixed := physical_run_to_mixed_same_fiber historyCtx blockCap dummy fixed
      (encode (historyProgram stages)) groupedDecode (historyProgram stages)
      historyBranch initial
    have stageMixed := physical_run_to_mixed_same_fiber stageCtx blockCap dummyStage fixedStage
      (encode (retainedStageActualProgram stages i)) groupedDecode
      (retainedStageActualProgram stages i) stageBranch initialStage
    rw [← sourceMixed, ← stageMixed]
    calc
      cast (stateTypeEq2 sameActiveKey sameWork)
          (fixedFiberToActive historyCtx blockCap dummy fixed
            (otherRoleTransform historyCtx blockCap
              (physicalRun (encode (historyProgram stages)) groupedDecode
                (historyProgram stages) historyBranch initial))) =
        fixedFiberToActive stageCtx blockCap dummyStage fixedStage
          (otherRoleTransform stageCtx blockCap
            (cast (stateTypeEq2 sameKey rfl)
              (physicalRun (encode (historyProgram stages)) groupedDecode
                (historyProgram stages) historyBranch initial))) :=
          history_retained_role_bundle_active_map_cast sameKey blockCap
            sourceFiberBundle stageCtx contextEq
            (physicalRun (encode (historyProgram stages)) groupedDecode
              (historyProgram stages) historyBranch initial)
      _ = fixedFiberToActive stageCtx blockCap dummyStage fixedStage
          (otherRoleTransform stageCtx blockCap
            (physicalRun (encode (retainedStageActualProgram stages i)) groupedDecode
              (retainedStageActualProgram stages i) stageBranch initialStage)) := by
          exact congrArg (fun state => fixedFiberToActive stageCtx blockCap dummyStage
            fixedStage (otherRoleTransform stageCtx blockCap state)) physicalEq
  have supportTransferred := selected_projection_support_cast_at_basis_two_types
    sameActiveKey sameWork sourceEvent stageEvent
    (mixedRun historyCtx blockCap fixed (encode (historyProgram stages)) groupedDecode
      (historyProgram stages) historyBranch sourceInitial)
    (mixedRun stageCtx blockCap fixedStage
      (encode (retainedStageActualProgram stages i)) groupedDecode
      (retainedStageActualProgram stages i) stageBranch stageInitial)
    mixedEq basis sourceSelected targetSelectedCast sourceSupport
  have stageSupport : selectedRoleState stageCtx blockCap
      (encode (retainedStageActualProgram stages i)) groupedDecode
      (retainedStageActualProgram stages i) stageBranch fixedStage stageInitial
      stageSelect basisStage ≠ 0 := by
    rw [targetState, basisStageEq]
    exact supportTransferred
  exact ⟨i, readback, keyFiber, fixedStage, dummyStage, initialStage, basisStage,
    rfl, rfl, rfl, rfl, rfl, stageSupport⟩

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentHistorySelectedRoleStateReplay
