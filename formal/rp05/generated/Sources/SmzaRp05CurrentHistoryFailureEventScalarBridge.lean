import SmzaRp05CurrentAdviceDependentPhysicalMass
import SmzaRp05ActualEventRecertification
import SmzaRp05CurrentAdaptiveExecution
import SmzaRp05ConditionedExecution
import SmzaRoleDomainConditioning
import SmzaChallengeStageTargets
import SmzaRp05CurrentHistorySelectedRoleStateReplay
import SmzaRp05CurrentMixedBranchClaimReadback
import SmzaRp05CurrentAcceptedDecsExtractionFailureEvent
import SmzaRp05CurrentHistoryVerifierProgram
import SmzaRp05CurrentHistorySelectorContexts
import SmzaRp05CurrentAcceptedOrdinaryMassBound
import SmzaRp05CurrentHistoryFailureMass
import SmzaRp05CurrentHistoryFailureCoverage
import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05ExecutableAddressCompiler
import SmzaRp05CurrentPhysicalBranchClaimReadback
import SmzaRp05CurrentProgramKeyReadbackTransport
import SmzaRp05CmsTwoTypeSelectedSupportTransport
import SmzaRp05ExecutableProgramEquality
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05GroupedSuffix
import SmzaRp05TracePrefixes
import SmzaRp05ConcreteSuffix
import SmzaRp05RelationRefinement
import SmzaRp05GeneratedCertificates
import HegemonCrypto.CmsOracleDatabaseBridge
import HegemonCrypto.FiniteOracleDatabase

/-! # Pointwise event transport for the one-history scalar cover

The helpers here transport a missing-claim conclusion through an actual
stage-to-history claim inclusion and identify current-advice events after
the checked history-stage context cast.  They do not add probability or
coverage premises.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryFailureEventScalarBridge

open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open scoped Classical
open HegemonCrypto.CmsCompressedOracle (Basis)
open SmzaRp05ActualEventRecertification (event)
open SmzaRp05CurrentAdviceDependentPhysicalMass (currentAdviceEventSpec)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05ConditionedExecution (FixedTable)
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRp05CurrentHistoryVerifierProgram
  (HistoryStage historyProgram terminalHistoryStageObserver
    terminalHistoryStageObserver_groups_eq)
open SmzaRp05CurrentHistoryFailureMass (emptyHistoryAdvice historyContext)
open SmzaRp05CurrentHistoryFailureCoverage
  (currentHistoryFailureRoleSelector historyStageContext historyStageProgramEq
    historyObserverKeyEquiv
    terminal_observer_claims_subset_history
    AcceptedHistoryStageReadback)
open SmzaRp05CurrentHistorySelectedRoleStateReplay
  (HistoryRetainedRoleFiberBundle
    history_failure_role_selected_support_transfers_to_retained_stage
    mixed_active_claim_mem_branch_claims)
open SmzaRp05CurrentHistorySelectorContexts
  (history_stage_target_key_eq_history historyStageProducer)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentFullOrRoleExtraction (currentAcceptedXViewFailureRoleSelector)
open SmzaRp05CurrentSelectedChallengeClaims (recognizedActiveChallengeClaims)
open SmzaRp05CurrentMixedBranchClaimReadback (mixedBranchClaims)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05ExecutableAddressCompiler (groups)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims)
open SmzaRp05CurrentProgramKeyReadbackTransport (branchClaims_cast_program)
open SmzaRp05FiniteKeyStateEmbedding
  (key_type_eq_of_groups_eq encode_cast_key_type_eq_of_groups_eq
    included_cast_key_type_eq_of_groups_eq)
open SmzaRp05ExecutableProgramEquality (castProgramBranch)
open SmzaRp05CurrentAcceptedDecsExtractionFailureEvent
  (grouped_four_role_failure_support_implies_current_advice_event_or_missing_claims)
open SmzaRp05CurrentAdaptiveExecution (Work)
open SmzaRp05ConditionedExecution
  (ActiveMemory FixedTable fixedFiberToActive otherRoleTransform activeMemoryEquiv)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05ActualEventRecertification (event)
open SmzaRp05CurrentAdviceDependentPhysicalMass (currentAdviceEventSpec)
open SmzaRp05TracePrefixes (RelationModel)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05RelationRefinement (GeneratedCertificates)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05CurrentAdaptiveExecution (CmsState)
open SmzaRp05CurrentFullOrRoleExtraction (currentAcceptedXViewFailureRoleSelector)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRoleDomainConditioning (ActiveKey RoleActive)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05GroupedSuffix (GroupCounter)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryVerifierProgram.historyProgram
  HegemonCrypto.SmallWood.SmzaRp05CurrentHistorySelectorContexts.historyStageProducer
  HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates.currentDsl

/-- A missing event over a sublist transports to the corresponding larger
claim list whenever each source claim maps to an equal database cell. -/
theorem missing_claims_of_mapped_subset
    {SourceKey TargetKey Output : Type}
    [Fintype SourceKey] [DecidableEq SourceKey]
    [Fintype TargetKey] [DecidableEq TargetKey]
    (sourceClaims : List (SourceKey × Output))
    (targetClaims : List (TargetKey × Output))
    (keyMap : SourceKey → TargetKey)
    (claimsSubset : ∀ claim, claim ∈ sourceClaims →
      (keyMap claim.1, claim.2) ∈ targetClaims)
    (sourceDatabase : Database SourceKey Output)
    (targetDatabase : Database TargetKey Output)
    (databaseAgreement : ∀ key, sourceDatabase key = targetDatabase (keyMap key))
    (sourceMissing : ¬ ClaimsDatabaseEvent sourceClaims sourceDatabase) :
    ¬ ClaimsDatabaseEvent targetClaims targetDatabase := by
  intro targetComplete
  apply sourceMissing
  intro claim member
  calc
    sourceDatabase claim.1 = targetDatabase (keyMap claim.1) :=
      databaseAgreement claim.1
    _ = claim.2 :=
      targetComplete (keyMap claim.1, claim.2) (claimsSubset claim member)

/-- Transfer either side of an event-or-missing-claims result across the
exact event equivalence and database/key transports already established by a
caller.  The source and target key spaces remain abstract. -/
private theorem event_or_missing_of_exact_transports
    {SourceKey TargetKey Output : Type}
    [Fintype SourceKey] [DecidableEq SourceKey]
    [Fintype TargetKey] [DecidableEq TargetKey]
    {SourceEvent TargetEvent : Prop}
    (eventBridge : TargetEvent ↔ SourceEvent)
    (sourceClaims : List (SourceKey × Output))
    (targetClaims : List (TargetKey × Output))
    (keyMap : SourceKey → TargetKey)
    (claimsSubset : ∀ claim, claim ∈ sourceClaims →
      (keyMap claim.1, claim.2) ∈ targetClaims)
    (sourceDatabase : Database SourceKey Output)
    (targetDatabase : Database TargetKey Output)
    (databaseAgreement : ∀ key, sourceDatabase key = targetDatabase (keyMap key))
    (sourceOutcome : SourceEvent ∨
      ¬ ClaimsDatabaseEvent sourceClaims sourceDatabase) :
    TargetEvent ∨ ¬ ClaimsDatabaseEvent targetClaims targetDatabase := by
  rcases sourceOutcome with sourceEvent | sourceMissing
  · exact Or.inl (eventBridge.mpr sourceEvent)
  · exact Or.inr (missing_claims_of_mapped_subset sourceClaims targetClaims
      keyMap claimsSubset sourceDatabase targetDatabase databaseAgreement sourceMissing)

/-- Current-advice event meaning is invariant under equality of the actual
context and fixed-table values.  History-stage casts are reduced to this
lemma only after `history_stage_context_cast_eq` has identified the context. -/
theorem current_advice_event_iff_of_context_fixed_eq
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctxLeft ctxRight : Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork))
    (ctxEq : ctxLeft = ctxRight)
    (blockCap : Role → Nat)
    (fixedLeft : FixedTable ctxLeft blockCap)
    (fixedRight : FixedTable ctxRight blockCap)
    (fixedEq : cast (congrArg (fun ctx => FixedTable ctx blockCap) ctxEq)
      fixedLeft = fixedRight)
    (cap : Nat)
    (memory : SmzaRp05ConditionedExecution.ActiveMemory ctxLeft)
    (memoryRight : SmzaRp05ConditionedExecution.ActiveMemory ctxRight)
    (memoryEq : cast (congrArg
      (fun ctx => SmzaRp05ConditionedExecution.ActiveMemory ctx) ctxEq) memory = memoryRight)
    (database : Database
      (SmzaRoleDomainConditioning.ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
      (SmzaRp05CurrentAdaptiveExecution.Output (Counter := Counter)))
    (databaseRight : Database
      (SmzaRoleDomainConditioning.ActiveKey ctxRight.role blockCap ctxRight.keyBytes)
      (SmzaRp05CurrentAdaptiveExecution.Output (Counter := Counter)))
    (databaseEq : cast (congrArg (fun ctx => Database
      (SmzaRoleDomainConditioning.ActiveKey ctx.role blockCap ctx.keyBytes)
      (SmzaRp05CurrentAdaptiveExecution.Output (Counter := Counter))) ctxEq)
      database = databaseRight) :
    (event (currentAdviceEventSpec ctxLeft blockCap fixedLeft cap)
      (SmzaRp05ConditionedExecution.activeMemoryEquiv ctxLeft memory) database ↔
    event (currentAdviceEventSpec ctxRight blockCap fixedRight cap)
      (SmzaRp05ConditionedExecution.activeMemoryEquiv ctxRight memoryRight)
      databaseRight) := by
  cases ctxEq
  cases fixedEq
  cases memoryEq
  cases databaseEq
  rfl

/-- Generic two-step value transport for event predicates. This is the
abstract cast boundary used by the history adapter; concrete program and
context equalities are only passed as data. -/
private theorem current_advice_event_iff_of_canonical_transport
    {KeyLeft KeyRight Counter BaseWork : Type}
    [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
    [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
    [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctxLeft : Context (Key := KeyLeft) (Counter := Counter)
      (BaseWork := BaseWork))
    (ctxRight : Context (Key := KeyRight) (Counter := Counter)
      (BaseWork := BaseWork))
    (keyEq : KeyLeft = KeyRight)
    (contextEq : cast (congrArg (fun key => Context (Key := key)
      (Counter := Counter) (BaseWork := BaseWork)) keyEq) ctxLeft = ctxRight)
    (blockCap : Role → Nat)
    (fixedLeft : FixedTable ctxLeft blockCap)
    (fixedRight : FixedTable ctxRight blockCap)
    (fixedTypeEq : FixedTable ctxLeft blockCap = FixedTable ctxRight blockCap)
    (fixedEq : fixedRight = cast fixedTypeEq fixedLeft)
    (cap : Nat)
    (memoryLeft : SmzaRp05ConditionedExecution.ActiveMemory ctxLeft)
    (memoryRight : SmzaRp05ConditionedExecution.ActiveMemory ctxRight)
    (memoryTypeEq : SmzaRp05ConditionedExecution.ActiveMemory ctxLeft =
      SmzaRp05ConditionedExecution.ActiveMemory ctxRight)
    (memoryEq : memoryRight = cast memoryTypeEq memoryLeft)
    (databaseLeft : Database
      (SmzaRoleDomainConditioning.ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
      (SmzaRp05CurrentAdaptiveExecution.Output (Counter := Counter)))
    (databaseRight : Database
      (SmzaRoleDomainConditioning.ActiveKey ctxRight.role blockCap ctxRight.keyBytes)
      (SmzaRp05CurrentAdaptiveExecution.Output (Counter := Counter)))
    (databaseTypeEq : Database
      (SmzaRoleDomainConditioning.ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
      (SmzaRp05CurrentAdaptiveExecution.Output (Counter := Counter)) =
      Database
        (SmzaRoleDomainConditioning.ActiveKey ctxRight.role blockCap ctxRight.keyBytes)
        (SmzaRp05CurrentAdaptiveExecution.Output (Counter := Counter)))
    (databaseEq : databaseRight = cast databaseTypeEq databaseLeft) :
    (event (currentAdviceEventSpec ctxLeft blockCap fixedLeft cap)
      (SmzaRp05ConditionedExecution.activeMemoryEquiv ctxLeft memoryLeft) databaseLeft ↔
    event (currentAdviceEventSpec ctxRight blockCap fixedRight cap)
      (SmzaRp05ConditionedExecution.activeMemoryEquiv ctxRight memoryRight)
      databaseRight) := by
  cases keyEq
  have sameFintype : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEq
  cases contextEq
  cases fixedTypeEq
  cases memoryTypeEq
  cases databaseTypeEq
  cases fixedEq
  cases memoryEq
  cases databaseEq
  rfl

private theorem context_cast_type_eq
    {KeyLeft KeyRight Counter BaseWork : Type}
    [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
    [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
    [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (keyEq : KeyLeft = KeyRight)
    (ctxLeft : Context (Key := KeyLeft) (Counter := Counter)
      (BaseWork := BaseWork))
    (ctxRight : Context (Key := KeyRight) (Counter := Counter)
      (BaseWork := BaseWork))
    (contextEq : cast (congrArg (fun key => Context (Key := key)
      (Counter := Counter) (BaseWork := BaseWork)) keyEq) ctxLeft = ctxRight)
    (F : {Key : Type} → Context (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) → Type) :
    F ctxLeft = F ctxRight := by
  cases keyEq
  have sameFintype : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEq
  cases contextEq
  rfl


private theorem retained_bundle_context_cast
    {BaseWork KeyLeft KeyRight : Type}
    [Fintype KeyLeft] [DecidableEq KeyLeft]
    [Fintype KeyRight] [DecidableEq KeyRight]
    (keyEq : KeyLeft = KeyRight) (blockCap : Role → Nat)
    (fiber : HistoryRetainedRoleFiberBundle (BaseWork := BaseWork) KeyLeft blockCap) :
    (cast (congrArg (fun key => HistoryRetainedRoleFiberBundle
      (BaseWork := BaseWork) key blockCap) keyEq) fiber).1 =
      cast (congrArg (fun key => Context (Key := key)
        (Counter := SmzaRp05GroupedSuffix.GroupCounter) (BaseWork := BaseWork)) keyEq)
        fiber.1 := by
  cases keyEq
  rfl

/-- Fixed advice is transported through the actual context stored in the
retained fiber, not through the preceding Key cast's intermediate context. -/
private theorem retained_fiber_fixed_cast
    {BaseWork KeyLeft KeyRight : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
    [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
    (keyEq : KeyLeft = KeyRight)
    (ctxLeft : Context (Key := KeyLeft) (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (ctxRight : Context (Key := KeyRight) (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (ctxEq : cast (congrArg (fun key => Context (Key := key)
      (Counter := SmzaRp05GroupedSuffix.GroupCounter) (BaseWork := BaseWork)) keyEq)
      ctxLeft = ctxRight)
    (blockCap : Role → Nat)
    (fixed : FixedTable ctxLeft blockCap)
    (dummy : ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
    (basis : Basis (ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctxLeft))
    (fiber : HistoryRetainedRoleFiberBundle (BaseWork := BaseWork) KeyRight blockCap)
    (fiberEq : fiber = cast (congrArg
      (fun key => HistoryRetainedRoleFiberBundle (BaseWork := BaseWork) key blockCap)
      keyEq) ⟨ctxLeft, (fixed, (dummy, basis))⟩)
    (fiberContextEq : fiber.1 = ctxRight)
    (fixedRight : FixedTable ctxRight blockCap)
    (fixedRightEq : fixedRight = cast
      (congrArg (fun ctx => FixedTable ctx blockCap) fiberContextEq) fiber.2.1)
    (fixedTypeEq : FixedTable ctxLeft blockCap = FixedTable ctxRight blockCap) :
    fixedRight = cast fixedTypeEq fixed := by
  cases keyEq
  have sameFintype : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEq
  cases ctxEq
  cases fixedTypeEq
  cases fiberEq
  cases fiberContextEq
  cases fixedRightEq
  rfl

private theorem retained_fiber_basis_cast
    {BaseWork KeyLeft KeyRight : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
    [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
    (keyEq : KeyLeft = KeyRight)
    (ctxLeft : Context (Key := KeyLeft) (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (ctxRight : Context (Key := KeyRight) (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (ctxEq : cast (congrArg (fun key => Context (Key := key)
      (Counter := SmzaRp05GroupedSuffix.GroupCounter) (BaseWork := BaseWork)) keyEq)
      ctxLeft = ctxRight)
    (blockCap : Role → Nat)
    (fixed : FixedTable ctxLeft blockCap)
    (dummy : ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
    (basis : Basis (ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctxLeft))
    (fiber : HistoryRetainedRoleFiberBundle (BaseWork := BaseWork) KeyRight blockCap)
    (fiberEq : fiber = cast (congrArg
      (fun key => HistoryRetainedRoleFiberBundle (BaseWork := BaseWork) key blockCap)
      keyEq) ⟨ctxLeft, (fixed, (dummy, basis))⟩)
    (fiberContextEq : fiber.1 = ctxRight)
    (basisRight : Basis (ActiveKey ctxRight.role blockCap ctxRight.keyBytes)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctxRight))
    (basisRightEq : basisRight = cast
      (congrArg (fun ctx => Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
        (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
        (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctx)) fiberContextEq)
      fiber.2.2.2)
    (basisTypeEq : Basis (ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctxLeft) =
      Basis (ActiveKey ctxRight.role blockCap ctxRight.keyBytes)
        (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
        (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctxRight)) :
    basisRight = cast basisTypeEq basis := by
  cases keyEq
  have sameFintype : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEq
  cases ctxEq
  cases basisTypeEq
  cases fiberEq
  cases fiberContextEq
  cases basisRightEq
  rfl

private theorem cast_context_basis_components
    {BaseWork KeyLeft KeyRight : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
    [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
    (ctxLeft : Context (Key := KeyLeft) (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (ctxRight : Context (Key := KeyRight) (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (keyEq : KeyLeft = KeyRight)
    (ctxEq : cast (congrArg (fun key => Context (Key := key)
      (Counter := SmzaRp05GroupedSuffix.GroupCounter) (BaseWork := BaseWork)) keyEq)
      ctxLeft = ctxRight)
    (blockCap : Role → Nat)
    (basisTypeEq : Basis (ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctxLeft) =
      Basis (ActiveKey ctxRight.role blockCap ctxRight.keyBytes)
        (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
        (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctxRight))
    (memoryTypeEq : ActiveMemory ctxLeft = ActiveMemory ctxRight)
    (databaseTypeEq : Database (ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
      (SmzaRp05CurrentAdaptiveExecution.Output (Counter := SmzaRp05GroupedSuffix.GroupCounter)) =
      Database (ActiveKey ctxRight.role blockCap ctxRight.keyBytes)
        (SmzaRp05CurrentAdaptiveExecution.Output (Counter := SmzaRp05GroupedSuffix.GroupCounter)))
    (basis : Basis (ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctxLeft)) :
    (cast basisTypeEq basis).workspace = cast memoryTypeEq basis.workspace ∧
    (cast basisTypeEq basis).database = cast databaseTypeEq basis.database := by
  cases keyEq
  have sameFintype : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEq
  cases ctxEq
  cases basisTypeEq
  cases memoryTypeEq
  cases databaseTypeEq
  exact ⟨rfl, rfl⟩

private theorem active_key_cast_value
    {BaseWork KeyLeft KeyRight : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
    [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
    (ctxLeft : Context (Key := KeyLeft) (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (ctxRight : Context (Key := KeyRight) (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (keyEq : KeyLeft = KeyRight)
    (ctxEq : cast (congrArg (fun key => Context (Key := key)
      (Counter := SmzaRp05GroupedSuffix.GroupCounter) (BaseWork := BaseWork)) keyEq)
      ctxLeft = ctxRight)
    (blockCap : Role → Nat)
    (activeKeyTypeEq : ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes =
      ActiveKey ctxRight.role blockCap ctxRight.keyBytes)
    (key : ActiveKey ctxRight.role blockCap ctxRight.keyBytes) :
    (cast activeKeyTypeEq.symm key).val = cast keyEq.symm key.val := by
  cases keyEq
  have sameFintype : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEq
  cases ctxEq
  cases activeKeyTypeEq
  rfl

private theorem cast_database_apply
    {KeyLeft KeyRight Output : Type}
    [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
    [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
    (keyEq : KeyLeft = KeyRight) (database : Database KeyLeft Output)
    (key : KeyRight) :
    (cast (congrArg (fun key => Database key Output) keyEq) database) key =
      database (cast keyEq.symm key) := by
  cases keyEq
  have sameFintype : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEq
  rfl

private theorem recognized_query_cast_context
    {BaseWork KeyLeft KeyRight : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
    [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
    (ctxLeft : Context (Key := KeyLeft) (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (ctxRight : Context (Key := KeyRight) (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (keyEq : KeyLeft = KeyRight)
    (ctxEq : cast (congrArg (fun key => Context (Key := key)
      (Counter := SmzaRp05GroupedSuffix.GroupCounter) (BaseWork := BaseWork)) keyEq)
      ctxLeft = ctxRight)
    (blockCap : Role → Nat)
    (activeKeyTypeEq : ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes =
      ActiveKey ctxRight.role blockCap ctxRight.keyBytes)
    (key : ActiveKey ctxRight.role blockCap ctxRight.keyBytes)
    (recognized : parseStageQuery
      (ctxRight.keyBytes key.val) ≠ none) :
    parseStageQuery
      (ctxLeft.keyBytes
        (cast activeKeyTypeEq.symm key).val) ≠ none := by
  cases keyEq
  have sameFintype : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEq
  cases ctxEq
  cases activeKeyTypeEq
  simpa using recognized

/-- Every raw answer-branch claim that has a live active key is retained in
the active mixed-branch transcript. -/
theorem active_branch_claim_mem_mixed_branch_claims
    {Key Counter BaseWork Result : Type}
    [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (claim : ActiveKey ctx.role blockCap ctx.keyBytes × VectorOutput Counter)
    (member : (claim.1.val, claim.2) ∈
      branchClaims (branchKeys encode decode program branch)
        (branchAnswers encode decode program branch)) :
    claim ∈ mixedBranchClaims ctx blockCap encode decode program branch := by
  induction program generalizing claim with
  | done result => simp [branchClaims, branchKeys, branchAnswers] at member
  | read raw next ih =>
      cases branch with
      | mk answer rest =>
          simp only [branchClaims, branchKeys, branchAnswers, List.mem_cons] at member
          rcases claim with ⟨⟨key, active⟩, output⟩
          rcases member with head | tail
          · rcases Prod.mk.inj head with ⟨keyEq, outputEq⟩
            have live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw) := keyEq ▸ active
            have claimEq : (⟨⟨key, active⟩, output⟩ :
                ActiveKey ctx.role blockCap ctx.keyBytes × VectorOutput Counter) =
                (⟨⟨encode raw, live⟩, answer⟩ :
                  ActiveKey ctx.role blockCap ctx.keyBytes × VectorOutput Counter) := by
              apply Prod.ext
              · apply Subtype.ext
                exact keyEq
              · exact outputEq
            simp only [mixedBranchClaims, dif_pos live, List.mem_cons]
            exact Or.inl claimEq
          · have tailMem := ih (decode raw answer) rest
              (⟨⟨key, active⟩, output⟩) tail
            simp only [mixedBranchClaims]
            by_cases live : RoleActive ctx.role blockCap ctx.keyBytes (encode raw)
            · simp only [dif_pos live, List.mem_cons]
              exact Or.inr tailMem
            · simpa only [dif_neg live] using tailMem

/-- Transport a selected stage event-or-missing result through the actual
retained history fiber.  All concrete Key, context, bundle, fixed-table, and
basis equalities are arguments; the helper performs the dependent casts once
over abstract key types, then applies the claim-list inclusion supplied by the
caller. -/
private theorem retained_history_event_or_missing_transport
    {BaseWork KeyLeft KeyRight : Type}
    [Fintype BaseWork] [DecidableEq BaseWork]
    [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
    [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
    (keyEq : KeyLeft = KeyRight)
    (ctxLeft : Context (Key := KeyLeft) (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (ctxRight : Context (Key := KeyRight) (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (ctxEq : cast (congrArg (fun key => Context (Key := key)
      (Counter := SmzaRp05GroupedSuffix.GroupCounter) (BaseWork := BaseWork)) keyEq)
      ctxLeft = ctxRight)
    (blockCap : Role → Nat)
    (fixed : FixedTable ctxLeft blockCap)
    (dummy : ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
    (basis : Basis (ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctxLeft))
    (fiber : HistoryRetainedRoleFiberBundle (BaseWork := BaseWork) KeyRight blockCap)
    (fiberEq : fiber = cast (congrArg
      (fun key => HistoryRetainedRoleFiberBundle (BaseWork := BaseWork) key blockCap)
      keyEq) ⟨ctxLeft, (fixed, (dummy, basis))⟩)
    (fixedRight : FixedTable ctxRight blockCap)
    (basisRight : Basis (ActiveKey ctxRight.role blockCap ctxRight.keyBytes)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctxRight))
    :
    let fiberContextEq : fiber.1 = ctxRight := by
      calc
        fiber.1 = (cast (congrArg
            (fun key => HistoryRetainedRoleFiberBundle (BaseWork := BaseWork) key blockCap)
            keyEq) ⟨ctxLeft, (fixed, (dummy, basis))⟩).1 := congrArg Sigma.fst fiberEq
        _ = cast (congrArg (fun key => Context (Key := key)
            (Counter := SmzaRp05GroupedSuffix.GroupCounter) (BaseWork := BaseWork))
            keyEq) ctxLeft := retained_bundle_context_cast keyEq blockCap
              ⟨ctxLeft, (fixed, (dummy, basis))⟩
        _ = ctxRight := ctxEq
    ∀ (_fixedRightEq : fixedRight = cast
        (congrArg (fun ctx => FixedTable ctx blockCap) fiberContextEq) fiber.2.1)
    (_basisRightEq : basisRight = cast
      (congrArg (fun ctx => Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
        (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
        (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctx)) fiberContextEq)
      fiber.2.2.2)
    (cap : Nat)
    (sourceClaims : List (ActiveKey ctxRight.role blockCap ctxRight.keyBytes ×
      VectorOutput SmzaRp05GroupedSuffix.GroupCounter))
    (targetClaims : List (ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes ×
      VectorOutput SmzaRp05GroupedSuffix.GroupCounter))
    (_claimsSubset : ∀ activeKeyTypeEq :
      ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes =
        ActiveKey ctxRight.role blockCap ctxRight.keyBytes,
      ∀ claim, claim ∈ sourceClaims →
        (cast activeKeyTypeEq.symm claim.1, claim.2) ∈ targetClaims)
    (_sourceOutcome :
      event (currentAdviceEventSpec ctxRight blockCap fixedRight cap)
        (activeMemoryEquiv ctxRight basisRight.workspace) basisRight.database ∨
      ¬ ClaimsDatabaseEvent sourceClaims basisRight.database),
    event (currentAdviceEventSpec ctxLeft blockCap fixed cap)
      (activeMemoryEquiv ctxLeft basis.workspace) basis.database ∨
    ¬ ClaimsDatabaseEvent targetClaims basis.database := by
  intro fiberContextEq fixedRightEq basisRightEq cap sourceClaims targetClaims
    claimsSubset sourceOutcome
  let fixedTypeEq := context_cast_type_eq keyEq ctxLeft ctxRight ctxEq
    (fun {Key} ctx => FixedTable ctx blockCap)
  let memoryTypeEq := context_cast_type_eq keyEq ctxLeft ctxRight ctxEq
    (fun {Key} ctx => ActiveMemory ctx)
  let activeKeyTypeEq := context_cast_type_eq keyEq ctxLeft ctxRight ctxEq
    (fun {Key} ctx => ActiveKey ctx.role blockCap ctx.keyBytes)
  let databaseTypeEq := congrArg (fun key => Database key
    (SmzaRp05CurrentAdaptiveExecution.Output
      (Counter := SmzaRp05GroupedSuffix.GroupCounter))) activeKeyTypeEq
  let basisTypeEq := context_cast_type_eq keyEq ctxLeft ctxRight ctxEq
    (fun {Key} ctx => Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter) (ActiveMemory ctx))
  have fixedNorm := retained_fiber_fixed_cast keyEq ctxLeft ctxRight ctxEq
    blockCap fixed dummy basis fiber fiberEq fiberContextEq fixedRight fixedRightEq
    fixedTypeEq
  have basisNorm := retained_fiber_basis_cast keyEq ctxLeft ctxRight ctxEq
    blockCap fixed dummy basis fiber fiberEq fiberContextEq basisRight basisRightEq
    basisTypeEq
  have basisComponents := cast_context_basis_components ctxLeft ctxRight keyEq
    ctxEq blockCap basisTypeEq memoryTypeEq databaseTypeEq basis
  have memoryEq : basisRight.workspace = cast memoryTypeEq basis.workspace := by
    rw [basisNorm]
    exact basisComponents.1
  have databaseEq : basisRight.database = cast databaseTypeEq basis.database := by
    rw [basisNorm]
    exact basisComponents.2
  have eventBridge := current_advice_event_iff_of_canonical_transport
    ctxLeft ctxRight keyEq ctxEq blockCap fixed fixedRight fixedTypeEq fixedNorm
    cap basis.workspace basisRight.workspace memoryTypeEq memoryEq
    basis.database basisRight.database databaseTypeEq databaseEq
  exact event_or_missing_of_exact_transports eventBridge sourceClaims targetClaims
    (fun key => cast activeKeyTypeEq.symm key) (claimsSubset activeKeyTypeEq)
    basisRight.database basis.database
    (by
      intro key
      calc
        basisRight.database key = (cast databaseTypeEq basis.database) key :=
          congrFun databaseEq key
        _ = basis.database (cast activeKeyTypeEq.symm key) :=
          cast_database_apply activeKeyTypeEq basis.database key)
    sourceOutcome

/-- A selected failure coefficient on the original history role transfers to
the current-advice event or missing recognized claims on that same history
database.  The retained stage is only an internal witness: its branch,
database keys, and role context are all transported through the checked
history readback. -/
private def current_history_failure_event_or_missing_goal
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (stages : List HistoryStage) (commonNs : SmzaRp05LeafNamespace.Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (certificates : GeneratedCertificates currentDsl) : Prop :=
    let historyProg : Program Unit := historyProgram stages
    let model : RelationModel :=
      SmzaRp05RelationRefinement.relationModel currentDsl certificates
    ∀ (bounded : ModelWithinProtocol model)
      (fallback : V8SmzaOracleParser.RawDigest)
      (blockCap : Role → Nat)
      (_positiveDecsMatrixCap : 0 < blockCap .decsMatrix)
      (_positivePiopMatrixCap : 0 < blockCap .piopMatrix)
      (_positivePiopOpeningCap : 0 < blockCap .piopOpening)
      (historyBranch : Branches groupedDecode historyProg)
      (role : Role),
    let historyCtx := historyContext (BaseWork := BaseWork) stages model bounded commonNs role
    ∀ (fixed : FixedTable historyCtx blockCap)
      (dummy : ActiveKey historyCtx.role blockCap historyCtx.keyBytes)
      (initial : CmsState (Key := Key historyProg)
        (Counter := SmzaRp05GroupedSuffix.GroupCounter) (BaseWork := BaseWork))
      (basis : Basis
        (ActiveKey historyCtx.role blockCap historyCtx.keyBytes)
        (V8Smz9CoherentVectorMerkle.VectorOutput
          SmzaRp05GroupedSuffix.GroupCounter)
        (V8Smz9CoherentVectorMerkle.VectorOutput
          SmzaRp05GroupedSuffix.GroupCounter)
        (ActiveMemory historyCtx))
      (cap : Nat)
      (_support : selectedRoleState
        historyCtx
        blockCap (encode historyProg) groupedDecode historyProg
        historyBranch fixed
        (fixedFiberToActive
          historyCtx
          blockCap dummy fixed
          (otherRoleTransform
            historyCtx
            blockCap initial))
        (fun view (_work : Work (Counter := SmzaRp05GroupedSuffix.GroupCounter)
          (BaseWork := BaseWork)) =>
          currentHistoryFailureRoleSelector (BaseWork := BaseWork)
          stages commonNs stageNsEq model
          bounded (emptyHistoryAdvice model)
          fallback 28 historyBranch role view) basis ≠ 0),
    event (currentAdviceEventSpec historyCtx
      blockCap fixed cap)
      (activeMemoryEquiv historyCtx basis.workspace)
      basis.database ∨
    ¬ ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims historyCtx
        blockCap (encode historyProg) groupedDecode
        historyProg historyBranch) basis.database

set_option maxRecDepth 18000 in
theorem history_failure_role_support_implies_current_advice_event_or_missing_claims
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (stages : List HistoryStage) (commonNs : SmzaRp05LeafNamespace.Namespace)
    (stageNsEq : ∀ i : Fin stages.length, (stages[i.val]).ns = commonNs)
    (certificates : GeneratedCertificates currentDsl) :
    current_history_failure_event_or_missing_goal (BaseWork := BaseWork)
      stages commonNs stageNsEq certificates := by
  unfold current_history_failure_event_or_missing_goal
  intro historyProg model bounded fallback blockCap positiveDecsMatrixCap positivePiopMatrixCap
    positivePiopOpeningCap historyBranch role historyCtx fixed dummy initial basis cap support
  classical
  rcases history_failure_role_selected_support_transfers_to_retained_stage
      (BaseWork := BaseWork) stages commonNs stageNsEq model bounded
      (emptyHistoryAdvice model) fallback 28 blockCap historyBranch role
      dummy fixed initial basis support with
      ⟨i, readback, keyFiber, fixedStage, dummyStage, initialStage, basisStage,
      keyFiberEq, fixedStageEq, _, _, basisStageEq,
      stageSupport⟩
  subst keyFiber
  let stageCtx := historyStageContext (BaseWork := BaseWork) stages i model bounded
    (emptyHistoryAdvice model) role
  let stageProgram := actualProgram (historyStageProducer stages i)
    (stages[i.val]).ns (stages[i.val]).statement (stages[i.val]).pending
    (stages[i.val]).nonce
  let stageBranch := castProgramBranch groupedDecode
    (terminalHistoryStageObserver stages i) stageProgram
    (historyStageProgramEq stages i).symm readback.observerBranch
  have stageResult :
      event (currentAdviceEventSpec stageCtx blockCap fixedStage cap)
        (activeMemoryEquiv stageCtx basisStage.workspace) basisStage.database ∨
      ¬ ClaimsDatabaseEvent
        (recognizedActiveChallengeClaims stageCtx blockCap
          (encode stageProgram) groupedDecode stageProgram stageBranch)
        basisStage.database :=
    grouped_four_role_failure_support_implies_current_advice_event_or_missing_claims
      (BaseWork := BaseWork) (historyStageProducer stages i) (stages[i.val]).ns
      (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce
      fallback certificates bounded blockCap positiveDecsMatrixCap
      positivePiopMatrixCap positivePiopOpeningCap role stageBranch fixedStage dummyStage
      initialStage basisStage cap stageSupport
  -- These are the canonical Key/context transports supplied by the retained
  -- readback.  Keep the computed equalities opaque in this concrete callback;
  -- the private generic transport lemmas above handle their casts.
  let keyEq := (history_stage_target_key_eq_history stages i).symm
  let ctxKeyEq := SmzaRp05CurrentHistorySelectedRoleStateReplay.history_stage_role_context_cast_eq
    (BaseWork := BaseWork) stages i commonNs (stageNsEq i) model bounded role
    (emptyHistoryAdvice model)
  let sourceClaims := recognizedActiveChallengeClaims stageCtx blockCap
    (encode stageProgram) groupedDecode stageProgram stageBranch
  let targetClaims := recognizedActiveChallengeClaims historyCtx blockCap
    (encode historyProg) groupedDecode historyProg historyBranch
  have claimsSubset : ∀ activeKeyTypeEq :
      ActiveKey historyCtx.role blockCap historyCtx.keyBytes =
        ActiveKey stageCtx.role blockCap stageCtx.keyBytes,
      ∀ claim, claim ∈ sourceClaims →
        (cast activeKeyTypeEq.symm claim.1, claim.2) ∈ targetClaims := by
    intro activeKeyTypeEq claim member
    rcases List.mem_filter.mp member with ⟨mixedMember, recognized⟩
    have rawMember := mixed_active_claim_mem_branch_claims
      stageCtx blockCap (encode stageProgram) groupedDecode stageProgram stageBranch
      claim mixedMember
    let observer := terminalHistoryStageObserver stages i
    have programEq : observer = stageProgram :=
      (historyStageProgramEq stages i).symm
    have groupsEq : groups observer = groups stageProgram := congrArg groups programEq
    let sameKey := key_type_eq_of_groups_eq observer stageProgram groupsEq
    have encodeEq : ∀ raw, encode stageProgram raw = cast sameKey (encode observer raw) := by
      intro raw
      exact (encode_cast_key_type_eq_of_groups_eq observer stageProgram groupsEq raw).symm
    have claimsEq := branchClaims_cast_program groupedDecode observer stageProgram
      programEq sameKey (encode observer) (encode stageProgram) encodeEq
      readback.observerBranch
    dsimp only [stageBranch] at rawMember
    have rawMemberEq := congrArg
      (fun claims => (claim.1.val, claim.2) ∈ claims) claimsEq
    have rawMember := Eq.mp rawMemberEq rawMember
    rcases List.mem_map.mp rawMember with ⟨observerClaim, observerMember, claimEq⟩
    have stageKeyEq : claim.1.val = cast sameKey observerClaim.1 :=
      (Prod.mk.inj claimEq).1.symm
    have outputEq : claim.2 = observerClaim.2 := (Prod.mk.inj claimEq).2.symm
    have observerMappedMember :
        (historyObserverKeyEquiv stages i observerClaim.1, observerClaim.2) ∈
          List.map
            (fun claim => (historyObserverKeyEquiv stages i claim.1, claim.2))
            (branchClaims (branchKeys (encode observer) groupedDecode observer
              readback.observerBranch)
              (branchAnswers (encode observer) groupedDecode observer
                readback.observerBranch)) := by
      exact List.mem_map.mpr ⟨observerClaim, observerMember, rfl⟩
    have historyObserverMember := terminal_observer_claims_subset_history
      stages i historyBranch readback.observerBranch readback.answerLogSubset
      observerMappedMember
    let historyKey := cast activeKeyTypeEq.symm claim.1
    have mappedValueEq : historyKey.val =
        historyObserverKeyEquiv stages i observerClaim.1 := by
      rw [active_key_cast_value historyCtx stageCtx keyEq ctxKeyEq blockCap
        activeKeyTypeEq claim.1]
      rw [stageKeyEq]
      have stageHistoryGroupsEq : groups stageProgram = groups historyProg :=
        (congrArg groups (historyStageProgramEq stages i)).trans
          (terminalHistoryStageObserver_groups_eq stages i)
      have stageHistoryKeyEq : keyEq.symm =
          key_type_eq_of_groups_eq stageProgram historyProg stageHistoryGroupsEq :=
        Subsingleton.elim _ _
      have castEq : cast keyEq.symm (cast sameKey observerClaim.1) =
          historyObserverKeyEquiv stages i observerClaim.1 := by
        apply Subtype.ext
        change included historyProg
            (cast keyEq.symm (cast sameKey observerClaim.1)) =
          included historyProg (historyObserverKeyEquiv stages i observerClaim.1)
        rw [stageHistoryKeyEq]
        calc
          included historyProg
              (cast (key_type_eq_of_groups_eq stageProgram historyProg stageHistoryGroupsEq)
                (cast sameKey observerClaim.1)) =
              included stageProgram (cast sameKey observerClaim.1) :=
            included_cast_key_type_eq_of_groups_eq stageProgram historyProg
              stageHistoryGroupsEq _
          _ = included observer observerClaim.1 :=
            included_cast_key_type_eq_of_groups_eq observer stageProgram groupsEq
              observerClaim.1
          _ = included historyProg (historyObserverKeyEquiv stages i observerClaim.1) := by
            rfl
      exact castEq
    have targetBranchMember : (historyKey.val, claim.2) ∈
        branchClaims (branchKeys (encode historyProg) groupedDecode
          historyProg historyBranch)
          (branchAnswers (encode historyProg) groupedDecode
            historyProg historyBranch) := by
      rw [mappedValueEq, outputEq]
      exact historyObserverMember
    have targetMixedMember := active_branch_claim_mem_mixed_branch_claims
      historyCtx blockCap (encode historyProg) groupedDecode
      historyProg historyBranch (historyKey, claim.2) targetBranchMember
    have historyRecognized := recognized_query_cast_context historyCtx stageCtx
      keyEq ctxKeyEq blockCap activeKeyTypeEq claim.1 (of_decide_eq_true recognized)
    exact List.mem_filter.mpr ⟨targetMixedMember, decide_eq_true historyRecognized⟩
  exact retained_history_event_or_missing_transport
    (BaseWork := BaseWork) (KeyLeft := Key historyProg) (KeyRight := Key stageProgram)
    (keyEq := keyEq) (ctxLeft := historyCtx) (ctxRight := stageCtx) (ctxEq := ctxKeyEq)
    blockCap fixed dummy basis
    (cast (congrArg
      (fun key => HistoryRetainedRoleFiberBundle (BaseWork := BaseWork) key blockCap)
      keyEq) ⟨historyCtx, (fixed, (dummy, basis))⟩) rfl
    fixedStage basisStage fixedStageEq
    basisStageEq cap sourceClaims targetClaims claimsSubset stageResult

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryFailureEventScalarBridge
