import SmzaRp05CurrentSelectedStageList
import SmzaRp05CurrentHistoryFailureCoverage
import SmzaRp05CurrentHistoryFailureMass
import SmzaRp05CurrentHistorySelectorContexts
import SmzaRp05CurrentAcceptedOrdinaryMassBound
import SmzaRp05ExecutableProgramEquality
import SmzaRp05CurrentSourceLedgerRunner
import SmzaRp05CurrentPublicHistoryAdmission

/-! # Canonical selected stages from one accepted verifier history

Every selected stage below is recovered from the original accepted history
branch.  Its verifier branch is the terminal observer branch transported to
the actual stage program, and its X-view is the original history database's
nonchallenge view.  No caller supplies a stage branch, view, or witness.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentHistorySelectedStageExtraction

open scoped Classical
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaChallengeStageTargets (Role)
open SmzaRp05CurrentAdaptiveExecution (Context Work)
open SmzaRp05ConditionedExecution (XKey xView)
open SmzaRp05CurrentHistoryVerifierProgram
  (HistoryStage historyProgram terminalHistoryStageObserver)
open SmzaRp05CurrentHistoryFailureCoverage
  (AcceptedHistoryStageReadback accepted_history_stage_readback
    historyStageProgramEq historyStageContext historyStageView
    currentHistoryFailureWitness)
open SmzaRp05CurrentHistorySelectorContexts (historyStageProducer)
open SmzaRp05CurrentHistoryFailureMass
  (emptyHistoryAdvice historyContext historyFailureEvent)
open SmzaRp05CurrentSelectedStageList
  (CurrentSelectedStage CurrentSelectedStage.envelope_eq_none_iff)
open SmzaRp05CurrentAcceptedOrdinaryMassBound (actualProgram)
open SmzaRp05CurrentFiniteGroupedProgram (Key)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05GroupedSuffix (GroupCounter)
open SmzaRp05CurrentSelectedChallengeClaims (nonchallengeRawKeySet)
open SmzaRp05CurrentPublicStatementTransport (parseCurrentPublicStatement?)
open SmzaRp05TracePrefixes (RelationModel)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05LeafNamespace (Namespace)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
  (V8NoteOpening V8PublicStatement)
open V8SmzaOracleParser (RawDigest)
open SmzaRp05ExecutableProgramEquality (castProgramBranch)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
  (initialCurrentSourceLedgerPrefix)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRunner
  (CurrentSelectedBlock CurrentSelectedHistoryOutcome
    executeSelectedCurrentHistoryFromGenesis)
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicHistoryAdmission
  (CurrentPublicBlock selectedBlockPublicView)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 18000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/-- Choose the checked retained-prefix readback derived from this accepted
history branch.  The choice contains no independent execution or caller data. -/
def canonicalAcceptedHistoryStageReadback
    (stages : List HistoryStage) (i : Fin stages.length)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (historyAccepted : branchResult groupedDecode (historyProgram stages)
      historyBranch = some ()) : AcceptedHistoryStageReadback stages i historyBranch :=
  Classical.choice (accepted_history_stage_readback stages i historyBranch historyAccepted)

/-- The unique public selected-stage carrier for index `i` on the accepted
history execution, evaluated against that same history's nonchallenge view. -/
def canonicalCurrentSelectedStage
    (stages : List HistoryStage) (i : Fin stages.length)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (historyAccepted : branchResult groupedDecode (historyProgram stages)
      historyBranch = some ())
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter)) :
    CurrentSelectedStage (BaseWork := BaseWork) := by
  let readback := canonicalAcceptedHistoryStageReadback stages i historyBranch historyAccepted
  let advice := emptyHistoryAdvice model
  let historyView := xView (nonchallengeRawKeySet
    (historyContext (BaseWork := BaseWork) stages model bounded commonNs .decsMatrix)) database
  exact {
    producer := historyStageProducer stages i
    ns := (stages[i.val]).ns
    statement := (stages[i.val]).statement
    pending := (stages[i.val]).pending
    nonce := (stages[i.val]).nonce
    fallback := fallback
    typed := typed i
    parsed := parsed i
    fuel := 28
    ctx := historyStageContext (BaseWork := BaseWork) stages i model bounded advice .decsMatrix
    branch := castProgramBranch groupedDecode (terminalHistoryStageObserver stages i)
      (actualProgram (historyStageProducer stages i) (stages[i.val]).ns
        (stages[i.val]).statement (stages[i.val]).pending (stages[i.val]).nonce)
      (historyStageProgramEq stages i).symm readback.observerBranch
    view := historyStageView (BaseWork := BaseWork) stages i commonNs (stageNsEq i)
      model bounded advice .decsMatrix historyView
  }

/-- Any missing envelope in the canonical stage list is a full-extraction
failure on the original accepted history and its original database. -/
theorem canonicalCurrentSelectedStage_envelope_none_implies_historyFailureEvent
    (stages : List HistoryStage) (i : Fin stages.length)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (historyAccepted : branchResult groupedDecode (historyProgram stages)
      historyBranch = some ())
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter))
    (missing : (canonicalCurrentSelectedStage (BaseWork := BaseWork)
      stages i commonNs stageNsEq typed parsed model bounded fallback historyBranch
      historyAccepted database).envelope = none) :
    historyFailureEvent (BaseWork := BaseWork) stages commonNs stageNsEq fallback
      typed 28 model bounded historyBranch database := by
  let selected := canonicalCurrentSelectedStage (BaseWork := BaseWork)
    stages i commonNs stageNsEq typed parsed model bounded fallback historyBranch
    historyAccepted database
  have noFull := (CurrentSelectedStage.envelope_eq_none_iff selected).mp missing
  change currentHistoryFailureWitness (BaseWork := BaseWork)
    stages commonNs stageNsEq model bounded (emptyHistoryAdvice model) fallback typed 28
    historyBranch
    (xView (nonchallengeRawKeySet
      (historyContext (BaseWork := BaseWork) stages model bounded commonNs .decsMatrix))
      database)
  refine ⟨historyAccepted, i,
    canonicalAcceptedHistoryStageReadback stages i historyBranch historyAccepted, ?_⟩
  exact noFull

/-- Finite, ordered list adapter for actual multi-block consumers. -/
def canonicalCurrentSelectedStages
    (stages : List HistoryStage)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (historyAccepted : branchResult groupedDecode (historyProgram stages)
      historyBranch = some ())
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter)) :
    List (CurrentSelectedStage (BaseWork := BaseWork)) :=
  List.ofFn fun i : Fin stages.length =>
    canonicalCurrentSelectedStage (BaseWork := BaseWork)
      stages i commonNs stageNsEq typed parsed model bounded fallback historyBranch
      historyAccepted database

@[simp] theorem canonicalCurrentSelectedStages_length
    (stages : List HistoryStage)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (historyAccepted : branchResult groupedDecode (historyProgram stages)
      historyBranch = some ())
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter)) :
    (canonicalCurrentSelectedStages (BaseWork := BaseWork) stages commonNs stageNsEq
      typed parsed model bounded fallback historyBranch historyAccepted database).length =
      stages.length := by
  simp [canonicalCurrentSelectedStages]

/-! ## Canonical block packaging and runner connection

The block boundary and optional coinbase are ordinary block-input data. The
transaction-count field only partitions the one canonical, ordered stage list
into consecutive slices; it does not carry extracted runs, selector witnesses,
or per-stage views.
-/

/-- Public per-block input needed to package a verifier history for native
replay. `transactionCount` assigns the next contiguous slice of history stages
to this block; coinbase data is passed through unchanged for source validation. -/
structure CurrentHistoryBlockLayout where
  transactionCount : Nat
  coinbase : Option (Nat × V8NoteOpening)

/-- Total number of verifier transactions assigned by a block layout. -/
def currentHistoryBlockLayoutStageCount
    (layout : List CurrentHistoryBlockLayout) : Nat :=
  (layout.map CurrentHistoryBlockLayout.transactionCount).sum

/-- Partition canonical stages in source order and attach each block's own
coinbase. A short layout leaves only the suffix unassigned; callers that need
an exact history must use `canonicalCurrentSelectedHistoryBlocks_stage_order`
with the total-count equality. -/
def packCanonicalCurrentSelectedBlocks :
    List CurrentHistoryBlockLayout →
      List (CurrentSelectedStage (BaseWork := BaseWork)) →
        List (CurrentSelectedBlock (BaseWork := BaseWork))
  | [], _ => []
  | block :: tail, stages =>
      { stages := stages.take block.transactionCount
        coinbase := block.coinbase } ::
        packCanonicalCurrentSelectedBlocks tail
          (stages.drop block.transactionCount)

/-- Public packing of already-parsed transaction statements. This function
depends only on public typed transactions, their block-count partition, and
the unchanged public coinbase entries; it has no selector, run, or ledger
input. -/
def packCanonicalCurrentPublicBlocks :
    List CurrentHistoryBlockLayout → List V8PublicStatement →
      List CurrentPublicBlock
  | [], _ => []
  | block :: tail, transactions =>
      { transactions := transactions.take block.transactionCount
        coinbase := block.coinbase } ::
        packCanonicalCurrentPublicBlocks tail
          (transactions.drop block.transactionCount)

/-- Under the exact layout-length condition, the blocks contain every stage
exactly once and preserve chronological order. -/
theorem packCanonicalCurrentSelectedBlocks_stage_order
    (layout : List CurrentHistoryBlockLayout)
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork)))
    (complete : currentHistoryBlockLayoutStageCount layout = stages.length) :
    (packCanonicalCurrentSelectedBlocks (BaseWork := BaseWork) layout stages).flatMap
      CurrentSelectedBlock.stages = stages := by
  induction layout generalizing stages with
  | nil =>
      cases stages with
      | nil => rfl
      | cons head tail => simp [currentHistoryBlockLayoutStageCount] at complete
  | cons block rest ih =>
      simp only [currentHistoryBlockLayoutStageCount, List.map_cons,
        List.sum_cons] at complete
      change block.transactionCount + currentHistoryBlockLayoutStageCount rest =
        stages.length at complete
      have restComplete : currentHistoryBlockLayoutStageCount rest =
          (stages.drop block.transactionCount).length := by
        rw [List.length_drop]
        calc
          currentHistoryBlockLayoutStageCount rest =
              block.transactionCount + currentHistoryBlockLayoutStageCount rest -
                block.transactionCount := by
            simp only [Nat.add_sub_cancel_left]
          _ = stages.length - block.transactionCount := by rw [complete]
      simp only [packCanonicalCurrentSelectedBlocks, List.flatMap_cons]
      rw [ih (stages.drop block.transactionCount) restComplete]
      exact List.take_append_drop _ _

/-- Packaging retains one block per layout entry and copies each supplied
coinbase to its corresponding block without deriving or altering it. -/
theorem packCanonicalCurrentSelectedBlocks_coinbases
    (layout : List CurrentHistoryBlockLayout)
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork))) :
    (packCanonicalCurrentSelectedBlocks (BaseWork := BaseWork) layout stages).map
      CurrentSelectedBlock.coinbase =
      layout.map CurrentHistoryBlockLayout.coinbase := by
  induction layout generalizing stages with
  | nil => rfl
  | cons block rest ih =>
      simp only [packCanonicalCurrentSelectedBlocks, List.map_cons]
      rw [ih (stages.drop block.transactionCount)]

/-- Projecting selected blocks to public native blocks is exactly the public
count-based packing of their typed transaction list. Block boundaries and
coinbases are preserved without selector-derived public data. -/
theorem packCanonicalCurrentSelectedBlocks_publicView
    (layout : List CurrentHistoryBlockLayout)
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork))) :
    (packCanonicalCurrentSelectedBlocks (BaseWork := BaseWork) layout stages).map
      selectedBlockPublicView =
      packCanonicalCurrentPublicBlocks layout
        (stages.map CurrentSelectedStage.typed) := by
  induction layout generalizing stages with
  | nil => rfl
  | cons block rest ih =>
      simp [packCanonicalCurrentSelectedBlocks, packCanonicalCurrentPublicBlocks,
        selectedBlockPublicView, List.map_take, List.map_drop, ih]

/-- Build the actual runner input from block layout plus the canonical stages
recovered from one original accepted history execution. No caller supplies a
`CurrentSelectedStage`, extracted envelope, stage branch, or X-view. -/
private def canonicalAcceptedCurrentSelectedHistoryBlocks
    (stages : List HistoryStage)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (historyAccepted : branchResult groupedDecode (historyProgram stages)
      historyBranch = some ())
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter))
    (layout : List CurrentHistoryBlockLayout) :
    List (CurrentSelectedBlock (BaseWork := BaseWork)) :=
  packCanonicalCurrentSelectedBlocks (BaseWork := BaseWork) layout
    (canonicalCurrentSelectedStages (BaseWork := BaseWork) stages commonNs stageNsEq
      typed parsed model bounded fallback historyBranch historyAccepted database)

/-- The packaged blocks flatten to exactly the canonical stage list when the
transaction-count layout covers the original history. -/
private theorem canonicalAcceptedCurrentSelectedHistoryBlocks_stage_order
    (stages : List HistoryStage)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (historyAccepted : branchResult groupedDecode (historyProgram stages)
      historyBranch = some ())
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter))
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length) :
    (canonicalAcceptedCurrentSelectedHistoryBlocks (BaseWork := BaseWork)
      stages commonNs stageNsEq typed parsed model bounded fallback historyBranch
      historyAccepted database layout).flatMap CurrentSelectedBlock.stages =
      canonicalCurrentSelectedStages (BaseWork := BaseWork) stages commonNs stageNsEq
        typed parsed model bounded fallback historyBranch historyAccepted database := by
  exact packCanonicalCurrentSelectedBlocks_stage_order (BaseWork := BaseWork)
    layout _ (by
      rw [canonicalCurrentSelectedStages_length]
      exact layoutCoversHistory)

/-- Execute the block layout through the source runner. The returned value is
the runner's actual complete-or-first-failure outcome, indexed by the blocks
constructed from the same accepted history branch and database. The layout
equality prevents silently omitting or appending verifier stages. -/
private noncomputable def executeAcceptedCurrentHistoryFromGenesis
    (stages : List HistoryStage)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (historyBranch : Branches groupedDecode (historyProgram stages))
    (historyAccepted : branchResult groupedDecode (historyProgram stages)
      historyBranch = some ())
    (database : Database (Key (historyProgram stages)) (VectorOutput GroupCounter))
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length) :
    CurrentSelectedHistoryOutcome
      (canonicalAcceptedCurrentSelectedHistoryBlocks (BaseWork := BaseWork)
        stages commonNs stageNsEq typed parsed model bounded fallback historyBranch
        historyAccepted database layout)
      initialCurrentSourceLedgerPrefix := by
  have _stageOrder := canonicalAcceptedCurrentSelectedHistoryBlocks_stage_order
    (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed model bounded
    fallback historyBranch historyAccepted database layout layoutCoversHistory
  exact executeSelectedCurrentHistoryFromGenesis
    (canonicalAcceptedCurrentSelectedHistoryBlocks (BaseWork := BaseWork)
      stages commonNs stageNsEq typed parsed model bounded fallback historyBranch
      historyAccepted database layout)

/-- Exact branch/basis carrier used by the original Born-outcome endpoint for
the complete verifier history. Its database is the measured `Basis.database`,
not an independently supplied stage view. -/
abbrev CurrentHistoryOriginalOutcome (stages : List HistoryStage) :=
  Branches groupedDecode (historyProgram stages) ×
    Basis (Key (historyProgram stages)) (VectorOutput GroupCounter)
      (VectorOutput GroupCounter)
      (Work (Counter := GroupCounter) (BaseWork := BaseWork))

/-- Accepted-branch-only packaging for a literal original branch/basis
outcome. Acceptance is tested from the branch inside this function. Rejected
branches return `none`; accepted branches build every stage from that same
branch and `outcome.2.database`. -/
noncomputable def canonicalCurrentSelectedHistoryBlocks?
    (stages : List HistoryStage)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages)
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length) :
    Option (List (CurrentSelectedBlock (BaseWork := BaseWork))) :=
  by
    let _layoutProof := layoutCoversHistory
    exact if accepted : branchResult groupedDecode (historyProgram stages) outcome.1 = some () then
      some (canonicalAcceptedCurrentSelectedHistoryBlocks (BaseWork := BaseWork)
        stages commonNs stageNsEq typed parsed model bounded fallback outcome.1
        accepted outcome.2.database layout)
    else none

/-- Rejected original branches cannot be assigned a canonical block list. -/
theorem canonicalCurrentSelectedHistoryBlocks?_rejected
    (stages : List HistoryStage)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages)
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length)
    (rejected : branchResult groupedDecode (historyProgram stages) outcome.1 ≠ some ()) :
    canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork) stages commonNs
      stageNsEq typed parsed model bounded fallback outcome layout layoutCoversHistory = none := by
  simp [canonicalCurrentSelectedHistoryBlocks?, rejected]

/-- On an accepted original history outcome, the optional canonical block
projection contains every stage exactly once, in history order. Rejected
outcomes are handled separately by the preceding theorem. -/
theorem canonicalCurrentSelectedHistoryBlocks?_accepted_stage_order
    (stages : List HistoryStage)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages)
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length)
    (accepted : branchResult groupedDecode (historyProgram stages) outcome.1 = some ()) :
    ((canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork) stages commonNs
      stageNsEq typed parsed model bounded fallback outcome layout
      layoutCoversHistory).getD []).flatMap CurrentSelectedBlock.stages =
      canonicalCurrentSelectedStages (BaseWork := BaseWork) stages commonNs stageNsEq
        typed parsed model bounded fallback outcome.1 accepted outcome.2.database := by
  classical
  simpa [canonicalCurrentSelectedHistoryBlocks?, accepted] using
    canonicalAcceptedCurrentSelectedHistoryBlocks_stage_order
      (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed model bounded
      fallback outcome.1 accepted outcome.2.database layout layoutCoversHistory

/-- If the same accepted original history has no global extraction failure,
then every stage in its flattened canonical blocks has a selected envelope.
This is derived per exact canonical stage; it does not take caller-selected
stage branches or views. -/
theorem canonicalCurrentSelectedHistoryBlocks?_envelopes_present_of_no_history_failure
    (stages : List HistoryStage)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages)
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length)
    (accepted : branchResult groupedDecode (historyProgram stages) outcome.1 = some ())
    (noHistoryFailure : ¬ historyFailureEvent (BaseWork := BaseWork) stages commonNs
      stageNsEq fallback typed 28 model bounded outcome.1 outcome.2.database) :
    ∀ stage ∈ ((canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
      stages commonNs stageNsEq typed parsed model bounded fallback outcome layout
      layoutCoversHistory).getD []).flatMap CurrentSelectedBlock.stages,
      stage.envelope ≠ none := by
  classical
  let canonicalStage := fun i : Fin stages.length =>
    canonicalCurrentSelectedStage (BaseWork := BaseWork) stages i commonNs stageNsEq
      typed parsed model bounded fallback outcome.1 accepted outcome.2.database
  let canonicalStages := canonicalCurrentSelectedStages (BaseWork := BaseWork)
    stages commonNs stageNsEq typed parsed model bounded fallback outcome.1 accepted
    outcome.2.database
  intro stage member missing
  rw [canonicalCurrentSelectedHistoryBlocks?_accepted_stage_order
    (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed model bounded
    fallback outcome layout layoutCoversHistory accepted] at member
  obtain ⟨index, found⟩ := List.mem_iff_getElem?.mp member
  have indexBoundCanonical : index < canonicalStages.length :=
    (List.getElem?_eq_some_iff.mp found).1
  have indexBound : index < stages.length := by
    simpa [canonicalStages] using indexBoundCanonical
  let i : Fin stages.length := ⟨index, indexBound⟩
  have memberGetD : canonicalStages.getD index (canonicalStage i) = stage := by
    rw [List.getD_eq_getElem?_getD, found]
    rfl
  have canonicalGetD : canonicalStages.getD index (canonicalStage i) = canonicalStage i := by
    change (List.ofFn canonicalStage).getD index (canonicalStage i) = canonicalStage i
    simp only [List.getD_eq_getElem?_getD, List.getElem?_ofFn,
      dif_pos indexBound, Option.getD_some]
    change canonicalStage i = canonicalStage i
    rfl
  have stageEq : canonicalStage i = stage := by
    calc
      canonicalStage i = canonicalStages.getD index (canonicalStage i) :=
        canonicalGetD.symm
      _ = stage := memberGetD
  have missingCanonical : (canonicalStage i).envelope = none := by
    rw [stageEq]
    exact missing
  apply noHistoryFailure
  exact canonicalCurrentSelectedStage_envelope_none_implies_historyFailureEvent
    (BaseWork := BaseWork) stages i commonNs stageNsEq typed parsed model bounded
    fallback outcome.1 accepted outcome.2.database missingCanonical

/-- Block-indexed form of the no-missing-stage fact, for consumers that keep
the native block partition rather than flattening it first. -/
theorem canonicalCurrentSelectedHistoryBlocks?_block_stages_envelopes_present_of_no_history_failure
    (stages : List HistoryStage)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages)
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length)
    (accepted : branchResult groupedDecode (historyProgram stages) outcome.1 = some ())
    (noHistoryFailure : ¬ historyFailureEvent (BaseWork := BaseWork) stages commonNs
      stageNsEq fallback typed 28 model bounded outcome.1 outcome.2.database) :
    ∀ block ∈ (canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork)
      stages commonNs stageNsEq typed parsed model bounded fallback outcome layout
      layoutCoversHistory).getD [],
      ∀ stage ∈ block.stages, stage.envelope ≠ none := by
  intro block blockMember stage stageMember missing
  exact canonicalCurrentSelectedHistoryBlocks?_envelopes_present_of_no_history_failure
    (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed model bounded fallback
    outcome layout layoutCoversHistory accepted noHistoryFailure stage
    (List.mem_flatMap.mpr ⟨block, blockMember, stageMember⟩) missing

/-- The runner blocks' public views are determined entirely by the public
typed statements, contiguous count partition, and unchanged coinbases. -/
theorem canonicalCurrentSelectedHistoryBlocks?_accepted_public_views
    (stages : List HistoryStage)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages)
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length)
    (accepted : branchResult groupedDecode (historyProgram stages) outcome.1 = some ()) :
    ((canonicalCurrentSelectedHistoryBlocks? (BaseWork := BaseWork) stages commonNs
      stageNsEq typed parsed model bounded fallback outcome layout
      layoutCoversHistory).getD []).map selectedBlockPublicView =
      packCanonicalCurrentPublicBlocks layout (List.ofFn typed) := by
  classical
  have canonicalTyped :
    (canonicalCurrentSelectedStages (BaseWork := BaseWork) stages commonNs
      stageNsEq typed parsed model bounded fallback outcome.1 accepted
        outcome.2.database).map CurrentSelectedStage.typed = List.ofFn typed := by
    simp [canonicalCurrentSelectedStages, canonicalCurrentSelectedStage]
    funext i
    rfl
  have blockViews :
      (canonicalAcceptedCurrentSelectedHistoryBlocks (BaseWork := BaseWork)
        stages commonNs stageNsEq typed parsed model bounded fallback outcome.1
        accepted outcome.2.database layout).map selectedBlockPublicView =
      packCanonicalCurrentPublicBlocks layout
        ((canonicalCurrentSelectedStages (BaseWork := BaseWork) stages commonNs
          stageNsEq typed parsed model bounded fallback outcome.1 accepted
          outcome.2.database).map CurrentSelectedStage.typed) := by
    simpa [canonicalAcceptedCurrentSelectedHistoryBlocks] using
      packCanonicalCurrentSelectedBlocks_publicView (BaseWork := BaseWork) layout
        (canonicalCurrentSelectedStages (BaseWork := BaseWork) stages commonNs
          stageNsEq typed parsed model bounded fallback outcome.1 accepted
          outcome.2.database)
  rw [canonicalTyped] at blockViews
  simpa [canonicalCurrentSelectedHistoryBlocks?, accepted] using blockViews

/-- Execute only the accepted branch/basis packaging, returning the source
runner's actual complete-or-first-failure outcome together with its generated
block list. The sigma keeps the outcome indexed by precisely those blocks;
native extraction, other native errors, source-input failures, and coinbase
checker failures remain distinct constructors and are not filtered here. -/
noncomputable def executeCanonicalCurrentHistoryFromGenesis?
    (stages : List HistoryStage)
    (commonNs : Namespace)
    (stageNsEq : ∀ j : Fin stages.length, (stages[j.val]).ns = commonNs)
    (typed : Fin stages.length → V8PublicStatement)
    (parsed : ∀ j : Fin stages.length,
      parseCurrentPublicStatement? (stages[j.val]).statement = some (typed j))
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (fallback : RawDigest)
    (outcome : CurrentHistoryOriginalOutcome (BaseWork := BaseWork) stages)
    (layout : List CurrentHistoryBlockLayout)
    (layoutCoversHistory : currentHistoryBlockLayoutStageCount layout = stages.length) :
    Option (Σ blocks : List (CurrentSelectedBlock (BaseWork := BaseWork)),
      CurrentSelectedHistoryOutcome (BaseWork := BaseWork) blocks
        initialCurrentSourceLedgerPrefix) := by
  classical
  if accepted : branchResult groupedDecode (historyProgram stages) outcome.1 = some () then
    let blocks := canonicalAcceptedCurrentSelectedHistoryBlocks (BaseWork := BaseWork)
      stages commonNs stageNsEq typed parsed model bounded fallback outcome.1
      accepted outcome.2.database layout
    have _stageOrder := canonicalAcceptedCurrentSelectedHistoryBlocks_stage_order
      (BaseWork := BaseWork) stages commonNs stageNsEq typed parsed model bounded
      fallback outcome.1 accepted outcome.2.database layout layoutCoversHistory
    exact some ⟨blocks,
      executeAcceptedCurrentHistoryFromGenesis (BaseWork := BaseWork)
        stages commonNs stageNsEq typed parsed model bounded fallback outcome.1
        accepted outcome.2.database layout layoutCoversHistory⟩
  else
    exact none

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentHistorySelectedStageExtraction
