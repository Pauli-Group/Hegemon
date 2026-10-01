import SmzaRp05CurrentSelectedStageList
import SmzaRp05CurrentSourceLedgerPrefix
import SmzaRp05CurrentSourceBlockReplay
import SmzaRp05CurrentSourceTransferConstructor
import SmzaRp05CurrentFiniteLedgerHistory
import SmzaRp05CurrentSourceCoinbaseLedger
import SmzaRp05CurrentSourceLedgerRecurrence
import SmzaRp05CurrentSourceLedgerRecurrenceCore
import SmzaRp05HistoryAdmissionDefinitions
import SmzaRp05CurrentSourceRegistryConservation
import SmzaRp05Components

/-! # Selector-fed current source ledger runner

The stage carrier below contains verifier inputs, never an extracted source
witness.  Its envelope is computed by the designated full-success selector;
the source-shaped native replay then resolves the resulting chronological
options and reports extraction/native failures before finite-ledger replay.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRunner

open HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedStageList
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceBlockReplay
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions
  (sourceOutputRecord)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceTransferConstructor
open HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteLedgerHistory
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceCoinbaseLedger
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrence
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore
open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedHistorySupplyEndpoint
  (DesignatedRun coinbaseOpeningCanonical coinbasePaid?)
open HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness (SupplyState)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceRegistryConservation
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
  (Digest V8NoteOpening V8PublicStatement encodePublicStatement nativeAssetId)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs (publicAnchor)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputs (outputOpenings)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative (inputSlotNative)
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport
  (rustV8SemanticPrimitives)
open HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness
  (designatedInputPacked)
open SmzaFiniteLedgerSupply
  (Action Ledger applyTransfer applyCoinbase Transfer burnEscrow badCollision transferCollision
    noteCollision potential allowance wealth nativeValue)
open Hegemon.Consensus (maxMonetarySupply nativeCoinbaseAmount)
open SmzaQ38Recovery (packedFromRows)
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate (noteCall)
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree (openingAt)
open HegemonCrypto.SmallWood.SmzaRp05CurrentOutputLedgerPositions
  (appendedOutputIds)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputHistory
  (blockOpeningStream)
open scoped Classical

set_option autoImplicit false

noncomputable section

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/-- The actual designated run's public output-opening stream. -/
def selectedRunOutputOpenings (envelope : CurrentRunEnvelope) :
    List V8NoteOpening :=
  outputOpenings (encodePublicStatement envelope.typedStatement)
    (designatedInputPacked envelope.run)

/-- The source ledger and selector name the exact same packed decoder rows. -/
private theorem selectedRunSourcePacked_eq (envelope : CurrentRunEnvelope) :
    sourcePacked envelope.run = designatedInputPacked envelope.run := by
  change packedFromRows envelope.run.source.data =
    packedFromRows envelope.run.source.data
  rfl

private theorem selectedRunOutputOpenings_eq_source (envelope : CurrentRunEnvelope) :
    selectedRunOutputOpenings envelope =
      outputOpenings (encodePublicStatement envelope.typedStatement)
        (sourcePacked envelope.run) := by
  change outputOpenings (encodePublicStatement envelope.typedStatement)
      (designatedInputPacked envelope.run) =
    outputOpenings (encodePublicStatement envelope.typedStatement)
      (sourcePacked envelope.run)
  rw [selectedRunSourcePacked_eq]

/-- Ordered output openings for the exact accepted runs, excluding the
trailing coinbase which is appended separately. -/
def selectedRunOpeningStream (runs : List CurrentRunEnvelope) :
    List V8NoteOpening := runs.flatMap selectedRunOutputOpenings

/-- A structural view of the exact designated decoder output in the current
run envelope. No packed witness is selected or supplied by this conversion. -/
def selectedDesignatedRun (envelope : CurrentRunEnvelope) : DesignatedRun :=
  { preamble := envelope.preamble
    typedStatement := envelope.typedStatement
    root := envelope.run.root
    fpp := envelope.run.fpp
    coefficients := envelope.run.coefficients
    source := envelope.run.source
    decoded := envelope.run.decoded
    parsed := envelope.run.parsed
    fullySatisfied := envelope.run.fullySatisfied }

def selectedDesignatedRuns (runs : List CurrentRunEnvelope) :
    List DesignatedRun := runs.map selectedDesignatedRun

/-- Coinbase checking reads only escrow and issued heights from SupplyState.
This projection uses the actual finite-ledger state at the start of the
block; its irrelevant circulating component is not an acceptance premise. -/
def currentSupplyCheckState (ledger : Ledger) : SupplyState :=
  { circulating := 0
    feeEscrow := ledger.feeEscrow
    issuedHeights := ledger.issuedHeights }

omit [Fintype BaseWork] [DecidableEq BaseWork] in
theorem selected_block_openings_decompose
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult ledgerPrefix.snapshot.parent
      ledgerPrefix.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase) :
    result.openingsAdded = selectedRunOpeningStream result.runs ++
      sourceCoinbaseOpenings coinbase := by
  rw [result.openingsAddedEq]
  have outputFnEq :
      (fun envelope : CurrentRunEnvelope =>
        outputOpenings (encodePublicStatement envelope.typedStatement)
          (sourcePacked envelope.run)) = selectedRunOutputOpenings := by
    funext envelope
    exact (selectedRunOutputOpenings_eq_source envelope).symm
  simp only [blockOpeningStream,
    HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputHistory.extractedOutputLog,
    outputRecords, outputRecord, sourceOutputRecord, blockCoinbaseOpening,
    List.flatMap_map]
  rw [outputFnEq]
  cases coinbase <;> rfl

/-- The next lemma will be used by the recursive finite-ledger replay: a
block-wide check decomposes into freshness for the first selected run and a
tail check against the nullifiers already appended by that run. -/
theorem checked_nullifiers_cons
    (spent : List Digest) (head : CurrentRunEnvelope)
    (tail : List CurrentRunEnvelope)
    (checked : nullifiersFresh spent (head :: tail) = true) :
    sourceNullifiersFresh spent head.run = true ∧
      nullifiersFresh (spent ++ sourceRunNullifiers head.run) tail = true := by
  classical
  let headValues := sourceRunNullifiers head.run
  let tailValues := blockNullifiers tail
  have appendEq : blockNullifiers (head :: tail) = headValues ++ tailValues := by
    simp [blockNullifiers, headValues, tailValues, sourceRunNullifiers]
  have checksBool : decide (headValues ++ tailValues).Nodup = true ∧
      (headValues ++ tailValues).all (fun value => !(spent.contains value)) = true := by
    simpa only [nullifiersFresh, appendEq, Bool.and_eq_true] using checked
  have checks : (headValues ++ tailValues).Nodup ∧
      (headValues ++ tailValues).all (fun value => !(spent.contains value)) = true := by
    exact ⟨of_decide_eq_true checksBool.1, checksBool.2⟩
  rcases checks with ⟨wholeNodup, wholeFresh⟩
  have nodupParts := List.nodup_append.mp wholeNodup
  have freshParts :
      headValues.all (fun value => !(spent.contains value)) = true ∧
      tailValues.all (fun value => !(spent.contains value)) = true := by
    simpa only [List.all_append, Bool.and_eq_true] using wholeFresh
  have headCheck : sourceNullifiersFresh spent head.run = true := by
    unfold sourceNullifiersFresh
    change (decide headValues.Nodup &&
      headValues.all (fun value => spent.contains value = false)) = true
    have allFalse : headValues.all
        (fun value => spent.contains value = false) = true := by
      simpa using freshParts.1
    simp only [Bool.and_eq_true_iff]
    exact ⟨
      by simpa only [decide_eq_true_eq] using nodupParts.1,
      allFalse⟩
  have tailCheck : nullifiersFresh (spent ++ headValues) tail = true := by
    unfold nullifiersFresh
    change (decide tailValues.Nodup && tailValues.all
      (fun value => !((spent ++ headValues).contains value))) = true
    have tailFresh : tailValues.all
        (fun value => (spent ++ headValues).contains value = false) = true := by
      apply List.all_eq_true.mpr
      intro value valueMember
      have absentSpent : spent.contains value = false := by
        have h := List.all_eq_true.mp freshParts.2 value valueMember
        simpa using h
      have absentHead : headValues.contains value = false := by
        cases present : headValues.contains value with
        | false => rfl
        | true =>
            have inHead := List.contains_iff_mem.mp present
            exact ((nodupParts.2.2 value inHead value valueMember) rfl).elim
      rw [List.contains_append, absentSpent, absentHead]
      rfl
    have tailAll : tailValues.all
        (fun value => !((spent ++ headValues).contains value)) = true := by
      simpa using tailFresh
    simp only [Bool.and_eq_true_iff]
    exact ⟨
      by simpa only [decide_eq_true_eq] using nodupParts.2.1,
      tailAll⟩
  exact ⟨headCheck, tailCheck⟩

private theorem checked_nullifiers_drop_prefix
    (spent : List Digest) (done rest : List CurrentRunEnvelope)
    (checked : nullifiersFresh spent (done ++ rest) = true) :
    nullifiersFresh (spent ++ blockNullifiers done) rest = true := by
  induction done generalizing spent with
  | nil => simpa [blockNullifiers] using checked
  | cons head tail ih =>
      have split := checked_nullifiers_cons spent head (tail ++ rest) (by
        simpa [List.cons_append, List.append_assoc] using checked)
      have tailChecked := ih (spent ++ sourceRunNullifiers head.run) split.2
      simpa [blockNullifiers, List.flatMap_append, List.flatMap_cons,
        sourceRunNullifiers, List.append_assoc] using tailChecked

/-- Run the native block checks directly on actual selector outputs.  This is
the public entry point for a list of verifier stages; callers cannot fill the
transaction list with independently constructed accepted witnesses. -/
def executeSelectedCurrentBlock (ledgerPrefix : CurrentSourceLedgerPrefix)
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork)))
    (coinbase : Option (Nat × V8NoteOpening)) :=
  executeCurrentBlock ledgerPrefix.snapshot.parent ledgerPrefix.spentNullifiers
    (selectedTransactions (BaseWork := BaseWork) stages) coinbase

/-- One final finite-note registry for every transaction action in a successful
selected block.  Its extension is exactly the native replay's transaction
outputs followed by the trailing coinbase opening. -/
def selectedBlockLedgerRegistry (ledgerPrefix : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult ledgerPrefix.snapshot.parent
      ledgerPrefix.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase) :
    Nat → V8NoteOpening :=
  fun position => openingAt (ledgerPrefix.stagedOpenings ++ result.openingsAdded)
    position

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- The native append transcript retained by the same block result is the
source of this registry's suffix; the equality includes trailing coinbase. -/
theorem selected_block_registry_suffix
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult ledgerPrefix.snapshot.parent
      ledgerPrefix.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase) :
    (selectedBlockLedgerRegistry ledgerPrefix result) =
      openingAt (ledgerPrefix.stagedOpenings ++
        blockOpeningStream (outputRecords result.runs)
          (blockCoinbaseOpening coinbase)) := by
  funext position
  simp [selectedBlockLedgerRegistry, result.openingsAddedEq]

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- While a block is being folded, the local transfer view and the initial
block's one final registry coincide whenever the already processed outputs,
this run's stream and the remaining transaction/coinbase suffix partition
the replayed append log.  The equality is structural append bookkeeping. -/
theorem current_run_registry_is_block_registry
    (initial current : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult initial.snapshot.parent
      initial.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase)
    (past added future : List V8NoteOpening)
    (stagedEq : current.stagedOpenings = initial.stagedOpenings ++ past)
    (suffixEq : result.openingsAdded = past ++ added ++ future) :
    currentSourceRegistry current added future =
      selectedBlockLedgerRegistry initial result := by
  funext position
  simp [currentSourceRegistry, selectedBlockLedgerRegistry,
    stagedEq, suffixEq, List.append_assoc]

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- The finite issuance checker views the exact same final registry as the
transaction fold when its supplied future suffix is the post-coinbase tail. -/
theorem source_coinbase_registry_is_block_registry
    (initial current : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult initial.snapshot.parent
      initial.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase)
    (past : List V8NoteOpening)
    (stagedEq : current.stagedOpenings = initial.stagedOpenings ++ past)
    (suffixEq : result.openingsAdded =
      past ++ sourceCoinbaseOpenings coinbase) :
    sourceCoinbaseRegistry current [] coinbase =
      selectedBlockLedgerRegistry initial result := by
  funext position
  simp [sourceCoinbaseRegistry, sourceCoinbaseOpenings,
    selectedBlockLedgerRegistry, stagedEq, suffixEq, List.append_assoc]

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- A successful public coinbase plan is a CurrentProtocolStep on the same
whole-block registry used by the preceding transfers.  Payment, issued-height
freshness, exact output frame and native paid-value realization come from the
checker; this adapter changes only the function-indexed registry. -/
theorem checked_coinbase_plan_block_step
    (initial current : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult initial.snapshot.parent
      initial.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase)
    (past : List V8NoteOpening)
    (stagedEq : current.stagedOpenings = initial.stagedOpenings ++ past)
    (suffixEq : result.openingsAdded =
      past ++ sourceCoinbaseOpenings coinbase)
    (action : Action) (after : Ledger)
    (checked : sourceCoinbasePlan current [] coinbase = some (action, after)) :
    CurrentProtocolStep (program := SmzaRp05Components.program)
      (primitives := rustV8SemanticPrimitives)
      (selectedBlockLedgerRegistry initial result) current.ledger action after := by
  have localStep := sourceCoinbasePlan_sound
    (program := SmzaRp05Components.program)
    (primitives := rustV8SemanticPrimitives) current [] coinbase action after checked
  have registryEq := source_coinbase_registry_is_block_registry
    initial current result past stagedEq suffixEq
  rw [← registryEq]
  exact localStep

/-- The successful source coinbase plan and its prefix update are the same
state transition.  A rejected present coinbase has no such witness because
the checked updater returns `none`. -/
theorem checked_coinbase_plan_prefix_update
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (coinbase : Option (Nat × V8NoteOpening))
    (action : Action) (after : Ledger)
    (checked : sourceCoinbasePlan ledgerPrefix [] coinbase =
      some (action, after)) :
    ∃ next : CurrentSourceLedgerPrefix,
      checkedSourceCoinbasePrefixAfter ledgerPrefix coinbase = some next ∧
        next.ledger = after := by
  cases coinbase with
  | none =>
      simp only [sourceCoinbasePlan] at checked
      have pairEq := Option.some.inj checked
      rcases pairEq with ⟨rfl, rfl⟩
      let next : CurrentSourceLedgerPrefix := {
          snapshot := ledgerPrefix.snapshot
          stagedOpenings := ledgerPrefix.stagedOpenings
          stagedPrefix := ledgerPrefix.stagedPrefix
          ledger := burnEscrow ledgerPrefix.ledger
          priorSpends := ledgerPrefix.priorSpends
          spentNullifiers := ledgerPrefix.spentNullifiers
          liveCoverage := by simpa only [burnEscrow] using ledgerPrefix.liveCoverage
          spentExact := by simpa only [burnEscrow] using ledgerPrefix.spentExact
          spentInStagedRange := by
            simpa only [burnEscrow] using ledgerPrefix.spentInStagedRange
          priorPrefix := ledgerPrefix.priorPrefix
          priorRegistered := ledgerPrefix.priorRegistered
        }
      refine ⟨next, ?_, rfl⟩
      simp [checkedSourceCoinbasePrefixAfter, next]
  | some pair =>
      rcases pair with ⟨height, opening⟩
      simp only [sourceCoinbasePlan] at checked
      cases payment : checkedSourceCoinbasePaid?
          ledgerPrefix.ledger height opening with
      | none => simp [payment] at checked
      | some paid =>
          simp only [payment] at checked
          have pairEq := Option.some.inj checked
          rcases pairEq with ⟨rfl, rfl⟩
          refine ⟨appendSourceCoinbasePrefix ledgerPrefix height opening,
            ?_, rfl⟩
          simp [checkedSourceCoinbasePrefixAfter, payment]

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- A successful selected block's anchor guard applies to each exact
selector-produced envelope against the unchanged pre-block native snapshot. -/
theorem selected_block_run_admitted
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork)))
    (coinbase : Option (Nat × V8NoteOpening))
    (result : CurrentBlockReplayResult ledgerPrefix.snapshot.parent
      ledgerPrefix.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase)
    (envelope : CurrentRunEnvelope) (member : envelope ∈ result.runs) :
    publicAnchor (encodePublicStatement envelope.typedStatement) ∈
      ledgerPrefix.snapshot.parent.history :=
  block_anchor_check_derives_membership ledgerPrefix.snapshot.parent
    result.runs result.anchorsChecked envelope member

/-- Resolve one actual selected run.  The positive-input classifier either
returns its exact charged source/path failure, or the transfer constructor
returns the current finite-ledger step or its exact source path-collision
arm.  Admission and nullifier freshness are premises here only as theorem
consequences of the enclosing successful block replay, not new guards. -/
theorem selected_run_step_or_charged_failure
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (envelope : CurrentRunEnvelope)
    (future : List V8NoteOpening)
    (admitted : publicAnchor (encodePublicStatement envelope.typedStatement) ∈
      ledgerPrefix.snapshot.parent.history)
    (fresh : sourceNullifiersFresh ledgerPrefix.spentNullifiers envelope.run = true) :
    CurrentRunInputFailure ledgerPrefix envelope admitted ∨
      CurrentProtocolStep (program := SmzaRp05Components.program)
        (primitives := rustV8SemanticPrimitives)
        (currentSourceRegistry ledgerPrefix
          (outputOpenings (encodePublicStatement envelope.typedStatement)
            (designatedInputPacked envelope.run)) future)
        ledgerPrefix.ledger
        (.transfer (currentSourceTransfer ledgerPrefix envelope.run future))
        (applyTransfer ledgerPrefix.ledger
          (currentSourceTransfer ledgerPrefix envelope.run future)) ∨
      (∃ _leftPositive : 0 < inputSlotNative envelope.typedStatement
          (designatedInputPacked envelope.run) 0,
        ∃ _rightPositive : 0 < inputSlotNative envelope.typedStatement
          (designatedInputPacked envelope.run) 1,
          HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness.CurrentInputPathCollision
              envelope.run ledgerPrefix.snapshot.openings 0 ∨
            HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness.CurrentInputPathCollision
              envelope.run ledgerPrefix.snapshot.openings 1) := by
  have classified := run_inputs_binding_or_charged_failure
    ledgerPrefix envelope admitted fresh
  rcases classified with bindings | failure
  · rcases current_source_transfer_step_of_successful_bindings
        ledgerPrefix envelope.run future admitted bindings with step | collision
    · exact Or.inr (Or.inl step)
    · exact Or.inr (Or.inr collision)
  · exact Or.inl failure

/-- The first charged positive-input outcome for one selected run. This is an
actual classifier result, not a supplied no-collision premise. -/
inductive CurrentRunChargedFailure (ledgerPrefix : CurrentSourceLedgerPrefix)
    (envelope : CurrentRunEnvelope) : Prop where
  | input {admitted : publicAnchor (encodePublicStatement envelope.typedStatement) ∈
      ledgerPrefix.snapshot.parent.history}
      (failure : CurrentRunInputFailure ledgerPrefix envelope admitted) :
      CurrentRunChargedFailure ledgerPrefix envelope
  | pathCollision
      (leftPositive : 0 < inputSlotNative envelope.typedStatement
        (designatedInputPacked envelope.run) 0)
      (rightPositive : 0 < inputSlotNative envelope.typedStatement
        (designatedInputPacked envelope.run) 1)
      (collision :
        HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness.CurrentInputPathCollision
            envelope.run ledgerPrefix.snapshot.openings 0 ∨
          HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness.CurrentInputPathCollision
            envelope.run ledgerPrefix.snapshot.openings 1) :
      CurrentRunChargedFailure ledgerPrefix envelope

/-- One selected-run replay attempt. Public anchor/nullifier checks are
derived by the caller from the enclosing block result; source input failure
or position-path collision is returned as the charged arm. On success the
result contains both the source-derived input bindings and exact transfer
step, required to construct the successor Prefix without selecting again. -/
theorem selected_run_attempt
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (envelope : CurrentRunEnvelope)
    (future : List V8NoteOpening)
    (admitted : publicAnchor (encodePublicStatement envelope.typedStatement) ∈
      ledgerPrefix.snapshot.parent.history)
    (fresh : sourceNullifiersFresh ledgerPrefix.spentNullifiers envelope.run = true)
    (registry : Nat → V8NoteOpening)
    (registryEq : currentSourceRegistry ledgerPrefix
      (outputOpenings (encodePublicStatement envelope.typedStatement)
        (designatedInputPacked envelope.run)) future = registry) :
    CurrentRunChargedFailure ledgerPrefix envelope ∨
      ∃ bindings : CurrentSuccessfulInputBindings ledgerPrefix envelope.run admitted,
        bindings = bindings ∧
        CurrentProtocolStep (program := SmzaRp05Components.program)
          (primitives := rustV8SemanticPrimitives) registry ledgerPrefix.ledger
          (.transfer (currentSourceTransfer ledgerPrefix envelope.run future))
          (applyTransfer ledgerPrefix.ledger
            (currentSourceTransfer ledgerPrefix envelope.run future)) := by
  have classified := run_inputs_binding_or_charged_failure
    ledgerPrefix envelope admitted fresh
  rcases classified with bindings | failure
  · rcases current_source_transfer_step_of_successful_bindings
        ledgerPrefix envelope.run future admitted bindings with step | collision
    · refine Or.inr ⟨bindings, rfl, ?_⟩
      rw [← registryEq]
      exact step
    · rcases collision with ⟨leftPositive, rightPositive, collision⟩
      exact Or.inl (.pathCollision leftPositive rightPositive collision)
  · exact Or.inl (.input failure)

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- Instantiate the per-run resolver from the enclosing successful native
block.  The anchor and nullifier facts are projections of that replay's
operational checks; the remaining branch is a transfer or a named charged
input/path failure. -/
theorem selected_block_head_resolves
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork)))
    (coinbase : Option (Nat × V8NoteOpening))
    (result : CurrentBlockReplayResult ledgerPrefix.snapshot.parent
      ledgerPrefix.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase)
    (envelope : CurrentRunEnvelope) (tail : List CurrentRunEnvelope)
    (runsEq : result.runs = envelope :: tail)
    (future : List V8NoteOpening) :
    ∃ admitted : publicAnchor (encodePublicStatement envelope.typedStatement) ∈
        ledgerPrefix.snapshot.parent.history,
    CurrentRunInputFailure ledgerPrefix envelope admitted ∨
      CurrentProtocolStep (program := SmzaRp05Components.program)
        (primitives := rustV8SemanticPrimitives)
        (currentSourceRegistry ledgerPrefix
          (outputOpenings (encodePublicStatement envelope.typedStatement)
            (designatedInputPacked envelope.run)) future)
        ledgerPrefix.ledger
        (.transfer (currentSourceTransfer ledgerPrefix envelope.run future))
        (applyTransfer ledgerPrefix.ledger
          (currentSourceTransfer ledgerPrefix envelope.run future)) ∨
      (∃ _leftPositive : 0 < inputSlotNative envelope.typedStatement
          (designatedInputPacked envelope.run) 0,
        ∃ _rightPositive : 0 < inputSlotNative envelope.typedStatement
          (designatedInputPacked envelope.run) 1,
          HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness.CurrentInputPathCollision
              envelope.run ledgerPrefix.snapshot.openings 0 ∨
            HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness.CurrentInputPathCollision
              envelope.run ledgerPrefix.snapshot.openings 1) := by
  have runMember : envelope ∈ result.runs := by
    rw [runsEq]
    simp
  have admitted := selected_block_run_admitted ledgerPrefix stages coinbase
    result envelope runMember
  have split := checked_nullifiers_cons ledgerPrefix.spentNullifiers
    envelope tail (by simpa [runsEq] using result.nullifiersChecked)
  rcases selected_run_step_or_charged_failure ledgerPrefix envelope future
      admitted split.1 with failure | resolved
  · exact ⟨admitted, Or.inl failure⟩
  · exact ⟨admitted, Or.inr resolved⟩

/-- The run fold either completes or stops at the first actual charged
failure. -/
inductive CurrentSelectedRunOutcome : Type where
  | complete : CurrentSelectedRunOutcome
  | chargedFailure {ledgerPrefix : CurrentSourceLedgerPrefix}
      {envelope : CurrentRunEnvelope}
      (failure : CurrentRunChargedFailure ledgerPrefix envelope) :
      CurrentSelectedRunOutcome

/-- One recursive finite-ledger result for a chronological run list.  A
successful constructor records the exact source-derived transfer step and
the proof-produced Prefix successor.  A stop records the first run whose
actual input classifier or path-collision reduction fails; later runs are
not silently accepted. -/
inductive CurrentSelectedRunFold
    (registry : Nat → V8NoteOpening) (trailing : List V8NoteOpening) :
    CurrentSourceLedgerPrefix → List CurrentRunEnvelope → List Action →
      CurrentSourceLedgerPrefix → CurrentSelectedRunOutcome → Prop where
  | complete (ledgerPrefix : CurrentSourceLedgerPrefix) :
      CurrentSelectedRunFold registry trailing ledgerPrefix [] [] ledgerPrefix .complete
  | stopped {ledgerPrefix : CurrentSourceLedgerPrefix}
      {envelope : CurrentRunEnvelope} {tail : List CurrentRunEnvelope}
      (failure : CurrentRunChargedFailure ledgerPrefix envelope) :
      CurrentSelectedRunFold registry trailing ledgerPrefix (envelope :: tail)
        [] ledgerPrefix (.chargedFailure failure)
  | transfer {ledgerPrefix next final : CurrentSourceLedgerPrefix}
      {envelope : CurrentRunEnvelope} {tail : List CurrentRunEnvelope}
      {actions : List Action} {outcome : CurrentSelectedRunOutcome}
      (admitted : publicAnchor (encodePublicStatement envelope.typedStatement) ∈
        ledgerPrefix.snapshot.parent.history)
      (bindings : CurrentSuccessfulInputBindings ledgerPrefix envelope.run admitted)
      (registryEq : currentSourceRegistry ledgerPrefix
        (selectedRunOutputOpenings envelope)
        (selectedRunOpeningStream tail ++ trailing) = registry)
      (step : CurrentProtocolStep (program := SmzaRp05Components.program)
        (primitives := rustV8SemanticPrimitives) registry ledgerPrefix.ledger
        (.transfer (currentSourceTransfer ledgerPrefix envelope.run
          (selectedRunOpeningStream tail ++ trailing)))
        (applyTransfer ledgerPrefix.ledger
          (currentSourceTransfer ledgerPrefix envelope.run
            (selectedRunOpeningStream tail ++ trailing))))
      (nextEq : next = prefix_after_transfer ledgerPrefix envelope.run
        (selectedRunOpeningStream tail ++ trailing) admitted bindings)
      (rest : CurrentSelectedRunFold registry trailing next tail actions final
        outcome) :
      CurrentSelectedRunFold registry trailing ledgerPrefix (envelope :: tail)
        (.transfer (currentSourceTransfer ledgerPrefix envelope.run
          (selectedRunOpeningStream tail ++ trailing)) :: actions)
        final outcome

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- The selected full-success envelopes of a successful native block can be
folded in source order over one registry containing the entire block output
log, including the trailing coinbase.  At each step anchor admission and
public-nullifier freshness are projected from the enclosing native block
checks; input failures remain explicit charged outcomes. -/
theorem fold_selected_block_runs
    (initial current : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult initial.snapshot.parent
      initial.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase)
    (done runs : List CurrentRunEnvelope)
    (runsEq : result.runs = done ++ runs)
    (snapshotEq : current.snapshot = initial.snapshot)
    (spentEq : current.spentNullifiers = initial.spentNullifiers ++
      blockNullifiers done)
    (stagedEq : current.stagedOpenings = initial.stagedOpenings ++
      selectedRunOpeningStream done)
    (suffixEq : result.openingsAdded =
      selectedRunOpeningStream done ++ selectedRunOpeningStream runs ++
        sourceCoinbaseOpenings coinbase) :
    ∃ actions final outcome,
      CurrentSelectedRunFold (selectedBlockLedgerRegistry initial result)
        (sourceCoinbaseOpenings coinbase) current runs actions final outcome := by
  induction runs generalizing current done with
  | nil =>
      exact ⟨[], current, .complete,
        CurrentSelectedRunFold.complete
          (registry := selectedBlockLedgerRegistry initial result)
          (trailing := sourceCoinbaseOpenings coinbase) current⟩
  | cons envelope tail ih =>
      have headOutput : selectedRunOpeningStream (envelope :: tail) =
          selectedRunOutputOpenings envelope ++ selectedRunOpeningStream tail := by
        simp [selectedRunOpeningStream]
      have splitSuffix : result.openingsAdded =
          (selectedRunOpeningStream done ++ selectedRunOutputOpenings envelope) ++
            (selectedRunOpeningStream tail ++ sourceCoinbaseOpenings coinbase) := by
        rw [suffixEq, headOutput]
        simp [List.append_assoc]
      have admitted : publicAnchor (encodePublicStatement envelope.typedStatement) ∈
          current.snapshot.parent.history := by
        have member : envelope ∈ result.runs := by
          rw [runsEq]
          simp [List.mem_append]
        rw [snapshotEq]
        exact selected_block_run_admitted initial stages coinbase result
          envelope member
      have currentFresh := checked_nullifiers_drop_prefix
        initial.spentNullifiers done (envelope :: tail) (by
          simpa [runsEq] using result.nullifiersChecked)
      have freshAtCurrent : nullifiersFresh current.spentNullifiers
          (envelope :: tail) = true := by
        rw [spentEq]
        exact currentFresh
      have freshness : sourceNullifiersFresh current.spentNullifiers
          envelope.run = true := by
        have checked := (checked_nullifiers_cons current.spentNullifiers
          envelope tail freshAtCurrent).1
        exact checked
      have registryEq := current_run_registry_is_block_registry initial current
        result (selectedRunOpeningStream done)
        (selectedRunOutputOpenings envelope)
        (selectedRunOpeningStream tail ++ sourceCoinbaseOpenings coinbase)
        stagedEq splitSuffix
      have attempt := selected_run_attempt current envelope
        (selectedRunOpeningStream tail ++ sourceCoinbaseOpenings coinbase)
        admitted freshness (selectedBlockLedgerRegistry initial result)
        registryEq
      rcases attempt with failure | successful
      · exact ⟨[], current, .chargedFailure failure,
          CurrentSelectedRunFold.stopped failure⟩
      · rcases successful with ⟨bindings, _, step⟩
        let next := prefix_after_transfer current envelope.run
          (selectedRunOpeningStream tail ++ sourceCoinbaseOpenings coinbase) admitted bindings
        have stagedNext : next.stagedOpenings =
            initial.stagedOpenings ++ selectedRunOpeningStream (done ++ [envelope]) := by
          simp [next, prefix_after_transfer, stagedEq,
            selectedRunOutputOpenings, selectedRunOpeningStream,
            List.append_assoc]
        have snapshotNext : next.snapshot = initial.snapshot := by
          simp [next, prefix_after_transfer, snapshotEq]
        have spentNext : next.spentNullifiers = initial.spentNullifiers ++
            blockNullifiers (done ++ [envelope]) := by
          simp [next, prefix_after_transfer, spentEq, blockNullifiers,
            List.flatMap_append, List.flatMap_cons, sourceRunNullifiers,
            List.append_assoc]
        have tailSuffix : result.openingsAdded =
            selectedRunOpeningStream (done ++ [envelope]) ++
              selectedRunOpeningStream tail ++ sourceCoinbaseOpenings coinbase := by
          calc
            result.openingsAdded =
                (selectedRunOpeningStream done ++ selectedRunOutputOpenings envelope) ++
                  (selectedRunOpeningStream tail ++ sourceCoinbaseOpenings coinbase) :=
              splitSuffix
            _ = selectedRunOpeningStream (done ++ [envelope]) ++
                  selectedRunOpeningStream tail ++ sourceCoinbaseOpenings coinbase := by
              simp [selectedRunOpeningStream, List.flatMap_append,
                List.flatMap_cons, List.append_assoc]
        have tailRunsEq : result.runs = (done ++ [envelope]) ++ tail := by
          rw [runsEq]
          simp [List.append_assoc]
        obtain ⟨actions, final, outcome, rest⟩ := ih next
          (done ++ [envelope]) tailRunsEq snapshotNext spentNext stagedNext tailSuffix
        exact ⟨.transfer (currentSourceTransfer current envelope.run
            (selectedRunOpeningStream tail ++ sourceCoinbaseOpenings coinbase)) :: actions,
          final, outcome, CurrentSelectedRunFold.transfer admitted bindings
            registryEq step (by rfl) rest⟩

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- Top-level transaction fold for a successful native block.  The fold
starts at the actual supplied ledger prefix; all chronological selector
outputs and the trailing coinbase already determine its fixed registry. -/
theorem selected_block_fold_from_boundary
    (initial : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult initial.snapshot.parent
      initial.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase) :
    ∃ actions final outcome,
      CurrentSelectedRunFold (selectedBlockLedgerRegistry initial result)
        (sourceCoinbaseOpenings coinbase) initial result.runs actions final outcome := by
  have openings := selected_block_openings_decompose initial result
  have suffixEq : result.openingsAdded =
      selectedRunOpeningStream [] ++ selectedRunOpeningStream result.runs ++
        sourceCoinbaseOpenings coinbase := by
    simpa [selectedRunOpeningStream] using openings
  exact fold_selected_block_runs initial initial result [] result.runs (by simp)
    rfl (by simp [blockNullifiers]) (by simp [selectedRunOpeningStream]) suffixEq

/-- Every completed selected-run fold induces the exact finite execution;
the public action order is the native chronological transaction order. -/
theorem selected_run_fold_execution
    {registry : Nat → V8NoteOpening} {trailing : List V8NoteOpening}
    {initial final : CurrentSourceLedgerPrefix} {runs : List CurrentRunEnvelope}
    {actions : List Action}
    (fold : CurrentSelectedRunFold registry trailing initial runs actions final
      .complete) :
    CurrentExecution (program := SmzaRp05Components.program)
      (primitives := rustV8SemanticPrimitives) (registry := registry)
      initial.ledger actions final.ledger := by
  generalize outcomeEq : CurrentSelectedRunOutcome.complete = outcome at fold
  revert outcomeEq
  induction fold with
  | complete ledgerPrefix =>
      intro outcomeEq
      cases outcomeEq
      exact .nil (program := SmzaRp05Components.program)
        (primitives := rustV8SemanticPrimitives) ledgerPrefix.ledger
  | stopped _ =>
      intro outcomeEq
      cases outcomeEq
  | transfer _ _ _ step nextEq rest ih =>
      intro outcomeEq
      cases nextEq
      simpa [prefix_after_transfer] using CurrentExecution.cons
        (program := SmzaRp05Components.program)
        (primitives := rustV8SemanticPrimitives) step (ih outcomeEq)

/-- No generated transfer action has an input/output note collision: both
opening functions are the exact same selected block registry retained in the
fold constructor, rather than merely commitment-equal notes. -/
theorem selected_run_fold_no_collision
    {registry : Nat → V8NoteOpening} {trailing : List V8NoteOpening}
    {initial final : CurrentSourceLedgerPrefix} {runs : List CurrentRunEnvelope}
    {actions : List Action}
    (fold : CurrentSelectedRunFold registry trailing initial runs actions final
      .complete) :
      ∀ action ∈ actions, ¬ badCollision registry action := by
  generalize outcomeEq : CurrentSelectedRunOutcome.complete = outcome at fold
  revert outcomeEq
  induction fold with
  | complete _ =>
      intro outcomeEq
      cases outcomeEq
      simp
  | stopped _ =>
      intro outcomeEq
      cases outcomeEq
  | @transfer ledgerPrefix next final envelope tail actions outcome
      admitted bindings registryEq step nextEq rest ih =>
      intro outcomeEq action member
      simp only [List.mem_cons] at member
      rcases member with first | later
      · subst action
        intro collision
        change transferCollision registry
          (currentSourceTransfer ledgerPrefix envelope.run
            (selectedRunOpeningStream tail ++ trailing)) at collision
        rcases collision with inputCollision | outputCollision
        · rcases inputCollision with ⟨id, _member, noteBad⟩
          have openingEq :
              (currentSourceTransfer ledgerPrefix envelope.run
                (selectedRunOpeningStream tail ++ trailing)).inputOpening id =
                registry id := by
            change currentSourceRegistry ledgerPrefix
              (selectedRunOutputOpenings envelope)
              (selectedRunOpeningStream tail ++ trailing) id = registry id
            exact congrFun registryEq id
          exact noteBad.1 (by rw [openingEq])
        · rcases outputCollision with ⟨id, _member, noteBad⟩
          have openingEq :
              (currentSourceTransfer ledgerPrefix envelope.run
                (selectedRunOpeningStream tail ++ trailing)).outputOpening id =
                registry id := by
            change currentSourceRegistry ledgerPrefix
              (selectedRunOutputOpenings envelope)
              (selectedRunOpeningStream tail ++ trailing) id = registry id
            exact congrFun registryEq id
          exact noteBad.1 (by rw [openingEq])
      · exact ih outcomeEq action later

/-- The staged log after a completed transaction fold is exactly the
initial staged log followed by those transactions' designated output
openings.  Coinbase remains a separate trailing event until its checked
ledger transition. -/
theorem selected_run_fold_staged
    {registry : Nat → V8NoteOpening} {trailing : List V8NoteOpening}
    {initial final : CurrentSourceLedgerPrefix} {runs : List CurrentRunEnvelope}
    {actions : List Action}
    (fold : CurrentSelectedRunFold registry trailing initial runs actions final
      .complete) :
    final.stagedOpenings = initial.stagedOpenings ++
      selectedRunOpeningStream runs := by
  generalize outcomeEq : CurrentSelectedRunOutcome.complete = outcome at fold
  revert outcomeEq
  induction fold with
  | complete _ =>
      intro outcomeEq
      cases outcomeEq
      simp [selectedRunOpeningStream]
  | stopped _ =>
      intro outcomeEq
      cases outcomeEq
  | @transfer ledgerPrefix next final envelope tail actions outcome
      admitted bindings registryEq step nextEq rest ih =>
      intro outcomeEq
      subst nextEq
      rw [ih outcomeEq]
      simp only [prefix_after_transfer]
      simp only [selectedRunOpeningStream, List.flatMap_cons,
        selectedRunOutputOpenings, List.append_assoc]

theorem selected_run_fold_snapshot
    {registry : Nat → V8NoteOpening} {trailing : List V8NoteOpening}
    {initial final : CurrentSourceLedgerPrefix} {runs : List CurrentRunEnvelope}
    {actions : List Action}
    (fold : CurrentSelectedRunFold registry trailing initial runs actions final
      .complete) :
    final.snapshot = initial.snapshot := by
  generalize outcomeEq : CurrentSelectedRunOutcome.complete = outcome at fold
  revert outcomeEq
  induction fold with
  | complete _ =>
      intro outcomeEq
      cases outcomeEq
      rfl
  | stopped _ =>
      intro outcomeEq
      cases outcomeEq
  | transfer _ _ _ _ nextEq _ ih =>
      intro outcomeEq
      subst nextEq
      simpa [prefix_after_transfer] using ih outcomeEq

theorem current_execution_append_step
    {registry : Nat → V8NoteOpening} {before middle after : Ledger}
    {actions : List Action} {action : Action}
    (execution : CurrentExecution (program := SmzaRp05Components.program)
      (primitives := rustV8SemanticPrimitives) (registry := registry)
      before actions middle)
    (step : CurrentProtocolStep (program := SmzaRp05Components.program)
      (primitives := rustV8SemanticPrimitives) registry middle action after) :
    CurrentExecution (program := SmzaRp05Components.program)
      (primitives := rustV8SemanticPrimitives) (registry := registry)
      before (actions ++ [action]) after := by
  induction execution with
  | nil state =>
      simpa using CurrentExecution.cons (program := SmzaRp05Components.program)
        (primitives := rustV8SemanticPrimitives) step
        (CurrentExecution.nil (program := SmzaRp05Components.program)
          (primitives := rustV8SemanticPrimitives) after)
  | cons first rest ih =>
      simpa [List.cons_append] using CurrentExecution.cons
        (program := SmzaRp05Components.program)
        (primitives := rustV8SemanticPrimitives) first (ih step)

/-- The successful finite fold accumulates exactly the source fees in the
same designated-run order used by the actual-history coinbase checker. -/
theorem selected_run_fold_fee_escrow
    {registry : Nat → V8NoteOpening} {trailing : List V8NoteOpening}
    {initial final : CurrentSourceLedgerPrefix} {runs : List CurrentRunEnvelope}
    {actions : List Action}
    (fold : CurrentSelectedRunFold registry trailing initial runs actions final
      .complete) :
    final.ledger.feeEscrow = initial.ledger.feeEscrow +
      HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedHistorySupplyEndpoint.blockFees
        (selectedDesignatedRuns runs) := by
  generalize outcomeEq : CurrentSelectedRunOutcome.complete = outcome at fold
  revert outcomeEq
  induction fold with
  | complete _ =>
      intro outcomeEq
      cases outcomeEq
      simp [HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedHistorySupplyEndpoint.blockFees,
        selectedDesignatedRuns]
  | stopped _ =>
      intro outcomeEq
      cases outcomeEq
  | @transfer ledgerPrefix next final envelope tail actions outcome
      admitted bindings registryEq step nextEq rest ih =>
      intro outcomeEq
      cases nextEq
      have ih' := ih outcomeEq
      simp only [HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedHistorySupplyEndpoint.blockFees,
        selectedDesignatedRuns, List.map_cons, List.sum_cons] at ih' ⊢
      have feeUpdate :
          (prefix_after_transfer ledgerPrefix envelope.run
            (selectedRunOpeningStream tail ++ trailing) admitted bindings).ledger.feeEscrow =
            ledgerPrefix.ledger.feeEscrow + envelope.typedStatement.fee := by
        simp [prefix_after_transfer, applyTransfer, currentSourceTransfer]
      rw [ih', feeUpdate]
      simp only [selectedDesignatedRun]
      omega

/-- Transfers leave the already issued-height set unchanged. -/
theorem selected_run_fold_issued_heights
    {registry : Nat → V8NoteOpening} {trailing : List V8NoteOpening}
    {initial final : CurrentSourceLedgerPrefix} {runs : List CurrentRunEnvelope}
    {actions : List Action}
    (fold : CurrentSelectedRunFold registry trailing initial runs actions final
      .complete) :
    final.ledger.issuedHeights = initial.ledger.issuedHeights := by
  generalize outcomeEq : CurrentSelectedRunOutcome.complete = outcome at fold
  revert outcomeEq
  induction fold with
  | complete _ =>
      intro outcomeEq
      cases outcomeEq
      rfl
  | stopped _ =>
      intro outcomeEq
      cases outcomeEq
  | transfer _ _ _ _ nextEq _ ih =>
      intro outcomeEq
      cases nextEq
      rw [ih outcomeEq]
      simp [prefix_after_transfer, applyTransfer, currentSourceTransfer]

/-- The complete transaction fold appends exactly the source nullifiers that
the public replay projects from the same ordered runs. -/
theorem selected_run_fold_spent_nullifiers
    {registry : Nat → V8NoteOpening} {trailing : List V8NoteOpening}
    {initial final : CurrentSourceLedgerPrefix} {runs : List CurrentRunEnvelope}
    {actions : List Action}
    (fold : CurrentSelectedRunFold registry trailing initial runs actions final
      .complete) :
    final.spentNullifiers = initial.spentNullifiers ++ blockNullifiers runs := by
  generalize outcomeEq : CurrentSelectedRunOutcome.complete = outcome at fold
  revert outcomeEq
  induction fold with
  | complete _ =>
      intro outcomeEq
      cases outcomeEq
      simp [blockNullifiers]
  | stopped _ =>
      intro outcomeEq
      cases outcomeEq
  | transfer _ _ _ _ nextEq _ ih =>
      intro outcomeEq
      cases nextEq
      simp [prefix_after_transfer, blockNullifiers, sourceRunNullifiers,
        List.append_assoc, ih outcomeEq]

/-- The checked coinbase plan always settles (burns or pays) the complete fee
escrow. It adds the supplied height exactly when the optional native
coinbase is present. -/
theorem source_coinbase_plan_public_fields
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (coinbase : Option (Nat × V8NoteOpening))
    (action : Action) (after : Ledger)
    (plan : sourceCoinbasePlan ledgerPrefix [] coinbase = some (action, after)) :
    after.feeEscrow = 0 ∧
      after.issuedHeights = match coinbase with
        | none => ledgerPrefix.ledger.issuedHeights
        | some (height, _) => insert height ledgerPrefix.ledger.issuedHeights := by
  cases coinbase with
  | none =>
      simp [sourceCoinbasePlan] at plan
      rcases plan with ⟨rfl, rfl⟩
      simp [burnEscrow]
  | some candidate =>
      rcases candidate with ⟨height, opening⟩
      unfold sourceCoinbasePlan at plan
      cases checked : checkedSourceCoinbasePaid? ledgerPrefix.ledger height opening with
      | none => simp [checked] at plan
      | some paid =>
          simp only [checked, Option.some.injEq, Prod.mk.injEq] at plan
          rcases plan with ⟨_, rfl⟩
          simp [applyCoinbase]

theorem checked_coinbase_prefix_spent_nullifiers
    (ledgerPrefix next : CurrentSourceLedgerPrefix)
    (coinbase : Option (Nat × V8NoteOpening))
    (updated : checkedSourceCoinbasePrefixAfter ledgerPrefix coinbase = some next) :
    next.spentNullifiers = ledgerPrefix.spentNullifiers := by
  cases coinbase with
  | none =>
      simp [checkedSourceCoinbasePrefixAfter] at updated
      subst next
      rfl
  | some candidate =>
      rcases candidate with ⟨height, opening⟩
      simp only [checkedSourceCoinbasePrefixAfter] at updated
      cases paid : checkedSourceCoinbasePaid? ledgerPrefix.ledger height opening with
      | none => simp [paid] at updated
      | some amount =>
          simp only [paid, Option.some.injEq] at updated
          subst next
          rfl

theorem checked_coinbase_update_snapshot
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (coinbase : Option (Nat × V8NoteOpening))
    (action : Action) (after : Ledger)
    (plan : sourceCoinbasePlan ledgerPrefix [] coinbase = some (action, after)) :
    ∃ next, checkedSourceCoinbasePrefixAfter ledgerPrefix coinbase = some next ∧
      next.ledger = after ∧
      next.snapshot = ledgerPrefix.snapshot ∧
      next.stagedOpenings = ledgerPrefix.stagedOpenings ++ sourceCoinbaseOpenings coinbase := by
  obtain ⟨next, updated, ledgerEq⟩ := checked_coinbase_plan_prefix_update
    ledgerPrefix coinbase action after plan
  refine ⟨next, updated, ledgerEq, ?_, ?_⟩
  · cases coinbase with
    | none =>
        simp [checkedSourceCoinbasePrefixAfter] at updated
        subst next
        rfl
    | some pair =>
        rcases pair with ⟨height, opening⟩
        simp only [checkedSourceCoinbasePrefixAfter] at updated
        cases paid : checkedSourceCoinbasePaid? ledgerPrefix.ledger height opening with
        | none => simp [paid] at updated
        | some amount =>
            simp only [paid, Option.some.injEq] at updated
            subst next
            rfl
  · cases coinbase with
    | none =>
        simp [checkedSourceCoinbasePrefixAfter] at updated
        subst next
        simp [sourceCoinbaseOpenings]
    | some pair =>
        rcases pair with ⟨height, opening⟩
        simp only [checkedSourceCoinbasePrefixAfter] at updated
        cases paid : checkedSourceCoinbasePaid? ledgerPrefix.ledger height opening with
        | none => simp [paid] at updated
        | some amount =>
            simp only [paid, Option.some.injEq] at updated
            subst next
            rfl

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- The trailing coinbase action is collision-free against the same whole
block registry: its checker-derived opening function is just the selected
native append log at every output position. -/
theorem checked_coinbase_plan_no_collision
    (initial current : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult initial.snapshot.parent
      initial.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase)
    (past : List V8NoteOpening)
    (stagedEq : current.stagedOpenings = initial.stagedOpenings ++ past)
    (suffixEq : result.openingsAdded = past ++ sourceCoinbaseOpenings coinbase)
    (action : Action) (after : Ledger)
    (checked : sourceCoinbasePlan current [] coinbase = some (action, after)) :
    ¬ badCollision (selectedBlockLedgerRegistry initial result) action := by
  cases coinbase with
  | none =>
      simp only [sourceCoinbasePlan] at checked
      have pairEq := Option.some.inj checked
      rcases pairEq with ⟨rfl, rfl⟩
      simp [badCollision]
  | some candidate =>
      rcases candidate with ⟨height, opening⟩
      simp only [sourceCoinbasePlan] at checked
      cases paidEq : checkedSourceCoinbasePaid? current.ledger height opening with
      | none => simp [paidEq] at checked
      | some paid =>
          simp only [paidEq] at checked
          have pairEq := Option.some.inj checked
          rcases pairEq with ⟨rfl, rfl⟩
          have registryEq := source_coinbase_registry_is_block_registry
            initial current result past stagedEq suffixEq
          intro collision
          simp only [badCollision] at collision
          rcases collision with ⟨position, _member, noteBad⟩
          have openingEq :
              sourceCoinbaseRegistry current [] (some (height, opening)) position =
                selectedBlockLedgerRegistry initial result position :=
            congrFun registryEq position
          exact noteBad.1 (by rw [openingEq])

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- A completed selector fold, followed by its checked trailing coinbase,
is one current finite-ledger execution. The same block result then rebases
the native snapshot to the complete transaction-plus-coinbase opening log. -/
theorem selected_block_execution_and_rebase_of_plan
    (initial : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult initial.snapshot.parent
      initial.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase)
    {actions : List Action} {final : CurrentSourceLedgerPrefix}
    (fold : CurrentSelectedRunFold (selectedBlockLedgerRegistry initial result)
      (sourceCoinbaseOpenings coinbase) initial result.runs actions final .complete)
    (boundary : initial.stagedOpenings = initial.snapshot.openings)
    (coinbasePlan : ∃ action after,
      sourceCoinbasePlan final [] coinbase = some (action, after)) :
    ∃ (coinbaseAction : Action) (after : Ledger)
      (afterPrefix rebased : CurrentSourceLedgerPrefix),
      sourceCoinbasePlan final [] coinbase = some (coinbaseAction, after) ∧
      CurrentExecution (program := SmzaRp05Components.program)
        (primitives := rustV8SemanticPrimitives)
        (registry := selectedBlockLedgerRegistry initial result)
        initial.ledger (actions ++ [coinbaseAction]) after ∧
      (∀ action ∈ actions ++ [coinbaseAction],
        ¬ badCollision (selectedBlockLedgerRegistry initial result) action) ∧
      checkedSourceCoinbasePrefixAfter final coinbase = some afterPrefix ∧
      afterPrefix.ledger = after ∧
      ∃ snapshotEq : afterPrefix.snapshot.openings = initial.snapshot.openings,
        ∃ stagedEq : afterPrefix.stagedOpenings =
          initial.snapshot.openings ++ result.openingsAdded,
          rebased = HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block initial afterPrefix result
              snapshotEq stagedEq := by
  rcases coinbasePlan with ⟨coinbaseAction, after, coinbasePlanProof⟩
  have stagedFinal := selected_run_fold_staged fold
  have suffixEq : result.openingsAdded =
      selectedRunOpeningStream result.runs ++ sourceCoinbaseOpenings coinbase := by
    simpa using selected_block_openings_decompose initial result
  have coinbaseStep := checked_coinbase_plan_block_step initial final result
    (selectedRunOpeningStream result.runs) stagedFinal suffixEq
    coinbaseAction after coinbasePlanProof
  rcases checked_coinbase_update_snapshot final coinbase coinbaseAction after
      coinbasePlanProof with ⟨afterPrefix, updateEq, ledgerEq,
        afterSnapshot, afterStaged⟩
  have snapshotEq : afterPrefix.snapshot.openings = initial.snapshot.openings :=
    congrArg (fun snapshot : CurrentNativeSnapshot => snapshot.openings)
      (afterSnapshot.trans (selected_run_fold_snapshot fold))
  have stagedEq : afterPrefix.stagedOpenings =
      initial.snapshot.openings ++ result.openingsAdded := by
    calc
      afterPrefix.stagedOpenings =
          final.stagedOpenings ++ sourceCoinbaseOpenings coinbase := afterStaged
      _ = (initial.stagedOpenings ++ selectedRunOpeningStream result.runs) ++
          sourceCoinbaseOpenings coinbase := by rw [stagedFinal]
      _ = initial.snapshot.openings ++ result.openingsAdded := by
        rw [boundary, suffixEq]
        simp [List.append_assoc]
  refine ⟨coinbaseAction, after, afterPrefix,
    HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block initial afterPrefix result snapshotEq stagedEq,
    coinbasePlanProof, ?_, ?_, updateEq, ledgerEq, ?_⟩
  · exact current_execution_append_step
      (selected_run_fold_execution fold) coinbaseStep
  · intro action member
    rcases List.mem_append.mp member with earlier | trailing
    · exact selected_run_fold_no_collision fold action earlier
    · simp only [List.mem_singleton] at trailing
      subst action
      exact checked_coinbase_plan_no_collision initial final result
        (selectedRunOpeningStream result.runs) stagedFinal suffixEq
        coinbaseAction after coinbasePlanProof
  · exact ⟨snapshotEq, stagedEq, rfl⟩

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- The actual-history coinbase checker, together with the exact fee and
issued-height equations of the completed source fold, determines the source
ledger coinbase plan.  No caller-supplied coinbase plan or security
conclusion is needed. -/
theorem selected_block_plan_of_actual_checker
    (initial : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult initial.snapshot.parent
      initial.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase)
    {actions : List Action} {final : CurrentSourceLedgerPrefix}
    (fold : CurrentSelectedRunFold (selectedBlockLedgerRegistry initial result)
      (sourceCoinbaseOpenings coinbase) initial result.runs actions final .complete)
    (paid : Nat)
    (actualChecker : coinbasePaid?
      (currentSupplyCheckState initial.ledger)
      (selectedDesignatedRuns result.runs) coinbase = some paid) :
    ∃ action after,
      sourceCoinbasePlan final [] coinbase = some (action, after) := by
  cases coinbase with
  | none =>
      exact ⟨.noCoinbase, burnEscrow final.ledger, by
        simp [sourceCoinbasePlan]⟩
  | some candidate =>
      rcases candidate with ⟨height, opening⟩
      have fees := selected_run_fold_fee_escrow fold
      have issued := selected_run_fold_issued_heights fold
      have checkerEq :
          coinbasePaid? (currentSupplyCheckState initial.ledger)
              (selectedDesignatedRuns result.runs) (some (height, opening)) =
            checkedSourceCoinbasePaid? final.ledger height opening := by
        unfold coinbasePaid? checkedSourceCoinbasePaid? currentSupplyCheckState
        rw [fees, issued]
        simp only [coinbaseOpeningCanonical]
        by_cases once : height ∉ initial.ledger.issuedHeights
        · by_cases positive : 0 < height
          · cases amountEq : nativeCoinbaseAmount height
                (initial.ledger.feeEscrow +
                  HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedHistorySupplyEndpoint.blockFees
                    (selectedDesignatedRuns result.runs)) with
            | none => simp [once, positive]
            | some amount =>
                by_cases value : nativeValue opening = amount
                · by_cases asset : opening.assetId = nativeAssetId
                  · by_cases canonical :
                      Hegemon.Transaction.Poseidon2V8SemanticSpecification.CanonicalNoteOpening
                        opening
                    · simp [once, positive, value, asset, canonical]
                    · simp [once, positive, value, asset, canonical]
                  · simp [once, positive, value, asset]
                · simp [once, positive, value]
          · simp [once, positive]
        · simp [once]
      have checked : checkedSourceCoinbasePaid? final.ledger height opening =
          some paid := by
        rw [← checkerEq]
        exact actualChecker
      refine ⟨.coinbase height paid
          (appendedOutputIds final.stagedOpenings [opening])
          (sourceCoinbaseRegistry final [] (some (height, opening))),
        applyCoinbase final.ledger height
          (appendedOutputIds final.stagedOpenings [opening]), ?_⟩
      simp [sourceCoinbasePlan, checked]

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- Completed source execution and native block replay joined at the actual
history endpoint.  The caller supplies the native replay equality and the
existing executable supply-check result; the source plan is derived above
from those facts and the internally proved chronological fee/height state. -/
theorem selected_block_execution_and_rebase
    (initial : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult initial.snapshot.parent
      initial.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) stages) coinbase)
    (nativeReplay : executeSelectedCurrentBlock initial stages coinbase = .ok result)
    {actions : List Action} {final : CurrentSourceLedgerPrefix}
    (fold : CurrentSelectedRunFold (selectedBlockLedgerRegistry initial result)
      (sourceCoinbaseOpenings coinbase) initial result.runs actions final .complete)
    (boundary : initial.stagedOpenings = initial.snapshot.openings)
    (paid : Nat)
    (actualChecker : coinbasePaid?
      (currentSupplyCheckState initial.ledger)
      (selectedDesignatedRuns result.runs) coinbase = some paid)
    :
    executeSelectedCurrentBlock initial stages coinbase = .ok result ∧
    ∃ (coinbaseAction : Action) (after : Ledger)
      (afterPrefix rebased : CurrentSourceLedgerPrefix),
      sourceCoinbasePlan final [] coinbase = some (coinbaseAction, after) ∧
      CurrentExecution (program := SmzaRp05Components.program)
        (primitives := rustV8SemanticPrimitives)
        (registry := selectedBlockLedgerRegistry initial result)
        initial.ledger (actions ++ [coinbaseAction]) after ∧
      (∀ action ∈ actions ++ [coinbaseAction],
        ¬ badCollision (selectedBlockLedgerRegistry initial result) action) ∧
      checkedSourceCoinbasePrefixAfter final coinbase = some afterPrefix ∧
      afterPrefix.ledger = after ∧
      ∃ snapshotEq : afterPrefix.snapshot.openings = initial.snapshot.openings,
        ∃ stagedEq : afterPrefix.stagedOpenings =
          initial.snapshot.openings ++ result.openingsAdded,
          rebased = HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block initial afterPrefix result
              snapshotEq stagedEq := by
  have plan := selected_block_plan_of_actual_checker initial result fold paid
    actualChecker
  rcases plan with ⟨coinbaseAction, after, planEq⟩
  rcases selected_block_execution_and_rebase_of_plan initial result fold
      boundary ⟨coinbaseAction, after, planEq⟩ with
    ⟨coinbaseAction, after, afterPrefix, rebased, planEq, execution,
      allNoCollision, updateEq, ledgerEq, rebaseEq⟩
  have stagedFinal := selected_run_fold_staged fold
  have suffixEq : result.openingsAdded =
      selectedRunOpeningStream result.runs ++ sourceCoinbaseOpenings coinbase := by
    simpa using selected_block_openings_decompose initial result
  have coinbaseNoCollision := checked_coinbase_plan_no_collision initial final
    result (selectedRunOpeningStream result.runs) stagedFinal suffixEq
    coinbaseAction after planEq
  have allNoCollision : ∀ action ∈ actions ++ [coinbaseAction],
      ¬ badCollision (selectedBlockLedgerRegistry initial result) action := by
    intro action member
    rcases List.mem_append.mp member with earlier | trailing
    · exact selected_run_fold_no_collision fold action earlier
    · simp only [List.mem_singleton] at trailing
      subst action
      exact coinbaseNoCollision
  exact ⟨nativeReplay, coinbaseAction, after, afterPrefix, rebased, planEq,
    execution, allNoCollision, updateEq, ledgerEq, rebaseEq⟩

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- A successful current block preserves the internal potential/allowance
invariant of its source prefix and has the finite-ledger lifetime cap.
Registry extension, the complete selected-run fold, checked coinbase and
exact native rebase are all tied to this same block result. -/
theorem selected_block_actual_lifetime_cap
    (initial : CurrentSourceLedgerPrefix)
    {stages : List (CurrentSelectedStage (BaseWork := BaseWork))}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult
      initial.snapshot.parent
      initial.spentNullifiers
      (selectedTransactions (BaseWork := BaseWork) stages) coinbase)
    (nativeReplay : executeSelectedCurrentBlock initial
      stages coinbase = .ok result)
    {actions : List Action} {final : CurrentSourceLedgerPrefix}
    (fold : CurrentSelectedRunFold
      (selectedBlockLedgerRegistry initial result)
      (sourceCoinbaseOpenings coinbase) initial
      result.runs actions final .complete)
    (paid : Nat)
    (actualChecker : coinbasePaid?
      (currentSupplyCheckState initial.ledger)
      (selectedDesignatedRuns result.runs) coinbase = some paid)
    (boundary : initial.stagedOpenings = initial.snapshot.openings)
    (historyInvariant : potential (openingAt initial.stagedOpenings)
      initial.ledger ≤ allowance initial.ledger) :
    ∃ (coinbaseAction : Action) (after : Ledger)
      (afterPrefix rebased : CurrentSourceLedgerPrefix),
      executeSelectedCurrentBlock initial stages coinbase =
        .ok result ∧
      sourceCoinbasePlan final [] coinbase = some (coinbaseAction, after) ∧
      CurrentExecution (program := SmzaRp05Components.program)
        (primitives := rustV8SemanticPrimitives)
        (registry := selectedBlockLedgerRegistry
          initial result)
        initial.ledger (actions ++ [coinbaseAction]) after ∧
      (∀ action ∈ actions ++ [coinbaseAction],
        ¬ badCollision (selectedBlockLedgerRegistry initial result) action) ∧
      checkedSourceCoinbasePrefixAfter final coinbase = some afterPrefix ∧
      afterPrefix.ledger = after ∧
      (∃ snapshotEq : afterPrefix.snapshot.openings =
          initial.snapshot.openings,
        ∃ stagedEq : afterPrefix.stagedOpenings =
          initial.snapshot.openings ++ result.openingsAdded,
          rebased = HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block initial afterPrefix
              result snapshotEq stagedEq) ∧
      wealth (selectedBlockLedgerRegistry initial result) after.live ≤
        maxMonetarySupply ∧
      potential (openingAt rebased.stagedOpenings) rebased.ledger ≤
        allowance rebased.ledger := by
  rcases selected_block_execution_and_rebase initial
      result nativeReplay fold boundary paid actualChecker with
    ⟨replayEq, coinbaseAction, after, afterPrefix, rebased, planEq,
      execution, good, updateEq, ledgerEq, rebaseWitness⟩
  rcases rebaseWitness with ⟨snapshotEq, stagedEq, rebaseEq⟩
  have genesis :
      potential (selectedBlockLedgerRegistry initial result) initial.ledger ≤
        0 + allowance initial.ledger := by
    change potential (openingAt (initial.stagedOpenings ++ result.openingsAdded))
      initial.ledger ≤ 0 + allowance initial.ledger
    rw [source_potential_registry_extension initial result.openingsAdded]
    simpa using historyInvariant
  have cap := current_deterministic_lifetime_cap execution good genesis
  have conserved := current_execution_supply_invariant execution good genesis
  have exactPotential :
      potential (openingAt rebased.stagedOpenings) rebased.ledger =
        potential (selectedBlockLedgerRegistry initial result) after := by
    rw [rebaseEq]
    change potential (openingAt
        (initial.snapshot.openings ++ result.openingsAdded)) afterPrefix.ledger =
      potential (openingAt
        (initial.stagedOpenings ++ result.openingsAdded)) after
    rw [ledgerEq, boundary]
  have rebasedLedgerEq : rebased.ledger = after := by
    calc
      rebased.ledger =
          (HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block
            initial afterPrefix result snapshotEq stagedEq).ledger :=
          congrArg (fun currentPrefix : CurrentSourceLedgerPrefix => currentPrefix.ledger)
            rebaseEq
      _ = afterPrefix.ledger := by
        simp [HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block]
      _ = after := ledgerEq
  have postInvariant : potential (openingAt rebased.stagedOpenings) rebased.ledger ≤
      allowance rebased.ledger := by
    rw [exactPotential, rebasedLedgerEq]
    simpa only [Nat.zero_add] using conserved
  refine ⟨coinbaseAction, after, afterPrefix, rebased,
    ⟨replayEq, planEq, execution, good, updateEq, ledgerEq,
      ⟨snapshotEq, stagedEq, rebaseEq⟩, ?_, postInvariant⟩⟩
  simpa using cap

/-! ## Whole-history runner

The history runner composes blocks from the empty native/finite-ledger
boundary. It invokes each native block executor itself, chooses only the
fold witness already proved to exist for that exact successful native result,
and stops at the first native, source-input, or source-coinbase failure.
-/

/-- One native block's selected transaction stages and optional trailing
coinbase. -/
structure CurrentSelectedBlock where
  stages : List (CurrentSelectedStage (BaseWork := BaseWork))
  coinbase : Option (Nat × V8NoteOpening)

/-- A checked, complete block receipt generated inside the recursive runner.
All transition actions, checks, and the native rebase are tied to the same
block result and same selected run fold. -/
structure CurrentSelectedBlockReceipt
    (before after : CurrentSourceLedgerPrefix) where
  block : CurrentSelectedBlock (BaseWork := BaseWork)
  result : CurrentBlockReplayResult before.snapshot.parent before.spentNullifiers
    (selectedTransactions (BaseWork := BaseWork) block.stages) block.coinbase
  nativeReplay : executeSelectedCurrentBlock before block.stages block.coinbase =
    .ok result
  actions : List Action
  finalLedgerPrefix : CurrentSourceLedgerPrefix
  fold : CurrentSelectedRunFold (selectedBlockLedgerRegistry before result)
    (sourceCoinbaseOpenings block.coinbase) before result.runs actions
      finalLedgerPrefix .complete
  paid : Nat
  actualChecker : coinbasePaid? (currentSupplyCheckState before.ledger)
    (selectedDesignatedRuns result.runs) block.coinbase = some paid
  coinbaseAction : Action
  afterLedger : Ledger
  afterPrefix : CurrentSourceLedgerPrefix
  plan : sourceCoinbasePlan finalLedgerPrefix [] block.coinbase =
    some (coinbaseAction, afterLedger)
  execution : CurrentExecution (program := SmzaRp05Components.program)
    (primitives := rustV8SemanticPrimitives)
    (registry := selectedBlockLedgerRegistry before result)
    before.ledger (actions ++ [coinbaseAction]) afterLedger
  noCollision : ∀ action ∈ actions ++ [coinbaseAction],
    ¬ badCollision (selectedBlockLedgerRegistry before result) action
  updater : checkedSourceCoinbasePrefixAfter finalLedgerPrefix block.coinbase =
    some afterPrefix
  afterLedgerEq : afterPrefix.ledger = afterLedger
  snapshotEq : afterPrefix.snapshot.openings = before.snapshot.openings
  stagedEq : afterPrefix.stagedOpenings =
    before.snapshot.openings ++ result.openingsAdded
  rebaseEq : after = HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block before afterPrefix result snapshotEq stagedEq
  lifetimeCap : wealth (selectedBlockLedgerRegistry before result)
    afterLedger.live ≤ maxMonetarySupply
  historyInvariant : potential (openingAt after.stagedOpenings) after.ledger ≤
    allowance after.ledger

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- A complete receipt's rebased native/source fields are the exact public
block projection: native frontier and ordered nullifiers come from the native
replay; fee settlement and height insertion come from its proved checker-plan
and transaction fold. -/
theorem selected_block_receipt_source_projection
    {before after : CurrentSourceLedgerPrefix}
    (receipt : CurrentSelectedBlockReceipt (BaseWork := BaseWork) before after) :
    after.snapshot.parent = receipt.result.nativeAfter ∧
    after.spentNullifiers = before.spentNullifiers ++
      blockNullifiers receipt.result.runs ∧
    after.ledger.feeEscrow = 0 ∧
    after.ledger.issuedHeights = match receipt.block.coinbase with
      | none => before.ledger.issuedHeights
      | some (height, _) => insert height before.ledger.issuedHeights := by
  have foldSpent := selected_run_fold_spent_nullifiers receipt.fold
  have foldIssued := selected_run_fold_issued_heights receipt.fold
  have planFields := source_coinbase_plan_public_fields receipt.finalLedgerPrefix
    receipt.block.coinbase receipt.coinbaseAction receipt.afterLedger receipt.plan
  have spentUpdate := checked_coinbase_prefix_spent_nullifiers
    receipt.finalLedgerPrefix receipt.afterPrefix receipt.block.coinbase receipt.updater
  have parentProjection := congrArg
    (fun currentPrefix : CurrentSourceLedgerPrefix => currentPrefix.snapshot.parent)
    receipt.rebaseEq
  have spentProjection := congrArg
    (fun currentPrefix : CurrentSourceLedgerPrefix => currentPrefix.spentNullifiers)
    receipt.rebaseEq
  have ledgerProjection := congrArg
    (fun currentPrefix : CurrentSourceLedgerPrefix => currentPrefix.ledger)
    receipt.rebaseEq
  have ledgerAfterPrefix : after.ledger = receipt.afterPrefix.ledger := by
    simpa [HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block]
      using ledgerProjection
  have afterLedgerProjection : after.ledger = receipt.afterLedger :=
    ledgerAfterPrefix.trans receipt.afterLedgerEq
  constructor
  · simpa [HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block]
      using parentProjection
  constructor
  · simpa [HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block,
      spentUpdate, foldSpent] using spentProjection
  constructor
  · exact (congrArg (fun ledger : Ledger => ledger.feeEscrow)
      afterLedgerProjection).trans planFields.1
  · cases coinbaseEq : receipt.block.coinbase with
    | none =>
        have planNone : sourceCoinbasePlan receipt.finalLedgerPrefix [] none =
            some (receipt.coinbaseAction, receipt.afterLedger) := by
          simpa only [coinbaseEq] using receipt.plan
        have fields := source_coinbase_plan_public_fields
          receipt.finalLedgerPrefix none receipt.coinbaseAction
          receipt.afterLedger planNone
        simpa only [foldIssued] using
          (congrArg (fun ledger : Ledger => ledger.issuedHeights)
            afterLedgerProjection).trans fields.2
    | some pair =>
        rcases pair with ⟨height, opening⟩
        have planSome : sourceCoinbasePlan receipt.finalLedgerPrefix []
            (some (height, opening)) =
              some (receipt.coinbaseAction, receipt.afterLedger) := by
          simpa only [coinbaseEq] using receipt.plan
        have fields := source_coinbase_plan_public_fields
          receipt.finalLedgerPrefix (some (height, opening))
          receipt.coinbaseAction receipt.afterLedger planSome
        simpa only [foldIssued] using
          (congrArg (fun ledger : Ledger => ledger.issuedHeights)
            afterLedgerProjection).trans fields.2

/-- Exact chronological block receipts from the input prefix to the final
prefix. -/
inductive CurrentSelectedHistoryTrace :
    List (CurrentSelectedBlock (BaseWork := BaseWork)) →
    CurrentSourceLedgerPrefix → CurrentSourceLedgerPrefix → Type where
  | nil (ledgerPrefix : CurrentSourceLedgerPrefix) :
      CurrentSelectedHistoryTrace [] ledgerPrefix ledgerPrefix
  | cons {tail : List (CurrentSelectedBlock (BaseWork := BaseWork))}
      {before middle final : CurrentSourceLedgerPrefix}
      (receipt : CurrentSelectedBlockReceipt (BaseWork := BaseWork) before middle)
      (rest : CurrentSelectedHistoryTrace tail middle final) :
      CurrentSelectedHistoryTrace
        (receipt.block :: tail) before final

/-! A history failure is tied to the exact executor, fold, or issuance-checker
result at the first unsuccessful block. -/

inductive CurrentSelectedHistoryFailure
    (before : CurrentSourceLedgerPrefix)
    (block : CurrentSelectedBlock (BaseWork := BaseWork)) : Type where
  | native (failure : CurrentBlockError)
      (actual : executeSelectedCurrentBlock before block.stages block.coinbase =
        .error failure) :
          CurrentSelectedHistoryFailure before block
  | sourceInput
      (result : CurrentBlockReplayResult before.snapshot.parent before.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) block.stages) block.coinbase)
      (native : executeSelectedCurrentBlock before block.stages block.coinbase =
        .ok result)
      {actions : List Action} {final : CurrentSourceLedgerPrefix}
      {ledgerPrefix : CurrentSourceLedgerPrefix}
      {envelope : CurrentRunEnvelope}
      (failure : CurrentRunChargedFailure ledgerPrefix envelope)
      (fold : CurrentSelectedRunFold (selectedBlockLedgerRegistry before result)
        (sourceCoinbaseOpenings block.coinbase) before result.runs actions final
          (.chargedFailure failure)) :
          CurrentSelectedHistoryFailure before block
  | coinbase
      (result : CurrentBlockReplayResult before.snapshot.parent before.spentNullifiers
        (selectedTransactions (BaseWork := BaseWork) block.stages) block.coinbase)
      (native : executeSelectedCurrentBlock before block.stages block.coinbase =
        .ok result)
      {actions : List Action} {final : CurrentSourceLedgerPrefix}
      (fold : CurrentSelectedRunFold (selectedBlockLedgerRegistry before result)
        (sourceCoinbaseOpenings block.coinbase) before result.runs actions final
          .complete)
      (checker : coinbasePaid? (currentSupplyCheckState before.ledger)
        (selectedDesignatedRuns result.runs) block.coinbase = none) :
      CurrentSelectedHistoryFailure before block

/-! The result records every completed block and, on failure, the exact first
failing block after that successful prefix. -/

inductive CurrentSelectedHistoryOutcome :
    List (CurrentSelectedBlock (BaseWork := BaseWork)) →
    CurrentSourceLedgerPrefix → Type where
  | complete {blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))}
      {initial final : CurrentSourceLedgerPrefix}
      (trace : CurrentSelectedHistoryTrace blocks initial final)
      (boundary : final.stagedOpenings = final.snapshot.openings)
      (historyInvariant : potential (openingAt final.stagedOpenings)
        final.ledger ≤ allowance final.ledger) :
      CurrentSelectedHistoryOutcome blocks initial
  | failed {done tail : List (CurrentSelectedBlock (BaseWork := BaseWork))}
      {initial before : CurrentSourceLedgerPrefix}
      (trace : CurrentSelectedHistoryTrace done initial before)
      (block : CurrentSelectedBlock (BaseWork := BaseWork))
      (failure : CurrentSelectedHistoryFailure before block) :
      CurrentSelectedHistoryOutcome
        (done ++ block :: tail) initial

private def prependSelectedHistoryOutcome
    {blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))}
    {initial middle : CurrentSourceLedgerPrefix}
    (receipt : CurrentSelectedBlockReceipt
      (BaseWork := BaseWork) initial middle)
    (rest : CurrentSelectedHistoryOutcome blocks middle) :
    CurrentSelectedHistoryOutcome (receipt.block :: blocks) initial := by
  cases rest with
  | complete trace boundary historyInvariant =>
      exact .complete (.cons receipt trace) boundary historyInvariant
  | failed trace block failure =>
      exact .failed (.cons receipt trace) block failure

omit [Fintype BaseWork] [DecidableEq BaseWork] in
theorem selected_history_invariant_implies_live_cap
    {_blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))}
    {final : CurrentSourceLedgerPrefix}
    (historyInvariant : potential (openingAt final.stagedOpenings)
      final.ledger ≤ allowance final.ledger) :
    wealth (openingAt final.stagedOpenings) final.ledger.live ≤
      maxMonetarySupply := by
  have issued := current_lifetime_issuance_bound final.ledger
  unfold potential at historyInvariant
  omega

/-! Recursive selected-history executor. Each next prefix is obtained only
from the exact native replay, complete selected-run fold, successful actual
coinbase checker, and native rebase for that block. The returned trace is
therefore generated by this recursion rather than supplied by a caller. -/

noncomputable def executeSelectedCurrentHistory :
    (blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))) →
      (initial : CurrentSourceLedgerPrefix) →
      (boundary : initial.stagedOpenings = initial.snapshot.openings) →
      (historyInvariant : potential (openingAt initial.stagedOpenings)
        initial.ledger ≤ allowance initial.ledger) →
        CurrentSelectedHistoryOutcome blocks initial
  | [], initial, boundary, historyInvariant =>
      .complete (.nil initial) boundary historyInvariant
  | block :: tail, initial, boundary, historyInvariant => by
      classical
      cases replay : executeSelectedCurrentBlock initial block.stages block.coinbase with
      | error error =>
          exact .failed (.nil initial) block (.native error replay)
      | ok result =>
          have native : executeSelectedCurrentBlock initial block.stages block.coinbase =
              .ok result := replay
          let foldExists := selected_block_fold_from_boundary initial result
          let actions := Classical.choose foldExists
          let final := Classical.choose (Classical.choose_spec foldExists)
          let fold := Classical.choose_spec
            (Classical.choose_spec (Classical.choose_spec foldExists))
          cases outcomeEq : Classical.choose
              (Classical.choose_spec (Classical.choose_spec foldExists)) with
          | chargedFailure failure =>
              have failureFold : CurrentSelectedRunFold
                  (selectedBlockLedgerRegistry initial result)
                  (sourceCoinbaseOpenings block.coinbase) initial
                  result.runs actions final (.chargedFailure failure) := by
                simpa only [actions, final, outcomeEq] using fold
              exact .failed (.nil initial) block
                (.sourceInput result native failure failureFold)
          | complete =>
              have completeFold : CurrentSelectedRunFold
                  (selectedBlockLedgerRegistry initial result)
                  (sourceCoinbaseOpenings block.coinbase) initial
                  result.runs actions final .complete := by
                simpa only [actions, final, outcomeEq] using fold
              cases checker : coinbasePaid? (currentSupplyCheckState initial.ledger)
                  (selectedDesignatedRuns result.runs) block.coinbase with
              | none =>
                  exact .failed (.nil initial) block
                    (.coinbase result native completeFold checker)
              | some paid =>
                  let capExists := selected_block_actual_lifetime_cap initial result
                    native completeFold paid checker boundary historyInvariant
                  let coinbaseAction := Classical.choose capExists
                  let after := Classical.choose (Classical.choose_spec capExists)
                  let afterPrefix := Classical.choose
                    (Classical.choose_spec (Classical.choose_spec capExists))
                  let rebased := Classical.choose
                    (Classical.choose_spec
                      (Classical.choose_spec (Classical.choose_spec capExists)))
                  have capFacts := Classical.choose_spec
                    (Classical.choose_spec
                      (Classical.choose_spec (Classical.choose_spec capExists)))
                  rcases capFacts with
                    ⟨replayEq, planEq, execution, noCollision, updater,
                      afterLedgerEq, rebaseWitness, ⟨cap, nextInvariant⟩⟩
                  let snapshotEq := Classical.choose rebaseWitness
                  let stagedEq := Classical.choose (Classical.choose_spec rebaseWitness)
                  let rebaseEq := Classical.choose_spec
                    (Classical.choose_spec rebaseWitness)
                  have nextBoundary : rebased.stagedOpenings = rebased.snapshot.openings := by
                    have stagedProjection := congrArg
                      (fun currentPrefix : CurrentSourceLedgerPrefix =>
                        currentPrefix.stagedOpenings) rebaseEq
                    have snapshotProjection := congrArg
                      (fun currentPrefix : CurrentSourceLedgerPrefix =>
                        currentPrefix.snapshot.openings) rebaseEq
                    calc
                      rebased.stagedOpenings =
                          (HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block
                            initial afterPrefix result snapshotEq stagedEq).stagedOpenings :=
                        stagedProjection
                      _ = (HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block
                            initial afterPrefix result snapshotEq stagedEq).snapshot.openings := by
                        simp [HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore.rebase_prefix_after_block]
                      _ = rebased.snapshot.openings := snapshotProjection.symm
                  let receipt : CurrentSelectedBlockReceipt
                      (BaseWork := BaseWork) initial rebased := {
                    block := block
                    result := result
                    nativeReplay := replayEq
                    actions := actions
                    finalLedgerPrefix := final
                    fold := completeFold
                    paid := paid
                    actualChecker := checker
                    coinbaseAction := coinbaseAction
                    afterLedger := after
                    afterPrefix := afterPrefix
                    plan := planEq
                    execution := execution
                    noCollision := noCollision
                    updater := updater
                    afterLedgerEq := afterLedgerEq
                    snapshotEq := snapshotEq
                    stagedEq := stagedEq
                    rebaseEq := rebaseEq
                    lifetimeCap := cap
                    historyInvariant := nextInvariant }
                  exact prependSelectedHistoryOutcome receipt
                    (executeSelectedCurrentHistory tail rebased nextBoundary
                      nextInvariant)
  termination_by blocks _initial _boundary _historyInvariant => blocks.length
  decreasing_by
    simp_wf

/-! Public endpoint from the exact empty native/finite-ledger boundary. The
potential and boundary premises are derived internally, never supplied by a
caller. -/

noncomputable def executeSelectedCurrentHistoryFromGenesis
    (blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))) :
      CurrentSelectedHistoryOutcome blocks
        initialCurrentSourceLedgerPrefix := by
  have boundary : initialCurrentSourceLedgerPrefix.stagedOpenings =
      initialCurrentSourceLedgerPrefix.snapshot.openings := rfl
  have invariant : potential (openingAt
      initialCurrentSourceLedgerPrefix.stagedOpenings)
      initialCurrentSourceLedgerPrefix.ledger ≤
        allowance initialCurrentSourceLedgerPrefix.ledger := by
    have potentialZero := initial_source_potential_zero []
    have allowanceZero := initial_source_allowance_zero
    change potential (openingAt
        (initialCurrentSourceLedgerPrefix.stagedOpenings ++ []))
        initialCurrentSourceLedgerPrefix.ledger ≤
      allowance initialCurrentSourceLedgerPrefix.ledger
    rw [potentialZero, allowanceZero]
  exact executeSelectedCurrentHistory blocks initialCurrentSourceLedgerPrefix
    boundary invariant

/-! Classification is indexed by input blocks and carries an equality to the
actual executor value in each arm, preserving the exact first failure for
downstream frame correlation. -/
inductive CurrentSelectedHistoryClassification :
    (blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))) →
    (actual : CurrentSelectedHistoryOutcome blocks
      initialCurrentSourceLedgerPrefix) → Prop where
  | complete {blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))}
      {final : CurrentSourceLedgerPrefix}
      (trace : CurrentSelectedHistoryTrace blocks
        initialCurrentSourceLedgerPrefix final)
      (boundary : final.stagedOpenings = final.snapshot.openings)
      (historyInvariant : potential (openingAt final.stagedOpenings)
        final.ledger ≤ allowance final.ledger)
      (lifetimeCap : wealth (openingAt final.stagedOpenings)
        final.ledger.live ≤ maxMonetarySupply)
      (actualEq : executeSelectedCurrentHistoryFromGenesis blocks =
        .complete trace boundary historyInvariant) :
      CurrentSelectedHistoryClassification blocks
        (.complete trace boundary historyInvariant)
  | failed {done tail : List (CurrentSelectedBlock (BaseWork := BaseWork))}
      {before : CurrentSourceLedgerPrefix}
      (trace : CurrentSelectedHistoryTrace done
        initialCurrentSourceLedgerPrefix before)
      (block : CurrentSelectedBlock (BaseWork := BaseWork))
      (failure : CurrentSelectedHistoryFailure before block)
      (actualEq : executeSelectedCurrentHistoryFromGenesis (done ++ block :: tail) =
        .failed trace block failure) :
      CurrentSelectedHistoryClassification
        (done ++ block :: tail)
        (.failed trace block failure)

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- Exhaustive case theorem for the actual from-genesis executor. It cannot
report a successful endpoint without its generated complete trace and proved
lifetime cap, and its failure arm is the exact first failing block after the
retained successful prefix. -/
theorem executeSelectedCurrentHistoryFromGenesis_cases
    (blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))) :
    CurrentSelectedHistoryClassification blocks
      (executeSelectedCurrentHistoryFromGenesis blocks) := by
  cases result : executeSelectedCurrentHistoryFromGenesis blocks with
  | complete trace boundary invariant =>
      exact .complete trace boundary invariant
        (selected_history_invariant_implies_live_cap
          (BaseWork := BaseWork) (_blocks := blocks) invariant) result
  | failed trace block failure =>
      exact .failed trace block failure result

omit [Fintype BaseWork] [DecidableEq BaseWork] in
/-- A completed result from the public empty-genesis runner exposes the
generated final trace and invariant, which imply both a live-wealth cap at
the exact final staged registry and the final potential/allowance bound. -/
theorem executeSelectedCurrentHistoryFromGenesis_complete_cap
    (blocks : List (CurrentSelectedBlock (BaseWork := BaseWork)))
    (complete : ∃ (final : CurrentSourceLedgerPrefix)
      (trace : CurrentSelectedHistoryTrace blocks
        initialCurrentSourceLedgerPrefix final)
      (boundary : final.stagedOpenings = final.snapshot.openings)
      (invariant : potential (openingAt final.stagedOpenings) final.ledger ≤
        allowance final.ledger),
      executeSelectedCurrentHistoryFromGenesis blocks =
        .complete trace boundary invariant) :
    ∃ (final : CurrentSourceLedgerPrefix),
      wealth (openingAt final.stagedOpenings) final.ledger.live ≤
        maxMonetarySupply ∧
      potential (openingAt final.stagedOpenings) final.ledger ≤
        allowance final.ledger := by
  rcases complete with ⟨final, trace, boundary, invariant, resultEq⟩
  refine ⟨final, ?_, invariant⟩
  have issued := current_lifetime_issuance_bound final.ledger
  unfold potential at invariant
  omega

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRunner
