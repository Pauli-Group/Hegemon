import SmzaRp05CurrentSourceLedgerPrefix
import SmzaRp05CurrentSourceLedgerTransitions
import SmzaRp05SupplyClosureOutputHistory
import SmzaRp05SupplyClosureHistoricalInputs
import SmzaRp05Components
import SmzaRp05SupplyClosureCanonicalPaths
import SmzaRp05SupplyClosureInputNative
import SmzaRp05SupplyClosureDistinctInputs
import SmzaRp05GeneratedCertificates
import SmzaRp05RelationRefinement

/-! # Deterministic current-source block/output replay

This small executable layer resolves each chronological optional current
extraction, checks public pre-block anchors and nullifiers against the same
incoming snapshot, then appends the exact accepted output stream followed by
the optional coinbase opening. It is the native-history half of the finite
ledger adapter; no private-position or aggregate-wealth test is introduced.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSourceBlockReplay

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
  (CurrentSourceLedgerPrefix)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputHistory
open HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree
open HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureCanonicalPaths
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDistinctInputs
open HegemonCrypto.SmallWood.SmzaRp05GeneratedCertificates
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false

attribute [local irreducible]
  SmzaRp05GeneratedCertificates.currentDsl
  SmzaRp05RelationRefinement.candidate
  HegemonCrypto.SmallWood.SmzaRp05Components.program
  HegemonCrypto.SmallWood.SmzaRp05CurrentPublicStatementTransport.rustV8SemanticPrimitives
  SmzaQ38Recovery.packedFromRows
  HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked
  HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative.inputSlotNative
  HegemonCrypto.SmallWood.PiopExtraction.FullySatisfied
  HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.projectNote
  Hegemon.Transaction.Poseidon2V8SemanticSpecification.exactV8NoteWords
  HegemonCrypto.SmallWood.SmzaRp05HistoricalTree.openingAt

noncomputable section

/-- Existential package for one exact current designated decoder result. -/
structure CurrentRunEnvelope where
  preamble : Statement
  typedStatement : V8PublicStatement
  run : HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.CurrentSourceRun
    preamble typedStatement

/-- Every positive input in one designated run has either the exact
snapshot/live-ledger binding required by the finite transfer constructor, or
the named source path/authorization collision event. -/
def CurrentRunInputBindings (ledgerPrefix : CurrentSourceLedgerPrefix)
    (envelope : CurrentRunEnvelope)
    (_admitted : publicAnchor (encodePublicStatement envelope.typedStatement) ∈
      ledgerPrefix.snapshot.parent.history) : Prop :=
  ∀ input : Fin 2,
    (positive : 0 < inputSlotNative envelope.typedStatement
      (HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked
        envelope.run) input) →
      CurrentInputLedgerBinding ledgerPrefix envelope.run input

private theorem fin_two_cases (input : Fin 2) : input = 0 ∨ input = 1 := by
  fin_cases input <;> simp

def CurrentRunInputFailure (ledgerPrefix : CurrentSourceLedgerPrefix)
    (envelope : CurrentRunEnvelope)
    (admitted : publicAnchor (encodePublicStatement envelope.typedStatement) ∈
      ledgerPrefix.snapshot.parent.history) : Prop :=
  ∃ input : Fin 2,
    ∃ positive : 0 < inputSlotNative envelope.typedStatement
      (HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked
        envelope.run) input,
      CurrentInputChargedFailure
        ⟨envelope.preamble, envelope.typedStatement, envelope.run, input,
          positive, ledgerPrefix.snapshot, admitted⟩
        ledgerPrefix.snapshot ledgerPrefix.priorSpends

theorem run_inputs_binding_or_charged_failure
    (ledgerPrefix : CurrentSourceLedgerPrefix) (envelope : CurrentRunEnvelope)
    (admitted : publicAnchor (encodePublicStatement envelope.typedStatement) ∈
      ledgerPrefix.snapshot.parent.history)
    (fresh : HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions.sourceNullifiersFresh
      ledgerPrefix.spentNullifiers envelope.run = true) :
    CurrentRunInputBindings ledgerPrefix envelope admitted ∨
      CurrentRunInputFailure ledgerPrefix envelope admitted := by
  classical
  by_cases positive0 : 0 < inputSlotNative envelope.typedStatement
      (HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked
        envelope.run) (0 : Fin 2)
  · rcases positive_input_success_or_charged_failure ledgerPrefix envelope.run
        (0 : Fin 2) positive0 admitted fresh with binding0 | failure0
    · by_cases positive1 : 0 < inputSlotNative envelope.typedStatement
          (HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked
            envelope.run) (1 : Fin 2)
      · rcases positive_input_success_or_charged_failure ledgerPrefix envelope.run
            (1 : Fin 2) positive1 admitted fresh with binding1 | failure1
        · left
          intro input positive
          rcases fin_two_cases input with inputZero | inputOne
          · subst input
            exact binding0
          · subst input
            exact binding1
        · exact Or.inr ⟨1, positive1, failure1⟩
      · left
        intro input positive
        rcases fin_two_cases input with inputZero | inputOne
        · subst input
          exact binding0
        · subst input
          have positiveSlot : 0 < inputSlotNative envelope.typedStatement
              (HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked
                envelope.run) (1 : Fin 2) := by simpa using positive
          exact (positive1 positiveSlot).elim
    · exact Or.inr ⟨0, positive0, failure0⟩
  · by_cases positive1 : 0 < inputSlotNative envelope.typedStatement
        (HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked
          envelope.run) (1 : Fin 2)
    · rcases positive_input_success_or_charged_failure ledgerPrefix envelope.run
          (1 : Fin 2) positive1 admitted fresh with binding1 | failure1
      · left
        intro input positive
        rcases fin_two_cases input with inputZero | inputOne
        · subst input
          have positiveSlot : 0 < inputSlotNative envelope.typedStatement
              (HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked
                envelope.run) (0 : Fin 2) := by simpa using positive
          exact (positive0 positiveSlot).elim
        · subst input
          exact binding1
      · exact Or.inr ⟨1, positive1, failure1⟩
    · left
      intro input positive
      rcases fin_two_cases input with inputZero | inputOne
      · subst input
        have positiveSlot : 0 < inputSlotNative envelope.typedStatement
            (HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked
              envelope.run) (0 : Fin 2) := by simpa using positive
        exact (positive0 positiveSlot).elim
      · subst input
        have positiveSlot : 0 < inputSlotNative envelope.typedStatement
            (HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix.sourcePacked
              envelope.run) (1 : Fin 2) := by simpa using positive
        exact (positive1 positiveSlot).elim

def outputRecord (envelope : CurrentRunEnvelope) : AcceptedOutputRecord :=
  sourceOutputRecord envelope.run

def outputRecords (runs : List CurrentRunEnvelope) : List AcceptedOutputRecord :=
  runs.map outputRecord

/-- A missing designated extraction is a distinct, indexed execution failure. -/
inductive CurrentBlockError where
  | extractionFailure (transactionIndex : Nat)
  | rejectedAnchor (transactionIndex : Nat)
  | duplicateOrSpentNullifier
  | invalidCoinbase
  | appendCapacity
  deriving DecidableEq

def extractCurrentRuns : Nat → List (Option CurrentRunEnvelope) →
    Except CurrentBlockError (List CurrentRunEnvelope)
  | _, [] => .ok []
  | index, none :: _ => .error (.extractionFailure index)
  | index, some run :: rest => do
      let later ← extractCurrentRuns (index + 1) rest
      pure (run :: later)

def blockAnchorCheck (parent : FrontierState) (runs : List CurrentRunEnvelope) : Bool :=
  runs.all fun envelope => decide
    (publicAnchor (encodePublicStatement envelope.typedStatement) ∈ parent.history)

def firstRejectedAnchor (parent : FrontierState) :
    List CurrentRunEnvelope → Option Nat
  | [] => none
  | envelope :: rest =>
      if publicAnchor (encodePublicStatement envelope.typedStatement) ∈ parent.history then
        (firstRejectedAnchor parent rest).map Nat.succ
      else some 0

def blockNullifiers (runs : List CurrentRunEnvelope) : List Digest :=
  runs.flatMap fun envelope =>
    (List.finRange 2).filterMap fun input =>
      if (encodePublicStatement envelope.typedStatement).getD input.val 0 = 1 then
        some (publicNullifier (encodePublicStatement envelope.typedStatement) input)
      else none

def nullifiersFresh (spent : List Digest) (runs : List CurrentRunEnvelope) : Bool :=
  let additions := blockNullifiers runs
  additions.Nodup && additions.all (fun value => !(spent.contains value))

def blockCoinbaseCanonical : Option (Nat × V8NoteOpening) → Bool
  | none => true
  | some (_, opening) => decide (CanonicalNoteOpening opening)

private theorem exactWords_append {left right : List Nat} {leftCount rightCount : Nat}
    (leftExact : ExactWords leftCount left)
    (rightExact : ExactWords rightCount right) :
    ExactWords (leftCount + rightCount) (left ++ right) := by
  constructor
  · simp [leftExact.1, rightExact.1]
  · intro word member
    rcases List.mem_append.mp member with inLeft | inRight
    · exact leftExact.2 word inLeft
    · exact rightExact.2 word inRight

private theorem canonical_coinbase_words_exact (opening : V8NoteOpening)
    (canonical : CanonicalNoteOpening opening) :
    ExactWords 18 (exactV8NoteWords opening) := by
  have pairExact : ExactWords 2 [opening.value, opening.assetId] := by
    constructor
    · rfl
    · intro word member
      have member' : word = opening.value ∨ word = opening.assetId := by
        simpa using member
      rcases member' with value | asset
      · rw [value]
        exact Nat.lt_of_lt_of_le canonical.1 (by decide)
      · rw [asset]
        exact canonical.2.1
  have joined₁ := exactWords_append pairExact canonical.2.2.2.1
  have joined₂ := exactWords_append joined₁ canonical.2.2.2.2.2.1
  have joined₃ := exactWords_append joined₂ canonical.2.2.2.2.2.2
  have joined₄ := exactWords_append joined₃ canonical.2.2.2.2.1
  simpa [exactV8NoteWords, List.append_assoc] using joined₄

def blockCoinbaseOpening (coinbase : Option (Nat × V8NoteOpening)) :
    Option V8NoteOpening := coinbase.map Prod.snd

/-- This output contains both the updated native frontier and the exact
transaction-then-coinbase openings that produced it. -/
structure CurrentBlockReplayResult
    (parent : FrontierState) (spent : List Digest)
    (transactions : List (Option CurrentRunEnvelope))
    (coinbase : Option (Nat × V8NoteOpening)) where
  runs : List CurrentRunEnvelope
  extraction : extractCurrentRuns 0 transactions = .ok runs
  anchorsChecked : blockAnchorCheck parent runs = true
  nullifiersChecked : nullifiersFresh spent runs = true
  coinbaseChecked : blockCoinbaseCanonical coinbase = true
  nativeAfter : FrontierState
  openingsAdded : List V8NoteOpening
  openingsAddedEq : openingsAdded =
    blockOpeningStream (outputRecords runs) (blockCoinbaseOpening coinbase)
  appended : appendDigestStream parent
      (blockCommitmentStream (outputRecords runs)
        (blockCoinbaseOpening coinbase)) = some nativeAfter

/-- Deterministic source-order block execution. This checks only the public
frontier/nullifier and canonical-coinbase conditions consumed by native note
admission. Finite-ledger transfer and issuance transitions are layered on
this exact result by the current-source ledger replay. -/
def executeCurrentBlock (parent : FrontierState) (spent : List Digest)
    (transactions : List (Option CurrentRunEnvelope))
    (coinbase : Option (Nat × V8NoteOpening)) :
    Except CurrentBlockError (CurrentBlockReplayResult parent spent transactions coinbase) :=
  match extraction : extractCurrentRuns 0 transactions with
  | .error error => .error error
  | .ok runs => do
      if anchors : blockAnchorCheck parent runs = true then
        if fresh : nullifiersFresh spent runs = true then
          if coinbaseShape : blockCoinbaseCanonical coinbase = true then
            match appendProof : appendDigestStream parent
                (blockCommitmentStream (outputRecords runs)
                  (blockCoinbaseOpening coinbase)) with
            | none => throw .appendCapacity
            | some nativeAfter =>
                pure {
                  runs := runs
                  extraction := extraction
                  anchorsChecked := anchors
                  nullifiersChecked := fresh
                  coinbaseChecked := coinbaseShape
                  nativeAfter := nativeAfter
                  openingsAdded := blockOpeningStream (outputRecords runs)
                    (blockCoinbaseOpening coinbase)
                  openingsAddedEq := rfl
                  appended := appendProof
                }
          else throw .invalidCoinbase
        else throw .duplicateOrSpentNullifier
      else throw (.rejectedAnchor ((firstRejectedAnchor parent runs).getD 0))

theorem output_records_accepted (runs : List CurrentRunEnvelope) :
    ∀ record ∈ outputRecords runs,
      HegemonCrypto.SmallWood.SmzaRp05Components.program.AcceptsPacked
        record.1 record.2 := by
  intro record member
  rcases List.mem_map.mp member with ⟨envelope, _member, equal⟩
  cases equal
  exact (source_run_accepted envelope.run).2

theorem block_anchor_check_derives_membership
    (parent : FrontierState) (runs : List CurrentRunEnvelope)
    (checked : blockAnchorCheck parent runs = true)
    (envelope : CurrentRunEnvelope) (member : envelope ∈ runs) :
    publicAnchor (encodePublicStatement envelope.typedStatement) ∈ parent.history := by
  have each : ∀ candidate ∈ runs,
      decide (publicAnchor (encodePublicStatement candidate.typedStatement) ∈
        parent.history) = true := List.all_eq_true.mp checked
  exact of_decide_eq_true (each envelope member)

theorem nullifier_check_derives_freshness
    (spent : List Digest) (runs : List CurrentRunEnvelope)
    (checked : nullifiersFresh spent runs = true) :
    (blockNullifiers runs).Nodup ∧
      ∀ nullifier ∈ blockNullifiers runs, nullifier ∉ spent := by
  simp only [nullifiersFresh, Bool.and_eq_true, decide_eq_true_eq] at checked
  rcases checked with ⟨unique, allFresh⟩
  constructor
  · exact unique
  · intro nullifier member present
    have absent := (List.all_eq_true.mp allFresh) nullifier member
    have presentBool : spent.contains nullifier = true :=
      List.contains_iff_mem.mpr present
    rw [presentBool] at absent
    simp at absent

theorem successful_block_extends_opening_log
    {parent : FrontierState} {spent : List Digest}
    {transactions : List (Option CurrentRunEnvelope)}
    {coinbase : Option (Nat × V8NoteOpening)} (openings : List V8NoteOpening)
    (prior : NativeReplay parent (openings.map exactV8NoteCommitment))
    (result : CurrentBlockReplayResult parent spent transactions coinbase)
    (accepted : ∀ record ∈ outputRecords result.runs,
      HegemonCrypto.SmallWood.SmzaRp05Components.program.AcceptsPacked
        record.1 record.2) :
    NativeReplay result.nativeAfter
      ((openings ++ result.openingsAdded).map exactV8NoteCommitment) := by
  rw [result.openingsAddedEq]
  exact accepted_block_append_extends_opening_log openings prior
    (outputRecords result.runs) accepted
    (blockCoinbaseOpening coinbase) result.appended

structure CurrentSourceBlock where
  transactions : List (Option CurrentRunEnvelope)
  coinbase : Option (Nat × V8NoteOpening)

structure CurrentSourceHistoryState where
  native : FrontierState
  openings : List V8NoteOpening
  openingsCanonical : ∀ opening ∈ openings,
    ExactWords 18 (exactV8NoteWords opening)
  records : List AcceptedOutputRecord
  recordsAccepted : ∀ record ∈ records,
    HegemonCrypto.SmallWood.SmzaRp05Components.program.AcceptsPacked
      record.1 record.2
  spentNullifiers : List Digest
  replay : NativeReplay native (openings.map exactV8NoteCommitment)

def initialCurrentSourceHistoryState : CurrentSourceHistoryState where
  native := newEmpty
  openings := []
  openingsCanonical := by simp
  records := []
  recordsAccepted := by simp
  spentNullifiers := []
  replay := NativeReplay.start

theorem block_openings_canonical
    {parent : FrontierState} {spent : List Digest}
    {transactions : List (Option CurrentRunEnvelope)}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult parent spent transactions coinbase)
    (accepted : ∀ record ∈ outputRecords result.runs,
      HegemonCrypto.SmallWood.SmzaRp05Components.program.AcceptsPacked
        record.1 record.2) :
    ∀ opening ∈ result.openingsAdded,
      ExactWords 18 (exactV8NoteWords opening) := by
  rw [result.openingsAddedEq]
  intro opening member
  rcases List.mem_append.mp member with fromOutput | fromCoinbase
  · exact accepted_output_log_canonical (outputRecords result.runs) accepted
      opening fromOutput
  · cases coinbase with
    | none => simp [blockCoinbaseOpening] at fromCoinbase
    | some pair =>
        rcases pair with ⟨height, coinbaseOpening⟩
        have sameOpening : opening = coinbaseOpening := by
          simpa [blockCoinbaseOpening] using fromCoinbase
        subst opening
        have canonical : CanonicalNoteOpening coinbaseOpening := by
          have checked : decide (CanonicalNoteOpening coinbaseOpening) = true := by
            simpa [blockCoinbaseCanonical] using result.coinbaseChecked
          exact of_decide_eq_true checked
        exact canonical_coinbase_words_exact coinbaseOpening canonical

def updateCurrentSourceHistoryState
    (state : CurrentSourceHistoryState) (block : CurrentSourceBlock)
    (result : CurrentBlockReplayResult state.native state.spentNullifiers
      block.transactions block.coinbase) : CurrentSourceHistoryState := by
  let newRecords := outputRecords result.runs
  refine {
    native := result.nativeAfter
    openings := state.openings ++ result.openingsAdded
    openingsCanonical := ?_
    records := state.records ++ newRecords
    recordsAccepted := ?_
    spentNullifiers := state.spentNullifiers ++ blockNullifiers result.runs
    replay := ?_
  }
  · intro opening member
    rcases List.mem_append.mp member with old | added
    · exact state.openingsCanonical opening old
    · exact block_openings_canonical result
        (output_records_accepted result.runs) opening added
  · intro record member
    rcases List.mem_append.mp member with old | added
    · exact state.recordsAccepted record old
    · exact output_records_accepted result.runs record added
  · exact successful_block_extends_opening_log state.openings state.replay
      result (output_records_accepted result.runs)

/-- Full chronological execution. The first absent designated extraction,
public-anchor/nullifier rejection, noncanonical coinbase, or native append
capacity failure is preserved by `Except`; on success the single returned
history contains the transaction outputs and each trailing coinbase opening
in block order. -/
def executeCurrentSourceHistory : List CurrentSourceBlock →
    CurrentSourceHistoryState → Except CurrentBlockError CurrentSourceHistoryState
  | [], state => .ok state
  | block :: rest, state =>
      match executeCurrentBlock state.native state.spentNullifiers
          block.transactions block.coinbase with
      | .error error => .error error
      | .ok result =>
          executeCurrentSourceHistory rest
            (updateCurrentSourceHistoryState state block result)

theorem executeCurrentSourceHistory_empty (state : CurrentSourceHistoryState) :
    executeCurrentSourceHistory [] state = .ok state := rfl

theorem executeCurrentSourceHistory_success
    (blocks : List CurrentSourceBlock) (state result : CurrentSourceHistoryState)
    (success : executeCurrentSourceHistory blocks state = .ok result) :
    (∀ record ∈ result.records,
      HegemonCrypto.SmallWood.SmzaRp05Components.program.AcceptsPacked
        record.1 record.2) ∧
      NativeReplay result.native (result.openings.map exactV8NoteCommitment) := by
  induction blocks generalizing state result with
  | nil =>
      simp only [executeCurrentSourceHistory] at success
      cases success
      exact ⟨state.recordsAccepted, state.replay⟩
  | cons block rest ih =>
      simp only [executeCurrentSourceHistory] at success
      cases execution : executeCurrentBlock state.native state.spentNullifiers
          block.transactions block.coinbase with
      | error error => simp [execution] at success
      | ok blockResult =>
          simp only [execution] at success
          exact ih (updateCurrentSourceHistoryState state block blockResult)
            result success
