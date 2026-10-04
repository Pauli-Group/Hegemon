import SmzaRp05CurrentSourceLedgerRunner
import SmzaRp05SupplyClosureOutputs
import SmzaRp05SupplyClosureOutputHistory
import SmzaRp05CurrentHistoryCertificateMass

/-! # Public/native admission bridge for selector-fed current blocks

This file keeps the native admission view public: its transaction side is a
chronological list of parsed typed statements, and its append stream is the
statements' public output commitments followed by the actual optional
coinbase.  A binding to the selector-produced envelopes is required before
the existing source block executor can be invoked.  Native frontier,
nullifier, append-capacity, and coinbase-payment rejection remain explicit.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPublicHistoryAdmission

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceBlockReplay
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRunner
open HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedStageList
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputs
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputHistory
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureDistinctInputs
open HegemonCrypto.SmallWood.SmzaRp05NativeFrontierModel (FrontierState newEmpty)
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree (openingAt)
open HegemonCrypto.SmallWood.SmzaRp05ActualAcceptedHistorySupplyEndpoint
  (blockFees coinbaseOpeningCanonical coinbasePaid?)
open HegemonCrypto.SmallWood.SmzaRp05Components
open Hegemon.Consensus (nativeCoinbaseAmount)
open HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness (SupplyState)
open SmzaFiniteLedgerSupply (nativeValue potential allowance)
open scoped Classical

set_option autoImplicit false

noncomputable section

variable {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/-- Public transaction and trailing coinbase data for one source block.
There is intentionally no proof result, selected envelope, ledger invariant,
or caller-declared success field here. -/
structure CurrentPublicBlock where
  transactions : List V8PublicStatement
  coinbase : Option (Nat × V8NoteOpening)

/-- The public/native projection needed by source block replay.  Circulating
value is intentionally absent: its post-transaction value depends on private
note values; coinbase checks need only escrow and issued heights. -/
structure CurrentPublicHistoryState where
  native : FrontierState
  spentNullifiers : List Digest
  feeEscrow : Nat
  issuedHeights : Finset Nat

def initialCurrentPublicHistoryState : CurrentPublicHistoryState :=
  { native := newEmpty
    spentNullifiers := []
    feeEscrow := 0
    issuedHeights := ∅ }

def CurrentPublicHistoryState.supplyCheckState
    (state : CurrentPublicHistoryState) : SupplyState :=
  { circulating := 0
    feeEscrow := state.feeEscrow
    issuedHeights := state.issuedHeights }

/-- Relates public/native history state to the exact chronological
source-ledger prefix.  This is a theorem target, not an input to the public
executor. -/
def CurrentPublicHistoryState.MatchesSourcePrefix
    (state : CurrentPublicHistoryState) (sourcePrefix : CurrentSourceLedgerPrefix) : Prop :=
  state.native = sourcePrefix.snapshot.parent ∧
    state.spentNullifiers = sourcePrefix.spentNullifiers ∧
    state.feeEscrow = sourcePrefix.ledger.feeEscrow ∧
    state.issuedHeights = sourcePrefix.ledger.issuedHeights

theorem initial_public_history_matches_source_genesis :
    initialCurrentPublicHistoryState.MatchesSourcePrefix
      initialCurrentSourceLedgerPrefix := by
  exact ⟨rfl, rfl, rfl, rfl⟩

def publicBlockWords (block : CurrentPublicBlock) : List (List Nat) :=
  block.transactions.map encodePublicStatement

def publicBlockAnchorsCheck (parent : FrontierState)
    (transactions : List V8PublicStatement) : Bool :=
  transactions.all fun statement =>
    decide (publicAnchor (encodePublicStatement statement) ∈ parent.history)

/-- Exactly the nullifier projection used by the native source executor,
computed from public statement flags and nullifier fields only. -/
def publicBlockNullifiers (transactions : List V8PublicStatement) : List Digest :=
  transactions.flatMap fun statement =>
    (List.finRange 2).filterMap fun input =>
      if (encodePublicStatement statement).getD input.val 0 = 1 then
        some (publicNullifier (encodePublicStatement statement) input)
      else none

def publicBlockNullifiersFresh (spent : List Digest)
    (transactions : List V8PublicStatement) : Bool :=
  let additions := publicBlockNullifiers transactions
  additions.Nodup && additions.all (fun value => !(spent.contains value))

def publicBlockCommitments (transactions : List V8PublicStatement) : List Digest :=
  transactions.flatMap fun statement =>
    outputCommitments (encodePublicStatement statement)

def publicBlockCommitmentStream (block : CurrentPublicBlock) : List Digest :=
  publicBlockCommitments block.transactions ++
    (block.coinbase.map (fun pair => exactV8NoteCommitment pair.2)).toList

/-- The issuance/payment check is evaluated from public typed statements and
the actual current supply state.  It mirrors the shipped source checker:
height uniqueness/positivity, scheduled amount, native asset, and canonical
coinbase opening are all recomputed. -/
def publicBlockFees (transactions : List V8PublicStatement) : Nat :=
  (transactions.map V8PublicStatement.fee).sum

def publicCoinbasePaid? (supply : SupplyState)
    (transactions : List V8PublicStatement)
    (coinbase : Option (Nat × V8NoteOpening)) : Option Nat :=
  match coinbase with
  | none => some 0
  | some (height, opening) =>
      if height ∉ supply.issuedHeights then
        if 0 < height then
          match nativeCoinbaseAmount height
              (supply.feeEscrow + publicBlockFees transactions) with
          | none => none
          | some paid =>
              if nativeValue opening = paid && opening.assetId = nativeAssetId then
                if coinbaseOpeningCanonical opening then some paid else none
              else none
        else none
      else none

inductive CurrentPublicBlockError where
  | rejectedAnchor
  | duplicateOrSpentNullifier
  | invalidCoinbaseShape
  | appendCapacity
  | invalidCoinbasePayment
  deriving DecidableEq, Repr

/-- Executable public block transition in native source order.  It updates
the note frontier from public commitment bytes, records exactly the active
public nullifiers, burns per-block escrow, and records an issued height only
for a successfully checked coinbase. -/
def executeCurrentPublicBlock (state : CurrentPublicHistoryState)
    (block : CurrentPublicBlock) : Except CurrentPublicBlockError CurrentPublicHistoryState :=
  if publicBlockAnchorsCheck state.native block.transactions = true then
    if publicBlockNullifiersFresh state.spentNullifiers
        block.transactions = true then
      if blockCoinbaseCanonical block.coinbase = true then
        match appendDigestStream state.native (publicBlockCommitmentStream block) with
        | none => .error .appendCapacity
        | some nativeAfter =>
            match publicCoinbasePaid? state.supplyCheckState
                block.transactions block.coinbase with
            | none => .error .invalidCoinbasePayment
            | some _ =>
                .ok {
                  native := nativeAfter
                  spentNullifiers := state.spentNullifiers ++
                    publicBlockNullifiers block.transactions
                  feeEscrow := 0
                  issuedHeights := match block.coinbase with
                    | none => state.issuedHeights
                    | some (height, _) => insert height state.issuedHeights
                }
      else .error .invalidCoinbaseShape
    else .error .duplicateOrSpentNullifier
  else .error .rejectedAnchor

/-- Exact executable history acceptance, starting from native genesis and
empty spent/issuance state.  Failures retain their block index and error;
successful runs return their computed public/native final state. -/
def executeCurrentPublicHistoryFrom (index : Nat) :
    List CurrentPublicBlock → CurrentPublicHistoryState →
      Except (Nat × CurrentPublicBlockError) CurrentPublicHistoryState
  | [], state => .ok state
  | block :: rest, state =>
      match executeCurrentPublicBlock state block with
      | .error failure => .error (index, failure)
      | .ok next => executeCurrentPublicHistoryFrom (index + 1) rest next

def executeCurrentPublicHistoryFromGenesis (blocks : List CurrentPublicBlock) :=
  executeCurrentPublicHistoryFrom 0 blocks initialCurrentPublicHistoryState

def CurrentPublicHistoryAccepted (blocks : List CurrentPublicBlock) : Prop :=
  ∃ finalState,
    executeCurrentPublicHistoryFromGenesis blocks = .ok finalState

/-- Source-native public acceptance for one block at its actual chronological
prefix.  `appendCapacity` is deliberately a checked append result, not an
assumption that the note tree has room.  Coinbase payment is kept separate
because it depends on the exact finite-ledger fee-escrow/issued-height state.
-/
structure CurrentPublicBlockNativeChecks (before : CurrentSourceLedgerPrefix)
    (block : CurrentPublicBlock) where
  anchors : publicBlockAnchorsCheck before.snapshot.parent block.transactions = true
  nullifiers : publicBlockNullifiersFresh before.spentNullifiers
    block.transactions = true
  coinbaseShape : blockCoinbaseCanonical block.coinbase = true
  appendCapacity : ∃ after : FrontierState,
    appendDigestStream before.snapshot.parent (publicBlockCommitmentStream block) =
      some after
  coinbasePayment : ∃ paid : Nat,
    publicCoinbasePaid? (currentSupplyCheckState before.ledger)
      block.transactions block.coinbase = some paid

/-- Exact link from one source block's parsed public statements to the
selector-derived transaction envelopes supplied to the existing runner.
`selected` is an equality with the actual stage envelope function, not a
caller-supplied success bit; `runStatements` binds every successful
designated decoder result back to that public transaction position. -/
structure CurrentSelectedPublicBlockBinding (block : CurrentPublicBlock)
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork)))
    (runs : List CurrentRunEnvelope) where
  selected : selectedTransactions stages = runs.map some
  stageStatements : stages.map CurrentSelectedStage.typed = block.transactions

def selectedBlockPublicView
    (block : CurrentSelectedBlock (BaseWork := BaseWork)) :
    CurrentPublicBlock :=
  { transactions := block.stages.map CurrentSelectedStage.typed
    coinbase := block.coinbase }

theorem successful_public_block_has_native_checks
    (state : CurrentPublicHistoryState) (block : CurrentPublicBlock)
    (next : CurrentPublicHistoryState)
    (accepted : executeCurrentPublicBlock state block = .ok next) :
    publicBlockAnchorsCheck state.native block.transactions = true ∧
    publicBlockNullifiersFresh state.spentNullifiers block.transactions = true ∧
    blockCoinbaseCanonical block.coinbase = true ∧
    (∃ nativeAfter, appendDigestStream state.native
      (publicBlockCommitmentStream block) = some nativeAfter) ∧
    (∃ paid, publicCoinbasePaid? state.supplyCheckState
      block.transactions block.coinbase = some paid) := by
  unfold executeCurrentPublicBlock at accepted
  by_cases anchors : publicBlockAnchorsCheck state.native block.transactions = true
  · simp only [if_pos anchors] at accepted
    by_cases nullifiers : publicBlockNullifiersFresh state.spentNullifiers
        block.transactions = true
    · simp only [if_pos nullifiers] at accepted
      by_cases shape : blockCoinbaseCanonical block.coinbase = true
      · simp only [if_pos shape] at accepted
        cases append : appendDigestStream state.native
            (publicBlockCommitmentStream block) with
        | none => simp [append] at accepted
        | some nativeAfter =>
            simp only [append] at accepted
            cases payment : publicCoinbasePaid? state.supplyCheckState
                block.transactions block.coinbase with
            | none => simp [payment] at accepted
            | some paid =>
                simp only [payment] at accepted
                have stateEq := Except.ok.inj accepted
                subst next
                exact ⟨anchors, nullifiers, shape, ⟨nativeAfter, rfl⟩,
                  ⟨paid, rfl⟩⟩
      · simp [shape] at accepted
    · simp [nullifiers] at accepted
  · simp [anchors] at accepted

private theorem public_supply_projection_eq_source
    (state : CurrentPublicHistoryState) (sourcePrefix : CurrentSourceLedgerPrefix)
    (prefixMatches : state.MatchesSourcePrefix sourcePrefix) :
    state.supplyCheckState = currentSupplyCheckState sourcePrefix.ledger := by
  rcases prefixMatches with ⟨_nativeEq, _spentEq, feeEq, heightsEq⟩
  simp [CurrentPublicHistoryState.supplyCheckState, currentSupplyCheckState,
    feeEq, heightsEq]

theorem successful_public_block_source_checks
    (state : CurrentPublicHistoryState) (sourcePrefix : CurrentSourceLedgerPrefix)
    (block : CurrentPublicBlock) (next : CurrentPublicHistoryState)
    (prefixMatches : state.MatchesSourcePrefix sourcePrefix)
    (accepted : executeCurrentPublicBlock state block = .ok next) :
    CurrentPublicBlockNativeChecks sourcePrefix block := by
  obtain ⟨anchors, nullifiers, coinbaseShape, append, payment⟩ :=
    successful_public_block_has_native_checks state block next accepted
  rcases append with ⟨nativeAfter, append⟩
  rcases payment with ⟨paid, payment⟩
  have supplyEq := public_supply_projection_eq_source state sourcePrefix prefixMatches
  refine ⟨?_, ?_, coinbaseShape, ?_, ?_⟩
  · simpa [prefixMatches.1] using anchors
  · simpa [prefixMatches.2.1] using nullifiers
  · refine ⟨nativeAfter, ?_⟩
    simpa [prefixMatches.1] using append
  · refine ⟨paid, ?_⟩
    rw [← supplyEq]
    exact payment

private theorem selected_envelopes_preserve_typed_statements
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork)))
    (runs : List CurrentRunEnvelope)
    (selected : selectedTransactions stages = runs.map some) :
    runs.map CurrentRunEnvelope.typedStatement =
      stages.map CurrentSelectedStage.typed := by
  induction stages generalizing runs with
  | nil =>
      cases runs <;> simp [selectedTransactions] at selected ⊢
  | cons stage rest ih =>
      cases envelopeEq : stage.envelope with
      | none =>
          cases runs with
          | nil => simp [selectedTransactions, envelopeEq] at selected
          | cons run tail => simp [selectedTransactions, envelopeEq] at selected
      | some envelope =>
          cases runs with
          | nil => simp [selectedTransactions, envelopeEq] at selected
          | cons run tail =>
              simp only [selectedTransactions, List.map_cons, envelopeEq,
                List.cons.injEq, Option.some.injEq] at selected
              rcases selected with ⟨headEq, tailEq⟩
              cases headEq
              have tailStatements := ih tail tailEq
              have headStatement :=
                (CurrentSelectedStage.envelope_statement stage envelope envelopeEq).2
              simp only [List.map_cons]
              rw [headStatement, tailStatements]

private theorem extractCurrentRuns_all_some
    (index : Nat) (runs : List CurrentRunEnvelope) :
    extractCurrentRuns index (runs.map some) = .ok runs := by
  induction runs generalizing index with
  | nil => rfl
  | cons run rest ih =>
      simp only [List.map_cons, extractCurrentRuns]
      rw [ih (index + 1)]
      rfl

private theorem extractCurrentRuns_success_has_no_missing
    (index : Nat) (transactions : List (Option CurrentRunEnvelope))
    (runs : List CurrentRunEnvelope)
    (extracted : extractCurrentRuns index transactions = .ok runs) :
    transactions = runs.map some := by
  induction transactions generalizing index runs with
  | nil =>
      cases runs <;> simp [extractCurrentRuns] at extracted ⊢
  | cons transaction rest ih =>
      cases transaction with
      | none => simp [extractCurrentRuns] at extracted
      | some envelope =>
          cases tailResult : extractCurrentRuns (index + 1) rest with
          | error failure => simp [extractCurrentRuns, tailResult] at extracted
          | ok tailRuns =>
              have headTailEq : envelope :: tailRuns = runs := by
                simpa [extractCurrentRuns, tailResult] using extracted
              cases headTailEq
              have tailNoMissing := ih (index + 1) tailRuns tailResult
              simp [tailNoMissing]

theorem CurrentSelectedPublicBlockBinding.runStatements
    (block : CurrentPublicBlock)
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork)))
    (runs : List CurrentRunEnvelope)
    (binding : CurrentSelectedPublicBlockBinding block stages runs) :
    runs.map CurrentRunEnvelope.typedStatement = block.transactions :=
  (selected_envelopes_preserve_typed_statements stages runs binding.selected).trans
    binding.stageStatements

private theorem selected_transactions_present
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork)))
    (present : ∀ stage ∈ stages, stage.envelope ≠ none) :
    ∃ runs : List CurrentRunEnvelope,
      selectedTransactions stages = runs.map some ∧
      runs.map CurrentRunEnvelope.typedStatement =
        stages.map CurrentSelectedStage.typed := by
  induction stages with
  | nil => exact ⟨[], rfl, rfl⟩
  | cons stage rest ih =>
      have headPresent := present stage (by simp)
      cases envelopeEq : stage.envelope with
      | none => exact False.elim (headPresent envelopeEq)
      | some envelope =>
          have restPresent : ∀ item ∈ rest, item.envelope ≠ none := by
            intro item itemIn
            exact present item (by simp [itemIn])
          obtain ⟨runs, selectedEq, typedEq⟩ := ih restPresent
          have statement := (CurrentSelectedStage.envelope_statement
            stage envelope envelopeEq).2
          refine ⟨envelope :: runs, ?_, ?_⟩
          · change stage.envelope :: selectedTransactions rest =
              some envelope :: List.map some runs
            rw [envelopeEq, selectedEq]
          · simp only [List.map_cons]
            rw [statement, typedEq]

private theorem selected_public_block_binding_of_present
    (block : CurrentPublicBlock)
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork)))
    (present : ∀ stage ∈ stages, stage.envelope ≠ none)
    (typedEq : stages.map CurrentSelectedStage.typed = block.transactions) :
    ∃ runs, CurrentSelectedPublicBlockBinding block stages runs := by
  obtain ⟨runs, selectedEq, _runTypedEq⟩ :=
    selected_transactions_present stages present
  exact ⟨runs, ⟨selectedEq, typedEq⟩⟩

omit [Fintype BaseWork] [DecidableEq BaseWork] in
theorem CurrentSelectedPublicBlockBinding.ofReceipt
    {before after : CurrentSourceLedgerPrefix}
    (receipt : CurrentSelectedBlockReceipt (BaseWork := BaseWork) before after) :
    CurrentSelectedPublicBlockBinding (selectedBlockPublicView receipt.block)
      receipt.block.stages receipt.result.runs where
  selected := extractCurrentRuns_success_has_no_missing 0
    (selectedTransactions receipt.block.stages) receipt.result.runs
    receipt.result.extraction
  stageStatements := rfl

private theorem selected_run_output_commitment_stream
    (runs : List CurrentRunEnvelope) :
    publicOutputStream (outputRecords runs) =
      publicBlockCommitments (runs.map CurrentRunEnvelope.typedStatement) := by
  induction runs with
  | nil => simp [publicOutputStream, outputRecords, publicBlockCommitments]
  | cons envelope rest ih =>
      change outputCommitments (encodePublicStatement envelope.typedStatement) ++
          publicOutputStream (outputRecords rest) =
        outputCommitments (encodePublicStatement envelope.typedStatement) ++
          publicBlockCommitments (rest.map CurrentRunEnvelope.typedStatement)
      rw [ih]

theorem selected_runs_public_output_commitments
    (block : CurrentPublicBlock) (runs : List CurrentRunEnvelope)
    (statementsEq : runs.map CurrentRunEnvelope.typedStatement = block.transactions) :
    publicOutputStream (outputRecords runs) = publicBlockCommitments block.transactions := by
  rw [← statementsEq]
  exact selected_run_output_commitment_stream runs

/-- The output-opening identity remains the accepted relation's theorem:
the source-generated openings in these envelopes commit to the public
statement output stream, in order. -/
theorem selected_runs_opening_identity
    (block : CurrentPublicBlock) (runs : List CurrentRunEnvelope)
    (statementsEq : runs.map CurrentRunEnvelope.typedStatement = block.transactions) :
    (extractedOutputLog (outputRecords runs)).map exactV8NoteCommitment =
      publicBlockCommitments block.transactions := by
  rw [accepted_records_output_stream (outputRecords runs)
    (output_records_accepted runs)]
  exact selected_runs_public_output_commitments block runs statementsEq

private theorem selected_runs_anchor_check_public
    (parent : FrontierState) (runs : List CurrentRunEnvelope) :
    blockAnchorCheck parent runs =
      publicBlockAnchorsCheck parent (runs.map CurrentRunEnvelope.typedStatement) := by
  induction runs with
  | nil => rfl
  | cons envelope rest ih =>
      change
        (decide (publicAnchor (encodePublicStatement envelope.typedStatement) ∈
          parent.history) && blockAnchorCheck parent rest) =
        (decide (publicAnchor (encodePublicStatement envelope.typedStatement) ∈
          parent.history) &&
          publicBlockAnchorsCheck parent (rest.map CurrentRunEnvelope.typedStatement))
      rw [ih]

private theorem runner_anchor_check_eq_public
    (parent : FrontierState) (runs : List CurrentRunEnvelope)
    (transactions : List V8PublicStatement)
    (statementsEq : runs.map CurrentRunEnvelope.typedStatement = transactions) :
    blockAnchorCheck parent runs = publicBlockAnchorsCheck parent transactions := by
  rw [← statementsEq]
  exact selected_runs_anchor_check_public parent runs

private theorem selected_runs_nullifiers_public
    (runs : List CurrentRunEnvelope) :
    blockNullifiers runs =
      publicBlockNullifiers (runs.map CurrentRunEnvelope.typedStatement) := by
  induction runs with
  | nil => rfl
  | cons envelope rest ih =>
      change
        (List.finRange 2).filterMap (fun input =>
          if (encodePublicStatement envelope.typedStatement).getD input.val 0 = 1 then
            some (publicNullifier (encodePublicStatement envelope.typedStatement) input)
          else none) ++ blockNullifiers rest =
        (List.finRange 2).filterMap (fun input =>
          if (encodePublicStatement envelope.typedStatement).getD input.val 0 = 1 then
            some (publicNullifier (encodePublicStatement envelope.typedStatement) input)
          else none) ++
          publicBlockNullifiers (rest.map CurrentRunEnvelope.typedStatement)
      rw [ih]

private theorem runner_nullifiers_eq_public
    (runs : List CurrentRunEnvelope) (transactions : List V8PublicStatement)
    (statementsEq : runs.map CurrentRunEnvelope.typedStatement = transactions) :
    blockNullifiers runs = publicBlockNullifiers transactions := by
  rw [← statementsEq]
  exact selected_runs_nullifiers_public runs

private theorem runner_commitments_eq_public
    (block : CurrentPublicBlock) (runs : List CurrentRunEnvelope)
    (statementsEq : runs.map CurrentRunEnvelope.typedStatement = block.transactions) :
    blockCommitmentStream (outputRecords runs) (blockCoinbaseOpening block.coinbase) =
      publicBlockCommitmentStream block := by
  simp only [blockCommitmentStream, blockCoinbaseOpening,
    selected_runs_public_output_commitments block runs statementsEq,
    publicBlockCommitmentStream]
  cases block.coinbase <;> rfl

private theorem runner_coinbase_checker_eq_public
    (supply : SupplyState) (runs : List CurrentRunEnvelope)
    (transactions : List V8PublicStatement) (coinbase : Option (Nat × V8NoteOpening))
    (statementsEq : runs.map CurrentRunEnvelope.typedStatement = transactions) :
    coinbasePaid? supply (selectedDesignatedRuns runs) coinbase =
      publicCoinbasePaid? supply transactions coinbase := by
  rw [← statementsEq]
  have feesEq : blockFees (selectedDesignatedRuns runs) =
      publicBlockFees (runs.map CurrentRunEnvelope.typedStatement) := by
    simp [blockFees, selectedDesignatedRuns, selectedDesignatedRun,
      publicBlockFees, List.map_map, Function.comp_def]
  cases coinbase with
  | none => rfl
  | some candidate =>
      rcases candidate with ⟨height, opening⟩
      simp only [coinbasePaid?, publicCoinbasePaid?]
      rw [feesEq]
      rfl

/-- A completed source receipt advances the independent public executor by
exactly one accepted public block and establishes the next public/source
prefix relation.  The public block is the parsed stage projection of the
receipt itself, so its coinbase and transaction grouping cannot drift. -/
theorem selected_receipt_advances_public_history
    {before after : CurrentSourceLedgerPrefix}
    (receipt : CurrentSelectedBlockReceipt (BaseWork := BaseWork) before after)
    (state : CurrentPublicHistoryState)
    (prefixMatches : state.MatchesSourcePrefix before) :
    ∃ nextState,
      executeCurrentPublicBlock state (selectedBlockPublicView receipt.block) = .ok nextState ∧
      nextState.MatchesSourcePrefix after := by
  let block := selectedBlockPublicView receipt.block
  let binding := CurrentSelectedPublicBlockBinding.ofReceipt receipt
  have statementsEq := binding.runStatements
  have sourceProjection := selected_block_receipt_source_projection receipt
  have anchors : publicBlockAnchorsCheck state.native block.transactions = true := by
    rw [prefixMatches.1, ← runner_anchor_check_eq_public before.snapshot.parent
      receipt.result.runs block.transactions statementsEq]
    exact receipt.result.anchorsChecked
  have nullifiers : publicBlockNullifiersFresh state.spentNullifiers
      block.transactions = true := by
    rw [prefixMatches.2.1]
    simpa [publicBlockNullifiersFresh, nullifiersFresh,
      ← runner_nullifiers_eq_public receipt.result.runs block.transactions statementsEq] using
      receipt.result.nullifiersChecked
  have append : appendDigestStream state.native
      (publicBlockCommitmentStream block) = some receipt.result.nativeAfter := by
    rw [prefixMatches.1, ← runner_commitments_eq_public block receipt.result.runs statementsEq]
    exact receipt.result.appended
  have supplyEq : state.supplyCheckState = currentSupplyCheckState before.ledger := by
    rcases prefixMatches with ⟨_nativeEq, _spentEq, feeEq, heightsEq⟩
    simp [CurrentPublicHistoryState.supplyCheckState, currentSupplyCheckState,
      feeEq, heightsEq]
  have paid : publicCoinbasePaid? state.supplyCheckState
      block.transactions block.coinbase = some receipt.paid := by
    rw [supplyEq, ← runner_coinbase_checker_eq_public (currentSupplyCheckState before.ledger)
      receipt.result.runs block.transactions block.coinbase statementsEq]
    exact receipt.actualChecker
  let nextState : CurrentPublicHistoryState := {
    native := receipt.result.nativeAfter
    spentNullifiers := state.spentNullifiers ++ publicBlockNullifiers block.transactions
    feeEscrow := 0
    issuedHeights := match block.coinbase with
      | none => state.issuedHeights
      | some (height, _) => insert height state.issuedHeights
  }
  have executed : executeCurrentPublicBlock state block = .ok nextState := by
    dsimp [nextState]
    unfold executeCurrentPublicBlock
    have coinbaseCheck : blockCoinbaseCanonical block.coinbase = true := by
      simpa [block, selectedBlockPublicView] using receipt.result.coinbaseChecked
    rw [anchors, nullifiers, if_pos coinbaseCheck, append, paid]
    rfl
  have afterMatches : nextState.MatchesSourcePrefix after := by
    dsimp [nextState]
    rcases sourceProjection with ⟨nativeEq, spentEq, escrowEq, heightsEq⟩
    constructor
    · exact nativeEq.symm
    constructor
    · change state.spentNullifiers ++ publicBlockNullifiers block.transactions =
        after.spentNullifiers
      rw [prefixMatches.2.1,
        ← runner_nullifiers_eq_public receipt.result.runs block.transactions statementsEq]
      exact spentEq.symm
    constructor
    · exact escrowEq.symm
    · change (match receipt.block.coinbase with
        | none => state.issuedHeights
        | some (height, _) => insert height state.issuedHeights) =
          after.ledger.issuedHeights
      rw [prefixMatches.2.2.2]
      exact heightsEq.symm
  exact ⟨nextState, executed, afterMatches⟩

private theorem selected_trace_advances_public_history
    {blocks : List (CurrentSelectedBlock (BaseWork := BaseWork))}
    {initial final : CurrentSourceLedgerPrefix}
    (trace : CurrentSelectedHistoryTrace (BaseWork := BaseWork) blocks
      initial final)
    {state : CurrentPublicHistoryState}
    (prefixMatches : state.MatchesSourcePrefix initial)
    (index : Nat) :
    ∃ finalState,
      executeCurrentPublicHistoryFrom index (blocks.map selectedBlockPublicView)
        state = .ok finalState ∧ finalState.MatchesSourcePrefix final := by
  induction trace generalizing state index with
  | nil _ =>
      exact ⟨state, rfl, prefixMatches⟩
  | @cons tail before middle final receipt rest ih =>
      obtain ⟨middleState, firstAccepted, middleMatches⟩ :=
        selected_receipt_advances_public_history receipt state prefixMatches
      obtain ⟨finalState, restAccepted, finalMatches⟩ :=
        ih (state := middleState) (index := index + 1) middleMatches
      refine ⟨finalState, ?_, finalMatches⟩
      simpa only [List.map_cons, executeCurrentPublicHistoryFrom, firstAccepted] using
        restAccepted

private theorem public_history_success_cons
    (index : Nat) (block : CurrentPublicBlock)
    (rest : List CurrentPublicBlock) (state final : CurrentPublicHistoryState)
    (accepted : executeCurrentPublicHistoryFrom index (block :: rest) state =
      .ok final) :
    ∃ middle, executeCurrentPublicBlock state block = .ok middle ∧
      executeCurrentPublicHistoryFrom (index + 1) rest middle = .ok final := by
  unfold executeCurrentPublicHistoryFrom at accepted
  cases step : executeCurrentPublicBlock state block with
  | error failure => simp [step] at accepted
  | ok middle =>
      simp only [step] at accepted
      exact ⟨middle, rfl, accepted⟩

private theorem public_history_success_split
    (index : Nat) (preceding suffix : List CurrentPublicBlock)
    (state final : CurrentPublicHistoryState)
    (accepted : executeCurrentPublicHistoryFrom index (preceding ++ suffix) state =
      .ok final) :
    ∃ middle,
      executeCurrentPublicHistoryFrom index preceding state = .ok middle ∧
      executeCurrentPublicHistoryFrom (index + preceding.length) suffix middle =
        .ok final := by
  induction preceding generalizing index state with
  | nil => exact ⟨state, rfl, accepted⟩
  | cons block preceding ih =>
      obtain ⟨stepState, stepAccepted, tailAccepted⟩ :=
        public_history_success_cons index block (preceding ++ suffix) state final accepted
      obtain ⟨middle, prefixAccepted, suffixAccepted⟩ :=
        ih (index + 1) stepState tailAccepted
      refine ⟨middle, ?_, ?_⟩
      · simpa [List.cons_append, executeCurrentPublicHistoryFrom, stepAccepted] using
          prefixAccepted
      · have indexEq : (index + 1) + preceding.length =
            index + (block :: preceding).length := by
          simp only [List.length_cons]
          omega
        simpa only [indexEq] using suffixAccepted

/-- Bounded one-block bridge.  Given the exact selector-output binding and
the public native checks at the real source prefix, the existing executor
cannot fail for extraction, anchor, nullifier, coinbase-shape, or append
capacity.  The public payment check is the same computation as the runner's
actual coinbase checker.  This theorem says nothing about finite-ledger
transfer feasibility/cap or the later protocol fold. -/
theorem public_checks_imply_selected_block_native_acceptance
    (before : CurrentSourceLedgerPrefix) (block : CurrentPublicBlock)
    (stages : List (CurrentSelectedStage (BaseWork := BaseWork)))
    (runs : List CurrentRunEnvelope)
    (binding : CurrentSelectedPublicBlockBinding block stages runs)
    (checks : CurrentPublicBlockNativeChecks before block) :
    ∃ result : CurrentBlockReplayResult before.snapshot.parent before.spentNullifiers
        (selectedTransactions stages) block.coinbase,
      executeSelectedCurrentBlock before stages block.coinbase = .ok result ∧
      result.runs = runs ∧
      ∃ paid : Nat,
        coinbasePaid? (currentSupplyCheckState before.ledger)
          (selectedDesignatedRuns result.runs) block.coinbase = some paid := by
  have runStatements := binding.runStatements
  obtain ⟨after, appendCheck⟩ := checks.appendCapacity
  obtain ⟨paid, publicPaid⟩ := checks.coinbasePayment
  have anchorCheck : blockAnchorCheck before.snapshot.parent runs = true := by
    rw [runner_anchor_check_eq_public before.snapshot.parent runs block.transactions
      runStatements]
    exact checks.anchors
  have nullifierCheck : nullifiersFresh before.spentNullifiers runs = true := by
    rw [nullifiersFresh, runner_nullifiers_eq_public runs block.transactions
      runStatements]
    exact checks.nullifiers
  have appendEq : appendDigestStream before.snapshot.parent
      (blockCommitmentStream (outputRecords runs) (blockCoinbaseOpening block.coinbase)) =
        some after := by
    rw [runner_commitments_eq_public block runs runStatements]
    exact appendCheck
  have extractionEq : extractCurrentRuns 0 (selectedTransactions stages) = .ok runs := by
    rw [binding.selected]
    exact extractCurrentRuns_all_some 0 runs
  let result : CurrentBlockReplayResult before.snapshot.parent before.spentNullifiers
      (selectedTransactions stages) block.coinbase := {
    runs := runs
    extraction := extractionEq
    anchorsChecked := anchorCheck
    nullifiersChecked := nullifierCheck
    coinbaseChecked := checks.coinbaseShape
    nativeAfter := after
    openingsAdded :=
      blockOpeningStream (outputRecords runs) (blockCoinbaseOpening block.coinbase)
    openingsAddedEq := rfl
    appended := appendEq
  }
  have nativeResult : executeCurrentBlock before.snapshot.parent before.spentNullifiers
      (selectedTransactions stages) block.coinbase = .ok result := by
    unfold executeCurrentBlock
    split
    · rename_i error extraction
      rw [extraction] at extractionEq
      cases extractionEq
    · rename_i found extraction
      have foundEq : found = runs :=
        Except.ok.inj (extraction.symm.trans extractionEq)
      subst found
      rw [dif_pos anchorCheck, dif_pos nullifierCheck,
        dif_pos checks.coinbaseShape]
      split
      · rename_i appendProof
        rw [appendProof] at appendEq
        cases appendEq
      · rename_i nativeAfter appendProof
        have nativeAfterEq : nativeAfter = after :=
          Option.some.inj (appendProof.symm.trans appendEq)
        subst nativeAfter
        rfl
  refine ⟨result, ?_, rfl, ?_⟩
  · simpa [executeSelectedCurrentBlock] using nativeResult
  · refine ⟨paid, ?_⟩
    rw [runner_coinbase_checker_eq_public (currentSupplyCheckState before.ledger)
      runs block.transactions block.coinbase runStatements]
    exact publicPaid

theorem accepted_public_block_yields_selected_native_acceptance
    (before : CurrentSourceLedgerPrefix) (state : CurrentPublicHistoryState)
    (block : CurrentSelectedBlock (BaseWork := BaseWork))
    (next : CurrentPublicHistoryState)
    (prefixMatches : state.MatchesSourcePrefix before)
    (present : ∀ stage ∈ block.stages, stage.envelope ≠ none)
    (accepted : executeCurrentPublicBlock state (selectedBlockPublicView block) = .ok next) :
    ∃ result : CurrentBlockReplayResult before.snapshot.parent before.spentNullifiers
        (selectedTransactions block.stages) block.coinbase,
      executeSelectedCurrentBlock before block.stages block.coinbase = .ok result ∧
      ∃ paid : Nat,
        coinbasePaid? (currentSupplyCheckState before.ledger)
          (selectedDesignatedRuns result.runs) block.coinbase = some paid := by
  have checks := successful_public_block_source_checks state before (selectedBlockPublicView block)
    next prefixMatches accepted
  have typedEq : block.stages.map CurrentSelectedStage.typed =
      (selectedBlockPublicView block).transactions := rfl
  obtain ⟨runs, binding⟩ := selected_public_block_binding_of_present
    (selectedBlockPublicView block) block.stages present typedEq
  obtain ⟨result, native, _runsEq, paid, payment⟩ :=
    public_checks_imply_selected_block_native_acceptance before (selectedBlockPublicView block)
      block.stages runs binding checks
  exact ⟨result, native, paid, by simpa [selectedBlockPublicView] using payment⟩

def CurrentSelectedHistoryFailureIsSourceInput
    {before : CurrentSourceLedgerPrefix}
    {block : CurrentSelectedBlock (BaseWork := BaseWork)}
    (failure : CurrentSelectedHistoryFailure (BaseWork := BaseWork) before block) : Prop :=
  match failure with
  | .sourceInput .. => True
  | .native .. => False
  | .coinbase .. => False

theorem accepted_public_step_excludes_native_and_coinbase_failure
    (before : CurrentSourceLedgerPrefix) (state : CurrentPublicHistoryState)
    (block : CurrentSelectedBlock (BaseWork := BaseWork))
    (next : CurrentPublicHistoryState)
    (prefixMatches : state.MatchesSourcePrefix before)
    (present : ∀ stage ∈ block.stages, stage.envelope ≠ none)
    (accepted : executeCurrentPublicBlock state (selectedBlockPublicView block) = .ok next)
    (failure : CurrentSelectedHistoryFailure (BaseWork := BaseWork) before block) :
    CurrentSelectedHistoryFailureIsSourceInput failure := by
  cases failure with
  | native error actual =>
      obtain ⟨result, native, _paid⟩ :=
        accepted_public_block_yields_selected_native_acceptance before state block
          next prefixMatches present accepted
      rw [actual] at native
      cases native
  | sourceInput result native chargedFailure fold =>
      trivial
  | coinbase result native fold checker =>
      obtain ⟨other, otherNative, paid, actualPaid⟩ :=
        accepted_public_block_yields_selected_native_acceptance before state block
          next prefixMatches present accepted
      rw [native] at otherNative
      injection otherNative with sameResult
      subst result
      rw [checker] at actualPaid
      cases actualPaid

omit [Fintype BaseWork] [DecidableEq BaseWork] in
private theorem public_failure_frame_some_of_source_input
    {done tail : List (CurrentSelectedBlock (BaseWork := BaseWork))}
    {before : CurrentSourceLedgerPrefix}
    (trace : CurrentSelectedHistoryTrace (BaseWork := BaseWork) done
      initialCurrentSourceLedgerPrefix before)
    (block : CurrentSelectedBlock (BaseWork := BaseWork))
    (failure : CurrentSelectedHistoryFailure (BaseWork := BaseWork) before block)
    (isSourceInput : CurrentSelectedHistoryFailureIsSourceInput failure) :
    (HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryCertificateMass.currentSelectedHistoryFailureFrame
      (blocks := done ++ block :: tail)
      (initial := initialCurrentSourceLedgerPrefix)
      (.failed (tail := tail) trace block failure)).isSome = true := by
  cases failure with
  | native error actual => cases isSourceInput
  | sourceInput result native chargedFailure fold => rfl
  | coinbase result native fold checker => cases isSourceInput

/-- Pointwise closure between accepted public/native input and the exact
selected-history result. A generated complete result carries its actual trace
and potential bound. Otherwise, public acceptance plus present selector
envelopes excludes native replay and issuance-checker failure, so the actual
first-failure frame is charged source input. -/
theorem public_history_acceptance_complete_or_charged
    (blocks : List (CurrentSelectedBlock (BaseWork := BaseWork)))
    (publicAccepted : CurrentPublicHistoryAccepted
      (blocks.map selectedBlockPublicView))
    (present : ∀ block ∈ blocks, ∀ stage ∈ block.stages,
      stage.envelope ≠ none) :
    (∃ (final : CurrentSourceLedgerPrefix)
      (trace : CurrentSelectedHistoryTrace (BaseWork := BaseWork) blocks
        initialCurrentSourceLedgerPrefix final)
      (boundary : final.stagedOpenings = final.snapshot.openings)
      (invariant : potential (openingAt final.stagedOpenings) final.ledger ≤
        allowance final.ledger),
      executeSelectedCurrentHistoryFromGenesis blocks =
        .complete trace boundary invariant) ∨
    (HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryCertificateMass.currentSelectedHistoryFailureFrame
      (executeSelectedCurrentHistoryFromGenesis blocks)).isSome = true := by
  obtain ⟨publicFinal, publicRun⟩ := publicAccepted
  cases actualEq : executeSelectedCurrentHistoryFromGenesis blocks with
  | complete trace boundary invariant =>
      exact Or.inl ⟨_, trace, boundary, invariant, rfl⟩
  | failed trace block failure =>
      rename_i done tail before
      have prefixFromTrace := selected_trace_advances_public_history trace
        initial_public_history_matches_source_genesis 0
      obtain ⟨traceState, tracePublicRun, traceMatches⟩ := prefixFromTrace
      have fullPublicRun : executeCurrentPublicHistoryFrom 0
          ((done ++ block :: tail).map selectedBlockPublicView)
          initialCurrentPublicHistoryState = .ok publicFinal := by
        simpa [executeCurrentPublicHistoryFromGenesis] using publicRun
      obtain ⟨splitState, prefixPublicRun, suffixPublicRun⟩ :=
        public_history_success_split 0
          (done.map selectedBlockPublicView)
          ((block :: tail).map selectedBlockPublicView)
          initialCurrentPublicHistoryState publicFinal (by
            simpa [List.map_append] using fullPublicRun)
      have sameState : traceState = splitState :=
        Except.ok.inj (tracePublicRun.symm.trans prefixPublicRun)
      subst splitState
      obtain ⟨nextState, blockAccepted, _tailAccepted⟩ :=
        public_history_success_cons done.length (selectedBlockPublicView block)
          (tail.map selectedBlockPublicView) traceState publicFinal (by
            simpa [List.length_map] using suffixPublicRun)
      have blockPresent : ∀ stage ∈ block.stages, stage.envelope ≠ none := by
        intro stage stageIn
        apply present block
        · exact List.mem_append_right done (by simp)
        · exact stageIn
      have sourceInput := accepted_public_step_excludes_native_and_coinbase_failure
        before traceState block nextState traceMatches blockPresent blockAccepted failure
      have frame := public_failure_frame_some_of_source_input
        (tail := tail) trace block failure sourceInput
      exact Or.inr frame

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentPublicHistoryAdmission
