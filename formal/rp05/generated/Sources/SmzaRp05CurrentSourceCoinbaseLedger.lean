import SmzaRp05CurrentSourceLedgerPrefix
import SmzaRp05CurrentFiniteLedgerHistory
import SmzaRp05CurrentOutputLedgerPositions
import SmzaRp05HistoricalTree
import SmzaRp05SupplyClosureInputNative
import LifetimeIssuanceR2

/-! # Source-shaped finite-ledger coinbase boundary

The public issuance checks are evaluated here, against the replayed finite
ledger.  Failure is the `none` result of the executable plan; successful
coinbase outputs occupy the actual singleton appended-note position.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSourceCoinbaseLedger

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
open HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteLedgerHistory
open HegemonCrypto.SmallWood.SmzaRp05CurrentOutputLedgerPositions
open HegemonCrypto.SmallWood.SmzaRp05HistoricalTree (openingAt)
open SmzaFiniteLedgerSupply
open Hegemon.Consensus (nativeCoinbaseAmount)
open scoped Classical

set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

noncomputable section
attribute [local instance] Classical.propDecidable

variable {program : RelationProgramComponents}
variable {primitives : V8SemanticPrimitives}

/-- The actual optional block coinbase as an opening list. -/
def sourceCoinbaseOpenings : Option (Nat × V8NoteOpening) → List V8NoteOpening
  | none => []
  | some (_, opening) => [opening]

/-- The exact registry after appending this optional coinbase to the staged
transaction-output frontier. -/
def sourceCoinbaseRegistry (ledgerPrefix : CurrentSourceLedgerPrefix)
    (future : List V8NoteOpening) (coinbase : Option (Nat × V8NoteOpening)) :
    Nat → V8NoteOpening :=
  fun id => openingAt
    (ledgerPrefix.stagedOpenings ++ sourceCoinbaseOpenings coinbase ++ future) id

/-- Executable issuance/value/canonicality guard. `none` is the rejected
branch for a supplied coinbase; it is not replaced by a caller-supplied
conservation equation. -/
def checkedSourceCoinbasePaid? (state : Ledger) (height : Nat)
    (opening : V8NoteOpening) : Option Nat :=
  if _once : height ∉ state.issuedHeights then
    if _positive : 0 < height then
      match nativeCoinbaseAmount height state.feeEscrow with
      | none => none
      | some paid =>
          if nativeValue opening = paid ∧ opening.assetId = nativeAssetId ∧
              CanonicalNoteOpening opening then some paid else none
    else none
  else none

/-- Plan the real finite-ledger action. An absent coinbase burns escrow; a
present but invalid candidate returns `none`. A valid candidate pays exactly
the public schedule and appends its actual opening as one fresh output. -/
def sourceCoinbasePlan (ledgerPrefix : CurrentSourceLedgerPrefix)
    (future : List V8NoteOpening)
    (coinbase : Option (Nat × V8NoteOpening)) : Option (Action × Ledger) :=
  match coinbase with
  | none => some (.noCoinbase, burnEscrow ledgerPrefix.ledger)
  | some (height, opening) =>
      match checkedSourceCoinbasePaid? ledgerPrefix.ledger height opening with
      | none => none
      | some paid =>
          let outputs := appendedOutputIds ledgerPrefix.stagedOpenings [opening]
          some (.coinbase height paid outputs
              (sourceCoinbaseRegistry ledgerPrefix future coinbase),
            applyCoinbase ledgerPrefix.ledger height outputs)

theorem checkedSourceCoinbasePaid_sound (state : Ledger) (height : Nat)
    (opening : V8NoteOpening) (paid : Nat)
    (checked : checkedSourceCoinbasePaid? state height opening = some paid) :
    height ∉ state.issuedHeights ∧ 0 < height ∧
      nativeCoinbaseAmount height state.feeEscrow = some paid ∧
      nativeValue opening = paid ∧ opening.assetId = nativeAssetId ∧
      CanonicalNoteOpening opening := by
  unfold checkedSourceCoinbasePaid? at checked
  by_cases once : height ∉ state.issuedHeights
  · simp only [dif_pos once] at checked
    by_cases positive : 0 < height
    · simp only [dif_pos positive] at checked
      cases payment : nativeCoinbaseAmount height state.feeEscrow with
      | none => simp [payment] at checked
      | some scheduled =>
          simp only [payment] at checked
          by_cases outputChecks :
              nativeValue opening = scheduled ∧
                opening.assetId = nativeAssetId ∧ CanonicalNoteOpening opening
          · simp only [if_pos outputChecks, Option.some.injEq] at checked
            subst paid
            exact ⟨once, positive, rfl, outputChecks.1,
              outputChecks.2.1, outputChecks.2.2⟩
          · simp only [if_neg outputChecks] at checked
            cases checked
    · simp only [dif_neg positive] at checked
      cases checked
  · simp only [dif_neg once] at checked
    cases checked

/-- Every successful executable plan is a genuine finite-ledger protocol
step. The option's `none` branch remains the concrete rejected-input result. -/
theorem sourceCoinbasePlan_sound (ledgerPrefix : CurrentSourceLedgerPrefix)
    (future : List V8NoteOpening)
    (coinbase : Option (Nat × V8NoteOpening))
    (action : Action) (after : Ledger)
    (checked : sourceCoinbasePlan ledgerPrefix future coinbase = some (action, after)) :
    CurrentProtocolStep (program := program) (primitives := primitives)
      (sourceCoinbaseRegistry ledgerPrefix future coinbase)
      ledgerPrefix.ledger action after := by
  cases coinbase with
  | none =>
      simp only [sourceCoinbasePlan] at checked
      have pairEq := Option.some.inj checked
      rcases pairEq with ⟨rfl, rfl⟩
      exact CurrentProtocolStep.noCoinbase (program := program)
        (primitives := primitives) ledgerPrefix.ledger
  | some candidate =>
      rcases candidate with ⟨height, opening⟩
      simp only [sourceCoinbasePlan] at checked
      cases paidEq : checkedSourceCoinbasePaid? ledgerPrefix.ledger height opening with
      | none => simp [paidEq] at checked
      | some paid =>
          simp only [paidEq] at checked
          have pairEq := Option.some.inj checked
          rcases pairEq with ⟨rfl, rfl⟩
          have guards := checkedSourceCoinbasePaid_sound
            ledgerPrefix.ledger height opening paid paidEq
          let outputs := appendedOutputIds ledgerPrefix.stagedOpenings [opening]
          let registry := sourceCoinbaseRegistry ledgerPrefix future (some (height, opening))
          have realization :
              (∑ id ∈ outputs, nativeValue (registry id)) = paid := by
            calc
              (∑ id ∈ outputs, nativeValue (registry id)) =
                  ([opening].map nativeValue).sum := by
                change (∑ id ∈ appendedOutputIds ledgerPrefix.stagedOpenings [opening],
                  nativeValue (openingAt
                    (ledgerPrefix.stagedOpenings ++ [opening] ++ future) id)) = _
                exact appended_output_native_sum ledgerPrefix.stagedOpenings
                  [opening] future
              _ = nativeValue opening := by simp
              _ = paid := guards.2.2.2.1
          apply CurrentProtocolStep.coinbase (program := program)
            (primitives := primitives) ledgerPrefix.ledger height paid outputs registry
          · exact guards.1
          · exact guards.2.1
          · exact guards.2.2.1
          · intro id _
            rfl
          · exact realization

/-- Prefix update after successful issuance. Since spent positions are
already bounded by the old staged frontier, the singleton appended position
is fresh; the ledger's live set and staged opening range advance together. -/
def appendSourceCoinbasePrefix (ledgerPrefix : CurrentSourceLedgerPrefix)
    (height : Nat) (opening : V8NoteOpening) : CurrentSourceLedgerPrefix := by
  let outputs := appendedOutputIds ledgerPrefix.stagedOpenings [opening]
  refine {
    snapshot := ledgerPrefix.snapshot
    stagedOpenings := ledgerPrefix.stagedOpenings ++ [opening]
    stagedPrefix := ?_
    ledger := applyCoinbase ledgerPrefix.ledger height outputs
    priorSpends := ledgerPrefix.priorSpends
    spentNullifiers := ledgerPrefix.spentNullifiers
    liveCoverage := ?_
    spentExact := ?_
    spentInStagedRange := ?_
    priorPrefix := ledgerPrefix.priorPrefix
    priorRegistered := ledgerPrefix.priorRegistered
  }
  · rcases ledgerPrefix.stagedPrefix with ⟨suffix, suffixEq⟩
    refine ⟨suffix ++ [opening], ?_⟩
    calc
      ledgerPrefix.snapshot.openings ++ (suffix ++ [opening]) =
          (ledgerPrefix.snapshot.openings ++ suffix) ++ [opening] := by
        rw [← List.append_assoc]
      _ = ledgerPrefix.stagedOpenings ++ [opening] := by rw [suffixEq]
  · have appendedIds : outputs = {ledgerPrefix.stagedOpenings.length} := by
      simp [outputs, appendedOutputIds]
    have freshPosition : ledgerPrefix.stagedOpenings.length ∉ ledgerPrefix.ledger.spent := by
      intro member
      have inRange := ledgerPrefix.spentInStagedRange member
      exact (Nat.lt_irrefl ledgerPrefix.stagedOpenings.length)
        (Finset.mem_range.mp inRange)
    have rangeSplit :
        Finset.range (ledgerPrefix.stagedOpenings ++ [opening]).length \
            ledgerPrefix.ledger.spent =
          (Finset.range ledgerPrefix.stagedOpenings.length \
            ledgerPrefix.ledger.spent) ∪ outputs := by
      rw [appendedIds]
      ext id
      simp only [Finset.mem_sdiff, Finset.mem_range, Finset.mem_union,
        Finset.mem_singleton, List.length_append, List.length_singleton]
      constructor
      · rintro ⟨bound, notSpent⟩
        by_cases oldBound : id < ledgerPrefix.stagedOpenings.length
        · exact Or.inl ⟨oldBound, notSpent⟩
        · right
          have atEnd : id = ledgerPrefix.stagedOpenings.length := by omega
          exact atEnd
      · rintro (⟨oldBound, notSpent⟩ | atEnd)
        · exact ⟨by omega, notSpent⟩
        · subst id
          exact ⟨by omega, freshPosition⟩
    have outputsFresh : ∀ id ∈ outputs, id ∉ ledgerPrefix.ledger.spent := by
      intro id member
      rw [appendedIds] at member
      simp only [Finset.mem_singleton] at member
      subst id
      exact freshPosition
    have outputsMinus : outputs \ ledgerPrefix.ledger.spent = outputs := by
      ext id
      simp only [Finset.mem_sdiff]
      constructor
      · exact And.left
      · intro member
        exact ⟨member, outputsFresh id member⟩
    simp only [applyCoinbase]
    change ledgerPrefix.ledger.live ∪
      (outputs \ ledgerPrefix.ledger.spent) = _
    rw [outputsMinus]
    rw [ledgerPrefix.liveCoverage]
    exact rangeSplit.symm
  · intro id member
    have oldBound : id < ledgerPrefix.stagedOpenings.length :=
      Finset.mem_range.mp (ledgerPrefix.spentInStagedRange member)
    exact Finset.mem_range.mpr (by
      simp only [List.length_append, List.length_singleton]
      omega)
  · simpa only [applyCoinbase] using ledgerPrefix.spentExact

/-- The prefix update is available only on the successful checked branch;
invalid present coinbases remain `none`. -/
def checkedSourceCoinbasePrefixAfter (ledgerPrefix : CurrentSourceLedgerPrefix)
    (coinbase : Option (Nat × V8NoteOpening)) : Option CurrentSourceLedgerPrefix :=
  match coinbase with
  | none => some {
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
  | some (height, opening) =>
      match checkedSourceCoinbasePaid? ledgerPrefix.ledger height opening with
      | none => none
      | some _ => some (appendSourceCoinbasePrefix ledgerPrefix height opening)

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentSourceCoinbaseLedger
