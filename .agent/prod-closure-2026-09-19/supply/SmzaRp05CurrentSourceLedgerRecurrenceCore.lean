import SmzaRp05CurrentSourceLedgerPrefix
import SmzaRp05CurrentSourceLedgerTransitions
import SmzaRp05CurrentSourceSpendPositionSet
import SmzaRp05CurrentOutputLedgerPositions
import SmzaRp05CurrentSourceBlockReplay
import SmzaRp05SupplyClosureHistoricalInputs
import FiniteLedgerSupplyR8

/-! # Structural recurrence core for current source ledger prefixes

These lemmas update only proof-carrying history/ledger invariants.  They do
not supply an admission gate; actual transfer authorization and extraction
are composed by the source-shaped recurrence layer.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
  (CurrentSourceLedgerPrefix CurrentNativeSnapshot CurrentSourceSpend
    CurrentSourceRun sourcePacked sourceSpendsOfRun sourceRunNullifiers)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions
  (source_spend_nullifier_mem)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceSpendPositionSet
  (source_spend_positions_toFinset_eq_positive_positions)
open HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness
  (positiveDesignatedInputPositions)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative (inputSlotNative)
open HegemonCrypto.SmallWood.SmzaRp05CurrentOutputLedgerPositions
  (appendedOutputIds)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs (publicAnchor)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceBlockReplay
  (CurrentBlockReplayResult CurrentRunEnvelope output_records_accepted
    block_openings_canonical successful_block_extends_opening_log)
open SmzaFiniteLedgerSupply (Transfer applyTransfer)
open scoped Classical

set_option autoImplicit false

noncomputable section

theorem prefix_append_staged
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (added : List V8NoteOpening) :
    ledgerPrefix.snapshot.openings.IsPrefix
      (ledgerPrefix.stagedOpenings ++ added) := by
  obtain ⟨suffix, suffixEq⟩ := ledgerPrefix.stagedPrefix
  refine ⟨suffix ++ added, ?_⟩
  rw [← List.append_assoc, suffixEq]

theorem source_spend_uses_parent_snapshot
    {preamble : SmzaRp05StatementNamespace.Statement}
    {typed : V8PublicStatement}
    (snapshot : CurrentNativeSnapshot)
    (run : CurrentSourceRun preamble typed)
    (admitted : publicAnchor (encodePublicStatement typed) ∈ snapshot.parent.history)
    (spend : CurrentSourceSpend)
    (member : spend ∈ sourceSpendsOfRun snapshot run admitted) :
    spend.snapshot.openings = snapshot.openings := by
  simp only [sourceSpendsOfRun] at member
  rcases List.mem_filterMap.mp member with ⟨input, _, produced⟩
  by_cases positive : 0 < inputSlotNative typed (sourcePacked run) input
  · simp only [dif_pos positive, Option.some.injEq] at produced
    cases produced
    rfl
  · simp only [dif_neg positive] at produced
    cases produced

theorem spentExact_after_transfer
    {preamble : SmzaRp05StatementNamespace.Statement}
    {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed)
    (admitted : publicAnchor (encodePublicStatement typed) ∈
      ledgerPrefix.snapshot.parent.history)
    (tx : Transfer)
    (inputsEq : tx.inputs = positiveDesignatedInputPositions run) :
    (applyTransfer ledgerPrefix.ledger tx).spent =
      ((ledgerPrefix.priorSpends ++
        sourceSpendsOfRun ledgerPrefix.snapshot run admitted).map
          CurrentSourceSpend.position).toFinset := by
  simp only [applyTransfer, List.map_append, List.toFinset_append]
  rw [ledgerPrefix.spentExact]
  rw [source_spend_positions_toFinset_eq_positive_positions
    ledgerPrefix.snapshot run admitted]
  rw [inputsEq]

private theorem range_append_is_prefix_union
    (prior added : List V8NoteOpening) :
    Finset.range (prior.length + added.length) =
      Finset.range prior.length ∪ appendedOutputIds prior added := by
  classical
  apply Finset.ext
  intro position
  simp only [Finset.mem_range, Finset.mem_union, appendedOutputIds,
    Finset.mem_image]
  constructor
  · intro bound
    by_cases inPrior : position < prior.length
    · exact Or.inl inPrior
    · right
      refine ⟨position - prior.length, ?_, ?_⟩
      · omega
      · omega
  · rintro (inPrior | ⟨index, indexBound, offsetEq⟩)
    · omega
    · omega

theorem liveCoverage_after_transfer
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (added : List V8NoteOpening)
    (tx : Transfer)
    (outputEq : tx.outputs = appendedOutputIds ledgerPrefix.stagedOpenings added) :
    (applyTransfer ledgerPrefix.ledger tx).live =
      Finset.range (ledgerPrefix.stagedOpenings ++ added).length \
        (applyTransfer ledgerPrefix.ledger tx).spent := by
  classical
  let oldRange := Finset.range ledgerPrefix.stagedOpenings.length
  let outputs := tx.outputs
  have rangeEq : Finset.range (ledgerPrefix.stagedOpenings ++ added).length =
      oldRange ∪ outputs := by
    rw [List.length_append]
    change Finset.range (ledgerPrefix.stagedOpenings.length + added.length) =
      Finset.range ledgerPrefix.stagedOpenings.length ∪ tx.outputs
    rw [outputEq]
    exact range_append_is_prefix_union ledgerPrefix.stagedOpenings added
  change (ledgerPrefix.ledger.live \ tx.inputs) ∪
      (tx.outputs \ (ledgerPrefix.ledger.spent ∪ tx.inputs)) =
    Finset.range (ledgerPrefix.stagedOpenings ++ added).length \
      (ledgerPrefix.ledger.spent ∪ tx.inputs)
  rw [ledgerPrefix.liveCoverage, rangeEq]
  ext position
  simp only [Finset.mem_sdiff, Finset.mem_union]
  tauto

def rebase_prefix_after_block
    (before after : CurrentSourceLedgerPrefix)
    {transactions : List (Option CurrentRunEnvelope)}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult before.snapshot.parent
      before.spentNullifiers transactions coinbase)
    (openingsEq : after.snapshot.openings = before.snapshot.openings)
    (stagedEq : after.stagedOpenings =
      before.snapshot.openings ++ result.openingsAdded) :
    CurrentSourceLedgerPrefix := by
  let finalOpenings := before.snapshot.openings ++ result.openingsAdded
  let nextSnapshot : CurrentNativeSnapshot := {
    parent := result.nativeAfter
    openings := finalOpenings
    canonical := by
      intro opening member
      rcases List.mem_append.mp member with oldOpening | newOpening
      · exact before.snapshot.canonical opening oldOpening
      · exact block_openings_canonical result
          (output_records_accepted result.runs) opening newOpening
    replay := successful_block_extends_opening_log before.snapshot.openings
      before.snapshot.replay result (output_records_accepted result.runs)
  }
  refine {
    snapshot := nextSnapshot
    stagedOpenings := finalOpenings
    stagedPrefix := ⟨[], by
      change finalOpenings ++ [] = finalOpenings
      exact List.append_nil _⟩
    ledger := after.ledger
    priorSpends := after.priorSpends
    spentNullifiers := after.spentNullifiers
    liveCoverage := ?_
    spentInStagedRange := ?_
    spentExact := after.spentExact
    priorPrefix := ?_
    priorRegistered := after.priorRegistered
  }
  · simpa only [stagedEq, finalOpenings] using after.liveCoverage
  · simpa only [stagedEq, finalOpenings] using after.spentInStagedRange
  · intro spend member
    obtain ⟨suffix, suffixEq⟩ := after.priorPrefix spend member
    refine ⟨suffix ++ result.openingsAdded, ?_⟩
    calc
      spend.snapshot.openings ++ (suffix ++ result.openingsAdded) =
          (spend.snapshot.openings ++ suffix) ++ result.openingsAdded := by
        simp only [List.append_assoc]
      _ = after.snapshot.openings ++ result.openingsAdded := by rw [suffixEq]
      _ = before.snapshot.openings ++ result.openingsAdded := by rw [openingsEq]

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrenceCore
