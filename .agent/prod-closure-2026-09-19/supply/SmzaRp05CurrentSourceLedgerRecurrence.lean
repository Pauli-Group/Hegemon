import SmzaRp05CurrentSourceLedgerPrefix
import SmzaRp05CurrentSourceLedgerTransitions
import SmzaRp05CurrentSourceTransferConstructor
import SmzaRp05CurrentSourceSpendPositionSet
import SmzaRp05CurrentOutputLedgerPositions
import SmzaRp05SupplyClosureHistoricalInputs
import SmzaRp05CurrentFiniteLedgerHistory
import SmzaRp05CurrentSourceBlockReplay

/-! # Replay-produced current source ledger prefix updates

The parent native snapshot remains fixed while transactions in one block are
processed.  Their output openings extend a separate staged registry, and the
finite ledger's live/spent sets are updated from the actual finite transfer.
This file contains the recurrence lemmas used to construct those prefix
states; none of the represented invariants is an admission input.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrence

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
  (CurrentSourceLedgerPrefix CurrentSourceRun CurrentNativeSnapshot
    CurrentSourceSpend sourcePacked sourceSpendsOfRun sourceRunNullifiers
    stagedOpenings_length_le)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerTransitions
  (source_spend_nullifier_mem)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceTransferConstructor
  (currentSourceTransfer CurrentSuccessfulInputBindings)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceSpendPositionSet
  (source_spend_positions_toFinset_eq_positive_positions)
open HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness
  (designatedInputPacked designatedInputPosition positiveDesignatedInputSlots
    positiveDesignatedInputPositions)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative
  (inputSlotNative)
open HegemonCrypto.SmallWood.SmzaRp05CurrentOutputLedgerPositions
  (appendedOutputIds)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs (publicAnchor)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputs (outputOpenings)
open HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteLedgerHistory
  (CurrentProtocolStep)
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceBlockReplay
  (CurrentBlockReplayResult CurrentRunEnvelope output_records_accepted
    block_openings_canonical successful_block_extends_opening_log)
open SmzaFiniteLedgerSupply (Transfer applyTransfer)
open scoped Classical

set_option autoImplicit false

noncomputable section

private theorem prefix_append_staged
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (added : List V8NoteOpening) :
    ledgerPrefix.snapshot.openings.IsPrefix
      (ledgerPrefix.stagedOpenings ++ added) := by
  obtain ⟨suffix, suffixEq⟩ := ledgerPrefix.stagedPrefix
  refine ⟨suffix ++ added, ?_⟩
  rw [← List.append_assoc, suffixEq]

private theorem designated_position_eq_source_position
    {preamble : SmzaRp05StatementNamespace.Statement}
    {typed : V8PublicStatement}
    (run : CurrentSourceRun preamble typed) (input : Fin 2) :
    designatedInputPosition run input =
      HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.projectPosition
        (sourcePacked run) input.val := by
  have packedEq : designatedInputPacked run = sourcePacked run := by
    change SmzaQ38Recovery.packedFromRows run.source.data =
      SmzaQ38Recovery.packedFromRows run.source.data
    rfl
  change HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.projectPosition
      (designatedInputPacked run) input.val =
    HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.projectPosition
      (sourcePacked run) input.val
  exact congrArg
    (fun packed => HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.projectPosition
      packed input.val) packedEq

private theorem source_spend_uses_parent_snapshot
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

private theorem spentExact_after_source_transfer
    {preamble : SmzaRp05StatementNamespace.Statement}
    {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed)
    (admitted : publicAnchor (encodePublicStatement typed) ∈
      ledgerPrefix.snapshot.parent.history)
    (future : List V8NoteOpening) :
    (applyTransfer ledgerPrefix.ledger
      (currentSourceTransfer ledgerPrefix run future)).spent =
        ((ledgerPrefix.priorSpends ++
          sourceSpendsOfRun ledgerPrefix.snapshot run admitted).map
            CurrentSourceSpend.position).toFinset := by
  simp only [applyTransfer, List.map_append, List.toFinset_append]
  rw [ledgerPrefix.spentExact]
  rw [source_spend_positions_toFinset_eq_positive_positions
    ledgerPrefix.snapshot run admitted]
  simp only [currentSourceTransfer]

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

/-- Appending the exact output positions of a transfer preserves the finite
ledger's live-range invariant.  Inputs are old positions; new outputs occupy
the disjoint suffix, so the equation follows from the actual `applyTransfer`
update rather than from a supply/availability gate. -/
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

/-- Extend the proof-carrying ledger prefix after one accepted designated
source run.  The parent snapshot is unchanged; only the staged opening log,
finite-ledger transition, source-spend provenance and public nullifier list
advance. -/
def prefix_after_transfer
    {preamble : SmzaRp05StatementNamespace.Statement}
    {typed : V8PublicStatement}
    (ledgerPrefix : CurrentSourceLedgerPrefix)
    (run : CurrentSourceRun preamble typed)
    (future : List V8NoteOpening)
    (admitted : publicAnchor (encodePublicStatement typed) ∈
      ledgerPrefix.snapshot.parent.history)
    (bindings : CurrentSuccessfulInputBindings ledgerPrefix run admitted) :
    CurrentSourceLedgerPrefix := by
  classical
  let added := outputOpenings (encodePublicStatement typed) (designatedInputPacked run)
  let tx := currentSourceTransfer ledgerPrefix run future
  have inputsBound : tx.inputs ⊆ Finset.range ledgerPrefix.stagedOpenings.length := by
    intro position member
    have positivePosition : position ∈ positiveDesignatedInputPositions run := by
      simpa [tx, currentSourceTransfer] using member
    rcases Finset.mem_image.mp positivePosition with
      ⟨input, slotMember, positionMemberEq⟩
    have positive : 0 < inputSlotNative typed (designatedInputPacked run) input :=
      (Finset.mem_filter.mp slotMember).2
    have binding := bindings input positive
    have designatedPositionEq :=
      designated_position_eq_source_position run input
    have positionBound : designatedInputPosition run input <
        ledgerPrefix.snapshot.openings.length := by
      rw [designatedPositionEq]
      exact binding.1
    have stagedBound : designatedInputPosition run input <
        ledgerPrefix.stagedOpenings.length :=
      lt_of_lt_of_le positionBound (stagedOpenings_length_le ledgerPrefix)
    exact Finset.mem_range.mpr
      (by simpa only [positionMemberEq] using stagedBound)
  have spentRange : (applyTransfer ledgerPrefix.ledger tx).spent ⊆
      Finset.range (ledgerPrefix.stagedOpenings ++ added).length := by
    intro position member
    simp only [applyTransfer, Finset.mem_union] at member
    apply Finset.mem_range.mpr
    simp only [List.length_append]
    rcases member with oldSpent | newInput
    · have oldBound := Finset.mem_range.mp
        (ledgerPrefix.spentInStagedRange oldSpent)
      omega
    · have inputBound := Finset.mem_range.mp (inputsBound newInput)
      omega
  refine {
    snapshot := ledgerPrefix.snapshot
    stagedOpenings := ledgerPrefix.stagedOpenings ++ added
    stagedPrefix := prefix_append_staged ledgerPrefix added
    ledger := applyTransfer ledgerPrefix.ledger tx
    priorSpends := ledgerPrefix.priorSpends ++
      sourceSpendsOfRun ledgerPrefix.snapshot run admitted
    spentNullifiers := ledgerPrefix.spentNullifiers ++ sourceRunNullifiers run
    liveCoverage := ?_
    spentInStagedRange := spentRange
    spentExact := ?_
    priorPrefix := ?_
    priorRegistered := ?_
  }
  · exact liveCoverage_after_transfer ledgerPrefix added tx rfl
  · simpa only [tx, currentSourceTransfer] using
      spentExact_after_source_transfer ledgerPrefix run admitted future
  · intro spend member
    rcases List.mem_append.mp member with oldMember | newMember
    · exact ledgerPrefix.priorPrefix spend oldMember
    · have currentSnapshot := source_spend_uses_parent_snapshot
        ledgerPrefix.snapshot run admitted spend newMember
      exact ⟨[], by simp [currentSnapshot]⟩
  · intro spend member
    rcases List.mem_append.mp member with oldMember | newMember
    · have registered := ledgerPrefix.priorRegistered spend oldMember
      exact List.mem_append.mpr (Or.inl registered)
    · have nullifierMember := source_spend_nullifier_mem
        ledgerPrefix.snapshot run admitted spend newMember
      exact List.mem_append.mpr (Or.inr nullifierMember)

/-- Once all source transactions and the trailing coinbase have advanced the
ledger, rebase its native anchor to the block replay's appended frontier.
The finite ledger/spend registries are retained, while staged and anchored
opening lists become the same complete chronological log. -/
def rebase_prefix_after_block
    (before after : CurrentSourceLedgerPrefix)
    {transactions : List (Option CurrentRunEnvelope)}
    {coinbase : Option (Nat × V8NoteOpening)}
    (result : CurrentBlockReplayResult before.snapshot.parent
      before.spentNullifiers transactions coinbase)
    (snapshotEq : after.snapshot = before.snapshot)
    (stagedEq : after.stagedOpenings =
      before.snapshot.openings ++ result.openingsAdded) :
    CurrentSourceLedgerPrefix := by
  have snapshotOpeningsEq : after.snapshot.openings = before.snapshot.openings :=
    congrArg CurrentNativeSnapshot.openings snapshotEq
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
    rw [snapshotOpeningsEq] at suffixEq
    refine ⟨suffix ++ result.openingsAdded, ?_⟩
    rw [← List.append_assoc, suffixEq]

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerRecurrence
