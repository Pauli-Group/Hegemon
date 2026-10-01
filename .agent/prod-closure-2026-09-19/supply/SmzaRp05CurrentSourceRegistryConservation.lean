import SmzaRp05CurrentSourceLedgerPrefix

/-! # Exact registry-extension accounting for the source ledger

Appending a block's future outputs does not change the native wealth already
live at the source prefix. The occupied-position bound comes from the prefix's
internal live-coverage invariant, not a new source admission predicate.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSourceRegistryConservation

open Hegemon.Transaction.Poseidon2V8SemanticSpecification (V8NoteOpening)
open SmzaRp05CurrentSourceLedgerPrefix
  (CurrentSourceLedgerPrefix initialCurrentSourceLedgerPrefix)
open SmzaRp05HistoricalTree (openingAt)
open SmzaFiniteLedgerSupply (nativeValue wealth potential allowance)
open scoped Classical BigOperators

set_option autoImplicit false
noncomputable section

private theorem opening_at_append_occupied
    (prior future : List V8NoteOpening) (position : Nat)
    (occupied : position < prior.length) :
    openingAt (prior ++ future) position = openingAt prior position := by
  have fullBound : position < (prior ++ future).length := by
    simp only [List.length_append]
    omega
  simp only [openingAt, if_pos occupied, if_pos fullBound]
  rw [List.getD_append _ _ _ _ occupied]

/-- Every live position is already occupied in the exact staged registry. -/
theorem source_live_position_occupied
    (ledgerPrefix : CurrentSourceLedgerPrefix) (position : Nat)
    (live : position ∈ ledgerPrefix.ledger.live) :
    position < ledgerPrefix.stagedOpenings.length := by
  rw [ledgerPrefix.liveCoverage] at live
  exact Finset.mem_range.mp (Finset.mem_sdiff.mp live).1

/-- Future block outputs cannot alter the wealth of existing live notes. -/
theorem source_live_wealth_registry_extension
    (ledgerPrefix : CurrentSourceLedgerPrefix) (future : List V8NoteOpening) :
    wealth (openingAt (ledgerPrefix.stagedOpenings ++ future)) ledgerPrefix.ledger.live =
      wealth (openingAt ledgerPrefix.stagedOpenings) ledgerPrefix.ledger.live := by
  unfold wealth
  apply Finset.sum_congr rfl
  intro position live
  exact congrArg nativeValue (opening_at_append_occupied
    ledgerPrefix.stagedOpenings future position
    (source_live_position_occupied ledgerPrefix position live))

/-- The same exact identity includes the carried fee escrow. -/
theorem source_potential_registry_extension
    (ledgerPrefix : CurrentSourceLedgerPrefix) (future : List V8NoteOpening) :
    potential (openingAt (ledgerPrefix.stagedOpenings ++ future)) ledgerPrefix.ledger =
      potential (openingAt ledgerPrefix.stagedOpenings) ledgerPrefix.ledger := by
  unfold potential
  rw [source_live_wealth_registry_extension]

/-- A source prefix rebased to the complete native append log has precisely
the potential measured by that log, without a different economic state. -/
theorem source_potential_after_exact_rebase
    (before after : CurrentSourceLedgerPrefix) (added : List V8NoteOpening)
    (sameLedger : after.ledger = before.ledger)
    (sameOpenings : after.stagedOpenings = before.stagedOpenings ++ added) :
    potential (openingAt after.stagedOpenings) after.ledger =
      potential (openingAt (before.stagedOpenings ++ added)) before.ledger := by
  rw [sameLedger, sameOpenings]

/-- Genesis establishes the empty economic boundary for every future
registry extension. No caller-supplied initial wealth bound is required. -/
theorem initial_source_potential_zero (future : List V8NoteOpening) :
    potential (openingAt
      (initialCurrentSourceLedgerPrefix.stagedOpenings ++ future))
      initialCurrentSourceLedgerPrefix.ledger = 0 := by
  simp [potential, wealth, initialCurrentSourceLedgerPrefix]

theorem initial_source_allowance_zero :
    allowance initialCurrentSourceLedgerPrefix.ledger = 0 := by
  simp [allowance, initialCurrentSourceLedgerPrefix]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentSourceRegistryConservation
