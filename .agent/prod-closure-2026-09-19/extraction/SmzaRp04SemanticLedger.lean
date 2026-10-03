import SmzaRp04BalanceCore
import FiniteLedgerSupplyR8

/-!
Actual RP04 finite-ledger reduction.

The ledger representation and authenticated-note collision event are reused
from `SmzaFiniteLedgerSupply`, but its RP03 witness projection and extraction
predicate are not.  Transfers below use the RP04 projection whose note calls
are exactly `1,38,75,78`, and extraction failure means failure of the actual
`SmzaRp04Components.program.AcceptsPacked` predicate.

Once actual RP04 acceptance and complete note-word binding hold, the transfer
step preserves the native-asset potential.  Thus a finite supply violation is
included in actual RP04 extraction failure or note binding failure; no third
semantic-refinement probability premise remains.
-/

namespace HegemonCrypto.SmallWood.SmzaRp04SemanticLedger

open scoped BigOperators Classical
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open SmzaFiniteLedgerSupply
open Hegemon.Consensus

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
attribute [local instance] Classical.propDecidable

/-- The actual RP04 typed view.  In particular, its note calls are
`SmzaRp04BalanceCore.noteCall = [1,38,75,78].getD`. -/
def rp04Witness (tx : Transfer) : V8Witness :=
  SmzaRp04BalanceCore.projectTypedWitness tx.statement tx.packed

def extractionFailure (tx : Transfer) : Prop :=
  ¬ SmzaRp04Components.program.AcceptsPacked
      (encodePublicStatement tx.statement) tx.packed

def badExtraction : Action → Prop
  | .transfer tx => extractionFailure tx
  | _ => False

/-- RP04 transition relation over the already checked finite ledger model.
Only the witness projection differs from the retained R8/RP03 relation. -/
inductive ProtocolStep (registry : Nat → V8NoteOpening) :
    Ledger → Action → Ledger → Prop where
  | transfer (state : Ledger) (tx : Transfer)
      (canonical : CanonicalPublicStatement exactV8SemanticPrimitives tx.statement)
      (historical : tx.inputs ⊆ state.live ∪ state.spent)
      (fresh : Disjoint tx.inputs state.spent)
      (inputFrames : ∀ id ∈ tx.inputs,
        exactV8NoteCommitment (tx.inputOpening id) = exactV8NoteCommitment (registry id))
      (outputFrames : ∀ id ∈ tx.outputs,
        exactV8NoteCommitment (tx.outputOpening id) = exactV8NoteCommitment (registry id))
      (inputRealization : (∑ id ∈ tx.inputs, nativeValue (tx.inputOpening id)) =
        inputValueForAsset (rp04Witness tx) nativeAssetId)
      (outputRealization : (∑ id ∈ tx.outputs, nativeValue (tx.outputOpening id)) =
        outputValueForAsset (rp04Witness tx) nativeAssetId) :
      ProtocolStep registry state (.transfer tx) (applyTransfer state tx)
  | coinbase (state : Ledger) (height paid : Nat) (outputs : Finset Nat)
      (opening : Nat → V8NoteOpening)
      (once : height ∉ state.issuedHeights)
      (positive : 0 < height)
      (payment : nativeCoinbaseAmount height state.feeEscrow = some paid)
      (frames : ∀ id ∈ outputs,
        exactV8NoteCommitment (opening id) = exactV8NoteCommitment (registry id))
      (realization : (∑ id ∈ outputs, nativeValue (opening id)) = paid) :
      ProtocolStep registry state (.coinbase height paid outputs opening)
        (applyCoinbase state height outputs)
  | noCoinbase (state : Ledger) :
      ProtocolStep registry state .noCoinbase (burnEscrow state)

inductive Execution (registry : Nat → V8NoteOpening) :
    Ledger → List Action → Ledger → Prop where
  | nil (state : Ledger) : Execution registry state [] state
  | cons {before middle after : Ledger} {action : Action} {actions : List Action}
      (step : ProtocolStep registry before action middle)
      (rest : Execution registry middle actions after) :
      Execution registry before (action :: actions) after

/-- Successful actual RP04 extraction supplies the exact Nat equality consumed
by a transfer step. -/
theorem extracted_native_balance (tx : Transfer)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives tx.statement)
    (success : ¬ extractionFailure tx) :
    inputValueForAsset (rp04Witness tx) nativeAssetId =
      outputValueForAsset (rp04Witness tx) nativeAssetId + tx.statement.fee := by
  have accepted : SmzaRp04Components.program.AcceptsPacked
      (encodePublicStatement tx.statement) tx.packed := Classical.not_not.mp success
  exact SmzaRp04BalanceCore.accepted_native_balance canonical accepted

theorem step_supply_invariant {registry : Nat → V8NoteOpening}
    {before after : Ledger} {action : Action} {initial : Nat}
    (step : ProtocolStep registry before action after)
    (noExtraction : ¬ badExtraction action)
    (noCollision : ¬ SmzaFiniteLedgerSupply.badCollision registry action)
    (prior : potential registry before ≤ initial + allowance before) :
    potential registry after ≤ initial + allowance after := by
  cases step with
  | transfer tx canonical historical fresh inFrames outFrames inReal outReal =>
    have available := historical_membership_and_freshness_give_available
      before tx.inputs historical fresh
    have noIn : ¬ ∃ id ∈ tx.inputs,
        noteCollision (tx.inputOpening id) (registry id) :=
      fun h => noCollision (Or.inl h)
    have noOut : ¬ ∃ id ∈ tx.outputs,
        noteCollision (tx.outputOpening id) (registry id) :=
      fun h => noCollision (Or.inr h)
    have ins := (binding_sum inFrames noIn).trans inReal
    have outs := (binding_sum outFrames noOut).trans outReal
    have balance := extracted_native_balance tx canonical noExtraction
    rw [← ins, ← outs] at balance
    have removed := Finset.sum_sdiff
      (f := fun id => nativeValue (registry id)) available
    have added := wealth_union_le registry (before.live \ tx.inputs)
      (tx.outputs \ (before.spent ∪ tx.inputs))
    have outputBound := wealth_mono registry
      (Finset.sdiff_subset : tx.outputs \ (before.spent ∪ tx.inputs) ⊆ tx.outputs)
    change wealth registry (before.live \ tx.inputs) + wealth registry tx.inputs =
      wealth registry before.live at removed
    simp only [potential, allowance, applyTransfer] at *
    omega
  | coinbase height paid outputs opening once positive payment frames realization =>
    have outputValue := (binding_sum frames noCollision).trans realization
    have added := wealth_union_le registry before.live (outputs \ before.spent)
    have outputBound := wealth_mono registry
      (Finset.sdiff_subset : outputs \ before.spent ⊆ outputs)
    have paidEq : paid = blockSubsidy height + before.feeEscrow := by
      unfold nativeCoinbaseAmount checkedU64Add at payment
      dsimp only at payment
      split at payment
      · exact (Option.some.inj payment).symm
      · contradiction
    have budget : allowance (applyCoinbase before height outputs) =
        blockSubsidy height + allowance before := by
      simp [allowance, applyCoinbase, Finset.sum_insert, once]
    rw [budget]
    simp only [potential, applyCoinbase, Nat.add_zero] at *
    omega
  | noCoinbase =>
    simp only [potential, burnEscrow, allowance, Nat.add_zero] at *
    omega

theorem execution_supply_invariant {registry : Nat → V8NoteOpening}
    {before after : Ledger} {actions : List Action} {initial : Nat}
    (run : Execution registry before actions after)
    (good : ∀ action ∈ actions,
      ¬ badExtraction action ∧
        ¬ SmzaFiniteLedgerSupply.badCollision registry action)
    (prior : potential registry before ≤ initial + allowance before) :
    potential registry after ≤ initial + allowance after := by
  induction run with
  | nil => exact prior
  | cons step rest ih =>
    apply ih
    · intro action member
      exact good action (List.mem_cons_of_mem _ member)
    · exact step_supply_invariant step (good _ (by simp)).1
        (good _ (by simp)).2 prior

theorem deterministic_lifetime_cap {registry : Nat → V8NoteOpening}
    {before after : Ledger} {actions : List Action} {initial : Nat}
    (run : Execution registry before actions after)
    (good : ∀ action ∈ actions,
      ¬ badExtraction action ∧
        ¬ SmzaFiniteLedgerSupply.badCollision registry action)
    (genesis : potential registry before ≤ initial + allowance before) :
    wealth registry after.live ≤ initial + Hegemon.Consensus.maxMonetarySupply := by
  have conserved := execution_supply_invariant run good genesis
  have cap := Hegemon.Consensus.blockSubsidy_finset_sum_le after.issuedHeights
  change allowance after ≤ Hegemon.Consensus.maxMonetarySupply at cap
  unfold potential at conserved
  omega

/-- Narrow deterministic interface exported by this ledger proof.  It is kept
independent of any draft accepted-transcript security composition: a later
adapter only has to copy these four predicates and `reduces` into the chosen
checked security interface. -/
structure LedgerLifetimeReduction (Outcome : Type*) where
  violation : Outcome → Prop
  acceptedExtractionFailure : Outcome → Prop
  commitmentBindingFailure : Outcome → Prop
  semanticLedgerFailure : Outcome → Prop
  reduces : ∀ outcome, violation outcome →
    acceptedExtractionFailure outcome ∨
      commitmentBindingFailure outcome ∨ semanticLedgerFailure outcome

/-- Concrete `LifetimeReduction` for the actual RP04 ledger.  The semantic
branch is empty: after actual extraction and note binding, the deterministic
Nat ledger theorem rules out the violation. -/
def lifetimeReduction {Outcome : Type*}
    (registry : Outcome → Nat → V8NoteOpening)
    (before after : Outcome → Ledger)
    (actions : Outcome → List Action) (initial : Nat)
    (runs : ∀ outcome, Execution (registry outcome) (before outcome)
      (actions outcome) (after outcome))
    (genesis : ∀ outcome, potential (registry outcome) (before outcome) ≤
      initial + allowance (before outcome)) :
    LedgerLifetimeReduction Outcome where
  violation := fun outcome =>
    initial + Hegemon.Consensus.maxMonetarySupply <
      wealth (registry outcome) (after outcome).live
  acceptedExtractionFailure := fun outcome =>
    ∃ action ∈ actions outcome, badExtraction action
  commitmentBindingFailure := fun outcome =>
    ∃ action ∈ actions outcome,
      SmzaFiniteLedgerSupply.badCollision (registry outcome) action
  semanticLedgerFailure := fun _ => False
  reduces := by
    intro outcome violation
    by_cases extraction : ∃ action ∈ actions outcome, badExtraction action
    · exact Or.inl extraction
    by_cases collision : ∃ action ∈ actions outcome,
        SmzaFiniteLedgerSupply.badCollision (registry outcome) action
    · exact Or.inr (Or.inl collision)
    · exfalso
      have good : ∀ action ∈ actions outcome,
          ¬ badExtraction action ∧
            ¬ SmzaFiniteLedgerSupply.badCollision (registry outcome) action := by
        intro action member
        exact ⟨fun bad => extraction ⟨action, member, bad⟩,
          fun bad => collision ⟨action, member, bad⟩⟩
      have bounded := deterministic_lifetime_cap (runs outcome) good (genesis outcome)
      omega

theorem semantic_ledger_failure_mass_zero {Outcome : Type} [Fintype Outcome]
    (weight : Outcome → ℝ)
    (registry : Outcome → Nat → V8NoteOpening)
    (before after : Outcome → Ledger)
    (actions : Outcome → List Action) (initial : Nat)
    (runs : ∀ outcome, Execution (registry outcome) (before outcome)
      (actions outcome) (after outcome))
    (genesis : ∀ outcome, potential (registry outcome) (before outcome) ≤
      initial + allowance (before outcome)) :
    SmzaFiniteLedgerSupply.mass weight
      (lifetimeReduction registry before after actions initial runs genesis).semanticLedgerFailure =
        0 := by
  simp [SmzaFiniteLedgerSupply.mass, lifetimeReduction]

end
end HegemonCrypto.SmallWood.SmzaRp04SemanticLedger
