import SmzaRp05BalanceCore
import SmzaRp05FinalSupplySoundness
import FiniteLedgerSupplyR8
import LifetimeIssuanceR2
import SmzaRp05CurrentBalanceCanonicality
import SmzaRp05SupplyClosureInputNative
import SmzaRp05SupplyClosureOutputs
import SmzaRp05SupplyClosureOutputFrame

/-! # Current-primitive finite-note supply conservation

This is the finite-note ledger invariant from `SmzaRp05SemanticLedger`, with
the transfer's canonicality predicate generalized to the current public
primitive.  The accepted packed witness is the current BalanceCore
projection.  No aggregate input-availability or conservation conclusion is
an input to these arithmetic theorems.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteLedgerHistory

open scoped BigOperators Classical
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Consensus
open SmzaFiniteLedgerSupply
open HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness (outputNative)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputs
  (outputOpenings activeOutputSlots)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

variable {program : RelationProgramComponents}
variable {primitives : V8SemanticPrimitives}

/-- The note-value projection carried by the current RP05 typed statement.
It deliberately uses the current BalanceCore note-call map, not the retained
R8/RP03 `Transfer.witness` projection. -/
def currentWitness (tx : Transfer) : V8Witness :=
  SmzaRp05BalanceCore.projectTypedWitness tx.statement tx.packed

/-- The current typed public statement fixes the flags of the actual emitted
output-opening stream. Thus the sum of native values in that stream is the
typed current output value, without a separate realization assumption. -/
theorem current_accepted_output_stream_native
    (statement : V8PublicStatement) (packed : List Nat)
    {primitives : V8SemanticPrimitives}
    (canonical : CanonicalPublicStatement primitives statement) :
    ((outputOpenings (encodePublicStatement statement) packed).map nativeValue).sum =
      outputNative statement packed := by
  have flag0 :=
    HegemonCrypto.SmallWood.SmzaRp05CurrentBalanceCanonicality.encoded_output_flag_for
      statement canonical (output := 0) (by decide)
  have flag1 :=
    HegemonCrypto.SmallWood.SmzaRp05CurrentBalanceCanonicality.encoded_output_flag_for
      statement canonical (output := 1) (by decide)
  rw [HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative.output_native_two_slots]
  simp only [outputOpenings, activeOutputSlots, List.filter_cons, List.filter_nil]
  simp only [flag0, flag1]
  split_ifs <;> simp_all
    [HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputFrame.noteCall]

/-- One finite-ledger transition, retaining actual protocol premises while
allowing the current typed public canonicality predicate.  Transfer
acceptance is exact to the selected current relation program. -/
inductive CurrentProtocolStep (registry : Nat → V8NoteOpening) :
    Ledger → Action → Ledger → Prop where
  | transfer (state : Ledger) (tx : Transfer)
      (canonical : CanonicalPublicStatement primitives tx.statement)
      (accepted : program.AcceptsPacked (encodePublicStatement tx.statement) tx.packed)
      (historical : tx.inputs ⊆ state.live ∪ state.spent)
      (fresh : Disjoint tx.inputs state.spent)
      (inputFrames : ∀ id ∈ tx.inputs,
        exactV8NoteCommitment (tx.inputOpening id) =
          exactV8NoteCommitment (registry id))
      (outputFrames : ∀ id ∈ tx.outputs,
        exactV8NoteCommitment (tx.outputOpening id) =
          exactV8NoteCommitment (registry id))
      (inputRealization : (∑ id ∈ tx.inputs,
        nativeValue (tx.inputOpening id)) =
        inputValueForAsset (currentWitness tx) nativeAssetId)
      (outputRealization : (∑ id ∈ tx.outputs,
        nativeValue (tx.outputOpening id)) =
        outputValueForAsset (currentWitness tx) nativeAssetId) :
      CurrentProtocolStep registry state (.transfer tx) (applyTransfer state tx)
  | coinbase (state : Ledger) (height paid : Nat) (outputs : Finset Nat)
      (opening : Nat → V8NoteOpening)
      (once : height ∉ state.issuedHeights)
      (positive : 0 < height)
      (payment : nativeCoinbaseAmount height state.feeEscrow = some paid)
      (frames : ∀ id ∈ outputs,
        exactV8NoteCommitment (opening id) =
          exactV8NoteCommitment (registry id))
      (realization : (∑ id ∈ outputs, nativeValue (opening id)) = paid) :
      CurrentProtocolStep registry state
        (.coinbase height paid outputs opening)
        (applyCoinbase state height outputs)
  | noCoinbase (state : Ledger) :
      CurrentProtocolStep registry state .noCoinbase (burnEscrow state)

/-- The current accepted typed relation yields the exact native balance
equation used by the finite-note transfer transition. -/
theorem current_accepted_native_balance (tx : Transfer)
    [SmzaRp05BalanceCore.BalanceCertificate program]
    (canonical : CanonicalPublicStatement primitives tx.statement)
    (accepted : program.AcceptsPacked (encodePublicStatement tx.statement) tx.packed) :
    inputValueForAsset (currentWitness tx) nativeAssetId =
      outputValueForAsset (currentWitness tx) nativeAssetId + tx.statement.fee := by
  exact SmzaRp05BalanceCore.accepted_native_balance canonical accepted

/-- An accepted current transfer's native input is bounded by the actual live
finite-note ledger whenever its input positions are historically present and
fresh.  The bound is derived from those identities; it is not an admission
guard or a caller-supplied aggregate-availability premise. -/
theorem current_transfer_input_le_live
    {registry : Nat → V8NoteOpening}
    {before after : Ledger} (tx : Transfer)
    (step : CurrentProtocolStep (program := program) (primitives := primitives)
      registry before (.transfer tx) after)
    (noCollision : ¬ badCollision registry (.transfer tx)) :
    SmzaRp05FinalSupplySoundness.inputNative tx.statement tx.packed ≤
      wealth registry before.live := by
  cases step with
  | transfer _ _ _ historical fresh inputFrames _
      inputRealization _ =>
    have available := historical_membership_and_freshness_give_available
      before tx.inputs historical fresh
    have noIn : ¬ ∃ id ∈ tx.inputs,
        noteCollision (tx.inputOpening id) (registry id) := by
      intro collision
      exact noCollision (Or.inl collision)
    have inputsEqual := (binding_sum inputFrames noIn).trans inputRealization
    have valueBound := wealth_mono registry available
    change inputValueForAsset (currentWitness tx) nativeAssetId ≤
      wealth registry before.live
    rw [← inputsEqual]
    exact valueBound

/-- One current finite-ledger step preserves native potential against the
exact issuance allowance.  Collision exclusion is explicit so the caller
can route it to the charged source-collision outcome. -/
theorem current_step_supply_invariant
    [SmzaRp05BalanceCore.BalanceCertificate program]
    {registry : Nat → V8NoteOpening}
    {before after : Ledger} {action : Action} {initial : Nat}
    (step : CurrentProtocolStep (program := program) (primitives := primitives)
      registry before action after)
    (noCollision : ¬ badCollision registry action)
    (prior : potential registry before ≤ initial + allowance before) :
    potential registry after ≤ initial + allowance after := by
  cases step with
  | transfer tx canonical accepted historical fresh inFrames outFrames
      inReal outReal =>
    have available := historical_membership_and_freshness_give_available
      before tx.inputs historical fresh
    have noIn : ¬ ∃ id ∈ tx.inputs,
        noteCollision (tx.inputOpening id) (registry id) := by
      intro collision
      exact noCollision (Or.inl collision)
    have noOut : ¬ ∃ id ∈ tx.outputs,
        noteCollision (tx.outputOpening id) (registry id) := by
      intro collision
      exact noCollision (Or.inr collision)
    have ins := (binding_sum inFrames noIn).trans inReal
    have outs := (binding_sum outFrames noOut).trans outReal
    have balance := current_accepted_native_balance (primitives := primitives)
      tx canonical accepted
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

/-- Chronological finite-ledger execution with current-primitive transfer
acceptance. -/
inductive CurrentExecution (registry : Nat → V8NoteOpening) :
    Ledger → List Action → Ledger → Prop where
  | nil (state : Ledger) : CurrentExecution registry state [] state
  | cons {before middle after : Ledger} {action : Action} {actions : List Action}
      (step : CurrentProtocolStep (program := program) (primitives := primitives)
        registry before action middle)
      (rest : CurrentExecution registry middle actions after) :
      CurrentExecution registry before (action :: actions) after

/-- Whole-history current finite-note conservation.  Every transfer has its
own accepted current witness; the only excluded economic exception is the
explicitly charged note-commitment collision event. -/
theorem current_execution_supply_invariant
    [SmzaRp05BalanceCore.BalanceCertificate program]
    {registry : Nat → V8NoteOpening}
    {before after : Ledger} {actions : List Action} {initial : Nat}
    (run : CurrentExecution (program := program) (primitives := primitives)
      registry before actions after)
    (good : ∀ action ∈ actions, ¬ badCollision registry action)
    (prior : potential registry before ≤ initial + allowance before) :
    potential registry after ≤ initial + allowance after := by
  induction run with
  | nil => exact prior
  | cons step rest ih =>
      apply ih
      · intro action member
        exact good action (List.mem_cons_of_mem _ member)
      · exact current_step_supply_invariant step (good _ (by simp)) prior

/-- The finite issued-height set is bounded by the checked schedule. -/
theorem current_lifetime_issuance_bound (state : Ledger) :
    allowance state ≤ maxMonetarySupply := by
  exact blockSubsidy_finset_sum_le state.issuedHeights

/-- Current finite-note endpoint: accepted transition history implies its
live native wealth cannot exceed initial wealth plus lifetime issuance. -/
theorem current_deterministic_lifetime_cap
    [SmzaRp05BalanceCore.BalanceCertificate program]
    {registry : Nat → V8NoteOpening}
    {before after : Ledger} {actions : List Action} {initial : Nat}
    (run : CurrentExecution (program := program) (primitives := primitives)
      registry before actions after)
    (good : ∀ action ∈ actions, ¬ badCollision registry action)
    (genesis : potential registry before ≤ initial + allowance before) :
    wealth registry after.live ≤ initial + maxMonetarySupply := by
  have conserved := current_execution_supply_invariant run good genesis
  have cap := current_lifetime_issuance_bound after
  unfold potential at conserved
  omega

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFiniteLedgerHistory
