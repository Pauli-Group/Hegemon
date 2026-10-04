import SmzaRp05BalanceCore
import LifetimeIssuanceR2

/-!
# RP05 accepted-relation supply soundness

This is the closed arithmetic supply projection of the current RP05 relation.
Every transfer branch carries actual `AcceptsPacked` evidence for the same
relation program.  Consequently its native input/output equation is derived
from `accepted_native_balance`; it is not a transition premise.

Coinbase branches carry only the concrete consensus payment result and the
fresh-height rule.  Their issuance contribution is derived from
`nativeCoinbaseAmount` and the checked finite halving schedule.  No caller
supplies a conservation theorem, an issuance cap, or a target supply equality.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness

open scoped BigOperators Classical
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Consensus

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

variable {program : RelationProgramComponents}
  [SmzaRp05BalanceCore.BalanceCertificate program]

/-- The native-value view fixed by an accepted packed RP05 witness. -/
def typedWitness (statement : V8PublicStatement) (packed : List Nat) : V8Witness :=
  SmzaRp05BalanceCore.projectTypedWitness statement packed

def inputNative (statement : V8PublicStatement) (packed : List Nat) : Nat :=
  inputValueForAsset (typedWitness statement packed) nativeAssetId

def outputNative (statement : V8PublicStatement) (packed : List Nat) : Nat :=
  outputValueForAsset (typedWitness statement packed) nativeAssetId

/-- Exact numerical projection of the live native ledger.  `circulating`
excludes fees awaiting the block's coinbase decision. -/
structure SupplyState where
  circulating : Nat
  feeEscrow : Nat
  issuedHeights : Finset Nat
deriving DecidableEq

def potential (state : SupplyState) : Nat :=
  state.circulating + state.feeEscrow

def issuanceAllowance (state : SupplyState) : Nat :=
  ∑ height ∈ state.issuedHeights, blockSubsidy height

/-- The three concrete block-action branches relevant to native supply. -/
inductive AcceptedAction where
  | transfer (statement : V8PublicStatement) (packed : List Nat)
  | coinbase (height paid : Nat)
  | noCoinbase

/-- Concrete branch transition.  Transfer conservation is deliberately not
a constructor field: the post-state is the actual spend/output/fee update and
the accepted relation proves that update conserves `potential`.

`available` is the state-membership projection that the spent native amount
is present before subtraction.  It is not a balance or conservation premise.
-/
inductive AcceptedStep (program : RelationProgramComponents) :
    SupplyState → AcceptedAction → SupplyState → Prop where
  | transfer (before : SupplyState) (statement : V8PublicStatement)
      (packed : List Nat)
      (canonical : ∃ primitives : V8SemanticPrimitives,
        CanonicalPublicStatement primitives statement)
      (accepted : program.AcceptsPacked (encodePublicStatement statement) packed)
      (available : inputNative statement packed ≤ before.circulating) :
      AcceptedStep program before (.transfer statement packed)
        { circulating := before.circulating - inputNative statement packed +
            outputNative statement packed
          feeEscrow := before.feeEscrow + statement.fee
          issuedHeights := before.issuedHeights }
  | coinbase (before : SupplyState) (height paid : Nat)
      (fresh : height ∉ before.issuedHeights)
      (positive : 0 < height)
      (payment : nativeCoinbaseAmount height before.feeEscrow = some paid) :
      AcceptedStep program before (.coinbase height paid)
        { circulating := before.circulating + paid
          feeEscrow := 0
          issuedHeights := insert height before.issuedHeights }
  | noCoinbase (before : SupplyState) :
      AcceptedStep program before .noCoinbase
        { before with feeEscrow := 0 }

inductive AcceptedExecution (program : RelationProgramComponents) :
    SupplyState → List AcceptedAction → SupplyState → Prop where
  | nil (state : SupplyState) : AcceptedExecution program state [] state
  | cons {before middle after : SupplyState}
      {action : AcceptedAction} {actions : List AcceptedAction}
      (step : AcceptedStep program before action middle)
      (rest : AcceptedExecution program middle actions after) :
      AcceptedExecution program before (action :: actions) after

/-- Native transfer balance follows from the accepted current relation. -/
theorem accepted_transfer_balance
    {statement : V8PublicStatement} {packed : List Nat}
    (canonical : ∃ primitives : V8SemanticPrimitives,
      CanonicalPublicStatement primitives statement)
    (accepted : program.AcceptsPacked (encodePublicStatement statement) packed) :
    inputNative statement packed =
      outputNative statement packed + statement.fee := by
  rcases canonical with ⟨primitives, canonical⟩
  exact SmzaRp05BalanceCore.accepted_native_balance canonical accepted

/-- One accepted concrete branch preserves the initial-plus-issued invariant.
Neither transfer conservation nor a coinbase issuance amount is assumed. -/
theorem accepted_step_supply_invariant
    {before after : SupplyState} {action : AcceptedAction} {initial : Nat}
    (step : AcceptedStep program before action after)
    (prior : potential before ≤ initial + issuanceAllowance before) :
    potential after ≤ initial + issuanceAllowance after := by
  cases step with
  | transfer statement packed canonical accepted available =>
      have balance := accepted_transfer_balance canonical accepted
      simp only [potential, issuanceAllowance] at prior ⊢
      omega
  | coinbase height paid fresh positive payment =>
      have paidEq : paid = blockSubsidy height + before.feeEscrow := by
        unfold nativeCoinbaseAmount checkedU64Add at payment
        dsimp only at payment
        split at payment
        · exact (Option.some.inj payment).symm
        · contradiction
      have allowanceEq :
          issuanceAllowance
              { circulating := before.circulating + paid
                feeEscrow := 0
                issuedHeights := insert height before.issuedHeights } =
            blockSubsidy height + issuanceAllowance before := by
        simp [issuanceAllowance, Finset.sum_insert, fresh]
      rw [allowanceEq]
      simp only [potential, Nat.add_zero] at prior ⊢
      omega
  | noCoinbase =>
      simp only [potential, issuanceAllowance, Nat.add_zero] at prior ⊢
      omega

/-- Whole accepted histories conserve the native potential against exactly
the heights they issued. -/
theorem accepted_execution_supply_invariant
    {before after : SupplyState} {actions : List AcceptedAction} {initial : Nat}
    (run : AcceptedExecution program before actions after)
    (genesis : potential before ≤ initial + issuanceAllowance before) :
    potential after ≤ initial + issuanceAllowance after := by
  induction run with
  | nil => exact genesis
  | cons step rest ih =>
      exact ih (accepted_step_supply_invariant step genesis)

/-- The concrete set of issued heights is bounded by the checked integer-floor
halving schedule; no lifetime-issuance premise is accepted from the caller. -/
theorem lifetime_issuance_bound (state : SupplyState) :
    issuanceAllowance state ≤ maxMonetarySupply := by
  exact blockSubsidy_finset_sum_le state.issuedHeights

/-- Final RP05 supply endpoint.  A single accepted relation program governs
every transfer in `run`; branch semantics derive conservation, and the checked
halving theorem derives lifetime issuance. -/
theorem accepted_rp05_lifetime_issuance_and_conservation
    {before after : SupplyState} {actions : List AcceptedAction} {initial : Nat}
    (run : AcceptedExecution program before actions after)
    (genesis : potential before ≤ initial + issuanceAllowance before) :
    potential after ≤ initial + issuanceAllowance after ∧
      issuanceAllowance after ≤ maxMonetarySupply ∧
      after.circulating ≤ initial + maxMonetarySupply := by
  have conserved := accepted_execution_supply_invariant run genesis
  have issued := lifetime_issuance_bound after
  refine ⟨conserved, issued, ?_⟩
  unfold potential at conserved
  omega

end
end HegemonCrypto.SmallWood.SmzaRp05FinalSupplySoundness
