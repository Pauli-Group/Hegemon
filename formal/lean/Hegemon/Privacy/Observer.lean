import Hegemon.Transaction.PublicInputs
import Hegemon.Wallet.NoteCiphertextWire

namespace Hegemon
namespace Privacy
namespace Observer

open Hegemon.Transaction.PublicInputs
open Hegemon.Wallet.NoteCiphertextWire

structure ObserverView where
  publicInputs : PublicInputShape
  ciphertextBytes : List (List Byte)
  ciphertextSummaries : List NoteCiphertextSummary
  blockHeight : Nat
  actionIndex : Nat
deriving DecidableEq, Repr

structure PrivateWitness where
  spendSecretSeeds : List Nat
  inputNoteValues : List Nat
  inputAssetIds : List Nat
  outputNoteValues : List Nat
  outputAssetIds : List Nat
  noteRandomnessSeeds : List Nat
  notePlaintextSeeds : List Nat
  memoPlaintextSeeds : List Nat
deriving DecidableEq, Repr

structure ShieldedTransactionWorld where
  publicInputs : PublicInputShape
  ciphertextBytes : List (List Byte)
  ciphertextSummaries : List NoteCiphertextSummary
  blockHeight : Nat
  actionIndex : Nat
  privateWitness : PrivateWitness
  proverRandomnessSeed : Nat
deriving DecidableEq, Repr

def observerView (world : ShieldedTransactionWorld) : ObserverView :=
  { publicInputs := world.publicInputs
    ciphertextBytes := world.ciphertextBytes
    ciphertextSummaries := world.ciphertextSummaries
    blockHeight := world.blockHeight
    actionIndex := world.actionIndex }

def sameAllowedLeakage
    (left right : ShieldedTransactionWorld) : Prop :=
  observerView left = observerView right

def samePublicInputs
    (left right : ShieldedTransactionWorld) : Prop :=
  left.publicInputs = right.publicInputs

def sameCiphertextWire
    (left right : ShieldedTransactionWorld) : Prop :=
  left.ciphertextBytes = right.ciphertextBytes
    ∧ left.ciphertextSummaries = right.ciphertextSummaries

def samePlacement
    (left right : ShieldedTransactionWorld) : Prop :=
  left.blockHeight = right.blockHeight
    ∧ left.actionIndex = right.actionIndex

theorem observer_view_ignores_private_witness
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness) :
    observerView { world with privateWitness := privateWitness } =
      observerView world := by
  rfl

theorem observer_view_ignores_prover_randomness
    (world : ShieldedTransactionWorld)
    (proverRandomnessSeed : Nat) :
    observerView { world with proverRandomnessSeed := proverRandomnessSeed } =
      observerView world := by
  rfl

theorem observer_view_ignores_private_witness_and_randomness
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat) :
    observerView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed } =
      observerView world := by
  rfl

theorem same_allowed_leakage_of_public_wire_and_placement
    {left right : ShieldedTransactionWorld}
    (publicInputs : samePublicInputs left right)
    (ciphertexts : sameCiphertextWire left right)
    (placement : samePlacement left right) :
    sameAllowedLeakage left right := by
  cases left
  cases right
  simp [sameAllowedLeakage, observerView, samePublicInputs, sameCiphertextWire,
    samePlacement] at publicInputs ciphertexts placement ⊢
  exact ⟨publicInputs, ciphertexts.left, ciphertexts.right,
    placement.left, placement.right⟩

theorem same_allowed_leakage_iff_observer_view_eq
    {left right : ShieldedTransactionWorld} :
    sameAllowedLeakage left right ↔ observerView left = observerView right := by
  rfl

end Observer
end Privacy
end Hegemon
