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

def parsedChainCiphertextSummaries :
    List (List Byte) -> Option (List NoteCiphertextSummary)
  | [] => some []
  | wire :: rest => do
      let summary ← parseChainNoteCiphertext wire
      let summaries ← parsedChainCiphertextSummaries rest
      some (summary :: summaries)

def summariesMatchChainWire (world : ShieldedTransactionWorld) : Prop :=
  parsedChainCiphertextSummaries world.ciphertextBytes =
    some world.ciphertextSummaries

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

theorem parsed_chain_ciphertext_summaries_length
    {wires : List (List Byte)}
    {summaries : List NoteCiphertextSummary}
    (parsed : parsedChainCiphertextSummaries wires = some summaries) :
    summaries.length = wires.length := by
  induction wires generalizing summaries with
  | nil =>
      simp [parsedChainCiphertextSummaries] at parsed
      cases parsed
      rfl
  | cons wire rest ih =>
      unfold parsedChainCiphertextSummaries at parsed
      cases parsedWire : parseChainNoteCiphertext wire with
      | none =>
          simp [parsedWire] at parsed
      | some summary =>
          simp [parsedWire] at parsed
          cases parsedRest : parsedChainCiphertextSummaries rest with
          | none =>
              simp [parsedRest] at parsed
          | some restSummaries =>
              simp [parsedRest] at parsed
              cases parsed
              simp [ih parsedRest]

theorem same_allowed_leakage_of_public_chain_wire_and_placement
    {left right : ShieldedTransactionWorld}
    (leftParsed : summariesMatchChainWire left)
    (rightParsed : summariesMatchChainWire right)
    (publicInputs : samePublicInputs left right)
    (ciphertextBytes : left.ciphertextBytes = right.ciphertextBytes)
    (placement : samePlacement left right) :
    sameAllowedLeakage left right := by
  have summaries :
      left.ciphertextSummaries = right.ciphertextSummaries := by
    have parsedEq :
        some left.ciphertextSummaries =
          some right.ciphertextSummaries := by
      rw [← leftParsed, ← rightParsed, ciphertextBytes]
    exact Option.some.inj parsedEq
  exact
    same_allowed_leakage_of_public_wire_and_placement
      publicInputs
      ⟨ciphertextBytes, summaries⟩
      placement

theorem same_allowed_leakage_iff_observer_view_eq
    {left right : ShieldedTransactionWorld} :
    sameAllowedLeakage left right ↔ observerView left = observerView right := by
  rfl

end Observer
end Privacy
end Hegemon
