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

def activeFlagCount : List Nat -> Nat
  | [] => 0
  | flag :: rest =>
      (if flag = 1 then 1 else 0) + activeFlagCount rest

def activeOutputCount (shape : PublicInputShape) : Nat :=
  activeFlagCount shape.outputFlags

def activeFlagCountBefore : List Nat -> Nat -> Nat
  | [], _ => 0
  | _ :: _, 0 => 0
  | flag :: rest, index + 1 =>
      (if flag = 1 then 1 else 0) + activeFlagCountBefore rest index

theorem output_slot_active_flag_count_nonzero
    {flags : List Nat}
    {commitments ciphertextHashes : List Digest}
    {index : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    (slot :
      OutputSlotAt
        flags
        commitments
        ciphertextHashes
        index
        1
        publicCommitment
        publicCiphertextHash) :
    activeFlagCount flags ≠ 0 := by
  induction flags generalizing commitments ciphertextHashes index with
  | nil =>
      cases commitments <;> cases ciphertextHashes <;> cases index <;>
        simp [OutputSlotAt] at slot
  | cons flag rest ih =>
      cases commitments with
      | nil =>
          cases ciphertextHashes <;> cases index <;>
            simp [OutputSlotAt] at slot
      | cons commitment commitmentsTail =>
          cases ciphertextHashes with
          | nil =>
              cases index <;> simp [OutputSlotAt] at slot
          | cons ciphertextHash ciphertextHashesTail =>
              cases index with
              | zero =>
                  have active : flag = 1 := by
                    exact slot.left.symm
                  simp [activeFlagCount, active]
              | succ indexTail =>
                  have tailNonzero :
                      activeFlagCount rest ≠ 0 :=
                    ih
                      (commitments := commitmentsTail)
                      (ciphertextHashes := ciphertextHashesTail)
                      (index := indexTail)
                      slot
                  unfold activeFlagCount
                  by_cases active : flag = 1
                  · simp [active]
                  · simp [active, tailNonzero]

theorem output_slot_active_rank_lt_count
    {flags : List Nat}
    {commitments ciphertextHashes : List Digest}
    {index : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    (slot :
      OutputSlotAt
        flags
        commitments
        ciphertextHashes
        index
        1
        publicCommitment
        publicCiphertextHash) :
    activeFlagCountBefore flags index < activeFlagCount flags := by
  induction flags generalizing commitments ciphertextHashes index with
  | nil =>
      cases commitments <;> cases ciphertextHashes <;> cases index <;>
        simp [OutputSlotAt] at slot
  | cons flag rest ih =>
      cases commitments with
      | nil =>
          cases ciphertextHashes <;> cases index <;>
            simp [OutputSlotAt] at slot
      | cons commitment commitmentsTail =>
          cases ciphertextHashes with
          | nil =>
              cases index <;> simp [OutputSlotAt] at slot
          | cons ciphertextHash ciphertextHashesTail =>
              cases index with
              | zero =>
                  have active : flag = 1 := by
                    exact slot.left.symm
                  dsimp [activeFlagCountBefore, activeFlagCount]
                  rw [if_pos active]
                  rw [Nat.add_comm]
                  exact Nat.zero_lt_succ (activeFlagCount rest)
              | succ indexTail =>
                  have tailLt :
                      activeFlagCountBefore rest indexTail <
                        activeFlagCount rest :=
                    ih
                      (commitments := commitmentsTail)
                      (ciphertextHashes := ciphertextHashesTail)
                      (index := indexTail)
                      slot
                  dsimp [activeFlagCountBefore, activeFlagCount]
                  by_cases active : flag = 1
                  · simpa [active] using Nat.add_lt_add_left tailLt 1
                  · simpa [active] using tailLt

def validObserverChainSurface
    (world : ShieldedTransactionWorld) : Prop :=
  validPublicInputShape world.publicInputs = true
    ∧ summariesMatchChainWire world
    ∧ world.ciphertextBytes.length =
        activeOutputCount world.publicInputs

def summaryHasChainCiphertextFormat
    (summary : NoteCiphertextSummary) : Prop :=
  summary.cryptoSuite = cryptoSuiteGamma
    ∧ summary.kemLen = mlKemCiphertextLen

def summariesHaveChainCiphertextFormat
    (summaries : List NoteCiphertextSummary) : Prop :=
  ∀ summary, summary ∈ summaries -> summaryHasChainCiphertextFormat summary

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

theorem parsed_chain_ciphertext_summaries_have_chain_format
    {wires : List (List Byte)}
    {summaries : List NoteCiphertextSummary}
    (parsed : parsedChainCiphertextSummaries wires = some summaries) :
    summariesHaveChainCiphertextFormat summaries := by
  induction wires generalizing summaries with
  | nil =>
      simp [parsedChainCiphertextSummaries,
        summariesHaveChainCiphertextFormat] at parsed ⊢
      cases parsed
      simp
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
              intro parsedSummary inSummaries
              simp [summariesHaveChainCiphertextFormat] at ih
              simp at inSummaries
              cases inSummaries with
              | inl sameSummary =>
                  cases sameSummary
                  exact parsed_chain_ciphertext_has_gamma_suite_and_fixed_kem
                    parsedWire
              | inr inRest =>
                  exact ih parsedRest parsedSummary inRest

theorem observer_view_summaries_have_chain_format
    {world : ShieldedTransactionWorld}
    (parsed : summariesMatchChainWire world) :
    summariesHaveChainCiphertextFormat world.ciphertextSummaries :=
  parsed_chain_ciphertext_summaries_have_chain_format parsed

theorem valid_observer_chain_surface_summaries_have_chain_format
    {world : ShieldedTransactionWorld}
    (valid : validObserverChainSurface world) :
    summariesHaveChainCiphertextFormat world.ciphertextSummaries :=
  observer_view_summaries_have_chain_format valid.right.left

theorem valid_observer_chain_surface_ciphertext_count
    {world : ShieldedTransactionWorld}
    (valid : validObserverChainSurface world) :
    world.ciphertextSummaries.length =
      activeOutputCount world.publicInputs := by
  exact
    (parsed_chain_ciphertext_summaries_length
      valid.right.left).trans
      valid.right.right

theorem same_public_inputs_active_output_count
    {left right : ShieldedTransactionWorld}
    (publicInputs : samePublicInputs left right) :
    activeOutputCount left.publicInputs =
      activeOutputCount right.publicInputs :=
  congrArg activeOutputCount publicInputs

theorem same_allowed_leakage_preserves_active_output_count
    {left right : ShieldedTransactionWorld}
    (same : sameAllowedLeakage left right) :
    activeOutputCount left.publicInputs =
      activeOutputCount right.publicInputs := by
  exact
    congrArg
      (fun view : ObserverView =>
        activeOutputCount view.publicInputs)
      same

theorem same_public_valid_observer_surfaces_ciphertext_count
    {left right : ShieldedTransactionWorld}
    (leftValid : validObserverChainSurface left)
    (rightValid : validObserverChainSurface right)
    (publicInputs : samePublicInputs left right) :
    left.ciphertextSummaries.length =
      right.ciphertextSummaries.length := by
  calc
    left.ciphertextSummaries.length =
        activeOutputCount left.publicInputs :=
      valid_observer_chain_surface_ciphertext_count leftValid
    _ = activeOutputCount right.publicInputs :=
      same_public_inputs_active_output_count publicInputs
    _ = right.ciphertextSummaries.length := by
      exact
        (valid_observer_chain_surface_ciphertext_count
          rightValid).symm

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

theorem same_allowed_leakage_of_valid_observer_chain_surfaces
    {left right : ShieldedTransactionWorld}
    (leftValid : validObserverChainSurface left)
    (rightValid : validObserverChainSurface right)
    (publicInputs : samePublicInputs left right)
    (ciphertextBytes : left.ciphertextBytes = right.ciphertextBytes)
    (placement : samePlacement left right) :
    sameAllowedLeakage left right :=
  same_allowed_leakage_of_public_chain_wire_and_placement
    leftValid.right.left
    rightValid.right.left
    publicInputs
    ciphertextBytes
    placement

theorem same_allowed_leakage_iff_observer_view_eq
    {left right : ShieldedTransactionWorld} :
    sameAllowedLeakage left right ↔ observerView left = observerView right := by
  rfl

end Observer
end Privacy
end Hegemon
