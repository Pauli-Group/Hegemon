import Hegemon.Transaction.Poseidon2V8LeftFeedForwardPrimitives
import Mathlib.Data.List.Basic

/-! Generic shape and canonical-word laws for the current executable hashes.
The proofs use round shape, modular addition and fold invariants. They assume
no hash-output law, input canonicality, collision bound or Rust equivalence. -/
namespace HegemonCrypto.NativePrivateSpendCurrentCanonicalHash

open Hegemon.Transaction.Poseidon2V8SemanticSpecification

namespace K
export Hegemon.Transaction.Poseidon2Width16Kernel
  (width fieldAdd applyMds4 externalLinearLayer internalLinearLayer externalRound
    internalRound permutation externalRoundConstantsInitial internalRoundConstants
    externalRoundConstantsTerminal external_linear_layer_length
    internal_linear_layer_length external_round_length internal_round_length)
end K

namespace P
export Hegemon.Transaction.Poseidon2V8LeftFeedForwardPrimitives
  (compress14 compressed_digest_has_seven_lanes)
end P

set_option autoImplicit false
noncomputable section

/-- Exact length and canonical Goldilocks words; no cryptographic assertion. -/
def GoodWords (n : Nat) (words : List Nat) : Prop :=
  words.length = n ∧ ∀ word ∈ words, word < fieldModulus

private def WordBounds (words : List Nat) : Prop :=
  ∀ word ∈ words, word < fieldModulus

private theorem modulus_positive : 0 < fieldModulus := by decide

private theorem field_add_lt (left right : Nat) :
    K.fieldAdd left right < fieldModulus := by
  change (left + right) % fieldModulus < fieldModulus
  exact Nat.mod_lt _ modulus_positive

private theorem bounded_getD (words : List Nat) :
    WordBounds words → ∀ index, words.getD index 0 < fieldModulus := by
  induction words with
  | nil =>
    intro _ _
    exact modulus_positive
  | cons head tail ih =>
    intro bounds index
    have tailBounds : WordBounds tail :=
      fun word present => bounds word (List.mem_cons_of_mem head present)
    cases index with
    | zero => exact bounds head (List.mem_cons_self (a := head) (l := tail))
    | succ index => exact ih tailBounds index

private theorem mds4_bounds (input : List Nat) : WordBounds (K.applyMds4 input) := by
  intro word present
  simp only [K.applyMds4, List.mem_cons, List.not_mem_nil, or_false] at present
  rcases present with rfl | rfl | rfl | rfl <;> exact field_add_lt _ _

private theorem external_layer_bounds (state : List Nat) :
    WordBounds (K.externalLinearLayer state) := by
  intro word present
  unfold K.externalLinearLayer at present
  rcases List.mem_map.mp present with ⟨index, _, rfl⟩
  exact bounded_getD (K.applyMds4 _) (mds4_bounds _) (index / 4)

private theorem internal_layer_bounds (state : List Nat) :
    WordBounds (K.internalLinearLayer state) := by
  intro word present
  unfold K.internalLinearLayer at present
  rcases List.mem_map.mp present with ⟨lane, _, rfl⟩
  exact field_add_lt _ _

private theorem external_round_good (state constants : List Nat) :
    GoodWords K.width (K.externalRound state constants) := by
  exact ⟨K.external_round_length state constants, external_layer_bounds _⟩

private theorem internal_round_good (state : List Nat) (constant : Nat) :
    GoodWords K.width (K.internalRound state constant) := by
  exact ⟨K.internal_round_length state constant, internal_layer_bounds _⟩

private theorem foldl_invariant {Item State : Type*}
    (step : State → Item → State) (invariant : State → Prop)
    (preserves : ∀ state item, invariant state → invariant (step state item))
    (items : List Item) :
    ∀ initial, invariant initial → invariant (items.foldl step initial) := by
  induction items with
  | nil => intro initial holds; exact holds
  | cons item items ih =>
    intro initial holds
    exact ih (step initial item) (preserves initial item holds)

/-- The kernel returns sixteen canonical words for every input list. -/
theorem permutation_canonical (state : List Nat) :
    GoodWords 16 (K.permutation state) := by
  have initial : GoodWords K.width (K.externalLinearLayer state) :=
    ⟨K.external_linear_layer_length state, external_layer_bounds state⟩
  have external := foldl_invariant K.externalRound (GoodWords K.width)
    (fun current constants _ => external_round_good current constants)
    K.externalRoundConstantsInitial (K.externalLinearLayer state) initial
  have internal := foldl_invariant K.internalRound (GoodWords K.width)
    (fun current constant _ => internal_round_good current constant)
    K.internalRoundConstants
    (K.externalRoundConstantsInitial.foldl K.externalRound (K.externalLinearLayer state))
    external
  have terminal := foldl_invariant K.externalRound (GoodWords K.width)
    (fun current constants _ => external_round_good current constants)
    K.externalRoundConstantsTerminal
    (K.internalRoundConstants.foldl K.internalRound
      (K.externalRoundConstantsInitial.foldl K.externalRound (K.externalLinearLayer state)))
    internal
  exact terminal

private theorem initial_state_good : GoodWords 16 poseidon2V8InitialState := by
  constructor
  · exact List.length_replicate ..
  · intro word present
    obtain rfl := List.eq_of_mem_replicate present
    exact modulus_positive

private theorem absorb_block_good (domain : Nat) (inputs : List Nat)
    (blockCount : Nat) (state : List Nat) (block : Nat) :
    GoodWords 16 (poseidon2V8AbsorbBlock domain inputs blockCount state block) := by
  unfold poseidon2V8AbsorbBlock
  exact permutation_canonical _

private theorem sponge_blocks_good (domain : Nat) (inputs : List Nat) (blockCount : Nat) :
    GoodWords 16 ((List.range blockCount).foldl
      (poseidon2V8AbsorbBlock domain inputs blockCount) poseidon2V8InitialState) := by
  exact foldl_invariant (poseidon2V8AbsorbBlock domain inputs blockCount)
    (GoodWords 16) (fun state block _ => absorb_block_good domain inputs blockCount state block)
    (List.range blockCount) poseidon2V8InitialState initial_state_good

/-- The unchanged NOTE sponge has seven canonical words, for arbitrary inputs
and domain. No concrete sponge call or closed message is evaluated. -/
theorem sponge_canonical (domain : Nat) (inputs : List Nat) :
    GoodWords 7 (poseidon2V8Sponge domain inputs) := by
  let blockCount := Nat.max 1
    ((inputs.length + Hegemon.Transaction.Poseidon2Width16Kernel.rate - 1) /
      Hegemon.Transaction.Poseidon2Width16Kernel.rate)
  let finalState := (List.range blockCount).foldl
    (poseidon2V8AbsorbBlock domain inputs blockCount) poseidon2V8InitialState
  have shape : GoodWords 16 finalState := sponge_blocks_good domain inputs blockCount
  change GoodWords 7 (finalState.take digestWords)
  constructor
  · have enough : digestWords ≤ finalState.length := by
      rw [shape.1]
      decide
    exact List.length_take_of_le enough
  · intro word present
    exact shape.2 word (List.mem_of_mem_take present)

/-- COMPFF returns seven canonical words even for noncanonical operands. Its
final modular additions suffice; the raw permutation is not evaluated. -/
theorem compff_canonical (domain : Nat) (left right : Digest) :
    GoodWords 7 (P.compress14 domain left right) := by
  constructor
  · exact P.compressed_digest_has_seven_lanes domain left right
  · intro word present
    unfold P.compress14 at present
    rcases List.mem_map.mp present with ⟨lane, _, rfl⟩
    exact field_add_lt _ _

end
end HegemonCrypto.NativePrivateSpendCurrentCanonicalHash
