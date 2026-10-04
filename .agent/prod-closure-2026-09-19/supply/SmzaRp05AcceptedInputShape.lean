import SmzaRp05BalanceCore
import SmzaRp05NullifierSourceDirection
import HegemonCrypto.SmallWoodV8Smz9SemanticDecoder
import HegemonCrypto.SmallWoodV8Smz9PositionBits

/-!
# Current RP05 accepted input shape (source-only)

This transports only decoder facts that depend on packed canonicality and the
current nonlinear direction-bit certificate.  The RP05 packed acceptance is
the actual current program's predicate.  No RP03 accepted predicate, Merkle
root equality or semantic-refinement premise is introduced.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedInputShape

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram

set_option autoImplicit false

/-- The RP05 typed projection reads all 32 sibling digests at the current
4/41 call offsets. Each limb is a canonical field word. -/
theorem accepted_siblings_exact
    {program : RelationProgramComponents}
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Nat) :
    (SmzaRp05BalanceCore.projectInput statement packed input).siblings.length = 32 ∧
      ∀ digest,
        digest ∈ (SmzaRp05BalanceCore.projectInput statement packed input).siblings →
        ExactWords 7 digest := by
  refine ⟨by simp [SmzaRp05BalanceCore.projectInput], ?_⟩
  intro digest member
  dsimp only [SmzaRp05BalanceCore.projectInput] at member
  obtain ⟨level, _, rfl⟩ := List.mem_map.mp member
  exact HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.exact_words_range_map 7 _
    (by
      intro limb _
      exact HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packed_word_canonical
        accepted.2.1 _)

/-- The current nonlinear Boolean roots certify all 32 packed direction
bits, hence the decoded numeric position lies inside the depth-32 tree. -/
theorem accepted_position_bounded
    {program : RelationProgramComponents}
    (directions : SmzaRp05NullifierSource.DirectionCertificate program)
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Fin 2) :
    (SmzaRp05BalanceCore.projectInput statement packed input.val).position <
      2 ^ 32 := by
  change HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.projectPosition
    packed input.val < 2 ^ 32
  exact SmzaRp05NullifierSource.accepted_position_lt_32
    directions accepted input

/-- Each orientation chosen by the current accepted packed rows is the
corresponding bit of the same decoded numeric position. -/
theorem accepted_position_bit_orientation
    {program : RelationProgramComponents}
    (directions : SmzaRp05NullifierSource.DirectionCertificate program)
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (statement : V8PublicStatement) (input : Fin 2) (level : Fin 32) :
    ((SmzaRp05BalanceCore.projectInput statement packed input.val).position /
      2 ^ level.val) % 2 =
      HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.directionWord
        packed input.val level.val := by
  change ((HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.projectPosition
    packed input.val / 2 ^ level.val) % 2) =
    HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.directionWord
      packed input.val level.val
  unfold HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.projectPosition
  apply HegemonCrypto.SmallWood.V8Smz9PositionBits.binary_natural_sum_bit
    _ 32 _ level.isLt
  intro bit bound
  rcases SmzaRp05NullifierSource.accepted_direction_bit_boolean
      directions accepted input ⟨bit, bound⟩ with zero | one
  · rw [HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.directionWord,
      HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord, zero]
    exact Nat.zero_le 1
  · rw [HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.directionWord,
      HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord, one]

end HegemonCrypto.SmallWood.SmzaRp05AcceptedInputShape
