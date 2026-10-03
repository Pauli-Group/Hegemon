import HegemonCrypto.SmallWoodV8Smz9SourceTailRows

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableTail

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (packedWitnessLaneRows)
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization (AuthHashFinals auth_exact_words_getD)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

inductive TailFamily where
  | source | roleDifference | roleSelector | roleInverse | booleans | numeric | multiplication | ranges
deriving DecidableEq, Repr

def TailFamily.base : TailFamily → Nat
  | .source => 0 | .roleDifference => 2 | .roleSelector => 9 | .roleInverse => 10
  | .booleans => 11 | .numeric => 12 | .multiplication => 13 | .ranges => 16

def TailFamily.width : TailFamily → Nat
  | .source => 2 | .roleDifference => 7 | .roleSelector | .roleInverse | .booleans | .numeric => 1
  | .multiplication => 3 | .ranges => 23

def tailFamilies : List TailFamily :=
  [.source,.roleDifference,.roleSelector,.roleInverse,.booleans,.numeric,.multiplication,.ranges]

theorem tail_family_extent (family : TailFamily) : family.base + family.width ≤ 39 := by
  cases family <;> decide

theorem tail_family_widths_sum : (tailFamilies.map TailFamily.width).sum = 39 := by decide

theorem tail_family_intervals_disjoint :
    tailFamilies.Pairwise (fun left right => left.base + left.width ≤ right.base) := by decide

theorem tail_families_cover_every_row :
    ∀ row : Fin 39, tailFamilies.any (fun family =>
      decide (family.base ≤ row.val ∧ row.val < family.base + family.width)) = true := by decide

def tailFamilyWord (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (family : TailFamily) (offset lane : Nat) : Nat :=
  let aux := sourceAux statement.stablecoin witness.stablecoin
  match family with
  | .source => stableSourceWord statement witness (offset * 64 + lane)
  | .roleDifference => sourceRoleWord statement witness hashes lane offset
  | .roleSelector => sourceRoleSelector statement witness hashes lane
  | .roleInverse => sourceRoleInverse statement witness hashes lane
  | .booleans => (sourceBooleanValues statement.stablecoin witness.stablecoin aux).getD lane 0
  | .numeric => (sourceNumericValues aux).getD lane 0
  | .multiplication =>
      if offset = 0 then (sourceMultiplication statement witness aux lane).a
      else if offset = 1 then (sourceMultiplication statement witness aux lane).b
      else (sourceMultiplication statement witness aux lane).c
  | .ranges => (sourceRangeDigits statement.stablecoin witness.stablecoin aux).getD (offset * 64 + lane) 0

theorem source_tail_at_9 (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (lane : Nat) :
    sourceTailWord statement witness hashes 9 lane = sourceRoleSelector statement witness hashes lane := by
  unfold sourceTailWord
  dsimp only
  rw [if_neg (by decide : ¬(9 < 2)),
    if_neg (by decide : ¬(9 < 9)),
    if_pos (rfl : 9 = 9)]

theorem source_tail_at_10 (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (lane : Nat) :
    sourceTailWord statement witness hashes 10 lane = sourceRoleInverse statement witness hashes lane := by
  unfold sourceTailWord
  dsimp only
  rw [if_neg (by decide : ¬(10 < 2)),
    if_neg (by decide : ¬(10 < 9)),
    if_neg (by decide : ¬(10 = 9)),
    if_pos (rfl : 10 = 10)]

theorem source_tail_at_11 (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (lane : Nat) :
    sourceTailWord statement witness hashes 11 lane = (sourceBooleanValues statement.stablecoin witness.stablecoin (sourceAux statement.stablecoin witness.stablecoin)).getD lane 0 := by
  unfold sourceTailWord
  dsimp only
  rw [if_neg (by decide : ¬(11 < 2)),
    if_neg (by decide : ¬(11 < 9)),
    if_neg (by decide : ¬(11 = 9)),
    if_neg (by decide : ¬(11 = 10)),
    if_pos (rfl : 11 = 11)]

theorem source_tail_at_12 (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (lane : Nat) :
    sourceTailWord statement witness hashes 12 lane = (sourceNumericValues (sourceAux statement.stablecoin witness.stablecoin)).getD lane 0 := by
  unfold sourceTailWord
  dsimp only
  rw [if_neg (by decide : ¬(12 < 2)),
    if_neg (by decide : ¬(12 < 9)),
    if_neg (by decide : ¬(12 = 9)),
    if_neg (by decide : ¬(12 = 10)),
    if_neg (by decide : ¬(12 = 11)),
    if_pos (rfl : 12 = 12)]

theorem source_tail_at_13 (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (lane : Nat) :
    sourceTailWord statement witness hashes 13 lane = (sourceMultiplication statement witness (sourceAux statement.stablecoin witness.stablecoin) lane).a := by
  unfold sourceTailWord
  dsimp only
  rw [if_neg (by decide : ¬(13 < 2)),
    if_neg (by decide : ¬(13 < 9)),
    if_neg (by decide : ¬(13 = 9)),
    if_neg (by decide : ¬(13 = 10)),
    if_neg (by decide : ¬(13 = 11)),
    if_neg (by decide : ¬(13 = 12)),
    if_pos (rfl : 13 = 13)]

theorem source_tail_at_14 (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (lane : Nat) :
    sourceTailWord statement witness hashes 14 lane = (sourceMultiplication statement witness (sourceAux statement.stablecoin witness.stablecoin) lane).b := by
  unfold sourceTailWord
  dsimp only
  rw [if_neg (by decide : ¬(14 < 2)),
    if_neg (by decide : ¬(14 < 9)),
    if_neg (by decide : ¬(14 = 9)),
    if_neg (by decide : ¬(14 = 10)),
    if_neg (by decide : ¬(14 = 11)),
    if_neg (by decide : ¬(14 = 12)),
    if_neg (by decide : ¬(14 = 13)),
    if_pos (rfl : 14 = 14)]

theorem source_tail_at_15 (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (lane : Nat) :
    sourceTailWord statement witness hashes 15 lane = (sourceMultiplication statement witness (sourceAux statement.stablecoin witness.stablecoin) lane).c := by
  unfold sourceTailWord
  dsimp only
  rw [if_neg (by decide : ¬(15 < 2)),
    if_neg (by decide : ¬(15 < 9)),
    if_neg (by decide : ¬(15 = 9)),
    if_neg (by decide : ¬(15 = 10)),
    if_neg (by decide : ¬(15 = 11)),
    if_neg (by decide : ¬(15 = 12)),
    if_neg (by decide : ¬(15 = 13)),
    if_neg (by decide : ¬(15 = 14)),
    if_pos (rfl : 15 = 15)]


theorem source_tail_family_readback (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (family : TailFamily) (offset lane : Nat)
    (bound : offset < family.width) :
    sourceTailWord statement witness hashes (family.base + offset) lane =
      tailFamilyWord statement witness hashes family offset lane := by
  cases family <;> simp only [TailFamily.base, TailFamily.width, tailFamilyWord] at bound ⊢
  · simp only [Nat.zero_add, sourceTailWord, if_pos bound]
  · unfold sourceTailWord
    dsimp only
    rw [if_neg (show ¬2 + offset < 2 by omega), if_pos (show 2 + offset < 9 by omega)]
    simp only [Nat.add_sub_cancel_left]
  · have zero : offset = 0 := by omega
    subst offset
    exact source_tail_at_9 statement witness hashes lane
  · have zero : offset = 0 := by omega
    subst offset
    exact source_tail_at_10 statement witness hashes lane
  · have zero : offset = 0 := by omega
    subst offset
    exact source_tail_at_11 statement witness hashes lane
  · have zero : offset = 0 := by omega
    subst offset
    exact source_tail_at_12 statement witness hashes lane
  · have cases : offset = 0 ∨ offset = 1 ∨ offset = 2 := by omega
    rcases cases with zero | one | two
    · subst offset; simpa using source_tail_at_13 statement witness hashes lane
    · subst offset; simpa using source_tail_at_14 statement witness hashes lane
    · subst offset; simpa using source_tail_at_15 statement witness hashes lane
  · unfold sourceTailWord
    dsimp only
    rw [if_neg (show ¬16 + offset < 2 by omega),
      if_neg (show ¬16 + offset < 9 by omega),
      if_neg (show ¬16 + offset = 9 by omega),
      if_neg (show ¬16 + offset = 10 by omega),
      if_neg (show ¬16 + offset = 11 by omega),
      if_neg (show ¬16 + offset = 12 by omega),
      if_neg (show ¬16 + offset = 13 by omega),
      if_neg (show ¬16 + offset = 14 by omega),
      if_neg (show ¬16 + offset = 15 by omega),
      if_pos (show 16 + offset < 39 by omega)]
    simp only [Nat.add_sub_cancel_left]

theorem source_tail_global_family_readback (before : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness) (hashes : AuthHashFinals)
    (prefixLength : before.length = 41408) (family : TailFamily) (offset : Nat)
    (bound : offset < family.width) (lane : Fin 64) :
    (packedWitnessLaneRows (embedSourceTail before statement witness hashes) lane.val).getD
        (647 + family.base + offset) 0 =
      tailFamilyWord statement witness hashes family offset lane.val := by
  have extent := tail_family_extent family
  have rowBound : family.base + offset < 39 := by omega
  rw [show 647 + family.base + offset = 647 + (family.base + offset) by omega,
    source_tail_global_lane_readback before statement witness hashes prefixLength
      ⟨family.base + offset,rowBound⟩ lane]
  exact source_tail_family_readback statement witness hashes family offset lane.val bound

theorem source_tail_last_padding_zero (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (lane : Fin 64) (padding : 26 ≤ lane.val) :
    sourceTailWord statement witness hashes 38 lane.val = 0 := by
  have readback := source_tail_family_readback statement witness hashes .ranges 22 lane.val (by decide)
  dsimp only [TailFamily.base, tailFamilyWord] at readback
  rw [readback]
  have length := source_range_digit_shape statement.stablecoin witness.stablecoin
    (sourceAux statement.stablecoin witness.stablecoin)
  have absent : (sourceRangeDigits statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin))[22 * 64 + lane.val]? = none :=
    List.getElem?_eq_none (by omega)
  simp only [List.getD_eq_getElem?_getD, absent, Option.getD_none]

theorem source_tail_global_padding_zero (before : List Nat)
    (statement : V8PublicStatement) (witness : V8Witness) (hashes : AuthHashFinals)
    (prefixLength : before.length = 41408) (lane : Fin 64) (padding : 26 ≤ lane.val) :
    (packedWitnessLaneRows (embedSourceTail before statement witness hashes) lane.val).getD 685 0 = 0 := by
  have readback := source_tail_global_lane_readback before statement witness hashes prefixLength
    ⟨38,by decide⟩ lane
  dsimp only at readback
  rw [readback]
  exact source_tail_last_padding_zero statement witness hashes lane padding

theorem source_tail_ranges_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (row : Fin 23) (lane : Fin 64) :
    sourceTailWord statement witness hashes (16 + row.val) lane.val < fieldModulus := by
  have readback := source_tail_family_readback statement witness hashes .ranges row.val lane.val row.isLt
  dsimp only [TailFamily.base, tailFamilyWord] at readback
  rw [readback]
  exact auth_exact_words_getD (source_range_digits_canonical statement.stablecoin witness.stablecoin
    (sourceAux statement.stablecoin witness.stablecoin)) _

theorem valid_source_tail_sources_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals)
    (row : Fin 2) (lane : Fin 64) :
    sourceTailWord statement witness hashes row.val lane.val < fieldModulus := by
  unfold sourceTailWord
  dsimp only
  rw [if_pos row.isLt]
  exact valid_stable_source_word_canonical statement witness valid _

theorem source_tail_selector_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (lane : Fin 64) :
    sourceTailWord statement witness hashes 9 lane.val < fieldModulus := by
  change sourceRoleSelector statement witness hashes lane.val < fieldModulus
  have bound := source_role_selector_bound statement witness hashes lane.val
  have modulus : 7 < fieldModulus := by decide
  omega

theorem source_tail_inverse_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (lane : Fin 64) :
    sourceTailWord statement witness hashes 10 lane.val < fieldModulus := by
  rw [source_tail_at_10]
  exact source_role_inverse_canonical statement witness hashes lane.val


end HegemonCrypto.SmallWood.V8Smz9SourceStableTail

