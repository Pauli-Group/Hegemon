import Mathlib.Data.Nat.Digits.Lemmas

/-!
# Compressed SmallWood production relation

This module checks the arithmetic behind the feature-gated compressed production relation.  The
Rust adapter keeps the production statement and semantic constraints, replaces each replicated
61-bit value decomposition with the fixed two-bit encoding below, and represents each Poseidon2
permutation by its boundary states and degree-seven S-box inputs.
-/

namespace HegemonCrypto.SmallWood.CompressedRelation

def rangeValueCount : Nat := 7
def rangeBitCount : Nat := 61
def oldRangeDigitBase : Nat := 8
def oldRangeDigitCount : Nat := 21
def rangeDigitBase : Nat := 4
def ordinaryDigitCount : Nat := 30
def packedDigitCount : Nat := ordinaryDigitCount + 1
def packingFactor : Nat := 64

def lowDigits (value : Nat) : List Nat :=
  Nat.digitsAppend rangeDigitBase ordinaryDigitCount
    (value % rangeDigitBase ^ ordinaryDigitCount)

def topBit (value : Nat) : Nat :=
  value / rangeDigitBase ^ ordinaryDigitCount

def encodedDigits (value : Nat) : List Nat :=
  lowDigits value ++ [topBit value]

def oldRangeDigits (value : Nat) : List Nat :=
  Nat.digitsAppend oldRangeDigitBase oldRangeDigitCount value

theorem low_digits_length (value : Nat) :
    (lowDigits value).length = ordinaryDigitCount := by
  apply Nat.length_digitsAppend
  · decide
  · exact Nat.mod_lt _ (by norm_num [rangeDigitBase, ordinaryDigitCount])

theorem low_digit_lt_four
    (value digit : Nat)
    (member : digit ∈ lowDigits value) :
    digit < rangeDigitBase := by
  exact Nat.lt_of_mem_digitsAppend (by decide) ordinaryDigitCount digit member

theorem low_digits_reconstruct (value : Nat) :
    Nat.ofDigits rangeDigitBase (lowDigits value) =
      value % rangeDigitBase ^ ordinaryDigitCount := by
  simp [lowDigits, Nat.digitsAppend, Nat.ofDigits_append_replicate_zero,
    Nat.ofDigits_digits]

theorem top_bit_lt_two
    {value : Nat}
    (bounded : value < 2 ^ rangeBitCount) :
    topBit value < 2 := by
  rw [topBit, Nat.div_lt_iff_lt_mul
    (by norm_num [rangeDigitBase, ordinaryDigitCount])]
  norm_num [rangeDigitBase, ordinaryDigitCount, rangeBitCount] at bounded ⊢
  exact bounded

theorem encoded_digits_length (value : Nat) :
    (encodedDigits value).length = packedDigitCount := by
  simp [encodedDigits, packedDigitCount, low_digits_length]

theorem encoded_digits_reconstruct (value : Nat) :
    Nat.ofDigits rangeDigitBase (encodedDigits value) = value := by
  rw [encodedDigits, Nat.ofDigits_append, low_digits_reconstruct, low_digits_length]
  simp [topBit]
  exact Nat.mod_add_div value (rangeDigitBase ^ ordinaryDigitCount)

theorem old_range_digits_reconstruct
    (value : Nat) :
    Nat.ofDigits oldRangeDigitBase (oldRangeDigits value) = value := by
  simp [oldRangeDigits, Nat.digitsAppend, Nat.ofDigits_append_replicate_zero,
    Nat.ofDigits_digits]

theorem old_range_digits_length
    {value : Nat}
    (bounded : value < 2 ^ rangeBitCount) :
    (oldRangeDigits value).length = oldRangeDigitCount := by
  apply Nat.length_digitsAppend
  · decide
  · exact lt_trans bounded (by norm_num [oldRangeDigitBase, oldRangeDigitCount, rangeBitCount])

theorem old_and_dense_range_encodings_agree
    (value : Nat) :
    Nat.ofDigits oldRangeDigitBase (oldRangeDigits value) =
      Nat.ofDigits rangeDigitBase (encodedDigits value) := by
  rw [old_range_digits_reconstruct, encoded_digits_reconstruct]

section PoseidonWires

variable {R : Type} [CommRing R]

abbrev PoseidonState (R : Type) := Fin 12 → R

def sboxSeven (value : R) : R := value ^ 7

def externalSboxInputs (state constants : PoseidonState R) : PoseidonState R :=
  fun index => state index + constants index

def externalRound
    (linearLayer : PoseidonState R → PoseidonState R)
    (state constants : PoseidonState R) : PoseidonState R :=
  linearLayer fun index => sboxSeven (externalSboxInputs state constants index)

def externalWireRound
    (linearLayer : PoseidonState R → PoseidonState R)
    (wires : PoseidonState R) : PoseidonState R :=
  linearLayer fun index => sboxSeven (wires index)

theorem external_sbox_wires_preserve_round
    (linearLayer : PoseidonState R → PoseidonState R)
    (state constants wires : PoseidonState R)
    (constrained : wires = externalSboxInputs state constants) :
    externalWireRound linearLayer wires = externalRound linearLayer state constants := by
  subst wires
  rfl

def replaceFirst (state : PoseidonState R) (value : R) : PoseidonState R :=
  fun index => if index = 0 then value else state index

def internalRound
    (linearLayer : PoseidonState R → PoseidonState R)
    (state : PoseidonState R)
    (constant : R) : PoseidonState R :=
  linearLayer (replaceFirst state (sboxSeven (state 0 + constant)))

def internalWireRound
    (linearLayer : PoseidonState R → PoseidonState R)
    (state : PoseidonState R)
    (wire : R) : PoseidonState R :=
  linearLayer (replaceFirst state (sboxSeven wire))

theorem internal_sbox_wire_preserves_round
    (linearLayer : PoseidonState R → PoseidonState R)
    (state : PoseidonState R)
    (constant wire : R)
    (constrained : wire = state 0 + constant) :
    internalWireRound linearLayer state wire = internalRound linearLayer state constant := by
  subst wire
  rfl

theorem poseidon_sbox_wire_count_is_118 : 8 * 12 + 22 = 118 := by
  decide

end PoseidonWires

/-- Four rows hold 210 ordinary digits; one row holds the seven top bits. -/
def denseRangeRowCount : Nat :=
  (rangeValueCount * ordinaryDigitCount + packingFactor - 1) / packingFactor + 1

theorem dense_range_row_count_is_five : denseRangeRowCount = 5 := by
  decide

def fullRowCount : Nat := 1531
def poseidonGroupCount : Nat := 3
def fullPoseidonRowsPerGroup : Nat := 31 * 12
def compressedPoseidonRowsPerGroup : Nat := 12 + 118 + 12
def oldRangeRowCount : Nat := rangeValueCount * 21
def fullNonPoseidonRowCount : Nat :=
  fullRowCount - poseidonGroupCount * fullPoseidonRowsPerGroup
def compressedNonPoseidonRowCount : Nat :=
  fullNonPoseidonRowCount - oldRangeRowCount + denseRangeRowCount
def compressedRowCount : Nat :=
  compressedNonPoseidonRowCount +
    poseidonGroupCount * compressedPoseidonRowsPerGroup

theorem compressed_relation_row_geometry :
    fullNonPoseidonRowCount = 415 ∧
      compressedNonPoseidonRowCount = 273 ∧
      compressedPoseidonRowsPerGroup = 142 ∧
      compressedRowCount = 699 := by
  decide

def fullConstraintCount : Nat := 1722
def fullPoseidonConstraintsPerGroup : Nat := 30 * 12
def compressedPoseidonConstraintsPerGroup : Nat := 118 + 12
def compressedConstraintCount : Nat :=
  fullConstraintCount - poseidonGroupCount * fullPoseidonConstraintsPerGroup -
      oldRangeRowCount +
    poseidonGroupCount * compressedPoseidonConstraintsPerGroup + denseRangeRowCount

theorem compressed_relation_constraint_geometry :
    compressedConstraintCount = 890 := by
  decide

def droppedRangeReplicationConstraints : Nat := oldRangeRowCount * (packingFactor - 1)

theorem dropped_range_replication_constraint_count :
    droppedRangeReplicationConstraints = 9261 := by
  decide

end HegemonCrypto.SmallWood.CompressedRelation
