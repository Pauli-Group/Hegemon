import Mathlib.Data.ENNReal.Inv
import Mathlib.Data.Fin.VecNotation
import Mathlib.Data.Fintype.BigOperators
import Mathlib.Data.Real.Basic
import Mathlib.Probability.ProbabilityMassFunction.Monad
import Mathlib.Tactic.FieldSimp
import Mathlib.Tactic.NormNum
import Mathlib.Tactic.Positivity
import Mathlib.Tactic.Ring
import Lean.Elab.Tactic.Omega

/-!
SMZD q58 source-specific finite byte grammar and ideal counting candidate.
UNCOMPILED: written under an explicit no-build/no-test instruction. No source
refinement, runtime randomness, QROM distance theorem, or production authority
is asserted. No old SMZ9 shape or grammar module is imported.
-/
namespace HegemonCrypto.SmzdLeafGrammar
open scoped BigOperators ENNReal Classical
noncomputable section
set_option maxRecDepth 4096

abbrev Byte := Fin 256
abbrev Bytes (n : ℕ) := Fin n → Byte
abbrev LeafIndex := Fin 8388608
abbrev LeafTape := Bytes 64
abbrev LeafInput := Bytes 2045
abbrev LeafPrefix := Bytes 797
abbrev LeafSuffix := Bytes 1184
abbrev IndexBytes := Bytes 8
abbrev HiddenTapes := LeafIndex → LeafTape

/-- Exact ASCII profile and role bytes from the pinned SMZD source. -/
def profileBytes : Bytes 61 := ![104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,110,97,116,105,118,101,45,112,114,105,118,97,116,101,45,115,112,101,110,100,46,115,109,122,100,46,115,104,97,53,49,50,46,112,114,111,102,105,108,101,46,118,49]

def roleBytes : Bytes 56 := ![104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,115,116,114,105,99,116,45,122,107,46,109,101,114,107,108,101,45,108,101,97,102,46,112,114,105,118,97,116,101,45,115,112,101,110,100,46,118,49]

/-- Little-endian machine-word bytes. No field modulus occurs in this grammar. -/
def u64LE (n : ℕ) : Bytes 8 :=
  fun j => ⟨(n / 256 ^ j.val) % 256, Nat.mod_lt _ (by decide)⟩

def decodeIndexBytes (b : IndexBytes) : ℕ :=
  (b 0).val + 256 * (b 1).val + 65536 * (b 2).val +
  16777216 * (b 3).val + 4294967296 * (b 4).val +
  1099511627776 * (b 5).val + 281474976710656 * (b 6).val +
  72057594037927936 * (b 7).val

def encodeIndexBytes (index : LeafIndex) : IndexBytes := u64LE index.val

theorem decode_encode_index (index : LeafIndex) :
    decodeIndexBytes (encodeIndexBytes index) = index.val := by
  have bounded : index.val < 8388608 := index.isLt
  norm_num [decodeIndexBytes, encodeIndexBytes, u64LE]
  omega

/-- 8+61+8+56+8 = 141 bytes, including all three length words. -/
def sourceFrame (profile : Bytes 61) (role : Bytes 56) : Bytes 141 :=
  Fin.append (u64LE 61)
    (Fin.append profile (Fin.append (u64LE 56) (Fin.append role (u64LE 237))))

/-- The 77 statement words are passed as their 616 complete source bytes. -/
def beforeIndex (profile : Bytes 61) (role : Bytes 56)
    (statement : Bytes 616) (salt : Bytes 32) : Bytes 789 :=
  Fin.append (sourceFrame profile role) (Fin.append statement salt)

/-- 140 row words, five mask words, their counts, and counter zero. -/
def sourceSuffix (rows : Bytes 1120) (masks : Bytes 40) : LeafSuffix :=
  Fin.append (u64LE 140)
    (Fin.append rows (Fin.append (u64LE 5) (Fin.append masks (u64LE 0))))

def tapedLeafInput (leafPrefix : LeafPrefix) (suffix : LeafSuffix)
    (tape : LeafTape) : LeafInput :=
  Fin.append leafPrefix (Fin.append tape suffix)

def indexedLeafInput (before : Bytes 789) (index : LeafIndex)
    (suffix : LeafSuffix) (tape : LeafTape) : LeafInput :=
  tapedLeafInput (Fin.append before (encodeIndexBytes index)) suffix tape

def sourceLeafInput (profile : Bytes 61) (role : Bytes 56)
    (statement : Bytes 616) (salt : Bytes 32) (index : LeafIndex)
    (tape : LeafTape) (rows : Bytes 1120) (masks : Bytes 40) : LeafInput :=
  indexedLeafInput (beforeIndex profile role statement salt) index
    (sourceSuffix rows masks) tape

/-- Fully fixed SMZD domain tags; payload bytes remain arbitrary. -/
def smzdLeafInput (statement : Bytes 616) (salt : Bytes 32)
    (index : LeafIndex) (tape : LeafTape) (rows : Bytes 1120) (masks : Bytes 40) :
    LeafInput := sourceLeafInput profileBytes roleBytes statement salt index tape rows masks

def leafTapeProjection (input : LeafInput) : LeafTape :=
  fun j => input (Fin.natAdd 797 (Fin.castAdd 1184 j))

def leafIndexBytesProjection (input : LeafInput) : IndexBytes :=
  fun j => input (Fin.castAdd 1248 (Fin.natAdd 789 j))

/-- A total overapproximation parser. Invalid indices alias modulo N; source
indices are in [0,N), so their projection is exact. This only enlarges support. -/
def leafIndexProjection (input : LeafInput) : LeafIndex :=
  ⟨decodeIndexBytes (leafIndexBytesProjection input) % 8388608,
    Nat.mod_lt _ (by decide)⟩

theorem leaf_layout_arithmetic :
    77 + 4 + 1 + 8 + 1 + 140 + 1 + 5 = 237 ∧
    8 + 61 + 8 + 56 + 8 = 141 ∧
    141 + 616 + 32 = 789 ∧ 789 + 8 = 797 ∧
    8 + 1120 + 8 + 40 + 8 = 1184 ∧ 797 + 64 + 1184 = 2045 := by decide

theorem tape_offset (j : Fin 64) :
    (Fin.natAdd 797 (Fin.castAdd 1184 j)).val = 797 + j.val := rfl

theorem index_offset (j : Fin 8) :
    (Fin.castAdd 1248 (Fin.natAdd 789 j)).val = 789 + j.val := rfl

theorem tape_byte_range (j : Fin 64) :
    797 ≤ (Fin.natAdd 797 (Fin.castAdd 1184 j)).val ∧
    (Fin.natAdd 797 (Fin.castAdd 1184 j)).val ≤ 860 := by
  rw [tape_offset]
  have bound := j.isLt
  omega

theorem index_byte_range (j : Fin 8) :
    789 ≤ (Fin.castAdd 1248 (Fin.natAdd 789 j)).val ∧
    (Fin.castAdd 1248 (Fin.natAdd 789 j)).val ≤ 796 := by
  rw [index_offset]
  have bound := j.isLt
  omega

@[simp] theorem taped_leaf_projection (leafPrefix : LeafPrefix) (suffix : LeafSuffix)
    (tape : LeafTape) : leafTapeProjection (tapedLeafInput leafPrefix suffix tape) = tape := by
  funext j
  simp [leafTapeProjection, tapedLeafInput]

theorem taped_leaf_input_injective (leafPrefix : LeafPrefix) (suffix : LeafSuffix) :
    Function.Injective (tapedLeafInput leafPrefix suffix) := by
  intro left right equality
  simpa only [taped_leaf_projection] using congrArg leafTapeProjection equality

@[simp] theorem indexed_leaf_tape_projection (before : Bytes 789) (index : LeafIndex)
    (suffix : LeafSuffix) (tape : LeafTape) :
    leafTapeProjection (indexedLeafInput before index suffix tape) = tape := by
  simp [indexedLeafInput]

@[simp] theorem indexed_leaf_index_bytes_projection (before : Bytes 789)
    (index : LeafIndex) (suffix : LeafSuffix) (tape : LeafTape) :
    leafIndexBytesProjection (indexedLeafInput before index suffix tape) =
      encodeIndexBytes index := by
  funext j
  simp [leafIndexBytesProjection, indexedLeafInput, tapedLeafInput]

@[simp] theorem indexed_leaf_index_projection (before : Bytes 789) (index : LeafIndex)
    (suffix : LeafSuffix) (tape : LeafTape) :
    leafIndexProjection (indexedLeafInput before index suffix tape) = index := by
  apply Fin.ext
  simp [leafIndexProjection, decode_encode_index, Nat.mod_eq_of_lt index.isLt]

theorem different_indices_separate_inputs
    (leftBefore rightBefore : Bytes 789) (leftIndex rightIndex : LeafIndex)
    (leftSuffix rightSuffix : LeafSuffix) (leftTape rightTape : LeafTape)
    (different : leftIndex ≠ rightIndex) :
    indexedLeafInput leftBefore leftIndex leftSuffix leftTape ≠
      indexedLeafInput rightBefore rightIndex rightSuffix rightTape := by
  intro equality
  apply different
  simpa only [indexed_leaf_index_projection] using congrArg leafIndexProjection equality

@[simp] theorem smzd_leaf_tape_projection (statement : Bytes 616) (salt : Bytes 32)
    (index : LeafIndex) (tape : LeafTape) (rows : Bytes 1120) (masks : Bytes 40) :
    leafTapeProjection (smzdLeafInput statement salt index tape rows masks) = tape := by
  simp [smzdLeafInput, sourceLeafInput]

@[simp] theorem smzd_leaf_index_projection (statement : Bytes 616) (salt : Bytes 32)
    (index : LeafIndex) (tape : LeafTape) (rows : Bytes 1120) (masks : Bytes 40) :
    leafIndexProjection (smzdLeafInput statement salt index tape rows masks) = index := by
  simp [smzdLeafInput, sourceLeafInput]

/-- Eight machine-word byte chunks retain all 512 bits, with no field quotient. -/
def splitTapeWords (tape : LeafTape) : Fin 8 → Bytes 8 := fun word byte =>
  tape ⟨word.val * 8 + byte.val, by
    have hw := word.isLt
    have hb := byte.isLt
    omega⟩

def joinTapeWords (words : Fin 8 → Bytes 8) : LeafTape := fun j =>
  words ⟨j.val / 8, by have hj := j.isLt; omega⟩
    ⟨j.val % 8, Nat.mod_lt _ (by decide)⟩

theorem join_split_tape_words (tape : LeafTape) :
    joinTapeWords (splitTapeWords tape) = tape := by
  funext j
  unfold joinTapeWords splitTapeWords
  congr 1
  apply Fin.ext
  dsimp
  omega

/-- These are unrestricted byte strings, including machine words >= Goldilocks p. -/
theorem leaf_tape_cardinality : Fintype.card LeafTape = 2 ^ 512 := by
  simp only [LeafTape, Bytes, Byte, Fintype.card_fun, Fintype.card_fin]
  rw [show (256 : ℕ) = 2 ^ 8 by decide, ← pow_mul]

end
end HegemonCrypto.SmzdLeafGrammar
