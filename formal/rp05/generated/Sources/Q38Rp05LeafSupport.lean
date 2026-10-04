import Q38CmsDependentContinuation
import SmzaRp05StatementNamespace

/-!
The RP05 leaf is not the historical 1,407-byte leaf.  Its v2 frame is
2,511 bytes: 119 framing bytes, the 1,104-byte statement preamble, 32 salt
bytes, eight index bytes, 64 fresh tape bytes, 1,176 remaining payload bytes,
and eight counter bytes.  This file gives that address its own finite type and
re-runs the CMS overlap argument without changing the historical namespace.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05LeafSupport

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open HegemonCrypto.SmallWood.V8Smz9MeasuredOracleHybrid
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.SmzaRp05LeafNamespace
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

def rp05LeafBytes : Nat := 2511
def rp05TapeOffset : Nat := 1263
def rp05TailBytes : Nat := 1184

abbrev Rp05LeafInput := Fin rp05LeafBytes → CanonicalBytes.Byte
abbrev Rp05LeafHead := Fin rp05TapeOffset → CanonicalBytes.Byte
abbrev Rp05LeafTail := Fin rp05TailBytes → CanonicalBytes.Byte
abbrev Rp05LeafFixedHead := Fin 1255 → CanonicalBytes.Byte

theorem rp05_leaf_layout :
    119 + preambleBytes + 32 + 8 = rp05TapeOffset ∧
      rp05TapeOffset + 64 + rp05TailBytes = rp05LeafBytes := by
  decide

def tapedRp05Leaf (head : Rp05LeafHead) (tape : LeafTape)
    (tail : Rp05LeafTail) : Rp05LeafInput :=
  Fin.append head (Fin.append tape tail)

def rp05TapeProjection (input : Rp05LeafInput) : LeafTape :=
  fun byte => input (Fin.natAdd rp05TapeOffset (Fin.castAdd rp05TailBytes byte))

theorem rp05_tape_projection (head : Rp05LeafHead) (tape : LeafTape)
    (tail : Rp05LeafTail) :
    rp05TapeProjection (tapedRp05Leaf head tape tail) = tape := by
  funext byte
  simp only [rp05TapeProjection, tapedRp05Leaf, Fin.append_right, Fin.append_left]

theorem taped_rp05_leaf_injective (head : Rp05LeafHead)
    (tail : Rp05LeafTail) : Function.Injective (fun tape =>
      tapedRp05Leaf head tape tail) := by
  intro left right same
  simpa only [rp05_tape_projection] using
    congrArg rp05TapeProjection same

def rp05IndexBytes (index : LeafIndex) : Fin 8 → CanonicalBytes.Byte := fun byte =>
  (encodeLE 8 index.val).get
    ⟨byte.val, by simpa only [encodeLE_length] using byte.isLt⟩

def indexedRp05Leaf (head : Rp05LeafFixedHead) (index : LeafIndex)
    (tape : LeafTape) (tail : Rp05LeafTail) : Rp05LeafInput :=
  Fin.append head (Fin.append (rp05IndexBytes index)
    (Fin.append tape tail))

def rp05IndexProjection (input : Rp05LeafInput) : LeafIndex :=
  ⟨decodeLE (List.ofFn fun byte : Fin 8 =>
      input (Fin.natAdd 1255 (Fin.castAdd 1248 byte))) % 8388608,
    Nat.mod_lt _ (by norm_num)⟩

theorem indexed_rp05_leaf_index (head : Rp05LeafFixedHead)
    (index : LeafIndex) (tape : LeafTape) (tail : Rp05LeafTail) :
    rp05IndexProjection (indexedRp05Leaf head index tape tail) = index := by
  apply Fin.ext
  have bytes : List.ofFn (rp05IndexBytes index) = encodeLE 8 index.val := by
    apply List.ext_get
    · simp only [List.length_ofFn, encodeLE_length]
    · intro n leftBound rightBound
      simp only [List.get_ofFn, rp05IndexBytes]
      rfl
  change decodeLE (List.ofFn fun byte : Fin 8 =>
    indexedRp05Leaf head index tape tail
      (Fin.natAdd 1255 (Fin.castAdd (64 + rp05TailBytes) byte))) % 8388608 = index.val
  simp only [indexedRp05Leaf, Fin.append_right, Fin.append_left]
  rw [bytes, decodeLE_encodeLE]
  have fits : index.val < 256 ^ 8 := by
    have bound := index.isLt
    change index.val < 8388608 at bound
    omega
  rw [Nat.mod_eq_of_lt fits, Nat.mod_eq_of_lt index.isLt]

theorem indexed_rp05_leaf_tape (head : Rp05LeafFixedHead)
    (index : LeafIndex) (tape : LeafTape) (tail : Rp05LeafTail) :
    rp05TapeProjection (indexedRp05Leaf head index tape tail) = tape := by
  funext byte
  have position : Fin.natAdd rp05TapeOffset (Fin.castAdd rp05TailBytes byte) =
      Fin.natAdd 1255 (Fin.natAdd 8 (Fin.castAdd rp05TailBytes byte)) := by
    apply Fin.ext
    simp only [Fin.val_natAdd, Fin.val_castAdd, rp05TapeOffset]
    omega
  unfold rp05TapeProjection
  rw [position]
  simp only [indexedRp05Leaf, Fin.append_right, Fin.append_left]

/- The literal frame head ends immediately before the 64-byte tape.  `get`
is used only after the exact length theorem below, so no padding is observed. -/
def rp05FixedHeadBytes (preamble : SmzaRp05StatementNamespace.Statement)
    (salt : Fin 32 → CanonicalBytes.Byte) : List CanonicalBytes.Byte :=
  encodeLE 8 V8SmzaOracleParser.profileDomain.length ++
    V8SmzaOracleParser.profileDomain ++ encodeLE 8 leafV2Role.length ++
    leafV2Role ++ encodeLE 8 currentLeafPayloadWords ++
    SmzaRp05StatementNamespace.Statement.toBytes preamble ++ List.ofFn salt

theorem rp05_fixed_head_length (preamble : SmzaRp05StatementNamespace.Statement)
    (salt : Fin 32 → CanonicalBytes.Byte) :
    (rp05FixedHeadBytes preamble salt).length = 1255 := by
  simp only [rp05FixedHeadBytes, List.length_append,
    SmzaRp05StatementNamespace.Statement.toBytes_length, encodeLE_length,
    List.length_ofFn]
  decide

def rp05FixedHead (preamble : SmzaRp05StatementNamespace.Statement)
    (salt : Fin 32 → CanonicalBytes.Byte) :
    Rp05LeafFixedHead := fun byte =>
  (rp05FixedHeadBytes preamble salt).get
    ⟨byte.val, by rw [rp05_fixed_head_length]; exact byte.isLt⟩

def rp05FrameTail (data : Fin 1176 → CanonicalBytes.Byte) : Rp05LeafTail :=
  Fin.append data (fun _ : Fin 8 => 0)

/-- Literal strict-leaf-v2 source address.  Preamble, salt and payload may be
branch dependent; the fresh tape remains the sole hidden coordinate. -/
def rp05SourceLeafInput (preamble : SmzaRp05StatementNamespace.Statement)
    (salt : Fin 32 → CanonicalBytes.Byte)
    (data : Fin 1176 → CanonicalBytes.Byte) (index : LeafIndex) (tape : LeafTape) :
    Rp05LeafInput :=
  indexedRp05Leaf (rp05FixedHead preamble salt) index tape
    (rp05FrameTail data)

theorem rp05_source_leaf_tape_projection (preamble : SmzaRp05StatementNamespace.Statement)
    (salt : Fin 32 → CanonicalBytes.Byte) (data : Fin 1176 → CanonicalBytes.Byte)
    (index : LeafIndex) (tape : LeafTape) :
    rp05TapeProjection (rp05SourceLeafInput preamble salt data index tape) =
      tape := by
  exact indexed_rp05_leaf_tape _ _ _ _

theorem rp05_source_leaf_index_projection (preamble : SmzaRp05StatementNamespace.Statement)
    (salt : Fin 32 → CanonicalBytes.Byte) (data : Fin 1176 → CanonicalBytes.Byte)
    (index : LeafIndex) (tape : LeafTape) :
    rp05IndexProjection (rp05SourceLeafInput preamble salt data index tape) =
      index := by
  exact indexed_rp05_leaf_index _ _ _ _

def recordedKeys {Key Output : Type} [Fintype Key] [DecidableEq Key]
    (database : Key → Option Output) : Finset Key :=
  Finset.univ.filter fun key => database key ≠ none

private def intersects {Key : Type} (recorded patched : Finset Key) : Prop :=
  ∃ key ∈ recorded, key ∈ patched

private theorem overlap_indicator_bound {Key : Type} [DecidableEq Key]
    (recorded patched : Finset Key) :
    (if intersects recorded patched then (1 : ℝ) else 0) ≤
      ∑ key ∈ recorded, if key ∈ patched then (1 : ℝ) else 0 := by
  by_cases hit : intersects recorded patched
  · obtain ⟨key, member, patchedMember⟩ := hit
    rw [if_pos ⟨key, member, patchedMember⟩]
    have bound := Finset.single_le_sum
      (f := fun key => if key ∈ patched then (1 : ℝ) else 0)
      (fun key _ => by positivity) member
    simpa only [if_pos patchedMember] using bound
  · rw [if_neg hit]
    exact Finset.sum_nonneg fun _ _ => by positivity

section GenericFiber

variable {Key Index Tape Branch Work Output : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Index] [DecidableEq Index]
variable [Fintype Tape] [DecidableEq Tape] [Nonempty Tape]
variable [Fintype Branch] [Fintype Work]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]

omit [Fintype Branch] in
/-- The no-number-of-leaves overlap bound for any concrete encoding exposing
an index and tape left inverse. -/
theorem encoded_record_overlap
    (selected : Branch → Index → Tape → Key)
    (keyIndex : Key → Index) (keyTape : Key → Tape)
    (indexLeft : ∀ branch index tape,
      keyIndex (selected branch index tape) = index)
    (tapeLeft : ∀ branch index tape,
      keyTape (selected branch index tape) = tape)
    (recorded : Finset Key) (branch : Branch) :
    uniformAverage (fun tapes : Index → Tape =>
      if intersects recorded
        (Finset.univ.image fun index => selected branch index (tapes index))
      then (1 : ℝ) else 0) ≤
      (recorded.card : ℝ) * (Fintype.card Tape : ℝ)⁻¹ := by
  apply (average_mono _ _ fun tapes => overlap_indicator_bound recorded _).trans
  simp only [uniformAverage, Finset.mul_sum]
  rw [Finset.sum_comm]
  calc
    _ ≤ ∑ _key ∈ recorded, (Fintype.card Tape : ℝ)⁻¹ := by
      apply Finset.sum_le_sum
      intro key _
      apply (average_mono _ (fun tapes : Index → Tape =>
        if key ∈ indexedSupport keyIndex keyTape tapes then (1 : ℝ) else 0) ?_).trans
      · exact average_support_indicator_le (indexedSupport keyIndex keyTape)
          (Fintype.card Tape : ℝ)⁻¹
          (fun input => (indexed_support_count keyIndex keyTape input).le) key
      · intro tapes
        by_cases member : key ∈ Finset.univ.image
            (fun index => selected branch index (tapes index))
        · have included := image_subset_indexed_support (selected branch)
            keyIndex keyTape (indexLeft branch) (tapeLeft branch) Finset.univ tapes member
          simp only [if_pos member, if_pos included, le_refl]
        · simp only [if_neg member]
          positivity
    _ = _ := by simp

/-- Generic branch-controlled CMS disturbance.  The quantitative premise is
only the reached database-size invariant; no desired probability bound is an
argument. -/
theorem encoded_resampling_disturbance
    (selected : Branch → Index → Tape → Key)
    (keyIndex : Key → Index) (keyTape : Key → Tape)
    (indexLeft : ∀ branch index tape,
      keyIndex (selected branch index tape) = index)
    (tapeLeft : ∀ branch index tape,
      keyTape (selected branch index tape) = tape)
    (indices : List Index)
    (core : Core Key Branch Work Output → ℂ) (queries : Nat)
    (supported : ∀ basis, core basis ≠ 0 →
      (recordedKeys basis.2.1).card ≤ queries) :
    uniformAverage (fun tapes : Index → Tape =>
      ‖exchangeMany (fun branch index => selected branch index (tapes index))
          indices (freshLabels (Index := Index) core) - freshLabels core‖ ^ 2) ≤
      4 * (queries : ℝ) * (Fintype.card Tape : ℝ)⁻¹ *
        ∑ basis : Core Key Branch Work Output, ‖core basis‖ ^ 2 := by
  have pointwise (tapes : Index → Tape) :
      ‖exchangeMany (fun branch index => selected branch index (tapes index))
          indices (freshLabels (Index := Index) core) - freshLabels core‖ ^ 2 ≤
        4 * ∑ basis : Core Key Branch Work Output,
          if ∃ index ∈ indices,
            basis.2.1 (selected basis.1 index (tapes index)) ≠ none
          then ‖core basis‖ ^ 2 else 0 :=
    controlled_swap_disturbance_mass (Key := Key) (Index := Index)
      (Branch := Branch) (Work := Work) (Output := Output)
      (fun branch index => selected branch index (tapes index)) indices core
  have averaged := average_mono _ _ pointwise
  apply averaged.trans
  rw [average_mul_left, average_sum]
  have perBasis (basis : Core Key Branch Work Output) :
      uniformAverage (fun tapes : Index → Tape =>
        if ∃ index ∈ indices,
          basis.2.1 (selected basis.1 index (tapes index)) ≠ none
        then ‖core basis‖ ^ 2 else 0) ≤
        (queries : ℝ) * (Fintype.card Tape : ℝ)⁻¹ *
          ‖core basis‖ ^ 2 := by
    by_cases zero : core basis = 0
    · simp [zero, uniformAverage]
    · have cardBound : ((recordedKeys basis.2.1).card : ℝ) ≤ (queries : ℝ) := by
        exact_mod_cast supported basis zero
      have averaged := mul_le_mul_of_nonneg_right
          ((encoded_record_overlap selected keyIndex keyTape indexLeft tapeLeft
            (recordedKeys basis.2.1) basis.1).trans
            (mul_le_mul_of_nonneg_right cardBound
              (by positivity))) (sq_nonneg (‖core basis‖))
      rw [← average_mul_right] at averaged
      apply (average_mono _ _ fun tapes => ?_).trans averaged
      by_cases hit : ∃ index ∈ indices,
          basis.2.1 (selected basis.1 index (tapes index)) ≠ none
      · obtain ⟨index, member, present⟩ := hit
        have hit : ∃ index ∈ indices,
            basis.2.1 (selected basis.1 index (tapes index)) ≠ none :=
          ⟨index, member, present⟩
        have overlap : intersects (recordedKeys basis.2.1)
            (Finset.univ.image fun i => selected basis.1 i (tapes i)) := by
          refine ⟨selected basis.1 index (tapes index), ?_, ?_⟩
          · simp [recordedKeys, present]
          · exact Finset.mem_image.mpr ⟨index, Finset.mem_univ _, rfl⟩
        simp [hit, overlap]
      · simp only [if_neg hit]
        positivity
  calc
    _ ≤ 4 * ∑ basis : Core Key Branch Work Output,
        (queries : ℝ) * (Fintype.card Tape : ℝ)⁻¹ *
          ‖core basis‖ ^ 2 :=
      mul_le_mul_of_nonneg_left
        (Finset.sum_le_sum fun basis _ => perBasis basis) (by norm_num)
    _ = _ := by rw [← Finset.mul_sum]; ring

end GenericFiber

end
end HegemonCrypto.SmallWood.Q38Rp05LeafSupport
