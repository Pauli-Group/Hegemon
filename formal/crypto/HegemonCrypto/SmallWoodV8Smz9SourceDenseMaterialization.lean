import HegemonCrypto.SmallWoodV8Smz9SemanticDenseRange

/-!
The concrete five-row dense-value materializer used by the honest assignment.
This component covers rows 247..251 only. The seven typed/public source values
remain explicit inputs until the complete assignment constructor is assembled.
No packed acceptance, evaluator success, or desired reconstruction is assumed.
This is a source-faithful natural/field model, not an extracted Rust theorem.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

abbrev SourceValues := Fin 7 → Nat

def ValuesBounded (values : SourceValues) : Prop :=
  ∀ index, values index < 2 ^ 61

def sourceDigit (value digit : Nat) : Nat := (value / 4 ^ digit) % 4

/-- Exact source bit operations at their natural-number interpretation. -/
theorem source_digit_is_shift_and (value digit : Nat) :
    sourceDigit value digit = (value >>> (2 * digit)) &&& 3 := by
  have mask := Nat.and_two_pow_sub_one_eq_mod (value >>> (2 * digit)) 2
  norm_num only [Nat.reducePow, Nat.reduceSub] at mask
  rw [mask, Nat.shiftRight_eq_div_pow]
  have powers : 2 ^ (2 * digit) = 4 ^ digit := by
    rw [pow_mul]
    norm_num
  rw [powers]
  rfl

/-- Flattened five-row block. The two unused ranges remain the source's zeros. -/
def sourceDenseCell (values : SourceValues) (slot : Nat) : Nat :=
  if bounded : slot < 210 then
    sourceDigit (values ⟨slot / 30, by omega⟩) (slot % 30)
  else if bounded : 256 ≤ slot ∧ slot < 263 then
    values ⟨slot - 256, by omega⟩ / 2 ^ 60
  else 0

def sourceDenseRows (values : SourceValues) (row : Fin 5) (lane : Fin 64) : Nat :=
  sourceDenseCell values (row.val * 64 + lane.val)

def sourceDensePacked (values : SourceValues) : List Nat :=
  List.ofFn fun slot : Fin 320 => sourceDenseCell values slot.val

/-- The exact source order; validity of these seven values is proved separately. -/
def orderedSourceValues (input0 input1 output0 output1 public44 public46 public62 : Nat) :
    SourceValues := ![input0, input1, output0, output1, public44, public46, public62]

/-- Embed the local block explicitly; no global lookup is made into a 320-word list. -/
def embedSourceDense (before after : List Nat) (values : SourceValues) : List Nat :=
  before ++ (sourceDensePacked values ++ after)

theorem source_dense_packed_length (values : SourceValues) :
    (sourceDensePacked values).length = 320 := by
  simp only [sourceDensePacked, List.length_ofFn]

theorem source_dense_packed_getD (values : SourceValues) (slot : Fin 320)
    (fallback : Nat) :
    (sourceDensePacked values).getD slot.val fallback = sourceDenseCell values slot.val := by
  simp only [sourceDensePacked, List.getD_eq_getElem?_getD,
    List.getElem?_ofFn, slot.isLt, dif_pos, Option.getD_some]

theorem source_dense_embedded_getD (before after : List Nat) (values : SourceValues)
    (slot : Fin 320) (fallback : Nat) :
    (embedSourceDense before after values).getD (before.length + slot.val) fallback =
      sourceDenseCell values slot.val := by
  have inBlock : slot.val < (sourceDensePacked values).length := by
    rw [source_dense_packed_length]
    exact slot.isLt
  simp only [embedSourceDense, List.getD_eq_getElem?_getD]
  rw [List.getElem?_append_right (by omega), Nat.add_sub_cancel_left,
    List.getElem?_append_left inBlock]
  exact source_dense_packed_getD values slot fallback

theorem source_dense_global_lane_readback (before after : List Nat)
    (values : SourceValues) (prefixLength : before.length = 15808)
    (row : Fin 5) (lane : Fin 64) :
    (packedWitnessLaneRows (embedSourceDense before after values) lane.val).getD
        (247 + row.val) 0 = sourceDenseRows values row lane := by
  have rowBound : 247 + row.val < 686 := by omega
  have slotBound : row.val * 64 + lane.val < 320 := by omega
  have address : (247 + row.val) * 64 + lane.val =
      before.length + (row.val * 64 + lane.val) := by omega
  simp only [packedWitnessLaneRows, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_range, relationRowCount, rowBound,
    Option.map_some, Option.getD_some, packingFactor]
  rw [address]
  exact source_dense_embedded_getD before after values ⟨_, slotBound⟩ 0

theorem source_dense_digit_cell (values : SourceValues)
    (value : Fin 7) (digit : Fin 30) :
    sourceDenseCell values (30 * value.val + digit.val) =
      sourceDigit (values value) digit.val := by
  have small : 30 * value.val + digit.val < 210 := by omega
  have quotient : (30 * value.val + digit.val) / 30 = value.val := by omega
  have remainder : (30 * value.val + digit.val) % 30 = digit.val := by omega
  simp only [sourceDenseCell, dif_pos small, quotient, remainder]

theorem source_dense_top_cell (values : SourceValues) (value : Fin 7) :
    sourceDenseCell values (256 + value.val) = values value / 2 ^ 60 := by
  have notDigit : ¬256 + value.val < 210 := by omega
  have top : 256 ≤ 256 + value.val ∧ 256 + value.val < 263 := by omega
  simp only [sourceDenseCell, dif_neg notDigit, dif_pos top, Nat.add_sub_cancel_left]

theorem source_dense_global_digit_address (before after : List Nat)
    (values : SourceValues) (prefixLength : before.length = 15808)
    (value : Fin 7) (digit : Fin 30) :
    (embedSourceDense before after values).getD
        (denseDigitAddress value.val digit.val) 0 = sourceDigit (values value) digit.val := by
  have bound : 30 * value.val + digit.val < 320 := by omega
  have address : denseDigitAddress value.val digit.val =
      before.length + (30 * value.val + digit.val) := by
    unfold denseDigitAddress
    omega
  rw [address, source_dense_embedded_getD before after values ⟨_, bound⟩]
  exact source_dense_digit_cell values value digit

theorem source_dense_global_top_address (before after : List Nat)
    (values : SourceValues) (prefixLength : before.length = 15808) (value : Fin 7) :
    (embedSourceDense before after values).getD (denseTopAddress value.val) 0 =
      values value / 2 ^ 60 := by
  have bound : 256 + value.val < 320 := by omega
  have address : denseTopAddress value.val = before.length + (256 + value.val) := by
    unfold denseTopAddress
    omega
  rw [address, source_dense_embedded_getD before after values ⟨_, bound⟩]
  exact source_dense_top_cell values value

theorem source_dense_padding_zero (values : SourceValues) (slot : Nat)
    (padding : (210 ≤ slot ∧ slot < 256) ∨ 263 ≤ slot) :
    sourceDenseCell values slot = 0 := by
  have notDigit : ¬ slot < 210 := by omega
  have notTop : ¬ (256 ≤ slot ∧ slot < 263) := by omega
  simp only [sourceDenseCell, dif_neg notDigit, dif_neg notTop]

theorem source_dense_digit_bound (values : SourceValues) (slot : Nat)
    (lowRows : slot < 256) : sourceDenseCell values slot < 4 := by
  by_cases digit : slot < 210
  · simp only [sourceDenseCell, dif_pos digit, sourceDigit]
    exact Nat.mod_lt _ (by decide)
  · rw [source_dense_padding_zero values slot (Or.inl ⟨by omega, lowRows⟩)]
    decide

theorem source_dense_top_bound (values : SourceValues)
    (bounded : ValuesBounded values) (lane : Nat) :
    sourceDenseCell values (256 + lane) < 2 := by
  by_cases small : lane < 7
  · rw [show 256 + lane = 256 + (⟨lane, small⟩ : Fin 7).val from rfl,
      source_dense_top_cell]
    have bound := bounded ⟨lane, small⟩
    norm_num at bound ⊢
    omega
  · rw [source_dense_padding_zero values (256 + lane) (Or.inr (by omega))]
    decide

theorem source_dense_cells_canonical (values : SourceValues)
    (bounded : ValuesBounded values) (slot : Nat) :
    sourceDenseCell values slot < fieldModulus := by
  by_cases lowRows : slot < 256
  · have bound := source_dense_digit_bound values slot lowRows
    norm_num [fieldModulus] at *
    omega
  · have bound := source_dense_top_bound values bounded (slot - 256)
    have same : 256 + (slot - 256) = slot := by omega
    rw [same] at bound
    norm_num [fieldModulus] at *
    omega

/-- A general finite radix identity; it does not assume an input range. -/
theorem source_radix_reconstruction (value count : Nat) :
    radixFourSum (sourceDigit value) count +
      4 ^ count * (value / 4 ^ count) = value := by
  induction count with
  | zero => simp [radixFourSum]
  | succ count inductionHypothesis =>
    have division := Nat.div_add_mod (value / 4 ^ count) 4
    have nextDivision : value / 4 ^ (count + 1) = (value / 4 ^ count) / 4 := by
      rw [pow_succ, Nat.div_div_eq_div_mul]
    simp only [radixFourSum, List.range_succ, List.map_append, List.sum_append,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero]
    change radixFourSum (sourceDigit value) count +
      4 ^ count * sourceDigit value count +
      4 ^ (count + 1) * (value / 4 ^ (count + 1)) = value
    rw [nextDivision, pow_succ]
    have weighted := congrArg (fun term => 4 ^ count * term) division
    unfold sourceDigit at inductionHypothesis ⊢
    nlinarith [weighted]

theorem source_dense_reconstructs_all_seven (values : SourceValues) (value : Fin 7) :
    radixFourSum
        (fun digit => sourceDenseCell values (30 * value.val + digit)) 30 +
      2 ^ 60 * sourceDenseCell values (256 + value.val) = values value := by
  have digitValues : radixFourSum
      (fun digit => sourceDenseCell values (30 * value.val + digit)) 30 =
      radixFourSum (sourceDigit (values value)) 30 := by
    unfold radixFourSum
    congr 1
    apply List.map_congr_left
    intro digit member
    have small : digit < 30 := List.mem_range.mp member
    dsimp only
    rw [show 30 * value.val + digit =
      30 * value.val + (⟨digit, small⟩ : Fin 30).val from rfl,
      source_dense_digit_cell]
  rw [digitValues, source_dense_top_cell]
  have result := source_radix_reconstruction (values value) 30
  norm_num only [Nat.reducePow] at result ⊢
  exact result

/-- The exact four low-row polynomial constraints used by the source. -/
theorem source_dense_digit_equations (values : SourceValues) (slot : Nat)
    (lowRows : slot < 256) :
    let digit : F := sourceDenseCell values slot
    digit * (digit - 1) * (digit - 2) * (digit - 3) = 0 := by
  have bound := source_dense_digit_bound values slot lowRows
  rcases (show sourceDenseCell values slot = 0 ∨ sourceDenseCell values slot = 1 ∨
      sourceDenseCell values slot = 2 ∨ sourceDenseCell values slot = 3 by omega) with
    value | value | value | value <;> simp [value]

/-- The source's high-row Boolean equation, including its zero padding. -/
theorem source_dense_top_equations (values : SourceValues)
    (bounded : ValuesBounded values) (lane : Nat) :
    let top : F := sourceDenseCell values (256 + lane)
    top * (top - 1) = 0 := by
  have bound := source_dense_top_bound values bounded lane
  rcases (show sourceDenseCell values (256 + lane) = 0 ∨
      sourceDenseCell values (256 + lane) = 1 by omega) with value | value <;>
    simp [value]


end HegemonCrypto.SmallWood.V8Smz9SourceDenseMaterialization
