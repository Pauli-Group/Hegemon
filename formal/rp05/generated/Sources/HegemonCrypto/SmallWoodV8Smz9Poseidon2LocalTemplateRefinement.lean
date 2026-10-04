import HegemonCrypto.Goldilocks
import Hegemon.Transaction.Poseidon2Width16Kernel
import Mathlib.Tactic.FinCases
import Mathlib.Tactic.Ring

/-! Arithmetic refinement of the actual width-16 Poseidon2 local templates.
The premises below are individual gate equations, never final trace equality.
Actual expression-index certification is supplied by the source replay module. -/

namespace HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement

open Hegemon.Transaction

set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 1000000

abbrev F := Goldilocks

@[simp] theorem cast_fieldValue (x : Nat) : (Poseidon2Width16Kernel.fieldValue x : F) = (x : F) := by
  change (((x % Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus : Nat) : F)) = _
  exact ZMod.natCast_mod _ _

@[simp] theorem cast_fieldAdd (x y : Nat) :
    (Poseidon2Width16Kernel.fieldAdd x y : F) = (x : F) + (y : F) := by
  change (((((x + y) % Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus) : Nat) : F)) = _
  simp

@[simp] theorem cast_fieldMul (x y : Nat) :
    (Poseidon2Width16Kernel.fieldMul x y : F) = (x : F) * (y : F) := by
  change (((((x * y) % Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus) : Nat) : F)) = _
  simp

def p4 (input : Nat → F) (chunk column : Nat) : F :=
  input (4 * chunk + column) +
    (((input (4 * chunk) + input (4 * chunk + 1)) +
      input (4 * chunk + 2)) + input (4 * chunk + 3))

def m4 (x0 x1 x2 x3 : F) (row : Nat) : F :=
  let t01 := x0 + x1
  let t23 := x2 + x3
  let total := t01 + t23
  match row with
  | 0 => (total + x1) + t01
  | 1 => (total + x1) + (x2 + x2)
  | 2 => (total + x3) + t23
  | 3 => (total + x3) + (x0 + x0)
  | _ => 0

def externalField (input : Nat → F) (lane : Nat) : F :=
  let c := lane % 4
  m4 (p4 input 0 c) (p4 input 1 c) (p4 input 2 c) (p4 input 3 c) (lane / 4)

def outputOffset (row : Nat) : Nat :=
  match row with
  | 0 => 9
  | 1 => 8
  | 2 => 10
  | _ => 6

/-- Exactly 28 chunk additions and 44 column additions. -/
structure External72 (input trace : Nat → F) : Prop where
  chunk0 : ∀ q < 4, trace (7*q) = input (4*q) + input (4*q+1)
  chunk1 : ∀ q < 4, trace (7*q+1) = input (4*q+2) + trace (7*q)
  chunk2 : ∀ q < 4, trace (7*q+2) = input (4*q+3) + trace (7*q+1)
  chunkOut : ∀ q < 4, ∀ c < 4,
    trace (7*q+3+c) = input (4*q+c) + trace (7*q+2)
  col0 : ∀ c < 4, trace (28+11*c) = trace (3+c) + trace (10+c)
  col1 : ∀ c < 4, trace (28+11*c+1) = trace (17+c) + trace (24+c)
  col2 : ∀ c < 4, trace (28+11*c+2) = trace (28+11*c) + trace (28+11*c+1)
  col3 : ∀ c < 4, trace (28+11*c+3) = trace (10+c) + trace (28+11*c+2)
  col4 : ∀ c < 4, trace (28+11*c+4) = trace (24+c) + trace (28+11*c+2)
  col5 : ∀ c < 4, trace (28+11*c+5) = trace (3+c) + trace (3+c)
  col6 : ∀ c < 4, trace (28+11*c+6) = trace (28+11*c+4) + trace (28+11*c+5)
  col7 : ∀ c < 4, trace (28+11*c+7) = trace (17+c) + trace (17+c)
  col8 : ∀ c < 4, trace (28+11*c+8) = trace (28+11*c+3) + trace (28+11*c+7)
  col9 : ∀ c < 4, trace (28+11*c+9) = trace (28+11*c) + trace (28+11*c+3)
  col10 : ∀ c < 4, trace (28+11*c+10) = trace (28+11*c+1) + trace (28+11*c+4)

theorem external72_chunk (input trace : Nat → F) (gates : External72 input trace)
    (q c : Nat) (hq : q < 4) (hc : c < 4) :
    trace (7*q+3+c) = p4 input q c := by
  rw [gates.chunkOut q hq c hc, gates.chunk2 q hq,
    gates.chunk1 q hq, gates.chunk0 q hq]
  unfold p4
  ring

theorem external72_column (input trace : Nat → F) (gates : External72 input trace)
    (c : Nat) (hc : c < 4) (row : Fin 4) :
    trace (28+11*c+outputOffset row.val) =
      m4 (p4 input 0 c) (p4 input 1 c) (p4 input 2 c) (p4 input 3 c) row.val := by
  have p0 := external72_chunk input trace gates 0 c (by omega) hc
  have p1 := external72_chunk input trace gates 1 c (by omega) hc
  have p2 := external72_chunk input trace gates 2 c (by omega) hc
  have p3 := external72_chunk input trace gates 3 c (by omega) hc
  norm_num at p0 p1 p2 p3
  fin_cases row <;>
    simp only [outputOffset, m4] <;>
    simp only [gates.col9 c hc, gates.col8 c hc, gates.col10 c hc,
      gates.col6 c hc, gates.col3 c hc, gates.col4 c hc, gates.col5 c hc,
      gates.col7 c hc, gates.col2 c hc, gates.col0 c hc, gates.col1 c hc,
      p0, p1, p2, p3] <;> ring

theorem external72_computes_field (input trace : Nat → F)
    (gates : External72 input trace) (lane : Fin 16) :
    trace (28+11*(lane.val%4)+outputOffset (lane.val/4)) =
      externalField input lane.val := by
  exact external72_column input trace gates (lane.val%4) (Nat.mod_lt _ (by decide))
    ⟨lane.val/4, by omega⟩

theorem p4_cast_kernel (input : List Nat) (q c : Nat) (hq : q < 4) (hc : c < 4) :
    (Poseidon2Width16Kernel.applyP4Chunks input |>.getD (4*q+c) 0 : F) =
      p4 (fun i => (input.getD i 0 : F)) q c := by
  have bound : 4*q+c < 16 := by omega
  have div : (4*q+c)/4 = q := by omega
  simp only [Poseidon2Width16Kernel.applyP4Chunks, Poseidon2Width16Kernel.width,
    List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range bound,
    Option.map_some, Option.getD_some, div]
  norm_num [List.range_succ, p4, Nat.mul_comm, cast_fieldAdd]

theorem m4_cast_kernel (x0 x1 x2 x3 : Nat) (row : Fin 4) :
    (Poseidon2Width16Kernel.applyMds4 [x0,x1,x2,x3] |>.getD row.val 0 : F) =
      m4 (x0 : F) (x1 : F) (x2 : F) (x3 : F) row.val := by
  fin_cases row <;> norm_num [Poseidon2Width16Kernel.applyMds4, m4]

theorem externalField_cast_kernel (input : List Nat) (lane : Fin 16) :
    (Poseidon2Width16Kernel.externalLinearLayer input |>.getD lane.val 0 : F) =
      externalField (fun i => (input.getD i 0 : F)) lane.val := by
  have hc : lane.val%4 < 4 := Nat.mod_lt _ (by decide)
  have p0 := p4_cast_kernel input 0 (lane.val%4) (by decide) hc
  have p1 := p4_cast_kernel input 1 (lane.val%4) (by decide) hc
  have p2 := p4_cast_kernel input 2 (lane.val%4) (by decide) hc
  have p3 := p4_cast_kernel input 3 (lane.val%4) (by decide) hc
  norm_num only [Nat.mul_zero, Nat.mul_one, Nat.zero_add, Nat.reduceMul] at p0 p1 p2 p3
  rw [Nat.add_comm 4 (lane.val%4)] at p1
  rw [Nat.add_comm 8 (lane.val%4)] at p2
  rw [Nat.add_comm 12 (lane.val%4)] at p3
  simp only [Poseidon2Width16Kernel.externalLinearLayer, Poseidon2Width16Kernel.width,
    List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range lane.isLt,
    Option.map_some, Option.getD_some]
  change (Poseidon2Width16Kernel.applyMds4
    [(Poseidon2Width16Kernel.applyP4Chunks input).getD (lane.val%4) 0,
     (Poseidon2Width16Kernel.applyP4Chunks input).getD (lane.val%4+4) 0,
     (Poseidon2Width16Kernel.applyP4Chunks input).getD (lane.val%4+8) 0,
     (Poseidon2Width16Kernel.applyP4Chunks input).getD (lane.val%4+12) 0] |>.getD (lane.val/4) 0 : F) = _
  rw [m4_cast_kernel _ _ _ _ ⟨lane.val/4, by omega⟩]
  rw [p0, p1, p2, p3]
  simp only [externalField, List.getD_eq_getElem?_getD]

/-- The arithmetic template computes the pinned kernel, for arbitrary inputs. -/
theorem external72_refines_kernel (input : List Nat) (trace : Nat → F)
    (gates : External72 (fun i => (input.getD i 0 : F)) trace) (lane : Fin 16) :
    trace (28+11*(lane.val%4)+outputOffset (lane.val/4)) =
      (Poseidon2Width16Kernel.externalLinearLayer input |>.getD lane.val 0 : F) := by
  rw [external72_computes_field _ _ gates, externalField_cast_kernel]


/-- The source multiplication order is x, x², x⁴, x⁶, x⁷. -/
structure Sbox5 (input constant : F) (trace : Nat → F) : Prop where
  add : trace 0 = input + constant
  square : trace 1 = trace 0 * trace 0
  fourth : trace 2 = trace 1 * trace 1
  sixth : trace 3 = trace 1 * trace 2
  seventh : trace 4 = trace 0 * trace 3

theorem sbox5_computes_power (input constant : F) (trace : Nat → F)
    (gates : Sbox5 input constant trace) : trace 4 = (input + constant)^7 := by
  rw [gates.seventh, gates.sixth, gates.fourth, gates.square, gates.add]
  ring

theorem cast_sbox (x : Nat) : (Poseidon2Width16Kernel.sbox x : F) = (x : F)^7 := by
  simp only [Poseidon2Width16Kernel.sbox, cast_fieldMul]
  ring

theorem sbox5_refines_kernel (input constant : Nat) (trace : Nat → F)
    (gates : Sbox5 (input : F) (constant : F) trace) :
    trace 4 = (Poseidon2Width16Kernel.sbox (Poseidon2Width16Kernel.fieldAdd input constant) : F) := by
  rw [sbox5_computes_power _ _ _ gates, cast_sbox, cast_fieldAdd]

theorem externalField_congr (input other : Nat → F)
    (agree : ∀ i < 16, input i = other i) (lane : Fin 16) :
    externalField input lane.val = externalField other lane.val := by
  fin_cases lane <;> simp [externalField, p4, m4, agree]

def externalRoundField (state constants : Nat → F) (lane : Nat) : F :=
  externalField (fun i => (state i + constants i)^7) lane

theorem externalRoundField_cast_kernel (state constants : List Nat) (lane : Fin 16) :
    (Poseidon2Width16Kernel.externalRound state constants |>.getD lane.val 0 : F) =
      externalRoundField (fun i => (state.getD i 0 : F))
        (fun i => (constants.getD i 0 : F)) lane.val := by
  unfold Poseidon2Width16Kernel.externalRound
  rw [externalField_cast_kernel]
  apply externalField_congr
  intro i hi
  simp only [Poseidon2Width16Kernel.width, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_range hi, Option.map_some, Option.getD_some,
    cast_sbox, cast_fieldAdd]

/-- Individual S-box and external-layer gates compose to the kernel round. -/
theorem externalRound_templates_refine_kernel (state constants : List Nat)
    (boxes : Nat → Nat → F) (linear : Nat → F)
    (sboxes : ∀ i < 16,
      Sbox5 (state.getD i 0 : F) (constants.getD i 0 : F) (boxes i))
    (gates : External72 (fun i => boxes i 4) linear) (lane : Fin 16) :
    linear (28+11*(lane.val%4)+outputOffset (lane.val/4)) =
      (Poseidon2Width16Kernel.externalRound state constants |>.getD lane.val 0 : F) := by
  rw [external72_computes_field _ _ gates, externalRoundField_cast_kernel]
  apply externalField_congr
  intro i hi
  exact sbox5_computes_power _ _ _ (sboxes i hi)


def partialSum (input : Nat → F) : Nat → F
  | 0 => input 0
  | n+1 => input (n+1) + partialSum input n

def diagonal (lane : Nat) : F :=
  (Poseidon2Width16Kernel.internalMatrixDiagonal.getD lane 0 : F)

def internalField (input : Nat → F) (lane : Nat) : F :=
  input lane * diagonal lane + partialSum input 15

/-- The source internal layer has 15 additions, 16 products and 16 final additions.
`sums 0` names the input itself; it is not an extra gate. -/
structure Internal47 (input sums products output : Nat → F) : Prop where
  first : sums 0 = input 0
  step : ∀ i < 15, sums (i+1) = input (i+1) + sums i
  product : ∀ i < 16, products i = input i * diagonal i
  final : ∀ i < 16, output i = sums 15 + products i

theorem internal47_sum (input sums products output : Nat → F)
    (gates : Internal47 input sums products output) (i : Nat) (hi : i < 16) :
    sums i = partialSum input i := by
  induction i with
  | zero => exact gates.first
  | succ i ih =>
    rw [gates.step i (by omega), partialSum, ih (by omega)]

theorem internal47_computes_field (input sums products output : Nat → F)
    (gates : Internal47 input sums products output) (lane : Fin 16) :
    output lane.val = internalField input lane.val := by
  rw [gates.final lane.val lane.isLt, gates.product lane.val lane.isLt,
    internal47_sum _ _ _ _ gates 15 (by decide)]
  exact add_comm _ _

def state16 (input : Nat → Nat) : List Nat := (List.range 16).map input

theorem cast_foldl_add (values : List Nat) (initial : Nat) :
    ((values.foldl Poseidon2Width16Kernel.fieldAdd initial : Nat) : F) =
      (initial : F) + (values.map (fun (value : Nat) => (value : F))).sum := by
  induction values generalizing initial with
  | nil => simp
  | cons value values ih =>
    simp only [List.foldl_cons, List.map_cons, List.sum_cons, ih, cast_fieldAdd,
      add_assoc]

theorem internalField_cast_kernel (input : Nat → Nat) (lane : Fin 16) :
    (Poseidon2Width16Kernel.internalLinearLayer (state16 input) |>.getD lane.val 0 : F) =
      internalField (fun i => (input i : F)) lane.val := by
  have entry : (state16 input).getD lane.val 0 = input lane.val := by
    simp only [state16, List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_range lane.isLt, Option.map_some, Option.getD_some]
  have total : (((state16 input).foldl Poseidon2Width16Kernel.fieldAdd 0 : Nat) : F) =
      partialSum (fun i => (input i : F)) 15 := by
    rw [cast_foldl_add]
    norm_num [state16, List.range_succ, partialSum]
    ring
  simp only [Poseidon2Width16Kernel.internalLinearLayer, Poseidon2Width16Kernel.width,
    List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range lane.isLt,
    Option.map_some, Option.getD_some, cast_fieldAdd, cast_fieldMul]
  change (((state16 input).getD lane.val 0 : Nat) : F) * diagonal lane.val +
    (((state16 input).foldl Poseidon2Width16Kernel.fieldAdd 0 : Nat) : F) = _
  rw [entry, total]
  rfl

theorem internal47_refines_kernel (input : Nat → Nat) (sums products output : Nat → F)
    (gates : Internal47 (fun i => (input i : F)) sums products output) (lane : Fin 16) :
    output lane.val =
      (Poseidon2Width16Kernel.internalLinearLayer (state16 input) |>.getD lane.val 0 : F) := by
  rw [internal47_computes_field _ _ _ _ gates, internalField_cast_kernel]


def replaceZero (state : Nat → F) (constant : F) (lane : Nat) : F :=
  if lane = 0 then (state 0 + constant)^7 else state lane

def internalRoundField (state : Nat → F) (constant : F) (lane : Nat) : F :=
  internalField (replaceZero state constant) lane

theorem internalField_congr (input other : Nat → F)
    (agree : ∀ i < 16, input i = other i) (lane : Fin 16) :
    internalField input lane.val = internalField other lane.val := by
  have sums : ∀ i < 16, partialSum input i = partialSum other i := by
    intro i hi
    induction i with
    | zero => exact agree 0 (by decide)
    | succ i ih => simp only [partialSum, agree (i+1) hi, ih (by omega)]
  simp only [internalField, agree lane.val lane.isLt, sums 15 (by decide)]

theorem internalRoundField_cast_kernel (input : Nat → Nat) (constant : Nat)
    (lane : Fin 16) :
    (Poseidon2Width16Kernel.internalRound (state16 input) constant |>.getD lane.val 0 : F) =
      internalRoundField (fun i => (input i : F)) (constant : F) lane.val := by
  have replaced : (state16 input).set 0
      (Poseidon2Width16Kernel.sbox
        (Poseidon2Width16Kernel.fieldAdd ((state16 input).getD 0 0) constant)) =
      state16 (fun i => if i = 0 then
        Poseidon2Width16Kernel.sbox (Poseidon2Width16Kernel.fieldAdd (input 0) constant)
        else input i) := by
    simp [state16, List.range_succ]
  unfold Poseidon2Width16Kernel.internalRound
  rw [replaced, internalField_cast_kernel]
  apply internalField_congr
  intro i _
  by_cases zero : i = 0
  · simp [zero, replaceZero, cast_sbox]
  · simp [zero, replaceZero]

theorem internalRound_templates_refine_kernel (input : Nat → Nat) (constant : Nat)
    (box sums products output : Nat → F)
    (sbox : Sbox5 (input 0 : F) (constant : F) box)
    (gates : Internal47 (fun i => if i = 0 then box 4 else (input i : F))
      sums products output) (lane : Fin 16) :
    output lane.val =
      (Poseidon2Width16Kernel.internalRound (state16 input) constant |>.getD lane.val 0 : F) := by
  rw [internal47_computes_field _ _ _ _ gates, internalRoundField_cast_kernel]
  apply internalField_congr
  intro i _
  by_cases zero : i = 0
  · simp [zero, replaceZero, sbox5_computes_power _ _ _ sbox]
  · simp [zero, replaceZero]


end HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
