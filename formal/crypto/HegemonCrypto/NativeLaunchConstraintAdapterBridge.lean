import Mathlib.Tactic.LinearCombination

/-! Source-shaped constant/Wire sparse lowering and HTLC arithmetic gates.
Matches circuit.rs constant shifting and emitted add/sub/copy/product rows.
Arithmetic meanings are independent equations, not Relation := rows-zero.
Exact native graph/table instantiation, duplicate-coefficient BTreeMap
normalization, packed lane transport, RP06 expression-DAG semantics and Rust
field refinement remain open. This local compiler bridge closes no gate. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchConstraintAdapterBridge
noncomputable section
variable {F : Type*} [Field F]

inductive Word (F : Type*) where
  | constant : F → Word F
  | wire : Nat → Word F

def read (assignment : Nat → F) : Word F → F
  | .constant value => value
  | .wire index => assignment index

def sparseEval (assignment : Nat → F) : List (Nat × F) → F
  | [] => 0
  | (index, coefficient) :: rest => coefficient * assignment index + sparseEval assignment rest

def termEval (assignment : Nat → F) : List (Word F × F) → F
  | [] => 0
  | (word, coefficient) :: rest => coefficient * read assignment word + termEval assignment rest

/-- Return wire terms and the constant amount moved to the RHS. Repeated
wire terms remain in this pre-coalescing list; no map-normalization claim. -/
def lower : List (Word F × F) → List (Nat × F) × F
  | [] => ([], 0)
  | (.constant value, coefficient) :: rest =>
      let below := lower rest
      (below.1, coefficient * value + below.2)
  | (.wire index, coefficient) :: rest =>
      let below := lower rest
      ((index, coefficient) :: below.1, below.2)

def rowSatisfied (assignment : Nat → F) (terms : List (Word F × F)) (target : F) : Prop :=
  sparseEval assignment (lower terms).1 = target - (lower terms).2

theorem lower_decomposition (assignment : Nat → F) (terms : List (Word F × F)) :
    termEval assignment terms = sparseEval assignment (lower terms).1 + (lower terms).2 := by
  induction terms with
  | nil => simp [termEval, lower, sparseEval]
  | cons term rest ih =>
      rcases term with ⟨word, coefficient⟩
      cases word <;> simp only [termEval, read, lower, sparseEval, ih] <;> ac_rfl

theorem lowered_row_iff (assignment : Nat → F) (terms : List (Word F × F)) (target : F) :
    rowSatisfied assignment terms target ↔ termEval assignment terms = target := by
  rw [lower_decomposition]
  exact eq_sub_iff_add_eq

theorem copy_row_semantics (assignment : Nat → F) (left right : Word F) :
    rowSatisfied assignment [(left, 1), (right, -1)] 0 ↔ read assignment left = read assignment right := by
  rw [lowered_row_iff]
  simpa [termEval, sub_eq_add_neg] using
    (sub_eq_zero : read assignment left - read assignment right = 0 ↔ read assignment left = read assignment right)

theorem add_row_semantics (assignment : Nat → F) (out left right : Word F) :
    rowSatisfied assignment [(out, 1), (left, -1), (right, -1)] 0 ↔
      read assignment out = read assignment left + read assignment right := by
  rw [lowered_row_iff]
  simp only [termEval, one_mul, neg_mul, add_zero]
  constructor <;> intro h <;> linear_combination h

theorem sub_row_semantics (assignment : Nat → F) (out left right : Word F) :
    rowSatisfied assignment [(out, 1), (left, -1), (right, 1)] 0 ↔
      read assignment out = read assignment left - read assignment right := by
  rw [lowered_row_iff]
  simp only [termEval, one_mul, neg_mul, add_zero]
  constructor <;> intro h <;> linear_combination h

theorem public_binding_semantics (assignment : Nat → F) (index : Nat) (publicValue : F) :
    rowSatisfied assignment [(.wire index, 1)] publicValue ↔ assignment index = publicValue := by
  simp [rowSatisfied, lower, sparseEval]

/-- Current HTLC batches evaluate occurrenceOut-occurrenceLeft*occurrenceRight.
The three emitted sparse copy rows transfer this to canonical Word operands. -/
theorem copied_product_semantics (assignment : Nat → F) (out left right : Word F)
    (outIndex leftIndex rightIndex : Nat)
    (copyOut : rowSatisfied assignment [(.wire outIndex, 1), (out, -1)] 0)
    (copyLeft : rowSatisfied assignment [(.wire leftIndex, 1), (left, -1)] 0)
    (copyRight : rowSatisfied assignment [(.wire rightIndex, 1), (right, -1)] 0)
    (nonlinear : assignment outIndex - assignment leftIndex * assignment rightIndex = 0) :
    read assignment out = read assignment left * read assignment right := by
  have outEq := (copy_row_semantics assignment (.wire outIndex) out).mp copyOut
  have leftEq := (copy_row_semantics assignment (.wire leftIndex) left).mp copyLeft
  have rightEq := (copy_row_semantics assignment (.wire rightIndex) right).mp copyRight
  change assignment outIndex = read assignment out at outEq
  change assignment leftIndex = read assignment left at leftEq
  change assignment rightIndex = read assignment right at rightEq
  rw [outEq, leftEq, rightEq] at nonlinear
  exact sub_eq_zero.mp nonlinear

end
end HegemonCrypto.NativeLaunchConstraintAdapterBridge
