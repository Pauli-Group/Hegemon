import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Tactic.Ring

/-!
# Algebraic normalization of native HTLC graph rows

This is a pure model of `smallwood_htlc/circuit.rs:325-347`, not a theorem
about Rust execution. Repeated wire coefficients are added, constant terms
are shifted to the target, zero coefficients are omitted, and an empty zero
equation may be dropped. All statements quantify over arbitrary field values.
-/
namespace HegemonCrypto.SmallWood.NativeHtlcGraphNormalization
open scoped BigOperators
set_option autoImplicit false

variable {F : Type*} [Field F] {n : Nat}

inductive Word (F : Type*) (n : Nat) where
  | constant (value : F)
  | wire (index : Fin n)

abbrev Term (F : Type*) (n : Nat) := Word F n × F

def wordValue (assignment : Fin n → F) : Word F n → F
  | .constant value => value
  | .wire index => assignment index

def termCoefficient (term : Term F n) (index : Fin n) : F :=
  match term.1 with
  | .constant _ => 0
  | .wire source => if index = source then term.2 else 0

def constantValue (term : Term F n) : F :=
  match term.1 with
  | .constant value => term.2 * value
  | .wire _ => 0

def coefficients : List (Term F n) → Fin n → F
  | [] => fun _ => 0
  | term :: rest => fun index => termCoefficient term index + coefficients rest index

def constants : List (Term F n) → F
  | [] => 0
  | term :: rest => constantValue term + constants rest

def originalValue (assignment : Fin n → F) : List (Term F n) → F
  | [] => 0
  | term :: rest => term.2 * wordValue assignment term.1 + originalValue assignment rest

def normalizedValue (assignment : Fin n → F) (terms : List (Term F n)) : F :=
  ∑ index, coefficients terms index * assignment index

theorem one_term_decomposition (assignment : Fin n → F) (term : Term F n) :
    term.2 * wordValue assignment term.1 =
      (∑ index, termCoefficient term index * assignment index) + constantValue term := by
  rcases term with ⟨word, coefficient⟩
  cases word with
  | constant value => simp [wordValue, termCoefficient, constantValue]
  | wire source => simp [wordValue, termCoefficient, constantValue]

/-- Aggregating duplicate wire coefficients and shifting constants preserves
the complete linear form, for every assignment and every list of terms. -/
theorem normalized_value_decomposition
    (assignment : Fin n → F) (terms : List (Term F n)) :
    originalValue assignment terms = normalizedValue assignment terms + constants terms := by
  induction terms with
  | nil => simp [originalValue, normalizedValue, coefficients, constants]
  | cons term rest ih =>
      rw [originalValue, one_term_decomposition, ih]
      simp only [normalizedValue, coefficients, constants, add_mul, Finset.sum_add_distrib]
      ring

/-- The normalized target is exactly the original target minus the constant
contribution, matching Rust's iterative `shifted = shifted - coefficient*value`. -/
theorem shifted_equation_iff
    (assignment : Fin n → F) (terms : List (Term F n)) (target : F) :
    normalizedValue assignment terms = target - constants terms ↔
      originalValue assignment terms = target := by
  rw [normalized_value_decomposition]
  exact eq_sub_iff_add_eq

noncomputable def retainedIndices (terms : List (Term F n)) : Finset (Fin n) :=
  by
    classical
    exact Finset.univ.filter (fun index => coefficients terms index ≠ 0)

/-- Omitting aggregated zero coefficients changes neither the equation nor
its interpretation. The sorted BTreeMap order is immaterial over a field. -/
theorem drop_zero_coefficients
    (assignment : Fin n → F) (terms : List (Term F n)) :
    (∑ index ∈ retainedIndices terms, coefficients terms index * assignment index) =
      normalizedValue assignment terms := by
  classical
  unfold retainedIndices normalizedValue
  apply Finset.sum_subset (Finset.filter_subset _ _)
  intro index _ absent
  have zero : coefficients terms index = 0 := by
    by_contra nonzero
    exact absent (Finset.mem_filter.mpr ⟨Finset.mem_univ index, nonzero⟩)
  simp [zero]

/-- This models the emitter's only deletion: an empty normalized row with
zero shifted target. It does not delete an empty contradictory equation. -/
def emittedEquation
    (assignment : Fin n → F) (terms : List (Term F n)) (target : F) : Prop :=
  by
    classical
    exact if (∀ index, coefficients terms index = 0) ∧ target - constants terms = 0 then
      True
    else
      normalizedValue assignment terms = target - constants terms

theorem emitted_equation_iff
    (assignment : Fin n → F) (terms : List (Term F n)) (target : F) :
    emittedEquation assignment terms target ↔ originalValue assignment terms = target := by
  classical
  unfold emittedEquation
  split_ifs with emptyZero
  · have normalizedZero : normalizedValue assignment terms = 0 := by
      simp [normalizedValue, emptyZero.1]
    have satisfies : normalizedValue assignment terms = target - constants terms := by
      rw [normalizedZero, emptyZero.2]
    exact ⟨fun _ => (shifted_equation_iff assignment terms target).mp satisfies,
      fun _ => trivial⟩
  · exact shifted_equation_iff assignment terms target

/-- A normalized empty row whose shifted target is nonzero remains a
contradiction; accepting it is impossible for every assignment. -/
theorem empty_nonzero_row_rejects
    (assignment : Fin n → F) (terms : List (Term F n)) (target : F)
    (empty : ∀ index, coefficients terms index = 0)
    (nonzero : target - constants terms ≠ 0) :
    ¬ emittedEquation assignment terms target := by
  intro accepted
  have normalized := (shifted_equation_iff assignment terms target).mpr
    ((emitted_equation_iff assignment terms target).mp accepted)
  have zero : normalizedValue assignment terms = 0 := by
    simp [normalizedValue, empty]
  rw [zero] at normalized
  exact nonzero normalized.symm

theorem emitted_rows_iff {Row : Type*}
    (assignment : Fin n → F) (terms : Row → List (Term F n)) (target : Row → F) :
    (∀ row, emittedEquation assignment (terms row) (target row)) ↔
      (∀ row, originalValue assignment (terms row) = target row) := by
  constructor
  · intro allRows row
    exact (emitted_equation_iff assignment (terms row) (target row)).mp (allRows row)
  · intro allRows row
    exact (emitted_equation_iff assignment (terms row) (target row)).mpr (allRows row)

/-- Exact additive node row from Rust: output - left - right = 0. -/
theorem additive_node_row_iff
    (assignment : Fin n → F) (output : Fin n) (left right : Word F n) :
    emittedEquation assignment [(.wire output, 1), (left, -1), (right, -1)] 0 ↔
      assignment output = wordValue assignment left + wordValue assignment right := by
  rw [emitted_equation_iff]
  have form : originalValue assignment
      [(.wire output, 1), (left, -1), (right, -1)] =
      assignment output - (wordValue assignment left + wordValue assignment right) := by
    simp only [originalValue, wordValue]
    ring
  rw [form]
  exact sub_eq_zero

/-- Exact subtractive node row from Rust: output - left + right = 0. -/
theorem subtractive_node_row_iff
    (assignment : Fin n → F) (output : Fin n) (left right : Word F n) :
    emittedEquation assignment [(.wire output, 1), (left, -1), (right, 1)] 0 ↔
      assignment output = wordValue assignment left - wordValue assignment right := by
  rw [emitted_equation_iff]
  have form : originalValue assignment
      [(.wire output, 1), (left, -1), (right, 1)] =
      assignment output - (wordValue assignment left - wordValue assignment right) := by
    simp only [originalValue, wordValue]
    ring
  rw [form]
  exact sub_eq_zero

/-- Exact asserted equality row from Rust: left - right = 0. -/
theorem equality_row_iff
    (assignment : Fin n → F) (left right : Word F n) :
    emittedEquation assignment [(left, 1), (right, -1)] 0 ↔
      wordValue assignment left = wordValue assignment right := by
  rw [emitted_equation_iff]
  have form : originalValue assignment [(left, 1), (right, -1)] =
      wordValue assignment left - wordValue assignment right := by
    simp only [originalValue]
    ring
  rw [form]
  exact sub_eq_zero

def zeroExtension (wireCount : Nat) (seed : Nat → F) (index : Nat) : F :=
  if index < wireCount then seed index else 0

/-- Rust emits `wire[index] = 0` from the canonical wire count up to the
rounded row capacity. Those equations uniquely extend the unchanged prefix
by zeros; the result also covers a graph with no tail padding. -/
theorem canonical_padding_iff
    (wireCount capacity : Nat) (fits : wireCount ≤ capacity)
    (assignment seed : Nat → F) :
    (∀ index < capacity, assignment index = zeroExtension wireCount seed index) ↔
      (∀ index < wireCount, assignment index = seed index) ∧
      (∀ index, wireCount ≤ index → index < capacity → assignment index = 0) := by
  constructor
  · intro allCells
    constructor
    · intro index inside
      have cell := allCells index (Nat.lt_of_lt_of_le inside fits)
      simpa [zeroExtension, inside] using cell
    · intro index padding inside
      have cell := allCells index inside
      simpa [zeroExtension, Nat.not_lt.mpr padding] using cell
  · rintro ⟨prefixEq, padding⟩ index inside
    by_cases inPrefix : index < wireCount
    · simpa [zeroExtension, inPrefix] using prefixEq index inPrefix
    · simpa [zeroExtension, inPrefix] using
        padding index (Nat.le_of_not_gt inPrefix) inside

end HegemonCrypto.SmallWood.NativeHtlcGraphNormalization
