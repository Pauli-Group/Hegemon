import HegemonCrypto.SmallWoodV8Smz9PiopReconstruction
import SmzaRp05ExecutableChallengeStage

/-!
# Computable Lagrange restoration

SOURCE-ONLY, NOT COMPILED. Executable definitions below use a finite syntax
tree and computable Goldilocks arithmetic (ZMod inversion uses extended
Euclid), not Polynomial's noncomputable representation. Polynomial is used
ONLY in the denotation and proof layer. `restoreSixWords` takes precisely
six points, six evaluations and 483 existing high words and returns 489
canonical words. No reconstructed transcript or successful-check input.

The algorithm subtracts the shifted high polynomial, constructs the low
Lagrange polynomial, and adds the shifted high part, as Rust poly_restore
(smallwood_engine.rs:17157). The implementation uses generic interpolation
also on consecutive points; equality to Rust's optimized consecutive
branch and its machine-integer operations is not claimed here.

The general k/m construction also covers seven points and 126 high words.
It does not perform the later linear packing-sum correction. Distinctness
is needed only by the evaluation/high preservation theorems, not by the
computable function. Admissible six-opening points are distinct upstream.
No compiler or performance claim is made; this direct tree interpreter is
a correctness-first computational primitive, not an optimized backend.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableRestore

open Polynomial DecsRestore
open SmzaRp05ExecutableChallengeStage (FieldWord)
open scoped BigOperators
set_option autoImplicit false

inductive Expr where
  | term : Nat → Goldilocks → Expr
  | add : Expr → Expr → Expr
  | mul : Expr → Expr → Expr

def eval : Expr → Goldilocks → Goldilocks
  | .term degree value, point => value * point ^ degree
  | .add left right, point => eval left point + eval right point
  | .mul left right, point => eval left point * eval right point

def coefficient : Expr → Nat → Goldilocks
  | .term degree value, index => if degree = index then value else 0
  | .add left right, index => coefficient left index + coefficient right index
  | .mul left right, index =>
      ∑ pair ∈ Finset.antidiagonal index,
        coefficient left pair.1 * coefficient right pair.2

def sumExpr : (n : Nat) → (Fin n → Expr) → Expr
  | 0, _ => .term 0 0
  | n + 1, terms => .add (terms 0) (sumExpr n fun i => terms i.succ)

def productExpr : (n : Nat) → (Fin n → Expr) → Expr
  | 0, _ => .term 0 1
  | n + 1, terms => .mul (terms 0) (productExpr n fun i => terms i.succ)

def divisor (x y : Goldilocks) : Expr :=
  .mul (.term 0 ((x - y)⁻¹)) (.add (.term 1 1) (.term 0 (-y)))

def basis {k : Nat} (points : Fin k → Goldilocks) (i : Fin k) : Expr :=
  productExpr k fun j =>
    if j ∈ (Finset.univ : Finset (Fin k)).erase i then
      divisor (points i) (points j) else .term 0 1

def highPart (k : Nat) {m : Nat} (high : Fin m → Goldilocks) : Expr :=
  sumExpr m fun i => .term (k + i.val) (high i)

def restore {k m : Nat} (points values : Fin k → Goldilocks)
    (high : Fin m → Goldilocks) : Expr :=
  let shifted := highPart k high
  .add (sumExpr k fun i =>
    .mul (.term 0 (values i - eval shifted (points i))) (basis points i)) shifted

def toField (word : FieldWord) : Goldilocks := word.val

def toWord (value : Goldilocks) : FieldWord := ⟨value.val, value.val_lt⟩

def restoreSixWords (points values : Fin 6 → FieldWord)
    (high : Fin 483 → FieldWord) : Fin 489 → FieldWord :=
  fun i => toWord (coefficient
    (restore (fun j => toField (points j)) (fun j => toField (values j))
      (fun j => toField (high j))) i.val)

def restoreSevenWords (points values : Fin 7 → FieldWord)
    (high : Fin 126 → FieldWord) : Fin 133 → FieldWord :=
  fun i => toWord (coefficient
    (restore (fun j => toField (points j)) (fun j => toField (values j))
      (fun j => toField (high j))) i.val)

/-! Everything above this boundary is computable. -/
noncomputable section

def denote : Expr → Goldilocks[X]
  | .term degree value => Polynomial.monomial degree value
  | .add left right => denote left + denote right
  | .mul left right => denote left * denote right

theorem eval_correct (expression : Expr) (point : Goldilocks) :
    eval expression point = (denote expression).eval point := by
  induction expression with
  | term degree value => simp [eval, denote]
  | add left right ihLeft ihRight => simp [eval, denote, ihLeft, ihRight]
  | mul left right ihLeft ihRight => simp [eval, denote, ihLeft, ihRight]

theorem coefficient_correct (expression : Expr) (index : Nat) :
    coefficient expression index = (denote expression).coeff index := by
  induction expression generalizing index with
  | term degree value => simp [coefficient, denote, Polynomial.coeff_monomial]
  | add left right ihLeft ihRight => simp [coefficient, denote, ihLeft, ihRight]
  | mul left right ihLeft ihRight =>
      simp only [coefficient, denote, Polynomial.coeff_mul, ihLeft, ihRight]

theorem denote_sum (n : Nat) (terms : Fin n → Expr) :
    denote (sumExpr n terms) = ∑ i, denote (terms i) := by
  induction n with
  | zero => simp [sumExpr, denote]
  | succ n ih => simp only [sumExpr, denote, Fin.sum_univ_succ, ih]

theorem denote_product (n : Nat) (terms : Fin n → Expr) :
    denote (productExpr n terms) = ∏ i, denote (terms i) := by
  induction n with
  | zero => simp [productExpr, denote]
  | succ n ih => simp only [productExpr, denote, Fin.prod_univ_succ, ih]

theorem denote_divisor (x y : Goldilocks) :
    denote (divisor x y) = Lagrange.basisDivisor x y := by
  simp only [divisor, denote, Lagrange.basisDivisor, Polynomial.monomial_zero_left,
    Polynomial.monomial_one_one_eq_X, map_neg, sub_eq_add_neg]

theorem denote_basis {k : Nat} (points : Fin k → Goldilocks) (i : Fin k) :
    denote (basis points i) = Lagrange.basis Finset.univ points i := by
  rw [basis, denote_product]
  have terms : ∀ j : Fin k,
      denote (if j ∈ (Finset.univ : Finset (Fin k)).erase i then
        divisor (points i) (points j) else .term 0 1) =
      if j ∈ (Finset.univ : Finset (Fin k)).erase i then
        Lagrange.basisDivisor (points i) (points j) else 1 := by
    intro j
    split <;> simp [denote_divisor, denote]
  simp_rw [terms]
  exact Finset.prod_ite_mem_eq _ _

/-- Equality to the library restoration requires no distinctness premise;
distinctness is needed to assert that restoration interpolates the input. -/
theorem restore_eq {k m : Nat} (points values : Fin k → Goldilocks)
    (high : Fin m → Goldilocks) :
    denote (restore points values high) =
      restorePolynomial Finset.univ points (denote (highPart k high)) values := by
  simp only [restore, denote, denote_sum, denote_basis, Polynomial.monomial_zero_left,
    eval_correct, restorePolynomial, Lagrange.interpolate_apply]

theorem restore_evaluation {k m : Nat} (points values : Fin k → Goldilocks)
    (high : Fin m → Goldilocks) (distinct : Function.Injective points) (i : Fin k) :
    eval (restore points values high) (points i) = values i := by
  rw [eval_correct, restore_eq]
  exact restore_polynomial_eval distinct.injOn (Finset.mem_univ i)

theorem restore_high_coefficients {k m : Nat} (points values : Fin k → Goldilocks)
    (high : Fin m → Goldilocks) (distinct : Function.Injective points)
    (degree : Nat) (above : k ≤ degree) :
    coefficient (restore points values high) degree =
      coefficient (highPart k high) degree := by
  rw [coefficient_correct, coefficient_correct, restore_eq]
  apply restore_polynomial_same_high_coefficients distinct.injOn
  simpa using above

/-- The six-point computational high part is exactly the existing PIOP
mathematical high part, not an arbitrary supplied high polynomial. -/
theorem six_high_eq (high : Fin 483 → Goldilocks) :
    denote (highPart 6 high) = V8Smz9PiopReconstruction.nonlinearHighPart high := by
  simp only [highPart, denote_sum, denote, V8Smz9PiopReconstruction.nonlinearHighPart,
    Polynomial.C_mul_X_pow_eq_monomial]

theorem six_restore_eq (points values : Fin 6 → Goldilocks)
    (high : Fin 483 → Goldilocks) :
    denote (restore points values high) =
      restorePolynomial Finset.univ points
        (V8Smz9PiopReconstruction.nonlinearHighPart high) values := by
  rw [restore_eq, six_high_eq]

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutableRestore
