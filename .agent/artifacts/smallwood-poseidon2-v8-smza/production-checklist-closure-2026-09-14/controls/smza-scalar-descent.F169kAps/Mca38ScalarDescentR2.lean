import HegemonCrypto.SmallWoodV8Smz9McaRecovery
import Mathlib.LinearAlgebra.Dual.Lemmas
import Mathlib.Algebra.Polynomial.BigOperators
import Mathlib.Algebra.Polynomial.Eval.Degree

/-! Scalar polynomiality descends along a field extension on the exact same support.
No support-size, counting, selector, finite-extension, or quantum assumption is made. -/
namespace HegemonCrypto.SmallWood.Mca38ScalarDescent

open V8Smz9McaRecovery Polynomial
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

variable {F K : Type*} [Field F] [Field K] [Algebra F K]

def projectPolynomial (degree : Nat) (projection : K →ₗ[F] F)
    (polynomial : K[X]) : F[X] :=
  ∑ index ∈ Finset.range (degree + 1),
    Polynomial.monomial index (projection (polynomial.coeff index))

theorem projectPolynomial_degree (degree : Nat) (projection : K →ₗ[F] F)
    (polynomial : K[X]) : (projectPolynomial degree projection polynomial).natDegree ≤ degree := by
  unfold projectPolynomial
  apply Polynomial.natDegree_sum_le_of_forall_le
  intro index member
  exact (Polynomial.natDegree_monomial_le _).trans
    (Nat.le_of_lt_succ (Finset.mem_range.mp member))

theorem projectPolynomial_eval (degree : Nat) (projection : K →ₗ[F] F)
    (polynomial : K[X]) (bounded : polynomial.natDegree ≤ degree) (point : F) :
    (projectPolynomial degree projection polynomial).eval point =
      projection (polynomial.eval (algebraMap F K point)) := by
  simp only [projectPolynomial, Polynomial.eval_finsetSum, Polynomial.eval_monomial]
  rw [Polynomial.eval_eq_sum_range' (Nat.lt_succ_of_le bounded), map_sum]
  apply Finset.sum_congr rfl
  intro index _
  rw [← (algebraMap F K).map_pow point index]
  simpa only [Algebra.smul_def, Algebra.algebraMap_self_apply, smul_eq_mul, mul_comm] using
    (projection.map_smul (point ^ index) (polynomial.coeff index)).symm

theorem scalar_retraction_exists :
    ∃ projection : K →ₗ[F] F, ∀ scalar : F,
      projection (algebraMap F K scalar) = scalar := by
  obtain ⟨projection, fixesOne⟩ :=
    Module.Projective.exists_dual_eq_one F (one_ne_zero : (1 : K) ≠ 0)
  refine ⟨projection, ?_⟩
  intro scalar
  calc
    projection (algebraMap F K scalar) = projection (scalar • (1 : K)) := by
      rw [Algebra.smul_def, mul_one]
    _ = scalar • projection 1 := projection.map_smul scalar 1
    _ = scalar := by rw [fixesOne, smul_eq_mul, mul_one]

variable {Position : Type*}

theorem embedded_scalar_codeOn_iff (point : Position → F) (degree : Nat)
    (word : Position → F) (support : Finset Position) :
    CodeOn (fun index => algebraMap F K (point index)) degree
      (fun index => algebraMap F K (word index)) support ↔
        CodeOn point degree word support := by
  constructor
  · rintro ⟨polynomial, bounded, agrees⟩
    obtain ⟨projection, retracts⟩ := scalar_retraction_exists (F := F) (K := K)
    refine ⟨projectPolynomial degree projection polynomial,
      projectPolynomial_degree degree projection polynomial, ?_⟩
    intro index member
    rw [projectPolynomial_eval degree projection polynomial bounded,
      agrees index member, retracts]
  · rintro ⟨polynomial, bounded, agrees⟩
    refine ⟨polynomial.map (algebraMap F K), Polynomial.natDegree_map_le.trans bounded, ?_⟩
    intro index member
    rw [Polynomial.eval_map_apply, agrees index member]

theorem embedded_scalar_noncode_iff (point : Position → F) (degree : Nat)
    (word : Position → F) (support : Finset Position) :
    (¬ CodeOn (fun index => algebraMap F K (point index)) degree
      (fun index => algebraMap F K (word index)) support) ↔
        ¬ CodeOn point degree word support :=
  not_congr (embedded_scalar_codeOn_iff point degree word support)

end
end HegemonCrypto.SmallWood.Mca38ScalarDescent

