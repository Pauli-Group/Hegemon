import SmzaRp04Degree
import SmzaQ38Recovery

/-! Repaired-program nonlinear transport, over the actual 8,130-node DAG and
773 roots parsed from RP04. The q38 witness map is reused because its geometry
is unchanged. Old RP03 nonlinear roots and its acceptance theorem are not used.
The remaining CSR normalization/acceptance endpoint must also be regenerated.
-/
namespace HegemonCrypto.SmallWood.SmzaRp04NonlinearTransport

open Polynomial SmzaRp04Components SmzaQ38Recovery
open V8Smz9ProgramPolynomials
noncomputable section
set_option maxRecDepth 10000
set_option maxHeartbeats 800000

def constraintPolynomial (pub : Nat → Goldilocks) (rows : Nat → Goldilocks[X])
    (root : Fin 773) : Goldilocks[X] :=
  polynomialAt exactNonlinearExpressions pub rows (exactNonlinearRoots.getD root.val 0)

def constraintScalar (pub rows : Nat → Goldilocks) (root : Fin 773) : Goldilocks :=
  fieldAt exactNonlinearExpressions pub rows (exactNonlinearRoots.getD root.val 0)

theorem actual_root_count : exactNonlinearRoots.length = 773 := by decide

theorem actual_constraint_evaluation (pub : Nat → Goldilocks)
    (rows : Nat → Goldilocks[X]) (rowDegree : ∀ row, (rows row).natDegree ≤ 69)
    (root : Fin 773) (point : Goldilocks) :
    (constraintPolynomial pub rows root).eval point =
      constraintScalar pub (fun row => (rows row).eval point) root :=
  polynomialAt_commutes exactNonlinearExpressions SmzaRp04Degree.degree SmzaRp04Degree.certificate
    pub rows 69 rowDegree _ point

theorem actual_constraint_degree (pub : Nat → Goldilocks)
    (rows : Nat → Goldilocks[X]) (rowDegree : ∀ row, (rows row).natDegree ≤ 69)
    (root : Fin 773) : (constraintPolynomial pub rows root).natDegree ≤ 552 := by
  have rootBound : root.val < exactNonlinearRoots.length := by
    rw [actual_root_count]
    exact root.isLt
  have member : exactNonlinearRoots.getD root.val 0 ∈ exactNonlinearRoots := by
    simp [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem rootBound]
  exact (polynomialAt_degree exactNonlinearExpressions SmzaRp04Degree.degree
    SmzaRp04Degree.certificate pub rows 69 rowDegree _).trans
    ((Nat.mul_le_mul_right 69 (SmzaRp04Degree.root_degree _ member)).trans (by decide))

end
end HegemonCrypto.SmallWood.SmzaRp04NonlinearTransport
