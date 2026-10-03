import Q38CompleteAlgebraR2
import HegemonCrypto.SmallWoodV8Smz9EagerSimulator

/-! Reconstruct all 140 opened rows and all five DECS masks from the actual
38-query public coordinates. This is the missing deterministic reconstruction
step, not an adaptive-oracle privacy assertion. -/
namespace HegemonCrypto.SmallWood.V8SmzaOpenedRows
open V8Smz9ZeroKnowledge V8Smz9RuntimeFieldLayout V8Smz9SingleProofPrivacy
open V8Smz9EagerPrivacy V8Smz9EagerSimulator V8Smz9RuntimeDistribution
open V8SmzaMathPrivacy
open Polynomial
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option backward.isDefEq.respectTransparency false

abbrev Rows (F : Type*) := Fin 38 → Fin 140 → F
abbrev Masks (F : Type*) := Fin 38 → Fin 5 → F

def interpolateValue {F : Type*} [Field F] (values : Fin 406 → F) (point : F) : F :=
  ∑ node : Fin 406, (Lagrange.basis Finset.univ
    (fun i : Fin 406 => (i.val : F)) node).eval point * values node

def rowValues {F : Type*} (heads : Heads F) (tails : Tails F)
    (row : Fin 140) : Fin 406 → F := Fin.append (tails row) (heads row)

def openedRows {F : Type*} [Field F] (heads : Heads F) (tails : Tails F)
    (targets : Fin 38 → F) : Rows F :=
  fun opening row => interpolateValue (rowValues heads tails row) (targets opening)

def combinationValues {F : Type*} [Field F] (heads : PublicCombinationHeads F)
    (early : Earlier F) (targets : Fin 38 → F) : Fin 38 → Fin 12 → F :=
  fun opening combination =>
    interpolateValue (Fin.append (early combination) (heads combination)) (targets opening)

def reconstruct {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F)
    (injective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (heads : PublicCombinationHeads F) (early : Earlier F)
    (targets : Fin 38 → F) (subset : Later F) : Rows F :=
  fun opening => (rowObservationEquiv points injective).symm
    (combinationValues heads early targets opening, subset opening)

theorem earlier_is_row_combination {F : Type*} [Field F]
    (points : Fin 6 → F) (tails : Tails F) (combination : Fin 12) (tail : Fin 38) :
    earlier points tails combination tail =
      ∑ row : Fin 140, smz9LvcsCombinationCoefficient points combination row * tails row tail := by
  exact (row_combination_partition points (fun row => tails row tail) combination).symm

theorem combined_row_values {F : Type*} [Field F]
    (points : Fin 6 → F) (heads : Heads F) (tails : Tails F)
    (combination : Fin 12) (node : Fin 406) :
    Fin.append (earlier points tails combination)
        (lvcsPublicCombinationHeads points heads combination) node =
      ∑ row : Fin 140, smz9LvcsCombinationCoefficient points combination row *
        rowValues heads tails row node := by
  refine Fin.addCases (m := 38) (n := 368) ?_ ?_ node
  · intro tail
    calc
      _ = earlier points tails combination tail := Fin.append_left _ _ tail
      _ = ∑ row : Fin 140, smz9LvcsCombinationCoefficient points combination row * tails row tail :=
        earlier_is_row_combination points tails combination tail
      _ = _ := by
        apply Finset.sum_congr rfl
        intro row _
        exact congrArg (fun value => smz9LvcsCombinationCoefficient points combination row * value)
          (Fin.append_left (tails row) (heads row) tail).symm
  · intro column
    simp only [Fin.append_right, rowValues]
    rfl

theorem combination_values_are_actual {F : Type*} [Field F]
    (points : Fin 6 → F) (heads : Heads F) (tails : Tails F)
    (targets : Fin 38 → F) (opening : Fin 38) :
    combinationValues (lvcsPublicCombinationHeads points heads) (earlier points tails)
      targets opening = rowCombination points (openedRows heads tails targets opening) := by
  funext combination
  unfold combinationValues interpolateValue
  simp_rw [combined_row_values, Finset.mul_sum]
  rw [Finset.sum_comm]
  unfold rowCombination openedRows interpolateValue
  apply Finset.sum_congr rfl
  intro row _
  rw [Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro node _
  ring

theorem subset_values_are_actual {F : Type*} [Field F]
    (heads : Heads F) (tails : Tails F) (targets : Fin 38 → F) (opening : Fin 38) :
    fullSubset heads tails targets opening = rowSubset (openedRows heads tails targets opening) := by
  funext subset
  change headContribution heads targets opening subset +
      tailEvaluationMap targets (fun tail => tails (smz9LvcsSubsetRow subset) tail) opening = _
  unfold headContribution tailEvaluationMap tailLagrangeCoefficient
  unfold rowSubset openedRows interpolateValue rowValues
  rw [Fin.sum_univ_add (a := 38) (b := 368)]
  simp only [Fin.append_left, Fin.append_right]
  change (∑ column : Fin 368, heads (smz9LvcsSubsetRow subset) column * _) +
      (∑ tail : Fin 38, _ * tails (smz9LvcsSubsetRow subset) tail) = _
  rw [add_comm]
  congr 1
  apply Finset.sum_congr rfl
  intro column _
  exact mul_comm _ _

/-- No full-row equality is a hypothesis: every opened row is reconstructed
from the twelve earlier combinations and 128 revealed subset evaluations. -/
theorem reconstruct_roundtrip {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F)
    (injective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (heads : Heads F) (tails : Tails F) (targets : Fin 38 → F) :
    reconstruct points injective (lvcsPublicCombinationHeads points heads)
      (earlier points tails) targets (fullSubset heads tails targets) =
        openedRows heads tails targets := by
  funext opening
  unfold reconstruct
  rw [combination_values_are_actual, subset_values_are_actual]
  exact (rowObservationEquiv points injective).symm_apply_apply _

def recoverMasks {F : Type*} [Field F] (gamma : Gamma F) (reply : Decs F)
    (targets : Fin 38 → F) (rows : Rows F) : Masks F :=
  fun opening polynomial => (coefficientPolynomial (reply polynomial)).eval (targets opening) -
    ∑ row : Fin 140, gamma polynomial row * rows opening row

theorem unmasked_coefficients_evaluate {F : Type*} [Field F]
    (nodesInjective : Function.Injective (fun i : Fin 406 => (i.val : F)))
    (gamma : Gamma F) (heads : Heads F) (tails : Tails F)
    (targets : Fin 38 → F) (opening : Fin 38) (polynomial : Fin 5) :
    (coefficientPolynomial (unmasked gamma heads tails polynomial)).eval (targets opening) =
      ∑ row : Fin 140, gamma polynomial row * openedRows heads tails targets opening row := by
  let p := Lagrange.interpolate Finset.univ (fun i : Fin 406 => (i.val : F))
    (fun node => ∑ row : Fin 140, gamma polynomial row * rowValues heads tails row node)
  have degree : p.natDegree < 406 := by
    by_cases zero : p = 0
    · simp [zero]
    apply (natDegree_lt_iff_degree_lt zero).2
    simpa only [Finset.card_univ, Fintype.card_fin] using
      Lagrange.degree_interpolate_lt (s := Finset.univ) nodesInjective.injOn
        (r := fun node => ∑ row : Fin 140, gamma polynomial row * rowValues heads tails row node)
  change (coefficientPolynomial (fun i : Fin 406 => p.coeff i.val)).eval _ = _
  rw [coefficient_polynomial_of_coefficients p degree]
  simp only [p, Lagrange.interpolate_apply, eval_finsetSum, eval_mul, eval_C, Finset.sum_mul]
  rw [Finset.sum_comm]
  unfold openedRows interpolateValue
  apply Finset.sum_congr rfl
  intro row _
  rw [Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro node _
  ring

theorem recover_masks_roundtrip {F : Type*} [Field F]
    (nodesInjective : Function.Injective (fun i : Fin 406 => (i.val : F)))
    (gamma : Gamma F) (heads : Heads F) (tails : Tails F) (mask : Decs F)
    (targets : Fin 38 → F) :
    recoverMasks gamma (response gamma heads tails mask) targets (openedRows heads tails targets) =
      fun opening polynomial => (coefficientPolynomial (mask polynomial)).eval (targets opening) := by
  funext opening polynomial
  unfold recoverMasks response
  change (coefficientPolynomial (unmasked gamma heads tails polynomial + mask polynomial)).eval _ - _ = _
  rw [coefficient_polynomial_add, eval_add,
    unmasked_coefficients_evaluate nodesInjective]
  ring

theorem recovered_public_masks_are_actual {F : Type*} [Field F] [Fintype F]
    (nodesInjective : Function.Injective (fun i : Fin 406 => (i.val : F)))
    (points : Fin 6 → F)
    (injective : Function.Injective (smz9LvcsSelectedBlockMap points))
    (gamma : Gamma F) (heads : Heads F) (tails : Tails F) (mask : Decs F)
    (targets : Fin 38 → F) :
    recoverMasks gamma (response gamma heads tails mask) targets
      (reconstruct points injective (lvcsPublicCombinationHeads points heads)
        (earlier points tails) targets (fullSubset heads tails targets)) =
      fun opening polynomial => (coefficientPolynomial (mask polynomial)).eval (targets opening) := by
  rw [reconstruct_roundtrip, recover_masks_roundtrip nodesInjective]

end
end HegemonCrypto.SmallWood.V8SmzaOpenedRows
