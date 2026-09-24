import HegemonCrypto.SmallWoodV8Smz9RuntimeDistribution
import Mathlib.Logic.Equiv.Fin.Basic

/-!
# Exact SMZ9 field coin allocation

This file connects the 12,201 ideal accepted field outputs to the six existing honest-prover
coin types. The map is an explicit permutation, with explicit inverses; it does not obtain an
arbitrary equivalence from equality of cardinalities.

The input order is witness row/word, then five alternating nonlinear/linear mask draws, then
PCS polynomial/opening/local-column, then LVCS row/tail and DECS polynomial/coefficient.
Witness rows are indexed by their destination, not the chronology of concurrent OS calls.
The five nonlinear PCS polynomials have seven randomizer columns each, followed by the five
linear polynomials with one column each. Their 240 words are transposed to opening/column.
The low/high products in the existing mask coin types split sampled coefficients; they do not
apply the later evaluation maps. In particular the linear constant coefficient is not sampled.

The final theorem transports the previously proved ideal rejection-output law to the joint
six-role coin space. It does not prove Rust execution agrees with this allocation, identify OS
outputs with ideal coins, model salt/tapes, or establish quantum security or production authority.
-/

namespace HegemonCrypto.SmallWood.V8Smz9RuntimeFieldLayout

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open scoped ENNReal

/-- Split a flat vector without discarding or duplicating any position. -/
def splitEquiv (left right : Nat) (F : Type*) :
    (Fin (left + right) → F) ≃ ((Fin left → F) × (Fin right → F)) :=
  (Fin.appendEquiv left right).symm

/-- Row-major indexing: column + columns * row. -/
def matrixEquiv (rows columns : Nat) (F : Type*) :
    (Fin (rows * columns) → F) ≃ (Fin rows → Fin columns → F) :=
  (Equiv.arrowCongr finProdFinEquiv.symm (Equiv.refl F)).trans
    (Equiv.curry (Fin rows) (Fin columns) F)

@[simp] theorem matrix_equiv_apply
    (rows columns : Nat) (F : Type*) (values : Fin (rows * columns) → F)
    (row : Fin rows) (column : Fin columns) :
    matrixEquiv rows columns F values row column =
      values (finProdFinEquiv (row, column)) := rfl

@[simp] theorem matrix_equiv_symm_apply
    (rows columns : Nat) (F : Type*) (values : Fin rows → Fin columns → F)
    (row : Fin rows) (column : Fin columns) :
    (matrixEquiv rows columns F).symm values (finProdFinEquiv (row, column)) =
      values row column := by
  exact congrFun (congrFun ((matrixEquiv rows columns F).apply_symm_apply values) row) column

/-- Split each sampled coefficient row at the same low/high boundary as the ZK model. -/
def coefficientRowsEquiv (rows low high : Nat) (F : Type*) :
    (Fin (rows * (low + high)) → F) ≃
      EvaluationHighCoordinates F rows low high :=
  (matrixEquiv rows (low + high) F).trans
    (Equiv.piCongrRight fun _ => splitEquiv low high F)

/-- Five draws of 489 coefficients followed by 132 nonconstant coefficients. -/
def alternatingMasksEquiv (F : Type*) :
    (Fin 3105 → F) ≃ (NonlinearPiopMaskCoins F × LinearPiopMaskCoins F) :=
  (matrixEquiv 5 (489 + 132) F).trans
    ((Equiv.piCongrRight fun _ : Fin 5 => splitEquiv 489 132 F).trans
      ((Equiv.arrowProdEquivProdArrow (Fin 5)
        (fun _ => Fin 489 → F) (fun _ => Fin 132 → F)).trans
        (Equiv.prodCongr
          (Equiv.piCongrRight fun _ : Fin 5 => splitEquiv 6 483 F)
          (Equiv.piCongrRight fun _ : Fin 5 => splitEquiv 6 126 F))))

/-- Transpose one PCS family from polynomial/opening/local-column to opening/column. -/
def pcsFamilyEquiv (width : Nat) (F : Type*) :
    (Fin (5 * (6 * width)) → F) ≃ (Fin 6 → Fin (5 * width) → F) :=
  (matrixEquiv 5 (6 * width) F).trans
    ((Equiv.piCongrRight fun _ : Fin 5 => matrixEquiv 6 width F).trans
      ((Equiv.piComm fun (_ : Fin 5) (_ : Fin 6) => Fin width → F).trans
        (Equiv.piCongrRight fun _ : Fin 6 => (matrixEquiv 5 width F).symm)))

theorem pcs_family_transpose_apply
    (width : Nat) (F : Type*) (values : Fin (5 * (6 * width)) → F)
    (polynomial : Fin 5) (opening : Fin 6) (column : Fin width) :
    pcsFamilyEquiv width F values opening (finProdFinEquiv (polynomial, column)) =
      values (finProdFinEquiv (polynomial, finProdFinEquiv (opening, column))) := by
  simp only [pcsFamilyEquiv, Equiv.trans_apply, Equiv.piCongrRight_apply, Pi.map,
    Equiv.piComm_apply, Function.swap, matrix_equiv_symm_apply, matrix_equiv_apply]

/-- Join the 35 nonlinear columns and the five linear columns at every opening. -/
def pcsColumnsEquiv (F : Type*) :
    ((Fin 6 → Fin 35 → F) × (Fin 6 → Fin 5 → F)) ≃ PcsUnstackCoins F :=
  (Equiv.arrowProdEquivProdArrow (Fin 6)
    (fun _ => Fin 35 → F) (fun _ => Fin 5 → F)).symm.trans
      (Equiv.piCongrRight fun _ : Fin 6 => (splitEquiv 35 5 F).symm)

def pcsFieldLayoutEquiv (F : Type*) : (Fin 240 → F) ≃ PcsUnstackCoins F :=
  (splitEquiv 210 30 F).trans
    ((Equiv.prodCongr (pcsFamilyEquiv 7 F) (pcsFamilyEquiv 1 F)).trans
      (pcsColumnsEquiv F))

theorem pcs_nonlinear_column_apply
    (F : Type*) (values : Fin 240 → F)
    (polynomial : Fin 5) (opening : Fin 6) (column : Fin 7) :
    pcsFieldLayoutEquiv F values opening
        (Fin.castAdd 5 (finProdFinEquiv (polynomial, column))) =
      values (Fin.castAdd 30
        (finProdFinEquiv (polynomial, finProdFinEquiv (opening, column)))) := by
  change Fin.append _ _ (Fin.castAdd 5 (finProdFinEquiv (polynomial, column))) = _
  rw [Fin.append_left]
  change pcsFamilyEquiv 7 F ((splitEquiv 210 30 F values).1) opening
    (finProdFinEquiv (polynomial, column)) = _
  rw [pcs_family_transpose_apply]
  rfl

theorem pcs_linear_column_apply
    (F : Type*) (values : Fin 240 → F)
    (polynomial : Fin 5) (opening : Fin 6) :
    pcsFieldLayoutEquiv F values opening (Fin.natAdd 35 polynomial) =
      values (Fin.natAdd 210 (finProdFinEquiv (polynomial, opening))) := by
  change Fin.append _ _ (Fin.natAdd 35 polynomial) = _
  rw [Fin.append_right]
  change pcsFamilyEquiv 1 F ((splitEquiv 210 30 F values).2) opening polynomial = _
  have columnIdentity : (finProdFinEquiv (polynomial, (0 : Fin 1)) : Fin 5) =
      polynomial := by
    apply Fin.ext
    simp [finProdFinEquiv]
  conv_lhs => rw [← columnIdentity]
  rw [pcs_family_transpose_apply]
  change values (Fin.natAdd 210
    (finProdFinEquiv (polynomial, finProdFinEquiv (opening, (0 : Fin 1))))) = _
  congr 1
  apply Fin.ext
  simp [finProdFinEquiv]

/-- The intermediate nesting follows the runtime's five contiguous allocation groups. -/
abbrev RuntimeRoleGroups (F : Type*) :=
  WitnessInterpolationCoins F ×
    ((NonlinearPiopMaskCoins F × LinearPiopMaskCoins F) ×
      (PcsUnstackCoins F × (LvcsRandomTailCoins F × DecsPolynomialCoins F)))

def runtimeRoleGroupsEquiv (F : Type*) : (Fin 12201 → F) ≃ RuntimeRoleGroups F :=
  (splitEquiv 4116 8085 F).trans
    (Equiv.prodCongr (matrixEquiv 686 6 F)
      ((splitEquiv 3105 4980 F).trans
        (Equiv.prodCongr (alternatingMasksEquiv F)
          ((splitEquiv 240 4740 F).trans
            (Equiv.prodCongr (pcsFieldLayoutEquiv F)
              ((splitEquiv 2800 1940 F).trans
                (Equiv.prodCongr (matrixEquiv 140 20 F)
                  (coefficientRowsEquiv 5 20 368 F))))))))

/-- Reorder role products to the existing honest algebraic coin type. -/
def roleProductOrderEquiv (F : Type*) :
    RuntimeRoleGroups F ≃ Smz9HonestAlgebraicCoins F where
  toFun groups :=
    (groups.1, groups.2.2.1, groups.2.1.1, groups.2.1.2,
      groups.2.2.2.1, groups.2.2.2.2)
  invFun coins :=
    (coins.1, ((coins.2.2.1, coins.2.2.2.1),
      (coins.2.1, (coins.2.2.2.2.1, coins.2.2.2.2.2))))
  left_inv _ := rfl
  right_inv _ := rfl

def rawFieldLayoutEquiv (F : Type*) :
    (Fin 12201 → F) ≃ Smz9HonestAlgebraicCoins F :=
  (runtimeRoleGroupsEquiv F).trans (roleProductOrderEquiv F)

/-- Every raw position is recovered, for arbitrary contents of every field. -/
theorem flatten_after_field_layout
    (F : Type*) (values : Fin 12201 → F) :
    (rawFieldLayoutEquiv F).symm (rawFieldLayoutEquiv F values) = values :=
  (rawFieldLayoutEquiv F).symm_apply_apply values

/-- Every typed coordinate is recovered, with no consistency premise on the supplied coins. -/
theorem field_layout_after_flatten
    (F : Type*) (coins : Smz9HonestAlgebraicCoins F) :
    rawFieldLayoutEquiv F ((rawFieldLayoutEquiv F).symm coins) = coins :=
  (rawFieldLayoutEquiv F).apply_symm_apply coins

/-- Half-open group boundaries in the accepted-word vector. -/
theorem exact_runtime_group_offsets :
    686 * 6 = 4116 ∧
      4116 + 5 * (489 + 132) = 7221 ∧
      7221 + (5 * (6 * 7) + 5 * (6 * 1)) = 7461 ∧
      7461 + 140 * 20 = 10261 ∧
      10261 + 5 * 388 = 12201 := by decide

def witnessRawIndex (row : Fin 686) (coefficient : Fin 6) : Fin 12201 :=
  Fin.castAdd 8085 (finProdFinEquiv (row, coefficient))

def maskRawIndex (polynomial : Fin 5) (coefficient : Fin 621) : Fin 12201 :=
  Fin.natAdd 4116 (Fin.castAdd 4980 (finProdFinEquiv (polynomial, coefficient)))

def pcsRawIndex (index : Fin 240) : Fin 12201 :=
  Fin.natAdd 4116 (Fin.natAdd 3105 (Fin.castAdd 4740 index))

def lvcsRawIndex (row : Fin 140) (tail : Fin 20) : Fin 12201 :=
  Fin.natAdd 4116 (Fin.natAdd 3105
    (Fin.natAdd 240 (Fin.castAdd 1940 (finProdFinEquiv (row, tail)))))

def decsRawIndex (polynomial : Fin 5) (coefficient : Fin 388) : Fin 12201 :=
  Fin.natAdd 4116 (Fin.natAdd 3105
    (Fin.natAdd 240 (Fin.natAdd 2800 (finProdFinEquiv (polynomial, coefficient)))))

/-- Numeric offsets of the actual allocation indices, usable as Rust conformance targets. -/
theorem raw_allocation_index_values
    (witnessRow : Fin 686) (witnessCoefficient : Fin 6)
    (maskPolynomial : Fin 5) (maskCoefficient : Fin 621) (pcsIndex : Fin 240)
    (lvcsRow : Fin 140) (lvcsTail : Fin 20)
    (decsPolynomial : Fin 5) (decsCoefficient : Fin 388) :
    (witnessRawIndex witnessRow witnessCoefficient).val =
        6 * witnessRow.val + witnessCoefficient.val ∧
      (maskRawIndex maskPolynomial maskCoefficient).val =
        4116 + 621 * maskPolynomial.val + maskCoefficient.val ∧
      (pcsRawIndex pcsIndex).val = 7221 + pcsIndex.val ∧
      (lvcsRawIndex lvcsRow lvcsTail).val = 7461 + 20 * lvcsRow.val + lvcsTail.val ∧
      (decsRawIndex decsPolynomial decsCoefficient).val =
        10261 + 388 * decsPolynomial.val + decsCoefficient.val := by
  simp [witnessRawIndex, maskRawIndex, pcsRawIndex, lvcsRawIndex, decsRawIndex,
    finProdFinEquiv]
  omega

theorem witness_word_allocation
    (F : Type*) (values : Fin 12201 → F) (row : Fin 686) (coefficient : Fin 6) :
    (rawFieldLayoutEquiv F values).1 row coefficient =
      values (witnessRawIndex row coefficient) := rfl

theorem nonlinear_low_word_allocation
    (F : Type*) (values : Fin 12201 → F) (polynomial : Fin 5) (coefficient : Fin 6) :
    ((rawFieldLayoutEquiv F values).2.2.1 polynomial).1 coefficient =
      values (maskRawIndex polynomial (Fin.castAdd 132 (Fin.castAdd 483 coefficient))) := rfl

theorem nonlinear_high_word_allocation
    (F : Type*) (values : Fin 12201 → F) (polynomial : Fin 5) (coefficient : Fin 483) :
    ((rawFieldLayoutEquiv F values).2.2.1 polynomial).2 coefficient =
      values (maskRawIndex polynomial (Fin.castAdd 132 (Fin.natAdd 6 coefficient))) := rfl

theorem linear_low_word_allocation
    (F : Type*) (values : Fin 12201 → F) (polynomial : Fin 5) (coefficient : Fin 6) :
    ((rawFieldLayoutEquiv F values).2.2.2.1 polynomial).1 coefficient =
      values (maskRawIndex polynomial (Fin.natAdd 489 (Fin.castAdd 126 coefficient))) := rfl

theorem linear_high_word_allocation
    (F : Type*) (values : Fin 12201 → F) (polynomial : Fin 5) (coefficient : Fin 126) :
    ((rawFieldLayoutEquiv F values).2.2.2.1 polynomial).2 coefficient =
      values (maskRawIndex polynomial (Fin.natAdd 489 (Fin.natAdd 6 coefficient))) := rfl

theorem pcs_word_allocation
    (F : Type*) (values : Fin 12201 → F) :
    (rawFieldLayoutEquiv F values).2.1 =
      pcsFieldLayoutEquiv F (fun index => values (pcsRawIndex index)) := rfl

theorem lvcs_word_allocation
    (F : Type*) (values : Fin 12201 → F) (row : Fin 140) (tail : Fin 20) :
    (rawFieldLayoutEquiv F values).2.2.2.2.1 row tail =
      values (lvcsRawIndex row tail) := rfl

theorem decs_low_word_allocation
    (F : Type*) (values : Fin 12201 → F) (polynomial : Fin 5) (coefficient : Fin 20) :
    ((rawFieldLayoutEquiv F values).2.2.2.2.2 polynomial).1 coefficient =
      values (decsRawIndex polynomial (Fin.castAdd 368 coefficient)) := rfl

theorem decs_high_word_allocation
    (F : Type*) (values : Fin 12201 → F) (polynomial : Fin 5) (coefficient : Fin 368) :
    ((rawFieldLayoutEquiv F values).2.2.2.2.2 polynomial).2 coefficient =
      values (decsRawIndex polynomial (Fin.natAdd 20 coefficient)) := rfl

/-- Witness draws occupy polynomial degrees 64 through 69. -/
def witnessCoefficientDegree (coefficient : Fin 6) : Fin 70 := Fin.natAdd 64 coefficient

/-- The six low linear draws occupy degrees 1 through 6; degree zero is derived. -/
def linearLowCoefficientDegree (coefficient : Fin 6) : Fin 133 :=
  Fin.natAdd 1 (Fin.castAdd 126 coefficient)

/-- The remaining 126 linear draws occupy degrees 7 through 132. -/
def linearHighCoefficientDegree (coefficient : Fin 126) : Fin 133 :=
  Fin.natAdd 1 (Fin.natAdd 6 coefficient)

theorem exact_sampled_coefficient_degrees
    (witness : Fin 6) (linearLow : Fin 6) (linearHigh : Fin 126) :
    (witnessCoefficientDegree witness).val = 64 + witness.val ∧
      (linearLowCoefficientDegree linearLow).val = 1 + linearLow.val ∧
      (linearHighCoefficientDegree linearHigh).val = 1 + (6 + linearHigh.val) := by
  exact ⟨rfl, rfl, rfl⟩

/-- Canonical accepted representatives become the existing Goldilocks coin type, coordinatewise. -/
noncomputable def runtimeFieldLayoutEquiv :
    RuntimeFieldCoins honestAlgebraicFieldCoinCount ≃ Smz9HonestAlgebraicCoins Goldilocks :=
  (Equiv.piCongrRight fun _ : Fin 12201 => idealFieldCoinEquivGoldilocks).trans
    (rawFieldLayoutEquiv Goldilocks)

theorem runtime_field_layout_inverse
    (values : RuntimeFieldCoins honestAlgebraicFieldCoinCount)
    (coins : Smz9HonestAlgebraicCoins Goldilocks) :
    runtimeFieldLayoutEquiv.symm (runtimeFieldLayoutEquiv values) = values ∧
      runtimeFieldLayoutEquiv (runtimeFieldLayoutEquiv.symm coins) = coins :=
  ⟨runtimeFieldLayoutEquiv.symm_apply_apply values,
    runtimeFieldLayoutEquiv.apply_symm_apply coins⟩

noncomputable local instance : Fintype (Smz9HonestAlgebraicCoins Goldilocks) :=
  Fintype.ofEquiv (RuntimeFieldCoins honestAlgebraicFieldCoinCount) runtimeFieldLayoutEquiv

/-- A bijective allocation transports joint uniformity, not just uniform individual marginals. -/
theorem uniform_pmf_map_equiv
    {alpha beta : Type*} [Fintype alpha] [Nonempty alpha]
    [Fintype beta] [Nonempty beta] (allocation : alpha ≃ beta) :
    pmfMap (uniformFintypePMF alpha) allocation = uniformFintypePMF beta := by
  classical
  apply PMF.ext
  intro output
  rw [pmfMap_apply]
  simp only [uniformFintypePMF_apply, tsum_fintype]
  rw [Finset.sum_eq_single (allocation.symm output)]
  · rw [if_pos (allocation.apply_symm_apply output).symm,
      Fintype.card_congr allocation]
  · intro candidate _ candidate_ne
    rw [if_neg]
    intro equality
    apply candidate_ne
    exact allocation.injective (equality.symm.trans (allocation.apply_symm_apply output).symm)
  · intro not_mem
    exact (not_mem (Finset.mem_univ _)).elim

/-- The proved rejection law reaches the existing complete six-role algebraic input space. -/
theorem exact_smz9_honest_algebraic_coin_law :
    pmfMap (iidUniformRejectionSamplerOutputPMF honestAlgebraicFieldCoinCount)
        runtimeFieldLayoutEquiv =
      uniformFintypePMF (Smz9HonestAlgebraicCoins Goldilocks) := by
  rw [exact_smz9_iid_uniform_rejection_output_law]
  exact uniform_pmf_map_equiv runtimeFieldLayoutEquiv

end HegemonCrypto.SmallWood.V8Smz9RuntimeFieldLayout
