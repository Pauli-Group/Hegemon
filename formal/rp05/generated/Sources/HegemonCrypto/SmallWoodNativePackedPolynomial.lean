import HegemonCrypto.SmallWoodOracleExtraction

set_option maxHeartbeats 500000
set_option maxRecDepth 100000

/-!
# Verifier-exact packed PCS polynomials

The verifier evaluates groups of unstacked PCS columns at one opening point.  This module defines
the resulting polynomial directly from every committed cell.  It does not assume that a malicious
commitment preserved the zero padding or masking cancellations used by the honest authoring path.
-/

namespace HegemonCrypto.SmallWood.NativePackedPolynomial

open Polynomial
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.RoundByRound
open scoped BigOperators

noncomputable section

/-- Read one unstacked PCS cell by natural indexes, failing closed outside the active geometry. -/
def unstackedCellAt
    (oracle : CommittedOracle)
    (row column : Nat) : Goldilocks :=
  if rowBound : row < unstackedRowCount then
    if columnBound : column < unstackedColumnCount then
      unstackedCell oracle ⟨row, rowBound⟩ ⟨column, columnBound⟩
    else
      0
  else
    0

/-- Polynomial carried by one of the 69-row unstacked PCS columns. -/
def unstackedColumnPolynomial
    (oracle : CommittedOracle)
    (column : Nat) : Goldilocks[X] :=
  ∑ row : Fin unstackedRowCount,
    C (unstackedCellAt oracle row.val column) * X ^ row.val

theorem unstacked_column_polynomial_eval
    (oracle : CommittedOracle)
    (column : Nat)
    (point : Goldilocks) :
    (unstackedColumnPolynomial oracle column).eval point =
      ∑ row : Fin unstackedRowCount,
        unstackedCellAt oracle row.val column * point ^ row.val := by
  unfold unstackedColumnPolynomial
  rw [eval_finsetSum]
  apply Finset.sum_congr rfl
  intro row _
  simp

theorem unstacked_column_polynomial_degree_le
    (oracle : CommittedOracle)
    (column : Nat) :
    (unstackedColumnPolynomial oracle column).natDegree ≤
      unstackedRowCount - 1 := by
  unfold unstackedColumnPolynomial
  apply natDegree_sum_le_of_forall_le
  intro row _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  have rowBound := row.isLt
  omega

/--
Power assigned to one packed column. Non-final columns advance by the 64-lane packing factor; the
final column starts `delta` coefficients later.
-/
def packedColumnShift
    (width delta : Nat)
    (column : Fin width) : Nat :=
  if column.val + 1 < width then
    packingFactor * column.val
  else
    packingFactor * (width - 1) - delta

/--
Exact polynomial evaluated by `pcs_build_opened_evaluations` and
`pcs_reconstruct_combi_heads`.
-/
def packedPolynomial
    (oracle : CommittedOracle)
    (offset width delta : Nat) : Goldilocks[X] :=
  ∑ column : Fin width,
    unstackedColumnPolynomial oracle (offset + column.val) *
      X ^ packedColumnShift width delta column

theorem packed_polynomial_eval
    (oracle : CommittedOracle)
    (offset width delta : Nat)
    (point : Goldilocks) :
    (packedPolynomial oracle offset width delta).eval point =
      ∑ column : Fin width,
        (∑ row : Fin unstackedRowCount,
          unstackedCellAt oracle row.val (offset + column.val) *
            point ^ row.val) *
          point ^ packedColumnShift width delta column := by
  unfold packedPolynomial
  rw [eval_finsetSum]
  apply Finset.sum_congr rfl
  intro column _
  rw [eval_mul, eval_X_pow, unstacked_column_polynomial_eval]

def nonlinearMaskOffset (repetition : Fin rho) : Nat :=
  rowCount + 8 * repetition.val

def linearMaskOffset (repetition : Fin rho) : Nat :=
  rowCount + 8 * rho + 2 * repetition.val

def nonlinearMaskPolynomial
    (oracle : CommittedOracle)
    (repetition : Fin rho) : Goldilocks[X] :=
  packedPolynomial oracle (nonlinearMaskOffset repetition) 8 36

def linearMaskPolynomial
    (oracle : CommittedOracle)
    (repetition : Fin rho) : Goldilocks[X] :=
  packedPolynomial oracle (linearMaskOffset repetition) 2 1

theorem nonlinear_mask_polynomial_degree_le
    (oracle : CommittedOracle)
    (repetition : Fin rho) :
    (nonlinearMaskPolynomial oracle repetition).natDegree ≤
      nonlinearMaskPolynomialDegree := by
  unfold nonlinearMaskPolynomial packedPolynomial
  apply natDegree_sum_le_of_forall_le
  intro column _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_X_pow]
  have columnDegree :=
    unstacked_column_polynomial_degree_le oracle
      (nonlinearMaskOffset repetition + column.val)
  have columnDegreeNumeric :
      (unstackedColumnPolynomial oracle
        (nonlinearMaskOffset repetition + column.val)).natDegree ≤ 68 := by
    have rowDegree : unstackedRowCount - 1 = 68 := by decide
    simpa only [rowDegree] using columnDegree
  have columnBound := column.isLt
  change column.val < 8 at columnBound
  unfold packedColumnShift
  split_ifs
  · change
      (unstackedColumnPolynomial oracle
        (nonlinearMaskOffset repetition + column.val)).natDegree +
          64 * column.val ≤ 480
    omega
  · change
      (unstackedColumnPolynomial oracle
        (nonlinearMaskOffset repetition + column.val)).natDegree +
          (64 * (8 - 1) - 36) ≤ 480
    omega

theorem linear_mask_polynomial_degree_le
    (oracle : CommittedOracle)
    (repetition : Fin rho) :
    (linearMaskPolynomial oracle repetition).natDegree ≤
      linearMaskPolynomialDegree := by
  unfold linearMaskPolynomial packedPolynomial
  apply natDegree_sum_le_of_forall_le
  intro column _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_X_pow]
  have columnDegree :=
    unstacked_column_polynomial_degree_le oracle
      (linearMaskOffset repetition + column.val)
  have columnDegreeNumeric :
      (unstackedColumnPolynomial oracle
        (linearMaskOffset repetition + column.val)).natDegree ≤ 68 := by
    have rowDegree : unstackedRowCount - 1 = 68 := by decide
    simpa only [rowDegree] using columnDegree
  have columnBound := column.isLt
  change column.val < 2 at columnBound
  unfold packedColumnShift
  split_ifs
  · change
      (unstackedColumnPolynomial oracle
        (linearMaskOffset repetition + column.val)).natDegree +
          64 * column.val ≤ 131
    omega
  · change
      (unstackedColumnPolynomial oracle
        (linearMaskOffset repetition + column.val)).natDegree +
          (64 * (2 - 1) - 1) ≤ 131
    omega

end

end HegemonCrypto.SmallWood.NativePackedPolynomial
