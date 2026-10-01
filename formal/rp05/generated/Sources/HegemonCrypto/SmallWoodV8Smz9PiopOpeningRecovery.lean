import HegemonCrypto.SmallWoodProductionPolynomials
import HegemonCrypto.SmallWoodLinearPiopExact
import Mathlib.Algebra.Polynomial.RingDivision

/-!
# Source-shaped SMZ9 PIOP mask-opening recovery

The nonlinear source constructs a batched constraint polynomial, divides by the
64 packing factors, and adds a degree-488 mask. The linear source adds a
zero-packing-sum mask and publishes only the 132 nonconstant coefficients.
This module derives both mask evaluations from the resulting transcript and
opened witness rows. Validity, polynomial degree, and nonzero denominators are
explicit hypotheses; an honest/simulator output-law equality is not a premise.

The generated arithmetic-program evaluation lemma is reused without using
the older PCS geometry. Exact HGV8RP03 program specialization and Rust execution
remain separate from these polynomial identities. No production authority or
quantum-security conclusion is constructed here.
-/

namespace HegemonCrypto.SmallWood.V8Smz9PiopOpeningRecovery

open Polynomial
open scoped BigOperators Classical

noncomputable section

set_option maxHeartbeats 2000000
set_option maxRecDepth 5000

variable {F : Type*} [Field F]

def packingVanishing (packing : Fin 64 → F) : F[X] :=
  ∏ lane : Fin 64, (X - C (packing lane))

theorem packing_vanishing_monic (packing : Fin 64 → F) :
    (packingVanishing packing).Monic :=
  monic_prod_X_sub_C packing Finset.univ

theorem packing_vanishing_degree (packing : Fin 64 → F) :
    (packingVanishing packing).natDegree = 64 := by
  simp [packingVanishing]

theorem packing_vanishing_evaluation (packing : Fin 64 → F) (point : F) :
    (packingVanishing packing).eval point =
      ∏ lane : Fin 64, (point - packing lane) := by
  simp [packingVanishing, eval_prod]

theorem packing_vanishing_eval_nonzero
    (packing : Fin 64 → F) (point : F)
    (outside : ∀ lane, point ≠ packing lane) :
    (packingVanishing packing).eval point ≠ 0 := by
  rw [packing_vanishing_evaluation]
  exact Finset.prod_ne_zero_iff.mpr (fun lane _ => sub_ne_zero.mpr (outside lane))

/-- Validity at all distinct packing points supplies divisibility, rather than assuming it. -/
theorem packing_vanishing_dvd_of_valid
    (packing : Fin 64 → F) (injective : Function.Injective packing)
    (polynomial : F[X]) (valid : ∀ lane, polynomial.eval (packing lane) = 0) :
    packingVanishing packing ∣ polynomial := by
  apply Fintype.prod_dvd_of_coprime (pairwise_coprime_X_sub_C injective)
  intro lane
  exact dvd_iff_isRoot.mpr (valid lane)

def nonlinearBatch {Checks : Type*} [Fintype Checks]
    (gamma : Checks → F) (constraints : Checks → F[X]) : F[X] :=
  ∑ check, C (gamma check) * constraints check

theorem nonlinear_batch_eval {Checks : Type*} [Fintype Checks]
    (gamma : Checks → F) (constraints : Checks → F[X]) (point : F) :
    (nonlinearBatch gamma constraints).eval point =
      ∑ check, gamma check * (constraints check).eval point := by
  simp [nonlinearBatch, eval_finsetSum]

theorem nonlinear_batch_valid {Checks : Type*} [Fintype Checks]
    (packing : Fin 64 → F) (gamma : Checks → F) (constraints : Checks → F[X])
    (valid : ∀ check lane, (constraints check).eval (packing lane) = 0) :
    ∀ lane, (nonlinearBatch gamma constraints).eval (packing lane) = 0 := by
  intro lane
  simp [nonlinear_batch_eval, valid]

theorem nonlinear_batch_degree {Checks : Type*} [Fintype Checks]
    (gamma : Checks → F) (constraints : Checks → F[X])
    (degreeBound : ∀ check, (constraints check).natDegree ≤ 552) :
    (nonlinearBatch gamma constraints).natDegree ≤ 552 := by
  unfold nonlinearBatch
  apply natDegree_sum_le_of_forall_le
  intro check _
  refine natDegree_mul_le.trans ?_
  simpa using degreeBound check

def sourceNonlinearQuotient (packing : Fin 64 → F) (batch : F[X]) : F[X] :=
  batch /ₘ packingVanishing packing

theorem nonlinear_quotient_reassembles
    (packing : Fin 64 → F) (injective : Function.Injective packing)
    (batch : F[X]) (valid : ∀ lane, batch.eval (packing lane) = 0) :
    packingVanishing packing * sourceNonlinearQuotient packing batch = batch := by
  obtain ⟨quotient, exact⟩ := packing_vanishing_dvd_of_valid packing injective batch valid
  rw [exact, sourceNonlinearQuotient,
    mul_divByMonic_cancel_left quotient (packing_vanishing_monic packing)]

def removePackingFactors (roots : List F) (polynomial : F[X]) : F[X] :=
  roots.foldl (fun current root => current /ₘ (X - C root)) polynomial

theorem remove_packing_factors_product (roots : List F) (quotient : F[X]) :
    removePackingFactors roots ((roots.map (fun root => X - C root)).prod * quotient) =
      quotient := by
  induction roots with
  | nil => simp [removePackingFactors]
  | cons root remaining induction =>
      simp only [removePackingFactors, List.map_cons, List.prod_cons, List.foldl_cons]
      rw [mul_assoc, mul_divByMonic_cancel_left _ (monic_X_sub_C root)]
      exact induction

/-- The source's repeated root-removal loop agrees with division by the packing product. -/
theorem sequential_packing_removal_matches_quotient
    (packing : Fin 64 → F) (injective : Function.Injective packing)
    (batch : F[X]) (valid : ∀ lane, batch.eval (packing lane) = 0) :
    removePackingFactors (List.ofFn packing) batch = sourceNonlinearQuotient packing batch := by
  have productExact : ((List.ofFn packing).map (fun root => X - C root)).prod =
      packingVanishing packing := by
    rw [List.map_ofFn, Fin.prod_ofFn]
    rfl
  calc
    removePackingFactors (List.ofFn packing) batch =
      removePackingFactors (List.ofFn packing)
        (packingVanishing packing * sourceNonlinearQuotient packing batch) :=
      congrArg (removePackingFactors (List.ofFn packing))
        (nonlinear_quotient_reassembles packing injective batch valid).symm
    _ = _ := by
      rw [← productExact]
      exact remove_packing_factors_product _ _

theorem nonlinear_quotient_degree
    (packing : Fin 64 → F) (batch : F[X]) (degreeBound : batch.natDegree ≤ 552) :
    (sourceNonlinearQuotient packing batch).natDegree ≤ 488 := by
  rw [sourceNonlinearQuotient, natDegree_divByMonic batch (packing_vanishing_monic packing),
    packing_vanishing_degree]
  omega

theorem nonlinear_quotient_evaluation
    (packing : Fin 64 → F) (injective : Function.Injective packing)
    (batch : F[X]) (valid : ∀ lane, batch.eval (packing lane) = 0)
    (point : F) (outside : ∀ lane, point ≠ packing lane) :
    (sourceNonlinearQuotient packing batch).eval point =
      batch.eval point / (packingVanishing packing).eval point := by
  have equation := congrArg (fun polynomial : F[X] => polynomial.eval point)
    (nonlinear_quotient_reassembles packing injective batch valid)
  rw [eval_mul] at equation
  apply (eq_div_iff (packing_vanishing_eval_nonzero packing point outside)).mpr
  simpa [mul_comm] using equation

def sourceNonlinearTranscript (packing : Fin 64 → F) (batch mask : F[X]) : F[X] :=
  sourceNonlinearQuotient packing batch + mask

def recoverNonlinearMaskOpening
    (packing : Fin 64 → F) (transcript : F[X]) (batchOpening point : F) : F :=
  transcript.eval point - batchOpening / (packingVanishing packing).eval point

/-- Actual mask opening, with polynomial divisibility derived from valid packing constraints. -/
theorem recover_nonlinear_mask_opening
    (packing : Fin 64 → F) (injective : Function.Injective packing)
    (batch mask : F[X]) (valid : ∀ lane, batch.eval (packing lane) = 0)
    (point : F) (outside : ∀ lane, point ≠ packing lane) :
    recoverNonlinearMaskOpening packing (sourceNonlinearTranscript packing batch mask)
        (batch.eval point) point = mask.eval point := by
  simp only [recoverNonlinearMaskOpening, sourceNonlinearTranscript, eval_add]
  rw [nonlinear_quotient_evaluation packing injective batch valid point outside]
  ring

/-- Reuse the generated instruction-by-instruction polynomial/evaluation invariant. -/
theorem generated_program_root_evaluation
    (publicValues : List Nat)
    (witnessPolynomials : Nat → Goldilocks[X])
    (expressions : List Hegemon.Transaction.SmallWoodProductionConstraintRefinement.ProductionConstraintExpression)
    (root : Nat) (point : Goldilocks) :
    ((ProductionPolynomials.polynomialProgram publicValues witnessPolynomials expressions).getD
      root 0).eval point =
    (ProductionPolynomials.goldilocksProgram publicValues
      (fun row => (witnessPolynomials row).eval point) expressions).getD root 0 :=
  (ProductionPolynomials.program_evaluation_invariant publicValues witnessPolynomials expressions
    point).2 root

/-- The source samples 553 points before interpolating degree-at-most-552 constraints. -/
theorem source_constraint_sampling_interpolation_exact
    (samples : Fin 553 → F) (injective : Function.Injective samples)
    (polynomial : F[X]) (degreeBound : polynomial.natDegree ≤ 552) :
    Lagrange.interpolate Finset.univ samples (fun index => polynomial.eval (samples index)) =
      polynomial := by
  apply (Lagrange.eq_interpolate injective.injOn _).symm
  have strict : polynomial.natDegree < 553 := by omega
  change polynomial.degree < (553 : WithBot Nat)
  exact degree_le_natDegree.trans_lt (WithBot.coe_lt_coe.mpr strict)

def generatedConstraintPolynomials
    (publicValues : List Nat) (witnessPolynomials : Nat → Goldilocks[X])
    (expressions : List Hegemon.Transaction.SmallWoodProductionConstraintRefinement.ProductionConstraintExpression)
    (roots : Fin 830 → Nat) : Fin 830 → Goldilocks[X] :=
  fun check => (ProductionPolynomials.polynomialProgram publicValues witnessPolynomials
    expressions).getD (roots check) 0

def generatedConstraintOpenings
    (publicValues : List Nat) (openedRows : Nat → Goldilocks)
    (expressions : List Hegemon.Transaction.SmallWoodProductionConstraintRefinement.ProductionConstraintExpression)
    (roots : Fin 830 → Nat) : Fin 830 → Goldilocks :=
  fun check => (ProductionPolynomials.goldilocksProgram publicValues openedRows expressions).getD
    (roots check) 0

/-- The public nonlinear numerator uses only these same opened witness rows. -/
theorem generated_nonlinear_batch_evaluation
    (publicValues : List Nat) (witnessPolynomials : Nat → Goldilocks[X])
    (expressions : List Hegemon.Transaction.SmallWoodProductionConstraintRefinement.ProductionConstraintExpression)
    (roots : Fin 830 → Nat) (gamma : Fin 830 → Goldilocks) (point : Goldilocks) :
    (nonlinearBatch gamma
      (generatedConstraintPolynomials publicValues witnessPolynomials expressions roots)).eval point =
    ∑ check, gamma check * generatedConstraintOpenings publicValues
      (fun row => (witnessPolynomials row).eval point) expressions roots check := by
  rw [nonlinear_batch_eval]
  apply Finset.sum_congr rfl
  intro check _
  rw [generatedConstraintPolynomials, generated_program_root_evaluation]
  rfl

theorem generated_nonlinear_mask_recovered_from_opened_rows
    (packing : Fin 64 → Goldilocks) (injective : Function.Injective packing)
    (publicValues : List Nat) (witnessPolynomials : Nat → Goldilocks[X])
    (expressions : List Hegemon.Transaction.SmallWoodProductionConstraintRefinement.ProductionConstraintExpression)
    (roots : Fin 830 → Nat) (gamma : Fin 830 → Goldilocks) (mask : Goldilocks[X])
    (valid : ∀ check lane,
      (generatedConstraintPolynomials publicValues witnessPolynomials expressions roots check).eval
        (packing lane) = 0)
    (point : Goldilocks) (outside : ∀ lane, point ≠ packing lane) :
    let batch := nonlinearBatch gamma
      (generatedConstraintPolynomials publicValues witnessPolynomials expressions roots)
    recoverNonlinearMaskOpening packing (sourceNonlinearTranscript packing batch mask)
      (∑ check, gamma check * generatedConstraintOpenings publicValues
        (fun row => (witnessPolynomials row).eval point) expressions roots check) point =
      mask.eval point := by
  dsimp only
  rw [← generated_nonlinear_batch_evaluation]
  exact recover_nonlinear_mask_opening packing injective _ mask
    (nonlinear_batch_valid packing gamma _ valid) point outside

def packingSum (packing : Fin 64 → F) (polynomial : F[X]) : F :=
  ∑ lane : Fin 64, polynomial.eval (packing lane)

def sourceLinearMask (packing : Fin 64 → F) (coins : Fin 132 → F) : F[X] :=
  ∑ index : Fin 132, C (coins index) *
    (X ^ (index.val + 1) - C ((∑ lane : Fin 64, packing lane ^ (index.val + 1)) / 64))

theorem source_linear_mask_evaluation (packing : Fin 64 → F)
    (coins : Fin 132 → F) (point : F) :
    (sourceLinearMask packing coins).eval point =
      ∑ index : Fin 132, coins index *
        (point ^ (index.val + 1) - (∑ lane : Fin 64, packing lane ^ (index.val + 1)) / 64) := by
  simp [sourceLinearMask, eval_finsetSum]

/-- The source-derived constant makes the complete 133-coefficient mask zero-sum. -/
theorem source_linear_mask_packing_sum_zero
    (packing : Fin 64 → F) (packingCardNonzero : (64 : F) ≠ 0)
    (coins : Fin 132 → F) : packingSum packing (sourceLinearMask packing coins) = 0 := by
  unfold packingSum
  simp_rw [source_linear_mask_evaluation]
  rw [Finset.sum_comm]
  apply Finset.sum_eq_zero
  intro index _
  rw [← Finset.mul_sum, Finset.sum_sub_distrib]
  have meanExact : (∑ _lane : Fin 64,
      (∑ lane : Fin 64, packing lane ^ (index.val + 1)) / 64) =
      ∑ lane : Fin 64, packing lane ^ (index.val + 1) := by
    simp only [Finset.sum_const, Finset.card_univ, Fintype.card_fin, nsmul_eq_mul]
    field_simp
    ring
  rw [meanExact, sub_self, mul_zero]

theorem source_linear_mask_degree (packing : Fin 64 → F) (coins : Fin 132 → F) :
    (sourceLinearMask packing coins).natDegree ≤ 132 := by
  unfold sourceLinearMask
  apply natDegree_sum_le_of_forall_le
  intro index _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, zero_add]
  refine (natDegree_sub_le _ _).trans ?_
  simp only [natDegree_X_pow, natDegree_C]
  have bound := index.isLt
  omega

def nonconstantPolynomial (high : Fin 132 → F) : F[X] :=
  ∑ index : Fin 132, C (high index) * X ^ (index.val + 1)

theorem polynomial_eq_constant_add_nonconstant
    (polynomial : F[X]) (degreeBound : polynomial.natDegree ≤ 132) :
    polynomial = C (polynomial.coeff 0) +
      nonconstantPolynomial (fun index => polynomial.coeff (index.val + 1)) := by
  have expanded : polynomial =
      ∑ index : Fin 133, C (polynomial.coeff index.val) * X ^ index.val := by
    rw [Fin.sum_univ_eq_sum_range (fun index => C (polynomial.coeff index) * X ^ index)]
    exact polynomial.as_sum_range_C_mul_X_pow' (by omega)
  rw [Fin.sum_univ_succ] at expanded
  simpa [nonconstantPolynomial] using expanded

def omittedLinearConstant (packing : Fin 64 → F) (target : F)
    (high : Fin 132 → F) : F :=
  (target - packingSum packing (nonconstantPolynomial high)) / 64

def restoredLinearTranscript (packing : Fin 64 → F) (target : F)
    (high : Fin 132 → F) : F[X] :=
  C (omittedLinearConstant packing target high) + nonconstantPolynomial high

theorem packing_sum_constant_add (packing : Fin 64 → F) (constant : F)
    (polynomial : F[X]) :
    packingSum packing (C constant + polynomial) =
      64 * constant + packingSum packing polynomial := by
  simp [packingSum, eval_add, Finset.sum_add_distrib]

/-- Recover the omitted source coefficient from the public target sum, not from witness rows. -/
theorem restored_linear_transcript_exact
    (packing : Fin 64 → F) (packingCardNonzero : (64 : F) ≠ 0)
    (constant target : F) (high : Fin 132 → F)
    (targetSum : packingSum packing (C constant + nonconstantPolynomial high) = target) :
    restoredLinearTranscript packing target high = C constant + nonconstantPolynomial high := by
  have constantExact : omittedLinearConstant packing target high = constant := by
    change (target - packingSum packing (nonconstantPolynomial high)) / 64 = constant
    apply (div_eq_iff packingCardNonzero).mpr
    rw [packing_sum_constant_add] at targetSum
    rw [← targetSum]
    ring
  rw [restoredLinearTranscript, constantExact]

def publicLinearOpening {Rows : Type*} [Fintype Rows]
    (weights : Rows → Fin 64 → F) (lagrange : Fin 64 → F[X])
    (openedRows : Rows → F) (point : F) : F :=
  ∑ row, openedRows row * ∑ lane : Fin 64, weights row lane * (lagrange lane).eval point

def sourceLinearUnmasked {Rows : Type*} [Fintype Rows]
    (weights : Rows → Fin 64 → F) (lagrange : Fin 64 → F[X])
    (witnessPolynomials : Rows → F[X]) : F[X] :=
  ∑ row, witnessPolynomials row * ∑ lane : Fin 64, C (weights row lane) * lagrange lane

theorem source_linear_unmasked_evaluation {Rows : Type*} [Fintype Rows]
    (weights : Rows → Fin 64 → F) (lagrange : Fin 64 → F[X])
    (witnessPolynomials : Rows → F[X]) (point : F) :
    (sourceLinearUnmasked weights lagrange witnessPolynomials).eval point =
      publicLinearOpening weights lagrange
        (fun row => (witnessPolynomials row).eval point) point := by
  simp [sourceLinearUnmasked, publicLinearOpening, eval_finsetSum]

def sourcePackingLagrange (packing : Fin 64 → F) (lane : Fin 64) : F[X] :=
  Lagrange.basis Finset.univ packing lane

theorem source_packing_lagrange_evaluation
    (packing : Fin 64 → F) (injective : Function.Injective packing)
    (lane node : Fin 64) :
    (sourcePackingLagrange packing lane).eval (packing node) = if lane = node then 1 else 0 := by
  by_cases equal : lane = node
  · subst node
    simp only [sourcePackingLagrange, if_true]
    exact Lagrange.eval_basis_self injective.injOn (Finset.mem_univ lane)
  · rw [if_neg equal]
    exact Lagrange.eval_basis_of_ne equal (Finset.mem_univ node)

/-- This is the source CSR/identity-witness relation summed over its packing lanes. -/
theorem source_linear_packing_sum {Rows : Type*} [Fintype Rows]
    (packing : Fin 64 → F) (injective : Function.Injective packing)
    (weights : Rows → Fin 64 → F) (witnessPolynomials : Rows → F[X]) :
    packingSum packing
      (sourceLinearUnmasked weights (sourcePackingLagrange packing) witnessPolynomials) =
    ∑ row, ∑ lane : Fin 64, weights row lane * (witnessPolynomials row).eval (packing lane) := by
  unfold packingSum
  simp_rw [source_linear_unmasked_evaluation, publicLinearOpening,
    source_packing_lagrange_evaluation packing injective]
  simp only [mul_ite, mul_one, mul_zero, Finset.sum_ite_eq', Finset.mem_univ, if_true]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro row _
  apply Finset.sum_congr rfl
  intro lane _
  ring

theorem source_linear_unmasked_degree {Rows : Type*} [Fintype Rows]
    (packing : Fin 64 → F) (injective : Function.Injective packing)
    (weights : Rows → Fin 64 → F) (witnessPolynomials : Rows → F[X])
    (witnessDegree : ∀ row, (witnessPolynomials row).natDegree ≤ 69) :
    (sourceLinearUnmasked weights (sourcePackingLagrange packing) witnessPolynomials).natDegree
      ≤ 132 := by
  unfold sourceLinearUnmasked
  apply natDegree_sum_le_of_forall_le
  intro row _
  have comboDegree : (∑ lane : Fin 64,
      C (weights row lane) * sourcePackingLagrange packing lane).natDegree ≤ 63 := by
    apply natDegree_sum_le_of_forall_le
    intro lane _
    refine natDegree_mul_le.trans ?_
    simp only [natDegree_C, zero_add]
    have degree := Lagrange.natDegree_basis injective.injOn (Finset.mem_univ lane)
    simpa [sourcePackingLagrange] using degree.le
  exact natDegree_mul_le.trans (Nat.add_le_add (witnessDegree row) comboDegree)

def batchedLinearWeights {Checks Rows : Type*} [Fintype Checks]
    (gamma : Checks → F) (coefficients : Checks → Rows → Fin 64 → F) : Rows → Fin 64 → F :=
  fun row lane => ∑ check, gamma check * coefficients check row lane

/-- Source public CSR coefficients and valid linear constraints supply the target used above. -/
theorem valid_linear_constraints_supply_batched_target
    {Checks Rows : Type*} [Fintype Checks] [Fintype Rows]
    (gamma : Checks → F) (coefficients : Checks → Rows → Fin 64 → F)
    (witnessValues : Rows → Fin 64 → F) (targets : Checks → F)
    (valid : ∀ check,
      (∑ row, ∑ lane : Fin 64, coefficients check row lane * witnessValues row lane) =
        targets check) :
    (∑ row, ∑ lane : Fin 64,
      batchedLinearWeights gamma coefficients row lane * witnessValues row lane) =
      ∑ check, gamma check * targets check := by
  simp only [batchedLinearWeights, Finset.sum_mul, mul_assoc]
  calc
    (∑ row, ∑ lane : Fin 64, ∑ check,
        gamma check * (coefficients check row lane * witnessValues row lane)) =
      ∑ row, ∑ check, ∑ lane : Fin 64,
        gamma check * (coefficients check row lane * witnessValues row lane) := by
      apply Finset.sum_congr rfl
      intro row _
      exact Finset.sum_comm
    _ = ∑ check, ∑ row, ∑ lane : Fin 64,
        gamma check * (coefficients check row lane * witnessValues row lane) :=
      Finset.sum_comm
    _ = _ := by
      simp_rw [← Finset.mul_sum, valid]

def recoverLinearMaskOpening {Rows : Type*} [Fintype Rows]
    (packing : Fin 64 → F) (target : F) (high : Fin 132 → F)
    (weights : Rows → Fin 64 → F) (lagrange : Fin 64 → F[X])
    (openedRows : Rows → F) (point : F) : F :=
  (restoredLinearTranscript packing target high).eval point -
    publicLinearOpening weights lagrange openedRows point

theorem recover_linear_mask_opening {Rows : Type*} [Fintype Rows]
    (packing : Fin 64 → F) (packingCardNonzero : (64 : F) ≠ 0)
    (weights : Rows → Fin 64 → F) (lagrange : Fin 64 → F[X])
    (witnessPolynomials : Rows → F[X]) (mask : F[X])
    (constant target : F) (high : Fin 132 → F)
    (transcriptCoefficients : sourceLinearUnmasked weights lagrange witnessPolynomials + mask =
      C constant + nonconstantPolynomial high)
    (unmaskedTarget : packingSum packing
      (sourceLinearUnmasked weights lagrange witnessPolynomials) = target)
    (maskZeroSum : packingSum packing mask = 0) (point : F) :
    recoverLinearMaskOpening packing target high weights lagrange
      (fun row => (witnessPolynomials row).eval point) point = mask.eval point := by
  have targetSum : packingSum packing (C constant + nonconstantPolynomial high) = target := by
    rw [← transcriptCoefficients]
    simp only [packingSum, eval_add, Finset.sum_add_distrib] at *
    rw [unmaskedTarget, maskZeroSum, add_zero]
  rw [recoverLinearMaskOpening,
    restored_linear_transcript_exact packing packingCardNonzero constant target high targetSum,
    ← transcriptCoefficients, eval_add, source_linear_unmasked_evaluation]
  ring

/-- Source-sized recovery with the coefficient decomposition and public target derived. -/
theorem recover_source_linear_mask_opening {Rows : Type*} [Fintype Rows]
    (packing : Fin 64 → F) (injective : Function.Injective packing)
    (packingCardNonzero : (64 : F) ≠ 0)
    (weights : Rows → Fin 64 → F) (witnessPolynomials : Rows → F[X]) (mask : F[X])
    (target : F)
    (valid : (∑ row, ∑ lane : Fin 64,
      weights row lane * (witnessPolynomials row).eval (packing lane)) = target)
    (maskZeroSum : packingSum packing mask = 0)
    (degreeBound :
      (sourceLinearUnmasked weights (sourcePackingLagrange packing) witnessPolynomials + mask).natDegree
        ≤ 132) (point : F) :
    let transcript := sourceLinearUnmasked weights (sourcePackingLagrange packing)
      witnessPolynomials + mask
    recoverLinearMaskOpening packing target
      (fun index => transcript.coeff (index.val + 1)) weights (sourcePackingLagrange packing)
      (fun row => (witnessPolynomials row).eval point) point = mask.eval point := by
  apply recover_linear_mask_opening packing packingCardNonzero weights (sourcePackingLagrange packing)
    witnessPolynomials mask _ target _
    (polynomial_eq_constant_add_nonconstant _ degreeBound)
  · rw [source_linear_packing_sum packing injective weights witnessPolynomials]
    exact valid
  · exact maskZeroSum

/-- Fully source-sized linear mask theorem: neither its zero-sum property nor the omitted
coefficient reconstruction is supplied as an assumed output equality. -/
theorem source_linear_coins_recovered_from_opened_rows {Rows : Type*} [Fintype Rows]
    (packing : Fin 64 → F) (injective : Function.Injective packing)
    (packingCardNonzero : (64 : F) ≠ 0)
    (weights : Rows → Fin 64 → F) (witnessPolynomials : Rows → F[X])
    (witnessDegree : ∀ row, (witnessPolynomials row).natDegree ≤ 69)
    (coins : Fin 132 → F) (target : F)
    (valid : (∑ row, ∑ lane : Fin 64,
      weights row lane * (witnessPolynomials row).eval (packing lane)) = target)
    (point : F) :
    let mask := sourceLinearMask packing coins
    let transcript := sourceLinearUnmasked weights (sourcePackingLagrange packing)
      witnessPolynomials + mask
    recoverLinearMaskOpening packing target
      (fun index => transcript.coeff (index.val + 1)) weights (sourcePackingLagrange packing)
      (fun row => (witnessPolynomials row).eval point) point = mask.eval point := by
  apply recover_source_linear_mask_opening packing injective packingCardNonzero weights
    witnessPolynomials (sourceLinearMask packing coins) target valid
    (source_linear_mask_packing_sum_zero packing packingCardNonzero coins)
  exact (natDegree_add_le _ _).trans (max_le
    (source_linear_unmasked_degree packing injective weights witnessPolynomials witnessDegree)
    (source_linear_mask_degree packing coins))

end

end HegemonCrypto.SmallWood.V8Smz9PiopOpeningRecovery
