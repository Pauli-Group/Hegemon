import HegemonCrypto.SmallWoodV8Smz9HonestHybrid
import HegemonCrypto.SmallWoodV8Smz9HiddenLeafQrom

/-!
# Eager SMZ9 privacy: chronological finite algebraic transports

The mask spaces below are the source's complete 5*489 nonlinear, 5*132 nonconstant
linear, and 5*388 DECS coefficient arrays. The first construction is an explicit
joint change of variables, including feedback from the DECS response into PIOP
challenges. No honest/simulated distribution equality is an input to that map.

This file does not define a production capability or assume a whole-view distance.
Quantum hybrid bounds and source implementation refinement are separate obligations.
-/

namespace HegemonCrypto.SmallWood.V8Smz9EagerPrivacy

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9JointAlgebraicLaw V8Smz9SingleProofPrivacy
open V8Smz9HonestHybrid
open Polynomial
open scoped BigOperators ENNReal Classical

noncomputable section

set_option maxRecDepth 5000
set_option maxHeartbeats 2000000

abbrev NonlinearCoefficients (F : Type*) := Fin 5 → Fin 489 → F
abbrev LinearNonconstantCoefficients (F : Type*) := Fin 5 → Fin 132 → F
abbrev PiopCoefficients (F : Type*) :=
  NonlinearCoefficients F × LinearNonconstantCoefficients F
abbrev JointMaskCoins (F : Type*) := PiopCoefficients F × DecsFullCoefficients F
abbrev JointMaskOutputs (F : Type*) := DecsFullCoefficients F × PiopCoefficients F

def sourceMaskCoefficientEquiv (F : Type*) :
    (NonlinearPiopMaskCoins F × LinearPiopMaskCoins F) ≃ PiopCoefficients F :=
  Equiv.prodCongr
    (Equiv.piCongrRight fun _ : Fin 5 => (splitEquiv 6 483 F).symm)
    (Equiv.piCongrRight fun _ : Fin 5 => (splitEquiv 6 126 F).symm)

def sourceDecsCoefficientEquiv (F : Type*) :
    DecsPolynomialCoins F ≃ DecsFullCoefficients F :=
  Equiv.piCongrRight fun _ : Fin 5 => (splitEquiv 20 368 F).symm

theorem eager_mask_coordinate_counts :
    5 * 489 + 5 * 132 = 3105 ∧ 5 * 388 = 1940 ∧
      4116 + 3105 + 240 + 2800 + 1940 = 12201 := by decide

def coefficientPolynomial {F : Type*} [Semiring F] {count : ℕ}
    (coefficients : Fin count → F) : F[X] :=
  ∑ coefficient : Fin count, C (coefficients coefficient) * X ^ coefficient.val

theorem coefficient_polynomial_evaluation {F : Type*} [CommSemiring F] {count : ℕ}
    (coefficients : Fin count → F) (point : F) :
    (coefficientPolynomial coefficients).eval point =
      ∑ coefficient : Fin count, point ^ coefficient.val * coefficients coefficient := by
  unfold coefficientPolynomial
  rw [eval_finsetSum]
  simp only [eval_mul, eval_C, eval_pow, eval_X]
  simp_rw [mul_comm]

theorem coefficient_polynomial_split {F : Type*} [CommSemiring F]
    (left right : ℕ) (coefficients : Fin (left + right) → F) :
    coefficientPolynomial coefficients =
      coefficientPolynomial (fun index => coefficients (Fin.castAdd right index)) +
        X ^ left * coefficientPolynomial (fun index => coefficients (Fin.natAdd left index)) := by
  unfold coefficientPolynomial
  rw [Fin.sum_univ_add]
  simp only [Fin.val_castAdd, Fin.val_natAdd, Finset.mul_sum, pow_add]
  congr 1
  apply Finset.sum_congr rfl
  intro index _
  ring

theorem coefficient_polynomial_rows {F : Type*} [CommSemiring F]
    (rows columns : ℕ) (coefficients : Fin (rows * columns) → F) :
    coefficientPolynomial coefficients =
      ∑ row : Fin rows, X ^ (columns * row.val) * coefficientPolynomial
        (fun column : Fin columns => coefficients (finProdFinEquiv (row, column))) := by
  unfold coefficientPolynomial
  rw [← (finProdFinEquiv : Fin rows × Fin columns ≃ Fin (rows * columns)).sum_comp]
  rw [Fintype.sum_prod_type]
  apply Finset.sum_congr rfl
  intro row _
  rw [Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro column _
  simp only [finProdFinEquiv, Equiv.coe_fn_mk, pow_add]
  ring

theorem coefficient_polynomial_nat_degree_le {F : Type*} [Semiring F]
    {count : ℕ} (coefficients : Fin count → F) :
    (coefficientPolynomial coefficients).natDegree ≤ count - 1 := by
  unfold coefficientPolynomial
  apply natDegree_sum_le_of_forall_le
  intro index _
  apply natDegree_mul_le.trans
  simp only [natDegree_C, zero_add]
  have degreeBound := natDegree_X_pow_le (R := F) index.val
  omega

theorem coefficient_polynomial_of_coefficients {F : Type*} [Semiring F]
    {count : ℕ} (polynomial : F[X]) (degreeBound : polynomial.natDegree < count) :
    coefficientPolynomial (fun index : Fin count => polynomial.coeff index.val) = polynomial := by
  unfold coefficientPolynomial
  calc
    _ = ∑ index ∈ Finset.range count, C (polynomial.coeff index) * X ^ index :=
      Fin.sum_univ_eq_sum_range _ _
    _ = polynomial := (polynomial.as_sum_range_C_mul_X_pow' degreeBound).symm

/-- The actual degree-132 mask has a derived constant, not 133 independent coins. -/
def sourceLinearMaskPolynomial {F : Type*} [Field F]
    (coefficients : Fin 132 → F) : F[X] :=
  ∑ coefficient : Fin 132,
    C (coefficients coefficient) *
      (X ^ (coefficient.val + 1) - C (packingPowerMean (coefficient.val + 1)))

theorem source_linear_mask_evaluation {F : Type*} [Field F]
    (coefficients : Fin 132 → F) (point : F) :
    (sourceLinearMaskPolynomial coefficients).eval point =
      ∑ coefficient : Fin 132,
        coefficients coefficient * linearAdjustedBasis point (coefficient.val + 1) := by
  unfold sourceLinearMaskPolynomial
  rw [eval_finsetSum]
  simp only [eval_mul, eval_C, eval_sub, eval_pow, eval_X, linearAdjustedBasis]

theorem source_linear_mask_zero_packing_sum {F : Type*} [Field F]
    (nonzeroPacking : (packingFactor : F) ≠ 0) (coefficients : Fin 132 → F) :
    (∑ lane : Fin packingFactor,
      (sourceLinearMaskPolynomial coefficients).eval (lane.val : F)) = 0 := by
  simp_rw [source_linear_mask_evaluation]
  rw [Finset.sum_comm]
  apply Finset.sum_eq_zero
  intro coefficient _
  rw [← Finset.mul_sum,
    linear_adjusted_basis_has_zero_packing_sum nonzeroPacking (coefficient.val + 1), mul_zero]

/-- Exact source-sized Q/M forward map. PIOP offsets are evaluated at the new response D. -/
def jointMaskForward {F : Type*} [Field F]
    (gammaD : DecsGamma F) (heads : PiopCoefficients F → LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F)
    (piopUnmasked : DecsFullCoefficients F → PiopCoefficients F)
    (coins : JointMaskCoins F) : JointMaskOutputs F :=
  let response := exactDecsResponse gammaD (heads coins.1) tails coins.2
  (response, piopUnmasked response + coins.1)

/-- The inverse is ordered D -> PIOP challenges -> Q -> committed rows -> M. -/
def jointMaskInverse {F : Type*} [Field F]
    (gammaD : DecsGamma F) (heads : PiopCoefficients F → LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F)
    (piopUnmasked : DecsFullCoefficients F → PiopCoefficients F)
    (output : JointMaskOutputs F) : JointMaskCoins F :=
  let masks := output.2 - piopUnmasked output.1
  (masks, output.1 - exactDecsUnmaskedCoefficients gammaD (heads masks) tails)

theorem joint_mask_inverse_after_forward {F : Type*} [Field F]
    (gammaD : DecsGamma F) (heads : PiopCoefficients F → LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F)
    (piopUnmasked : DecsFullCoefficients F → PiopCoefficients F)
    (coins : JointMaskCoins F) :
    jointMaskInverse gammaD heads tails piopUnmasked
        (jointMaskForward gammaD heads tails piopUnmasked coins) = coins := by
  simp only [jointMaskInverse, jointMaskForward, add_sub_cancel_left]
  change (coins.1, exactDecsUnmaskedCoefficients gammaD (heads coins.1) tails + coins.2 -
      exactDecsUnmaskedCoefficients gammaD (heads coins.1) tails) = coins
  rw [add_sub_cancel_left]

theorem joint_mask_forward_after_inverse {F : Type*} [Field F]
    (gammaD : DecsGamma F) (heads : PiopCoefficients F → LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F)
    (piopUnmasked : DecsFullCoefficients F → PiopCoefficients F)
    (output : JointMaskOutputs F) :
    jointMaskForward gammaD heads tails piopUnmasked
        (jointMaskInverse gammaD heads tails piopUnmasked output) = output := by
  have response_eq :
      exactDecsResponse gammaD (heads (output.2 - piopUnmasked output.1)) tails
          (output.1 - exactDecsUnmaskedCoefficients gammaD
            (heads (output.2 - piopUnmasked output.1)) tails) = output.1 := by
    unfold exactDecsResponse
    abel
  simp only [jointMaskForward, jointMaskInverse, response_eq]
  congr 1
  abel

def jointPiopDecsMaskEquiv {F : Type*} [Field F]
    (gammaD : DecsGamma F) (heads : PiopCoefficients F → LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F)
    (piopUnmasked : DecsFullCoefficients F → PiopCoefficients F) :
    JointMaskCoins F ≃ JointMaskOutputs F where
  toFun := jointMaskForward gammaD heads tails piopUnmasked
  invFun := jointMaskInverse gammaD heads tails piopUnmasked
  left_inv := joint_mask_inverse_after_forward gammaD heads tails piopUnmasked
  right_inv := joint_mask_forward_after_inverse gammaD heads tails piopUnmasked

theorem joint_piop_decs_complete_uniform_law {F : Type*} [Field F] [Fintype F]
    (gammaD : DecsGamma F) (heads : PiopCoefficients F → LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F)
    (piopUnmasked : DecsFullCoefficients F → PiopCoefficients F) :
    pmfMap (uniformFintypePMF (JointMaskCoins F))
        (jointMaskForward gammaD heads tails piopUnmasked) =
      uniformFintypePMF (JointMaskOutputs F) :=
  uniform_pmf_map_equiv (jointPiopDecsMaskEquiv gammaD heads tails piopUnmasked)

/-- Arbitrary observations retain the old masks and their witness-dependent leaf inputs. -/
theorem joint_mask_transport_retains_arbitrary_observation
    {F Result : Type*} [Field F] [Fintype F]
    (gammaD : DecsGamma F) (heads : PiopCoefficients F → LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F)
    (piopUnmasked : DecsFullCoefficients F → PiopCoefficients F)
    (observe : JointMaskCoins F → JointMaskOutputs F → PMF Result) :
    ((uniformFintypePMF (JointMaskCoins F)).bind fun coins =>
      observe coins (jointMaskForward gammaD heads tails piopUnmasked coins)) =
    ((uniformFintypePMF (JointMaskOutputs F)).bind fun output =>
      observe (jointMaskInverse gammaD heads tails piopUnmasked output) output) := by
  let transport := jointPiopDecsMaskEquiv gammaD heads tails piopUnmasked
  calc
    _ = (pmfMap (uniformFintypePMF (JointMaskCoins F)) transport).bind
        (fun output => observe (transport.symm output) output) := by
      simp [pmfMap, PMF.bind_bind, Function.comp_def, transport]
      rfl
    _ = _ := by
      rw [uniform_pmf_map_equiv transport]
      rfl

/-- The full Q/M response is sampled before all retained witness/PCS/LVCS coins.
The observation may retain every original mask and every resulting leaf input. -/
theorem chronological_joint_mask_transport
    {F Base Leaves Result : Type*} [Field F] [Fintype F]
    (baseLaw : PMF Base) (leafLaw : PMF Leaves)
    (gammaD : Leaves → DecsGamma F)
    (heads : Base → PiopCoefficients F → LvcsCommittedHeads F)
    (tails : Base → LvcsRandomTailCoins F)
    (piopUnmasked : Base → Leaves → DecsFullCoefficients F → PiopCoefficients F)
    (observe : Base → Leaves → JointMaskCoins F → JointMaskOutputs F → PMF Result) :
    (baseLaw.bind fun base =>
      (uniformFintypePMF (JointMaskCoins F)).bind fun coins =>
        leafLaw.bind fun leaves => observe base leaves coins
          (jointMaskForward (gammaD leaves) (heads base) (tails base)
            (piopUnmasked base leaves) coins)) =
    (leafLaw.bind fun leaves =>
      (uniformFintypePMF (JointMaskOutputs F)).bind fun output =>
        baseLaw.bind fun base => observe base leaves
          (jointMaskInverse (gammaD leaves) (heads base) (tails base)
            (piopUnmasked base leaves) output) output) := by
  calc
    _ = baseLaw.bind (fun base => leafLaw.bind (fun leaves =>
        (uniformFintypePMF (JointMaskCoins F)).bind fun coins =>
          observe base leaves coins
            (jointMaskForward (gammaD leaves) (heads base) (tails base)
              (piopUnmasked base leaves) coins))) := by
      congr 1
      funext base
      exact PMF.bind_comm _ _ _
    _ = leafLaw.bind (fun leaves => baseLaw.bind (fun base =>
        (uniformFintypePMF (JointMaskCoins F)).bind fun coins =>
          observe base leaves coins
            (jointMaskForward (gammaD leaves) (heads base) (tails base)
              (piopUnmasked base leaves) coins))) := PMF.bind_comm _ _ _
    _ = leafLaw.bind (fun leaves => baseLaw.bind (fun base =>
        (uniformFintypePMF (JointMaskOutputs F)).bind fun output =>
          observe base leaves
            (jointMaskInverse (gammaD leaves) (heads base) (tails base)
              (piopUnmasked base leaves) output) output)) := by
      congr 1
      funext leaves
      congr 1
      funext base
      exact joint_mask_transport_retains_arbitrary_observation _ _ _ _ _
    _ = _ := by
      congr 1
      funext leaves
      exact PMF.bind_comm _ _ _

abbrev WitnessPackingValues (F : Type*) := Fin 686 → Fin 64 → F
abbrev WitnessPolynomials (F : Type*) [Semiring F] := Fin 686 → F[X]

def sourceWitnessBasePolynomial {F : Type*} [Field F]
    (values : Fin 64 → F) : F[X] :=
  ∑ lane : Fin 64, C (values lane) *
    Lagrange.basis (Finset.univ : Finset (Fin 64)) (fun index => (index.val : F)) lane

def sourceWitnessPolynomials {F : Type*} [Field F]
    (values : WitnessPackingValues F) (coins : WitnessInterpolationCoins F) :
    WitnessPolynomials F := fun row =>
  sourceWitnessBasePolynomial (values row) + witnessRandomnessPolynomial (coins row)

def sourceWitnessBaseOpenings {F : Type*} [Field F]
    (values : WitnessPackingValues F) (points : Fin piopOpeningCount → F) :
    WitnessOpeningView F := fun opening row =>
  (sourceWitnessBasePolynomial (values row)).eval (points opening)

def sourceWitnessOpenings {F : Type*} [Field F]
    (values : WitnessPackingValues F) (points : Fin piopOpeningCount → F)
    (coins : WitnessInterpolationCoins F) : WitnessOpeningView F := fun opening row =>
  (sourceWitnessPolynomials values coins row).eval (points opening)

def sourceWitnessOpeningEquiv {F : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin piopOpeningCount → F)
    (admissible : Smz9WitnessInterpolationAdmissible points) :
    WitnessInterpolationCoins F ≃ WitnessOpeningView F :=
  affineOutputEquiv (exactWitnessInterpolationAddEquiv points admissible)
    (sourceWitnessBaseOpenings values points)

theorem source_witness_opening_equiv_matches_polynomials
    {F : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin piopOpeningCount → F)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (coins : WitnessInterpolationCoins F) :
    sourceWitnessOpeningEquiv values points admissible coins =
      sourceWitnessOpenings values points coins := by
  funext opening row
  change (sourceWitnessBasePolynomial (values row)).eval (points opening) +
      exactWitnessInterpolationMap points coins opening row = _
  simp only [sourceWitnessOpenings, sourceWitnessPolynomials, eval_add]
  rw [witness_randomness_polynomial_eval_opening]
  rfl

abbrev SourceNonlinearPcsCoins (F : Type*) := Fin 5 → Fin 7 → Fin 6 → F
abbrev SourceLinearPcsCoins (F : Type*) := Fin 5 → Fin 6 → F
abbrev SourcePcsCoins (F : Type*) := SourceNonlinearPcsCoins F × SourceLinearPcsCoins F
abbrev SourceNonlinearPcsView (F : Type*) := Fin 5 → Fin 6 → Fin 7 → F
abbrev SourceLinearPcsView (F : Type*) := Fin 5 → Fin 6 → F
abbrev SourcePcsView (F : Type*) := SourceNonlinearPcsView F × SourceLinearPcsView F

/-- Rust draw order is polynomial -> coefficient-row -> coin-column; the
nonlinear function space transposes the last two coordinates explicitly. -/
def sourcePcsAllocationEquiv (F : Type*) : (Fin 240 → F) ≃ SourcePcsCoins F :=
  (splitEquiv 210 30 F).trans
    (Equiv.prodCongr
      ((matrixEquiv 5 (6 * 7) F).trans
        (Equiv.piCongrRight fun _ : Fin 5 =>
          (matrixEquiv 6 7 F).trans
            (Equiv.piComm (fun _ : Fin 6 => fun _ : Fin 7 => F))))
      (matrixEquiv 5 6 F))

theorem source_pcs_nonlinear_allocation_index
    (F : Type*) (values : Fin 240 → F)
    (polynomial : Fin 5) (column : Fin 7) (coefficient : Fin 6) :
    (sourcePcsAllocationEquiv F values).1 polynomial column coefficient =
      values (Fin.castAdd 30
        (finProdFinEquiv (polynomial, finProdFinEquiv (coefficient, column)))) := rfl

theorem source_pcs_linear_allocation_index
    (F : Type*) (values : Fin 240 → F)
    (polynomial : Fin 5) (coefficient : Fin 6) :
    (sourcePcsAllocationEquiv F values).2 polynomial coefficient =
      values (Fin.natAdd 210 (finProdFinEquiv (polynomial, coefficient))) := rfl

def acceptedSourcePcsAllocation : RuntimeFieldCoins 240 ≃ SourcePcsCoins Goldilocks :=
  (Equiv.piCongrRight fun _ : Fin 240 => idealFieldCoinEquivGoldilocks).trans
    (sourcePcsAllocationEquiv Goldilocks)

theorem ideal_source_pcs_allocation_is_uniform :
    pmfMap (iidUniformRejectionSamplerOutputPMF 240) acceptedSourcePcsAllocation =
      uniformFintypePMF (SourcePcsCoins Goldilocks) := by
  rw [iid_uniform_rejection_output_vector_uniform]
  exact uniform_pmf_map_equiv acceptedSourcePcsAllocation

/-- Actual source next-column update, not the legacy same-column audit matrix. -/
def sourceNonlinearPcsPointMap {F : Type*} [Field F]
    (point : F) (values : Fin 7 → F) : Fin 7 → F :=
  ![point ^ 64 * values 1 - values 0,
    point ^ 64 * values 2 - values 1,
    point ^ 64 * values 3 - values 2,
    point ^ 64 * values 4 - values 3,
    point ^ 64 * values 5 - values 4,
    point ^ 64 * values 6 - values 5,
    -(point ^ 29 * values 6)]

theorem source_nonlinear_pcs_point_map_injective {F : Type*} [Field F]
    {point : F} (nonzero : point ≠ 0) :
    Function.Injective (sourceNonlinearPcsPointMap point) := by
  intro left right equal
  have h6 : left 6 = right 6 := by
    have h := congrFun equal 6
    simpa [sourceNonlinearPcsPointMap, pow_ne_zero _ nonzero] using h
  have h5 : left 5 = right 5 := by
    have h := congrFun equal 5
    simpa [sourceNonlinearPcsPointMap, h6] using h
  have h4 : left 4 = right 4 := by
    have h := congrFun equal 4
    simpa [sourceNonlinearPcsPointMap, h5] using h
  have h3 : left 3 = right 3 := by
    have h := congrFun equal 3
    simpa [sourceNonlinearPcsPointMap, h4] using h
  have h2 : left 2 = right 2 := by
    have h := congrFun equal 2
    simpa [sourceNonlinearPcsPointMap, h3] using h
  have h1 : left 1 = right 1 := by
    have h := congrFun equal 1
    simpa [sourceNonlinearPcsPointMap, h2] using h
  have h0 : left 0 = right 0 := by
    have h := congrFun equal 0
    simpa [sourceNonlinearPcsPointMap, h1] using h
  funext index
  fin_cases index <;> assumption

def sourceNonlinearPcsPointEquiv {F : Type*} [Field F] [Fintype F]
    (point : F) (nonzero : point ≠ 0) : (Fin 7 → F) ≃ (Fin 7 → F) :=
  Equiv.ofBijective (sourceNonlinearPcsPointMap point)
    ((Fintype.bijective_iff_injective_and_card _).2
      ⟨source_nonlinear_pcs_point_map_injective nonzero, rfl⟩)

def sourcePcsCoinEvaluation {F : Type*} [Field F]
    (points : Fin 6 → F) (coins : Fin 6 → F) : Fin 6 → F := fun opening =>
  ∑ coefficient : Fin 6, points opening ^ coefficient.val * coins coefficient

theorem source_pcs_coin_evaluation_injective {F : Type*} [Field F]
    {points : Fin 6 → F} (injective : Function.Injective points) :
    Function.Injective (sourcePcsCoinEvaluation points) := by
  have h := pcs_unstack_block_map_injective (points := points) (factor := fun _ => 1)
    injective (by intro _; exact one_ne_zero)
  have mapsEqual : pcsUnstackBlockMap points (fun _ => 1) =
      sourcePcsCoinEvaluation points := by
    funext coins opening
    simp only [pcsUnstackBlockMap, one_mul, sourcePcsCoinEvaluation]
    rfl
  rwa [mapsEqual] at h

def sourcePcsCoinEvaluationEquiv {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F) (injective : Function.Injective points) :
    (Fin 6 → F) ≃ (Fin 6 → F) :=
  Equiv.ofBijective (sourcePcsCoinEvaluation points)
    ((Fintype.bijective_iff_injective_and_card _).2
      ⟨source_pcs_coin_evaluation_injective injective, rfl⟩)

def sourceNonlinearPcsMap {F : Type*} [Field F]
    (points : Fin 6 → F) (coins : SourceNonlinearPcsCoins F) : SourceNonlinearPcsView F :=
  fun polynomial opening => sourceNonlinearPcsPointMap (points opening)
    (fun column => sourcePcsCoinEvaluation points (coins polynomial column) opening)

def sourceLinearPcsMap {F : Type*} [Field F]
    (points : Fin 6 → F) (coins : SourceLinearPcsCoins F) : SourceLinearPcsView F :=
  fun polynomial opening => -(points opening *
    sourcePcsCoinEvaluation points (coins polynomial) opening)

def sourceNonlinearPcsEquiv {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F) (injective : Function.Injective points)
    (nonzero : ∀ opening, points opening ≠ 0) :
    SourceNonlinearPcsCoins F ≃ SourceNonlinearPcsView F :=
  (Equiv.piCongrRight fun _ : Fin 5 =>
    (Equiv.piCongrRight fun _ : Fin 7 => sourcePcsCoinEvaluationEquiv points injective).trans
      (Equiv.piComm (fun _ : Fin 7 => fun _ : Fin 6 => F))).trans
    (Equiv.piCongrRight fun _ : Fin 5 =>
      Equiv.piCongrRight fun opening : Fin 6 =>
        sourceNonlinearPcsPointEquiv (points opening) (nonzero opening))

def sourceLinearPcsEquiv {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F) (injective : Function.Injective points)
    (nonzero : ∀ opening, points opening ≠ 0) :
    SourceLinearPcsCoins F ≃ SourceLinearPcsView F :=
  (Equiv.piCongrRight fun _ : Fin 5 => sourcePcsCoinEvaluationEquiv points injective).trans
    (Equiv.piCongrRight fun _ : Fin 5 =>
      Equiv.piCongrRight fun opening : Fin 6 =>
        (Equiv.mulLeft₀ (points opening) (nonzero opening)).trans (Equiv.neg F))

def sourcePcsEquiv {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F) (injective : Function.Injective points)
    (nonzero : ∀ opening, points opening ≠ 0) : SourcePcsCoins F ≃ SourcePcsView F :=
  Equiv.prodCongr (sourceNonlinearPcsEquiv points injective nonzero)
    (sourceLinearPcsEquiv points injective nonzero)

theorem source_pcs_equiv_matches_next_column_map {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F) (injective : Function.Injective points)
    (nonzero : ∀ opening, points opening ≠ 0) (coins : SourcePcsCoins F) :
    sourcePcsEquiv points injective nonzero coins =
      (sourceNonlinearPcsMap points coins.1, sourceLinearPcsMap points coins.2) := rfl

theorem source_pcs_joint_uniform_law {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F) (injective : Function.Injective points)
    (nonzero : ∀ opening, points opening ≠ 0) :
    pmfMap (uniformFintypePMF (SourcePcsCoins F))
        (sourcePcsEquiv points injective nonzero) =
      uniformFintypePMF (SourcePcsView F) :=
  uniform_pmf_map_equiv (sourcePcsEquiv points injective nonzero)

/-- The legacy linear block differs even for every nonzero point that it admits. -/
theorem actual_linear_pcs_constant_coin_ne_legacy {F : Type*} [Field F]
    (point : F) (nonzero : point ≠ 0) :
    -point ≠ point ^ 64 - point := by
  intro same
  have zeroPower : point ^ 64 = 0 := by linear_combination -same
  exact pow_ne_zero 64 nonzero zeroPower

theorem actual_linear_pcs_constant_coin_goldilocks_65 :
    -(65 : Goldilocks) ≠ (65 : Goldilocks) ^ 64 - 65 := by
  apply actual_linear_pcs_constant_coin_ne_legacy
  change (65 : ZMod goldilocksModulus) ≠ 0
  exact (CharP.cast_eq_zero_iff (ZMod goldilocksModulus) goldilocksModulus 65).not.mpr
    (by norm_num [goldilocksModulus])

/-- Values of all eight nonlinear PCS columns, including the un-serialized first one. -/
def sourceNonlinearColumnValues {F : Type*} [CommRing F]
    (point : F) (base : Fin 8 → F) (randomness : Fin 7 → F) : Fin 8 → F :=
  ![base 0 + point ^ 64 * randomness 0,
    base 1 + point ^ 64 * randomness 1 - randomness 0,
    base 2 + point ^ 64 * randomness 2 - randomness 1,
    base 3 + point ^ 64 * randomness 3 - randomness 2,
    base 4 + point ^ 64 * randomness 4 - randomness 3,
    base 5 + point ^ 64 * randomness 5 - randomness 4,
    base 6 + point ^ 64 * randomness 6 - randomness 5,
    base 7 - point ^ 29 * randomness 6]

def sourceNonlinearReconstruction {F : Type*} [CommRing F]
    (point : F) (values : Fin 8 → F) : F :=
  values 0 + point ^ 64 * values 1 + point ^ 128 * values 2 +
    point ^ 192 * values 3 + point ^ 256 * values 4 + point ^ 320 * values 5 +
    point ^ 384 * values 6 + point ^ 419 * values 7

theorem source_nonlinear_partials_match_point_map {F : Type*} [Field F]
    (point : F) (base : Fin 8 → F) (randomness : Fin 7 → F) :
    (fun column : Fin 7 => sourceNonlinearColumnValues point base randomness column.succ) =
      (fun column : Fin 7 => base column.succ) +
        sourceNonlinearPcsPointMap point randomness := by
  funext column
  fin_cases column <;> simp [sourceNonlinearColumnValues, sourceNonlinearPcsPointMap] <;> ring

/-- Source reassembly cancels every next-column mask, including the degree-shifted last one. -/
theorem source_nonlinear_reconstruction_cancels_pcs_randomness
    {F : Type*} [Field F]
    (point : F) (base : Fin 8 → F) (randomness : Fin 7 → F) :
    sourceNonlinearReconstruction point (sourceNonlinearColumnValues point base randomness) =
      sourceNonlinearReconstruction point base := by
  simp [sourceNonlinearReconstruction, sourceNonlinearColumnValues]
  ring

def sourceRecoveredNonlinearFirstColumn {F : Type*} [Field F]
    (point scalar : F) (partials : Fin 7 → F) : F :=
  scalar - (point ^ 64 * partials 0 + point ^ 128 * partials 1 +
    point ^ 192 * partials 2 + point ^ 256 * partials 3 + point ^ 320 * partials 4 +
    point ^ 384 * partials 5 + point ^ 419 * partials 6)

theorem source_nonlinear_first_column_is_publicly_recovered
    {F : Type*} [Field F]
    (point : F) (base : Fin 8 → F) (randomness : Fin 7 → F) :
    sourceRecoveredNonlinearFirstColumn point (sourceNonlinearReconstruction point base)
        (fun column => sourceNonlinearColumnValues point base randomness column.succ) =
      sourceNonlinearColumnValues point base randomness 0 := by
  simp [sourceRecoveredNonlinearFirstColumn, sourceNonlinearReconstruction,
    sourceNonlinearColumnValues]
  ring

def sourceLinearColumnValues {F : Type*} [CommRing F]
    (point : F) (base : Fin 2 → F) (randomness : F) : Fin 2 → F :=
  ![base 0 + point ^ 64 * randomness, base 1 - point * randomness]

theorem source_linear_reconstruction_cancels_pcs_randomness
    {F : Type*} [Field F] (point : F) (base : Fin 2 → F) (randomness : F) :
    sourceLinearColumnValues point base randomness 0 +
        point ^ 63 * sourceLinearColumnValues point base randomness 1 =
      base 0 + point ^ 63 * base 1 := by
  simp only [sourceLinearColumnValues, Matrix.cons_val_zero, Matrix.cons_val_one]
  ring

theorem source_linear_first_column_is_publicly_recovered
    {F : Type*} [Field F] (point : F) (base : Fin 2 → F) (randomness : F) :
    (base 0 + point ^ 63 * base 1) -
        point ^ 63 * sourceLinearColumnValues point base randomness 1 =
      sourceLinearColumnValues point base randomness 0 := by
  have recombine := source_linear_reconstruction_cancels_pcs_randomness point base randomness
  linear_combination -recombine

abbrev SourceRemainingCoins (F : Type*) :=
  WitnessInterpolationCoins F × (SourcePcsCoins F × LvcsRandomTailCoins F)
abbrev SourceRemainingView (F : Type*) :=
  WitnessOpeningView F × (SourcePcsView F × (LvcsEarlierTails F × LvcsLaterSubset F))

abbrev SourceRuntimeRoleGroups (F : Type*) :=
  WitnessInterpolationCoins F × (PiopCoefficients F ×
    (SourcePcsCoins F × (LvcsRandomTailCoins F × DecsFullCoefficients F)))

/-- Exact sequential allocation: 4116 W, 3105 alternating Q, 240 PCS,
2800 LVCS, then 1940 DECS. The nonlinear PCS allocation transposition is explicit. -/
def sourceRuntimeRoleAllocation (F : Type*) :
    (Fin 12201 → F) ≃ SourceRuntimeRoleGroups F :=
  (splitEquiv 4116 8085 F).trans
    (Equiv.prodCongr (matrixEquiv 686 6 F)
      ((splitEquiv 3105 4980 F).trans
        (Equiv.prodCongr ((alternatingMasksEquiv F).trans (sourceMaskCoefficientEquiv F))
          ((splitEquiv 240 4740 F).trans
            (Equiv.prodCongr (sourcePcsAllocationEquiv F)
              ((splitEquiv 2800 1940 F).trans
                (Equiv.prodCongr (matrixEquiv 140 20 F) (matrixEquiv 5 388 F))))))))

def sourceRuntimeRoleOrder (F : Type*) :
    SourceRuntimeRoleGroups F ≃ (SourceRemainingCoins F × JointMaskCoins F) where
  toFun groups :=
    ((groups.1, groups.2.2.1, groups.2.2.2.1), (groups.2.1, groups.2.2.2.2))
  invFun coins :=
    (coins.1.1, coins.2.1, coins.1.2.1, coins.1.2.2, coins.2.2)
  left_inv _ := rfl
  right_inv _ := rfl

def sourceCompleteCoinAllocation (F : Type*) :
    (Fin 12201 → F) ≃ (SourceRemainingCoins F × JointMaskCoins F) :=
  (sourceRuntimeRoleAllocation F).trans (sourceRuntimeRoleOrder F)

def acceptedSourceCompleteCoinAllocation :
    RuntimeFieldCoins 12201 ≃
      (SourceRemainingCoins Goldilocks × JointMaskCoins Goldilocks) :=
  (Equiv.piCongrRight fun _ : Fin 12201 => idealFieldCoinEquivGoldilocks).trans
    (sourceCompleteCoinAllocation Goldilocks)

theorem ideal_source_complete_coin_allocation_is_uniform :
    pmfMap (iidUniformRejectionSamplerOutputPMF 12201) acceptedSourceCompleteCoinAllocation =
      uniformFintypePMF (SourceRemainingCoins Goldilocks × JointMaskCoins Goldilocks) := by
  rw [iid_uniform_rejection_output_vector_uniform]
  exact uniform_pmf_map_equiv acceptedSourceCompleteCoinAllocation

def sourceAffinePcsEquiv {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F) (injective : Function.Injective points)
    (nonzero : ∀ opening, points opening ≠ 0) (base : SourcePcsView F) :
    SourcePcsCoins F ≃ SourcePcsView F :=
  (sourcePcsEquiv points injective nonzero).trans (Equiv.addLeft base)

/-- A dependent transport, in chronological public-output order. Reconstructing the
old witness and PCS coins is internal; no witness-dependent datum is emitted. -/
def sourceRemainingViewEquiv {F : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → LvcsCommittedHeads F)
    (chooseTargets : WitnessOpeningView F → SourcePcsView F →
      LvcsEarlierTails F → LvcsAdmissibleTargets points) :
    SourceRemainingCoins F ≃ SourceRemainingView F :=
  let witnessEquiv := sourceWitnessOpeningEquiv values points witnessAdmissible
  (Equiv.prodCongr witnessEquiv (Equiv.refl _)).trans
    (Equiv.prodCongrRight fun witnessView =>
      let witnessCoins := witnessEquiv.symm witnessView
      let pcsEquiv := sourceAffinePcsEquiv points witnessAdmissible.openingPointsInjective
        pointsNonzero (pcsBase witnessCoins)
      (Equiv.prodCongr pcsEquiv (Equiv.refl _)).trans
        (Equiv.prodCongrRight fun pcsView =>
          exactLvcsChallengeFeedbackEquiv points
            (heads witnessCoins (pcsEquiv.symm pcsView))
            (chooseTargets witnessView pcsView)))

def sourcePcsFullView {F : Type*} [Field F]
    (points : Fin 6 → F) (base : SourcePcsView F) (coins : SourcePcsCoins F) :
    SourcePcsView F :=
  base + (sourceNonlinearPcsMap points coins.1, sourceLinearPcsMap points coins.2)

theorem source_affine_pcs_equiv_apply {F : Type*} [Field F] [Fintype F]
    (points : Fin 6 → F) (injective : Function.Injective points)
    (nonzero : ∀ opening, points opening ≠ 0) (base : SourcePcsView F)
    (coins : SourcePcsCoins F) :
    sourceAffinePcsEquiv points injective nonzero base coins =
      sourcePcsFullView points base coins := rfl

def sourceRemainingChronologicalView {F : Type*} [Field F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → LvcsCommittedHeads F)
    (chooseTargets : WitnessOpeningView F → SourcePcsView F →
      LvcsEarlierTails F → LvcsAdmissibleTargets points)
    (coins : SourceRemainingCoins F) : SourceRemainingView F :=
  let witnessView := sourceWitnessOpenings values points coins.1
  let pcsView := sourcePcsFullView points (pcsBase coins.1) coins.2.1
  let early := lvcsEarlierOutput points coins.2.2
  (witnessView, pcsView, early,
    lvcsFullSubsetInterpolation (heads coins.1 coins.2.1) coins.2.2
      (chooseTargets witnessView pcsView early).val)

theorem source_remaining_equiv_matches_chronological_view
    {F : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → LvcsCommittedHeads F)
    (chooseTargets : WitnessOpeningView F → SourcePcsView F →
      LvcsEarlierTails F → LvcsAdmissibleTargets points)
    (coins : SourceRemainingCoins F) :
    sourceRemainingViewEquiv values points witnessAdmissible pointsNonzero
        pcsBase heads chooseTargets coins =
      sourceRemainingChronologicalView values points pcsBase heads chooseTargets coins := by
  rcases coins with ⟨witnessCoins, pcsCoins, tailCoins⟩
  simp only [sourceRemainingViewEquiv, Equiv.trans_apply, Equiv.prodCongr_apply,
    Prod.map_apply, Equiv.refl_apply, Equiv.prodCongrRight_apply, Equiv.symm_apply_apply]
  simp only [exact_lvcs_feedback_matches_chronological_output,
    source_witness_opening_equiv_matches_polynomials, source_affine_pcs_equiv_apply,
    sourceRemainingChronologicalView]

theorem source_remaining_view_joint_uniform_law
    {F : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → LvcsCommittedHeads F)
    (chooseTargets : WitnessOpeningView F → SourcePcsView F →
      LvcsEarlierTails F → LvcsAdmissibleTargets points) :
    pmfMap (uniformFintypePMF (SourceRemainingCoins F))
        (sourceRemainingViewEquiv values points witnessAdmissible pointsNonzero
          pcsBase heads chooseTargets) =
      uniformFintypePMF (SourceRemainingView F) :=
  uniform_pmf_map_equiv (sourceRemainingViewEquiv values points witnessAdmissible
    pointsNonzero pcsBase heads chooseTargets)

theorem source_remaining_chronological_joint_uniform_law
    {F : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → LvcsCommittedHeads F)
    (chooseTargets : WitnessOpeningView F → SourcePcsView F →
      LvcsEarlierTails F → LvcsAdmissibleTargets points) :
    pmfMap (uniformFintypePMF (SourceRemainingCoins F))
        (sourceRemainingChronologicalView values points pcsBase heads chooseTargets) =
      uniformFintypePMF (SourceRemainingView F) := by
  have functionsEqual :
      sourceRemainingChronologicalView values points pcsBase heads chooseTargets =
        sourceRemainingViewEquiv values points witnessAdmissible pointsNonzero
          pcsBase heads chooseTargets := by
    funext coins
    exact (source_remaining_equiv_matches_chronological_view values points
      witnessAdmissible pointsNonzero pcsBase heads chooseTargets coins).symm
  rw [functionsEqual]
  exact source_remaining_view_joint_uniform_law _ _ _ _ _ _ _

abbrev SourcePartialRemainingView (F : Type*) :=
  WitnessOpeningView F × (SourcePcsView F ×
    (LvcsEarlierTails F × Option (LvcsLaterSubset F)))

def sourceRemainingPartialChronologicalView {F : Type*} [Field F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → LvcsCommittedHeads F)
    (chooseTargets : WitnessOpeningView F → SourcePcsView F →
      LvcsEarlierTails F → Option (LvcsAdmissibleTargets points))
    (coins : SourceRemainingCoins F) : SourcePartialRemainingView F :=
  let witnessView := sourceWitnessOpenings values points coins.1
  let pcsView := sourcePcsFullView points (pcsBase coins.1) coins.2.1
  (witnessView, pcsView, exactLvcsPartialFeedbackOutput points (heads coins.1 coins.2.1)
    (chooseTargets witnessView pcsView) coins.2.2)

def sourceRemainingAbortProjection {F : Type*} [Field F]
    {points : Fin 6 → F}
    (chooseTargets : WitnessOpeningView F → SourcePcsView F →
      LvcsEarlierTails F → Option (LvcsAdmissibleTargets points))
    (view : SourceRemainingView F) : SourcePartialRemainingView F :=
  (view.1, view.2.1, view.2.2.1,
    (chooseTargets view.1 view.2.1 view.2.2.1).map fun _ => view.2.2.2)

/-- The late sampler failure is retained; no conditioning-on-success equality is used. -/
theorem source_remaining_partial_chronological_joint_law
    {F : Type*} [Field F] [Fintype F]
    (values : WitnessPackingValues F) (points : Fin 6 → F)
    (witnessAdmissible : Smz9WitnessInterpolationAdmissible points)
    (pointsNonzero : ∀ opening, points opening ≠ 0)
    (pcsBase : WitnessInterpolationCoins F → SourcePcsView F)
    (heads : WitnessInterpolationCoins F → SourcePcsCoins F → LvcsCommittedHeads F)
    (fallback : LvcsAdmissibleTargets points)
    (chooseTargets : WitnessOpeningView F → SourcePcsView F →
      LvcsEarlierTails F → Option (LvcsAdmissibleTargets points)) :
    pmfMap (uniformFintypePMF (SourceRemainingCoins F))
        (sourceRemainingPartialChronologicalView values points pcsBase heads chooseTargets) =
      pmfMap (uniformFintypePMF (SourceRemainingView F))
        (sourceRemainingAbortProjection chooseTargets) := by
  let totalChoose := fun witnessView pcsView early =>
    (chooseTargets witnessView pcsView early).getD fallback
  have uniform := source_remaining_chronological_joint_uniform_law values points
    witnessAdmissible pointsNonzero pcsBase heads totalChoose
  have pushed := congrArg (fun law => pmfMap law (sourceRemainingAbortProjection chooseTargets))
    uniform
  rw [pmfMap_comp] at pushed
  have functionsEqual : sourceRemainingAbortProjection chooseTargets ∘
      sourceRemainingChronologicalView values points pcsBase heads totalChoose =
        sourceRemainingPartialChronologicalView values points pcsBase heads chooseTargets := by
    funext coins
    cases selected : chooseTargets (sourceWitnessOpenings values points coins.1)
        (sourcePcsFullView points (pcsBase coins.1) coins.2.1)
        (lvcsEarlierOutput points coins.2.2) with
    | none =>
      simp [sourceRemainingAbortProjection,
        sourceRemainingChronologicalView, sourceRemainingPartialChronologicalView,
        exactLvcsPartialFeedbackOutput, selected]
    | some targets =>
      simp [sourceRemainingAbortProjection,
        sourceRemainingChronologicalView, sourceRemainingPartialChronologicalView,
        exactLvcsPartialFeedbackOutput, totalChoose, selected]
  rw [functionsEqual] at pushed
  exact pushed

def sourceNonlinearPcsColumnPolynomials {F : Type*} [Field F]
    (base : Fin 8 → F[X]) (coins : Fin 7 → Fin 6 → F) : Fin 8 → F[X] :=
  sourceNonlinearColumnValues X base (fun column => coefficientPolynomial (coins column))

def sourceNonlinearLowChunk {F : Type*} [Field F]
    (coefficients : Fin 489 → F) (column : Fin 7) : F[X] :=
  coefficientPolynomial (fun index : Fin 64 =>
    coefficients (Fin.castAdd 41 (finProdFinEquiv (column, index))))

def sourceNonlinearLastChunk {F : Type*} [Field F]
    (coefficients : Fin 489 → F) : F[X] :=
  X ^ 29 * coefficientPolynomial (fun index : Fin 41 =>
    coefficients (Fin.natAdd 448 index))

def sourceNonlinearBaseColumns {F : Type*} [Field F]
    (coefficients : Fin 489 → F) : Fin 8 → F[X] :=
  ![sourceNonlinearLowChunk coefficients 0, sourceNonlinearLowChunk coefficients 1,
    sourceNonlinearLowChunk coefficients 2, sourceNonlinearLowChunk coefficients 3,
    sourceNonlinearLowChunk coefficients 4, sourceNonlinearLowChunk coefficients 5,
    sourceNonlinearLowChunk coefficients 6, sourceNonlinearLastChunk coefficients]

theorem source_nonlinear_chunks_reconstruct_full_polynomial
    {F : Type*} [Field F] (coefficients : Fin 489 → F) :
    sourceNonlinearReconstruction X (sourceNonlinearBaseColumns coefficients) =
      coefficientPolynomial coefficients := by
  have split := coefficient_polynomial_split 448 41 coefficients
  have rows := coefficient_polynomial_rows 7 64
    (fun index : Fin 448 => coefficients (Fin.castAdd 41 index))
  rw [rows, Fin.sum_univ_seven] at split
  rw [split]
  simp [sourceNonlinearReconstruction, sourceNonlinearBaseColumns,
    sourceNonlinearLowChunk, sourceNonlinearLastChunk]
  ring

def sourceLinearBaseColumns {F : Type*} [Field F]
    (coefficients : Fin 133 → F) : Fin 2 → F[X] :=
  ![coefficientPolynomial (fun index : Fin 64 => coefficients (Fin.castAdd 69 index)),
    X * coefficientPolynomial (fun index : Fin 69 => coefficients (Fin.natAdd 64 index))]

theorem source_linear_chunks_reconstruct_full_polynomial
    {F : Type*} [Field F] (coefficients : Fin 133 → F) :
    sourceLinearBaseColumns coefficients 0 + X ^ 63 * sourceLinearBaseColumns coefficients 1 =
      coefficientPolynomial coefficients := by
  rw [coefficient_polynomial_split 64 69 coefficients]
  simp [sourceLinearBaseColumns]
  ring

theorem source_nonlinear_column_polynomial_evaluation
    {F : Type*} [Field F]
    (base : Fin 8 → F[X]) (coins : Fin 7 → Fin 6 → F) (point : F) (column : Fin 8) :
    (sourceNonlinearPcsColumnPolynomials base coins column).eval point =
      sourceNonlinearColumnValues point (fun index => (base index).eval point)
        (fun index => ∑ coefficient : Fin 6,
          point ^ coefficient.val * coins index coefficient) column := by
  fin_cases column <;>
    dsimp [sourceNonlinearPcsColumnPolynomials, sourceNonlinearColumnValues] <;>
    simp only [eval_add, eval_sub, eval_mul, eval_pow, eval_X,
      coefficient_polynomial_evaluation]

theorem source_nonlinear_point_intermediate_formula {F : Type*} [Field F]
    (point : F) (values : Fin 7 → F) (column : Fin 6) :
    sourceNonlinearPcsPointMap point values column.castSucc =
      point ^ 64 * values column.succ - values column.castSucc := by
  fin_cases column <;> simp [sourceNonlinearPcsPointMap]

theorem source_nonlinear_next_column_coefficient_formula
    {F : Type*} [Field F]
    (points : Fin 6 → F) (coins : SourceNonlinearPcsCoins F)
    (polynomial : Fin 5) (opening column : Fin 6) :
    sourceNonlinearPcsMap points coins polynomial opening column.castSucc =
      (∑ coefficient : Fin 6,
        points opening ^ (64 + coefficient.val) * coins polynomial column.succ coefficient) -
      ∑ coefficient : Fin 6,
        points opening ^ coefficient.val * coins polynomial column.castSucc coefficient := by
  unfold sourceNonlinearPcsMap
  rw [source_nonlinear_point_intermediate_formula]
  simp only [sourcePcsCoinEvaluation, Finset.mul_sum, pow_add, mul_assoc]

theorem source_nonlinear_final_column_coefficient_formula
    {F : Type*} [Field F]
    (points : Fin 6 → F) (coins : SourceNonlinearPcsCoins F)
    (polynomial : Fin 5) (opening : Fin 6) :
    sourceNonlinearPcsMap points coins polynomial opening 6 =
      -(∑ coefficient : Fin 6,
        points opening ^ (29 + coefficient.val) * coins polynomial 6 coefficient) := by
  simp [sourceNonlinearPcsMap, sourceNonlinearPcsPointMap, sourcePcsCoinEvaluation,
    Finset.mul_sum, pow_add, mul_assoc]

theorem source_linear_next_column_coefficient_formula
    {F : Type*} [Field F]
    (points : Fin 6 → F) (coins : SourceLinearPcsCoins F)
    (polynomial : Fin 5) (opening : Fin 6) :
    sourceLinearPcsMap points coins polynomial opening =
      -(∑ coefficient : Fin 6,
        points opening ^ (1 + coefficient.val) * coins polynomial coefficient) := by
  simp only [sourceLinearPcsMap, sourcePcsCoinEvaluation, Finset.mul_sum, pow_add,
    pow_one, mul_assoc]

abbrev SourceUnstackedColumns (F : Type*) := Fin 736 → Fin 70 → F

/-- Exact reshape: row s selects coefficient s%70 and the column half s/70. -/
def sourceStackedHeads {F : Type*} (columns : SourceUnstackedColumns F) :
    LvcsCommittedHeads F := fun row column =>
  let position := (finProdFinEquiv : Fin 2 × Fin 70 ≃ Fin 140).symm row
  columns (finProdFinEquiv (position.1, column)) position.2

theorem source_stacked_head_at_row_major_index
    {F : Type*} (columns : SourceUnstackedColumns F)
    (block : Fin 2) (coefficient : Fin 70) (column : Fin 368) :
    sourceStackedHeads columns (finProdFinEquiv (block, coefficient)) column =
      columns (finProdFinEquiv (block, column)) coefficient := by
  simp only [sourceStackedHeads, Equiv.symm_apply_apply]
  rfl

theorem source_combination_matrix_at_row_major_index
    {F : Type*} [Field F] (points : Fin 6 → F)
    (opening : Fin 6) (block rowBlock : Fin 2) (coefficient : Fin 70) :
    smz9LvcsCombinationCoefficient points (finProdFinEquiv (opening, block))
        (finProdFinEquiv (rowBlock, coefficient)) =
      if rowBlock = block then points opening ^ coefficient.val else 0 := by
  have openingMatch :
      smz9LvcsCombinationOpening (finProdFinEquiv (opening, block)) = opening := by
    apply Fin.ext
    simp [smz9LvcsCombinationOpening, finProdFinEquiv, Nat.add_mul_div_left,
      Nat.div_eq_of_lt block.isLt]
  have blockMatch :
      (finProdFinEquiv (opening, block) : Fin 12).val % 2 = block.val := by
    simp [finProdFinEquiv, Nat.add_mod, Nat.mod_eq_of_lt block.isLt]
  unfold smz9LvcsCombinationCoefficient
  rw [openingMatch, blockMatch]
  change (if 70 * block.val ≤ coefficient.val + 70 * rowBlock.val ∧
      coefficient.val + 70 * rowBlock.val < 70 * block.val + 70 then
        points opening ^ (coefficient.val + 70 * rowBlock.val - 70 * block.val) else 0) = _
  by_cases blocksEqual : rowBlock = block
  · subst rowBlock
    have inside : 70 * block.val ≤ coefficient.val + 70 * block.val ∧
        coefficient.val + 70 * block.val < 70 * block.val + 70 := by omega
    simp [inside]
  · have differentValues : rowBlock.val ≠ block.val := by
      intro equal
      exact blocksEqual (Fin.ext equal)
    have outside : ¬ (70 * block.val ≤ coefficient.val + 70 * rowBlock.val ∧
        coefficient.val + 70 * rowBlock.val < 70 * block.val + 70) := by
      have hb := block.isLt
      have hr := rowBlock.isLt
      have hc := coefficient.isLt
      omega
    simp [outside, blocksEqual]

theorem source_public_combination_heads_equal_column_evaluations
    {F : Type*} [Field F]
    (points : Fin 6 → F) (columns : SourceUnstackedColumns F)
    (opening : Fin 6) (block : Fin 2) (column : Fin 368) :
    lvcsPublicCombinationHeads points (sourceStackedHeads columns)
        (finProdFinEquiv (opening, block)) column =
      (coefficientPolynomial (columns (finProdFinEquiv (block, column)))).eval
        (points opening) := by
  unfold lvcsPublicCombinationHeads
  calc
    _ = ∑ position : Fin 2 × Fin 70,
        smz9LvcsCombinationCoefficient points (finProdFinEquiv (opening, block))
          (finProdFinEquiv position) *
        sourceStackedHeads columns (finProdFinEquiv position) column :=
      ((finProdFinEquiv : Fin 2 × Fin 70 ≃ Fin 140).sum_comp
        (fun row : Fin 140 =>
          smz9LvcsCombinationCoefficient points (finProdFinEquiv (opening, block)) row *
            sourceStackedHeads columns row column)).symm
    _ = _ := by
      rw [Fintype.sum_prod_type]
      simp_rw [source_combination_matrix_at_row_major_index,
        source_stacked_head_at_row_major_index]
      simp [coefficient_polynomial_evaluation]

theorem source_public_combination_heads_equal_source_polynomials
    {F : Type*} [Field F]
    (points : Fin 6 → F) (polynomials : Fin 736 → F[X])
    (degreeBounds : ∀ column, (polynomials column).natDegree < 70)
    (opening : Fin 6) (block : Fin 2) (column : Fin 368) :
    lvcsPublicCombinationHeads points
        (sourceStackedHeads (fun index coefficient =>
          (polynomials index).coeff coefficient.val))
        (finProdFinEquiv (opening, block)) column =
      (polynomials (finProdFinEquiv (block, column))).eval (points opening) := by
  rw [source_public_combination_heads_equal_column_evaluations,
    coefficient_polynomial_of_coefficients _ (degreeBounds _)]

end

end HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
