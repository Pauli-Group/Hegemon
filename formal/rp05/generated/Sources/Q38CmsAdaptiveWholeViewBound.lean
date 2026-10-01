import Q38CmsInitializedFullDomainAssembly
import Q38WholeViewCmsSemantics

/-!
Continuity of the checked whole-view interpreter on an initialized CMS
purification.

The theorem in this file is deliberately downstream of both independently
checked components:

* `initialized_cms_full_domain_resampling_disturbance`, which bounds the
  mean squared distance of the *actual* controlled CMS states; and
* `databaseRun_totalOracleFamilyState`, which identifies the seven-constructor
  persistent-database interpreter with the uniform total-oracle purification.

No adaptive-reprogramming or semantic-distance conclusion is assumed.  The
only representation hypotheses in the final interface identify the two
states with their exact total-oracle families.
-/
namespace HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewBound

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open scoped BigOperators Classical ENNReal

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

/-! ## Finite uniform Cauchy--Schwarz -/

/-- Cauchy--Schwarz with the normalization already included in
`uniformAverage`.  Writing it this way avoids introducing the cardinality of
the (very large) oracle-function type into later goals. -/
theorem uniform_average_mul_le_sqrt_mul_sqrt
    {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (left right : Coins → ℝ) :
    uniformAverage (fun coin => left coin * right coin) ≤
      Real.sqrt (uniformAverage (fun coin => left coin ^ 2)) *
        Real.sqrt (uniformAverage (fun coin => right coin ^ 2)) := by
  let weight : Coins → ℝ :=
    fun coin => (uniformFintypePMF Coins coin).toReal
  have weightNonnegative (coin : Coins) : 0 ≤ weight coin :=
    ENNReal.toReal_nonneg
  have weightedSquare (coin : Coins) :
      (Real.sqrt (weight coin) * left coin) ^ 2 =
        weight coin * left coin ^ 2 := by
    rw [mul_pow, Real.sq_sqrt (weightNonnegative coin)]
  have weightedSquareRight (coin : Coins) :
      (Real.sqrt (weight coin) * right coin) ^ 2 =
        weight coin * right coin ^ 2 := by
    rw [mul_pow, Real.sq_sqrt (weightNonnegative coin)]
  have weightedProduct (coin : Coins) :
      (Real.sqrt (weight coin) * left coin) *
          (Real.sqrt (weight coin) * right coin) =
        weight coin * (left coin * right coin) := by
    calc
      (Real.sqrt (weight coin) * left coin) *
          (Real.sqrt (weight coin) * right coin) =
          (Real.sqrt (weight coin) * Real.sqrt (weight coin)) *
            (left coin * right coin) := by ring
      _ = weight coin * (left coin * right coin) := by
        rw [Real.mul_self_sqrt (weightNonnegative coin)]
  have cauchy := Real.sum_mul_le_sqrt_mul_sqrt
    (Finset.univ : Finset Coins)
    (fun coin => Real.sqrt (weight coin) * left coin)
    (fun coin => Real.sqrt (weight coin) * right coin)
  unfold uniformAverage
  change
    (∑ coin, weight coin * (left coin * right coin)) ≤
      Real.sqrt (∑ coin, weight coin * left coin ^ 2) *
        Real.sqrt (∑ coin, weight coin * right coin ^ 2)
  simpa only [weightedProduct, weightedSquare, weightedSquareRight] using cauchy

/-- Jensen/Cauchy--Schwarz for the square root step, retained locally so this
module does not depend on an uncompiled historical wrapper. -/
theorem uniform_average_le_sqrt_mean_square
    {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (value : Coins → ℝ) (nonnegative : ∀ coin, 0 ≤ value coin)
    (loss : ℝ) (lossNonnegative : 0 ≤ loss)
    (bounded : uniformAverage (fun coin => value coin ^ 2) ≤ loss) :
    uniformAverage value ≤ Real.sqrt loss := by
  have cardPositive : (0 : ℝ) < Fintype.card Coins := by
    exact_mod_cast Fintype.card_pos
  rw [uniformAverage_eq_sum_div] at bounded ⊢
  have sumBound := (div_le_iff₀ cardPositive).mp bounded
  apply (sq_le_sq₀
    (div_nonneg (Finset.sum_nonneg fun coin _ => nonnegative coin)
      cardPositive.le)
    (Real.sqrt_nonneg _)).1
  rw [Real.sq_sqrt lossNonnegative, div_pow]
  apply (div_le_iff₀ (sq_pos_of_pos cardPositive)).2
  calc
    _ ≤ (Fintype.card Coins : ℝ) * ∑ coin, value coin ^ 2 := by
      simpa using sq_sum_le_card_mul_sum_sq
        (s := (Finset.univ : Finset Coins)) (f := value)
    _ ≤ (Fintype.card Coins : ℝ) *
          (loss * Fintype.card Coins) :=
      mul_le_mul_of_nonneg_left sumBound cardPositive.le
    _ = _ := by ring

/-! ## The total-oracle purification carries the native CMS L2 norm -/

variable {Input Work : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work]

/-- Summing the full final event over every retained database is exactly the
native CMS squared norm. -/
theorem database_born_univ_eq_norm_squared
    (state : ResponseCmsState Input Work) :
    databaseBorn (Finset.univ :
        Finset (QueryBasis Input DigestRegister Work)) state =
      normSquared state := by
  let reindex :
      (Database Input DigestRegister ×
          QueryBasis Input DigestRegister Work) ≃
        HegemonCrypto.CmsCompressedOracle.Basis
          Input DigestRegister DigestRegister Work :=
    { toFun := fun pair =>
        { input := pair.2.1
          phase := pair.2.2.1
          workspace := pair.2.2.2
          database := pair.1 }
      invFun := fun basis =>
        (basis.database, (basis.input, basis.phase, basis.workspace))
      left_inv := by intro pair; cases pair; rfl
      right_inv := by intro basis; cases basis; rfl }
  have eventUniv
      (vector : GameState (Input := Input) (Work := Work)) :
      eventProjection
          (Finset.univ : Finset (QueryBasis Input DigestRegister Work))
          vector = vector := by
    ext basis
    simp [eventProjection]
  unfold databaseBorn born normSquared
  simp_rw [eventUniv, EuclideanSpace.norm_sq_eq]
  rw [← reindex.sum_comp]
  rw [Fintype.sum_prod_type]
  apply Finset.sum_congr rfl
  intro database _
  apply Finset.sum_congr rfl
  intro basis _
  exact Complex.sq_norm _

/-- The L2 norm of an exact total-oracle purification is the uniform average
of the squared norms of its oracle-indexed register vectors. -/
theorem total_oracle_family_norm_squared
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    normSquared (totalOracleFamilyState family) =
      uniformAverage (fun oracle : Input → DigestRegister =>
        ‖familyGameState family oracle‖ ^ 2) := by
  calc
    normSquared (totalOracleFamilyState family) =
        databaseBorn
          (Finset.univ : Finset (QueryBasis Input DigestRegister Work))
          (totalOracleFamilyState family) :=
      (database_born_univ_eq_norm_squared _).symm
    _ = uniformAverage (fun oracle : Input → DigestRegister =>
          born (Finset.univ :
              Finset (QueryBasis Input DigestRegister Work))
            (familyGameState family oracle)) :=
      databaseBorn_totalOracleFamilyState _ family
    _ = uniformAverage (fun oracle : Input → DigestRegister =>
          ‖familyGameState family oracle‖ ^ 2) := by
      apply congrArg uniformAverage
      funext oracle
      unfold born
      have eventUniv :
          eventProjection
              (Finset.univ :
                Finset (QueryBasis Input DigestRegister Work))
              (familyGameState family oracle) =
            familyGameState family oracle := by
        ext basis
        simp [eventProjection]
      rw [eventUniv]

theorem total_oracle_family_state_sub
    (left right : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    totalOracleFamilyState (fun oracle basis =>
        left oracle basis - right oracle basis) =
      totalOracleFamilyState left - totalOracleFamilyState right := by
  funext basis
  unfold totalOracleFamilyState
  simp only [Pi.sub_apply]
  rw [← mul_sub, ← Finset.sum_sub_distrib]
  apply congrArg
  apply Finset.sum_congr rfl
  intro oracle _
  by_cases same : basis.database = totalDatabase oracle
  · simp [same]
  · simp [same]

theorem family_game_state_sub
    (left right : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (oracle : Input → DigestRegister) :
    familyGameState (fun selected basis =>
        left selected basis - right selected basis) oracle =
      familyGameState left oracle - familyGameState right oracle := by
  ext basis
  rfl

theorem total_oracle_family_difference_norm_squared
    (left right : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    normSquared
        (totalOracleFamilyState left - totalOracleFamilyState right) =
      uniformAverage (fun oracle : Input → DigestRegister =>
        ‖familyGameState left oracle - familyGameState right oracle‖ ^ 2) := by
  rw [← total_oracle_family_state_sub]
  rw [total_oracle_family_norm_squared]
  apply congrArg uniformAverage
  funext oracle
  rw [family_game_state_sub]

/-! ## Physical continuation on the persistent database -/

/-- The exact seven-constructor continuation is 2-Lipschitz on normalized
total-oracle purifications.  The proof is the ordinary checked program
continuity on each oracle fiber followed by finite uniform
Cauchy--Schwarz; no QROM reprogramming theorem is used here. -/
theorem database_run_total_family_difference
    (randomized : Bool) (program : Program Input Work)
    (left right : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (leftNormalized :
      normSquared (totalOracleFamilyState left) = 1)
    (rightNormalized :
      normSquared (totalOracleFamilyState right) = 1) :
    |databaseRun randomized program (totalOracleFamilyState left) -
        databaseRun randomized program (totalOracleFamilyState right)| ≤
      2 * Real.sqrt
        (normSquared
          (totalOracleFamilyState left - totalOracleFamilyState right)) := by
  rw [databaseRun_totalOracleFamilyState,
    databaseRun_totalOracleFamilyState]
  apply (average_difference_abs_le _ _).trans
  have pointwise (oracle : Input → DigestRegister) :
      |databaseRun randomized program
            (oracleState oracle (familyGameState left oracle)) -
          databaseRun randomized program
            (oracleState oracle (familyGameState right oracle))| ≤
        (‖familyGameState left oracle‖ +
            ‖familyGameState right oracle‖) *
          ‖familyGameState left oracle -
            familyGameState right oracle‖ := by
    rw [databaseRun_oracleState, databaseRun_oracleState]
    exact run_difference_subnormalized randomized program oracle
      (familyGameState left oracle) (familyGameState right oracle)
  apply (average_mono _ _ pointwise).trans
  have cauchy := uniform_average_mul_le_sqrt_mul_sqrt
    (fun oracle : Input → DigestRegister =>
      ‖familyGameState left oracle‖ + ‖familyGameState right oracle‖)
    (fun oracle : Input → DigestRegister =>
      ‖familyGameState left oracle - familyGameState right oracle‖)
  apply cauchy.trans
  have firstMoment :
      uniformAverage (fun oracle : Input → DigestRegister =>
        (‖familyGameState left oracle‖ +
          ‖familyGameState right oracle‖) ^ 2) ≤ 4 := by
    calc
      _ ≤ uniformAverage (fun oracle : Input → DigestRegister =>
          2 * ‖familyGameState left oracle‖ ^ 2 +
            2 * ‖familyGameState right oracle‖ ^ 2) := by
        apply average_mono
        intro oracle
        nlinarith [sq_nonneg
          (‖familyGameState left oracle‖ -
            ‖familyGameState right oracle‖)]
      _ = 2 * normSquared (totalOracleFamilyState left) +
          2 * normSquared (totalOracleFamilyState right) := by
        rw [average_add, average_mul_left, average_mul_left,
          ← total_oracle_family_norm_squared,
          ← total_oracle_family_norm_squared]
      _ = 4 := by rw [leftNormalized, rightNormalized]; norm_num
  have firstSqrt :
      Real.sqrt (uniformAverage (fun oracle : Input → DigestRegister =>
        (‖familyGameState left oracle‖ +
          ‖familyGameState right oracle‖) ^ 2)) ≤ 2 := by
    have nonnegative : 0 ≤
        uniformAverage (fun oracle : Input → DigestRegister =>
          (‖familyGameState left oracle‖ +
            ‖familyGameState right oracle‖) ^ 2) := by
      exact Finset.sum_nonneg fun oracle _ =>
        mul_nonneg ENNReal.toReal_nonneg (sq_nonneg _)
    nlinarith [Real.sq_sqrt nonnegative, Real.sqrt_nonneg
      (uniformAverage (fun oracle : Input → DigestRegister =>
        (‖familyGameState left oracle‖ +
          ‖familyGameState right oracle‖) ^ 2))]
  rw [← total_oracle_family_difference_norm_squared]
  exact mul_le_mul_of_nonneg_right firstSqrt (Real.sqrt_nonneg _)

/-! ## Mean-square CMS disturbance to whole-view probability -/

/-- A checked mean-square disturbance of normalized total-oracle CMS states
implies a whole-view probability disturbance.  This is the exact hybrid step
used after the full-domain resampling count. -/
theorem total_family_whole_view_hybrid
    {Secret : Type} [Fintype Secret] [Nonempty Secret]
    (randomized : Bool) (program : Program Input Work)
    (left : Secret → ResponseCmsState Input Work)
    (right : ResponseCmsState Input Work)
    (leftFamily : Secret → OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (rightFamily : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (leftRepresentation : ∀ secret,
      left secret = totalOracleFamilyState (leftFamily secret))
    (rightRepresentation :
      right = totalOracleFamilyState rightFamily)
    (leftNormalized : ∀ secret, normSquared (left secret) = 1)
    (rightNormalized : normSquared right = 1)
    (loss : ℝ) (lossNonnegative : 0 ≤ loss)
    (meanSquare : uniformAverage (fun secret =>
      normSquared (left secret - right)) ≤ loss) :
    |uniformAverage (fun secret =>
        databaseRun randomized program (left secret)) -
      databaseRun randomized program right| ≤
      2 * Real.sqrt loss := by
  have constantAverage :
      uniformAverage (fun _ : Secret =>
        databaseRun randomized program right) =
          databaseRun randomized program right := by
    unfold uniformAverage
    rw [← Finset.sum_mul,
      HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition.pmf_real_weights_sum,
      one_mul]
  rw [← constantAverage]
  apply (average_difference_abs_le _ _).trans
  have pointwise (secret : Secret) :
      |databaseRun randomized program (left secret) -
          databaseRun randomized program right| ≤
        2 * Real.sqrt (normSquared (left secret - right)) := by
    rw [leftRepresentation secret, rightRepresentation]
    exact database_run_total_family_difference randomized program
      (leftFamily secret) rightFamily
      (by simpa [leftRepresentation secret] using leftNormalized secret)
      (by simpa [rightRepresentation] using rightNormalized)
  apply (average_mono _ _ pointwise).trans
  rw [average_mul_left]
  apply mul_le_mul_of_nonneg_left _ (by norm_num)
  have squareRootMean := uniform_average_le_sqrt_mean_square
    (fun secret =>
      Real.sqrt (normSquared (left secret - right)))
    (fun _ => Real.sqrt_nonneg _)
    loss lossNonnegative
  apply squareRootMean
  have distanceNonnegative (secret : Secret) :
      0 ≤ normSquared (left secret - right) := by
    unfold normSquared
    exact Finset.sum_nonneg fun basis _ =>
      Complex.normSq_nonneg ((left secret - right) basis)
  simpa only [Real.sq_sqrt (distanceNonnegative _)] using meanSquare

end
end HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewBound
