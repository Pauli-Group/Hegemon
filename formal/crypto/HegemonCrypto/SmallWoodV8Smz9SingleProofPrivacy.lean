import HegemonCrypto.SmallWoodV8Smz9RuntimeFieldLayout
import HegemonCrypto.SmallWoodV8Smz9RepeatedAlgebraicZk
import HegemonCrypto.SmallWoodV8Smz9JointAlgebraicLaw
import HegemonCrypto.SmallWoodV8Smz9TriangularAlgebraicLaw

/-!
# SMZ9 single-proof privacy: input entropy, triangular LVCS, and a programming obstruction

This file proves simulator-side entropy and an exact later-challenge LVCS algebraic law,
NOT honest/simulated transcript privacy.
The typed simulator samples its last 3,045 accepted field words as five nonlinear high rows
of length 483, followed by five linear high rows of length 126. `poly_restore` retains them;
the degree-six linear correction cannot alter linear coefficients seven and above.
The final input is eight raw digest words followed by five alternating 489/132 coefficient
blocks. All low coefficients and the digest prefix may depend on the high coins: the explicit
high-coordinate projection still gives a left inverse. This avoids treating honest challenges
derived after commitment as independent of the committed masks.

The finite counterexample shows why even fresh conditional input entropy plus a
uniform programmed target does not justify GHHM21 adaptive reprogramming when the input depends
on that target. The final section then proves the actual 240/2,560-word LVCS triangular law,
including the committed-head offset and selector aborts. No quantum-oracle theorem,
Rust execution refinement, concrete-RNG security,
single-proof zero knowledge, repeated security, or production authority is asserted here.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SingleProofPrivacy

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9RepeatedAlgebraicZk
open V8Smz9JointAlgebraicLaw V8Smz9TriangularAlgebraicLaw
open scoped ENNReal BigOperators

noncomputable section

set_option exponentiation.threshold 4096

/-- The actual last two matrix draws: all nonlinear rows, then all linear rows. -/
abbrev SimulatorHighCoins (F : Type*) :=
  (Fin 5 → Fin 483 → F) × (Fin 5 → Fin 126 → F)

abbrev SimulatorLowCoefficients (F : Type*) :=
  (Fin 5 → Fin 6 → F) × (Fin 5 → Fin 6 → F)

def simulatorHighAllocation (F : Type*) :
    (Fin 3045 → F) ≃ SimulatorHighCoins F :=
  (splitEquiv 2415 630 F).trans
    (Equiv.prodCongr (matrixEquiv 5 483 F) (matrixEquiv 5 126 F))

def simulatorAcceptedHighAllocation :
    RuntimeFieldCoins 3045 ≃ SimulatorHighCoins Goldilocks :=
  (Equiv.piCongrRight fun _ : Fin 3045 => idealFieldCoinEquivGoldilocks).trans
    (simulatorHighAllocation Goldilocks)

theorem simulator_high_draw_shape :
    5 * 483 = 2415 ∧ 5 * 126 = 630 ∧ 2415 + 630 = 3045 ∧
      8 + 5 * (489 + 132) = 3113 := by decide

theorem ideal_accepted_simulator_highs_are_jointly_uniform :
    pmfMap (iidUniformRejectionSamplerOutputPMF 3045)
        simulatorAcceptedHighAllocation =
      uniformFintypePMF (SimulatorHighCoins Goldilocks) := by
  rw [iid_uniform_rejection_output_vector_uniform]
  exact uniform_pmf_map_equiv simulatorAcceptedHighAllocation

/-- The low coordinates are reconstructed; the high coordinates are retained verbatim. -/
def simulatorCoefficientTail {F : Type*}
    (low : SimulatorLowCoefficients F) (high : SimulatorHighCoins F) : Fin 3105 → F :=
  (alternatingMasksEquiv F).symm
    ((fun rep => (low.1 rep, high.1 rep)), (fun rep => (low.2 rep, high.2 rep)))

/-- Read precisely the two high slices of each alternating block. -/
def projectSimulatorHighs {F : Type*} (tail : Fin 3105 → F) : SimulatorHighCoins F :=
  ((fun rep => ((alternatingMasksEquiv F tail).1 rep).2),
    (fun rep => ((alternatingMasksEquiv F tail).2 rep).2))

theorem high_projection_is_left_inverse {F : Type*}
    (low : SimulatorLowCoefficients F) (high : SimulatorHighCoins F) :
    projectSimulatorHighs (simulatorCoefficientTail low high) = high := by
  simp [projectSimulatorHighs, simulatorCoefficientTail]

def nonlinearHighInputIndex (rep : Fin 5) (coefficient : Fin 483) : Fin 3105 :=
  finProdFinEquiv (rep, Fin.castAdd 132 (Fin.natAdd 6 coefficient))

def linearHighInputIndex (rep : Fin 5) (coefficient : Fin 126) : Fin 3105 :=
  finProdFinEquiv (rep, Fin.natAdd 489 (Fin.natAdd 6 coefficient))

theorem simulator_high_projection_raw_indices {F : Type*} (tail : Fin 3105 → F)
    (rep : Fin 5) (nonlinear : Fin 483) (linear : Fin 126) :
    (projectSimulatorHighs tail).1 rep nonlinear =
        tail (nonlinearHighInputIndex rep nonlinear) ∧
      (projectSimulatorHighs tail).2 rep linear =
        tail (linearHighInputIndex rep linear) := by
  constructor <;> rfl

theorem simulator_high_input_index_offsets
    (rep : Fin 5) (nonlinear : Fin 483) (linear : Fin 126) :
    8 + (nonlinearHighInputIndex rep nonlinear).val =
        8 + 621 * rep.val + 6 + nonlinear.val ∧
      8 + (linearHighInputIndex rep linear).val =
        8 + 621 * rep.val + 495 + linear.val := by
  simp [nonlinearHighInputIndex, linearHighInputIndex, finProdFinEquiv]
  omega

/--
An earlier simulator state can contain its already selected final output and opening challenges.
All computed low words and even the prefix may depend arbitrarily on the fresh high coins.
This is a concrete layout constructor, not an assumed hiding or complete-view property.
-/
def simulatorFinalInput {Prior F : Type*}
    (digestPrefix : Prior → SimulatorHighCoins F → FinalPiopDigestPrefix)
    (low : Prior → SimulatorHighCoins F → SimulatorLowCoefficients F)
    (prior : Prior) (high : SimulatorHighCoins F) :
    FinalPiopDigestPrefix × (Fin 3105 → F) :=
  (digestPrefix prior high, simulatorCoefficientTail (low prior high) high)

theorem simulator_final_input_injective_in_last_coins
    {Prior F : Type*}
    (digestPrefix : Prior → SimulatorHighCoins F → FinalPiopDigestPrefix)
    (low : Prior → SimulatorHighCoins F → SimulatorLowCoefficients F)
    (prior : Prior) : Function.Injective (simulatorFinalInput digestPrefix low prior) := by
  intro left right same
  have projection := congrArg (fun input => projectSimulatorHighs input.2) same
  simpa only [simulatorFinalInput, high_projection_is_left_inverse] using projection

theorem exact_simulator_high_coin_space_card :
    Fintype.card (SimulatorHighCoins Goldilocks) = goldilocksModulus ^ 3045 := by
  change Fintype.card ((Fin 5 → Fin 483 → Goldilocks) ×
    (Fin 5 → Fin 126 → Goldilocks)) = _
  simp only [Fintype.card_prod, Fintype.card_fun, Fintype.card_fin, goldilocks_card]
  rw [← pow_mul, ← pow_mul, ← pow_add]

theorem simulator_high_coin_space_supports_512_bits :
    2 ^ 512 ≤ Fintype.card (SimulatorHighCoins Goldilocks) := by
  rw [exact_simulator_high_coin_space_card]
  have base : 2 ^ 63 ≤ goldilocksModulus := by norm_num [goldilocksModulus]
  calc
    2 ^ 512 ≤ 2 ^ (63 * 9) := Nat.pow_le_pow_right (by omega) (by omega)
    _ = (2 ^ 63) ^ 9 := by rw [pow_mul]
    _ ≤ goldilocksModulus ^ 9 := Nat.pow_le_pow_left base 9
    _ ≤ goldilocksModulus ^ 3045 := Nat.pow_le_pow_right
      (by norm_num [goldilocksModulus]) (by omega)

/--
Finite-fiber entropy of the simulator input with fresh last-stage ideal coins. This does NOT
condition on a later observation depending on these coins, and is NOT quantum min-entropy.
Injective byte encoding preserves the result; identifying the Rust encoder is separate.
-/
theorem simulator_final_input_has_512_bits_fresh_conditional_entropy
    {Prior Input : Type*}
    (digestPrefix : Prior → SimulatorHighCoins Goldilocks → FinalPiopDigestPrefix)
    (low : Prior → SimulatorHighCoins Goldilocks → SimulatorLowCoefficients Goldilocks)
    (encode : FinalPiopDigestPrefix × (Fin 3105 → Goldilocks) → Input)
    (encodeInjective : Function.Injective encode) :
    UniformConditionalMinEntropyAtLeast Prior (SimulatorHighCoins Goldilocks) Input
      (fun prior high => encode (simulatorFinalInput digestPrefix low prior high)) 512 := by
  apply uniform_conditional_min_entropy_of_injective _ 512
    simulator_high_coin_space_supports_512_bits
  intro prior
  exact encodeInjective.comp (simulator_final_input_injective_in_last_coins digestPrefix low prior)

/-! ## Why input entropy alone cannot justify target-first programming -/

/-- Input contains a fresh arbitrary-length nonce and the earlier chosen uniform target bit. -/
def targetFirstInput {Nonce : Type*} (target : Bool) (nonce : Nonce) : Nonce × Bool :=
  (nonce, target)

/-- Even fixing the earlier target, the input retains ALL nonce entropy. -/
theorem target_first_input_retains_nonce_entropy
    {Nonce : Type*} [Fintype Nonce] (bits : Nat)
    (enoughNonces : 2 ^ bits ≤ Fintype.card Nonce) :
    UniformConditionalMinEntropyAtLeast Bool Nonce (Nonce × Bool)
      targetFirstInput bits := by
  apply uniform_conditional_min_entropy_of_injective _ bits enoughNonces
  intro target left right same
  exact (Prod.mk.inj same).1

/--
One classical query after receiving x=(nonce,target). In the unchanged random-oracle game,
the sole queried response is a fresh independent bit (lazy sampling, no earlier queries).
In the programmed game H(x)=target. The distinguisher compares that response with x.2.
The two independent bits below are the uniform target and the unchanged oracle response.
-/
def targetFirstOneQueryAccept (programmed : Bool) (coins : Bool × Bool) : Bool :=
  decide ((if programmed then coins.1 else coins.2) = coins.1)

def targetFirstOneQueryGame (programmed : Bool) : PMF Bool :=
  pmfMap (uniformFintypePMF (Bool × Bool)) (targetFirstOneQueryAccept programmed)

theorem unchanged_one_query_acceptance :
    targetFirstOneQueryGame false true = (2 : ℝ≥0∞)⁻¹ := by
  rw [targetFirstOneQueryGame, pmfMap_apply, tsum_fintype]
  simp [targetFirstOneQueryAccept, uniformFintypePMF_apply, Fintype.sum_prod_type]
  have four : (4 : ℝ≥0∞) = 2 * 2 := by norm_num
  rw [four, ENNReal.mul_inv (by simp) (by simp), ← mul_assoc,
    ENNReal.mul_inv_cancel (by simp) (by simp), one_mul]

theorem programmed_one_query_acceptance :
    targetFirstOneQueryGame true true = 1 := by
  rw [targetFirstOneQueryGame, pmfMap_apply, tsum_fintype]
  simp [targetFirstOneQueryAccept, uniformFintypePMF_apply]
  exact ENNReal.mul_inv_cancel (by simp) (by simp)

/-- Arbitrarily large conditional nonce entropy coexists with a one-query advantage of 1/2. -/
theorem target_first_games_are_distinct :
    targetFirstOneQueryGame false ≠ targetFirstOneQueryGame true := by
  intro same
  have equalMass := congrFun (congrArg DFunLike.coe same) true
  rw [unchanged_one_query_acceptance, programmed_one_query_acceptance] at equalMass
  norm_num at equalMass

/-! ## The actual LVCS later-challenge triangular block

`lvcs_open` first computes combination tails, hashes those together with earlier heads and
`h_piop`, and only then evaluates 128 remaining rows at the resulting DECS targets. The first
coordinate below has no target parameter. This is dataflow independence, NOT probabilistic
independence of that coordinate and its derived challenge. The latter are generally correlated.

The head offset is included explicitly: rotation moves the twenty random tail values to
interpolation nodes 0..19 and the 368 committed head values to nodes 20..387. This gives the
exact full subset interpolation, rather than forgetting its target-dependent affine term.
Admissibility remains explicit, and the caller still must justify earlier points/heads and the
fresh tail law in the honest commitment hybrid. This block closes later-target feedback only.
-/

abbrev LvcsEarlierTails (F : Type*) :=
  Fin lvcsOpenedCombinationCount → Fin decsOpeningCount → F

abbrev LvcsLaterSubset (F : Type*) :=
  Fin decsOpeningCount → Fin lvcsSubsetRowCount → F

abbrev LvcsCommittedHeads (F : Type*) :=
  Fin lvcsRowCount → Fin proofGeometryColumns → F

def lvcsEarlierOutput {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) (tails : LvcsRandomTailCoins F) :
    LvcsEarlierTails F :=
  fun combination tail =>
    smz9LvcsSelectedTailMap points tails combination tail +
      smz9LvcsSubsetCombinationContribution points tails combination tail

def lvcsRowPartition :
    (Fin lvcsOpenedCombinationCount ⊕ Fin lvcsSubsetRowCount) → Fin lvcsRowCount :=
  Sum.elim smz9LvcsSelectedRow smz9LvcsSubsetRow

theorem lvcs_row_partition_surjective : Function.Surjective lvcsRowPartition := by
  intro row
  rcases every_lvcs_row_is_selected_or_subset row with
    ⟨selected, selectedExact⟩ | ⟨subset, subsetExact⟩
  · exact ⟨Sum.inl selected, selectedExact⟩
  · exact ⟨Sum.inr subset, subsetExact⟩

/-- The explicit selected/complement enumeration visits every physical row exactly once. -/
def lvcsRowPartitionEquiv :
    (Fin lvcsOpenedCombinationCount ⊕ Fin lvcsSubsetRowCount) ≃ Fin lvcsRowCount :=
  Equiv.ofBijective lvcsRowPartition
    ((Fintype.bijective_iff_surjective_and_card lvcsRowPartition).2
      ⟨lvcs_row_partition_surjective, by
        exact Fintype.card_congr
          (finSumFinEquiv : (Fin 12 ⊕ Fin 128) ≃ Fin 140)⟩)

/-- The retained first coordinate is literally Rust's columnwise C-times-tail matrix product. -/
theorem lvcs_earlier_output_is_full_row_matrix_product
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) (tails : LvcsRandomTailCoins F)
    (combination : Fin lvcsOpenedCombinationCount) (tail : Fin decsOpeningCount) :
    lvcsEarlierOutput points tails combination tail =
      ∑ row : Fin lvcsRowCount,
        smz9LvcsCombinationCoefficient points combination row * tails row tail := by
  have partitioned := lvcsRowPartitionEquiv.sum_comp
    (fun row => smz9LvcsCombinationCoefficient points combination row * tails row tail)
  simpa [lvcsEarlierOutput, smz9LvcsSelectedTailMap, smz9LvcsSelectedBlockMap,
    smz9LvcsSubsetCombinationContribution, lvcsRowPartitionEquiv, lvcsRowPartition,
    Fintype.sum_sum_type] using partitioned

theorem exact_lvcs_first_coordinate_has_no_later_target
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (targets : Fin decsOpeningCount → F) (tails : LvcsRandomTailCoins F) :
    (exactLvcsJointTailMap points targets tails).1 = lvcsEarlierOutput points tails := rfl

def lvcsHeadNode (column : Fin proofGeometryColumns) : Fin decsPolynomialCoefficientCount :=
  Fin.natAdd decsOpeningCount column

def lvcsRotatedRow {F : Type*} (heads : LvcsCommittedHeads F)
    (tails : LvcsRandomTailCoins F) (row : Fin lvcsRowCount) :
    Fin decsPolynomialCoefficientCount → F :=
  Fin.append (tails row) (heads row)

/-- The contribution of the previously committed 368-column head to each subset evaluation. -/
def lvcsSubsetHeadContribution {F : Type*} [Field F]
    (heads : LvcsCommittedHeads F) (targets : Fin decsOpeningCount → F) :
    LvcsLaterSubset F :=
  fun opening subset =>
    ∑ column : Fin proofGeometryColumns,
      (Lagrange.basis (Finset.univ : Finset (Fin decsPolynomialCoefficientCount))
        (fun source => (source.val : F)) (lvcsHeadNode column)).eval (targets opening) *
          heads (smz9LvcsSubsetRow subset) column

/-- Direct interpolation at all 388 rotated nodes, before splitting head and tail. -/
def lvcsFullSubsetInterpolation {F : Type*} [Field F]
    (heads : LvcsCommittedHeads F) (tails : LvcsRandomTailCoins F)
    (targets : Fin decsOpeningCount → F) : LvcsLaterSubset F :=
  fun opening subset =>
    ∑ source : Fin decsPolynomialCoefficientCount,
      (Lagrange.basis (Finset.univ : Finset (Fin decsPolynomialCoefficientCount))
        (fun node => (node.val : F)) source).eval (targets opening) *
          lvcsRotatedRow heads tails (smz9LvcsSubsetRow subset) source

theorem full_lvcs_interpolation_splits_at_rotated_tail_boundary
    {F : Type*} [Field F]
    (heads : LvcsCommittedHeads F) (tails : LvcsRandomTailCoins F)
    (points : Fin piopOpeningCount → F) (targets : Fin decsOpeningCount → F) :
    lvcsFullSubsetInterpolation heads tails targets =
      lvcsSubsetHeadContribution heads targets + (exactLvcsJointTailMap points targets tails).2 := by
  funext opening subset
  change (∑ source : Fin (decsOpeningCount + proofGeometryColumns), _) = _
  rw [Fin.sum_univ_add]
  simp only [lvcsRotatedRow, Fin.append_left, Fin.append_right]
  change
    (∑ coordinate : Fin decsOpeningCount,
      smz9LvcsTailLagrangeCoefficient (targets opening) coordinate *
        tails (smz9LvcsSubsetRow subset) coordinate) +
      lvcsSubsetHeadContribution heads targets opening subset = _
  simp only [Pi.add_apply, exactLvcsJointTailMap, smz9LvcsTailEvaluationMap]
  exact add_comm _ _

abbrev LvcsAdmissibleTargets {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) :=
  { targets : Fin decsOpeningCount → F // Smz9LvcsTailAdmissible points targets }

/-- Actual exact tail map plus the actual committed-head interpolation offset. -/
def exactLvcsFullViewEquiv {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : LvcsCommittedHeads F)
    (targets : LvcsAdmissibleTargets points) :
    LvcsRandomTailCoins F ≃ (LvcsEarlierTails F × LvcsLaterSubset F) :=
  affineOutputEquiv (exactLvcsJointTailAddEquiv points targets.val targets.property)
    (0, lvcsSubsetHeadContribution heads targets.val)

theorem exact_lvcs_full_view_retains_earlier_tails
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : LvcsCommittedHeads F)
    (targets : LvcsAdmissibleTargets points) (tails : LvcsRandomTailCoins F) :
    (exactLvcsFullViewEquiv points heads targets tails).1 = lvcsEarlierOutput points tails := by
  change (0 : LvcsEarlierTails F) +
    (exactLvcsJointTailAddEquiv points targets.val targets.property tails).1 = _
  rw [zero_add, exact_lvcs_joint_tail_add_equiv_apply]
  rfl

theorem exact_lvcs_full_view_later_coordinate
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : LvcsCommittedHeads F)
    (targets : LvcsAdmissibleTargets points) (tails : LvcsRandomTailCoins F) :
    (exactLvcsFullViewEquiv points heads targets tails).2 =
      lvcsFullSubsetInterpolation heads tails targets.val := by
  change lvcsSubsetHeadContribution heads targets.val +
    (exactLvcsJointTailAddEquiv points targets.val targets.property tails).2 = _
  rw [exact_lvcs_joint_tail_add_equiv_apply]
  exact (full_lvcs_interpolation_splits_at_rotated_tail_boundary
    heads tails points targets.val).symm

/-- The challenge is genuinely computed from these same coins' earlier 240 output words. -/
def exactLvcsChallengeFeedbackEquiv {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : LvcsCommittedHeads F)
    (chooseTargets : LvcsEarlierTails F → LvcsAdmissibleTargets points) :
    LvcsRandomTailCoins F ≃ (LvcsEarlierTails F × LvcsLaterSubset F) :=
  triangularChallengeEquiv (exactLvcsFullViewEquiv points heads)
    (lvcsEarlierOutput points) (exact_lvcs_full_view_retains_earlier_tails points heads)
      chooseTargets

theorem exact_lvcs_feedback_matches_chronological_output
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : LvcsCommittedHeads F)
    (chooseTargets : LvcsEarlierTails F → LvcsAdmissibleTargets points)
    (tails : LvcsRandomTailCoins F) :
    exactLvcsChallengeFeedbackEquiv points heads chooseTargets tails =
      (lvcsEarlierOutput points tails,
        lvcsFullSubsetInterpolation heads tails
          (chooseTargets (lvcsEarlierOutput points tails)).val) := by
  change exactLvcsFullViewEquiv points heads
    (chooseTargets (lvcsEarlierOutput points tails)) tails = _
  apply Prod.ext
  · exact exact_lvcs_full_view_retains_earlier_tails points heads _ tails
  · exact exact_lvcs_full_view_later_coordinate points heads _ tails

/-- All 2,800 output words remain jointly uniform with this later-challenge feedback. -/
theorem exact_lvcs_feedback_joint_uniform_law
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : LvcsCommittedHeads F)
    (chooseTargets : LvcsEarlierTails F → LvcsAdmissibleTargets points) :
    pmfMap (uniformFintypePMF (LvcsRandomTailCoins F))
      (fun tails =>
        (lvcsEarlierOutput points tails,
          lvcsFullSubsetInterpolation heads tails
            (chooseTargets (lvcsEarlierOutput points tails)).val)) =
      uniformFintypePMF (LvcsEarlierTails F × LvcsLaterSubset F) := by
  have sameFunction :
      (fun tails =>
        (lvcsEarlierOutput points tails,
          lvcsFullSubsetInterpolation heads tails
            (chooseTargets (lvcsEarlierOutput points tails)).val)) =
        exactLvcsChallengeFeedbackEquiv points heads chooseTargets := by
    funext tails
    exact (exact_lvcs_feedback_matches_chronological_output points heads chooseTargets tails).symm
  rw [sameFunction]
  exact uniform_pmf_map_equiv (exactLvcsChallengeFeedbackEquiv points heads chooseTargets)

theorem exact_lvcs_feedback_word_counts :
    lvcsOpenedCombinationCount * decsOpeningCount = 240 ∧
      decsOpeningCount * lvcsSubsetRowCount = 2560 ∧
      lvcsRowCount * decsOpeningCount = 2800 := by decide

/-- The fixed DECS sampler can exhaust its candidate pool. Preserve that branch explicitly. -/
def exactLvcsPartialFeedbackOutput {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) (heads : LvcsCommittedHeads F)
    (chooseTargets : LvcsEarlierTails F → Option (LvcsAdmissibleTargets points))
    (tails : LvcsRandomTailCoins F) : LvcsEarlierTails F × Option (LvcsLaterSubset F) :=
  let early := lvcsEarlierOutput points tails
  (early, (chooseTargets early).map fun targets =>
    lvcsFullSubsetInterpolation heads tails targets.val)

/--
The law includes failure, rather than asserting that conditioning on success is free. The
fallback is only used to construct a bijection on the discarded failure branch; it is never
exposed by either output. The selector may implement any deterministic hash/sampler at fixed
earlier public inputs, provided its successful targets satisfy the stated admissibility.
-/
theorem exact_lvcs_partial_feedback_joint_law
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F) (heads : LvcsCommittedHeads F)
    (fallback : LvcsAdmissibleTargets points)
    (chooseTargets : LvcsEarlierTails F → Option (LvcsAdmissibleTargets points)) :
    pmfMap (uniformFintypePMF (LvcsRandomTailCoins F))
        (exactLvcsPartialFeedbackOutput points heads chooseTargets) =
      pmfMap (uniformFintypePMF (LvcsEarlierTails F × LvcsLaterSubset F))
        (fun view => (view.1, (chooseTargets view.1).map fun _ => view.2)) := by
  let totalChoose : LvcsEarlierTails F → LvcsAdmissibleTargets points :=
    fun early => (chooseTargets early).getD fallback
  let observe : LvcsEarlierTails F × LvcsLaterSubset F →
      LvcsEarlierTails F × Option (LvcsLaterSubset F) :=
    fun view => (view.1, (chooseTargets view.1).map fun _ => view.2)
  have uniform := exact_lvcs_feedback_joint_uniform_law points heads totalChoose
  have pushed := congrArg (fun law => pmfMap law observe) uniform
  rw [pmfMap_comp] at pushed
  have sameFunction :
      observe ∘ (fun tails =>
        (lvcsEarlierOutput points tails,
          lvcsFullSubsetInterpolation heads tails
            (totalChoose (lvcsEarlierOutput points tails)).val)) =
        exactLvcsPartialFeedbackOutput points heads chooseTargets := by
    funext tails
    cases selected : chooseTargets (lvcsEarlierOutput points tails) with
    | none => simp [observe, exactLvcsPartialFeedbackOutput, selected]
    | some targets =>
      simp [observe, exactLvcsPartialFeedbackOutput,
        totalChoose, selected]
  rw [sameFunction] at pushed
  exact pushed

/--
Different committed row heads have the same complete local law for the same earlier public
inputs and the same selector, including aborts. Public combination heads and h_piop used by
that selector must already be matched; changing them is outside this theorem.
-/
theorem exact_lvcs_partial_feedback_hides_head_offsets
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F)
    (leftHeads rightHeads : LvcsCommittedHeads F)
    (fallback : LvcsAdmissibleTargets points)
    (chooseTargets : LvcsEarlierTails F → Option (LvcsAdmissibleTargets points)) :
    pmfMap (uniformFintypePMF (LvcsRandomTailCoins F))
        (exactLvcsPartialFeedbackOutput points leftHeads chooseTargets) =
      pmfMap (uniformFintypePMF (LvcsRandomTailCoins F))
        (exactLvcsPartialFeedbackOutput points rightHeads chooseTargets) :=
  (exact_lvcs_partial_feedback_joint_law points leftHeads fallback chooseTargets).trans
    (exact_lvcs_partial_feedback_joint_law points rightHeads fallback chooseTargets).symm

/-- Public combination heads use the same matrix, but only the 368 previously fixed columns. -/
def lvcsPublicCombinationHeads {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F) (heads : LvcsCommittedHeads F) :
    Fin lvcsOpenedCombinationCount → Fin proofGeometryColumns → F :=
  fun combination column =>
    ∑ row : Fin lvcsRowCount,
      smz9LvcsCombinationCoefficient points combination row * heads row column

theorem exact_lvcs_partial_feedback_hides_heads_with_same_public_combinations
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F)
    (leftHeads rightHeads : LvcsCommittedHeads F)
    (samePublicHeads : lvcsPublicCombinationHeads points leftHeads =
      lvcsPublicCombinationHeads points rightHeads)
    (fallback : LvcsAdmissibleTargets points)
    (chooseTargets : (Fin lvcsOpenedCombinationCount → Fin proofGeometryColumns → F) →
      LvcsEarlierTails F → Option (LvcsAdmissibleTargets points)) :
    pmfMap (uniformFintypePMF (LvcsRandomTailCoins F))
        (exactLvcsPartialFeedbackOutput points leftHeads
          (chooseTargets (lvcsPublicCombinationHeads points leftHeads))) =
      pmfMap (uniformFintypePMF (LvcsRandomTailCoins F))
        (exactLvcsPartialFeedbackOutput points rightHeads
          (chooseTargets (lvcsPublicCombinationHeads points rightHeads))) := by
  rw [samePublicHeads]
  exact exact_lvcs_partial_feedback_hides_head_offsets points leftHeads rightHeads fallback _

/-- Allocation of the ideal accepted tail words to the actual 140-by-20 row loop. -/
def acceptedLvcsTailAllocation : RuntimeFieldCoins 2800 ≃ LvcsRandomTailCoins Goldilocks :=
  (Equiv.piCongrRight fun _ : Fin 2800 => idealFieldCoinEquivGoldilocks).trans
    (matrixEquiv lvcsRowCount decsOpeningCount Goldilocks)

theorem ideal_accepted_lvcs_tails_are_jointly_uniform :
    pmfMap (iidUniformRejectionSamplerOutputPMF 2800) acceptedLvcsTailAllocation =
      uniformFintypePMF (LvcsRandomTailCoins Goldilocks) := by
  rw [iid_uniform_rejection_output_vector_uniform]
  exact uniform_pmf_map_equiv acceptedLvcsTailAllocation

/-- The feedback/abort law starts from the proved ideal rejection sampler, not a uniform premise. -/
theorem exact_ideal_sampler_lvcs_partial_feedback_law
    (points : Fin piopOpeningCount → Goldilocks) (heads : LvcsCommittedHeads Goldilocks)
    (fallback : LvcsAdmissibleTargets points)
    (chooseTargets : LvcsEarlierTails Goldilocks → Option (LvcsAdmissibleTargets points)) :
    pmfMap (iidUniformRejectionSamplerOutputPMF 2800)
        ((exactLvcsPartialFeedbackOutput points heads chooseTargets) ∘ acceptedLvcsTailAllocation) =
      pmfMap (uniformFintypePMF (LvcsEarlierTails Goldilocks × LvcsLaterSubset Goldilocks))
        (fun view => (view.1, (chooseTargets view.1).map fun _ => view.2)) := by
  rw [← pmfMap_comp, ideal_accepted_lvcs_tails_are_jointly_uniform]
  exact exact_lvcs_partial_feedback_joint_law points heads fallback chooseTargets

end

end HegemonCrypto.SmallWood.V8Smz9SingleProofPrivacy
