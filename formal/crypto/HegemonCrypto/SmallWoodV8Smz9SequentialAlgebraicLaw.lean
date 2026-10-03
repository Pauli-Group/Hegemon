import HegemonCrypto.SmallWoodV8Smz9JointAlgebraicLaw

/-!
# SMZ9 fresh mask phase with the earlier prefix retained

The production order in `smallwood_engine.rs` is important: witness interpolation completes,
then five iterations sample 489 nonlinear coefficients and 132 nonconstant linear coefficients,
then `pcs_commit` commits these masks, then `piop_run` and the opening samplers derive challenges.
The existing `alternatingMasksEquiv` is the exact allocation of those 3,105 accepted words.

This file derives a joint law for an arbitrary earlier prefix followed by that fresh ideal mask
phase. Unlike a fixed-prefix equality alone, the prefix itself is retained in the probability
experiment, so arbitrary dependence on earlier history is preserved. Transformations may depend
on that earlier prefix, but never on the same newly sampled coins. The equality is derived from
the rejection-sampler law and explicit affine inverses, not assumed as a simulator premise.

The actual phase is the identity-map, zero-offset specialization. The algebraic hiding maps
depending on PIOP/DECS opening challenges are NOT instantiated here: those challenges are computed
after commitments to these very coins, so the required freshness premise is not yet available.
A checked finite counterexample proves why bijectivity at every fixed challenge is insufficient.
This is neither adaptive transcript privacy nor a bound for OS randomness, commitments, or QROM.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SequentialAlgebraicLaw

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9RuntimeFieldLayout V8Smz9JointAlgebraicLaw
open scoped ENNReal

noncomputable section

local instance : Fintype Goldilocks :=
  Fintype.ofEquiv IdealFieldCoin idealFieldCoinEquivGoldilocks

/-- All independent coefficients sampled by the actual pre-commitment mask loop. -/
abbrev MaskPhaseCoins :=
  NonlinearPiopMaskCoins Goldilocks × LinearPiopMaskCoins Goldilocks

/-- Convert accepted canonical words, then apply the existing exact alternating allocation. -/
def maskPhaseAllocation : RuntimeFieldCoins 3105 ≃ MaskPhaseCoins :=
  (Equiv.piCongrRight fun _ : Fin 3105 => idealFieldCoinEquivGoldilocks).trans
    (alternatingMasksEquiv Goldilocks)

theorem exact_mask_phase_word_count :
    5 * (489 + 132) = 3105 ∧ 4116 + 3105 = 7221 := by decide

/-- The fresh phase law follows from rejection sampling, not an assumed uniform output. -/
theorem exact_fresh_mask_phase_law :
    pmfMap (iidUniformRejectionSamplerOutputPMF 3105) maskPhaseAllocation =
      uniformFintypePMF MaskPhaseCoins := by
  rw [iid_uniform_rejection_output_vector_uniform]
  exact uniform_pmf_map_equiv maskPhaseAllocation

/-- Preserve a possibly nonuniform prefix and sample new words after that prefix. -/
def prefixAndFreshPhase {Prior Output : Type*}
    (prefixLaw : PMF Prior) (output : Prior → MaskPhaseCoins → Output) :
    PMF (Prior × Output) :=
  prefixLaw.bind fun prior =>
    pmfMap (iidUniformRejectionSamplerOutputPMF 3105)
      (fun words => (prior, output prior (maskPhaseAllocation words)))

/--
The exact pre-PCS runtime mask allocation has its uniform law jointly with every earlier prefix.
The fresh product is part of the defined ideal experiment; nothing identifies `getrandom` with it.
-/
theorem mask_phase_preserves_prior_joint_law {Prior : Type*} (prefixLaw : PMF Prior) :
    prefixAndFreshPhase prefixLaw (fun _ coins => coins) =
      prefixLaw.bind (fun prior => pmfMap (uniformFintypePMF MaskPhaseCoins)
        (fun coins => (prior, coins))) := by
  unfold prefixAndFreshPhase
  apply congrArg (PMF.bind prefixLaw)
  funext prior
  change pmfMap (iidUniformRejectionSamplerOutputPMF 3105)
      ((fun coins => (prior, coins)) ∘ maskPhaseAllocation) = _
  rw [← pmfMap_comp, exact_fresh_mask_phase_law]

/--
Maps and offsets chosen from earlier history preserve the complete joint prefix/output law.
There is no premise equating honest and simulated outputs. Coin-dependent maps are excluded by
the order of arguments in the experiment, not silently treated as fixed challenge parameters.
-/
theorem prior_selected_affine_mask_joint_law
    {Prior : Type*} (prefixLaw : PMF Prior)
    (maps : Prior → MaskPhaseCoins ≃+ MaskPhaseCoins)
    (offsets : Prior → MaskPhaseCoins) :
    prefixAndFreshPhase prefixLaw
        (fun prior => transformedAffineView (maps prior) (offsets prior)) =
      prefixLaw.bind (fun prior => pmfMap (uniformFintypePMF MaskPhaseCoins)
        (fun output => (prior, output))) := by
  unfold prefixAndFreshPhase
  apply congrArg (PMF.bind prefixLaw)
  funext prior
  change pmfMap (iidUniformRejectionSamplerOutputPMF 3105)
      ((fun output => (prior, output)) ∘
        ((affineOutputEquiv (maps prior) (offsets prior)) ∘ maskPhaseAllocation)) = _
  rw [← pmfMap_comp, ← pmfMap_comp, exact_fresh_mask_phase_law]
  rw [uniform_pmf_map_equiv (affineOutputEquiv (maps prior) (offsets prior))]

/-- Different prefix-dependent offsets have identical JOINT laws, not just equal marginals. -/
theorem prior_selected_offsets_do_not_change_joint_law
    {Prior : Type*} (prefixLaw : PMF Prior)
    (maps : Prior → MaskPhaseCoins ≃+ MaskPhaseCoins)
    (left right : Prior → MaskPhaseCoins) :
    prefixAndFreshPhase prefixLaw
        (fun prior => transformedAffineView (maps prior) (left prior)) =
      prefixAndFreshPhase prefixLaw
        (fun prior => transformedAffineView (maps prior) (right prior)) :=
  (prior_selected_affine_mask_joint_law prefixLaw maps left).trans
    (prior_selected_affine_mask_joint_law prefixLaw maps right).symm

/-- Any subsequent operation using only the retained prefix and output preserves that equality. -/
theorem prefix_output_continuation_preserves_law
    {Prior Result : Type*} (prefixLaw : PMF Prior)
    (maps : Prior → MaskPhaseCoins ≃+ MaskPhaseCoins)
    (left right : Prior → MaskPhaseCoins)
    (continuation : Prior × MaskPhaseCoins → PMF Result) :
    (prefixAndFreshPhase prefixLaw
        (fun prior => transformedAffineView (maps prior) (left prior))).bind continuation =
      (prefixAndFreshPhase prefixLaw
        (fun prior => transformedAffineView (maps prior) (right prior))).bind continuation := by
  rw [prior_selected_offsets_do_not_change_joint_law prefixLaw maps left right]

/--
Iterate actual fresh phases. Each next prefix is computed from the current prefix and its output;
therefore later maps and offsets see the generated history, not an externally fixed history list.
This is an ideal algebraic experiment, not the within-proof SMZ9 challenge schedule.
-/
def runFreshMaskPhases {Prior : Type*}
    (maps : Prior → MaskPhaseCoins ≃+ MaskPhaseCoins)
    (offsets : Prior → MaskPhaseCoins)
    (advance : Prior × MaskPhaseCoins → Prior) : Nat → PMF Prior → PMF Prior
  | 0, prefixLaw => prefixLaw
  | count + 1, prefixLaw =>
      runFreshMaskPhases maps offsets advance count
        (pmfMap (prefixAndFreshPhase prefixLaw
          (fun prior => transformedAffineView (maps prior) (offsets prior))) advance)

/--
Finite sequential composition with history-dependent choices, proved by induction from the
concrete fresh-mask law. No equality of transition kernels or desired coupling is supplied.
The update must use the preserved prefix/output, not unrevealed coins or the choice of secret.
-/
theorem sequential_fresh_mask_phases_have_same_law
    {Prior : Type*}
    (maps : Prior → MaskPhaseCoins ≃+ MaskPhaseCoins)
    (left right : Prior → MaskPhaseCoins)
    (advance : Prior × MaskPhaseCoins → Prior)
    (count : Nat) (prefixLaw : PMF Prior) :
    runFreshMaskPhases maps left advance count prefixLaw =
      runFreshMaskPhases maps right advance count prefixLaw := by
  induction count generalizing prefixLaw with
  | zero => rfl
  | succ count inductionHypothesis =>
      simp only [runFreshMaskPhases]
      rw [prior_selected_offsets_do_not_change_joint_law prefixLaw maps left right]
      exact inductionHypothesis _

/-! ## Checked obstruction to feeding the same coins back into their challenge -/

/-- Each fixed challenge acts by a bijection on a two-element coin space. -/
def fixedChallengeMap (challenge : ZMod 2) : ZMod 2 ≃ ZMod 2 :=
  affineOutputEquiv (AddEquiv.refl (ZMod 2)) challenge

theorem every_fixed_challenge_is_uniform (challenge : ZMod 2) :
    pmfMap (uniformFintypePMF (ZMod 2)) (fixedChallengeMap challenge) =
      uniformFintypePMF (ZMod 2) :=
  uniform_pmf_map_equiv (fixedChallengeMap challenge)

/-- Choosing the challenge from the same coins can collapse every output to zero. -/
theorem same_coin_challenge_collapses_output :
    pmfMap (uniformFintypePMF (ZMod 2))
        (fun coins => fixedChallengeMap (-coins) coins) = PMF.pure 0 := by
  have output_constant : (fun coins : ZMod 2 => fixedChallengeMap (-coins) coins) =
      (fun _ => 0) := by
    funext coins
    change -coins + coins = 0
    exact neg_add_cancel coins
  rw [output_constant]
  unfold pmfMap
  exact PMF.bind_const _ _

theorem same_coin_challenge_is_not_uniform :
    pmfMap (uniformFintypePMF (ZMod 2))
        (fun coins => fixedChallengeMap (-coins) coins) ≠
      uniformFintypePMF (ZMod 2) := by
  rw [same_coin_challenge_collapses_output]
  intro equality
  have point_mass := congrArg (fun law : PMF (ZMod 2) => law 1) equality
  norm_num [PMF.pure_apply, uniformFintypePMF_apply] at point_mass
  have nonzero : (2 : ℝ≥0∞)⁻¹ ≠ 0 := by simp
  exact nonzero point_mass.symm

end

end HegemonCrypto.SmallWood.V8Smz9SequentialAlgebraicLaw
