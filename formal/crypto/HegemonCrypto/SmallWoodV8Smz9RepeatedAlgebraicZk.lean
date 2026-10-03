import HegemonCrypto.SmallWoodV8Smz9AdaptiveFiniteAccounting
import HegemonCrypto.SmallWoodV8Smz9ZeroKnowledge

/-!
# Repeated V8/SMZ9 algebraic privacy and final-PIOP entropy

This module lifts the six exact single-proof additive equivalences from
`SmallWoodV8Smz9ZeroKnowledge` to a product of `Fin n` fresh coin spaces.  The maps may vary with
the proof index, so a history-conditioned verifier may select different admissible opening maps
at every interaction.  Uniform sampling from `Fin n -> Coins` is the finite product model for
fresh independent coins; the repeated transport remains a bijection and couples every algebraic
view exactly.

The active final-PIOP SHA-512 input has an eight-raw-word digest prefix followed by the complete
nonlinear and linear PIOP views: 2,445 plus 660 Goldilocks words.  For any fixed prior view, its
fresh affine mask map is injective.  The resulting uniform-fiber theorem gives a conservative
512-bit conditional min-entropy bound (the exact coin space is much larger).  With one final-PIOP
program per generated honest view, `Q = 2^64`, honest programmed exposures included through the
conservative `Q + H < 2^65` ceiling, and the arithmetic specialization
`512 * 4096 = 2,097,152`, the
corresponding GHHM-shaped arithmetic screen is `3 * 2,097,152 / 2^224`, strictly below `2^-201`
and hence below the 128-bit target.  In the exact even-entropy dyadic family, 366 conditional bits
are the minimum; 364 fail, while the byte-aligned minimum is 368.

This is an ideal fresh-coin and exact-layout result, not a deployed QROM theorem.  Refinement of
the executable RNG to fresh conditional coins, injective raw-word serialization, applicability of
the adaptive reprogramming theorem to every prior quantum view, and a concrete SHA-512 QRO
instantiation remain explicit constructor-free premises.  The active full DECS tree additionally
hashes `2^23` taped leaves and `2^23 - 1` internal nodes per proof.  Separate ideal leaf and
internal-node fiber theorems show where 512 conditional bits can come from, and exact lifetime
arithmetic covers every such event.  The executable lazy-tree refinement, internal-node entropy
record/replay is pinned below to its checked-in source-rebuilt vector; RNG-to-independent-uniform
freshness, hidden-subtree entropy propagation, the quantum collision theorem, and concrete
SHA-512 QRO instantiation remain constructor-free.  No production or release authority is
constructed here.
-/

namespace HegemonCrypto
namespace SmallWood
namespace V8Smz9RepeatedAlgebraicZk

open V8Smz9ZeroKnowledge

set_option maxHeartbeats 0
set_option maxRecDepth 100000
set_option exponentiation.threshold 4096

/-! ## Pointwise finite-product couplings -/

/-- Uniform sampling from this full function space is the finite product model for `n` fresh,
independent copies of `Coins`. -/
abbrev RepeatedFreshCoins (n : Nat) (Coins : Type*) := Fin n -> Coins

theorem repeated_fresh_coin_space_card
    (n : Nat) (Coins : Type*) [Fintype Coins] :
    Fintype.card (RepeatedFreshCoins n Coins) = Fintype.card Coins ^ n := by
  simp [RepeatedFreshCoins]

/-- Pointwise product of index-dependent additive equivalences. -/
noncomputable def repeatedAddEquiv
    {n : Nat} {Coins View : Type*}
    [AddCommGroup Coins] [AddCommGroup View]
    (maps : Fin n -> Coins ≃+ View) :
    RepeatedFreshCoins n Coins ≃+ RepeatedFreshCoins n View where
  toFun coins index := maps index (coins index)
  invFun view index := (maps index).symm (view index)
  left_inv coins := by
    funext index
    exact (maps index).symm_apply_apply (coins index)
  right_inv view := by
    funext index
    exact (maps index).apply_symm_apply (view index)
  map_add' left right := by
    funext index
    exact (maps index).map_add (left index) (right index)

/-- Pointwise product of ordinary equivalences. -/
noncomputable def repeatedEquiv
    {n : Nat} {Left Right : Type*}
    (maps : Fin n -> Left ≃ Right) :
    RepeatedFreshCoins n Left ≃ RepeatedFreshCoins n Right where
  toFun left index := maps index (left index)
  invFun right index := (maps index).symm (right index)
  left_inv left := by
    funext index
    exact (maps index).symm_apply_apply (left index)
  right_inv right := by
    funext index
    exact (maps index).apply_symm_apply (right index)

def repeatedTransformedAffineView
    {n : Nat} {Coins View : Type*}
    [AddCommGroup Coins] [AddCommGroup View]
    (maps : Fin n -> Coins ≃+ View)
    (secret : Fin n -> View)
    (coins : RepeatedFreshCoins n Coins) : Fin n -> View :=
  fun index => transformedAffineView (maps index) (secret index) (coins index)

/-- The product coin transport that changes every affine secret while preserving every view. -/
noncomputable def repeatedTransformedAffineCoinsEquiv
    {n : Nat} {Coins View : Type*}
    [AddCommGroup Coins] [AddCommGroup View]
    (maps : Fin n -> Coins ≃+ View)
    (leftSecret rightSecret : Fin n -> View) :
    RepeatedFreshCoins n Coins ≃ RepeatedFreshCoins n Coins :=
  repeatedEquiv (fun index =>
    transformedAffineCoinsEquiv (maps index)
      (leftSecret index) (rightSecret index))

theorem repeated_transformed_affine_views_are_exactly_coupled
    {n : Nat} {Coins View : Type*}
    [AddCommGroup Coins] [AddCommGroup View]
    (maps : Fin n -> Coins ≃+ View)
    (leftSecret rightSecret : Fin n -> View)
    (coins : RepeatedFreshCoins n Coins) :
    repeatedTransformedAffineView maps rightSecret
        (repeatedTransformedAffineCoinsEquiv maps leftSecret rightSecret coins) =
      repeatedTransformedAffineView maps leftSecret coins := by
  funext index
  change transformedAffineView (maps index) (rightSecret index)
      (transformedAffineCoinsEquiv (maps index)
        (leftSecret index) (rightSecret index) (coins index)) =
    transformedAffineView (maps index) (leftSecret index) (coins index)
  exact transformed_affine_views_are_exactly_coupled
    (maps index) (leftSecret index) (rightSecret index) (coins index)

/-- Conditional form of the pointwise product theorem.  `prior index` may be the complete
realized transcript before interaction `index`; after fixing that transcript, every map and
affine secret may depend on it while the current product coordinate remains fresh.  This is the
exact one-step kernel needed by an adaptive hybrid.  Turning the family of kernels into an
interactive probabilistic/QROM theorem remains external. -/
theorem history_conditioned_repeated_transformed_affine_views_are_exactly_coupled
    {n : Nat} {Prior Coins View : Type*}
    [AddCommGroup Coins] [AddCommGroup View]
    (maps : (index : Fin n) -> Prior -> Coins ≃+ View)
    (leftSecret rightSecret : (index : Fin n) -> Prior -> View)
    (prior : Fin n -> Prior)
    (coins : RepeatedFreshCoins n Coins) :
    repeatedTransformedAffineView
        (fun index => maps index (prior index))
        (fun index => rightSecret index (prior index))
        (repeatedTransformedAffineCoinsEquiv
          (fun index => maps index (prior index))
          (fun index => leftSecret index (prior index))
          (fun index => rightSecret index (prior index)) coins) =
      repeatedTransformedAffineView
        (fun index => maps index (prior index))
        (fun index => leftSecret index (prior index)) coins :=
  repeated_transformed_affine_views_are_exactly_coupled
    (fun index => maps index (prior index))
    (fun index => leftSecret index (prior index))
    (fun index => rightSecret index (prior index)) coins

theorem smz9_repeated_witness_opening_views_are_exactly_coupled
    {n : Nat} {F : Type*} [AddCommGroup F]
    (maps : Fin n -> Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret : Fin n -> WitnessOpeningView F)
    (coins : RepeatedFreshCoins n (WitnessInterpolationCoins F)) :
    repeatedTransformedAffineView
        (fun index => (maps index).witnessInterpolationTransform) rightSecret
        (repeatedTransformedAffineCoinsEquiv
          (fun index => (maps index).witnessInterpolationTransform)
          leftSecret rightSecret coins) =
      repeatedTransformedAffineView
        (fun index => (maps index).witnessInterpolationTransform) leftSecret coins :=
  repeated_transformed_affine_views_are_exactly_coupled
    (fun index => (maps index).witnessInterpolationTransform) leftSecret rightSecret coins

theorem smz9_repeated_pcs_partial_evaluation_views_are_exactly_coupled
    {n : Nat} {F : Type*} [AddCommGroup F]
    (maps : Fin n -> Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret : Fin n -> PcsPartialEvaluationView F)
    (coins : RepeatedFreshCoins n (PcsUnstackCoins F)) :
    repeatedTransformedAffineView
        (fun index => (maps index).pcsUnstackTransform) rightSecret
        (repeatedTransformedAffineCoinsEquiv
          (fun index => (maps index).pcsUnstackTransform)
          leftSecret rightSecret coins) =
      repeatedTransformedAffineView
        (fun index => (maps index).pcsUnstackTransform) leftSecret coins :=
  repeated_transformed_affine_views_are_exactly_coupled
    (fun index => (maps index).pcsUnstackTransform) leftSecret rightSecret coins

theorem smz9_repeated_nonlinear_piop_views_are_exactly_coupled
    {n : Nat} {F : Type*} [AddCommGroup F]
    (maps : Fin n -> Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret : Fin n -> NonlinearPiopView F)
    (coins : RepeatedFreshCoins n (NonlinearPiopMaskCoins F)) :
    repeatedTransformedAffineView
        (fun index => (maps index).nonlinearPiopTransform) rightSecret
        (repeatedTransformedAffineCoinsEquiv
          (fun index => (maps index).nonlinearPiopTransform)
          leftSecret rightSecret coins) =
      repeatedTransformedAffineView
        (fun index => (maps index).nonlinearPiopTransform) leftSecret coins :=
  repeated_transformed_affine_views_are_exactly_coupled
    (fun index => (maps index).nonlinearPiopTransform) leftSecret rightSecret coins

theorem smz9_repeated_linear_piop_views_are_exactly_coupled
    {n : Nat} {F : Type*} [AddCommGroup F]
    (maps : Fin n -> Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret : Fin n -> LinearPiopView F)
    (coins : RepeatedFreshCoins n (LinearPiopMaskCoins F)) :
    repeatedTransformedAffineView
        (fun index => (maps index).linearPiopTransform) rightSecret
        (repeatedTransformedAffineCoinsEquiv
          (fun index => (maps index).linearPiopTransform)
          leftSecret rightSecret coins) =
      repeatedTransformedAffineView
        (fun index => (maps index).linearPiopTransform) leftSecret coins :=
  repeated_transformed_affine_views_are_exactly_coupled
    (fun index => (maps index).linearPiopTransform) leftSecret rightSecret coins

theorem smz9_repeated_lvcs_joint_tail_views_are_exactly_coupled
    {n : Nat} {F : Type*} [AddCommGroup F]
    (maps : Fin n -> Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret : Fin n -> LvcsJointTailView F)
    (coins : RepeatedFreshCoins n (LvcsRandomTailCoins F)) :
    repeatedTransformedAffineView
        (fun index => (maps index).lvcsJointTailTransform) rightSecret
        (repeatedTransformedAffineCoinsEquiv
          (fun index => (maps index).lvcsJointTailTransform)
          leftSecret rightSecret coins) =
      repeatedTransformedAffineView
        (fun index => (maps index).lvcsJointTailTransform) leftSecret coins :=
  repeated_transformed_affine_views_are_exactly_coupled
    (fun index => (maps index).lvcsJointTailTransform) leftSecret rightSecret coins

theorem smz9_repeated_decs_evaluation_high_views_are_exactly_coupled
    {n : Nat} {F : Type*} [AddCommGroup F]
    (maps : Fin n -> Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret : Fin n -> DecsEvaluationHighView F)
    (coins : RepeatedFreshCoins n (DecsPolynomialCoins F)) :
    repeatedTransformedAffineView
        (fun index => (maps index).decsEvaluationHighTransform) rightSecret
        (repeatedTransformedAffineCoinsEquiv
          (fun index => (maps index).decsEvaluationHighTransform)
          leftSecret rightSecret coins) =
      repeatedTransformedAffineView
        (fun index => (maps index).decsEvaluationHighTransform) leftSecret coins :=
  repeated_transformed_affine_views_are_exactly_coupled
    (fun index => (maps index).decsEvaluationHighTransform) leftSecret rightSecret coins

/-! ## Exact finite-history instance -/

/-- Arithmetic specialization at the consensus accepted-action cap times the analysis block
window.  It is not, by itself, evidence that this many honest proof views were generated or
observed by the SHA-512 oracle; that exposure premise remains explicit below. -/
def finiteHistoryProofInteractions : Nat :=
  V8Smz9AdaptiveFiniteAccounting.Historical.analysisHistoryProofInteractions

theorem exact_finite_history_proof_interactions :
    finiteHistoryProofInteractions = 2097152 := by
  norm_num [finiteHistoryProofInteractions,
    V8Smz9AdaptiveFiniteAccounting.Historical.analysisHistoryProofInteractions,
    V8Smz9QromAccounting.analysisHistoryProofInteractions,
    V8Smz9QromAccounting.consensusProofActionsPerBlock,
    V8Smz9QromAccounting.analysisHistoryBlocks]

abbrev FiniteHistoryFreshCoins (Coins : Type*) :=
  RepeatedFreshCoins finiteHistoryProofInteractions Coins

theorem finite_history_fresh_coin_space_card
    (Coins : Type*) [Fintype Coins] :
    Fintype.card (FiniteHistoryFreshCoins Coins) =
      Fintype.card Coins ^ 2097152 := by
  rw [repeated_fresh_coin_space_card, exact_finite_history_proof_interactions]

theorem smz9_finite_history_witness_opening_views_are_exactly_coupled
    {F : Type*} [AddCommGroup F]
    (maps : Fin finiteHistoryProofInteractions -> Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret :
      Fin finiteHistoryProofInteractions -> WitnessOpeningView F)
    (coins : FiniteHistoryFreshCoins (WitnessInterpolationCoins F)) :
    repeatedTransformedAffineView
        (fun index => (maps index).witnessInterpolationTransform) rightSecret
        (repeatedTransformedAffineCoinsEquiv
          (fun index => (maps index).witnessInterpolationTransform)
          leftSecret rightSecret coins) =
      repeatedTransformedAffineView
        (fun index => (maps index).witnessInterpolationTransform) leftSecret coins :=
  smz9_repeated_witness_opening_views_are_exactly_coupled
    maps leftSecret rightSecret coins

theorem smz9_finite_history_pcs_partial_evaluation_views_are_exactly_coupled
    {F : Type*} [AddCommGroup F]
    (maps : Fin finiteHistoryProofInteractions -> Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret :
      Fin finiteHistoryProofInteractions -> PcsPartialEvaluationView F)
    (coins : FiniteHistoryFreshCoins (PcsUnstackCoins F)) :
    repeatedTransformedAffineView
        (fun index => (maps index).pcsUnstackTransform) rightSecret
        (repeatedTransformedAffineCoinsEquiv
          (fun index => (maps index).pcsUnstackTransform)
          leftSecret rightSecret coins) =
      repeatedTransformedAffineView
        (fun index => (maps index).pcsUnstackTransform) leftSecret coins :=
  smz9_repeated_pcs_partial_evaluation_views_are_exactly_coupled
    maps leftSecret rightSecret coins

theorem smz9_finite_history_nonlinear_piop_views_are_exactly_coupled
    {F : Type*} [AddCommGroup F]
    (maps : Fin finiteHistoryProofInteractions -> Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret :
      Fin finiteHistoryProofInteractions -> NonlinearPiopView F)
    (coins : FiniteHistoryFreshCoins (NonlinearPiopMaskCoins F)) :
    repeatedTransformedAffineView
        (fun index => (maps index).nonlinearPiopTransform) rightSecret
        (repeatedTransformedAffineCoinsEquiv
          (fun index => (maps index).nonlinearPiopTransform)
          leftSecret rightSecret coins) =
      repeatedTransformedAffineView
        (fun index => (maps index).nonlinearPiopTransform) leftSecret coins :=
  smz9_repeated_nonlinear_piop_views_are_exactly_coupled
    maps leftSecret rightSecret coins

theorem smz9_finite_history_linear_piop_views_are_exactly_coupled
    {F : Type*} [AddCommGroup F]
    (maps : Fin finiteHistoryProofInteractions -> Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret :
      Fin finiteHistoryProofInteractions -> LinearPiopView F)
    (coins : FiniteHistoryFreshCoins (LinearPiopMaskCoins F)) :
    repeatedTransformedAffineView
        (fun index => (maps index).linearPiopTransform) rightSecret
        (repeatedTransformedAffineCoinsEquiv
          (fun index => (maps index).linearPiopTransform)
          leftSecret rightSecret coins) =
      repeatedTransformedAffineView
        (fun index => (maps index).linearPiopTransform) leftSecret coins :=
  smz9_repeated_linear_piop_views_are_exactly_coupled
    maps leftSecret rightSecret coins

theorem smz9_finite_history_lvcs_joint_tail_views_are_exactly_coupled
    {F : Type*} [AddCommGroup F]
    (maps : Fin finiteHistoryProofInteractions -> Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret :
      Fin finiteHistoryProofInteractions -> LvcsJointTailView F)
    (coins : FiniteHistoryFreshCoins (LvcsRandomTailCoins F)) :
    repeatedTransformedAffineView
        (fun index => (maps index).lvcsJointTailTransform) rightSecret
        (repeatedTransformedAffineCoinsEquiv
          (fun index => (maps index).lvcsJointTailTransform)
          leftSecret rightSecret coins) =
      repeatedTransformedAffineView
        (fun index => (maps index).lvcsJointTailTransform) leftSecret coins :=
  smz9_repeated_lvcs_joint_tail_views_are_exactly_coupled
    maps leftSecret rightSecret coins

theorem smz9_finite_history_decs_evaluation_high_views_are_exactly_coupled
    {F : Type*} [AddCommGroup F]
    (maps : Fin finiteHistoryProofInteractions -> Smz9AlgebraicHidingMaps F)
    (leftSecret rightSecret :
      Fin finiteHistoryProofInteractions -> DecsEvaluationHighView F)
    (coins : FiniteHistoryFreshCoins (DecsPolynomialCoins F)) :
    repeatedTransformedAffineView
        (fun index => (maps index).decsEvaluationHighTransform) rightSecret
        (repeatedTransformedAffineCoinsEquiv
          (fun index => (maps index).decsEvaluationHighTransform)
          leftSecret rightSecret coins) =
      repeatedTransformedAffineView
        (fun index => (maps index).decsEvaluationHighTransform) leftSecret coins :=
  smz9_repeated_decs_evaluation_high_views_are_exactly_coupled
    maps leftSecret rightSecret coins

/-! ## Exact final-PIOP input layout and ideal conditional entropy -/

def finalPiopDigestPrefixWords : Nat := 8
def nonlinearPiopRandomViewWords : Nat :=
  nonlinearMaskPolynomialCount * (nonlinearMaskPolynomialDegree + 1)
def linearPiopRandomViewWords : Nat :=
  linearMaskPolynomialCount * linearMaskPolynomialDegree
def finalPiopRandomViewWords : Nat :=
  nonlinearPiopRandomViewWords + linearPiopRandomViewWords
def finalPiopProgrammedInputWords : Nat :=
  finalPiopDigestPrefixWords + finalPiopRandomViewWords

theorem exact_final_piop_programmed_input_word_counts :
    finalPiopDigestPrefixWords = 8 ∧
      nonlinearPiopRandomViewWords = 2445 ∧
      linearPiopRandomViewWords = 660 ∧
      finalPiopRandomViewWords = 3105 ∧
      finalPiopProgrammedInputWords = 3113 := by
  decide

abbrev FinalPiopCoins (F : Type*) :=
  NonlinearPiopMaskCoins F × LinearPiopMaskCoins F
abbrev FinalPiopView (F : Type*) :=
  NonlinearPiopView F × LinearPiopView F
/-- The active Rust `digest_to_words` prefix consists of eight arbitrary little-endian `u64`
words.  They are not Goldilocks field elements. -/
abbrev RawSha512Word := Fin (2 ^ 64)
abbrev FinalPiopDigestPrefix :=
  Fin finalPiopDigestPrefixWords -> RawSha512Word
abbrev FinalPiopProgrammedInput (F : Type*) :=
  FinalPiopDigestPrefix × FinalPiopView F

noncomputable def finalPiopAddEquiv
    {F : Type*} [AddCommGroup F]
    (maps : Smz9AlgebraicHidingMaps F) :
    FinalPiopCoins F ≃+ FinalPiopView F where
  toFun coins :=
    (maps.nonlinearPiopTransform coins.1, maps.linearPiopTransform coins.2)
  invFun view :=
    (maps.nonlinearPiopTransform.symm view.1, maps.linearPiopTransform.symm view.2)
  left_inv coins := by ext <;> simp
  right_inv view := by ext <;> simp
  map_add' left right := by ext <;> simp

noncomputable def finalPiopProgrammedInput
    {F : Type*} [AddCommGroup F]
    (maps : Smz9AlgebraicHidingMaps F)
    (digestPrefix : FinalPiopDigestPrefix)
    (secret : FinalPiopView F)
    (coins : FinalPiopCoins F) : FinalPiopProgrammedInput F :=
  (digestPrefix, transformedAffineView (finalPiopAddEquiv maps) secret coins)

theorem final_piop_programmed_input_is_injective_in_fresh_coins
    {F : Type*} [AddCommGroup F]
    (maps : Smz9AlgebraicHidingMaps F)
    (digestPrefix : FinalPiopDigestPrefix)
    (secret : FinalPiopView F) :
    Function.Injective (finalPiopProgrammedInput maps digestPrefix secret) := by
  intro left right same
  apply (finalPiopAddEquiv maps).injective
  have sameView := congrArg Prod.snd same
  exact add_left_cancel sameView

/-- A finite uniform-fiber statement for conditional min-entropy.  It says that after fixing any
prior view, every exact programmed input has point mass at most `2^-bits` when `Coins` is sampled
uniformly. -/
noncomputable def UniformConditionalMinEntropyAtLeast
    (Prior Coins Input : Type*) [Fintype Coins]
    (sample : Prior -> Coins -> Input) (bits : Nat) : Prop := by
  classical
  exact ∀ prior output,
    2 ^ bits *
        (Finset.univ.filter (fun coins => sample prior coins = output)).card ≤
      Fintype.card Coins

theorem uniform_conditional_min_entropy_of_injective
    {Prior Coins Input : Type*}
    [Fintype Coins]
    (sample : Prior -> Coins -> Input)
    (bits : Nat)
    (cardBound : 2 ^ bits ≤ Fintype.card Coins)
    (injective : ∀ prior, Function.Injective (sample prior)) :
    UniformConditionalMinEntropyAtLeast Prior Coins Input sample bits := by
  classical
  intro prior output
  have fiberCard :
      (Finset.univ.filter (fun coins => sample prior coins = output)).card ≤ 1 := by
    rw [Finset.card_le_one_iff]
    intro left right leftMem rightMem
    apply injective prior
    have leftEq : sample prior left = output := by
      simpa only [Finset.mem_filter, Finset.mem_univ, true_and] using leftMem
    have rightEq : sample prior right = output := by
      simpa only [Finset.mem_filter, Finset.mem_univ, true_and] using rightMem
    exact leftEq.trans rightEq.symm
  calc
    2 ^ bits *
        (Finset.univ.filter (fun coins => sample prior coins = output)).card ≤
        2 ^ bits * 1 := Nat.mul_le_mul_left (2 ^ bits) fiberCard
    _ = 2 ^ bits := Nat.mul_one _
    _ ≤ Fintype.card Coins := cardBound

theorem nonlinear_final_piop_coin_space_card :
    Fintype.card (NonlinearPiopMaskCoins Goldilocks) =
      Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus ^ 2445 := by
  change Fintype.card
    (Fin 5 -> ((Fin 6 -> Goldilocks) × (Fin 483 -> Goldilocks))) = _
  simp only [Fintype.card_fun, Fintype.card_prod, Fintype.card_fin, goldilocks_card]
  rw [← pow_add, ← pow_mul]

theorem linear_final_piop_coin_space_card :
    Fintype.card (LinearPiopMaskCoins Goldilocks) =
      Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus ^ 660 := by
  change Fintype.card
    (Fin 5 -> ((Fin 6 -> Goldilocks) × (Fin 126 -> Goldilocks))) = _
  simp only [Fintype.card_fun, Fintype.card_prod, Fintype.card_fin, goldilocks_card]
  rw [← pow_add, ← pow_mul]

theorem exact_final_piop_coin_space_card :
    Fintype.card (FinalPiopCoins Goldilocks) =
      Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus ^ 3105 := by
  rw [Fintype.card_prod, nonlinear_final_piop_coin_space_card,
    linear_final_piop_coin_space_card, ← pow_add]

theorem final_piop_coin_space_supports_512_bits :
    2 ^ 512 ≤ Fintype.card (FinalPiopCoins Goldilocks) := by
  rw [exact_final_piop_coin_space_card]
  have base :
      2 ^ 63 ≤
        Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus := by
    norm_num [Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus]
  calc
    2 ^ 512 ≤ 2 ^ (63 * 9) := Nat.pow_le_pow_right (by omega) (by omega)
    _ = (2 ^ 63) ^ 9 := by rw [pow_mul]
    _ ≤
        Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus ^ 9 :=
      Nat.pow_le_pow_left base 9
    _ ≤
        Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus ^ 3105 :=
      Nat.pow_le_pow_right
        (by
          norm_num
            [Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus])
        (by omega)

/-- An exact ideal final-input model. `Prior` may contain the complete adaptive history before the
current final-PIOP program.  The map, affine secret, and fixed digest prefix may all depend on that
history; only the current `FinalPiopCoins` remain fresh. -/
structure IdealFinalPiopInputModel (Prior Input : Type*) where
  maps : Prior -> Smz9AlgebraicHidingMaps Goldilocks
  digestPrefix : Prior -> FinalPiopDigestPrefix
  affineSecret : Prior -> FinalPiopView Goldilocks
  encode : FinalPiopProgrammedInput Goldilocks -> Input
  encodeInjective : Function.Injective encode

noncomputable def IdealFinalPiopInputModel.sample
    {Prior Input : Type*}
    (model : IdealFinalPiopInputModel Prior Input)
    (prior : Prior) (coins : FinalPiopCoins Goldilocks) : Input :=
  model.encode
    (finalPiopProgrammedInput (model.maps prior) (model.digestPrefix prior)
      (model.affineSecret prior) coins)

theorem ideal_final_piop_input_has_512_bits_conditional_min_entropy
    {Prior Input : Type*}
    (model : IdealFinalPiopInputModel Prior Input) :
    UniformConditionalMinEntropyAtLeast Prior (FinalPiopCoins Goldilocks) Input
      model.sample 512 := by
  apply uniform_conditional_min_entropy_of_injective
    model.sample 512 final_piop_coin_space_supports_512_bits
  intro prior
  exact model.encodeInjective.comp
    (final_piop_programmed_input_is_injective_in_fresh_coins
      (model.maps prior) (model.digestPrefix prior) (model.affineSecret prior))

/-- The final-PIOP entropy lower bound survives even when the complete eight-word prefix is fixed.
Consequently the active final-PIOP point is not a salt-only entropy model in the ideal algebraic
game: its entropy can come entirely from the fresh nonlinear and linear PIOP masks. -/
noncomputable def fixedPrefixFinalPiopInputModel
    (maps : Smz9AlgebraicHidingMaps Goldilocks)
    (digestPrefix : FinalPiopDigestPrefix)
    (affineSecret : FinalPiopView Goldilocks) :
    IdealFinalPiopInputModel Unit (FinalPiopProgrammedInput Goldilocks) where
  maps _ := maps
  digestPrefix _ := digestPrefix
  affineSecret _ := affineSecret
  encode := id
  encodeInjective := Function.injective_id

theorem fixed_prefix_final_piop_input_has_512_bits_conditional_min_entropy
    (maps : Smz9AlgebraicHidingMaps Goldilocks)
    (digestPrefix : FinalPiopDigestPrefix)
    (affineSecret : FinalPiopView Goldilocks) :
    UniformConditionalMinEntropyAtLeast Unit (FinalPiopCoins Goldilocks)
      (FinalPiopProgrammedInput Goldilocks)
      (fixedPrefixFinalPiopInputModel maps digestPrefix affineSecret).sample 512 :=
  ideal_final_piop_input_has_512_bits_conditional_min_entropy
    (fixedPrefixFinalPiopInputModel maps digestPrefix affineSecret)

/-! ## Active full-tree leaf and internal-node input fibers -/

def sha512DigestBytes : Nat := 64
def activeSmz9SaltBytes : Nat := 32
def smz9MerkleLeafDomainBits : Nat := 23
def smz9MerkleLeafCount : Nat := 2 ^ smz9MerkleLeafDomainBits
def smz9MerkleInternalNodeCount : Nat := smz9MerkleLeafCount - 1
def smz9FullTreeProgramEventsPerProof : Nat :=
  smz9MerkleLeafCount + smz9MerkleInternalNodeCount

theorem exact_smz9_full_tree_event_counts :
    smz9MerkleLeafCount = 8388608 ∧
      smz9MerkleInternalNodeCount = 8388607 ∧
      smz9FullTreeProgramEventsPerProof = 16777215 := by
  decide

abbrev RawByte := Fin 256
/-- Finite-index representation of the active 64-byte string space.  Exact conversion to the
executable byte array is part of the raw-serialization refinement, not silently identified here. -/
abbrev Sha512Digest := Fin (2 ^ 512)
/-- The active strict-ZK DECS tape has exactly the same 64-byte width as a SHA-512 digest. -/
abbrev Smz9LeafTape := Sha512Digest
abbrev Smz9Salt := Fin activeSmz9SaltBytes -> RawByte
abbrev Smz9PerProofLeafTapes := Fin smz9MerkleLeafCount -> Smz9LeafTape

theorem exact_sha512_digest_space_card :
    Fintype.card Sha512Digest = 2 ^ 512 := by
  simp [Sha512Digest]

theorem exact_smz9_leaf_tape_space_card :
    Fintype.card Smz9LeafTape = 2 ^ 512 :=
  exact_sha512_digest_space_card

theorem exact_smz9_per_proof_leaf_tape_product_card :
    Fintype.card Smz9PerProofLeafTapes = (2 ^ 512) ^ 8388608 := by
  rw [Fintype.card_fun, exact_smz9_leaf_tape_space_card]
  norm_num [smz9MerkleLeafCount, smz9MerkleLeafDomainBits]

abbrev Smz9FiniteHistoryLeafTapes :=
  FiniteHistoryFreshCoins Smz9PerProofLeafTapes

theorem exact_smz9_finite_history_leaf_tape_product_card :
    Fintype.card Smz9FiniteHistoryLeafTapes =
      ((2 ^ 512) ^ 8388608) ^ 2097152 := by
  rw [finite_history_fresh_coin_space_card,
    exact_smz9_per_proof_leaf_tape_product_card]

/-- Semantic fields absorbed by the active strict-ZK leaf hash, in source order.  The executable
serialization also frames lengths and role domains; connecting this record to the exact byte
string is an external injective-serialization refinement below. -/
structure StrictZkMerkleLeafInput where
  salt : Smz9Salt
  leafIndex : RawSha512Word
  tape : Smz9LeafTape
  committedEvaluations : List RawSha512Word
  maskingEvaluations : List RawSha512Word

def strictZkMerkleLeafInput
    (salt : Smz9Salt)
    (leafIndex : RawSha512Word)
    (committedEvaluations maskingEvaluations : List RawSha512Word)
    (tape : Smz9LeafTape) : StrictZkMerkleLeafInput where
  salt := salt
  leafIndex := leafIndex
  tape := tape
  committedEvaluations := committedEvaluations
  maskingEvaluations := maskingEvaluations

theorem strict_zk_merkle_leaf_input_is_injective_in_tape
    (salt : Smz9Salt)
    (leafIndex : RawSha512Word)
    (committedEvaluations maskingEvaluations : List RawSha512Word) :
    Function.Injective
      (strictZkMerkleLeafInput salt leafIndex committedEvaluations maskingEvaluations) := by
  intro left right same
  exact congrArg StrictZkMerkleLeafInput.tape same

/-- An arbitrary adaptive prior may fix the salt, leaf index, committed evaluations, and masking
evaluations.  The ideal leaf kernel keeps the current 64-byte tape fresh. -/
structure IdealMerkleLeafInputModel (Prior Input : Type*) where
  salt : Prior -> Smz9Salt
  leafIndex : Prior -> RawSha512Word
  committedEvaluations : Prior -> List RawSha512Word
  maskingEvaluations : Prior -> List RawSha512Word
  encode : StrictZkMerkleLeafInput -> Input
  encodeInjective : Function.Injective encode

def IdealMerkleLeafInputModel.sample
    {Prior Input : Type*}
    (model : IdealMerkleLeafInputModel Prior Input)
    (prior : Prior) (tape : Smz9LeafTape) : Input :=
  model.encode
    (strictZkMerkleLeafInput (model.salt prior) (model.leafIndex prior)
      (model.committedEvaluations prior) (model.maskingEvaluations prior) tape)

theorem ideal_smz9_merkle_leaf_input_has_512_bits_conditional_min_entropy
    {Prior Input : Type*}
    (model : IdealMerkleLeafInputModel Prior Input) :
    UniformConditionalMinEntropyAtLeast Prior Smz9LeafTape Input model.sample 512 := by
  apply uniform_conditional_min_entropy_of_injective model.sample 512
  · rw [exact_smz9_leaf_tape_space_card]
  · intro prior
    exact model.encodeInjective.comp
      (strict_zk_merkle_leaf_input_is_injective_in_tape
        (model.salt prior) (model.leafIndex prior)
        (model.committedEvaluations prior) (model.maskingEvaluations prior))

/-- The active SHA-512 SMZ9 internal-node request absorbs the left and right 64-byte digests under
the Merkle-node role domain.  Unlike the HX512 candidate path, its raw input does not absorb the
tree level or node index. -/
structure ActiveSha512MerkleNodeInput where
  left : Sha512Digest
  right : Sha512Digest

def activeSha512MerkleNodeInput
    (freshOnLeft : Bool) (fixedChild freshChild : Sha512Digest) :
    ActiveSha512MerkleNodeInput :=
  if freshOnLeft then ⟨freshChild, fixedChild⟩ else ⟨fixedChild, freshChild⟩

theorem active_sha512_merkle_node_input_is_injective_in_one_fresh_child
    (freshOnLeft : Bool) (fixedChild : Sha512Digest) :
    Function.Injective (activeSha512MerkleNodeInput freshOnLeft fixedChild) := by
  cases freshOnLeft <;> intro left right same
  · exact congrArg ActiveSha512MerkleNodeInput.right same
  · exact congrArg ActiveSha512MerkleNodeInput.left same

/-- The wire-neutral lazy simulator record samples both ordered hidden children. -/
abbrev MerkleInternalFreshChildren := Sha512Digest × Sha512Digest

def activeSha512MerkleNodeInputOfFreshChildren
    (children : MerkleInternalFreshChildren) : ActiveSha512MerkleNodeInput :=
  ⟨children.1, children.2⟩

theorem active_sha512_merkle_node_input_is_injective_in_two_fresh_children :
    Function.Injective activeSha512MerkleNodeInputOfFreshChildren := by
  rintro ⟨leftA, rightA⟩ ⟨leftB, rightB⟩ same
  cases same
  rfl

theorem exact_merkle_internal_fresh_children_space_card :
    Fintype.card MerkleInternalFreshChildren = 2 ^ 1024 := by
  rw [Fintype.card_prod, exact_sha512_digest_space_card, ← pow_add]

structure IdealMerkleInternalTwoChildInputModel (Prior Input : Type*) where
  encode : Prior -> ActiveSha512MerkleNodeInput -> Input
  encodeInjective : ∀ prior, Function.Injective (encode prior)

def IdealMerkleInternalTwoChildInputModel.sample
    {Prior Input : Type*}
    (model : IdealMerkleInternalTwoChildInputModel Prior Input)
    (prior : Prior) (children : MerkleInternalFreshChildren) : Input :=
  model.encode prior (activeSha512MerkleNodeInputOfFreshChildren children)

theorem ideal_smz9_merkle_internal_input_has_1024_bits_conditional_min_entropy
    {Prior Input : Type*}
    (model : IdealMerkleInternalTwoChildInputModel Prior Input) :
    UniformConditionalMinEntropyAtLeast Prior MerkleInternalFreshChildren Input
      model.sample 1024 := by
  apply uniform_conditional_min_entropy_of_injective model.sample 1024
  · rw [exact_merkle_internal_fresh_children_space_card]
  · intro prior
    exact (model.encodeInjective prior).comp
      active_sha512_merkle_node_input_is_injective_in_two_fresh_children

/-- This is the exact ideal kernel needed at an internal-node programming point: conditioned on
the adversary's prior view, one ordered child digest remains uniform.  The theorem below proves
the fiber consequence; it does not derive this premise from the executable tree schedule. -/
structure IdealMerkleInternalInputModel (Prior Input : Type*) where
  freshOnLeft : Prior -> Bool
  fixedChild : Prior -> Sha512Digest
  encode : ActiveSha512MerkleNodeInput -> Input
  encodeInjective : Function.Injective encode

def IdealMerkleInternalInputModel.sample
    {Prior Input : Type*}
    (model : IdealMerkleInternalInputModel Prior Input)
    (prior : Prior) (freshChild : Sha512Digest) : Input :=
  model.encode
    (activeSha512MerkleNodeInput (model.freshOnLeft prior)
      (model.fixedChild prior) freshChild)

theorem ideal_smz9_merkle_internal_input_has_512_bits_conditional_min_entropy
    {Prior Input : Type*}
    (model : IdealMerkleInternalInputModel Prior Input) :
    UniformConditionalMinEntropyAtLeast Prior Sha512Digest Input model.sample 512 := by
  apply uniform_conditional_min_entropy_of_injective model.sample 512
  · rw [exact_sha512_digest_space_card]
  · intro prior
    exact model.encodeInjective.comp
      (active_sha512_merkle_node_input_is_injective_in_one_fresh_child
        (model.freshOnLeft prior) (model.fixedChild prior))

/-! ## Exact finite-history programming-loss screen -/

def finalPiopConditionalEntropyBits : Nat := 512
def analysisGlobalQuantumQueryBits : Nat := 64
/-- Honest programmed oracle exposures make `Q + H` exceed `2^64`; the source-backed full-history
count proves it remains below `2^65`.  The adaptive dyadic screens conservatively use this
power-of-two ceiling, while collision accounting below retains the exact `Q + H` count. -/
def analysisTotalOracleStepExponentCeiling : Nat := 65
def strictProgrammingTargetBits : Nat := 128
def minimumEvenGapConditionalEntropyBits : Nat := 366
def minimumByteAlignedConditionalEntropyBits : Nat := 368
def minimumWordAlignedConditionalEntropyBits : Nat := 384

structure DyadicProgrammingScreen where
  numerator : Nat
  denominatorExponent : Nat
deriving DecidableEq, Repr

abbrev DyadicProgrammingScreen.StrictlyBelowBits
    (screen : DyadicProgrammingScreen) (bits : Nat) : Prop :=
  screen.numerator * 2 ^ bits < 2 ^ screen.denominatorExponent

/-- Conservative dyadic upper form of `(3/2) * sqrt((Q + H) * 2^-h) * N`, using
`Q + H < 2^65` and rounding an odd entropy gap down in the denominator. Applicability of that
adaptive-QROM inequality is deliberately external below. -/
def finalPiopHistoryProgrammingScreen (conditionalEntropyBits : Nat) :
    DyadicProgrammingScreen where
  numerator := 3 * finiteHistoryProofInteractions
  denominatorExponent :=
    1 + (conditionalEntropyBits - analysisTotalOracleStepExponentCeiling) / 2

def FinalPiopProgrammingScreenWellFormed (conditionalEntropyBits : Nat) : Prop :=
  analysisTotalOracleStepExponentCeiling < conditionalEntropyBits

theorem exact_final_piop_history_programming_screen :
    finalPiopHistoryProgrammingScreen finalPiopConditionalEntropyBits =
      ⟨6291456, 224⟩ := by
  norm_num [finalPiopHistoryProgrammingScreen, finalPiopConditionalEntropyBits,
    analysisTotalOracleStepExponentCeiling, exact_finite_history_proof_interactions]

theorem final_piop_history_programming_screen_is_well_formed :
    FinalPiopProgrammingScreenWellFormed finalPiopConditionalEntropyBits := by
  norm_num [FinalPiopProgrammingScreenWellFormed, finalPiopConditionalEntropyBits,
    analysisTotalOracleStepExponentCeiling]

theorem final_piop_history_programming_screen_strictly_below_201_bits :
    (finalPiopHistoryProgrammingScreen finalPiopConditionalEntropyBits).StrictlyBelowBits 201 := by
  rw [exact_final_piop_history_programming_screen]
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits]

theorem final_piop_history_programming_screen_not_below_202_bits :
    ¬ (finalPiopHistoryProgrammingScreen finalPiopConditionalEntropyBits).StrictlyBelowBits 202 := by
  rw [exact_final_piop_history_programming_screen]
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits]

theorem final_piop_history_programming_screen_strictly_below_target :
    (finalPiopHistoryProgrammingScreen finalPiopConditionalEntropyBits).StrictlyBelowBits
      strictProgrammingTargetBits := by
  rw [exact_final_piop_history_programming_screen]
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits, strictProgrammingTargetBits]

/-- For the exact history and the conservative `Q + H < 2^65` ceiling, an even entropy bit count
of the form `66 + 2 * halfGap` supports strict 128-bit programming loss exactly when its half-gap
is at least 150. -/
theorem final_piop_even_half_gap_minimum_iff (halfGap : Nat) :
    (finalPiopHistoryProgrammingScreen
      (analysisTotalOracleStepExponentCeiling + 1 + 2 * halfGap)).StrictlyBelowBits
        strictProgrammingTargetBits ↔
      150 ≤ halfGap := by
  rw [show
    finalPiopHistoryProgrammingScreen
        (analysisTotalOracleStepExponentCeiling + 1 + 2 * halfGap) =
      ⟨3 * finiteHistoryProofInteractions, 1 + halfGap⟩ by
    simp [finalPiopHistoryProgrammingScreen, analysisTotalOracleStepExponentCeiling]
    omega]
  constructor
  · intro strict
    by_contra below
    have halfGapLt : halfGap < 150 := Nat.lt_of_not_ge below
    have exponentLe : 2 ^ (1 + halfGap) ≤ 2 ^ 150 :=
      Nat.pow_le_pow_right (by norm_num) (by omega)
    have lower :
        2 ^ 150 ≤
          (3 * finiteHistoryProofInteractions) * 2 ^ strictProgrammingTargetBits := by
      norm_num [strictProgrammingTargetBits, exact_finite_history_proof_interactions]
    exact (not_lt_of_ge lower) (strict.trans_le exponentLe)
  · intro enough
    have baseStrict :
        (3 * finiteHistoryProofInteractions) * 2 ^ strictProgrammingTargetBits <
          2 ^ 151 := by
      norm_num [strictProgrammingTargetBits, exact_finite_history_proof_interactions]
    have exponentGe : 2 ^ 151 ≤ 2 ^ (1 + halfGap) :=
      Nat.pow_le_pow_right (by norm_num) (by omega)
    exact baseStrict.trans_le exponentGe

theorem exact_minimum_even_gap_conditional_entropy :
    analysisTotalOracleStepExponentCeiling + 1 + 2 * 150 =
      minimumEvenGapConditionalEntropyBits := by
  decide

theorem minimum_even_gap_entropy_passes_strict_target :
    (finalPiopHistoryProgrammingScreen minimumEvenGapConditionalEntropyBits).StrictlyBelowBits
      strictProgrammingTargetBits := by
  simpa [minimumEvenGapConditionalEntropyBits, analysisTotalOracleStepExponentCeiling] using
    (final_piop_even_half_gap_minimum_iff 150).2 (by omega)

theorem preceding_even_gap_entropy_fails_strict_target :
    ¬ (finalPiopHistoryProgrammingScreen 364).StrictlyBelowBits
      strictProgrammingTargetBits := by
  simpa [analysisTotalOracleStepExponentCeiling] using
    (not_congr (final_piop_even_half_gap_minimum_iff 149)).2 (by omega)

theorem byte_aligned_minimum_entropy_passes_129_bits :
    (finalPiopHistoryProgrammingScreen minimumByteAlignedConditionalEntropyBits).StrictlyBelowBits
      129 := by
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits,
    finalPiopHistoryProgrammingScreen, minimumByteAlignedConditionalEntropyBits,
    analysisTotalOracleStepExponentCeiling, exact_finite_history_proof_interactions]

/-! A salt-only event is a separate conditional model.  The mathematical minimum is 366 bits,
which rounds to 46 whole bytes and then to 48 bytes under the active core's eight-byte alignment
rule.  This is a 16-byte delta from SMZ9's fixed 32-byte salt, not a 14-byte operational delta.
These facts neither show that any SMZ9 programming event is salt-only nor make widening sufficient
for the whole view. -/

def currentSmz9SaltBytes : Nat := 32
def minimumMathematicalSaltOnlyEntropyBits : Nat :=
  minimumEvenGapConditionalEntropyBits
def minimumWholeByteSaltOnlyBytes : Nat :=
  (minimumMathematicalSaltOnlyEntropyBits + 7) / 8
def activeSaltWordAlignmentBytes : Nat := 8
def minimumWordAlignedSaltOnlyBytes : Nat :=
  ((minimumWholeByteSaltOnlyBytes + activeSaltWordAlignmentBytes - 1) /
    activeSaltWordAlignmentBytes) * activeSaltWordAlignmentBytes
def wordAlignedSaltOnlyDeltaBytes : Nat :=
  minimumWordAlignedSaltOnlyBytes - currentSmz9SaltBytes

theorem exact_salt_only_repair_arithmetic :
    minimumMathematicalSaltOnlyEntropyBits = 366 ∧
      minimumWholeByteSaltOnlyBytes = 46 ∧
      minimumByteAlignedConditionalEntropyBits = 368 ∧
      minimumWordAlignedSaltOnlyBytes = 48 ∧
      minimumWordAlignedConditionalEntropyBits = 384 ∧
      wordAlignedSaltOnlyDeltaBytes = 16 := by
  decide

theorem word_aligned_salt_only_entropy_passes_strict_target :
    (finalPiopHistoryProgrammingScreen minimumWordAlignedConditionalEntropyBits).StrictlyBelowBits
      strictProgrammingTargetBits := by
  simpa [minimumWordAlignedConditionalEntropyBits, analysisTotalOracleStepExponentCeiling] using
    (final_piop_even_half_gap_minimum_iff 159).2 (by omega)

/-! ## Every full-tree event and the strongest source-backed lazy cap -/

def smz9FinalPiopProgramEventsPerProof : Nat := 1
/-- Safe full-tree count: every taped leaf, every internal node, and the final-PIOP point. -/
def smz9AllFullProgrammingEventsPerProof : Nat :=
  smz9FullTreeProgramEventsPerProof + smz9FinalPiopProgramEventsPerProof

def smz9CompactProgrammedMerkleNodeCap : Nat := 372
/-- Joint lazy-program count extracted from the canonical compact-path grammar.  Level-zero
strict-leaf programs are bounded by the 20 opened indices, while the total of level-zero and
internal programs is bounded by the exact split-DP cap 372.  These are joint constraints; 20 and
372 must not be added as independent maxima. -/
structure Smz9LazyProgramCounts where
  strictLeafPrograms : Nat
  internalPrograms : Nat
deriving DecidableEq, Repr

def smz9LazyStrictLeafProgramCap : Nat := 20
def smz9LazyTotalMerkleProgramCap : Nat := 372
def smz9LazyFinalPiopPrograms : Nat := 1
def smz9LazyInternalProgramsAtWeightedCorner : Nat :=
  smz9LazyTotalMerkleProgramCap - smz9LazyStrictLeafProgramCap

abbrev Smz9LazyProgramCounts.Admissible (counts : Smz9LazyProgramCounts) : Prop :=
  counts.strictLeafPrograms ≤ smz9LazyStrictLeafProgramCap ∧
    counts.strictLeafPrograms + counts.internalPrograms ≤ smz9LazyTotalMerkleProgramCap

theorem exact_smz9_lazy_joint_program_caps :
    smz9LazyStrictLeafProgramCap = 20 ∧
      smz9LazyTotalMerkleProgramCap = 372 ∧
      smz9LazyFinalPiopPrograms = 1 ∧
      smz9LazyInternalProgramsAtWeightedCorner = 352 := by
  decide

/-- When a 1024-bit internal-program event has no more loss weight than a 512-bit leaf/final
event, the exact joint envelope is bounded by the corner `21` leaf/final events and `352` internal
events.  This is the formal step that forbids the invalid independent-maxima sum `21 + 372`. -/
theorem smz9_lazy_joint_weighted_corner_bound
    (counts : Smz9LazyProgramCounts)
    (leafFinalWeight internalWeight : Nat)
    (admissible : counts.Admissible)
    (internalWeightLe : internalWeight ≤ leafFinalWeight) :
    (counts.strictLeafPrograms + smz9LazyFinalPiopPrograms) * leafFinalWeight +
        counts.internalPrograms * internalWeight ≤
      (smz9LazyStrictLeafProgramCap + smz9LazyFinalPiopPrograms) * leafFinalWeight +
        smz9LazyInternalProgramsAtWeightedCorner * internalWeight := by
  rcases admissible with ⟨leafLe, totalLe⟩
  norm_num [smz9LazyStrictLeafProgramCap, smz9LazyTotalMerkleProgramCap,
    smz9LazyFinalPiopPrograms, smz9LazyInternalProgramsAtWeightedCorner] at leafLe totalLe ⊢
  have internalLe :
      counts.internalPrograms ≤ 372 - counts.strictLeafPrograms := by
    omega
  have split :
      372 - counts.strictLeafPrograms =
        (20 - counts.strictLeafPrograms) + 352 := by
    omega
  have slackWeight :
      (20 - counts.strictLeafPrograms) * internalWeight ≤
        (20 - counts.strictLeafPrograms) * leafFinalWeight :=
    Nat.mul_le_mul_left _ internalWeightLe
  have leafSum :
      (counts.strictLeafPrograms + 1) +
          (20 - counts.strictLeafPrograms) = 21 := by
    omega
  calc
    (counts.strictLeafPrograms + 1) * leafFinalWeight +
        counts.internalPrograms * internalWeight ≤
      (counts.strictLeafPrograms + 1) * leafFinalWeight +
        (372 - counts.strictLeafPrograms) * internalWeight :=
      Nat.add_le_add_left (Nat.mul_le_mul_right internalWeight internalLe) _
    _ = (counts.strictLeafPrograms + 1) * leafFinalWeight +
        ((20 - counts.strictLeafPrograms) * internalWeight +
          352 * internalWeight) := by
      simpa [Nat.add_mul] using
        congrArg
          (fun value =>
            (counts.strictLeafPrograms + 1) * leafFinalWeight + value * internalWeight)
          split
    _ ≤ (counts.strictLeafPrograms + 1) * leafFinalWeight +
        ((20 - counts.strictLeafPrograms) * leafFinalWeight +
          352 * internalWeight) :=
      Nat.add_le_add_left (Nat.add_le_add_right slackWeight _) _
    _ = 21 * leafFinalWeight + 352 * internalWeight := by
      rw [← Nat.add_assoc, ← Nat.add_mul, leafSum]

/-- The generic-`T` lazy arithmetic uses the same strict exposure exponent
`e(T) = bit_length(2^64 + 2^24 T)` as the source-backed eager accounting.  By
`smz9_lazy_joint_weighted_corner_bound`, every admissible inventory is loss-bounded by the weighted
corner of 20 leaf inputs plus final PIOP at 512 bits and 352 internal inputs at 1024 bits.  The 352
value is not a standalone internal-node cap. -/
def smz9LazyJointProgrammingRatio (totalProofInteractions : Nat) :
    V8Smz9AdaptiveFiniteAccounting.ExactNatRatio :=
  (V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingRatio
      (smz9LazyStrictLeafProgramCap + smz9LazyFinalPiopPrograms) 512
      totalProofInteractions).add
    (V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingRatio
      smz9LazyInternalProgramsAtWeightedCorner 1024 totalProofInteractions)

theorem smz9_lazy_joint_programming_ratio_uses_generic_exposure
    (totalProofInteractions : Nat) :
    smz9LazyJointProgrammingRatio totalProofInteractions =
      (V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingRatio 21 512
        totalProofInteractions).add
      (V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingRatio 352 1024
        totalProofInteractions) := by
  simp [smz9LazyJointProgrammingRatio, smz9LazyStrictLeafProgramCap,
    smz9LazyFinalPiopPrograms, smz9LazyInternalProgramsAtWeightedCorner,
    smz9LazyTotalMerkleProgramCap]

theorem exact_finite_history_total_oracle_exposure_exponent :
    V8Smz9AdaptiveFiniteAccounting.totalOracleExposureExponent
      finiteHistoryProofInteractions = 65 := by
  rw [exact_finite_history_proof_interactions]
  have exposureLog :
      Nat.log 2 (V8Smz9AdaptiveFiniteAccounting.totalOracleExposures 2097152) = 64 := by
    apply Nat.log_eq_of_pow_le_of_lt_pow
    · norm_num [V8Smz9AdaptiveFiniteAccounting.totalOracleExposures,
        V8Smz9AdaptiveFiniteAccounting.honestProgramExposures,
        V8Smz9AdaptiveFiniteAccounting.eagerAllProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.eagerTreeProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.finalPiopProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.Historical.decsDomainSize,
        V8Smz9QromAccounting.decsDomainSize,
        V8Smz9AdaptiveFiniteAccounting.Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
    · norm_num [V8Smz9AdaptiveFiniteAccounting.totalOracleExposures,
        V8Smz9AdaptiveFiniteAccounting.honestProgramExposures,
        V8Smz9AdaptiveFiniteAccounting.eagerAllProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.eagerTreeProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.finalPiopProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.Historical.decsDomainSize,
        V8Smz9QromAccounting.decsDomainSize,
        V8Smz9AdaptiveFiniteAccounting.Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
  unfold V8Smz9AdaptiveFiniteAccounting.totalOracleExposureExponent
  rw [Nat.log2_eq_log_two, exposureLog]

theorem fixed_history_lazy_joint_entropies_are_applicable :
    V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingApplicable
        512 finiteHistoryProofInteractions ∧
      V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingApplicable
        1024 finiteHistoryProofInteractions := by
  change
    V8Smz9AdaptiveFiniteAccounting.totalOracleExposureExponent
          finiteHistoryProofInteractions ≤ 512 ∧
      V8Smz9AdaptiveFiniteAccounting.totalOracleExposureExponent
          finiteHistoryProofInteractions ≤ 1024
  rw [show
    V8Smz9AdaptiveFiniteAccounting.totalOracleExposureExponent
        finiteHistoryProofInteractions = 65 by
      exact exact_finite_history_total_oracle_exposure_exponent]
  norm_num

/-- Under the exact fixed history, the source-derived joint lazy inventory has floors 197 bits
for its 512-bit leaf/final component, 448 bits for its 1024-bit internal component, and 197 bits
for their sum.  Applicability of the adaptive-programming inequality remains external. -/
theorem fixed_history_lazy_joint_programming_bit_floors :
    (V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingRatio
        21 512 finiteHistoryProofInteractions).strictlyBelowBits 197 ∧
      ¬ (V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingRatio
          21 512 finiteHistoryProofInteractions).strictlyBelowBits 198 ∧
      (V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingRatio
          352 1024 finiteHistoryProofInteractions).strictlyBelowBits 448 ∧
      ¬ (V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingRatio
          352 1024 finiteHistoryProofInteractions).strictlyBelowBits 449 ∧
      (smz9LazyJointProgrammingRatio finiteHistoryProofInteractions).strictlyBelowBits 197 ∧
      ¬ (smz9LazyJointProgrammingRatio finiteHistoryProofInteractions).strictlyBelowBits 198 := by
  simp only [smz9LazyJointProgrammingRatio,
    V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingRatio,
    V8Smz9AdaptiveFiniteAccounting.ExactNatRatio.add,
    V8Smz9AdaptiveFiniteAccounting.ExactNatRatio.strictlyBelowBits]
  rw [show
    V8Smz9AdaptiveFiniteAccounting.totalOracleExposureExponent
        finiteHistoryProofInteractions = 65 by
      exact exact_finite_history_total_oracle_exposure_exponent]
  norm_num [smz9LazyStrictLeafProgramCap, smz9LazyFinalPiopPrograms,
    smz9LazyInternalProgramsAtWeightedCorner, smz9LazyTotalMerkleProgramCap,
    exact_finite_history_proof_interactions]

def smz9LazyJointMaximumHonestProofViewsAt128 : Nat :=
  18889465930379069227007

theorem exact_smz9_lazy_joint_maximum_exposure_exponents :
    V8Smz9AdaptiveFiniteAccounting.totalOracleExposureExponent
        smz9LazyJointMaximumHonestProofViewsAt128 = 98 ∧
      V8Smz9AdaptiveFiniteAccounting.totalOracleExposureExponent
        (smz9LazyJointMaximumHonestProofViewsAt128 + 1) = 99 := by
  have maximumLog :
      Nat.log 2 (V8Smz9AdaptiveFiniteAccounting.totalOracleExposures
        smz9LazyJointMaximumHonestProofViewsAt128) = 97 := by
    apply Nat.log_eq_of_pow_le_of_lt_pow
    · norm_num [V8Smz9AdaptiveFiniteAccounting.totalOracleExposures,
        V8Smz9AdaptiveFiniteAccounting.honestProgramExposures,
        V8Smz9AdaptiveFiniteAccounting.eagerAllProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.eagerTreeProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.finalPiopProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.Historical.decsDomainSize,
        V8Smz9AdaptiveFiniteAccounting.Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.decsDomainSize,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent,
        smz9LazyJointMaximumHonestProofViewsAt128]
    · norm_num [V8Smz9AdaptiveFiniteAccounting.totalOracleExposures,
        V8Smz9AdaptiveFiniteAccounting.honestProgramExposures,
        V8Smz9AdaptiveFiniteAccounting.eagerAllProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.eagerTreeProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.finalPiopProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.Historical.decsDomainSize,
        V8Smz9AdaptiveFiniteAccounting.Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.decsDomainSize,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent,
        smz9LazyJointMaximumHonestProofViewsAt128]
  have successorLog :
      Nat.log 2 (V8Smz9AdaptiveFiniteAccounting.totalOracleExposures
        (smz9LazyJointMaximumHonestProofViewsAt128 + 1)) = 98 := by
    apply Nat.log_eq_of_pow_le_of_lt_pow
    · norm_num [V8Smz9AdaptiveFiniteAccounting.totalOracleExposures,
        V8Smz9AdaptiveFiniteAccounting.honestProgramExposures,
        V8Smz9AdaptiveFiniteAccounting.eagerAllProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.eagerTreeProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.finalPiopProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.Historical.decsDomainSize,
        V8Smz9AdaptiveFiniteAccounting.Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.decsDomainSize,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent,
        smz9LazyJointMaximumHonestProofViewsAt128]
    · norm_num [V8Smz9AdaptiveFiniteAccounting.totalOracleExposures,
        V8Smz9AdaptiveFiniteAccounting.honestProgramExposures,
        V8Smz9AdaptiveFiniteAccounting.eagerAllProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.eagerTreeProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.finalPiopProgramsPerProof,
        V8Smz9AdaptiveFiniteAccounting.Historical.decsDomainSize,
        V8Smz9AdaptiveFiniteAccounting.Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.decsDomainSize,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent,
        smz9LazyJointMaximumHonestProofViewsAt128]
  constructor <;>
    unfold V8Smz9AdaptiveFiniteAccounting.totalOracleExposureExponent <;>
    rw [Nat.log2_eq_log_two]
  · rw [maximumLog]
  · rw [successorLog]

theorem smz9_lazy_joint_maximum_strictly_supports_128_bits :
    (smz9LazyJointProgrammingRatio
      smz9LazyJointMaximumHonestProofViewsAt128).strictlyBelowBits 128 := by
  simp only [smz9LazyJointProgrammingRatio,
    V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingRatio,
    V8Smz9AdaptiveFiniteAccounting.ExactNatRatio.add,
    V8Smz9AdaptiveFiniteAccounting.ExactNatRatio.strictlyBelowBits]
  rw [exact_smz9_lazy_joint_maximum_exposure_exponents.1]
  norm_num [smz9LazyStrictLeafProgramCap, smz9LazyFinalPiopPrograms,
    smz9LazyInternalProgramsAtWeightedCorner, smz9LazyTotalMerkleProgramCap,
    smz9LazyJointMaximumHonestProofViewsAt128]

theorem smz9_lazy_joint_maximum_successor_fails_strict_128_bits :
    ¬ (smz9LazyJointProgrammingRatio
      (smz9LazyJointMaximumHonestProofViewsAt128 + 1)).strictlyBelowBits 128 := by
  simp only [smz9LazyJointProgrammingRatio,
    V8Smz9AdaptiveFiniteAccounting.genericAdaptiveProgrammingRatio,
    V8Smz9AdaptiveFiniteAccounting.ExactNatRatio.add,
    V8Smz9AdaptiveFiniteAccounting.ExactNatRatio.strictlyBelowBits]
  rw [exact_smz9_lazy_joint_maximum_exposure_exponents.2]
  norm_num [smz9LazyStrictLeafProgramCap, smz9LazyFinalPiopPrograms,
    smz9LazyInternalProgramsAtWeightedCorner, smz9LazyTotalMerkleProgramCap,
    smz9LazyJointMaximumHonestProofViewsAt128]

/-- Conservative all-512 lazy fallback: at most 372 total programmed Merkle points, including at
most 20 level-zero strict-leaf points, plus the one final-PIOP point.  Other opened-path and root
hashes are concrete oracle calls rather than programming records. -/
def smz9LazyProgrammingEventsPerProofCap : Nat :=
  smz9CompactProgrammedMerkleNodeCap + smz9FinalPiopProgramEventsPerProof

theorem exact_smz9_full_and_lazy_programming_counts :
    smz9AllFullProgrammingEventsPerProof = 16777216 ∧
      smz9CompactProgrammedMerkleNodeCap = 372 ∧
      smz9LazyProgrammingEventsPerProofCap = 373 := by
  decide

def repeatedHistoryProgrammingScreen
    (eventsPerProof conditionalEntropyBits : Nat) : DyadicProgrammingScreen where
  numerator := 3 * eventsPerProof * finiteHistoryProofInteractions
  denominatorExponent :=
    1 + (conditionalEntropyBits - analysisTotalOracleStepExponentCeiling) / 2

theorem exact_full_tree_only_history_programming_screen :
    repeatedHistoryProgrammingScreen smz9FullTreeProgramEventsPerProof 512 =
      ⟨105553109975040, 224⟩ := by
  norm_num [repeatedHistoryProgrammingScreen, smz9FullTreeProgramEventsPerProof,
    smz9MerkleLeafCount, smz9MerkleInternalNodeCount, smz9MerkleLeafDomainBits,
    exact_finite_history_proof_interactions, analysisTotalOracleStepExponentCeiling]

theorem exact_all_full_history_programming_screen :
    repeatedHistoryProgrammingScreen smz9AllFullProgrammingEventsPerProof 512 =
      ⟨105553116266496, 224⟩ := by
  norm_num [repeatedHistoryProgrammingScreen, smz9AllFullProgrammingEventsPerProof,
    smz9FullTreeProgramEventsPerProof, smz9FinalPiopProgramEventsPerProof,
    smz9MerkleLeafCount, smz9MerkleInternalNodeCount, smz9MerkleLeafDomainBits,
    exact_finite_history_proof_interactions, analysisTotalOracleStepExponentCeiling]

theorem all_full_history_programming_screen_strictly_below_177_bits :
    (repeatedHistoryProgrammingScreen smz9AllFullProgrammingEventsPerProof 512).StrictlyBelowBits
      177 := by
  rw [exact_all_full_history_programming_screen]
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits]

theorem all_full_history_programming_screen_not_below_178_bits :
    ¬ (repeatedHistoryProgrammingScreen smz9AllFullProgrammingEventsPerProof 512).StrictlyBelowBits
      178 := by
  rw [exact_all_full_history_programming_screen]
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits]

def fullHistoryMinimumEvenConditionalEntropyBits : Nat := 414
def fullHistoryMinimumWholeByteEntropyBits : Nat := 416
def fullHistoryMinimumWholeBytes : Nat := 52
def fullHistoryMinimumActiveWordAlignedEntropyBits : Nat := 448
def fullHistoryMinimumActiveWordAlignedBytes : Nat := 56
def fullHistoryActiveWordAlignedSaltDeltaBytes : Nat := 24

theorem exact_full_history_entropy_minimum_alignment :
    fullHistoryMinimumEvenConditionalEntropyBits = 414 ∧
      fullHistoryMinimumWholeByteEntropyBits = 416 ∧
      fullHistoryMinimumWholeBytes = 52 ∧
      fullHistoryMinimumActiveWordAlignedEntropyBits = 448 ∧
      fullHistoryMinimumActiveWordAlignedBytes = 56 ∧
      fullHistoryActiveWordAlignedSaltDeltaBytes = 24 := by
  decide

/-- Adjacent-even pass/fail establishes 414 as the exact even-entropy minimum for the safe full
count under the `Q + H < 2^65` ceiling. -/
theorem full_history_minimum_even_entropy_passes_strict_target :
    (repeatedHistoryProgrammingScreen smz9AllFullProgrammingEventsPerProof
      fullHistoryMinimumEvenConditionalEntropyBits).StrictlyBelowBits
        strictProgrammingTargetBits := by
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits, repeatedHistoryProgrammingScreen,
    smz9AllFullProgrammingEventsPerProof, smz9FullTreeProgramEventsPerProof,
    smz9FinalPiopProgramEventsPerProof, smz9MerkleLeafCount, smz9MerkleInternalNodeCount,
    smz9MerkleLeafDomainBits, fullHistoryMinimumEvenConditionalEntropyBits,
    strictProgrammingTargetBits, analysisTotalOracleStepExponentCeiling,
    exact_finite_history_proof_interactions]

theorem full_history_preceding_even_entropy_fails_strict_target :
    ¬ DyadicProgrammingScreen.StrictlyBelowBits
      (repeatedHistoryProgrammingScreen smz9AllFullProgrammingEventsPerProof 412)
      strictProgrammingTargetBits := by
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits, repeatedHistoryProgrammingScreen,
    smz9AllFullProgrammingEventsPerProof, smz9FullTreeProgramEventsPerProof,
    smz9FinalPiopProgramEventsPerProof, smz9MerkleLeafCount, smz9MerkleInternalNodeCount,
    smz9MerkleLeafDomainBits, strictProgrammingTargetBits, analysisTotalOracleStepExponentCeiling,
    exact_finite_history_proof_interactions]

theorem full_history_384_bits_fails_strict_target :
    ¬ DyadicProgrammingScreen.StrictlyBelowBits
      (repeatedHistoryProgrammingScreen smz9AllFullProgrammingEventsPerProof 384)
      strictProgrammingTargetBits := by
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits, repeatedHistoryProgrammingScreen,
    smz9AllFullProgrammingEventsPerProof, smz9FullTreeProgramEventsPerProof,
    smz9FinalPiopProgramEventsPerProof, smz9MerkleLeafCount, smz9MerkleInternalNodeCount,
    smz9MerkleLeafDomainBits, strictProgrammingTargetBits, analysisTotalOracleStepExponentCeiling,
    exact_finite_history_proof_interactions]

theorem full_history_active_word_aligned_entropy_passes_strict_target :
    (repeatedHistoryProgrammingScreen smz9AllFullProgrammingEventsPerProof
      fullHistoryMinimumActiveWordAlignedEntropyBits).StrictlyBelowBits
        strictProgrammingTargetBits := by
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits, repeatedHistoryProgrammingScreen,
    smz9AllFullProgrammingEventsPerProof, smz9FullTreeProgramEventsPerProof,
    smz9FinalPiopProgramEventsPerProof, smz9MerkleLeafCount, smz9MerkleInternalNodeCount,
    smz9MerkleLeafDomainBits, fullHistoryMinimumActiveWordAlignedEntropyBits,
    strictProgrammingTargetBits, analysisTotalOracleStepExponentCeiling,
    exact_finite_history_proof_interactions]

theorem exact_lazy_history_programming_screen :
    repeatedHistoryProgrammingScreen smz9LazyProgrammingEventsPerProofCap 512 =
      ⟨2346713088, 224⟩ := by
  norm_num [repeatedHistoryProgrammingScreen, smz9LazyProgrammingEventsPerProofCap,
    smz9CompactProgrammedMerkleNodeCap, smz9FinalPiopProgramEventsPerProof,
    exact_finite_history_proof_interactions, analysisTotalOracleStepExponentCeiling]

theorem lazy_history_programming_screen_strictly_below_192_bits :
    (repeatedHistoryProgrammingScreen smz9LazyProgrammingEventsPerProofCap 512).StrictlyBelowBits
      192 := by
  rw [exact_lazy_history_programming_screen]
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits]

theorem lazy_history_programming_screen_not_below_193_bits :
    ¬ (repeatedHistoryProgrammingScreen smz9LazyProgrammingEventsPerProofCap 512).StrictlyBelowBits
      193 := by
  rw [exact_lazy_history_programming_screen]
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits]

def lazyHistoryMinimumEvenConditionalEntropyBits : Nat := 384
def lazyHistoryMinimumAlignedEntropyBits : Nat := 384
def lazyHistoryMinimumAlignedBytes : Nat := 48

theorem exact_lazy_history_entropy_minimum_alignment :
    lazyHistoryMinimumEvenConditionalEntropyBits = 384 ∧
      lazyHistoryMinimumAlignedEntropyBits = 384 ∧
      lazyHistoryMinimumAlignedBytes = 48 := by
  decide

theorem lazy_history_minimum_even_entropy_passes_strict_target :
    (repeatedHistoryProgrammingScreen smz9LazyProgrammingEventsPerProofCap
      lazyHistoryMinimumEvenConditionalEntropyBits).StrictlyBelowBits
        strictProgrammingTargetBits := by
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits, repeatedHistoryProgrammingScreen,
    smz9LazyProgrammingEventsPerProofCap, smz9CompactProgrammedMerkleNodeCap,
    smz9FinalPiopProgramEventsPerProof, lazyHistoryMinimumEvenConditionalEntropyBits,
    strictProgrammingTargetBits, analysisTotalOracleStepExponentCeiling,
    exact_finite_history_proof_interactions]

theorem lazy_history_preceding_even_entropy_fails_strict_target :
    ¬ DyadicProgrammingScreen.StrictlyBelowBits
      (repeatedHistoryProgrammingScreen smz9LazyProgrammingEventsPerProofCap 382)
      strictProgrammingTargetBits := by
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits, repeatedHistoryProgrammingScreen,
    smz9LazyProgrammingEventsPerProofCap, smz9CompactProgrammedMerkleNodeCap,
    smz9FinalPiopProgramEventsPerProof, strictProgrammingTargetBits,
    analysisTotalOracleStepExponentCeiling, exact_finite_history_proof_interactions]

theorem lazy_history_aligned_entropy_passes_strict_target :
    (repeatedHistoryProgrammingScreen smz9LazyProgrammingEventsPerProofCap
      lazyHistoryMinimumAlignedEntropyBits).StrictlyBelowBits strictProgrammingTargetBits := by
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits, repeatedHistoryProgrammingScreen,
    smz9LazyProgrammingEventsPerProofCap, smz9CompactProgrammedMerkleNodeCap,
    smz9FinalPiopProgramEventsPerProof, lazyHistoryMinimumAlignedEntropyBits,
    strictProgrammingTargetBits, analysisTotalOracleStepExponentCeiling,
    exact_finite_history_proof_interactions]

/-! A collision screen must include the single global quantum-query budget, not reset it for each
proof.  The classical pair screen is recorded for comparison.  The coefficient-one cubic screen
is a conservative arithmetic normalization for a quantum collision theorem; its applicability
and exact constant are external, so no concrete collision claim is obtained merely by evaluating
it. -/

def fullHistoryProgramEventCount : Nat :=
  smz9AllFullProgrammingEventsPerProof * finiteHistoryProofInteractions
def globalOracleExposureCount : Nat :=
  2 ^ analysisGlobalQuantumQueryBits + fullHistoryProgramEventCount

theorem exact_full_history_and_global_exposure_counts :
    fullHistoryProgramEventCount = 35184372088832 ∧
      globalOracleExposureCount = 18446779258081640448 := by
  norm_num [fullHistoryProgramEventCount, globalOracleExposureCount,
    smz9AllFullProgrammingEventsPerProof, smz9FullTreeProgramEventsPerProof,
    smz9FinalPiopProgramEventsPerProof, smz9MerkleLeafCount,
    smz9MerkleInternalNodeCount, smz9MerkleLeafDomainBits,
    analysisGlobalQuantumQueryBits, exact_finite_history_proof_interactions]

theorem global_oracle_exposure_uses_q_plus_h_and_has_exact_ceiling :
    2 ^ analysisGlobalQuantumQueryBits < globalOracleExposureCount ∧
      globalOracleExposureCount < 2 ^ analysisTotalOracleStepExponentCeiling := by
  rw [exact_full_history_and_global_exposure_counts.2]
  norm_num [analysisGlobalQuantumQueryBits, analysisTotalOracleStepExponentCeiling]

def classicalSha512BirthdayCollisionScreen : DyadicProgrammingScreen where
  numerator := globalOracleExposureCount * (globalOracleExposureCount - 1) / 2
  denominatorExponent := 512

def coefficientOneQromCubicCollisionScreen : DyadicProgrammingScreen where
  numerator := globalOracleExposureCount ^ 3
  denominatorExponent := 512

theorem exact_classical_sha512_birthday_collision_screen :
    classicalSha512BirthdayCollisionScreen =
      ⟨170141832498195518595560170536334000128, 512⟩ := by
  simp only [classicalSha512BirthdayCollisionScreen]
  rw [show globalOracleExposureCount = 18446779258081640448 by
    exact exact_full_history_and_global_exposure_counts.2]

theorem classical_sha512_birthday_screen_strictly_below_384_bits :
    classicalSha512BirthdayCollisionScreen.StrictlyBelowBits 384 := by
  rw [exact_classical_sha512_birthday_collision_screen]
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits]

theorem classical_sha512_birthday_screen_not_below_385_bits :
    ¬ classicalSha512BirthdayCollisionScreen.StrictlyBelowBits 385 := by
  rw [exact_classical_sha512_birthday_collision_screen]
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits]

theorem coefficient_one_qrom_cubic_screen_strictly_below_319_bits :
    coefficientOneQromCubicCollisionScreen.StrictlyBelowBits 319 := by
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits,
    coefficientOneQromCubicCollisionScreen, globalOracleExposureCount,
    fullHistoryProgramEventCount, smz9AllFullProgrammingEventsPerProof,
    smz9FullTreeProgramEventsPerProof, smz9FinalPiopProgramEventsPerProof,
    smz9MerkleLeafCount, smz9MerkleInternalNodeCount, smz9MerkleLeafDomainBits,
    analysisGlobalQuantumQueryBits, exact_finite_history_proof_interactions]

theorem coefficient_one_qrom_cubic_screen_not_below_320_bits :
    ¬ coefficientOneQromCubicCollisionScreen.StrictlyBelowBits 320 := by
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits,
    coefficientOneQromCubicCollisionScreen, globalOracleExposureCount,
    fullHistoryProgramEventCount, smz9AllFullProgrammingEventsPerProof,
    smz9FullTreeProgramEventsPerProof, smz9FinalPiopProgramEventsPerProof,
    smz9MerkleLeafCount, smz9MerkleInternalNodeCount, smz9MerkleLeafDomainBits,
    analysisGlobalQuantumQueryBits, exact_finite_history_proof_interactions]

/-- The cubic collision screen is far below one unit at denominator `2^224`.  Adding one such
unit to the programming numerator therefore gives a kernel-cheap strict upper envelope for the
sum; no enormous common-denominator normalization or native evaluator is needed. -/
theorem coefficient_one_qrom_cubic_screen_strictly_below_224_bits :
    coefficientOneQromCubicCollisionScreen.StrictlyBelowBits 224 := by
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits,
    coefficientOneQromCubicCollisionScreen, globalOracleExposureCount,
    fullHistoryProgramEventCount, smz9AllFullProgrammingEventsPerProof,
    smz9FullTreeProgramEventsPerProof, smz9FinalPiopProgramEventsPerProof,
    smz9MerkleLeafCount, smz9MerkleInternalNodeCount, smz9MerkleLeafDomainBits,
    analysisGlobalQuantumQueryBits, exact_finite_history_proof_interactions]

def combinedFullProgrammingAndCubicCollisionUpperScreen : DyadicProgrammingScreen where
  numerator :=
    (repeatedHistoryProgrammingScreen smz9AllFullProgrammingEventsPerProof 512).numerator + 1
  denominatorExponent := 224

theorem exact_combined_full_programming_and_cubic_collision_upper_screen :
    combinedFullProgrammingAndCubicCollisionUpperScreen = ⟨105553116266497, 224⟩ := by
  norm_num [combinedFullProgrammingAndCubicCollisionUpperScreen,
    repeatedHistoryProgrammingScreen, smz9AllFullProgrammingEventsPerProof,
    smz9FullTreeProgramEventsPerProof, smz9FinalPiopProgramEventsPerProof,
    smz9MerkleLeafCount, smz9MerkleInternalNodeCount, smz9MerkleLeafDomainBits,
    analysisTotalOracleStepExponentCeiling, exact_finite_history_proof_interactions]

theorem combined_full_programming_and_cubic_collision_upper_screen_strictly_below_177_bits :
    combinedFullProgrammingAndCubicCollisionUpperScreen.StrictlyBelowBits 177 := by
  rw [exact_combined_full_programming_and_cubic_collision_upper_screen]
  norm_num [DyadicProgrammingScreen.StrictlyBelowBits]

/-! ## Explicit non-authority boundary -/

inductive ExecutableRngToFreshFinalPiopCoinsRefinement : Prop
inductive ExactFinalPiopRawWordSerializationRefinement : Prop
inductive AdaptiveFinalPiopReprogrammingTheoremApplicability : Prop
inductive ConcreteSha512QuantumRandomOracleInstantiation : Prop
inductive ExecutableAllLeafTapesFreshAcrossHistoryRefinement : Prop
inductive ExactStrictZkLeafInputSerializationRefinement : Prop
inductive AdaptiveEagerTreeInternalEntropyPropagation : Prop
inductive ProtocolLifetimeGlobalQuantumQueryBinding : Prop
inductive ObservedHonestProofViewExposureBound : Nat → Prop
inductive CoefficientOneQromCubicCollisionTheoremApplicability : Prop

/-- Source locations and digests for the narrow executable record/replay receipt.  These constants
pin the generated vector and its negative-mutation test; Lean does not thereby verify Rust source
semantics or any cryptographic assumption. -/
def exactLazyMerkleRecordingSource : String :=
  "transaction_circuit::smallwood_engine::validate_smallwood_strict_whole_view_simulation_v1"
def exactLazyMerkleMutationTestSource : String :=
  "transaction_circuit::smallwood_engine::tests::smz9_whole_view_simulator_is_witness_free_canonical_and_mutation_bound"
def exactLazyMerkleRefinementVectorSource : String :=
  "docs/crypto/smallwood_poseidon2_v8_smz9_executable_zk_refinement.json"
def exactLazyMerkleRefinementReportBytes : Nat := 4230
def exactLazyMerkleRefinementReportSha512 : String :=
  "e89ff29b047d85c6121689c4d298f031141d2dac6452f182d5d8d53cdd4ef7694c8616909ade6be95bcf1b1e06e98dd25b13df79bd7372be9a5af0500fe9015b"
def exactLazyMerkleRelationProgramSha512 : String :=
  "7e50eba07d84433a53a6c85ed2b3efecbeff103ca402bb931831e1598e6c9ab8fa138c9b2f0cb9d21bf2bf044b50d4d057ae0bb12e4def00ec52765245cf9e17"
def exactLazyMerkleProgramTableSha512 : String :=
  "618bd3c61d59348cdfb680ebab86ebf93d7aa3cd6e3ff398b0a35b9a2e2bf9ea6a648c7a7ab523bb2cf21ed9291308420e5c25dcf480dd3a4680c2bac135b2d3"
def exactLazyMerkleQueryTraceSha512 : String :=
  "187c8ec0b3b43229f6b6537abe7dab7c01cb86a016d921d5b64da386bb33956626dcdbc8c3edcf2088eb722e488482ecff9f7babe78bff1e094e0acdfaa46dae"
def exactLazyMerkleProofSha512 : String :=
  "66c1552ebc33133bffb14c271680986fb98185632982350e5e0bec092e82e4ede5ae4934649b418d46a3a36802c3f2618de6ac264dde59055c5515cff72be73b"
def exactLazyMerkleVectorLevelHistogram : List Nat :=
  [20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 18, 13, 10, 7, 4, 1, 0, 0]

/-- Exhaustive typed roles admitted by the executable lazy program-table constructor.  The
salt-only role is retained in this datatype solely so its absence is an explicit decidable source
inventory statement rather than an omission from the vocabulary. -/
inductive Smz9ExecutableProgramKeyRole where
  | strictLeaf
  | internalNode
  | finalPiop
  | saltOnlyFirstProgram256
deriving DecidableEq, Repr

def smz9ExecutableLazyProgramKeyRoles : List Smz9ExecutableProgramKeyRole :=
  [.strictLeaf, .internalNode, .finalPiop]

def smz9ExecutableDirect256BitFirstProgramRouteUsed : Bool :=
  decide (.saltOnlyFirstProgram256 ∈ smz9ExecutableLazyProgramKeyRoles)

theorem exact_smz9_executable_lazy_program_key_inventory :
    smz9ExecutableLazyProgramKeyRoles =
        [.strictLeaf, .internalNode, .finalPiop] ∧
      .saltOnlyFirstProgram256 ∉ smz9ExecutableLazyProgramKeyRoles ∧
      smz9ExecutableDirect256BitFirstProgramRouteUsed = false := by
  decide

/-- Narrow, inhabited pinned receipt for executable evidence: the active simulator records a
discriminated strict-leaf preimage at level zero and a two-child node preimage above level zero,
installs full 64-byte
program outputs in a canonical query/program-table overlay, and rejects the checked mutation
suite.  This receipt is intentionally only a pinned regression/refinement witness; it gives no
independent-uniform RNG or adaptive-QROM theorem. -/
structure ExactLazyMerkleProgramInputOutputRecordingRefinement : Prop where
  recordingSourceExact :
    exactLazyMerkleRecordingSource =
      "transaction_circuit::smallwood_engine::validate_smallwood_strict_whole_view_simulation_v1"
  mutationTestSourceExact :
    exactLazyMerkleMutationTestSource =
      "transaction_circuit::smallwood_engine::tests::smz9_whole_view_simulator_is_witness_free_canonical_and_mutation_bound"
  vectorSourceExact :
    exactLazyMerkleRefinementVectorSource =
      "docs/crypto/smallwood_poseidon2_v8_smz9_executable_zk_refinement.json"
  reportPinExact :
    exactLazyMerkleRefinementReportBytes = 4230 ∧
      exactLazyMerkleRefinementReportSha512 =
        "e89ff29b047d85c6121689c4d298f031141d2dac6452f182d5d8d53cdd4ef7694c8616909ade6be95bcf1b1e06e98dd25b13df79bd7372be9a5af0500fe9015b"
  sourceAndOraclePinsExact :
    exactLazyMerkleRelationProgramSha512 =
        "7e50eba07d84433a53a6c85ed2b3efecbeff103ca402bb931831e1598e6c9ab8fa138c9b2f0cb9d21bf2bf044b50d4d057ae0bb12e4def00ec52765245cf9e17" ∧
      exactLazyMerkleProgramTableSha512 =
        "618bd3c61d59348cdfb680ebab86ebf93d7aa3cd6e3ff398b0a35b9a2e2bf9ea6a648c7a7ab523bb2cf21ed9291308420e5c25dcf480dd3a4680c2bac135b2d3" ∧
      exactLazyMerkleQueryTraceSha512 =
        "187c8ec0b3b43229f6b6537abe7dab7c01cb86a016d921d5b64da386bb33956626dcdbc8c3edcf2088eb722e488482ecff9f7babe78bff1e094e0acdfaa46dae" ∧
      exactLazyMerkleProofSha512 =
        "66c1552ebc33133bffb14c271680986fb98185632982350e5e0bec092e82e4ede5ae4934649b418d46a3a36802c3f2618de6ac264dde59055c5515cff72be73b"
  vectorJointCountsExact :
    exactLazyMerkleVectorLevelHistogram =
        [20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 18, 13, 10,
          7, 4, 1, 0, 0] ∧
      20 + 333 = 353 ∧ 353 + 1 = 354
  sourceProgramKeyInventoryExact :
    .saltOnlyFirstProgram256 ∉ smz9ExecutableLazyProgramKeyRoles ∧
      smz9ExecutableDirect256BitFirstProgramRouteUsed = false

theorem checked_in_exact_lazy_merkle_program_input_output_recording_refinement :
    ExactLazyMerkleProgramInputOutputRecordingRefinement := by
  exact
    ⟨rfl, rfl, rfl, ⟨rfl, rfl⟩, ⟨rfl, rfl, rfl, rfl⟩, ⟨rfl, by decide⟩,
      exact_smz9_executable_lazy_program_key_inventory.2⟩

inductive ExecutableSimulatorRngToFreshLazyInputsRefinement : Prop
inductive AdaptiveLazyHiddenSubtreeCompletionTheoremApplicability : Prop

/-- These are the external premises required to reinterpret the ideal 512-bit fiber theorem and
the dyadic screen as a concrete SHA-512 adaptive-programming loss. -/
structure ConcreteFinalPiopProgrammingPremises : Prop where
  executableRngFreshness : ExecutableRngToFreshFinalPiopCoinsRefinement
  exactRawWordSerialization : ExactFinalPiopRawWordSerializationRefinement
  adaptiveReprogrammingApplicability : AdaptiveFinalPiopReprogrammingTheoremApplicability
  concreteSha512Qro : ConcreteSha512QuantumRandomOracleInstantiation

/-- Premises needed to give the conservative `2^24` event arithmetic concrete meaning for the
active eager full tree plus final PIOP.  In particular, fresh leaf tapes do not by themselves
prove that a derived internal-node input retains 512 conditional bits after every prior quantum
view. -/
structure ConcreteFullHistoryProgrammingPremises : Prop where
  observedHonestViewBound : ObservedHonestProofViewExposureBound finiteHistoryProofInteractions
  executableLeafTapeFreshness : ExecutableAllLeafTapesFreshAcrossHistoryRefinement
  exactLeafSerialization : ExactStrictZkLeafInputSerializationRefinement
  eagerInternalEntropyPropagation : AdaptiveEagerTreeInternalEntropyPropagation
  finalPiop : ConcreteFinalPiopProgrammingPremises
  lifetimeGlobalQueryBinding : ProtocolLifetimeGlobalQuantumQueryBinding
  qromCollisionApplicability : CoefficientOneQromCubicCollisionTheoremApplicability

/-- Premises needed to replace the safe full-tree count by the source-derived lazy joint envelope.
Opened paths and the root are concrete queries and add no programming point.  The executable
recording premise is inhabited above; independent-uniform typed coins, adaptive hidden-subtree
completion, final-PIOP programming, lifetime query binding, and collision applicability remain
external. -/
structure ConcreteLazyHistoryProgrammingPremises : Prop where
  observedHonestViewBound : ObservedHonestProofViewExposureBound finiteHistoryProofInteractions
  exactMerkleInputOutputRecording : ExactLazyMerkleProgramInputOutputRecordingRefinement
  executableFreshLazyInputs : ExecutableSimulatorRngToFreshLazyInputsRefinement
  adaptiveHiddenSubtreeCompletion : AdaptiveLazyHiddenSubtreeCompletionTheoremApplicability
  finalPiop : ConcreteFinalPiopProgrammingPremises
  lifetimeGlobalQueryBinding : ProtocolLifetimeGlobalQuantumQueryBinding
  qromCollisionApplicability : CoefficientOneQromCubicCollisionTheoremApplicability

theorem concrete_final_piop_programming_premises_are_unavailable :
    ¬ Nonempty ConcreteFinalPiopProgrammingPremises := by
  rintro ⟨premises⟩
  exact nomatch premises.executableRngFreshness

theorem concrete_full_history_programming_premises_are_unavailable :
    ¬ Nonempty ConcreteFullHistoryProgrammingPremises := by
  rintro ⟨premises⟩
  exact nomatch premises.executableLeafTapeFreshness

theorem consensus_accepted_action_cap_does_not_construct_honest_view_exposure_bound :
    ¬ ObservedHonestProofViewExposureBound finiteHistoryProofInteractions := by
  intro bound
  exact nomatch bound

theorem concrete_lazy_history_programming_premises_are_unavailable :
    ¬ Nonempty ConcreteLazyHistoryProgrammingPremises := by
  rintro ⟨premises⟩
  exact nomatch premises.executableFreshLazyInputs

theorem exact_lazy_recording_is_available_but_rng_freshness_is_not :
    ExactLazyMerkleProgramInputOutputRecordingRefinement ∧
      ¬ ExecutableSimulatorRngToFreshLazyInputsRefinement := by
  exact ⟨checked_in_exact_lazy_merkle_program_input_output_recording_refinement,
    fun freshness => nomatch freshness⟩

theorem final_piop_result_does_not_cover_earlier_merkle_programming :
    ¬ Nonempty AdaptiveFinalPiopReprogrammingTheoremApplicability := by
  rintro ⟨premise⟩
  exact nomatch premise

end V8Smz9RepeatedAlgebraicZk
end SmallWood
end HegemonCrypto
