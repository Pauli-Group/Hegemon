import Q38Rp05CurrentCompleteRequest
import Q38Rp05AdaptiveOpening
import Q38CmsAdaptiveWholeViewBound
import Q38Rp05AbortAwareOpening
import Q38Rp05SelectedContinuation

/-!
# Current SMZA selected-byte opening game

Instantiate the generic retained-opening theorem on the corrected 2511-byte
raw-input partition and the SMZA selector. Both sides execute the same
selected-byte continuation; on index exhaustion no leaf is programmed by
the public game. This is a single measured-branch bound, not the full
adaptive-history privacy endpoint.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentAdaptiveOpening

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaAdaptiveOpening
open HegemonCrypto.SmallWood.V8SmzaSelectionFeedback
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal
open HegemonCrypto.SmallWood.Q38Rp05FullAdaptiveComposition
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.Q38Rp05SelectedContinuation
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame (SaltBytes)
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch (LeafIndex)
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid (Opened tapeSplit)
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid (q38Unopened)
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsCompressedOracle (normSquared)
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame (uniformAverage)
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewBound
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped BigOperators Classical

local notation "Statement" =>
  HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

private theorem read_count_bind_done
    {Other Result Next : Type} (program : NonleafProgram Other Result)
    (finish : Result → Next) :
    NonleafProgram.readCount
      (NonleafProgram.bind program (fun result => .done (finish result))) =
      NonleafProgram.readCount program := by
  induction program with
  | done result => rfl
  | read input rest ih =>
      have each : (fun answer => NonleafProgram.readCount
          (NonleafProgram.bind (rest answer)
            (fun result => .done (finish result)))) =
          (fun answer => NonleafProgram.readCount (rest answer)) := by
        funext answer
        exact ih answer
      simp only [NonleafProgram.bind, NonleafProgram.readCount, each]

/-- The actual current index selector makes at most twelve honest reads:
one opening digest and at most eleven 50-word field-XOF blocks. -/
theorem current_selector_reads_le_twelve
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (points : Fin 6 → Goldilocks) (pointsDistinct : Function.Injective points)
    (digest : DigestRegister) (heads : PublicCombinationHeads Goldilocks)
    (tails : Earlier Goldilocks) (pending : Bool) :
    NonleafProgram.readCount
      (currentSelectIndices bound largeEnough points pointsDistinct
        digest heads tails pending) ≤ 12 := by
  change (Finset.univ.sup fun challenge =>
      NonleafProgram.readCount (NonleafProgram.bind
        (currentFixedIndexXof bound largeEnough challenge)
        (fun sampled => .done
          (⟨challenge, sampled,
            sampledTargets points pointsDistinct (sourceReturnedWords 50 sampled),
            sourcePendingFailure pending sampled⟩ : SelectionResult points)))) + 1 ≤ 12
  have each (challenge : DigestRegister) :
      NonleafProgram.readCount (NonleafProgram.bind
        (currentFixedIndexXof bound largeEnough challenge)
        (fun sampled => .done
          (⟨challenge, sampled,
            sampledTargets points pointsDistinct (sourceReturnedWords 50 sampled),
            sourcePendingFailure pending sampled⟩ : SelectionResult points))) ≤ 11 := by
    rw [read_count_bind_done]
    exact (source_field_read_loop_count 50 [] _).trans (by simp)
  have maximum : (Finset.univ.sup fun challenge =>
      NonleafProgram.readCount (NonleafProgram.bind
        (currentFixedIndexXof bound largeEnough challenge)
        (fun sampled => .done
          (⟨challenge, sampled,
            sampledTargets points pointsDistinct (sourceReturnedWords 50 sampled),
            sourcePendingFailure pending sampled⟩ : SelectionResult points)))) ≤ 11 :=
    Finset.sup_le fun challenge _ => each challenge
  omega

private theorem as_selection_exposures_eq_read_count
    {Other Result Work : Type} [Fintype Other] [Fintype Work]
    (program : NonleafProgram Other Result) :
    exposures (asSelection (Work := Work) program) =
      NonleafProgram.readCount program := by
  induction program with
  | done result => rfl
  | read input rest ih =>
      have each : (fun answer =>
          exposures (asSelection (Work := Work) (rest answer))) =
          (fun answer => NonleafProgram.readCount (rest answer)) := by
        funext answer
        exact ih answer
      simp only [asSelection, exposures, NonleafProgram.readCount, each]

theorem current_selector_exposures_le_twelve
    {Work : Type} [Fintype Work]
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (points : Fin 6 → Goldilocks) (pointsDistinct : Function.Injective points)
    (digest : DigestRegister) (heads : PublicCombinationHeads Goldilocks)
    (tails : Earlier Goldilocks) (pending : Bool) :
    exposures (asSelection (Work := Work)
      (currentSelectIndices bound largeEnough points pointsDistinct
        digest heads tails pending)) ≤ 12 := by
  rw [as_selection_exposures_eq_read_count]
  exact current_selector_reads_le_twelve bound largeEnough points
    pointsDistinct digest heads tails pending

/-- The selected-opening loss coefficient is uniform over every measured
DECS/PIOP/final-digest branch, even though the public selector itself depends
on that branch. This is the common coefficient for the unnormalised trace
mass telescope; it does not assert the full P7/P10 game identification. -/
theorem current_selector_loss_uniform
    {Work : Type} [Fintype Work]
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (points : Fin 6 → Goldilocks) (pointsDistinct : Function.Injective points)
    (digest : DigestRegister) (heads : PublicCombinationHeads Goldilocks)
    (tails : Earlier Goldilocks) (pending : Bool) (queries : Nat) :
    4 * ((exposures (asSelection (Work := Work)
      (currentSelectIndices bound largeEnough points pointsDistinct digest
        heads tails pending)) : ℝ) + queries) / (2 : ℝ)^256 ≤
      4 * (12 + (queries : ℝ)) / (2 : ℝ)^256 := by
  have capped : (exposures (asSelection (Work := Work)
      (currentSelectIndices bound largeEnough points pointsDistinct digest
        heads tails pending)) : ℝ) ≤ 12 := by
    exact_mod_cast current_selector_exposures_le_twelve
      (Work := Work) bound largeEnough points pointsDistinct digest heads
      tails pending
  apply div_le_div_of_nonneg_right _ (by positivity)
  nlinarith

/-- Finite oracle-family averaging preserves a homogeneous local comparison
without a factor for the number of oracle fibers. The pointwise mass may be
unnormalised and zero. -/
theorem uniform_average_distance_le_mass
    {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (left right mass : Coins → ℝ) (loss : ℝ)
    (pointwiseBound : ∀ coin, |left coin - right coin| ≤ loss * mass coin) :
    |uniformAverage left - uniformAverage right| ≤
      loss * uniformAverage mass := by
  have cardPositive : (0 : ℝ) < Fintype.card Coins := by
    exact_mod_cast Fintype.card_pos
  have averageEq (value : Coins → ℝ) :
      uniformAverage value =
        (∑ coin : Coins, value coin) / (Fintype.card Coins : ℝ) := by
    simpa only [uniformAverage] using
      Q38WholeViewCmsSemantics.uniformAverage_eq_sum_div value
  calc
    _ = |∑ coin : Coins, (left coin - right coin)| /
          (Fintype.card Coins : ℝ) := by
          rw [averageEq left, averageEq right]
          rw [← sub_div, ← Finset.sum_sub_distrib, abs_div,
            abs_of_pos cardPositive]
    _ ≤ (∑ coin : Coins, |left coin - right coin|) /
          (Fintype.card Coins : ℝ) :=
        div_le_div_of_nonneg_right
          (Finset.abs_sum_le_sum_abs _ _) cardPositive.le
    _ ≤ (∑ coin : Coins, loss * mass coin) /
          (Fintype.card Coins : ℝ) := by
          apply div_le_div_of_nonneg_right _ cardPositive.le
          exact Finset.sum_le_sum (fun coin _ => pointwiseBound coin)
    _ = loss * uniformAverage mass := by
          rw [averageEq, ← Finset.mul_sum]
          ring

/-- The serialized proof sees precisely the job's actually opened tapes.
The padding is internal; it is never transmitted or sampled anew. -/
def currentSelectedContinuation
    {bound : Nat} {Work : Type} [Fintype Work]
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister))
    (next : Except String (List Byte) →
      Program (Rp05FullRawInput bound) Work)
    (job : SelectionResult opening.points)
    (visible : Opened (rp05AbortAwareUnopened job) → LeafTape) :
    Program (Rp05FullRawInput bound) Work :=
  let tapes := Q38Rp05AdaptiveOpening.visiblePadding
    (rp05AbortAwareUnopened job) visible
  next (selectedBytes dsl statement parameters opening gamma reply transcript
    digest salt tree tapes (selectedPhysicalView values base q reply job) job)

theorem current_selected_continuation_on_real_tapes
    {bound : Nat} {Work : Type} [Fintype Work]
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister))
    (next : Except String (List Byte) →
      Program (Rp05FullRawInput bound) Work)
    (job : SelectionResult opening.points) (tapes : TapeTable) :
    currentSelectedContinuation dsl statement parameters opening values base q
        gamma reply transcript digest salt tree next job
        ((tapeSplit (rp05AbortAwareUnopened job) tapes).1) =
      next (selectedBytes dsl statement parameters opening gamma reply
        transcript digest salt tree tapes
        (selectedPhysicalView values base q reply job) job) := by
  unfold currentSelectedContinuation
  change next (selectedBytes dsl statement parameters opening gamma reply
      transcript digest salt tree
      (Q38Rp05AdaptiveOpening.visiblePadding
        (rp05AbortAwareUnopened job) ((tapeSplit (rp05AbortAwareUnopened job) tapes).1))
      (selectedPhysicalView values base q reply job) job) = _
  exact congrArg next
    (selected_bytes_ignore_unopened_tapes dsl statement parameters
      opening values base q gamma reply transcript digest salt tree job tapes).symm

/-- Current-profile P8/P9 loss on any unnormalised reached state. The
selector, its byte continuation and both games use one physical oracle. -/
theorem current_selected_opening_bound_mass
    {bound : Nat} {Work : Type} [Fintype Work]
    (randomized : Bool) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (gamma : Gamma Goldilocks)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister))
    (next : Except String (List Byte) →
      Program (Rp05FullRawInput bound) Work)
    (queries : Nat)
    (bounded : ∀ bytes, queryCount (next bytes) ≤ queries)
    (old : Rp05LeafInput → DigestRegister)
    (other : Rp05OtherRawInput bound → DigestRegister)
    (labels : LeafIndex → DigestRegister)
    (state : GameState
      (Input := Rp05FullRawInput bound) (Work := Work)) :
    let reply := V8SmzaMathPrivacy.response gamma
      (currentHeads values base q) base.2.2 m
    let transcript := Q38Rp05ChronologicalAlgebra.response dsl statement parameters
      (sourceWitnessPolynomials values base.1) q
    let selector := asSelection (currentSelectIndices bound largeEnough
      opening.points (computed_opening_points_distinct opening) digest
      (combinationHeads dsl statement parameters opening.points transcript
        (sourceWitnessOpenings values opening.points base.1)
        (sourcePcsFullView opening.points
          (pcsBase opening.points q reply) base.2.1))
      (earlier opening.points base.2.2) opening.pendingFailure)
    let program := currentSelectedContinuation dsl statement parameters opening
      values base q gamma reply transcript digest salt tree next
    |fullGame randomized selector rp05AbortAwareUnopened program
        old other labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m) state -
      publicGame randomized selector rp05AbortAwareUnopened program
        old other labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m) state| ≤
      (4 * ((exposures selector : ℝ) + queries) / (2 ^ 256 : ℝ)) *
        ‖state‖ ^ 2 := by
  apply adaptive_opening_bound_mass randomized
    (asSelection (currentSelectIndices bound largeEnough opening.points
      (computed_opening_points_distinct opening) digest
      (combinationHeads dsl statement parameters opening.points
        (Q38Rp05ChronologicalAlgebra.response dsl statement parameters
          (sourceWitnessPolynomials values base.1) q)
        (sourceWitnessOpenings values opening.points base.1)
        (sourcePcsFullView opening.points
          (pcsBase opening.points q
            (V8SmzaMathPrivacy.response gamma
              (currentHeads values base q) base.2.2 m)) base.2.1))
      (earlier opening.points base.2.2) opening.pendingFailure))
    rp05AbortAwareUnopened
    (fun job => by
      cases h : job.targets with
      | none => exact ⟨0, by simp [rp05AbortAwareUnopened, h]⟩
      | some targets =>
          simpa [rp05AbortAwareUnopened, h] using
            q38Anchor targets.val targets.property.1)
    (currentSelectedContinuation dsl statement parameters opening values base q
      gamma (V8SmzaMathPrivacy.response gamma
        (currentHeads values base q) base.2.2 m)
      (Q38Rp05ChronologicalAlgebra.response dsl statement parameters
        (sourceWitnessPolynomials values base.1) q)
      digest salt tree next)
    old other labels statement salt
    (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
    queries (by intro job visible; exact bounded _) state

/-- The corrected P8/P9 comparison on the unchanged total-oracle family.
The selector may see the fixed public branch, but every oracle fiber keeps
its own residual register state. The 12-read coefficient is paid once
against the family's incoming squared norm, with no oracle-count factor. -/
theorem current_selected_opening_family_bound_mass
    {bound : Nat} {Work : Type} [Fintype Work] [DecidableEq Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (gamma : Gamma Goldilocks)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister))
    (next : Except String (List Byte) →
      Program (Rp05FullRawInput bound) Work)
    (queries : Nat)
    (bounded : ∀ bytes, queryCount (next bytes) ≤ queries)
    (labels : LeafIndex → DigestRegister)
    (family : OracleRegisterFamily
      (Input := Rp05FullRawInput bound) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    let reply := V8SmzaMathPrivacy.response gamma
      (currentHeads values base q) base.2.2 m
    let transcript := Q38Rp05ChronologicalAlgebra.response dsl statement parameters
      (sourceWitnessPolynomials values base.1) q
    let selector := asSelection (currentSelectIndices bound largeEnough
      opening.points (computed_opening_points_distinct opening) digest
      (combinationHeads dsl statement parameters opening.points transcript
        (sourceWitnessOpenings values opening.points base.1)
        (sourcePcsFullView opening.points
          (pcsBase opening.points q reply) base.2.1))
      (earlier opening.points base.2.2) opening.pendingFailure)
    let program := currentSelectedContinuation dsl statement parameters opening
      values base q gamma reply transcript digest salt tree next
    let data := q38PhysicalSuffix (currentHeads values base q) base.2.2 m
    |uniformAverage (fun oracle : Rp05FullRawInput bound → DigestRegister =>
        fullGame true selector rp05AbortAwareUnopened program
          (fun leaf => oracle (Sum.inl leaf))
          (fun other => oracle (Sum.inr other)) labels statement salt data
          (familyGameState family oracle)) -
      uniformAverage (fun oracle : Rp05FullRawInput bound → DigestRegister =>
        publicGame true selector rp05AbortAwareUnopened program
          (fun leaf => oracle (Sum.inl leaf))
          (fun other => oracle (Sum.inr other)) labels statement salt data
          (familyGameState family oracle))| ≤
      (4 * (12 + (queries : ℝ)) / (2 : ℝ)^256) *
        normSquared (totalOracleFamilyState family) := by
  let reply := V8SmzaMathPrivacy.response gamma
    (currentHeads values base q) base.2.2 m
  let transcript := Q38Rp05ChronologicalAlgebra.response dsl statement
    parameters (sourceWitnessPolynomials values base.1) q
  let selector := asSelection (Work := Work) (currentSelectIndices bound largeEnough
    opening.points (computed_opening_points_distinct opening) digest
    (combinationHeads dsl statement parameters opening.points transcript
      (sourceWitnessOpenings values opening.points base.1)
      (sourcePcsFullView opening.points
        (pcsBase opening.points q reply) base.2.1))
    (earlier opening.points base.2.2) opening.pendingFailure)
  let program := currentSelectedContinuation dsl statement parameters opening
    values base q gamma reply transcript digest salt tree next
  let data := q38PhysicalSuffix (currentHeads values base q) base.2.2 m
  let full := fun oracle : Rp05FullRawInput bound → DigestRegister =>
    fullGame true selector rp05AbortAwareUnopened program
      (fun leaf => oracle (Sum.inl leaf))
      (fun other => oracle (Sum.inr other)) labels statement salt data
      (familyGameState family oracle)
  let publicPart := fun oracle : Rp05FullRawInput bound → DigestRegister =>
    publicGame true selector rp05AbortAwareUnopened program
      (fun leaf => oracle (Sum.inl leaf))
      (fun other => oracle (Sum.inr other)) labels statement salt data
      (familyGameState family oracle)
  let loss : ℝ := 4 * (12 + (queries : ℝ)) / (2 : ℝ)^256
  have pointwiseBound (oracle : Rp05FullRawInput bound → DigestRegister) :
      |full oracle - publicPart oracle| ≤
        loss * ‖familyGameState family oracle‖ ^ 2 := by
    have pointwise := current_selected_opening_bound_mass true largeEnough
      dsl statement parameters opening values base q m gamma digest salt tree
      next queries bounded (fun leaf => oracle (Sum.inl leaf))
      (fun other => oracle (Sum.inr other)) labels
      (familyGameState family oracle)
    have coefficient := current_selector_loss_uniform (Work := Work) bound
      largeEnough opening.points (computed_opening_points_distinct opening)
      digest
      (combinationHeads dsl statement parameters opening.points transcript
        (sourceWitnessOpenings values opening.points base.1)
        (sourcePcsFullView opening.points
          (pcsBase opening.points q reply) base.2.1))
      (earlier opening.points base.2.2) opening.pendingFailure queries
    exact pointwise.trans
      (mul_le_mul_of_nonneg_right coefficient (by positivity))
  have lifted := uniform_average_distance_le_mass full publicPart
    (fun oracle => ‖familyGameState family oracle‖ ^ 2) loss pointwiseBound
  rw [total_oracle_family_norm_squared family]
  exact lifted

/-- The retained-opening game's public oracle is exactly the persistent
batch of the selected 38 physical leaves, for the corrected raw partition. -/
theorem current_opened_overlay_eq_batch
    (bound : Nat) (statement : Statement) (salt : SaltBytes)
    (data : LeafIndex → Fin 1176 → Byte)
    (selected : Fin 38 → LeafIndex) (distinct : Function.Injective selected)
    (labels : LeafIndex → DigestRegister) (tapes : TapeTable)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    overlay (Other := Rp05OtherRawInput bound)
      (fun input => oldOracle (Sum.inl input))
      (fun input => oldOracle (Sum.inr input)) labels statement salt data
      (q38Unopened selected)ᶜ tapes =
    updateRp05Batch 38
      (fun i => Sum.inl (rp05SourceLeafInput statement salt
        (data (selected i)) (selected i) (tapes (selected i))))
      (fun i => labels (selected i)) oldOracle := by
  let keys : Fin 38 → Rp05FullRawInput bound :=
    fun i => Sum.inl (rp05SourceLeafInput statement salt
      (data (selected i)) (selected i) (tapes (selected i)))
  have keyDistinct : Function.Injective keys := by
    intro i j same
    apply distinct
    have indices := congrArg rp05FullIndex same
    simpa [keys, rp05FullIndex, rp05_source_leaf_index_projection] using indices
  have support_eq :
      support (Other := Rp05OtherRawInput bound) statement salt data
        (q38Unopened selected)ᶜ tapes = Finset.univ.image keys := by
    simp only [support, q38Unopened, compl_compl]
    rw [Finset.image_image]
    rfl
  funext input
  by_cases member : input ∈ Finset.univ.image keys
  · obtain ⟨i, _, equal⟩ := Finset.mem_image.mp member
    subst input
    rw [update_rp05_batch_at 38 keys (fun i => labels (selected i))
      oldOracle keyDistinct i]
    simp [overlay, support_eq, member, keys,
      rp05_source_leaf_index_projection]
  · have outside : ∀ i, input ≠ keys i := by
      intro i equal
      apply member
      exact Finset.mem_image.mpr ⟨i, Finset.mem_univ i, equal.symm⟩
    rw [update_rp05_batch_outside 38 keys
      (fun i => labels (selected i)) oldOracle input outside]
    cases input with
    | inl leaf => simp [overlay, support_eq, member]
    | inr other => simp [overlay, support_eq, member]

/-- The corrected public game averages runs with the literal selector
result and its exact abort-aware opened-leaf overlay on the old state. -/
theorem current_public_game_tape_average
    {Work : Type} [Fintype Work]
    (bound : Nat) (randomized : Bool)
    (points : Fin 6 → Goldilocks)
    (selector : NonleafProgram (Rp05OtherRawInput bound)
      (SelectionResult points))
    (program : (job : SelectionResult points) →
      (Opened (rp05AbortAwareUnopened job) → LeafTape) →
        Program (Rp05FullRawInput bound) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Rp05OtherRawInput bound → DigestRegister)
    (labels : LeafIndex → DigestRegister)
    (statement : Statement) (salt : SaltBytes)
    (data : LeafIndex → Fin 1176 → Byte)
    (state : GameState
      (Input := Rp05FullRawInput bound) (Work := Work)) :
    let result := NonleafProgram.interpret other selector
    publicGame randomized (asSelection selector) rp05AbortAwareUnopened
      program old other labels statement salt data state =
    uniformAverage fun tapes : TapeTable =>
      run randomized
        (program result ((tapeSplit (rp05AbortAwareUnopened result) tapes).1))
        (match result.targets with
          | none => Sum.elim old other
          | some targets => updateRp05Batch 38
              (fun i => Sum.inl (rp05SourceLeafInput statement salt
                (data (targets.val i)) (targets.val i)
                  (tapes (targets.val i))))
              (fun i => labels (targets.val i)) (Sum.elim old other)) state := by
  let result := NonleafProgram.interpret other selector
  unfold publicGame
  apply congrArg uniformAverage
  funext tapes
  rw [execute_as_selection selector
    (publicKernel randomized rp05AbortAwareUnopened program old other
      labels statement salt data tapes) (Sum.elim old other) state]
  change run randomized
      (program result ((tapeSplit (rp05AbortAwareUnopened result) tapes).1))
      (overlay old other labels statement salt data
        (rp05AbortAwareUnopened result)ᶜ tapes) state = _
  cases h : result.targets with
  | none =>
      have openedNone : (rp05AbortAwareUnopened result)ᶜ = ∅ := by
        simp [rp05AbortAwareUnopened, h]
      dsimp only [result] at *
      have oracleEq :
          HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening.overlay
            (Other := Rp05OtherRawInput bound) old other labels statement salt
            data ∅ tapes = Sum.elim old other := by
        funext input
        simp [HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening.overlay,
          HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening.support]
      rw [openedNone, oracleEq]
  | some targets =>
      have openedSet : rp05AbortAwareUnopened result =
          V8SmzaLeafFrameHybrid.q38Unopened targets.val := by
        simp [rp05AbortAwareUnopened, h]
      have oracleEq :
          overlay old other labels statement salt data
              (rp05AbortAwareUnopened result)ᶜ tapes =
            updateRp05Batch 38
              (fun i => Sum.inl (rp05SourceLeafInput statement salt
                (data (targets.val i)) (targets.val i) (tapes (targets.val i))))
              (fun i => labels (targets.val i)) (Sum.elim old other) := by
        rw [openedSet]
        exact current_opened_overlay_eq_batch bound statement salt data
          targets.val targets.property.1 labels tapes (Sum.elim old other)
      rw [oracleEq]

/-- For the actual selected-byte continuation, the corrected public game
is an average of the very bytes serialized from each full tape table.
No padded unopened tape is observable in the successful or abort branch. -/
theorem current_public_selected_byte_average
    {bound : Nat} {Work : Type} [Fintype Work]
    (randomized : Bool)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister))
    (selector : NonleafProgram (Rp05OtherRawInput bound)
      (SelectionResult opening.points))
    (next : Except String (List Byte) →
      Program (Rp05FullRawInput bound) Work)
    (old : Rp05LeafInput → DigestRegister)
    (other : Rp05OtherRawInput bound → DigestRegister)
    (labels : LeafIndex → DigestRegister)
    (data : LeafIndex → Fin 1176 → Byte)
    (state : GameState
      (Input := Rp05FullRawInput bound) (Work := Work)) :
    let result := NonleafProgram.interpret other selector
    publicGame randomized (asSelection selector) rp05AbortAwareUnopened
      (currentSelectedContinuation dsl statement parameters opening values base q
        gamma reply transcript digest salt tree next)
      old other labels statement salt data state =
    uniformAverage fun tapes : TapeTable =>
      run randomized
        (next (selectedBytes dsl statement parameters opening gamma reply
          transcript digest salt tree tapes
          (selectedPhysicalView values base q reply result) result))
        (match result.targets with
          | none => Sum.elim old other
          | some targets => updateRp05Batch 38
              (fun i => Sum.inl (rp05SourceLeafInput statement salt
                (data (targets.val i)) (targets.val i)
                  (tapes (targets.val i))))
              (fun i => labels (targets.val i)) (Sum.elim old other)) state := by
  let result := NonleafProgram.interpret other selector
  rw [current_public_game_tape_average]
  apply congrArg uniformAverage
  funext tapes
  cases h : result.targets with
  | none =>
      rw [current_selected_continuation_on_real_tapes]
  | some targets =>
      rw [current_selected_continuation_on_real_tapes]

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentAdaptiveOpening
