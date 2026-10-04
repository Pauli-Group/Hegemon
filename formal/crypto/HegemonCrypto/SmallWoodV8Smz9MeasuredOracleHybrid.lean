import HegemonCrypto.SmallWoodV8Smz9MeasuredRunContinuity

namespace HegemonCrypto.SmallWood.V8Smz9MeasuredOracleHybrid

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9HonestWholeViewGames V8Smz9MeasuredRunContinuity
open scoped BigOperators Classical ENNReal

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Input Work Secret : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]
variable [Fintype Secret] [Nonempty Secret]

theorem average_eq_sum_div (value : Secret → ℝ) :
    uniformAverage value = (∑ secret, value secret) / (Fintype.card Secret : ℝ) := by
  simp only [uniformAverage, uniformFintypePMF_apply, ENNReal.toReal_inv, ENNReal.toReal_natCast]
  rw [← Finset.mul_sum, div_eq_mul_inv, mul_comm]

omit [Fintype Input] in
theorem average_support_indicator_le (support : Secret → Finset Input) (p : ℝ)
    (bounded : ∀ input, supportCount support input ≤ (Fintype.card Secret : ℝ) * p)
    (input : Input) :
    uniformAverage (fun secret => if input ∈ support secret then (1 : ℝ) else 0) ≤ p := by
  rw [average_eq_sum_div]
  have positive : (0 : ℝ) < Fintype.card Secret := by exact_mod_cast Fintype.card_pos
  apply (div_le_iff₀ positive).2
  simpa only [supportCount, mul_comm] using bounded input

theorem average_query_distance_le (oldOracle : Input → DigestRegister)
    (newOracle : Secret → Input → DigestRegister) (support : Secret → Finset Input) (p : ℝ)
    (nonnegative : 0 ≤ p)
    (same : ∀ secret input, input ∉ support secret → oldOracle input = newOracle secret input)
    (bounded : ∀ input, supportCount support input ≤ (Fintype.card Secret : ℝ) * p)
    (state : GameState (Input := Input) (Work := Work)) :
    uniformAverage (fun secret => ‖query (newOracle secret) state - query oldOracle state‖) ≤
      2 * Real.sqrt p * ‖state‖ := by
  have positive : (0 : ℝ) < Fintype.card Secret := by exact_mod_cast Fintype.card_pos
  have sumBound : (∑ secret, ‖query (newOracle secret) state - query oldOracle state‖) ≤
      2 * (Fintype.card Secret : ℝ) * Real.sqrt p * ‖state‖ := by
    apply (sq_le_sq₀ (Finset.sum_nonneg fun _ _ => norm_nonneg _) (by positivity)).1
    calc
      _ ≤ (Fintype.card Secret : ℝ) *
          ∑ secret, ‖query (newOracle secret) state - query oldOracle state‖ ^ 2 := by
        simpa using sq_sum_le_card_mul_sum_sq (s := (Finset.univ : Finset Secret))
          (f := fun secret => ‖query (newOracle secret) state - query oldOracle state‖)
      _ ≤ (Fintype.card Secret : ℝ) *
          (4 * ((Fintype.card Secret : ℝ) * p * ‖state‖ ^ 2)) :=
        mul_le_mul_of_nonneg_left
          (sum_query_difference_sq_le oldOracle newOracle support p same bounded state) positive.le
      _ = _ := by simp only [mul_pow, Real.sq_sqrt nonnegative]; ring
  rw [average_eq_sum_div]
  apply (div_le_iff₀ positive).2
  exact sumBound.trans_eq (by ring)

def programDistance (randomized : Bool) (program : Program Input Work)
    (oldOracle : Input → DigestRegister) (newOracle : Secret → Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) : ℝ :=
  uniformAverage fun secret =>
    |V8Smz9HonestWholeViewGames.run randomized program (newOracle secret) state -
      V8Smz9HonestWholeViewGames.run randomized program oldOracle state|

def queryLoss (p : ℝ) (queries : Nat)
    (state : GameState (Input := Input) (Work := Work)) : ℝ :=
  4 * (queries : ℝ) * Real.sqrt p * ‖state‖ ^ 2

omit [DecidableEq Input] in
theorem query_loss_mono (p : ℝ) {left right : Nat} (bounded : left ≤ right)
    (state : GameState (Input := Input) (Work := Work)) :
    queryLoss p left state ≤ queryLoss p right state := by
  unfold queryLoss
  gcongr

theorem p_le_four_sqrt {p : ℝ} (nonnegative : 0 ≤ p) (atMostOne : p ≤ 1) :
    p ≤ 4 * Real.sqrt p := by
  have square := Real.sq_sqrt nonnegative
  have rootNonnegative := Real.sqrt_nonneg p
  nlinarith

/-- A classical oracle-result branch is not free advice: a changed answer
costs its changed-input probability, even when the next program is arbitrary. -/
theorem charged_read_distance_le (randomized : Bool)
    (next : DigestRegister → Program Input Work) (input : Input)
    (oldOracle : Input → DigestRegister) (newOracle : Secret → Input → DigestRegister)
    (support : Secret → Finset Input) (p : ℝ) (nonnegative : 0 ≤ p) (atMostOne : p ≤ 1)
    (same : ∀ secret point, point ∉ support secret → oldOracle point = newOracle secret point)
    (bounded : ∀ point, supportCount support point ≤ (Fintype.card Secret : ℝ) * p)
    (state : GameState (Input := Input) (Work := Work)) (remaining : Nat)
    (continuationBound : ∀ answer,
      programDistance randomized (next answer) oldOracle newOracle state ≤ queryLoss p remaining state) :
    uniformAverage (fun secret =>
      |V8Smz9HonestWholeViewGames.run randomized (next (newOracle secret input)) (newOracle secret) state -
        V8Smz9HonestWholeViewGames.run randomized (next (oldOracle input)) oldOracle state|) ≤
      queryLoss p (remaining + 1) state := by
  have pointwise (secret : Secret) :
      |V8Smz9HonestWholeViewGames.run randomized (next (newOracle secret input)) (newOracle secret) state -
        V8Smz9HonestWholeViewGames.run randomized (next (oldOracle input)) oldOracle state| ≤
      (if input ∈ support secret then (1 : ℝ) else 0) * ‖state‖ ^ 2 +
        |V8Smz9HonestWholeViewGames.run randomized (next (oldOracle input)) (newOracle secret) state -
          V8Smz9HonestWholeViewGames.run randomized (next (oldOracle input)) oldOracle state| := by
    have branchBound :
        |V8Smz9HonestWholeViewGames.run randomized (next (newOracle secret input)) (newOracle secret) state -
          V8Smz9HonestWholeViewGames.run randomized (next (oldOracle input)) (newOracle secret) state| ≤
        (if input ∈ support secret then (1 : ℝ) else 0) * ‖state‖ ^ 2 := by
      by_cases member : input ∈ support secret
      · rw [if_pos member, one_mul]
        have left := run_has_physical_probability randomized (next (newOracle secret input)) (newOracle secret) state
        have right := run_has_physical_probability randomized (next (oldOracle input)) (newOracle secret) state
        exact abs_le.mpr ⟨by linarith, by linarith⟩
      · rw [if_neg member, zero_mul, ← same secret input member, sub_self, abs_zero]
    exact (abs_sub_le _ _ _).trans (add_le_add branchBound le_rfl)
  calc
    _ ≤ uniformAverage (fun secret =>
        (if input ∈ support secret then (1 : ℝ) else 0) * ‖state‖ ^ 2 +
        |V8Smz9HonestWholeViewGames.run randomized (next (oldOracle input)) (newOracle secret) state -
          V8Smz9HonestWholeViewGames.run randomized (next (oldOracle input)) oldOracle state|) :=
      average_mono _ _ pointwise
    _ = uniformAverage (fun secret => if input ∈ support secret then (1 : ℝ) else 0) * ‖state‖ ^ 2 +
        programDistance randomized (next (oldOracle input)) oldOracle newOracle state := by
      rw [average_add, average_mul_right]
      rfl
    _ ≤ p * ‖state‖ ^ 2 + queryLoss p remaining state :=
      add_le_add (mul_le_mul_of_nonneg_right (average_support_indicator_le support p bounded input) (sq_nonneg _))
        (continuationBound (oldOracle input))
    _ ≤ 4 * Real.sqrt p * ‖state‖ ^ 2 + queryLoss p remaining state :=
      add_le_add (mul_le_mul_of_nonneg_right (p_le_four_sqrt nonnegative atMostOne) (sq_nonneg _)) le_rfl
    _ = _ := by simp only [queryLoss, Nat.cast_add, Nat.cast_one]; ring

omit [Fintype Input] [Fintype Secret] [Nonempty Secret] in
theorem same_outside_after_update
    (oldOracle : Input → DigestRegister) (newOracle : Secret → Input → DigestRegister)
    (support : Secret → Finset Input)
    (same : ∀ secret point, point ∉ support secret → oldOracle point = newOracle secret point)
    (input : Input) (answer : DigestRegister) :
    ∀ secret point, point ∉ support secret →
      Function.update oldOracle input answer point = Function.update (newOracle secret) input answer point := by
  intro secret point outside
  by_cases equal : point = input
  · subst point
    simp only [Function.update_self]
  · simp only [Function.update_of_ne equal, same secret point outside]

/-- Direct hybrid for the actual complete measured interpreter. Initial state,
reference table and program do not depend on the hidden secret. Arbitrary
subnormalized instrument branches and persistent fresh updates are retained. -/
theorem measured_program_hidden_patch_bound
    (randomized : Bool) (program : Program Input Work)
    (support : Secret → Finset Input) (p : ℝ) (nonnegative : 0 ≤ p) (atMostOne : p ≤ 1)
    (bounded : ∀ input, supportCount support input ≤ (Fintype.card Secret : ℝ) * p)
    (oldOracle : Input → DigestRegister) (newOracle : Secret → Input → DigestRegister)
    (same : ∀ secret input, input ∉ support secret → oldOracle input = newOracle secret input)
    (state : GameState (Input := Input) (Work := Work)) :
    programDistance randomized program oldOracle newOracle state ≤ queryLoss p (queryCount program) state := by
  induction program generalizing oldOracle newOracle state with
  | finish event => simp [programDistance, V8Smz9HonestWholeViewGames.run, queryCount, queryLoss, uniform_average_const]
  | gate operation next ih =>
      simpa only [programDistance, V8Smz9HonestWholeViewGames.run, queryCount, queryLoss, operation.norm_map] using
        ih oldOracle newOracle same (operation state)
  | quantumQuery next ih =>
      have pointwise (secret : Secret) :
          |V8Smz9HonestWholeViewGames.run randomized next (newOracle secret) (query (newOracle secret) state) -
            V8Smz9HonestWholeViewGames.run randomized next oldOracle (query oldOracle state)| ≤
          2 * ‖state‖ * ‖query (newOracle secret) state - query oldOracle state‖ +
            |V8Smz9HonestWholeViewGames.run randomized next (newOracle secret) (query oldOracle state) -
              V8Smz9HonestWholeViewGames.run randomized next oldOracle (query oldOracle state)| := by
        have continuity := run_difference_subnormalized randomized next (newOracle secret)
          (query (newOracle secret) state) (query oldOracle state)
        simp only [(query (newOracle secret)).norm_map, (query oldOracle).norm_map] at continuity
        exact (abs_sub_le _ _ _).trans (add_le_add (by simpa only [two_mul] using continuity) le_rfl)
      calc
        _ ≤ uniformAverage (fun secret =>
            2 * ‖state‖ * ‖query (newOracle secret) state - query oldOracle state‖ +
            |V8Smz9HonestWholeViewGames.run randomized next (newOracle secret) (query oldOracle state) -
              V8Smz9HonestWholeViewGames.run randomized next oldOracle (query oldOracle state)|) :=
          average_mono _ _ pointwise
        _ = 2 * ‖state‖ * uniformAverage (fun secret =>
            ‖query (newOracle secret) state - query oldOracle state‖) +
            programDistance randomized next oldOracle newOracle (query oldOracle state) := by
          rw [average_add, average_mul_left]
          rfl
        _ ≤ 2 * ‖state‖ * (2 * Real.sqrt p * ‖state‖) +
            queryLoss p (queryCount next) (query oldOracle state) :=
          add_le_add (mul_le_mul_of_nonneg_left
            (average_query_distance_le oldOracle newOracle support p nonnegative same bounded state) (by positivity))
            (ih oldOracle newOracle same (query oldOracle state))
        _ = _ := by
          simp only [queryLoss, queryCount, (query oldOracle).norm_map, Nat.cast_add, Nat.cast_one]
          ring
  | honestRead input next ih =>
      apply charged_read_distance_le randomized next input oldOracle newOracle support p
        nonnegative atMostOne same bounded state
      intro answer
      exact (ih answer oldOracle newOracle same state).trans
        (query_loss_mono p (Finset.le_sup (f := fun answer => queryCount (next answer))
          (Finset.mem_univ answer)) state)
  | instrument operation next ih =>
      have pointwise (secret : Secret) :
          |V8Smz9HonestWholeViewGames.run randomized (.instrument operation next) (newOracle secret) state -
            V8Smz9HonestWholeViewGames.run randomized (.instrument operation next) oldOracle state| ≤
          ∑ branch, |V8Smz9HonestWholeViewGames.run randomized (next branch) (newOracle secret)
              (operation.branch branch state) -
            V8Smz9HonestWholeViewGames.run randomized (next branch) oldOracle (operation.branch branch state)| := by
        simp only [V8Smz9HonestWholeViewGames.run, ← Finset.sum_sub_distrib]
        exact Finset.abs_sum_le_sum_abs _ _
      calc
        _ ≤ uniformAverage (fun secret => ∑ branch,
            |V8Smz9HonestWholeViewGames.run randomized (next branch) (newOracle secret) (operation.branch branch state) -
              V8Smz9HonestWholeViewGames.run randomized (next branch) oldOracle (operation.branch branch state)|) :=
          average_mono _ _ pointwise
        _ = ∑ branch, programDistance randomized (next branch) oldOracle newOracle (operation.branch branch state) :=
          average_sum _
        _ ≤ ∑ branch, queryLoss p (queryCount (.instrument operation next)) (operation.branch branch state) := by
          apply Finset.sum_le_sum
          intro branch _
          exact (ih branch oldOracle newOracle same (operation.branch branch state)).trans
            (query_loss_mono p (Finset.le_sup (f := fun branch => queryCount (next branch))
              (Finset.mem_univ branch)) _)
        _ = _ := by simp only [queryLoss, ← Finset.mul_sum, operation.complete]
  | random source next ih =>
      calc
        _ ≤ uniformAverage (fun secret => uniformAverage (fun coin =>
            |V8Smz9HonestWholeViewGames.run randomized (next coin) (newOracle secret) state -
              V8Smz9HonestWholeViewGames.run randomized (next coin) oldOracle state|)) :=
          average_mono _ _ (fun _ => average_difference_abs_le _ _)
        _ = uniformAverage (fun coin => programDistance randomized (next coin) oldOracle newOracle state) :=
          uniform_average_comm _
        _ ≤ _ := average_le_const _ _ (fun coin =>
          (ih coin oldOracle newOracle same state).trans
            (query_loss_mono p (Finset.le_sup (f := fun coin => queryCount (next coin))
              (Finset.mem_univ coin)) state))
  | freshInput sampler next ih =>
      cases randomized with
      | false =>
          simp only [programDistance, V8Smz9HonestWholeViewGames.run, Bool.false_eq_true, if_false,
            uniform_average_const]
          apply (average_mono _ _ (fun _ => average_difference_abs_le _ _)).trans
          rw [uniform_average_comm]
          apply average_le_const
          intro coins
          apply charged_read_distance_le false (next coins) (sampler.input coins)
            oldOracle newOracle support p nonnegative atMostOne same bounded state
          intro answer
          have localBound := ih coins answer oldOracle newOracle same state
          exact localBound.trans (query_loss_mono p
            ((Finset.le_sup (f := fun answer => queryCount (next coins answer)) (Finset.mem_univ answer)).trans
              (Finset.le_sup (f := fun coin => Finset.univ.sup fun output => queryCount (next coin output))
                (Finset.mem_univ coins))) state)
      | true =>
          simp only [programDistance, V8Smz9HonestWholeViewGames.run, if_true, Function.update_self]
          apply (average_mono _ _ (fun _ => average_difference_abs_le _ _)).trans
          rw [uniform_average_comm]
          apply average_le_const
          intro coins
          apply (average_mono _ _ (fun _ => average_difference_abs_le _ _)).trans
          rw [uniform_average_comm]
          apply average_le_const
          intro answer
          have localBound := ih coins answer (Function.update oldOracle (sampler.input coins) answer)
            (fun secret => Function.update (newOracle secret) (sampler.input coins) answer)
            (same_outside_after_update oldOracle newOracle support same (sampler.input coins) answer) state
          exact localBound.trans (query_loss_mono p
            ((Finset.le_sup (f := fun answer => queryCount (next coins answer)) (Finset.mem_univ answer)).trans
              ((Finset.le_sup (f := fun coin => Finset.univ.sup fun output => queryCount (next coin output))
                (Finset.mem_univ coins)).trans (Nat.le_succ _))) state)


end
end HegemonCrypto.SmallWood.V8Smz9MeasuredOracleHybrid
