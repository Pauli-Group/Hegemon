import HegemonCrypto.SmallWoodV8Smz9MeasuredSourceHiddenPatch

/-! A measured preselection program ending in an explicit reveal continuation.
The continuation may depend on all tapes; the preselection program may not.
Oracle answers, complete measurement outcomes and independent coins can all
adaptively select the reveal job. Unlike applying a fixed-program oracle
hybrid to a tape-dependent whole program, this charges exactly the selecPrefix.

The oracle is read-only during the selecPrefix. This models ordinary ROM calls
after the atomic leaf commitment and before opening; it does not identify
the honest leaf batch with independently sampled/programmed leaf labels. -/
namespace HegemonCrypto.SmallWood.V8SmzaSelectionFeedback
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9HonestWholeViewGames
open V8Smz9MeasuredRunContinuity V8Smz9MeasuredOracleHybrid
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

inductive Selection (Input Work Job : Type) [Fintype Input] [Fintype Work] : Type 1 where
  | reveal (job : Job)
  | gate (operation : GameGate (Input := Input) (Work := Work)) (next : Selection Input Work Job)
  | quantumQuery (next : Selection Input Work Job)
  | honestRead (input : Input) (next : DigestRegister → Selection Input Work Job)
  | instrument {count : Nat} (operation : Instrument Input Work count)
      (next : Fin count → Selection Input Work Job)
  | random (source : RandomSource) (next : source.Coins → Selection Input Work Job)

variable {Input Work Job Secret : Type}
variable [Fintype Input] [DecidableEq Input] [Fintype Work]

abbrev Kernel := Job → GameState (Input := Input) (Work := Work) → ℝ

def execute : Selection Input Work Job → Kernel (Input := Input) (Work := Work) (Job := Job) →
    (Input → DigestRegister) → GameState (Input := Input) (Work := Work) → ℝ
  | .reveal job, next, _oracle, state => next job state
  | .gate operation tail, next, oracle, state => execute tail next oracle (operation state)
  | .quantumQuery tail, next, oracle, state => execute tail next oracle (query oracle state)
  | .honestRead input tail, next, oracle, state => execute (tail (oracle input)) next oracle state
  | .instrument operation tail, next, oracle, state =>
      ∑ branch, execute (tail branch) next oracle (operation.branch branch state)
  | .random source tail, next, oracle, state =>
      uniformAverage fun coin : source.Coins => execute (tail coin) next oracle state

def exposures : Selection Input Work Job → Nat
  | .reveal _ => 0
  | .gate _ tail => exposures tail
  | .quantumQuery tail => exposures tail + 1
  | .honestRead _ tail => (Finset.univ.sup fun answer => exposures (tail answer)) + 1
  | .instrument _ tail => Finset.univ.sup fun branch => exposures (tail branch)
  | .random _ tail => Finset.univ.sup fun coin => exposures (tail coin)

structure PhysicalKernel (Job : Type) where
  observe : Kernel (Input := Input) (Work := Work) (Job := Job)
  probability : ∀ job state, 0 ≤ observe job state ∧ observe job state ≤ ‖state‖ ^ 2
  continuity : ∀ job left right,
    |observe job left - observe job right| ≤ (‖left‖ + ‖right‖) * ‖left - right‖

/-- This constructs the physical endpoint from an actual measured oracle
program, rather than taking its event distribution or security as a premise. -/
def programKernel (randomized : Bool) (program : Job → Program Input Work)
    (oracle : Job → Input → DigestRegister) : PhysicalKernel (Input := Input) (Work := Work) Job where
  observe job state := V8Smz9HonestWholeViewGames.run randomized (program job) (oracle job) state
  probability job state := run_has_physical_probability randomized (program job) (oracle job) state
  continuity job left right := run_difference_subnormalized randomized (program job) (oracle job) left right

def selectedKernel (selecPrefix : Selection Input Work Job)
    (next : PhysicalKernel (Input := Input) (Work := Work) Job)
    (oracle : Input → DigestRegister) : PhysicalKernel (Input := Input) (Work := Work) Unit := by
  induction selecPrefix with
  | reveal job =>
      exact ⟨fun _ => next.observe job, fun _ => next.probability job, fun _ => next.continuity job⟩
  | gate operation tail ih =>
      refine ⟨fun _ state => ih.observe () (operation state), ?_, ?_⟩
      · intro _ state
        simpa only [operation.norm_map] using ih.probability () (operation state)
      · intro _ left right
        simpa only [← map_sub, operation.norm_map] using ih.continuity () (operation left) (operation right)
  | quantumQuery tail ih =>
      refine ⟨fun _ state => ih.observe () (query oracle state), ?_, ?_⟩
      · intro _ state
        simpa only [(query oracle).norm_map] using ih.probability () (query oracle state)
      · intro _ left right
        simpa only [← map_sub, (query oracle).norm_map] using ih.continuity () (query oracle left) (query oracle right)
  | honestRead input tail ih => exact ih (oracle input)
  | instrument operation tail ih =>
      refine ⟨fun _ state => ∑ branch, (ih branch).observe () (operation.branch branch state), ?_, ?_⟩
      · intro _ state
        constructor
        · exact Finset.sum_nonneg fun branch _ => ((ih branch).probability () _).1
        · exact (Finset.sum_le_sum fun branch _ => ((ih branch).probability () _).2).trans_eq
            (operation.complete state)
      · intro _ left right
        rw [← Finset.sum_sub_distrib]
        calc
          _ ≤ ∑ branch, |(ih branch).observe () (operation.branch branch left) -
              (ih branch).observe () (operation.branch branch right)| := Finset.abs_sum_le_sum_abs _ _
          _ ≤ ∑ branch, (‖operation.branch branch left‖ + ‖operation.branch branch right‖) *
              ‖operation.branch branch (left - right)‖ := by
            apply Finset.sum_le_sum
            intro branch _
            simpa only [map_sub] using (ih branch).continuity () (operation.branch branch left)
              (operation.branch branch right)
          _ = (∑ branch, ‖operation.branch branch left‖ * ‖operation.branch branch (left - right)‖) +
              ∑ branch, ‖operation.branch branch right‖ * ‖operation.branch branch (left - right)‖ := by
            simp only [add_mul, Finset.sum_add_distrib]
          _ ≤ ‖left‖ * ‖left - right‖ + ‖right‖ * ‖left - right‖ :=
            add_le_add (instrument_norm_products_le operation left (left - right))
              (instrument_norm_products_le operation right (left - right))
          _ = _ := by ring
  | random source tail ih =>
      refine ⟨fun _ state => uniformAverage fun coin : source.Coins => (ih coin).observe () state, ?_, ?_⟩
      · intro _ state
        exact uniform_average_bounds _ _ fun coin => (ih coin).probability () state
      · intro _ left right
        exact (average_difference_abs_le _ _).trans
          (average_le_const _ _ fun coin => (ih coin).continuity () left right)

omit [DecidableEq Input] in
theorem selected_kernel_executes (selecPrefix : Selection Input Work Job)
    (next : PhysicalKernel (Input := Input) (Work := Work) Job)
    (oracle : Input → DigestRegister) (state : GameState (Input := Input) (Work := Work)) :
    (selectedKernel selecPrefix next oracle).observe () state = execute selecPrefix next.observe oracle state := by
  induction selecPrefix generalizing state with
  | reveal job => rfl
  | gate operation tail ih => exact ih (operation state)
  | quantumQuery tail ih => exact ih (query oracle state)
  | honestRead input tail ih => exact ih (oracle input) state
  | instrument operation tail ih =>
      change (∑ branch, (selectedKernel (tail branch) next oracle).observe () (operation.branch branch state)) =
        ∑ branch, execute (tail branch) next.observe oracle (operation.branch branch state)
      exact Finset.sum_congr rfl fun branch _ => ih branch (operation.branch branch state)
  | random source tail ih => exact congrArg uniformAverage (funext fun coin => ih coin state)

omit [DecidableEq Input] in
theorem execution_probability (selecPrefix : Selection Input Work Job)
    (next : PhysicalKernel (Input := Input) (Work := Work) Job)
    (oracle : Input → DigestRegister) (state : GameState (Input := Input) (Work := Work)) :
    0 ≤ execute selecPrefix next.observe oracle state ∧ execute selecPrefix next.observe oracle state ≤ ‖state‖ ^ 2 := by
  rw [← selected_kernel_executes]
  exact (selectedKernel selecPrefix next oracle).probability () state

omit [DecidableEq Input] in
theorem execution_continuity (selecPrefix : Selection Input Work Job)
    (next : PhysicalKernel (Input := Input) (Work := Work) Job)
    (oracle : Input → DigestRegister) (left right : GameState (Input := Input) (Work := Work)) :
    |execute selecPrefix next.observe oracle left - execute selecPrefix next.observe oracle right| ≤
      (‖left‖ + ‖right‖) * ‖left - right‖ := by
  simp_rw [← selected_kernel_executes selecPrefix next oracle]
  exact (selectedKernel selecPrefix next oracle).continuity () left right

variable [Fintype Secret] [Nonempty Secret]

def feedbackDistance (selecPrefix : Selection Input Work Job)
    (next : Secret → PhysicalKernel (Input := Input) (Work := Work) Job)
    (old : Input → DigestRegister) (patched : Secret → Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) : ℝ :=
  uniformAverage fun secret =>
    |execute selecPrefix (next secret).observe (patched secret) state - execute selecPrefix (next secret).observe old state|

/-- The reveal continuation depends on the hidden table in BOTH games.
Only preselection oracle feedback is removed. Complete measurement branches
retain their subnormalized weight; no postselection independence is assumed. -/
theorem remove_preselection_feedback
    (selecPrefix : Selection Input Work Job)
    (next : Secret → PhysicalKernel (Input := Input) (Work := Work) Job)
    (support : Secret → Finset Input) (p : ℝ) (nonnegative : 0 ≤ p) (atMostOne : p ≤ 1)
    (bounded : ∀ input, supportCount support input ≤ (Fintype.card Secret : ℝ) * p)
    (old : Input → DigestRegister) (patched : Secret → Input → DigestRegister)
    (same : ∀ secret input, input ∉ support secret → old input = patched secret input)
    (state : GameState (Input := Input) (Work := Work)) :
    feedbackDistance selecPrefix next old patched state ≤ queryLoss p (exposures selecPrefix) state := by
  induction selecPrefix generalizing state with
  | reveal job => simp [feedbackDistance, execute, exposures, queryLoss, uniform_average_const]
  | gate operation tail ih =>
      simpa only [feedbackDistance, execute, exposures, queryLoss, operation.norm_map] using ih (operation state)
  | quantumQuery tail ih =>
      have pointwise (secret : Secret) :
          |execute tail (next secret).observe (patched secret) (query (patched secret) state) -
            execute tail (next secret).observe old (query old state)| ≤
          2 * ‖state‖ * ‖query (patched secret) state - query old state‖ +
            |execute tail (next secret).observe (patched secret) (query old state) -
              execute tail (next secret).observe old (query old state)| := by
        have continuity := execution_continuity tail (next secret) (patched secret)
          (query (patched secret) state) (query old state)
        simp only [(query (patched secret)).norm_map, (query old).norm_map] at continuity
        exact (abs_sub_le _ _ _).trans (add_le_add (by simpa only [two_mul] using continuity) le_rfl)
      calc
        _ ≤ uniformAverage (fun secret => 2 * ‖state‖ * ‖query (patched secret) state - query old state‖ +
            |execute tail (next secret).observe (patched secret) (query old state) -
              execute tail (next secret).observe old (query old state)|) := average_mono _ _ pointwise
        _ = 2 * ‖state‖ * uniformAverage (fun secret => ‖query (patched secret) state - query old state‖) +
            feedbackDistance tail next old patched (query old state) := by
          rw [average_add, average_mul_left]
          rfl
        _ ≤ 2 * ‖state‖ * (2 * Real.sqrt p * ‖state‖) + queryLoss p (exposures tail) (query old state) :=
          add_le_add (mul_le_mul_of_nonneg_left
            (average_query_distance_le old patched support p nonnegative same bounded state) (by positivity))
            (ih (query old state))
        _ = _ := by simp only [queryLoss, exposures, (query old).norm_map, Nat.cast_add, Nat.cast_one]; ring
  | honestRead input tail ih =>
      let remaining := Finset.univ.sup fun answer => exposures (tail answer)
      have pointwise (secret : Secret) :
          |execute (tail (patched secret input)) (next secret).observe (patched secret) state -
            execute (tail (old input)) (next secret).observe old state| ≤
          (if input ∈ support secret then (1 : ℝ) else 0) * ‖state‖ ^ 2 +
            |execute (tail (old input)) (next secret).observe (patched secret) state -
              execute (tail (old input)) (next secret).observe old state| := by
        have branchBound :
            |execute (tail (patched secret input)) (next secret).observe (patched secret) state -
              execute (tail (old input)) (next secret).observe (patched secret) state| ≤
              (if input ∈ support secret then (1 : ℝ) else 0) * ‖state‖ ^ 2 := by
          by_cases member : input ∈ support secret
          · rw [if_pos member, one_mul]
            have left := execution_probability (tail (patched secret input)) (next secret) (patched secret) state
            have right := execution_probability (tail (old input)) (next secret) (patched secret) state
            exact abs_le.mpr ⟨by linarith, by linarith⟩
          · rw [if_neg member, zero_mul, ← same secret input member, sub_self, abs_zero]
        exact (abs_sub_le _ _ _).trans (add_le_add branchBound le_rfl)
      calc
        _ ≤ uniformAverage (fun secret => (if input ∈ support secret then (1 : ℝ) else 0) * ‖state‖ ^ 2 +
            |execute (tail (old input)) (next secret).observe (patched secret) state -
              execute (tail (old input)) (next secret).observe old state|) := average_mono _ _ pointwise
        _ = uniformAverage (fun secret => if input ∈ support secret then (1 : ℝ) else 0) * ‖state‖ ^ 2 +
            feedbackDistance (tail (old input)) next old patched state := by rw [average_add, average_mul_right]; rfl
        _ ≤ p * ‖state‖ ^ 2 + queryLoss p remaining state :=
          add_le_add (mul_le_mul_of_nonneg_right (average_support_indicator_le support p bounded input) (sq_nonneg _))
            ((ih (old input) state).trans (query_loss_mono p (Finset.le_sup (f := fun answer => exposures (tail answer))
              (Finset.mem_univ (old input))) state))
        _ ≤ 4 * Real.sqrt p * ‖state‖ ^ 2 + queryLoss p remaining state :=
          add_le_add (mul_le_mul_of_nonneg_right (p_le_four_sqrt nonnegative atMostOne) (sq_nonneg _)) le_rfl
        _ = _ := by simp only [queryLoss, exposures, remaining, Nat.cast_add, Nat.cast_one]; ring
  | instrument operation tail ih =>
      have pointwise (secret : Secret) :
          |execute (.instrument operation tail) (next secret).observe (patched secret) state -
            execute (.instrument operation tail) (next secret).observe old state| ≤
          ∑ branch, |execute (tail branch) (next secret).observe (patched secret) (operation.branch branch state) -
            execute (tail branch) (next secret).observe old (operation.branch branch state)| := by
        simp only [execute, ← Finset.sum_sub_distrib]
        exact Finset.abs_sum_le_sum_abs _ _
      calc
        _ ≤ uniformAverage (fun secret => ∑ branch, |execute (tail branch) (next secret).observe
            (patched secret) (operation.branch branch state) -
            execute (tail branch) (next secret).observe old (operation.branch branch state)|) := average_mono _ _ pointwise
        _ = ∑ branch, feedbackDistance (tail branch) next old patched (operation.branch branch state) := by rw [average_sum]; rfl
        _ ≤ ∑ branch, queryLoss p (exposures (.instrument operation tail)) (operation.branch branch state) := by
          apply Finset.sum_le_sum
          intro branch _
          exact (ih branch (operation.branch branch state)).trans (query_loss_mono p
            (Finset.le_sup (f := fun branch => exposures (tail branch)) (Finset.mem_univ branch)) _)
        _ = _ := by simp only [queryLoss, ← Finset.mul_sum, operation.complete]
  | random source tail ih =>
      simp only [feedbackDistance, execute]
      apply (average_mono _ _ (fun _ => average_difference_abs_le _ _)).trans
      rw [uniform_average_comm]
      exact average_le_const _ _ (fun coin => (ih coin state).trans (query_loss_mono p
        (Finset.le_sup (f := fun coin => exposures (tail coin)) (Finset.mem_univ coin)) state))

end
end HegemonCrypto.SmallWood.V8SmzaSelectionFeedback
