import HegemonCrypto.SmallWoodV8Smz9MixedMaskSemantics
import HegemonCrypto.SmallWoodV8Smz9MeasuredRunContinuity

/-! One finite, charged lifetime history with an adaptively chosen pivot.
All history actions occur inside this syntax before the initial oracle is
sampled. Measurements keep their unnormalized branches. Fixed writes and
selected updates retain one table; no prior state is supplied as independent
oracle-correlated advice. Actual pivot kernels are instantiated separately. -/

namespace HegemonCrypto.SmallWood.V8Smz9MeasuredPrefix

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9HonestWholeViewGames
open V8Smz9MixedMaskCompiler (MixedProgram)
open V8Smz9MeasuredRunContinuity
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

universe u

inductive Prefix (Input Work : Type) [Fintype Input] [Fintype Work] (Job : Type u) : Type (max 1 u) where
  | finish (event : Finset (QueryBasis Input DigestRegister Work))
  | pivot (job : Job)
  | gate (operation : GameGate (Input := Input) (Work := Work)) (next : Prefix Input Work Job)
  | quantumQuery (next : Prefix Input Work Job)
  | honestRead (input : Input) (next : DigestRegister → Prefix Input Work Job)
  | instrument {count : Nat} (operation : Instrument Input Work count)
      (next : Fin count → Prefix Input Work Job)
  | random (source : RandomSource) (next : source.Coins → Prefix Input Work Job)
  | freshInput (sampler : InputSampler Input)
      (next : sampler.Coins → DigestRegister → Prefix Input Work Job)
  | write (input : Input) (answer : DigestRegister) (next : Prefix Input Work Job)

variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]
variable {Job : Type u}

abbrev PivotKernel (Input Work : Type) [Fintype Input] [Fintype Work] (Job : Type u) :=
  Job → (Input → DigestRegister) → GameState (Input := Input) (Work := Work) → ℝ

def runPrefix (randomized : Bool) : Prefix Input Work Job → PivotKernel Input Work Job →
    (Input → DigestRegister) → GameState (Input := Input) (Work := Work) → ℝ
  | .finish event, _pivot, _oracle, state => born event state
  | .pivot job, pivot, oracle, state => pivot job oracle state
  | .gate operation next, pivot, oracle, state => runPrefix randomized next pivot oracle (operation state)
  | .quantumQuery next, pivot, oracle, state => runPrefix randomized next pivot oracle (query oracle state)
  | .honestRead input next, pivot, oracle, state =>
      runPrefix randomized (next (oracle input)) pivot oracle state
  | .instrument operation next, pivot, oracle, state =>
      ∑ outcome, runPrefix randomized (next outcome) pivot oracle (operation.branch outcome state)
  | .random source next, pivot, oracle, state =>
      uniformAverage fun coins : source.Coins => runPrefix randomized (next coins) pivot oracle state
  | .freshInput sampler next, pivot, oracle, state =>
      uniformAverage fun coins : sampler.Coins => uniformAverage fun answer : DigestRegister =>
        let input := sampler.input coins
        let current := if randomized then Function.update oracle input answer else oracle
        runPrefix randomized (next coins (current input)) pivot current state
  | .write input answer next, pivot, oracle, state =>
      runPrefix randomized next pivot (Function.update oracle input answer) state

def compilePrefix : Prefix Input Work Job → (Job → MixedProgram Input Work) → MixedProgram Input Work
  | .finish event, _pivot => .finish event
  | .pivot job, pivot => pivot job
  | .gate operation next, pivot => .gate operation (compilePrefix next pivot)
  | .quantumQuery next, pivot => .quantumQuery (compilePrefix next pivot)
  | .honestRead input next, pivot => .honestRead input (fun answer => compilePrefix (next answer) pivot)
  | .instrument operation next, pivot => .instrument operation (fun outcome => compilePrefix (next outcome) pivot)
  | .random source next, pivot => .random source (fun coins => compilePrefix (next coins) pivot)
  | .freshInput sampler next, pivot =>
      .freshInput sampler (fun coins answer => compilePrefix (next coins answer) pivot)
  | .write input answer next, pivot => .write input answer (compilePrefix next pivot)

theorem compiled_prefix_executes (randomized : Bool) (history : Prefix Input Work Job)
    (pivot : Job → MixedProgram Input Work) (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run randomized (compilePrefix history pivot) oracle state =
      runPrefix randomized history (fun job => V8Smz9MixedMaskCompiler.run randomized (pivot job)) oracle state := by
  induction history generalizing oracle state with
  | finish event => rfl
  | pivot job => rfl
  | gate operation next ih => exact ih oracle (operation state)
  | quantumQuery next ih => exact ih oracle (query oracle state)
  | honestRead input next ih => exact ih (oracle input) oracle state
  | instrument operation next ih =>
      simp only [compilePrefix, V8Smz9MixedMaskCompiler.run, runPrefix]
      exact Finset.sum_congr rfl (fun outcome _ => ih outcome oracle (operation.branch outcome state))
  | random source next ih =>
      simp only [compilePrefix, V8Smz9MixedMaskCompiler.run, runPrefix]
      exact congrArg uniformAverage (funext fun coins => ih coins oracle state)
  | freshInput sampler next ih =>
      simp only [compilePrefix, V8Smz9MixedMaskCompiler.run, runPrefix]
      apply congrArg uniformAverage
      funext coins
      apply congrArg uniformAverage
      funext answer
      exact ih coins _ _ state
  | write input answer next ih => exact ih (Function.update oracle input answer) state

/-- Generic complete-instrument lifting. The factor is the existing branch
weight, never a conditioned or renormalized success probability. -/
theorem prefix_subnormalized_pivot_bound (randomized : Bool) (history : Prefix Input Work Job)
    (left right : PivotKernel Input Work Job) (loss : ℝ) (nonnegative : 0 ≤ loss)
    (pivotBound : ∀ job oracle state,
      |left job oracle state - right job oracle state| ≤ loss * ‖state‖ ^ 2)
    (oracle : Input → DigestRegister) (state : GameState (Input := Input) (Work := Work)) :
    |runPrefix randomized history left oracle state - runPrefix randomized history right oracle state| ≤
      loss * ‖state‖ ^ 2 := by
  induction history generalizing oracle state with
  | finish event =>
      simpa only [runPrefix, sub_self, abs_zero] using mul_nonneg nonnegative (sq_nonneg ‖state‖)
  | pivot job => exact pivotBound job oracle state
  | gate operation next ih =>
      simpa only [runPrefix, operation.norm_map] using ih oracle (operation state)
  | quantumQuery next ih =>
      simpa only [runPrefix, (query oracle).norm_map] using ih oracle (query oracle state)
  | honestRead input next ih => exact ih (oracle input) oracle state
  | instrument operation next ih =>
      simp only [runPrefix]
      rw [← Finset.sum_sub_distrib]
      calc
        _ ≤ ∑ outcome, |runPrefix randomized (next outcome) left oracle (operation.branch outcome state) -
            runPrefix randomized (next outcome) right oracle (operation.branch outcome state)| :=
          Finset.abs_sum_le_sum_abs _ _
        _ ≤ ∑ outcome, loss * ‖operation.branch outcome state‖ ^ 2 :=
          Finset.sum_le_sum fun outcome _ => ih outcome oracle (operation.branch outcome state)
        _ = _ := by rw [← Finset.mul_sum, operation.complete]
  | random source next ih =>
      exact (average_difference_abs_le _ _).trans
        (average_le_const _ _ fun coins => ih coins oracle state)
  | freshInput sampler next ih =>
      apply (average_difference_abs_le _ _).trans
      apply average_le_const
      intro coins
      exact (average_difference_abs_le _ _).trans
        (average_le_const _ _ fun answer => ih coins _ _ state)
  | write input answer next ih => exact ih (Function.update oracle input answer) state

def prefixAcceptance (randomized : Bool) (history : Prefix Input Work Job)
    (pivot : PivotKernel Input Work Job)
    (initial : GameState (Input := Input) (Work := Work)) : ℝ :=
  uniformAverage fun oracle : Input → DigestRegister => runPrefix randomized history pivot oracle initial

/-- The history and initial state are fixed BEFORE the random oracle draw.
Every correlation at the pivot was generated by a charged action inside the
single history program. The pivot may depend on all actual classical outcomes. -/
theorem actual_history_prefix_pivot_bound (randomized : Bool) (history : Prefix Input Work Job)
    (left right : PivotKernel Input Work Job) (loss : ℝ) (nonnegative : 0 ≤ loss)
    (pivotBound : ∀ job oracle state,
      |left job oracle state - right job oracle state| ≤ loss * ‖state‖ ^ 2)
    (initial : GameState (Input := Input) (Work := Work)) (normalized : ‖initial‖ = 1) :
    |prefixAcceptance randomized history left initial - prefixAcceptance randomized history right initial| ≤ loss := by
  apply (average_difference_abs_le _ _).trans
  apply average_le_const
  intro oracle
  simpa only [normalized, one_pow, mul_one] using
    prefix_subnormalized_pivot_bound randomized history left right loss nonnegative pivotBound oracle initial

/-- Compiled source acceptance, with one initially empty correction log.
No separate oracle-dependent history state or correction advice is an input. -/
theorem compiled_prefix_acceptance (randomized : Bool) (history : Prefix Input Work Job)
    (pivot : Job → MixedProgram Input Work)
    (initial : GameState (Input := Input) (Work := Work)) :
    V8Smz9HonestWholeViewGames.acceptance randomized
      (V8Smz9MixedMaskCompiler.compile (compilePrefix history pivot) []) initial =
    prefixAcceptance randomized history (fun job => V8Smz9MixedMaskCompiler.run randomized (pivot job)) initial := by
  rw [V8Smz9MixedMaskCompiler.compiled_acceptance_eq]
  unfold V8Smz9MixedMaskCompiler.acceptance prefixAcceptance
  exact congrArg uniformAverage (funext fun oracle => compiled_prefix_executes randomized history pivot oracle initial)

end
end HegemonCrypto.SmallWood.V8Smz9MeasuredPrefix
