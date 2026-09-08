import HegemonCrypto.SmallWoodV8Smz9HonestWholeViewGames
import Mathlib.Tactic.Abel

/-! A collision-exact physical compiler for selected reprogrammings interleaved
with fixed classical writes. The effective table is the raw oracle plus a finite
classical correction log. Each fixed write obtains its correction with one
charged raw read; it is not free oracle-correlated advice. A selected raw refresh
remains an effective uniform refresh by an explicit output translation.
-/

namespace HegemonCrypto.SmallWood.V8Smz9MixedMaskCompiler

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9RuntimeDistribution
open V8Smz9HonestWholeViewGames (GameState GameGate Instrument InputSampler RandomSource)
open scoped BigOperators Classical ENNReal



noncomputable section
set_option maxHeartbeats 1000000
set_option maxRecDepth 5000

variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

/-- Finite, newest-first classical records. Repeated addresses are intentional;
the latest correction wins. Nothing is supplied as an oracle-dependent initial
record in the final acceptance adapter. -/
abbrev CorrectionLog (Input : Type) := List (Input × DigestRegister)

def correction : CorrectionLog Input → Input → DigestRegister
  | [], _ => 0
  | (address, value) :: rest, input =>
      if input = address then value else correction rest input

def effective (oracle : Input → DigestRegister) (log : CorrectionLog Input) :
    Input → DigestRegister := fun input => oracle input + correction log input

omit [Fintype Input] in
theorem effective_empty (oracle : Input → DigestRegister) : effective oracle [] = oracle := by
  funext input
  simp only [effective, correction, add_zero]

omit [Fintype Input] in
/-- A fixed write uses the raw answer obtained at the moment of that write,
not a stale value from an earlier version of the table. -/
theorem effective_fixed_write (oracle : Input → DigestRegister) (log : CorrectionLog Input)
    (input : Input) (answer : DigestRegister) :
    effective oracle ((input, answer - oracle input) :: log) =
      Function.update (effective oracle log) input answer := by
  funext address
  by_cases same : address = input
  · subst address
    simp only [effective, correction, if_true, Function.update_self]
    abel
  · simp only [effective, correction, same, if_false, Function.update_of_ne same]

omit [Fintype Input] in
/-- A raw refresh transfers through the retained correction. The translated
answer is uniform, even when this address has appeared in any earlier write. -/
theorem effective_selected_write (oracle : Input → DigestRegister) (log : CorrectionLog Input)
    (input : Input) (answer : DigestRegister) :
    effective (Function.update oracle input answer) log =
      Function.update (effective oracle log) input (answer + correction log input) := by
  funext address
  by_cases same : address = input
  · subst address
    simp only [effective, Function.update_self]
  · simp only [effective, Function.update_of_ne same]

def translateOutput (offset : DigestRegister) : DigestRegister ≃ DigestRegister where
  toFun answer := answer + offset
  invFun answer := answer - offset
  left_inv answer := by simp
  right_inv answer := by simp

theorem uniform_translated_output (offset : DigestRegister) (value : DigestRegister → ℝ) :
    uniformAverage (fun answer => value (answer + offset)) = uniformAverage value :=
  uniform_average_equiv (translateOutput offset) value

/-- One raw oracle query followed by an oracle-independent, classically known
correction gate is exactly a query to the effective mutable table. -/
theorem corrected_query_is_physical (oracle : Input → DigestRegister) (log : CorrectionLog Input)
    (state : GameState (Input := Input) (Work := Work)) :
    query (correction log) (query oracle state) = query (effective oracle log) state := by
  ext basis
  simp only [query_apply, effective]
  have answer : (basis.2.1 - correction log basis.1) - oracle basis.1 =
      basis.2.1 - (oracle basis.1 + correction log basis.1) := by abel
  rw [answer]

inductive MixedProgram (Input Work : Type) [Fintype Input] [Fintype Work] : Type 1 where
  | finish (event : Finset (QueryBasis Input DigestRegister Work))
  | gate (operation : GameGate (Input := Input) (Work := Work)) (next : MixedProgram Input Work)
  | quantumQuery (next : MixedProgram Input Work)
  | honestRead (input : Input) (next : DigestRegister → MixedProgram Input Work)
  | instrument {count : Nat} (operation : Instrument Input Work count)
      (next : Fin count → MixedProgram Input Work)
  | random (source : RandomSource) (next : source.Coins → MixedProgram Input Work)
  | freshInput (sampler : InputSampler Input)
      (next : sampler.Coins → DigestRegister → MixedProgram Input Work)
  | write (input : Input) (answer : DigestRegister) (next : MixedProgram Input Work)

/-- Only selected fresh-input events depend on the game bit. Fixed writes are
performed in both games. One persistent effective oracle is used everywhere. -/
def run (randomized : Bool) : MixedProgram Input Work → (Input → DigestRegister) →
    GameState (Input := Input) (Work := Work) → ℝ
  | .finish event, _oracle, state => born event state
  | .gate operation next, oracle, state => run randomized next oracle (operation state)
  | .quantumQuery next, oracle, state => run randomized next oracle (query oracle state)
  | .honestRead input next, oracle, state => run randomized (next (oracle input)) oracle state
  | .instrument operation next, oracle, state =>
      ∑ outcome, run randomized (next outcome) oracle (operation.branch outcome state)
  | .random source next, oracle, state =>
      uniformAverage fun coins : source.Coins => run randomized (next coins) oracle state
  | .freshInput sampler next, oracle, state =>
      uniformAverage fun coins : sampler.Coins => uniformAverage fun answer : DigestRegister =>
        let input := sampler.input coins
        let current := if randomized then Function.update oracle input answer else oracle
        run randomized (next coins (current input)) current state
  | .write input answer next, oracle, state =>
      run randomized next (Function.update oracle input answer) state

/-- The compiler carries only finite classical records, and never examines a
quantum state. All gates and complete instruments from the original program are
retained without changing or selecting their measurement outcomes. -/
def compile : MixedProgram Input Work → CorrectionLog Input → V8Smz9HonestWholeViewGames.Program Input Work
  | .finish event, _log => .finish event
  | .gate operation next, log => .gate operation (compile next log)
  | .quantumQuery next, log => .quantumQuery (.gate (query (correction log)) (compile next log))
  | .honestRead input next, log =>
      .honestRead input (fun answer => compile (next (answer + correction log input)) log)
  | .instrument operation next, log =>
      .instrument operation (fun outcome => compile (next outcome) log)
  | .random source next, log => .random source (fun coins => compile (next coins) log)
  | .freshInput sampler next, log => .freshInput sampler (fun coins answer =>
      compile (next coins (answer + correction log (sampler.input coins))) log)
  | .write input answer next, log => .honestRead input (fun rawAnswer =>
      compile next ((input, answer - rawAnswer) :: log))

/-- Exact execution, pointwise in the initial raw table and subnormalized
quantum state. There is no source-distance or semantic-correspondence premise. -/
theorem compile_executes (randomized : Bool) (program : MixedProgram Input Work)
    (oracle : Input → DigestRegister) (log : CorrectionLog Input)
    (state : GameState (Input := Input) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run randomized (compile program log) oracle state =
      run randomized program (effective oracle log) state := by
  induction program generalizing oracle log state with
  | finish event => rfl
  | gate operation next ih => exact ih oracle log (operation state)
  | quantumQuery next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.run, run]
      rw [ih, corrected_query_is_physical]
  | honestRead input next ih =>
      exact ih (oracle input + correction log input) oracle log state
  | instrument operation next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.run, run]
      apply Finset.sum_congr rfl
      intro outcome _
      exact ih outcome oracle log (operation.branch outcome state)
  | random source next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.run, run]
      apply congrArg uniformAverage
      funext coins
      exact ih coins oracle log state
  | freshInput sampler next ih =>
      cases randomized with
      | false =>
          simp only [compile, V8Smz9HonestWholeViewGames.run, run, Bool.false_eq_true, if_false]
          apply congrArg uniformAverage
          funext coins
          apply congrArg uniformAverage
          funext answer
          exact ih coins (oracle (sampler.input coins) + correction log (sampler.input coins))
            oracle log state
      | true =>
          simp only [compile, V8Smz9HonestWholeViewGames.run, run, if_true, Function.update_self]
          apply congrArg uniformAverage
          funext coins
          calc
            _ = uniformAverage (fun answer : DigestRegister =>
                run true (next coins (answer + correction log (sampler.input coins)))
                  (Function.update (effective oracle log) (sampler.input coins)
                    (answer + correction log (sampler.input coins))) state) := by
              apply congrArg uniformAverage
              funext answer
              rw [ih, effective_selected_write]
            _ = _ := uniform_translated_output _ (fun answer =>
              run true (next coins answer)
                (Function.update (effective oracle log) (sampler.input coins) answer) state)
  | write input answer next ih =>
      simp only [compile, V8Smz9HonestWholeViewGames.run, run]
      rw [ih, effective_fixed_write]

def acceptance (randomized : Bool) (program : MixedProgram Input Work)
    (initial : GameState (Input := Input) (Work := Work)) : ℝ :=
  uniformAverage fun oracle : Input → DigestRegister => run randomized program oracle initial

theorem compiled_acceptance_eq (randomized : Bool) (program : MixedProgram Input Work)
    (initial : GameState (Input := Input) (Work := Work)) :
    V8Smz9HonestWholeViewGames.acceptance randomized (compile program []) initial = acceptance randomized program initial := by
  unfold V8Smz9HonestWholeViewGames.acceptance acceptance
  apply congrArg uniformAverage
  funext oracle
  rw [compile_executes, effective_empty]

theorem run_has_physical_probability (randomized : Bool) (program : MixedProgram Input Work)
    (oracle : Input → DigestRegister) (state : GameState (Input := Input) (Work := Work)) :
    0 ≤ run randomized program oracle state ∧ run randomized program oracle state ≤ ‖state‖ ^ 2 := by
  have physical := V8Smz9HonestWholeViewGames.run_has_physical_probability randomized (compile program []) oracle state
  simpa only [compile_executes, effective_empty] using physical


end
end HegemonCrypto.SmallWood.V8Smz9MixedMaskCompiler
