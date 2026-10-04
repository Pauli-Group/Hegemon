import HegemonCrypto.SmallWoodV8Smz9MixedMaskAccounting

namespace HegemonCrypto.SmallWood.V8Smz9MixedMaskCompiler

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9RuntimeDistribution
open V8Smz9HonestWholeViewGames (GameState InputSampler RandomSource)
open scoped BigOperators Classical ENNReal

noncomputable section
set_option maxHeartbeats 1000000
set_option maxRecDepth 5000

variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

def samplerCoins (sampler : InputSampler Input) : RandomSource where
  Coins := sampler.Coins
  finite := sampler.finite
  inhabited := sampler.inhabited

def outputCoins : RandomSource where
  Coins := DigestRegister
  finite := inferInstance
  inhabited := inferInstance

/-- A fresh input that is merely read in both games. -/
def sampledRead (sampler : InputSampler Input)
    (next : sampler.Coins → DigestRegister → MixedProgram Input Work) : MixedProgram Input Work :=
  .random (samplerCoins sampler) (fun coins => .honestRead (sampler.input coins) (next coins))

/-- A uniform fixed write in both games. The input is sampled before the new
answer, and the answer is retained in the continuation exactly as in the source
physical game. It is not a selected external reprogramming. -/
def fixedFresh (sampler : InputSampler Input)
    (next : sampler.Coins → DigestRegister → MixedProgram Input Work) : MixedProgram Input Work :=
  .random (samplerCoins sampler) (fun coins => .random outputCoins (fun answer =>
    .write (sampler.input coins) answer (next coins answer)))

theorem sampled_read_execution (randomized : Bool) (sampler : InputSampler Input)
    (next : sampler.Coins → DigestRegister → MixedProgram Input Work)
    (oracle : Input → DigestRegister) (state : GameState (Input := Input) (Work := Work)) :
    run randomized (sampledRead sampler next) oracle state =
      uniformAverage (fun coins : sampler.Coins =>
        run randomized (next coins (oracle (sampler.input coins))) oracle state) := rfl

theorem fixed_fresh_execution (randomized : Bool) (sampler : InputSampler Input)
    (next : sampler.Coins → DigestRegister → MixedProgram Input Work)
    (oracle : Input → DigestRegister) (state : GameState (Input := Input) (Work := Work)) :
    run randomized (fixedFresh sampler next) oracle state =
      uniformAverage (fun coins : sampler.Coins => uniformAverage (fun answer : DigestRegister =>
        run randomized (next coins answer) (Function.update oracle (sampler.input coins) answer) state)) := rfl

/-- Embed a physical program while retaining all its fresh events as selected. -/
def selectedProgram : V8Smz9HonestWholeViewGames.Program Input Work → MixedProgram Input Work
  | .finish event => .finish event
  | .gate operation next => .gate operation (selectedProgram next)
  | .quantumQuery next => .quantumQuery (selectedProgram next)
  | .honestRead input next => .honestRead input (fun answer => selectedProgram (next answer))
  | .instrument operation next => .instrument operation (fun outcome => selectedProgram (next outcome))
  | .random source next => .random source (fun coins => selectedProgram (next coins))
  | .freshInput sampler next => .freshInput sampler (fun coins answer => selectedProgram (next coins answer))

/-- Embed a physical program whose fresh events have already been fixed to one
hybrid mode. The surrounding mixed-game bit cannot change those events. -/
def fixedProgram (fixedMode : Bool) : V8Smz9HonestWholeViewGames.Program Input Work → MixedProgram Input Work
  | .finish event => .finish event
  | .gate operation next => .gate operation (fixedProgram fixedMode next)
  | .quantumQuery next => .quantumQuery (fixedProgram fixedMode next)
  | .honestRead input next => .honestRead input (fun answer => fixedProgram fixedMode (next answer))
  | .instrument operation next => .instrument operation (fun outcome => fixedProgram fixedMode (next outcome))
  | .random source next => .random source (fun coins => fixedProgram fixedMode (next coins))
  | .freshInput sampler next =>
      if fixedMode then fixedFresh sampler (fun coins answer => fixedProgram fixedMode (next coins answer))
      else sampledRead sampler (fun coins answer => fixedProgram fixedMode (next coins answer))

theorem selected_program_execution (randomized : Bool)
    (program : V8Smz9HonestWholeViewGames.Program Input Work)
    (oracle : Input → DigestRegister) (state : GameState (Input := Input) (Work := Work)) :
    run randomized (selectedProgram program) oracle state =
      V8Smz9HonestWholeViewGames.run randomized program oracle state := by
  induction program generalizing oracle state with
  | finish event => rfl
  | gate operation next ih => exact ih oracle (operation state)
  | quantumQuery next ih => exact ih oracle (query oracle state)
  | honestRead input next ih => exact ih (oracle input) oracle state
  | instrument operation next ih =>
      simp only [selectedProgram, run, V8Smz9HonestWholeViewGames.run]
      apply Finset.sum_congr rfl
      intro outcome _
      exact ih outcome oracle (operation.branch outcome state)
  | random source next ih =>
      simp only [selectedProgram, run, V8Smz9HonestWholeViewGames.run]
      apply congrArg uniformAverage
      funext coins
      exact ih coins oracle state
  | freshInput sampler next ih =>
      simp only [selectedProgram, run, V8Smz9HonestWholeViewGames.run]
      apply congrArg uniformAverage
      funext coins
      apply congrArg uniformAverage
      funext answer
      exact ih coins _ _ state

theorem fixed_program_execution (randomized fixedMode : Bool)
    (program : V8Smz9HonestWholeViewGames.Program Input Work)
    (oracle : Input → DigestRegister) (state : GameState (Input := Input) (Work := Work)) :
    run randomized (fixedProgram fixedMode program) oracle state =
      V8Smz9HonestWholeViewGames.run fixedMode program oracle state := by
  induction program generalizing oracle state with
  | finish event => rfl
  | gate operation next ih => exact ih oracle (operation state)
  | quantumQuery next ih => exact ih oracle (query oracle state)
  | honestRead input next ih => exact ih (oracle input) oracle state
  | instrument operation next ih =>
      simp only [fixedProgram, run, V8Smz9HonestWholeViewGames.run]
      apply Finset.sum_congr rfl
      intro outcome _
      exact ih outcome oracle (operation.branch outcome state)
  | random source next ih =>
      simp only [fixedProgram, run, V8Smz9HonestWholeViewGames.run]
      apply congrArg uniformAverage
      funext coins
      exact ih coins oracle state
  | freshInput sampler next ih =>
      cases fixedMode with
      | false =>
          simp only [fixedProgram, Bool.false_eq_true, if_false, sampledRead, run,
            V8Smz9HonestWholeViewGames.run, uniform_average_const]
          apply congrArg uniformAverage
          funext coins
          exact ih coins (oracle (sampler.input coins)) oracle state
      | true =>
          simp only [fixedProgram, if_true, fixedFresh, run,
            V8Smz9HonestWholeViewGames.run, Function.update_self]
          apply congrArg uniformAverage
          funext coins
          apply congrArg uniformAverage
          funext answer
          exact ih coins answer (Function.update oracle (sampler.input coins) answer) state

omit [Fintype Input] in
/-- A repeated key is replaced by the newest correction record. -/
theorem correction_latest_write (log : CorrectionLog Input) (input : Input)
    (first second : DigestRegister) :
    correction ((input, second) :: (input, first) :: log) input = second := by
  simp only [correction, if_true]

omit [Fintype Input] in
/-- The fixed write after a selected refresh uses the *new* raw oracle value.
No old correction can shadow this chronological update. -/
theorem fixed_write_after_same_key_refresh (oracle : Input → DigestRegister) (log : CorrectionLog Input)
    (input : Input) (refreshed written : DigestRegister) :
    effective (Function.update oracle input refreshed)
        ((input, written - refreshed) :: log) =
      Function.update (effective (Function.update oracle input refreshed) log) input written := by
  simpa only [Function.update_self] using
    effective_fixed_write (Function.update oracle input refreshed) log input written


end
end HegemonCrypto.SmallWood.V8Smz9MixedMaskCompiler
