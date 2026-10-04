import HegemonCrypto.SmallWoodV8Smz9MixedMaskAdapters

/-! Fixing a complete future to one hybrid mode preserves its query budget
and removes every selected event. Ordinary reads and fixed writes both cost
one raw query under the collision-exact correction-log compiler. -/

namespace HegemonCrypto.SmallWood.V8Smz9MixedMaskCompiler

open V8Smz9HonestWholeViewGames (Program)
open scoped Classical ENNReal

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

omit [DecidableEq Input] in
theorem fixed_program_query_count (mode : Bool) (program : Program Input Work) :
    queryCount (fixedProgram mode program) = V8Smz9HonestWholeViewGames.queryCount program := by
  induction program with
  | finish event => rfl
  | gate operation next ih => exact ih
  | quantumQuery next ih => simp only [fixedProgram, queryCount, V8Smz9HonestWholeViewGames.queryCount, ih]
  | honestRead input next ih => simp only [fixedProgram, queryCount, V8Smz9HonestWholeViewGames.queryCount, ih]
  | instrument operation next ih => simp only [fixedProgram, queryCount, V8Smz9HonestWholeViewGames.queryCount, ih]
  | random source next ih => simp only [fixedProgram, queryCount, V8Smz9HonestWholeViewGames.queryCount, ih]
  | freshInput sampler next ih =>
      cases mode <;>
        simp only [fixedProgram, Bool.false_eq_true, if_false, if_true, fixedFresh, sampledRead,
          queryCount, V8Smz9HonestWholeViewGames.queryCount, samplerCoins, outputCoins, ih,
          Finset.sup_add Finset.univ_nonempty]

omit [DecidableEq Input] in
theorem fixed_program_selected_count_zero (mode : Bool) (program : Program Input Work) :
    programmingCount (fixedProgram mode program) = 0 := by
  induction program with
  | finish event => rfl
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact ih
  | honestRead input next ih => simp [fixedProgram, programmingCount, ih]
  | instrument operation next ih => simp [fixedProgram, programmingCount, ih]
  | random source next ih => simp [fixedProgram, programmingCount, ih]
  | freshInput sampler next ih =>
      cases mode <;> simp [fixedProgram, fixedFresh, sampledRead, programmingCount, ih]

omit [DecidableEq Input] in
theorem fixed_program_input_mass (mode : Bool) (program : Program Input Work) (cap : ℝ≥0∞) :
    InputMassAtMost cap (fixedProgram mode program) := by
  induction program with
  | finish event => trivial
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact ih
  | honestRead input next ih => exact ih
  | instrument operation next ih => exact ih
  | random source next ih => exact ih
  | freshInput sampler next ih =>
      cases mode <;> simpa only [fixedProgram, if_true, Bool.false_eq_true, if_false,
        fixedFresh, sampledRead, InputMassAtMost, samplerCoins, outputCoins] using ih

end
end HegemonCrypto.SmallWood.V8Smz9MixedMaskCompiler
