import HegemonCrypto.SmallWoodV8Smz9MixedMaskAccounting
import HegemonCrypto.SmallWoodV8Smz9MixedMaskAdapters
import HegemonCrypto.SmallWoodV8Smz9HonestRequestSchedule

namespace HegemonCrypto.SmallWood.V8Smz9MixedFinalOperational

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9HonestRequestSchedule V8Smz9HonestFinalGame
open V8Smz9HonestWholeViewGames (GameState)
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped BigOperators Classical ENNReal

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000

variable {Other Result Work : Type} [Fintype Other] [DecidableEq Other] [Fintype Work]

def nonleafCompile : NonleafProgram Other Result →
    (Result → MixedProgram (LeafInput ⊕ Other) Work) → MixedProgram (LeafInput ⊕ Other) Work
  | .done result, next => next result
  | .read input rest, next => .honestRead (Sum.inr input) fun answer => nonleafCompile (rest answer) next

theorem nonleaf_compile_executes (randomized : Bool) (program : NonleafProgram Other Result)
    (next : Result → MixedProgram (LeafInput ⊕ Other) Work)
    (oracle : (LeafInput ⊕ Other) → DigestRegister)
    (state : GameState (Input := LeafInput ⊕ Other) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run randomized (nonleafCompile program next) oracle state =
      V8Smz9MixedMaskCompiler.run randomized
        (next (NonleafProgram.interpret (fun input => oracle (Sum.inr input)) program)) oracle state := by
  induction program with
  | done result => rfl
  | read input rest ih => exact ih (oracle (Sum.inr input))

omit [DecidableEq Other] in
theorem nonleaf_compile_mass (cap : ℝ≥0∞) (program : NonleafProgram Other Result)
    (next : Result → MixedProgram (LeafInput ⊕ Other) Work)
    (remaining : ∀ result, V8Smz9MixedMaskCompiler.InputMassAtMost cap (next result)) :
    V8Smz9MixedMaskCompiler.InputMassAtMost cap (nonleafCompile program next) := by
  induction program with
  | done result => exact remaining result
  | read input rest ih => exact ih

omit [DecidableEq Other] in
theorem nonleaf_compile_program_bound (program : NonleafProgram Other Result)
    (next : Result → MixedProgram (LeafInput ⊕ Other) Work) (programs : Nat)
    (remaining : ∀ result, V8Smz9MixedMaskCompiler.programmingCount (next result) ≤ programs) :
    V8Smz9MixedMaskCompiler.programmingCount (nonleafCompile program next) ≤ programs := by
  induction program with
  | done result => exact remaining result
  | read input rest ih => exact Finset.sup_le fun output _ => ih output

omit [DecidableEq Other] in
theorem nonleaf_compile_query_bound (program : NonleafProgram Other Result)
    (next : Result → MixedProgram (LeafInput ⊕ Other) Work) (queries : Nat)
    (remaining : ∀ result, V8Smz9MixedMaskCompiler.queryCount (next result) ≤ queries) :
    V8Smz9MixedMaskCompiler.queryCount (nonleafCompile program next) ≤
      NonleafProgram.readCount program + queries := by
  induction program with
  | done result =>
      simpa only [nonleafCompile, NonleafProgram.readCount, Nat.zero_add] using remaining result
  | read input rest ih =>
      change (Finset.univ.sup fun output => V8Smz9MixedMaskCompiler.queryCount
        (nonleafCompile (rest output) next)) + 1 ≤
        (Finset.univ.sup fun output => NonleafProgram.readCount (rest output)) + 1 + queries
      have bounded : (Finset.univ.sup fun output => V8Smz9MixedMaskCompiler.queryCount
          (nonleafCompile (rest output) next)) ≤
          (Finset.univ.sup fun output => NonleafProgram.readCount (rest output)) + queries := by
        apply Finset.sup_le
        intro output member
        exact (ih output).trans (Nat.add_le_add_right
          (Finset.le_sup (f := fun output => NonleafProgram.readCount (rest output)) member) queries)
      omega

omit [DecidableEq Other] in
theorem nonleaf_compile_fixed_program (fixedMode : Bool) (program : NonleafProgram Other Result)
    (next : Result → V8Smz9HonestWholeViewGames.Program (LeafInput ⊕ Other) Work) :
    nonleafCompile program (fun result => V8Smz9MixedMaskCompiler.fixedProgram fixedMode (next result)) =
      V8Smz9MixedMaskCompiler.fixedProgram fixedMode (NonleafProgram.compile program next) := by
  induction program with
  | done result => rfl
  | read input rest ih =>
      simp only [nonleafCompile, NonleafProgram.compile, V8Smz9MixedMaskCompiler.fixedProgram]
      congr 1
      funext output
      exact ih output

omit [DecidableEq Other] in
theorem fixed_program_has_no_selected_events (fixedMode : Bool)
    (program : V8Smz9HonestWholeViewGames.Program (LeafInput ⊕ Other) Work) :
    V8Smz9MixedMaskCompiler.programmingCount (V8Smz9MixedMaskCompiler.fixedProgram fixedMode program) = 0 := by
  induction program with
  | finish event => rfl
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact ih
  | honestRead input next ih =>
      simp [V8Smz9MixedMaskCompiler.fixedProgram, V8Smz9MixedMaskCompiler.programmingCount, ih]
  | instrument operation next ih =>
      simp [V8Smz9MixedMaskCompiler.fixedProgram, V8Smz9MixedMaskCompiler.programmingCount, ih]
  | random source next ih =>
      simp [V8Smz9MixedMaskCompiler.fixedProgram, V8Smz9MixedMaskCompiler.programmingCount, ih]
  | freshInput sampler next ih =>
      cases fixedMode <;> simp [V8Smz9MixedMaskCompiler.fixedProgram, V8Smz9MixedMaskCompiler.fixedFresh,
        V8Smz9MixedMaskCompiler.sampledRead, V8Smz9MixedMaskCompiler.programmingCount, ih]

omit [DecidableEq Other] in
theorem fixed_program_has_input_mass (cap : ℝ≥0∞) (fixedMode : Bool)
    (program : V8Smz9HonestWholeViewGames.Program (LeafInput ⊕ Other) Work) :
    V8Smz9MixedMaskCompiler.InputMassAtMost cap (V8Smz9MixedMaskCompiler.fixedProgram fixedMode program) := by
  induction program with
  | finish event => trivial
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact ih
  | honestRead input next ih => exact ih
  | instrument operation next ih => exact ih
  | random source next ih => exact ih
  | freshInput sampler next ih =>
      cases fixedMode
      · exact ih
      · exact ih


end
end HegemonCrypto.SmallWood.V8Smz9MixedFinalOperational
