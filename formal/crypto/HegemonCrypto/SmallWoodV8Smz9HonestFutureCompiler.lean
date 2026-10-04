import HegemonCrypto.SmallWoodV8Smz9HonestWholeViewGames

/-! Selective current-request reprogramming keeps the complete later honest
program. Fresh-input nodes in that suffix become explicit local sampling and
ordinary charged oracle reads. Both interpretations of the compiled suffix
therefore execute the original honest suffix, on the same persistent table.
No source execution or final security endpoint is asserted here. -/

namespace HegemonCrypto.SmallWood.V8Smz9HonestFutureCompiler

open V8Smz9HonestWholeViewGames V8Smz9RuntimeDistribution V8Smz9CurrentPrivacyComposition
open scoped Classical ENNReal

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000

variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

def honestizeFreshInputs : Program Input Work → Program Input Work
  | .finish event => .finish event
  | .gate operation next => .gate operation (honestizeFreshInputs next)
  | .quantumQuery next => .quantumQuery (honestizeFreshInputs next)
  | .honestRead input next => .honestRead input (fun output => honestizeFreshInputs (next output))
  | .instrument operation next => .instrument operation (fun outcome => honestizeFreshInputs (next outcome))
  | .random source next => .random source (fun coins => honestizeFreshInputs (next coins))
  | .freshInput sampler next =>
      .random ⟨sampler.Coins, sampler.finite, sampler.inhabited⟩ (fun coins =>
        .honestRead (sampler.input coins) (fun output => honestizeFreshInputs (next coins output)))

theorem honestized_run_eq_honest (randomized : Bool) (program : Program Input Work)
    (oracle : Input → V8Smz9HiddenLeafQrom.DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    run randomized (honestizeFreshInputs program) oracle state = run false program oracle state := by
  induction program generalizing oracle state with
  | finish event => rfl
  | gate operation next ih => simpa only [honestizeFreshInputs, run] using ih oracle (operation state)
  | quantumQuery next ih =>
      simpa only [honestizeFreshInputs, run] using ih oracle (V8Smz9HiddenPatch.query oracle state)
  | honestRead input next ih =>
      simpa only [honestizeFreshInputs, run] using ih (oracle input) oracle state
  | instrument operation next ih =>
      simp only [honestizeFreshInputs, run, ih]
  | random source next ih =>
      simp only [honestizeFreshInputs, run, ih]
  | freshInput sampler next ih =>
      simp only [honestizeFreshInputs, run, Bool.false_eq_true, if_false, ih, uniform_average_const]

omit [DecidableEq Input] in
theorem honestized_programming_count_zero (program : Program Input Work) :
    programmingCount (honestizeFreshInputs program) = 0 := by
  induction program with
  | finish event => rfl
  | gate operation next ih => simpa only [honestizeFreshInputs, programmingCount] using ih
  | quantumQuery next ih => simpa only [honestizeFreshInputs, programmingCount] using ih
  | honestRead input next ih => simp [honestizeFreshInputs, programmingCount, ih]
  | instrument operation next ih => simp [honestizeFreshInputs, programmingCount, ih]
  | random source next ih => simp [honestizeFreshInputs, programmingCount, ih]
  | freshInput sampler next ih => simp [honestizeFreshInputs, programmingCount, ih]

omit [DecidableEq Input] in
theorem honestized_input_mass_bound (program : Program Input Work) (cap : ℝ≥0∞) :
    InputMassAtMost cap (honestizeFreshInputs program) := by
  induction program with
  | finish event => trivial
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact ih
  | honestRead input next ih => exact ih
  | instrument operation next ih => exact ih
  | random source next ih => exact ih
  | freshInput sampler next ih => exact ih

omit [DecidableEq Input] in
theorem honestized_query_count (program : Program Input Work) :
    queryCount (honestizeFreshInputs program) = queryCount program := by
  induction program with
  | finish event => rfl
  | gate operation next ih => simpa only [honestizeFreshInputs, queryCount] using ih
  | quantumQuery next ih => simp only [honestizeFreshInputs, queryCount, ih]
  | honestRead input next ih => simp only [honestizeFreshInputs, queryCount, ih]
  | instrument operation next ih => simp only [honestizeFreshInputs, queryCount, ih]
  | random source next ih => simp only [honestizeFreshInputs, queryCount, ih]
  | freshInput sampler next ih =>
      simp only [honestizeFreshInputs, queryCount, ih]
      apply le_antisymm
      · apply Finset.sup_le
        intro coins member
        exact Nat.add_le_add_right (Finset.le_sup
          (f := fun coins => Finset.univ.sup fun output => queryCount (next coins output)) member) 1
      · obtain ⟨coins, member, greatest⟩ := Finset.exists_mem_eq_sup
          (s := (Finset.univ : Finset sampler.Coins))
          (f := fun coins => Finset.univ.sup fun output => queryCount (next coins output))
          Finset.univ_nonempty
        rw [greatest]
        exact Finset.le_sup
          (f := fun coins => (Finset.univ.sup fun output => queryCount (next coins output)) + 1) member

theorem honestized_acceptance_eq_honest (randomized : Bool) (program : Program Input Work)
    (initial : GameState (Input := Input) (Work := Work)) :
    acceptance randomized (honestizeFreshInputs program) initial = acceptance false program initial := by
  simp only [acceptance, honestized_run_eq_honest]


end
end HegemonCrypto.SmallWood.V8Smz9HonestFutureCompiler
