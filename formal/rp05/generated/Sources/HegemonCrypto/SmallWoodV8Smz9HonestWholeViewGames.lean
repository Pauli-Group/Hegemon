import HegemonCrypto.SmallWoodV8Smz9CurrentRepeatedPrivacy

/-! Physical finite games for the honest-input adaptive reprogramming boundary.
Measurement branches are complete complex-linear instruments and their states
remain subnormalized. Each fresh-input event samples its input before its new
uniform output, updates the persistent oracle only in the randomized game, and
charges the ordinary read used to obtain that output. The external theorem is
the uniform-cap specialization of GHHM Theorem 1, equation (2), on these games
(arXiv:2010.15103, with the adaptive hybrid detailed in Appendix A).

This file supplies a game language and the actual source-leaf input adapter;
it does not claim that the entire current Rust prover has been compiled into it.
-/

namespace HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open scoped BigOperators Classical ENNReal

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

abbrev GameState := State (Input := Input) (Output := DigestRegister) (Workspace := Work)
abbrev GameGate := GameState (Input := Input) (Work := Work) ≃ₗᵢ[ℂ]
  GameState (Input := Input) (Work := Work)

/-- A complete finite instrument, with one Kraus map per refined outcome.
Extra Kraus outcomes can be retained internally. No selected branch is
renormalized or discarded by the interpreter. -/
structure Instrument (Input Work : Type) [Fintype Input] [Fintype Work] (count : Nat) where
  branch : Fin count → GameState (Input := Input) (Work := Work) →ₗ[ℂ]
    GameState (Input := Input) (Work := Work)
  complete : ∀ state, ∑ outcome, ‖branch outcome state‖ ^ 2 = ‖state‖ ^ 2

structure InputSampler (Input : Type) where
  Coins : Type
  finite : Fintype Coins
  inhabited : Nonempty Coins
  input : Coins → Input

attribute [instance] InputSampler.finite InputSampler.inhabited

structure RandomSource where
  Coins : Type
  finite : Fintype Coins
  inhabited : Nonempty Coins

attribute [instance] RandomSource.finite RandomSource.inhabited

inductive Program (Input Work : Type) [Fintype Input] [Fintype Work] : Type 1 where
  | finish (event : Finset (QueryBasis Input DigestRegister Work))
  | gate (operation : GameGate (Input := Input) (Work := Work)) (next : Program Input Work)
  | quantumQuery (next : Program Input Work)
  | honestRead (input : Input) (next : DigestRegister → Program Input Work)
  | instrument {count : Nat} (operation : Instrument Input Work count)
      (next : Fin count → Program Input Work)
  | random (source : RandomSource) (next : source.Coins → Program Input Work)
  | freshInput (sampler : InputSampler Input)
      (next : sampler.Coins → DigestRegister → Program Input Work)

/-- A single persistent table is threaded through every branch and request.
The final value is the Born weight of an actual final measurement event. -/
def run (randomized : Bool) : Program Input Work → (Input → DigestRegister) →
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
      uniformAverage fun coins : sampler.Coins => uniformAverage fun output : DigestRegister =>
        let input := sampler.input coins
        let current := if randomized then Function.update oracle input output else oracle
        run randomized (next coins (current input)) current state

def acceptance (randomized : Bool) (program : Program Input Work)
    (initial : GameState (Input := Input) (Work := Work)) : ℝ :=
  uniformAverage fun oracle : Input → DigestRegister => run randomized program oracle initial

/-- The read after every fresh-input instruction is an ordinary oracle call.
Every possible measured or sampled branch is covered by the worst-case bound. -/
def queryCount : Program Input Work → Nat
  | .finish _ => 0
  | .gate _ next => queryCount next
  | .quantumQuery next => queryCount next + 1
  | .honestRead _ next => (Finset.univ.sup fun output => queryCount (next output)) + 1
  | .instrument _ next => Finset.univ.sup fun outcome => queryCount (next outcome)
  | .random _ next => Finset.univ.sup fun coins => queryCount (next coins)
  | .freshInput _ next =>
      (Finset.univ.sup fun coins => Finset.univ.sup fun output => queryCount (next coins output)) + 1

def programmingCount : Program Input Work → Nat
  | .finish _ => 0
  | .gate _ next => programmingCount next
  | .quantumQuery next => programmingCount next
  | .honestRead _ next => Finset.univ.sup fun output => programmingCount (next output)
  | .instrument _ next => Finset.univ.sup fun outcome => programmingCount (next outcome)
  | .random _ next => Finset.univ.sup fun coins => programmingCount (next coins)
  | .freshInput _ next =>
      (Finset.univ.sup fun coins => Finset.univ.sup fun output => programmingCount (next coins output)) + 1

/-- This is the sampling-distribution premise of the published theorem, not
a conditional-entropy statement after observing a desired hash output. -/
def InputMassAtMost (cap : ℝ≥0∞) : Program Input Work → Prop
  | .finish _ => True
  | .gate _ next => InputMassAtMost cap next
  | .quantumQuery next => InputMassAtMost cap next
  | .honestRead _ next => ∀ output, InputMassAtMost cap (next output)
  | .instrument _ next => ∀ outcome, InputMassAtMost cap (next outcome)
  | .random _ next => ∀ coins, InputMassAtMost cap (next coins)
  | .freshInput sampler next =>
      (∀ input, pmfMap (uniformFintypePMF sampler.Coins) sampler.input input ≤ cap) ∧
      ∀ coins output, InputMassAtMost cap (next coins output)

theorem uniform_average_bounds {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (value : Coins → ℝ) (upper : ℝ) (bounded : ∀ coin, 0 ≤ value coin ∧ value coin ≤ upper) :
    0 ≤ uniformAverage value ∧ uniformAverage value ≤ upper := by
  constructor
  · exact Finset.sum_nonneg fun coin _ => mul_nonneg ENNReal.toReal_nonneg (bounded coin).1
  · calc
      uniformAverage value ≤ uniformAverage (fun _ : Coins => upper) := by
        apply Finset.sum_le_sum
        intro coin _
        exact mul_le_mul_of_nonneg_left (bounded coin).2 ENNReal.toReal_nonneg
      _ = upper := uniform_average_const upper

/-- Complete instruments preserve total branch weight, and each final event
has Born weight between zero and the input squared norm. -/
theorem run_has_physical_probability (randomized : Bool) (program : Program Input Work)
    (oracle : Input → DigestRegister) (state : GameState (Input := Input) (Work := Work)) :
    0 ≤ run randomized program oracle state ∧ run randomized program oracle state ≤ ‖state‖ ^ 2 := by
  induction program generalizing oracle state with
  | finish event =>
      constructor
      · exact sq_nonneg _
      · exact event_projection_norm_sq_le event state
  | gate operation next ih =>
      simpa only [run, operation.norm_map] using ih oracle (operation state)
  | quantumQuery next ih =>
      simpa only [run, (query oracle).norm_map] using ih oracle (query oracle state)
  | honestRead input next ih => exact ih (oracle input) oracle state
  | instrument operation next ih =>
      constructor
      · exact Finset.sum_nonneg fun outcome _ => (ih outcome oracle (operation.branch outcome state)).1
      · calc
          _ ≤ ∑ outcome, ‖operation.branch outcome state‖ ^ 2 :=
            Finset.sum_le_sum fun outcome _ => (ih outcome oracle (operation.branch outcome state)).2
          _ = ‖state‖ ^ 2 := operation.complete state
  | random source next ih => exact uniform_average_bounds _ _ fun coins => ih coins oracle state
  | freshInput sampler next ih =>
      apply uniform_average_bounds
      intro coins
      apply uniform_average_bounds
      intro output
      exact ih coins _ _ state

theorem game_acceptance_is_probability (randomized : Bool) (program : Program Input Work)
    (initial : GameState (Input := Input) (Work := Work)) (normalized : ‖initial‖ = 1) :
    0 ≤ acceptance randomized program initial ∧ acceptance randomized program initial ≤ 1 := by
  have bound := uniform_average_bounds
    (fun oracle : Input → DigestRegister => run randomized program oracle initial)
    (‖initial‖ ^ 2) (fun oracle => run_has_physical_probability randomized program oracle initial)
  simpa only [acceptance, normalized, one_pow] using bound

/-- The uniform-query/max-mass specialization of GHHM Theorem 1, equation (2), exposed
as an external theorem parameter. This declaration does not assert that the
paper has been formalized in Lean or introduce a project axiom. -/
def ExternalAdaptiveReprogramming : Prop :=
  ∀ (program : Program Input Work) (initial : GameState (Input := Input) (Work := Work))
    (queries programs : Nat) (cap : ℝ),
    ‖initial‖ = 1 → queryCount program ≤ queries → programmingCount program ≤ programs →
    0 ≤ cap → InputMassAtMost (ENNReal.ofReal cap) program →
    |acceptance true program initial - acceptance false program initial| ≤
      (programs : ℝ) * (Real.sqrt ((queries : ℝ) * cap) + (queries : ℝ) * cap / 2)

/-- Instantiation for any one persistent measured program whose fresh-input
events satisfy the actual leaf mass bound. Bounds cover every branch, not an
average or a successful-request subset. The GHHM theorem is the only external
mathematical premise; no desired source-game distance is accepted separately. -/
theorem measured_adaptive_leaf_game_bound
    (ghhm : ExternalAdaptiveReprogramming (Input := Input) (Work := Work))
    (program : Program Input Work) (initial : GameState (Input := Input) (Work := Work))
    (queries leaves : Nat) (normalized : ‖initial‖ = 1)
    (queryBound : queryCount program ≤ queries)
    (leafBound : programmingCount program ≤ leaves)
    (massBound : InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ program) :
    |acceptance true program initial - acceptance false program initial| ≤
      (leaves : ℝ) * (Real.sqrt ((queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) +
        (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2) := by
  apply ghhm program initial queries leaves _ normalized queryBound leafBound (by positivity)
  simpa only [ENNReal.ofReal_inv_of_pos (by positivity : (0 : ℝ) < 2 ^ 512),
    ENNReal.ofReal_pow (by norm_num : (0 : ℝ) ≤ 2), ENNReal.ofReal_ofNat] using massBound

section SourceLeaf

variable {Other : Type} [Fintype Other] [DecidableEq Other]

def sourceLeafSampler (header : LeafHeader) (payload : LeafSuffix) (index : LeafIndex) :
    InputSampler (LeafInput ⊕ Other) where
  Coins := LeafTape
  finite := inferInstance
  inhabited := inferInstance
  input := fun tape => Sum.inl (sourceLeafInput header payload index tape)

omit [Fintype Other] [DecidableEq Other] in
theorem actual_source_leaf_sampler_mass
    (header : LeafHeader) (payload : LeafSuffix) (index : LeafIndex)
    (input : LeafInput ⊕ Other) :
    pmfMap (uniformFintypePMF (sourceLeafSampler (Other := Other) header payload index).Coins)
      (sourceLeafSampler header payload index).input input ≤ (2 ^ 512 : ℝ≥0∞)⁻¹ := by
  cases input with
  | inl input =>
      have bound := fresh_leaf_input_max_mass (Fin.append header (indexBytes index)) payload input
      simpa [sourceLeafSampler, sourceLeafInput, freshLeafInputLaw, pmfMap_apply,
        Sum.inl.injEq] using bound
  | inr other =>
      simp only [sourceLeafSampler, pmfMap_apply, Sum.inr_ne_inl, if_false, tsum_zero]
      exact bot_le

/-- The actual source leaf payload can be selected from preceding measured
history. Only the tape is drawn inside this instruction. -/
def sourceLeaf (header : LeafHeader) (payload : LeafSuffix) (index : LeafIndex)
    (next : LeafTape → DigestRegister → Program (LeafInput ⊕ Other) Work) :
    Program (LeafInput ⊕ Other) Work :=
  .freshInput (sourceLeafSampler header payload index) next

theorem source_leaf_honest_execution
    (header : LeafHeader) (payload : LeafSuffix) (index : LeafIndex)
    (next : LeafTape → DigestRegister → Program (LeafInput ⊕ Other) Work)
    (oracle : (LeafInput ⊕ Other) → DigestRegister)
    (state : GameState (Input := LeafInput ⊕ Other) (Work := Work)) :
    run false (sourceLeaf header payload index next) oracle state =
      uniformAverage (fun tape : LeafTape =>
        run false (next tape (oracle (Sum.inl (sourceLeafInput header payload index tape)))) oracle state) := by
  simp only [sourceLeaf, run, Bool.false_eq_true, if_false, sourceLeafSampler, uniform_average_const]

theorem source_leaf_randomized_execution
    (header : LeafHeader) (payload : LeafSuffix) (index : LeafIndex)
    (next : LeafTape → DigestRegister → Program (LeafInput ⊕ Other) Work)
    (oracle : (LeafInput ⊕ Other) → DigestRegister)
    (state : GameState (Input := LeafInput ⊕ Other) (Work := Work)) :
    run true (sourceLeaf header payload index next) oracle state =
      uniformAverage (fun tape : LeafTape => uniformAverage (fun output : DigestRegister =>
        run true (next tape output)
          (Function.update oracle (Sum.inl (sourceLeafInput header payload index tape)) output) state)) := by
  simp only [sourceLeaf, run, if_true, sourceLeafSampler, Function.update_self]

omit [DecidableEq Other] in
theorem source_leaf_preserves_input_mass_bound
    (header : LeafHeader) (payload : LeafSuffix) (index : LeafIndex)
    (next : LeafTape → DigestRegister → Program (LeafInput ⊕ Other) Work)
    (remaining : ∀ tape output, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next tape output)) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (sourceLeaf header payload index next) :=
  ⟨actual_source_leaf_sampler_mass header payload index, remaining⟩

end SourceLeaf
end
end HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
