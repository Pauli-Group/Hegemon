import Q38Rp05LeafSupport
import Q38MeasuredCmsNonleaf
import Q38SelectionCompiler
import Q38AdaptiveOpeningGames
import Q38Rp05ChronologicalAlgebra
import Q38CmsPhaseDecodeIsometry
import HegemonCrypto.SmallWoodV8Smz9HonestLeafBatch
import HegemonCrypto.SmallWoodV8Smz9CappedRawSamplerTail

/-!
# Concrete RP05 adaptive-privacy boundary

This file closes the two reusable mathematical steps which were previously
hidden behind an external adaptive-reprogramming premise:

* the successor's literal 2,511-byte leaf address has a 512-bit tape fiber;
  the resulting controlled CMS swap has the derived `4q/2^512` mean-square
  loss; and
* the common continuation measures CURRENT answers from the same persistent
  database before selecting the answer-indexed continuation.  The overwritten
  answers remain in the CMS label register.

It deliberately does not identify the old RP04 773-root response formula or
the historical `actualRequestCompiler` (whose input is `Fin 1407 -> Byte`)
with RP05.  Those are different executable objects, not missing simp lemmas.
-/
namespace HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestLeafBatch
open HegemonCrypto.SmallWood.Q38CmsPhaseDecodeIsometry
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsDependentContinuation
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.Q38CmsResamplingCoordinates
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical ENNReal

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

section CurrentAnswer

variable {Input Work : Type}
variable [Fintype Input] [DecidableEq Input] [Fintype Work]

/-- Sequential measurement of the current persistent-oracle cells.  Unlike a
saved-label shortcut, this reads the post-swap answer at each literal key. -/
def readCurrentAnswers : (count : Nat) → (Fin count → Input) →
    ((Fin count → DigestRegister) → Program Input Work) →
      Program Input Work
  | 0, _, next => next Fin.elim0
  | count + 1, keys, next =>
      .honestRead (keys 0) fun answer =>
        readCurrentAnswers count (fun i => keys i.succ) fun answers =>
          next (Fin.cons answer answers)

omit [DecidableEq Input] in
theorem read_current_answers_query_count (count : Nat)
    (keys : Fin count → Input)
    (next : (Fin count → DigestRegister) → Program Input Work)
    (queries : Nat) (bounded : ∀ answers, queryCount (next answers) ≤ queries) :
    queryCount (readCurrentAnswers count keys next) ≤ count + queries := by
  induction count with
  | zero => simpa [readCurrentAnswers] using bounded Fin.elim0
  | succ count ih =>
      simp only [readCurrentAnswers, queryCount]
      have remaining : (Finset.univ.sup fun answer : DigestRegister =>
          queryCount (readCurrentAnswers count (fun i => keys i.succ)
            (fun answers => next (Fin.cons answer answers)))) ≤ count + queries := by
        apply Finset.sup_le
        intro answer _
        exact ih (fun i => keys i.succ)
          (fun answers => next (Fin.cons answer answers))
          (fun answers => bounded (Fin.cons answer answers))
      omega

/-- One constructor step is literally a complete current-answer projector on
the same CMS state, followed by the answer-indexed tail. -/
theorem phase_run_read_current_answers_succ (randomized : Bool) (count : Nat)
    (keys : Fin (count + 1) → Input)
    (next : (Fin (count + 1) → DigestRegister) → Program Input Work)
    (state : ResponseCmsState Input Work) :
    phaseRun randomized (readCurrentAnswers (count + 1) keys next) state =
      ∑ answer : DigestRegister,
        phaseRun randomized
          (readCurrentAnswers count (fun i => keys i.succ)
            (fun answers => next (Fin.cons answer answers)))
          (phaseReadBranch (keys 0) answer state) := by
  rfl

/-- The current-answer readout is a measurement of the persistent database,
not an external oracle table. -/
theorem phase_run_read_current_answers_is_database_run (randomized : Bool)
    (count : Nat) (keys : Fin count → Input)
    (next : (Fin count → DigestRegister) → Program Input Work)
    (state : ResponseCmsState Input Work) :
    phaseRun randomized (readCurrentAnswers count keys next) state =
      databaseRun randomized (readCurrentAnswers count keys next)
        (phaseDecode state) :=
  phase_run_eq_database_run randomized _ _

end CurrentAnswer

private theorem recorded_keys_card_eq_size
    {Key Output : Type} [Fintype Key] [DecidableEq Key]
    (database : Key → Option Output) :
    (recordedKeys database).card = size database := by
  unfold recordedKeys size
  congr 1
  ext key
  simp only [FiniteOracleDatabase.support, Finset.mem_filter, Finset.mem_univ, true_and]
  cases database key <;> simp

section Rp05Disturbance

variable {Other Branch BaseWork : Type}
variable [Fintype Other] [DecidableEq Other]
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype BaseWork] [DecidableEq BaseWork]

local notation "FullInput" => Rp05LeafInput ⊕ Other
local notation "FullWork" =>
  (LeafIndex → DigestRegister) × (Branch × BaseWork)
local notation "FullCore" =>
  Core FullInput Branch
    (FullInput × DigestRegister × BaseWork) DigestRegister

def rp05Selected (preamble : Branch → Statement)
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (tapes : LeafIndex → LeafTape) : Branch → LeafIndex → FullInput :=
  fun branch index => Sum.inl
    (rp05SourceLeafInput (preamble branch) (salt branch)
      (data branch index) index (tapes index))

def rp05FullIndex : FullInput → LeafIndex :=
  Sum.elim rp05IndexProjection (fun _ => 0)

def rp05FullTape : FullInput → LeafTape :=
  Sum.elim rp05TapeProjection (fun _ => 0)

omit [Fintype Other] [DecidableEq Other] [Fintype Branch] [DecidableEq Branch] in
theorem rp05_selected_index (preamble : Branch → Statement)
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (branch : Branch) (index : LeafIndex) (tape : LeafTape) :
    rp05FullIndex (Sum.inl
      (rp05SourceLeafInput (preamble branch) (salt branch)
        (data branch index) index tape) : FullInput) = index := by
  exact rp05_source_leaf_index_projection _ _ _ _ _

omit [Fintype Other] [DecidableEq Other] [Fintype Branch] [DecidableEq Branch] in
theorem rp05_selected_tape (preamble : Branch → Statement)
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (branch : Branch) (index : LeafIndex) (tape : LeafTape) :
    rp05FullTape (Sum.inl
      (rp05SourceLeafInput (preamble branch) (salt branch)
        (data branch index) index tape) : FullInput) = tape := by
  exact rp05_source_leaf_tape_projection _ _ _ _ _

/-- Successor-leaf CMS disturbance with no historical address coercion and no
caller-supplied security probability. -/
theorem rp05_initialized_resampling_disturbance
    (preamble : Branch → Statement)
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex) (core : FullCore → ℂ) (queries : Nat)
    (bounded : BoundedState queries
      (initializedFreshState (Index := LeafIndex) core)) :
    uniformAverage (fun tapes : LeafIndex → LeafTape =>
      ‖exchangeMany (rp05Selected preamble salt data tapes) indices
          (freshLabels (Index := LeafIndex) core) - freshLabels core‖ ^ 2) ≤
      4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ *
        ∑ basis : FullCore, ‖core basis‖ ^ 2 := by
  have support (basis : FullCore) (nonzero : core basis ≠ 0) :
      (recordedKeys basis.2.1).card ≤ queries := by
    rw [recorded_keys_card_eq_size]
    exact core_database_size_le_of_bounded
      (Input := FullInput) (Output := DigestRegister) (Phase := DigestRegister)
      (Work := BaseWork) (Index := LeafIndex) (Branch := Branch)
      core queries bounded basis nonzero
  have generic := encoded_resampling_disturbance
    (Key := FullInput) (Index := LeafIndex) (Tape := LeafTape)
    (Branch := Branch) (Work := FullInput × DigestRegister × BaseWork)
    (Output := DigestRegister)
    (fun branch index tape => Sum.inl
      (rp05SourceLeafInput (preamble branch) (salt branch)
        (data branch index) index tape))
    rp05FullIndex rp05FullTape
    (rp05_selected_index preamble salt data)
    (rp05_selected_tape preamble salt data) indices core queries support
  unfold rp05Selected
  simpa only [leaf_tape_cardinality, Nat.cast_pow, Nat.cast_ofNat] using generic

/-- The derived RP05 disturbance passed through the SAME tape-dependent
current-answer continuation.  This is the `2*sqrt(4q/2^512)` request hop. -/
theorem rp05_initialized_dependent_phase_run_bound
    (preamble : Branch → Statement)
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex) (core : FullCore → ℂ) (queries : Nat)
    (bounded : BoundedState queries
      (initializedFreshState (Index := LeafIndex) core))
    (coreSubnormalized : ∑ basis : FullCore, ‖core basis‖ ^ 2 ≤ 1)
    (randomized : Bool)
    (program : (LeafIndex → LeafTape) → Program FullInput FullWork)
    (baseSupport : TotalDatabaseSupport (globalDecompress
      (initializedFreshState (Index := LeafIndex) core))) :
    |uniformAverage (fun tapes : LeafIndex → LeafTape =>
        phaseRun randomized (program tapes)
          (controlledCompressed (rp05Selected preamble salt data tapes)
            indices (initializedFreshState core))) -
      uniformAverage (fun tapes : LeafIndex → LeafTape =>
        phaseRun randomized (program tapes)
          (initializedFreshState (Index := LeafIndex) core))| ≤
      2 * Real.sqrt (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) := by
  let base : ResponseCmsState FullInput FullWork :=
    initializedFreshState (Index := LeafIndex) core
  let changed : (LeafIndex → LeafTape) →
      ResponseCmsState FullInput FullWork := fun tapes =>
    controlledCompressed (rp05Selected preamble salt data tapes) indices base
  have baseSub : normSquared (phaseDecode base) ≤ 1 := by
    rw [phase_decode_norm_squared]
    have native := J_sub_norm_squared
      (Input := FullInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Work := BaseWork)
      (Index := LeafIndex) (Branch := Branch)
      base (0 : ResponseCmsState FullInput FullWork)
    have jZero : J (Input := FullInput) (Output := DigestRegister)
        (Phase := DigestRegister) (Work := BaseWork)
        (Index := LeafIndex) (Branch := Branch)
        (0 : ResponseCmsState FullInput FullWork) = 0 := by ext basis; rfl
    rw [jZero, sub_zero, sub_zero, J_initializedFreshState,
      fresh_labels_norm_sq] at native
    exact native.symm.trans_le coreSubnormalized
  have changedSub (tapes : LeafIndex → LeafTape) :
      normSquared (phaseDecode (changed tapes)) ≤ 1 := by
    rw [phase_decode_norm_squared]
    have native := J_sub_norm_squared
      (Input := FullInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Work := BaseWork)
      (Index := LeafIndex) (Branch := Branch)
      (changed tapes) (0 : ResponseCmsState FullInput FullWork)
    have jZero : J (Input := FullInput) (Output := DigestRegister)
        (Phase := DigestRegister) (Work := BaseWork)
        (Index := LeafIndex) (Branch := Branch)
        (0 : ResponseCmsState FullInput FullWork) = 0 := by ext basis; rfl
    rw [jZero, sub_zero, sub_zero] at native
    rw [show J (changed tapes) =
        exchangeMany (rp05Selected preamble salt data tapes) indices
          (freshLabels (Index := LeafIndex) core) by
      unfold changed base
      rw [J_controlled_many, J_initializedFreshState]] at native
    rw [(exchangeMany (rp05Selected preamble salt data tapes)
      indices).norm_map, fresh_labels_norm_sq] at native
    exact native.symm.trans_le coreSubnormalized
  have changedSupport (tapes : LeafIndex → LeafTape) :
      TotalDatabaseSupport (phaseDecode (changed tapes)) := by
    unfold phaseDecode
    apply total_database_support_response_fourier_inverse
    rw [show globalDecompress (changed tapes) =
        controlledRaw (rp05Selected preamble salt data tapes) indices
          (globalDecompress base) by
      unfold changed
      exact global_controlled_swap_intertwining _ _ _]
    exact total_database_support_controlled_raw _ _ _ baseSupport
  have decodedBaseSupport : TotalDatabaseSupport (phaseDecode base) := by
    exact total_database_support_response_fourier_inverse _ baseSupport
  have meanSquare : uniformAverage (fun tapes : LeafIndex → LeafTape =>
      normSquared (phaseDecode (changed tapes) - phaseDecode base)) ≤
      4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
    have native := rp05_initialized_resampling_disturbance
      preamble salt data indices core queries bounded
    calc
      _ = uniformAverage (fun tapes : LeafIndex → LeafTape =>
          ‖exchangeMany (rp05Selected preamble salt data tapes) indices
              (freshLabels (Index := LeafIndex) core) - freshLabels core‖ ^ 2) := by
        apply congrArg uniformAverage
        funext tapes
        rw [phase_decode_difference_norm_squared]
        rw [← J_sub_norm_squared
          (Input := FullInput) (Output := DigestRegister)
          (Phase := DigestRegister) (Work := BaseWork)
          (Index := LeafIndex) (Branch := Branch)]
        unfold changed base
        rw [J_controlled_many, J_initializedFreshState]
      _ ≤ 4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ *
          ∑ basis : FullCore, ‖core basis‖ ^ 2 := native
      _ ≤ 4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
        simpa only [mul_one] using mul_le_mul_of_nonneg_left
          coreSubnormalized
          (show 0 ≤ 4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ by
            positivity)
  exact phase_run_total_support_dependent_hybrid randomized program changed
    base changedSupport decodedBaseSupport changedSub baseSub _ (by positivity)
    meanSquare

end Rp05Disturbance

section Rp05RequestCompiler

variable {Other Work : Type}
variable [Fintype Other] [DecidableEq Other] [Fintype Work]
local notation "FullInput" => Rp05LeafInput ⊕ Other

def rp05LeafSampler (preamble : Statement) (salt : Fin 32 → Byte)
    (data : Fin 1176 → Byte) (index : LeafIndex) :
    InputSampler FullInput where
  Coins := LeafTape
  finite := inferInstance
  inhabited := inferInstance
  input := fun tape => Sum.inl
    (rp05SourceLeafInput preamble salt data index tape)

/-- One literal successor leaf instruction. -/
def rp05SourceLeaf (preamble : Statement) (salt : Fin 32 → Byte)
    (data : Fin 1176 → Byte) (index : LeafIndex)
    (next : LeafTape → DigestRegister → Program FullInput Work) :
    Program FullInput Work :=
  .freshInput (rp05LeafSampler preamble salt data index) next

/-- Atomic successor batch.  The preamble is the complete statement
namespace and is fixed before any leaf answer is read. -/
def rp05LeafBatch : (count : Nat) → (Fin count → LeafIndex) →
    Statement → (Fin 32 → Byte) →
    (Fin count → Fin 1176 → Byte) →
    ((Fin count → LeafTape) → (Fin count → DigestRegister) →
      Program FullInput Work) → Program FullInput Work
  | 0, _, _, _, _, next => next Fin.elim0 Fin.elim0
  | count + 1, indices, preamble, salt, data, next =>
      rp05SourceLeaf preamble salt (data 0) (indices 0) fun tape output =>
        rp05LeafBatch count (fun i => indices i.succ) preamble salt
          (fun i => data i.succ) fun tapes outputs =>
            next (Fin.cons tape tapes) (Fin.cons output outputs)

def updateRp05Batch : (count : Nat) → (Fin count → FullInput) →
    (Fin count → DigestRegister) → (FullInput → DigestRegister) →
      FullInput → DigestRegister
  | 0, _, _, oracle => oracle
  | count + 1, inputs, outputs, oracle =>
      updateRp05Batch count (fun i => inputs i.succ)
        (fun i => outputs i.succ)
        (Function.update oracle (inputs 0) (outputs 0))

omit [Fintype Other] in
theorem update_rp05_batch_outside (count : Nat)
    (inputs : Fin count → FullInput)
    (outputs : Fin count → DigestRegister)
    (oracle : FullInput → DigestRegister) (input : FullInput)
    (outside : ∀ i, input ≠ inputs i) :
    updateRp05Batch count inputs outputs oracle input = oracle input := by
  induction count generalizing oracle with
  | zero => rfl
  | succ count ih =>
      rw [updateRp05Batch, ih _ _ _ (fun i => outside i.succ)]
      exact Function.update_of_ne (outside 0) _ _

omit [Fintype Other] in
theorem update_rp05_batch_at (count : Nat)
    (inputs : Fin count → FullInput)
    (outputs : Fin count → DigestRegister)
    (oracle : FullInput → DigestRegister)
    (distinct : Function.Injective inputs) (i : Fin count) :
    updateRp05Batch count inputs outputs oracle (inputs i) = outputs i := by
  induction count generalizing oracle with
  | zero => exact Fin.elim0 i
  | succ count ih =>
      refine Fin.cases ?_ (fun i => ?_) i
      · simp only [updateRp05Batch]
        rw [show updateRp05Batch count (fun i => inputs i.succ)
            (fun i => outputs i.succ)
            (Function.update oracle (inputs 0) (outputs 0)) (inputs 0) =
            Function.update oracle (inputs 0) (outputs 0) (inputs 0) by
          apply update_rp05_batch_outside
          intro i same
          exact Fin.succ_ne_zero _ (distinct same).symm]
        exact Function.update_self _ _ _
      · exact ih _ _ _ (fun a b same =>
          Fin.succ_injective _ (distinct same)) i

omit [Fintype Other] [DecidableEq Other] in
theorem rp05_source_inputs_distinct (preamble : Statement)
    (salt : Fin 32 → Byte) (data : LeafIndex → Fin 1176 → Byte)
    (tapes : LeafIndex → LeafTape) :
    Function.Injective (fun index => (Sum.inl
      (rp05SourceLeafInput preamble salt (data index) index (tapes index)) :
        FullInput)) := by
  intro left right same
  have raw := Sum.inl.inj same
  have projected := congrArg rp05IndexProjection raw
  simpa only [rp05_source_leaf_index_projection] using projected

theorem read_current_answers_execution (randomized : Bool) (count : Nat)
    (keys : Fin count → FullInput)
    (next : (Fin count → DigestRegister) → Program FullInput Work)
    (oracle : FullInput → DigestRegister)
    (state : GameState (Input := FullInput) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run randomized (readCurrentAnswers count keys next) oracle state =
      V8Smz9HonestWholeViewGames.run randomized (next (fun i => oracle (keys i))) oracle state := by
  induction count generalizing state with
  | zero =>
      have empty : (fun i : Fin 0 => oracle (keys i)) = Fin.elim0 :=
        Subsingleton.elim _ _
      simp [readCurrentAnswers, empty]
  | succ count ih =>
      simp only [readCurrentAnswers, V8Smz9HonestWholeViewGames.run]
      rw [ih]
      have answers : Fin.cons (oracle (keys 0))
          (fun i : Fin count => oracle (keys i.succ)) =
          (fun i : Fin (count + 1) => oracle (keys i)) := by
        funext i
        exact Fin.cases rfl (fun _ => rfl) i
      rw [answers]

private theorem rp05_leaf_batch_randomized_execution (count : Nat)
    (indices : Fin count → LeafIndex) (preamble : Statement) (salt : Fin 32 → Byte)
    (data : Fin count → Fin 1176 → Byte)
    (next : (Fin count → LeafTape) → (Fin count → DigestRegister) → Program FullInput Work)
    (oracle : FullInput → DigestRegister)
    (state : GameState (Input := FullInput) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run true
        (rp05LeafBatch count indices preamble salt data next) oracle state =
      uniformAverage (fun tapes : Fin count → LeafTape =>
        uniformAverage (fun outputs : Fin count → DigestRegister =>
          V8Smz9HonestWholeViewGames.run true (next tapes outputs)
            (updateRp05Batch count (fun i => Sum.inl
              (rp05SourceLeafInput preamble salt (data i) (indices i) (tapes i)))
              outputs oracle) state)) := by
  induction count generalizing oracle with
  | zero =>
      have tapes : ∀ xs : Fin 0 → LeafTape, xs = Fin.elim0 :=
        fun _ => Subsingleton.elim _ _
      have outputs : ∀ xs : Fin 0 → DigestRegister, xs = Fin.elim0 :=
        fun _ => Subsingleton.elim _ _
      simp only [rp05LeafBatch, updateRp05Batch, tapes, outputs, uniform_average_const]
  | succ count ih =>
      simp only [rp05LeafBatch, rp05SourceLeaf, V8Smz9HonestWholeViewGames.run,
        if_true, rp05LeafSampler, Function.update_self]
      conv_rhs => rw [uniform_average_fin_cons count]
      apply congrArg uniformAverage
      funext tape
      simp_rw [ih]
      rw [uniform_average_comm]
      apply congrArg uniformAverage
      funext tapes
      conv_rhs => rw [uniform_average_fin_cons count]
      apply congrArg uniformAverage
      funext output
      apply congrArg uniformAverage
      funext outputs
      rfl

/-- Exact fresh-answer/current-answer identity.  The right side first installs
the independently sampled outputs in one persistent table and then measures
those CURRENT cells.  The old answers are not substituted for the readout. -/
theorem rp05_leaf_batch_is_current_answer_overlay (count : Nat)
    (indices : Fin count → LeafIndex) (distinct : Function.Injective indices)
    (preamble : Statement) (salt : Fin 32 → Byte)
    (data : Fin count → Fin 1176 → Byte)
    (next : (Fin count → LeafTape) → (Fin count → DigestRegister) →
      Program FullInput Work)
    (oracle : FullInput → DigestRegister)
    (state : GameState (Input := FullInput) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run true (rp05LeafBatch count indices preamble salt data next) oracle state =
      uniformAverage (fun tapes : Fin count → LeafTape =>
        uniformAverage (fun outputs : Fin count → DigestRegister =>
          let keys : Fin count → FullInput := fun i => Sum.inl
            (rp05SourceLeafInput preamble salt (data i) (indices i) (tapes i))
          let overlay := updateRp05Batch count keys outputs oracle
          V8Smz9HonestWholeViewGames.run true
            (readCurrentAnswers count keys (next tapes)) overlay state)) := by
  rw [rp05_leaf_batch_randomized_execution]
  apply congrArg uniformAverage
  funext tapes
  apply congrArg uniformAverage
  funext outputs
  let keys : Fin count → FullInput := fun i => Sum.inl
    (rp05SourceLeafInput preamble salt (data i) (indices i) (tapes i))
  change V8Smz9HonestWholeViewGames.run true (next tapes outputs)
      (updateRp05Batch count keys outputs oracle) state =
    V8Smz9HonestWholeViewGames.run true (readCurrentAnswers count keys (next tapes))
      (updateRp05Batch count keys outputs oracle) state
  have keyDistinct : Function.Injective keys := by
    intro left right same
    apply distinct
    have raw := Sum.inl.inj same
    simpa only [rp05_source_leaf_index_projection] using congrArg rp05IndexProjection raw
  rw [read_current_answers_execution]
  have answers : (fun i => updateRp05Batch count keys outputs oracle (keys i)) = outputs := by
    funext i
    exact update_rp05_batch_at count keys outputs oracle keyDistinct i
  rw [answers]

end Rp05RequestCompiler

section Rp05Chronology

open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra

/-- The current-answer request identity composes with the RP05/818-root
state-valued response transport.  The intermediate measured branch is kept
inside `kernel`, hence the second coin translation occurs chronologically
after the branch and not against a fixed random-oracle table. -/
theorem rp05_chronological_response_sum
    {PublicBranch Value : Type*} [Fintype PublicBranch] [AddCommMonoid Value]
    (dsl : HegemonCrypto.SmallWood.SmzaRp05RelationRefinement.RelationDsl)
    (statement : Statement)
    (gamma : Gamma Goldilocks)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks)
    (parameters :
      HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra.D → PublicBranch →
        Parameters dsl statement)
    (kernel : HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra.D →
      PublicBranch → HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra.Q →
      HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra.D →
      HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra.Q → Value) :
    (∑ q, ∑ m, ∑ branch,
      let reply := V8SmzaMathPrivacy.response gamma
        (currentHeads values base q) base.2.2 m
      kernel reply branch q m
        (Q38Rp05ChronologicalAlgebra.response dsl statement (parameters reply branch)
          (sourceWitnessPolynomials values base.1) q)) =
    ∑ reply, ∑ branch, ∑ transcript,
      let q := transcript - unmaskedResponse dsl statement
        (parameters reply branch) (sourceWitnessPolynomials values base.1)
      let m := reply - V8SmzaMathPrivacy.unmasked gamma
        (currentHeads values base q) base.2.2
      kernel reply branch q m transcript := by
  exact response_state_kernel_sum dsl statement gamma values base parameters
    kernel

end Rp05Chronology

section LatchedFailure

open HegemonCrypto.SmallWood.V8Smz9CappedRawSampler
open HegemonCrypto.SmallWood.V8Smz9CappedRawSamplerTail
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler

/-- Actual source scope: once either capped field sampler exhausts, the request
remains failed through every later round. -/
def latchFailure (failed now : Bool) : Bool := failed || now

theorem latch_failure_monotone (failed now : Bool) :
    failed = true → latchFailure failed now = true := by
  intro h
  simp [latchFailure, h]

/-- The failure event is the literal source byte parser at its actual capped
counter count.  This is not an abstract per-round failure parameter. -/
theorem literal_source_field_xof_failure_bound (requested : Nat)
    (positive : 0 < requested) :
    literalByteParserLaw (digestCallCap requested) requested none ≤
      unionBound (digestCallCap requested * 8)
        (digestCallCap requested * 8 - requested + 1) := by
  exact literal_byte_parser_abort_choose_union_bound
    (digestCallCap requested) requested positive
      (positive_request_capacity_threshold requested positive).1

theorem literal_decs_field_xof_failure_bound :
    literalByteParserLaw (digestCallCap 700) 700 none ≤
      unionBound (digestCallCap 700 * 8)
        (digestCallCap 700 * 8 - 700 + 1) := by
  exact literal_source_field_xof_failure_bound 700 (by norm_num)

theorem literal_piop_field_xof_failure_bound (retainedRows : Nat)
    (bounded : retainedRows ≤ 20605) :
    literalByteParserLaw
        (digestCallCap (gammaRequestedWords retainedRows))
        (gammaRequestedWords retainedRows) none ≤
      unionBound 103064 33 := by
  exact gamma_all_rows_literal_abort_union_bound retainedRows bounded

/-- First-bad decomposition for the literal sampler events.  This is an exact
finite union statement; it does not assume a per-round security advantage. -/
theorem first_sampler_failure_union_bound (rounds : Nat)
    (bad : Fin rounds → Finset (Fin (2 ^ 64))) :
    (Finset.univ.filter (fun coin : Fin (2 ^ 64) =>
      ∃ round, coin ∈ bad round)).card ≤
      ∑ round, (bad round).card := by
  have subset : Finset.univ.filter (fun coin : Fin (2 ^ 64) =>
      ∃ round, coin ∈ bad round) ⊆
      (Finset.univ : Finset (Fin rounds)).biUnion bad := by
    intro coin member
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at member
    obtain ⟨round, badCoin⟩ := member
    exact Finset.mem_biUnion.mpr ⟨round, Finset.mem_univ _, badCoin⟩
  exact (Finset.card_le_card subset).trans
    (Finset.card_biUnion_le (s := Finset.univ) (t := bad))

end LatchedFailure

end
end HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
