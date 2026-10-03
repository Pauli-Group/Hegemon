import Q38Rp05RequestCompiler
import HegemonCrypto.SmallWoodV8Smz9RunHomogeneity
import Q38Rp05ExecutionBridgeEnvironment

/-!
# RP05 initialized-CMS execution bridge

This file records two distinct exact identities.  First, after controlled
swaps we can decode the complete persistent database, reconstruct its
canonical total-oracle family, and execute the same seven-constructor
`Program` on every named oracle branch.  That family remains tape-dependent,
so this identity alone is deliberately *not* advertised as the common-state
input to the adaptive-opening theorem.  Second, the literal RP05
`Program.freshInput` batch is reduced to the finite old-oracle/full-overlay
law while retaining the old-oracle-indexed prior state.

The terminal reads below are explicitly CURRENT reads.  On each canonical
branch they return `oracle (key i)`; reinstalling those answers with the RP05
batch-update function leaves that complete oracle unchanged.  Thus the saved
fresh-label registers are never substituted for current database answers.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9RunHomogeneity
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8SmzaCmsSwapConjugation
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

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

/-- Reinstalling the values currently stored at a set of distinct RP05 keys
is the identity on the complete oracle. -/
theorem update_rp05_batch_current_answers (count : Nat)
    (keys : Fin count → FullInput) (distinct : Function.Injective keys)
    (oracle : FullInput → DigestRegister) :
    updateRp05Batch count keys (fun i => oracle (keys i)) oracle = oracle := by
  funext input
  by_cases hit : ∃ i, input = keys i
  · obtain ⟨i, rfl⟩ := hit
    exact update_rp05_batch_at count keys
      (fun i => oracle (keys i)) oracle distinct i
  · exact update_rp05_batch_outside count keys
      (fun i => oracle (keys i)) oracle input (fun i same => hit ⟨i, same⟩)

/-- Literal successor keys remain distinct after selecting any injective list
of leaf indices.  The proof uses the index bytes of the current 2,511-byte
RP05 input and does not appeal to the RP04 namespace. -/
theorem rp05_current_keys_injective (count : Nat)
    (sites : Fin count → LeafIndex) (siteDistinct : Function.Injective sites)
    (preamble : Statement) (salt : Fin 32 → Byte)
    (data : LeafIndex → Fin 1176 → Byte) (tapes : LeafIndex → LeafTape) :
    Function.Injective (fun i => (Sum.inl
      (rp05SourceLeafInput preamble salt (data (sites i))
        (sites i) (tapes (sites i))) : FullInput)) := by
  intro left right same
  apply siteDistinct
  have raw := Sum.inl.inj same
  simpa only [rp05_source_leaf_index_projection] using
    congrArg rp05IndexProjection raw

/-- Pointwise finite fresh-input law in the ordering needed by the RP05
request.  The old complete oracle and its prior state stay fixed; fresh tapes
and outputs create the persistent overlay, and the continuation receives the
CURRENT overlay answers.  The overwritten answers are exactly the branch sum
inside the already-proved `Program.freshInput` interpreter. -/
theorem rp05_leaf_batch_full_overlay_execution (count : Nat)
    (sites : Fin count → LeafIndex) (siteDistinct : Function.Injective sites)
    (preamble : Statement) (salt : Fin 32 → Byte)
    (data : Fin count → Fin 1176 → Byte)
    (next : (Fin count → LeafTape) →
      (Fin count → DigestRegister) → Program FullInput BaseWork)
    (oracle : FullInput → DigestRegister)
    (state : GameState (Input := FullInput) (Work := BaseWork)) :
    V8Smz9HonestWholeViewGames.run true
        (rp05LeafBatch count sites preamble salt data next) oracle state =
      uniformAverage (fun tapes : Fin count → LeafTape =>
        uniformAverage (fun outputs : Fin count → DigestRegister =>
          let keys : Fin count → FullInput := fun i => Sum.inl
            (rp05SourceLeafInput preamble salt (data i) (sites i) (tapes i))
          let fullOverlay := updateRp05Batch count keys outputs oracle
          V8Smz9HonestWholeViewGames.run true (next tapes outputs)
            fullOverlay state)) := by
  rw [rp05_leaf_batch_is_current_answer_overlay count sites siteDistinct
    preamble salt data next oracle state]
  apply congrArg uniformAverage
  funext tapes
  apply congrArg uniformAverage
  funext outputs
  dsimp only
  let keys : Fin count → FullInput := fun i => Sum.inl
    (rp05SourceLeafInput preamble salt (data i) (sites i) (tapes i))
  let fullOverlay := updateRp05Batch count keys outputs oracle
  rw [read_current_answers_execution]
  congr 1
  apply congrArg (next tapes)
  funext i
  apply update_rp05_batch_at count keys outputs oracle
  intro left right same
  apply siteDistinct
  have raw := Sum.inl.inj same
  simpa only [rp05_source_leaf_index_projection] using
    congrArg rp05IndexProjection raw

/-- Oracle-indexed prior form of the same law.  This is the precise finite
identity

`avg_H run leafBatch H f_H = avg_H,tapes,b run next(b) (H[S:=b]) f_H`.

In particular, the state is `prior H`, not a tape-dependent canonical family
and not `prior (H[S:=b])`. -/
theorem rp05_leaf_batch_preserves_old_oracle_prior (count : Nat)
    (sites : Fin count → LeafIndex) (siteDistinct : Function.Injective sites)
    (preamble : Statement) (salt : Fin 32 → Byte)
    (data : Fin count → Fin 1176 → Byte)
    (next : (Fin count → LeafTape) →
      (Fin count → DigestRegister) → Program FullInput BaseWork)
    (prior : (FullInput → DigestRegister) →
      GameState (Input := FullInput) (Work := BaseWork)) :
    uniformAverage (fun oracle : FullInput → DigestRegister =>
      V8Smz9HonestWholeViewGames.run true
        (rp05LeafBatch count sites preamble salt data next)
        oracle (prior oracle)) =
      uniformAverage (fun oracle : FullInput → DigestRegister =>
        uniformAverage (fun tapes : Fin count → LeafTape =>
          uniformAverage (fun outputs : Fin count → DigestRegister =>
            let keys : Fin count → FullInput := fun i => Sum.inl
              (rp05SourceLeafInput preamble salt (data i) (sites i) (tapes i))
            let fullOverlay := updateRp05Batch count keys outputs oracle
            V8Smz9HonestWholeViewGames.run true (next tapes outputs)
              fullOverlay (prior oracle)))) := by
  apply congrArg uniformAverage
  funext oracle
  exact rp05_leaf_batch_full_overlay_execution count sites siteDistinct
    preamble salt data next oracle (prior oracle)

/-- The same identity in tape-first order, matching the averaging order of
the controlled-CMS disturbance theorem. -/
theorem rp05_leaf_batch_preserves_old_oracle_prior_tape_first (count : Nat)
    (sites : Fin count → LeafIndex) (siteDistinct : Function.Injective sites)
    (preamble : Statement) (salt : Fin 32 → Byte)
    (data : Fin count → Fin 1176 → Byte)
    (next : (Fin count → LeafTape) →
      (Fin count → DigestRegister) → Program FullInput BaseWork)
    (prior : (FullInput → DigestRegister) →
      GameState (Input := FullInput) (Work := BaseWork)) :
    uniformAverage (fun oracle : FullInput → DigestRegister =>
      V8Smz9HonestWholeViewGames.run true
        (rp05LeafBatch count sites preamble salt data next)
        oracle (prior oracle)) =
      uniformAverage (fun tapes : Fin count → LeafTape =>
        uniformAverage (fun outputs : Fin count → DigestRegister =>
          uniformAverage (fun oracle : FullInput → DigestRegister =>
            let keys : Fin count → FullInput := fun i => Sum.inl
              (rp05SourceLeafInput preamble salt (data i) (sites i) (tapes i))
            let fullOverlay := updateRp05Batch count keys outputs oracle
            V8Smz9HonestWholeViewGames.run true (next tapes outputs)
              fullOverlay (prior oracle)))) := by
  rw [rp05_leaf_batch_preserves_old_oracle_prior count sites siteDistinct
    preamble salt data next prior]
  rw [V8Smz9CurrentPrivacyComposition.uniform_average_comm]
  apply congrArg uniformAverage
  funext tapes
  exact V8Smz9CurrentPrivacyComposition.uniform_average_comm _

/-- Controlled swaps preserve complete-database support after the exact
phase decode.  This is the concrete state invariant needed by canonical
oracle-family reconstruction. -/
theorem controlled_phase_decode_total_support
    (selected : Branch → LeafIndex → FullInput)
    (indices : List LeafIndex) (core : FullCore → ℂ)
    (baseSupport : TotalDatabaseSupport
      (globalDecompress
        (initializedFreshState (Index := LeafIndex) core))) :
    TotalDatabaseSupport
      (phaseDecode
        (controlledCompressed selected indices
          (initializedFreshState (Index := LeafIndex) core))) := by
  unfold phaseDecode
  apply total_database_support_response_fourier_inverse
  rw [global_controlled_swap_intertwining]
  exact total_database_support_controlled_raw selected indices _ baseSupport

/-- Exact pointwise canonical decomposition.  The left side is the initialized CMS
state after the actual branch-controlled swaps.  The right side is the
existing `Program.run` on every complete oracle in the canonical family of
that same decoded state.  Sequential honest reads receive current oracle
answers, while the full register state (including saved labels) is retained
as `familyGameState`.

No desired execution equality or adaptive-reprogramming theorem is assumed.
Because the canonical family depends on `changed`, callers must not use this
theorem as a common-state adaptive-opening bridge without the separate
old-label environment trace-out law.
-/
theorem controlled_current_answers_as_oracle_runs
    (randomized : Bool)
    (selected : Branch → LeafIndex → FullInput)
    (indices : List LeafIndex) (core : FullCore → ℂ)
    (baseSupport : TotalDatabaseSupport
      (globalDecompress
        (initializedFreshState (Index := LeafIndex) core)))
    (count : Nat) (readKeys : Fin count → FullInput)
    (next : (Fin count → DigestRegister) → Program FullInput FullWork) :
    let changed := controlledCompressed selected indices
      (initializedFreshState (Index := LeafIndex) core)
    phaseRun randomized (readCurrentAnswers count readKeys next) changed =
      uniformAverage (fun oracle : FullInput → DigestRegister =>
        V8Smz9HonestWholeViewGames.run randomized
          (next (fun i => oracle (readKeys i))) oracle
          (familyGameState
            (canonicalTotalFamily (phaseDecode changed)) oracle)) := by
  dsimp only
  let changed := controlledCompressed selected indices
    (initializedFreshState (Index := LeafIndex) core)
  have supported : TotalDatabaseSupport (phaseDecode changed) :=
    controlled_phase_decode_total_support selected indices core baseSupport
  calc
    phaseRun randomized (readCurrentAnswers count readKeys next) changed =
        databaseRun randomized (readCurrentAnswers count readKeys next)
          (phaseDecode changed) :=
      phase_run_eq_database_run randomized _ _
    _ = databaseRun randomized (readCurrentAnswers count readKeys next)
          (totalOracleFamilyState
            (canonicalTotalFamily (phaseDecode changed))) := by
      rw [total_oracle_family_canonical_eq (phaseDecode changed) supported]
    _ = uniformAverage (fun oracle : FullInput → DigestRegister =>
          databaseRun randomized (readCurrentAnswers count readKeys next)
            (oracleState oracle
              (familyGameState
                (canonicalTotalFamily (phaseDecode changed)) oracle))) :=
      databaseRun_totalOracleFamilyState randomized _ _
    _ = uniformAverage (fun oracle : FullInput → DigestRegister =>
          V8Smz9HonestWholeViewGames.run randomized
            (readCurrentAnswers count readKeys next) oracle
            (familyGameState
              (canonicalTotalFamily (phaseDecode changed)) oracle)) := by
      apply congrArg uniformAverage
      funext oracle
      exact databaseRun_oracleState randomized _ _ _
    _ = uniformAverage (fun oracle : FullInput → DigestRegister =>
          V8Smz9HonestWholeViewGames.run randomized
            (next (fun i => oracle (readKeys i))) oracle
            (familyGameState
              (canonicalTotalFamily (phaseDecode changed)) oracle)) := by
      apply congrArg uniformAverage
      funext oracle
      exact read_current_answers_execution randomized count readKeys next
        oracle _

/-- Equivalent full-overlay form of the preceding endpoint.  The overlay is
built from the CURRENT answers of the canonical complete oracle, and hence is
definitionally the same physical oracle by
`update_rp05_batch_current_answers`. -/
theorem controlled_current_answers_as_full_overlays
    (randomized : Bool)
    (selected : Branch → LeafIndex → FullInput)
    (indices : List LeafIndex) (core : FullCore → ℂ)
    (baseSupport : TotalDatabaseSupport
      (globalDecompress
        (initializedFreshState (Index := LeafIndex) core)))
    (count : Nat) (readKeys : Fin count → FullInput)
    (distinct : Function.Injective readKeys)
    (next : (Fin count → DigestRegister) → Program FullInput FullWork) :
    let changed := controlledCompressed selected indices
      (initializedFreshState (Index := LeafIndex) core)
    phaseRun randomized (readCurrentAnswers count readKeys next) changed =
      uniformAverage (fun oracle : FullInput → DigestRegister =>
        let current := fun i => oracle (readKeys i)
        let fullOverlay := updateRp05Batch count readKeys current oracle
        V8Smz9HonestWholeViewGames.run randomized (next current) fullOverlay
          (familyGameState
            (canonicalTotalFamily (phaseDecode changed)) oracle)) := by
  change phaseRun randomized (readCurrentAnswers count readKeys next)
      (controlledCompressed selected indices
        (initializedFreshState (Index := LeafIndex) core)) =
    uniformAverage (fun oracle : FullInput → DigestRegister =>
      let current := fun i => oracle (readKeys i)
      let fullOverlay := updateRp05Batch count readKeys current oracle
      V8Smz9HonestWholeViewGames.run randomized (next current) fullOverlay
        (familyGameState
          (canonicalTotalFamily (phaseDecode
            (controlledCompressed selected indices
              (initializedFreshState (Index := LeafIndex) core)))) oracle))
  rw [controlled_current_answers_as_oracle_runs randomized selected indices
    core baseSupport count readKeys next]
  apply congrArg uniformAverage
  funext oracle
  dsimp only
  rw [update_rp05_batch_current_answers count readKeys distinct oracle]

/-- Uniform-tape form used immediately after the RP05 controlled-resampling
hybrid.  Every tape branch uses its own current strict-v2 keys and its own
canonical complete-oracle decomposition; there is no common saved-answer
table smuggled across branches. -/
theorem rp05_controlled_current_answers_average
    (randomized : Bool)
    (preamble : Branch → Statement)
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex) (core : FullCore → ℂ)
    (baseSupport : TotalDatabaseSupport
      (globalDecompress
        (initializedFreshState (Index := LeafIndex) core)))
    (count : Nat)
    (readKeys : (LeafIndex → LeafTape) → Fin count → FullInput)
    (next : (LeafIndex → LeafTape) →
      (Fin count → DigestRegister) → Program FullInput FullWork) :
    uniformAverage (fun tapes : LeafIndex → LeafTape =>
      phaseRun randomized
        (readCurrentAnswers count (readKeys tapes) (next tapes))
        (controlledCompressed (rp05Selected preamble salt data tapes) indices
          (initializedFreshState (Index := LeafIndex) core))) =
      uniformAverage (fun tapes : LeafIndex → LeafTape =>
        let changed := controlledCompressed
          (rp05Selected preamble salt data tapes) indices
          (initializedFreshState (Index := LeafIndex) core)
        uniformAverage (fun oracle : FullInput → DigestRegister =>
          V8Smz9HonestWholeViewGames.run randomized
            (next tapes (fun i => oracle (readKeys tapes i))) oracle
            (familyGameState
              (canonicalTotalFamily (phaseDecode changed)) oracle))) := by
  apply congrArg uniformAverage
  funext tapes
  exact controlled_current_answers_as_oracle_runs randomized
    (rp05Selected preamble salt data tapes) indices core baseSupport
    count (readKeys tapes) (next tapes)

/-- Fully initialized specialization.  The base-support fact is discharged by
the checked execution of the actual CMS query sequence from the empty random
oracle; it is not exposed as an endpoint premise. -/
theorem rp05_initialized_current_answers_as_oracle_runs
    (system : PhaseSystem DigestRegister DigestRegister)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := FullInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Branch × BaseWork)))
    (initialRegisters :
      RegisterBasis (Input := FullInput) (Phase := DigestRegister)
        (Workspace := Branch × BaseWork) → ℂ)
    (capacity : steps.length ≤ queryBound)
    (randomized : Bool)
    (selected : Branch → LeafIndex → FullInput)
    (indices : List LeafIndex)
    (count : Nat) (readKeys : Fin count → FullInput)
    (next : (Fin count → DigestRegister) → Program FullInput FullWork) :
    let reached := rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
    let changed := controlledCompressed selected indices
      (initializedFreshState (Index := LeafIndex) (coreOfCmsState reached))
    phaseRun randomized (readCurrentAnswers count readKeys next) changed =
      uniformAverage (fun oracle : FullInput → DigestRegister =>
        V8Smz9HonestWholeViewGames.run randomized
          (next (fun i => oracle (readKeys i))) oracle
          (familyGameState
            (canonicalTotalFamily (phaseDecode changed)) oracle)) := by
  dsimp only
  let reached := rawRun system queryBound
    (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
    (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
  have baseSupport : TotalDatabaseSupport
      (globalDecompress
        (initializedFreshState (Index := LeafIndex)
          (coreOfCmsState reached))) := by
    exact raw_run_initializedFreshState_total_support
      (Index := LeafIndex) system queryBound steps initialRegisters capacity
  exact controlled_current_answers_as_oracle_runs randomized selected indices
    (coreOfCmsState reached) baseSupport count readKeys next

/-- Uniform-tape corollary at the same fully initialized endpoint.  This is
the equality consumed alongside `rp05_initialized_dependent_phase_run_bound`:
the latter changes the state, while this theorem identifies the execution on
the changed state without another privacy or run-equivalence premise. -/
theorem rp05_initialized_current_answers_average
    (system : PhaseSystem DigestRegister DigestRegister)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := FullInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Branch × BaseWork)))
    (initialRegisters :
      RegisterBasis (Input := FullInput) (Phase := DigestRegister)
        (Workspace := Branch × BaseWork) → ℂ)
    (capacity : steps.length ≤ queryBound)
    (randomized : Bool)
    (preamble : Branch → Statement)
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex) (count : Nat)
    (readKeys : (LeafIndex → LeafTape) → Fin count → FullInput)
    (next : (LeafIndex → LeafTape) →
      (Fin count → DigestRegister) → Program FullInput FullWork) :
    let reached := rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
    uniformAverage (fun tapes : LeafIndex → LeafTape =>
      phaseRun randomized
        (readCurrentAnswers count (readKeys tapes) (next tapes))
        (controlledCompressed (rp05Selected preamble salt data tapes) indices
          (initializedFreshState (Index := LeafIndex)
            (coreOfCmsState reached)))) =
      uniformAverage (fun tapes : LeafIndex → LeafTape =>
        let changed := controlledCompressed
          (rp05Selected preamble salt data tapes) indices
          (initializedFreshState (Index := LeafIndex)
            (coreOfCmsState reached))
        uniformAverage (fun oracle : FullInput → DigestRegister =>
          V8Smz9HonestWholeViewGames.run randomized
            (next tapes (fun i => oracle (readKeys tapes i))) oracle
            (familyGameState
              (canonicalTotalFamily (phaseDecode changed)) oracle))) := by
  dsimp only
  let reached := rawRun system queryBound
    (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
    (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
  have baseSupport : TotalDatabaseSupport
      (globalDecompress
        (initializedFreshState (Index := LeafIndex)
          (coreOfCmsState reached))) := by
    exact raw_run_initializedFreshState_total_support
      (Index := LeafIndex) system queryBound steps initialRegisters capacity
  exact rp05_controlled_current_answers_average randomized preamble salt data
    indices (coreOfCmsState reached) baseSupport count readKeys next

end
end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
