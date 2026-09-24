import HegemonCrypto.SmallWoodV8Smz9SourceByteProgram
import HegemonCrypto.SmallWoodV8Smz9PublicByteAccounting

/-! Repeated hidden-byte replacement in one finite adaptive lifetime.

Every byte call is expanded by the actual charged source/public compiler.
The indexed query budget covers both worlds and every byte/error future.
The entire syntax and initial state are fixed before the uniform raw oracle.
Measurements retain their original subnormalized branch states.

This theorem starts at admitted post-final byte stages. It does not assert
that arbitrary stage fields arose from an earlier dynamic source request,
does not supply the preceding final-hash reprogramming telescope, and does
not establish a full witness-pair or production privacy endpoint. -/

namespace HegemonCrypto.SmallWood.V8Smz9HiddenLifetime

open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SemanticBinding V8Smz9HiddenLeafQrom V8Smz9HiddenPatch
open V8Smz9EagerPrivacy V8Smz9EagerOracleGame V8Smz9RuntimeRandomness
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9CurrentPublicContext
open V8Smz9ZeroKnowledge V8Smz9MeasuredSameOracleAdjacent
open V8Smz9HonestHybrid (DecsGamma DecsFullCoefficients)
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestRequestSchedule
open V8Smz9PostFinalProgram V8Smz9PostFinalPhysical V8Smz9BytePrefix
open V8Smz9PublicByteProgram V8Smz9PublicByteAccounting V8Smz9SourceByteProgram
open V8Smz9PrivacyGameComposition V8Smz9MeasuredRunContinuity
open V8Smz9RuntimeDistribution
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical BigOperators

noncomputable section
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
set_option Elab.async false

/-- All 2^23 literal source writes plus at most 97 post-final reads.
The public implementation costs at most 117, hence fits this same budget. -/
def byteCallCost : Nat := 8388705

theorem public_cost_le_byte_call_cost : 117 ≤ byteCallCost := by
  norm_num [byteCallCost]

attribute [local irreducible] byteCallCost

/-- The same public stage data is used in both worlds. The witness and its
packed-domain certificate are consumed only by the source implementation and
the local hidden-patch theorem. No continuation, oracle or state is a field. -/
structure SourceByteStage (bound : Nat) where
  largeEnough : 37434 ≤ bound
  statement : V8PublicStatement
  publicValues : List Nat
  batching : Fin 5 → Nat → Goldilocks
  gamma : DecsGamma Goldilocks
  response : DecsFullCoefficients Goldilocks
  transcript : PiopCoefficients Goldilocks
  digest : DigestRegister
  pending : Bool
  salt : SaltBytes
  labels : LeafIndex → DigestRegister
  tree : List (List DigestRegister)
  witness : List Nat
  domain : CanonicalPublicPackedDomain statement publicValues witness

abbrev ByteResult := Except String (List CanonicalBytes.Byte)

/-- Query and call indices are worst-branch budgets, and finish may leave
either budget unused. A call cannot hide an unbounded byte continuation. -/
inductive Lifetime (bound : Nat) (Work : Type) [Fintype Work] : Nat → Nat → Type 1 where
  | finish {queries requests : Nat}
      (event : Finset (QueryBasis (FullRawInput bound) DigestRegister Work)) :
      Lifetime bound Work queries requests
  | gate {queries requests : Nat}
      (operation : GameGate (Input := FullRawInput bound) (Work := Work))
      (next : Lifetime bound Work queries requests) : Lifetime bound Work queries requests
  | quantumQuery {queries requests : Nat}
      (next : Lifetime bound Work queries requests) : Lifetime bound Work (queries + 1) requests
  | honestRead {queries requests : Nat} (input : FullRawInput bound)
      (next : DigestRegister → Lifetime bound Work queries requests) :
      Lifetime bound Work (queries + 1) requests
  | instrument {queries requests count : Nat}
      (operation : Instrument (FullRawInput bound) Work count)
      (next : Fin count → Lifetime bound Work queries requests) : Lifetime bound Work queries requests
  | random {queries requests : Nat} (source : RandomSource)
      (next : source.Coins → Lifetime bound Work queries requests) : Lifetime bound Work queries requests
  | write {queries requests : Nat} (input : FullRawInput bound) (answer : DigestRegister)
      (next : Lifetime bound Work queries requests) : Lifetime bound Work (queries + 1) requests
  | nonleaf {queries requests : Nat} {Result : Type} (reads : Nat)
      (program : NonleafProgram (OtherRawInput bound) Result)
      (counted : NonleafProgram.readCount program ≤ reads)
      (next : Result → Lifetime bound Work queries requests) :
      Lifetime bound Work (reads + queries) requests
  | byteCall {queries requests : Nat} (stage : SourceByteStage bound)
      (next : ByteResult → Lifetime bound Work queries requests) :
      Lifetime bound Work (byteCallCost + queries) (requests + 1)

variable {bound : Nat} {Work : Type} [Fintype Work]

abbrev BoundedMixed (bound : Nat) (Work : Type) [Fintype Work] (queries : Nat) :=
  { program : MixedProgram (FullRawInput bound) Work //
    V8Smz9MixedMaskCompiler.queryCount program ≤ queries }

/-- A fresh local compiler log does not reset the oracle: the complete
future is interpreted against the current live effective table. -/
def futureGames {queries : Nat} (next : ByteResult → BoundedMixed bound Work queries) :
    ByteFuture (Work := Work) bound :=
  fun bytes => V8Smz9MixedMaskCompiler.compile (next bytes).1 []

theorem future_games_query_bound {queries : Nat} (next : ByteResult → BoundedMixed bound Work queries)
    (bytes : ByteResult) : queryCount (futureGames next bytes) ≤ queries :=
  (V8Smz9MixedMaskCompiler.compiled_query_count_le (next bytes).1 []).trans (next bytes).2

def SourceByteStage.toJob {queries : Nat} (stage : SourceByteStage bound)
    (next : ByteResult → BoundedMixed bound Work queries) : BytePivotJob (Work := Work) bound queries where
  largeEnough := stage.largeEnough
  statement := stage.statement
  publicValues := stage.publicValues
  batching := stage.batching
  gamma := stage.gamma
  response := stage.response
  transcript := stage.transcript
  digest := stage.digest
  pending := stage.pending
  salt := stage.salt
  labels := stage.labels
  tree := stage.tree
  next := futureGames next
  witness := stage.witness
  domain := stage.domain
  bounded := future_games_query_bound next

/-- Both branches return their proved query budget. False is the literal
source replay and true is the opened-only public byte implementation. -/
def buildByteCall (publicWorld : Bool) {queries : Nat} (stage : SourceByteStage bound)
    (next : ByteResult → BoundedMixed bound Work queries) :
    BoundedMixed bound Work (byteCallCost + queries) := by
  let job := stage.toJob next
  cases publicWorld with
  | false =>
      refine ⟨sourceByteProgram false bound queries job, ?_⟩
      simpa only [byteCallCost] using source_byte_program_query_bound false bound queries job
  | true =>
      refine ⟨publicByteProgram false bound job.toPublicBytePivot, ?_⟩
      exact (public_byte_program_query_bound false bound job.toPublicBytePivot queries job.bounded).trans
        (Nat.add_le_add_right public_cost_le_byte_call_cost queries)

/-- Compilation and its certificate are constructed together by structural
recursion. No future-budget or endpoint equality is assumed as an input. -/
def compileWorld (publicWorld : Bool) : {queries requests : Nat} →
    Lifetime bound Work queries requests → BoundedMixed bound Work queries
  | _, _, .finish event => ⟨.finish event, Nat.zero_le _⟩
  | _, _, .gate operation next =>
      ⟨.gate operation (compileWorld publicWorld next).1, (compileWorld publicWorld next).2⟩
  | _, _, .quantumQuery next =>
      ⟨.quantumQuery (compileWorld publicWorld next).1,
        Nat.add_le_add_right (compileWorld publicWorld next).2 1⟩
  | _, _, .honestRead input next =>
      ⟨.honestRead input (fun answer => (compileWorld publicWorld (next answer)).1),
        Nat.add_le_add_right (Finset.sup_le fun answer _ => (compileWorld publicWorld (next answer)).2) 1⟩
  | _, _, .instrument operation next =>
      ⟨.instrument operation (fun outcome => (compileWorld publicWorld (next outcome)).1),
        Finset.sup_le fun outcome _ => (compileWorld publicWorld (next outcome)).2⟩
  | _, _, .random source next =>
      ⟨.random source (fun coins => (compileWorld publicWorld (next coins)).1),
        Finset.sup_le fun coins _ => (compileWorld publicWorld (next coins)).2⟩
  | _, _, .write input answer next =>
      ⟨.write input answer (compileWorld publicWorld next).1,
        Nat.add_le_add_right (compileWorld publicWorld next).2 1⟩
  | _, _, .nonleaf reads program counted next =>
      ⟨compileNonleaf program (fun result => (compileWorld publicWorld (next result)).1),
        (mixed_nonleaf_query_bound program _ _ (fun result => (compileWorld publicWorld (next result)).2)).trans
          (Nat.add_le_add_right counted _)⟩
  | _, _, .byteCall stage next =>
      buildByteCall publicWorld stage (fun bytes => compileWorld publicWorld (next bytes))

theorem compiled_query_bound (publicWorld : Bool) {queries requests : Nat}
    (lifetime : Lifetime bound Work queries requests) :
    V8Smz9MixedMaskCompiler.queryCount (compileWorld publicWorld lifetime).1 ≤ queries :=
  (compileWorld publicWorld lifetime).2

def runLifetime (publicWorld : Bool) {queries requests : Nat}
    (lifetime : Lifetime bound Work queries requests) (oracle : FullOracle bound)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) : ℝ :=
  V8Smz9MixedMaskCompiler.run false (compileWorld publicWorld lifetime).1 oracle state

theorem future_games_execution {queries : Nat} (next : ByteResult → BoundedMixed bound Work queries)
    (bytes : ByteResult) (oracle : FullOracle bound)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    run false (futureGames next bytes) oracle state =
      V8Smz9MixedMaskCompiler.run false (next bytes).1 oracle state := by
  unfold futureGames
  rw [V8Smz9MixedMaskCompiler.compile_executes,
    V8Smz9MixedMaskCompiler.effective_empty]

theorem nonleaf_execution (publicWorld : Bool) {queries requests : Nat} {Result : Type}
    (reads : Nat) (program : NonleafProgram (OtherRawInput bound) Result)
    (counted : NonleafProgram.readCount program ≤ reads)
    (next : Result → Lifetime bound Work queries requests) (oracle : FullOracle bound)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    runLifetime publicWorld (.nonleaf reads program counted next) oracle state =
      runLifetime publicWorld
        (next (NonleafProgram.interpret (fun input => oracle (Sum.inr input)) program)) oracle state := by
  change V8Smz9MixedMaskCompiler.run false
    (compileNonleaf program (fun result => (compileWorld publicWorld (next result)).1)) oracle state = _
  exact compile_nonleaf_executes false program _ oracle state

theorem source_call_execution {queries requests : Nat} (stage : SourceByteStage bound)
    (next : ByteResult → Lifetime bound Work queries requests) (oracle : FullOracle bound)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    runLifetime false (.byteCall stage next) oracle state =
      rawByteSourceKernel false bound queries
        (stage.toJob (fun bytes => compileWorld false (next bytes))) oracle state := by
  change V8Smz9MixedMaskCompiler.run false
    (sourceByteProgram false bound queries (stage.toJob (fun bytes => compileWorld false (next bytes))))
    oracle state = _
  exact source_byte_program_executes_raw_kernel false false bound queries _ oracle state

theorem public_call_execution {queries requests : Nat} (stage : SourceByteStage bound)
    (next : ByteResult → Lifetime bound Work queries requests) (oracle : FullOracle bound)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    runLifetime true (.byteCall stage next) oracle state =
      rawBytePublicKernel false bound
        (stage.toJob (fun bytes => compileWorld true (next bytes))).toPublicBytePivot oracle state := by
  change V8Smz9MixedMaskCompiler.run false
    (publicByteProgram false bound (stage.toJob (fun bytes => compileWorld true (next bytes))).toPublicBytePivot)
    oracle state = _
  exact public_byte_program_executes_raw_kernel false false bound _ oracle state

theorem stage_job_replace_future {queries : Nat} (stage : SourceByteStage bound)
    (left right : ByteResult → BoundedMixed bound Work queries) :
    replaceByteNext bound queries (stage.toJob left) (futureGames right) (future_games_query_bound right) =
      stage.toJob right := rfl

/-- Telescope one call by changing the future under the source execution,
then applying the already-proved source/public pivot with that public future.
The same source/public stage fields are retained on all three terms. -/
theorem byte_call_subnormalized_step {queries requests : Nat} (stage : SourceByteStage bound)
    (next : ByteResult → Lifetime bound Work queries requests) (globalQueries : Nat)
    (within : queries ≤ globalQueries)
    (remaining : ∀ bytes oracle state,
      |runLifetime false (next bytes) oracle state - runLifetime true (next bytes) oracle state| ≤
        (requests : ℝ) * hiddenPatchLoss globalQueries * ‖state‖ ^ 2)
    (oracle : FullOracle bound) (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    |runLifetime false (.byteCall stage next) oracle state -
      runLifetime true (.byteCall stage next) oracle state| ≤
      ((requests + 1 : Nat) : ℝ) * hiddenPatchLoss globalQueries * ‖state‖ ^ 2 := by
  let left := fun bytes => compileWorld false (next bytes)
  let right := fun bytes => compileWorld true (next bytes)
  have futureChange := raw_source_byte_continuation_bound false bound queries (stage.toJob left)
    (futureGames right) (future_games_query_bound right) ((requests : ℝ) * hiddenPatchLoss globalQueries)
    (by
      intro bytes current branch
      simpa only [SourceByteStage.toJob, future_games_execution, left, right, runLifetime] using
        remaining bytes current branch) oracle state
  rw [stage_job_replace_future] at futureChange
  have localChange := actual_byte_pivot_subnormalized_bound false bound queries
    (stage.toJob right) oracle state
  have enlarged : hiddenPatchLoss queries * ‖state‖ ^ 2 ≤
      hiddenPatchLoss globalQueries * ‖state‖ ^ 2 :=
    mul_le_mul_of_nonneg_right (hidden_patch_loss_mono within) (sq_nonneg ‖state‖)
  rw [source_call_execution, public_call_execution]
  calc
    _ ≤ |rawByteSourceKernel false bound queries (stage.toJob left) oracle state -
          rawByteSourceKernel false bound queries (stage.toJob right) oracle state| +
        |rawByteSourceKernel false bound queries (stage.toJob right) oracle state -
          rawBytePublicKernel false bound (stage.toJob right).toPublicBytePivot oracle state| :=
      abs_sub_le _ _ _
    _ ≤ (requests : ℝ) * hiddenPatchLoss globalQueries * ‖state‖ ^ 2 +
        hiddenPatchLoss globalQueries * ‖state‖ ^ 2 :=
      add_le_add futureChange (localChange.trans enlarged)
    _ = _ := by push_cast; ring

/-- Every prior and future classical/quantum branch is included. The global
query budget bounds the entire remaining lifetime, not only the current call. -/
theorem hidden_lifetime_subnormalized_bound (globalQueries : Nat)
    {queries requests : Nat} (lifetime : Lifetime bound Work queries requests)
    (within : queries ≤ globalQueries) (oracle : FullOracle bound)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    |runLifetime false lifetime oracle state - runLifetime true lifetime oracle state| ≤
      (requests : ℝ) * hiddenPatchLoss globalQueries * ‖state‖ ^ 2 := by
  have lossNonnegative : 0 ≤ hiddenPatchLoss globalQueries := by
    rw [current_hidden_patch_loss_closed_form]
    positivity
  induction lifetime generalizing oracle state with
  | finish event =>
      simp only [runLifetime, compileWorld, V8Smz9MixedMaskCompiler.run, sub_self, abs_zero]
      exact mul_nonneg (mul_nonneg (Nat.cast_nonneg _) lossNonnegative) (sq_nonneg ‖state‖)
  | gate operation next ih =>
      simpa only [runLifetime, compileWorld, V8Smz9MixedMaskCompiler.run, operation.norm_map] using
        ih within oracle (operation state)
  | quantumQuery next ih =>
      simpa only [runLifetime, compileWorld, V8Smz9MixedMaskCompiler.run, (query oracle).norm_map] using
        ih (by omega) oracle (query oracle state)
  | honestRead input next ih =>
      exact ih (oracle input) (by omega) oracle state
  | instrument operation next ih =>
      change |(∑ outcome, runLifetime false (next outcome) oracle (operation.branch outcome state)) -
        ∑ outcome, runLifetime true (next outcome) oracle (operation.branch outcome state)| ≤ _
      rw [← Finset.sum_sub_distrib]
      calc
        _ ≤ ∑ outcome, |runLifetime false (next outcome) oracle (operation.branch outcome state) -
            runLifetime true (next outcome) oracle (operation.branch outcome state)| :=
          Finset.abs_sum_le_sum_abs _ _
        _ ≤ ∑ outcome, (_ : ℝ) * hiddenPatchLoss globalQueries * ‖operation.branch outcome state‖ ^ 2 :=
          Finset.sum_le_sum fun outcome _ => ih outcome within oracle (operation.branch outcome state)
        _ = _ := by rw [← Finset.mul_sum, operation.complete]
  | random source next ih =>
      exact (average_difference_abs_le _ _).trans
        (average_le_const _ _ fun coins => ih coins within oracle state)
  | write input answer next ih =>
      exact ih (by omega) (Function.update oracle input answer) state
  | nonleaf reads program counted next ih =>
      change |V8Smz9MixedMaskCompiler.run false (compileNonleaf program _) oracle state -
        V8Smz9MixedMaskCompiler.run false (compileNonleaf program _) oracle state| ≤ _
      rw [compile_nonleaf_executes, compile_nonleaf_executes]
      exact ih (NonleafProgram.interpret (fun input => oracle (Sum.inr input)) program)
        (by omega) oracle state
  | byteCall stage next ih =>
      apply byte_call_subnormalized_step stage next globalQueries (by omega)
      intro bytes current branch
      exact ih bytes (by omega) current branch

/-- Exactly one initial oracle is averaged, after the complete adaptive AST
and initial quantum state have been fixed. No stage-origin claim is implicit. -/
def lifetimeAcceptance (publicWorld : Bool) {queries requests : Nat}
    (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) : ℝ :=
  V8Smz9MixedMaskCompiler.acceptance false (compileWorld publicWorld lifetime).1 initial

theorem hidden_lifetime_acceptance_bound {queries requests : Nat}
    (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    |lifetimeAcceptance false lifetime initial - lifetimeAcceptance true lifetime initial| ≤
      (requests : ℝ) * hiddenPatchLoss queries := by
  unfold lifetimeAcceptance V8Smz9MixedMaskCompiler.acceptance
  apply (average_difference_abs_le _ _).trans
  apply average_le_const
  intro oracle
  simpa only [runLifetime, normalized, one_pow, mul_one] using
    hidden_lifetime_subnormalized_bound queries lifetime (Nat.le_refl _) oracle initial

/-- The same whole-lifetime result for the physical raw-query compiler,
starting with no oracle-correlated correction advice. -/
theorem compiled_hidden_lifetime_acceptance_bound {queries requests : Nat}
    (lifetime : Lifetime bound Work queries requests)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) (normalized : ‖initial‖ = 1) :
    |acceptance false (V8Smz9MixedMaskCompiler.compile (compileWorld false lifetime).1 []) initial -
      acceptance false (V8Smz9MixedMaskCompiler.compile (compileWorld true lifetime).1 []) initial| ≤
      (requests : ℝ) * hiddenPatchLoss queries := by
  rw [V8Smz9MixedMaskCompiler.compiled_acceptance_eq,
    V8Smz9MixedMaskCompiler.compiled_acceptance_eq]
  exact hidden_lifetime_acceptance_bound lifetime initial normalized

end
end HegemonCrypto.SmallWood.V8Smz9HiddenLifetime
