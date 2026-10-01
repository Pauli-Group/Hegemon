import Q38Rp05StoppedSupport
import Q38Rp05StoppedMass

/-! Exact syntactic reverse-hybrid refinement, not an assumed schedule. -/
namespace HegemonCrypto.SmallWood.Q38Rp05StoppedRefinement

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler
open HegemonCrypto.SmallWood.Q38Rp05StoppedMass
open HegemonCrypto.SmallWood.Q38Rp05StoppedSupport
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
universe u
variable {Input Work : Type} {Job : Type u}
variable [Fintype Input] [DecidableEq Input] [Fintype Work] [DecidableEq Work]

def mixedPrefix : Prefix Input Work Job → (Job → MixedProgram Input Work) → MixedProgram Input Work
  | .finish event, _ => .finish event
  | .pivot job, future => future job
  | .gate operation next, future => .gate operation (mixedPrefix next future)
  | .quantumQuery next, future => .quantumQuery (mixedPrefix next future)
  | .honestRead input next, future => .honestRead input (fun answer => mixedPrefix (next answer) future)
  | .instrument operation next, future => .instrument operation (fun outcome => mixedPrefix (next outcome) future)
  | .random source next, future => .random source (fun coins => mixedPrefix (next coins) future)

omit [DecidableEq Work] in
theorem mixed_prefix_executes (mode : Bool) (stopped : Prefix Input Work Job)
    (future : Job → MixedProgram Input Work) (oracle : Input → DigestRegister)
    (state : GameState (Input := Input) (Work := Work)) :
    run mode (closePrefix stopped (fun job => V8Smz9MixedMaskCompiler.compile (future job) []))
        oracle state =
      V8Smz9MixedMaskCompiler.run mode (mixedPrefix stopped future) oracle state := by
  induction stopped generalizing state with
  | finish event => rfl
  | pivot job =>
      exact (V8Smz9MixedMaskCompiler.compile_executes mode (future job) oracle [] state).trans
        (by rw [V8Smz9MixedMaskCompiler.effective_empty]; rfl)
  | gate operation next ih => exact ih _
  | quantumQuery next ih => exact ih _
  | honestRead input next ih => exact ih (oracle input) state
  | instrument operation next ih =>
      simp only [closePrefix, mixedPrefix,
        V8Smz9HonestWholeViewGames.run, V8Smz9MixedMaskCompiler.run]
      exact Finset.sum_congr rfl fun outcome _ => ih outcome _
  | random source next ih =>
      simp only [closePrefix, mixedPrefix,
        V8Smz9HonestWholeViewGames.run, V8Smz9MixedMaskCompiler.run]
      exact congrArg uniformAverage (funext fun coins => ih coins state)

omit [DecidableEq Work] in
theorem closed_prefix_query_le_mixed (stopped : Prefix Input Work Job)
    (future : Job → MixedProgram Input Work) :
    queryCount (closePrefix stopped (fun job => V8Smz9MixedMaskCompiler.compile (future job) [])) ≤
      V8Smz9MixedMaskCompiler.queryCount (mixedPrefix stopped future) := by
  induction stopped with
  | finish event => exact le_rfl
  | pivot job => exact V8Smz9MixedMaskCompiler.compiled_query_count_le _ _
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact Nat.add_le_add_right ih 1
  | honestRead input next ih =>
      apply Nat.add_le_add_right
      exact Finset.sup_le fun answer member =>
        (ih answer).trans (Finset.le_sup
          (f := fun output => V8Smz9MixedMaskCompiler.queryCount
            (mixedPrefix (next output) future)) member)
  | instrument operation next ih =>
      exact Finset.sup_le fun outcome member =>
        (ih outcome).trans (Finset.le_sup
          (f := fun output => V8Smz9MixedMaskCompiler.queryCount
            (mixedPrefix (next output) future)) member)
  | random source next ih =>
      exact Finset.sup_le fun coins member =>
        (ih coins).trans (Finset.le_sup
          (f := fun output => V8Smz9MixedMaskCompiler.queryCount
            (mixedPrefix (next output) future)) member)

section Current
variable {bound : Nat}
local notation "CurrentInput" => Rp05FullRawInput bound
local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

omit [DecidableEq Work] in
theorem mixed_prefix_nonleaf {Result : Type}
    (program : NonleafProgram (Rp05OtherRawInput bound) Result)
    (next : Result → Prefix CurrentInput Work Job)
    (future : Job → MixedProgram CurrentInput Work) :
    mixedPrefix (nonleafPrefix program next) future =
      mixedNonleaf program (fun result => mixedPrefix (next result) future) := by
  induction program with
  | done result => rfl
  | read input rest ih =>
      simp only [nonleafPrefix, mixedPrefix, mixedNonleaf]
      congr 1
      funext answer
      exact ih answer

omit [DecidableEq Work] in
private theorem mixed_prefix_random {source : RandomSource}
    (next : source.Coins → Prefix CurrentInput Work Job)
    (future : Job → MixedProgram CurrentInput Work) :
    mixedPrefix (.random source next) future =
      MixedProgram.random source (fun coins => mixedPrefix (next coins) future) := rfl

omit [DecidableEq Work] in
theorem mixed_prefix_real_leaf (count : Nat) (indices : Fin count → LeafIndex)
    (statement : Statement) (salt : SaltBytes) (data : Fin count → Fin 1176 → Byte)
    (next : (Fin count → LeafTape) → (Fin count → DigestRegister) → Prefix CurrentInput Work Job)
    (future : Job → MixedProgram CurrentInput Work) :
    mixedPrefix (realLeafPrefix count indices statement salt data next) future =
      realLeafBatch count indices statement salt data
        (fun tapes labels => mixedPrefix (next tapes labels) future) := by
  induction count with
  | zero => rfl
  | succ count ih =>
      simp only [realLeafPrefix, mixedPrefix, realLeafBatch]
      congr 1
      funext tape
      congr 1
      funext answer
      apply ih

attribute [local irreducible] mixedPrefix
  HegemonCrypto.SmallWood.Q38Rp05StoppedMass.realLeafPrefix
  HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler.realLeafBatch
  HegemonCrypto.SmallWood.Q38Rp05StoppedMass.nonleafPrefix
  HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler.mixedNonleaf

omit [DecidableEq Work] in
theorem mixed_prefix_real_request (data : Request bound)
    (next : Bytes → Prefix CurrentInput Work Job)
    (future : Job → MixedProgram CurrentInput Work) :
    mixedPrefix (realRequestPrefix data next) future =
      realRequest data (fun bytes => mixedPrefix (next bytes) future) := by
  conv_lhs => rw [realRequestPrefix]
  conv_rhs => rw [realRequest]
  conv_lhs => rw [mixed_prefix_random]
  congr 1
  funext base
  conv_lhs => rw [mixed_prefix_random]
  congr 1
  funext masks
  conv_lhs => rw [mixed_prefix_real_leaf]
  congr 1
  funext tapes labels
  conv_lhs => rw [mixed_prefix_nonleaf]

attribute [local semireducible] mixedPrefix
  HegemonCrypto.SmallWood.Q38Rp05StoppedMass.realLeafPrefix
  HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler.realLeafBatch
  HegemonCrypto.SmallWood.Q38Rp05StoppedMass.nonleafPrefix
  HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler.mixedNonleaf

def realPivot (job : Pivot bound Work) : MixedProgram CurrentInput Work :=
  realRequest job.1 job.2

def publicPivot (job : Pivot bound Work) : MixedProgram CurrentInput Work :=
  publicRequest job.1.largeEnough job.1.dsl job.1.statement job.1.salt job.1.widthBound job.2

omit [DecidableEq Work] in
/-- Exact adjacent experiments from the actual finite adaptive syntax. Both
identities hold even when the schedule stops before the nominated request. -/
theorem stopped_hybrid_pair {requests : Nat} (schedule : Schedule bound Work requests) (skip : Nat) :
    mixedPrefix (stopBefore skip schedule) realPivot = hybrid (skip + 1) schedule ∧
    mixedPrefix (stopBefore skip schedule) publicPivot = hybrid skip schedule := by
  induction schedule generalizing skip with
  | finish event => exact ⟨rfl, rfl⟩
  | gate operation next ih =>
      constructor <;> simp only [stopBefore, mixedPrefix, hybrid] <;>
        congr 1
      · exact (ih skip).1
      · exact (ih skip).2
  | quantumQuery next ih =>
      exact ⟨congrArg MixedProgram.quantumQuery (ih skip).1,
        congrArg MixedProgram.quantumQuery (ih skip).2⟩
  | honestRead input next ih =>
      constructor <;> simp only [stopBefore, mixedPrefix, hybrid] <;>
        congr 1 <;> funext answer
      · exact (ih answer skip).1
      · exact (ih answer skip).2
  | instrument operation next ih =>
      constructor <;> simp only [stopBefore, mixedPrefix, hybrid] <;>
        congr 1 <;> funext outcome
      · exact (ih outcome skip).1
      · exact (ih outcome skip).2
  | random source next ih =>
      constructor <;> simp only [stopBefore, mixedPrefix, hybrid] <;>
        congr 1 <;> funext coins
      · exact (ih coins skip).1
      · exact (ih coins skip).2
  | request data next ih =>
      cases skip with
      | zero => exact ⟨rfl, rfl⟩
      | succ skip =>
          constructor <;> simp only [stopBefore, mixed_prefix_real_request, hybrid] <;>
            congr 1 <;> funext bytes
          · exact (ih bytes skip).1
          · exact (ih bytes skip).2

omit [DecidableEq Work] in
theorem stopped_hybrid_budget {requests : Nat} (schedule : Schedule bound Work requests)
    (total skip : Nat) (budget : WithinBudget schedule total) (before : skip < requests) :
    queryCount (closePrefix (stopBefore skip schedule)
      (fun job => V8Smz9MixedMaskCompiler.compile (realPivot job) [])) ≤ total ∧
    queryCount (closePrefix (stopBefore skip schedule)
      (fun job => V8Smz9MixedMaskCompiler.compile (publicPivot job) [])) ≤ total := by
  constructor
  · apply (closed_prefix_query_le_mixed _ _).trans
    rw [(stopped_hybrid_pair schedule skip).1]
    exact budget (skip + 1) (by omega)
  · apply (closed_prefix_query_le_mixed _ _).trans
    rw [(stopped_hybrid_pair schedule skip).2]
    exact budget skip (by omega)

end Current
end
end HegemonCrypto.SmallWood.Q38Rp05StoppedRefinement
