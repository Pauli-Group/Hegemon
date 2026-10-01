import Q38Rp05RetainedKernelJoin
import Q38Rp05AdaptivePostfinalCore
import Q38Rp05UniformAverageTransport
import HegemonCrypto.SmallWoodV8Smz9MixedMaskAdapters
import HegemonCrypto.SmallWoodV8Smz9MixedMaskAccounting
import SmzaRp05CurrentCoset406

/-! Concrete current-profile public request and adaptive schedule.
The existing correction-log compiler implements fixed published-label writes;
it does not resample a label or replay the transcript selector. Source only.
The remaining endpoint is identified in SCHEDULER_HANDOFF.md. -/
namespace HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.SmallWood.Q38Rp05CurrentP10
open HegemonCrypto.SmallWood.Q38Rp05RecordedRequest
open HegemonCrypto.SmallWood.Q38Rp05DependentP10
open HegemonCrypto.SmallWood.Q38Rp05RetainedKernelJoin
open HegemonCrypto.SmallWood.Q38Rp05OpeningSchedule
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38Rp05UniformAverageTransport
open HegemonCrypto.SmallWood.V8Smz9PostFinalProgram (certifyOpening)
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
-- Computation allowance only: kernel checking and all claims remain unchanged,
-- while the coordinator separately bounds RAM and wall-clock time.
set_option maxHeartbeats 40000000

variable {bound : Nat} {Work : Type} [Fintype Work]
local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
local notation "OracleInput" => Rp05FullRawInput bound

attribute [local irreducible] certifyOpening rp05ChooseOpening NonleafProgram.interpret
  uniformAverage publicPostfinal

/-- Share the interpreted public stage before transporting its dependent
selector. This is the same identity as Retained's checked stage bridge; no
oracle interpretation is performed in its proof. -/
private theorem scheduler_dynamic_stage_eq
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (labels : LeafIndex → DigestRegister)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (other : Rp05OtherRawInput bound → DigestRegister) (reply : D) :
    let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement
      salt labels widthBound
    let decs := NonleafProgram.interpret other (decsPrefix shape)
    let computed := NonleafProgram.interpret other (piopSuffix shape decs reply)
    dynamicStage largeEnough dsl statement salt labels widthBound other reply =
      DynamicStage.mk (decodedParameters dsl statement computed.piopGamma)
        (decodedQ38DecsGamma computed.decsGamma) computed.hashFpp
        (sourcePendingFailure (sourcePendingFailure false computed.decsGamma)
          computed.piopGamma) computed.tree := by
  rfl

/-- Normalize the public reply/transcript/view law before inserting the
concrete interpreted stage. The finite-sum proof is checked once with opaque
selector and kernel arguments, not replayed inside the request execution. -/
private theorem public_average_eq_nested
    (points : D → Unit → Q → Fin 6 → Goldilocks)
    (choose : ∀ reply branch transcript,
      V8Smz9ZeroKnowledge.WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
        Earlier Goldilocks → Option (Targets (points reply branch transcript)))
    (kernel : D → Unit → Q → PartialView Goldilocks → ℝ) :
    publicRequestAverage points choose kernel =
      uniformAverage (fun reply : D =>
        uniformAverage (fun transcript : Q =>
          uniformAverage (fun view : RemainingView Goldilocks =>
            kernel reply () transcript
              (abortProjection (choose reply () transcript) view)))) := by
  unfold publicRequestAverage publicRequestKernelSum
  simp only [Fintype.sum_unique]
  exact (three_uniform_averages_eq_normalized_sum
    (fun reply transcript view => kernel reply () transcript
      (abortProjection (choose reply () transcript) view))).symm

private theorem dependent_public_average_eq_nested
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement) (salt : SaltBytes)
    (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (abortPoints : Fin 6 → Goldilocks)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oracle : OracleInput → DigestRegister)
    (state : GameState (Input := OracleInput) (Work := Work))
    (next : Bytes → Program OracleInput Work) :
    dependentPublicAverage largeEnough dsl statement salt widthBound abortPoints
      tapes labels oracle state next =
      uniformAverage (fun reply : D =>
        uniformAverage (fun transcript : Q =>
          uniformAverage (fun fullView : RemainingView Goldilocks =>
            let other := fun key => oracle (Sum.inr key)
            let stage := dynamicStage largeEnough dsl statement salt labels
              widthBound other reply
            dynamicKernel largeEnough dsl statement salt tapes stage other
              reply transcript
              (abortProjection (dynamicChoose largeEnough dsl statement
                abortPoints stage other transcript) fullView)
              (dynamicContinuationObservation dsl statement salt tapes labels
                oracle state next)))) := by
  unfold dependentPublicAverage
  exact public_average_eq_nested _ _ _

/-- One exact uniform-sampling step. Keep `run` and its continuation opaque
when applying this equality at the concrete public request. -/
private theorem mixed_uniform_executes
    {A : Type} [Fintype A] [Nonempty A]
    (next : A → MixedProgram OracleInput Work)
    (oracle : OracleInput → DigestRegister)
    (state : GameState (Input := OracleInput) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run true
      (.random (uniformSource A) next) oracle state =
      uniformAverage (fun coin : A =>
        V8Smz9MixedMaskCompiler.run true (next coin) oracle state) := by
  rfl

/-- Literal chronology, with each nonleaf read compiled once. The same measured
selector result determines both the partial view and the subsequent writes. -/
def publicRequest
    (largeEnough : 39162 ≤ bound) (dsl : RelationDsl) (statement : Statement)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (next : Bytes → MixedProgram OracleInput Work) : MixedProgram OracleInput Work :=
  .random (uniformSource (LeafIndex → DigestRegister)) fun labels =>
  .random (uniformSource TapeTable) fun tapes =>
  let shape := rp05CurrentPrefinalShape bound largeEnough dsl statement salt
    labels widthBound
  mixedNonleaf (decsPrefix shape) fun decs =>
  .random (uniformSource D) fun reply =>
  mixedNonleaf (piopSuffix shape decs reply) fun computed =>
  .random (uniformSource Q) fun transcript =>
  publicPostfinal largeEnough dsl statement salt labels tapes
    ⟨decodedParameters dsl statement computed.piopGamma,
      decodedQ38DecsGamma computed.decsGamma, computed.hashFpp,
      sourcePendingFailure (sourcePendingFailure false computed.decsGamma)
        computed.piopGamma, computed.tree⟩ reply transcript next

/-- The scalar P10 simulator has an actual pre-oracle program. The full public
view is sampled only once; its later coordinates are discarded on index abort.
The mathematical abort padding is irrelevant to the nonce-abort execution. -/
theorem public_request_executes
    (largeEnough : 39162 ≤ bound) (dsl : RelationDsl) (statement : Statement)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (abortPoints : Fin 6 → Goldilocks)
    (next : Bytes → MixedProgram OracleInput Work)
    (oracle : OracleInput → DigestRegister)
    (state : GameState (Input := OracleInput) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run true
      (publicRequest largeEnough dsl statement salt widthBound next) oracle state =
      publicSimulatorProbability largeEnough dsl statement salt widthBound
        abortPoints oracle state
        (fun bytes => V8Smz9MixedMaskCompiler.compile (next bytes) []) := by
  unfold publicSimulatorProbability
  simp_rw [dependent_public_average_eq_nested]
  simp only [publicRequest, mixed_uniform_executes, mixed_nonleaf_executes]
  apply uniform_average_congr_instances
  intro labels
  apply uniform_average_congr_instances
  intro tapes
  apply uniform_average_congr_instances
  intro reply
  apply uniform_average_congr_instances
  intro transcript
  -- Fix bound, workspace and every public argument before theorem matching.
  -- Infer only the already computed stage from the literal program; do not
  -- ask a partially applied rewrite to synthesize a workspace dictionary.
  refine (public_postfinal_executes (bound := bound) (Work := Work)
    largeEnough dsl statement salt labels tapes _ reply transcript
    abortPoints next oracle state).trans ?_
  apply uniform_average_congr_instances
  intro fullView
  -- Transport a shared stage propositionally, rather than making the kernel
  -- normalize interpreted stages inside the dependent opening/Targets index.
  exact congrArg
    (fun stage : DynamicStage dsl statement =>
      dynamicKernel largeEnough dsl statement salt tapes stage
        (fun key => oracle (Sum.inr key)) reply transcript
        (abortProjection (dynamicChoose largeEnough dsl statement abortPoints stage
          (fun key => oracle (Sum.inr key)) transcript) fullView)
        (dynamicContinuationObservation dsl statement salt tapes labels oracle state
          (fun bytes => V8Smz9MixedMaskCompiler.compile (next bytes) [])))
    (scheduler_dynamic_stage_eq largeEnough dsl statement salt labels widthBound
      (fun key => oracle (Sum.inr key)) reply).symm

/-- Public request data and real-only witness are explicit fields, not kernels
allowed to inspect an oracle or a quantum state. -/
structure Request (bound : Nat) where
  largeEnough : 39162 ≤ bound
  dsl : RelationDsl
  statement : Statement
  witness : WitnessPackingValues Goldilocks
  salt : SaltBytes
  widthBound : 5 * dsl.width statement ≤ 2 ^ 24

/-- The real source uses uniform tapes and CURRENT answers; no selected
freshInput remains to have its mode changed by an enclosing hybrid. -/
def realLeafBatch : (count : Nat) → (Fin count → LeafIndex) → Statement → SaltBytes →
    (Fin count → Fin 1176 → Byte) →
    ((Fin count → LeafTape) → (Fin count → DigestRegister) →
      MixedProgram OracleInput Work) → MixedProgram OracleInput Work
  | 0, _, _, _, _, next => next Fin.elim0 Fin.elim0
  | count + 1, indices, statement, salt, data, next =>
    .random (uniformSource LeafTape) fun tape =>
    .honestRead (.inl (rp05SourceLeafInput statement salt (data 0) (indices 0) tape))
      fun answer => realLeafBatch count (fun i => indices i.succ) statement salt
        (fun i => data i.succ) fun tapes labels =>
          next (Fin.cons tape tapes) (Fin.cons answer labels)

def realRequest (data : Request bound)
    (next : Bytes → MixedProgram OracleInput Work) : MixedProgram OracleInput Work :=
  .random rp05RemainingCoinsSource fun base =>
  .random rp05JointMasksSource fun masks =>
  realLeafBatch 8388608 id data.statement data.salt
    (q38PhysicalSuffix (currentHeads data.witness base masks.1) base.2.2 masks.2)
    fun tapes labels =>
  mixedNonleaf (recordedPrefix data.largeEnough data.dsl data.statement
    data.witness data.salt data.widthBound base masks labels) fun record =>
  next (recordBytes data.dsl data.statement data.witness base masks.1 data.salt tapes record)

/-- Stops may leave requests unused. Every measured outcome, random sample,
byte/error response, and subsequent request is inside the pre-oracle syntax. -/
inductive Schedule (bound : Nat) (Work : Type) [Fintype Work] : Nat → Type 1 where
  | finish {requests : Nat} (event : Finset (QueryBasis (Rp05FullRawInput bound)
      DigestRegister Work)) : Schedule bound Work requests
  | gate {requests : Nat} (operation : GameGate (Input := Rp05FullRawInput bound)
      (Work := Work)) (next : Schedule bound Work requests) : Schedule bound Work requests
  | quantumQuery {requests : Nat} (next : Schedule bound Work requests) :
      Schedule bound Work requests
  | honestRead {requests : Nat} (input : Rp05FullRawInput bound)
      (next : DigestRegister → Schedule bound Work requests) : Schedule bound Work requests
  | instrument {requests count : Nat} (operation : Instrument (Rp05FullRawInput bound) Work count)
      (next : Fin count → Schedule bound Work requests) : Schedule bound Work requests
  | random {requests : Nat} (source : RandomSource)
      (next : source.Coins → Schedule bound Work requests) : Schedule bound Work requests
  | request {requests : Nat} (data : Request bound)
      (next : Bytes → Schedule bound Work requests) : Schedule bound Work (requests + 1)

/-- Reverse hybrids: first `realRequests` calls are real; every later call is
the concrete public code above. Compiling a continuation starts a fresh local
correction log against the CURRENT effective oracle, never a new oracle draw. -/
def hybrid : {requests : Nat} → Nat →
    HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler.Schedule bound Work requests →
    MixedProgram OracleInput Work
  | _, _, .finish event => .finish event
  | _, real, .gate operation next => .gate operation (hybrid real next)
  | _, real, .quantumQuery next => .quantumQuery (hybrid real next)
  | _, real, .honestRead input next => .honestRead input (fun answer => hybrid real (next answer))
  | _, real, .instrument operation next => .instrument operation (fun outcome => hybrid real (next outcome))
  | _, real, .random source next => .random source (fun coins => hybrid real (next coins))
  | _, 0, .request data next => publicRequest data.largeEnough data.dsl data.statement
      data.salt data.widthBound (fun bytes => hybrid 0 (next bytes))
  | _, real + 1, .request data next =>
      realRequest data (fun bytes => hybrid real (next bytes))

def compiledHybrid {requests : Nat} (real : Nat)
    (schedule : HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler.Schedule bound Work requests) :
    Program OracleInput Work := V8Smz9MixedMaskCompiler.compile (hybrid real schedule) []

/-- Concrete worst-branch query count includes honest/nonleaf reads, every
fixed public write, and all continuations. No success conditioning is used. -/
def WithinBudget {requests : Nat}
    (schedule : HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler.Schedule bound Work requests)
    (total : Nat) : Prop :=
  ∀ real ≤ requests, V8Smz9MixedMaskCompiler.queryCount (hybrid real schedule) ≤ total

theorem compiled_hybrid_within_budget {requests : Nat}
    (schedule : HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler.Schedule bound Work requests)
    (total real : Nat)
    (budget : WithinBudget schedule total) (bounded : real ≤ requests) :
    V8Smz9HonestWholeViewGames.queryCount (compiledHybrid real schedule) ≤ total :=
  (V8Smz9MixedMaskCompiler.compiled_query_count_le (hybrid real schedule) []).trans
    (budget real bounded)

/-- Physical semantics is a theorem of the existing fixed-write compiler,
not an assumption that a scalar simulator can be used as a Program. -/
theorem compiled_hybrid_executes {requests : Nat}
    (schedule : HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler.Schedule bound Work requests)
    (real : Nat)
    (oracle : OracleInput → DigestRegister)
    (state : GameState (Input := OracleInput) (Work := Work)) :
    run true (compiledHybrid real schedule) oracle state =
      V8Smz9MixedMaskCompiler.run true (hybrid real schedule) oracle state := by
  rw [compiledHybrid, V8Smz9MixedMaskCompiler.compile_executes,
    V8Smz9MixedMaskCompiler.effective_empty]

end
end HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler
