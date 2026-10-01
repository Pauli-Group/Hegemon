import Q38Rp05StoppedRefinement
import HegemonCrypto.SmallWoodV8Smz9MeasuredPrefix
import SmzaRp05CurrentCoset406

/-! A request's bounded expansion does not bound its callback on impossible
bytes. Example: finish on all valid results, but perform bytes.length queries
on successful strings longer than 164113. The following exact syntactic
clipping law removes only over-budget unreachable callback branches. -/
namespace HegemonCrypto.SmallWood.Q38Rp05ClippedCallbacks

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.Q38Rp05OpeningSchedule
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler
open HegemonCrypto.SmallWood.Q38Rp05StoppedMass
open HegemonCrypto.SmallWood.Q38Rp05StoppedRefinement
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition (TapeTable)
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule (sourcePendingFailure)
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
set_option maxHeartbeats 2000000
universe u
variable {Input Work : Type} {Result : Type u}
variable [Fintype Input] [DecidableEq Input] [Fintype Work]

local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

local notation "Return" => V8Smz9MeasuredPrefix.Prefix
local notation "plug" => V8Smz9MeasuredPrefix.compilePrefix

def clip (total : Nat) (program : MixedProgram Input Work) : MixedProgram Input Work :=
  if V8Smz9MixedMaskCompiler.queryCount program ≤ total then program else .finish ∅

omit [DecidableEq Input] in
theorem clip_query_bound (total : Nat) (program : MixedProgram Input Work) :
    V8Smz9MixedMaskCompiler.queryCount (clip total program) ≤ total := by
  unfold clip
  split
  · assumption
  · exact Nat.zero_le _

theorem compiled_clip_query_bound (total : Nat) (program : MixedProgram Input Work) :
    queryCount (V8Smz9MixedMaskCompiler.compile (clip total program) []) ≤ total :=
  (V8Smz9MixedMaskCompiler.compiled_query_count_le _ _).trans (clip_query_bound _ _)

omit [DecidableEq Input] in
/-- Exact CODE equality: under the real expanded budget, no actually present
callback leaf is replaced. This is stronger than probability equality and
requires neither reachability advice nor an all-byte callback hypothesis. -/
theorem plug_clipped_eq (stopped : Return Input Work Result)
    (next : Result → MixedProgram Input Work) (total : Nat)
    (budget : V8Smz9MixedMaskCompiler.queryCount (plug stopped next) ≤ total) :
    plug stopped (fun result => clip total (next result)) = plug stopped next := by
  induction stopped with
  | finish event => rfl
  | pivot result =>
      change clip total (next result) = next result
      change V8Smz9MixedMaskCompiler.queryCount (next result) ≤ total at budget
      simp only [clip, if_pos budget]
  | gate operation rest ih => exact congrArg (MixedProgram.gate operation) (ih budget)
  | quantumQuery rest ih =>
      apply congrArg MixedProgram.quantumQuery
      apply ih
      change V8Smz9MixedMaskCompiler.queryCount (plug rest next) + 1 ≤ total at budget
      omega
  | honestRead input rest ih =>
      apply congrArg (MixedProgram.honestRead input)
      funext answer
      apply ih answer
      have branch := Finset.le_sup
        (f := fun output => V8Smz9MixedMaskCompiler.queryCount (plug (rest output) next))
        (Finset.mem_univ answer)
      change (Finset.univ.sup fun output =>
        V8Smz9MixedMaskCompiler.queryCount (plug (rest output) next)) + 1 ≤ total at budget
      omega
  | instrument operation rest ih =>
      apply congrArg (MixedProgram.instrument operation)
      funext outcome
      apply ih outcome
      exact (Finset.le_sup (Finset.mem_univ outcome)).trans budget
  | random source rest ih =>
      apply congrArg (MixedProgram.random source)
      funext coins
      apply ih coins
      exact (Finset.le_sup (Finset.mem_univ coins)).trans budget
  | freshInput sampler rest ih =>
      apply congrArg (MixedProgram.freshInput sampler)
      funext coins answer
      apply ih coins answer
      have first := Finset.le_sup
        (f := fun c => Finset.univ.sup fun a =>
          V8Smz9MixedMaskCompiler.queryCount (plug (rest c a) next)) (Finset.mem_univ coins)
      have second := Finset.le_sup
        (f := fun a => V8Smz9MixedMaskCompiler.queryCount (plug (rest coins a) next))
        (Finset.mem_univ answer)
      change (Finset.univ.sup fun c => Finset.univ.sup fun a =>
        V8Smz9MixedMaskCompiler.queryCount (plug (rest c a) next)) + 1 ≤ total at budget
      omega
  | write input answer rest ih =>
      apply congrArg (MixedProgram.write input answer)
      apply ih
      change V8Smz9MixedMaskCompiler.queryCount (plug rest next) + 1 ≤ total at budget
      omega

def toReturning : Prefix Input Work Result → Return Input Work Result
  | .finish event => .finish event
  | .pivot result => .pivot result
  | .gate operation next => .gate operation (toReturning next)
  | .quantumQuery next => .quantumQuery (toReturning next)
  | .honestRead input next => .honestRead input (fun answer => toReturning (next answer))
  | .instrument operation next => .instrument operation (fun outcome => toReturning (next outcome))
  | .random source next => .random source (fun coins => toReturning (next coins))

omit [DecidableEq Input] in
theorem plug_to_returning (stopped : Prefix Input Work Result)
    (next : Result → MixedProgram Input Work) :
    plug (toReturning stopped) next = mixedPrefix stopped next := by
  induction stopped with
  | finish event => rfl
  | pivot result => rfl
  | gate operation rest ih => exact congrArg (MixedProgram.gate operation) ih
  | quantumQuery rest ih => exact congrArg MixedProgram.quantumQuery ih
  | honestRead input rest ih => exact congrArg (MixedProgram.honestRead input) (funext ih)
  | instrument operation rest ih => exact congrArg (MixedProgram.instrument operation) (funext ih)
  | random source rest ih => exact congrArg (MixedProgram.random source) (funext ih)

section Current
variable {bound : Nat}
local notation "CurrentInput" => Rp05FullRawInput bound

theorem real_request_clipped_eq (data : Request bound)
    (next : Bytes → MixedProgram CurrentInput Work) (total : Nat)
    (budget : V8Smz9MixedMaskCompiler.queryCount (realRequest data next) ≤ total) :
    realRequest data (fun bytes => clip total (next bytes)) = realRequest data next := by
  let stopped : Prefix CurrentInput Work Bytes := realRequestPrefix data Prefix.pivot
  have transport (future : Bytes → MixedProgram CurrentInput Work) :
      plug (toReturning stopped) future = realRequest data future := by
    rw [plug_to_returning, mixed_prefix_real_request]
    rfl
  rw [← transport, ← transport]
  apply plug_clipped_eq (Input := CurrentInput) (Work := Work)
  rwa [transport]

def returningNonleaf {A : Type} : NonleafProgram (Rp05OtherRawInput bound) A →
    (A → Return CurrentInput Work Bytes) → Return CurrentInput Work Bytes
  | .done result, next => next result
  | .read input rest, next => .honestRead (.inr input)
      (fun answer => returningNonleaf (rest answer) next)

theorem plug_returning_nonleaf {A : Type}
    (program : NonleafProgram (Rp05OtherRawInput bound) A)
    (rest : A → Return CurrentInput Work Bytes) (next : Bytes → MixedProgram CurrentInput Work) :
    plug (returningNonleaf program rest) next =
      mixedNonleaf program (fun result => plug (rest result) next) := by
  induction program with
  | done result => rfl
  | read input tail ih =>
      exact congrArg (MixedProgram.honestRead (.inr input)) (funext ih)

def returningWrites : (count : Nat) → (Fin count → CurrentInput) →
    (Fin count → DigestRegister) → Return CurrentInput Work Bytes → Return CurrentInput Work Bytes
  | 0, _, _, next => next
  | count + 1, keys, labels, next => .write (keys 0) (labels 0)
      (returningWrites count (fun i => keys i.succ) (fun i => labels i.succ) next)

theorem plug_returning_writes (count : Nat) (keys : Fin count → CurrentInput)
    (labels : Fin count → DigestRegister) (rest : Return CurrentInput Work Bytes)
    (next : Bytes → MixedProgram CurrentInput Work) :
    plug (returningWrites count keys labels rest) next = writeBatch count keys labels (plug rest next) := by
  induction count with
  | zero => rfl
  | succ count ih =>
      apply congrArg (MixedProgram.write (keys 0) (labels 0))
      apply ih

def returningOpenedWrites
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes) (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks) (result : SelectionResult opening.points)
    (next : Return CurrentInput Work Bytes) : Return CurrentInput Work Bytes :=
  match result.targets, view.2.2.2 with
  | some _, some later =>
    let selected := selectedIndices result
    let heads := combinationHeads dsl statement parameters opening.points transcript view.1 view.2.1
    let targets := fun i =>
      HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint (selected i)
    let data := q38SelectedPublicData selected
      (q38PublicSuffix opening.points (computed_opening_selected_rank opening)
        gamma reply heads view.2.2.1 targets later)
    returningWrites 38
      (fun i => .inl (rp05SourceLeafInput statement salt
        (data (selected i)) (selected i) (tapes (selected i))))
      (fun i => labels (selected i)) next
  | _, _ => next

theorem plug_returning_opened_writes
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes) (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks) (result : SelectionResult opening.points)
    (rest : Return CurrentInput Work Bytes) (next : Bytes → MixedProgram CurrentInput Work) :
    plug (returningOpenedWrites dsl statement parameters opening gamma reply transcript
        salt tapes labels view result rest) next =
      publicOpenedWrites dsl statement parameters opening gamma reply transcript
        salt tapes labels view result (plug rest next) := by
  cases h : result.targets <;> cases v : view.2.2.2 <;>
    simp only [returningOpenedWrites, publicOpenedWrites, h, v]
  exact plug_returning_writes (bound := bound) (Work := Work) _ _ _ _ _

attribute [local irreducible] certifyOpening rp05ChooseOpening NonleafProgram.interpret
  uniformAverage publicPostfinal publicRequest

def publicReturning (data : Request bound) : Return CurrentInput Work Bytes :=
  .random (uniformSource (LeafIndex → DigestRegister)) fun labels =>
  .random (uniformSource TapeTable) fun tapes =>
  let shape := rp05CurrentPrefinalShape bound data.largeEnough data.dsl data.statement
    data.salt labels data.widthBound
  returningNonleaf (decsPrefix shape) fun decs =>
  .random (uniformSource D) fun reply =>
  returningNonleaf (piopSuffix shape decs reply) fun computed =>
  let parameters := decodedParameters data.dsl data.statement computed.piopGamma
  let gamma := decodedQ38DecsGamma computed.decsGamma
  let pending := sourcePendingFailure
    (sourcePendingFailure false computed.decsGamma) computed.piopGamma
  .random (uniformSource Q) fun transcript =>
  .honestRead (.inr (currentFinalKey bound (by have := data.largeEnough; omega) computed.hashFpp transcript)) fun digest =>
  returningNonleaf (rp05ChooseOpening bound (by have := data.largeEnough; omega) digest pending) fun trial =>
  match certifyOpening trial with
  | none => .pivot (.error "smallwood opening nonce trial limit exhausted")
  | some opening =>
    .random (uniformSource (RemainingView Goldilocks)) fun fullView =>
    returningNonleaf (currentSelectIndices bound data.largeEnough opening.points
      (computed_opening_points_distinct opening) digest
      (combinationHeads data.dsl data.statement parameters opening.points transcript
        fullView.1 fullView.2.1) fullView.2.2.1 opening.pendingFailure) fun selected =>
    let view : PartialView Goldilocks :=
      (fullView.1, fullView.2.1, fullView.2.2.1, selected.targets.map fun _ => fullView.2.2.2)
    returningOpenedWrites data.dsl data.statement parameters opening gamma reply transcript
      data.salt tapes labels view selected
      (.pivot (selectedBytes data.dsl data.statement parameters opening gamma reply transcript
        digest data.salt computed.tree tapes view selected))

private theorem plug_random_root {Job : Type} (source : RandomSource)
    (rest : source.Coins → Return CurrentInput Work Job)
    (next : Job → MixedProgram CurrentInput Work) :
    Eq (α := MixedProgram CurrentInput Work)
      (V8Smz9MeasuredPrefix.compilePrefix (Input := CurrentInput) (Work := Work)
        (Job := Job) (.random source rest) next)
      (.random source (fun coins =>
        V8Smz9MeasuredPrefix.compilePrefix (Input := CurrentInput) (Work := Work)
          (Job := Job) (rest coins) next)) := rfl

private theorem plug_honest_read_root {Job : Type} (input : CurrentInput)
    (rest : DigestRegister → Return CurrentInput Work Job)
    (next : Job → MixedProgram CurrentInput Work) :
    Eq (α := MixedProgram CurrentInput Work)
      (V8Smz9MeasuredPrefix.compilePrefix (Input := CurrentInput) (Work := Work)
        (Job := Job) (.honestRead input rest) next)
      (.honestRead input (fun answer =>
        V8Smz9MeasuredPrefix.compilePrefix (Input := CurrentInput) (Work := Work)
          (Job := Job) (rest answer) next)) := rfl

private theorem plug_pivot_root {Job : Type} (job : Job)
    (next : Job → MixedProgram CurrentInput Work) :
    Eq (α := MixedProgram CurrentInput Work)
      (V8Smz9MeasuredPrefix.compilePrefix (Input := CurrentInput) (Work := Work)
        (Job := Job) (.pivot job) next) (next job) := rfl

attribute [local irreducible] publicReturning V8Smz9MeasuredPrefix.compilePrefix
  returningNonleaf HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler.mixedNonleaf

theorem public_returning_compiles (data : Request bound)
    (next : Bytes → MixedProgram CurrentInput Work) :
    Eq (α := MixedProgram CurrentInput Work)
      (V8Smz9MeasuredPrefix.compilePrefix (Input := CurrentInput) (Work := Work)
        (Job := Bytes) (publicReturning (bound := bound) (Work := Work) data) next)
      (publicRequest (bound := bound) (Work := Work) data.largeEnough data.dsl
        data.statement data.salt data.widthBound next) := by
  unfold publicReturning publicRequest publicPostfinal
  rw [plug_random_root (bound := bound) (Work := Work)]
  apply congrArg (MixedProgram.random (uniformSource (LeafIndex → DigestRegister)))
  funext labels
  rw [plug_random_root (bound := bound) (Work := Work)]
  apply congrArg (MixedProgram.random (uniformSource TapeTable))
  funext tapes
  rw [plug_returning_nonleaf (bound := bound) (Work := Work)]
  apply congrArg (mixedNonleaf (decsPrefix _))
  funext decs
  rw [plug_random_root (bound := bound) (Work := Work)]
  apply congrArg (MixedProgram.random (uniformSource D))
  funext reply
  rw [plug_returning_nonleaf (bound := bound) (Work := Work)]
  apply congrArg (mixedNonleaf (piopSuffix _ decs reply))
  funext computed
  rw [plug_random_root (bound := bound) (Work := Work)]
  apply congrArg (MixedProgram.random (uniformSource Q))
  funext transcript
  rw [plug_honest_read_root (bound := bound) (Work := Work)]
  apply congrArg (MixedProgram.honestRead (Input := CurrentInput) (Work := Work) (.inr
    (currentFinalKey bound (by have := data.largeEnough; omega) computed.hashFpp transcript)))
  funext digest
  rw [plug_returning_nonleaf (bound := bound) (Work := Work)]
  apply congrArg (mixedNonleaf (rp05ChooseOpening bound
    (by have := data.largeEnough; omega) digest
    (sourcePendingFailure
      (sourcePendingFailure false computed.decsGamma) computed.piopGamma)))
  funext trial
  generalize openingEq : certifyOpening trial = opening
  cases opening with
  | none => rw [plug_pivot_root (bound := bound) (Work := Work)]
  | some opening =>
    rw [plug_random_root (bound := bound) (Work := Work)]
    apply congrArg (MixedProgram.random (uniformSource (RemainingView Goldilocks)))
    funext fullView
    rw [plug_returning_nonleaf (bound := bound) (Work := Work)]
    apply congrArg (mixedNonleaf (currentSelectIndices bound data.largeEnough opening.points
      (computed_opening_points_distinct opening)
      digest
      (combinationHeads data.dsl data.statement
        (decodedParameters data.dsl data.statement computed.piopGamma)
        opening.points transcript fullView.1 fullView.2.1)
      fullView.2.2.1 opening.pendingFailure))
    funext selected
    rw [plug_returning_opened_writes (bound := bound) (Work := Work),
      plug_pivot_root (bound := bound) (Work := Work)]

theorem public_request_clipped_eq (data : Request bound)
    (next : Bytes → MixedProgram CurrentInput Work) (total : Nat)
    (budget : V8Smz9MixedMaskCompiler.queryCount
      (publicRequest data.largeEnough data.dsl data.statement data.salt data.widthBound next) ≤ total) :
    publicRequest data.largeEnough data.dsl data.statement data.salt data.widthBound
      (fun bytes => clip total (next bytes)) =
      publicRequest data.largeEnough data.dsl data.statement data.salt data.widthBound next := by
  rw [← public_returning_compiles (bound := bound) (Work := Work),
    ← public_returning_compiles (bound := bound) (Work := Work)]
  apply plug_clipped_eq (Input := CurrentInput) (Work := Work)
  rwa [public_returning_compiles (bound := bound) (Work := Work)]

end Current
end
end HegemonCrypto.SmallWood.Q38Rp05ClippedCallbacks
